mod backups;
mod categories;
mod entries;
mod lifecycle;
mod master_password;
mod password_health;
mod site_icons;
mod totp;

pub use password_health::{PasswordHealthItem, PasswordHealthReport, PasswordWeakReason};
pub use site_icons::SiteIconSummary;
pub use totp::TotpCode;

use std::{
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use localvault_core::sync_state::Locator;
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::vault::{
    backup::BackupError,
    lifecycle::VaultLifecycleError,
    session::{
        BindingResetConfirmRefusal, BindingResetOutcome, BindingResetPreview, BindingResetRefusal,
        BindingStatus, CopyCreationConfirmRefusal, CopyCreationOutcome, CopyCreationPreview,
        CopyCreationRefusal, InitialBindingApproval, InitialBindingConfirmRefusal,
        InitialBindingOutcome, InitialBindingPreview, InitialBindingRefusal,
        RemoteObservationOutcome, RemoteObservationRefusal, RemoteTargetRefusal, SessionError,
        SessionSyncState, UnlockedVaultSession, UpdateReadiness,
    },
    sync_file_adapter::SyncFileTarget,
    sync_state_store::SyncStateRoot,
};

const DEFAULT_AUTO_LOCK_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(debug_assertions)]
const DEV_AUTO_LOCK_ENV: &str = "LOCALVAULT_DEV_AUTO_LOCK_SECONDS";

#[cfg(debug_assertions)]
const MIN_DEV_AUTO_LOCK_SECONDS: u64 = 5;

#[cfg(debug_assertions)]
fn parse_dev_auto_lock_timeout(value: &str) -> Option<Duration> {
    let seconds = value.parse::<u64>().ok()?;

    if !(MIN_DEV_AUTO_LOCK_SECONDS..=DEFAULT_AUTO_LOCK_TIMEOUT.as_secs()).contains(&seconds) {
        return None;
    }

    Some(Duration::from_secs(seconds))
}

fn configured_auto_lock_timeout() -> Duration {
    #[cfg(debug_assertions)]
    {
        if let Ok(value) = std::env::var(DEV_AUTO_LOCK_ENV) {
            if let Some(timeout) = parse_dev_auto_lock_timeout(&value) {
                return timeout;
            }
        }
    }

    DEFAULT_AUTO_LOCK_TIMEOUT
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub unlocked: bool,
    pub dirty: bool,
}

#[derive(Debug, Error)]
pub enum AppStateError {
    #[error("a vault is already unlocked")]
    AlreadyUnlocked,

    #[error("vault is locked")]
    VaultLocked,

    #[error("vault session expired")]
    SessionExpired,

    #[error("application state is unavailable")]
    StateUnavailable,

    #[error("system clock is invalid")]
    InvalidClock,

    /// The unlocked session a sync-binding file selection began in is no longer
    /// the live one (it was locked, expired or replaced while the native picker
    /// was open). Nothing was prepared.
    #[error("the vault session changed")]
    SessionChanged,

    /// The sync-binding attempt that opened a native file picker is no longer the
    /// current one (its dialog was closed or a newer attempt began). Nothing was
    /// prepared.
    #[error("the sync binding attempt was superseded")]
    AttemptSuperseded,

    #[error("site hostname is not referenced by a vault entry")]
    SiteHostnameNotReferenced,

    #[error("encrypted site icon cache capacity is exceeded")]
    SiteIconCacheFull,

    #[error("TOTP is not configured for this entry")]
    TotpNotConfigured,

    #[error("TOTP code generation failed")]
    TotpGenerationFailed,

    #[error("vault session operation failed")]
    Session(#[from] SessionError),

    #[error("backup operation failed")]
    Backup(#[from] BackupError),

    #[error("vault lifecycle operation failed")]
    Lifecycle(#[from] VaultLifecycleError),
}

/// Identity of one live unlocked session, for an interaction that must not leave
/// the session it began in (a native file picker that runs without the state
/// mutex). Comes only from [`AppState::begin_sync_binding_selection`]; compares
/// equal only to the session that issued it. Carries no secret, path or vault
/// identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionToken(u64);

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// Correlation handle of one sync-binding dialog attempt, supplied by the caller.
///
/// It exists only to tell two attempts within the SAME unlocked session apart
/// (the session identity cannot): a picker that finishes late for a closed
/// dialog, or a late cancel from one, must not prepare or discard what a newer
/// attempt owns. It is NOT consent and NOT an approval: it is chosen by the
/// caller, is never returned by Rust, and confirms nothing. Binding still needs
/// the Rust-generated, one-time preparation id and its own explicit
/// confirmation. Carries no path or vault data.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BindingAttemptId(uuid::Uuid);

impl BindingAttemptId {
    /// Canonical hyphenated UUID text only.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != 36 {
            return None;
        }

        uuid::Uuid::parse_str(text).ok().map(Self)
    }
}

impl std::fmt::Debug for BindingAttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BindingAttemptId(<redacted>)")
    }
}

/// How many cancelled attempt ids are remembered (see
/// [`AppState::cancel_binding_attempt`]).
const CANCELLED_ATTEMPTS_REMEMBERED: usize = 16;

#[derive(Default)]
struct AppStateInner {
    session: Option<UnlockedVaultSession>,
    last_activity: Option<Instant>,
    expiry_notification_pending: bool,

    // Advanced every time a session is placed in `session` (create, unlock), so
    // two sessions never share a value, even for the same vault file locked and
    // unlocked again. Never reset.
    session_epoch: u64,

    // The one sync-binding attempt allowed to prepare, and to own, the pending
    // initial-binding approval. Set by `begin_sync_binding_selection`, replaced by
    // the next attempt, cleared by its own cancel and whenever a session is placed.
    binding_attempt: Option<BindingAttemptId>,

    // The one reset attempt that owns the pending reset preparation. Set only by a
    // successful `prepare_binding_reset_for_attempt` (the session voids the older
    // preparation whatever the outcome), cleared by its own cancel and whenever a
    // session is placed.
    reset_attempt: Option<BindingAttemptId>,

    // The one copy-creation attempt allowed to prepare, and to own, the pending
    // copy-creation approval (Stage 1U-4 B2b). Set by
    // `begin_copy_creation_selection`, kept only by a successful preparation,
    // cleared by its own cancel, by any confirmation and whenever a session is
    // placed. An id is a label, never an approval.
    copy_attempt: Option<BindingAttemptId>,

    // Recently cancelled attempts (binding, reset and copy creation share the
    // list; an id names one attempt only), oldest first, so a cancel that
    // overtakes the command it cancels still wins.
    cancelled_binding_attempts: Vec<BindingAttemptId>,
}

impl AppStateInner {
    fn remember_cancelled(&mut self, attempt: BindingAttemptId) {
        if self.cancelled_binding_attempts.contains(&attempt) {
            return;
        }

        if self.cancelled_binding_attempts.len() >= CANCELLED_ATTEMPTS_REMEMBERED {
            self.cancelled_binding_attempts.remove(0);
        }

        self.cancelled_binding_attempts.push(attempt);
    }
}

pub struct AppState {
    inner: Mutex<AppStateInner>,
    auto_lock_timeout: Duration,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            inner: Mutex::new(AppStateInner::default()),
            auto_lock_timeout: configured_auto_lock_timeout(),
        }
    }
}

impl AppState {
    pub fn status(&self) -> Result<VaultStatus, AppStateError> {
        let mut guard = self.inner_guard()?;

        /*
         * Status observes expiry but deliberately does not
         * count as user activity. Polling get_vault_status
         * must never keep a vault unlocked forever.
         */
        self.expire_if_needed(&mut guard, Instant::now());

        Ok(status_from_session(guard.session.as_ref()))
    }

    pub fn create_vault(
        &self,
        path: PathBuf,
        master_password: Zeroizing<String>,
    ) -> Result<VaultStatus, AppStateError> {
        let mut guard = self.inner_guard()?;

        /*
         * A stale expired session must not prevent the user
         * from creating/opening another vault if the watcher
         * has not observed expiry yet.
         */
        self.expire_if_needed(&mut guard, Instant::now());

        if guard.session.is_some() {
            return Err(AppStateError::AlreadyUnlocked);
        }

        let now_ms = unix_time_ms()?;

        let session = UnlockedVaultSession::create(path, master_password, now_ms)?;

        guard.session = Some(session);
        guard.session_epoch = guard.session_epoch.wrapping_add(1);
        guard.binding_attempt = None;
        guard.reset_attempt = None;
        guard.copy_attempt = None;
        guard.last_activity = Some(Instant::now());
        guard.expiry_notification_pending = false;

        Ok(status_from_session(guard.session.as_ref()))
    }

    pub fn unlock_vault(
        &self,
        path: PathBuf,
        master_password: Zeroizing<String>,
    ) -> Result<VaultStatus, AppStateError> {
        let mut guard = self.inner_guard()?;

        self.expire_if_needed(&mut guard, Instant::now());

        if guard.session.is_some() {
            return Err(AppStateError::AlreadyUnlocked);
        }

        let session = UnlockedVaultSession::unlock(path, master_password)?;

        guard.session = Some(session);
        guard.session_epoch = guard.session_epoch.wrapping_add(1);
        guard.binding_attempt = None;
        guard.reset_attempt = None;
        guard.copy_attempt = None;
        guard.last_activity = Some(Instant::now());
        guard.expiry_notification_pending = false;

        Ok(status_from_session(guard.session.as_ref()))
    }

    pub fn lock_vault(&self) -> Result<VaultStatus, AppStateError> {
        let mut guard = self.inner_guard()?;

        if let Some(session) = guard.session.as_mut() {
            session.save()?;
        }

        /*
         * Manual lock retains the existing save-before-drop
         * guarantee. If save fails, both the session and its
         * activity timestamp remain alive so plaintext
         * changes are not silently lost.
         */
        guard.session = None;
        guard.last_activity = None;
        guard.expiry_notification_pending = false;

        Ok(status_from_session(None))
    }

    pub fn touch_activity(&self) -> Result<(), AppStateError> {
        /*
         * active_session_guard performs both the expiry
         * check and the activity refresh atomically under
         * the same state mutex.
         */
        let _guard = self.active_session_guard()?;

        Ok(())
    }

    pub fn expire_inactive_session(&self) -> Result<bool, AppStateError> {
        let mut guard = self.inner_guard()?;

        self.expire_if_needed(&mut guard, Instant::now());

        if guard.expiry_notification_pending {
            guard.expiry_notification_pending = false;

            return Ok(true);
        }

        Ok(false)
    }

    /// Read-only load of the unlocked vault's device-local sync-state record
    /// (Stage 1U-4 B1b). Internal: no command, event or UI is attached.
    ///
    /// Fails with `VaultLocked`/`SessionExpired` unless a session is live, and
    /// holds the application-state mutex (and therefore the session and its
    /// exclusive OS lock) for the whole read. It observes expiry but, like
    /// `status`, does not count as user activity: an internal check must never
    /// keep a vault unlocked. The root comes from the trusted application
    /// context via `SyncStateRoot::from_app`; this method takes no path.
    pub fn load_sync_state(&self, root: &SyncStateRoot) -> Result<SessionSyncState, AppStateError> {
        let mut guard = self.inner_guard()?;

        if self.expire_if_needed(&mut guard, Instant::now()) {
            return Err(AppStateError::SessionExpired);
        }

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session.load_sync_state(root))
    }

    /// Read-only assessment of whether an update of the bound encrypted copy
    /// would currently pass the core push rules (Stage 1U-4 B3a). Internal: no
    /// command, event or UI is attached, so the frontend cannot reach it.
    ///
    /// Fails with `VaultLocked`/`SessionExpired` unless a session is live, and in
    /// that case no file is opened. The application-state mutex (and with it the
    /// session and its exclusive OS lock) is held for the whole assessment. Like
    /// `load_sync_state` it observes expiry but does not count as user activity:
    /// an internal check must never keep a vault unlocked. It takes no path and no
    /// target (both come from the verified stored binding), creates or spends no
    /// approval and writes nothing. The result is a diagnostic snapshot, **not an
    /// authorization**: see `UnlockedVaultSession::assess_bound_target_update`.
    pub fn assess_bound_target_update(
        &self,
        root: &SyncStateRoot,
    ) -> Result<UpdateReadiness, AppStateError> {
        let mut guard = self.inner_guard()?;

        if self.expire_if_needed(&mut guard, Instant::now()) {
            return Err(AppStateError::SessionExpired);
        }

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session.assess_bound_target_update(root))
    }

    /// Record a newly authenticated remote observation against the unlocked
    /// vault's existing synchronization binding (Stage 1U-4 B1c). Internal: no
    /// command, event or UI is attached, so the frontend cannot reach it.
    ///
    /// The outer error is "no live session" (`VaultLocked`/`SessionExpired`).
    /// The inner result is the session's own: see
    /// [`UnlockedVaultSession::record_remote_observation`] for what is checked,
    /// what is written and, in particular, why `target` and `candidate_raw` are
    /// caller assertions that a future target adapter must back (it must read
    /// the bytes from exactly the retained target).
    ///
    /// The application-state mutex, and with it the session and its exclusive
    /// OS lock, is held for the whole operation. Like `load_sync_state`, it
    /// observes expiry but does not count as user activity.
    pub fn record_remote_observation(
        &self,
        root: &SyncStateRoot,
        target: &Locator,
        candidate_raw: &[u8],
    ) -> Result<Result<RemoteObservationOutcome, RemoteObservationRefusal>, AppStateError> {
        let mut guard = self.inner_guard()?;

        if self.expire_if_needed(&mut guard, Instant::now()) {
            return Err(AppStateError::SessionExpired);
        }

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session.record_remote_observation(root, target, candidate_raw))
    }

    /// Read the selected local file target and record the authenticated
    /// observation against the unlocked vault's existing binding (Stage 1U-4
    /// B1e). Internal: no command, event or UI is attached, nothing calls it on
    /// startup or unlock, and no user-facing synchronization is enabled by it.
    ///
    /// The outer error is "no live session" (`VaultLocked`/`SessionExpired`), and
    /// in that case the target is never opened. The inner result is the
    /// session's own: see [`UnlockedVaultSession::observe_remote_target`] for the
    /// order of checks (the binding's target is compared **before** the file is
    /// read) and for what a result does not prove.
    ///
    /// The application-state mutex, and with it the session and its exclusive OS
    /// lock, is held across the whole filesystem read and state update, so a
    /// concurrent lock, expiry or save cannot interleave. Like `load_sync_state`
    /// and `record_remote_observation`, it observes expiry but does not count as
    /// user activity: an internal check must never keep a vault unlocked.
    pub fn observe_remote_target(
        &self,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
    ) -> Result<Result<RemoteObservationOutcome, RemoteTargetRefusal>, AppStateError> {
        let mut guard = self.inner_guard()?;

        if self.expire_if_needed(&mut guard, Instant::now()) {
            return Err(AppStateError::SessionExpired);
        }

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session.observe_remote_target(root, target))
    }

    /// Bind the unlocked vault to an existing, byte-identical encrypted file for
    /// the first time (Stage 1U-4 B1f). Internal: no command, event or UI is
    /// attached, nothing calls it on startup or unlock, and it enables no working
    /// synchronization.
    ///
    /// The outer error is "no live session" (`VaultLocked`/`SessionExpired`), and
    /// in that case the target is never opened and the approval is simply dropped.
    /// The inner result is the session's own: see
    /// [`UnlockedVaultSession::bind_existing_identical_target`] for the order of
    /// checks, the failure classes (in particular `PersistenceUnverified`) and the
    /// approval boundary. **No user-facing confirmation exists yet**: the
    /// [`InitialBindingApproval`] it requires can only be built by the session's
    /// own `confirm_initial_binding`, so nothing outside the session (and its
    /// tests) can call this with a real approval.
    ///
    /// The application-state mutex, and with it the session and its exclusive OS
    /// lock, is held across the whole read, the inspection and the publication, so
    /// a concurrent lock, expiry or save cannot interleave. Like the other sync
    /// operations it observes expiry but does not count as user activity: an
    /// internal check must never keep a vault unlocked.
    pub fn bind_existing_identical_target(
        &self,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
        approval: InitialBindingApproval,
    ) -> Result<Result<InitialBindingOutcome, InitialBindingRefusal>, AppStateError> {
        let mut guard = self.inner_guard()?;

        if self.expire_if_needed(&mut guard, Instant::now()) {
            return Err(AppStateError::SessionExpired);
        }

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session.bind_existing_identical_target(root, target, approval))
    }

    /// First half of the initial-binding consent (Stage 1U-4 B1h): examine the
    /// selected target read-only and remember the result in the unlocked session.
    /// Internal: no command, event or UI is attached, and nothing is bound,
    /// written or created. See [`UnlockedVaultSession::prepare_initial_binding`].
    ///
    /// The outer error is "no live session" (`VaultLocked`/`SessionExpired`), and
    /// in that case the target is never opened. Unlike the passive sync checks,
    /// this is an explicit user action and therefore counts as activity. The
    /// application-state mutex, and with it the session and its exclusive OS
    /// lock, is held for the whole examination.
    pub fn prepare_initial_binding(
        &self,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
    ) -> Result<Result<InitialBindingPreview, InitialBindingRefusal>, AppStateError> {
        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        Ok(session.prepare_initial_binding(root, target))
    }

    /// Second half of the initial-binding consent (Stage 1U-4 B1h): spend the
    /// pending preparation and, if it is still current, run the guarded initial
    /// binding. Internal: no command, event or UI is attached. See
    /// [`UnlockedVaultSession::confirm_initial_binding`] for the order of checks
    /// and for why every call spends the preparation.
    ///
    /// The outer error is "no live session" (`VaultLocked`/`SessionExpired`);
    /// the preparation, if any, dies with the session. Like preparation, this is
    /// an explicit user action and counts as activity. The application-state
    /// mutex is held across the whole operation.
    pub fn confirm_initial_binding(
        &self,
        root: &SyncStateRoot,
        preparation_id: &str,
    ) -> Result<Result<InitialBindingOutcome, InitialBindingConfirmRefusal>, AppStateError> {
        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        Ok(session.confirm_initial_binding(root, preparation_id))
    }

    /// Discard the pending initial-binding preparation, if any. Idempotent: with
    /// no session there is nothing to discard, which is not an error. It neither
    /// observes expiry nor counts as activity.
    pub fn cancel_initial_binding(&self) -> Result<(), AppStateError> {
        let mut guard = self.inner_guard()?;

        if let Some(session) = guard.session.as_mut() {
            session.cancel_initial_binding();
        }

        Ok(())
    }

    /// Start a sync-binding file selection (Stage 1U-4 B1j-1): confirm a live
    /// session, void any pending initial-binding preparation of it, and return
    /// the identity of that session. The caller then opens a native file picker
    /// **without** holding the state mutex and passes the token back to
    /// [`prepare_initial_binding_for_session`](Self::prepare_initial_binding_for_session).
    ///
    /// An explicit user action, so it counts as activity. Voiding first means a
    /// selection that is cancelled, invalid or abandoned can never leave an older
    /// approval usable.
    ///
    /// `attempt` becomes THE current attempt, superseding any older one, unless it
    /// was already cancelled (`AttemptSuperseded`: nothing is voided, no picker
    /// should open). See [`BindingAttemptId`] for its limited purpose.
    pub fn begin_sync_binding_selection(
        &self,
        attempt: BindingAttemptId,
    ) -> Result<SessionToken, AppStateError> {
        let mut guard = self.active_session_guard()?;

        if guard.cancelled_binding_attempts.contains(&attempt) {
            return Err(AppStateError::AttemptSuperseded);
        }

        let token = SessionToken(guard.session_epoch);

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        session.cancel_initial_binding();

        guard.binding_attempt = Some(attempt);

        Ok(token)
    }

    /// [`prepare_initial_binding`](Self::prepare_initial_binding), but only for
    /// the session that issued `token`. The token is checked under the same lock
    /// that runs the preparation, so a lock, expiry or a different vault unlocked
    /// while the picker was open yields [`AppStateError::SessionChanged`] (or
    /// `VaultLocked`/`SessionExpired`) and prepares nothing, for any session.
    ///
    /// Within the session, only the current `attempt` may prepare: a picker that
    /// finishes late for a cancelled or superseded attempt yields
    /// `AttemptSuperseded` and prepares nothing. Checked under the same lock.
    pub fn prepare_initial_binding_for_session(
        &self,
        token: SessionToken,
        attempt: BindingAttemptId,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
    ) -> Result<Result<InitialBindingPreview, InitialBindingRefusal>, AppStateError> {
        let mut guard = self.active_session_guard()?;

        if SessionToken(guard.session_epoch) != token {
            return Err(AppStateError::SessionChanged);
        }

        if guard.binding_attempt != Some(attempt) {
            return Err(AppStateError::AttemptSuperseded);
        }

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        Ok(session.prepare_initial_binding(root, target))
    }

    /// Cancel one sync-binding attempt: it can no longer prepare, and if it is the
    /// current attempt its pending preparation (if any) is discarded. An attempt
    /// that is not the current one discards nothing, so a late cancel from an old
    /// dialog never touches what a newer attempt prepared. The id is remembered
    /// (bounded) so a cancel that overtakes its own `begin_sync_binding_selection`
    /// still wins. Idempotent; neither observes expiry nor counts as activity.
    pub fn cancel_binding_attempt(&self, attempt: BindingAttemptId) -> Result<(), AppStateError> {
        let mut guard = self.inner_guard()?;

        guard.remember_cancelled(attempt);

        if guard.binding_attempt == Some(attempt) {
            guard.binding_attempt = None;

            if let Some(session) = guard.session.as_mut() {
                session.cancel_initial_binding();
            }
        }

        Ok(())
    }

    /// Sanitized, read-only summary of the unlocked vault's synchronization
    /// binding (Stage 1U-4 B1i). Internal: no command or UI is attached. See
    /// [`UnlockedVaultSession::binding_status`].
    ///
    /// Fails with `VaultLocked`/`SessionExpired` unless a session is live. Like
    /// `load_sync_state` it observes expiry but does not count as user activity:
    /// a status check must never keep a vault unlocked.
    pub fn binding_status(&self, root: &SyncStateRoot) -> Result<BindingStatus, AppStateError> {
        let mut guard = self.inner_guard()?;

        if self.expire_if_needed(&mut guard, Instant::now()) {
            return Err(AppStateError::SessionExpired);
        }

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session.binding_status(root))
    }

    /// First half of the explicit binding reset (Stage 1U-4 B1i): examine the
    /// stored state read-only and remember it in the unlocked session. Internal:
    /// no command, event or UI is attached, and nothing is removed. See
    /// [`UnlockedVaultSession::prepare_binding_reset`] for which states are
    /// resettable.
    ///
    /// The outer error is "no live session" (`VaultLocked`/`SessionExpired`);
    /// the inner result is the session's own. This is an explicit user action
    /// and therefore counts as activity. It voids a pending initial-binding
    /// preparation. The application-state mutex is held for the whole call.
    pub fn prepare_binding_reset(
        &self,
        root: &SyncStateRoot,
    ) -> Result<Result<BindingResetPreview, BindingResetRefusal>, AppStateError> {
        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        Ok(session.prepare_binding_reset(root))
    }

    /// [`prepare_binding_reset`](Self::prepare_binding_reset) on behalf of one reset
    /// `attempt`, which becomes the owner of the pending preparation if it
    /// succeeds. An attempt cancelled before this call arrives (a closed dialog
    /// whose request was still in flight) prepares nothing and voids nothing
    /// (`AttemptSuperseded`). The check and the preparation share one lock. See
    /// [`BindingAttemptId`] for the attempt's limited purpose: it is a label, not
    /// an approval.
    pub fn prepare_binding_reset_for_attempt(
        &self,
        attempt: BindingAttemptId,
        root: &SyncStateRoot,
    ) -> Result<Result<BindingResetPreview, BindingResetRefusal>, AppStateError> {
        let mut guard = self.active_session_guard()?;

        if guard.cancelled_binding_attempts.contains(&attempt) {
            return Err(AppStateError::AttemptSuperseded);
        }

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        let outcome = session.prepare_binding_reset(root);

        // A failed preparation also voided the previous one, so nobody owns it.
        guard.reset_attempt = outcome.is_ok().then_some(attempt);

        Ok(outcome)
    }

    /// Second half of the explicit binding reset (Stage 1U-4 B1i): spend the
    /// pending preparation and, if the stored state is still exactly what it
    /// examined, remove it. Internal: no command, event or UI is attached. See
    /// [`UnlockedVaultSession::confirm_binding_reset`] for the order of checks,
    /// the definite and ambiguous outcomes, and why this is not an atomic
    /// compare-and-swap.
    ///
    /// The outer error is "no live session" (`VaultLocked`/`SessionExpired`); the
    /// preparation, if any, dies with the session. Like preparation, this is an
    /// explicit user action and counts as activity. The application-state mutex
    /// is held across the whole operation.
    pub fn confirm_binding_reset(
        &self,
        root: &SyncStateRoot,
        preparation_id: &str,
    ) -> Result<Result<BindingResetOutcome, BindingResetConfirmRefusal>, AppStateError> {
        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        Ok(session.confirm_binding_reset(root, preparation_id))
    }

    /// Discard the pending reset preparation, if any. Idempotent: with no session
    /// there is nothing to discard, which is not an error. It neither observes
    /// expiry nor counts as activity.
    pub fn cancel_binding_reset(&self) -> Result<(), AppStateError> {
        let mut guard = self.inner_guard()?;

        if let Some(session) = guard.session.as_mut() {
            session.cancel_binding_reset();
        }

        Ok(())
    }

    /// Cancel one reset attempt: it can no longer prepare, and if it owns the
    /// pending reset preparation that preparation is discarded. An attempt that
    /// does not own it discards nothing, and an initial-binding approval or
    /// attempt is never touched. Idempotent; neither observes expiry nor counts as
    /// activity.
    pub fn cancel_reset_attempt(&self, attempt: BindingAttemptId) -> Result<(), AppStateError> {
        let mut guard = self.inner_guard()?;

        guard.remember_cancelled(attempt);

        if guard.reset_attempt == Some(attempt) {
            guard.reset_attempt = None;

            if let Some(session) = guard.session.as_mut() {
                session.cancel_binding_reset();
            }
        }

        Ok(())
    }

    /// Start a copy-creation destination selection (Stage 1U-4 B2b): confirm a
    /// live session, void this flow's own pending preparation and return the
    /// identity of that session. The caller then opens the native save dialog
    /// **without** holding the state mutex and passes the token back to
    /// [`prepare_copy_creation_for_session`](Self::prepare_copy_creation_for_session).
    /// Internal: no command is registered yet.
    ///
    /// An explicit user action, so it counts as activity; nothing keeps the
    /// session alive while the dialog is open, so a long-open dialog can end in
    /// `SessionExpired`. Only the copy-creation preparation is voided here: a
    /// binding or reset approval is untouched (the next preparation voids them,
    /// as every B1h/B1i/B2a preparation does). `attempt` becomes THE current copy
    /// attempt unless it was already cancelled (`AttemptSuperseded`: nothing is
    /// voided, no dialog should open). See [`BindingAttemptId`].
    pub fn begin_copy_creation_selection(
        &self,
        attempt: BindingAttemptId,
    ) -> Result<SessionToken, AppStateError> {
        let mut guard = self.active_session_guard()?;

        if guard.cancelled_binding_attempts.contains(&attempt) {
            return Err(AppStateError::AttemptSuperseded);
        }

        let token = SessionToken(guard.session_epoch);

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        session.cancel_copy_creation();

        guard.copy_attempt = Some(attempt);

        Ok(token)
    }

    /// [`UnlockedVaultSession::prepare_copy_creation`], but only for the session
    /// that issued `token` and only for the current copy `attempt`. Both are
    /// compared under the same lock that runs the preparation and **before** the
    /// session is touched, because a preparation voids every other pending
    /// approval: a late result of a closed, superseded or replaced dialog fails
    /// with `SessionChanged` / `AttemptSuperseded` and voids nothing.
    ///
    /// The attempt keeps its authority only if the preparation succeeds (it then
    /// owns the pending preparation); a refusal spends it. Internal. An explicit
    /// user action, so it counts as activity. The state mutex is held for the
    /// whole read-only examination.
    pub fn prepare_copy_creation_for_session(
        &self,
        token: SessionToken,
        attempt: BindingAttemptId,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
    ) -> Result<Result<CopyCreationPreview, CopyCreationRefusal>, AppStateError> {
        let mut guard = self.active_session_guard()?;

        if SessionToken(guard.session_epoch) != token {
            return Err(AppStateError::SessionChanged);
        }

        if guard.copy_attempt != Some(attempt) {
            return Err(AppStateError::AttemptSuperseded);
        }

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        let outcome = session.prepare_copy_creation(root, target);

        guard.copy_attempt = outcome.is_ok().then_some(attempt);

        Ok(outcome)
    }

    /// Second half of the copy-creation consent (Stage 1U-4 B2b): spend the
    /// pending preparation and, if it is still current, create the copy. Internal.
    /// See [`UnlockedVaultSession::confirm_copy_creation`] for the checks, the
    /// definite and the ambiguous outcomes, and why every call spends the
    /// preparation.
    ///
    /// Takes only the Rust-issued preparation id: no path, no bytes, no flag. The
    /// outer error is "no live session"; the preparation dies with the session.
    /// An explicit user action, so it counts as activity. Every call that reaches
    /// the session also ends the current copy attempt's authority, because the
    /// preparation it owned is spent. The state mutex is held across the whole
    /// creation.
    pub fn confirm_copy_creation(
        &self,
        root: &SyncStateRoot,
        preparation_id: &str,
    ) -> Result<Result<CopyCreationOutcome, CopyCreationConfirmRefusal>, AppStateError> {
        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        let outcome = session.confirm_copy_creation(root, preparation_id);

        guard.copy_attempt = None;

        Ok(outcome)
    }

    /// Cancel one copy-creation attempt: it can no longer begin or prepare, and if
    /// it is the current attempt its pending preparation (if any) is discarded. An
    /// attempt that is not the current one discards nothing, and a binding or
    /// reset approval is never touched. The id is remembered (bounded) so a cancel
    /// that overtakes its own `begin_copy_creation_selection` still wins.
    /// Idempotent; neither observes expiry nor counts as activity.
    pub fn cancel_copy_creation_attempt(
        &self,
        attempt: BindingAttemptId,
    ) -> Result<(), AppStateError> {
        let mut guard = self.inner_guard()?;

        guard.remember_cancelled(attempt);

        if guard.copy_attempt == Some(attempt) {
            guard.copy_attempt = None;

            if let Some(session) = guard.session.as_mut() {
                session.cancel_copy_creation();
            }
        }

        Ok(())
    }

    fn active_session_guard(&self) -> Result<MutexGuard<'_, AppStateInner>, AppStateError> {
        let mut guard = self.inner_guard()?;

        let now = Instant::now();

        if self.expire_if_needed(&mut guard, now) {
            return Err(AppStateError::SessionExpired);
        }

        if guard.session.is_none() {
            return Err(AppStateError::VaultLocked);
        }

        guard.last_activity = Some(now);

        Ok(guard)
    }

    fn expire_if_needed(&self, guard: &mut AppStateInner, now: Instant) -> bool {
        if guard.session.is_none() {
            /*
             * A pending notification may belong to an expiry
             * already caused by another protected operation.
             * Do not clear that notification here.
             */
            guard.last_activity = None;
            return false;
        }

        let expired = match guard.last_activity {
            Some(last_activity) => {
                now.saturating_duration_since(last_activity) >= self.auto_lock_timeout
            }

            /*
             * An unlocked session without an activity
             * timestamp is inconsistent. Fail closed.
             */
            None => true,
        };

        if expired {
            /*
             * Auto-lock never calls save().
             *
             * Normal CRUD mutations are transactional and
             * already persisted before entering live state.
             * More importantly, an inactivity lock must not
             * be prevented by storage/I/O failure.
             *
             * Dropping UnlockedVaultSession destroys the
             * Vault Key and decrypted VaultData.
             */
            guard.session = None;
            guard.last_activity = None;
            guard.expiry_notification_pending = true;
        }

        expired
    }
    fn inner_guard(&self) -> Result<MutexGuard<'_, AppStateInner>, AppStateError> {
        self.inner
            .lock()
            .map_err(|_| AppStateError::StateUnavailable)
    }

    #[cfg(test)]
    fn with_auto_lock_timeout(timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(AppStateInner::default()),
            auto_lock_timeout: timeout,
        }
    }

    #[cfg(test)]
    fn age_session_for_test(&self, age: Duration) {
        let mut guard = self.inner.lock().unwrap();

        assert!(guard.session.is_some(), "test requires unlocked session");

        guard.last_activity = Some(
            Instant::now()
                .checked_sub(age)
                .expect("test activity age is representable"),
        );
    }

    #[cfg(test)]
    fn last_activity_for_test(&self) -> Option<Instant> {
        self.inner.lock().unwrap().last_activity
    }
}

fn status_from_session(session: Option<&UnlockedVaultSession>) -> VaultStatus {
    match session {
        Some(session) => VaultStatus {
            unlocked: true,
            dirty: session.is_dirty(),
        },

        None => VaultStatus {
            unlocked: false,
            dirty: false,
        },
    }
}

fn unix_time_ms() -> Result<i64, AppStateError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppStateError::InvalidClock)?;

    i64::try_from(duration.as_millis()).map_err(|_| AppStateError::InvalidClock)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::vault::storage::save_envelope_atomic;
    use localvault_core::vault::{data::VaultEntry, format::create_envelope};

    const MASTER_PASSWORD: &str = "app-state-master-password-test-only";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    #[test]
    fn new_app_state_is_locked() {
        let state = AppState::default();

        let status = state.status().unwrap();

        assert!(!status.unlocked);
        assert!(!status.dirty);
    }

    #[test]
    fn create_vault_unlocks_state_and_blocks_second_active_vault() {
        let temp = tempdir().unwrap();

        let first_path = temp.path().join("first.lvault");

        let second_path = temp.path().join("second.lvault");

        let state = AppState::default();

        let status = state.create_vault(first_path, password()).unwrap();

        assert!(status.unlocked);
        assert!(!status.dirty);

        let result = state.create_vault(second_path.clone(), password());

        assert!(matches!(result, Err(AppStateError::AlreadyUnlocked)));

        assert!(!second_path.exists());
    }

    #[test]
    fn wrong_password_unlock_leaves_state_locked() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let session = UnlockedVaultSession::create(&path, password(), 1_700_000_000_000).unwrap();

        session.lock();

        let state = AppState::default();

        let result = state.unlock_vault(path, Zeroizing::new("wrong-password".to_owned()));

        assert!(result.is_err());

        let status = state.status().unwrap();

        assert!(!status.unlocked);
        assert!(!status.dirty);
    }

    #[test]
    fn lock_saves_dirty_data_before_dropping_session() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path.clone(), password()).unwrap();

        {
            let mut guard = state.inner.lock().unwrap();

            let session = guard.session.as_mut().unwrap();

            let next_ms = session.data().updated_at_ms + 1;

            let mut entry = VaultEntry::new("AppState Entry", next_ms).unwrap();

            entry.password = "APP_STATE_TEST_SECRET".to_owned();

            let data = session.data_mut();

            data.entries.push(entry);
            data.updated_at_ms = next_ms;
        }

        let before = state.status().unwrap();

        assert!(before.unlocked);
        assert!(before.dirty);

        let locked = state.lock_vault().unwrap();

        assert!(!locked.unlocked);
        assert!(!locked.dirty);

        state.unlock_vault(path, password()).unwrap();

        {
            let guard = state.inner.lock().unwrap();

            let session = guard.session.as_ref().unwrap();

            assert_eq!(session.data().entries.len(), 1);

            assert_eq!(session.data().entries[0].password, "APP_STATE_TEST_SECRET");
        }

        state.lock_vault().unwrap();
    }

    #[test]
    fn failed_lock_save_keeps_dirty_session_alive() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path.clone(), password()).unwrap();

        {
            let mut guard = state.inner.lock().unwrap();

            let session = guard.session.as_mut().unwrap();

            let next_ms = session.data().updated_at_ms + 1;

            let mut entry = VaultEntry::new("Unsaved AppState Entry", next_ms).unwrap();

            entry.password = "UNSAVED_APP_STATE_SECRET".to_owned();

            let data = session.data_mut();

            data.entries.push(entry);
            data.updated_at_ms = next_ms;
        }

        let external = create_envelope(MASTER_PASSWORD, b"external-change").unwrap();

        save_envelope_atomic(&path, &external).unwrap();

        let result = state.lock_vault();

        assert!(matches!(
            result,
            Err(AppStateError::Session(SessionError::ChangedOnDisk))
        ));

        let status = state.status().unwrap();

        assert!(status.unlocked);
        assert!(status.dirty);

        let guard = state.inner.lock().unwrap();

        let session = guard.session.as_ref().unwrap();

        assert_eq!(session.data().entries.len(), 1);

        assert_eq!(
            session.data().entries[0].password,
            "UNSAVED_APP_STATE_SECRET"
        );
    }

    #[test]
    fn locking_already_locked_state_is_idempotent() {
        let state = AppState::default();

        let status = state.lock_vault().unwrap();

        assert!(!status.unlocked);
        assert!(!status.dirty);
    }

    #[test]
    fn status_does_not_refresh_activity_deadline() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(60));

        state.create_vault(path, password()).unwrap();

        let before = state.last_activity_for_test().unwrap();

        let status = state.status().unwrap();

        let after = state.last_activity_for_test().unwrap();

        assert!(status.unlocked);
        assert_eq!(before, after);
    }

    #[test]
    fn status_expires_inactive_session_and_drops_it() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(60));

        state.create_vault(path, password()).unwrap();

        state.age_session_for_test(Duration::from_secs(61));

        let status = state.status().unwrap();

        assert!(!status.unlocked);
        assert!(!status.dirty);

        let guard = state.inner.lock().unwrap();

        assert!(guard.session.is_none());

        assert!(guard.last_activity.is_none());
    }

    #[test]
    fn activity_heartbeat_refreshes_deadline() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(60));

        state.create_vault(path, password()).unwrap();

        state.age_session_for_test(Duration::from_secs(50));

        let before = state.last_activity_for_test().unwrap();

        state.touch_activity().unwrap();

        let after = state.last_activity_for_test().unwrap();

        assert!(after > before);
        assert!(state.status().unwrap().unlocked);
    }

    #[test]
    fn expired_heartbeat_fails_closed_and_drops_session() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(60));

        state.create_vault(path, password()).unwrap();

        state.age_session_for_test(Duration::from_secs(61));

        let result = state.touch_activity();

        assert!(matches!(result, Err(AppStateError::SessionExpired)));

        assert!(!state.status().unwrap().unlocked);
    }

    #[test]
    fn explicit_expiry_reports_transition_only_once() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(60));

        state.create_vault(path, password()).unwrap();

        state.age_session_for_test(Duration::from_secs(61));

        assert!(state.expire_inactive_session().unwrap());

        assert!(!state.expire_inactive_session().unwrap());
    }

    #[test]
    fn expiry_from_protected_activity_remains_pending_for_watcher() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(60));

        state.create_vault(path, password()).unwrap();

        state.age_session_for_test(Duration::from_secs(61));

        assert!(matches!(
            state.touch_activity(),
            Err(AppStateError::SessionExpired)
        ));

        /*
         * touch_activity already destroyed the session.
         * Watcher must still receive exactly one event.
         */
        assert!(state.expire_inactive_session().unwrap());

        assert!(!state.expire_inactive_session().unwrap());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_timeout_parser_accepts_only_safe_bounded_values() {
        assert_eq!(
            parse_dev_auto_lock_timeout("20"),
            Some(Duration::from_secs(20))
        );

        assert_eq!(parse_dev_auto_lock_timeout("4"), None);

        assert_eq!(parse_dev_auto_lock_timeout("901"), None);

        assert_eq!(parse_dev_auto_lock_timeout("not-a-number"), None);
    }

    // -- Stage 1U-4 B1b: sync-state load through the application state --------
    //
    // Scratch lives under the git-ignored `.qa-local/sync-state-b1-tests/`,
    // never `%TEMP%`.

    fn qa_scratch(name: &str) -> tempfile::TempDir {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("sync-state-b1-tests");

        std::fs::create_dir_all(&base).unwrap();

        tempfile::Builder::new()
            .prefix(&format!("{name}-"))
            .tempdir_in(&base)
            .unwrap()
    }

    #[test]
    fn sync_state_load_requires_a_live_session_and_touches_nothing_otherwise() {
        let scratch = qa_scratch("b1b-appstate-locked");

        let app_local = scratch.path().join("app-local");

        let root = SyncStateRoot::for_test(app_local.clone());

        let state = AppState::default();

        assert!(matches!(
            state.load_sync_state(&root),
            Err(AppStateError::VaultLocked)
        ));

        let path = scratch.path().join("vault.lvault");

        state.create_vault(path, password()).unwrap();

        assert_eq!(
            state.load_sync_state(&root).unwrap(),
            SessionSyncState::NotConfigured
        );

        state.lock_vault().unwrap();

        assert!(matches!(
            state.load_sync_state(&root),
            Err(AppStateError::VaultLocked)
        ));

        assert!(!app_local.exists());
    }

    #[test]
    fn sync_state_load_does_not_count_as_activity_and_fails_after_expiry() {
        let scratch = qa_scratch("b1b-appstate-expiry");

        let root = SyncStateRoot::for_test(scratch.path().join("app-local"));

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state
            .create_vault(scratch.path().join("vault.lvault"), password())
            .unwrap();

        state.age_session_for_test(Duration::from_secs(10));

        let before = state.last_activity_for_test();

        assert_eq!(
            state.load_sync_state(&root).unwrap(),
            SessionSyncState::NotConfigured
        );

        assert_eq!(state.last_activity_for_test(), before);

        state.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            state.load_sync_state(&root),
            Err(AppStateError::SessionExpired)
        ));

        assert!(!state.status().unwrap().unlocked);

        assert!(matches!(
            state.load_sync_state(&root),
            Err(AppStateError::VaultLocked)
        ));

        assert!(!root.path().exists());
    }

    // -- Stage 1U-4 B1c: recording a remote observation through the state -------
    //
    // The success path (a real binding, real candidate envelopes, store fault
    // injection) is tested in `sync_state_store::tests`, next to the scratch and
    // fault helpers. Here: the live-session and activity rules only.

    fn observation_target() -> Locator {
        Locator::new(r"\\?\D:\Synthetic\Remote\target.lvault").unwrap()
    }

    #[test]
    fn recording_an_observation_requires_a_live_session_and_touches_nothing_otherwise() {
        let scratch = qa_scratch("b1c-appstate-locked");

        let app_local = scratch.path().join("app-local");

        let root = SyncStateRoot::for_test(app_local.clone());

        let state = AppState::default();

        assert!(matches!(
            state.record_remote_observation(&root, &observation_target(), b"candidate"),
            Err(AppStateError::VaultLocked)
        ));

        state
            .create_vault(scratch.path().join("vault.lvault"), password())
            .unwrap();

        // A live session with no binding: refused, and nothing is created.
        assert_eq!(
            state
                .record_remote_observation(&root, &observation_target(), b"candidate")
                .unwrap(),
            Err(RemoteObservationRefusal::NotConfigured)
        );

        state.lock_vault().unwrap();

        assert!(matches!(
            state.record_remote_observation(&root, &observation_target(), b"candidate"),
            Err(AppStateError::VaultLocked)
        ));

        assert!(!app_local.exists());
    }

    #[test]
    fn recording_an_observation_does_not_count_as_activity_and_fails_after_expiry() {
        let scratch = qa_scratch("b1c-appstate-expiry");

        let root = SyncStateRoot::for_test(scratch.path().join("app-local"));

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state
            .create_vault(scratch.path().join("vault.lvault"), password())
            .unwrap();

        state.age_session_for_test(Duration::from_secs(10));

        let before = state.last_activity_for_test();

        assert_eq!(
            state
                .record_remote_observation(&root, &observation_target(), b"candidate")
                .unwrap(),
            Err(RemoteObservationRefusal::NotConfigured)
        );

        assert_eq!(state.last_activity_for_test(), before);

        state.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            state.record_remote_observation(&root, &observation_target(), b"candidate"),
            Err(AppStateError::SessionExpired)
        ));

        assert!(matches!(
            state.record_remote_observation(&root, &observation_target(), b"candidate"),
            Err(AppStateError::VaultLocked)
        ));

        assert!(!root.path().exists());
    }

    // -- Stage 1U-4 B3a: read-only update-readiness assessment ------------------
    //
    // The decisions themselves are tested next to the session
    // (`session/target_update.rs`). Here: the live-session, lock, expiry and
    // activity rules, plus one real end-to-end assessment. Scratch lives under
    // the git-ignored `.qa-local/sync-update-b3-tests/`, never `%TEMP%`.

    fn b3_scratch(name: &str) -> tempfile::TempDir {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("sync-update-b3-tests");

        std::fs::create_dir_all(&base).unwrap();

        tempfile::Builder::new()
            .prefix(&format!("{name}-"))
            .tempdir_in(&base)
            .unwrap()
    }

    #[test]
    fn update_assessment_requires_a_live_session_and_touches_nothing_otherwise() {
        let scratch = b3_scratch("b3a-appstate-locked");

        let app_local = scratch.path().join("app-local");

        let root = SyncStateRoot::for_test(app_local.clone());

        let state = AppState::default();

        assert!(matches!(
            state.assess_bound_target_update(&root),
            Err(AppStateError::VaultLocked)
        ));

        state
            .create_vault(scratch.path().join("vault.lvault"), password())
            .unwrap();

        // A live session with no binding: classified, and nothing is created.
        assert_eq!(
            state.assess_bound_target_update(&root).unwrap(),
            UpdateReadiness::Blocked(crate::vault::session::UpdateBlock::NotConfigured)
        );

        state.lock_vault().unwrap();

        assert!(matches!(
            state.assess_bound_target_update(&root),
            Err(AppStateError::VaultLocked)
        ));

        assert!(!app_local.exists());
    }

    #[test]
    fn update_assessment_does_not_count_as_activity_and_fails_after_expiry() {
        let scratch = b3_scratch("b3a-appstate-expiry");

        let root = SyncStateRoot::for_test(scratch.path().join("app-local"));

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state
            .create_vault(scratch.path().join("vault.lvault"), password())
            .unwrap();

        state.age_session_for_test(Duration::from_secs(10));

        let before = state.last_activity_for_test();

        assert_eq!(
            state.assess_bound_target_update(&root).unwrap(),
            UpdateReadiness::Blocked(crate::vault::session::UpdateBlock::NotConfigured)
        );

        assert_eq!(state.last_activity_for_test(), before);

        state.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            state.assess_bound_target_update(&root),
            Err(AppStateError::SessionExpired)
        ));

        assert!(!state.status().unwrap().unlocked);

        assert!(matches!(
            state.assess_bound_target_update(&root),
            Err(AppStateError::VaultLocked)
        ));

        assert!(!root.path().exists());
    }

    #[test]
    fn update_assessment_of_a_real_binding_changes_no_file_and_no_activity() {
        use crate::vault::{handle_ops::test_support::snapshot, session::UpdateBlock};

        let scratch = b3_scratch("b3a-appstate-bound");

        let root = SyncStateRoot::for_test(scratch.path().join("app-local"));
        let vault = scratch.path().join("vault.lvault");
        let copy = scratch.path().join("copy.lvault");

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state.create_vault(vault.clone(), password()).unwrap();

        std::fs::copy(&vault, &copy).unwrap();

        let target = SyncFileTarget::from_path(&copy).unwrap();

        {
            let guard = state.inner.lock().unwrap();

            assert_eq!(
                guard
                    .session
                    .as_ref()
                    .unwrap()
                    .bind_existing_identical_target(
                        &root,
                        &target,
                        InitialBindingApproval::for_test(&target),
                    ),
                Ok(InitialBindingOutcome::BoundAndVerified)
            );
        }

        state.age_session_for_test(Duration::from_secs(10));

        let activity = state.last_activity_for_test();
        let before = snapshot(scratch.path());

        assert_eq!(
            state.assess_bound_target_update(&root).unwrap(),
            UpdateReadiness::UpToDate
        );

        // Unsaved changes are classified without touching any file.
        {
            let mut guard = state.inner.lock().unwrap();

            guard.session.as_mut().unwrap().data_mut().updated_at_ms += 1;
        }

        assert_eq!(
            state.assess_bound_target_update(&root).unwrap(),
            UpdateReadiness::Blocked(UpdateBlock::UnsavedChanges)
        );

        assert_eq!(snapshot(scratch.path()), before);
        assert_eq!(state.last_activity_for_test(), activity);
    }

    // -- Stage 1U-4 B1e: observing a local file target through the state --------
    //
    // The ordering of the checks inside a session (the binding's target is
    // compared before the file is read) and every outcome are tested next to the
    // session. Here: the live-session, lock and activity rules, plus one real
    // end-to-end observation. Limit: a test cannot observe a read that never
    // happened; "the target was not opened without a live session" is shown by
    // the result being `VaultLocked`/`SessionExpired` instead of the
    // `AbsentOnDisk`/`TargetUnavailable` classification only a read can produce,
    // and by the session-level read counter.

    use crate::vault::{
        session::CategoryInput,
        sync_file_adapter::UnavailableReason,
        sync_state_store::{SyncStateStore, SYNC_STATE_DIRECTORY},
    };
    use localvault_core::{
        sync::{EnvelopeFingerprint, RemoteHighWater},
        sync_state::{
            BindingId, SyncBase, SyncCheckpoint, SyncState, VaultBindingTag, BINDING_SALT_LEN,
        },
    };

    struct Bound {
        scratch: tempfile::TempDir,
        vault: PathBuf,
        root: SyncStateRoot,
        target: SyncFileTarget,
        remote: PathBuf,
        original: SyncState,
        candidate: Vec<u8>,
    }

    fn checkpoint(high_water: u64) -> SyncBase {
        SyncBase::Based(
            SyncCheckpoint::new(
                EnvelopeFingerprint::of_bytes(&[1]),
                1,
                RemoteHighWater::new(high_water),
            )
            .unwrap(),
        )
    }

    fn state_with_high_water(
        local: &str,
        vault_id: uuid::Uuid,
        target: &str,
        high_water: u64,
    ) -> SyncState {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);

        SyncState::new(
            BindingId::new(uuid::Uuid::from_u128(0x1111_2222_3333_4444)).unwrap(),
            VaultBindingTag::derive(salt, vault_id).unwrap(),
            Locator::new(local).unwrap(),
            Locator::new(target).unwrap(),
            checkpoint(high_water),
            None,
        )
        .unwrap()
    }

    /// A vault with a published binding (high-water 5) whose target file is
    /// absent, and a genuine revision-9 candidate envelope of the same vault.
    /// The vault is locked again before this returns.
    fn bound_vault(name: &str) -> Bound {
        let scratch = qa_scratch(name);
        let vaults = scratch.path().join("vaults");
        let remote_dir = scratch.path().join("remote");

        std::fs::create_dir_all(&vaults).unwrap();
        std::fs::create_dir_all(&remote_dir).unwrap();

        let vault = vaults.join("vault.lvault");
        let remote = remote_dir.join("target.lvault");
        let root = SyncStateRoot::for_test(scratch.path().join("app-local"));

        let session = UnlockedVaultSession::create(&vault, password(), 1_700_000_000_000).unwrap();
        let local = crate::recent_vaults::normalize_existing_vault_path(&vault).unwrap();
        let target = SyncFileTarget::from_path(&remote).unwrap();
        let original = state_with_high_water(
            &local,
            session.data().vault_id,
            target.locator().as_str(),
            5,
        );

        SyncStateStore::new(root.path())
            .unwrap()
            .create(&original)
            .unwrap();

        session.lock();

        let copy_path = scratch.path().join("candidates").join("rev9.lvault");

        std::fs::create_dir_all(copy_path.parent().unwrap()).unwrap();
        std::fs::copy(&vault, &copy_path).unwrap();

        let mut copy = UnlockedVaultSession::unlock(&copy_path, password()).unwrap();

        for n in 0..9 {
            copy.create_category(
                CategoryInput {
                    name: format!("candidate-{n}"),
                },
                1_700_000_000_000 + n,
            )
            .unwrap();
        }

        assert_eq!(copy.data().revision, 9);
        copy.lock();

        let candidate = std::fs::read(&copy_path).unwrap();

        Bound {
            scratch,
            vault,
            root,
            target,
            remote,
            original,
            candidate,
        }
    }

    fn record_of(bound: &Bound) -> Vec<u8> {
        std::fs::read(
            bound
                .root
                .path()
                .join(SYNC_STATE_DIRECTORY)
                .read_dir()
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension().is_some_and(|ext| ext == "json"))
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn observing_a_target_requires_a_live_session_and_does_not_classify_the_file_otherwise() {
        let bound = bound_vault("b1e-appstate-locked");
        let state = AppState::default();
        let original = record_of(&bound);

        // The target file does not exist: a read would say `AbsentOnDisk`.
        assert!(!bound.remote.exists());
        assert!(matches!(
            state.observe_remote_target(&bound.root, &bound.target),
            Err(AppStateError::VaultLocked)
        ));

        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        assert_eq!(
            state
                .observe_remote_target(&bound.root, &bound.target)
                .unwrap(),
            Err(RemoteTargetRefusal::AbsentOnDisk)
        );
        assert_eq!(record_of(&bound), original);
        assert!(!bound.remote.exists(), "the observation created the target");

        state.lock_vault().unwrap();

        assert!(matches!(
            state.observe_remote_target(&bound.root, &bound.target),
            Err(AppStateError::VaultLocked)
        ));
        assert_eq!(record_of(&bound), original);

        drop(bound.scratch);
    }

    #[test]
    fn observing_a_target_through_the_state_changes_only_the_record() {
        let bound = bound_vault("b1e-appstate-success");

        std::fs::write(&bound.remote, &bound.candidate).unwrap();

        let vault_bytes = std::fs::read(&bound.vault).unwrap();
        let remote_bytes = std::fs::read(&bound.remote).unwrap();
        let state = AppState::default();

        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        assert_eq!(
            state
                .observe_remote_target(&bound.root, &bound.target)
                .unwrap(),
            Ok(RemoteObservationOutcome::HighWaterRaised)
        );

        let SyncBase::Based(old) = bound.original.base() else {
            panic!("expected a based state");
        };
        let expected = SyncState::new(
            bound.original.binding_id(),
            *bound.original.vault_tag(),
            bound.original.local_locator().clone(),
            bound.original.target_locator().clone(),
            SyncBase::Based(
                SyncCheckpoint::new(
                    *old.synced(),
                    old.synced_revision(),
                    RemoteHighWater::new(9),
                )
                .unwrap(),
            ),
            None,
        )
        .unwrap();

        assert_eq!(record_of(&bound), expected.encode().unwrap());

        // A second observation is a no-op, and the lock is still held by the
        // state's session.
        assert_eq!(
            state
                .observe_remote_target(&bound.root, &bound.target)
                .unwrap(),
            Ok(RemoteObservationOutcome::Unchanged)
        );
        assert!(matches!(
            UnlockedVaultSession::unlock(&bound.vault, password()),
            Err(crate::vault::session::SessionError::InUse)
        ));

        assert_eq!(std::fs::read(&bound.vault).unwrap(), vault_bytes);
        assert_eq!(std::fs::read(&bound.remote).unwrap(), remote_bytes);

        state.lock_vault().unwrap();

        assert!(matches!(
            state.observe_remote_target(&bound.root, &bound.target),
            Err(AppStateError::VaultLocked)
        ));

        drop(bound.scratch);
    }

    #[test]
    fn observing_a_target_does_not_count_as_activity_and_fails_after_expiry() {
        let bound = bound_vault("b1e-appstate-expiry");

        std::fs::write(&bound.remote, &bound.candidate).unwrap();

        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state.unlock_vault(bound.vault.clone(), password()).unwrap();
        state.age_session_for_test(Duration::from_secs(10));

        let before = state.last_activity_for_test();

        assert_eq!(
            state
                .observe_remote_target(&bound.root, &bound.target)
                .unwrap(),
            Ok(RemoteObservationOutcome::HighWaterRaised)
        );
        assert_eq!(state.last_activity_for_test(), before);

        // An unavailable target is reported, not retried, and is not activity.
        std::fs::remove_file(&bound.remote).unwrap();
        std::fs::create_dir(&bound.remote).unwrap();

        assert_eq!(
            state
                .observe_remote_target(&bound.root, &bound.target)
                .unwrap(),
            Err(RemoteTargetRefusal::TargetUnavailable(
                UnavailableReason::UnexpectedObject
            ))
        );
        assert_eq!(state.last_activity_for_test(), before);

        let record_before_expiry = record_of(&bound);

        state.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            state.observe_remote_target(&bound.root, &bound.target),
            Err(AppStateError::SessionExpired)
        ));
        assert!(!state.status().unwrap().unlocked);
        assert!(matches!(
            state.observe_remote_target(&bound.root, &bound.target),
            Err(AppStateError::VaultLocked)
        ));
        assert_eq!(record_of(&bound), record_before_expiry);

        drop(bound.scratch);
    }

    // -- Stage 1U-4 B1f: initial binding through the state ----------------------
    //
    // The order of checks, every refusal and every persistence failure class are
    // tested next to the session and the store. Here: the live-session, lock and
    // activity rules, plus one real end-to-end binding. As for B1e, "the target
    // was not opened without a live session" is shown by the result being
    // `VaultLocked`/`SessionExpired` and by the target being a path a read would
    // classify differently. There is no user-confirmation flow: the approval is
    // the test-only constructor.

    use crate::vault::session::{
        InitialBindingApproval, InitialBindingOutcome, InitialBindingRefusal,
    };

    struct Unbound {
        scratch: tempfile::TempDir,
        vault: PathBuf,
        root: SyncStateRoot,
        target: SyncFileTarget,
        remote: PathBuf,
    }

    /// A vault with no sync state, and an identical byte copy as the target. The
    /// vault is locked again before this returns.
    fn unbound_vault(name: &str) -> Unbound {
        let scratch = qa_scratch(name);
        let vaults = scratch.path().join("vaults");
        let remote_dir = scratch.path().join("remote");

        std::fs::create_dir_all(&vaults).unwrap();
        std::fs::create_dir_all(&remote_dir).unwrap();

        let vault = vaults.join("vault.lvault");
        let remote = remote_dir.join("target.lvault");
        let root = SyncStateRoot::for_test(scratch.path().join("app-local"));

        UnlockedVaultSession::create(&vault, password(), 1_700_000_000_000)
            .unwrap()
            .lock();

        std::fs::copy(&vault, &remote).unwrap();

        let target = SyncFileTarget::from_path(&remote).unwrap();

        Unbound {
            scratch,
            vault,
            root,
            target,
            remote,
        }
    }

    fn approve(unbound: &Unbound) -> InitialBindingApproval {
        InitialBindingApproval::for_test(&unbound.target)
    }

    #[test]
    fn binding_a_target_requires_a_live_session_and_creates_nothing_otherwise() {
        let unbound = unbound_vault("b1f-appstate-locked");
        let state = AppState::default();

        assert!(matches!(
            state.bind_existing_identical_target(&unbound.root, &unbound.target, approve(&unbound)),
            Err(AppStateError::VaultLocked)
        ));
        assert!(!unbound.root.path().exists());

        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();

        assert_eq!(
            state
                .bind_existing_identical_target(&unbound.root, &unbound.target, approve(&unbound))
                .unwrap(),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );

        // The binding is visible to the unchanged load, through the same state.
        let SessionSyncState::Bound(bound) = state.load_sync_state(&unbound.root).unwrap() else {
            panic!("the binding was not retained");
        };

        assert_eq!(bound.state().target_locator(), unbound.target.locator());

        // A second attempt is a refusal, not a replacement.
        let record = std::fs::read_dir(unbound.root.path().join(SYNC_STATE_DIRECTORY))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();
        let bytes = std::fs::read(&record).unwrap();

        assert_eq!(
            state
                .bind_existing_identical_target(&unbound.root, &unbound.target, approve(&unbound))
                .unwrap(),
            Err(InitialBindingRefusal::ExistingBinding)
        );
        assert_eq!(std::fs::read(&record).unwrap(), bytes);

        state.lock_vault().unwrap();

        assert!(matches!(
            state.bind_existing_identical_target(&unbound.root, &unbound.target, approve(&unbound)),
            Err(AppStateError::VaultLocked)
        ));
        assert_eq!(std::fs::read(&record).unwrap(), bytes);

        drop(unbound.scratch);
    }

    #[test]
    fn binding_does_not_count_as_activity_and_fails_after_expiry() {
        let unbound = unbound_vault("b1f-appstate-expiry");
        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();
        state.age_session_for_test(Duration::from_secs(10));

        let before = state.last_activity_for_test();

        // A refusal is not activity either: the target is made unavailable.
        std::fs::remove_file(&unbound.remote).unwrap();
        std::fs::create_dir(&unbound.remote).unwrap();

        assert_eq!(
            state
                .bind_existing_identical_target(&unbound.root, &unbound.target, approve(&unbound))
                .unwrap(),
            Err(InitialBindingRefusal::TargetUnavailable(
                UnavailableReason::UnexpectedObject
            ))
        );
        assert_eq!(state.last_activity_for_test(), before);
        assert!(!unbound.root.path().exists());

        std::fs::remove_dir(&unbound.remote).unwrap();
        std::fs::copy(&unbound.vault, &unbound.remote).unwrap();

        assert_eq!(
            state
                .bind_existing_identical_target(&unbound.root, &unbound.target, approve(&unbound))
                .unwrap(),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );
        assert_eq!(state.last_activity_for_test(), before);

        // Expiry: reported as such, the session is gone, nothing is created.
        let other = unbound_vault("b1f-appstate-expiry-second");
        let second = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        second
            .unlock_vault(other.vault.clone(), password())
            .unwrap();
        second.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            second.bind_existing_identical_target(&other.root, &other.target, approve(&other)),
            Err(AppStateError::SessionExpired)
        ));
        assert!(!second.status().unwrap().unlocked);
        assert!(matches!(
            second.bind_existing_identical_target(&other.root, &other.target, approve(&other)),
            Err(AppStateError::VaultLocked)
        ));
        assert!(!other.root.path().exists());

        drop(other.scratch);
        drop(unbound.scratch);
    }

    // -- Stage 1U-4 B1h: explicit initial-binding consent through the state ------
    //
    // The checks of the two steps are tested next to the session. Here: the
    // live-session rule, that a preparation dies with the session (lock, expiry,
    // a different vault), and the activity rules. Nothing outside these tests can
    // call the steps: no command or UI exists.

    use crate::vault::session::{InitialBindingConfirmRefusal, InitialBindingStale};

    fn prepared_id(state: &AppState, unbound: &Unbound) -> String {
        state
            .prepare_initial_binding(&unbound.root, &unbound.target)
            .unwrap()
            .unwrap()
            .preparation_id()
            .to_owned()
    }

    fn new_attempt() -> BindingAttemptId {
        BindingAttemptId::parse(&uuid::Uuid::new_v4().to_string()).unwrap()
    }

    #[test]
    fn only_the_current_attempt_may_prepare_and_an_expired_or_replaced_session_fails_closed() {
        let unbound = unbound_vault("b1j2-appstate-attempts");
        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();

        let (a, b) = (new_attempt(), new_attempt());

        let token_a = state.begin_sync_binding_selection(a).unwrap();
        let token_b = state.begin_sync_binding_selection(b).unwrap();

        // The session is the same; the attempt is not.
        assert!(matches!(
            state.prepare_initial_binding_for_session(token_a, a, &unbound.root, &unbound.target),
            Err(AppStateError::AttemptSuperseded)
        ));
        assert!(!unbound.root.path().exists());

        // A cancelled attempt cannot begin again, and cancelling is idempotent.
        state.cancel_binding_attempt(a).unwrap();
        state.cancel_binding_attempt(a).unwrap();
        assert!(matches!(
            state.begin_sync_binding_selection(a),
            Err(AppStateError::AttemptSuperseded)
        ));

        // The current attempt prepares; a stale cancel leaves it pending.
        let id = state
            .prepare_initial_binding_for_session(token_b, b, &unbound.root, &unbound.target)
            .unwrap()
            .unwrap()
            .preparation_id()
            .to_owned();

        state.cancel_binding_attempt(a).unwrap();

        // Expiry while the old picker is open: reported as such, nothing prepared.
        state.age_session_for_test(Duration::from_secs(31));

        let c = new_attempt();
        let late =
            state.prepare_initial_binding_for_session(token_b, c, &unbound.root, &unbound.target);

        assert!(matches!(late, Err(AppStateError::SessionExpired)));
        assert!(matches!(
            state.confirm_initial_binding(&unbound.root, &id),
            Err(AppStateError::VaultLocked)
        ));

        // A later session starts with no current attempt.
        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();

        assert!(matches!(
            state.prepare_initial_binding_for_session(token_b, b, &unbound.root, &unbound.target),
            Err(AppStateError::SessionChanged)
        ));
        assert!(!unbound.root.path().exists());
    }

    fn no_pending() -> Result<InitialBindingOutcome, InitialBindingConfirmRefusal> {
        Err(InitialBindingConfirmRefusal::Stale(
            InitialBindingStale::NoPendingApproval,
        ))
    }

    #[test]
    fn consent_requires_a_live_session_and_binds_only_after_a_separate_confirmation() {
        let unbound = unbound_vault("b1h-appstate-flow");
        let state = AppState::default();

        assert!(matches!(
            state.prepare_initial_binding(&unbound.root, &unbound.target),
            Err(AppStateError::VaultLocked)
        ));
        assert!(matches!(
            state.confirm_initial_binding(&unbound.root, "any"),
            Err(AppStateError::VaultLocked)
        ));
        // Cancelling with nothing to cancel is not an error.
        state.cancel_initial_binding().unwrap();
        assert!(!unbound.root.path().exists());

        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();

        let id = prepared_id(&state, &unbound);

        // Preparing bound nothing.
        assert_eq!(
            state.load_sync_state(&unbound.root).unwrap(),
            SessionSyncState::NotConfigured
        );
        assert!(!unbound.root.path().exists());

        assert_eq!(
            state.confirm_initial_binding(&unbound.root, &id).unwrap(),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );

        let SessionSyncState::Bound(bound) = state.load_sync_state(&unbound.root).unwrap() else {
            panic!("the binding was not retained");
        };

        assert_eq!(bound.state().target_locator(), unbound.target.locator());
        assert_eq!(
            state.confirm_initial_binding(&unbound.root, &id).unwrap(),
            no_pending()
        );

        state.cancel_initial_binding().unwrap();
        state.lock_vault().unwrap();
        state.cancel_initial_binding().unwrap();

        drop(unbound.scratch);
    }

    #[test]
    fn a_preparation_dies_with_a_lock_an_expiry_or_a_different_vault() {
        let unbound = unbound_vault("b1h-appstate-lifetime");
        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        // Lock, then unlock the same vault.
        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();

        let id = prepared_id(&state, &unbound);

        state.lock_vault().unwrap();

        assert!(matches!(
            state.confirm_initial_binding(&unbound.root, &id),
            Err(AppStateError::VaultLocked)
        ));

        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();

        assert_eq!(
            state.confirm_initial_binding(&unbound.root, &id).unwrap(),
            no_pending()
        );
        assert!(!unbound.root.path().exists());

        // Expiry: reported as such, the session and the preparation are gone.
        let id = prepared_id(&state, &unbound);

        state.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            state.confirm_initial_binding(&unbound.root, &id),
            Err(AppStateError::SessionExpired)
        ));
        assert!(!state.status().unwrap().unlocked);

        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();

        assert_eq!(
            state.confirm_initial_binding(&unbound.root, &id).unwrap(),
            no_pending()
        );
        assert!(!unbound.root.path().exists());

        // A preparation for one vault cannot be confirmed in another.
        let id = prepared_id(&state, &unbound);
        let other = unbound_vault("b1h-appstate-lifetime-other");

        state.lock_vault().unwrap();
        state.unlock_vault(other.vault.clone(), password()).unwrap();

        assert_eq!(
            state.confirm_initial_binding(&other.root, &id).unwrap(),
            no_pending()
        );
        assert_eq!(
            state.confirm_initial_binding(&unbound.root, &id).unwrap(),
            no_pending()
        );
        assert!(!other.root.path().exists());
        assert!(!unbound.root.path().exists());

        drop(other.scratch);
        drop(unbound.scratch);
    }

    #[test]
    fn preparing_and_confirming_count_as_activity_but_cancelling_does_not() {
        let unbound = unbound_vault("b1h-appstate-activity");
        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state
            .unlock_vault(unbound.vault.clone(), password())
            .unwrap();
        state.age_session_for_test(Duration::from_secs(10));

        let aged = state.last_activity_for_test().unwrap();

        // Cancelling is not an explicit user action on the vault.
        state.cancel_initial_binding().unwrap();
        assert_eq!(state.last_activity_for_test(), Some(aged));

        let id = prepared_id(&state, &unbound);
        let after_prepare = state.last_activity_for_test().unwrap();

        assert!(after_prepare > aged, "preparing did not refresh activity");

        state.age_session_for_test(Duration::from_secs(10));

        let aged = state.last_activity_for_test().unwrap();

        assert_eq!(
            state.confirm_initial_binding(&unbound.root, &id).unwrap(),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );
        assert!(
            state.last_activity_for_test().unwrap() > aged,
            "confirming did not refresh activity"
        );

        drop(unbound.scratch);
    }

    // -- Stage 1U-4 B1i: binding status and explicit reset through the state ----
    //
    // The eligibility rules, the evidence checks and every outcome are tested
    // next to the session and the store. Here: the live-session, lock, expiry,
    // vault-switch and activity rules, plus one real end-to-end reset.

    use crate::vault::session::{
        BindingResetOutcome, BindingResetRefusal, BindingResetStale, BindingState,
        PendingPushIndication,
    };

    type ResetConfirm =
        Result<BindingResetOutcome, crate::vault::session::BindingResetConfirmRefusal>;

    fn reset_no_pending() -> ResetConfirm {
        Err(crate::vault::session::BindingResetConfirmRefusal::Stale(
            BindingResetStale::NoPendingReset,
        ))
    }

    fn reset_prepared_id(state: &AppState, bound: &Bound) -> String {
        state
            .prepare_binding_reset(&bound.root)
            .unwrap()
            .expect("the reset preparation succeeds")
            .preparation_id()
            .to_owned()
    }

    #[test]
    fn binding_status_requires_a_live_session_and_is_not_activity() {
        let bound = bound_vault("b1i-appstate-status");
        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));
        let original = record_of(&bound);

        assert!(matches!(
            state.binding_status(&bound.root),
            Err(AppStateError::VaultLocked)
        ));

        state.unlock_vault(bound.vault.clone(), password()).unwrap();
        state.age_session_for_test(Duration::from_secs(10));

        let aged = state.last_activity_for_test();
        let status = state.binding_status(&bound.root).unwrap();

        assert!(matches!(status.state(), BindingState::Linked(_)));
        assert_eq!(status.target_path(), Some(bound.target.locator().as_str()));
        assert_eq!(status.pending_push(), PendingPushIndication::None);
        assert_eq!(state.last_activity_for_test(), aged);
        assert_eq!(record_of(&bound), original);

        state.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            state.binding_status(&bound.root),
            Err(AppStateError::SessionExpired)
        ));
        assert!(matches!(
            state.binding_status(&bound.root),
            Err(AppStateError::VaultLocked)
        ));
        assert_eq!(record_of(&bound), original);

        drop(bound.scratch);
    }

    #[test]
    fn a_reset_needs_a_live_session_and_does_not_outlive_it() {
        let bound = bound_vault("b1i-appstate-lifetime");
        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));
        let original = record_of(&bound);

        // Locked: nothing is examined or removed, and cancelling is not an error.
        assert!(matches!(
            state.prepare_binding_reset(&bound.root),
            Err(AppStateError::VaultLocked)
        ));
        assert!(matches!(
            state.confirm_binding_reset(&bound.root, "00000000-0000-4000-8000-000000000000"),
            Err(AppStateError::VaultLocked)
        ));
        assert!(state.cancel_binding_reset().is_ok());
        assert_eq!(record_of(&bound), original);

        // Lock after preparing: the same vault, unlocked again, has no preparation.
        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        let id = reset_prepared_id(&state, &bound);

        state.lock_vault().unwrap();

        assert!(matches!(
            state.confirm_binding_reset(&bound.root, &id),
            Err(AppStateError::VaultLocked)
        ));

        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        assert_eq!(
            state.confirm_binding_reset(&bound.root, &id).unwrap(),
            reset_no_pending()
        );
        assert_eq!(record_of(&bound), original);

        // Expiry: reported as such; the session and the preparation are gone.
        let id = reset_prepared_id(&state, &bound);

        state.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            state.confirm_binding_reset(&bound.root, &id),
            Err(AppStateError::SessionExpired)
        ));
        assert!(!state.status().unwrap().unlocked);

        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        assert_eq!(
            state.confirm_binding_reset(&bound.root, &id).unwrap(),
            reset_no_pending()
        );
        assert_eq!(record_of(&bound), original);

        // A preparation for one vault cannot be confirmed in another.
        let id = reset_prepared_id(&state, &bound);
        let other = bound_vault("b1i-appstate-lifetime-other");
        let other_original = record_of(&other);

        state.lock_vault().unwrap();
        state.unlock_vault(other.vault.clone(), password()).unwrap();

        assert_eq!(
            state.confirm_binding_reset(&other.root, &id).unwrap(),
            reset_no_pending()
        );
        assert_eq!(
            state.confirm_binding_reset(&bound.root, &id).unwrap(),
            reset_no_pending()
        );
        assert_eq!(record_of(&bound), original);
        assert_eq!(record_of(&other), other_original);

        drop(other.scratch);
        drop(bound.scratch);
    }

    #[test]
    fn a_reset_through_the_state_removes_only_the_sync_state_record() {
        let bound = bound_vault("b1i-appstate-reset");

        std::fs::write(&bound.remote, &bound.candidate).unwrap();

        let vault_bytes = std::fs::read(&bound.vault).unwrap();
        let remote_bytes = std::fs::read(&bound.remote).unwrap();
        let state = AppState::default();

        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        let id = reset_prepared_id(&state, &bound);

        assert_eq!(
            state.confirm_binding_reset(&bound.root, &id).unwrap(),
            Ok(BindingResetOutcome::ResetAndVerified)
        );

        assert!(!bound
            .root
            .path()
            .join(SYNC_STATE_DIRECTORY)
            .read_dir()
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|e| e == "json")));
        assert_eq!(std::fs::read(&bound.vault).unwrap(), vault_bytes);
        assert_eq!(std::fs::read(&bound.remote).unwrap(), remote_bytes);
        assert!(matches!(
            state.binding_status(&bound.root).unwrap().state(),
            BindingState::NotConfigured
        ));

        // The session and its lock are still the state's.
        assert!(matches!(
            UnlockedVaultSession::unlock(&bound.vault, password()),
            Err(crate::vault::session::SessionError::InUse)
        ));

        // Nothing is left to reset, and nothing was rebuilt.
        assert_eq!(
            state
                .prepare_binding_reset(&bound.root)
                .unwrap()
                .map(|_| ()),
            Err(BindingResetRefusal::NothingToReset)
        );

        drop(bound.scratch);
    }

    #[test]
    fn preparing_and_confirming_a_reset_count_as_activity_but_cancelling_does_not() {
        let bound = bound_vault("b1i-appstate-activity");
        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));

        state.unlock_vault(bound.vault.clone(), password()).unwrap();
        state.age_session_for_test(Duration::from_secs(10));

        let aged = state.last_activity_for_test().unwrap();

        state.cancel_binding_reset().unwrap();
        assert_eq!(state.last_activity_for_test(), Some(aged));

        let id = reset_prepared_id(&state, &bound);

        assert!(
            state.last_activity_for_test().unwrap() > aged,
            "preparing did not refresh activity"
        );

        state.age_session_for_test(Duration::from_secs(10));

        let aged = state.last_activity_for_test().unwrap();

        assert_eq!(
            state.confirm_binding_reset(&bound.root, &id).unwrap(),
            Ok(BindingResetOutcome::ResetAndVerified)
        );
        assert!(
            state.last_activity_for_test().unwrap() > aged,
            "confirming did not refresh activity"
        );

        drop(bound.scratch);
    }

    #[test]
    fn a_reset_attempt_does_not_outlive_an_expired_or_replaced_session() {
        let bound = bound_vault("b1j2-appstate-reset-attempts");
        let state = AppState::with_auto_lock_timeout(Duration::from_secs(30));
        let original = record_of(&bound);

        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        let a = new_attempt();

        let shown = state
            .prepare_binding_reset_for_attempt(a, &bound.root)
            .unwrap()
            .unwrap()
            .preparation_id()
            .to_owned();

        // Expiry: the preparation dies with the session; nothing is removed.
        state.age_session_for_test(Duration::from_secs(31));

        assert!(matches!(
            state.confirm_binding_reset(&bound.root, &shown),
            Err(AppStateError::SessionExpired)
        ));
        assert!(matches!(
            state.prepare_binding_reset_for_attempt(new_attempt(), &bound.root),
            Err(AppStateError::VaultLocked)
        ));
        state.cancel_reset_attempt(a).unwrap();
        assert_eq!(record_of(&bound), original);

        // A new session starts owning nothing: the old attempt's late cancel
        // cannot discard the new session's preparation.
        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        let b = new_attempt();

        let current = state
            .prepare_binding_reset_for_attempt(b, &bound.root)
            .unwrap()
            .unwrap()
            .preparation_id()
            .to_owned();

        state.cancel_reset_attempt(a).unwrap();

        // The cancelled id cannot prepare again, in this or any session.
        assert!(matches!(
            state.prepare_binding_reset_for_attempt(a, &bound.root),
            Err(AppStateError::AttemptSuperseded)
        ));
        assert_eq!(record_of(&bound), original);

        assert!(matches!(
            state.confirm_binding_reset(&bound.root, &current),
            Ok(Ok(_))
        ));
    }

    #[test]
    fn a_reset_and_an_initial_binding_preparation_void_each_other_through_the_state() {
        let bound = bound_vault("b1i-appstate-exclusion");
        let state = AppState::default();
        let original = record_of(&bound);

        state.unlock_vault(bound.vault.clone(), password()).unwrap();

        // An initial-binding attempt (refused here: a binding exists) voids a
        // pending reset.
        let id = reset_prepared_id(&state, &bound);

        assert_eq!(
            state
                .prepare_initial_binding(&bound.root, &bound.target)
                .unwrap()
                .map(|_| ()),
            Err(InitialBindingRefusal::ExistingBinding)
        );
        assert_eq!(
            state.confirm_binding_reset(&bound.root, &id).unwrap(),
            reset_no_pending()
        );
        assert_eq!(record_of(&bound), original);

        // Cancelling the initial binding does not cancel a reset.
        let id = reset_prepared_id(&state, &bound);

        state.cancel_initial_binding().unwrap();

        assert_eq!(
            state.confirm_binding_reset(&bound.root, &id).unwrap(),
            Ok(BindingResetOutcome::ResetAndVerified)
        );

        drop(bound.scratch);
    }

    // -- Stage 1U-4 B2b: copy-creation attempt ownership through the state --------
    //
    // The checks of the two B2a steps are tested next to the session, and the
    // command-level flows next to the commands. Here: the live-session rule, that
    // an attempt does not outlive an expired or replaced session, and the activity
    // rules. Scratch lives under the git-ignored `.qa-local/sync-copy-b2-tests/`.

    #[cfg(windows)]
    mod copy_creation {
        use super::*;
        use crate::vault::session::{
            CopyCreationConfirmRefusal, CopyCreationOutcome, CopyCreationStale,
        };

        struct Copying {
            state: AppState,
            vault: PathBuf,
            root: SyncStateRoot,
            target: SyncFileTarget,
            target_path: PathBuf,
            _scratch: tempfile::TempDir,
        }

        fn copying(name: &str, timeout: Duration) -> Copying {
            let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(".qa-local")
                .join("sync-copy-b2-tests");

            std::fs::create_dir_all(&base).unwrap();

            let scratch = tempfile::Builder::new()
                .prefix(&format!("{name}-"))
                .tempdir_in(&base)
                .unwrap();

            let vaults = scratch.path().join("vaults");
            let dest = scratch.path().join("dest");

            std::fs::create_dir_all(&vaults).unwrap();
            std::fs::create_dir_all(&dest).unwrap();

            let vault = vaults.join("vault.lvault");
            let target_path = dest.join("copy.lvault");

            UnlockedVaultSession::create(&vault, password(), 1_700_000_000_000)
                .unwrap()
                .lock();

            let state = AppState::with_auto_lock_timeout(timeout);

            state.unlock_vault(vault.clone(), password()).unwrap();

            Copying {
                root: SyncStateRoot::for_test(scratch.path().join("app-local")),
                target: SyncFileTarget::from_path(&target_path).unwrap(),
                state,
                vault,
                target_path,
                _scratch: scratch,
            }
        }

        fn no_pending() -> Result<CopyCreationOutcome, CopyCreationConfirmRefusal> {
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NoPendingApproval,
            ))
        }

        fn prepared_id(
            c: &Copying,
            token: SessionToken,
            attempt: BindingAttemptId,
        ) -> Result<String, AppStateError> {
            c.state
                .prepare_copy_creation_for_session(token, attempt, &c.root, &c.target)
                .map(|prepared| prepared.unwrap().preparation_id().to_owned())
        }

        #[test]
        fn only_the_current_attempt_may_prepare_and_an_expired_or_replaced_session_fails_closed() {
            let c = copying("b2b-appstate-attempts", Duration::from_secs(30));
            let state = &c.state;

            let (a, b) = (new_attempt(), new_attempt());

            let token_a = state.begin_copy_creation_selection(a).unwrap();
            let token_b = state.begin_copy_creation_selection(b).unwrap();

            // The session is the same; the attempt is not.
            assert!(matches!(
                prepared_id(&c, token_a, a),
                Err(AppStateError::AttemptSuperseded)
            ));
            assert!(!c.target_path.exists());

            // A cancelled attempt cannot begin again, and cancelling is idempotent.
            state.cancel_copy_creation_attempt(a).unwrap();
            state.cancel_copy_creation_attempt(a).unwrap();
            assert!(matches!(
                state.begin_copy_creation_selection(a),
                Err(AppStateError::AttemptSuperseded)
            ));

            // The current attempt prepares; a stale cancel leaves it pending.
            let id = prepared_id(&c, token_b, b).unwrap();

            state.cancel_copy_creation_attempt(a).unwrap();

            // Expiry while the old dialog is open: reported as such, nothing prepared.
            state.age_session_for_test(Duration::from_secs(31));

            assert!(matches!(
                prepared_id(&c, token_b, new_attempt()),
                Err(AppStateError::SessionExpired)
            ));
            assert!(matches!(
                state.confirm_copy_creation(&c.root, &id),
                Err(AppStateError::VaultLocked)
            ));
            assert!(!c.target_path.exists());

            // A later session starts with no current attempt and no preparation.
            state.unlock_vault(c.vault.clone(), password()).unwrap();

            assert!(matches!(
                prepared_id(&c, token_b, b),
                Err(AppStateError::SessionChanged)
            ));
            assert_eq!(
                state.confirm_copy_creation(&c.root, &id).unwrap(),
                no_pending()
            );
            assert!(!c.target_path.exists());

            // The old attempts' late cancels cannot discard the new session's
            // preparation, and the cancelled id still cannot begin.
            let d = new_attempt();
            let token_d = state.begin_copy_creation_selection(d).unwrap();
            let current = prepared_id(&c, token_d, d).unwrap();

            state.cancel_copy_creation_attempt(a).unwrap();
            state.cancel_copy_creation_attempt(b).unwrap();

            assert!(matches!(
                state.begin_copy_creation_selection(b),
                Err(AppStateError::AttemptSuperseded)
            ));

            assert_eq!(
                state.confirm_copy_creation(&c.root, &current).unwrap(),
                Ok(CopyCreationOutcome::CreatedAndVerified)
            );
            assert!(c.target_path.is_file());
        }

        #[test]
        fn a_session_replaced_while_the_dialog_is_open_is_refused_before_the_session_is_asked() {
            let c = copying("b2b-appstate-replaced", Duration::from_secs(30));
            let state = &c.state;

            let a = new_attempt();
            let token = state.begin_copy_creation_selection(a).unwrap();

            // The same vault, locked and unlocked again: a different session. The
            // old dialog's late result is refused on the session identity alone.
            state.lock_vault().unwrap();
            state.unlock_vault(c.vault.clone(), password()).unwrap();

            assert!(matches!(
                prepared_id(&c, token, a),
                Err(AppStateError::SessionChanged)
            ));
            assert!(!c.target_path.exists());
        }

        #[test]
        fn a_refused_obsolete_selection_voids_no_other_approval() {
            let c = copying("b2b-appstate-obsolete", Duration::from_secs(30));
            let state = &c.state;

            // An older dialog's result arrives after a newer attempt prepared: it
            // is refused on the attempt alone and the newer preparation survives.
            let old = new_attempt();
            let old_token = state.begin_copy_creation_selection(old).unwrap();

            let current = new_attempt();
            let current_token = state.begin_copy_creation_selection(current).unwrap();
            let id = prepared_id(&c, current_token, current).unwrap();

            // The obsolete selection finishes: refused before the session is touched.
            assert!(matches!(
                prepared_id(&c, old_token, old),
                Err(AppStateError::AttemptSuperseded)
            ));

            assert_eq!(
                state.confirm_copy_creation(&c.root, &id).unwrap(),
                Ok(CopyCreationOutcome::CreatedAndVerified)
            );
        }

        #[test]
        fn begin_prepare_and_confirm_count_as_activity_and_cancel_does_not() {
            let c = copying("b2b-appstate-activity", Duration::from_secs(30));
            let state = &c.state;

            let a = new_attempt();

            state.age_session_for_test(Duration::from_secs(10));

            let aged = state.last_activity_for_test().unwrap();
            let token = state.begin_copy_creation_selection(a).unwrap();

            assert!(
                state.last_activity_for_test().unwrap() > aged,
                "beginning did not refresh activity"
            );

            state.age_session_for_test(Duration::from_secs(10));

            let aged = state.last_activity_for_test().unwrap();

            // Cancelling observes nothing and refreshes nothing.
            state.cancel_copy_creation_attempt(new_attempt()).unwrap();
            assert_eq!(state.last_activity_for_test(), Some(aged));

            let id = prepared_id(&c, token, a).unwrap();

            assert!(
                state.last_activity_for_test().unwrap() > aged,
                "preparing did not refresh activity"
            );

            state.age_session_for_test(Duration::from_secs(10));

            let aged = state.last_activity_for_test().unwrap();

            assert_eq!(
                state.confirm_copy_creation(&c.root, &id).unwrap(),
                Ok(CopyCreationOutcome::CreatedAndVerified)
            );
            assert!(
                state.last_activity_for_test().unwrap() > aged,
                "confirming did not refresh activity"
            );
        }

        #[test]
        fn cancelling_without_a_session_is_not_an_error_and_confirming_needs_one() {
            let c = copying("b2b-appstate-locked", Duration::from_secs(30));
            let state = &c.state;

            let a = new_attempt();

            state.begin_copy_creation_selection(a).unwrap();
            state.lock_vault().unwrap();

            assert!(state.cancel_copy_creation_attempt(a).is_ok());
            assert!(matches!(
                state.begin_copy_creation_selection(new_attempt()),
                Err(AppStateError::VaultLocked)
            ));
            assert!(matches!(
                state.confirm_copy_creation(&c.root, "00000000-0000-4000-8000-000000000000"),
                Err(AppStateError::VaultLocked)
            ));
            assert!(!c.target_path.exists());
        }
    }
}
