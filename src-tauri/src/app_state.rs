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
        RemoteObservationOutcome, RemoteObservationRefusal, RemoteTargetRefusal, SessionError,
        SessionSyncState, UnlockedVaultSession,
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

#[derive(Default)]
struct AppStateInner {
    session: Option<UnlockedVaultSession>,
    last_activity: Option<Instant>,
    expiry_notification_pending: bool,
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
}
