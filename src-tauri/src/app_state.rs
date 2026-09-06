mod categories;
mod entries;

use std::{
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::vault::session::{SessionError, UnlockedVaultSession};

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

    #[error("vault session operation failed")]
    Session(#[from] SessionError),
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
    use crate::vault::{data::VaultEntry, format::create_envelope, storage::save_envelope_atomic};

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
}
