mod entries;

use std::{
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::vault::session::{SessionError, UnlockedVaultSession};

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

    #[error("application state is unavailable")]
    StateUnavailable,

    #[error("system clock is invalid")]
    InvalidClock,

    #[error("vault session operation failed")]
    Session(#[from] SessionError),
}

#[derive(Default)]
pub struct AppState {
    session: Mutex<Option<UnlockedVaultSession>>,
}

impl AppState {
    pub fn status(&self) -> Result<VaultStatus, AppStateError> {
        let guard = self.session_guard()?;

        Ok(status_from_session(guard.as_ref()))
    }

    pub fn create_vault(
        &self,
        path: PathBuf,
        master_password: Zeroizing<String>,
    ) -> Result<VaultStatus, AppStateError> {
        let mut guard = self.session_guard()?;

        if guard.is_some() {
            return Err(AppStateError::AlreadyUnlocked);
        }

        let now_ms = unix_time_ms()?;

        let session = UnlockedVaultSession::create(path, master_password, now_ms)?;

        *guard = Some(session);

        Ok(status_from_session(guard.as_ref()))
    }

    pub fn unlock_vault(
        &self,
        path: PathBuf,
        master_password: Zeroizing<String>,
    ) -> Result<VaultStatus, AppStateError> {
        let mut guard = self.session_guard()?;

        if guard.is_some() {
            return Err(AppStateError::AlreadyUnlocked);
        }

        let session = UnlockedVaultSession::unlock(path, master_password)?;

        *guard = Some(session);

        Ok(status_from_session(guard.as_ref()))
    }

    pub fn lock_vault(&self) -> Result<VaultStatus, AppStateError> {
        let mut guard = self.session_guard()?;

        if let Some(session) = guard.as_mut() {
            session.save()?;
        }

        // The session is removed only after save succeeds.
        // If save fails, the unlocked/dirty session remains
        // available so unsaved plaintext changes are not lost.
        *guard = None;

        Ok(status_from_session(None))
    }

    fn session_guard(&self) -> Result<MutexGuard<'_, Option<UnlockedVaultSession>>, AppStateError> {
        self.session
            .lock()
            .map_err(|_| AppStateError::StateUnavailable)
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
            let mut guard = state.session.lock().unwrap();

            let session = guard.as_mut().unwrap();

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
            let guard = state.session.lock().unwrap();

            let session = guard.as_ref().unwrap();

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
            let mut guard = state.session.lock().unwrap();

            let session = guard.as_mut().unwrap();

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

        let guard = state.session.lock().unwrap();

        let session = guard.as_ref().unwrap();

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
}
