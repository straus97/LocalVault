use std::{path::PathBuf, time::Instant};

use zeroize::Zeroizing;

use super::{AppState, AppStateError};

use crate::vault::backup::restore_backup_file;

#[cfg(test)]
use crate::vault::backup::BackupError;

impl AppState {
    pub fn create_backup(&self, destination: PathBuf) -> Result<(), AppStateError> {
        /*
         * This operation requires and refreshes an active
         * unlocked session.
         */
        let guard = self.active_session_guard()?;

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        session.create_user_backup(destination)?;

        Ok(())
    }

    pub fn restore_backup(
        &self,
        backup_path: PathBuf,
        destination_path: PathBuf,
        master_password: Zeroizing<String>,
    ) -> Result<(), AppStateError> {
        let mut guard = self.inner_guard()?;

        self.expire_if_needed(&mut guard, Instant::now());

        /*
         * Restore never runs beside an unlocked decrypted
         * session. The restored file remains locked afterwards.
         */
        if guard.session.is_some() {
            return Err(AppStateError::AlreadyUnlocked);
        }

        restore_backup_file(&backup_path, &destination_path, master_password)
            .map_err(AppStateError::Backup)?;

        guard.last_activity = None;

        guard.expiry_notification_pending = false;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    use crate::vault::{backup::restore_backup_file, session::UnlockedVaultSession};

    const MASTER_PASSWORD: &str = "app-state-backup-test-only";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    #[test]
    fn create_backup_requires_unlocked_session() {
        let temp = tempdir().unwrap();

        let state = AppState::default();

        let result = state.create_backup(temp.path().join("snapshot.lvbackup"));

        assert!(matches!(result, Err(AppStateError::VaultLocked)));
    }

    #[test]
    fn active_state_creates_backup_and_remains_unlocked() {
        let temp = tempdir().unwrap();

        let vault = temp.path().join("vault.lvault");

        let backup = temp.path().join("snapshot.lvbackup");

        let state = AppState::default();

        state.create_vault(vault, password()).unwrap();

        state.create_backup(backup.clone()).unwrap();

        assert!(backup.is_file());

        assert!(state.status().unwrap().unlocked);
    }

    #[test]
    fn restore_requires_locked_application_state() {
        let temp = tempdir().unwrap();

        let source = temp.path().join("source.lvault");

        let destination = temp.path().join("restored.lvault");

        let state = AppState::default();

        state.create_vault(source.clone(), password()).unwrap();

        let result = state.restore_backup(source, destination.clone(), password());

        assert!(matches!(result, Err(AppStateError::AlreadyUnlocked)));

        assert!(!destination.exists());
    }

    #[test]
    fn successful_restore_leaves_state_locked_until_explicit_unlock() {
        let temp = tempdir().unwrap();

        let backup = temp.path().join("snapshot.lvbackup");

        let destination = temp.path().join("restored.lvault");

        let original =
            UnlockedVaultSession::create(&backup, password(), 1_700_000_000_000).unwrap();

        original.lock();

        let state = AppState::default();

        state
            .restore_backup(backup, destination.clone(), password())
            .unwrap();

        assert!(!state.status().unwrap().unlocked);

        state.unlock_vault(destination, password()).unwrap();

        assert!(state.status().unwrap().unlocked);
    }

    #[test]
    fn standalone_restore_core_is_available_without_app_state_session() {
        let temp = tempdir().unwrap();

        let source = temp.path().join("backup.lvbackup");

        let destination = temp.path().join("restored.lvault");

        let original =
            UnlockedVaultSession::create(&source, password(), 1_700_000_000_000).unwrap();

        original.lock();

        restore_backup_file(&source, &destination, password()).unwrap();

        assert!(destination.is_file());
    }

    #[test]
    fn backup_errors_are_carried_by_app_state_without_secret_details() {
        let error = AppStateError::Backup(BackupError::Storage(
            crate::vault::storage::StorageError::NotFound,
        ));

        assert!(matches!(
            error,
            AppStateError::Backup(BackupError::Storage(
                crate::vault::storage::StorageError::NotFound
            ))
        ));
    }
}
