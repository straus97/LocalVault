use std::{path::PathBuf, time::Instant};

use super::{AppState, AppStateError};

use crate::vault::lifecycle::{delete_closed_vault_files, DeletedVaultOutcome};

impl AppState {
    pub fn delete_closed_vault(&self, path: PathBuf) -> Result<DeletedVaultOutcome, AppStateError> {
        /*
         * Keep the AppState mutex for the complete filesystem
         * operation so another command in this LocalVault
         * process cannot unlock/create a session concurrently.
         */
        let mut guard = self.inner_guard()?;

        self.expire_if_needed(&mut guard, Instant::now());

        if guard.session.is_some() {
            return Err(AppStateError::AlreadyUnlocked);
        }

        let outcome = delete_closed_vault_files(&path)?;

        guard.last_activity = None;

        guard.expiry_notification_pending = false;

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::*;

    const MASTER_PASSWORD: &str = "lifecycle-app-state-test-only";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    #[test]
    fn deletion_is_rejected_while_any_vault_is_unlocked() {
        let temp = tempdir().unwrap();

        let active = temp.path().join("active.lvault");

        let target = temp.path().join("target.lvault");

        std::fs::write(&target, b"target").unwrap();

        let state = AppState::default();

        state.create_vault(active, password()).unwrap();

        let result = state.delete_closed_vault(target.clone());

        assert!(matches!(result, Err(AppStateError::AlreadyUnlocked)));

        assert!(target.exists());
    }

    #[test]
    fn deletion_succeeds_after_application_is_locked() {
        let temp = tempdir().unwrap();

        let target = temp.path().join("target.lvault");

        let state = AppState::default();

        state.create_vault(target.clone(), password()).unwrap();

        state.lock_vault().unwrap();

        let outcome = state.delete_closed_vault(target.clone()).unwrap();

        assert!(!target.exists());

        assert!(outcome.internal_backup_removed);
    }
}
