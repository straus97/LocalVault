use std::path::PathBuf;

use tauri::State;
use zeroize::Zeroizing;

use crate::{app_state::AppState, commands::CommandError};

#[tauri::command]
pub fn create_vault_backup(path: String, state: State<'_, AppState>) -> Result<(), CommandError> {
    state
        .create_backup(PathBuf::from(path))
        .map_err(CommandError::from)
}

#[tauri::command(async)]
pub fn restore_vault_backup(
    backup_path: String,
    destination_path: String,
    master_password: String,
    state: State<'_, AppState>,
) -> Result<(), CommandError> {
    /*
     * As with create_vault/unlock_vault, immediately move the
     * deserialized String under zeroization control.
     */
    let master_password = Zeroizing::new(master_password);

    state
        .restore_backup(
            PathBuf::from(backup_path),
            PathBuf::from(destination_path),
            master_password,
        )
        .map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        app_state::AppStateError,
        crypto::CryptoError,
        vault::{backup::BackupError, format::VaultError, storage::StorageError},
    };

    #[test]
    fn existing_backup_destination_has_stable_error() {
        let error = CommandError::from(AppStateError::Backup(BackupError::Storage(
            StorageError::DestinationExists,
        )));

        assert_eq!(error.code, "backupAlreadyExists");
    }

    #[test]
    fn restore_authentication_failure_is_sanitized() {
        let error = CommandError::from(AppStateError::Backup(BackupError::Vault(
            VaultError::Crypto(CryptoError::Decryption),
        )));

        assert_eq!(error.code, "backupAuthenticationFailed");

        assert_eq!(error.message, "The backup could not be authenticated.");
    }

    #[test]
    fn missing_backup_has_stable_error() {
        let error = CommandError::from(AppStateError::Backup(BackupError::Storage(
            StorageError::NotFound,
        )));

        assert_eq!(error.code, "backupNotFound");
    }
}
