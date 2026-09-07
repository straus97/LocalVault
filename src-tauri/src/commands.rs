pub(crate) mod categories;
pub(crate) mod entries;
pub(crate) mod recent_vaults;

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use crate::{
    app_state::{AppState, AppStateError, VaultStatus},
    crypto::CryptoError,
    secure_clipboard::{SecureClipboard, SecureClipboardError},
    vault::{format::VaultError, session::SessionError, storage::StorageError},
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    pub code: &'static str,
    pub message: &'static str,
}

impl CommandError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl From<AppStateError> for CommandError {
    fn from(error: AppStateError) -> Self {
        match error {
            AppStateError::AlreadyUnlocked => {
                Self::new("vaultAlreadyUnlocked", "A vault is already unlocked.")
            }

            AppStateError::VaultLocked => Self::new("vaultLocked", "The vault is locked."),

            AppStateError::SessionExpired => Self::new(
                "vaultSessionExpired",
                "The vault session expired due to inactivity.",
            ),

            AppStateError::Session(SessionError::EntryNotFound) => {
                Self::new("entryNotFound", "The vault entry was not found.")
            }

            AppStateError::Session(SessionError::InvalidEntry(_)) => {
                Self::new("invalidEntry", "The vault entry is invalid.")
            }

            AppStateError::Session(SessionError::PendingUnsavedChanges) => Self::new(
                "pendingUnsavedChanges",
                "The vault has pending unsaved changes.",
            ),

            AppStateError::Session(SessionError::CategoryNotFound) => {
                Self::new("categoryNotFound", "The vault category was not found.")
            }

            AppStateError::Session(SessionError::CategoryInUse) => {
                Self::new("categoryInUse", "The vault category is still in use.")
            }

            AppStateError::Session(SessionError::InvalidCategory(_)) => {
                Self::new("invalidCategory", "The vault category is invalid.")
            }

            AppStateError::StateUnavailable => Self::new(
                "stateUnavailable",
                "LocalVault state is temporarily unavailable.",
            ),

            AppStateError::InvalidClock => {
                Self::new("invalidSystemClock", "The system clock is unavailable.")
            }

            AppStateError::Session(SessionError::AlreadyExists) => Self::new(
                "vaultAlreadyExists",
                "A vault already exists at this location.",
            ),

            AppStateError::Session(SessionError::InUse) => {
                Self::new("vaultInUse", "This vault is already open.")
            }

            AppStateError::Session(SessionError::ChangedOnDisk) => Self::new(
                "vaultChangedOnDisk",
                "The vault changed on disk and was not overwritten.",
            ),

            AppStateError::Session(SessionError::Storage(StorageError::NotFound)) => {
                Self::new("vaultNotFound", "The vault file was not found.")
            }

            AppStateError::Session(SessionError::Storage(StorageError::InvalidPath)) => {
                Self::new("invalidVaultPath", "The selected vault path is invalid.")
            }

            AppStateError::Session(SessionError::Vault(VaultError::EmptyMasterPassword)) => {
                Self::new("masterPasswordRequired", "A master password is required.")
            }

            AppStateError::Session(SessionError::Vault(VaultError::Crypto(
                CryptoError::Decryption,
            ))) => Self::new("unlockFailed", "The vault could not be unlocked."),

            AppStateError::Session(SessionError::LockIo(_)) => Self::new(
                "vaultLockFailed",
                "The vault session lock could not be acquired.",
            ),

            AppStateError::Session(SessionError::Storage(
                StorageError::EmptyFile
                | StorageError::TooLarge
                | StorageError::NotRegularFile
                | StorageError::SymlinkPath,
            ))
            | AppStateError::Session(SessionError::Storage(
                StorageError::Deserialization(_) | StorageError::InvalidEnvelope(_),
            ))
            | AppStateError::Session(SessionError::Vault(
                VaultError::UnsupportedFormat | VaultError::InvalidWrappedKey,
            ))
            | AppStateError::Session(SessionError::Vault(VaultError::Crypto(
                CryptoError::InvalidKdfParameters,
            )))
            | AppStateError::Session(SessionError::Deserialization(_))
            | AppStateError::Session(SessionError::Data(_)) => {
                Self::new("invalidVault", "The vault file is invalid or unsupported.")
            }

            _ => Self::new(
                "vaultOperationFailed",
                "The vault operation could not be completed.",
            ),
        }
    }
}

impl From<SecureClipboardError> for CommandError {
    fn from(_error: SecureClipboardError) -> Self {
        Self::new(
            "clipboardUnavailable",
            "The secure clipboard is unavailable.",
        )
    }
}
#[tauri::command]
pub fn get_vault_status(state: State<'_, AppState>) -> Result<VaultStatus, CommandError> {
    state.status().map_err(CommandError::from)
}

#[tauri::command]
pub fn create_vault(
    path: String,
    master_password: String,
    state: State<'_, AppState>,
) -> Result<VaultStatus, CommandError> {
    // The String produced by Tauri deserialization is moved
    // directly into Zeroizing without cloning it.
    let master_password = Zeroizing::new(master_password);

    state
        .create_vault(PathBuf::from(path), master_password)
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn unlock_vault(
    path: String,
    master_password: String,
    state: State<'_, AppState>,
) -> Result<VaultStatus, CommandError> {
    // As soon as Rust owns the IPC String, put that same
    // allocation under zeroization control.
    let master_password = Zeroizing::new(master_password);

    state
        .unlock_vault(PathBuf::from(path), master_password)
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn lock_vault(
    state: State<'_, AppState>,
    clipboard: State<'_, SecureClipboard>,
) -> Result<VaultStatus, CommandError> {
    let result = state.lock_vault().map_err(CommandError::from);

    clipboard.clear_owned_best_effort();

    result
}

#[tauri::command]
pub fn touch_vault_activity(state: State<'_, AppState>) -> Result<(), CommandError> {
    state.touch_activity().map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn wrong_password_maps_to_generic_unlock_error() {
        let source = AppStateError::Session(SessionError::Vault(VaultError::Crypto(
            CryptoError::Decryption,
        )));

        let error = CommandError::from(source);

        assert_eq!(error.code, "unlockFailed");

        assert_eq!(error.message, "The vault could not be unlocked.");
    }

    #[test]
    fn invalid_kdf_metadata_maps_to_invalid_vault() {
        let source = AppStateError::Session(SessionError::Vault(VaultError::Crypto(
            CryptoError::InvalidKdfParameters,
        )));

        let error = CommandError::from(source);

        assert_eq!(error.code, "invalidVault");
    }

    #[test]
    fn changed_on_disk_has_stable_command_error() {
        let source = AppStateError::Session(SessionError::ChangedOnDisk);

        let error = CommandError::from(source);

        assert_eq!(error.code, "vaultChangedOnDisk");
    }

    #[test]
    fn internal_io_details_are_not_exposed_to_frontend() {
        let source = AppStateError::Session(SessionError::Storage(StorageError::Io(
            io::Error::other("SECRET_INTERNAL_IO_DETAIL"),
        )));

        let error = CommandError::from(source);

        assert_eq!(error.code, "vaultOperationFailed");

        assert!(!error.message.contains("SECRET_INTERNAL_IO_DETAIL"));
    }

    #[test]
    fn expired_session_has_stable_command_error() {
        let error = CommandError::from(AppStateError::SessionExpired);

        assert_eq!(error.code, "vaultSessionExpired");

        assert_eq!(
            error.message,
            "The vault session expired due to inactivity."
        );
    }

    #[test]
    fn clipboard_errors_are_sanitized_for_frontend() {
        let error = CommandError::from(SecureClipboardError::Unavailable);

        assert_eq!(error.code, "clipboardUnavailable");

        assert_eq!(error.message, "The secure clipboard is unavailable.");
    }
}
