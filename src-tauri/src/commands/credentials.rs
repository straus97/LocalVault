use tauri::State;
use zeroize::Zeroizing;

use crate::{app_state::AppState, commands::CommandError};

#[tauri::command(async)]
pub fn change_master_password(
    current_master_password: String,
    new_master_password: String,
    state: State<'_, AppState>,
) -> Result<(), CommandError> {
    /*
     * Immediately move both IPC-owned String allocations under
     * zeroization control. No password copies are made here.
     */
    let current_master_password = Zeroizing::new(current_master_password);

    let new_master_password = Zeroizing::new(new_master_password);

    state
        .change_master_password(current_master_password, new_master_password)
        .map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{app_state::AppStateError, vault::session::SessionError};

    #[test]
    fn wrong_current_password_has_operation_specific_error() {
        let error = CommandError::from(AppStateError::Session(
            SessionError::CurrentMasterPasswordInvalid,
        ));

        assert_eq!(error.code, "currentMasterPasswordInvalid");

        assert_eq!(error.message, "The current master password is invalid.");
    }

    #[test]
    fn same_new_password_has_stable_error() {
        let error = CommandError::from(AppStateError::Session(
            SessionError::NewMasterPasswordMatchesCurrent,
        ));

        assert_eq!(error.code, "newMasterPasswordMatchesCurrent");
    }

    #[test]
    fn internal_rotation_failure_is_sanitized() {
        let error = CommandError::from(AppStateError::Session(
            SessionError::PasswordChangeRollbackFailed,
        ));

        assert_eq!(error.code, "masterPasswordChangeFailed");
    }
}
