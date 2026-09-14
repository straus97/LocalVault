use tauri::State;
use uuid::Uuid;

use crate::{
    app_state::{AppState, TotpCode},
    secure_clipboard::SecureClipboard,
};

use super::{entries::ClipboardCopyResult, CommandError};

fn parse_entry_id(id: &str) -> Result<Uuid, CommandError> {
    Uuid::parse_str(id)
        .map_err(|_| CommandError::new("invalidEntryId", "The vault entry identifier is invalid."))
}

#[tauri::command]
pub fn get_entry_totp_code(
    id: String,
    state: State<'_, AppState>,
) -> Result<TotpCode, CommandError> {
    let id = parse_entry_id(&id)?;

    state.entry_totp_code(id).map_err(CommandError::from)
}

#[tauri::command]
pub fn copy_entry_totp(
    id: String,
    state: State<'_, AppState>,
    clipboard: State<'_, SecureClipboard>,
) -> Result<ClipboardCopyResult, CommandError> {
    let id = parse_entry_id(&id)?;

    /*
     * Unlike passive display refresh, copying is an
     * explicit user action. AppState intentionally uses
     * the active-session guard for this path.
     */
    let code = state.entry_totp_for_clipboard(id)?;

    let clear_after_seconds = clipboard.copy_secret(code.as_str())?;

    Ok(ClipboardCopyResult {
        clear_after_seconds,
    })
}

#[cfg(test)]
mod tests {
    use localvault_core::totp::TotpError;

    use crate::app_state::AppStateError;

    use super::*;

    #[test]
    fn invalid_entry_id_has_stable_error() {
        let error = parse_entry_id("not-a-uuid").unwrap_err();

        assert_eq!(error.code, "invalidEntryId",);
    }

    #[test]
    fn missing_totp_has_stable_error() {
        let error = CommandError::from(AppStateError::TotpNotConfigured);

        assert_eq!(error.code, "totpNotConfigured",);
    }

    #[test]
    fn invalid_totp_setup_is_sanitized() {
        let error = CommandError::from(TotpError::InvalidSecret);

        assert_eq!(error.code, "invalidTotpSetup",);

        assert!(!error.message.contains("secret"));
    }
}
