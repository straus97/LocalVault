use tauri::State;

use crate::app_state::{AppState, PasswordHealthReport};

use super::CommandError;

#[tauri::command]
pub fn get_password_health(
    state: State<'_, AppState>,
) -> Result<PasswordHealthReport, CommandError> {
    state.password_health().map_err(CommandError::from)
}
