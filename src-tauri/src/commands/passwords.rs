use serde::Deserialize;
use tauri::State;

use crate::{
    app_state::AppState,
    commands::CommandError,
    password_generator::{
        generate_password as generate_secure_password, GeneratedPassword, PasswordGeneratorOptions,
    },
};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordGeneratorInput {
    pub length: usize,
    pub include_lowercase: bool,
    pub include_uppercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
}

impl From<PasswordGeneratorInput> for PasswordGeneratorOptions {
    fn from(input: PasswordGeneratorInput) -> Self {
        Self {
            length: input.length,
            include_lowercase: input.include_lowercase,
            include_uppercase: input.include_uppercase,
            include_digits: input.include_digits,
            include_symbols: input.include_symbols,
        }
    }
}

#[tauri::command]
pub fn generate_password(
    input: PasswordGeneratorInput,
    state: State<'_, AppState>,
) -> Result<GeneratedPassword, CommandError> {
    /*
     * Generating a password counts as active use of an
     * unlocked vault.
     */
    state.touch_activity()?;

    generate_secure_password(input.into()).map_err(CommandError::from)
}
