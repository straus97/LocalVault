use std::mem;

use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    app_state::AppState,
    secure_clipboard::SecureClipboard,
    totp::{parse_totp_input, TotpError},
    vault::session::{EntryDetails, EntryInput, EntrySummary, TotpUpdate},
};

use super::CommandError;

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum TotpUpdateCommand {
    #[default]
    Keep,
    Replace,
    Remove,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryCommandInput {
    pub title: String,

    #[serde(default)]
    pub profile_name: String,

    pub url: String,
    pub username: String,
    pub password: String,

    #[serde(default)]
    totp_update: TotpUpdateCommand,

    #[serde(default)]
    pub totp_input: String,

    pub notes: String,
    pub category_id: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardCopyResult {
    pub clear_after_seconds: u64,
}
impl Drop for EntryCommandInput {
    fn drop(&mut self) {
        self.title.zeroize();
        self.profile_name.zeroize();
        self.url.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.totp_input.zeroize();
        self.notes.zeroize();

        if let Some(category_id) = self.category_id.as_mut() {
            category_id.zeroize();
        }

        self.category_id = None;

        for tag in &mut self.tags {
            tag.zeroize();
        }

        self.tags.clear();
    }
}

impl EntryCommandInput {
    fn into_parts(mut self) -> Result<(EntryInput, TotpUpdate), CommandError> {
        let category_id = match self.category_id.as_deref() {
            Some(value) => Some(parse_category_id(value)?),

            None => None,
        };

        let has_totp_input = !self.totp_input.trim().is_empty();

        let totp_update = match self.totp_update {
            TotpUpdateCommand::Keep => {
                if has_totp_input {
                    return Err(CommandError::from(TotpError::ConflictingUpdate));
                }

                TotpUpdate::Keep
            }

            TotpUpdateCommand::Replace => {
                if !has_totp_input {
                    return Err(CommandError::from(TotpError::EmptyInput));
                }

                let config =
                    parse_totp_input(self.totp_input.as_str()).map_err(CommandError::from)?;

                TotpUpdate::Replace(config)
            }

            TotpUpdateCommand::Remove => {
                if has_totp_input {
                    return Err(CommandError::from(TotpError::ConflictingUpdate));
                }

                TotpUpdate::Remove
            }
        };

        let input = EntryInput {
            title: mem::take(&mut self.title),

            profile_name: mem::take(&mut self.profile_name),

            url: mem::take(&mut self.url),

            username: mem::take(&mut self.username),

            password: mem::take(&mut self.password),

            notes: mem::take(&mut self.notes),

            category_id,

            tags: mem::take(&mut self.tags),

            favorite: self.favorite,
        };

        Ok((input, totp_update))
    }
}

fn parse_entry_id(id: &str) -> Result<Uuid, CommandError> {
    Uuid::parse_str(id)
        .map_err(|_| CommandError::new("invalidEntryId", "The vault entry identifier is invalid."))
}

fn parse_category_id(id: &str) -> Result<Uuid, CommandError> {
    Uuid::parse_str(id).map_err(|_| {
        CommandError::new(
            "invalidCategoryId",
            "The vault category identifier is invalid.",
        )
    })
}

#[tauri::command]
pub fn list_entries(state: State<'_, AppState>) -> Result<Vec<EntrySummary>, CommandError> {
    state.list_entries().map_err(CommandError::from)
}

#[tauri::command]
pub fn get_entry(id: String, state: State<'_, AppState>) -> Result<EntryDetails, CommandError> {
    let id = parse_entry_id(&id)?;

    state.get_entry(id).map_err(CommandError::from)
}

#[tauri::command]
pub fn copy_entry_password(
    id: String,
    state: State<'_, AppState>,
    clipboard: State<'_, SecureClipboard>,
) -> Result<ClipboardCopyResult, CommandError> {
    let id = parse_entry_id(&id)?;

    let password = state.entry_password_for_clipboard(id)?;

    let clear_after_seconds = clipboard.copy_secret(password.as_str())?;

    Ok(ClipboardCopyResult {
        clear_after_seconds,
    })
}
#[tauri::command]
pub fn create_entry(
    input: EntryCommandInput,
    state: State<'_, AppState>,
) -> Result<EntrySummary, CommandError> {
    let (input, totp_update) = input.into_parts()?;

    match totp_update {
        TotpUpdate::Keep => state.create_entry(input).map_err(CommandError::from),

        TotpUpdate::Replace(config) => state
            .create_entry_with_totp(input, config)
            .map_err(CommandError::from),

        TotpUpdate::Remove => Err(CommandError::from(TotpError::ConflictingUpdate)),
    }
}

#[tauri::command]
pub fn update_entry(
    id: String,
    input: EntryCommandInput,
    state: State<'_, AppState>,
) -> Result<EntrySummary, CommandError> {
    let id = parse_entry_id(&id)?;

    let (input, totp_update) = input.into_parts()?;

    match totp_update {
        TotpUpdate::Keep => state.update_entry(id, input).map_err(CommandError::from),

        TotpUpdate::Replace(config) => state
            .update_entry_with_totp(id, input, TotpUpdate::Replace(config))
            .map_err(CommandError::from),

        TotpUpdate::Remove => state
            .update_entry_with_totp(id, input, TotpUpdate::Remove)
            .map_err(CommandError::from),
    }
}

#[tauri::command]
pub fn delete_entry(id: String, state: State<'_, AppState>) -> Result<(), CommandError> {
    let id = parse_entry_id(&id)?;

    state.delete_entry(id).map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use crate::{
        app_state::AppStateError,
        vault::{data::VaultDataError, session::SessionError},
    };

    use super::*;

    fn command_input(category_id: Option<String>) -> EntryCommandInput {
        EntryCommandInput {
            title: "IPC Entry".to_owned(),
            profile_name: "Work".to_owned(),
            url: "https://ipc.example.test".to_owned(),
            username: "ipc-user".to_owned(),
            password: "IPC_ENTRY_SECRET".to_owned(),
            totp_update: TotpUpdateCommand::Keep,
            totp_input: String::new(),
            notes: "IPC_ENTRY_NOTE".to_owned(),
            category_id,
            tags: vec!["ipc".to_owned()],
            favorite: false,
        }
    }

    #[test]
    fn valid_entry_id_parses() {
        let id = Uuid::new_v4();

        assert_eq!(parse_entry_id(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn invalid_entry_id_has_stable_error() {
        let error = parse_entry_id("not-a-uuid").unwrap_err();

        assert_eq!(error.code, "invalidEntryId");
    }

    #[test]
    fn locked_state_has_stable_entry_error() {
        let error = CommandError::from(AppStateError::VaultLocked);

        assert_eq!(error.code, "vaultLocked");
    }

    #[test]
    fn missing_entry_has_stable_error() {
        let error = CommandError::from(AppStateError::Session(SessionError::EntryNotFound));

        assert_eq!(error.code, "entryNotFound");
    }

    #[test]
    fn invalid_entry_details_are_not_exposed() {
        let internal_id = Uuid::new_v4();

        let error = CommandError::from(AppStateError::Session(SessionError::InvalidEntry(
            VaultDataError::EmptyEntryTitle(internal_id),
        )));

        assert_eq!(error.code, "invalidEntry");

        assert!(!error.message.contains(&internal_id.to_string()));
    }

    #[test]
    fn pending_changes_have_stable_error() {
        let error = CommandError::from(AppStateError::Session(SessionError::PendingUnsavedChanges));

        assert_eq!(error.code, "pendingUnsavedChanges");
    }

    #[test]
    fn valid_category_id_is_converted_before_app_state() {
        let category_id = Uuid::new_v4();

        let (internal, totp_update) = command_input(Some(category_id.to_string()))
            .into_parts()
            .unwrap();

        assert_eq!(internal.category_id, Some(category_id),);

        assert_eq!(internal.password, "IPC_ENTRY_SECRET",);

        assert!(matches!(totp_update, TotpUpdate::Keep));
    }

    #[test]
    fn invalid_category_id_has_stable_error() {
        let result = command_input(Some("not-a-category-uuid".to_owned())).into_parts();

        let error = match result {
            Ok(_) => {
                panic!("invalid category id unexpectedly accepted")
            }

            Err(error) => error,
        };

        assert_eq!(error.code, "invalidCategoryId",);
    }

    #[test]
    fn replace_totp_input_is_parsed() {
        let mut input = command_input(None);

        input.totp_update = TotpUpdateCommand::Replace;

        input.totp_input = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();

        let (_, update) = input.into_parts().unwrap();

        assert!(matches!(update, TotpUpdate::Replace(_)));
    }

    #[test]
    fn totp_input_without_replace_action_is_rejected() {
        let mut input = command_input(None);

        input.totp_input = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();

        let result = input.into_parts();

        let error = match result {
            Ok(_) => {
                panic!("conflicting TOTP input unexpectedly accepted")
            }

            Err(error) => error,
        };

        assert_eq!(error.code, "invalidTotpUpdate",);
    }
}
