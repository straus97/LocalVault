use std::mem;

use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    app_state::AppState,
    secure_clipboard::SecureClipboard,
    vault::session::{EntryDetails, EntryInput, EntrySummary},
};

use super::CommandError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryCommandInput {
    pub title: String,
    #[serde(default)]
    pub profile_name: String,
    pub url: String,
    pub username: String,
    pub password: String,
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
    fn into_entry_input(mut self) -> Result<EntryInput, CommandError> {
        let category_id = match self.category_id.as_deref() {
            Some(value) => Some(parse_category_id(value)?),
            None => None,
        };

        Ok(EntryInput {
            title: mem::take(&mut self.title),
            profile_name: mem::take(&mut self.profile_name),
            url: mem::take(&mut self.url),
            username: mem::take(&mut self.username),
            password: mem::take(&mut self.password),
            notes: mem::take(&mut self.notes),
            category_id,
            tags: mem::take(&mut self.tags),
            favorite: self.favorite,
        })
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
    let input = input.into_entry_input()?;

    state.create_entry(input).map_err(CommandError::from)
}

#[tauri::command]
pub fn update_entry(
    id: String,
    input: EntryCommandInput,
    state: State<'_, AppState>,
) -> Result<EntrySummary, CommandError> {
    let id = parse_entry_id(&id)?;

    let input = input.into_entry_input()?;

    state.update_entry(id, input).map_err(CommandError::from)
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

        let internal = command_input(Some(category_id.to_string()))
            .into_entry_input()
            .unwrap();

        assert_eq!(internal.category_id, Some(category_id));

        assert_eq!(internal.password, "IPC_ENTRY_SECRET");
    }

    #[test]
    fn invalid_category_id_has_stable_error() {
        let result = command_input(Some("not-a-category-uuid".to_owned())).into_entry_input();

        let error = match result {
            Ok(_) => {
                panic!("invalid category id unexpectedly accepted")
            }
            Err(error) => error,
        };

        assert_eq!(error.code, "invalidCategoryId");
    }
}
