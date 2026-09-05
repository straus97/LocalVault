use tauri::State;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    vault::session::{EntryDetails, EntryInput, EntrySummary},
};

use super::CommandError;

fn parse_entry_id(id: &str) -> Result<Uuid, CommandError> {
    Uuid::parse_str(id)
        .map_err(|_| CommandError::new("invalidEntryId", "The vault entry identifier is invalid."))
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
pub fn create_entry(
    input: EntryInput,
    state: State<'_, AppState>,
) -> Result<EntrySummary, CommandError> {
    state.create_entry(input).map_err(CommandError::from)
}

#[tauri::command]
pub fn update_entry(
    id: String,
    input: EntryInput,
    state: State<'_, AppState>,
) -> Result<EntrySummary, CommandError> {
    let id = parse_entry_id(&id)?;

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
}
