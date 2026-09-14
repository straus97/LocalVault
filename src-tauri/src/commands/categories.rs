use std::mem;

use serde::Deserialize;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    app_state::AppState,
    vault::session::{CategoryInput, CategorySummary},
};

use super::CommandError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryCommandInput {
    pub name: String,
}

impl Drop for CategoryCommandInput {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

impl CategoryCommandInput {
    fn into_category_input(mut self) -> CategoryInput {
        CategoryInput {
            name: mem::take(&mut self.name),
        }
    }
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
pub fn list_categories(state: State<'_, AppState>) -> Result<Vec<CategorySummary>, CommandError> {
    state.list_categories().map_err(CommandError::from)
}

#[tauri::command]
pub fn get_category(
    id: String,
    state: State<'_, AppState>,
) -> Result<CategorySummary, CommandError> {
    let id = parse_category_id(&id)?;

    state.get_category(id).map_err(CommandError::from)
}

#[tauri::command]
pub fn create_category(
    input: CategoryCommandInput,
    state: State<'_, AppState>,
) -> Result<CategorySummary, CommandError> {
    state
        .create_category(input.into_category_input())
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn update_category(
    id: String,
    input: CategoryCommandInput,
    state: State<'_, AppState>,
) -> Result<CategorySummary, CommandError> {
    let id = parse_category_id(&id)?;

    state
        .update_category(id, input.into_category_input())
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn delete_category(id: String, state: State<'_, AppState>) -> Result<(), CommandError> {
    let id = parse_category_id(&id)?;

    state.delete_category(id).map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use crate::{app_state::AppStateError, vault::session::SessionError};

    use super::*;
    use localvault_core::vault::data::VaultDataError;

    #[test]
    fn valid_category_id_parses() {
        let id = Uuid::new_v4();

        assert_eq!(parse_category_id(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn invalid_category_id_has_stable_error() {
        let error = parse_category_id("not-a-category-uuid").unwrap_err();

        assert_eq!(error.code, "invalidCategoryId");
    }

    #[test]
    fn missing_category_has_stable_error() {
        let error = CommandError::from(AppStateError::Session(SessionError::CategoryNotFound));

        assert_eq!(error.code, "categoryNotFound");
    }

    #[test]
    fn category_in_use_has_stable_error() {
        let error = CommandError::from(AppStateError::Session(SessionError::CategoryInUse));

        assert_eq!(error.code, "categoryInUse");
    }

    #[test]
    fn invalid_category_details_are_not_exposed() {
        let internal_id = Uuid::new_v4();

        let error = CommandError::from(AppStateError::Session(SessionError::InvalidCategory(
            VaultDataError::EmptyCategoryName(internal_id),
        )));

        assert_eq!(error.code, "invalidCategory");

        assert!(!error.message.contains(&internal_id.to_string()));
    }

    #[test]
    fn command_input_moves_category_name_into_internal_dto() {
        let internal = CategoryCommandInput {
            name: "Work".to_owned(),
        }
        .into_category_input();

        assert_eq!(internal.name, "Work");
    }
}
