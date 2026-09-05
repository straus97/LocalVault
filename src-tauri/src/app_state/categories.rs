use uuid::Uuid;

use crate::vault::session::{CategoryInput, CategorySummary};

use super::{unix_time_ms, AppState, AppStateError};

impl AppState {
    pub fn list_categories(&self) -> Result<Vec<CategorySummary>, AppStateError> {
        let guard = self.session_guard()?;

        let session = guard.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session.list_categories())
    }

    pub fn get_category(&self, id: Uuid) -> Result<CategorySummary, AppStateError> {
        let guard = self.session_guard()?;

        let session = guard.as_ref().ok_or(AppStateError::VaultLocked)?;

        session.get_category(id).map_err(AppStateError::from)
    }

    pub fn create_category(&self, input: CategoryInput) -> Result<CategorySummary, AppStateError> {
        let now_ms = unix_time_ms()?;

        let mut guard = self.session_guard()?;

        let session = guard.as_mut().ok_or(AppStateError::VaultLocked)?;

        session
            .create_category(input, now_ms)
            .map_err(AppStateError::from)
    }

    pub fn update_category(
        &self,
        id: Uuid,
        input: CategoryInput,
    ) -> Result<CategorySummary, AppStateError> {
        let now_ms = unix_time_ms()?;

        let mut guard = self.session_guard()?;

        let session = guard.as_mut().ok_or(AppStateError::VaultLocked)?;

        session
            .update_category(id, input, now_ms)
            .map_err(AppStateError::from)
    }

    pub fn delete_category(&self, id: Uuid) -> Result<(), AppStateError> {
        let now_ms = unix_time_ms()?;

        let mut guard = self.session_guard()?;

        let session = guard.as_mut().ok_or(AppStateError::VaultLocked)?;

        session
            .delete_category(id, now_ms)
            .map_err(AppStateError::from)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::*;

    const MASTER_PASSWORD: &str = "app-state-category-password-test-only";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    fn input(name: &str) -> CategoryInput {
        CategoryInput {
            name: name.to_owned(),
        }
    }

    #[test]
    fn locked_state_rejects_category_operations() {
        let state = AppState::default();

        assert!(matches!(
            state.list_categories(),
            Err(AppStateError::VaultLocked)
        ));

        assert!(matches!(
            state.get_category(Uuid::new_v4()),
            Err(AppStateError::VaultLocked)
        ));

        assert!(matches!(
            state.create_category(input("Blocked")),
            Err(AppStateError::VaultLocked)
        ));
    }

    #[test]
    fn create_list_and_get_category_round_trip_through_app_state() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        let created = state.create_category(input("Work")).unwrap();

        let categories = state.list_categories().unwrap();

        assert_eq!(categories.len(), 1);
        assert_eq!(categories[0].id, created.id);
        assert_eq!(categories[0].name, "Work");

        let loaded = state.get_category(created.id).unwrap();

        assert_eq!(loaded.name, "Work");
    }

    #[test]
    fn update_category_round_trips_through_app_state() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        let created = state.create_category(input("Before")).unwrap();

        let updated = state.update_category(created.id, input("After")).unwrap();

        assert_eq!(updated.id, created.id);
        assert_eq!(updated.name, "After");
        assert_eq!(updated.created_at_ms, created.created_at_ms);
    }

    #[test]
    fn delete_category_round_trips_through_app_state() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        let created = state.create_category(input("Delete")).unwrap();

        state.delete_category(created.id).unwrap();

        assert!(state.list_categories().unwrap().is_empty());

        assert!(matches!(
            state.get_category(created.id),
            Err(AppStateError::Session(
                crate::vault::session::SessionError::CategoryNotFound
            ))
        ));
    }
}
