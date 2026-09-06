use uuid::Uuid;

use crate::vault::session::{EntryDetails, EntryInput, EntrySummary};

use super::{unix_time_ms, AppState, AppStateError};

impl AppState {
    pub fn list_entries(&self) -> Result<Vec<EntrySummary>, AppStateError> {
        let guard = self.active_session_guard()?;

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        Ok(session.list_entries())
    }

    pub fn get_entry(&self, id: Uuid) -> Result<EntryDetails, AppStateError> {
        let guard = self.active_session_guard()?;

        let session = guard.session.as_ref().ok_or(AppStateError::VaultLocked)?;

        session.get_entry(id).map_err(AppStateError::from)
    }

    pub fn create_entry(&self, input: EntryInput) -> Result<EntrySummary, AppStateError> {
        let now_ms = unix_time_ms()?;

        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        session
            .create_entry(input, now_ms)
            .map_err(AppStateError::from)
    }

    pub fn update_entry(&self, id: Uuid, input: EntryInput) -> Result<EntrySummary, AppStateError> {
        let now_ms = unix_time_ms()?;

        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        session
            .update_entry(id, input, now_ms)
            .map_err(AppStateError::from)
    }

    pub fn delete_entry(&self, id: Uuid) -> Result<(), AppStateError> {
        let now_ms = unix_time_ms()?;

        let mut guard = self.active_session_guard()?;

        let session = guard.session.as_mut().ok_or(AppStateError::VaultLocked)?;

        session
            .delete_entry(id, now_ms)
            .map_err(AppStateError::from)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::*;

    const MASTER_PASSWORD: &str = "app-state-entry-master-password-test-only";

    const ENTRY_SECRET: &str = "APP_STATE_ENTRY_TEST_SECRET";

    const ENTRY_NOTE: &str = "APP_STATE_ENTRY_PRIVATE_NOTE";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    fn input(title: &str) -> EntryInput {
        EntryInput {
            title: title.to_owned(),
            url: "https://state-entry.example.test".to_owned(),
            username: "state-entry-user@example.test".to_owned(),
            password: ENTRY_SECRET.to_owned(),
            notes: ENTRY_NOTE.to_owned(),
            category_id: None,
            tags: vec!["state-test".to_owned()],
            favorite: false,
        }
    }

    #[test]
    fn locked_state_rejects_entry_operations() {
        let state = AppState::default();

        assert!(matches!(
            state.list_entries(),
            Err(AppStateError::VaultLocked)
        ));

        assert!(matches!(
            state.get_entry(Uuid::new_v4()),
            Err(AppStateError::VaultLocked)
        ));

        assert!(matches!(
            state.create_entry(input("Blocked")),
            Err(AppStateError::VaultLocked)
        ));
    }

    #[test]
    fn create_list_and_get_entry_round_trip_through_app_state() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        let created = state.create_entry(input("State Entry")).unwrap();

        assert_eq!(created.title, "State Entry");

        let summaries = state.list_entries().unwrap();

        assert_eq!(summaries.len(), 1);

        let serialized = serde_json::to_string(&summaries).unwrap();

        assert!(!serialized.contains(ENTRY_SECRET));
        assert!(!serialized.contains(ENTRY_NOTE));

        let details = state.get_entry(created.id).unwrap();

        assert_eq!(details.password, ENTRY_SECRET);
        assert_eq!(details.notes, ENTRY_NOTE);
    }

    #[test]
    fn update_entry_round_trips_through_app_state() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        let created = state.create_entry(input("Before")).unwrap();

        let mut replacement = input("After");

        replacement.password = "UPDATED_STATE_ENTRY_SECRET".to_owned();

        replacement.favorite = true;

        let updated = state.update_entry(created.id, replacement).unwrap();

        assert_eq!(updated.id, created.id);
        assert_eq!(updated.title, "After");
        assert!(updated.favorite);

        let details = state.get_entry(created.id).unwrap();

        assert_eq!(details.password, "UPDATED_STATE_ENTRY_SECRET");
    }

    #[test]
    fn delete_entry_round_trips_through_app_state() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::default();

        state.create_vault(path, password()).unwrap();

        let created = state.create_entry(input("Delete")).unwrap();

        state.delete_entry(created.id).unwrap();

        assert!(state.list_entries().unwrap().is_empty());

        assert!(matches!(
            state.get_entry(created.id),
            Err(AppStateError::Session(
                crate::vault::session::SessionError::EntryNotFound
            ))
        ));
    }

    #[test]
    fn expired_state_rejects_entry_operation_and_drops_session() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let state = AppState::with_auto_lock_timeout(std::time::Duration::from_secs(60));

        state.create_vault(path, password()).unwrap();

        state.age_session_for_test(std::time::Duration::from_secs(61));

        assert!(matches!(
            state.list_entries(),
            Err(AppStateError::SessionExpired)
        ));

        assert!(!state.status().unwrap().unlocked);
    }
}
