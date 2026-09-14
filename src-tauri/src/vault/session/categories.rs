use std::mem;

use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroize;

use localvault_core::vault::data::VaultCategory;

use super::{SessionError, UnlockedVaultSession};

pub struct CategoryInput {
    pub name: String,
}

impl Drop for CategoryInput {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CategorySummary {
    pub id: Uuid,
    pub name: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl Drop for CategorySummary {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

impl CategorySummary {
    fn from_category(category: &VaultCategory) -> Self {
        Self {
            id: category.id,
            name: category.name.clone(),
            created_at_ms: category.created_at_ms,
            updated_at_ms: category.updated_at_ms,
        }
    }
}

impl CategoryInput {
    fn into_new_category(mut self, now_ms: i64) -> Result<VaultCategory, SessionError> {
        let name = mem::take(&mut self.name);

        VaultCategory::new(name, now_ms).map_err(SessionError::InvalidCategory)
    }

    fn into_existing_category(
        mut self,
        id: Uuid,
        created_at_ms: i64,
        updated_at_ms: i64,
    ) -> VaultCategory {
        VaultCategory {
            id,
            name: mem::take(&mut self.name),
            created_at_ms,
            updated_at_ms,
        }
    }
}

impl UnlockedVaultSession {
    pub fn list_categories(&self) -> Vec<CategorySummary> {
        self.data()
            .categories
            .iter()
            .map(CategorySummary::from_category)
            .collect()
    }

    pub fn get_category(&self, id: Uuid) -> Result<CategorySummary, SessionError> {
        let category = self
            .data()
            .categories
            .iter()
            .find(|category| category.id == id)
            .ok_or(SessionError::CategoryNotFound)?;

        Ok(CategorySummary::from_category(category))
    }

    pub fn create_category(
        &mut self,
        input: CategoryInput,
        now_ms: i64,
    ) -> Result<CategorySummary, SessionError> {
        if self.is_dirty() {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let category = input.into_new_category(now_ms)?;

        let category_id = category.id;

        let mut candidate = self.data().clone();

        candidate.categories.push(category);

        candidate.updated_at_ms = candidate.updated_at_ms.max(now_ms);

        candidate
            .validate()
            .map_err(SessionError::InvalidCategory)?;

        let summary = candidate
            .categories
            .iter()
            .find(|category| category.id == category_id)
            .map(CategorySummary::from_category)
            .ok_or(SessionError::CategoryNotFound)?;

        self.commit_candidate(candidate)?;

        Ok(summary)
    }

    pub fn update_category(
        &mut self,
        id: Uuid,
        input: CategoryInput,
        now_ms: i64,
    ) -> Result<CategorySummary, SessionError> {
        if self.is_dirty() {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let mut candidate = self.data().clone();

        let index = candidate
            .categories
            .iter()
            .position(|category| category.id == id)
            .ok_or(SessionError::CategoryNotFound)?;

        let created_at_ms = candidate.categories[index].created_at_ms;

        let previous_updated_at_ms = candidate.categories[index].updated_at_ms;

        let effective_updated_at_ms = now_ms.max(previous_updated_at_ms);

        let replacement = input.into_existing_category(id, created_at_ms, effective_updated_at_ms);

        candidate.categories[index] = replacement;

        candidate.updated_at_ms = candidate.updated_at_ms.max(effective_updated_at_ms);

        candidate
            .validate()
            .map_err(SessionError::InvalidCategory)?;

        let summary = CategorySummary::from_category(&candidate.categories[index]);

        self.commit_candidate(candidate)?;

        Ok(summary)
    }

    pub fn delete_category(&mut self, id: Uuid, now_ms: i64) -> Result<(), SessionError> {
        if self.is_dirty() {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let mut candidate = self.data().clone();

        let index = candidate
            .categories
            .iter()
            .position(|category| category.id == id)
            .ok_or(SessionError::CategoryNotFound)?;

        if candidate
            .entries
            .iter()
            .any(|entry| entry.category_id == Some(id))
        {
            return Err(SessionError::CategoryInUse);
        }

        candidate.categories.remove(index);

        candidate.updated_at_ms = candidate.updated_at_ms.max(now_ms);

        candidate
            .validate()
            .map_err(SessionError::InvalidCategory)?;

        self.commit_candidate(candidate)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::*;
    use crate::vault::session::EntryInput;

    const NOW_MS: i64 = 1_700_000_000_000;

    const MASTER_PASSWORD: &str = "category-crud-master-password-test-only";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    fn category_input(name: &str) -> CategoryInput {
        CategoryInput {
            name: name.to_owned(),
        }
    }

    fn entry_input(category_id: Uuid) -> EntryInput {
        EntryInput {
            title: "Categorized Entry".to_owned(),
            profile_name: "Work".to_owned(),
            url: "https://category.example.test".to_owned(),
            username: "category-user".to_owned(),
            password: "CATEGORY_ENTRY_SECRET".to_owned(),
            notes: "CATEGORY_ENTRY_NOTE".to_owned(),
            category_id: Some(category_id),
            tags: vec!["category-test".to_owned()],
            favorite: false,
        }
    }

    #[test]
    fn create_category_persists_and_session_stays_clean() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let created = session
            .create_category(category_input("Work"), NOW_MS + 1)
            .unwrap();

        let id = created.id;

        assert_eq!(created.name, "Work");
        assert!(!session.is_dirty());

        session.lock();

        let reopened = UnlockedVaultSession::unlock(&path, password()).unwrap();

        let loaded = reopened.get_category(id).unwrap();

        assert_eq!(loaded.name, "Work");
    }

    #[test]
    fn list_and_get_category_return_expected_summary() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let created = session
            .create_category(category_input("Personal"), NOW_MS + 1)
            .unwrap();

        let categories = session.list_categories();

        assert_eq!(categories.len(), 1);
        assert_eq!(categories[0].id, created.id);
        assert_eq!(categories[0].name, "Personal");

        let loaded = session.get_category(created.id).unwrap();

        assert_eq!(loaded.id, created.id);
        assert_eq!(loaded.name, "Personal");
    }

    #[test]
    fn update_category_preserves_identity_and_creation_time() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let created = session
            .create_category(category_input("Before"), NOW_MS + 1)
            .unwrap();

        let id = created.id;
        let created_at_ms = created.created_at_ms;

        let updated = session
            .update_category(id, category_input("After"), NOW_MS + 2)
            .unwrap();

        assert_eq!(updated.id, id);
        assert_eq!(updated.name, "After");
        assert_eq!(updated.created_at_ms, created_at_ms);
        assert!(!session.is_dirty());
    }

    #[test]
    fn delete_category_persists_removal() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let created = session
            .create_category(category_input("Temporary"), NOW_MS + 1)
            .unwrap();

        session.delete_category(created.id, NOW_MS + 2).unwrap();

        assert!(session.list_categories().is_empty());

        session.lock();

        let reopened = UnlockedVaultSession::unlock(&path, password()).unwrap();

        assert!(reopened.list_categories().is_empty());
    }

    #[test]
    fn invalid_category_create_does_not_modify_session_or_disk() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let before = fs::read(&path).unwrap();

        let result = session.create_category(category_input("   "), NOW_MS + 1);

        assert!(matches!(result, Err(SessionError::InvalidCategory(_))));

        assert!(session.list_categories().is_empty());
        assert!(!session.is_dirty());

        let after = fs::read(&path).unwrap();

        assert_eq!(after, before);
    }

    #[test]
    fn category_in_use_cannot_be_deleted() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let category = session
            .create_category(category_input("Used"), NOW_MS + 1)
            .unwrap();

        session
            .create_entry(entry_input(category.id), NOW_MS + 2)
            .unwrap();

        let before = fs::read(&path).unwrap();

        let result = session.delete_category(category.id, NOW_MS + 3);

        assert!(matches!(result, Err(SessionError::CategoryInUse)));

        assert_eq!(session.list_categories().len(), 1);

        let after = fs::read(&path).unwrap();

        assert_eq!(after, before);
    }

    #[test]
    fn pending_dirty_state_blocks_transactional_category_mutation() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        session.data_mut().updated_at_ms = NOW_MS + 1;

        assert!(session.is_dirty());

        let result = session.create_category(category_input("Blocked"), NOW_MS + 2);

        assert!(matches!(result, Err(SessionError::PendingUnsavedChanges)));

        assert!(session.data().categories.is_empty());
    }
}
