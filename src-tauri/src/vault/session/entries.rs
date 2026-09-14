use std::mem;

use serde::Serialize;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use localvault_core::vault::data::{TotpConfig, VaultEntry, VAULT_DATA_SCHEMA_VERSION};

use super::{SessionError, UnlockedVaultSession};

pub struct EntryInput {
    pub title: String,
    pub profile_name: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub category_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub favorite: bool,
}

impl Drop for EntryInput {
    fn drop(&mut self) {
        self.title.zeroize();
        self.profile_name.zeroize();
        self.url.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();

        for tag in &mut self.tags {
            tag.zeroize();
        }

        self.tags.clear();
    }
}

pub enum TotpUpdate {
    Keep,
    Replace(TotpConfig),
    Remove,
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummary {
    pub id: Uuid,
    pub title: String,
    pub profile_name: String,
    pub url: String,
    pub username: String,
    pub totp_enabled: bool,
    pub category_id: Option<Uuid>,
    pub favorite: bool,
    pub updated_at_ms: i64,
}

impl Drop for EntrySummary {
    fn drop(&mut self) {
        self.title.zeroize();
        self.profile_name.zeroize();
        self.url.zeroize();
        self.username.zeroize();
    }
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EntryDetails {
    pub id: Uuid,
    pub title: String,
    pub profile_name: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub totp_enabled: bool,
    pub notes: String,
    pub category_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl Drop for EntryDetails {
    fn drop(&mut self) {
        self.title.zeroize();
        self.profile_name.zeroize();
        self.url.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();

        for tag in &mut self.tags {
            tag.zeroize();
        }

        self.tags.clear();
    }
}

impl EntrySummary {
    fn from_entry(entry: &VaultEntry) -> Self {
        Self {
            id: entry.id,
            title: entry.title.clone(),
            profile_name: entry.profile_name.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            totp_enabled: entry.totp.is_some(),
            category_id: entry.category_id,
            favorite: entry.favorite,
            updated_at_ms: entry.updated_at_ms,
        }
    }
}

impl EntryDetails {
    fn from_entry(entry: &VaultEntry) -> Self {
        Self {
            id: entry.id,
            title: entry.title.clone(),
            profile_name: entry.profile_name.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            password: entry.password.clone(),
            totp_enabled: entry.totp.is_some(),
            notes: entry.notes.clone(),
            category_id: entry.category_id,
            tags: entry.tags.clone(),
            favorite: entry.favorite,
            created_at_ms: entry.created_at_ms,
            updated_at_ms: entry.updated_at_ms,
        }
    }
}

impl EntryInput {
    fn into_new_entry(mut self, now_ms: i64) -> Result<VaultEntry, SessionError> {
        let title = mem::take(&mut self.title);

        let mut entry = VaultEntry::new(title, now_ms).map_err(SessionError::InvalidEntry)?;

        entry.profile_name = mem::take(&mut self.profile_name);
        entry.url = mem::take(&mut self.url);
        entry.username = mem::take(&mut self.username);
        entry.password = mem::take(&mut self.password);
        entry.notes = mem::take(&mut self.notes);
        entry.category_id = self.category_id;
        entry.tags = mem::take(&mut self.tags);
        entry.favorite = self.favorite;

        Ok(entry)
    }

    fn into_existing_entry(
        mut self,
        id: Uuid,
        created_at_ms: i64,
        updated_at_ms: i64,
        totp: Option<TotpConfig>,
    ) -> VaultEntry {
        VaultEntry {
            id,
            title: mem::take(&mut self.title),
            profile_name: mem::take(&mut self.profile_name),
            url: mem::take(&mut self.url),
            username: mem::take(&mut self.username),
            password: mem::take(&mut self.password),
            totp,
            notes: mem::take(&mut self.notes),
            category_id: self.category_id,
            tags: mem::take(&mut self.tags),
            favorite: self.favorite,
            created_at_ms,
            updated_at_ms,
        }
    }
}

impl UnlockedVaultSession {
    pub fn list_entries(&self) -> Vec<EntrySummary> {
        self.data()
            .entries
            .iter()
            .map(EntrySummary::from_entry)
            .collect()
    }

    pub fn get_entry(&self, id: Uuid) -> Result<EntryDetails, SessionError> {
        let entry = self
            .data()
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(SessionError::EntryNotFound)?;

        Ok(EntryDetails::from_entry(entry))
    }

    pub fn password_for_clipboard(&self, id: Uuid) -> Result<Zeroizing<String>, SessionError> {
        let entry = self
            .data()
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(SessionError::EntryNotFound)?;

        Ok(Zeroizing::new(entry.password.clone()))
    }
    pub fn create_entry(
        &mut self,
        input: EntryInput,
        now_ms: i64,
    ) -> Result<EntrySummary, SessionError> {
        if self.is_dirty() {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let entry = input.into_new_entry(now_ms)?;

        let entry_id = entry.id;

        let mut candidate = self.data().clone();

        candidate.entries.push(entry);

        candidate.updated_at_ms = candidate.updated_at_ms.max(now_ms);

        candidate.validate().map_err(SessionError::InvalidEntry)?;

        let details = candidate
            .entries
            .iter()
            .find(|entry| entry.id == entry_id)
            .map(EntrySummary::from_entry)
            .ok_or(SessionError::EntryNotFound)?;

        self.commit_candidate(candidate)?;

        Ok(details)
    }

    pub fn create_entry_with_totp(
        &mut self,
        input: EntryInput,
        totp: TotpConfig,
        now_ms: i64,
    ) -> Result<EntrySummary, SessionError> {
        if self.is_dirty() {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let mut entry = input.into_new_entry(now_ms)?;

        entry.totp = Some(totp);

        let entry_id = entry.id;

        let mut candidate = self.data().clone();

        candidate.entries.push(entry);

        candidate.schema_version = VAULT_DATA_SCHEMA_VERSION;

        candidate.updated_at_ms = candidate.updated_at_ms.max(now_ms);

        candidate.validate().map_err(SessionError::InvalidEntry)?;

        let summary = candidate
            .entries
            .iter()
            .find(|entry| entry.id == entry_id)
            .map(EntrySummary::from_entry)
            .ok_or(SessionError::EntryNotFound)?;

        self.commit_candidate(candidate)?;

        Ok(summary)
    }

    pub fn update_entry(
        &mut self,
        id: Uuid,
        input: EntryInput,
        now_ms: i64,
    ) -> Result<EntrySummary, SessionError> {
        if self.is_dirty() {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let mut candidate = self.data().clone();

        let index = candidate
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(SessionError::EntryNotFound)?;

        let created_at_ms = candidate.entries[index].created_at_ms;

        let previous_updated_at_ms = candidate.entries[index].updated_at_ms;

        let effective_updated_at_ms = now_ms.max(previous_updated_at_ms);

        let totp = candidate.entries[index].totp.take();

        let replacement =
            input.into_existing_entry(id, created_at_ms, effective_updated_at_ms, totp);

        candidate.entries[index] = replacement;

        candidate.updated_at_ms = candidate.updated_at_ms.max(effective_updated_at_ms);

        candidate.validate().map_err(SessionError::InvalidEntry)?;

        let details = EntrySummary::from_entry(&candidate.entries[index]);

        self.commit_candidate(candidate)?;

        Ok(details)
    }

    pub fn update_entry_with_totp(
        &mut self,
        id: Uuid,
        input: EntryInput,
        totp_update: TotpUpdate,
        now_ms: i64,
    ) -> Result<EntrySummary, SessionError> {
        if self.is_dirty() {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let mut candidate = self.data().clone();

        let index = candidate
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(SessionError::EntryNotFound)?;

        let created_at_ms = candidate.entries[index].created_at_ms;

        let previous_updated_at_ms = candidate.entries[index].updated_at_ms;

        let effective_updated_at_ms = now_ms.max(previous_updated_at_ms);

        let previous_totp = candidate.entries[index].totp.take();

        let next_totp = match totp_update {
            TotpUpdate::Keep => previous_totp,

            TotpUpdate::Replace(config) => Some(config),

            TotpUpdate::Remove => None,
        };

        let replacement =
            input.into_existing_entry(id, created_at_ms, effective_updated_at_ms, next_totp);

        candidate.entries[index] = replacement;

        candidate.schema_version = VAULT_DATA_SCHEMA_VERSION;

        candidate.updated_at_ms = candidate.updated_at_ms.max(effective_updated_at_ms);

        candidate.validate().map_err(SessionError::InvalidEntry)?;

        let summary = EntrySummary::from_entry(&candidate.entries[index]);

        self.commit_candidate(candidate)?;

        Ok(summary)
    }

    pub fn delete_entry(&mut self, id: Uuid, now_ms: i64) -> Result<(), SessionError> {
        if self.is_dirty() {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let mut candidate = self.data().clone();

        let index = candidate
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(SessionError::EntryNotFound)?;

        candidate.entries.remove(index);

        candidate.updated_at_ms = candidate.updated_at_ms.max(now_ms);

        candidate.validate().map_err(SessionError::InvalidEntry)?;

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

    const NOW_MS: i64 = 1_700_000_000_000;

    const MASTER_PASSWORD: &str = "entry-crud-master-password-test-only";

    const ENTRY_SECRET: &str = "ENTRY_CRUD_TEST_ONLY_SECRET";

    const ENTRY_NOTE: &str = "ENTRY_CRUD_PRIVATE_NOTE";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    fn input(title: &str) -> EntryInput {
        EntryInput {
            title: title.to_owned(),
            profile_name: "Personal".to_owned(),
            url: "https://crud.example.test".to_owned(),
            username: "crud-user@example.test".to_owned(),
            password: ENTRY_SECRET.to_owned(),
            notes: ENTRY_NOTE.to_owned(),
            category_id: None,
            tags: vec!["login".to_owned(), "test".to_owned()],
            favorite: true,
        }
    }

    #[test]
    fn create_entry_persists_and_session_stays_clean() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let created = session
            .create_entry(input("Created Entry"), NOW_MS + 1)
            .unwrap();

        let id = created.id;

        assert_eq!(created.title, "Created Entry");
        let created_details = session.get_entry(id).unwrap();

        assert_eq!(created_details.password, ENTRY_SECRET);
        assert!(!session.is_dirty());

        session.lock();

        let reopened = UnlockedVaultSession::unlock(&path, password()).unwrap();

        let loaded = reopened.get_entry(id).unwrap();

        assert_eq!(loaded.password, ENTRY_SECRET);
        assert_eq!(loaded.notes, ENTRY_NOTE);
    }

    #[test]
    fn list_entries_does_not_expose_password_or_notes() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        session
            .create_entry(input("Summary Entry"), NOW_MS + 1)
            .unwrap();

        let summaries = session.list_entries();

        assert_eq!(summaries.len(), 1);

        let json = serde_json::to_string(&summaries).unwrap();

        assert!(!json.contains(ENTRY_SECRET));
        assert!(!json.contains(ENTRY_NOTE));
        assert!(json.contains("Summary Entry"));
    }

    #[test]
    fn get_entry_returns_requested_full_record() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let created = session
            .create_entry(input("Details Entry"), NOW_MS + 1)
            .unwrap();

        let loaded = session.get_entry(created.id).unwrap();

        assert_eq!(loaded.id, created.id);
        assert_eq!(loaded.password, ENTRY_SECRET);
        assert_eq!(loaded.notes, ENTRY_NOTE);
    }

    #[test]
    fn update_entry_preserves_identity_and_creation_time() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let created = session
            .create_entry(input("Before Update"), NOW_MS + 1)
            .unwrap();

        let id = created.id;
        let before_update = session.get_entry(id).unwrap();

        let created_at_ms = before_update.created_at_ms;

        let mut changed = input("After Update");

        changed.password = "UPDATED_ENTRY_SECRET".to_owned();

        changed.favorite = false;

        let updated = session.update_entry(id, changed, NOW_MS + 2).unwrap();

        assert_eq!(updated.id, id);
        assert_eq!(updated.title, "After Update");
        let updated_details = session.get_entry(id).unwrap();

        assert_eq!(updated_details.created_at_ms, created_at_ms);
        assert_eq!(updated_details.password, "UPDATED_ENTRY_SECRET");
        assert!(!updated.favorite);
        assert!(!session.is_dirty());
    }

    #[test]
    fn delete_entry_persists_removal() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let created = session
            .create_entry(input("Delete Me"), NOW_MS + 1)
            .unwrap();

        let id = created.id;

        session.delete_entry(id, NOW_MS + 2).unwrap();

        assert!(matches!(
            session.get_entry(id),
            Err(SessionError::EntryNotFound)
        ));

        session.lock();

        let reopened = UnlockedVaultSession::unlock(&path, password()).unwrap();

        assert!(reopened.list_entries().is_empty());
    }

    #[test]
    fn invalid_create_does_not_modify_session_or_disk() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        let before = fs::read(&path).unwrap();

        let result = session.create_entry(input("   "), NOW_MS + 1);

        assert!(matches!(result, Err(SessionError::InvalidEntry(_))));

        assert!(session.list_entries().is_empty());
        assert!(!session.is_dirty());

        let after = fs::read(&path).unwrap();

        assert_eq!(after, before);
    }

    #[test]
    fn pending_dirty_state_blocks_transactional_entry_mutation() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, password(), NOW_MS).unwrap();

        session.data_mut().updated_at_ms = NOW_MS + 1;

        assert!(session.is_dirty());

        let result = session.create_entry(input("Blocked Entry"), NOW_MS + 2);

        assert!(matches!(result, Err(SessionError::PendingUnsavedChanges)));

        assert!(session.data().entries.is_empty());
    }
}
