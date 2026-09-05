use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

pub const VAULT_DATA_SCHEMA_VERSION: u16 = 1;

pub const MAX_ENTRIES: usize = 50_000;
pub const MAX_CATEGORIES: usize = 512;

pub const MAX_TITLE_CHARS: usize = 256;
pub const MAX_USERNAME_CHARS: usize = 1_024;
pub const MAX_PASSWORD_CHARS: usize = 16_384;
pub const MAX_URL_CHARS: usize = 4_096;
pub const MAX_NOTES_CHARS: usize = 262_144;

pub const MAX_CATEGORY_NAME_CHARS: usize = 128;
pub const MAX_TAGS_PER_ENTRY: usize = 64;
pub const MAX_TAG_CHARS: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultDataError {
    #[error("unsupported vault data schema version")]
    UnsupportedSchemaVersion,

    #[error("vault id must not be nil")]
    NilVaultId,

    #[error("entry id must not be nil")]
    NilEntryId,

    #[error("category id must not be nil")]
    NilCategoryId,

    #[error("vault contains too many entries")]
    TooManyEntries,

    #[error("vault contains too many categories")]
    TooManyCategories,

    #[error("duplicate entry id")]
    DuplicateEntryId(Uuid),

    #[error("duplicate category id")]
    DuplicateCategoryId(Uuid),

    #[error("entry references an unknown category")]
    UnknownCategory(Uuid),

    #[error("entry title must not be empty")]
    EmptyEntryTitle(Uuid),

    #[error("entry title is too long")]
    EntryTitleTooLong(Uuid),

    #[error("entry username is too long")]
    EntryUsernameTooLong(Uuid),

    #[error("entry password is too long")]
    EntryPasswordTooLong(Uuid),

    #[error("entry URL is too long")]
    EntryUrlTooLong(Uuid),

    #[error("entry notes are too long")]
    EntryNotesTooLong(Uuid),

    #[error("entry contains too many tags")]
    TooManyTags(Uuid),

    #[error("entry contains an empty tag")]
    EmptyTag(Uuid),

    #[error("entry tag is too long")]
    TagTooLong(Uuid),

    #[error("entry contains a duplicate tag")]
    DuplicateTag(Uuid),

    #[error("category name must not be empty")]
    EmptyCategoryName(Uuid),

    #[error("category name is too long")]
    CategoryNameTooLong(Uuid),

    #[error("vault timestamp is invalid")]
    InvalidVaultTimestamp,

    #[error("entry timestamp is invalid")]
    InvalidEntryTimestamp(Uuid),

    #[error("category timestamp is invalid")]
    InvalidCategoryTimestamp(Uuid),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultData {
    pub schema_version: u16,
    pub vault_id: Uuid,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub entries: Vec<VaultEntry>,
    pub categories: Vec<VaultCategory>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEntry {
    pub id: Uuid,
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub category_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultCategory {
    pub id: Uuid,
    pub name: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl VaultData {
    pub fn new(now_ms: i64) -> Result<Self, VaultDataError> {
        if now_ms < 0 {
            return Err(VaultDataError::InvalidVaultTimestamp);
        }

        Ok(Self {
            schema_version: VAULT_DATA_SCHEMA_VERSION,
            vault_id: Uuid::new_v4(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            entries: Vec::new(),
            categories: Vec::new(),
        })
    }

    pub fn validate(&self) -> Result<(), VaultDataError> {
        if self.schema_version != VAULT_DATA_SCHEMA_VERSION {
            return Err(VaultDataError::UnsupportedSchemaVersion);
        }

        if self.vault_id.is_nil() {
            return Err(VaultDataError::NilVaultId);
        }

        if !valid_timestamps(self.created_at_ms, self.updated_at_ms) {
            return Err(VaultDataError::InvalidVaultTimestamp);
        }

        if self.entries.len() > MAX_ENTRIES {
            return Err(VaultDataError::TooManyEntries);
        }

        if self.categories.len() > MAX_CATEGORIES {
            return Err(VaultDataError::TooManyCategories);
        }

        let mut category_ids = HashSet::with_capacity(self.categories.len());

        for category in &self.categories {
            validate_category(category)?;

            if !category_ids.insert(category.id) {
                return Err(VaultDataError::DuplicateCategoryId(category.id));
            }
        }

        let mut entry_ids = HashSet::with_capacity(self.entries.len());

        for entry in &self.entries {
            validate_entry(entry, &category_ids)?;

            if !entry_ids.insert(entry.id) {
                return Err(VaultDataError::DuplicateEntryId(entry.id));
            }
        }

        Ok(())
    }
}

impl VaultData {
    pub(crate) fn zeroize_sensitive_fields(&mut self) {
        for entry in &mut self.entries {
            entry.title.zeroize();
            entry.url.zeroize();
            entry.username.zeroize();
            entry.password.zeroize();
            entry.notes.zeroize();

            for tag in &mut entry.tags {
                tag.zeroize();
            }

            entry.tags.clear();
        }

        for category in &mut self.categories {
            category.name.zeroize();
        }

        self.entries.clear();
        self.categories.clear();
    }
}
impl Drop for VaultData {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}
impl VaultEntry {
    pub(crate) fn zeroize_sensitive_fields(&mut self) {
        self.title.zeroize();
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

impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}

impl VaultCategory {
    pub(crate) fn zeroize_sensitive_fields(&mut self) {
        self.name.zeroize();
    }
}

impl Drop for VaultCategory {
    fn drop(&mut self) {
        self.zeroize_sensitive_fields();
    }
}
impl VaultEntry {
    pub fn new(title: impl Into<String>, now_ms: i64) -> Result<Self, VaultDataError> {
        if now_ms < 0 {
            return Err(VaultDataError::InvalidEntryTimestamp(Uuid::nil()));
        }

        let entry = Self {
            id: Uuid::new_v4(),
            title: title.into(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
            category_id: None,
            tags: Vec::new(),
            favorite: false,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        if entry.title.trim().is_empty() {
            return Err(VaultDataError::EmptyEntryTitle(entry.id));
        }

        if char_count(&entry.title) > MAX_TITLE_CHARS {
            return Err(VaultDataError::EntryTitleTooLong(entry.id));
        }

        Ok(entry)
    }
}

impl VaultCategory {
    pub fn new(name: impl Into<String>, now_ms: i64) -> Result<Self, VaultDataError> {
        if now_ms < 0 {
            return Err(VaultDataError::InvalidCategoryTimestamp(Uuid::nil()));
        }

        let category = Self {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        if category.name.trim().is_empty() {
            return Err(VaultDataError::EmptyCategoryName(category.id));
        }

        if char_count(&category.name) > MAX_CATEGORY_NAME_CHARS {
            return Err(VaultDataError::CategoryNameTooLong(category.id));
        }

        Ok(category)
    }
}

fn validate_category(category: &VaultCategory) -> Result<(), VaultDataError> {
    if category.id.is_nil() {
        return Err(VaultDataError::NilCategoryId);
    }

    if category.name.trim().is_empty() {
        return Err(VaultDataError::EmptyCategoryName(category.id));
    }

    if char_count(&category.name) > MAX_CATEGORY_NAME_CHARS {
        return Err(VaultDataError::CategoryNameTooLong(category.id));
    }

    if !valid_timestamps(category.created_at_ms, category.updated_at_ms) {
        return Err(VaultDataError::InvalidCategoryTimestamp(category.id));
    }

    Ok(())
}

fn validate_entry(entry: &VaultEntry, category_ids: &HashSet<Uuid>) -> Result<(), VaultDataError> {
    if entry.id.is_nil() {
        return Err(VaultDataError::NilEntryId);
    }

    if entry.title.trim().is_empty() {
        return Err(VaultDataError::EmptyEntryTitle(entry.id));
    }

    if char_count(&entry.title) > MAX_TITLE_CHARS {
        return Err(VaultDataError::EntryTitleTooLong(entry.id));
    }

    if char_count(&entry.username) > MAX_USERNAME_CHARS {
        return Err(VaultDataError::EntryUsernameTooLong(entry.id));
    }

    if char_count(&entry.password) > MAX_PASSWORD_CHARS {
        return Err(VaultDataError::EntryPasswordTooLong(entry.id));
    }

    if char_count(&entry.url) > MAX_URL_CHARS {
        return Err(VaultDataError::EntryUrlTooLong(entry.id));
    }

    if char_count(&entry.notes) > MAX_NOTES_CHARS {
        return Err(VaultDataError::EntryNotesTooLong(entry.id));
    }

    if entry.tags.len() > MAX_TAGS_PER_ENTRY {
        return Err(VaultDataError::TooManyTags(entry.id));
    }

    let mut seen_tags = HashSet::with_capacity(entry.tags.len());

    for tag in &entry.tags {
        if tag.trim().is_empty() {
            return Err(VaultDataError::EmptyTag(entry.id));
        }

        if char_count(tag) > MAX_TAG_CHARS {
            return Err(VaultDataError::TagTooLong(entry.id));
        }

        if !seen_tags.insert(tag.as_str()) {
            return Err(VaultDataError::DuplicateTag(entry.id));
        }
    }

    if let Some(category_id) = entry.category_id {
        if !category_ids.contains(&category_id) {
            return Err(VaultDataError::UnknownCategory(entry.id));
        }
    }

    if !valid_timestamps(entry.created_at_ms, entry.updated_at_ms) {
        return Err(VaultDataError::InvalidEntryTimestamp(entry.id));
    }

    Ok(())
}

fn valid_timestamps(created_at_ms: i64, updated_at_ms: i64) -> bool {
    created_at_ms >= 0 && updated_at_ms >= created_at_ms
}

fn char_count(value: &str) -> usize {
    value.chars().count()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::vault::{
        format::{create_envelope, open_envelope},
        storage::{load_envelope, save_envelope_atomic},
    };

    const NOW_MS: i64 = 1_700_000_000_000;

    const MASTER_PASSWORD: &str = "model-layer-master-password-test-only";

    const MODEL_TEST_SECRET: &str = "MODEL_TEST_ONLY_SECRET";

    fn valid_sample_data() -> VaultData {
        let mut data = VaultData::new(NOW_MS).unwrap();

        let category = VaultCategory::new("Work", NOW_MS).unwrap();

        let category_id = category.id;

        let mut entry = VaultEntry::new("Example Account", NOW_MS).unwrap();

        entry.url = "https://example.test".to_owned();
        entry.username = "user@example.test".to_owned();
        entry.password = MODEL_TEST_SECRET.to_owned();
        entry.notes = "Test-only note".to_owned();
        entry.category_id = Some(category_id);
        entry.tags = vec!["work".to_owned(), "email".to_owned()];
        entry.favorite = true;

        data.categories.push(category);
        data.entries.push(entry);

        data.validate().unwrap();

        data
    }

    #[test]
    fn new_vault_has_valid_defaults() {
        let data = VaultData::new(NOW_MS).unwrap();

        assert_eq!(data.schema_version, VAULT_DATA_SCHEMA_VERSION);
        assert!(!data.vault_id.is_nil());
        assert!(data.entries.is_empty());
        assert!(data.categories.is_empty());
        assert!(data.validate().is_ok());
    }

    #[test]
    fn valid_entry_and_category_are_accepted() {
        let data = valid_sample_data();

        assert_eq!(data.entries.len(), 1);
        assert_eq!(data.categories.len(), 1);
        assert!(data.validate().is_ok());
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let mut data = valid_sample_data();

        data.schema_version = VAULT_DATA_SCHEMA_VERSION + 1;

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::UnsupportedSchemaVersion)
        ));
    }

    #[test]
    fn duplicate_entry_ids_are_rejected() {
        let mut data = valid_sample_data();

        let duplicate = data.entries[0].clone();
        data.entries.push(duplicate);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::DuplicateEntryId(_))
        ));
    }

    #[test]
    fn duplicate_category_ids_are_rejected() {
        let mut data = valid_sample_data();

        let duplicate = data.categories[0].clone();
        data.categories.push(duplicate);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::DuplicateCategoryId(_))
        ));
    }

    #[test]
    fn unknown_category_reference_is_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].category_id = Some(Uuid::new_v4());

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::UnknownCategory(_))
        ));
    }

    #[test]
    fn empty_entry_title_is_rejected() {
        let result = VaultEntry::new("   ", NOW_MS);

        assert!(matches!(result, Err(VaultDataError::EmptyEntryTitle(_))));
    }

    #[test]
    fn oversized_password_is_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].password = "x".repeat(MAX_PASSWORD_CHARS + 1);

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::EntryPasswordTooLong(_))
        ));
    }

    #[test]
    fn invalid_timestamp_order_is_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].updated_at_ms = data.entries[0].created_at_ms - 1;

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::InvalidEntryTimestamp(_))
        ));
    }

    #[test]
    fn duplicate_tags_are_rejected() {
        let mut data = valid_sample_data();

        data.entries[0].tags = vec!["work".to_owned(), "work".to_owned()];

        assert!(matches!(
            data.validate(),
            Err(VaultDataError::DuplicateTag(_))
        ));
    }

    #[test]
    fn serialization_round_trip_preserves_model() {
        let data = valid_sample_data();

        let json = serde_json::to_vec(&data).unwrap();

        let restored: VaultData = serde_json::from_slice(&json).unwrap();

        restored.validate().unwrap();

        assert!(restored == data);
    }

    #[test]
    fn encrypted_storage_round_trip_preserves_model_and_hides_secrets() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("model.lvault");

        let data = valid_sample_data();

        let plaintext = serde_json::to_vec(&data).unwrap();

        let envelope = create_envelope(MASTER_PASSWORD, &plaintext).unwrap();

        save_envelope_atomic(&path, &envelope).unwrap();

        let raw = fs::read_to_string(&path).unwrap();

        assert!(!raw.contains(MASTER_PASSWORD));
        assert!(!raw.contains(MODEL_TEST_SECRET));
        assert!(!raw.contains("user@example.test"));
        assert!(!raw.contains("https://example.test"));

        let loaded = load_envelope(&path).unwrap();

        let decrypted = open_envelope(MASTER_PASSWORD, &loaded).unwrap();

        let restored: VaultData = serde_json::from_slice(decrypted.as_slice()).unwrap();

        restored.validate().unwrap();

        assert!(restored == data);
    }

    #[test]
    fn sensitive_fields_are_zeroized_before_session_drop() {
        let mut data = valid_sample_data();

        assert!(!data.entries[0].password.is_empty());
        assert!(!data.entries[0].username.is_empty());
        assert!(!data.entries[0].url.is_empty());
        assert!(!data.entries[0].notes.is_empty());
        assert!(!data.categories[0].name.is_empty());

        data.zeroize_sensitive_fields();

        assert!(data.entries.is_empty());
        assert!(data.categories.is_empty());
    }

    #[test]
    fn individual_entry_sensitive_fields_can_be_zeroized() {
        let mut entry = VaultEntry::new("Sensitive title", NOW_MS).unwrap();

        entry.url = "https://sensitive.example".to_owned();
        entry.username = "sensitive-user".to_owned();
        entry.password = "sensitive-password".to_owned();
        entry.notes = "sensitive-notes".to_owned();
        entry.tags = vec!["private".to_owned(), "important".to_owned()];

        entry.zeroize_sensitive_fields();

        assert!(entry.title.is_empty());
        assert!(entry.url.is_empty());
        assert!(entry.username.is_empty());
        assert!(entry.password.is_empty());
        assert!(entry.notes.is_empty());
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn individual_category_name_can_be_zeroized() {
        let mut category = VaultCategory::new("Sensitive Category", NOW_MS).unwrap();

        assert!(!category.name.is_empty());

        category.zeroize_sensitive_fields();

        assert!(category.name.is_empty());
    }
}
