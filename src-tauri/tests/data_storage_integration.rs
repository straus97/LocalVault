//! Desktop-storage-integrated coverage for the persisted `VaultData` model
//! (task 1S-C2).
//!
//! This test used to live inline inside `vault/data.rs`'s own `#[cfg(test)]`
//! module as `encrypted_storage_round_trip_preserves_model_and_hides_secrets`.
//! It was relocated here, unchanged in intent and assertions, when
//! `vault/data.rs` moved into `localvault-core` (`localvault_core::vault::data`)
//! -- the persisted data model itself must not depend on desktop storage
//! (`localvault_lib::vault::storage`), so this specific round-trip test,
//! which does depend on desktop storage, could not simply move with it.
//!
//! It is deliberately kept separate from `compat_baseline.rs`, which stays
//! focused on the committed compatibility fixtures.

use std::fs;

use localvault_core::vault::{
    data::VaultData,
    format::{create_envelope, open_envelope},
};
use localvault_lib::vault::storage::{load_envelope, save_envelope_atomic};

const NOW_MS: i64 = 1_700_000_000_000;

const MASTER_PASSWORD: &str = "model-layer-master-password-test-only";

const MODEL_TEST_SECRET: &str = "MODEL_TEST_ONLY_SECRET";

fn valid_sample_data() -> VaultData {
    use localvault_core::vault::data::{VaultCategory, VaultEntry};

    let mut data = VaultData::new(NOW_MS).unwrap();

    let category = VaultCategory::new("Work", NOW_MS).unwrap();

    let category_id = category.id;

    let mut entry = VaultEntry::new("Example Account", NOW_MS).unwrap();

    entry.profile_name = "Personal".to_owned();
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
fn encrypted_storage_round_trip_preserves_model_and_hides_secrets() {
    let temp = tempfile::tempdir().unwrap();
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
