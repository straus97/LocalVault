//! Pre-extraction compatibility safety net (task 1S-B1).
//!
//! These integration tests exist to protect LocalVault's persisted vault
//! format and upgrade-on-write behavior ahead of the `localvault-core`
//! extraction (1S). They exercise the CURRENT, unmodified public vault API
//! (`localvault_lib::vault::*`, `localvault_lib::totp::*`) against two
//! committed synthetic fixtures:
//!
//! - `fixtures/compat/schema2_baseline.envelope.json` -- schema version 2,
//!   includes one normal credential, one credential with a TOTP
//!   configuration, and one cached site icon, so it genuinely exercises the
//!   schema-2 shape.
//! - `fixtures/compat/schema1_baseline.envelope.json` -- schema version 1
//!   (legacy). Schema 1 cannot carry TOTP, so no entry here has one; it
//!   DOES carry one cached site icon, because `VaultData::validate` only
//!   restricts TOTP for legacy vaults -- `site_icons` has no schema gate.
//!
//! The fixtures are ordinary encrypted `VaultEnvelope` JSON -- byte-for-byte
//! what `save_envelope_atomic` would write to a `.lvault` file. They use the
//! `.envelope.json` extension (not `.lvault`) purely so they are not
//! swallowed by this repo's `.gitignore`, which intentionally ignores
//! `*.lvault`/`*.lvault.*` to keep real vault files out of version control;
//! that ignore rule was left untouched, as `.gitignore` is outside this
//! task's approved scope.
//!
//! Fixture data is entirely synthetic (example.com-style domains, fixed
//! test-only passwords, a fixed fake TOTP secret). Both fixtures were
//! generated from pre-extraction checkpoint
//! `c5eb5e6ae8698b1197a645fa11ef5cd9a5a4e6cc` using LocalVault's own
//! `VaultData` / `create_envelope` production APIs (no hand-crafted
//! ciphertext). They are PRE-EXTRACTION BASELINE fixtures -- compatibility
//! baselines captured from current HEAD, not proof that any historical
//! release binary produced identical bytes, and not secret material.
//!
//! Freshly generated envelopes are expected to use fresh, non-deterministic
//! randomness (salt/nonce/ciphertext/key). Nothing here asserts otherwise;
//! see `fresh_vault_creation_uses_randomized_encryption` below, which
//! explicitly asserts the opposite (non-equality) for two independently
//! created vaults.
//!
//! Test placement: this lives as a `tests/*.rs` integration test (a
//! separate crate depending on the `localvault_lib` rlib, plus the
//! `localvault_core` rlib for the format layer) rather than as an inline
//! `#[cfg(test)]` module, because every API needed --
//! `UnlockedVaultSession::{unlock, create, data, list_categories,
//! create_category}`, `localvault_core::vault::format::open_envelope`,
//! `vault::storage::load_envelope`, `vault::data::*`, and `totp::*` -- is
//! already `pub`. No production visibility changes were needed or made
//! beyond the four `localvault-core` extraction functions documented in
//! the 1S-C1 extraction task.

use std::{collections::BTreeSet, fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use localvault_core::vault::format::open_envelope;
use localvault_lib::{
    totp::generate_totp,
    vault::{
        data::{
            SiteIcon, TotpAlgorithm, TotpConfig, VaultCategory, VaultData, VaultEntry,
            LEGACY_VAULT_DATA_SCHEMA_VERSION, VAULT_DATA_SCHEMA_VERSION,
        },
        session::{CategoryInput, UnlockedVaultSession},
        storage::load_envelope,
    },
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Test-only master password intentionally embedded in source; it protects
/// only synthetic fixture data, never a real vault.
const MASTER_PASSWORD: &str = "compat-baseline-master-password-test-only";

const NOW_MS: i64 = 1_700_000_000_000;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat")
}

fn schema2_fixture_path() -> PathBuf {
    fixtures_dir().join("schema2_baseline.envelope.json")
}

fn schema1_fixture_path() -> PathBuf {
    fixtures_dir().join("schema1_baseline.envelope.json")
}

fn password() -> Zeroizing<String> {
    Zeroizing::new(MASTER_PASSWORD.to_owned())
}

// ---------------------------------------------------------------------
// A. Current schema-2 encrypted baseline fixture
// ---------------------------------------------------------------------

#[test]
fn schema2_baseline_fixture_authenticates_and_recovers_expected_data() {
    let envelope = load_envelope(&schema2_fixture_path()).expect("fixture envelope parses");

    let plaintext =
        open_envelope(MASTER_PASSWORD, &envelope).expect("fixture authenticates and decrypts");

    let data: VaultData =
        serde_json::from_slice(plaintext.as_slice()).expect("fixture plaintext is valid VaultData");

    data.validate()
        .expect("fixture VaultData is semantically valid");

    assert_eq!(data.schema_version, VAULT_DATA_SCHEMA_VERSION);
    assert_eq!(data.categories.len(), 1);
    assert_eq!(data.categories[0].name, "Fixture Category");
    assert_eq!(data.entries.len(), 2);

    let normal_entry = data
        .entries
        .iter()
        .find(|entry| entry.title == "Fixture Login")
        .expect("normal fixture entry is present");

    assert_eq!(normal_entry.username, "fixture.user@example.com");
    assert_eq!(normal_entry.password, "FixtureBaselinePassword123!");
    assert_eq!(normal_entry.profile_name, "Fixture Profile");
    assert!(normal_entry.totp.is_none());

    let totp_entry = data
        .entries
        .iter()
        .find(|entry| entry.title == "Fixture TOTP Account")
        .expect("TOTP fixture entry is present");

    assert_eq!(totp_entry.username, "totp.user@example.com");
    assert_eq!(totp_entry.password, "FixtureTotpPassword456!");

    let totp = totp_entry
        .totp
        .as_ref()
        .expect("TOTP configuration is recovered");

    assert_eq!(totp.algorithm, TotpAlgorithm::Sha256);
    assert_eq!(totp.digits, 8);
    assert_eq!(totp.period_seconds, 60);

    // Deterministic RFC 6238-style check: the same secret/algorithm/digits/
    // period at a fixed point in time always yields the same code. This
    // value was captured once from the unmodified current implementation
    // when the fixture was generated.
    let check_now_ms: i64 = 1_700_000_100_000;
    let generated = generate_totp(totp, check_now_ms).expect("TOTP code computes");
    assert_eq!(generated.code(), "27711647");

    assert_eq!(data.site_icons.len(), 1);

    let icon = &data.site_icons[0];
    assert_eq!(icon.hostname, "example.com");

    let icon_bytes = BASE64_STANDARD
        .decode(icon.png_base64.as_bytes())
        .expect("cached icon payload is valid base64");
    assert_eq!(icon_bytes, b"\x89PNG\r\n\x1a\nCOMPATFIXTURE1");
}

// ---------------------------------------------------------------------
// B. Legacy schema-1 baseline fixture
// ---------------------------------------------------------------------

#[test]
fn schema1_baseline_fixture_authenticates_and_recovers_expected_data() {
    let envelope = load_envelope(&schema1_fixture_path()).expect("fixture envelope parses");

    let plaintext =
        open_envelope(MASTER_PASSWORD, &envelope).expect("fixture authenticates and decrypts");

    let data: VaultData =
        serde_json::from_slice(plaintext.as_slice()).expect("fixture plaintext is valid VaultData");

    data.validate()
        .expect("legacy fixture VaultData is semantically valid");

    assert_eq!(data.schema_version, LEGACY_VAULT_DATA_SCHEMA_VERSION);
    assert_eq!(data.categories.len(), 1);
    assert_eq!(data.categories[0].name, "Legacy Fixture Category");
    assert_eq!(data.entries.len(), 2);

    for entry in &data.entries {
        assert!(
            entry.totp.is_none(),
            "schema 1 must never carry a TOTP configuration"
        );
    }

    let first = data
        .entries
        .iter()
        .find(|entry| entry.title == "Legacy Fixture Login")
        .expect("first legacy fixture entry is present");

    assert_eq!(first.username, "legacy.user@example.com");
    assert_eq!(first.password, "LegacyBaselinePassword123!");
    assert_eq!(first.profile_name, "Legacy Profile");

    let second = data
        .entries
        .iter()
        .find(|entry| entry.title == "Legacy Fixture Second Login")
        .expect("second legacy fixture entry is present");

    assert_eq!(second.username, "legacy2.user@example.com");
    assert_eq!(second.password, "LegacyBaselinePassword456!");

    // Schema 1 has no restriction on site_icons -- only TOTP is
    // legacy-gated -- so a legacy vault legitimately carries a cached icon.
    assert_eq!(data.site_icons.len(), 1);

    let icon = &data.site_icons[0];
    assert_eq!(icon.hostname, "legacy.example.com");

    let icon_bytes = BASE64_STANDARD
        .decode(icon.png_base64.as_bytes())
        .expect("cached icon payload is valid base64");
    assert_eq!(icon_bytes, b"\x89PNG\r\n\x1a\nLEGACYFIXTURE1");
}

// ---------------------------------------------------------------------
// C. End-to-end legacy v1 -> v2 upgrade-on-write
// ---------------------------------------------------------------------

#[test]
fn legacy_schema1_vault_upgrades_to_schema2_on_write_and_preserves_data() {
    let fixture_bytes_before = fs::read(schema1_fixture_path()).expect("fixture is readable");

    let temp = tempfile::tempdir().unwrap();
    let vault_path = temp.path().join("legacy-copy.lvault");

    // Work on a COPY in a temporary directory; the committed fixture is
    // never opened for writing.
    fs::copy(schema1_fixture_path(), &vault_path).expect("fixture copies into temp dir");

    let mut session =
        UnlockedVaultSession::unlock(&vault_path, password()).expect("legacy copy unlocks");

    assert_eq!(
        session.data().schema_version,
        LEGACY_VAULT_DATA_SCHEMA_VERSION
    );

    let original_entry_count = session.data().entries.len();
    let original_titles: Vec<String> = session
        .data()
        .entries
        .iter()
        .map(|entry| entry.title.clone())
        .collect();

    assert_eq!(session.data().site_icons.len(), 1);
    let original_site_icons: Vec<SiteIcon> = session.data().site_icons.clone();

    // A harmless real mutation through the existing, real session/domain
    // API. `create_category` goes through `commit_candidate`, which is the
    // actual upgrade-on-write code path (it unconditionally rewrites a
    // legacy schema_version to the current one before validating/saving).
    session
        .create_category(
            CategoryInput {
                name: "Upgrade Marker Category".to_owned(),
            },
            NOW_MS + 10,
        )
        .expect("category creation succeeds and saves through the real save path");

    assert!(!session.is_dirty());

    session.lock();

    let reopened =
        UnlockedVaultSession::unlock(&vault_path, password()).expect("upgraded vault reopens");

    assert_eq!(
        reopened.data().schema_version,
        VAULT_DATA_SCHEMA_VERSION,
        "write to a legacy vault must upgrade it to the current schema"
    );

    assert_eq!(reopened.data().entries.len(), original_entry_count);

    for title in &original_titles {
        assert!(
            reopened
                .data()
                .entries
                .iter()
                .any(|entry| &entry.title == title),
            "pre-existing synthetic entry '{title}' must survive the upgrade"
        );
    }

    assert!(
        reopened
            .list_categories()
            .iter()
            .any(|category| category.name == "Upgrade Marker Category"),
        "the mutation performed during upgrade must be preserved"
    );

    // `SiteIcon` intentionally does not derive `Debug` (it holds
    // cache/secret-adjacent data), so compare via `PartialEq` and report
    // mismatches through its individual (Debug-able) fields instead of
    // `assert_eq!`, which requires `Debug`.
    assert!(
        reopened.data().site_icons == original_site_icons,
        "the pre-existing synthetic cached site icon must survive the v1 -> v2 upgrade-on-write: \
         before={:?} after={:?}",
        original_site_icons
            .iter()
            .map(|icon| (&icon.hostname, &icon.png_base64, icon.updated_at_ms))
            .collect::<Vec<_>>(),
        reopened
            .data()
            .site_icons
            .iter()
            .map(|icon| (&icon.hostname, &icon.png_base64, icon.updated_at_ms))
            .collect::<Vec<_>>()
    );

    // Still authenticates/decrypts normally end-to-end.
    let reopened_envelope = load_envelope(&vault_path).unwrap();
    let reopened_plaintext = open_envelope(MASTER_PASSWORD, &reopened_envelope).unwrap();
    let reopened_data: VaultData = serde_json::from_slice(reopened_plaintext.as_slice()).unwrap();
    reopened_data
        .validate()
        .expect("upgraded vault data is valid");

    // The committed fixture itself must be untouched by this test.
    let fixture_bytes_after = fs::read(schema1_fixture_path()).expect("fixture is still readable");
    assert_eq!(
        fixture_bytes_before, fixture_bytes_after,
        "the committed schema-1 fixture must never be modified by this test"
    );
}

// ---------------------------------------------------------------------
// D. Structural plaintext serialization regression test
// ---------------------------------------------------------------------

#[test]
fn plaintext_serialization_structure_matches_expected_schema_2_shape() {
    let vault_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
    let category_id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
    let totp_entry_id = Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap();
    let plain_entry_id = Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap();

    let mut category = VaultCategory::new("Structural Category", NOW_MS).unwrap();
    category.id = category_id;

    let mut totp_entry = VaultEntry::new("Structural TOTP Entry", NOW_MS).unwrap();
    totp_entry.id = totp_entry_id;
    totp_entry.profile_name = "Structural Profile".to_owned();
    totp_entry.url = "https://structure.example.com".to_owned();
    totp_entry.username = "structure.user@example.com".to_owned();
    totp_entry.password = "StructuralPassword123!".to_owned();
    totp_entry.notes = "structural notes".to_owned();
    totp_entry.category_id = Some(category_id);
    totp_entry.tags = vec!["structure".to_owned()];
    totp_entry.favorite = true;
    totp_entry.totp = Some(TotpConfig {
        secret_base64: BASE64_STANDARD.encode(b"structural-fake-totp-secret!!"),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period_seconds: 30,
    });

    // A second entry with no TOTP and an empty profile_name, to confirm
    // `skip_serializing_if` omission behavior for optional fields.
    let mut plain_entry = VaultEntry::new("Structural Plain Entry", NOW_MS).unwrap();
    plain_entry.id = plain_entry_id;
    plain_entry.url = "https://structure2.example.com".to_owned();
    plain_entry.username = "structure2.user@example.com".to_owned();
    plain_entry.password = "StructuralPassword456!".to_owned();

    let mut data = VaultData::new(NOW_MS).unwrap();
    data.vault_id = vault_id;
    data.categories.push(category);
    data.entries.push(totp_entry);
    data.entries.push(plain_entry);
    data.updated_at_ms = NOW_MS;
    data.validate().unwrap();

    let value = serde_json::to_value(&data).unwrap();

    let expected_top_level: BTreeSet<String> = [
        "schema_version",
        "vault_id",
        "created_at_ms",
        "updated_at_ms",
        "entries",
        "categories",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    let top_level_keys: BTreeSet<String> = value.as_object().unwrap().keys().cloned().collect();

    assert_eq!(
        top_level_keys, expected_top_level,
        "top-level VaultData fields must not be silently renamed/added/removed; \
         `site_icons` must stay omitted when empty"
    );

    assert_eq!(
        value["schema_version"],
        serde_json::json!(VAULT_DATA_SCHEMA_VERSION)
    );

    let expected_entry_keys: BTreeSet<String> = [
        "id",
        "title",
        "profile_name",
        "url",
        "username",
        "password",
        "totp",
        "notes",
        "category_id",
        "tags",
        "favorite",
        "created_at_ms",
        "updated_at_ms",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    let totp_entry_value = &value["entries"][0];
    let totp_entry_keys: BTreeSet<String> = totp_entry_value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(totp_entry_keys, expected_entry_keys);

    assert_eq!(
        totp_entry_value["title"],
        serde_json::json!("Structural TOTP Entry")
    );
    assert_eq!(
        totp_entry_value["password"],
        serde_json::json!("StructuralPassword123!")
    );

    let expected_totp_keys: BTreeSet<String> =
        ["secret_base64", "algorithm", "digits", "period_seconds"]
            .into_iter()
            .map(String::from)
            .collect();

    let totp_value = &totp_entry_value["totp"];
    let totp_keys: BTreeSet<String> = totp_value.as_object().unwrap().keys().cloned().collect();
    assert_eq!(totp_keys, expected_totp_keys);

    // Enum representation regression: TotpAlgorithm must keep serializing
    // as its plain uppercase string form, not e.g. a nested tagged object.
    assert_eq!(totp_value["algorithm"], serde_json::json!("SHA1"));

    let plain_entry_value = &value["entries"][1];
    let plain_entry_keys: BTreeSet<String> = plain_entry_value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();

    let expected_plain_entry_keys: BTreeSet<String> = expected_entry_keys
        .iter()
        .filter(|key| *key != "totp" && *key != "profile_name")
        .cloned()
        .collect();

    assert_eq!(
        plain_entry_keys, expected_plain_entry_keys,
        "`totp: None` and an empty `profile_name` must both stay omitted, not null"
    );

    let expected_category_keys: BTreeSet<String> = ["id", "name", "created_at_ms", "updated_at_ms"]
        .into_iter()
        .map(String::from)
        .collect();

    let category_value = &value["categories"][0];
    let category_keys: BTreeSet<String> = category_value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(category_keys, expected_category_keys);
    assert_eq!(
        category_value["name"],
        serde_json::json!("Structural Category")
    );
}

// ---------------------------------------------------------------------
// D2. Structural plaintext serialization regression test: non-empty
//     `site_icons` (persisted encrypted favicon cache data model only --
//     no network/fetch behavior is exercised here).
// ---------------------------------------------------------------------

#[test]
fn plaintext_serialization_structure_matches_expected_nonempty_site_icons_shape() {
    let icon_bytes: &[u8] = b"\x89PNG\r\n\x1a\nSTRUCTURALICON1";
    let icon_base64 = BASE64_STANDARD.encode(icon_bytes);

    let mut data = VaultData::new(NOW_MS).unwrap();
    data.site_icons.push(SiteIcon {
        hostname: "structural-icon.example.com".to_owned(),
        png_base64: icon_base64.clone(),
        updated_at_ms: NOW_MS + 5,
    });
    data.updated_at_ms = NOW_MS + 5;
    data.validate().unwrap();

    let value = serde_json::to_value(&data).unwrap();

    let top_level_keys: BTreeSet<String> = value.as_object().unwrap().keys().cloned().collect();

    assert!(
        top_level_keys.contains("site_icons"),
        "`site_icons` must be present in the serialized object when non-empty"
    );

    let site_icons_value = value["site_icons"]
        .as_array()
        .expect("site_icons serializes as a JSON array");
    assert_eq!(site_icons_value.len(), 1);

    let expected_icon_keys: BTreeSet<String> = ["hostname", "png_base64", "updated_at_ms"]
        .into_iter()
        .map(String::from)
        .collect();

    let icon_value = &site_icons_value[0];
    let icon_keys: BTreeSet<String> = icon_value.as_object().unwrap().keys().cloned().collect();

    assert_eq!(
        icon_keys, expected_icon_keys,
        "the persisted cached site-icon fields must not be silently renamed/added/removed"
    );

    assert_eq!(
        icon_value["hostname"],
        serde_json::json!("structural-icon.example.com")
    );
    assert_eq!(icon_value["png_base64"], serde_json::json!(icon_base64));
    assert_eq!(icon_value["updated_at_ms"], serde_json::json!(NOW_MS + 5));

    // Round-trip the persisted base64 encoding itself, since that encoding
    // (not just the field's presence) is part of the persisted contract.
    let decoded = BASE64_STANDARD
        .decode(icon_value["png_base64"].as_str().unwrap())
        .expect("persisted png_base64 must remain valid standard base64");
    assert_eq!(decoded, icon_bytes);

    // Re-parse and re-validate to confirm the round trip is faithful end to
    // end, not just at the raw `serde_json::Value` level.
    let restored: VaultData = serde_json::from_value(value).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored.site_icons.len(), 1);
    assert_eq!(
        restored.site_icons[0].hostname,
        "structural-icon.example.com"
    );
    assert_eq!(restored.site_icons[0].png_base64, icon_base64);
    assert_eq!(restored.site_icons[0].updated_at_ms, NOW_MS + 5);
}

// ---------------------------------------------------------------------
// E. Envelope/crypto compatibility: freshness is NOT expected to be
//    deterministic, at the session layer specifically.
// ---------------------------------------------------------------------

#[test]
fn fresh_vault_creation_uses_randomized_encryption() {
    let temp = tempfile::tempdir().unwrap();

    let first_path = temp.path().join("first.lvault");
    let second_path = temp.path().join("second.lvault");

    let first_session =
        UnlockedVaultSession::create(&first_path, password(), NOW_MS).expect("first vault creates");
    let second_session = UnlockedVaultSession::create(&second_path, password(), NOW_MS)
        .expect("second vault creates");

    first_session.lock();
    second_session.lock();

    let first_envelope = load_envelope(&first_path).unwrap();
    let second_envelope = load_envelope(&second_path).unwrap();

    // Same master password, same now_ms, same empty starting data -- but
    // salts/nonces/keys/ciphertext must never be equal across independent
    // fresh vaults.
    assert_ne!(first_envelope.kdf_salt, second_envelope.kdf_salt);
    assert_ne!(
        first_envelope.wrapped_vault_key,
        second_envelope.wrapped_vault_key
    );
    assert_ne!(first_envelope.payload.nonce, second_envelope.payload.nonce);
}
