//! Android FFI adapter for `localvault-core` (stable UniFFI 0.32 Kotlin/JNA).
//!
//! This crate is a thin adapter: it marshals bytes and small non-secret
//! values across the FFI boundary and owns the decrypted session state on the
//! Rust side. It must never duplicate cryptography, vault-format parsing or
//! schema validation -- all of that stays in `localvault-core` (see
//! `docs/ARCHITECTURE.md`).
//!
//! B2 scope is deliberately read-only: open an encrypted vault envelope with
//! the master password, keep the decrypted `VaultData` Rust-owned inside a
//! `VaultSession`, list non-secret entry summaries, and lock. The Master Key
//! and Vault Key never leave `localvault-core`; decrypted `VaultData` and its
//! JSON never cross the boundary.

use std::sync::{Arc, Mutex, MutexGuard};

use localvault_core::vault::{
    data::VaultData,
    format::{open_envelope, CryptoError, VaultEnvelope, VaultError},
};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// Non-secret list-row summary. Deliberately excludes passwords, notes, TOTP
/// configuration/secrets, tags and key material.
///
/// Every field is required to render a useful row: `id` is the stable entry
/// identity, `title` is the primary label, and `profile_name`, `username` and
/// `url` are the direct existing entry fields that distinguish entries that
/// share a title (the desktop list shows the same fields). No normalization
/// or reinterpretation is applied -- values are passed through as stored.
///
/// The record intentionally has no `Drop`/zeroize impl: UniFFI's generated
/// lowering moves fields out of the value, and the lowered copy handed to the
/// JVM cannot be zeroized in any case (see docs/SECURITY_MODEL.md's JS-string
/// precedent for the same, runtime-shaped limitation).
#[derive(uniffi::Record)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub profile_name: String,
    pub url: String,
    pub username: String,
}

/// Non-secret detail for one entry, fetched only when the user opens it.
///
/// Deliberately excludes the password (fetched separately, and only on an
/// explicit show/copy via [`VaultSession::entry_password`]), notes, TOTP
/// configuration/secrets, tags and key material. Opening an entry card
/// therefore never moves that entry's password across the FFI boundary.
#[derive(uniffi::Record)]
pub struct EntryDetails {
    pub id: String,
    pub title: String,
    pub profile_name: String,
    pub url: String,
    pub username: String,
}

/// Structured, oracle-safe bridge error.
///
/// `localvault-core` does not distinguish "wrong master password" from
/// "tampered/corrupted authenticated ciphertext" -- both collapse into
/// `CryptoError::Decryption` -- so this enum preserves that indistinguishability
/// (`AuthenticationFailed`) instead of inventing a finer authentication oracle.
/// `UnsupportedFormat` is safe to expose separately: it is decided either by
/// `VaultEnvelope::validate_header` before any password-dependent operation,
/// or only *after* successful authentication (malformed/invalid decrypted
/// data), so it cannot leak whether a password guess was close.
#[derive(uniffi::Error, thiserror::Error, Debug, PartialEq, Eq)]
pub enum BridgeError {
    #[error("input is invalid")]
    InvalidInput,
    #[error("vault format is unsupported")]
    UnsupportedFormat,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("vault session is locked")]
    SessionLocked,
    #[error("entry not found")]
    EntryNotFound,
}

fn map_vault_error(err: VaultError) -> BridgeError {
    match err {
        VaultError::EmptyMasterPassword => BridgeError::InvalidInput,
        VaultError::UnsupportedFormat => BridgeError::UnsupportedFormat,
        VaultError::Crypto(CryptoError::InvalidKdfParameters) => BridgeError::UnsupportedFormat,
        VaultError::Crypto(_) => BridgeError::AuthenticationFailed,
        VaultError::InvalidWrappedKey => BridgeError::AuthenticationFailed,
    }
}

/// An unlocked, Rust-owned, read-only vault session.
///
/// Holds only the decrypted `VaultData` -- not the Master Key, not the Vault
/// Key (`open_envelope` drops and zeroizes both before returning). Locking
/// takes the `VaultData` out and drops it, which zeroizes its sensitive
/// fields through `localvault-core`'s existing `Drop` implementation. Dropping
/// the last reference to the session does the same.
#[derive(uniffi::Object)]
pub struct VaultSession {
    data: Mutex<Option<VaultData>>,
}

impl VaultSession {
    fn guard(&self) -> MutexGuard<'_, Option<VaultData>> {
        // A poisoned mutex must never turn a lock/list call into a panic
        // across the FFI boundary; the guarded state is still valid to drop.
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn find_entry<'a>(
    data: &'a VaultData,
    entry_id: &str,
) -> Result<&'a localvault_core::vault::data::VaultEntry, BridgeError> {
    data.entries
        .iter()
        .find(|entry| entry.id.to_string() == entry_id)
        .ok_or(BridgeError::EntryNotFound)
}

/// Synchronously open an encrypted vault envelope (`.lvault` file bytes) with
/// the master password and return a Rust-owned session.
///
/// Uses `localvault-core`'s existing envelope, schema and validation APIs
/// unchanged. This performs a real Argon2id derivation and must be called off
/// the Android main thread.
#[uniffi::export]
pub fn open_vault(
    envelope_bytes: Vec<u8>,
    master_password: String,
) -> Result<Arc<VaultSession>, BridgeError> {
    // Move the received password into zeroizing storage as early as
    // practical. This bounds the Rust-side copy's lifetime to this call; it
    // does not (and cannot) erase the JVM/JNA-side copy that produced it.
    let master_password = Zeroizing::new(master_password);

    let envelope: VaultEnvelope =
        serde_json::from_slice(&envelope_bytes).map_err(|_| BridgeError::UnsupportedFormat)?;

    let plaintext = open_envelope(master_password.as_str(), &envelope).map_err(map_vault_error)?;

    let data: VaultData =
        serde_json::from_slice(plaintext.as_slice()).map_err(|_| BridgeError::UnsupportedFormat)?;

    data.validate()
        .map_err(|_| BridgeError::UnsupportedFormat)?;

    Ok(Arc::new(VaultSession {
        data: Mutex::new(Some(data)),
    }))
}

#[uniffi::export]
impl VaultSession {
    /// Non-secret summaries of every entry, in stored order.
    pub fn list_entries(&self) -> Result<Vec<EntrySummary>, BridgeError> {
        let guard = self.guard();
        let data = guard.as_ref().ok_or(BridgeError::SessionLocked)?;

        Ok(data
            .entries
            .iter()
            .map(|entry| EntrySummary {
                id: entry.id.to_string(),
                title: entry.title.clone(),
                profile_name: entry.profile_name.clone(),
                url: entry.url.clone(),
                username: entry.username.clone(),
            })
            .collect())
    }

    /// Non-secret details of one entry (no password, notes or TOTP).
    pub fn entry_details(&self, entry_id: String) -> Result<EntryDetails, BridgeError> {
        let guard = self.guard();
        let data = guard.as_ref().ok_or(BridgeError::SessionLocked)?;
        let entry = find_entry(data, &entry_id)?;

        Ok(EntryDetails {
            id: entry.id.to_string(),
            title: entry.title.clone(),
            profile_name: entry.profile_name.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
        })
    }

    /// The entry's password. Call only for an explicit user show/copy action.
    ///
    /// The returned `String` necessarily becomes a JVM string; neither side of
    /// that boundary can deterministically zeroize it, so callers must keep its
    /// lifetime narrow.
    pub fn entry_password(&self, entry_id: String) -> Result<String, BridgeError> {
        let guard = self.guard();
        let data = guard.as_ref().ok_or(BridgeError::SessionLocked)?;
        let entry = find_entry(data, &entry_id)?;

        Ok(entry.password.clone())
    }

    /// Drop (and thereby zeroize) the decrypted vault data. Idempotent.
    pub fn lock(&self) {
        // Take the value out under the lock, then drop it after the guard is
        // released so `VaultData`'s zeroizing `Drop` never runs under the lock.
        let taken = self.guard().take();
        drop(taken);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    const SCHEMA2_FIXTURE_SHA256: &str =
        "f5bf1fcdb11115f0fa39598389a7a8ce3b9c44b78ddfd5295b57845b52155f55";
    const SCHEMA1_FIXTURE_SHA256: &str =
        "17edf060385cca1a778b2236842ecfa44d21aa174d9b70092c1d9cbdd0fcb9a8";

    const TEST_MASTER_PASSWORD: &str = "compat-baseline-master-password-test-only";
    const WRONG_PASSWORD: &str = "definitely-wrong-password-test-only";

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../src-tauri/tests/fixtures/compat")
            .join(name)
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn read_fixture(name: &str, expected_sha256: &str) -> Vec<u8> {
        let bytes = std::fs::read(fixture_path(name)).expect("canonical fixture is readable");
        assert_eq!(
            hex_sha256(&bytes),
            expected_sha256,
            "canonical compat fixture must not silently drift"
        );
        bytes
    }

    fn schema2() -> Vec<u8> {
        read_fixture("schema2_baseline.envelope.json", SCHEMA2_FIXTURE_SHA256)
    }

    fn schema1() -> Vec<u8> {
        read_fixture("schema1_baseline.envelope.json", SCHEMA1_FIXTURE_SHA256)
    }

    fn open_ok(bytes: Vec<u8>) -> Arc<VaultSession> {
        match open_vault(bytes, TEST_MASTER_PASSWORD.to_owned()) {
            Ok(session) => session,
            Err(_) => panic!("fixture should open with the test password"),
        }
    }

    fn open_err(bytes: Vec<u8>, password: &str) -> BridgeError {
        match open_vault(bytes, password.to_owned()) {
            Ok(_) => panic!("open was expected to fail"),
            Err(error) => error,
        }
    }

    fn schema_version(session: &VaultSession) -> u16 {
        session
            .guard()
            .as_ref()
            .expect("session is unlocked")
            .schema_version
    }

    #[test]
    fn schema2_fixture_opens_and_lists_entries() {
        let session = open_ok(schema2());

        assert_eq!(schema_version(&session), 2);

        let entries = session.list_entries().unwrap();
        assert_eq!(entries.len(), 2);

        let mut titles: Vec<&str> = entries.iter().map(|entry| entry.title.as_str()).collect();
        titles.sort_unstable();
        assert_eq!(titles, ["Fixture Login", "Fixture TOTP Account"]);

        let login = entries
            .iter()
            .find(|entry| entry.title == "Fixture Login")
            .unwrap();
        assert_eq!(login.username, "fixture.user@example.com");
        assert_eq!(login.profile_name, "Fixture Profile");
        assert_eq!(login.id.len(), 36);
    }

    #[test]
    fn legacy_schema1_fixture_still_opens_and_lists_entries() {
        let session = open_ok(schema1());

        assert_eq!(schema_version(&session), 1);
        assert_eq!(session.list_entries().unwrap().len(), 2);
    }

    #[test]
    fn entry_summary_carries_no_secret_fields() {
        let session = open_ok(schema2());
        let summaries = session.list_entries().unwrap();

        // Exhaustive destructuring pins the exact field set: adding a field
        // (for example a password) fails to compile until this test is
        // consciously updated.
        for summary in &summaries {
            let EntrySummary {
                id: _,
                title: _,
                profile_name: _,
                url: _,
                username: _,
            } = summary;
        }

        // Value check against the real decrypted secrets held by the session.
        let guard = session.guard();
        let data = guard.as_ref().unwrap();
        assert!(data.entries.iter().any(|entry| entry.totp.is_some()));

        for entry in &data.entries {
            let mut secrets: Vec<&str> = vec![entry.password.as_str()];
            if !entry.notes.is_empty() {
                secrets.push(entry.notes.as_str());
            }
            if let Some(totp) = entry.totp.as_ref() {
                secrets.push(totp.secret_base64.as_str());
            }

            for summary in &summaries {
                for secret in &secrets {
                    for field in [
                        &summary.id,
                        &summary.title,
                        &summary.profile_name,
                        &summary.url,
                        &summary.username,
                    ] {
                        assert!(!field.contains(secret), "a secret leaked into a summary");
                    }
                }
            }
        }
    }

    #[test]
    fn wrong_password_returns_generic_authentication_failure() {
        assert_eq!(
            open_err(schema2(), WRONG_PASSWORD),
            BridgeError::AuthenticationFailed
        );
    }

    #[test]
    fn corrupted_ciphertext_is_indistinguishable_from_wrong_password() {
        let mut envelope: VaultEnvelope = serde_json::from_slice(&schema2()).unwrap();
        envelope.payload.ciphertext[0] ^= 0x01;
        let corrupted_payload = serde_json::to_vec(&envelope).unwrap();

        let mut envelope: VaultEnvelope = serde_json::from_slice(&schema2()).unwrap();
        envelope.wrapped_vault_key.ciphertext[0] ^= 0x01;
        let corrupted_key = serde_json::to_vec(&envelope).unwrap();

        assert_eq!(
            open_err(corrupted_payload, TEST_MASTER_PASSWORD),
            BridgeError::AuthenticationFailed
        );
        assert_eq!(
            open_err(corrupted_key, TEST_MASTER_PASSWORD),
            BridgeError::AuthenticationFailed
        );
    }

    #[test]
    fn unsupported_header_is_reported_before_authentication() {
        let mut envelope: VaultEnvelope = serde_json::from_slice(&schema2()).unwrap();
        envelope.version = 99;
        let bytes = serde_json::to_vec(&envelope).unwrap();

        // Same result regardless of whether the password is right or wrong.
        assert_eq!(
            open_err(bytes.clone(), TEST_MASTER_PASSWORD),
            BridgeError::UnsupportedFormat
        );
        assert_eq!(
            open_err(bytes, WRONG_PASSWORD),
            BridgeError::UnsupportedFormat
        );
    }

    #[test]
    fn malformed_bytes_and_empty_password_are_structured_errors() {
        assert_eq!(
            open_err(b"not a vault envelope".to_vec(), "x"),
            BridgeError::UnsupportedFormat
        );
        assert_eq!(open_err(schema2(), ""), BridgeError::InvalidInput);
    }

    #[test]
    fn lock_drops_decrypted_data_and_invalidates_the_session() {
        let session = open_ok(schema2());
        assert!(session.list_entries().is_ok());

        session.lock();

        assert!(session.guard().is_none());
        assert_eq!(
            session.list_entries().err(),
            Some(BridgeError::SessionLocked)
        );

        // Idempotent, and never panics.
        session.lock();
        assert_eq!(
            session.list_entries().err(),
            Some(BridgeError::SessionLocked)
        );
    }

    fn id_of(session: &VaultSession, title: &str) -> String {
        session
            .list_entries()
            .unwrap()
            .into_iter()
            .find(|entry| entry.title == title)
            .expect("fixture entry exists")
            .id
    }

    #[test]
    fn entry_details_return_non_secret_fields_for_a_known_entry() {
        let session = open_ok(schema2());
        let id = id_of(&session, "Fixture Login");

        let details = session.entry_details(id.clone()).unwrap();

        assert_eq!(details.id, id);
        assert_eq!(details.title, "Fixture Login");
        assert_eq!(details.profile_name, "Fixture Profile");
        assert_eq!(details.username, "fixture.user@example.com");
    }

    #[test]
    fn entry_details_carry_no_secret_fields() {
        let session = open_ok(schema2());

        // Exhaustive destructuring pins the exact field set: adding a field
        // (for example a password) fails to compile until consciously updated.
        let id = id_of(&session, "Fixture TOTP Account");
        let EntryDetails {
            id: _,
            title: _,
            profile_name: _,
            url: _,
            username: _,
        } = session.entry_details(id).unwrap();

        // Value check against every real secret held by the session. All
        // details are gathered before taking the guard (the mutex is not
        // re-entrant).
        let all_details: Vec<EntryDetails> = session
            .list_entries()
            .unwrap()
            .into_iter()
            .map(|entry| session.entry_details(entry.id).unwrap())
            .collect();
        assert_eq!(all_details.len(), 2);

        let guard = session.guard();
        let data = guard.as_ref().unwrap();

        for details in &all_details {
            for entry in &data.entries {
                let mut secrets: Vec<&str> = vec![entry.password.as_str()];
                if !entry.notes.is_empty() {
                    secrets.push(entry.notes.as_str());
                }
                if let Some(totp) = entry.totp.as_ref() {
                    secrets.push(totp.secret_base64.as_str());
                }

                for secret in secrets {
                    for field in [
                        &details.id,
                        &details.title,
                        &details.profile_name,
                        &details.url,
                        &details.username,
                    ] {
                        assert!(!field.contains(secret), "a secret leaked into details");
                    }
                }
            }
        }
    }

    #[test]
    fn password_is_returned_only_by_the_explicit_password_call() {
        let session = open_ok(schema2());
        let id = id_of(&session, "Fixture Login");

        let password = session.entry_password(id).unwrap();

        // Compared without ever placing the value in an assertion message.
        assert!(
            password == "FixtureBaselinePassword123!",
            "unexpected password"
        );
    }

    #[test]
    fn unknown_or_malformed_entry_ids_return_entry_not_found() {
        let session = open_ok(schema2());

        for bad in [
            "",
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
            "FIXTURE LOGIN",
        ] {
            assert_eq!(
                session.entry_details(bad.to_owned()).err(),
                Some(BridgeError::EntryNotFound)
            );
            assert_eq!(
                session.entry_password(bad.to_owned()).err(),
                Some(BridgeError::EntryNotFound)
            );
        }
    }

    #[test]
    fn locked_session_cannot_return_details_or_password() {
        let session = open_ok(schema2());
        let id = id_of(&session, "Fixture Login");

        session.lock();

        assert_eq!(
            session.entry_details(id.clone()).err(),
            Some(BridgeError::SessionLocked)
        );
        assert_eq!(
            session.entry_password(id).err(),
            Some(BridgeError::SessionLocked)
        );
    }

    #[test]
    fn legacy_schema1_entry_details_and_password_work() {
        let session = open_ok(schema1());
        let id = id_of(&session, "Legacy Fixture Login");

        assert_eq!(
            session.entry_details(id.clone()).unwrap().username,
            "legacy.user@example.com"
        );
        assert!(
            session.entry_password(id).unwrap() == "LegacyBaselinePassword123!",
            "unexpected password"
        );
    }
}
