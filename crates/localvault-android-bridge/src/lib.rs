//! 1T-B1b architecture-proof Android FFI adapter.
//!
//! This crate exists to prove exactly one thing: that a Kotlin caller, via
//! stable UniFFI Kotlin/JNA bindings, can reach `localvault-core`'s existing
//! vault-envelope API and get back a non-secret compatibility result. It is
//! deliberately not a general Android vault API yet -- see
//! `docs/ROADMAP.md` 1T and the 1T-A/1T-A2/1T-B1a audits in project history
//! for the approved architecture this implements.
//!
//! This crate must never duplicate cryptography, vault-format parsing, or
//! schema validation -- all of that stays in `localvault-core` (see
//! `docs/ARCHITECTURE.md`). It only marshals bytes across the FFI boundary
//! and maps `localvault-core`'s existing error semantics onto a small,
//! oracle-safe structured error enum.

use localvault_core::vault::format::{open_envelope, CryptoError, VaultEnvelope, VaultError};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// Non-secret proof-of-open result. Intentionally carries nothing from the
/// decrypted payload beyond the schema version, which is not secret (it is
/// also visible, in effect, from which upgrade path a write would take).
#[derive(uniffi::Record, Debug, PartialEq, Eq)]
pub struct CompatibilityResult {
    pub schema_version: u16,
}

/// Structured, oracle-safe bridge error.
///
/// `localvault-core` itself does not distinguish "wrong master password"
/// from "tampered/corrupted authenticated ciphertext" -- both collapse into
/// `CryptoError::Decryption` (see `vault::format::open_envelope_with_key`).
/// This enum preserves that indistinguishability rather than inventing a
/// finer-grained authentication oracle the core does not safely provide.
/// `UnsupportedFormat` is safe to expose separately because it is decided by
/// `VaultEnvelope::validate_header` before any password-dependent operation
/// runs, so it cannot leak anything about whether a supplied password was
/// close to correct.
#[derive(uniffi::Error, thiserror::Error, Debug, PartialEq, Eq)]
pub enum BridgeError {
    #[error("input is invalid")]
    InvalidInput,
    #[error("vault format is unsupported")]
    UnsupportedFormat,
    #[error("authentication failed")]
    AuthenticationFailed,
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

/// Synchronously verify that `envelope_bytes` is a `VaultEnvelope` openable
/// with `master_password`, using `localvault-core`'s existing, unmodified
/// envelope/schema APIs, and return only the resulting schema version.
///
/// No decrypted content (entries, credentials, TOTP secrets, URLs, notes)
/// ever crosses this boundary -- only the non-secret schema version. This is
/// the entire 1T-B1b FFI surface: proof that Kotlin -> generated binding ->
/// this bridge -> `localvault-core` -> the existing encrypted persisted
/// format works end to end, nothing more.
#[uniffi::export]
pub fn verify_compatibility_fixture(
    envelope_bytes: Vec<u8>,
    master_password: String,
) -> Result<CompatibilityResult, BridgeError> {
    // Move the received password into zeroizing storage as early as
    // practical. This does not make the JVM/JNA-side copy that produced the
    // `String` disappear -- deterministic zeroization is not achievable
    // across that boundary (see docs/SECURITY_MODEL.md's JS-string
    // precedent for the same, JVM-shaped, limitation) -- but it bounds this
    // Rust-side copy's lifetime to this call.
    let master_password = Zeroizing::new(master_password);

    let envelope: VaultEnvelope =
        serde_json::from_slice(&envelope_bytes).map_err(|_| BridgeError::UnsupportedFormat)?;

    let plaintext = open_envelope(master_password.as_str(), &envelope).map_err(map_vault_error)?;

    let data: localvault_core::vault::data::VaultData =
        serde_json::from_slice(plaintext.as_slice()).map_err(|_| BridgeError::UnsupportedFormat)?;

    Ok(CompatibilityResult {
        schema_version: data.schema_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    const CANONICAL_FIXTURE_SHA256: &str =
        "f5bf1fcdb11115f0fa39598389a7a8ce3b9c44b78ddfd5295b57845b52155f55";

    const TEST_MASTER_PASSWORD: &str = "compat-baseline-master-password-test-only";

    fn canonical_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../src-tauri/tests/fixtures/compat/schema2_baseline.envelope.json")
    }

    fn read_canonical_fixture() -> Vec<u8> {
        std::fs::read(canonical_fixture_path()).expect("canonical fixture is readable")
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn canonical_fixture_hash_matches_expected() {
        let bytes = read_canonical_fixture();
        assert_eq!(
            hex_sha256(&bytes),
            CANONICAL_FIXTURE_SHA256,
            "the canonical schema-2 compat fixture must not silently drift; \
             if it was intentionally changed, this pinned hash (and the \
             Android build script's copy of it) must be updated deliberately"
        );
    }

    #[test]
    fn opens_canonical_fixture_and_reports_schema_version() {
        let bytes = read_canonical_fixture();

        let result = verify_compatibility_fixture(bytes, TEST_MASTER_PASSWORD.to_owned()).unwrap();

        assert_eq!(result, CompatibilityResult { schema_version: 2 });
    }

    #[test]
    fn wrong_password_returns_authentication_failed_without_panicking() {
        let bytes = read_canonical_fixture();

        let result =
            verify_compatibility_fixture(bytes, "definitely-wrong-password-test-only".to_owned());

        assert_eq!(result, Err(BridgeError::AuthenticationFailed));
    }

    #[test]
    fn empty_password_is_rejected_as_invalid_input_not_authentication_failure() {
        let bytes = read_canonical_fixture();

        let result = verify_compatibility_fixture(bytes, String::new());

        assert_eq!(result, Err(BridgeError::InvalidInput));
    }

    #[test]
    fn malformed_envelope_bytes_return_unsupported_format_without_panicking() {
        let result = verify_compatibility_fixture(b"not a vault envelope".to_vec(), "x".to_owned());

        assert_eq!(result, Err(BridgeError::UnsupportedFormat));
    }
}
