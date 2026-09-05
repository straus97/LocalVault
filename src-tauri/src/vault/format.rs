use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{
    cipher::{decrypt, encrypt, EncryptedBlob},
    kdf::{derive_master_key, KdfParams},
    keys::{random_salt, random_secret_key, KEY_LEN, SALT_LEN},
    CryptoError,
};

pub const VAULT_MAGIC: &str = "LOCALVAULT";
pub const VAULT_VERSION: u16 = 1;

const WRAPPED_KEY_AAD: &[u8] = b"LocalVault/v1/vault-key";
const PAYLOAD_AAD: &[u8] = b"LocalVault/v1/payload";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("master password must not be empty")]
    EmptyMasterPassword,

    #[error("unsupported or invalid vault format")]
    UnsupportedFormat,

    #[error("invalid wrapped vault key")]
    InvalidWrappedKey,

    #[error("cryptographic operation failed")]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEnvelope {
    pub magic: String,
    pub version: u16,
    pub kdf: KdfParams,
    pub kdf_salt: [u8; SALT_LEN],
    pub wrapped_vault_key: EncryptedBlob,
    pub payload: EncryptedBlob,
}

impl VaultEnvelope {
    pub fn validate_header(&self) -> Result<(), VaultError> {
        if self.magic != VAULT_MAGIC || self.version != VAULT_VERSION {
            return Err(VaultError::UnsupportedFormat);
        }

        self.kdf.validate()?;

        Ok(())
    }
}

pub fn create_envelope(
    master_password: &str,
    plaintext: &[u8],
) -> Result<VaultEnvelope, VaultError> {
    if master_password.is_empty() {
        return Err(VaultError::EmptyMasterPassword);
    }

    let kdf = KdfParams::default();
    let kdf_salt = random_salt()?;

    let master_key = derive_master_key(master_password, &kdf_salt, kdf)?;

    let vault_key = random_secret_key()?;

    let wrapped_vault_key = encrypt(&master_key, vault_key.as_slice(), WRAPPED_KEY_AAD)?;

    let payload = encrypt(&vault_key, plaintext, PAYLOAD_AAD)?;

    Ok(VaultEnvelope {
        magic: VAULT_MAGIC.to_owned(),
        version: VAULT_VERSION,
        kdf,
        kdf_salt,
        wrapped_vault_key,
        payload,
    })
}

pub fn open_envelope(
    master_password: &str,
    envelope: &VaultEnvelope,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if master_password.is_empty() {
        return Err(VaultError::EmptyMasterPassword);
    }

    envelope.validate_header()?;

    let master_key = derive_master_key(master_password, &envelope.kdf_salt, envelope.kdf)?;

    let decrypted_vault_key = decrypt(&master_key, &envelope.wrapped_vault_key, WRAPPED_KEY_AAD)?;

    if decrypted_vault_key.len() != KEY_LEN {
        return Err(VaultError::InvalidWrappedKey);
    }

    let mut vault_key = Zeroizing::new([0u8; KEY_LEN]);
    vault_key.copy_from_slice(decrypted_vault_key.as_slice());

    decrypt(&vault_key, &envelope.payload, PAYLOAD_AAD).map_err(VaultError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{kdf::MAX_MEMORY_KIB, CryptoError};

    const MASTER_PASSWORD: &str = "correct horse battery staple - test only";

    const TEST_PAYLOAD: &[u8] =
        br#"{"entries":[{"site":"example.test","password":"TEST_ONLY_SECRET"}]}"#;

    #[test]
    fn vault_round_trip_succeeds() {
        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        let plaintext = open_envelope(MASTER_PASSWORD, &envelope).unwrap();

        assert_eq!(plaintext.as_slice(), TEST_PAYLOAD);
    }

    #[test]
    fn wrong_master_password_is_rejected() {
        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        let result = open_envelope("definitely-wrong-password", &envelope);

        assert!(matches!(
            result,
            Err(VaultError::Crypto(CryptoError::Decryption))
        ));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let mut envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        assert!(!envelope.payload.ciphertext.is_empty());

        envelope.payload.ciphertext[0] ^= 0x01;

        let result = open_envelope(MASTER_PASSWORD, &envelope);

        assert!(matches!(
            result,
            Err(VaultError::Crypto(CryptoError::Decryption))
        ));
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let mut envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        assert!(!envelope.wrapped_vault_key.ciphertext.is_empty());

        envelope.wrapped_vault_key.ciphertext[0] ^= 0x01;

        let result = open_envelope(MASTER_PASSWORD, &envelope);

        assert!(matches!(
            result,
            Err(VaultError::Crypto(CryptoError::Decryption))
        ));
    }

    #[test]
    fn fresh_vaults_use_fresh_randomness() {
        let first = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        let second = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        assert_ne!(first.kdf_salt, second.kdf_salt);
        assert_ne!(
            first.wrapped_vault_key.nonce,
            second.wrapped_vault_key.nonce
        );
        assert_ne!(first.payload.nonce, second.payload.nonce);
        assert_ne!(first.payload.ciphertext, second.payload.ciphertext);
    }

    #[test]
    fn serialized_envelope_contains_no_plaintext_secrets() {
        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        let json = serde_json::to_string(&envelope).unwrap();

        assert!(!json.contains(MASTER_PASSWORD));
        assert!(!json.contains("TEST_ONLY_SECRET"));
        assert!(!json.contains("example.test"));
    }

    #[test]
    fn serialized_envelope_can_be_loaded_and_opened() {
        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        let json = serde_json::to_string(&envelope).unwrap();

        let loaded: VaultEnvelope = serde_json::from_str(&json).unwrap();

        let plaintext = open_envelope(MASTER_PASSWORD, &loaded).unwrap();

        assert_eq!(plaintext.as_slice(), TEST_PAYLOAD);
    }

    #[test]
    fn unreasonable_kdf_parameters_are_rejected_before_use() {
        let mut envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        envelope.kdf.memory_kib = MAX_MEMORY_KIB + 1;

        let result = open_envelope(MASTER_PASSWORD, &envelope);

        assert!(matches!(
            result,
            Err(VaultError::Crypto(CryptoError::InvalidKdfParameters))
        ));
    }

    #[test]
    fn empty_master_password_is_rejected() {
        let result = create_envelope("", TEST_PAYLOAD);

        assert!(matches!(result, Err(VaultError::EmptyMasterPassword)));
    }
}
