pub mod cipher;
pub mod kdf;
pub mod keys;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("secure random generation failed")]
    Randomness,

    #[error("invalid key-derivation parameters")]
    InvalidKdfParameters,

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("invalid encryption key")]
    InvalidKey,

    #[error("encryption failed")]
    Encryption,

    #[error("decryption or authentication failed")]
    Decryption,
}
