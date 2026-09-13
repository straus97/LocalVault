use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    keys::{random_nonce, KEY_LEN, NONCE_LEN},
    CryptoError,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn build_cipher(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)
}

pub fn encrypt(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedBlob, CryptoError> {
    let cipher = build_cipher(key)?;
    let nonce = random_nonce()?;

    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    Ok(EncryptedBlob { nonce, ciphertext })
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    encrypted: &EncryptedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = build_cipher(key)?;

    let plaintext = cipher
        .decrypt(
            &XNonce::from(encrypted.nonce),
            Payload {
                msg: encrypted.ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| CryptoError::Decryption)?;

    Ok(Zeroizing::new(plaintext))
}
