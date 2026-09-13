use zeroize::Zeroizing;

use super::CryptoError;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

pub type SecretKey = Zeroizing<[u8; KEY_LEN]>;

fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];

    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Randomness)?;

    Ok(bytes)
}

pub fn random_secret_key() -> Result<SecretKey, CryptoError> {
    Ok(Zeroizing::new(random_array::<KEY_LEN>()?))
}

pub fn random_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    random_array::<SALT_LEN>()
}

pub fn random_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    random_array::<NONCE_LEN>()
}
