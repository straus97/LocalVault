use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    keys::{SecretKey, KEY_LEN, SALT_LEN},
    CryptoError,
};

pub const MIN_MEMORY_KIB: u32 = 19_456;
pub const MAX_MEMORY_KIB: u32 = 131_072;
pub const MIN_ITERATIONS: u32 = 2;
pub const MAX_ITERATIONS: u32 = 6;
pub const MIN_PARALLELISM: u32 = 1;
pub const MAX_PARALLELISM: u32 = 4;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    pub fn validate(&self) -> Result<(), CryptoError> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations)
            || !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism)
        {
            return Err(CryptoError::InvalidKdfParameters);
        }

        Ok(())
    }

    fn to_argon2_params(self) -> Result<Params, CryptoError> {
        self.validate()?;

        Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| CryptoError::InvalidKdfParameters)
    }
}

pub fn derive_master_key(
    master_password: &str,
    salt: &[u8; SALT_LEN],
    config: KdfParams,
) -> Result<SecretKey, CryptoError> {
    let params = config.to_argon2_params()?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; KEY_LEN]);

    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut *output)
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(output)
}
