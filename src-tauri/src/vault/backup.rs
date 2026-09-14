use std::path::Path;

use thiserror::Error;
use zeroize::Zeroizing;

use super::storage::{
    ensure_distinct_paths, load_envelope, save_envelope_atomic_new, StorageError,
};
use localvault_core::vault::{
    data::{VaultData, VaultDataError},
    format::{open_envelope, VaultError},
};

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("backup storage operation failed")]
    Storage(#[from] StorageError),

    #[error("backup cryptographic authentication failed")]
    Vault(#[from] VaultError),

    #[error("backup payload deserialization failed")]
    Deserialization(#[source] serde_json::Error),

    #[error("backup payload validation failed")]
    Data(#[from] VaultDataError),
}

pub fn restore_backup_file(
    backup_path: &Path,
    destination_path: &Path,
    master_password: Zeroizing<String>,
) -> Result<(), BackupError> {
    /*
     * The destination is deliberately a new file. The backup
     * itself is never modified by restore.
     */
    ensure_distinct_paths(backup_path, destination_path)?;

    /*
     * Load one encrypted envelope and authenticate exactly that
     * envelope before allowing it to become a restored vault.
     */
    let envelope = load_envelope(backup_path)?;

    let plaintext = open_envelope(master_password.as_str(), &envelope)?;

    /*
     * Successful AEAD authentication is not enough on its own:
     * also require a valid current LocalVault data model.
     */
    let data: VaultData =
        serde_json::from_slice(plaintext.as_slice()).map_err(BackupError::Deserialization)?;

    data.validate()?;

    /*
     * No decrypt/re-encrypt migration is performed here.
     * The same authenticated encrypted envelope is persisted.
     */
    save_envelope_atomic_new(destination_path, &envelope)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::vault::storage::{load_envelope, save_envelope_atomic, StorageError};
    use localvault_core::vault::{
        data::{VaultData, VaultEntry},
        format::{create_envelope, CryptoError, VaultError},
    };

    const NOW_MS: i64 = 1_700_000_000_000;

    const MASTER_PASSWORD: &str = "backup-restore-master-test-only";

    fn valid_envelope() -> localvault_core::vault::format::VaultEnvelope {
        let mut data = VaultData::new(NOW_MS).unwrap();

        let mut entry = VaultEntry::new("Backup test", NOW_MS + 1).unwrap();

        entry.username = "backup-user@example.test".to_owned();

        entry.password = "BACKUP_RESTORE_TEST_SECRET".to_owned();

        data.entries.push(entry);

        data.updated_at_ms = NOW_MS + 1;

        data.validate().unwrap();

        let plaintext = serde_json::to_vec(&data).unwrap();

        create_envelope(MASTER_PASSWORD, &plaintext).unwrap()
    }

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    #[test]
    fn authenticated_backup_restores_equivalent_encrypted_vault() {
        let temp = tempdir().unwrap();

        let backup = temp.path().join("snapshot.lvbackup");

        let restored = temp.path().join("restored.lvault");

        let envelope = valid_envelope();

        save_envelope_atomic(&backup, &envelope).unwrap();

        restore_backup_file(&backup, &restored, password()).unwrap();

        assert_eq!(load_envelope(&restored).unwrap(), envelope);

        assert_eq!(load_envelope(&backup).unwrap(), envelope);
    }

    #[test]
    fn wrong_password_creates_no_restored_file() {
        let temp = tempdir().unwrap();

        let backup = temp.path().join("snapshot.lvbackup");

        let restored = temp.path().join("restored.lvault");

        save_envelope_atomic(&backup, &valid_envelope()).unwrap();

        let result = restore_backup_file(
            &backup,
            &restored,
            Zeroizing::new("wrong-password".to_owned()),
        );

        assert!(matches!(
            result,
            Err(BackupError::Vault(VaultError::Crypto(
                CryptoError::Decryption
            )))
        ));

        assert!(!restored.exists());
    }

    #[test]
    fn tampered_backup_creates_no_restored_file() {
        let temp = tempdir().unwrap();

        let backup = temp.path().join("tampered.lvbackup");

        let restored = temp.path().join("restored.lvault");

        let mut envelope = valid_envelope();

        envelope.payload.ciphertext[0] ^= 0x01;

        save_envelope_atomic(&backup, &envelope).unwrap();

        let result = restore_backup_file(&backup, &restored, password());

        assert!(matches!(
            result,
            Err(BackupError::Vault(VaultError::Crypto(
                CryptoError::Decryption
            )))
        ));

        assert!(!restored.exists());
    }

    #[test]
    fn restore_never_overwrites_existing_destination() {
        let temp = tempdir().unwrap();

        let backup = temp.path().join("snapshot.lvbackup");

        let restored = temp.path().join("existing.lvault");

        save_envelope_atomic(&backup, &valid_envelope()).unwrap();

        fs::write(&restored, b"DO-NOT-OVERWRITE").unwrap();

        let before = fs::read(&restored).unwrap();

        let result = restore_backup_file(&backup, &restored, password());

        assert!(matches!(
            result,
            Err(BackupError::Storage(StorageError::DestinationExists))
        ));

        assert_eq!(fs::read(&restored).unwrap(), before);
    }

    #[test]
    fn backup_cannot_restore_over_itself() {
        let temp = tempdir().unwrap();

        let backup = temp.path().join("snapshot.lvbackup");

        save_envelope_atomic(&backup, &valid_envelope()).unwrap();

        let before = fs::read(&backup).unwrap();

        let result = restore_backup_file(&backup, &backup, password());

        assert!(matches!(
            result,
            Err(BackupError::Storage(StorageError::BackupPathMatchesVault))
        ));

        assert_eq!(fs::read(&backup).unwrap(), before);
    }
}
