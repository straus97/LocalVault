use std::path::Path;

use super::{SessionError, UnlockedVaultSession};

use crate::vault::storage::{ensure_distinct_paths, load_envelope, save_envelope_atomic_new};

impl UnlockedVaultSession {
    pub fn create_user_backup(&self, destination: impl AsRef<Path>) -> Result<(), SessionError> {
        if self.dirty {
            return Err(SessionError::PendingUnsavedChanges);
        }

        let destination = destination.as_ref();

        ensure_distinct_paths(&self.path, destination)?;

        /*
         * Refuse to snapshot a vault that changed externally
         * after this session authenticated it.
         */
        let current_on_disk = load_envelope(&self.path)?;

        if current_on_disk != self.envelope {
            return Err(SessionError::ChangedOnDisk);
        }

        /*
         * Copy only the encrypted envelope. No VaultData
         * plaintext is serialized for user backup creation.
         */
        save_envelope_atomic_new(destination, &current_on_disk)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::*;

    use crate::vault::{
        data::VaultEntry,
        format::create_envelope,
        storage::{load_envelope, save_envelope_atomic, StorageError},
    };

    const NOW_MS: i64 = 1_700_000_000_000;

    const MASTER_PASSWORD: &str = "user-backup-session-test-only";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    #[test]
    fn user_backup_contains_current_authenticated_encrypted_envelope() {
        let temp = tempdir().unwrap();

        let vault = temp.path().join("vault.lvault");

        let backup = temp.path().join("snapshot.lvbackup");

        let mut session = UnlockedVaultSession::create(&vault, password(), NOW_MS).unwrap();

        let mut entry = VaultEntry::new("Backup entry", NOW_MS + 1).unwrap();

        entry.password = "USER_BACKUP_TEST_SECRET".to_owned();

        {
            let data = session.data_mut();

            data.entries.push(entry);

            data.updated_at_ms = NOW_MS + 1;
        }

        session.save().unwrap();

        session.create_user_backup(&backup).unwrap();

        assert_eq!(
            load_envelope(&vault).unwrap(),
            load_envelope(&backup).unwrap()
        );

        let raw = fs::read_to_string(&backup).unwrap();

        assert!(!raw.contains(MASTER_PASSWORD));

        assert!(!raw.contains("USER_BACKUP_TEST_SECRET"));
    }

    #[test]
    fn user_backup_refuses_existing_destination_without_modifying_it() {
        let temp = tempdir().unwrap();

        let vault = temp.path().join("vault.lvault");

        let backup = temp.path().join("existing.lvbackup");

        let session = UnlockedVaultSession::create(&vault, password(), NOW_MS).unwrap();

        fs::write(&backup, b"KEEP-THIS-BACKUP").unwrap();

        let before = fs::read(&backup).unwrap();

        let result = session.create_user_backup(&backup);

        assert!(matches!(
            result,
            Err(SessionError::Storage(StorageError::DestinationExists))
        ));

        assert_eq!(fs::read(&backup).unwrap(), before);
    }

    #[test]
    fn user_backup_rejects_vault_changed_on_disk() {
        let temp = tempdir().unwrap();

        let vault = temp.path().join("vault.lvault");

        let backup = temp.path().join("snapshot.lvbackup");

        let session = UnlockedVaultSession::create(&vault, password(), NOW_MS).unwrap();

        let replacement = create_envelope(MASTER_PASSWORD, b"external replacement").unwrap();

        save_envelope_atomic(&vault, &replacement).unwrap();

        let result = session.create_user_backup(&backup);

        assert!(matches!(result, Err(SessionError::ChangedOnDisk)));

        assert!(!backup.exists());
    }

    #[test]
    fn dirty_session_is_never_exported_as_backup() {
        let temp = tempdir().unwrap();

        let vault = temp.path().join("vault.lvault");

        let backup = temp.path().join("snapshot.lvbackup");

        let mut session = UnlockedVaultSession::create(&vault, password(), NOW_MS).unwrap();

        let mut entry = VaultEntry::new("Unsaved entry", NOW_MS + 1).unwrap();

        entry.password = "UNSAVED_BACKUP_TEST_SECRET".to_owned();

        session.data_mut().entries.push(entry);

        let result = session.create_user_backup(&backup);

        assert!(matches!(result, Err(SessionError::PendingUnsavedChanges)));

        assert!(!backup.exists());
    }
}
