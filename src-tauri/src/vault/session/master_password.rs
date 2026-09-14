use std::{fs, io};

use zeroize::Zeroizing;

use super::{SessionError, UnlockedVaultSession};

use crate::vault::storage::{load_envelope, save_envelope_atomic, StorageError};
use localvault_core::vault::format::{
    open_envelope_with_key, rewrap_envelope_master_password, CryptoError, SecretKey, VaultEnvelope,
    VaultError,
};

fn authenticate_current_password(
    password: &str,
    envelope: &VaultEnvelope,
) -> Result<SecretKey, SessionError> {
    match open_envelope_with_key(password, envelope) {
        Ok((vault_key, _plaintext)) => Ok(vault_key),

        Err(VaultError::Crypto(CryptoError::Decryption)) => {
            Err(SessionError::CurrentMasterPasswordInvalid)
        }

        Err(error) => Err(SessionError::Vault(error)),
    }
}

impl UnlockedVaultSession {
    pub fn change_master_password(
        &mut self,
        current_master_password: Zeroizing<String>,
        new_master_password: Zeroizing<String>,
    ) -> Result<(), SessionError> {
        if self.dirty {
            return Err(SessionError::PendingUnsavedChanges);
        }

        if current_master_password.as_str() == new_master_password.as_str() {
            return Err(SessionError::NewMasterPasswordMatchesCurrent);
        }

        /*
         * Preserve the existing external-change protection.
         */
        let current_on_disk = load_envelope(&self.path)?;

        if current_on_disk != self.envelope {
            return Err(SessionError::ChangedOnDisk);
        }

        /*
         * Authenticate the supplied current password against
         * the exact envelope held by this session.
         */
        let verified_key =
            authenticate_current_password(current_master_password.as_str(), &self.envelope)?;

        if verified_key.as_slice() != self.vault_key.as_slice() {
            return Err(SessionError::CurrentMasterPasswordInvalid);
        }

        let updated_primary = rewrap_envelope_master_password(
            &self.envelope,
            &self.vault_key,
            new_master_password.as_str(),
        )?;

        /*
         * If LocalVault's adjacent previous-version backup
         * exists, authenticate it with the old password and
         * prepare a new-password wrapper for the same Vault Key.
         *
         * User-created *.lvbackup files are not addressed here.
         */
        let original_backup = match fs::symlink_metadata(&self.backup_path) {
            Ok(_) => Some(
                load_envelope(&self.backup_path)
                    .map_err(|_| SessionError::InternalBackupInvalid)?,
            ),

            Err(error) if error.kind() == io::ErrorKind::NotFound => None,

            Err(error) => {
                return Err(SessionError::Storage(StorageError::Io(error)));
            }
        };

        let updated_backup = if let Some(backup_envelope) = original_backup.as_ref() {
            let (backup_key, _backup_plaintext) =
                open_envelope_with_key(current_master_password.as_str(), backup_envelope)
                    .map_err(|_| SessionError::InternalBackupInvalid)?;

            if backup_key.as_slice() != self.vault_key.as_slice() {
                return Err(SessionError::InternalBackupInvalid);
            }

            Some(rewrap_envelope_master_password(
                backup_envelope,
                &self.vault_key,
                new_master_password.as_str(),
            )?)
        } else {
            None
        };

        /*
         * Security-first publication order:
         *
         * 1. Rewrap the internal previous-version backup.
         * 2. Rewrap the primary vault.
         *
         * If primary publication fails, best-effort rollback
         * restores the original backup so a failed operation
         * does not silently leave inconsistent credentials.
         */
        if let Some(updated_backup) = updated_backup.as_ref() {
            save_envelope_atomic(&self.backup_path, updated_backup)?;
        }

        if let Err(primary_error) = save_envelope_atomic(&self.path, &updated_primary) {
            if let Some(original_backup) = original_backup.as_ref() {
                if save_envelope_atomic(&self.backup_path, original_backup).is_err() {
                    return Err(SessionError::PasswordChangeRollbackFailed);
                }
            }

            return Err(SessionError::Storage(primary_error));
        }

        /*
         * Only after the primary vault has committed do we
         * switch the authenticated session envelope.
         */
        self.envelope = updated_primary;

        self.dirty = false;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    use crate::vault::storage::{load_envelope, save_envelope_atomic};
    use localvault_core::vault::{data::VaultEntry, format::open_envelope};

    const OLD_PASSWORD: &str = "old-master-password-test-only";

    const NEW_PASSWORD: &str = "new-master-password-test-only";

    const NOW_MS: i64 = 1_700_000_000_000;

    fn old_password() -> Zeroizing<String> {
        Zeroizing::new(OLD_PASSWORD.to_owned())
    }

    fn new_password() -> Zeroizing<String> {
        Zeroizing::new(NEW_PASSWORD.to_owned())
    }

    fn session_with_saved_entry(path: &std::path::Path) -> UnlockedVaultSession {
        let mut session = UnlockedVaultSession::create(path, old_password(), NOW_MS).unwrap();

        let mut entry = VaultEntry::new("Password change account", NOW_MS + 1).unwrap();

        entry.password = "PASSWORD_CHANGE_TEST_SECRET".to_owned();

        {
            let data = session.data_mut();

            data.entries.push(entry);

            data.updated_at_ms = NOW_MS + 1;
        }

        session.save().unwrap();

        session
    }

    #[test]
    fn password_change_preserves_payload_and_session_data() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let mut session = session_with_saved_entry(&path);

        let before = load_envelope(&path).unwrap();

        session
            .change_master_password(old_password(), new_password())
            .unwrap();

        let after = load_envelope(&path).unwrap();

        assert_eq!(after.payload, before.payload);

        assert_ne!(after.kdf_salt, before.kdf_salt);

        assert_eq!(
            session.data().entries[0].password,
            "PASSWORD_CHANGE_TEST_SECRET"
        );

        assert!(!session.is_dirty());
    }

    #[test]
    fn successful_change_rejects_old_password_and_accepts_new_password() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let mut session = session_with_saved_entry(&path);

        session
            .change_master_password(old_password(), new_password())
            .unwrap();

        session.lock();

        assert!(UnlockedVaultSession::unlock(&path, old_password(),).is_err());

        let reopened = UnlockedVaultSession::unlock(&path, new_password()).unwrap();

        assert_eq!(
            reopened.data().entries[0].password,
            "PASSWORD_CHANGE_TEST_SECRET"
        );
    }

    #[test]
    fn internal_previous_version_backup_is_rewrapped_too() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let mut session = session_with_saved_entry(&path);

        let backup_path = session.backup_path().to_path_buf();

        assert!(backup_path.is_file());

        let backup_before = load_envelope(&backup_path).unwrap();

        session
            .change_master_password(old_password(), new_password())
            .unwrap();

        let backup_after = load_envelope(&backup_path).unwrap();

        assert_eq!(backup_after.payload, backup_before.payload);

        assert!(open_envelope(OLD_PASSWORD, &backup_after,).is_err());

        assert!(open_envelope(NEW_PASSWORD, &backup_after,).is_ok());
    }

    #[test]
    fn wrong_current_password_changes_no_files() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let mut session = session_with_saved_entry(&path);

        let backup_path = session.backup_path().to_path_buf();

        let primary_before = fs::read(&path).unwrap();

        let backup_before = fs::read(&backup_path).unwrap();

        let result = session.change_master_password(
            Zeroizing::new("wrong-current-password".to_owned()),
            new_password(),
        );

        assert!(matches!(
            result,
            Err(SessionError::CurrentMasterPasswordInvalid)
        ));

        assert_eq!(fs::read(&path).unwrap(), primary_before);

        assert_eq!(fs::read(&backup_path).unwrap(), backup_before);
    }

    #[test]
    fn change_rejects_external_disk_change() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let mut session = session_with_saved_entry(&path);

        let replacement =
            localvault_core::vault::format::create_envelope(OLD_PASSWORD, b"external replacement")
                .unwrap();

        save_envelope_atomic(&path, &replacement).unwrap();

        let result = session.change_master_password(old_password(), new_password());

        assert!(matches!(result, Err(SessionError::ChangedOnDisk)));

        assert_eq!(load_envelope(&path).unwrap(), replacement);
    }

    #[test]
    fn new_password_must_differ_from_current_password() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let mut session = session_with_saved_entry(&path);

        let before = fs::read(&path).unwrap();

        let result = session.change_master_password(old_password(), old_password());

        assert!(matches!(
            result,
            Err(SessionError::NewMasterPasswordMatchesCurrent)
        ));

        assert_eq!(fs::read(&path).unwrap(), before);
    }
}
