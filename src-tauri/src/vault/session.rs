mod categories;
pub use categories::{CategoryInput, CategorySummary};
mod entries;
pub use entries::{EntryDetails, EntryInput, EntrySummary};

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::keys::SecretKey;

use super::{
    data::{VaultData, VaultDataError},
    format::{
        create_envelope_with_key, open_envelope_with_key, reseal_envelope, VaultEnvelope,
        VaultError,
    },
    storage::{load_envelope, save_envelope_atomic_with_backup, StorageError},
};

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("vault already exists")]
    AlreadyExists,

    #[error("vault is already open in another LocalVault session")]
    InUse,

    #[error("vault changed on disk while this session was unlocked")]
    ChangedOnDisk,

    #[error("vault contains pending unsaved changes")]
    PendingUnsavedChanges,

    #[error("vault entry was not found")]
    EntryNotFound,

    #[error("vault entry is invalid")]
    InvalidEntry(#[source] VaultDataError),

    #[error("vault category was not found")]
    CategoryNotFound,

    #[error("vault category is still used by an entry")]
    CategoryInUse,

    #[error("vault category is invalid")]
    InvalidCategory(#[source] VaultDataError),

    #[error("vault session lock filesystem operation failed")]
    LockIo(#[source] io::Error),

    #[error("vault data serialization failed")]
    Serialization(#[source] serde_json::Error),

    #[error("vault data deserialization failed")]
    Deserialization(#[source] serde_json::Error),

    #[error("vault data validation failed")]
    Data(#[from] VaultDataError),

    #[error("vault cryptographic operation failed")]
    Vault(#[from] VaultError),

    #[error("vault storage operation failed")]
    Storage(#[from] StorageError),
}

pub struct UnlockedVaultSession {
    path: PathBuf,
    backup_path: PathBuf,
    envelope: VaultEnvelope,
    vault_key: SecretKey,
    data: VaultData,
    dirty: bool,

    // Keeping this File alive keeps the OS-level exclusive
    // session lock alive. The file itself contains no secrets.
    _lock_file: File,
}

impl UnlockedVaultSession {
    pub fn create(
        path: impl AsRef<Path>,
        master_password: Zeroizing<String>,
        now_ms: i64,
    ) -> Result<Self, SessionError> {
        let path = path.as_ref().to_path_buf();
        let backup_path = backup_path_for(&path);

        let lock_file = acquire_session_lock(&path)?;

        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(SessionError::AlreadyExists);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SessionError::LockIo(error));
            }
        }

        let data = VaultData::new(now_ms)?;

        let plaintext =
            Zeroizing::new(serde_json::to_vec(&data).map_err(SessionError::Serialization)?);

        let (envelope, vault_key) =
            create_envelope_with_key(master_password.as_str(), plaintext.as_slice())?;

        save_envelope_atomic_with_backup(&path, &backup_path, &envelope)?;

        Ok(Self {
            path,
            backup_path,
            envelope,
            vault_key,
            data,
            dirty: false,
            _lock_file: lock_file,
        })
    }

    pub fn unlock(
        path: impl AsRef<Path>,
        master_password: Zeroizing<String>,
    ) -> Result<Self, SessionError> {
        let path = path.as_ref().to_path_buf();
        let backup_path = backup_path_for(&path);

        // First preserve the normal storage error semantics:
        // missing/malformed/oversized vault should be reported
        // as a vault-storage problem, not a lock-file problem.
        load_envelope(&path)?;

        let lock_file = acquire_session_lock(&path)?;

        // Re-read after the lock has been acquired so the
        // session starts from the post-lock disk state.
        let envelope = load_envelope(&path)?;

        let (vault_key, plaintext) = open_envelope_with_key(master_password.as_str(), &envelope)?;

        let data: VaultData =
            serde_json::from_slice(plaintext.as_slice()).map_err(SessionError::Deserialization)?;

        data.validate()?;

        Ok(Self {
            path,
            backup_path,
            envelope,
            vault_key,
            data,
            dirty: false,
            _lock_file: lock_file,
        })
    }

    pub fn data(&self) -> &VaultData {
        &self.data
    }

    #[cfg(test)]
    pub(crate) fn data_mut(&mut self) -> &mut VaultData {
        self.dirty = true;

        &mut self.data
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn backup_path(&self) -> &Path {
        &self.backup_path
    }

    pub fn save(&mut self) -> Result<bool, SessionError> {
        if !self.dirty {
            return Ok(false);
        }

        self.data.validate()?;

        // Refuse to overwrite a vault which changed after
        // this session was opened/saved.
        let current_on_disk = load_envelope(&self.path)?;

        if current_on_disk != self.envelope {
            return Err(SessionError::ChangedOnDisk);
        }

        let plaintext =
            Zeroizing::new(serde_json::to_vec(&self.data).map_err(SessionError::Serialization)?);

        let updated_envelope =
            reseal_envelope(&self.envelope, &self.vault_key, plaintext.as_slice())?;

        save_envelope_atomic_with_backup(&self.path, &self.backup_path, &updated_envelope)?;

        self.envelope = updated_envelope;
        self.dirty = false;

        Ok(true)
    }

    pub(crate) fn commit_candidate(&mut self, candidate: VaultData) -> Result<(), SessionError> {
        if self.dirty {
            return Err(SessionError::PendingUnsavedChanges);
        }

        candidate.validate()?;

        let current_on_disk = load_envelope(&self.path)?;

        if current_on_disk != self.envelope {
            return Err(SessionError::ChangedOnDisk);
        }

        let plaintext =
            Zeroizing::new(serde_json::to_vec(&candidate).map_err(SessionError::Serialization)?);

        let updated_envelope =
            reseal_envelope(&self.envelope, &self.vault_key, plaintext.as_slice())?;

        save_envelope_atomic_with_backup(&self.path, &self.backup_path, &updated_envelope)?;

        self.envelope = updated_envelope;
        self.data = candidate;
        self.dirty = false;

        Ok(())
    }

    pub fn lock(self) {
        drop(self);
    }
}

fn backup_path_for(path: &Path) -> PathBuf {
    let mut backup = path.as_os_str().to_os_string();

    backup.push(".backup");

    PathBuf::from(backup)
}

fn lock_path_for(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();

    lock.push(".lock");

    PathBuf::from(lock)
}

fn acquire_session_lock(path: &Path) -> Result<File, SessionError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(SessionError::Storage(StorageError::InvalidPath))?;

    fs::create_dir_all(parent).map_err(SessionError::LockIo)?;

    let lock_path = lock_path_for(path);

    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(SessionError::LockIo)?;

    match lock_file.try_lock() {
        Ok(()) => Ok(lock_file),

        Err(TryLockError::WouldBlock) => Err(SessionError::InUse),

        Err(TryLockError::Error(error)) => Err(SessionError::LockIo(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::{
        crypto::CryptoError,
        vault::{
            data::VaultEntry,
            format::{create_envelope, open_envelope, VaultError},
            storage::{load_envelope, save_envelope_atomic},
        },
    };

    const NOW_MS: i64 = 1_700_000_000_000;

    const MASTER_PASSWORD: &str = "session-master-password-test-only";

    const SESSION_SECRET: &str = "SESSION_TEST_ONLY_SECRET";
    fn test_password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    #[test]
    fn create_session_persists_valid_empty_vault_and_is_clean() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        assert!(path.is_file());
        assert!(!session.is_dirty());
        assert!(session.data().entries.is_empty());
        assert!(session.data().categories.is_empty());
        assert!(session.data().validate().is_ok());
    }

    #[test]
    fn existing_vault_unlocks_with_correct_password() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        let vault_id = session.data().vault_id;

        session.lock();

        let reopened = UnlockedVaultSession::unlock(&path, test_password()).unwrap();

        assert!(reopened.data().vault_id == vault_id);
        assert!(!reopened.is_dirty());
    }

    #[test]
    fn wrong_master_password_is_rejected_by_session() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        session.lock();

        let result = UnlockedVaultSession::unlock(
            &path,
            Zeroizing::new("definitely-wrong-password".to_owned()),
        );

        assert!(matches!(
            result,
            Err(SessionError::Vault(VaultError::Crypto(
                CryptoError::Decryption
            )))
        ));
    }

    #[test]
    fn dirty_mutation_save_and_reopen_persists_data() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        let mut entry = VaultEntry::new("Session Account", NOW_MS + 1).unwrap();

        entry.username = "session-user@example.test".to_owned();

        entry.password = SESSION_SECRET.to_owned();

        {
            let data = session.data_mut();

            data.entries.push(entry);
            data.updated_at_ms = NOW_MS + 1;
        }

        assert!(session.is_dirty());

        assert!(session.save().unwrap());

        assert!(!session.is_dirty());

        session.lock();

        let reopened = UnlockedVaultSession::unlock(&path, test_password()).unwrap();

        assert_eq!(reopened.data().entries.len(), 1);

        assert_eq!(reopened.data().entries[0].title, "Session Account");

        assert_eq!(reopened.data().entries[0].password, SESSION_SECRET);
    }

    #[test]
    fn clean_session_save_is_noop_and_creates_no_backup() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        let backup = session.backup_path().to_path_buf();

        assert!(!backup.exists());

        assert!(!session.save().unwrap());

        assert!(!backup.exists());
        assert!(!session.is_dirty());
    }

    #[test]
    fn backup_contains_previous_authenticated_vault_version() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        let mut first = VaultEntry::new("First Entry", NOW_MS + 1).unwrap();

        first.password = "first-secret".to_owned();

        {
            let data = session.data_mut();

            data.entries.push(first);
            data.updated_at_ms = NOW_MS + 1;
        }

        session.save().unwrap();

        let second = VaultEntry::new("Second Entry", NOW_MS + 2).unwrap();

        {
            let data = session.data_mut();

            data.entries.push(second);
            data.updated_at_ms = NOW_MS + 2;
        }

        session.save().unwrap();

        let backup_envelope = load_envelope(session.backup_path()).unwrap();

        let backup_plaintext = open_envelope(MASTER_PASSWORD, &backup_envelope).unwrap();

        let backup_data: VaultData = serde_json::from_slice(backup_plaintext.as_slice()).unwrap();

        backup_data.validate().unwrap();

        assert_eq!(backup_data.entries.len(), 1);

        assert_eq!(backup_data.entries[0].title, "First Entry");

        assert_eq!(backup_data.entries[0].password, "first-secret");
    }

    #[test]
    fn session_storage_contains_no_plaintext_master_or_entry_secret() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        let mut entry = VaultEntry::new("Secret Session Entry", NOW_MS + 1).unwrap();

        entry.username = "plaintext-user@example.test".to_owned();

        entry.password = SESSION_SECRET.to_owned();

        {
            let data = session.data_mut();

            data.entries.push(entry);
            data.updated_at_ms = NOW_MS + 1;
        }

        session.save().unwrap();

        let raw = fs::read_to_string(session.path()).unwrap();

        assert!(!raw.contains(MASTER_PASSWORD));
        assert!(!raw.contains(SESSION_SECRET));
        assert!(!raw.contains("plaintext-user@example.test"));
        assert!(!raw.contains("Secret Session Entry"));
    }

    #[test]
    fn create_refuses_to_overwrite_existing_vault() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let existing = create_envelope(MASTER_PASSWORD, b"existing-encrypted-payload").unwrap();

        save_envelope_atomic(&path, &existing).unwrap();

        let before = fs::read(&path).unwrap();

        let result = UnlockedVaultSession::create(&path, test_password(), NOW_MS);

        assert!(matches!(result, Err(SessionError::AlreadyExists)));

        let after = fs::read(&path).unwrap();

        assert_eq!(after, before);
    }

    #[test]
    fn second_session_for_same_vault_is_rejected_while_first_is_open() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let _first = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        let result = UnlockedVaultSession::unlock(&path, test_password());

        assert!(matches!(result, Err(SessionError::InUse)));
    }

    #[test]
    fn dropping_session_releases_exclusive_lock() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let first = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        drop(first);

        let reopened = UnlockedVaultSession::unlock(&path, test_password()).unwrap();

        assert!(!reopened.is_dirty());
    }

    #[test]
    fn save_rejects_vault_changed_on_disk() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        let mut entry = VaultEntry::new("Unsaved Entry", NOW_MS + 1).unwrap();

        entry.password = SESSION_SECRET.to_owned();

        {
            let data = session.data_mut();

            data.entries.push(entry);
            data.updated_at_ms = NOW_MS + 1;
        }

        let replacement_data = VaultData::new(NOW_MS + 10).unwrap();

        let replacement_plaintext = Zeroizing::new(serde_json::to_vec(&replacement_data).unwrap());

        let replacement =
            create_envelope(MASTER_PASSWORD, replacement_plaintext.as_slice()).unwrap();

        // Simulates a non-cooperating external writer.
        save_envelope_atomic(&path, &replacement).unwrap();

        let result = session.save();

        assert!(matches!(result, Err(SessionError::ChangedOnDisk)));

        assert!(session.is_dirty());

        let current = load_envelope(&path).unwrap();

        assert_eq!(current, replacement);
    }
}
