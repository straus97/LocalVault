mod backups;
mod categories;
pub use categories::{CategoryInput, CategorySummary};
mod entries;
mod master_password;
pub use entries::{EntryDetails, EntryInput, EntrySummary, TotpUpdate};

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use localvault_core::{
    sync_state::{BindingMismatch, Locator, SyncState},
    vault::{
        data::{VaultData, VaultDataError},
        format::{
            create_envelope_with_key, open_envelope_with_key, reseal_envelope, SecretKey,
            VaultEnvelope, VaultError,
        },
    },
};

use super::{
    storage::{load_envelope, save_envelope_atomic_with_backup, StorageError},
    sync_state_store::{
        path_identity_eq, CorruptReason, StateLoad, SyncStateRoot, SyncStateStore, UnreadableReason,
    },
};
use crate::recent_vaults::normalize_existing_vault_path;

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

    #[error("current master password is invalid")]
    CurrentMasterPasswordInvalid,

    #[error("new master password matches the current password")]
    NewMasterPasswordMatchesCurrent,

    #[error("internal previous-version backup is invalid for password rotation")]
    InternalBackupInvalid,

    #[error("master-password change rollback failed")]
    PasswordChangeRollbackFailed,

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

/// A saved sync-state record that passed the session-bound checks of
/// [`UnlockedVaultSession::load_sync_state`]: it is bound to this session's
/// authenticated `vault_id` and to this session's normalized local location.
///
/// **It says nothing about any remote target.** There is no selected target in
/// this slice, so the record's target locator was only compared with itself.
/// A future synchronization operation must separately compare the target it was
/// asked to use with [`SyncState::target_locator`] before touching anything. A
/// bound record is neither authorization to publish nor to adopt remote data,
/// and its absence of mismatch is not proof of freshness. The state is shown
/// by neither `Debug` nor any error.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionBoundSyncState {
    state: SyncState,
}

impl SessionBoundSyncState {
    pub fn state(&self) -> &SyncState {
        &self.state
    }
}

impl std::fmt::Debug for SessionBoundSyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionBoundSyncState(<redacted>)")
    }
}

/// Why no sync-state outcome could be produced for this session at all.
/// Categories only: no path, locator or identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStateUnavailable {
    /// The vault file has no usable normalized locator (it is missing, is not a
    /// regular `.lvault` file, or its path cannot be represented).
    LocalLocator,
    /// The vault file at the session's path is not the envelope this session
    /// unlocked (replaced, changed or unreadable), so the path cannot be
    /// treated as the location of this session's vault.
    LocalVaultChanged,
    /// The device-local application-data root cannot be used.
    Root,
}

/// Result of [`UnlockedVaultSession::load_sync_state`]. Every variant is
/// distinct and none is a healthy binding except [`Self::Bound`]; in particular
/// `NotConfigured` is not a trusted checkpoint and does not authorize
/// publishing over an existing remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSyncState {
    /// Confirmed no record. Not a trusted prior checkpoint.
    NotConfigured,
    Bound(Box<SessionBoundSyncState>),
    Corrupt(CorruptReason),
    UnsupportedVersion,
    Unreadable(UnreadableReason),
    /// A readable record that belongs to a different vault, or to a different
    /// local location, than this session. The record is left untouched.
    BindingMismatch(BindingMismatch),
    Unavailable(SyncStateUnavailable),
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

        // Prepare a copy, never the committed data: if any later step fails
        // the session keeps its pre-save schema and revision, so a retry
        // advances the revision exactly once.
        let mut candidate = self.data.clone();

        candidate.prepare_for_write()?;

        // Refuse to overwrite a vault which changed after
        // this session was opened/saved.
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

        Ok(true)
    }

    pub(crate) fn commit_candidate(
        &mut self,
        mut candidate: VaultData,
    ) -> Result<(), SessionError> {
        if self.dirty {
            return Err(SessionError::PendingUnsavedChanges);
        }

        // `candidate` is owned here, so a failure below drops it and leaves the
        // committed data (and its revision) untouched.
        candidate.prepare_for_write()?;

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

    /// Strictly read-only load of this vault's device-local sync-state record
    /// (Stage 1U-4 B1b).
    ///
    /// * **Session-bound.** Only an unlocked session can call this. It takes
    ///   `&self`, so the session — and with it the exclusive OS lock held by
    ///   `_lock_file` — outlives the whole read; a closed or expired session
    ///   does not exist to call it on.
    /// * **Authenticated identity.** The vault id comes from this session's
    ///   decrypted data, never from a caller, filename or the record. It is
    ///   used only inside `verify_binding` and is never returned or logged.
    /// * **Locator.** The local locator is the existing
    ///   `normalize_existing_vault_path` result for the session's path, after
    ///   confirming the file there still holds the envelope this session
    ///   unlocked. Path-string equality does not prove the identity of every
    ///   filesystem object behind it.
    /// * **Root.** [`SyncStateRoot`] comes from the trusted application context
    ///   (`app_local_data_dir()`), not from the UI.
    /// * **Read-only.** Nothing is created, repaired, replaced or deleted, and
    ///   no remote or network is touched. The local vault is only read.
    ///
    /// Failure to read the state never prevents ordinary local use of the
    /// session; it is reported, never swallowed into a healthy binding.
    pub fn load_sync_state(&self, root: &SyncStateRoot) -> SessionSyncState {
        match load_envelope(&self.path) {
            Ok(on_disk) if on_disk == self.envelope => {}
            _ => return SessionSyncState::Unavailable(SyncStateUnavailable::LocalVaultChanged),
        }

        let Some(local_locator) = normalize_existing_vault_path(&self.path)
            .ok()
            .and_then(|normalized| Locator::new(&normalized).ok())
        else {
            return SessionSyncState::Unavailable(SyncStateUnavailable::LocalLocator);
        };

        let Ok(store) = SyncStateStore::new(root.path()) else {
            return SessionSyncState::Unavailable(SyncStateUnavailable::Root);
        };

        match store.load(&local_locator) {
            StateLoad::NotConfigured => SessionSyncState::NotConfigured,
            StateLoad::Loaded(state) => bind_loaded(*state, self.data.vault_id, &local_locator),
            StateLoad::Corrupt(reason) => SessionSyncState::Corrupt(reason),
            StateLoad::UnsupportedVersion => SessionSyncState::UnsupportedVersion,
            StateLoad::Unreadable(reason) => SessionSyncState::Unreadable(reason),
        }
    }
}

/// Verify a loaded record against the authenticated vault id and the session's
/// normalized local locator.
///
/// The store already found the record through the existing ASCII
/// case-insensitive path identity, so that same rule is applied to the locator
/// here (a case-only spelling difference is the same location); anything else
/// that differs is a mismatch. `verify_binding` also needs a target locator;
/// with no selected target in this slice the record's own is passed, which makes
/// the target comparison vacuous by construction. See [`SessionBoundSyncState`].
fn bind_loaded(
    state: SyncState,
    authenticated_vault_id: Uuid,
    local_locator: &Locator,
) -> SessionSyncState {
    let expected_local = if path_identity_eq(state.local_locator().as_str(), local_locator.as_str())
    {
        state.local_locator().clone()
    } else {
        local_locator.clone()
    };
    let retained_target = state.target_locator().clone();

    match state.verify_binding(authenticated_vault_id, &expected_local, &retained_target) {
        Ok(()) => SessionSyncState::Bound(Box::new(SessionBoundSyncState { state })),
        Err(mismatch) => SessionSyncState::BindingMismatch(mismatch),
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
    use crate::vault::storage::{load_envelope, save_envelope_atomic};
    use localvault_core::vault::{
        data::{VaultEntry, VAULT_DATA_SCHEMA_VERSION},
        format::{create_envelope, open_envelope, CryptoError, VaultError},
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

    // -- Stage 1U-2: schema 3 and authenticated revision tracking ---------

    fn persisted_data(path: &Path) -> VaultData {
        let envelope = load_envelope(path).unwrap();

        let plaintext = open_envelope(MASTER_PASSWORD, &envelope).unwrap();

        serde_json::from_slice(plaintext.as_slice()).unwrap()
    }

    fn category(name: &str) -> CategoryInput {
        CategoryInput {
            name: name.to_owned(),
        }
    }

    /// Writes a legacy (pre-revision) vault straight to disk, the way an
    /// older build left it, so no current-code write path touches it first.
    fn write_legacy_vault(path: &Path, schema_version: u16) -> VaultData {
        let mut data = VaultData::new(NOW_MS).unwrap();
        data.schema_version = schema_version;

        let plaintext = Zeroizing::new(serde_json::to_vec(&data).unwrap());

        let value: serde_json::Value = serde_json::from_slice(plaintext.as_slice()).unwrap();
        assert!(value.get("revision").is_none());

        let envelope = create_envelope(MASTER_PASSWORD, plaintext.as_slice()).unwrap();

        save_envelope_atomic(path, &envelope).unwrap();

        data
    }

    #[test]
    fn new_vault_is_schema_three_at_revision_zero_and_creation_does_not_bump_it() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        assert_eq!(session.data().schema_version, 3);
        assert_eq!(session.data().revision, 0);

        let persisted = persisted_data(&path);

        assert_eq!(persisted.schema_version, 3);
        assert_eq!(persisted.revision, 0);

        let bytes_after_create = fs::read(&path).unwrap();

        session.lock();

        // Unlocking and locking a current vault rewrites nothing.
        let reopened = UnlockedVaultSession::unlock(&path, test_password()).unwrap();

        assert_eq!(reopened.data().revision, 0);

        reopened.lock();

        assert_eq!(fs::read(&path).unwrap(), bytes_after_create);
    }

    #[test]
    fn each_successful_write_advances_the_persisted_revision_by_exactly_one() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        // Transactional path (`commit_candidate`).
        session
            .create_category(category("One"), NOW_MS + 1)
            .unwrap();

        assert_eq!(session.data().revision, 1);
        assert_eq!(persisted_data(&path).revision, 1);

        // Dirty path (`save`).
        session.data_mut().updated_at_ms = NOW_MS + 2;

        assert!(session.save().unwrap());

        assert_eq!(session.data().revision, 2);
        assert_eq!(persisted_data(&path).revision, 2);

        session
            .create_category(category("Two"), NOW_MS + 3)
            .unwrap();

        assert_eq!(session.data().revision, 3);
        assert_eq!(persisted_data(&path).revision, 3);

        // A clean save writes nothing and so counts nothing.
        assert!(!session.save().unwrap());

        assert_eq!(persisted_data(&path).revision, 3);

        session.lock();

        let reopened = UnlockedVaultSession::unlock(&path, test_password()).unwrap();

        assert_eq!(reopened.data().revision, 3);
    }

    #[test]
    fn backup_keeps_the_previous_revision() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        session
            .create_category(category("One"), NOW_MS + 1)
            .unwrap();
        session
            .create_category(category("Two"), NOW_MS + 2)
            .unwrap();

        assert_eq!(persisted_data(&path).revision, 2);
        assert_eq!(persisted_data(session.backup_path()).revision, 1);
    }

    #[test]
    fn external_change_refuses_the_commit_and_keeps_the_committed_revision() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        session
            .create_category(category("One"), NOW_MS + 1)
            .unwrap();

        let replacement =
            create_envelope(MASTER_PASSWORD, b"external replacement payload").unwrap();

        // Simulates a non-cooperating external writer.
        save_envelope_atomic(&path, &replacement).unwrap();

        let result = session.create_category(category("Two"), NOW_MS + 2);

        assert!(matches!(result, Err(SessionError::ChangedOnDisk)));

        assert_eq!(session.data().revision, 1);
        assert_eq!(session.data().schema_version, 3);
        assert_eq!(session.data().categories.len(), 1);
        assert_eq!(load_envelope(&path).unwrap(), replacement);
    }

    #[test]
    fn failed_save_keeps_legacy_schema_and_revision_so_a_retry_counts_once() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        write_legacy_vault(&path, 2);

        let mut session = UnlockedVaultSession::unlock(&path, test_password()).unwrap();

        assert_eq!(session.data().schema_version, 2);
        assert_eq!(session.data().revision, 0);

        session.data_mut().updated_at_ms = NOW_MS + 1;

        let replacement = create_envelope(MASTER_PASSWORD, b"external replacement").unwrap();

        save_envelope_atomic(&path, &replacement).unwrap();

        let result = session.save();

        assert!(matches!(result, Err(SessionError::ChangedOnDisk)));

        // Neither the schema upgrade nor the increment leaked into the
        // committed in-memory data.
        assert!(session.is_dirty());
        assert_eq!(session.data().schema_version, 2);
        assert_eq!(session.data().revision, 0);
        assert_eq!(load_envelope(&path).unwrap(), replacement);
    }

    #[test]
    fn revision_overflow_is_rejected_without_wrapping_or_writing() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut session = UnlockedVaultSession::create(&path, test_password(), NOW_MS).unwrap();

        session.data.revision = u64::MAX;

        let bytes_before = fs::read(&path).unwrap();

        // Transactional path.
        let result = session.create_category(category("Overflow"), NOW_MS + 1);

        assert!(matches!(
            result,
            Err(SessionError::Data(VaultDataError::RevisionOverflow))
        ));

        assert_eq!(session.data().revision, u64::MAX);
        assert!(session.data().categories.is_empty());
        assert_eq!(fs::read(&path).unwrap(), bytes_before);

        // Dirty path.
        session.data_mut().updated_at_ms = NOW_MS + 2;

        let result = session.save();

        assert!(matches!(
            result,
            Err(SessionError::Data(VaultDataError::RevisionOverflow))
        ));

        assert!(session.is_dirty());
        assert_eq!(session.data().revision, u64::MAX);
        assert_eq!(fs::read(&path).unwrap(), bytes_before);
    }

    #[test]
    fn unlock_rejects_unsupported_future_schema() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut payload = serde_json::to_value(VaultData::new(NOW_MS).unwrap()).unwrap();

        payload["schema_version"] = serde_json::json!(VAULT_DATA_SCHEMA_VERSION + 1);

        let envelope =
            create_envelope(MASTER_PASSWORD, &serde_json::to_vec(&payload).unwrap()).unwrap();

        save_envelope_atomic(&path, &envelope).unwrap();

        let result = UnlockedVaultSession::unlock(&path, test_password());

        assert!(matches!(
            result,
            Err(SessionError::Data(VaultDataError::UnsupportedSchemaVersion))
        ));
    }

    #[test]
    fn unlock_rejects_schema_three_payload_without_a_revision() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let mut payload = serde_json::to_value(VaultData::new(NOW_MS).unwrap()).unwrap();

        assert!(payload
            .as_object_mut()
            .unwrap()
            .remove("revision")
            .is_some());

        let envelope =
            create_envelope(MASTER_PASSWORD, &serde_json::to_vec(&payload).unwrap()).unwrap();

        save_envelope_atomic(&path, &envelope).unwrap();

        let result = UnlockedVaultSession::unlock(&path, test_password());

        assert!(matches!(result, Err(SessionError::Deserialization(_))));
    }

    // -- Stage 1U-4 B1b: binding verification (pure; no filesystem) --------
    //
    // The filesystem-backed, real-session tests live beside the store's scratch
    // helper in `sync_state_store::tests` (they must not use `%TEMP%`).

    mod sync_binding {
        use localvault_core::{
            sync::{EnvelopeFingerprint, RemoteHighWater},
            sync_state::{BindingId, SyncBase, SyncCheckpoint, VaultBindingTag, BINDING_SALT_LEN},
        };

        use super::*;

        const LOCAL: &str = r"\\?\C:\Synthetic\Vaults\Mine.lvault";
        const TARGET: &str = r"\\?\D:\Synthetic\Remote\target.lvault";
        const VAULT_ID: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        const OTHER_ID: Uuid = Uuid::from_u128(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210);

        fn loc(value: &str) -> Locator {
            Locator::new(value).unwrap()
        }

        fn state(local: &str, vault_id: Uuid, target: &str) -> SyncState {
            let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
            let checkpoint = SyncCheckpoint::new(
                EnvelopeFingerprint::of_bytes(&[1]),
                1,
                RemoteHighWater::new(1),
            )
            .unwrap();

            SyncState::new(
                BindingId::new(Uuid::from_u128(7)).unwrap(),
                VaultBindingTag::derive(salt, vault_id).unwrap(),
                loc(local),
                loc(target),
                SyncBase::Based(checkpoint),
                None,
            )
            .unwrap()
        }

        #[test]
        fn matching_vault_and_locator_are_bound() {
            let record = state(LOCAL, VAULT_ID, TARGET);

            let result = bind_loaded(record.clone(), VAULT_ID, &loc(LOCAL));

            assert_eq!(
                result,
                SessionSyncState::Bound(Box::new(SessionBoundSyncState { state: record }))
            );
        }

        #[test]
        fn a_case_only_locator_difference_is_the_same_location() {
            // The existing Windows path identity is ASCII case-insensitive.
            let record = state(LOCAL, VAULT_ID, TARGET);

            let result = bind_loaded(record, VAULT_ID, &loc(&LOCAL.to_ascii_uppercase()));

            assert!(matches!(result, SessionSyncState::Bound(_)));
        }

        #[test]
        fn a_different_local_path_is_a_mismatch() {
            let record = state(LOCAL, VAULT_ID, TARGET);

            let other = r"\\?\C:\Synthetic\Vaults\Other.lvault";

            assert_eq!(
                bind_loaded(record, VAULT_ID, &loc(other)),
                SessionSyncState::BindingMismatch(BindingMismatch::LocalLocator)
            );
        }

        #[test]
        fn a_different_vault_at_the_same_path_is_a_mismatch() {
            let record = state(LOCAL, VAULT_ID, TARGET);

            assert_eq!(
                bind_loaded(record.clone(), OTHER_ID, &loc(LOCAL)),
                SessionSyncState::BindingMismatch(BindingMismatch::VaultIdentity)
            );
            assert_eq!(
                bind_loaded(record, Uuid::nil(), &loc(LOCAL)),
                SessionSyncState::BindingMismatch(BindingMismatch::VaultIdentity)
            );
        }

        #[test]
        fn a_bound_record_does_not_authorize_a_different_target() {
            let record = state(LOCAL, VAULT_ID, TARGET);

            let SessionSyncState::Bound(bound) = bind_loaded(record, VAULT_ID, &loc(LOCAL)) else {
                panic!("expected a bound state");
            };

            // `Bound` carries the retained target; choosing a target is a
            // separate, later comparison that must still fail for any other.
            assert_eq!(bound.state().target_locator().as_str(), TARGET);
            assert_eq!(
                bound.state().verify_binding(
                    VAULT_ID,
                    &loc(LOCAL),
                    &loc(r"\\?\D:\Synthetic\Remote\someone-elses.lvault"),
                ),
                Err(BindingMismatch::TargetLocator)
            );
            assert!(bound
                .state()
                .verify_binding(VAULT_ID, &loc(LOCAL), &loc(TARGET))
                .is_ok());
        }

        #[test]
        fn outcomes_show_no_identifier_locator_or_state() {
            let record = state(LOCAL, VAULT_ID, TARGET);

            let mut outcomes = vec![
                bind_loaded(record.clone(), VAULT_ID, &loc(LOCAL)),
                bind_loaded(record.clone(), OTHER_ID, &loc(LOCAL)),
                bind_loaded(record, VAULT_ID, &loc(r"\\?\C:\Synthetic\Other.lvault")),
                SessionSyncState::NotConfigured,
                SessionSyncState::UnsupportedVersion,
            ];
            outcomes.push(SessionSyncState::Corrupt(CorruptReason::Undecodable));
            outcomes.push(SessionSyncState::Unreadable(UnreadableReason::Io(
                io::ErrorKind::PermissionDenied,
            )));
            for reason in [
                SyncStateUnavailable::LocalLocator,
                SyncStateUnavailable::LocalVaultChanged,
                SyncStateUnavailable::Root,
            ] {
                outcomes.push(SessionSyncState::Unavailable(reason));
            }

            let needles = [
                "Synthetic",
                "Mine.lvault",
                "target.lvault",
                "0123456789abcdef",
                "01234567-89ab-cdef",
                "fedcba98",
                "00000000-0000-0000-0000-000000000007",
            ];

            for outcome in &outcomes {
                let shown = format!("{outcome:?}");

                for needle in needles {
                    assert!(!shown.contains(needle), "leaks {needle:?}: {shown}");
                }
            }
        }
    }
}
