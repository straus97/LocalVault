mod backups;
mod categories;
pub use categories::{CategoryInput, CategorySummary};
mod entries;
mod master_password;
pub use entries::{EntryDetails, EntryInput, EntrySummary, TotpUpdate};

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read},
    path::{Path, PathBuf},
};

use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use localvault_core::{
    sync::{inspect_remote_bytes, BoundInspectionError},
    sync_state::{
        record_remote_observation, BindingMismatch, HighWaterOutcome, Locator, SyncBase, SyncState,
        TransitionRefusal,
    },
    vault::{
        data::{VaultData, VaultDataError},
        format::{
            create_envelope_with_key, open_envelope_with_key, reseal_envelope, SecretKey,
            VaultEnvelope, VaultError,
        },
    },
};

use super::{
    storage::{
        load_envelope, save_envelope_atomic_with_backup, StorageError, MAX_VAULT_FILE_BYTES,
    },
    sync_file_adapter::{SyncFileRead, SyncFileTarget, UnavailableReason},
    sync_state_store::{
        path_identity_eq, CorruptReason, StateLoad, StoreError, SyncStateRoot, SyncStateStore,
        UnreadableReason,
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

/// What a successful [`UnlockedVaultSession::record_remote_observation`]
/// established. Fieldless on purpose: no revision, fingerprint or identifier.
///
/// Neither variant moves the synchronized baseline and neither authorizes a
/// push or a pull.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum RemoteObservationOutcome {
    /// The authenticated remote revision was above the trusted high-water mark.
    /// The raised record was published by guarded replacement, read back
    /// byte-identically by the store, and then loaded again by a fresh read
    /// that agreed with it.
    HighWaterRaised,
    /// The authenticated remote revision equals the trusted high-water mark.
    /// Nothing was written.
    Unchanged,
}

/// Why no observation was recorded. Fixed categories only: no path, locator,
/// identifier, fingerprint or revision, in `Debug` or `Display`.
///
/// Every variant except [`PersistenceUnverified`](Self::PersistenceUnverified)
/// leaves the stored record as it was, and none of them lowers the high-water
/// mark, clears a pending push or resets the binding. After
/// `PersistenceUnverified` (and after [`NotPersisted`](Self::NotPersisted)) any
/// later decision must start with a fresh load; nothing is retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RemoteObservationRefusal {
    /// The session's own vault or location cannot serve as the binding anchor.
    #[error("the session's vault or sync-state location is unavailable")]
    Unavailable(SyncStateUnavailable),
    /// No record exists. An observation never creates a binding.
    #[error("no synchronization binding exists")]
    NotConfigured,
    #[error("the synchronization binding record is corrupt")]
    Corrupt(CorruptReason),
    #[error("the synchronization binding record has an unsupported version")]
    UnsupportedVersion,
    #[error("the synchronization binding record could not be read")]
    Unreadable(UnreadableReason),
    /// The record belongs to another vault, or the supplied target is not the
    /// retained one (the target comparison is exact).
    #[error("the synchronization binding does not match this vault or target")]
    BindingMismatch(BindingMismatch),
    /// The candidate bytes (or the local reference) did not authenticate as
    /// this vault's envelope. Names the input at fault; carries no content.
    #[error("the envelope inspection was rejected")]
    Inspection(BoundInspectionError),
    /// The accepted core transition refused (for example a pending push, an
    /// unbased state, or a legacy candidate with no revision counter).
    #[error("the high-water transition was refused")]
    Transition(TransitionRefusal),
    /// The authenticated remote is below the trusted high-water mark. The mark
    /// is not lowered, the record is not touched and the binding is not reset.
    #[error("the remote is below the trusted high-water revision")]
    KnownRegression,
    /// The store failed at a step that precedes publication of the replacement
    /// (a precondition, the comparisons, or staging the temporary file), so the
    /// previous record was never replaced. Only errors for which
    /// `replace_error_may_follow_publication` is false land here.
    #[error("the raised high-water state was not persisted")]
    NotPersisted(StoreError),
    /// The replacement may or may not have been published: the failure was the
    /// publication step itself (the store reports only that the rename failed)
    /// or the readback after it, or a fresh reload disagreed. The persisted
    /// state is unknown until freshly loaded; nothing is retried.
    #[error("the raised high-water state could not be verified after writing")]
    PersistenceUnverified,
}

/// Why [`UnlockedVaultSession::observe_remote_target`] recorded nothing. Fixed
/// categories only: no path, locator, identifier, fingerprint, revision or file
/// content, in `Debug` or `Display`.
///
/// Every variant leaves the sync-state record as it was, except the
/// persistence classifications carried inside [`Self::Observation`]
/// ([`RemoteObservationRefusal::PersistenceUnverified`] and
/// [`RemoteObservationRefusal::NotPersisted`]), whose meaning is unchanged from
/// B1c. Nothing is retried, and none of these lowers the high-water mark,
/// clears a pending push or creates a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RemoteTargetRefusal {
    /// Refused by the binding check made **before** the target was read, or by
    /// the B1c observation (authentication, transition, persistence) after it.
    #[error("the remote observation was refused")]
    Observation(#[from] RemoteObservationRefusal),
    /// The target was not found in a valid, readable local parent chain. This is
    /// a fact about this machine's folder at this instant. It is **not** remote
    /// absence, not an authorization to publish, and creates no state.
    #[error("the target file was not found in the local folder")]
    AbsentOnDisk,
    /// Nothing may be concluded about the target (unreadable, a directory or
    /// reparse point, empty, oversized, changed during the read, ...). Never
    /// absence, never retried.
    #[error("the target file could not be read")]
    TargetUnavailable(UnavailableReason),
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

        let Some(local_locator) = self.local_locator() else {
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

    /// Record a newly authenticated remote observation against this vault's
    /// **existing** synchronization binding (Stage 1U-4 B1c). Internal: no
    /// command, event or UI is attached, and no user-facing synchronization
    /// operation is enabled by it.
    ///
    /// What it does, in order, all inside one `&self` borrow of the unlocked
    /// session (so the exclusive OS lock held by `_lock_file` is held for the
    /// whole call, and a closed session has nothing to call it on):
    ///
    /// 1. reads the vault file's **exact current bytes** and requires that they
    ///    parse to precisely the envelope this session unlocked (otherwise the
    ///    vault changed on disk: [`SyncStateUnavailable::LocalVaultChanged`]);
    ///    the same raw bytes, never a re-serialization, are the local reference
    ///    of the inspection;
    /// 2. loads the saved record through [`SyncStateStore`] and refuses a
    ///    missing, corrupt, unsupported, unreadable or foreign one, never
    ///    creating or repairing anything;
    /// 3. verifies it against the authenticated `vault_id` of this session, the
    ///    session's normalized local location and the supplied `target`;
    /// 4. authenticates `candidate_raw` with `inspect_remote_bytes` under this
    ///    session's Vault Key, producing the only evidence the core transition
    ///    accepts (a `BoundInspection` of those exact bytes);
    /// 5. applies the core `record_remote_observation` transition and writes
    ///    only a `Raised` result, by [`SyncStateStore::replace`] (guarded
    ///    replacement with readback), then loads the record afresh and requires
    ///    it to equal the proposed state.
    ///
    /// Nothing else changes: the encrypted vault, its `.backup` and its lock
    /// file are not written, nothing is sent to any remote, the synchronized
    /// checkpoint and any pending push are left as they are, and the high-water
    /// mark can only rise. There is no retry.
    ///
    /// # The target boundary (read this before calling)
    ///
    /// **`target` and `candidate_raw` are caller assertions; this method cannot
    /// verify that the bytes were read from that target.** There is no remote
    /// target adapter yet. The only thing proven here is that the bytes are a
    /// genuine envelope of this very vault (authenticated under its Vault Key),
    /// and that `target` is, by exact string comparison, the target retained in
    /// the binding. A future adapter must itself:
    ///
    /// * resolve the target the user chose and verify it is the retained one;
    /// * read the encrypted bytes from exactly that target and pass exactly
    ///   those bytes here;
    /// * re-verify the target's identity if its provider can change it between
    ///   operations.
    ///
    /// Bytes taken from anywhere else (an older copy, a backup, another
    /// location) that are still authentic envelopes of this vault could only
    /// raise the mark to a revision the vault really reached: that is the
    /// stricter direction, but it can later make the true remote look like a
    /// regression. This is why the method must never be reachable from the
    /// frontend or from an unvetted caller.
    ///
    /// # Concurrency
    ///
    /// The store's replacement is read-compare-write, not compare-and-swap
    /// against an arbitrary process. It is safe only because this session holds
    /// the exclusive per-vault lock; a non-cooperating external writer of the
    /// state file can still win a race, which the store detects only
    /// opportunistically. Power-loss durability is not claimed.
    pub fn record_remote_observation(
        &self,
        root: &SyncStateRoot,
        target: &Locator,
        candidate_raw: &[u8],
    ) -> Result<RemoteObservationOutcome, RemoteObservationRefusal> {
        let store = SyncStateStore::new(root.path())
            .map_err(|_| RemoteObservationRefusal::Unavailable(SyncStateUnavailable::Root))?;

        self.record_remote_observation_in(&store, target, candidate_raw)
    }

    /// [`record_remote_observation`](Self::record_remote_observation) over an
    /// explicit store. Split out only so tests can inject store faults.
    pub(crate) fn record_remote_observation_in(
        &self,
        store: &SyncStateStore,
        target: &Locator,
        candidate_raw: &[u8],
    ) -> Result<RemoteObservationOutcome, RemoteObservationRefusal> {
        use RemoteObservationRefusal as Refusal;

        let local_raw = self.current_local_raw().ok_or(Refusal::Unavailable(
            SyncStateUnavailable::LocalVaultChanged,
        ))?;

        let local_locator = self
            .local_locator()
            .ok_or(Refusal::Unavailable(SyncStateUnavailable::LocalLocator))?;

        let state = match store.load(&local_locator) {
            StateLoad::Loaded(state) => *state,
            StateLoad::NotConfigured => return Err(Refusal::NotConfigured),
            StateLoad::Corrupt(reason) => return Err(Refusal::Corrupt(reason)),
            StateLoad::UnsupportedVersion => return Err(Refusal::UnsupportedVersion),
            StateLoad::Unreadable(reason) => return Err(Refusal::Unreadable(reason)),
        };

        let expected_local = effective_local_locator(&state, &local_locator);

        state
            .verify_binding(self.data.vault_id, &expected_local, target)
            .map_err(Refusal::BindingMismatch)?;

        // The state's own mark is the trusted high-water; an unbased state has
        // none, and the transition refuses it below.
        let high_water = match state.base() {
            SyncBase::Based(checkpoint) => Some(checkpoint.high_water()),
            SyncBase::Unbased => None,
        };

        let observation = inspect_remote_bytes(
            &self.vault_key,
            self.data.vault_id,
            &local_raw,
            candidate_raw,
            high_water,
        )
        .map_err(Refusal::Inspection)?;

        match record_remote_observation(&state, &expected_local, target, &observation) {
            Ok(HighWaterOutcome::Unchanged) => Ok(RemoteObservationOutcome::Unchanged),
            Ok(HighWaterOutcome::KnownRegression) => Err(Refusal::KnownRegression),
            Ok(HighWaterOutcome::Raised(proposed)) => {
                match store.replace(&state, &proposed) {
                    Ok(()) => {}
                    Err(error) if replace_error_may_follow_publication(error) => {
                        return Err(Refusal::PersistenceUnverified)
                    }
                    Err(error) => return Err(Refusal::NotPersisted(error)),
                }

                if persisted_matches(store.load(&local_locator), &proposed) {
                    Ok(RemoteObservationOutcome::HighWaterRaised)
                } else {
                    Err(Refusal::PersistenceUnverified)
                }
            }
            Err(refusal) => Err(Refusal::Transition(refusal)),
        }
    }

    /// Read the user-selected local file `target` and record what it proves
    /// against this vault's **existing** synchronization binding (Stage 1U-4
    /// B1e). Internal: no command, event, UI or automatic caller exists, and no
    /// user-facing synchronization is enabled by it.
    ///
    /// This joins the read-only filesystem adapter (B1d) to the authenticated
    /// high-water observation (B1c) without re-implementing either. In order,
    /// all inside one `&self` borrow of the unlocked session (so the exclusive OS
    /// lock held by `_lock_file` is held across the whole read and the state
    /// update, and a closed session has nothing to call it on):
    ///
    /// 1. [`load_sync_state`](Self::load_sync_state) must yield a **bound**
    ///    record (this session's authenticated `vault_id`, this session's local
    ///    location, the local vault file still the unlocked envelope). Every
    ///    other outcome is refused;
    /// 2. the record's retained target locator must equal `target`'s locator
    ///    exactly (core `verify_binding`), **before any byte of the target is
    ///    opened**: a mismatch never touches the selected file;
    /// 3. only then [`SyncFileTarget::read`] runs;
    /// 4. a `Present` read hands its own paired `target()` and `candidate_raw()`
    ///    — the very values the adapter produced, never re-derived or
    ///    re-serialized — to [`record_remote_observation`](Self::record_remote_observation),
    ///    which reloads and re-verifies the binding and the local vault, then
    ///    authenticates the bytes and applies the single accepted transition and
    ///    persistence path. That repeated verification is deliberate.
    ///
    /// `AbsentOnDisk` and `Unavailable` are returned as distinct refusals and
    /// change nothing: no record is created, no pending push is cleared and no
    /// mark moves. Neither is ever treated as remote absence, and nothing here
    /// retries.
    ///
    /// # What a success does and does not mean
    ///
    /// * Matching the locator to the stored binding does **not** prove a cloud
    ///   provider's authority over the file; it is a local filesystem path.
    /// * `Present` proves only that bounded bytes were read through the adapter's
    ///   local-file checks; authentication proves only that they are a genuine
    ///   envelope of **this vault**. Neither proves freshness, provider
    ///   consistency or global ancestry, and a file absent here says nothing
    ///   about a remote artifact.
    /// * Nothing is written to the target, the vault, its `.backup` or its lock
    ///   file; the synchronized baseline never moves; nothing is uploaded; and
    ///   no completed provider upload is asserted.
    pub fn observe_remote_target(
        &self,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
    ) -> Result<RemoteObservationOutcome, RemoteTargetRefusal> {
        self.observe_remote_target_with(root, target, SyncFileTarget::read)
    }

    /// [`observe_remote_target`](Self::observe_remote_target) with the read step
    /// injectable. Private, so no caller outside this module (and its tests) can
    /// substitute the read: tests use it to prove the read does not happen before
    /// the binding check, happens exactly once afterwards, and runs under the
    /// session lock.
    fn observe_remote_target_with(
        &self,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
        read: impl FnOnce(&SyncFileTarget) -> SyncFileRead,
    ) -> Result<RemoteObservationOutcome, RemoteTargetRefusal> {
        use RemoteObservationRefusal as Refusal;

        let bound = match self.load_sync_state(root) {
            SessionSyncState::Bound(bound) => bound,
            SessionSyncState::NotConfigured => return Err(Refusal::NotConfigured.into()),
            SessionSyncState::Corrupt(reason) => return Err(Refusal::Corrupt(reason).into()),
            SessionSyncState::UnsupportedVersion => return Err(Refusal::UnsupportedVersion.into()),
            SessionSyncState::Unreadable(reason) => return Err(Refusal::Unreadable(reason).into()),
            SessionSyncState::BindingMismatch(mismatch) => {
                return Err(Refusal::BindingMismatch(mismatch).into())
            }
            SessionSyncState::Unavailable(reason) => {
                return Err(Refusal::Unavailable(reason).into())
            }
        };

        // `load_sync_state` already proved the record's vault and local location,
        // so its own local locator is the exact expectation here; the only new
        // fact checked is the selected target, by the core's exact comparison.
        let state = bound.state();

        state
            .verify_binding(self.data.vault_id, state.local_locator(), target.locator())
            .map_err(Refusal::BindingMismatch)?;

        match read(target) {
            SyncFileRead::Present(present) => self
                .record_remote_observation(root, present.target(), present.candidate_raw())
                .map_err(RemoteTargetRefusal::Observation),
            SyncFileRead::AbsentOnDisk => Err(RemoteTargetRefusal::AbsentOnDisk),
            SyncFileRead::Unavailable(reason) => {
                Err(RemoteTargetRefusal::TargetUnavailable(reason))
            }
        }
    }

    /// The session's normalized local location (the existing
    /// `normalize_existing_vault_path` result), if it has one.
    fn local_locator(&self) -> Option<Locator> {
        normalize_existing_vault_path(&self.path)
            .ok()
            .and_then(|normalized| Locator::new(&normalized).ok())
    }

    /// The exact bytes now in the vault file, only if they parse to precisely
    /// the envelope this session unlocked or last wrote. These raw bytes (not a
    /// re-serialization of `self.envelope`, which can differ byte for byte from
    /// what is on disk) are what the core fingerprints and authenticates.
    fn current_local_raw(&self) -> Option<Vec<u8>> {
        let raw = read_vault_file_bytes(&self.path)?;

        let parsed: VaultEnvelope = serde_json::from_slice(&raw).ok()?;

        parsed.validate_header().ok()?;

        (parsed == self.envelope).then_some(raw)
    }
}

/// Bounded read of a regular, non-symlink, non-empty vault file, with the same
/// limits as `storage::load_envelope` (whose raw reader is private to that
/// module).
fn read_vault_file_bytes(path: &Path) -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).ok()?;

    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_VAULT_FILE_BYTES
    {
        return None;
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);

    File::open(path)
        .ok()?
        .take(MAX_VAULT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;

    (!bytes.is_empty() && bytes.len() as u64 <= MAX_VAULT_FILE_BYTES).then_some(bytes)
}

/// Whether a `SyncStateStore::replace` error could have happened at or after
/// publication. Derived from the store's own sequence: preconditions, the two
/// comparisons and temp staging (`Inspect`, `Open`, `Write`, `Sync`) all fail
/// before the rename and leave the record untouched. The rename itself
/// (`Replace`) reports only that it failed, not that nothing was published, and
/// `VerificationFailed` is by construction post-publication. The match is
/// exhaustive on purpose; anything `replace` does not produce, or that is not
/// understood, fails closed as ambiguous.
pub(crate) fn replace_error_may_follow_publication(error: StoreError) -> bool {
    use super::sync_state_store::IoStage;

    match error {
        StoreError::Io {
            stage: IoStage::Inspect | IoStage::Open | IoStage::Write | IoStage::Sync,
            ..
        }
        | StoreError::Missing
        | StoreError::UnexpectedObject
        | StoreError::CurrentUnreadable
        | StoreError::CurrentCorrupt
        | StoreError::CurrentUnsupportedVersion
        | StoreError::CurrentLocatorMismatch
        | StoreError::Changed
        | StoreError::LocatorMismatch
        | StoreError::BindingIdentityChanged
        | StoreError::TrustedHistoryRegression
        | StoreError::Encode(_)
        | StoreError::RootNotAbsolute => false,

        StoreError::Io {
            stage: IoStage::Replace | IoStage::Directory | IoStage::Scan,
            ..
        }
        | StoreError::VerificationFailed
        | StoreError::AlreadyExists
        | StoreError::UnresolvedArtifacts
        | StoreError::NoClobberUnsupported
        | StoreError::IncompleteDeletion => true,
    }
}

/// A freshly loaded record is the persisted state only if it is exactly the
/// proposed one.
fn persisted_matches(load: StateLoad, proposed: &SyncState) -> bool {
    matches!(load, StateLoad::Loaded(current) if *current == *proposed)
}

/// The store found the record through the existing ASCII case-insensitive path
/// identity, so a case-only spelling difference is the same location and the
/// record's own spelling is used for the exact core comparison; anything else
/// is passed through and fails as a mismatch.
fn effective_local_locator(state: &SyncState, session_locator: &Locator) -> Locator {
    if path_identity_eq(state.local_locator().as_str(), session_locator.as_str()) {
        state.local_locator().clone()
    } else {
        session_locator.clone()
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
    let expected_local = effective_local_locator(&state, local_locator);
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
        fn only_an_identical_fresh_load_confirms_a_persisted_state() {
            let proposed = state(LOCAL, VAULT_ID, TARGET);
            let mut other = proposed.clone();

            // Same binding, different mark.
            let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
            other = SyncState::new(
                other.binding_id(),
                VaultBindingTag::derive(salt, VAULT_ID).unwrap(),
                loc(LOCAL),
                loc(TARGET),
                SyncBase::Based(
                    SyncCheckpoint::new(
                        EnvelopeFingerprint::of_bytes(&[1]),
                        1,
                        RemoteHighWater::new(2),
                    )
                    .unwrap(),
                ),
                None,
            )
            .unwrap();

            assert!(persisted_matches(
                StateLoad::Loaded(Box::new(proposed.clone())),
                &proposed
            ));
            for load in [
                StateLoad::Loaded(Box::new(other)),
                StateLoad::NotConfigured,
                StateLoad::UnsupportedVersion,
                StateLoad::Corrupt(CorruptReason::Undecodable),
                StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts),
            ] {
                assert!(!persisted_matches(load, &proposed));
            }
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

    // -- Stage 1U-4 B1e: observing a local file target through the session ----
    //
    // Real unlocked sessions, real synthetic vaults, real synthetic target files
    // and a real sync-state store, all beneath the git-ignored
    // `.qa-local/sync-state-b1-tests/` (never `%TEMP%`). Candidate "remote"
    // envelopes are genuine envelopes of the same vault, produced by committing
    // real writes on a copy, so their revisions are authenticated counters.
    //
    // Not covered here (and not claimed): any provider, network or cloud
    // behavior (none exists and none is called; this cannot be asserted by a
    // test, only by the absence of such code in the diff), store fault injection
    // (the store's hooks are private to its module; the B1c classifications of
    // `NotPersisted` and `PersistenceUnverified` are tested there and are reached
    // here only through the unchanged B1c call), and cross-process races.
    mod remote_target {
        use std::{cell::Cell, error::Error as _, time::SystemTime};

        use localvault_core::sync::{
            BoundInspectionError, EnvelopeFingerprint, EnvelopeInput, InspectionError,
            PayloadRejection, PushBaseline, PushIntent, RemoteHighWater, MAX_ENVELOPE_BYTES,
        };
        use localvault_core::sync_state::{
            BindingId, PendingPush, SyncCheckpoint, VaultBindingTag, BINDING_SALT_LEN,
        };

        use super::*;
        use crate::vault::sync_state_store::SYNC_STATE_DIRECTORY;

        type Outcome = RemoteObservationOutcome;
        type Obs = RemoteObservationRefusal;

        const PASSWORD: &str = "b1e-target-observation-test-only-password";
        const OTHER_LOCAL: &str = r"\\?\C:\Synthetic\Vaults\OTHER-MARKER.lvault";
        const OTHER_VAULT_ID: Uuid = Uuid::from_u128(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210);
        const BINDING: Uuid = Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555);
        const INTENT: Uuid = Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee);
        const STALE_TOKEN: &str = "0123456789abcdef0123456789abcdef";

        fn password() -> Zeroizing<String> {
            Zeroizing::new(PASSWORD.to_owned())
        }

        fn loc(value: &str) -> Locator {
            Locator::new(value).unwrap()
        }

        fn fp(tag: u8) -> EnvelopeFingerprint {
            EnvelopeFingerprint::of_bytes(&[tag])
        }

        fn checkpoint(high_water: u64) -> SyncBase {
            SyncBase::Based(
                SyncCheckpoint::new(fp(1), 1, RemoteHighWater::new(high_water)).unwrap(),
            )
        }

        fn pending_push(revision: u64) -> PendingPush {
            let intent = PushIntent::new(PushBaseline::Present(fp(1)), fp(3)).unwrap();

            PendingPush::new(INTENT, intent, revision).unwrap()
        }

        fn state_with(
            local: &str,
            vault_id: Uuid,
            target: &str,
            base: SyncBase,
            pending: Option<PendingPush>,
        ) -> SyncState {
            let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);

            SyncState::new(
                BindingId::new(BINDING).unwrap(),
                VaultBindingTag::derive(salt, vault_id).unwrap(),
                loc(local),
                loc(target),
                base,
                pending,
            )
            .unwrap()
        }

        /// Same binding as `old`, different base and pending push.
        fn rebuilt(old: &SyncState, base: SyncBase, pending: Option<PendingPush>) -> SyncState {
            SyncState::new(
                old.binding_id(),
                *old.vault_tag(),
                old.local_locator().clone(),
                old.target_locator().clone(),
                base,
                pending,
            )
            .unwrap()
        }

        fn tampered(state: &SyncState, edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
            let mut value: serde_json::Value =
                serde_json::from_slice(&state.encode().unwrap()).unwrap();

            edit(&mut value);

            serde_json::to_vec(&value).unwrap()
        }

        fn refused(refusal: Obs) -> Result<Outcome, RemoteTargetRefusal> {
            Err(RemoteTargetRefusal::Observation(refusal))
        }

        fn scratch(name: &str) -> tempfile::TempDir {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(".qa-local")
                .join("sync-state-b1-tests");

            fs::create_dir_all(&base).unwrap();

            tempfile::Builder::new()
                .prefix(&format!("{name}-"))
                .tempdir_in(&base)
                .unwrap()
        }

        fn names(dir: &Path) -> Vec<String> {
            let mut found: Vec<String> = fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();

            found.sort();

            found
        }

        /// Everything beneath `dir` without following reparse points: kind, name
        /// and, for plain files, length, modification time and content hash. The
        /// session's own exclusively locked `.lock` file is recorded by name only.
        fn snapshot(dir: &Path) -> Vec<String> {
            fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
                let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();

                entries.sort_by_key(|entry| entry.file_name());

                for entry in entries {
                    let path = entry.path();
                    let metadata = fs::symlink_metadata(&path).unwrap();
                    let relative = path
                        .strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    let kind = metadata.file_type();

                    if kind.is_symlink() {
                        out.push(format!("L {relative}"));
                    } else if kind.is_dir() {
                        out.push(format!("D {relative}"));
                        walk(&path, base, out);
                    } else if relative.ends_with(".lock") {
                        out.push(format!("K {relative}"));
                    } else {
                        let modified: SystemTime = metadata.modified().unwrap();
                        let hash = EnvelopeFingerprint::of_bytes(&fs::read(&path).unwrap());

                        out.push(format!(
                            "F {relative} {} {modified:?} {}",
                            metadata.len(),
                            hash.to_hex()
                        ));
                    }
                }
            }

            let mut out = Vec::new();

            walk(dir, dir, &mut out);

            out
        }

        /// Open without sharing: later opens for data fail with a sharing
        /// violation.
        #[cfg(windows)]
        fn hold_exclusively(path: &Path) -> fs::File {
            use std::os::windows::fs::OpenOptionsExt;

            OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(path)
                .unwrap()
        }

        #[cfg(windows)]
        fn make_junction(link: &Path, destination: &Path) {
            let status = std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(destination)
                .output()
                .unwrap();

            assert!(status.status.success(), "could not create a test junction");
        }

        /// An unlocked session with a published binding and an (initially
        /// absent) target file. `session` is declared first so that it (and its
        /// exclusive lock file) drops before the scratch directory is removed.
        struct Fx {
            session: UnlockedVaultSession,
            root: SyncStateRoot,
            target: SyncFileTarget,
            vault: PathBuf,
            remote: PathBuf,
            local: String,
            vault_id: Uuid,
            state: SyncState,
            dir: tempfile::TempDir,
        }

        impl Fx {
            /// Based at high-water 5 (synced revision 1), no pending push.
            fn new(name: &str) -> Self {
                Self::with(name, |local, vault_id, target| {
                    state_with(local, vault_id, target, checkpoint(5), None)
                })
            }

            fn with(name: &str, make: impl FnOnce(&str, Uuid, &str) -> SyncState) -> Self {
                let dir = scratch(name);
                let vaults = dir.path().join("vaults");
                let remote_dir = dir.path().join("remote");

                fs::create_dir_all(&vaults).unwrap();
                fs::create_dir_all(&remote_dir).unwrap();

                let vault = vaults.join("vault.lvault");
                let remote = remote_dir.join("target.lvault");

                let session = UnlockedVaultSession::create(&vault, password(), NOW_MS).unwrap();
                let vault_id = session.data().vault_id;
                let local = normalize_existing_vault_path(&vault).unwrap();
                let target = SyncFileTarget::from_path(&remote).unwrap();
                let state = make(&local, vault_id, target.locator().as_str());
                let root = SyncStateRoot::for_test(dir.path().join("app-local"));

                SyncStateStore::new(root.path())
                    .unwrap()
                    .create(&state)
                    .unwrap();

                Self {
                    session,
                    root,
                    target,
                    vault,
                    remote,
                    local,
                    vault_id,
                    state,
                    dir,
                }
            }

            fn vaults_dir(&self) -> PathBuf {
                self.vault.parent().unwrap().to_path_buf()
            }

            fn remote_dir(&self) -> PathBuf {
                self.remote.parent().unwrap().to_path_buf()
            }

            fn candidates_dir(&self) -> PathBuf {
                self.dir.path().join("candidates")
            }

            fn state_dir(&self) -> PathBuf {
                self.root.path().join(SYNC_STATE_DIRECTORY)
            }

            /// The single state record file.
            fn record(&self) -> PathBuf {
                let found: Vec<PathBuf> = fs::read_dir(self.state_dir())
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                    .collect();

                assert_eq!(found.len(), 1);

                found.into_iter().next().unwrap()
            }

            fn record_bytes(&self) -> Vec<u8> {
                fs::read(self.record()).unwrap()
            }

            fn put_remote(&self, bytes: &[u8]) {
                fs::write(&self.remote, bytes).unwrap();
            }

            fn loaded(&self) -> SyncState {
                match self.session.load_sync_state(&self.root) {
                    SessionSyncState::Bound(bound) => bound.state().clone(),
                    other => panic!("expected a bound state, got {other:?}"),
                }
            }

            /// Genuine envelope bytes of this vault advanced to `revision` by real
            /// committed writes on a copy (the original is never touched). The
            /// copy's plaintext carries a marker no output may show.
            fn candidate(&self, name: &str, revision: u64) -> Vec<u8> {
                let candidates = self.candidates_dir();

                fs::create_dir_all(&candidates).unwrap();

                let path = candidates.join(format!("{name}.lvault"));

                fs::copy(&self.vault, &path).unwrap();

                let mut copy = UnlockedVaultSession::unlock(&path, password()).unwrap();
                let mut n: i64 = 0;

                while copy.data().revision < revision {
                    n += 1;

                    copy.create_category(
                        CategoryInput {
                            name: format!("LEAKMARK-PLAINTEXT-{n}"),
                        },
                        NOW_MS + n,
                    )
                    .unwrap();
                }

                assert_eq!(copy.data().revision, revision);

                copy.lock();

                fs::read(&path).unwrap()
            }

            fn observe(&self) -> Result<Outcome, RemoteTargetRefusal> {
                self.session.observe_remote_target(&self.root, &self.target)
            }

            /// Observe `target` and count how many times the read step ran.
            fn observe_counting(
                &self,
                target: &SyncFileTarget,
            ) -> (Result<Outcome, RemoteTargetRefusal>, usize) {
                let reads = Cell::new(0usize);

                let result = self
                    .session
                    .observe_remote_target_with(&self.root, target, |t| {
                        reads.set(reads.get() + 1);

                        t.read()
                    });

                (result, reads.get())
            }

            /// Assert the refusal happened before the target was read and left the
            /// state directory exactly as it was.
            fn assert_refused_unread(&self, expected: Obs) {
                let before = snapshot(&self.state_dir());

                let (result, reads) = self.observe_counting(&self.target);

                assert_eq!(result, refused(expected));
                assert_eq!(reads, 0, "the target was read before the check");
                assert_eq!(snapshot(&self.state_dir()), before);
            }
        }

        // 1, 2. A higher authenticated file raises the mark; a fresh read keeps it.
        #[test]
        fn a_higher_authenticated_file_raises_the_mark_and_a_fresh_read_keeps_it() {
            let fx = Fx::new("b1e-raised");
            let candidate = fx.candidate("rev9", 9);

            fx.put_remote(&candidate);

            let vaults_before = snapshot(&fx.vaults_dir());
            let remote_before = snapshot(&fx.remote_dir());
            let candidates_before = snapshot(&fx.candidates_dir());

            assert_eq!(fx.observe(), Ok(Outcome::HighWaterRaised));

            let expected = rebuilt(&fx.state, checkpoint(9), None);

            assert_eq!(fx.record_bytes(), expected.encode().unwrap());
            assert_eq!(names(&fx.state_dir()).len(), 1, "no staging file is left");

            // A fresh, independent load sees the retained mark.
            let reloaded = fx.loaded();

            assert_eq!(reloaded, expected);

            // Only the mark moved: the synchronized baseline did not.
            let (SyncBase::Based(old), SyncBase::Based(new)) = (fx.state.base(), reloaded.base())
            else {
                panic!("expected based states");
            };

            assert_eq!(new.high_water().revision(), 9);
            assert_eq!(new.synced(), old.synced());
            assert_eq!(new.synced_revision(), old.synced_revision());
            assert!(reloaded.pending_push().is_none());

            // The file, the vault and the candidates were only read.
            assert_eq!(snapshot(&fx.vaults_dir()), vaults_before);
            assert_eq!(snapshot(&fx.remote_dir()), remote_before);
            assert_eq!(snapshot(&fx.candidates_dir()), candidates_before);

            // A later, fresh operation starts from the retained value.
            let state_before = snapshot(&fx.state_dir());

            assert_eq!(fx.observe(), Ok(Outcome::Unchanged));
            assert_eq!(snapshot(&fx.state_dir()), state_before);

            fx.put_remote(&fx.candidate("rev7", 7));

            assert_eq!(
                fx.observe(),
                refused(Obs::KnownRegression),
                "the mark never goes down"
            );
        }

        #[test]
        fn the_raised_mark_survives_closing_and_reopening_the_session() {
            let fx = Fx::new("b1e-reopen");

            fx.put_remote(&fx.candidate("rev9", 9));

            assert_eq!(fx.observe(), Ok(Outcome::HighWaterRaised));

            let Fx {
                session,
                root,
                target,
                vault,
                dir,
                ..
            } = fx;

            session.lock();

            let reopened = UnlockedVaultSession::unlock(&vault, password()).unwrap();

            assert_eq!(
                reopened.observe_remote_target(&root, &target),
                Ok(Outcome::Unchanged)
            );

            drop(reopened);
            drop(dir);
        }

        // 3, 4. Equal and lower authenticated revisions rewrite nothing.
        #[test]
        fn an_equal_revision_is_unchanged_and_rewrites_nothing() {
            let fx = Fx::new("b1e-equal");

            fx.put_remote(&fx.candidate("rev5", 5));

            let before = snapshot(&fx.state_dir());

            assert_eq!(fx.observe(), Ok(Outcome::Unchanged));

            // Same bytes and same modification time: not even rewritten
            // identically.
            assert_eq!(snapshot(&fx.state_dir()), before);
            assert_eq!(fx.record_bytes(), fx.state.encode().unwrap());
        }

        #[test]
        fn a_lower_revision_is_a_known_regression_that_changes_nothing() {
            let fx = Fx::new("b1e-regression");

            fx.put_remote(&fx.candidate("rev3", 3));

            let before = snapshot(&fx.state_dir());

            assert_eq!(fx.observe(), refused(Obs::KnownRegression));
            assert_eq!(snapshot(&fx.state_dir()), before);
            assert_eq!(fx.loaded(), fx.state);
        }

        // 5. A target other than the retained one is refused before it is read.
        #[test]
        fn a_target_other_than_the_retained_one_is_refused_before_it_is_read() {
            let fx = Fx::new("b1e-wrong-target");
            let candidate = fx.candidate("rev9", 9);

            // The retained target holds a genuine higher candidate too; so does a
            // second, unbound file. Only the bound locator may ever be read.
            fx.put_remote(&candidate);

            let other = fx.remote_dir().join("other.lvault");

            fs::write(&other, &candidate).unwrap();

            let remote_text = fx.remote.to_str().unwrap().to_owned();
            let lowered = remote_text.to_ascii_lowercase();

            assert_ne!(lowered, remote_text, "the case variant must differ");

            let before = snapshot(&fx.state_dir());
            let remote_before = snapshot(&fx.remote_dir());

            for wrong in [
                other,
                PathBuf::from(lowered),
                PathBuf::from(remote_text + "x"),
            ] {
                let wrong = SyncFileTarget::from_path(&wrong).unwrap();
                let (result, reads) = fx.observe_counting(&wrong);

                assert_eq!(
                    result,
                    refused(Obs::BindingMismatch(BindingMismatch::TargetLocator))
                );
                assert_eq!(reads, 0, "an unbound target was read");
                assert_eq!(snapshot(&fx.state_dir()), before);
            }

            assert_eq!(snapshot(&fx.remote_dir()), remote_before);

            // Control: the retained target itself is read once and accepted.
            let (result, reads) = fx.observe_counting(&fx.target);

            assert_eq!(result, Ok(Outcome::HighWaterRaised));
            assert_eq!(reads, 1);
        }

        // 6. A record for another vault identity is refused before the read.
        #[test]
        fn a_record_for_another_vault_identity_is_refused_before_the_read() {
            let fx = Fx::with("b1e-wrong-vault", |local, _, target| {
                state_with(local, OTHER_VAULT_ID, target, checkpoint(5), None)
            });

            assert_ne!(fx.vault_id, OTHER_VAULT_ID);

            fx.put_remote(&fx.candidate("rev9", 9));
            fx.assert_refused_unread(Obs::BindingMismatch(BindingMismatch::VaultIdentity));
        }

        // 7. No record: refused, no read, nothing created.
        #[test]
        fn a_missing_record_is_refused_before_the_read_and_nothing_is_created() {
            let fx = Fx::new("b1e-missing-record");

            fx.put_remote(&fx.candidate("rev9", 9));

            // The state directory exists but holds no record.
            fs::remove_file(fx.record()).unwrap();
            fx.assert_refused_unread(Obs::NotConfigured);
            assert!(names(&fx.state_dir()).is_empty());

            // First use: not even the application-data root exists.
            fs::remove_dir_all(fx.root.path()).unwrap();

            let (result, reads) = fx.observe_counting(&fx.target);

            assert_eq!(result, refused(Obs::NotConfigured));
            assert_eq!(reads, 0);
            assert!(!fx.root.path().exists());
        }

        // 8, 9. Corrupt and unsupported records are refused before the read.
        #[test]
        fn corrupt_and_unsupported_records_are_refused_before_the_read() {
            let fx = Fx::new("b1e-unusable-record");
            let record = fx.record();

            fx.put_remote(&fx.candidate("rev9", 9));

            let check = |bytes: &[u8], expected: Obs| {
                fs::write(&record, bytes).unwrap();
                fx.assert_refused_unread(expected);
                assert_eq!(fs::read(&record).unwrap(), bytes);
                assert_eq!(names(&fx.state_dir()).len(), 1);
            };

            check(
                b"this is not a sync state",
                Obs::Corrupt(CorruptReason::Undecodable),
            );
            check(b"", Obs::Corrupt(CorruptReason::Empty));
            check(
                &state_with(
                    OTHER_LOCAL,
                    fx.vault_id,
                    fx.target.locator().as_str(),
                    checkpoint(5),
                    None,
                )
                .encode()
                .unwrap(),
                Obs::Corrupt(CorruptReason::LocatorMismatch),
            );
            check(
                &tampered(&fx.state, |value| {
                    value["version"] = serde_json::json!(2);
                    value["added_in_v2"] = serde_json::json!(true);
                }),
                Obs::UnsupportedVersion,
            );
        }

        // 10. An unreadable state is refused before the read, never as absent.
        #[test]
        fn an_unreadable_state_is_refused_before_the_read() {
            let fx = Fx::new("b1e-unreadable-record");

            fx.put_remote(&fx.candidate("rev9", 9));

            #[cfg(windows)]
            {
                let original = fx.record_bytes();
                let before = snapshot(&fx.state_dir());
                let guard = hold_exclusively(&fx.record());
                let (result, reads) = fx.observe_counting(&fx.target);

                assert!(
                    matches!(
                        result,
                        Err(RemoteTargetRefusal::Observation(Obs::Unreadable(
                            UnreadableReason::Io(_)
                        )))
                    ),
                    "got {result:?}"
                );
                assert_eq!(reads, 0);

                drop(guard);

                assert_eq!(snapshot(&fx.state_dir()), before);
                assert_eq!(fx.record_bytes(), original);
            }

            // An interrupted-write artifact without a record.
            let record = fx.record();
            let stem = record.file_stem().unwrap().to_str().unwrap().to_owned();
            let artifact = fx.state_dir().join(format!("{stem}.{STALE_TOKEN}.tmp"));

            fs::remove_file(&record).unwrap();
            fs::write(&artifact, b"debris").unwrap();

            fx.assert_refused_unread(Obs::Unreadable(UnreadableReason::UnresolvedArtifacts));

            assert_eq!(fs::read(&artifact).unwrap(), b"debris");
            assert!(!record.exists());
        }

        // 11, 21. A local miss is distinct, changes nothing and creates no state.
        #[test]
        fn a_missing_target_in_a_valid_directory_is_absent_on_disk_and_changes_nothing() {
            let fx = Fx::new("b1e-absent");
            let before = snapshot(&fx.state_dir());
            let vaults_before = snapshot(&fx.vaults_dir());

            assert!(!fx.remote.exists());
            assert_eq!(fx.observe(), Err(RemoteTargetRefusal::AbsentOnDisk));

            assert_eq!(snapshot(&fx.state_dir()), before);
            assert_eq!(fx.record_bytes(), fx.state.encode().unwrap());
            assert_eq!(snapshot(&fx.vaults_dir()), vaults_before);
            assert!(!fx.remote.exists(), "the observation created the target");

            // Not even a pending push or the mark is touched: it is simply not a
            // result, and a later retry is the caller's explicit decision.
            assert_eq!(fx.loaded(), fx.state);
        }

        #[test]
        fn a_local_miss_never_creates_a_record() {
            let fx = Fx::new("b1e-absent-no-record");

            // No record at all and no root: refused before the target is even
            // consulted, and nothing is created for the absent file.
            fs::remove_dir_all(fx.root.path()).unwrap();

            let (result, reads) = fx.observe_counting(&fx.target);

            assert_eq!(result, refused(Obs::NotConfigured));
            assert_eq!(reads, 0);
            assert!(!fx.root.path().exists());
            assert!(!fx.remote.exists());
        }

        // 12. An inaccessible target is unavailable, not absent.
        #[cfg(windows)]
        #[test]
        fn an_inaccessible_target_is_unavailable_and_changes_nothing() {
            let fx = Fx::new("b1e-inaccessible");
            let candidate = fx.candidate("rev9", 9);

            fx.put_remote(&candidate);

            let before = snapshot(&fx.state_dir());
            let guard = hold_exclusively(&fx.remote);

            let result = fx.observe();

            assert!(
                matches!(
                    result,
                    Err(RemoteTargetRefusal::TargetUnavailable(
                        UnavailableReason::Io(_)
                    ))
                ),
                "got {result:?}"
            );
            assert_eq!(snapshot(&fx.state_dir()), before);

            drop(guard);

            // Nothing retried by itself; an explicit later call simply works.
            assert_eq!(snapshot(&fx.state_dir()), before);
            assert_eq!(fx.observe(), Ok(Outcome::HighWaterRaised));
        }

        // 13. A directory or junction target is unavailable.
        #[test]
        fn a_directory_target_is_unavailable_and_changes_nothing() {
            let fx = Fx::new("b1e-directory");
            let before = snapshot(&fx.state_dir());

            fs::create_dir(&fx.remote).unwrap();

            assert_eq!(
                fx.observe(),
                Err(RemoteTargetRefusal::TargetUnavailable(
                    UnavailableReason::UnexpectedObject
                ))
            );
            assert_eq!(snapshot(&fx.state_dir()), before);
            assert!(fx.remote.is_dir());
        }

        #[cfg(windows)]
        #[test]
        fn a_junction_target_is_unavailable_and_is_not_followed() {
            let fx = Fx::new("b1e-junction");
            let candidate = fx.candidate("rev9", 9);
            let elsewhere = fx.dir.path().join("elsewhere");

            fs::create_dir(&elsewhere).unwrap();
            fs::write(elsewhere.join("inner.lvault"), &candidate).unwrap();
            make_junction(&fx.remote, &elsewhere);

            let before = snapshot(&fx.state_dir());
            let elsewhere_before = snapshot(&elsewhere);

            assert_eq!(
                fx.observe(),
                Err(RemoteTargetRefusal::TargetUnavailable(
                    UnavailableReason::UnexpectedObject
                ))
            );
            assert_eq!(snapshot(&fx.state_dir()), before);
            assert_eq!(snapshot(&elsewhere), elsewhere_before);
        }

        // 14. Empty and oversized files are unavailable, never absent, never a mark.
        #[test]
        fn empty_and_oversized_targets_are_unavailable_and_raise_nothing() {
            let fx = Fx::new("b1e-empty-oversized");
            let before = snapshot(&fx.state_dir());

            fx.put_remote(b"");

            assert_eq!(
                fx.observe(),
                Err(RemoteTargetRefusal::TargetUnavailable(
                    UnavailableReason::Empty
                ))
            );

            fx.put_remote(&vec![0u8; MAX_ENVELOPE_BYTES + 1]);

            assert_eq!(
                fx.observe(),
                Err(RemoteTargetRefusal::TargetUnavailable(
                    UnavailableReason::TooLarge
                ))
            );

            assert_eq!(snapshot(&fx.state_dir()), before);
            assert_eq!(fx.loaded(), fx.state);
        }

        // 15. A candidate that does not authenticate is refused by B1c/core.
        #[test]
        fn a_file_that_does_not_authenticate_as_this_vault_is_refused() {
            let fx = Fx::new("b1e-bad-candidate");
            let genuine = fx.candidate("rev9", 9);
            let before = snapshot(&fx.state_dir());

            let malformed = refused(Obs::Inspection(BoundInspectionError::MalformedEnvelope {
                input: EnvelopeInput::Candidate,
            }));
            let unauthenticated = refused(Obs::Inspection(BoundInspectionError::Inspection(
                InspectionError::Candidate(PayloadRejection::AuthenticationFailed),
            )));

            fx.put_remote(b"{\"revision\": 99}");
            assert_eq!(fx.observe(), malformed);

            fx.put_remote(&genuine[..genuine.len() / 2]);
            assert_eq!(fx.observe(), malformed);

            // A genuine envelope whose ciphertext was altered: the revision inside
            // it cannot be forged without the key.
            let mut value: serde_json::Value = serde_json::from_slice(&genuine).unwrap();
            let first = value["payload"]["ciphertext"][0].as_u64().unwrap();

            value["payload"]["ciphertext"][0] = serde_json::json!((first + 1) % 256);
            fx.put_remote(&serde_json::to_vec(&value).unwrap());
            assert_eq!(fx.observe(), unauthenticated);

            // Another vault, with another key.
            let foreign_path = fx.dir.path().join("foreign").join("other.lvault");
            let foreign = UnlockedVaultSession::create(
                &foreign_path,
                Zeroizing::new("another-password-entirely".to_owned()),
                NOW_MS,
            )
            .unwrap();

            fx.put_remote(&fs::read(&foreign_path).unwrap());
            assert_eq!(fx.observe(), unauthenticated);
            drop(foreign);

            assert_eq!(snapshot(&fx.state_dir()), before);
            assert_eq!(fx.loaded(), fx.state);
        }

        // 16. A pending push or an unbased state blocks every observation.
        #[test]
        fn a_pending_push_or_an_unbased_state_blocks_the_observation() {
            let pending = Fx::with("b1e-pending", |local, vault_id, target| {
                state_with(
                    local,
                    vault_id,
                    target,
                    checkpoint(5),
                    Some(pending_push(6)),
                )
            });

            pending.put_remote(&pending.candidate("rev9", 9));

            let before = snapshot(&pending.state_dir());

            assert_eq!(
                pending.observe(),
                refused(Obs::Transition(TransitionRefusal::PendingIntentExists))
            );
            assert_eq!(snapshot(&pending.state_dir()), before);
            assert!(pending.loaded().pending_push().is_some());

            let unbased = Fx::with("b1e-unbased", |local, vault_id, target| {
                state_with(
                    local,
                    vault_id,
                    target,
                    SyncBase::Unbased,
                    Some(
                        PendingPush::new(
                            INTENT,
                            PushIntent::new(PushBaseline::Absent, fp(2)).unwrap(),
                            1,
                        )
                        .unwrap(),
                    ),
                )
            });

            unbased.put_remote(&unbased.candidate("rev9", 9));

            let before = snapshot(&unbased.state_dir());

            assert_eq!(
                unbased.observe(),
                refused(Obs::Transition(TransitionRefusal::NotBased))
            );
            assert_eq!(snapshot(&unbased.state_dir()), before);
        }

        // 17. A replaced or deleted local primary is refused.
        #[test]
        fn a_vault_file_that_is_not_the_unlocked_one_is_refused() {
            let fx = Fx::new("b1e-vault-changed");

            fx.put_remote(&fx.candidate("rev9", 9));

            // Replaced by a non-cooperating writer.
            let replacement = create_envelope(PASSWORD, b"external replacement").unwrap();

            save_envelope_atomic(&fx.vault, &replacement).unwrap();
            fx.assert_refused_unread(Obs::Unavailable(SyncStateUnavailable::LocalVaultChanged));

            // Deleted.
            fs::remove_file(&fx.vault).unwrap();
            fx.assert_refused_unread(Obs::Unavailable(SyncStateUnavailable::LocalVaultChanged));
        }

        #[test]
        fn a_primary_replaced_during_the_read_is_caught_by_the_repeated_verification() {
            let fx = Fx::new("b1e-vault-changed-mid-read");

            fx.put_remote(&fx.candidate("rev9", 9));

            let before = snapshot(&fx.state_dir());
            let vault = fx.vault.clone();
            let reads = Cell::new(0usize);

            let result = fx
                .session
                .observe_remote_target_with(&fx.root, &fx.target, |target| {
                    reads.set(reads.get() + 1);

                    // After the binding check, before the observation is recorded.
                    let replacement = create_envelope(PASSWORD, b"external replacement").unwrap();

                    save_envelope_atomic(&vault, &replacement).unwrap();

                    target.read()
                });

            assert_eq!(reads.get(), 1);
            assert_eq!(
                result,
                refused(Obs::Unavailable(SyncStateUnavailable::LocalVaultChanged))
            );
            assert_eq!(snapshot(&fx.state_dir()), before);
            assert_eq!(fx.record_bytes(), fx.state.encode().unwrap());
        }

        // 19. The exclusive session lock is held across the read and afterwards.
        #[test]
        fn the_session_lock_is_held_across_the_read() {
            let fx = Fx::new("b1e-lock");

            fx.put_remote(&fx.candidate("rev9", 9));

            let vault = fx.vault.clone();
            let probed = Cell::new(0u8);

            let result = fx
                .session
                .observe_remote_target_with(&fx.root, &fx.target, |target| {
                    // From inside the operation, between the binding check and
                    // the observation: another session must be refused.
                    let attempt = UnlockedVaultSession::unlock(&vault, password());

                    probed.set(if matches!(attempt, Err(SessionError::InUse)) {
                        1
                    } else {
                        2
                    });

                    target.read()
                });

            assert_eq!(result, Ok(Outcome::HighWaterRaised));
            assert_eq!(probed.get(), 1, "the lock was not held during the read");

            // Still held afterwards, released only by dropping the session.
            assert!(matches!(
                UnlockedVaultSession::unlock(&fx.vault, password()),
                Err(SessionError::InUse)
            ));
        }

        // 20. No outcome writes the target, the vault, its backup or a candidate.
        #[test]
        fn no_outcome_writes_the_target_the_vault_its_backup_or_a_candidate() {
            let fx = Fx::new("b1e-no-writes");
            let low = fx.candidate("rev3", 3);
            let same = fx.candidate("rev5", 5);
            let high = fx.candidate("rev8", 8);
            let backup = PathBuf::from(format!("{}.backup", fx.vault.display()));

            assert!(!backup.exists());

            let vaults_before = snapshot(&fx.vaults_dir());
            let candidates_before = snapshot(&fx.candidates_dir());

            fx.put_remote(&low);
            let remote_low = snapshot(&fx.remote_dir());
            assert_eq!(fx.observe(), refused(Obs::KnownRegression));
            assert_eq!(snapshot(&fx.remote_dir()), remote_low);

            fx.put_remote(&same);
            let remote_same = snapshot(&fx.remote_dir());
            assert_eq!(fx.observe(), Ok(Outcome::Unchanged));
            assert_eq!(snapshot(&fx.remote_dir()), remote_same);

            fx.put_remote(&high);
            let remote_high = snapshot(&fx.remote_dir());
            assert_eq!(fx.observe(), Ok(Outcome::HighWaterRaised));
            assert_eq!(snapshot(&fx.remote_dir()), remote_high);

            // The mark is monotone: values acceptable before are now behind it.
            fx.put_remote(&same);
            assert_eq!(fx.observe(), refused(Obs::KnownRegression));
            fx.put_remote(&high);
            assert_eq!(fx.observe(), Ok(Outcome::Unchanged));
            fx.put_remote(b"garbage");
            assert!(fx.observe().is_err());

            assert_eq!(snapshot(&fx.vaults_dir()), vaults_before);
            assert_eq!(snapshot(&fx.candidates_dir()), candidates_before);
            assert!(!backup.exists());
            assert!(!fx.session.is_dirty());

            // The binding is intact: same identity, checkpoint kept, mark at 8.
            assert_eq!(fx.loaded(), rebuilt(&fx.state, checkpoint(8), None));
        }

        // 22. Neither outcomes nor errors reveal a path, identifier or content.
        #[test]
        fn outcomes_and_errors_reveal_no_path_identifier_or_content() {
            let fx = Fx::new("b1e-no-leak");
            let up = fx.candidate("rev9", 9);
            let down = fx.candidate("rev3", 3);
            let mut shown: Vec<String> = Vec::new();

            let mut note = |result: Result<Outcome, RemoteTargetRefusal>| {
                shown.push(format!("{result:?}"));

                if let Err(error) = result {
                    shown.push(error.to_string());

                    let mut source = error.source();

                    while let Some(inner) = source {
                        shown.push(inner.to_string());
                        shown.push(format!("{inner:?}"));
                        source = inner.source();
                    }
                }
            };

            note(fx.observe()); // absent on disk
            fx.put_remote(&down);
            note(fx.observe()); // regression
            fx.put_remote(&up);
            note(fx.observe()); // raised
            note(fx.observe()); // unchanged
            fx.put_remote(b"garbage");
            note(fx.observe()); // malformed
            fx.put_remote(b"");
            note(fx.observe()); // unavailable
            note(Err(RemoteTargetRefusal::TargetUnavailable(
                UnavailableReason::Io(io::ErrorKind::PermissionDenied),
            )));
            note(refused(Obs::PersistenceUnverified));
            note(refused(Obs::Unavailable(
                SyncStateUnavailable::LocalLocator,
            )));

            let fingerprint = |bytes: &[u8]| EnvelopeFingerprint::of_bytes(bytes).to_hex();
            let prefix = String::from_utf8_lossy(&up[..48.min(up.len())]).into_owned();

            let needles = vec![
                fx.dir.path().to_string_lossy().into_owned(),
                fx.remote.to_string_lossy().into_owned(),
                fx.target.locator().as_str().to_owned(),
                fx.local.clone(),
                fx.vault_id.to_string(),
                fx.vault_id.simple().to_string(),
                BINDING.to_string(),
                "target.lvault".to_owned(),
                "vault.lvault".to_owned(),
                ".qa-local".to_owned(),
                "LEAKMARK".to_owned(),
                PASSWORD.to_owned(),
                fingerprint(&up),
                fingerprint(&down),
                fingerprint(&fs::read(&fx.vault).unwrap()),
                prefix,
            ];

            assert!(shown.len() > 8);

            for output in &shown {
                for needle in &needles {
                    assert!(
                        !output.contains(needle.as_str()),
                        "leaks {needle:?}: {output}"
                    );
                }
            }
        }

        // 23. The raw-bytes B1c operation is unchanged, and the file path ends in
        // the very same persisted state.
        #[test]
        fn the_raw_bytes_operation_is_unchanged_and_persists_the_same_state() {
            let via_file = Fx::new("b1e-same-via-file");
            let via_raw = Fx::new("b1e-same-via-raw");

            via_file.put_remote(&via_file.candidate("rev9", 9));

            let raw = via_raw.candidate("rev9", 9);

            assert_eq!(via_file.observe(), Ok(Outcome::HighWaterRaised));
            assert_eq!(
                via_raw.session.record_remote_observation(
                    &via_raw.root,
                    via_raw.target.locator(),
                    &raw
                ),
                Ok(Outcome::HighWaterRaised)
            );

            assert_eq!(
                via_file.record_bytes(),
                rebuilt(&via_file.state, checkpoint(9), None)
                    .encode()
                    .unwrap()
            );
            assert_eq!(
                via_raw.record_bytes(),
                rebuilt(&via_raw.state, checkpoint(9), None)
                    .encode()
                    .unwrap()
            );

            // The raw operation still checks the target itself, as before.
            assert_eq!(
                via_raw
                    .session
                    .record_remote_observation(&via_raw.root, &loc(OTHER_LOCAL), &raw),
                Err(Obs::BindingMismatch(BindingMismatch::TargetLocator))
            );
        }

        #[test]
        fn the_read_runs_exactly_once_and_only_after_the_binding_is_confirmed() {
            let fx = Fx::new("b1e-read-once");

            fx.put_remote(&fx.candidate("rev9", 9));

            let (result, reads) = fx.observe_counting(&fx.target);

            assert_eq!(result, Ok(Outcome::HighWaterRaised));
            assert_eq!(reads, 1);
        }
    }
}
