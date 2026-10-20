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
        bind_identical_remote, record_remote_observation, BindingMismatch, HighWaterOutcome,
        Locator, NewBinding, RemoteEvidence, SyncBase, SyncState, SyncStateLoad, TransitionRefusal,
        UserApproval, BINDING_SALT_LEN,
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

/// Typed proof-of-consent that [`UnlockedVaultSession::bind_existing_identical_target`]
/// requires, bound to exactly one target.
///
/// # This is not a confirmation, and nothing can currently produce one
///
/// **No user-confirmation flow exists yet.** There is no UI, command or event
/// that asks the user whether this vault may be bound to a chosen file, and
/// therefore nothing in production that may honestly claim "the user approved".
/// For that reason this type has **no production constructor**: its field is
/// private, it has no `Default`, `Clone`, `Copy` or `From`, and the only way to
/// build one is the `#[cfg(test)]` helper below. In a production build the
/// binding operation is consequently unreachable, by construction and not by
/// convention. A boolean or an enum that any caller could set to "granted" would
/// have claimed a confirmation that never happened; this does not.
///
/// A later slice that adds the real confirmation (a dialog the user can see,
/// naming the vault and the target, answered by a deliberate action) must add the
/// production constructor, and it must live in this module because the field is
/// private. It must take as its input a value that only that confirmation
/// handler can produce, tie the approval to that one answer, and be consumed by
/// a single call. It must not be a general "trusted" constructor that any caller
/// in the crate could use. Passing this value is a precondition, never evidence
/// that a confirmation was shown; only the code that builds it can make that
/// true.
///
/// The value is single-use (consumed by the operation), is bound to the target
/// locator it was made for (an approval for one file cannot be spent on
/// another), and is not shown by `Debug`.
#[must_use = "an approval is consumed by the binding operation"]
pub struct InitialBindingApproval {
    target: Locator,
}

impl InitialBindingApproval {
    /// Test-only. Not a model of any real confirmation: it exists so the
    /// operation's behavior can be exercised before a confirmation flow exists.
    #[cfg(test)]
    pub(crate) fn for_test(target: &SyncFileTarget) -> Self {
        Self {
            target: target.locator().clone(),
        }
    }

    fn target(&self) -> &Locator {
        &self.target
    }

    /// The approval the accepted core transition understands. Consumes `self`,
    /// so the only way to obtain `Granted` is to hold (and spend) this value.
    fn into_core(self) -> UserApproval {
        UserApproval::Granted
    }
}

impl std::fmt::Debug for InitialBindingApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InitialBindingApproval(<redacted>)")
    }
}

/// What a successful [`UnlockedVaultSession::bind_existing_identical_target`]
/// established. Fieldless on purpose: no revision, fingerprint, identifier or
/// path.
///
/// It means: a new sync-state record was published, read back
/// byte-identically by the store, and then loaded again by a fresh read that
/// equalled the proposed state and passed the authenticated binding check. It
/// does **not** mean any synchronization happened, that the target is fresh, or
/// that a cloud provider has anything to do with the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum InitialBindingOutcome {
    BoundAndVerified,
}

/// Why no initial binding was confirmed. Fixed categories only: no path,
/// locator, identifier, fingerprint, revision, key or file content, in `Debug`
/// or `Display`.
///
/// Every variant except [`PersistenceUnverified`](Self::PersistenceUnverified)
/// leaves the sync-state directory as it was: the record was definitely not
/// published by this call. After `PersistenceUnverified` the record may or may
/// not exist, and nothing is retried, deleted or reset: any later decision must
/// start with a fresh load. A refusal never resets, repairs or adopts an
/// existing record, never writes the target, the vault or its backup, and never
/// treats the target's absence as authority to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InitialBindingRefusal {
    /// The session's own vault or location cannot serve as the binding anchor.
    #[error("the session's vault or sync-state location is unavailable")]
    Unavailable(SyncStateUnavailable),
    /// The approval was made for a different target than the one supplied.
    #[error("the approval does not belong to this target")]
    ApprovalTargetMismatch,
    /// A valid record for this vault and location already exists. Never
    /// replaced; rebinding needs an explicit reset that this operation is not.
    #[error("a synchronization binding already exists")]
    ExistingBinding,
    /// A readable record exists but belongs to a different vault, or to a
    /// different location. Left untouched and never adopted.
    #[error("a synchronization record for a different binding exists")]
    ExistingBindingMismatch(BindingMismatch),
    #[error("the synchronization binding record is corrupt")]
    Corrupt(CorruptReason),
    #[error("the synchronization binding record has an unsupported version")]
    UnsupportedVersion,
    /// Includes a stale recovery artifact: absence was not confirmed.
    #[error("the synchronization binding record could not be read")]
    Unreadable(UnreadableReason),
    /// The target is, or cannot be shown not to be, this vault's own primary
    /// file, its `.backup`, its `.lock` file or a file inside the sync-state
    /// directory. This is a path-level check; see the operation's limits.
    #[error("the target names a file that belongs to this vault or its sync state")]
    TargetIsVaultFile,
    /// Not found in a valid local folder. **Not** remote absence, never an
    /// authorization to publish, and never creates anything.
    #[error("the target file was not found in the local folder")]
    TargetAbsentOnDisk,
    #[error("the target file could not be read")]
    TargetUnavailable(UnavailableReason),
    /// The local vault file or the target changed between the inspection and
    /// the point of publication, so the evidence no longer describes what is on
    /// disk.
    #[error("the evidence changed before the binding could be published")]
    EvidenceChanged,
    /// The local reference or the target did not authenticate as this vault's
    /// envelope. Names the input at fault; carries no content.
    #[error("the envelope inspection was rejected")]
    Inspection(BoundInspectionError),
    /// Secure randomness for the binding identity was unavailable.
    #[error("secure randomness is unavailable")]
    Randomness,
    /// The accepted core transition refused (for example: not byte-identical, a
    /// legacy payload with no revision counter).
    #[error("the initial binding transition was refused")]
    Transition(TransitionRefusal),
    /// A record appeared between the check and publication. The store's
    /// no-clobber publication refused it; the other record is untouched.
    #[error("a synchronization record appeared before publication")]
    RecordAppeared,
    /// The store failed at a step that precedes publication (see
    /// `create_error_may_follow_publication`): the record was not created.
    #[error("the initial binding was not persisted")]
    NotPersisted(StoreError),
    /// The record may or may not have been published: the publication step
    /// itself failed, or the readback or the fresh reload disagreed. The
    /// persisted state is unknown until freshly loaded. Nothing is retried,
    /// deleted or reset.
    #[error("the initial binding could not be verified after writing")]
    PersistenceUnverified,
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

    /// Bind this vault to an **existing, byte-identical** encrypted file for the
    /// first time (Stage 1U-4 B1f). Internal: no command, event, UI, startup or
    /// unlock path reaches it, and in a production build nothing can: the
    /// required [`InitialBindingApproval`] has no production constructor (see its
    /// documentation). It enables no working synchronization.
    ///
    /// Supported scenario, and only this one: an existing target whose exact
    /// bytes equal the exact bytes of this session's vault file, authenticated
    /// under this session's Vault Key as this vault, at a schema-3 revision,
    /// with no sync-state record for this location. Everything else is refused:
    /// an absent target, initial publication, overwrite, import, divergence,
    /// merge, a different encryption of the same plaintext, a legacy payload, an
    /// existing record of any kind, and any rebinding.
    ///
    /// # The approval boundary
    ///
    /// The approval is a precondition, **not** evidence that a confirmation took
    /// place. No confirmation flow exists. The future UI must show the user the
    /// vault and the chosen file and obtain a deliberate explicit confirmation
    /// **before** it constructs an approval and calls this. See
    /// [`InitialBindingApproval`].
    ///
    /// # Order of operations
    ///
    /// All inside one `&self` borrow of the unlocked session, so the exclusive OS
    /// lock held by `_lock_file` is held from the first step to the last.
    ///
    /// 1. the approval must be for this target;
    /// 2. the vault file's exact current bytes must parse to precisely the
    ///    envelope this session unlocked (they become the local reference), and
    ///    the session's normalized local locator is resolved;
    /// 3. the sync-state record is loaded: only a **confirmed** `NotConfigured`
    ///    continues. A loaded record (valid or foreign), a corrupt, unsupported
    ///    or unreadable one, and an unresolved recovery artifact are refused and
    ///    left exactly as they are;
    /// 4. the target is refused if it names this vault's primary, `.backup`,
    ///    `.lock` or a file in the sync-state directory;
    /// 5. only then [`SyncFileTarget::read`] runs, and only `Present` continues:
    ///    absence on disk and unavailability are refusals, never authority to
    ///    publish;
    /// 6. `inspect_remote_bytes` authenticates both byte strings under this
    ///    session's Vault Key and the session's own authenticated `vault_id`
    ///    (never a caller, file name or the target);
    /// 7. a fresh binding id and salt are drawn from the OS CSPRNG;
    /// 8. the core `bind_identical_remote` proposes the state. It requires equal
    ///    raw fingerprints, equal schema-3 counter revisions and a confirmed
    ///    `NotConfigured`; no state is constructed by this module;
    /// 9. the local file and the target are read again and must be byte-for-byte
    ///    what was inspected;
    /// 10. `SyncStateStore::create` publishes by no-clobber hard link;
    /// 11. a fresh load must equal the proposed state and pass
    ///     `verify_binding` for this vault, both locators exactly.
    ///
    /// Only then is [`InitialBindingOutcome::BoundAndVerified`] returned. The
    /// only persistent change is the new record: the target, the vault, its
    /// `.backup` and its lock file are never written, nothing is imported or
    /// uploaded, no revision or high-water mark is changed independently of the
    /// core, and nothing retries.
    ///
    /// # Failure classes
    ///
    /// * **Definitely not published**: every refusal other than the two below.
    ///   The sync-state directory is unchanged by this call.
    /// * **Record appeared** ([`InitialBindingRefusal::RecordAppeared`]): the
    ///   no-clobber publication found another record and left it alone.
    /// * **Possibly published, unverified**
    ///   ([`InitialBindingRefusal::PersistenceUnverified`]): the publication
    ///   step or the verification failed. The record is **not** deleted, rolled
    ///   back or retried, and a possibly valid committed binding is never
    ///   downgraded. A later decision must start with a fresh load.
    ///
    /// # What a success does and does not mean
    ///
    /// * The binding is local-filesystem evidence only. No cloud provider
    ///   authority, freshness, or completed upload is established, and a path the
    ///   user chose is not shown to be a provider's copy of anything.
    /// * Byte identity and authentication prove that the target was, at that
    ///   instant, an exact copy of this vault's envelope. They prove neither that
    ///   it is the latest version nor that it will stay so.
    /// * The target check is by canonical path string (ASCII case-insensitive on
    ///   Windows). It does **not** detect a hard link, or any other second name,
    ///   for the same physical file: stable `std` exposes no file identity, so an
    ///   alias of the vault itself that sits at another path is byte-identical by
    ///   construction and would be accepted. The adapter's own length-and-timestamp
    ///   checks and the check-then-use windows documented on [`SyncFileTarget`]
    ///   also apply.
    pub fn bind_existing_identical_target(
        &self,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
        approval: InitialBindingApproval,
    ) -> Result<InitialBindingOutcome, InitialBindingRefusal> {
        let store = SyncStateStore::new(root.path())
            .map_err(|_| InitialBindingRefusal::Unavailable(SyncStateUnavailable::Root))?;

        self.bind_existing_identical_target_in(
            &store,
            target,
            approval,
            &mut SyncFileTarget::read,
            &mut |buffer| getrandom::fill(buffer).is_ok(),
        )
    }

    /// [`bind_existing_identical_target`](Self::bind_existing_identical_target)
    /// over an explicit store, read step and entropy source. Crate-private so no
    /// caller outside the crate's own tests can substitute any of them: tests use
    /// it to inject store faults, to prove the read runs only after the state
    /// and target checks and only under the session lock, and to fail randomness.
    pub(crate) fn bind_existing_identical_target_in(
        &self,
        store: &SyncStateStore,
        target: &SyncFileTarget,
        approval: InitialBindingApproval,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
        entropy: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> Result<InitialBindingOutcome, InitialBindingRefusal> {
        use InitialBindingRefusal as Refusal;

        if approval.target() != target.locator() {
            return Err(Refusal::ApprovalTargetMismatch);
        }

        let local_raw = self.current_local_raw().ok_or(Refusal::Unavailable(
            SyncStateUnavailable::LocalVaultChanged,
        ))?;

        let local_locator = self
            .local_locator()
            .ok_or(Refusal::Unavailable(SyncStateUnavailable::LocalLocator))?;

        match store.load(&local_locator) {
            StateLoad::NotConfigured => {}
            StateLoad::Loaded(state) => {
                let expected_local = effective_local_locator(&state, &local_locator);

                return Err(
                    match state.verify_binding(
                        self.data.vault_id,
                        &expected_local,
                        state.target_locator(),
                    ) {
                        Ok(()) => Refusal::ExistingBinding,
                        Err(mismatch) => Refusal::ExistingBindingMismatch(mismatch),
                    },
                );
            }
            StateLoad::Corrupt(reason) => return Err(Refusal::Corrupt(reason)),
            StateLoad::UnsupportedVersion => return Err(Refusal::UnsupportedVersion),
            StateLoad::Unreadable(reason) => return Err(Refusal::Unreadable(reason)),
        }

        if self.target_names_vault_file(store.directory(), target, &local_locator) {
            return Err(Refusal::TargetIsVaultFile);
        }

        let present = match read(target) {
            SyncFileRead::Present(present) => present,
            SyncFileRead::AbsentOnDisk => return Err(Refusal::TargetAbsentOnDisk),
            SyncFileRead::Unavailable(reason) => return Err(Refusal::TargetUnavailable(reason)),
        };

        // The adapter pairs the bytes with the locator they were read from; a
        // pairing that disagrees with the target asked for is not trusted.
        if present.target() != target.locator() {
            return Err(Refusal::EvidenceChanged);
        }

        let inspection = inspect_remote_bytes(
            &self.vault_key,
            self.data.vault_id,
            &local_raw,
            present.candidate_raw(),
            None,
        )
        .map_err(Refusal::Inspection)?;

        let mut id_bytes = [0u8; 16];
        let mut tag_salt = [0u8; BINDING_SALT_LEN];

        if !entropy(&mut id_bytes) || !entropy(&mut tag_salt) {
            return Err(Refusal::Randomness);
        }

        // Version and variant bits make the id a valid, non-nil random UUID.
        let binding_id = uuid::Builder::from_random_bytes(id_bytes).into_uuid();

        let proposed = bind_identical_remote(
            &SyncStateLoad::NotConfigured,
            approval.into_core(),
            RemoteEvidence::Inspected(&inspection),
            &NewBinding {
                binding_id,
                tag_salt,
                local_locator: &local_locator,
                target_locator: present.target(),
            },
        )
        .map_err(Refusal::Transition)?;

        // Repeat, as close to publication as the filesystem allows, the two
        // observations the proposal rests on. This narrows the window; it does
        // not close it.
        match self.current_local_raw() {
            Some(raw) if raw == local_raw => {}
            _ => {
                return Err(Refusal::Unavailable(
                    SyncStateUnavailable::LocalVaultChanged,
                ))
            }
        }

        match read(target) {
            SyncFileRead::Present(again)
                if again.target() == present.target()
                    && again.candidate_raw() == present.candidate_raw() => {}
            _ => return Err(Refusal::EvidenceChanged),
        }

        match store.create(&proposed) {
            Ok(()) => {}
            Err(StoreError::AlreadyExists) => return Err(Refusal::RecordAppeared),
            Err(error) if create_error_may_follow_publication(error) => {
                return Err(Refusal::PersistenceUnverified)
            }
            Err(error) => return Err(Refusal::NotPersisted(error)),
        }

        // A fresh, independent load must be exactly the proposal and must be
        // bound to this authenticated vault and to both locators.
        if fresh_load_confirms_binding(
            store.load(&local_locator),
            &proposed,
            self.data.vault_id,
            &local_locator,
            present.target(),
        ) {
            Ok(InitialBindingOutcome::BoundAndVerified)
        } else {
            Err(Refusal::PersistenceUnverified)
        }
    }

    /// Whether `target` names, or cannot be shown not to name, a file that
    /// belongs to this vault: its primary, `.backup` or `.lock`, or anything
    /// inside the sync-state directory.
    ///
    /// Compares canonical path strings (ASCII case-insensitive, the project's
    /// path-identity rule), so `D:\x\v.lvault` and `\\?\d:\X\V.lvault` agree. A
    /// target that does not exist cannot alias anything and is left to the read
    /// (which reports it as absent or unavailable); any other failure to resolve
    /// an existing target fails closed. This is a string-level check: it cannot
    /// see a hard link or another second name of the same file.
    fn target_names_vault_file(
        &self,
        state_directory: &Path,
        target: &SyncFileTarget,
        local_locator: &Locator,
    ) -> bool {
        if path_identity_eq(target.locator().as_str(), local_locator.as_str()) {
            return true;
        }

        let canonical_target = match fs::canonicalize(target.locator().as_str()) {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
            Err(_) => return true,
        };

        let Some(canonical_target) = canonical_target.to_str() else {
            return true;
        };

        let comparable = |path: &Path| -> Option<String> {
            match fs::canonicalize(path) {
                Ok(canonical) => canonical.to_str().map(str::to_owned),
                Err(_) => path.to_str().map(str::to_owned),
            }
        };

        let owned = [
            comparable(Path::new(local_locator.as_str())),
            comparable(&self.path),
            comparable(&self.backup_path),
            comparable(&lock_path_for(&self.path)),
        ];

        if owned.iter().any(|path| {
            path.as_deref()
                .is_none_or(|p| path_identity_eq(p, canonical_target))
        }) {
            return true;
        }

        let in_state_directory =
            Path::new(canonical_target).parent().is_some_and(|parent| {
                match (parent.to_str(), comparable(state_directory)) {
                    (Some(parent), Some(state_directory)) => {
                        path_identity_eq(parent, &state_directory)
                    }
                    _ => true,
                }
            });

        in_state_directory
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

/// Whether a `SyncStateStore::create` error could have happened at or after
/// publication. Derived from the store's own sequence: encoding, the directory,
/// the existence check, the artifact scan and temp staging (`Directory`,
/// `Inspect`, `Scan`, `Open`, `Write`, `Sync`) all fail before the hard link and
/// leave the record unpublished, and `AlreadyExists` and `NoClobberUnsupported`
/// are the link itself refusing, so nothing was created by this call. Any other
/// failure of the link (`Replace`, which `create` reports for a link error that
/// is neither of those) cannot be shown not to have published, and
/// `VerificationFailed` is by construction post-publication. The match is
/// exhaustive on purpose; an error `create` does not produce, or one that is not
/// understood, fails closed as ambiguous.
pub(crate) fn create_error_may_follow_publication(error: StoreError) -> bool {
    use super::sync_state_store::IoStage;

    match error {
        StoreError::Io {
            stage:
                IoStage::Directory
                | IoStage::Inspect
                | IoStage::Scan
                | IoStage::Open
                | IoStage::Write
                | IoStage::Sync,
            ..
        }
        | StoreError::RootNotAbsolute
        | StoreError::AlreadyExists
        | StoreError::UnresolvedArtifacts
        | StoreError::UnexpectedObject
        | StoreError::NoClobberUnsupported
        | StoreError::Encode(_) => false,

        StoreError::Io {
            stage: IoStage::Replace,
            ..
        }
        | StoreError::VerificationFailed
        | StoreError::Missing
        | StoreError::CurrentUnreadable
        | StoreError::CurrentCorrupt
        | StoreError::CurrentUnsupportedVersion
        | StoreError::CurrentLocatorMismatch
        | StoreError::Changed
        | StoreError::LocatorMismatch
        | StoreError::BindingIdentityChanged
        | StoreError::TrustedHistoryRegression
        | StoreError::IncompleteDeletion => true,
    }
}

/// Whether a fresh load confirms an initial binding: the record must be exactly
/// the proposed state **and** pass the core's `verify_binding` for the
/// authenticated vault and both locators. Anything else (no record, an
/// unreadable, corrupt or unsupported one, a different record, a mismatch) does
/// not confirm, and the caller reports the persistence as unverified.
fn fresh_load_confirms_binding(
    load: StateLoad,
    proposed: &SyncState,
    authenticated_vault_id: Uuid,
    local_locator: &Locator,
    target_locator: &Locator,
) -> bool {
    match load {
        StateLoad::Loaded(current) if *current == *proposed => {
            let expected_local = effective_local_locator(&current, local_locator);

            current
                .verify_binding(authenticated_vault_id, &expected_local, target_locator)
                .is_ok()
        }
        _ => false,
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

    // -- Stage 1U-4 B1f: initial binding to an existing identical target -------
    //
    // Real unlocked sessions, real synthetic vaults, real synthetic target files
    // and a real sync-state store, all beneath the git-ignored
    // `.qa-local/sync-state-b1-tests/` (never `%TEMP%`). The "remote" is a byte
    // copy of the vault file; every other candidate is a genuine envelope of the
    // same vault produced by the real sealing path.
    //
    // Not covered here (and not claimed):
    // * Store fault injection (the store's hooks are private to its module): the
    //   pre-publication, publication and verification failures are tested in
    //   `sync_state_store::tests`, through the same operation.
    // * The adapter's own change-during-read detection (its probe seam is private
    //   to the adapter and covered by its B1d tests); here only the session's
    //   reaction to an `Unavailable(Changed)` result and to a target that differs
    //   at the second read is exercised.
    // * A physical file symlink (needs a privilege this account lacks); a
    //   junction is exercised instead.
    // * A hard link or any other second name of the same physical file (not
    //   detectable with stable `std`; the limitation is documented, not tested).
    // * Any provider, network or cloud behavior (none exists and none is called;
    //   this cannot be asserted by a test, only by the absence of such code in
    //   the diff), the user-confirmation flow (none exists), and cross-process
    //   races.
    mod initial_binding {
        use std::{
            cell::{Cell, RefCell},
            error::Error as _,
            time::SystemTime,
        };

        use localvault_core::sync::{
            BoundInspectionError, EnvelopeFingerprint, EnvelopeInput, InspectionError,
            PayloadRejection, PushBaseline, PushIntent, RemoteHighWater, MAX_ENVELOPE_BYTES,
        };
        use localvault_core::sync_state::{
            BindingId, PendingPush, SyncCheckpoint, VaultBindingTag,
        };

        use super::*;
        use crate::vault::sync_state_store::{IoStage, SYNC_STATE_DIRECTORY};

        type Refusal = InitialBindingRefusal;
        type Outcome = InitialBindingOutcome;

        const OTHER_VAULT_ID: Uuid = Uuid::from_u128(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210);
        const BINDING: Uuid = Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555);
        const INTENT: Uuid = Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee);
        const STALE_TOKEN: &str = "0123456789abcdef0123456789abcdef";

        fn loc(value: &str) -> Locator {
            Locator::new(value).unwrap()
        }

        fn fp(tag: u8) -> EnvelopeFingerprint {
            EnvelopeFingerprint::of_bytes(&[tag])
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

        /// An unlocked session over a synthetic schema-3 vault, an application
        /// root with no sync state, and a target. `session` is declared first so
        /// that it (and its exclusive lock file) drops before the scratch
        /// directory is removed.
        struct Bx {
            session: UnlockedVaultSession,
            root: SyncStateRoot,
            target: SyncFileTarget,
            vault: PathBuf,
            remote: PathBuf,
            local: String,
            vault_id: Uuid,
            dir: tempfile::TempDir,
        }

        impl Bx {
            /// The target is a byte-for-byte copy of the vault file.
            fn new(name: &str) -> Self {
                let bx = Self::bare(name);

                fs::copy(&bx.vault, &bx.remote).unwrap();

                bx
            }

            /// The target does not exist.
            fn bare(name: &str) -> Self {
                Self::from_vault(name, |vault| {
                    UnlockedVaultSession::create(vault, test_password(), NOW_MS).unwrap()
                })
            }

            /// A legacy (schema 2, no revision) vault, unlocked, with an
            /// identical target.
            fn legacy(name: &str) -> Self {
                let bx = Self::from_vault(name, |vault| {
                    write_legacy_vault(vault, 2);

                    UnlockedVaultSession::unlock(vault, test_password()).unwrap()
                });

                fs::copy(&bx.vault, &bx.remote).unwrap();

                bx
            }

            fn from_vault(name: &str, open: impl FnOnce(&Path) -> UnlockedVaultSession) -> Self {
                let dir = scratch(name);
                let vaults = dir.path().join("vaults");
                let remote_dir = dir.path().join("remote");

                fs::create_dir_all(&vaults).unwrap();
                fs::create_dir_all(&remote_dir).unwrap();

                let vault = vaults.join("vault.lvault");
                let remote = remote_dir.join("target.lvault");

                let session = open(&vault);
                let vault_id = session.data().vault_id;
                let local = normalize_existing_vault_path(&vault).unwrap();
                let target = SyncFileTarget::from_path(&remote).unwrap();
                let root = SyncStateRoot::for_test(dir.path().join("app-local"));

                Self {
                    session,
                    root,
                    target,
                    vault,
                    remote,
                    local,
                    vault_id,
                    dir,
                }
            }

            fn vaults_dir(&self) -> PathBuf {
                self.vault.parent().unwrap().to_path_buf()
            }

            fn remote_dir(&self) -> PathBuf {
                self.remote.parent().unwrap().to_path_buf()
            }

            fn state_dir(&self) -> PathBuf {
                self.root.path().join(SYNC_STATE_DIRECTORY)
            }

            fn store(&self) -> SyncStateStore {
                SyncStateStore::new(self.root.path()).unwrap()
            }

            /// The single record file, if one exists.
            fn record(&self) -> Option<PathBuf> {
                let dir = self.state_dir();

                if !dir.exists() {
                    return None;
                }

                let mut found: Vec<PathBuf> = fs::read_dir(dir)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                    .collect();

                assert!(found.len() <= 1);

                found.pop()
            }

            fn record_bytes(&self) -> Vec<u8> {
                fs::read(self.record().expect("a record")).unwrap()
            }

            fn approval(&self) -> InitialBindingApproval {
                InitialBindingApproval::for_test(&self.target)
            }

            fn bind(&self) -> Result<Outcome, Refusal> {
                self.session.bind_existing_identical_target(
                    &self.root,
                    &self.target,
                    self.approval(),
                )
            }

            /// Bind with the real filesystem read and entropy, counting reads.
            fn bind_counting(&self, target: &SyncFileTarget) -> (Result<Outcome, Refusal>, usize) {
                let reads = Cell::new(0usize);

                let result = self.bind_with(
                    target,
                    &mut |t| {
                        reads.set(reads.get() + 1);

                        t.read()
                    },
                    &mut |buffer| getrandom::fill(buffer).is_ok(),
                );

                (result, reads.get())
            }

            fn bind_with(
                &self,
                target: &SyncFileTarget,
                read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
                entropy: &mut dyn FnMut(&mut [u8]) -> bool,
            ) -> Result<Outcome, Refusal> {
                self.session.bind_existing_identical_target_in(
                    &self.store(),
                    target,
                    InitialBindingApproval::for_test(target),
                    read,
                    entropy,
                )
            }

            /// A record for this very vault, location and target.
            fn state(&self, base: SyncBase, pending: Option<PendingPush>) -> SyncState {
                let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);

                SyncState::new(
                    BindingId::new(BINDING).unwrap(),
                    VaultBindingTag::derive(salt, self.vault_id).unwrap(),
                    loc(&self.local),
                    self.target.locator().clone(),
                    base,
                    pending,
                )
                .unwrap()
            }

            fn based(&self) -> SyncState {
                self.state(
                    SyncBase::Based(
                        SyncCheckpoint::new(fp(1), 1, RemoteHighWater::new(5)).unwrap(),
                    ),
                    None,
                )
            }

            fn publish(&self, state: &SyncState) {
                self.store().create(state).unwrap();
            }

            /// Envelope bytes of this vault with `edit` applied to the payload,
            /// sealed by the real sealing path under the real Vault Key. A fresh
            /// nonce makes them differ from the file even without an edit.
            fn resealed(&self, edit: impl FnOnce(&mut VaultData)) -> Vec<u8> {
                let mut data = self.session.data().clone();

                edit(&mut data);

                let plaintext = Zeroizing::new(serde_json::to_vec(&data).unwrap());
                let envelope = reseal_envelope(
                    &self.session.envelope,
                    &self.session.vault_key,
                    plaintext.as_slice(),
                )
                .unwrap();

                serde_json::to_vec(&envelope).unwrap()
            }

            fn put_remote(&self, bytes: &[u8]) {
                fs::write(&self.remote, bytes).unwrap();
            }

            /// Assert the refusal happened without creating or changing any
            /// sync state, and without writing the vault folder or the target
            /// folder.
            fn assert_refused(&self, expected: Refusal) {
                let vaults = snapshot(&self.vaults_dir());
                let remote = snapshot(&self.remote_dir());
                let state_existed = self.state_dir().exists();
                let state = state_existed.then(|| snapshot(&self.state_dir()));

                assert_eq!(self.bind(), Err(expected));

                assert_eq!(snapshot(&self.vaults_dir()), vaults);
                assert_eq!(snapshot(&self.remote_dir()), remote);
                assert_eq!(self.state_dir().exists(), state_existed);

                if let Some(state) = state {
                    assert_eq!(snapshot(&self.state_dir()), state);
                }
            }

            /// As [`assert_refused`](Self::assert_refused), and the target was
            /// never read.
            fn assert_refused_unread(&self, expected: Refusal) {
                let state_existed = self.state_dir().exists();
                let state = state_existed.then(|| snapshot(&self.state_dir()));

                let (result, reads) = self.bind_counting(&self.target);

                assert_eq!(result, Err(expected));
                assert_eq!(reads, 0, "the target was read before the check");
                assert_eq!(self.state_dir().exists(), state_existed);

                if let Some(state) = state {
                    assert_eq!(snapshot(&self.state_dir()), state);
                }
            }

            fn loaded(&self) -> SyncState {
                match self.session.load_sync_state(&self.root) {
                    SessionSyncState::Bound(bound) => bound.state().clone(),
                    other => panic!("expected a bound state, got {other:?}"),
                }
            }
        }

        fn transition(refusal: TransitionRefusal) -> Refusal {
            Refusal::Transition(refusal)
        }

        fn inspection(error: BoundInspectionError) -> Refusal {
            Refusal::Inspection(error)
        }

        fn candidate_rejected(reason: PayloadRejection) -> Refusal {
            inspection(BoundInspectionError::Inspection(
                InspectionError::Candidate(reason),
            ))
        }

        // 1, 2, 8, 25, 26, 29. An identical target creates a verified binding that
        // a fresh load retains, with the right locators and checkpoint, and
        // nothing else changes.
        #[test]
        fn an_identical_target_creates_a_verified_binding_and_changes_only_the_record() {
            let bx = Bx::new("b1f-bind");
            let vault_bytes = fs::read(&bx.vault).unwrap();

            assert_eq!(fs::read(&bx.remote).unwrap(), vault_bytes);

            // First use: not even the application-data root exists.
            assert!(!bx.root.path().exists());
            assert_eq!(
                bx.session.load_sync_state(&bx.root),
                SessionSyncState::NotConfigured
            );

            let vaults_before = snapshot(&bx.vaults_dir());
            let remote_before = snapshot(&bx.remote_dir());

            assert_eq!(bx.bind(), Ok(Outcome::BoundAndVerified));

            // Only the sync-state record exists afterwards.
            assert_eq!(snapshot(&bx.vaults_dir()), vaults_before);
            assert_eq!(snapshot(&bx.remote_dir()), remote_before);
            assert_eq!(fs::read(&bx.vault).unwrap(), vault_bytes);
            assert_eq!(fs::read(&bx.remote).unwrap(), vault_bytes);
            assert_eq!(names(bx.root.path()), [SYNC_STATE_DIRECTORY]);
            assert_eq!(names(&bx.state_dir()).len(), 1, "no staging file is left");

            // A fresh load retains the binding.
            let state = bx.loaded();

            assert_eq!(state.local_locator().as_str(), bx.local);
            assert_eq!(state.target_locator(), bx.target.locator());
            assert!(state.vault_tag().matches_vault(bx.vault_id));
            assert!(!state.vault_tag().matches_vault(OTHER_VAULT_ID));
            assert!(state.pending_push().is_none());
            assert_eq!(bx.record_bytes(), state.encode().unwrap());

            // The checkpoint is exactly the core's: the exact bytes' fingerprint,
            // the authenticated revision (0 for a new vault) as both the synced
            // revision and the starting high-water mark.
            let SyncBase::Based(checkpoint) = state.base() else {
                panic!("expected a based state");
            };

            assert_eq!(
                *checkpoint.synced(),
                EnvelopeFingerprint::of_bytes(&vault_bytes)
            );
            assert_eq!(checkpoint.synced_revision(), 0);
            assert_eq!(checkpoint.high_water().revision(), 0);
        }

        #[test]
        fn the_binding_survives_closing_and_reopening_the_session() {
            let bx = Bx::new("b1f-reopen");

            assert_eq!(bx.bind(), Ok(Outcome::BoundAndVerified));

            let expected = bx.loaded();
            let Bx {
                session,
                root,
                vault,
                dir,
                ..
            } = bx;

            session.lock();

            let reopened = UnlockedVaultSession::unlock(&vault, test_password()).unwrap();

            let SessionSyncState::Bound(bound) = reopened.load_sync_state(&root) else {
                panic!("the binding was not retained");
            };

            assert_eq!(*bound.state(), expected);

            drop(reopened);
            drop(dir);
        }

        // 31. The binding is a real one: the accepted B1c/B1e observation works on
        // it unchanged, and an observation of the identical target changes nothing.
        #[test]
        fn the_new_binding_is_usable_by_the_unchanged_observation() {
            let bx = Bx::new("b1f-observe");

            assert_eq!(bx.bind(), Ok(Outcome::BoundAndVerified));

            let record = bx.record_bytes();
            let before = snapshot(&bx.state_dir());

            assert_eq!(
                bx.session.observe_remote_target(&bx.root, &bx.target),
                Ok(RemoteObservationOutcome::Unchanged)
            );
            assert_eq!(bx.record_bytes(), record);
            assert_eq!(snapshot(&bx.state_dir()), before);
        }

        // 3. A target that differs in bytes is refused and creates nothing.
        #[test]
        fn a_target_that_differs_in_bytes_is_refused_and_creates_nothing() {
            let bx = Bx::new("b1f-differs");

            // A genuine envelope of this vault at a higher revision.
            bx.put_remote(&bx.resealed(|data| data.revision = 7));
            bx.assert_refused(transition(TransitionRefusal::RemoteDiffers));
            assert!(bx.record().is_none());
            assert!(!bx.state_dir().exists());

            // One byte appended to an otherwise identical copy: not an envelope.
            let mut longer = fs::read(&bx.vault).unwrap();

            longer.push(b' ');
            bx.put_remote(&longer);

            // Trailing whitespace is tolerated by JSON parsing, so the envelope
            // authenticates, and the bytes differ.
            bx.assert_refused(transition(TransitionRefusal::RemoteDiffers));
            assert!(!bx.state_dir().exists());
        }

        // 4. The same plaintext and key, sealed again or merely reformatted, is a
        // different byte string and is refused: byte identity is required.
        #[test]
        fn a_different_encryption_of_the_same_plaintext_is_refused() {
            let bx = Bx::new("b1f-representation");
            let on_disk = fs::read(&bx.vault).unwrap();

            // Re-sealed: fresh nonce, identical authenticated contents.
            let resealed = bx.resealed(|_| {});

            assert_ne!(resealed, on_disk);

            bx.put_remote(&resealed);
            bx.assert_refused(transition(TransitionRefusal::RemoteDiffers));

            // Same envelope, different JSON formatting.
            let envelope: VaultEnvelope = serde_json::from_slice(&on_disk).unwrap();
            let pretty = serde_json::to_vec_pretty(&envelope).unwrap();

            assert_ne!(pretty, on_disk);

            bx.put_remote(&pretty);
            bx.assert_refused(transition(TransitionRefusal::RemoteDiffers));

            assert!(!bx.state_dir().exists());
        }

        // 5. A payload authenticated under this vault's key but carrying another
        // vault identity is refused; the identity is never taken from the target.
        #[test]
        fn a_target_with_another_authenticated_vault_identity_is_refused() {
            let bx = Bx::new("b1f-identity");

            bx.put_remote(&bx.resealed(|data| data.vault_id = OTHER_VAULT_ID));
            bx.assert_refused(candidate_rejected(PayloadRejection::VaultIdMismatch));
            assert!(!bx.state_dir().exists());
        }

        // 6. A foreign vault, a damaged envelope and garbage never authenticate.
        #[test]
        fn a_target_that_does_not_authenticate_as_this_vault_is_refused() {
            let bx = Bx::new("b1f-authentication");

            // Another vault entirely: a different Vault Key.
            let foreign_path = bx.dir.path().join("foreign").join("foreign.lvault");
            let foreign =
                UnlockedVaultSession::create(&foreign_path, test_password(), NOW_MS).unwrap();

            foreign.lock();

            bx.put_remote(&fs::read(&foreign_path).unwrap());
            bx.assert_refused(candidate_rejected(PayloadRejection::AuthenticationFailed));

            // This vault's own envelope with one payload byte flipped.
            let mut damaged: VaultEnvelope =
                serde_json::from_slice(&fs::read(&bx.vault).unwrap()).unwrap();

            damaged.payload.ciphertext[0] ^= 0x01;
            bx.put_remote(&serde_json::to_vec(&damaged).unwrap());
            bx.assert_refused(candidate_rejected(PayloadRejection::AuthenticationFailed));

            // Not an envelope at all.
            bx.put_remote(b"this is not an envelope");
            bx.assert_refused(inspection(BoundInspectionError::MalformedEnvelope {
                input: EnvelopeInput::Candidate,
            }));

            assert!(!bx.state_dir().exists());
        }

        // 7. A payload with no authenticated revision cannot be bound, on either
        // side.
        #[test]
        fn a_legacy_payload_without_an_authenticated_revision_is_refused() {
            // A legacy local vault and a byte-identical legacy target: the
            // identity holds, but there is no revision to checkpoint.
            let legacy = Bx::legacy("b1f-legacy-local");

            assert_eq!(
                fs::read(&legacy.vault).unwrap(),
                fs::read(&legacy.remote).unwrap()
            );
            legacy.assert_refused(transition(TransitionRefusal::LocalUnversioned));
            assert!(!legacy.state_dir().exists());

            // A schema-3 local vault and a legacy copy of the same vault.
            let bx = Bx::new("b1f-legacy-target");

            bx.put_remote(&bx.resealed(|data| data.schema_version = 2));
            bx.assert_refused(transition(TransitionRefusal::RemoteDiffers));
            assert!(!bx.state_dir().exists());
        }

        // 9, 10, 11. An existing record, of any base, is never replaced.
        #[test]
        fn an_existing_based_unbased_or_pending_record_is_never_overwritten() {
            type MakeState = Box<dyn Fn(&Bx) -> SyncState>;

            let cases: Vec<(&str, MakeState)> = vec![
                ("based", Box::new(|bx| bx.based())),
                (
                    "unbased",
                    Box::new(|bx| {
                        bx.state(
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
                    }),
                ),
                (
                    "pending",
                    Box::new(|bx| {
                        bx.state(
                            SyncBase::Based(
                                SyncCheckpoint::new(fp(1), 1, RemoteHighWater::new(5)).unwrap(),
                            ),
                            Some(
                                PendingPush::new(
                                    INTENT,
                                    PushIntent::new(PushBaseline::Present(fp(1)), fp(3)).unwrap(),
                                    6,
                                )
                                .unwrap(),
                            ),
                        )
                    }),
                ),
            ];

            for (name, make) in cases {
                let bx = Bx::new(&format!("b1f-existing-{name}"));
                let existing = make(&bx);

                bx.publish(&existing);

                let record = bx.record_bytes();

                bx.assert_refused_unread(Refusal::ExistingBinding);

                assert_eq!(bx.record_bytes(), record, "{name}");
                assert_eq!(bx.loaded(), existing, "{name}");
            }
        }

        // A record for another vault, or another location, is also refused, left
        // alone and never adopted.
        #[test]
        fn a_record_for_another_vault_is_refused_and_left_alone() {
            let bx = Bx::new("b1f-existing-foreign");
            let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
            let foreign = SyncState::new(
                BindingId::new(BINDING).unwrap(),
                VaultBindingTag::derive(salt, OTHER_VAULT_ID).unwrap(),
                loc(&bx.local),
                bx.target.locator().clone(),
                bx.based().base().to_owned(),
                None,
            )
            .unwrap();

            bx.publish(&foreign);

            let record = bx.record_bytes();

            bx.assert_refused_unread(Refusal::ExistingBindingMismatch(
                BindingMismatch::VaultIdentity,
            ));
            assert_eq!(bx.record_bytes(), record);
        }

        // 12, 13, 14, 15. Corrupt, unsupported, unreadable and stale-artifact
        // states are refused, never reset, never treated as absence.
        #[test]
        fn corrupt_unsupported_unreadable_and_stale_states_are_never_replaced() {
            let bx = Bx::new("b1f-unusable");

            bx.publish(&bx.based());

            let record = bx.record().unwrap();
            let valid = bx.based();

            let check = |bytes: &[u8], expected: Refusal| {
                fs::write(&record, bytes).unwrap();

                bx.assert_refused_unread(expected);

                assert_eq!(fs::read(&record).unwrap(), bytes);
                assert_eq!(names(&bx.state_dir()).len(), 1);
            };

            check(
                b"this is not a sync state",
                Refusal::Corrupt(CorruptReason::Undecodable),
            );
            check(b"", Refusal::Corrupt(CorruptReason::Empty));

            let mut future: serde_json::Value =
                serde_json::from_slice(&valid.encode().unwrap()).unwrap();

            future["version"] = serde_json::json!(2);
            future["added_in_v2"] = serde_json::json!(true);
            check(
                &serde_json::to_vec(&future).unwrap(),
                Refusal::UnsupportedVersion,
            );

            // Unreadable: the record is held open without sharing.
            fs::write(&record, valid.encode().unwrap()).unwrap();

            #[cfg(windows)]
            {
                let original = fs::read(&record).ok();
                let guard = hold_exclusively(&record);
                let (result, reads) = bx.bind_counting(&bx.target);

                assert!(
                    matches!(result, Err(Refusal::Unreadable(UnreadableReason::Io(_)))),
                    "got {result:?}"
                );
                assert_eq!(reads, 0);

                drop(guard);

                assert_eq!(fs::read(&record).ok(), original);
            }

            // An interrupted-write artifact without a record: absence is not
            // established.
            let key = record.file_stem().unwrap().to_string_lossy().into_owned();
            let artifact = bx.state_dir().join(format!("{key}.{STALE_TOKEN}.tmp"));

            fs::remove_file(&record).unwrap();
            fs::write(&artifact, b"debris").unwrap();
            bx.assert_refused_unread(Refusal::Unreadable(UnreadableReason::UnresolvedArtifacts));

            assert_eq!(fs::read(&artifact).unwrap(), b"debris");
            assert!(bx.record().is_none());
        }

        // 16. A target absent from a valid local folder is a refusal, never
        // authority to publish.
        #[test]
        fn a_missing_target_is_refused_and_nothing_is_published() {
            let bx = Bx::bare("b1f-missing");

            assert!(!bx.remote.exists());

            let (result, reads) = bx.bind_counting(&bx.target);

            // The read ran (it is the step that reports absence) but nothing was
            // created: no target, no state directory, no application root.
            assert_eq!(result, Err(Refusal::TargetAbsentOnDisk));
            assert_eq!(reads, 1);
            assert!(!bx.remote.exists());
            assert!(!bx.state_dir().exists());
            assert!(!bx.root.path().exists());

            // A missing folder is unavailable, not absent.
            let nested =
                SyncFileTarget::from_path(&bx.dir.path().join("nowhere").join("t.lvault")).unwrap();
            let (result, _) = bx.bind_counting(&nested);

            assert_eq!(
                result,
                Err(Refusal::TargetUnavailable(UnavailableReason::ParentMissing))
            );
            assert!(!bx.root.path().exists());
        }

        // 17. An inaccessible, special or redirected target is unavailable.
        #[test]
        fn an_inaccessible_target_is_refused_and_nothing_is_published() {
            let bx = Bx::new("b1f-inaccessible");

            #[cfg(windows)]
            {
                let guard = hold_exclusively(&bx.remote);
                let (result, _) = bx.bind_counting(&bx.target);

                assert!(
                    matches!(
                        result,
                        Err(Refusal::TargetUnavailable(UnavailableReason::Io(_)))
                    ),
                    "got {result:?}"
                );

                drop(guard);
            }

            // A directory in the target's place.
            fs::remove_file(&bx.remote).unwrap();
            fs::create_dir(&bx.remote).unwrap();
            bx.assert_refused(Refusal::TargetUnavailable(
                UnavailableReason::UnexpectedObject,
            ));

            // A junction in the target's folder chain is not followed.
            #[cfg(windows)]
            {
                fs::remove_dir(&bx.remote).unwrap();

                let real = bx.dir.path().join("real");

                fs::create_dir_all(&real).unwrap();
                fs::copy(&bx.vault, real.join("target.lvault")).unwrap();

                let link = bx.dir.path().join("link");

                make_junction(&link, &real);

                let through = SyncFileTarget::from_path(&link.join("target.lvault")).unwrap();
                let (result, _) = bx.bind_counting(&through);

                assert_eq!(
                    result,
                    Err(Refusal::TargetUnavailable(
                        UnavailableReason::UnexpectedObject
                    ))
                );

                // Removes only the junction, not what it points to.
                fs::remove_dir(&link).unwrap();
                assert!(real.join("target.lvault").exists());
            }

            assert!(!bx.state_dir().exists());
            assert!(!bx.root.path().exists());
        }

        // 18. An empty or oversized target is refused.
        #[test]
        fn an_empty_or_oversized_target_is_refused_and_nothing_is_published() {
            let bx = Bx::new("b1f-empty-oversized");

            bx.put_remote(b"");
            bx.assert_refused(Refusal::TargetUnavailable(UnavailableReason::Empty));

            bx.put_remote(&vec![0u8; MAX_ENVELOPE_BYTES + 1]);
            bx.assert_refused(Refusal::TargetUnavailable(UnavailableReason::TooLarge));

            assert!(!bx.state_dir().exists());
            assert!(!bx.root.path().exists());
        }

        // 19. The vault's own primary, backup, lock and sync state are never a
        // target, however the path is spelled, and are refused before any read.
        #[test]
        fn a_target_naming_a_vault_file_is_refused_before_any_read() {
            let bx = Bx::new("b1f-alias");

            // The backup file, as a save would leave it.
            let backup = bx.session.backup_path().to_path_buf();

            fs::copy(&bx.vault, &backup).unwrap();

            // A file inside the sync-state directory, with no record for this
            // location (so the state is still confirmed absent).
            fs::create_dir_all(bx.state_dir()).unwrap();

            let unrelated = bx.state_dir().join("unrelated.json");

            fs::write(&unrelated, fs::read(&bx.vault).unwrap()).unwrap();

            let primary = bx.vault.to_string_lossy().into_owned();
            let spellings = [
                // As the user would pick it.
                primary.clone(),
                // The normalized form the binding itself stores.
                bx.local.clone(),
                // Case differences are the same file on Windows.
                primary.to_ascii_uppercase(),
                backup.to_string_lossy().into_owned(),
                lock_path_for(&bx.vault).to_string_lossy().into_owned(),
                unrelated.to_string_lossy().into_owned(),
            ];

            for spelling in spellings {
                let aliased = SyncFileTarget::from_path(Path::new(&spelling)).unwrap();
                let state = snapshot(&bx.state_dir());
                let vaults = snapshot(&bx.vaults_dir());
                let (result, reads) = bx.bind_counting(&aliased);

                assert_eq!(result, Err(Refusal::TargetIsVaultFile), "{spelling}");
                assert_eq!(reads, 0, "read before the check: {spelling}");
                assert_eq!(snapshot(&bx.state_dir()), state);
                assert_eq!(snapshot(&bx.vaults_dir()), vaults);
            }

            // The control: an unrelated byte copy elsewhere is accepted.
            assert_eq!(bx.bind(), Ok(Outcome::BoundAndVerified));
        }

        // The approval belongs to one target.
        #[test]
        fn an_approval_for_another_target_is_refused_before_anything_is_read() {
            let bx = Bx::new("b1f-approval");
            let other = SyncFileTarget::from_path(&bx.remote_dir().join("other.lvault")).unwrap();
            let reads = Cell::new(0usize);

            let result = bx.session.bind_existing_identical_target_in(
                &bx.store(),
                &bx.target,
                InitialBindingApproval::for_test(&other),
                &mut |t| {
                    reads.set(reads.get() + 1);

                    t.read()
                },
                &mut |buffer| getrandom::fill(buffer).is_ok(),
            );

            assert_eq!(result, Err(Refusal::ApprovalTargetMismatch));
            assert_eq!(reads.get(), 0);
            assert!(!bx.root.path().exists());
        }

        // 20. A local vault that is not the unlocked one is refused before the
        // target is read.
        #[test]
        fn a_vault_file_that_is_not_the_unlocked_one_is_refused() {
            let bx = Bx::new("b1f-vault-changed");
            let unavailable = Refusal::Unavailable(SyncStateUnavailable::LocalVaultChanged);

            // Replaced by a non-cooperating writer.
            let replacement = create_envelope(MASTER_PASSWORD, b"external replacement").unwrap();

            save_envelope_atomic(&bx.vault, &replacement).unwrap();
            bx.assert_refused_unread(unavailable);

            // Deleted.
            fs::remove_file(&bx.vault).unwrap();
            bx.assert_refused_unread(unavailable);

            assert!(!bx.root.path().exists());
        }

        // 21. A local vault replaced between the inspection and the publication,
        // and a target that changes or is withdrawn before it, are caught by the
        // repeated verification.
        #[test]
        fn evidence_that_changes_before_publication_is_refused() {
            // The target is unavailable (as the adapter reports a change during
            // a read).
            let bx = Bx::new("b1f-changed-during-read");
            let result = bx.bind_with(
                &bx.target,
                &mut |_| SyncFileRead::Unavailable(UnavailableReason::Changed),
                &mut |buffer| getrandom::fill(buffer).is_ok(),
            );

            assert_eq!(
                result,
                Err(Refusal::TargetUnavailable(UnavailableReason::Changed))
            );
            assert!(!bx.root.path().exists());

            // The local vault is replaced after the first read.
            let bx = Bx::new("b1f-local-replaced");
            let vault = bx.vault.clone();
            let reads = Cell::new(0usize);

            let result = bx.bind_with(
                &bx.target,
                &mut |t| {
                    let read = t.read();

                    if reads.get() == 0 {
                        let replacement =
                            create_envelope(MASTER_PASSWORD, b"external replacement").unwrap();

                        save_envelope_atomic(&vault, &replacement).unwrap();
                    }

                    reads.set(reads.get() + 1);

                    read
                },
                &mut |buffer| getrandom::fill(buffer).is_ok(),
            );

            assert_eq!(
                result,
                Err(Refusal::Unavailable(
                    SyncStateUnavailable::LocalVaultChanged
                ))
            );
            assert_eq!(reads.get(), 1, "the target was read again after the change");
            assert!(!bx.root.path().exists());

            // The target is replaced before the second read.
            let bx = Bx::new("b1f-target-replaced");
            let remote = bx.remote.clone();
            let changed = bx.resealed(|_| {});
            let reads = Cell::new(0usize);

            let result = bx.bind_with(
                &bx.target,
                &mut |t| {
                    if reads.get() == 1 {
                        fs::write(&remote, &changed).unwrap();
                    }

                    reads.set(reads.get() + 1);

                    t.read()
                },
                &mut |buffer| getrandom::fill(buffer).is_ok(),
            );

            assert_eq!(result, Err(Refusal::EvidenceChanged));
            assert_eq!(reads.get(), 2);
            assert!(!bx.root.path().exists());

            // The target is withdrawn before the second read.
            let bx = Bx::new("b1f-target-withdrawn");
            let remote = bx.remote.clone();
            let reads = Cell::new(0usize);

            let result = bx.bind_with(
                &bx.target,
                &mut |t| {
                    if reads.get() == 1 {
                        fs::remove_file(&remote).unwrap();
                    }

                    reads.set(reads.get() + 1);

                    t.read()
                },
                &mut |buffer| getrandom::fill(buffer).is_ok(),
            );

            assert_eq!(result, Err(Refusal::EvidenceChanged));
            assert!(!bx.root.path().exists());
        }

        // 22. A record that appears between the check and publication is never
        // clobbered.
        #[test]
        fn a_record_that_appears_before_publication_is_not_replaced() {
            let bx = Bx::new("b1f-appeared");
            let planted = bx.based();
            let store = bx.store();
            let reads = Cell::new(0usize);

            let result = bx.session.bind_existing_identical_target_in(
                &store,
                &bx.target,
                bx.approval(),
                &mut |t| {
                    // After the second (pre-publication) read the record is
                    // created by someone else.
                    if reads.get() == 1 {
                        let publisher = SyncStateStore::new(bx.root.path()).unwrap();

                        publisher.create(&planted).unwrap();
                    }

                    reads.set(reads.get() + 1);

                    t.read()
                },
                &mut |buffer| getrandom::fill(buffer).is_ok(),
            );

            assert_eq!(result, Err(Refusal::RecordAppeared));
            assert_eq!(bx.record_bytes(), planted.encode().unwrap());
            assert_eq!(bx.loaded(), planted);
            assert_eq!(names(&bx.state_dir()).len(), 1);
        }

        // 26. A fresh id and salt per binding, drawn from the entropy source.
        #[test]
        fn each_binding_draws_a_fresh_id_and_salt() {
            let first = Bx::new("b1f-fresh-1");

            // The same vault (same authenticated vault id) at a second location.
            let second_vault = first.dir.path().join("vaults").join("second.lvault");

            fs::copy(&first.vault, &second_vault).unwrap();

            let second_session =
                UnlockedVaultSession::unlock(&second_vault, test_password()).unwrap();
            let second_remote = first.dir.path().join("remote").join("second-target.lvault");

            fs::copy(&second_vault, &second_remote).unwrap();

            let second_target = SyncFileTarget::from_path(&second_remote).unwrap();

            let requested = RefCell::new(Vec::new());

            assert_eq!(
                first.bind_with(&first.target, &mut |t| t.read(), &mut |buffer| {
                    requested.borrow_mut().push(buffer.len());

                    getrandom::fill(buffer).is_ok()
                },),
                Ok(Outcome::BoundAndVerified)
            );
            assert_eq!(*requested.borrow(), [16, BINDING_SALT_LEN]);

            assert_eq!(
                second_session.bind_existing_identical_target(
                    &first.root,
                    &second_target,
                    InitialBindingApproval::for_test(&second_target),
                ),
                Ok(Outcome::BoundAndVerified)
            );

            let one = first.loaded();
            let SessionSyncState::Bound(two) = second_session.load_sync_state(&first.root) else {
                panic!("the second binding was not retained");
            };
            let two = two.state();

            assert_eq!(first.vault_id, second_session.data().vault_id);
            assert_ne!(one.binding_id(), two.binding_id());
            assert_ne!(one.vault_tag(), two.vault_tag(), "the salt was reused");
            assert_eq!(one.binding_id().uuid().get_version_num(), 4);
            assert!(!one.binding_id().uuid().is_nil());
            assert!(one.vault_tag().matches_vault(first.vault_id));
            assert!(two.vault_tag().matches_vault(first.vault_id));

            drop(second_session);
        }

        #[test]
        fn unavailable_randomness_creates_nothing() {
            let bx = Bx::new("b1f-no-entropy");
            let draws = Cell::new(0usize);

            let result = bx.bind_with(&bx.target, &mut |t| t.read(), &mut |_| {
                draws.set(draws.get() + 1);

                false
            });

            assert_eq!(result, Err(Refusal::Randomness));
            assert_eq!(draws.get(), 1, "a second draw was attempted");
            assert!(!bx.root.path().exists());
        }

        // 24 (the branch no store fault can reach). After a successful
        // publication and the store's own readback, success is reported only if a
        // fresh, independent load is exactly the proposal and still passes the
        // core's binding check for this authenticated vault and both locators.
        // Every other load, or any disagreement, leaves the persistence
        // unverified. Exercised directly, because no hook exists between the
        // store's verification and the operation's reload.
        #[test]
        fn only_a_fresh_load_equal_to_the_proposal_and_bound_to_this_vault_confirms() {
            let bx = Bx::new("b1f-fresh-load");
            let proposed = bx.based();
            let local = loc(&bx.local);
            let target = bx.target.locator().clone();

            let confirms = |load: StateLoad, vault: Uuid, local: &Locator, target: &Locator| {
                fresh_load_confirms_binding(load, &proposed, vault, local, target)
            };
            let loaded = |state: &SyncState| StateLoad::Loaded(Box::new(state.clone()));

            // The control: exactly the proposal, for this vault and locators.
            assert!(confirms(loaded(&proposed), bx.vault_id, &local, &target));

            // No usable record is never a confirmation.
            for load in [
                StateLoad::NotConfigured,
                StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts),
                StateLoad::Unreadable(UnreadableReason::Io(io::ErrorKind::PermissionDenied)),
                StateLoad::Corrupt(CorruptReason::Undecodable),
                StateLoad::UnsupportedVersion,
            ] {
                assert!(!confirms(load, bx.vault_id, &local, &target));
            }

            // A valid record that is not the proposal (another binding id, another
            // checkpoint, a pending push) is not a confirmation.
            let other_id = SyncState::new(
                BindingId::new(INTENT).unwrap(),
                *proposed.vault_tag(),
                proposed.local_locator().clone(),
                proposed.target_locator().clone(),
                *proposed.base(),
                None,
            )
            .unwrap();
            let other_checkpoint = bx.state(
                SyncBase::Based(SyncCheckpoint::new(fp(9), 3, RemoteHighWater::new(3)).unwrap()),
                None,
            );

            assert!(!confirms(loaded(&other_id), bx.vault_id, &local, &target));
            assert!(!confirms(
                loaded(&other_checkpoint),
                bx.vault_id,
                &local,
                &target
            ));

            // The proposal itself, but not bound to the authenticated vault or to
            // the locators the operation used.
            assert!(!confirms(
                loaded(&proposed),
                OTHER_VAULT_ID,
                &local,
                &target
            ));
            assert!(!confirms(
                loaded(&proposed),
                bx.vault_id,
                &loc("C:\\elsewhere\\vault.lvault"),
                &target
            ));
            assert!(!confirms(
                loaded(&proposed),
                bx.vault_id,
                &local,
                &loc("C:\\elsewhere\\target.lvault")
            ));
        }

        // 27. The exclusive OS lock is held for the whole operation, across both
        // reads of the target and the publication, and afterwards.
        #[test]
        fn the_session_lock_is_held_across_the_operation() {
            let bx = Bx::new("b1f-lock");
            let vault = bx.vault.clone();
            let refused = Cell::new(0u8);

            let result = bx.bind_with(
                &bx.target,
                &mut |t| {
                    let attempt = UnlockedVaultSession::unlock(&vault, test_password());

                    if matches!(attempt, Err(SessionError::InUse)) {
                        refused.set(refused.get() + 1);
                    }

                    t.read()
                },
                &mut |buffer| getrandom::fill(buffer).is_ok(),
            );

            assert_eq!(result, Ok(Outcome::BoundAndVerified));
            assert_eq!(refused.get(), 2, "the lock was not held during both reads");

            assert!(matches!(
                UnlockedVaultSession::unlock(&bx.vault, test_password()),
                Err(SessionError::InUse)
            ));
        }

        // 29. No outcome writes the target, the vault, its backup, or anything
        // outside the sync-state directory.
        #[test]
        fn no_outcome_writes_anything_but_the_new_record() {
            let bx = Bx::new("b1f-no-writes");
            let vaults = snapshot(&bx.vaults_dir());

            // A refusal.
            bx.put_remote(b"garbage");

            let remote_garbage = snapshot(&bx.remote_dir());

            assert!(bx.bind().is_err());
            assert_eq!(snapshot(&bx.vaults_dir()), vaults);
            assert_eq!(snapshot(&bx.remote_dir()), remote_garbage);
            assert!(!bx.root.path().exists());

            // Success.
            fs::copy(&bx.vault, &bx.remote).unwrap();

            let remote = snapshot(&bx.remote_dir());

            assert_eq!(bx.bind(), Ok(Outcome::BoundAndVerified));
            assert_eq!(snapshot(&bx.vaults_dir()), vaults);
            assert_eq!(snapshot(&bx.remote_dir()), remote);

            let created = names(bx.root.path());

            assert_eq!(created, [SYNC_STATE_DIRECTORY]);
            assert_eq!(names(&bx.state_dir()).len(), 1);
        }

        // 30. Nothing printed, in any outcome, carries a path, identifier,
        // fingerprint, key, password or content.
        #[test]
        fn outcomes_and_errors_reveal_no_path_identifier_or_content() {
            let bx = Bx::new("b1f-no-leak");
            let on_disk = fs::read(&bx.vault).unwrap();
            let mut shown: Vec<String> = Vec::new();

            let mut note = |result: Result<Outcome, Refusal>| {
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

            bx.put_remote(&bx.resealed(|data| data.revision = 7));
            note(bx.bind()); // differs
            bx.put_remote(&bx.resealed(|data| data.vault_id = OTHER_VAULT_ID));
            note(bx.bind()); // another identity
            bx.put_remote(b"garbage");
            note(bx.bind()); // malformed
            bx.put_remote(b"");
            note(bx.bind()); // unavailable
            fs::remove_file(&bx.remote).unwrap();
            note(bx.bind()); // absent
            note(bx.session.bind_existing_identical_target(
                &bx.root,
                &bx.target,
                InitialBindingApproval::for_test(
                    &SyncFileTarget::from_path(&bx.remote_dir().join("x.lvault")).unwrap(),
                ),
            )); // approval mismatch
            note(bx.session.bind_existing_identical_target(
                &bx.root,
                &SyncFileTarget::from_path(&bx.vault).unwrap(),
                InitialBindingApproval::for_test(&SyncFileTarget::from_path(&bx.vault).unwrap()),
            )); // the primary itself
            fs::write(&bx.remote, &on_disk).unwrap();
            note(bx.bind()); // success
            note(bx.bind()); // existing
            note(Err(Refusal::NotPersisted(StoreError::Io {
                stage: IoStage::Sync,
                kind: io::ErrorKind::PermissionDenied,
            })));
            note(Err(Refusal::PersistenceUnverified));
            note(Err(Refusal::RecordAppeared));
            note(Err(Refusal::Randomness));
            note(Err(Refusal::Corrupt(CorruptReason::Undecodable)));
            note(Err(Refusal::Unreadable(UnreadableReason::Io(
                io::ErrorKind::PermissionDenied,
            ))));

            shown.push(format!("{:?}", bx.approval()));

            let fingerprint = |bytes: &[u8]| EnvelopeFingerprint::of_bytes(bytes).to_hex();
            let prefix = String::from_utf8_lossy(&on_disk[..48.min(on_disk.len())]).into_owned();

            let needles = vec![
                bx.dir.path().to_string_lossy().into_owned(),
                bx.remote.to_string_lossy().into_owned(),
                bx.target.locator().as_str().to_owned(),
                bx.local.clone(),
                bx.vault_id.to_string(),
                bx.vault_id.simple().to_string(),
                OTHER_VAULT_ID.to_string(),
                BINDING.to_string(),
                "target.lvault".to_owned(),
                "vault.lvault".to_owned(),
                ".qa-local".to_owned(),
                "LEAKMARK".to_owned(),
                MASTER_PASSWORD.to_owned(),
                fingerprint(&on_disk),
                prefix,
            ];

            assert!(shown.len() > 20);

            for output in &shown {
                for needle in &needles {
                    assert!(
                        !output.contains(needle.as_str()),
                        "leaks {needle:?}: {output}"
                    );
                }
            }

            // The stored binding id is not printed by the session's own view.
            let SessionSyncState::Bound(bound) = bx.session.load_sync_state(&bx.root) else {
                panic!("expected a bound state");
            };
            let printed = format!("{bound:?}");

            assert!(!printed.contains(&bound.state().binding_id().uuid().to_string()));
        }

        // The classification of every store error, the heart of "definitely not
        // published" versus "possibly published".
        #[test]
        fn create_errors_are_classified_as_published_only_where_publication_may_have_happened() {
            let io = |stage| StoreError::Io {
                stage,
                kind: io::ErrorKind::PermissionDenied,
            };

            // Fail before the hard link: the record was not created.
            for definite in [
                io(IoStage::Directory),
                io(IoStage::Inspect),
                io(IoStage::Scan),
                io(IoStage::Open),
                io(IoStage::Write),
                io(IoStage::Sync),
                StoreError::RootNotAbsolute,
                StoreError::AlreadyExists,
                StoreError::UnresolvedArtifacts,
                StoreError::UnexpectedObject,
                StoreError::NoClobberUnsupported,
                StoreError::Encode(localvault_core::sync_state::SyncStateEncodeError::TooLarge),
            ] {
                assert!(
                    !create_error_may_follow_publication(definite),
                    "{definite:?} must be definite"
                );
            }

            // The link itself failed for another reason, or the verification
            // failed, or the error is not one `create` produces.
            for ambiguous in [
                io(IoStage::Replace),
                StoreError::VerificationFailed,
                StoreError::Missing,
                StoreError::CurrentUnreadable,
                StoreError::CurrentCorrupt,
                StoreError::CurrentUnsupportedVersion,
                StoreError::CurrentLocatorMismatch,
                StoreError::Changed,
                StoreError::LocatorMismatch,
                StoreError::BindingIdentityChanged,
                StoreError::TrustedHistoryRegression,
                StoreError::IncompleteDeletion,
            ] {
                assert!(
                    create_error_may_follow_publication(ambiguous),
                    "{ambiguous:?} must be ambiguous"
                );
            }
        }
    }
}
