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
    time::{Duration, Instant},
};

use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use localvault_core::{
    sync::{
        inspect_remote_bytes, AuthenticatedRevision, BoundInspection, BoundInspectionError,
        EnvelopeFingerprint,
    },
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
    file_identity::{compare, facts_of, FileIdentity, HandleFacts, IdentityError, PhysicalVerdict},
    storage::{
        load_envelope, save_envelope_atomic_with_backup, StorageError, MAX_VAULT_FILE_BYTES,
    },
    sync_file_adapter::{PresentFile, SyncFileRead, SyncFileTarget, UnavailableReason},
    sync_state_store::{
        path_identity_eq, ConditionalDeleteError, CorruptReason, DeleteOutcome, EvidenceRefusal,
        RecordEvidence, StateLoad, StoreError, SyncStateRoot, SyncStateStore, UnreadableReason,
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
/// # Where an approval can come from
///
/// This type has exactly one production constructor, the private
/// `from_confirmed`, and it is reachable only through
/// [`UnlockedVaultSession::confirm_initial_binding`]. Its field is private, it
/// has no `Default`, `Clone`, `Copy` or `From`, and no `pub` or `pub(crate)`
/// constructor exists. The other way to build one is the `#[cfg(test)]` helper
/// below. A boolean or an enum that any caller could set to "granted" would claim
/// a confirmation that never happened; this does not.
///
/// `from_confirmed` takes a `PendingInitialBinding` **by value**. That value is
/// private to this module and only
/// [`UnlockedVaultSession::prepare_initial_binding`] can create one, after a
/// successful read-only examination of exactly one target, and it is stored in
/// the unlocked session itself. `confirm_initial_binding` removes it from the
/// session (so one preparation can be spent at most once, whether the attempt
/// succeeds or fails), checks that the caller names that very preparation, that it
/// is fresh, and that the vault and the target are still what was examined, and
/// only then builds the approval, which is consumed by the unchanged binding
/// operation. The approval is therefore tied to one preparation, to one target
/// and to one live session, and cannot outlive any of them.
///
/// **No user interface or command calls either step yet.** The frontend is
/// inside the trust boundary: a caller that can reach both steps can prepare and
/// confirm without a human, and this type does not claim otherwise. What it
/// guarantees is that there is no binding without a separate confirm call that
/// follows a successful prepare in the same live session. Passing this value is a
/// precondition, never evidence that a person was shown anything; only the code
/// that exposes the two steps to a person can make that true.
///
/// The value is single-use (consumed by the operation), is bound to the target
/// locator it was made for (an approval for one file cannot be spent on
/// another), and is not shown by `Debug`.
#[must_use = "an approval is consumed by the binding operation"]
pub struct InitialBindingApproval {
    target: Locator,
}

impl InitialBindingApproval {
    /// The only production constructor. Private to this module, and called only
    /// by [`UnlockedVaultSession::confirm_initial_binding_in`]. Taking the
    /// pending preparation by value ties the approval to the one preparation it
    /// came from and to the target that preparation examined.
    fn from_confirmed(pending: PendingInitialBinding) -> Self {
        Self {
            target: pending.target.locator().clone(),
        }
    }

    /// Test-only. Not a model of the real confirmation: it exists so the
    /// operation's behavior can be exercised directly.
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
    /// directory, by path or by physical identity (for example a hard link to the
    /// primary). See the operation's limits.
    #[error("the target names a file that belongs to this vault or its sync state")]
    TargetIsVaultFile,
    /// The physical identity of the local vault file or the target could not be
    /// established with certainty: a lookup failed, a volume is not local NTFS or
    /// ReFS, an identifier is degenerate, a file is delete-pending, the target has
    /// more than one name, or the target is a network (UNC) path. Never authority
    /// to publish.
    #[error("the physical identity of the vault file or target is uncertain")]
    TargetIdentityUncertain,
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

/// How long a successful preparation stays confirmable. Measured from the
/// preparation, not from user activity, and in addition to the session's own
/// inactivity lock.
const INITIAL_BINDING_APPROVAL_TTL: Duration = Duration::from_secs(120);

/// What [`UnlockedVaultSession::prepare_initial_binding`] established and is now
/// waiting to be confirmed. It exists only as a field of the unlocked session:
/// it is never serialized, logged, persisted or handed out, and it is dropped
/// with the session (lock, expiry, vault switch, process exit). Private to this
/// module, so no other code can build one or turn it into an approval.
struct PendingInitialBinding {
    /// Opaque random correlation id. It ties a confirmation to the preview that
    /// was shown; it is not a secret and not proof of consent.
    id: Uuid,
    /// The exact target the user selected.
    target: SyncFileTarget,
    /// Fingerprint of the exact bytes of the local vault file at preparation.
    /// The target held byte-identical content, so this is also the target's.
    local_fingerprint: EnvelopeFingerprint,
    /// Physical identity of the target file at preparation.
    target_identity: FileIdentity,
    prepared_at: Instant,
}

impl std::fmt::Debug for PendingInitialBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingInitialBinding(<redacted>)")
    }
}

/// What the user must be shown before an initial binding may be confirmed.
/// Returned only by a successful [`UnlockedVaultSession::prepare_initial_binding`].
///
/// `target_path` is the exact locator string Rust will bind, not a copy supplied
/// by a caller. Both paths are meant for display to the user and for nothing
/// else: they are not shown by `Debug`, and this type is not `Clone`.
pub struct InitialBindingPreview {
    preparation_id: String,
    vault_file_name: String,
    target_path: String,
}

impl InitialBindingPreview {
    /// Opaque correlation id to pass back to
    /// [`UnlockedVaultSession::confirm_initial_binding`].
    pub fn preparation_id(&self) -> &str {
        &self.preparation_id
    }

    pub fn vault_file_name(&self) -> &str {
        &self.vault_file_name
    }

    pub fn target_path(&self) -> &str {
        &self.target_path
    }
}

impl std::fmt::Debug for InitialBindingPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InitialBindingPreview(<redacted>)")
    }
}

/// Why a confirmation was rejected as out of date, before the binding operation
/// ran. Fixed categories only: no path, id, fingerprint or content. In every
/// case nothing was written and the preparation is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InitialBindingStale {
    /// No successful preparation is pending: none was made, it was already
    /// confirmed or cancelled, a later attempt replaced it, or the session it
    /// belonged to is gone.
    #[error("no initial binding is waiting for confirmation")]
    NoPendingApproval,
    /// The id does not name the pending preparation.
    #[error("the confirmation does not belong to the current preparation")]
    NotCurrentPreparation,
    /// The preparation is older than its lifetime.
    #[error("the preparation has expired")]
    Expired,
    /// The vault file changed after the preparation (for example a save or a
    /// master-password change in this session).
    #[error("the vault changed after the preparation")]
    LocalVaultChanged,
    /// The target's bytes or physical file changed after the preparation, which
    /// includes an identical copy re-created at the same path.
    #[error("the target changed after the preparation")]
    TargetChanged,
}

/// Why [`UnlockedVaultSession::confirm_initial_binding`] bound nothing. Fixed
/// categories only. Whatever the variant, the preparation is spent: a new one is
/// needed for another attempt.
///
/// [`Binding`](Self::Binding) carries the unchanged binding operation's own
/// refusal, with its documented meaning (in particular for
/// [`InitialBindingRefusal::PersistenceUnverified`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InitialBindingConfirmRefusal {
    #[error("the initial binding confirmation is out of date")]
    Stale(InitialBindingStale),
    #[error("the initial binding was refused")]
    Binding(InitialBindingRefusal),
}

/// Whether a push is recorded as started and not yet resolved. Separate from the
/// binding state on purpose: it says nothing about the target, and it is
/// reported only from a record that passed the authenticated binding check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingPushIndication {
    /// A verified record exists and holds no pending push.
    None,
    /// A verified record holds a pending push (an unresolved local sync intent).
    Pending,
    /// There is no verified record to read it from (none exists, or the record is
    /// corrupt, unsupported, unreadable, foreign or unverifiable). Not "none".
    Unavailable,
}

/// The target a verified binding retains, for an informed-consent display. A
/// local path string: never shown by `Debug`, and not evidence about the file.
#[derive(Clone, PartialEq, Eq)]
pub struct LinkedTarget {
    path: String,
}

impl LinkedTarget {
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl std::fmt::Debug for LinkedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkedTarget(<redacted>)")
    }
}

/// Why a stored binding cannot be shown as linked. One fixed category each; none
/// is a healthy binding, and none exposes a stored target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingAttention {
    Corrupt(CorruptReason),
    UnsupportedVersion,
    /// Includes an unresolved recovery artifact: absence was not confirmed.
    Unreadable(UnreadableReason),
    /// A readable record for another vault or another location. Its target is
    /// not exposed.
    Mismatch(BindingMismatch),
    /// The session's vault, its location or the state root could not anchor the
    /// check at all.
    Unavailable(SyncStateUnavailable),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingState {
    /// Confirmed no record. Not a trusted prior checkpoint.
    NotConfigured,
    /// A record that passed the authenticated binding check for this vault and
    /// this location. The target was not read and nothing is claimed about it.
    Linked(LinkedTarget),
    NeedsAttention(BindingAttention),
}

/// Sanitized, read-only summary of this vault's local synchronization binding
/// (Stage 1U-4 B1i). `Debug` and every category reveal no path, identifier,
/// fingerprint or revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingStatus {
    state: BindingState,
    pending_push: PendingPushIndication,
}

impl BindingStatus {
    pub fn state(&self) -> &BindingState {
        &self.state
    }

    pub fn pending_push(&self) -> PendingPushIndication {
        self.pending_push
    }

    /// The target path of a **linked** binding only; `None` for every other state,
    /// in particular after a mismatch or any verification failure.
    pub fn target_path(&self) -> Option<&str> {
        match &self.state {
            BindingState::Linked(target) => Some(target.path()),
            _ => None,
        }
    }
}

/// What kind of local state a reset would remove, as the user is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingResetSubject {
    /// A record that passed the authenticated binding check.
    VerifiedBinding,
    /// A readable record for another vault or another location.
    MismatchedRecord,
    /// A record that exists but cannot be decoded (or is for another location).
    CorruptRecord,
    /// A record written by a newer, unsupported version.
    UnsupportedRecord,
    /// No record, only the recovery artifacts of an interrupted write.
    InterruptedWriteRemnants,
}

/// A fixed fact about what a reset does and does not do, for the confirmation
/// dialog. The list is the same for every subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingResetConsequence {
    RemovesLocalBindingRecord,
    RemovesTrustedSyncHistory,
    MayDiscardPendingSyncIntent,
    KeepsVaultAndBackup,
    KeepsRemoteTarget,
    DoesNotProveRemoteContentAbsent,
    DoesNotEnablePublication,
}

const BINDING_RESET_CONSEQUENCES: [BindingResetConsequence; 7] = [
    BindingResetConsequence::RemovesLocalBindingRecord,
    BindingResetConsequence::RemovesTrustedSyncHistory,
    BindingResetConsequence::MayDiscardPendingSyncIntent,
    BindingResetConsequence::KeepsVaultAndBackup,
    BindingResetConsequence::KeepsRemoteTarget,
    BindingResetConsequence::DoesNotProveRemoteContentAbsent,
    BindingResetConsequence::DoesNotEnablePublication,
];

/// How long a successful reset preparation stays confirmable. Measured from the
/// preparation, in addition to the session's own inactivity lock.
const BINDING_RESET_TTL: Duration = Duration::from_secs(120);

/// What [`UnlockedVaultSession::prepare_binding_reset`] established and is now
/// waiting to be confirmed. Like [`PendingInitialBinding`] it exists only as a
/// field of the unlocked session: never serialized, logged or handed out, and
/// dropped with the session. Private to this module.
struct PendingBindingReset {
    /// Opaque random correlation id: ties a confirmation to the preview shown.
    id: Uuid,
    /// The session's local location when it was prepared.
    local_locator: Locator,
    subject: BindingResetSubject,
    /// The exact store state the user was shown.
    evidence: RecordEvidence,
    prepared_at: Instant,
}

impl std::fmt::Debug for PendingBindingReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingBindingReset(<redacted>)")
    }
}

/// What the user must be shown before a reset may be confirmed. Returned only by
/// a successful [`UnlockedVaultSession::prepare_binding_reset`]. Paths are for
/// display only; `Debug` shows nothing, and the type is not `Clone`.
pub struct BindingResetPreview {
    preparation_id: String,
    subject: BindingResetSubject,
    target_path: Option<String>,
    pending_push: PendingPushIndication,
}

impl BindingResetPreview {
    /// Opaque correlation id to pass back to
    /// [`UnlockedVaultSession::confirm_binding_reset`].
    pub fn preparation_id(&self) -> &str {
        &self.preparation_id
    }

    pub fn subject(&self) -> BindingResetSubject {
        self.subject
    }

    /// The retained target of a **verified** binding only.
    pub fn target_path(&self) -> Option<&str> {
        self.target_path.as_deref()
    }

    pub fn pending_push(&self) -> PendingPushIndication {
        self.pending_push
    }

    pub fn consequences(&self) -> &'static [BindingResetConsequence] {
        &BINDING_RESET_CONSEQUENCES
    }
}

impl std::fmt::Debug for BindingResetPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BindingResetPreview(<redacted>)")
    }
}

/// What a successful reset established: the local record and its recognized
/// recovery artifacts were removed, and a fresh load confirmed that nothing is
/// configured. Fieldless on purpose. It does **not** mean the remote target is
/// empty, that publication is enabled, or that a new binding exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum BindingResetOutcome {
    ResetAndVerified,
}

/// Why no reset was prepared, or why a confirmation refused before anything was
/// removed. Fixed categories only. Nothing here removed anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BindingResetRefusal {
    /// The session's own vault or location cannot anchor the check.
    #[error("the session's vault or sync-state location is unavailable")]
    Unavailable(SyncStateUnavailable),
    /// No record and no recovery artifact exists (confirmed): nothing to reset.
    #[error("there is no synchronization binding to reset")]
    NothingToReset,
    /// The state could not be read, and absence or contents are unknown. These
    /// are **intentionally not resettable**: an I/O or permission failure, an
    /// unexpected object (directory, junction, symlink), or too many entries.
    #[error("the synchronization state could not be read and is not resettable")]
    UnreadableState(UnreadableReason),
    /// Exact evidence of the stored files could not be captured (for example an
    /// inaccessible or oversized file, or a reparse point). Not resettable.
    #[error("exact evidence of the synchronization state could not be captured")]
    Evidence(EvidenceRefusal),
    /// The stored state changed while it was being examined, or the load and the
    /// evidence disagree.
    #[error("the synchronization state changed while it was examined")]
    RecordChanged,
    /// Secure randomness for the preparation id was unavailable.
    #[error("secure randomness is unavailable")]
    Randomness,
}

/// Why a confirmation was rejected as out of date, before anything was removed.
/// In every case the preparation is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BindingResetStale {
    #[error("no reset is waiting for confirmation")]
    NoPendingReset,
    #[error("the confirmation does not belong to the current preparation")]
    NotCurrentPreparation,
    #[error("the preparation has expired")]
    Expired,
    /// The session's local location is not the one that was prepared.
    #[error("the vault location changed after the preparation")]
    LocatorChanged,
    /// The stored state is not what the user was shown: its bytes, its artifacts
    /// or its kind differ, or it is gone. A record that is **already absent** is
    /// reported here, never as a reset performed by this confirmation.
    #[error("the synchronization state changed after the preparation")]
    RecordChanged,
}

/// Why a reset ended without a confirmed result after removal may have begun.
/// Never a success, never retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BindingResetAmbiguity {
    /// The deletion reported that it could not remove or verify everything. Some
    /// files may be gone and others not.
    #[error("the synchronization state deletion is incomplete")]
    IncompleteDeletion,
    /// The deletion reported success, but a fresh load did not confirm that
    /// nothing is configured.
    #[error("the removal could not be confirmed by a fresh load")]
    AbsenceNotConfirmed,
}

/// Why [`UnlockedVaultSession::confirm_binding_reset`] did not report a verified
/// reset. Fixed categories only. Whatever the variant, the preparation is spent.
///
/// * [`Stale`](Self::Stale) and [`Refused`](Self::Refused) and
///   [`NotRemoved`](Self::NotRemoved): **definitely nothing was removed** by this
///   call.
/// * [`Ambiguous`](Self::Ambiguous): removal may have happened in part or in
///   whole. Nothing is retried, repaired or rebound; the next decision starts with
///   a fresh status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BindingResetConfirmRefusal {
    #[error("the reset confirmation is out of date")]
    Stale(BindingResetStale),
    #[error("the reset was refused")]
    Refused(BindingResetRefusal),
    /// The store refused or failed strictly before the first removal.
    #[error("the synchronization state could not be removed")]
    NotRemoved(StoreError),
    #[error("the reset could not be confirmed")]
    Ambiguous(BindingResetAmbiguity),
}

/// Classification of a loaded state for reset, with the facts a preview shows.
struct ResetClass {
    subject: BindingResetSubject,
    pending_push: PendingPushIndication,
    target_path: Option<String>,
}

pub struct UnlockedVaultSession {
    path: PathBuf,
    backup_path: PathBuf,
    envelope: VaultEnvelope,
    vault_key: SecretKey,
    data: VaultData,
    dirty: bool,

    // In memory only, and never copied anywhere: it lives and dies with this
    // session. See `PendingInitialBinding`.
    pending_initial_binding: Option<PendingInitialBinding>,

    // Same lifetime rules. At most one of the two pending values exists at a
    // time: preparing or confirming either one discards the other.
    pending_binding_reset: Option<PendingBindingReset>,

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
            pending_initial_binding: None,
            pending_binding_reset: None,
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
            pending_initial_binding: None,
            pending_binding_reset: None,
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
    /// unlock path reaches it. In a production build the only caller is
    /// [`confirm_initial_binding`](Self::confirm_initial_binding), because the
    /// required [`InitialBindingApproval`] has no other production constructor
    /// (see its documentation). It enables no working synchronization.
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
    /// place. The Rust-side two-step flow
    /// ([`prepare_initial_binding`](Self::prepare_initial_binding), then
    /// [`confirm_initial_binding`](Self::confirm_initial_binding)) is the only
    /// production source of one, but no user interface calls it yet: a future UI
    /// must show the user the vault and the chosen file and obtain a deliberate
    /// explicit confirmation before it makes the confirming call. See
    /// [`InitialBindingApproval`].
    ///
    /// # Order of operations
    ///
    /// All inside one `&self` borrow of the unlocked session, so the exclusive OS
    /// lock held by `_lock_file` is held from the first step to the last.
    ///
    /// 1. the approval must be for this target;
    /// 2. the vault file is opened once, read through that handle and held open
    ///    for the whole operation: its exact current bytes must parse to
    ///    precisely the envelope this session unlocked (they become the local
    ///    reference), its physical identity is read from the same handle, and the
    ///    session's normalized local locator is resolved;
    /// 3. the sync-state record is loaded: only a **confirmed** `NotConfigured`
    ///    continues. A loaded record (valid or foreign), a corrupt, unsupported
    ///    or unreadable one, and an unresolved recovery artifact are refused and
    ///    left exactly as they are;
    /// 4. the target is refused if it is a network (UNC) path, or names this
    ///    vault's primary, `.backup`, `.lock` or a file in the sync-state
    ///    directory;
    /// 5. only then [`SyncFileTarget::read`] runs, and only `Present` continues:
    ///    absence on disk and unavailability are refusals, never authority to
    ///    publish. The target's physical identity (read from the handle that
    ///    produced its bytes) must then be a **distinct** file from the primary,
    ///    both on local NTFS or ReFS volumes, the target with exactly one name;
    ///    the same file is [`InitialBindingRefusal::TargetIsVaultFile`] and
    ///    anything not established with certainty is
    ///    [`InitialBindingRefusal::TargetIdentityUncertain`];
    /// 6. `inspect_remote_bytes` authenticates both byte strings under this
    ///    session's Vault Key and the session's own authenticated `vault_id`
    ///    (never a caller, file name or the target);
    /// 7. a fresh binding id and salt are drawn from the OS CSPRNG;
    /// 8. the core `bind_identical_remote` proposes the state. It requires equal
    ///    raw fingerprints, equal schema-3 counter revisions and a confirmed
    ///    `NotConfigured`; no state is constructed by this module;
    /// 9. the local file and the target are read again and must be byte-for-byte
    ///    what was inspected and the same physical files (the target again
    ///    distinct and singly named);
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
    /// * The target is first compared by canonical path string (ASCII
    ///   case-insensitive on Windows) and then, on the open handles, by volume and
    ///   128-bit file identifier (see `file_identity`), so a hard link to the
    ///   primary is refused. This is a policy, not a proof: it accepts only local
    ///   NTFS or ReFS volumes (FAT/exFAT, SMB and other network redirectors,
    ///   virtual volumes and unidentifiable filesystems are refused, including
    ///   legitimate ones) and a target with exactly one name. Driver-reported
    ///   filesystem and device properties cannot be independently guaranteed; ReFS
    ///   is accepted on documentation and has not been exercised; the checks hold
    ///   at the instants they ran and filesystem races are narrowed, not
    ///   eliminated. The identity is not persisted: every save replaces the
    ///   primary file.
    /// * The adapter's own length-and-timestamp checks and the check-then-use
    ///   windows documented on [`SyncFileTarget`] also apply.
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

        // Steps 2 to 6: the read-only examination shared with the preparation
        // step. The primary stays open (inside `primary`) until this returns.
        let Examined {
            primary,
            local_locator,
            present,
            target_facts,
            inspection,
        } = self.examine_identical_target(store, target, read)?;

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
        // observations the proposal rests on, now including the physical files.
        // This narrows the window; it does not close it.
        match self.hold_local_primary() {
            Some(again)
                if again.raw == primary.raw
                    && matches!(
                        (&again.physical, &primary.physical),
                        (Ok(now), Ok(held)) if now.identity() == held.identity()
                    ) => {}
            _ => {
                return Err(Refusal::Unavailable(
                    SyncStateUnavailable::LocalVaultChanged,
                ))
            }
        }

        match read(target) {
            SyncFileRead::Present(again)
                if again.target() == present.target()
                    && again.candidate_raw() == present.candidate_raw() =>
            {
                let again_facts = physical_distinct(&primary, &again)?;

                if again_facts.identity() != target_facts.identity() {
                    return Err(Refusal::EvidenceChanged);
                }
            }
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

    /// The read-only examination both the binding operation and the preparation
    /// step rest on (steps 2 to 6 of
    /// [`bind_existing_identical_target`](Self::bind_existing_identical_target)),
    /// in exactly that order: hold the primary, resolve the local locator,
    /// require a confirmed `NotConfigured`, refuse a UNC target and the vault's
    /// own files, read the target once, require a distinct physical file, and
    /// authenticate both byte strings under this session's Vault Key. It writes
    /// nothing, creates nothing and draws no randomness. The returned
    /// [`Examined`] keeps the primary open.
    fn examine_identical_target(
        &self,
        store: &SyncStateStore,
        target: &SyncFileTarget,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
    ) -> Result<Examined, InitialBindingRefusal> {
        use InitialBindingRefusal as Refusal;

        // The primary is opened once; its bytes and physical facts come from this
        // handle, which stays open until the caller is done with the result.
        let primary = self.hold_local_primary().ok_or(Refusal::Unavailable(
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

        // Refused before anything touches the network: a UNC path (also in its
        // verbatim form) is never eligible, and is not resolved or read.
        if target_is_unc(target) {
            return Err(Refusal::TargetIdentityUncertain);
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

        // Same file, or an identity that cannot be established, is refused before
        // the bytes are even authenticated.
        let target_facts = physical_distinct(&primary, &present)?;

        let inspection = inspect_remote_bytes(
            &self.vault_key,
            self.data.vault_id,
            &primary.raw,
            present.candidate_raw(),
            None,
        )
        .map_err(Refusal::Inspection)?;

        Ok(Examined {
            primary,
            local_locator,
            present,
            target_facts,
            inspection,
        })
    }

    /// First half of the initial-binding consent (Stage 1U-4 B1h): examine
    /// `target` read-only and, if it is a candidate for
    /// [`bind_existing_identical_target`](Self::bind_existing_identical_target),
    /// remember that fact in this session and return what the user must be shown.
    /// Internal: no command, event or UI calls it, and it enables no
    /// synchronization.
    ///
    /// **Nothing is bound, written or created.** Any earlier pending preparation
    /// is discarded **first**, before any filesystem or cryptographic work, so a
    /// failed attempt can never leave an older preparation usable. The
    /// examination is the one the binding operation itself starts with (see
    /// `examine_identical_target`), followed by a mirror of the core's
    /// preconditions for identical bytes: equal fingerprints and schema-3 counter
    /// revisions on both sides. That mirror only lets the preview refuse early; the
    /// core decides again at confirmation, and a successful preparation promises
    /// nothing about it.
    ///
    /// The pending preparation expires after 120 seconds, is dropped with this
    /// session, and is spent by the first
    /// [`confirm_initial_binding`](Self::confirm_initial_binding) after it.
    pub fn prepare_initial_binding(
        &mut self,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
    ) -> Result<InitialBindingPreview, InitialBindingRefusal> {
        // Before anything that can fail, including opening the store. A reset
        // preparation is voided too: the two approvals exclude each other.
        self.pending_initial_binding = None;
        self.pending_binding_reset = None;

        let store = SyncStateStore::new(root.path())
            .map_err(|_| InitialBindingRefusal::Unavailable(SyncStateUnavailable::Root))?;

        self.prepare_initial_binding_in(
            &store,
            target,
            &mut SyncFileTarget::read,
            &mut |buffer| getrandom::fill(buffer).is_ok(),
            Instant::now(),
        )
    }

    /// [`prepare_initial_binding`](Self::prepare_initial_binding) over an
    /// explicit store, read step, entropy source and clock. Crate-private so only
    /// the crate's own tests can substitute them.
    pub(crate) fn prepare_initial_binding_in(
        &mut self,
        store: &SyncStateStore,
        target: &SyncFileTarget,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
        entropy: &mut dyn FnMut(&mut [u8]) -> bool,
        now: Instant,
    ) -> Result<InitialBindingPreview, InitialBindingRefusal> {
        use InitialBindingRefusal as Refusal;

        self.pending_initial_binding = None;
        self.pending_binding_reset = None;

        let examined = self.examine_identical_target(store, target, read)?;

        // The core's preconditions for binding identical bytes, in the core's
        // order. Not authoritative: confirmation runs the core transition.
        let local_fingerprint = *examined.inspection.local_fingerprint();

        if local_fingerprint != *examined.inspection.candidate_fingerprint() {
            return Err(Refusal::Transition(TransitionRefusal::RemoteDiffers));
        }

        let revisions = examined.inspection.inspection();

        let AuthenticatedRevision::Counter(local_revision) = revisions.local_revision() else {
            return Err(Refusal::Transition(TransitionRefusal::LocalUnversioned));
        };

        let AuthenticatedRevision::Counter(remote_revision) = revisions.candidate_revision() else {
            return Err(Refusal::Transition(TransitionRefusal::RemoteUnversioned));
        };

        if local_revision != remote_revision {
            return Err(Refusal::Transition(TransitionRefusal::RemoteDiffers));
        }

        let mut id_bytes = [0u8; 16];

        if !entropy(&mut id_bytes) {
            return Err(Refusal::Randomness);
        }

        let id = uuid::Builder::from_random_bytes(id_bytes).into_uuid();

        self.pending_initial_binding = Some(PendingInitialBinding {
            id,
            target: target.clone(),
            local_fingerprint,
            target_identity: examined.target_facts.identity(),
            prepared_at: now,
        });

        Ok(InitialBindingPreview {
            preparation_id: id.to_string(),
            vault_file_name: self
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            target_path: target.locator().as_str().to_owned(),
        })
    }

    /// Second half of the initial-binding consent (Stage 1U-4 B1h): spend the
    /// pending preparation named by `preparation_id` and, if the vault and the
    /// target are still what it examined, run the unchanged
    /// [`bind_existing_identical_target`](Self::bind_existing_identical_target)
    /// with an approval made from that very preparation. Internal: no command,
    /// event or UI calls it.
    ///
    /// **The preparation is spent by every call**, whatever its outcome: it is
    /// removed from the session before anything is checked, so a stale, mistaken
    /// or failed confirmation can never be retried against the same preparation,
    /// and a double submit binds at most once. In order:
    ///
    /// 1. a preparation must be pending, and `preparation_id` must name it
    ///    ([`InitialBindingStale::NoPendingApproval`],
    ///    [`NotCurrentPreparation`](InitialBindingStale::NotCurrentPreparation));
    /// 2. it must be at most 120 seconds old
    ///    ([`Expired`](InitialBindingStale::Expired)); a stale confirmation reads
    ///    no file;
    /// 3. the vault file must still be exactly what was examined
    ///    ([`LocalVaultChanged`](InitialBindingStale::LocalVaultChanged); a file
    ///    that is no longer this session's envelope is the binding operation's own
    ///    `Unavailable(LocalVaultChanged)`);
    /// 4. one read of the target must give the same bytes from the same physical
    ///    file ([`TargetChanged`](InitialBindingStale::TargetChanged); an absent or
    ///    unavailable target is the binding operation's own refusal);
    /// 5. only then is the approval built and the unchanged binding operation run,
    ///    which repeats every one of its own checks.
    ///
    /// The id is correlation, not proof of consent: it ties this call to the
    /// preview that was shown. See [`InitialBindingApproval`] for what the whole
    /// flow does and does not guarantee.
    pub fn confirm_initial_binding(
        &mut self,
        root: &SyncStateRoot,
        preparation_id: &str,
    ) -> Result<InitialBindingOutcome, InitialBindingConfirmRefusal> {
        let store = match SyncStateStore::new(root.path()) {
            Ok(store) => store,
            Err(_) => {
                // Spent even though nothing could be checked.
                self.pending_initial_binding = None;
                self.pending_binding_reset = None;

                return Err(InitialBindingConfirmRefusal::Binding(
                    InitialBindingRefusal::Unavailable(SyncStateUnavailable::Root),
                ));
            }
        };

        self.confirm_initial_binding_in(
            &store,
            preparation_id,
            &mut SyncFileTarget::read,
            &mut |buffer| getrandom::fill(buffer).is_ok(),
            Instant::now(),
        )
    }

    /// [`confirm_initial_binding`](Self::confirm_initial_binding) over an explicit
    /// store, read step, entropy source and clock. Crate-private so only the
    /// crate's own tests can substitute them.
    pub(crate) fn confirm_initial_binding_in(
        &mut self,
        store: &SyncStateStore,
        preparation_id: &str,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
        entropy: &mut dyn FnMut(&mut [u8]) -> bool,
        now: Instant,
    ) -> Result<InitialBindingOutcome, InitialBindingConfirmRefusal> {
        use InitialBindingConfirmRefusal::{Binding, Stale};
        use InitialBindingRefusal as Refusal;

        // A reset preparation is voided by any confirmation attempt, and this
        // one is spent first and unconditionally.
        self.pending_binding_reset = None;

        let Some(pending) = self.pending_initial_binding.take() else {
            return Err(Stale(InitialBindingStale::NoPendingApproval));
        };

        if Uuid::parse_str(preparation_id) != Ok(pending.id) {
            return Err(Stale(InitialBindingStale::NotCurrentPreparation));
        }

        if now.saturating_duration_since(pending.prepared_at) > INITIAL_BINDING_APPROVAL_TTL {
            return Err(Stale(InitialBindingStale::Expired));
        }

        // Evidence re-check against the preview. The primary is held open only
        // for this block: the binding operation opens it again itself.
        {
            let primary = self
                .hold_local_primary()
                .ok_or(Binding(Refusal::Unavailable(
                    SyncStateUnavailable::LocalVaultChanged,
                )))?;

            if EnvelopeFingerprint::of_bytes(&primary.raw) != pending.local_fingerprint {
                return Err(Stale(InitialBindingStale::LocalVaultChanged));
            }

            let present = match read(&pending.target) {
                SyncFileRead::Present(present) => present,
                SyncFileRead::AbsentOnDisk => return Err(Binding(Refusal::TargetAbsentOnDisk)),
                SyncFileRead::Unavailable(reason) => {
                    return Err(Binding(Refusal::TargetUnavailable(reason)))
                }
            };

            if present.target() != pending.target.locator() {
                return Err(Binding(Refusal::EvidenceChanged));
            }

            // The target held the local vault's bytes at preparation, so the
            // preparation's local fingerprint is also the target's.
            if EnvelopeFingerprint::of_bytes(present.candidate_raw()) != pending.local_fingerprint {
                return Err(Stale(InitialBindingStale::TargetChanged));
            }

            match present.physical() {
                Ok(facts) if facts.identity() == pending.target_identity => {}
                Ok(_) => return Err(Stale(InitialBindingStale::TargetChanged)),
                Err(_) => return Err(Binding(Refusal::TargetIdentityUncertain)),
            }
        }

        let target = pending.target.clone();
        let approval = InitialBindingApproval::from_confirmed(pending);

        self.bind_existing_identical_target_in(store, &target, approval, read, entropy)
            .map_err(Binding)
    }

    /// Discard the pending initial-binding preparation, if any. Idempotent, and
    /// never an error.
    pub fn cancel_initial_binding(&mut self) {
        self.pending_initial_binding = None;
    }

    /// Sanitized, strictly read-only summary of this vault's local
    /// synchronization binding (Stage 1U-4 B1i). Internal: no command or UI calls
    /// it.
    ///
    /// It is [`load_sync_state`](Self::load_sync_state) re-expressed in fixed
    /// categories: a record is `Linked` only after the existing authenticated
    /// binding check (this session's `vault_id` and normalized location), and
    /// after a mismatch or any other failure the stored target is **not**
    /// exposed. The pending-push indication is read only from a verified record.
    /// It never reads the target, never repairs, writes, resets or creates
    /// anything, and assumes no provider authority.
    pub fn binding_status(&self, root: &SyncStateRoot) -> BindingStatus {
        let attention = |reason| BindingStatus {
            state: BindingState::NeedsAttention(reason),
            pending_push: PendingPushIndication::Unavailable,
        };

        match self.load_sync_state(root) {
            SessionSyncState::NotConfigured => BindingStatus {
                state: BindingState::NotConfigured,
                pending_push: PendingPushIndication::None,
            },
            SessionSyncState::Bound(bound) => {
                let state = bound.state();

                BindingStatus {
                    state: BindingState::Linked(LinkedTarget {
                        path: state.target_locator().as_str().to_owned(),
                    }),
                    pending_push: if state.pending_push().is_some() {
                        PendingPushIndication::Pending
                    } else {
                        PendingPushIndication::None
                    },
                }
            }
            SessionSyncState::Corrupt(reason) => attention(BindingAttention::Corrupt(reason)),
            SessionSyncState::UnsupportedVersion => attention(BindingAttention::UnsupportedVersion),
            SessionSyncState::Unreadable(reason) => attention(BindingAttention::Unreadable(reason)),
            SessionSyncState::BindingMismatch(mismatch) => {
                attention(BindingAttention::Mismatch(mismatch))
            }
            SessionSyncState::Unavailable(reason) => {
                attention(BindingAttention::Unavailable(reason))
            }
        }
    }

    /// First half of the explicit binding reset (Stage 1U-4 B1i): examine this
    /// location's stored synchronization state **read-only**, remember exactly
    /// what was seen, and return what the user must be shown. Internal: no
    /// command, event or UI calls it, and nothing is removed.
    ///
    /// Any earlier reset preparation **and any pending initial-binding
    /// preparation** are discarded first, before any filesystem work, so a failed
    /// attempt never leaves an older approval usable.
    ///
    /// # What is resettable
    ///
    /// Only states for which exact evidence of every stored byte can be captured
    /// ([`SyncStateStore::evidence`]) and that an explicit reset can fully
    /// remove:
    ///
    /// * a verified binding (with or without a pending push);
    /// * a readable record for another vault or location;
    /// * a corrupt record (any decodable-or-not bytes, empty included) or one of
    ///   an unsupported version;
    /// * recovery artifacts of an interrupted write with no record.
    ///
    /// Refused, and **intentionally not resettable**: no state at all
    /// ([`NothingToReset`](BindingResetRefusal::NothingToReset)); any
    /// `Unreadable` state other than unresolved artifacts (an I/O or permission
    /// failure, a directory, junction or symlink where a file belongs, too many
    /// entries); and anything whose evidence cannot be captured (an inaccessible
    /// or oversized record or artifact). Their contents are unknown, so no
    /// confirmation could be shown to be about them.
    ///
    /// The state is read, bound by evidence, read again and bound again; the two
    /// must agree, or the preparation is refused as changed.
    pub fn prepare_binding_reset(
        &mut self,
        root: &SyncStateRoot,
    ) -> Result<BindingResetPreview, BindingResetRefusal> {
        self.pending_initial_binding = None;
        self.pending_binding_reset = None;

        let store = SyncStateStore::new(root.path())
            .map_err(|_| BindingResetRefusal::Unavailable(SyncStateUnavailable::Root))?;

        self.prepare_binding_reset_in(
            &store,
            &mut |buffer| getrandom::fill(buffer).is_ok(),
            Instant::now(),
        )
    }

    /// [`prepare_binding_reset`](Self::prepare_binding_reset) over an explicit
    /// store, entropy source and clock. Crate-private so only the crate's own
    /// tests can substitute them.
    pub(crate) fn prepare_binding_reset_in(
        &mut self,
        store: &SyncStateStore,
        entropy: &mut dyn FnMut(&mut [u8]) -> bool,
        now: Instant,
    ) -> Result<BindingResetPreview, BindingResetRefusal> {
        self.pending_initial_binding = None;
        self.pending_binding_reset = None;

        let (local_locator, class, evidence) = self.examine_binding_reset(store)?;

        let mut id_bytes = [0u8; 16];

        if !entropy(&mut id_bytes) {
            return Err(BindingResetRefusal::Randomness);
        }

        let id = uuid::Builder::from_random_bytes(id_bytes).into_uuid();

        self.pending_binding_reset = Some(PendingBindingReset {
            id,
            local_locator,
            subject: class.subject,
            evidence,
            prepared_at: now,
        });

        Ok(BindingResetPreview {
            preparation_id: id.to_string(),
            subject: class.subject,
            target_path: class.target_path,
            pending_push: class.pending_push,
        })
    }

    /// Second half of the explicit binding reset (Stage 1U-4 B1i): spend the
    /// pending preparation named by `preparation_id` and, if the stored state is
    /// still exactly what it examined, remove this location's sync-state record
    /// and recognized recovery artifacts with the store's conditional deletion.
    /// Internal: no command, event or UI calls it.
    ///
    /// **The preparation is spent by every call**, whatever its outcome, and any
    /// pending initial-binding preparation is discarded too. In order:
    ///
    /// 1. a preparation must be pending and `preparation_id` must name it, and it
    ///    must be at most 120 seconds old ([`BindingResetStale`]);
    /// 2. the vault file must still be this session's, and its normalized location
    ///    must equal the prepared one;
    /// 3. the state is examined again exactly as at preparation (same
    ///    resettability rules, same load, evidence, load, evidence agreement) and
    ///    must be the same kind with equal evidence. A state that is now **gone**
    ///    is [`RecordChanged`](BindingResetStale::RecordChanged), never a reset
    ///    performed here;
    /// 4. only then `SyncStateStore::delete_if_evidence_matches` runs, which
    ///    compares evidence once more immediately before its first removal;
    /// 5. a fresh load must report that nothing is configured.
    ///
    /// # Outcomes
    ///
    /// * [`BindingResetOutcome::ResetAndVerified`]: removal verified by the store
    ///   **and** by the fresh load.
    /// * `Stale`, `Refused`, `NotRemoved`: nothing was removed by this call.
    /// * `Ambiguous`: removal may have happened in part (`IncompleteDeletion`) or
    ///   the fresh load did not confirm absence. Never reported as success, never
    ///   retried; the binding is not rebuilt and nothing is published.
    ///
    /// # Not guaranteed
    ///
    /// This is a read-compare-delete sequence, **not** an atomic cross-process
    /// compare-and-swap. The exclusive session lock keeps other LocalVault
    /// sessions out of this vault, but a process that ignores it can still change
    /// the files between the comparison and the removal. The vault, its `.backup`
    /// and `.lock`, and any remote or selected sync file are never touched.
    pub fn confirm_binding_reset(
        &mut self,
        root: &SyncStateRoot,
        preparation_id: &str,
    ) -> Result<BindingResetOutcome, BindingResetConfirmRefusal> {
        let store = match SyncStateStore::new(root.path()) {
            Ok(store) => store,
            Err(_) => {
                // Spent even though nothing could be checked.
                self.pending_initial_binding = None;
                self.pending_binding_reset = None;

                return Err(BindingResetConfirmRefusal::Refused(
                    BindingResetRefusal::Unavailable(SyncStateUnavailable::Root),
                ));
            }
        };

        self.confirm_binding_reset_in(
            &store,
            preparation_id,
            &mut |store, locator| store.load(locator),
            Instant::now(),
        )
    }

    /// [`confirm_binding_reset`](Self::confirm_binding_reset) over an explicit
    /// store, post-deletion load and clock. Crate-private so only the crate's own
    /// tests can substitute them: the load seam exists to prove that a deletion
    /// which the store calls complete is still not reported as a success unless a
    /// fresh load agrees.
    pub(crate) fn confirm_binding_reset_in(
        &mut self,
        store: &SyncStateStore,
        preparation_id: &str,
        reload: &mut dyn FnMut(&SyncStateStore, &Locator) -> StateLoad,
        now: Instant,
    ) -> Result<BindingResetOutcome, BindingResetConfirmRefusal> {
        use BindingResetConfirmRefusal::{Ambiguous, NotRemoved, Refused, Stale};

        // A pending initial binding is voided by any reset confirmation attempt,
        // and the reset preparation is spent first and unconditionally.
        self.pending_initial_binding = None;

        let Some(pending) = self.pending_binding_reset.take() else {
            return Err(Stale(BindingResetStale::NoPendingReset));
        };

        if Uuid::parse_str(preparation_id) != Ok(pending.id) {
            return Err(Stale(BindingResetStale::NotCurrentPreparation));
        }

        if now.saturating_duration_since(pending.prepared_at) > BINDING_RESET_TTL {
            return Err(Stale(BindingResetStale::Expired));
        }

        let (local_locator, class, evidence) = match self.examine_binding_reset(store) {
            Ok(examined) => examined,
            // Prepared over an existing state, now confirmed absent: stale.
            Err(BindingResetRefusal::NothingToReset) => {
                return Err(Stale(BindingResetStale::RecordChanged))
            }
            Err(refusal) => return Err(Refused(refusal)),
        };

        if local_locator != pending.local_locator {
            return Err(Stale(BindingResetStale::LocatorChanged));
        }

        if class.subject != pending.subject || evidence != pending.evidence {
            return Err(Stale(BindingResetStale::RecordChanged));
        }

        match store.delete_if_evidence_matches(&local_locator, &pending.evidence) {
            Ok(DeleteOutcome::Removed) => {}
            // Nothing was there to remove: not a reset performed by this call.
            Ok(DeleteOutcome::AlreadyAbsent) | Err(ConditionalDeleteError::EvidenceChanged) => {
                return Err(Stale(BindingResetStale::RecordChanged))
            }
            Err(ConditionalDeleteError::Evidence(reason)) => {
                return Err(Refused(BindingResetRefusal::Evidence(reason)))
            }
            Err(error) if error.removal_may_have_started() => {
                return Err(Ambiguous(BindingResetAmbiguity::IncompleteDeletion))
            }
            Err(ConditionalDeleteError::Store(error)) => return Err(NotRemoved(error)),
        }

        // The store's own verification is not taken on trust alone.
        match reload(store, &local_locator) {
            StateLoad::NotConfigured => Ok(BindingResetOutcome::ResetAndVerified),
            _ => Err(Ambiguous(BindingResetAmbiguity::AbsenceNotConfirmed)),
        }
    }

    /// Discard the pending reset preparation, if any. Idempotent, and never an
    /// error. It does not touch a pending initial-binding preparation.
    pub fn cancel_binding_reset(&mut self) {
        self.pending_binding_reset = None;
    }

    /// The read-only examination both reset steps rest on. Requires the session's
    /// vault to still be the file at its path, resolves the local location,
    /// refuses states that are not resettable, and returns the kind of state with
    /// the exact evidence of it. The state is loaded and its evidence captured
    /// twice, and the two must agree. Writes and creates nothing.
    fn examine_binding_reset(
        &self,
        store: &SyncStateStore,
    ) -> Result<(Locator, ResetClass, RecordEvidence), BindingResetRefusal> {
        use BindingResetRefusal as Refusal;

        if self.current_local_raw().is_none() {
            return Err(Refusal::Unavailable(
                SyncStateUnavailable::LocalVaultChanged,
            ));
        }

        let local_locator = self
            .local_locator()
            .ok_or(Refusal::Unavailable(SyncStateUnavailable::LocalLocator))?;

        let first = store.load(&local_locator);
        let class = self.classify_for_reset(first.clone(), &local_locator)?;

        let before = store.evidence(&local_locator).map_err(Refusal::Evidence)?;
        let second = store.load(&local_locator);
        let after = store.evidence(&local_locator).map_err(Refusal::Evidence)?;

        if first != second || before != after {
            return Err(Refusal::RecordChanged);
        }

        // The load and the evidence must describe the same kind of state.
        let consistent = match class.subject {
            BindingResetSubject::InterruptedWriteRemnants => {
                !after.primary_present() && after.artifact_count() > 0
            }
            _ => after.primary_present(),
        };

        if !consistent {
            return Err(Refusal::RecordChanged);
        }

        Ok((local_locator, class, after))
    }

    /// Which resettable kind a load is, or why it is not resettable. The stored
    /// target and pending push are read only from a record that passed the
    /// authenticated binding check.
    fn classify_for_reset(
        &self,
        load: StateLoad,
        local_locator: &Locator,
    ) -> Result<ResetClass, BindingResetRefusal> {
        let unverified = |subject| ResetClass {
            subject,
            pending_push: PendingPushIndication::Unavailable,
            target_path: None,
        };

        match load {
            StateLoad::NotConfigured => Err(BindingResetRefusal::NothingToReset),
            StateLoad::Loaded(state) => {
                match bind_loaded(*state, self.data.vault_id, local_locator) {
                    SessionSyncState::Bound(bound) => {
                        let state = bound.state();

                        Ok(ResetClass {
                            subject: BindingResetSubject::VerifiedBinding,
                            pending_push: if state.pending_push().is_some() {
                                PendingPushIndication::Pending
                            } else {
                                PendingPushIndication::None
                            },
                            target_path: Some(state.target_locator().as_str().to_owned()),
                        })
                    }
                    // `bind_loaded` yields nothing else; anything unexpected is
                    // treated as unverified, never as a linked binding.
                    _ => Ok(unverified(BindingResetSubject::MismatchedRecord)),
                }
            }
            StateLoad::Corrupt(_) => Ok(unverified(BindingResetSubject::CorruptRecord)),
            StateLoad::UnsupportedVersion => Ok(unverified(BindingResetSubject::UnsupportedRecord)),
            StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts) => {
                Ok(unverified(BindingResetSubject::InterruptedWriteRemnants))
            }
            StateLoad::Unreadable(reason) => Err(BindingResetRefusal::UnreadableState(reason)),
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
    /// see a hard link or another second name of the same file. The physical
    /// check on the open handles (`physical_distinct`) does.
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

    /// The primary opened once, for the bound inspection: the same acceptance
    /// rules as [`current_local_raw`](Self::current_local_raw) (not a symlink, a
    /// regular file, `1..=MAX_VAULT_FILE_BYTES`, parses to exactly this session's
    /// envelope), but the file is opened without following a reparse point, judged
    /// again on the handle, read through that handle and queried for its physical
    /// facts on it. `None` means this is not the session's vault file.
    fn hold_local_primary(&self) -> Option<HeldPrimary> {
        fn acceptable(metadata: &fs::Metadata) -> bool {
            !metadata.file_type().is_symlink()
                && metadata.is_file()
                && metadata.len() != 0
                && metadata.len() <= MAX_VAULT_FILE_BYTES
        }

        if !acceptable(&fs::symlink_metadata(&self.path).ok()?) {
            return None;
        }

        let handle = open_without_following(&self.path).ok()?;
        let opened = handle.metadata().ok()?;

        // The object actually opened, not the path that may have been swapped.
        if !acceptable(&opened) {
            return None;
        }

        let mut raw = Vec::with_capacity(opened.len() as usize);

        (&handle)
            .take(MAX_VAULT_FILE_BYTES + 1)
            .read_to_end(&mut raw)
            .ok()?;

        if raw.is_empty() || raw.len() as u64 > MAX_VAULT_FILE_BYTES {
            return None;
        }

        let parsed: VaultEnvelope = serde_json::from_slice(&raw).ok()?;

        parsed.validate_header().ok()?;

        if parsed != self.envelope {
            return None;
        }

        let physical = facts_of(&handle);

        Some(HeldPrimary {
            _handle: handle,
            raw,
            physical,
        })
    }
}

/// The primary, opened once: its bytes and physical facts come from the same
/// handle, which is held open for the whole binding operation so the object
/// cannot be fully deleted (and its identifier reused) while the target is
/// examined. The facts are private to this module.
struct HeldPrimary {
    _handle: File,
    raw: Vec<u8>,
    physical: Result<HandleFacts, IdentityError>,
}

/// What [`UnlockedVaultSession::examine_identical_target`] established. Holds the
/// primary open, so its object cannot be fully deleted (and its identifier
/// reused) while the caller still relies on its physical facts.
struct Examined {
    primary: HeldPrimary,
    local_locator: Locator,
    present: PresentFile,
    target_facts: HandleFacts,
    inspection: BoundInspection,
}

/// Open for reading without following a reparse point, so a primary swapped for
/// a link after the path check is judged as the link, not as what it points to.
fn open_without_following(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

/// Whether the target names a network share (UNC, also verbatim). Such a path
/// is refused outright; this is a syntactic refusal only, never a reason to
/// accept anything.
fn target_is_unc(target: &SyncFileTarget) -> bool {
    use std::path::{Component, Prefix};

    matches!(
        Path::new(target.locator().as_str()).components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::UNC(..) | Prefix::VerbatimUNC(..))
    )
}

/// The target's facts if, and only if, the primary and the target are distinct
/// files on local NTFS or ReFS volumes and the target has exactly one name.
/// Fail closed: a lookup failure on either side is uncertainty, never
/// distinctness.
fn physical_distinct(
    primary: &HeldPrimary,
    present: &PresentFile,
) -> Result<HandleFacts, InitialBindingRefusal> {
    let (Ok(primary), Ok(target)) = (primary.physical.as_ref(), present.physical()) else {
        return Err(InitialBindingRefusal::TargetIdentityUncertain);
    };

    match compare(primary, target) {
        PhysicalVerdict::Distinct => Ok(*target),
        PhysicalVerdict::Same => Err(InitialBindingRefusal::TargetIsVaultFile),
        PhysicalVerdict::Uncertain => Err(InitialBindingRefusal::TargetIdentityUncertain),
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
    // * ReFS, FAT/exFAT, SMB and virtual volumes (none is available here): their
    //   refusal is covered only through injected facts, never claimed as a
    //   physical test. B1g tests below use real NTFS files beneath the
    //   git-ignored `.qa-local/file-identity-b1g-tests/`.
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
        use crate::vault::file_identity::FileSystemKind;
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

        const B1F_SCRATCH: &str = "sync-state-b1-tests";
        const B1G_SCRATCH: &str = "file-identity-b1g-tests";

        fn scratch_in(base: &str, name: &str) -> tempfile::TempDir {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(".qa-local")
                .join(base);

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

            /// As [`bare`](Self::bare), under the B1g scratch directory.
            fn bare_b1g(name: &str) -> Self {
                Self::from_vault_in(B1G_SCRATCH, name, |vault| {
                    UnlockedVaultSession::create(vault, test_password(), NOW_MS).unwrap()
                })
            }

            /// As [`new`](Self::new), under the B1g scratch directory: the
            /// target is an independent byte copy of the vault file.
            fn new_b1g(name: &str) -> Self {
                let bx = Self::bare_b1g(name);

                fs::copy(&bx.vault, &bx.remote).unwrap();

                bx
            }

            fn from_vault(name: &str, open: impl FnOnce(&Path) -> UnlockedVaultSession) -> Self {
                Self::from_vault_in(B1F_SCRATCH, name, open)
            }

            fn from_vault_in(
                base: &str,
                name: &str,
                open: impl FnOnce(&Path) -> UnlockedVaultSession,
            ) -> Self {
                let dir = scratch_in(base, name);
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

        // ---- Stage 1U-4 B1g: physical file identity ---------------------------
        //
        // Real NTFS files on this machine (D:, local). ReFS, FAT/exFAT, SMB and
        // virtual volumes are NOT available here: those verdicts are exercised
        // only through injected facts (the `PresentFile` test seam) and the pure
        // `compare` unit tests, and no physical result is claimed for them.

        fn entropy(buffer: &mut [u8]) -> bool {
            getrandom::fill(buffer).is_ok()
        }

        /// A real read whose physical facts are replaced (test seam).
        fn read_injecting(
            target: &SyncFileTarget,
            physical: Result<HandleFacts, IdentityError>,
        ) -> SyncFileRead {
            match target.read() {
                SyncFileRead::Present(present) => {
                    SyncFileRead::Present(present.with_physical_for_test(physical))
                }
                other => other,
            }
        }

        fn assert_nothing_created(bx: &Bx) {
            assert!(!bx.state_dir().exists());
            assert!(!bx.root.path().exists());
            assert!(bx.record().is_none());
        }

        // 2, 8. A hard link to the primary is the same physical file: refused,
        // no binding, and the primary, its backup and the link are untouched.
        #[test]
        fn a_hard_link_to_the_primary_is_refused_and_writes_nothing() {
            let bx = Bx::bare_b1g("b1g-hard-link");
            let backup = bx.session.backup_path().to_path_buf();

            fs::copy(&bx.vault, &backup).unwrap();
            fs::hard_link(&bx.vault, &bx.remote).unwrap();

            // The alias is a different path string and byte-identical.
            assert_eq!(fs::read(&bx.remote).unwrap(), fs::read(&bx.vault).unwrap());

            let vaults = snapshot(&bx.vaults_dir());
            let remote = snapshot(&bx.remote_dir());
            let vault_bytes = fs::read(&bx.vault).unwrap();
            let (result, reads) = bx.bind_counting(&bx.target);

            assert_eq!(result, Err(Refusal::TargetIsVaultFile));
            assert_eq!(reads, 1, "the check runs on the read target");
            assert_eq!(snapshot(&bx.vaults_dir()), vaults);
            assert_eq!(snapshot(&bx.remote_dir()), remote);
            assert_eq!(fs::read(&bx.vault).unwrap(), vault_bytes);
            assert_eq!(fs::read(&backup).unwrap(), vault_bytes);
            assert_nothing_created(&bx);
        }

        // 3. An independent copy with identical encrypted bytes is a distinct
        // physical file and binds. A primary that has another name elsewhere is
        // allowed: only the target must have exactly one name.
        #[test]
        fn an_independent_identical_copy_binds_even_if_the_primary_has_another_name() {
            let bx = Bx::new_b1g("b1g-independent-copy");
            let extra_name = bx.dir.path().join("another-name-of-the-primary.lvault");

            fs::hard_link(&bx.vault, &extra_name).unwrap();

            let vaults = snapshot(&bx.vaults_dir());
            let remote = snapshot(&bx.remote_dir());

            assert_eq!(bx.bind(), Ok(Outcome::BoundAndVerified));
            assert_eq!(snapshot(&bx.vaults_dir()), vaults);
            assert_eq!(snapshot(&bx.remote_dir()), remote);
            assert_eq!(bx.loaded().target_locator(), bx.target.locator());
            assert_eq!(names(&bx.state_dir()).len(), 1);
        }

        // 4. A distinct file with different bytes is still refused by the core.
        #[test]
        fn a_distinct_file_with_different_bytes_is_still_refused_by_the_core() {
            let bx = Bx::new_b1g("b1g-divergent");

            bx.put_remote(&bx.resealed(|data| data.revision = 7));
            bx.assert_refused(transition(TransitionRefusal::RemoteDiffers));
            assert_nothing_created(&bx);
        }

        // 5. A failed identity lookup is uncertainty, never distinctness.
        #[test]
        fn an_identity_that_cannot_be_established_is_refused_and_creates_nothing() {
            let bx = Bx::new_b1g("b1g-lookup-failure");
            let vaults = snapshot(&bx.vaults_dir());
            let remote = snapshot(&bx.remote_dir());

            for error in [IdentityError::Lookup, IdentityError::Unsupported] {
                let result = bx.bind_with(
                    &bx.target,
                    &mut |t| read_injecting(t, Err(error)),
                    &mut entropy,
                );

                assert_eq!(result, Err(Refusal::TargetIdentityUncertain), "{error:?}");
                assert_nothing_created(&bx);
            }

            assert_eq!(snapshot(&bx.vaults_dir()), vaults);
            assert_eq!(snapshot(&bx.remote_dir()), remote);

            // The control: the real read binds.
            assert_eq!(bx.bind(), Ok(Outcome::BoundAndVerified));
        }

        // 6a. A network (UNC) target is refused syntactically, before any read.
        #[cfg(windows)]
        #[test]
        fn a_unc_target_is_refused_before_it_is_read() {
            let bx = Bx::new_b1g("b1g-unc");

            for text in [
                r"\\localhost\share\t.lvault",
                r"\\?\UNC\localhost\share\t.lvault",
            ] {
                let unc = SyncFileTarget::from_path(Path::new(text)).unwrap();
                let (result, reads) = bx.bind_counting(&unc);

                assert_eq!(result, Err(Refusal::TargetIdentityUncertain), "{text}");
                assert_eq!(reads, 0, "a UNC target was read: {text}");
                assert_nothing_created(&bx);
            }
        }

        // 6b. Unsupported, non-local, degenerate, delete-pending and multiply
        // named targets (injected: no such volume is available here), and the
        // same identity (injected equal to the real primary's).
        #[test]
        fn unsupported_or_degenerate_target_facts_are_refused() {
            let bx = Bx::new_b1g("b1g-injected-facts");
            let facts = |volume: u64,
                         id: [u8; 16],
                         links: u32,
                         pending: bool,
                         filesystem: FileSystemKind,
                         local: bool| {
                HandleFacts::for_test(volume, id, links, pending, filesystem, local)
            };
            let ntfs = FileSystemKind::Ntfs;

            let cases = [
                (
                    "other filesystem",
                    facts(5, [9; 16], 1, false, FileSystemKind::Other, true),
                ),
                (
                    "not a local device",
                    facts(5, [9; 16], 1, false, ntfs, false),
                ),
                ("zero volume", facts(0, [9; 16], 1, false, ntfs, true)),
                ("zero file id", facts(5, [0; 16], 1, false, ntfs, true)),
                ("delete pending", facts(5, [9; 16], 1, true, ntfs, true)),
                ("two links", facts(5, [9; 16], 2, false, ntfs, true)),
                ("no links", facts(5, [9; 16], 0, false, ntfs, true)),
            ];

            for (name, injected) in cases {
                let result = bx.bind_with(
                    &bx.target,
                    &mut |t| read_injecting(t, Ok(injected)),
                    &mut entropy,
                );

                assert_eq!(result, Err(Refusal::TargetIdentityUncertain), "{name}");
                assert_nothing_created(&bx);
            }

            // The injected identity equals the real primary's: the same file.
            let primary = facts_of(&File::open(&bx.vault).unwrap()).unwrap();
            let same = facts(5, [9; 16], 1, false, ntfs, true).with_identity_of(&primary);
            let result = bx.bind_with(
                &bx.target,
                &mut |t| read_injecting(t, Ok(same)),
                &mut entropy,
            );

            assert_eq!(result, Err(Refusal::TargetIsVaultFile));
            assert_nothing_created(&bx);

            // The control: trustworthy, distinct, singly named facts bind.
            let good = facts(5, [9; 16], 1, false, ntfs, true);

            assert_eq!(
                bx.bind_with(
                    &bx.target,
                    &mut |t| read_injecting(t, Ok(good)),
                    &mut entropy
                ),
                Ok(Outcome::BoundAndVerified)
            );
        }

        // 7. A target replaced between the two reads by a byte-identical but
        // physically different file is an observable change.
        #[test]
        fn a_target_replaced_by_an_identical_copy_between_reads_is_refused() {
            let bx = Bx::new_b1g("b1g-target-swapped");
            let (vault, remote) = (bx.vault.clone(), bx.remote.clone());
            let reads = Cell::new(0usize);

            let result = bx.bind_with(
                &bx.target,
                &mut |t| {
                    if reads.get() == 1 {
                        let staging = remote.with_file_name("staging.lvault");

                        fs::copy(&vault, &staging).unwrap();
                        fs::rename(&staging, &remote).unwrap();
                    }

                    reads.set(reads.get() + 1);

                    t.read()
                },
                &mut entropy,
            );

            assert_eq!(result, Err(Refusal::EvidenceChanged));
            assert_eq!(reads.get(), 2);
            assert_nothing_created(&bx);
        }

        // 7b. A second name for the target created between the reads.
        #[test]
        fn a_hard_link_added_to_the_target_between_reads_is_refused() {
            let bx = Bx::new_b1g("b1g-target-linked");
            let remote = bx.remote.clone();
            let reads = Cell::new(0usize);

            let result = bx.bind_with(
                &bx.target,
                &mut |t| {
                    if reads.get() == 1 {
                        fs::hard_link(&remote, remote.with_file_name("alias.lvault")).unwrap();
                    }

                    reads.set(reads.get() + 1);

                    t.read()
                },
                &mut entropy,
            );

            assert_eq!(result, Err(Refusal::TargetIdentityUncertain));
            assert_eq!(reads.get(), 2);
            assert_nothing_created(&bx);
        }

        // 7c. The primary path re-pointed (byte-identical, different file)
        // between the checks.
        #[test]
        fn a_primary_path_re_pointed_between_checks_is_refused() {
            let bx = Bx::new_b1g("b1g-primary-swapped");
            let vault = bx.vault.clone();
            let reads = Cell::new(0usize);

            let result = bx.bind_with(
                &bx.target,
                &mut |t| {
                    let read = t.read();

                    // After the first read, before the primary is re-checked.
                    if reads.get() == 0 {
                        let staging = vault.with_file_name("staging.lvault");

                        fs::copy(&vault, &staging).unwrap();
                        fs::rename(&staging, &vault).unwrap();
                    }

                    reads.set(reads.get() + 1);

                    read
                },
                &mut entropy,
            );

            assert_eq!(
                result,
                Err(Refusal::Unavailable(
                    SyncStateUnavailable::LocalVaultChanged
                ))
            );
            assert_eq!(reads.get(), 1, "the target was read again after the change");
            assert_nothing_created(&bx);
        }

        // A primary replaced by a file symlink is judged as the link, not
        // followed. Needs the symlink privilege; skipped (and said so) without it.
        #[cfg(windows)]
        #[test]
        fn a_primary_replaced_by_a_file_symlink_is_not_followed() {
            let bx = Bx::new_b1g("b1g-primary-symlink");
            let real = bx.dir.path().join("real-copy.lvault");

            fs::copy(&bx.vault, &real).unwrap();
            fs::remove_file(&bx.vault).unwrap();

            if std::os::windows::fs::symlink_file(&real, &bx.vault).is_err() {
                eprintln!("SKIPPED: the file-symlink privilege is unavailable");

                return;
            }

            let (result, reads) = bx.bind_counting(&bx.target);

            assert_eq!(
                result,
                Err(Refusal::Unavailable(
                    SyncStateUnavailable::LocalVaultChanged
                ))
            );
            assert_eq!(reads, 0);
            assert_nothing_created(&bx);

            fs::remove_file(&bx.vault).unwrap();
        }

        // 11. The B1c/B1e observation never reads the physical facts: a failed
        // lookup changes nothing about what it records.
        #[test]
        fn observation_ignores_a_failed_physical_lookup() {
            let outcome = |inject: bool| {
                let bx = Bx::new_b1g(if inject {
                    "b1g-observe-injected"
                } else {
                    "b1g-observe-real"
                });

                assert_eq!(bx.bind(), Ok(Outcome::BoundAndVerified));

                let unchanged = bx
                    .session
                    .observe_remote_target_with(&bx.root, &bx.target, |t| {
                        if inject {
                            read_injecting(t, Err(IdentityError::Lookup))
                        } else {
                            t.read()
                        }
                    });

                bx.put_remote(&bx.resealed(|data| data.revision = 7));

                let raised = bx
                    .session
                    .observe_remote_target_with(&bx.root, &bx.target, |t| {
                        if inject {
                            read_injecting(t, Err(IdentityError::Lookup))
                        } else {
                            t.read()
                        }
                    });

                let SyncBase::Based(checkpoint) = *bx.loaded().base() else {
                    panic!("expected a based state");
                };

                (unchanged, raised, checkpoint.high_water().revision())
            };

            let real = outcome(false);
            let injected = outcome(true);

            assert_eq!(real.0, Ok(RemoteObservationOutcome::Unchanged));
            assert_eq!(real.1, Ok(RemoteObservationOutcome::HighWaterRaised));
            assert_eq!(real.2, 7);
            assert_eq!(injected, real);
        }

        // 12. The new refusal and the physical facts print nothing identifying.
        #[test]
        fn physical_checks_reveal_no_path_identifier_or_content() {
            let bx = Bx::new_b1g("b1g-LEAKMARK-leak");
            let mut shown: Vec<String> = Vec::new();

            let mut note = |result: Result<Outcome, Refusal>| {
                shown.push(format!("{result:?}"));

                if let Err(error) = result {
                    shown.push(error.to_string());
                    shown.push(format!("{error:?}"));
                }
            };

            note(Err(Refusal::TargetIdentityUncertain));
            note(bx.bind_with(
                &bx.target,
                &mut |t| read_injecting(t, Err(IdentityError::Lookup)),
                &mut entropy,
            ));

            // A hard link to the primary.
            let link = bx.remote_dir().join("link.lvault");

            fs::hard_link(&bx.vault, &link).unwrap();

            let linked = SyncFileTarget::from_path(&link).unwrap();

            note(bx.bind_with(&linked, &mut |t| t.read(), &mut entropy));

            if let SyncFileRead::Present(present) = bx.target.read() {
                shown.push(format!("{present:?}"));
                shown.push(format!("{:?}", present.physical()));
                shown.push(format!(
                    "{:?}",
                    present.physical().map(|facts| facts.identity())
                ));
            }

            shown.push(format!("{:?}", IdentityError::Lookup));
            shown.push(IdentityError::Lookup.to_string());

            let needles = vec![
                bx.dir.path().to_string_lossy().into_owned(),
                bx.remote.to_string_lossy().into_owned(),
                bx.local.clone(),
                bx.vault_id.to_string(),
                bx.vault_id.simple().to_string(),
                "target.lvault".to_owned(),
                "vault.lvault".to_owned(),
                "link.lvault".to_owned(),
                ".qa-local".to_owned(),
                "LEAKMARK".to_owned(),
                MASTER_PASSWORD.to_owned(),
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

        // ---- Stage 1U-4 B1h: Rust-owned explicit consent ----------------------
        //
        // Prepare (read-only) and confirm (spends the preparation, then runs the
        // unchanged B1f operation). All scratch is under the same git-ignored
        // `.qa-local/sync-state-b1-tests/` as the B1f tests, via `Bx`.
        //
        // Not covered here, and why:
        // * `PersistenceUnverified` through `confirm`: the store's fault hooks are
        //   private to `sync_state_store` (out of scope for B1h). Its production
        //   path is the unchanged B1f one and is classified by the B1f tests;
        //   `confirm` only wraps it in `Binding(..)`, shown below for the other
        //   post-check refusals (`RecordAppeared`, `Randomness`).
        // * Any user interface or command: none exists.
        mod consent {
            use super::*;

            type Stale = InitialBindingStale;
            type Confirm = InitialBindingConfirmRefusal;

            fn stale(reason: Stale) -> Confirm {
                Confirm::Stale(reason)
            }

            fn binding(refusal: Refusal) -> Confirm {
                Confirm::Binding(refusal)
            }

            fn prepare_target(
                bx: &mut Bx,
                target: &SyncFileTarget,
            ) -> Result<InitialBindingPreview, Refusal> {
                let store = bx.store();

                bx.session.prepare_initial_binding_in(
                    &store,
                    target,
                    &mut |t| t.read(),
                    &mut entropy,
                    Instant::now(),
                )
            }

            fn prepare(bx: &mut Bx) -> Result<InitialBindingPreview, Refusal> {
                bx.session.prepare_initial_binding(&bx.root, &bx.target)
            }

            fn prepared(bx: &mut Bx) -> String {
                prepare(bx)
                    .expect("the preparation succeeds")
                    .preparation_id()
                    .to_owned()
            }

            fn confirm(bx: &mut Bx, id: &str) -> Result<Outcome, Confirm> {
                bx.session.confirm_initial_binding(&bx.root, id)
            }

            /// Confirm with a counting real read and counting real entropy.
            fn confirm_counting(
                bx: &mut Bx,
                id: &str,
                now: Instant,
            ) -> (Result<Outcome, Confirm>, usize, usize) {
                let reads = Cell::new(0usize);
                let draws = Cell::new(0usize);
                let store = bx.store();

                let result = bx.session.confirm_initial_binding_in(
                    &store,
                    id,
                    &mut |t| {
                        reads.set(reads.get() + 1);

                        t.read()
                    },
                    &mut |buffer| {
                        draws.set(draws.get() + 1);

                        getrandom::fill(buffer).is_ok()
                    },
                    now,
                );

                (result, reads.get(), draws.get())
            }

            fn unknown_id() -> String {
                Uuid::from_u128(0x0123_4567_89ab_4def_8123_4567_89ab_cdef).to_string()
            }

            /// A second, valid, byte-identical target in the remote folder.
            fn second_target(bx: &Bx) -> SyncFileTarget {
                let path = bx.remote_dir().join("second.lvault");

                fs::copy(&bx.vault, &path).unwrap();

                SyncFileTarget::from_path(&path).unwrap()
            }

            /// The refusal equals the B1f operation's own for the same target,
            /// creates nothing and leaves no pending preparation.
            fn assert_prepare_refused(bx: &mut Bx, target: &SyncFileTarget, expected: Refusal) {
                assert_eq!(
                    bx.bind_counting(target).0,
                    Err(expected),
                    "the B1f operation disagrees"
                );

                let state_existed = bx.state_dir().exists();
                let record = bx.record().map(|path| fs::read(path).unwrap());

                assert_eq!(prepare_target(bx, target).map(|_| ()), Err(expected));
                assert_eq!(
                    confirm(bx, &unknown_id()),
                    Err(stale(Stale::NoPendingApproval))
                );
                assert_eq!(bx.state_dir().exists(), state_existed);
                assert_eq!(bx.record().map(|path| fs::read(path).unwrap()), record);
            }

            // 1. A successful preparation returns the preview and changes nothing.
            #[test]
            fn preparing_returns_a_preview_and_changes_nothing() {
                let mut bx = Bx::new("b1h-prepare");
                let vaults = snapshot(&bx.vaults_dir());
                let remote = snapshot(&bx.remote_dir());
                let vault_bytes = fs::read(&bx.vault).unwrap();
                let reads = Cell::new(0usize);
                let target = bx.target.clone();
                let store = bx.store();

                let preview = bx
                    .session
                    .prepare_initial_binding_in(
                        &store,
                        &target,
                        &mut |t| {
                            reads.set(reads.get() + 1);

                            t.read()
                        },
                        &mut entropy,
                        Instant::now(),
                    )
                    .unwrap();

                assert_eq!(reads.get(), 1, "the target is read exactly once");
                assert_eq!(preview.vault_file_name(), "vault.lvault");
                assert_eq!(preview.target_path(), bx.target.locator().as_str());

                let id = Uuid::parse_str(preview.preparation_id()).unwrap();

                assert_eq!(id.get_version_num(), 4);

                // Nothing was bound, written or created, not even the root.
                assert_eq!(
                    bx.session.load_sync_state(&bx.root),
                    SessionSyncState::NotConfigured
                );
                assert!(!bx.root.path().exists());
                assert!(bx.record().is_none());
                assert_eq!(snapshot(&bx.vaults_dir()), vaults);
                assert_eq!(snapshot(&bx.remote_dir()), remote);
                assert_eq!(fs::read(&bx.vault).unwrap(), vault_bytes);
                assert_eq!(fs::read(&bx.remote).unwrap(), vault_bytes);
            }

            // 2. Every refusal the B1f operation makes before the core transition
            // is made by the preparation too, creates nothing and leaves nothing
            // confirmable.
            #[test]
            fn preparation_refusals_mirror_the_binding_operation_and_leave_nothing_pending() {
                // Differs, and not this vault.
                let mut bx = Bx::new("b1h-refuse-differs");
                let target = bx.target.clone();

                bx.put_remote(&bx.resealed(|data| data.revision = 7));
                assert_prepare_refused(
                    &mut bx,
                    &target,
                    transition(TransitionRefusal::RemoteDiffers),
                );
                bx.put_remote(&bx.resealed(|data| data.vault_id = OTHER_VAULT_ID));
                assert_prepare_refused(
                    &mut bx,
                    &target,
                    candidate_rejected(PayloadRejection::VaultIdMismatch),
                );
                bx.put_remote(b"garbage");
                assert_prepare_refused(
                    &mut bx,
                    &target,
                    inspection(BoundInspectionError::MalformedEnvelope {
                        input: EnvelopeInput::Candidate,
                    }),
                );

                // A legacy local vault.
                let mut legacy = Bx::legacy("b1h-refuse-legacy");
                let target = legacy.target.clone();

                assert_prepare_refused(
                    &mut legacy,
                    &target,
                    transition(TransitionRefusal::LocalUnversioned),
                );

                // The vault's own file.
                let mut own = Bx::new("b1h-refuse-own");
                let primary = SyncFileTarget::from_path(&own.vault).unwrap();

                assert_prepare_refused(&mut own, &primary, Refusal::TargetIsVaultFile);

                // A hard link to the primary.
                let mut linked = Bx::bare_b1g("b1h-refuse-hard-link");
                let target = linked.target.clone();

                fs::hard_link(&linked.vault, &linked.remote).unwrap();
                assert_prepare_refused(&mut linked, &target, Refusal::TargetIsVaultFile);

                // A network path.
                #[cfg(windows)]
                {
                    let mut unc = Bx::new("b1h-refuse-unc");
                    let target =
                        SyncFileTarget::from_path(Path::new(r"\\localhost\share\t.lvault"))
                            .unwrap();

                    assert_prepare_refused(&mut unc, &target, Refusal::TargetIdentityUncertain);
                }

                // Absent, and unavailable.
                let mut absent = Bx::bare("b1h-refuse-absent");
                let target = absent.target.clone();

                assert_prepare_refused(&mut absent, &target, Refusal::TargetAbsentOnDisk);
                fs::create_dir(&absent.remote).unwrap();
                assert_prepare_refused(
                    &mut absent,
                    &target,
                    Refusal::TargetUnavailable(UnavailableReason::UnexpectedObject),
                );

                // An existing record, and a corrupt one.
                let mut recorded = Bx::new("b1h-refuse-record");
                let target = recorded.target.clone();

                recorded.publish(&recorded.based());
                assert_prepare_refused(&mut recorded, &target, Refusal::ExistingBinding);

                let record = recorded.record().unwrap();

                fs::write(&record, b"this is not a sync state").unwrap();
                assert_prepare_refused(
                    &mut recorded,
                    &target,
                    Refusal::Corrupt(CorruptReason::Undecodable),
                );
                assert_eq!(fs::read(&record).unwrap(), b"this is not a sync state");
            }

            // 3. The correct id binds, and only the record changes.
            #[test]
            fn confirming_the_current_preparation_binds_the_selected_target() {
                let mut bx = Bx::new("b1h-confirm");
                let vaults = snapshot(&bx.vaults_dir());
                let remote = snapshot(&bx.remote_dir());
                let id = prepared(&mut bx);

                assert_eq!(confirm(&mut bx, &id), Ok(Outcome::BoundAndVerified));

                let state = bx.loaded();

                assert_eq!(state.target_locator(), bx.target.locator());
                assert_eq!(state.local_locator().as_str(), bx.local);
                assert!(state.vault_tag().matches_vault(bx.vault_id));
                assert_eq!(snapshot(&bx.vaults_dir()), vaults);
                assert_eq!(snapshot(&bx.remote_dir()), remote);
                assert_eq!(names(bx.root.path()), [SYNC_STATE_DIRECTORY]);
                assert_eq!(names(&bx.state_dir()).len(), 1);
            }

            // 4. A double submit binds at most once and cannot touch the record.
            #[test]
            fn a_second_confirmation_is_stale_and_changes_nothing() {
                let mut bx = Bx::new("b1h-double");
                let id = prepared(&mut bx);

                assert_eq!(confirm(&mut bx, &id), Ok(Outcome::BoundAndVerified));

                let record = bx.record_bytes();
                let before = snapshot(&bx.state_dir());

                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingApproval)));
                assert_eq!(bx.record_bytes(), record);
                assert_eq!(snapshot(&bx.state_dir()), before);
            }

            // 5. A wrong, garbage or foreign id binds nothing and spends the
            // preparation: the user has to prepare again.
            #[test]
            fn a_wrong_id_is_stale_and_spends_the_preparation() {
                let mut bx = Bx::new("b1h-wrong-id");

                for wrong in [
                    "",
                    "not-an-id",
                    "00000000-0000-0000-0000-000000000000",
                    &unknown_id(),
                ] {
                    let id = prepared(&mut bx);
                    let (result, reads, draws) = confirm_counting(&mut bx, wrong, Instant::now());

                    assert_eq!(
                        result,
                        Err(stale(Stale::NotCurrentPreparation)),
                        "{wrong:?}"
                    );
                    assert_eq!((reads, draws), (0, 0), "a stale id read or drew");
                    assert!(!bx.root.path().exists());

                    // Spent: not even the right id works now.
                    assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingApproval)));
                    assert!(!bx.root.path().exists());
                }
            }

            // 6. A later attempt voids the earlier preparation, even a failed
            // later attempt; a preview for one target cannot confirm another.
            #[test]
            fn a_new_preparation_voids_the_previous_one_even_when_it_fails() {
                let mut bx = Bx::new("b1h-supersede");
                let first = bx.target.clone();
                let second = second_target(&bx);
                let missing =
                    SyncFileTarget::from_path(&bx.remote_dir().join("none.lvault")).unwrap();

                // A, then a failing B.
                let id_a = prepare_target(&mut bx, &first)
                    .unwrap()
                    .preparation_id()
                    .to_owned();

                assert_eq!(
                    prepare_target(&mut bx, &missing).map(|_| ()),
                    Err(Refusal::TargetAbsentOnDisk)
                );
                assert_eq!(
                    confirm(&mut bx, &id_a),
                    Err(stale(Stale::NoPendingApproval))
                );

                // A, then a successful B: A's id cannot confirm, and the attempt
                // consumes B as well.
                let id_a = prepare_target(&mut bx, &first)
                    .unwrap()
                    .preparation_id()
                    .to_owned();
                let id_b = prepare_target(&mut bx, &second)
                    .unwrap()
                    .preparation_id()
                    .to_owned();

                assert_ne!(id_a, id_b);
                assert_eq!(
                    confirm(&mut bx, &id_a),
                    Err(stale(Stale::NotCurrentPreparation))
                );
                assert_eq!(
                    confirm(&mut bx, &id_b),
                    Err(stale(Stale::NoPendingApproval))
                );
                assert!(!bx.root.path().exists());

                // A, then B, then B's own id: B and only B is bound.
                prepare_target(&mut bx, &first).unwrap();

                let id_b = prepare_target(&mut bx, &second)
                    .unwrap()
                    .preparation_id()
                    .to_owned();

                assert_eq!(confirm(&mut bx, &id_b), Ok(Outcome::BoundAndVerified));
                assert_eq!(bx.loaded().target_locator(), second.locator());
                assert_ne!(bx.loaded().target_locator(), first.locator());
            }

            // 6b. Even a preparation that fails before any file is touched voids
            // the earlier one, and randomness is drawn only after the checks.
            #[test]
            fn a_failed_attempt_of_any_kind_voids_the_previous_preparation() {
                // The very first step fails: the vault file is no longer this
                // session's envelope. (An unusable application-data root cannot be
                // built in a test: `SyncStateRoot` only holds absolute paths, which
                // is the only thing `SyncStateStore::new` checks.)
                let mut bx = Bx::new("b1h-void-first-step");
                let id = prepared(&mut bx);
                let original = fs::read(&bx.vault).unwrap();

                fs::write(&bx.vault, bx.resealed(|_| {})).unwrap();

                assert_eq!(
                    prepare(&mut bx).map(|_| ()),
                    Err(Refusal::Unavailable(
                        SyncStateUnavailable::LocalVaultChanged
                    ))
                );

                fs::write(&bx.vault, original).unwrap();

                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingApproval)));

                // Randomness is unavailable.
                let id = prepared(&mut bx);
                let target = bx.target.clone();
                let store = bx.store();
                let draws = Cell::new(0usize);

                assert_eq!(
                    bx.session
                        .prepare_initial_binding_in(
                            &store,
                            &target,
                            &mut |t| t.read(),
                            &mut |_| {
                                draws.set(draws.get() + 1);

                                false
                            },
                            Instant::now(),
                        )
                        .map(|_| ()),
                    Err(Refusal::Randomness)
                );
                assert_eq!(draws.get(), 1);
                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingApproval)));
                assert!(!bx.root.path().exists());
            }

            // 7. A preparation is confirmable for 120 seconds and no longer; an
            // expired one reads no file.
            #[test]
            fn an_expired_preparation_is_stale_and_reads_nothing() {
                let base = Instant::now();

                let mut late = Bx::new("b1h-expired");
                let target = late.target.clone();
                let id = prepare_target_at(&mut late, &target, base);
                let (result, reads, draws) =
                    confirm_counting(&mut late, &id, base + Duration::from_secs(121));

                assert_eq!(result, Err(stale(Stale::Expired)));
                assert_eq!((reads, draws), (0, 0));
                assert!(!late.root.path().exists());
                assert_eq!(
                    confirm(&mut late, &id),
                    Err(stale(Stale::NoPendingApproval))
                );

                // The boundary is inclusive.
                let mut edge = Bx::new("b1h-ttl-edge");
                let target = edge.target.clone();
                let id = prepare_target_at(&mut edge, &target, base);
                let (result, _, _) =
                    confirm_counting(&mut edge, &id, base + Duration::from_secs(120));

                assert_eq!(result, Ok(Outcome::BoundAndVerified));
            }

            fn prepare_target_at(bx: &mut Bx, target: &SyncFileTarget, now: Instant) -> String {
                let store = bx.store();

                bx.session
                    .prepare_initial_binding_in(
                        &store,
                        target,
                        &mut |t| t.read(),
                        &mut entropy,
                        now,
                    )
                    .unwrap()
                    .preparation_id()
                    .to_owned()
            }

            // 8. The vault changing after the preparation is caught: an in-session
            // save is stale, an external rewrite is the binding operation's own
            // refusal.
            #[test]
            fn a_vault_that_changed_after_the_preparation_is_not_bound() {
                let mut saved = Bx::new("b1h-local-saved");
                let id = prepared(&mut saved);

                saved.session.data_mut().updated_at_ms = NOW_MS + 5;
                assert!(saved.session.save().unwrap());

                let (result, reads, _) = confirm_counting(&mut saved, &id, Instant::now());

                assert_eq!(result, Err(stale(Stale::LocalVaultChanged)));
                assert_eq!(reads, 0, "the target was read after the vault changed");
                assert!(!saved.root.path().exists());

                let mut rewritten = Bx::new("b1h-local-rewritten");
                let id = prepared(&mut rewritten);

                fs::write(&rewritten.vault, rewritten.resealed(|_| {})).unwrap();

                assert_eq!(
                    confirm(&mut rewritten, &id),
                    Err(binding(Refusal::Unavailable(
                        SyncStateUnavailable::LocalVaultChanged
                    )))
                );
                assert!(!rewritten.root.path().exists());
            }

            // 9. The target changing after the preparation is caught: different
            // bytes, an identical copy that is a different physical file, a
            // deleted target, a target that became a directory.
            #[test]
            fn a_target_that_changed_after_the_preparation_is_not_bound() {
                let mut bytes = Bx::new("b1h-target-bytes");
                let id = prepared(&mut bytes);

                bytes.put_remote(&bytes.resealed(|data| data.revision = 7));
                assert_eq!(confirm(&mut bytes, &id), Err(stale(Stale::TargetChanged)));
                assert!(!bytes.root.path().exists());

                // Same bytes, but another physical file at the same path.
                let mut copy = Bx::new("b1h-target-recreated");
                let id = prepared(&mut copy);
                let replacement = copy.remote_dir().join("replacement.lvault");

                fs::copy(&copy.vault, &replacement).unwrap();
                fs::remove_file(&copy.remote).unwrap();
                fs::rename(&replacement, &copy.remote).unwrap();

                assert_eq!(
                    fs::read(&copy.remote).unwrap(),
                    fs::read(&copy.vault).unwrap()
                );

                let (result, reads, _) = confirm_counting(&mut copy, &id, Instant::now());

                assert_eq!(result, Err(stale(Stale::TargetChanged)));
                assert_eq!(reads, 1, "only the one confirmation read ran");
                assert!(!copy.root.path().exists());

                // The control: untouched, the same preparation binds.
                let mut control = Bx::new("b1h-target-control");
                let id = prepared(&mut control);

                assert_eq!(confirm(&mut control, &id), Ok(Outcome::BoundAndVerified));

                let mut gone = Bx::new("b1h-target-deleted");
                let id = prepared(&mut gone);

                fs::remove_file(&gone.remote).unwrap();
                assert_eq!(
                    confirm(&mut gone, &id),
                    Err(binding(Refusal::TargetAbsentOnDisk))
                );
                assert!(!gone.root.path().exists());

                let mut directory = Bx::new("b1h-target-directory");
                let id = prepared(&mut directory);

                fs::remove_file(&directory.remote).unwrap();
                fs::create_dir(&directory.remote).unwrap();
                assert_eq!(
                    confirm(&mut directory, &id),
                    Err(binding(Refusal::TargetUnavailable(
                        UnavailableReason::UnexpectedObject
                    )))
                );
                assert!(!directory.root.path().exists());
            }

            // 10. A record that appeared after the preparation is never replaced,
            // whether before the confirmation or during it.
            #[test]
            fn a_record_that_appeared_after_the_preparation_is_never_replaced() {
                let mut early = Bx::new("b1h-record-early");
                let id = prepared(&mut early);

                early.publish(&early.based());

                let record = early.record_bytes();

                assert_eq!(
                    confirm(&mut early, &id),
                    Err(binding(Refusal::ExistingBinding))
                );
                assert_eq!(early.record_bytes(), record);

                // During the confirmation: published between the proposal and the
                // no-clobber publication (the third read of the target).
                let mut late = Bx::new("b1h-record-late");
                let id = prepared(&mut late);
                let rival = late.based();
                let rival_store = late.store();
                let store = late.store();
                let reads = Cell::new(0usize);
                let draws = Cell::new(0usize);

                let result = late.session.confirm_initial_binding_in(
                    &store,
                    &id,
                    &mut |t| {
                        reads.set(reads.get() + 1);

                        if reads.get() == 3 {
                            rival_store.create(&rival).unwrap();
                        }

                        t.read()
                    },
                    &mut |buffer| {
                        draws.set(draws.get() + 1);

                        getrandom::fill(buffer).is_ok()
                    },
                    Instant::now(),
                );

                assert_eq!(result, Err(binding(Refusal::RecordAppeared)));
                // Nothing is retried: the confirmation read once, the binding
                // read twice, and the identity and the salt were drawn once.
                assert_eq!((reads.get(), draws.get()), (3, 2));
                assert_eq!(late.loaded(), rival);
                assert_eq!(names(&late.state_dir()).len(), 1);
                assert_eq!(
                    confirm(&mut late, &id),
                    Err(stale(Stale::NoPendingApproval))
                );
            }

            // 11. Whatever refuses after the checks, the preparation is spent and
            // nothing is retried or repaired.
            #[test]
            fn unavailable_randomness_at_confirmation_spends_the_preparation() {
                let mut bx = Bx::new("b1h-confirm-entropy");
                let id = prepared(&mut bx);
                let store = bx.store();
                let reads = Cell::new(0usize);
                let draws = Cell::new(0usize);

                let result = bx.session.confirm_initial_binding_in(
                    &store,
                    &id,
                    &mut |t| {
                        reads.set(reads.get() + 1);

                        t.read()
                    },
                    &mut |_| {
                        draws.set(draws.get() + 1);

                        false
                    },
                    Instant::now(),
                );

                assert_eq!(result, Err(binding(Refusal::Randomness)));
                assert_eq!((reads.get(), draws.get()), (2, 1));
                assert!(!bx.root.path().exists());
                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingApproval)));
            }

            // Cancelling discards the preparation, and is idempotent.
            #[test]
            fn cancelling_discards_the_preparation_and_is_idempotent() {
                let mut bx = Bx::new("b1h-cancel");

                bx.session.cancel_initial_binding();
                bx.session.cancel_initial_binding();

                let id = prepared(&mut bx);

                bx.session.cancel_initial_binding();
                bx.session.cancel_initial_binding();

                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingApproval)));
                assert!(!bx.root.path().exists());
            }

            // A new or reopened session has no preparation: it lives only in the
            // session that made it.
            #[test]
            fn a_preparation_does_not_survive_its_session() {
                let mut fresh = Bx::new("b1h-fresh-session");

                assert_eq!(
                    confirm(&mut fresh, &unknown_id()),
                    Err(stale(Stale::NoPendingApproval))
                );

                let mut bx = Bx::new("b1h-reopen");
                let id = prepared(&mut bx);
                let Bx {
                    session,
                    root,
                    vault,
                    dir,
                    ..
                } = bx;

                session.lock();

                let mut reopened = UnlockedVaultSession::unlock(&vault, test_password()).unwrap();

                assert_eq!(
                    reopened.confirm_initial_binding(&root, &id),
                    Err(stale(Stale::NoPendingApproval))
                );
                assert!(!root.path().exists());

                drop(reopened);
                drop(dir);
            }

            // 13. Nothing printed, by the preview, the pending value, a refusal or
            // a stale category, carries a path, identifier or fingerprint.
            #[test]
            fn consent_types_reveal_no_path_identifier_or_fingerprint() {
                let mut bx = Bx::new("b1h-no-leak");
                let on_disk = fs::read(&bx.vault).unwrap();
                let mut shown: Vec<String> = Vec::new();

                let preview = prepare(&mut bx).unwrap();
                let id = preview.preparation_id().to_owned();

                shown.push(format!("{preview:?}"));
                shown.push(format!("{:?}", bx.session.pending_initial_binding));
                shown.push(format!(
                    "{:?}",
                    bx.session.pending_initial_binding.as_ref().unwrap()
                ));

                for reason in [
                    Stale::NoPendingApproval,
                    Stale::NotCurrentPreparation,
                    Stale::Expired,
                    Stale::LocalVaultChanged,
                    Stale::TargetChanged,
                ] {
                    shown.push(format!("{reason:?}"));
                    shown.push(reason.to_string());
                    shown.push(format!("{:?}", stale(reason)));
                    shown.push(stale(reason).to_string());
                }

                for refusal in [
                    Refusal::TargetIsVaultFile,
                    Refusal::PersistenceUnverified,
                    Refusal::RecordAppeared,
                    Refusal::Randomness,
                    Refusal::TargetUnavailable(UnavailableReason::UnexpectedObject),
                ] {
                    shown.push(format!("{:?}", binding(refusal)));
                    shown.push(binding(refusal).to_string());
                }

                // Real outcomes: a stale id and a success.
                shown.push(format!("{:?}", confirm(&mut bx, "wrong-id-LEAKMARK")));
                shown.push(format!("{:?}", prepare(&mut bx).map(|_| ())));
                shown.push(format!("{:?}", confirm(&mut bx, &id)));

                let id_now = prepared(&mut bx);

                shown.push(format!("{:?}", confirm(&mut bx, &id_now)));

                let prefix =
                    String::from_utf8_lossy(&on_disk[..48.min(on_disk.len())]).into_owned();
                let needles = vec![
                    bx.dir.path().to_string_lossy().into_owned(),
                    bx.remote.to_string_lossy().into_owned(),
                    bx.local.clone(),
                    bx.vault_id.to_string(),
                    bx.vault_id.simple().to_string(),
                    id.clone(),
                    Uuid::parse_str(&id).unwrap().simple().to_string(),
                    id_now.clone(),
                    EnvelopeFingerprint::of_bytes(&on_disk).to_hex(),
                    "target.lvault".to_owned(),
                    "vault.lvault".to_owned(),
                    ".qa-local".to_owned(),
                    "LEAKMARK".to_owned(),
                    prefix,
                    MASTER_PASSWORD.to_owned(),
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
            }
        }

        // Stage 1U-4 B1i: binding status and the explicit two-step reset.
        //
        // Real synthetic vault sessions, real records, real files under the
        // git-ignored `.qa-local/sync-state-b1-tests/` (never `%TEMP%`).
        //
        // Not proven here, and not claimed:
        //
        // * Atomicity. The reset is read, compare, delete; the evidence is
        //   compared again inside the store immediately before the first removal
        //   (shown through the store's window seam), but a process that ignores
        //   the session lock can still change a file after that comparison. The
        //   outcome is then either a removal of what is there or a reported
        //   incomplete deletion.
        // * `NotRemoved`: a store refusal strictly between the second examination
        //   and the first removal cannot be provoked without a store fault the
        //   session's tests cannot reach; its mapping is a single arm, and the
        //   store tests classify every such error as pre-removal.
        // * A `LocatorChanged` caused by the filesystem: the pending value is
        //   altered directly instead.
        // * Any user interface or command: none exists.
        mod reset {
            use super::*;

            type Reset = BindingResetRefusal;
            type Stale = BindingResetStale;
            type Confirm = BindingResetConfirmRefusal;
            type Done = BindingResetOutcome;

            const OTHER_TOKEN: &str = "fedcba9876543210fedcba9876543210";

            fn stale(reason: Stale) -> Confirm {
                Confirm::Stale(reason)
            }

            fn refused(refusal: Reset) -> Confirm {
                Confirm::Refused(refusal)
            }

            fn key(bx: &Bx) -> String {
                EnvelopeFingerprint::of_bytes(bx.local.to_ascii_lowercase().as_bytes()).to_hex()
            }

            fn record_path(bx: &Bx) -> PathBuf {
                bx.state_dir().join(format!("{}.json", key(bx)))
            }

            fn artifact_path(bx: &Bx, token: &str) -> PathBuf {
                bx.state_dir().join(format!("{}.{token}.tmp", key(bx)))
            }

            fn put(bx: &Bx, path: &Path, bytes: &[u8]) {
                fs::create_dir_all(bx.state_dir()).unwrap();
                fs::write(path, bytes).unwrap();
            }

            fn state_for(bx: &Bx, local: &str, vault_id: Uuid, pending: bool) -> SyncState {
                let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
                let checkpoint = SyncBase::Based(
                    SyncCheckpoint::new(fp(1), 1, RemoteHighWater::new(5)).unwrap(),
                );
                let pending = pending.then(|| {
                    PendingPush::new(
                        INTENT,
                        PushIntent::new(PushBaseline::Present(fp(1)), fp(3)).unwrap(),
                        6,
                    )
                    .unwrap()
                });

                SyncState::new(
                    BindingId::new(BINDING).unwrap(),
                    VaultBindingTag::derive(salt, vault_id).unwrap(),
                    loc(local),
                    bx.target.locator().clone(),
                    checkpoint,
                    pending,
                )
                .unwrap()
            }

            fn pending_push_state(bx: &Bx) -> SyncState {
                state_for(bx, &bx.local, bx.vault_id, true)
            }

            /// A readable record at this vault's location that belongs to another
            /// vault.
            fn foreign_state(bx: &Bx) -> SyncState {
                state_for(bx, &bx.local, OTHER_VAULT_ID, false)
            }

            /// A readable record whose own location is not the one it is stored
            /// under (`Corrupt(LocatorMismatch)`).
            fn misplaced_state(bx: &Bx) -> SyncState {
                state_for(
                    bx,
                    r"\\?\C:\Synthetic\Vaults\Elsewhere.lvault",
                    bx.vault_id,
                    false,
                )
            }

            fn state_snapshot(bx: &Bx) -> Option<Vec<String>> {
                bx.state_dir().exists().then(|| snapshot(&bx.state_dir()))
            }

            /// Everything outside the sync-state directory that a reset must
            /// leave alone: the vault folder (primary, backup, lock) and the
            /// target folder.
            fn untouchable(bx: &Bx) -> (Vec<String>, Vec<String>) {
                (snapshot(&bx.vaults_dir()), snapshot(&bx.remote_dir()))
            }

            fn prepare(bx: &mut Bx) -> Result<BindingResetPreview, Reset> {
                bx.session.prepare_binding_reset(&bx.root)
            }

            fn prepared(bx: &mut Bx) -> String {
                prepare(bx)
                    .expect("the reset preparation succeeds")
                    .preparation_id()
                    .to_owned()
            }

            fn prepared_at(bx: &mut Bx, now: Instant) -> String {
                let store = bx.store();

                bx.session
                    .prepare_binding_reset_in(&store, &mut entropy, now)
                    .expect("the reset preparation succeeds")
                    .preparation_id()
                    .to_owned()
            }

            fn confirm(bx: &mut Bx, id: &str) -> Result<Done, Confirm> {
                bx.session.confirm_binding_reset(&bx.root, id)
            }

            /// Confirm with a counting post-deletion load, optionally replaced.
            fn confirm_with(
                bx: &mut Bx,
                id: &str,
                now: Instant,
                loads: &Cell<usize>,
                lie: Option<StateLoad>,
            ) -> Result<Done, Confirm> {
                let store = bx.store();

                bx.session.confirm_binding_reset_in(
                    &store,
                    id,
                    &mut |store, locator| {
                        loads.set(loads.get() + 1);

                        lie.clone().unwrap_or_else(|| store.load(locator))
                    },
                    now,
                )
            }

            fn unknown_id() -> String {
                Uuid::from_u128(0x0123_4567_89ab_4def_8123_4567_89ab_cdef).to_string()
            }

            fn assert_nothing_pending(bx: &mut Bx) {
                assert_eq!(
                    confirm(bx, &unknown_id()),
                    Err(stale(Stale::NoPendingReset))
                );
            }

            /// Open for reading while forbidding deletion and writing by anyone
            /// else: reading still works, removal fails with a sharing violation.
            #[cfg(windows)]
            fn hold_against_removal(path: &Path) -> fs::File {
                use std::os::windows::fs::OpenOptionsExt;

                const FILE_SHARE_READ: u32 = 1;

                OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ)
                    .open(path)
                    .unwrap()
            }

            // -- status -------------------------------------------------------

            /// The status of the state `setup` leaves, with the proof that taking
            /// it wrote, created and removed nothing anywhere.
            fn status_after(name: &str, setup: impl FnOnce(&Bx)) -> (Bx, BindingStatus) {
                let bx = Bx::new(name);

                setup(&bx);

                let outside = untouchable(&bx);
                let state = state_snapshot(&bx);
                let root_existed = bx.root.path().exists();

                let first = bx.session.binding_status(&bx.root);
                let second = bx.session.binding_status(&bx.root);

                assert_eq!(first, second, "{name}");
                assert_eq!(untouchable(&bx), outside, "{name}");
                assert_eq!(state_snapshot(&bx), state, "{name}");
                assert_eq!(bx.root.path().exists(), root_existed, "{name}");

                (bx, first)
            }

            #[test]
            fn status_reports_a_fixed_category_for_every_state_and_writes_nothing() {
                // No record: not configured, and nothing is created.
                let (bx, status) = status_after("b1i-status-absent", |_| {});

                assert_eq!(status.state(), &BindingState::NotConfigured);
                assert_eq!(status.pending_push(), PendingPushIndication::None);
                assert_eq!(status.target_path(), None);
                assert!(!bx.root.path().exists());

                // A verified binding: the retained target is shown, no push pending.
                let (bx, status) = status_after("b1i-status-linked", |bx| bx.publish(&bx.based()));

                assert!(
                    matches!(status.state(), BindingState::Linked(t) if t.path() == bx.target.locator().as_str())
                );
                assert_eq!(status.target_path(), Some(bx.target.locator().as_str()));
                assert_eq!(status.pending_push(), PendingPushIndication::None);

                // A pending push is a separate indication on the same linked state.
                let (_, status) = status_after("b1i-status-pending", |bx| {
                    bx.publish(&pending_push_state(bx))
                });

                assert!(matches!(status.state(), BindingState::Linked(_)));
                assert_eq!(status.pending_push(), PendingPushIndication::Pending);

                // Everything else needs attention, names a distinct category and
                // exposes no stored target.
                type Setup = Box<dyn Fn(&Bx)>;

                let cases: Vec<(&str, Setup, BindingAttention)> = vec![
                    (
                        "b1i-status-corrupt",
                        Box::new(|bx| put(bx, &record_path(bx), b"garbage")),
                        BindingAttention::Corrupt(CorruptReason::Undecodable),
                    ),
                    (
                        "b1i-status-empty",
                        Box::new(|bx| put(bx, &record_path(bx), b"")),
                        BindingAttention::Corrupt(CorruptReason::Empty),
                    ),
                    (
                        "b1i-status-misplaced",
                        Box::new(|bx| {
                            put(bx, &record_path(bx), &misplaced_state(bx).encode().unwrap())
                        }),
                        BindingAttention::Corrupt(CorruptReason::LocatorMismatch),
                    ),
                    (
                        "b1i-status-unsupported",
                        Box::new(|bx| {
                            let future = tampered_version(&bx.based());

                            put(bx, &record_path(bx), &future);
                        }),
                        BindingAttention::UnsupportedVersion,
                    ),
                    (
                        "b1i-status-remnants",
                        Box::new(|bx| put(bx, &artifact_path(bx, STALE_TOKEN), b"debris")),
                        BindingAttention::Unreadable(UnreadableReason::UnresolvedArtifacts),
                    ),
                    (
                        "b1i-status-directory",
                        Box::new(|bx| {
                            fs::create_dir_all(record_path(bx)).unwrap();
                        }),
                        BindingAttention::Unreadable(UnreadableReason::UnexpectedObject),
                    ),
                    (
                        "b1i-status-foreign",
                        Box::new(|bx| bx.publish(&foreign_state(bx))),
                        BindingAttention::Mismatch(BindingMismatch::VaultIdentity),
                    ),
                    (
                        "b1i-status-vault-changed",
                        Box::new(|bx| fs::write(&bx.vault, bx.resealed(|_| {})).unwrap()),
                        BindingAttention::Unavailable(SyncStateUnavailable::LocalVaultChanged),
                    ),
                ];

                for (name, setup, expected) in &cases {
                    let (_, status) = status_after(name, |bx| setup(bx));

                    assert_eq!(
                        status.state(),
                        &BindingState::NeedsAttention(*expected),
                        "{name}"
                    );
                    assert_eq!(status.target_path(), None, "{name}");
                    assert_eq!(
                        status.pending_push(),
                        PendingPushIndication::Unavailable,
                        "{name}"
                    );
                }
            }

            /// A schema-valid record that claims a future version.
            fn tampered_version(state: &SyncState) -> Vec<u8> {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&state.encode().unwrap()).unwrap();

                value["version"] = serde_json::json!(2);

                serde_json::to_vec(&value).unwrap()
            }

            // -- preparation --------------------------------------------------

            #[test]
            fn preparing_returns_a_typed_preview_and_changes_nothing() {
                let mut bx = Bx::new("b1i-prepare");

                bx.session.data_mut().updated_at_ms = NOW_MS + 5;
                assert!(bx.session.save().unwrap());

                bx.publish(&pending_push_state(&bx));
                put(&bx, &artifact_path(&bx, STALE_TOKEN), b"debris");

                let outside = untouchable(&bx);
                let state = state_snapshot(&bx);

                let preview = prepare(&mut bx).expect("the reset preparation succeeds");

                assert_eq!(preview.subject(), BindingResetSubject::VerifiedBinding);
                assert_eq!(preview.target_path(), Some(bx.target.locator().as_str()));
                assert_eq!(preview.pending_push(), PendingPushIndication::Pending);
                assert!(Uuid::parse_str(preview.preparation_id()).is_ok());
                assert_eq!(preview.consequences(), &BINDING_RESET_CONSEQUENCES[..]);

                for fact in [
                    BindingResetConsequence::RemovesLocalBindingRecord,
                    BindingResetConsequence::RemovesTrustedSyncHistory,
                    BindingResetConsequence::MayDiscardPendingSyncIntent,
                    BindingResetConsequence::KeepsVaultAndBackup,
                    BindingResetConsequence::KeepsRemoteTarget,
                    BindingResetConsequence::DoesNotProveRemoteContentAbsent,
                    BindingResetConsequence::DoesNotEnablePublication,
                ] {
                    assert!(preview.consequences().contains(&fact), "{fact:?}");
                }

                // Preparation is read-only: not one byte, name or timestamp moved.
                assert_eq!(untouchable(&bx), outside);
                assert_eq!(state_snapshot(&bx), state);
                assert!(bx.session.backup_path().exists());
                assert!(matches!(
                    bx.session.load_sync_state(&bx.root),
                    SessionSyncState::Bound(_)
                ));
            }

            #[test]
            fn a_preview_shows_a_target_only_for_a_verified_binding() {
                let mut foreign = Bx::new("b1i-preview-foreign");

                foreign.publish(&foreign_state(&foreign));

                let preview = prepare(&mut foreign).unwrap();

                assert_eq!(preview.subject(), BindingResetSubject::MismatchedRecord);
                assert_eq!(preview.target_path(), None);
                assert_eq!(preview.pending_push(), PendingPushIndication::Unavailable);

                let mut corrupt = Bx::new("b1i-preview-corrupt");

                put(&corrupt, &record_path(&corrupt), b"garbage");

                let preview = prepare(&mut corrupt).unwrap();

                assert_eq!(preview.subject(), BindingResetSubject::CorruptRecord);
                assert_eq!(preview.target_path(), None);
            }

            // -- confirmation: what is removed --------------------------------

            #[test]
            fn confirming_removes_only_this_locations_sync_state() {
                let mut bx = Bx::new("b1i-confirm");

                bx.session.data_mut().updated_at_ms = NOW_MS + 5;
                assert!(bx.session.save().unwrap());

                let backup = bx.session.backup_path().to_path_buf();

                bx.publish(&pending_push_state(&bx));
                put(&bx, &artifact_path(&bx, STALE_TOKEN), b"debris");

                // Neighbours the reset must not touch: another location's
                // record and a file that merely shares this record's prefix.
                let neighbour = state_for(
                    &bx,
                    r"\\?\C:\Synthetic\Vaults\Neighbour.lvault",
                    OTHER_VAULT_ID,
                    false,
                );
                bx.store().create(&neighbour).unwrap();
                let unrelated = bx.state_dir().join(format!("{}.notes.txt", key(&bx)));
                fs::write(&unrelated, b"unrelated").unwrap();

                let vault_bytes = fs::read(&bx.vault).unwrap();
                let backup_bytes = fs::read(&backup).unwrap();
                let remote_bytes = fs::read(&bx.remote).unwrap();
                let outside = untouchable(&bx);

                let id = prepared(&mut bx);

                assert_eq!(confirm(&mut bx, &id), Ok(Done::ResetAndVerified));

                // Exactly this location's record and artifact are gone.
                assert!(!record_path(&bx).exists());
                assert!(!artifact_path(&bx, STALE_TOKEN).exists());
                assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated");
                assert_eq!(
                    bx.store().load(neighbour.local_locator()),
                    StateLoad::Loaded(Box::new(neighbour.clone()))
                );
                assert_eq!(names(&bx.state_dir()).len(), 2);

                // The vault, its backup and lock, and the target are untouched.
                assert_eq!(fs::read(&bx.vault).unwrap(), vault_bytes);
                assert_eq!(fs::read(&backup).unwrap(), backup_bytes);
                assert_eq!(fs::read(&bx.remote).unwrap(), remote_bytes);
                assert_eq!(untouchable(&bx), outside);

                // Nothing was rebuilt: a fresh load and the status agree.
                assert_eq!(
                    bx.session.load_sync_state(&bx.root),
                    SessionSyncState::NotConfigured
                );
                assert_eq!(
                    bx.session.binding_status(&bx.root).state(),
                    &BindingState::NotConfigured
                );
                assert!(!record_path(&bx).exists());

                // The session is still usable and still holds its lock.
                assert!(matches!(
                    UnlockedVaultSession::unlock(&bx.vault, test_password()),
                    Err(SessionError::InUse)
                ));
            }

            #[test]
            fn every_resettable_kind_is_removed_and_nothing_else_changes() {
                type Setup = Box<dyn Fn(&Bx)>;

                let cases: Vec<(&str, Setup, BindingResetSubject)> = vec![
                    (
                        "b1i-kind-verified",
                        Box::new(|bx| bx.publish(&bx.based())),
                        BindingResetSubject::VerifiedBinding,
                    ),
                    (
                        "b1i-kind-pending",
                        Box::new(|bx| bx.publish(&pending_push_state(bx))),
                        BindingResetSubject::VerifiedBinding,
                    ),
                    (
                        "b1i-kind-foreign",
                        Box::new(|bx| bx.publish(&foreign_state(bx))),
                        BindingResetSubject::MismatchedRecord,
                    ),
                    (
                        "b1i-kind-corrupt",
                        Box::new(|bx| put(bx, &record_path(bx), b"garbage")),
                        BindingResetSubject::CorruptRecord,
                    ),
                    (
                        "b1i-kind-empty",
                        Box::new(|bx| put(bx, &record_path(bx), b"")),
                        BindingResetSubject::CorruptRecord,
                    ),
                    (
                        "b1i-kind-misplaced",
                        Box::new(|bx| {
                            put(bx, &record_path(bx), &misplaced_state(bx).encode().unwrap())
                        }),
                        BindingResetSubject::CorruptRecord,
                    ),
                    (
                        "b1i-kind-unsupported",
                        Box::new(|bx| {
                            put(bx, &record_path(bx), &tampered_version(&bx.based()));
                        }),
                        BindingResetSubject::UnsupportedRecord,
                    ),
                    (
                        "b1i-kind-remnants",
                        Box::new(|bx| {
                            put(bx, &artifact_path(bx, STALE_TOKEN), b"debris");
                            put(bx, &artifact_path(bx, OTHER_TOKEN), b"");
                        }),
                        BindingResetSubject::InterruptedWriteRemnants,
                    ),
                    (
                        "b1i-kind-record-and-artifacts",
                        Box::new(|bx| {
                            bx.publish(&bx.based());
                            put(bx, &artifact_path(bx, STALE_TOKEN), b"debris");
                        }),
                        BindingResetSubject::VerifiedBinding,
                    ),
                ];

                for (name, setup, subject) in &cases {
                    let mut bx = Bx::new(name);

                    setup(&bx);

                    let outside = untouchable(&bx);
                    let id;

                    {
                        let preview = prepare(&mut bx).unwrap_or_else(|e| panic!("{name}: {e:?}"));

                        assert_eq!(preview.subject(), *subject, "{name}");
                        id = preview.preparation_id().to_owned();
                    }

                    assert_eq!(confirm(&mut bx, &id), Ok(Done::ResetAndVerified), "{name}");
                    assert_eq!(
                        bx.session.load_sync_state(&bx.root),
                        SessionSyncState::NotConfigured,
                        "{name}"
                    );
                    assert_eq!(
                        bx.session.binding_status(&bx.root).state(),
                        &BindingState::NotConfigured,
                        "{name}"
                    );
                    assert!(
                        names(&bx.state_dir()).is_empty(),
                        "{name}: {:?}",
                        names(&bx.state_dir())
                    );
                    assert_eq!(untouchable(&bx), outside, "{name}");

                    // Nothing left to reset; nothing was recreated.
                    assert_eq!(
                        prepare(&mut bx).map(|_| ()),
                        Err(Reset::NothingToReset),
                        "{name}"
                    );
                }
            }

            // -- states that are deliberately not resettable ------------------

            #[test]
            fn states_without_exact_evidence_are_refused_not_accepted() {
                // Nothing at all.
                let mut bx = Bx::new("b1i-refuse-nothing");

                assert_eq!(prepare(&mut bx).map(|_| ()), Err(Reset::NothingToReset));
                assert!(!bx.root.path().exists());
                assert_nothing_pending(&mut bx);

                // A directory where the record belongs.
                let mut bx = Bx::new("b1i-refuse-directory");
                fs::create_dir_all(record_path(&bx)).unwrap();
                fs::write(record_path(&bx).join("inner.txt"), b"keep").unwrap();
                let state = state_snapshot(&bx);

                assert_eq!(
                    prepare(&mut bx).map(|_| ()),
                    Err(Reset::UnreadableState(UnreadableReason::UnexpectedObject))
                );
                assert_eq!(state_snapshot(&bx), state);
                assert_nothing_pending(&mut bx);

                // The sync-state path is a regular file.
                let mut bx = Bx::new("b1i-refuse-file");
                fs::create_dir_all(bx.root.path()).unwrap();
                fs::write(bx.state_dir(), b"not a directory").unwrap();

                assert!(matches!(prepare(&mut bx), Err(Reset::UnreadableState(_))));
                assert_eq!(fs::read(bx.state_dir()).unwrap(), b"not a directory");
                assert_nothing_pending(&mut bx);

                // A record too large to read in full: its category is corrupt, but
                // its bytes cannot be bound.
                let mut bx = Bx::new("b1i-refuse-oversized-record");
                fs::create_dir_all(bx.state_dir()).unwrap();
                let file = fs::File::create(record_path(&bx)).unwrap();
                file.set_len(localvault_core::sync_state::MAX_SYNC_STATE_BYTES as u64 + 1)
                    .unwrap();
                drop(file);

                assert_eq!(
                    prepare(&mut bx).map(|_| ()),
                    Err(Reset::Evidence(EvidenceRefusal::Oversized))
                );
                assert!(record_path(&bx).exists());
                assert_nothing_pending(&mut bx);

                // A valid record beside an oversized artifact.
                let mut bx = Bx::new("b1i-refuse-oversized-artifact");
                bx.publish(&bx.based());
                let file = fs::File::create(artifact_path(&bx, STALE_TOKEN)).unwrap();
                file.set_len(localvault_core::sync_state::MAX_SYNC_STATE_BYTES as u64 + 1)
                    .unwrap();
                drop(file);

                assert_eq!(
                    prepare(&mut bx).map(|_| ()),
                    Err(Reset::Evidence(EvidenceRefusal::Oversized))
                );
                assert!(record_path(&bx).exists());
                assert_nothing_pending(&mut bx);

                // Recovery artifacts that are not plain files.
                let mut bx = Bx::new("b1i-refuse-artifact-directory");
                fs::create_dir_all(artifact_path(&bx, STALE_TOKEN)).unwrap();

                assert_eq!(
                    bx.session.load_sync_state(&bx.root),
                    SessionSyncState::Unreadable(UnreadableReason::UnresolvedArtifacts)
                );
                assert_eq!(
                    prepare(&mut bx).map(|_| ()),
                    Err(Reset::Evidence(EvidenceRefusal::UnexpectedObject))
                );
                assert!(artifact_path(&bx, STALE_TOKEN).is_dir());
                assert_nothing_pending(&mut bx);
            }

            #[cfg(windows)]
            #[test]
            fn inaccessible_files_and_reparse_points_are_refused_not_accepted() {
                // A record that cannot be opened: contents unknown.
                let mut bx = Bx::new("b1i-refuse-held-record");
                bx.publish(&bx.based());
                let state = state_snapshot(&bx);
                {
                    let _guard = hold_exclusively(&record_path(&bx));

                    assert!(matches!(
                        prepare(&mut bx),
                        Err(Reset::UnreadableState(UnreadableReason::Io(_)))
                    ));
                }
                assert_eq!(state_snapshot(&bx), state);
                assert_nothing_pending(&mut bx);

                // A readable record beside an artifact that cannot be opened:
                // the artifact set cannot be bound exactly.
                let mut bx = Bx::new("b1i-refuse-held-artifact");
                bx.publish(&bx.based());
                put(&bx, &artifact_path(&bx, STALE_TOKEN), b"debris");
                let state = state_snapshot(&bx);
                {
                    let _guard = hold_exclusively(&artifact_path(&bx, STALE_TOKEN));

                    assert_eq!(
                        prepare(&mut bx).map(|_| ()),
                        Err(Reset::Evidence(EvidenceRefusal::Unreadable))
                    );
                }
                assert_eq!(state_snapshot(&bx), state);
                assert_nothing_pending(&mut bx);

                // The sync-state directory is a junction.
                let mut bx = Bx::new("b1i-refuse-junction-directory");
                let elsewhere = bx.dir.path().join("elsewhere");
                fs::create_dir_all(&elsewhere).unwrap();
                fs::write(
                    elsewhere.join(format!("{}.json", key(&bx))),
                    bx.based().encode().unwrap(),
                )
                .unwrap();
                fs::create_dir_all(bx.root.path()).unwrap();
                make_junction(&bx.state_dir(), &elsewhere);
                let outside = snapshot(&elsewhere);

                assert_eq!(
                    prepare(&mut bx).map(|_| ()),
                    Err(Reset::UnreadableState(UnreadableReason::UnexpectedObject))
                );
                assert_eq!(snapshot(&elsewhere), outside);
                assert_nothing_pending(&mut bx);
                fs::remove_dir(bx.state_dir()).unwrap();

                // The record itself is a junction.
                let mut bx = Bx::new("b1i-refuse-junction-record");
                let target = bx.dir.path().join("junction-target");
                fs::create_dir_all(&target).unwrap();
                fs::create_dir_all(bx.state_dir()).unwrap();
                make_junction(&record_path(&bx), &target);

                assert_eq!(
                    prepare(&mut bx).map(|_| ()),
                    Err(Reset::UnreadableState(UnreadableReason::UnexpectedObject))
                );
                assert!(snapshot(&target).is_empty());
                assert_nothing_pending(&mut bx);
                fs::remove_dir(record_path(&bx)).unwrap();
            }

            // -- identifiers, expiry, single use ------------------------------

            #[test]
            fn a_wrong_id_is_stale_and_spends_the_preparation() {
                let mut bx = Bx::new("b1i-wrong-id");
                bx.publish(&bx.based());
                let record = bx.record_bytes();
                let id = prepared(&mut bx);
                let unknown = unknown_id();

                for wrong in ["", "not-a-uuid", "LEAKMARK", unknown.as_str()] {
                    let mut again = Bx::new("b1i-wrong-id-each");
                    again.publish(&again.based());
                    let id = prepared(&mut again);
                    let before = state_snapshot(&again);

                    assert_eq!(
                        confirm(&mut again, wrong),
                        Err(stale(Stale::NotCurrentPreparation)),
                        "{wrong:?}"
                    );
                    assert_eq!(state_snapshot(&again), before);
                    // The right id no longer works either: spent.
                    assert_eq!(confirm(&mut again, &id), Err(stale(Stale::NoPendingReset)));
                    assert_eq!(state_snapshot(&again), before);
                }

                // The first fixture was never confirmed and is untouched.
                assert_eq!(bx.record_bytes(), record);
                assert_eq!(confirm(&mut bx, &id), Ok(Done::ResetAndVerified));
            }

            #[test]
            fn a_confirmation_works_once() {
                let mut bx = Bx::new("b1i-double");
                bx.publish(&bx.based());
                let id = prepared(&mut bx);

                assert_eq!(confirm(&mut bx, &id), Ok(Done::ResetAndVerified));

                // Same id again: stale, and the freshly absent state is not
                // reported as a second reset.
                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingReset)));

                // A binding made in between is not removed by the spent id.
                bx.publish(&bx.based());
                let record = bx.record_bytes();

                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingReset)));
                assert_eq!(bx.record_bytes(), record);
            }

            #[test]
            fn a_new_preparation_voids_the_previous_one() {
                let mut bx = Bx::new("b1i-new-prep");
                bx.publish(&bx.based());
                let record = bx.record_bytes();

                let first = prepared(&mut bx);
                let second = prepared(&mut bx);

                assert_ne!(first, second);

                // The old id is not current, and naming it spends the new one too.
                assert_eq!(
                    confirm(&mut bx, &first),
                    Err(stale(Stale::NotCurrentPreparation))
                );
                assert_eq!(confirm(&mut bx, &second), Err(stale(Stale::NoPendingReset)));
                assert_eq!(bx.record_bytes(), record);

                // The newest one does work.
                let first = prepared(&mut bx);
                let second = prepared(&mut bx);

                assert_ne!(first, second);
                assert_eq!(confirm(&mut bx, &second), Ok(Done::ResetAndVerified));
                assert!(!record_path(&bx).exists());
            }

            #[test]
            fn a_failed_preparation_also_voids_the_previous_one() {
                let mut bx = Bx::new("b1i-failed-prep");
                bx.publish(&bx.based());
                let id = prepared(&mut bx);

                // The state becomes something that cannot be reset.
                let record = fs::read(record_path(&bx)).unwrap();
                fs::remove_file(record_path(&bx)).unwrap();
                fs::create_dir_all(record_path(&bx)).unwrap();

                assert_eq!(
                    prepare(&mut bx).map(|_| ()),
                    Err(Reset::UnreadableState(UnreadableReason::UnexpectedObject))
                );

                fs::remove_dir(record_path(&bx)).unwrap();
                fs::write(record_path(&bx), &record).unwrap();

                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingReset)));
                assert_eq!(fs::read(record_path(&bx)).unwrap(), record);

                // Unavailable randomness is a failed preparation too.
                let id = prepared(&mut bx);
                let store = bx.store();

                assert_eq!(
                    bx.session
                        .prepare_binding_reset_in(&store, &mut |_| false, Instant::now())
                        .map(|_| ()),
                    Err(Reset::Randomness)
                );
                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingReset)));
                assert_eq!(fs::read(record_path(&bx)).unwrap(), record);
            }

            #[test]
            fn a_preparation_is_confirmable_for_120_seconds_and_no_longer() {
                let base = Instant::now();

                let mut late = Bx::new("b1i-expired");
                late.publish(&late.based());
                let id = prepared_at(&mut late, base);
                let state = state_snapshot(&late);
                let loads = Cell::new(0usize);

                assert_eq!(
                    confirm_with(
                        &mut late,
                        &id,
                        base + Duration::from_secs(121),
                        &loads,
                        None
                    ),
                    Err(stale(Stale::Expired))
                );
                assert_eq!(loads.get(), 0);
                assert_eq!(state_snapshot(&late), state);
                assert_eq!(confirm(&mut late, &id), Err(stale(Stale::NoPendingReset)));

                // The boundary is inclusive.
                let mut edge = Bx::new("b1i-ttl-edge");
                edge.publish(&edge.based());
                let id = prepared_at(&mut edge, base);

                assert_eq!(
                    confirm_with(
                        &mut edge,
                        &id,
                        base + Duration::from_secs(120),
                        &loads,
                        None
                    ),
                    Ok(Done::ResetAndVerified)
                );
            }

            // -- interaction with the initial-binding approval ----------------

            #[test]
            fn a_reset_and_an_initial_binding_approval_void_each_other() {
                // Initial binding prepared, then a reset is prepared over a
                // record that appeared: the binding approval is voided.
                let mut bx = Bx::new("b1i-exclusion-a");
                let initial = consent_prepare(&mut bx);

                bx.publish(&bx.based());
                let reset = prepared(&mut bx);

                assert_eq!(
                    bx.session.confirm_initial_binding(&bx.root, &initial),
                    Err(InitialBindingConfirmRefusal::Stale(
                        InitialBindingStale::NoPendingApproval
                    ))
                );
                // ...and that confirmation attempt voided the reset in turn.
                assert_eq!(confirm(&mut bx, &reset), Err(stale(Stale::NoPendingReset)));
                assert!(record_path(&bx).exists());

                // Reset prepared, then the record is removed and an initial
                // binding is prepared: the reset is voided.
                let mut bx = Bx::new("b1i-exclusion-b");
                bx.publish(&bx.based());
                let reset = prepared(&mut bx);

                fs::remove_file(record_path(&bx)).unwrap();
                let initial = consent_prepare(&mut bx);

                assert_eq!(confirm(&mut bx, &reset), Err(stale(Stale::NoPendingReset)));
                // The confirmation attempt voided the binding approval too.
                assert_eq!(
                    bx.session.confirm_initial_binding(&bx.root, &initial),
                    Err(InitialBindingConfirmRefusal::Stale(
                        InitialBindingStale::NoPendingApproval
                    ))
                );
                assert!(!bx.state_dir().exists() || names(&bx.state_dir()).is_empty());

                // Neither kind of id can be spent on the other kind.
                let mut bx = Bx::new("b1i-exclusion-c");
                let initial = consent_prepare(&mut bx);

                assert_eq!(
                    confirm(&mut bx, &initial),
                    Err(stale(Stale::NoPendingReset))
                );
                assert_eq!(
                    bx.session.confirm_initial_binding(&bx.root, &initial),
                    Err(InitialBindingConfirmRefusal::Stale(
                        InitialBindingStale::NoPendingApproval
                    ))
                );
                assert!(!bx.root.path().exists());

                let mut bx = Bx::new("b1i-exclusion-d");
                bx.publish(&bx.based());
                let reset = prepared(&mut bx);
                let record = bx.record_bytes();

                assert_eq!(
                    bx.session.confirm_initial_binding(&bx.root, &reset),
                    Err(InitialBindingConfirmRefusal::Stale(
                        InitialBindingStale::NoPendingApproval
                    ))
                );
                assert_eq!(confirm(&mut bx, &reset), Err(stale(Stale::NoPendingReset)));
                assert_eq!(bx.record_bytes(), record);

                // A failed attempt of either kind voids the other kind.
                let mut bx = Bx::new("b1i-exclusion-e");
                let initial = consent_prepare(&mut bx);

                assert_eq!(prepare(&mut bx).map(|_| ()), Err(Reset::NothingToReset));
                assert_eq!(
                    bx.session.confirm_initial_binding(&bx.root, &initial),
                    Err(InitialBindingConfirmRefusal::Stale(
                        InitialBindingStale::NoPendingApproval
                    ))
                );

                let mut bx = Bx::new("b1i-exclusion-f");
                bx.publish(&bx.based());
                let reset = prepared(&mut bx);

                assert!(bx
                    .session
                    .prepare_initial_binding(&bx.root, &bx.target)
                    .is_err());
                assert_eq!(confirm(&mut bx, &reset), Err(stale(Stale::NoPendingReset)));

                // Cancelling one kind leaves the other alone.
                let mut bx = Bx::new("b1i-exclusion-g");
                bx.publish(&bx.based());
                let reset = prepared(&mut bx);

                bx.session.cancel_initial_binding();
                assert_eq!(confirm(&mut bx, &reset), Ok(Done::ResetAndVerified));

                let mut bx = Bx::new("b1i-exclusion-h");
                let initial = consent_prepare(&mut bx);

                bx.session.cancel_binding_reset();
                assert_eq!(
                    bx.session.confirm_initial_binding(&bx.root, &initial),
                    Ok(InitialBindingOutcome::BoundAndVerified)
                );
            }

            fn consent_prepare(bx: &mut Bx) -> String {
                bx.session
                    .prepare_initial_binding(&bx.root, &bx.target)
                    .expect("the initial-binding preparation succeeds")
                    .preparation_id()
                    .to_owned()
            }

            // -- the state changing between preparation and confirmation ------

            #[test]
            fn state_that_changed_after_the_preparation_is_not_removed() {
                type Setup = Box<dyn Fn(&Bx)>;
                type Change = Box<dyn Fn(&Bx)>;

                let setup: Setup = Box::new(|bx| {
                    bx.publish(&bx.based());
                    put(bx, &artifact_path(bx, STALE_TOKEN), b"debris");
                });

                let changes: Vec<(&str, Change)> = vec![
                    (
                        "record byte",
                        Box::new(|bx| {
                            let mut bytes = fs::read(record_path(bx)).unwrap();

                            bytes[10] ^= 0x01;
                            fs::write(record_path(bx), bytes).unwrap();
                        }),
                    ),
                    (
                        "record replaced by another valid state",
                        Box::new(|bx| {
                            let newer = rebuilt_high_water(bx, 77);

                            fs::write(record_path(bx), newer.encode().unwrap()).unwrap();
                        }),
                    ),
                    (
                        "record became corrupt",
                        Box::new(|bx| fs::write(record_path(bx), b"garbage").unwrap()),
                    ),
                    (
                        "record removed, artifact remains",
                        Box::new(|bx| fs::remove_file(record_path(bx)).unwrap()),
                    ),
                    (
                        "everything removed",
                        Box::new(|bx| {
                            fs::remove_file(record_path(bx)).unwrap();
                            fs::remove_file(artifact_path(bx, STALE_TOKEN)).unwrap();
                        }),
                    ),
                    (
                        "artifact content",
                        Box::new(|bx| {
                            fs::write(artifact_path(bx, STALE_TOKEN), b"DEBRIS").unwrap()
                        }),
                    ),
                    (
                        "artifact removed",
                        Box::new(|bx| fs::remove_file(artifact_path(bx, STALE_TOKEN)).unwrap()),
                    ),
                    (
                        "artifact added",
                        Box::new(|bx| put(bx, &artifact_path(bx, OTHER_TOKEN), b"more")),
                    ),
                ];

                for (name, change) in &changes {
                    let mut bx = Bx::new("b1i-changed");

                    setup(&bx);

                    let id = prepared(&mut bx);

                    change(&bx);

                    let after_change = state_snapshot(&bx);
                    let outside = untouchable(&bx);
                    let result = confirm(&mut bx, &id);

                    assert_eq!(result, Err(stale(Stale::RecordChanged)), "{name}");
                    assert!(result.is_err(), "{name}: reported a reset");
                    assert_eq!(state_snapshot(&bx), after_change, "{name}");
                    assert_eq!(untouchable(&bx), outside, "{name}");
                    assert_eq!(
                        confirm(&mut bx, &id),
                        Err(stale(Stale::NoPendingReset)),
                        "{name}"
                    );
                    assert_eq!(state_snapshot(&bx), after_change, "{name}");
                }

                // Something that cannot be examined any more is refused for what
                // it is, and also left exactly as it is.
                let mut bx = Bx::new("b1i-changed-unreadable");

                setup(&bx);

                let id = prepared(&mut bx);

                fs::remove_file(record_path(&bx)).unwrap();
                fs::create_dir_all(record_path(&bx)).unwrap();
                let after_change = state_snapshot(&bx);

                assert_eq!(
                    confirm(&mut bx, &id),
                    Err(refused(Reset::UnreadableState(
                        UnreadableReason::UnexpectedObject
                    )))
                );
                assert_eq!(state_snapshot(&bx), after_change);
            }

            fn rebuilt_high_water(bx: &Bx, high_water: u64) -> SyncState {
                SyncState::new(
                    BindingId::new(BINDING).unwrap(),
                    *bx.based().vault_tag(),
                    loc(&bx.local),
                    bx.target.locator().clone(),
                    SyncBase::Based(
                        SyncCheckpoint::new(fp(1), 1, RemoteHighWater::new(high_water)).unwrap(),
                    ),
                    None,
                )
                .unwrap()
            }

            #[test]
            fn a_state_that_vanished_is_stale_never_a_reset_by_this_confirmation() {
                let mut bx = Bx::new("b1i-vanished");
                bx.publish(&bx.based());
                let id = prepared(&mut bx);

                // Somebody else removed it between the two steps.
                fs::remove_file(record_path(&bx)).unwrap();

                let loads = Cell::new(0usize);
                let result = confirm_with(&mut bx, &id, Instant::now(), &loads, None);

                assert_eq!(result, Err(stale(Stale::RecordChanged)));
                assert_eq!(
                    loads.get(),
                    0,
                    "nothing was deleted, so nothing was reloaded"
                );
                assert!(!record_path(&bx).exists());
            }

            #[test]
            fn a_change_in_the_window_before_the_first_removal_is_caught_by_the_store() {
                let mut bx = Bx::new("b1i-window");
                bx.publish(&bx.based());
                put(&bx, &artifact_path(&bx, STALE_TOKEN), b"debris");
                let id = prepared(&mut bx);
                let store = bx.store();
                let record = record_path(&bx);
                let newer = rebuilt_high_water(&bx, 88).encode().unwrap();
                let written = newer.clone();

                // After the session's own second examination, inside the store's
                // conditional deletion: the record is rewritten.
                store.run_before_evidence_recheck_for_test(move || {
                    fs::write(&record, &written).unwrap();
                });

                let loads = Cell::new(0usize);
                let result = bx.session.confirm_binding_reset_in(
                    &store,
                    &id,
                    &mut |store, locator| {
                        loads.set(loads.get() + 1);

                        store.load(locator)
                    },
                    Instant::now(),
                );

                assert_eq!(result, Err(stale(Stale::RecordChanged)));
                assert_eq!(loads.get(), 0);
                assert_eq!(fs::read(record_path(&bx)).unwrap(), newer);
                assert_eq!(
                    fs::read(artifact_path(&bx, STALE_TOKEN)).unwrap(),
                    b"debris"
                );
            }

            #[test]
            fn a_changed_vault_or_location_is_refused_and_removes_nothing() {
                // An in-session save does not change the location or the state:
                // the reset still works.
                let mut saved = Bx::new("b1i-vault-saved");
                saved.publish(&saved.based());
                let id = prepared(&mut saved);

                saved.session.data_mut().updated_at_ms = NOW_MS + 5;
                assert!(saved.session.save().unwrap());

                assert_eq!(confirm(&mut saved, &id), Ok(Done::ResetAndVerified));

                // The vault file rewritten from outside: no longer this session's.
                let mut rewritten = Bx::new("b1i-vault-rewritten");
                rewritten.publish(&rewritten.based());
                let id = prepared(&mut rewritten);

                fs::write(&rewritten.vault, rewritten.resealed(|_| {})).unwrap();
                let state = state_snapshot(&rewritten);

                assert_eq!(
                    confirm(&mut rewritten, &id),
                    Err(refused(Reset::Unavailable(
                        SyncStateUnavailable::LocalVaultChanged
                    )))
                );
                assert_eq!(state_snapshot(&rewritten), state);
                assert_eq!(
                    prepare(&mut rewritten).map(|_| ()),
                    Err(Reset::Unavailable(SyncStateUnavailable::LocalVaultChanged))
                );

                // A preparation for another location is not applied to this one.
                let mut moved = Bx::new("b1i-locator");
                moved.publish(&moved.based());
                let id = prepared(&mut moved);

                moved
                    .session
                    .pending_binding_reset
                    .as_mut()
                    .unwrap()
                    .local_locator = loc(r"\\?\C:\Synthetic\Vaults\Other.lvault");
                let state = state_snapshot(&moved);

                assert_eq!(confirm(&mut moved, &id), Err(stale(Stale::LocatorChanged)));
                assert_eq!(state_snapshot(&moved), state);
            }

            // -- definite and ambiguous outcomes ------------------------------

            #[test]
            fn a_deletion_the_store_calls_complete_is_not_success_unless_a_fresh_load_agrees() {
                let mut bx = Bx::new("b1i-absence-unconfirmed");
                bx.publish(&bx.based());
                let id = prepared(&mut bx);
                let loads = Cell::new(0usize);

                let result = confirm_with(
                    &mut bx,
                    &id,
                    Instant::now(),
                    &loads,
                    Some(StateLoad::Unreadable(UnreadableReason::Io(
                        io::ErrorKind::Other,
                    ))),
                );

                assert_eq!(
                    result,
                    Err(Confirm::Ambiguous(
                        BindingResetAmbiguity::AbsenceNotConfirmed
                    ))
                );
                // One fresh load, never retried, and nothing was rebuilt.
                assert_eq!(loads.get(), 1);
                assert!(!record_path(&bx).exists());
                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingReset)));

                // A load that finds the record again (somebody recreated it) is
                // equally not a success.
                let mut bx = Bx::new("b1i-absence-recreated");
                bx.publish(&bx.based());
                let id = prepared(&mut bx);
                let again = bx.based();
                let loads = Cell::new(0usize);

                assert_eq!(
                    confirm_with(
                        &mut bx,
                        &id,
                        Instant::now(),
                        &loads,
                        Some(StateLoad::Loaded(Box::new(again)))
                    ),
                    Err(Confirm::Ambiguous(
                        BindingResetAmbiguity::AbsenceNotConfirmed
                    ))
                );
                assert_eq!(loads.get(), 1);
            }

            #[cfg(windows)]
            #[test]
            fn an_incomplete_deletion_is_ambiguous_and_is_never_retried() {
                // An artifact that cannot be removed: artifacts go first, so the
                // record is still intact.
                let mut bx = Bx::new("b1i-incomplete-artifact");
                bx.publish(&bx.based());
                put(&bx, &artifact_path(&bx, STALE_TOKEN), b"debris");
                let record = bx.record_bytes();
                let id = prepared(&mut bx);
                let loads = Cell::new(0usize);
                let outside = untouchable(&bx);

                {
                    let _guard = hold_against_removal(&artifact_path(&bx, STALE_TOKEN));

                    assert_eq!(
                        confirm_with(&mut bx, &id, Instant::now(), &loads, None),
                        Err(Confirm::Ambiguous(
                            BindingResetAmbiguity::IncompleteDeletion
                        ))
                    );
                }

                assert_eq!(loads.get(), 0, "no verification is claimed after a failure");
                assert_eq!(bx.record_bytes(), record);
                assert!(artifact_path(&bx, STALE_TOKEN).exists());
                assert_eq!(untouchable(&bx), outside);

                // Nothing retries on its own, even once the obstacle is gone.
                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingReset)));
                assert_eq!(bx.record_bytes(), record);
                assert!(matches!(
                    bx.session.binding_status(&bx.root).state(),
                    BindingState::Linked(_)
                ));

                // Only a new, explicit preparation and confirmation finishes it.
                let id = prepared(&mut bx);

                assert_eq!(confirm(&mut bx, &id), Ok(Done::ResetAndVerified));

                // The record itself cannot be removed after the artifacts went:
                // a partial state, reported as ambiguous.
                let mut bx = Bx::new("b1i-incomplete-record");
                bx.publish(&bx.based());
                put(&bx, &artifact_path(&bx, STALE_TOKEN), b"debris");
                let record = bx.record_bytes();
                let id = prepared(&mut bx);

                {
                    let _guard = hold_against_removal(&record_path(&bx));

                    assert_eq!(
                        confirm(&mut bx, &id),
                        Err(Confirm::Ambiguous(
                            BindingResetAmbiguity::IncompleteDeletion
                        ))
                    );
                }

                assert!(!artifact_path(&bx, STALE_TOKEN).exists());
                assert_eq!(bx.record_bytes(), record);
                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingReset)));
                assert_eq!(bx.record_bytes(), record);
            }

            // -- lifetime -----------------------------------------------------

            #[test]
            fn a_reset_preparation_does_not_survive_its_session() {
                let mut fresh = Bx::new("b1i-fresh-session");

                assert_eq!(
                    confirm(&mut fresh, &unknown_id()),
                    Err(stale(Stale::NoPendingReset))
                );

                let mut bx = Bx::new("b1i-reopen");
                bx.publish(&bx.based());
                let id = prepared(&mut bx);
                let record = bx.record_bytes();
                let Bx {
                    session,
                    root,
                    vault,
                    dir,
                    ..
                } = bx;

                session.lock();

                let mut reopened = UnlockedVaultSession::unlock(&vault, test_password()).unwrap();

                assert_eq!(
                    reopened.confirm_binding_reset(&root, &id),
                    Err(stale(Stale::NoPendingReset))
                );
                assert!(matches!(
                    reopened.binding_status(&root).state(),
                    BindingState::Linked(_)
                ));

                drop(reopened);

                let state_dir = root
                    .path()
                    .join(crate::vault::sync_state_store::SYNC_STATE_DIRECTORY);
                let kept: Vec<_> = fs::read_dir(&state_dir)
                    .unwrap()
                    .map(|e| fs::read(e.unwrap().path()).unwrap())
                    .collect();

                assert_eq!(kept, vec![record]);

                drop(dir);
            }

            #[test]
            fn a_reset_preparation_belongs_to_one_vault() {
                let mut one = Bx::new("b1i-vault-one");
                one.publish(&one.based());
                let id = prepared(&mut one);

                let mut two = Bx::new("b1i-vault-two");
                two.publish(&two.based());
                let record_one = one.record_bytes();
                let record_two = two.record_bytes();

                assert_eq!(confirm(&mut two, &id), Err(stale(Stale::NoPendingReset)));
                assert_eq!(two.record_bytes(), record_two);
                assert_eq!(one.record_bytes(), record_one);
                assert_eq!(confirm(&mut one, &id), Ok(Done::ResetAndVerified));
                assert_eq!(two.record_bytes(), record_two);
            }

            #[test]
            fn cancelling_discards_a_reset_preparation_and_is_idempotent() {
                let mut bx = Bx::new("b1i-cancel");
                bx.publish(&bx.based());
                let record = bx.record_bytes();

                bx.session.cancel_binding_reset();
                bx.session.cancel_binding_reset();

                let id = prepared(&mut bx);

                bx.session.cancel_binding_reset();
                bx.session.cancel_binding_reset();

                assert_eq!(confirm(&mut bx, &id), Err(stale(Stale::NoPendingReset)));
                assert_eq!(bx.record_bytes(), record);
            }

            // -- nothing is printed -------------------------------------------

            #[test]
            fn reset_types_reveal_no_path_identifier_fingerprint_or_content() {
                let mut bx = Bx::new("b1i-no-leak");
                bx.publish(&pending_push_state(&bx));
                put(&bx, &artifact_path(&bx, STALE_TOKEN), b"LEAKMARK-debris");

                let record = bx.record_bytes();
                let status = bx.session.binding_status(&bx.root);
                let preview = prepare(&mut bx).unwrap();
                let id = preview.preparation_id().to_owned();
                let mut shown: Vec<String> = Vec::new();

                shown.push(format!("{status:?}"));
                shown.push(format!("{:?}", status.state()));
                shown.push(format!("{preview:?}"));
                shown.push(format!("{:?}", bx.session.pending_binding_reset));
                shown.push(format!(
                    "{:?}",
                    bx.session.pending_binding_reset.as_ref().unwrap()
                ));
                shown.push(format!("{:?}", preview.consequences()));
                shown.push(format!("{:?}", preview.subject()));
                shown.push(format!("{:?}", bx.session.load_sync_state(&bx.root)));

                for reason in [
                    Stale::NoPendingReset,
                    Stale::NotCurrentPreparation,
                    Stale::Expired,
                    Stale::LocatorChanged,
                    Stale::RecordChanged,
                ] {
                    shown.push(format!("{reason:?}"));
                    shown.push(reason.to_string());
                    shown.push(format!("{:?}", stale(reason)));
                    shown.push(stale(reason).to_string());
                }

                for refusal in [
                    Reset::NothingToReset,
                    Reset::Randomness,
                    Reset::RecordChanged,
                    Reset::UnreadableState(UnreadableReason::UnexpectedObject),
                    Reset::Evidence(EvidenceRefusal::Oversized),
                    Reset::Evidence(EvidenceRefusal::Unreadable),
                    Reset::Unavailable(SyncStateUnavailable::LocalVaultChanged),
                ] {
                    shown.push(format!("{refusal:?}"));
                    shown.push(refusal.to_string());
                    shown.push(format!("{:?}", refused(refusal)));
                    shown.push(refused(refusal).to_string());
                }

                for ambiguity in [
                    BindingResetAmbiguity::IncompleteDeletion,
                    BindingResetAmbiguity::AbsenceNotConfirmed,
                ] {
                    shown.push(format!("{:?}", Confirm::Ambiguous(ambiguity)));
                    shown.push(Confirm::Ambiguous(ambiguity).to_string());
                    shown.push(ambiguity.to_string());
                }

                shown.push(format!(
                    "{:?}",
                    Confirm::NotRemoved(StoreError::UnexpectedObject)
                ));
                shown.push(Confirm::NotRemoved(StoreError::UnexpectedObject).to_string());

                // Real outcomes: a wrong id, then a success.
                shown.push(format!("{:?}", confirm(&mut bx, "wrong-id-LEAKMARK")));

                let id_now = prepared(&mut bx);

                shown.push(format!("{:?}", confirm(&mut bx, &id_now)));
                shown.push(format!("{:?}", bx.session.binding_status(&bx.root)));

                let needles = vec![
                    bx.dir.path().to_string_lossy().into_owned(),
                    bx.remote.to_string_lossy().into_owned(),
                    bx.local.clone(),
                    bx.target.locator().as_str().to_owned(),
                    bx.vault_id.to_string(),
                    bx.vault_id.simple().to_string(),
                    id.clone(),
                    Uuid::parse_str(&id).unwrap().simple().to_string(),
                    id_now.clone(),
                    key(&bx),
                    EnvelopeFingerprint::of_bytes(&record).to_hex(),
                    EnvelopeFingerprint::of_bytes(b"LEAKMARK-debris").to_hex(),
                    STALE_TOKEN.to_owned(),
                    "target.lvault".to_owned(),
                    "vault.lvault".to_owned(),
                    ".qa-local".to_owned(),
                    "LEAKMARK".to_owned(),
                    MASTER_PASSWORD.to_owned(),
                ];

                assert!(shown.len() > 40);

                for output in &shown {
                    for needle in &needles {
                        assert!(
                            !output.contains(needle.as_str()),
                            "leaks {needle:?}: {output}"
                        );
                    }
                }
            }
        }
    }
}
