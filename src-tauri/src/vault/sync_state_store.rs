//! Device-local, crash-conscious file store for the accepted
//! [`SyncState`] model (Stage 1U-4, slice B1a).
//!
//! Storage only. Nothing here is connected to vault unlock/save/delete, to a
//! Tauri command, to the recent-vault list, to a remote or to the network; the
//! pure transitions in `localvault_core::sync_state` decide *what* to persist,
//! this module only persists, reads back and removes it.
//!
//! # Location (integration boundary)
//!
//! [`SyncStateStore::new`] takes the **device-local application-data root**
//! supplied by the future caller (the approved source is Tauri's
//! `app_local_data_dir()`, which resolves under the per-user *local*
//! application-data directory) and always uses its `sync-state` subdirectory.
//! It must never be the roaming `app_config_dir()` used by the recent-vault list,
//! and never the directory holding `.lvault` files. This module cannot verify
//! which directory it was given beyond requiring an absolute path.
//!
//! # Record identity
//!
//! One record per local vault *location*, never per `vault_id`:
//!
//! * key = lowercase hex SHA-256 of the ASCII-lowercased bytes of the local
//!   locator string; record file = `<key>.json`.
//! * ASCII-lowercasing mirrors `recent_vaults::path_strings_equal`
//!   (`eq_ignore_ascii_case` on Windows), the existing path-identity rule. That
//!   function is private to `recent_vaults`, so the rule is repeated in
//!   [`path_identity_eq`] and pinned by tests; the store does **not**
//!   canonicalize. The caller must pass the locator produced by the existing
//!   `recent_vaults::normalize_existing_vault_path` (the canonical path string);
//!   the session integration (`UnlockedVaultSession::load_sync_state`) does
//!   exactly that. Two spellings of one file that the existing normalization
//!   would not unify get different records. Path-string equality does not prove
//!   the identity of the filesystem object behind it.
//! * The decoded state carries its own `local_locator`; a record whose locator
//!   does not agree with the requested one is reported as corrupt
//!   ([`CorruptReason::LocatorMismatch`]) and is never treated as a binding.
//! * The store cannot authenticate which *vault* a record belongs to. A path
//!   later reused by a different encrypted vault loads the old record unchanged;
//!   the unlocked-session integration **must** call `SyncState::verify_binding`
//!   with the authenticated `vault_id` before trusting any loaded state.
//!
//! # Outcomes are never conflated
//!
//! [`StateLoad::NotConfigured`] is returned only when the `sync-state`
//! directory is confirmed absent, or it exists as a real directory and neither
//! the record nor any recognized recovery artifact is present. Every I/O
//! failure, unexpected object (directory, symlink, junction or other reparse
//! point), unresolved recovery artifact, undecodable or oversized record and
//! unsupported version is something else.
//!
//! Windows reports a missing path component and "a component is a regular
//! file" alike as "not found". So when the `sync-state` directory is not found,
//! the nearest existing ancestor must be shown to be a plain directory
//! (missing intermediate directories are normal first use); a regular file,
//! reparse point, I/O error or a path with no existing ancestor at all is
//! `Unreadable`, never `NotConfigured`.
//!
//! # Recovery artifacts
//!
//! Temporary files are `<key>.<32 lowercase hex>.tmp` in the same directory.
//! Exactly that pattern, for the record's own key, is a *recovery artifact*:
//! it blocks [`SyncStateStore::create`], makes a missing record
//! [`UnreadableReason::UnresolvedArtifacts`] rather than absent, and is removed
//! by an explicit [`SyncStateStore::delete`]. Nothing else is ever deleted, and
//! nothing is deleted automatically: files that merely share the prefix are
//! unrelated and ignored. A primary record is authoritative regardless of
//! leftover artifacts (an unpublished temp can never be adopted), so `load` and
//! `replace` tolerate them.
//!
//! # Reset evidence (Stage 1U-4 B1i)
//!
//! [`SyncStateStore::evidence`] captures read-only [`RecordEvidence`]: whether
//! the primary record exists and the length and SHA-256 of its exact bytes, plus
//! every recognized recovery artifact by name, length and SHA-256. It refuses
//! (never guesses) when any of those files cannot be read in full and judged a
//! plain file. [`SyncStateStore::delete_if_evidence_matches`] is `delete` that
//! first compares fresh evidence with the expected evidence, immediately before
//! its first removal, and refuses with nothing removed on any difference. It is
//! a narrowed read-then-delete, **not** compare-and-swap. `load` and `delete`
//! are unchanged.
//!
//! # v3 layout diagnostic (Stage 1U-4 B3c-3b-1)
//!
//! [`SyncStateStore::inspect_v3_layout`] is a separate, dormant, strictly
//! read-only observation of the directory for one record key: the primary,
//! `<key>.<32 hex>.tmp`, `<key>.<32 hex>.retired` and (reserved, see below)
//! `<key>.<32 hex>.v3stage` siblings, and a count of other key-prefixed entries. It
//! has its own name grammar and its own bounded scan, and it shares no code with
//! the recovery-artifact rules above. Those rules are **unchanged in what they
//! recognize and remove**: the legacy store still recognizes, and deletes, only its
//! `.tmp` staging names, and it never removes a `.retired` or `.v3stage` file.
//! Since Stage 1U-4 B3c-3b-2a the legacy operations additionally *consult* the
//! observation through the compatibility gate described next and refuse when it
//! shows newer-state evidence. A recognized name is an indicator only (never
//! ownership, recovery authority, deletion authority or write permission), no
//! production code calls the diagnostic itself, and a successful observation is not
//! a lock.
//!
//! # Legacy compatibility gate (Stage 1U-4 B3c-3b-2a)
//!
//! **Refuse-only.** `load`, `read_record`, `create`, `replace`, `evidence` and the
//! deletion planning (so `delete` and `delete_if_evidence_matches` too) ask the gate
//! first. The gate only observes: it creates, removes, renames, replaces and adopts
//! nothing, it never authenticates a version-1 record as anything else, and it adds
//! no deletion target. It can only take permissions away. For the current record
//! key it refuses when:
//!
//! * a recognized `.retired` sibling exists, whatever it contains;
//! * a recognized `.v3stage` sibling exists, whatever it contains or whether it
//!   can be read (the name is judged before any body byte);
//! * a key-prefixed entry exists that matches no recognized shape (so renamed or
//!   future evidence is not silently ignored); entries of other record keys never
//!   count;
//! * a `.tmp` holds a **complete, well-formed** record of a version this build
//!   does not support;
//! * the observation is incomplete or inconsistent (unreadable entry, entry or
//!   sibling limit, an alias, or a change between the two passes). Uncertainty is
//!   never confirmed absence.
//!
//! `delete` and `delete_if_evidence_matches` additionally refuse a primary of an
//! unsupported version, so such a record is no longer resettable. A primary is
//! never refused by `read_record` (its bytes are still returned, with a truthful
//! [`ArtifactPresence`]), so the dormant authenticated loader keeps working.
//!
//! An incomplete or empty `.tmp` keeps its legacy meaning (a resettable remnant):
//! the complete-record check cannot see an empty or truncated version-3 record,
//! because the codec parses the whole input before it reads a version. That is why
//! the `.v3stage` name is reserved (decision U9): a future publisher must never use
//! `.tmp`, and **nothing in this build creates a `.v3stage` file**. A matching name
//! identifies a conforming publisher's file; it is not ownership and gives no
//! recovery authority.
//!
//! **What this is not.** It is check-then-use, not a lock and not compare-and-swap:
//! anything can change right after the check. Older binaries are not gated. The
//! gate itself does not make deletion safe against a replaced primary; since Stage
//! 1U-4 B3c-3b-2d-1 the deletion is bound to held handles instead (next section).
//! `replace` still has a check-then-rename shape and its re-check before the rename
//! narrows, but does not close, the window (**G12-replace, open**). G2 is not
//! resolved by this gate.
//!
//! # Handle-bound deletion (Stage 1U-4 B3c-3b-2d-1; G12 for reset)
//!
//! `delete` and `delete_if_evidence_matches` no longer remove anything by path. They
//! pin the directory, hold every planned file open (`GENERIC_READ | DELETE`,
//! read-only sharing) before the first removal, compare the bytes read through those
//! handles with the expected evidence, recheck the layout, and mark each file for
//! removal through its own handle (see `held_removal`). The grammar of what may be
//! removed (the record and its recognized `.tmp` artifacts) is unchanged. A refusal
//! before the first removal is [`StoreError::RemovalRefused`]; a failure after it is
//! `IncompleteDeletion`; a result is `Removed` only when every mark was proven and
//! the names were then verified absent. The guarantees and limits are listed on
//! [`SyncStateStore::delete_if_evidence_matches`].
//!
//! # Guarantees and limits
//!
//! * **Create** is no-clobber because publication is `hard_link(temp, record)`,
//!   which fails if the name exists (verified: `ERROR_ALREADY_EXISTS` on NTFS).
//!   `fs::rename` is *not* used for creation: on Windows it replaces an existing
//!   destination, so check-then-rename would be a race. A filesystem without
//!   hard links yields [`StoreError::NoClobberUnsupported`]; there is no
//!   fallback to an overwriting rename.
//! * **Replace** is a re-read, compare, temp-write, re-read, rename sequence. It
//!   is **not** compare-and-swap against an arbitrary competing process: another
//!   writer can still slip in between the last read and the rename. It is safe
//!   only under the exclusive per-vault session lock, which the future
//!   integration must hold for every state operation. This module adds no
//!   cross-process locking.
//! * Temp contents are flushed (`sync_all`) before publication and every write is
//!   verified by reading the record back and decoding it. Directory entries are
//!   not flushed (std offers no portable way on Windows); physical power-loss
//!   consistency is **not** proven here and relies on NTFS journaling.
//! * Unexpected reparse points are never followed: the directory and record are
//!   inspected with `symlink_metadata`, the record is opened with
//!   `FILE_FLAG_OPEN_REPARSE_POINT` and re-checked on the handle. Every
//!   *existing* ancestor of the `sync-state` directory, up to the filesystem
//!   root, must also be a plain directory (Stage 1U-4 B1b); a junction, symlink
//!   or other reparse point anywhere in that chain is `Unreadable`, never
//!   trusted as ordinary device-local storage, and never created through. This
//!   is a check-then-use inspection: it does not stop a redirection that is
//!   installed *after* the check, and the later opens still traverse ancestors
//!   normally.
//! * Physical file-symlink rejection is covered by the shared reparse check and
//!   by junction tests, but the file-symlink test could not create a symlink
//!   under this account's privileges and is an unverified residual.
//! * Errors and `Debug` output carry fixed categories and `io::ErrorKind` only:
//!   never a path, locator, vault id, binding id or record body.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use localvault_core::{
    sync::EnvelopeFingerprint,
    sync_state::{
        Locator, SyncBase, SyncState, SyncStateEncodeError, SyncStateLoad, MAX_SYNC_STATE_BYTES,
    },
};
use thiserror::Error;
use uuid::Uuid;

use super::{
    file_identity::{facts_of, FileIdentity},
    held_removal::{DirectoryPin, HeldFile, RemovalMark},
};

/// Subdirectory of the supplied application-data root that holds all records.
pub const SYNC_STATE_DIRECTORY: &str = "sync-state";

/// Why a [`SyncStateRoot`] could not be established. Categories only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RootError {
    #[error("the device-local application-data directory is unavailable")]
    Unavailable,
    #[error("the device-local application-data directory is not an absolute path")]
    NotAbsolute,
}

/// The device-local application-data root that sync-state records live under.
///
/// The only production constructor is [`SyncStateRoot::from_app`], which asks
/// the trusted Tauri application context for `app_local_data_dir()`. No
/// command, UI value or user-supplied string can produce one, so a caller of
/// the session integration cannot redirect the store to an arbitrary directory
/// (such as the vault's folder, the roaming config directory or the working
/// directory). Tests build one from an explicit scratch path.
#[derive(Clone, PartialEq, Eq)]
pub struct SyncStateRoot(PathBuf);

impl SyncStateRoot {
    /// Resolve Tauri's `app_local_data_dir()` (the per-user *local*, non-roaming
    /// application-data directory). Never `app_config_dir()`.
    pub fn from_app<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<Self, RootError> {
        use tauri::Manager;

        Self::from_resolved(app.path().app_local_data_dir())
    }

    fn from_resolved<E>(resolved: Result<PathBuf, E>) -> Result<Self, RootError> {
        let path = resolved.map_err(|_| RootError::Unavailable)?;

        if !path.is_absolute() {
            return Err(RootError::NotAbsolute);
        }

        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(path: PathBuf) -> Self {
        Self::from_resolved::<()>(Ok(path)).unwrap()
    }
}

impl fmt::Debug for SyncStateRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyncStateRoot(<redacted>)")
    }
}

const RECORD_EXTENSION: &str = "json";
const ARTIFACT_EXTENSION: &str = "tmp";
const ARTIFACT_TOKEN_LEN: usize = 32;
const MAX_SCANNED_ENTRIES: usize = 10_000;
const TEMP_ALLOCATION_ATTEMPTS: usize = 16;

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Why a record that exists was not accepted as corrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptReason {
    /// Zero bytes.
    Empty,
    /// Larger than `MAX_SYNC_STATE_BYTES`; rejected from metadata, or after a
    /// bounded read if it grew.
    TooLarge,
    /// Not decodable by the core codec (bad JSON, truncation, checksum,
    /// malformed or inconsistent fields).
    Undecodable,
    /// Decodes, but its own `local_locator` is not the requested location
    /// (for example a record copied under another key).
    LocatorMismatch,
}

/// Why the state could not be read, or its absence could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadableReason {
    /// An I/O or permission failure.
    Io(io::ErrorKind),
    /// A directory, symlink, junction or other reparse point where a plain
    /// file or directory was required.
    UnexpectedObject,
    /// No record, but a recovery artifact of an interrupted write exists.
    UnresolvedArtifacts,
    /// The directory holds too many entries to scan for artifacts.
    EntryLimit,
    /// Files that this version does not understand exist beside the record (a
    /// reserved or retained sibling of a newer state, or a complete record of a
    /// newer version in a staging file). They are never read as state, adopted or
    /// removed by this version. Never absence.
    UnresolvedNewerState,
    /// The directory could not be assessed completely (too many related files, an
    /// ambiguous name, or a change while it was scanned). Never absence.
    LayoutUncertain,
    /// Entries named after this record's key match no recognized shape. They are
    /// left alone and block the operation. Never absence.
    UnrecognizedEntries,
}

/// Typed result of [`SyncStateStore::load`]. A superset of the core
/// [`SyncStateLoad`]; see [`StateLoad::into_sync_state_load`].
#[derive(Clone, PartialEq, Eq)]
pub enum StateLoad {
    /// Confirmed absent, including recovery artifacts.
    NotConfigured,
    /// A valid record for exactly the requested local location. The vault
    /// binding tag is **not** verified here.
    Loaded(Box<SyncState>),
    Corrupt(CorruptReason),
    UnsupportedVersion,
    Unreadable(UnreadableReason),
}

impl StateLoad {
    /// The accepted core outcome, for the pure transitions. Every reason is
    /// folded into `Corrupt` or `Unreadable`; neither is ever `NotConfigured`.
    pub fn into_sync_state_load(self) -> SyncStateLoad {
        match self {
            Self::NotConfigured => SyncStateLoad::NotConfigured,
            Self::Loaded(state) => SyncStateLoad::Loaded(state),
            Self::Corrupt(_) => SyncStateLoad::Corrupt,
            Self::UnsupportedVersion => SyncStateLoad::UnsupportedVersion,
            Self::Unreadable(_) => SyncStateLoad::Unreadable,
        }
    }
}

// The state is not printed: its own Debug would show binding ids, fingerprints
// and revisions, none of which belong in a log line.
impl fmt::Debug for StateLoad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("NotConfigured"),
            Self::Loaded(_) => f.write_str("Loaded(<state>)"),
            Self::Corrupt(reason) => write!(f, "Corrupt({reason:?})"),
            Self::UnsupportedVersion => f.write_str("UnsupportedVersion"),
            Self::Unreadable(reason) => write!(f, "Unreadable({reason:?})"),
        }
    }
}

/// Whether recognized recovery artifacts (`<key>.<token>.tmp`) were seen beside a
/// primary record that was read. A diagnostic indicator only.
///
/// Neither [`Present`](Self::Present) nor [`Unknown`](Self::Unknown) is ever a
/// clean-persistence condition and neither is permission for anything: a caller
/// must not treat either value as "safe to proceed", and [`None`](Self::None) is
/// only what one directory scan reported at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactPresence {
    /// The scan completed and found no recognized artifact.
    None,
    /// The scan completed and found at least one recognized artifact. Its
    /// contents were not read and are never adopted.
    Present,
    /// The scan could not be completed (I/O failure or too many entries), so
    /// nothing is known about artifacts. Never reported as [`None`](Self::None).
    Unknown,
}

/// The exact bytes of a primary record, as read once, with the artifact
/// indicator. Not `Clone`: the bytes are the raw record and stay with the one
/// reader. `Debug` reveals nothing.
pub struct PresentRecord {
    bytes: Vec<u8>,
    artifacts: ArtifactPresence,
}

impl PresentRecord {
    /// The exact bounded bytes read from the primary record (`1..=
    /// MAX_SYNC_STATE_BYTES`). Not decoded and not authenticated.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn artifacts(&self) -> ArtifactPresence {
        self.artifacts
    }
}

impl fmt::Debug for PresentRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresentRecord(<redacted>)")
    }
}

/// Typed result of [`SyncStateStore::read_record`]: the raw outcome of reading
/// one record, before any decoding. The same categories as [`StateLoad`], except
/// that a primary that was read is returned as bytes
/// ([`Present`](Self::Present)) instead of being decoded.
pub enum RecordRead {
    /// Confirmed absent, including recovery artifacts.
    NotConfigured,
    Unreadable(UnreadableReason),
    /// Only [`CorruptReason::Empty`] or [`CorruptReason::TooLarge`]: the store
    /// never decodes, so nothing else can be established here.
    Corrupt(CorruptReason),
    Present(PresentRecord),
}

// The bytes are not printed.
impl fmt::Debug for RecordRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("NotConfigured"),
            Self::Unreadable(reason) => write!(f, "Unreadable({reason:?})"),
            Self::Corrupt(reason) => write!(f, "Corrupt({reason:?})"),
            Self::Present(_) => f.write_str("Present(<redacted>)"),
        }
    }
}

/// Which filesystem step failed. A category only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoStage {
    Directory,
    Inspect,
    Scan,
    Open,
    Write,
    Sync,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StoreError {
    #[error("the sync-state root must be an absolute path")]
    RootNotAbsolute,
    #[error("a sync-state record already exists")]
    AlreadyExists,
    #[error("the sync-state record is missing")]
    Missing,
    #[error("unresolved sync-state recovery artifacts exist")]
    UnresolvedArtifacts,
    #[error("a sync-state path is not a regular file or directory")]
    UnexpectedObject,
    #[error("the current sync-state record could not be read")]
    CurrentUnreadable,
    #[error("the current sync-state record is corrupt")]
    CurrentCorrupt,
    #[error("the current sync-state record has an unsupported version")]
    CurrentUnsupportedVersion,
    #[error("the current sync-state record belongs to a different local location")]
    CurrentLocatorMismatch,
    #[error("the sync-state record changed since it was observed")]
    Changed,
    #[error("the replacement is for a different local location")]
    LocatorMismatch,
    #[error("a replacement must keep the binding identity")]
    BindingIdentityChanged,
    #[error("a replacement must not lower or drop the trusted checkpoint")]
    TrustedHistoryRegression,
    #[error("the filesystem cannot publish a new record without overwriting")]
    NoClobberUnsupported,
    #[error("the written sync-state record could not be verified")]
    VerificationFailed,
    #[error("sync-state deletion is incomplete")]
    IncompleteDeletion,
    #[error("sync state could not be encoded: {0}")]
    Encode(SyncStateEncodeError),
    #[error("a sync-state filesystem operation failed ({stage:?}, {kind:?})")]
    Io { stage: IoStage, kind: io::ErrorKind },
    #[error("files of a newer or unresolved sync state exist; nothing was changed")]
    UnresolvedNewerState,
    #[error("the sync-state directory could not be assessed completely; nothing was changed")]
    LayoutUncertain,
    #[error("unrecognized entries exist for this sync-state record; nothing was changed")]
    UnrecognizedEntries,
    /// The deletion could not hold the files it would remove. Produced **only
    /// before any removal** in the call that returns it: nothing was removed.
    #[error("the sync-state files could not be held for removal; nothing was removed")]
    RemovalRefused(RemovalRefusal),
}

/// Why a deletion refused to start (B3c-3b-2d-1). Every one of them means this call
/// removed **nothing**; a failure after the first removal is
/// [`StoreError::IncompleteDeletion`], never one of these. Categories only: no path,
/// name, identifier or native status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalRefusal {
    /// Another process has a file open in a way that excludes the hold (no delete
    /// sharing, or write access). No automatic retry.
    Busy,
    /// The sync-state directory is not a plain directory on local NTFS, or it was
    /// replaced while it was pinned.
    DirectoryUnsupported,
    /// A planned file is not something that can be held for removal: not a plain
    /// file, read-only, not on local NTFS, delete-pending, or otherwise unopenable.
    FileUnsuitable,
    /// A planned file has a name outside the plan (a hard link), or its facts
    /// changed after they were judged.
    ExtraNames,
    /// What is in the directory is no longer what was planned.
    PlanChanged,
}

/// Outcome of a successful [`SyncStateStore::delete`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// Something was removed and the removal was verified.
    Removed,
    /// There was nothing to remove (verified).
    AlreadyAbsent,
}

/// Why [`SyncStateStore::evidence`] could not capture exact evidence. Categories
/// only: no path, name, size or `io::ErrorKind`. Every one of them means "do not
/// treat this record as resettable": nothing was concluded about its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EvidenceRefusal {
    /// An I/O or permission failure while inspecting or reading a file.
    #[error("the sync-state files could not be read to capture evidence")]
    Unreadable,
    /// A directory, symlink, junction or other reparse point where a plain file
    /// or directory was required.
    #[error("a sync-state path is not a regular file or directory")]
    UnexpectedObject,
    /// The directory holds too many entries to scan.
    #[error("the sync-state directory holds too many entries")]
    EntryLimit,
    /// The record or a recovery artifact is larger than the supported maximum, so
    /// it cannot be read in full and bound exactly.
    #[error("a sync-state file is larger than the supported maximum")]
    Oversized,
    /// A file disappeared between listing it and reading it.
    #[error("a sync-state file changed while evidence was captured")]
    Unstable,
    /// Files of a newer or unresolved state exist beside the record, so no
    /// evidence of the record alone can stand for its state.
    #[error("files of a newer or unresolved sync state exist")]
    UnresolvedNewerState,
    /// Entries named after this record's key match no recognized shape.
    #[error("unrecognized entries exist for this sync-state record")]
    UnrecognizedEntries,
}

impl From<Fault> for EvidenceRefusal {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Io(_) => Self::Unreadable,
            Fault::Unexpected => Self::UnexpectedObject,
            Fault::EntryLimit => Self::EntryLimit,
        }
    }
}

/// Length and SHA-256 of the exact bytes of one fully read file.
#[derive(Clone, PartialEq, Eq)]
struct FileEvidence {
    len: u64,
    digest: EnvelopeFingerprint,
}

impl FileEvidence {
    fn of(bytes: &[u8]) -> Self {
        Self {
            len: bytes.len() as u64,
            digest: EnvelopeFingerprint::of_bytes(bytes),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ArtifactEvidence {
    /// ASCII-lowercased file name (the store's own artifact-name rule).
    name: String,
    file: FileEvidence,
}

/// Exact, read-only evidence of what the store holds for **one local location**
/// at one instant: whether the primary record is present and, if it is, the
/// length and SHA-256 of its exact bytes, plus the complete set of recognized
/// recovery artifacts, each by name, length and SHA-256 of its exact bytes.
///
/// Equality of two values means every one of those bytes was identical when they
/// were captured, for the same record key. It is **not** proof that no other
/// process changed anything in between, it carries no physical file identity (a
/// file replaced by an identical copy is equal evidence), and it is not a lock.
///
/// It exists so that an explicit, user-approved reset can refuse to delete state
/// that differs from what the user was shown; see
/// [`SyncStateStore::delete_if_evidence_matches`]. `Debug` reveals nothing: no
/// path, name, length, hash or key.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordEvidence {
    key: String,
    primary: Option<FileEvidence>,
    artifacts: Vec<ArtifactEvidence>,
}

impl RecordEvidence {
    /// Whether a primary record file was present.
    pub fn primary_present(&self) -> bool {
        self.primary.is_some()
    }

    /// How many recognized recovery artifacts were present.
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }
}

impl fmt::Debug for RecordEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordEvidence(<redacted>)")
    }
}

/// Why [`SyncStateStore::delete_if_evidence_matches`] did not complete.
///
/// [`Evidence`](Self::Evidence), [`EvidenceChanged`](Self::EvidenceChanged) and
/// every [`Store`](Self::Store) error except `IncompleteDeletion` are reported
/// strictly **before the first removal**: this call removed nothing. Only
/// `Store(IncompleteDeletion)` can follow a partial removal. See
/// [`removal_may_have_started`](Self::removal_may_have_started).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConditionalDeleteError {
    #[error("evidence could not be captured; nothing was removed")]
    Evidence(EvidenceRefusal),
    #[error("the sync-state files differ from the expected evidence; nothing was removed")]
    EvidenceChanged,
    #[error("sync-state deletion failed")]
    Store(StoreError),
}

impl ConditionalDeleteError {
    /// Whether this call may already have removed something. Derived from the
    /// deletion's own sequence: every precondition (directory, artifact scan, the
    /// plain-file checks, the evidence comparison) precedes the first removal and
    /// reports a different error; once removal has begun, a failure to remove or
    /// to verify the removal is `IncompleteDeletion`, and nothing else.
    pub fn removal_may_have_started(self) -> bool {
        matches!(self, Self::Store(StoreError::IncompleteDeletion))
    }
}

/// What a deletion will remove, established before anything is removed.
struct DeletePlan {
    key: String,
    record: PathBuf,
    artifacts: Vec<PathBuf>,
    record_present: bool,
}

/// Internal filesystem failure, before it is mapped to a public type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Io(io::ErrorKind),
    Unexpected,
    EntryLimit,
}

impl From<Fault> for UnreadableReason {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Io(kind) => Self::Io(kind),
            Fault::Unexpected => Self::UnexpectedObject,
            Fault::EntryLimit => Self::EntryLimit,
        }
    }
}

impl Fault {
    fn into_store_error(self, stage: IoStage) -> StoreError {
        match self {
            Self::Io(kind) => StoreError::Io { stage, kind },
            Self::Unexpected => StoreError::UnexpectedObject,
            Self::EntryLimit => StoreError::Io {
                stage: IoStage::Scan,
                kind: io::ErrorKind::Other,
            },
        }
    }
}

enum DirState {
    Absent,
    Present,
}

enum Primary {
    Absent,
    Empty,
    TooLarge,
    Bytes(Vec<u8>),
}

/// Fault-injection points (tests only act on them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Point {
    TempSync,
    Publish,
    BeforeReplace,
    Replace,
    Verify,
    RemoveArtifact,
    RemovePrimary,
    BeforeEvidenceRecheck,
    /// Before the deletion pins the directory and holds its files.
    BeforeHold,
    /// After every planned file is held and read, before the layout is rechecked.
    AfterHold,
    /// After the last handle has been closed, before the absence is verified.
    AfterClose,
}

#[cfg(test)]
enum Action {
    Fail(io::ErrorKind),
    Run(Box<dyn Fn() + Send>),
}

pub struct SyncStateStore {
    directory: PathBuf,
    #[cfg(test)]
    faults: std::sync::Mutex<Vec<(Point, Action)>>,
}

impl fmt::Debug for SyncStateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyncStateStore(<redacted>)")
    }
}

impl SyncStateStore {
    /// `app_local_data_root` is the caller-supplied device-local
    /// application-data directory; records live in its `sync-state`
    /// subdirectory, which is created on first [`create`](Self::create).
    pub fn new(app_local_data_root: &Path) -> Result<Self, StoreError> {
        if !app_local_data_root.is_absolute() {
            return Err(StoreError::RootNotAbsolute);
        }

        Ok(Self {
            directory: app_local_data_root.join(SYNC_STATE_DIRECTORY),
            #[cfg(test)]
            faults: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// The `sync-state` directory this store reads and writes. A path, never an
    /// authorization: it lets a caller refuse a selected target that lies inside
    /// the store itself.
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    /// Strictly read the record of `local_locator`.
    ///
    /// Never creates, repairs, deletes or resets anything.
    pub fn load(&self, local_locator: &Locator) -> StateLoad {
        let key = record_key(local_locator);

        match self.inspect_directory() {
            Ok(DirState::Absent) => return StateLoad::NotConfigured,
            Ok(DirState::Present) => {}
            Err(fault) => return StateLoad::Unreadable(fault.into()),
        }

        // Refuse-only: newer-state evidence or an uncertain scan is never absence
        // and is never overridden by a readable primary.
        if let Err(refusal) = self.legacy_gate(&key) {
            return StateLoad::Unreadable(refusal.into());
        }

        match self.read_primary(&self.record_path(&key)) {
            Err(fault) => StateLoad::Unreadable(fault.into()),
            Ok(Primary::Empty) => StateLoad::Corrupt(CorruptReason::Empty),
            Ok(Primary::TooLarge) => StateLoad::Corrupt(CorruptReason::TooLarge),
            Ok(Primary::Bytes(bytes)) => classify(local_locator, &bytes),
            Ok(Primary::Absent) => match self.scan_artifacts(&key) {
                Err(fault) => StateLoad::Unreadable(fault.into()),
                Ok(artifacts) if !artifacts.is_empty() => {
                    StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
                }
                Ok(_) => StateLoad::NotConfigured,
            },
        }
    }

    /// Strictly read the raw bytes of the record of `local_locator`, without
    /// decoding them.
    ///
    /// Same guarded order and helpers as [`load`](Self::load): every existing
    /// ancestor and the directory must be plain directories (absent directory:
    /// `NotConfigured`), the primary is read through the bounded no-follow path
    /// (`Empty` and `TooLarge` are reported, never read past the limit), and an
    /// absent primary is `NotConfigured` only when no recognized recovery
    /// artifact exists (otherwise `Unreadable(UnresolvedArtifacts)`). A failure,
    /// an unexpected object or an unscannable directory is `Unreadable`, never
    /// absence.
    ///
    /// When the primary is present its exact bytes are returned, together with an
    /// [`ArtifactPresence`] from one extra scan; a scan failure there makes it
    /// `Unknown` and never fails the read. A recovery artifact is never read,
    /// adopted or preferred over the primary.
    ///
    /// This is crypto-agnostic: it neither decodes nor verifies nor produces any
    /// MAC, and it never creates, repairs, replaces or removes anything. The bytes
    /// are what the filesystem returned at one instant; this is not a lock and not
    /// compare-and-swap, and a caller that needs more than that must say so itself.
    pub fn read_record(&self, local_locator: &Locator) -> RecordRead {
        let key = record_key(local_locator);

        match self.inspect_directory() {
            Ok(DirState::Absent) => return RecordRead::NotConfigured,
            Ok(DirState::Present) => {}
            Err(fault) => return RecordRead::Unreadable(fault.into()),
        }

        // The gate never refuses a primary that is present: the read-only
        // authenticated loader depends on getting its exact bytes. It only makes
        // the artifact indicator truthful.
        let gate = self.legacy_gate(&key);

        match self.read_primary(&self.record_path(&key)) {
            Err(fault) => RecordRead::Unreadable(fault.into()),
            Ok(Primary::Empty) => RecordRead::Corrupt(CorruptReason::Empty),
            Ok(Primary::TooLarge) => RecordRead::Corrupt(CorruptReason::TooLarge),
            Ok(Primary::Bytes(bytes)) => {
                let artifacts = match gate {
                    Err(LegacyGateRefusal::NewerState | LegacyGateRefusal::UnrecognizedEntries) => {
                        ArtifactPresence::Present
                    }
                    Err(LegacyGateRefusal::Uncertain(_)) => ArtifactPresence::Unknown,
                    Ok(_) => match self.scan_artifacts(&key) {
                        Ok(found) if found.is_empty() => ArtifactPresence::None,
                        Ok(_) => ArtifactPresence::Present,
                        Err(_) => ArtifactPresence::Unknown,
                    },
                };

                RecordRead::Present(PresentRecord { bytes, artifacts })
            }
            Ok(Primary::Absent) => match gate {
                Err(refusal) => RecordRead::Unreadable(refusal.into()),
                Ok(_) => match self.scan_artifacts(&key) {
                    Err(fault) => RecordRead::Unreadable(fault.into()),
                    Ok(artifacts) if !artifacts.is_empty() => {
                        RecordRead::Unreadable(UnreadableReason::UnresolvedArtifacts)
                    }
                    Ok(_) => RecordRead::NotConfigured,
                },
            },
        }
    }

    /// Publish a new record. Succeeds only if the record is definitely absent,
    /// no recovery artifact exists, publication is no-clobber, and the record
    /// reads back byte-identical and decodes to `state`.
    ///
    /// After `VerificationFailed` or an `Io` error the record may or may not
    /// exist: call [`load`](Self::load) before deciding anything.
    pub fn create(&self, state: &SyncState) -> Result<(), StoreError> {
        let bytes = state.encode().map_err(StoreError::Encode)?;
        let key = record_key(state.local_locator());

        self.ensure_directory()?;

        // Refuse-only. There is deliberately no second check later in this method:
        // publication is a no-clobber link and the caller reloads afterwards.
        self.legacy_gate(&key).map_err(StoreError::from)?;

        let record = self.record_path(&key);

        match fs::symlink_metadata(&record) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(metadata) if is_plain_file(&metadata) => return Err(StoreError::AlreadyExists),
            Ok(_) => return Err(StoreError::UnexpectedObject),
            Err(error) => {
                return Err(StoreError::Io {
                    stage: IoStage::Inspect,
                    kind: error.kind(),
                })
            }
        }

        let artifacts = self
            .scan_artifacts(&key)
            .map_err(|fault| fault.into_store_error(IoStage::Scan))?;
        if !artifacts.is_empty() {
            return Err(StoreError::UnresolvedArtifacts);
        }

        let temp = self.write_temp(&key, &bytes)?;

        let published = self
            .hook(Point::Publish)
            .and_then(|()| fs::hard_link(&temp, &record));

        // The temp name is only a staging name; the record is now (or never
        // will be) a second name for the same synced file.
        let _ = fs::remove_file(&temp);

        if let Err(error) = published {
            return Err(map_publish_error(&error));
        }

        self.verify(&record, &bytes, state)
    }

    /// Replace the record that currently holds `expected` with `proposed`.
    ///
    /// See the module documentation: this is read-compare-write, not
    /// compare-and-swap, and requires the caller to hold the exclusive vault
    /// session lock. The replacement must keep the binding identity (binding id,
    /// vault tag, both locators) and must not lower the trusted high-water mark
    /// or drop the checkpoint; resetting a binding is [`delete`](Self::delete)
    /// followed by a new binding.
    pub fn replace(&self, expected: &SyncState, proposed: &SyncState) -> Result<(), StoreError> {
        check_replacement(expected, proposed)?;

        let bytes = proposed.encode().map_err(StoreError::Encode)?;
        let key = record_key(expected.local_locator());

        match self
            .inspect_directory()
            .map_err(|fault| fault.into_store_error(IoStage::Inspect))?
        {
            DirState::Absent => return Err(StoreError::Missing),
            DirState::Present => {}
        }

        self.legacy_gate(&key).map_err(StoreError::from)?;

        let record = self.record_path(&key);

        let observed = match self.read_primary(&record) {
            Err(_) => return Err(StoreError::CurrentUnreadable),
            Ok(Primary::Absent) => return Err(StoreError::Missing),
            Ok(Primary::Empty) | Ok(Primary::TooLarge) => return Err(StoreError::CurrentCorrupt),
            Ok(Primary::Bytes(observed)) => observed,
        };

        match classify(expected.local_locator(), &observed) {
            StateLoad::Loaded(current) if *current == *expected => {}
            StateLoad::Loaded(_) => return Err(StoreError::Changed),
            StateLoad::Corrupt(CorruptReason::LocatorMismatch) => {
                return Err(StoreError::CurrentLocatorMismatch)
            }
            StateLoad::UnsupportedVersion => return Err(StoreError::CurrentUnsupportedVersion),
            _ => return Err(StoreError::CurrentCorrupt),
        }

        let temp = self.write_temp(&key, &bytes)?;

        let swapped = (|| {
            self.hook(Point::BeforeReplace)
                .map_err(|error| StoreError::Io {
                    stage: IoStage::Inspect,
                    kind: error.kind(),
                })?;

            // Narrow the window: the record must still be byte-identical to
            // what was compared above. This does not close it.
            match self.read_primary(&record) {
                Ok(Primary::Bytes(again)) if again == observed => {}
                Ok(_) => return Err(StoreError::Changed),
                Err(_) => return Err(StoreError::CurrentUnreadable),
            }

            // Newer-state evidence that appeared since the first check refuses
            // here, before the only step that destroys. A refusal leaves the record
            // untouched and takes the cleanup path below. This narrows the window
            // to the calls between this check and the rename; it does not close it.
            self.legacy_gate(&key).map_err(StoreError::from)?;

            self.hook(Point::Replace)
                .and_then(|()| fs::rename(&temp, &record))
                .map_err(|error| StoreError::Io {
                    stage: IoStage::Replace,
                    kind: error.kind(),
                })
        })();

        if let Err(error) = swapped {
            // The record was never replaced; only our own staging file goes.
            let _ = fs::remove_file(&temp);
            return Err(error);
        }

        self.verify(&record, &bytes, proposed)
    }

    /// Explicitly remove the record of `local_locator` and its recognized
    /// recovery artifacts. Works on a corrupt or unsupported record too; it is
    /// the only operation that removes anything, and must only be called for an
    /// explicit user-approved reset, unbind or vault deletion.
    ///
    /// Artifacts go first and the record last. A crash before the record is
    /// removed leaves the intact binding. A crash after the last file was
    /// removed but before success is reported leaves a fully absent record
    /// (`NotConfigured`): that is the intended, user-authorized loss of trust
    /// history, not an error. Partial cleanup that leaves artifacts is
    /// `Unreadable`, never absent. Anything that cannot be removed or verified
    /// gone is [`StoreError::IncompleteDeletion`]. Nothing else ever deletes.
    ///
    /// # Handle-bound removal (B3c-3b-2d-1, gate G12 for reset)
    ///
    /// Every file is removed through a handle it was held by, never by path. After
    /// the plan is made, the directory is pinned and every planned file is opened
    /// (`GENERIC_READ | DELETE`, read-only sharing) **before the first removal**;
    /// the layout is rechecked; and each file is then marked for removal through
    /// its own handle. A refusal to hold or recheck is
    /// [`StoreError::RemovalRefused`] and removed **nothing**; a failure after the
    /// first removal, or an unproven mark, is `IncompleteDeletion`. There is no
    /// retry and no path-based fallback. This variant reads no bytes, so it binds
    /// no content; the caller that needs that is
    /// [`delete_if_evidence_matches`](Self::delete_if_evidence_matches).
    pub fn delete(&self, local_locator: &Locator) -> Result<DeleteOutcome, StoreError> {
        let Some(plan) = self.plan_delete(local_locator)? else {
            return Ok(DeleteOutcome::AlreadyAbsent);
        };

        let held = self.hold_for_removal(&plan)?;

        self.recheck_held(&plan, &held)?;
        self.execute_delete(&plan, held)
    }

    /// Capture exact, read-only [`RecordEvidence`] of everything the store holds
    /// for `local_locator`: the primary record's length and SHA-256 and every
    /// recognized recovery artifact's name, length and SHA-256.
    ///
    /// It reads through the same guarded paths as [`load`](Self::load): every
    /// existing ancestor and the directory must be plain directories, files are
    /// judged with `symlink_metadata` and on the opened handle, nothing follows a
    /// reparse point, and reads are bounded by `MAX_SYNC_STATE_BYTES`. It never
    /// creates, repairs or removes anything.
    ///
    /// It **refuses** (an [`EvidenceRefusal`]) rather than guess whenever a file
    /// cannot be read in full and judged a plain file: a permission or I/O
    /// failure, a directory or reparse point where a file belongs, an oversized
    /// record or artifact, too many entries, or a file that vanished mid-capture.
    /// A missing directory or an empty one is the empty evidence (nothing present).
    ///
    /// A corrupt or unsupported record is **not** refused: its exact bytes are
    /// bound whatever they decode to.
    pub fn evidence(&self, local_locator: &Locator) -> Result<RecordEvidence, EvidenceRefusal> {
        let key = record_key(local_locator);

        match self.inspect_directory()? {
            DirState::Absent => {
                return Ok(RecordEvidence {
                    key,
                    primary: None,
                    artifacts: Vec::new(),
                })
            }
            DirState::Present => {}
        }

        self.legacy_gate(&key)?;

        let primary = match self.read_primary(&self.record_path(&key))? {
            Primary::Absent => None,
            Primary::Empty => Some(FileEvidence::of(&[])),
            Primary::TooLarge => return Err(EvidenceRefusal::Oversized),
            Primary::Bytes(bytes) => Some(FileEvidence::of(&bytes)),
        };

        let mut artifacts = Vec::new();

        for path in self.scan_artifacts(&key)? {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_ascii_lowercase)
                .ok_or(EvidenceRefusal::UnexpectedObject)?;

            let file = match self.read_primary(&path)? {
                Primary::Absent => return Err(EvidenceRefusal::Unstable),
                Primary::Empty => FileEvidence::of(&[]),
                Primary::TooLarge => return Err(EvidenceRefusal::Oversized),
                Primary::Bytes(bytes) => FileEvidence::of(&bytes),
            };

            artifacts.push(ArtifactEvidence { name, file });
        }

        artifacts.sort_by(|left, right| left.name.cmp(&right.name));

        Ok(RecordEvidence {
            key,
            primary,
            artifacts,
        })
    }

    /// [`delete`](Self::delete), but only if the store still holds exactly the
    /// state that `expected` describes for `local_locator`.
    ///
    /// In order: the same preconditions as `delete` (directory, artifact scan,
    /// every target a plain file); fresh evidence by path, compared with `expected`;
    /// then the directory is pinned and **every planned file is held and read
    /// through its own handle**, and the bytes read there are compared with
    /// `expected` again. **That comparison, on the handles that will remove the
    /// files, is the one that matters**: the earlier path comparison only fails
    /// early. Any difference refuses with nothing removed. Then the layout is
    /// rechecked and the files are marked for removal through the same handles,
    /// artifacts first and the record last, and the removal is verified.
    ///
    /// # What `Removed` means
    ///
    /// The planned names were removed through handles whose bytes were verified and
    /// which were held with read-only sharing from the read to the removal, and
    /// afterwards neither the record name nor any recognized artifact remained. It
    /// does **not** mean the bytes are erased: removing a name is not erasing a file,
    /// and a hard link created in the single call gap before a mark keeps the file
    /// object (the mark is then not `Marked`, and the result is
    /// `IncompleteDeletion`). It is not power-loss durable, and a multi-file removal
    /// is not atomic: a partial removal is `IncompleteDeletion`, never success.
    ///
    /// # What this is not
    ///
    /// It is **not** compare-and-swap. Sharing modes bind ordinary processes only;
    /// administrators, backup-privileged processes, kernel components and filter
    /// drivers can bypass them, writable mapped views are not addressed, and the
    /// driver's reported facts are trusted. When the record is a second name of a
    /// recovery artifact (the `create` remnant) the record's own name is **not**
    /// protected by the hold on the artifact (measured: another process can rename
    /// or unlink it); it is reopened and re-verified after the artifact is removed,
    /// and a mismatch is `IncompleteDeletion`. The legacy replacement is unchanged
    /// and still has the check-then-rename shape (G12-replace, open).
    ///
    /// New refusals, all before any removal ([`StoreError::RemovalRefused`]): a
    /// planned file is open elsewhere in a way that excludes the hold, has a name
    /// outside the plan, is read-only, or the directory is not on local NTFS.
    ///
    /// `Ok(AlreadyAbsent)` is returned only when the store holds nothing **and**
    /// `expected` is the empty evidence.
    pub fn delete_if_evidence_matches(
        &self,
        local_locator: &Locator,
        expected: &RecordEvidence,
    ) -> Result<DeleteOutcome, ConditionalDeleteError> {
        let plan = self
            .plan_delete(local_locator)
            .map_err(ConditionalDeleteError::Store)?;

        if self.hook(Point::BeforeEvidenceRecheck).is_err() {
            return Err(ConditionalDeleteError::Evidence(
                EvidenceRefusal::Unreadable,
            ));
        }

        let current = self
            .evidence(local_locator)
            .map_err(ConditionalDeleteError::Evidence)?;

        if current != *expected {
            return Err(ConditionalDeleteError::EvidenceChanged);
        }

        let Some(plan) = plan else {
            return Ok(DeleteOutcome::AlreadyAbsent);
        };

        if self.hook(Point::BeforeHold).is_err() {
            return Err(ConditionalDeleteError::Evidence(
                EvidenceRefusal::Unreadable,
            ));
        }

        let mut held = self
            .hold_for_removal(&plan)
            .map_err(ConditionalDeleteError::Store)?;

        // The comparison that matters: the bytes of the held files, read through the
        // handles that will remove them.
        match self.held_evidence(&plan, &mut held) {
            Some(evidence) if evidence == *expected => {}
            _ => return Err(ConditionalDeleteError::EvidenceChanged),
        }

        self.recheck_held(&plan, &held)
            .map_err(ConditionalDeleteError::Store)?;

        self.execute_delete(&plan, held)
            .map_err(ConditionalDeleteError::Store)
    }

    /// Everything `delete` checks before it removes anything. `None` is verified
    /// absence. Any error is reported with nothing removed.
    fn plan_delete(&self, local_locator: &Locator) -> Result<Option<DeletePlan>, StoreError> {
        let key = record_key(local_locator);

        match self
            .inspect_directory()
            .map_err(|fault| fault.into_store_error(IoStage::Inspect))?
        {
            DirState::Absent => return Ok(None),
            DirState::Present => {}
        }

        // Refuse-only. Beyond the sibling evidence, a primary of a version this
        // build does not support is no longer something it may remove.
        let layout = self.legacy_gate(&key).map_err(StoreError::from)?;

        if let LayoutPrimary::Bytes(bytes) = layout.primary() {
            if matches!(
                SyncStateLoad::from_bytes(bytes),
                SyncStateLoad::UnsupportedVersion
            ) {
                return Err(StoreError::UnresolvedNewerState);
            }
        }

        let record = self.record_path(&key);

        let artifacts = self
            .scan_artifacts(&key)
            .map_err(|fault| fault.into_store_error(IoStage::Scan))?;

        // Refuse before removing anything if any target is not a plain file.
        for artifact in &artifacts {
            match fs::symlink_metadata(artifact) {
                Ok(metadata) if is_plain_file(&metadata) => {}
                Ok(_) => return Err(StoreError::UnexpectedObject),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(StoreError::Io {
                        stage: IoStage::Inspect,
                        kind: error.kind(),
                    })
                }
            }
        }

        let record_present = match fs::symlink_metadata(&record) {
            Ok(metadata) if is_plain_file(&metadata) => true,
            Ok(_) => return Err(StoreError::UnexpectedObject),
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(StoreError::Io {
                    stage: IoStage::Inspect,
                    kind: error.kind(),
                })
            }
        };

        if artifacts.is_empty() && !record_present {
            return Ok(None);
        }

        Ok(Some(DeletePlan {
            key,
            record,
            artifacts,
            record_present,
        }))
    }

    /// Pin the directory and hold every planned file, **before anything is
    /// removed**. Any refusal returns with nothing removed.
    ///
    /// Link rule, exact: a planned file with one name is accepted. A planned
    /// artifact with exactly two names is accepted only as the `create` remnant: the
    /// record is planned and a read-only probe shows the artifact and the record are
    /// the same file, and no other artifact is such an alias. Everything else
    /// (including a record with an outside name, and two artifacts that are names of
    /// each other) is `ExtraNames` (or `Busy`, when the sharing mode of the first
    /// hold already excludes the second name). The record of an alias remnant is not
    /// held here; see [`HeldPrimary::Deferred`].
    fn hold_for_removal(&self, plan: &DeletePlan) -> Result<HeldFiles, StoreError> {
        use RemovalRefusal as Refusal;

        let refuse = StoreError::RemovalRefused;

        let pin = DirectoryPin::acquire(&self.directory).map_err(refuse)?;

        // After the pin, so a redirection installed before it is caught here.
        if self.confirm_ancestors().is_err() {
            return Err(refuse(Refusal::DirectoryUnsupported));
        }

        let mut artifacts: Vec<HeldArtifact> = Vec::with_capacity(plan.artifacts.len());

        for path in &plan.artifacts {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_ascii_lowercase)
                .ok_or(refuse(Refusal::FileUnsuitable))?;
            let file = HeldFile::open(path).map_err(refuse)?;

            let alias = match link_verdict(file.link_count()) {
                LinkVerdict::Single => false,
                LinkVerdict::Pair => {
                    if plan.record_present
                        && !artifacts.iter().any(|held| held.alias)
                        && self.is_second_name_of_record(plan, &file)
                    {
                        true
                    } else {
                        return Err(refuse(Refusal::ExtraNames));
                    }
                }
                LinkVerdict::Refuse => return Err(refuse(Refusal::ExtraNames)),
            };

            artifacts.push(HeldArtifact { name, file, alias });
        }

        let primary = if !plan.record_present {
            HeldPrimary::None
        } else if let Some(alias) = artifacts.iter().find(|held| held.alias) {
            HeldPrimary::Deferred {
                identity: alias.file.identity(),
                expected: None,
            }
        } else {
            let file = HeldFile::open(&plan.record).map_err(refuse)?;

            if link_verdict(file.link_count()) != LinkVerdict::Single {
                return Err(refuse(Refusal::ExtraNames));
            }

            HeldPrimary::Held(file)
        };

        Ok(HeldFiles {
            pin,
            artifacts,
            primary,
        })
    }

    /// Whether the record's name reaches the very file `held` is a handle to: a
    /// read-only, fully shared, no-follow probe, judged on its own handle.
    fn is_second_name_of_record(&self, plan: &DeletePlan, held: &HeldFile) -> bool {
        let Ok(probe) = open_no_follow(&plan.record) else {
            return false;
        };

        probe
            .metadata()
            .is_ok_and(|metadata| is_plain_file(&metadata))
            && facts_of(&probe).is_ok_and(|facts| facts.identity() == held.identity())
    }

    /// Rebuild the evidence of what is held from the bytes read **through the held
    /// handles**. `None` when any file cannot be read in full within the bound. The
    /// record of an alias remnant has the bytes of its held alias; they are kept for
    /// the later reopen.
    fn held_evidence(&self, plan: &DeletePlan, held: &mut HeldFiles) -> Option<RecordEvidence> {
        let limit = MAX_SYNC_STATE_BYTES as u64;

        let mut artifacts = Vec::with_capacity(held.artifacts.len());
        let mut alias_evidence = None;

        for artifact in &held.artifacts {
            let file = FileEvidence::of(&artifact.file.read_bounded(limit)?);

            if artifact.alias {
                alias_evidence = Some(file.clone());
            }

            artifacts.push(ArtifactEvidence {
                name: artifact.name.clone(),
                file,
            });
        }

        artifacts.sort_by(|left, right| left.name.cmp(&right.name));

        let primary = match &mut held.primary {
            HeldPrimary::None => None,
            HeldPrimary::Held(file) => Some(FileEvidence::of(&file.read_bounded(limit)?)),
            HeldPrimary::Deferred { expected, .. } => {
                let evidence = alias_evidence?;

                *expected = Some(evidence.clone());

                Some(evidence)
            }
        };

        Some(RecordEvidence {
            key: plan.key.clone(),
            primary,
            artifacts,
        })
    }

    /// The directory still holds exactly what was planned: the compatibility gate
    /// passes, the recognized artifacts are exactly `expected_artifacts` (lowercased
    /// names) and the record is present exactly if it was planned. Observes only.
    fn recheck_layout(
        &self,
        plan: &DeletePlan,
        expected_artifacts: &[String],
    ) -> Result<(), StoreError> {
        let layout = self.legacy_gate(&plan.key).map_err(StoreError::from)?;

        let record_present = match layout.primary() {
            LayoutPrimary::Absent => false,
            LayoutPrimary::Unexpected => {
                return Err(StoreError::RemovalRefused(RemovalRefusal::PlanChanged))
            }
            _ => true,
        };

        let mut names: Vec<String> = self
            .scan_artifacts(&plan.key)
            .map_err(|fault| fault.into_store_error(IoStage::Scan))?
            .iter()
            .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
            .map(str::to_ascii_lowercase)
            .collect();
        let mut expected: Vec<String> = expected_artifacts.to_vec();

        names.sort();
        expected.sort();

        if names != expected || record_present != plan.record_present {
            return Err(StoreError::RemovalRefused(RemovalRefusal::PlanChanged));
        }

        Ok(())
    }

    /// R1, before the first removal: the layout is as planned, the pinned directory
    /// is still the one the path reaches, and every held file still has exactly the
    /// facts it was judged with (a new name is noticed here). Nothing is removed on
    /// failure.
    fn recheck_held(&self, plan: &DeletePlan, held: &HeldFiles) -> Result<(), StoreError> {
        if let Err(error) = self.hook(Point::AfterHold) {
            return Err(StoreError::Io {
                stage: IoStage::Inspect,
                kind: error.kind(),
            });
        }

        let names: Vec<String> = held
            .artifacts
            .iter()
            .map(|artifact| artifact.name.clone())
            .collect();

        self.recheck_layout(plan, &names)?;

        if !held.pin.still_names(&self.directory) {
            return Err(StoreError::RemovalRefused(
                RemovalRefusal::DirectoryUnsupported,
            ));
        }

        let primary_unchanged = match &held.primary {
            HeldPrimary::Held(file) => file.unchanged(),
            HeldPrimary::None | HeldPrimary::Deferred { .. } => true,
        };

        if !primary_unchanged || !held.artifacts.iter().all(|a| a.file.unchanged()) {
            return Err(StoreError::RemovalRefused(RemovalRefusal::ExtraNames));
        }

        Ok(())
    }

    /// The removal and its verification. Artifacts first, the record last, each
    /// through its own handle; the handle of a file is closed when it is marked.
    ///
    /// A failure before the first mark that is a refusal (a changed fact) is
    /// `RemovalRefused`; once any mark has been attempted, every failure and every
    /// mark that is not proven is `IncompleteDeletion`. The final namespace check
    /// is mandatory: a successful mark alone is never success.
    fn execute_delete(
        &self,
        plan: &DeletePlan,
        held: HeldFiles,
    ) -> Result<DeleteOutcome, StoreError> {
        let HeldFiles {
            pin,
            artifacts,
            primary,
        } = held;
        let mut removed_any = false;

        for artifact in artifacts {
            self.hook(Point::RemoveArtifact)
                .map_err(|_| StoreError::IncompleteDeletion)?;

            if !artifact.file.unchanged() {
                return Err(changed_fact(removed_any));
            }

            match artifact.file.mark_for_removal() {
                RemovalMark::Marked => removed_any = true,
                RemovalMark::NotMarked | RemovalMark::Unknown => {
                    return Err(StoreError::IncompleteDeletion)
                }
            }
        }

        // The record of an alias remnant: its own name was not held. Open it now that
        // the artifact's handle is closed, and require the very same file, now with
        // one name, and (when bytes were verified) the very same bytes.
        let primary = match primary {
            HeldPrimary::None => None,
            HeldPrimary::Held(file) => Some(file),
            HeldPrimary::Deferred { identity, expected } => {
                let file =
                    HeldFile::open(&plan.record).map_err(|_| StoreError::IncompleteDeletion)?;
                let same_bytes = expected.as_ref().is_none_or(|evidence| {
                    file.read_bounded(MAX_SYNC_STATE_BYTES as u64)
                        .is_some_and(|bytes| FileEvidence::of(&bytes) == *evidence)
                });

                if file.identity() != identity || file.link_count() != 1 || !same_bytes {
                    return Err(StoreError::IncompleteDeletion);
                }

                Some(file)
            }
        };

        // R2: nothing new appeared while the artifacts went.
        if removed_any
            && (self.recheck_layout(plan, &[]).is_err() || !pin.still_names(&self.directory))
        {
            return Err(StoreError::IncompleteDeletion);
        }

        if let Some(file) = primary {
            self.hook(Point::RemovePrimary)
                .map_err(|_| StoreError::IncompleteDeletion)?;

            if !file.unchanged() {
                return Err(changed_fact(removed_any));
            }

            match file.mark_for_removal() {
                RemovalMark::Marked => {}
                RemovalMark::NotMarked | RemovalMark::Unknown => {
                    return Err(StoreError::IncompleteDeletion)
                }
            }
        }

        self.hook(Point::AfterClose)
            .map_err(|_| StoreError::IncompleteDeletion)?;

        // Verify while the directory is still pinned, treating "cannot tell" as
        // incomplete.
        let outcome = match fs::symlink_metadata(&plan.record) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match self.scan_artifacts(&plan.key) {
                    Ok(remaining) if remaining.is_empty() => Ok(DeleteOutcome::Removed),
                    _ => Err(StoreError::IncompleteDeletion),
                }
            }
            _ => Err(StoreError::IncompleteDeletion),
        };

        drop(pin);

        outcome
    }

    // ---- internals ---------------------------------------------------------

    fn record_path(&self, key: &str) -> PathBuf {
        self.directory.join(format!("{key}.{RECORD_EXTENSION}"))
    }

    fn inspect_directory(&self) -> Result<DirState, Fault> {
        self.confirm_ancestors()?;

        match fs::symlink_metadata(&self.directory) {
            Ok(metadata) if is_plain_directory(&metadata) => Ok(DirState::Present),
            Ok(_) => Err(Fault::Unexpected),
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.confirm_parent_chain(),
            Err(error) => Err(Fault::Io(error.kind())),
        }
    }

    /// Every existing ancestor of the `sync-state` directory (the supplied
    /// root and everything above it) must be a plain directory: a junction,
    /// symlink or other reparse point, a regular file or an unreadable
    /// component is a fault. Missing components are normal first use. Runs
    /// before every other inspection so no operation trusts or creates through
    /// a redirected path.
    fn confirm_ancestors(&self) -> Result<(), Fault> {
        for ancestor in self.directory.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }

            match fs::symlink_metadata(ancestor) {
                Ok(metadata) if is_plain_directory(&metadata) => {}
                Ok(_) => return Err(Fault::Unexpected),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(Fault::Io(error.kind())),
            }
        }

        Ok(())
    }

    /// Windows reports "not found" both for a genuinely missing path and when a
    /// component is a regular file. So absence of the `sync-state` directory
    /// only counts once the nearest *existing* ancestor is shown to be a plain
    /// directory; a file, reparse point, unreadable or nonexistent-to-the-top
    /// path is a fault. Missing intermediate directories (first use) are fine.
    fn confirm_parent_chain(&self) -> Result<DirState, Fault> {
        let mut ancestor = self.directory.parent();

        while let Some(path) = ancestor {
            match fs::symlink_metadata(path) {
                Ok(metadata) if is_plain_directory(&metadata) => return Ok(DirState::Absent),
                Ok(_) => return Err(Fault::Unexpected),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    ancestor = path.parent();
                }
                Err(error) => return Err(Fault::Io(error.kind())),
            }
        }

        // Not even a drive/root exists: absence cannot be established.
        Err(Fault::Io(io::ErrorKind::NotFound))
    }

    fn ensure_directory(&self) -> Result<(), StoreError> {
        // Establish the surrounding filesystem first: never create through a
        // junction, a file ancestor or an unreadable path.
        self.inspect_directory()
            .map_err(|fault| fault.into_store_error(IoStage::Directory))?;

        // `create_dir_all` returns Ok without creating anything when the path
        // is already a directory, including a junction; the inspection below
        // is what rejects that.
        fs::create_dir_all(&self.directory).map_err(|error| StoreError::Io {
            stage: IoStage::Directory,
            kind: error.kind(),
        })?;

        match self
            .inspect_directory()
            .map_err(|fault| fault.into_store_error(IoStage::Directory))?
        {
            DirState::Present => Ok(()),
            DirState::Absent => Err(StoreError::Io {
                stage: IoStage::Directory,
                kind: io::ErrorKind::NotFound,
            }),
        }
    }

    /// Bounded, reparse-safe read. `Absent` only when the *first* metadata call
    /// says not found; a record that vanishes afterwards is an I/O fault.
    fn read_primary(&self, path: &Path) -> Result<Primary, Fault> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Primary::Absent),
            Err(error) => return Err(Fault::Io(error.kind())),
        };

        if !is_plain_file(&metadata) {
            return Err(Fault::Unexpected);
        }
        if let Some(early) = size_verdict(metadata.len()) {
            return Ok(early);
        }

        let file = open_no_follow(path).map_err(|error| Fault::Io(error.kind()))?;

        // Judge the opened handle, not the path that may have been swapped.
        let opened = file.metadata().map_err(|error| Fault::Io(error.kind()))?;
        if !is_plain_file(&opened) {
            return Err(Fault::Unexpected);
        }
        if let Some(early) = size_verdict(opened.len()) {
            return Ok(early);
        }

        let mut bytes = Vec::new();
        file.take(MAX_SYNC_STATE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| Fault::Io(error.kind()))?;

        match size_verdict(bytes.len() as u64) {
            Some(verdict) => Ok(verdict),
            None => Ok(Primary::Bytes(bytes)),
        }
    }

    fn scan_artifacts(&self, key: &str) -> Result<Vec<PathBuf>, Fault> {
        let entries = fs::read_dir(&self.directory).map_err(|error| Fault::Io(error.kind()))?;

        let mut found = Vec::new();
        for (index, entry) in entries.enumerate() {
            if index >= MAX_SCANNED_ENTRIES {
                return Err(Fault::EntryLimit);
            }
            let entry = entry.map_err(|error| Fault::Io(error.kind()))?;

            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| is_artifact_name(name, key))
            {
                found.push(entry.path());
            }
        }

        Ok(found)
    }

    /// Create, fill, flush and close a staging file; remove it on any failure.
    fn write_temp(&self, key: &str, bytes: &[u8]) -> Result<PathBuf, StoreError> {
        let (path, mut file) = self.create_temp(key)?;

        let written = (|| {
            file.write_all(bytes).map_err(|error| StoreError::Io {
                stage: IoStage::Write,
                kind: error.kind(),
            })?;
            file.flush().map_err(|error| StoreError::Io {
                stage: IoStage::Write,
                kind: error.kind(),
            })?;
            self.hook(Point::TempSync)
                .and_then(|()| file.sync_all())
                .map_err(|error| StoreError::Io {
                    stage: IoStage::Sync,
                    kind: error.kind(),
                })
        })();

        // Close before publication; Windows will not link or rename an open
        // file that was opened without delete sharing by someone else, and we
        // want our own handle gone regardless.
        drop(file);

        match written {
            Ok(()) => Ok(path),
            Err(error) => {
                let _ = fs::remove_file(&path);
                Err(error)
            }
        }
    }

    fn create_temp(&self, key: &str) -> Result<(PathBuf, File), StoreError> {
        for _ in 0..TEMP_ALLOCATION_ATTEMPTS {
            let name = format!("{key}.{}.{ARTIFACT_EXTENSION}", Uuid::new_v4().simple());
            let path = self.directory.join(name);

            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(StoreError::Io {
                        stage: IoStage::Open,
                        kind: error.kind(),
                    })
                }
            }
        }

        Err(StoreError::Io {
            stage: IoStage::Open,
            kind: io::ErrorKind::AlreadyExists,
        })
    }

    /// Read the record back; it must be byte-identical to what was written and
    /// decode to the intended state.
    fn verify(
        &self,
        record: &Path,
        written: &[u8],
        intended: &SyncState,
    ) -> Result<(), StoreError> {
        if self.hook(Point::Verify).is_err() {
            return Err(StoreError::VerificationFailed);
        }

        match self.read_primary(record) {
            Ok(Primary::Bytes(read_back))
                if read_back == written
                    && SyncState::decode(&read_back).is_ok_and(|decoded| decoded == *intended) =>
            {
                Ok(())
            }
            _ => Err(StoreError::VerificationFailed),
        }
    }

    /// Test seam for the session's tests (the fault hooks are private): run
    /// `run` inside [`delete_if_evidence_matches`](Self::delete_if_evidence_matches)
    /// after its preconditions and before its evidence comparison, which is the
    /// window the comparison exists to close.
    #[cfg(test)]
    pub(crate) fn run_before_evidence_recheck_for_test(&self, run: impl Fn() + Send + 'static) {
        self.faults
            .lock()
            .unwrap()
            .push((Point::BeforeEvidenceRecheck, Action::Run(Box::new(run))));
    }

    /// Test seam: run `run` inside [`create`](Self::create) immediately before the
    /// no-clobber publication, the window in which a late file can appear.
    #[cfg(test)]
    pub(crate) fn run_before_publish_for_test(&self, run: impl Fn() + Send + 'static) {
        self.faults
            .lock()
            .unwrap()
            .push((Point::Publish, Action::Run(Box::new(run))));
    }

    /// Test seam: run `run` inside the deletion immediately before the primary
    /// record is removed, after every comparison has already passed.
    #[cfg(test)]
    pub(crate) fn run_before_primary_removal_for_test(&self, run: impl Fn() + Send + 'static) {
        self.faults
            .lock()
            .unwrap()
            .push((Point::RemovePrimary, Action::Run(Box::new(run))));
    }

    /// Test seam: run `run` inside [`delete_if_evidence_matches`](Self::delete_if_evidence_matches)
    /// after the evidence comparison by path and before the directory is pinned and
    /// the files are held: the window in which a file can still be swapped.
    #[cfg(test)]
    pub(crate) fn run_before_hold_for_test(&self, run: impl Fn() + Send + 'static) {
        self.faults
            .lock()
            .unwrap()
            .push((Point::BeforeHold, Action::Run(Box::new(run))));
    }

    /// Test seam: run `run` inside the deletion after every file was removed and its
    /// handle closed, before the absence is verified.
    #[cfg(test)]
    pub(crate) fn run_after_close_for_test(&self, run: impl Fn() + Send + 'static) {
        self.faults
            .lock()
            .unwrap()
            .push((Point::AfterClose, Action::Run(Box::new(run))));
    }

    #[cfg(not(test))]
    #[inline(always)]
    fn hook(&self, _point: Point) -> io::Result<()> {
        Ok(())
    }

    #[cfg(test)]
    fn hook(&self, point: Point) -> io::Result<()> {
        let faults = self.faults.lock().unwrap();
        for (at, action) in faults.iter() {
            if *at == point {
                match action {
                    Action::Fail(kind) => return Err(io::Error::from(*kind)),
                    Action::Run(run) => run(),
                }
            }
        }
        Ok(())
    }
}

// ---- free helpers -----------------------------------------------------------

/// The existing Windows path-identity rule (`recent_vaults::path_strings_equal`,
/// which is private there): ASCII case-insensitive. Non-ASCII letters are
/// compared exactly, exactly as `eq_ignore_ascii_case` does.
pub(crate) fn path_identity_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

/// Record key: hex SHA-256 of the ASCII-lowercased locator bytes. The core
/// fingerprint type is used purely as its existing SHA-256 helper (no new
/// dependency); the value is not an envelope fingerprint.
fn record_key(locator: &Locator) -> String {
    EnvelopeFingerprint::of_bytes(locator.as_str().to_ascii_lowercase().as_bytes()).to_hex()
}

/// A held file whose facts changed after it was judged: a refusal while nothing has
/// been removed, otherwise part of a partial removal.
fn changed_fact(removed_any: bool) -> StoreError {
    if removed_any {
        StoreError::IncompleteDeletion
    } else {
        StoreError::RemovalRefused(RemovalRefusal::ExtraNames)
    }
}

/// What the number of names of a planned file allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkVerdict {
    /// One name: accepted.
    Single,
    /// Two names: accepted only for the `create` remnant (an artifact that is also
    /// the record), which the caller must show.
    Pair,
    /// Zero, or three or more: refused.
    Refuse,
}

fn link_verdict(links: u32) -> LinkVerdict {
    match links {
        1 => LinkVerdict::Single,
        2 => LinkVerdict::Pair,
        _ => LinkVerdict::Refuse,
    }
}

/// One planned artifact, held.
struct HeldArtifact {
    /// ASCII-lowercased file name (the store's own artifact-name rule).
    name: String,
    file: HeldFile,
    /// The one artifact that is a second name of the record (the `create` remnant).
    alias: bool,
}

/// The record's side of a deletion.
enum HeldPrimary {
    /// No record is planned.
    None,
    Held(HeldFile),
    /// The record is the second name of a held artifact. It is **not** held: a
    /// second hold would be refused by the first one's sharing mode. It is opened
    /// after the artifact's handle closes and must then be the same file with one
    /// name and (when bytes were compared) the same bytes.
    Deferred {
        identity: FileIdentity,
        expected: Option<FileEvidence>,
    },
}

/// Everything a deletion holds, acquired before the first removal. Dropping it
/// closes every handle and removes nothing.
struct HeldFiles {
    pin: DirectoryPin,
    artifacts: Vec<HeldArtifact>,
    primary: HeldPrimary,
}

fn is_artifact_name(name: &str, key: &str) -> bool {
    let lowered = name.to_ascii_lowercase();

    lowered
        .strip_prefix(key)
        .and_then(|rest| rest.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(ARTIFACT_EXTENSION))
        .and_then(|rest| rest.strip_suffix('.'))
        .is_some_and(|token| {
            token.len() == ARTIFACT_TOKEN_LEN
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn size_verdict(len: u64) -> Option<Primary> {
    if len == 0 {
        Some(Primary::Empty)
    } else if len > MAX_SYNC_STATE_BYTES as u64 {
        Some(Primary::TooLarge)
    } else {
        None
    }
}

/// Decode with the accepted core mapping, then require the record to be for the
/// requested location.
fn classify(requested: &Locator, bytes: &[u8]) -> StateLoad {
    match SyncStateLoad::from_bytes(bytes) {
        SyncStateLoad::Loaded(state) => {
            if path_identity_eq(state.local_locator().as_str(), requested.as_str()) {
                StateLoad::Loaded(state)
            } else {
                StateLoad::Corrupt(CorruptReason::LocatorMismatch)
            }
        }
        SyncStateLoad::UnsupportedVersion => StateLoad::UnsupportedVersion,
        // `from_bytes` yields nothing else; anything unexpected fails closed.
        _ => StateLoad::Corrupt(CorruptReason::Undecodable),
    }
}

fn check_replacement(expected: &SyncState, proposed: &SyncState) -> Result<(), StoreError> {
    if !path_identity_eq(
        expected.local_locator().as_str(),
        proposed.local_locator().as_str(),
    ) {
        return Err(StoreError::LocatorMismatch);
    }

    if expected.binding_id() != proposed.binding_id()
        || expected.vault_tag() != proposed.vault_tag()
        || expected.local_locator() != proposed.local_locator()
        || expected.target_locator() != proposed.target_locator()
    {
        return Err(StoreError::BindingIdentityChanged);
    }

    // Defense in depth only: the core transitions never produce these.
    match (expected.base(), proposed.base()) {
        (SyncBase::Based(_), SyncBase::Unbased) => Err(StoreError::TrustedHistoryRegression),
        (SyncBase::Based(old), SyncBase::Based(new))
            if new.high_water().revision() < old.high_water().revision() =>
        {
            Err(StoreError::TrustedHistoryRegression)
        }
        _ => Ok(()),
    }
}

fn map_publish_error(error: &io::Error) -> StoreError {
    // ERROR_INVALID_FUNCTION (1) / ERROR_NOT_SUPPORTED (50): no hard links.
    if error.kind() == io::ErrorKind::AlreadyExists {
        StoreError::AlreadyExists
    } else if error.kind() == io::ErrorKind::Unsupported
        || matches!(error.raw_os_error(), Some(1) | Some(50))
    {
        StoreError::NoClobberUnsupported
    } else {
        StoreError::Io {
            stage: IoStage::Replace,
            kind: error.kind(),
        }
    }
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.file_type().is_symlink()
    }

    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn is_plain_file(metadata: &fs::Metadata) -> bool {
    !is_reparse_point(metadata) && metadata.is_file()
}

fn is_plain_directory(metadata: &fs::Metadata) -> bool {
    !is_reparse_point(metadata) && metadata.is_dir()
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    options.open(path)
}

// ---- v3 layout assessment (read-only) ----------------------------------------
//
// Stage 1U-4 B3c-3b-1. A strictly read-only observation. Nothing in this region
// writes, moves, links or deletes anything, and it never calls the legacy artifact
// scan or any mutator. Outside this region the only production caller of
// `observe_v3_layout` is the legacy compatibility gate that follows it
// (B3c-3b-2a), and `inspect_v3_layout` is called only by the dormant authenticated
// assessment. It shares no code with the legacy (v1) artifact recognition, which
// is unchanged and still knows only its own staging names.

/// Diagnostic bound: the most directory entries one v3 layout observation will
/// visit. A scanning safety limit that keeps one observation finite. It is **not**
/// a retention policy and says nothing about how many files a product may keep.
const V3_SCAN_ENTRY_LIMIT: usize = 10_000;
/// Diagnostic bound: the most recognized sibling files one observation will read.
/// Like [`V3_SCAN_ENTRY_LIMIT`] it is a scanning limit, not a retention policy.
const V3_SIBLING_READ_LIMIT: usize = 16;
/// Length of the hexadecimal token in a sibling name.
const V3_SIBLING_TOKEN_LEN: usize = 32;
/// Length of a record key (hexadecimal SHA-256).
const V3_KEY_LEN: usize = 64;
/// The longest file name a component may have, in UTF-16 code units.
const V3_MAX_NAME_UNITS: usize = 255;

/// What kind of sibling a recognized name is. A name is an indicator only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SiblingKind {
    /// `<key>.<32 hex>.tmp`
    Staging,
    /// `<key>.<32 hex>.retired`
    Retired,
    /// `<key>.<32 hex>.v3stage`: a name reserved for a future authenticated
    /// publisher (decision U9). Recognized by name alone, before any body byte is
    /// read, so an empty, cut-short, malformed, unreadable or non-plain file is
    /// still recognized. Nothing in this build creates one, a matching name proves
    /// no ownership and gives no recovery authority, and it is not a legacy
    /// staging name.
    ReservedStaging,
}

/// How one directory entry name relates to one record key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V3NameClass {
    /// Exactly `<key>.json`, compared ASCII case-insensitively.
    Primary,
    /// Exactly `<key>.<32 hex>.tmp`, `<key>.<32 hex>.retired` or
    /// `<key>.<32 hex>.v3stage`.
    Sibling(SiblingKind),
    /// Starts with the key (ASCII case-insensitively, judged on the lossy form so
    /// that a non-Unicode name still counts) but is none of the shapes above.
    Unrecognized,
    /// Not related to this key. Ignored and uncounted.
    Other,
}

/// Pure name grammar of the v3 reader. `entry_lossy` is the entry name converted
/// lossily; `exact_unicode` says whether the original name was valid Unicode, and
/// only an exactly valid name is ever recognized as a primary or a sibling.
///
/// A match is an **indication only**. It gives no ownership, no authentication,
/// no recovery authority, no deletion authority and no write permission, and a
/// path derived from it must never be handed to any operation that changes
/// anything.
fn recognize_v3_sibling_name(entry_lossy: &str, exact_unicode: bool, key: &str) -> V3NameClass {
    let key = key.as_bytes();

    // Only a well-formed key can match anything.
    if key.len() != V3_KEY_LEN
        || !key
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return V3NameClass::Other;
    }

    let name = entry_lossy.as_bytes();

    if name.len() < key.len() || !name[..key.len()].eq_ignore_ascii_case(key) {
        return V3NameClass::Other;
    }

    // A name longer than a path component can be is never a recognized shape,
    // but it is still a suspicious key-prefixed entry.
    if !exact_unicode || entry_lossy.encode_utf16().count() > V3_MAX_NAME_UNITS {
        return V3NameClass::Unrecognized;
    }

    let rest = &name[key.len()..];

    if rest.eq_ignore_ascii_case(b".json") {
        return V3NameClass::Primary;
    }

    match v3_sibling_shape(rest) {
        Some(kind) => V3NameClass::Sibling(kind),
        None => V3NameClass::Unrecognized,
    }
}

/// `.<32 hex>.tmp`, `.<32 hex>.retired` or `.<32 hex>.v3stage`, either case,
/// nothing else.
fn v3_sibling_shape(rest: &[u8]) -> Option<SiblingKind> {
    let rest = rest.strip_prefix(b".")?;

    if rest.len() <= V3_SIBLING_TOKEN_LEN {
        return None;
    }

    let (token, tail) = rest.split_at(V3_SIBLING_TOKEN_LEN);

    if !token.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }

    if tail.eq_ignore_ascii_case(b".tmp") {
        Some(SiblingKind::Staging)
    } else if tail.eq_ignore_ascii_case(b".retired") {
        Some(SiblingKind::Retired)
    } else if tail.eq_ignore_ascii_case(b".v3stage") {
        Some(SiblingKind::ReservedStaging)
    } else {
        None
    }
}

/// The primary record of a v3 layout observation, as the filesystem showed it.
/// The bytes are neither decoded nor authenticated here.
#[derive(PartialEq, Eq)]
pub enum LayoutPrimary {
    /// No primary record was present.
    Absent,
    /// Zero bytes.
    Empty,
    /// Larger than the supported maximum; not read past the limit.
    TooLarge,
    /// The exact bounded bytes.
    Bytes(Vec<u8>),
    /// A directory, junction, symlink or other object where a file belongs.
    Unexpected,
}

// The bytes, and their length, are not printed.
impl fmt::Debug for LayoutPrimary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::Empty => f.write_str("Empty"),
            Self::TooLarge => f.write_str("TooLarge"),
            Self::Bytes(_) => f.write_str("Bytes(<redacted>)"),
            Self::Unexpected => f.write_str("Unexpected"),
        }
    }
}

/// What reading one recognized sibling gave.
pub enum SiblingContent {
    /// The exact bounded bytes.
    Bytes(Vec<u8>),
    Empty,
    TooLarge,
    /// The sibling could not be read.
    Unreadable(io::ErrorKind),
    /// A directory, junction, symlink or other object where a file belongs.
    Unexpected,
    /// The sibling was listed and was gone when it was read.
    Vanished,
}

// The bytes, and their length, are not printed.
impl fmt::Debug for SiblingContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(_) => f.write_str("Bytes(<redacted>)"),
            Self::Empty => f.write_str("Empty"),
            Self::TooLarge => f.write_str("TooLarge"),
            Self::Unreadable(kind) => write!(f, "Unreadable({kind:?})"),
            Self::Unexpected => f.write_str("Unexpected"),
            Self::Vanished => f.write_str("Vanished"),
        }
    }
}

/// One recognized sibling. Neither its name nor its token nor its path is kept.
pub struct LayoutSibling {
    kind: SiblingKind,
    content: SiblingContent,
}

impl LayoutSibling {
    pub fn kind(&self) -> SiblingKind {
        self.kind
    }

    pub fn content(&self) -> &SiblingContent {
        &self.content
    }
}

impl fmt::Debug for LayoutSibling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LayoutSibling(<redacted>)")
    }
}

/// Why a v3 layout observation is incomplete or untrustworthy. Never absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutUncertainty {
    /// An I/O or permission failure.
    Io(io::ErrorKind),
    /// A directory, junction, symlink or other object where a plain directory was
    /// required (the state directory or one of its ancestors).
    UnexpectedObject,
    /// More directory entries than the scan visits ([`V3_SCAN_ENTRY_LIMIT`]).
    EntryLimit,
    /// More recognized siblings than one observation reads
    /// ([`V3_SIBLING_READ_LIMIT`]).
    SiblingLimit,
    /// Two or more entries fold to the same recognized name, so which one a path
    /// reaches is ambiguous.
    AliasAmbiguity,
    /// The two observations of the directory, or of the primary, disagreed.
    ChangedDuringScan,
}

impl From<Fault> for LayoutUncertainty {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Io(kind) => Self::Io(kind),
            Fault::Unexpected => Self::UnexpectedObject,
            Fault::EntryLimit => Self::EntryLimit,
        }
    }
}

/// A complete observation of the state directory for one record key: the primary,
/// the recognized siblings in a stable order, and a count of suspicious
/// key-prefixed entries that match no recognized shape.
///
/// What was observed at one point in time; see [`SyncStateStore::inspect_v3_layout`].
pub struct V3Layout {
    primary: LayoutPrimary,
    siblings: Vec<LayoutSibling>,
    unrecognized: usize,
}

impl V3Layout {
    pub fn primary(&self) -> &LayoutPrimary {
        &self.primary
    }

    pub fn siblings(&self) -> &[LayoutSibling] {
        &self.siblings
    }

    /// Key-prefixed entries that are none of the recognized shapes.
    pub fn unrecognized(&self) -> usize {
        self.unrecognized
    }
}

impl fmt::Debug for V3Layout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("V3Layout(<redacted>)")
    }
}

/// Result of [`SyncStateStore::inspect_v3_layout`].
#[must_use]
pub enum V3LayoutInspection {
    Observed(V3Layout),
    Uncertain(LayoutUncertainty),
}

impl fmt::Debug for V3LayoutInspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observed(_) => f.write_str("Observed(<redacted>)"),
            Self::Uncertain(reason) => write!(f, "Uncertain({reason:?})"),
        }
    }
}

/// How a listed entry was recognized, ordered for a stable comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NameTag {
    Primary,
    Sibling(SiblingKind),
    Unrecognized,
}

/// Every related directory entry of one enumeration, sorted.
type ObservedNames = Vec<(NameTag, std::ffi::OsString)>;

impl SyncStateStore {
    /// Observe, without changing anything, what the state directory holds for
    /// `local_locator`: the primary record, every `<key>.<32 hex>.tmp` and
    /// `<key>.<32 hex>.retired` sibling, and a count of other key-prefixed entries.
    ///
    /// In order: the directory and every existing ancestor must be plain
    /// directories (an absent directory is an observed absence; a redirected or
    /// otherwise unexpected one is uncertain, never absence); one bounded enumeration classifies the names;
    /// the primary and each recognized sibling are read through the existing
    /// bounded, no-follow, read-only reader; then the directory is enumerated and
    /// the primary read a second time, and any difference makes the result
    /// uncertain.
    ///
    /// A failed or over-limit enumeration, an ambiguous alias, too many siblings or
    /// disagreeing observations is [`V3LayoutInspection::Uncertain`], and no
    /// uncertainty is ever turned into confirmed absence. A sibling that is not a
    /// plain file is reported as such and is never followed.
    ///
    /// # What this does not do
    ///
    /// The second pass only narrows a race. It cannot prove that no change
    /// happened between or after the passes: another process can add, delete,
    /// replace or re-create (and restore) any name at any moment, and the second
    /// pass cannot tell a change that was undone. No file identity is recorded, and
    /// the ancestor inspection is check-then-use. The result is what was observed,
    /// never what is. A recognized name is not ownership, authentication, recovery
    /// authority, deletion authority or write permission, and this function is not
    /// a lock.
    pub fn inspect_v3_layout(&self, local_locator: &Locator) -> V3LayoutInspection {
        let key = record_key(local_locator);

        match self.inspect_directory() {
            Ok(DirState::Absent) => {
                return V3LayoutInspection::Observed(V3Layout {
                    primary: LayoutPrimary::Absent,
                    siblings: Vec::new(),
                    unrecognized: 0,
                })
            }
            Ok(DirState::Present) => {}
            Err(fault) => return V3LayoutInspection::Uncertain(fault.into()),
        }

        match self.observe_v3_layout(&key) {
            Ok(layout) => V3LayoutInspection::Observed(layout),
            Err(uncertainty) => V3LayoutInspection::Uncertain(uncertainty),
        }
    }

    fn observe_v3_layout(&self, key: &str) -> Result<V3Layout, LayoutUncertainty> {
        let first = self.enumerate_v3_names(key)?;

        reject_v3_aliases(&first)?;

        let siblings: Vec<_> = first
            .iter()
            .filter(|(tag, _)| matches!(tag, NameTag::Sibling(_)))
            .collect();

        if siblings.len() > V3_SIBLING_READ_LIMIT {
            return Err(LayoutUncertainty::SiblingLimit);
        }

        let primary = self.read_v3_primary(key, &first)?;

        let mut read = Vec::with_capacity(siblings.len());
        for (tag, name) in siblings {
            let NameTag::Sibling(kind) = *tag else {
                continue;
            };

            read.push(LayoutSibling {
                kind,
                content: self.read_v3_sibling(name),
            });
        }

        // The consistency re-check: the same names and the same primary, or the
        // observation is not trusted. It narrows the race; it does not close it.
        let second = self.enumerate_v3_names(key)?;
        let primary_again = self.read_v3_primary(key, &second)?;

        if second != first || primary_again != primary {
            return Err(LayoutUncertainty::ChangedDuringScan);
        }

        let unrecognized = first
            .iter()
            .filter(|(tag, _)| *tag == NameTag::Unrecognized)
            .count();

        Ok(V3Layout {
            primary,
            siblings: read,
            unrecognized,
        })
    }

    /// One bounded pass over the directory, keeping only the entries related to
    /// `key`. Names are classified from the lossy form so that a non-Unicode name
    /// with the key prefix is counted rather than ignored.
    fn enumerate_v3_names(&self, key: &str) -> Result<ObservedNames, LayoutUncertainty> {
        let entries =
            fs::read_dir(&self.directory).map_err(|error| LayoutUncertainty::Io(error.kind()))?;

        let mut found = ObservedNames::new();

        for (index, entry) in entries.enumerate() {
            if index >= V3_SCAN_ENTRY_LIMIT {
                return Err(LayoutUncertainty::EntryLimit);
            }

            let entry = entry.map_err(|error| LayoutUncertainty::Io(error.kind()))?;
            let name = entry.file_name();
            let exact = name.to_str().is_some();

            let tag = match recognize_v3_sibling_name(&name.to_string_lossy(), exact, key) {
                V3NameClass::Primary => NameTag::Primary,
                V3NameClass::Sibling(kind) => NameTag::Sibling(kind),
                V3NameClass::Unrecognized => NameTag::Unrecognized,
                V3NameClass::Other => continue,
            };

            found.push((tag, name));
        }

        found.sort();

        Ok(found)
    }

    /// Read the primary through the bounded no-follow reader. The listing and the
    /// read must agree about whether a primary exists.
    fn read_v3_primary(
        &self,
        key: &str,
        names: &[(NameTag, std::ffi::OsString)],
    ) -> Result<LayoutPrimary, LayoutUncertainty> {
        let listed = names.iter().find(|(tag, _)| *tag == NameTag::Primary);

        let path = match listed {
            Some((_, name)) => self.directory.join(name),
            None => self.record_path(key),
        };

        let primary = match self.read_primary(&path) {
            Ok(Primary::Absent) => LayoutPrimary::Absent,
            Ok(Primary::Empty) => LayoutPrimary::Empty,
            Ok(Primary::TooLarge) => LayoutPrimary::TooLarge,
            Ok(Primary::Bytes(bytes)) => LayoutPrimary::Bytes(bytes),
            Err(Fault::Unexpected) => LayoutPrimary::Unexpected,
            Err(fault) => return Err(fault.into()),
        };

        // Listed but gone, or unlisted but there: two views of one directory
        // that disagree.
        if listed.is_some() == matches!(primary, LayoutPrimary::Absent) {
            return Err(LayoutUncertainty::ChangedDuringScan);
        }

        Ok(primary)
    }

    fn read_v3_sibling(&self, name: &std::ffi::OsString) -> SiblingContent {
        match self.read_primary(&self.directory.join(name)) {
            Ok(Primary::Absent) => SiblingContent::Vanished,
            Ok(Primary::Empty) => SiblingContent::Empty,
            Ok(Primary::TooLarge) => SiblingContent::TooLarge,
            Ok(Primary::Bytes(bytes)) => SiblingContent::Bytes(bytes),
            Err(Fault::Unexpected) => SiblingContent::Unexpected,
            Err(Fault::Io(io::ErrorKind::NotFound)) => SiblingContent::Vanished,
            Err(Fault::Io(kind)) => SiblingContent::Unreadable(kind),
            Err(Fault::EntryLimit) => SiblingContent::Unreadable(io::ErrorKind::Other),
        }
    }
}

/// Two recognized entries that fold to the same name make every path to "the"
/// primary or sibling ambiguous.
fn reject_v3_aliases(names: &[(NameTag, std::ffi::OsString)]) -> Result<(), LayoutUncertainty> {
    let mut folded: Vec<String> = names
        .iter()
        .filter(|(tag, _)| *tag != NameTag::Unrecognized)
        .map(|(_, name)| name.to_string_lossy().to_ascii_lowercase())
        .collect();

    folded.sort();

    if folded.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LayoutUncertainty::AliasAmbiguity);
    }

    Ok(())
}

// ---- end v3 layout assessment ------------------------------------------------

// ---- legacy compatibility gate (read-only) -----------------------------------
//
// Stage 1U-4 B3c-3b-2a. Refuse-only. This region only observes (through
// `observe_v3_layout`) and decides; it creates, removes, moves, replaces and adopts
// nothing, grants nothing, and adds no deletion target. It can only take
// permissions away from the legacy operations that ask it.
//
// It is check-then-use. It is not a lock and not compare-and-swap, and it cannot
// see a change made after it returned, a change that was undone between its two
// passes, or evidence that was moved or deleted so it no longer carries this
// record's key. Older binaries do not ask it anything.

/// Why the legacy store will not act on a record key. A fixed category: no name,
/// token, path, length or byte of any file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyGateRefusal {
    /// A sibling that belongs to a newer state exists: a recognized `.retired` or
    /// `.v3stage` file (judged by name, whatever it holds or whether it can be
    /// read), or a `.tmp` holding a complete, well-formed record of a version this
    /// build does not support.
    NewerState,
    /// Entries named after this record's key match no recognized shape (decision
    /// U2). Entries of other record keys never count.
    UnrecognizedEntries,
    /// The observation is incomplete or inconsistent. Never absence.
    Uncertain(LayoutUncertainty),
}

/// The pure decision over one complete observation. The primary is not judged here.
///
/// In order: a `.retired` or `.v3stage` sibling is newer-state evidence whatever
/// its content; then any unrecognized key-prefixed entry; then each `.tmp` sibling.
/// For a `.tmp` only a complete, well-formed record of an unsupported version counts
/// as newer state, because the codec parses its whole input before it reads a
/// version: an empty or cut-short record of a newer version is byte-for-byte
/// indistinguishable from a legacy remnant and passes. That is defence in depth
/// only, never protection of partial staging, and the reason the `.v3stage` name is
/// reserved. An unreadable `.tmp` or one that vanished during the scan is
/// uncertainty. Everything else passes to the legacy rules unchanged.
fn legacy_verdict(layout: &V3Layout) -> Result<(), LegacyGateRefusal> {
    if layout.siblings().iter().any(|sibling| {
        matches!(
            sibling.kind(),
            SiblingKind::Retired | SiblingKind::ReservedStaging
        )
    }) {
        return Err(LegacyGateRefusal::NewerState);
    }

    if layout.unrecognized() > 0 {
        return Err(LegacyGateRefusal::UnrecognizedEntries);
    }

    let staging = || {
        layout
            .siblings()
            .iter()
            .filter(|sibling| sibling.kind() == SiblingKind::Staging)
    };

    if staging().any(|sibling| match sibling.content() {
        SiblingContent::Bytes(bytes) => matches!(
            SyncStateLoad::from_bytes(bytes),
            SyncStateLoad::UnsupportedVersion
        ),
        _ => false,
    }) {
        return Err(LegacyGateRefusal::NewerState);
    }

    for sibling in staging() {
        match sibling.content() {
            SiblingContent::Unreadable(kind) => {
                return Err(LegacyGateRefusal::Uncertain(LayoutUncertainty::Io(*kind)))
            }
            SiblingContent::Vanished => {
                return Err(LegacyGateRefusal::Uncertain(
                    LayoutUncertainty::ChangedDuringScan,
                ))
            }
            SiblingContent::Bytes(_)
            | SiblingContent::Empty
            | SiblingContent::TooLarge
            | SiblingContent::Unexpected => {}
        }
    }

    Ok(())
}

impl SyncStateStore {
    /// Observe the directory for `key` and decide whether the legacy store may go
    /// on. Runs only after the directory itself was established to be a plain
    /// directory. Returns the observation so a caller can look at the primary it
    /// holds; the observation grants nothing.
    fn legacy_gate(&self, key: &str) -> Result<V3Layout, LegacyGateRefusal> {
        let layout = self
            .observe_v3_layout(key)
            .map_err(LegacyGateRefusal::Uncertain)?;

        legacy_verdict(&layout)?;

        Ok(layout)
    }
}

impl From<LegacyGateRefusal> for UnreadableReason {
    fn from(refusal: LegacyGateRefusal) -> Self {
        match refusal {
            LegacyGateRefusal::NewerState => Self::UnresolvedNewerState,
            LegacyGateRefusal::UnrecognizedEntries => Self::UnrecognizedEntries,
            LegacyGateRefusal::Uncertain(LayoutUncertainty::Io(kind)) => Self::Io(kind),
            LegacyGateRefusal::Uncertain(LayoutUncertainty::UnexpectedObject) => {
                Self::UnexpectedObject
            }
            LegacyGateRefusal::Uncertain(LayoutUncertainty::EntryLimit) => Self::EntryLimit,
            LegacyGateRefusal::Uncertain(
                LayoutUncertainty::SiblingLimit
                | LayoutUncertainty::AliasAmbiguity
                | LayoutUncertainty::ChangedDuringScan,
            ) => Self::LayoutUncertain,
        }
    }
}

impl From<LegacyGateRefusal> for StoreError {
    fn from(refusal: LegacyGateRefusal) -> Self {
        match refusal {
            LegacyGateRefusal::NewerState => Self::UnresolvedNewerState,
            LegacyGateRefusal::UnrecognizedEntries => Self::UnrecognizedEntries,
            LegacyGateRefusal::Uncertain(LayoutUncertainty::Io(kind)) => Self::Io {
                stage: IoStage::Scan,
                kind,
            },
            LegacyGateRefusal::Uncertain(LayoutUncertainty::UnexpectedObject) => {
                Self::UnexpectedObject
            }
            // As `Fault::EntryLimit` is mapped today.
            LegacyGateRefusal::Uncertain(LayoutUncertainty::EntryLimit) => Self::Io {
                stage: IoStage::Scan,
                kind: io::ErrorKind::Other,
            },
            LegacyGateRefusal::Uncertain(
                LayoutUncertainty::SiblingLimit
                | LayoutUncertainty::AliasAmbiguity
                | LayoutUncertainty::ChangedDuringScan,
            ) => Self::LayoutUncertain,
        }
    }
}

impl From<LegacyGateRefusal> for EvidenceRefusal {
    fn from(refusal: LegacyGateRefusal) -> Self {
        match refusal {
            LegacyGateRefusal::NewerState => Self::UnresolvedNewerState,
            LegacyGateRefusal::UnrecognizedEntries => Self::UnrecognizedEntries,
            LegacyGateRefusal::Uncertain(LayoutUncertainty::Io(_)) => Self::Unreadable,
            LegacyGateRefusal::Uncertain(LayoutUncertainty::UnexpectedObject) => {
                Self::UnexpectedObject
            }
            LegacyGateRefusal::Uncertain(LayoutUncertainty::EntryLimit) => Self::EntryLimit,
            LegacyGateRefusal::Uncertain(LayoutUncertainty::ChangedDuringScan) => Self::Unstable,
            LegacyGateRefusal::Uncertain(
                LayoutUncertainty::SiblingLimit | LayoutUncertainty::AliasAmbiguity,
            ) => Self::Unreadable,
        }
    }
}

// ---- end legacy compatibility gate -------------------------------------------

/// Windows storage tests. Synthetic states only; no vault fixture is read or
/// modified. Every test owns a uniquely named scratch directory under the
/// git-ignored `<repo>/.qa-local/sync-state-b1-tests/` (never `%TEMP%`) and
/// removes only that directory.
///
/// Not proven here: physical power-loss behavior, Windows filesystem crash
/// consistency, and behavior on a filesystem without hard links. Crash states
/// are produced by constructing the files an interruption would leave, and
/// unreproducible I/O failures by the test-only fault seam (`Point`).
#[cfg(test)]
mod tests {
    use std::{fs, io, path::PathBuf};

    use localvault_core::{
        sync::{PushBaseline, PushIntent, RemoteHighWater},
        sync_state::{BindingId, PendingPush, SyncCheckpoint, VaultBindingTag, BINDING_SALT_LEN},
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::vault::session::UnlockedVaultSession;

    const LOCAL: &str = r"\\?\C:\Synthetic\Vaults\LOCAL-MARKER.lvault";
    const OTHER_LOCAL: &str = r"\\?\C:\Synthetic\Vaults\OTHER-MARKER.lvault";
    const TARGET: &str = r"\\?\D:\Synthetic\Remote\TARGET-MARKER.lvault";

    const VAULT_ID: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    const OTHER_VAULT_ID: Uuid = Uuid::from_u128(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210);
    const BINDING: Uuid = Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555);
    const INTENT: Uuid = Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee);

    const STALE_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    // ---- scratch and builders ---------------------------------------------

    struct Scratch {
        dir: tempfile::TempDir,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(".qa-local")
                .join("sync-state-b1-tests");
            fs::create_dir_all(&base).unwrap();

            // `.qa-local` is ignored by its own `.gitignore`; only supply it if
            // the directory was just created without one.
            let ignore = base.parent().unwrap().join(".gitignore");
            if !ignore.exists() {
                fs::write(&ignore, "*\n").unwrap();
            }

            let dir = tempfile::Builder::new()
                .prefix(&format!("{name}-"))
                .tempdir_in(&base)
                .unwrap();

            Self { dir }
        }

        fn root(&self) -> PathBuf {
            self.dir.path().to_path_buf()
        }

        fn state_dir(&self) -> PathBuf {
            self.root().join(SYNC_STATE_DIRECTORY)
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(&self.root()).unwrap()
        }

        fn record(&self, local: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.json", record_key(&loc(local))))
        }

        fn artifact(&self, local: &str, token: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.{token}.tmp", record_key(&loc(local))))
        }

        fn put(&self, path: &Path, bytes: &[u8]) {
            fs::create_dir_all(self.state_dir()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        found.sort();
        found
    }

    fn fp(tag: u8) -> EnvelopeFingerprint {
        EnvelopeFingerprint::of_bytes(&[tag])
    }

    fn loc(value: &str) -> Locator {
        Locator::new(value).unwrap()
    }

    fn tag_for(vault_id: Uuid) -> VaultBindingTag {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
        VaultBindingTag::derive(salt, vault_id).unwrap()
    }

    fn build(
        local: &str,
        vault_id: Uuid,
        base: SyncBase,
        pending: Option<PendingPush>,
    ) -> SyncState {
        SyncState::new(
            BindingId::new(BINDING).unwrap(),
            tag_for(vault_id),
            loc(local),
            loc(TARGET),
            base,
            pending,
        )
        .unwrap()
    }

    /// Unbased, with a pending initial publication from an absent remote.
    fn unbased(local: &str) -> SyncState {
        let intent = PushIntent::new(PushBaseline::Absent, fp(2)).unwrap();
        build(
            local,
            VAULT_ID,
            SyncBase::Unbased,
            Some(PendingPush::new(INTENT, intent, 1).unwrap()),
        )
    }

    fn checkpoint(high_water: u64) -> SyncBase {
        SyncBase::Based(SyncCheckpoint::new(fp(1), 1, RemoteHighWater::new(high_water)).unwrap())
    }

    fn based(local: &str, high_water: u64) -> SyncState {
        build(local, VAULT_ID, checkpoint(high_water), None)
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

    fn pending_push(revision: u64) -> PendingPush {
        let intent = PushIntent::new(PushBaseline::Present(fp(1)), fp(3)).unwrap();
        PendingPush::new(INTENT, intent, revision).unwrap()
    }

    fn tampered(state: &SyncState, edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&state.encode().unwrap()).unwrap();
        edit(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    fn loaded(load: StateLoad) -> SyncState {
        match load {
            StateLoad::Loaded(state) => *state,
            other => panic!("expected a loaded state, got {other:?}"),
        }
    }

    fn fail_at(store: &SyncStateStore, point: Point, kind: io::ErrorKind) {
        store
            .faults
            .lock()
            .unwrap()
            .push((point, Action::Fail(kind)));
    }

    fn run_at(store: &SyncStateStore, point: Point, run: impl Fn() + Send + 'static) {
        store
            .faults
            .lock()
            .unwrap()
            .push((point, Action::Run(Box::new(run))));
    }

    /// Open without delete/write sharing: later opens for data or delete fail.
    #[cfg(windows)]
    fn hold_exclusively(path: &Path) -> fs::File {
        use std::os::windows::fs::OpenOptionsExt;

        OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .unwrap()
    }

    /// Open for reading and allow others to read but not to write or delete, so a
    /// reader still gets the bytes while a removal fails with a sharing violation.
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

    #[cfg(windows)]
    fn make_junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(status.status.success(), "could not create a test junction");
    }

    // ---- 1. create / load round trip ---------------------------------------

    #[test]
    fn valid_state_create_load_round_trip() {
        let scratch = Scratch::new("roundtrip");
        let store = scratch.store();
        let state = unbased(LOCAL);

        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);

        store.create(&state).unwrap();

        assert_eq!(loaded(store.load(&loc(LOCAL))), state);
        assert_eq!(
            fs::read(scratch.record(LOCAL)).unwrap(),
            state.encode().unwrap()
        );
        // Only the record: the staging name was removed.
        assert_eq!(names(&scratch.state_dir()).len(), 1);

        assert!(matches!(
            store.load(&loc(LOCAL)).into_sync_state_load(),
            SyncStateLoad::Loaded(_)
        ));
    }

    // ---- 2. replacement ------------------------------------------------------

    #[test]
    fn replacement_is_atomic_and_verified_by_read_back() {
        let scratch = Scratch::new("replace");
        let store = scratch.store();

        let first = based(LOCAL, 9);
        store.create(&first).unwrap();

        let raised = rebuilt(&first, checkpoint(12), None);
        store.replace(&first, &raised).unwrap();
        assert_eq!(loaded(store.load(&loc(LOCAL))), raised);
        assert_eq!(
            fs::read(scratch.record(LOCAL)).unwrap(),
            raised.encode().unwrap()
        );
        assert_eq!(names(&scratch.state_dir()).len(), 1);

        let pending = rebuilt(&raised, checkpoint(12), Some(pending_push(13)));
        store.replace(&raised, &pending).unwrap();
        assert_eq!(loaded(store.load(&loc(LOCAL))), pending);

        // Unbased -> Based is a legitimate (finalize) replacement.
        let other = Scratch::new("replace-unbased");
        let other_store = other.store();
        let initial = unbased(LOCAL);
        other_store.create(&initial).unwrap();
        let finalized = rebuilt(&initial, checkpoint(1), None);
        other_store.replace(&initial, &finalized).unwrap();
        assert_eq!(loaded(other_store.load(&loc(LOCAL))), finalized);
    }

    // ---- 3. create refuses existing -----------------------------------------

    #[test]
    fn create_refuses_an_existing_state_without_modifying_it() {
        let scratch = Scratch::new("create-exists");
        let store = scratch.store();
        let original = unbased(LOCAL);
        store.create(&original).unwrap();
        let before = fs::read(scratch.record(LOCAL)).unwrap();

        assert_eq!(store.create(&original), Err(StoreError::AlreadyExists));
        assert_eq!(
            store.create(&based(LOCAL, 3)),
            Err(StoreError::AlreadyExists)
        );

        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), before);
        assert_eq!(names(&scratch.state_dir()).len(), 1);
    }

    // ---- 4. replacement refuses a changed expectation -----------------------

    #[test]
    fn replacement_refuses_a_changed_expected_state() {
        let scratch = Scratch::new("replace-changed");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        let before = fs::read(scratch.record(LOCAL)).unwrap();

        let stale_expectation = based(LOCAL, 8);
        let proposed = rebuilt(&stale_expectation, checkpoint(10), None);

        assert_eq!(
            store.replace(&stale_expectation, &proposed),
            Err(StoreError::Changed)
        );
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), before);
        assert_eq!(names(&scratch.state_dir()).len(), 1);
    }

    #[test]
    fn replacement_detects_a_record_swapped_between_the_two_reads() {
        let scratch = Scratch::new("replace-swapped");
        let store = scratch.store();
        let expected = based(LOCAL, 9);
        store.create(&expected).unwrap();

        // Another valid state is written after the compare, before the rename.
        let intruder = rebuilt(&expected, checkpoint(50), None);
        let record = scratch.record(LOCAL);
        let intruder_bytes = intruder.encode().unwrap();
        let swap_bytes = intruder_bytes.clone();
        run_at(&store, Point::BeforeReplace, move || {
            fs::write(&record, &swap_bytes).unwrap();
        });

        let proposed = rebuilt(&expected, checkpoint(10), None);
        assert_eq!(
            store.replace(&expected, &proposed),
            Err(StoreError::Changed)
        );

        // The intruder's record is untouched and our staging file is gone.
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), intruder_bytes);
        assert_eq!(names(&scratch.state_dir()).len(), 1);
    }

    // ---- 5. replacement refuses a missing state -----------------------------

    #[test]
    fn replacement_refuses_a_missing_state_and_creates_nothing() {
        let scratch = Scratch::new("replace-missing");
        let store = scratch.store();
        let expected = based(LOCAL, 9);
        let proposed = rebuilt(&expected, checkpoint(10), None);

        assert_eq!(
            store.replace(&expected, &proposed),
            Err(StoreError::Missing)
        );
        assert!(!scratch.state_dir().exists());

        fs::create_dir_all(scratch.state_dir()).unwrap();
        assert_eq!(
            store.replace(&expected, &proposed),
            Err(StoreError::Missing)
        );
        assert!(names(&scratch.state_dir()).is_empty());
    }

    #[test]
    fn replacement_guards_binding_identity_and_trusted_history() {
        let scratch = Scratch::new("replace-guards");
        let store = scratch.store();
        let current = based(LOCAL, 9);
        store.create(&current).unwrap();
        let before = fs::read(scratch.record(LOCAL)).unwrap();

        // Different record.
        assert_eq!(
            store.replace(&current, &based(OTHER_LOCAL, 9)),
            Err(StoreError::LocatorMismatch)
        );

        // Different vault tag, same locators.
        let retagged = build(LOCAL, OTHER_VAULT_ID, checkpoint(9), None);
        assert_eq!(
            store.replace(&current, &retagged),
            Err(StoreError::BindingIdentityChanged)
        );

        // Same locator up to ASCII case is the same record but not the same
        // binding identity.
        let recased = based(&LOCAL.to_ascii_uppercase(), 9);
        assert_eq!(
            store.replace(&current, &recased),
            Err(StoreError::BindingIdentityChanged)
        );

        // The trusted high-water mark never goes down, and a checkpoint is
        // never dropped.
        let lowered = rebuilt(&current, checkpoint(8), None);
        assert_eq!(
            store.replace(&current, &lowered),
            Err(StoreError::TrustedHistoryRegression)
        );
        let dropped = rebuilt(
            &current,
            SyncBase::Unbased,
            Some(
                PendingPush::new(
                    INTENT,
                    PushIntent::new(PushBaseline::Absent, fp(2)).unwrap(),
                    1,
                )
                .unwrap(),
            ),
        );
        assert_eq!(
            store.replace(&current, &dropped),
            Err(StoreError::TrustedHistoryRegression)
        );

        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), before);
    }

    // ---- 6-10. load classification ------------------------------------------

    #[test]
    fn corrupt_json_is_corrupt_and_left_in_place() {
        let scratch = Scratch::new("corrupt-json");
        let store = scratch.store();
        scratch.put(&scratch.record(LOCAL), b"{ definitely not json");

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::Undecodable)
        );
        assert_eq!(
            store.load(&loc(LOCAL)).into_sync_state_load(),
            SyncStateLoad::Corrupt
        );
        assert_eq!(
            fs::read(scratch.record(LOCAL)).unwrap(),
            b"{ definitely not json"
        );

        // A corrupt record is never replaced by a new binding or a replacement.
        assert_eq!(
            store.create(&unbased(LOCAL)),
            Err(StoreError::AlreadyExists)
        );
        let expected = based(LOCAL, 9);
        assert_eq!(
            store.replace(&expected, &rebuilt(&expected, checkpoint(10), None)),
            Err(StoreError::CurrentCorrupt)
        );
        assert_eq!(
            fs::read(scratch.record(LOCAL)).unwrap(),
            b"{ definitely not json"
        );
    }

    #[test]
    fn bad_checksum_is_corrupt() {
        let scratch = Scratch::new("bad-checksum");
        let store = scratch.store();
        let state = based(LOCAL, 9);

        let flipped_digest = tampered(&state, |value| {
            let mut digest = value["body_sha256"].as_str().unwrap().to_owned();
            let first = if digest.starts_with('0') { "1" } else { "0" };
            digest.replace_range(0..1, first);
            value["body_sha256"] = serde_json::Value::String(digest);
        });
        scratch.put(&scratch.record(LOCAL), &flipped_digest);
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::Undecodable)
        );

        // A changed body under the old checksum is equally rejected.
        let edited_body = tampered(&state, |value| {
            let body = value["body"]
                .as_str()
                .unwrap()
                .replace("\"high_water\":9", "\"high_water\":8");
            value["body"] = serde_json::Value::String(body);
        });
        fs::write(scratch.record(LOCAL), &edited_body).unwrap();
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::Undecodable)
        );
    }

    #[test]
    fn unsupported_future_version_stays_blocked() {
        let scratch = Scratch::new("future-version");
        let store = scratch.store();
        let state = based(LOCAL, 9);

        let future = tampered(&state, |value| {
            value["version"] = serde_json::json!(2);
            value["added_in_v2"] = serde_json::json!(true);
        });
        scratch.put(&scratch.record(LOCAL), &future);

        assert_eq!(store.load(&loc(LOCAL)), StateLoad::UnsupportedVersion);
        assert_eq!(
            store.load(&loc(LOCAL)).into_sync_state_load(),
            SyncStateLoad::UnsupportedVersion
        );

        // Not reset, not replaced, not overwritten by a fresh binding.
        assert_eq!(
            store.create(&unbased(LOCAL)),
            Err(StoreError::AlreadyExists)
        );
        assert_eq!(
            store.replace(&state, &rebuilt(&state, checkpoint(10), None)),
            Err(StoreError::CurrentUnsupportedVersion)
        );
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), future);
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::UnsupportedVersion);
    }

    #[test]
    fn oversized_file_is_rejected_without_reading_it() {
        let scratch = Scratch::new("oversized");
        let store = scratch.store();
        fs::create_dir_all(scratch.state_dir()).unwrap();

        // A sparse 512 MiB file: reading it would be slow and large; the
        // metadata length alone must decide.
        let file = File::create(scratch.record(LOCAL)).unwrap();
        file.set_len(512 * 1024 * 1024).unwrap();
        drop(file);

        let started = std::time::Instant::now();
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::TooLarge)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));

        // One byte over the limit.
        let file = OpenOptions::new()
            .write(true)
            .open(scratch.record(LOCAL))
            .unwrap();
        file.set_len(MAX_SYNC_STATE_BYTES as u64 + 1).unwrap();
        drop(file);
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::TooLarge)
        );
        assert_eq!(
            store.create(&unbased(LOCAL)),
            Err(StoreError::AlreadyExists)
        );

        // Exactly the limit is read (bounded) and then fails to decode.
        fs::write(scratch.record(LOCAL), vec![b'x'; MAX_SYNC_STATE_BYTES]).unwrap();
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::Undecodable)
        );

        assert!(matches!(size_verdict(0), Some(Primary::Empty)));
        assert!(size_verdict(MAX_SYNC_STATE_BYTES as u64).is_none());
        assert!(matches!(
            size_verdict(MAX_SYNC_STATE_BYTES as u64 + 1),
            Some(Primary::TooLarge)
        ));
    }

    #[test]
    fn truncated_state_is_never_not_configured() {
        let scratch = Scratch::new("truncated");
        let store = scratch.store();
        let full = based(LOCAL, 9).encode().unwrap();

        scratch.put(&scratch.record(LOCAL), b"");
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::Empty)
        );

        for cut in (1..full.len()).step_by(7) {
            fs::write(scratch.record(LOCAL), &full[..cut]).unwrap();
            assert_eq!(
                store.load(&loc(LOCAL)),
                StateLoad::Corrupt(CorruptReason::Undecodable),
                "cut at {cut}"
            );
        }

        // Loading never repairs or removes it.
        assert!(scratch.record(LOCAL).exists());
    }

    // ---- 11. I/O errors are not absence --------------------------------------

    #[cfg(windows)]
    #[test]
    fn io_and_permission_errors_are_never_not_configured() {
        let scratch = Scratch::new("io-errors");
        let store = scratch.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();

        {
            // The record exists but cannot be opened for reading.
            let _guard = hold_exclusively(&scratch.record(LOCAL));

            let outcome = store.load(&loc(LOCAL));
            assert!(
                matches!(outcome, StateLoad::Unreadable(UnreadableReason::Io(_))),
                "got {outcome:?}"
            );
            assert_eq!(
                store.load(&loc(LOCAL)).into_sync_state_load(),
                SyncStateLoad::Unreadable
            );
            // B3c-3b-2a: the compatibility gate cannot read the held record, so
            // both mutators are refused at its scan (formerly `CurrentUnreadable`
            // and `AlreadyExists`). Still a refusal; nothing is replaced or created.
            assert!(
                matches!(
                    store.replace(&state, &rebuilt(&state, checkpoint(10), None)),
                    Err(StoreError::Io {
                        stage: IoStage::Scan,
                        ..
                    })
                ),
                "replace over a held record"
            );
            assert!(
                matches!(
                    store.create(&state),
                    Err(StoreError::Io {
                        stage: IoStage::Scan,
                        ..
                    })
                ),
                "create over a held record"
            );
        }

        // Released: the record was never harmed.
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);

        // The sync-state "directory" being a regular file is not absence.
        let blocked = Scratch::new("io-errors-file-dir");
        fs::write(blocked.state_dir(), b"not a directory").unwrap();
        assert_eq!(
            blocked.store().load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert_eq!(
            blocked.store().create(&state),
            Err(StoreError::UnexpectedObject)
        );

        // A genuinely missing root (first run) is the one case of absence.
        let pristine = Scratch::new("io-errors-pristine");
        let missing_root = pristine.root().join("not-created-yet");
        let pristine_store = SyncStateStore::new(&missing_root).unwrap();
        assert_eq!(pristine_store.load(&loc(LOCAL)), StateLoad::NotConfigured);
        assert!(!missing_root.exists());
    }

    // ---- 12-14. record identity ----------------------------------------------

    #[test]
    fn a_record_copied_under_the_wrong_key_is_rejected() {
        let scratch = Scratch::new("wrong-key");
        let store = scratch.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();

        fs::copy(scratch.record(LOCAL), scratch.record(OTHER_LOCAL)).unwrap();

        assert_eq!(
            store.load(&loc(OTHER_LOCAL)),
            StateLoad::Corrupt(CorruptReason::LocatorMismatch)
        );
        assert_eq!(
            store.load(&loc(OTHER_LOCAL)).into_sync_state_load(),
            SyncStateLoad::Corrupt
        );

        let wrong = based(OTHER_LOCAL, 9);
        assert_eq!(
            store.replace(&wrong, &rebuilt(&wrong, checkpoint(10), None)),
            Err(StoreError::CurrentLocatorMismatch)
        );

        // The genuine record is still valid.
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);
    }

    #[test]
    fn different_local_paths_have_different_keys_and_agree_with_path_identity() {
        let key = record_key(&loc(LOCAL));
        assert_eq!(key.len(), 64);
        assert!(key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_ne!(key, record_key(&loc(OTHER_LOCAL)));

        // Key equality is exactly the existing Windows path-identity rule
        // (ASCII case-insensitive; non-ASCII compared exactly).
        let spellings = [
            LOCAL,
            r"\\?\c:\synthetic\vaults\local-marker.LVAULT",
            OTHER_LOCAL,
            r"\\?\C:\Synthetic\Vaults\Ä.lvault",
            r"\\?\C:\Synthetic\Vaults\ä.lvault",
            r"C:\Synthetic\Vaults\LOCAL-MARKER.lvault",
        ];
        for left in spellings {
            for right in spellings {
                assert_eq!(
                    record_key(&loc(left)) == record_key(&loc(right)),
                    path_identity_eq(left, right),
                    "{left} vs {right}"
                );
            }
        }
        assert!(!path_identity_eq("Ä", "ä"));
        assert!(path_identity_eq("A", "a"));

        let scratch = Scratch::new("two-records");
        let store = scratch.store();
        let first = based(LOCAL, 9);
        let second = based(OTHER_LOCAL, 4);
        store.create(&first).unwrap();
        store.create(&second).unwrap();
        assert_eq!(loaded(store.load(&loc(LOCAL))), first);
        assert_eq!(loaded(store.load(&loc(OTHER_LOCAL))), second);
        assert_eq!(names(&scratch.state_dir()).len(), 2);
    }

    #[test]
    fn a_case_variant_request_finds_the_record_but_core_still_compares_exactly() {
        let scratch = Scratch::new("case-variant");
        let store = scratch.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();

        let variant = loc(&LOCAL.to_ascii_uppercase());
        let found = loaded(store.load(&variant));
        assert_eq!(found, state);

        // The store keys on path identity; the core's binding check remains an
        // exact comparison and refuses the differently spelled locator.
        assert_eq!(
            found
                .verify_binding(VAULT_ID, &variant, &loc(TARGET))
                .unwrap_err(),
            localvault_core::sync_state::BindingMismatch::LocalLocator
        );
    }

    #[test]
    fn a_reused_path_loads_the_old_record_so_the_caller_must_verify_the_vault_tag() {
        let scratch = Scratch::new("reused-path");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();

        // Later a different encrypted vault sits at the same path. The store
        // cannot tell: it returns the old record unchanged...
        let inherited = loaded(store.load(&loc(LOCAL)));

        // ...and only the authenticated-vault-id check rejects it.
        assert!(inherited
            .verify_binding(VAULT_ID, &loc(LOCAL), &loc(TARGET))
            .is_ok());
        assert_eq!(
            inherited
                .verify_binding(OTHER_VAULT_ID, &loc(LOCAL), &loc(TARGET))
                .unwrap_err(),
            localvault_core::sync_state::BindingMismatch::VaultIdentity
        );
    }

    // ---- 15-16. recovery artifacts and interruption ---------------------------

    #[test]
    fn stale_recovery_artifacts_fail_closed_and_are_never_auto_deleted() {
        let scratch = Scratch::new("stale-artifacts");
        let store = scratch.store();
        let artifact = scratch.artifact(LOCAL, STALE_TOKEN);
        scratch.put(&artifact, b"{\"half written");

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
        );
        assert_eq!(
            store.load(&loc(LOCAL)).into_sync_state_load(),
            SyncStateLoad::Unreadable
        );
        assert_eq!(
            store.create(&unbased(LOCAL)),
            Err(StoreError::UnresolvedArtifacts)
        );
        assert!(artifact.exists());
        assert!(!scratch.record(LOCAL).exists());

        // Another record's artifacts are not this record's artifacts: they neither
        // block nor get touched. (B3c-3b-2a, decision U2: files that only look
        // related to THIS key used to be ignored here too; they now block, see
        // `legacy_gate_unrecognized_tests`, and are still never touched.)
        fs::remove_file(&artifact).unwrap();
        let key = record_key(&loc(LOCAL));
        let suspicious = [
            scratch.state_dir().join(format!("{key}.notes.txt")),
            scratch.state_dir().join(format!("{key}.json.bak")),
            scratch
                .state_dir()
                .join(format!("{key}.{STALE_TOKEN}.tmp.old")),
            scratch.state_dir().join(format!("{key}.short.tmp")),
        ];
        for path in &suspicious {
            fs::write(path, b"unrelated").unwrap();
            assert_eq!(
                store.load(&loc(LOCAL)),
                StateLoad::Unreadable(UnreadableReason::UnrecognizedEntries)
            );
            assert_eq!(
                store.create(&unbased(LOCAL)),
                Err(StoreError::UnrecognizedEntries)
            );
            assert_eq!(fs::read(path).unwrap(), b"unrelated");
            assert!(!scratch.record(LOCAL).exists());
            fs::remove_file(path).unwrap();
        }

        let other = scratch.artifact(OTHER_LOCAL, STALE_TOKEN);
        fs::write(&other, b"unrelated").unwrap();
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);
        store.create(&unbased(LOCAL)).unwrap();
        assert_eq!(fs::read(&other).unwrap(), b"unrelated");
    }

    #[test]
    fn artifact_name_pattern_is_exact() {
        let key = record_key(&loc(LOCAL));
        let other = record_key(&loc(OTHER_LOCAL));

        assert!(is_artifact_name(&format!("{key}.{STALE_TOKEN}.tmp"), &key));
        // NTFS names are case-insensitive.
        assert!(is_artifact_name(
            &format!("{key}.{STALE_TOKEN}.tmp").to_ascii_uppercase(),
            &key
        ));
        assert!(!is_artifact_name(
            &format!("{other}.{STALE_TOKEN}.tmp"),
            &key
        ));
        assert!(!is_artifact_name(&format!("{key}.json"), &key));
        assert!(!is_artifact_name(
            &format!("{key}.{STALE_TOKEN}.tmp.x"),
            &key
        ));
        assert!(!is_artifact_name(
            &format!("{key}.{STALE_TOKEN}0.tmp"),
            &key
        ));
        assert!(!is_artifact_name(
            &format!("{key}.{}.tmp", "g".repeat(32)),
            &key
        ));
        assert!(!is_artifact_name(&format!("{key}{STALE_TOKEN}.tmp"), &key));
    }

    #[test]
    fn an_interrupted_write_never_authorizes_an_initial_binding() {
        // Crash after the staging file was written, before publication.
        let scratch = Scratch::new("interrupted-before-publish");
        let store = scratch.store();
        let state = unbased(LOCAL);
        scratch.put(
            &scratch.artifact(LOCAL, STALE_TOKEN),
            &state.encode().unwrap(),
        );
        assert_ne!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);
        assert_eq!(store.create(&state), Err(StoreError::UnresolvedArtifacts));

        // A non-atomic writer died halfway through the record itself.
        let torn = Scratch::new("interrupted-torn-record");
        let torn_store = torn.store();
        let bytes = state.encode().unwrap();
        torn.put(&torn.record(LOCAL), &bytes[..bytes.len() / 2]);
        assert_eq!(
            torn_store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::Undecodable)
        );
        assert_eq!(torn_store.create(&state), Err(StoreError::AlreadyExists));

        // Crash after publication, before the staging name was removed: the
        // record is complete and authoritative, the leftover is only debris.
        let linked = Scratch::new("interrupted-after-publish");
        let linked_store = linked.store();
        linked.put(&linked.record(LOCAL), &bytes);
        linked.put(&linked.artifact(LOCAL, STALE_TOKEN), &bytes);
        assert_eq!(loaded(linked_store.load(&loc(LOCAL))), state);
        assert_eq!(linked_store.create(&state), Err(StoreError::AlreadyExists));

        // Crash during a replacement: old record intact, partial staging file.
        let replacing = Scratch::new("interrupted-during-replace");
        let replacing_store = replacing.store();
        let old = based(LOCAL, 9);
        replacing_store.create(&old).unwrap();
        let next = rebuilt(&old, checkpoint(12), None);
        let next_bytes = next.encode().unwrap();
        replacing.put(
            &replacing.artifact(LOCAL, STALE_TOKEN),
            &next_bytes[..next_bytes.len() / 3],
        );
        assert_eq!(loaded(replacing_store.load(&loc(LOCAL))), old);
        replacing_store.replace(&old, &next).unwrap();
        assert_eq!(loaded(replacing_store.load(&loc(LOCAL))), next);
        assert!(replacing.artifact(LOCAL, STALE_TOKEN).exists());
    }

    #[test]
    fn failed_publication_leaves_no_record_and_no_staging_file() {
        let scratch = Scratch::new("fault-publish");
        let store = scratch.store();
        let state = unbased(LOCAL);

        fail_at(&store, Point::Publish, io::ErrorKind::PermissionDenied);
        assert!(matches!(
            store.create(&state),
            Err(StoreError::Io {
                stage: IoStage::Replace,
                kind: io::ErrorKind::PermissionDenied
            })
        ));
        assert!(names(&scratch.state_dir()).is_empty());
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);

        // A filesystem without hard links is reported, never worked around.
        let unsupported = Scratch::new("fault-no-hard-links");
        let unsupported_store = unsupported.store();
        fail_at(
            &unsupported_store,
            Point::Publish,
            io::ErrorKind::Unsupported,
        );
        assert_eq!(
            unsupported_store.create(&state),
            Err(StoreError::NoClobberUnsupported)
        );
        assert!(names(&unsupported.state_dir()).is_empty());

        // A failed flush of the staging file.
        let unflushed = Scratch::new("fault-sync");
        let unflushed_store = unflushed.store();
        fail_at(&unflushed_store, Point::TempSync, io::ErrorKind::Other);
        assert!(matches!(
            unflushed_store.create(&state),
            Err(StoreError::Io {
                stage: IoStage::Sync,
                ..
            })
        ));
        assert!(names(&unflushed.state_dir()).is_empty());
    }

    #[test]
    fn publication_never_clobbers_a_record_that_appears_after_the_existence_check() {
        let scratch = Scratch::new("no-clobber-race");
        let store = scratch.store();

        // A competing writer publishes a different valid record in the window
        // between the existence check and our publication.
        let intruder = based(LOCAL, 40);
        let intruder_bytes = intruder.encode().unwrap();
        let record = scratch.record(LOCAL);
        let planted = intruder_bytes.clone();
        run_at(&store, Point::Publish, move || {
            fs::write(&record, &planted).unwrap();
        });

        assert_eq!(
            store.create(&unbased(LOCAL)),
            Err(StoreError::AlreadyExists)
        );

        // The competing record survived untouched and our staging file is gone.
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), intruder_bytes);
        assert_eq!(names(&scratch.state_dir()).len(), 1);
        assert_eq!(loaded(store.load(&loc(LOCAL))), intruder);
    }

    #[test]
    fn a_failed_read_back_is_not_reported_as_success() {
        let scratch = Scratch::new("fault-verify-create");
        let store = scratch.store();
        let state = unbased(LOCAL);

        fail_at(&store, Point::Verify, io::ErrorKind::Other);
        assert_eq!(store.create(&state), Err(StoreError::VerificationFailed));
        // The caller is told to reload; the record that was published is not
        // silently removed.
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);

        let replacing = Scratch::new("fault-verify-replace");
        let replacing_store = replacing.store();
        let old = based(LOCAL, 9);
        replacing_store.create(&old).unwrap();
        let next = rebuilt(&old, checkpoint(10), None);
        fail_at(&replacing_store, Point::Verify, io::ErrorKind::Other);
        assert_eq!(
            replacing_store.replace(&old, &next),
            Err(StoreError::VerificationFailed)
        );
        assert_eq!(loaded(replacing_store.load(&loc(LOCAL))), next);
    }

    #[test]
    fn a_failed_replacement_leaves_the_trusted_record_untouched() {
        let scratch = Scratch::new("fault-replace");
        let store = scratch.store();
        let old = based(LOCAL, 9);
        store.create(&old).unwrap();
        let before = fs::read(scratch.record(LOCAL)).unwrap();
        let next = rebuilt(&old, checkpoint(10), None);

        fail_at(&store, Point::Replace, io::ErrorKind::PermissionDenied);
        assert!(matches!(
            store.replace(&old, &next),
            Err(StoreError::Io {
                stage: IoStage::Replace,
                ..
            })
        ));
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), before);
        assert_eq!(names(&scratch.state_dir()).len(), 1);

        // A failed flush of the replacement's staging file.
        let flush = Scratch::new("fault-replace-sync");
        let flush_store = flush.store();
        flush_store.create(&old).unwrap();
        fail_at(&flush_store, Point::TempSync, io::ErrorKind::Other);
        assert!(matches!(
            flush_store.replace(&old, &next),
            Err(StoreError::Io {
                stage: IoStage::Sync,
                ..
            })
        ));
        assert_eq!(loaded(flush_store.load(&loc(LOCAL))), old);
        assert_eq!(names(&flush.state_dir()).len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn a_real_rename_failure_leaves_the_trusted_record_untouched() {
        let scratch = Scratch::new("real-replace-failure");
        let store = scratch.store();
        let old = based(LOCAL, 9);
        store.create(&old).unwrap();
        let next = rebuilt(&old, checkpoint(10), None);

        // Hold the record so Windows refuses to replace it. The pre-replace
        // read fails first, which is equally fail-closed.
        let guard = hold_exclusively(&scratch.record(LOCAL));
        let result = store.replace(&old, &next);
        assert!(result.is_err(), "replacement over a held record succeeded");
        drop(guard);

        assert_eq!(loaded(store.load(&loc(LOCAL))), old);
        assert_eq!(names(&scratch.state_dir()).len(), 1);
    }

    // ---- 17-18. deletion --------------------------------------------------------

    #[test]
    fn verified_deletion_removes_only_this_records_files() {
        let scratch = Scratch::new("delete");
        let store = scratch.store();

        let doomed = based(LOCAL, 9);
        let survivor = based(OTHER_LOCAL, 4);
        store.create(&doomed).unwrap();
        store.create(&survivor).unwrap();
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        // B3c-3b-2a (U2): a neighbour that merely shares THIS record's key prefix
        // now blocks the deletion (and one with the survivor's prefix would block
        // the survivor), so it carries the key of a third, unrelated location. It
        // must stay untouched and must not block anything.
        let third_key = record_key(&loc(r"\\?\C:\Synthetic\Vaults\THIRD-MARKER.lvault"));
        let unrelated = scratch.state_dir().join(format!("{third_key}.notes.txt"));
        fs::write(&unrelated, b"unrelated").unwrap();

        assert_eq!(store.delete(&loc(LOCAL)), Ok(DeleteOutcome::Removed));

        assert!(!scratch.record(LOCAL).exists());
        assert!(!scratch.artifact(LOCAL, STALE_TOKEN).exists());
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);
        assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated");
        assert_eq!(loaded(store.load(&loc(OTHER_LOCAL))), survivor);

        assert_eq!(store.delete(&loc(LOCAL)), Ok(DeleteOutcome::AlreadyAbsent));

        // A missing directory is verified absence too.
        let empty = Scratch::new("delete-nothing");
        assert_eq!(
            empty.store().delete(&loc(LOCAL)),
            Ok(DeleteOutcome::AlreadyAbsent)
        );
        assert!(!empty.state_dir().exists());
    }

    #[test]
    fn loading_never_deletes_and_explicit_delete_clears_unusable_records() {
        let scratch = Scratch::new("delete-unusable");
        let store = scratch.store();
        scratch.put(&scratch.record(LOCAL), b"garbage");

        for _ in 0..3 {
            assert!(matches!(store.load(&loc(LOCAL)), StateLoad::Corrupt(_)));
        }
        assert!(scratch.record(LOCAL).exists());

        // Only the explicit operation removes it, after which a binding can be
        // created deliberately.
        assert_eq!(store.delete(&loc(LOCAL)), Ok(DeleteOutcome::Removed));
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);
        store.create(&unbased(LOCAL)).unwrap();
    }

    #[test]
    fn interrupted_or_failed_deletion_is_reported_and_never_absence() {
        // Artifact removal fails: the record is untouched (artifacts go first).
        let scratch = Scratch::new("delete-fail-artifact");
        let store = scratch.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        fail_at(
            &store,
            Point::RemoveArtifact,
            io::ErrorKind::PermissionDenied,
        );
        assert_eq!(
            store.delete(&loc(LOCAL)),
            Err(StoreError::IncompleteDeletion)
        );
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);

        // Record removal fails after the artifacts were removed: the binding is
        // intact, which is not "unbound".
        let second = Scratch::new("delete-fail-record");
        let second_store = second.store();
        second_store.create(&state).unwrap();
        second.put(&second.artifact(LOCAL, STALE_TOKEN), b"debris");
        fail_at(
            &second_store,
            Point::RemovePrimary,
            io::ErrorKind::PermissionDenied,
        );
        assert_eq!(
            second_store.delete(&loc(LOCAL)),
            Err(StoreError::IncompleteDeletion)
        );
        assert!(!second.artifact(LOCAL, STALE_TOKEN).exists());
        assert_eq!(loaded(second_store.load(&loc(LOCAL))), state);

        // A deletion interrupted with the record gone and an artifact left:
        // that is unresolved, never NotConfigured, and a second delete finishes.
        let third = Scratch::new("delete-interrupted");
        let third_store = third.store();
        third.put(&third.artifact(LOCAL, STALE_TOKEN), b"debris");
        assert_eq!(
            third_store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
        );
        assert_eq!(third_store.delete(&loc(LOCAL)), Ok(DeleteOutcome::Removed));
        assert_eq!(third_store.load(&loc(LOCAL)), StateLoad::NotConfigured);
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_busy_files_refuse_the_deletion_before_anything_is_removed() {
        // REAL NTFS. Formerly `real_windows_deletion_failure_is_reported_as_incomplete`.
        let scratch = Scratch::new("delete-real-failure");
        let store = scratch.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();

        // B3c-3b-2a: a file held exclusively cannot even be read by the
        // compatibility gate, so the deletion is refused before anything is
        // removed (formerly it reached the removal and failed there).
        {
            let _guard = hold_exclusively(&scratch.record(LOCAL));
            assert!(matches!(
                store.delete(&loc(LOCAL)),
                Err(StoreError::Io {
                    stage: IoStage::Scan,
                    ..
                })
            ));
            assert!(scratch.record(LOCAL).exists());
        }
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);

        // B3c-3b-2d-1: a file that can be read but is open without delete sharing can
        // no longer be held for removal. The deletion is refused (`Busy`) before the
        // first removal; formerly this reached the removal and was `IncompleteDeletion`.
        {
            let _guard = hold_against_removal(&scratch.record(LOCAL));
            assert_eq!(
                store.delete(&loc(LOCAL)),
                Err(StoreError::RemovalRefused(RemovalRefusal::Busy))
            );
            assert!(scratch.record(LOCAL).exists());
        }
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);

        // With an artifact held instead, nothing is removed: the record survives, and
        // so does the artifact (formerly the artifact failed mid-way).
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        {
            let _guard = hold_against_removal(&scratch.artifact(LOCAL, STALE_TOKEN));
            assert_eq!(
                store.delete(&loc(LOCAL)),
                Err(StoreError::RemovalRefused(RemovalRefusal::Busy))
            );
            assert_eq!(loaded(store.load(&loc(LOCAL))), state);
            assert!(scratch.artifact(LOCAL, STALE_TOKEN).exists());
        }
        assert_eq!(store.delete(&loc(LOCAL)), Ok(DeleteOutcome::Removed));
    }

    // ---- B1i. reset evidence and conditional deletion -------------------------

    const OTHER_TOKEN: &str = "fedcba9876543210fedcba9876543210";

    /// Name and exact bytes of every plain file in `dir`.
    fn contents(dir: &Path) -> Vec<(String, Vec<u8>)> {
        names(dir)
            .into_iter()
            .map(|name| {
                let bytes = fs::read(dir.join(&name)).unwrap();
                (name, bytes)
            })
            .collect()
    }

    #[test]
    fn evidence_binds_the_exact_bytes_of_the_record_and_every_artifact() {
        let scratch = Scratch::new("evidence-bytes");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris-one");
        scratch.put(&scratch.artifact(LOCAL, OTHER_TOKEN), b"debris-two");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        assert!(evidence.primary_present());
        assert_eq!(evidence.artifact_count(), 2);
        assert_eq!(store.evidence(&loc(LOCAL)).unwrap(), evidence);

        // One byte of the record changes, its length does not.
        let record = fs::read(scratch.record(LOCAL)).unwrap();
        let mut altered = record.clone();
        altered[10] ^= 0x01;
        fs::write(scratch.record(LOCAL), &altered).unwrap();
        assert_ne!(store.evidence(&loc(LOCAL)).unwrap(), evidence);

        // The evidence is the bytes, not a timestamp: restoring them restores it.
        fs::write(scratch.record(LOCAL), &record).unwrap();
        assert_eq!(store.evidence(&loc(LOCAL)).unwrap(), evidence);

        // An artifact keeps its name and length but not its content.
        fs::write(scratch.artifact(LOCAL, STALE_TOKEN), b"debris-ONE").unwrap();
        assert_ne!(store.evidence(&loc(LOCAL)).unwrap(), evidence);
        fs::write(scratch.artifact(LOCAL, STALE_TOKEN), b"debris-one").unwrap();
        assert_eq!(store.evidence(&loc(LOCAL)).unwrap(), evidence);

        // The same bytes under another artifact name.
        fs::rename(
            scratch.artifact(LOCAL, OTHER_TOKEN),
            scratch.artifact(LOCAL, "00000000000000000000000000000000"),
        )
        .unwrap();
        assert_ne!(store.evidence(&loc(LOCAL)).unwrap(), evidence);
        fs::rename(
            scratch.artifact(LOCAL, "00000000000000000000000000000000"),
            scratch.artifact(LOCAL, OTHER_TOKEN),
        )
        .unwrap();
        assert_eq!(store.evidence(&loc(LOCAL)).unwrap(), evidence);

        // An artifact added, one removed, the record removed.
        let extra = scratch.artifact(LOCAL, "11111111111111111111111111111111");
        fs::write(&extra, b"more").unwrap();
        assert_ne!(store.evidence(&loc(LOCAL)).unwrap(), evidence);
        fs::remove_file(&extra).unwrap();
        fs::remove_file(scratch.artifact(LOCAL, OTHER_TOKEN)).unwrap();
        assert_ne!(store.evidence(&loc(LOCAL)).unwrap(), evidence);
        fs::write(scratch.artifact(LOCAL, OTHER_TOKEN), b"debris-two").unwrap();
        assert_eq!(store.evidence(&loc(LOCAL)).unwrap(), evidence);
        fs::remove_file(scratch.record(LOCAL)).unwrap();
        assert_ne!(store.evidence(&loc(LOCAL)).unwrap(), evidence);
    }

    #[test]
    fn evidence_tells_absence_from_presence_and_reads_unusable_records() {
        let scratch = Scratch::new("evidence-absence");
        let store = scratch.store();

        // No directory at all: the empty evidence, and reading it creates nothing.
        let nothing = store.evidence(&loc(LOCAL)).unwrap();
        assert!(!nothing.primary_present());
        assert_eq!(nothing.artifact_count(), 0);
        assert!(!scratch.state_dir().exists());

        // An empty directory is the same nothing.
        fs::create_dir_all(scratch.state_dir()).unwrap();
        assert_eq!(store.evidence(&loc(LOCAL)).unwrap(), nothing);

        // Files that are not this record's own are not part of its evidence.
        // (B3c-3b-2a, U2: the stray file now carries the OTHER record's key; one
        // with this record's key prefix is refused instead.)
        scratch.put(&scratch.record(OTHER_LOCAL), b"someone else's");
        let other_key = record_key(&loc(OTHER_LOCAL));
        fs::write(
            scratch.state_dir().join(format!("{other_key}.notes.txt")),
            b"x",
        )
        .unwrap();
        assert_eq!(store.evidence(&loc(LOCAL)).unwrap(), nothing);

        // A zero-byte record is present, and not the same as nothing.
        scratch.put(&scratch.record(LOCAL), b"");
        let empty = store.evidence(&loc(LOCAL)).unwrap();
        assert!(empty.primary_present());
        assert_ne!(empty, nothing);

        // Corrupt and unsupported records are bound by their exact bytes too.
        scratch.put(&scratch.record(LOCAL), b"garbage");
        let garbage = store.evidence(&loc(LOCAL)).unwrap();
        assert!(matches!(store.load(&loc(LOCAL)), StateLoad::Corrupt(_)));
        assert_ne!(garbage, empty);

        let future = tampered(&based(LOCAL, 9), |value| {
            value["version"] = serde_json::json!(2);
        });
        scratch.put(&scratch.record(LOCAL), &future);
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::UnsupportedVersion);
        let unsupported = store.evidence(&loc(LOCAL)).unwrap();
        assert!(unsupported.primary_present());
        assert_ne!(unsupported, garbage);

        // Artifact-only remnants: no record, one artifact.
        fs::remove_file(scratch.record(LOCAL)).unwrap();
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        let remnants = store.evidence(&loc(LOCAL)).unwrap();
        assert!(!remnants.primary_present());
        assert_eq!(remnants.artifact_count(), 1);
        assert_ne!(remnants, nothing);

        // An empty artifact is still a present artifact.
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"");
        assert_ne!(store.evidence(&loc(LOCAL)).unwrap(), remnants);
    }

    #[test]
    fn evidence_for_one_location_is_not_evidence_for_another() {
        let scratch = Scratch::new("evidence-key");
        let store = scratch.store();

        // Both locations hold nothing, yet their evidence is not interchangeable.
        assert_ne!(
            store.evidence(&loc(LOCAL)).unwrap(),
            store.evidence(&loc(OTHER_LOCAL)).unwrap()
        );

        // The key follows the store's own path-identity rule (ASCII case).
        assert_eq!(
            store.evidence(&loc(LOCAL)).unwrap(),
            store
                .evidence(&loc(&LOCAL
                    .to_ascii_uppercase()
                    .replace("LVAULT", "lvault")))
                .unwrap()
        );
    }

    #[test]
    fn evidence_capture_writes_nothing() {
        let scratch = Scratch::new("evidence-readonly");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        scratch.put(&scratch.record(OTHER_LOCAL), b"neighbour");

        let before = contents(&scratch.state_dir());
        let modified = fs::metadata(scratch.record(LOCAL))
            .unwrap()
            .modified()
            .unwrap();

        for _ in 0..3 {
            let _ = store.evidence(&loc(LOCAL)).unwrap();
        }

        assert_eq!(contents(&scratch.state_dir()), before);
        assert_eq!(
            fs::metadata(scratch.record(LOCAL))
                .unwrap()
                .modified()
                .unwrap(),
            modified
        );
    }

    #[test]
    fn evidence_refuses_what_it_cannot_read_in_full_as_a_plain_file() {
        // An oversized record cannot be bound exactly.
        let big = Scratch::new("evidence-oversized-record");
        let store = big.store();
        fs::create_dir_all(big.state_dir()).unwrap();
        let file = File::create(big.record(LOCAL)).unwrap();
        file.set_len(MAX_SYNC_STATE_BYTES as u64 + 1).unwrap();
        drop(file);
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Corrupt(CorruptReason::TooLarge)
        );
        assert_eq!(
            store.evidence(&loc(LOCAL)).unwrap_err(),
            EvidenceRefusal::Oversized
        );

        // So cannot an oversized artifact beside a readable record.
        let artifact = Scratch::new("evidence-oversized-artifact");
        let store = artifact.store();
        store.create(&based(LOCAL, 9)).unwrap();
        let file = File::create(artifact.artifact(LOCAL, STALE_TOKEN)).unwrap();
        file.set_len(MAX_SYNC_STATE_BYTES as u64 + 1).unwrap();
        drop(file);
        assert_eq!(
            store.evidence(&loc(LOCAL)).unwrap_err(),
            EvidenceRefusal::Oversized
        );

        // A directory where the record belongs.
        let directory = Scratch::new("evidence-directory-record");
        let store = directory.store();
        fs::create_dir_all(directory.record(LOCAL)).unwrap();
        assert_eq!(
            store.evidence(&loc(LOCAL)).unwrap_err(),
            EvidenceRefusal::UnexpectedObject
        );

        // A directory named like an artifact.
        let named = Scratch::new("evidence-directory-artifact");
        let store = named.store();
        fs::create_dir_all(named.artifact(LOCAL, STALE_TOKEN)).unwrap();
        assert_eq!(
            store.evidence(&loc(LOCAL)).unwrap_err(),
            EvidenceRefusal::UnexpectedObject
        );

        // A regular file where the sync-state directory belongs.
        let file_dir = Scratch::new("evidence-file-directory");
        let store = file_dir.store();
        fs::write(file_dir.state_dir(), b"not a directory").unwrap();
        assert!(store.evidence(&loc(LOCAL)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn evidence_refuses_inaccessible_files_and_reparse_points() {
        // A record that cannot be opened for reading.
        let scratch = Scratch::new("evidence-inaccessible-record");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        {
            let _guard = hold_exclusively(&scratch.record(LOCAL));
            assert_eq!(
                store.evidence(&loc(LOCAL)).unwrap_err(),
                EvidenceRefusal::Unreadable
            );
        }
        assert!(store.evidence(&loc(LOCAL)).is_ok());

        // An artifact that cannot be opened for reading.
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        {
            let _guard = hold_exclusively(&scratch.artifact(LOCAL, STALE_TOKEN));
            assert_eq!(
                store.evidence(&loc(LOCAL)).unwrap_err(),
                EvidenceRefusal::Unreadable
            );
        }

        // The sync-state directory is a junction: never read through.
        let junction = Scratch::new("evidence-junction-directory");
        let elsewhere = junction.root().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(
            elsewhere.join(format!("{}.json", record_key(&loc(LOCAL)))),
            based(LOCAL, 9).encode().unwrap(),
        )
        .unwrap();
        make_junction(&junction.state_dir(), &elsewhere);
        assert_eq!(
            junction.store().evidence(&loc(LOCAL)).unwrap_err(),
            EvidenceRefusal::UnexpectedObject
        );
        fs::remove_dir(junction.state_dir()).unwrap();

        // The record path is a junction to a directory.
        let record = Scratch::new("evidence-junction-record");
        let target = record.root().join("target-dir");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(record.state_dir()).unwrap();
        make_junction(&record.record(LOCAL), &target);
        assert_eq!(
            record.store().evidence(&loc(LOCAL)).unwrap_err(),
            EvidenceRefusal::UnexpectedObject
        );
        fs::remove_dir(record.record(LOCAL)).unwrap();
    }

    #[test]
    fn evidence_reveals_nothing_when_printed() {
        let scratch = Scratch::new("evidence-debug");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"LEAKMARK-debris");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        let record = fs::read(scratch.record(LOCAL)).unwrap();
        let mut shown = vec![format!("{evidence:?}"), format!("{:#?}", evidence)];

        for refusal in [
            EvidenceRefusal::Unreadable,
            EvidenceRefusal::UnexpectedObject,
            EvidenceRefusal::EntryLimit,
            EvidenceRefusal::Oversized,
            EvidenceRefusal::Unstable,
        ] {
            shown.push(format!("{refusal:?}"));
            shown.push(refusal.to_string());
            shown.push(format!("{:?}", ConditionalDeleteError::Evidence(refusal)));
            shown.push(ConditionalDeleteError::Evidence(refusal).to_string());
        }
        shown.push(format!("{:?}", ConditionalDeleteError::EvidenceChanged));
        shown.push(ConditionalDeleteError::EvidenceChanged.to_string());
        shown.push(ConditionalDeleteError::Store(StoreError::IncompleteDeletion).to_string());

        let needles = [
            scratch.root().to_string_lossy().into_owned(),
            record_key(&loc(LOCAL)),
            STALE_TOKEN.to_owned(),
            EnvelopeFingerprint::of_bytes(&record).to_hex(),
            EnvelopeFingerprint::of_bytes(b"LEAKMARK-debris").to_hex(),
            record.len().to_string(),
            "LEAKMARK".to_owned(),
            ".json".to_owned(),
            ".tmp".to_owned(),
            "MARKER".to_owned(),
        ];

        for output in &shown {
            for needle in &needles {
                assert!(
                    !output.contains(needle.as_str()),
                    "leaks {needle:?}: {output}"
                );
            }
        }
    }

    #[test]
    fn conditional_deletion_removes_exactly_what_the_evidence_describes() {
        let scratch = Scratch::new("conditional-delete");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        let survivor = based(OTHER_LOCAL, 4);
        store.create(&survivor).unwrap();
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        // B3c-3b-2a (U2): the neighbour carries the key of a third, unrelated
        // location (not this record's, and not the survivor's).
        let third_key = record_key(&loc(r"\\?\C:\Synthetic\Vaults\THIRD-MARKER.lvault"));
        let unrelated = scratch.state_dir().join(format!("{third_key}.notes.txt"));
        fs::write(&unrelated, b"unrelated").unwrap();

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Ok(DeleteOutcome::Removed)
        );

        assert!(!scratch.record(LOCAL).exists());
        assert!(!scratch.artifact(LOCAL, STALE_TOKEN).exists());
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);
        assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated");
        assert_eq!(loaded(store.load(&loc(OTHER_LOCAL))), survivor);

        // The old evidence is not an authorization to delete again: what is
        // there now is nothing, and nothing is not what it described.
        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Err(ConditionalDeleteError::EvidenceChanged)
        );
        assert_eq!(loaded(store.load(&loc(OTHER_LOCAL))), survivor);
    }

    #[test]
    fn conditional_deletion_of_a_corrupt_unsupported_or_remnant_state() {
        type Setup = Box<dyn Fn(&Scratch)>;

        let cases: Vec<(&str, Setup)> = vec![
            ("corrupt", Box::new(|s| s.put(&s.record(LOCAL), b"garbage"))),
            ("empty", Box::new(|s| s.put(&s.record(LOCAL), b""))),
            (
                "unsupported",
                Box::new(|s| {
                    let future = tampered(&based(LOCAL, 9), |value| {
                        value["version"] = serde_json::json!(2);
                    });
                    s.put(&s.record(LOCAL), &future);
                }),
            ),
            (
                "remnants",
                Box::new(|s| s.put(&s.artifact(LOCAL, STALE_TOKEN), b"debris")),
            ),
        ];

        for (name, setup) in &cases {
            let scratch = Scratch::new(&format!("conditional-{name}"));
            let store = scratch.store();
            setup(&scratch);

            let evidence = store.evidence(&loc(LOCAL)).unwrap();

            if *name == "unsupported" {
                // B3c-3b-2a: a record of an unsupported version may belong to a
                // newer state. Its evidence can still be captured, but this store
                // no longer removes it, and nothing is changed.
                let before = contents(&scratch.state_dir());

                assert_eq!(
                    store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
                    Err(ConditionalDeleteError::Store(
                        StoreError::UnresolvedNewerState
                    )),
                    "{name}"
                );
                assert_eq!(
                    store.load(&loc(LOCAL)),
                    StateLoad::UnsupportedVersion,
                    "{name}"
                );
                assert_eq!(contents(&scratch.state_dir()), before, "{name}");

                continue;
            }

            assert_eq!(
                store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
                Ok(DeleteOutcome::Removed),
                "{name}"
            );
            assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured, "{name}");
        }
    }

    #[test]
    fn conditional_deletion_refuses_any_difference_and_removes_nothing() {
        type Change = Box<dyn Fn(&Scratch)>;

        let changes: Vec<(&str, Change)> = vec![
            (
                "record bytes",
                Box::new(|s| {
                    let mut bytes = fs::read(s.record(LOCAL)).unwrap();
                    bytes[10] ^= 0x01;
                    fs::write(s.record(LOCAL), bytes).unwrap();
                }),
            ),
            (
                "record replaced by a valid other state",
                Box::new(|s| {
                    fs::write(s.record(LOCAL), based(LOCAL, 77).encode().unwrap()).unwrap();
                }),
            ),
            (
                "record removed",
                Box::new(|s| fs::remove_file(s.record(LOCAL)).unwrap()),
            ),
            (
                "artifact content",
                Box::new(|s| fs::write(s.artifact(LOCAL, STALE_TOKEN), b"DEBRIS").unwrap()),
            ),
            (
                "artifact removed",
                Box::new(|s| fs::remove_file(s.artifact(LOCAL, STALE_TOKEN)).unwrap()),
            ),
            (
                "artifact added",
                Box::new(|s| fs::write(s.artifact(LOCAL, OTHER_TOKEN), b"new").unwrap()),
            ),
        ];

        for (name, change) in &changes {
            let scratch = Scratch::new("conditional-changed");
            let store = scratch.store();
            store.create(&based(LOCAL, 9)).unwrap();
            scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
            let evidence = store.evidence(&loc(LOCAL)).unwrap();

            change(&scratch);
            let after_change = contents(&scratch.state_dir());

            let error = store
                .delete_if_evidence_matches(&loc(LOCAL), &evidence)
                .unwrap_err();

            assert_eq!(error, ConditionalDeleteError::EvidenceChanged, "{name}");
            assert!(!error.removal_may_have_started(), "{name}");
            assert_eq!(contents(&scratch.state_dir()), after_change, "{name}");
        }
    }

    #[test]
    fn conditional_deletion_rechecks_immediately_before_the_first_removal() {
        let scratch = Scratch::new("conditional-window");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        // The record is rewritten after the preconditions passed and before the
        // comparison: the hook runs exactly there.
        let record = scratch.record(LOCAL);
        run_at(&store, Point::BeforeEvidenceRecheck, move || {
            fs::write(&record, based(LOCAL, 123).encode().unwrap()).unwrap();
        });

        let before = fs::read(scratch.record(LOCAL)).unwrap();

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Err(ConditionalDeleteError::EvidenceChanged)
        );
        assert_ne!(fs::read(scratch.record(LOCAL)).unwrap(), before);
        assert!(scratch.record(LOCAL).exists());
        assert!(scratch.artifact(LOCAL, STALE_TOKEN).exists());
    }

    #[test]
    fn evidence_for_another_location_never_authorizes_a_deletion() {
        let scratch = Scratch::new("conditional-other-key");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        let foreign = store.evidence(&loc(OTHER_LOCAL)).unwrap();
        let before = contents(&scratch.state_dir());

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &foreign),
            Err(ConditionalDeleteError::EvidenceChanged)
        );
        assert_eq!(contents(&scratch.state_dir()), before);
    }

    #[test]
    fn conditional_deletion_of_nothing_needs_the_empty_evidence() {
        let scratch = Scratch::new("conditional-nothing");
        let store = scratch.store();

        let nothing = store.evidence(&loc(LOCAL)).unwrap();
        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &nothing),
            Ok(DeleteOutcome::AlreadyAbsent)
        );
        assert!(!scratch.state_dir().exists());

        // Evidence of something that has since vanished is a change.
        store.create(&based(LOCAL, 9)).unwrap();
        let something = store.evidence(&loc(LOCAL)).unwrap();
        fs::remove_file(scratch.record(LOCAL)).unwrap();

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &something),
            Err(ConditionalDeleteError::EvidenceChanged)
        );
    }

    #[test]
    fn conditional_deletion_failures_are_classified_by_whether_removal_began() {
        // Before the first removal: an unexpected object blocks, nothing removed.
        let blocked = Scratch::new("conditional-blocked");
        let store = blocked.store();
        store.create(&based(LOCAL, 9)).unwrap();
        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        fs::remove_file(blocked.record(LOCAL)).unwrap();
        fs::create_dir_all(blocked.record(LOCAL)).unwrap();

        let error = store
            .delete_if_evidence_matches(&loc(LOCAL), &evidence)
            .unwrap_err();
        assert_eq!(
            error,
            ConditionalDeleteError::Store(StoreError::UnexpectedObject)
        );
        assert!(!error.removal_may_have_started());
        assert!(blocked.record(LOCAL).is_dir());

        // The recheck cannot capture evidence: refused, nothing removed.
        let unreadable = Scratch::new("conditional-recheck-fault");
        let store = unreadable.store();
        store.create(&based(LOCAL, 9)).unwrap();
        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        fail_at(
            &store,
            Point::BeforeEvidenceRecheck,
            io::ErrorKind::PermissionDenied,
        );
        let error = store
            .delete_if_evidence_matches(&loc(LOCAL), &evidence)
            .unwrap_err();
        assert!(matches!(error, ConditionalDeleteError::Evidence(_)));
        assert!(!error.removal_may_have_started());
        assert!(unreadable.record(LOCAL).exists());

        // After removal began: an artifact removal fails; the record is intact.
        let partial = Scratch::new("conditional-artifact-fault");
        let store = partial.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();
        partial.put(&partial.artifact(LOCAL, STALE_TOKEN), b"debris");
        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        fail_at(
            &store,
            Point::RemoveArtifact,
            io::ErrorKind::PermissionDenied,
        );
        let error = store
            .delete_if_evidence_matches(&loc(LOCAL), &evidence)
            .unwrap_err();
        assert_eq!(
            error,
            ConditionalDeleteError::Store(StoreError::IncompleteDeletion)
        );
        assert!(error.removal_may_have_started());
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);

        // After removal began: the artifacts are gone but the record is not.
        let late = Scratch::new("conditional-record-fault");
        let store = late.store();
        store.create(&state).unwrap();
        late.put(&late.artifact(LOCAL, STALE_TOKEN), b"debris");
        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        fail_at(
            &store,
            Point::RemovePrimary,
            io::ErrorKind::PermissionDenied,
        );
        let error = store
            .delete_if_evidence_matches(&loc(LOCAL), &evidence)
            .unwrap_err();
        assert!(error.removal_may_have_started());
        assert!(!late.artifact(LOCAL, STALE_TOKEN).exists());
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_state_directory_is_never_deleted_through() {
        let scratch = Scratch::new("conditional-junction");
        let elsewhere = scratch.root().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let record = elsewhere.join(format!("{}.json", record_key(&loc(LOCAL))));
        fs::write(&record, based(LOCAL, 9).encode().unwrap()).unwrap();
        make_junction(&scratch.state_dir(), &elsewhere);

        let store = scratch.store();
        let nothing = {
            let empty = Scratch::new("conditional-junction-empty");
            empty.store().evidence(&loc(LOCAL)).unwrap()
        };

        let error = store
            .delete_if_evidence_matches(&loc(LOCAL), &nothing)
            .unwrap_err();

        assert_eq!(
            error,
            ConditionalDeleteError::Store(StoreError::UnexpectedObject)
        );
        assert!(!error.removal_may_have_started());
        assert!(record.exists());
        fs::remove_dir(scratch.state_dir()).unwrap();
    }

    #[test]
    fn the_plain_deletion_keeps_its_contract() {
        // `delete` still removes without any evidence, and still reports
        // `AlreadyAbsent` for nothing: B1i added a conditional sibling and left
        // this one alone.
        let scratch = Scratch::new("plain-delete-unchanged");
        let store = scratch.store();
        scratch.put(&scratch.record(LOCAL), b"garbage");
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");

        assert_eq!(store.delete(&loc(LOCAL)), Ok(DeleteOutcome::Removed));
        assert_eq!(store.delete(&loc(LOCAL)), Ok(DeleteOutcome::AlreadyAbsent));
    }

    // ---- 19. unexpected objects and reparse points -------------------------------

    #[test]
    fn a_directory_in_place_of_a_record_is_unexpected_and_untouched() {
        let scratch = Scratch::new("directory-record");
        let store = scratch.store();
        fs::create_dir_all(scratch.record(LOCAL)).unwrap();
        fs::write(scratch.record(LOCAL).join("inner.txt"), b"keep").unwrap();
        let state = based(LOCAL, 9);

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert_eq!(store.create(&state), Err(StoreError::UnexpectedObject));
        assert_eq!(
            store.replace(&state, &rebuilt(&state, checkpoint(10), None)),
            Err(StoreError::CurrentUnreadable)
        );
        assert_eq!(store.delete(&loc(LOCAL)), Err(StoreError::UnexpectedObject));
        assert_eq!(
            fs::read(scratch.record(LOCAL).join("inner.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn a_directory_named_like_an_artifact_blocks_and_is_never_deleted() {
        let scratch = Scratch::new("directory-artifact");
        let store = scratch.store();
        fs::create_dir_all(scratch.artifact(LOCAL, STALE_TOKEN)).unwrap();

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
        );
        assert_eq!(
            store.create(&unbased(LOCAL)),
            Err(StoreError::UnresolvedArtifacts)
        );
        assert_eq!(store.delete(&loc(LOCAL)), Err(StoreError::UnexpectedObject));
        assert!(scratch.artifact(LOCAL, STALE_TOKEN).is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn junctions_are_never_followed() {
        let state = based(LOCAL, 9);

        // The sync-state directory itself is a junction.
        let scratch = Scratch::new("junction-directory");
        let elsewhere = scratch.root().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        make_junction(&scratch.state_dir(), &elsewhere);
        let store = scratch.store();

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert_eq!(store.create(&state), Err(StoreError::UnexpectedObject));
        assert_eq!(
            store.replace(&state, &rebuilt(&state, checkpoint(10), None)),
            Err(StoreError::UnexpectedObject)
        );
        assert_eq!(store.delete(&loc(LOCAL)), Err(StoreError::UnexpectedObject));
        assert!(names(&elsewhere).is_empty());
        fs::remove_dir(scratch.state_dir()).unwrap();

        // The record path is a junction to a directory holding a valid state
        // file under the very same record name.
        let second = Scratch::new("junction-record");
        let second_store = second.store();
        let target = second.root().join("target-dir");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(second.state_dir()).unwrap();
        make_junction(&second.record(LOCAL), &target);
        assert_eq!(
            second_store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert_eq!(
            second_store.create(&state),
            Err(StoreError::UnexpectedObject)
        );
        assert_eq!(
            second_store.delete(&loc(LOCAL)),
            Err(StoreError::UnexpectedObject)
        );
        assert!(names(&target).is_empty());
        fs::remove_dir(second.record(LOCAL)).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_file_symlink_record_is_not_followed_when_the_platform_allows_creating_one() {
        use std::os::windows::fs::symlink_file;

        let scratch = Scratch::new("symlink-record");
        let store = scratch.store();
        let state = based(LOCAL, 9);

        // A valid state under another name, linked at the record path.
        let genuine = scratch.root().join("genuine.json");
        fs::write(&genuine, state.encode().unwrap()).unwrap();
        fs::create_dir_all(scratch.state_dir()).unwrap();

        if let Err(error) = symlink_file(&genuine, scratch.record(LOCAL)) {
            // File symlinks need a privilege this account may not hold. The
            // junction test above still covers reparse rejection.
            eprintln!(
                "SKIPPED symlink assertions: cannot create a file symlink here ({:?})",
                error.kind()
            );
            return;
        }

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert_eq!(store.create(&state), Err(StoreError::UnexpectedObject));
        assert_eq!(store.delete(&loc(LOCAL)), Err(StoreError::UnexpectedObject));
        assert_eq!(fs::read(&genuine).unwrap(), state.encode().unwrap());
    }

    // ---- absence classification regressions (A-H) ----------------------------

    #[test]
    fn a_normal_missing_root_sync_dir_or_record_is_not_configured() {
        // A. root (and several of its parents) do not exist yet: first use.
        let scratch = Scratch::new("absent-root");
        let deep = scratch.root().join("a").join("b").join("app-data");
        let store = SyncStateStore::new(&deep).unwrap();
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);
        assert!(!scratch.root().join("a").exists());

        // B. root exists, `sync-state` does not.
        let second = Scratch::new("absent-sync-dir");
        assert_eq!(second.store().load(&loc(LOCAL)), StateLoad::NotConfigured);

        // C. directory exists, record does not.
        fs::create_dir_all(second.state_dir()).unwrap();
        assert_eq!(second.store().load(&loc(LOCAL)), StateLoad::NotConfigured);

        // First use still works end to end from the deep missing root.
        store.create(&unbased(LOCAL)).unwrap();
        assert!(matches!(store.load(&loc(LOCAL)), StateLoad::Loaded(_)));
    }

    #[test]
    fn a_regular_file_ancestor_is_unreadable_and_blocks_creation() {
        // D. the injected root has a regular-file ancestor.
        let scratch = Scratch::new("file-ancestor");
        let blocker = scratch.root().join("afile");
        fs::write(&blocker, b"plain file").unwrap();
        let state = unbased(LOCAL);

        let beneath = SyncStateStore::new(&blocker.join("deep").join("app-data")).unwrap();
        assert_eq!(
            beneath.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert_eq!(
            beneath.load(&loc(LOCAL)).into_sync_state_load(),
            SyncStateLoad::Unreadable
        );

        // The root itself is a regular file.
        let as_root = SyncStateStore::new(&blocker).unwrap();
        assert_eq!(
            as_root.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );

        // H. neither failed load authorizes a new record.
        assert!(beneath.create(&state).is_err());
        assert!(as_root.create(&state).is_err());
        assert_eq!(fs::read(&blocker).unwrap(), b"plain file");
        assert!(beneath.delete(&loc(LOCAL)).is_err());
    }

    #[test]
    fn sync_state_being_a_regular_file_is_unreadable_for_every_operation() {
        // E.
        let scratch = Scratch::new("sync-state-is-file");
        fs::write(scratch.state_dir(), b"plain file").unwrap();
        let store = scratch.store();
        let state = based(LOCAL, 9);

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert!(store.create(&state).is_err());
        assert!(store
            .replace(&state, &rebuilt(&state, checkpoint(10), None))
            .is_err());
        assert!(store.delete(&loc(LOCAL)).is_err());
        assert_eq!(fs::read(scratch.state_dir()).unwrap(), b"plain file");
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_ancestor_of_a_missing_sync_dir_is_never_trusted() {
        // F. the nearest existing ancestor of the absent `sync-state` is a
        // junction; absence behind it is not established.
        let scratch = Scratch::new("junction-ancestor");
        let target = scratch.root().join("target-dir");
        fs::create_dir_all(&target).unwrap();
        let link = scratch.root().join("link");
        make_junction(&link, &target);

        let store = SyncStateStore::new(&link.join("app-data")).unwrap();
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert!(store.create(&unbased(LOCAL)).is_err());
        assert!(names(&target).is_empty());

        // Root itself a junction, `sync-state` not yet present.
        let direct = SyncStateStore::new(&link).unwrap();
        assert_eq!(
            direct.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );
        assert!(names(&target).is_empty());
        fs::remove_dir(&link).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn io_errors_stay_unreadable_and_a_failed_load_cannot_authorize_creation() {
        // G + H. A held record cannot be read; the unreadable outcome is not
        // absence and creation is refused.
        let scratch = Scratch::new("io-no-authorize");
        let store = scratch.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();
        let guard = hold_exclusively(&scratch.record(LOCAL));

        let load = store.load(&loc(LOCAL));
        assert!(matches!(
            load,
            StateLoad::Unreadable(UnreadableReason::Io(_))
        ));
        assert_ne!(load.into_sync_state_load(), SyncStateLoad::NotConfigured);
        // B3c-3b-2a: refused at the compatibility gate's scan (formerly
        // `AlreadyExists`); creation is still refused and nothing is written.
        assert!(matches!(
            store.create(&state),
            Err(StoreError::Io {
                stage: IoStage::Scan,
                ..
            })
        ));
        drop(guard);
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);
    }

    #[test]
    fn deletion_that_removed_the_last_file_is_a_fully_absent_record() {
        // A process that dies after the last removal but before reporting
        // success leaves exactly this disk state: absent, by explicit
        // user-authorized deletion. It is not an error state.
        let scratch = Scratch::new("delete-crash-after-last");
        let store = scratch.store();
        store.create(&based(LOCAL, 9)).unwrap();
        fs::remove_file(scratch.record(LOCAL)).unwrap();
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);

        // Partial cleanup (an artifact remains) is not absence.
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
        );
    }

    #[test]
    fn the_store_root_must_be_absolute() {
        assert_eq!(
            SyncStateStore::new(Path::new("relative\\app-data")).unwrap_err(),
            StoreError::RootNotAbsolute
        );
        assert_eq!(
            SyncStateStore::new(Path::new("")).unwrap_err(),
            StoreError::RootNotAbsolute
        );
    }

    // ---- 20. sanitized output -----------------------------------------------------

    #[test]
    fn errors_and_debug_output_carry_no_paths_locators_or_identifiers() {
        let scratch = Scratch::new("sanitized");
        let store = scratch.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();

        let mut outputs: Vec<String> = Vec::new();
        let mut note = |text: String| outputs.push(text);

        note(format!("{store:?}"));
        note(format!("{:?}", store.load(&loc(LOCAL))));
        note(format!("{:?}", store.load(&loc(OTHER_LOCAL))));

        let results = [
            store.create(&state),
            store.replace(&based(LOCAL, 8), &based(LOCAL, 10)),
            store.replace(&based(OTHER_LOCAL, 1), &based(OTHER_LOCAL, 2)),
            store.replace(&state, &based(OTHER_LOCAL, 9)),
            store.delete(&loc(OTHER_LOCAL)).map(|_| ()),
        ];
        for result in results {
            if let Err(error) = result {
                note(format!("{error} | {error:?}"));
            }
        }

        scratch.put(&scratch.artifact(OTHER_LOCAL, STALE_TOKEN), b"x");
        note(format!("{:?}", store.load(&loc(OTHER_LOCAL))));
        if let Err(error) = store.create(&based(OTHER_LOCAL, 1)) {
            note(format!("{error} | {error:?}"));
        }

        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::Other,
        ] {
            let error = StoreError::Io {
                stage: IoStage::Open,
                kind,
            };
            note(format!("{error} | {error:?}"));
            note(format!(
                "{:?}",
                StateLoad::Unreadable(UnreadableReason::Io(kind))
            ));
        }
        for error in [
            StoreError::RootNotAbsolute,
            StoreError::AlreadyExists,
            StoreError::Missing,
            StoreError::UnresolvedArtifacts,
            StoreError::UnexpectedObject,
            StoreError::CurrentUnreadable,
            StoreError::CurrentCorrupt,
            StoreError::CurrentUnsupportedVersion,
            StoreError::CurrentLocatorMismatch,
            StoreError::Changed,
            StoreError::LocatorMismatch,
            StoreError::BindingIdentityChanged,
            StoreError::TrustedHistoryRegression,
            StoreError::NoClobberUnsupported,
            StoreError::VerificationFailed,
            StoreError::IncompleteDeletion,
            StoreError::Encode(SyncStateEncodeError::TooLarge),
        ] {
            note(format!("{error} | {error:?}"));
        }

        let root = scratch.root().to_string_lossy().into_owned();
        let key = record_key(&loc(LOCAL));
        let other_key = record_key(&loc(OTHER_LOCAL));
        let needles = [
            "LOCAL-MARKER",
            "TARGET-MARKER",
            "OTHER-MARKER",
            "Synthetic",
            ".qa-local",
            "sanitized-",
            root.as_str(),
            key.as_str(),
            other_key.as_str(),
            "11111111-2222-3333-4444-555555555555",
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "01234567-89ab-cdef-0123-456789abcdef",
        ];
        for output in &outputs {
            for needle in needles {
                assert!(
                    !output.contains(needle),
                    "output leaks {needle:?}: {output}"
                );
            }
        }
        assert!(!outputs.is_empty());
    }

    // ---- 21. local-only vault behavior is unchanged -----------------------------------

    #[test]
    fn local_only_vault_files_and_sessions_are_unaffected() {
        const NOW_MS: i64 = 1_700_000_000_000;
        const PASSWORD: &str = "sync-state-store-test-only-password";

        let scratch = Scratch::new("local-only");
        let vault_dir = scratch.root().join("vaults");
        fs::create_dir_all(&vault_dir).unwrap();
        let vault_path = vault_dir.join("vault.lvault");

        let session =
            UnlockedVaultSession::create(&vault_path, Zeroizing::new(PASSWORD.to_owned()), NOW_MS)
                .unwrap();
        let vault_id = session.data().vault_id;

        let vault_bytes = fs::read(&vault_path).unwrap();
        let vault_dir_listing = names(&vault_dir);

        // Exercise every store operation while the exclusive session lock is
        // held, as the future integration will.
        let locator = loc(&vault_path.to_string_lossy());
        let store = scratch.store();
        assert_eq!(store.load(&locator), StateLoad::NotConfigured);
        let initial = build(
            &vault_path.to_string_lossy(),
            vault_id,
            SyncBase::Unbased,
            Some(
                PendingPush::new(
                    INTENT,
                    PushIntent::new(PushBaseline::Absent, fp(2)).unwrap(),
                    1,
                )
                .unwrap(),
            ),
        );
        store.create(&initial).unwrap();
        let based_state = rebuilt(&initial, checkpoint(1), None);
        store.replace(&initial, &based_state).unwrap();
        assert!(loaded(store.load(&locator))
            .verify_binding(vault_id, &locator, &loc(TARGET))
            .is_ok());
        assert_eq!(store.delete(&locator), Ok(DeleteOutcome::Removed));

        // The vault, its directory and its lock/backup siblings are untouched,
        // and the sync-state directory is not inside the vault directory.
        assert_eq!(fs::read(&vault_path).unwrap(), vault_bytes);
        assert_eq!(names(&vault_dir), vault_dir_listing);
        assert!(!scratch.state_dir().starts_with(&vault_dir));

        session.lock();
        let reopened =
            UnlockedVaultSession::unlock(&vault_path, Zeroizing::new(PASSWORD.to_owned())).unwrap();
        assert_eq!(reopened.data().vault_id, vault_id);
        assert_eq!(fs::read(&vault_path).unwrap(), vault_bytes);
    }

    // ---- Stage 1U-4 B1b: session-bound, read-only load ----------------------------
    //
    // Real `UnlockedVaultSession`s over synthetic vaults and synthetic state
    // records, all beneath the git-ignored `.qa-local/sync-state-b1-tests/`.
    // Not covered here (and not claimed): a live remote or target adapter (none
    // exists), UI, Tauri command wiring, and `SyncStateRoot::from_app` itself
    // (it needs a running Tauri app; its path validation is tested through
    // `from_resolved`).

    use crate::{
        recent_vaults::normalize_existing_vault_path,
        vault::{
            session::{CategoryInput, SessionSyncState, SyncStateUnavailable},
            storage::save_envelope_atomic,
        },
    };
    use localvault_core::{sync_state::BindingMismatch, vault::format::create_envelope};

    const B1B_PASSWORD: &str = "sync-state-b1b-test-only-password";
    const B1B_NOW_MS: i64 = 1_700_000_000_000;

    fn b1b_password() -> Zeroizing<String> {
        Zeroizing::new(B1B_PASSWORD.to_owned())
    }

    /// A scratch directory with a `vaults` folder and a separate, initially
    /// absent `app-local` root (first use).
    struct Fixture {
        scratch: Scratch,
        vaults: PathBuf,
        vault: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let scratch = Scratch::new(name);
            let vaults = scratch.root().join("vaults");
            fs::create_dir_all(&vaults).unwrap();
            let vault = vaults.join("vault.lvault");

            Self {
                scratch,
                vaults,
                vault,
            }
        }

        fn app_root(&self) -> PathBuf {
            self.scratch.root().join("app-local")
        }

        fn root(&self) -> SyncStateRoot {
            SyncStateRoot::for_test(self.app_root())
        }
    }

    fn create_session(path: &Path) -> UnlockedVaultSession {
        UnlockedVaultSession::create(path, b1b_password(), B1B_NOW_MS).unwrap()
    }

    fn open_session(path: &Path) -> UnlockedVaultSession {
        UnlockedVaultSession::unlock(path, b1b_password()).unwrap()
    }

    fn canonical(path: &Path) -> String {
        normalize_existing_vault_path(path).unwrap()
    }

    fn state_for(local: &str, vault_id: Uuid, target: &str) -> SyncState {
        SyncState::new(
            BindingId::new(BINDING).unwrap(),
            tag_for(vault_id),
            loc(local),
            loc(target),
            checkpoint(5),
            None,
        )
        .unwrap()
    }

    fn record_in(root: &SyncStateRoot, locator: &str) -> PathBuf {
        root.path()
            .join(SYNC_STATE_DIRECTORY)
            .join(format!("{}.json", record_key(&loc(locator))))
    }

    fn publish(root: &SyncStateRoot, state: &SyncState) {
        SyncStateStore::new(root.path())
            .unwrap()
            .create(state)
            .unwrap();
    }

    fn put_at(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn bound(result: SessionSyncState) -> SyncState {
        match result {
            SessionSyncState::Bound(bound) => bound.state().clone(),
            other => panic!("expected a bound state, got {other:?}"),
        }
    }

    /// Everything beneath `dir`, without following reparse points: kind, name,
    /// and for files the modification time and content hash.
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

                if is_plain_directory(&metadata) {
                    out.push(format!("D {relative}"));
                    walk(&path, base, out);
                } else if relative.ends_with(".lock") {
                    // The session's own exclusively locked lock file: name only.
                    out.push(format!("L {relative}"));
                } else if is_plain_file(&metadata) {
                    let hash = EnvelopeFingerprint::of_bytes(&fs::read(&path).unwrap()).to_hex();
                    out.push(format!(
                        "F {relative} {:?} {hash}",
                        metadata.modified().unwrap()
                    ));
                } else {
                    out.push(format!("O {relative}"));
                }
            }
        }

        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out
    }

    #[test]
    fn a_session_loads_its_matching_record_and_changes_nothing() {
        let fx = Fixture::new("b1b-bound");
        let session = create_session(&fx.vault);
        let vault_id = session.data().vault_id;
        let root = fx.root();
        let locator = canonical(&fx.vault);

        // The stored locator is the existing normalization (canonical, verbatim
        // on Windows), and the record file is keyed from exactly that string.
        #[cfg(windows)]
        assert!(locator.starts_with(r"\\?\"));
        let state = state_for(&locator, vault_id, TARGET);
        publish(&root, &state);
        assert!(record_in(&root, &locator).is_file());

        let before = snapshot(&fx.scratch.root());

        let loaded = bound(session.load_sync_state(&root));

        assert_eq!(loaded, state);
        // Read-only: not created, not changed (content and modification time).
        assert_eq!(snapshot(&fx.scratch.root()), before);

        // The loaded record is not authorization for any other target.
        assert_eq!(
            loaded.verify_binding(vault_id, &loc(&locator), &loc(OTHER_LOCAL)),
            Err(BindingMismatch::TargetLocator)
        );
        assert!(loaded
            .verify_binding(vault_id, &loc(&locator), &loc(TARGET))
            .is_ok());
    }

    #[test]
    fn no_record_is_not_configured_and_nothing_is_created() {
        let fx = Fixture::new("b1b-absent");
        let session = create_session(&fx.vault);
        let root = fx.root();
        let before = snapshot(&fx.scratch.root());

        // First use: the app-local root does not even exist yet.
        assert_eq!(
            session.load_sync_state(&root),
            SessionSyncState::NotConfigured
        );
        assert!(!root.path().exists());

        // The directory exists but holds no record.
        fs::create_dir_all(root.path().join(SYNC_STATE_DIRECTORY)).unwrap();
        let with_dir = snapshot(&fx.scratch.root());
        assert_eq!(
            session.load_sync_state(&root),
            SessionSyncState::NotConfigured
        );
        assert_eq!(snapshot(&fx.scratch.root()), with_dir);
        assert_ne!(with_dir, before);
    }

    #[test]
    fn every_failure_outcome_stays_distinct_and_leaves_the_record_alone() {
        let fx = Fixture::new("b1b-outcomes");
        let session = create_session(&fx.vault);
        let vault_id = session.data().vault_id;
        let root = fx.root();
        let locator = canonical(&fx.vault);
        let record = record_in(&root, &locator);
        let valid = state_for(&locator, vault_id, TARGET);

        let check = |bytes: &[u8], expected: SessionSyncState| {
            put_at(&record, bytes);
            let result = session.load_sync_state(&root);
            assert_eq!(result, expected);
            assert_ne!(result, SessionSyncState::NotConfigured);
            assert_eq!(fs::read(&record).unwrap(), bytes);
        };

        check(
            b"this is not a sync state",
            SessionSyncState::Corrupt(CorruptReason::Undecodable),
        );
        check(b"", SessionSyncState::Corrupt(CorruptReason::Empty));
        check(
            &tampered(&valid, |value| {
                value["version"] = serde_json::json!(2);
                value["added_in_v2"] = serde_json::json!(true);
            }),
            SessionSyncState::UnsupportedVersion,
        );

        // A record for another location copied under this key.
        check(
            &state_for(OTHER_LOCAL, vault_id, TARGET).encode().unwrap(),
            SessionSyncState::Corrupt(CorruptReason::LocatorMismatch),
        );

        // No record, but an interrupted-write artifact.
        fs::remove_file(&record).unwrap();
        let artifact = record
            .parent()
            .unwrap()
            .join(format!("{}.{STALE_TOKEN}.tmp", record_key(&loc(&locator))));
        put_at(&artifact, b"debris");
        assert_eq!(
            session.load_sync_state(&root),
            SessionSyncState::Unreadable(UnreadableReason::UnresolvedArtifacts)
        );
        assert_eq!(fs::read(&artifact).unwrap(), b"debris");
        fs::remove_file(&artifact).unwrap();

        // A valid record that cannot be opened: unreadable, not absent.
        #[cfg(windows)]
        {
            put_at(&record, &valid.encode().unwrap());
            let guard = hold_exclusively(&record);
            let result = session.load_sync_state(&root);
            assert!(
                matches!(
                    result,
                    SessionSyncState::Unreadable(UnreadableReason::Io(_))
                ),
                "got {result:?}"
            );
            drop(guard);
            assert_eq!(bound(session.load_sync_state(&root)), valid);
        }
    }

    #[test]
    fn a_record_for_another_vault_id_is_a_mismatch_and_is_not_reset() {
        let fx = Fixture::new("b1b-wrong-id");
        let session = create_session(&fx.vault);
        let root = fx.root();
        let locator = canonical(&fx.vault);

        assert_ne!(session.data().vault_id, OTHER_VAULT_ID);
        let foreign = state_for(&locator, OTHER_VAULT_ID, TARGET);
        publish(&root, &foreign);
        let before = snapshot(&fx.scratch.root());

        assert_eq!(
            session.load_sync_state(&root),
            SessionSyncState::BindingMismatch(BindingMismatch::VaultIdentity)
        );
        assert_eq!(snapshot(&fx.scratch.root()), before);
        assert_eq!(
            fs::read(record_in(&root, &locator)).unwrap(),
            foreign.encode().unwrap()
        );
    }

    #[test]
    fn a_different_vault_created_at_a_reused_path_is_a_mismatch() {
        let fx = Fixture::new("b1b-reused-path");
        let first = create_session(&fx.vault);
        let first_id = first.data().vault_id;
        let root = fx.root();
        let locator = canonical(&fx.vault);
        let original = state_for(&locator, first_id, TARGET);
        publish(&root, &original);
        assert_eq!(bound(first.load_sync_state(&root)), original);
        first.lock();

        // The vault is deleted and a different one is created at the same path.
        fs::remove_file(&fx.vault).unwrap();
        let _ = fs::remove_file(format!("{}.backup", fx.vault.display()));
        let second = create_session(&fx.vault);
        assert_ne!(second.data().vault_id, first_id);
        assert_eq!(canonical(&fx.vault), locator);

        assert_eq!(
            second.load_sync_state(&root),
            SessionSyncState::BindingMismatch(BindingMismatch::VaultIdentity)
        );
        assert_eq!(
            fs::read(record_in(&root, &locator)).unwrap(),
            original.encode().unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn equivalent_windows_path_spellings_reach_the_same_record() {
        let fx = Fixture::new("b1b-spellings");
        let first = create_session(&fx.vault);
        let vault_id = first.data().vault_id;
        let root = fx.root();
        let locator = canonical(&fx.vault);
        let state = state_for(&locator, vault_id, TARGET);
        publish(&root, &state);
        first.lock();

        fs::create_dir_all(fx.vaults.join("sub")).unwrap();
        let vault_dir_listing = names(&fx.vaults);
        let plain = fx.vault.to_string_lossy().into_owned();

        let spellings = [
            fx.vault.clone(),
            fx.vaults.join(".").join("vault.lvault"),
            fx.vaults.join("sub").join("..").join("vault.lvault"),
            PathBuf::from(plain.to_ascii_uppercase()),
            PathBuf::from(plain.to_ascii_lowercase()),
            PathBuf::from(plain.replace('\\', "/")),
            PathBuf::from(format!(r"\\?\{plain}")),
        ];

        for spelling in spellings {
            let session = open_session(&spelling);

            assert_eq!(canonical(&spelling), locator, "{}", spelling.display());
            assert_eq!(bound(session.load_sync_state(&root)), state);
            session.lock();
        }

        assert_eq!(names(&fx.vaults), vault_dir_listing);
    }

    #[test]
    fn a_record_for_a_different_vault_path_is_not_this_sessions() {
        let fx = Fixture::new("b1b-other-path");
        let first = create_session(&fx.vault);
        let first_id = first.data().vault_id;
        let second_path = fx.vaults.join("other.lvault");
        let second = create_session(&second_path);
        let root = fx.root();
        let first_locator = canonical(&fx.vault);
        let second_locator = canonical(&second_path);
        assert_ne!(first_locator, second_locator);

        let first_state = state_for(&first_locator, first_id, TARGET);
        publish(&root, &first_state);

        // The other vault has no record of its own.
        assert_eq!(
            second.load_sync_state(&root),
            SessionSyncState::NotConfigured
        );
        assert_eq!(bound(first.load_sync_state(&root)), first_state);

        // A record for the first location copied under the second one's key is
        // a wrong local locator: rejected, never bound.
        let copied = record_in(&root, &second_locator);
        put_at(&copied, &first_state.encode().unwrap());
        assert_eq!(
            second.load_sync_state(&root),
            SessionSyncState::Corrupt(CorruptReason::LocatorMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_redirected_root_or_ancestor_fails_closed() {
        let fx = Fixture::new("b1b-reparse");
        let session = create_session(&fx.vault);
        let vault_id = session.data().vault_id;
        let locator = canonical(&fx.vault);
        let state = state_for(&locator, vault_id, TARGET);

        // Control: the genuine root loads.
        let real = fx.scratch.root().join("real-app-local");
        let real_root = SyncStateRoot::for_test(real.clone());
        publish(&real_root, &state);
        assert_eq!(bound(session.load_sync_state(&real_root)), state);
        let before = snapshot(&real);

        // 1. The root itself is a junction to a directory that holds a record.
        let link_root = fx.scratch.root().join("link-root");
        make_junction(&link_root, &real);
        let via_root = SyncStateRoot::for_test(link_root.clone());

        // 2. An ancestor of the root is a junction; the record exists behind it.
        let holder = fx.scratch.root().join("holder");
        let holder_root = SyncStateRoot::for_test(holder.join("app-local"));
        publish(&holder_root, &state);
        let link_ancestor = fx.scratch.root().join("link-ancestor");
        make_junction(&link_ancestor, &holder);
        let via_ancestor = SyncStateRoot::for_test(link_ancestor.join("app-local"));
        let holder_before = snapshot(&holder);

        // 3. The sync-state directory itself is a junction.
        let third = fx.scratch.root().join("third-app-local");
        fs::create_dir_all(&third).unwrap();
        let link_dir = third.join(SYNC_STATE_DIRECTORY);
        make_junction(&link_dir, &real.join(SYNC_STATE_DIRECTORY));
        let via_dir = SyncStateRoot::for_test(third.clone());

        for root in [&via_root, &via_ancestor, &via_dir] {
            assert_eq!(
                session.load_sync_state(root),
                SessionSyncState::Unreadable(UnreadableReason::UnexpectedObject)
            );

            // No store operation trusts or creates through the redirection.
            let store = SyncStateStore::new(root.path()).unwrap();
            assert!(store.create(&unbased(&locator)).is_err());
            assert!(store
                .replace(&state, &rebuilt(&state, checkpoint(6), None))
                .is_err());
            assert!(store.delete(&loc(&locator)).is_err());
        }

        assert_eq!(snapshot(&real), before);
        assert_eq!(snapshot(&holder), holder_before);

        fs::remove_dir(&link_root).unwrap();
        fs::remove_dir(&link_ancestor).unwrap();
        fs::remove_dir(&link_dir).unwrap();
    }

    #[test]
    fn loading_leaves_local_vault_save_and_unlock_behavior_unchanged() {
        let fx = Fixture::new("b1b-local-unchanged");
        let mut session = create_session(&fx.vault);
        let vault_id = session.data().vault_id;
        let root = fx.root();
        let locator = canonical(&fx.vault);

        let vault_bytes = fs::read(&fx.vault).unwrap();
        let listing = names(&fx.vaults);

        assert_eq!(
            session.load_sync_state(&root),
            SessionSyncState::NotConfigured
        );
        assert_eq!(fs::read(&fx.vault).unwrap(), vault_bytes);
        assert_eq!(names(&fx.vaults), listing);
        assert!(!session.is_dirty());
        assert!(!session.save().unwrap());

        // Ordinary local use continues, and a vault rewritten by this very
        // session is still this session's vault for the next load.
        session
            .create_category(
                CategoryInput {
                    name: "One".to_owned(),
                },
                B1B_NOW_MS + 1,
            )
            .unwrap();
        assert_eq!(session.data().revision, 1);
        let state = state_for(&locator, vault_id, TARGET);
        publish(&root, &state);
        assert_eq!(bound(session.load_sync_state(&root)), state);
        assert_eq!(session.data().revision, 1);

        // A sync-state failure never blocks the vault.
        put_at(&record_in(&root, &locator), b"garbage");
        assert!(matches!(
            session.load_sync_state(&root),
            SessionSyncState::Corrupt(_)
        ));
        session
            .create_category(
                CategoryInput {
                    name: "Two".to_owned(),
                },
                B1B_NOW_MS + 2,
            )
            .unwrap();
        session.lock();

        let reopened = open_session(&fx.vault);
        assert_eq!(reopened.data().vault_id, vault_id);
        assert_eq!(reopened.data().revision, 2);
        assert_eq!(reopened.data().categories.len(), 2);
    }

    #[test]
    fn a_session_whose_vault_file_is_not_the_unlocked_one_has_no_locator() {
        let fx = Fixture::new("b1b-unavailable");
        let session = create_session(&fx.vault);
        let root = fx.root();

        // Replaced by a non-cooperating writer.
        let replacement = create_envelope(B1B_PASSWORD, b"external replacement").unwrap();
        save_envelope_atomic(&fx.vault, &replacement).unwrap();
        assert_eq!(
            session.load_sync_state(&root),
            SessionSyncState::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        );

        // Deleted.
        fs::remove_file(&fx.vault).unwrap();
        assert_eq!(
            session.load_sync_state(&root),
            SessionSyncState::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        );
        assert!(!root.path().exists());

        // A vault whose name has no `.lvault` extension has no normalized
        // locator at all. It is reported, not given an invented one.
        let odd = fx.vaults.join("vault.bin");
        let odd_session = create_session(&odd);
        assert_eq!(
            odd_session.load_sync_state(&root),
            SessionSyncState::Unavailable(SyncStateUnavailable::LocalLocator)
        );
        assert!(!root.path().exists());
    }

    #[test]
    fn the_exclusive_session_lock_is_held_across_and_after_the_load() {
        // The method is `&self` on `UnlockedVaultSession`: there is no way to
        // call it without a live session, and the borrow keeps `_lock_file`
        // (the OS lock) alive for the whole call. A closed session no longer
        // exists to call it on. This checks the observable side: the lock is
        // still exclusively held afterwards and released only by dropping.
        let fx = Fixture::new("b1b-lock");
        let session = create_session(&fx.vault);
        let root = fx.root();

        assert_eq!(
            session.load_sync_state(&root),
            SessionSyncState::NotConfigured
        );
        assert!(matches!(
            UnlockedVaultSession::unlock(&fx.vault, b1b_password()),
            Err(crate::vault::session::SessionError::InUse)
        ));

        session.lock();
        assert_eq!(
            open_session(&fx.vault).load_sync_state(&root),
            SessionSyncState::NotConfigured
        );
    }

    #[test]
    fn a_retained_target_is_never_opened_or_created() {
        let fx = Fixture::new("b1b-no-remote");
        let session = create_session(&fx.vault);
        let vault_id = session.data().vault_id;
        let root = fx.root();
        let locator = canonical(&fx.vault);

        let remote = fx.scratch.root().join("remote");
        fs::create_dir_all(&remote).unwrap();
        fs::write(remote.join("sentinel.lvault"), b"remote bytes").unwrap();
        let target = remote.join("target.lvault");
        let target_text = target.to_string_lossy().into_owned();

        publish(&root, &state_for(&locator, vault_id, &target_text));
        let before = snapshot(&remote);

        let loaded = bound(session.load_sync_state(&root));

        assert_eq!(loaded.target_locator().as_str(), target_text);
        assert!(!target.exists());
        assert_eq!(snapshot(&remote), before);
        // By construction nothing in the call has a target adapter: the retained
        // target is carried as a string and compared with itself only.
    }

    #[test]
    fn outcomes_for_a_real_session_leak_no_identifier_path_or_locator() {
        let fx = Fixture::new("b1b-no-leak");
        let session = create_session(&fx.vault);
        let vault_id = session.data().vault_id;
        let root = fx.root();
        let locator = canonical(&fx.vault);
        let key = record_key(&loc(&locator));

        let mut shown = vec![format!("{root:?}")];
        shown.push(format!("{:?}", session.load_sync_state(&root)));

        publish(&root, &state_for(&locator, vault_id, TARGET));
        shown.push(format!("{:?}", session.load_sync_state(&root)));

        fs::write(record_in(&root, &locator), b"garbage").unwrap();
        shown.push(format!("{:?}", session.load_sync_state(&root)));

        fs::write(
            record_in(&root, &locator),
            state_for(&locator, OTHER_VAULT_ID, TARGET)
                .encode()
                .unwrap(),
        )
        .unwrap();
        shown.push(format!("{:?}", session.load_sync_state(&root)));

        let scratch_root = fx.scratch.root().to_string_lossy().into_owned();
        let needles = [
            vault_id.to_string(),
            vault_id.simple().to_string(),
            OTHER_VAULT_ID.to_string(),
            BINDING.to_string(),
            scratch_root,
            key,
            locator,
            "TARGET-MARKER".to_owned(),
            "vault.lvault".to_owned(),
            ".qa-local".to_owned(),
        ];

        for output in &shown {
            for needle in &needles {
                assert!(
                    !output.contains(needle.as_str()),
                    "leaks {needle:?}: {output}"
                );
            }
        }
    }

    #[test]
    fn the_app_local_root_must_be_resolved_absolute_and_is_redacted() {
        assert!(SyncStateRoot::from_resolved::<()>(Ok(PathBuf::from(
            r"C:\Users\x\AppData\Local\app"
        )))
        .is_ok());

        assert_eq!(
            SyncStateRoot::from_resolved::<()>(Err(())).unwrap_err(),
            RootError::Unavailable
        );
        for relative in ["", "app-data", r"..\app-data", r"sub\dir"] {
            assert_eq!(
                SyncStateRoot::from_resolved::<()>(Ok(PathBuf::from(relative))).unwrap_err(),
                RootError::NotAbsolute
            );
        }

        let root = SyncStateRoot::for_test(PathBuf::from(r"C:\Users\x\AppData\Local\app"));
        let shown = format!("{root:?}");
        assert!(!shown.contains("AppData") && !shown.contains("Users"));
    }

    // ---- Stage 1U-4 B1c: session-bound high-water observation ---------------------
    //
    // Real unlocked sessions over synthetic vaults. Candidate "remote" envelopes
    // are genuine envelopes of the same vault, produced by unlocking a copy of
    // the vault file and committing real writes, so their revisions are
    // authenticated counters. Not covered here (and not claimed): any remote or
    // target adapter (none exists), cross-process compare-and-swap, power-loss
    // durability, or Tauri command wiring (there is none).

    use crate::{
        app_state::{AppState, AppStateError},
        vault::session::{RemoteObservationOutcome, RemoteObservationRefusal, SessionError},
    };
    use localvault_core::{
        sync::{
            BoundInspectionError, EnvelopeInput, InspectionError, PayloadRejection,
            MAX_ENVELOPE_BYTES,
        },
        sync_state::TransitionRefusal,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    type Outcome = RemoteObservationOutcome;
    type Refusal = RemoteObservationRefusal;

    /// Genuine envelope bytes of the vault at `vault`, advanced to `revision` by
    /// real committed writes on a copy (the original is never touched).
    fn candidate_from(vault: &Path, scratch_root: &Path, name: &str, revision: u64) -> Vec<u8> {
        let dir = scratch_root.join("candidates");
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join(format!("{name}.lvault"));
        fs::copy(vault, &path).unwrap();

        let mut copy = open_session(&path);
        let mut n: i64 = 0;
        while copy.data().revision < revision {
            n += 1;
            copy.create_category(
                CategoryInput {
                    name: format!("candidate-{n}"),
                },
                B1B_NOW_MS + n,
            )
            .unwrap();
        }
        assert_eq!(copy.data().revision, revision);
        copy.lock();

        fs::read(&path).unwrap()
    }

    /// An unlocked session with a published binding. `session` is declared first
    /// so that it (and its exclusive lock file) drops before the scratch
    /// directory is removed.
    struct Observed {
        session: UnlockedVaultSession,
        root: SyncStateRoot,
        locator: String,
        vault_id: Uuid,
        state: SyncState,
        fx: Fixture,
    }

    impl Observed {
        /// Based at high-water 5 (synced revision 1), no pending push.
        fn new(name: &str) -> Self {
            Self::with(name, |locator, vault_id| {
                build(locator, vault_id, checkpoint(5), None)
            })
        }

        fn with(name: &str, make: impl FnOnce(&str, Uuid) -> SyncState) -> Self {
            let fx = Fixture::new(name);
            let session = create_session(&fx.vault);
            let vault_id = session.data().vault_id;
            let root = fx.root();
            let locator = canonical(&fx.vault);
            let state = make(&locator, vault_id);
            publish(&root, &state);

            Self {
                session,
                root,
                locator,
                vault_id,
                state,
                fx,
            }
        }

        fn record(&self) -> PathBuf {
            record_in(&self.root, &self.locator)
        }

        fn state_dir(&self) -> PathBuf {
            self.root.path().join(SYNC_STATE_DIRECTORY)
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(self.root.path()).unwrap()
        }

        fn record_bytes(&self) -> Vec<u8> {
            fs::read(self.record()).unwrap()
        }

        fn candidates_dir(&self) -> PathBuf {
            self.fx.scratch.root().join("candidates")
        }

        fn candidate(&self, name: &str, revision: u64) -> Vec<u8> {
            candidate_from(&self.fx.vault, &self.fx.scratch.root(), name, revision)
        }

        fn observe(&self, candidate: &[u8]) -> Result<Outcome, Refusal> {
            self.session
                .record_remote_observation(&self.root, &loc(TARGET), candidate)
        }

        fn observe_in(&self, store: &SyncStateStore, candidate: &[u8]) -> Result<Outcome, Refusal> {
            self.session
                .record_remote_observation_in(store, &loc(TARGET), candidate)
        }
    }

    #[test]
    fn a_higher_authenticated_revision_raises_and_retains_only_the_high_water() {
        let o = Observed::new("b1c-raised");
        let candidate = o.candidate("rev9", 9);
        let vault_before = snapshot(&o.fx.vaults);
        let candidates_before = snapshot(&o.candidates_dir());

        assert_eq!(o.observe(&candidate), Ok(Outcome::HighWaterRaised));

        let expected = rebuilt(&o.state, checkpoint(9), None);
        assert_eq!(o.record_bytes(), expected.encode().unwrap());
        assert_eq!(names(&o.state_dir()).len(), 1, "no staging file is left");

        // A fresh, independent load sees the retained mark.
        let reloaded = bound(o.session.load_sync_state(&o.root));
        assert_eq!(reloaded, expected);

        // Only the mark moved: the synchronized baseline did not.
        let (SyncBase::Based(old), SyncBase::Based(new)) = (o.state.base(), reloaded.base()) else {
            panic!("expected based states");
        };
        assert_eq!(new.high_water().revision(), 9);
        assert_eq!(new.synced(), old.synced());
        assert_eq!(new.synced_revision(), old.synced_revision());
        assert!(reloaded.pending_push().is_none());

        // No vault, backup, lock or candidate write.
        assert_eq!(snapshot(&o.fx.vaults), vault_before);
        assert_eq!(snapshot(&o.candidates_dir()), candidates_before);

        // A later, fresh operation starts from the retained value.
        assert_eq!(
            o.observe(&o.candidate("rev7", 7)),
            Err(Refusal::KnownRegression)
        );
        assert_eq!(o.observe(&candidate), Ok(Outcome::Unchanged));
        assert_eq!(o.record_bytes(), expected.encode().unwrap());
    }

    #[test]
    fn the_raised_mark_survives_closing_and_reopening_the_session() {
        let o = Observed::new("b1c-reopen");
        let candidate = o.candidate("rev9", 9);
        assert_eq!(o.observe(&candidate), Ok(Outcome::HighWaterRaised));

        let Observed {
            session, root, fx, ..
        } = o;
        session.lock();

        let reopened = open_session(&fx.vault);
        let loaded = bound(reopened.load_sync_state(&root));
        let SyncBase::Based(checkpoint) = loaded.base() else {
            panic!("expected a based state");
        };
        assert_eq!(checkpoint.high_water().revision(), 9);

        // And a new operation in the new session honours it.
        assert_eq!(
            reopened.record_remote_observation(&root, &loc(TARGET), &candidate),
            Ok(Outcome::Unchanged)
        );
    }

    #[test]
    fn an_equal_revision_is_unchanged_and_rewrites_nothing() {
        let o = Observed::new("b1c-equal");
        let candidate = o.candidate("rev5", 5);
        let before = snapshot(&o.state_dir());

        assert_eq!(o.observe(&candidate), Ok(Outcome::Unchanged));

        // Same bytes and same modification time: not even rewritten identically.
        assert_eq!(snapshot(&o.state_dir()), before);
        assert_eq!(o.record_bytes(), o.state.encode().unwrap());
    }

    #[test]
    fn a_lower_revision_is_a_known_regression_that_changes_nothing() {
        let o = Observed::new("b1c-regression");
        let candidate = o.candidate("rev3", 3);
        let before = snapshot(&o.state_dir());

        assert_eq!(o.observe(&candidate), Err(Refusal::KnownRegression));

        assert_eq!(snapshot(&o.state_dir()), before);
        assert_eq!(bound(o.session.load_sync_state(&o.root)), o.state);
    }

    #[test]
    fn a_pending_push_or_an_unbased_state_blocks_every_observation() {
        let pending = Observed::with("b1c-pending", |locator, vault_id| {
            build(locator, vault_id, checkpoint(5), Some(pending_push(6)))
        });
        let candidate = pending.candidate("rev9", 9);
        let before = snapshot(&pending.state_dir());
        assert_eq!(
            pending.observe(&candidate),
            Err(Refusal::Transition(TransitionRefusal::PendingIntentExists))
        );
        assert_eq!(snapshot(&pending.state_dir()), before);
        // The pending push is still there, untouched.
        assert!(bound(pending.session.load_sync_state(&pending.root))
            .pending_push()
            .is_some());

        let unbased = Observed::with("b1c-unbased", |locator, vault_id| {
            build(
                locator,
                vault_id,
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
        let before = snapshot(&unbased.state_dir());
        assert_eq!(
            unbased.observe(&unbased.candidate("rev9", 9)),
            Err(Refusal::Transition(TransitionRefusal::NotBased))
        );
        assert_eq!(snapshot(&unbased.state_dir()), before);
    }

    #[test]
    fn a_record_for_another_vault_is_refused_and_left_alone() {
        let o = Observed::with("b1c-wrong-vault", |locator, _| {
            build(locator, OTHER_VAULT_ID, checkpoint(5), None)
        });
        assert_ne!(o.vault_id, OTHER_VAULT_ID);
        let before = snapshot(&o.state_dir());

        assert_eq!(
            o.observe(&o.candidate("rev9", 9)),
            Err(Refusal::BindingMismatch(BindingMismatch::VaultIdentity))
        );
        assert_eq!(snapshot(&o.state_dir()), before);
    }

    #[test]
    fn only_the_retained_target_is_accepted_and_it_is_compared_exactly() {
        let o = Observed::new("b1c-target");
        let candidate = o.candidate("rev9", 9);
        let before = snapshot(&o.state_dir());

        for other in [
            OTHER_LOCAL.to_owned(),
            TARGET.to_ascii_lowercase(),
            format!("{TARGET}x"),
        ] {
            assert_eq!(
                o.session
                    .record_remote_observation(&o.root, &loc(&other), &candidate),
                Err(Refusal::BindingMismatch(BindingMismatch::TargetLocator)),
                "{other}"
            );
            assert_eq!(snapshot(&o.state_dir()), before);
        }

        // Control: the retained target itself is accepted.
        assert_eq!(o.observe(&candidate), Ok(Outcome::HighWaterRaised));
    }

    #[test]
    fn a_missing_record_is_refused_and_nothing_is_created() {
        let o = Observed::new("b1c-missing");
        let candidate = o.candidate("rev9", 9);

        // The sync-state directory exists but holds no record.
        fs::remove_file(o.record()).unwrap();
        assert_eq!(o.observe(&candidate), Err(Refusal::NotConfigured));
        assert!(names(&o.state_dir()).is_empty());

        // First use: not even the application-data root exists.
        fs::remove_dir_all(o.root.path()).unwrap();
        assert_eq!(o.observe(&candidate), Err(Refusal::NotConfigured));
        assert!(!o.root.path().exists());
    }

    #[test]
    fn corrupt_and_unsupported_records_are_refused_and_left_in_place() {
        let o = Observed::new("b1c-unusable");
        let candidate = o.candidate("rev9", 9);
        let record = o.record();

        let check = |bytes: &[u8], expected: Refusal| {
            put_at(&record, bytes);
            assert_eq!(o.observe(&candidate), Err(expected));
            assert_eq!(fs::read(&record).unwrap(), bytes);
            assert_eq!(names(&o.state_dir()).len(), 1);
        };

        check(
            b"this is not a sync state",
            Refusal::Corrupt(CorruptReason::Undecodable),
        );
        check(b"", Refusal::Corrupt(CorruptReason::Empty));
        check(
            &state_for(OTHER_LOCAL, o.vault_id, TARGET).encode().unwrap(),
            Refusal::Corrupt(CorruptReason::LocatorMismatch),
        );
        check(
            &tampered(&o.state, |value| {
                value["version"] = serde_json::json!(2);
                value["added_in_v2"] = serde_json::json!(true);
            }),
            Refusal::UnsupportedVersion,
        );
    }

    #[test]
    fn an_unreadable_state_is_refused_and_never_treated_as_absent() {
        let o = Observed::new("b1c-unreadable");
        let candidate = o.candidate("rev9", 9);

        #[cfg(windows)]
        {
            let original = o.record_bytes();
            let guard = hold_exclusively(&o.record());
            let result = o.observe(&candidate);
            assert!(
                matches!(result, Err(Refusal::Unreadable(UnreadableReason::Io(_)))),
                "got {result:?}"
            );
            drop(guard);
            assert_eq!(o.record_bytes(), original);
        }

        // An interrupted-write artifact without a record.
        let artifact = o.state_dir().join(format!(
            "{}.{STALE_TOKEN}.tmp",
            record_key(&loc(&o.locator))
        ));
        fs::remove_file(o.record()).unwrap();
        put_at(&artifact, b"debris");
        assert_eq!(
            o.observe(&candidate),
            Err(Refusal::Unreadable(UnreadableReason::UnresolvedArtifacts))
        );
        assert_eq!(fs::read(&artifact).unwrap(), b"debris");
        assert!(!o.record().exists());
    }

    #[test]
    fn a_vault_file_that_is_not_the_unlocked_one_is_refused() {
        let o = Observed::new("b1c-vault-changed");
        let candidate = o.candidate("rev9", 9);
        let before = snapshot(&o.state_dir());
        let unavailable = Err(Refusal::Unavailable(
            SyncStateUnavailable::LocalVaultChanged,
        ));

        // Replaced by a non-cooperating writer.
        let replacement = create_envelope(B1B_PASSWORD, b"external replacement").unwrap();
        save_envelope_atomic(&o.fx.vault, &replacement).unwrap();
        assert_eq!(o.observe(&candidate), unavailable);
        assert_eq!(snapshot(&o.state_dir()), before);

        // Deleted.
        fs::remove_file(&o.fx.vault).unwrap();
        assert_eq!(o.observe(&candidate), unavailable);
        assert_eq!(snapshot(&o.state_dir()), before);
    }

    #[test]
    fn a_candidate_that_does_not_authenticate_as_this_vault_is_refused() {
        let o = Observed::new("b1c-bad-candidate");
        let genuine = o.candidate("rev9", 9);
        let before = snapshot(&o.state_dir());
        let malformed = Err(Refusal::Inspection(
            BoundInspectionError::MalformedEnvelope {
                input: EnvelopeInput::Candidate,
            },
        ));
        let unauthenticated = Err(Refusal::Inspection(BoundInspectionError::Inspection(
            InspectionError::Candidate(PayloadRejection::AuthenticationFailed),
        )));

        assert_eq!(o.observe(b"{\"revision\": 99}"), malformed);
        assert_eq!(o.observe(&genuine[..genuine.len() / 2]), malformed);
        assert_eq!(
            o.observe(&vec![0u8; MAX_ENVELOPE_BYTES + 1]),
            Err(Refusal::Inspection(BoundInspectionError::InputTooLarge {
                input: EnvelopeInput::Candidate,
                actual: MAX_ENVELOPE_BYTES + 1,
                limit: MAX_ENVELOPE_BYTES,
            }))
        );

        // A genuine envelope whose ciphertext was altered: the revision inside
        // it cannot be forged without the key.
        let mut value: serde_json::Value = serde_json::from_slice(&genuine).unwrap();
        let first = value["payload"]["ciphertext"][0].as_u64().unwrap();
        value["payload"]["ciphertext"][0] = serde_json::json!((first + 1) % 256);
        assert_eq!(
            o.observe(&serde_json::to_vec(&value).unwrap()),
            unauthenticated
        );

        // Another vault, with another key.
        let foreign_path = o.fx.scratch.root().join("foreign").join("other.lvault");
        let foreign = UnlockedVaultSession::create(
            &foreign_path,
            Zeroizing::new("another-password-entirely".to_owned()),
            B1B_NOW_MS,
        )
        .unwrap();
        assert_eq!(
            o.observe(&fs::read(&foreign_path).unwrap()),
            unauthenticated
        );
        drop(foreign);

        assert_eq!(snapshot(&o.state_dir()), before);
        assert_eq!(bound(o.session.load_sync_state(&o.root)), o.state);
    }

    #[test]
    fn the_session_lock_is_held_for_the_whole_operation() {
        let o = Observed::new("b1c-lock");
        let candidate = o.candidate("rev9", 9);
        let store = o.store();

        // Probe from inside the operation, between the compare and the swap.
        let probe = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&probe);
        let vault = o.fx.vault.clone();
        run_at(&store, Point::BeforeReplace, move || {
            let attempt = UnlockedVaultSession::unlock(&vault, b1b_password());
            seen.store(
                if matches!(attempt, Err(SessionError::InUse)) {
                    1
                } else {
                    2
                },
                Ordering::SeqCst,
            );
        });

        assert_eq!(
            o.observe_in(&store, &candidate),
            Ok(Outcome::HighWaterRaised)
        );
        assert_eq!(probe.load(Ordering::SeqCst), 1, "lock was not held");

        // Still held afterwards, released only by dropping the session.
        assert!(matches!(
            UnlockedVaultSession::unlock(&o.fx.vault, b1b_password()),
            Err(SessionError::InUse)
        ));
    }

    #[test]
    fn a_failed_state_write_is_not_reported_as_success() {
        let o = Observed::new("b1c-write-fails");
        let candidate = o.candidate("rev9", 9);
        let original = o.record_bytes();

        let cases = [
            (
                Point::TempSync,
                io::ErrorKind::PermissionDenied,
                IoStage::Sync,
            ),
            (
                Point::BeforeReplace,
                io::ErrorKind::TimedOut,
                IoStage::Inspect,
            ),
        ];

        for (point, kind, stage) in cases {
            let store = o.store();
            fail_at(&store, point, kind);

            assert_eq!(
                o.observe_in(&store, &candidate),
                Err(Refusal::NotPersisted(StoreError::Io { stage, kind })),
                "{point:?}"
            );
            // The trusted record is untouched and no staging file is left.
            assert_eq!(o.record_bytes(), original, "{point:?}");
            assert_eq!(names(&o.state_dir()).len(), 1, "{point:?}");
        }

        // Nothing was lost: a fresh, unfaulted operation succeeds.
        assert_eq!(o.observe(&candidate), Ok(Outcome::HighWaterRaised));
    }

    /// Counts attempts at the publication step (the rename).
    fn count_publications(store: &SyncStateStore) -> Arc<AtomicUsize> {
        let counter = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&counter);
        run_at(store, Point::Replace, move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        counter
    }

    #[test]
    fn replace_errors_are_classified_by_whether_publication_could_have_happened() {
        use crate::vault::session::replace_error_may_follow_publication as ambiguous;

        let io = |stage| StoreError::Io {
            stage,
            kind: io::ErrorKind::Other,
        };

        // Fail before the rename: the store never replaced the record.
        for definite in [
            io(IoStage::Inspect),
            io(IoStage::Open),
            io(IoStage::Write),
            io(IoStage::Sync),
            StoreError::Missing,
            StoreError::UnexpectedObject,
            StoreError::CurrentUnreadable,
            StoreError::CurrentCorrupt,
            StoreError::CurrentUnsupportedVersion,
            StoreError::CurrentLocatorMismatch,
            StoreError::Changed,
            StoreError::LocatorMismatch,
            StoreError::BindingIdentityChanged,
            StoreError::TrustedHistoryRegression,
            StoreError::Encode(SyncStateEncodeError::TooLarge),
            StoreError::RootNotAbsolute,
        ] {
            assert!(!ambiguous(definite), "{definite:?}");
        }

        // The publication step itself, anything after it, and everything this
        // sequence does not produce (fail closed).
        for uncertain in [
            io(IoStage::Replace),
            io(IoStage::Directory),
            io(IoStage::Scan),
            StoreError::VerificationFailed,
            StoreError::AlreadyExists,
            StoreError::UnresolvedArtifacts,
            StoreError::NoClobberUnsupported,
            StoreError::IncompleteDeletion,
            // Produced only by a deletion; fails closed here.
            StoreError::RemovalRefused(RemovalRefusal::Busy),
            StoreError::RemovalRefused(RemovalRefusal::PlanChanged),
        ] {
            assert!(ambiguous(uncertain), "{uncertain:?}");
        }
    }

    #[test]
    fn a_publication_error_is_ambiguous_with_the_original_still_present_and_never_retried() {
        let o = Observed::new("b1c-publish-fails");
        let candidate = o.candidate("rev9", 9);
        let original = o.record_bytes();
        let store = o.store();

        // The rename reports failure (before the real rename runs).
        let attempts = count_publications(&store);
        fail_at(&store, Point::Replace, io::ErrorKind::PermissionDenied);

        assert_eq!(
            o.observe_in(&store, &candidate),
            Err(Refusal::PersistenceUnverified)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "no retry");

        // D: the original is what a fresh load finds, mark not changed.
        assert_eq!(o.record_bytes(), original);
        assert_eq!(bound(o.session.load_sync_state(&o.root)), o.state);
        assert_eq!(names(&o.state_dir()).len(), 1);

        // F: only a fresh operation decides, and it still raises exactly once.
        assert_eq!(o.observe(&candidate), Ok(Outcome::HighWaterRaised));
        assert_eq!(o.observe(&candidate), Ok(Outcome::Unchanged));
    }

    #[test]
    fn a_verification_failure_after_publication_leaves_the_proposed_state_and_is_not_success() {
        let o = Observed::new("b1c-verify-fails");
        let candidate = o.candidate("rev9", 9);
        let store = o.store();
        let attempts = count_publications(&store);
        fail_at(&store, Point::Verify, io::ErrorKind::Other);

        assert_eq!(
            o.observe_in(&store, &candidate),
            Err(Refusal::PersistenceUnverified)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "no retry");

        // E: the proposed state has in fact reached disk.
        let proposed = rebuilt(&o.state, checkpoint(9), None);
        assert_eq!(o.record_bytes(), proposed.encode().unwrap());

        // F: a fresh operation sees it as the current mark and writes nothing.
        let before = snapshot(&o.state_dir());
        assert_eq!(o.observe(&candidate), Ok(Outcome::Unchanged));
        assert_eq!(snapshot(&o.state_dir()), before);
        assert_eq!(
            o.observe(&o.candidate("rev7", 7)),
            Err(Refusal::KnownRegression)
        );
    }

    #[test]
    fn a_record_swapped_during_verification_is_unverified_and_the_mark_never_drops() {
        let o = Observed::new("b1c-verify-swapped");
        let candidate = o.candidate("rev9", 9);
        let store = o.store();

        // Another writer puts a different valid state (mark 12) in place after
        // the publication but before the readback.
        let other = rebuilt(&o.state, checkpoint(12), None).encode().unwrap();
        let record = o.record();
        let written = other.clone();
        run_at(&store, Point::Verify, move || {
            fs::write(&record, &written).unwrap();
        });

        assert_eq!(
            o.observe_in(&store, &candidate),
            Err(Refusal::PersistenceUnverified)
        );

        // Not reported as success, and the higher mark is not lowered to 9.
        assert_eq!(o.record_bytes(), other);
        assert_eq!(
            o.observe(&candidate),
            Err(Refusal::KnownRegression),
            "a fresh load sees the retained 12, above the candidate's 9"
        );
        assert_eq!(o.record_bytes(), other);
    }

    #[test]
    fn a_failure_before_publication_is_definite_and_publishes_nothing() {
        let o = Observed::new("b1c-pre-publication");
        let candidate = o.candidate("rev9", 9);
        let original = o.record_bytes();

        for (point, stage) in [
            (Point::TempSync, IoStage::Sync),
            (Point::BeforeReplace, IoStage::Inspect),
        ] {
            let store = o.store();
            let attempts = count_publications(&store);
            fail_at(&store, point, io::ErrorKind::PermissionDenied);

            assert_eq!(
                o.observe_in(&store, &candidate),
                Err(Refusal::NotPersisted(StoreError::Io {
                    stage,
                    kind: io::ErrorKind::PermissionDenied
                })),
                "{point:?}"
            );
            assert_eq!(attempts.load(Ordering::SeqCst), 0, "{point:?}: no rename");
            assert_eq!(o.record_bytes(), original, "{point:?}");
        }
    }

    #[test]
    fn a_failed_readback_is_not_reported_as_success_and_is_not_retried() {
        let o = Observed::new("b1c-readback-fails");
        let candidate = o.candidate("rev9", 9);
        let store = o.store();

        fail_at(&store, Point::Verify, io::ErrorKind::Other);
        let replacements = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&replacements);
        run_at(&store, Point::Replace, move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });

        assert_eq!(
            o.observe_in(&store, &candidate),
            Err(Refusal::PersistenceUnverified)
        );
        assert_eq!(replacements.load(Ordering::SeqCst), 1, "no retry");

        // The ambiguity is real: the replacement was in fact published, which
        // is exactly why only a fresh load may decide what happens next.
        let expected = rebuilt(&o.state, checkpoint(9), None);
        assert_eq!(o.record_bytes(), expected.encode().unwrap());
        assert_eq!(bound(o.session.load_sync_state(&o.root)), expected);
        assert_eq!(names(&o.state_dir()).len(), 1);
    }

    #[test]
    fn an_unexpected_concurrent_state_change_is_refused_and_not_overwritten() {
        let o = Observed::new("b1c-concurrent");
        let candidate = o.candidate("rev9", 9);
        let store = o.store();

        // Another writer changes the record while the replacement is staged.
        let concurrent = rebuilt(&o.state, checkpoint(6), None).encode().unwrap();
        let record = o.record();
        let written = concurrent.clone();
        run_at(&store, Point::TempSync, move || {
            fs::write(&record, &written).unwrap();
        });

        assert_eq!(
            o.observe_in(&store, &candidate),
            Err(Refusal::NotPersisted(StoreError::Changed))
        );
        assert_eq!(o.record_bytes(), concurrent);
        assert_eq!(names(&o.state_dir()).len(), 1);
    }

    #[test]
    fn no_outcome_writes_the_vault_its_backup_or_a_candidate() {
        let o = Observed::new("b1c-no-other-writes");
        let low = o.candidate("rev3", 3);
        let same = o.candidate("rev5", 5);
        let high = o.candidate("rev8", 8);
        let vault_before = snapshot(&o.fx.vaults);
        let candidates_before = snapshot(&o.candidates_dir());
        let backup = PathBuf::from(format!("{}.backup", o.fx.vault.display()));
        assert!(!backup.exists());

        assert_eq!(o.observe(&low), Err(Refusal::KnownRegression));
        assert_eq!(o.observe(&same), Ok(Outcome::Unchanged));
        assert_eq!(o.observe(&high), Ok(Outcome::HighWaterRaised));
        // The mark is monotone: the previously acceptable values are now
        // behind it, and nothing resets the binding.
        assert_eq!(o.observe(&same), Err(Refusal::KnownRegression));
        assert_eq!(o.observe(&high), Ok(Outcome::Unchanged));
        assert!(o.observe(b"garbage").is_err());

        assert_eq!(snapshot(&o.fx.vaults), vault_before);
        assert_eq!(snapshot(&o.candidates_dir()), candidates_before);
        assert!(!backup.exists());
        assert!(!o.session.is_dirty());

        // The binding is intact: same identity, checkpoint kept, mark at 8.
        assert_eq!(
            bound(o.session.load_sync_state(&o.root)),
            rebuilt(&o.state, checkpoint(8), None)
        );
    }

    #[test]
    fn local_vault_use_is_unaffected_before_and_after_a_recorded_observation() {
        let o = Observed::new("b1c-local-use");
        let candidate = o.candidate("rev9", 9);
        assert_eq!(o.observe(&candidate), Ok(Outcome::HighWaterRaised));

        let Observed {
            mut session,
            root,
            fx,
            ..
        } = o;

        // Ordinary local writes continue, and the next observation reads the
        // vault file as this session just rewrote it (its current bytes), not a
        // stale or re-serialized copy.
        session
            .create_category(
                CategoryInput {
                    name: "Local".to_owned(),
                },
                B1B_NOW_MS + 100,
            )
            .unwrap();
        assert_eq!(session.data().revision, 1);
        let later = candidate_from(&fx.vault, &fx.scratch.root(), "rev12", 12);
        assert_eq!(
            session.record_remote_observation(&root, &loc(TARGET), &later),
            Ok(Outcome::HighWaterRaised)
        );

        session.lock();

        let reopened = open_session(&fx.vault);
        assert_eq!(reopened.data().revision, 1);
        assert_eq!(reopened.data().categories.len(), 1);
        let loaded = bound(reopened.load_sync_state(&root));
        let SyncBase::Based(checkpoint) = loaded.base() else {
            panic!("expected a based state");
        };
        assert_eq!(checkpoint.high_water().revision(), 12);
    }

    #[test]
    fn the_application_state_needs_a_live_session_and_changes_only_the_record() {
        let fx = Fixture::new("b1c-appstate");
        let first = create_session(&fx.vault);
        let vault_id = first.data().vault_id;
        let root = fx.root();
        let locator = canonical(&fx.vault);
        let original = build(&locator, vault_id, checkpoint(5), None);
        publish(&root, &original);
        first.lock();

        let candidate = candidate_from(&fx.vault, &fx.scratch.root(), "rev9", 9);
        let vault_bytes = fs::read(&fx.vault).unwrap();
        let target = loc(TARGET);

        let app = AppState::default();
        assert!(matches!(
            app.record_remote_observation(&root, &target, &candidate),
            Err(AppStateError::VaultLocked)
        ));
        assert_eq!(
            fs::read(record_in(&root, &locator)).unwrap(),
            original.encode().unwrap()
        );

        app.unlock_vault(fx.vault.clone(), b1b_password()).unwrap();
        assert_eq!(
            app.record_remote_observation(&root, &target, &candidate)
                .unwrap(),
            Ok(Outcome::HighWaterRaised)
        );
        match app.load_sync_state(&root).unwrap() {
            SessionSyncState::Bound(bound) => {
                assert_eq!(bound.state(), &rebuilt(&original, checkpoint(9), None))
            }
            other => panic!("expected a bound state, got {other:?}"),
        }
        assert_eq!(fs::read(&fx.vault).unwrap(), vault_bytes);

        app.lock_vault().unwrap();
        assert!(matches!(
            app.record_remote_observation(&root, &target, &candidate),
            Err(AppStateError::VaultLocked)
        ));
    }

    #[test]
    fn outcomes_and_errors_reveal_no_identifier_path_locator_or_fingerprint() {
        let o = Observed::new("b1c-no-leak");
        let down = o.candidate("rev3", 3);
        let up = o.candidate("rev9", 9);
        let higher = o.candidate("rev12", 12);

        let mut shown: Vec<String> = Vec::new();
        let mut note = |result: Result<Outcome, Refusal>| {
            shown.push(format!("{result:?}"));
            if let Err(error) = result {
                shown.push(error.to_string());
            }
        };

        note(o.observe(&down));
        note(o.observe(&up));
        note(o.observe(&up));
        note(o.observe(b"garbage"));
        note(
            o.session
                .record_remote_observation(&o.root, &loc(OTHER_LOCAL), &up),
        );

        let faulted = o.store();
        fail_at(&faulted, Point::Replace, io::ErrorKind::PermissionDenied);
        note(o.observe_in(&faulted, &higher));

        let unverified = o.store();
        fail_at(&unverified, Point::Verify, io::ErrorKind::Other);
        note(o.observe_in(&unverified, &higher));

        fs::write(o.record(), b"garbage").unwrap();
        note(o.observe(&up));

        let fingerprint = |bytes: &[u8]| EnvelopeFingerprint::of_bytes(bytes).to_hex();
        let needles = [
            o.vault_id.to_string(),
            o.vault_id.simple().to_string(),
            OTHER_VAULT_ID.to_string(),
            BINDING.to_string(),
            o.fx.scratch.root().to_string_lossy().into_owned(),
            record_key(&loc(&o.locator)),
            o.locator.clone(),
            "TARGET-MARKER".to_owned(),
            "OTHER-MARKER".to_owned(),
            "vault.lvault".to_owned(),
            ".qa-local".to_owned(),
            B1B_PASSWORD.to_owned(),
            fingerprint(&down),
            fingerprint(&up),
            fingerprint(&higher),
            fingerprint(&fs::read(&o.fx.vault).unwrap()),
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

    // ---- Stage 1U-4 B1f: persistence failures of the initial binding ------------
    //
    // The initial-binding operation
    // (`UnlockedVaultSession::bind_existing_identical_target`) is exercised end to
    // end over a real unlocked session, a real identical target file and a real
    // store; the store's private fault hooks are the only way to reach the
    // failure classes below. The success path and every refusal that needs no
    // fault are tested next to the session.
    //
    // Not covered here (and not claimed): the branch where publication and the
    // store's own readback succeed but the operation's *fresh reload* then
    // disagrees (no hook exists after the store's verification), and real
    // power-loss or provider behavior.

    use crate::vault::{
        session::{InitialBindingApproval, InitialBindingOutcome, InitialBindingRefusal},
        sync_file_adapter::SyncFileTarget,
    };

    struct Initial {
        session: UnlockedVaultSession,
        root: SyncStateRoot,
        target: SyncFileTarget,
        locator: String,
        fx: Fixture,
    }

    impl Initial {
        fn new(name: &str) -> Self {
            let fx = Fixture::new(name);
            let session = create_session(&fx.vault);
            let remote_dir = fx.scratch.root().join("remote");

            fs::create_dir_all(&remote_dir).unwrap();

            let remote = remote_dir.join("target.lvault");

            fs::copy(&fx.vault, &remote).unwrap();

            let target = SyncFileTarget::from_path(&remote).unwrap();
            let root = fx.root();
            let locator = canonical(&fx.vault);

            Self {
                session,
                root,
                target,
                locator,
                fx,
            }
        }

        fn state_dir(&self) -> PathBuf {
            self.root.path().join(SYNC_STATE_DIRECTORY)
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(self.root.path()).unwrap()
        }

        fn record(&self) -> PathBuf {
            self.state_dir()
                .join(format!("{}.json", record_key(&loc(&self.locator))))
        }

        /// Bind through `store`, counting how many times the target was read.
        fn bind_in(
            &self,
            store: &SyncStateStore,
        ) -> (Result<InitialBindingOutcome, InitialBindingRefusal>, usize) {
            let reads = AtomicUsize::new(0);

            let result = self.session.bind_existing_identical_target_in(
                store,
                &self.target,
                InitialBindingApproval::for_test(&self.target),
                &mut |target| {
                    reads.fetch_add(1, Ordering::SeqCst);

                    target.read()
                },
                &mut |buffer| getrandom::fill(buffer).is_ok(),
            );

            (result, reads.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn a_failure_before_publication_is_definite_and_leaves_no_record() {
        let i = Initial::new("b1f-store-before");
        let faulted = i.store();

        fail_at(&faulted, Point::TempSync, io::ErrorKind::PermissionDenied);

        let (result, reads) = i.bind_in(&faulted);

        assert_eq!(
            result,
            Err(InitialBindingRefusal::NotPersisted(StoreError::Io {
                stage: IoStage::Sync,
                kind: io::ErrorKind::PermissionDenied,
            }))
        );
        // Both reads of the target happened, and nothing was retried.
        assert_eq!(reads, 2);

        // Not published, and the staging file was removed: no record, no
        // artifact, and the store reports a confirmed absence, not a fault.
        assert!(!i.record().exists());
        assert!(names(&i.state_dir()).is_empty());
        assert_eq!(i.store().load(&loc(&i.locator)), StateLoad::NotConfigured);
        assert_eq!(
            i.session.load_sync_state(&i.root),
            SessionSyncState::NotConfigured
        );

        // The target and the vault are untouched, and a later, separate, fresh
        // operation is free to bind: nothing was left in the way.
        assert_eq!(
            fs::read(&i.fx.vault).unwrap(),
            fs::read(i.target.locator().as_str()).unwrap()
        );
        assert_eq!(
            i.bind_in(&i.store()).0,
            Ok(InitialBindingOutcome::BoundAndVerified)
        );
    }

    #[test]
    fn a_failure_of_the_publication_step_is_ambiguous_and_nothing_is_cleaned_up() {
        let i = Initial::new("b1f-store-publish");
        let faulted = i.store();

        // The store reports a failed link only as such (`IoStage::Replace`); it
        // cannot show that nothing was published, so the operation must not
        // claim it. Here nothing was in fact published.
        fail_at(&faulted, Point::Publish, io::ErrorKind::PermissionDenied);

        let (result, reads) = i.bind_in(&faulted);

        assert_eq!(result, Err(InitialBindingRefusal::PersistenceUnverified));
        assert_eq!(reads, 2);

        // No rollback, deletion or reset was attempted on anything.
        assert!(!i.record().exists());
        assert_eq!(i.store().load(&loc(&i.locator)), StateLoad::NotConfigured);
    }

    #[test]
    fn a_verification_failure_after_publication_is_ambiguous_and_never_undone() {
        let i = Initial::new("b1f-store-verify");
        let faulted = i.store();

        fail_at(&faulted, Point::Verify, io::ErrorKind::Other);

        let (result, reads) = i.bind_in(&faulted);

        assert_eq!(result, Err(InitialBindingRefusal::PersistenceUnverified));
        assert_eq!(reads, 2, "the operation retried");

        // The record was published and is **not** deleted, rolled back or
        // downgraded: a fresh load finds a valid binding for this vault, both
        // locators and a checkpoint.
        assert!(i.record().exists());

        let published = SyncState::decode(&fs::read(i.record()).unwrap()).unwrap();
        let SessionSyncState::Bound(bound) = i.session.load_sync_state(&i.root) else {
            panic!("the published record is not loadable");
        };

        assert_eq!(*bound.state(), published);
        assert_eq!(published.local_locator().as_str(), i.locator);
        assert_eq!(published.target_locator(), i.target.locator());
        assert!(matches!(published.base(), SyncBase::Based(_)));
        assert_eq!(names(&i.state_dir()).len(), 1, "no staging file is left");

        // A later operation, as the caller must do after an ambiguous result,
        // starts from a fresh load: it sees the binding and replaces nothing.
        let before = fs::read(i.record()).unwrap();

        assert_eq!(
            i.bind_in(&i.store()).0,
            Err(InitialBindingRefusal::ExistingBinding)
        );
        assert_eq!(fs::read(i.record()).unwrap(), before);
    }

    #[test]
    fn a_record_that_cannot_be_verified_is_left_exactly_as_found() {
        let i = Initial::new("b1f-store-damaged");
        let faulted = i.store();
        let record = i.record();

        // Something replaces the freshly published record before it is read
        // back.
        run_at(&faulted, Point::Verify, {
            let record = record.clone();

            move || fs::write(&record, b"damaged by someone else").unwrap()
        });

        let (result, reads) = i.bind_in(&faulted);

        assert_eq!(result, Err(InitialBindingRefusal::PersistenceUnverified));
        assert_eq!(reads, 2);

        // Not deleted, not repaired, not reset, and not reported as absent.
        assert_eq!(fs::read(&record).unwrap(), b"damaged by someone else");
        assert_eq!(
            i.store().load(&loc(&i.locator)),
            StateLoad::Corrupt(CorruptReason::Undecodable)
        );
        assert_eq!(names(&i.state_dir()).len(), 1);

        // And it blocks, rather than permits, a new binding.
        assert_eq!(
            i.bind_in(&i.store()).0,
            Err(InitialBindingRefusal::Corrupt(CorruptReason::Undecodable))
        );
        assert_eq!(fs::read(&record).unwrap(), b"damaged by someone else");
    }

    #[test]
    fn a_record_created_at_the_instant_of_publication_is_never_clobbered() {
        let i = Initial::new("b1f-store-race");
        let faulted = i.store();
        let planted = build(&i.locator, VAULT_ID, checkpoint(5), None)
            .encode()
            .unwrap();

        // After the store's own existence check, immediately before the
        // no-clobber link, another writer publishes a record.
        run_at(&faulted, Point::Publish, {
            let record = i.record();
            let planted = planted.clone();

            move || fs::write(&record, &planted).unwrap()
        });

        let (result, reads) = i.bind_in(&faulted);

        assert_eq!(result, Err(InitialBindingRefusal::RecordAppeared));
        assert_eq!(reads, 2);

        // The other record is intact, and our staging file is gone.
        assert_eq!(fs::read(i.record()).unwrap(), planted);
        assert_eq!(names(&i.state_dir()).len(), 1);
    }
}

/// Stage 1U-4 B3c-3a tests for the raw, crypto-agnostic [`SyncStateStore::read_record`].
/// Synthetic bytes only; every test owns a uniquely named scratch directory under
/// the git-ignored `<repo>/.qa-local/sync-state-b3c3a-tests/` (never `%TEMP%`) and
/// removes only that directory. Nothing here decodes with a MAC or writes through
/// the store: the fixtures are plain files, as an interrupted write or another
/// process would leave them.
#[cfg(all(test, windows))]
mod read_record_tests {
    use std::{fs, path::PathBuf};

    use localvault_core::{
        sync::{PushBaseline, PushIntent},
        sync_state::{BindingId, PendingPush, VaultBindingTag, BINDING_SALT_LEN},
    };

    use super::*;
    use crate::vault::handle_ops::test_support::{make_junction, snapshot};

    const LOCAL: &str = r"\\?\C:\Synthetic\Vaults\LOCAL-MARKER.lvault";
    const OTHER_LOCAL: &str = r"\\?\C:\Synthetic\Vaults\OTHER-MARKER.lvault";
    const TARGET: &str = r"\\?\D:\Synthetic\Remote\TARGET-MARKER.lvault";
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const V3_SHAPED: &[u8] =
        br#"{"format":"localvault-sync-state","version":3,"body":"x","mac":"00"}"#;

    struct Scratch {
        dir: tempfile::TempDir,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(".qa-local")
                .join("sync-state-b3c3a-tests");
            fs::create_dir_all(&base).unwrap();

            let dir = tempfile::Builder::new()
                .prefix(&format!("{name}-"))
                .tempdir_in(&base)
                .unwrap();

            assert!(!dir.path().starts_with(std::env::temp_dir()));

            Self { dir }
        }

        fn root(&self) -> PathBuf {
            self.dir.path().to_path_buf()
        }

        fn state_dir(&self) -> PathBuf {
            self.root().join(SYNC_STATE_DIRECTORY)
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(&self.root()).unwrap()
        }

        fn record(&self, local: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.json", record_key(&loc(local))))
        }

        fn artifact(&self, local: &str, token: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.{token}.tmp", record_key(&loc(local))))
        }

        fn put(&self, path: &Path, bytes: &[u8]) {
            fs::create_dir_all(self.state_dir()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    fn loc(value: &str) -> Locator {
        Locator::new(value).unwrap()
    }

    fn state(local: &str) -> SyncState {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
        let intent =
            PushIntent::new(PushBaseline::Absent, EnvelopeFingerprint::of_bytes(&[2])).unwrap();
        let intent_id = Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee);

        SyncState::new(
            BindingId::new(Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555)).unwrap(),
            VaultBindingTag::derive(
                salt,
                Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            )
            .unwrap(),
            loc(local),
            loc(TARGET),
            SyncBase::Unbased,
            Some(PendingPush::new(intent_id, intent, 1).unwrap()),
        )
        .unwrap()
    }

    /// The bytes and artifact indicator of `read`, which must be a present record.
    fn bytes_of(read: RecordRead) -> (Vec<u8>, ArtifactPresence) {
        match read {
            RecordRead::Present(record) => (record.bytes().to_vec(), record.artifacts()),
            other => panic!("expected a present record, got {other:?}"),
        }
    }

    // ---- every variant -----------------------------------------------------------

    #[test]
    fn a_missing_directory_and_an_empty_directory_are_not_configured() {
        let scratch = Scratch::new("rr-absent");
        let store = scratch.store();

        assert!(matches!(
            store.read_record(&loc(LOCAL)),
            RecordRead::NotConfigured
        ));
        // Reading created nothing.
        assert!(!scratch.state_dir().exists());

        fs::create_dir_all(scratch.state_dir()).unwrap();
        assert!(matches!(
            store.read_record(&loc(LOCAL)),
            RecordRead::NotConfigured
        ));
    }

    #[test]
    fn a_staging_artifact_without_a_primary_is_unresolved() {
        let scratch = Scratch::new("rr-temp-only");

        scratch.put(&scratch.artifact(LOCAL, TOKEN), b"leftover");

        assert!(matches!(
            scratch.store().read_record(&loc(LOCAL)),
            RecordRead::Unreadable(UnreadableReason::UnresolvedArtifacts)
        ));
    }

    #[test]
    fn empty_and_oversized_records_are_reported_not_returned() {
        let scratch = Scratch::new("rr-sizes");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), b"");
        assert!(matches!(
            store.read_record(&loc(LOCAL)),
            RecordRead::Corrupt(CorruptReason::Empty)
        ));

        scratch.put(
            &scratch.record(LOCAL),
            &vec![b'a'; MAX_SYNC_STATE_BYTES + 1],
        );
        assert!(matches!(
            store.read_record(&loc(LOCAL)),
            RecordRead::Corrupt(CorruptReason::TooLarge)
        ));

        // Exactly the limit is still returned, in full.
        let exact = vec![b'a'; MAX_SYNC_STATE_BYTES];
        scratch.put(&scratch.record(LOCAL), &exact);
        assert_eq!(bytes_of(store.read_record(&loc(LOCAL))).0, exact);
    }

    #[test]
    fn a_primary_is_returned_as_the_exact_bytes_without_being_decoded() {
        let scratch = Scratch::new("rr-raw");
        let store = scratch.store();

        let v1 = state(LOCAL).encode().unwrap();
        let v2 = state(LOCAL).encode_exchange_record().unwrap();

        for bytes in [
            v1.as_slice(),
            v2.as_slice(),
            V3_SHAPED,
            b"not a record at all".as_slice(),
            &[0xff, 0xfe, 0x00, 0x01],
        ] {
            scratch.put(&scratch.record(LOCAL), bytes);

            let (read, artifacts) = bytes_of(store.read_record(&loc(LOCAL)));

            assert_eq!(read, bytes);
            assert_eq!(artifacts, ArtifactPresence::None);
        }
    }

    #[test]
    fn artifact_presence_is_none_present_or_unknown_and_never_adopted() {
        let scratch = Scratch::new("rr-artifacts");
        let store = scratch.store();
        let primary = state(LOCAL).encode().unwrap();

        scratch.put(&scratch.record(LOCAL), &primary);

        // Files that belong to another location are not this record's artifacts.
        scratch.put(&scratch.artifact(OTHER_LOCAL, TOKEN), b"other");
        assert_eq!(
            bytes_of(store.read_record(&loc(LOCAL))).1,
            ArtifactPresence::None
        );

        // B3c-3b-2a (U2): a file that merely shares THIS record's key prefix is
        // not a recognized artifact either, but it is no longer ignored: the
        // primary is still returned, and the indicator is truthful (`Present`).
        let stray = scratch
            .state_dir()
            .join(format!("{}.not-a-token.tmp", record_key(&loc(LOCAL))));
        scratch.put(&stray, b"unrelated");
        let (read, artifacts) = bytes_of(store.read_record(&loc(LOCAL)));
        assert_eq!(read, primary);
        assert_eq!(artifacts, ArtifactPresence::Present);
        fs::remove_file(&stray).unwrap();
        assert_eq!(
            bytes_of(store.read_record(&loc(LOCAL))).1,
            ArtifactPresence::None
        );

        // A candidate beside the primary is reported, never read in its place.
        let candidate = state(LOCAL).encode_exchange_record().unwrap();
        scratch.put(&scratch.artifact(LOCAL, TOKEN), &candidate);

        let (read, artifacts) = bytes_of(store.read_record(&loc(LOCAL)));
        assert_eq!(read, primary);
        assert_ne!(read, candidate);
        assert_eq!(artifacts, ArtifactPresence::Present);
    }

    #[test]
    fn an_artifact_scan_that_cannot_finish_is_unknown_and_does_not_fail_the_read() {
        let scratch = Scratch::new("rr-unknown");
        let store = scratch.store();
        let primary = state(LOCAL).encode().unwrap();

        scratch.put(&scratch.record(LOCAL), &primary);

        // More entries than the scan will visit.
        for index in 0..=MAX_SCANNED_ENTRIES {
            fs::write(
                scratch.state_dir().join(format!("unrelated-{index}.dat")),
                b"x",
            )
            .unwrap();
        }

        let (read, artifacts) = bytes_of(store.read_record(&loc(LOCAL)));

        assert_eq!(read, primary);
        assert_eq!(artifacts, ArtifactPresence::Unknown);

        // The same overflow with no primary is an unreadable directory, never
        // absence.
        fs::remove_file(scratch.record(LOCAL)).unwrap();
        assert!(matches!(
            store.read_record(&loc(LOCAL)),
            RecordRead::Unreadable(UnreadableReason::EntryLimit)
        ));
    }

    // ---- unsafe objects ----------------------------------------------------------

    #[test]
    fn a_directory_or_junction_where_a_record_belongs_is_an_unexpected_object() {
        let scratch = Scratch::new("rr-objects");
        let store = scratch.store();
        let record = scratch.record(LOCAL);

        fs::create_dir_all(&record).unwrap();
        assert!(matches!(
            store.read_record(&loc(LOCAL)),
            RecordRead::Unreadable(UnreadableReason::UnexpectedObject)
        ));
        fs::remove_dir(&record).unwrap();

        let behind = scratch.root().join("behind");
        fs::create_dir_all(&behind).unwrap();
        make_junction(&record, &behind);
        assert!(matches!(
            store.read_record(&loc(LOCAL)),
            RecordRead::Unreadable(UnreadableReason::UnexpectedObject)
        ));
    }

    #[test]
    fn a_junction_for_the_state_directory_or_an_ancestor_is_never_followed() {
        let scratch = Scratch::new("rr-junctions");
        let bytes = state(LOCAL).encode().unwrap();

        // The state directory itself.
        let moved = scratch.root().join("moved");
        fs::create_dir_all(&moved).unwrap();
        fs::write(
            moved.join(scratch.record(LOCAL).file_name().unwrap()),
            &bytes,
        )
        .unwrap();
        make_junction(&scratch.state_dir(), &moved);
        assert!(matches!(
            scratch.store().read_record(&loc(LOCAL)),
            RecordRead::Unreadable(UnreadableReason::UnexpectedObject)
        ));

        // An ancestor of the root.
        let real = scratch.root().join("real");
        let link = scratch.root().join("link");
        fs::create_dir_all(real.join("app-local").join(SYNC_STATE_DIRECTORY)).unwrap();
        make_junction(&link, &real);

        let through = SyncStateStore::new(&link.join("app-local")).unwrap();
        assert!(matches!(
            through.read_record(&loc(LOCAL)),
            RecordRead::Unreadable(UnreadableReason::UnexpectedObject)
        ));
    }

    // ---- agreement with load, read-only, redaction ---------------------------------

    fn agrees(read: &RecordRead, load: &StateLoad) -> bool {
        match (read, load) {
            (RecordRead::NotConfigured, StateLoad::NotConfigured) => true,
            (RecordRead::Unreadable(left), StateLoad::Unreadable(right)) => left == right,
            (RecordRead::Corrupt(left), StateLoad::Corrupt(right)) => {
                left == right && matches!(left, CorruptReason::Empty | CorruptReason::TooLarge)
            }
            (
                RecordRead::Present(_),
                StateLoad::Loaded(_)
                | StateLoad::UnsupportedVersion
                | StateLoad::Corrupt(CorruptReason::Undecodable | CorruptReason::LocatorMismatch),
            ) => true,
            _ => false,
        }
    }

    fn damaged_v1_checksum() -> Vec<u8> {
        let mut bytes = state(LOCAL).encode().unwrap();
        let marker = "\"body_sha256\":\"";
        let text = String::from_utf8(bytes.clone()).unwrap();
        let at = text.find(marker).unwrap() + marker.len();

        bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
        bytes
    }

    #[test]
    fn read_record_agrees_with_load_for_every_fixture_and_changes_nothing() {
        type Setup = fn(&Scratch);

        fn record(scratch: &Scratch, bytes: &[u8]) {
            scratch.put(&scratch.record(LOCAL), bytes);
        }

        let fixtures: [(&str, Setup); 13] = [
            ("no directory", |_| {}),
            ("empty directory", |s| {
                fs::create_dir_all(s.state_dir()).unwrap();
            }),
            ("temp only", |s| s.put(&s.artifact(LOCAL, TOKEN), b"x")),
            ("empty record", |s| record(s, b"")),
            ("oversized record", |s| {
                record(s, &vec![b'a'; MAX_SYNC_STATE_BYTES + 1]);
            }),
            ("junk", |s| record(s, b"junk")),
            ("version 1", |s| record(s, &state(LOCAL).encode().unwrap())),
            ("version 1, other location", |s| {
                record(s, &state(OTHER_LOCAL).encode().unwrap());
            }),
            ("version 1, damaged checksum", |s| {
                record(s, &damaged_v1_checksum());
            }),
            ("version 2", |s| {
                record(s, &state(LOCAL).encode_exchange_record().unwrap());
            }),
            ("version 3 shaped", |s| record(s, V3_SHAPED)),
            ("version 4", |s| {
                record(s, br#"{"format":"localvault-sync-state","version":4}"#);
            }),
            ("record is a directory", |s| {
                fs::create_dir_all(s.record(LOCAL)).unwrap();
            }),
        ];

        for (label, setup) in fixtures {
            let scratch = Scratch::new("rr-agree");
            setup(&scratch);

            let store = scratch.store();
            let before = snapshot(scratch.dir.path());

            let read = store.read_record(&loc(LOCAL));
            let load = store.load(&loc(LOCAL));

            assert!(agrees(&read, &load), "{label}: {read:?} vs {load:?}");
            assert_eq!(
                snapshot(scratch.dir.path()),
                before,
                "{label}: the read changed the filesystem"
            );

            if let RecordRead::Present(present) = &read {
                assert_eq!(present.bytes(), fs::read(scratch.record(LOCAL)).unwrap());
            }
        }
    }

    #[test]
    fn a_case_variant_locator_reads_the_same_record() {
        let scratch = Scratch::new("rr-case");
        let bytes = state(LOCAL).encode().unwrap();

        scratch.put(&scratch.record(LOCAL), &bytes);

        let shouting = loc(&LOCAL.to_ascii_uppercase());
        assert_ne!(shouting, loc(LOCAL));
        assert_eq!(bytes_of(scratch.store().read_record(&shouting)).0, bytes);
    }

    #[test]
    fn the_debug_output_of_a_read_reveals_nothing() {
        let scratch = Scratch::new("rr-debug");
        let bytes = state(LOCAL).encode().unwrap();

        scratch.put(&scratch.record(LOCAL), &bytes);

        let read = scratch.store().read_record(&loc(LOCAL));
        let RecordRead::Present(present) = &read else {
            panic!("expected a present record");
        };

        let rendered = [
            format!("{read:?}"),
            format!("{present:?}"),
            format!("{:?}", ArtifactPresence::Present),
            format!("{:?}", RecordRead::NotConfigured),
            format!("{:?}", RecordRead::Corrupt(CorruptReason::Empty)),
            format!(
                "{:?}",
                RecordRead::Unreadable(UnreadableReason::Io(io::ErrorKind::PermissionDenied))
            ),
        ];

        assert_eq!(rendered[0], "Present(<redacted>)");
        assert_eq!(rendered[1], "PresentRecord(<redacted>)");

        let text = String::from_utf8(bytes).unwrap();
        for output in &rendered {
            assert!(!output.contains("localvault-sync-state"));
            assert!(!output.contains(&text[..16]));
            assert!(!output.contains("MARKER"));
            assert!(!output.contains(&record_key(&loc(LOCAL))));
        }
    }
}

// ---- B3c-3b-1 test support (begin) -------------------------------------------

/// Shared scaffolding for the Stage 1U-4 B3c-3b-1 tests. Synthetic bytes only.
/// Every test owns a uniquely named scratch directory under the git-ignored
/// `<repo>/.qa-local/sync-state-b3c3b1-tests/` (never `%TEMP%`) and removes only
/// that directory.
#[cfg(all(test, windows))]
mod b3c3b1_support {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use localvault_core::{
        sync::{EnvelopeFingerprint, PushBaseline, PushIntent},
        sync_state::{
            BindingId, Locator, PendingPush, SyncBase, SyncState, VaultBindingTag, BINDING_SALT_LEN,
        },
    };
    use uuid::Uuid;

    use super::{record_key, SyncStateStore, SYNC_STATE_DIRECTORY};

    pub(super) const LOCAL: &str = r"\\?\C:\Synthetic\Vaults\LOCAL-MARKER.lvault";
    pub(super) const OTHER_LOCAL: &str = r"\\?\C:\Synthetic\Vaults\OTHER-MARKER.lvault";
    pub(super) const TARGET: &str = r"\\?\D:\Synthetic\Remote\TARGET-MARKER.lvault";
    pub(super) const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    pub(super) const RETIRED_TOKEN: &str = "fedcba9876543210fedcba9876543210";

    pub(super) struct Scratch {
        pub(super) dir: tempfile::TempDir,
    }

    impl Scratch {
        pub(super) fn new(name: &str) -> Self {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(".qa-local")
                .join("sync-state-b3c3b1-tests");
            fs::create_dir_all(&base).unwrap();

            let dir = tempfile::Builder::new()
                .prefix(&format!("{name}-"))
                .tempdir_in(&base)
                .unwrap();

            assert!(!dir.path().starts_with(std::env::temp_dir()));

            Self { dir }
        }

        pub(super) fn root(&self) -> PathBuf {
            self.dir.path().to_path_buf()
        }

        pub(super) fn state_dir(&self) -> PathBuf {
            self.root().join(SYNC_STATE_DIRECTORY)
        }

        pub(super) fn store(&self) -> SyncStateStore {
            SyncStateStore::new(&self.root()).unwrap()
        }

        pub(super) fn record(&self, local: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.json", record_key(&loc(local))))
        }

        pub(super) fn staging(&self, local: &str, token: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.{token}.tmp", record_key(&loc(local))))
        }

        pub(super) fn retired(&self, local: &str, token: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.{token}.retired", record_key(&loc(local))))
        }

        pub(super) fn put(&self, path: &Path, bytes: &[u8]) {
            fs::create_dir_all(self.state_dir()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    pub(super) fn loc(value: &str) -> Locator {
        Locator::new(value).unwrap()
    }

    pub(super) fn state(local: &str) -> SyncState {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
        let intent =
            PushIntent::new(PushBaseline::Absent, EnvelopeFingerprint::of_bytes(&[2])).unwrap();
        let intent_id = Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee);

        SyncState::new(
            BindingId::new(Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555)).unwrap(),
            VaultBindingTag::derive(
                salt,
                Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            )
            .unwrap(),
            loc(local),
            loc(TARGET),
            SyncBase::Unbased,
            Some(PendingPush::new(intent_id, intent, 1).unwrap()),
        )
        .unwrap()
    }

    /// Sorted names of the direct children of `dir`.
    pub(super) fn names(dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        found.sort();
        found
    }
}

// ---- B3c-3b-1 test support (end) ---------------------------------------------

// ---- B3c-3b-1 v1 non-regression tests (begin) --------------------------------

/// Stage 1U-4 B3c-3b-1 pinned the legacy (v1) store as **blind** to
/// `<key>.<32hex>.retired` files. Stage 1U-4 B3c-3b-2a ends that blindness with a
/// refuse-only compatibility gate, so these tests now pin the opposite, for the
/// same three synthetic layouts and the same operations: every legacy operation
/// refuses (nothing is created, replaced or removed), the tree does not move by a
/// byte, and a retired file is never removed or changed by any operation, whatever
/// it contains. A retired file of ANOTHER location blocks only that location.
///
/// Originally `v1_retired_tests`; renamed because "v1 retired" is no longer true.
#[cfg(all(test, windows))]
mod legacy_gate_retired_tests {
    use std::fs;

    use super::b3c3b1_support::{
        loc, names, state, Scratch, LOCAL, OTHER_LOCAL, RETIRED_TOKEN, TOKEN,
    };
    use super::b3c3b2a_support::{empty_evidence, proposed_state};
    use super::*;
    use crate::vault::handle_ops::test_support::snapshot;

    const RETIRED_BYTES: &[u8] = b"synthetic retired record, never read by v1";

    #[derive(Clone, Copy, Debug)]
    enum Layout {
        RetiredOnly,
        PrimaryAndRetired,
        StagingAndRetired,
    }

    const LAYOUTS: [Layout; 3] = [
        Layout::RetiredOnly,
        Layout::PrimaryAndRetired,
        Layout::StagingAndRetired,
    ];

    fn primary_bytes() -> Vec<u8> {
        state(LOCAL).encode().unwrap()
    }

    fn fixture(layout: Layout) -> Scratch {
        let scratch = Scratch::new("legacy-gate-retired");

        scratch.put(&scratch.retired(LOCAL, RETIRED_TOKEN), RETIRED_BYTES);

        match layout {
            Layout::RetiredOnly => {}
            Layout::PrimaryAndRetired => scratch.put(&scratch.record(LOCAL), &primary_bytes()),
            Layout::StagingAndRetired => scratch.put(&scratch.staging(LOCAL, TOKEN), b"staging"),
        }

        scratch
    }

    fn retired_is_untouched(scratch: &Scratch) {
        assert_eq!(
            fs::read(scratch.retired(LOCAL, RETIRED_TOKEN)).unwrap(),
            RETIRED_BYTES,
            "the retired file was changed or removed"
        );
    }

    #[test]
    fn load_and_read_record_refuse_and_change_nothing() {
        for layout in LAYOUTS {
            let scratch = fixture(layout);
            let store = scratch.store();
            let before = snapshot(scratch.dir.path());

            // Even with a readable primary, the load is refused; never
            // `NotConfigured`, never `Loaded`.
            assert_eq!(
                store.load(&loc(LOCAL)),
                StateLoad::Unreadable(UnreadableReason::UnresolvedNewerState),
                "{layout:?}"
            );

            let read = store.read_record(&loc(LOCAL));

            match layout {
                Layout::PrimaryAndRetired => {
                    // A present primary is never refused: the read-only loader gets
                    // its exact bytes, and the indicator is truthful.
                    let RecordRead::Present(present) = &read else {
                        panic!("{layout:?}: expected a present record, got {read:?}");
                    };
                    assert_eq!(present.bytes(), primary_bytes());
                    assert_eq!(present.artifacts(), ArtifactPresence::Present);
                }
                Layout::RetiredOnly | Layout::StagingAndRetired => {
                    assert!(
                        matches!(
                            read,
                            RecordRead::Unreadable(UnreadableReason::UnresolvedNewerState)
                        ),
                        "{layout:?}: {read:?}"
                    );
                }
            }

            assert_eq!(snapshot(scratch.dir.path()), before, "{layout:?}");
            retired_is_untouched(&scratch);
        }
    }

    #[test]
    fn create_and_replace_refuse_and_never_touch_the_retired_file() {
        for layout in LAYOUTS {
            let scratch = fixture(layout);
            let store = scratch.store();
            let before = snapshot(scratch.dir.path());

            assert_eq!(
                store.create(&state(LOCAL)),
                Err(StoreError::UnresolvedNewerState),
                "{layout:?}"
            );
            assert_eq!(
                store.replace(&state(LOCAL), &proposed_state()),
                Err(StoreError::UnresolvedNewerState),
                "{layout:?}"
            );

            assert_eq!(snapshot(scratch.dir.path()), before, "{layout:?}");
            retired_is_untouched(&scratch);
        }
    }

    #[test]
    fn evidence_refuses_instead_of_binding_a_state_it_does_not_describe() {
        for layout in LAYOUTS {
            let scratch = fixture(layout);
            let store = scratch.store();
            let before = snapshot(scratch.dir.path());

            assert_eq!(
                store.evidence(&loc(LOCAL)).map(|_| ()),
                Err(EvidenceRefusal::UnresolvedNewerState),
                "{layout:?}"
            );

            assert_eq!(snapshot(scratch.dir.path()), before, "{layout:?}");
            retired_is_untouched(&scratch);
        }
    }

    #[test]
    fn delete_never_removes_a_retired_file_because_it_refuses_first() {
        for layout in LAYOUTS {
            let scratch = fixture(layout);
            let before = snapshot(scratch.dir.path());

            assert_eq!(
                scratch.store().delete(&loc(LOCAL)),
                Err(StoreError::UnresolvedNewerState),
                "{layout:?}"
            );

            assert_eq!(snapshot(scratch.dir.path()), before, "{layout:?}");
            retired_is_untouched(&scratch);
        }
    }

    #[test]
    fn conditional_delete_never_removes_a_retired_file_because_it_refuses_first() {
        for layout in LAYOUTS {
            let scratch = fixture(layout);
            let before = snapshot(scratch.dir.path());

            // No evidence of this layout can be captured; any other evidence is no
            // authority either.
            assert_eq!(
                scratch
                    .store()
                    .delete_if_evidence_matches(&loc(LOCAL), &empty_evidence()),
                Err(ConditionalDeleteError::Store(
                    StoreError::UnresolvedNewerState
                )),
                "{layout:?}"
            );

            assert_eq!(snapshot(scratch.dir.path()), before, "{layout:?}");
            retired_is_untouched(&scratch);
        }
    }

    #[test]
    fn a_retired_file_of_another_location_blocks_only_that_location() {
        let scratch = Scratch::new("legacy-gate-other-retired");
        let other = scratch.retired(OTHER_LOCAL, RETIRED_TOKEN);

        scratch.put(&scratch.record(LOCAL), &primary_bytes());
        scratch.put(&other, RETIRED_BYTES);

        let store = scratch.store();

        // This location is not affected: it loads, binds its evidence and its
        // conditional deletion removes exactly its own files.
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Loaded(Box::new(state(LOCAL)))
        );

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Ok(DeleteOutcome::Removed)
        );

        // The other location, which does have a retired file, is refused; its
        // file is untouched either way.
        assert_eq!(
            store.delete(&loc(OTHER_LOCAL)),
            Err(StoreError::UnresolvedNewerState)
        );
        assert_eq!(fs::read(&other).unwrap(), RETIRED_BYTES);
        assert_eq!(
            names(&scratch.state_dir()),
            [format!(
                "{}.{RETIRED_TOKEN}.retired",
                record_key(&loc(OTHER_LOCAL))
            )]
        );
    }
}

// ---- B3c-3b-1 v1 non-regression tests (end) ----------------------------------

// ---- B3c-3b-2a golden v1 baseline (begin) ------------------------------------

/// Stage 1U-4 B3c-3b-2a golden baseline: what the legacy (v1) store does for the
/// ordinary v1 layouts, through every operation, with real files on NTFS.
///
/// These assertions were written and run against the **unmodified** production
/// store before the compatibility gate existed, and are meant to pass unchanged
/// afterwards: an ordinary v1 layout (no recognized newer-state evidence) must keep
/// its outcome, its refusals and the exact set of files it leaves behind. Every
/// operation runs on its own freshly built, uniquely owned scratch directory.
#[cfg(all(test, windows))]
mod legacy_v1_golden_tests {
    use std::fs;

    use localvault_core::{
        sync::{EnvelopeFingerprint, PushBaseline, PushIntent},
        sync_state::{BindingId, PendingPush, SyncBase, VaultBindingTag, BINDING_SALT_LEN},
    };

    use super::b3c3b1_support::{
        loc, names, state, Scratch, LOCAL, OTHER_LOCAL, RETIRED_TOKEN, TARGET, TOKEN,
    };
    use super::*;
    use crate::vault::handle_ops::test_support::snapshot;

    #[derive(Clone, Copy, Debug)]
    enum Layout {
        NoDirectory,
        EmptyDirectory,
        V1Primary,
        PrimaryAndEmptyTmp,
        PrimaryAndPartialTmp,
        PrimaryAndCompleteTmp,
        TmpOnlyEmpty,
        TmpOnlyPartial,
        TmpOnlyComplete,
        CorruptPrimary,
        OversizedTmp,
        DirectoryTmp,
        OtherKeysOnly,
        PrimaryAndOtherKeys,
        /// The `create` remnant (F2): the primary and one `.tmp` are two names
        /// (hard links) of ONE file. Added in B3c-3b-2d-1 and run on the unmodified
        /// path-based deletion first.
        AliasRemnant,
    }

    const LAYOUTS: [Layout; 15] = [
        Layout::NoDirectory,
        Layout::EmptyDirectory,
        Layout::V1Primary,
        Layout::PrimaryAndEmptyTmp,
        Layout::PrimaryAndPartialTmp,
        Layout::PrimaryAndCompleteTmp,
        Layout::TmpOnlyEmpty,
        Layout::TmpOnlyPartial,
        Layout::TmpOnlyComplete,
        Layout::CorruptPrimary,
        Layout::OversizedTmp,
        Layout::DirectoryTmp,
        Layout::OtherKeysOnly,
        Layout::PrimaryAndOtherKeys,
        Layout::AliasRemnant,
    ];

    /// The same binding as `state(LOCAL)` with a different pending-push revision.
    fn proposed() -> SyncState {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
        let intent =
            PushIntent::new(PushBaseline::Absent, EnvelopeFingerprint::of_bytes(&[2])).unwrap();

        SyncState::new(
            BindingId::new(Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555)).unwrap(),
            VaultBindingTag::derive(
                salt,
                Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            )
            .unwrap(),
            loc(LOCAL),
            loc(TARGET),
            SyncBase::Unbased,
            Some(
                PendingPush::new(
                    Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee),
                    intent,
                    2,
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }

    fn complete() -> Vec<u8> {
        state(LOCAL).encode().unwrap()
    }

    fn fixture(layout: Layout) -> Scratch {
        let scratch = Scratch::new("golden-v1");
        let tmp = scratch.staging(LOCAL, TOKEN);
        let record = scratch.record(LOCAL);

        match layout {
            Layout::NoDirectory => {}
            Layout::EmptyDirectory => fs::create_dir_all(scratch.state_dir()).unwrap(),
            Layout::V1Primary => scratch.put(&record, &complete()),
            Layout::PrimaryAndEmptyTmp => {
                scratch.put(&record, &complete());
                scratch.put(&tmp, b"");
            }
            Layout::PrimaryAndPartialTmp => {
                scratch.put(&record, &complete());
                scratch.put(&tmp, &complete()[..20]);
            }
            Layout::PrimaryAndCompleteTmp => {
                scratch.put(&record, &complete());
                scratch.put(&tmp, &complete());
            }
            Layout::AliasRemnant => {
                scratch.put(&record, &complete());
                fs::hard_link(&record, &tmp).unwrap();
            }
            Layout::TmpOnlyEmpty => scratch.put(&tmp, b""),
            Layout::TmpOnlyPartial => scratch.put(&tmp, &complete()[..20]),
            Layout::TmpOnlyComplete => scratch.put(&tmp, &complete()),
            Layout::CorruptPrimary => scratch.put(&record, b"garbage"),
            Layout::OversizedTmp => {
                fs::create_dir_all(scratch.state_dir()).unwrap();
                let file = fs::File::create(&tmp).unwrap();
                file.set_len(MAX_SYNC_STATE_BYTES as u64 + 1).unwrap();
            }
            Layout::DirectoryTmp => fs::create_dir_all(&tmp).unwrap(),
            Layout::OtherKeysOnly | Layout::PrimaryAndOtherKeys => {
                if matches!(layout, Layout::PrimaryAndOtherKeys) {
                    scratch.put(&record, &complete());
                }
                scratch.put(
                    &scratch.record(OTHER_LOCAL),
                    &state(OTHER_LOCAL).encode().unwrap(),
                );
                scratch.put(&scratch.staging(OTHER_LOCAL, TOKEN), b"other staging");
                scratch.put(
                    &scratch.retired(OTHER_LOCAL, RETIRED_TOKEN),
                    b"other retired",
                );
                scratch.put(&scratch.state_dir().join("unrelated.txt"), b"unrelated");
            }
        }

        scratch
    }

    /// The directory's file names with the record keys and tokens abbreviated, so
    /// the expectations read the same whatever the hashes are.
    fn listing(scratch: &Scratch) -> String {
        let dir = scratch.state_dir();

        if !dir.exists() {
            return "none".to_owned();
        }

        let key = record_key(&loc(LOCAL));
        let other = record_key(&loc(OTHER_LOCAL));

        let mut found: Vec<String> = names(&dir)
            .into_iter()
            .map(|name| {
                name.replace(&key, "K")
                    .replace(&other, "O")
                    .replace(TOKEN, "T")
                    .replace(RETIRED_TOKEN, "R")
            })
            .collect();

        found.sort();

        if found.is_empty() {
            "-".to_owned()
        } else {
            found.join(",")
        }
    }

    fn evidence_text(result: Result<RecordEvidence, EvidenceRefusal>) -> String {
        match result {
            Ok(evidence) => format!(
                "Ok(primary={}, artifacts={})",
                evidence.primary_present(),
                evidence.artifact_count()
            ),
            Err(refusal) => format!("Err({refusal:?})"),
        }
    }

    /// Load, read, create, replace, evidence, delete and conditional delete, each
    /// on a fresh fixture. The first three read-only operations also prove that
    /// nothing in the tree moved.
    fn observe(layout: Layout) -> [String; 7] {
        let read_only = |run: &dyn Fn(&SyncStateStore) -> String| {
            let scratch = fixture(layout);
            let before = snapshot(scratch.dir.path());
            let text = run(&scratch.store());

            assert_eq!(snapshot(scratch.dir.path()), before, "{layout:?}: {text}");

            text
        };
        let mutating = |run: &dyn Fn(&Scratch, &SyncStateStore) -> String| {
            let scratch = fixture(layout);
            let text = run(&scratch, &scratch.store());

            format!("{text}@{}", listing(&scratch))
        };

        let load = read_only(&|store| match store.load(&loc(LOCAL)) {
            StateLoad::Loaded(loaded) => format!("Loaded(same={})", *loaded == state(LOCAL)),
            other => format!("{other:?}"),
        });

        let read = {
            let scratch = fixture(layout);
            let before = snapshot(scratch.dir.path());
            let read = scratch.store().read_record(&loc(LOCAL));
            let text = match &read {
                RecordRead::Present(present) => format!(
                    "Present(same_bytes={}, {:?})",
                    present.bytes() == fs::read(scratch.record(LOCAL)).unwrap(),
                    present.artifacts()
                ),
                other => format!("{other:?}"),
            };

            assert_eq!(snapshot(scratch.dir.path()), before, "{layout:?}: {text}");

            text
        };

        let create = mutating(&|_, store| format!("{:?}", store.create(&state(LOCAL))));
        let replace =
            mutating(&|_, store| format!("{:?}", store.replace(&state(LOCAL), &proposed())));

        let evidence = read_only(&|store| evidence_text(store.evidence(&loc(LOCAL))));

        let delete = mutating(&|_, store| format!("{:?}", store.delete(&loc(LOCAL))));

        let conditional = mutating(&|_, store| {
            // A file that cannot be bound is judged against the empty evidence.
            let expected = match layout {
                Layout::OversizedTmp | Layout::DirectoryTmp => Scratch::new("golden-empty")
                    .store()
                    .evidence(&loc(LOCAL))
                    .unwrap(),
                _ => store.evidence(&loc(LOCAL)).unwrap(),
            };

            format!(
                "{:?}",
                store.delete_if_evidence_matches(&loc(LOCAL), &expected)
            )
        });

        [load, read, create, replace, evidence, delete, conditional]
    }

    const OTHERS: &str = "O.R.retired,O.T.tmp,O.json,unrelated.txt";

    fn expected(layout: Layout) -> [String; 7] {
        let s = |text: &str| text.to_owned();
        let others = |text: &str| format!("{text},{OTHERS}");

        match layout {
            Layout::NoDirectory => [
                s("NotConfigured"),
                s("NotConfigured"),
                s("Ok(())@K.json"),
                s("Err(Missing)@none"),
                s("Ok(primary=false, artifacts=0)"),
                s("Ok(AlreadyAbsent)@none"),
                s("Ok(AlreadyAbsent)@none"),
            ],
            Layout::EmptyDirectory => [
                s("NotConfigured"),
                s("NotConfigured"),
                s("Ok(())@K.json"),
                s("Err(Missing)@-"),
                s("Ok(primary=false, artifacts=0)"),
                s("Ok(AlreadyAbsent)@-"),
                s("Ok(AlreadyAbsent)@-"),
            ],
            Layout::V1Primary => [
                s("Loaded(same=true)"),
                s("Present(same_bytes=true, None)"),
                s("Err(AlreadyExists)@K.json"),
                s("Ok(())@K.json"),
                s("Ok(primary=true, artifacts=0)"),
                s("Ok(Removed)@-"),
                s("Ok(Removed)@-"),
            ],
            Layout::PrimaryAndEmptyTmp
            | Layout::PrimaryAndPartialTmp
            | Layout::PrimaryAndCompleteTmp
            | Layout::AliasRemnant => [
                s("Loaded(same=true)"),
                s("Present(same_bytes=true, Present)"),
                s("Err(AlreadyExists)@K.T.tmp,K.json"),
                s("Ok(())@K.T.tmp,K.json"),
                s("Ok(primary=true, artifacts=1)"),
                s("Ok(Removed)@-"),
                s("Ok(Removed)@-"),
            ],
            Layout::TmpOnlyEmpty | Layout::TmpOnlyPartial | Layout::TmpOnlyComplete => [
                s("Unreadable(UnresolvedArtifacts)"),
                s("Unreadable(UnresolvedArtifacts)"),
                s("Err(UnresolvedArtifacts)@K.T.tmp"),
                s("Err(Missing)@K.T.tmp"),
                s("Ok(primary=false, artifacts=1)"),
                s("Ok(Removed)@-"),
                s("Ok(Removed)@-"),
            ],
            Layout::CorruptPrimary => [
                s("Corrupt(Undecodable)"),
                s("Present(same_bytes=true, None)"),
                s("Err(AlreadyExists)@K.json"),
                s("Err(CurrentCorrupt)@K.json"),
                s("Ok(primary=true, artifacts=0)"),
                s("Ok(Removed)@-"),
                s("Ok(Removed)@-"),
            ],
            Layout::OversizedTmp => [
                s("Unreadable(UnresolvedArtifacts)"),
                s("Unreadable(UnresolvedArtifacts)"),
                s("Err(UnresolvedArtifacts)@K.T.tmp"),
                s("Err(Missing)@K.T.tmp"),
                s("Err(Oversized)"),
                s("Ok(Removed)@-"),
                s("Err(Evidence(Oversized))@K.T.tmp"),
            ],
            Layout::DirectoryTmp => [
                s("Unreadable(UnresolvedArtifacts)"),
                s("Unreadable(UnresolvedArtifacts)"),
                s("Err(UnresolvedArtifacts)@K.T.tmp"),
                s("Err(Missing)@K.T.tmp"),
                s("Err(UnexpectedObject)"),
                s("Err(UnexpectedObject)@K.T.tmp"),
                s("Err(Store(UnexpectedObject))@K.T.tmp"),
            ],
            Layout::OtherKeysOnly => [
                s("NotConfigured"),
                s("NotConfigured"),
                format!("Ok(())@{}", others("K.json")),
                format!("Err(Missing)@{OTHERS}"),
                s("Ok(primary=false, artifacts=0)"),
                format!("Ok(AlreadyAbsent)@{OTHERS}"),
                format!("Ok(AlreadyAbsent)@{OTHERS}"),
            ],
            Layout::PrimaryAndOtherKeys => [
                s("Loaded(same=true)"),
                s("Present(same_bytes=true, None)"),
                format!("Err(AlreadyExists)@{}", others("K.json")),
                format!("Ok(())@{}", others("K.json")),
                s("Ok(primary=true, artifacts=0)"),
                format!("Ok(Removed)@{OTHERS}"),
                format!("Ok(Removed)@{OTHERS}"),
            ],
        }
    }

    #[test]
    fn ordinary_v1_layouts_keep_their_outcomes_through_every_operation() {
        for layout in LAYOUTS {
            assert_eq!(observe(layout), expected(layout), "{layout:?}");
        }
    }
}

// ---- B3c-3b-2a golden v1 baseline (end) --------------------------------------

/// Stage 1U-4 B3c-3b-1 tests of the name grammar and of the read-only
/// [`SyncStateStore::inspect_v3_layout`]. Real NTFS, synthetic bytes. Fixtures are
/// built with plain file operations on uniquely owned scratch directories, as an
/// interrupted write or another process would leave them. The assessment itself
/// only reads: every no-mutation proof prepares a stable fixture, takes a
/// snapshot, calls **only** the assessment and requires the same snapshot. The
/// race tests change the tree on purpose and therefore never claim whole-tree
/// equality; they assert safe outcomes only.
#[cfg(all(test, windows))]
mod v3_layout_tests {
    use std::{
        ffi::OsString,
        fs,
        os::windows::ffi::OsStringExt,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };

    use super::b3c3b1_support::{loc, names, Scratch, LOCAL, OTHER_LOCAL, RETIRED_TOKEN, TOKEN};
    use super::*;
    use crate::vault::handle_ops::test_support::{make_junction, snapshot};

    type Shape = (Option<Vec<u8>>, Vec<(SiblingKind, Option<Vec<u8>>)>, usize);

    const PRIMARY_BYTES: &[u8] = b"SECRET-PRIMARY-MARKER";
    const SIBLING_BYTES: &[u8] = b"SECRET-SIBLING-MARKER";

    fn key() -> String {
        record_key(&loc(LOCAL))
    }

    fn class(name: &str) -> V3NameClass {
        recognize_v3_sibling_name(name, true, &key())
    }

    // ---- the pure grammar ---------------------------------------------------------

    #[test]
    fn the_exact_shapes_are_recognized() {
        let key = key();

        assert_eq!(key.len(), 64);
        assert_eq!(class(&format!("{key}.json")), V3NameClass::Primary);
        assert_eq!(
            class(&format!("{key}.{TOKEN}.tmp")),
            V3NameClass::Sibling(SiblingKind::Staging)
        );
        assert_eq!(
            class(&format!("{key}.{RETIRED_TOKEN}.retired")),
            V3NameClass::Sibling(SiblingKind::Retired)
        );
    }

    #[test]
    fn case_variants_are_recognized_like_the_lowercase_names() {
        let key = key();
        let upper_token = TOKEN.to_ascii_uppercase();

        for name in [
            format!("{}.JSON", key.to_ascii_uppercase()),
            format!("{}.Json", key.to_ascii_uppercase()),
            format!("{key}.JSON"),
        ] {
            assert_eq!(class(&name), V3NameClass::Primary, "{name}");
        }

        for (name, kind) in [
            (
                format!("{}.{upper_token}.TMP", key.to_ascii_uppercase()),
                SiblingKind::Staging,
            ),
            (format!("{key}.{upper_token}.tmp"), SiblingKind::Staging),
            (
                format!("{}.{RETIRED_TOKEN}.RETIRED", key.to_ascii_uppercase()),
                SiblingKind::Retired,
            ),
            (
                format!("{key}.{}.Retired", RETIRED_TOKEN.to_ascii_uppercase()),
                SiblingKind::Retired,
            ),
        ] {
            assert_eq!(class(&name), V3NameClass::Sibling(kind), "{name}");
        }
    }

    #[test]
    fn another_key_or_an_unrelated_name_is_ignored() {
        let key = key();
        let other = record_key(&loc(OTHER_LOCAL));

        assert_ne!(key, other);

        for name in [
            format!("{other}.json"),
            format!("{other}.{TOKEN}.tmp"),
            format!("{other}.{TOKEN}.retired"),
            // One character short of the key, or a prefix of it.
            format!("{}.json", &key[..63]),
            format!("x{key}.json"),
            format!(" {key}.json"),
            "unrelated.dat".to_owned(),
            ".lock".to_owned(),
            String::new(),
            "a".to_owned(),
        ] {
            assert_eq!(class(&name), V3NameClass::Other, "{name:?}");
        }
    }

    #[test]
    fn a_token_of_the_wrong_length_or_alphabet_is_suspicious_not_recognized() {
        let key = key();

        for token in [
            TOKEN[..31].to_owned(),
            format!("{TOKEN}0"),
            String::new(),
            "0".to_owned(),
            format!("{}g", &TOKEN[..31]),
            format!("{}-", &TOKEN[..31]),
            format!("{} ", &TOKEN[..31]),
        ] {
            for extension in ["tmp", "retired"] {
                let name = format!("{key}.{token}.{extension}");

                assert_eq!(class(&name), V3NameClass::Unrecognized, "{name}");
            }
        }
    }

    #[test]
    fn misleading_suffixes_are_suspicious_not_recognized() {
        let key = key();

        for name in [
            key.clone(),
            format!("{key}."),
            format!("{key}.json.bak"),
            format!("{key}.json.tmp"),
            format!("{key}.json.retired"),
            format!("{key}.jsonx"),
            format!("{key}.JSON.old"),
            format!("{key}.{TOKEN}"),
            format!("{key}.{TOKEN}."),
            format!("{key}.{TOKEN}.tmp.old"),
            format!("{key}.{TOKEN}.tmp.retired"),
            format!("{key}.{TOKEN}.retired.x"),
            format!("{key}.{TOKEN}.retired.tmp"),
            format!("{key}.{TOKEN}.tmpx"),
            format!("{key}.{TOKEN}.retire"),
            format!("{key}.{TOKEN}.json"),
            format!("{key}.tmp"),
            format!("{key}.retired"),
            format!("{key}..tmp"),
            format!("{key}..retired"),
            format!("{key}.{TOKEN}{TOKEN}.tmp"),
            format!("{key}.{TOKEN}.{TOKEN}.tmp"),
            format!("{key}.notes.txt"),
            format!("{key}{TOKEN}.tmp"),
        ] {
            assert_eq!(class(&name), V3NameClass::Unrecognized, "{name:?}");
        }
    }

    #[test]
    fn a_trailing_dot_or_space_is_suspicious_not_recognized() {
        let key = key();

        for name in [
            format!("{key}.json."),
            format!("{key}.json "),
            format!("{key}.json. "),
            format!("{key}.{TOKEN}.tmp."),
            format!("{key}.{TOKEN}.tmp "),
            format!("{key}.{TOKEN}.retired."),
            format!("{key}.{TOKEN}.retired "),
            format!("{key}.{TOKEN}.retired\t"),
            format!("{key}.json\n"),
        ] {
            assert_eq!(class(&name), V3NameClass::Unrecognized, "{name:?}");
        }
    }

    #[test]
    fn non_ascii_names_never_match_but_a_key_prefix_still_counts() {
        let key = key();

        // After the key: suspicious.
        for name in [
            format!("{key}.json\u{e9}"),
            format!("{key}.\u{ff4a}son"),
            format!("{key}.{TOKEN}.tm\u{440}"),
            format!("{key}.{}\u{e9}.tmp", &TOKEN[..31]),
            format!("{key}\u{200b}.json"),
        ] {
            assert_eq!(class(&name), V3NameClass::Unrecognized, "{name:?}");
        }

        // Inside the key or before it: not this key's name at all.
        for name in [
            format!("\u{e9}{}.json", &key[1..]),
            format!("{}\u{ff41}{}.json", &key[..10], &key[11..]),
            format!("\u{feff}{key}.json"),
        ] {
            assert_eq!(class(&name), V3NameClass::Other, "{name:?}");
        }
    }

    #[test]
    fn a_name_that_is_not_valid_unicode_is_never_recognized() {
        let key = key();

        // The lossy form of a non-Unicode name keeps its ASCII prefix.
        for lossy in [
            format!("{key}.json\u{fffd}"),
            format!("{key}.json"),
            format!("{key}.{TOKEN}.tmp"),
            format!("{key}.{TOKEN}.retired"),
            format!("{key}.\u{fffd}"),
        ] {
            assert_eq!(
                recognize_v3_sibling_name(&lossy, false, &key),
                V3NameClass::Unrecognized,
                "{lossy:?}"
            );
        }

        assert_eq!(
            recognize_v3_sibling_name("unrelated\u{fffd}", false, &key),
            V3NameClass::Other
        );
        assert_eq!(
            recognize_v3_sibling_name(&format!("{}\u{fffd}", &key[..63]), false, &key),
            V3NameClass::Other
        );
    }

    #[test]
    fn an_overlong_name_is_never_recognized_and_the_unit_count_is_utf16() {
        let key = key();

        // 255 UTF-16 units is the longest component; 256 is not a name at all.
        let long_suffix = "a".repeat(V3_MAX_NAME_UNITS + 1 - key.len());
        let prefixed = format!("{key}{long_suffix}");

        assert_eq!(prefixed.encode_utf16().count(), V3_MAX_NAME_UNITS + 1);
        assert_eq!(class(&prefixed), V3NameClass::Unrecognized);
        assert_eq!(class(&"b".repeat(400)), V3NameClass::Other);

        // A supplementary-plane character is two units and four bytes: the limit
        // is counted in units, never in bytes or characters.
        let astral = format!("{key}.json{}", "\u{1f600}".repeat(95));
        assert_eq!(astral.chars().count(), key.len() + 5 + 95);
        assert_eq!(astral.encode_utf16().count(), key.len() + 5 + 190);
        assert!(astral.encode_utf16().count() > V3_MAX_NAME_UNITS);
        assert_eq!(class(&astral), V3NameClass::Unrecognized);

        // The recognized shapes are far below the limit.
        assert!(format!("{key}.{RETIRED_TOKEN}.retired").len() < V3_MAX_NAME_UNITS);
    }

    #[test]
    fn a_malformed_key_matches_nothing() {
        let key = key();

        for bad in [
            String::new(),
            "abc".to_owned(),
            key[..63].to_owned(),
            format!("{key}0"),
            key.to_ascii_uppercase(),
            format!("{}g", &key[..63]),
        ] {
            for name in [
                format!("{key}.json"),
                format!("{key}.{TOKEN}.tmp"),
                bad.clone(),
            ] {
                assert_eq!(
                    recognize_v3_sibling_name(&name, true, &bad),
                    V3NameClass::Other,
                    "{bad:?} {name:?}"
                );
            }
        }
    }

    #[test]
    fn the_staging_grammar_agrees_with_the_unchanged_v1_rule_without_sharing_code() {
        let key = key();
        let upper_key = key.to_ascii_uppercase();
        let other = record_key(&loc(OTHER_LOCAL));

        let battery = [
            format!("{key}.{TOKEN}.tmp"),
            format!("{upper_key}.{TOKEN}.TMP"),
            format!("{key}.{}.tmp", TOKEN.to_ascii_uppercase()),
            format!("{key}.{}.tmp", &TOKEN[..31]),
            format!("{key}.{TOKEN}0.tmp"),
            format!("{key}.{}g.tmp", &TOKEN[..31]),
            format!("{key}.{TOKEN}.tmp.old"),
            format!("{key}.{TOKEN}.tmp "),
            format!("{key}.{TOKEN}.tmp."),
            format!("{key}.{TOKEN}.retired"),
            format!("{key}.{TOKEN}.json"),
            format!("{key}.json"),
            format!("{key}.tmp"),
            format!("{key}..tmp"),
            format!("{other}.{TOKEN}.tmp"),
            format!("x{key}.{TOKEN}.tmp"),
            "unrelated.tmp".to_owned(),
        ];

        for name in &battery {
            assert_eq!(
                is_artifact_name(name, &key),
                class(name) == V3NameClass::Sibling(SiblingKind::Staging),
                "{name:?}"
            );
        }

        // And the v1 rule stays blind to the new sibling kind.
        let retired = format!("{key}.{RETIRED_TOKEN}.retired");
        assert!(!is_artifact_name(&retired, &key));
        assert_eq!(class(&retired), V3NameClass::Sibling(SiblingKind::Retired));
    }

    // ---- fixtures and the no-mutation helper ------------------------------------

    /// One assessment of a **stable** fixture: the whole scratch tree is
    /// snapshotted before and after, and only the assessment runs in between.
    fn observe(scratch: &Scratch) -> V3LayoutInspection {
        let store = scratch.store();
        let before = snapshot(scratch.dir.path());
        let result = store.inspect_v3_layout(&loc(LOCAL));

        assert_eq!(
            snapshot(scratch.dir.path()),
            before,
            "the assessment changed the filesystem"
        );

        result
    }

    fn layout_of(inspection: V3LayoutInspection) -> V3Layout {
        match inspection {
            V3LayoutInspection::Observed(layout) => layout,
            other => panic!("expected an observed layout, got {other:?}"),
        }
    }

    fn uncertainty_of(inspection: V3LayoutInspection) -> LayoutUncertainty {
        match inspection {
            V3LayoutInspection::Uncertain(reason) => reason,
            other => panic!("expected an uncertain result, got {other:?}"),
        }
    }

    fn content_bytes(content: &SiblingContent) -> Option<&[u8]> {
        match content {
            SiblingContent::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Everything a layout shows, as plain comparable data.
    fn shape(layout: &V3Layout) -> Shape {
        let primary = match layout.primary() {
            LayoutPrimary::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        };

        (
            primary,
            layout
                .siblings()
                .iter()
                .map(|sibling| {
                    (
                        sibling.kind(),
                        content_bytes(sibling.content()).map(<[u8]>::to_vec),
                    )
                })
                .collect(),
            layout.unrecognized(),
        )
    }

    fn token(index: usize) -> String {
        format!("{index:032x}")
    }

    // ---- case A: nothing there --------------------------------------------------

    #[test]
    fn a_missing_directory_is_an_observed_absence_and_nothing_is_created() {
        let scratch = Scratch::new("v3-absent");
        let layout = layout_of(observe(&scratch));

        assert_eq!(*layout.primary(), LayoutPrimary::Absent);
        assert!(layout.siblings().is_empty());
        assert_eq!(layout.unrecognized(), 0);
        assert!(!scratch.state_dir().exists());
    }

    #[test]
    fn an_empty_directory_and_unrelated_files_are_an_observed_absence() {
        let scratch = Scratch::new("v3-empty");

        fs::create_dir_all(scratch.state_dir()).unwrap();
        let layout = layout_of(observe(&scratch));
        assert_eq!(*layout.primary(), LayoutPrimary::Absent);
        assert!(layout.siblings().is_empty());
        assert_eq!(layout.unrecognized(), 0);

        // Other keys and unrelated names are ignored and uncounted.
        let other = loc(OTHER_LOCAL);
        scratch.put(&scratch.record(OTHER_LOCAL), PRIMARY_BYTES);
        scratch.put(&scratch.staging(OTHER_LOCAL, TOKEN), SIBLING_BYTES);
        scratch.put(&scratch.retired(OTHER_LOCAL, TOKEN), SIBLING_BYTES);
        scratch.put(&scratch.state_dir().join("notes.txt"), b"x");
        scratch.put(&scratch.state_dir().join("sync.lock"), b"");

        assert_ne!(record_key(&other), key());

        let layout = layout_of(observe(&scratch));
        assert_eq!(*layout.primary(), LayoutPrimary::Absent);
        assert!(layout.siblings().is_empty());
        assert_eq!(layout.unrecognized(), 0);
    }

    // ---- cases A-G: primary and siblings ------------------------------------------

    #[test]
    fn a_primary_alone_is_read_in_full() {
        let scratch = Scratch::new("v3-primary");

        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);

        let layout = layout_of(observe(&scratch));

        assert_eq!(
            *layout.primary(),
            LayoutPrimary::Bytes(PRIMARY_BYTES.to_vec())
        );
        assert!(layout.siblings().is_empty());
        assert_eq!(layout.unrecognized(), 0);
    }

    #[test]
    fn a_primary_beside_a_staging_or_retired_sibling_reports_both() {
        let scratch = Scratch::new("v3-primary-sibling");

        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);
        scratch.put(&scratch.staging(LOCAL, TOKEN), b"staging bytes");

        let layout = layout_of(observe(&scratch));
        assert_eq!(
            *layout.primary(),
            LayoutPrimary::Bytes(PRIMARY_BYTES.to_vec())
        );
        assert_eq!(
            shape(&layout).1,
            [(SiblingKind::Staging, Some(b"staging bytes".to_vec()))]
        );

        scratch.put(&scratch.retired(LOCAL, RETIRED_TOKEN), b"retired bytes");

        let layout = layout_of(observe(&scratch));
        assert_eq!(
            *layout.primary(),
            LayoutPrimary::Bytes(PRIMARY_BYTES.to_vec())
        );
        assert_eq!(
            shape(&layout).1,
            [
                (SiblingKind::Staging, Some(b"staging bytes".to_vec())),
                (SiblingKind::Retired, Some(b"retired bytes".to_vec())),
            ]
        );
    }

    #[test]
    fn siblings_without_a_primary_are_reported_and_the_primary_stays_absent() {
        // Staging only, retired only, both, and several retired.
        type Setup = fn(&Scratch);

        let cases: [(&str, Setup, usize); 4] = [
            ("staging", |s| s.put(&s.staging(LOCAL, TOKEN), b"s"), 1),
            (
                "retired",
                |s| s.put(&s.retired(LOCAL, RETIRED_TOKEN), b"r"),
                1,
            ),
            (
                "both",
                |s| {
                    s.put(&s.staging(LOCAL, TOKEN), b"s");
                    s.put(&s.retired(LOCAL, RETIRED_TOKEN), b"r");
                },
                2,
            ),
            (
                "several retired",
                |s| {
                    for index in 0..5 {
                        s.put(&s.retired(LOCAL, &token(index)), b"r");
                    }
                },
                5,
            ),
        ];

        for (label, setup, count) in cases {
            let scratch = Scratch::new("v3-no-primary");
            setup(&scratch);

            let layout = layout_of(observe(&scratch));

            assert_eq!(*layout.primary(), LayoutPrimary::Absent, "{label}");
            assert_eq!(layout.siblings().len(), count, "{label}");
            assert_eq!(layout.unrecognized(), 0, "{label}");
        }
    }

    #[test]
    fn a_suspicious_key_prefixed_entry_is_counted_and_never_ignored() {
        let scratch = Scratch::new("v3-suspicious");
        let key = key();

        for name in [
            format!("{key}.json.bak"),
            format!("{key}.{TOKEN}.retired.x"),
            format!("{key}.retired"),
            format!("{key}.{}.tmp", &TOKEN[..31]),
            format!("{key}.notes.txt"),
        ] {
            scratch.put(&scratch.state_dir().join(&name), b"x");
        }

        let layout = layout_of(observe(&scratch));

        assert_eq!(*layout.primary(), LayoutPrimary::Absent);
        assert!(layout.siblings().is_empty());
        assert_eq!(layout.unrecognized(), 5);

        // They do not disturb a real primary either.
        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);

        let layout = layout_of(observe(&scratch));
        assert_eq!(
            *layout.primary(),
            LayoutPrimary::Bytes(PRIMARY_BYTES.to_vec())
        );
        assert_eq!(layout.unrecognized(), 5);
    }

    #[test]
    fn siblings_come_back_in_a_stable_order_and_two_observations_agree() {
        let scratch = Scratch::new("v3-order");

        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);
        for index in [7usize, 3, 11, 1] {
            scratch.put(&scratch.retired(LOCAL, &token(index)), &[index as u8]);
        }
        scratch.put(&scratch.staging(LOCAL, &token(9)), b"s");

        let first = layout_of(observe(&scratch));
        let second = layout_of(observe(&scratch));

        assert_eq!(shape(&first), shape(&second));

        // Staging first, then retired, each by name.
        let kinds: Vec<_> = first.siblings().iter().map(LayoutSibling::kind).collect();
        assert_eq!(
            kinds,
            [
                SiblingKind::Staging,
                SiblingKind::Retired,
                SiblingKind::Retired,
                SiblingKind::Retired,
                SiblingKind::Retired,
            ]
        );
        assert_eq!(
            shape(&first)
                .1
                .iter()
                .skip(1)
                .map(|(_, bytes)| bytes.clone().unwrap())
                .collect::<Vec<_>>(),
            [vec![1u8], vec![3], vec![7], vec![11]]
        );
    }

    #[test]
    fn foreign_bytes_at_a_valid_name_are_just_bytes_here() {
        // The store is crypto-agnostic: it never decides whose a file is.
        let scratch = Scratch::new("v3-foreign");

        scratch.put(&scratch.record(LOCAL), &[0xff, 0xfe, 0x00]);
        scratch.put(&scratch.staging(LOCAL, TOKEN), b"{\"not\":\"ours\"}");

        let layout = layout_of(observe(&scratch));

        assert_eq!(
            *layout.primary(),
            LayoutPrimary::Bytes(vec![0xff, 0xfe, 0x00])
        );
        assert_eq!(shape(&layout).1.len(), 1);
    }

    // ---- primary sizes and unexpected objects -------------------------------------

    #[test]
    fn an_empty_and_an_oversized_primary_are_reported_not_returned() {
        let scratch = Scratch::new("v3-sizes");

        scratch.put(&scratch.record(LOCAL), b"");
        assert_eq!(
            *layout_of(observe(&scratch)).primary(),
            LayoutPrimary::Empty
        );

        scratch.put(
            &scratch.record(LOCAL),
            &vec![b'a'; MAX_SYNC_STATE_BYTES + 1],
        );
        assert_eq!(
            *layout_of(observe(&scratch)).primary(),
            LayoutPrimary::TooLarge
        );

        let exact = vec![b'a'; MAX_SYNC_STATE_BYTES];
        scratch.put(&scratch.record(LOCAL), &exact);
        assert_eq!(
            *layout_of(observe(&scratch)).primary(),
            LayoutPrimary::Bytes(exact)
        );
    }

    #[test]
    fn an_empty_and_an_oversized_sibling_are_reported_not_returned() {
        let scratch = Scratch::new("v3-sibling-sizes");

        scratch.put(&scratch.staging(LOCAL, TOKEN), b"");
        scratch.put(
            &scratch.retired(LOCAL, RETIRED_TOKEN),
            &vec![b'a'; MAX_SYNC_STATE_BYTES + 1],
        );

        let layout = layout_of(observe(&scratch));
        let contents: Vec<_> = layout
            .siblings()
            .iter()
            .map(LayoutSibling::content)
            .collect();

        assert!(matches!(contents[0], SiblingContent::Empty));
        assert!(matches!(contents[1], SiblingContent::TooLarge));
    }

    #[test]
    fn a_directory_or_junction_in_place_of_the_primary_is_unexpected_and_untouched() {
        let scratch = Scratch::new("v3-primary-objects");
        let record = scratch.record(LOCAL);

        fs::create_dir_all(&record).unwrap();
        assert_eq!(
            *layout_of(observe(&scratch)).primary(),
            LayoutPrimary::Unexpected
        );
        fs::remove_dir(&record).unwrap();

        let behind = scratch.root().join("behind");
        fs::create_dir_all(&behind).unwrap();
        fs::write(behind.join("inside.txt"), b"inside").unwrap();
        make_junction(&record, &behind);

        assert_eq!(
            *layout_of(observe(&scratch)).primary(),
            LayoutPrimary::Unexpected
        );

        // Nothing was followed or removed.
        assert_eq!(fs::read(behind.join("inside.txt")).unwrap(), b"inside");
    }

    #[test]
    fn a_file_symlink_primary_is_not_followed_where_one_can_be_created() {
        let scratch = Scratch::new("v3-primary-symlink");
        let target = scratch.root().join("target.bin");

        fs::write(&target, PRIMARY_BYTES).unwrap();
        fs::create_dir_all(scratch.state_dir()).unwrap();

        if std::os::windows::fs::symlink_file(&target, scratch.record(LOCAL)).is_err() {
            eprintln!("SKIPPED file-symlink primary: this account cannot create a symlink");
            return;
        }

        assert_eq!(
            *layout_of(observe(&scratch)).primary(),
            LayoutPrimary::Unexpected
        );
    }

    #[test]
    fn a_directory_or_junction_in_place_of_a_sibling_is_unexpected_and_untouched() {
        let scratch = Scratch::new("v3-sibling-objects");
        let behind = scratch.root().join("behind");

        fs::create_dir_all(&behind).unwrap();
        fs::write(behind.join("inside.txt"), b"inside").unwrap();

        fs::create_dir_all(scratch.staging(LOCAL, TOKEN)).unwrap();
        fs::create_dir_all(scratch.state_dir()).unwrap();
        make_junction(&scratch.retired(LOCAL, RETIRED_TOKEN), &behind);

        let layout = layout_of(observe(&scratch));
        let contents: Vec<_> = layout
            .siblings()
            .iter()
            .map(LayoutSibling::content)
            .collect();

        assert_eq!(contents.len(), 2);
        assert!(contents
            .iter()
            .all(|content| matches!(content, SiblingContent::Unexpected)));
        assert_eq!(fs::read(behind.join("inside.txt")).unwrap(), b"inside");
    }

    #[test]
    fn a_hard_linked_sibling_is_read_as_the_file_it_is_and_the_other_name_is_untouched() {
        // The store records no link facts (no file identity in this slice): a
        // second name for a file is read like any file. Pinned so that nothing
        // later assumes otherwise.
        let scratch = Scratch::new("v3-sibling-link");
        let outside = scratch.root().join("outside.bin");

        fs::write(&outside, SIBLING_BYTES).unwrap();
        fs::create_dir_all(scratch.state_dir()).unwrap();
        fs::hard_link(&outside, scratch.retired(LOCAL, RETIRED_TOKEN)).unwrap();

        let layout = layout_of(observe(&scratch));

        assert_eq!(
            shape(&layout).1,
            [(SiblingKind::Retired, Some(SIBLING_BYTES.to_vec()))]
        );
        assert_eq!(fs::read(&outside).unwrap(), SIBLING_BYTES);
    }

    // ---- limits --------------------------------------------------------------------

    #[test]
    fn the_entry_limit_is_uncertain_never_absence() {
        let scratch = Scratch::new("v3-entry-limit");

        fs::create_dir_all(scratch.state_dir()).unwrap();
        for index in 0..V3_SCAN_ENTRY_LIMIT {
            fs::write(
                scratch.state_dir().join(format!("unrelated-{index}.dat")),
                b"x",
            )
            .unwrap();
        }

        // Exactly the limit is still fully observed.
        let layout = layout_of(observe(&scratch));
        assert_eq!(*layout.primary(), LayoutPrimary::Absent);

        // One more is not.
        fs::write(scratch.state_dir().join("one-more.dat"), b"x").unwrap();
        assert_eq!(
            uncertainty_of(observe(&scratch)),
            LayoutUncertainty::EntryLimit
        );

        // Not even with a primary that was there to read.
        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);
        assert_eq!(
            uncertainty_of(observe(&scratch)),
            LayoutUncertainty::EntryLimit
        );
    }

    #[test]
    fn the_sibling_read_limit_is_uncertain_never_a_partial_list() {
        let scratch = Scratch::new("v3-sibling-limit");

        for index in 0..V3_SIBLING_READ_LIMIT {
            scratch.put(&scratch.retired(LOCAL, &token(index)), b"r");
        }

        let layout = layout_of(observe(&scratch));
        assert_eq!(layout.siblings().len(), V3_SIBLING_READ_LIMIT);

        scratch.put(&scratch.staging(LOCAL, &token(99)), b"s");
        assert_eq!(
            uncertainty_of(observe(&scratch)),
            LayoutUncertainty::SiblingLimit
        );
    }

    // ---- aliases ---------------------------------------------------------------------

    #[test]
    fn an_upper_case_primary_name_is_the_same_primary() {
        let scratch = Scratch::new("v3-case");
        let upper = scratch
            .state_dir()
            .join(format!("{}.JSON", key().to_ascii_uppercase()));

        scratch.put(&upper, PRIMARY_BYTES);

        let layout = layout_of(observe(&scratch));

        assert_eq!(
            *layout.primary(),
            LayoutPrimary::Bytes(PRIMARY_BYTES.to_vec())
        );
        assert_eq!(layout.unrecognized(), 0);
    }

    #[test]
    fn two_entries_that_fold_to_one_name_are_ambiguous() {
        let key = key();

        // The decision itself, on synthetic listings.
        let primary = |name: String| (NameTag::Primary, OsString::from(name));
        let staging = |name: String| (NameTag::Sibling(SiblingKind::Staging), OsString::from(name));

        assert_eq!(
            reject_v3_aliases(&[
                primary(format!("{key}.json")),
                primary(format!("{key}.JSON")),
            ]),
            Err(LayoutUncertainty::AliasAmbiguity)
        );
        assert_eq!(
            reject_v3_aliases(&[
                staging(format!("{key}.{TOKEN}.tmp")),
                staging(format!("{key}.{}.TMP", TOKEN.to_ascii_uppercase())),
            ]),
            Err(LayoutUncertainty::AliasAmbiguity)
        );
        assert_eq!(
            reject_v3_aliases(&[
                primary(format!("{key}.json")),
                staging(format!("{key}.{TOKEN}.tmp")),
                (NameTag::Unrecognized, OsString::from(format!("{key}.json"))),
            ]),
            Ok(())
        );

        // The physical case: a case-sensitive directory can hold both spellings.
        let scratch = Scratch::new("v3-alias");
        fs::create_dir_all(scratch.state_dir()).unwrap();

        let enabled = std::process::Command::new("fsutil.exe")
            .args(["file", "setCaseSensitiveInfo"])
            .arg(scratch.state_dir())
            .arg("enable")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if !enabled {
            eprintln!("SKIPPED physical case alias: per-directory case sensitivity is unavailable");
            return;
        }

        fs::write(scratch.state_dir().join(format!("{key}.json")), b"lower").unwrap();
        fs::write(scratch.state_dir().join(format!("{key}.JSON")), b"upper").unwrap();

        if names(&scratch.state_dir()).len() != 2 {
            eprintln!("SKIPPED physical case alias: the directory stayed case-insensitive");
            return;
        }

        assert_eq!(
            uncertainty_of(observe(&scratch)),
            LayoutUncertainty::AliasAmbiguity
        );
    }

    // ---- non-Unicode names ----------------------------------------------------------------

    #[test]
    fn a_non_unicode_key_prefixed_name_is_counted_and_an_unrelated_one_is_not() {
        let scratch = Scratch::new("v3-non-unicode");
        fs::create_dir_all(scratch.state_dir()).unwrap();

        // A lone surrogate is a legal NTFS name unit and is not valid Unicode.
        let mut prefixed: Vec<u16> = format!("{}.json", key()).encode_utf16().collect();
        prefixed.push(0xD800);
        let prefixed = OsString::from_wide(&prefixed);

        let mut unrelated: Vec<u16> = "unrelated".encode_utf16().collect();
        unrelated.push(0xD800);
        let unrelated = OsString::from_wide(&unrelated);

        if fs::write(scratch.state_dir().join(&prefixed), b"x").is_err() {
            eprintln!("SKIPPED non-Unicode name: the filesystem refused a lone surrogate");
            return;
        }
        fs::write(scratch.state_dir().join(&unrelated), b"x").unwrap();

        assert!(prefixed.to_str().is_none());

        let layout = layout_of(observe(&scratch));

        assert_eq!(*layout.primary(), LayoutPrimary::Absent);
        assert!(layout.siblings().is_empty());
        assert_eq!(layout.unrecognized(), 1);
    }

    // ---- unsafe directories and ancestors ------------------------------------------------

    #[test]
    fn an_unsafe_state_directory_or_ancestor_is_uncertain_never_absence() {
        // The state directory itself is a junction.
        let scratch = Scratch::new("v3-dir-junction");
        let moved = scratch.root().join("moved");

        fs::create_dir_all(&moved).unwrap();
        fs::write(
            moved.join(scratch.record(LOCAL).file_name().unwrap()),
            PRIMARY_BYTES,
        )
        .unwrap();
        make_junction(&scratch.state_dir(), &moved);

        assert_eq!(
            uncertainty_of(observe(&scratch)),
            LayoutUncertainty::UnexpectedObject
        );

        // An ancestor of the root is a junction.
        let real = scratch.root().join("real");
        let link = scratch.root().join("link");
        fs::create_dir_all(real.join("app-local").join(SYNC_STATE_DIRECTORY)).unwrap();
        make_junction(&link, &real);

        let through = SyncStateStore::new(&link.join("app-local")).unwrap();
        assert_eq!(
            uncertainty_of(through.inspect_v3_layout(&loc(LOCAL))),
            LayoutUncertainty::UnexpectedObject
        );
    }

    #[test]
    fn a_regular_file_in_place_of_the_state_directory_or_an_ancestor_is_uncertain() {
        let scratch = Scratch::new("v3-dir-file");

        fs::write(scratch.state_dir(), b"a file").unwrap();
        assert_eq!(
            uncertainty_of(observe(&scratch)),
            LayoutUncertainty::UnexpectedObject
        );

        let blocked = scratch.root().join("blocked");
        fs::write(&blocked, b"a file").unwrap();

        let below = SyncStateStore::new(&blocked.join("app-local")).unwrap();
        let result = below.inspect_v3_layout(&loc(LOCAL));

        assert!(
            matches!(
                result,
                V3LayoutInspection::Uncertain(
                    LayoutUncertainty::UnexpectedObject | LayoutUncertainty::Io(_)
                )
            ),
            "{result:?}"
        );
    }

    // ---- the two observations: deterministic pieces -------------------------------------

    #[test]
    fn a_listed_primary_that_is_gone_or_an_unlisted_one_that_is_there_disagree() {
        let scratch = Scratch::new("v3-pieces");
        let store = scratch.store();
        let key = key();
        let listed = vec![(NameTag::Primary, OsString::from(format!("{key}.json")))];
        let unlisted = ObservedNames::new();

        fs::create_dir_all(scratch.state_dir()).unwrap();

        // Listed, then gone.
        assert_eq!(
            store.read_v3_primary(&key, &listed),
            Err(LayoutUncertainty::ChangedDuringScan)
        );
        // Not listed, but there.
        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);
        assert_eq!(
            store.read_v3_primary(&key, &unlisted),
            Err(LayoutUncertainty::ChangedDuringScan)
        );
        // Listed and there: agreement.
        assert_eq!(
            store.read_v3_primary(&key, &listed),
            Ok(LayoutPrimary::Bytes(PRIMARY_BYTES.to_vec()))
        );
        // Unlisted and not there: agreement.
        fs::remove_file(scratch.record(LOCAL)).unwrap();
        assert_eq!(
            store.read_v3_primary(&key, &unlisted),
            Ok(LayoutPrimary::Absent)
        );
    }

    #[test]
    fn a_sibling_that_disappears_between_listing_and_reading_is_vanished() {
        let scratch = Scratch::new("v3-vanished");
        let store = scratch.store();
        let name = OsString::from(format!("{}.{TOKEN}.tmp", key()));

        fs::create_dir_all(scratch.state_dir()).unwrap();

        assert!(matches!(
            store.read_v3_sibling(&name),
            SiblingContent::Vanished
        ));
    }

    #[test]
    fn two_enumerations_of_a_changed_directory_differ() {
        let scratch = Scratch::new("v3-enumeration");
        let store = scratch.store();
        let key = key();

        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);
        scratch.put(&scratch.staging(LOCAL, TOKEN), b"s");

        let first = store.enumerate_v3_names(&key).unwrap();
        assert_eq!(first, store.enumerate_v3_names(&key).unwrap());

        // A sibling added, one removed, one swapped for another name, and a
        // suspicious entry added each change the observation.
        scratch.put(&scratch.retired(LOCAL, RETIRED_TOKEN), b"r");
        let added = store.enumerate_v3_names(&key).unwrap();
        assert_ne!(first, added);

        fs::remove_file(scratch.retired(LOCAL, RETIRED_TOKEN)).unwrap();
        scratch.put(&scratch.state_dir().join(format!("{key}.json.bak")), b"x");
        let suspicious = store.enumerate_v3_names(&key).unwrap();
        assert_ne!(first, suspicious);
        assert_ne!(added, suspicious);

        fs::remove_file(scratch.state_dir().join(format!("{key}.json.bak"))).unwrap();
        fs::remove_file(scratch.staging(LOCAL, TOKEN)).unwrap();
        scratch.put(&scratch.staging(LOCAL, &token(1)), b"s");
        assert_ne!(first, store.enumerate_v3_names(&key).unwrap());
    }

    // ---- the race, stress style -----------------------------------------------------------

    #[test]
    fn a_sibling_created_and_removed_concurrently_is_never_misreported() {
        // A helper thread churns one sibling while the assessment runs repeatedly.
        // The tree changes on purpose, so this proves no whole-tree equality; it
        // asserts only that every outcome is a safe one. The distribution of
        // outcomes depends on scheduling and is deliberately not asserted.
        let scratch = Scratch::new("v3-race");
        let store = scratch.store();
        let churned = scratch.staging(LOCAL, TOKEN);
        let stop = Arc::new(AtomicBool::new(false));
        let cycles = Arc::new(AtomicUsize::new(0));

        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);

        let worker = {
            let (stop, cycles, churned) = (stop.clone(), cycles.clone(), churned.clone());

            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let _ = fs::write(&churned, b"churned");
                    let _ = fs::remove_file(&churned);
                    cycles.fetch_add(1, Ordering::SeqCst);
                }
            })
        };

        for _ in 0..300 {
            match store.inspect_v3_layout(&loc(LOCAL)) {
                V3LayoutInspection::Observed(layout) => {
                    // The primary never changed and nothing else could appear.
                    assert_eq!(
                        *layout.primary(),
                        LayoutPrimary::Bytes(PRIMARY_BYTES.to_vec())
                    );
                    assert!(layout.siblings().len() <= 1);
                    assert_eq!(layout.unrecognized(), 0);
                }
                V3LayoutInspection::Uncertain(
                    LayoutUncertainty::ChangedDuringScan | LayoutUncertainty::Io(_),
                ) => {}
                V3LayoutInspection::Uncertain(other) => {
                    panic!("an unrelated uncertainty under a sibling race: {other:?}")
                }
            }
        }

        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();

        assert!(cycles.load(Ordering::SeqCst) > 0, "the race never ran");

        // Once the churn stops, the observation is complete and stable again.
        let _ = fs::remove_file(&churned);
        let layout = layout_of(observe(&scratch));
        assert!(layout.siblings().is_empty());
    }

    #[test]
    fn a_primary_replaced_concurrently_is_never_reported_as_stable_garbage() {
        // The primary alternates between two valid contents. An observation either
        // returns exactly one of them or is uncertain.
        let scratch = Scratch::new("v3-race-primary");
        let store = scratch.store();
        let record = scratch.record(LOCAL);
        let stop = Arc::new(AtomicBool::new(false));

        scratch.put(&record, b"AAAAAAAAAAAAAAAAAAAA");

        let worker = {
            let stop = stop.clone();
            let record = record.clone();
            let scratch_root = scratch.root();

            std::thread::spawn(move || {
                let mut flip = false;

                while !stop.load(Ordering::SeqCst) {
                    flip = !flip;

                    // Whole-file replacement through a sibling of the root, as a
                    // foreign writer would, so a reader sees one content or the other.
                    let staged = scratch_root.join("swap.bin");
                    let content: &[u8] = if flip {
                        b"BBBBBBBBBBBBBBBBBBBB"
                    } else {
                        b"AAAAAAAAAAAAAAAAAAAA"
                    };

                    if fs::write(&staged, content).is_ok() {
                        let _ = fs::rename(&staged, &record);
                    }
                }
            })
        };

        for _ in 0..300 {
            match store.inspect_v3_layout(&loc(LOCAL)) {
                V3LayoutInspection::Observed(layout) => match layout.primary() {
                    LayoutPrimary::Bytes(bytes) => assert!(
                        bytes == b"AAAAAAAAAAAAAAAAAAAA" || bytes == b"BBBBBBBBBBBBBBBBBBBB",
                        "a torn primary was reported as observed"
                    ),
                    // A momentary absence while a foreign writer swaps the name is
                    // a faithful observation; garbage is what must never appear.
                    LayoutPrimary::Absent => {}
                    other => panic!("an unexpected primary under a replacement race: {other:?}"),
                },
                V3LayoutInspection::Uncertain(
                    LayoutUncertainty::ChangedDuringScan | LayoutUncertainty::Io(_),
                ) => {}
                V3LayoutInspection::Uncertain(other) => {
                    panic!("an unrelated uncertainty under a replacement race: {other:?}")
                }
            }
        }

        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
    }

    // ---- redaction and isolation --------------------------------------------------------------

    #[test]
    fn debug_output_reveals_no_bytes_path_name_token_key_or_length() {
        let scratch = Scratch::new("v3-debug");

        scratch.put(&scratch.record(LOCAL), PRIMARY_BYTES);
        scratch.put(&scratch.staging(LOCAL, TOKEN), SIBLING_BYTES);
        scratch.put(&scratch.retired(LOCAL, RETIRED_TOKEN), SIBLING_BYTES);
        scratch.put(
            &scratch.state_dir().join(format!("{}.json.bak", key())),
            b"x",
        );

        let inspection = observe(&scratch);
        let V3LayoutInspection::Observed(layout) = &inspection else {
            panic!("expected an observed layout");
        };

        let mut rendered = vec![
            format!("{inspection:?}"),
            format!("{layout:?}"),
            format!("{:?}", layout.primary()),
            format!("{:?}", layout.siblings()),
            format!("{:?}", layout.siblings()[0]),
            format!("{:?}", layout.siblings()[0].content()),
            format!("{:?}", layout.siblings()[0].kind()),
            format!("{:?}", LayoutPrimary::Bytes(PRIMARY_BYTES.to_vec())),
            format!("{:?}", SiblingContent::Bytes(SIBLING_BYTES.to_vec())),
            format!(
                "{:?}",
                SiblingContent::Unreadable(io::ErrorKind::PermissionDenied)
            ),
        ];

        for primary in [
            LayoutPrimary::Absent,
            LayoutPrimary::Empty,
            LayoutPrimary::TooLarge,
            LayoutPrimary::Unexpected,
        ] {
            rendered.push(format!("{primary:?}"));
        }
        for content in [
            SiblingContent::Empty,
            SiblingContent::TooLarge,
            SiblingContent::Unexpected,
            SiblingContent::Vanished,
        ] {
            rendered.push(format!("{content:?}"));
        }
        for reason in [
            LayoutUncertainty::Io(io::ErrorKind::PermissionDenied),
            LayoutUncertainty::UnexpectedObject,
            LayoutUncertainty::EntryLimit,
            LayoutUncertainty::SiblingLimit,
            LayoutUncertainty::AliasAmbiguity,
            LayoutUncertainty::ChangedDuringScan,
        ] {
            rendered.push(format!("{:?}", V3LayoutInspection::Uncertain(reason)));
            rendered.push(format!("{reason:?}"));
        }

        assert_eq!(rendered[0], "Observed(<redacted>)");
        assert_eq!(rendered[1], "V3Layout(<redacted>)");
        assert_eq!(rendered[2], "Bytes(<redacted>)");
        assert_eq!(rendered[4], "LayoutSibling(<redacted>)");

        let forbidden = [
            "SECRET".to_owned(),
            "MARKER".to_owned(),
            key(),
            TOKEN.to_owned(),
            RETIRED_TOKEN.to_owned(),
            scratch.dir.path().to_string_lossy().into_owned(),
            ".qa-local".to_owned(),
            ".lvault".to_owned(),
            ".json".to_owned(),
            ".tmp".to_owned(),
            ".retired".to_owned(),
            // The lengths of the byte fixtures.
            PRIMARY_BYTES.len().to_string(),
            SIBLING_BYTES.len().to_string(),
        ];

        for text in &rendered {
            for mark in &forbidden {
                assert!(!text.contains(mark.as_str()), "{mark} leaked in {text}");
            }
        }
    }

    /// The text of the read-only region of the production half of this file.
    fn region() -> &'static str {
        let source = include_str!("sync_state_store.rs");
        let start = source
            .find("\n// ---- v3 layout assessment (read-only)")
            .expect("the begin marker");
        let end = start
            + source[start..]
                .find("\n// ---- end v3 layout assessment")
                .expect("the end marker");

        &source[start..end]
    }

    #[test]
    fn the_read_only_region_contains_no_mutating_or_legacy_call() {
        let region = region();

        assert!(region.contains("fn inspect_v3_layout"));
        assert!(region.contains("fn recognize_v3_sibling_name"));
        assert!(!region.contains("#[cfg("));

        for forbidden in [
            "remove_file",
            "remove_dir",
            ".remove(",
            "rename",
            "hard_link",
            "create_new",
            "write_all",
            "sync_all",
            "OpenOptions",
            "fs::write",
            "fs::copy",
            "set_len",
            "truncate",
            "unsafe",
            "allow(",
            "getrandom",
            "new_v4",
            "File::create",
            "scan_artifacts",
            "is_artifact_name",
            "ARTIFACT_EXTENSION",
            "MAX_SCANNED_ENTRIES",
            "plan_delete",
            "execute_delete",
            "write_temp",
            "create_temp",
            "ensure_directory",
            "self.hook",
            "Point::",
            "evidence(",
            "delete_if_evidence_matches",
            ".create(",
            ".replace(",
            ".delete(",
            "thread",
            "Command",
        ] {
            assert!(!region.contains(forbidden), "{forbidden:?} in the region");
        }

        // The only file it opens is through the existing bounded no-follow reader.
        assert!(region.contains("self.read_primary("));
        assert!(!region.contains("open_no_follow"));
    }

    #[test]
    fn the_legacy_artifact_machinery_still_names_only_tmp() {
        let source = include_str!("sync_state_store.rs");

        // Everything before the v3 region is the legacy production code (and its
        // documentation); the test modules, which quote these strings, come after.
        let legacy = &source[..source
            .find("\n// ---- v3 layout assessment (read-only)")
            .unwrap()];

        assert!(legacy.contains("const ARTIFACT_EXTENSION: &str = \"tmp\";"));
        assert_eq!(
            legacy
                .matches("fn is_artifact_name(name: &str, key: &str) -> bool")
                .count(),
            1
        );
        // The legacy items do not mention the new kind in their production bodies.
        assert!(!legacy.contains(".retired\""));
        assert!(!legacy.contains("Retired"));
    }

    #[test]
    fn the_scratch_base_is_under_the_repository_and_never_the_temp_directory() {
        let scratch = Scratch::new("v3-base");

        assert!(!scratch.dir.path().starts_with(std::env::temp_dir()));
        assert!(scratch
            .root()
            .components()
            .any(|part| part.as_os_str() == "sync-state-b3c3b1-tests"));
    }
}

// ---- B3c-3b-2a test support (begin) ------------------------------------------

/// Shared scaffolding for the Stage 1U-4 B3c-3b-2a tests. Synthetic bytes only; the
/// scratch directories are the uniquely owned ones of `b3c3b1_support::Scratch`,
/// under the git-ignored `<repo>/.qa-local/` (never `%TEMP%`).
#[cfg(all(test, windows))]
mod b3c3b2a_support {
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use localvault_core::{
        sync::{EnvelopeFingerprint, PushBaseline, PushIntent},
        sync_state::{
            BindingId, PendingPush, SyncBase, SyncState, VaultBindingTag, BINDING_SALT_LEN,
        },
    };
    use uuid::Uuid;

    use super::b3c3b1_support::{loc, state, Scratch, LOCAL, TARGET};
    use super::{record_key, RecordEvidence, MAX_SYNC_STATE_BYTES};
    use crate::vault::handle_ops::test_support::{make_junction, snapshot};

    /// A well-formed token for a `.v3stage` name.
    pub(super) const STAGE_TOKEN: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

    const VAULT_ID: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);

    pub(super) fn v3stage(scratch: &Scratch, local: &str, token: &str) -> PathBuf {
        scratch
            .state_dir()
            .join(format!("{}.{token}.v3stage", record_key(&loc(local))))
    }

    /// A complete version-1 record for `LOCAL`.
    pub(super) fn v1_bytes() -> Vec<u8> {
        state(LOCAL).encode().unwrap()
    }

    /// A complete version-2 (exchange) record for `LOCAL`.
    pub(super) fn v2_bytes() -> Vec<u8> {
        state(LOCAL).encode_exchange_record().unwrap()
    }

    /// A complete, real version-3 (authenticated) record for `LOCAL`: the exact
    /// output of the core's authenticated encoder for `state(LOCAL)` under a fixed
    /// synthetic test key, captured once. It is a literal, not a call, because a
    /// repository scan (in the core crate) forbids naming the authenticated APIs in
    /// any source file but their one session module. Nothing authenticates it here;
    /// every test only needs it to be a complete, well-formed record of a version
    /// this build does not support.
    const V3_RECORD: &str = r#"{"format":"localvault-sync-state","version":3,"body":"{\"binding_id\":\"11111111-2222-3333-4444-555555555555\",\"vault_tag\":{\"salt\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"digest\":\"533cfabc5ff2073b76dab8c6cb60289e44d95f9dbb67cdbdac12bdcf94025aa8\"},\"local_locator\":\"\\\\\\\\?\\\\C:\\\\Synthetic\\\\Vaults\\\\LOCAL-MARKER.lvault\",\"target_locator\":\"\\\\\\\\?\\\\D:\\\\Synthetic\\\\Remote\\\\TARGET-MARKER.lvault\",\"base\":{\"kind\":\"unbased\"},\"pending_push\":{\"intent_id\":\"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\",\"baseline\":{\"kind\":\"absent\"},\"intended\":\"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986\",\"intended_revision\":1},\"exchange\":null,\"retained_previous\":[]}","mac":"5de78e8da09519e20b40a22e21b2a63e9b38366539408610e30caf6c8e19191d"}"#;

    pub(super) fn v3_bytes() -> Vec<u8> {
        V3_RECORD.as_bytes().to_vec()
    }

    /// The version-1 wrapper of `LOCAL` with its version number rewritten.
    pub(super) fn tampered_version(version: u64) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(&v1_bytes()).unwrap();

        value["version"] = serde_json::json!(version);

        serde_json::to_vec(&value).unwrap()
    }

    /// Same binding as `state(LOCAL)`, different pending-push revision.
    pub(super) fn proposed_state() -> SyncState {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
        let intent =
            PushIntent::new(PushBaseline::Absent, EnvelopeFingerprint::of_bytes(&[2])).unwrap();

        SyncState::new(
            BindingId::new(Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555)).unwrap(),
            VaultBindingTag::derive(salt, VAULT_ID).unwrap(),
            loc(LOCAL),
            loc(TARGET),
            SyncBase::Unbased,
            Some(
                PendingPush::new(
                    Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee),
                    intent,
                    2,
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }

    /// The evidence of a store that holds nothing for `LOCAL`.
    pub(super) fn empty_evidence() -> RecordEvidence {
        Scratch::new("gate-empty-evidence")
            .store()
            .evidence(&loc(LOCAL))
            .unwrap()
    }

    /// A sparse file one byte over the supported maximum.
    pub(super) fn oversized(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        let file = fs::File::create(path).unwrap();

        file.set_len(MAX_SYNC_STATE_BYTES as u64 + 1).unwrap();
    }

    /// A directory at `path` (a plain directory, not a link).
    pub(super) fn directory(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("inner.txt"), b"keep").unwrap();
    }

    /// A junction at `path` to a directory kept outside the state directory.
    pub(super) fn junction(scratch: &Scratch, path: &Path) {
        let elsewhere = scratch.root().join("junction-target");

        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(scratch.state_dir()).unwrap();
        make_junction(path, &elsewhere);
    }

    /// Write `bytes` at `dest` from a REAL separate process (`cmd.exe copy`), as a
    /// non-cooperating program would. The staging source lives outside the state
    /// directory under `root` and is removed again.
    pub(super) fn child_puts(root: &Path, dest: &Path, bytes: &[u8]) {
        let source = root.join("child-source.bin");

        fs::write(&source, bytes).unwrap();

        let output = Command::new("cmd")
            .arg("/C")
            .arg("copy")
            .arg("/Y")
            .arg(&source)
            .arg(dest)
            .output()
            .unwrap();

        fs::remove_file(&source).unwrap();

        assert!(output.status.success(), "the child process could not write");
    }

    /// The same real `cmd.exe copy`, but the write must be REFUSED by the kernel
    /// (the destination is held). The staging source is removed again either way.
    pub(super) fn child_put_fails(root: &Path, dest: &Path, bytes: &[u8]) {
        let source = root.join("child-source.bin");

        fs::write(&source, bytes).unwrap();

        let output = Command::new("cmd")
            .arg("/C")
            .arg("copy")
            .arg("/Y")
            .arg(&source)
            .arg(dest)
            .output()
            .unwrap();

        fs::remove_file(&source).unwrap();

        assert!(
            !output.status.success(),
            "the child process WROTE to a held file: the hold did not prevent it"
        );
    }

    /// What a refused layout must produce, in all three error types.
    #[derive(Clone, Copy, Debug)]
    pub(super) enum Gate {
        Newer,
        Unrecognized,
        Uncertain,
    }

    use super::{
        ArtifactPresence, ConditionalDeleteError, EvidenceRefusal, RecordRead, StateLoad,
        StoreError, UnreadableReason,
    };

    /// Every legacy operation refuses `scratch` with the category `gate` names, and
    /// the whole tree (names, kinds, bytes, timestamps) is the same afterwards. A
    /// present primary is still returned by `read_record`, with a truthful
    /// indicator.
    pub(super) fn assert_gated(scratch: &Scratch, gate: Gate, label: &str) {
        let store = scratch.store();
        let before = snapshot(scratch.dir.path());

        let (reason, error, refusal, presence) = match gate {
            Gate::Newer => (
                UnreadableReason::UnresolvedNewerState,
                StoreError::UnresolvedNewerState,
                EvidenceRefusal::UnresolvedNewerState,
                ArtifactPresence::Present,
            ),
            Gate::Unrecognized => (
                UnreadableReason::UnrecognizedEntries,
                StoreError::UnrecognizedEntries,
                EvidenceRefusal::UnrecognizedEntries,
                ArtifactPresence::Present,
            ),
            Gate::Uncertain => (
                UnreadableReason::LayoutUncertain,
                StoreError::LayoutUncertain,
                EvidenceRefusal::Unreadable,
                ArtifactPresence::Unknown,
            ),
        };

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(reason),
            "{label}: load"
        );

        match store.read_record(&loc(LOCAL)) {
            RecordRead::Unreadable(found) => assert_eq!(found, reason, "{label}: read_record"),
            RecordRead::Present(present) => {
                assert_eq!(present.artifacts(), presence, "{label}: read_record")
            }
            other => panic!("{label}: read_record gave {other:?}"),
        }

        assert_eq!(store.create(&state(LOCAL)), Err(error), "{label}: create");
        assert_eq!(
            store.replace(&state(LOCAL), &proposed_state()),
            Err(error),
            "{label}: replace"
        );
        assert_eq!(
            store.evidence(&loc(LOCAL)).map(|_| ()),
            Err(refusal),
            "{label}: evidence"
        );
        assert_eq!(store.delete(&loc(LOCAL)), Err(error), "{label}: delete");
        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &empty_evidence()),
            Err(ConditionalDeleteError::Store(error)),
            "{label}: delete_if_evidence_matches"
        );

        assert_eq!(
            snapshot(scratch.dir.path()),
            before,
            "{label}: the tree moved"
        );
    }
}

// ---- B3c-3b-2a test support (end) --------------------------------------------

// ---- B3c-3b-2a pure verdict tests (begin) ------------------------------------

/// The gate's decision, on hand-built observations. No filesystem.
#[cfg(all(test, windows))]
mod legacy_gate_pure_tests {
    use std::io;

    use super::b3c3b2a_support::{v1_bytes, v2_bytes, v3_bytes};
    use super::*;

    fn sibling(kind: SiblingKind, content: SiblingContent) -> LayoutSibling {
        LayoutSibling { kind, content }
    }

    fn layout(
        primary: LayoutPrimary,
        siblings: Vec<LayoutSibling>,
        unrecognized: usize,
    ) -> V3Layout {
        V3Layout {
            primary,
            siblings,
            unrecognized,
        }
    }

    /// One of each kind of sibling content, freshly built (it is not `Clone`).
    fn every_content() -> Vec<(&'static str, SiblingContent)> {
        vec![
            ("v1", SiblingContent::Bytes(v1_bytes())),
            ("v2", SiblingContent::Bytes(v2_bytes())),
            ("v3", SiblingContent::Bytes(v3_bytes())),
            ("junk", SiblingContent::Bytes(b"junk".to_vec())),
            (
                "cut short",
                SiblingContent::Bytes(v3_bytes()[..24].to_vec()),
            ),
            ("empty", SiblingContent::Empty),
            ("too large", SiblingContent::TooLarge),
            (
                "unreadable",
                SiblingContent::Unreadable(io::ErrorKind::PermissionDenied),
            ),
            ("unexpected", SiblingContent::Unexpected),
            ("vanished", SiblingContent::Vanished),
        ]
    }

    #[test]
    fn an_empty_layout_passes_and_the_primary_is_never_judged() {
        assert_eq!(
            legacy_verdict(&layout(LayoutPrimary::Absent, vec![], 0)),
            Ok(())
        );

        for primary in [
            LayoutPrimary::Bytes(v1_bytes()),
            LayoutPrimary::Bytes(v3_bytes()),
            LayoutPrimary::Bytes(b"garbage".to_vec()),
            LayoutPrimary::Empty,
            LayoutPrimary::TooLarge,
            LayoutPrimary::Unexpected,
        ] {
            let label = format!("{primary:?}");

            assert_eq!(
                legacy_verdict(&layout(primary, vec![], 0)),
                Ok(()),
                "{label}"
            );
        }
    }

    #[test]
    fn a_retired_or_reserved_staging_sibling_is_newer_state_whatever_it_holds() {
        for kind in [SiblingKind::Retired, SiblingKind::ReservedStaging] {
            for (label, content) in every_content() {
                assert_eq!(
                    legacy_verdict(&layout(
                        LayoutPrimary::Absent,
                        vec![sibling(kind, content)],
                        0
                    )),
                    Err(LegacyGateRefusal::NewerState),
                    "{kind:?} holding {label}"
                );
            }
        }
    }

    #[test]
    fn a_staging_sibling_is_judged_by_its_content() {
        let expected = |label: &str| match label {
            "v2" | "v3" => Err(LegacyGateRefusal::NewerState),
            "unreadable" => Err(LegacyGateRefusal::Uncertain(LayoutUncertainty::Io(
                io::ErrorKind::PermissionDenied,
            ))),
            "vanished" => Err(LegacyGateRefusal::Uncertain(
                LayoutUncertainty::ChangedDuringScan,
            )),
            // A complete v1 record, junk, a cut-short record, empty, oversized and
            // a non-file all keep their legacy meaning.
            _ => Ok(()),
        };

        for (label, content) in every_content() {
            assert_eq!(
                legacy_verdict(&layout(
                    LayoutPrimary::Absent,
                    vec![sibling(SiblingKind::Staging, content)],
                    0
                )),
                expected(label),
                "staging holding {label}"
            );
        }
    }

    #[test]
    fn the_order_of_the_rules_is_fixed() {
        // A retired sibling beats an unrecognized entry.
        assert_eq!(
            legacy_verdict(&layout(
                LayoutPrimary::Absent,
                vec![sibling(SiblingKind::Retired, SiblingContent::Empty)],
                1
            )),
            Err(LegacyGateRefusal::NewerState)
        );

        // An unrecognized entry beats anything a staging file holds.
        for content in [
            SiblingContent::Bytes(v3_bytes()),
            SiblingContent::Unreadable(io::ErrorKind::PermissionDenied),
            SiblingContent::Vanished,
        ] {
            assert_eq!(
                legacy_verdict(&layout(
                    LayoutPrimary::Absent,
                    vec![sibling(SiblingKind::Staging, content)],
                    2
                )),
                Err(LegacyGateRefusal::UnrecognizedEntries)
            );
        }

        assert_eq!(
            legacy_verdict(&layout(LayoutPrimary::Absent, vec![], 1)),
            Err(LegacyGateRefusal::UnrecognizedEntries)
        );

        // Among staging files, complete newer-state content is reported before
        // uncertainty, whatever their order.
        for newer_first in [true, false] {
            let mut siblings = vec![
                sibling(
                    SiblingKind::Staging,
                    SiblingContent::Unreadable(io::ErrorKind::PermissionDenied),
                ),
                sibling(SiblingKind::Staging, SiblingContent::Bytes(v3_bytes())),
            ];

            if newer_first {
                siblings.reverse();
            }

            assert_eq!(
                legacy_verdict(&layout(LayoutPrimary::Absent, siblings, 0)),
                Err(LegacyGateRefusal::NewerState)
            );
        }

        // Several harmless staging files stay harmless.
        assert_eq!(
            legacy_verdict(&layout(
                LayoutPrimary::Bytes(v1_bytes()),
                vec![
                    sibling(SiblingKind::Staging, SiblingContent::Empty),
                    sibling(SiblingKind::Staging, SiblingContent::Bytes(v1_bytes())),
                    sibling(SiblingKind::Staging, SiblingContent::Bytes(b"x".to_vec())),
                ],
                0
            )),
            Ok(())
        );
    }

    #[test]
    fn every_refusal_maps_to_one_fixed_category_in_all_three_error_types() {
        use LayoutUncertainty as U;

        let kind = io::ErrorKind::PermissionDenied;

        // (refusal, reason, store error, evidence refusal)
        let table: Vec<(
            LegacyGateRefusal,
            UnreadableReason,
            StoreError,
            EvidenceRefusal,
        )> = vec![
            (
                LegacyGateRefusal::NewerState,
                UnreadableReason::UnresolvedNewerState,
                StoreError::UnresolvedNewerState,
                EvidenceRefusal::UnresolvedNewerState,
            ),
            (
                LegacyGateRefusal::UnrecognizedEntries,
                UnreadableReason::UnrecognizedEntries,
                StoreError::UnrecognizedEntries,
                EvidenceRefusal::UnrecognizedEntries,
            ),
            (
                LegacyGateRefusal::Uncertain(U::Io(kind)),
                UnreadableReason::Io(kind),
                StoreError::Io {
                    stage: IoStage::Scan,
                    kind,
                },
                EvidenceRefusal::Unreadable,
            ),
            (
                LegacyGateRefusal::Uncertain(U::UnexpectedObject),
                UnreadableReason::UnexpectedObject,
                StoreError::UnexpectedObject,
                EvidenceRefusal::UnexpectedObject,
            ),
            (
                LegacyGateRefusal::Uncertain(U::EntryLimit),
                UnreadableReason::EntryLimit,
                StoreError::Io {
                    stage: IoStage::Scan,
                    kind: io::ErrorKind::Other,
                },
                EvidenceRefusal::EntryLimit,
            ),
            (
                LegacyGateRefusal::Uncertain(U::ChangedDuringScan),
                UnreadableReason::LayoutUncertain,
                StoreError::LayoutUncertain,
                EvidenceRefusal::Unstable,
            ),
            (
                LegacyGateRefusal::Uncertain(U::SiblingLimit),
                UnreadableReason::LayoutUncertain,
                StoreError::LayoutUncertain,
                EvidenceRefusal::Unreadable,
            ),
            (
                LegacyGateRefusal::Uncertain(U::AliasAmbiguity),
                UnreadableReason::LayoutUncertain,
                StoreError::LayoutUncertain,
                EvidenceRefusal::Unreadable,
            ),
        ];

        for (refusal, reason, error, evidence) in table {
            assert_eq!(UnreadableReason::from(refusal), reason, "{refusal:?}");
            assert_eq!(StoreError::from(refusal), error, "{refusal:?}");
            assert_eq!(EvidenceRefusal::from(refusal), evidence, "{refusal:?}");

            // No uncertainty or evidence ever becomes confirmed absence.
            assert_ne!(
                StateLoad::Unreadable(reason).into_sync_state_load(),
                SyncStateLoad::NotConfigured
            );
        }
    }
}

// ---- B3c-3b-2a pure verdict tests (end) --------------------------------------

// ---- B3c-3b-2a real NTFS gate tests (begin) ----------------------------------

/// The compatibility gate through every legacy operation, on real files on NTFS.
/// Every refusal is proven by comparing a recursive snapshot of the whole tree
/// before and after: the gate removes, renames, creates and rewrites nothing.
#[cfg(all(test, windows))]
mod legacy_gate_ntfs_tests {
    use std::fs;

    use super::b3c3b1_support::{
        loc, names, state, Scratch, LOCAL, OTHER_LOCAL, RETIRED_TOKEN, TOKEN,
    };
    use super::b3c3b2a_support::{
        assert_gated, directory, junction, oversized, tampered_version, v1_bytes, v2_bytes,
        v3_bytes, v3stage, Gate, STAGE_TOKEN,
    };
    use super::*;
    use crate::vault::handle_ops::test_support::snapshot;

    type Build = Box<dyn Fn(&Scratch)>;

    fn run(cases: Vec<(&str, Gate, Build)>) {
        for (label, gate, build) in cases {
            let scratch = Scratch::new("legacy-gate-matrix");

            build(&scratch);
            assert_gated(&scratch, gate, label);
        }
    }

    fn retired(s: &Scratch, content: &[u8]) {
        s.put(&s.retired(LOCAL, RETIRED_TOKEN), content);
    }

    fn staging(s: &Scratch, content: &[u8]) {
        s.put(&s.staging(LOCAL, TOKEN), content);
    }

    fn stage(s: &Scratch, content: &[u8]) {
        s.put(&v3stage(s, LOCAL, STAGE_TOKEN), content);
    }

    fn primary(s: &Scratch, content: &[u8]) {
        s.put(&s.record(LOCAL), content);
    }

    #[test]
    fn retained_siblings_refuse_every_operation_whatever_else_is_there() {
        run(vec![
            ("retired only", Gate::Newer, Box::new(|s| retired(s, b"r"))),
            (
                "retired and a legacy temp",
                Gate::Newer,
                Box::new(|s| {
                    retired(s, b"r");
                    staging(s, b"staging");
                }),
            ),
            (
                "retired and a v1 primary",
                Gate::Newer,
                Box::new(|s| {
                    retired(s, b"r");
                    primary(s, &v1_bytes());
                }),
            ),
            (
                "retired and a real v3 primary",
                Gate::Newer,
                Box::new(|s| {
                    retired(s, b"r");
                    primary(s, &v3_bytes());
                }),
            ),
            (
                "retired and a corrupt primary",
                Gate::Newer,
                Box::new(|s| {
                    retired(s, b"r");
                    primary(s, b"garbage");
                }),
            ),
            (
                "retired holding a valid v1 record",
                Gate::Newer,
                Box::new(|s| retired(s, &v1_bytes())),
            ),
            (
                "retired holding a real v3 record",
                Gate::Newer,
                Box::new(|s| retired(s, &v3_bytes())),
            ),
            (
                "retired holding junk",
                Gate::Newer,
                Box::new(|s| retired(s, b"\x00\xff junk")),
            ),
            ("retired, empty", Gate::Newer, Box::new(|s| retired(s, b""))),
            (
                "retired, oversized",
                Gate::Newer,
                Box::new(|s| oversized(&s.retired(LOCAL, RETIRED_TOKEN))),
            ),
            (
                "retired, a directory",
                Gate::Newer,
                Box::new(|s| directory(&s.retired(LOCAL, RETIRED_TOKEN))),
            ),
            (
                "retired, a junction",
                Gate::Newer,
                Box::new(|s| junction(s, &s.retired(LOCAL, RETIRED_TOKEN))),
            ),
            (
                "retired, an upper-case name",
                Gate::Newer,
                Box::new(|s| {
                    s.put(
                        &s.state_dir().join(format!(
                            "{}.{}.RETIRED",
                            record_key(&loc(LOCAL)).to_ascii_uppercase(),
                            RETIRED_TOKEN.to_ascii_uppercase()
                        )),
                        b"r",
                    )
                }),
            ),
            (
                "three retired files",
                Gate::Newer,
                Box::new(|s| {
                    for index in 0..3 {
                        s.put(&s.retired(LOCAL, &format!("{index:032x}")), b"r");
                    }
                }),
            ),
            (
                "sixteen retired files (the sibling read limit itself)",
                Gate::Newer,
                Box::new(|s| {
                    for index in 0..V3_SIBLING_READ_LIMIT {
                        s.put(&s.retired(LOCAL, &format!("{index:032x}")), b"r");
                    }
                }),
            ),
            (
                "seventeen retired files (past the sibling read limit)",
                Gate::Uncertain,
                Box::new(|s| {
                    for index in 0..=V3_SIBLING_READ_LIMIT {
                        s.put(&s.retired(LOCAL, &format!("{index:032x}")), b"r");
                    }
                }),
            ),
        ]);
    }

    #[test]
    fn a_complete_newer_record_in_a_legacy_temp_refuses_every_operation() {
        run(vec![
            (
                "complete v3 temp alone",
                Gate::Newer,
                Box::new(|s| staging(s, &v3_bytes())),
            ),
            (
                "complete v3 temp beside a v1 primary",
                Gate::Newer,
                Box::new(|s| {
                    primary(s, &v1_bytes());
                    staging(s, &v3_bytes());
                }),
            ),
            (
                "complete v3 temp beside a corrupt primary",
                Gate::Newer,
                Box::new(|s| {
                    primary(s, b"garbage");
                    staging(s, &v3_bytes());
                }),
            ),
            (
                "complete v2 temp alone",
                Gate::Newer,
                Box::new(|s| staging(s, &v2_bytes())),
            ),
            (
                "complete record of a made-up future version",
                Gate::Newer,
                Box::new(|s| staging(s, &tampered_version(99))),
            ),
        ]);
    }

    #[test]
    fn the_reserved_staging_name_refuses_every_operation_whatever_the_file_is() {
        let cut = v3_bytes()[..24].to_vec();

        run(vec![
            ("v3stage, empty", Gate::Newer, Box::new(|s| stage(s, b""))),
            (
                "v3stage, cut short",
                Gate::Newer,
                Box::new(move |s| stage(s, &cut)),
            ),
            (
                "v3stage, oversized",
                Gate::Newer,
                Box::new(|s| oversized(&v3stage(s, LOCAL, STAGE_TOKEN))),
            ),
            (
                "v3stage, a valid v3 record",
                Gate::Newer,
                Box::new(|s| stage(s, &v3_bytes())),
            ),
            (
                "v3stage, a valid v1 record",
                Gate::Newer,
                Box::new(|s| stage(s, &v1_bytes())),
            ),
            (
                "v3stage, malformed",
                Gate::Newer,
                Box::new(|s| stage(s, b"{not json at all")),
            ),
            (
                "v3stage, a directory",
                Gate::Newer,
                Box::new(|s| directory(&v3stage(s, LOCAL, STAGE_TOKEN))),
            ),
            (
                "v3stage, a junction",
                Gate::Newer,
                Box::new(|s| junction(s, &v3stage(s, LOCAL, STAGE_TOKEN))),
            ),
            (
                "v3stage beside a v1 primary",
                Gate::Newer,
                Box::new(|s| {
                    primary(s, &v1_bytes());
                    stage(s, b"");
                }),
            ),
            (
                "v3stage beside a real v3 primary",
                Gate::Newer,
                Box::new(|s| {
                    primary(s, &v3_bytes());
                    stage(s, &v3_bytes());
                }),
            ),
            (
                "v3stage beside a retired file",
                Gate::Newer,
                Box::new(|s| {
                    retired(s, b"r");
                    stage(s, b"");
                }),
            ),
            (
                "v3stage, an upper-case name",
                Gate::Newer,
                Box::new(|s| {
                    s.put(
                        &s.state_dir().join(format!(
                            "{}.{}.V3STAGE",
                            record_key(&loc(LOCAL)).to_ascii_uppercase(),
                            STAGE_TOKEN.to_ascii_uppercase()
                        )),
                        b"",
                    )
                }),
            ),
        ]);
    }

    #[test]
    fn a_primary_of_an_unsupported_version_is_read_but_never_removed() {
        let versions: Vec<(&str, Vec<u8>)> = vec![
            ("real v3", v3_bytes()),
            ("real v2", v2_bytes()),
            ("version-tampered v1", tampered_version(2)),
            ("made-up future version", tampered_version(99)),
        ];

        for (label, bytes) in versions {
            let scratch = Scratch::new("legacy-gate-unsupported");
            primary(&scratch, &bytes);

            let store = scratch.store();
            let before = snapshot(scratch.dir.path());

            // Nothing about the siblings refuses the read, the evidence or the
            // diagnostics: the record is bound by its exact bytes.
            assert_eq!(
                store.load(&loc(LOCAL)),
                StateLoad::UnsupportedVersion,
                "{label}"
            );

            let RecordRead::Present(present) = store.read_record(&loc(LOCAL)) else {
                panic!("{label}: the primary must still be returned");
            };
            assert_eq!(present.bytes(), bytes, "{label}");
            assert_eq!(present.artifacts(), ArtifactPresence::None, "{label}");

            let evidence = store.evidence(&loc(LOCAL)).unwrap();
            assert!(evidence.primary_present(), "{label}");

            assert_eq!(
                store.create(&state(LOCAL)),
                Err(StoreError::AlreadyExists),
                "{label}"
            );
            assert_eq!(
                store.replace(&state(LOCAL), &super::b3c3b2a_support::proposed_state()),
                Err(StoreError::CurrentUnsupportedVersion),
                "{label}"
            );

            // But it is not something this build may remove.
            assert_eq!(
                store.delete(&loc(LOCAL)),
                Err(StoreError::UnresolvedNewerState),
                "{label}"
            );
            assert_eq!(
                store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
                Err(ConditionalDeleteError::Store(
                    StoreError::UnresolvedNewerState
                )),
                "{label}"
            );

            assert_eq!(snapshot(scratch.dir.path()), before, "{label}");
            assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), bytes, "{label}");
        }
    }

    #[test]
    fn a_partial_v3_like_temp_is_indistinguishable_and_stays_legacy_resettable_known_limit() {
        // KNOWN LIMIT, not a feature: the codec parses its whole input before it
        // reads a version, so an empty or cut-short record of a newer version is
        // byte-for-byte a legacy remnant. This is why the `.v3stage` name exists.
        let whole = v3_bytes();
        let text = String::from_utf8(whole.clone()).unwrap();
        let version = text.find("\"version\":").expect("a version field") + "\"version\":".len();

        let partials: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("cut before the version digit", whole[..version].to_vec()),
            (
                "cut right after the version digit",
                whole[..=version].to_vec(),
            ),
            ("cut in the middle", whole[..whole.len() / 2].to_vec()),
        ];

        for (label, bytes) in partials {
            let scratch = Scratch::new("legacy-gate-partial-tmp");
            staging(&scratch, &bytes);

            let store = scratch.store();

            assert_eq!(
                store.load(&loc(LOCAL)),
                StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts),
                "{label}"
            );

            let evidence = store.evidence(&loc(LOCAL)).unwrap();

            assert_eq!(
                store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
                Ok(DeleteOutcome::Removed),
                "{label}"
            );
            assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured, "{label}");
        }
    }

    #[test]
    fn ordinary_legacy_remnants_are_not_newer_state() {
        let scratch = Scratch::new("legacy-gate-ordinary");

        // A complete v1 record, an empty file and junk, all as legacy temps, beside
        // a v1 primary: exactly today's behaviour.
        primary(&scratch, &v1_bytes());
        scratch.put(&scratch.staging(LOCAL, TOKEN), &v1_bytes());
        scratch.put(
            &scratch.staging(LOCAL, "1111111111111111111111111111111a"),
            b"",
        );
        scratch.put(
            &scratch.staging(LOCAL, "2222222222222222222222222222222b"),
            b"junk",
        );

        let store = scratch.store();

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Loaded(Box::new(state(LOCAL)))
        );

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        assert_eq!(evidence.artifact_count(), 3);
        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Ok(DeleteOutcome::Removed)
        );
        assert!(names(&scratch.state_dir()).is_empty());
    }

    #[test]
    fn files_of_another_record_key_never_block() {
        // Every shape that blocks THIS key is harmless under ANOTHER key.
        let scratch = Scratch::new("legacy-gate-other-key");
        primary(&scratch, &v1_bytes());

        scratch.put(&scratch.retired(OTHER_LOCAL, RETIRED_TOKEN), b"r");
        scratch.put(&v3stage(&scratch, OTHER_LOCAL, STAGE_TOKEN), b"");
        scratch.put(&scratch.staging(OTHER_LOCAL, TOKEN), &v3_bytes());
        scratch.put(&scratch.record(OTHER_LOCAL), &v3_bytes());
        scratch.put(
            &scratch
                .state_dir()
                .join(format!("{}.json.bak", record_key(&loc(OTHER_LOCAL)))),
            b"x",
        );
        scratch.put(&scratch.state_dir().join("notes.txt"), b"x");

        let store = scratch.store();
        let before = snapshot(scratch.dir.path());

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Loaded(Box::new(state(LOCAL)))
        );

        let RecordRead::Present(present) = store.read_record(&loc(LOCAL)) else {
            panic!("the record must be returned");
        };
        assert_eq!(present.artifacts(), ArtifactPresence::None);

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        assert_eq!(snapshot(scratch.dir.path()), before);
        assert_eq!(
            store.replace(&state(LOCAL), &super::b3c3b2a_support::proposed_state()),
            Ok(())
        );
        // The replacement changed the record, so the old evidence no longer holds.
        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Err(ConditionalDeleteError::EvidenceChanged)
        );

        let fresh = store.evidence(&loc(LOCAL)).unwrap();

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &fresh),
            Ok(DeleteOutcome::Removed)
        );

        // Only this record's own file went; every other key's file is untouched.
        assert_eq!(names(&scratch.state_dir()).len(), 6);
    }

    #[test]
    fn a_scan_that_cannot_finish_is_a_refusal_never_absence() {
        // More entries than one observation visits, with a primary that could be
        // read. Today's load never scanned in that case; it now refuses.
        let scratch = Scratch::new("legacy-gate-entry-limit");
        primary(&scratch, &v1_bytes());

        for index in 0..V3_SCAN_ENTRY_LIMIT {
            fs::write(
                scratch.state_dir().join(format!("unrelated-{index}.dat")),
                b"x",
            )
            .unwrap();
        }

        let store = scratch.store();
        let before = snapshot(scratch.dir.path());

        // The primary plus 10 000 others is one entry over what an observation
        // visits, so the whole observation is refused.
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::EntryLimit)
        );

        let RecordRead::Present(present) = store.read_record(&loc(LOCAL)) else {
            panic!("a present primary is still returned");
        };
        assert_eq!(present.artifacts(), ArtifactPresence::Unknown);

        let limit = StoreError::Io {
            stage: IoStage::Scan,
            kind: io::ErrorKind::Other,
        };

        assert_eq!(store.create(&state(LOCAL)), Err(limit));
        assert_eq!(
            store.replace(&state(LOCAL), &super::b3c3b2a_support::proposed_state()),
            Err(limit)
        );
        assert_eq!(
            store.evidence(&loc(LOCAL)).map(|_| ()),
            Err(EvidenceRefusal::EntryLimit)
        );
        assert_eq!(store.delete(&loc(LOCAL)), Err(limit));
        assert_eq!(
            store
                .delete_if_evidence_matches(&loc(LOCAL), &super::b3c3b2a_support::empty_evidence()),
            Err(ConditionalDeleteError::Store(limit))
        );

        assert_eq!(snapshot(scratch.dir.path()), before);
    }

    #[test]
    fn too_many_legacy_temps_are_a_refusal_at_the_sibling_read_limit() {
        // INTENTIONAL consequence of observing before acting: sixteen leftover
        // legacy temps are still handled, seventeen are not, because one observation
        // reads at most sixteen recognized siblings. Each failed write removes its
        // own temp, so this is not reachable in normal use.
        let scratch = Scratch::new("legacy-gate-many-tmp");
        primary(&scratch, &v1_bytes());

        for index in 0..V3_SIBLING_READ_LIMIT {
            scratch.put(&scratch.staging(LOCAL, &format!("{index:032x}")), b"");
        }

        let store = scratch.store();

        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Loaded(Box::new(state(LOCAL)))
        );

        scratch.put(&scratch.staging(LOCAL, &format!("{:032x}", 99)), b"");

        assert_gated(&scratch, Gate::Uncertain, "seventeen legacy temps");
    }

    #[test]
    fn a_temp_that_cannot_be_read_is_a_refusal_not_a_removal() {
        use std::os::windows::fs::OpenOptionsExt;

        let scratch = Scratch::new("legacy-gate-held-tmp");
        primary(&scratch, &v1_bytes());
        staging(&scratch, b"debris");

        let store = scratch.store();
        let before = snapshot(scratch.dir.path());

        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(scratch.staging(LOCAL, TOKEN))
            .unwrap();

        assert!(matches!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::Io(_))
        ));
        assert!(matches!(
            store.create(&state(LOCAL)),
            Err(StoreError::Io {
                stage: IoStage::Scan,
                ..
            })
        ));
        assert!(matches!(
            store.evidence(&loc(LOCAL)),
            Err(EvidenceRefusal::Unreadable)
        ));
        assert!(matches!(
            store.delete(&loc(LOCAL)),
            Err(StoreError::Io {
                stage: IoStage::Scan,
                ..
            })
        ));

        // The snapshot reads every file, so the hold has to end first.
        drop(held);
        assert_eq!(snapshot(scratch.dir.path()), before);
    }

    #[test]
    fn two_names_that_fold_to_one_are_a_refusal_where_the_directory_can_hold_both() {
        let key = record_key(&loc(LOCAL));
        let scratch = Scratch::new("legacy-gate-alias");
        fs::create_dir_all(scratch.state_dir()).unwrap();

        let enabled = std::process::Command::new("fsutil.exe")
            .args(["file", "setCaseSensitiveInfo"])
            .arg(scratch.state_dir())
            .arg("enable")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if !enabled {
            eprintln!("SKIPPED physical case alias: per-directory case sensitivity is unavailable");
            return;
        }

        fs::write(scratch.state_dir().join(format!("{key}.json")), v1_bytes()).unwrap();
        fs::write(scratch.state_dir().join(format!("{key}.JSON")), v1_bytes()).unwrap();

        if names(&scratch.state_dir()).len() != 2 {
            eprintln!("SKIPPED physical case alias: the directory stayed case-insensitive");
            return;
        }

        assert_gated(&scratch, Gate::Uncertain, "case-sensitive alias");
    }
}

// ---- B3c-3b-2a real NTFS gate tests (end) ------------------------------------

// ---- B3c-3b-2a unrecognized entries (U2) tests (begin) -----------------------

/// Decision U2: an entry named after THIS record's key that is none of the
/// recognized shapes blocks the legacy operations, and is never touched. The same
/// names under ANOTHER record's key are unrelated and never block.
#[cfg(all(test, windows))]
mod legacy_gate_unrecognized_tests {
    use std::{ffi::OsString, fs, os::windows::ffi::OsStringExt};

    use super::b3c3b1_support::{loc, state, Scratch, LOCAL, OTHER_LOCAL, RETIRED_TOKEN, TOKEN};
    use super::b3c3b2a_support::{assert_gated, v1_bytes, Gate, STAGE_TOKEN};
    use super::*;
    use crate::vault::handle_ops::test_support::snapshot;

    /// What follows the key in each suspicious name.
    fn suffixes() -> Vec<(&'static str, String)> {
        vec![
            ("json backup", ".json.bak".to_owned()),
            ("notes file", ".notes.txt".to_owned()),
            ("temp with an extra suffix", format!(".{TOKEN}.tmp.old")),
            ("temp without a token", ".short.tmp".to_owned()),
            ("temp with a 31-hex token", format!(".{}.tmp", &TOKEN[..31])),
            ("temp with a 33-hex token", format!(".{TOKEN}0.tmp")),
            (
                "temp with a non-hex token",
                format!(".{}.tmp", "g".repeat(32)),
            ),
            ("temp without a separator", format!("{TOKEN}.tmp")),
            (
                "retired with an extra suffix",
                format!(".{RETIRED_TOKEN}.retired.x"),
            ),
            (
                "retired with a 31-hex token",
                format!(".{}.retired", &RETIRED_TOKEN[..31]),
            ),
            (
                "reserved staging with an extra suffix",
                format!(".{STAGE_TOKEN}.v3stage.bak"),
            ),
            (
                "reserved staging with a 31-hex token",
                format!(".{}.v3stage", &STAGE_TOKEN[..31]),
            ),
            (
                "reserved staging with a 33-hex token",
                format!(".{STAGE_TOKEN}f.v3stage"),
            ),
            ("reserved staging without a token", ".v3stage".to_owned()),
            ("bare key", String::new()),
        ]
    }

    fn named(scratch: &Scratch, local: &str, suffix: &str) -> std::path::PathBuf {
        scratch
            .state_dir()
            .join(format!("{}{suffix}", record_key(&loc(local))))
    }

    #[test]
    fn every_suspicious_shape_refuses_every_operation_and_changes_nothing() {
        for (label, suffix) in suffixes() {
            // Alone, and beside a readable v1 primary.
            for with_primary in [false, true] {
                let scratch = Scratch::new("legacy-gate-u2");

                if with_primary {
                    scratch.put(&scratch.record(LOCAL), &v1_bytes());
                }
                scratch.put(&named(&scratch, LOCAL, &suffix), b"suspicious");

                assert_gated(
                    &scratch,
                    Gate::Unrecognized,
                    &format!("{label} ({with_primary})"),
                );
                assert_eq!(
                    fs::read(named(&scratch, LOCAL, &suffix)).unwrap(),
                    b"suspicious",
                    "{label}: the file was touched"
                );
            }
        }
    }

    #[test]
    fn the_same_names_under_another_key_do_not_block() {
        for (label, suffix) in suffixes() {
            let scratch = Scratch::new("legacy-gate-u2-other");

            scratch.put(&scratch.record(LOCAL), &v1_bytes());
            scratch.put(&named(&scratch, OTHER_LOCAL, &suffix), b"someone else's");

            let store = scratch.store();
            let before = snapshot(scratch.dir.path());

            assert_eq!(
                store.load(&loc(LOCAL)),
                StateLoad::Loaded(Box::new(state(LOCAL))),
                "{label}"
            );
            assert_eq!(snapshot(scratch.dir.path()), before, "{label}");

            let evidence = store.evidence(&loc(LOCAL)).unwrap();

            assert_eq!(
                store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
                Ok(DeleteOutcome::Removed),
                "{label}"
            );
            assert_eq!(
                fs::read(named(&scratch, OTHER_LOCAL, &suffix)).unwrap(),
                b"someone else's",
                "{label}: another key's file was touched"
            );
        }
    }

    #[test]
    fn an_unrelated_file_that_only_looks_like_a_name_never_blocks() {
        let scratch = Scratch::new("legacy-gate-u2-unrelated");

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        scratch.put(&scratch.state_dir().join("readme.txt"), b"x");
        // Shorter than a key, and a key with one character changed.
        scratch.put(
            &scratch.state_dir().join(&record_key(&loc(LOCAL))[..63]),
            b"x",
        );
        let mut changed = record_key(&loc(LOCAL));
        changed.replace_range(0..1, if changed.starts_with('0') { "1" } else { "0" });
        scratch.put(&scratch.state_dir().join(format!("{changed}.json")), b"x");

        assert_eq!(
            scratch.store().load(&loc(LOCAL)),
            StateLoad::Loaded(Box::new(state(LOCAL)))
        );
    }

    #[test]
    fn a_name_that_is_not_valid_unicode_but_carries_the_key_refuses() {
        let scratch = Scratch::new("legacy-gate-u2-non-unicode");
        std::fs::create_dir_all(scratch.state_dir()).unwrap();

        // A lone surrogate is a legal NTFS name unit and is not valid Unicode.
        let mut units: Vec<u16> = format!("{}.json", record_key(&loc(LOCAL)))
            .encode_utf16()
            .collect();
        units.push(0xD800);
        let name = OsString::from_wide(&units);

        if fs::write(scratch.state_dir().join(&name), b"x").is_err() {
            eprintln!("SKIPPED non-Unicode name: the filesystem refused a lone surrogate");
            return;
        }

        assert_gated(&scratch, Gate::Unrecognized, "non-Unicode name");
    }
}

// ---- B3c-3b-2a unrecognized entries (U2) tests (end) -------------------------

// ---- B3c-3b-2a reserved staging name (U9) tests (begin) ----------------------

/// Decision U9: `<key>.<32 hex>.v3stage` is reserved for a future authenticated
/// publisher. This slice only recognizes the name; nothing creates, adopts or
/// removes such a file.
#[cfg(all(test, windows))]
mod v3stage_namespace_tests {
    use std::fs;

    use super::b3c3b1_support::{loc, Scratch, LOCAL, OTHER_LOCAL, TOKEN};
    use super::b3c3b2a_support::{
        directory, junction, oversized, v1_bytes, v3_bytes, v3stage, STAGE_TOKEN,
    };
    use super::*;

    fn key() -> String {
        record_key(&loc(LOCAL))
    }

    fn class(name: &str) -> V3NameClass {
        recognize_v3_sibling_name(name, true, &key())
    }

    #[test]
    fn only_the_exact_scoped_shape_is_recognized() {
        let key = key();
        let reserved = V3NameClass::Sibling(SiblingKind::ReservedStaging);

        assert_eq!(class(&format!("{key}.{STAGE_TOKEN}.v3stage")), reserved);
        // Either case, and any mix, like the other grammar.
        assert_eq!(class(&format!("{key}.{STAGE_TOKEN}.V3STAGE")), reserved);
        assert_eq!(class(&format!("{key}.{STAGE_TOKEN}.V3Stage")), reserved);
        assert_eq!(
            class(&format!(
                "{}.{}.v3stage",
                key.to_ascii_uppercase(),
                STAGE_TOKEN.to_ascii_uppercase()
            )),
            reserved
        );

        for wrong in [
            format!("{key}.{}.v3stage", &STAGE_TOKEN[..31]),
            format!("{key}.{STAGE_TOKEN}0.v3stage"),
            format!("{key}.{}.v3stage", "g".repeat(32)),
            format!("{key}.v3stage"),
            format!("{key}..v3stage"),
            format!("{key}{STAGE_TOKEN}.v3stage"),
            format!("{key}.{STAGE_TOKEN}.v3stage.bak"),
            format!("{key}.{STAGE_TOKEN}.v3stage "),
            format!("{key}.{STAGE_TOKEN}.v3stage."),
            format!("{key}.{STAGE_TOKEN}.v3stag"),
            format!("{key}.{STAGE_TOKEN}.v3stages"),
            format!("{key}.{STAGE_TOKEN}.v4stage"),
        ] {
            assert_eq!(class(&wrong), V3NameClass::Unrecognized, "{wrong}");
        }

        // Another key's name, and an unrelated one, are not this key's at all.
        let other = record_key(&loc(OTHER_LOCAL));
        assert_eq!(
            class(&format!("{other}.{STAGE_TOKEN}.v3stage")),
            V3NameClass::Other
        );
        assert_eq!(class("readme.v3stage"), V3NameClass::Other);

        // The old shapes are unchanged.
        assert_eq!(
            class(&format!("{key}.{TOKEN}.tmp")),
            V3NameClass::Sibling(SiblingKind::Staging)
        );
        assert_eq!(
            class(&format!("{key}.{TOKEN}.retired")),
            V3NameClass::Sibling(SiblingKind::Retired)
        );
        assert_eq!(class(&format!("{key}.json")), V3NameClass::Primary);

        // Not valid Unicode, or too long for a path component: never recognized.
        assert_eq!(
            recognize_v3_sibling_name(&format!("{key}.{STAGE_TOKEN}.v3stage"), false, &key),
            V3NameClass::Unrecognized
        );
        assert_eq!(
            class(&format!("{key}.{STAGE_TOKEN}.v3stage{}", "x".repeat(200))),
            V3NameClass::Unrecognized
        );
    }

    #[test]
    fn the_legacy_artifact_rule_knows_nothing_of_the_reserved_name() {
        let key = key();
        let name = format!("{key}.{STAGE_TOKEN}.v3stage");

        assert!(!is_artifact_name(&name, &key));
        assert!(!is_artifact_name(&name.to_ascii_uppercase(), &key));
        // The staging grammar still agrees with the unchanged v1 rule for `.tmp`.
        assert!(is_artifact_name(&format!("{key}.{TOKEN}.tmp"), &key));
        assert_eq!(ARTIFACT_EXTENSION, "tmp");
    }

    #[test]
    fn a_reserved_file_is_recognized_before_its_body_whatever_the_body_is() {
        type Make = Box<dyn Fn(&Scratch)>;

        let cut = v3_bytes()[..24].to_vec();

        let cases: Vec<(&str, Make)> = vec![
            (
                "empty",
                Box::new(|s| s.put(&v3stage(s, LOCAL, STAGE_TOKEN), b"")),
            ),
            (
                "cut short",
                Box::new(move |s| s.put(&v3stage(s, LOCAL, STAGE_TOKEN), &cut)),
            ),
            (
                "malformed",
                Box::new(|s| s.put(&v3stage(s, LOCAL, STAGE_TOKEN), b"{{")),
            ),
            (
                "oversized",
                Box::new(|s| oversized(&v3stage(s, LOCAL, STAGE_TOKEN))),
            ),
            (
                "a v1 record",
                Box::new(|s| s.put(&v3stage(s, LOCAL, STAGE_TOKEN), &v1_bytes())),
            ),
            (
                "a v3 record",
                Box::new(|s| s.put(&v3stage(s, LOCAL, STAGE_TOKEN), &v3_bytes())),
            ),
            (
                "a directory",
                Box::new(|s| directory(&v3stage(s, LOCAL, STAGE_TOKEN))),
            ),
            (
                "a junction",
                Box::new(|s| junction(s, &v3stage(s, LOCAL, STAGE_TOKEN))),
            ),
        ];

        for (label, make) in cases {
            let scratch = Scratch::new("v3stage-recognized");

            make(&scratch);

            let before = crate::vault::handle_ops::test_support::snapshot(scratch.dir.path());

            let V3LayoutInspection::Observed(layout) =
                scratch.store().inspect_v3_layout(&loc(LOCAL))
            else {
                panic!("{label}: the observation must complete");
            };

            let kinds: Vec<SiblingKind> = layout.siblings().iter().map(|s| s.kind()).collect();

            assert_eq!(kinds, [SiblingKind::ReservedStaging], "{label}");
            assert_eq!(layout.unrecognized(), 0, "{label}");
            assert_eq!(
                crate::vault::handle_ops::test_support::snapshot(scratch.dir.path()),
                before,
                "{label}"
            );
        }
    }

    #[test]
    fn an_unreadable_reserved_file_is_still_recognized_and_the_gate_refuses() {
        use std::os::windows::fs::OpenOptionsExt;

        let scratch = Scratch::new("v3stage-held");
        let path = v3stage(&scratch, LOCAL, STAGE_TOKEN);
        scratch.put(&path, b"held");

        let _held = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();

        let V3LayoutInspection::Observed(layout) = scratch.store().inspect_v3_layout(&loc(LOCAL))
        else {
            panic!("the observation must complete");
        };

        assert_eq!(layout.siblings()[0].kind(), SiblingKind::ReservedStaging);
        assert!(matches!(
            layout.siblings()[0].content(),
            SiblingContent::Unreadable(_)
        ));
        assert_eq!(legacy_verdict(&layout), Err(LegacyGateRefusal::NewerState));
    }

    #[test]
    fn another_keys_reserved_file_never_blocks_and_this_slice_creates_none() {
        let scratch = Scratch::new("v3stage-other-key");

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        scratch.put(&v3stage(&scratch, OTHER_LOCAL, STAGE_TOKEN), b"");

        let store = scratch.store();

        assert!(matches!(store.load(&loc(LOCAL)), StateLoad::Loaded(_)));

        // Every mutating operation that is allowed to run leaves no reserved file.
        let before: Vec<String> = super::b3c3b1_support::names(&scratch.state_dir());

        assert_eq!(
            store.replace(
                &super::b3c3b1_support::state(LOCAL),
                &super::b3c3b2a_support::proposed_state()
            ),
            Ok(())
        );

        let after = super::b3c3b1_support::names(&scratch.state_dir());

        assert_eq!(before, after);
        assert_eq!(
            after
                .iter()
                .filter(|name| name.ends_with(".v3stage"))
                .count(),
            1,
            "only the fixture's own file exists"
        );

        // Creating a record in a fresh store creates no such file either.
        let fresh = Scratch::new("v3stage-create");
        fresh
            .store()
            .create(&super::b3c3b1_support::state(LOCAL))
            .unwrap();
        assert!(super::b3c3b1_support::names(&fresh.state_dir())
            .iter()
            .all(|name| !name.ends_with(".v3stage")));
    }

    #[test]
    fn the_legacy_artifact_scan_never_lists_a_reserved_file() {
        let scratch = Scratch::new("v3stage-scan");

        scratch.put(&v3stage(&scratch, LOCAL, STAGE_TOKEN), b"");
        scratch.put(&scratch.staging(LOCAL, TOKEN), b"");

        let found = scratch.store().scan_artifacts(&key()).unwrap();
        let listed: Vec<String> = found
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert_eq!(listed, [format!("{}.{TOKEN}.tmp", key())]);
    }
}

// ---- B3c-3b-2a reserved staging name (U9) tests (end) ------------------------

// ---- B3c-3b-2a forced race tests (begin) -------------------------------------

/// Late changes at exact points of the existing operations, driven through the
/// store's test seams with REAL child processes (`cmd.exe copy`) doing the writing,
/// so the change really comes from outside this process. Each test names what it
/// shows:
///
/// * PREVENTED: the operation could not have gone ahead.
/// * REFUSED: the operation noticed and stopped before changing anything.
/// * DETECTED AFTERWARD: the operation completed and a later load now refuses.
/// * NOT PREVENTED: the operation completed over the late change.
///
/// Synthetic fixtures only, under the scratch directory.
#[cfg(all(test, windows))]
mod legacy_gate_race_tests {
    use std::fs;

    use super::b3c3b1_support::{loc, names, state, Scratch, LOCAL, RETIRED_TOKEN, TOKEN};
    use super::b3c3b2a_support::{child_put_fails, child_puts, proposed_state, v1_bytes};
    use super::*;
    use crate::vault::handle_ops::test_support::snapshot;

    const LATE: &[u8] = b"a retired record that appeared late";
    const FOREIGN: &[u8] = b"SYNTHETIC-FOREIGN-BYTES-NOT-A-REAL-RECORD";

    fn late_retired(scratch: &Scratch) -> impl Fn() + Send + 'static {
        let root = scratch.root();
        let path = scratch.retired(LOCAL, RETIRED_TOKEN);

        move || child_puts(&root, &path, LATE)
    }

    fn retired_is_intact(scratch: &Scratch) {
        assert_eq!(
            fs::read(scratch.retired(LOCAL, RETIRED_TOKEN)).unwrap(),
            LATE,
            "the retired file was touched"
        );
    }

    #[test]
    fn a_retired_file_inserted_before_the_evidence_recheck_refuses_and_removes_nothing() {
        // REFUSED. The deletion's preconditions have passed; a child process drops a
        // retired file; the fresh evidence capture now sees it and nothing is removed.
        let scratch = Scratch::new("race-evidence");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        scratch.put(&scratch.staging(LOCAL, TOKEN), b"debris");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        store.run_before_evidence_recheck_for_test(late_retired(&scratch));

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Err(ConditionalDeleteError::Evidence(
                EvidenceRefusal::UnresolvedNewerState
            ))
        );

        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());
        assert_eq!(fs::read(scratch.staging(LOCAL, TOKEN)).unwrap(), b"debris");
        retired_is_intact(&scratch);
    }

    #[test]
    fn a_retired_file_inserted_before_the_replace_check_refuses_and_leaves_the_record() {
        // REFUSED. Inserted at the point just before the second read, so the
        // re-check before the rename sees it: the record is unchanged and the
        // replacement's own staging file is gone.
        let scratch = Scratch::new("race-before-replace");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());

        let hook = late_retired(&scratch);
        store
            .faults
            .lock()
            .unwrap()
            .push((Point::BeforeReplace, Action::Run(Box::new(hook))));

        assert_eq!(
            store.replace(&state(LOCAL), &proposed_state()),
            Err(StoreError::UnresolvedNewerState)
        );

        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());
        retired_is_intact(&scratch);
        assert_eq!(
            names(&scratch.state_dir()).len(),
            2,
            "own temp must be gone"
        );
    }

    #[test]
    fn a_retired_file_inserted_at_the_rename_itself_is_not_prevented_but_detected_afterward() {
        // NOT PREVENTED, DETECTED AFTERWARD. After the last re-check and before the
        // rename nothing can look any more: the replacement completes, and the next
        // load refuses.
        let scratch = Scratch::new("race-at-replace");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());

        let hook = late_retired(&scratch);
        store
            .faults
            .lock()
            .unwrap()
            .push((Point::Replace, Action::Run(Box::new(hook))));

        assert_eq!(store.replace(&state(LOCAL), &proposed_state()), Ok(()));
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnresolvedNewerState)
        );
        retired_is_intact(&scratch);
    }

    #[test]
    fn a_retired_file_inserted_at_publication_is_not_prevented_but_detected_afterward() {
        // NOT PREVENTED, DETECTED AFTERWARD. `create` checks before it stages; a file
        // that appears at the no-clobber link is not seen by it. The record is
        // published, and the very next load refuses (a session's fresh load turns
        // that into an unverified outcome; see the session tests).
        let scratch = Scratch::new("race-publish");
        let store = scratch.store();

        store.run_before_publish_for_test(late_retired(&scratch));

        assert_eq!(store.create(&state(LOCAL)), Ok(()));
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());
        assert_eq!(
            store.load(&loc(LOCAL)),
            StateLoad::Unreadable(UnreadableReason::UnresolvedNewerState)
        );
        retired_is_intact(&scratch);
    }

    // ---- G12-RESET: held-handle removal (B3c-3b-2d-1) -----------------------------
    //
    // These three tests used to pin a KNOWN VULNERABILITY: the deletion resolved the
    // primary by path, a child process could overwrite it after the last comparison,
    // and the foreign bytes were removed under a normal "removed" result. The removal
    // now goes through handles that were held (read-only sharing) from the byte
    // comparison to the removal, so the same child write is REFUSED BY THE KERNEL. It
    // holds for ordinary processes only (see `held_removal`). The legacy REPLACE has
    // the old shape and is still open (G12-replace); its characterization is at the
    // end of this module.

    #[test]
    fn a_primary_overwrite_after_the_hold_is_refused_by_the_kernel_g12_reset() {
        // REAL NTFS, real child process, synthetic bytes. Formerly
        // `a_primary_replaced_after_the_final_comparison_is_removed_known_unprevented_race_g12`.
        let scratch = Scratch::new("race-g12-store");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());

        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        let root = scratch.root();
        let record = scratch.record(LOCAL);
        let hook_record = record.clone();

        store.run_before_primary_removal_for_test(move || {
            // The child cannot write; the verified object is still exactly what was verified.
            child_put_fails(&root, &hook_record, FOREIGN);
            assert_eq!(fs::read(&hook_record).unwrap(), v1_bytes());
        });

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Ok(DeleteOutcome::Removed)
        );

        // Only the verified object existed, and it is the one that went.
        assert!(!record.exists());
        assert!(names(&scratch.state_dir()).is_empty());
        assert!(!scratch.root().join("child-source.bin").exists());
    }

    #[test]
    fn a_temp_overwrite_after_the_hold_is_refused_by_the_kernel_g12_reset() {
        // REAL NTFS, same for a recognized legacy temp file. Formerly
        // `a_temp_replaced_after_the_final_comparison_is_removed_known_unprevented_race_g12`.
        let scratch = Scratch::new("race-g12-temp");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        scratch.put(&scratch.staging(LOCAL, TOKEN), b"debris");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        let root = scratch.root();
        let temp = scratch.staging(LOCAL, TOKEN);

        store.faults.lock().unwrap().push((
            Point::RemoveArtifact,
            Action::Run(Box::new(move || {
                child_put_fails(&root, &temp, FOREIGN);
                assert_eq!(fs::read(&temp).unwrap(), b"debris");
            })),
        ));

        assert_eq!(
            store.delete_if_evidence_matches(&loc(LOCAL), &evidence),
            Ok(DeleteOutcome::Removed)
        );
        assert!(names(&scratch.state_dir()).is_empty());
    }

    #[test]
    fn a_retired_file_present_beforehand_is_never_part_of_any_removal() {
        // The gate refuses before any hold, so a retired file that is already there is
        // never part of a removal: nothing is removed at all. Formerly
        // `the_known_races_never_touch_a_retired_file_even_when_one_is_present_beforehand`.
        let scratch = Scratch::new("race-retired-first");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        scratch.put(&scratch.retired(LOCAL, RETIRED_TOKEN), LATE);

        let before = snapshot(scratch.dir.path());

        assert!(store
            .delete_if_evidence_matches(&loc(LOCAL), &super::b3c3b2a_support::empty_evidence())
            .is_err());
        assert_eq!(snapshot(scratch.dir.path()), before);
    }

    // ---- KNOWN UNFIXED G12-REPLACE (characterization, not a fix) ------------------

    #[test]
    fn a_primary_replaced_at_the_rename_is_overwritten_known_unprevented_race_g12_replace() {
        // KNOWN UNFIXED G12-REPLACE, gate OPEN, NOT ACCEPTABLE behaviour, and NOT a
        // passing security property. REAL NTFS, synthetic bytes only. The legacy
        // replacement checks the primary, then renames its staging file over whatever
        // the name holds at that instant, with no handle held on the primary. A child
        // process overwrites the primary at `Point::Replace`; `replace` returns Ok and
        // the foreign bytes are gone. No registered command reaches `replace` today.
        // This test pins the present behaviour so a change is noticed; the fix is the
        // separate slice 2d-2 (decision U11), not this one.
        let scratch = Scratch::new("race-g12-replace");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());

        let root = scratch.root();
        let record = scratch.record(LOCAL);
        let hook_record = record.clone();

        store.faults.lock().unwrap().push((
            Point::Replace,
            Action::Run(Box::new(move || child_puts(&root, &hook_record, FOREIGN))),
        ));

        assert_eq!(store.replace(&state(LOCAL), &proposed_state()), Ok(()));
        assert_eq!(
            fs::read(&record).unwrap(),
            proposed_state().encode().unwrap(),
            "the foreign bytes were overwritten without a trace"
        );
    }
}

// ---- B3c-3b-2a forced race tests (end) ---------------------------------------

// ---- B3c-3b-2d-1 handle-bound reset tests (begin) -----------------------------------

/// Stage 1U-4 B3c-3b-2d-1. The handle-bound legacy reset (G12-reset).
///
/// Every test labels its class: **REAL NTFS** (real files, handles and, where a foreign
/// writer is needed, a real child `cmd.exe`), **INJECTED** (a test-only fault or a
/// substituted native status), **PURE** (no filesystem) or **UNAVAILABLE** (documented
/// as not exercised). Scratch is under `.qa-local` only; the bytes are synthetic. A
/// kernel refusal shown here binds ordinary processes only; nothing here is a stress
/// test and none claims a race-prevention guarantee beyond what the sharing model
/// gives.
#[cfg(all(test, windows))]
mod held_reset_tests {
    use std::{
        fs,
        os::windows::fs::OpenOptionsExt,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use super::b3c3b1_support::{
        loc, names, state, Scratch, LOCAL, OTHER_LOCAL, RETIRED_TOKEN, TOKEN,
    };
    use super::b3c3b2a_support::{child_puts, v1_bytes};
    use super::*;
    use crate::vault::handle_ops::{
        inject_delete_status,
        test_support::{make_junction, snapshot},
    };

    const FOREIGN: &[u8] = b"SYNTHETIC-FOREIGN-BYTES-NOT-A-REAL-RECORD";
    const TOKEN2: &str = "fedcba9876543210fedcba9876543210";
    const DENIED: i32 = 0xC000_0022_u32 as i32;

    type Conditional = Result<DeleteOutcome, ConditionalDeleteError>;

    fn at(store: &SyncStateStore, point: Point, run: impl Fn() + Send + 'static) {
        store
            .faults
            .lock()
            .unwrap()
            .push((point, Action::Run(Box::new(run))));
    }

    fn refused(refusal: RemovalRefusal) -> Conditional {
        Err(ConditionalDeleteError::Store(StoreError::RemovalRefused(
            refusal,
        )))
    }

    fn incomplete() -> Conditional {
        Err(ConditionalDeleteError::Store(
            StoreError::IncompleteDeletion,
        ))
    }

    /// Run a real child `cmd.exe` and report whether it succeeded.
    fn cmd(args: &[&std::ffi::OsStr]) -> bool {
        std::process::Command::new("cmd")
            .arg("/C")
            .args(args)
            .output()
            .unwrap()
            .status
            .success()
    }

    /// A record and one `.tmp`, the evidence of both.
    fn record_and_tmp(name: &str) -> (Scratch, SyncStateStore, RecordEvidence) {
        let scratch = Scratch::new(name);
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        scratch.put(&scratch.staging(LOCAL, TOKEN), b"debris");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        (scratch, store, evidence)
    }

    /// The `create` remnant: the record and one `.tmp` are two names of ONE file.
    fn alias_remnant(name: &str) -> (Scratch, SyncStateStore, RecordEvidence) {
        let scratch = Scratch::new(name);
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        fs::hard_link(scratch.record(LOCAL), scratch.staging(LOCAL, TOKEN)).unwrap();

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        (scratch, store, evidence)
    }

    fn delete(store: &SyncStateStore, evidence: &RecordEvidence) -> Conditional {
        store.delete_if_evidence_matches(&loc(LOCAL), evidence)
    }

    /// Name and exact bytes of every file that does not belong to this location.
    fn neighbours(scratch: &Scratch) -> Vec<(String, Vec<u8>)> {
        let key = record_key(&loc(LOCAL));

        names(&scratch.state_dir())
            .into_iter()
            .filter(|name| !name.starts_with(&key))
            .map(|name| {
                let bytes = fs::read(scratch.state_dir().join(&name)).unwrap();

                (name, bytes)
            })
            .collect()
    }

    // ---- ordinary resets --------------------------------------------------------------

    #[test]
    fn real_a_single_file_and_a_multi_file_reset_remove_exactly_this_locations_files() {
        // REAL NTFS.
        let scratch = Scratch::new("2d1-single");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        assert_eq!(delete(&store, &evidence), Ok(DeleteOutcome::Removed));
        assert!(names(&scratch.state_dir()).is_empty());

        // Multi-file, with another location's files and an unrelated file beside.
        let (scratch, store, _) = record_and_tmp("2d1-multi");
        scratch.put(&scratch.staging(LOCAL, TOKEN2), b"");
        scratch.put(
            &scratch.record(OTHER_LOCAL),
            &state(OTHER_LOCAL).encode().unwrap(),
        );
        scratch.put(&scratch.staging(OTHER_LOCAL, TOKEN), b"other staging");
        scratch.put(&scratch.state_dir().join("unrelated.txt"), b"unrelated");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        let others = neighbours(&scratch);

        assert_eq!(others.len(), 3);
        assert_eq!(delete(&store, &evidence), Ok(DeleteOutcome::Removed));
        assert_eq!(neighbours(&scratch), others, "another key's files moved");
        assert_eq!(names(&scratch.state_dir()).len(), 3);
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);

        // The unconditional variant too.
        let (scratch, store, _) = record_and_tmp("2d1-multi-delete");

        assert_eq!(store.delete(&loc(LOCAL)), Ok(DeleteOutcome::Removed));
        assert!(names(&scratch.state_dir()).is_empty());
    }

    #[test]
    fn real_an_upper_case_primary_name_is_removed_by_handle() {
        // REAL NTFS. NTFS resolves the case variant to the same object.
        let scratch = Scratch::new("2d1-upper");
        let store = scratch.store();
        let key = record_key(&loc(LOCAL));
        let upper = scratch
            .state_dir()
            .join(format!("{}.JSON", key.to_ascii_uppercase()));

        scratch.put(&upper, &v1_bytes());

        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        assert!(evidence.primary_present());
        assert_eq!(delete(&store, &evidence), Ok(DeleteOutcome::Removed));
        assert!(names(&scratch.state_dir()).is_empty());
    }

    // ---- holds refused ------------------------------------------------------------------

    #[test]
    fn real_a_file_open_elsewhere_without_delete_sharing_refuses_with_nothing_removed() {
        // REAL NTFS. A reader that shares only reading, and a writer, both refuse as
        // Busy; an exclusive handle cannot even be read, so evidence refuses.
        for target in ["record", "tmp"] {
            for (label, share, write) in [("read-share only", 1u32, false), ("writer", 7, true)] {
                let (scratch, store, evidence) = record_and_tmp("2d1-busy");
                let path = if target == "record" {
                    scratch.record(LOCAL)
                } else {
                    scratch.staging(LOCAL, TOKEN)
                };
                let before = snapshot(scratch.dir.path());

                {
                    let _other = fs::OpenOptions::new()
                        .read(true)
                        .write(write)
                        .share_mode(share)
                        .open(&path)
                        .unwrap();

                    assert_eq!(
                        delete(&store, &evidence),
                        refused(RemovalRefusal::Busy),
                        "{target} {label}"
                    );
                }

                assert_eq!(snapshot(scratch.dir.path()), before, "{target} {label}");
            }

            let (scratch, store, evidence) = record_and_tmp("2d1-exclusive");
            let path = if target == "record" {
                scratch.record(LOCAL)
            } else {
                scratch.staging(LOCAL, TOKEN)
            };
            let before = snapshot(scratch.dir.path());

            {
                let _other = fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .open(&path)
                    .unwrap();

                assert!(
                    matches!(
                        delete(&store, &evidence),
                        Err(ConditionalDeleteError::Evidence(_))
                            | Err(ConditionalDeleteError::Store(StoreError::Io { .. }))
                    ),
                    "{target} exclusive"
                );
            }

            assert_eq!(snapshot(scratch.dir.path()), before, "{target} exclusive");
        }
    }

    #[test]
    fn real_a_reader_that_shares_everything_does_not_block_the_removal() {
        // REAL NTFS. The reader is opened inside the removal and kept past it.
        let (scratch, store, evidence) = record_and_tmp("2d1-reader");
        let kept: Arc<Mutex<Vec<fs::File>>> = Arc::default();
        let held_open = Arc::clone(&kept);
        let record = scratch.record(LOCAL);
        let temp = scratch.staging(LOCAL, TOKEN);

        at(&store, Point::RemoveArtifact, move || {
            held_open
                .lock()
                .unwrap()
                .push(fs::File::open(&temp).unwrap());
            held_open
                .lock()
                .unwrap()
                .push(fs::File::open(&record).unwrap());
        });

        assert_eq!(delete(&store, &evidence), Ok(DeleteOutcome::Removed));
        assert!(names(&scratch.state_dir()).is_empty());
        assert_eq!(kept.lock().unwrap().len(), 2);
    }

    #[test]
    fn real_a_name_outside_the_plan_refuses_with_all_names_intact() {
        // REAL NTFS. U10b: a hard link outside the plan refuses.
        for target in ["record", "tmp"] {
            let (scratch, store, evidence) = record_and_tmp("2d1-outside-link");
            let path = if target == "record" {
                scratch.record(LOCAL)
            } else {
                scratch.staging(LOCAL, TOKEN)
            };

            fs::hard_link(&path, scratch.root().join("outside-link.bin")).unwrap();

            let before = snapshot(scratch.dir.path());

            assert_eq!(
                delete(&store, &evidence),
                refused(RemovalRefusal::ExtraNames),
                "{target}"
            );
            assert_eq!(
                store.delete(&loc(LOCAL)),
                Err(StoreError::RemovalRefused(RemovalRefusal::ExtraNames)),
                "{target}"
            );
            assert_eq!(snapshot(scratch.dir.path()), before, "{target}");
        }
    }

    // ---- the create alias remnant -----------------------------------------------------------

    #[test]
    fn real_the_create_alias_remnant_stays_resettable_and_both_names_go() {
        // REAL NTFS. The primary and one `.tmp` are two names of one file (links = 2).
        let (scratch, store, evidence) = alias_remnant("2d1-alias");
        scratch.put(
            &scratch.record(OTHER_LOCAL),
            &state(OTHER_LOCAL).encode().unwrap(),
        );
        let others = neighbours(&scratch);

        assert!(evidence.primary_present());
        assert_eq!(evidence.artifact_count(), 1);
        assert_eq!(delete(&store, &evidence), Ok(DeleteOutcome::Removed));
        assert_eq!(neighbours(&scratch), others);
        assert_eq!(names(&scratch.state_dir()).len(), 1);
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);

        // The unconditional variant (no bytes read).
        let (scratch, store, _) = alias_remnant("2d1-alias-delete");

        assert_eq!(store.delete(&loc(LOCAL)), Ok(DeleteOutcome::Removed));
        assert!(names(&scratch.state_dir()).is_empty());

        // The alias beside another, ordinary `.tmp`.
        let (scratch, store, _) = alias_remnant("2d1-alias-plus");
        scratch.put(&scratch.staging(LOCAL, TOKEN2), b"debris");
        let evidence = store.evidence(&loc(LOCAL)).unwrap();

        assert_eq!(evidence.artifact_count(), 2);
        assert_eq!(delete(&store, &evidence), Ok(DeleteOutcome::Removed));
        assert!(names(&scratch.state_dir()).is_empty());
    }

    #[test]
    fn real_an_alias_whose_record_name_is_unlinked_after_the_hold_is_refused_before_removal() {
        // REAL NTFS. Measured: the other name of a held file is NOT protected from an
        // unlink. Done at AfterHold, the recheck sees the record gone (PlanChanged).
        let (scratch, store, evidence) = alias_remnant("2d1-alias-unlink");
        let record = scratch.record(LOCAL);

        at(&store, Point::AfterHold, move || {
            fs::remove_file(&record).unwrap();
        });

        assert_eq!(
            delete(&store, &evidence),
            refused(RemovalRefusal::PlanChanged)
        );
        assert!(
            scratch.staging(LOCAL, TOKEN).exists(),
            "nothing was removed"
        );
        assert_eq!(fs::read(scratch.staging(LOCAL, TOKEN)).unwrap(), v1_bytes());
    }

    #[test]
    fn real_an_alias_whose_record_name_is_swapped_after_its_artifact_went_preserves_the_foreign_file(
    ) {
        // REAL NTFS. Two artifacts, the alias first. After the alias `.tmp` was marked
        // and closed, and before the record is reopened, a foreign file takes the
        // record's name. The reopen must find a different file: IncompleteDeletion and
        // the foreign file is preserved.
        let scratch = Scratch::new("2d1-alias-swap");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        fs::hard_link(scratch.record(LOCAL), scratch.staging(LOCAL, TOKEN)).unwrap();
        scratch.put(&scratch.staging(LOCAL, TOKEN2), b"debris");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        let root = scratch.root();
        let record = scratch.record(LOCAL);
        let hits = Arc::new(AtomicUsize::new(0));

        at(&store, Point::RemoveArtifact, move || {
            // The second artifact's hook runs after the alias was marked and closed.
            if hits.fetch_add(1, Ordering::SeqCst) == 1 {
                fs::remove_file(&record).unwrap();
                child_puts(&root, &record, FOREIGN);
            }
        });

        let result = delete(&store, &evidence);

        assert_eq!(result, incomplete());
        assert!(result.unwrap_err().removal_may_have_started());
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), FOREIGN);
        // Both held artifacts went (the second one's hook runs before its own mark);
        // the foreign file at the record's name was never touched.
        assert!(!scratch.staging(LOCAL, TOKEN).exists());
        assert!(!scratch.staging(LOCAL, TOKEN2).exists());
        assert_eq!(names(&scratch.state_dir()).len(), 1);
    }

    #[test]
    fn real_two_temp_names_of_one_file_are_refused() {
        // REAL NTFS. Two `.tmp` aliases of each other (and no record): refused, nothing
        // removed. (The sharing mode of the first hold excludes the second name, so the
        // refusal is Busy or ExtraNames.)
        let scratch = Scratch::new("2d1-two-tmp");
        let store = scratch.store();

        scratch.put(&scratch.staging(LOCAL, TOKEN), b"debris");
        fs::hard_link(
            scratch.staging(LOCAL, TOKEN),
            scratch.staging(LOCAL, TOKEN2),
        )
        .unwrap();

        let before = snapshot(scratch.dir.path());
        let result = store.delete(&loc(LOCAL));

        assert!(
            matches!(
                result,
                Err(StoreError::RemovalRefused(
                    RemovalRefusal::Busy | RemovalRefusal::ExtraNames
                ))
            ),
            "{result:?}"
        );
        assert_eq!(snapshot(scratch.dir.path()), before);
    }

    // ---- swaps and substitutions before the hold --------------------------------------------

    #[test]
    fn real_a_foreign_file_swapped_in_before_the_hold_is_detected_and_left_intact() {
        // REAL NTFS, real child. Done at BeforeHold, after the path evidence matched.
        for target in ["record", "tmp"] {
            let (scratch, store, evidence) = record_and_tmp("2d1-swap");
            let root = scratch.root();
            let path = if target == "record" {
                scratch.record(LOCAL)
            } else {
                scratch.staging(LOCAL, TOKEN)
            };
            let hook_path = path.clone();

            at(&store, Point::BeforeHold, move || {
                fs::remove_file(&hook_path).unwrap();
                child_puts(&root, &hook_path, FOREIGN);
            });

            let result = delete(&store, &evidence);

            assert_eq!(
                result,
                Err(ConditionalDeleteError::EvidenceChanged),
                "{target}"
            );
            assert!(!result.unwrap_err().removal_may_have_started());
            assert_eq!(fs::read(&path).unwrap(), FOREIGN, "{target}: foreign bytes");
            assert_eq!(names(&scratch.state_dir()).len(), 2, "{target}");
        }
    }

    #[test]
    fn real_a_file_that_grew_past_the_bound_before_the_hold_is_a_changed_file() {
        // REAL NTFS. The held read is bounded: a longer file is "changed", never a
        // truncated read.
        let (scratch, store, evidence) = record_and_tmp("2d1-grown");
        let temp = scratch.staging(LOCAL, TOKEN);
        let grown = temp.clone();

        at(&store, Point::BeforeHold, move || {
            let file = fs::OpenOptions::new().write(true).open(&grown).unwrap();

            file.set_len(MAX_SYNC_STATE_BYTES as u64 + 1).unwrap();
        });

        assert_eq!(
            delete(&store, &evidence),
            Err(ConditionalDeleteError::EvidenceChanged)
        );
        assert!(scratch.record(LOCAL).exists());
        assert!(temp.exists());
    }

    #[test]
    fn real_a_junction_or_directory_or_symlink_at_a_name_before_the_hold_is_refused() {
        // REAL NTFS. The foreign contents behind each are untouched.
        for (label, target_name) in [("junction", "tmp"), ("directory", "record")] {
            let (scratch, store, evidence) = record_and_tmp("2d1-unsuitable");
            let path = if target_name == "record" {
                scratch.record(LOCAL)
            } else {
                scratch.staging(LOCAL, TOKEN)
            };
            let elsewhere = scratch.root().join("elsewhere");
            let hook_path = path.clone();
            let hook_elsewhere = elsewhere.clone();
            let junction = label == "junction";

            fs::create_dir_all(&elsewhere).unwrap();
            fs::write(elsewhere.join("inside.bin"), b"keep").unwrap();

            at(&store, Point::BeforeHold, move || {
                fs::remove_file(&hook_path).unwrap();

                if junction {
                    make_junction(&hook_path, &hook_elsewhere);
                } else {
                    fs::create_dir(&hook_path).unwrap();
                    fs::write(hook_path.join("inside.bin"), b"keep").unwrap();
                }
            });

            assert_eq!(
                delete(&store, &evidence),
                refused(RemovalRefusal::FileUnsuitable),
                "{label}"
            );
            assert_eq!(
                fs::read(elsewhere.join("inside.bin")).unwrap(),
                b"keep",
                "{label}"
            );
        }

        // A file symlink needs a privilege this account may lack: UNAVAILABLE if so.
        let (scratch, store, evidence) = record_and_tmp("2d1-symlink");
        let temp = scratch.staging(LOCAL, TOKEN);
        let foreign = scratch.root().join("symlink-target.bin");

        fs::write(&foreign, b"keep").unwrap();
        fs::remove_file(&temp).unwrap();

        if std::os::windows::fs::symlink_file(&foreign, &temp).is_err() {
            println!("UNAVAILABLE: this account cannot create a file symlink; case not run");

            return;
        }

        // The evidence refused it already (a reparse point), before any hold.
        assert!(store.evidence(&loc(LOCAL)).is_err());
        assert!(delete(&store, &evidence).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"keep");
    }

    #[test]
    fn real_a_state_directory_replaced_by_a_junction_before_the_hold_is_refused() {
        // REAL NTFS. The directory is moved away and a junction to it takes its place at
        // BeforeHold; the pin refuses it and the contents are intact.
        let (scratch, store, evidence) = record_and_tmp("2d1-dir-junction");
        let state_dir = scratch.state_dir();
        let moved = scratch.root().join("moved-state");
        let hook_state = state_dir.clone();
        let hook_moved = moved.clone();

        at(&store, Point::BeforeHold, move || {
            fs::rename(&hook_state, &hook_moved).unwrap();
            make_junction(&hook_state, &hook_moved);
        });

        assert_eq!(
            delete(&store, &evidence),
            refused(RemovalRefusal::DirectoryUnsupported)
        );
        assert_eq!(
            fs::read(moved.join(format!("{}.json", record_key(&loc(LOCAL))))).unwrap(),
            v1_bytes()
        );
        assert_eq!(names(&moved).len(), 2);
    }

    #[test]
    fn real_the_state_directory_cannot_be_renamed_while_it_is_pinned() {
        // REAL NTFS, real child `ren` at AfterHold.
        let (scratch, store, evidence) = record_and_tmp("2d1-dir-rename");
        let state_dir = scratch.state_dir();
        let renamed = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&renamed);

        at(&store, Point::AfterHold, move || {
            flag.store(
                cmd(&[
                    std::ffi::OsStr::new("ren"),
                    state_dir.as_os_str(),
                    std::ffi::OsStr::new("renamed-state"),
                ]),
                Ordering::SeqCst,
            );
        });

        assert_eq!(delete(&store, &evidence), Ok(DeleteOutcome::Removed));
        assert!(
            !renamed.load(Ordering::SeqCst),
            "the child renamed the directory"
        );
        assert!(scratch.state_dir().exists());
        assert!(!scratch.root().join("renamed-state").exists());
    }

    // ---- changes after the hold ---------------------------------------------------------------

    #[test]
    fn real_a_new_name_or_new_entry_after_the_hold_refuses_with_nothing_removed() {
        // REAL NTFS, at AfterHold (before the first removal).
        // A hard link to the record (a new name) -> ExtraNames.
        let (scratch, store, evidence) = record_and_tmp("2d1-new-link");
        let record = scratch.record(LOCAL);
        let outside = scratch.root().join("late-link.bin");

        at(&store, Point::AfterHold, move || {
            fs::hard_link(&record, &outside).unwrap();
        });

        assert_eq!(
            delete(&store, &evidence),
            refused(RemovalRefusal::ExtraNames)
        );
        assert_eq!(names(&scratch.state_dir()).len(), 2);
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());

        // A new `.tmp` -> PlanChanged.
        let (scratch, store, evidence) = record_and_tmp("2d1-new-tmp");
        let new_tmp = scratch.staging(LOCAL, TOKEN2);

        at(&store, Point::AfterHold, move || {
            fs::write(&new_tmp, b"late").unwrap()
        });

        assert_eq!(
            delete(&store, &evidence),
            refused(RemovalRefusal::PlanChanged)
        );
        assert_eq!(names(&scratch.state_dir()).len(), 3);

        // A primary appearing on a remnant-only plan -> PlanChanged, remnants intact.
        let scratch = Scratch::new("2d1-new-primary");
        let store = scratch.store();

        scratch.put(&scratch.staging(LOCAL, TOKEN), b"debris");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        let record = scratch.record(LOCAL);
        let root = scratch.root();

        at(&store, Point::AfterHold, move || {
            child_puts(&root, &record, FOREIGN)
        });

        assert_eq!(
            delete(&store, &evidence),
            refused(RemovalRefusal::PlanChanged)
        );
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), FOREIGN);
        assert_eq!(fs::read(scratch.staging(LOCAL, TOKEN)).unwrap(), b"debris");
    }

    #[test]
    fn real_newer_state_that_appears_after_the_hold_refuses_with_nothing_removed() {
        // REAL NTFS. U2 and U9: a retired file, a reserved staging name or an
        // unrecognized key-prefixed entry is never part of a plan; if one appears after
        // the hold, the recheck refuses.
        let key = record_key(&loc(LOCAL));

        for (label, name, expected) in [
            (
                "retired",
                format!("{key}.{RETIRED_TOKEN}.retired"),
                StoreError::UnresolvedNewerState,
            ),
            (
                "reserved staging",
                format!("{key}.{RETIRED_TOKEN}.v3stage"),
                StoreError::UnresolvedNewerState,
            ),
            (
                "unrecognized",
                format!("{key}.notes.txt"),
                StoreError::UnrecognizedEntries,
            ),
        ] {
            let (scratch, store, evidence) = record_and_tmp("2d1-newer");
            let late = scratch.state_dir().join(name);
            let hook_late = late.clone();

            at(&store, Point::AfterHold, move || {
                fs::write(&hook_late, b"late").unwrap()
            });

            assert_eq!(
                delete(&store, &evidence),
                Err(ConditionalDeleteError::Store(expected)),
                "{label}"
            );
            assert_eq!(fs::read(&late).unwrap(), b"late", "{label}: never touched");
            assert_eq!(
                fs::read(scratch.record(LOCAL)).unwrap(),
                v1_bytes(),
                "{label}"
            );
            assert_eq!(
                fs::read(scratch.staging(LOCAL, TOKEN)).unwrap(),
                b"debris",
                "{label}"
            );
        }
    }

    #[test]
    fn real_a_hard_link_created_just_before_the_primary_mark_is_refused_and_the_primary_intact() {
        // REAL NTFS, at RemovePrimary (after every check but the facts recheck).
        // Without artifacts nothing has been removed: a refusal.
        let scratch = Scratch::new("2d1-link-primary");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());

        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        let record = scratch.record(LOCAL);
        let outside = scratch.root().join("late-link.bin");

        store.run_before_primary_removal_for_test(move || {
            fs::hard_link(&record, &outside).unwrap();
        });

        assert_eq!(
            delete(&store, &evidence),
            refused(RemovalRefusal::ExtraNames)
        );
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());

        // With an artifact already removed, the same event is a partial removal.
        let (scratch, store, evidence) = record_and_tmp("2d1-link-primary-partial");
        let record = scratch.record(LOCAL);
        let outside = scratch.root().join("late-link.bin");

        store.run_before_primary_removal_for_test(move || {
            fs::hard_link(&record, &outside).unwrap();
        });

        let result = delete(&store, &evidence);

        assert_eq!(result, incomplete());
        assert!(result.unwrap_err().removal_may_have_started());
        assert!(!scratch.staging(LOCAL, TOKEN).exists());
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());
    }

    #[test]
    fn real_a_foreign_file_at_the_name_after_the_handles_closed_is_preserved_and_not_success() {
        // REAL NTFS, real child, at AfterClose. The removal is verified by name AFTER
        // the handles closed: a file there is IncompleteDeletion, never Removed.
        let (scratch, store, evidence) = record_and_tmp("2d1-after-close");
        let root = scratch.root();
        let record = scratch.record(LOCAL);

        store.run_after_close_for_test(move || child_puts(&root, &record, FOREIGN));

        let result = delete(&store, &evidence);

        assert_eq!(result, incomplete());
        assert!(result.unwrap_err().removal_may_have_started());
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), FOREIGN);
        assert!(!scratch.staging(LOCAL, TOKEN).exists());

        // The same for a new recognized artifact at the same point.
        let (scratch, store, evidence) = record_and_tmp("2d1-after-close-tmp");
        let late = scratch.staging(LOCAL, TOKEN2);

        store.run_after_close_for_test({
            let late = late.clone();

            move || fs::write(&late, b"late").unwrap()
        });

        assert_eq!(delete(&store, &evidence), incomplete());
        assert_eq!(fs::read(&late).unwrap(), b"late");
    }

    #[test]
    fn real_a_second_reset_inside_the_first_is_refused_as_busy() {
        // REAL NTFS. A second store instance runs the conditional deletion inside the
        // first's AfterHold: the files are held, so it gets Busy and removes nothing;
        // the first completes.
        let (scratch, store, evidence) = record_and_tmp("2d1-concurrent");
        let second = scratch.store();
        let inner: Arc<Mutex<Option<Conditional>>> = Arc::default();
        let slot = Arc::clone(&inner);
        let expected = evidence.clone();

        at(&store, Point::AfterHold, move || {
            *slot.lock().unwrap() = Some(second.delete_if_evidence_matches(&loc(LOCAL), &expected));
        });

        assert_eq!(delete(&store, &evidence), Ok(DeleteOutcome::Removed));
        assert_eq!(
            inner.lock().unwrap().take(),
            Some(refused(RemovalRefusal::Busy))
        );
        assert!(names(&scratch.state_dir()).is_empty());
    }

    // ---- INJECTED: partial results and unknown statuses ----------------------------------------

    #[test]
    fn injected_a_failure_after_one_artifact_is_a_partial_removal_never_a_success() {
        // INJECTED. The second artifact's handle delete reports an error status.
        let scratch = Scratch::new("2d1-inj-second");
        let store = scratch.store();

        scratch.put(&scratch.record(LOCAL), &v1_bytes());
        scratch.put(&scratch.staging(LOCAL, TOKEN), b"one");
        scratch.put(&scratch.staging(LOCAL, TOKEN2), b"two");

        let evidence = store.evidence(&loc(LOCAL)).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));

        at(&store, Point::RemoveArtifact, move || {
            if hits.fetch_add(1, Ordering::SeqCst) == 1 {
                inject_delete_status(DENIED);
            }
        });

        let result = delete(&store, &evidence);

        assert_eq!(result, incomplete());
        assert!(result.unwrap_err().removal_may_have_started());
        assert!(!scratch.staging(LOCAL, TOKEN).exists());
        assert_eq!(fs::read(scratch.staging(LOCAL, TOKEN2)).unwrap(), b"two");
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());
        assert_ne!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);
    }

    #[test]
    fn injected_a_failure_before_the_primary_leaves_the_artifacts_gone_and_the_primary_intact() {
        // INJECTED.
        let (scratch, store, evidence) = record_and_tmp("2d1-inj-primary");

        store.run_before_primary_removal_for_test(|| inject_delete_status(DENIED));

        let result = delete(&store, &evidence);

        assert_eq!(result, incomplete());
        assert!(result.unwrap_err().removal_may_have_started());
        assert!(!scratch.staging(LOCAL, TOKEN).exists());
        assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());
    }

    #[test]
    fn injected_an_error_status_marks_nothing_and_a_silent_success_is_unknown() {
        // INJECTED. Both are IncompleteDeletion, neither is retried, nothing but the
        // verified file is ever removed.
        for status in [DENIED, 0xC000_0001_u32 as i32, 0xC000_0043_u32 as i32, 1, 0] {
            let scratch = Scratch::new("2d1-inj-status");
            let store = scratch.store();

            scratch.put(&scratch.record(LOCAL), &v1_bytes());

            let evidence = store.evidence(&loc(LOCAL)).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);

            store.run_before_primary_removal_for_test(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                inject_delete_status(status);
            });

            let result = delete(&store, &evidence);

            assert_eq!(result, incomplete(), "status {status:#x}");
            assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry");
            assert_eq!(fs::read(scratch.record(LOCAL)).unwrap(), v1_bytes());
        }
    }

    #[test]
    fn injected_hook_faults_before_any_mark_keep_their_incomplete_meaning() {
        // INJECTED. The pre-existing contract of the removal hooks is unchanged.
        let (scratch, store, evidence) = record_and_tmp("2d1-hook-fault");

        store.faults.lock().unwrap().push((
            Point::RemoveArtifact,
            Action::Fail(io::ErrorKind::PermissionDenied),
        ));

        assert_eq!(delete(&store, &evidence), incomplete());
        assert_eq!(names(&scratch.state_dir()).len(), 2);
    }

    // ---- PURE ---------------------------------------------------------------------------------

    #[test]
    fn pure_the_link_rule_is_exact() {
        // PURE.
        assert_eq!(link_verdict(0), LinkVerdict::Refuse);
        assert_eq!(link_verdict(1), LinkVerdict::Single);
        assert_eq!(link_verdict(2), LinkVerdict::Pair);

        for links in [3, 4, 255, u32::MAX] {
            assert_eq!(link_verdict(links), LinkVerdict::Refuse, "{links}");
        }
    }

    #[test]
    fn pure_a_changed_fact_is_a_refusal_only_while_nothing_has_been_removed() {
        // PURE.
        assert_eq!(
            changed_fact(false),
            StoreError::RemovalRefused(RemovalRefusal::ExtraNames)
        );
        assert_eq!(changed_fact(true), StoreError::IncompleteDeletion);
    }

    #[test]
    fn pure_a_refusal_is_not_an_incomplete_deletion_and_reveals_nothing() {
        // PURE. A refusal never claims a removal may have started; its text is fixed.
        for refusal in [
            RemovalRefusal::Busy,
            RemovalRefusal::DirectoryUnsupported,
            RemovalRefusal::FileUnsuitable,
            RemovalRefusal::ExtraNames,
            RemovalRefusal::PlanChanged,
        ] {
            let error = ConditionalDeleteError::Store(StoreError::RemovalRefused(refusal));

            assert!(!error.removal_may_have_started());
            assert_eq!(
                StoreError::RemovalRefused(refusal).to_string(),
                "the sync-state files could not be held for removal; nothing was removed"
            );

            let shown = format!("{error} {error:?} {refusal:?}");

            for mark in [".tmp", ".json", "\\", ".qa-local", "0x"] {
                assert!(!shown.contains(mark), "{mark} in {shown}");
            }
        }

        assert!(
            ConditionalDeleteError::Store(StoreError::IncompleteDeletion)
                .removal_may_have_started()
        );
    }

    #[test]
    fn pure_no_path_based_removal_remains_in_the_deletion() {
        // PURE source scan of the production half.
        let production = include_str!("sync_state_store.rs");
        let production = &production[..production.find("\n#[cfg(test)]\nmod tests {").unwrap()];

        fn body(production: &str, signature: &str) -> String {
            let start = production
                .find(signature)
                .unwrap_or_else(|| panic!("{signature}"));
            let rest = &production[start + signature.len()..];
            let end = ["\n    pub fn ", "\n    fn ", "\n    pub(crate) fn "]
                .iter()
                .filter_map(|marker| rest.find(marker))
                .min()
                .unwrap_or(rest.len());

            rest[..end].to_owned()
        }

        for signature in [
            "pub fn delete(&self, local_locator: &Locator) -> Result<DeleteOutcome, StoreError> {",
            "pub fn delete_if_evidence_matches(",
            "fn execute_delete(",
            "fn hold_for_removal(",
            "fn recheck_held(",
            "fn recheck_layout(",
            "fn held_evidence(",
        ] {
            let text = body(production, signature);

            for forbidden in [
                "remove_file",
                "remove_dir",
                "hard_link",
                "fs::rename",
                "fs::write",
                "unsafe",
                "extern",
                "getrandom",
                ".remove(",
                "retired",
                "v3stage",
                "Reserved",
            ] {
                assert!(!text.contains(forbidden), "{forbidden:?} in {signature}");
            }
        }

        assert!(!production.contains("fn remove(&self, point"));
        assert_eq!(
            production.matches("remove_file").count(),
            3,
            "only create, replace, write_temp"
        );
        assert_eq!(production.matches("mark_for_removal()").count(), 2);
    }

    #[test]
    fn pure_the_deletion_plan_still_names_only_the_primary_and_tmp_artifacts() {
        // PURE. U2 / U9: nothing newer can enter a plan.
        let key = "a".repeat(64);

        for name in [format!("{key}.{TOKEN}.tmp"), format!("{}.{TOKEN}.TMP", key)] {
            assert!(is_artifact_name(&name, &key), "{name}");
        }
        for name in [
            format!("{key}.{TOKEN}.retired"),
            format!("{key}.{TOKEN}.v3stage"),
            format!("{key}.json"),
            format!("{key}.notes.txt"),
            format!("{key}.{TOKEN}.tmp.retired"),
            format!("{key}.{TOKEN}.tmp "),
        ] {
            assert!(!is_artifact_name(&name, &key), "{name}");
        }
    }

    // UNAVAILABLE / NOT TESTED: ReFS, SMB and FAT volumes (refusal rests on the
    // file-identity facts, tested purely in `held_removal`); 8.3 short names (none are
    // generated on this volume); case-sensitive directories; writable mapped views;
    // process kill, OS crash and power loss; and behaviour on the `C:` AppData volume.
}

// ---- B3c-3b-2d-1 handle-bound reset tests (end) -------------------------------------

// ---- B3c-3b-2a isolation tests (begin) ---------------------------------------

/// Source-level proofs about the shape of the change, in the manner of the existing
/// region scans: the gate region cannot mutate, nothing but the gate calls the
/// observation, and the legacy deletion grammar is unchanged.
#[cfg(all(test, windows))]
mod legacy_gate_isolation_tests {
    use super::*;

    fn source() -> &'static str {
        include_str!("sync_state_store.rs")
    }

    /// Everything before the test modules: the production half of this file.
    fn production() -> &'static str {
        let source = source();

        &source[..source
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("the first test module")]
    }

    fn gate_region() -> &'static str {
        let source = source();
        let start = source
            .find("\n// ---- legacy compatibility gate (read-only)")
            .expect("the begin marker");
        let end = start
            + source[start..]
                .find("\n// ---- end legacy compatibility gate")
                .expect("the end marker");

        &source[start..end]
    }

    /// The text of one method: from its signature to the next method.
    fn body_of(signature: &str) -> &'static str {
        let production = production();
        let start = production
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} not found"));
        let rest = &production[start + signature.len()..];
        let end = rest
            .find("\n    pub fn ")
            .into_iter()
            .chain(rest.find("\n    fn "))
            .chain(rest.find("\n    pub(crate) fn "))
            .min()
            .unwrap_or(rest.len());

        &rest[..end]
    }

    #[test]
    fn the_gate_region_only_observes() {
        let region = gate_region();

        assert!(region.contains("fn legacy_verdict"));
        assert!(region.contains("fn legacy_gate"));
        // (rustfmt may put the method call on its own line, so no `self` prefix.)
        assert!(region.contains(".observe_v3_layout("));
        assert!(!region.contains("#[cfg("));

        for forbidden in [
            "remove_file",
            "remove_dir",
            ".remove(",
            "rename",
            "hard_link",
            "create_new",
            "write_all",
            "sync_all",
            "OpenOptions",
            "fs::write",
            "fs::copy",
            "set_len",
            "truncate",
            "unsafe",
            "allow(",
            "getrandom",
            "new_v4",
            "scan_artifacts",
            "plan_delete",
            "execute_delete",
            "write_temp",
            "create_temp",
            "self.hook",
            "Point::",
            "thread",
            "Command",
            "inspect_v3_layout(",
            "read_primary",
            "File::",
            "fs::",
        ] {
            assert!(
                !region.contains(forbidden),
                "{forbidden:?} in the gate region"
            );
        }
    }

    #[test]
    fn no_function_of_the_gate_region_reads_like_a_permission_accessor() {
        for name in region_function_names(gate_region()) {
            for word in [
                "ready", "clean", "safe", "allow", "permit", "may_", "can_", "authoriz", "adopt",
                "recover", "release", "restore", "write", "delete", "remove", "publish",
                "finalize", "prefer", "approve", "grant",
            ] {
                assert!(!name.contains(word), "{name} looks like a {word} accessor");
            }
        }
    }

    fn region_function_names(region: &str) -> Vec<String> {
        region
            .split("fn ")
            .skip(1)
            .map(|rest| {
                rest.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect()
            })
            .collect()
    }

    #[test]
    fn every_legacy_operation_asks_the_gate_and_the_observation_has_one_production_caller() {
        for signature in [
            "pub fn load(&self, local_locator: &Locator) -> StateLoad {",
            "pub fn read_record(&self, local_locator: &Locator) -> RecordRead {",
            "pub fn create(&self, state: &SyncState) -> Result<(), StoreError> {",
            "pub fn evidence(&self, local_locator: &Locator) -> Result<RecordEvidence, EvidenceRefusal> {",
            "fn plan_delete(&self, local_locator: &Locator) -> Result<Option<DeletePlan>, StoreError> {",
        ] {
            assert!(
                body_of(signature).contains("self.legacy_gate("),
                "{signature} does not ask the gate"
            );
        }

        // `replace` asks twice: before it reads, and again before its rename.
        let replace = body_of(
            "pub fn replace(&self, expected: &SyncState, proposed: &SyncState) -> Result<(), StoreError> {",
        );
        assert_eq!(replace.matches("self.legacy_gate(").count(), 2);
        assert!(
            replace.find("self.legacy_gate(").unwrap()
                < replace.find("let temp = self.write_temp").unwrap()
        );
        assert!(
            replace.rfind("self.legacy_gate(").unwrap()
                < replace.find("self.hook(Point::Replace)").unwrap(),
            "the second check must come before the rename"
        );

        // `create` asks once and does not touch its temp cleanup.
        assert_eq!(
            body_of("pub fn create(&self, state: &SyncState) -> Result<(), StoreError> {")
                .matches("self.legacy_gate(")
                .count(),
            1
        );

        // The observation: one caller in the gate and one in the dormant diagnostic;
        // the diagnostic itself is never called by the production half of the store.
        let production = production();

        assert_eq!(production.matches(".observe_v3_layout(").count(), 2);
        assert_eq!(production.matches("inspect_v3_layout(").count(), 1);
    }

    #[test]
    fn the_legacy_deletion_grammar_is_unchanged_and_names_neither_newer_kind() {
        let production = production();

        assert!(production.contains("const ARTIFACT_EXTENSION: &str = \"tmp\";"));
        assert!(!production.contains("ARTIFACT_EXTENSION: &str = \"v3stage\""));

        // The artifact rule's body names neither extension.
        let start = production
            .find("fn is_artifact_name(name: &str, key: &str) -> bool {")
            .unwrap();
        let body = &production[start..start + production[start..].find("\n}\n").unwrap()];

        assert!(body.contains("ARTIFACT_EXTENSION"));
        assert!(!body.contains("v3stage"));
        assert!(!body.contains("retired"));

        // The deletion machinery never mentions the new names.
        for signature in [
            "fn scan_artifacts(&self, key: &str) -> Result<Vec<PathBuf>, Fault> {",
            "fn execute_delete(\n        &self,\n        plan: &DeletePlan,\n        held: HeldFiles,\n    ) -> Result<DeleteOutcome, StoreError> {",
        ] {
            let body = body_of(signature);

            assert!(!body.contains("v3stage"), "{signature}");
            assert!(!body.contains("retired"), "{signature}");
            assert!(!body.contains("Reserved"), "{signature}");
        }
    }

    #[test]
    fn nothing_in_production_creates_a_reserved_staging_file_or_adds_unsafe() {
        let production = production();

        // The reserved extension appears as one literal: the grammar arm.
        assert_eq!(production.matches("v3stage\"").count(), 1);
        assert!(production.contains("b\".v3stage\""));

        // No new unsafe, FFI or lint suppression in the production half.
        assert!(!production.contains("unsafe "));
        assert!(!production.contains("extern \""));
        assert!(!production.contains("#[allow("));
        assert!(!production.contains("#![allow("));
    }

    #[test]
    fn the_new_categories_are_fixed_and_reveal_nothing_when_printed() {
        fn has_hex_run(text: &str, run: usize) -> bool {
            let mut count = 0;

            for c in text.chars() {
                if c.is_ascii_hexdigit() {
                    count += 1;
                    if count >= run {
                        return true;
                    }
                } else {
                    count = 0;
                }
            }

            false
        }

        let mut shown = Vec::new();

        for error in [
            StoreError::UnresolvedNewerState,
            StoreError::LayoutUncertain,
            StoreError::UnrecognizedEntries,
        ] {
            shown.push(format!("{error}"));
            shown.push(format!("{error:?}"));
        }
        for reason in [
            UnreadableReason::UnresolvedNewerState,
            UnreadableReason::LayoutUncertain,
            UnreadableReason::UnrecognizedEntries,
        ] {
            shown.push(format!("{reason:?}"));
            shown.push(format!("{:?}", StateLoad::Unreadable(reason)));
            shown.push(format!("{:?}", RecordRead::Unreadable(reason)));
        }
        for refusal in [
            EvidenceRefusal::UnresolvedNewerState,
            EvidenceRefusal::UnrecognizedEntries,
        ] {
            shown.push(format!("{refusal}"));
            shown.push(format!("{refusal:?}"));
            shown.push(format!("{}", ConditionalDeleteError::Evidence(refusal)));
        }

        let key = record_key(&super::b3c3b1_support::loc(super::b3c3b1_support::LOCAL));

        for text in &shown {
            assert!(!has_hex_run(text, 16), "{text}");

            for mark in [
                key.as_str(),
                ".tmp",
                ".retired",
                ".v3stage",
                ".json",
                "\\",
                "LOCAL-MARKER",
            ] {
                assert!(!text.contains(mark), "{mark} leaked in {text}");
            }
        }
    }
}

// ---- B3c-3b-2a isolation tests (end) -----------------------------------------
