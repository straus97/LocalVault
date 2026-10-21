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
    pub fn delete(&self, local_locator: &Locator) -> Result<DeleteOutcome, StoreError> {
        match self.plan_delete(local_locator)? {
            None => Ok(DeleteOutcome::AlreadyAbsent),
            Some(plan) => self.execute_delete(&plan),
        }
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
    /// every target a plain file), then **immediately before the first removal**
    /// fresh evidence is captured and compared with `expected`; any difference,
    /// or any failure to capture it, refuses with nothing removed. Only then are
    /// the artifacts and finally the record removed and the removal verified,
    /// exactly as `delete` does. Nothing outside this location's record and its
    /// recognized artifacts is touched, and nothing is followed through a reparse
    /// point.
    ///
    /// # What this is not
    ///
    /// It is **not** compare-and-swap, and not atomic against another process:
    /// the evidence is read, then the files are removed, and a writer that is not
    /// bound by the exclusive per-vault session lock can still change them in
    /// between (the window is narrowed to the few calls between the comparison and
    /// the first removal, not closed). A file that changes after the comparison is
    /// either removed as it then is, or makes the final verification report
    /// `IncompleteDeletion`. The unlocked vault session lock must be held by the
    /// caller, as for every state operation.
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

        match plan {
            None => Ok(DeleteOutcome::AlreadyAbsent),
            Some(plan) => self
                .execute_delete(&plan)
                .map_err(ConditionalDeleteError::Store),
        }
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

    /// The removal and its verification. Artifacts first, the record last.
    fn execute_delete(&self, plan: &DeletePlan) -> Result<DeleteOutcome, StoreError> {
        for artifact in &plan.artifacts {
            self.remove(Point::RemoveArtifact, artifact)?;
        }
        if plan.record_present {
            self.remove(Point::RemovePrimary, &plan.record)?;
        }

        // Verify, treating "cannot tell" as incomplete.
        match fs::symlink_metadata(&plan.record) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(StoreError::IncompleteDeletion),
        }
        match self.scan_artifacts(&plan.key) {
            Ok(remaining) if remaining.is_empty() => Ok(DeleteOutcome::Removed),
            _ => Err(StoreError::IncompleteDeletion),
        }
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

    fn remove(&self, point: Point, path: &Path) -> Result<(), StoreError> {
        match self.hook(point).and_then(|()| fs::remove_file(path)) {
            Ok(()) => Ok(()),
            // Already gone is the goal; the final verification decides.
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StoreError::IncompleteDeletion),
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
            assert_eq!(
                store.replace(&state, &rebuilt(&state, checkpoint(10), None)),
                Err(StoreError::CurrentUnreadable)
            );
            assert_eq!(store.create(&state), Err(StoreError::AlreadyExists));
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

        // Files that only look related, and other records' artifacts, are not
        // this record's artifacts: they neither block nor get touched.
        fs::remove_file(&artifact).unwrap();
        let key = record_key(&loc(LOCAL));
        let unrelated = [
            scratch.state_dir().join(format!("{key}.notes.txt")),
            scratch.state_dir().join(format!("{key}.json.bak")),
            scratch
                .state_dir()
                .join(format!("{key}.{STALE_TOKEN}.tmp.old")),
            scratch.state_dir().join(format!("{key}.short.tmp")),
            scratch.artifact(OTHER_LOCAL, STALE_TOKEN),
        ];
        for path in &unrelated {
            fs::write(path, b"unrelated").unwrap();
        }
        assert_eq!(store.load(&loc(LOCAL)), StateLoad::NotConfigured);
        store.create(&unbased(LOCAL)).unwrap();
        for path in &unrelated {
            assert_eq!(fs::read(path).unwrap(), b"unrelated");
        }
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
        let key = record_key(&loc(LOCAL));
        let unrelated = scratch.state_dir().join(format!("{key}.notes.txt"));
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
    fn real_windows_deletion_failure_is_reported_as_incomplete() {
        let scratch = Scratch::new("delete-real-failure");
        let store = scratch.store();
        let state = based(LOCAL, 9);
        store.create(&state).unwrap();

        {
            let _guard = hold_exclusively(&scratch.record(LOCAL));
            assert_eq!(
                store.delete(&loc(LOCAL)),
                Err(StoreError::IncompleteDeletion)
            );
            assert!(scratch.record(LOCAL).exists());
        }
        assert_eq!(loaded(store.load(&loc(LOCAL))), state);

        // With an artifact held instead, the record must survive.
        scratch.put(&scratch.artifact(LOCAL, STALE_TOKEN), b"debris");
        {
            let _guard = hold_exclusively(&scratch.artifact(LOCAL, STALE_TOKEN));
            assert_eq!(
                store.delete(&loc(LOCAL)),
                Err(StoreError::IncompleteDeletion)
            );
            assert_eq!(loaded(store.load(&loc(LOCAL))), state);
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
        scratch.put(&scratch.record(OTHER_LOCAL), b"someone else's");
        let key = record_key(&loc(LOCAL));
        fs::write(scratch.state_dir().join(format!("{key}.notes.txt")), b"x").unwrap();
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
        let key = record_key(&loc(LOCAL));
        let unrelated = scratch.state_dir().join(format!("{key}.notes.txt"));
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
        assert_eq!(store.create(&state), Err(StoreError::AlreadyExists));
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
