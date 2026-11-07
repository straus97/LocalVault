//! Test-only, synthetic, handle-bound exchange of ONE legacy version-1 sync-state
//! record (Stage 1U-4, slice G12R-1).
//!
//! **This module is a measurement. It is test-only, synthetic and unreachable from
//! any production build or caller, and it authorizes nothing.** It is declared as
//! `#[cfg(all(test, windows))] mod ...` in `vault/mod.rs`, so it is not compiled into
//! a normal or a release build. The production `SyncStateStore::replace` is not
//! changed by it and does not call it.
//!
//! # What is measured
//!
//! Whether the primary record `<key>.json` of the legacy store can be replaced by a
//! new version-1 record **without any rename ever replacing an existing name**, using
//! only the existing native primitives, and how the UNCHANGED legacy store classifies
//! every intermediate state of that sequence. The sequence:
//!
//! 1. validate the contract (both records, the locator, the binding) before any I/O;
//! 2. pin the directory and judge it, check the ancestors and the directory listing;
//! 3. hold the old primary `P` (`GENERIC_READ | DELETE`, read-only sharing, no reparse
//!    follow), judge the handle, read it through the handle and validate it as the
//!    expected legacy version-1 record;
//! 4. create the staging object `S` exclusively, keep its handle, write, flush, sync
//!    and verify it;
//! 5. re-check both held objects, then rename `P` to the retention name `R` through
//!    the held handle (no replace), then rename `S` to the primary name through its
//!    handle (no replace);
//! 6. verify both objects and both names independently;
//! 7. classify every uncertain result. Nothing is removed, retried or repaired
//!    silently.
//!
//! Staging and retention both use the existing legacy artifact grammar
//! `<key>.<32 lowercase hex>.tmp`, so the unchanged legacy gate already recognizes
//! them and no new name family exists. `P`, `S` and `R` are distinguished by their
//! held handles and by physical identity, never by name.
//!
//! # Evidence classes
//!
//! * RUNTIME-ONLY: the sharing modes and the no-clobber property hold only while the
//!   handles are open, and only against ordinary processes.
//! * PROCESS-LEVEL: namespace outcomes observed after a handle was released or a
//!   real child process exited, on a running operating system.
//! * UNPROVEN: Windows shutdown, OS crash, power loss, the persistence atomicity or
//!   order of the two renames, directory durability and whether a flush is honoured
//!   by the device. Nothing here claims any of these.
//!
//! # Limits (not claimed away)
//!
//! * Privileged, backup-privileged and filter-driver actors bypass sharing modes.
//! * Writable mapped views are not addressed.
//! * A hard link created in the single call gap before a check is not prevented.
//! * The opens before the pin are by path.
//! * Nothing flushes the directory.
//! * Measured on Windows 10 build 19045, local NTFS on `D:` only.
//!
//! # Ownership
//!
//! There is no custom `Drop` anywhere. Dropping a value closes its handles and
//! removes or renames nothing. No uncertain native result is ever retried.
//!
//! | value                  | pin | old object | new object |
//! |------------------------|-----|------------|------------|
//! | `ExchangeContract`     | -   | -          | -          |
//! | `HeldRecord`           | own | own        | -          |
//! | `StageFailure`         | own (in `held`) | own | consumed by a handle removal |
//! | `StagedRecord`         | own | own        | own        |
//! | `NotExchanged`         | own (in `held`) | own | consumed by a handle removal |
//! | `Restored`             | own (in `held`) | own | consumed by a handle removal |
//! | `RetainedOld`          | own | own        | consumed by a handle removal |
//! | `InterruptedRecord`    | own | own        | own        |
//! | `UnknownRecord`        | own | own        | own        |
//! | `SwappedRecord`        | own | own        | own        |
//! | `UnverifiedRecord`     | own | own        | own        |
//! | `VerifiedRecord`       | own | own        | own        |
//! | `PublishedRecord`      | own | consumed by the test-only mark | own |
//!
//! The new object is removed only through its own handle, only while it certainly
//! still carries its staging name, and never after an unknown status, after a
//! successful publication or while interrupted.
//!
//! No path, name, key, token, identity, length, native status or byte appears in any
//! `Debug` output.

use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use localvault_core::{
    sync::EnvelopeFingerprint,
    sync_state::{Locator, SyncState, SyncStateLoad, MAX_SYNC_STATE_BYTES},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    },
};

use super::{
    file_identity::{
        compare, directory_identity_of, facts_of, volume_facts_of, FileIdentity, HandleFacts,
        IdentityError, PhysicalVerdict,
    },
    handle_ops::{self, DefiniteRefusal, RenameStatus},
    new_copy_file::open_directory_pin,
    sync_state_store::path_identity_eq,
};

/// The most directory entries the listing examines.
const MAX_LISTED_ENTRIES: usize = 10_000;

/// Length of a record key: a lowercase hexadecimal SHA-256.
const KEY_LEN: usize = 64;

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {
        $(
            impl fmt::Debug for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(concat!(stringify!($name), "(<redacted>)"))
                }
            }
        )+
    };
}

// ---- 1. contract validation (pure, before any I/O) --------------------------------

/// The record key of `locator`: lowercase hexadecimal SHA-256 of the ASCII-lowercased
/// locator. Duplicates the store's private derivation; the tests cross-check it
/// against the file name the store itself creates.
pub(crate) fn exchange_key(locator: &Locator) -> String {
    EnvelopeFingerprint::of_bytes(locator.as_str().to_ascii_lowercase().as_bytes()).to_hex()
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Why the three leaf names could not be derived. Categories only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafRefusal {
    /// The key is not exactly 64 lowercase hexadecimal characters.
    KeyMalformed,
    /// A staging or retention token was the nil UUID.
    TokenNil,
    /// The staging and retention tokens are equal.
    TokensNotDistinct,
}

/// The three leaf names of one exchange: `<key>.json`, and the staging and retention
/// names `<key>.<32 lowercase hex>.tmp`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecordLeaves {
    primary: OsString,
    staging: OsString,
    retention: OsString,
}

redacted_debug!(RecordLeaves);

impl RecordLeaves {
    pub(crate) fn derive(key: &str, staging: Uuid, retention: Uuid) -> Result<Self, LeafRefusal> {
        if key.len() != KEY_LEN || !is_lower_hex(key) {
            return Err(LeafRefusal::KeyMalformed);
        }

        if staging.is_nil() || retention.is_nil() {
            return Err(LeafRefusal::TokenNil);
        }

        if staging == retention {
            return Err(LeafRefusal::TokensNotDistinct);
        }

        Ok(Self {
            primary: OsString::from(format!("{key}.json")),
            staging: OsString::from(format!("{key}.{}.tmp", staging.simple())),
            retention: OsString::from(format!("{key}.{}.tmp", retention.simple())),
        })
    }

    pub(crate) fn primary(&self) -> &OsStr {
        &self.primary
    }

    pub(crate) fn staging(&self) -> &OsStr {
        &self.staging
    }

    pub(crate) fn retention(&self) -> &OsStr {
        &self.retention
    }
}

/// Why the contract was refused. Nothing was touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContractRefusal {
    /// A state's local locator is not the requested locator.
    LocatorMismatch,
    /// The binding id, vault tag, local locator or target locator differ exactly.
    BindingChanged,
    /// The proposed state is not exactly representable as a legacy version-1 record.
    NewNotLegacyRecord,
    /// The proposed record is byte-identical to the expected old record.
    NoChange,
    Leaf(LeafRefusal),
}

/// The pure, validated input of one exchange. The module never takes raw bytes.
#[derive(Clone)]
pub(crate) struct ExchangeContract {
    locator: Locator,
    expected_old: SyncState,
    proposed: SyncState,
    new_bytes: Vec<u8>,
    leaves: RecordLeaves,
}

redacted_debug!(ExchangeContract);

impl ExchangeContract {
    pub(crate) fn new(
        locator: &Locator,
        expected_old: &SyncState,
        proposed: &SyncState,
        staging: Uuid,
        retention: Uuid,
    ) -> Result<Self, ContractRefusal> {
        let names_locator =
            |state: &SyncState| path_identity_eq(state.local_locator().as_str(), locator.as_str());

        if !names_locator(expected_old) || !names_locator(proposed) {
            return Err(ContractRefusal::LocatorMismatch);
        }

        if expected_old.binding_id() != proposed.binding_id()
            || expected_old.vault_tag() != proposed.vault_tag()
            || expected_old.local_locator() != proposed.local_locator()
            || expected_old.target_locator() != proposed.target_locator()
        {
            return Err(ContractRefusal::BindingChanged);
        }

        let new_bytes = proposed
            .encode()
            .map_err(|_| ContractRefusal::NewNotLegacyRecord)?;

        if new_bytes.is_empty()
            || new_bytes.len() > MAX_SYNC_STATE_BYTES
            || !matches!(SyncState::decode(&new_bytes), Ok(decoded) if decoded == *proposed)
        {
            return Err(ContractRefusal::NewNotLegacyRecord);
        }

        if expected_old.encode().is_ok_and(|old| old == new_bytes) {
            return Err(ContractRefusal::NoChange);
        }

        let leaves = RecordLeaves::derive(&exchange_key(locator), staging, retention)
            .map_err(ContractRefusal::Leaf)?;

        Ok(Self {
            locator: locator.clone(),
            expected_old: expected_old.clone(),
            proposed: proposed.clone(),
            new_bytes,
            leaves,
        })
    }

    pub(crate) fn leaves(&self) -> &RecordLeaves {
        &self.leaves
    }
}

// ---- 2. refusal and reason categories ---------------------------------------------

/// Why the old record could not be held and validated. Every refusal: nothing was
/// created or changed, and the pin was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquireRefusal {
    DirectoryUnavailable,
    DirectoryNotPlain,
    DirectoryNotLocalNtfs,
    AncestorNotPlain,
    ListingIncomplete,
    PrimaryNameNotCanonical,
    AliasAmbiguity,
    StagingNameExists,
    RetentionNameExists,
    /// Another handle excludes the hold (a sharing violation).
    Busy,
    PrimaryMissing,
    OpenFailed,
    FileUnsuitable,
    SizeUnsupported,
    IdentityUncertain,
    NotLocalNtfs,
    /// The record has a second name.
    ExtraNames,
    ReadFailed,
    OldCorrupt,
    OldUnsupportedVersion,
    OldLocatorMismatch,
    OldStateChanged,
    FreshReadMismatch,
    DirectoryChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageRefusal {
    StagingNameExists,
    StagingCreateFailed,
    WriteFailed,
    FlushFailed,
    SyncFailed,
    LengthMismatch,
    IdentityUncertain,
    ReadBackMismatch,
}

/// Why nothing was exchanged: the old object never left the primary name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotExchangedReason {
    RecheckRefused,
    TargetChanged,
    TargetNotSingleLink,
    TargetDeletePending,
    IdentityUncertain,
    StagingChanged,
    DirectoryChanged,
    /// The first rename was refused because the retention name exists.
    RetentionCollision,
    /// The first rename was otherwise definitely refused.
    RetentionRefused,
}

/// Which native step did not give a definite answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnknownStep {
    RetentionRename,
    Publication,
    Restoration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyRefusal {
    NewVersionChanged,
    PreviousChanged,
    TargetUnreadable,
    TargetIdentityMismatch,
    TargetFactsRefused,
    TargetBytesMismatch,
    RetentionUnreadable,
    RetentionIdentityMismatch,
    RetentionBytesMismatch,
    DirectoryChanged,
}

// ---- 3. seams ---------------------------------------------------------------------

/// Fixed points of the sequence, for the test hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordStage {
    /// The old record is held, judged and validated.
    AfterAcquire,
    BeforeStageWrite,
    BeforeRetentionRename,
    BetweenRenames,
    BeforeRestore,
    BeforeVerify,
    BeforeRelease,
}

/// A staging failure to inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageFault {
    /// Fail after writing half of the bytes.
    Write,
    Flush,
    Sync,
}

/// Test seams. Injected faults and hooks prove decision logic only; they say
/// nothing about what a real filesystem does. Native statuses are injected only
/// through the thread-local one-shot injectors of the native module.
#[derive(Default)]
pub(crate) struct RecordSeams {
    hook: Option<Box<dyn FnMut(RecordStage)>>,
    fault: Option<StageFault>,
}

impl RecordSeams {
    pub(crate) fn none() -> Self {
        Self::default()
    }

    pub(crate) fn on_stage(mut self, hook: impl FnMut(RecordStage) + 'static) -> Self {
        self.hook = Some(Box::new(hook));

        self
    }

    pub(crate) fn with_fault(mut self, fault: StageFault) -> Self {
        self.fault = Some(fault);

        self
    }

    fn hit(&mut self, stage: RecordStage) {
        if let Some(hook) = self.hook.as_mut() {
            hook(stage);
        }
    }
}

// ---- 4. shared helpers --------------------------------------------------------------

fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.file_type().is_symlink()
}

fn is_plain_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && !is_reparse(metadata)
}

fn is_plain_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir() && !is_reparse(metadata)
}

/// Every ancestor of `path` (its parent up to the root) exists and is a plain
/// directory.
fn ancestors_are_plain(path: &Path) -> bool {
    let mut confirmed = 0usize;

    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }

        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_plain_directory(&metadata) => confirmed += 1,
            _ => return false,
        }
    }

    confirmed > 0
}

fn ascii_fold(name: &OsStr) -> String {
    name.to_string_lossy().to_ascii_lowercase()
}

/// Read a held file from its start through its own handle: at most the supported
/// maximum, `None` if it is longer or the read fails.
fn read_bounded(file: &File) -> Option<Vec<u8>> {
    let mut reader = file;

    reader.seek(SeekFrom::Start(0)).ok()?;

    let mut bytes = Vec::new();

    reader
        .take(MAX_SYNC_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;

    (bytes.len() <= MAX_SYNC_STATE_BYTES).then_some(bytes)
}

/// What a fresh, independent, no-follow open of a path found.
enum FreshRead {
    Absent,
    Present(Fresh),
    /// A directory, link or other object that is not a plain file.
    Unexpected,
    /// Nothing can be concluded.
    Failed,
}

struct Fresh {
    facts: HandleFacts,
    /// `None` if the bytes were longer than the supported maximum or unreadable.
    bytes: Option<Vec<u8>>,
}

impl Fresh {
    fn is(&self, identity: FileIdentity, bytes: &[u8]) -> bool {
        self.facts.identity() == identity && self.bytes.as_deref() == Some(bytes)
    }
}

/// Read-only open with the standard sharing, never following a reparse point, judged
/// on the opened handle.
fn fresh_read(path: &Path) -> FreshRead {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return FreshRead::Absent,
        Err(_) => return FreshRead::Failed,
        Ok(metadata) if !is_plain_file(&metadata) => return FreshRead::Unexpected,
        Ok(_) => {}
    }

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return FreshRead::Absent,
        Err(_) => return FreshRead::Failed,
    };

    match file.metadata() {
        Ok(metadata) if is_plain_file(&metadata) => {}
        Ok(_) => return FreshRead::Unexpected,
        Err(_) => return FreshRead::Failed,
    }

    match facts_of(&file) {
        Ok(facts) => FreshRead::Present(Fresh {
            facts,
            bytes: read_bounded(&file),
        }),
        Err(_) => FreshRead::Failed,
    }
}

/// Who is at a name, judged by physical identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Occupant {
    Empty,
    /// The new object.
    New,
    /// The old object.
    Previous,
    /// Some other file or object.
    Foreign,
    /// Nothing can be concluded.
    Indeterminate,
}

fn occupant(read: &FreshRead, new: &HandleFacts, old: &HandleFacts) -> Occupant {
    match read {
        FreshRead::Absent => Occupant::Empty,
        FreshRead::Present(fresh) if fresh.facts.identity() == new.identity() => Occupant::New,
        FreshRead::Present(fresh) if fresh.facts.identity() == old.identity() => Occupant::Previous,
        FreshRead::Present(_) | FreshRead::Unexpected => Occupant::Foreign,
        FreshRead::Failed => Occupant::Indeterminate,
    }
}

/// The classified result of one handle-bound rename.
enum Step {
    Done,
    Refused { collision: bool },
    Unknown,
}

/// The only place a rename is made: handle to handle, relative to the pinned
/// directory, never replacing.
fn rename_step(file: &File, pin: &File, leaf: &OsStr) -> Step {
    match handle_ops::rename_into_directory_no_replace(file, pin, leaf) {
        RenameStatus::Renamed => Step::Done,
        RenameStatus::Refused(DefiniteRefusal::NameCollision) => Step::Refused { collision: true },
        // `Rejected`: the leaf was not one plain name and no native call was made.
        RenameStatus::Refused(_) | RenameStatus::Rejected => Step::Refused { collision: false },
        RenameStatus::Unknown => Step::Unknown,
    }
}

/// Handle-bound cleanup of OUR OWN new object, only while it certainly still carries
/// its staging name. The effect of the mark shows when the handle closes, so the
/// handle is dropped and the name is then checked. Returns whether the file could not
/// be confirmed gone. This is the removal used before the first rename and after a
/// definite refusal of the second one.
fn remove_staging(new: File, staging_path: &Path) -> bool {
    let marked = handle_ops::delete_by_handle(&new).is_ok();

    drop(new);

    let gone = marked
        && matches!(
            fs::symlink_metadata(staging_path),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        );

    !gone
}

fn slot(file: Option<&File>) -> Slot {
    match file {
        None => Slot::NotOwned,
        Some(file) => facts_of(file).map_or(Slot::Unqueryable, Slot::Live),
    }
}

/// What a value's handles report right now. Read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    /// The value does not own this handle.
    NotOwned,
    Live(HandleFacts),
    /// The value owns the handle but the query failed.
    Unqueryable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourceFacts {
    /// The pinned directory's identity; `None` if the query failed.
    pub(crate) pin: Option<FileIdentity>,
    pub(crate) old: Slot,
    pub(crate) new: Slot,
}

// ---- 5. owned state -----------------------------------------------------------------

/// What every stage holds: the pinned directory and the held old object.
struct Core {
    pin: File,
    pin_identity: FileIdentity,
    directory: PathBuf,
    contract: ExchangeContract,
    old: File,
    old_facts: HandleFacts,
    old_bytes: Vec<u8>,
}

impl Core {
    fn primary_path(&self) -> PathBuf {
        self.directory.join(self.contract.leaves.primary())
    }

    fn staging_path(&self) -> PathBuf {
        self.directory.join(self.contract.leaves.staging())
    }

    fn retention_path(&self) -> PathBuf {
        self.directory.join(self.contract.leaves.retention())
    }

    /// The pin is still the same live directory, and a fresh open of the directory
    /// reaches it. Detects an observed substitution only.
    fn pin_names_directory(&self) -> bool {
        if directory_identity_of(&self.pin) != Ok(self.pin_identity) {
            return false;
        }

        match open_directory_pin(&self.directory) {
            Ok(fresh) => directory_identity_of(&fresh) == Ok(self.pin_identity),
            Err(_) => false,
        }
    }

    fn resources(&self, new: Option<&File>) -> ResourceFacts {
        ResourceFacts {
            pin: directory_identity_of(&self.pin).ok(),
            old: slot(Some(&self.old)),
            new: slot(new),
        }
    }
}

/// `Core` plus the held new object.
struct Live {
    core: Core,
    new: File,
    new_facts: HandleFacts,
}

impl Live {
    fn resources(&self) -> ResourceFacts {
        self.core.resources(Some(&self.new))
    }

    /// The old object is still the held object, at its name, with its bytes; the
    /// new object is unchanged; the pin still names the directory.
    fn check_in_place(&self) -> Result<(), NotExchangedReason> {
        use NotExchangedReason as Reason;

        let now = facts_of(&self.core.old).map_err(|_| Reason::IdentityUncertain)?;

        if now.identity() != self.core.old_facts.identity() {
            return Err(Reason::TargetChanged);
        }

        if !now.has_single_link() {
            return Err(Reason::TargetNotSingleLink);
        }

        if now.is_delete_pending() {
            return Err(Reason::TargetDeletePending);
        }

        if now != self.core.old_facts {
            return Err(Reason::IdentityUncertain);
        }

        match facts_of(&self.new) {
            Ok(facts) if facts == self.new_facts => {}
            _ => return Err(Reason::StagingChanged),
        }

        match fresh_read(&self.core.primary_path()) {
            FreshRead::Present(fresh) if fresh.is(now.identity(), &self.core.old_bytes) => {}
            _ => return Err(Reason::TargetChanged),
        }

        if !self.core.pin_names_directory() {
            return Err(Reason::DirectoryChanged);
        }

        Ok(())
    }
}

// ---- 6. the held old record -----------------------------------------------------------

/// The old record, held open in a pinned directory. Move-only; dropping it closes the
/// handles and changes nothing.
#[must_use]
pub(crate) struct HeldRecord(Box<Core>);

redacted_debug!(HeldRecord);

impl HeldRecord {
    /// Pin the directory, hold the old primary and validate it. See the module
    /// documentation. Every refusal: nothing was created or changed.
    pub(crate) fn acquire(
        directory: &Path,
        contract: ExchangeContract,
        seams: &mut RecordSeams,
    ) -> Result<Self, AcquireRefusal> {
        use AcquireRefusal as Refusal;

        // 1. Pin the directory and judge the handle, not the path.
        let pin = open_directory_pin(directory).map_err(|_| Refusal::DirectoryUnavailable)?;

        match pin.metadata() {
            Ok(metadata) if is_plain_directory(&metadata) => {}
            _ => return Err(Refusal::DirectoryNotPlain),
        }

        match volume_facts_of(&pin) {
            Ok(volume) if volume.is_local_ntfs() => {}
            _ => return Err(Refusal::DirectoryNotLocalNtfs),
        }

        let pin_identity =
            directory_identity_of(&pin).map_err(|_| Refusal::DirectoryUnavailable)?;

        // 2. After the pin, so a redirection installed before it is caught here.
        if !ancestors_are_plain(directory) {
            return Err(Refusal::AncestorNotPlain);
        }

        // 3. The listing.
        check_listing(directory, &contract.leaves)?;

        // 4. Hold the primary: read and delete access, read-only sharing, never
        // following a reparse point. There is no fallback to a path-based operation.
        let primary_path = directory.join(contract.leaves.primary());

        let old = OpenOptions::new()
            .read(true)
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&primary_path)
            .map_err(|error| match error.raw_os_error() {
                Some(code) if code == ERROR_SHARING_VIOLATION as i32 => Refusal::Busy,
                _ if error.kind() == io::ErrorKind::NotFound => Refusal::PrimaryMissing,
                _ => Refusal::OpenFailed,
            })?;

        // 5. Judge the handle.
        let metadata = old.metadata().map_err(|_| Refusal::FileUnsuitable)?;

        if !is_plain_file(&metadata) || metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
            return Err(Refusal::FileUnsuitable);
        }

        if metadata.len() == 0 || metadata.len() > MAX_SYNC_STATE_BYTES as u64 {
            return Err(Refusal::SizeUnsupported);
        }

        let old_facts = facts_of(&old).map_err(|_| Refusal::IdentityUncertain)?;

        if !old_facts.is_local_ntfs() {
            return Err(Refusal::NotLocalNtfs);
        }

        if !old_facts.has_single_link() {
            return Err(Refusal::ExtraNames);
        }

        if old_facts.is_delete_pending() {
            return Err(Refusal::FileUnsuitable);
        }

        // 6. The old bytes, through THIS handle only, validated as the expected
        // legacy version-1 record.
        let old_bytes = read_bounded(&old).ok_or(Refusal::ReadFailed)?;

        match SyncStateLoad::from_bytes(&old_bytes) {
            SyncStateLoad::Loaded(state) => {
                if !path_identity_eq(state.local_locator().as_str(), contract.locator.as_str()) {
                    return Err(Refusal::OldLocatorMismatch);
                }

                if *state != contract.expected_old {
                    return Err(Refusal::OldStateChanged);
                }
            }
            SyncStateLoad::UnsupportedVersion => return Err(Refusal::OldUnsupportedVersion),
            _ => return Err(Refusal::OldCorrupt),
        }

        // 7. A fresh, independent, no-follow read of the path reports the same file.
        match fresh_read(&primary_path) {
            FreshRead::Present(fresh) if fresh.is(old_facts.identity(), &old_bytes) => {}
            _ => return Err(Refusal::FreshReadMismatch),
        }

        let core = Core {
            pin,
            pin_identity,
            directory: directory.to_path_buf(),
            contract,
            old,
            old_facts,
            old_bytes,
        };

        // 8. The pin still names the directory.
        if !core.pin_names_directory() {
            return Err(Refusal::DirectoryChanged);
        }

        // The hold is complete.
        seams.hit(RecordStage::AfterAcquire);

        Ok(Self(Box::new(core)))
    }

    pub(crate) fn resources(&self) -> ResourceFacts {
        self.0.resources(None)
    }

    /// Create the new object exclusively in the pinned directory, keep its handle and
    /// write, flush, sync and verify it. A failure returns the held record with it.
    pub(crate) fn stage(self, seams: &mut RecordSeams) -> Result<StagedRecord, StageFailure> {
        use StageRefusal as Refusal;

        let core = *self.0;

        let fail = |core: Core, reason: StageRefusal, staging_remains: bool| StageFailure {
            reason,
            staging_remains,
            held: HeldRecord(Box::new(core)),
        };

        seams.hit(RecordStage::BeforeStageWrite);

        let staging_path = core.staging_path();
        let bytes = core.contract.new_bytes.clone();

        // Exclusively: a name that exists is never opened.
        let mut new = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_READ)
            .open(&staging_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(fail(core, Refusal::StagingNameExists, false))
            }
            Err(_) => return Err(fail(core, Refusal::StagingCreateFailed, false)),
        };

        // From here on the object certainly carries the staging name, so a failure is
        // cleaned up by handle only.
        let abandon = |core: Core, new: File, reason: StageRefusal| {
            let remains = remove_staging(new, &core.staging_path());

            fail(core, reason, remains)
        };

        if let Err(reason) = write_new(&mut new, &bytes, seams.fault) {
            return Err(abandon(core, new, reason));
        }

        let Ok(facts) = facts_of(&new) else {
            return Err(abandon(core, new, Refusal::IdentityUncertain));
        };

        if !facts.is_local_ntfs()
            || !facts.has_single_link()
            || facts.is_delete_pending()
            || compare(&core.old_facts, &facts) != PhysicalVerdict::Distinct
        {
            return Err(abandon(core, new, Refusal::IdentityUncertain));
        }

        if read_bounded(&new).as_deref() != Some(bytes.as_slice()) {
            return Err(abandon(core, new, Refusal::ReadBackMismatch));
        }

        match fresh_read(&staging_path) {
            FreshRead::Present(fresh) if fresh.is(facts.identity(), &bytes) => {}
            _ => return Err(abandon(core, new, Refusal::ReadBackMismatch)),
        }

        Ok(StagedRecord(Box::new(Live {
            core,
            new,
            new_facts: facts,
        })))
    }
}

/// The directory listing: the exact primary leaf exists, no other spelling of it
/// does, and neither the staging nor the retention name exists in any ASCII case.
fn check_listing(directory: &Path, leaves: &RecordLeaves) -> Result<(), AcquireRefusal> {
    use AcquireRefusal as Refusal;

    let listing = fs::read_dir(directory).map_err(|_| Refusal::ListingIncomplete)?;

    let primary = ascii_fold(leaves.primary());
    let staging = ascii_fold(leaves.staging());
    let retention = ascii_fold(leaves.retention());

    let mut canonical = false;
    let mut alias = false;
    let mut seen = 0usize;

    for entry in listing {
        seen += 1;

        if seen > MAX_LISTED_ENTRIES {
            return Err(Refusal::ListingIncomplete);
        }

        let name = entry.map_err(|_| Refusal::ListingIncomplete)?.file_name();
        let folded = ascii_fold(&name);

        if name == leaves.primary() {
            canonical = true;
        } else if folded == primary {
            alias = true;
        }

        if folded == staging {
            return Err(Refusal::StagingNameExists);
        }

        if folded == retention {
            return Err(Refusal::RetentionNameExists);
        }
    }

    if !canonical {
        Err(Refusal::PrimaryNameNotCanonical)
    } else if alias {
        Err(Refusal::AliasAmbiguity)
    } else {
        Ok(())
    }
}

fn write_new(new: &mut File, bytes: &[u8], fault: Option<StageFault>) -> Result<(), StageRefusal> {
    if fault == Some(StageFault::Write) {
        let _ = new.write_all(&bytes[..bytes.len() / 2]);

        return Err(StageRefusal::WriteFailed);
    }

    new.write_all(bytes)
        .map_err(|_| StageRefusal::WriteFailed)?;

    if fault == Some(StageFault::Flush) {
        return Err(StageRefusal::FlushFailed);
    }

    new.flush().map_err(|_| StageRefusal::FlushFailed)?;

    if fault == Some(StageFault::Sync) {
        return Err(StageRefusal::SyncFailed);
    }

    new.sync_all().map_err(|_| StageRefusal::SyncFailed)?;

    match new.metadata() {
        Ok(metadata) if metadata.len() == bytes.len() as u64 => Ok(()),
        _ => Err(StageRefusal::LengthMismatch),
    }
}

/// A failed [`HeldRecord::stage`]. `staging_remains` is true only if our own new
/// object could not be confirmed removed. The held record is returned.
#[must_use]
pub(crate) struct StageFailure {
    pub(crate) reason: StageRefusal,
    pub(crate) staging_remains: bool,
    pub(crate) held: HeldRecord,
}

impl fmt::Debug for StageFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StageFailure")
            .field("reason", &self.reason)
            .field("staging_remains", &self.staging_remains)
            .finish_non_exhaustive()
    }
}

// ---- 7. the staged record --------------------------------------------------------------

/// The old and the new object, both held, nothing renamed yet. Dropping it closes
/// both handles and changes nothing (the staging file stays, exactly as after a
/// process exit).
#[must_use]
pub(crate) struct StagedRecord(Box<Live>);

redacted_debug!(StagedRecord);

impl StagedRecord {
    pub(crate) fn resources(&self) -> ResourceFacts {
        self.0.resources()
    }

    /// Rename the old object to the retention name, then the new object to the
    /// primary name. Both by handle, relative to the pinned directory, without
    /// replace. `recheck` is called once, immediately before the first rename, and
    /// must return `true` only if the caller's own evidence is unchanged.
    pub(crate) fn exchange(
        self,
        recheck: &mut dyn FnMut() -> bool,
        seams: &mut RecordSeams,
    ) -> RecordExchangeOutcome {
        let live = *self.0;

        if !recheck() {
            return not_exchanged(live, NotExchangedReason::RecheckRefused);
        }

        if let Err(reason) = live.check_in_place() {
            return not_exchanged(live, reason);
        }

        // 1. old -> retention. Nothing is replaced.
        seams.hit(RecordStage::BeforeRetentionRename);

        match rename_step(
            &live.core.old,
            &live.core.pin,
            live.core.contract.leaves.retention(),
        ) {
            Step::Done => {}
            Step::Refused { collision } => {
                // A refusal is trusted only if the old object is provably still at
                // its name.
                let read = fresh_read(&live.core.primary_path());

                return match occupant(&read, &live.new_facts, &live.core.old_facts) {
                    Occupant::Previous => not_exchanged(
                        live,
                        if collision {
                            NotExchangedReason::RetentionCollision
                        } else {
                            NotExchangedReason::RetentionRefused
                        },
                    ),
                    _ => unknown(live, UnknownStep::RetentionRename),
                };
            }
            Step::Unknown => return unknown(live, UnknownStep::RetentionRename),
        }

        // The primary name is now empty.
        seams.hit(RecordStage::BetweenRenames);

        // 2. new -> primary. Nothing is replaced.
        match rename_step(
            &live.new,
            &live.core.pin,
            live.core.contract.leaves.primary(),
        ) {
            Step::Done => {
                // Best effort, claims nothing: the content was already flushed.
                let _ = live.new.sync_all();

                RecordExchangeOutcome::Exchanged(SwappedRecord(Box::new(live)))
            }
            Step::Unknown => unknown(live, UnknownStep::Publication),
            Step::Refused { collision } => {
                let read = fresh_read(&live.core.primary_path());

                match occupant(&read, &live.new_facts, &live.core.old_facts) {
                    // The refusal is contradicted by our own object at the name, or
                    // by the old object being back: nothing may be concluded.
                    Occupant::New | Occupant::Previous | Occupant::Indeterminate => {
                        unknown(live, UnknownStep::Publication)
                    }
                    // Someone else holds the name: never touched. Our new object
                    // still carries its staging name (the rename was refused), so it
                    // alone is removed by handle; the old object stays retained.
                    Occupant::Foreign => taken_over(live),
                    // The kernel says the name exists but it is empty: contradictory.
                    Occupant::Empty if collision => unknown(live, UnknownStep::Publication),
                    Occupant::Empty => restore(live, seams),
                }
            }
        }
    }
}

/// The old object never left its name: only our own new object is removed, by handle.
fn not_exchanged(live: Live, reason: NotExchangedReason) -> RecordExchangeOutcome {
    let Live { core, new, .. } = live;
    let staging_remains = remove_staging(new, &core.staging_path());

    RecordExchangeOutcome::NotExchanged(Box::new(NotExchanged {
        reason,
        staging_remains,
        held: HeldRecord(Box::new(core)),
    }))
}

/// A status was not definite: remove nothing, retry nothing, keep every handle.
fn unknown(live: Live, at: UnknownStep) -> RecordExchangeOutcome {
    RecordExchangeOutcome::Unknown(Box::new(UnknownRecord {
        at,
        live: StagedRecord(Box::new(live)),
    }))
}

/// The primary name was filled by someone else during the window.
fn taken_over(live: Live) -> RecordExchangeOutcome {
    let Live { core, new, .. } = live;
    let staging_remains = remove_staging(new, &core.staging_path());

    RecordExchangeOutcome::TakenOver(Box::new(RetainedOld {
        staging_remains,
        core,
    }))
}

/// The second rename was definitely refused with the primary name provably empty:
/// put the old object back (no replace) and remove our new object.
fn restore(live: Live, seams: &mut RecordSeams) -> RecordExchangeOutcome {
    seams.hit(RecordStage::BeforeRestore);

    match rename_step(
        &live.core.old,
        &live.core.pin,
        live.core.contract.leaves.primary(),
    ) {
        Step::Done => {}
        Step::Refused { .. } => {
            return RecordExchangeOutcome::Interrupted(Box::new(InterruptedRecord {
                live: StagedRecord(Box::new(live)),
            }))
        }
        Step::Unknown => return unknown(live, UnknownStep::Restoration),
    }

    // The old object must provably be back before anything is cleaned up.
    let back = matches!(
        fresh_read(&live.core.primary_path()),
        FreshRead::Present(fresh) if fresh.is(live.core.old_facts.identity(), &live.core.old_bytes)
    );

    if !back {
        return unknown(live, UnknownStep::Restoration);
    }

    let Live { core, new, .. } = live;
    let staging_remains = remove_staging(new, &core.staging_path());

    RecordExchangeOutcome::Restored(Box::new(Restored {
        staging_remains,
        held: HeldRecord(Box::new(core)),
    }))
}

/// What [`StagedRecord::exchange`] established. None of these is consent to anything.
#[derive(Debug)]
#[must_use]
pub(crate) enum RecordExchangeOutcome {
    /// Both renames succeeded.
    Exchanged(SwappedRecord),
    /// The old object never left its name; our new object was removed by handle.
    NotExchanged(Box<NotExchanged>),
    /// The second rename was definitely refused with the name provably empty; the
    /// old object was renamed back and verified there.
    Restored(Box<Restored>),
    /// The primary name was filled by someone else during the window. It was not
    /// touched; the old record is retained under the retention name.
    TakenOver(Box<RetainedOld>),
    /// The second rename and the restoration were both refused: the old record is at
    /// the retention name, the new one at its staging name, the primary is empty.
    Interrupted(Box<InterruptedRecord>),
    /// A native status was not definite. Nothing was removed or renamed further.
    Unknown(Box<UnknownRecord>),
}

#[must_use]
pub(crate) struct NotExchanged {
    pub(crate) reason: NotExchangedReason,
    pub(crate) staging_remains: bool,
    pub(crate) held: HeldRecord,
}

impl fmt::Debug for NotExchanged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotExchanged")
            .field("reason", &self.reason)
            .field("staging_remains", &self.staging_remains)
            .finish_non_exhaustive()
    }
}

impl NotExchanged {
    pub(crate) fn resources(&self) -> ResourceFacts {
        self.held.resources()
    }
}

#[must_use]
pub(crate) struct Restored {
    pub(crate) staging_remains: bool,
    pub(crate) held: HeldRecord,
}

impl fmt::Debug for Restored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Restored")
            .field("staging_remains", &self.staging_remains)
            .finish_non_exhaustive()
    }
}

impl Restored {
    pub(crate) fn resources(&self) -> ResourceFacts {
        self.held.resources()
    }
}

/// The old record, retained under the retention name after a third party took the
/// primary name. The handles are kept only to keep the object in place.
#[must_use]
pub(crate) struct RetainedOld {
    pub(crate) staging_remains: bool,
    core: Core,
}

impl fmt::Debug for RetainedOld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedOld")
            .field("staging_remains", &self.staging_remains)
            .finish_non_exhaustive()
    }
}

impl RetainedOld {
    pub(crate) fn resources(&self) -> ResourceFacts {
        self.core.resources(None)
    }
}

/// Old record at the retention name, new record at its staging name, primary empty.
/// Both handles held; dropping closes them and changes nothing.
#[must_use]
pub(crate) struct InterruptedRecord {
    live: StagedRecord,
}

redacted_debug!(InterruptedRecord);

impl InterruptedRecord {
    pub(crate) fn resources(&self) -> ResourceFacts {
        self.live.resources()
    }
}

/// A native status was not definite. Both handles held; dropping closes them and
/// changes nothing.
#[must_use]
pub(crate) struct UnknownRecord {
    at: UnknownStep,
    live: StagedRecord,
}

impl fmt::Debug for UnknownRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnknownRecord")
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

impl UnknownRecord {
    pub(crate) fn at(&self) -> UnknownStep {
        self.at
    }

    pub(crate) fn resources(&self) -> ResourceFacts {
        self.live.resources()
    }
}

// ---- 8. the swapped record ----------------------------------------------------------------

/// Both renames succeeded; nothing is verified yet. Dropping closes both handles and
/// changes nothing.
#[must_use]
pub(crate) struct SwappedRecord(Box<Live>);

redacted_debug!(SwappedRecord);

impl SwappedRecord {
    pub(crate) fn resources(&self) -> ResourceFacts {
        self.0.resources()
    }

    /// While both objects are still held, independently read the new primary and the
    /// retained old record and compare identities and bytes.
    pub(crate) fn verify(
        self,
        seams: &mut RecordSeams,
    ) -> Result<VerifiedRecord, UnverifiedRecord> {
        seams.hit(RecordStage::BeforeVerify);

        let live = *self.0;

        match verify_swap(&live) {
            Ok(()) => Ok(VerifiedRecord(Box::new(live))),
            Err(reason) => Err(UnverifiedRecord {
                reason,
                live: Box::new(live),
            }),
        }
    }
}

fn verify_swap(live: &Live) -> Result<(), VerifyRefusal> {
    use VerifyRefusal as Refusal;

    match facts_of(&live.new) {
        Ok(now) if now == live.new_facts => {}
        _ => return Err(Refusal::NewVersionChanged),
    }

    match facts_of(&live.core.old) {
        Ok(now) if now == live.core.old_facts => {}
        _ => return Err(Refusal::PreviousChanged),
    }

    // The new primary.
    let FreshRead::Present(target) = fresh_read(&live.core.primary_path()) else {
        return Err(Refusal::TargetUnreadable);
    };

    if target.facts.identity() != live.new_facts.identity() {
        return Err(Refusal::TargetIdentityMismatch);
    }

    if !target.facts.has_single_link()
        || target.facts.is_delete_pending()
        || !target.facts.is_local_ntfs()
        || compare(&live.core.old_facts, &target.facts) != PhysicalVerdict::Distinct
    {
        return Err(Refusal::TargetFactsRefused);
    }

    let new_bytes = live.core.contract.new_bytes.as_slice();

    if target.bytes.as_deref() != Some(new_bytes)
        || !matches!(
            SyncState::decode(new_bytes),
            Ok(decoded) if decoded == live.core.contract.proposed
        )
    {
        return Err(Refusal::TargetBytesMismatch);
    }

    // The retained old record.
    let FreshRead::Present(kept) = fresh_read(&live.core.retention_path()) else {
        return Err(Refusal::RetentionUnreadable);
    };

    if kept.facts.identity() != live.core.old_facts.identity()
        || !kept.facts.has_single_link()
        || !kept.facts.is_local_ntfs()
    {
        return Err(Refusal::RetentionIdentityMismatch);
    }

    if kept.bytes.as_deref() != Some(live.core.old_bytes.as_slice()) {
        return Err(Refusal::RetentionBytesMismatch);
    }

    if !live.core.pin_names_directory() {
        return Err(Refusal::DirectoryChanged);
    }

    Ok(())
}

/// The exchange was not confirmed. Both handles are still held and nothing was
/// removed. Dropping closes the handles.
#[must_use]
pub(crate) struct UnverifiedRecord {
    reason: VerifyRefusal,
    live: Box<Live>,
}

impl fmt::Debug for UnverifiedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnverifiedRecord")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl UnverifiedRecord {
    pub(crate) fn reason(&self) -> VerifyRefusal {
        self.reason
    }

    pub(crate) fn resources(&self) -> ResourceFacts {
        self.live.resources()
    }
}

/// The exchange was independently verified. This is **not** a commit and not an
/// authorization: the old record is retained unless the test-only release below is
/// called, and nothing in production calls either.
#[must_use]
pub(crate) struct VerifiedRecord(Box<Live>);

redacted_debug!(VerifiedRecord);

/// What the test-only release established about the retained old record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviousRelease {
    /// Marked for removal with one name fewer, the retention name is gone, and the
    /// new primary is unchanged.
    Released,
    /// The native call was refused and the old record is unchanged.
    Retained,
    /// Anything else. The retention name is kept.
    Unknown,
}

/// What a mark of the held old object established. The rule is the one the store's
/// handle-bound reset already uses, copied here as a private pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviousMark {
    Marked,
    NotMarked,
    Unknown,
}

fn judge_mark(
    native_ok: bool,
    after: Result<HandleFacts, IdentityError>,
    saved: &HandleFacts,
) -> PreviousMark {
    let Ok(now) = after else {
        return PreviousMark::Unknown;
    };

    if now.identity() != saved.identity() || !now.is_local_ntfs() {
        return PreviousMark::Unknown;
    }

    if native_ok {
        let one_name_fewer =
            saved.link_count() > 0 && saved.link_count().checked_sub(1) == Some(now.link_count());

        if now.is_delete_pending() && one_name_fewer {
            PreviousMark::Marked
        } else {
            PreviousMark::Unknown
        }
    } else if !now.is_delete_pending() && now.link_count() == saved.link_count() {
        PreviousMark::NotMarked
    } else {
        PreviousMark::Unknown
    }
}

/// The numbers the release observed on the old handle. Measurement only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReleaseObservation {
    pub(crate) links_before: u32,
    pub(crate) links_after: Option<u32>,
    pub(crate) delete_pending_after: Option<bool>,
}

#[must_use]
pub(crate) struct ReleaseReport {
    pub(crate) release: PreviousRelease,
    pub(crate) observed: ReleaseObservation,
    pub(crate) published: PublishedRecord,
}

impl fmt::Debug for ReleaseReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseReport")
            .field("release", &self.release)
            .finish_non_exhaustive()
    }
}

/// The pin and the handle of the published new primary. Dropping closes them.
#[must_use]
pub(crate) struct PublishedRecord {
    pin: File,
    new: File,
}

redacted_debug!(PublishedRecord);

impl PublishedRecord {
    pub(crate) fn resources(&self) -> ResourceFacts {
        ResourceFacts {
            pin: directory_identity_of(&self.pin).ok(),
            old: Slot::NotOwned,
            new: slot(Some(&self.new)),
        }
    }

    pub(crate) fn close(self) {
        drop(self);
    }
}

impl VerifiedRecord {
    pub(crate) fn resources(&self) -> ResourceFacts {
        self.0.resources()
    }

    /// Close the handles; the retained old record stays on disk.
    pub(crate) fn retain_previous(self) {
        drop(self.0);
    }

    /// MEASUREMENT ONLY (this module is test-only and has no production meaning):
    /// mark the retained old record for removal through its own held handle, judge the
    /// result with the store's reset rule and report the observed numbers.
    pub(crate) fn release_previous(self, seams: &mut RecordSeams) -> ReleaseReport {
        seams.hit(RecordStage::BeforeRelease);

        let Live {
            core,
            new,
            new_facts,
        } = *self.0;

        let saved = core.old_facts;
        let retention_path = core.retention_path();
        let primary_path = core.primary_path();
        let new_bytes = core.contract.new_bytes.clone();
        let old = core.old;
        let published = PublishedRecord { pin: core.pin, new };

        let mut observed = ReleaseObservation {
            links_before: saved.link_count(),
            links_after: None,
            delete_pending_after: None,
        };

        let report = |release, observed, published| ReleaseReport {
            release,
            observed,
            published,
        };

        // The old handle must still report exactly what it reported when judged.
        if facts_of(&old) != Ok(saved) {
            return report(PreviousRelease::Unknown, observed, published);
        }

        let native_ok = handle_ops::delete_by_handle(&old).is_ok();
        let after = facts_of(&old);

        if let Ok(now) = after {
            observed.links_after = Some(now.link_count());
            observed.delete_pending_after = Some(now.is_delete_pending());
        }

        let mark = judge_mark(native_ok, after, &saved);

        drop(old);

        let release = match mark {
            PreviousMark::NotMarked => PreviousRelease::Retained,
            PreviousMark::Unknown => PreviousRelease::Unknown,
            PreviousMark::Marked => {
                let name_gone = matches!(
                    fs::symlink_metadata(&retention_path),
                    Err(error) if error.kind() == io::ErrorKind::NotFound
                );
                let new_unchanged = facts_of(&published.new) == Ok(new_facts);
                let primary_intact = matches!(
                    fresh_read(&primary_path),
                    FreshRead::Present(fresh) if fresh.is(new_facts.identity(), &new_bytes)
                );

                if name_gone && new_unchanged && primary_intact {
                    PreviousRelease::Released
                } else {
                    PreviousRelease::Unknown
                }
            }
        };

        report(release, observed, published)
    }
}

// ---- tests ----

// Evidence labels used by every test below:
//
//   REAL NTFS          real files, handles and renames on D: (local NTFS), real child
//                      processes (cmd.exe) as the foreign actors.
//   REAL PROCESS EXIT  a real child test process that calls `std::process::exit(86)`
//                      at a fixed point. NOT an OS crash, NOT a Windows shutdown and
//                      NOT a power loss: the operating system keeps running and closes
//                      the process's handles, which says nothing about what survives a
//                      power loss.
//   INJECTED           decision logic driven by an injected native status or fault; the
//                      rest of the filesystem is real. Says nothing about what NTFS does.
//   PURE               no filesystem effect.
//   UNAVAILABLE        not measurable by an ordinary test, and NOT faked here: Windows
//                      shutdown, OS crash, power loss, per-rename persistence atomicity
//                      and order, directory durability, the C: AppData volume,
//                      ReFS/SMB/FAT, 8.3 short names, case-sensitive directories,
//                      writable mapped views, privileged and filter-driver actors.

#[cfg(test)]
mod tests {
    use std::{cell::Cell, process::Command, rc::Rc};

    use localvault_core::sync::{PushBaseline, PushIntent};
    use localvault_core::sync_state::{
        BindingId, PendingPush, SyncBase, VaultBindingTag, BINDING_SALT_LEN,
    };

    use super::*;
    use crate::vault::{
        file_identity::FileSystemKind,
        handle_ops::test_support::{assert_local_ntfs, make_junction, names, snapshot},
        sync_state_store::{
            StateLoad, StoreError, SyncStateStore, UnreadableReason, SYNC_STATE_DIRECTORY,
        },
    };

    const LOCAL: &str = r"\\?\C:\Synthetic\Vaults\LOCAL-MARKER.lvault";
    const OTHER_LOCAL: &str = r"\\?\C:\Synthetic\Vaults\OTHER-MARKER.lvault";
    const TARGET: &str = r"\\?\D:\Synthetic\Remote\TARGET-MARKER.lvault";
    const OTHER_TARGET: &str = r"\\?\D:\Synthetic\Remote\OTHER-TARGET-MARKER.lvault";
    const BINDING: u128 = 0x1111_1111_2222_3333_4444_5555_5555_5555;
    const OTHER_BINDING: u128 = 0x2222_2222_3333_4444_5555_6666_6666_6666;
    const VAULT: u128 = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef;
    const OTHER_VAULT: u128 = 0xfedc_ba98_7654_3210_fedc_ba98_7654_3210;
    const FOREIGN: &[u8] = b"SYNTHETIC-FOREIGN-BYTES-NOT-A-REAL-RECORD";

    const DENIED: i32 = 0xC000_0022_u32 as i32;
    const COLLISION: i32 = 0xC000_0035_u32 as i32;
    const PENDING: i32 = 0x0000_0103;
    const BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;
    const UNSUCCESSFUL: i32 = 0xC000_0001_u32 as i32;

    // ---- fixtures -------------------------------------------------------------------

    fn loc(value: &str) -> Locator {
        Locator::new(value).unwrap()
    }

    fn state_with(
        local: &str,
        target: &str,
        binding: u128,
        vault: u128,
        revision: u64,
    ) -> SyncState {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
        let intent =
            PushIntent::new(PushBaseline::Absent, EnvelopeFingerprint::of_bytes(&[2])).unwrap();

        SyncState::new(
            BindingId::new(Uuid::from_u128(binding)).unwrap(),
            VaultBindingTag::derive(salt, Uuid::from_u128(vault)).unwrap(),
            loc(local),
            loc(target),
            SyncBase::Unbased,
            Some(
                PendingPush::new(
                    Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee),
                    intent,
                    revision,
                )
                .unwrap(),
            ),
        )
        .unwrap()
    }

    /// The synthetic record of `LOCAL` at write counter `revision`.
    fn rev(revision: u64) -> SyncState {
        state_with(LOCAL, TARGET, BINDING, VAULT, revision)
    }

    fn bytes_of(revision: u64) -> Vec<u8> {
        rev(revision).encode().unwrap()
    }

    fn loaded(state: &SyncState) -> StateLoad {
        StateLoad::Loaded(Box::new(state.clone()))
    }

    fn scratch_base() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("legacy-record-exchange-tests")
    }

    /// A unique, test-owned directory under the dedicated G12R-1 scratch base. Removed
    /// only by its guard.
    fn scratch(prefix: &str) -> tempfile::TempDir {
        let base = scratch_base();

        fs::create_dir_all(&base).unwrap();

        let dir = tempfile::Builder::new()
            .prefix(&format!("{prefix}-"))
            .tempdir_in(&base)
            .unwrap();

        assert!(!dir.path().starts_with(std::env::temp_dir()));
        assert_local_ntfs(dir.path());

        dir
    }

    struct Fixture {
        // The guard is declared first, so it is dropped after every handle a test holds.
        scratch: tempfile::TempDir,
        locator: Locator,
        staging: Uuid,
        retention: Uuid,
    }

    impl Fixture {
        /// A scratch root whose `sync-state` directory holds the record of `rev(1)`,
        /// created by the public store API and loaded back before anything else.
        fn new(name: &str) -> Self {
            // Native statuses are thread-local; never inherit one from another test.
            let _ = handle_ops::take_last_rename_status();
            let _ = handle_ops::take_last_delete_status();

            let fixture = Self {
                scratch: scratch(name),
                locator: loc(LOCAL),
                staging: Uuid::new_v4(),
                retention: Uuid::new_v4(),
            };

            fixture.store().create(&rev(1)).unwrap();

            assert_eq!(fixture.load(), loaded(&rev(1)));

            fixture
        }

        fn root(&self) -> &Path {
            self.scratch.path()
        }

        fn dir(&self) -> PathBuf {
            self.root().join(SYNC_STATE_DIRECTORY)
        }

        fn key(&self) -> String {
            exchange_key(&self.locator)
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(self.root()).unwrap()
        }

        fn load(&self) -> StateLoad {
            self.store().load(&self.locator)
        }

        fn primary_leaf(&self) -> String {
            format!("{}.json", self.key())
        }

        fn primary(&self) -> PathBuf {
            self.dir().join(self.primary_leaf())
        }

        fn staging(&self) -> PathBuf {
            self.dir()
                .join(format!("{}.{}.tmp", self.key(), self.staging.simple()))
        }

        fn retention(&self) -> PathBuf {
            self.dir()
                .join(format!("{}.{}.tmp", self.key(), self.retention.simple()))
        }

        fn names(&self) -> Vec<String> {
            names(&self.dir())
        }

        fn rotate(&mut self) {
            self.staging = Uuid::new_v4();
            self.retention = Uuid::new_v4();
        }

        fn contract_for(&self, old: &SyncState, new: &SyncState) -> ExchangeContract {
            ExchangeContract::new(&self.locator, old, new, self.staging, self.retention).unwrap()
        }

        fn contract(&self) -> ExchangeContract {
            self.contract_for(&rev(1), &rev(2))
        }

        fn acquire(&self) -> HeldRecord {
            HeldRecord::acquire(&self.dir(), self.contract(), &mut RecordSeams::none()).unwrap()
        }

        fn refusal(&self) -> AcquireRefusal {
            match HeldRecord::acquire(&self.dir(), self.contract(), &mut RecordSeams::none()) {
                Err(refusal) => refusal,
                Ok(_) => panic!("the acquire was expected to be refused"),
            }
        }

        fn expect_sorted(&self, mut expected: Vec<String>) {
            expected.sort();

            assert_eq!(self.names(), expected);
        }
    }

    fn live(slot: Slot) -> bool {
        matches!(slot, Slot::Live(_))
    }

    fn assert_resources(resources: ResourceFacts, old: bool, new: bool) {
        assert!(resources.pin.is_some(), "the pin must be live");
        assert_eq!(live(resources.old), old);
        assert_eq!(live(resources.new), new);

        if !old {
            assert_eq!(resources.old, Slot::NotOwned);
        }

        if !new {
            assert_eq!(resources.new, Slot::NotOwned);
        }
    }

    fn identity_of(path: &Path) -> FileIdentity {
        facts_of(&File::open(path).unwrap()).unwrap().identity()
    }

    fn hex(status: i32) -> String {
        format!("0x{:08X}", status as u32)
    }

    fn exchanged(outcome: RecordExchangeOutcome) -> SwappedRecord {
        match outcome {
            RecordExchangeOutcome::Exchanged(swapped) => swapped,
            other => panic!("expected Exchanged, got {other:?}"),
        }
    }

    /// acquire -> stage -> exchange -> verify, each step required to succeed.
    fn run_to_verified(
        fx: &Fixture,
        old: &SyncState,
        new: &SyncState,
        seams: &mut RecordSeams,
    ) -> VerifiedRecord {
        let held = HeldRecord::acquire(&fx.dir(), fx.contract_for(old, new), seams).unwrap();
        let staged = held.stage(seams).unwrap();
        let swapped = exchanged(staged.exchange(&mut || true, seams));

        swapped.verify(seams).unwrap()
    }

    // ---- foreign actors: real child processes -------------------------------------------

    fn child(args: &[&str]) -> Option<i32> {
        Command::new("cmd")
            .arg("/C")
            .args(args)
            .output()
            .unwrap()
            .status
            .code()
    }

    fn text(path: &Path) -> &str {
        path.to_str().unwrap()
    }

    /// `cmd.exe copy /Y` of `bytes` over (or to) `dest`, from a separate process. The
    /// source is outside the sync-state directory and is removed again.
    fn child_copy_over(root: &Path, bytes: &[u8], dest: &Path) -> Option<i32> {
        let source = root.join("child-source.bin");

        fs::write(&source, bytes).unwrap();

        let code = child(&["copy", "/Y", text(&source), text(dest)]);

        fs::remove_file(&source).unwrap();

        code
    }

    /// Every ordinary foreign operation against a held object must fail and change
    /// nothing. Prints the observed exit codes.
    fn attack_held(root: &Path, label: &str, target: &Path, expected: &[u8]) {
        let identity = identity_of(target);
        let moved = target.with_extension("moved-away");
        let renamed = target.with_file_name("renamed-by-child.bin");

        let copy = child_copy_over(root, FOREIGN, target);
        let moved_code = child(&["move", "/Y", text(target), text(&moved)]);
        let del_output = Command::new("cmd")
            .arg("/C")
            .args(["del", "/F", "/Q", text(target)])
            .output()
            .unwrap();
        let del = del_output.status.code();
        // The message is localized OEM text, so only its presence is checked: `del`
        // reports a refusal on stderr but still exits with zero.
        let del_message_bytes = del_output.stderr.len();
        let ren = child(&["ren", text(target), "renamed-by-child.bin"]);

        eprintln!(
            "OBSERVED {label}: child copy exit={copy:?} move exit={moved_code:?} del exit={del:?} (stderr: {del_message_bytes} bytes) ren exit={ren:?}"
        );

        assert!(del_message_bytes > 0, "{label}: del reported no refusal");

        assert_ne!(copy, Some(0), "{label}: the child overwrote a held object");
        assert_ne!(
            moved_code,
            Some(0),
            "{label}: the child moved a held object"
        );
        assert_ne!(ren, Some(0), "{label}: the child renamed a held object");

        assert_eq!(
            fs::read(target).unwrap(),
            expected,
            "{label}: bytes changed"
        );
        assert_eq!(identity_of(target), identity, "{label}: object replaced");
        assert!(!moved.exists(), "{label}");
        assert!(!renamed.exists(), "{label}");
    }

    // ================================================================================
    // REAL NTFS: R1-R18
    // ================================================================================

    #[test]
    fn r1_full_exchange_verifies_and_the_test_only_release_marks_one_to_zero() {
        // REAL NTFS.
        let fx = Fixture::new("r1");

        // The key derivation equals the name the store itself created.
        assert_eq!(fx.names(), vec![fx.primary_leaf()]);

        let old_identity = identity_of(&fx.primary());
        let first = Rc::new(Cell::new(None));
        let first_hook = Rc::clone(&first);
        let mut seams = RecordSeams::none().on_stage(move |stage| {
            if stage == RecordStage::BetweenRenames {
                first_hook.set(handle_ops::take_last_rename_status());
            }
        });

        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();

        assert_resources(held.resources(), true, false);

        let staged = held.stage(&mut seams).unwrap();

        assert_resources(staged.resources(), true, true);

        let _ = handle_ops::take_last_rename_status();
        let swapped = exchanged(staged.exchange(&mut || true, &mut seams));
        let second = handle_ops::take_last_rename_status();

        eprintln!(
            "OBSERVED R1 rename old->retention (held handle, no replace): NTSTATUS {}",
            first.get().map_or("none".to_owned(), hex)
        );
        eprintln!(
            "OBSERVED R1 rename staging->primary (held handle, no replace): NTSTATUS {}",
            second.map_or("none".to_owned(), hex)
        );

        assert_eq!(first.get(), Some(0));
        assert_eq!(second, Some(0));
        assert_resources(swapped.resources(), true, true);

        let verified = swapped.verify(&mut seams).unwrap();

        assert_resources(verified.resources(), true, true);

        let report = verified.release_previous(&mut seams);

        eprintln!(
            "OBSERVED R1 test-only release: {:?}, old handle links {} -> {:?}, delete-pending after {:?}",
            report.release,
            report.observed.links_before,
            report.observed.links_after,
            report.observed.delete_pending_after
        );

        assert_eq!(report.release, PreviousRelease::Released);
        assert_eq!(report.observed.links_before, 1);
        assert_eq!(report.observed.links_after, Some(0));
        assert_eq!(report.observed.delete_pending_after, Some(true));
        assert_resources(report.published.resources(), false, true);

        report.published.close();

        assert_eq!(fx.load(), loaded(&rev(2)));
        fx.expect_sorted(vec![fx.primary_leaf()]);
        assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(2));
        assert_ne!(identity_of(&fx.primary()), old_identity);
        assert!(!fx.retention().exists());
        assert!(!fx.staging().exists());
    }

    #[test]
    fn r2_retaining_keeps_exactly_one_artifact_and_a_second_exchange_works_from_it() {
        // REAL NTFS.
        let mut fx = Fixture::new("r2");

        run_to_verified(&fx, &rev(1), &rev(2), &mut RecordSeams::none()).retain_previous();

        assert_eq!(fx.load(), loaded(&rev(2)));
        fx.expect_sorted(vec![
            fx.primary_leaf(),
            fx.retention().file_name().unwrap().to_string_lossy().into(),
        ]);
        assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));

        let evidence = fx.store().evidence(&fx.locator).unwrap();

        eprintln!(
            "OBSERVED R2 evidence after retain: primary_present={} artifact_count={}",
            evidence.primary_present(),
            evidence.artifact_count()
        );

        assert!(evidence.primary_present());
        assert_eq!(evidence.artifact_count(), 1);

        // A second exchange from that layout.
        let first_retention = fx.retention();

        fx.rotate();

        let report = run_to_verified(&fx, &rev(2), &rev(3), &mut RecordSeams::none())
            .release_previous(&mut RecordSeams::none());

        assert_eq!(report.release, PreviousRelease::Released);

        report.published.close();

        assert_eq!(fx.load(), loaded(&rev(3)));
        assert_eq!(fs::read(&first_retention).unwrap(), bytes_of(1));
        assert_eq!(fx.names().len(), 2);
    }

    #[test]
    fn r3_five_consecutive_exchanges_with_release_leave_only_the_primary_each_time() {
        // REAL NTFS.
        let mut fx = Fixture::new("r3");

        for step in 1..=5u64 {
            let report = run_to_verified(&fx, &rev(step), &rev(step + 1), &mut RecordSeams::none())
                .release_previous(&mut RecordSeams::none());

            assert_eq!(report.release, PreviousRelease::Released, "step {step}");

            report.published.close();

            fx.expect_sorted(vec![fx.primary_leaf()]);
            assert_eq!(fx.load(), loaded(&rev(step + 1)), "step {step}");

            fx.rotate();
        }

        eprintln!("OBSERVED R3 five consecutive exchanges: every step Released, only the primary remained");
    }

    #[test]
    fn r4_a_missing_or_wrongly_cased_primary_is_refused_and_nothing_is_created() {
        // REAL NTFS.
        let fx = Fixture::new("r4");
        let upper = fx.dir().join(format!("{}.JSON", fx.key().to_uppercase()));

        // Wrong case: the name exists, but not as the canonical leaf.
        fs::rename(fx.primary(), &upper).unwrap();

        let before = snapshot(fx.root());

        assert_eq!(fx.refusal(), AcquireRefusal::PrimaryNameNotCanonical);
        assert_eq!(snapshot(fx.root()), before);

        // Absent.
        fs::remove_file(&upper).unwrap();

        let before = snapshot(fx.root());
        let refusal = fx.refusal();

        eprintln!("OBSERVED R4 absent primary: {refusal:?}");

        assert_eq!(refusal, AcquireRefusal::PrimaryNameNotCanonical);
        assert_eq!(snapshot(fx.root()), before);
        assert!(fx.names().is_empty());
    }

    #[test]
    fn r5_another_open_handle_that_excludes_the_hold_is_busy() {
        // REAL NTFS.
        let fx = Fixture::new("r5");
        let before = snapshot(fx.root());

        // (a) write access with the default (full) sharing.
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(fx.primary())
            .unwrap();

        assert_eq!(fx.refusal(), AcquireRefusal::Busy);

        drop(writer);

        // (b) a reader that does not share delete.
        let reader = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | 2)
            .open(fx.primary())
            .unwrap();

        assert_eq!(fx.refusal(), AcquireRefusal::Busy);

        drop(reader);

        assert_eq!(snapshot(fx.root()), before);

        // The blockers were the cause.
        drop(fx.acquire());
    }

    #[test]
    fn r6_a_primary_with_a_second_name_is_refused() {
        // REAL NTFS.
        let fx = Fixture::new("r6");

        fs::hard_link(fx.primary(), fx.dir().join("second-name.bin")).unwrap();

        let before = snapshot(fx.root());

        assert_eq!(fx.refusal(), AcquireRefusal::ExtraNames);
        assert_eq!(snapshot(fx.root()), before);
    }

    #[test]
    fn r7_and_r8_a_hard_link_after_the_hold_is_detected_and_nothing_is_deleted() {
        // REAL NTFS. R8 is merged here: the same detection at both points.
        //
        // (a) A link made right after the hold is complete: detected before any rename.
        let fx = Fixture::new("r7a");
        let (primary, extra) = (fx.primary(), fx.dir().join("late-link.bin"));
        let hook_extra = extra.clone();
        let mut seams = RecordSeams::none().on_stage(move |stage| {
            if stage == RecordStage::AfterAcquire {
                fs::hard_link(&primary, &hook_extra).expect("a hard link to a held file");
            }
        });

        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();
        let outcome = staged.exchange(&mut || true, &mut seams);

        let RecordExchangeOutcome::NotExchanged(not_exchanged) = outcome else {
            panic!("expected NotExchanged");
        };

        eprintln!(
            "OBSERVED R7a hard link after the hold: NotExchanged({:?}), staging_remains={}",
            not_exchanged.reason, not_exchanged.staging_remains
        );

        assert_eq!(
            not_exchanged.reason,
            NotExchangedReason::TargetNotSingleLink
        );
        assert!(!not_exchanged.staging_remains);
        assert!(!fx.staging().exists());
        assert_resources(not_exchanged.resources(), true, false);
        assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(1));
        assert_eq!(fs::read(&extra).unwrap(), bytes_of(1));

        drop(not_exchanged);

        // (b) A link made between the two renames: not prevented, detected at verify.
        let fx = Fixture::new("r7b");
        let (retention, extra) = (fx.retention(), fx.dir().join("late-link.bin"));
        let hook_extra = extra.clone();
        let mut seams = RecordSeams::none().on_stage(move |stage| {
            if stage == RecordStage::BetweenRenames {
                fs::hard_link(&retention, &hook_extra).expect("a hard link to a held file");
            }
        });

        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();
        let swapped = exchanged(staged.exchange(&mut || true, &mut seams));
        let unverified = swapped.verify(&mut seams).unwrap_err();

        eprintln!(
            "OBSERVED R7b hard link between the renames: Exchanged, verify -> {:?}",
            unverified.reason()
        );

        assert_eq!(unverified.reason(), VerifyRefusal::PreviousChanged);
        assert_resources(unverified.resources(), true, true);
        assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
        assert_eq!(fs::read(&extra).unwrap(), bytes_of(1));
        assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(2));
    }

    fn attack_during(name: &str, at: RecordStage) {
        let fx = Fixture::new(name);
        let root = fx.root().to_path_buf();
        let (primary, staging, retention) = (fx.primary(), fx.staging(), fx.retention());
        let (old, new) = (bytes_of(1), bytes_of(2));
        let mut seams = RecordSeams::none().on_stage(move |stage| {
            if stage != at {
                return;
            }

            match stage {
                RecordStage::AfterAcquire => {
                    attack_held(&root, "primary after the hold", &primary, &old)
                }
                RecordStage::BeforeRetentionRename => {
                    attack_held(&root, "primary before the first rename", &primary, &old);
                    attack_held(&root, "staging before the first rename", &staging, &new);
                }
                RecordStage::BetweenRenames => {
                    attack_held(&root, "old object at the retention name", &retention, &old);
                    attack_held(&root, "staging between the renames", &staging, &new);
                }
                _ => unreachable!("not an attack point"),
            }
        });

        // The attacks changed nothing, so the exchange completes normally.
        let verified = run_to_verified(&fx, &rev(1), &rev(2), &mut seams);

        verified.retain_previous();

        assert_eq!(fx.load(), loaded(&rev(2)));
    }

    #[test]
    fn r9_ordinary_foreign_operations_on_held_objects_all_fail_after_the_hold() {
        // REAL NTFS, real child processes.
        attack_during("r9a", RecordStage::AfterAcquire);
    }

    #[test]
    fn r9_ordinary_foreign_operations_on_held_objects_all_fail_before_the_first_rename() {
        // REAL NTFS, real child processes.
        attack_during("r9b", RecordStage::BeforeRetentionRename);
    }

    #[test]
    fn r9_ordinary_foreign_operations_on_held_objects_all_fail_between_the_renames() {
        // REAL NTFS, real child processes.
        attack_during("r9c", RecordStage::BetweenRenames);
    }

    #[test]
    fn r10_a_foreign_file_in_the_empty_window_is_never_replaced_and_the_old_record_is_kept() {
        // REAL NTFS, real child process.
        let fx = Fixture::new("r10");
        let root = fx.root().to_path_buf();
        let primary = fx.primary();
        let foreign = bytes_of(9);
        let hook_foreign = foreign.clone();
        let mut seams = RecordSeams::none().on_stage(move |stage| {
            if stage == RecordStage::BetweenRenames {
                assert_eq!(child_copy_over(&root, &hook_foreign, &primary), Some(0));
            }
        });

        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();

        let _ = handle_ops::take_last_rename_status();

        let outcome = staged.exchange(&mut || true, &mut seams);
        let status = handle_ops::take_last_rename_status();

        let RecordExchangeOutcome::TakenOver(retained) = outcome else {
            panic!("expected TakenOver, got {outcome:?}");
        };

        eprintln!(
            "OBSERVED R10 staging->primary with a foreign file present: NTSTATUS {}, staging_remains={}",
            status.map_or("none".to_owned(), hex),
            retained.staging_remains
        );

        assert_eq!(status, Some(COLLISION));
        assert!(!retained.staging_remains);
        assert_resources(retained.resources(), true, false);

        assert_eq!(
            fs::read(fx.primary()).unwrap(),
            foreign,
            "foreign file untouched"
        );
        assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
        assert!(!fx.staging().exists());
        fx.expect_sorted(vec![
            fx.primary_leaf(),
            fx.retention().file_name().unwrap().to_string_lossy().into(),
        ]);
    }

    #[test]
    fn r11_foreign_files_at_the_staging_or_retention_names_are_never_touched() {
        // REAL NTFS.
        let token = |uuid: Uuid| uuid.simple().to_string();

        for (label, upper, retention_side) in [
            ("staging", false, false),
            ("staging uppercase", true, false),
            ("retention", false, true),
            ("retention uppercase", true, true),
        ] {
            let fx = Fixture::new("r11a");
            let uuid = if retention_side {
                fx.retention
            } else {
                fx.staging
            };
            let leaf = format!(
                "{}.{}.tmp",
                fx.key(),
                if upper {
                    token(uuid).to_uppercase()
                } else {
                    token(uuid)
                }
            );

            fs::write(fx.dir().join(&leaf), FOREIGN).unwrap();

            let before = snapshot(fx.root());
            let refusal = fx.refusal();

            eprintln!("OBSERVED R11 foreign at the {label} name: {refusal:?}");

            assert_eq!(
                refusal,
                if retention_side {
                    AcquireRefusal::RetentionNameExists
                } else {
                    AcquireRefusal::StagingNameExists
                },
                "{label}"
            );
            assert_eq!(snapshot(fx.root()), before, "{label}");
        }

        // A foreign file that appears at the retention name after the hold.
        let fx = Fixture::new("r11b");
        let (root, retention) = (fx.root().to_path_buf(), fx.retention());
        let mut seams = RecordSeams::none().on_stage(move |stage| {
            if stage == RecordStage::BeforeRetentionRename {
                assert_eq!(child_copy_over(&root, FOREIGN, &retention), Some(0));
            }
        });

        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();

        let _ = handle_ops::take_last_rename_status();

        let outcome = staged.exchange(&mut || true, &mut seams);
        let status = handle_ops::take_last_rename_status();

        let RecordExchangeOutcome::NotExchanged(not_exchanged) = outcome else {
            panic!("expected NotExchanged, got {outcome:?}");
        };

        eprintln!(
            "OBSERVED R11 foreign file at the retention name at the first rename: NTSTATUS {}, {:?}",
            status.map_or("none".to_owned(), hex),
            not_exchanged.reason
        );

        assert_eq!(status, Some(COLLISION));
        assert_eq!(not_exchanged.reason, NotExchangedReason::RetentionCollision);
        assert!(!not_exchanged.staging_remains);
        assert!(!fx.staging().exists());
        assert_eq!(fs::read(fx.retention()).unwrap(), FOREIGN);
        assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(1));
        assert_resources(not_exchanged.resources(), true, false);
    }

    #[test]
    fn r12_a_junction_as_the_directory_or_as_an_ancestor_is_refused() {
        // REAL NTFS.
        let fx = Fixture::new("r12");

        // (a) The sync-state directory itself is a junction.
        let aside = fx.root().join("aside");

        fs::create_dir(&aside).unwrap();
        fs::copy(fx.primary(), aside.join(fx.primary_leaf())).unwrap();

        let link = fx.root().join("junction-dir");

        make_junction(&link, &aside);

        let before = snapshot(fx.root());
        let refusal = match HeldRecord::acquire(&link, fx.contract(), &mut RecordSeams::none()) {
            Err(refusal) => refusal,
            Ok(_) => panic!("a junction directory was accepted"),
        };

        eprintln!("OBSERVED R12 junction as the sync-state directory: {refusal:?}");

        assert_eq!(refusal, AcquireRefusal::DirectoryNotPlain);
        assert_eq!(snapshot(fx.root()), before);

        // (b) An ancestor of the directory is a junction.
        let outer = fx.root().join("outer-real");

        fs::create_dir_all(outer.join(SYNC_STATE_DIRECTORY)).unwrap();
        fs::copy(
            fx.primary(),
            outer.join(SYNC_STATE_DIRECTORY).join(fx.primary_leaf()),
        )
        .unwrap();

        let outer_link = fx.root().join("junction-outer");

        make_junction(&outer_link, &outer);

        let before = snapshot(fx.root());
        let refusal = match HeldRecord::acquire(
            &outer_link.join(SYNC_STATE_DIRECTORY),
            fx.contract(),
            &mut RecordSeams::none(),
        ) {
            Err(refusal) => refusal,
            Ok(_) => panic!("a junction ancestor was accepted"),
        };

        eprintln!("OBSERVED R12 junction as an ancestor: {refusal:?}");

        assert_eq!(refusal, AcquireRefusal::AncestorNotPlain);
        assert_eq!(snapshot(fx.root()), before);
    }

    #[test]
    fn r13_while_held_a_child_can_neither_move_nor_remove_the_pinned_directory() {
        // REAL NTFS, real child processes.
        let fx = Fixture::new("r13");
        let held = fx.acquire();
        let staged = held.stage(&mut RecordSeams::none()).unwrap();
        let dir = fx.dir();
        let moved = fx.root().join("sync-state-moved");

        let move_code = child(&["move", "/Y", text(&dir), text(&moved)]);
        let rmdir_code = child(&["rmdir", "/S", "/Q", text(&dir)]);

        eprintln!("OBSERVED R13 child move of the pinned directory exit={move_code:?}; rmdir /S /Q exit={rmdir_code:?}");

        assert_ne!(move_code, Some(0));
        assert!(dir.is_dir());
        assert!(!moved.exists());
        assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(1));
        assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));

        // Nothing was damaged, so the exchange still completes.
        let swapped = exchanged(staged.exchange(&mut || true, &mut RecordSeams::none()));

        swapped
            .verify(&mut RecordSeams::none())
            .unwrap()
            .retain_previous();

        assert_eq!(fx.load(), loaded(&rev(2)));
    }

    #[test]
    fn r14_a_second_acquire_of_the_same_record_while_the_first_is_held_is_busy() {
        // REAL NTFS.
        let fx = Fixture::new("r14");
        let first = fx.acquire();

        assert_eq!(fx.refusal(), AcquireRefusal::Busy);

        let staged = first.stage(&mut RecordSeams::none()).unwrap();
        let swapped = exchanged(staged.exchange(&mut || true, &mut RecordSeams::none()));

        swapped
            .verify(&mut RecordSeams::none())
            .unwrap()
            .retain_previous();

        assert_eq!(fx.load(), loaded(&rev(2)));
    }

    #[test]
    fn r15_while_held_a_second_stores_conditional_reset_is_refused_and_removes_nothing() {
        // REAL NTFS. The legacy reset is the unchanged production code.
        let fx = Fixture::new("r15");
        let second = fx.store();
        let evidence = second.evidence(&fx.locator).unwrap();
        let held = fx.acquire();
        let before = snapshot(&fx.dir());

        let result = second.delete_if_evidence_matches(&fx.locator, &evidence);

        eprintln!("OBSERVED R15 second store reset while held: {result:?}");

        assert!(result.is_err());
        assert_eq!(snapshot(&fx.dir()), before);
        assert_resources(held.resources(), true, false);
    }

    #[test]
    fn r16_while_held_a_second_stores_legacy_replace_is_refused_and_the_primary_stays() {
        // REAL NTFS. The legacy replace is the unchanged production code.
        let fx = Fixture::new("r16");
        let second = fx.store();
        let held = fx.acquire();

        let result = second.replace(&rev(1), &rev(2));

        eprintln!("OBSERVED R16 second store replace while held: {result:?}");
        eprintln!(
            "OBSERVED R16 directory afterwards: {} entries",
            fx.names().len()
        );

        assert!(result.is_err());
        assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(1));
        // The legacy replace removes its own temp; if it ever could not, this reports it.
        assert!(
            fx.names()
                .iter()
                .filter(|name| !name.ends_with(".tmp"))
                .count()
                == 1,
            "unexpected non-temp entries: {:?}",
            fx.names()
        );

        let staged = held.stage(&mut RecordSeams::none()).unwrap();
        let swapped = exchanged(staged.exchange(&mut || true, &mut RecordSeams::none()));

        swapped
            .verify(&mut RecordSeams::none())
            .unwrap()
            .retain_previous();

        assert_eq!(fx.load(), loaded(&rev(2)));
    }

    fn unreadable_artifacts() -> StateLoad {
        StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
    }

    fn inject_at(at: RecordStage, status: i32) -> RecordSeams {
        RecordSeams::none().on_stage(move |stage| {
            if stage == at {
                handle_ops::inject_rename_status(status);
            }
        })
    }

    #[test]
    fn r17a_a_dropped_staged_record_loads_the_old_state_and_leaves_the_staging_file() {
        // REAL NTFS, handle release (PROCESS-LEVEL, not a crash).
        let fx = Fixture::new("r17a");
        let held = fx.acquire();
        let staged = held.stage(&mut RecordSeams::none()).unwrap();

        assert_resources(staged.resources(), true, true);

        drop(staged);

        let load = fx.load();

        eprintln!("OBSERVED R17a dropped StagedRecord: load={load:?}");

        assert_eq!(load, loaded(&rev(1)));
        assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));
        assert!(fx.primary().exists());
    }

    #[test]
    fn r17b_an_unknown_publication_keeps_every_handle_and_loads_as_unresolved_artifacts() {
        // REAL NTFS + injected status 0x103 on the second rename; handle release.
        let fx = Fixture::new("r17b");
        let mut seams = inject_at(RecordStage::BetweenRenames, PENDING);
        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();

        let RecordExchangeOutcome::Unknown(unknown) = staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Unknown");
        };

        assert_eq!(unknown.at(), UnknownStep::Publication);
        assert_resources(unknown.resources(), true, true);
        assert!(!fx.primary().exists());
        assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
        assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));

        drop(unknown);

        let load = fx.load();

        eprintln!("OBSERVED R17b Unknown{{Publication}} released: load={load:?}");

        assert_eq!(load, unreadable_artifacts());
        assert_ne!(load, StateLoad::NotConfigured);
        assert_eq!(
            fx.store().create(&rev(1)),
            Err(StoreError::UnresolvedArtifacts)
        );

        let evidence = fx.store().evidence(&fx.locator).unwrap();

        eprintln!(
            "OBSERVED R17b evidence: primary_present={} artifact_count={}",
            evidence.primary_present(),
            evidence.artifact_count()
        );

        assert!(!evidence.primary_present());
        assert_eq!(evidence.artifact_count(), 2);
        // I3: the primary is absent, and the old object is at the retention name.
        assert!(fx.retention().exists());
    }

    #[test]
    fn r17c_a_dropped_swapped_record_loads_the_new_state_and_keeps_the_retention_file() {
        // REAL NTFS, handle release.
        let fx = Fixture::new("r17c");
        let held = fx.acquire();
        let staged = held.stage(&mut RecordSeams::none()).unwrap();
        let swapped = exchanged(staged.exchange(&mut || true, &mut RecordSeams::none()));

        drop(swapped);

        let load = fx.load();

        eprintln!("OBSERVED R17c dropped SwappedRecord: load={load:?}");

        assert_eq!(load, loaded(&rev(2)));
        assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
        assert!(!fx.staging().exists());
    }

    #[test]
    fn r17d_a_failed_restoration_keeps_every_handle_and_loads_as_unresolved_artifacts() {
        // REAL NTFS + injected refusals of the second rename and of the restoration.
        let fx = Fixture::new("r17d");
        let mut seams = RecordSeams::none().on_stage(|stage| match stage {
            RecordStage::BetweenRenames | RecordStage::BeforeRestore => {
                handle_ops::inject_rename_status(DENIED)
            }
            _ => {}
        });
        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();

        let RecordExchangeOutcome::Interrupted(interrupted) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Interrupted");
        };

        assert_resources(interrupted.resources(), true, true);
        assert!(!fx.primary().exists());

        drop(interrupted);

        let load = fx.load();

        eprintln!("OBSERVED R17d Interrupted released: load={load:?}");

        assert_eq!(load, unreadable_artifacts());
        assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
        assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));
    }

    #[test]
    fn r17e_a_taken_over_primary_loads_the_foreign_state_and_the_old_bytes_stay_retained() {
        // REAL NTFS, real child process writes a valid version-1 record for the same locator.
        let fx = Fixture::new("r17e");
        let (root, primary) = (fx.root().to_path_buf(), fx.primary());
        let foreign = bytes_of(7);
        let hook_foreign = foreign.clone();
        let mut seams = RecordSeams::none().on_stage(move |stage| {
            if stage == RecordStage::BetweenRenames {
                assert_eq!(child_copy_over(&root, &hook_foreign, &primary), Some(0));
            }
        });
        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();

        let RecordExchangeOutcome::TakenOver(retained) = staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected TakenOver");
        };

        drop(retained);

        let load = fx.load();

        eprintln!("OBSERVED R17e TakenOver released: load={load:?}");

        assert_eq!(load, loaded(&rev(7)));
        assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
        assert!(!fx.staging().exists());
    }

    #[test]
    fn r17f_an_unknown_first_rename_keeps_every_handle_and_the_old_state_loads() {
        // REAL NTFS + injected status 0x103 on the first rename (the old object is NOT moved).
        let fx = Fixture::new("r17f");
        let mut seams = inject_at(RecordStage::BeforeRetentionRename, PENDING);
        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();

        let RecordExchangeOutcome::Unknown(unknown) = staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Unknown");
        };

        assert_eq!(unknown.at(), UnknownStep::RetentionRename);
        assert_resources(unknown.resources(), true, true);

        drop(unknown);

        let load = fx.load();

        eprintln!("OBSERVED R17f Unknown{{RetentionRename}} released: load={load:?}");

        assert_eq!(load, loaded(&rev(1)));
        assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));
        assert!(!fx.retention().exists());
    }

    #[test]
    fn r18_a_refused_publication_with_an_empty_primary_restores_the_old_record() {
        // REAL NTFS + injected STATUS_ACCESS_DENIED on the second rename only.
        let fx = Fixture::new("r18");
        let old_identity = identity_of(&fx.primary());
        let mut seams = inject_at(RecordStage::BetweenRenames, DENIED);
        let held = HeldRecord::acquire(&fx.dir(), fx.contract(), &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();

        let RecordExchangeOutcome::Restored(restored) = staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Restored");
        };

        eprintln!(
            "OBSERVED R18 refused publication: Restored, staging_remains={}",
            restored.staging_remains
        );

        assert!(!restored.staging_remains);
        assert_resources(restored.resources(), true, false);
        assert_eq!(identity_of(&fx.primary()), old_identity);
        assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(1));

        drop(restored);

        assert!(!fx.staging().exists());
        assert!(!fx.retention().exists());
        fx.expect_sorted(vec![fx.primary_leaf()]);
        assert_eq!(fx.load(), loaded(&rev(1)));
    }

    // ================================================================================
    // REAL PROCESS EXIT: R19
    // ================================================================================
    //
    // A real child test process runs the exchange against a synthetic fixture and calls
    // `std::process::exit(86)` at a fixed point: an intentional abrupt exit with no
    // stack unwinding and no local destructors. The parent asserts the exact exit code
    // and the exit-point line, then classifies the resulting filesystem state with a
    // FRESH store. This is process termination on a RUNNING operating system. It is not
    // an OS crash, not a Windows shutdown and not a power loss, and it says nothing about
    // what is persisted after one.

    const CHILD_TEST: &str = "real_process_exit_child";
    const ENV_STAGE: &str = "LV_G12R1_CHILD";
    const ENV_ROOT: &str = "LV_G12R1_ROOT";
    const ENV_MARKER: &str = "LV_G12R1_MARKER";
    const ENV_STAGING: &str = "LV_G12R1_STAGING";
    const ENV_RETENTION: &str = "LV_G12R1_RETENTION";
    const MARKER_FILE: &str = "g12r1-owner.marker";
    const CHILD_PREFIX: &str = "r19-";
    const EXIT_CODE: i32 = 86;

    const EXIT_POINTS: [RecordStage; 5] = [
        RecordStage::BeforeStageWrite,
        RecordStage::BeforeRetentionRename,
        RecordStage::BetweenRenames,
        RecordStage::BeforeVerify,
        RecordStage::BeforeRelease,
    ];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ChildRefusal {
        NotAbsolute,
        Unresolvable,
        NotOwnedChild,
        Redirected,
        UnexpectedName,
        ApplicationData,
        MarkerMissing,
        MarkerMismatch,
        UnexpectedContents,
    }

    fn looks_like_application_data(canonical: &str) -> bool {
        let lowered = canonical.to_ascii_lowercase();

        lowered.contains("\\appdata\\") || lowered.ends_with("\\appdata")
    }

    /// Everything the child must establish BEFORE it mutates anything. Pure with
    /// respect to the filesystem: it only reads.
    fn check_child_fixture(
        root: &Path,
        expected_marker: &str,
        base: &Path,
    ) -> Result<(), ChildRefusal> {
        if !root.is_absolute() {
            return Err(ChildRefusal::NotAbsolute);
        }

        if expected_marker.trim().is_empty() {
            return Err(ChildRefusal::MarkerMissing);
        }

        let canonical_base = fs::canonicalize(base).map_err(|_| ChildRefusal::Unresolvable)?;
        let canonical_root = fs::canonicalize(root).map_err(|_| ChildRefusal::Unresolvable)?;

        // A uniquely owned CHILD of the dedicated base: not the base itself, not
        // anything outside it, not anything nested deeper.
        if canonical_root.parent() != Some(canonical_base.as_path()) {
            return Err(ChildRefusal::NotOwnedChild);
        }

        // No reparse point at the base or at the fixture, and the path as given
        // resolves to itself.
        for path in [base, root] {
            match fs::symlink_metadata(path) {
                Ok(metadata) if is_plain_directory(&metadata) => {}
                _ => return Err(ChildRefusal::Redirected),
            }
        }

        if root.file_name() != canonical_root.file_name() {
            return Err(ChildRefusal::Redirected);
        }

        let name = canonical_root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();

        if !name.starts_with(CHILD_PREFIX) {
            return Err(ChildRefusal::UnexpectedName);
        }

        // No production application data.
        if looks_like_application_data(&canonical_root.to_string_lossy()) {
            return Err(ChildRefusal::ApplicationData);
        }

        // The ownership marker the parent wrote, matching the value passed separately.
        let marker_path = root.join(MARKER_FILE);

        match fs::symlink_metadata(&marker_path) {
            Ok(metadata) if is_plain_file(&metadata) && metadata.len() <= 256 => {}
            _ => return Err(ChildRefusal::MarkerMissing),
        }

        match fs::read_to_string(&marker_path) {
            Ok(found) if found == expected_marker => {}
            Ok(_) => return Err(ChildRefusal::MarkerMismatch),
            Err(_) => return Err(ChildRefusal::MarkerMissing),
        }

        // Exactly what the parent builds, nothing else.
        let mut found: Vec<String> = fs::read_dir(root)
            .map_err(|_| ChildRefusal::UnexpectedContents)?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .map_err(|_| ChildRefusal::UnexpectedContents)
            })
            .collect::<Result<_, _>>()?;

        found.sort();

        if found != [MARKER_FILE, SYNC_STATE_DIRECTORY] {
            return Err(ChildRefusal::UnexpectedContents);
        }

        match fs::symlink_metadata(root.join(SYNC_STATE_DIRECTORY)) {
            Ok(metadata) if is_plain_directory(&metadata) => Ok(()),
            _ => Err(ChildRefusal::Redirected),
        }
    }

    fn env_text(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
    }

    #[test]
    #[ignore = "REAL PROCESS EXIT child: runs only when the parent test spawns it with its environment"]
    fn real_process_exit_child() {
        let Some(selector) = std::env::var_os(ENV_STAGE) else {
            return;
        };

        let selector = selector.into_string().expect("the stage selector is text");

        // It must be the intended ignored test, run exactly, with an explicit selector.
        let args: Vec<String> = std::env::args().collect();

        assert!(
            args.iter().any(|arg| arg == "--exact")
                && args.iter().any(|arg| arg == "--ignored")
                && args.iter().any(|arg| arg.ends_with(CHILD_TEST)),
            "the child was not invoked as the exact ignored child test"
        );

        let stage = EXIT_POINTS
            .into_iter()
            .find(|stage| format!("{stage:?}") == selector)
            .expect("an unknown stage selector");

        let root = PathBuf::from(env_text(ENV_ROOT));
        let marker = env_text(ENV_MARKER);

        // Refuse before any mutation if the fixture is not provably the parent's.
        if let Err(refusal) = check_child_fixture(&root, &marker, &scratch_base()) {
            panic!("the child refuses to mutate anything: {refusal:?}");
        }

        let staging = Uuid::parse_str(&env_text(ENV_STAGING)).expect("a staging token");
        let retention = Uuid::parse_str(&env_text(ENV_RETENTION)).expect("a retention token");
        let contract = ExchangeContract::new(&loc(LOCAL), &rev(1), &rev(2), staging, retention)
            .expect("a valid contract");

        let mut seams = RecordSeams::none().on_stage(move |reached| {
            if reached == stage {
                eprintln!("G12R1-CHILD-EXIT-POINT {selector}");

                std::process::exit(EXIT_CODE);
            }
        });

        let held = HeldRecord::acquire(&root.join(SYNC_STATE_DIRECTORY), contract, &mut seams)
            .expect("acquire");
        let staged = held.stage(&mut seams).expect("stage");
        let swapped = exchanged(staged.exchange(&mut || true, &mut seams));
        let verified = swapped.verify(&mut seams).expect("verify");

        let _ = verified.release_previous(&mut seams);

        panic!("the selected exit point was never reached");
    }

    fn real_process_exit(stage: RecordStage) {
        assert!(
            std::env::var_os(ENV_STAGE).is_none(),
            "recursion guard: the parent test must not run inside the child"
        );

        let selector = format!("{stage:?}");
        let fx = Fixture::new(&format!("r19-{}", selector.to_ascii_lowercase()));
        let marker = Uuid::new_v4().to_string();

        fs::write(fx.root().join(MARKER_FILE), &marker).unwrap();

        // The parent proves ownership with the very same check the child will run.
        assert_eq!(
            check_child_fixture(fx.root(), &marker, &scratch_base()),
            Ok(())
        );

        let test_path = format!(
            "{}::{CHILD_TEST}",
            module_path!().split_once("::").expect("a crate prefix").1
        );

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                test_path.as_str(),
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(ENV_STAGE, &selector)
            .env(ENV_ROOT, fx.root())
            .env(ENV_MARKER, &marker)
            .env(ENV_STAGING, fx.staging.simple().to_string())
            .env(ENV_RETENTION, fx.retention.simple().to_string())
            .output()
            .unwrap();

        let code = output.status.code();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let load = fx.load();
        let names = fx.names();

        eprintln!(
            "OBSERVED REAL PROCESS EXIT stage={selector} exit_code={code:?} load={load:?} entries={names:?}"
        );

        // Not any abnormal termination: exactly the intentional exit code, reached at
        // exactly the selected point.
        assert_eq!(
            code,
            Some(EXIT_CODE),
            "unexpected child status\nstdout: {}\nstderr: {stderr}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            stderr.contains(&format!("G12R1-CHILD-EXIT-POINT {selector}")),
            "the child did not report the selected exit point"
        );

        let retention_leaf = fx
            .retention()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let staging_leaf = fx
            .staging()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        match stage {
            RecordStage::BeforeStageWrite => {
                assert_eq!(load, loaded(&rev(1)));
                assert_eq!(names, vec![fx.primary_leaf()]);
            }
            RecordStage::BeforeRetentionRename => {
                assert_eq!(load, loaded(&rev(1)));

                let mut want = vec![fx.primary_leaf(), staging_leaf];

                want.sort();

                assert_eq!(names, want);
                assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));
            }
            RecordStage::BetweenRenames => {
                assert_eq!(load, unreadable_artifacts());
                assert_ne!(load, StateLoad::NotConfigured);
                assert!(!fx.primary().exists(), "the primary name must be empty");

                let mut want = vec![staging_leaf, retention_leaf];

                want.sort();

                assert_eq!(names, want);
                assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
                assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));
            }
            RecordStage::BeforeVerify | RecordStage::BeforeRelease => {
                assert_eq!(load, loaded(&rev(2)));

                let mut want = vec![fx.primary_leaf(), retention_leaf];

                want.sort();

                assert_eq!(names, want);
                assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
                assert!(!fx.staging().exists());
            }
            other => panic!("not an exit point: {other:?}"),
        }

        // I3: whenever the primary name is empty, the old object is at the retention name.
        if !fx.primary().exists() {
            assert!(fx.retention().exists());
        }
    }

    #[test]
    fn r19_real_process_exit_before_stage_write() {
        // REAL PROCESS EXIT.
        real_process_exit(RecordStage::BeforeStageWrite);
    }

    #[test]
    fn r19_real_process_exit_before_retention_rename() {
        // REAL PROCESS EXIT.
        real_process_exit(RecordStage::BeforeRetentionRename);
    }

    #[test]
    fn r19_real_process_exit_between_renames() {
        // REAL PROCESS EXIT.
        real_process_exit(RecordStage::BetweenRenames);
    }

    #[test]
    fn r19_real_process_exit_before_verify() {
        // REAL PROCESS EXIT.
        real_process_exit(RecordStage::BeforeVerify);
    }

    #[test]
    fn r19_real_process_exit_before_release() {
        // REAL PROCESS EXIT.
        real_process_exit(RecordStage::BeforeRelease);
    }

    #[test]
    fn r19_the_child_refuses_every_fixture_it_does_not_provably_own() {
        // REAL NTFS. Only reads; nothing is mutated by a refusal.
        let base = scratch_base();

        fs::create_dir_all(&base).unwrap();

        let marker = "expected-marker-value";
        let build = |prefix: &str, with_marker: bool| {
            let dir = scratch(prefix);

            fs::create_dir(dir.path().join(SYNC_STATE_DIRECTORY)).unwrap();

            if with_marker {
                fs::write(dir.path().join(MARKER_FILE), marker).unwrap();
            }

            dir
        };

        let owned = build("r19-owned", true);

        assert_eq!(check_child_fixture(owned.path(), marker, &base), Ok(()));
        assert_eq!(
            check_child_fixture(Path::new("r19-owned"), marker, &base),
            Err(ChildRefusal::NotAbsolute)
        );
        assert_eq!(
            check_child_fixture(&base, marker, &base),
            Err(ChildRefusal::NotOwnedChild)
        );
        assert_eq!(
            check_child_fixture(&owned.path().join(SYNC_STATE_DIRECTORY), marker, &base),
            Err(ChildRefusal::NotOwnedChild)
        );
        assert_eq!(
            check_child_fixture(owned.path(), "", &base),
            Err(ChildRefusal::MarkerMissing)
        );
        assert_eq!(
            check_child_fixture(owned.path(), "another-value", &base),
            Err(ChildRefusal::MarkerMismatch)
        );

        // Outside the dedicated base (a sibling under .qa-local): never owned.
        let outside = tempfile::Builder::new()
            .prefix("r19-outside-")
            .tempdir_in(base.parent().unwrap())
            .unwrap();

        fs::create_dir(outside.path().join(SYNC_STATE_DIRECTORY)).unwrap();
        fs::write(outside.path().join(MARKER_FILE), marker).unwrap();

        assert_eq!(
            check_child_fixture(outside.path(), marker, &base),
            Err(ChildRefusal::NotOwnedChild)
        );

        // Not a name the parent creates, and no marker.
        let other = build("not-r19", true);

        assert_eq!(
            check_child_fixture(other.path(), marker, &base),
            Err(ChildRefusal::UnexpectedName)
        );

        let unmarked = build("r19-unmarked", false);

        assert_eq!(
            check_child_fixture(unmarked.path(), marker, &base),
            Err(ChildRefusal::MarkerMissing)
        );

        // Unexpected contents.
        fs::write(owned.path().join("extra.bin"), b"x").unwrap();

        assert_eq!(
            check_child_fixture(owned.path(), marker, &base),
            Err(ChildRefusal::UnexpectedContents)
        );

        fs::remove_file(owned.path().join("extra.bin")).unwrap();

        // A junction in the base: to somewhere outside it, and to an owned fixture.
        let unique = Uuid::new_v4().simple().to_string();
        let outward = base.join(format!("{CHILD_PREFIX}link-out-{unique}"));
        let inward = base.join(format!("{CHILD_PREFIX}link-in-{unique}"));

        make_junction(&outward, outside.path());
        make_junction(&inward, owned.path());

        let outward_result = check_child_fixture(&outward, marker, &base);
        let inward_result = check_child_fixture(&inward, marker, &base);

        // Remove the links themselves (never their targets) before asserting.
        fs::remove_dir(&outward).unwrap();
        fs::remove_dir(&inward).unwrap();

        assert_eq!(outward_result, Err(ChildRefusal::NotOwnedChild));
        assert_eq!(inward_result, Err(ChildRefusal::Redirected));

        // The application-data rule, without touching any real application data.
        assert!(looks_like_application_data(
            r"\\?\C:\Users\Synthetic\AppData\Local\Synthetic\fixture"
        ));
        assert!(!looks_like_application_data(
            r"\\?\D:\LocalVault\.qa-local\legacy-record-exchange-tests\r19-x"
        ));

        eprintln!("OBSERVED R19 child preflight: every foreign or malformed fixture was refused before any mutation");
    }

    // ================================================================================
    // NEGATIVE VALIDATION: N1-N9
    // ================================================================================

    fn assert_refused_untouched(fx: &Fixture, expected: AcquireRefusal) {
        let before = snapshot(fx.root());
        let refusal = fx.refusal();

        eprintln!("OBSERVED negative validation: {refusal:?}");

        assert_eq!(refusal, expected);
        assert_eq!(
            snapshot(fx.root()),
            before,
            "a refusal created or changed a file"
        );
    }

    #[test]
    fn n1_malformed_json_is_old_corrupt() {
        // REAL NTFS.
        let fx = Fixture::new("n1");

        fs::write(fx.primary(), b"{ this is not a sync-state record").unwrap();

        assert_refused_untouched(&fx, AcquireRefusal::OldCorrupt);
    }

    #[test]
    fn n2_a_complete_record_of_an_unsupported_version_is_old_unsupported_version() {
        // REAL NTFS.
        let fx = Fixture::new("n2");
        let version_two = rev(1).encode_exchange_record().unwrap();

        assert_eq!(
            SyncStateLoad::from_bytes(&version_two),
            SyncStateLoad::UnsupportedVersion
        );

        fs::write(fx.primary(), &version_two).unwrap();

        assert_refused_untouched(&fx, AcquireRefusal::OldUnsupportedVersion);
    }

    #[test]
    fn n3_an_empty_or_oversized_primary_is_size_unsupported() {
        // REAL NTFS.
        let fx = Fixture::new("n3");

        fs::write(fx.primary(), b"").unwrap();
        assert_refused_untouched(&fx, AcquireRefusal::SizeUnsupported);

        fs::write(fx.primary(), vec![b'x'; MAX_SYNC_STATE_BYTES + 1]).unwrap();
        assert_refused_untouched(&fx, AcquireRefusal::SizeUnsupported);
    }

    #[test]
    fn n4_a_valid_record_of_another_locator_at_this_key_is_old_locator_mismatch() {
        // REAL NTFS.
        let fx = Fixture::new("n4");
        let other = state_with(OTHER_LOCAL, TARGET, BINDING, VAULT, 1);

        fs::write(fx.primary(), other.encode().unwrap()).unwrap();

        assert_refused_untouched(&fx, AcquireRefusal::OldLocatorMismatch);
    }

    #[test]
    fn n5_a_valid_record_that_is_not_the_expected_old_state_is_old_state_changed() {
        // REAL NTFS.
        let fx = Fixture::new("n5");

        fs::write(fx.primary(), bytes_of(3)).unwrap();

        assert_refused_untouched(&fx, AcquireRefusal::OldStateChanged);
    }

    fn contract_refusal(old: &SyncState, new: &SyncState) -> ContractRefusal {
        ExchangeContract::new(&loc(LOCAL), old, new, Uuid::new_v4(), Uuid::new_v4()).unwrap_err()
    }

    #[test]
    fn n6_a_proposed_state_of_another_locator_is_refused() {
        // PURE.
        let other = state_with(OTHER_LOCAL, TARGET, BINDING, VAULT, 2);

        assert_eq!(
            contract_refusal(&rev(1), &other),
            ContractRefusal::LocatorMismatch
        );
        assert_eq!(
            contract_refusal(&state_with(OTHER_LOCAL, TARGET, BINDING, VAULT, 1), &rev(2)),
            ContractRefusal::LocatorMismatch
        );
    }

    #[test]
    fn n7_a_changed_binding_vault_tag_or_target_is_refused() {
        // PURE.
        for (label, proposed) in [
            (
                "binding id",
                state_with(LOCAL, TARGET, OTHER_BINDING, VAULT, 2),
            ),
            (
                "vault tag",
                state_with(LOCAL, TARGET, BINDING, OTHER_VAULT, 2),
            ),
            ("target", state_with(LOCAL, OTHER_TARGET, BINDING, VAULT, 2)),
            (
                "local locator spelled in another ASCII case",
                state_with(&LOCAL.to_ascii_lowercase(), TARGET, BINDING, VAULT, 2),
            ),
        ] {
            assert_eq!(
                contract_refusal(&rev(1), &proposed),
                ContractRefusal::BindingChanged,
                "{label}"
            );
        }
    }

    #[test]
    fn n8_a_proposed_state_identical_to_the_expected_old_one_is_no_change() {
        // PURE.
        assert_eq!(
            contract_refusal(&rev(1), &rev(1)),
            ContractRefusal::NoChange
        );
    }

    #[test]
    fn n9_bad_keys_and_tokens_are_refused() {
        // PURE.
        let key = exchange_key(&loc(LOCAL));
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());

        assert!(RecordLeaves::derive(&key, a, b).is_ok());

        for (label, bad) in [
            ("uppercase", key.to_uppercase()),
            ("63 characters", key[..63].to_owned()),
            ("65 characters", format!("{key}0")),
            ("non-hex", format!("g{}", &key[1..])),
            ("empty", String::new()),
        ] {
            assert_eq!(
                RecordLeaves::derive(&bad, a, b).unwrap_err(),
                LeafRefusal::KeyMalformed,
                "{label}"
            );
        }

        assert_eq!(
            RecordLeaves::derive(&key, Uuid::nil(), b).unwrap_err(),
            LeafRefusal::TokenNil
        );
        assert_eq!(
            RecordLeaves::derive(&key, a, Uuid::nil()).unwrap_err(),
            LeafRefusal::TokenNil
        );
        assert_eq!(
            RecordLeaves::derive(&key, a, a).unwrap_err(),
            LeafRefusal::TokensNotDistinct
        );

        // The same refusals through the contract.
        assert_eq!(
            ExchangeContract::new(&loc(LOCAL), &rev(1), &rev(2), Uuid::nil(), b).unwrap_err(),
            ContractRefusal::Leaf(LeafRefusal::TokenNil)
        );
        assert_eq!(
            ExchangeContract::new(&loc(LOCAL), &rev(1), &rev(2), a, a).unwrap_err(),
            ContractRefusal::Leaf(LeafRefusal::TokensNotDistinct)
        );
    }

    // ================================================================================
    // INJECTED: I1-I5
    // ================================================================================

    #[test]
    fn i1_stage_faults_remove_the_new_object_by_handle_and_leave_no_tmp_file() {
        // INJECTED faults, real files.
        for (fault, reason) in [
            (StageFault::Write, StageRefusal::WriteFailed),
            (StageFault::Flush, StageRefusal::FlushFailed),
            (StageFault::Sync, StageRefusal::SyncFailed),
        ] {
            let fx = Fixture::new("i1");
            let mut seams = RecordSeams::none().with_fault(fault);
            let failure = match fx.acquire().stage(&mut seams) {
                Err(failure) => failure,
                Ok(_) => panic!("a staging fault was not reported"),
            };

            eprintln!(
                "OBSERVED I1 {fault:?}: {:?}, staging_remains={}",
                failure.reason, failure.staging_remains
            );

            assert_eq!(failure.reason, reason);
            assert!(!failure.staging_remains);
            assert_resources(failure.held.resources(), true, false);
            assert!(!fx.staging().exists());
            fx.expect_sorted(vec![fx.primary_leaf()]);
            assert_eq!(fx.load(), loaded(&rev(1)));
        }
    }

    #[test]
    fn i2_injected_first_rename_results_are_classified_and_unknown_removes_nothing() {
        // INJECTED statuses over a real filesystem (the old object really stays in place).
        for (status, reason) in [
            (COLLISION, NotExchangedReason::RetentionCollision),
            (DENIED, NotExchangedReason::RetentionRefused),
        ] {
            let fx = Fixture::new("i2a");
            let mut seams = inject_at(RecordStage::BeforeRetentionRename, status);
            let staged = fx.acquire().stage(&mut seams).unwrap();

            let RecordExchangeOutcome::NotExchanged(not_exchanged) =
                staged.exchange(&mut || true, &mut seams)
            else {
                panic!("expected NotExchanged for {}", hex(status));
            };

            eprintln!(
                "OBSERVED I2 injected {} on the first rename: {:?}",
                hex(status),
                not_exchanged.reason
            );

            assert_eq!(not_exchanged.reason, reason);
            assert!(!not_exchanged.staging_remains);
            assert!(!fx.staging().exists());
            assert_resources(not_exchanged.resources(), true, false);
            fx.expect_sorted(vec![fx.primary_leaf()]);
            assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(1));
        }

        for status in [PENDING, BUFFER_OVERFLOW, UNSUCCESSFUL] {
            let fx = Fixture::new("i2b");
            let mut seams = inject_at(RecordStage::BeforeRetentionRename, status);
            let staged = fx.acquire().stage(&mut seams).unwrap();

            let RecordExchangeOutcome::Unknown(unknown) = staged.exchange(&mut || true, &mut seams)
            else {
                panic!("expected Unknown for {}", hex(status));
            };

            eprintln!(
                "OBSERVED I2 injected {} on the first rename: Unknown at {:?}",
                hex(status),
                unknown.at()
            );

            assert_eq!(unknown.at(), UnknownStep::RetentionRename);
            assert_resources(unknown.resources(), true, true);
            // The new object was NOT removed.
            assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));
            assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(1));
            assert!(!fx.retention().exists());
        }
    }

    #[test]
    fn i3_unknown_publication_failed_restoration_and_unknown_restoration_remove_nothing() {
        // INJECTED statuses over a real filesystem.
        let all_kept = |fx: &Fixture, resources: ResourceFacts| {
            assert_resources(resources, true, true);
            assert!(!fx.primary().exists());
            assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1));
            assert_eq!(fs::read(fx.staging()).unwrap(), bytes_of(2));
        };

        // (a) the second rename is unknown.
        let fx = Fixture::new("i3a");
        let mut seams = inject_at(RecordStage::BetweenRenames, PENDING);
        let staged = fx.acquire().stage(&mut seams).unwrap();

        let RecordExchangeOutcome::Unknown(unknown) = staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Unknown");
        };

        eprintln!(
            "OBSERVED I3 second rename unknown: Unknown at {:?}",
            unknown.at()
        );

        assert_eq!(unknown.at(), UnknownStep::Publication);
        all_kept(&fx, unknown.resources());
        drop(unknown);

        // (b) the second rename and the restoration are both refused.
        let fx = Fixture::new("i3b");
        let mut seams = RecordSeams::none().on_stage(|stage| match stage {
            RecordStage::BetweenRenames | RecordStage::BeforeRestore => {
                handle_ops::inject_rename_status(DENIED)
            }
            _ => {}
        });
        let staged = fx.acquire().stage(&mut seams).unwrap();

        let RecordExchangeOutcome::Interrupted(interrupted) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Interrupted");
        };

        eprintln!("OBSERVED I3 restoration refused: Interrupted");

        all_kept(&fx, interrupted.resources());
        drop(interrupted);

        // (c) the second rename is refused and the restoration is unknown.
        let fx = Fixture::new("i3c");
        let mut seams = RecordSeams::none().on_stage(|stage| match stage {
            RecordStage::BetweenRenames => handle_ops::inject_rename_status(DENIED),
            RecordStage::BeforeRestore => handle_ops::inject_rename_status(PENDING),
            _ => {}
        });
        let staged = fx.acquire().stage(&mut seams).unwrap();

        let RecordExchangeOutcome::Unknown(unknown) = staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Unknown");
        };

        eprintln!(
            "OBSERVED I3 restoration unknown: Unknown at {:?}",
            unknown.at()
        );

        assert_eq!(unknown.at(), UnknownStep::Restoration);
        all_kept(&fx, unknown.resources());
    }

    #[test]
    fn i4_a_failing_handle_removal_leaves_the_staging_file_and_says_so() {
        // INJECTED delete failure, real files.
        // (a) while staging fails.
        let fx = Fixture::new("i4a");
        let mut seams = RecordSeams::none()
            .with_fault(StageFault::Write)
            .on_stage(|stage| {
                if stage == RecordStage::BeforeStageWrite {
                    handle_ops::inject_delete_status(UNSUCCESSFUL);
                }
            });
        let failure = match fx.acquire().stage(&mut seams) {
            Err(failure) => failure,
            Ok(_) => panic!("a staging fault was not reported"),
        };

        eprintln!(
            "OBSERVED I4 staging removal refused: staging_remains={}",
            failure.staging_remains
        );

        assert_eq!(failure.reason, StageRefusal::WriteFailed);
        assert!(failure.staging_remains);
        assert!(fx.staging().exists(), "the file must stay");
        assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(1));

        // (b) when the recheck refuses: first with a failing removal, then a working one.
        for (inject, remains) in [(true, true), (false, false)] {
            let fx = Fixture::new("i4b");
            let staged = fx.acquire().stage(&mut RecordSeams::none()).unwrap();

            if inject {
                handle_ops::inject_delete_status(UNSUCCESSFUL);
            }

            let RecordExchangeOutcome::NotExchanged(not_exchanged) =
                staged.exchange(&mut || false, &mut RecordSeams::none())
            else {
                panic!("expected NotExchanged");
            };

            assert_eq!(not_exchanged.reason, NotExchangedReason::RecheckRefused);
            assert_eq!(not_exchanged.staging_remains, remains);
            assert_eq!(fx.staging().exists(), remains);
        }
    }

    #[test]
    fn i5_the_test_only_release_distinguishes_refused_marked_and_unproven_results() {
        // INJECTED delete statuses over real files; the retention file is kept in both.
        let hook = |status: i32| {
            RecordSeams::none().on_stage(move |stage| {
                if stage == RecordStage::BeforeRelease {
                    handle_ops::inject_delete_status(status);
                }
            })
        };

        for (status, expected, label) in [
            (UNSUCCESSFUL, PreviousRelease::Retained, "injected failure"),
            (
                0,
                PreviousRelease::Unknown,
                "injected success without a real mark",
            ),
        ] {
            let fx = Fixture::new("i5");
            let verified = run_to_verified(&fx, &rev(1), &rev(2), &mut RecordSeams::none());
            let report = verified.release_previous(&mut hook(status));

            eprintln!(
                "OBSERVED I5 {label}: {:?}, links {} -> {:?}, delete-pending after {:?}",
                report.release,
                report.observed.links_before,
                report.observed.links_after,
                report.observed.delete_pending_after
            );

            assert_eq!(report.release, expected, "{label}");
            assert_eq!(fs::read(fx.retention()).unwrap(), bytes_of(1), "{label}");
            assert_eq!(fs::read(fx.primary()).unwrap(), bytes_of(2), "{label}");

            report.published.close();
        }
    }

    // ================================================================================
    // PURE: P1-P5
    // ================================================================================

    #[test]
    fn p1_leaf_shapes_match_the_legacy_grammar() {
        // PURE.
        let key = exchange_key(&loc(LOCAL));
        let (staging, retention) = (Uuid::new_v4(), Uuid::new_v4());
        let leaves = RecordLeaves::derive(&key, staging, retention).unwrap();

        assert_eq!(key.len(), KEY_LEN);
        assert!(is_lower_hex(&key));
        assert_eq!(
            key,
            exchange_key(&loc(&LOCAL.to_ascii_lowercase())),
            "the key ignores the ASCII case of the locator"
        );
        assert_eq!(leaves.primary(), format!("{key}.json").as_str());

        for (leaf, token) in [(leaves.staging(), staging), (leaves.retention(), retention)] {
            let leaf = leaf.to_str().unwrap();
            let rest = leaf
                .strip_prefix(key.as_str())
                .and_then(|rest| rest.strip_prefix('.'))
                .and_then(|rest| rest.strip_suffix(".tmp"))
                .expect("<key>.<token>.tmp");

            assert_eq!(rest.len(), 32);
            assert!(is_lower_hex(rest));
            assert_eq!(rest, token.simple().to_string());
        }
    }

    #[test]
    fn p2_the_mark_judgement_and_occupant_tables() {
        // PURE.
        let facts = |links: u32, pending: bool| {
            HandleFacts::for_test(1, [1; 16], links, pending, FileSystemKind::Ntfs, true)
        };
        let saved = facts(1, false);

        // A native success needs delete-pending and exactly one name fewer.
        assert_eq!(
            judge_mark(true, Ok(facts(0, true)), &saved),
            PreviousMark::Marked
        );
        assert_eq!(
            judge_mark(true, Ok(facts(1, true)), &facts(2, false)),
            PreviousMark::Marked
        );
        assert_eq!(
            judge_mark(true, Ok(facts(1, true)), &saved),
            PreviousMark::Unknown
        );
        assert_eq!(
            judge_mark(true, Ok(facts(0, false)), &saved),
            PreviousMark::Unknown
        );
        assert_eq!(
            judge_mark(true, Ok(facts(2, true)), &saved),
            PreviousMark::Unknown
        );
        assert_eq!(
            judge_mark(true, Ok(facts(1, false)), &saved),
            PreviousMark::Unknown
        );
        assert_eq!(
            judge_mark(true, Ok(facts(0, true)), &facts(0, false)),
            PreviousMark::Unknown,
            "a saved count of zero can never go one lower"
        );

        // A native refusal needs the very same, not delete-pending, unchanged facts.
        assert_eq!(
            judge_mark(false, Ok(facts(1, false)), &saved),
            PreviousMark::NotMarked
        );
        assert_eq!(
            judge_mark(false, Ok(facts(1, true)), &saved),
            PreviousMark::Unknown
        );
        assert_eq!(
            judge_mark(false, Ok(facts(0, false)), &saved),
            PreviousMark::Unknown
        );
        assert_eq!(
            judge_mark(false, Ok(facts(0, true)), &saved),
            PreviousMark::Unknown
        );

        // Another file, another filesystem, a remote device or a failed query prove nothing.
        let other_file = HandleFacts::for_test(1, [2; 16], 0, true, FileSystemKind::Ntfs, true);
        let remote = HandleFacts::for_test(1, [1; 16], 0, true, FileSystemKind::Ntfs, false);
        let refs = HandleFacts::for_test(1, [1; 16], 0, true, FileSystemKind::Refs, true);

        for native_ok in [true, false] {
            for after in [other_file, remote, refs] {
                assert_eq!(
                    judge_mark(native_ok, Ok(after), &saved),
                    PreviousMark::Unknown
                );
            }

            assert_eq!(
                judge_mark(native_ok, Err(IdentityError::Lookup), &saved),
                PreviousMark::Unknown
            );
        }

        // The occupant table.
        let (new, old) = (
            HandleFacts::for_test(1, [3; 16], 1, false, FileSystemKind::Ntfs, true),
            HandleFacts::for_test(1, [4; 16], 1, false, FileSystemKind::Ntfs, true),
        );
        let present = |id: u8| {
            FreshRead::Present(Fresh {
                facts: HandleFacts::for_test(1, [id; 16], 1, false, FileSystemKind::Ntfs, true),
                bytes: None,
            })
        };

        assert_eq!(occupant(&FreshRead::Absent, &new, &old), Occupant::Empty);
        assert_eq!(occupant(&present(3), &new, &old), Occupant::New);
        assert_eq!(occupant(&present(4), &new, &old), Occupant::Previous);
        assert_eq!(occupant(&present(5), &new, &old), Occupant::Foreign);
        assert_eq!(
            occupant(&FreshRead::Unexpected, &new, &old),
            Occupant::Foreign
        );
        assert_eq!(
            occupant(&FreshRead::Failed, &new, &old),
            Occupant::Indeterminate
        );
    }

    #[test]
    fn p3_no_debug_output_reveals_a_path_key_token_identity_or_status() {
        // PURE over values produced by real runs.
        let fx = Fixture::new("p3");
        let mut shown: Vec<String> = Vec::new();
        let mut show = |value: &dyn fmt::Debug| shown.push(format!("{value:?}"));

        show(&fx.contract());
        show(fx.contract().leaves());

        // A complete run.
        let held = fx.acquire();

        show(&held);
        show(&held.resources());

        let staged = held.stage(&mut RecordSeams::none()).unwrap();

        show(&staged);

        let outcome = staged.exchange(&mut || true, &mut RecordSeams::none());

        show(&outcome);

        let swapped = exchanged(outcome);

        show(&swapped);

        let verified = swapped.verify(&mut RecordSeams::none()).unwrap();

        show(&verified);

        let report = verified.release_previous(&mut RecordSeams::none());

        show(&report);
        show(&report.published);
        show(&report.observed);
        report.published.close();

        // A staging failure, and every other outcome.
        let mut next = Fixture::new("p3b");
        let failure = match next
            .acquire()
            .stage(&mut RecordSeams::none().with_fault(StageFault::Flush))
        {
            Err(failure) => failure,
            Ok(_) => panic!("a staging fault was not reported"),
        };

        show(&failure);
        drop(failure);
        next.rotate();

        let flows: [(&str, RecordSeams, bool); 5] = [
            ("not exchanged", RecordSeams::none(), false),
            (
                "unknown",
                inject_at(RecordStage::BeforeRetentionRename, PENDING),
                true,
            ),
            (
                "restored",
                inject_at(RecordStage::BetweenRenames, DENIED),
                true,
            ),
            (
                "interrupted",
                RecordSeams::none().on_stage(|stage| match stage {
                    RecordStage::BetweenRenames | RecordStage::BeforeRestore => {
                        handle_ops::inject_rename_status(DENIED)
                    }
                    _ => {}
                }),
                true,
            ),
            ("unverified", RecordSeams::none(), true),
        ];

        // Each outcome is declared before its fixture, so its handles close first.
        let mut keepers: Vec<(Option<RecordExchangeOutcome>, Fixture)> = Vec::new();

        for (index, (label, mut seams, recheck)) in flows.into_iter().enumerate() {
            let fx = Fixture::new(&format!("p3c{index}"));
            let staged = fx.acquire().stage(&mut seams).unwrap();
            let outcome = staged.exchange(&mut || recheck, &mut seams);

            show(&outcome);

            if let RecordExchangeOutcome::NotExchanged(inner) = &outcome {
                show(inner.as_ref());
            }

            if label == "unverified" {
                let swapped = exchanged(outcome);

                // Break the verification on purpose: a link to the retained object.
                fs::hard_link(fx.retention(), fx.dir().join("extra-name.bin")).unwrap();

                let unverified = swapped.verify(&mut RecordSeams::none()).unwrap_err();

                show(&unverified);
                keepers.push((None, fx));
            } else {
                keepers.push((Some(outcome), fx));
            }
        }

        // Every category enum, by value.
        show(&AcquireRefusal::OldCorrupt);
        show(&StageRefusal::ReadBackMismatch);
        show(&NotExchangedReason::RetentionCollision);
        show(&UnknownStep::Restoration);
        show(&VerifyRefusal::RetentionBytesMismatch);
        show(&ContractRefusal::Leaf(LeafRefusal::TokenNil));
        show(&PreviousRelease::Released);
        show(&Slot::NotOwned);

        let mut forbidden: Vec<String> = [
            ".tmp",
            ".json",
            "\\",
            ".qa-local",
            "0x",
            "Synthetic",
            "MARKER",
        ]
        .map(str::to_owned)
        .into();

        forbidden.push(fx.key());
        forbidden.push(fx.staging.simple().to_string());
        forbidden.push(fx.retention.simple().to_string());
        forbidden.push(next.staging.simple().to_string());

        assert!(shown.len() >= 25);

        for text in &shown {
            for needle in &forbidden {
                assert!(!text.contains(needle.as_str()), "{text:?} leaks {needle:?}");
            }
        }

        eprintln!(
            "OBSERVED P3 {} Debug outputs checked, none leaked",
            shown.len()
        );

        drop(keepers);
    }

    fn fragments(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn p4_the_experiment_region_contains_only_the_permitted_native_calls() {
        // PURE: a text scan of this very file.
        let source = include_str!("legacy_record_exchange.rs");
        let marker = concat!("// ---- ", "tests ----");

        assert_eq!(
            source.matches(marker).count(),
            1,
            "exactly one tests marker"
        );

        let region = source.split(marker).next().unwrap();
        let code: String = region
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        // Forbidden anywhere in the file (code, comments, tests): other modules' names.
        for parts in [
            &["target", "_exchange"][..],
            &["exchange", "_recovery"],
            &["authenticated", "_state"],
            &["read_", "record("],
            &["inspect_", "v3_layout"],
            &["V3", "Layout"],
            &["Layout", "Primary"],
            &["Layout", "Uncertainty"],
            &["Layout", "Sibling"],
            &["Sibling", "Kind"],
            &["Sibling", "Content"],
            &["Sibling", "Verdict"],
            &["Sibling", "Report"],
            &["State", "Assessment"],
            &["NonAuthoritative", "Primary"],
            &["recognize_", "v3_sibling_name"],
            &["assess_", "authenticated_sync_state"],
            &["load_", "authenticated_sync_state"],
            &["assess_", "interrupted", "_exchange"],
            &["Exchange", "RecoveryAssessment"],
            &["interrupted_", "exchange"],
            &["SyncState", "MacKey"],
            &["encode_", "authenticated"],
            &["decode_", "authenticated"],
            &["SYNC_STATE_", "AUTHENTICATED_VERSION"],
            &["derive_", "state_mac_key"],
            &["verify_", "state_mac"],
            &["state_", "mac::"],
            &["Authenticated", "SyncState"],
            &["begin_", "exchange"],
            &["finalize_", "exchange"],
            &["clear_", "exchange"],
            &["Exchange", "Refusal"],
            &["Exchange", "TargetEvidence"],
            &["Retained", "VersionEvidence"],
            &["Artifact", "Observation"],
            &["Exchange", "Artifact"],
            &["Previous", "Fault"],
        ] {
            let needle = fragments(parts);

            assert!(!source.contains(&needle), "{needle:?} appears in this file");
        }

        // Forbidden in the experiment region, comment lines excluded.
        for parts in [
            &["fs::", "rename"][..],
            &["fs::", "remove_file"],
            &["fs::", "remove_dir"],
            &["fs::", "hard_link"],
            &["fs::", "copy"],
            &["fs::", "write"],
            &["set_", "len"],
            &[".trunc", "ate("],
            &["Replace", "FileW"],
            &["Move", "File"],
            &["Replace", "IfExists"],
            &["uns", "afe"],
            &["ext", "ern"],
            &["temp", "_dir"],
            &["get", "random"],
            &[".ret", "ired"],
            &[".v3", "stage"],
            &["impl ", "Drop"],
            &["al", "low("],
            &["#!", "["],
        ] {
            let needle = fragments(parts);

            assert!(
                !code.contains(&needle),
                "{needle:?} in the experiment region"
            );
        }

        // The whole file: no attribute that suppresses a lint, no custom Drop.
        assert!(!source.contains(&fragments(&["al", "low("])));
        assert!(!source.contains(&fragments(&["impl ", "Drop"])));
        assert!(!source.contains(&fragments(&["uns", "afe"])));

        // The permitted native calls, counted.
        assert_eq!(code.matches("rename_into_directory_no_replace(").count(), 1);
        assert_eq!(code.matches("delete_by_handle(").count(), 2);
        assert_eq!(code.matches("create_new(true)").count(), 1);
    }

    #[test]
    fn p5_nothing_else_reaches_the_module_and_it_is_private_and_test_only() {
        // PURE: a scan of the source tree.
        fn collect(dir: &Path, extensions: &[&str], found: &mut Vec<(PathBuf, String)>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();

                if path.is_dir() {
                    if path
                        .file_name()
                        .is_some_and(|name| name == "node_modules" || name == "target")
                    {
                        continue;
                    }

                    collect(&path, extensions, found);
                } else if path
                    .extension()
                    .is_some_and(|ext| extensions.iter().any(|wanted| ext == *wanted))
                {
                    found.push((path.clone(), fs::read_to_string(&path).unwrap()));
                }
            }
        }

        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let source_root = manifest.join("src");
        let mut sources = Vec::new();

        collect(&source_root, &["rs"], &mut sources);

        let mut mentioning: Vec<String> = sources
            .iter()
            .filter(|(_, text)| text.contains("legacy_record_exchange"))
            .map(|(path, _)| {
                path.strip_prefix(&source_root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        mentioning.sort();

        assert_eq!(
            mentioning,
            ["vault/legacy_record_exchange.rs", "vault/mod.rs"]
        );

        let (_, declaration) = sources
            .iter()
            .find(|(path, _)| path.ends_with("vault/mod.rs") || path.ends_with("vault\\mod.rs"))
            .unwrap();

        assert!(
            declaration.contains("#[cfg(all(test, windows))]\nmod legacy_record_exchange;")
                || declaration
                    .contains("#[cfg(all(test, windows))]\r\nmod legacy_record_exchange;")
        );
        assert_eq!(declaration.matches("legacy_record_exchange").count(), 1);
        assert!(!declaration.contains("pub mod legacy_record_exchange"));
        assert!(!declaration.contains("pub(crate) mod legacy_record_exchange"));

        // No frontend file knows about it.
        let mut frontend = Vec::new();

        collect(
            &manifest.parent().unwrap().join("src"),
            &["ts", "tsx"],
            &mut frontend,
        );

        assert!(!frontend.is_empty());

        for (path, text) in frontend {
            assert!(
                !text.contains("legacy_record_exchange"),
                "{}",
                path.display()
            );
        }
    }
}
