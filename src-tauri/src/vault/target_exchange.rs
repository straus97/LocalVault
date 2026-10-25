//! Dormant, synthetic Windows held-handle file exchange (Stage 1U-4, slice B3b-1).
//!
//! **This is an experiment, not an update feature.** It exists to find out, on a
//! real local NTFS volume, whether an existing file can be replaced by a new one
//! while *nothing is ever replaced*: the old file is moved aside under a new name
//! and the new file is moved into the old name, both renames made through handles
//! that stay open and into a directory that stays pinned. It is unreachable from
//! sessions, commands and the UI (nothing outside this file and its `mod`
//! declaration refers to it; a test scans for that) and is exercised only on
//! synthetic dummy bytes in a test-owned scratch directory.
//!
//! **No outcome of this module authorizes anything.** A successful native
//! operation here is not consent, not permission and not a reason to update a
//! bound vault. There is no approval type, no conversion to one, and no
//! sync-state interaction. Every later step (recovery, authentication of the
//! sync state, the session write path) is a separate, not yet approved slice.
//!
//! # Sequence
//!
//! 1. [`HeldTarget::acquire`]: pin the target's directory; open the old file `T`
//!    with `GENERIC_READ | DELETE`, share mode `FILE_SHARE_READ` **only**, and
//!    `FILE_FLAG_OPEN_REPARSE_POINT`; judge the handle; read `T`'s bytes through
//!    that same handle. While it is held no ordinary process can write to,
//!    delete, rename or replace `T`.
//! 2. [`HeldTarget::stage`]: create the new file `S` (`create_new`) in the same
//!    directory under a derived hidden name, hold it with read, write and delete
//!    access and read-only sharing, write the bytes, flush, `sync_all`, and check
//!    the physical facts of the handle.
//! 3. [`Staged::exchange`]: rename `T` to the retention name `R`, then rename `S`
//!    to the original leaf. Both are `NtSetInformationFile(FileRenameInformation)`
//!    with `ReplaceIfExists` FALSE, applied to the open handle and relative to the
//!    pinned directory object (`handle_ops`, reused unchanged). Nothing is
//!    replaced; a name that exists makes the kernel refuse.
//! 4. [`Swapped::verify`]: while both handles are still held, read the new target
//!    and the retained old file independently and compare identities and bytes.
//!
//! # The empty-name window
//!
//! Between the two renames the original leaf does not exist. A third party that
//! creates a file at that name in the window is **never overwritten**: the second
//! rename is refused by the kernel and the outcome is
//! [`ExchangeOutcome::TargetTakenOver`], with the old version retained. This
//! window is the price of never replacing; whether it is acceptable for any user
//! facing use is a later product decision.
//!
//! # Names
//!
//! [`ExchangeNames`] is derived only from the target's actual leaf and a non-nil
//! [`ExchangeId`]; callers cannot supply a staging or retention name. The leaf must
//! be the exact long name present in the directory (an 8.3 alias or a different
//! case is refused: renaming `S` to a different spelling would break name
//! continuity). The staging and retention names must be absent before anything is
//! created; the kernel's no-replace rule still holds if one appears afterwards.
//!
//! # Deletion rules
//!
//! The only production deletion is a handle-bound delete of **our own staging
//! file**, and only while that object certainly still carries its staging name
//! (a failure before the first rename, or a rename the kernel definitely refused).
//! No production method deletes or renames the retained old file `R`:
//! [`Verified::retain_previous`] only closes the handles. A
//! `#[cfg(test)]` method exists solely so tests can prove the deletion mechanics.
//! After an unknown native status nothing is deleted and nothing is retried.
//! Dropping any value in this module closes handles and deletes nothing: it is the
//! crash-equivalent.
//!
//! # Limits (not claimed away)
//!
//! * Guarantees hold for **ordinary processes** that honor sharing modes.
//!   Administrators, backup-privileged processes, kernel components and
//!   filesystem filter drivers can bypass them; pre-existing writable memory
//!   mappings of `T` are not addressed; the driver-reported filesystem facts are
//!   trusted.
//! * Opening `T` and creating `S` are by path (std offers no create relative to a
//!   handle without more `windows-sys` features); the handles are judged after
//!   the open and the renames are handle-bound, but a redirection installed in the
//!   instant between the ancestor check and the open is not excluded.
//! * `sync_all` and a verified read-back are **not** directory or power-loss
//!   durability. No directory flush is performed, so after a power loss recent
//!   renames may be absent, in some order; nothing here establishes which states
//!   are possible. After a process crash the on-disk state is exactly the state at
//!   the crash instant.
//! * Cross-volume ordering, other Windows builds, ReFS, SMB, FAT, real cloud
//!   clients and Controlled Folder Access are not exercised.
//!
//! # Measured native behaviour (Windows 10 build 19045.2965, local NTFS)
//!
//! Recorded by the tests (`--nocapture` prints `OBSERVED ...` lines):
//!
//! * Renaming the held `T` to `R`, then renaming the held `S` to the original
//!   leaf, both by handle into the pinned directory, without replace: accepted
//!   (`STATUS_SUCCESS`). File identities survive both renames.
//! * An additional reader (read access, full sharing) opened on `T` after it was
//!   held: the open succeeds, both held-handle renames still succeed, and the
//!   reader's handle keeps reading the old bytes (it follows the file, not the
//!   name).
//! * A competing writer, an append or truncating open, a delete-access open,
//!   `fs::write`, `remove_file` and `rename` away, in-process and (write, `del`,
//!   `ren`) from a child `cmd.exe`: all refused with `ERROR_SHARING_VIOLATION`
//!   (32) while `T` is held. A rename-replace *onto* `T` (the sync-client
//!   `MoveFileEx` pattern) is refused with `ERROR_ACCESS_DENIED` (5).
//! * A hard link created to the held `T`: **succeeds** (links become 2); a
//!   read-only share mode does not stop it. The recheck immediately before the
//!   first rename refuses it (`TargetNotSingleLink`). A link created *after* that
//!   recheck is not prevented: the handle-bound rename moves only the name `T`
//!   was opened through, the other name keeps the old bytes, the exchange is
//!   accepted, and [`Swapped::verify`] then refuses it (`PreviousChanged`). Nothing
//!   is lost.
//! * Renaming an ancestor of the pinned directory while a file in it is held:
//!   refused (`ERROR_ACCESS_DENIED`, 5).
//! * 8.3 short names on the scratch volume (`D:`): none were generated for a long
//!   name, so the short-alias refusal was **not** physically tested here; only the
//!   code-unit-exact directory-listing rule that implements it was (with a
//!   different-case spelling).
//! * A foreign file created in the empty-name window: the second rename is
//!   refused by the kernel (`STATUS_OBJECT_NAME_COLLISION`); the foreign file is
//!   untouched. The same status refuses a first rename onto an existing
//!   retention name.
//!
//! Unproven here and stated plainly: power loss and directory durability,
//! privileged or filter-driver interference, writable mapped views, ReFS/SMB/FAT,
//! real cloud-client behaviour, other Windows builds, and Controlled Folder
//! Access.
//!
//! No path, name, identifier, native status or byte appears in any error, outcome
//! or `Debug` output.
#![cfg(windows)]
#![cfg_attr(not(test), allow(dead_code))]

use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use localvault_core::sync::MAX_ENVELOPE_BYTES;
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ},
};

use super::{
    file_identity::{
        compare, facts_of, volume_facts_of, FileIdentity, HandleFacts, IdentityError,
        PhysicalVerdict, VolumeFacts,
    },
    handle_ops::{self, DefiniteRefusal, RenameStatus},
    new_copy_file::open_directory_pin,
    sync_file_adapter::{SyncFileRead, SyncFileTarget, UnavailableReason},
};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// The longest file name NTFS accepts, in UTF-16 code units.
const MAX_LEAF_UNITS: usize = 255;

// ---- names -------------------------------------------------------------------

/// Why a name could not be derived. Categories only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameRefusal {
    /// The exchange id was the nil UUID.
    IdNil,
    /// The target locator has no file name.
    LocatorUnusable,
    /// Empty, `.` or `..`.
    LeafEmpty,
    /// Not valid Unicode (an unpaired surrogate).
    LeafNotUnicode,
    /// A separator, an alternate-data-stream colon, a wildcard, a quote, an angle
    /// bracket, a pipe, a control character or NUL.
    LeafForbiddenCharacter,
    /// Ends with a dot or a space, which Windows silently strips.
    LeafTrailingDotOrSpace,
    /// A reserved device name (`CON`, `NUL`, `COM1`, ...), with any extension.
    LeafReservedDevice,
    /// More than 255 UTF-16 code units.
    LeafTooLong,
    /// Two of the three names are equal exactly, ASCII-case-insensitively or
    /// under Unicode uppercase folding.
    LeavesNotDistinct,
}

/// A non-nil identifier that makes the staging and retention names unique.
/// Caller-supplied (a later slice will use the pending intent id). `Debug` is
/// redacted. Carries no authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExchangeId(Uuid);

impl ExchangeId {
    pub(crate) fn new(id: Uuid) -> Result<Self, NameRefusal> {
        if id.is_nil() {
            Err(NameRefusal::IdNil)
        } else {
            Ok(Self(id))
        }
    }
}

impl fmt::Debug for ExchangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExchangeId(<redacted>)")
    }
}

/// The three leaves of one exchange: the target's own, the hidden staging name
/// and the retention name. Fields are private and only
/// [`derive`](Self::derive) builds one, so an application caller can never name a
/// file for this module to create or rename to. `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExchangeNames {
    target: OsString,
    staging: OsString,
    retention: OsString,
}

impl fmt::Debug for ExchangeNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExchangeNames(<redacted>)")
    }
}

impl ExchangeNames {
    /// `target` is the exact leaf of `target`; `staging` is
    /// `"." + leaf + ".localvault-update-" + id + ".tmp"`; `retention` is
    /// `"." + leaf + ".localvault-previous-" + id + ".lvprev"` (never `.lvault`).
    /// `id` is the lowercase hyphenated form. Pure: no I/O.
    pub(crate) fn derive(target: &SyncFileTarget, id: ExchangeId) -> Result<Self, NameRefusal> {
        let leaf = Path::new(target.locator().as_str())
            .file_name()
            .ok_or(NameRefusal::LocatorUnusable)?;

        validate_leaf(leaf)?;

        let id = id.0.hyphenated().to_string();

        let mut staging = OsString::from(".");

        staging.push(leaf);
        staging.push(format!(".localvault-update-{id}.tmp"));

        let mut retention = OsString::from(".");

        retention.push(leaf);
        retention.push(format!(".localvault-previous-{id}.lvprev"));

        validate_leaf(&staging)?;
        validate_leaf(&retention)?;

        if !leaves_are_distinct(&[leaf, &staging, &retention]) {
            return Err(NameRefusal::LeavesNotDistinct);
        }

        Ok(Self {
            target: leaf.to_owned(),
            staging,
            retention,
        })
    }
}

/// One plain file name that Windows will not reinterpret.
fn validate_leaf(leaf: &OsStr) -> Result<(), NameRefusal> {
    let text = leaf.to_str().ok_or(NameRefusal::LeafNotUnicode)?;

    if text.is_empty() || text == "." || text == ".." {
        return Err(NameRefusal::LeafEmpty);
    }

    if text.chars().any(|c| {
        matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || c.is_control()
    }) {
        return Err(NameRefusal::LeafForbiddenCharacter);
    }

    if text.ends_with('.') || text.ends_with(' ') {
        return Err(NameRefusal::LeafTrailingDotOrSpace);
    }

    if is_reserved_device_name(text) {
        return Err(NameRefusal::LeafReservedDevice);
    }

    if text.encode_utf16().count() > MAX_LEAF_UNITS {
        return Err(NameRefusal::LeafTooLong);
    }

    Ok(())
}

fn is_reserved_device_name(name: &str) -> bool {
    // A reserved name is reserved with any extension: `NUL.txt` is `NUL`.
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    let upper = stem.to_ascii_uppercase();

    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|rest| {
            let mut chars = rest.chars();

            // `COM1`-`COM9` and the superscript forms Windows also reserves.
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
}

fn ascii_fold(name: &OsStr) -> String {
    name.to_string_lossy().to_ascii_lowercase()
}

fn unicode_fold(name: &OsStr) -> String {
    name.to_string_lossy()
        .chars()
        .flat_map(char::to_uppercase)
        .collect()
}

/// Pairwise distinct under exact, ASCII-case-insensitive and Unicode-uppercase
/// comparison.
fn leaves_are_distinct(leaves: &[&OsStr]) -> bool {
    leaves.iter().enumerate().all(|(index, first)| {
        leaves[index + 1..].iter().all(|second| {
            first != second
                && ascii_fold(first) != ascii_fold(second)
                && unicode_fold(first) != unicode_fold(second)
        })
    })
}

// ---- refusal and reason categories ---------------------------------------------

/// Why [`HeldTarget::acquire`] refused. Nothing was created; the old file was not
/// touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquireRefusal {
    /// The locator has no parent or leaf.
    TargetLocatorUnusable,
    /// The names were not derived from this target's leaf.
    NamesMismatch,
    /// The parent directory could not be opened or listed.
    ParentUnavailable,
    /// The parent is a reparse point (junction, symlink, mount point) or not a
    /// directory.
    ParentNotPlain,
    /// The parent is not on a local NTFS volume.
    VolumeNotLocalNtfs,
    /// An ancestor of the parent is a reparse point, missing or not a directory.
    AncestorNotPlain,
    /// The directory has no entry whose name equals the locator's leaf code unit
    /// for code unit (a different case or an 8.3 alias).
    TargetNameNotCanonical,
    /// The staging name already exists in the directory, in any case.
    StagingNameExists,
    /// The retention name already exists in the directory, in any case.
    RetentionNameExists,
    /// There is no file at the target.
    TargetMissing,
    /// A directory, reparse point or special file is at the target name.
    TargetNotPlainFile,
    /// Another handle's access or sharing is incompatible with holding the file
    /// (a sharing violation).
    TargetBusy,
    /// The file could not be opened for another reason (permission, I/O).
    TargetOpenFailed,
    /// Empty or larger than the envelope limit.
    SizeUnsupported,
    /// The physical facts of the handle could not be established or do not allow
    /// a conclusion.
    IdentityUncertain,
    /// The handle is not on a local NTFS volume.
    TargetNotLocalNtfs,
    /// The target is the same physical file as the primary.
    PrimaryAlias,
    /// The target has more than one hard link.
    NotSingleLink,
    /// The target is delete-pending.
    DeletePending,
    /// The physical identity is not the expected one.
    IdentityChanged,
    /// The bytes could not be read completely through the held handle.
    ReadFailed,
    /// A fresh read of the target path does not report the held file.
    FreshReadMismatch,
}

/// Why [`HeldTarget::stage`] failed. `staging_remains` in
/// [`StageFailure`] says whether our own staging file could not be confirmed
/// removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageRefusal {
    /// The new bytes are empty or larger than the envelope limit.
    BytesUnsupported,
    /// The staging name appeared before it could be created.
    StagingNameExists,
    /// The staging file could not be created.
    StagingCreateFailed,
    /// Writing failed.
    WriteFailed,
    /// Flushing or `sync_all` failed.
    FlushFailed,
    /// The file length is not the number of bytes written.
    LengthMismatch,
    /// The staging file is not on a local NTFS volume.
    VolumeNotLocalNtfs,
    /// The physical facts could not be established, or the staging file is not a
    /// single-link, live file distinct from the primary and the old target.
    IdentityUncertain,
    /// An independent read of the staging file does not return what was written.
    ReadBackMismatch,
}

/// Why nothing was exchanged: the old file never left its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotExchangedReason {
    /// The caller's own check said the evidence changed.
    RecheckRefused,
    /// The old file's physical facts could not be re-established or changed in an
    /// unclassified way.
    IdentityUncertain,
    /// The path no longer resolves to the held file with the held bytes.
    TargetChanged,
    /// The held file gained a hard link.
    TargetNotSingleLink,
    /// The held file is delete-pending.
    TargetDeletePending,
    /// The staging file changed after it was checked.
    StagingChanged,
    /// The retention name existed: the kernel refused the first rename.
    RetentionCollision,
    /// The kernel definitely refused the first rename for another reason.
    RetentionRefused,
}

/// Which native step was not definite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeStep {
    /// The first rename (old file to the retention name).
    RetentionRename,
    /// The second rename (new file to the original leaf), or the evidence around
    /// a refusal of it was contradictory.
    Publication,
    /// The restoring rename (old file back to the original leaf).
    Restoration,
}

/// Why [`Swapped::verify`] did not confirm the exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyRefusal {
    /// The new file's handle facts changed.
    NewVersionChanged,
    /// The old file's handle facts changed.
    PreviousChanged,
    /// The target path could not be read, or is not a plain file.
    TargetUnreadable,
    /// The target path does not resolve to the new file.
    TargetIdentityMismatch,
    /// The target path's file is not a single-link, local-NTFS file distinct from
    /// the primary and the old file.
    TargetFactsRefused,
    /// The target's bytes are not the new bytes.
    TargetBytesMismatch,
    /// The caller's own check of the target bytes failed.
    CheckRejected,
    /// The retention path could not be read.
    RetentionUnreadable,
    /// The retention path does not resolve to the old file.
    RetentionIdentityMismatch,
    /// The retained file's bytes are not the old bytes.
    RetentionBytesMismatch,
}

// ---- seams ---------------------------------------------------------------------

/// Fixed points of the sequence, for the test hooks. Always defined; only tests
/// can observe or act on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    BeforeAcquire,
    AfterAcquire,
    BeforeStageWrite,
    BeforeRetentionRename,
    BetweenRenames,
    BeforeRestore,
    BeforeVerify,
}

#[cfg(test)]
type StageHook = Box<dyn FnMut(Stage)>;

/// A write failure to inject while staging (tests only).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageFault {
    /// Fail after writing the first half of the bytes.
    Write,
    Flush,
    Sync,
}

/// Test seams. In production this is an empty value whose methods change nothing.
/// Injected facts, faults and hooks prove **decision logic only**; they say nothing
/// about what a real filesystem does.
#[derive(Default)]
pub(crate) struct Seams {
    #[cfg(test)]
    hook: Option<StageHook>,
    #[cfg(test)]
    directory_facts: Option<VolumeFacts>,
    #[cfg(test)]
    target_facts: Option<Result<HandleFacts, IdentityError>>,
    #[cfg(test)]
    staging_facts: Option<Result<HandleFacts, IdentityError>>,
    #[cfg(test)]
    stage_fault: Option<StageFault>,
    #[cfg(test)]
    verify_read: Option<Box<dyn FnMut(SyncFileRead) -> SyncFileRead>>,
}

impl Seams {
    pub(crate) fn none() -> Self {
        Self::default()
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn hit(&mut self, stage: Stage) {
        #[cfg(test)]
        if let Some(hook) = self.hook.as_mut() {
            hook(stage);
        }
    }

    fn directory_facts(
        &self,
        real: Result<VolumeFacts, IdentityError>,
    ) -> Result<VolumeFacts, IdentityError> {
        #[cfg(test)]
        if let Some(injected) = self.directory_facts {
            return Ok(injected);
        }

        real
    }

    fn target_facts(
        &self,
        real: Result<HandleFacts, IdentityError>,
    ) -> Result<HandleFacts, IdentityError> {
        #[cfg(test)]
        if let Some(injected) = self.target_facts {
            return injected;
        }

        real
    }

    fn staging_facts(
        &self,
        real: Result<HandleFacts, IdentityError>,
    ) -> Result<HandleFacts, IdentityError> {
        #[cfg(test)]
        if let Some(injected) = self.staging_facts {
            return injected;
        }

        real
    }

    fn verify_read(&mut self, real: SyncFileRead) -> SyncFileRead {
        #[cfg(test)]
        if let Some(map) = self.verify_read.as_mut() {
            return map(real);
        }

        real
    }
}

// ---- shared helpers ------------------------------------------------------------

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
/// directory. Local on purpose: the sibling modules' own checks are private.
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

/// Read exactly `len` bytes through `handle`, consuming at most `len + 1`.
fn read_through(handle: &File, len: u64) -> Option<Vec<u8>> {
    if len == 0 || len > MAX_ENVELOPE_BYTES as u64 {
        return None;
    }

    let probe = len + 1;
    let mut bytes = Vec::with_capacity(usize::try_from(probe).ok()?);

    Read::take(handle, probe).read_to_end(&mut bytes).ok()?;

    (bytes.len() as u64 == len).then_some(bytes)
}

/// The classified result of one handle-bound rename.
enum Step {
    Done,
    Refused { collision: bool },
    Unknown,
}

fn rename_step(file: &File, pin: &File, leaf: &OsStr) -> Step {
    match handle_ops::rename_into_directory_no_replace(file, pin, leaf) {
        RenameStatus::Renamed => Step::Done,
        RenameStatus::Refused(DefiniteRefusal::NameCollision) => Step::Refused { collision: true },
        // `Rejected`: the leaf was not one plain name and no native call was made.
        RenameStatus::Refused(_) | RenameStatus::Rejected => Step::Refused { collision: false },
        RenameStatus::Unknown => Step::Unknown,
    }
}

/// Who is at a name, judged by physical identity.
enum Occupant {
    Empty,
    /// The new file.
    New,
    /// The old file.
    Previous,
    /// Some other file or object.
    Foreign,
    /// Nothing can be concluded.
    Indeterminate,
}

fn occupant(read: &SyncFileRead, new: &HandleFacts, previous: &HandleFacts) -> Occupant {
    match read {
        SyncFileRead::AbsentOnDisk => Occupant::Empty,
        SyncFileRead::Present(present) => match present.physical() {
            Ok(facts) if facts.identity() == new.identity() => Occupant::New,
            Ok(facts) if facts.identity() == previous.identity() => Occupant::Previous,
            Ok(_) => Occupant::Foreign,
            Err(_) => Occupant::Indeterminate,
        },
        SyncFileRead::Unavailable(UnavailableReason::UnexpectedObject) => Occupant::Foreign,
        SyncFileRead::Unavailable(_) => Occupant::Indeterminate,
    }
}

/// Handle-bound cleanup of **our own staging file**, only while the object
/// certainly still carries its staging name. The delete is by handle; because its
/// effect is observed only when the handle closes, the handle is dropped and the
/// result is then checked. Returns whether the file could not be confirmed gone.
/// This is the only deletion in the production code of this module.
fn remove_staging(staging: File, staging_path: &Path) -> bool {
    let deleted = handle_ops::delete_by_handle(&staging).is_ok();

    drop(staging);

    let gone = deleted
        && matches!(
            fs::symlink_metadata(staging_path),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        );

    !gone
}

// ---- owned state ---------------------------------------------------------------

/// What every stage holds: the pinned directory, the held old file `T`, and what
/// was learned about it. No `Drop`: dropping closes handles and deletes nothing.
struct Core {
    pin: File,
    target_handle: File,
    sync_target: SyncFileTarget,
    names: ExchangeNames,
    parent: PathBuf,
    primary: HandleFacts,
    t_facts: HandleFacts,
    old_bytes: Vec<u8>,
}

impl Core {
    fn staging_path(&self) -> PathBuf {
        self.parent.join(&self.names.staging)
    }

    fn retention_path(&self) -> PathBuf {
        self.parent.join(&self.names.retention)
    }
}

/// `Core` plus the held new file `S`.
struct Live {
    core: Core,
    staging: File,
    s_facts: HandleFacts,
    new_bytes: Vec<u8>,
}

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

// ---- 1. the held old file ------------------------------------------------------

/// The old target `T`, held open with `GENERIC_READ | DELETE` and read-only
/// sharing, in a pinned directory. Move-only; dropping it closes the handles and
/// deletes nothing. Carries no authority to update anything.
#[must_use]
pub(crate) struct HeldTarget(Box<Core>);

redacted_debug!(HeldTarget);

impl HeldTarget {
    /// Hold `target`. See the module documentation. `expected` is the physical
    /// identity the caller observed earlier; `primary` the facts of the vault's own
    /// primary file, which the target must be distinct from.
    pub(crate) fn acquire(
        target: &SyncFileTarget,
        names: &ExchangeNames,
        expected: FileIdentity,
        primary: &HandleFacts,
        seams: &mut Seams,
    ) -> Result<Self, AcquireRefusal> {
        use AcquireRefusal as Refusal;

        seams.hit(Stage::BeforeAcquire);

        let target_path = Path::new(target.locator().as_str());

        let (Some(parent), Some(leaf)) = (target_path.parent(), target_path.file_name()) else {
            return Err(Refusal::TargetLocatorUnusable);
        };

        if leaf != names.target {
            return Err(Refusal::NamesMismatch);
        }

        // Pin the directory and judge the handle, not the path.
        let pin = open_directory_pin(parent).map_err(|_| Refusal::ParentUnavailable)?;

        match pin.metadata() {
            Ok(metadata) if is_plain_directory(&metadata) => {}
            _ => return Err(Refusal::ParentNotPlain),
        }

        match seams.directory_facts(volume_facts_of(&pin)) {
            Ok(facts) if facts.is_local_ntfs() => {}
            _ => return Err(Refusal::VolumeNotLocalNtfs),
        }

        // After the pin, so a redirection installed before it is caught here.
        if !ancestors_are_plain(target_path) {
            return Err(Refusal::AncestorNotPlain);
        }

        match fs::symlink_metadata(target_path) {
            Ok(metadata) if is_plain_file(&metadata) => {}
            Ok(_) => return Err(Refusal::TargetNotPlainFile),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Refusal::TargetMissing)
            }
            Err(_) => return Err(Refusal::TargetOpenFailed),
        }

        check_directory_listing(parent, leaf, names)?;

        // Hold the file: read and delete access, read-only sharing, never following
        // a reparse point. A sharing violation is a definite TargetBusy; there is
        // no fallback to a path-based operation.
        let handle = OpenOptions::new()
            .read(true)
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(target_path)
            .map_err(|error| match error.raw_os_error() {
                Some(code) if code == ERROR_SHARING_VIOLATION as i32 => Refusal::TargetBusy,
                _ if error.kind() == io::ErrorKind::NotFound => Refusal::TargetMissing,
                _ => Refusal::TargetOpenFailed,
            })?;

        seams.hit(Stage::AfterAcquire);

        // Judge the handle.
        let metadata = handle.metadata().map_err(|_| Refusal::TargetOpenFailed)?;

        if !is_plain_file(&metadata) {
            return Err(Refusal::TargetNotPlainFile);
        }

        let len = metadata.len();

        if len == 0 || len > MAX_ENVELOPE_BYTES as u64 {
            return Err(Refusal::SizeUnsupported);
        }

        let facts = seams
            .target_facts(facts_of(&handle))
            .map_err(|_| Refusal::IdentityUncertain)?;

        if !facts.is_local_ntfs() {
            return Err(Refusal::TargetNotLocalNtfs);
        }

        if compare(primary, &facts) == PhysicalVerdict::Same {
            return Err(Refusal::PrimaryAlias);
        }

        if !facts.has_single_link() {
            return Err(Refusal::NotSingleLink);
        }

        if facts.is_delete_pending() {
            return Err(Refusal::DeletePending);
        }

        if compare(primary, &facts) != PhysicalVerdict::Distinct {
            return Err(Refusal::IdentityUncertain);
        }

        if facts.identity() != expected {
            return Err(Refusal::IdentityChanged);
        }

        // The old bytes, through THIS handle only.
        let old_bytes = read_through(&handle, len).ok_or(Refusal::ReadFailed)?;

        // A fresh, independent read of the path must report the same file.
        match target.read() {
            SyncFileRead::Present(present)
                if present
                    .physical()
                    .is_ok_and(|fresh| fresh.identity() == facts.identity())
                    && present.candidate_raw() == old_bytes.as_slice() => {}
            _ => return Err(Refusal::FreshReadMismatch),
        }

        Ok(Self(Box::new(Core {
            pin,
            target_handle: handle,
            sync_target: target.clone(),
            names: names.clone(),
            parent: parent.to_path_buf(),
            primary: *primary,
            t_facts: facts,
            old_bytes,
        })))
    }

    /// The old file's bytes, as read through the held handle.
    pub(crate) fn old_bytes(&self) -> &[u8] {
        &self.0.old_bytes
    }

    /// Create the new file `S` in the pinned directory and write `new_bytes` to
    /// it. On a failure the held target comes back with it.
    pub(crate) fn stage(self, new_bytes: &[u8], seams: &mut Seams) -> Result<Staged, StageFailure> {
        use StageRefusal as Refusal;

        let core = *self.0;

        let fail = |core: Core, reason: StageRefusal, staging_remains: bool| StageFailure {
            reason,
            staging_remains,
            held: HeldTarget(Box::new(core)),
        };

        if new_bytes.is_empty() || new_bytes.len() as u64 > MAX_ENVELOPE_BYTES as u64 {
            return Err(fail(core, Refusal::BytesUnsupported, false));
        }

        seams.hit(Stage::BeforeStageWrite);

        let staging_path = core.staging_path();

        // Exclusively (`create_new`): a name that exists is never opened.
        let mut staging = match OpenOptions::new()
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

        // From here on the object certainly carries the staging name, so a
        // failure is cleaned up by handle.
        let abandon = |core: Core, staging: File, reason: StageRefusal| {
            let remains = remove_staging(staging, &core.staging_path());

            fail(core, reason, remains)
        };

        if let Err(reason) = write_staging(&mut staging, new_bytes, seams) {
            return Err(abandon(core, staging, reason));
        }

        let facts = match seams.staging_facts(facts_of(&staging)) {
            Ok(facts) => facts,
            Err(_) => return Err(abandon(core, staging, Refusal::IdentityUncertain)),
        };

        if !facts.is_local_ntfs() {
            return Err(abandon(core, staging, Refusal::VolumeNotLocalNtfs));
        }

        if !facts.has_single_link()
            || facts.is_delete_pending()
            || compare(&core.primary, &facts) != PhysicalVerdict::Distinct
            || compare(&core.t_facts, &facts) != PhysicalVerdict::Distinct
        {
            return Err(abandon(core, staging, Refusal::IdentityUncertain));
        }

        // An independent read of the staging path returns what was written.
        let read_back = SyncFileTarget::from_path(&staging_path).map(|target| target.read());

        match read_back {
            Ok(SyncFileRead::Present(present))
                if present
                    .physical()
                    .is_ok_and(|fresh| fresh.identity() == facts.identity())
                    && present.candidate_raw() == new_bytes => {}
            _ => return Err(abandon(core, staging, Refusal::ReadBackMismatch)),
        }

        Ok(Staged(Box::new(Live {
            core,
            staging,
            s_facts: facts,
            new_bytes: new_bytes.to_vec(),
        })))
    }
}

/// Look for the exact long name of the target, and for a staging or retention
/// name in any case.
fn check_directory_listing(
    parent: &Path,
    leaf: &OsStr,
    names: &ExchangeNames,
) -> Result<(), AcquireRefusal> {
    use AcquireRefusal as Refusal;

    let listing = fs::read_dir(parent).map_err(|_| Refusal::ParentUnavailable)?;

    let staging = (ascii_fold(&names.staging), unicode_fold(&names.staging));
    let retention = (ascii_fold(&names.retention), unicode_fold(&names.retention));

    let mut canonical = false;

    for entry in listing {
        let name = entry.map_err(|_| Refusal::ParentUnavailable)?.file_name();

        if name == leaf {
            canonical = true;
        }

        if ascii_fold(&name) == staging.0 || unicode_fold(&name) == staging.1 {
            return Err(Refusal::StagingNameExists);
        }

        if ascii_fold(&name) == retention.0 || unicode_fold(&name) == retention.1 {
            return Err(Refusal::RetentionNameExists);
        }
    }

    if canonical {
        Ok(())
    } else {
        Err(Refusal::TargetNameNotCanonical)
    }
}

#[cfg_attr(not(test), allow(unused_variables))]
fn write_staging(staging: &mut File, bytes: &[u8], seams: &Seams) -> Result<(), StageRefusal> {
    #[cfg(test)]
    if seams.stage_fault == Some(StageFault::Write) {
        let _ = staging.write_all(&bytes[..bytes.len() / 2]);

        return Err(StageRefusal::WriteFailed);
    }

    staging
        .write_all(bytes)
        .map_err(|_| StageRefusal::WriteFailed)?;

    #[cfg(test)]
    if seams.stage_fault == Some(StageFault::Flush) {
        return Err(StageRefusal::FlushFailed);
    }

    staging.flush().map_err(|_| StageRefusal::FlushFailed)?;

    #[cfg(test)]
    if seams.stage_fault == Some(StageFault::Sync) {
        return Err(StageRefusal::FlushFailed);
    }

    staging.sync_all().map_err(|_| StageRefusal::FlushFailed)?;

    match staging.metadata() {
        Ok(metadata) if metadata.len() == bytes.len() as u64 => Ok(()),
        _ => Err(StageRefusal::LengthMismatch),
    }
}

/// A failed [`HeldTarget::stage`]. `staging_remains` is true only if our own
/// staging file could not be confirmed removed. The held target is returned.
#[must_use]
pub(crate) struct StageFailure {
    pub(crate) reason: StageRefusal,
    pub(crate) staging_remains: bool,
    pub(crate) held: HeldTarget,
}

impl fmt::Debug for StageFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StageFailure")
            .field("reason", &self.reason)
            .field("staging_remains", &self.staging_remains)
            .finish_non_exhaustive()
    }
}

// ---- 2. the staged file --------------------------------------------------------

/// The old file `T` and the new file `S`, both held, nothing renamed yet.
/// Move-only; dropping it closes both handles and deletes nothing (the staging
/// file stays on disk, exactly as after a crash).
#[must_use]
pub(crate) struct Staged(Box<Live>);

redacted_debug!(Staged);

impl Staged {
    /// Rename `T` to the retention name, then `S` to the original leaf. Both by
    /// handle, relative to the pinned directory, without replace. `recheck` is
    /// called once, immediately before the first rename, and must return `true`
    /// only if the caller's own evidence is unchanged.
    pub(crate) fn exchange(
        self,
        recheck: &mut dyn FnMut() -> bool,
        seams: &mut Seams,
    ) -> ExchangeOutcome {
        let live = *self.0;

        if !recheck() {
            return not_exchanged(live, NotExchangedReason::RecheckRefused);
        }

        if let Err(reason) = live.check_old_file_in_place() {
            return not_exchanged(live, reason);
        }

        // 1. T -> R. Nothing is replaced.
        seams.hit(Stage::BeforeRetentionRename);

        match rename_step(
            &live.core.target_handle,
            &live.core.pin,
            &live.core.names.retention,
        ) {
            Step::Done => {}
            Step::Refused { collision } => {
                // A refusal is trusted only if the old file is provably still at
                // its name.
                let read = live.core.sync_target.read();

                return match occupant(&read, &live.s_facts, &live.core.t_facts) {
                    Occupant::Previous => not_exchanged(
                        live,
                        if collision {
                            NotExchangedReason::RetentionCollision
                        } else {
                            NotExchangedReason::RetentionRefused
                        },
                    ),
                    _ => unknown(live, ExchangeStep::RetentionRename),
                };
            }
            Step::Unknown => return unknown(live, ExchangeStep::RetentionRename),
        }

        // The original leaf is now empty.
        seams.hit(Stage::BetweenRenames);

        // 2. S -> original leaf. Nothing is replaced.
        match rename_step(&live.staging, &live.core.pin, &live.core.names.target) {
            Step::Done => {
                // Best effort, claims nothing: the content was already flushed.
                let _ = live.staging.sync_all();

                ExchangeOutcome::Exchanged(Swapped(Box::new(live)))
            }
            Step::Unknown => unknown(live, ExchangeStep::Publication),
            Step::Refused { collision } => {
                let read = live.core.sync_target.read();

                match occupant(&read, &live.s_facts, &live.core.t_facts) {
                    // The refusal is contradicted by our own file at the name, or
                    // by the old file being back: nothing may be concluded.
                    Occupant::New | Occupant::Previous | Occupant::Indeterminate => {
                        unknown(live, ExchangeStep::Publication)
                    }
                    // Someone else holds the name: never touched. Our staging file
                    // still carries its staging name (the rename was refused), so
                    // it alone is removed by handle; the old file stays retained.
                    Occupant::Foreign => taken_over(live),
                    // The kernel says the name exists but it is empty: contradictory.
                    Occupant::Empty if collision => unknown(live, ExchangeStep::Publication),
                    Occupant::Empty => restore(live, seams),
                }
            }
        }
    }
}

impl Live {
    /// The old file is still the held file, at its name, with its bytes.
    fn check_old_file_in_place(&self) -> Result<(), NotExchangedReason> {
        use NotExchangedReason as Reason;

        let now = facts_of(&self.core.target_handle).map_err(|_| Reason::IdentityUncertain)?;

        if now.identity() != self.core.t_facts.identity() {
            return Err(Reason::TargetChanged);
        }

        if !now.has_single_link() {
            return Err(Reason::TargetNotSingleLink);
        }

        if now.is_delete_pending() {
            return Err(Reason::TargetDeletePending);
        }

        if now != self.core.t_facts {
            return Err(Reason::IdentityUncertain);
        }

        match facts_of(&self.staging) {
            Ok(staging) if staging == self.s_facts => {}
            _ => return Err(Reason::StagingChanged),
        }

        match self.core.sync_target.read() {
            SyncFileRead::Present(present)
                if present
                    .physical()
                    .is_ok_and(|fresh| fresh.identity() == now.identity())
                    && present.candidate_raw() == self.core.old_bytes.as_slice() =>
            {
                Ok(())
            }
            _ => Err(Reason::TargetChanged),
        }
    }
}

/// `T` never left its name: only our own staging file is removed, by handle.
fn not_exchanged(live: Live, reason: NotExchangedReason) -> ExchangeOutcome {
    let Live { core, staging, .. } = live;
    let staging_remains = remove_staging(staging, &core.staging_path());

    ExchangeOutcome::NotExchanged {
        reason,
        staging_remains,
        held: HeldTarget(Box::new(core)),
    }
}

/// A status was not definite: delete nothing, retry nothing, keep every handle.
fn unknown(live: Live, at: ExchangeStep) -> ExchangeOutcome {
    ExchangeOutcome::Unknown(UnknownExchange {
        at,
        live: Box::new(live),
    })
}

/// The name was filled by someone else during the window.
fn taken_over(live: Live) -> ExchangeOutcome {
    let Live { core, staging, .. } = live;
    let staging_remains = remove_staging(staging, &core.staging_path());

    ExchangeOutcome::TargetTakenOver(RetainedPrevious {
        staging_remains,
        core: Box::new(core),
    })
}

/// The second rename was definitely refused and the name is provably empty: put
/// the old file back (no replace) and remove our staging file.
fn restore(live: Live, seams: &mut Seams) -> ExchangeOutcome {
    seams.hit(Stage::BeforeRestore);

    match rename_step(
        &live.core.target_handle,
        &live.core.pin,
        &live.core.names.target,
    ) {
        Step::Done => {}
        Step::Refused { .. } => {
            return ExchangeOutcome::Interrupted(InterruptedExchange(Box::new(live)))
        }
        Step::Unknown => return unknown(live, ExchangeStep::Restoration),
    }

    // The old file must provably be back before anything is cleaned up.
    let back = matches!(
        live.core.sync_target.read(),
        SyncFileRead::Present(present)
            if present
                .physical()
                .is_ok_and(|fresh| fresh.identity() == live.core.t_facts.identity())
                && present.candidate_raw() == live.core.old_bytes.as_slice()
    );

    if !back {
        return unknown(live, ExchangeStep::Restoration);
    }

    let Live { core, staging, .. } = live;
    let staging_remains = remove_staging(staging, &core.staging_path());

    ExchangeOutcome::Restored {
        staging_remains,
        held: HeldTarget(Box::new(core)),
    }
}

/// What [`Staged::exchange`] established. None of these is consent to anything.
#[derive(Debug)]
#[must_use]
pub(crate) enum ExchangeOutcome {
    /// Both renames succeeded.
    Exchanged(Swapped),
    /// `T` never left its name; our staging file was removed by handle.
    NotExchanged {
        reason: NotExchangedReason,
        staging_remains: bool,
        held: HeldTarget,
    },
    /// The second rename was definitely refused with the name provably empty; `T`
    /// was renamed back and verified there.
    Restored {
        staging_remains: bool,
        held: HeldTarget,
    },
    /// The name was filled by someone else during the window. It was not touched;
    /// the old version is retained under the retention name.
    TargetTakenOver(RetainedPrevious),
    /// The second rename and the restoration were both refused: the old version
    /// is at the retention name, the new one at its staging name, the original
    /// leaf is empty. Both are kept.
    Interrupted(InterruptedExchange),
    /// A native status was not definite. Nothing was deleted.
    Unknown(UnknownExchange),
}

/// The old version, retained under the retention name after a third party took
/// the original name. The held handle is returned only to keep the file in place.
#[must_use]
pub(crate) struct RetainedPrevious {
    pub(crate) staging_remains: bool,
    core: Box<Core>,
}

impl fmt::Debug for RetainedPrevious {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedPrevious")
            .field("staging_remains", &self.staging_remains)
            .finish_non_exhaustive()
    }
}

/// Old version at the retention name, new version at its staging name, original
/// leaf empty. Both handles held; dropping closes them and deletes nothing.
#[must_use]
pub(crate) struct InterruptedExchange(#[allow(dead_code)] Box<Live>);

redacted_debug!(InterruptedExchange);

/// A native status was not definite. Both handles held; dropping closes them and
/// deletes nothing.
#[must_use]
pub(crate) struct UnknownExchange {
    at: ExchangeStep,
    /// Held only to keep both files open.
    #[allow(dead_code)]
    live: Box<Live>,
}

impl UnknownExchange {
    /// Which step was not definite.
    pub(crate) fn at(&self) -> ExchangeStep {
        self.at
    }
}

impl fmt::Debug for UnknownExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnknownExchange")
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

// ---- 3. the swapped files ------------------------------------------------------

/// Both renames succeeded; nothing is verified yet. Dropping closes both handles
/// and deletes nothing.
#[must_use]
pub(crate) struct Swapped(Box<Live>);

redacted_debug!(Swapped);

impl Swapped {
    /// While `T` and `S` are still held, independently read the new target and the
    /// retained old file and compare identities and bytes. `check` receives the
    /// bytes read back from the target path. A failure retains the old version.
    pub(crate) fn verify(
        self,
        check: &mut dyn FnMut(&[u8]) -> bool,
        seams: &mut Seams,
    ) -> Result<Verified, Unverified> {
        seams.hit(Stage::BeforeVerify);

        let live = *self.0;

        match live.verify_swap(check, seams) {
            Ok(()) => Ok(Verified(Box::new(live))),
            Err(reason) => Err(Unverified {
                reason,
                live: Box::new(live),
            }),
        }
    }
}

impl Live {
    fn verify_swap(
        &self,
        check: &mut dyn FnMut(&[u8]) -> bool,
        seams: &mut Seams,
    ) -> Result<(), VerifyRefusal> {
        use VerifyRefusal as Refusal;

        match facts_of(&self.staging) {
            Ok(now) if now == self.s_facts => {}
            _ => return Err(Refusal::NewVersionChanged),
        }

        match facts_of(&self.core.target_handle) {
            Ok(now) if now == self.core.t_facts => {}
            _ => return Err(Refusal::PreviousChanged),
        }

        // The new target.
        let SyncFileRead::Present(present) = seams.verify_read(self.core.sync_target.read()) else {
            return Err(Refusal::TargetUnreadable);
        };

        let Ok(read) = present.physical() else {
            return Err(Refusal::TargetUnreadable);
        };

        if present.target() != self.core.sync_target.locator()
            || read.identity() != self.s_facts.identity()
        {
            return Err(Refusal::TargetIdentityMismatch);
        }

        if !read.has_single_link()
            || read.is_delete_pending()
            || !read.is_local_ntfs()
            || compare(&self.core.primary, read) != PhysicalVerdict::Distinct
            || compare(&self.core.t_facts, read) != PhysicalVerdict::Distinct
        {
            return Err(Refusal::TargetFactsRefused);
        }

        if present.candidate_raw() != self.new_bytes.as_slice() {
            return Err(Refusal::TargetBytesMismatch);
        }

        if !check(present.candidate_raw()) {
            return Err(Refusal::CheckRejected);
        }

        // The retained old file.
        let retention = SyncFileTarget::from_path(&self.core.retention_path())
            .map_err(|_| Refusal::RetentionUnreadable)?;

        let SyncFileRead::Present(kept) = retention.read() else {
            return Err(Refusal::RetentionUnreadable);
        };

        let Ok(kept_facts) = kept.physical() else {
            return Err(Refusal::RetentionUnreadable);
        };

        if kept_facts.identity() != self.core.t_facts.identity()
            || !kept_facts.has_single_link()
            || !kept_facts.is_local_ntfs()
        {
            return Err(Refusal::RetentionIdentityMismatch);
        }

        if kept.candidate_raw() != self.core.old_bytes.as_slice() {
            return Err(Refusal::RetentionBytesMismatch);
        }

        Ok(())
    }
}

/// The exchange was not confirmed. Both handles are still held and the old
/// version is retained; nothing was deleted. Dropping closes the handles.
#[must_use]
pub(crate) struct Unverified {
    reason: VerifyRefusal,
    /// Held only to keep both files open.
    #[allow(dead_code)]
    live: Box<Live>,
}

impl Unverified {
    pub(crate) fn reason(&self) -> VerifyRefusal {
        self.reason
    }
}

impl fmt::Debug for Unverified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unverified")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// The exchange was independently verified. This is **not** a commit and not an
/// authorization: the old version is retained until some later, separately
/// approved mechanism decides otherwise, and no production method deletes or
/// renames it.
#[must_use]
pub(crate) struct Verified(Box<Live>);

redacted_debug!(Verified);

impl Verified {
    /// Close the handles; the retained old version stays on disk.
    pub(crate) fn retain_previous(self) {
        drop(self.0);
    }
}

// ---- test-only code below this line (the production source ends here) ----------

/// What [`Verified::release_previous_for_test`] established.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviousRelease {
    Removed,
    Retained,
}

#[cfg(test)]
impl Verified {
    /// Test-only. Requires `Verified` ownership. Deletes the retained old file by
    /// its own handle, closes everything and confirms the name is gone. Absent from
    /// every non-test build.
    pub(crate) fn release_previous_for_test(self) -> PreviousRelease {
        let Live { core, staging, .. } = *self.0;
        let retention_path = core.retention_path();

        drop(staging);

        let deleted = handle_ops::delete_by_handle(&core.target_handle).is_ok();

        drop(core);

        let gone = matches!(
            fs::symlink_metadata(&retention_path),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        );

        if deleted && gone {
            PreviousRelease::Removed
        } else {
            PreviousRelease::Retained
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::ffi::OsStringExt;
    use std::{cell::RefCell, ffi::OsString, marker::PhantomData, process::Command, rc::Rc};

    use super::*;
    use crate::vault::{
        file_identity::FileSystemKind,
        handle_ops::{
            inject_delete_status, inject_rename_status, take_last_delete_status,
            take_last_rename_status,
            test_support::{assert_local_ntfs, cwd_names, make_junction, names, snapshot},
        },
    };

    // A mark that must never appear in any `Debug` output: it is part of the
    // target leaf, so it is also part of both derived names.
    const LEAF: &str = "LEAKMARK-bound.lvault";
    const OLD: &[u8] = b"b3b1-synthetic-old-version: opaque dummy bytes";
    const NEW: &[u8] = b"b3b1-synthetic-new-version: opaque dummy bytes, a little longer";
    const PRIMARY: &[u8] = b"b3b1-synthetic-primary stand-in";
    const FOREIGN: &[u8] = b"b3b1-foreign file created by someone else";

    const ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
    const NAME_INVALID: i32 = 0xC000_0033_u32 as i32;
    const UNSUCCESSFUL: i32 = 0xC000_0001_u32 as i32;

    /// A unique, test-owned directory under the B3 scratch base, never `%TEMP%`.
    /// Removed only by its `TempDir` guard; the base is never removed.
    fn scratch(name: &str) -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("sync-update-b3-tests");

        fs::create_dir_all(&base).unwrap();

        let dir = tempfile::Builder::new()
            .prefix(&format!("{name}-"))
            .tempdir_in(&base)
            .unwrap();

        // Fails loudly (never skips) off a local NTFS volume.
        assert_local_ntfs(dir.path());
        assert!(!dir.path().starts_with(std::env::temp_dir()));

        dir
    }

    fn id() -> ExchangeId {
        ExchangeId::new(Uuid::new_v4()).unwrap()
    }

    #[derive(Clone, Copy)]
    enum Which {
        Bound,
        Staging,
        Retention,
    }

    /// `primary\primary.lvault` (the stand-in primary vault), `control\` (files that
    /// are never held), and the destination directory holding the bound target.
    struct Rig {
        // The held primary handle is declared before the scratch directory guard
        // (declared last) so it closes first.
        primary_handle: File,
        primary_facts: HandleFacts,
        primary_dir: PathBuf,
        primary_before: Vec<String>,
        cwd_before: Vec<String>,
        control: PathBuf,
        dest: PathBuf,
        bound: PathBuf,
        target: SyncFileTarget,
        expected: FileIdentity,
        names: ExchangeNames,
        dir: tempfile::TempDir,
    }

    impl Rig {
        fn new(name: &str) -> Self {
            Self::at(name, &["dest"])
        }

        fn at(name: &str, dest: &[&str]) -> Self {
            let dir = scratch(name);
            let primary_dir = dir.path().join("primary");
            let control = dir.path().join("control");
            let mut dest_path = dir.path().to_path_buf();

            for part in dest {
                dest_path.push(part);
            }

            fs::create_dir(&primary_dir).unwrap();
            fs::create_dir(&control).unwrap();
            fs::create_dir_all(&dest_path).unwrap();

            let primary_path = primary_dir.join("primary.lvault");

            fs::write(&primary_path, PRIMARY).unwrap();

            let bound = dest_path.join(LEAF);

            fs::write(&bound, OLD).unwrap();

            let primary_handle = File::open(&primary_path).unwrap();
            let primary_facts = facts_of(&primary_handle).unwrap();
            let expected = facts_of(&File::open(&bound).unwrap()).unwrap().identity();
            let target = SyncFileTarget::from_path(&bound).unwrap();
            let names = ExchangeNames::derive(&target, id()).unwrap();

            // Snapshots after the fixture is complete.
            let primary_before = snapshot(&primary_dir);
            let cwd_before = cwd_names();

            Self {
                primary_handle,
                primary_facts,
                primary_dir,
                primary_before,
                cwd_before,
                control,
                dest: dest_path,
                bound,
                target,
                expected,
                names,
                dir,
            }
        }

        fn acquire(&self, seams: &mut Seams) -> Result<HeldTarget, AcquireRefusal> {
            HeldTarget::acquire(
                &self.target,
                &self.names,
                self.expected,
                &self.primary_facts,
                seams,
            )
        }

        fn held(&self) -> HeldTarget {
            self.acquire(&mut Seams::none()).expect("acquire")
        }

        fn staged(&self) -> Staged {
            self.held().stage(NEW, &mut Seams::none()).expect("stage")
        }

        fn staging_name(&self) -> String {
            self.names.staging.to_string_lossy().into_owned()
        }

        fn retention_name(&self) -> String {
            self.names.retention.to_string_lossy().into_owned()
        }

        fn staging_path(&self) -> PathBuf {
            self.dest.join(&self.names.staging)
        }

        fn retention_path(&self) -> PathBuf {
            self.dest.join(&self.names.retention)
        }

        fn dest_names(&self) -> Vec<String> {
            names(&self.dest)
        }

        /// The destination holds exactly these names with exactly these bytes.
        fn expect(&self, expected: &[(Which, &[u8])]) {
            let mut wanted: Vec<(String, &[u8])> = expected
                .iter()
                .map(|(which, bytes)| {
                    let name = match which {
                        Which::Bound => LEAF.to_owned(),
                        Which::Staging => self.staging_name(),
                        Which::Retention => self.retention_name(),
                    };

                    (name, *bytes)
                })
                .collect();

            wanted.sort();

            assert_eq!(
                self.dest_names(),
                wanted
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect::<Vec<_>>()
            );

            for (name, bytes) in wanted {
                assert_eq!(fs::read(self.dest.join(&name)).unwrap(), bytes, "{name}");
            }
        }

        /// Nothing outside the destination changed: the primary vault stand-in and
        /// its directory, and the working directory.
        fn assert_isolated(&self) {
            assert_eq!(snapshot(&self.primary_dir), self.primary_before);
            assert_eq!(cwd_names(), self.cwd_before);
            assert_eq!(facts_of(&self.primary_handle).unwrap(), self.primary_facts);
            assert!(self.dir.path().starts_with(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join(".qa-local")
                    .join("sync-update-b3-tests")
            ));
        }
    }

    fn held_rig(name: &str) -> (Rig, HeldTarget) {
        let rig = Rig::new(name);
        let held = rig.held();

        (rig, held)
    }

    fn hook(f: impl FnMut(Stage) + 'static) -> Seams {
        Seams {
            hook: Some(Box::new(f)),
            ..Seams::none()
        }
    }

    fn at(stage: Stage, mut f: impl FnMut() + 'static) -> Seams {
        hook(move |hit| {
            if hit == stage {
                f();
            }
        })
    }

    fn exchange(staged: Staged, seams: &mut Seams) -> ExchangeOutcome {
        staged.exchange(&mut || true, seams)
    }

    /// The held old file is unchanged and is still the only name in the directory.
    fn assert_unchanged(rig: &Rig, held: &HeldTarget) {
        assert_eq!(fs::read(&rig.bound).unwrap(), OLD);

        let fresh = facts_of(&File::open(&rig.bound).unwrap()).unwrap();

        assert_eq!(fresh.identity(), held.0.t_facts.identity());
        assert!(fresh.has_single_link());
        assert_eq!(rig.dest_names(), vec![LEAF.to_owned()]);
    }

    fn blocked(label: &str, result: io::Result<()>) {
        let error = result.expect_err(label);

        eprintln!(
            "OBSERVED held target, {label}: kind={:?} os={:?}",
            error.kind(),
            error.raw_os_error()
        );
    }

    fn hex(status: i32) -> String {
        format!("0x{:08X}", status as u32)
    }

    fn swapped(rig: &Rig) -> Swapped {
        match exchange(rig.staged(), &mut Seams::none()) {
            ExchangeOutcome::Exchanged(swapped) => swapped,
            other => panic!("expected Exchanged, got {other:?}"),
        }
    }

    // ---- 1-2. the renames, with the intended handles held --------------------------

    #[test]
    fn t01_both_renames_succeed_while_the_intended_handles_are_held() {
        let rig = Rig::new("t01");
        let dest_before = snapshot(&rig.dest);
        let held = rig.held();

        assert_eq!(held.old_bytes(), OLD);

        let t_identity = held.0.t_facts.identity();
        let staged = held.stage(NEW, &mut Seams::none()).expect("stage");
        let s_identity = staged.0.s_facts.identity();

        rig.expect(&[(Which::Bound, OLD), (Which::Staging, NEW)]);

        let _ = take_last_rename_status();

        let ExchangeOutcome::Exchanged(swapped) = exchange(staged, &mut Seams::none()) else {
            panic!("the exchange was not accepted");
        };

        // OBSERVED: the native status of the second (and the first) rename.
        let raw = take_last_rename_status().expect("a native status was recorded");

        eprintln!("OBSERVED held-handle renames: {}", hex(raw));

        assert_eq!(raw, 0);

        // The target is the new file (S's identity, one link); R is the old file
        // (T's identity).
        let target = facts_of(&File::open(&rig.bound).unwrap()).unwrap();
        let kept = facts_of(&File::open(rig.retention_path()).unwrap()).unwrap();

        assert_eq!(target.identity(), s_identity);
        assert!(target.has_single_link() && target.is_local_ntfs());
        assert_eq!(kept.identity(), t_identity);
        assert!(kept.has_single_link());

        rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);

        // The snapshot diff is exactly: the old entry moved to R with the same
        // length, modification time and hash, plus the new target.
        let after = snapshot(&rig.dest);
        let moved = dest_before[0].replacen(LEAF, &rig.retention_name(), 1);

        assert_eq!(after.len(), 2);
        assert!(after.contains(&moved), "{after:?} vs {moved}");

        let verified = swapped
            .verify(&mut |bytes| bytes == NEW, &mut Seams::none())
            .expect("verified");

        verified.retain_previous();

        rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);
        rig.assert_isolated();
    }

    #[test]
    fn t02_an_additional_reader_is_measured_and_never_causes_damage() {
        let rig = Rig::new("t02");
        let staged = rig.staged();
        let reader = OpenOptions::new()
            .read(true)
            .open(&rig.bound)
            .expect("a fully shared reader can open the held file");

        match exchange(staged, &mut Seams::none()) {
            ExchangeOutcome::Exchanged(swapped) => {
                eprintln!("OBSERVED additional reader: both held-handle renames SUCCEEDED");

                let verified = swapped
                    .verify(&mut |bytes| bytes == NEW, &mut Seams::none())
                    .expect("verified");

                verified.retain_previous();
                rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);
            }
            ExchangeOutcome::NotExchanged { reason, held, .. } => {
                eprintln!("OBSERVED additional reader: the exchange was refused ({reason:?})");

                assert_unchanged(&rig, &held);
            }
            other => panic!("damage or an unexpected outcome: {other:?}"),
        }

        // The reader's handle still reads the old file's bytes, wherever it is.
        let mut seen = Vec::new();

        (&reader).read_to_end(&mut seen).unwrap();

        assert_eq!(seen, OLD);

        drop(reader);
        rig.assert_isolated();
    }

    // ---- 3-4. incompatible handles at acquire ------------------------------------

    #[test]
    fn t03_an_existing_writer_makes_acquire_fail_with_target_busy() {
        let rig = Rig::new("t03");
        let writer = OpenOptions::new().write(true).open(&rig.bound).unwrap();

        assert_eq!(
            rig.acquire(&mut Seams::none()).unwrap_err(),
            AcquireRefusal::TargetBusy
        );

        // Nothing was created or changed.
        rig.expect(&[(Which::Bound, OLD)]);

        drop(writer);

        // Control: without the writer the same call succeeds.
        let _held = rig.held();

        rig.assert_isolated();
    }

    #[test]
    fn t04_a_handle_without_delete_sharing_makes_acquire_fail_with_target_busy() {
        let rig = Rig::new("t04");
        // Read access, read and write sharing, but not FILE_SHARE_DELETE.
        let reader = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | 2)
            .open(&rig.bound)
            .unwrap();

        assert_eq!(
            rig.acquire(&mut Seams::none()).unwrap_err(),
            AcquireRefusal::TargetBusy
        );

        rig.expect(&[(Which::Bound, OLD)]);

        drop(reader);

        let _held = rig.held();

        rig.assert_isolated();
    }

    // ---- 5-12. while the target is held ------------------------------------------

    #[test]
    fn t05_an_in_process_writer_is_blocked() {
        let (rig, held) = held_rig("t05");

        blocked(
            "open for write",
            OpenOptions::new().write(true).open(&rig.bound).map(|_| ()),
        );
        blocked(
            "open for append",
            OpenOptions::new().append(true).open(&rig.bound).map(|_| ()),
        );
        blocked(
            "open and truncate",
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&rig.bound)
                .map(|_| ()),
        );
        blocked("fs::write", fs::write(&rig.bound, b"overwrite"));

        assert_unchanged(&rig, &held);
        rig.assert_isolated();
    }

    #[test]
    fn t06_an_in_process_open_requesting_delete_is_blocked() {
        let (rig, held) = held_rig("t06");

        blocked(
            "open with DELETE access",
            OpenOptions::new()
                .read(true)
                .access_mode(0x0001_0000)
                .open(&rig.bound)
                .map(|_| ()),
        );
        blocked(
            "open with generic write access",
            OpenOptions::new()
                .access_mode(0x4000_0000)
                .open(&rig.bound)
                .map(|_| ()),
        );

        assert_unchanged(&rig, &held);
        rig.assert_isolated();
    }

    fn cmd(args: &[&str], path: &Path) -> std::process::Output {
        Command::new("cmd")
            .arg("/C")
            .args(args)
            .arg(path)
            .output()
            .expect("cmd.exe runs")
    }

    #[test]
    fn t07_an_independent_child_process_writer_is_blocked() {
        let (rig, held) = held_rig("t07");

        // Control: the same command line succeeds on a file that is not held.
        let control = rig.control.join("control.txt");

        fs::write(&control, b"start").unwrap();

        let controlled = cmd(&["echo", "child-write", ">>"], &control);

        assert!(controlled.status.success());
        assert!(fs::read(&control).unwrap().len() > b"start".len());

        let output = cmd(&["echo", "child-write", ">>"], &rig.bound);

        eprintln!(
            "OBSERVED child-process write to the held target: exit={:?} stderr={:?}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );

        assert!(!output.status.success());
        assert_unchanged(&rig, &held);
        rig.assert_isolated();
    }

    #[test]
    fn t08_child_process_delete_and_rename_are_blocked() {
        let (rig, held) = held_rig("t08");

        // Controls on files that are not held.
        let doomed = rig.control.join("doomed.txt");
        let renamed = rig.control.join("renamed-from.txt");

        fs::write(&doomed, b"x").unwrap();
        fs::write(&renamed, b"x").unwrap();

        let _ = cmd(&["del"], &doomed);
        let _ = Command::new("cmd")
            .arg("/C")
            .arg("ren")
            .arg(&renamed)
            .arg("renamed-to.txt")
            .output()
            .unwrap();

        assert!(!doomed.exists(), "the control `del` works");
        assert!(rig.control.join("renamed-to.txt").exists());

        // The held target.
        let deleted = cmd(&["del"], &rig.bound);
        let moved = Command::new("cmd")
            .arg("/C")
            .arg("ren")
            .arg(&rig.bound)
            .arg("moved-away.lvault")
            .output()
            .unwrap();

        eprintln!(
            "OBSERVED child-process del: {:?}; ren: {:?}",
            String::from_utf8_lossy(&deleted.stderr).trim(),
            String::from_utf8_lossy(&moved.stderr).trim()
        );

        assert_unchanged(&rig, &held);
        rig.assert_isolated();
    }

    #[test]
    fn t09_remove_file_is_blocked() {
        let (rig, held) = held_rig("t09");

        blocked("fs::remove_file", fs::remove_file(&rig.bound));

        assert_unchanged(&rig, &held);
        rig.assert_isolated();
    }

    #[test]
    fn t10_renaming_the_target_away_is_blocked() {
        let (rig, held) = held_rig("t10");

        blocked(
            "fs::rename away",
            fs::rename(&rig.bound, rig.dest.join("moved-away.lvault")),
        );

        assert_unchanged(&rig, &held);
        rig.assert_isolated();
    }

    #[test]
    fn t11_a_competing_rename_replace_is_blocked() {
        let (rig, held) = held_rig("t11");
        let competitor = rig.control.join("competitor.lvault");

        fs::write(&competitor, FOREIGN).unwrap();

        // The sync-client pattern: MoveFileEx replacing the existing name.
        blocked("fs::rename over", fs::rename(&competitor, &rig.bound));

        assert_unchanged(&rig, &held);
        assert_eq!(fs::read(&competitor).unwrap(), FOREIGN);
        rig.assert_isolated();
    }

    #[test]
    fn t12_a_hard_link_to_the_held_target_is_measured_and_refused_before_the_exchange() {
        let (rig, held) = held_rig("t12");
        let alias = rig.dest.join("alias.lvault");

        match fs::hard_link(&rig.bound, &alias) {
            Ok(()) => {
                eprintln!("OBSERVED hard link to the held target: SUCCEEDED (links become 2)");

                let staged = held.stage(NEW, &mut Seams::none()).expect("stage");
                let ExchangeOutcome::NotExchanged {
                    reason,
                    staging_remains,
                    held,
                } = exchange(staged, &mut Seams::none())
                else {
                    panic!("the exchange must be refused");
                };

                assert_eq!(reason, NotExchangedReason::TargetNotSingleLink);
                assert!(!staging_remains);

                // Nothing was renamed or deleted: the target and its alias remain.
                assert_eq!(fs::read(&rig.bound).unwrap(), OLD);
                assert_eq!(fs::read(&alias).unwrap(), OLD);
                assert_eq!(
                    rig.dest_names(),
                    vec![LEAF.to_owned(), "alias.lvault".to_owned()]
                );

                drop(held);
            }
            Err(error) => {
                eprintln!(
                    "OBSERVED hard link to the held target: BLOCKED kind={:?} os={:?}",
                    error.kind(),
                    error.raw_os_error()
                );

                assert!(!alias.exists());
                assert_unchanged(&rig, &held);
            }
        }

        rig.assert_isolated();
    }

    #[test]
    fn t12b_a_hard_link_created_after_the_recheck_is_measured_and_fails_verification() {
        let rig = Rig::new("t12b");
        let staged = rig.staged();
        let bound = rig.bound.clone();
        let alias = rig.dest.join("alias.lvault");
        let mut seams = at(Stage::BeforeRetentionRename, move || {
            fs::hard_link(&bound, &alias).unwrap();
        });

        // The link is created after the last recheck, so the rename cannot see it.
        let outcome = exchange(staged, &mut seams);

        eprintln!(
            "OBSERVED hard link created after the recheck: names={:?}",
            rig.dest_names()
        );

        match outcome {
            ExchangeOutcome::Exchanged(swapped) => {
                // The extra link is detected afterwards, never as a success.
                let unverified = swapped
                    .verify(&mut |_| true, &mut Seams::none())
                    .unwrap_err();

                eprintln!(
                    "OBSERVED hard link created after the recheck: exchange accepted, \
                     verification refused ({:?})",
                    unverified.reason()
                );

                assert_eq!(unverified.reason(), VerifyRefusal::PreviousChanged);
            }
            other => eprintln!("OBSERVED hard link created after the recheck: {other:?}"),
        }

        // Nothing was lost: every name holds one of the two versions, and the old
        // version is still reachable under at least one name.
        let mut old_names = 0;

        for name in rig.dest_names() {
            let bytes = fs::read(rig.dest.join(&name)).unwrap();

            assert!(bytes == OLD || bytes == NEW, "{name}");

            if bytes == OLD {
                old_names += 1;
            }
        }

        assert!(old_names >= 1);
        rig.assert_isolated();
    }

    // ---- 13-15. identity ------------------------------------------------------------

    #[test]
    fn t13_a_changed_expected_identity_is_refused() {
        let rig = Rig::new("t13");
        let replacement = rig.dest.join("replacement.tmp");

        // A different physical file with identical bytes now holds the name.
        fs::write(&replacement, OLD).unwrap();
        fs::rename(&replacement, &rig.bound).unwrap();

        assert_eq!(
            rig.acquire(&mut Seams::none()).unwrap_err(),
            AcquireRefusal::IdentityChanged
        );

        rig.expect(&[(Which::Bound, OLD)]);
        rig.assert_isolated();
    }

    #[test]
    fn t14_a_target_that_is_a_hard_link_of_the_primary_is_refused() {
        let rig = Rig::new("t14");
        let primary_path = rig.primary_dir.join("primary.lvault");

        fs::remove_file(&rig.bound).unwrap();
        fs::hard_link(&primary_path, &rig.bound).unwrap();

        // The primary's own identity is "expected", so only the alias check can
        // refuse.
        let refusal = HeldTarget::acquire(
            &rig.target,
            &rig.names,
            rig.primary_facts.identity(),
            &rig.primary_facts,
            &mut Seams::none(),
        )
        .unwrap_err();

        assert_eq!(refusal, AcquireRefusal::PrimaryAlias);
        assert_eq!(fs::read(&primary_path).unwrap(), PRIMARY);
        assert_eq!(fs::read(&rig.bound).unwrap(), PRIMARY);
        assert_eq!(rig.dest_names(), vec![LEAF.to_owned()]);
    }

    #[test]
    fn t15_a_target_with_two_links_is_refused() {
        let rig = Rig::new("t15");

        fs::hard_link(&rig.bound, rig.dest.join("second-name.lvault")).unwrap();

        assert_eq!(
            rig.acquire(&mut Seams::none()).unwrap_err(),
            AcquireRefusal::NotSingleLink
        );

        assert_eq!(fs::read(&rig.bound).unwrap(), OLD);
        assert_eq!(
            rig.dest_names(),
            vec![LEAF.to_owned(), "second-name.lvault".to_owned()]
        );
        rig.assert_isolated();
    }

    // ---- 16-20. names -----------------------------------------------------------------

    #[test]
    fn t16_a_locator_spelled_in_another_case_is_refused() {
        let rig = Rig::new("t16");
        let other_case = rig.dest.join(LEAF.to_uppercase());

        assert_ne!(other_case, rig.bound);

        // The file is reachable through the other spelling...
        let target = SyncFileTarget::from_path(&other_case).unwrap();

        assert!(matches!(target.read(), SyncFileRead::Present(_)));

        // ...but renaming S to that spelling would break name continuity.
        let names = ExchangeNames::derive(&target, id()).unwrap();
        let refusal = HeldTarget::acquire(
            &target,
            &names,
            rig.expected,
            &rig.primary_facts,
            &mut Seams::none(),
        )
        .unwrap_err();

        assert_eq!(refusal, AcquireRefusal::TargetNameNotCanonical);
        rig.expect(&[(Which::Bound, OLD)]);
        rig.assert_isolated();
    }

    #[test]
    fn t17_an_8_3_short_name_locator_is_refused_where_short_names_exist() {
        let rig = Rig::new("t17");
        let long = "an-intentionally-long-name-for-short-alias-generation.lvault";

        fs::write(rig.dest.join(long), OLD).unwrap();

        // Windows build, recorded for the report.
        let version = Command::new("cmd").args(["/C", "ver"]).output().unwrap();

        eprintln!(
            "OBSERVED Windows build: {}",
            String::from_utf8_lossy(&version.stdout).trim()
        );

        let listing = Command::new("cmd")
            .args(["/C", "dir", "/x"])
            .arg(&rig.dest)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&listing.stdout).into_owned();
        let short = text
            .lines()
            .filter(|line| line.contains(long))
            .flat_map(str::split_whitespace)
            .find(|token| token.contains('~'))
            .map(str::to_owned);

        match short {
            None => eprintln!(
                "OBSERVED 8.3 short names: NOT AVAILABLE on the scratch volume (none generated); \
                 the short-name refusal was NOT physically tested"
            ),
            Some(short) => {
                eprintln!("OBSERVED 8.3 short names: AVAILABLE on the scratch volume");

                let alias = rig.dest.join(&short);
                let identity = facts_of(&File::open(&alias).unwrap()).unwrap().identity();
                let target = SyncFileTarget::from_path(&alias).unwrap();
                let names = ExchangeNames::derive(&target, id()).unwrap();
                let refusal = HeldTarget::acquire(
                    &target,
                    &names,
                    identity,
                    &rig.primary_facts,
                    &mut Seams::none(),
                )
                .unwrap_err();

                assert_eq!(refusal, AcquireRefusal::TargetNameNotCanonical);
            }
        }

        assert_eq!(rig.dest_names().len(), 2);
        rig.assert_isolated();
    }

    #[test]
    fn t18_unusable_leaves_are_refused_before_any_io() {
        let long = "x".repeat(256);
        let cases: Vec<(OsString, NameRefusal)> = vec![
            ("".into(), NameRefusal::LeafEmpty),
            (".".into(), NameRefusal::LeafEmpty),
            ("..".into(), NameRefusal::LeafEmpty),
            ("a\\b".into(), NameRefusal::LeafForbiddenCharacter),
            ("a/b".into(), NameRefusal::LeafForbiddenCharacter),
            ("a:b".into(), NameRefusal::LeafForbiddenCharacter),
            ("a:stream".into(), NameRefusal::LeafForbiddenCharacter),
            ("a*b".into(), NameRefusal::LeafForbiddenCharacter),
            ("a\u{1}b".into(), NameRefusal::LeafForbiddenCharacter),
            ("a\0b".into(), NameRefusal::LeafForbiddenCharacter),
            ("trailing.".into(), NameRefusal::LeafTrailingDotOrSpace),
            ("trailing ".into(), NameRefusal::LeafTrailingDotOrSpace),
            ("NUL".into(), NameRefusal::LeafReservedDevice),
            ("nul.lvault".into(), NameRefusal::LeafReservedDevice),
            ("Com1.txt".into(), NameRefusal::LeafReservedDevice),
            ("LPT9".into(), NameRefusal::LeafReservedDevice),
            ("CONIN$".into(), NameRefusal::LeafReservedDevice),
            (long.into(), NameRefusal::LeafTooLong),
            (
                OsString::from_wide(&[0x61, 0xD800, 0x62]),
                NameRefusal::LeafNotUnicode,
            ),
        ];

        for (leaf, expected) in &cases {
            assert_eq!(validate_leaf(leaf), Err(*expected), "{leaf:?}");
        }

        // Ordinary names are accepted, including one that only looks reserved.
        for fine in [
            "vault.lvault",
            "ünï-ключ.lvault",
            "COM10.lvault",
            ".hidden",
            "a b",
        ] {
            assert_eq!(validate_leaf(OsStr::new(fine)), Ok(()), "{fine}");
        }

        // A leaf that is valid by itself but whose derived names are too long.
        let rig = Rig::new("t18");
        let snapshot_before = snapshot(rig.dir.path());
        let derived_too_long = rig.dir.path().join("d").join("y".repeat(200));
        let target = SyncFileTarget::from_path(&derived_too_long).unwrap();

        assert_eq!(
            ExchangeNames::derive(&target, id()).unwrap_err(),
            NameRefusal::LeafTooLong
        );
        assert_eq!(
            ExchangeId::new(Uuid::nil()).unwrap_err(),
            NameRefusal::IdNil
        );

        // Nothing was created.
        assert_eq!(snapshot(rig.dir.path()), snapshot_before);

        // A real derivation has the documented shape.
        let uuid = Uuid::new_v4();
        let names = ExchangeNames::derive(&rig.target, ExchangeId::new(uuid).unwrap()).unwrap();

        assert_eq!(names.target, OsString::from(LEAF));
        assert_eq!(
            names.staging,
            OsString::from(format!(".{LEAF}.localvault-update-{uuid}.tmp"))
        );
        assert_eq!(
            names.retention,
            OsString::from(format!(".{LEAF}.localvault-previous-{uuid}.lvprev"))
        );
        assert!(!names.retention.to_string_lossy().ends_with(".lvault"));
    }

    #[test]
    fn t19_the_three_names_must_be_pairwise_distinct_under_every_folding() {
        let o = OsStr::new;

        assert!(leaves_are_distinct(&[o("a"), o("b"), o("c")]));
        // Exact duplicates.
        assert!(!leaves_are_distinct(&[o("a"), o("b"), o("a")]));
        // ASCII case-insensitive.
        assert!(!leaves_are_distinct(&[
            o("a.lvault"),
            o("b"),
            o("A.LVAULT")
        ]));
        // Unicode uppercase folding (the sharp s uppercases to SS).
        assert!(!leaves_are_distinct(&[o("straße"), o("b"), o("STRASSE")]));
        assert!(!leaves_are_distinct(&[o("ключ"), o("КЛЮЧ"), o("c")]));

        // The derived names are distinct from each other and from the target.
        let rig = Rig::new("t19");

        assert!(leaves_are_distinct(&[
            rig.names.target.as_os_str(),
            rig.names.staging.as_os_str(),
            rig.names.retention.as_os_str(),
        ]));
    }

    #[test]
    fn t20_an_existing_staging_or_retention_name_in_any_case_is_refused() {
        type NameOf = Box<dyn Fn(&Rig) -> String>;

        let cases: Vec<(&str, NameOf, AcquireRefusal)> = vec![
            (
                "staging-exact",
                Box::new(|rig| rig.staging_name()),
                AcquireRefusal::StagingNameExists,
            ),
            (
                "staging-upper",
                Box::new(|rig| rig.staging_name().to_uppercase()),
                AcquireRefusal::StagingNameExists,
            ),
            (
                "retention-exact",
                Box::new(|rig| rig.retention_name()),
                AcquireRefusal::RetentionNameExists,
            ),
            (
                "retention-upper",
                Box::new(|rig| rig.retention_name().to_uppercase()),
                AcquireRefusal::RetentionNameExists,
            ),
        ];

        for (label, name_of, expected) in cases {
            let rig = Rig::new(&format!("t20-{label}"));
            let existing = rig.dest.join(name_of(&rig));

            fs::write(&existing, FOREIGN).unwrap();

            let before = snapshot(&rig.dest);

            assert_eq!(
                rig.acquire(&mut Seams::none()).unwrap_err(),
                expected,
                "{label}"
            );

            // Nothing was created or changed, and the foreign file is untouched.
            assert_eq!(snapshot(&rig.dest), before, "{label}");
            assert_eq!(fs::read(&existing).unwrap(), FOREIGN);
            rig.assert_isolated();
        }
    }

    // ---- 21-22. reparse points, parents, ancestors --------------------------------------

    #[test]
    fn t21_junctions_reparse_objects_and_a_missing_parent_are_refused() {
        // A junction parent.
        let rig = Rig::new("t21-parent");
        let link = rig.dir.path().join("link");

        make_junction(&link, &rig.dest);

        let through = SyncFileTarget::from_path(&link.join(LEAF)).unwrap();
        let names = ExchangeNames::derive(&through, id()).unwrap();

        assert_eq!(
            HeldTarget::acquire(
                &through,
                &names,
                rig.expected,
                &rig.primary_facts,
                &mut Seams::none()
            )
            .unwrap_err(),
            AcquireRefusal::ParentNotPlain
        );
        rig.expect(&[(Which::Bound, OLD)]);

        // A junction at the target name.
        let rig = Rig::new("t21-target");
        let aside = rig.dir.path().join("aside");

        fs::create_dir(&aside).unwrap();
        fs::write(aside.join("inner.txt"), b"inside").unwrap();
        fs::remove_file(&rig.bound).unwrap();
        make_junction(&rig.bound, &aside);

        assert_eq!(
            rig.acquire(&mut Seams::none()).unwrap_err(),
            AcquireRefusal::TargetNotPlainFile
        );
        assert_eq!(fs::read(aside.join("inner.txt")).unwrap(), b"inside");

        // A missing parent creates nothing.
        let rig = Rig::new("t21-missing");
        let missing = rig.dir.path().join("nope").join(LEAF);
        let target = SyncFileTarget::from_path(&missing).unwrap();
        let names = ExchangeNames::derive(&target, id()).unwrap();

        assert_eq!(
            HeldTarget::acquire(
                &target,
                &names,
                rig.expected,
                &rig.primary_facts,
                &mut Seams::none()
            )
            .unwrap_err(),
            AcquireRefusal::ParentUnavailable
        );
        assert!(!rig.dir.path().join("nope").exists());

        // The remaining object kinds at the target name.
        let rig = Rig::new("t21-kinds");

        fs::remove_file(&rig.bound).unwrap();
        assert_eq!(
            rig.acquire(&mut Seams::none()).unwrap_err(),
            AcquireRefusal::TargetMissing
        );

        fs::write(&rig.bound, b"").unwrap();
        assert_eq!(
            rig.acquire(&mut Seams::none()).unwrap_err(),
            AcquireRefusal::SizeUnsupported
        );

        fs::remove_file(&rig.bound).unwrap();
        fs::create_dir(&rig.bound).unwrap();
        assert_eq!(
            rig.acquire(&mut Seams::none()).unwrap_err(),
            AcquireRefusal::TargetNotPlainFile
        );

        // Names derived from another target are refused.
        let other = SyncFileTarget::from_path(&rig.dest.join("other.lvault")).unwrap();
        let other_names = ExchangeNames::derive(&other, id()).unwrap();

        assert_eq!(
            HeldTarget::acquire(
                &rig.target,
                &other_names,
                rig.expected,
                &rig.primary_facts,
                &mut Seams::none()
            )
            .unwrap_err(),
            AcquireRefusal::NamesMismatch
        );
    }

    #[test]
    fn t22_an_ancestor_rename_while_pinned_is_measured_and_never_a_wrong_path_success() {
        let rig = Rig::at("t22", &["outer", "inner"]);
        let held = rig.held();
        let outer = rig.dir.path().join("outer");
        let renamed = rig.dir.path().join("outer-renamed");

        match fs::rename(&outer, &renamed) {
            Err(error) => {
                eprintln!(
                    "OBSERVED ancestor rename while the directory is pinned and the file held: \
                     BLOCKED kind={:?} os={:?}",
                    error.kind(),
                    error.raw_os_error()
                );

                // Normal operation continues on the right path.
                let staged = held.stage(NEW, &mut Seams::none()).expect("stage");

                assert!(matches!(
                    exchange(staged, &mut Seams::none()),
                    ExchangeOutcome::Exchanged(_)
                ));
                rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);
            }
            Ok(()) => {
                eprintln!(
                    "OBSERVED ancestor rename while the directory is pinned and the file held: \
                     SUCCEEDED"
                );

                // The staging file is created by path: the old path is gone, so
                // staging fails and nothing is exchanged at a wrong path.
                let failure = held.stage(NEW, &mut Seams::none()).unwrap_err();

                assert_eq!(failure.reason, StageRefusal::StagingCreateFailed);
                assert!(!failure.staging_remains);

                drop(failure);
                fs::rename(&renamed, &outer).unwrap();
                rig.expect(&[(Which::Bound, OLD)]);
            }
        }

        rig.assert_isolated();
    }

    // ---- 23-27. the window and the statuses ------------------------------------------------

    #[test]
    fn t23_a_foreign_file_created_between_the_renames_is_never_overwritten() {
        let rig = Rig::new("t23");
        let staged = rig.staged();
        let bound = rig.bound.clone();
        let mut seams = at(Stage::BetweenRenames, move || {
            fs::write(&bound, FOREIGN).unwrap();
        });

        let _ = take_last_rename_status();
        let outcome = exchange(staged, &mut seams);

        // The REAL kernel refused the second rename because the name exists.
        eprintln!(
            "OBSERVED second rename onto a foreign file: {}",
            hex(take_last_rename_status().unwrap())
        );

        let ExchangeOutcome::TargetTakenOver(retained) = outcome else {
            panic!("expected TargetTakenOver, got {outcome:?}");
        };

        assert!(!retained.staging_remains);

        // The foreign bytes are untouched, the old version is retained, our staging
        // file is gone.
        rig.expect(&[(Which::Bound, FOREIGN), (Which::Retention, OLD)]);

        let kept = facts_of(&File::open(rig.retention_path()).unwrap()).unwrap();

        assert_eq!(kept.identity(), retained.core.t_facts.identity());

        drop(retained);
        rig.assert_isolated();
    }

    #[test]
    fn t24_a_refused_second_rename_with_an_empty_name_restores_the_old_file() {
        let rig = Rig::new("t24");
        let staged = rig.staged();
        let t_identity = staged.0.core.t_facts.identity();
        let mut seams = at(Stage::BetweenRenames, || inject_rename_status(NAME_INVALID));
        let outcome = exchange(staged, &mut seams);

        let ExchangeOutcome::Restored {
            staging_remains,
            held,
        } = outcome
        else {
            panic!("expected Restored, got {outcome:?}");
        };

        assert!(!staging_remains);

        // T is back at the original name with the same identity and bytes.
        let back = facts_of(&File::open(&rig.bound).unwrap()).unwrap();

        assert_eq!(back.identity(), t_identity);
        rig.expect(&[(Which::Bound, OLD)]);

        // The returned held target is usable again.
        let again = held.stage(NEW, &mut Seams::none()).expect("stage again");

        drop(again);
        rig.assert_isolated();
    }

    #[test]
    fn t25_a_refused_second_rename_and_a_refused_restore_keep_both_artifacts() {
        let rig = Rig::new("t25");
        let staged = rig.staged();
        let mut seams = hook(|stage| match stage {
            Stage::BetweenRenames => inject_rename_status(NAME_INVALID),
            Stage::BeforeRestore => inject_rename_status(ACCESS_DENIED),
            _ => {}
        });

        let _ = take_last_delete_status();
        let outcome = exchange(staged, &mut seams);

        let ExchangeOutcome::Interrupted(interrupted) = outcome else {
            panic!("expected Interrupted, got {outcome:?}");
        };

        // The old version at R, the new version at its staging name, no target.
        rig.expect(&[(Which::Retention, OLD), (Which::Staging, NEW)]);
        // Nothing was deleted.
        assert_eq!(take_last_delete_status(), None);

        drop(interrupted);
        rig.expect(&[(Which::Retention, OLD), (Which::Staging, NEW)]);
        rig.assert_isolated();
    }

    #[test]
    fn t26_an_unknown_native_status_deletes_nothing_and_retries_nothing() {
        // Unknown on the first rename (injected: nothing actually moved).
        let rig = Rig::new("t26-first");
        let staged = rig.staged();
        let mut seams = at(Stage::BeforeRetentionRename, || {
            inject_rename_status(UNSUCCESSFUL)
        });

        let _ = take_last_delete_status();
        let _ = take_last_rename_status();

        let ExchangeOutcome::Unknown(unknown) = exchange(staged, &mut seams) else {
            panic!("expected Unknown");
        };

        assert_eq!(unknown.at(), ExchangeStep::RetentionRename);
        assert_eq!(take_last_delete_status(), None);
        // Exactly the one injected rename; no retry.
        assert_eq!(take_last_rename_status(), Some(UNSUCCESSFUL));
        assert_eq!(take_last_rename_status(), None);
        rig.expect(&[(Which::Bound, OLD), (Which::Staging, NEW)]);

        drop(unknown);
        rig.expect(&[(Which::Bound, OLD), (Which::Staging, NEW)]);

        // Unknown on the second rename (injected: the name stays empty).
        let rig = Rig::new("t26-second");
        let staged = rig.staged();
        let mut seams = at(Stage::BetweenRenames, || inject_rename_status(UNSUCCESSFUL));

        let _ = take_last_delete_status();

        let ExchangeOutcome::Unknown(unknown) = exchange(staged, &mut seams) else {
            panic!("expected Unknown");
        };

        assert_eq!(unknown.at(), ExchangeStep::Publication);
        assert_eq!(take_last_delete_status(), None);
        rig.expect(&[(Which::Retention, OLD), (Which::Staging, NEW)]);

        drop(unknown);
        rig.expect(&[(Which::Retention, OLD), (Which::Staging, NEW)]);

        // Unknown on the restoring rename.
        let rig = Rig::new("t26-restore");
        let staged = rig.staged();
        let mut seams = hook(|stage| match stage {
            Stage::BetweenRenames => inject_rename_status(NAME_INVALID),
            Stage::BeforeRestore => inject_rename_status(UNSUCCESSFUL),
            _ => {}
        });

        let _ = take_last_delete_status();

        let ExchangeOutcome::Unknown(unknown) = exchange(staged, &mut seams) else {
            panic!("expected Unknown");
        };

        assert_eq!(unknown.at(), ExchangeStep::Restoration);
        assert_eq!(take_last_delete_status(), None);
        rig.expect(&[(Which::Retention, OLD), (Which::Staging, NEW)]);
    }

    #[test]
    fn t27_a_refused_first_rename_leaves_the_old_file_in_place() {
        // Injected definite refusal.
        let rig = Rig::new("t27-injected");
        let staged = rig.staged();
        let mut seams = at(Stage::BeforeRetentionRename, || {
            inject_rename_status(ACCESS_DENIED)
        });

        let ExchangeOutcome::NotExchanged {
            reason,
            staging_remains,
            held,
        } = exchange(staged, &mut seams)
        else {
            panic!("expected NotExchanged");
        };

        assert_eq!(reason, NotExchangedReason::RetentionRefused);
        assert!(!staging_remains);
        assert_unchanged(&rig, &held);

        // A real collision: someone creates the retention name after the checks.
        let rig = Rig::new("t27-real");
        let staged = rig.staged();
        let retention = rig.retention_path();
        let mut seams = at(Stage::BeforeRetentionRename, move || {
            fs::write(&retention, FOREIGN).unwrap();
        });

        let _ = take_last_rename_status();

        let ExchangeOutcome::NotExchanged {
            reason,
            staging_remains,
            ..
        } = exchange(staged, &mut seams)
        else {
            panic!("expected NotExchanged");
        };

        eprintln!(
            "OBSERVED first rename onto an existing retention name: {}",
            hex(take_last_rename_status().unwrap())
        );

        assert_eq!(reason, NotExchangedReason::RetentionCollision);
        assert!(!staging_remains);
        rig.expect(&[(Which::Bound, OLD), (Which::Retention, FOREIGN)]);
        rig.assert_isolated();

        // A failed caller recheck.
        let rig = Rig::new("t27-recheck");
        let staged = rig.staged();
        let outcome = staged.exchange(&mut || false, &mut Seams::none());

        assert!(matches!(
            outcome,
            ExchangeOutcome::NotExchanged {
                reason: NotExchangedReason::RecheckRefused,
                staging_remains: false,
                ..
            }
        ));
        rig.expect(&[(Which::Bound, OLD)]);
    }

    // ---- 28-29. staging failures and unsupported facts ---------------------------------------

    #[test]
    fn t28_staging_write_and_flush_failures_remove_only_our_staging_file() {
        for (fault, reason) in [
            (StageFault::Write, StageRefusal::WriteFailed),
            (StageFault::Flush, StageRefusal::FlushFailed),
            (StageFault::Sync, StageRefusal::FlushFailed),
        ] {
            let (rig, held) = held_rig(&format!("t28-{fault:?}"));
            let mut seams = Seams {
                stage_fault: Some(fault),
                ..Seams::none()
            };
            let failure = held.stage(NEW, &mut seams).unwrap_err();

            assert_eq!(failure.reason, reason);
            assert!(!failure.staging_remains);
            assert_unchanged(&rig, &failure.held);
            rig.assert_isolated();
        }

        // The cleanup itself fails: the leftover is reported, not hidden.
        let (rig, held) = held_rig("t28-cleanup");
        let mut seams = Seams {
            stage_fault: Some(StageFault::Write),
            ..Seams::none()
        };

        inject_delete_status(UNSUCCESSFUL);

        let failure = held.stage(NEW, &mut seams).unwrap_err();

        assert!(failure.staging_remains);

        drop(failure);

        assert!(rig.staging_path().exists());

        // Unsupported bytes: nothing created.
        let (rig, held) = held_rig("t28-bytes");
        let failure = held.stage(b"", &mut Seams::none()).unwrap_err();

        assert_eq!(failure.reason, StageRefusal::BytesUnsupported);
        assert_unchanged(&rig, &failure.held);

        // A foreign file at the staging name is never opened, truncated or removed.
        let (rig, held) = held_rig("t28-foreign");
        let staging = rig.staging_path();
        let mut seams = at(Stage::BeforeStageWrite, move || {
            fs::write(&staging, FOREIGN).unwrap()
        });
        let failure = held.stage(NEW, &mut seams).unwrap_err();

        assert_eq!(failure.reason, StageRefusal::StagingNameExists);
        assert!(!failure.staging_remains);
        rig.expect(&[(Which::Bound, OLD), (Which::Staging, FOREIGN)]);
    }

    #[test]
    fn t29_unsupported_or_uncertain_volume_and_identity_facts_are_refused() {
        let rig = Rig::new("t29");

        // Injected directory facts.
        for facts in [
            VolumeFacts::for_test(FileSystemKind::Other, true),
            VolumeFacts::for_test(FileSystemKind::Refs, true),
            VolumeFacts::for_test(FileSystemKind::Ntfs, false),
        ] {
            let mut seams = Seams {
                directory_facts: Some(facts),
                ..Seams::none()
            };

            assert_eq!(
                rig.acquire(&mut seams).unwrap_err(),
                AcquireRefusal::VolumeNotLocalNtfs
            );
        }

        // Injected target facts.
        fn facts(
            links: u32,
            pending: bool,
            kind: FileSystemKind,
            local: bool,
        ) -> Result<HandleFacts, IdentityError> {
            Ok(HandleFacts::for_test(
                7, [9; 16], links, pending, kind, local,
            ))
        }

        let target_cases = [
            (
                facts(1, false, FileSystemKind::Other, true),
                AcquireRefusal::TargetNotLocalNtfs,
            ),
            (
                facts(1, false, FileSystemKind::Ntfs, false),
                AcquireRefusal::TargetNotLocalNtfs,
            ),
            (
                facts(2, false, FileSystemKind::Ntfs, true),
                AcquireRefusal::NotSingleLink,
            ),
            (
                facts(1, true, FileSystemKind::Ntfs, true),
                AcquireRefusal::DeletePending,
            ),
            (
                Err(IdentityError::Lookup),
                AcquireRefusal::IdentityUncertain,
            ),
            (
                facts(1, false, FileSystemKind::Ntfs, true),
                AcquireRefusal::IdentityChanged,
            ),
        ];

        for (injected, expected) in target_cases {
            let mut seams = Seams {
                target_facts: Some(injected),
                ..Seams::none()
            };

            assert_eq!(rig.acquire(&mut seams).unwrap_err(), expected);
        }

        rig.expect(&[(Which::Bound, OLD)]);

        // Injected staging facts: the staging file is removed by handle.
        type Inject = Box<dyn Fn(&HeldTarget) -> Result<HandleFacts, IdentityError>>;

        let staging_cases: Vec<(Inject, StageRefusal)> = vec![
            (
                Box::new(|_| Err(IdentityError::Lookup)),
                StageRefusal::IdentityUncertain,
            ),
            (
                Box::new(|_| facts(1, false, FileSystemKind::Other, true)),
                StageRefusal::VolumeNotLocalNtfs,
            ),
            (
                Box::new(|_| facts(2, false, FileSystemKind::Ntfs, true)),
                StageRefusal::IdentityUncertain,
            ),
            (
                Box::new(|_| facts(1, true, FileSystemKind::Ntfs, true)),
                StageRefusal::IdentityUncertain,
            ),
            // The staging file reports the old target's own identity.
            (
                Box::new(|held| Ok(held.0.t_facts)),
                StageRefusal::IdentityUncertain,
            ),
        ];

        for (index, (injected, expected)) in staging_cases.into_iter().enumerate() {
            let (rig, held) = held_rig(&format!("t29-staging-{index}"));
            let mut seams = Seams {
                staging_facts: Some(injected(&held)),
                ..Seams::none()
            };
            let failure = held.stage(NEW, &mut seams).unwrap_err();

            assert_eq!(failure.reason, expected, "case {index}");
            assert!(!failure.staging_remains);
            assert_unchanged(&rig, &failure.held);
        }

        rig.assert_isolated();
    }

    // ---- 30. dropping every ownership stage ------------------------------------------------------

    #[test]
    fn t30_dropping_any_value_deletes_nothing() {
        // HeldTarget.
        let rig = Rig::new("t30-held");

        drop(rig.held());
        rig.expect(&[(Which::Bound, OLD)]);

        // Staged: the staging file stays, exactly as after a crash.
        let rig = Rig::new("t30-staged");

        let _ = take_last_delete_status();

        drop(rig.staged());
        rig.expect(&[(Which::Bound, OLD), (Which::Staging, NEW)]);
        assert_eq!(take_last_delete_status(), None);

        // StageFailure (cleanup failed): the leftover stays.
        let (rig, held) = held_rig("t30-failure");
        let mut seams = Seams {
            stage_fault: Some(StageFault::Write),
            ..Seams::none()
        };

        inject_delete_status(UNSUCCESSFUL);
        drop(held.stage(NEW, &mut seams).unwrap_err());
        assert!(rig.staging_path().exists());

        // Exchanged -> Swapped, Verified, Unverified.
        let rig = Rig::new("t30-swapped");
        let swapped_value = swapped(&rig);

        let _ = take_last_delete_status();

        drop(swapped_value);
        rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);

        let rig = Rig::new("t30-verified");
        let verified = swapped(&rig)
            .verify(&mut |_| true, &mut Seams::none())
            .expect("verified");

        drop(verified);
        rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);

        let rig = Rig::new("t30-unverified");
        let unverified = swapped(&rig)
            .verify(&mut |_| false, &mut Seams::none())
            .unwrap_err();

        drop(unverified);
        rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);
        assert_eq!(take_last_delete_status(), None);

        // NotExchanged and Restored carry the held target; dropping deletes nothing.
        let rig = Rig::new("t30-notexchanged");

        drop(rig.staged().exchange(&mut || false, &mut Seams::none()));
        rig.expect(&[(Which::Bound, OLD)]);

        let rig = Rig::new("t30-restored");
        let mut seams = at(Stage::BetweenRenames, || inject_rename_status(NAME_INVALID));

        drop(exchange(rig.staged(), &mut seams));
        rig.expect(&[(Which::Bound, OLD)]);

        // TargetTakenOver.
        let rig = Rig::new("t30-takenover");
        let bound = rig.bound.clone();
        let mut seams = at(Stage::BetweenRenames, move || {
            fs::write(&bound, FOREIGN).unwrap();
        });

        drop(exchange(rig.staged(), &mut seams));
        rig.expect(&[(Which::Bound, FOREIGN), (Which::Retention, OLD)]);

        // Interrupted.
        let rig = Rig::new("t30-interrupted");
        let mut seams = hook(|stage| match stage {
            Stage::BetweenRenames => inject_rename_status(NAME_INVALID),
            Stage::BeforeRestore => inject_rename_status(ACCESS_DENIED),
            _ => {}
        });

        drop(exchange(rig.staged(), &mut seams));
        rig.expect(&[(Which::Retention, OLD), (Which::Staging, NEW)]);

        // Unknown.
        let rig = Rig::new("t30-unknown");
        let mut seams = at(Stage::BetweenRenames, || inject_rename_status(UNSUCCESSFUL));

        drop(exchange(rig.staged(), &mut seams));
        rig.expect(&[(Which::Retention, OLD), (Which::Staging, NEW)]);
    }

    // ---- 31. verification --------------------------------------------------------------------------

    #[test]
    fn t31_a_failed_verification_retains_the_old_version() {
        // The caller's own check fails.
        let rig = Rig::new("t31-check");
        let unverified = swapped(&rig)
            .verify(&mut |_| false, &mut Seams::none())
            .unwrap_err();

        assert_eq!(unverified.reason(), VerifyRefusal::CheckRejected);

        // Both artifacts are kept, and both handles are still held.
        rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);
        blocked(
            "write to the retained old file after a failed verification",
            OpenOptions::new()
                .write(true)
                .open(rig.retention_path())
                .map(|_| ()),
        );
        blocked(
            "write to the new target after a failed verification",
            OpenOptions::new().write(true).open(&rig.bound).map(|_| ()),
        );

        drop(unverified);
        rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);
        rig.assert_isolated();

        // Injected wrong read-backs.
        type Wrong = Box<dyn FnMut(SyncFileRead) -> SyncFileRead>;

        let wrong_reads: Vec<(Wrong, VerifyRefusal)> = vec![
            (
                Box::new(|_| SyncFileRead::AbsentOnDisk),
                VerifyRefusal::TargetUnreadable,
            ),
            (
                Box::new(|_| SyncFileRead::Unavailable(UnavailableReason::Changed)),
                VerifyRefusal::TargetUnreadable,
            ),
            (
                Box::new(|read| match read {
                    SyncFileRead::Present(present) => SyncFileRead::Present(
                        present.with_physical_for_test(Err(IdentityError::Lookup)),
                    ),
                    other => other,
                }),
                VerifyRefusal::TargetUnreadable,
            ),
            (
                Box::new(|read| match read {
                    SyncFileRead::Present(present) => {
                        let other =
                            HandleFacts::for_test(7, [5; 16], 1, false, FileSystemKind::Ntfs, true);

                        SyncFileRead::Present(present.with_physical_for_test(Ok(other)))
                    }
                    other => other,
                }),
                VerifyRefusal::TargetIdentityMismatch,
            ),
        ];

        for (index, (map, expected)) in wrong_reads.into_iter().enumerate() {
            let rig = Rig::new(&format!("t31-read-{index}"));
            let mut seams = Seams {
                verify_read: Some(map),
                ..Seams::none()
            };
            let unverified = swapped(&rig).verify(&mut |_| true, &mut seams).unwrap_err();

            assert_eq!(unverified.reason(), expected, "case {index}");
            rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);
        }

        // Disagreement with what the exchange believes it wrote or retained.
        let rig = Rig::new("t31-bytes");
        let mut live = swapped(&rig);

        live.0.new_bytes = b"not what was written".to_vec();

        assert_eq!(
            live.verify(&mut |_| true, &mut Seams::none())
                .unwrap_err()
                .reason(),
            VerifyRefusal::TargetBytesMismatch
        );

        let rig = Rig::new("t31-retention-bytes");
        let mut live = swapped(&rig);

        live.0.core.old_bytes = b"not the old version".to_vec();

        assert_eq!(
            live.verify(&mut |_| true, &mut Seams::none())
                .unwrap_err()
                .reason(),
            VerifyRefusal::RetentionBytesMismatch
        );

        let rig = Rig::new("t31-facts");
        let mut live = swapped(&rig);

        live.0.s_facts = HandleFacts::for_test(7, [5; 16], 1, false, FileSystemKind::Ntfs, true);

        assert_eq!(
            live.verify(&mut |_| true, &mut Seams::none())
                .unwrap_err()
                .reason(),
            VerifyRefusal::NewVersionChanged
        );

        let rig = Rig::new("t31-previous");
        let mut live = swapped(&rig);

        live.0.core.t_facts =
            HandleFacts::for_test(7, [5; 16], 1, false, FileSystemKind::Ntfs, true);

        assert_eq!(
            live.verify(&mut |_| true, &mut Seams::none())
                .unwrap_err()
                .reason(),
            VerifyRefusal::PreviousChanged
        );
    }

    // ---- 32. retention and the test-only release ----------------------------------------------------

    #[test]
    fn t32_the_previous_version_is_released_only_from_verified_and_only_in_tests() {
        let rig = Rig::new("t32");
        let verified = swapped(&rig)
            .verify(&mut |bytes| bytes == NEW, &mut Seams::none())
            .expect("verified");

        // Retention is the default: nothing deletes R until this test-only call,
        // which requires `Verified` ownership.
        assert_eq!(
            verified.release_previous_for_test(),
            PreviousRelease::Removed
        );
        rig.expect(&[(Which::Bound, NEW)]);
        rig.assert_isolated();

        // `retain_previous` keeps R.
        let rig = Rig::new("t32-retain");
        let verified = swapped(&rig)
            .verify(&mut |_| true, &mut Seams::none())
            .expect("verified");

        verified.retain_previous();
        rig.expect(&[(Which::Bound, NEW), (Which::Retention, OLD)]);
    }

    /// The production half of this file: everything before the test-only marker,
    /// without comment lines.
    fn production_code() -> String {
        include_str!("target_exchange.rs")
            .split("// ---- test-only code below this line")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn t32_a_production_build_has_no_way_to_delete_or_rename_the_previous_version() {
        let code = production_code();

        // The test-only release does not exist before the marker (and is cfg(test)
        // after it).
        assert!(!code.contains("release_previous"));

        // Exactly one deletion in production: the staging cleanup, by handle.
        assert_eq!(code.matches("delete_by_handle(").count(), 1);
        assert!(code.contains("fn remove_staging(staging: File"));

        // Exactly one rename call, with the no-replace handle-bound primitive.
        assert_eq!(code.matches("rename_into_directory_no_replace(").count(), 1);

        // No path-based mutation, no replacing primitive, no unsafe, no %TEMP%.
        for forbidden in [
            "ReplaceFileW",
            "ReplaceIfExists",
            "MoveFile",
            "fs::rename",
            "fs::remove_file",
            "fs::remove_dir",
            "fs::hard_link",
            "fs::copy",
            "fs::write",
            "set_len",
            ".truncate(",
            "unsafe",
            "temp_dir",
        ] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }
    }

    // ---- 33. isolation --------------------------------------------------------------------------------

    #[test]
    fn t33_nothing_is_written_outside_the_scratch_directory() {
        let rig = Rig::new("t33");
        let verified = swapped(&rig)
            .verify(&mut |_| true, &mut Seams::none())
            .expect("verified");

        verified.retain_previous();

        // The working directory and the primary stand-in are unchanged, and the
        // scratch directory is under the B3 base, not %TEMP%.
        rig.assert_isolated();
        assert!(!rig.dir.path().starts_with(std::env::temp_dir()));
    }

    #[test]
    fn no_other_source_file_refers_to_the_module() {
        fn walk(dir: &Path, found: &mut Vec<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();

                if path.is_dir() {
                    walk(&path, found);
                } else if path.extension().is_some_and(|ext| ext == "rs")
                    && fs::read_to_string(&path)
                        .unwrap()
                        .contains("target_exchange")
                {
                    found.push(path.file_name().unwrap().to_string_lossy().into_owned());
                }
            }
        }

        let mut found = Vec::new();

        walk(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut found,
        );
        found.sort();

        assert_eq!(
            found,
            vec!["mod.rs".to_owned(), "target_exchange.rs".to_owned()]
        );
    }

    // ---- types: ownership, redaction, order ---------------------------------------------------------------

    struct Probe<T>(PhantomData<T>);

    trait Fallback {
        const IS_CLONE: bool = false;
        const IS_COPY: bool = false;
    }

    impl<T> Fallback for Probe<T> {}

    impl<T: Clone> Probe<T> {
        const IS_CLONE: bool = true;
    }

    impl<T: Copy> Probe<T> {
        const IS_COPY: bool = true;
    }

    macro_rules! assert_move_only {
        ($($ty:ty),+ $(,)?) => {
            $(
                assert!(!Probe::<$ty>::IS_CLONE, stringify!($ty));
                assert!(!Probe::<$ty>::IS_COPY, stringify!($ty));
            )+
        };
    }

    #[test]
    fn handle_owning_values_are_move_only() {
        assert_move_only!(
            HeldTarget,
            Staged,
            Swapped,
            Verified,
            Unverified,
            StageFailure,
            ExchangeOutcome,
            RetainedPrevious,
            InterruptedExchange,
            UnknownExchange,
        );

        // Sanity check of the probe itself.
        const {
            assert!(Probe::<ExchangeId>::IS_CLONE && Probe::<ExchangeId>::IS_COPY);
            assert!(Probe::<String>::IS_CLONE && !Probe::<String>::IS_COPY);
        }
    }

    #[test]
    fn debug_output_reveals_no_path_name_identifier_status_or_byte() {
        let uuid = Uuid::new_v4();
        let rig = Rig::new("t-debug");
        let names = ExchangeNames::derive(&rig.target, ExchangeId::new(uuid).unwrap()).unwrap();
        let held = rig.held();

        let mut rendered = vec![
            format!("{names:?}"),
            format!("{:?}", ExchangeId::new(uuid).unwrap()),
            format!("{held:?}"),
        ];

        let staged = held.stage(NEW, &mut Seams::none()).unwrap();

        rendered.push(format!("{staged:?}"));

        let outcome = exchange(staged, &mut Seams::none());

        rendered.push(format!("{outcome:?}"));

        let ExchangeOutcome::Exchanged(swapped_value) = outcome else {
            panic!("expected Exchanged");
        };

        let unverified = swapped_value
            .verify(&mut |_| false, &mut Seams::none())
            .unwrap_err();

        rendered.push(format!("{unverified:?}"));

        // Other outcomes.
        let rig = Rig::new("t-debug-other");
        let failure = {
            let mut seams = Seams {
                stage_fault: Some(StageFault::Write),
                ..Seams::none()
            };

            rig.held().stage(NEW, &mut seams).unwrap_err()
        };

        rendered.push(format!("{failure:?}"));
        drop(failure);
        rendered.push(format!("{:?}", rig.acquire(&mut Seams::none()).map(|_| ())));

        let bound = rig.bound.clone();
        let mut seams = at(Stage::BetweenRenames, move || {
            fs::write(&bound, FOREIGN).unwrap();
        });

        rendered.push(format!("{:?}", exchange(rig.staged(), &mut seams)));

        let mut seams = at(Stage::BetweenRenames, || inject_rename_status(UNSUCCESSFUL));
        let rig = Rig::new("t-debug-unknown");

        rendered.push(format!("{:?}", exchange(rig.staged(), &mut seams)));

        let mut seams = hook(|stage| match stage {
            Stage::BetweenRenames => inject_rename_status(NAME_INVALID),
            Stage::BeforeRestore => inject_rename_status(ACCESS_DENIED),
            _ => {}
        });
        let rig = Rig::new("t-debug-interrupted");

        rendered.push(format!("{:?}", exchange(rig.staged(), &mut seams)));

        let forbidden = [
            "LEAKMARK".to_owned(),
            uuid.to_string(),
            "b3b1".to_owned(),
            "synthetic".to_owned(),
            "qa-local".to_owned(),
            "C000".to_owned(),
            "c000".to_owned(),
        ];

        for text in &rendered {
            for mark in &forbidden {
                assert!(!text.contains(mark.as_str()), "{mark} in {text}");
            }
        }
    }

    #[test]
    fn the_stages_are_visited_in_the_documented_order() {
        let rig = Rig::new("t-order");
        let log = Rc::new(RefCell::new(Vec::new()));
        let recorder = |log: &Rc<RefCell<Vec<Stage>>>| {
            let log = Rc::clone(log);

            hook(move |stage| log.borrow_mut().push(stage))
        };

        let held = rig.acquire(&mut recorder(&log)).unwrap();
        let staged = held.stage(NEW, &mut recorder(&log)).unwrap();
        let ExchangeOutcome::Exchanged(swapped_value) = exchange(staged, &mut recorder(&log))
        else {
            panic!("expected Exchanged");
        };
        let verified = swapped_value
            .verify(&mut |_| true, &mut recorder(&log))
            .unwrap();

        verified.retain_previous();

        assert_eq!(
            *log.borrow(),
            vec![
                Stage::BeforeAcquire,
                Stage::AfterAcquire,
                Stage::BeforeStageWrite,
                Stage::BeforeRetentionRename,
                Stage::BetweenRenames,
                Stage::BeforeVerify,
            ]
        );
    }
}
