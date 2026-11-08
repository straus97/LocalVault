//! Test-only, strictly read-only classifier of the physical layout of the legacy
//! version-1 sync-state record files of ONE locator (Stage 1U-4, slice G12R-R1).
//!
//! **This module is a measurement. It is test-only, it never changes anything on disk,
//! it authorizes nothing, and it is unreachable from any production build or caller.**
//! It is declared as `#[cfg(all(test, windows))] mod ...` in `vault/mod.rs`.
//!
//! # What it answers
//!
//! Which physical evidence is present in the legacy `sync-state` directory for one
//! record key, and which layouts that evidence is *consistent with*. It never says
//! which file is the old record, which is the new one, which was written first, or
//! what to do. [`HistoryStatus`] has exactly one variant, permanently.
//!
//! # Five separate layers
//!
//! * A, physical layout: counts of record files only ([`RecordLayout`]), plus the
//!   physical findings ([`PhysicalFindings`]) and their verdict ([`PhysicalSupport`]).
//! * B, entry validity: one [`EntryFinding`] per probed entry.
//! * C, binding and duplicates: [`BindingRelation`] and [`DuplicateFindings`].
//! * Gate parity: [`GateObservation`], the categories the legacy gate refuses on.
//!   It carries no permission meaning; it mirrors a refusal.
//! * D, exchange compatibility: [`ExchangeCompatibility`], derived by an explicit table.
//! * E, history: [`HistoryStatus::NotEstablished`], unconditionally.
//!
//! # Observation
//!
//! Read-only handles only: no write access, no delete access, full sharing, reparse
//! points never followed. The directory is listed and every probed entry is read
//! through its own handle (at most `MAX_SYNC_STATE_BYTES + 1` bytes), then the same is
//! done a second time and the two passes must agree on the related name set and, per
//! entry, on finding, physical identity, link count, length and SHA-256. The
//! directory identity must be equal at the first open, at the end, and on a fresh
//! open of the path.
//!
//! **A two-pass match is not an atomic snapshot.** A change that is undone between the
//! passes, or made after the call returned, is not detected. Opens are by path and
//! the ancestor check is check-then-use.
//!
//! # The bounded-read limit
//!
//! An entry longer than `MAX_SYNC_STATE_BYTES` is read only up to one byte past that
//! bound and is reported as [`EntryFinding::TooLarge`]. For such an entry **no digest
//! of its complete bytes exists**: only its supported metadata (physical identity, link
//! count, length) is known, and a change of its content that keeps its length is not
//! detected by the two passes. Such an entry is never usable: it contributes to no
//! valid pair, to no duplicate of valid records, to no ordering and to no exchange
//! compatibility. No unbounded hashing is attempted.
//!
//! # What is not inferred
//!
//! Historical authority, a trusted old/new order, retention or staging roles, record
//! ownership from file names, user consent, cryptographic authentication, safe
//! automatic recovery. No record field is compared to order records.
//!
//! # Limits
//!
//! * Zero-valued identities cannot be recognized by this module (the recognizer is
//!   private to the identity module): two probed names with equal identities are
//!   reported as one shared object, which is the conservative reading.
//! * Measured on local NTFS on `D:` only. ReFS, SMB, FAT, 8.3 names, case-sensitive
//!   directories, privileged actors and filter drivers are UNVERIFIED.
//! * Nothing here concerns power loss, OS crash or the persistence order of renames.

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use localvault_core::{
    sync::EnvelopeFingerprint,
    sync_state::{Locator, SyncState, SyncStateLoad, MAX_SYNC_STATE_BYTES},
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};

use super::{
    file_identity::{directory_identity_of, facts_of, volume_facts_of, FileIdentity, HandleFacts},
    sync_state_store::{path_identity_eq, SyncStateStore},
};

/// The most directory entries one listing examines.
const MAX_LISTED_ENTRIES: usize = 10_000;

/// The most `.tmp`, `.retired` and `.v3stage` names one observation accepts (the
/// legacy gate's own scanning limit, mirrored).
const MAX_RELATED_ARTIFACTS: usize = 16;

/// Length of a record key: a lowercase hexadecimal SHA-256.
const KEY_LEN: usize = 64;

/// Length of the hexadecimal token in an artifact name.
const TOKEN_LEN: usize = 32;

/// The longest file name a component may have, in UTF-16 code units.
const MAX_NAME_UNITS: usize = 255;

/// `ERROR_SHARING_VIOLATION`.
const SHARING_VIOLATION: i32 = 32;

// ---- 1. the reading ---------------------------------------------------------------

/// What one assessment found. Categories and counts only: no path, name, key, token,
/// length, digest, identity or state is stored in or printed from any value.
///
/// A reading is an observation at one instant. It is not a lock, not a snapshot, not
/// an authentication and not permission for anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum LayoutReading {
    /// Nothing can be concluded about the directory.
    Unobservable(ObservationProblem),
    /// The directory is absent, confirmed twice with a plain existing ancestor.
    NoDirectory,
    /// The two passes, or the directory identity checks, disagreed.
    ChangedDuringAssessment,
    /// At least one probed entry could not be read completely.
    Incomplete(EntryProblem),
    Observed(LayoutReport),
}

/// Why nothing can be concluded about the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationProblem {
    /// An existing ancestor is a link, a reparse point or not a directory.
    AncestorNotPlain,
    /// The directory itself is a link, a reparse point or not a directory.
    DirectoryNotPlain,
    DirectoryUnreadable,
    /// The directory is not on a verified local NTFS volume.
    NotLocalNtfs,
    DirectoryIdentityUnavailable,
    ListingFailed,
    ListingIncomplete,
    /// More directory entries than one listing examines.
    EntryLimit,
    /// More related artifact names than one observation accepts.
    RelatedEntryLimit,
    /// Two related names are equal after ASCII lowercasing.
    AliasAmbiguity,
}

/// Why one probed entry could not be read completely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryProblem {
    /// Another handle excludes the read (a sharing violation or a refusal).
    OpenRefused,
    Unreadable,
    IdentityUncertain,
}

/// One complete observation. Every field is always filled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LayoutReport {
    /// A: physical counts only; it never says anything about validity.
    pub(crate) layout: RecordLayout,
    /// B: the primary entry.
    pub(crate) primary: EntryFinding,
    /// B: counts of the `.tmp` entries.
    pub(crate) temps: TempFindings,
    /// C: over the `V1ForLocator` entries only.
    pub(crate) binding: BindingRelation,
    /// C.
    pub(crate) duplicates: DuplicateFindings,
    /// Gate parity: evidence the legacy gate refuses on. No permission meaning.
    pub(crate) gate: GateObservation,
    /// Detail for the gate field.
    pub(crate) foreign: ForeignNames,
    /// A: detail for the physical verdict.
    pub(crate) physical: PhysicalFindings,
    /// A: the physical verdict.
    pub(crate) support: PhysicalSupport,
    /// D: derived by an explicit table; "consistent with", never proof.
    pub(crate) compatibility: ExchangeCompatibility,
    /// E: always not established.
    pub(crate) history: HistoryStatus,
}

/// How many record files exist, and nothing else. "Several" means a primary plus two
/// or more `.tmp` entries, or no primary plus three or more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordLayout {
    NoRecordFiles,
    PrimaryOnly,
    PrimaryAndOneTemp,
    PrimaryAndSeveralTemps,
    NoPrimaryOneTemp,
    NoPrimaryTwoTemps,
    NoPrimarySeveralTemps,
}

/// What one probed entry is. Judged from its own bytes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryFinding {
    Absent,
    /// A directory, link, reparse point or other object where a file belongs.
    NotPlainFile,
    DeletePending,
    Empty,
    /// Longer than the supported maximum. No digest of its complete bytes exists.
    TooLarge,
    /// Not decodable as a version-1 record (partial, truncated, damaged, or any
    /// other format).
    Corrupt,
    /// A complete wrapper of a version this build does not support.
    UnsupportedVersion,
    /// A valid version-1 record whose local locator is another locator.
    V1OtherLocator,
    /// A valid version-1 record whose local locator is the assessed locator.
    V1ForLocator,
}

/// Counts of the `.tmp` entries by finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct TempFindings {
    pub(crate) total: u8,
    pub(crate) not_plain: u8,
    pub(crate) delete_pending: u8,
    pub(crate) empty: u8,
    pub(crate) too_large: u8,
    pub(crate) corrupt: u8,
    pub(crate) unsupported_version: u8,
    pub(crate) v1_other_locator: u8,
    pub(crate) v1_for_locator: u8,
}

/// The relation of the bindings of the `V1ForLocator` entries only. Binding id, vault
/// tag, exact local locator and target locator must all be equal for `AllSame`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingRelation {
    NoValidRecords,
    Single,
    AllSame,
    Differ,
}

/// Byte-identical content found in distinct physical objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct DuplicateFindings {
    /// Two or more distinct probed `V1ForLocator` objects hold equal SHA-256.
    pub(crate) valid_records: bool,
    /// Two or more distinct non-`V1ForLocator` objects hold equal SHA-256. A
    /// `TooLarge` entry has no digest and never counts.
    pub(crate) other_content: bool,
}

/// Whether the evidence is of a kind the legacy gate refuses on. It mirrors a
/// refusal; it is not a permission and its absence is not one either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateObservation {
    NoGateEvidence,
    /// A `.retired` name, a `.v3stage` name, an unrecognized key-prefixed name, or a
    /// `.tmp` holding a complete record of an unsupported version.
    NewerOrUnrecognizedEvidence,
}

/// Which gate-relevant name families exist. Names are never opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ForeignNames {
    pub(crate) retired: bool,
    pub(crate) reserved_stage: bool,
    pub(crate) unrecognized: bool,
}

/// Physical facts, each true if any probed entry shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PhysicalFindings {
    pub(crate) not_plain: bool,
    pub(crate) delete_pending: bool,
    /// Two probed names are one physical object.
    pub(crate) shared_object: bool,
    /// An object has more names than the probed names that reach it.
    pub(crate) outside_names: bool,
    /// The primary exists only under a non-canonical spelling of its name.
    pub(crate) non_canonical_primary: bool,
    pub(crate) not_local_ntfs: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhysicalSupport {
    Supported,
    Unsupported(PhysicalReason),
}

/// The first true physical flag, in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhysicalReason {
    NotPlainFile,
    DeletePending,
    SharedObject,
    OutsideNames,
    NonCanonicalPrimaryName,
    NotLocalNtfs,
}

/// Which exchange states the physical evidence is consistent with.
///
/// **Every variant is "consistent with", never proof, never permission.** None of them
/// identifies an old record, a new record, an order, a role or an owner; none says what
/// may be done; each has explanations that have nothing to do with an exchange. The
/// G12R-1 tests named below are the cases in which the experiment itself produced the
/// layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeCompatibility {
    /// Not assessed: newer or unrecognized evidence exists, or the physical evidence is
    /// unsupported. Nothing at all is claimed.
    NotAssessed,
    /// No record file and no `.tmp` entry, or a primary alone. Consistent with a
    /// store that was never exchanged, a completed and released exchange, or any
    /// other history.
    NoExchangeArtifacts,
    /// A valid primary and a distinct valid `.tmp` of the same binding. Consistent with
    /// R17a, R17f, R17c, R17e (same binding) and the R19 exit points before the
    /// retention rename, before verify and before release; also with a legacy replace
    /// interrupted before its rename, a manual copy, or anything else. Which of the two
    /// files is older is NOT determined, and the two layouts are physically identical.
    BeforeFirstRenameOrAfterSecondRename,
    /// No primary and two distinct valid `.tmp` entries of the same binding.
    /// Consistent with R17b, R17d and the R19 exit point between the renames; also with
    /// a primary that was removed by any other means. Which file would be restored,
    /// if any, is NOT determined.
    BetweenRenames,
    /// A valid primary beside an empty, partial, damaged or oversized `.tmp`.
    /// Consistent with an interrupted staging write or a legacy remnant.
    UnusableTempBesideRecord,
    /// An unusable primary beside a valid `.tmp`. Consistent with a damaged primary or
    /// a foreign file at the primary name.
    UnusablePrimaryBesideRecord,
    /// A valid record of another locator is present among the entries.
    OtherLocatorRecordPresent,
    /// Valid records of this locator with different bindings. Consistent with a
    /// foreign writer (R17e with a different binding) or unrelated copies.
    MixedBindings,
    /// Two or more distinct physical objects hold byte-identical, complete, valid
    /// version-1 records for this locator and binding (a primary and one `.tmp`, or
    /// two `.tmp` entries without a primary). This is NOT a G12R-1 exchange state,
    /// because that contract refuses identical old and new bytes. It is consistent
    /// with manual copies, a legacy replace of identical content interrupted before
    /// its rename, or an older binary. It implies no corruption, no unrelated binding
    /// and no ordering; neither record is preferred; it is never a basis for recovery;
    /// and it is distinct from [`PhysicalReason::SharedObject`], which is two names of
    /// one object.
    DuplicateRecords,
    /// The entries are all unusable, or the combination matches no layout the
    /// experiment produces.
    NoTestedExchangeState,
    /// Several `.tmp` entries: the pairing is ambiguous.
    AmbiguousPairing,
}

/// What is known about the history of the files. Exactly one variant, permanently.
/// Never add another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryStatus {
    NotEstablished,
}

// ---- 2. seams ---------------------------------------------------------------------

/// Fixed points of an assessment, for the test hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssessPoint {
    AfterDirectoryOpen,
    AfterFirstListing,
    /// While the first pass holds one entry's handle.
    EntryHeld,
    BetweenPasses,
    BeforeDirectoryRecheck,
}

/// A fault to inject. Injected faults prove decision logic only.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AssessFault {
    ListingFails,
    ListingIteratorFails {
        after: usize,
    },
    ListingOverLimit,
    /// Listed in both passes, as a persistent extra directory entry would be.
    ExtraListedName(OsString),
    SecondListingDiffers,
    OpenFails {
        nth: usize,
        kind: io::ErrorKind,
    },
    FactsFail {
        nth: usize,
    },
    ReadFails {
        nth: usize,
    },
    SecondReadDiffers {
        nth: usize,
    },
    DirectoryIdentityFails,
    VolumeNotNtfs,
}

#[derive(Default)]
struct AssessSeams {
    hook: Option<Box<dyn FnMut(AssessPoint)>>,
    fault: Option<AssessFault>,
}

impl AssessSeams {
    fn none() -> Self {
        Self::default()
    }

    fn on_point(mut self, hook: impl FnMut(AssessPoint) + 'static) -> Self {
        self.hook = Some(Box::new(hook));

        self
    }

    fn with_fault(mut self, fault: AssessFault) -> Self {
        self.fault = Some(fault);

        self
    }

    fn hit(&mut self, point: AssessPoint) {
        if let Some(hook) = self.hook.as_mut() {
            hook(point);
        }
    }

    fn fault(&self) -> Option<&AssessFault> {
        self.fault.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    First,
    Second,
}

// ---- 3. entry point ---------------------------------------------------------------

/// Assess the legacy sync-state directory of `store` for `locator`. Strictly
/// read-only. See the module documentation for everything this does not mean.
pub(crate) fn assess_legacy_layout(store: &SyncStateStore, locator: &Locator) -> LayoutReading {
    assess_with(store, locator, &mut AssessSeams::none())
}

fn assess_with(
    store: &SyncStateStore,
    locator: &Locator,
    seams: &mut AssessSeams,
) -> LayoutReading {
    let key = derive_key(locator);

    classify(&observe(store.directory(), &key, locator, seams))
}

/// The record key: lowercase hexadecimal SHA-256 of the ASCII-lowercased locator.
/// Duplicates the store's private derivation; a test cross-checks it against the file
/// name the store itself creates.
fn derive_key(locator: &Locator) -> String {
    EnvelopeFingerprint::of_bytes(locator.as_str().to_ascii_lowercase().as_bytes()).to_hex()
}

// ---- 4. names ---------------------------------------------------------------------

/// How a directory entry name relates to the record key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NameClass {
    Primary,
    Temp,
    Retired,
    ReservedStage,
    Unrecognized,
}

/// A related name. Sorted by class, then name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Related {
    class: NameClass,
    name: OsString,
    /// Only meaningful for `Primary`: the name is exactly `<key>.json`.
    canonical: bool,
}

/// The grammar of the legacy store and its gate, mirrored. A name is related iff its
/// lossy form starts with the key, ASCII case-insensitively. A match is an indication
/// only: it is not ownership, not authority and not permission.
fn classify_name(name: &OsStr, key: &str) -> Option<Related> {
    let lossy = name.to_string_lossy();
    let bytes = lossy.as_bytes();

    if bytes.len() < key.len() || !bytes[..key.len()].eq_ignore_ascii_case(key.as_bytes()) {
        return None;
    }

    let related = |class, canonical| {
        Some(Related {
            class,
            name: name.to_os_string(),
            canonical,
        })
    };

    if name.to_str().is_none()
        || name.encode_wide().take(MAX_NAME_UNITS + 1).count() > MAX_NAME_UNITS
    {
        return related(NameClass::Unrecognized, false);
    }

    let rest = &bytes[key.len()..];

    if rest.eq_ignore_ascii_case(b".json") {
        return related(NameClass::Primary, lossy == format!("{key}.json"));
    }

    match artifact_shape(rest) {
        Some(class) => related(class, false),
        None => related(NameClass::Unrecognized, false),
    }
}

/// `.<32 hex>.tmp`, `.<32 hex>.retired` or `.<32 hex>.v3stage`, either case.
fn artifact_shape(rest: &[u8]) -> Option<NameClass> {
    let rest = rest.strip_prefix(b".")?;

    if rest.len() <= TOKEN_LEN {
        return None;
    }

    let (token, tail) = rest.split_at(TOKEN_LEN);

    if !token.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }

    if tail.eq_ignore_ascii_case(b".tmp") {
        Some(NameClass::Temp)
    } else if tail.eq_ignore_ascii_case(b".retired") {
        Some(NameClass::Retired)
    } else if tail.eq_ignore_ascii_case(b".v3stage") {
        Some(NameClass::ReservedStage)
    } else {
        None
    }
}

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

// ---- 5. directory ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    Present,
    Absent,
}

/// Every existing ancestor must be a plain directory. A missing directory counts as
/// absent only if the nearest existing ancestor is a plain directory.
fn survey_path(directory: &Path) -> Result<Presence, ObservationProblem> {
    for ancestor in directory.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }

        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_plain_directory(&metadata) => {}
            Ok(_) => return Err(ObservationProblem::AncestorNotPlain),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(ObservationProblem::DirectoryUnreadable),
        }
    }

    match fs::symlink_metadata(directory) {
        Ok(metadata) if is_plain_directory(&metadata) => Ok(Presence::Present),
        Ok(_) => Err(ObservationProblem::DirectoryNotPlain),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            nearest_ancestor_is_plain(directory)
        }
        Err(_) => Err(ObservationProblem::DirectoryUnreadable),
    }
}

fn nearest_ancestor_is_plain(directory: &Path) -> Result<Presence, ObservationProblem> {
    let mut ancestor = directory.parent();

    while let Some(path) = ancestor {
        match fs::symlink_metadata(path) {
            Ok(metadata) if is_plain_directory(&metadata) => return Ok(Presence::Absent),
            Ok(_) => return Err(ObservationProblem::AncestorNotPlain),
            Err(error) if error.kind() == io::ErrorKind::NotFound => ancestor = path.parent(),
            Err(_) => return Err(ObservationProblem::DirectoryUnreadable),
        }
    }

    Err(ObservationProblem::DirectoryUnreadable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryOpen {
    Gone,
    Failed,
}

/// Read-only, full sharing, never following a reparse point. No access or share mode
/// is requested, so nothing is blocked and nothing can be changed.
fn open_directory(directory: &Path) -> Result<File, DirectoryOpen> {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                DirectoryOpen::Gone
            } else {
                DirectoryOpen::Failed
            }
        })
}

/// The handle must be a plain directory on a verified local NTFS volume with an
/// identity from the directory API (no fallback to file metadata).
fn judge_directory_handle(
    handle: &File,
    seams: &AssessSeams,
) -> Result<FileIdentity, ObservationProblem> {
    match handle.metadata() {
        Ok(metadata) if is_plain_directory(&metadata) => {}
        Ok(_) => return Err(ObservationProblem::DirectoryNotPlain),
        Err(_) => return Err(ObservationProblem::DirectoryUnreadable),
    }

    if seams.fault() == Some(&AssessFault::VolumeNotNtfs) {
        return Err(ObservationProblem::NotLocalNtfs);
    }

    match volume_facts_of(handle) {
        Ok(volume) if volume.is_local_ntfs() => {}
        Ok(_) => return Err(ObservationProblem::NotLocalNtfs),
        Err(_) => return Err(ObservationProblem::DirectoryIdentityUnavailable),
    }

    if seams.fault() == Some(&AssessFault::DirectoryIdentityFails) {
        return Err(ObservationProblem::DirectoryIdentityUnavailable);
    }

    directory_identity_of(handle).map_err(|_| ObservationProblem::DirectoryIdentityUnavailable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recheck {
    Same,
    Different,
    Problem(ObservationProblem),
}

/// The very handle of the first open and a fresh open of the path must both still be
/// the directory of the first open.
fn recheck_directory(directory: &Path, handle: &File, first: FileIdentity) -> Recheck {
    match directory_identity_of(handle) {
        Ok(identity) if identity == first => {}
        Ok(_) => return Recheck::Different,
        Err(_) => return Recheck::Problem(ObservationProblem::DirectoryIdentityUnavailable),
    }

    match open_directory(directory) {
        Ok(fresh) => match directory_identity_of(&fresh) {
            Ok(identity) if identity == first => Recheck::Same,
            Ok(_) => Recheck::Different,
            Err(_) => Recheck::Problem(ObservationProblem::DirectoryIdentityUnavailable),
        },
        Err(DirectoryOpen::Gone) => Recheck::Different,
        Err(DirectoryOpen::Failed) => Recheck::Problem(ObservationProblem::DirectoryUnreadable),
    }
}

// ---- 6. listing -------------------------------------------------------------------

/// One bounded pass over the directory, keeping only the entries related to `key`,
/// sorted. Aliases and the related-artifact limit are judged here.
fn list_related(
    directory: &Path,
    key: &str,
    seams: &AssessSeams,
    pass: Pass,
) -> Result<Vec<Related>, ObservationProblem> {
    let first = pass == Pass::First;

    if first && seams.fault() == Some(&AssessFault::ListingFails) {
        return Err(ObservationProblem::ListingFailed);
    }

    let entries = fs::read_dir(directory).map_err(|_| ObservationProblem::ListingFailed)?;
    let limit = if first && seams.fault() == Some(&AssessFault::ListingOverLimit) {
        0
    } else {
        MAX_LISTED_ENTRIES
    };

    let mut related = Vec::new();
    let mut seen = 0usize;

    for entry in entries {
        if first {
            if let Some(AssessFault::ListingIteratorFails { after }) = seams.fault() {
                if seen == *after {
                    return Err(ObservationProblem::ListingIncomplete);
                }
            }
        }

        seen += 1;

        if seen > limit {
            return Err(ObservationProblem::EntryLimit);
        }

        let name = entry
            .map_err(|_| ObservationProblem::ListingIncomplete)?
            .file_name();

        related.extend(classify_name(&name, key));
    }

    if let Some(AssessFault::ExtraListedName(name)) = seams.fault() {
        related.extend(classify_name(name, key));
    }

    if !first && seams.fault() == Some(&AssessFault::SecondListingDiffers) {
        related.extend(classify_name(
            OsStr::new(&format!("{key}.second-listing")),
            key,
        ));
    }

    related.sort();

    let mut folded: Vec<String> = related
        .iter()
        .map(|entry| entry.name.to_string_lossy().to_ascii_lowercase())
        .collect();

    folded.sort();

    if folded.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ObservationProblem::AliasAmbiguity);
    }

    let artifacts = related
        .iter()
        .filter(|entry| {
            matches!(
                entry.class,
                NameClass::Temp | NameClass::Retired | NameClass::ReservedStage
            )
        })
        .count();

    if artifacts > MAX_RELATED_ARTIFACTS {
        return Err(ObservationProblem::RelatedEntryLimit);
    }

    Ok(related)
}

// ---- 7. entries -------------------------------------------------------------------

/// What one probed entry looked like, judged. Held in memory only.
#[derive(Clone)]
struct Seen {
    finding: EntryFinding,
    identity: Option<FileIdentity>,
    links: u32,
    length: u64,
    /// SHA-256 of the complete bytes. `None` when the complete bytes were not read.
    digest: Option<EnvelopeFingerprint>,
    not_local_ntfs: bool,
    /// The decoded record, for `V1ForLocator` only.
    state: Option<SyncState>,
}

impl Seen {
    fn not_plain() -> Self {
        Self {
            finding: EntryFinding::NotPlainFile,
            identity: None,
            links: 0,
            length: 0,
            digest: None,
            not_local_ntfs: false,
            state: None,
        }
    }

    /// The comparison between the two passes. The decoded record is a function of the
    /// digest and is not compared separately.
    fn same_observation(&self, other: &Self) -> bool {
        self.finding == other.finding
            && self.identity == other.identity
            && self.links == other.links
            && self.length == other.length
            && self.digest == other.digest
            && self.not_local_ntfs == other.not_local_ntfs
    }
}

/// The bytes of one entry as far as they were read.
#[derive(Clone, PartialEq, Eq)]
enum Content {
    Empty,
    /// More than the supported maximum; only the bound was read.
    TooLarge,
    Within(Vec<u8>),
}

/// Everything the judgement looks at, gathered from one handle.
struct RawEntry {
    facts: HandleFacts,
    length: u64,
    content: Content,
}

/// The pure judgement of one entry.
fn judge_entry(raw: &RawEntry, locator: &Locator) -> Seen {
    let seen = |finding, digest, state| Seen {
        finding,
        identity: Some(raw.facts.identity()),
        links: raw.facts.link_count(),
        length: raw.length,
        digest,
        not_local_ntfs: !raw.facts.is_local_ntfs(),
        state,
    };

    if raw.facts.is_delete_pending() {
        return seen(EntryFinding::DeletePending, None, None);
    }

    match &raw.content {
        Content::Empty => seen(
            EntryFinding::Empty,
            Some(EnvelopeFingerprint::of_bytes(&[])),
            None,
        ),
        Content::TooLarge => seen(EntryFinding::TooLarge, None, None),
        Content::Within(bytes) => {
            let digest = Some(EnvelopeFingerprint::of_bytes(bytes));

            match SyncStateLoad::from_bytes(bytes) {
                SyncStateLoad::Loaded(state)
                    if path_identity_eq(state.local_locator().as_str(), locator.as_str()) =>
                {
                    seen(EntryFinding::V1ForLocator, digest, Some(*state))
                }
                SyncStateLoad::Loaded(_) => seen(EntryFinding::V1OtherLocator, digest, None),
                SyncStateLoad::UnsupportedVersion => {
                    seen(EntryFinding::UnsupportedVersion, digest, None)
                }
                _ => seen(EntryFinding::Corrupt, digest, None),
            }
        }
    }
}

/// What probing one name gave.
enum Probe {
    Vanished,
    Refused,
    Unreadable,
    Uncertain,
    /// The handle's own facts changed while it was held.
    Changed,
    Seen(Box<Seen>),
}

fn refusal_of(error: &io::Error) -> Probe {
    if error.kind() == io::ErrorKind::NotFound {
        Probe::Vanished
    } else if error.kind() == io::ErrorKind::PermissionDenied
        || error.raw_os_error() == Some(SHARING_VIOLATION)
    {
        Probe::Refused
    } else {
        Probe::Unreadable
    }
}

/// Read at most the supported maximum plus one byte through the held handle.
fn read_content(file: &File) -> Result<(Content, u64), ()> {
    let reader: &File = file;
    let mut bytes = Vec::new();

    reader
        .take(MAX_SYNC_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;

    if bytes.is_empty() {
        Ok((Content::Empty, 0))
    } else if bytes.len() > MAX_SYNC_STATE_BYTES {
        let length = file
            .metadata()
            .map_or(bytes.len() as u64, |metadata| metadata.len());

        Ok((Content::TooLarge, length.max(bytes.len() as u64)))
    } else {
        let length = bytes.len() as u64;

        Ok((Content::Within(bytes), length))
    }
}

/// Probe one name: judge the path, open read-only with full sharing and no reparse
/// follow, judge the handle, read through that same handle, check the handle's facts
/// again and close it.
fn probe(
    directory: &Path,
    name: &OsStr,
    locator: &Locator,
    seams: &mut AssessSeams,
    pass: Pass,
    nth: usize,
) -> Probe {
    let path = directory.join(name);

    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Probe::Vanished,
        Err(_) => return Probe::Unreadable,
        Ok(metadata) if !is_plain_file(&metadata) => {
            return Probe::Seen(Box::new(Seen::not_plain()))
        }
        Ok(_) => {}
    }

    // Persistent: the same fault in both passes, as a real refusal would be.
    if let Some(AssessFault::OpenFails { nth: at, kind }) = seams.fault() {
        if *at == nth {
            return refusal_of(&io::Error::from(*kind));
        }
    }

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) => return refusal_of(&error),
    };

    match file.metadata() {
        Ok(metadata) if is_plain_file(&metadata) => {}
        Ok(_) => return Probe::Seen(Box::new(Seen::not_plain())),
        Err(_) => return Probe::Unreadable,
    }

    let facts = if seams.fault() == Some(&AssessFault::FactsFail { nth }) {
        None
    } else {
        facts_of(&file).ok()
    };

    let Some(facts) = facts else {
        return Probe::Uncertain;
    };

    if pass == Pass::First {
        seams.hit(AssessPoint::EntryHeld);
    }

    let read = if seams.fault() == Some(&AssessFault::ReadFails { nth }) {
        Err(())
    } else {
        read_content(&file)
    };

    let Ok((mut content, length)) = read else {
        return Probe::Unreadable;
    };

    if pass == Pass::Second && seams.fault() == Some(&AssessFault::SecondReadDiffers { nth }) {
        content = match content {
            Content::Within(mut bytes) => {
                bytes.push(0);

                Content::Within(bytes)
            }
            Content::Empty | Content::TooLarge => Content::Within(vec![0]),
        };
    }

    match facts_of(&file) {
        Ok(again) if again == facts => {}
        Ok(_) => return Probe::Changed,
        Err(_) => return Probe::Uncertain,
    }

    drop(file);

    Probe::Seen(Box::new(judge_entry(
        &RawEntry {
            facts,
            length,
            content,
        },
        locator,
    )))
}

fn is_probed(entry: &&Related) -> bool {
    matches!(entry.class, NameClass::Primary | NameClass::Temp)
}

/// Probe the primary and every `.tmp`, in the sorted order of the listing. Retired,
/// reserved-stage and unrecognized names are never opened.
fn probe_all(
    directory: &Path,
    names: &[Related],
    locator: &Locator,
    seams: &mut AssessSeams,
    pass: Pass,
) -> Vec<Probe> {
    names
        .iter()
        .filter(is_probed)
        .enumerate()
        .map(|(nth, entry)| probe(directory, &entry.name, locator, seams, pass, nth))
        .collect()
}

// ---- 8. the observation (gathered) and its pure judgement ----------------------------

/// Everything gathered, before any conclusion. `classify` is pure.
struct Observation {
    unobservable: Option<ObservationProblem>,
    no_directory: bool,
    changed: bool,
    incomplete: Option<EntryProblem>,
    foreign: ForeignNames,
    non_canonical_primary: bool,
    primary: Option<Seen>,
    temps: Vec<Seen>,
}

impl Observation {
    fn new() -> Self {
        Self {
            unobservable: None,
            no_directory: false,
            changed: false,
            incomplete: None,
            foreign: ForeignNames::default(),
            non_canonical_primary: false,
            primary: None,
            temps: Vec::new(),
        }
    }
}

fn observe(directory: &Path, key: &str, locator: &Locator, seams: &mut AssessSeams) -> Observation {
    let mut observation = Observation::new();

    match survey_path(directory) {
        Err(problem) => {
            observation.unobservable = Some(problem);

            return observation;
        }
        Ok(Presence::Absent) => {
            // Confirmed again at the end.
            match survey_path(directory) {
                Ok(Presence::Absent) => observation.no_directory = true,
                Ok(Presence::Present) => observation.changed = true,
                Err(problem) => observation.unobservable = Some(problem),
            }

            return observation;
        }
        Ok(Presence::Present) => {}
    }

    let handle = match open_directory(directory) {
        Ok(handle) => handle,
        Err(DirectoryOpen::Gone) => {
            observation.changed = true;

            return observation;
        }
        Err(DirectoryOpen::Failed) => {
            observation.unobservable = Some(ObservationProblem::DirectoryUnreadable);

            return observation;
        }
    };

    let first_identity = match judge_directory_handle(&handle, seams) {
        Ok(identity) => identity,
        Err(problem) => {
            observation.unobservable = Some(problem);

            return observation;
        }
    };

    seams.hit(AssessPoint::AfterDirectoryOpen);

    let first_names = match list_related(directory, key, seams, Pass::First) {
        Ok(names) => names,
        Err(problem) => {
            observation.unobservable = Some(problem);

            return observation;
        }
    };

    seams.hit(AssessPoint::AfterFirstListing);

    let first_probes = probe_all(directory, &first_names, locator, seams, Pass::First);

    seams.hit(AssessPoint::BetweenPasses);

    let second_names = match list_related(directory, key, seams, Pass::Second) {
        Ok(names) => names,
        Err(problem) => {
            observation.unobservable = Some(problem);

            return observation;
        }
    };

    let second_probes = (second_names == first_names)
        .then(|| probe_all(directory, &second_names, locator, seams, Pass::Second));

    seams.hit(AssessPoint::BeforeDirectoryRecheck);

    match recheck_directory(directory, &handle, first_identity) {
        Recheck::Same => {}
        Recheck::Different => observation.changed = true,
        Recheck::Problem(problem) => {
            observation.unobservable = Some(problem);

            return observation;
        }
    }

    let Some(second_probes) = second_probes else {
        observation.changed = true;

        return observation;
    };

    let mut incomplete = None;

    for (one, two) in first_probes.iter().zip(&second_probes) {
        match (one, two) {
            (Probe::Refused, Probe::Refused) => {
                incomplete.get_or_insert(EntryProblem::OpenRefused);
            }
            (Probe::Unreadable, Probe::Unreadable) => {
                incomplete.get_or_insert(EntryProblem::Unreadable);
            }
            (Probe::Uncertain, Probe::Uncertain) => {
                incomplete.get_or_insert(EntryProblem::IdentityUncertain);
            }
            (Probe::Seen(a), Probe::Seen(b)) if a.same_observation(b) => {}
            _ => observation.changed = true,
        }
    }

    if observation.changed {
        return observation;
    }

    if incomplete.is_some() {
        observation.incomplete = incomplete;

        return observation;
    }

    for entry in &first_names {
        match entry.class {
            NameClass::Retired => observation.foreign.retired = true,
            NameClass::ReservedStage => observation.foreign.reserved_stage = true,
            NameClass::Unrecognized => observation.foreign.unrecognized = true,
            NameClass::Primary => observation.non_canonical_primary = !entry.canonical,
            NameClass::Temp => {}
        }
    }

    for (entry, probed) in first_names.iter().filter(is_probed).zip(first_probes) {
        let Probe::Seen(seen) = probed else {
            // Every non-`Seen` probe was handled above; fail closed regardless.
            observation.changed = true;

            return observation;
        };

        if entry.class == NameClass::Primary {
            observation.primary = Some(*seen);
        } else {
            observation.temps.push(*seen);
        }
    }

    observation
}

/// The pure precedence: unobservable, then no directory, then changed, then
/// incomplete, then observed.
fn classify(observation: &Observation) -> LayoutReading {
    if let Some(problem) = observation.unobservable {
        LayoutReading::Unobservable(problem)
    } else if observation.no_directory {
        LayoutReading::NoDirectory
    } else if observation.changed {
        LayoutReading::ChangedDuringAssessment
    } else if let Some(problem) = observation.incomplete {
        LayoutReading::Incomplete(problem)
    } else {
        LayoutReading::Observed(report_of(observation))
    }
}

fn count(value: usize) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

fn layout_of(primary_listed: bool, temps: usize) -> RecordLayout {
    match (primary_listed, temps) {
        (false, 0) => RecordLayout::NoRecordFiles,
        (true, 0) => RecordLayout::PrimaryOnly,
        (true, 1) => RecordLayout::PrimaryAndOneTemp,
        (true, _) => RecordLayout::PrimaryAndSeveralTemps,
        (false, 1) => RecordLayout::NoPrimaryOneTemp,
        (false, 2) => RecordLayout::NoPrimaryTwoTemps,
        (false, _) => RecordLayout::NoPrimarySeveralTemps,
    }
}

fn temp_findings(temps: &[Seen]) -> TempFindings {
    let mut found = TempFindings {
        total: count(temps.len()),
        ..TempFindings::default()
    };

    for temp in temps {
        let slot = match temp.finding {
            EntryFinding::Absent => continue,
            EntryFinding::NotPlainFile => &mut found.not_plain,
            EntryFinding::DeletePending => &mut found.delete_pending,
            EntryFinding::Empty => &mut found.empty,
            EntryFinding::TooLarge => &mut found.too_large,
            EntryFinding::Corrupt => &mut found.corrupt,
            EntryFinding::UnsupportedVersion => &mut found.unsupported_version,
            EntryFinding::V1OtherLocator => &mut found.v1_other_locator,
            EntryFinding::V1ForLocator => &mut found.v1_for_locator,
        };

        *slot = slot.saturating_add(1);
    }

    found
}

fn same_binding(a: &SyncState, b: &SyncState) -> bool {
    a.binding_id() == b.binding_id()
        && a.vault_tag() == b.vault_tag()
        && a.local_locator() == b.local_locator()
        && a.target_locator() == b.target_locator()
}

/// Over the given valid records only. No ordering, no high-water, no revision, no
/// base and no pending-push comparison of any kind.
fn binding_relation(states: &[&SyncState]) -> BindingRelation {
    match states {
        [] => BindingRelation::NoValidRecords,
        [_] => BindingRelation::Single,
        [first, rest @ ..] => {
            if rest.iter().all(|other| same_binding(first, other)) {
                BindingRelation::AllSame
            } else {
                BindingRelation::Differ
            }
        }
    }
}

fn duplicate_findings(entries: &[&Seen]) -> DuplicateFindings {
    let mut found = DuplicateFindings::default();

    for (index, one) in entries.iter().enumerate() {
        for two in &entries[index + 1..] {
            let (Some(a), Some(b)) = (one.digest, two.digest) else {
                continue;
            };

            // Equal bytes in ONE object (two names) are a shared object, not a duplicate.
            if a != b || one.identity == two.identity {
                continue;
            }

            match (
                one.finding == EntryFinding::V1ForLocator,
                two.finding == EntryFinding::V1ForLocator,
            ) {
                (true, true) => found.valid_records = true,
                (false, false) => found.other_content = true,
                (true, false) | (false, true) => {}
            }
        }
    }

    found
}

fn physical_findings(entries: &[&Seen], non_canonical_primary: bool) -> PhysicalFindings {
    let mut found = PhysicalFindings {
        non_canonical_primary,
        ..PhysicalFindings::default()
    };

    for one in entries {
        found.not_plain |= one.finding == EntryFinding::NotPlainFile;
        found.delete_pending |= one.finding == EntryFinding::DeletePending;
        found.not_local_ntfs |= one.not_local_ntfs;

        let Some(identity) = one.identity else {
            continue;
        };

        let names = entries
            .iter()
            .filter(|other| other.identity == Some(identity))
            .count();

        found.shared_object |= names > 1;
        found.outside_names |= u64::from(one.links) > names as u64;
    }

    found
}

fn support_of(found: &PhysicalFindings) -> PhysicalSupport {
    let reason = if found.not_plain {
        PhysicalReason::NotPlainFile
    } else if found.delete_pending {
        PhysicalReason::DeletePending
    } else if found.shared_object {
        PhysicalReason::SharedObject
    } else if found.outside_names {
        PhysicalReason::OutsideNames
    } else if found.non_canonical_primary {
        PhysicalReason::NonCanonicalPrimaryName
    } else if found.not_local_ntfs {
        PhysicalReason::NotLocalNtfs
    } else {
        return PhysicalSupport::Supported;
    };

    PhysicalSupport::Unsupported(reason)
}

fn gate_of(foreign: &ForeignNames, temps: &TempFindings) -> GateObservation {
    if foreign.retired
        || foreign.reserved_stage
        || foreign.unrecognized
        || temps.unsupported_version > 0
    {
        GateObservation::NewerOrUnrecognizedEvidence
    } else {
        GateObservation::NoGateEvidence
    }
}

/// The inputs of the compatibility table: a pure function of these values only, so the
/// table can be checked exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summary {
    layout: RecordLayout,
    primary: EntryFinding,
    temps: TempFindings,
    binding: BindingRelation,
    duplicates: DuplicateFindings,
    gate: GateObservation,
    support: PhysicalSupport,
}

fn report_of(observation: &Observation) -> LayoutReport {
    let primary = observation.primary.as_ref();
    let entries: Vec<&Seen> = primary.into_iter().chain(&observation.temps).collect();
    let states: Vec<&SyncState> = entries
        .iter()
        .filter_map(|entry| entry.state.as_ref())
        .collect();

    let primary_finding = primary.map_or(EntryFinding::Absent, |entry| entry.finding);
    let temps = temp_findings(&observation.temps);
    let physical = physical_findings(&entries, observation.non_canonical_primary);
    let summary = Summary {
        layout: layout_of(primary.is_some(), observation.temps.len()),
        primary: primary_finding,
        temps,
        binding: binding_relation(&states),
        duplicates: duplicate_findings(&entries),
        gate: gate_of(&observation.foreign, &temps),
        support: support_of(&physical),
    };

    LayoutReport {
        layout: summary.layout,
        primary: summary.primary,
        temps: summary.temps,
        binding: summary.binding,
        duplicates: summary.duplicates,
        gate: summary.gate,
        foreign: observation.foreign,
        physical,
        support: summary.support,
        compatibility: compatibility(&summary),
        history: HistoryStatus::NotEstablished,
    }
}

// ---- 9. the compatibility table (pure) ----------------------------------------------

fn is_usable(finding: EntryFinding) -> bool {
    finding == EntryFinding::V1ForLocator
}

fn is_unusable(finding: EntryFinding) -> bool {
    matches!(
        finding,
        EntryFinding::Empty
            | EntryFinding::TooLarge
            | EntryFinding::Corrupt
            | EntryFinding::UnsupportedVersion
    )
}

/// The finding of the only temp, if the counts describe exactly one.
fn only_temp(temps: &TempFindings) -> Option<EntryFinding> {
    let all = temps_in_order(temps);

    match all.as_slice() {
        [one] if temps.total == 1 => Some(*one),
        _ => None,
    }
}

/// The findings of the only two temps, if the counts describe exactly two.
fn two_temps(temps: &TempFindings) -> Option<(EntryFinding, EntryFinding)> {
    let all = temps_in_order(temps);

    match all.as_slice() {
        [one, two] if temps.total == 2 => Some((*one, *two)),
        _ => None,
    }
}

/// The counted findings, expanded in a fixed order. Order carries no meaning.
fn temps_in_order(temps: &TempFindings) -> Vec<EntryFinding> {
    let counted = [
        (EntryFinding::NotPlainFile, temps.not_plain),
        (EntryFinding::DeletePending, temps.delete_pending),
        (EntryFinding::Empty, temps.empty),
        (EntryFinding::TooLarge, temps.too_large),
        (EntryFinding::Corrupt, temps.corrupt),
        (EntryFinding::UnsupportedVersion, temps.unsupported_version),
        (EntryFinding::V1OtherLocator, temps.v1_other_locator),
        (EntryFinding::V1ForLocator, temps.v1_for_locator),
    ];

    counted
        .into_iter()
        .flat_map(|(finding, number)| std::iter::repeat_n(finding, usize::from(number)))
        .collect()
}

/// Two usable records: the binding and the duplicate flag decide.
fn both_usable(summary: &Summary, same: ExchangeCompatibility) -> ExchangeCompatibility {
    match summary.binding {
        BindingRelation::Differ => ExchangeCompatibility::MixedBindings,
        BindingRelation::AllSame if summary.duplicates.valid_records => {
            ExchangeCompatibility::DuplicateRecords
        }
        BindingRelation::AllSame => same,
        // Not reachable from a real observation: two usable entries have two records.
        BindingRelation::NoValidRecords | BindingRelation::Single => {
            ExchangeCompatibility::NoTestedExchangeState
        }
    }
}

/// G1 gate evidence and G2 unsupported physical evidence come first; G3 is the table.
/// Every row is explicit. An input that matches no row is `NoTestedExchangeState`.
fn compatibility(summary: &Summary) -> ExchangeCompatibility {
    use ExchangeCompatibility as Compatibility;

    if summary.gate == GateObservation::NewerOrUnrecognizedEvidence {
        return Compatibility::NotAssessed;
    }

    if matches!(summary.support, PhysicalSupport::Unsupported(_)) {
        return Compatibility::NotAssessed;
    }

    // A layout that does not match the counts is not a real observation.
    if layout_of(
        summary.primary != EntryFinding::Absent,
        usize::from(summary.temps.total),
    ) != summary.layout
    {
        return Compatibility::NoTestedExchangeState;
    }

    match summary.layout {
        RecordLayout::NoRecordFiles | RecordLayout::PrimaryOnly => {
            Compatibility::NoExchangeArtifacts
        }
        RecordLayout::PrimaryAndOneTemp => {
            let Some(temp) = only_temp(&summary.temps) else {
                return Compatibility::NoTestedExchangeState;
            };
            let primary = summary.primary;

            if primary == EntryFinding::V1OtherLocator || temp == EntryFinding::V1OtherLocator {
                Compatibility::OtherLocatorRecordPresent
            } else if is_usable(primary) && is_unusable(temp) {
                Compatibility::UnusableTempBesideRecord
            } else if is_unusable(primary) && is_usable(temp) {
                Compatibility::UnusablePrimaryBesideRecord
            } else if is_unusable(primary) && is_unusable(temp) {
                Compatibility::NoTestedExchangeState
            } else if is_usable(primary) && is_usable(temp) {
                both_usable(summary, Compatibility::BeforeFirstRenameOrAfterSecondRename)
            } else {
                Compatibility::NoTestedExchangeState
            }
        }
        RecordLayout::NoPrimaryOneTemp => match only_temp(&summary.temps) {
            Some(EntryFinding::V1OtherLocator) => Compatibility::OtherLocatorRecordPresent,
            Some(_) | None => Compatibility::NoTestedExchangeState,
        },
        RecordLayout::NoPrimaryTwoTemps => {
            let Some((one, two)) = two_temps(&summary.temps) else {
                return Compatibility::NoTestedExchangeState;
            };

            if one == EntryFinding::V1OtherLocator || two == EntryFinding::V1OtherLocator {
                Compatibility::OtherLocatorRecordPresent
            } else if is_unusable(one) || is_unusable(two) {
                Compatibility::NoTestedExchangeState
            } else if is_usable(one) && is_usable(two) {
                both_usable(summary, Compatibility::BetweenRenames)
            } else {
                Compatibility::NoTestedExchangeState
            }
        }
        RecordLayout::PrimaryAndSeveralTemps | RecordLayout::NoPrimarySeveralTemps => {
            Compatibility::AmbiguousPairing
        }
    }
}

// ---- tests ----

// Evidence labels used by every test below:
//
//   REAL NTFS            real files, handles and renames on D: (local NTFS).
//   CONTROLLED ACTOR     a real test-controlled operation performed inside a seam hook
//                        (Contract B).
//   INJECTED             decision logic driven by an injected fault or fact; the rest of
//                        the filesystem is real. Says nothing about what NTFS does.
//   PURE                 no filesystem effect.
//   SYNTHESIZED-FROM-R19 layouts rebuilt by hand from the end states R19 asserts. The
//                        real-process-exit suite was NOT re-run here.
//   UNAVAILABLE          not measurable by an ordinary test and NOT faked: a file
//                        symlink when the account cannot create one, Windows shutdown,
//                        OS crash, power loss, persistence order, directory
//                        durability, the C: AppData volume, ReFS/SMB/FAT, 8.3 short
//                        names, case-sensitive directories, privileged and
//                        filter-driver actors.
//
// Contract A (no actor): the snapshot before equals the snapshot after.
// Contract B (a controlled actor): the classifier causes no mutation beyond the
// actor's one logged operation.

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::PathBuf, rc::Rc};

    use localvault_core::{
        sync::{PushBaseline, PushIntent, RemoteHighWater},
        sync_state::{
            BindingId, PendingPush, SyncBase, SyncCheckpoint, VaultBindingTag, BINDING_SALT_LEN,
        },
    };
    use uuid::Uuid;

    use super::*;
    use crate::vault::{
        file_identity::FileSystemKind,
        handle_ops::{
            self,
            test_support::{assert_local_ntfs, make_junction},
        },
        legacy_record_exchange as exchange,
        sync_state_store::{CorruptReason, StateLoad, UnreadableReason, SYNC_STATE_DIRECTORY},
    };

    const LOCAL: &str = r"\\?\C:\Synthetic\Vaults\LOCAL-MARKER.lvault";
    const OTHER_LOCAL: &str = r"\\?\C:\Synthetic\Vaults\OTHER-MARKER.lvault";
    const TARGET: &str = r"\\?\D:\Synthetic\Remote\TARGET-MARKER.lvault";
    const OTHER_TARGET: &str = r"\\?\D:\Synthetic\Remote\OTHER-TARGET-MARKER.lvault";
    const BINDING: u128 = 0x1111_1111_2222_3333_4444_5555_5555_5555;
    const OTHER_BINDING: u128 = 0x2222_2222_3333_4444_5555_6666_6666_6666;
    const VAULT: u128 = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef;
    const OTHER_VAULT: u128 = 0xfedc_ba98_7654_3210_fedc_ba98_7654_3210;

    // ---- synthetic states -------------------------------------------------------------

    fn loc(value: &str) -> Locator {
        Locator::new(value).unwrap()
    }

    fn fp(tag: u8) -> EnvelopeFingerprint {
        EnvelopeFingerprint::of_bytes(&[tag])
    }

    fn pending(revision: u64) -> PendingPush {
        let intent = PushIntent::new(PushBaseline::Absent, fp(2)).unwrap();

        PendingPush::new(
            Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee),
            intent,
            revision,
        )
        .unwrap()
    }

    fn build(
        local: &str,
        target: &str,
        binding: u128,
        vault: u128,
        base: SyncBase,
        pending: Option<PendingPush>,
    ) -> SyncState {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);

        SyncState::new(
            BindingId::new(Uuid::from_u128(binding)).unwrap(),
            VaultBindingTag::derive(salt, Uuid::from_u128(vault)).unwrap(),
            loc(local),
            loc(target),
            base,
            pending,
        )
        .unwrap()
    }

    fn state_with(
        local: &str,
        target: &str,
        binding: u128,
        vault: u128,
        revision: u64,
    ) -> SyncState {
        build(
            local,
            target,
            binding,
            vault,
            SyncBase::Unbased,
            Some(pending(revision)),
        )
    }

    /// The synthetic record of `LOCAL` at write counter `revision`.
    fn rev(revision: u64) -> SyncState {
        state_with(LOCAL, TARGET, BINDING, VAULT, revision)
    }

    fn bytes_of(revision: u64) -> Vec<u8> {
        rev(revision).encode().unwrap()
    }

    /// A record of `LOCAL` under another binding id.
    fn other_binding(revision: u64) -> SyncState {
        state_with(LOCAL, TARGET, OTHER_BINDING, VAULT, revision)
    }

    /// A valid record whose local locator is another locator.
    fn other_locator(revision: u64) -> SyncState {
        state_with(OTHER_LOCAL, TARGET, BINDING, VAULT, revision)
    }

    /// A record of `LOCAL`, same binding, with a trusted high-water mark.
    fn with_high_water(high_water: u64) -> SyncState {
        build(
            LOCAL,
            TARGET,
            BINDING,
            VAULT,
            SyncBase::Based(
                SyncCheckpoint::new(fp(1), 1, RemoteHighWater::new(high_water)).unwrap(),
            ),
            None,
        )
    }

    fn half(bytes: &[u8]) -> Vec<u8> {
        bytes[..bytes.len() / 2].to_vec()
    }

    /// One byte of the body changed: a complete-looking record that does not decode.
    fn damaged(bytes: &[u8]) -> Vec<u8> {
        let mut damaged = bytes.to_vec();
        let middle = damaged.len() / 2;

        damaged[middle] ^= 0x01;

        assert_eq!(
            SyncStateLoad::from_bytes(&damaged),
            SyncStateLoad::Corrupt,
            "the damaged record must decode as corrupt"
        );

        damaged
    }

    // ---- scratch and fixtures ---------------------------------------------------------

    fn scratch_base() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("legacy-layout-assessment-tests")
    }

    /// A unique, test-owned directory under the dedicated G12R-R1 scratch base. Removed
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

    struct Fx {
        scratch: tempfile::TempDir,
        locator: Locator,
        /// The root handed to the store; the scratch root unless a test says otherwise.
        store_root: PathBuf,
    }

    impl Fx {
        /// A scratch root without a `sync-state` directory.
        fn bare(name: &str) -> Self {
            let scratch = scratch(name);
            let store_root = scratch.path().to_path_buf();

            Self {
                scratch,
                locator: loc(LOCAL),
                store_root,
            }
        }

        /// A scratch root whose store holds `state`, created by the public store API.
        fn with_state(name: &str, state: &SyncState) -> Self {
            let fx = Self::bare(name);

            fx.store().create(state).unwrap();

            fx
        }

        fn root(&self) -> &Path {
            self.scratch.path()
        }

        fn dir(&self) -> PathBuf {
            self.store_root.join(SYNC_STATE_DIRECTORY)
        }

        fn key(&self) -> String {
            exchange::exchange_key(&self.locator)
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(&self.store_root).unwrap()
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

        fn temp_leaf(&self) -> String {
            format!("{}.{}.tmp", self.key(), Uuid::new_v4().simple())
        }

        fn put(&self, leaf: &str, bytes: &[u8]) -> PathBuf {
            fs::create_dir_all(self.dir()).unwrap();

            let path = self.dir().join(leaf);

            fs::write(&path, bytes).unwrap();

            path
        }

        fn put_primary(&self, bytes: &[u8]) -> PathBuf {
            self.put(&self.primary_leaf(), bytes)
        }

        /// A new `.tmp` entry with a fresh random token.
        fn add_temp(&self, bytes: &[u8]) -> PathBuf {
            self.put(&self.temp_leaf(), bytes)
        }

        fn assess(&self) -> LayoutReading {
            assess_legacy_layout(&self.store(), &self.locator)
        }
    }

    // ---- snapshots -------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Kind {
        File,
        Directory,
        Reparse,
    }

    /// One entry of a snapshot: name, kind, length, SHA-256, physical identity and
    /// link count.
    #[derive(Debug, Clone, PartialEq)]
    struct Entry {
        path: String,
        kind: Kind,
        len: u64,
        digest: Option<String>,
        identity: Option<FileIdentity>,
        links: u32,
    }

    type Snapshot = Vec<Entry>;

    fn digest_hex(bytes: &[u8]) -> String {
        EnvelopeFingerprint::of_bytes(bytes).to_hex()
    }

    /// Every entry beneath `root`, sorted, never following a reparse point, using only
    /// full-sharing read opens.
    fn snapshot(root: &Path) -> Snapshot {
        fn walk(dir: &Path, base: &Path, out: &mut Snapshot) {
            let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();

            entries.sort_by_key(|entry| entry.file_name());

            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let relative = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");

                if is_reparse(&metadata) {
                    out.push(Entry {
                        path: relative,
                        kind: Kind::Reparse,
                        len: 0,
                        digest: None,
                        identity: None,
                        links: 0,
                    });
                } else if metadata.is_dir() {
                    let identity = open_directory(&path)
                        .ok()
                        .and_then(|handle| directory_identity_of(&handle).ok());

                    out.push(Entry {
                        path: relative,
                        kind: Kind::Directory,
                        len: 0,
                        digest: None,
                        identity,
                        links: 0,
                    });
                    walk(&path, base, out);
                } else {
                    let file = OpenOptions::new()
                        .read(true)
                        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                        .open(&path)
                        .unwrap();
                    let facts = facts_of(&file).unwrap();
                    let mut bytes = Vec::new();

                    (&file).read_to_end(&mut bytes).unwrap();

                    out.push(Entry {
                        path: relative,
                        kind: Kind::File,
                        len: bytes.len() as u64,
                        digest: Some(digest_hex(&bytes)),
                        identity: Some(facts.identity()),
                        links: facts.link_count(),
                    });
                }
            }
        }

        let mut out = Vec::new();

        walk(root, root, &mut out);

        out
    }

    fn rel(leaf: &str) -> String {
        format!("{SYNC_STATE_DIRECTORY}/{leaf}")
    }

    fn find<'a>(snapshot: &'a [Entry], path: &str) -> Option<&'a Entry> {
        snapshot.iter().find(|entry| entry.path == path)
    }

    fn without(snapshot: &[Entry], skip: &[&str]) -> Snapshot {
        snapshot
            .iter()
            .filter(|entry| !skip.contains(&entry.path.as_str()))
            .cloned()
            .collect()
    }

    /// (path, digest) of every file entry: names and bytes, no identity.
    fn file_set(snapshot: &[Entry]) -> Vec<(String, Option<String>)> {
        snapshot
            .iter()
            .filter(|entry| entry.kind == Kind::File)
            .map(|entry| (entry.path.clone(), entry.digest.clone()))
            .collect()
    }

    // ---- reading helpers --------------------------------------------------------------

    fn report(reading: LayoutReading) -> LayoutReport {
        match reading {
            LayoutReading::Observed(report) => report,
            other => panic!("expected Observed, got {other:?}"),
        }
    }

    fn describe(reading: &LayoutReading) -> String {
        match reading {
            LayoutReading::Observed(r) => format!(
                "Observed(layout={:?} primary={:?} temps={:?} binding={:?} duplicates={:?} gate={:?} support={:?} compatibility={:?} history={:?})",
                r.layout, r.primary, r.temps, r.binding, r.duplicates, r.gate, r.support, r.compatibility, r.history
            ),
            other => format!("{other:?}"),
        }
    }

    fn assert_shape(
        report: &LayoutReport,
        layout: RecordLayout,
        primary: EntryFinding,
        compatibility: ExchangeCompatibility,
    ) {
        assert_eq!(report.layout, layout, "layout");
        assert_eq!(report.primary, primary, "primary");
        assert_eq!(report.compatibility, compatibility, "compatibility");
        assert_eq!(report.history, HistoryStatus::NotEstablished);
    }

    /// The category-specific consistency mapping between a reading and the unchanged
    /// legacy `load`. It is NOT "every load failure forbids a layout".
    fn assert_load_consistent(reading: &LayoutReading, load: &StateLoad) {
        use LayoutReading as Reading;

        let observed = match reading {
            Reading::Observed(report) => Some(report),
            _ => None,
        };

        match load {
            StateLoad::Loaded(_) => {
                if let Some(r) = observed {
                    assert_eq!(r.primary, EntryFinding::V1ForLocator, "Loaded");
                }
            }
            StateLoad::Corrupt(reason) => {
                if let Some(r) = observed {
                    let want = match reason {
                        CorruptReason::Empty => EntryFinding::Empty,
                        CorruptReason::TooLarge => EntryFinding::TooLarge,
                        CorruptReason::Undecodable => EntryFinding::Corrupt,
                        CorruptReason::LocatorMismatch => EntryFinding::V1OtherLocator,
                    };

                    assert_eq!(r.primary, want, "Corrupt({reason:?})");
                }
            }
            StateLoad::UnsupportedVersion => {
                if let Some(r) = observed {
                    assert_eq!(r.primary, EntryFinding::UnsupportedVersion);
                }
            }
            StateLoad::NotConfigured => {
                assert!(
                    matches!(reading, Reading::NoDirectory)
                        || observed.is_some_and(|r| r.layout == RecordLayout::NoRecordFiles),
                    "NotConfigured must be NoDirectory or NoRecordFiles, got {}",
                    describe(reading)
                );
            }
            StateLoad::Unreadable(reason) => match reason {
                UnreadableReason::UnresolvedArtifacts => {
                    if let Some(r) = observed {
                        assert_eq!(r.primary, EntryFinding::Absent);
                        assert!(r.temps.total >= 1);
                    }
                }
                // NON-WEAKENING.
                UnreadableReason::UnresolvedNewerState | UnreadableReason::UnrecognizedEntries => {
                    assert!(
                        observed
                            .is_none_or(|r| r.gate == GateObservation::NewerOrUnrecognizedEvidence
                                && r.compatibility == ExchangeCompatibility::NotAssessed),
                        "a gate refusal must never be weakened: {}",
                        describe(reading)
                    );
                }
                // NON-WEAKENING.
                UnreadableReason::LayoutUncertain => {
                    assert!(
                        matches!(
                            reading,
                            Reading::Unobservable(
                                ObservationProblem::RelatedEntryLimit
                                    | ObservationProblem::AliasAmbiguity
                            ) | Reading::ChangedDuringAssessment
                                | Reading::Incomplete(_)
                        ),
                        "LayoutUncertain must never be weakened: {}",
                        describe(reading)
                    );
                }
                // NON-WEAKENING.
                UnreadableReason::UnexpectedObject => {
                    assert!(
                        matches!(reading, Reading::Unobservable(_))
                            || observed.is_some_and(|r| r.support
                                == PhysicalSupport::Unsupported(PhysicalReason::NotPlainFile)),
                        "UnexpectedObject must never be weakened: {}",
                        describe(reading)
                    );
                }
                UnreadableReason::Io(_) | UnreadableReason::EntryLimit => {
                    assert!(
                        matches!(
                            reading,
                            Reading::Unobservable(_)
                                | Reading::Incomplete(_)
                                | Reading::ChangedDuringAssessment
                        ),
                        "an I/O uncertainty must not be Observed: {}",
                        describe(reading)
                    );
                }
            },
        }

        // The reverse direction: no gate evidence in the reading means the legacy gate
        // must not have refused on newer or unrecognized evidence.
        if let Some(r) = observed {
            if r.gate == GateObservation::NoGateEvidence {
                assert!(
                    !matches!(
                        load,
                        StateLoad::Unreadable(
                            UnreadableReason::UnresolvedNewerState
                                | UnreadableReason::UnrecognizedEntries
                        )
                    ),
                    "the classifier missed gate evidence the store refused on"
                );
            }
        }
    }

    /// CONTRACT A: no concurrent actor. The snapshot after equals the snapshot before,
    /// and the reading is consistent with the unchanged legacy `load`.
    fn contract_a(fx: &Fx, label: &str) -> LayoutReading {
        let before = snapshot(fx.root());
        let reading = fx.assess();
        let after = snapshot(fx.root());

        assert_eq!(after, before, "Contract A violated ({label})");

        let load = fx.load();

        assert_eq!(
            snapshot(fx.root()),
            before,
            "load changed something ({label})"
        );

        eprintln!(
            "OBSERVED {label}: reading={} load={load:?}",
            describe(&reading)
        );

        assert_load_consistent(&reading, &load);

        reading
    }

    // ---- Contract B ------------------------------------------------------------------

    /// The one operation a controlled actor performs.
    #[derive(Debug, Clone)]
    enum ActorOp {
        Add {
            leaf: String,
            bytes: Vec<u8>,
        },
        Remove {
            leaf: String,
        },
        /// In place: the identity is unchanged.
        Rewrite {
            leaf: String,
            bytes: Vec<u8>,
        },
        /// A new object under the same name.
        Replace {
            leaf: String,
            bytes: Vec<u8>,
        },
        Swap {
            first: String,
            second: String,
        },
        /// The sync-state directory is renamed to `moved` and a fresh one gets copies.
        MoveDirectory {
            moved: String,
        },
        /// Add then remove: the model effect is identity.
        AddThenRemove {
            leaf: String,
        },
        /// A complex operation checked by names and bytes against a twin fixture.
        Twinned {
            label: &'static str,
            expected: Vec<(String, Option<String>)>,
        },
    }

    type ActorLog = Rc<RefCell<Vec<ActorOp>>>;

    /// The model: what `after` must be, given `before` and the one operation.
    fn model_check(before: &[Entry], after: &[Entry], op: &ActorOp) {
        match op {
            ActorOp::Add { leaf, bytes } => {
                let path = rel(leaf);
                let added = find(after, &path).expect("the added file");

                assert!(find(before, &path).is_none());
                assert_eq!(added.kind, Kind::File);
                assert_eq!(added.digest.as_deref(), Some(digest_hex(bytes).as_str()));
                assert_eq!(without(after, &[path.as_str()]), without(before, &[]));
            }
            ActorOp::Remove { leaf } => {
                let path = rel(leaf);

                assert!(find(before, &path).is_some());
                assert!(find(after, &path).is_none());
                assert_eq!(without(after, &[]), without(before, &[path.as_str()]));
            }
            ActorOp::Rewrite { leaf, bytes } => {
                let path = rel(leaf);
                let old = find(before, &path).expect("the old file");
                let new = find(after, &path).expect("the rewritten file");

                assert_eq!(
                    new.identity, old.identity,
                    "an in-place rewrite keeps the identity"
                );
                assert_eq!(new.digest.as_deref(), Some(digest_hex(bytes).as_str()));
                assert_eq!(
                    without(after, &[path.as_str()]),
                    without(before, &[path.as_str()])
                );
            }
            ActorOp::Replace { leaf, bytes } => {
                let path = rel(leaf);
                let old = find(before, &path).expect("the old file");
                let new = find(after, &path).expect("the replacing file");

                assert_ne!(
                    new.identity, old.identity,
                    "a replaced object has a new identity"
                );
                assert_eq!(new.digest.as_deref(), Some(digest_hex(bytes).as_str()));
                assert_eq!(
                    without(after, &[path.as_str()]),
                    without(before, &[path.as_str()])
                );
            }
            ActorOp::Swap { first, second } => {
                let (a, b) = (rel(first), rel(second));
                let (old_a, old_b) = (find(before, &a).unwrap(), find(before, &b).unwrap());
                let (new_a, new_b) = (find(after, &a).unwrap(), find(after, &b).unwrap());

                assert_eq!(new_a.identity, old_a.identity);
                assert_eq!(new_b.identity, old_b.identity);
                assert_eq!(new_a.digest, old_b.digest);
                assert_eq!(new_b.digest, old_a.digest);
                assert_eq!(
                    without(after, &[a.as_str(), b.as_str()]),
                    without(before, &[a.as_str(), b.as_str()])
                );
            }
            ActorOp::MoveDirectory { moved } => {
                let old_dir = find(before, SYNC_STATE_DIRECTORY).expect("the old directory");
                let moved_dir = find(after, moved).expect("the moved directory");
                let new_dir = find(after, SYNC_STATE_DIRECTORY).expect("the fresh directory");

                assert_eq!(moved_dir.identity, old_dir.identity);
                assert_ne!(new_dir.identity, old_dir.identity);

                let prefix = format!("{SYNC_STATE_DIRECTORY}/");

                for old in before
                    .iter()
                    .filter(|entry| entry.path.starts_with(&prefix))
                {
                    let leaf = &old.path[prefix.len()..];
                    let kept = find(after, &format!("{moved}/{leaf}")).expect("the moved file");
                    let copy = find(after, &old.path).expect("the copied file");

                    assert_eq!(kept.identity, old.identity);
                    assert_eq!(kept.digest, old.digest);
                    assert_eq!(copy.digest, old.digest);
                    assert_ne!(copy.identity, old.identity, "a copy is a new object");
                }
            }
            ActorOp::AddThenRemove { leaf } => {
                let path = rel(leaf);

                assert!(find(before, &path).is_none() && find(after, &path).is_none());
                assert_eq!(after, before);
            }
            ActorOp::Twinned { label, expected } => {
                assert_eq!(&file_set(after), expected, "twin comparison ({label})");
            }
        }
    }

    /// CONTRACT B: one controlled actor, inside a seam hook, performs exactly one
    /// logged operation; the classifier causes no mutation beyond it.
    fn contract_b(
        fx: &Fx,
        label: &str,
        point: AssessPoint,
        op: ActorOp,
        actor: impl FnOnce() + 'static,
    ) -> LayoutReading {
        let root = fx.root().to_path_buf();
        let s0 = snapshot(&root);
        let log: ActorLog = Rc::default();
        let s2_cell: Rc<RefCell<Option<Snapshot>>> = Rc::default();
        let mut actor = Some(actor);
        let (hook_root, hook_s0, hook_log, hook_s2, hook_op) = (
            root.clone(),
            s0.clone(),
            Rc::clone(&log),
            Rc::clone(&s2_cell),
            op.clone(),
        );
        let mut seams = AssessSeams::none().on_point(move |at| {
            if at != point {
                return;
            }

            let Some(actor) = actor.take() else {
                return;
            };
            let s1 = snapshot(&hook_root);

            assert_eq!(s1, hook_s0, "Contract B: pass 1 mutated something");

            actor();
            hook_log.borrow_mut().push(hook_op.clone());

            let s2 = snapshot(&hook_root);

            model_check(&s1, &s2, &hook_op);

            *hook_s2.borrow_mut() = Some(s2);
        });
        let reading = assess_with(&fx.store(), &fx.locator, &mut seams);

        drop(seams);

        let s3 = snapshot(&root);
        let s2 = s2_cell.borrow().clone().expect("the actor never ran");

        assert_eq!(
            s3, s2,
            "Contract B: pass 2 or the rechecks mutated something"
        );
        assert_eq!(log.borrow().len(), 1, "exactly one logged operation");

        eprintln!(
            "OBSERVED {label} (Contract B): reading={}",
            describe(&reading)
        );

        reading
    }

    /// The reading of a layout that is built by hand, for comparisons.
    fn reading_of(fx: &Fx, label: &str) -> LayoutReport {
        report(contract_a(fx, label))
    }

    // ================================================================================
    // REAL NTFS: T1 .. T26 (Contract A unless marked B)
    // ================================================================================

    use ExchangeCompatibility as Compat;
    use RecordLayout as Layout;

    type ValidityCase = (
        &'static str,
        Option<Vec<u8>>,
        EntryFinding,
        fn(&StateLoad) -> bool,
    );
    type TempCase = (&'static str, Vec<u8>, fn(&TempFindings) -> bool);
    type GateCase = (
        &'static str,
        String,
        Option<Vec<u8>>,
        ForeignNames,
        UnreadableReason,
    );

    fn loaded(load: &StateLoad) -> bool {
        matches!(load, StateLoad::Loaded(_))
    }

    #[test]
    fn t01_l0_a_primary_alone_in_each_validity() {
        // REAL NTFS, Contract A.
        let cases: [ValidityCase; 5] = [
            ("t01-valid", None, EntryFinding::V1ForLocator, loaded),
            (
                "t01-corrupt",
                Some(b"SYNTHETIC-NOT-A-RECORD".to_vec()),
                EntryFinding::Corrupt,
                |load| matches!(load, StateLoad::Corrupt(CorruptReason::Undecodable)),
            ),
            ("t01-empty", Some(Vec::new()), EntryFinding::Empty, |load| {
                matches!(load, StateLoad::Corrupt(CorruptReason::Empty))
            }),
            (
                "t01-v2",
                Some(rev(1).encode_exchange_record().unwrap()),
                EntryFinding::UnsupportedVersion,
                |load| matches!(load, StateLoad::UnsupportedVersion),
            ),
            (
                "t01-other-locator",
                Some(other_locator(1).encode().unwrap()),
                EntryFinding::V1OtherLocator,
                |load| matches!(load, StateLoad::Corrupt(CorruptReason::LocatorMismatch)),
            ),
        ];

        for (label, bytes, finding, load_ok) in cases {
            let fx = match &bytes {
                None => Fx::with_state(label, &rev(1)),
                Some(bytes) => {
                    let fx = Fx::bare(label);

                    fx.put_primary(bytes);

                    fx
                }
            };
            let r = report(contract_a(&fx, label));

            assert_shape(
                &r,
                Layout::PrimaryOnly,
                finding,
                Compat::NoExchangeArtifacts,
            );
            assert_eq!(r.gate, GateObservation::NoGateEvidence);
            assert_eq!(r.support, PhysicalSupport::Supported);
            assert_eq!(r.temps.total, 0);
            assert!(load_ok(&fx.load()), "{label}: {:?}", fx.load());
        }
    }

    /// A primary of `primary` beside a `.tmp` of `temp`, built with the public store.
    fn pair(label: &str, primary: &SyncState, temp: &[u8]) -> LayoutReport {
        let fx = Fx::with_state(label, primary);

        fx.add_temp(temp);

        let r = reading_of(&fx, label);

        assert!(loaded(&fx.load()), "{label}");

        r
    }

    #[test]
    fn t02_l1_and_l6_are_physically_identical() {
        // REAL NTFS, Contract A. The old/new roles are NOT determinable: both layouts
        // give the same report.
        let l1 = pair("t02-l1", &rev(1), &bytes_of(2));
        let l6 = pair("t02-l6", &rev(2), &bytes_of(1));

        assert_shape(
            &l1,
            Layout::PrimaryAndOneTemp,
            EntryFinding::V1ForLocator,
            Compat::BeforeFirstRenameOrAfterSecondRename,
        );
        assert_eq!(l1.binding, BindingRelation::AllSame);
        assert_eq!(l1.duplicates, DuplicateFindings::default());
        assert_eq!(l1.temps.v1_for_locator, 1);
        assert_eq!(l1, l6, "L1 and L6 must be indistinguishable");
    }

    #[test]
    fn t03_l7_same_a_foreign_same_binding_primary_equals_t02() {
        // REAL NTFS, Contract A. R17e: a valid foreign same-binding primary beside the
        // old record is physically the same as L1.
        let l1 = pair("t03-l1", &rev(1), &bytes_of(2));
        let foreign = pair("t03-foreign", &rev(7), &bytes_of(1));

        assert_eq!(foreign, l1);
    }

    #[test]
    fn t04_case_a_duplicate_valid_records_beside_a_primary() {
        // REAL NTFS, Contract A. Two distinct objects with byte-identical valid records.
        let fx = Fx::with_state("t04-copy", &rev(1));

        fx.add_temp(&bytes_of(1));

        let copy = reading_of(&fx, "t04 CASE A");

        assert_shape(
            &copy,
            Layout::PrimaryAndOneTemp,
            EntryFinding::V1ForLocator,
            Compat::DuplicateRecords,
        );
        assert_eq!(copy.binding, BindingRelation::AllSame);
        assert!(copy.duplicates.valid_records);
        assert!(!copy.duplicates.other_content);
        assert_eq!(copy.support, PhysicalSupport::Supported);
        assert!(loaded(&fx.load()));

        // The contrast: two names of ONE object are not a duplicate exchange.
        let linked = Fx::with_state("t04-link", &rev(1));

        fs::hard_link(linked.primary(), linked.dir().join(linked.temp_leaf())).unwrap();

        let link = reading_of(&linked, "t04 two names of one object");

        assert_eq!(
            link.support,
            PhysicalSupport::Unsupported(PhysicalReason::SharedObject)
        );
        assert!(link.physical.shared_object);
        assert!(
            !link.duplicates.valid_records,
            "one object is not a duplicate"
        );
        assert_eq!(link.compatibility, Compat::NotAssessed);
        assert_eq!(link.layout, Layout::PrimaryAndOneTemp);
        assert!(loaded(&linked.load()));
        assert_ne!(copy, link, "the two readings must differ");
    }

    #[test]
    fn t05_l2_an_unusable_temp_beside_a_primary() {
        // REAL NTFS, Contract A.
        let valid = bytes_of(2);
        let v2 = rev(2).encode_exchange_record().unwrap();
        let cases: [TempCase; 4] = [
            ("empty", Vec::new(), |t| t.empty == 1),
            ("half-written", half(&valid), |t| t.corrupt == 1),
            ("bad-checksum", damaged(&valid), |t| t.corrupt == 1),
            ("truncated-v2", half(&v2), |t| t.corrupt == 1),
        ];

        for (name, bytes, counted) in cases {
            let label = format!("t05-{name}");
            let r = pair(&label, &rev(1), &bytes);

            assert_shape(
                &r,
                Layout::PrimaryAndOneTemp,
                EntryFinding::V1ForLocator,
                Compat::UnusableTempBesideRecord,
            );
            assert!(counted(&r.temps), "{name}");
            assert_eq!(r.gate, GateObservation::NoGateEvidence, "{name}");
        }

        // Two empty temps beside the primary.
        let fx = Fx::with_state("t05-two-empty", &rev(1));

        fx.add_temp(&[]);
        fx.add_temp(&[]);

        let r = reading_of(&fx, "t05 two empty temps");

        assert_eq!(r.layout, Layout::PrimaryAndSeveralTemps);
        assert!(r.duplicates.other_content);
        assert!(!r.duplicates.valid_records);
        assert_eq!(r.temps.empty, 2);
        assert_eq!(r.compatibility, Compat::AmbiguousPairing);
    }

    #[test]
    fn t06_l3_no_primary_and_two_distinct_valid_temps() {
        // REAL NTFS, Contract A. R17b / R17d. Swapping the contents gives an equal reading.
        let forward = Fx::bare("t06-forward");

        forward.add_temp(&bytes_of(1));
        forward.add_temp(&bytes_of(2));

        let r = reading_of(&forward, "t06 L3");

        assert_shape(
            &r,
            Layout::NoPrimaryTwoTemps,
            EntryFinding::Absent,
            Compat::BetweenRenames,
        );
        assert_eq!(r.binding, BindingRelation::AllSame);
        assert!(matches!(
            forward.load(),
            StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
        ));
        assert_ne!(forward.load(), StateLoad::NotConfigured);

        let swapped = Fx::bare("t06-swapped");

        swapped.add_temp(&bytes_of(2));
        swapped.add_temp(&bytes_of(1));

        assert_eq!(reading_of(&swapped, "t06 L3 swapped"), r);
    }

    #[test]
    fn t07_case_b_duplicate_valid_records_without_a_primary() {
        // REAL NTFS, Contract A.
        let fx = Fx::bare("t07");

        fx.add_temp(&bytes_of(1));
        fx.add_temp(&bytes_of(1));

        let r = reading_of(&fx, "t07 CASE B");

        assert_shape(
            &r,
            Layout::NoPrimaryTwoTemps,
            EntryFinding::Absent,
            Compat::DuplicateRecords,
        );
        assert_ne!(r.compatibility, Compat::NoTestedExchangeState);
        assert!(r.duplicates.valid_records);
        assert_eq!(r.binding, BindingRelation::AllSame);
        assert!(matches!(
            fx.load(),
            StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
        ));
    }

    #[test]
    fn t08_plausible_but_undecidable_pairs_give_equal_readings_in_both_orders() {
        // REAL NTFS, Contract A. No chronology is inferred from any record field.
        let sets: [(&str, SyncState, SyncState); 2] = [
            ("high-water", with_high_water(10), with_high_water(3)),
            ("pending-revision", rev(9), rev(5)),
        ];

        for (name, high, low) in sets {
            let (high, low) = (high.encode().unwrap(), low.encode().unwrap());

            // No primary: two temps.
            let one = Fx::bare(&format!("t08-{name}-a"));

            one.add_temp(&high);
            one.add_temp(&low);

            let two = Fx::bare(&format!("t08-{name}-b"));

            two.add_temp(&low);
            two.add_temp(&high);

            let (a, b) = (
                reading_of(&one, "t08 two temps"),
                reading_of(&two, "t08 two temps reversed"),
            );

            assert_eq!(a, b, "{name}");
            assert_eq!(a.compatibility, Compat::BetweenRenames, "{name}");

            // A primary and a temp, both ways round.
            let mut readings = Vec::new();

            for (label, primary, temp) in [("hl", &high, &low), ("lh", &low, &high)] {
                let fx = Fx::bare(&format!("t08-{name}-{label}"));

                fx.put_primary(primary);
                fx.add_temp(temp);
                readings.push(reading_of(&fx, "t08 primary and temp"));
            }

            assert_eq!(readings[0], readings[1], "{name}");
            assert_eq!(
                readings[0].compatibility,
                Compat::BeforeFirstRenameOrAfterSecondRename,
                "{name}"
            );
        }
    }

    #[test]
    fn t09_l4_one_complete_temp_without_a_primary() {
        // REAL NTFS, Contract A.
        let fx = Fx::bare("t09");

        fx.add_temp(&bytes_of(1));

        let r = reading_of(&fx, "t09 L4");

        assert_shape(
            &r,
            Layout::NoPrimaryOneTemp,
            EntryFinding::Absent,
            Compat::NoTestedExchangeState,
        );
        assert!(matches!(
            fx.load(),
            StateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
        ));

        let foreign = Fx::bare("t09-other");

        foreign.add_temp(&other_locator(1).encode().unwrap());

        let r = reading_of(&foreign, "t09 L4 other locator");

        assert_shape(
            &r,
            Layout::NoPrimaryOneTemp,
            EntryFinding::Absent,
            Compat::OtherLocatorRecordPresent,
        );
    }

    #[test]
    fn t10_l5_a_complete_temp_beside_a_partial_or_a_newer_one() {
        // REAL NTFS, Contract A.
        let partial = Fx::bare("t10-partial");

        partial.add_temp(&bytes_of(1));
        partial.add_temp(&half(&bytes_of(2)));

        let r = reading_of(&partial, "t10 L5");

        assert_shape(
            &r,
            Layout::NoPrimaryTwoTemps,
            EntryFinding::Absent,
            Compat::NoTestedExchangeState,
        );
        assert_eq!(r.gate, GateObservation::NoGateEvidence);

        let newer = Fx::bare("t10-v2");

        newer.add_temp(&bytes_of(1));
        newer.add_temp(&rev(2).encode_exchange_record().unwrap());

        let r = reading_of(&newer, "t10 L5'");

        assert_eq!(r.gate, GateObservation::NewerOrUnrecognizedEvidence);
        assert_eq!(r.compatibility, Compat::NotAssessed);
        assert_eq!(r.temps.unsupported_version, 1);
        assert!(matches!(
            newer.load(),
            StateLoad::Unreadable(UnreadableReason::UnresolvedNewerState)
        ));
    }

    #[test]
    fn t11_l7_a_primary_that_is_not_the_old_record() {
        // REAL NTFS, Contract A.
        let mixed = Fx::with_state("t11-mixed", &other_binding(1));

        mixed.add_temp(&bytes_of(2));

        let r = reading_of(&mixed, "t11 other binding");

        assert_shape(
            &r,
            Layout::PrimaryAndOneTemp,
            EntryFinding::V1ForLocator,
            Compat::MixedBindings,
        );
        assert_eq!(r.binding, BindingRelation::Differ);
        assert!(loaded(&mixed.load()));

        let garbage = Fx::bare("t11-garbage");

        garbage.put_primary(b"SYNTHETIC-NOT-A-RECORD");
        garbage.add_temp(&bytes_of(2));

        let r = reading_of(&garbage, "t11 garbage primary");

        assert_shape(
            &r,
            Layout::PrimaryAndOneTemp,
            EntryFinding::Corrupt,
            Compat::UnusablePrimaryBesideRecord,
        );
        assert!(matches!(
            garbage.load(),
            StateLoad::Corrupt(CorruptReason::Undecodable)
        ));

        let foreign = Fx::bare("t11-other-locator");

        foreign.put_primary(&other_locator(1).encode().unwrap());
        foreign.add_temp(&bytes_of(2));

        let r = reading_of(&foreign, "t11 other-locator primary");

        assert_shape(
            &r,
            Layout::PrimaryAndOneTemp,
            EntryFinding::V1OtherLocator,
            Compat::OtherLocatorRecordPresent,
        );
        assert!(matches!(
            foreign.load(),
            StateLoad::Corrupt(CorruptReason::LocatorMismatch)
        ));
    }

    #[test]
    fn t12_l7_plus_s_a_foreign_primary_with_two_temps() {
        // REAL NTFS, Contract A.
        let fx = Fx::with_state("t12", &other_binding(7));

        fx.add_temp(&bytes_of(1));
        fx.add_temp(&bytes_of(2));

        let r = reading_of(&fx, "t12 L7+S");

        assert_shape(
            &r,
            Layout::PrimaryAndSeveralTemps,
            EntryFinding::V1ForLocator,
            Compat::AmbiguousPairing,
        );
    }

    #[test]
    fn t13_l8_nothing_for_this_key() {
        // REAL NTFS, Contract A.
        let empty = Fx::bare("t13-empty");

        fs::create_dir_all(empty.dir()).unwrap();

        let r = report(contract_a(&empty, "t13 empty directory"));

        assert_shape(
            &r,
            Layout::NoRecordFiles,
            EntryFinding::Absent,
            Compat::NoExchangeArtifacts,
        );
        assert_eq!(empty.load(), StateLoad::NotConfigured);

        let absent = Fx::bare("t13-absent");

        assert_eq!(
            contract_a(&absent, "t13 absent directory"),
            LayoutReading::NoDirectory
        );
        assert_eq!(absent.load(), StateLoad::NotConfigured);

        let others = Fx::bare("t13-other-keys");

        others.store().create(&other_locator(1)).unwrap();

        let r = report(contract_a(&others, "t13 only other keys"));

        assert_shape(
            &r,
            Layout::NoRecordFiles,
            EntryFinding::Absent,
            Compat::NoExchangeArtifacts,
        );
        assert_eq!(others.load(), StateLoad::NotConfigured);
    }

    #[test]
    fn t14_l9_remnants_and_the_sibling_limit() {
        // REAL NTFS, Contract A.
        let remnants = Fx::with_state("t14-remnants", &rev(1));

        for revision in 2..=4 {
            remnants.add_temp(&bytes_of(revision));
        }

        let r = reading_of(&remnants, "t14 primary and three remnants");

        assert_shape(
            &r,
            Layout::PrimaryAndSeveralTemps,
            EntryFinding::V1ForLocator,
            Compat::AmbiguousPairing,
        );
        assert!(loaded(&remnants.load()));

        // Exactly 16 siblings: still observed.
        let sixteen = Fx::with_state("t14-sixteen", &rev(1));

        for revision in 0..16 {
            sixteen.add_temp(&bytes_of(100 + revision));
        }

        let r = reading_of(&sixteen, "t14 sixteen siblings");

        assert_eq!(r.temps.total, 16);
        assert_eq!(r.layout, Layout::PrimaryAndSeveralTemps);
        assert!(loaded(&sixteen.load()));

        // Seventeen siblings: not observable, and the legacy gate refuses too.
        let seventeen = Fx::with_state("t14-seventeen", &rev(1));

        for revision in 0..17 {
            seventeen.add_temp(&bytes_of(100 + revision));
        }

        let reading = contract_a(&seventeen, "t14 seventeen siblings");

        assert_eq!(
            reading,
            LayoutReading::Unobservable(ObservationProblem::RelatedEntryLimit)
        );
        assert_eq!(
            seventeen.load(),
            StateLoad::Unreadable(UnreadableReason::LayoutUncertain)
        );
    }

    #[test]
    fn t15_l10_gate_evidence_is_never_weakened() {
        // REAL NTFS, Contract A. Each in a fresh fixture beside a valid primary.
        let token = "0123456789abcdef0123456789abcdef";
        let cases: [GateCase; 7] = [
            (
                "retired",
                format!("{{key}}.{token}.retired"),
                Some(b"SYNTHETIC-GARBAGE".to_vec()),
                ForeignNames {
                    retired: true,
                    ..ForeignNames::default()
                },
                UnreadableReason::UnresolvedNewerState,
            ),
            (
                "v3stage-empty",
                format!("{{key}}.{token}.v3stage"),
                Some(Vec::new()),
                ForeignNames {
                    reserved_stage: true,
                    ..ForeignNames::default()
                },
                UnreadableReason::UnresolvedNewerState,
            ),
            (
                "v3stage-garbage",
                format!("{{key}}.{token}.v3stage"),
                Some(b"SYNTHETIC-GARBAGE".to_vec()),
                ForeignNames {
                    reserved_stage: true,
                    ..ForeignNames::default()
                },
                UnreadableReason::UnresolvedNewerState,
            ),
            (
                "v3stage-directory",
                format!("{{key}}.{token}.v3stage"),
                None,
                ForeignNames {
                    reserved_stage: true,
                    ..ForeignNames::default()
                },
                UnreadableReason::UnresolvedNewerState,
            ),
            (
                "notes",
                "{key}.notes.txt".to_owned(),
                Some(b"SYNTHETIC".to_vec()),
                ForeignNames {
                    unrecognized: true,
                    ..ForeignNames::default()
                },
                UnreadableReason::UnrecognizedEntries,
            ),
            (
                "json-bak",
                "{key}.json.bak".to_owned(),
                Some(b"SYNTHETIC".to_vec()),
                ForeignNames {
                    unrecognized: true,
                    ..ForeignNames::default()
                },
                UnreadableReason::UnrecognizedEntries,
            ),
            (
                "non-hex-token",
                "{key}.zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.tmp".to_owned(),
                Some(b"SYNTHETIC".to_vec()),
                ForeignNames {
                    unrecognized: true,
                    ..ForeignNames::default()
                },
                UnreadableReason::UnrecognizedEntries,
            ),
        ];

        for (name, pattern, bytes, foreign, refusal) in cases {
            let label = format!("t15-{name}");
            let fx = Fx::with_state(&label, &rev(1));
            let leaf = pattern.replace("{key}", &fx.key());

            match &bytes {
                Some(bytes) => {
                    fx.put(&leaf, bytes);
                }
                None => fs::create_dir(fx.dir().join(&leaf)).unwrap(),
            }

            let r = report(contract_a(&fx, &label));

            assert_eq!(
                r.gate,
                GateObservation::NewerOrUnrecognizedEvidence,
                "{name}"
            );
            assert_eq!(r.foreign, foreign, "{name}");
            assert_eq!(r.compatibility, Compat::NotAssessed, "{name}");
            assert_eq!(fx.load(), StateLoad::Unreadable(refusal), "{name}");
        }

        // An upper-case ".TMP" is an ordinary temp.
        let fx = Fx::with_state("t15-upper-tmp", &rev(1));

        fx.put(
            &format!("{}.{}.TMP", fx.key(), "ABCDEF0123456789ABCDEF0123456789"),
            &bytes_of(2),
        );

        let r = reading_of(&fx, "t15 upper-case .TMP");

        assert_eq!(r.gate, GateObservation::NoGateEvidence);
        assert_eq!(r.temps.v1_for_locator, 1);
        assert_eq!(
            r.compatibility,
            Compat::BeforeFirstRenameOrAfterSecondRename
        );
        assert!(loaded(&fx.load()));
    }

    #[test]
    fn t16_l11_objects_that_are_not_plain() {
        // REAL NTFS, Contract A.
        // The primary is a directory.
        let fx = Fx::bare("t16-primary-dir");

        fs::create_dir_all(fx.primary()).unwrap();

        let r = report(contract_a(&fx, "t16 primary is a directory"));

        assert_eq!(r.primary, EntryFinding::NotPlainFile);
        assert_eq!(
            r.support,
            PhysicalSupport::Unsupported(PhysicalReason::NotPlainFile)
        );
        assert_eq!(r.compatibility, Compat::NotAssessed);
        assert_eq!(
            fx.load(),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );

        // A temp directory beside a valid primary.
        let fx = Fx::with_state("t16-temp-dir", &rev(1));

        fs::create_dir(fx.dir().join(fx.temp_leaf())).unwrap();

        let r = report(contract_a(&fx, "t16 temp directory"));

        assert_eq!(
            r.support,
            PhysicalSupport::Unsupported(PhysicalReason::NotPlainFile)
        );
        assert_eq!(r.compatibility, Compat::NotAssessed);
        assert!(loaded(&fx.load()), "stricter than load, which loads");

        // A temp junction beside a valid primary.
        let fx = Fx::with_state("t16-temp-junction", &rev(1));
        let target = fx.root().join("junction-target");

        fs::create_dir(&target).unwrap();
        make_junction(&fx.dir().join(fx.temp_leaf()), &target);

        let r = report(contract_a(&fx, "t16 temp junction"));

        assert_eq!(
            r.support,
            PhysicalSupport::Unsupported(PhysicalReason::NotPlainFile)
        );
        assert!(loaded(&fx.load()));

        // The sync-state directory is a junction.
        let fx = Fx::bare("t16-state-junction");
        let target = fx.root().join("real-state");

        fs::create_dir(&target).unwrap();
        make_junction(&fx.dir(), &target);

        assert_eq!(
            contract_a(&fx, "t16 sync-state junction"),
            LayoutReading::Unobservable(ObservationProblem::DirectoryNotPlain)
        );
        assert_eq!(
            fx.load(),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );

        // An ancestor of the directory is a junction.
        let mut fx = Fx::bare("t16-ancestor-junction");
        let real = fx.root().join("real");
        let link = fx.root().join("link");

        fs::create_dir(&real).unwrap();
        make_junction(&link, &real);
        fx.store_root = link;

        assert_eq!(
            contract_a(&fx, "t16 ancestor junction"),
            LayoutReading::Unobservable(ObservationProblem::AncestorNotPlain)
        );
        assert_eq!(
            fx.load(),
            StateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        );

        // A file symlink: UNVERIFIED if this account cannot create one.
        let fx = Fx::with_state("t16-file-symlink", &rev(1));
        let target = fx.root().join("symlink-target.bin");

        fs::write(&target, bytes_of(2)).unwrap();

        match std::os::windows::fs::symlink_file(&target, fx.dir().join(fx.temp_leaf())) {
            Ok(()) => {
                let r = report(contract_a(&fx, "t16 file symlink"));

                assert_eq!(
                    r.support,
                    PhysicalSupport::Unsupported(PhysicalReason::NotPlainFile)
                );
            }
            Err(_) => {
                eprintln!("UNVERIFIED t16: a file symlink could not be created under this account")
            }
        }
    }

    #[test]
    fn t17_l12_names_that_are_not_one_to_one() {
        // REAL NTFS, Contract A.
        // A hard link primary -> temp (also covered by T4).
        let fx = Fx::with_state("t17-shared", &rev(1));

        fs::hard_link(fx.primary(), fx.dir().join(fx.temp_leaf())).unwrap();

        let r = report(contract_a(&fx, "t17 shared object"));

        assert_eq!(
            r.support,
            PhysicalSupport::Unsupported(PhysicalReason::SharedObject)
        );
        assert_eq!(r.compatibility, Compat::NotAssessed);

        // A temp linked outside the directory.
        let fx = Fx::with_state("t17-outside", &rev(1));
        let temp = fx.add_temp(&bytes_of(2));

        fs::hard_link(&temp, fx.root().join("outside.bin")).unwrap();

        let r = report(contract_a(&fx, "t17 link outside the directory"));

        assert_eq!(
            r.support,
            PhysicalSupport::Unsupported(PhysicalReason::OutsideNames)
        );
        assert!(r.physical.outside_names);
        assert!(!r.physical.shared_object);
        assert_eq!(r.compatibility, Compat::NotAssessed);
        assert!(loaded(&fx.load()));

        // A "<KEY>.JSON" primary.
        let fx = Fx::bare("t17-spelling");

        fx.put(
            &format!("{}.JSON", fx.key().to_ascii_uppercase()),
            &bytes_of(1),
        );

        let r = report(contract_a(&fx, "t17 non-canonical primary spelling"));

        assert_eq!(
            r.support,
            PhysicalSupport::Unsupported(PhysicalReason::NonCanonicalPrimaryName)
        );
        assert_eq!(r.compatibility, Compat::NotAssessed);
        assert!(loaded(&fx.load()), "stricter than load, which loads");
    }

    #[test]
    fn t18_l13_accumulated_artifacts_from_several_operations() {
        // REAL NTFS, Contract A.
        let fx = Fx::with_state("t18", &rev(1));

        fx.add_temp(&bytes_of(2));
        fx.add_temp(&bytes_of(3));
        fx.add_temp(&other_binding(4).encode().unwrap());

        let r = reading_of(&fx, "t18 L13");

        assert_shape(
            &r,
            Layout::PrimaryAndSeveralTemps,
            EntryFinding::V1ForLocator,
            Compat::AmbiguousPairing,
        );
        assert_eq!(r.binding, BindingRelation::Differ);
    }

    #[test]
    fn t19_repeated_assessments_agree_and_change_nothing() {
        // REAL NTFS, Contract A.
        let fx = Fx::with_state("t19", &rev(1));

        fx.add_temp(&bytes_of(2));

        let s0 = snapshot(fx.root());
        let (one, two) = (fx.assess(), fx.assess());

        assert_eq!(one, two);
        assert_eq!(snapshot(fx.root()), s0);
        assert_eq!(report(contract_a(&fx, "t19")), report(one));
    }

    #[test]
    fn t20_busy_an_exclusive_handle_makes_the_reading_incomplete() {
        // REAL NTFS, Contract A: the snapshot is taken before the exclusive handle is
        // opened and after it is closed. An exclusive hold is not a mutation.
        for target_is_primary in [true, false] {
            let label = if target_is_primary {
                "t20-primary"
            } else {
                "t20-temp"
            };
            let fx = Fx::with_state(label, &rev(1));
            let temp = fx.add_temp(&bytes_of(2));
            let held = if target_is_primary {
                fx.primary()
            } else {
                temp
            };
            let before = snapshot(fx.root());
            let exclusive = OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&held)
                .unwrap();
            let reading = fx.assess();
            let load = fx.load();

            drop(exclusive);

            assert_eq!(snapshot(fx.root()), before, "{label}");
            eprintln!(
                "OBSERVED {label}: reading={} load={load:?}",
                describe(&reading)
            );
            assert_eq!(
                reading,
                LayoutReading::Incomplete(EntryProblem::OpenRefused),
                "{label}"
            );
            assert_load_consistent(&reading, &load);
        }
    }

    /// A fixture with a primary and one temp, for the changes made between the passes.
    fn primary_and_temp(label: &str) -> (Fx, String, String) {
        let fx = Fx::with_state(label, &rev(1));
        let temp = fx.add_temp(&bytes_of(2));
        let leaf = temp.file_name().unwrap().to_string_lossy().into_owned();
        let primary = fx.primary_leaf();

        (fx, primary, leaf)
    }

    #[test]
    fn t21_b_a_change_between_the_passes_is_reported_as_changed() {
        // CONTROLLED ACTOR, Contract B. Each on a FRESH fixture.
        // (a) a temp is added.
        let (fx, _, _) = primary_and_temp("t21-add");
        let leaf = fx.temp_leaf();
        let (path, bytes) = (fx.dir().join(&leaf), bytes_of(3));
        let write = bytes.clone();
        let reading = contract_b(
            &fx,
            "t21 add a temp",
            AssessPoint::BetweenPasses,
            ActorOp::Add { leaf, bytes },
            move || fs::write(path, write).unwrap(),
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);

        // (b) a temp is removed.
        let (fx, _, temp) = primary_and_temp("t21-remove");
        let path = fx.dir().join(&temp);
        let reading = contract_b(
            &fx,
            "t21 remove a temp",
            AssessPoint::BetweenPasses,
            ActorOp::Remove { leaf: temp },
            move || fs::remove_file(path).unwrap(),
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);

        // (c) the primary's bytes are rewritten.
        let (fx, primary, _) = primary_and_temp("t21-rewrite");
        let (path, bytes) = (fx.primary(), bytes_of(5));
        let write = bytes.clone();
        let reading = contract_b(
            &fx,
            "t21 rewrite the primary",
            AssessPoint::BetweenPasses,
            ActorOp::Rewrite {
                leaf: primary,
                bytes,
            },
            move || fs::write(path, write).unwrap(),
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);

        // (d) the primary is replaced by a NEW object holding IDENTICAL bytes: only the
        // physical identity differs.
        let (fx, primary, _) = primary_and_temp("t21-replace");
        let (path, bytes) = (fx.primary(), bytes_of(1));
        let write = bytes.clone();
        let reading = contract_b(
            &fx,
            "t21 replace the primary with an identical-bytes object",
            AssessPoint::BetweenPasses,
            ActorOp::Replace {
                leaf: primary,
                bytes,
            },
            move || {
                fs::remove_file(&path).unwrap();
                fs::write(&path, write).unwrap();
            },
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);

        // (e) the contents of two temps are swapped (the identities stay).
        let fx = Fx::with_state("t21-swap", &rev(1));
        let (one, two) = (fx.add_temp(&bytes_of(2)), fx.add_temp(&bytes_of(3)));
        let leaf = |path: &Path| path.file_name().unwrap().to_string_lossy().into_owned();
        let op = ActorOp::Swap {
            first: leaf(&one),
            second: leaf(&two),
        };
        let reading = contract_b(
            &fx,
            "t21 swap two temps",
            AssessPoint::BetweenPasses,
            op,
            move || {
                let (a, b) = (fs::read(&one).unwrap(), fs::read(&two).unwrap());

                fs::write(&one, b).unwrap();
                fs::write(&two, a).unwrap();
            },
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);

        // (f) the sync-state directory is renamed away and a fresh one gets copies.
        let (fx, _, _) = primary_and_temp("t21-directory");
        let (dir, moved) = (fx.dir(), fx.root().join("moved-state"));
        let reading = contract_b(
            &fx,
            "t21 replace the directory",
            AssessPoint::BetweenPasses,
            ActorOp::MoveDirectory {
                moved: "moved-state".to_owned(),
            },
            move || {
                fs::rename(&dir, &moved).unwrap();
                fs::create_dir(&dir).unwrap();

                for entry in fs::read_dir(&moved).unwrap() {
                    let entry = entry.unwrap();

                    fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
                }
            },
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);
    }

    #[test]
    fn t22_b_a_change_that_is_undone_is_not_detected_a_documented_limitation() {
        // CONTROLLED ACTOR, Contract B. DOCUMENTED LIMITATION: two passes are not an
        // atomic snapshot. A temp is added and removed again after the first listing.
        let (fx, _, _) = primary_and_temp("t22");
        let baseline = {
            let (other, _, _) = primary_and_temp("t22-baseline");

            report(contract_a(&other, "t22 baseline"))
        };
        let leaf = fx.temp_leaf();
        let path = fx.dir().join(&leaf);
        let reading = contract_b(
            &fx,
            "t22 add then remove a temp",
            AssessPoint::AfterFirstListing,
            ActorOp::AddThenRemove { leaf },
            move || {
                fs::write(&path, bytes_of(9)).unwrap();
                fs::remove_file(&path).unwrap();
            },
        );

        eprintln!(
            "DOCUMENTED LIMITATION t22: an undone change is not detected; reading={}",
            describe(&reading)
        );

        assert_eq!(report(reading), baseline);
    }

    /// A fixture with the assessed record and the record of another locator.
    fn with_neighbour(label: &str) -> (Fx, Locator, String) {
        let fx = Fx::with_state(label, &rev(1));
        let neighbour = loc(OTHER_LOCAL);

        fx.store().create(&other_locator(1)).unwrap();

        let leaf = format!("{}.json", exchange::exchange_key(&neighbour));

        (fx, neighbour, leaf)
    }

    /// acquire -> stage -> exchange -> verify of rev(1) -> rev(2), each step required to
    /// succeed, every handle dropped on return. G12R-1 items, used by tests only.
    fn exchange_to_verified(dir: &Path, locator: &Locator, tokens: (Uuid, Uuid)) {
        let contract =
            exchange::ExchangeContract::new(locator, &rev(1), &rev(2), tokens.0, tokens.1).unwrap();
        let mut seams = exchange::RecordSeams::none();
        let held = exchange::HeldRecord::acquire(dir, contract, &mut seams).unwrap();
        let staged = held.stage(&mut seams).unwrap();
        let exchange::RecordExchangeOutcome::Exchanged(swapped) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Exchanged");
        };

        drop(swapped.verify(&mut seams).unwrap());
    }

    #[test]
    fn t23_b_the_classifier_never_blocks_a_concurrent_actor() {
        // CONTROLLED ACTOR, Contract B. Each on its OWN fresh fixture. Full sharing means
        // the classifier blocks neither a store operation nor a G12R-1 exchange.

        // (a) the store deletes ANOTHER locator's record in BetweenPasses.
        let (fx, neighbour, leaf) = with_neighbour("t23a");
        let store = fx.store();
        let reading = contract_b(
            &fx,
            "t23a delete another record",
            AssessPoint::BetweenPasses,
            ActorOp::Remove { leaf },
            move || {
                store.delete(&neighbour).unwrap();
            },
        );

        // The related set is unaffected, so Observed is what the model predicts.
        let r = report(reading);

        assert_shape(
            &r,
            Layout::PrimaryOnly,
            EntryFinding::V1ForLocator,
            Compat::NoExchangeArtifacts,
        );

        // (b) a G12R-1 acquire + stage + exchange + verify of the assessed record, while
        // the classifier holds the primary handle. The twin runs the same operation
        // without the classifier.
        let tokens = (Uuid::new_v4(), Uuid::new_v4());
        let twin = Fx::with_state("t23b-twin", &rev(1));

        exchange_to_verified(&twin.dir(), &twin.locator, tokens);

        let expected = file_set(&snapshot(twin.root()));
        let fx = Fx::with_state("t23b", &rev(1));
        let (dir, locator) = (fx.dir(), fx.locator.clone());
        let reading = contract_b(
            &fx,
            "t23b G12R-1 exchange while the primary handle is held",
            AssessPoint::EntryHeld,
            ActorOp::Twinned {
                label: "t23b",
                expected,
            },
            move || exchange_to_verified(&dir, &locator, tokens),
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);

        // (c) a store reset of the assessed record while the classifier holds it.
        let twin = Fx::with_state("t23c-twin", &rev(1));
        let evidence = twin.store().evidence(&twin.locator).unwrap();

        twin.store()
            .delete_if_evidence_matches(&twin.locator, &evidence)
            .unwrap();

        let expected = file_set(&snapshot(twin.root()));
        let fx = Fx::with_state("t23c", &rev(1));
        let (store, locator, evidence) = (
            fx.store(),
            fx.locator.clone(),
            fx.store().evidence(&fx.locator).unwrap(),
        );
        let reading = contract_b(
            &fx,
            "t23c store reset while the primary handle is held",
            AssessPoint::EntryHeld,
            ActorOp::Twinned {
                label: "t23c",
                expected,
            },
            move || {
                store
                    .delete_if_evidence_matches(&locator, &evidence)
                    .unwrap();
            },
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);

        // (d) the store creates a second locator's record in BetweenPasses.
        let twin = Fx::with_state("t23d-twin", &rev(1));

        twin.store().create(&other_locator(1)).unwrap();

        let expected = file_set(&snapshot(twin.root()));
        let fx = Fx::with_state("t23d", &rev(1));
        let store = fx.store();
        let reading = contract_b(
            &fx,
            "t23d create another record",
            AssessPoint::BetweenPasses,
            ActorOp::Twinned {
                label: "t23d",
                expected,
            },
            move || store.create(&other_locator(1)).unwrap(),
        );

        let r = report(reading);

        assert_shape(
            &r,
            Layout::PrimaryOnly,
            EntryFinding::V1ForLocator,
            Compat::NoExchangeArtifacts,
        );
    }

    #[test]
    fn t24_the_derived_key_is_the_leaf_the_store_creates() {
        // REAL NTFS, Contract A.
        let fx = Fx::with_state("t24", &rev(1));
        let leaves = handle_ops::test_support::names(&fx.dir());

        assert_eq!(leaves, vec![format!("{}.json", derive_key(&fx.locator))]);
        assert_eq!(derive_key(&fx.locator), exchange::exchange_key(&fx.locator));
        assert_eq!(derive_key(&fx.locator).len(), KEY_LEN);
    }

    /// An R19 end state rebuilt by hand. R19 was NOT re-run.
    fn r19_end_state(label: &str, primary: Option<u64>, temps: &[u64]) -> LayoutReport {
        let fx = Fx::bare(label);

        if let Some(revision) = primary {
            fx.put_primary(&bytes_of(revision));
        }

        for revision in temps {
            fx.add_temp(&bytes_of(*revision));
        }

        reading_of(&fx, label)
    }

    #[test]
    fn t25_synthesized_from_r19_the_end_states_of_each_exit_point() {
        // SYNTHESIZED-FROM-R19. The real-process-exit suite was NOT re-run; these are
        // the layouts its assertions describe, rebuilt by hand.
        let valid_only = r19_end_state("t25-before-stage-write", Some(1), &[]);
        let l1 = pair("t25-reference-l1", &rev(1), &bytes_of(2));
        let l3 = {
            let fx = Fx::bare("t25-reference-l3");

            fx.add_temp(&bytes_of(1));
            fx.add_temp(&bytes_of(2));

            reading_of(&fx, "t25 reference L3")
        };

        assert_eq!(valid_only.compatibility, Compat::NoExchangeArtifacts);
        assert_eq!(valid_only.layout, Layout::PrimaryOnly);
        // BeforeRetentionRename: the old primary and the staging file.
        assert_eq!(
            r19_end_state("t25-before-retention-rename", Some(1), &[2]),
            l1
        );
        // BetweenRenames: the retention and staging files, no primary.
        assert_eq!(r19_end_state("t25-between-renames", None, &[1, 2]), l3);
        // BeforeVerify and BeforeRelease: the new primary and the retention file.
        let l6 = r19_end_state("t25-before-verify", Some(2), &[1]);

        assert_eq!(l6, l1);
        assert_eq!(r19_end_state("t25-before-release", Some(2), &[1]), l1);
    }

    #[test]
    fn t26_gate_category_differential_against_the_unchanged_store() {
        // REAL NTFS, Contract A: assert_load_consistent inside contract_a covers the
        // non-weakening rows and the reverse check. Nothing is asserted for Loaded /
        // Corrupt / UnsupportedVersion beyond the mapping.
        let token = "fedcba9876543210fedcba9876543210";
        let names: Vec<(&str, String, Option<Vec<u8>>)> = vec![
            (
                "retired",
                format!("{{key}}.{token}.retired"),
                Some(b"G".to_vec()),
            ),
            (
                "v3stage-empty",
                format!("{{key}}.{token}.v3stage"),
                Some(Vec::new()),
            ),
            ("v3stage-dir", format!("{{key}}.{token}.v3stage"), None),
            ("notes", "{key}.notes.txt".to_owned(), Some(b"N".to_vec())),
            ("json-bak", "{key}.json.bak".to_owned(), Some(b"B".to_vec())),
            (
                "non-hex",
                "{key}.gggggggggggggggggggggggggggggggg.tmp".to_owned(),
                Some(b"H".to_vec()),
            ),
            (
                "upper-tmp",
                format!("{{key}}.{}.TMP", token.to_ascii_uppercase()),
                Some(bytes_of(2)),
            ),
            (
                "short-token",
                "{key}.0123456789abcdef.tmp".to_owned(),
                Some(b"S".to_vec()),
            ),
        ];

        for beside_primary in [true, false] {
            for (name, pattern, bytes) in &names {
                let label = format!(
                    "t26-{name}-{}",
                    if beside_primary { "primary" } else { "bare" }
                );
                let fx = if beside_primary {
                    Fx::with_state(&label, &rev(1))
                } else {
                    Fx::bare(&label)
                };
                let leaf = pattern.replace("{key}", &fx.key());

                match bytes {
                    Some(bytes) => {
                        fx.put(&leaf, bytes);
                    }
                    None => {
                        fs::create_dir_all(fx.dir()).unwrap();
                        fs::create_dir(fx.dir().join(&leaf)).unwrap();
                    }
                }

                let _ = contract_a(&fx, &label);
            }

            // The sibling-limit set: 17 temps.
            let label = format!(
                "t26-seventeen-{}",
                if beside_primary { "primary" } else { "bare" }
            );
            let fx = if beside_primary {
                Fx::with_state(&label, &rev(1))
            } else {
                Fx::bare(&label)
            };

            for revision in 0..17 {
                fx.add_temp(&bytes_of(10 + revision));
            }

            let _ = contract_a(&fx, &label);
        }

        // A non-Unicode key-prefixed name through the injected listing: gate evidence.
        let fx = Fx::with_state("t26-non-unicode", &rev(1));
        let lone_surrogate = {
            use std::os::windows::ffi::OsStringExt;

            let mut units: Vec<u16> = format!("{}.", fx.key()).encode_utf16().collect();

            units.push(0xD800);

            OsString::from_wide(&units)
        };
        let mut seams =
            AssessSeams::none().with_fault(AssessFault::ExtraListedName(lone_surrogate));
        let r = report(assess_with(&fx.store(), &fx.locator, &mut seams));

        assert_eq!(r.gate, GateObservation::NewerOrUnrecognizedEvidence);
        assert!(r.foreign.unrecognized);
        assert_eq!(r.compatibility, Compat::NotAssessed);
    }

    // ================================================================================
    // OVERSIZED ENTRIES: the bounded-read limit (extra to the T1..T26 matrix)
    // ================================================================================

    /// A synthetic file one byte over the supported maximum.
    fn oversized(fill: u8) -> Vec<u8> {
        vec![fill; MAX_SYNC_STATE_BYTES + 1]
    }

    #[test]
    fn t27_an_oversized_entry_is_too_large_and_never_contributes_to_a_pair() {
        // REAL NTFS, Contract A. No digest of the complete bytes exists, so the entry is
        // never usable, never part of a duplicate and never an exchange compatibility.
        let fx = Fx::with_state("t27-temp", &rev(1));

        fx.add_temp(&oversized(b'a'));

        let r = reading_of(&fx, "t27 oversized temp beside a primary");

        assert_shape(
            &r,
            Layout::PrimaryAndOneTemp,
            EntryFinding::V1ForLocator,
            Compat::UnusableTempBesideRecord,
        );
        assert_eq!(r.temps.too_large, 1);
        assert!(loaded(&fx.load()));

        // An oversized primary beside a valid temp.
        let fx = Fx::bare("t27-primary");

        fx.put_primary(&oversized(b'a'));
        fx.add_temp(&bytes_of(2));

        let r = reading_of(&fx, "t27 oversized primary beside a temp");

        assert_shape(
            &r,
            Layout::PrimaryAndOneTemp,
            EntryFinding::TooLarge,
            Compat::UnusablePrimaryBesideRecord,
        );
        assert!(matches!(
            fx.load(),
            StateLoad::Corrupt(CorruptReason::TooLarge)
        ));

        // Two oversized temps with IDENTICAL content: no digest, so no duplicate.
        let fx = Fx::bare("t27-two");

        fx.add_temp(&oversized(b'a'));
        fx.add_temp(&oversized(b'a'));

        let r = reading_of(&fx, "t27 two identical oversized temps");

        assert_eq!(r.layout, Layout::NoPrimaryTwoTemps);
        assert_eq!(r.temps.too_large, 2);
        assert_eq!(r.duplicates, DuplicateFindings::default());
        assert_eq!(r.compatibility, Compat::NoTestedExchangeState);

        // An oversized temp beside a valid temp, no primary.
        let fx = Fx::bare("t27-mixed");

        fx.add_temp(&oversized(b'a'));
        fx.add_temp(&bytes_of(1));

        let r = reading_of(&fx, "t27 oversized and valid temps");

        assert_eq!(r.compatibility, Compat::NoTestedExchangeState);
        assert_eq!(r.binding, BindingRelation::Single);
    }

    #[test]
    fn t28_b_a_same_length_change_of_an_oversized_file_is_not_detected_the_actual_limit() {
        // CONTROLLED ACTOR, Contract B. HONEST DETECTION LIMIT: for an oversized entry
        // only the supported metadata is compared (identity, links, length). A rewrite
        // that keeps the length is NOT detected; a rewrite that changes the length is.
        // Nothing positive is ever reported for such an entry either way.
        let build = |label: &str| {
            let fx = Fx::with_state(label, &rev(1));
            let temp = fx.add_temp(&oversized(b'a'));
            let leaf = temp.file_name().unwrap().to_string_lossy().into_owned();

            (fx, temp, leaf)
        };

        let (reference, _, _) = build("t28-reference");
        let reference = report(contract_a(&reference, "t28 reference"));

        // Same length, different bytes.
        let (fx, path, leaf) = build("t28-same-length");
        let bytes = oversized(b'b');
        let write = bytes.clone();
        let reading = contract_b(
            &fx,
            "t28 same-length rewrite of an oversized temp",
            AssessPoint::BetweenPasses,
            ActorOp::Rewrite { leaf, bytes },
            move || fs::write(path, write).unwrap(),
        );

        eprintln!(
            "DETECTION LIMIT t28: a same-length content change of an oversized file was NOT \
             detected; reading={}",
            describe(&reading)
        );

        assert_ne!(reading, LayoutReading::ChangedDuringAssessment);
        assert_eq!(report(reading), reference);
        assert_eq!(
            report(reading).compatibility,
            Compat::UnusableTempBesideRecord
        );
        assert!(!report(reading).duplicates.valid_records);

        // A different length is detected.
        let (fx, path, leaf) = build("t28-new-length");
        let mut bytes = oversized(b'a');

        bytes.extend_from_slice(b"extra");

        let write = bytes.clone();
        let reading = contract_b(
            &fx,
            "t28 longer rewrite of an oversized temp",
            AssessPoint::BetweenPasses,
            ActorOp::Rewrite { leaf, bytes },
            move || fs::write(path, write).unwrap(),
        );

        assert_eq!(reading, LayoutReading::ChangedDuringAssessment);
    }

    // ================================================================================
    // G12R-1 CROSS-CHECKS: X1 .. X8
    // ================================================================================

    const DENIED: i32 = 0xC000_0022_u32 as i32;
    const PENDING: i32 = 0x0000_0103;

    fn contract_for(
        fx: &Fx,
        tokens: (Uuid, Uuid),
        old: &SyncState,
        new: &SyncState,
    ) -> exchange::ExchangeContract {
        exchange::ExchangeContract::new(&fx.locator, old, new, tokens.0, tokens.1).unwrap()
    }

    fn acquire(
        fx: &Fx,
        tokens: (Uuid, Uuid),
        seams: &mut exchange::RecordSeams,
    ) -> exchange::HeldRecord {
        exchange::HeldRecord::acquire(&fx.dir(), contract_for(fx, tokens, &rev(1), &rev(2)), seams)
            .unwrap()
    }

    fn inject_at(at: exchange::RecordStage, status: i32) -> exchange::RecordSeams {
        exchange::RecordSeams::none().on_stage(move |stage| {
            if stage == at {
                handle_ops::inject_rename_status(status);
            }
        })
    }

    /// The same names and bytes, written by hand into a FRESH scratch.
    fn by_hand(from: &Fx, label: &str) -> Fx {
        let copy = Fx::bare(label);

        for entry in fs::read_dir(from.dir()).unwrap() {
            let entry = entry.unwrap();

            copy.put(
                &entry.file_name().to_string_lossy(),
                &fs::read(entry.path()).unwrap(),
            );
        }

        copy
    }

    /// Assess the experiment's end state, then the same names and bytes written by
    /// hand; the two readings must be equal.
    fn cross_check(label: &str, fx: &Fx) -> LayoutReport {
        let experiment = reading_of(fx, &format!("{label} (experiment)"));
        let hand = by_hand(fx, &format!("{label}-by-hand"));

        assert_eq!(
            handle_ops::test_support::names(&hand.dir()),
            handle_ops::test_support::names(&fx.dir())
        );
        assert_eq!(reading_of(&hand, &format!("{label} (by hand)")), experiment);

        experiment
    }

    fn fresh(label: &str) -> (Fx, (Uuid, Uuid)) {
        let _ = handle_ops::take_last_rename_status();
        let _ = handle_ops::take_last_delete_status();

        (
            Fx::with_state(label, &rev(1)),
            (Uuid::new_v4(), Uuid::new_v4()),
        )
    }

    fn l1_reading() -> LayoutReport {
        pair("x-reference-l1", &rev(1), &bytes_of(2))
    }

    fn l3_reading() -> LayoutReport {
        let fx = Fx::bare("x-reference-l3");

        fx.add_temp(&bytes_of(1));
        fx.add_temp(&bytes_of(2));

        reading_of(&fx, "x reference L3")
    }

    #[test]
    fn x1_r17a_a_dropped_staged_record() {
        // REAL NTFS, Contract A; the end state of the real experiment.
        let (fx, tokens) = fresh("x1");
        let mut seams = exchange::RecordSeams::none();
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();

        drop(staged);

        let r = cross_check("x1 R17a", &fx);

        assert_eq!(
            r.compatibility,
            Compat::BeforeFirstRenameOrAfterSecondRename
        );
        assert_eq!(r, l1_reading());
    }

    #[test]
    fn x2_r17b_an_unknown_publication() {
        // REAL NTFS + injected 0x103 on the second rename.
        let (fx, tokens) = fresh("x2");
        let mut seams = inject_at(exchange::RecordStage::BetweenRenames, PENDING);
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();
        let exchange::RecordExchangeOutcome::Unknown(unknown) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Unknown");
        };

        drop(unknown);

        let r = cross_check("x2 R17b", &fx);

        assert_eq!(r.compatibility, Compat::BetweenRenames);
        assert_eq!(r, l3_reading());
    }

    #[test]
    fn x3_r17c_a_dropped_swapped_record() {
        // REAL NTFS.
        let (fx, tokens) = fresh("x3");
        let mut seams = exchange::RecordSeams::none();
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();
        let exchange::RecordExchangeOutcome::Exchanged(swapped) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Exchanged");
        };

        drop(swapped);

        let r = cross_check("x3 R17c", &fx);

        // L6 is physically identical to L1: the report cannot tell old from new.
        assert_eq!(r, l1_reading());
    }

    #[test]
    fn x4_r17d_a_failed_restoration() {
        // REAL NTFS + injected refusals of the second rename and of the restoration.
        let (fx, tokens) = fresh("x4");
        let mut seams = exchange::RecordSeams::none().on_stage(|stage| {
            if matches!(
                stage,
                exchange::RecordStage::BetweenRenames | exchange::RecordStage::BeforeRestore
            ) {
                handle_ops::inject_rename_status(DENIED);
            }
        });
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();
        let exchange::RecordExchangeOutcome::Interrupted(interrupted) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Interrupted");
        };

        drop(interrupted);

        assert_eq!(cross_check("x4 R17d", &fx), l3_reading());
    }

    #[test]
    fn x5_r17e_a_taken_over_primary_with_the_same_binding() {
        // REAL NTFS; the foreign writer is an in-process write at the seam (R17e itself
        // uses a child process). A valid same-binding foreign primary, rev 7.
        let (fx, tokens) = fresh("x5");
        let primary = fx.primary();
        let mut seams = exchange::RecordSeams::none().on_stage(move |stage| {
            if stage == exchange::RecordStage::BetweenRenames {
                fs::write(&primary, bytes_of(7)).unwrap();
            }
        });
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();
        let exchange::RecordExchangeOutcome::TakenOver(retained) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected TakenOver");
        };

        drop(retained);

        assert_eq!(cross_check("x5 R17e", &fx), l1_reading());
    }

    #[test]
    fn x6_r17f_an_unknown_first_rename() {
        // REAL NTFS + injected 0x103 on the first rename.
        let (fx, tokens) = fresh("x6");
        let mut seams = inject_at(exchange::RecordStage::BeforeRetentionRename, PENDING);
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();
        let exchange::RecordExchangeOutcome::Unknown(unknown) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Unknown");
        };

        drop(unknown);

        assert_eq!(cross_check("x6 R17f", &fx), l1_reading());
    }

    #[test]
    fn x7_r18_a_refused_publication_restores_the_old_record() {
        // REAL NTFS + injected STATUS_ACCESS_DENIED on the second rename only.
        let (fx, tokens) = fresh("x7");
        let mut seams = inject_at(exchange::RecordStage::BetweenRenames, DENIED);
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();
        let exchange::RecordExchangeOutcome::Restored(restored) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Restored");
        };

        drop(restored);

        let r = cross_check("x7 R18", &fx);

        assert_shape(
            &r,
            Layout::PrimaryOnly,
            EntryFinding::V1ForLocator,
            Compat::NoExchangeArtifacts,
        );
    }

    #[test]
    fn x8_b_the_classifier_does_not_disturb_a_held_experiment() {
        // CONTROLLED ACTOR, Contract B: the experiment's handles stay held while the
        // classifier runs, then the experiment continues.
        let (fx, tokens) = fresh("x8-staged");
        let mut seams = exchange::RecordSeams::none();
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();
        let before = snapshot(fx.root());
        let reading = fx.assess();

        assert_eq!(
            snapshot(fx.root()),
            before,
            "Contract A while a StagedRecord is held"
        );
        eprintln!(
            "OBSERVED x8 (StagedRecord held): reading={}",
            describe(&reading)
        );
        assert_eq!(report(reading), l1_reading());

        let exchange::RecordExchangeOutcome::Exchanged(swapped) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Exchanged after an assessment");
        };

        assert!(
            swapped.verify(&mut seams).is_ok(),
            "verify after an assessment"
        );
        assert!(matches!(fx.load(), StateLoad::Loaded(state) if *state == rev(2)));

        // An UnknownRecord stays held.
        let (fx, tokens) = fresh("x8-unknown");
        let mut seams = inject_at(exchange::RecordStage::BetweenRenames, PENDING);
        let staged = acquire(&fx, tokens, &mut seams).stage(&mut seams).unwrap();
        let exchange::RecordExchangeOutcome::Unknown(unknown) =
            staged.exchange(&mut || true, &mut seams)
        else {
            panic!("expected Unknown");
        };
        let before = snapshot(fx.root());
        let reading = fx.assess();

        assert_eq!(
            snapshot(fx.root()),
            before,
            "Contract A while an UnknownRecord is held"
        );
        eprintln!(
            "OBSERVED x8 (UnknownRecord held): reading={}",
            describe(&reading)
        );
        assert_eq!(report(reading), l3_reading());

        drop(unknown);
    }

    // ================================================================================
    // INJECTED: J1 .. J12
    // ================================================================================

    fn injected(fx: &Fx, label: &str, fault: AssessFault) -> LayoutReading {
        let before = snapshot(fx.root());
        let reading = assess_with(
            &fx.store(),
            &fx.locator,
            &mut AssessSeams::none().with_fault(fault),
        );

        assert_eq!(
            snapshot(fx.root()),
            before,
            "an injected fault changed something ({label})"
        );
        eprintln!(
            "OBSERVED {label} (INJECTED): reading={}",
            describe(&reading)
        );

        reading
    }

    fn primary_with_temp(label: &str) -> Fx {
        let fx = Fx::with_state(label, &rev(1));

        fx.add_temp(&bytes_of(2));

        fx
    }

    #[test]
    fn j01_the_listing_fails() {
        let fx = primary_with_temp("j01");

        assert_eq!(
            injected(&fx, "j01", AssessFault::ListingFails),
            LayoutReading::Unobservable(ObservationProblem::ListingFailed)
        );
    }

    #[test]
    fn j02_the_listing_iterator_fails() {
        let fx = primary_with_temp("j02");

        assert_eq!(
            injected(&fx, "j02", AssessFault::ListingIteratorFails { after: 1 }),
            LayoutReading::Unobservable(ObservationProblem::ListingIncomplete)
        );
    }

    #[test]
    fn j03_the_listing_is_over_the_limit() {
        let fx = primary_with_temp("j03");

        assert_eq!(
            injected(&fx, "j03", AssessFault::ListingOverLimit),
            LayoutReading::Unobservable(ObservationProblem::EntryLimit)
        );
    }

    #[test]
    fn j04_an_open_is_refused_or_fails() {
        let fx = primary_with_temp("j04");

        assert_eq!(
            injected(
                &fx,
                "j04 permission denied",
                AssessFault::OpenFails {
                    nth: 0,
                    kind: io::ErrorKind::PermissionDenied
                }
            ),
            LayoutReading::Incomplete(EntryProblem::OpenRefused)
        );
        assert_eq!(
            injected(
                &fx,
                "j04 other",
                AssessFault::OpenFails {
                    nth: 1,
                    kind: io::ErrorKind::Other
                }
            ),
            LayoutReading::Incomplete(EntryProblem::Unreadable)
        );
    }

    #[test]
    fn j05_the_identity_facts_fail() {
        let fx = primary_with_temp("j05");

        assert_eq!(
            injected(&fx, "j05", AssessFault::FactsFail { nth: 0 }),
            LayoutReading::Incomplete(EntryProblem::IdentityUncertain)
        );
    }

    #[test]
    fn j06_a_read_fails() {
        let fx = primary_with_temp("j06");

        assert_eq!(
            injected(&fx, "j06", AssessFault::ReadFails { nth: 0 }),
            LayoutReading::Incomplete(EntryProblem::Unreadable)
        );
    }

    #[test]
    fn j07_the_second_read_differs() {
        let fx = primary_with_temp("j07");

        assert_eq!(
            injected(&fx, "j07", AssessFault::SecondReadDiffers { nth: 0 }),
            LayoutReading::ChangedDuringAssessment
        );
    }

    #[test]
    fn j08_the_directory_identity_fails() {
        let fx = primary_with_temp("j08");

        assert_eq!(
            injected(&fx, "j08", AssessFault::DirectoryIdentityFails),
            LayoutReading::Unobservable(ObservationProblem::DirectoryIdentityUnavailable)
        );
    }

    #[test]
    fn j09_the_volume_is_not_ntfs() {
        let fx = primary_with_temp("j09");

        assert_eq!(
            injected(&fx, "j09", AssessFault::VolumeNotNtfs),
            LayoutReading::Unobservable(ObservationProblem::NotLocalNtfs)
        );
    }

    #[test]
    fn j10_an_alias_and_a_non_unicode_name() {
        let fx = primary_with_temp("j10");
        let alias = OsString::from(format!("{}.JSON", fx.key().to_ascii_uppercase()));

        assert_eq!(
            injected(&fx, "j10 alias", AssessFault::ExtraListedName(alias)),
            LayoutReading::Unobservable(ObservationProblem::AliasAmbiguity)
        );

        let lone_surrogate = {
            use std::os::windows::ffi::OsStringExt;

            let mut units: Vec<u16> = format!("{}.", fx.key()).encode_utf16().collect();

            units.push(0xD800);

            OsString::from_wide(&units)
        };
        let r = report(injected(
            &fx,
            "j10 non-Unicode",
            AssessFault::ExtraListedName(lone_surrogate),
        ));

        assert_eq!(r.gate, GateObservation::NewerOrUnrecognizedEvidence);
        assert!(r.foreign.unrecognized);
        assert_eq!(r.compatibility, Compat::NotAssessed);
    }

    fn judged(facts: HandleFacts, content: Content) -> Seen {
        let length = match &content {
            Content::Within(bytes) => bytes.len() as u64,
            Content::Empty => 0,
            Content::TooLarge => MAX_SYNC_STATE_BYTES as u64 + 1,
        };

        judge_entry(
            &RawEntry {
                facts,
                length,
                content,
            },
            &loc(LOCAL),
        )
    }

    fn facts(
        links: u32,
        delete_pending: bool,
        filesystem: FileSystemKind,
        local: bool,
    ) -> HandleFacts {
        HandleFacts::for_test(7, [1; 16], links, delete_pending, filesystem, local)
    }

    #[test]
    fn j11_judge_entry_with_injected_facts() {
        // INJECTED facts; no filesystem.
        let valid = || Content::Within(bytes_of(1));
        let ok = judged(facts(1, false, FileSystemKind::Ntfs, true), valid());

        assert_eq!(ok.finding, EntryFinding::V1ForLocator);
        assert!(!ok.not_local_ntfs);
        assert_eq!(ok.links, 1);

        // ReFS and a remote device are not local NTFS.
        assert!(judged(facts(1, false, FileSystemKind::Refs, true), valid()).not_local_ntfs);
        assert!(judged(facts(1, false, FileSystemKind::Ntfs, false), valid()).not_local_ntfs);

        // Delete-pending is judged before any content.
        let pending = judged(facts(1, true, FileSystemKind::Ntfs, true), valid());

        assert_eq!(pending.finding, EntryFinding::DeletePending);
        assert!(pending.digest.is_none());

        // The link count is reported as it is.
        assert_eq!(
            judged(facts(2, false, FileSystemKind::Ntfs, true), valid()).links,
            2
        );

        // Content findings.
        let at = |content| judged(facts(1, false, FileSystemKind::Ntfs, true), content).finding;

        assert_eq!(at(Content::Empty), EntryFinding::Empty);
        assert_eq!(at(Content::TooLarge), EntryFinding::TooLarge);
        assert_eq!(at(Content::Within(b"x".to_vec())), EntryFinding::Corrupt);
        assert_eq!(
            at(Content::Within(rev(1).encode_exchange_record().unwrap())),
            EntryFinding::UnsupportedVersion
        );
        assert_eq!(
            at(Content::Within(other_locator(1).encode().unwrap())),
            EntryFinding::V1OtherLocator
        );
        assert!(judged(
            facts(1, false, FileSystemKind::Ntfs, true),
            Content::TooLarge
        )
        .digest
        .is_none());

        // A zero identity cannot be recognized by this module; two such names are one
        // shared object, which is the conservative reading. UNVERIFIED for a lone one.
        let zero =
            |links| HandleFacts::for_test(0, [0; 16], links, false, FileSystemKind::Ntfs, true);
        let (a, b) = (
            judged(zero(1), valid()),
            judged(zero(1), Content::Within(bytes_of(2))),
        );

        assert!(physical_findings(&[&a, &b], false).shared_object);

        // A report built from an injected ReFS primary is not assessed.
        let mut observation = Observation::new();

        observation.primary = Some(judged(facts(1, false, FileSystemKind::Refs, true), valid()));

        let r = report(classify(&observation));

        assert_eq!(
            r.support,
            PhysicalSupport::Unsupported(PhysicalReason::NotLocalNtfs)
        );
        assert_eq!(r.compatibility, Compat::NotAssessed);
    }

    #[test]
    fn j12_the_second_listing_differs() {
        let fx = primary_with_temp("j12");

        assert_eq!(
            injected(&fx, "j12", AssessFault::SecondListingDiffers),
            LayoutReading::ChangedDuringAssessment
        );
    }

    // ================================================================================
    // PURE and isolation: P1 .. P10
    // ================================================================================

    fn all_primaries() -> [EntryFinding; 9] {
        [
            EntryFinding::Absent,
            EntryFinding::NotPlainFile,
            EntryFinding::DeletePending,
            EntryFinding::Empty,
            EntryFinding::TooLarge,
            EntryFinding::Corrupt,
            EntryFinding::UnsupportedVersion,
            EntryFinding::V1OtherLocator,
            EntryFinding::V1ForLocator,
        ]
    }

    fn all_temp_findings() -> [EntryFinding; 8] {
        [
            EntryFinding::NotPlainFile,
            EntryFinding::DeletePending,
            EntryFinding::Empty,
            EntryFinding::TooLarge,
            EntryFinding::Corrupt,
            EntryFinding::UnsupportedVersion,
            EntryFinding::V1OtherLocator,
            EntryFinding::V1ForLocator,
        ]
    }

    /// Every multiset of temp findings of up to `max` members (combinations with
    /// repetition), as sorted lists.
    fn multisets(max: usize) -> Vec<Vec<EntryFinding>> {
        fn extend(
            pool: &[EntryFinding],
            start: usize,
            current: &mut Vec<EntryFinding>,
            max: usize,
            out: &mut Vec<Vec<EntryFinding>>,
        ) {
            if current.len() == max {
                return;
            }

            for index in start..pool.len() {
                current.push(pool[index]);
                out.push(current.clone());
                extend(pool, index, current, max, out);
                current.pop();
            }
        }

        let mut out = vec![Vec::new()];

        extend(&all_temp_findings(), 0, &mut Vec::new(), max, &mut out);

        out
    }

    /// Written independently of the production counting.
    fn counts_of(list: &[EntryFinding]) -> TempFindings {
        let mut found = TempFindings {
            total: list.len() as u8,
            ..TempFindings::default()
        };

        for finding in list {
            match finding {
                EntryFinding::Absent => unreachable!("a temp is never absent"),
                EntryFinding::NotPlainFile => found.not_plain += 1,
                EntryFinding::DeletePending => found.delete_pending += 1,
                EntryFinding::Empty => found.empty += 1,
                EntryFinding::TooLarge => found.too_large += 1,
                EntryFinding::Corrupt => found.corrupt += 1,
                EntryFinding::UnsupportedVersion => found.unsupported_version += 1,
                EntryFinding::V1OtherLocator => found.v1_other_locator += 1,
                EntryFinding::V1ForLocator => found.v1_for_locator += 1,
            }
        }

        found
    }

    fn all_layouts() -> [RecordLayout; 7] {
        [
            RecordLayout::NoRecordFiles,
            RecordLayout::PrimaryOnly,
            RecordLayout::PrimaryAndOneTemp,
            RecordLayout::PrimaryAndSeveralTemps,
            RecordLayout::NoPrimaryOneTemp,
            RecordLayout::NoPrimaryTwoTemps,
            RecordLayout::NoPrimarySeveralTemps,
        ]
    }

    fn all_bindings() -> [BindingRelation; 4] {
        [
            BindingRelation::NoValidRecords,
            BindingRelation::Single,
            BindingRelation::AllSame,
            BindingRelation::Differ,
        ]
    }

    fn all_duplicates() -> Vec<DuplicateFindings> {
        let mut out = Vec::new();

        for valid_records in [false, true] {
            for other_content in [false, true] {
                out.push(DuplicateFindings {
                    valid_records,
                    other_content,
                });
            }
        }

        out
    }

    fn all_supports() -> [PhysicalSupport; 7] {
        [
            PhysicalSupport::Supported,
            PhysicalSupport::Unsupported(PhysicalReason::NotPlainFile),
            PhysicalSupport::Unsupported(PhysicalReason::DeletePending),
            PhysicalSupport::Unsupported(PhysicalReason::SharedObject),
            PhysicalSupport::Unsupported(PhysicalReason::OutsideNames),
            PhysicalSupport::Unsupported(PhysicalReason::NonCanonicalPrimaryName),
            PhysicalSupport::Unsupported(PhysicalReason::NotLocalNtfs),
        ]
    }

    fn all_gates() -> [GateObservation; 2] {
        [
            GateObservation::NoGateEvidence,
            GateObservation::NewerOrUnrecognizedEvidence,
        ]
    }

    /// One letter per finding, for the independently written table.
    fn letter(finding: EntryFinding) -> char {
        match finding {
            EntryFinding::V1ForLocator => 'U',
            EntryFinding::V1OtherLocator => 'O',
            EntryFinding::Empty
            | EntryFinding::TooLarge
            | EntryFinding::Corrupt
            | EntryFinding::UnsupportedVersion => 'X',
            EntryFinding::Absent => '-',
            EntryFinding::NotPlainFile | EntryFinding::DeletePending => 'Z',
        }
    }

    fn expand(counts: &TempFindings) -> Vec<EntryFinding> {
        let mut out = Vec::new();

        for _ in 0..counts.v1_for_locator {
            out.push(EntryFinding::V1ForLocator);
        }
        for _ in 0..counts.v1_other_locator {
            out.push(EntryFinding::V1OtherLocator);
        }
        for _ in 0..counts.unsupported_version {
            out.push(EntryFinding::UnsupportedVersion);
        }
        for _ in 0..counts.corrupt {
            out.push(EntryFinding::Corrupt);
        }
        for _ in 0..counts.too_large {
            out.push(EntryFinding::TooLarge);
        }
        for _ in 0..counts.empty {
            out.push(EntryFinding::Empty);
        }
        for _ in 0..counts.delete_pending {
            out.push(EntryFinding::DeletePending);
        }
        for _ in 0..counts.not_plain {
            out.push(EntryFinding::NotPlainFile);
        }

        out
    }

    /// The compatibility table, written a second time in another form: one letter per
    /// entry, a tuple match, and an explicit conservative value for everything else.
    fn expected(s: &Summary) -> Compat {
        if s.gate == GateObservation::NewerOrUnrecognizedEvidence {
            return Compat::NotAssessed;
        }

        if s.support != PhysicalSupport::Supported {
            return Compat::NotAssessed;
        }

        let temps = expand(&s.temps);
        let listed = s.primary != EntryFinding::Absent;
        let wanted = match (listed, s.temps.total) {
            (false, 0) => RecordLayout::NoRecordFiles,
            (true, 0) => RecordLayout::PrimaryOnly,
            (true, 1) => RecordLayout::PrimaryAndOneTemp,
            (true, _) => RecordLayout::PrimaryAndSeveralTemps,
            (false, 1) => RecordLayout::NoPrimaryOneTemp,
            (false, 2) => RecordLayout::NoPrimaryTwoTemps,
            (false, _) => RecordLayout::NoPrimarySeveralTemps,
        };

        if wanted != s.layout {
            return Compat::NoTestedExchangeState;
        }

        let consistent = temps.len() == usize::from(s.temps.total);
        let primary = letter(s.primary);
        let two_usable = |same: Compat| match s.binding {
            BindingRelation::Differ => Compat::MixedBindings,
            BindingRelation::AllSame if s.duplicates.valid_records => Compat::DuplicateRecords,
            BindingRelation::AllSame => same,
            BindingRelation::NoValidRecords | BindingRelation::Single => {
                Compat::NoTestedExchangeState
            }
        };

        match (s.layout, temps.as_slice()) {
            (RecordLayout::NoRecordFiles | RecordLayout::PrimaryOnly, _) => {
                Compat::NoExchangeArtifacts
            }
            (RecordLayout::PrimaryAndOneTemp, [temp]) if consistent => {
                match (primary, letter(*temp)) {
                    ('O', _) | (_, 'O') => Compat::OtherLocatorRecordPresent,
                    ('U', 'X') => Compat::UnusableTempBesideRecord,
                    ('X', 'U') => Compat::UnusablePrimaryBesideRecord,
                    ('X', 'X') => Compat::NoTestedExchangeState,
                    ('U', 'U') => two_usable(Compat::BeforeFirstRenameOrAfterSecondRename),
                    _ => Compat::NoTestedExchangeState,
                }
            }
            (RecordLayout::PrimaryAndOneTemp, _) => Compat::NoTestedExchangeState,
            (RecordLayout::NoPrimaryOneTemp, [temp]) if consistent => {
                if letter(*temp) == 'O' {
                    Compat::OtherLocatorRecordPresent
                } else {
                    Compat::NoTestedExchangeState
                }
            }
            (RecordLayout::NoPrimaryOneTemp, _) => Compat::NoTestedExchangeState,
            (RecordLayout::NoPrimaryTwoTemps, [a, b]) if consistent => {
                match (letter(*a), letter(*b)) {
                    ('O', _) | (_, 'O') => Compat::OtherLocatorRecordPresent,
                    ('X', _) | (_, 'X') => Compat::NoTestedExchangeState,
                    ('U', 'U') => two_usable(Compat::BetweenRenames),
                    _ => Compat::NoTestedExchangeState,
                }
            }
            (RecordLayout::NoPrimaryTwoTemps, _) => Compat::NoTestedExchangeState,
            (RecordLayout::PrimaryAndSeveralTemps | RecordLayout::NoPrimarySeveralTemps, _) => {
                Compat::AmbiguousPairing
            }
        }
    }

    /// P2: a label never appears without the evidence it names.
    fn assert_honest(s: &Summary, compatibility: Compat) {
        let every_entry_usable =
            matches!(s.primary, EntryFinding::Absent | EntryFinding::V1ForLocator)
                && s.temps.v1_for_locator == s.temps.total;
        let unusable_temps =
            s.temps.empty + s.temps.too_large + s.temps.corrupt + s.temps.unsupported_version;

        match compatibility {
            Compat::BeforeFirstRenameOrAfterSecondRename => {
                assert!(
                    every_entry_usable && s.binding == BindingRelation::AllSame,
                    "{s:?}"
                );
                assert_eq!(s.layout, RecordLayout::PrimaryAndOneTemp, "{s:?}");
                assert_eq!(s.primary, EntryFinding::V1ForLocator, "{s:?}");
                assert!(!s.duplicates.valid_records, "{s:?}");
            }
            Compat::BetweenRenames => {
                assert!(
                    every_entry_usable && s.binding == BindingRelation::AllSame,
                    "{s:?}"
                );
                assert_eq!(s.layout, RecordLayout::NoPrimaryTwoTemps, "{s:?}");
                assert!(!s.duplicates.valid_records, "{s:?}");
            }
            Compat::DuplicateRecords => {
                assert!(
                    every_entry_usable && s.binding == BindingRelation::AllSame,
                    "{s:?}"
                );
                assert!(s.duplicates.valid_records, "{s:?}");
                assert!(matches!(
                    s.layout,
                    RecordLayout::PrimaryAndOneTemp | RecordLayout::NoPrimaryTwoTemps
                ));
            }
            Compat::UnusableTempBesideRecord => {
                assert_eq!(s.primary, EntryFinding::V1ForLocator, "{s:?}");
                assert!(unusable_temps >= 1 && s.temps.v1_for_locator == 0, "{s:?}");
            }
            Compat::UnusablePrimaryBesideRecord => {
                assert!(
                    matches!(
                        s.primary,
                        EntryFinding::Empty
                            | EntryFinding::TooLarge
                            | EntryFinding::Corrupt
                            | EntryFinding::UnsupportedVersion
                    ),
                    "{s:?}"
                );
                assert_eq!(s.temps.v1_for_locator, 1, "{s:?}");
            }
            Compat::OtherLocatorRecordPresent => {
                assert!(
                    s.primary == EntryFinding::V1OtherLocator || s.temps.v1_other_locator > 0,
                    "{s:?}"
                );
            }
            Compat::MixedBindings => assert_eq!(s.binding, BindingRelation::Differ, "{s:?}"),
            Compat::NotAssessed => assert!(
                s.gate == GateObservation::NewerOrUnrecognizedEvidence
                    || s.support != PhysicalSupport::Supported,
                "{s:?}"
            ),
            Compat::NoExchangeArtifacts
            | Compat::NoTestedExchangeState
            | Compat::AmbiguousPairing => {}
        }
    }

    #[test]
    fn p1_p2_the_table_is_total_correct_and_honest() {
        // PURE: the exhaustive table, against an independently written one, and the
        // label honesty of every result.
        let mut seen = std::collections::BTreeSet::new();
        let mut checked = 0u64;

        for primary in all_primaries() {
            for temps in multisets(3) {
                let layout = layout_of(primary != EntryFinding::Absent, temps.len());
                let counts = counts_of(&temps);

                for binding in all_bindings() {
                    for duplicates in all_duplicates() {
                        for gate in all_gates() {
                            for support in all_supports() {
                                let s = Summary {
                                    layout,
                                    primary,
                                    temps: counts,
                                    binding,
                                    duplicates,
                                    gate,
                                    support,
                                };
                                let got = compatibility(&s);

                                assert_eq!(got, expected(&s), "{s:?}");
                                assert_honest(&s, got);
                                seen.insert(format!("{got:?}"));

                                checked += 1;
                            }
                        }
                    }
                }
            }
        }

        // Inconsistent inputs (a layout that does not match the counts) stay
        // conservative: never a positive label.
        for layout in all_layouts() {
            for primary in all_primaries() {
                for temps in multisets(2) {
                    for binding in all_bindings() {
                        for duplicates in all_duplicates() {
                            let s = Summary {
                                layout,
                                primary,
                                temps: counts_of(&temps),
                                binding,
                                duplicates,
                                gate: GateObservation::NoGateEvidence,
                                support: PhysicalSupport::Supported,
                            };
                            let got = compatibility(&s);

                            assert_eq!(got, expected(&s), "{s:?}");

                            let consistent =
                                layout == layout_of(primary != EntryFinding::Absent, temps.len());

                            if !consistent {
                                assert_eq!(
                                    got,
                                    Compat::NoTestedExchangeState,
                                    "an inconsistent summary must stay conservative: {s:?}"
                                );
                            }

                            checked += 1;
                        }
                    }
                }
            }
        }

        eprintln!("OBSERVED p1: {checked} summaries checked; labels reached: {seen:?}");

        // Every label is reachable, so no row is dead and none is reached by default.
        assert_eq!(seen.len(), 11, "{seen:?}");

        // The named cases.
        let one = |primary, temp| Summary {
            layout: RecordLayout::PrimaryAndOneTemp,
            primary,
            temps: counts_of(&[temp]),
            binding: BindingRelation::AllSame,
            duplicates: DuplicateFindings {
                valid_records: true,
                other_content: false,
            },
            gate: GateObservation::NoGateEvidence,
            support: PhysicalSupport::Supported,
        };

        assert_eq!(
            compatibility(&one(EntryFinding::V1ForLocator, EntryFinding::V1ForLocator)),
            Compat::DuplicateRecords,
            "CASE A"
        );

        let two = Summary {
            layout: RecordLayout::NoPrimaryTwoTemps,
            primary: EntryFinding::Absent,
            temps: counts_of(&[EntryFinding::V1ForLocator, EntryFinding::V1ForLocator]),
            binding: BindingRelation::AllSame,
            duplicates: DuplicateFindings {
                valid_records: true,
                other_content: false,
            },
            gate: GateObservation::NoGateEvidence,
            support: PhysicalSupport::Supported,
        };

        assert_eq!(compatibility(&two), Compat::DuplicateRecords, "CASE B");

        // The impossible Differ + valid_records: MixedBindings wins.
        let impossible = Summary {
            binding: BindingRelation::Differ,
            ..two
        };

        assert_eq!(compatibility(&impossible), Compat::MixedBindings);
    }

    #[test]
    fn p3_precedence_each_higher_class_masks_every_lower_one() {
        // PURE.
        let mut o = Observation::new();

        o.unobservable = Some(ObservationProblem::ListingFailed);
        o.no_directory = true;
        o.changed = true;
        o.incomplete = Some(EntryProblem::Unreadable);
        assert_eq!(
            classify(&o),
            LayoutReading::Unobservable(ObservationProblem::ListingFailed)
        );

        o.unobservable = None;
        assert_eq!(classify(&o), LayoutReading::NoDirectory);

        o.no_directory = false;
        assert_eq!(classify(&o), LayoutReading::ChangedDuringAssessment);

        o.changed = false;
        assert_eq!(
            classify(&o),
            LayoutReading::Incomplete(EntryProblem::Unreadable)
        );

        o.incomplete = None;
        assert!(matches!(classify(&o), LayoutReading::Observed(_)));

        // Inside Observed: G1 > G2 > G3, shown on what would be a DuplicateRecords.
        let duplicate = Summary {
            layout: RecordLayout::NoPrimaryTwoTemps,
            primary: EntryFinding::Absent,
            temps: counts_of(&[EntryFinding::V1ForLocator, EntryFinding::V1ForLocator]),
            binding: BindingRelation::AllSame,
            duplicates: DuplicateFindings {
                valid_records: true,
                other_content: false,
            },
            gate: GateObservation::NoGateEvidence,
            support: PhysicalSupport::Supported,
        };

        assert_eq!(compatibility(&duplicate), Compat::DuplicateRecords);
        assert_eq!(
            compatibility(&Summary {
                support: PhysicalSupport::Unsupported(PhysicalReason::SharedObject),
                ..duplicate
            }),
            Compat::NotAssessed
        );
        assert_eq!(
            compatibility(&Summary {
                gate: GateObservation::NewerOrUnrecognizedEvidence,
                ..duplicate
            }),
            Compat::NotAssessed
        );
        assert_eq!(
            compatibility(&Summary {
                gate: GateObservation::NewerOrUnrecognizedEvidence,
                support: PhysicalSupport::Unsupported(PhysicalReason::NotLocalNtfs),
                ..duplicate
            }),
            Compat::NotAssessed
        );
    }

    #[test]
    fn p4_history_has_exactly_one_variant_and_the_flags_are_unconditional() {
        // PURE: an exhaustive match is a compile-time proof; a scan confirms it.
        fn only(history: HistoryStatus) {
            match history {
                HistoryStatus::NotEstablished => {}
            }
        }

        only(HistoryStatus::NotEstablished);

        let production = production_half();
        let start = production.find("pub(crate) enum HistoryStatus {").unwrap();
        let body = &production[start..];
        let body = &body[..body.find('}').unwrap()];
        let variants = body
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with("//"))
            .count();

        assert_eq!(variants, 1);

        // Every report built from any observation says NotEstablished.
        let mut observation = Observation::new();

        observation.primary = Some(Seen::not_plain());

        assert_eq!(
            report(classify(&observation)).history,
            HistoryStatus::NotEstablished
        );
    }

    #[test]
    fn p5_binding_relation_compares_four_fields_exactly_and_nothing_else() {
        // PURE.
        let base = rev(1);
        let alone: [(&str, SyncState); 4] = [
            (
                "binding id",
                state_with(LOCAL, TARGET, OTHER_BINDING, VAULT, 1),
            ),
            (
                "vault tag",
                state_with(LOCAL, TARGET, BINDING, OTHER_VAULT, 1),
            ),
            (
                "target locator",
                state_with(LOCAL, OTHER_TARGET, BINDING, VAULT, 1),
            ),
            (
                "local locator (ASCII case)",
                state_with(&LOCAL.to_ascii_lowercase(), TARGET, BINDING, VAULT, 1),
            ),
        ];

        for (name, other) in &alone {
            assert_eq!(
                binding_relation(&[&base, other]),
                BindingRelation::Differ,
                "{name}"
            );
        }

        // Fields that are NOT bindings never matter: revision, high-water, base.
        assert_eq!(
            binding_relation(&[&base, &rev(2)]),
            BindingRelation::AllSame
        );
        assert_eq!(
            binding_relation(&[&with_high_water(10), &with_high_water(3)]),
            BindingRelation::AllSame
        );
        assert_eq!(binding_relation(&[]), BindingRelation::NoValidRecords);
        assert_eq!(binding_relation(&[&base]), BindingRelation::Single);

        // The ASCII-case variant is still a record FOR the locator (path identity), but
        // the binding comparison is exact.
        let variant = judged(
            facts(1, false, FileSystemKind::Ntfs, true),
            Content::Within(alone[3].1.encode().unwrap()),
        );

        assert_eq!(variant.finding, EntryFinding::V1ForLocator);
        assert!(!same_binding(&base, &alone[3].1));
    }

    fn has_hex_run(text: &str, length: usize) -> bool {
        let mut run = 0usize;

        for character in text.chars() {
            if character.is_ascii_hexdigit() {
                run += 1;

                if run >= length {
                    return true;
                }
            } else {
                run = 0;
            }
        }

        false
    }

    #[test]
    fn p6_no_debug_output_reveals_a_path_key_token_locator_or_digest() {
        // PURE (plus one populated report from a real assessment).
        let fx = Fx::with_state("p6", &rev(1));

        fx.add_temp(&bytes_of(2));

        let populated = fx.assess();
        let mut rendered: Vec<String> =
            vec![format!("{populated:?}"), format!("{:?}", report(populated))];

        macro_rules! all {
            ($($value:expr),+ $(,)?) => { $( rendered.push(format!("{:?}", $value)); )+ };
        }

        all!(
            LayoutReading::NoDirectory,
            LayoutReading::ChangedDuringAssessment,
            LayoutReading::Incomplete(EntryProblem::OpenRefused),
            LayoutReading::Incomplete(EntryProblem::Unreadable),
            LayoutReading::Incomplete(EntryProblem::IdentityUncertain),
            ObservationProblem::AncestorNotPlain,
            ObservationProblem::DirectoryNotPlain,
            ObservationProblem::DirectoryUnreadable,
            ObservationProblem::NotLocalNtfs,
            ObservationProblem::DirectoryIdentityUnavailable,
            ObservationProblem::ListingFailed,
            ObservationProblem::ListingIncomplete,
            ObservationProblem::EntryLimit,
            ObservationProblem::RelatedEntryLimit,
            ObservationProblem::AliasAmbiguity,
            HistoryStatus::NotEstablished,
            TempFindings::default(),
            ForeignNames {
                retired: true,
                reserved_stage: true,
                unrecognized: true
            },
            PhysicalFindings {
                not_plain: true,
                delete_pending: true,
                shared_object: true,
                outside_names: true,
                non_canonical_primary: true,
                not_local_ntfs: true
            },
            DuplicateFindings {
                valid_records: true,
                other_content: true
            },
        );

        for layout in all_layouts() {
            all!(layout);
        }
        for finding in all_primaries() {
            all!(finding);
        }
        for binding in all_bindings() {
            all!(binding);
        }
        for gate in all_gates() {
            all!(gate);
        }
        for support in all_supports() {
            all!(support);
        }
        for compatibility in [
            Compat::NotAssessed,
            Compat::NoExchangeArtifacts,
            Compat::BeforeFirstRenameOrAfterSecondRename,
            Compat::BetweenRenames,
            Compat::UnusableTempBesideRecord,
            Compat::UnusablePrimaryBesideRecord,
            Compat::OtherLocatorRecordPresent,
            Compat::MixedBindings,
            Compat::DuplicateRecords,
            Compat::NoTestedExchangeState,
            Compat::AmbiguousPairing,
        ] {
            all!(compatibility);
        }

        let forbidden = [
            fx.key(),
            "LOCAL-MARKER".to_owned(),
            "OTHER-MARKER".to_owned(),
            "TARGET-MARKER".to_owned(),
            "Synthetic".to_owned(),
            "sync-state".to_owned(),
            ".qa-local".to_owned(),
        ];

        for text in &rendered {
            assert!(!has_hex_run(text, 8), "a hex run in {text}");
            assert!(
                !text.contains('\\') && !text.contains(":/"),
                "a path in {text}"
            );

            for mark in &forbidden {
                assert!(!text.contains(mark.as_str()), "{mark} leaked in {text}");
            }
        }
    }

    #[test]
    fn p7_every_type_is_copy_and_the_reading_is_must_use() {
        // PURE: a compile-time assertion.
        fn assert_copy<T: Copy + std::fmt::Debug + PartialEq + Eq>() {}

        assert_copy::<LayoutReading>();
        assert_copy::<ObservationProblem>();
        assert_copy::<EntryProblem>();
        assert_copy::<LayoutReport>();
        assert_copy::<RecordLayout>();
        assert_copy::<EntryFinding>();
        assert_copy::<TempFindings>();
        assert_copy::<BindingRelation>();
        assert_copy::<DuplicateFindings>();
        assert_copy::<GateObservation>();
        assert_copy::<ForeignNames>();
        assert_copy::<PhysicalFindings>();
        assert_copy::<PhysicalSupport>();
        assert_copy::<PhysicalReason>();
        assert_copy::<ExchangeCompatibility>();
        assert_copy::<HistoryStatus>();

        let source = production_half();
        let start = source.find("pub(crate) enum LayoutReading").unwrap();

        assert!(source[..start].trim_end().ends_with("#[must_use]"));
    }

    fn fragments(parts: &[&str]) -> String {
        parts.concat()
    }

    fn source() -> &'static str {
        include_str!("legacy_layout_assessment.rs")
    }

    fn production_half() -> &'static str {
        let marker = concat!("// ---- ", "tests ----");

        assert_eq!(
            source().matches(marker).count(),
            1,
            "exactly one tests marker"
        );

        source().split(marker).next().unwrap()
    }

    /// The production half without its comment lines.
    fn production_code() -> String {
        production_half()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn p8_the_production_half_cannot_mutate_or_reach_anything_else() {
        // PURE: a text scan of this very file.
        let code = production_code();

        for needle in [
            "fs::rename",
            "remove_file",
            "remove_dir",
            "hard_link",
            "fs::copy",
            "fs::write",
            ".write(",
            "write(true)",
            "create(true)",
            "create_new",
            "truncate",
            "set_len",
            "access_mode(",
            "share_mode(",
            "DELETE",
            "delete_by_handle",
            "rename_into_directory_no_replace",
            "mark_for_removal",
            "HeldFile",
            "DirectoryPin",
            "open_directory_pin",
            "new_v4",
            "getrandom",
            ".create(",
            ".replace(",
            ".delete(",
            "delete_if_evidence_matches",
            ".encode(",
            "modified(",
            "created(",
            "accessed(",
            "SystemTime",
            "Instant",
            "Command",
            "thread",
            "temp_dir",
            "high_water",
            "revision(",
            "base(",
            "pending_push",
        ] {
            assert!(!code.contains(needle), "{needle:?} in the production half");
        }

        // Whole file: text constraints of the other modules' scan tests.
        let whole = source();

        for parts in [
            &["uns", "afe"][..],
            &["ext", "ern"],
            &["al", "low("],
            &["cfg", "_attr("],
            &["inspect_", "v3_layout"],
            &["V3", "Layout"],
            &["Layout", "Primary"],
            &["Layout", "Sibling"],
            &["Layout", "Uncertainty"],
            &["Sibling", "Kind"],
            &["Sibling", "Content"],
            &["Sibling", "Verdict"],
            &["Sibling", "Report"],
            &["State", "Assessment"],
            &["NonAuthoritative", "Primary"],
            &["recognize_", "v3_sibling_name"],
            &["read_", "record("],
            &["load_", "authenticated_sync_state"],
            &["assess_", "authenticated_sync_state"],
            &["authenticated", "_state"],
            &["exchange", "_recovery"],
            &["target", "_exchange"],
            &["assess_", "interrupted_exchange"],
            &["Exchange", "RecoveryAssessment"],
            &["impl ", "Drop"],
        ] {
            let needle = fragments(parts);

            assert!(!whole.contains(&needle), "{needle:?} appears in this file");
        }

        // The other module is named only inside the tests.
        assert!(!production_half().contains(&fragments(&["legacy_record", "_exchange"])));

        // Read-only opens only: one open for files, one for directories.
        assert_eq!(code.matches("OpenOptions::new()").count(), 2);
        assert_eq!(code.matches(".read(true)").count(), 2);
        assert!(code.contains("FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT"));
    }

    #[test]
    fn p9_no_name_in_the_production_half_reads_like_a_permission_or_an_action() {
        // PURE.
        let code = production_code();
        let allowed = [
            "DeletePending",
            "delete_pending",
            "is_delete_pending",
            "NewerOrUnrecognizedEvidence",
        ];
        let words = [
            "recover", "restor", "safe", "authori", "trust", "adopt", "approv", "permit", "allow",
            "grant", "winner", "prefer", "choose", "select", "newest", "latest", "older", "newer",
            "release", "publish", "finalize", "delete", "remove", "write", "repair",
        ];
        let mut identifiers = std::collections::BTreeSet::new();

        for token in code.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if !token.is_empty() {
                identifiers.insert(token.to_owned());
            }
        }

        assert!(identifiers.contains("assess_legacy_layout"));

        for name in &identifiers {
            if allowed.contains(&name.as_str()) {
                continue;
            }

            let lowered = name.to_ascii_lowercase();

            for word in words {
                assert!(!lowered.contains(word), "{name} looks like a {word} name");
            }
        }
    }

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

    #[test]
    fn p10_nothing_reaches_the_module_and_it_is_private_and_test_only() {
        // PURE: a scan of the source tree.
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let source_root = manifest.join("src");
        let mut sources = Vec::new();

        collect(&source_root, &["rs"], &mut sources);

        let mut mentioning: Vec<String> = sources
            .iter()
            .filter(|(_, text)| text.contains("legacy_layout_assessment"))
            .map(|(path, _)| {
                path.strip_prefix(&source_root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        mentioning.sort();

        // The module, its declaration, and the amended allowlist of the G12R-1
        // isolation test (which must name this module to allow it).
        assert_eq!(
            mentioning,
            [
                "vault/legacy_layout_assessment.rs",
                "vault/legacy_record_exchange.rs",
                "vault/mod.rs"
            ]
        );

        let (_, declaration) = sources
            .iter()
            .find(|(path, _)| path.ends_with("vault/mod.rs") || path.ends_with("vault\\mod.rs"))
            .unwrap();

        assert!(
            declaration.contains("#[cfg(all(test, windows))]\nmod legacy_layout_assessment;")
                || declaration
                    .contains("#[cfg(all(test, windows))]\r\nmod legacy_layout_assessment;")
        );
        assert_eq!(declaration.matches("legacy_layout_assessment").count(), 1);
        assert!(!declaration.contains("pub mod legacy_layout_assessment"));
        assert!(!declaration.contains("pub(crate) mod legacy_layout_assessment"));

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
                !text.contains("legacy_layout_assessment"),
                "{}",
                path.display()
            );
        }

        // No production function takes a reading or a report as a parameter.
        let code = production_code();

        for signature in code.split("fn ").skip(1) {
            let head = signature.split(['{', ';']).next().unwrap();
            let parameters = head.split("->").next().unwrap();

            assert!(
                !parameters.contains("LayoutReading") && !parameters.contains("LayoutReport"),
                "{head}"
            );
        }
    }

    #[test]
    fn p11_the_scratch_base_is_the_dedicated_directory_and_never_the_temp_directory() {
        // PURE.
        let base = scratch_base();

        assert!(base.ends_with(Path::new(".qa-local").join("legacy-layout-assessment-tests")));
        assert!(!base.starts_with(std::env::temp_dir()));
    }
}
