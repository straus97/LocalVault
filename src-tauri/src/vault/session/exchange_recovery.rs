//! Dormant, read-only classifier for an interrupted bound-target exchange
//! (Stage 1U-4, slice B3b-2a).
//!
//! # What it is
//!
//! [`UnlockedVaultSession::assess_interrupted_exchange`] answers one diagnostic
//! question from fresh evidence: *given the stored pending push, which of the
//! states of the held-handle exchange of B3b-1 (`T -> R`, then `S -> T`) does the
//! target folder look like right now?* `T` is the bound target, `R` the retention
//! name and `S` the staging name, both derived from the persisted
//! `PendingPush::intent_id`. The answer is a fixed category
//! ([`ExchangeRecoveryAssessment`]); nothing else leaves this module.
//!
//! Nothing calls it: no command, event, `AppState` wrapper, startup hook or UI
//! reaches this module, and a test scans for that.
//!
//! # What it is not
//!
//! * **The result is a diagnostic snapshot and authorizes nothing.** No
//!   [`ExchangeState`] means "recoverable", "safe to restore" or "may be
//!   replaced". There is no approval, consent or restore type, and nothing here
//!   is a reason to move, delete, retry or finalize anything.
//! * It is strictly read-only. It writes no vault bytes, creates no staging file,
//!   renames, restores and deletes nothing, never modifies or clears the
//!   sync-state record, never finalizes a push or advances a baseline, never
//!   retries an exchange, draws no randomness, and never opens a file or
//!   directory with write or DELETE access or with a restrictive share mode. A
//!   post-crash state is left exactly as found.
//! * The record is **unauthenticated** (the sync-state checksum is not a MAC;
//!   G-AUTH stays unresolved), so a stored fingerprint or intent id is never
//!   treated as authority on its own. An exchange id is never invented: with a
//!   pending push the id is the persisted intent id, without one no id exists
//!   and only the *shape* of a name is looked for.
//! * A filename is not ownership. SHA-256 equality is not a MAC. Authenticated
//!   revision order is not causal ancestry. A readback is not durability, and a
//!   local miss is never remote-provider absence.
//!
//! # Evidence
//!
//! The three slots are read through [`SyncFileTarget::read`], unchanged, so every
//! protection of the adapter applies (plain-file ancestors, no-follow open,
//! bounded read, change detection). A slot is judged only if its physical
//! identity is established (local NTFS, one hard link, not delete-pending,
//! distinct from the vault's own file) and its bytes authenticate under the Vault
//! Key through core's `inspect_remote_bytes`; the intent and the checkpoint are
//! then compared by core's `PushIntent::reconcile` plus the exact authenticated
//! revision. No cryptographic shortcut is taken here.
//!
//! The directory is surveyed twice, before and after the reads, each time
//! read-only, bounded by [`MAX_SURVEY_ENTRIES`] and fail-closed. The directory
//! identity comes from `directory_identity_of` on a handle opened read-only, with
//! full sharing, `FILE_FLAG_BACKUP_SEMANTICS` and `FILE_FLAG_OPEN_REPARSE_POINT`;
//! any failure of that lookup is [`ListingProblem::DirectoryIdentityUnavailable`]
//! and no file metadata or path equality is ever substituted for it. Absence of an
//! artifact is claimed only by a complete, unchanged, alias-free listing.
//!
//! # Limits (not claimed away)
//!
//! * **Directory TOCTOU remains.** The survey is a snapshot. Without a pin the
//!   parent can be renamed away, substituted and restored between the checks;
//!   entries can appear and vanish between a survey and a read in ways that cancel
//!   out; a redirection installed after the ancestor check is not excluded. The
//!   directory identity is driver-reported.
//! * Nothing here establishes quiescence: another process may be writing right
//!   now. Nothing establishes durability or ordering: after a power loss the
//!   directory may show any order of the renames.
//! * Cross-volume ordering, ReFS, SMB, FAT, cloud placeholders and clients,
//!   privileged or filter-driver interference and other Windows builds are not
//!   covered.
//!
//! Every type here is a fixed category: no `Debug` output contains a path, leaf,
//! locator, identifier, fingerprint, revision or native status.
#![cfg_attr(not(test), allow(dead_code))]

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::Path,
};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};

use localvault_core::{
    sync::{
        inspect_remote_bytes, AuthenticatedRevision, BoundInspectionError, InspectionError,
        PushReconciliation, RemoteObservation,
    },
    sync_state::{BindingMismatch, PendingPush, SyncBase, SyncCheckpoint},
};

use super::{
    bind_loaded, physical_distinct, target_is_unc, CorruptReason, HeldPrimary, SessionSyncState,
    StateLoad, SyncFileRead, SyncFileTarget, SyncStateRoot, SyncStateStore, SyncStateUnavailable,
    UnavailableReason, UnlockedVaultSession, UnreadableReason,
};
use crate::vault::{
    file_identity::{directory_identity_of, volume_facts_of, FileIdentity},
    target_exchange::{
        ancestors_are_plain, is_plain_directory, ArtifactKind, ArtifactPattern, ExchangeId,
        ExchangeNames,
    },
};

/// Most directory entries one survey examines. Memory is constant (no name is
/// kept) and the work per entry is bounded by the NTFS name limit; at most two
/// surveys run, so one assessment looks at no more than twice this many entries.
/// Exceeding it is a refusal, never a claim of absence.
const MAX_SURVEY_ENTRIES: usize = 10_000;

/// The longest file name NTFS accepts, in UTF-16 code units. A longer listing
/// entry cannot be a real name and is never compared.
const MAX_NAME_UNITS: usize = 255;

// ---- the result ------------------------------------------------------------------

/// Result of [`UnlockedVaultSession::assess_interrupted_exchange`].
///
/// Diagnostic only. No variant authorizes, schedules or prepares a recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum ExchangeRecoveryAssessment {
    /// The stored record could not anchor the assessment. Nothing was read from
    /// the target folder beyond what is needed to refuse.
    RecordUnusable(RecordProblem),
    /// No push is pending, so there is no exchange to describe and no exchange id.
    /// Only the shape of artifact names was looked for (zero slot reads).
    NoPendingExchange { artifacts: ArtifactIndicators },
    /// A push is pending on a record that has no baseline (an initial
    /// publication). That is not an exchange of an existing file. Zero reads.
    NotAnExchange,
    /// A pending push over a based record, classified from the three slots.
    Classified {
        state: ExchangeState,
        evidence: ExchangeEvidence,
        /// Names of the right shape that are not this exchange's own artifacts.
        /// Indicators only: never ownership.
        unlinked: ArtifactIndicators,
    },
}

/// Why the record could not anchor the assessment. Fixed categories; the nested
/// types are existing redacted categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordProblem {
    Unavailable(SyncStateUnavailable),
    NotConfigured,
    Corrupt(CorruptReason),
    UnsupportedVersion,
    Unreadable(UnreadableReason),
    BindingMismatch(BindingMismatch),
    TargetInvalidLocator,
    TargetIsVaultFile,
    TargetIsNetworkPath,
    /// The staging or retention name cannot be derived for this target and intent.
    NamesUnderivable,
}

/// What a complete listing says about names of the exchange-artifact shape that
/// are not part of the assessed exchange. **Indicators only.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactIndicators {
    /// A complete, consistent, unchanged and alias-free listing showed none.
    NoneFound,
    Found {
        staging_like: bool,
        retention_like: bool,
    },
    /// A name equal to the target or an artifact name only after case folding.
    AmbiguousNames,
    /// The directory could not be examined completely: absence is not claimed.
    Unknown(ListingProblem),
}

/// Why a directory survey could not be completed or trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListingProblem {
    ParentMissing,
    ParentUnreadable,
    ParentNotPlain,
    AncestorNotPlain,
    NotLocalNtfs,
    /// `directory_identity_of` gave no identity (at any of its uses).
    DirectoryIdentityUnavailable,
    ReadFailed,
    IterationFailed,
    TooManyEntries,
    /// The two surveys, or the directory handle and the second survey, differ.
    ChangedDuringAssessment,
}

/// What the directory evidence amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListingVerdict {
    /// Complete, unchanged, alias-free, and agreeing with the three slot reads.
    Consistent,
    /// A name equals the target or an artifact name only after case folding.
    Ambiguous,
    /// The listing and a slot read contradict each other.
    Disagrees,
    Unavailable(ListingProblem),
}

/// What one of the three names holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    /// Not found in a verified local folder. Never remote-provider absence.
    Absent,
    /// Authenticates, and is exactly the recorded baseline.
    Baseline,
    /// Authenticates, and is exactly the recorded intended version.
    Intended,
    /// Readable, and definitely not an authentic envelope of this vault (empty,
    /// oversized, malformed or failing authentication).
    Invalid,
    /// Authentic for this vault, but neither the baseline nor the intended version.
    OtherVersion,
    /// A directory, link, junction or other non-file object.
    UnexpectedObject,
    /// Could not be inspected (I/O, change during the read, unsupported, or not
    /// the requested name).
    Unreadable,
    /// Read, but its physical identity is not certain enough to judge.
    IdentityUncertain,
}

impl Slot {
    /// Not inspected: nothing may be concluded about what this name holds.
    fn is_uninspectable(self) -> bool {
        matches!(self, Self::Unreadable | Self::IdentityUncertain)
    }

    /// Fully inspected and definitely neither the baseline nor the intended one.
    fn is_defect(self) -> bool {
        matches!(
            self,
            Self::Invalid | Self::OtherVersion | Self::UnexpectedObject
        )
    }
}

/// The three slots and the directory evidence behind them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExchangeEvidence {
    /// The bound target `T`.
    pub(crate) target: Slot,
    /// The retention name `R`.
    pub(crate) retained: Slot,
    /// The staging name `S`.
    pub(crate) staging: Slot,
    pub(crate) listing: ListingVerdict,
}

/// A description of the folder. Never an authorization, whatever the variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeState {
    /// `T` is the baseline; `R` and `S` are absent.
    NotStarted,
    /// `T` is the baseline; `S` holds the intended version; `R` is absent.
    StagedIntended,
    /// `T` is the baseline; `R` is absent; `S` holds something definite that is not
    /// the intended version.
    StagedInvalid,
    /// `T` is absent; `R` is the baseline; `S` holds the intended version.
    BetweenRenames,
    /// `T` is the intended version; `R` is the baseline; `S` is absent.
    ExchangedNotFinalized,
    /// `T` is the intended version, `S` is absent, and `R` is missing or
    /// definitely not the baseline.
    ExchangedPreviousNotVerified,
    /// `T` holds something definite that is not ours; the baseline is at `R`.
    TargetOccupied,
    /// Some evidence could not be inspected or trusted.
    Indeterminate,
    /// Fully inspected, and it contradicts every legitimate sequence.
    Inconsistent,
}

// ---- classification (pure) ---------------------------------------------------------

/// The classification precedence, first match wins:
///
/// 1. P0: any listing verdict but `Consistent` is `Indeterminate`.
/// 2. P1: any uninspectable slot is `Indeterminate`, so a clean or defect state can
///    never hide an unreadable staging or retention object.
/// 3. P2: exactly one of the four clean patterns.
/// 4. P3: the definite, fully inspected defects, under their exact conditions.
/// 5. P4: everything else is `Inconsistent`.
fn classify(evidence: ExchangeEvidence) -> ExchangeState {
    use ExchangeState as State;
    use Slot::{Absent, Baseline, Intended};

    let ExchangeEvidence {
        target,
        retained,
        staging,
        listing,
    } = evidence;

    if listing != ListingVerdict::Consistent {
        return State::Indeterminate;
    }

    if [target, retained, staging]
        .into_iter()
        .any(Slot::is_uninspectable)
    {
        return State::Indeterminate;
    }

    match (target, retained, staging) {
        (Baseline, Absent, Absent) => State::NotStarted,
        (Baseline, Absent, Intended) => State::StagedIntended,
        (Absent, Baseline, Intended) => State::BetweenRenames,
        (Intended, Baseline, Absent) => State::ExchangedNotFinalized,
        (Baseline, Absent, defect) if defect.is_defect() => State::StagedInvalid,
        (Intended, previous, Absent) if previous == Absent || previous.is_defect() => {
            State::ExchangedPreviousNotVerified
        }
        (occupant, Baseline, other)
            if occupant.is_defect()
                && (other == Absent || other == Intended || other.is_defect()) =>
        {
            State::TargetOccupied
        }
        _ => State::Inconsistent,
    }
}

// ---- the directory survey -----------------------------------------------------------

/// What one survey saw. `Copy` and compared as a whole between the two surveys.
/// Carries no name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observed {
    /// Whether the exact name of `T`, `R` and `S` was listed (`R`, `S` only with an
    /// exchange).
    exact: [bool; 3],
    /// A name equal to one of the three only after case folding.
    alias: bool,
    /// Another name of the staging shape.
    staging_like: bool,
    /// Another name of the retention shape.
    retention_like: bool,
    directory: FileIdentity,
}

/// One survey: what was seen, and the directory handle it was seen through.
struct Survey {
    observed: Observed,
    directory: File,
}

type EntryIter = Box<dyn Iterator<Item = io::Result<OsString>>>;

/// The listing seam. Production always passes [`read_directory`]; tests inject
/// failures.
type Entries<'a> = dyn FnMut(&Path) -> io::Result<EntryIter> + 'a;

fn read_directory(parent: &Path) -> io::Result<EntryIter> {
    Ok(Box::new(
        fs::read_dir(parent)?.map(|entry| entry.map(|entry| entry.file_name())),
    ))
}

/// Survey the folder of `target_path`: verify it, identify it, and classify at most
/// `limit` entry names without keeping any. Read-only.
fn survey_with_limit(
    target_path: &Path,
    pattern: &ArtifactPattern,
    own: Option<&ExchangeNames>,
    entries: &mut Entries<'_>,
    limit: usize,
) -> Result<Survey, ListingProblem> {
    use ListingProblem as Problem;

    let (Some(parent), Some(leaf)) = (target_path.parent(), target_path.file_name()) else {
        return Err(Problem::ParentMissing);
    };

    // S1: the folder is a plain directory.
    match fs::symlink_metadata(parent) {
        Ok(metadata) if is_plain_directory(&metadata) => {}
        Ok(_) => return Err(Problem::ParentNotPlain),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(Problem::ParentMissing)
        }
        Err(_) => return Err(Problem::ParentUnreadable),
    }

    // S2: and so is every ancestor.
    if !ancestors_are_plain(target_path) {
        return Err(Problem::AncestorNotPlain);
    }

    // S3: opened read-only with full sharing, never following a link. No access or
    // share mode is requested, so nothing is blocked and nothing can be changed.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(parent)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Problem::ParentMissing
            } else {
                Problem::ParentUnreadable
            }
        })?;

    match directory.metadata() {
        Ok(metadata) if is_plain_directory(&metadata) => {}
        Ok(_) => return Err(Problem::ParentNotPlain),
        Err(_) => return Err(Problem::ParentUnreadable),
    }

    // S4: a verified local NTFS volume.
    match volume_facts_of(&directory) {
        Ok(volume) if volume.is_local_ntfs() => {}
        _ => return Err(Problem::NotLocalNtfs),
    }

    // S5: the physical identity of the directory, from the directory API only.
    // There is no fallback to file metadata or to path equality.
    let identity =
        directory_identity_of(&directory).map_err(|_| Problem::DirectoryIdentityUnavailable)?;

    // S6: a bounded, complete iteration.
    let leaves = [
        Some(leaf),
        own.map(ExchangeNames::retention_leaf),
        own.map(ExchangeNames::staging_leaf),
    ];
    let mut observed = Observed {
        exact: [false; 3],
        alias: false,
        staging_like: false,
        retention_like: false,
        directory: identity,
    };
    let mut seen = 0usize;

    for entry in entries(parent).map_err(|_| Problem::ReadFailed)? {
        let name = entry.map_err(|_| Problem::IterationFailed)?;

        seen += 1;

        if seen > limit {
            return Err(Problem::TooManyEntries);
        }

        // No real name is longer than this; it cannot alias anything either.
        if name.encode_wide().take(MAX_NAME_UNITS + 1).count() > MAX_NAME_UNITS {
            continue;
        }

        if let Some(index) = leaves.iter().position(|own| *own == Some(name.as_os_str())) {
            observed.exact[index] = true;
        } else if leaves
            .iter()
            .flatten()
            .any(|own| pattern.folds_equal(&name, own))
        {
            observed.alias = true;
        } else {
            match pattern.recognize(&name) {
                Some(ArtifactKind::StagingLike) => observed.staging_like = true,
                Some(ArtifactKind::RetentionLike) => observed.retention_like = true,
                None => {}
            }
        }
    }

    Ok(Survey {
        observed,
        directory,
    })
}

/// What the two surveys, the directory handle and the slot reads amount to.
/// `slots` is `None` when there are no reads to cross-check.
fn judge_listing(
    first: &Result<Survey, ListingProblem>,
    second: Option<&Result<Survey, ListingProblem>>,
    slots: Option<[Slot; 3]>,
) -> ListingVerdict {
    use ListingProblem as Problem;

    let first = match first {
        Ok(first) => first,
        Err(problem) => return ListingVerdict::Unavailable(*problem),
    };

    let second = match second {
        Some(Ok(second)) => second,
        Some(Err(problem)) => return ListingVerdict::Unavailable(*problem),
        // Constructed only after a first survey succeeded; fail closed regardless.
        None => return ListingVerdict::Unavailable(Problem::ChangedDuringAssessment),
    };

    if first.observed != second.observed {
        return ListingVerdict::Unavailable(Problem::ChangedDuringAssessment);
    }

    // The very handle the first survey was made through must still be that
    // directory, and the second survey (by path) must have found the same one.
    match directory_identity_of(&first.directory) {
        Ok(identity) if identity == first.observed.directory => {}
        Ok(_) => return ListingVerdict::Unavailable(Problem::ChangedDuringAssessment),
        Err(_) => return ListingVerdict::Unavailable(Problem::DirectoryIdentityUnavailable),
    }

    if first.observed.alias {
        return ListingVerdict::Ambiguous;
    }

    if let Some(slots) = slots {
        for (slot, listed) in slots.iter().zip(first.observed.exact) {
            let agrees = match slot {
                Slot::Unreadable => true,
                Slot::Absent => !listed,
                _ => listed,
            };

            if !agrees {
                return ListingVerdict::Disagrees;
            }
        }
    }

    ListingVerdict::Consistent
}

/// The artifact indicators a trustworthy survey supports.
fn indicators(observed: &Observed) -> ArtifactIndicators {
    if observed.alias {
        ArtifactIndicators::AmbiguousNames
    } else if observed.staging_like || observed.retention_like {
        ArtifactIndicators::Found {
            staging_like: observed.staging_like,
            retention_like: observed.retention_like,
        }
    } else {
        ArtifactIndicators::NoneFound
    }
}

/// `NoneFound` only from a complete, consistent, unchanged, alias-free survey.
fn indicators_for(
    first: &Result<Survey, ListingProblem>,
    verdict: ListingVerdict,
) -> ArtifactIndicators {
    match (first, verdict) {
        (Ok(first), ListingVerdict::Consistent) => indicators(&first.observed),
        (_, ListingVerdict::Ambiguous) => ArtifactIndicators::AmbiguousNames,
        (_, ListingVerdict::Unavailable(problem)) => ArtifactIndicators::Unknown(problem),
        (_, ListingVerdict::Disagrees) | (Err(_), ListingVerdict::Consistent) => {
            ArtifactIndicators::Unknown(ListingProblem::ChangedDuringAssessment)
        }
    }
}

// ---- judging one slot -----------------------------------------------------------------

/// The vault's own (local) side was rejected by core while judging a slot: this is
/// a problem with the session, not with the folder.
struct LocalSideRejected;

/// One slot and, if it was established, the physical identity of what it holds.
struct Judged {
    slot: Slot,
    identity: Option<FileIdentity>,
}

fn judged(slot: Slot) -> Judged {
    Judged {
        slot,
        identity: None,
    }
}

/// Which side of `inspect_remote_bytes` a failure belongs to. The candidate is the
/// slot; anything else is the vault's own envelope.
fn fault_is_candidate(error: BoundInspectionError) -> bool {
    use localvault_core::sync::EnvelopeInput;

    match error {
        BoundInspectionError::InputTooLarge { input, .. }
        | BoundInspectionError::MalformedEnvelope { input } => input == EnvelopeInput::Candidate,
        BoundInspectionError::Inspection(InspectionError::Candidate(_)) => true,
        BoundInspectionError::Inspection(InspectionError::LocalReference(_)) => false,
    }
}

impl UnlockedVaultSession {
    /// Judge what the adapter read at `requested` against the recorded push.
    fn judge_slot(
        &self,
        primary: &HeldPrimary,
        pending: &PendingPush,
        checkpoint: &SyncCheckpoint,
        requested: &SyncFileTarget,
        outcome: SyncFileRead,
    ) -> Result<Judged, LocalSideRejected> {
        let present = match outcome {
            SyncFileRead::AbsentOnDisk => return Ok(judged(Slot::Absent)),
            SyncFileRead::Unavailable(UnavailableReason::Empty | UnavailableReason::TooLarge) => {
                return Ok(judged(Slot::Invalid))
            }
            SyncFileRead::Unavailable(UnavailableReason::UnexpectedObject) => {
                return Ok(judged(Slot::UnexpectedObject))
            }
            SyncFileRead::Unavailable(
                UnavailableReason::Io(_)
                | UnavailableReason::Changed
                | UnavailableReason::ParentMissing
                | UnavailableReason::Unsupported,
            ) => return Ok(judged(Slot::Unreadable)),
            SyncFileRead::Present(present) => present,
        };

        // Bytes paired with another name are not evidence about this one.
        if present.target() != requested.locator() {
            return Ok(judged(Slot::Unreadable));
        }

        let facts = match physical_distinct(primary, &present) {
            Ok(facts) if facts.is_local_ntfs() => facts,
            _ => return Ok(judged(Slot::IdentityUncertain)),
        };

        let bound = match inspect_remote_bytes(
            &self.vault_key,
            self.data.vault_id,
            &primary.raw,
            present.candidate_raw(),
            Some(checkpoint.high_water()),
        ) {
            Ok(bound) => bound,
            Err(error) if fault_is_candidate(error) => return Ok(judged(Slot::Invalid)),
            Err(_) => return Err(LocalSideRejected),
        };

        let revision = bound.inspection().candidate_revision();
        let observation = RemoteObservation::Present(*bound.candidate_fingerprint());

        let slot = match pending.intent().reconcile(&observation) {
            PushReconciliation::Published
                if revision == AuthenticatedRevision::Counter(pending.intended_revision()) =>
            {
                Slot::Intended
            }
            PushReconciliation::NotPublished
                if revision == AuthenticatedRevision::Counter(checkpoint.synced_revision()) =>
            {
                Slot::Baseline
            }
            _ => Slot::OtherVersion,
        };

        Ok(Judged {
            slot,
            identity: Some(facts.identity()),
        })
    }
}

// ---- the assessment ---------------------------------------------------------------------

impl UnlockedVaultSession {
    /// Assess, read-only, what an interrupted exchange of the bound target would
    /// look like on disk. See the module documentation: the result is a
    /// diagnostic snapshot and authorizes nothing.
    pub(crate) fn assess_interrupted_exchange(
        &self,
        root: &SyncStateRoot,
    ) -> ExchangeRecoveryAssessment {
        let Ok(store) = SyncStateStore::new(root.path()) else {
            return ExchangeRecoveryAssessment::RecordUnusable(RecordProblem::Unavailable(
                SyncStateUnavailable::Root,
            ));
        };

        self.assess_interrupted_exchange_in(&store, &mut SyncFileTarget::read)
    }

    /// [`assess_interrupted_exchange`](Self::assess_interrupted_exchange) over an
    /// explicit store and read step. Crate-private so only the crate's own tests
    /// can substitute them: they count reads, rewrite results and change the
    /// folder at an exact point.
    pub(crate) fn assess_interrupted_exchange_in(
        &self,
        store: &SyncStateStore,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
    ) -> ExchangeRecoveryAssessment {
        self.assess_with_limit(store, read, MAX_SURVEY_ENTRIES)
    }

    fn assess_with_limit(
        &self,
        store: &SyncStateStore,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
        limit: usize,
    ) -> ExchangeRecoveryAssessment {
        match self.assess_exchange_inner(store, read, limit) {
            Ok(assessment) => assessment,
            Err(problem) => ExchangeRecoveryAssessment::RecordUnusable(problem),
        }
    }

    fn assess_exchange_inner(
        &self,
        store: &SyncStateStore,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
        limit: usize,
    ) -> Result<ExchangeRecoveryAssessment, RecordProblem> {
        use RecordProblem as Problem;

        // 1. The primary is opened once, read-only, and must be exactly this
        //    session's envelope.
        let primary = self.hold_local_primary().ok_or(Problem::Unavailable(
            SyncStateUnavailable::LocalVaultChanged,
        ))?;

        // 2. The session's normalized local location.
        let local_locator = self
            .local_locator()
            .ok_or(Problem::Unavailable(SyncStateUnavailable::LocalLocator))?;

        // 3. The stored record, verified against the authenticated vault id and the
        //    local location. Only a bound record continues.
        let state = match store.load(&local_locator) {
            StateLoad::NotConfigured => return Err(Problem::NotConfigured),
            StateLoad::Corrupt(reason) => return Err(Problem::Corrupt(reason)),
            StateLoad::UnsupportedVersion => return Err(Problem::UnsupportedVersion),
            StateLoad::Unreadable(reason) => return Err(Problem::Unreadable(reason)),
            StateLoad::Loaded(state) => {
                match bind_loaded(*state, self.data.vault_id, &local_locator) {
                    SessionSyncState::Bound(bound) => bound.state().clone(),
                    SessionSyncState::BindingMismatch(mismatch) => {
                        return Err(Problem::BindingMismatch(mismatch))
                    }
                    // `bind_loaded` yields nothing else; anything unexpected is
                    // treated as unverified, never as a bound record.
                    _ => {
                        return Err(Problem::Unavailable(
                            SyncStateUnavailable::LocalVaultChanged,
                        ))
                    }
                }
            }
        };

        // 4. The target comes only from the verified record, and is refused before
        //    its folder is read or surveyed.
        let target = SyncFileTarget::from_locator(state.target_locator())
            .map_err(|_| Problem::TargetInvalidLocator)?;

        if target_is_unc(&target) {
            return Err(Problem::TargetIsNetworkPath);
        }

        if self.target_names_vault_file(store.directory(), &target, &local_locator) {
            return Err(Problem::TargetIsVaultFile);
        }

        // 5. The shape of this target's artifact names.
        let pattern =
            ArtifactPattern::for_target(&target).map_err(|_| Problem::NamesUnderivable)?;
        let target_path = Path::new(target.locator().as_str());

        // 6. No pending push: no exchange and no id. Two surveys, zero slot reads.
        let Some(pending) = state.pending_push() else {
            let first = survey_with_limit(target_path, &pattern, None, &mut read_directory, limit);
            let second = first.is_ok().then(|| {
                survey_with_limit(target_path, &pattern, None, &mut read_directory, limit)
            });
            let verdict = judge_listing(&first, second.as_ref(), None);

            return Ok(ExchangeRecoveryAssessment::NoPendingExchange {
                artifacts: indicators_for(&first, verdict),
            });
        };

        // A pending push over a record without a baseline is an initial publication.
        let SyncBase::Based(checkpoint) = state.base() else {
            return Ok(ExchangeRecoveryAssessment::NotAnExchange);
        };

        // 7. The exchange names, from the persisted intent id only.
        let id = ExchangeId::new(pending.intent_id()).map_err(|_| Problem::NamesUnderivable)?;
        let names = ExchangeNames::derive(&target, id).map_err(|_| Problem::NamesUnderivable)?;
        let parent = target_path.parent().ok_or(Problem::NamesUnderivable)?;
        let retention = SyncFileTarget::from_path(&parent.join(names.retention_leaf()))
            .map_err(|_| Problem::NamesUnderivable)?;
        let staging = SyncFileTarget::from_path(&parent.join(names.staging_leaf()))
            .map_err(|_| Problem::NamesUnderivable)?;

        // 8. Survey, then exactly three reads in the order T, R, S, then survey.
        //    If the first survey fails nothing is read: the folder is not trusted.
        let first = survey_with_limit(
            target_path,
            &pattern,
            Some(&names),
            &mut read_directory,
            limit,
        );
        let mut slots = [Slot::Unreadable; 3];
        let mut identities: [Option<FileIdentity>; 3] = [None; 3];
        let mut second = None;

        if first.is_ok() {
            for (index, requested) in [&target, &retention, &staging].into_iter().enumerate() {
                let outcome = read(requested);
                let judged = self
                    .judge_slot(&primary, pending, checkpoint, requested, outcome)
                    .map_err(|_| Problem::Unavailable(SyncStateUnavailable::LocalVaultChanged))?;

                slots[index] = judged.slot;
                identities[index] = judged.identity;
            }

            second = Some(survey_with_limit(
                target_path,
                &pattern,
                Some(&names),
                &mut read_directory,
                limit,
            ));
        }

        // 9. Two names that are one physical file cannot both be judged.
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            if identities[a].is_some() && identities[a] == identities[b] {
                slots[a] = Slot::IdentityUncertain;
                slots[b] = Slot::IdentityUncertain;
            }
        }

        // 10. Cross-check, then classify.
        let listing = judge_listing(&first, second.as_ref(), Some(slots));
        let evidence = ExchangeEvidence {
            target: slots[0],
            retained: slots[1],
            staging: slots[2],
            listing,
        };

        Ok(ExchangeRecoveryAssessment::Classified {
            state: classify(evidence),
            evidence,
            unlinked: indicators_for(&first, listing),
        })
    }
}

// ---- test-only code below this line (the production source ends here) ------------

// Test labels. [NTFS]: a real local NTFS volume and the real B3b-1 operations.
// [INJ]: injected facts, faults or results, which prove decision logic only. [PURE]:
// no I/O. A "restart" here is an in-process drop of every value plus a fresh unlock;
// it is not an operating-system crash and restart.
#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        fs::{self, File},
        os::windows::fs::OpenOptionsExt,
        path::PathBuf,
    };

    use uuid::Uuid;
    use windows_sys::Win32::Storage::FileSystem::DELETE;
    use zeroize::Zeroizing;

    use localvault_core::{
        sync::{EnvelopeFingerprint, PushBaseline, PushIntent, RemoteHighWater},
        sync_state::{
            begin_push, BindingId, Locator, RemoteEvidence, SyncState, VaultBindingTag,
            BINDING_SALT_LEN,
        },
    };

    use super::*;
    use crate::vault::{
        file_identity::{facts_of, FileSystemKind, HandleFacts, IdentityError},
        handle_ops::{
            delete_by_handle, inject_delete_status, inject_rename_status,
            test_support::{assert_local_ntfs, make_junction, snapshot},
        },
        session::{InitialBindingApproval, InitialBindingOutcome},
        sync_file_adapter::PresentFile,
        sync_state_store::SYNC_STATE_DIRECTORY,
        target_exchange::{ExchangeOutcome, HeldTarget, Seams, Stage, StageFault, Staged},
    };

    const NOW_MS: i64 = 1_700_000_000_000;
    const MASTER_PASSWORD: &str = "session-master-password-test-only";
    /// A mark that must never appear in any `Debug` output: it is part of the leaf.
    const LEAF: &str = "LEAKMARK-copy.lvault";
    const FOREIGN: &[u8] = b"b3b2-foreign bytes, not an envelope";
    const UNSUCCESSFUL: i32 = 0xC000_0001_u32 as i32;
    const INTENT: Uuid = Uuid::from_u128(0x0b3b_2a00_0000_4000_8000_0000_0000_00ab);
    const OTHER_ID: &str = "0b3b2a00-0000-4000-8000-0000000000cd";

    const A: Slot = Slot::Absent;
    const B: Slot = Slot::Baseline;
    const N: Slot = Slot::Intended;
    const I: Slot = Slot::Invalid;
    const O: Slot = Slot::OtherVersion;
    const E: Slot = Slot::UnexpectedObject;
    const U: Slot = Slot::Unreadable;
    const Q: Slot = Slot::IdentityUncertain;
    const ALL_SLOTS: [Slot; 8] = [A, B, N, I, O, E, U, Q];

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    /// A unique, test-owned directory under the B3 scratch base, never `%TEMP%`.
    /// Removed only by its `TempDir` guard. Fails loudly unless on local NTFS.
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

        assert_local_ntfs(dir.path());
        assert!(!dir.path().starts_with(std::env::temp_dir()));

        dir
    }

    /// Kind, name, length and modification time of everything beneath `dir`, without
    /// reading any content or following a link. Works while a file is held open with
    /// a share mode that denies reading.
    fn shallow(dir: &Path) -> Vec<String> {
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

                if metadata.is_dir()
                    && !crate::vault::target_exchange::is_plain_directory(&metadata)
                {
                    out.push(format!("J {relative}"));
                } else if metadata.is_dir() {
                    out.push(format!("D {relative}"));
                    walk(&path, base, out);
                } else {
                    out.push(format!(
                        "F {relative} {} {:?}",
                        metadata.len(),
                        metadata.modified().unwrap()
                    ));
                }
            }
        }

        let mut out = Vec::new();

        walk(dir, dir, &mut out);

        out
    }

    fn save_edit(session: &mut UnlockedVaultSession, bump: i64) {
        session.data_mut().updated_at_ms += bump;

        assert!(session.save().unwrap());
    }

    fn leaf_of(target: &SyncFileTarget) -> String {
        Path::new(target.locator().as_str())
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    /// A synthetic vault `V`, an encrypted copy `C` bound to it through the real
    /// initial binding, and (for [`Rig::pending`]) a real pending push over a local
    /// save, so that `T` holds the baseline `B` and `V` holds the intended `N`.
    /// `session` is declared first so that it (and its lock file) drops before the
    /// scratch directory is removed.
    struct Rig {
        session: UnlockedVaultSession,
        root: SyncStateRoot,
        vault: PathBuf,
        copy: PathBuf,
        dest: PathBuf,
        target: SyncFileTarget,
        names: ExchangeNames,
        dir: tempfile::TempDir,
    }

    impl Rig {
        fn unbound(name: &str) -> Self {
            let dir = scratch(name);
            let vaults = dir.path().join("vaults");
            let dest = dir.path().join("outer").join("dest");

            fs::create_dir_all(&vaults).unwrap();
            fs::create_dir_all(&dest).unwrap();

            let vault = vaults.join("vault.lvault");
            let session = UnlockedVaultSession::create(&vault, password(), NOW_MS).unwrap();
            let copy = dest.join(LEAF);

            fs::copy(&vault, &copy).unwrap();

            let target = SyncFileTarget::from_path(&copy).unwrap();
            let names = ExchangeNames::derive(&target, ExchangeId::new(INTENT).unwrap()).unwrap();

            Self {
                session,
                root: SyncStateRoot::for_test(dir.path().join("app-local")),
                vault,
                copy,
                dest,
                target,
                names,
                dir,
            }
        }

        /// Bound through the real, unchanged initial-binding operation. No push.
        fn bound(name: &str) -> Self {
            let rig = Self::unbound(name);

            assert_eq!(
                rig.session.bind_existing_identical_target_in(
                    &rig.store(),
                    &rig.target,
                    InitialBindingApproval::for_test(&rig.target),
                    &mut SyncFileTarget::read,
                    &mut |buffer| getrandom::fill(buffer).is_ok(),
                ),
                Ok(InitialBindingOutcome::BoundAndVerified)
            );

            rig
        }

        /// Bound, then a local save and a pending push recorded exactly as the core
        /// `begin_push` proposes it (fixture setup; the assessment never writes).
        fn pending(name: &str) -> Self {
            let mut rig = Self::bound(name);

            save_edit(&mut rig.session, 1);

            let state = rig.loaded_state();
            let SyncBase::Based(checkpoint) = state.base() else {
                panic!("a based state is required");
            };

            let bound = localvault_core::sync::inspect_remote_bytes(
                &rig.session.vault_key,
                rig.session.data.vault_id,
                &fs::read(&rig.vault).unwrap(),
                &fs::read(&rig.copy).unwrap(),
                Some(checkpoint.high_water()),
            )
            .unwrap();

            let proposed = begin_push(
                &state,
                state.local_locator(),
                state.target_locator(),
                RemoteEvidence::Inspected(&bound),
                INTENT,
            )
            .unwrap();

            rig.store().replace(&state, &proposed).unwrap();

            rig
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(self.root.path()).unwrap()
        }

        fn state_dir(&self) -> PathBuf {
            self.root.path().join(SYNC_STATE_DIRECTORY)
        }

        fn record(&self) -> PathBuf {
            let mut found: Vec<PathBuf> = fs::read_dir(self.state_dir())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect();

            assert_eq!(found.len(), 1, "expected exactly one record");

            found.remove(0)
        }

        fn loaded_state(&self) -> SyncState {
            match self.store().load(&self.session.local_locator().unwrap()) {
                StateLoad::Loaded(state) => *state,
                other => panic!("expected a record, found {other:?}"),
            }
        }

        /// A record built directly, for states the real operations cannot reach.
        fn craft(
            &self,
            vault_id: Uuid,
            target: &str,
            base: SyncBase,
            pending: Option<PendingPush>,
        ) -> SyncState {
            let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);

            SyncState::new(
                BindingId::new(Uuid::from_u128(0xB1)).unwrap(),
                VaultBindingTag::derive(salt, vault_id).unwrap(),
                self.session.local_locator().unwrap(),
                Locator::new(target).unwrap(),
                base,
                pending,
            )
            .unwrap()
        }

        fn put_crafted(&self, target: &str) {
            let base = SyncBase::Based(
                localvault_core::sync_state::SyncCheckpoint::new(
                    EnvelopeFingerprint::of_bytes(b"synthetic"),
                    0,
                    RemoteHighWater::new(0),
                )
                .unwrap(),
            );

            self.store()
                .create(&self.craft(self.session.data.vault_id, target, base, None))
                .unwrap();
        }

        fn t_path(&self) -> PathBuf {
            self.copy.clone()
        }

        fn r_path(&self) -> PathBuf {
            self.dest.join(self.names.retention_leaf())
        }

        fn s_path(&self) -> PathBuf {
            self.dest.join(self.names.staging_leaf())
        }

        fn baseline_bytes(&self) -> Vec<u8> {
            fs::read(self.t_path()).unwrap()
        }

        fn intended_bytes(&self) -> Vec<u8> {
            fs::read(&self.vault).unwrap()
        }

        /// The bytes of another genuine envelope of this vault that is neither the
        /// baseline nor the intended version.
        fn fork_bytes(&self, baseline: &[u8]) -> Vec<u8> {
            let folder = self.dir.path().join("fork");

            fs::create_dir_all(&folder).unwrap();

            let path = folder.join("vault.lvault");

            fs::write(&path, baseline).unwrap();

            let mut fork = UnlockedVaultSession::unlock(&path, password()).unwrap();

            save_edit(&mut fork, 2);
            drop(fork);

            fs::read(&path).unwrap()
        }

        // ---- the real B3b-1 operations, stopped at each stage ----------------------

        fn held(&self) -> HeldTarget {
            let primary = facts_of(&File::open(&self.vault).unwrap()).unwrap();
            let expected = facts_of(&File::open(&self.copy).unwrap())
                .unwrap()
                .identity();

            HeldTarget::acquire(
                &self.target,
                &self.names,
                expected,
                &primary,
                &mut Seams::none(),
            )
            .expect("acquire")
        }

        fn staged(&self) -> Staged {
            self.held()
                .stage(&self.intended_bytes(), &mut Seams::none())
                .expect("stage")
        }

        /// `T` held and never touched, then everything dropped.
        fn run_not_started(&self) {
            drop(self.held());
        }

        /// `S` created and filled, then everything dropped.
        fn run_staged(&self) {
            drop(self.staged());
        }

        /// `T -> R` accepted, the second rename not made (a native status injected at
        /// the empty-name window), then everything dropped.
        fn run_between_renames(&self) {
            let mut seams = Seams::at_stage_for_test(Stage::BetweenRenames, || {
                inject_rename_status(UNSUCCESSFUL)
            });

            let outcome = self.staged().exchange(&mut || true, &mut seams);

            assert!(
                matches!(outcome, ExchangeOutcome::Unknown(_)),
                "{outcome:?}"
            );
        }

        /// Both renames accepted and verified, the previous version retained.
        fn run_exchanged(&self) {
            let ExchangeOutcome::Exchanged(swapped) =
                self.staged().exchange(&mut || true, &mut Seams::none())
            else {
                panic!("the exchange was not accepted");
            };

            swapped
                .verify(&mut |_| true, &mut Seams::none())
                .expect("verified")
                .retain_previous();
        }

        /// Every value and the session dropped, then a fresh unlock of the vault.
        fn restart(self) -> Self {
            let Self {
                session,
                root,
                vault,
                copy,
                dest,
                target,
                names,
                dir,
            } = self;

            drop(session);

            let session = UnlockedVaultSession::unlock(&vault, password()).unwrap();

            Self {
                session,
                root,
                vault,
                copy,
                dest,
                target,
                names,
                dir,
            }
        }

        // ---- the assessment, with a no-mutation proof ---------------------------------

        /// One assessment. The whole test-owned tree is snapshotted after all setup
        /// and before every read, and must not change except by `hook`, which runs
        /// just before read `n` and is the only writer. `rewrite` may replace what
        /// read `n` returns. Returns the leaves read, in order.
        fn run(
            &self,
            limit: usize,
            full: bool,
            hook: &mut dyn FnMut(usize),
            rewrite: &mut dyn FnMut(usize, SyncFileRead) -> SyncFileRead,
        ) -> (ExchangeRecoveryAssessment, Vec<String>) {
            let take = || {
                if full {
                    snapshot(self.dir.path())
                } else {
                    shallow(self.dir.path())
                }
            };
            let store = self.store();
            let reads = RefCell::new(Vec::new());
            let expected = RefCell::new(take());

            let result = self.session.assess_with_limit(
                &store,
                &mut |target| {
                    let n = reads.borrow().len();

                    reads.borrow_mut().push(leaf_of(target));

                    assert_eq!(
                        take(),
                        *expected.borrow(),
                        "the assessment changed the filesystem before read {n}"
                    );

                    hook(n);

                    *expected.borrow_mut() = take();

                    rewrite(n, target.read())
                },
                limit,
            );

            assert_eq!(
                take(),
                *expected.borrow(),
                "the assessment changed the filesystem"
            );

            (result, reads.into_inner())
        }

        fn assess(&self) -> (ExchangeRecoveryAssessment, Vec<String>) {
            self.run(MAX_SURVEY_ENTRIES, true, &mut |_| {}, &mut |_, read| read)
        }

        fn assess_shallow(&self) -> (ExchangeRecoveryAssessment, Vec<String>) {
            self.run(MAX_SURVEY_ENTRIES, false, &mut |_| {}, &mut |_, read| read)
        }

        fn assess_with_limit(&self, limit: usize) -> (ExchangeRecoveryAssessment, Vec<String>) {
            self.run(limit, true, &mut |_| {}, &mut |_, read| read)
        }

        fn assess_rewriting(
            &self,
            rewrite: &mut dyn FnMut(usize, SyncFileRead) -> SyncFileRead,
        ) -> ExchangeRecoveryAssessment {
            let (assessment, reads) = self.run(MAX_SURVEY_ENTRIES, true, &mut |_| {}, rewrite);

            assert_eq!(reads.len(), 3);

            assessment
        }

        fn assess_hooked(&self, hook: &mut dyn FnMut(usize)) -> ExchangeRecoveryAssessment {
            self.run(MAX_SURVEY_ENTRIES, true, hook, &mut |_, read| read)
                .0
        }

        fn read_order(&self) -> Vec<String> {
            vec![
                LEAF.to_owned(),
                self.names.retention_leaf().to_string_lossy().into_owned(),
                self.names.staging_leaf().to_string_lossy().into_owned(),
            ]
        }

        /// The classified result with exactly three reads in the order T, R, S.
        fn classified(&self) -> (ExchangeState, ExchangeEvidence, ArtifactIndicators) {
            let (assessment, reads) = self.assess();

            assert_eq!(reads, self.read_order(), "{assessment:?}");

            classified_parts(assessment)
        }

        /// A consistent classification with these slots.
        fn expect(&self, state: ExchangeState, slots: [Slot; 3]) -> ArtifactIndicators {
            let (got, evidence, unlinked) = self.classified();

            assert_eq!(
                (
                    got,
                    [evidence.target, evidence.retained, evidence.staging],
                    evidence.listing
                ),
                (state, slots, ListingVerdict::Consistent),
            );

            unlinked
        }

        /// An indeterminate classification whose listing is not consistent.
        fn expect_listing(&self, problem: ListingProblem) {
            let (assessment, _) = self.assess();
            let (state, evidence, unlinked) = classified_parts(assessment);

            assert_eq!(state, ExchangeState::Indeterminate);
            assert_eq!(evidence.listing, ListingVerdict::Unavailable(problem));
            assert_eq!(unlinked, ArtifactIndicators::Unknown(problem));
        }
    }

    fn classified_parts(
        assessment: ExchangeRecoveryAssessment,
    ) -> (ExchangeState, ExchangeEvidence, ArtifactIndicators) {
        match assessment {
            ExchangeRecoveryAssessment::Classified {
                state,
                evidence,
                unlinked,
            } => (state, evidence, unlinked),
            other => panic!("expected a classification, found {other:?}"),
        }
    }

    fn present(read: SyncFileRead) -> PresentFile {
        match read {
            SyncFileRead::Present(present) => present,
            other => panic!("expected a present file, found {other:?}"),
        }
    }

    // ---- 1. restart-style reconstruction from the real B3b-1 operations ---------------

    #[test]
    fn ntfs_no_exchange_started_is_not_started() {
        let rig = Rig::pending("b3b2-not-started");

        rig.run_not_started();

        let rig = rig.restart();

        assert_eq!(
            rig.expect(ExchangeState::NotStarted, [B, A, A]),
            ArtifactIndicators::NoneFound
        );
    }

    #[test]
    fn ntfs_staged_intended_bytes_are_staged_intended() {
        let rig = Rig::pending("b3b2-staged");

        rig.run_staged();

        let rig = rig.restart();

        assert_eq!(
            rig.expect(ExchangeState::StagedIntended, [B, A, N]),
            ArtifactIndicators::NoneFound
        );
        assert_eq!(fs::read(rig.s_path()).unwrap(), rig.intended_bytes());
    }

    #[test]
    fn ntfs_the_empty_name_window_is_between_renames() {
        // [NTFS] for the first rename and the staging; [INJ] for the refused second
        // rename (a native status injected at the window). The state comes from the
        // disk, not from the outcome.
        let rig = Rig::pending("b3b2-between");

        rig.run_between_renames();

        assert!(!rig.t_path().exists());
        assert!(rig.r_path().exists() && rig.s_path().exists());

        let rig = rig.restart();

        assert_eq!(
            rig.expect(ExchangeState::BetweenRenames, [A, B, N]),
            ArtifactIndicators::NoneFound
        );
    }

    #[test]
    fn ntfs_both_renames_accepted_is_exchanged_not_finalized() {
        let rig = Rig::pending("b3b2-exchanged");

        rig.run_exchanged();

        let rig = rig.restart();

        assert_eq!(
            rig.expect(ExchangeState::ExchangedNotFinalized, [N, B, A]),
            ArtifactIndicators::NoneFound
        );
        assert_eq!(fs::read(rig.t_path()).unwrap(), rig.intended_bytes());
    }

    #[test]
    fn ntfs_the_record_is_never_modified_by_any_state() {
        let rig = Rig::pending("b3b2-record-untouched");
        let record = fs::read(rig.record()).unwrap();

        rig.run_between_renames();
        let _ = rig.assess();

        assert_eq!(fs::read(rig.record()).unwrap(), record);
        assert!(rig.loaded_state().pending_push().is_some());
    }

    // ---- 2. definite defects ----------------------------------------------------------

    #[test]
    fn inj_a_failed_staging_write_leaves_a_half_written_staging_file() {
        // [INJ] the write fault and the failing cleanup; [NTFS] what is then on disk.
        let rig = Rig::pending("b3b2-staged-invalid-inj");
        let mut seams = Seams::with_stage_fault_for_test(StageFault::Write);

        inject_delete_status(UNSUCCESSFUL);

        let failure = rig.held().stage(&rig.intended_bytes(), &mut seams);

        assert!(failure.is_err());
        drop(failure);

        let rig = rig.restart();

        assert!(rig.s_path().exists());
        rig.expect(ExchangeState::StagedInvalid, [B, A, I]);
    }

    #[test]
    fn ntfs_staging_with_something_definite_that_is_not_ours_is_staged_invalid() {
        for (label, expected_slot) in [
            ("empty", I),
            ("garbage", I),
            ("fork", O),
            ("directory", E),
            ("baseline-truncated", I),
        ] {
            let rig = Rig::pending(&format!("b3b2-staged-invalid-{label}"));
            let s = rig.s_path();

            match label {
                "empty" => fs::write(&s, b"").unwrap(),
                "garbage" => fs::write(&s, FOREIGN).unwrap(),
                "fork" => fs::write(&s, rig.fork_bytes(&rig.baseline_bytes())).unwrap(),
                "directory" => fs::create_dir(&s).unwrap(),
                _ => fs::write(&s, &rig.baseline_bytes()[..10]).unwrap(),
            }

            rig.expect(ExchangeState::StagedInvalid, [B, A, expected_slot]);
        }
    }

    #[test]
    fn ntfs_a_target_occupied_by_something_foreign_is_target_occupied() {
        let rig = Rig::pending("b3b2-occupied-garbage");

        rig.run_between_renames();
        fs::write(rig.t_path(), FOREIGN).unwrap();
        rig.expect(ExchangeState::TargetOccupied, [I, B, N]);

        // A genuine envelope of this vault that is neither of ours.
        let rig = Rig::pending("b3b2-occupied-fork");
        let baseline = rig.baseline_bytes();

        rig.run_between_renames();
        fs::write(rig.t_path(), rig.fork_bytes(&baseline)).unwrap();
        rig.expect(ExchangeState::TargetOccupied, [O, B, N]);

        // With staging gone as well, and with the previous state exchanged.
        let rig = Rig::pending("b3b2-occupied-no-staging");

        rig.run_between_renames();
        fs::write(rig.t_path(), FOREIGN).unwrap();
        fs::remove_file(rig.s_path()).unwrap();
        rig.expect(ExchangeState::TargetOccupied, [I, B, A]);
    }

    #[test]
    fn ntfs_a_missing_or_changed_previous_version_is_not_verified() {
        // R missing.
        let rig = Rig::pending("b3b2-previous-missing");

        rig.run_exchanged();
        fs::remove_file(rig.r_path()).unwrap();
        rig.expect(ExchangeState::ExchangedPreviousNotVerified, [N, A, A]);

        // R with one byte flipped.
        let rig = Rig::pending("b3b2-previous-flipped");

        rig.run_exchanged();

        let mut bytes = fs::read(rig.r_path()).unwrap();
        let middle = bytes.len() / 2;

        bytes[middle] ^= 0x01;
        fs::write(rig.r_path(), bytes).unwrap();
        rig.expect(ExchangeState::ExchangedPreviousNotVerified, [N, I, A]);

        // R replaced by an older genuine fork.
        let rig = Rig::pending("b3b2-previous-fork");
        let baseline = rig.baseline_bytes();

        rig.run_exchanged();
        fs::write(rig.r_path(), rig.fork_bytes(&baseline)).unwrap();
        rig.expect(ExchangeState::ExchangedPreviousNotVerified, [N, O, A]);
    }

    #[test]
    fn ntfs_combinations_that_no_legitimate_sequence_produces_are_inconsistent() {
        // F: only S. G: only R. H: everything. L: T and R both the baseline.
        // All absent. S a copy of the baseline. R a copy of the intended version.
        type Place = fn(&Rig);

        let cases: [(&str, Place, [Slot; 3]); 7] = [
            (
                "f",
                |rig| {
                    fs::rename(rig.t_path(), rig.s_path()).unwrap();
                    fs::write(rig.s_path(), rig.intended_bytes()).unwrap();
                },
                [A, A, N],
            ),
            (
                "g",
                |rig| fs::rename(rig.t_path(), rig.r_path()).unwrap(),
                [A, B, A],
            ),
            (
                "h",
                |rig| {
                    fs::copy(rig.t_path(), rig.r_path()).unwrap();
                    fs::write(rig.s_path(), rig.intended_bytes()).unwrap();
                    fs::write(rig.t_path(), rig.intended_bytes()).unwrap();
                },
                [N, B, N],
            ),
            (
                "l",
                |rig| {
                    fs::copy(rig.t_path(), rig.r_path()).unwrap();
                },
                [B, B, A],
            ),
            (
                "none",
                |rig| fs::remove_file(rig.t_path()).unwrap(),
                [A, A, A],
            ),
            (
                "s-is-baseline",
                |rig| {
                    fs::copy(rig.t_path(), rig.s_path()).unwrap();
                },
                [B, A, B],
            ),
            (
                "r-is-intended",
                |rig| fs::write(rig.r_path(), rig.intended_bytes()).unwrap(),
                [B, N, A],
            ),
        ];

        for (label, place, slots) in cases {
            let rig = Rig::pending(&format!("b3b2-inconsistent-{label}"));

            place(&rig);
            rig.expect(ExchangeState::Inconsistent, slots);
        }
    }

    // ---- 3. an uninspectable object is never hidden behind a clean or defect state ----

    #[test]
    fn ntfs_an_unreadable_staging_file_is_indeterminate_not_staged_invalid() {
        let rig = Rig::pending("b3b2-share-zero");

        rig.run_staged();

        // Held with a share mode that denies every other open, so it cannot be read.
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(rig.s_path())
            .unwrap();

        let (assessment, reads) = rig.assess_shallow();
        let (state, evidence, _) = classified_parts(assessment);

        assert_eq!(reads, rig.read_order());
        assert_eq!(state, ExchangeState::Indeterminate);
        assert_eq!(
            (evidence.target, evidence.retained, evidence.staging),
            (B, A, U)
        );

        drop(held);

        rig.expect(ExchangeState::StagedIntended, [B, A, N]);
    }

    #[test]
    fn ntfs_hard_links_make_a_slot_uncertain_and_the_result_indeterminate() {
        let control = |rig: &Rig| {
            let folder = rig.dir.path().join("control");

            fs::create_dir_all(&folder).unwrap();

            folder
        };

        // T with a second name (instead of a clean "not started").
        let rig = Rig::pending("b3b2-link-t");

        fs::hard_link(rig.t_path(), control(&rig).join("t-link")).unwrap();
        rig.expect(ExchangeState::Indeterminate, [Q, A, A]);

        // S with a second name (not "staged invalid" or "staged intended").
        let rig = Rig::pending("b3b2-link-s");

        rig.run_staged();
        fs::hard_link(rig.s_path(), control(&rig).join("s-link")).unwrap();
        rig.expect(ExchangeState::Indeterminate, [B, A, Q]);

        // R with a second name (not "previous not verified" or "not finalized").
        let rig = Rig::pending("b3b2-link-r");

        rig.run_exchanged();
        fs::hard_link(rig.r_path(), control(&rig).join("r-link")).unwrap();
        rig.expect(ExchangeState::Indeterminate, [N, Q, A]);

        // S and R are one physical file.
        let rig = Rig::pending("b3b2-link-s-r");

        rig.run_between_renames();
        fs::remove_file(rig.s_path()).unwrap();
        fs::hard_link(rig.r_path(), rig.s_path()).unwrap();
        rig.expect(ExchangeState::Indeterminate, [A, Q, Q]);
    }

    #[test]
    fn ntfs_a_hard_link_to_the_vault_itself_is_uncertain() {
        let rig = Rig::pending("b3b2-link-primary");

        fs::hard_link(&rig.vault, rig.s_path()).unwrap();
        rig.expect(ExchangeState::Indeterminate, [B, A, Q]);
    }

    #[test]
    fn ntfs_reparse_objects_and_junctions_are_definite_unexpected_objects() {
        let rig = Rig::pending("b3b2-junction-r");
        let elsewhere = rig.dir.path().join("elsewhere");

        fs::create_dir(&elsewhere).unwrap();
        make_junction(&rig.r_path(), &elsewhere);
        rig.expect(ExchangeState::Inconsistent, [B, E, A]);

        let rig = Rig::pending("b3b2-junction-t");
        let elsewhere = rig.dir.path().join("elsewhere");

        rig.run_between_renames();
        fs::create_dir(&elsewhere).unwrap();
        make_junction(&rig.t_path(), &elsewhere);
        rig.expect(ExchangeState::TargetOccupied, [E, B, N]);

        let rig = Rig::pending("b3b2-junction-s");
        let elsewhere = rig.dir.path().join("elsewhere");

        fs::create_dir(&elsewhere).unwrap();
        make_junction(&rig.s_path(), &elsewhere);
        rig.expect(ExchangeState::StagedInvalid, [B, A, E]);
    }

    #[test]
    fn ntfs_a_delete_pending_staging_file_is_never_a_clean_state() {
        let rig = Rig::pending("b3b2-delete-pending");

        rig.run_staged();

        let deleter = OpenOptions::new()
            .read(true)
            .access_mode(DELETE)
            .open(rig.s_path())
            .unwrap();

        delete_by_handle(&deleter).expect("marked for deletion");

        let (assessment, reads) = rig.assess_shallow();
        let (state, evidence, _) = classified_parts(assessment);

        eprintln!(
            "OBSERVED delete-pending staging file: state={state:?} slots={:?}",
            [evidence.target, evidence.retained, evidence.staging]
        );

        assert_eq!(reads, rig.read_order());
        // Either the name is already gone (absent: a clean "not started"), or the
        // object is seen and cannot be judged. Never "staged intended".
        assert!(matches!(
            (state, evidence.staging),
            (ExchangeState::NotStarted, Slot::Absent)
                | (
                    ExchangeState::Indeterminate,
                    Slot::Unreadable | Slot::IdentityUncertain
                )
        ));
    }

    // ---- 4. the folder: junctions, removal, substitution, change ----------------------

    #[test]
    fn ntfs_a_folder_that_is_not_plain_or_not_there_is_never_examined() {
        // The target folder replaced by a junction: no read is made at all.
        let rig = Rig::pending("b3b2-folder-junction");
        let moved = rig.dir.path().join("outer").join("dest-real");

        fs::rename(&rig.dest, &moved).unwrap();
        make_junction(&rig.dest, &moved);

        let (assessment, reads) = rig.assess();

        assert!(reads.is_empty());

        let (state, evidence, unlinked) = classified_parts(assessment);

        assert_eq!(state, ExchangeState::Indeterminate);
        assert_eq!(
            evidence.listing,
            ListingVerdict::Unavailable(ListingProblem::ParentNotPlain)
        );
        assert_eq!(
            unlinked,
            ArtifactIndicators::Unknown(ListingProblem::ParentNotPlain)
        );
        assert_eq!(
            (evidence.target, evidence.retained, evidence.staging),
            (U, U, U)
        );

        // An ancestor of the folder replaced by a junction.
        let rig = Rig::pending("b3b2-ancestor-junction");
        let outer = rig.dir.path().join("outer");
        let moved = rig.dir.path().join("outer-real");

        fs::rename(&outer, &moved).unwrap();
        make_junction(&outer, &moved);
        rig.expect_listing(ListingProblem::AncestorNotPlain);

        // The folder removed.
        let rig = Rig::pending("b3b2-folder-missing");

        fs::remove_file(rig.t_path()).unwrap();
        fs::remove_dir(&rig.dest).unwrap();
        rig.expect_listing(ListingProblem::ParentMissing);
    }

    #[test]
    fn ntfs_a_folder_substituted_during_the_assessment_is_a_change() {
        let rig = Rig::pending("b3b2-substituted");
        let dest = rig.dest.clone();
        let moved = rig.dir.path().join("outer").join("dest-moved");

        // The directory is renamed away and recreated with identical files inside,
        // after the first survey and the first read.
        let (assessment, reads) = rig.run(
            MAX_SURVEY_ENTRIES,
            true,
            &mut |n| {
                if n == 1 {
                    fs::rename(&dest, &moved).unwrap();
                    fs::create_dir(&dest).unwrap();

                    for entry in fs::read_dir(&moved).unwrap() {
                        let entry = entry.unwrap();

                        fs::copy(entry.path(), dest.join(entry.file_name())).unwrap();
                    }
                }
            },
            &mut |_, read| read,
        );

        assert_eq!(reads, rig.read_order());

        let (state, evidence, unlinked) = classified_parts(assessment);
        let changed = ListingProblem::ChangedDuringAssessment;

        assert_eq!(state, ExchangeState::Indeterminate);
        assert_eq!(evidence.listing, ListingVerdict::Unavailable(changed));
        assert_eq!(unlinked, ArtifactIndicators::Unknown(changed));
    }

    #[test]
    fn ntfs_names_appearing_or_vanishing_during_the_assessment_are_a_change() {
        let changed = ListingProblem::ChangedDuringAssessment;

        // A staging-shaped decoy appears between the surveys.
        let rig = Rig::pending("b3b2-appears");
        let decoy = rig
            .dest
            .join(format!(".{LEAF}.localvault-update-{OTHER_ID}.tmp"));
        let state = classified_parts(rig.assess_hooked(&mut |n| {
            if n == 1 {
                fs::write(&decoy, FOREIGN).unwrap();
            }
        }));

        assert_eq!(state.0, ExchangeState::Indeterminate);
        assert_eq!(state.1.listing, ListingVerdict::Unavailable(changed));

        // A staging-shaped decoy vanishes between the surveys.
        let rig = Rig::pending("b3b2-vanishes");
        let decoy = rig
            .dest
            .join(format!(".{LEAF}.localvault-update-{OTHER_ID}.tmp"));

        fs::write(&decoy, FOREIGN).unwrap();

        let state = classified_parts(rig.assess_hooked(&mut |n| {
            if n == 1 {
                fs::remove_file(&decoy).unwrap();
            }
        }));

        assert_eq!(state.1.listing, ListingVerdict::Unavailable(changed));

        // The staging file itself is removed after it was listed.
        let rig = Rig::pending("b3b2-slot-vanishes");

        rig.run_staged();

        let staging = rig.s_path();
        let state = classified_parts(rig.assess_hooked(&mut |n| {
            if n == 2 {
                fs::remove_file(&staging).unwrap();
            }
        }));

        assert_eq!(state.0, ExchangeState::Indeterminate);
        assert_eq!(state.1.listing, ListingVerdict::Unavailable(changed));
        assert_eq!(state.1.staging, A);
    }

    #[test]
    fn ntfs_a_directory_that_loses_its_identity_is_unavailable_not_assumed() {
        // The survey's own directory handle is queried again after the reads. Here
        // the directory becomes delete-pending in between.
        let dir = scratch("b3b2-dir-identity-lost");
        let folder = dir.path().join("folder");

        fs::create_dir(&folder).unwrap();

        let path = folder.join("copy.lvault");
        let pattern =
            ArtifactPattern::for_target(&SyncFileTarget::from_path(&path).unwrap()).unwrap();
        let first = survey_with_limit(&path, &pattern, None, &mut read_directory, 100);
        let second = survey_with_limit(&path, &pattern, None, &mut read_directory, 100);

        assert_eq!(
            judge_listing(&first, Some(&second), None),
            ListingVerdict::Consistent
        );

        let deleter = OpenOptions::new()
            .read(true)
            .access_mode(DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&folder)
            .unwrap();

        delete_by_handle(&deleter).expect("the directory can be marked for deletion");

        assert_eq!(
            judge_listing(&first, Some(&second), None),
            ListingVerdict::Unavailable(ListingProblem::DirectoryIdentityUnavailable)
        );
    }

    #[test]
    fn ntfs_directory_identity_is_stable_and_a_substitute_differs() {
        let dir = scratch("b3b2-dir-identity");
        let folder = dir.path().join("folder");
        let moved = dir.path().join("moved");

        fs::create_dir(&folder).unwrap();

        let path = folder.join("copy.lvault");
        let pattern =
            ArtifactPattern::for_target(&SyncFileTarget::from_path(&path).unwrap()).unwrap();
        let survey = || {
            survey_with_limit(&path, &pattern, None, &mut read_directory, 100)
                .ok()
                .unwrap()
        };

        let (one, two) = (survey(), survey());

        assert_eq!(one.observed, two.observed);

        // The file API still refuses directories; the directory API does not.
        assert_eq!(facts_of(&one.directory).err(), Some(IdentityError::Lookup));
        assert!(directory_identity_of(&one.directory).is_ok());

        // The same directory renamed away and a new one made at its name.
        fs::rename(&folder, &moved).unwrap();
        fs::create_dir(&folder).unwrap();

        let three = survey();

        assert_ne!(one.observed.directory, three.observed.directory);
        assert_eq!(
            directory_identity_of(&one.directory).unwrap(),
            one.observed.directory
        );
    }

    // ---- 5. the survey: limits and listing failures ----------------------------------

    fn sample() -> (tempfile::TempDir, PathBuf, ArtifactPattern) {
        let dir = scratch("b3b2-survey");
        let path = dir.path().join(LEAF);
        let pattern =
            ArtifactPattern::for_target(&SyncFileTarget::from_path(&path).unwrap()).unwrap();

        (dir, path, pattern)
    }

    #[test]
    fn ntfs_the_entry_limit_is_exact_and_exceeding_it_never_means_nothing_found() {
        let (dir, path, pattern) = sample();

        for index in 0..5 {
            fs::write(dir.path().join(format!("entry-{index}")), b"x").unwrap();
        }

        let run = |limit| survey_with_limit(&path, &pattern, None, &mut read_directory, limit);

        assert_eq!(run(3).err(), Some(ListingProblem::TooManyEntries));
        assert_eq!(run(4).err(), Some(ListingProblem::TooManyEntries));
        assert!(run(5).is_ok());
        assert!(run(6).is_ok());
    }

    #[test]
    fn ntfs_the_production_entry_limit_is_ten_thousand() {
        assert_eq!(MAX_SURVEY_ENTRIES, 10_000);

        // A real folder with exactly the limit is fully examined; one more is not.
        let rig = Rig::bound("b3b2-ten-thousand");

        for index in 0..(MAX_SURVEY_ENTRIES - 1) {
            fs::write(rig.dest.join(format!("e{index}")), b"").unwrap();
        }

        // The target itself plus 9,999 others.
        let (assessment, reads) =
            rig.run(MAX_SURVEY_ENTRIES, false, &mut |_| {}, &mut |_, read| read);

        assert!(reads.is_empty());
        assert_eq!(
            assessment,
            ExchangeRecoveryAssessment::NoPendingExchange {
                artifacts: ArtifactIndicators::NoneFound
            }
        );

        fs::write(rig.dest.join("one-too-many"), b"").unwrap();

        let (assessment, _) = rig.run(MAX_SURVEY_ENTRIES, false, &mut |_| {}, &mut |_, read| read);

        assert_eq!(
            assessment,
            ExchangeRecoveryAssessment::NoPendingExchange {
                artifacts: ArtifactIndicators::Unknown(ListingProblem::TooManyEntries)
            }
        );
    }

    #[test]
    fn ntfs_a_listing_over_the_limit_is_indeterminate_with_no_reads() {
        let rig = Rig::pending("b3b2-limit-pending");

        for index in 0..5 {
            fs::write(rig.dest.join(format!("e{index}")), b"").unwrap();
        }

        let (assessment, reads) = rig.assess_with_limit(3);

        assert!(reads.is_empty());

        let (state, evidence, unlinked) = classified_parts(assessment);
        let problem = ListingProblem::TooManyEntries;

        assert_eq!(state, ExchangeState::Indeterminate);
        assert_eq!(evidence.listing, ListingVerdict::Unavailable(problem));
        assert_eq!(unlinked, ArtifactIndicators::Unknown(problem));
    }

    #[test]
    fn inj_listing_failures_are_refusals() {
        let (_dir, path, pattern) = sample();

        let mut cannot_list = |_: &Path| -> io::Result<EntryIter> { Err(io::Error::other("x")) };

        assert_eq!(
            survey_with_limit(&path, &pattern, None, &mut cannot_list, 100).err(),
            Some(ListingProblem::ReadFailed)
        );

        let mut fails_midway = |_: &Path| -> io::Result<EntryIter> {
            Ok(Box::new(
                vec![
                    Ok(OsString::from("a")),
                    Err(io::Error::other("x")),
                    Ok(OsString::from("b")),
                ]
                .into_iter(),
            ))
        };

        assert_eq!(
            survey_with_limit(&path, &pattern, None, &mut fails_midway, 100).err(),
            Some(ListingProblem::IterationFailed)
        );

        // A listing that is exactly empty is complete: nothing found.
        let mut empty =
            |_: &Path| -> io::Result<EntryIter> { Ok(Box::new(Vec::new().into_iter())) };
        let survey = survey_with_limit(&path, &pattern, None, &mut empty, 100)
            .ok()
            .unwrap();

        assert_eq!(indicators(&survey.observed), ArtifactIndicators::NoneFound);
        assert_eq!(survey.observed.exact, [false; 3]);
    }

    #[test]
    fn inj_a_survey_classifies_names_without_trusting_them() {
        let (_dir, path, pattern) = sample();
        let names = ExchangeNames::derive(
            &SyncFileTarget::from_path(&path).unwrap(),
            ExchangeId::new(INTENT).unwrap(),
        )
        .unwrap();
        let other_staging = format!(".{LEAF}.localvault-update-{OTHER_ID}.tmp");
        let other_retention = format!(
            ".{LEAF}.LOCALVAULT-PREVIOUS-{}.lvprev",
            OTHER_ID.to_uppercase()
        );

        let list = |entries: Vec<OsString>, own: Option<&ExchangeNames>| {
            let mut entries_fn = move |_: &Path| -> io::Result<EntryIter> {
                Ok(Box::new(entries.clone().into_iter().map(Ok)))
            };

            survey_with_limit(&path, &pattern, own, &mut entries_fn, 100)
                .ok()
                .unwrap()
                .observed
        };

        let own_staging = names.staging_leaf().to_owned();
        let own_retention = names.retention_leaf().to_owned();

        // Own artifacts are exact matches, never indicators.
        let seen = list(
            vec![
                OsString::from(LEAF),
                own_retention.clone(),
                own_staging.clone(),
            ],
            Some(&names),
        );

        assert_eq!(seen.exact, [true, true, true]);
        assert!(!seen.alias && !seen.staging_like && !seen.retention_like);

        // Another id is an indicator only.
        let seen = list(
            vec![
                OsString::from(&other_staging),
                OsString::from(&other_retention),
            ],
            Some(&names),
        );

        assert_eq!(seen.exact, [false; 3]);
        assert!(seen.staging_like && seen.retention_like && !seen.alias);

        // Own names in another case are aliases (ambiguous), not indicators.
        let seen = list(
            vec![OsString::from(own_staging.to_string_lossy().to_uppercase())],
            Some(&names),
        );

        assert!(seen.alias && !seen.staging_like);

        let seen = list(vec![OsString::from(LEAF.to_uppercase())], None);

        assert!(seen.alias && seen.exact == [false; 3]);

        // Without an exchange, own-looking names are only indicators.
        let seen = list(vec![own_staging], None);

        assert!(seen.staging_like && !seen.alias);

        // Unrelated names and over-long names are ignored.
        let seen = list(
            vec![
                OsString::from("unrelated.txt"),
                OsString::from(format!(".{LEAF}.localvault-copy-{OTHER_ID}.tmp")),
                OsString::from("a".repeat(400)),
            ],
            None,
        );

        assert_eq!(indicators(&seen), ArtifactIndicators::NoneFound);
    }

    // ---- 6. aliases and case --------------------------------------------------------------

    #[test]
    fn ntfs_a_case_variant_of_an_artifact_name_is_ambiguous() {
        let rig = Rig::pending("b3b2-alias-r");

        rig.run_between_renames();

        let lower = rig.r_path();
        let name = rig.names.retention_leaf().to_string_lossy().into_owned();
        let upper_id = name.replace(
            &INTENT.hyphenated().to_string(),
            &INTENT.hyphenated().to_string().to_uppercase(),
        );

        assert_ne!(name, upper_id);
        fs::rename(&lower, rig.dest.join(&upper_id)).unwrap();

        let (assessment, _) = rig.assess();
        let (state, evidence, unlinked) = classified_parts(assessment);

        // The case-insensitive read still finds it, so the three slots are readable;
        // only the listing is ambiguous.
        assert_eq!(state, ExchangeState::Indeterminate);
        assert_eq!(evidence.listing, ListingVerdict::Ambiguous);
        assert_eq!(
            (evidence.target, evidence.retained, evidence.staging),
            (A, B, N)
        );
        assert_eq!(unlinked, ArtifactIndicators::AmbiguousNames);
    }

    #[test]
    fn ntfs_a_locator_leaf_in_another_case_than_the_name_on_disk_is_ambiguous() {
        let rig = Rig::pending("b3b2-alias-t");

        fs::rename(rig.t_path(), rig.dest.join(LEAF.to_uppercase())).unwrap();

        let (assessment, _) = rig.assess();
        let (state, evidence, unlinked) = classified_parts(assessment);

        assert_eq!(state, ExchangeState::Indeterminate);
        assert_eq!(evidence.listing, ListingVerdict::Ambiguous);
        assert_eq!(unlinked, ArtifactIndicators::AmbiguousNames);
    }

    // ---- 7. artifact indicators (pending and no-pending) -----------------------------

    #[test]
    fn ntfs_other_ids_are_unlinked_indicators_that_never_change_the_state() {
        let rig = Rig::pending("b3b2-unlinked");

        assert_eq!(
            rig.expect(ExchangeState::NotStarted, [B, A, A]),
            ArtifactIndicators::NoneFound
        );

        fs::write(
            rig.dest
                .join(format!(".{LEAF}.localvault-update-{OTHER_ID}.tmp")),
            FOREIGN,
        )
        .unwrap();
        assert_eq!(
            rig.expect(ExchangeState::NotStarted, [B, A, A]),
            ArtifactIndicators::Found {
                staging_like: true,
                retention_like: false
            }
        );

        fs::write(
            rig.dest
                .join(format!(".{LEAF}.localvault-previous-{OTHER_ID}.lvprev")),
            FOREIGN,
        )
        .unwrap();
        assert_eq!(
            rig.expect(ExchangeState::NotStarted, [B, A, A]),
            ArtifactIndicators::Found {
                staging_like: true,
                retention_like: true
            }
        );

        // The B2 copy-creation pattern is not interpreted here.
        let rig = Rig::pending("b3b2-unlinked-b2");

        fs::write(
            rig.dest
                .join(format!(".{LEAF}.localvault-copy-{OTHER_ID}.tmp")),
            FOREIGN,
        )
        .unwrap();
        assert_eq!(
            rig.expect(ExchangeState::NotStarted, [B, A, A]),
            ArtifactIndicators::NoneFound
        );
    }

    #[test]
    fn ntfs_without_a_pending_push_only_indicators_are_reported_and_nothing_is_read() {
        let found = |staging_like, retention_like| ExchangeRecoveryAssessment::NoPendingExchange {
            artifacts: ArtifactIndicators::Found {
                staging_like,
                retention_like,
            },
        };

        let rig = Rig::bound("b3b2-no-pending");

        let (assessment, reads) = rig.assess();

        assert!(reads.is_empty());
        assert_eq!(
            assessment,
            ExchangeRecoveryAssessment::NoPendingExchange {
                artifacts: ArtifactIndicators::NoneFound
            }
        );

        // The names an exchange would have used, were there a pending push: here
        // they are only indicators, and no id exists or is invented.
        let staging = rig.dest.join(rig.names.staging_leaf());

        fs::write(&staging, FOREIGN).unwrap();
        assert_eq!(rig.assess().0, found(true, false));

        fs::remove_file(&staging).unwrap();
        fs::write(rig.r_path(), FOREIGN).unwrap();
        assert_eq!(rig.assess().0, found(false, true));

        // The shape is case-insensitive.
        let upper = rig.dest.join(format!(
            ".{LEAF}.LOCALVAULT-UPDATE-{}.TMP",
            OTHER_ID.to_uppercase()
        ));

        fs::write(&upper, FOREIGN).unwrap();
        assert_eq!(rig.assess().0, found(true, true));

        // The B2 pattern is nothing.
        let rig = Rig::bound("b3b2-no-pending-b2");

        fs::write(
            rig.dest
                .join(format!(".{LEAF}.localvault-copy-{OTHER_ID}.tmp")),
            FOREIGN,
        )
        .unwrap();
        assert_eq!(
            rig.assess().0,
            ExchangeRecoveryAssessment::NoPendingExchange {
                artifacts: ArtifactIndicators::NoneFound
            }
        );

        // A case-variant of the target leaf is ambiguous.
        let rig = Rig::bound("b3b2-no-pending-alias");

        fs::rename(rig.t_path(), rig.dest.join(LEAF.to_uppercase())).unwrap();
        assert_eq!(
            rig.assess().0,
            ExchangeRecoveryAssessment::NoPendingExchange {
                artifacts: ArtifactIndicators::AmbiguousNames
            }
        );

        // The folder is not examined: nothing is claimed absent.
        let rig = Rig::bound("b3b2-no-pending-missing");

        fs::remove_file(rig.t_path()).unwrap();
        fs::remove_dir(&rig.dest).unwrap();
        assert_eq!(
            rig.assess().0,
            ExchangeRecoveryAssessment::NoPendingExchange {
                artifacts: ArtifactIndicators::Unknown(ListingProblem::ParentMissing)
            }
        );
    }

    #[test]
    fn ntfs_a_pending_push_without_a_baseline_is_not_an_exchange() {
        let rig = Rig::unbound("b3b2-unbased");
        let pending = PendingPush::new(
            INTENT,
            PushIntent::new(
                PushBaseline::Absent,
                EnvelopeFingerprint::of_bytes(b"intended"),
            )
            .unwrap(),
            1,
        )
        .unwrap();
        let state = rig.craft(
            rig.session.data.vault_id,
            rig.copy.to_str().unwrap(),
            SyncBase::Unbased,
            Some(pending),
        );

        rig.store().create(&state).unwrap();

        // Neither a survey nor a read: a decoy in the folder is not even looked at.
        fs::write(rig.dest.join(rig.names.staging_leaf()), FOREIGN).unwrap();

        let (assessment, reads) = rig.assess();

        assert!(reads.is_empty());
        assert_eq!(assessment, ExchangeRecoveryAssessment::NotAnExchange);
    }

    // ---- 8. the record ------------------------------------------------------------------

    fn record_problem(assessment: ExchangeRecoveryAssessment) -> RecordProblem {
        match assessment {
            ExchangeRecoveryAssessment::RecordUnusable(problem) => problem,
            other => panic!("expected an unusable record, found {other:?}"),
        }
    }

    #[test]
    fn ntfs_an_unusable_record_is_refused_before_the_folder_is_read() {
        let rig = Rig::unbound("b3b2-not-configured");
        let (assessment, reads) = rig.assess();

        assert!(reads.is_empty());
        assert_eq!(record_problem(assessment), RecordProblem::NotConfigured);

        let rig = Rig::bound("b3b2-damaged-record");
        let record = rig.record();
        let valid = fs::read(&record).unwrap();
        let check = |expected: RecordProblem| {
            let (assessment, reads) = rig.assess();

            assert!(reads.is_empty());
            assert_eq!(record_problem(assessment), expected);
        };

        fs::write(&record, b"garbage").unwrap();
        check(RecordProblem::Corrupt(CorruptReason::Undecodable));

        fs::write(&record, b"").unwrap();
        check(RecordProblem::Corrupt(CorruptReason::Empty));

        let mut future: serde_json::Value = serde_json::from_slice(&valid).unwrap();

        future["version"] = serde_json::json!(2);
        future["added_in_v2"] = serde_json::json!(true);
        fs::write(&record, serde_json::to_vec(&future).unwrap()).unwrap();
        check(RecordProblem::UnsupportedVersion);

        fs::remove_file(&record).unwrap();
        fs::create_dir(&record).unwrap();
        check(RecordProblem::Unreadable(
            UnreadableReason::UnexpectedObject,
        ));

        fs::remove_dir(&record).unwrap();
        fs::write(
            record.with_extension(format!("{}.tmp", "0".repeat(32))),
            b"leftover",
        )
        .unwrap();
        check(RecordProblem::Unreadable(
            UnreadableReason::UnresolvedArtifacts,
        ));
    }

    #[test]
    fn ntfs_a_record_held_with_share_zero_is_unreadable() {
        let rig = Rig::bound("b3b2-record-held");
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(rig.record())
            .unwrap();
        let (assessment, reads) = rig.assess_shallow();

        assert!(reads.is_empty());
        assert!(matches!(
            record_problem(assessment),
            RecordProblem::Unreadable(UnreadableReason::Io(_))
        ));

        drop(held);
    }

    #[test]
    fn ntfs_a_record_of_another_vault_is_a_binding_mismatch() {
        let rig = Rig::unbound("b3b2-foreign-record");
        let base = SyncBase::Based(
            localvault_core::sync_state::SyncCheckpoint::new(
                EnvelopeFingerprint::of_bytes(b"synthetic"),
                0,
                RemoteHighWater::new(0),
            )
            .unwrap(),
        );
        let state = rig.craft(
            Uuid::from_u128(0xF0),
            rig.copy.to_str().unwrap(),
            base,
            None,
        );

        rig.store().create(&state).unwrap();

        let (assessment, reads) = rig.assess();

        assert!(reads.is_empty());
        assert_eq!(
            record_problem(assessment),
            RecordProblem::BindingMismatch(BindingMismatch::VaultIdentity)
        );
    }

    #[test]
    fn ntfs_a_stored_target_that_is_invalid_network_or_the_vaults_own_is_refused_first() {
        let rig = Rig::unbound("b3b2-invalid-locator");

        rig.put_crafted(r"relative\copy.lvault");

        let (assessment, reads) = rig.assess();

        assert!(reads.is_empty());
        assert_eq!(
            record_problem(assessment),
            RecordProblem::TargetInvalidLocator
        );

        for unc in [
            r"\\server.invalid\share\copy.lvault",
            r"\\?\UNC\server.invalid\share\copy.lvault",
        ] {
            let rig = Rig::unbound("b3b2-unc");

            rig.put_crafted(unc);

            let (assessment, reads) = rig.assess();

            assert!(reads.is_empty());
            assert_eq!(
                record_problem(assessment),
                RecordProblem::TargetIsNetworkPath
            );
        }

        type OwnFile = fn(&mut Rig) -> PathBuf;

        let own_files: [(&str, OwnFile); 3] = [
            ("b3b2-own-lock", |rig| {
                super::super::lock_path_for(&rig.vault)
            }),
            ("b3b2-own-backup", |rig| {
                save_edit(&mut rig.session, 1);

                rig.session.backup_path().to_path_buf()
            }),
            ("b3b2-own-state-dir", |rig| {
                fs::create_dir_all(rig.state_dir()).unwrap();

                let in_state = rig.state_dir().join("copy.lvault");

                fs::write(&in_state, b"x").unwrap();

                in_state
            }),
        ];

        for (name, pick) in own_files {
            let mut rig = Rig::unbound(name);
            let own = pick(&mut rig);

            rig.put_crafted(own.to_str().unwrap());

            let (assessment, reads) = rig.assess();

            assert!(reads.is_empty());
            assert_eq!(record_problem(assessment), RecordProblem::TargetIsVaultFile);
        }
    }

    #[test]
    fn ntfs_a_replaced_primary_is_unavailable() {
        let rig = Rig::pending("b3b2-primary-changed");
        let other_dir = rig.dir.path().join("elsewhere");

        fs::create_dir_all(&other_dir).unwrap();

        let other = other_dir.join("vault.lvault");
        let _other = UnlockedVaultSession::create(&other, password(), NOW_MS).unwrap();

        fs::copy(&other, &rig.vault).unwrap();

        let (assessment, reads) = rig.assess();

        assert!(reads.is_empty());
        assert_eq!(
            record_problem(assessment),
            RecordProblem::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        );
    }

    #[test]
    fn ntfs_a_target_leaf_too_long_to_derive_names_for_is_names_underivable() {
        // Legal as a leaf, but not once the 59-unit staging suffix is added.
        let long = "x".repeat(230);
        let rig = Rig::unbound("b3b2-names");
        let copy = rig.dest.join(format!("{long}.lvault"));

        fs::copy(&rig.vault, &copy).unwrap();

        let pending = PendingPush::new(
            INTENT,
            PushIntent::new(
                PushBaseline::Present(EnvelopeFingerprint::of_bytes(b"baseline")),
                EnvelopeFingerprint::of_bytes(b"intended"),
            )
            .unwrap(),
            2,
        )
        .unwrap();
        let base = SyncBase::Based(
            localvault_core::sync_state::SyncCheckpoint::new(
                EnvelopeFingerprint::of_bytes(b"baseline"),
                1,
                RemoteHighWater::new(1),
            )
            .unwrap(),
        );

        rig.store()
            .create(&rig.craft(
                rig.session.data.vault_id,
                copy.to_str().unwrap(),
                base,
                Some(pending),
            ))
            .unwrap();

        let (assessment, reads) = rig.assess();

        assert!(reads.is_empty());
        assert_eq!(record_problem(assessment), RecordProblem::NamesUnderivable);
    }

    // ---- 9. read-only access behaviour -------------------------------------------------------

    #[test]
    fn ntfs_the_assessment_works_while_the_exchange_handles_are_still_held() {
        // B3b-1 holds `T` with read-only sharing and `S` with read-only sharing and
        // write/delete access. An assessment that asked for write or delete access, or
        // for a restrictive share mode, could not read them.
        let rig = Rig::pending("b3b2-held");
        let held = rig.held();

        rig.expect(ExchangeState::NotStarted, [B, A, A]);

        let staged = held
            .stage(&rig.intended_bytes(), &mut Seams::none())
            .unwrap();

        rig.expect(ExchangeState::StagedIntended, [B, A, N]);

        // And after the assessment, the exchange itself still proceeds.
        assert!(matches!(
            staged.exchange(&mut || true, &mut Seams::none()),
            ExchangeOutcome::Exchanged(_)
        ));
        rig.expect(ExchangeState::ExchangedNotFinalized, [N, B, A]);
    }

    #[test]
    fn ntfs_the_assessment_is_idempotent_and_the_public_entry_matches() {
        let rig = Rig::pending("b3b2-idempotent");

        rig.run_between_renames();

        let first = rig.assess();
        let second = rig.assess();

        assert_eq!(first, second);
        assert_eq!(rig.session.assess_interrupted_exchange(&rig.root), first.0);
    }

    // ---- 10. injected results (decision logic only) ----------------------------------------------

    #[test]
    fn inj_unavailable_reads_map_to_fixed_slots() {
        let cases = [
            (
                SyncFileRead::Unavailable(UnavailableReason::Io(io::ErrorKind::PermissionDenied)),
                U,
            ),
            (SyncFileRead::Unavailable(UnavailableReason::Changed), U),
            (
                SyncFileRead::Unavailable(UnavailableReason::ParentMissing),
                U,
            ),
            (SyncFileRead::Unavailable(UnavailableReason::Unsupported), U),
            (SyncFileRead::Unavailable(UnavailableReason::Empty), I),
            (SyncFileRead::Unavailable(UnavailableReason::TooLarge), I),
            (
                SyncFileRead::Unavailable(UnavailableReason::UnexpectedObject),
                E,
            ),
            (SyncFileRead::AbsentOnDisk, A),
        ];

        for index in 0..3 {
            for (injected, slot) in &cases {
                let rig = Rig::pending("b3b2-inj-unavailable");
                let assessment = rig.assess_rewriting(&mut |n, read| {
                    if n == index {
                        injected.clone()
                    } else {
                        read
                    }
                });
                let (_, evidence, _) = classified_parts(assessment);
                let seen = [evidence.target, evidence.retained, evidence.staging][index];

                // A slot injected absent while it is listed disagrees with the listing.
                if matches!(injected, SyncFileRead::AbsentOnDisk) && index == 0 {
                    assert_eq!(seen, A);
                    assert_eq!(evidence.listing, ListingVerdict::Disagrees);
                } else if matches!(injected, SyncFileRead::AbsentOnDisk) {
                    assert_eq!(seen, A);
                } else {
                    assert_eq!(seen, *slot);
                }

                if slot.is_uninspectable() {
                    assert_eq!(classified_parts(assessment).0, ExchangeState::Indeterminate);
                }
            }
        }
    }

    #[test]
    fn inj_physical_facts_that_are_not_certain_make_a_slot_uncertain() {
        let rig = Rig::pending("b3b2-inj-physical");
        let primary = facts_of(&File::open(&rig.vault).unwrap()).unwrap();
        let ntfs = |links, delete_pending, filesystem, local| {
            HandleFacts::for_test(7, [9; 16], links, delete_pending, filesystem, local)
        };

        let cases: [(&str, Result<HandleFacts, IdentityError>); 7] = [
            ("lookup failed", Err(IdentityError::Lookup)),
            ("unsupported", Err(IdentityError::Unsupported)),
            ("two names", Ok(ntfs(2, false, FileSystemKind::Ntfs, true))),
            (
                "delete pending",
                Ok(ntfs(1, true, FileSystemKind::Ntfs, true)),
            ),
            ("ReFS", Ok(ntfs(1, false, FileSystemKind::Refs, true))),
            (
                "another filesystem",
                Ok(ntfs(1, false, FileSystemKind::Other, true)),
            ),
            (
                "the vault's own identity",
                Ok(ntfs(1, false, FileSystemKind::Ntfs, true).with_identity_of(&primary)),
            ),
        ];

        for (label, physical) in cases {
            let assessment = rig.assess_rewriting(&mut |n, read| {
                if n == 0 {
                    SyncFileRead::Present(present(read).with_physical_for_test(physical))
                } else {
                    read
                }
            });
            let (state, evidence, _) = classified_parts(assessment);

            assert_eq!(evidence.target, Q, "{label}");
            assert_eq!(state, ExchangeState::Indeterminate, "{label}");
        }
    }

    #[test]
    fn inj_two_names_with_one_physical_identity_are_both_uncertain() {
        let rig = Rig::pending("b3b2-inj-shared");
        let shared = RefCell::new(None);

        rig.run_staged();

        // S is made to report T's physical facts.
        let assessment = rig.assess_rewriting(&mut |n, read| match n {
            0 => {
                let file = present(read);

                *shared.borrow_mut() = Some(*file.physical().unwrap());

                SyncFileRead::Present(file)
            }
            2 => SyncFileRead::Present(
                present(read).with_physical_for_test(Ok(shared.borrow().unwrap())),
            ),
            _ => read,
        });
        let (state, evidence, _) = classified_parts(assessment);

        assert_eq!(
            (evidence.target, evidence.retained, evidence.staging),
            (Q, A, Q)
        );
        assert_eq!(state, ExchangeState::Indeterminate);
    }

    #[test]
    fn inj_evidence_paired_with_another_name_is_not_trusted() {
        let rig = Rig::pending("b3b2-inj-wrong-name");
        let elsewhere = SyncFileTarget::from_path(&rig.vault).unwrap();

        // Slot T answers with bytes read from another name.
        let assessment =
            rig.assess_rewriting(&mut |n, read| if n == 0 { elsewhere.read() } else { read });
        let (state, evidence, _) = classified_parts(assessment);

        assert_eq!(evidence.target, U);
        assert_eq!(state, ExchangeState::Indeterminate);
    }

    #[test]
    fn inj_a_rejected_local_envelope_is_never_blamed_on_a_slot() {
        // [PURE/INJ] A failure of the vault's own (local reference) envelope is the
        // session's problem and aborts the whole assessment; only a failure of the
        // candidate makes a slot invalid.
        use localvault_core::sync::{EnvelopeInput, PayloadRejection};

        for input in [EnvelopeInput::Candidate, EnvelopeInput::LocalReference] {
            let is_candidate = input == EnvelopeInput::Candidate;

            assert_eq!(
                fault_is_candidate(BoundInspectionError::MalformedEnvelope { input }),
                is_candidate
            );
            assert_eq!(
                fault_is_candidate(BoundInspectionError::InputTooLarge {
                    input,
                    actual: 2,
                    limit: 1
                }),
                is_candidate
            );
        }

        let rejection = PayloadRejection::AuthenticationFailed;

        assert!(fault_is_candidate(BoundInspectionError::Inspection(
            InspectionError::Candidate(rejection)
        )));
        assert!(!fault_is_candidate(BoundInspectionError::Inspection(
            InspectionError::LocalReference(rejection)
        )));
    }

    // ---- 11. pure classification ------------------------------------------------------------------

    fn listings() -> Vec<ListingVerdict> {
        use ListingProblem::*;

        let mut all = vec![
            ListingVerdict::Consistent,
            ListingVerdict::Ambiguous,
            ListingVerdict::Disagrees,
        ];

        all.extend(
            [
                ParentMissing,
                ParentUnreadable,
                ParentNotPlain,
                AncestorNotPlain,
                NotLocalNtfs,
                DirectoryIdentityUnavailable,
                ReadFailed,
                IterationFailed,
                TooManyEntries,
                ChangedDuringAssessment,
            ]
            .map(ListingVerdict::Unavailable),
        );

        all
    }

    /// Written independently of `classify`: a table of the sixteen listed patterns
    /// and a precedence walk.
    fn oracle(t: Slot, r: Slot, s: Slot, listing: ListingVerdict) -> ExchangeState {
        let defects = [I, O, E];
        let is_defect = |slot: Slot| defects.contains(&slot);

        if listing != ListingVerdict::Consistent
            || [t, r, s].iter().any(|slot| [U, Q].contains(slot))
        {
            return ExchangeState::Indeterminate;
        }

        let clean = [
            ((B, A, A), ExchangeState::NotStarted),
            ((B, A, N), ExchangeState::StagedIntended),
            ((A, B, N), ExchangeState::BetweenRenames),
            ((N, B, A), ExchangeState::ExchangedNotFinalized),
        ];

        if let Some((_, state)) = clean.iter().find(|(pattern, _)| *pattern == (t, r, s)) {
            return *state;
        }

        if t == B && r == A && is_defect(s) {
            return ExchangeState::StagedInvalid;
        }

        if t == N && s == A && (r == A || is_defect(r)) {
            return ExchangeState::ExchangedPreviousNotVerified;
        }

        if is_defect(t) && r == B && (s == A || s == N || is_defect(s)) {
            return ExchangeState::TargetOccupied;
        }

        ExchangeState::Inconsistent
    }

    #[test]
    fn pure_classify_matches_an_independent_oracle_for_every_combination() {
        for listing in listings() {
            for t in ALL_SLOTS {
                for r in ALL_SLOTS {
                    for s in ALL_SLOTS {
                        let evidence = ExchangeEvidence {
                            target: t,
                            retained: r,
                            staging: s,
                            listing,
                        };

                        assert_eq!(classify(evidence), oracle(t, r, s, listing), "{evidence:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn pure_classify_has_exactly_the_planned_number_of_combinations_per_state() {
        let mut counts = std::collections::BTreeMap::new();

        for t in ALL_SLOTS {
            for r in ALL_SLOTS {
                for s in ALL_SLOTS {
                    let state = classify(ExchangeEvidence {
                        target: t,
                        retained: r,
                        staging: s,
                        listing: ListingVerdict::Consistent,
                    });

                    *counts.entry(format!("{state:?}")).or_insert(0usize) += 1;
                }
            }
        }

        let expected = [
            ("NotStarted", 1),
            ("StagedIntended", 1),
            ("BetweenRenames", 1),
            ("ExchangedNotFinalized", 1),
            // T = Baseline, R = Absent, S in the three definite defects.
            ("StagedInvalid", 3),
            // T = Intended, S = Absent, R = Absent or one of three defects.
            ("ExchangedPreviousNotVerified", 4),
            // T one of three defects, R = Baseline, S = Absent / Intended / 3 defects.
            ("TargetOccupied", 15),
            // 512 - 6^3 combinations without an uninspectable slot.
            ("Indeterminate", 512 - 216),
        ];

        for (state, count) in expected {
            assert_eq!(counts.get(state).copied(), Some(count), "{state}");
        }

        let classified: usize = expected.iter().map(|(_, count)| count).sum();

        assert_eq!(counts.get("Inconsistent").copied(), Some(512 - classified));
        assert_eq!(counts.values().sum::<usize>(), 512);
    }

    #[test]
    fn pure_an_uninspectable_slot_or_a_doubtful_listing_is_never_hidden() {
        for listing in listings() {
            for (t, r, s) in [
                (B, A, U),
                (B, A, Q),
                (U, B, N),
                (N, Q, A),
                (B, A, N),
                (A, B, N),
                (N, B, A),
                (B, A, A),
            ] {
                let state = classify(ExchangeEvidence {
                    target: t,
                    retained: r,
                    staging: s,
                    listing,
                });
                let doubtful = listing != ListingVerdict::Consistent
                    || [t, r, s].iter().any(|slot| slot.is_uninspectable());

                assert_eq!(
                    state == ExchangeState::Indeterminate,
                    doubtful,
                    "{t:?} {r:?} {s:?} {listing:?}"
                );
            }
        }

        // Indeterminate and Inconsistent are distinct outcomes of distinct inputs.
        assert_ne!(ExchangeState::Indeterminate, ExchangeState::Inconsistent);
    }

    // ---- 12. redaction, isolation and the forbidden-operation scan ---------------------------------

    #[test]
    fn debug_output_reveals_no_path_name_identifier_fingerprint_or_status() {
        let rig = Rig::pending("b3b2-redaction");
        let baseline = EnvelopeFingerprint::of_bytes(&rig.baseline_bytes()).to_hex();
        let intended = EnvelopeFingerprint::of_bytes(&rig.intended_bytes()).to_hex();

        rig.run_between_renames();

        let (assessment, _) = rig.assess();
        let no_pending = Rig::bound("b3b2-redaction-bound").assess().0;
        let target = SyncFileTarget::from_path(&rig.copy).unwrap();

        let rendered = [
            format!("{assessment:?}"),
            format!("{no_pending:?}"),
            format!("{:?}", classified_parts(assessment).1),
            format!("{:?}", ArtifactPattern::for_target(&target).unwrap()),
            format!("{:?}", rig.names),
            format!("{:?}", rig.session.assess_interrupted_exchange(&rig.root)),
        ]
        .join("\n");

        for mark in [
            "LEAKMARK",
            "qa-local",
            ".lvprev",
            ".tmp",
            "localvault-update",
            "localvault-previous",
            "outer",
            &INTENT.hyphenated().to_string(),
            &INTENT.hyphenated().to_string().to_uppercase(),
            &baseline,
            &intended,
        ] {
            assert!(!rendered.contains(mark), "{mark}");
        }
    }

    fn production_code() -> String {
        include_str!("exchange_recovery.rs")
            .split("// ---- test-only code below this line")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Whether `token` occurs in `code` as a whole identifier (not as a part of a
    /// longer one such as `StagedIntended`).
    fn contains_word(code: &str, token: &str) -> bool {
        let is_word = |c: char| c.is_alphanumeric() || c == '_';

        code.match_indices(token).any(|(start, _)| {
            !code[..start].chars().next_back().is_some_and(is_word)
                && !code[start + token.len()..]
                    .chars()
                    .next()
                    .is_some_and(is_word)
        })
    }

    #[test]
    fn the_production_code_has_no_way_to_write_rename_delete_or_hold_anything() {
        let code = production_code();

        for forbidden in [
            "rename",
            "remove_file",
            "remove_dir",
            "delete_by_handle",
            ".write(",
            "create(",
            "create_new",
            ".replace(",
            "delete(",
            "delete_if_evidence_matches",
            "share_mode",
            "access_mode",
            "open_directory_pin",
            "fs::write",
            "hard_link",
            "fs::copy",
            "set_len",
            "truncate",
            "getrandom",
            "new_v4",
            "begin_push(",
            "temp_dir",
            "pub use",
            "rename_into_directory_no_replace",
        ] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }

        for word in ["unsafe", "HeldTarget", "Staged", "Seams", "ExchangeOutcome"] {
            assert!(!contains_word(&code, word), "{word}");
        }

        // The only open in this module: the read-only directory handle.
        assert_eq!(code.matches("OpenOptions::new()").count(), 1);
        assert_eq!(code.matches("directory_identity_of(").count(), 2);
        assert!(code.contains("FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT"));

        // No file metadata is ever a stand-in for the directory identity.
        assert!(!contains_word(&code, "facts_of"));
    }

    #[test]
    fn the_module_is_private_dormant_and_unreachable_from_anything_else() {
        fn walk(dir: &Path, extension: &str, found: &mut Vec<(String, String)>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();

                if path.is_dir() {
                    if path
                        .file_name()
                        .is_some_and(|name| name == "node_modules" || name == "target")
                    {
                        continue;
                    }

                    walk(&path, extension, found);
                } else if path.extension().is_some_and(|ext| ext == extension) {
                    found.push((
                        path.file_name().unwrap().to_string_lossy().into_owned(),
                        fs::read_to_string(&path).unwrap(),
                    ));
                }
            }
        }

        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut sources = Vec::new();

        walk(&manifest.join("src"), "rs", &mut sources);

        let mut mentioning: Vec<&str> = sources
            .iter()
            .filter(|(_, text)| text.contains("exchange_recovery"))
            .map(|(name, _)| name.as_str())
            .collect();

        mentioning.sort_unstable();

        // The declaration, the module itself, and the B3b-1 reference scan that names it.
        assert_eq!(
            mentioning,
            ["exchange_recovery.rs", "session.rs", "target_exchange.rs"]
        );

        for (name, text) in &sources {
            if name != "exchange_recovery.rs" {
                assert!(!text.contains("assess_interrupted_exchange"), "{name}");
                assert!(!text.contains("ExchangeRecoveryAssessment"), "{name}");
            }
        }

        // Only a private, Windows-only declaration, and no re-export.
        let session = sources
            .iter()
            .find(|(name, _)| name == "session.rs")
            .unwrap();

        assert!(
            session
                .1
                .contains("#[cfg(windows)]\nmod exchange_recovery;")
                || session
                    .1
                    .contains("#[cfg(windows)]\r\nmod exchange_recovery;")
        );
        assert!(!session.1.contains("pub mod exchange_recovery"));
        assert!(!session.1.contains("exchange_recovery::"));

        // No frontend file knows about it.
        let mut frontend = Vec::new();

        for extension in ["ts", "tsx"] {
            walk(
                &manifest.parent().unwrap().join("src"),
                extension,
                &mut frontend,
            );
        }

        for (name, text) in frontend {
            assert!(
                !text.contains("interrupted_exchange") && !text.contains("exchange_recovery"),
                "{name}"
            );
        }
    }
}
