//! Read-only readiness assessment for updating the already bound encrypted copy
//! (Stage 1U-4, slice B3a). Dormant: no command, event or UI calls any of this,
//! and it enables no synchronization.
//!
//! # What it is
//!
//! [`UnlockedVaultSession::assess_bound_target_update`] answers one diagnostic
//! question from fresh evidence, under the session lock: *if an update of the
//! bound copy were attempted right now, would the accepted core push rules
//! (`begin_push`) allow it, and if not, why not?* The answer is a fixed
//! classification ([`UpdateReadiness`]); nothing else leaves this module.
//!
//! # What it is not
//!
//! * **[`UpdateReadiness::ProvisionallyReady`] is a diagnostic snapshot, not an
//!   authorization.** It describes the instants at which the reads ran. No later
//!   step may treat it as consent, as evidence carried forward, or as a reason to
//!   skip any check; a real update would have to repeat every check itself.
//! * It is strictly read-only. It never opens a file or directory with write or
//!   DELETE access, never requests a restrictive share mode, never holds a target
//!   handle beyond the single adapter read, never creates a staging file, never
//!   persists an intent, never calls `SyncStateStore::{create, replace, delete,
//!   delete_if_evidence_matches}`, never draws randomness, and never changes the
//!   vault, its `.backup`, its `.lock`, the target or the sync-state record.
//! * It creates, spends and voids no approval, and does not alter the session.
//! * The target is never a parameter. It comes only from the verified stored
//!   binding (a record bound to this session's authenticated vault id and local
//!   location), so neither the frontend nor a caller can name a destination.
//! * It does not use `new_copy_file::destination_is_eligible`: that is the B2
//!   *new-destination* publication preview (it pins the parent directory without
//!   share-delete and its contract is publication eligibility). Every fact needed
//!   here comes from the existing read-only adapter read and its handle facts.
//!
//! # Core rules reused, not re-implemented
//!
//! `inspect_remote_bytes` authenticates the primary and the candidate;
//! `begin_push` is evaluated as a **dry run** with a private, non-nil, never
//! persisted intent id and its returned proposal is dropped (no randomness is
//! drawn); `reconcile_pending_push` is evaluated as a dry run only to *describe* an
//! existing pending push. No decision rule (schema-3, revision, byte comparison,
//! wrapper, high-water) is repeated here.
//!
//! # Pending pushes are observational
//!
//! If the record holds a pending push, the target is read once and described as
//! matching the intended bytes, matching the baseline, or unresolved. That
//! description is never permission to finalize, clear, retry or erase anything,
//! and none of it is applied: the record is not rewritten, the baseline is not
//! advanced, and nothing is retried. A target that is absent, unreadable,
//! unidentified or unauthenticated is *unresolved*; a local miss is never passed
//! to core as authenticated remote absence.
//!
//! # Policy applied without writing
//!
//! A future update would write; the local NTFS write policy is therefore applied
//! now. A ReFS-bound copy remains a valid binding (B1g/B1j) but is reported as
//! [`UpdateBlock::TargetNotLocalNtfs`], because it is not eligible for the future
//! update path.
//!
//! # Trust and limits (not claimed away)
//!
//! * **Snapshot only; check-then-use.** The target can change right after the read,
//!   and a hard link or redirection created later is not prevented. The adapter's
//!   own change detection is length and timestamps. There is no exclusive hold.
//! * **The sync-state checksum is not a MAC.** The record can be forged or rolled
//!   back by anyone who can write local application data; a stored fingerprint is
//!   never treated as authenticated sync-state evidence on its own.
//! * **Authenticated revision order is not causal ancestry**, and equal revision
//!   numbers alone never prove identical content. Core decides with fingerprints
//!   and authenticated payload relations; this module adds no inference.
//! * **A local path is not cloud-provider authority.** A file in a synchronized
//!   folder is only a local file; nothing here proves that a provider uploaded,
//!   holds or will keep it.
//! * Filesystem name and device facts come from the driver stack and are trusted.
//!
//! Every type here is a fixed category: no `Debug` or `Display` output contains a
//! path, locator, identifier, fingerprint, revision or native status.

use std::fmt;

use thiserror::Error;
use uuid::Uuid;

use localvault_core::{
    sync::{inspect_remote_bytes, BoundInspectionError, WrapperRelation},
    sync_state::{
        begin_push, reconcile_pending_push, BindingMismatch, PushResolution, RemoteEvidence,
        SyncBase, SyncState, TransitionRefusal,
    },
};

use super::{
    bind_loaded, physical_distinct, target_is_unc, CorruptReason, HeldPrimary,
    InitialBindingRefusal, SessionSyncState, StateLoad, SyncFileRead, SyncFileTarget,
    SyncStateRoot, SyncStateStore, SyncStateUnavailable, UnavailableReason, UnlockedVaultSession,
    UnreadableReason,
};

/// The intent id given to the `begin_push` dry run. Valid and non-nil because core
/// requires that; it is never persisted, never compared with a stored id, and
/// never leaves this module (the proposal that would carry it is dropped).
const DRY_RUN_INTENT_ID: Uuid = Uuid::from_u128(0x0b3a_0000_0000_4000_8000_0000_0000_0001);

/// Result of [`UnlockedVaultSession::assess_bound_target_update`].
///
/// Diagnostic only. No variant authorizes, schedules or prepares an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum UpdateReadiness {
    /// Provisional diagnostic snapshot: the core push preconditions held at the
    /// instants of these reads. **Not an authorization to replace anything.**
    /// `wrapper_changes` is true if the local password wrapper differs from the
    /// target's (an observation, not evidence of a correct password change).
    ProvisionallyReady {
        wrapper_changes: bool,
    },
    /// Core says there are no local changes: the local envelope, the target and
    /// the checkpoint are the same bytes.
    UpToDate,
    Blocked(UpdateBlock),
}

impl fmt::Display for UpdateReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProvisionallyReady { .. } => {
                f.write_str("the update preconditions provisionally held (not an authorization)")
            }
            Self::UpToDate => f.write_str("the bound copy is up to date"),
            Self::Blocked(block) => write!(f, "the update is blocked: {block}"),
        }
    }
}

/// Why an update of the bound copy would not currently pass. Fixed categories
/// only: the nested types are existing redacted categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UpdateBlock {
    /// The session has unsaved changes. Decided before any I/O.
    #[error("the vault has unsaved changes")]
    UnsavedChanges,
    /// The session's own vault or the sync-state root cannot anchor the check.
    #[error("the vault or the sync-state location is unavailable")]
    Unavailable(SyncStateUnavailable),
    #[error("no synchronization binding exists")]
    NotConfigured,
    #[error("the synchronization binding record is corrupt")]
    Corrupt(CorruptReason),
    #[error("the synchronization binding record has an unsupported version")]
    UnsupportedVersion,
    /// Includes an unresolved recovery artifact: absence was not confirmed.
    #[error("the synchronization binding record could not be read")]
    Unreadable(UnreadableReason),
    #[error("the synchronization binding does not match this vault")]
    BindingMismatch(BindingMismatch),
    /// A push is already recorded as pending. Observational only: nothing was
    /// reconciled, cleared or retried.
    #[error("a push is already pending")]
    PendingPush(PendingPushObservation),
    #[error("the stored target is not a valid file location")]
    TargetInvalidLocator,
    /// The target is, by path or by physical identity, this vault's primary,
    /// `.backup`, `.lock` or a sync-state file.
    #[error("the target names a file that belongs to this vault or its sync state")]
    TargetIsVaultFile,
    /// A network (UNC) path, or a physical identity that cannot be established
    /// with certainty (more than one name, delete-pending, degenerate id, a failed
    /// lookup, an unsupported filesystem).
    #[error("the physical identity of the target is uncertain")]
    TargetIdentityUncertain,
    /// A local miss only. Never remote absence.
    #[error("the target file was not found in the local folder")]
    TargetAbsentOnDisk,
    #[error("the target file could not be read")]
    TargetUnavailable(UnavailableReason),
    /// The adapter paired the bytes with a locator other than the one requested.
    #[error("the target evidence does not belong to the stored target")]
    TargetEvidenceChanged,
    /// A valid binding, but not on a local NTFS volume (for example ReFS), so not
    /// eligible for the future update path.
    #[error("the target is not on a local NTFS volume")]
    TargetNotLocalNtfs,
    /// The primary or the target did not authenticate as this vault's envelope.
    #[error("the envelope inspection was rejected")]
    Inspection(BoundInspectionError),
    /// The accepted core `begin_push` refused (for example `RemoteAhead`,
    /// `Diverged`, `Converged`, `WrapperChangeBlocked`, `SameRevisionConflict`,
    /// `KnownRegression`, `NotStrictlyAboveHighWater`).
    #[error("the push transition was refused")]
    Transition(TransitionRefusal),
}

/// What a dry-run reconciliation says about an existing pending push. A
/// description, never permission: nothing is finalized, cleared or retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingPushObservation {
    /// Dry-run reconcile = `Finalize`: the target holds the intended bytes.
    TargetMatchesIntended,
    /// Dry-run reconcile = `ClearIntent` / `DeleteUnbasedRecord`: the target
    /// holds the baseline.
    TargetMatchesBaseline,
    /// `StillPending`, or the target could not be read, identified or
    /// authenticated. A missing target is never passed to core as absent.
    Unresolved,
}

impl fmt::Display for PendingPushObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TargetMatchesIntended => "the target appears to hold the intended version",
            Self::TargetMatchesBaseline => "the target appears to hold the baseline version",
            Self::Unresolved => "the pending push cannot be resolved from the target",
        })
    }
}

impl UnlockedVaultSession {
    /// Assess, read-only, whether an update of the bound copy would currently
    /// pass the core push rules. See the module documentation: the result is a
    /// diagnostic snapshot and authorizes nothing.
    pub fn assess_bound_target_update(&self, root: &SyncStateRoot) -> UpdateReadiness {
        // Before anything else, as the same check inside the operation does.
        if self.dirty {
            return UpdateReadiness::Blocked(UpdateBlock::UnsavedChanges);
        }

        let Ok(store) = SyncStateStore::new(root.path()) else {
            return UpdateReadiness::Blocked(UpdateBlock::Unavailable(SyncStateUnavailable::Root));
        };

        self.assess_bound_target_update_in(&store, &mut SyncFileTarget::read)
    }

    /// [`assess_bound_target_update`](Self::assess_bound_target_update) over an
    /// explicit store and read step. Crate-private so only the crate's own tests
    /// can substitute them: tests use it to count target reads and to inject
    /// physical facts the real volume cannot produce.
    pub(crate) fn assess_bound_target_update_in(
        &self,
        store: &SyncStateStore,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
    ) -> UpdateReadiness {
        match self.assess_inner(store, read) {
            Ok(readiness) => readiness,
            Err(block) => UpdateReadiness::Blocked(block),
        }
    }

    /// The ordered, fail-on-first checks. The primary stays open (inside
    /// `primary`) until this returns.
    fn assess_inner(
        &self,
        store: &SyncStateStore,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
    ) -> Result<UpdateReadiness, UpdateBlock> {
        use UpdateBlock as Block;

        // 1. Unsaved changes: no I/O at all.
        if self.dirty {
            return Err(Block::UnsavedChanges);
        }

        // 2. The primary is opened once, read-only, and must be exactly this
        //    session's envelope.
        let primary = self
            .hold_local_primary()
            .ok_or(Block::Unavailable(SyncStateUnavailable::LocalVaultChanged))?;

        // 3. The session's normalized local location.
        let local_locator = self
            .local_locator()
            .ok_or(Block::Unavailable(SyncStateUnavailable::LocalLocator))?;

        // 4. The stored record, verified against the authenticated vault id and
        //    the local location. Only a bound record continues.
        let state = match store.load(&local_locator) {
            StateLoad::NotConfigured => return Err(Block::NotConfigured),
            StateLoad::Corrupt(reason) => return Err(Block::Corrupt(reason)),
            StateLoad::UnsupportedVersion => return Err(Block::UnsupportedVersion),
            StateLoad::Unreadable(reason) => return Err(Block::Unreadable(reason)),
            StateLoad::Loaded(state) => {
                match bind_loaded(*state, self.data.vault_id, &local_locator) {
                    SessionSyncState::Bound(bound) => bound.state().clone(),
                    SessionSyncState::BindingMismatch(mismatch) => {
                        return Err(Block::BindingMismatch(mismatch))
                    }
                    // `bind_loaded` yields nothing else; anything unexpected is
                    // treated as unverified, never as a bound record.
                    _ => return Err(Block::Unavailable(SyncStateUnavailable::LocalVaultChanged)),
                }
            }
        };

        // 5. The target comes only from the verified record.
        let target = SyncFileTarget::from_locator(state.target_locator())
            .map_err(|_| Block::TargetInvalidLocator)?;

        // 6. Refused before any byte of the target is opened.
        if target_is_unc(&target) {
            return Err(Block::TargetIdentityUncertain);
        }

        if self.target_names_vault_file(store.directory(), &target, &local_locator) {
            return Err(Block::TargetIsVaultFile);
        }

        // 7. Exactly one read.
        let outcome = read(&target);

        // 8. A pending push is described, never applied.
        if state.pending_push().is_some() {
            return Err(Block::PendingPush(
                self.observe_pending_push(&primary, &state, &target, &outcome),
            ));
        }

        // 9. The read outcome. A local miss is not remote absence.
        let present = match outcome {
            SyncFileRead::Present(present) => present,
            SyncFileRead::AbsentOnDisk => return Err(Block::TargetAbsentOnDisk),
            SyncFileRead::Unavailable(reason) => return Err(Block::TargetUnavailable(reason)),
        };

        if present.target() != target.locator() {
            return Err(Block::TargetEvidenceChanged);
        }

        // 10. Distinct physical file, then the local-NTFS write policy.
        let facts = physical_distinct(&primary, &present).map_err(|refusal| match refusal {
            InitialBindingRefusal::TargetIsVaultFile => Block::TargetIsVaultFile,
            _ => Block::TargetIdentityUncertain,
        })?;

        if !facts.is_local_ntfs() {
            return Err(Block::TargetNotLocalNtfs);
        }

        // 11. Authenticated evidence. A record without a pending push is always
        //     based (an unbased record requires a pending initial publication);
        //     anything else fails closed through core.
        let SyncBase::Based(checkpoint) = state.base() else {
            return Err(Block::Transition(TransitionRefusal::NotBased));
        };

        let bound = inspect_remote_bytes(
            &self.vault_key,
            self.data.vault_id,
            &primary.raw,
            present.candidate_raw(),
            Some(checkpoint.high_water()),
        )
        .map_err(Block::Inspection)?;

        // 12. The core decision, as a dry run whose proposal is dropped.
        match begin_push(
            &state,
            state.local_locator(),
            state.target_locator(),
            RemoteEvidence::Inspected(&bound),
            DRY_RUN_INTENT_ID,
        ) {
            Ok(_proposal) => Ok(UpdateReadiness::ProvisionallyReady {
                wrapper_changes: bound.inspection().wrapper() == WrapperRelation::Different,
            }),
            Err(TransitionRefusal::NoLocalChanges) => Ok(UpdateReadiness::UpToDate),
            Err(refusal) => Err(Block::Transition(refusal)),
        }
    }

    /// Describe a recorded pending push against the one read already made.
    /// Observational only: the core reconciliation is a dry run and its proposed
    /// state is dropped. Anything that is not an authenticated, identified,
    /// readable target is `Unresolved`; a local miss is never converted into
    /// `RemoteEvidence::Absent`.
    fn observe_pending_push(
        &self,
        primary: &HeldPrimary,
        state: &SyncState,
        target: &SyncFileTarget,
        outcome: &SyncFileRead,
    ) -> PendingPushObservation {
        use PendingPushObservation as Observation;

        let SyncFileRead::Present(present) = outcome else {
            return Observation::Unresolved;
        };

        if present.target() != target.locator() || physical_distinct(primary, present).is_err() {
            return Observation::Unresolved;
        }

        let high_water = match state.base() {
            SyncBase::Based(checkpoint) => Some(checkpoint.high_water()),
            SyncBase::Unbased => None,
        };

        let Ok(bound) = inspect_remote_bytes(
            &self.vault_key,
            self.data.vault_id,
            &primary.raw,
            present.candidate_raw(),
            high_water,
        ) else {
            return Observation::Unresolved;
        };

        match reconcile_pending_push(
            state,
            state.local_locator(),
            state.target_locator(),
            RemoteEvidence::Inspected(&bound),
        ) {
            Ok(PushResolution::Finalize { .. }) => Observation::TargetMatchesIntended,
            Ok(PushResolution::ClearIntent { .. } | PushResolution::DeleteUnbasedRecord { .. }) => {
                Observation::TargetMatchesBaseline
            }
            Ok(PushResolution::StillPending { .. }) | Err(_) => Observation::Unresolved,
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        cell::Cell,
        fs::{self, File, OpenOptions},
        os::windows::fs::OpenOptionsExt,
        path::{Path, PathBuf},
    };

    use zeroize::Zeroizing;

    use localvault_core::{
        sync::{EnvelopeFingerprint, EnvelopeInput, RemoteHighWater},
        sync_state::{BindingId, Locator, SyncCheckpoint, VaultBindingTag, BINDING_SALT_LEN},
    };

    use super::*;
    use crate::vault::{
        file_identity::{facts_of, FileSystemKind, HandleFacts, IdentityError},
        handle_ops::test_support::{assert_local_ntfs, make_junction, snapshot},
        session::{InitialBindingApproval, InitialBindingOutcome},
        sync_state_store::SYNC_STATE_DIRECTORY,
    };

    /// Picks one of the vault's own files on a fresh rig.
    type OwnFile = fn(&mut Rig) -> PathBuf;

    const NOW_MS: i64 = 1_700_000_000_000;
    const MASTER_PASSWORD: &str = "session-master-password-test-only";
    const NEW_PASSWORD: &str = "session-new-password-test-only";

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

        dir
    }

    fn save_edit(session: &mut UnlockedVaultSession, bump: i64) {
        session.data_mut().updated_at_ms += bump;

        assert!(session.save().unwrap());
    }

    fn checkpoint_base(synced: &[u8], synced_revision: u64, high_water: u64) -> SyncBase {
        SyncBase::Based(
            SyncCheckpoint::new(
                EnvelopeFingerprint::of_bytes(synced),
                synced_revision,
                RemoteHighWater::new(high_water),
            )
            .unwrap(),
        )
    }

    /// A synthetic vault with an identical copy, an application root, and
    /// (optionally) the real B1f binding between them. `session` is declared
    /// first so that it (and its exclusive lock file) drops before the scratch
    /// directory is removed.
    struct Rig {
        session: UnlockedVaultSession,
        root: SyncStateRoot,
        target: SyncFileTarget,
        vault: PathBuf,
        copy: PathBuf,
        dir: tempfile::TempDir,
    }

    impl Rig {
        fn unbound(name: &str) -> Self {
            let dir = scratch(name);
            let vaults = dir.path().join("vaults");
            let dest = dir.path().join("dest");

            fs::create_dir_all(&vaults).unwrap();
            fs::create_dir_all(&dest).unwrap();

            let vault = vaults.join("vault.lvault");
            let session = UnlockedVaultSession::create(&vault, password(), NOW_MS).unwrap();
            let copy = dest.join("copy.lvault");

            fs::copy(&vault, &copy).unwrap();

            let target = SyncFileTarget::from_path(&copy).unwrap();
            let root = SyncStateRoot::for_test(dir.path().join("app-local"));

            Self {
                session,
                root,
                target,
                vault,
                copy,
                dir,
            }
        }

        /// Bound through the real, unchanged initial-binding operation.
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

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(self.root.path()).unwrap()
        }

        fn state_dir(&self) -> PathBuf {
            self.root.path().join(SYNC_STATE_DIRECTORY)
        }

        /// The only record file in the state directory.
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

        /// A copy of the current baseline (the copy file), opened as another
        /// session of the same vault at another path.
        fn fork(&self, label: &str) -> UnlockedVaultSession {
            let folder = self.dir.path().join(format!("fork-{label}"));

            fs::create_dir_all(&folder).unwrap();

            let path = folder.join("vault.lvault");

            fs::copy(&self.copy, &path).unwrap();

            UnlockedVaultSession::unlock(&path, password()).unwrap()
        }

        /// A record built directly, for states the real operations cannot reach.
        fn craft(&self, vault_id: Uuid, target: &str, base: SyncBase) -> SyncState {
            let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);

            SyncState::new(
                BindingId::new(Uuid::from_u128(0xB1)).unwrap(),
                VaultBindingTag::derive(salt, vault_id).unwrap(),
                self.session.local_locator().unwrap(),
                Locator::new(target).unwrap(),
                base,
                None,
            )
            .unwrap()
        }

        fn put_crafted(&self, target: &str) {
            let state = self.craft(
                self.session.data.vault_id,
                target,
                checkpoint_base(b"synthetic", 0, 0),
            );

            self.store().create(&state).unwrap();
        }

        /// Record a pending push exactly as the core `begin_push` proposes it, as
        /// fixture setup (a write the assessment itself never makes).
        fn plant_pending_push(&self) {
            let state = self.loaded_state();
            let SyncBase::Based(checkpoint) = state.base() else {
                panic!("a based state is required");
            };

            let bound = inspect_remote_bytes(
                &self.session.vault_key,
                self.session.data.vault_id,
                &fs::read(&self.vault).unwrap(),
                &fs::read(&self.copy).unwrap(),
                Some(checkpoint.high_water()),
            )
            .unwrap();

            let proposed = begin_push(
                &state,
                state.local_locator(),
                state.target_locator(),
                RemoteEvidence::Inspected(&bound),
                Uuid::from_u128(0x77),
            )
            .unwrap();

            self.store().replace(&state, &proposed).unwrap();
        }

        /// One assessment with a counted, optionally rewritten target read. The
        /// whole test-owned tree is snapshotted after all setup writes and
        /// again after the assessment, and must be identical.
        fn assess_with(
            &self,
            mut rewrite: impl FnMut(SyncFileRead) -> SyncFileRead,
        ) -> (UpdateReadiness, usize) {
            let store = self.store();
            let reads = Cell::new(0usize);
            let before = snapshot(self.dir.path());

            let result = self
                .session
                .assess_bound_target_update_in(&store, &mut |target| {
                    reads.set(reads.get() + 1);

                    rewrite(target.read())
                });

            assert_eq!(
                snapshot(self.dir.path()),
                before,
                "the assessment changed the filesystem"
            );

            (result, reads.get())
        }

        fn assess(&self) -> (UpdateReadiness, usize) {
            self.assess_with(|read| read)
        }

        fn expect(&self, expected: UpdateReadiness, reads: usize) {
            assert_eq!(self.assess(), (expected, reads));
        }

        fn blocked(&self, block: UpdateBlock, reads: usize) {
            self.expect(UpdateReadiness::Blocked(block), reads);
        }
    }

    // ---- the core decisions, over a real binding ------------------------------

    #[test]
    fn just_bound_and_identical_is_up_to_date() {
        let rig = Rig::bound("b3a-up-to-date");

        rig.expect(UpdateReadiness::UpToDate, 1);
    }

    #[test]
    fn a_local_save_after_binding_is_provisionally_ready_without_wrapper_changes() {
        let mut rig = Rig::bound("b3a-ready");

        save_edit(&mut rig.session, 1);

        rig.expect(
            UpdateReadiness::ProvisionallyReady {
                wrapper_changes: false,
            },
            1,
        );
    }

    #[test]
    fn a_copy_changed_by_another_session_is_remote_ahead() {
        let rig = Rig::bound("b3a-remote-ahead");
        let mut fork = rig.fork("a");

        save_edit(&mut fork, 5);
        fs::copy(fork.path(), &rig.copy).unwrap();

        rig.blocked(UpdateBlock::Transition(TransitionRefusal::RemoteAhead), 1);
    }

    #[test]
    fn both_sides_changed_is_diverged() {
        let mut rig = Rig::bound("b3a-diverged");
        let mut fork = rig.fork("a");

        save_edit(&mut fork, 5);
        fs::copy(fork.path(), &rig.copy).unwrap();
        save_edit(&mut rig.session, 1);

        rig.blocked(UpdateBlock::Transition(TransitionRefusal::Diverged), 1);
    }

    #[test]
    fn both_sides_changed_to_identical_bytes_is_converged() {
        let mut rig = Rig::bound("b3a-converged");

        save_edit(&mut rig.session, 1);
        fs::copy(&rig.vault, &rig.copy).unwrap();

        rig.blocked(UpdateBlock::Transition(TransitionRefusal::Converged), 1);
    }

    #[test]
    fn two_forks_at_the_same_revision_are_a_same_revision_conflict() {
        // The copy is a fork at revision 1 and is also the recorded checkpoint;
        // the local vault is a different fork at the same revision. The record is
        // built directly because no real operation can bind two such forks.
        let mut rig = Rig::unbound("b3a-same-revision");
        let mut fork = rig.fork("a");

        save_edit(&mut fork, 5);
        fs::copy(fork.path(), &rig.copy).unwrap();
        save_edit(&mut rig.session, 1);

        let state = rig.craft(
            rig.session.data.vault_id,
            rig.copy.to_str().unwrap(),
            checkpoint_base(&fs::read(&rig.copy).unwrap(), 1, 1),
        );

        rig.store().create(&state).unwrap();

        rig.blocked(
            UpdateBlock::Transition(TransitionRefusal::SameRevisionConflict),
            1,
        );
    }

    #[test]
    fn a_high_water_above_the_baseline_is_a_known_regression() {
        let mut rig = Rig::bound("b3a-regression");
        let mut fork = rig.fork("a");

        save_edit(&mut rig.session, 1);
        save_edit(&mut fork, 5);

        // Fixture setup: an authenticated higher observation raises the mark. The
        // copy itself still holds the baseline bytes.
        assert_eq!(
            rig.session.record_remote_observation(
                &rig.root,
                rig.target.locator(),
                &fs::read(fork.path()).unwrap(),
            ),
            Ok(crate::vault::session::RemoteObservationOutcome::HighWaterRaised)
        );

        rig.blocked(
            UpdateBlock::Transition(TransitionRefusal::KnownRegression),
            1,
        );
    }

    #[test]
    fn a_password_only_change_is_blocked_and_a_password_change_with_an_edit_is_ready() {
        let mut rig = Rig::bound("b3a-wrapper");

        rig.session
            .change_master_password(password(), Zeroizing::new(NEW_PASSWORD.to_owned()))
            .unwrap();

        rig.blocked(
            UpdateBlock::Transition(TransitionRefusal::WrapperChangeBlocked),
            1,
        );

        save_edit(&mut rig.session, 1);

        rig.expect(
            UpdateReadiness::ProvisionallyReady {
                wrapper_changes: true,
            },
            1,
        );
    }

    // ---- the target itself -------------------------------------------------------

    #[test]
    fn a_corrupt_or_foreign_target_fails_authentication() {
        let rig = Rig::bound("b3a-corrupt-foreign");

        fs::write(&rig.copy, b"this is not an envelope").unwrap();

        rig.blocked(
            UpdateBlock::Inspection(BoundInspectionError::MalformedEnvelope {
                input: EnvelopeInput::Candidate,
            }),
            1,
        );

        // Another vault's genuine envelope under the same password.
        let foreign_dir = rig.dir.path().join("foreign");

        fs::create_dir_all(&foreign_dir).unwrap();

        let foreign_path = foreign_dir.join("vault.lvault");
        let _foreign = UnlockedVaultSession::create(&foreign_path, password(), NOW_MS).unwrap();

        fs::copy(&foreign_path, &rig.copy).unwrap();

        let (result, reads) = rig.assess();

        assert_eq!(reads, 1);
        assert!(
            matches!(
                result,
                UpdateReadiness::Blocked(UpdateBlock::Inspection(
                    BoundInspectionError::Inspection(_)
                ))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn a_missing_directory_or_junction_target_is_never_ready() {
        let rig = Rig::bound("b3a-absent-dir-junction");

        fs::remove_file(&rig.copy).unwrap();
        rig.blocked(UpdateBlock::TargetAbsentOnDisk, 1);

        fs::create_dir(&rig.copy).unwrap();
        rig.blocked(
            UpdateBlock::TargetUnavailable(UnavailableReason::UnexpectedObject),
            1,
        );

        fs::remove_dir(&rig.copy).unwrap();
        fs::copy(&rig.vault, &rig.copy).unwrap();
        rig.expect(UpdateReadiness::UpToDate, 1);

        // The folder holding the copy becomes a junction to the real folder.
        let dest = rig.copy.parent().unwrap().to_path_buf();
        let moved = rig.dir.path().join("dest-real");

        fs::rename(&dest, &moved).unwrap();
        make_junction(&dest, &moved);

        rig.blocked(
            UpdateBlock::TargetUnavailable(UnavailableReason::UnexpectedObject),
            1,
        );
    }

    #[test]
    fn a_hard_link_to_the_primary_is_the_vaults_own_file() {
        let rig = Rig::bound("b3a-hardlink-primary");

        fs::remove_file(&rig.copy).unwrap();
        fs::hard_link(&rig.vault, &rig.copy).unwrap();

        rig.blocked(UpdateBlock::TargetIsVaultFile, 1);
    }

    #[test]
    fn a_target_with_a_second_name_is_uncertain() {
        let rig = Rig::bound("b3a-second-link");

        fs::hard_link(&rig.copy, rig.copy.with_file_name("alias.lvault")).unwrap();

        rig.blocked(UpdateBlock::TargetIdentityUncertain, 1);
    }

    #[test]
    fn injected_physical_facts_are_judged_by_the_unchanged_identity_policy() {
        let mut rig = Rig::bound("b3a-injected-facts");

        save_edit(&mut rig.session, 1);

        let primary_facts = facts_of(&File::open(&rig.vault).unwrap()).unwrap();
        let real_target_facts = facts_of(&File::open(&rig.copy).unwrap()).unwrap();

        let facts = |filesystem, local, links, pending| {
            HandleFacts::for_test(7, [9; 16], links, pending, filesystem, local)
        };
        let injected = |physical: Result<HandleFacts, IdentityError>| {
            move |read: SyncFileRead| match read {
                SyncFileRead::Present(present) => {
                    SyncFileRead::Present(present.with_physical_for_test(physical))
                }
                other => other,
            }
        };

        // Local ReFS is a valid binding but not eligible for the update path.
        assert_eq!(
            rig.assess_with(injected(Ok(facts(FileSystemKind::Refs, true, 1, false)))),
            (UpdateReadiness::Blocked(UpdateBlock::TargetNotLocalNtfs), 1)
        );

        // Everything the identity policy cannot vouch for is uncertain.
        for (label, physical) in [
            ("FAT-like", Ok(facts(FileSystemKind::Other, true, 1, false))),
            (
                "non-local NTFS",
                Ok(facts(FileSystemKind::Ntfs, false, 1, false)),
            ),
            ("two names", Ok(facts(FileSystemKind::Ntfs, true, 2, false))),
            (
                "delete-pending",
                Ok(facts(FileSystemKind::Ntfs, true, 1, true)),
            ),
            ("lookup failed", Err(IdentityError::Lookup)),
            ("unsupported", Err(IdentityError::Unsupported)),
        ] {
            assert_eq!(
                rig.assess_with(injected(physical)),
                (
                    UpdateReadiness::Blocked(UpdateBlock::TargetIdentityUncertain),
                    1
                ),
                "{label}"
            );
        }

        // The primary's own identity reported for the target.
        assert_eq!(
            rig.assess_with(injected(Ok(
                real_target_facts.with_identity_of(&primary_facts)
            ))),
            (UpdateReadiness::Blocked(UpdateBlock::TargetIsVaultFile), 1)
        );

        // And the unmodified read is still ready.
        rig.expect(
            UpdateReadiness::ProvisionallyReady {
                wrapper_changes: false,
            },
            1,
        );
    }

    #[test]
    fn evidence_paired_with_another_locator_is_not_trusted() {
        let mut rig = Rig::bound("b3a-evidence-changed");

        save_edit(&mut rig.session, 1);

        let other = SyncFileTarget::from_path(rig.vault.as_path()).unwrap();

        assert_eq!(
            rig.assess_with(|_| other.read()),
            (
                UpdateReadiness::Blocked(UpdateBlock::TargetEvidenceChanged),
                1
            )
        );
    }

    // ---- pending pushes: observational only ----------------------------------

    #[test]
    fn a_pending_push_is_described_and_never_applied() {
        let mut rig = Rig::bound("b3a-pending");

        save_edit(&mut rig.session, 1);
        rig.plant_pending_push();

        let record = rig.record();
        let record_bytes = fs::read(&record).unwrap();
        let pending_blocked =
            |observation| UpdateReadiness::Blocked(UpdateBlock::PendingPush(observation));

        // The copy is still the baseline.
        assert_eq!(
            rig.assess(),
            (
                pending_blocked(PendingPushObservation::TargetMatchesBaseline),
                1
            )
        );

        // The copy holds exactly the intended bytes.
        fs::copy(&rig.vault, &rig.copy).unwrap();
        assert_eq!(
            rig.assess(),
            (
                pending_blocked(PendingPushObservation::TargetMatchesIntended),
                1
            )
        );

        // A third version of the same vault.
        let mut fork = rig.fork("third");

        save_edit(&mut fork, 9);
        fs::copy(fork.path(), &rig.copy).unwrap();
        assert_eq!(
            rig.assess(),
            (pending_blocked(PendingPushObservation::Unresolved), 1)
        );

        // Unreadable, absent and corrupt targets are unresolved, never "absent".
        fs::remove_file(&rig.copy).unwrap();
        assert_eq!(
            rig.assess(),
            (pending_blocked(PendingPushObservation::Unresolved), 1)
        );

        fs::create_dir(&rig.copy).unwrap();
        assert_eq!(
            rig.assess(),
            (pending_blocked(PendingPushObservation::Unresolved), 1)
        );

        fs::remove_dir(&rig.copy).unwrap();
        fs::write(&rig.copy, b"not an envelope").unwrap();
        assert_eq!(
            rig.assess(),
            (pending_blocked(PendingPushObservation::Unresolved), 1)
        );

        // The record, pending intent included, is exactly as it was.
        assert_eq!(fs::read(&record).unwrap(), record_bytes);
        assert!(rig.loaded_state().pending_push().is_some());
    }

    #[test]
    fn a_pending_push_with_an_aliasing_target_is_unresolved() {
        let mut rig = Rig::bound("b3a-pending-alias");

        save_edit(&mut rig.session, 1);
        rig.plant_pending_push();

        fs::remove_file(&rig.copy).unwrap();
        fs::hard_link(&rig.vault, &rig.copy).unwrap();

        rig.blocked(
            UpdateBlock::PendingPush(PendingPushObservation::Unresolved),
            1,
        );
    }

    // ---- the record, before any target read ----------------------------------

    #[test]
    fn no_record_blocks_without_reading_the_target() {
        let rig = Rig::unbound("b3a-not-configured");

        rig.blocked(UpdateBlock::NotConfigured, 0);
    }

    #[test]
    fn a_damaged_record_blocks_without_reading_the_target() {
        let rig = Rig::bound("b3a-damaged-record");
        let record = rig.record();
        let valid = fs::read(&record).unwrap();

        fs::write(&record, b"garbage").unwrap();
        rig.blocked(UpdateBlock::Corrupt(CorruptReason::Undecodable), 0);

        fs::write(&record, b"").unwrap();
        rig.blocked(UpdateBlock::Corrupt(CorruptReason::Empty), 0);

        let mut future: serde_json::Value = serde_json::from_slice(&valid).unwrap();

        future["version"] = serde_json::json!(2);
        future["added_in_v2"] = serde_json::json!(true);
        fs::write(&record, serde_json::to_vec(&future).unwrap()).unwrap();
        rig.blocked(UpdateBlock::UnsupportedVersion, 0);

        // A directory where the record belongs.
        fs::remove_file(&record).unwrap();
        fs::create_dir(&record).unwrap();
        rig.blocked(
            UpdateBlock::Unreadable(UnreadableReason::UnexpectedObject),
            0,
        );

        // An interrupted-write artifact with no record: absence is not confirmed.
        fs::remove_dir(&record).unwrap();

        let artifact = record.with_extension(format!("{}.tmp", "0".repeat(32)));

        fs::write(&artifact, b"leftover").unwrap();
        rig.blocked(
            UpdateBlock::Unreadable(UnreadableReason::UnresolvedArtifacts),
            0,
        );
    }

    #[test]
    fn a_record_of_another_vault_is_a_binding_mismatch() {
        let rig = Rig::unbound("b3a-foreign-record");
        let state = rig.craft(
            Uuid::from_u128(0xF0),
            rig.copy.to_str().unwrap(),
            checkpoint_base(b"synthetic", 0, 0),
        );

        rig.store().create(&state).unwrap();

        rig.blocked(
            UpdateBlock::BindingMismatch(BindingMismatch::VaultIdentity),
            0,
        );
    }

    #[test]
    fn a_stored_target_that_is_invalid_unc_or_the_vaults_own_is_refused_before_any_read() {
        // An invalid stored locator.
        let rig = Rig::unbound("b3a-invalid-locator");

        rig.put_crafted(r"relative\copy.lvault");
        rig.blocked(UpdateBlock::TargetInvalidLocator, 0);

        // A network path, also in its verbatim form.
        for unc in [
            r"\\server.invalid\share\copy.lvault",
            r"\\?\UNC\server.invalid\share\copy.lvault",
        ] {
            let rig = Rig::unbound("b3a-unc");

            rig.put_crafted(unc);
            rig.blocked(UpdateBlock::TargetIdentityUncertain, 0);
        }

        // The vault's own `.lock`, `.backup` and a file in the state directory,
        // each on a fresh rig (the record is created once per rig).
        let own_files: [(&str, OwnFile); 3] = [
            ("b3a-own-lock", |rig| {
                super::super::lock_path_for(&rig.vault)
            }),
            ("b3a-own-backup", |rig| {
                // A save creates the internal previous-version backup.
                save_edit(&mut rig.session, 1);

                let backup = rig.session.backup_path().to_path_buf();

                assert!(backup.exists());

                backup
            }),
            ("b3a-own-state-dir", |rig| {
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
            rig.blocked(UpdateBlock::TargetIsVaultFile, 0);
        }
    }

    #[test]
    fn a_dirty_session_is_refused_before_any_io() {
        let mut rig = Rig::bound("b3a-dirty");

        rig.session.data_mut().updated_at_ms += 1;

        // Not even the primary is needed to answer: no I/O happens first.
        fs::remove_file(&rig.vault).unwrap();

        rig.blocked(UpdateBlock::UnsavedChanges, 0);

        let outer = rig.session.assess_bound_target_update(&rig.root);

        assert_eq!(outer, UpdateReadiness::Blocked(UpdateBlock::UnsavedChanges));
    }

    #[test]
    fn a_replaced_primary_is_unavailable() {
        let rig = Rig::bound("b3a-primary-changed");

        // The primary is no longer the envelope this session unlocked.
        let other_dir = rig.dir.path().join("elsewhere");

        fs::create_dir_all(&other_dir).unwrap();

        let other = other_dir.join("vault.lvault");
        let _other = UnlockedVaultSession::create(&other, password(), NOW_MS).unwrap();

        fs::copy(&other, &rig.vault).unwrap();

        rig.blocked(
            UpdateBlock::Unavailable(SyncStateUnavailable::LocalVaultChanged),
            0,
        );
    }

    // ---- read-only proof ------------------------------------------------------

    #[test]
    fn the_assessment_succeeds_while_files_are_held_by_a_handle_denying_write_and_delete() {
        let mut rig = Rig::bound("b3a-share-read-only");

        save_edit(&mut rig.session, 1);

        // `FILE_SHARE_READ` only: another open must ask for read access alone,
        // so a write or DELETE request by the assessment would fail here.
        let hold = |path: &Path| {
            OpenOptions::new()
                .read(true)
                .share_mode(0x0000_0001)
                .open(path)
                .unwrap()
        };
        let _primary = hold(&rig.vault);
        let _copy = hold(&rig.copy);
        let _record = hold(&rig.record());

        rig.expect(
            UpdateReadiness::ProvisionallyReady {
                wrapper_changes: false,
            },
            1,
        );

        // The same for the public entry point.
        assert_eq!(
            rig.session.assess_bound_target_update(&rig.root),
            UpdateReadiness::ProvisionallyReady {
                wrapper_changes: false
            }
        );
    }

    #[test]
    fn the_assessment_is_repeatable_and_touches_no_approval() {
        let mut rig = Rig::bound("b3a-no-approval");

        save_edit(&mut rig.session, 1);

        let _preview = rig.session.prepare_binding_reset(&rig.root).unwrap();
        let pending = rig.session.pending_binding_reset.as_ref().map(|p| p.id);

        assert!(pending.is_some());

        let first = rig.assess();
        let second = rig.assess();

        assert_eq!(first, second);
        assert_eq!(
            rig.session.pending_binding_reset.as_ref().map(|p| p.id),
            pending
        );
        assert!(rig.session.pending_initial_binding.is_none());
        assert!(rig.session.pending_copy_creation.is_none());
        assert!(!rig.session.dirty);
    }

    #[test]
    fn the_public_entry_point_matches_the_injectable_one_over_the_real_store() {
        let mut rig = Rig::bound("b3a-public-entry");

        assert_eq!(
            rig.session.assess_bound_target_update(&rig.root),
            UpdateReadiness::UpToDate
        );

        save_edit(&mut rig.session, 1);

        assert_eq!(
            rig.session.assess_bound_target_update(&rig.root),
            UpdateReadiness::ProvisionallyReady {
                wrapper_changes: false
            }
        );
    }

    #[test]
    fn the_dry_run_intent_id_is_a_valid_non_nil_constant() {
        assert!(!DRY_RUN_INTENT_ID.is_nil());
        assert_eq!(DRY_RUN_INTENT_ID.get_version_num(), 4);
    }

    #[test]
    fn nothing_here_prints_paths_identifiers_or_content() {
        let mut rig = Rig::bound("b3a-redaction");

        save_edit(&mut rig.session, 1);

        let mut shown: Vec<String> = Vec::new();
        let mut note = |value: &dyn std::fmt::Debug, text: String| {
            shown.push(format!("{value:?}"));
            shown.push(text);
        };

        for observation in [
            PendingPushObservation::TargetMatchesIntended,
            PendingPushObservation::TargetMatchesBaseline,
            PendingPushObservation::Unresolved,
        ] {
            note(&observation, observation.to_string());
            note(
                &UpdateBlock::PendingPush(observation),
                UpdateBlock::PendingPush(observation).to_string(),
            );
        }

        for block in [
            UpdateBlock::UnsavedChanges,
            UpdateBlock::Unavailable(SyncStateUnavailable::Root),
            UpdateBlock::NotConfigured,
            UpdateBlock::Corrupt(CorruptReason::Undecodable),
            UpdateBlock::UnsupportedVersion,
            UpdateBlock::Unreadable(UnreadableReason::UnresolvedArtifacts),
            UpdateBlock::BindingMismatch(BindingMismatch::TargetLocator),
            UpdateBlock::TargetInvalidLocator,
            UpdateBlock::TargetIsVaultFile,
            UpdateBlock::TargetIdentityUncertain,
            UpdateBlock::TargetAbsentOnDisk,
            UpdateBlock::TargetUnavailable(UnavailableReason::Io(
                std::io::ErrorKind::PermissionDenied,
            )),
            UpdateBlock::TargetEvidenceChanged,
            UpdateBlock::TargetNotLocalNtfs,
            UpdateBlock::Inspection(BoundInspectionError::MalformedEnvelope {
                input: EnvelopeInput::Candidate,
            }),
            UpdateBlock::Transition(TransitionRefusal::RemoteAhead),
        ] {
            note(&block, block.to_string());
            note(
                &UpdateReadiness::Blocked(block),
                UpdateReadiness::Blocked(block).to_string(),
            );
        }

        for readiness in [
            UpdateReadiness::UpToDate,
            UpdateReadiness::ProvisionallyReady {
                wrapper_changes: true,
            },
        ] {
            note(&readiness, readiness.to_string());
        }

        // The real outcomes of this very vault, too.
        let (real, _) = rig.assess();

        note(&real, real.to_string());

        let vault_bytes = fs::read(&rig.vault).unwrap();
        let copy_bytes = fs::read(&rig.copy).unwrap();
        let record = rig.record();
        let needles = [
            "vault.lvault".to_owned(),
            "copy.lvault".to_owned(),
            ".qa-local".to_owned(),
            MASTER_PASSWORD.to_owned(),
            rig.session.data.vault_id.to_string(),
            rig.session.data.vault_id.simple().to_string(),
            EnvelopeFingerprint::of_bytes(&vault_bytes).to_hex(),
            EnvelopeFingerprint::of_bytes(&copy_bytes).to_hex(),
            rig.dir.path().to_string_lossy().into_owned(),
            record.file_stem().unwrap().to_string_lossy().into_owned(),
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
