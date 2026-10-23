//! Guarded creation of one new encrypted copy of the unlocked vault (Stage 1U-4,
//! slice B2a). Dormant: no command, event or UI calls any of this.
//!
//! # What it does
//!
//! Creates ONE new file, at a user-selected local NTFS path that does not exist,
//! holding **the exact authenticated raw on-disk bytes** of this session's vault
//! file. It is a separate, explicit, two-step consent (prepare, then confirm)
//! owned by the Rust session, exactly like the initial binding (B1h) and the
//! binding reset (B1i), with which it excludes itself: preparing or confirming any
//! one of the three discards the other two.
//!
//! # What it deliberately does not do
//!
//! * It never overwrites, replaces, truncates or deletes an existing target, and
//!   never creates a directory. The destination parent must already exist.
//! * It never writes the sync state and never binds the new copy: afterwards the
//!   state is exactly as before (`NotConfigured`). Binding stays the separate,
//!   unchanged B1h flow, which re-reads and re-authenticates the file.
//! * It does not call `plan_initial_publication`, `begin_push` or
//!   `reconcile_pending_push`, and it never turns `AbsentOnDisk` into evidence of
//!   remote absence: a local miss is a fact about this folder at this instant.
//! * It uses no transport, no provider and no network.
//!
//! # Prepare (read-only; writes nothing)
//!
//! All pending approvals are discarded first. The session must have no unsaved
//! changes; the primary is held open once and must be exactly this session's
//! envelope (schema 3, an authenticated revision counter; a legacy vault is
//! refused); the sync state must be a confirmed `NotConfigured`; the target must
//! not be a UNC path, the vault, its `.backup`, its `.lock` or a file inside the
//! sync-state directory; it must be **absent**; and its parent must already be an
//! eligible directory (plain, on a local NTFS volume). A fresh random id is drawn
//! last. The pending details are private to this module and are never serialized.
//!
//! # Confirm (spent by every call)
//!
//! The pending approval is taken out of the session before anything is checked,
//! so a stale, mistaken or failed confirmation can never be retried against the
//! same preparation. The id and the 120-second lifetime are checked before any
//! file is read. Every preparation check is then repeated with fresh evidence
//! (the vault bytes must still have the prepared fingerprint, the target must
//! still be absent, the sync state still `NotConfigured`), and the file is
//! published by the handle-bound no-replace primitive of `new_copy_file`. The copy
//! is then independently read back and must be the same physical file with the
//! same bytes, and its bytes must authenticate under this session's Vault Key
//! with the same fingerprint and the same revision counter as the vault.
//! [`CopyCreationOutcome::CreatedAndVerified`] is returned only after all of it.
//!
//! # Outcomes (nothing is retried; nothing is bound)
//!
//! * `Stale`, `Refused`: nothing was written.
//! * `NotPublished { staging_remains: false }`: nothing is left behind.
//! * `NotPublished { staging_remains: true }`: no target was published, but a
//!   hidden staging file of this attempt could not be confirmed removed.
//! * `PublicationUnknown`: the target may or may not exist. Nothing was deleted.
//! * `CreatedUnverified`: the target exists (or may) and an independent check
//!   failed or could not run. It is kept.
//!
//! After `PublicationUnknown` and `CreatedUnverified` there is no automatic
//! retry, no cleanup of the target, no binding and no trust-state change.
//!
//! # Limits
//!
//! The creation is an unlocked, check-then-use sequence guarded by sharing modes,
//! not an atomic transaction; see `new_copy_file` for the remaining path and
//! ancestor races, the privileged-actor limits and the durability statement
//! (the published name is not claimed to survive a power loss).
//!
//! The copy keeps this vault's current password wrapper: a later master-password
//! change in this session does not update it, and a later save makes it stale
//! (binding it would then be refused).
//!
//! No path, id, fingerprint, revision, file identifier or content appears in any
//! `Debug` or error output of these types.

use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

use thiserror::Error;
use uuid::Uuid;

use localvault_core::sync::{
    inspect_local_bytes, inspect_remote_bytes, AuthenticatedRevision, EnvelopeFingerprint,
};

use super::{
    lock_path_for, path_identity_eq, target_is_unc, HeldPrimary, Locator, StateLoad, SyncFileRead,
    SyncFileTarget, SyncStateStore, SyncStateUnavailable, UnavailableReason, UnlockedVaultSession,
};
use crate::vault::{
    file_identity::HandleFacts,
    new_copy_file::{
        destination_is_eligible, publish_new_copy, PublishOutcome, PublishRequest, Seams,
    },
    sync_state_store::SyncStateRoot,
};

pub use crate::vault::new_copy_file::NotPublishedReason;

/// How long a successful preparation stays confirmable. Measured from the
/// preparation, in addition to the session's own inactivity lock.
const COPY_CREATION_APPROVAL_TTL: Duration = Duration::from_secs(120);

/// What [`UnlockedVaultSession::prepare_copy_creation`] established and is now
/// waiting to be confirmed. It exists only as a field of the unlocked session:
/// never serialized, logged, persisted or handed out, and dropped with the
/// session. Private to the session module, so no other code can build one.
pub(super) struct PendingCopyCreation {
    /// Opaque random correlation id. It ties a confirmation to the preview that
    /// was shown; it is not a secret and not proof of consent.
    id: Uuid,
    /// The exact absent target the user selected.
    target: SyncFileTarget,
    /// Fingerprint of the exact bytes of the vault file at preparation.
    source_fingerprint: EnvelopeFingerprint,
    /// The authenticated schema-3 revision counter of those bytes.
    source_revision: u64,
    prepared_at: Instant,
}

impl std::fmt::Debug for PendingCopyCreation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingCopyCreation(<redacted>)")
    }
}

/// What the user must be shown before a copy may be created. Returned only by a
/// successful [`UnlockedVaultSession::prepare_copy_creation`]. `target_path` is
/// the exact locator string Rust will create, not a copy supplied by a caller.
/// Both strings are for display only; `Debug` shows nothing and the type is not
/// `Clone`.
pub struct CopyCreationPreview {
    preparation_id: String,
    vault_file_name: String,
    target_path: String,
}

impl CopyCreationPreview {
    /// Opaque correlation id to pass back to
    /// [`UnlockedVaultSession::confirm_copy_creation`].
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

impl std::fmt::Debug for CopyCreationPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CopyCreationPreview(<redacted>)")
    }
}

/// What a successful [`UnlockedVaultSession::confirm_copy_creation`]
/// established. Fieldless on purpose: no path, fingerprint, revision or
/// identifier.
///
/// It means: the file was created by a no-replace, handle-bound rename, then read
/// back independently as the same physical file (one link, local NTFS, distinct
/// from the vault) with exactly the vault's bytes, and those bytes authenticated
/// under this session's key with the vault's fingerprint and revision counter. It
/// does **not** mean the copy is bound, synchronized, durable across a power
/// loss, accepted by any cloud provider, or current after the next save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum CopyCreationOutcome {
    CreatedAndVerified,
}

/// Why no copy was prepared, or why a confirmation refused before anything was
/// written. Fixed categories only. Nothing here wrote anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CopyCreationRefusal {
    /// The session has unsaved changes: the copy would not be what the user sees.
    #[error("the vault has unsaved changes")]
    UnsavedChanges,
    /// A schema-1/2 vault has no authenticated revision counter.
    #[error("the vault has no authenticated revision counter")]
    LegacyVault,
    /// A synchronization record for this location exists (valid or not).
    #[error("a synchronization binding already exists")]
    BindingExists,
    /// The sync state could not be read, is corrupt or has an unsupported
    /// version, so a confirmed `NotConfigured` is not available.
    #[error("the synchronization binding record could not be read")]
    BindingStateUnreadable,
    /// Something already exists at the target name.
    #[error("the target already exists")]
    TargetExists,
    /// The target is, or cannot be shown not to be, the vault, its `.backup`, its
    /// `.lock` or a file inside the sync-state directory.
    #[error("the target names a file that belongs to this vault or its sync state")]
    TargetIsVaultFile,
    /// The target is a UNC path, its parent is missing or not an eligible local
    /// NTFS directory, or an ancestor is not a plain directory.
    #[error("the target location is not supported")]
    TargetLocationUnsupported,
    /// The target could not be inspected (an I/O failure, a changed state).
    #[error("the target could not be inspected")]
    TargetUnavailable,
    /// The physical identity of the vault file could not be established.
    #[error("the physical identity of the vault file is uncertain")]
    SourceIdentityUncertain,
    /// The session's own vault or location cannot serve as the source.
    #[error("the session's vault or sync-state location is unavailable")]
    Unavailable(SyncStateUnavailable),
    /// Secure randomness for the preparation id was unavailable.
    #[error("secure randomness is unavailable")]
    Randomness,
}

/// Why a confirmation was rejected as out of date. In every case nothing was
/// written and the preparation is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CopyCreationStale {
    /// No successful preparation is pending: none was made, it was already
    /// confirmed or cancelled, another approval replaced it, or its session is
    /// gone.
    #[error("no copy creation is waiting for confirmation")]
    NoPendingApproval,
    /// The id does not name the pending preparation.
    #[error("the confirmation does not belong to the current preparation")]
    NotCurrentPreparation,
    /// The preparation is older than its lifetime.
    #[error("the preparation has expired")]
    Expired,
    /// The vault file changed after the preparation (for example a save).
    #[error("the vault changed after the preparation")]
    LocalVaultChanged,
    /// Something now exists at the target name.
    #[error("the target appeared after the preparation")]
    TargetAppeared,
}

/// Why [`UnlockedVaultSession::confirm_copy_creation`] did not report a verified
/// copy. Fixed categories only. Whatever the variant, the preparation is spent
/// and nothing is retried, bound or trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CopyCreationConfirmRefusal {
    /// Out of date. Nothing was written.
    #[error("the copy creation confirmation is out of date")]
    Stale(CopyCreationStale),
    /// Refused before any write.
    #[error("the copy creation was refused")]
    Refused(CopyCreationRefusal),
    /// Definitely no target was published. `staging_remains` says whether this
    /// attempt's own hidden staging file could not be confirmed removed.
    #[error("the copy was not created")]
    NotPublished {
        reason: NotPublishedReason,
        staging_remains: bool,
    },
    /// The target may or may not have been created. Nothing was deleted.
    #[error("whether the copy was created could not be established")]
    PublicationUnknown,
    /// The target exists (or may) but an independent check failed or could not
    /// run. It is kept; do not bind it without checking the folder.
    #[error("the copy was created but could not be verified")]
    CreatedUnverified,
}

/// The read-only evidence both steps rest on. Holds the primary open.
struct Examined {
    primary: HeldPrimary,
    primary_facts: HandleFacts,
    local_locator: Locator,
    fingerprint: EnvelopeFingerprint,
    revision: u64,
}

enum ExamineFailure {
    Refused(CopyCreationRefusal),
    /// The vault bytes are no longer the prepared ones.
    SourceChanged,
}

impl From<CopyCreationRefusal> for ExamineFailure {
    fn from(refusal: CopyCreationRefusal) -> Self {
        Self::Refused(refusal)
    }
}

impl UnlockedVaultSession {
    /// The read-only examination both steps rest on, in this order: no unsaved
    /// changes; the primary held open once and authenticated with a schema-3
    /// revision counter; the local location; a confirmed `NotConfigured` sync
    /// state; a target that is not UNC and not one of the vault's own files; a
    /// target that is absent; an eligible destination parent. It writes nothing,
    /// creates nothing and draws no randomness.
    fn examine_copy_creation(
        &self,
        store: &SyncStateStore,
        target: &SyncFileTarget,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
        expected: Option<EnvelopeFingerprint>,
    ) -> Result<Examined, ExamineFailure> {
        use CopyCreationRefusal as Refusal;

        if self.dirty {
            return Err(Refusal::UnsavedChanges.into());
        }

        let primary = self.hold_local_primary().ok_or(Refusal::Unavailable(
            SyncStateUnavailable::LocalVaultChanged,
        ))?;

        let snapshot = inspect_local_bytes(&self.vault_key, self.data.vault_id, &primary.raw)
            .map_err(|_| Refusal::Unavailable(SyncStateUnavailable::LocalVaultChanged))?;

        if expected.is_some_and(|fingerprint| fingerprint != *snapshot.fingerprint()) {
            return Err(ExamineFailure::SourceChanged);
        }

        let AuthenticatedRevision::Counter(revision) = snapshot.revision() else {
            return Err(Refusal::LegacyVault.into());
        };

        let primary_facts = *primary
            .physical
            .as_ref()
            .map_err(|_| Refusal::SourceIdentityUncertain)?;

        let local_locator = self
            .local_locator()
            .ok_or(Refusal::Unavailable(SyncStateUnavailable::LocalLocator))?;

        match store.load(&local_locator) {
            StateLoad::NotConfigured => {}
            StateLoad::Loaded(_) => return Err(Refusal::BindingExists.into()),
            StateLoad::Corrupt(_) | StateLoad::UnsupportedVersion | StateLoad::Unreadable(_) => {
                return Err(Refusal::BindingStateUnreadable.into())
            }
        }

        // Refused before anything touches the target: a network path is never
        // eligible, and the vault's own files cannot be a copy's name.
        if target_is_unc(target) {
            return Err(Refusal::TargetLocationUnsupported.into());
        }

        if self.target_names_vault_file(store.directory(), target, &local_locator)
            || self.absent_target_collides_with_vault_files(
                store.directory(),
                target,
                &local_locator,
            )
        {
            return Err(Refusal::TargetIsVaultFile.into());
        }

        // The target must be absent. A local miss is a fact about this folder at
        // this instant, never about any remote.
        match read(target) {
            SyncFileRead::AbsentOnDisk => {}
            SyncFileRead::Present(_) => return Err(Refusal::TargetExists.into()),
            SyncFileRead::Unavailable(
                UnavailableReason::ParentMissing
                | UnavailableReason::UnexpectedObject
                | UnavailableReason::Unsupported,
            ) => return Err(Refusal::TargetLocationUnsupported.into()),
            SyncFileRead::Unavailable(_) => return Err(Refusal::TargetUnavailable.into()),
        }

        if !destination_is_eligible(Path::new(target.locator().as_str())) {
            return Err(Refusal::TargetLocationUnsupported.into());
        }

        Ok(Examined {
            primary,
            primary_facts,
            local_locator,
            fingerprint: *snapshot.fingerprint(),
            revision,
        })
    }

    /// The part of "is this a file of the vault" that the existing check cannot
    /// see because it resolves the target itself: an **absent** target. A name
    /// that does not exist yet can still be the vault's `.backup` or `.lock` name
    /// (they appear later), or lie inside the sync-state directory. Compares the
    /// lexical names and the names with the parent resolved, and fails closed when
    /// the parent cannot be resolved.
    fn absent_target_collides_with_vault_files(
        &self,
        state_directory: &Path,
        target: &SyncFileTarget,
        local_locator: &Locator,
    ) -> bool {
        let target_text = target.locator().as_str();
        let target_path = Path::new(target_text);

        let owned = [
            local_locator.as_str().to_owned(),
            self.path.to_string_lossy().into_owned(),
            self.backup_path.to_string_lossy().into_owned(),
            lock_path_for(&self.path).to_string_lossy().into_owned(),
        ];

        if owned.iter().any(|name| path_identity_eq(name, target_text)) {
            return true;
        }

        let (Some(parent), Some(name)) = (target_path.parent(), target_path.file_name()) else {
            return true;
        };

        // Names with their parent resolved: verbatim and differently spelled forms
        // all compare equal here. A parent that does not exist holds none of the
        // vault's files (and is refused as an unsupported location by the read);
        // any other failure to resolve it cannot be shown safe.
        let resolved_parent = match fs::canonicalize(parent) {
            Ok(resolved) => resolved,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
            Err(_) => return true,
        };
        let resolved_target = resolved_parent.join(name);

        let Some(resolved_target_text) = resolved_target.to_str() else {
            return true;
        };

        for owned_name in &owned {
            let owned_path = Path::new(owned_name);
            let resolved_owned = match (owned_path.parent(), owned_path.file_name()) {
                (Some(owned_parent), Some(owned_file)) => fs::canonicalize(owned_parent)
                    .map(|resolved| resolved.join(owned_file))
                    .ok(),
                _ => None,
            };

            match resolved_owned.as_deref().and_then(Path::to_str) {
                Some(resolved) if path_identity_eq(resolved, resolved_target_text) => return true,
                Some(_) => {}
                // Cannot resolve the owned name: not shown to be different.
                None => return true,
            }
        }

        // Anything inside the sync-state directory (which may not exist yet:
        // then only the lexical comparison is possible).
        let in_state_directory = match fs::canonicalize(state_directory) {
            Ok(resolved_state) => resolved_parent
                .to_str()
                .zip(resolved_state.to_str())
                .is_none_or(|(parent, state)| path_identity_eq(parent, state)),
            Err(_) => parent
                .to_str()
                .zip(state_directory.to_str())
                .is_none_or(|(parent, state)| path_identity_eq(parent, state)),
        };

        in_state_directory
    }

    /// Whether `candidate_raw` is a faithful authenticated copy of `local_raw`:
    /// both authenticate under this session's Vault Key and vault id, the
    /// fingerprints are equal, and both carry the same schema-3 revision counter
    /// that was prepared. Read-only.
    fn copy_authenticates(&self, local_raw: &[u8], candidate_raw: &[u8], revision: u64) -> bool {
        let Ok(inspection) = inspect_remote_bytes(
            &self.vault_key,
            self.data.vault_id,
            local_raw,
            candidate_raw,
            None,
        ) else {
            return false;
        };

        let revisions = inspection.inspection();

        inspection.local_fingerprint() == inspection.candidate_fingerprint()
            && matches!(
                (revisions.local_revision(), revisions.candidate_revision()),
                (AuthenticatedRevision::Counter(local), AuthenticatedRevision::Counter(remote))
                    if local == remote && local == revision
            )
    }

    /// First half of the copy-creation consent (Stage 1U-4 B2a): examine
    /// `target` **read-only** and, if a new copy could be created there, remember
    /// that fact in this session and return what the user must be shown.
    /// Internal: no command, event or UI calls it.
    ///
    /// **Nothing is created, written or bound.** Any pending approval (this one,
    /// an initial binding or a reset) is discarded **first**, before any
    /// filesystem or cryptographic work. See the module documentation for the
    /// checks, and [`confirm_copy_creation`](Self::confirm_copy_creation) for the
    /// second half. The preparation expires after 120 seconds and is dropped with
    /// the session.
    pub fn prepare_copy_creation(
        &mut self,
        root: &SyncStateRoot,
        target: &SyncFileTarget,
    ) -> Result<CopyCreationPreview, CopyCreationRefusal> {
        self.pending_initial_binding = None;
        self.pending_binding_reset = None;
        self.pending_copy_creation = None;

        let store = SyncStateStore::new(root.path())
            .map_err(|_| CopyCreationRefusal::Unavailable(SyncStateUnavailable::Root))?;

        self.prepare_copy_creation_in(
            &store,
            target,
            &mut SyncFileTarget::read,
            &mut |buffer| getrandom::fill(buffer).is_ok(),
            Instant::now(),
        )
    }

    /// [`prepare_copy_creation`](Self::prepare_copy_creation) over an explicit
    /// store, read step, entropy source and clock. Crate-private so only the
    /// crate's own tests can substitute them.
    pub(crate) fn prepare_copy_creation_in(
        &mut self,
        store: &SyncStateStore,
        target: &SyncFileTarget,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
        entropy: &mut dyn FnMut(&mut [u8]) -> bool,
        now: Instant,
    ) -> Result<CopyCreationPreview, CopyCreationRefusal> {
        self.pending_initial_binding = None;
        self.pending_binding_reset = None;
        self.pending_copy_creation = None;

        let examined = match self.examine_copy_creation(store, target, read, None) {
            Ok(examined) => examined,
            Err(ExamineFailure::Refused(refusal)) => return Err(refusal),
            // Cannot happen without an expected fingerprint; fails closed anyway.
            Err(ExamineFailure::SourceChanged) => {
                return Err(CopyCreationRefusal::Unavailable(
                    SyncStateUnavailable::LocalVaultChanged,
                ))
            }
        };

        let mut id_bytes = [0u8; 16];

        if !entropy(&mut id_bytes) {
            return Err(CopyCreationRefusal::Randomness);
        }

        let id = uuid::Builder::from_random_bytes(id_bytes).into_uuid();

        self.pending_copy_creation = Some(PendingCopyCreation {
            id,
            target: target.clone(),
            source_fingerprint: examined.fingerprint,
            source_revision: examined.revision,
            prepared_at: now,
        });

        Ok(CopyCreationPreview {
            preparation_id: id.to_string(),
            vault_file_name: self
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            target_path: target.locator().as_str().to_owned(),
        })
    }

    /// Second half of the copy-creation consent (Stage 1U-4 B2a): spend the
    /// pending preparation named by `preparation_id` and, if the vault and the
    /// target are still what it examined, create the copy. Internal: no command,
    /// event or UI calls it.
    ///
    /// **The preparation is spent by every call**, whatever its outcome, and a
    /// pending initial binding or reset is discarded too. In order: a preparation
    /// must be pending and named by `preparation_id`; it must be at most 120
    /// seconds old (a stale confirmation reads no file); every preparation check
    /// is repeated with fresh evidence; the file is published; the read-back and
    /// the cryptographic check must pass. See the module documentation for the
    /// outcomes. Nothing is retried, repaired, bound or deleted after a
    /// publication whose result is unknown.
    pub fn confirm_copy_creation(
        &mut self,
        root: &SyncStateRoot,
        preparation_id: &str,
    ) -> Result<CopyCreationOutcome, CopyCreationConfirmRefusal> {
        let store = match SyncStateStore::new(root.path()) {
            Ok(store) => store,
            Err(_) => {
                // Spent even though nothing could be checked.
                self.pending_initial_binding = None;
                self.pending_binding_reset = None;
                self.pending_copy_creation = None;

                return Err(CopyCreationConfirmRefusal::Refused(
                    CopyCreationRefusal::Unavailable(SyncStateUnavailable::Root),
                ));
            }
        };

        self.confirm_copy_creation_in(
            &store,
            preparation_id,
            &mut SyncFileTarget::read,
            Instant::now(),
            &mut Seams::none(),
        )
    }

    /// [`confirm_copy_creation`](Self::confirm_copy_creation) over an explicit
    /// store, read step, clock and test seams. Crate-private so only the crate's
    /// own tests can substitute them.
    pub(crate) fn confirm_copy_creation_in(
        &mut self,
        store: &SyncStateStore,
        preparation_id: &str,
        read: &mut dyn FnMut(&SyncFileTarget) -> SyncFileRead,
        now: Instant,
        seams: &mut Seams,
    ) -> Result<CopyCreationOutcome, CopyCreationConfirmRefusal> {
        use CopyCreationConfirmRefusal::{Refused, Stale};
        use CopyCreationRefusal as Refusal;

        // The other approvals are voided by any confirmation attempt, and this one
        // is spent first and unconditionally.
        self.pending_initial_binding = None;
        self.pending_binding_reset = None;

        let Some(pending) = self.pending_copy_creation.take() else {
            return Err(Stale(CopyCreationStale::NoPendingApproval));
        };

        if Uuid::parse_str(preparation_id) != Ok(pending.id) {
            return Err(Stale(CopyCreationStale::NotCurrentPreparation));
        }

        if now.saturating_duration_since(pending.prepared_at) > COPY_CREATION_APPROVAL_TTL {
            return Err(Stale(CopyCreationStale::Expired));
        }

        let examined = match self.examine_copy_creation(
            store,
            &pending.target,
            read,
            Some(pending.source_fingerprint),
        ) {
            Ok(examined) => examined,
            Err(ExamineFailure::SourceChanged) => {
                return Err(Stale(CopyCreationStale::LocalVaultChanged))
            }
            // Present at confirmation: it appeared after the preparation.
            Err(ExamineFailure::Refused(Refusal::TargetExists)) => {
                return Err(Stale(CopyCreationStale::TargetAppeared))
            }
            Err(ExamineFailure::Refused(refusal)) => return Err(Refused(refusal)),
        };

        if examined.revision != pending.source_revision
            || examined.fingerprint != pending.source_fingerprint
        {
            return Err(Stale(CopyCreationStale::LocalVaultChanged));
        }

        // From here on `self` is only read: the pending approval is already spent.
        let this = &*self;
        let local_locator = examined.local_locator.clone();
        let fingerprint = examined.fingerprint;

        let mut recheck = || {
            !this.dirty
                && this.local_locator().as_ref() == Some(&local_locator)
                && this
                    .hold_local_primary()
                    .is_some_and(|held| EnvelopeFingerprint::of_bytes(&held.raw) == fingerprint)
                && matches!(store.load(&local_locator), StateLoad::NotConfigured)
        };

        let mut authenticates = |candidate: &[u8]| {
            this.copy_authenticates(&examined.primary.raw, candidate, pending.source_revision)
        };

        let outcome = publish_new_copy(
            &PublishRequest {
                target: &pending.target,
                source: &examined.primary.raw,
                primary: &examined.primary_facts,
            },
            &mut recheck,
            &mut authenticates,
            seams,
        );

        match outcome {
            PublishOutcome::Published => Ok(CopyCreationOutcome::CreatedAndVerified),
            PublishOutcome::NotPublished {
                reason,
                staging_remains,
            } => Err(CopyCreationConfirmRefusal::NotPublished {
                reason,
                staging_remains,
            }),
            PublishOutcome::PublicationUnknown => {
                Err(CopyCreationConfirmRefusal::PublicationUnknown)
            }
            PublishOutcome::CreatedUnverified => Err(CopyCreationConfirmRefusal::CreatedUnverified),
        }
    }

    /// Discard the pending copy-creation preparation, if any. Idempotent, and
    /// never an error. It does not touch the other pending approvals.
    pub fn cancel_copy_creation(&mut self) {
        self.pending_copy_creation = None;
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::{cell::Cell, path::PathBuf};

    use zeroize::Zeroizing;

    use localvault_core::vault::{data::VaultData, format::create_envelope};

    use super::*;
    use crate::vault::{
        file_identity::{compare, facts_of, PhysicalVerdict},
        handle_ops::{
            inject_delete_status, inject_rename_status, take_last_rename_status, test_support::*,
        },
        new_copy_file::Stage,
        session::{InitialBindingApproval, InitialBindingOutcome},
        storage::{load_envelope, save_envelope_atomic},
        sync_state_store::SYNC_STATE_DIRECTORY,
    };

    type Scenario = Box<dyn Fn(&mut Bx) -> Option<Seams>>;

    const NOW_MS: i64 = 1_700_000_000_000;
    const MASTER_PASSWORD: &str = "session-master-password-test-only";
    const STAGING_MARK: &str = ".localvault-copy-";
    const LEAK_MARK: &str = "LEAKMARK-COPYCREATION";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    fn entropy(buffer: &mut [u8]) -> bool {
        getrandom::fill(buffer).is_ok()
    }

    fn write_legacy_vault(path: &Path) {
        let mut data = VaultData::new(NOW_MS).unwrap();

        data.schema_version = 2;

        let plaintext = Zeroizing::new(serde_json::to_vec(&data).unwrap());
        let envelope = create_envelope(MASTER_PASSWORD, plaintext.as_slice()).unwrap();

        save_envelope_atomic(path, &envelope).unwrap();
    }

    /// An unlocked session over a synthetic schema-3 vault, an application root
    /// with no sync state, and an absent target in `dest\`. `session` is declared
    /// first so that it (and its exclusive lock file) drops before the scratch
    /// directory is removed.
    struct Bx {
        session: UnlockedVaultSession,
        root: SyncStateRoot,
        target: SyncFileTarget,
        vault: PathBuf,
        dest: PathBuf,
        target_path: PathBuf,
        dir: tempfile::TempDir,
    }

    impl Bx {
        fn new(name: &str) -> Self {
            Self::with(name, |vault| {
                UnlockedVaultSession::create(vault, password(), NOW_MS).unwrap()
            })
        }

        fn legacy(name: &str) -> Self {
            Self::with(name, |vault| {
                write_legacy_vault(vault);

                UnlockedVaultSession::unlock(vault, password()).unwrap()
            })
        }

        fn with(name: &str, open: impl FnOnce(&Path) -> UnlockedVaultSession) -> Self {
            let dir = scratch(name);
            let vaults = dir.path().join("vaults");
            let dest = dir.path().join("dest");

            fs::create_dir_all(&vaults).unwrap();
            fs::create_dir_all(&dest).unwrap();

            let vault = vaults.join("vault.lvault");
            let session = open(&vault);
            let target_path = dest.join("copy.lvault");
            let target = SyncFileTarget::from_path(&target_path).unwrap();
            let root = SyncStateRoot::for_test(dir.path().join("app-local"));

            Self {
                session,
                root,
                target,
                vault,
                dest,
                target_path,
                dir,
            }
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(self.root.path()).unwrap()
        }

        fn state_dir(&self) -> PathBuf {
            self.root.path().join(SYNC_STATE_DIRECTORY)
        }

        fn prepare(&mut self) -> Result<CopyCreationPreview, CopyCreationRefusal> {
            let store = self.store();

            self.session.prepare_copy_creation_in(
                &store,
                &self.target,
                &mut SyncFileTarget::read,
                &mut entropy,
                Instant::now(),
            )
        }

        fn prepare_target(
            &mut self,
            target: &SyncFileTarget,
        ) -> Result<CopyCreationPreview, CopyCreationRefusal> {
            let store = self.store();

            self.session.prepare_copy_creation_in(
                &store,
                target,
                &mut SyncFileTarget::read,
                &mut entropy,
                Instant::now(),
            )
        }

        fn confirm(&mut self, id: &str) -> Result<CopyCreationOutcome, CopyCreationConfirmRefusal> {
            self.confirm_with(id, Instant::now(), &mut Seams::none())
        }

        fn confirm_with(
            &mut self,
            id: &str,
            now: Instant,
            seams: &mut Seams,
        ) -> Result<CopyCreationOutcome, CopyCreationConfirmRefusal> {
            let store = self.store();

            self.session
                .confirm_copy_creation_in(&store, id, &mut SyncFileTarget::read, now, seams)
        }

        fn prepared_id(&mut self) -> String {
            self.prepare()
                .expect("a successful preparation")
                .preparation_id()
                .to_owned()
        }

        /// Everything the operation must not touch: the vault folder (primary,
        /// backup, lock), the destination folder and the sync-state area.
        fn everything(&self) -> Vec<String> {
            snapshot(self.dir.path())
        }

        fn everything_but_staging(&self) -> Vec<String> {
            self.everything()
                .into_iter()
                .filter(|line| !line.contains(STAGING_MARK))
                .collect()
        }

        fn staging_names(&self) -> bool {
            any_name_contains(self.dir.path(), STAGING_MARK)
        }

        fn source_bytes(&self) -> Vec<u8> {
            fs::read(&self.vault).unwrap()
        }

        fn refused(&mut self, expected: CopyCreationRefusal) {
            let before = self.everything();

            assert_eq!(self.prepare().err(), Some(expected));
            assert!(self.session.pending_copy_creation.is_none());
            assert_eq!(self.everything(), before);
        }
    }

    // ---- prepare: read-only ------------------------------------------------------

    #[test]
    fn preparation_is_read_only_and_creates_nothing() {
        let mut bx = Bx::new("copy-prepare-readonly");
        let before = bx.everything();

        let preview = bx.prepare().expect("preparation");

        assert_eq!(preview.vault_file_name(), "vault.lvault");
        assert_eq!(preview.target_path(), bx.target.locator().as_str());
        assert_eq!(
            Uuid::parse_str(preview.preparation_id())
                .unwrap()
                .get_version_num(),
            4
        );

        // Not one byte, name or timestamp changed, and no sync state exists.
        assert_eq!(bx.everything(), before);
        assert!(!bx.target_path.exists());
        assert!(!bx.root.path().exists());
        assert!(bx.session.pending_copy_creation.is_some());
    }

    #[test]
    fn each_preparation_draws_a_fresh_id() {
        let mut bx = Bx::new("copy-prepare-fresh-id");
        let first = bx.prepared_id();
        let second = bx.prepared_id();

        assert_ne!(first, second);
    }

    #[test]
    fn unavailable_randomness_prepares_nothing() {
        let mut bx = Bx::new("copy-prepare-entropy");
        let before = bx.everything();
        let store = bx.store();

        let result = bx.session.prepare_copy_creation_in(
            &store,
            &bx.target,
            &mut SyncFileTarget::read,
            &mut |_| false,
            Instant::now(),
        );

        assert_eq!(result.err(), Some(CopyCreationRefusal::Randomness));
        assert!(bx.session.pending_copy_creation.is_none());
        assert_eq!(bx.everything(), before);
    }

    // ---- prepare: refusals -------------------------------------------------------

    #[test]
    fn an_existing_file_directory_or_junction_target_is_refused() {
        let mut bx = Bx::new("copy-prepare-exists-file");

        fs::write(&bx.target_path, b"someone else's file").unwrap();
        bx.refused(CopyCreationRefusal::TargetExists);

        for kind in ["directory", "junction"] {
            let mut bx = Bx::new(&format!("copy-prepare-exists-{kind}"));
            let aside = bx.dir.path().join("aside");

            fs::create_dir(&aside).unwrap();

            if kind == "directory" {
                fs::create_dir(&bx.target_path).unwrap();
            } else {
                make_junction(&bx.target_path, &aside);
            }

            bx.refused(CopyCreationRefusal::TargetLocationUnsupported);
        }
    }

    #[test]
    fn a_missing_parent_and_an_unsafe_ancestor_are_refused_and_no_directory_is_created() {
        let mut bx = Bx::new("copy-prepare-parent");
        let missing =
            SyncFileTarget::from_path(&bx.dir.path().join("absent").join("copy.lvault")).unwrap();
        let before = bx.everything();

        assert_eq!(
            bx.prepare_target(&missing).err(),
            Some(CopyCreationRefusal::TargetLocationUnsupported)
        );
        assert_eq!(bx.everything(), before);
        assert!(!bx.dir.path().join("absent").exists());

        // A junction anywhere in the ancestry.
        let aside = bx.dir.path().join("aside");
        let link = bx.dir.path().join("link");

        fs::create_dir(&aside).unwrap();
        make_junction(&link, &aside);

        let through = SyncFileTarget::from_path(&link.join("copy.lvault")).unwrap();
        let before = bx.everything();

        assert_eq!(
            bx.prepare_target(&through).err(),
            Some(CopyCreationRefusal::TargetLocationUnsupported)
        );
        assert_eq!(bx.everything(), before);
        assert!(names(&aside).is_empty());
    }

    #[test]
    fn the_vaults_own_files_and_a_state_directory_target_are_refused() {
        let mut bx = Bx::new("copy-prepare-vault-files");
        let backup = bx.session.backup_path().to_path_buf();
        let lock = lock_path_for(&bx.vault);
        // A file name inside the sync-state directory.
        fs::create_dir_all(bx.state_dir()).unwrap();
        let in_state = bx.state_dir().join("copy.lvault");

        for (label, path) in [
            ("primary", bx.vault.clone()),
            ("backup (absent)", backup),
            ("lock", lock),
            ("sync-state directory", in_state),
        ] {
            let target = SyncFileTarget::from_path(&path).unwrap();
            let before = bx.everything();

            assert_eq!(
                bx.prepare_target(&target).err(),
                Some(CopyCreationRefusal::TargetIsVaultFile),
                "{label}"
            );
            assert!(bx.session.pending_copy_creation.is_none(), "{label}");
            assert_eq!(bx.everything(), before, "{label}");
        }

        // Spelled differently (case, and through `..` of an existing folder).
        let upper = bx.vault.to_string_lossy().to_uppercase();
        let target = SyncFileTarget::from_path(Path::new(&upper)).unwrap();

        assert_eq!(
            bx.prepare_target(&target).err(),
            Some(CopyCreationRefusal::TargetIsVaultFile)
        );
    }

    #[test]
    fn a_unc_target_is_refused_before_it_is_read() {
        let mut bx = Bx::new("copy-prepare-unc");
        let unc =
            SyncFileTarget::from_path(Path::new(r"\\server.invalid\share\copy.lvault")).unwrap();
        let verbatim =
            SyncFileTarget::from_path(Path::new(r"\\?\UNC\server.invalid\share\copy.lvault"))
                .unwrap();

        for target in [unc, verbatim] {
            let reads = Cell::new(0usize);
            let store = bx.store();

            let result = bx.session.prepare_copy_creation_in(
                &store,
                &target,
                &mut |t| {
                    reads.set(reads.get() + 1);

                    t.read()
                },
                &mut entropy,
                Instant::now(),
            );

            assert_eq!(
                result.err(),
                Some(CopyCreationRefusal::TargetLocationUnsupported)
            );
            assert_eq!(reads.get(), 0);
        }
    }

    #[test]
    fn dirty_and_legacy_vaults_are_refused() {
        let mut bx = Bx::new("copy-prepare-dirty");

        bx.session.data_mut().updated_at_ms += 1;
        bx.refused(CopyCreationRefusal::UnsavedChanges);

        // After the save the same session can prepare.
        bx.session.save().unwrap();
        assert!(bx.prepare().is_ok());

        let mut legacy = Bx::legacy("copy-prepare-legacy");

        assert_eq!(legacy.session.data().schema_version, 2);
        legacy.refused(CopyCreationRefusal::LegacyVault);
    }

    #[test]
    fn any_sync_record_is_refused_and_left_unchanged() {
        let mut bx = Bx::new("copy-prepare-record");
        let remote = bx.dir.path().join("remote.lvault");

        fs::copy(&bx.vault, &remote).unwrap();

        let remote_target = SyncFileTarget::from_path(&remote).unwrap();

        assert_eq!(
            bx.session.bind_existing_identical_target(
                &bx.root,
                &remote_target,
                InitialBindingApproval::for_test(&remote_target),
            ),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );

        let record_before = snapshot(&bx.state_dir());

        bx.refused(CopyCreationRefusal::BindingExists);
        assert_eq!(snapshot(&bx.state_dir()), record_before);

        // A record that cannot be read is not a confirmed NotConfigured either.
        let record = fs::read_dir(bx.state_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();

        fs::write(&record, b"not a record").unwrap();
        bx.refused(CopyCreationRefusal::BindingStateUnreadable);
    }

    // ---- confirm: success --------------------------------------------------------

    #[test]
    fn confirmation_creates_a_verified_copy_with_exactly_the_vault_bytes() {
        let mut bx = Bx::new("copy-confirm-ok");
        let id = bx.prepared_id();
        let source = bx.source_bytes();
        let vault_dir_before = snapshot(bx.vault.parent().unwrap());

        assert_eq!(bx.confirm(&id), Ok(CopyCreationOutcome::CreatedAndVerified));

        // Exactly the bytes, exactly one new name, no staging name anywhere.
        assert_eq!(fs::read(&bx.target_path).unwrap(), source);
        assert_eq!(names(&bx.dest), vec!["copy.lvault".to_owned()]);
        assert!(!bx.staging_names());

        // A distinct physical file with one link.
        let copy = facts_of(&fs::File::open(&bx.target_path).unwrap()).unwrap();
        let primary = facts_of(&fs::File::open(&bx.vault).unwrap()).unwrap();

        assert!(copy.has_single_link());
        assert_eq!(compare(&primary, &copy), PhysicalVerdict::Distinct);

        // The vault folder (primary, backup, lock) and the sync state are untouched.
        assert_eq!(snapshot(bx.vault.parent().unwrap()), vault_dir_before);
        assert!(!bx.session.backup_path().exists());
        assert!(!bx.root.path().exists());
        assert_eq!(
            bx.session.load_sync_state(&bx.root),
            crate::vault::session::SessionSyncState::NotConfigured
        );

        // Spent: a second confirmation does nothing.
        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NoPendingApproval
            ))
        );
        assert_eq!(fs::read(&bx.target_path).unwrap(), source);
    }

    #[test]
    fn the_copy_is_the_raw_on_disk_bytes_not_a_reserialization() {
        let mut bx = Bx::new("copy-confirm-raw");
        let envelope = load_envelope(&bx.vault).unwrap();
        let pretty = serde_json::to_vec_pretty(&envelope).unwrap();

        // The same envelope, laid out differently on disk.
        assert_ne!(pretty, serde_json::to_vec(&envelope).unwrap());
        fs::write(&bx.vault, &pretty).unwrap();

        let id = bx.prepared_id();

        assert_eq!(bx.confirm(&id), Ok(CopyCreationOutcome::CreatedAndVerified));
        assert_eq!(fs::read(&bx.target_path).unwrap(), pretty);
    }

    #[test]
    fn the_created_copy_is_accepted_by_the_unchanged_initial_binding() {
        let mut bx = Bx::new("copy-then-bind");
        let id = bx.prepared_id();

        assert_eq!(bx.confirm(&id), Ok(CopyCreationOutcome::CreatedAndVerified));

        // The existing B1h flow, unchanged, binds the created file.
        let store = bx.store();
        let preview = bx
            .session
            .prepare_initial_binding_in(
                &store,
                &bx.target,
                &mut SyncFileTarget::read,
                &mut entropy,
                Instant::now(),
            )
            .expect("the created copy is a binding candidate");

        assert_eq!(
            bx.session.confirm_initial_binding_in(
                &store,
                preview.preparation_id(),
                &mut SyncFileTarget::read,
                &mut entropy,
                Instant::now(),
            ),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );
    }

    #[test]
    fn the_copy_goes_stale_after_the_next_save_and_binding_then_refuses_it() {
        let mut bx = Bx::new("copy-stale-after-save");
        let id = bx.prepared_id();

        assert_eq!(bx.confirm(&id), Ok(CopyCreationOutcome::CreatedAndVerified));

        bx.session.data_mut().updated_at_ms += 1;
        bx.session.save().unwrap();

        let store = bx.store();

        assert!(bx
            .session
            .prepare_initial_binding_in(
                &store,
                &bx.target,
                &mut SyncFileTarget::read,
                &mut entropy,
                Instant::now(),
            )
            .is_err());
    }

    // ---- confirm: the approval lifecycle ----------------------------------------

    #[test]
    fn no_pending_wrong_id_and_expired_confirmations_write_nothing_and_are_spent() {
        let mut bx = Bx::new("copy-confirm-lifecycle");
        let before = bx.everything();

        // Nothing pending.
        assert_eq!(
            bx.confirm(&Uuid::nil().to_string()),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NoPendingApproval
            ))
        );

        // Wrong id, then the right one is spent too.
        let id = bx.prepared_id();

        assert_eq!(
            bx.confirm("00000000-0000-4000-8000-000000000000"),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NotCurrentPreparation
            ))
        );
        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NoPendingApproval
            ))
        );

        // A malformed id is just as spent.
        let id = bx.prepared_id();

        assert_eq!(
            bx.confirm("not-a-uuid"),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NotCurrentPreparation
            ))
        );
        assert!(bx.session.pending_copy_creation.is_none());
        let _ = id;

        // Expired: one second over, and no file was read.
        let id = bx.prepared_id();
        let reads = Cell::new(0usize);
        let store = bx.store();

        let result = bx.session.confirm_copy_creation_in(
            &store,
            &id,
            &mut |t| {
                reads.set(reads.get() + 1);

                t.read()
            },
            Instant::now() + Duration::from_secs(121),
            &mut Seams::none(),
        );

        assert_eq!(
            result,
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::Expired
            ))
        );
        assert_eq!(reads.get(), 0);
        assert!(bx.session.pending_copy_creation.is_none());
        assert_eq!(bx.everything(), before);
        assert!(!bx.target_path.exists());
    }

    #[test]
    fn a_confirmation_just_inside_the_lifetime_is_accepted() {
        let mut bx = Bx::new("copy-confirm-edge");
        let id = bx.prepared_id();
        let prepared = Instant::now();

        assert_eq!(
            bx.confirm_with(&id, prepared + Duration::from_secs(119), &mut Seams::none()),
            Ok(CopyCreationOutcome::CreatedAndVerified)
        );
    }

    #[test]
    fn a_replaced_preparation_makes_the_older_id_stale() {
        let mut bx = Bx::new("copy-confirm-replaced");
        let first = bx.prepared_id();
        let second = bx.prepared_id();

        assert_eq!(
            bx.confirm(&first),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NotCurrentPreparation
            ))
        );
        // The mistaken confirmation spent the newer one as well.
        assert_eq!(
            bx.confirm(&second),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NoPendingApproval
            ))
        );
        assert!(!bx.target_path.exists());
    }

    #[test]
    fn cancelling_discards_the_preparation_and_is_idempotent() {
        let mut bx = Bx::new("copy-cancel");
        let id = bx.prepared_id();

        bx.session.cancel_copy_creation();
        bx.session.cancel_copy_creation();

        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::NoPendingApproval
            ))
        );
        assert!(!bx.target_path.exists());
    }

    #[test]
    fn the_three_approvals_void_each_other() {
        // Preparing or confirming a binding or a reset voids a pending copy.
        let other_pending = |bx: &mut Bx| {
            let remote = bx.dir.path().join("remote.lvault");

            if !remote.exists() {
                fs::copy(&bx.vault, &remote).unwrap();
            }

            SyncFileTarget::from_path(&remote).unwrap()
        };

        // prepare_initial_binding voids copy.
        let mut bx = Bx::new("copy-excl-prepare-binding");
        let id = bx.prepared_id();
        let remote = other_pending(&mut bx);
        let store = bx.store();

        let _ = bx.session.prepare_initial_binding_in(
            &store,
            &remote,
            &mut SyncFileTarget::read,
            &mut entropy,
            Instant::now(),
        );
        assert!(bx.session.pending_copy_creation.is_none());
        assert!(bx.confirm(&id).is_err());
        assert!(!bx.target_path.exists());

        // prepare_binding_reset voids copy (and refuses: nothing to reset).
        let mut bx = Bx::new("copy-excl-prepare-reset");
        let id = bx.prepared_id();
        let store = bx.store();

        let _ = bx
            .session
            .prepare_binding_reset_in(&store, &mut entropy, Instant::now());
        assert!(bx.session.pending_copy_creation.is_none());
        assert!(bx.confirm(&id).is_err());

        // confirm_initial_binding voids copy.
        let mut bx = Bx::new("copy-excl-confirm-binding");
        let id = bx.prepared_id();
        let store = bx.store();

        let _ = bx.session.confirm_initial_binding_in(
            &store,
            &Uuid::nil().to_string(),
            &mut SyncFileTarget::read,
            &mut entropy,
            Instant::now(),
        );
        assert!(bx.session.pending_copy_creation.is_none());
        assert!(bx.confirm(&id).is_err());

        // confirm_binding_reset voids copy.
        let mut bx = Bx::new("copy-excl-confirm-reset");
        let id = bx.prepared_id();
        let store = bx.store();

        let _ = bx.session.confirm_binding_reset_in(
            &store,
            &Uuid::nil().to_string(),
            &mut |s, l| s.load(l),
            Instant::now(),
        );
        assert!(bx.session.pending_copy_creation.is_none());
        assert!(bx.confirm(&id).is_err());

        // And the other way round: preparing/confirming a copy voids the others.
        let mut bx = Bx::new("copy-excl-reverse");
        let remote = other_pending(&mut bx);
        let store = bx.store();
        let binding = bx
            .session
            .prepare_initial_binding_in(
                &store,
                &remote,
                &mut SyncFileTarget::read,
                &mut entropy,
                Instant::now(),
            )
            .expect("a binding preparation");

        assert!(bx.session.pending_initial_binding.is_some());

        let copy_id = bx.prepared_id();

        assert!(bx.session.pending_initial_binding.is_none());
        assert!(bx.session.pending_binding_reset.is_none());

        // The voided binding confirmation reports nothing pending.
        assert!(bx
            .session
            .confirm_initial_binding_in(
                &store,
                binding.preparation_id(),
                &mut SyncFileTarget::read,
                &mut entropy,
                Instant::now(),
            )
            .is_err());
        // ... and that attempt voided the copy.
        assert!(bx.session.pending_copy_creation.is_none());
        let _ = copy_id;

        // Confirming a copy voids a pending binding and a pending reset.
        let mut bx = Bx::new("copy-excl-confirm-copy");
        let remote = other_pending(&mut bx);
        let store = bx.store();

        bx.session
            .prepare_initial_binding_in(
                &store,
                &remote,
                &mut SyncFileTarget::read,
                &mut entropy,
                Instant::now(),
            )
            .unwrap();

        bx.session.pending_copy_creation = Some(PendingCopyCreation {
            id: Uuid::nil(),
            target: bx.target.clone(),
            source_fingerprint: EnvelopeFingerprint::of_bytes(b"x"),
            source_revision: 0,
            prepared_at: Instant::now(),
        });

        let _ = bx.confirm(&Uuid::nil().to_string());

        assert!(bx.session.pending_initial_binding.is_none());
        assert!(bx.session.pending_binding_reset.is_none());
    }

    // ---- confirm: stale and refused ---------------------------------------------

    #[test]
    fn a_save_after_preparation_makes_the_confirmation_stale() {
        let mut bx = Bx::new("copy-stale-save");
        let id = bx.prepared_id();

        bx.session.data_mut().updated_at_ms += 1;
        bx.session.save().unwrap();

        let before = bx.everything();

        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::Stale(
                CopyCreationStale::LocalVaultChanged
            ))
        );
        assert_eq!(bx.everything(), before);
        assert!(!bx.target_path.exists());
    }

    #[test]
    fn unsaved_changes_after_preparation_refuse_the_confirmation() {
        let mut bx = Bx::new("copy-stale-dirty");
        let id = bx.prepared_id();

        bx.session.data_mut().updated_at_ms += 1;

        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::Refused(
                CopyCreationRefusal::UnsavedChanges
            ))
        );
        assert!(!bx.target_path.exists());
    }

    #[test]
    fn a_vault_file_replaced_after_preparation_is_refused() {
        let mut bx = Bx::new("copy-stale-replaced");
        let id = bx.prepared_id();
        let other = bx.dir.path().join("other.lvault");

        write_legacy_vault(&other);
        fs::copy(&other, &bx.vault).unwrap();

        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::Refused(
                CopyCreationRefusal::Unavailable(SyncStateUnavailable::LocalVaultChanged)
            ))
        );
        assert!(!bx.target_path.exists());
    }

    #[test]
    fn a_target_that_appears_after_preparation_is_never_replaced() {
        for kind in ["file", "directory", "junction"] {
            let mut bx = Bx::new(&format!("copy-stale-target-{kind}"));
            let id = bx.prepared_id();
            let aside = bx.dir.path().join("aside");

            fs::create_dir(&aside).unwrap();

            match kind {
                "file" => fs::write(&bx.target_path, b"appeared").unwrap(),
                "directory" => fs::create_dir(&bx.target_path).unwrap(),
                _ => make_junction(&bx.target_path, &aside),
            }

            let before = bx.everything();
            let result = bx.confirm(&id);

            if kind == "file" {
                assert_eq!(
                    result,
                    Err(CopyCreationConfirmRefusal::Stale(
                        CopyCreationStale::TargetAppeared
                    )),
                    "{kind}"
                );
            } else {
                // A directory or junction is not "present" to the reader; it is
                // an unsupported location. Either way nothing is replaced.
                assert_eq!(
                    result,
                    Err(CopyCreationConfirmRefusal::Refused(
                        CopyCreationRefusal::TargetLocationUnsupported
                    )),
                    "{kind}"
                );
            }

            assert_eq!(bx.everything(), before, "{kind}");
        }
    }

    #[test]
    fn a_sync_record_created_after_preparation_refuses_the_confirmation() {
        let mut bx = Bx::new("copy-stale-record");
        let id = bx.prepared_id();
        let remote = bx.dir.path().join("remote.lvault");

        fs::copy(&bx.vault, &remote).unwrap();

        let remote_target = SyncFileTarget::from_path(&remote).unwrap();
        let store = bx.store();

        // Bound by the unchanged operation directly (not through prepare, which
        // would void the copy approval).
        assert_eq!(
            bx.session.bind_existing_identical_target_in(
                &store,
                &remote_target,
                InitialBindingApproval::for_test(&remote_target),
                &mut SyncFileTarget::read,
                &mut entropy,
            ),
            Ok(InitialBindingOutcome::BoundAndVerified)
        );

        let record_before = snapshot(&bx.state_dir());

        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::Refused(
                CopyCreationRefusal::BindingExists
            ))
        );
        assert_eq!(snapshot(&bx.state_dir()), record_before);
        assert!(!bx.target_path.exists());
    }

    #[test]
    fn a_record_appearing_after_the_recheck_is_the_documented_remaining_window() {
        let mut bx = Bx::new("copy-recheck-state");
        let id = bx.prepared_id();
        let state_dir = bx.state_dir();
        // A record appears at the last moment (any file with a record's shape
        // makes the state unreadable, which is not a confirmed NotConfigured).
        let mut seams = Seams {
            hook: Some(Box::new(move |stage, _| {
                if stage == Stage::BeforeRename {
                    fs::create_dir_all(&state_dir).unwrap();
                    fs::write(state_dir.join("0.json"), b"not a record").unwrap();
                }
            })),
            ..Seams::none()
        };

        let result = bx.confirm_with(&id, Instant::now(), &mut seams);

        // The recheck ran just before the hook point and passed; the record
        // appeared after it. This documents the remaining check-then-use window
        // honestly: the copy is created, and this operation neither reads nor
        // touches that record again.
        assert_eq!(result, Ok(CopyCreationOutcome::CreatedAndVerified));
        assert!(bx.target_path.exists());
        assert_eq!(fs::read(&bx.target_path).unwrap(), bx.source_bytes());
        assert!(!bx.staging_names());
    }

    #[test]
    fn a_source_that_changes_before_the_rename_is_caught_by_the_recheck() {
        let mut bx = Bx::new("copy-recheck-source");
        let id = bx.prepared_id();
        let vault = bx.vault.clone();
        let other = bx.dir.path().join("other.lvault");

        write_legacy_vault(&other);

        // The recheck runs before the BeforeRename hook, so change the source at
        // the identity stage, which precedes it.
        let mut seams = Seams {
            hook: Some(Box::new(move |stage, _| {
                if stage == Stage::BeforeIdentity {
                    fs::copy(&other, &vault).unwrap();
                }
            })),
            ..Seams::none()
        };

        let result = bx.confirm_with(&id, Instant::now(), &mut seams);

        assert_eq!(
            result,
            Err(CopyCreationConfirmRefusal::NotPublished {
                reason: NotPublishedReason::EvidenceChanged,
                staging_remains: false,
            })
        );
        assert!(!bx.target_path.exists());
        assert!(!bx.staging_names());
    }

    // ---- confirm: publication outcomes ------------------------------------------

    #[test]
    fn a_competing_creation_just_before_the_rename_never_replaces_it() {
        let mut bx = Bx::new("copy-race");
        let id = bx.prepared_id();
        let target = bx.target_path.clone();
        let competitor = b"the competing bytes".to_vec();
        let planted = competitor.clone();

        let mut seams = Seams {
            hook: Some(Box::new(move |stage, _| {
                if stage == Stage::BeforeRename {
                    fs::write(&target, &planted).unwrap();
                }
            })),
            ..Seams::none()
        };

        let before_vault = snapshot(bx.vault.parent().unwrap());
        let result = bx.confirm_with(&id, Instant::now(), &mut seams);

        assert_eq!(
            result,
            Err(CopyCreationConfirmRefusal::NotPublished {
                reason: NotPublishedReason::TargetAppeared,
                staging_remains: false,
            })
        );
        assert_eq!(fs::read(&bx.target_path).unwrap(), competitor);
        assert!(!bx.staging_names());
        assert_eq!(snapshot(bx.vault.parent().unwrap()), before_vault);
        assert!(!bx.root.path().exists());
    }

    #[test]
    fn a_failed_staging_cleanup_is_reported_as_a_leftover_never_as_success() {
        let mut bx = Bx::new("copy-leftover");
        let id = bx.prepared_id();
        let target = bx.target_path.clone();

        let mut seams = Seams {
            hook: Some(Box::new(move |stage, _| {
                if stage == Stage::BeforeRename {
                    fs::write(&target, b"competitor").unwrap();
                }
            })),
            ..Seams::none()
        };

        inject_delete_status(0xC000_0001_u32 as i32);

        assert_eq!(
            bx.confirm_with(&id, Instant::now(), &mut seams),
            Err(CopyCreationConfirmRefusal::NotPublished {
                reason: NotPublishedReason::TargetAppeared,
                staging_remains: true,
            })
        );
        assert!(bx.staging_names());
        assert_eq!(fs::read(&bx.target_path).unwrap(), b"competitor");
    }

    #[test]
    fn unexpected_native_results_are_never_success_and_delete_nothing_uncertain() {
        // Unknown status: nothing deleted, target absent.
        let mut bx = Bx::new("copy-status-unknown");
        let id = bx.prepared_id();

        inject_rename_status(0xC000_0001_u32 as i32);

        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::PublicationUnknown)
        );
        assert!(!bx.target_path.exists());
        assert!(bx.staging_names());

        // Injected success with no file at the target: created, unverified.
        let mut bx = Bx::new("copy-status-success-absent");
        let id = bx.prepared_id();

        inject_rename_status(0);

        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::CreatedUnverified)
        );
        assert!(!bx.target_path.exists());
        assert!(bx.staging_names());

        // A refusal with the target absent: definitely not published, cleaned.
        let mut bx = Bx::new("copy-status-refused");
        let id = bx.prepared_id();

        inject_rename_status(0xC000_000D_u32 as i32);

        assert_eq!(
            bx.confirm(&id),
            Err(CopyCreationConfirmRefusal::NotPublished {
                reason: NotPublishedReason::RenameRefused,
                staging_remains: false,
            })
        );
        assert!(!bx.staging_names());
        let _ = take_last_rename_status();
    }

    #[test]
    fn identical_bytes_with_the_primarys_physical_identity_are_created_unverified() {
        let mut bx = Bx::new("copy-verify-same-identity");
        let id = bx.prepared_id();
        let primary = facts_of(&fs::File::open(&bx.vault).unwrap()).unwrap();

        // The read-back claims the primary's own physical file.
        let mut seams = Seams {
            verify_read: Some(Box::new(move |read| match read {
                SyncFileRead::Present(present) => {
                    SyncFileRead::Present(present.with_physical_for_test(Ok(primary)))
                }
                other => other,
            })),
            ..Seams::none()
        };

        assert_eq!(
            bx.confirm_with(&id, Instant::now(), &mut seams),
            Err(CopyCreationConfirmRefusal::CreatedUnverified)
        );
        // The target is kept, and nothing else changed.
        assert_eq!(fs::read(&bx.target_path).unwrap(), bx.source_bytes());
        assert!(!bx.root.path().exists());
    }

    #[test]
    fn the_cryptographic_check_accepts_only_a_faithful_copy() {
        let bx = Bx::new("copy-crypto");
        let raw = bx.source_bytes();
        let revision = 0;

        assert!(bx.session.copy_authenticates(&raw, &raw, revision));

        // The wrong prepared revision.
        assert!(!bx.session.copy_authenticates(&raw, &raw, revision + 1));

        // One flipped byte (no longer parses or authenticates).
        let mut flipped = raw.clone();
        let last = flipped.len() / 2;

        flipped[last] ^= 1;
        assert!(!bx.session.copy_authenticates(&raw, &flipped, revision));

        // A different encryption of the same plaintext is not a copy.
        let envelope = load_envelope(&bx.vault).unwrap();
        let plaintext = Zeroizing::new(serde_json::to_vec(bx.session.data()).unwrap());
        let resealed =
            super::super::reseal_envelope(&envelope, &bx.session.vault_key, plaintext.as_slice())
                .unwrap();
        let resealed = serde_json::to_vec(&resealed).unwrap();

        assert_ne!(resealed, raw);
        assert!(!bx.session.copy_authenticates(&raw, &resealed, revision));

        // Truncated and empty candidates.
        assert!(!bx
            .session
            .copy_authenticates(&raw, &raw[..raw.len() / 2], revision));
        assert!(!bx.session.copy_authenticates(&raw, b"", revision));

        // A legacy vault has no revision counter at all.
        let other = bx.dir.path().join("legacy.lvault");

        write_legacy_vault(&other);

        let legacy_raw = fs::read(&other).unwrap();

        assert!(!bx.session.copy_authenticates(&raw, &legacy_raw, revision));
    }

    // ---- no unrelated writes ----------------------------------------------------

    #[test]
    fn no_refusal_or_failure_writes_anything_outside_the_staging_name() {
        // Run a set of failing confirmations and compare whole-tree snapshots.
        let scenarios: Vec<(&str, Scenario)> = vec![
            (
                "rename refused",
                Box::new(|_| {
                    inject_rename_status(0xC000_000D_u32 as i32);

                    None
                }),
            ),
            (
                "unknown status",
                Box::new(|_| {
                    inject_rename_status(0x4000_0000);

                    None
                }),
            ),
            (
                "competitor",
                Box::new(|bx| {
                    let target = bx.target_path.clone();

                    Some(Seams {
                        hook: Some(Box::new(move |stage, _| {
                            if stage == Stage::BeforeRename {
                                fs::write(&target, b"competitor").unwrap();
                            }
                        })),
                        ..Seams::none()
                    })
                }),
            ),
        ];

        for (label, scenario) in scenarios {
            let mut bx = Bx::new("copy-no-unrelated-writes");
            let decoy = bx.dest.join("decoy.txt");

            fs::write(&decoy, b"unrelated decoy").unwrap();

            let id = bx.prepared_id();
            let before = bx.everything_but_staging();
            let mut seams = scenario(&mut bx).unwrap_or_else(Seams::none);
            let result = bx.confirm_with(&id, Instant::now(), &mut seams);

            assert!(result.is_err(), "{label}");

            // Everything except our staging name, the competitor and the target
            // is exactly as before.
            let after: Vec<String> = bx
                .everything_but_staging()
                .into_iter()
                .filter(|line| !line.contains("copy.lvault"))
                .collect();
            let before: Vec<String> = before
                .into_iter()
                .filter(|line| !line.contains("copy.lvault"))
                .collect();

            assert_eq!(after, before, "{label}");
        }
    }

    // ---- redaction ----------------------------------------------------------------

    #[test]
    fn nothing_here_prints_paths_identifiers_or_content() {
        let mut bx = Bx::new(&format!("copy-redact-{}", &LEAK_MARK[9..13]));
        let leaky_dir = bx.dest.join(LEAK_MARK);

        fs::create_dir(&leaky_dir).unwrap();

        let leaky =
            SyncFileTarget::from_path(&leaky_dir.join(format!("{LEAK_MARK}.lvault"))).unwrap();
        let preview = bx.prepare_target(&leaky).expect("preparation");
        let id = preview.preparation_id().to_owned();

        let mut shown = vec![
            format!("{preview:?}"),
            format!("{:#?}", preview),
            format!("{:?}", bx.session.pending_copy_creation),
            format!("{:#?}", bx.session.pending_copy_creation.as_ref().unwrap()),
            format!("{:?}", CopyCreationOutcome::CreatedAndVerified),
        ];

        let refusals = [
            CopyCreationRefusal::UnsavedChanges,
            CopyCreationRefusal::LegacyVault,
            CopyCreationRefusal::BindingExists,
            CopyCreationRefusal::BindingStateUnreadable,
            CopyCreationRefusal::TargetExists,
            CopyCreationRefusal::TargetIsVaultFile,
            CopyCreationRefusal::TargetLocationUnsupported,
            CopyCreationRefusal::TargetUnavailable,
            CopyCreationRefusal::SourceIdentityUncertain,
            CopyCreationRefusal::Unavailable(SyncStateUnavailable::LocalLocator),
            CopyCreationRefusal::Randomness,
        ];

        for refusal in refusals {
            shown.push(format!("{refusal:?}"));
            shown.push(refusal.to_string());
            shown.push(format!(
                "{:?}",
                CopyCreationConfirmRefusal::Refused(refusal)
            ));
        }

        for stale in [
            CopyCreationStale::NoPendingApproval,
            CopyCreationStale::NotCurrentPreparation,
            CopyCreationStale::Expired,
            CopyCreationStale::LocalVaultChanged,
            CopyCreationStale::TargetAppeared,
        ] {
            shown.push(format!("{stale:?}"));
            shown.push(stale.to_string());
        }

        for refusal in [
            CopyCreationConfirmRefusal::PublicationUnknown,
            CopyCreationConfirmRefusal::CreatedUnverified,
            CopyCreationConfirmRefusal::NotPublished {
                reason: NotPublishedReason::TargetAppeared,
                staging_remains: true,
            },
        ] {
            shown.push(format!("{refusal:?}"));
            shown.push(refusal.to_string());
        }

        // The real outcome of this very target, too.
        shown.push(format!("{:?}", bx.confirm(&id)));

        let source = bx.source_bytes();
        let vault_text = String::from_utf8_lossy(&source).into_owned();

        for output in &shown {
            for needle in [
                LEAK_MARK,
                ".qa-local",
                id.as_str(),
                "vault.lvault",
                "copy.lvault",
                MASTER_PASSWORD,
                &vault_text[vault_text.len() / 2..vault_text.len() / 2 + 24],
            ] {
                assert!(!output.contains(needle), "leaks {needle:?}: {output}");
            }
        }
    }
}
