//! Dormant, strictly read-only classification of the stored synchronization
//! record of the unlocked vault (Stage 1U-4, slice B3c-3a).
//!
//! # What it is
//!
//! [`UnlockedVaultSession::load_authenticated_sync_state`] reads the raw bytes of
//! this vault's device-local record through [`SyncStateStore::read_record`] and
//! sorts them into exactly one fixed category ([`AuthenticatedStateLoad`]). A
//! version-3 record is [`Authenticated`](AuthenticatedStateLoad::Authenticated)
//! only if its MAC verifies under a key derived **in this call** from this
//! session's private Vault Key and decrypted vault id, and only if it is bound to
//! this session's normalized local location. Every other byte pattern, legacy
//! records included, maps to a category that carries no authority.
//!
//! Nothing calls it: there is no `AppState` wrapper, no command, no frontend
//! reference and no startup use, and the existing load, status and reset paths are
//! untouched (a version-3 record is still `UnsupportedVersion` for all of them).
//!
//! # What `Authenticated` proves, and what it does not
//!
//! It proves one thing: the bytes read **during this call** carry a valid MAC for
//! this vault, and they name this vault and this location. It is **not**
//!
//! * permission to write, move, remove, recover, finalize, release or migrate
//!   anything, and it creates or spends no approval;
//! * proof of freshness: an older, valid record of the same binding (a backup, a
//!   restore, another installation) is accepted, because replay cannot be detected
//!   without an external anchor;
//! * proof of durability, of user consent, of any exchange having happened, or of
//!   the state of the target, a retained copy or a staging file;
//! * proof about the filesystem: the bytes are what the OS returned at one
//!   instant, and a fingerprint of them ([`RecordFingerprint`]) only identifies
//!   those observed bytes for a later comparison.
//!
//! # Artifacts are indicators, never clean-persistence conditions
//!
//! [`ArtifactPresence::Present`] and [`ArtifactPresence::Unknown`] are diagnostic
//! values. Neither (and not even [`ArtifactPresence::None`], which is one scan at
//! one instant) may be silently read as "persistence is clean" by this or any
//! later operation. A temporary file is never read, adopted or preferred over the
//! primary record.
//!
//! # Legacy records carry no authority
//!
//! * A version-1 record (a checksum, not a MAC) decodes through the ordinary
//!   decoder and is at most [`Legacy`](AuthenticatedStateLoad::Legacy), a
//!   diagnostic. Anyone who can write the application-data directory can produce
//!   one.
//! * A version-2 record was never written by any LocalVault build. It is reported
//!   as [`UnauthenticatedExchangeFormat`](AuthenticatedStateLoad::UnauthenticatedExchangeFormat)
//!   with no state exposed.
//! * A version-3 record that fails its MAC is never handed to a legacy decoder.
//! * Nothing is migrated, reset, re-signed or rewritten.
//!
//! # Key ownership and lifetime
//!
//! The MAC key is derived per call by a private method, used for one decode and
//! dropped before the record is classified further. It is never stored in the
//! session or in `AppState`, never returned, logged or placed in an approval, and
//! the Vault Key has no getter. Because a master-password change re-wraps the same
//! Vault Key, records stay valid across it; locking and unlocking again derives the
//! same key afresh.
//!
//! # Not approved here (prerequisite of the next slice)
//!
//! The future retired-record artifact and the retire-and-publish protocol are
//! **not** approved. This module creates no such record, removes none, never
//! recognizes one as trusted and never adopts one. The store's artifact scan
//! recognizes only its own `.tmp` staging names, so a legacy reset never removes a
//! retired-record file, and nothing here changes that. Since B3c-3b-2a the legacy
//! store does not ignore such a file either: a refuse-only compatibility gate in
//! the store (it only observes) makes every legacy operation refuse while a
//! `.retired` or reserved `.v3stage` sibling of this record exists, and a record
//! of an unsupported version is no longer resettable. That gate is check-then-use,
//! grants nothing and recovers nothing. Handling a retired record beside a missing
//! primary (recovery authority) remains **not approved**, and the name `.v3stage`
//! is reserved only: no code creates, adopts or removes such a file.
//!
//! Every type here is a fixed category: no `Debug` output contains a path,
//! locator, identifier, fingerprint, MAC or record body.
//!
//! # Layout assessment (Stage 1U-4 B3c-3b-1)
//!
//! [`UnlockedVaultSession::assess_authenticated_sync_state`] is a second, equally
//! dormant and read-only entry point. Instead of the raw record alone it asks the
//! store for the whole v3 layout of this vault's record key (the primary, any
//! `.tmp`, `.retired` and reserved `.v3stage` siblings, and suspicious
//! key-prefixed entries) and sorts
//! every file it holds with the same classifier as above. Its purpose is narrow: a
//! missing primary beside any sibling, or an incomplete observation, can never be
//! mistaken for absence.
//!
//! * [`StateAssessment::ConfirmedAbsent`] needs a complete observation, no primary,
//!   no sibling and no suspicious entry.
//! * An absent primary beside anything is [`StateAssessment::PrimaryMissing`].
//! * An incomplete, ambiguous or self-contradicting observation is
//!   [`StateAssessment::Uncertain`], never absence.
//! * A sibling is classified and reported. It is never adopted, never preferred
//!   over the primary, never read as a recovery source, and a valid newer sibling
//!   beside an older primary leaves the primary's classification unchanged.
//!
//! [`SiblingVerdict::AuthenticatedForVaultAndLocator`] and
//! [`StateAssessment::PrimaryAuthenticatedForVaultAndLocator`] prove exactly what
//! `Authenticated` proves above: a valid MAC under the key of this session's vault,
//! the vault tag of this vault, and this session's normalized local location (the
//! target comparison is vacuous). They do **not** establish the binding a caller
//! expects, the identity of any target file, the current authority over a target,
//! causal ancestry between two records, ownership of an operation, freshness,
//! durability or user approval. Nothing here is a readiness verdict, a permission
//! or a recovery or cleanup authority, and no such accessor exists. The observation
//! is one pass narrowed by a second one, not a lock.

use std::fmt;

use localvault_core::{
    sync::EnvelopeFingerprint,
    sync_state::{
        AuthenticatedDecodeError, AuthenticatedSyncState, BindingMismatch, Locator, SyncState,
        SyncStateDecodeError, SyncStateMacKey,
    },
};

use super::{
    effective_local_locator, load_envelope, path_identity_eq, CorruptReason, SyncStateRoot,
    SyncStateStore, SyncStateUnavailable, UnlockedVaultSession, UnreadableReason,
};
use crate::vault::sync_state_store::{
    ArtifactPresence, LayoutPrimary, LayoutUncertainty, RecordRead, SiblingContent, SiblingKind,
    V3LayoutInspection,
};

/// Length and SHA-256 of the exact bytes of one record, as read.
///
/// It identifies **observed bytes** so that a later observation can be compared
/// with them. It is not a MAC, not a freshness proof and not a persistence
/// guarantee, and equal fingerprints do not identify a file, only its bytes.
/// `Debug` prints nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecordFingerprint {
    len: u64,
    digest: EnvelopeFingerprint,
}

impl RecordFingerprint {
    fn of(bytes: &[u8]) -> Self {
        Self {
            len: bytes.len() as u64,
            digest: EnvelopeFingerprint::of_bytes(bytes),
        }
    }
}

impl fmt::Debug for RecordFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordFingerprint(<redacted>)")
    }
}

/// A record whose MAC verified for this vault during one load, bound to this
/// session's location.
///
/// Provenance only: see the module documentation. Not `Clone`, and never stored
/// in the session or in `AppState`; the fingerprint is all a later step may keep.
pub struct StoredAuthenticatedRecord {
    state: AuthenticatedSyncState,
    fingerprint: RecordFingerprint,
    artifacts: ArtifactPresence,
}

impl StoredAuthenticatedRecord {
    pub fn state(&self) -> &SyncState {
        self.state.state()
    }

    /// The length and SHA-256 of the exact bytes this record was decoded from.
    pub fn fingerprint(&self) -> RecordFingerprint {
        self.fingerprint
    }

    /// A diagnostic indicator. `Present` and `Unknown` must not be silently
    /// treated as a clean condition.
    pub fn artifacts(&self) -> ArtifactPresence {
        self.artifacts
    }
}

impl fmt::Debug for StoredAuthenticatedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredAuthenticatedRecord(<redacted>)")
    }
}

/// A version-1 record that decoded and matched this vault and location. A
/// checksummed, **unauthenticated** diagnostic: anyone who can write the
/// application-data directory can forge one, so it is never authority for any
/// operation.
pub struct LegacyRecord {
    state: SyncState,
    fingerprint: RecordFingerprint,
    artifacts: ArtifactPresence,
}

impl LegacyRecord {
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    pub fn fingerprint(&self) -> RecordFingerprint {
        self.fingerprint
    }

    /// A diagnostic indicator. `Present` and `Unknown` must not be silently
    /// treated as a clean condition.
    pub fn artifacts(&self) -> ArtifactPresence {
        self.artifacts
    }
}

impl fmt::Debug for LegacyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyRecord(<redacted>)")
    }
}

/// The classification of the stored record. Exactly one variant per load; none
/// but [`Authenticated`](Self::Authenticated) is a MAC-verified record, and even
/// that one authorizes nothing.
#[must_use]
pub enum AuthenticatedStateLoad {
    /// Confirmed no record and no recovery artifact. Not a trusted checkpoint.
    NotConfigured,
    /// A version-3 record with a valid MAC for this vault, naming this location.
    Authenticated(Box<StoredAuthenticatedRecord>),
    /// A version-1 record. Diagnostic only; see [`LegacyRecord`].
    Legacy(Box<LegacyRecord>),
    /// A version-1 record that decodes but is bound to another vault, location or
    /// target. Its contents are not exposed.
    LegacyMismatch(BindingMismatch),
    /// A version-2 record. No build ever wrote one and it carries no MAC; no state
    /// is exposed.
    UnauthenticatedExchangeFormat,
    /// A version-3 record whose MAC does not verify under this session's key
    /// (modified, signed by another key, or another vault's record).
    NotAuthentic,
    /// A readable record that is bound to another vault or location.
    BindingMismatch(BindingMismatch),
    Corrupt(CorruptReason),
    /// A well-formed wrapper of a version this build does not know.
    UnsupportedVersion,
    Unreadable(UnreadableReason),
    /// The session's vault, its location or the state root could not anchor the
    /// check, so the store was not read.
    Unavailable(SyncStateUnavailable),
    /// The MAC key could not be derived for this session.
    KeyUnavailable,
}

// The records and their fingerprints are not printed.
impl fmt::Debug for AuthenticatedStateLoad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("NotConfigured"),
            Self::Authenticated(_) => f.write_str("Authenticated(<redacted>)"),
            Self::Legacy(_) => f.write_str("Legacy(<redacted>)"),
            Self::LegacyMismatch(mismatch) => write!(f, "LegacyMismatch({mismatch:?})"),
            Self::UnauthenticatedExchangeFormat => f.write_str("UnauthenticatedExchangeFormat"),
            Self::NotAuthentic => f.write_str("NotAuthentic"),
            Self::BindingMismatch(mismatch) => write!(f, "BindingMismatch({mismatch:?})"),
            Self::Corrupt(reason) => write!(f, "Corrupt({reason:?})"),
            Self::UnsupportedVersion => f.write_str("UnsupportedVersion"),
            Self::Unreadable(reason) => write!(f, "Unreadable({reason:?})"),
            Self::Unavailable(reason) => write!(f, "Unavailable({reason:?})"),
            Self::KeyUnavailable => f.write_str("KeyUnavailable"),
        }
    }
}

/// What the authenticated decoder's failure means for routing.
enum DecodeRoute {
    /// The classification is final.
    Final(AuthenticatedStateLoad),
    /// A version-1 or version-2 record: it has no MAC, so only the unauthenticated
    /// codecs may look at it, and only for a diagnostic.
    Unauthenticated,
}

/// Every authenticated-decode failure, matched without a wildcard so that a new
/// variant cannot be routed silently. A failed MAC is final: it never reaches an
/// unauthenticated decoder.
fn route_decode_error(error: AuthenticatedDecodeError) -> DecodeRoute {
    use AuthenticatedDecodeError as Failure;
    use AuthenticatedStateLoad as Load;

    match error {
        Failure::AuthenticationFailed => DecodeRoute::Final(Load::NotAuthentic),
        Failure::VaultMismatch => {
            DecodeRoute::Final(Load::BindingMismatch(BindingMismatch::VaultIdentity))
        }
        Failure::UnsupportedVersion => DecodeRoute::Final(Load::UnsupportedVersion),
        Failure::LegacyUnauthenticated => DecodeRoute::Unauthenticated,
        Failure::TooLarge
        | Failure::Malformed
        | Failure::UnsupportedFormat
        | Failure::NonCanonical
        | Failure::InvalidBody
        | Failure::InvalidState(_) => DecodeRoute::Final(Load::Corrupt(CorruptReason::Undecodable)),
    }
}

impl UnlockedVaultSession {
    /// Classify this vault's stored synchronization record. Strictly read-only and
    /// dormant; see the module documentation for what the result does and does not
    /// mean. The root comes from the trusted application context, never the UI.
    ///
    /// Takes `&self`, so the session, and with it the exclusive OS lock, outlives
    /// the whole call.
    pub fn load_authenticated_sync_state(&self, root: &SyncStateRoot) -> AuthenticatedStateLoad {
        let Ok(store) = SyncStateStore::new(root.path()) else {
            return AuthenticatedStateLoad::Unavailable(SyncStateUnavailable::Root);
        };

        self.load_authenticated_sync_state_in(&store)
    }

    /// [`load_authenticated_sync_state`](Self::load_authenticated_sync_state) over
    /// an explicit store. Crate-private so only the crate's own tests can supply
    /// one.
    ///
    /// In order: the vault file at the session's path must still hold the envelope
    /// this session unlocked, and must have a normalized location, both **before
    /// the store is touched**; then the raw record is read; then it is classified.
    pub(crate) fn load_authenticated_sync_state_in(
        &self,
        store: &SyncStateStore,
    ) -> AuthenticatedStateLoad {
        match load_envelope(&self.path) {
            Ok(on_disk) if on_disk == self.envelope => {}
            _ => {
                return AuthenticatedStateLoad::Unavailable(SyncStateUnavailable::LocalVaultChanged)
            }
        }

        let Some(local_locator) = self.local_locator() else {
            return AuthenticatedStateLoad::Unavailable(SyncStateUnavailable::LocalLocator);
        };

        match store.read_record(&local_locator) {
            RecordRead::NotConfigured => AuthenticatedStateLoad::NotConfigured,
            RecordRead::Unreadable(reason) => AuthenticatedStateLoad::Unreadable(reason),
            RecordRead::Corrupt(reason) => AuthenticatedStateLoad::Corrupt(reason),
            RecordRead::Present(record) => {
                self.classify_present(&local_locator, record.bytes(), record.artifacts())
            }
        }
    }

    /// The MAC key of this session's records, derived from the private Vault Key
    /// and the decrypted vault id. Used for one call and never kept.
    fn sync_state_mac_key(&self) -> Option<SyncStateMacKey> {
        SyncStateMacKey::derive(&self.vault_key, self.data.vault_id).ok()
    }

    fn classify_present(
        &self,
        local_locator: &Locator,
        bytes: &[u8],
        artifacts: ArtifactPresence,
    ) -> AuthenticatedStateLoad {
        let Some(key) = self.sync_state_mac_key() else {
            return AuthenticatedStateLoad::KeyUnavailable;
        };

        let decoded = AuthenticatedSyncState::decode(bytes, &key);

        // The key has done its one job.
        drop(key);

        let fingerprint = RecordFingerprint::of(bytes);

        match decoded {
            Ok(authenticated) => {
                if !path_identity_eq(
                    authenticated.state().local_locator().as_str(),
                    local_locator.as_str(),
                ) {
                    return AuthenticatedStateLoad::Corrupt(CorruptReason::LocatorMismatch);
                }

                match self.binding_of(authenticated.state(), local_locator) {
                    Ok(()) => {
                        AuthenticatedStateLoad::Authenticated(Box::new(StoredAuthenticatedRecord {
                            state: authenticated,
                            fingerprint,
                            artifacts,
                        }))
                    }
                    Err(mismatch) => AuthenticatedStateLoad::BindingMismatch(mismatch),
                }
            }
            Err(error) => match route_decode_error(error) {
                DecodeRoute::Final(load) => load,
                DecodeRoute::Unauthenticated => {
                    self.classify_unauthenticated(local_locator, bytes, fingerprint, artifacts)
                }
            },
        }
    }

    /// Version-1 and version-2 records, which have no MAC. Reached only through a
    /// record that declares itself legacy, never after a failed MAC.
    fn classify_unauthenticated(
        &self,
        local_locator: &Locator,
        bytes: &[u8],
        fingerprint: RecordFingerprint,
        artifacts: ArtifactPresence,
    ) -> AuthenticatedStateLoad {
        match SyncState::decode(bytes) {
            Ok(state) => {
                if !path_identity_eq(state.local_locator().as_str(), local_locator.as_str()) {
                    return AuthenticatedStateLoad::Corrupt(CorruptReason::LocatorMismatch);
                }

                match self.binding_of(&state, local_locator) {
                    Ok(()) => AuthenticatedStateLoad::Legacy(Box::new(LegacyRecord {
                        state,
                        fingerprint,
                        artifacts,
                    })),
                    Err(mismatch) => AuthenticatedStateLoad::LegacyMismatch(mismatch),
                }
            }
            // The ordinary decoder knows version 1 only: a version-2 record gets
            // its own explicit codec, and nothing it decodes leaves this function.
            Err(SyncStateDecodeError::UnsupportedVersion) => {
                if SyncState::decode_exchange_record(bytes).is_ok() {
                    AuthenticatedStateLoad::UnauthenticatedExchangeFormat
                } else {
                    AuthenticatedStateLoad::Corrupt(CorruptReason::Undecodable)
                }
            }
            Err(
                SyncStateDecodeError::TooLarge
                | SyncStateDecodeError::Malformed
                | SyncStateDecodeError::UnsupportedFormat
                | SyncStateDecodeError::ChecksumMismatch
                | SyncStateDecodeError::InvalidBody
                | SyncStateDecodeError::InvalidState(_),
            ) => AuthenticatedStateLoad::Corrupt(CorruptReason::Undecodable),
        }
    }

    /// The core binding check against this session's authenticated vault id and
    /// normalized location (a case-only spelling difference is the same location,
    /// as the store found the record through that rule). With no selected target
    /// the record's own is passed, so the target comparison is vacuous by
    /// construction: this says nothing about any target.
    fn binding_of(
        &self,
        state: &SyncState,
        local_locator: &Locator,
    ) -> Result<(), BindingMismatch> {
        let expected_local = effective_local_locator(state, local_locator);

        state.verify_binding(self.data.vault_id, &expected_local, state.target_locator())
    }
}

// ---- layout assessment (read-only) -------------------------------------------

/// What one file beside the primary (a `.tmp` or `.retired` sibling) turned out to
/// be, by the same classifier as the primary.
///
/// A report, not an authority. `AuthenticatedForVaultAndLocator` means the bytes
/// carry a valid MAC under this session's vault key, name this vault and name this
/// session's location, and nothing more: not the binding id a caller expects, not a
/// target, not lineage, ownership, freshness or durability, and not permission to
/// adopt, prefer, recover from, release or remove the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingVerdict {
    /// MAC, vault tag and local location only. Equal fingerprints mean equal bytes.
    AuthenticatedForVaultAndLocator(RecordFingerprint),
    /// A version-1 record: a checksum, not a MAC.
    LegacyV1Unauthenticated,
    /// A version-1 record bound to another vault.
    LegacyBoundElsewhere,
    /// A version-2 record: no MAC.
    UnauthenticatedExchangeFormat,
    /// A version-3 record whose MAC does not verify under this session's key.
    NotAuthentic,
    BoundToOtherVault,
    WrongLocator,
    Corrupt,
    Empty,
    TooLarge,
    UnsupportedVersion,
    /// The file could not be read.
    Unreadable,
    /// Not a plain file.
    UnexpectedObject,
    /// Listed, then gone when it was read.
    Vanished,
}

/// The siblings of one assessment, by kind, in a stable order, plus how many other
/// key-prefixed entries were seen. Verdicts and counts only: no name, token or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingReport {
    staging: Vec<SiblingVerdict>,
    retired: Vec<SiblingVerdict>,
    unrecognized: usize,
}

impl SiblingReport {
    pub fn staging(&self) -> &[SiblingVerdict] {
        &self.staging
    }

    pub fn retired(&self) -> &[SiblingVerdict] {
        &self.retired
    }

    /// Key-prefixed entries that match no recognized shape.
    pub fn unrecognized(&self) -> usize {
        self.unrecognized
    }

    /// Nothing beside the primary: no sibling of either kind and no suspicious entry.
    pub fn is_empty(&self) -> bool {
        self.staging.is_empty() && self.retired.is_empty() && self.unrecognized == 0
    }
}

/// Why a primary record that exists carries no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonAuthoritativePrimary {
    LegacyV1,
    LegacyBoundElsewhere,
    UnauthenticatedExchangeFormat,
    NotAuthentic,
    BoundToOtherVault,
    WrongLocator,
    Corrupt,
    Empty,
    TooLarge,
    UnsupportedVersion,
    UnexpectedObject,
}

impl From<NonAuthoritativePrimary> for SiblingVerdict {
    fn from(class: NonAuthoritativePrimary) -> Self {
        match class {
            NonAuthoritativePrimary::LegacyV1 => Self::LegacyV1Unauthenticated,
            NonAuthoritativePrimary::LegacyBoundElsewhere => Self::LegacyBoundElsewhere,
            NonAuthoritativePrimary::UnauthenticatedExchangeFormat => {
                Self::UnauthenticatedExchangeFormat
            }
            NonAuthoritativePrimary::NotAuthentic => Self::NotAuthentic,
            NonAuthoritativePrimary::BoundToOtherVault => Self::BoundToOtherVault,
            NonAuthoritativePrimary::WrongLocator => Self::WrongLocator,
            NonAuthoritativePrimary::Corrupt => Self::Corrupt,
            NonAuthoritativePrimary::Empty => Self::Empty,
            NonAuthoritativePrimary::TooLarge => Self::TooLarge,
            NonAuthoritativePrimary::UnsupportedVersion => Self::UnsupportedVersion,
            NonAuthoritativePrimary::UnexpectedObject => Self::UnexpectedObject,
        }
    }
}

/// The result of one layout assessment. Exactly one variant; none grants anything.
#[must_use]
#[derive(Debug)]
pub enum StateAssessment {
    /// A complete observation found no primary, no sibling and no suspicious entry.
    /// One observation at one instant; not a lock and not a permission.
    ConfirmedAbsent,
    /// The primary carries a valid MAC for this vault and location. See
    /// [`SiblingVerdict::AuthenticatedForVaultAndLocator`] for what that does and
    /// does not prove. The siblings are reported, never adopted.
    PrimaryAuthenticatedForVaultAndLocator {
        record: Box<StoredAuthenticatedRecord>,
        siblings: SiblingReport,
    },
    /// No primary, but at least one sibling or suspicious entry. Never absence.
    PrimaryMissing { siblings: SiblingReport },
    /// A primary exists and carries no authority.
    PrimaryNotAuthenticated {
        class: NonAuthoritativePrimary,
        siblings: SiblingReport,
    },
    /// The observation was incomplete, ambiguous or contradicted itself. Never
    /// absence.
    Uncertain(LayoutUncertainty),
    /// The session's vault, its location or the state root could not anchor the
    /// check, so the store was not consulted.
    Unavailable(SyncStateUnavailable),
    /// The MAC key could not be derived for this session.
    KeyUnavailable,
}

/// A classified file, before it becomes a verdict or a primary assessment.
enum Judged {
    Authenticated(Box<StoredAuthenticatedRecord>),
    Weak(NonAuthoritativePrimary),
    /// An outcome the content classifier cannot produce for bytes it was given;
    /// treated as unreadable, never as authority.
    Unusable,
    KeyUnavailable,
}

/// Every classifier outcome, matched without a wildcard so that a new variant
/// cannot be routed silently.
fn judge(load: AuthenticatedStateLoad) -> Judged {
    use AuthenticatedStateLoad as Load;
    use NonAuthoritativePrimary as Weak;

    match load {
        Load::Authenticated(record) => Judged::Authenticated(record),
        Load::Legacy(_) => Judged::Weak(Weak::LegacyV1),
        Load::LegacyMismatch(_) => Judged::Weak(Weak::LegacyBoundElsewhere),
        Load::UnauthenticatedExchangeFormat => Judged::Weak(Weak::UnauthenticatedExchangeFormat),
        Load::NotAuthentic => Judged::Weak(Weak::NotAuthentic),
        Load::BindingMismatch(BindingMismatch::VaultIdentity) => {
            Judged::Weak(Weak::BoundToOtherVault)
        }
        Load::BindingMismatch(BindingMismatch::LocalLocator | BindingMismatch::TargetLocator) => {
            Judged::Weak(Weak::WrongLocator)
        }
        Load::Corrupt(CorruptReason::Empty) => Judged::Weak(Weak::Empty),
        Load::Corrupt(CorruptReason::TooLarge) => Judged::Weak(Weak::TooLarge),
        Load::Corrupt(CorruptReason::Undecodable) => Judged::Weak(Weak::Corrupt),
        Load::Corrupt(CorruptReason::LocatorMismatch) => Judged::Weak(Weak::WrongLocator),
        Load::UnsupportedVersion => Judged::Weak(Weak::UnsupportedVersion),
        Load::KeyUnavailable => Judged::KeyUnavailable,
        Load::NotConfigured | Load::Unreadable(_) | Load::Unavailable(_) => Judged::Unusable,
    }
}

impl UnlockedVaultSession {
    /// Assess this vault's whole stored layout: the primary record and every
    /// sibling beside it. Strictly read-only and dormant; see the module
    /// documentation for what the result does and does not mean. The root comes
    /// from the trusted application context, never the UI.
    ///
    /// Takes `&self`, so the session, and with it the exclusive OS lock, outlives
    /// the whole call.
    pub fn assess_authenticated_sync_state(&self, root: &SyncStateRoot) -> StateAssessment {
        let Ok(store) = SyncStateStore::new(root.path()) else {
            return StateAssessment::Unavailable(SyncStateUnavailable::Root);
        };

        self.assess_authenticated_sync_state_in(&store)
    }

    /// [`assess_authenticated_sync_state`](Self::assess_authenticated_sync_state)
    /// over an explicit store. Crate-private so only the crate's own tests can
    /// supply one.
    ///
    /// In order: the vault file at the session's path must still hold the envelope
    /// this session unlocked, and must have a normalized location, both **before
    /// the store is touched**; then the layout is observed; then the primary and
    /// every sibling are classified.
    pub(crate) fn assess_authenticated_sync_state_in(
        &self,
        store: &SyncStateStore,
    ) -> StateAssessment {
        match load_envelope(&self.path) {
            Ok(on_disk) if on_disk == self.envelope => {}
            _ => return StateAssessment::Unavailable(SyncStateUnavailable::LocalVaultChanged),
        }

        let Some(local_locator) = self.local_locator() else {
            return StateAssessment::Unavailable(SyncStateUnavailable::LocalLocator);
        };

        let layout = match store.inspect_v3_layout(&local_locator) {
            V3LayoutInspection::Observed(layout) => layout,
            V3LayoutInspection::Uncertain(reason) => return StateAssessment::Uncertain(reason),
        };

        let mut siblings = SiblingReport {
            staging: Vec::new(),
            retired: Vec::new(),
            unrecognized: layout.unrecognized(),
        };

        for sibling in layout.siblings() {
            let Some(verdict) = self.verdict_of(&local_locator, sibling.content()) else {
                return StateAssessment::KeyUnavailable;
            };

            match sibling.kind() {
                // A reserved staging name is reported with the staging files,
                // classified by its content like any other, never adopted and
                // never preferred over the primary.
                SiblingKind::Staging | SiblingKind::ReservedStaging => {
                    siblings.staging.push(verdict)
                }
                SiblingKind::Retired => siblings.retired.push(verdict),
            }
        }

        let primary_class = match layout.primary() {
            LayoutPrimary::Absent => {
                return if siblings.is_empty() {
                    StateAssessment::ConfirmedAbsent
                } else {
                    StateAssessment::PrimaryMissing { siblings }
                };
            }
            LayoutPrimary::Empty => NonAuthoritativePrimary::Empty,
            LayoutPrimary::TooLarge => NonAuthoritativePrimary::TooLarge,
            LayoutPrimary::Unexpected => NonAuthoritativePrimary::UnexpectedObject,
            LayoutPrimary::Bytes(bytes) => {
                // Anything beside the primary, of any kind, is reported as present;
                // the indicator is never "none" when the observation saw something.
                let artifacts = if siblings.is_empty() {
                    ArtifactPresence::None
                } else {
                    ArtifactPresence::Present
                };

                match judge(self.classify_present(&local_locator, bytes, artifacts)) {
                    Judged::Authenticated(record) => {
                        return StateAssessment::PrimaryAuthenticatedForVaultAndLocator {
                            record,
                            siblings,
                        };
                    }
                    Judged::Weak(class) => class,
                    Judged::Unusable => {
                        return StateAssessment::Uncertain(LayoutUncertainty::Io(
                            std::io::ErrorKind::Other,
                        ));
                    }
                    Judged::KeyUnavailable => return StateAssessment::KeyUnavailable,
                }
            }
        };

        StateAssessment::PrimaryNotAuthenticated {
            class: primary_class,
            siblings,
        }
    }

    /// The verdict for one sibling's content, or `None` when no MAC key can be
    /// derived for this session.
    fn verdict_of(
        &self,
        local_locator: &Locator,
        content: &SiblingContent,
    ) -> Option<SiblingVerdict> {
        match content {
            SiblingContent::Bytes(bytes) => {
                // The artifact indicator belongs to a primary; it is not used here.
                match judge(self.classify_present(local_locator, bytes, ArtifactPresence::Unknown))
                {
                    Judged::Authenticated(record) => Some(
                        SiblingVerdict::AuthenticatedForVaultAndLocator(record.fingerprint()),
                    ),
                    Judged::Weak(class) => Some(class.into()),
                    Judged::Unusable => Some(SiblingVerdict::Unreadable),
                    Judged::KeyUnavailable => None,
                }
            }
            SiblingContent::Empty => Some(SiblingVerdict::Empty),
            SiblingContent::TooLarge => Some(SiblingVerdict::TooLarge),
            SiblingContent::Unreadable(_) => Some(SiblingVerdict::Unreadable),
            SiblingContent::Unexpected => Some(SiblingVerdict::UnexpectedObject),
            SiblingContent::Vanished => Some(SiblingVerdict::Vanished),
        }
    }
}

// ---- end layout assessment ---------------------------------------------------

// ---- test-only code below this line ------------------------------------------

#[cfg(all(test, windows))]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use uuid::Uuid;
    use zeroize::Zeroizing;

    use localvault_core::{
        sync::{PushBaseline, PushIntent, RemoteHighWater},
        sync_state::{
            BindingId, ExchangeIntent, ExchangeScheme, ObjectAnchor, PendingPush, SyncBase,
            SyncCheckpoint, SyncStateError, VaultBindingTag, BINDING_SALT_LEN,
            MAX_SYNC_STATE_BYTES,
        },
    };

    use super::*;
    use crate::vault::{
        handle_ops::test_support::{assert_local_ntfs, make_junction, snapshot},
        session::{
            BindingAttention, BindingResetOutcome, BindingResetSubject, BindingState,
            InitialBindingApproval, InitialBindingOutcome, SessionSyncState,
        },
        sync_file_adapter::SyncFileTarget,
        sync_state_store::{StateLoad, SYNC_STATE_DIRECTORY},
    };

    const NOW_MS: i64 = 1_700_000_000_000;
    const MASTER_PASSWORD: &str = "b3c3a-master-password-test-only";
    const NEW_PASSWORD: &str = "b3c3a-new-master-password-test-only";
    const OTHER_LOCAL: &str = r"\\?\C:\Synthetic\Vaults\OTHER-MARKER.lvault";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    /// A unique, test-owned directory under the B3c-3a scratch base, never
    /// `%TEMP%`. Removed only by its `TempDir` guard. Fails loudly unless on a
    /// local NTFS volume.
    fn scratch(name: &str) -> tempfile::TempDir {
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
        assert_local_ntfs(dir.path());

        dir
    }

    fn anchor(byte: u8) -> ObjectAnchor {
        ObjectAnchor::new(&[byte; 8]).unwrap()
    }

    fn new_session(path: &Path) -> UnlockedVaultSession {
        UnlockedVaultSession::create(path, password(), NOW_MS).unwrap()
    }

    fn mac_key(session: &UnlockedVaultSession) -> SyncStateMacKey {
        SyncStateMacKey::derive(&session.vault_key, session.data.vault_id).unwrap()
    }

    fn v3_of(session: &UnlockedVaultSession, state: &SyncState) -> Vec<u8> {
        state.encode_authenticated(&mac_key(session)).unwrap()
    }

    /// A state with the same binding as `state`, but another base.
    fn with_base(state: &SyncState, base: SyncBase) -> SyncState {
        SyncState::new(
            state.binding_id(),
            *state.vault_tag(),
            state.local_locator().clone(),
            state.target_locator().clone(),
            base,
            None,
        )
        .unwrap()
    }

    /// A synthetic vault with an identical copy, an application root, and the real
    /// B1f binding between them. `session` is declared first so that it (and its
    /// exclusive lock file) drops before the scratch directory is removed.
    struct Rig {
        session: UnlockedVaultSession,
        root: SyncStateRoot,
        target: SyncFileTarget,
        vault: PathBuf,
        /// The version-1 record the real binding wrote, captured once.
        bound_state: Option<SyncState>,
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
            let session = new_session(&vault);
            let copy = dest.join("copy.lvault");

            fs::copy(&vault, &copy).unwrap();

            let target = SyncFileTarget::from_path(&copy).unwrap();
            let root = SyncStateRoot::for_test(dir.path().join("app-local"));

            Self {
                session,
                root,
                target,
                vault,
                bound_state: None,
                dir,
            }
        }

        /// Bound through the real, unchanged initial-binding operation: a
        /// version-1 record.
        fn bound(name: &str) -> Self {
            let mut rig = Self::unbound(name);

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

            rig.bound_state = match rig.store().load(&rig.locator()) {
                StateLoad::Loaded(state) => Some(*state),
                other => panic!("expected a version-1 record, found {other:?}"),
            };

            rig
        }

        fn store(&self) -> SyncStateStore {
            SyncStateStore::new(self.root.path()).unwrap()
        }

        fn state_dir(&self) -> PathBuf {
            self.root.path().join(SYNC_STATE_DIRECTORY)
        }

        fn locator(&self) -> Locator {
            self.session.local_locator().unwrap()
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

        /// A staging name for this record's key, as an interrupted write leaves it.
        fn temp_path(&self, token: &str) -> PathBuf {
            let record = self.record();
            let key = record.file_stem().unwrap().to_str().unwrap();

            self.state_dir().join(format!("{key}.{token}.tmp"))
        }

        /// The version-1 record the real binding wrote (as bound, whatever was
        /// written over it since).
        fn v1_state(&self) -> SyncState {
            self.bound_state.clone().expect("a bound rig")
        }

        fn put(&self, bytes: &[u8]) {
            fs::write(self.record(), bytes).unwrap();
        }

        fn put_v3(&self, state: &SyncState) {
            self.put(&v3_of(&self.session, state));
        }

        fn raw(&self) -> Vec<u8> {
            fs::read(self.record()).unwrap()
        }

        /// A state bound to `vault_id`, for `local`, with this rig's target.
        fn craft(&self, vault_id: Uuid, local: &Locator) -> SyncState {
            let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
            let current = self.v1_state();

            SyncState::new(
                BindingId::new(Uuid::from_u128(0xB3C3)).unwrap(),
                VaultBindingTag::derive(salt, vault_id).unwrap(),
                local.clone(),
                current.target_locator().clone(),
                *current.base(),
                None,
            )
            .unwrap()
        }

        fn other_locator() -> Locator {
            Locator::new(OTHER_LOCAL).unwrap()
        }

        /// A second, independent vault in the same scratch tree.
        fn foreign(&self) -> UnlockedVaultSession {
            let folder = self.dir.path().join("foreign");

            fs::create_dir_all(&folder).unwrap();

            new_session(&folder.join("foreign.lvault"))
        }

        /// A state with an exchange intent, as the dormant exchange records allow.
        fn exchange_state(&self) -> SyncState {
            let current = self.v1_state();
            let SyncBase::Based(checkpoint) = current.base() else {
                panic!("a based state is required");
            };

            let intent = PushIntent::new(
                PushBaseline::Present(*checkpoint.synced()),
                EnvelopeFingerprint::of_bytes(b"b3c3a-intended"),
            )
            .unwrap();
            let pending = PendingPush::new(
                Uuid::from_u128(0xE1),
                intent,
                checkpoint.high_water().revision() + 1,
            )
            .unwrap();

            SyncState::new_with_exchange_records(
                current.binding_id(),
                *current.vault_tag(),
                current.local_locator().clone(),
                current.target_locator().clone(),
                *current.base(),
                Some(pending),
                Some(ExchangeIntent::new(
                    ExchangeScheme::RetainAndPublishV1,
                    anchor(1),
                    anchor(2),
                )),
                Vec::new(),
            )
            .unwrap()
        }

        /// One load, with the whole scratch tree (names, kinds, lengths, times and
        /// content hashes; the `.lock` by name only) snapshotted before and after.
        fn load(&self) -> AuthenticatedStateLoad {
            self.load_in(&self.store())
        }

        fn load_in(&self, store: &SyncStateStore) -> AuthenticatedStateLoad {
            let before = snapshot(self.dir.path());
            let result = self.session.load_authenticated_sync_state_in(store);

            assert_eq!(
                snapshot(self.dir.path()),
                before,
                "the load changed the filesystem"
            );

            result
        }

        fn authenticated(&self) -> Box<StoredAuthenticatedRecord> {
            match self.load() {
                AuthenticatedStateLoad::Authenticated(record) => record,
                other => panic!("expected Authenticated, found {other:?}"),
            }
        }
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    /// The expected fingerprint, computed independently of `RecordFingerprint::of`.
    fn fingerprint_of(bytes: &[u8]) -> RecordFingerprint {
        RecordFingerprint {
            len: bytes.len() as u64,
            digest: EnvelopeFingerprint::of_bytes(bytes),
        }
    }

    /// The byte right after `marker`, turned into a different hex digit.
    fn flip_hex_after(bytes: &[u8], marker: &str) -> Vec<u8> {
        let text = std::str::from_utf8(bytes).unwrap();
        let at = text.find(marker).expect("marker present") + marker.len();

        let mut out = bytes.to_vec();
        out[at] = if out[at] == b'0' { b'1' } else { b'0' };
        out
    }

    /// One lowercase letter inside the `body` string changed to another letter, so
    /// the wrapper stays canonical and only the MAC can notice.
    fn change_a_body_letter(bytes: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(bytes).unwrap();
        let start = text.find("\"body\":\"").expect("body present") + "\"body\":\"".len();

        let mut out = bytes.to_vec();
        let at = start
            + out[start..]
                .iter()
                .position(u8::is_ascii_lowercase)
                .expect("a letter in the body");
        out[at] = if out[at] == b'a' { b'b' } else { b'a' };
        out
    }

    fn higher_base(state: &SyncState) -> SyncBase {
        let SyncBase::Based(checkpoint) = state.base() else {
            panic!("a based state is required");
        };

        SyncBase::Based(
            SyncCheckpoint::new(
                *checkpoint.synced(),
                checkpoint.synced_revision(),
                RemoteHighWater::new(checkpoint.high_water().revision() + 5),
            )
            .unwrap(),
        )
    }

    // ---- absence ----------------------------------------------------------------

    #[test]
    fn a_missing_directory_and_an_empty_directory_are_not_configured() {
        let rig = Rig::unbound("absent");

        assert!(!rig.state_dir().exists());
        assert!(matches!(rig.load(), AuthenticatedStateLoad::NotConfigured));

        // The dormant read did not create the directory either.
        assert!(!rig.state_dir().exists());

        fs::create_dir_all(rig.state_dir()).unwrap();
        assert!(matches!(rig.load(), AuthenticatedStateLoad::NotConfigured));
    }

    #[test]
    fn a_staging_file_without_a_primary_is_unresolved_not_absent() {
        let rig = Rig::bound("temp-only");
        let bytes = rig.raw();
        let temp = rig.temp_path(TOKEN);

        fs::remove_file(rig.record()).unwrap();
        fs::write(&temp, bytes).unwrap();

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Unreadable(UnreadableReason::UnresolvedArtifacts)
        ));
    }

    // ---- unsafe objects ----------------------------------------------------------

    #[test]
    fn a_record_that_is_a_directory_is_an_unexpected_object() {
        let rig = Rig::bound("record-is-dir");
        let record = rig.record();

        fs::remove_file(&record).unwrap();
        fs::create_dir(&record).unwrap();

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        ));
    }

    #[test]
    fn a_state_directory_substituted_by_a_junction_is_never_followed() {
        let rig = Rig::bound("dir-junction");
        let moved = rig.dir.path().join("moved-state");

        // A perfectly valid record sits behind the junction.
        rig.put_v3(&rig.v1_state());
        fs::rename(rig.state_dir(), &moved).unwrap();
        make_junction(&rig.state_dir(), &moved);

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        ));
    }

    #[test]
    fn a_junction_among_the_ancestors_of_the_root_is_never_followed() {
        let rig = Rig::bound("ancestor-junction");
        let real = rig.dir.path().join("real");
        let link = rig.dir.path().join("link");
        let behind = real.join("app-local").join(SYNC_STATE_DIRECTORY);

        fs::create_dir_all(&behind).unwrap();
        fs::copy(rig.record(), behind.join(rig.record().file_name().unwrap())).unwrap();
        make_junction(&link, &real);

        let store = SyncStateStore::new(&link.join("app-local")).unwrap();

        assert!(matches!(
            rig.load_in(&store),
            AuthenticatedStateLoad::Unreadable(UnreadableReason::UnexpectedObject)
        ));
    }

    // ---- corrupt and unsupported -------------------------------------------------

    #[test]
    fn empty_oversized_and_undecodable_records_are_corrupt() {
        let rig = Rig::bound("corrupt");

        rig.put(b"");
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::Empty)
        ));

        rig.put(&vec![b'a'; MAX_SYNC_STATE_BYTES + 1]);
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::TooLarge)
        ));

        rig.put(b"this is not a sync-state record");
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::Undecodable)
        ));

        // A wrapper of another format is not a record of this one.
        rig.put(br#"{"format":"something-else","version":3}"#);
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::Undecodable)
        ));
    }

    #[test]
    fn a_version_one_checksum_flip_is_corrupt_not_legacy() {
        let rig = Rig::bound("v1-checksum");

        rig.put(&flip_hex_after(&rig.raw(), "\"body_sha256\":\""));

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::Undecodable)
        ));
    }

    #[test]
    fn a_non_canonical_version_three_record_is_corrupt() {
        let rig = Rig::bound("v3-noncanonical");
        let mut bytes = v3_of(&rig.session, &rig.v1_state());

        bytes.push(b' ');
        rig.put(&bytes);

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::Undecodable)
        ));
    }

    #[test]
    fn an_unknown_future_version_is_unsupported() {
        let rig = Rig::bound("future-version");

        rig.put(br#"{"format":"localvault-sync-state","version":4}"#);
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::UnsupportedVersion
        ));

        rig.put(br#"{"format":"localvault-sync-state","version":0}"#);
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::UnsupportedVersion
        ));
    }

    // ---- legacy ------------------------------------------------------------------

    #[test]
    fn a_valid_version_one_record_is_a_legacy_diagnostic_and_the_old_status_is_unchanged() {
        let rig = Rig::bound("legacy");
        let before = rig.session.binding_status(&rig.root);
        let bytes = rig.raw();

        let AuthenticatedStateLoad::Legacy(record) = rig.load() else {
            panic!("expected Legacy");
        };

        assert_eq!(*record.state(), rig.v1_state());
        assert_eq!(record.fingerprint(), fingerprint_of(&bytes));
        assert_eq!(record.artifacts(), ArtifactPresence::None);

        // The existing status path is exactly what it was.
        let after = rig.session.binding_status(&rig.root);
        assert_eq!(after, before);
        assert!(matches!(after.state(), BindingState::Linked(_)));
        assert!(matches!(
            rig.session.load_sync_state(&rig.root),
            SessionSyncState::Bound(_)
        ));
    }

    #[test]
    fn a_version_one_record_of_a_foreign_vault_is_a_legacy_mismatch() {
        let rig = Rig::bound("legacy-foreign");
        let foreign = rig.foreign();

        rig.put(
            &rig.craft(foreign.data.vault_id, &rig.locator())
                .encode()
                .unwrap(),
        );

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::LegacyMismatch(BindingMismatch::VaultIdentity)
        ));
    }

    #[test]
    fn a_version_one_record_for_another_location_is_a_locator_mismatch() {
        let rig = Rig::bound("legacy-locator");

        rig.put(
            &rig.craft(rig.session.data.vault_id, &Rig::other_locator())
                .encode()
                .unwrap(),
        );

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::LocatorMismatch)
        ));
    }

    #[test]
    fn a_valid_version_two_record_is_unauthenticated_and_exposes_no_state() {
        let rig = Rig::bound("v2");

        rig.put(&rig.v1_state().encode_exchange_record().unwrap());
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::UnauthenticatedExchangeFormat
        ));

        // With exchange records, too: still no MAC, still not authenticated.
        rig.put(&rig.exchange_state().encode_exchange_record().unwrap());
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::UnauthenticatedExchangeFormat
        ));
    }

    #[test]
    fn a_damaged_version_two_record_is_corrupt() {
        let rig = Rig::bound("v2-damaged");
        let bytes = rig.v1_state().encode_exchange_record().unwrap();

        rig.put(&flip_hex_after(&bytes, "\"body_sha256\":\""));

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::Undecodable)
        ));
    }

    // ---- authenticated -----------------------------------------------------------

    #[test]
    fn a_valid_version_three_record_is_authenticated_with_the_exact_fingerprint() {
        let rig = Rig::bound("authenticated");
        let state = rig.v1_state();

        rig.put_v3(&state);
        let bytes = rig.raw();

        let record = rig.authenticated();

        assert_eq!(*record.state(), state);
        assert_eq!(record.fingerprint(), fingerprint_of(&bytes));
        assert_eq!(record.artifacts(), ArtifactPresence::None);
    }

    #[test]
    fn the_fingerprint_is_the_length_and_sha256_of_the_exact_bytes() {
        // The digest is SHA-256 (FIPS 180 test vector for "abc").
        assert_eq!(
            EnvelopeFingerprint::of_bytes(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let fingerprint = RecordFingerprint::of(b"abc");

        assert_eq!(fingerprint.len, 3);
        assert_eq!(fingerprint, fingerprint_of(b"abc"));
        assert_ne!(fingerprint, RecordFingerprint::of(b"abd"));
        assert_ne!(fingerprint, RecordFingerprint::of(b"abc "));
        assert_ne!(fingerprint, RecordFingerprint::of(b"ab"));
    }

    #[test]
    fn a_staging_file_beside_the_primary_is_reported_and_never_adopted() {
        let rig = Rig::bound("authenticated-temp");
        let state = rig.v1_state();

        rig.put_v3(&state);
        fs::write(rig.temp_path(TOKEN), b"an unpublished candidate").unwrap();

        let record = rig.authenticated();

        assert_eq!(*record.state(), state);
        assert_eq!(record.artifacts(), ArtifactPresence::Present);

        // The result changed nothing else: the old path still does not accept it.
        assert_eq!(
            rig.session.binding_status(&rig.root).state(),
            &BindingState::NeedsAttention(BindingAttention::UnsupportedVersion)
        );
    }

    #[test]
    fn the_primary_always_wins_over_an_unpublished_candidate() {
        let rig = Rig::bound("primary-wins");
        let older = rig.v1_state();
        let newer = with_base(&older, higher_base(&older));

        rig.put_v3(&older);
        fs::write(rig.temp_path(TOKEN), v3_of(&rig.session, &newer)).unwrap();

        let record = rig.authenticated();

        assert_eq!(*record.state(), older);
        assert_ne!(*record.state(), newer);
        assert_eq!(record.artifacts(), ArtifactPresence::Present);

        // A valid candidate does not rescue a damaged primary either.
        rig.put(b"damaged");
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::Undecodable)
        ));
    }

    #[test]
    fn an_artifact_scan_that_cannot_complete_stays_unknown() {
        let rig = Rig::bound("artifacts-unknown");
        let state = rig.v1_state();

        rig.put_v3(&state);

        // More entries than the store will scan: the primary is still read in
        // full, but nothing can be said about artifacts.
        for index in 0..10_001 {
            fs::write(rig.state_dir().join(format!("unrelated-{index}.dat")), b"x").unwrap();
        }

        let bytes = rig.raw();
        let entries = fs::read_dir(rig.state_dir()).unwrap().count();

        let AuthenticatedStateLoad::Authenticated(record) =
            rig.session.load_authenticated_sync_state_in(&rig.store())
        else {
            panic!("expected Authenticated");
        };

        assert_eq!(*record.state(), state);
        assert_eq!(record.artifacts(), ArtifactPresence::Unknown);
        assert_ne!(record.artifacts(), ArtifactPresence::None);

        // Nothing was added, removed or changed.
        assert_eq!(fs::read_dir(rig.state_dir()).unwrap().count(), entries);
        assert_eq!(rig.raw(), bytes);
    }

    #[test]
    fn a_state_with_exchange_records_is_classified_only() {
        let rig = Rig::bound("authenticated-exchange");
        let state = rig.exchange_state();

        assert!(state.has_exchange_records());
        rig.put_v3(&state);

        let record = rig.authenticated();

        assert_eq!(*record.state(), state);
        assert!(record.state().has_exchange_records());
    }

    // ---- not authentic -----------------------------------------------------------

    #[test]
    fn a_record_signed_by_another_vault_is_not_authentic() {
        let rig = Rig::bound("foreign-key");
        let foreign = rig.foreign();
        let theirs = rig.craft(foreign.data.vault_id, &rig.locator());

        rig.put(&v3_of(&foreign, &theirs));

        assert!(matches!(rig.load(), AuthenticatedStateLoad::NotAuthentic));
    }

    #[test]
    fn a_record_signed_with_the_wrong_vault_key_is_not_authentic() {
        let rig = Rig::bound("wrong-key");
        let foreign = rig.foreign();
        let mine = rig.v1_state();

        // This vault's identity, but another vault's key.
        let wrong = SyncStateMacKey::derive(&foreign.vault_key, rig.session.data.vault_id).unwrap();
        rig.put(&mine.encode_authenticated(&wrong).unwrap());

        assert!(matches!(rig.load(), AuthenticatedStateLoad::NotAuthentic));
    }

    #[test]
    fn a_flipped_tag_bit_or_a_changed_body_byte_is_not_authentic_and_never_legacy() {
        let rig = Rig::bound("tampered");
        let bytes = v3_of(&rig.session, &rig.v1_state());

        rig.put(&bytes);
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Authenticated(_)
        ));

        rig.put(&flip_hex_after(&bytes, "\"mac\":\""));
        assert!(matches!(rig.load(), AuthenticatedStateLoad::NotAuthentic));

        rig.put(&change_a_body_letter(&bytes));
        assert!(matches!(rig.load(), AuthenticatedStateLoad::NotAuthentic));
    }

    // ---- binding -----------------------------------------------------------------

    #[test]
    fn a_version_three_record_of_this_vault_for_another_location_is_a_locator_mismatch() {
        let rig = Rig::bound("v3-locator");
        let elsewhere = rig.craft(rig.session.data.vault_id, &Rig::other_locator());

        rig.put_v3(&elsewhere);

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Corrupt(CorruptReason::LocatorMismatch)
        ));
    }

    #[test]
    fn a_case_only_difference_of_the_location_is_the_same_location() {
        let rig = Rig::bound("case-variant");
        let shouting = Locator::new(&rig.locator().as_str().to_ascii_uppercase()).unwrap();
        let state = rig.craft(rig.session.data.vault_id, &shouting);

        assert_ne!(shouting, rig.locator());

        rig.put_v3(&state);
        let record = rig.authenticated();
        assert_eq!(*record.state(), state);

        rig.put(&state.encode().unwrap());
        assert!(matches!(rig.load(), AuthenticatedStateLoad::Legacy(_)));
    }

    #[test]
    fn replay_of_an_older_valid_record_is_not_detected() {
        let rig = Rig::bound("replay");
        let older = rig.v1_state();
        let newer = with_base(&older, higher_base(&older));

        rig.put_v3(&newer);
        assert_eq!(*rig.authenticated().state(), newer);

        // The older record of the same binding, restored from a backup: accepted.
        // This is a documented limit (no external anchor), pinned on purpose.
        rig.put_v3(&older);
        let record = rig.authenticated();

        assert_eq!(*record.state(), older);
        assert_ne!(*record.state(), newer);
    }

    // ---- key lifetime ------------------------------------------------------------

    #[test]
    fn a_master_password_change_keeps_the_record_authenticated() {
        let mut rig = Rig::bound("password-change");
        let state = rig.v1_state();

        rig.put_v3(&state);
        let before = rig.authenticated().fingerprint();

        rig.session
            .change_master_password(password(), Zeroizing::new(NEW_PASSWORD.to_owned()))
            .unwrap();

        // The same Vault Key was re-wrapped, so the same record still verifies.
        let after = rig.authenticated();

        assert_eq!(*after.state(), state);
        assert_eq!(after.fingerprint(), before);

        // And again after a full lock and unlock with the new password.
        let Rig {
            session,
            root,
            vault,
            dir,
            ..
        } = rig;

        session.lock();

        let reopened =
            UnlockedVaultSession::unlock(&vault, Zeroizing::new(NEW_PASSWORD.to_owned())).unwrap();

        assert!(matches!(
            reopened.load_authenticated_sync_state(&root),
            AuthenticatedStateLoad::Authenticated(_)
        ));

        drop(reopened);
        drop(dir);
    }

    #[test]
    fn locking_and_unlocking_again_derives_the_key_afresh_and_still_verifies() {
        let rig = Rig::bound("relock");
        let state = rig.v1_state();

        rig.put_v3(&state);

        let Rig {
            session,
            root,
            vault,
            dir,
            ..
        } = rig;

        session.lock();

        let reopened = UnlockedVaultSession::unlock(&vault, password()).unwrap();

        let AuthenticatedStateLoad::Authenticated(record) =
            reopened.load_authenticated_sync_state(&root)
        else {
            panic!("expected Authenticated");
        };

        assert_eq!(*record.state(), state);

        drop(record);
        drop(reopened);
        drop(dir);
    }

    #[test]
    fn a_session_without_a_usable_vault_id_has_no_key() {
        let mut rig = Rig::bound("no-key");

        rig.put_v3(&rig.v1_state());
        rig.session.data_mut().vault_id = Uuid::nil();

        assert!(matches!(rig.load(), AuthenticatedStateLoad::KeyUnavailable));
    }

    // ---- the session guard -------------------------------------------------------

    #[test]
    fn a_vault_changed_on_disk_is_unavailable_and_the_store_is_not_consulted() {
        let rig = Rig::bound("vault-changed");
        let foreign = rig.foreign();

        rig.put_v3(&rig.v1_state());

        // Without any state directory the store would answer NotConfigured, and
        // that is exactly what must not leak through.
        fs::remove_dir_all(rig.state_dir()).unwrap();
        fs::copy(foreign.path(), &rig.vault).unwrap();

        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        ));

        fs::remove_file(&rig.vault).unwrap();
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        ));

        fs::write(&rig.vault, b"not a vault").unwrap();
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        ));
    }

    #[test]
    fn a_vault_without_a_normalized_location_is_unavailable() {
        let dir = scratch("no-locator");
        let session = new_session(&dir.path().join("vault.bin"));
        let root = SyncStateRoot::for_test(dir.path().join("app-local"));

        assert!(matches!(
            session.load_authenticated_sync_state(&root),
            AuthenticatedStateLoad::Unavailable(SyncStateUnavailable::LocalLocator)
        ));
        assert!(!dir.path().join("app-local").exists());
    }

    // ---- read-only behaviour, determinism ------------------------------------------

    #[test]
    fn repeated_loads_give_the_same_classification_and_change_nothing() {
        let rig = Rig::bound("determinism");

        rig.put_v3(&rig.v1_state());

        let first = rig.authenticated();
        let second = rig.authenticated();

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.state(), second.state());
        assert_eq!(first.artifacts(), second.artifacts());

        // Legacy too.
        rig.put(&rig.v1_state().encode().unwrap());
        let AuthenticatedStateLoad::Legacy(one) = rig.load() else {
            panic!("expected Legacy");
        };
        let AuthenticatedStateLoad::Legacy(two) = rig.load() else {
            panic!("expected Legacy");
        };

        assert_eq!(one.fingerprint(), two.fingerprint());
        assert_eq!(one.state(), two.state());
    }

    // ---- compatibility with the existing paths -------------------------------------

    #[test]
    fn the_old_entry_points_still_see_version_three_as_unsupported() {
        let rig = Rig::bound("old-v3");

        rig.put_v3(&rig.v1_state());

        assert_eq!(
            rig.store().load(&rig.locator()),
            StateLoad::UnsupportedVersion
        );
        assert_eq!(
            rig.session.load_sync_state(&rig.root),
            SessionSyncState::UnsupportedVersion
        );
        assert_eq!(
            rig.session.binding_status(&rig.root).state(),
            &BindingState::NeedsAttention(BindingAttention::UnsupportedVersion)
        );

        // Only the explicit loader accepts it.
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Authenticated(_)
        ));
    }

    #[test]
    fn the_existing_reset_still_removes_version_one_but_no_longer_a_version_three_record() {
        // B3c-3b-2a: this used to reset a version-3 record as well ("unsupported
        // record"). The refuse-only compatibility gate no longer lets the legacy
        // store remove any record of an unsupported version.
        let mut rig = Rig::bound("reset-v1");

        let _ = rig.load();

        let preview = rig.session.prepare_binding_reset(&rig.root).unwrap();
        assert_eq!(preview.subject(), BindingResetSubject::VerifiedBinding);

        let id = preview.preparation_id().to_owned();
        assert_eq!(
            rig.session.confirm_binding_reset(&rig.root, &id),
            Ok(BindingResetOutcome::ResetAndVerified)
        );
        assert!(matches!(rig.load(), AuthenticatedStateLoad::NotConfigured));

        let mut rig = Rig::bound("reset-v3");

        rig.put_v3(&rig.v1_state());
        let _ = rig.load();

        let bytes = rig.raw();

        assert!(matches!(
            rig.session.prepare_binding_reset(&rig.root),
            Err(crate::vault::session::BindingResetRefusal::UnreadableState(
                UnreadableReason::UnresolvedNewerState
            ))
        ));

        // Nothing was removed, and the explicit authenticated loader still reads it.
        assert_eq!(rig.raw(), bytes);
        assert!(matches!(
            rig.load(),
            AuthenticatedStateLoad::Authenticated(_)
        ));
    }

    // ---- exhaustive routing ------------------------------------------------------

    #[test]
    fn every_authenticated_decode_failure_has_its_own_fixed_route() {
        use AuthenticatedDecodeError as E;
        use AuthenticatedStateLoad as L;

        let final_of = |error| match route_decode_error(error) {
            DecodeRoute::Final(load) => load,
            DecodeRoute::Unauthenticated => panic!("not final"),
        };

        assert!(matches!(final_of(E::AuthenticationFailed), L::NotAuthentic));
        assert!(matches!(
            final_of(E::VaultMismatch),
            L::BindingMismatch(BindingMismatch::VaultIdentity)
        ));
        assert!(matches!(
            final_of(E::UnsupportedVersion),
            L::UnsupportedVersion
        ));

        for error in [
            E::TooLarge,
            E::Malformed,
            E::UnsupportedFormat,
            E::NonCanonical,
            E::InvalidBody,
            E::InvalidState(SyncStateError::NilBindingId),
        ] {
            assert!(
                matches!(final_of(error), L::Corrupt(CorruptReason::Undecodable)),
                "{error:?}"
            );
        }

        // The only failure that reaches an unauthenticated decoder is a record that
        // declares itself legacy. A failed MAC is final above.
        assert!(matches!(
            route_decode_error(E::LegacyUnauthenticated),
            DecodeRoute::Unauthenticated
        ));
    }

    // ---- redaction ---------------------------------------------------------------

    fn has_hex_run(text: &str, length: usize) -> bool {
        let mut run = 0;

        for c in text.chars() {
            if c.is_ascii_hexdigit() {
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
    fn debug_output_reveals_no_path_locator_identifier_fingerprint_or_mac() {
        use AuthenticatedStateLoad as L;

        let rig = Rig::bound("redaction");
        let state = rig.v1_state();
        let v3 = v3_of(&rig.session, &state);
        let mac = {
            let text = std::str::from_utf8(&v3).unwrap();
            let at = text.find("\"mac\":\"").unwrap() + "\"mac\":\"".len();
            text[at..at + 64].to_owned()
        };

        rig.put(&v3);
        let L::Authenticated(authenticated) = rig.load() else {
            panic!("expected Authenticated");
        };
        let authenticated_fingerprint = authenticated.fingerprint();

        let mut rendered = vec![
            format!("{authenticated:?}"),
            format!("{authenticated_fingerprint:?}"),
            format!("{:?}", L::Authenticated(authenticated)),
        ];

        rig.put(&state.encode().unwrap());
        let L::Legacy(legacy) = rig.load() else {
            panic!("expected Legacy");
        };
        rendered.push(format!("{legacy:?}"));
        rendered.push(format!("{:?}", L::Legacy(legacy)));

        for load in [
            L::NotConfigured,
            L::LegacyMismatch(BindingMismatch::VaultIdentity),
            L::LegacyMismatch(BindingMismatch::LocalLocator),
            L::LegacyMismatch(BindingMismatch::TargetLocator),
            L::UnauthenticatedExchangeFormat,
            L::NotAuthentic,
            L::BindingMismatch(BindingMismatch::VaultIdentity),
            L::BindingMismatch(BindingMismatch::LocalLocator),
            L::Corrupt(CorruptReason::Empty),
            L::Corrupt(CorruptReason::TooLarge),
            L::Corrupt(CorruptReason::Undecodable),
            L::Corrupt(CorruptReason::LocatorMismatch),
            L::UnsupportedVersion,
            L::Unreadable(UnreadableReason::Io(std::io::ErrorKind::PermissionDenied)),
            L::Unreadable(UnreadableReason::UnexpectedObject),
            L::Unreadable(UnreadableReason::UnresolvedArtifacts),
            L::Unreadable(UnreadableReason::EntryLimit),
            L::Unavailable(SyncStateUnavailable::LocalLocator),
            L::Unavailable(SyncStateUnavailable::LocalVaultChanged),
            L::Unavailable(SyncStateUnavailable::Root),
            L::KeyUnavailable,
        ] {
            rendered.push(format!("{load:?}"));
        }

        let vault_id = rig.session.data.vault_id;
        let forbidden = [
            rig.dir.path().to_string_lossy().into_owned(),
            rig.vault.to_string_lossy().into_owned(),
            rig.locator().as_str().to_owned(),
            state.target_locator().as_str().to_owned(),
            vault_id.hyphenated().to_string(),
            vault_id.simple().to_string(),
            state.binding_id().uuid().hyphenated().to_string(),
            fingerprint_of(&v3).digest.to_hex(),
            mac,
            ".lvault".to_owned(),
            r"\\?\".to_owned(),
        ];

        for text in &rendered {
            assert!(!has_hex_run(text, 16), "{text}");

            for mark in &forbidden {
                assert!(!text.contains(mark), "{mark} leaked in {text}");
            }
        }
    }

    // ---- isolation ---------------------------------------------------------------

    fn production_half(source: &str) -> &str {
        source.split("#[cfg(all(test, windows))]").next().unwrap()
    }

    fn all_sources(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();

            if path.is_dir() {
                all_sources(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = fs::read_to_string(&path).unwrap();

                found.push((path, text));
            }
        }
    }

    fn tauri_sources() -> Vec<(PathBuf, String)> {
        let mut found = Vec::new();

        all_sources(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut found,
        );

        found
    }

    fn file_name(path: &Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn the_production_half_cannot_write_move_remove_or_derive_anything_else() {
        let production = production_half(include_str!("authenticated_state.rs"));

        // One key derivation, one authenticated decode, and no conditional code.
        assert!(!production.contains("#[cfg("));
        assert_eq!(production.matches("SyncStateMacKey::derive(").count(), 1);
        assert_eq!(
            production
                .matches("AuthenticatedSyncState::decode(")
                .count(),
            1
        );

        for forbidden in [
            concat!("encode_", "authenticated"),
            concat!("decode_", "authenticated"),
            concat!("begin_", "exchange"),
            concat!("finalize_", "exchange"),
            concat!("clear_", "exchange"),
            ".create(",
            ".replace(",
            ".delete(",
            "delete_if_evidence_matches",
            "fs::write",
            "fs::copy",
            "OpenOptions",
            "remove_file",
            "remove_dir",
            "rename",
            "hard_link",
            "create_new",
            "set_len",
            "truncate",
            "write_all",
            "sync_all",
            "unsafe",
            "allow(",
            "getrandom",
            "new_v4",
            "temp_dir",
            "Instant",
            "SystemTime",
            "thread",
            "Command",
        ] {
            assert!(
                !production.contains(forbidden),
                "{forbidden:?} in the production half"
            );
        }

        // The key is derived by a private method and never held in a field.
        assert!(production.contains("    fn sync_state_mac_key(&self)"));
        assert!(!production.contains("pub fn sync_state_mac_key"));
        assert!(!production.contains("pub(crate) fn sync_state_mac_key"));

        // The whole file keeps clear of the two dormant exchange modules.
        let whole = include_str!("authenticated_state.rs");

        assert!(!whole.contains(concat!("exchange_", "recovery")));
        assert!(!whole.contains(concat!("target_", "exchange")));
    }

    #[test]
    fn nothing_but_the_module_reaches_the_loader_or_the_raw_reader() {
        let sources = tauri_sources();

        let mut loaders: Vec<String> = sources
            .iter()
            .filter(|(_, text)| text.contains("load_authenticated_sync_state"))
            .map(|(path, _)| file_name(path))
            .collect();
        loaders.sort();
        assert_eq!(loaders, ["authenticated_state.rs"]);

        let mut readers: Vec<String> = sources
            .iter()
            .filter(|(_, text)| text.contains("read_record("))
            .map(|(path, _)| file_name(path))
            .collect();
        readers.sort();
        assert_eq!(readers, ["authenticated_state.rs", "sync_state_store.rs"]);

        // Neither the application state nor any command knows the new types.
        for (path, text) in &sources {
            let name = file_name(path);
            let in_commands = path
                .components()
                .any(|component| component.as_os_str() == "commands");

            if name == "app_state.rs" || name == "lib.rs" || in_commands {
                for word in [
                    "AuthenticatedStateLoad",
                    "StoredAuthenticatedRecord",
                    "LegacyRecord",
                    "RecordFingerprint",
                    "RecordRead",
                    "PresentRecord",
                    "ArtifactPresence",
                    "authenticated_state",
                    "read_record",
                ] {
                    assert!(!text.contains(word), "{name} mentions {word}");
                }
            }
        }

        // Only the declaration and the module itself name the module.
        let mut modules: Vec<String> = sources
            .iter()
            .filter(|(_, text)| text.contains("authenticated_state"))
            .map(|(path, _)| file_name(path))
            .collect();
        modules.sort();
        assert_eq!(modules, ["authenticated_state.rs", "session.rs"]);

        let session = sources
            .iter()
            .find(|(path, _)| file_name(path) == "session.rs")
            .unwrap();

        // Private, unconditional declaration; the key type never appears there.
        assert!(session.1.starts_with("mod authenticated_state;"));
        assert!(!session.1.contains("pub mod authenticated_state"));
        assert!(!session.1.contains("SyncStateMacKey"));

        // No frontend file knows about it.
        let frontend = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("src");

        for extension in ["ts", "tsx"] {
            fn walk(dir: &Path, extension: &str) {
                for entry in fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();

                    if path.is_dir() {
                        walk(&path, extension);
                    } else if path.extension().is_some_and(|ext| ext == extension) {
                        let text = fs::read_to_string(&path).unwrap();

                        assert!(
                            !text.contains("authenticated_sync_state")
                                && !text.contains("AuthenticatedStateLoad"),
                            "{}",
                            path.display()
                        );
                    }
                }
            }

            walk(&frontend, extension);
        }
    }

    #[test]
    fn the_scratch_base_is_under_the_repository_and_never_the_temp_directory() {
        let dir = scratch("scratch-base");

        assert!(!dir.path().starts_with(std::env::temp_dir()));
        assert!(dir
            .path()
            .components()
            .any(|part| { part.as_os_str() == "sync-state-b3c3a-tests" }));
    }
}

// ---- layout assessment tests (Stage 1U-4 B3c-3b-1) ---------------------------

/// Tests of [`UnlockedVaultSession::assess_authenticated_sync_state`] over real
/// sessions, real MACs and real NTFS layouts. Synthetic vaults only; every test
/// owns a uniquely named scratch directory under the git-ignored
/// `<repo>/.qa-local/sync-state-b3c3b1-tests/` (never `%TEMP%`) and removes only
/// that directory. The assessment is read-only: every no-mutation proof builds a
/// stable fixture, snapshots the whole scratch tree, calls **only** the
/// assessment, and requires the same snapshot. The concurrency test changes the
/// tree on purpose and so asserts safe outcomes, never whole-tree equality.
#[cfg(all(test, windows))]
mod assessment_tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };

    use uuid::Uuid;
    use zeroize::Zeroizing;

    use localvault_core::{
        sync::{PushBaseline, PushIntent, RemoteHighWater},
        sync_state::{
            BindingId, ExchangeIntent, ExchangeScheme, ObjectAnchor, PendingPush, SyncBase,
            SyncCheckpoint, VaultBindingTag, BINDING_SALT_LEN, MAX_SYNC_STATE_BYTES,
        },
    };

    use super::*;
    use crate::vault::{
        handle_ops::test_support::{assert_local_ntfs, make_junction, snapshot},
        session::{InitialBindingApproval, InitialBindingOutcome},
        sync_file_adapter::SyncFileTarget,
        sync_state_store::SYNC_STATE_DIRECTORY,
    };

    const NOW_MS: i64 = 1_700_000_000_000;
    const MASTER_PASSWORD: &str = "b3c3b1-master-password-test-only";
    const NEW_PASSWORD: &str = "b3c3b1-new-master-password-test-only";
    const OTHER_LOCAL: &str = r"\\?\C:\Synthetic\Vaults\OTHER-MARKER.lvault";
    const TARGET: &str = r"\\?\D:\Synthetic\Remote\TARGET-MARKER.lvault";
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const RETIRED_TOKEN: &str = "fedcba9876543210fedcba9876543210";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(MASTER_PASSWORD.to_owned())
    }

    /// A unique, test-owned directory under the B3c-3b-1 scratch base, never
    /// `%TEMP%`. Removed only by its `TempDir` guard. Fails loudly unless on a
    /// local NTFS volume.
    fn scratch(name: &str) -> tempfile::TempDir {
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
        assert_local_ntfs(dir.path());

        dir
    }

    fn new_session(path: &Path) -> UnlockedVaultSession {
        UnlockedVaultSession::create(path, password(), NOW_MS).unwrap()
    }

    fn mac_key(session: &UnlockedVaultSession) -> SyncStateMacKey {
        SyncStateMacKey::derive(&session.vault_key, session.data.vault_id).unwrap()
    }

    fn v3_of(session: &UnlockedVaultSession, state: &SyncState) -> Vec<u8> {
        state.encode_authenticated(&mac_key(session)).unwrap()
    }

    /// The record key, recomputed independently of the store's own helper.
    fn key_of(locator: &Locator) -> String {
        EnvelopeFingerprint::of_bytes(locator.as_str().to_ascii_lowercase().as_bytes()).to_hex()
    }

    fn state_for(vault_id: Uuid, local: &Locator, high_water: u64) -> SyncState {
        let salt: [u8; BINDING_SALT_LEN] = std::array::from_fn(|i| i as u8);
        let checkpoint = SyncCheckpoint::new(
            EnvelopeFingerprint::of_bytes(&[1]),
            1,
            RemoteHighWater::new(high_water),
        )
        .unwrap();

        SyncState::new(
            BindingId::new(Uuid::from_u128(0xB3C3B1)).unwrap(),
            VaultBindingTag::derive(salt, vault_id).unwrap(),
            local.clone(),
            Locator::new(TARGET).unwrap(),
            SyncBase::Based(checkpoint),
            None,
        )
        .unwrap()
    }

    /// The byte right after `marker`, turned into a different hex digit.
    fn flip_hex_after(bytes: &[u8], marker: &str) -> Vec<u8> {
        let text = std::str::from_utf8(bytes).unwrap();
        let at = text.find(marker).expect("marker present") + marker.len();

        let mut out = bytes.to_vec();
        out[at] = if out[at] == b'0' { b'1' } else { b'0' };
        out
    }

    /// One lowercase letter inside the `body` string changed to another letter, so
    /// the wrapper stays canonical and only the MAC can notice.
    fn change_a_body_letter(bytes: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(bytes).unwrap();
        let start = text.find("\"body\":\"").expect("body present") + "\"body\":\"".len();

        let mut out = bytes.to_vec();
        let at = start
            + out[start..]
                .iter()
                .position(u8::is_ascii_lowercase)
                .expect("a letter in the body");
        out[at] = if out[at] == b'a' { b'b' } else { b'a' };
        out
    }

    /// A synthetic vault and an application root, inside one scratch tree.
    /// `session` is declared first so that it (and its exclusive lock file) drops
    /// before the scratch directory is removed.
    struct Rig {
        session: UnlockedVaultSession,
        root: SyncStateRoot,
        vault: PathBuf,
        dir: tempfile::TempDir,
    }

    impl Rig {
        fn new(name: &str) -> Self {
            let dir = scratch(name);
            let vaults = dir.path().join("vaults");

            fs::create_dir_all(&vaults).unwrap();

            let vault = vaults.join("vault.lvault");
            let session = new_session(&vault);
            let root = SyncStateRoot::for_test(dir.path().join("app-local"));

            Self {
                session,
                root,
                vault,
                dir,
            }
        }

        /// Bound through the real, unchanged initial-binding operation, which writes
        /// a version-1 record.
        fn bound(name: &str) -> Self {
            let rig = Self::new(name);
            let dest = rig.dir.path().join("dest");

            fs::create_dir_all(&dest).unwrap();

            let copy = dest.join("copy.lvault");
            fs::copy(&rig.vault, &copy).unwrap();

            let target = SyncFileTarget::from_path(&copy).unwrap();

            assert_eq!(
                rig.session.bind_existing_identical_target_in(
                    &rig.store(),
                    &target,
                    InitialBindingApproval::for_test(&target),
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

        fn locator(&self) -> Locator {
            self.session.local_locator().unwrap()
        }

        fn primary_path(&self) -> PathBuf {
            self.state_dir()
                .join(format!("{}.json", key_of(&self.locator())))
        }

        fn staging_path(&self, token: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.{token}.tmp", key_of(&self.locator())))
        }

        fn retired_path(&self, token: &str) -> PathBuf {
            self.state_dir()
                .join(format!("{}.{token}.retired", key_of(&self.locator())))
        }

        fn put(&self, path: &Path, bytes: &[u8]) {
            fs::create_dir_all(self.state_dir()).unwrap();
            fs::write(path, bytes).unwrap();
        }

        fn put_primary(&self, bytes: &[u8]) {
            self.put(&self.primary_path(), bytes);
        }

        /// Remove everything this test put in the state directory.
        fn clear(&self) {
            if self.state_dir().exists() {
                fs::remove_dir_all(self.state_dir()).unwrap();
            }
        }

        /// A state of this vault and location.
        fn mine(&self, high_water: u64) -> SyncState {
            state_for(self.session.data.vault_id, &self.locator(), high_water)
        }

        fn v3(&self, state: &SyncState) -> Vec<u8> {
            v3_of(&self.session, state)
        }

        /// A second, independent vault in the same scratch tree.
        fn foreign(&self) -> UnlockedVaultSession {
            let folder = self.dir.path().join("foreign");

            fs::create_dir_all(&folder).unwrap();

            new_session(&folder.join("foreign.lvault"))
        }

        /// A state with an exchange intent, as the dormant exchange records allow.
        fn exchange_state(&self) -> SyncState {
            let current = self.mine(1);
            let SyncBase::Based(checkpoint) = current.base() else {
                panic!("a based state is required");
            };

            let intent = PushIntent::new(
                PushBaseline::Present(*checkpoint.synced()),
                EnvelopeFingerprint::of_bytes(b"b3c3b1-intended"),
            )
            .unwrap();
            let pending = PendingPush::new(
                Uuid::from_u128(0xE1),
                intent,
                checkpoint.high_water().revision() + 1,
            )
            .unwrap();

            SyncState::new_with_exchange_records(
                current.binding_id(),
                *current.vault_tag(),
                current.local_locator().clone(),
                current.target_locator().clone(),
                *current.base(),
                Some(pending),
                Some(ExchangeIntent::new(
                    ExchangeScheme::RetainAndPublishV1,
                    ObjectAnchor::new(&[1; 8]).unwrap(),
                    ObjectAnchor::new(&[2; 8]).unwrap(),
                )),
                Vec::new(),
            )
            .unwrap()
        }

        /// One assessment of a **stable** fixture: the whole scratch tree (names,
        /// kinds, lengths, times and content hashes; the `.lock` by name only) is
        /// snapshotted before and after, and only the assessment runs in between.
        fn assess(&self) -> StateAssessment {
            self.assess_in(&self.store())
        }

        fn assess_in(&self, store: &SyncStateStore) -> StateAssessment {
            let before = snapshot(self.dir.path());
            let result = self.session.assess_authenticated_sync_state_in(store);

            assert_eq!(
                snapshot(self.dir.path()),
                before,
                "the assessment changed the filesystem"
            );

            result
        }
    }

    fn fingerprint_of(bytes: &[u8]) -> RecordFingerprint {
        RecordFingerprint::of(bytes)
    }

    /// What a classified fixture must come out as.
    #[derive(Clone, Copy, Debug)]
    enum Expect {
        Authenticated,
        Weak(NonAuthoritativePrimary),
    }

    impl Expect {
        fn verdict(self, bytes: &[u8]) -> SiblingVerdict {
            match self {
                Self::Authenticated => {
                    SiblingVerdict::AuthenticatedForVaultAndLocator(fingerprint_of(bytes))
                }
                Self::Weak(class) => class.into(),
            }
        }
    }

    /// Every kind of content the classifier distinguishes, as real bytes.
    fn fixtures(rig: &Rig) -> Vec<(&'static str, Vec<u8>, Expect)> {
        use NonAuthoritativePrimary as Weak;

        let foreign = rig.foreign();
        let vault_id = rig.session.data.vault_id;
        let locator = rig.locator();
        let elsewhere = Locator::new(OTHER_LOCAL).unwrap();
        let own = rig.v3(&rig.mine(1));
        let mine = rig.mine(1);

        // This vault's identity, but another vault's key.
        let wrong_key = SyncStateMacKey::derive(&foreign.vault_key, vault_id).unwrap();

        let mut non_canonical = own.clone();
        non_canonical.push(b' ');

        vec![
            ("own version 3", own.clone(), Expect::Authenticated),
            (
                "version 3 with exchange records",
                rig.v3(&rig.exchange_state()),
                Expect::Authenticated,
            ),
            (
                "version 3 signed by another vault",
                v3_of(&foreign, &state_for(foreign.data.vault_id, &locator, 5)),
                Expect::Weak(Weak::NotAuthentic),
            ),
            (
                "version 3 with the wrong Vault Key",
                mine.encode_authenticated(&wrong_key).unwrap(),
                Expect::Weak(Weak::NotAuthentic),
            ),
            (
                "version 3 with a flipped tag bit",
                flip_hex_after(&own, "\"mac\":\""),
                Expect::Weak(Weak::NotAuthentic),
            ),
            (
                "version 3 with a changed body byte",
                change_a_body_letter(&own),
                Expect::Weak(Weak::NotAuthentic),
            ),
            (
                "version 3 for another location",
                v3_of(&rig.session, &state_for(vault_id, &elsewhere, 5)),
                Expect::Weak(Weak::WrongLocator),
            ),
            (
                "version 3, not canonical",
                non_canonical,
                Expect::Weak(Weak::Corrupt),
            ),
            (
                "version 1",
                mine.encode().unwrap(),
                Expect::Weak(Weak::LegacyV1),
            ),
            (
                "version 1 of another vault",
                state_for(foreign.data.vault_id, &locator, 5)
                    .encode()
                    .unwrap(),
                Expect::Weak(Weak::LegacyBoundElsewhere),
            ),
            (
                "version 1 for another location",
                state_for(vault_id, &elsewhere, 5).encode().unwrap(),
                Expect::Weak(Weak::WrongLocator),
            ),
            (
                "version 2",
                mine.encode_exchange_record().unwrap(),
                Expect::Weak(Weak::UnauthenticatedExchangeFormat),
            ),
            (
                "a future version",
                br#"{"format":"localvault-sync-state","version":4}"#.to_vec(),
                Expect::Weak(Weak::UnsupportedVersion),
            ),
            (
                "junk",
                b"this is not a sync-state record".to_vec(),
                Expect::Weak(Weak::Corrupt),
            ),
            ("empty", Vec::new(), Expect::Weak(Weak::Empty)),
            (
                "larger than the maximum",
                vec![b'a'; MAX_SYNC_STATE_BYTES + 1],
                Expect::Weak(Weak::TooLarge),
            ),
        ]
    }

    fn primary_class_of(assessment: StateAssessment) -> (NonAuthoritativePrimary, SiblingReport) {
        match assessment {
            StateAssessment::PrimaryNotAuthenticated { class, siblings } => (class, siblings),
            other => panic!("expected PrimaryNotAuthenticated, found {other:?}"),
        }
    }

    fn missing_siblings_of(assessment: StateAssessment) -> SiblingReport {
        match assessment {
            StateAssessment::PrimaryMissing { siblings } => siblings,
            other => panic!("expected PrimaryMissing, found {other:?}"),
        }
    }

    fn authenticated_of(
        assessment: StateAssessment,
    ) -> (Box<StoredAuthenticatedRecord>, SiblingReport) {
        match assessment {
            StateAssessment::PrimaryAuthenticatedForVaultAndLocator { record, siblings } => {
                (record, siblings)
            }
            other => panic!("expected an authenticated primary, found {other:?}"),
        }
    }

    // ---- the same classifier for a primary and for a sibling -----------------------

    #[test]
    fn every_content_class_is_the_same_for_a_primary_and_for_a_sibling() {
        let rig = Rig::new("table");

        for (label, bytes, expect) in fixtures(&rig) {
            // As the primary.
            rig.clear();
            rig.put_primary(&bytes);

            match expect {
                Expect::Authenticated => {
                    let (record, siblings) = authenticated_of(rig.assess());

                    assert_eq!(record.fingerprint(), fingerprint_of(&bytes), "{label}");
                    assert_eq!(record.artifacts(), ArtifactPresence::None, "{label}");
                    assert!(siblings.is_empty(), "{label}");
                }
                Expect::Weak(class) => {
                    let (found, siblings) = primary_class_of(rig.assess());

                    assert_eq!(found, class, "{label}");
                    assert!(siblings.is_empty(), "{label}");
                }
            }

            // As a lone staging file, then as a lone retired file: never a primary.
            rig.clear();
            rig.put(&rig.staging_path(TOKEN), &bytes);
            let report = missing_siblings_of(rig.assess());
            assert_eq!(report.staging(), [expect.verdict(&bytes)], "{label}");
            assert!(report.retired().is_empty(), "{label}");

            rig.clear();
            rig.put(&rig.retired_path(RETIRED_TOKEN), &bytes);
            let report = missing_siblings_of(rig.assess());
            assert_eq!(report.retired(), [expect.verdict(&bytes)], "{label}");
            assert!(report.staging().is_empty(), "{label}");
        }
    }

    #[test]
    fn a_sibling_never_changes_how_the_primary_is_classified() {
        let rig = Rig::new("table-beside");
        let own = rig.v3(&rig.mine(1));

        for (label, bytes, expect) in fixtures(&rig) {
            rig.clear();
            rig.put_primary(&own);
            rig.put(&rig.staging_path(TOKEN), &bytes);
            rig.put(&rig.retired_path(RETIRED_TOKEN), &bytes);

            let (record, siblings) = authenticated_of(rig.assess());

            assert_eq!(*record.state(), rig.mine(1), "{label}");
            assert_eq!(record.fingerprint(), fingerprint_of(&own), "{label}");
            assert_eq!(record.artifacts(), ArtifactPresence::Present, "{label}");
            assert_eq!(siblings.staging(), [expect.verdict(&bytes)], "{label}");
            assert_eq!(siblings.retired(), [expect.verdict(&bytes)], "{label}");
        }
    }

    #[test]
    fn every_classifier_outcome_has_its_own_fixed_route() {
        use AuthenticatedStateLoad as Load;
        use NonAuthoritativePrimary as Weak;

        // A record that is MAC-valid under this key but carries another vault's tag
        // cannot be built with the public encoder (it refuses), so the route for that
        // classifier outcome is pinned here instead of through bytes.
        let weak = |load: Load, class: Weak| match judge(load) {
            Judged::Weak(found) => assert_eq!(found, class),
            _ => panic!("expected a weak class"),
        };

        weak(
            Load::BindingMismatch(BindingMismatch::VaultIdentity),
            Weak::BoundToOtherVault,
        );
        weak(
            Load::BindingMismatch(BindingMismatch::LocalLocator),
            Weak::WrongLocator,
        );
        weak(
            Load::BindingMismatch(BindingMismatch::TargetLocator),
            Weak::WrongLocator,
        );
        weak(
            Load::LegacyMismatch(BindingMismatch::VaultIdentity),
            Weak::LegacyBoundElsewhere,
        );
        weak(Load::NotAuthentic, Weak::NotAuthentic);
        weak(
            Load::UnauthenticatedExchangeFormat,
            Weak::UnauthenticatedExchangeFormat,
        );
        weak(Load::UnsupportedVersion, Weak::UnsupportedVersion);
        weak(Load::Corrupt(CorruptReason::Empty), Weak::Empty);
        weak(Load::Corrupt(CorruptReason::TooLarge), Weak::TooLarge);
        weak(Load::Corrupt(CorruptReason::Undecodable), Weak::Corrupt);
        weak(
            Load::Corrupt(CorruptReason::LocatorMismatch),
            Weak::WrongLocator,
        );

        assert!(matches!(
            judge(Load::KeyUnavailable),
            Judged::KeyUnavailable
        ));

        // Outcomes the classifier cannot produce for bytes it was given are never
        // authority.
        for load in [
            Load::NotConfigured,
            Load::Unreadable(UnreadableReason::UnresolvedArtifacts),
            Load::Unavailable(SyncStateUnavailable::Root),
        ] {
            assert!(matches!(judge(load), Judged::Unusable));
        }
    }

    // ---- authenticated layouts ----------------------------------------------------

    #[test]
    fn a_valid_primary_alone_is_authenticated_with_the_exact_fingerprint() {
        let rig = Rig::new("a-primary");
        let state = rig.mine(1);
        let bytes = rig.v3(&state);

        rig.put_primary(&bytes);

        let (record, siblings) = authenticated_of(rig.assess());

        assert_eq!(*record.state(), state);
        assert_eq!(record.fingerprint(), fingerprint_of(&bytes));
        assert_eq!(record.artifacts(), ArtifactPresence::None);
        assert!(siblings.is_empty());
        assert_eq!(siblings.unrecognized(), 0);
    }

    #[test]
    fn a_valid_primary_beside_a_staging_or_a_retired_file_reports_it() {
        let rig = Rig::new("b-and-c");
        let bytes = rig.v3(&rig.mine(1));
        let newer = rig.v3(&rig.mine(7));

        rig.put_primary(&bytes);
        rig.put(&rig.staging_path(TOKEN), &newer);

        let (record, siblings) = authenticated_of(rig.assess());
        assert_eq!(record.artifacts(), ArtifactPresence::Present);
        assert_eq!(
            siblings.staging(),
            [SiblingVerdict::AuthenticatedForVaultAndLocator(
                fingerprint_of(&newer)
            )]
        );
        assert!(siblings.retired().is_empty());

        rig.clear();
        rig.put_primary(&bytes);
        rig.put(&rig.retired_path(RETIRED_TOKEN), b"junk");

        let (record, siblings) = authenticated_of(rig.assess());
        assert_eq!(record.artifacts(), ArtifactPresence::Present);
        assert!(siblings.staging().is_empty());
        assert_eq!(siblings.retired(), [SiblingVerdict::Corrupt]);
    }

    #[test]
    fn a_newer_valid_staging_file_never_replaces_an_older_primary() {
        let rig = Rig::new("primary-wins");
        let older = rig.mine(1);
        let newer = rig.mine(9);

        rig.put_primary(&rig.v3(&older));
        rig.put(&rig.staging_path(TOKEN), &rig.v3(&newer));
        rig.put(&rig.retired_path(RETIRED_TOKEN), &rig.v3(&newer));

        let (record, siblings) = authenticated_of(rig.assess());

        assert_eq!(*record.state(), older);
        assert_ne!(*record.state(), newer);
        assert_eq!(siblings.staging().len(), 1);
        assert_eq!(siblings.retired().len(), 1);

        // And a valid sibling does not rescue a damaged primary either.
        rig.put_primary(b"damaged");
        let (class, siblings) = primary_class_of(rig.assess());

        assert_eq!(class, NonAuthoritativePrimary::Corrupt);
        assert_eq!(siblings.staging().len(), 1);
    }

    #[test]
    fn replay_of_an_older_valid_record_is_not_detected_by_the_assessment() {
        // Documented limit, pinned on purpose: with no external anchor an older,
        // validly authenticated record of the same binding is accepted as the
        // primary. Nothing here detects replay.
        let rig = Rig::new("replay");
        let older = rig.mine(1);
        let newer = rig.mine(9);

        rig.put_primary(&rig.v3(&newer));
        assert_eq!(*authenticated_of(rig.assess()).0.state(), newer);

        rig.put_primary(&rig.v3(&older));
        let (record, _) = authenticated_of(rig.assess());

        assert_eq!(*record.state(), older);
        assert_ne!(*record.state(), newer);
    }

    #[test]
    fn exchange_records_are_classified_and_nothing_is_started_or_changed() {
        let rig = Rig::new("exchange");
        let state = rig.exchange_state();

        assert!(state.has_exchange_records());
        rig.put_primary(&rig.v3(&state));
        rig.put(&rig.staging_path(TOKEN), &rig.v3(&state));

        // `assess` proves the whole tree is unchanged.
        let (record, siblings) = authenticated_of(rig.assess());

        assert_eq!(*record.state(), state);
        assert!(record.state().has_exchange_records());
        assert_eq!(siblings.staging().len(), 1);
    }

    // ---- a missing primary is never absence ---------------------------------------------

    #[test]
    fn no_primary_beside_any_sibling_is_primary_missing_never_absent() {
        let rig = Rig::new("missing");
        let own = rig.v3(&rig.mine(1));

        type Setup = fn(&Rig, &[u8]);

        let cases: [(&str, Setup, usize, usize, usize); 6] = [
            ("staging", |r, b| r.put(&r.staging_path(TOKEN), b), 1, 0, 0),
            (
                "retired",
                |r, b| r.put(&r.retired_path(RETIRED_TOKEN), b),
                0,
                1,
                0,
            ),
            (
                "both",
                |r, b| {
                    r.put(&r.staging_path(TOKEN), b);
                    r.put(&r.retired_path(RETIRED_TOKEN), b);
                },
                1,
                1,
                0,
            ),
            (
                "several retired",
                |r, b| {
                    for index in 0..3 {
                        r.put(&r.retired_path(&format!("{index:032x}")), b);
                    }
                },
                0,
                3,
                0,
            ),
            (
                "only a suspicious key-prefixed name",
                |r, b| {
                    let key = key_of(&r.locator());
                    r.put(&r.state_dir().join(format!("{key}.json.bak")), b);
                },
                0,
                0,
                1,
            ),
            (
                "a misleading retired name",
                |r, b| {
                    let key = key_of(&r.locator());
                    r.put(
                        &r.state_dir()
                            .join(format!("{key}.{RETIRED_TOKEN}.retired.x")),
                        b,
                    );
                },
                0,
                0,
                1,
            ),
        ];

        for (label, setup, staging, retired, unrecognized) in cases {
            rig.clear();
            setup(&rig, &own);

            let assessment = rig.assess();

            assert!(
                !matches!(assessment, StateAssessment::ConfirmedAbsent),
                "{label}"
            );

            let report = missing_siblings_of(assessment);

            assert_eq!(report.staging().len(), staging, "{label}");
            assert_eq!(report.retired().len(), retired, "{label}");
            assert_eq!(report.unrecognized(), unrecognized, "{label}");
            assert!(!report.is_empty(), "{label}");
        }
    }

    #[test]
    fn confirmed_absent_needs_a_complete_clean_observation_and_nothing_else() {
        let rig = Rig::new("absent");

        // No directory at all, and an empty one: confirmed absent, created nothing.
        assert!(matches!(rig.assess(), StateAssessment::ConfirmedAbsent));
        assert!(!rig.state_dir().exists());

        fs::create_dir_all(rig.state_dir()).unwrap();
        assert!(matches!(rig.assess(), StateAssessment::ConfirmedAbsent));

        // Files that belong to another location or to nobody do not count.
        let other = key_of(&Locator::new(OTHER_LOCAL).unwrap());
        rig.put(&rig.state_dir().join(format!("{other}.json")), b"x");
        rig.put(&rig.state_dir().join(format!("{other}.{TOKEN}.tmp")), b"x");
        rig.put(
            &rig.state_dir().join(format!("{other}.{TOKEN}.retired")),
            b"x",
        );
        rig.put(&rig.state_dir().join("notes.txt"), b"x");
        assert!(matches!(rig.assess(), StateAssessment::ConfirmedAbsent));

        // Any one thing of ours makes it something else.
        rig.put(&rig.staging_path(TOKEN), b"x");
        assert!(!matches!(rig.assess(), StateAssessment::ConfirmedAbsent));
    }

    #[test]
    fn an_incomplete_or_unexpected_observation_is_uncertain_never_absent() {
        let rig = Rig::new("uncertain");

        // Too many entries.
        fs::create_dir_all(rig.state_dir()).unwrap();
        for index in 0..=10_000 {
            fs::write(rig.state_dir().join(format!("unrelated-{index}.dat")), b"x").unwrap();
        }
        assert!(matches!(
            rig.assess(),
            StateAssessment::Uncertain(LayoutUncertainty::EntryLimit)
        ));

        // Too many siblings.
        rig.clear();
        for index in 0..17 {
            rig.put(&rig.retired_path(&format!("{index:032x}")), b"r");
        }
        assert!(matches!(
            rig.assess(),
            StateAssessment::Uncertain(LayoutUncertainty::SiblingLimit)
        ));

        // The state directory is a junction (a valid-looking record sits behind it).
        rig.clear();
        let moved = rig.dir.path().join("moved");
        fs::create_dir_all(&moved).unwrap();
        fs::write(
            moved.join(rig.primary_path().file_name().unwrap()),
            rig.v3(&rig.mine(1)),
        )
        .unwrap();
        make_junction(&rig.state_dir(), &moved);
        assert!(matches!(
            rig.assess(),
            StateAssessment::Uncertain(LayoutUncertainty::UnexpectedObject)
        ));

        // An ancestor of the root is a junction.
        let real = rig.dir.path().join("real");
        let link = rig.dir.path().join("link");
        fs::create_dir_all(real.join("app-local").join(SYNC_STATE_DIRECTORY)).unwrap();
        make_junction(&link, &real);
        let through = SyncStateStore::new(&link.join("app-local")).unwrap();
        assert!(matches!(
            rig.assess_in(&through),
            StateAssessment::Uncertain(LayoutUncertainty::UnexpectedObject)
        ));

        // The state directory is a regular file.
        let rig = Rig::new("uncertain-file");
        fs::create_dir_all(rig.root.path()).unwrap();
        fs::write(rig.state_dir(), b"a file").unwrap();
        assert!(matches!(
            rig.assess(),
            StateAssessment::Uncertain(LayoutUncertainty::UnexpectedObject)
        ));
    }

    #[test]
    fn a_directory_in_place_of_the_primary_or_a_sibling_is_reported_and_untouched() {
        let rig = Rig::new("objects");

        fs::create_dir_all(rig.primary_path()).unwrap();
        let (class, siblings) = primary_class_of(rig.assess());
        assert_eq!(class, NonAuthoritativePrimary::UnexpectedObject);
        assert!(siblings.is_empty());

        rig.clear();
        fs::create_dir_all(rig.staging_path(TOKEN)).unwrap();
        let report = missing_siblings_of(rig.assess());
        assert_eq!(report.staging(), [SiblingVerdict::UnexpectedObject]);
    }

    // ---- the session guard ----------------------------------------------------------

    #[test]
    fn a_vault_changed_on_disk_is_unavailable_and_the_store_is_not_consulted() {
        let rig = Rig::new("vault-changed");
        let foreign = rig.foreign();

        // Without a state directory the store would answer "confirmed absent", and
        // that is exactly what must not leak through.
        assert!(!rig.state_dir().exists());
        fs::copy(foreign.path(), &rig.vault).unwrap();

        assert!(matches!(
            rig.session.assess_authenticated_sync_state_in(&rig.store()),
            StateAssessment::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        ));

        fs::remove_file(&rig.vault).unwrap();
        assert!(matches!(
            rig.session.assess_authenticated_sync_state_in(&rig.store()),
            StateAssessment::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        ));

        fs::write(&rig.vault, b"not a vault").unwrap();
        assert!(matches!(
            rig.session.assess_authenticated_sync_state_in(&rig.store()),
            StateAssessment::Unavailable(SyncStateUnavailable::LocalVaultChanged)
        ));

        // The store was never touched.
        assert!(!rig.state_dir().exists());
    }

    #[test]
    fn a_vault_without_a_normalized_location_is_unavailable() {
        let dir = scratch("no-locator");
        let session = new_session(&dir.path().join("vault.bin"));
        let root = SyncStateRoot::for_test(dir.path().join("app-local"));

        assert!(matches!(
            session.assess_authenticated_sync_state(&root),
            StateAssessment::Unavailable(SyncStateUnavailable::LocalLocator)
        ));
        assert!(!dir.path().join("app-local").exists());
    }

    #[test]
    fn a_session_without_a_usable_vault_id_has_no_key_but_absence_needs_none() {
        let mut rig = Rig::new("no-key");
        let own = rig.v3(&rig.mine(1));

        rig.session.data_mut().vault_id = Uuid::nil();

        // Nothing to classify: confirmed absent needs no key.
        assert!(matches!(rig.assess(), StateAssessment::ConfirmedAbsent));

        // A primary or a sibling with bytes cannot be classified without one.
        rig.put_primary(&own);
        assert!(matches!(rig.assess(), StateAssessment::KeyUnavailable));

        rig.clear();
        rig.put(&rig.retired_path(RETIRED_TOKEN), &own);
        assert!(matches!(rig.assess(), StateAssessment::KeyUnavailable));

        // Content that needs no key is still reported as what it is.
        rig.clear();
        rig.put(&rig.retired_path(RETIRED_TOKEN), b"");
        let report = missing_siblings_of(rig.assess());
        assert_eq!(report.retired(), [SiblingVerdict::Empty]);
    }

    // ---- key lifetime ---------------------------------------------------------------

    #[test]
    fn a_master_password_change_and_a_relock_keep_the_verdicts() {
        let mut rig = Rig::new("password-change");
        let bytes = rig.v3(&rig.mine(1));

        rig.put_primary(&bytes);
        rig.put(&rig.staging_path(TOKEN), &bytes);

        let before = authenticated_of(rig.assess()).0.fingerprint();

        rig.session
            .change_master_password(password(), Zeroizing::new(NEW_PASSWORD.to_owned()))
            .unwrap();

        // The same Vault Key was re-wrapped, so the same records still verify.
        let (record, siblings) = authenticated_of(rig.assess());
        assert_eq!(record.fingerprint(), before);
        assert_eq!(
            siblings.staging(),
            [SiblingVerdict::AuthenticatedForVaultAndLocator(before)]
        );

        // And again after a full lock and unlock with the new password.
        let Rig {
            session,
            root,
            vault,
            dir,
        } = rig;

        session.lock();

        let reopened =
            UnlockedVaultSession::unlock(&vault, Zeroizing::new(NEW_PASSWORD.to_owned())).unwrap();

        let (record, siblings) = authenticated_of(reopened.assess_authenticated_sync_state(&root));
        assert_eq!(record.fingerprint(), before);
        assert_eq!(siblings.staging().len(), 1);

        drop(record);
        drop(reopened);
        drop(dir);
    }

    // ---- the existing paths -----------------------------------------------------------

    #[test]
    fn the_existing_reset_refuses_beside_a_retired_file_and_the_assessment_still_sees_it() {
        // B3c-3b-2a: this used to reset the v1 binding and leave the retired file
        // behind (the v1 "blind spot"). The compatibility gate now refuses first, so
        // neither file is removed and the layout is never read as absence.
        let mut rig = Rig::bound("reset-retired");

        // A real version-1 binding, and a retired file beside it.
        rig.put(&rig.retired_path(RETIRED_TOKEN), b"retired bytes");

        let (class, siblings) = primary_class_of(rig.assess());
        assert_eq!(class, NonAuthoritativePrimary::LegacyV1);
        assert_eq!(siblings.retired().len(), 1);

        let primary = fs::read(rig.primary_path()).unwrap();

        assert!(matches!(
            rig.session.prepare_binding_reset(&rig.root),
            Err(crate::vault::session::BindingResetRefusal::UnreadableState(
                UnreadableReason::UnresolvedNewerState
            ))
        ));

        // Both files are untouched, and the assessment still sees the sibling.
        assert_eq!(fs::read(rig.primary_path()).unwrap(), primary);
        assert_eq!(
            fs::read(rig.retired_path(RETIRED_TOKEN)).unwrap(),
            b"retired bytes"
        );

        let (class, siblings) = primary_class_of(rig.assess());
        assert_eq!(class, NonAuthoritativePrimary::LegacyV1);
        assert_eq!(siblings.retired().len(), 1);

        // The explicit loader still returns the primary it holds: it is never
        // reported as not configured.
        assert!(!matches!(
            rig.session.load_authenticated_sync_state(&rig.root),
            AuthenticatedStateLoad::NotConfigured
        ));
    }

    #[test]
    fn a_retired_file_with_the_primary_gone_is_never_absence_for_the_legacy_store_either() {
        // The case the v1 blind spot used to hide: no primary, a retired file.
        let rig = Rig::new("missing-primary-retired");

        rig.put(&rig.retired_path(RETIRED_TOKEN), b"retired bytes");

        // The assessment says so (unchanged) ...
        assert_eq!(missing_siblings_of(rig.assess()).retired().len(), 1);

        // ... and so does the state the legacy store reports: attention, with the
        // retired file untouched, never `NotConfigured`.
        assert_eq!(
            rig.session.load_sync_state(&rig.root),
            crate::vault::session::SessionSyncState::Unreadable(
                UnreadableReason::UnresolvedNewerState
            )
        );
        assert_eq!(
            fs::read(rig.retired_path(RETIRED_TOKEN)).unwrap(),
            b"retired bytes"
        );
    }

    #[test]
    fn a_reserved_staging_name_is_reported_with_the_staging_files_and_never_preferred() {
        // B3c-3b-2a (U9): recognized by name, classified by content like any other
        // staging file, never adopted and never preferred over the primary.
        let rig = Rig::bound("reserved-name");
        let bytes = rig.v3(&rig.mine(1));
        let key = key_of(&rig.locator());

        rig.put(
            &rig.state_dir().join(format!("{key}.{TOKEN}.v3stage")),
            &bytes,
        );

        let (class, siblings) = primary_class_of(rig.assess());

        assert_eq!(class, NonAuthoritativePrimary::LegacyV1);
        assert_eq!(siblings.retired().len(), 0);
        assert_eq!(siblings.unrecognized(), 0);
        assert_eq!(siblings.staging().len(), 1);
        assert!(matches!(
            siblings.staging()[0],
            SiblingVerdict::AuthenticatedForVaultAndLocator(_)
        ));

        // Empty, cut short or malformed: still recognized by its name.
        for body in [&b""[..], &bytes[..bytes.len() / 2], &b"{{"[..]] {
            rig.put(
                &rig.state_dir().join(format!("{key}.{TOKEN}.v3stage")),
                body,
            );

            let (_, siblings) = primary_class_of(rig.assess());

            assert_eq!(siblings.staging().len(), 1);
            assert_eq!(siblings.unrecognized(), 0);
        }
    }

    // ---- determinism and concurrency -------------------------------------------------

    type Summary = (
        &'static str,
        Option<RecordFingerprint>,
        Option<SiblingReport>,
        Option<NonAuthoritativePrimary>,
    );

    fn summary(assessment: &StateAssessment) -> Summary {
        match assessment {
            StateAssessment::ConfirmedAbsent => ("absent", None, None, None),
            StateAssessment::PrimaryAuthenticatedForVaultAndLocator { record, siblings } => (
                "authenticated",
                Some(record.fingerprint()),
                Some(siblings.clone()),
                None,
            ),
            StateAssessment::PrimaryMissing { siblings } => {
                ("missing", None, Some(siblings.clone()), None)
            }
            StateAssessment::PrimaryNotAuthenticated { class, siblings } => (
                "not-authenticated",
                None,
                Some(siblings.clone()),
                Some(*class),
            ),
            StateAssessment::Uncertain(_) => ("uncertain", None, None, None),
            StateAssessment::Unavailable(_) => ("unavailable", None, None, None),
            StateAssessment::KeyUnavailable => ("key", None, None, None),
        }
    }

    #[test]
    fn repeated_assessments_of_a_stable_layout_agree() {
        let rig = Rig::new("determinism");
        let bytes = rig.v3(&rig.mine(1));

        rig.put_primary(&bytes);
        for index in [4usize, 1, 3] {
            rig.put(&rig.retired_path(&format!("{index:032x}")), &bytes);
        }
        rig.put(&rig.staging_path(TOKEN), b"junk");

        let first = summary(&rig.assess());
        let second = summary(&rig.assess());

        assert_eq!(first, second);
        assert_eq!(first.0, "authenticated");

        // Missing primary, too.
        fs::remove_file(rig.primary_path()).unwrap();
        assert_eq!(summary(&rig.assess()), summary(&rig.assess()));
    }

    #[test]
    fn a_staging_file_created_and_removed_concurrently_never_yields_an_unsafe_outcome() {
        // A helper thread churns one staging file while the assessment runs
        // repeatedly. The tree changes on purpose, so this proves no whole-tree
        // equality. It asserts only that every outcome is a safe one: an observation
        // that saw nothing, one that saw exactly the churned file, or "uncertain".
        // The distribution of outcomes depends on scheduling and is not asserted.
        let rig = Rig::new("race");
        let churned = rig.staging_path(TOKEN);
        let stop = Arc::new(AtomicBool::new(false));
        let cycles = Arc::new(AtomicUsize::new(0));

        fs::create_dir_all(rig.state_dir()).unwrap();

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
            match rig.session.assess_authenticated_sync_state_in(&rig.store()) {
                StateAssessment::ConfirmedAbsent => {}
                StateAssessment::PrimaryMissing { siblings } => {
                    assert_eq!(siblings.staging().len(), 1);
                    assert!(siblings.retired().is_empty());
                    assert_eq!(siblings.unrecognized(), 0);
                }
                StateAssessment::Uncertain(
                    LayoutUncertainty::ChangedDuringScan | LayoutUncertainty::Io(_),
                ) => {}
                other => panic!("an unsafe outcome under a sibling race: {other:?}"),
            }
        }

        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();

        assert!(cycles.load(Ordering::SeqCst) > 0, "the race never ran");

        // Once it stops, the observation is complete and stable again.
        let _ = fs::remove_file(&churned);
        assert!(matches!(rig.assess(), StateAssessment::ConfirmedAbsent));
    }

    // ---- redaction -----------------------------------------------------------------

    fn has_hex_run(text: &str, length: usize) -> bool {
        let mut run = 0;

        for c in text.chars() {
            if c.is_ascii_hexdigit() {
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
    fn debug_output_reveals_no_path_locator_identifier_fingerprint_mac_or_token() {
        let rig = Rig::new("redaction");
        let state = rig.mine(1);
        let own = rig.v3(&state);
        let mac = {
            let text = std::str::from_utf8(&own).unwrap();
            let at = text.find("\"mac\":\"").unwrap() + "\"mac\":\"".len();
            text[at..at + 64].to_owned()
        };

        rig.put_primary(&own);
        rig.put(&rig.staging_path(TOKEN), &own);
        rig.put(&rig.retired_path(RETIRED_TOKEN), b"junk");

        let assessment = rig.assess();
        let (record, siblings) = authenticated_of(rig.assess());

        let mut rendered = vec![
            format!("{assessment:?}"),
            format!("{record:?}"),
            format!("{siblings:?}"),
            format!("{:?}", siblings.staging()),
            format!("{:?}", siblings.retired()),
        ];

        for class in [
            NonAuthoritativePrimary::LegacyV1,
            NonAuthoritativePrimary::LegacyBoundElsewhere,
            NonAuthoritativePrimary::UnauthenticatedExchangeFormat,
            NonAuthoritativePrimary::NotAuthentic,
            NonAuthoritativePrimary::BoundToOtherVault,
            NonAuthoritativePrimary::WrongLocator,
            NonAuthoritativePrimary::Corrupt,
            NonAuthoritativePrimary::Empty,
            NonAuthoritativePrimary::TooLarge,
            NonAuthoritativePrimary::UnsupportedVersion,
            NonAuthoritativePrimary::UnexpectedObject,
        ] {
            rendered.push(format!("{class:?}"));
            rendered.push(format!("{:?}", SiblingVerdict::from(class)));
            rendered.push(format!(
                "{:?}",
                StateAssessment::PrimaryNotAuthenticated {
                    class,
                    siblings: siblings.clone()
                }
            ));
        }

        for verdict in [
            SiblingVerdict::AuthenticatedForVaultAndLocator(fingerprint_of(&own)),
            SiblingVerdict::Unreadable,
            SiblingVerdict::Vanished,
        ] {
            rendered.push(format!("{verdict:?}"));
        }

        for reason in [
            LayoutUncertainty::Io(std::io::ErrorKind::PermissionDenied),
            LayoutUncertainty::UnexpectedObject,
            LayoutUncertainty::EntryLimit,
            LayoutUncertainty::SiblingLimit,
            LayoutUncertainty::AliasAmbiguity,
            LayoutUncertainty::ChangedDuringScan,
        ] {
            rendered.push(format!("{:?}", StateAssessment::Uncertain(reason)));
        }

        for other in [
            StateAssessment::ConfirmedAbsent,
            StateAssessment::PrimaryMissing {
                siblings: siblings.clone(),
            },
            StateAssessment::Unavailable(SyncStateUnavailable::LocalLocator),
            StateAssessment::Unavailable(SyncStateUnavailable::LocalVaultChanged),
            StateAssessment::Unavailable(SyncStateUnavailable::Root),
            StateAssessment::KeyUnavailable,
        ] {
            rendered.push(format!("{other:?}"));
        }

        let vault_id = rig.session.data.vault_id;
        let forbidden = [
            rig.dir.path().to_string_lossy().into_owned(),
            rig.vault.to_string_lossy().into_owned(),
            rig.locator().as_str().to_owned(),
            state.target_locator().as_str().to_owned(),
            vault_id.hyphenated().to_string(),
            vault_id.simple().to_string(),
            state.binding_id().uuid().hyphenated().to_string(),
            fingerprint_of(&own).digest.to_hex(),
            key_of(&rig.locator()),
            mac,
            TOKEN.to_owned(),
            RETIRED_TOKEN.to_owned(),
            ".lvault".to_owned(),
            r"\\?\".to_owned(),
            ".json".to_owned(),
            ".tmp".to_owned(),
            ".retired".to_owned(),
        ];

        for text in &rendered {
            assert!(!has_hex_run(text, 16), "{text}");

            for mark in &forbidden {
                assert!(!text.contains(mark.as_str()), "{mark} leaked in {text}");
            }
        }
    }

    // ---- isolation -----------------------------------------------------------------

    fn production_half(source: &str) -> &str {
        source.split("#[cfg(all(test, windows))]").next().unwrap()
    }

    fn all_sources(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();

            if path.is_dir() {
                all_sources(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push((path.clone(), fs::read_to_string(&path).unwrap()));
            }
        }
    }

    fn tauri_sources() -> Vec<(PathBuf, String)> {
        let mut found = Vec::new();

        all_sources(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut found,
        );

        found
    }

    fn file_name(path: &Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    /// Every identifier that follows `fn ` in `source`.
    fn function_names(source: &str) -> Vec<String> {
        source
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
    fn the_production_half_derives_decodes_and_observes_exactly_once_and_cannot_mutate() {
        let production = production_half(include_str!("authenticated_state.rs"));

        // The new assessment adds no key derivation and no decode of its own: it
        // reaches both only through the existing classifier.
        assert_eq!(production.matches("SyncStateMacKey::derive(").count(), 1);
        assert_eq!(
            production
                .matches("AuthenticatedSyncState::decode(")
                .count(),
            1
        );
        assert_eq!(production.matches("fn classify_present(").count(), 1);
        // The load path, the assessment's primary, and the assessment's siblings.
        assert_eq!(production.matches("self.classify_present(").count(), 3);
        assert_eq!(production.matches(".inspect_v3_layout(").count(), 1);
        assert!(!production.contains("#[cfg("));

        // None of the mutating or clock-like tokens, in code or in comments.
        for forbidden in [
            ".create(",
            ".replace(",
            ".delete(",
            "delete_if_evidence_matches",
            "fs::write",
            "fs::copy",
            "OpenOptions",
            "remove_file",
            "remove_dir",
            "rename",
            "hard_link",
            "create_new",
            "set_len",
            "truncate",
            "write_all",
            "sync_all",
            "unsafe",
            "allow(",
            "getrandom",
            "new_v4",
            "temp_dir",
            "Instant",
            "SystemTime",
            "thread",
            "Command",
        ] {
            assert!(
                !production.contains(forbidden),
                "{forbidden:?} in the production half"
            );
        }
    }

    #[test]
    fn no_readiness_permission_or_recovery_accessor_exists() {
        let production = production_half(include_str!("authenticated_state.rs"));
        let store = include_str!("../sync_state_store.rs");
        let start = store
            .find("\n// ---- v3 layout assessment (read-only)")
            .unwrap();
        let end = start
            + store[start..]
                .find("\n// ---- end v3 layout assessment")
                .unwrap();

        let mut names =
            function_names(&production[production.find("// ---- layout assessment").unwrap()..]);
        names.extend(function_names(&store[start..end]));

        assert!(names
            .iter()
            .any(|name| name == "assess_authenticated_sync_state"));
        assert!(names.iter().any(|name| name == "inspect_v3_layout"));

        for name in &names {
            for word in [
                "ready", "clean", "safe", "allow", "permit", "may_", "can_", "authoriz", "adopt",
                "recover", "release", "restore", "write", "delete", "remove", "publish",
                "finalize", "prefer", "approve", "grant",
            ] {
                assert!(!name.contains(word), "{name} looks like a {word} accessor");
            }
        }

        // The assessment value is not an approval, a lock or a token either.
        for text in [production, store] {
            assert!(!text.contains("impl From<StateAssessment>"));
            assert!(!text.contains("impl PartialOrd for StateAssessment"));
        }
    }

    #[test]
    fn nothing_outside_the_store_the_module_and_the_reexport_knows_the_new_apis() {
        let sources = tauri_sources();

        let mut layout_callers: Vec<String> = sources
            .iter()
            .filter(|(_, text)| text.contains("inspect_v3_layout("))
            .map(|(path, _)| file_name(path))
            .collect();
        layout_callers.sort();
        assert_eq!(
            layout_callers,
            ["authenticated_state.rs", "sync_state_store.rs"]
        );

        let mut assessors: Vec<String> = sources
            .iter()
            .filter(|(_, text)| text.contains("assess_authenticated_sync_state"))
            .map(|(path, _)| file_name(path))
            .collect();
        assessors.sort();
        assert_eq!(assessors, ["authenticated_state.rs"]);

        let names = [
            "StateAssessment",
            "SiblingVerdict",
            "SiblingReport",
            "NonAuthoritativePrimary",
            "V3Layout",
            "V3LayoutInspection",
            "LayoutPrimary",
            "LayoutSibling",
            "LayoutUncertainty",
            "SiblingContent",
            "SiblingKind",
            "inspect_v3_layout",
            "recognize_v3_sibling_name",
        ];

        for (path, text) in &sources {
            let name = file_name(path);

            if matches!(
                name.as_str(),
                "authenticated_state.rs" | "sync_state_store.rs"
            ) {
                continue;
            }

            for word in names {
                if name == "session.rs" {
                    // Only the existing re-export mentions the four public types.
                    if !matches!(
                        word,
                        "StateAssessment"
                            | "SiblingVerdict"
                            | "SiblingReport"
                            | "NonAuthoritativePrimary"
                    ) {
                        assert!(!text.contains(word), "session.rs mentions {word}");
                    }
                } else {
                    assert!(!text.contains(word), "{} mentions {word}", path.display());
                }
            }
        }

        // No frontend file knows about it.
        let frontend = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("src");

        fn walk(dir: &Path) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();

                if path.is_dir() {
                    walk(&path);
                } else if path
                    .extension()
                    .is_some_and(|ext| ext == "ts" || ext == "tsx")
                {
                    let text = fs::read_to_string(&path).unwrap();

                    assert!(
                        !text.contains("assess_authenticated_sync_state")
                            && !text.contains("StateAssessment"),
                        "{}",
                        path.display()
                    );
                }
            }
        }

        walk(&frontend);

        // The re-export stays in the one existing declaration.
        let session = sources
            .iter()
            .find(|(path, _)| file_name(path) == "session.rs")
            .unwrap();

        assert!(session.1.starts_with("mod authenticated_state;"));
        assert_eq!(
            session.1.matches("pub use authenticated_state::{").count(),
            1
        );
    }

    #[test]
    fn the_scratch_base_is_the_b3c3b1_directory_and_never_the_temp_directory() {
        let dir = scratch("scratch-base");

        assert!(!dir.path().starts_with(std::env::temp_dir()));
        assert!(dir
            .path()
            .components()
            .any(|part| part.as_os_str() == "sync-state-b3c3b1-tests"));
    }
}
