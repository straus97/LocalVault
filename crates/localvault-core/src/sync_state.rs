//! Pure model, codec and transitions for a per-vault local synchronization
//! binding (Stage 1U-4, slices A1 and A2b).
//!
//! A [`SyncState`] records which local vault file is bound to which remote
//! target, the last successfully synchronized checkpoint and an optional
//! interrupted push. This module *describes, (de)serializes and proposes
//! transitions of* that state. It performs no I/O, no network access, no vault
//! cryptography, reads no clock, generates no randomness (binding ids, tag salts
//! and intent ids are supplied by the caller), mutates no vault data and never
//! persists anything. Persistence belongs to platform storage adapters.
//!
//! # Transitions (slice A2b)
//!
//! The functions in the "Pure transitions" section take the current state (or
//! the load outcome) and authenticated evidence, and return a *proposed* new
//! [`SyncState`], an explicit outcome, or a typed [`TransitionRefusal`]. Nothing
//! they return has happened: the input is never mutated, and a proposal is not a
//! committed checkpoint until a platform adapter has persisted its encoded bytes
//! atomically and read them back. A failed persistence must therefore leave the
//! previous durable state as the source of truth. No transition writes to a
//! remote, retries, or authorizes a pull.
//!
//! Evidence comes only from [`crate::sync`]: a [`BoundInspection`] (a remote
//! envelope authenticated together with the local one, with fingerprints of the
//! exact raw bytes) or a [`LocalSnapshot`] (the local envelope alone). Both
//! carry the vault identity they were authenticated against, so a stored
//! [`VaultBindingTag`] is checked against the evidence itself and never against
//! a separately supplied id; revisions and fingerprints are never accepted as
//! loose numbers.
//!
//! # What the persisted state does not contain
//!
//! No plaintext `vault_id`, master password, Vault Key, decrypted entries, TOTP
//! secrets, device credentials or network tokens. The vault identity is bound
//! through a salted, domain-separated [`VaultBindingTag`].
//!
//! # The checksum is not authentication
//!
//! The serialized form carries a SHA-256 checksum of its body. It detects
//! **accidental corruption only** (truncation, bit rot, a partial write). It is
//! not a MAC: anyone, or any process, able to rewrite the file can change the
//! body and recompute the checksum, and such a state is accepted. Likewise the
//! binding tag does not authenticate the file and does not protect against an
//! actor who can rewrite local application data. The state is **not**
//! tamper-proof and **not** rollback-proof.
//!
//! # Outer wrapper tolerance
//!
//! The checksum covers the exact bytes of the `body` string. The outer wrapper
//! is parsed as ordinary JSON, so insignificant representation changes outside
//! the protected body (whitespace, key order, equivalent string escapes) are
//! deliberately accepted. The body itself must be exactly the canonical
//! encoding this module produces.
//!
//! # Missing is not the same as unreadable or corrupt
//!
//! [`SyncStateLoad::NotConfigured`] may only be reported by a platform storage
//! adapter after it has confirmed that neither a state file nor any relevant
//! recovery artifact exists. Nothing in this module ever infers it: invalid
//! JSON, a bad checksum, truncation, an unsupported version, a permission
//! denial or any read error is never "not configured".
//!
//! # Locators
//!
//! A [`Locator`] is an opaque, validated string compared exactly. The
//! "local differs from target" rule enforced here is structural only: it does
//! **not** prove that two differently written paths or URIs cannot name the
//! same file. Platform adapters must independently reject same-file bindings
//! using safe platform-specific identity checks.
//!
//! # Dormant exchange records (slice B3c-1)
//!
//! A state may additionally carry an [`ExchangeIntent`] (the physical identity
//! of an update target observed when an exchange was recorded) and a bounded
//! list of [`RetainedPrevious`] entries, through
//! [`SyncState::new_with_exchange_records`]. They are encoded only by the
//! explicit version-[`SYNC_STATE_EXCHANGE_VERSION`] codec
//! ([`SyncState::encode_exchange_record`] / [`SyncState::decode_exchange_record`]).
//!
//! This codec is **dormant**: the functions are compiled, public core APIs with
//! no caller in any current production flow. [`SyncState::encode`] refuses a
//! state that has exchange records, and [`SyncState::decode`] and
//! [`SyncStateLoad::from_bytes`] still report any version-2 record as an
//! unsupported version, so the existing storage adapter can neither load nor
//! persist one. The transitions refuse such a state instead of silently
//! dropping its records.
//!
//! The codec is **unauthenticated** (the checksum above is not a MAC) and
//! **policy-neutral**: it decides nothing about message authentication,
//! retention or cleanup. Object anchors are opaque observations and a retained
//! entry only records that a previous version was retained at one instant; both
//! are only ever descriptive, never authority for any action.

use std::fmt;

use data_encoding::HEXLOWER;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::sync::{
    classify, AuthenticatedRevision, BoundInspection, EnvelopeFingerprint, LocalSnapshot,
    PayloadRelation, PushBaseline, PushIntent, PushReconciliation, RemoteHighWater,
    RemoteObservation, SyncClassification,
};

pub const SYNC_STATE_FORMAT: &str = "localvault-sync-state";
pub const SYNC_STATE_VERSION: u32 = 1;
/// Dormant tag of the explicit exchange-record codec
/// ([`SyncState::encode_exchange_record`]). [`SYNC_STATE_VERSION`] stays 1.
/// [`SyncState::decode`] and [`SyncStateLoad::from_bytes`] do not accept it; the
/// persisted version is decided when a later slice enables decoding.
pub const SYNC_STATE_EXCHANGE_VERSION: u32 = 2;
pub const MAX_SYNC_STATE_BYTES: usize = 65_536;
pub const MAX_LOCATOR_BYTES: usize = 4_096;
/// Longest accepted [`ObjectAnchor`], in bytes.
pub const MAX_OBJECT_ANCHOR_BYTES: usize = 64;
/// Most [`RetainedPrevious`] entries one state may carry. A technical size
/// bound of the record, **not** a retention policy.
pub const MAX_RETAINED_PREVIOUS: usize = 8;

/// Length of the caller-supplied salt of a [`VaultBindingTag`].
pub const BINDING_SALT_LEN: usize = 32;

const BINDING_DIGEST_LEN: usize = 32;
const BINDING_TAG_DOMAIN: &[u8] = b"LocalVault/sync-binding-tag/v1";

/// Why a state, or one of its parts, was rejected. Fixed variants only: no
/// locator, identity, salt, digest or deserializer detail is ever carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SyncStateError {
    #[error("binding id must not be nil")]
    NilBindingId,
    #[error("vault id must not be nil")]
    NilVaultId,
    #[error("push intent id must not be nil")]
    NilIntentId,
    #[error("locator must not be empty")]
    EmptyLocator,
    #[error("locator is too long")]
    LocatorTooLong,
    #[error("locator contains a control character")]
    LocatorControlCharacter,
    #[error("local and target locators must differ")]
    IdenticalLocators,
    #[error("synced revision exceeds the remote high-water revision")]
    CheckpointRevisionAboveHighWater,
    #[error("an unbased state requires a pending initial publication")]
    UnbasedRequiresInitialPublication,
    #[error("a pending push from an absent remote requires an unbased state")]
    AbsentBaselineRequiresUnbased,
    #[error("pending push baseline does not match the synced checkpoint")]
    PendingBaselineMismatch,
    #[error("pending push revision must exceed the remote high-water revision")]
    PendingRevisionNotAboveHighWater,
    #[error("pending push intent is invalid")]
    InvalidPushIntent,
    #[error("object anchor must be between 1 and 64 bytes")]
    InvalidObjectAnchor,
    #[error("exchange id must not be nil")]
    NilExchangeId,
    #[error("an exchange intent requires a pending push")]
    ExchangeWithoutPendingPush,
    #[error("an exchange intent requires a based state")]
    ExchangeOnUnbasedState,
    #[error("retained previous versions require a based state")]
    RetainedOnUnbasedState,
    #[error("too many retained previous versions")]
    RetainedLimitExceeded,
    #[error("retained previous versions must have distinct exchange ids")]
    DuplicateRetainedId,
    #[error("a retained previous version must not reuse the pending intent id")]
    RetainedIdIsPendingIntent,
    #[error("a retained previous version must differ from the synced version")]
    RetainedIsSyncedVersion,
    #[error("a retained previous version must have a revision below the synced revision")]
    RetainedRevisionNotBelowSynced,
    #[error("a state with exchange records requires the exchange format")]
    ExchangeRecordsRequireExchangeFormat,
    #[error("a state with exchange records is not supported by this transition")]
    ExchangeRecordsUnsupportedByTransition,
}

/// Which expected value did not match the stored binding. Categories only; the
/// offending values are never reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BindingMismatch {
    #[error("the state is bound to a different vault")]
    VaultIdentity,
    #[error("the state is bound to a different local location")]
    LocalLocator,
    #[error("the state is bound to a different synchronization target")]
    TargetLocator,
}

/// Why [`SyncState::encode`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SyncStateEncodeError {
    #[error("sync state is invalid: {0}")]
    InvalidState(SyncStateError),
    #[error("encoded sync state exceeds the size limit")]
    TooLarge,
    #[error("sync state could not be serialized")]
    Serialization,
}

/// Why [`SyncState::decode`] failed. None of these variants carries input
/// content; raw deserializer messages are discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SyncStateDecodeError {
    #[error("sync state exceeds the size limit")]
    TooLarge,
    #[error("sync state is not a well-formed wrapper")]
    Malformed,
    #[error("unsupported sync state format")]
    UnsupportedFormat,
    #[error("unsupported sync state version")]
    UnsupportedVersion,
    #[error("sync state checksum does not match")]
    ChecksumMismatch,
    #[error("sync state body is malformed")]
    InvalidBody,
    #[error("sync state is inconsistent: {0}")]
    InvalidState(SyncStateError),
}

/// Random per-binding identifier. Non-nil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingId(Uuid);

impl BindingId {
    pub fn new(id: Uuid) -> Result<Self, SyncStateError> {
        if id.is_nil() {
            return Err(SyncStateError::NilBindingId);
        }
        Ok(Self(id))
    }

    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

/// Salted, domain-separated identity tag of a vault:
///
/// `SHA-256("LocalVault/sync-binding-tag/v1" || 0x00 || salt || vault_id bytes)`
///
/// It lets a stored state be checked against an *authenticated* `vault_id`
/// without persisting that id. It is not a MAC and authenticates nothing about
/// the state file. Salt and digest are not shown by `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VaultBindingTag {
    salt: [u8; BINDING_SALT_LEN],
    digest: [u8; BINDING_DIGEST_LEN],
}

impl VaultBindingTag {
    /// Tag for `vault_id` under the caller-supplied `salt`. Randomness is the
    /// caller's responsibility; this crate generates none here.
    pub fn derive(salt: [u8; BINDING_SALT_LEN], vault_id: Uuid) -> Result<Self, SyncStateError> {
        if vault_id.is_nil() {
            return Err(SyncStateError::NilVaultId);
        }
        Ok(Self {
            salt,
            digest: binding_digest(&salt, &vault_id),
        })
    }

    /// Whether this tag was derived from `authenticated_vault_id`. The id must
    /// come from an authenticated vault payload, never from file names or
    /// provider metadata. A nil id never matches.
    pub fn matches_vault(&self, authenticated_vault_id: Uuid) -> bool {
        !authenticated_vault_id.is_nil()
            && binding_digest(&self.salt, &authenticated_vault_id) == self.digest
    }
}

impl fmt::Debug for VaultBindingTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultBindingTag(<redacted>)")
    }
}

fn binding_digest(salt: &[u8; BINDING_SALT_LEN], vault_id: &Uuid) -> [u8; BINDING_DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_TAG_DOMAIN);
    hasher.update([0u8]);
    hasher.update(salt);
    hasher.update(vault_id.as_bytes());
    hasher.finalize().into()
}

/// An opaque local-path or provider-URI string: non-empty, at most
/// [`MAX_LOCATOR_BYTES`] bytes, no control characters, compared exactly. No
/// normalization is performed here; see the module documentation. `Debug`
/// never shows the contents.
#[derive(Clone, PartialEq, Eq)]
pub struct Locator(String);

impl Locator {
    pub fn new(value: &str) -> Result<Self, SyncStateError> {
        validate_locator(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Locator(<redacted>)")
    }
}

fn validate_locator(value: &str) -> Result<(), SyncStateError> {
    if value.is_empty() {
        return Err(SyncStateError::EmptyLocator);
    }
    if value.len() > MAX_LOCATOR_BYTES {
        return Err(SyncStateError::LocatorTooLong);
    }
    if value.chars().any(char::is_control) {
        return Err(SyncStateError::LocatorControlCharacter);
    }
    Ok(())
}

/// The last successful synchronization, in terms of authenticated evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCheckpoint {
    synced: EnvelopeFingerprint,
    synced_revision: u64,
    high_water: RemoteHighWater,
}

impl SyncCheckpoint {
    /// `synced_revision` must not exceed `high_water`: the remote cannot be
    /// trusted to have reached less than what was last synchronized.
    pub fn new(
        synced: EnvelopeFingerprint,
        synced_revision: u64,
        high_water: RemoteHighWater,
    ) -> Result<Self, SyncStateError> {
        let checkpoint = Self {
            synced,
            synced_revision,
            high_water,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    /// Fingerprint of the envelope bytes last synchronized.
    pub fn synced(&self) -> &EnvelopeFingerprint {
        &self.synced
    }

    /// Authenticated revision of the last synchronized payload.
    pub fn synced_revision(&self) -> u64 {
        self.synced_revision
    }

    /// Highest remote revision the caller holds authenticated evidence for.
    pub fn high_water(&self) -> RemoteHighWater {
        self.high_water
    }

    fn validate(&self) -> Result<(), SyncStateError> {
        if self.synced_revision > self.high_water.revision() {
            return Err(SyncStateError::CheckpointRevisionAboveHighWater);
        }
        Ok(())
    }
}

/// Whether a prior successful synchronization is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncBase {
    /// No successful synchronization yet. Valid only together with a pending
    /// initial publication.
    Unbased,
    Based(SyncCheckpoint),
}

/// A recorded, possibly interrupted push, used to reconcile after a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingPush {
    intent_id: Uuid,
    intent: PushIntent,
    intended_revision: u64,
}

impl PendingPush {
    /// `intended_revision` is the authenticated revision of the envelope the
    /// push intends to publish.
    pub fn new(
        intent_id: Uuid,
        intent: PushIntent,
        intended_revision: u64,
    ) -> Result<Self, SyncStateError> {
        let pending = Self {
            intent_id,
            intent,
            intended_revision,
        };
        pending.validate()?;
        Ok(pending)
    }

    pub fn intent_id(&self) -> Uuid {
        self.intent_id
    }

    pub fn intent(&self) -> &PushIntent {
        &self.intent
    }

    pub fn intended_revision(&self) -> u64 {
        self.intended_revision
    }

    fn validate(&self) -> Result<(), SyncStateError> {
        if self.intent_id.is_nil() {
            return Err(SyncStateError::NilIntentId);
        }
        Ok(())
    }
}

/// An opaque, adapter-defined physical identity observed at one instant (for
/// example a volume serial plus a file id): 1 to [`MAX_OBJECT_ANCHOR_BYTES`]
/// bytes. It is **not** authenticated, **not** proof of ownership and **not**
/// authority for any action. `Debug` never shows the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ObjectAnchor(Vec<u8>);

impl ObjectAnchor {
    pub fn new(bytes: &[u8]) -> Result<Self, SyncStateError> {
        if bytes.is_empty() || bytes.len() > MAX_OBJECT_ANCHOR_BYTES {
            return Err(SyncStateError::InvalidObjectAnchor);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ObjectAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObjectAnchor(<redacted>)")
    }
}

/// How an exchange publishes a new target version.
///
/// Artifact names are derived, never stored:
/// `"." + leaf + ".localvault-update-<id>.tmp"` and
/// `"." + leaf + ".localvault-previous-<id>.lvprev"`, where `<id>` is the
/// pending intent id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeScheme {
    /// Wire name `retain_and_publish_v1`.
    RetainAndPublishV1,
}

impl ExchangeScheme {
    fn wire_name(self) -> &'static str {
        match self {
            Self::RetainAndPublishV1 => "retain_and_publish_v1",
        }
    }

    fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "retain_and_publish_v1" => Some(Self::RetainAndPublishV1),
            _ => None,
        }
    }
}

/// The physical identities observed when an exchange was recorded, attached to
/// a pending push. Descriptive only: the anchors are unauthenticated
/// observations and never authority. `Debug` does not print anchor bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeIntent {
    scheme: ExchangeScheme,
    target_anchor: ObjectAnchor,
    directory_anchor: ObjectAnchor,
}

impl ExchangeIntent {
    pub fn new(
        scheme: ExchangeScheme,
        target_anchor: ObjectAnchor,
        directory_anchor: ObjectAnchor,
    ) -> Self {
        Self {
            scheme,
            target_anchor,
            directory_anchor,
        }
    }

    pub fn scheme(&self) -> ExchangeScheme {
        self.scheme
    }

    pub fn target_anchor(&self) -> &ObjectAnchor {
        &self.target_anchor
    }

    pub fn directory_anchor(&self) -> &ObjectAnchor {
        &self.directory_anchor
    }
}

/// A record that a previous version was retained at one instant. It is **not**
/// a guarantee that the version is still present, readable, durable or held by
/// any cloud provider. `Debug` does not print anchor bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedPrevious {
    exchange_id: Uuid,
    fingerprint: EnvelopeFingerprint,
    revision: u64,
    object_anchor: ObjectAnchor,
    directory_anchor: ObjectAnchor,
}

impl RetainedPrevious {
    pub fn new(
        exchange_id: Uuid,
        fingerprint: EnvelopeFingerprint,
        revision: u64,
        object_anchor: ObjectAnchor,
        directory_anchor: ObjectAnchor,
    ) -> Result<Self, SyncStateError> {
        if exchange_id.is_nil() {
            return Err(SyncStateError::NilExchangeId);
        }
        Ok(Self {
            exchange_id,
            fingerprint,
            revision,
            object_anchor,
            directory_anchor,
        })
    }

    pub fn exchange_id(&self) -> Uuid {
        self.exchange_id
    }

    pub fn fingerprint(&self) -> &EnvelopeFingerprint {
        &self.fingerprint
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn object_anchor(&self) -> &ObjectAnchor {
        &self.object_anchor
    }

    pub fn directory_anchor(&self) -> &ObjectAnchor {
        &self.directory_anchor
    }
}

/// The persistent local binding of one vault to one synchronization target.
///
/// Fields are private; every instance has passed [`SyncState::new`] (or a
/// full decode), which enforce all invariants:
///
/// 1. non-nil binding and intent ids;
/// 2. valid locators, and local and target locators not identical;
/// 3. a checkpoint's `synced_revision` does not exceed its `high_water`;
/// 4. an unbased state carries a pending push from a confirmed-absent remote;
/// 5. a pending push from an absent remote exists only in an unbased state;
/// 6. in a based state a pending push starts from exactly the synced
///    fingerprint and intends a revision above `high_water`.
///
/// The dormant exchange records of [`SyncState::new_with_exchange_records`]
/// (module documentation) add, and [`SyncState::new`] never produces them:
///
/// 7. an exchange intent requires a pending push;
/// 8. an exchange intent requires a based state;
/// 9. retained previous versions require a based state;
/// 10. at most [`MAX_RETAINED_PREVIOUS`] retained entries;
/// 11. retained exchange ids are pairwise distinct;
/// 12. no retained exchange id equals the pending intent id;
/// 13. no retained fingerprint equals the synced fingerprint;
/// 14. every retained revision is below the synced revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    binding_id: BindingId,
    vault_tag: VaultBindingTag,
    local_locator: Locator,
    target_locator: Locator,
    base: SyncBase,
    pending_push: Option<PendingPush>,
    exchange: Option<ExchangeIntent>,
    retained: Vec<RetainedPrevious>,
}

impl SyncState {
    pub fn new(
        binding_id: BindingId,
        vault_tag: VaultBindingTag,
        local_locator: Locator,
        target_locator: Locator,
        base: SyncBase,
        pending_push: Option<PendingPush>,
    ) -> Result<Self, SyncStateError> {
        let state = Self {
            binding_id,
            vault_tag,
            local_locator,
            target_locator,
            base,
            pending_push,
            exchange: None,
            retained: Vec::new(),
        };
        state.validate()?;
        Ok(state)
    }

    /// Like [`SyncState::new`], additionally carrying the dormant exchange
    /// records. With `None` and an empty list it equals `new`. Such a state is
    /// encoded only by [`SyncState::encode_exchange_record`].
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_exchange_records(
        binding_id: BindingId,
        vault_tag: VaultBindingTag,
        local_locator: Locator,
        target_locator: Locator,
        base: SyncBase,
        pending_push: Option<PendingPush>,
        exchange: Option<ExchangeIntent>,
        retained: Vec<RetainedPrevious>,
    ) -> Result<Self, SyncStateError> {
        let state = Self {
            binding_id,
            vault_tag,
            local_locator,
            target_locator,
            base,
            pending_push,
            exchange,
            retained,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn binding_id(&self) -> BindingId {
        self.binding_id
    }

    pub fn vault_tag(&self) -> &VaultBindingTag {
        &self.vault_tag
    }

    pub fn local_locator(&self) -> &Locator {
        &self.local_locator
    }

    pub fn target_locator(&self) -> &Locator {
        &self.target_locator
    }

    pub fn base(&self) -> &SyncBase {
        &self.base
    }

    pub fn pending_push(&self) -> Option<&PendingPush> {
        self.pending_push.as_ref()
    }

    pub fn exchange_intent(&self) -> Option<&ExchangeIntent> {
        self.exchange.as_ref()
    }

    pub fn retained_previous(&self) -> &[RetainedPrevious] {
        &self.retained
    }

    /// Whether the state carries an exchange intent or any retained previous
    /// version. Such a state is refused by [`SyncState::encode`] and by every
    /// transition in this module.
    pub fn has_exchange_records(&self) -> bool {
        self.exchange.is_some() || !self.retained.is_empty()
    }

    /// Read-only check that this state is bound to the authenticated vault and
    /// to exactly the expected locators (exact string comparison; adapters
    /// pass already-normalized locators). Reports the first mismatching
    /// category and never the values.
    pub fn verify_binding(
        &self,
        authenticated_vault_id: Uuid,
        expected_local_locator: &Locator,
        expected_target_locator: &Locator,
    ) -> Result<(), BindingMismatch> {
        if !self.vault_tag.matches_vault(authenticated_vault_id) {
            return Err(BindingMismatch::VaultIdentity);
        }
        if &self.local_locator != expected_local_locator {
            return Err(BindingMismatch::LocalLocator);
        }
        if &self.target_locator != expected_target_locator {
            return Err(BindingMismatch::TargetLocator);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), SyncStateError> {
        self.validate_base_invariants()?;
        self.validate_exchange_records()
    }

    /// Invariants 7 to 14. They are checked after invariants 1 to 6 and add no
    /// rule about coexistence of an exchange intent and retained entries.
    fn validate_exchange_records(&self) -> Result<(), SyncStateError> {
        if self.exchange.is_some() {
            if self.pending_push.is_none() {
                return Err(SyncStateError::ExchangeWithoutPendingPush);
            }
            if matches!(self.base, SyncBase::Unbased) {
                return Err(SyncStateError::ExchangeOnUnbasedState);
            }
        }

        if self.retained.is_empty() {
            return Ok(());
        }
        let SyncBase::Based(checkpoint) = &self.base else {
            return Err(SyncStateError::RetainedOnUnbasedState);
        };
        if self.retained.len() > MAX_RETAINED_PREVIOUS {
            return Err(SyncStateError::RetainedLimitExceeded);
        }

        for (index, entry) in self.retained.iter().enumerate() {
            if self.retained[..index]
                .iter()
                .any(|earlier| earlier.exchange_id == entry.exchange_id)
            {
                return Err(SyncStateError::DuplicateRetainedId);
            }
        }
        for entry in &self.retained {
            if let Some(pending) = &self.pending_push {
                if entry.exchange_id == pending.intent_id {
                    return Err(SyncStateError::RetainedIdIsPendingIntent);
                }
            }
            if entry.fingerprint == checkpoint.synced {
                return Err(SyncStateError::RetainedIsSyncedVersion);
            }
            if entry.revision >= checkpoint.synced_revision {
                return Err(SyncStateError::RetainedRevisionNotBelowSynced);
            }
        }
        Ok(())
    }

    fn validate_base_invariants(&self) -> Result<(), SyncStateError> {
        if self.binding_id.0.is_nil() {
            return Err(SyncStateError::NilBindingId);
        }

        validate_locator(&self.local_locator.0)?;
        validate_locator(&self.target_locator.0)?;
        if self.local_locator == self.target_locator {
            return Err(SyncStateError::IdenticalLocators);
        }

        if let SyncBase::Based(checkpoint) = &self.base {
            checkpoint.validate()?;
        }
        if let Some(pending) = &self.pending_push {
            pending.validate()?;
        }

        match (&self.base, &self.pending_push) {
            (SyncBase::Unbased, Some(pending))
                if *pending.intent.baseline() == PushBaseline::Absent =>
            {
                Ok(())
            }
            (SyncBase::Unbased, _) => Err(SyncStateError::UnbasedRequiresInitialPublication),
            (SyncBase::Based(_), None) => Ok(()),
            (SyncBase::Based(checkpoint), Some(pending)) => match pending.intent.baseline() {
                PushBaseline::Absent => Err(SyncStateError::AbsentBaselineRequiresUnbased),
                PushBaseline::Present(from) if *from != checkpoint.synced => {
                    Err(SyncStateError::PendingBaselineMismatch)
                }
                PushBaseline::Present(_)
                    if pending.intended_revision <= checkpoint.high_water.revision() =>
                {
                    Err(SyncStateError::PendingRevisionNotAboveHighWater)
                }
                PushBaseline::Present(_) => Ok(()),
            },
        }
    }

    /// Deterministic, versioned UTF-8 JSON. Revalidates the state first and
    /// enforces [`MAX_SYNC_STATE_BYTES`].
    ///
    /// A state with exchange records is refused
    /// ([`SyncStateError::ExchangeRecordsRequireExchangeFormat`]): version 1
    /// cannot represent them and must never silently drop them. Use
    /// [`encode_exchange_record`](Self::encode_exchange_record).
    pub fn encode(&self) -> Result<Vec<u8>, SyncStateEncodeError> {
        self.validate()
            .map_err(SyncStateEncodeError::InvalidState)?;
        if self.has_exchange_records() {
            return Err(SyncStateEncodeError::InvalidState(
                SyncStateError::ExchangeRecordsRequireExchangeFormat,
            ));
        }

        let body = self.encode_body()?;
        seal_wrapper(SYNC_STATE_VERSION, body)
    }

    /// Strictly decode and fully revalidate. Fails closed: any deviation is an
    /// error, and nothing is silently corrected. See the module documentation
    /// for what the checksum does and does not establish.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncStateDecodeError> {
        let outer = open_wrapper(bytes, SYNC_STATE_VERSION)?;

        let wire: BodyWire =
            serde_json::from_str(&outer.body).map_err(|_| SyncStateDecodeError::InvalidBody)?;
        let state = wire.into_state()?;

        // The body must be exactly the canonical encoding. This rejects
        // anything a lenient parse could have quietly normalized.
        let canonical = state
            .encode_body()
            .map_err(|_| SyncStateDecodeError::InvalidBody)?;
        if canonical != outer.body {
            return Err(SyncStateDecodeError::InvalidBody);
        }

        Ok(state)
    }

    /// Deterministic UTF-8 JSON of the dormant exchange-record format, always
    /// [`SYNC_STATE_EXCHANGE_VERSION`], for any valid state (with or without
    /// exchange records). Revalidates first and enforces
    /// [`MAX_SYNC_STATE_BYTES`]. The checksum is not authentication.
    pub fn encode_exchange_record(&self) -> Result<Vec<u8>, SyncStateEncodeError> {
        self.validate()
            .map_err(SyncStateEncodeError::InvalidState)?;

        let body = self.encode_exchange_body()?;
        seal_wrapper(SYNC_STATE_EXCHANGE_VERSION, body)
    }

    /// Strict inverse of [`encode_exchange_record`](Self::encode_exchange_record),
    /// accepting version [`SYNC_STATE_EXCHANGE_VERSION`] only (a version-1
    /// record is [`SyncStateDecodeError::UnsupportedVersion`] here, and
    /// [`SyncState::decode`] likewise refuses version 2). Same strictness as
    /// [`decode`](Self::decode): canonical body, full revalidation.
    pub fn decode_exchange_record(bytes: &[u8]) -> Result<Self, SyncStateDecodeError> {
        let outer = open_wrapper(bytes, SYNC_STATE_EXCHANGE_VERSION)?;

        let wire: ExchangeBodyWire =
            serde_json::from_str(&outer.body).map_err(|_| SyncStateDecodeError::InvalidBody)?;
        let state = wire.into_state()?;

        let canonical = state
            .encode_exchange_body()
            .map_err(|_| SyncStateDecodeError::InvalidBody)?;
        if canonical != outer.body {
            return Err(SyncStateDecodeError::InvalidBody);
        }

        Ok(state)
    }

    fn encode_body(&self) -> Result<String, SyncStateEncodeError> {
        serde_json::to_string(&BodyWire::from(self))
            .map_err(|_| SyncStateEncodeError::Serialization)
    }

    fn encode_exchange_body(&self) -> Result<String, SyncStateEncodeError> {
        serde_json::to_string(&ExchangeBodyWire::from(self))
            .map_err(|_| SyncStateEncodeError::Serialization)
    }
}

/// Wrap an already-canonical `body` in the checksummed outer wrapper and
/// enforce [`MAX_SYNC_STATE_BYTES`].
fn seal_wrapper(version: u32, body: String) -> Result<Vec<u8>, SyncStateEncodeError> {
    let outer = OuterWire {
        format: SYNC_STATE_FORMAT.to_owned(),
        version,
        body_sha256: HEXLOWER.encode(&Sha256::digest(body.as_bytes())),
        body,
    };

    let bytes = serde_json::to_vec(&outer).map_err(|_| SyncStateEncodeError::Serialization)?;
    if bytes.len() > MAX_SYNC_STATE_BYTES {
        return Err(SyncStateEncodeError::TooLarge);
    }
    Ok(bytes)
}

/// Size gate, lenient format and version routing, strict wrapper parse and
/// checksum comparison, in that order. The body is not looked at.
fn open_wrapper(bytes: &[u8], expected_version: u32) -> Result<OuterWire, SyncStateDecodeError> {
    if bytes.len() > MAX_SYNC_STATE_BYTES {
        return Err(SyncStateDecodeError::TooLarge);
    }

    // Format and version are judged before the rest of the wrapper, so a
    // future version that adds fields is reported as unsupported rather
    // than as corrupt.
    let probe: Probe =
        serde_json::from_slice(bytes).map_err(|_| SyncStateDecodeError::Malformed)?;
    if probe.format != SYNC_STATE_FORMAT {
        return Err(SyncStateDecodeError::UnsupportedFormat);
    }
    if probe.version != u64::from(expected_version) {
        return Err(SyncStateDecodeError::UnsupportedVersion);
    }

    let outer: OuterWire =
        serde_json::from_slice(bytes).map_err(|_| SyncStateDecodeError::Malformed)?;
    let claimed = decode_hex32(&outer.body_sha256).ok_or(SyncStateDecodeError::Malformed)?;
    let actual: [u8; 32] = Sha256::digest(outer.body.as_bytes()).into();
    if claimed != actual {
        return Err(SyncStateDecodeError::ChecksumMismatch);
    }
    Ok(outer)
}

/// Outcome of loading the persisted state of a vault.
///
/// Only a platform storage adapter may produce
/// [`NotConfigured`](Self::NotConfigured) or
/// [`Unreadable`](Self::Unreadable); [`from_bytes`](Self::from_bytes) never
/// does. See the module documentation: absence must be positively confirmed,
/// and every failure to read or decode is something other than absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStateLoad {
    /// No state file and no relevant recovery artifact were confirmed to exist.
    NotConfigured,
    /// The state could not be read (I/O error, permission, ...). Not absence.
    Unreadable,
    /// The bytes were read but are not a valid state. Not absence.
    Corrupt,
    /// A well-formed wrapper of an unsupported version. Not absence.
    UnsupportedVersion,
    /// Boxed only to keep the enum small; the state is an ordinary
    /// [`SyncState`].
    Loaded(Box<SyncState>),
}

impl SyncStateLoad {
    /// Classify bytes that were successfully read. Yields only
    /// [`Loaded`](Self::Loaded), [`Corrupt`](Self::Corrupt) or
    /// [`UnsupportedVersion`](Self::UnsupportedVersion).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match SyncState::decode(bytes) {
            Ok(state) => Self::Loaded(Box::new(state)),
            Err(SyncStateDecodeError::UnsupportedVersion) => Self::UnsupportedVersion,
            Err(_) => Self::Corrupt,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure transitions (Stage 1U-4, slice A2b)
// ---------------------------------------------------------------------------
//
// Every function below is pure and deterministic: it reads its arguments, never
// mutates them, and returns either a proposal or a typed refusal. See the module
// documentation for what a proposal does and does not mean.
//
// What the evidence does and does not establish (applies to every transition):
//
// * A fingerprint proves byte identity only. A revision is a write counter, not
//   a freshness proof, and a revision above the high-water mark does **not**
//   prove that a version descends from another one; the provider is not assumed
//   honest. The high-water mark is trusted only relative to this device's own
//   persisted history and the authenticated observations that fed it.
// * `RemoteEvidence::Absent`, `RemoteObservation::Absent` and
//   `SyncStateLoad::NotConfigured` are *assertions of the platform adapter*. The
//   pure core cannot prove that a file is physically missing: the adapter must
//   have established it with correct error handling (an I/O failure is
//   `Unavailable`, never `Absent`) and must create the remote with no-clobber
//   semantics so that a concurrently created file is never overwritten.
// * Matching locator strings do not prove that two differently written
//   paths/URIs name different physical files; adapters check that themselves.

/// Why a transition was refused.
///
/// Fixed variants only. A refusal never carries (and its `Display`/`Debug`
/// never show) a vault id, locator, path, URI, key, password, ciphertext,
/// plaintext, fingerprint or raw JSON; the nested categories are fixed enums.
/// A refusal changes nothing and authorizes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransitionRefusal {
    #[error("the explicit user approval was withheld")]
    ApprovalWithheld,
    #[error("a synchronization binding already exists; it must be reset explicitly")]
    ExistingBinding,
    #[error("the prior synchronization state could not be established")]
    PriorStateUnknown,
    #[error("the remote exists; it cannot be treated as an initial publication target")]
    RemoteNotAbsent,
    #[error("the remote is absent")]
    RemoteAbsent,
    #[error("the remote disappeared since the last synchronization")]
    RemoteDisappeared,
    #[error("the remote could not be read")]
    RemoteUnavailable,
    #[error("the remote is not byte-identical to the local envelope")]
    RemoteDiffers,
    #[error("the local payload predates the revision counter")]
    LocalUnversioned,
    #[error("the remote payload predates the revision counter")]
    RemoteUnversioned,
    #[error("binding mismatch: {0}")]
    BindingMismatch(BindingMismatch),
    #[error("the state has no synchronized checkpoint")]
    NotBased,
    #[error("the state has no pending push")]
    NoPendingPush,
    #[error("a push is already pending and must be reconciled first")]
    PendingIntentExists,
    #[error("the local envelope has not changed since the last synchronization")]
    NoLocalChanges,
    #[error("the remote changed since the last synchronization")]
    RemoteAhead,
    #[error("local and remote both changed since the last synchronization")]
    Diverged,
    #[error("local and remote both changed to identical bytes")]
    Converged,
    #[error("the local change is only a wrapper or re-encryption change")]
    WrapperChangeBlocked,
    #[error("two different histories claim the same revision")]
    SameRevisionConflict,
    #[error("the relation between local and remote cannot be established")]
    AmbiguousChange,
    #[error("the remote bytes authenticate to a different revision than recorded")]
    BaselineRevisionMismatch,
    #[error("the remote is below the trusted high-water revision")]
    KnownRegression,
    #[error("the local revision is not strictly above the trusted high-water revision")]
    NotStrictlyAboveHighWater,
    #[error("the resulting state is invalid: {0}")]
    InvalidState(SyncStateError),
}

/// Whether the user explicitly approved the binding workflow being proposed.
/// The pure core only checks that the calling workflow obtained it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserApproval {
    Granted,
    Withheld,
}

/// What an adapter established about the remote at one point in time, as input
/// to a transition. Contrast with [`RemoteObservation`], which carries only a
/// fingerprint: `Inspected` carries a [`BoundInspection`], i.e. authenticated
/// evidence bound to the exact raw bytes of both envelopes.
///
/// `Absent` and `Unavailable` are adapter assertions (see the section notes); a
/// read failure must be `Unavailable`, never `Absent`.
#[derive(Debug, Clone, Copy)]
pub enum RemoteEvidence<'a> {
    Absent,
    Unavailable,
    Inspected(&'a BoundInspection),
}

/// Caller-supplied identity material for a **new** binding. Plain parameters,
/// validated when a state is built from them: a nil binding id or identical
/// locators is refused as [`TransitionRefusal::InvalidState`].
///
/// The salt must be fresh randomness from the adapter. No vault id is accepted
/// here: the tag is derived from the vault identity carried by the evidence.
#[derive(Clone)]
pub struct NewBinding<'a> {
    pub binding_id: Uuid,
    pub tag_salt: [u8; BINDING_SALT_LEN],
    pub local_locator: &'a Locator,
    pub target_locator: &'a Locator,
}

// Nothing is printed: the salt and locators are redacted by their own types, and
// the rest adds nothing worth showing.
impl fmt::Debug for NewBinding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewBinding(<redacted>)")
    }
}

/// Result of [`record_remote_observation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HighWaterOutcome {
    /// A newer authenticated remote revision: a proposed state whose only
    /// difference is a higher `high_water`. The synchronized fingerprint and
    /// revision are untouched, and nothing is authorized (no push, no pull).
    Raised(Box<SyncState>),
    /// The observation equals the current mark: nothing to change or persist.
    Unchanged,
    /// The authenticated remote is below the mark: the remote is known to have
    /// held something newer (a replayed or restored older copy, or a lost
    /// write). The mark is **not** lowered and the binding is not reset; this
    /// needs the user's attention.
    KnownRegression,
}

/// Result of [`reconcile_pending_push`]. Every variant is a *proposal or
/// report*; none is an instruction to upload, retry, discard or adopt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushResolution {
    /// The remote holds exactly the intended bytes, with the intended
    /// authenticated revision. One proposed state: the checkpoint advanced to
    /// the intended fingerprint and revision, the high-water mark raised
    /// monotonically, and the pending push cleared, all in one replacement. The
    /// payload revision is not incremented again.
    Finalize {
        intent_id: Uuid,
        state: Box<SyncState>,
    },
    /// The remote still holds the original baseline: a proposed state with the
    /// pending push removed and the checkpoint and high-water mark unchanged.
    ///
    /// This is a snapshot. It does not prove that the provider has no earlier
    /// write still in flight, and it does not authorize a retry: before
    /// applying it the adapter must establish safe quiescence (nothing can
    /// still complete the abandoned write).
    ClearIntent {
        intent_id: Uuid,
        state: Box<SyncState>,
    },
    /// An initial publication whose remote is still absent: propose deleting
    /// the unbased record. The same snapshot and quiescence caveats as
    /// [`ClearIntent`](Self::ClearIntent) apply, and absence must be
    /// re-established by the adapter, not assumed.
    DeleteUnbasedRecord { intent_id: Uuid },
    /// Unreadable, unexpectedly missing, corrupt, a third version, or evidence
    /// that is inconsistent with the recorded intent. The pending push stays,
    /// the checkpoint does not move, no new publication may start, and neither
    /// version is discarded; this needs explicit future user resolution.
    StillPending { intent_id: Uuid },
}

/// Propose the initial binding for a **confirmed-absent** remote: an unbased
/// state holding a pending initial publication from an absent baseline.
///
/// Nothing is written. The adapter must persist the returned state and read it
/// back **before** it attempts the no-clobber creation of the remote, so that a
/// crash between the two leaves a recorded intent to reconcile.
///
/// Requires: explicit approval; `prior` is [`SyncStateLoad::NotConfigured`] (a
/// loaded binding is [`ExistingBinding`](TransitionRefusal::ExistingBinding) and
/// is never silently replaced; `Unreadable`, `Corrupt` and `UnsupportedVersion`
/// are [`PriorStateUnknown`](TransitionRefusal::PriorStateUnknown), never
/// absence); the adapter's assertion `remote == Absent`; and a
/// [`LocalSnapshot`] with a schema-3 counter revision. The pending push records
/// the exact fingerprint and authenticated revision of that snapshot.
pub fn plan_initial_publication(
    prior: &SyncStateLoad,
    approval: UserApproval,
    remote: RemoteObservation,
    local: &LocalSnapshot,
    binding: &NewBinding<'_>,
    intent_id: Uuid,
) -> Result<SyncState, TransitionRefusal> {
    require_approval(approval)?;
    require_not_configured(prior)?;

    match remote {
        RemoteObservation::Absent => {}
        RemoteObservation::Present(_) => return Err(TransitionRefusal::RemoteNotAbsent),
        RemoteObservation::Unavailable => return Err(TransitionRefusal::RemoteUnavailable),
    }

    let revision = counter(local.revision()).ok_or(TransitionRefusal::LocalUnversioned)?;

    let intent = PushIntent::new(PushBaseline::Absent, *local.fingerprint())
        .map_err(|_| invalid(SyncStateError::InvalidPushIntent))?;
    let pending = PendingPush::new(intent_id, intent, revision).map_err(invalid)?;

    new_state(
        binding,
        local.authenticated_vault_id(),
        SyncBase::Unbased,
        Some(pending),
    )
}

/// Propose the initial binding to an **existing remote that is byte-identical**
/// to the local envelope: a based state at the authenticated revision, with the
/// high-water mark starting there and no pending push.
///
/// Requires: explicit approval; `prior` is `NotConfigured` (see
/// [`plan_initial_publication`] for the other load outcomes); inspected
/// evidence whose raw local and remote fingerprints are equal and whose payloads
/// authenticated under the current Vault Key and expected vault identity (that is
/// what a [`BoundInspection`] is); and a schema-3 counter revision. A remote
/// that differs, is absent or unavailable, or a legacy payload is refused. The
/// remote cannot be corrupt or foreign here: such bytes never produce a
/// `BoundInspection`.
pub fn bind_identical_remote(
    prior: &SyncStateLoad,
    approval: UserApproval,
    remote: RemoteEvidence<'_>,
    binding: &NewBinding<'_>,
) -> Result<SyncState, TransitionRefusal> {
    require_approval(approval)?;
    require_not_configured(prior)?;

    let bound = match remote {
        RemoteEvidence::Inspected(bound) => bound,
        RemoteEvidence::Absent => return Err(TransitionRefusal::RemoteAbsent),
        RemoteEvidence::Unavailable => return Err(TransitionRefusal::RemoteUnavailable),
    };

    if bound.local_fingerprint() != bound.candidate_fingerprint() {
        return Err(TransitionRefusal::RemoteDiffers);
    }

    let local_revision =
        counter(bound.inspection().local_revision()).ok_or(TransitionRefusal::LocalUnversioned)?;
    let remote_revision = counter(bound.inspection().candidate_revision())
        .ok_or(TransitionRefusal::RemoteUnversioned)?;

    // Identical bytes authenticate to one revision; anything else is not a
    // state this transition may bind.
    if local_revision != remote_revision {
        return Err(TransitionRefusal::RemoteDiffers);
    }

    let checkpoint = SyncCheckpoint::new(
        *bound.local_fingerprint(),
        local_revision,
        RemoteHighWater::new(local_revision),
    )
    .map_err(invalid)?;

    new_state(
        binding,
        bound.authenticated_vault_id(),
        SyncBase::Based(checkpoint),
        None,
    )
}

/// Record a newly authenticated remote revision against the trusted high-water
/// mark.
///
/// Requires a based state without a pending push (a pending push blocks every
/// observation-based change and is left intact), a verified binding, and a
/// schema-3 remote revision. The mark only ever rises: a higher revision yields
/// [`HighWaterOutcome::Raised`], an equal one [`Unchanged`](HighWaterOutcome::Unchanged),
/// and a lower one reports [`KnownRegression`](HighWaterOutcome::KnownRegression)
/// without lowering anything or resetting the binding.
///
/// Observing a newer remote never moves the synchronized fingerprint or revision
/// and never authorizes an upload or adopting remote data.
pub fn record_remote_observation(
    state: &SyncState,
    expected_local: &Locator,
    expected_target: &Locator,
    observation: &BoundInspection,
) -> Result<HighWaterOutcome, TransitionRefusal> {
    refuse_exchange_records(state)?;
    check_binding(
        state,
        Some(observation.authenticated_vault_id()),
        expected_local,
        expected_target,
    )?;

    let SyncBase::Based(checkpoint) = state.base else {
        return Err(TransitionRefusal::NotBased);
    };

    if state.pending_push.is_some() {
        return Err(TransitionRefusal::PendingIntentExists);
    }

    let observed = counter(observation.inspection().candidate_revision())
        .ok_or(TransitionRefusal::RemoteUnversioned)?;

    let current = checkpoint.high_water.revision();

    match observed.cmp(&current) {
        std::cmp::Ordering::Less => Ok(HighWaterOutcome::KnownRegression),
        std::cmp::Ordering::Equal => Ok(HighWaterOutcome::Unchanged),
        std::cmp::Ordering::Greater => {
            let raised = SyncCheckpoint::new(
                checkpoint.synced,
                checkpoint.synced_revision,
                RemoteHighWater::new(observed.max(current)),
            )
            .map_err(invalid)?;

            let proposed = state
                .with_parts(SyncBase::Based(raised), None)
                .map_err(invalid)?;

            Ok(HighWaterOutcome::Raised(Box::new(proposed)))
        }
    }
}

/// Evaluate whether a new outgoing publication can be prepared and, if so,
/// propose the state that records it as a pending push.
///
/// The returned state is a *durable intent candidate*. Nothing is uploaded. The
/// adapter must persist it atomically, read it back and verify it, repeat the
/// remote stale check, and only then attempt the remote write; any crash leaves
/// the previous durable state as the source of truth, and a pending push blocks
/// every further push until it is explicitly reconciled. There is no automatic
/// retry.
///
/// Accepted only when all of these hold: the binding (verified vault identity
/// from `remote` and both locators) matches; the state is based and has no
/// pending push; both payloads authenticated with schema-3 counters; the remote
/// bytes equal the synchronized fingerprint and authenticate to the recorded
/// synchronized revision; the remote is not below the high-water mark; the local
/// envelope is the only side that changed ([`SyncClassification::LocalAhead`])
/// with a genuine payload change (not a wrapper-only or re-encryption change,
/// not a same-revision conflict); and the authenticated local revision is
/// strictly above the high-water mark.
///
/// A higher revision does **not** prove that the local state descends from the
/// synchronized one. The caller-supplied `intent_id` must be fresh and non-nil.
/// The evidence's own `checkpoint()` comparison is deliberately ignored: it
/// depends on a mark the inspection does not record, so this function compares
/// revisions against the state's own mark.
pub fn begin_push(
    state: &SyncState,
    expected_local: &Locator,
    expected_target: &Locator,
    remote: RemoteEvidence<'_>,
    intent_id: Uuid,
) -> Result<SyncState, TransitionRefusal> {
    refuse_exchange_records(state)?;
    let vault_id = match remote {
        RemoteEvidence::Inspected(bound) => Some(bound.authenticated_vault_id()),
        RemoteEvidence::Absent | RemoteEvidence::Unavailable => None,
    };
    check_binding(state, vault_id, expected_local, expected_target)?;

    let SyncBase::Based(checkpoint) = state.base else {
        return Err(TransitionRefusal::NotBased);
    };

    if state.pending_push.is_some() {
        return Err(TransitionRefusal::PendingIntentExists);
    }

    let bound = match remote {
        RemoteEvidence::Inspected(bound) => bound,
        RemoteEvidence::Absent => return Err(TransitionRefusal::RemoteDisappeared),
        RemoteEvidence::Unavailable => return Err(TransitionRefusal::RemoteUnavailable),
    };

    let inspection = bound.inspection();
    let local_revision =
        counter(inspection.local_revision()).ok_or(TransitionRefusal::LocalUnversioned)?;
    let remote_revision =
        counter(inspection.candidate_revision()).ok_or(TransitionRefusal::RemoteUnversioned)?;

    match classify(
        Some(&checkpoint.synced),
        bound.local_fingerprint(),
        &RemoteObservation::Present(*bound.candidate_fingerprint()),
    ) {
        SyncClassification::LocalAhead => {}
        SyncClassification::InSync => return Err(TransitionRefusal::NoLocalChanges),
        SyncClassification::RemoteAhead => return Err(TransitionRefusal::RemoteAhead),
        SyncClassification::Diverged => return Err(TransitionRefusal::Diverged),
        SyncClassification::Converged => return Err(TransitionRefusal::Converged),
        // Not reachable for a present remote with a recorded baseline.
        _ => return Err(TransitionRefusal::AmbiguousChange),
    }

    // Local differs from the synchronized bytes and the remote still equals
    // them. Distinguish a real payload change from a wrapper/re-encryption one.
    match inspection.payload() {
        PayloadRelation::IdenticalCiphertext
        | PayloadRelation::EquivalentContentDifferentCiphertext => {
            return Err(TransitionRefusal::WrapperChangeBlocked);
        }
        PayloadRelation::SameRevisionDifferentContent => {
            return Err(TransitionRefusal::SameRevisionConflict);
        }
        PayloadRelation::Unordered => return Err(TransitionRefusal::AmbiguousChange),
        PayloadRelation::CandidateLowerRevision | PayloadRelation::CandidateHigherRevision => {}
    }

    if remote_revision != checkpoint.synced_revision {
        return Err(TransitionRefusal::BaselineRevisionMismatch);
    }

    if remote_revision < checkpoint.high_water.revision() {
        return Err(TransitionRefusal::KnownRegression);
    }

    // Also refuses a local payload that is behind the remote.
    if local_revision <= checkpoint.high_water.revision() {
        return Err(TransitionRefusal::NotStrictlyAboveHighWater);
    }

    // After the checks above the local side must be strictly ahead of the
    // remote; anything else is not a state this function may act on.
    if inspection.payload() != PayloadRelation::CandidateLowerRevision {
        return Err(TransitionRefusal::AmbiguousChange);
    }

    let intent = PushIntent::new(
        PushBaseline::Present(checkpoint.synced),
        *bound.local_fingerprint(),
    )
    .map_err(|_| invalid(SyncStateError::InvalidPushIntent))?;
    let pending = PendingPush::new(intent_id, intent, local_revision).map_err(invalid)?;

    state.with_parts(state.base, Some(pending)).map_err(invalid)
}

/// Judge a persisted pending push against a fresh remote observation, using the
/// accepted [`PushIntent::reconcile`] semantics, and propose the matching state
/// change. Nothing is persisted and nothing is retried.
///
/// * **Published**: the remote holds exactly the intended bytes *and* they
///   authenticate to the intended revision → [`PushResolution::Finalize`].
/// * **Not published**: the remote is at the original baseline (still absent, for
///   an initial publication; for a based push, the baseline bytes authenticating
///   to the recorded synchronized revision) → [`PushResolution::ClearIntent`] or
///   [`PushResolution::DeleteUnbasedRecord`]. This is a snapshot only; see those
///   variants for the quiescence the adapter must establish first.
/// * **Anything else** (unreadable, unexpectedly missing, a third version, or
///   inconsistent evidence) → [`PushResolution::StillPending`].
///
/// A [`NoPendingPush`](TransitionRefusal::NoPendingPush) refusal makes a repeated
/// reconciliation of an already-finalized state harmless: the revision is never
/// applied twice. Without inspected evidence (`Absent`/`Unavailable`) only the
/// locators of the binding can be verified.
pub fn reconcile_pending_push(
    state: &SyncState,
    expected_local: &Locator,
    expected_target: &Locator,
    remote: RemoteEvidence<'_>,
) -> Result<PushResolution, TransitionRefusal> {
    refuse_exchange_records(state)?;
    let vault_id = match remote {
        RemoteEvidence::Inspected(bound) => Some(bound.authenticated_vault_id()),
        RemoteEvidence::Absent | RemoteEvidence::Unavailable => None,
    };
    check_binding(state, vault_id, expected_local, expected_target)?;

    let pending = state.pending_push.ok_or(TransitionRefusal::NoPendingPush)?;
    let intent_id = pending.intent_id;
    let still_pending = Ok(PushResolution::StillPending { intent_id });

    let (observed, revision) = match remote {
        RemoteEvidence::Absent => (RemoteObservation::Absent, None),
        RemoteEvidence::Unavailable => (RemoteObservation::Unavailable, None),
        RemoteEvidence::Inspected(bound) => (
            RemoteObservation::Present(*bound.candidate_fingerprint()),
            counter(bound.inspection().candidate_revision()),
        ),
    };

    match pending.intent.reconcile(&observed) {
        PushReconciliation::Published => {
            if revision != Some(pending.intended_revision) {
                return still_pending;
            }

            let previous = match state.base {
                SyncBase::Based(checkpoint) => checkpoint.high_water.revision(),
                SyncBase::Unbased => 0,
            };
            let checkpoint = SyncCheckpoint::new(
                *pending.intent.intended(),
                pending.intended_revision,
                RemoteHighWater::new(previous.max(pending.intended_revision)),
            )
            .map_err(invalid)?;
            let proposed = state
                .with_parts(SyncBase::Based(checkpoint), None)
                .map_err(invalid)?;

            Ok(PushResolution::Finalize {
                intent_id,
                state: Box::new(proposed),
            })
        }
        PushReconciliation::NotPublished => match state.base {
            SyncBase::Unbased => Ok(PushResolution::DeleteUnbasedRecord { intent_id }),
            SyncBase::Based(checkpoint) => {
                if revision != Some(checkpoint.synced_revision) {
                    return still_pending;
                }

                let proposed = state
                    .with_parts(SyncBase::Based(checkpoint), None)
                    .map_err(invalid)?;

                Ok(PushResolution::ClearIntent {
                    intent_id,
                    state: Box::new(proposed),
                })
            }
        },
        PushReconciliation::Unknown => still_pending,
    }
}

impl SyncState {
    /// A copy with a different base and pending push, revalidated by
    /// [`SyncState::new`]. The binding identity and locators are carried over.
    fn with_parts(
        &self,
        base: SyncBase,
        pending_push: Option<PendingPush>,
    ) -> Result<SyncState, SyncStateError> {
        // Defense in depth: this copy has no exchange records, so it must not
        // be built from a state that has some.
        if self.has_exchange_records() {
            return Err(SyncStateError::ExchangeRecordsUnsupportedByTransition);
        }
        SyncState::new(
            self.binding_id,
            self.vault_tag,
            self.local_locator.clone(),
            self.target_locator.clone(),
            base,
            pending_push,
        )
    }
}

fn invalid(error: SyncStateError) -> TransitionRefusal {
    TransitionRefusal::InvalidState(error)
}

/// The transitions of this module build new states without exchange records and
/// must therefore never silently discard an existing intent or retained entry.
fn refuse_exchange_records(state: &SyncState) -> Result<(), TransitionRefusal> {
    if state.has_exchange_records() {
        return Err(invalid(
            SyncStateError::ExchangeRecordsUnsupportedByTransition,
        ));
    }
    Ok(())
}

fn counter(revision: AuthenticatedRevision) -> Option<u64> {
    match revision {
        AuthenticatedRevision::Counter(value) => Some(value),
        AuthenticatedRevision::Unversioned { .. } => None,
    }
}

fn require_approval(approval: UserApproval) -> Result<(), TransitionRefusal> {
    match approval {
        UserApproval::Granted => Ok(()),
        UserApproval::Withheld => Err(TransitionRefusal::ApprovalWithheld),
    }
}

/// Only a confirmed absence of any prior state authorizes an initial binding.
fn require_not_configured(prior: &SyncStateLoad) -> Result<(), TransitionRefusal> {
    match prior {
        SyncStateLoad::NotConfigured => Ok(()),
        SyncStateLoad::Loaded(_) => Err(TransitionRefusal::ExistingBinding),
        SyncStateLoad::Unreadable | SyncStateLoad::Corrupt | SyncStateLoad::UnsupportedVersion => {
            Err(TransitionRefusal::PriorStateUnknown)
        }
    }
}

/// Verify the binding of an existing state. With evidence, the vault tag is
/// checked against the identity the evidence was authenticated for; without it
/// (an absent or unavailable remote) only the locators can be checked.
fn check_binding(
    state: &SyncState,
    authenticated_vault_id: Option<Uuid>,
    expected_local: &Locator,
    expected_target: &Locator,
) -> Result<(), TransitionRefusal> {
    let result = match authenticated_vault_id {
        Some(vault_id) => state.verify_binding(vault_id, expected_local, expected_target),
        None if &state.local_locator != expected_local => Err(BindingMismatch::LocalLocator),
        None if &state.target_locator != expected_target => Err(BindingMismatch::TargetLocator),
        None => Ok(()),
    };

    result.map_err(TransitionRefusal::BindingMismatch)
}

fn new_state(
    binding: &NewBinding<'_>,
    authenticated_vault_id: Uuid,
    base: SyncBase,
    pending_push: Option<PendingPush>,
) -> Result<SyncState, TransitionRefusal> {
    let binding_id = BindingId::new(binding.binding_id).map_err(invalid)?;
    let vault_tag =
        VaultBindingTag::derive(binding.tag_salt, authenticated_vault_id).map_err(invalid)?;

    SyncState::new(
        binding_id,
        vault_tag,
        binding.local_locator.clone(),
        binding.target_locator.clone(),
        base,
        pending_push,
    )
    .map_err(invalid)
}

// ---------------------------------------------------------------------------
// Wire representation (private). Plain data; every value is revalidated when
// converted into the domain types above.
// ---------------------------------------------------------------------------

/// Lenient first pass: only `format` and `version`, unknown fields ignored.
#[derive(Deserialize)]
struct Probe {
    format: String,
    version: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OuterWire {
    format: String,
    version: u32,
    body_sha256: String,
    body: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyWire {
    binding_id: String,
    vault_tag: TagWire,
    local_locator: String,
    target_locator: String,
    base: BaseWire,
    #[serde(deserialize_with = "required_option")]
    pending_push: Option<PendingWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TagWire {
    salt: String,
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum BaseWire {
    Unbased {},
    Based {
        synced: String,
        synced_revision: u64,
        high_water: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingWire {
    intent_id: String,
    baseline: BaselineWire,
    intended: String,
    intended_revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum BaselineWire {
    Absent {},
    Present { fingerprint: String },
}

/// Unlike serde's default for `Option`, a missing key is an error: `null` must
/// be written explicitly.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl From<&SyncState> for BodyWire {
    fn from(state: &SyncState) -> Self {
        Self {
            binding_id: state.binding_id.0.hyphenated().to_string(),
            vault_tag: TagWire {
                salt: HEXLOWER.encode(&state.vault_tag.salt),
                digest: HEXLOWER.encode(&state.vault_tag.digest),
            },
            local_locator: state.local_locator.0.clone(),
            target_locator: state.target_locator.0.clone(),
            base: match &state.base {
                SyncBase::Unbased => BaseWire::Unbased {},
                SyncBase::Based(checkpoint) => BaseWire::Based {
                    synced: checkpoint.synced.to_hex(),
                    synced_revision: checkpoint.synced_revision,
                    high_water: checkpoint.high_water.revision(),
                },
            },
            pending_push: state.pending_push.as_ref().map(|pending| PendingWire {
                intent_id: pending.intent_id.hyphenated().to_string(),
                baseline: match pending.intent.baseline() {
                    PushBaseline::Absent => BaselineWire::Absent {},
                    PushBaseline::Present(fingerprint) => BaselineWire::Present {
                        fingerprint: fingerprint.to_hex(),
                    },
                },
                intended: pending.intent.intended().to_hex(),
                intended_revision: pending.intended_revision,
            }),
        }
    }
}

/// Body of the dormant version-2 record: every [`BodyWire`] field, unchanged
/// and in the same order, plus the two required exchange-record fields.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeBodyWire {
    binding_id: String,
    vault_tag: TagWire,
    local_locator: String,
    target_locator: String,
    base: BaseWire,
    #[serde(deserialize_with = "required_option")]
    pending_push: Option<PendingWire>,
    #[serde(deserialize_with = "required_option")]
    exchange: Option<ExchangeWire>,
    retained_previous: Vec<RetainedWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeWire {
    scheme: String,
    target_anchor: String,
    directory_anchor: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedWire {
    exchange_id: String,
    fingerprint: String,
    revision: u64,
    object_anchor: String,
    directory_anchor: String,
}

impl From<&SyncState> for ExchangeBodyWire {
    fn from(state: &SyncState) -> Self {
        let BodyWire {
            binding_id,
            vault_tag,
            local_locator,
            target_locator,
            base,
            pending_push,
        } = BodyWire::from(state);

        Self {
            binding_id,
            vault_tag,
            local_locator,
            target_locator,
            base,
            pending_push,
            exchange: state.exchange.as_ref().map(|exchange| ExchangeWire {
                scheme: exchange.scheme.wire_name().to_owned(),
                target_anchor: HEXLOWER.encode(&exchange.target_anchor.0),
                directory_anchor: HEXLOWER.encode(&exchange.directory_anchor.0),
            }),
            retained_previous: state
                .retained
                .iter()
                .map(|entry| RetainedWire {
                    exchange_id: entry.exchange_id.hyphenated().to_string(),
                    fingerprint: entry.fingerprint.to_hex(),
                    revision: entry.revision,
                    object_anchor: HEXLOWER.encode(&entry.object_anchor.0),
                    directory_anchor: HEXLOWER.encode(&entry.directory_anchor.0),
                })
                .collect(),
        }
    }
}

impl ExchangeBodyWire {
    fn into_state(self) -> Result<SyncState, SyncStateDecodeError> {
        use SyncStateDecodeError::{InvalidBody, InvalidState};

        let exchange = self
            .exchange
            .map(|wire| -> Result<ExchangeIntent, SyncStateDecodeError> {
                Ok(ExchangeIntent::new(
                    ExchangeScheme::from_wire_name(&wire.scheme).ok_or(InvalidBody)?,
                    decode_anchor(&wire.target_anchor).ok_or(InvalidBody)?,
                    decode_anchor(&wire.directory_anchor).ok_or(InvalidBody)?,
                ))
            })
            .transpose()?;

        let retained = self
            .retained_previous
            .into_iter()
            .map(|wire| {
                RetainedPrevious::new(
                    parse_canonical_uuid(&wire.exchange_id).ok_or(InvalidBody)?,
                    EnvelopeFingerprint::from_hex(&wire.fingerprint).map_err(|_| InvalidBody)?,
                    wire.revision,
                    decode_anchor(&wire.object_anchor).ok_or(InvalidBody)?,
                    decode_anchor(&wire.directory_anchor).ok_or(InvalidBody)?,
                )
                .map_err(InvalidState)
            })
            .collect::<Result<Vec<_>, _>>()?;

        BodyWire {
            binding_id: self.binding_id,
            vault_tag: self.vault_tag,
            local_locator: self.local_locator,
            target_locator: self.target_locator,
            base: self.base,
            pending_push: self.pending_push,
        }
        .into_state_with(exchange, retained)
    }
}

impl BodyWire {
    fn into_state(self) -> Result<SyncState, SyncStateDecodeError> {
        self.into_state_with(None, Vec::new())
    }

    fn into_state_with(
        self,
        exchange: Option<ExchangeIntent>,
        retained: Vec<RetainedPrevious>,
    ) -> Result<SyncState, SyncStateDecodeError> {
        use SyncStateDecodeError::{InvalidBody, InvalidState};

        let binding_id = BindingId::new(parse_canonical_uuid(&self.binding_id).ok_or(InvalidBody)?)
            .map_err(InvalidState)?;

        let vault_tag = VaultBindingTag {
            salt: decode_hex32(&self.vault_tag.salt).ok_or(InvalidBody)?,
            digest: decode_hex32(&self.vault_tag.digest).ok_or(InvalidBody)?,
        };

        let local_locator = Locator::new(&self.local_locator).map_err(InvalidState)?;
        let target_locator = Locator::new(&self.target_locator).map_err(InvalidState)?;

        let base = match self.base {
            BaseWire::Unbased {} => SyncBase::Unbased,
            BaseWire::Based {
                synced,
                synced_revision,
                high_water,
            } => SyncBase::Based(
                SyncCheckpoint::new(
                    EnvelopeFingerprint::from_hex(&synced).map_err(|_| InvalidBody)?,
                    synced_revision,
                    RemoteHighWater::new(high_water),
                )
                .map_err(InvalidState)?,
            ),
        };

        let pending_push = self
            .pending_push
            .map(|pending| {
                let baseline = match pending.baseline {
                    BaselineWire::Absent {} => PushBaseline::Absent,
                    BaselineWire::Present { fingerprint } => PushBaseline::Present(
                        EnvelopeFingerprint::from_hex(&fingerprint).map_err(|_| InvalidBody)?,
                    ),
                };
                let intended =
                    EnvelopeFingerprint::from_hex(&pending.intended).map_err(|_| InvalidBody)?;
                let intent = PushIntent::new(baseline, intended)
                    .map_err(|_| InvalidState(SyncStateError::InvalidPushIntent))?;
                let intent_id = parse_canonical_uuid(&pending.intent_id).ok_or(InvalidBody)?;

                PendingPush::new(intent_id, intent, pending.intended_revision).map_err(InvalidState)
            })
            .transpose()?;

        SyncState::new_with_exchange_records(
            binding_id,
            vault_tag,
            local_locator,
            target_locator,
            base,
            pending_push,
            exchange,
            retained,
        )
        .map_err(InvalidState)
    }
}

/// An anchor as lowercase hexadecimal: even length, 2 to
/// `2 * MAX_OBJECT_ANCHOR_BYTES` characters. Uppercase, odd lengths and any
/// non-hex character are refused.
fn decode_anchor(text: &str) -> Option<ObjectAnchor> {
    if text.len() < 2 || text.len() > 2 * MAX_OBJECT_ANCHOR_BYTES {
        return None;
    }
    let bytes = HEXLOWER.decode(text.as_bytes()).ok()?;
    ObjectAnchor::new(&bytes).ok()
}

/// Exactly 64 lowercase hexadecimal characters.
fn decode_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    HEXLOWER.decode(text.as_bytes()).ok()?.try_into().ok()
}

/// Only the canonical lowercase hyphenated form; `Uuid::parse_str` alone also
/// accepts simple, braced, URN and uppercase spellings.
fn parse_canonical_uuid(text: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(text).ok()?;
    (id.hyphenated().to_string() == text).then_some(id)
}

/// Synthetic values only. No committed fixture is read or modified.
#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &str = "synthetic/local/LOCAL-MARKER.lvault";
    const TARGET: &str = "synthetic/remote/TARGET-MARKER.lvault";
    const OTHER: &str = "synthetic/other/OTHER-MARKER.lvault";

    const VAULT_ID: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    const BINDING: Uuid = Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555);
    const INTENT: Uuid = Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee);

    const INTENT_TEXT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    // ---- builders ----------------------------------------------------------

    fn salt(seed: u8) -> [u8; BINDING_SALT_LEN] {
        std::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    fn fp(tag: u8) -> EnvelopeFingerprint {
        EnvelopeFingerprint::of_bytes(&[tag])
    }

    fn loc(value: &str) -> Locator {
        Locator::new(value).unwrap()
    }

    fn tag() -> VaultBindingTag {
        VaultBindingTag::derive(salt(0), VAULT_ID).unwrap()
    }

    /// Synced revision 7, remote high-water 9.
    fn checkpoint() -> SyncCheckpoint {
        SyncCheckpoint::new(fp(1), 7, RemoteHighWater::new(9)).unwrap()
    }

    fn pending(baseline: PushBaseline, intended: u8, revision: u64) -> PendingPush {
        PendingPush::new(
            INTENT,
            PushIntent::new(baseline, fp(intended)).unwrap(),
            revision,
        )
        .unwrap()
    }

    fn build(
        base: SyncBase,
        pending_push: Option<PendingPush>,
    ) -> Result<SyncState, SyncStateError> {
        SyncState::new(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(LOCAL),
            loc(TARGET),
            base,
            pending_push,
        )
    }

    fn based_state() -> SyncState {
        build(SyncBase::Based(checkpoint()), None).unwrap()
    }

    fn unbased_state() -> SyncState {
        build(SyncBase::Unbased, Some(pending(PushBaseline::Absent, 2, 1))).unwrap()
    }

    fn pending_state() -> SyncState {
        build(
            SyncBase::Based(checkpoint()),
            Some(pending(PushBaseline::Present(fp(1)), 2, 10)),
        )
        .unwrap()
    }

    /// Bypasses every constructor so encode-side revalidation can be exercised.
    fn raw(base: SyncBase, pending_push: Option<PendingPush>) -> SyncState {
        SyncState {
            binding_id: BindingId(BINDING),
            vault_tag: tag(),
            local_locator: Locator(LOCAL.to_owned()),
            target_locator: Locator(TARGET.to_owned()),
            base,
            pending_push,
            exchange: None,
            retained: Vec::new(),
        }
    }

    // ---- wrapper helpers: the "a writer who recomputes the checksum" path ---

    fn checksum_hex(body: &str) -> String {
        HEXLOWER.encode(&Sha256::digest(body.as_bytes()))
    }

    /// A syntactically valid wrapper around an arbitrary body, with a checksum
    /// that matches it. Anyone able to write the file can do exactly this.
    fn forge(body: &str) -> Vec<u8> {
        serde_json::to_vec(&OuterWire {
            format: SYNC_STATE_FORMAT.to_owned(),
            version: SYNC_STATE_VERSION,
            body_sha256: checksum_hex(body),
            body: body.to_owned(),
        })
        .unwrap()
    }

    fn outer_of(bytes: &[u8]) -> OuterWire {
        serde_json::from_slice(bytes).unwrap()
    }

    fn body_of(state: &SyncState) -> String {
        outer_of(&state.encode().unwrap()).body
    }

    fn with_outer(bytes: &[u8], mutate: impl FnOnce(&mut OuterWire)) -> Vec<u8> {
        let mut outer = outer_of(bytes);
        mutate(&mut outer);
        serde_json::to_vec(&outer).unwrap()
    }

    fn replace_once(text: &str, from: &str, to: &str) -> String {
        assert_eq!(text.matches(from).count(), 1, "{from:?} must occur once");
        text.replacen(from, to, 1)
    }

    fn forge_with(mutate: impl FnOnce(&mut BodyWire)) -> Vec<u8> {
        let mut wire = BodyWire::from(&pending_state());
        mutate(&mut wire);
        forge(&serde_json::to_string(&wire).unwrap())
    }

    fn decode_with(mutate: impl FnOnce(&mut BodyWire)) -> Result<SyncState, SyncStateDecodeError> {
        SyncState::decode(&forge_with(mutate))
    }

    fn remove_at(body: &str, parent: &str, key: &str) -> String {
        let mut value: serde_json::Value = serde_json::from_str(body).unwrap();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key)
            .expect("key must exist");
        serde_json::to_string(&value).unwrap()
    }

    fn json(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    type Mutation<'a> = Box<dyn Fn(&mut BodyWire) + 'a>;
    type InvariantCase = (&'static str, fn(&mut BodyWire), SyncStateError);

    // ---- 1-4. round trips and determinism ------------------------------------

    #[test]
    fn based_state_round_trips() {
        let state = based_state();
        let decoded = SyncState::decode(&state.encode().unwrap()).unwrap();

        assert_eq!(decoded, state);
        assert_eq!(decoded.binding_id().uuid(), BINDING);
        assert_eq!(decoded.local_locator().as_str(), LOCAL);
        assert_eq!(decoded.target_locator().as_str(), TARGET);
        assert!(decoded.pending_push().is_none());

        let SyncBase::Based(checkpoint) = decoded.base() else {
            panic!("expected a based state");
        };
        assert_eq!(checkpoint.synced(), &fp(1));
        assert_eq!(checkpoint.synced_revision(), 7);
        assert_eq!(checkpoint.high_water(), RemoteHighWater::new(9));
    }

    #[test]
    fn unbased_initial_publication_round_trips() {
        let state = unbased_state();
        let decoded = SyncState::decode(&state.encode().unwrap()).unwrap();

        assert_eq!(decoded, state);
        assert_eq!(decoded.base(), &SyncBase::Unbased);

        let pending = decoded.pending_push().unwrap();
        assert_eq!(pending.intent_id(), INTENT);
        assert_eq!(pending.intent().baseline(), &PushBaseline::Absent);
        assert_eq!(pending.intent().intended(), &fp(2));
        assert_eq!(pending.intended_revision(), 1);
    }

    #[test]
    fn based_state_with_pending_push_round_trips() {
        let state = pending_state();
        let decoded = SyncState::decode(&state.encode().unwrap()).unwrap();

        assert_eq!(decoded, state);

        let pending = decoded.pending_push().unwrap();
        assert_eq!(pending.intent().baseline(), &PushBaseline::Present(fp(1)));
        assert_eq!(pending.intent().intended(), &fp(2));
        assert_eq!(pending.intended_revision(), 10);
    }

    #[test]
    fn extreme_revisions_round_trip() {
        let checkpoint =
            SyncCheckpoint::new(fp(1), u64::MAX, RemoteHighWater::new(u64::MAX)).unwrap();
        let state = build(SyncBase::Based(checkpoint), None).unwrap();
        assert_eq!(SyncState::decode(&state.encode().unwrap()).unwrap(), state);

        let zero = SyncCheckpoint::new(fp(1), 0, RemoteHighWater::new(0)).unwrap();
        let state = build(SyncBase::Based(zero), None).unwrap();
        assert_eq!(SyncState::decode(&state.encode().unwrap()).unwrap(), state);
    }

    #[test]
    fn encoding_is_deterministic_and_canonical() {
        for state in [based_state(), unbased_state(), pending_state()] {
            let first = state.encode().unwrap();

            assert_eq!(state.encode().unwrap(), first);

            // Re-encoding what was decoded reproduces the exact bytes.
            let decoded = SyncState::decode(&first).unwrap();
            assert_eq!(decoded.encode().unwrap(), first);
        }

        // An independently built, equal state encodes identically.
        assert_eq!(
            pending_state().encode().unwrap(),
            pending_state().encode().unwrap()
        );
    }

    // ---- 5. golden ------------------------------------------------------------

    // Pinned literals. The three SHA-256 values inside them (fingerprints of
    // the single bytes 0x01 and 0x02, the binding-tag digest and the body
    // checksum) were reproduced with an independent SHA-256 implementation
    // over bodies assembled by hand from the format description, not taken
    // from this module's encoder.
    const GOLDEN_PENDING: &str = r#"{"format":"localvault-sync-state","version":1,"body_sha256":"0fea98768af90e8ecc0630d3c7a7615cd294c8aa16aa9a973a5c48f89026d46b","body":"{\"binding_id\":\"11111111-2222-3333-4444-555555555555\",\"vault_tag\":{\"salt\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"digest\":\"533cfabc5ff2073b76dab8c6cb60289e44d95f9dbb67cdbdac12bdcf94025aa8\"},\"local_locator\":\"synthetic/local/LOCAL-MARKER.lvault\",\"target_locator\":\"synthetic/remote/TARGET-MARKER.lvault\",\"base\":{\"kind\":\"based\",\"synced\":\"4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a\",\"synced_revision\":7,\"high_water\":9},\"pending_push\":{\"intent_id\":\"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\",\"baseline\":{\"kind\":\"present\",\"fingerprint\":\"4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a\"},\"intended\":\"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986\",\"intended_revision\":10}}"}"#;

    const GOLDEN_UNBASED: &str = r#"{"format":"localvault-sync-state","version":1,"body_sha256":"c84701b767f9c4f461fe3161543870dbf30b849ebb7a38103718bcd49cd3c3cd","body":"{\"binding_id\":\"11111111-2222-3333-4444-555555555555\",\"vault_tag\":{\"salt\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"digest\":\"533cfabc5ff2073b76dab8c6cb60289e44d95f9dbb67cdbdac12bdcf94025aa8\"},\"local_locator\":\"synthetic/local/LOCAL-MARKER.lvault\",\"target_locator\":\"synthetic/remote/TARGET-MARKER.lvault\",\"base\":{\"kind\":\"unbased\"},\"pending_push\":{\"intent_id\":\"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\",\"baseline\":{\"kind\":\"absent\"},\"intended\":\"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986\",\"intended_revision\":1}}"}"#;

    #[test]
    fn golden_serialization_of_a_synthetic_based_state_with_pending_push() {
        let bytes = pending_state().encode().unwrap();

        assert_eq!(String::from_utf8(bytes.clone()).unwrap(), GOLDEN_PENDING);
        // The pinned bytes themselves must decode back to the same state.
        assert_eq!(
            SyncState::decode(GOLDEN_PENDING.as_bytes()).unwrap(),
            pending_state()
        );
    }

    #[test]
    fn golden_serialization_of_a_synthetic_unbased_state() {
        let bytes = unbased_state().encode().unwrap();

        assert_eq!(String::from_utf8(bytes).unwrap(), GOLDEN_UNBASED);
        assert_eq!(
            SyncState::decode(GOLDEN_UNBASED.as_bytes()).unwrap(),
            unbased_state()
        );
    }

    // ---- 6. truncation --------------------------------------------------------

    #[test]
    fn every_truncation_is_rejected_and_classified_corrupt() {
        let bytes = pending_state().encode().unwrap();

        for length in 0..bytes.len() {
            let prefix = &bytes[..length];

            assert!(
                SyncState::decode(prefix).is_err(),
                "a {length}-byte prefix was accepted"
            );
            assert_eq!(SyncStateLoad::from_bytes(prefix), SyncStateLoad::Corrupt);
        }

        assert!(SyncState::decode(&bytes).is_ok());
    }

    // ---- 7-9. corruption versus tampering --------------------------------------

    #[test]
    fn flipping_any_protected_body_byte_is_a_checksum_mismatch() {
        let bytes = pending_state().encode().unwrap();
        let outer = outer_of(&bytes);
        assert!(outer.body.is_ascii());

        for index in 0..outer.body.len() {
            let mut corrupted = outer.body.clone().into_bytes();
            corrupted[index] ^= 0x01;

            let tampered = serde_json::to_vec(&OuterWire {
                format: outer.format.clone(),
                version: outer.version,
                body_sha256: outer.body_sha256.clone(),
                body: String::from_utf8(corrupted).unwrap(),
            })
            .unwrap();

            assert_eq!(
                SyncState::decode(&tampered).unwrap_err(),
                SyncStateDecodeError::ChecksumMismatch,
                "flip at body byte {index}"
            );
        }
    }

    #[test]
    fn checksum_field_corruption_is_detected() {
        let bytes = pending_state().encode().unwrap();
        let original = outer_of(&bytes).body_sha256;

        // One changed digit.
        let mut digits = original.clone().into_bytes();
        digits[0] = if digits[0] == b'0' { b'1' } else { b'0' };
        let changed = String::from_utf8(digits).unwrap();
        assert_eq!(
            SyncState::decode(&with_outer(&bytes, |o| o.body_sha256 = changed.clone()))
                .unwrap_err(),
            SyncStateDecodeError::ChecksumMismatch
        );

        // Not a canonical 64-character lowercase digest at all.
        let upper = original.to_uppercase();
        assert_ne!(upper, original, "fixture needs hex letters");
        for bad in [
            String::new(),
            original[..63].to_owned(),
            format!("{original}0"),
            upper,
            format!("0x{}", &original[2..]),
            "g".repeat(64),
        ] {
            assert_eq!(
                SyncState::decode(&with_outer(&bytes, |o| o.body_sha256 = bad.clone()))
                    .unwrap_err(),
                SyncStateDecodeError::Malformed,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_recomputed_checksum_is_not_authentication() {
        let original = pending_state();
        let body = body_of(&original);

        // A forged target: the checksum is recomputed, so the file is accepted.
        let forged_body = replace_once(&body, TARGET, "synthetic/remote/FORGED.lvault");
        let forged = SyncState::decode(&forge(&forged_body)).unwrap();

        assert_ne!(forged, original);
        assert_eq!(
            forged.target_locator().as_str(),
            "synthetic/remote/FORGED.lvault"
        );

        // Likewise a lowered high-water mark: the checksum gives no rollback
        // protection. (Without a pending push, so only the checkpoint
        // invariant applies; 7 is the synced revision, the lowest it may go.)
        let based_body = body_of(&based_state());
        let lowered = replace_once(&based_body, "\"high_water\":9", "\"high_water\":7");
        let lowered = SyncState::decode(&forge(&lowered)).unwrap();
        let SyncBase::Based(checkpoint) = lowered.base() else {
            panic!("expected a based state");
        };
        assert_eq!(checkpoint.high_water(), RemoteHighWater::new(7));

        // The checksum only ever detects accidental damage to the exact body.
        assert_eq!(
            checksum_hex(&body),
            outer_of(&original.encode().unwrap()).body_sha256
        );
    }

    // ---- benign representation changes outside the protected body ---------------

    #[test]
    fn benign_outer_representation_changes_are_accepted() {
        let state = pending_state();
        let bytes = state.encode().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();

        let mut leading = b"  \n".to_vec();
        leading.extend_from_slice(&bytes);
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(b"\r\n\t ");

        let pretty = serde_json::to_vec_pretty(&json(&bytes)).unwrap();
        // `serde_json::Value` orders keys alphabetically, so the key order of
        // the outer wrapper differs too.
        let compact_reordered = serde_json::to_vec(&json(&bytes)).unwrap();
        assert_ne!(compact_reordered, bytes);

        // An equivalent string escape inside the (already decoded) body.
        let escaped = replace_once(&text, "\\\"binding_id", "\\\"\\u0062inding_id");
        assert_ne!(escaped.as_bytes(), bytes.as_slice());

        for variant in [
            leading,
            trailing,
            pretty,
            compact_reordered,
            escaped.into_bytes(),
        ] {
            assert_eq!(SyncState::decode(&variant).unwrap(), state);
        }
    }

    #[test]
    fn a_non_canonical_body_is_rejected_even_with_a_valid_checksum() {
        let body = body_of(&pending_state());

        let reordered =
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&body).unwrap())
                .unwrap();
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        )
        .unwrap();
        assert_ne!(reordered, body);

        for non_canonical in [reordered, pretty, format!(" {body}"), format!("{body}\n")] {
            assert_eq!(
                SyncState::decode(&forge(&non_canonical)).unwrap_err(),
                SyncStateDecodeError::InvalidBody
            );
        }
    }

    #[test]
    fn structurally_broken_wrappers_are_malformed() {
        let bytes = pending_state().encode().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();

        let mut with_bom = vec![0xef, 0xbb, 0xbf];
        with_bom.extend_from_slice(&bytes);
        let mut trailing_garbage = bytes.clone();
        trailing_garbage.extend_from_slice(b"x");
        let mut two_documents = bytes.clone();
        two_documents.extend_from_slice(&bytes);
        let mut invalid_utf8 = bytes.clone();
        let body_start = text.find("binding_id").unwrap();
        invalid_utf8[body_start] = 0xff;
        let duplicate_format = replace_once(
            &text,
            "{\"format\":\"localvault-sync-state\"",
            "{\"format\":\"localvault-sync-state\",\"format\":\"localvault-sync-state\"",
        );

        for broken in [
            Vec::new(),
            b"not json".to_vec(),
            b"null".to_vec(),
            b"[]".to_vec(),
            b"{}".to_vec(),
            with_bom,
            trailing_garbage,
            two_documents,
            invalid_utf8,
            duplicate_format.into_bytes(),
        ] {
            assert!(SyncState::decode(&broken).is_err());
            assert_eq!(SyncStateLoad::from_bytes(&broken), SyncStateLoad::Corrupt);
        }
    }

    // ---- 10. format and version -------------------------------------------------

    #[test]
    fn wrong_format_is_rejected() {
        let bytes = pending_state().encode().unwrap();

        for format in [
            "",
            "localvault-vault",
            "LocalVault-Sync-State",
            "localvault-sync-state ",
        ] {
            assert_eq!(
                SyncState::decode(&with_outer(&bytes, |o| o.format = format.to_owned()))
                    .unwrap_err(),
                SyncStateDecodeError::UnsupportedFormat,
                "{format:?}"
            );
        }
    }

    #[test]
    fn unsupported_versions_are_reported_as_such() {
        let bytes = pending_state().encode().unwrap();

        for version in [
            json_number(0),
            json_number(2),
            json_number(1_000),
            serde_json::json!(u64::MAX),
        ] {
            let mut value = json(&bytes);
            value["version"] = version.clone();
            let file = serde_json::to_vec(&value).unwrap();

            assert_eq!(
                SyncState::decode(&file).unwrap_err(),
                SyncStateDecodeError::UnsupportedVersion,
                "{version}"
            );
            assert_eq!(
                SyncStateLoad::from_bytes(&file),
                SyncStateLoad::UnsupportedVersion
            );
        }

        // A future version may add fields and change the body entirely; it is
        // still "unsupported version", not "corrupt".
        let future =
            br#"{"format":"localvault-sync-state","version":2,"anything":[1,2],"body":42}"#;
        assert_eq!(
            SyncState::decode(future).unwrap_err(),
            SyncStateDecodeError::UnsupportedVersion
        );
        assert_eq!(
            SyncStateLoad::from_bytes(future),
            SyncStateLoad::UnsupportedVersion
        );

        // A wrong format outranks the version.
        let foreign = br#"{"format":"other","version":2}"#;
        assert_eq!(
            SyncState::decode(foreign).unwrap_err(),
            SyncStateDecodeError::UnsupportedFormat
        );
    }

    fn json_number(value: u64) -> serde_json::Value {
        serde_json::json!(value)
    }

    #[test]
    fn non_integer_versions_are_malformed() {
        let bytes = pending_state().encode().unwrap();

        for version in [
            serde_json::json!("1"),
            serde_json::json!(-1),
            serde_json::json!(1.0),
            serde_json::json!(1.5),
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!([1]),
        ] {
            let mut value = json(&bytes);
            value["version"] = version.clone();

            assert_eq!(
                SyncState::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
                SyncStateDecodeError::Malformed,
                "{version}"
            );
        }
    }

    // ---- 11. missing and unknown fields -------------------------------------------

    #[test]
    fn missing_or_unknown_outer_fields_are_malformed() {
        let bytes = pending_state().encode().unwrap();

        for key in ["format", "version", "body_sha256", "body"] {
            let mut value = json(&bytes);
            value.as_object_mut().unwrap().remove(key).unwrap();

            assert_eq!(
                SyncState::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
                SyncStateDecodeError::Malformed,
                "missing {key}"
            );
        }

        let mut value = json(&bytes);
        value["extra"] = serde_json::json!(1);
        assert_eq!(
            SyncState::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            SyncStateDecodeError::Malformed
        );

        let mut value = json(&bytes);
        value["body"] = serde_json::json!(5);
        assert_eq!(
            SyncState::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            SyncStateDecodeError::Malformed
        );
    }

    #[test]
    fn every_missing_body_field_is_rejected_by_the_parser_itself() {
        let body = body_of(&pending_state());

        let paths: &[(&str, &str)] = &[
            ("", "binding_id"),
            ("", "vault_tag"),
            ("", "local_locator"),
            ("", "target_locator"),
            ("", "base"),
            // `null` must be written; an absent key is not "no pending push".
            ("", "pending_push"),
            ("/vault_tag", "salt"),
            ("/vault_tag", "digest"),
            ("/base", "kind"),
            ("/base", "synced"),
            ("/base", "synced_revision"),
            ("/base", "high_water"),
            ("/pending_push", "intent_id"),
            ("/pending_push", "baseline"),
            ("/pending_push", "intended"),
            ("/pending_push", "intended_revision"),
            ("/pending_push/baseline", "kind"),
            ("/pending_push/baseline", "fingerprint"),
        ];

        for (parent, key) in paths {
            let damaged = remove_at(&body, parent, key);

            assert!(
                serde_json::from_str::<BodyWire>(&damaged).is_err(),
                "parser accepted a body without {parent}/{key}"
            );
            assert_eq!(
                SyncState::decode(&forge(&damaged)).unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "{parent}/{key}"
            );
        }

        // An unbased state's discriminator is required as well.
        let unbased = body_of(&unbased_state());
        let damaged = remove_at(&unbased, "/base", "kind");
        assert!(serde_json::from_str::<BodyWire>(&damaged).is_err());
    }

    #[test]
    fn unknown_body_fields_are_rejected_at_every_level() {
        let pending = body_of(&pending_state());
        let unbased = body_of(&unbased_state());

        let cases = [
            (pending.clone(), "{", "{\"extra\":1,"),
            (pending.clone(), "\"salt\"", "\"extra\":1,\"salt\""),
            (
                pending.clone(),
                "\"kind\":\"based\"",
                "\"kind\":\"based\",\"extra\":1",
            ),
            (
                pending.clone(),
                "\"intent_id\"",
                "\"extra\":1,\"intent_id\"",
            ),
            (
                pending.clone(),
                "\"kind\":\"present\"",
                "\"kind\":\"present\",\"extra\":1",
            ),
            (
                unbased.clone(),
                "\"kind\":\"unbased\"",
                "\"kind\":\"unbased\",\"extra\":1",
            ),
            (
                unbased,
                "\"kind\":\"absent\"",
                "\"kind\":\"absent\",\"extra\":1",
            ),
        ];

        for (body, from, to) in cases {
            let widened = body.replacen(from, to, 1);
            assert_ne!(widened, body, "{from}");

            assert!(
                serde_json::from_str::<BodyWire>(&widened).is_err(),
                "parser accepted an unknown field near {from}"
            );
            assert_eq!(
                SyncState::decode(&forge(&widened)).unwrap_err(),
                SyncStateDecodeError::InvalidBody
            );
        }
    }

    #[test]
    fn unknown_discriminators_are_rejected() {
        let pending = body_of(&pending_state());

        for (from, to) in [
            ("\"kind\":\"based\"", "\"kind\":\"rebased\""),
            ("\"kind\":\"based\"", "\"kind\":\"Based\""),
            ("\"kind\":\"present\"", "\"kind\":\"unknown\""),
            ("\"kind\":\"present\"", "\"kind\":\"\""),
        ] {
            assert_eq!(
                SyncState::decode(&forge(&replace_once(&pending, from, to))).unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "{to}"
            );
        }
    }

    // ---- 12. UUIDs --------------------------------------------------------------

    #[test]
    fn nil_uuids_are_rejected() {
        assert_eq!(
            BindingId::new(Uuid::nil()),
            Err(SyncStateError::NilBindingId)
        );
        assert_eq!(
            PendingPush::new(
                Uuid::nil(),
                PushIntent::new(PushBaseline::Absent, fp(2)).unwrap(),
                1
            ),
            Err(SyncStateError::NilIntentId)
        );
        assert_eq!(
            VaultBindingTag::derive(salt(0), Uuid::nil()),
            Err(SyncStateError::NilVaultId)
        );

        let nil = Uuid::nil().hyphenated().to_string();
        assert_eq!(
            decode_with(|w| w.binding_id = nil.clone()).unwrap_err(),
            SyncStateDecodeError::InvalidState(SyncStateError::NilBindingId)
        );
        assert_eq!(
            decode_with(|w| w.pending_push.as_mut().unwrap().intent_id = nil.clone()).unwrap_err(),
            SyncStateDecodeError::InvalidState(SyncStateError::NilIntentId)
        );
    }

    #[test]
    fn only_canonical_lowercase_hyphenated_uuids_are_accepted() {
        // The spellings of one valid UUID. It must contain hex letters, or its
        // uppercase form would be the canonical form itself.
        assert_ne!(INTENT_TEXT.to_uppercase(), INTENT_TEXT);

        let variants = [
            INTENT_TEXT.to_uppercase(),
            INTENT_TEXT.replace('-', ""),
            format!("{{{INTENT_TEXT}}}"),
            format!("urn:uuid:{INTENT_TEXT}"),
            format!(" {INTENT_TEXT}"),
            format!("{INTENT_TEXT} "),
            INTENT_TEXT[..35].to_owned(),
            "not-a-uuid".to_owned(),
            String::new(),
        ];

        for variant in variants {
            assert_eq!(
                decode_with(|w| w.binding_id = variant.clone()).unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "binding_id {variant:?}"
            );
            assert_eq!(
                decode_with(|w| w.pending_push.as_mut().unwrap().intent_id = variant.clone())
                    .unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "intent_id {variant:?}"
            );
        }

        assert_eq!(parse_canonical_uuid(INTENT_TEXT), Some(INTENT));
    }

    // ---- 13. fingerprints and hex ------------------------------------------------

    #[test]
    fn invalid_hex_encodings_are_rejected() {
        let good = fp(9).to_hex();
        assert!(
            good.bytes().any(|b| b.is_ascii_lowercase()),
            "needs letters"
        );

        let bad_values = [
            good.to_uppercase(),
            good[..63].to_owned(),
            format!("{good}0"),
            format!("0x{}", &good[2..]),
            format!(" {}", &good[1..]),
            format!("{}g", &good[..63]),
            String::new(),
        ];

        for bad in bad_values {
            let mutations: [(&str, Mutation<'_>); 5] = [
                (
                    "synced",
                    Box::new(|w| {
                        w.base = BaseWire::Based {
                            synced: bad.clone(),
                            synced_revision: 7,
                            high_water: 9,
                        }
                    }),
                ),
                (
                    "baseline fingerprint",
                    Box::new(|w| {
                        w.pending_push.as_mut().unwrap().baseline = BaselineWire::Present {
                            fingerprint: bad.clone(),
                        }
                    }),
                ),
                (
                    "intended",
                    Box::new(|w| w.pending_push.as_mut().unwrap().intended = bad.clone()),
                ),
                ("salt", Box::new(|w| w.vault_tag.salt = bad.clone())),
                ("digest", Box::new(|w| w.vault_tag.digest = bad.clone())),
            ];

            for (name, mutate) in mutations {
                assert_eq!(
                    decode_with(mutate).unwrap_err(),
                    SyncStateDecodeError::InvalidBody,
                    "{name}: {bad:?}"
                );
            }
        }
    }

    #[test]
    fn hex_helper_is_strictly_lowercase_and_exact() {
        let digest = tag().digest;
        let hex = HEXLOWER.encode(&digest);

        assert_eq!(decode_hex32(&hex), Some(digest));
        assert_eq!(decode_hex32(&hex.to_uppercase()), None);
        assert_eq!(decode_hex32(&hex[..62]), None);
        assert_eq!(decode_hex32(&format!("{hex}00")), None);
        assert_eq!(decode_hex32(&"é".repeat(32)), None);
    }

    // ---- 14. revisions ------------------------------------------------------------

    #[test]
    fn malformed_revision_values_are_rejected() {
        let body = body_of(&pending_state());

        for field in [
            "\"synced_revision\":7",
            "\"high_water\":9",
            "\"intended_revision\":10",
        ] {
            let name = field.split(':').next().unwrap();

            for bad in [
                "-1",
                "1.5",
                "7.0",
                "1e1",
                "\"7\"",
                "null",
                "true",
                "[7]",
                "07",
                "+7",
                "18446744073709551616",
                "99999999999999999999999999",
            ] {
                let damaged = replace_once(&body, field, &format!("{name}:{bad}"));

                assert_eq!(
                    SyncState::decode(&forge(&damaged)).unwrap_err(),
                    SyncStateDecodeError::InvalidBody,
                    "{name} = {bad}"
                );
            }
        }

        // The largest representable value is fine where the invariants allow it.
        let widest = replace_once(
            &body,
            "\"intended_revision\":10",
            "\"intended_revision\":18446744073709551615",
        );
        let state = SyncState::decode(&forge(&widest)).unwrap();
        assert_eq!(state.pending_push().unwrap().intended_revision(), u64::MAX);
    }

    // ---- 15. locators --------------------------------------------------------------

    #[test]
    fn locator_validation() {
        assert_eq!(Locator::new(""), Err(SyncStateError::EmptyLocator));

        // The limit is in bytes.
        assert!(Locator::new(&"a".repeat(MAX_LOCATOR_BYTES)).is_ok());
        assert_eq!(
            Locator::new(&"a".repeat(MAX_LOCATOR_BYTES + 1)),
            Err(SyncStateError::LocatorTooLong)
        );
        assert!(Locator::new(&"é".repeat(MAX_LOCATOR_BYTES / 2)).is_ok());
        assert_eq!(
            Locator::new(&"é".repeat(MAX_LOCATOR_BYTES / 2 + 1)),
            Err(SyncStateError::LocatorTooLong)
        );

        for control in ['\0', '\n', '\r', '\t', '\u{1b}', '\u{7f}', '\u{85}'] {
            assert_eq!(
                Locator::new(&format!("a{control}b")),
                Err(SyncStateError::LocatorControlCharacter),
                "{control:?}"
            );
        }

        // Ordinary text, including spaces and non-ASCII, is accepted verbatim.
        for fine in [
            " ",
            "a b",
            "Док/файл.lvault",
            "content://x/y%20z",
            "C:\\Users\\a b\\v.lvault",
        ] {
            assert_eq!(Locator::new(fine).unwrap().as_str(), fine);
        }
    }

    #[test]
    fn locators_are_compared_exactly_without_normalization() {
        assert_eq!(loc("a/b"), loc("a/b"));
        assert_ne!(loc("a/b"), loc("a/b/"));
        assert_ne!(loc("a/b"), loc("A/B"));
        assert_ne!(loc("a/b"), loc("a//b"));
        assert_ne!(loc("a/b"), loc("./a/b"));
        assert_ne!(loc("a/b"), loc("a\\b"));
        assert_ne!(loc("a/b"), loc("a/b "));

        // Structural only: differently spelled names for one file are distinct
        // here, which is exactly why adapters must check file identity.
        assert!(build_with_locators("C:\\v\\a.lvault", "C:\\v\\..\\v\\a.lvault").is_ok());
        assert_eq!(
            build_with_locators("same", "same"),
            Err(SyncStateError::IdenticalLocators)
        );
    }

    fn build_with_locators(local: &str, target: &str) -> Result<SyncState, SyncStateError> {
        SyncState::new(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(local),
            loc(target),
            SyncBase::Based(checkpoint()),
            None,
        )
    }

    #[test]
    fn invalid_locators_are_rejected_when_decoding() {
        let cases: [(&str, SyncStateError); 4] = [
            ("", SyncStateError::EmptyLocator),
            ("SECRET-LOC\u{7}", SyncStateError::LocatorControlCharacter),
            ("SECRET-LOC\n", SyncStateError::LocatorControlCharacter),
            (
                &"a".repeat(MAX_LOCATOR_BYTES + 1),
                SyncStateError::LocatorTooLong,
            ),
        ];

        for (bad, expected) in cases {
            assert_eq!(
                decode_with(|w| w.local_locator = bad.to_owned()).unwrap_err(),
                SyncStateDecodeError::InvalidState(expected)
            );
            assert_eq!(
                decode_with(|w| w.target_locator = bad.to_owned()).unwrap_err(),
                SyncStateDecodeError::InvalidState(expected)
            );
        }

        assert_eq!(
            decode_with(|w| w.target_locator = w.local_locator.clone()).unwrap_err(),
            SyncStateDecodeError::InvalidState(SyncStateError::IdenticalLocators)
        );
    }

    #[test]
    fn locators_needing_json_escapes_round_trip() {
        let local = "q\"uote\\slash/{brace}[bracket]";
        let target = "\\\\server\\share\\\"v\".lvault";
        let state = SyncState::new(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(local),
            loc(target),
            SyncBase::Based(checkpoint()),
            None,
        )
        .unwrap();

        let decoded = SyncState::decode(&state.encode().unwrap()).unwrap();

        assert_eq!(decoded.local_locator().as_str(), local);
        assert_eq!(decoded.target_locator().as_str(), target);
    }

    // ---- 16. size bound ------------------------------------------------------------

    #[test]
    fn worst_case_state_fits_the_size_bound() {
        // `"` and `\` are the only permitted characters that JSON escapes, and
        // they are escaped twice (body, then the string that carries it).
        let state = SyncState::new(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(&"\"".repeat(MAX_LOCATOR_BYTES)),
            loc(&"\\".repeat(MAX_LOCATOR_BYTES)),
            SyncBase::Based(checkpoint()),
            Some(pending(PushBaseline::Present(fp(1)), 2, 10)),
        )
        .unwrap();

        let bytes = state.encode().unwrap();

        assert!(bytes.len() <= MAX_SYNC_STATE_BYTES);
        assert!(bytes.len() > 2 * MAX_LOCATOR_BYTES * 4, "escaping applied");
        assert_eq!(SyncState::decode(&bytes).unwrap(), state);
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() {
        assert_eq!(
            SyncState::decode(&vec![b' '; MAX_SYNC_STATE_BYTES + 1]).unwrap_err(),
            SyncStateDecodeError::TooLarge
        );
        // Exactly at the limit passes the size gate and fails on content.
        assert_eq!(
            SyncState::decode(&vec![b' '; MAX_SYNC_STATE_BYTES]).unwrap_err(),
            SyncStateDecodeError::Malformed
        );

        // A valid state padded with insignificant whitespace to the limit.
        let mut padded = pending_state().encode().unwrap();
        padded.resize(MAX_SYNC_STATE_BYTES, b' ');
        assert_eq!(SyncState::decode(&padded).unwrap(), pending_state());
        padded.push(b' ');
        assert_eq!(
            SyncState::decode(&padded).unwrap_err(),
            SyncStateDecodeError::TooLarge
        );
        assert_eq!(SyncStateLoad::from_bytes(&padded), SyncStateLoad::Corrupt);
    }

    // ---- 17. state invariants ---------------------------------------------------------

    #[test]
    fn constructors_reject_every_invalid_state() {
        let absent = |revision| Some(pending(PushBaseline::Absent, 2, revision));
        let present =
            |from: u8, revision| Some(pending(PushBaseline::Present(fp(from)), 2, revision));

        let cases = [
            (
                "unbased without a pending push",
                build(SyncBase::Unbased, None),
                SyncStateError::UnbasedRequiresInitialPublication,
            ),
            (
                "unbased with a pending push from a present remote",
                build(SyncBase::Unbased, present(1, 5)),
                SyncStateError::UnbasedRequiresInitialPublication,
            ),
            (
                "absent baseline in a based state",
                build(SyncBase::Based(checkpoint()), absent(10)),
                SyncStateError::AbsentBaselineRequiresUnbased,
            ),
            (
                "pending baseline is not the synced fingerprint",
                build(SyncBase::Based(checkpoint()), present(3, 10)),
                SyncStateError::PendingBaselineMismatch,
            ),
            (
                "intended revision equals the high-water mark",
                build(SyncBase::Based(checkpoint()), present(1, 9)),
                SyncStateError::PendingRevisionNotAboveHighWater,
            ),
            (
                "intended revision below the high-water mark",
                build(SyncBase::Based(checkpoint()), present(1, 0)),
                SyncStateError::PendingRevisionNotAboveHighWater,
            ),
            (
                "nothing can exceed a saturated high-water mark",
                build(
                    SyncBase::Based(
                        SyncCheckpoint::new(fp(1), 7, RemoteHighWater::new(u64::MAX)).unwrap(),
                    ),
                    present(1, u64::MAX),
                ),
                SyncStateError::PendingRevisionNotAboveHighWater,
            ),
            (
                "identical locators",
                build_with_locators("same", "same"),
                SyncStateError::IdenticalLocators,
            ),
        ];

        for (name, result, expected) in cases {
            assert_eq!(result.unwrap_err(), expected, "{name}");
        }

        assert_eq!(
            SyncCheckpoint::new(fp(1), 10, RemoteHighWater::new(9)),
            Err(SyncStateError::CheckpointRevisionAboveHighWater)
        );
        assert_eq!(
            PendingPush::new(
                INTENT,
                PushIntent::new(PushBaseline::Absent, fp(2)).unwrap(),
                0
            )
            .unwrap()
            .intended_revision(),
            0
        );
    }

    #[test]
    fn constructors_accept_every_boundary_that_is_valid() {
        // Equality at the checkpoint, one above for the pending push.
        assert!(SyncCheckpoint::new(fp(1), 9, RemoteHighWater::new(9)).is_ok());
        assert!(build(
            SyncBase::Based(checkpoint()),
            Some(pending(PushBaseline::Present(fp(1)), 2, 10))
        )
        .is_ok());

        // An initial publication may intend any revision, including zero.
        for revision in [0, 1, u64::MAX] {
            assert!(build(
                SyncBase::Unbased,
                Some(pending(PushBaseline::Absent, 2, revision))
            )
            .is_ok());
        }

        // A based state may have no pending push.
        assert!(build(SyncBase::Based(checkpoint()), None).is_ok());
    }

    #[test]
    fn decoding_enforces_every_state_invariant() {
        let cases: [InvariantCase; 9] = [
            (
                "unbased without a pending push",
                |w| {
                    w.base = BaseWire::Unbased {};
                    w.pending_push = None;
                },
                SyncStateError::UnbasedRequiresInitialPublication,
            ),
            (
                "unbased with a pending push from a present remote",
                |w| w.base = BaseWire::Unbased {},
                SyncStateError::UnbasedRequiresInitialPublication,
            ),
            (
                "absent baseline in a based state",
                |w| w.pending_push.as_mut().unwrap().baseline = BaselineWire::Absent {},
                SyncStateError::AbsentBaselineRequiresUnbased,
            ),
            (
                "pending baseline mismatch",
                |w| {
                    w.pending_push.as_mut().unwrap().baseline = BaselineWire::Present {
                        fingerprint: fp(3).to_hex(),
                    }
                },
                SyncStateError::PendingBaselineMismatch,
            ),
            (
                "intended revision at the high-water mark",
                |w| w.pending_push.as_mut().unwrap().intended_revision = 9,
                SyncStateError::PendingRevisionNotAboveHighWater,
            ),
            (
                "synced revision above the high-water mark",
                |w| {
                    w.base = BaseWire::Based {
                        synced: fp(1).to_hex(),
                        synced_revision: 10,
                        high_water: 9,
                    }
                },
                SyncStateError::CheckpointRevisionAboveHighWater,
            ),
            (
                "no-op push intent",
                |w| w.pending_push.as_mut().unwrap().intended = fp(1).to_hex(),
                SyncStateError::InvalidPushIntent,
            ),
            (
                "nil binding id",
                |w| w.binding_id = Uuid::nil().hyphenated().to_string(),
                SyncStateError::NilBindingId,
            ),
            (
                "identical locators",
                |w| w.target_locator = w.local_locator.clone(),
                SyncStateError::IdenticalLocators,
            ),
        ];

        for (name, mutate, expected) in cases {
            assert_eq!(
                decode_with(mutate).unwrap_err(),
                SyncStateDecodeError::InvalidState(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn encoding_revalidates_instead_of_trusting_construction() {
        let valid_checkpoint = checkpoint();
        let broken_checkpoint = SyncCheckpoint {
            synced: fp(1),
            synced_revision: 10,
            high_water: RemoteHighWater::new(9),
        };
        let nil_intent = PendingPush {
            intent_id: Uuid::nil(),
            intent: PushIntent::new(PushBaseline::Absent, fp(2)).unwrap(),
            intended_revision: 1,
        };

        let mut same_locators = raw(SyncBase::Based(valid_checkpoint), None);
        same_locators.target_locator = same_locators.local_locator.clone();

        let mut empty_locator = raw(SyncBase::Based(valid_checkpoint), None);
        empty_locator.local_locator = Locator(String::new());

        let mut oversized_locator = raw(SyncBase::Based(valid_checkpoint), None);
        oversized_locator.target_locator = Locator("a".repeat(MAX_LOCATOR_BYTES + 1));

        let mut control_locator = raw(SyncBase::Based(valid_checkpoint), None);
        control_locator.target_locator = Locator("a\u{0}b".to_owned());

        let mut nil_binding = raw(SyncBase::Based(valid_checkpoint), None);
        nil_binding.binding_id = BindingId(Uuid::nil());

        let cases = [
            ("nil binding id", nil_binding, SyncStateError::NilBindingId),
            (
                "identical locators",
                same_locators,
                SyncStateError::IdenticalLocators,
            ),
            ("empty locator", empty_locator, SyncStateError::EmptyLocator),
            (
                "oversized locator",
                oversized_locator,
                SyncStateError::LocatorTooLong,
            ),
            (
                "control character in locator",
                control_locator,
                SyncStateError::LocatorControlCharacter,
            ),
            (
                "broken checkpoint",
                raw(SyncBase::Based(broken_checkpoint), None),
                SyncStateError::CheckpointRevisionAboveHighWater,
            ),
            (
                "nil intent id",
                raw(SyncBase::Unbased, Some(nil_intent)),
                SyncStateError::NilIntentId,
            ),
            (
                "unbased without a pending push",
                raw(SyncBase::Unbased, None),
                SyncStateError::UnbasedRequiresInitialPublication,
            ),
            (
                "absent baseline in a based state",
                raw(
                    SyncBase::Based(valid_checkpoint),
                    Some(pending(PushBaseline::Absent, 2, 10)),
                ),
                SyncStateError::AbsentBaselineRequiresUnbased,
            ),
            (
                "pending baseline mismatch",
                raw(
                    SyncBase::Based(valid_checkpoint),
                    Some(pending(PushBaseline::Present(fp(3)), 2, 10)),
                ),
                SyncStateError::PendingBaselineMismatch,
            ),
            (
                "pending revision not above the high-water mark",
                raw(
                    SyncBase::Based(valid_checkpoint),
                    Some(pending(PushBaseline::Present(fp(1)), 2, 9)),
                ),
                SyncStateError::PendingRevisionNotAboveHighWater,
            ),
        ];

        for (name, state, expected) in cases {
            assert_eq!(
                state.encode().unwrap_err(),
                SyncStateEncodeError::InvalidState(expected),
                "{name}"
            );
        }
    }

    // ---- 18-19. vault tag -------------------------------------------------------------

    #[test]
    fn vault_tag_known_answer_vectors() {
        // Computed outside this crate (a separate SHA-256 implementation) over
        // "LocalVault/sync-binding-tag/v1" || 0x00 || salt || vault_id bytes.
        let counting = VaultBindingTag::derive(salt(0), VAULT_ID).unwrap();
        assert_eq!(counting.salt, std::array::from_fn::<u8, 32, _>(|i| i as u8));
        assert_eq!(
            HEXLOWER.encode(&counting.digest),
            "533cfabc5ff2073b76dab8c6cb60289e44d95f9dbb67cdbdac12bdcf94025aa8"
        );

        let patterned = VaultBindingTag::derive(
            [0xa5; BINDING_SALT_LEN],
            Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0001),
        )
        .unwrap();
        assert_eq!(
            HEXLOWER.encode(&patterned.digest),
            "c143ce6a85927e65dd548d1d8618e761ea269ffcb619e072e5ab5cc70432e696"
        );
    }

    #[test]
    fn vault_tag_depends_on_salt_and_vault_identity() {
        let base = VaultBindingTag::derive(salt(0), VAULT_ID).unwrap();

        // Deterministic for equal inputs.
        assert_eq!(base, VaultBindingTag::derive(salt(0), VAULT_ID).unwrap());

        // A different salt gives a different digest for the same vault.
        let other_salt = VaultBindingTag::derive(salt(1), VAULT_ID).unwrap();
        assert_ne!(base.digest, other_salt.digest);
        assert_ne!(base, other_salt);

        // A different vault gives a different digest under the same salt.
        let other_vault =
            VaultBindingTag::derive(salt(0), Uuid::from_u128(VAULT_ID.as_u128() ^ 1)).unwrap();
        assert_ne!(base.digest, other_vault.digest);

        // A single flipped salt bit changes the digest.
        let mut flipped = salt(0);
        flipped[31] ^= 0x80;
        assert_ne!(
            base.digest,
            VaultBindingTag::derive(flipped, VAULT_ID).unwrap().digest
        );
    }

    #[test]
    fn vault_tag_matches_only_the_vault_it_was_derived_from() {
        let tag = tag();

        assert!(tag.matches_vault(VAULT_ID));
        assert!(!tag.matches_vault(Uuid::from_u128(VAULT_ID.as_u128() ^ 1)));
        assert!(!tag.matches_vault(Uuid::nil()));

        // The same vault under another salt is a different tag.
        let other = VaultBindingTag::derive(salt(7), VAULT_ID).unwrap();
        assert!(other.matches_vault(VAULT_ID));
        assert_ne!(other, tag);
    }

    #[test]
    fn serialized_state_never_contains_the_plaintext_vault_id() {
        let text = String::from_utf8(pending_state().encode().unwrap()).unwrap();

        assert!(!text.contains(&VAULT_ID.hyphenated().to_string()));
        assert!(!text.contains(&VAULT_ID.simple().to_string()));
        assert!(!text
            .to_uppercase()
            .contains(&VAULT_ID.simple().to_string().to_uppercase()));
    }

    // ---- 20-22. binding verification ----------------------------------------------------

    #[test]
    fn matching_binding_verifies() {
        assert_eq!(
            pending_state().verify_binding(VAULT_ID, &loc(LOCAL), &loc(TARGET)),
            Ok(())
        );
    }

    #[test]
    fn wrong_vault_identity_is_a_mismatch() {
        let state = pending_state();

        for wrong in [
            Uuid::from_u128(VAULT_ID.as_u128() ^ 1),
            Uuid::nil(),
            BINDING,
        ] {
            assert_eq!(
                state.verify_binding(wrong, &loc(LOCAL), &loc(TARGET)),
                Err(BindingMismatch::VaultIdentity)
            );
        }

        // Identity is judged first, whatever else is also wrong.
        assert_eq!(
            state.verify_binding(Uuid::nil(), &loc(OTHER), &loc(OTHER)),
            Err(BindingMismatch::VaultIdentity)
        );
    }

    #[test]
    fn wrong_local_locator_is_a_mismatch() {
        let state = pending_state();

        for wrong in [
            OTHER,
            TARGET,
            "synthetic/local/LOCAL-MARKER.lvault/",
            "SYNTHETIC/LOCAL/LOCAL-MARKER.LVAULT",
        ] {
            assert_eq!(
                state.verify_binding(VAULT_ID, &loc(wrong), &loc(TARGET)),
                Err(BindingMismatch::LocalLocator),
                "{wrong}"
            );
        }
    }

    #[test]
    fn wrong_target_locator_is_a_mismatch() {
        let state = pending_state();

        for wrong in [OTHER, LOCAL, "synthetic/remote/TARGET-MARKER.lvault "] {
            assert_eq!(
                state.verify_binding(VAULT_ID, &loc(LOCAL), &loc(wrong)),
                Err(BindingMismatch::TargetLocator),
                "{wrong}"
            );
        }

        // Swapped roles are not interchangeable.
        assert_eq!(
            state.verify_binding(VAULT_ID, &loc(TARGET), &loc(LOCAL)),
            Err(BindingMismatch::LocalLocator)
        );
    }

    // ---- 23. no sensitive values in Debug or errors --------------------------------------

    fn assert_redacted(text: &str) {
        let tag = tag();
        let sensitive = [
            "LOCAL-MARKER".to_owned(),
            "TARGET-MARKER".to_owned(),
            "OTHER-MARKER".to_owned(),
            "SECRET-LOC".to_owned(),
            "SECRET-NOT-A-UUID".to_owned(),
            VAULT_ID.hyphenated().to_string(),
            VAULT_ID.simple().to_string(),
            HEXLOWER.encode(&tag.salt),
            HEXLOWER.encode(&tag.digest),
        ];

        for value in sensitive {
            assert!(!text.contains(&value), "{value:?} leaked into {text:?}");
        }
    }

    #[test]
    fn debug_output_redacts_locators_identity_salt_and_digest() {
        let state = pending_state();

        assert_redacted(&format!("{state:?}"));
        assert_redacted(&format!("{state:#?}"));
        assert_redacted(&format!("{:?}", state.local_locator()));
        assert_redacted(&format!("{:?}", state.target_locator()));
        assert_redacted(&format!("{:?}", state.vault_tag()));
        assert_redacted(&format!(
            "{:?}",
            SyncStateLoad::Loaded(Box::new(state.clone()))
        ));

        assert_eq!(format!("{:?}", loc(LOCAL)), "Locator(<redacted>)");
        assert_eq!(format!("{:?}", tag()), "VaultBindingTag(<redacted>)");
    }

    #[test]
    fn errors_never_echo_locators_identity_or_input() {
        let secret_local = "SECRET-LOC\u{7}".to_owned();
        let not_a_uuid = "SECRET-NOT-A-UUID".to_owned();

        let mut texts: Vec<String> = Vec::new();
        let mut record = |error: &dyn std::fmt::Debug, display: &dyn std::fmt::Display| {
            texts.push(format!("{error:?}"));
            texts.push(display.to_string());
        };

        for result in [
            decode_with(|w| w.local_locator = secret_local.clone()),
            decode_with(|w| w.binding_id = not_a_uuid.clone()),
            decode_with(|w| w.vault_tag.digest = not_a_uuid.clone()),
            decode_with(|w| w.target_locator = w.local_locator.clone()),
            SyncState::decode(&forge(&format!("{{\"binding_id\":\"{not_a_uuid}\"}}"))),
            SyncState::decode(format!("{{\"format\":\"{not_a_uuid}\",\"version\":1}}").as_bytes()),
            SyncState::decode(format!("{{\"format\":\"{secret_local}").as_bytes()),
            SyncState::decode(&with_outer(&pending_state().encode().unwrap(), |o| {
                o.body.push_str("SECRET-LOC")
            })),
        ] {
            let error = result.unwrap_err();
            record(&error, &error);
        }

        for error in [
            Locator::new(&secret_local).unwrap_err(),
            Locator::new("").unwrap_err(),
            VaultBindingTag::derive(salt(0), Uuid::nil()).unwrap_err(),
            build_with_locators("SECRET-LOC", "SECRET-LOC").unwrap_err(),
        ] {
            record(&error, &error);
        }

        for mismatch in [
            pending_state()
                .verify_binding(Uuid::nil(), &loc(LOCAL), &loc(TARGET))
                .unwrap_err(),
            pending_state()
                .verify_binding(VAULT_ID, &loc(OTHER), &loc(TARGET))
                .unwrap_err(),
            pending_state()
                .verify_binding(VAULT_ID, &loc(LOCAL), &loc(OTHER))
                .unwrap_err(),
        ] {
            record(&mismatch, &mismatch);
        }

        let mut oversized = raw(SyncBase::Based(checkpoint()), None);
        oversized.target_locator = Locator("SECRET-LOC".repeat(MAX_LOCATOR_BYTES));
        let error = oversized.encode().unwrap_err();
        record(&error, &error);

        assert!(texts.len() >= 24);
        for text in texts {
            assert_redacted(&text);
        }
    }

    // ---- 24. missing versus corrupt versus unreadable ---------------------------------------

    fn label(load: &SyncStateLoad) -> &'static str {
        // Deliberately exhaustive: a new variant must be classified here.
        match load {
            SyncStateLoad::NotConfigured => "not-configured",
            SyncStateLoad::Unreadable => "unreadable",
            SyncStateLoad::Corrupt => "corrupt",
            SyncStateLoad::UnsupportedVersion => "unsupported-version",
            SyncStateLoad::Loaded(_) => "loaded",
        }
    }

    #[test]
    fn byte_classification_never_reports_absence_or_unreadability() {
        let valid = pending_state().encode().unwrap();

        let mut bad_checksum = valid.clone();
        let outer = outer_of(&valid);
        bad_checksum = with_outer(&bad_checksum, |o| {
            o.body_sha256 = "0".repeat(64);
            o.body = outer.body.clone();
        });

        let future =
            br#"{"format":"localvault-sync-state","version":2,"body":"{}","body_sha256":"x"}"#
                .to_vec();

        let table: Vec<(&str, Vec<u8>, &str)> = vec![
            ("valid", valid.clone(), "loaded"),
            ("empty file", Vec::new(), "corrupt"),
            ("whitespace only", b"  \n".to_vec(), "corrupt"),
            ("not json", b"hello".to_vec(), "corrupt"),
            ("truncated", valid[..valid.len() / 2].to_vec(), "corrupt"),
            ("checksum mismatch", bad_checksum, "corrupt"),
            (
                "wrong format",
                with_outer(&valid, |o| o.format = "x".to_owned()),
                "corrupt",
            ),
            (
                "inconsistent state",
                forge_with(|w| w.base = BaseWire::Unbased {}),
                "corrupt",
            ),
            ("oversized", vec![b'a'; MAX_SYNC_STATE_BYTES + 1], "corrupt"),
            ("future version", future, "unsupported-version"),
        ];

        for (name, bytes, expected) in table {
            let load = SyncStateLoad::from_bytes(&bytes);

            assert_eq!(label(&load), expected, "{name}");
            // Absence and unreadability are never inferred from content.
            assert!(
                !matches!(
                    load,
                    SyncStateLoad::NotConfigured | SyncStateLoad::Unreadable
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn load_outcomes_are_distinct_states() {
        let loaded = SyncStateLoad::Loaded(Box::new(based_state()));
        let outcomes = [
            SyncStateLoad::NotConfigured,
            SyncStateLoad::Unreadable,
            SyncStateLoad::Corrupt,
            SyncStateLoad::UnsupportedVersion,
            loaded,
        ];

        for (i, left) in outcomes.iter().enumerate() {
            for (j, right) in outcomes.iter().enumerate() {
                assert_eq!(left == right, i == j, "{} vs {}", label(left), label(right));
            }
        }
    }

    // ---- B3c-1: dormant exchange records ---------------------------------------
    //
    // Everything below is synthetic. The anchors are arbitrary byte patterns, not
    // identities of any real file or directory.

    const RETAINED_A: Uuid = Uuid::from_u128(0xbbbb_bbbb_cccc_4ddd_8eee_ffff_ffff_ffff);
    const RETAINED_A_TEXT: &str = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";

    // Assembled by hand (Python `hashlib`/`json`) from the v1 golden body plus the
    // two new keys; not taken from this module's encoder.
    const GOLDEN_EXCHANGE: &str = r#"{"format":"localvault-sync-state","version":2,"body_sha256":"1101fdda533dfdfeeeda8a019186f050762dce64c199a6d45e9b06d4d8931777","body":"{\"binding_id\":\"11111111-2222-3333-4444-555555555555\",\"vault_tag\":{\"salt\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"digest\":\"533cfabc5ff2073b76dab8c6cb60289e44d95f9dbb67cdbdac12bdcf94025aa8\"},\"local_locator\":\"synthetic/local/LOCAL-MARKER.lvault\",\"target_locator\":\"synthetic/remote/TARGET-MARKER.lvault\",\"base\":{\"kind\":\"based\",\"synced\":\"4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a\",\"synced_revision\":7,\"high_water\":9},\"pending_push\":{\"intent_id\":\"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\",\"baseline\":{\"kind\":\"present\",\"fingerprint\":\"4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a\"},\"intended\":\"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986\",\"intended_revision\":10},\"exchange\":{\"scheme\":\"retain_and_publish_v1\",\"target_anchor\":\"1011121314151617\",\"directory_anchor\":\"a0a1a2a3\"},\"retained_previous\":[{\"exchange_id\":\"bbbbbbbb-cccc-4ddd-8eee-ffffffffffff\",\"fingerprint\":\"084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5\",\"revision\":5,\"object_anchor\":\"202122232425262728292a2b2c2d2e2f\",\"directory_anchor\":\"b0b1b2b3\"}]}"}"#;

    fn anchor_of(bytes: &[u8]) -> ObjectAnchor {
        ObjectAnchor::new(bytes).unwrap()
    }

    /// `len` bytes counting up from `start`.
    fn anchor_run(start: u8, len: usize) -> ObjectAnchor {
        let bytes: Vec<u8> = (0..len).map(|i| start.wrapping_add(i as u8)).collect();
        anchor_of(&bytes)
    }

    fn exchange_intent() -> ExchangeIntent {
        ExchangeIntent::new(
            ExchangeScheme::RetainAndPublishV1,
            anchor_run(0x10, 8),
            anchor_of(&[0xa0, 0xa1, 0xa2, 0xa3]),
        )
    }

    fn retained_a() -> RetainedPrevious {
        RetainedPrevious::new(
            RETAINED_A,
            fp(3),
            5,
            anchor_run(0x20, 16),
            anchor_of(&[0xb0, 0xb1, 0xb2, 0xb3]),
        )
        .unwrap()
    }

    /// Distinct, valid entries for the checkpoint of [`checkpoint`] (synced
    /// revision 7): revisions stay below it.
    fn retained_n(index: u8) -> RetainedPrevious {
        RetainedPrevious::new(
            Uuid::from_u128(0x7000_0000_0000_4000_8000_0000_0000_0000 + u128::from(index)),
            fp(100 + index),
            u64::from(index % 7),
            anchor_run(index, MAX_OBJECT_ANCHOR_BYTES),
            anchor_run(index.wrapping_add(0x80), MAX_OBJECT_ANCHOR_BYTES),
        )
        .unwrap()
    }

    fn with_records(
        base: SyncBase,
        pending_push: Option<PendingPush>,
        exchange: Option<ExchangeIntent>,
        retained: Vec<RetainedPrevious>,
    ) -> Result<SyncState, SyncStateError> {
        SyncState::new_with_exchange_records(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(LOCAL),
            loc(TARGET),
            base,
            pending_push,
            exchange,
            retained,
        )
    }

    fn based_base() -> SyncBase {
        SyncBase::Based(checkpoint())
    }

    fn based_pending_push() -> Option<PendingPush> {
        Some(pending(PushBaseline::Present(fp(1)), 2, 10))
    }

    fn unbased_pending_push() -> Option<PendingPush> {
        Some(pending(PushBaseline::Absent, 2, 1))
    }

    /// [`pending_state`] plus an exchange intent and one retained entry.
    fn exchange_state() -> SyncState {
        with_records(
            based_base(),
            based_pending_push(),
            Some(exchange_intent()),
            vec![retained_a()],
        )
        .unwrap()
    }

    fn exchange_only_state() -> SyncState {
        with_records(
            based_base(),
            based_pending_push(),
            Some(exchange_intent()),
            Vec::new(),
        )
        .unwrap()
    }

    fn retained_only_state() -> SyncState {
        with_records(based_base(), None, None, vec![retained_a()]).unwrap()
    }

    fn forge_v2(body: &str) -> Vec<u8> {
        serde_json::to_vec(&OuterWire {
            format: SYNC_STATE_FORMAT.to_owned(),
            version: SYNC_STATE_EXCHANGE_VERSION,
            body_sha256: checksum_hex(body),
            body: body.to_owned(),
        })
        .unwrap()
    }

    fn exchange_body_of(state: &SyncState) -> String {
        outer_of(&state.encode_exchange_record().unwrap()).body
    }

    fn retained_wire(entry: &RetainedPrevious) -> RetainedWire {
        RetainedWire {
            exchange_id: entry.exchange_id.hyphenated().to_string(),
            fingerprint: entry.fingerprint.to_hex(),
            revision: entry.revision,
            object_anchor: HEXLOWER.encode(&entry.object_anchor.0),
            directory_anchor: HEXLOWER.encode(&entry.directory_anchor.0),
        }
    }

    fn forge_exchange_with(mutate: impl FnOnce(&mut ExchangeBodyWire)) -> Vec<u8> {
        let mut wire = ExchangeBodyWire::from(&exchange_state());
        mutate(&mut wire);
        forge_v2(&serde_json::to_string(&wire).unwrap())
    }

    fn decode_exchange_with(
        mutate: impl FnOnce(&mut ExchangeBodyWire),
    ) -> Result<SyncState, SyncStateDecodeError> {
        SyncState::decode_exchange_record(&forge_exchange_with(mutate))
    }

    fn assert_exchange_round_trips(state: &SyncState) {
        let bytes = state.encode_exchange_record().unwrap();
        let decoded = SyncState::decode_exchange_record(&bytes).unwrap();

        assert_eq!(&decoded, state);
        assert_eq!(decoded.encode_exchange_record().unwrap(), bytes);
    }

    type ExchangeMutation = fn(&mut ExchangeBodyWire);
    type ExchangeInvariantCase = (&'static str, ExchangeMutation, SyncStateError);

    // ---- a. the v1 format is untouched ---------------------------------------------

    #[test]
    fn version_one_bytes_are_identical_with_the_new_fields_empty() {
        assert_eq!(SYNC_STATE_VERSION, 1);
        assert_eq!(SYNC_STATE_EXCHANGE_VERSION, 2);

        for state in [based_state(), unbased_state(), pending_state()] {
            let same =
                with_records(*state.base(), state.pending_push().copied(), None, vec![]).unwrap();

            assert_eq!(same, state);
            assert!(!same.has_exchange_records());
            assert!(same.exchange_intent().is_none());
            assert!(same.retained_previous().is_empty());
            assert_eq!(same.encode().unwrap(), state.encode().unwrap());
        }

        // The pinned v1 literals are still produced, byte for byte, through the
        // new constructor.
        let through_new = with_records(based_base(), based_pending_push(), None, vec![]).unwrap();
        assert_eq!(
            String::from_utf8(through_new.encode().unwrap()).unwrap(),
            GOLDEN_PENDING
        );
        let through_new =
            with_records(SyncBase::Unbased, unbased_pending_push(), None, vec![]).unwrap();
        assert_eq!(
            String::from_utf8(through_new.encode().unwrap()).unwrap(),
            GOLDEN_UNBASED
        );
    }

    #[test]
    fn the_ordinary_constructor_never_produces_exchange_records() {
        for state in [based_state(), unbased_state(), pending_state()] {
            assert!(!state.has_exchange_records());
            assert!(state.exchange_intent().is_none());
            assert!(state.retained_previous().is_empty());
        }

        // Neither does decoding a version-1 record.
        let decoded = SyncState::decode(GOLDEN_PENDING.as_bytes()).unwrap();
        assert!(!decoded.has_exchange_records());
    }

    // ---- b. version 2 round trips ----------------------------------------------------

    #[test]
    fn exchange_records_round_trip() {
        let exchange_only = exchange_only_state();
        let decoded =
            SyncState::decode_exchange_record(&exchange_only.encode_exchange_record().unwrap())
                .unwrap();
        assert_eq!(decoded, exchange_only);
        assert_eq!(decoded.exchange_intent(), Some(&exchange_intent()));
        assert!(decoded.retained_previous().is_empty());
        assert!(decoded.has_exchange_records());

        let one = retained_only_state();
        let decoded =
            SyncState::decode_exchange_record(&one.encode_exchange_record().unwrap()).unwrap();
        assert_eq!(decoded, one);
        assert_eq!(decoded.retained_previous(), &[retained_a()]);
        assert!(decoded.exchange_intent().is_none());
        assert!(decoded.has_exchange_records());

        let both = exchange_state();
        let decoded =
            SyncState::decode_exchange_record(&both.encode_exchange_record().unwrap()).unwrap();
        assert_eq!(decoded, both);
        assert_eq!(decoded.exchange_intent(), Some(&exchange_intent()));
        assert_eq!(decoded.retained_previous(), &[retained_a()]);

        for state in [exchange_only, one, both] {
            assert_exchange_round_trips(&state);
        }
    }

    #[test]
    fn eight_retained_entries_round_trip_in_the_given_order() {
        assert_eq!(MAX_RETAINED_PREVIOUS, 8);

        // Deliberately not sorted: the order is preserved exactly.
        let entries: Vec<RetainedPrevious> = (0..8).rev().map(retained_n).collect();
        let ids: Vec<Uuid> = entries.iter().map(RetainedPrevious::exchange_id).collect();

        let state = with_records(based_base(), None, None, entries).unwrap();
        let decoded =
            SyncState::decode_exchange_record(&state.encode_exchange_record().unwrap()).unwrap();

        assert_eq!(decoded, state);
        assert_eq!(decoded.retained_previous().len(), 8);
        assert_eq!(
            decoded
                .retained_previous()
                .iter()
                .map(RetainedPrevious::exchange_id)
                .collect::<Vec<_>>(),
            ids
        );
    }

    #[test]
    fn a_state_without_exchange_records_also_round_trips_through_the_exchange_codec() {
        for state in [based_state(), unbased_state(), pending_state()] {
            assert_exchange_round_trips(&state);

            let bytes = state.encode_exchange_record().unwrap();
            let outer = outer_of(&bytes);
            assert_eq!(outer.version, SYNC_STATE_EXCHANGE_VERSION);
            assert!(outer.body.contains("\"exchange\":null"));
            assert!(outer.body.contains("\"retained_previous\":[]"));
        }
    }

    #[test]
    fn the_exchange_record_golden_is_pinned() {
        let bytes = exchange_state().encode_exchange_record().unwrap();

        assert_eq!(String::from_utf8(bytes).unwrap(), GOLDEN_EXCHANGE);
        assert_eq!(
            SyncState::decode_exchange_record(GOLDEN_EXCHANGE.as_bytes()).unwrap(),
            exchange_state()
        );

        // Version 2 extends the version-1 body; the existing fields keep their
        // exact bytes and order.
        let v1_body = outer_of(GOLDEN_PENDING.as_bytes()).body;
        let v2_body = outer_of(GOLDEN_EXCHANGE.as_bytes()).body;
        assert!(v2_body.starts_with(&v1_body[..v1_body.len() - 1]));
        assert!(v2_body.ends_with("}]}"));
    }

    // ---- i. determinism --------------------------------------------------------------

    #[test]
    fn exchange_encoding_is_deterministic() {
        for state in [
            exchange_state(),
            exchange_only_state(),
            retained_only_state(),
        ] {
            let first = state.encode_exchange_record().unwrap();
            assert_eq!(state.encode_exchange_record().unwrap(), first);
            assert_eq!(state.clone().encode_exchange_record().unwrap(), first);
        }

        // An independently built, equal state encodes identically.
        assert_eq!(
            exchange_state().encode_exchange_record().unwrap(),
            exchange_state().encode_exchange_record().unwrap()
        );
    }

    // ---- value types -----------------------------------------------------------------

    #[test]
    fn object_anchors_are_one_to_sixty_four_bytes() {
        assert_eq!(MAX_OBJECT_ANCHOR_BYTES, 64);
        assert_eq!(
            ObjectAnchor::new(&[]),
            Err(SyncStateError::InvalidObjectAnchor)
        );
        assert_eq!(
            ObjectAnchor::new(&[0u8; MAX_OBJECT_ANCHOR_BYTES + 1]),
            Err(SyncStateError::InvalidObjectAnchor)
        );
        assert_eq!(ObjectAnchor::new(&[0]).unwrap().as_bytes(), &[0]);
        assert_eq!(
            ObjectAnchor::new(&[7u8; MAX_OBJECT_ANCHOR_BYTES])
                .unwrap()
                .as_bytes(),
            &[7u8; MAX_OBJECT_ANCHOR_BYTES]
        );
    }

    #[test]
    fn exchange_value_types_expose_what_they_were_built_from() {
        let intent = exchange_intent();
        assert_eq!(intent.scheme(), ExchangeScheme::RetainAndPublishV1);
        assert_eq!(intent.target_anchor(), &anchor_run(0x10, 8));
        assert_eq!(
            intent.directory_anchor().as_bytes(),
            &[0xa0, 0xa1, 0xa2, 0xa3]
        );

        let entry = retained_a();
        assert_eq!(entry.exchange_id(), RETAINED_A);
        assert_eq!(entry.fingerprint(), &fp(3));
        assert_eq!(entry.revision(), 5);
        assert_eq!(entry.object_anchor(), &anchor_run(0x20, 16));
        assert_eq!(
            entry.directory_anchor().as_bytes(),
            &[0xb0, 0xb1, 0xb2, 0xb3]
        );

        assert_eq!(
            RetainedPrevious::new(Uuid::nil(), fp(3), 5, anchor_run(0, 4), anchor_run(1, 4)),
            Err(SyncStateError::NilExchangeId)
        );
    }

    // ---- c. every new invariant, through the constructor ------------------------------

    #[test]
    fn constructors_reject_every_exchange_record_violation() {
        let nine: Vec<_> = (0..9).map(retained_n).collect();
        let entry = |id: Uuid, fingerprint: EnvelopeFingerprint, revision: u64| {
            RetainedPrevious::new(
                id,
                fingerprint,
                revision,
                anchor_run(1, 4),
                anchor_run(2, 4),
            )
            .unwrap()
        };

        let cases = [
            (
                "exchange without a pending push",
                with_records(based_base(), None, Some(exchange_intent()), vec![]),
                SyncStateError::ExchangeWithoutPendingPush,
            ),
            (
                "exchange on an unbased state",
                with_records(
                    SyncBase::Unbased,
                    unbased_pending_push(),
                    Some(exchange_intent()),
                    vec![],
                ),
                SyncStateError::ExchangeOnUnbasedState,
            ),
            (
                "retained on an unbased state",
                with_records(
                    SyncBase::Unbased,
                    unbased_pending_push(),
                    None,
                    vec![retained_a()],
                ),
                SyncStateError::RetainedOnUnbasedState,
            ),
            (
                "nine retained entries",
                with_records(based_base(), None, None, nine),
                SyncStateError::RetainedLimitExceeded,
            ),
            (
                "duplicate retained ids",
                with_records(based_base(), None, None, vec![retained_a(), retained_a()]),
                SyncStateError::DuplicateRetainedId,
            ),
            (
                "retained id equals the pending intent id",
                with_records(
                    based_base(),
                    based_pending_push(),
                    None,
                    vec![entry(INTENT, fp(3), 5)],
                ),
                SyncStateError::RetainedIdIsPendingIntent,
            ),
            (
                "retained fingerprint equals the synced one",
                with_records(based_base(), None, None, vec![entry(RETAINED_A, fp(1), 5)]),
                SyncStateError::RetainedIsSyncedVersion,
            ),
            (
                "retained revision equals the synced revision",
                with_records(based_base(), None, None, vec![entry(RETAINED_A, fp(3), 7)]),
                SyncStateError::RetainedRevisionNotBelowSynced,
            ),
            (
                "retained revision above the synced revision",
                with_records(
                    based_base(),
                    None,
                    None,
                    vec![entry(RETAINED_A, fp(3), u64::MAX)],
                ),
                SyncStateError::RetainedRevisionNotBelowSynced,
            ),
        ];

        for (name, result, expected) in cases {
            assert_eq!(result.unwrap_err(), expected, "{name}");
        }
    }

    #[test]
    fn the_exchange_record_rules_add_no_other_restriction() {
        // Exchange and retained entries may coexist, and neither is required.
        assert!(with_records(based_base(), None, None, vec![]).is_ok());
        assert!(with_records(
            based_base(),
            based_pending_push(),
            Some(exchange_intent()),
            vec![]
        )
        .is_ok());
        // A pending push without an exchange intent, with retained entries.
        assert!(with_records(based_base(), based_pending_push(), None, vec![retained_a()]).is_ok());
        // Exactly the limit, and a retained revision one below the synced one.
        let eight: Vec<_> = (0..8).map(retained_n).collect();
        assert!(with_records(based_base(), None, None, eight).is_ok());
        let boundary =
            RetainedPrevious::new(RETAINED_A, fp(3), 6, anchor_run(1, 4), anchor_run(2, 4))
                .unwrap();
        assert!(with_records(based_base(), None, None, vec![boundary]).is_ok());
        // The base-state rules still come first.
        assert_eq!(
            with_records(SyncBase::Unbased, None, None, vec![]).unwrap_err(),
            SyncStateError::UnbasedRequiresInitialPublication
        );
    }

    #[test]
    fn encoding_revalidates_exchange_records() {
        let mut no_pending = based_state();
        no_pending.exchange = Some(exchange_intent());

        let mut too_many = based_state();
        too_many.retained = (0..9).map(retained_n).collect();

        let mut duplicated = based_state();
        duplicated.retained = vec![retained_a(), retained_a()];

        for (name, state, expected) in [
            (
                "exchange without a pending push",
                no_pending,
                SyncStateError::ExchangeWithoutPendingPush,
            ),
            (
                "nine retained entries",
                too_many,
                SyncStateError::RetainedLimitExceeded,
            ),
            (
                "duplicate retained ids",
                duplicated,
                SyncStateError::DuplicateRetainedId,
            ),
        ] {
            assert_eq!(
                state.encode_exchange_record().unwrap_err(),
                SyncStateEncodeError::InvalidState(expected),
                "{name}"
            );
            // Invalid states stay invalid for the ordinary encoder as well.
            assert_eq!(
                state.encode().unwrap_err(),
                SyncStateEncodeError::InvalidState(expected),
                "{name}"
            );
        }
    }

    // ---- c. every new invariant, through the decoder ----------------------------------

    #[test]
    fn the_decoder_enforces_every_exchange_record_invariant() {
        let cases: [ExchangeInvariantCase; 10] = [
            (
                "exchange without a pending push",
                |w| w.pending_push = None,
                SyncStateError::ExchangeWithoutPendingPush,
            ),
            (
                "exchange on an unbased state",
                |w| {
                    w.base = BaseWire::Unbased {};
                    w.pending_push.as_mut().unwrap().baseline = BaselineWire::Absent {};
                },
                SyncStateError::ExchangeOnUnbasedState,
            ),
            (
                "retained on an unbased state",
                |w| {
                    w.base = BaseWire::Unbased {};
                    w.pending_push.as_mut().unwrap().baseline = BaselineWire::Absent {};
                    w.exchange = None;
                },
                SyncStateError::RetainedOnUnbasedState,
            ),
            (
                "nine retained entries",
                |w| w.retained_previous = (0..9).map(|i| retained_wire(&retained_n(i))).collect(),
                SyncStateError::RetainedLimitExceeded,
            ),
            (
                "duplicate retained ids",
                |w| w.retained_previous.push(retained_wire(&retained_a())),
                SyncStateError::DuplicateRetainedId,
            ),
            (
                "retained id equals the pending intent id",
                |w| w.retained_previous[0].exchange_id = INTENT_TEXT.to_owned(),
                SyncStateError::RetainedIdIsPendingIntent,
            ),
            (
                "retained fingerprint equals the synced one",
                |w| w.retained_previous[0].fingerprint = fp(1).to_hex(),
                SyncStateError::RetainedIsSyncedVersion,
            ),
            (
                "retained revision equals the synced revision",
                |w| w.retained_previous[0].revision = 7,
                SyncStateError::RetainedRevisionNotBelowSynced,
            ),
            (
                "retained revision above the synced revision",
                |w| w.retained_previous[0].revision = u64::MAX,
                SyncStateError::RetainedRevisionNotBelowSynced,
            ),
            (
                "nil retained id",
                |w| w.retained_previous[0].exchange_id = Uuid::nil().hyphenated().to_string(),
                SyncStateError::NilExchangeId,
            ),
        ];

        for (name, mutate, expected) in cases {
            assert_eq!(
                decode_exchange_with(mutate).unwrap_err(),
                SyncStateDecodeError::InvalidState(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn the_existing_state_invariants_still_apply_to_exchange_records() {
        let cases: [ExchangeInvariantCase; 3] = [
            (
                "pending baseline mismatch",
                |w| {
                    w.pending_push.as_mut().unwrap().baseline = BaselineWire::Present {
                        fingerprint: fp(9).to_hex(),
                    }
                },
                SyncStateError::PendingBaselineMismatch,
            ),
            (
                "identical locators",
                |w| w.target_locator = w.local_locator.clone(),
                SyncStateError::IdenticalLocators,
            ),
            (
                "nil binding id",
                |w| w.binding_id = Uuid::nil().hyphenated().to_string(),
                SyncStateError::NilBindingId,
            ),
        ];

        for (name, mutate, expected) in cases {
            assert_eq!(
                decode_exchange_with(mutate).unwrap_err(),
                SyncStateDecodeError::InvalidState(expected),
                "{name}"
            );
        }
    }

    // ---- d. strictness ------------------------------------------------------------------

    #[test]
    fn every_missing_exchange_body_field_is_rejected_by_the_parser_itself() {
        let body = exchange_body_of(&exchange_state());

        let paths: &[(&str, &str)] = &[
            ("", "exchange"),
            ("", "retained_previous"),
            ("/exchange", "scheme"),
            ("/exchange", "target_anchor"),
            ("/exchange", "directory_anchor"),
            ("/retained_previous/0", "exchange_id"),
            ("/retained_previous/0", "fingerprint"),
            ("/retained_previous/0", "revision"),
            ("/retained_previous/0", "object_anchor"),
            ("/retained_previous/0", "directory_anchor"),
        ];

        for (parent, key) in paths {
            let damaged = remove_at(&body, parent, key);

            assert!(
                serde_json::from_str::<ExchangeBodyWire>(&damaged).is_err(),
                "parser accepted a body without {parent}/{key}"
            );
            assert_eq!(
                SyncState::decode_exchange_record(&forge_v2(&damaged)).unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "{parent}/{key}"
            );
        }

        // A version-1 body is not a version-2 body: the new keys are required.
        assert_eq!(
            SyncState::decode_exchange_record(&forge_v2(&body_of(&pending_state()))).unwrap_err(),
            SyncStateDecodeError::InvalidBody
        );
    }

    #[test]
    fn unknown_exchange_body_fields_are_rejected_at_every_level() {
        let body = exchange_body_of(&exchange_state());

        let cases = [
            ("{", "{\"extra\":1,"),
            ("\"scheme\"", "\"extra\":1,\"scheme\""),
            ("\"exchange_id\"", "\"extra\":1,\"exchange_id\""),
            (
                "\"directory_anchor\":\"b0b1b2b3\"",
                "\"directory_anchor\":\"b0b1b2b3\",\"extra\":1",
            ),
        ];

        for (from, to) in cases {
            let widened = body.replacen(from, to, 1);
            assert_ne!(widened, body, "{from}");

            assert!(
                serde_json::from_str::<ExchangeBodyWire>(&widened).is_err(),
                "parser accepted an unknown field near {from}"
            );
            assert_eq!(
                SyncState::decode_exchange_record(&forge_v2(&widened)).unwrap_err(),
                SyncStateDecodeError::InvalidBody
            );
        }
    }

    #[test]
    fn a_version_two_body_is_not_accepted_inside_a_version_one_wrapper() {
        // The ordinary decoder keeps its deny_unknown_fields behavior.
        assert_eq!(
            SyncState::decode(&forge(&exchange_body_of(&exchange_state()))).unwrap_err(),
            SyncStateDecodeError::InvalidBody
        );
        assert_eq!(
            SyncState::decode(&forge(&exchange_body_of(&pending_state()))).unwrap_err(),
            SyncStateDecodeError::InvalidBody
        );
    }

    #[test]
    fn an_unknown_exchange_scheme_is_rejected() {
        let body = exchange_body_of(&exchange_state());

        for scheme in [
            "retain_and_publish_v2",
            "RETAIN_AND_PUBLISH_V1",
            "retain_and_publish_v1 ",
            "",
            "replace",
        ] {
            let damaged = replace_once(&body, "retain_and_publish_v1", scheme);

            assert_eq!(
                SyncState::decode_exchange_record(&forge_v2(&damaged)).unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "{scheme:?}"
            );
        }
    }

    #[test]
    fn anchors_must_be_canonical_lowercase_hex_of_one_to_sixty_four_bytes() {
        let too_long = "ab".repeat(MAX_OBJECT_ANCHOR_BYTES + 1);
        assert_eq!(too_long.len(), 130);

        let bad_values = [
            String::new(),
            "a".to_owned(),
            "A0".to_owned(),
            "aB".to_owned(),
            "abc".to_owned(),
            "zz".to_owned(),
            "g0".to_owned(),
            " a0".to_owned(),
            "a0 ".to_owned(),
            "0xa0".to_owned(),
            "a0a0\n".to_owned(),
            "é0".to_owned(),
            too_long,
        ];

        for bad in &bad_values {
            for name in [
                "exchange target",
                "exchange directory",
                "retained object",
                "retained directory",
            ] {
                let bytes = forge_exchange_with(|w| match name {
                    "exchange target" => w.exchange.as_mut().unwrap().target_anchor = bad.clone(),
                    "exchange directory" => {
                        w.exchange.as_mut().unwrap().directory_anchor = bad.clone()
                    }
                    "retained object" => w.retained_previous[0].object_anchor = bad.clone(),
                    _ => w.retained_previous[0].directory_anchor = bad.clone(),
                });

                assert_eq!(
                    SyncState::decode_exchange_record(&bytes).unwrap_err(),
                    SyncStateDecodeError::InvalidBody,
                    "{name}: {bad:?}"
                );
            }
        }

        // The boundaries themselves are fine: 1 byte and 64 bytes.
        for good in ["00".to_owned(), "ab".repeat(MAX_OBJECT_ANCHOR_BYTES)] {
            let decoded = decode_exchange_with(|w| {
                w.exchange.as_mut().unwrap().target_anchor = good.clone();
                w.retained_previous[0].object_anchor = good.clone();
            })
            .unwrap();

            assert_eq!(
                HEXLOWER.encode(
                    decoded
                        .exchange_intent()
                        .unwrap()
                        .target_anchor()
                        .as_bytes()
                ),
                good
            );
        }
    }

    #[test]
    fn exchange_ids_must_be_canonical_lowercase_hyphenated_uuids() {
        assert_ne!(RETAINED_A_TEXT.to_uppercase(), RETAINED_A_TEXT);

        let variants = [
            RETAINED_A_TEXT.to_uppercase(),
            RETAINED_A_TEXT.replace('-', ""),
            format!("{{{RETAINED_A_TEXT}}}"),
            format!("urn:uuid:{RETAINED_A_TEXT}"),
            format!(" {RETAINED_A_TEXT}"),
            format!("{RETAINED_A_TEXT} "),
            RETAINED_A_TEXT[..35].to_owned(),
            "not-a-uuid".to_owned(),
            String::new(),
        ];

        for variant in variants {
            assert_eq!(
                decode_exchange_with(|w| w.retained_previous[0].exchange_id = variant.clone())
                    .unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "{variant:?}"
            );
        }

        // The nil id is canonical text, so it reaches the model and is refused
        // there (asserted with the other invariants as well).
        assert_eq!(
            decode_exchange_with(|w| {
                w.retained_previous[0].exchange_id = Uuid::nil().hyphenated().to_string()
            })
            .unwrap_err(),
            SyncStateDecodeError::InvalidState(SyncStateError::NilExchangeId)
        );
    }

    #[test]
    fn retained_fingerprints_and_revisions_follow_the_existing_rules() {
        let good = fp(3).to_hex();

        for bad in [
            good.to_uppercase(),
            good[..63].to_owned(),
            format!("{good}0"),
            format!("0x{}", &good[2..]),
            format!("{}g", &good[..63]),
            String::new(),
        ] {
            assert_eq!(
                decode_exchange_with(|w| w.retained_previous[0].fingerprint = bad.clone())
                    .unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "{bad:?}"
            );
        }

        let body = exchange_body_of(&exchange_state());
        for bad in [
            "-1",
            "1.5",
            "5.0",
            "\"5\"",
            "null",
            "05",
            "18446744073709551616",
        ] {
            let damaged = replace_once(&body, "\"revision\":5", &format!("\"revision\":{bad}"));

            assert_eq!(
                SyncState::decode_exchange_record(&forge_v2(&damaged)).unwrap_err(),
                SyncStateDecodeError::InvalidBody,
                "revision {bad}"
            );
        }
    }

    #[test]
    fn a_non_canonical_exchange_body_is_rejected_even_with_a_valid_checksum() {
        let body = exchange_body_of(&exchange_state());

        let reordered =
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&body).unwrap())
                .unwrap();
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        )
        .unwrap();
        assert_ne!(reordered, body);

        // `retained_previous` before `exchange`: same content, different order.
        let swapped = {
            let exchange_start = body.find(",\"exchange\":").unwrap();
            let retained_start = body.find(",\"retained_previous\":").unwrap();
            let exchange_part = &body[exchange_start..retained_start];
            let retained_part = &body[retained_start..body.len() - 1];
            format!(
                "{}{}{}}}",
                &body[..exchange_start],
                retained_part,
                exchange_part
            )
        };
        assert_ne!(swapped, body);

        for non_canonical in [
            reordered,
            pretty,
            swapped,
            format!(" {body}"),
            format!("{body}\n"),
        ] {
            assert_eq!(
                SyncState::decode_exchange_record(&forge_v2(&non_canonical)).unwrap_err(),
                SyncStateDecodeError::InvalidBody
            );
        }
    }

    #[test]
    fn flipping_any_protected_exchange_body_byte_is_a_checksum_mismatch() {
        let bytes = exchange_state().encode_exchange_record().unwrap();
        let outer = outer_of(&bytes);
        assert!(outer.body.is_ascii());

        for index in 0..outer.body.len() {
            let mut corrupted = outer.body.clone().into_bytes();
            corrupted[index] ^= 0x01;

            let tampered = serde_json::to_vec(&OuterWire {
                format: outer.format.clone(),
                version: outer.version,
                body_sha256: outer.body_sha256.clone(),
                body: String::from_utf8(corrupted).unwrap(),
            })
            .unwrap();

            assert_eq!(
                SyncState::decode_exchange_record(&tampered).unwrap_err(),
                SyncStateDecodeError::ChecksumMismatch,
                "flip at body byte {index}"
            );
        }
    }

    #[test]
    fn exchange_wrapper_damage_is_classified_like_the_ordinary_one() {
        let bytes = exchange_state().encode_exchange_record().unwrap();
        let original = outer_of(&bytes).body_sha256;

        let mut digits = original.clone().into_bytes();
        digits[0] = if digits[0] == b'0' { b'1' } else { b'0' };
        let changed = String::from_utf8(digits).unwrap();
        assert_eq!(
            SyncState::decode_exchange_record(
                &with_outer(&bytes, |o| o.body_sha256 = changed.clone())
            )
            .unwrap_err(),
            SyncStateDecodeError::ChecksumMismatch
        );

        for bad in [String::new(), original.to_uppercase(), "g".repeat(64)] {
            assert_eq!(
                SyncState::decode_exchange_record(
                    &with_outer(&bytes, |o| o.body_sha256 = bad.clone())
                )
                .unwrap_err(),
                SyncStateDecodeError::Malformed
            );
        }

        let mut extra = json(&bytes);
        extra["extra"] = serde_json::json!(1);
        assert_eq!(
            SyncState::decode_exchange_record(&serde_json::to_vec(&extra).unwrap()).unwrap_err(),
            SyncStateDecodeError::Malformed
        );

        for length in 0..bytes.len() {
            assert!(
                SyncState::decode_exchange_record(&bytes[..length]).is_err(),
                "a {length}-byte prefix was accepted"
            );
        }

        assert_eq!(
            SyncState::decode_exchange_record(&vec![b' '; MAX_SYNC_STATE_BYTES + 1]).unwrap_err(),
            SyncStateDecodeError::TooLarge
        );
        assert_eq!(
            SyncState::decode_exchange_record(&vec![b' '; MAX_SYNC_STATE_BYTES]).unwrap_err(),
            SyncStateDecodeError::Malformed
        );
    }

    // ---- e. version routing --------------------------------------------------------------

    #[test]
    fn the_ordinary_decoder_and_loader_still_refuse_version_two() {
        for state in [exchange_state(), exchange_only_state(), based_state()] {
            let bytes = state.encode_exchange_record().unwrap();

            assert_eq!(
                SyncState::decode(&bytes).unwrap_err(),
                SyncStateDecodeError::UnsupportedVersion
            );
            assert_eq!(
                SyncStateLoad::from_bytes(&bytes),
                SyncStateLoad::UnsupportedVersion
            );
        }

        assert_eq!(
            SyncState::decode(GOLDEN_EXCHANGE.as_bytes()).unwrap_err(),
            SyncStateDecodeError::UnsupportedVersion
        );
        assert_eq!(
            SyncStateLoad::from_bytes(GOLDEN_EXCHANGE.as_bytes()),
            SyncStateLoad::UnsupportedVersion
        );
    }

    #[test]
    fn the_exchange_decoder_accepts_version_two_only() {
        let v2 = exchange_state().encode_exchange_record().unwrap();

        // A genuine version-1 record.
        assert_eq!(
            SyncState::decode_exchange_record(&pending_state().encode().unwrap()).unwrap_err(),
            SyncStateDecodeError::UnsupportedVersion
        );
        assert_eq!(
            SyncState::decode_exchange_record(GOLDEN_PENDING.as_bytes()).unwrap_err(),
            SyncStateDecodeError::UnsupportedVersion
        );

        for version in [
            json_number(0),
            json_number(1),
            json_number(3),
            json_number(1_000),
            serde_json::json!(u64::MAX),
        ] {
            let mut value = json(&v2);
            value["version"] = version.clone();

            assert_eq!(
                SyncState::decode_exchange_record(&serde_json::to_vec(&value).unwrap())
                    .unwrap_err(),
                SyncStateDecodeError::UnsupportedVersion,
                "{version}"
            );
        }

        // A future version may add fields; it is still "unsupported version".
        let future =
            br#"{"format":"localvault-sync-state","version":3,"anything":[1,2],"body":42}"#;
        assert_eq!(
            SyncState::decode_exchange_record(future).unwrap_err(),
            SyncStateDecodeError::UnsupportedVersion
        );

        for version in [
            serde_json::json!("2"),
            serde_json::json!(-2),
            serde_json::json!(2.0),
            serde_json::json!(null),
        ] {
            let mut value = json(&v2);
            value["version"] = version.clone();

            assert_eq!(
                SyncState::decode_exchange_record(&serde_json::to_vec(&value).unwrap())
                    .unwrap_err(),
                SyncStateDecodeError::Malformed,
                "{version}"
            );
        }
    }

    #[test]
    fn a_foreign_format_is_unsupported_for_the_exchange_decoder_too() {
        let v2 = exchange_state().encode_exchange_record().unwrap();

        for format in ["", "localvault-vault", "LocalVault-Sync-State"] {
            assert_eq!(
                SyncState::decode_exchange_record(
                    &with_outer(&v2, |o| o.format = format.to_owned())
                )
                .unwrap_err(),
                SyncStateDecodeError::UnsupportedFormat,
                "{format:?}"
            );
        }

        // A wrong format outranks the version.
        assert_eq!(
            SyncState::decode_exchange_record(br#"{"format":"other","version":3}"#).unwrap_err(),
            SyncStateDecodeError::UnsupportedFormat
        );
        assert_eq!(
            SyncState::decode_exchange_record(br#"{"format":"other","version":2}"#).unwrap_err(),
            SyncStateDecodeError::UnsupportedFormat
        );
    }

    // ---- f. the ordinary encoder refuses states with exchange records --------------------

    #[test]
    fn the_ordinary_encoder_refuses_states_with_exchange_records() {
        for (name, state) in [
            ("exchange and retained", exchange_state()),
            ("exchange only", exchange_only_state()),
            ("retained only", retained_only_state()),
        ] {
            assert!(state.has_exchange_records(), "{name}");
            assert_eq!(
                state.encode().unwrap_err(),
                SyncStateEncodeError::InvalidState(
                    SyncStateError::ExchangeRecordsRequireExchangeFormat
                ),
                "{name}"
            );
        }
    }

    // ---- h. worst-case size ----------------------------------------------------------------

    #[test]
    fn worst_case_exchange_record_fits_the_size_bound() {
        // Every escaped character is the 4x worst case (escaped in the body, then
        // again in the string that carries it); every number has 20 digits; every
        // anchor is the longest allowed; the list is full.
        let top = u64::MAX;
        let checkpoint =
            SyncCheckpoint::new(fp(1), top - 1, RemoteHighWater::new(top - 1)).unwrap();
        let pending = PendingPush::new(
            INTENT,
            PushIntent::new(PushBaseline::Present(fp(1)), fp(2)).unwrap(),
            top,
        )
        .unwrap();
        let retained: Vec<RetainedPrevious> = (0..MAX_RETAINED_PREVIOUS as u8)
            .map(|index| {
                RetainedPrevious::new(
                    Uuid::from_u128(0x7000_0000_0000_4000_8000_0000_0000_0000 + u128::from(index)),
                    fp(100 + index),
                    top - 2,
                    anchor_run(index, MAX_OBJECT_ANCHOR_BYTES),
                    anchor_run(index.wrapping_add(0x80), MAX_OBJECT_ANCHOR_BYTES),
                )
                .unwrap()
            })
            .collect();

        // Two different locators, both of the longest length, all escaped.
        let local = "\\".repeat(MAX_LOCATOR_BYTES);
        let target = format!("{}\"", "\\".repeat(MAX_LOCATOR_BYTES - 1));

        let state = SyncState::new_with_exchange_records(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(&local),
            loc(&target),
            SyncBase::Based(checkpoint),
            Some(pending),
            Some(ExchangeIntent::new(
                ExchangeScheme::RetainAndPublishV1,
                anchor_run(0xc0, MAX_OBJECT_ANCHOR_BYTES),
                anchor_run(0xd0, MAX_OBJECT_ANCHOR_BYTES),
            )),
            retained,
        )
        .unwrap();

        let bytes = state.encode_exchange_record().unwrap();

        assert!(bytes.len() <= MAX_SYNC_STATE_BYTES);
        assert!(bytes.len() > 2 * MAX_LOCATOR_BYTES * 4, "escaping applied");
        assert_eq!(state.retained_previous().len(), MAX_RETAINED_PREVIOUS);
        assert_eq!(SyncState::decode_exchange_record(&bytes).unwrap(), state);
    }

    // ---- j. redaction -------------------------------------------------------------------------

    #[test]
    fn debug_output_never_shows_anchor_bytes() {
        let target = ObjectAnchor::new(&[0xab; MAX_OBJECT_ANCHOR_BYTES]).unwrap();
        let directory = ObjectAnchor::new(&[0xcd; MAX_OBJECT_ANCHOR_BYTES]).unwrap();
        let object = ObjectAnchor::new(&[0xef; MAX_OBJECT_ANCHOR_BYTES]).unwrap();
        let retained_directory = ObjectAnchor::new(&[0x9a; MAX_OBJECT_ANCHOR_BYTES]).unwrap();

        let intent = ExchangeIntent::new(
            ExchangeScheme::RetainAndPublishV1,
            target.clone(),
            directory.clone(),
        );
        let entry = RetainedPrevious::new(
            RETAINED_A,
            fp(3),
            5,
            object.clone(),
            retained_directory.clone(),
        )
        .unwrap();
        let state = with_records(
            based_base(),
            based_pending_push(),
            Some(intent.clone()),
            vec![entry.clone()],
        )
        .unwrap();

        assert_eq!(format!("{target:?}"), "ObjectAnchor(<redacted>)");

        let anchors = [&target, &directory, &object, &retained_directory];
        let renderings = [
            format!("{target:?}"),
            format!("{intent:?}"),
            format!("{intent:#?}"),
            format!("{entry:?}"),
            format!("{entry:#?}"),
            format!("{state:?}"),
            format!("{state:#?}"),
            format!("{:?}", SyncStateLoad::Loaded(Box::new(state.clone()))),
        ];

        for text in &renderings {
            assert_redacted(text);
            for anchor in anchors {
                let lower = HEXLOWER.encode(anchor.as_bytes());
                assert!(!text.contains(&lower), "{lower} leaked into {text}");
                assert!(!text.contains(&lower.to_uppercase()));
                // Neither as a byte list.
                assert!(!text.contains(&format!("{}, {}", anchor.0[0], anchor.0[0])));
            }
        }

        // The encoded record does carry them (it is a codec); Debug does not.
        let encoded = String::from_utf8(state.encode_exchange_record().unwrap()).unwrap();
        assert!(encoded.contains(&HEXLOWER.encode(target.as_bytes())));
    }

    #[test]
    fn exchange_errors_never_echo_input() {
        let secret = "SECRET-ANCHOR-TEXT".to_owned();
        let mut texts: Vec<String> = Vec::new();

        for result in [
            decode_exchange_with(|w| w.exchange.as_mut().unwrap().target_anchor = secret.clone()),
            decode_exchange_with(|w| w.exchange.as_mut().unwrap().scheme = secret.clone()),
            decode_exchange_with(|w| w.retained_previous[0].exchange_id = secret.clone()),
            decode_exchange_with(|w| w.retained_previous[0].fingerprint = secret.clone()),
            SyncState::decode_exchange_record(
                format!("{{\"format\":\"{secret}\",\"version\":2}}").as_bytes(),
            ),
            SyncState::decode_exchange_record(&with_outer(
                &exchange_state().encode_exchange_record().unwrap(),
                |o| o.body.push_str(&secret),
            )),
        ] {
            let error = result.unwrap_err();
            texts.push(format!("{error:?}"));
            texts.push(error.to_string());
        }

        for error in [
            SyncStateError::InvalidObjectAnchor,
            SyncStateError::NilExchangeId,
            SyncStateError::ExchangeWithoutPendingPush,
            SyncStateError::ExchangeOnUnbasedState,
            SyncStateError::RetainedOnUnbasedState,
            SyncStateError::RetainedLimitExceeded,
            SyncStateError::DuplicateRetainedId,
            SyncStateError::RetainedIdIsPendingIntent,
            SyncStateError::RetainedIsSyncedVersion,
            SyncStateError::RetainedRevisionNotBelowSynced,
            SyncStateError::ExchangeRecordsRequireExchangeFormat,
            SyncStateError::ExchangeRecordsUnsupportedByTransition,
        ] {
            assert!(!error.to_string().is_empty());
            texts.push(format!("{error:?}"));
            texts.push(error.to_string());
        }

        for text in texts {
            assert!(!text.contains("SECRET-ANCHOR-TEXT"), "{text}");
            assert_redacted(&text);
        }
    }
}

/// Stage 1U-4 A2b tests for the pure transitions. Evidence comes from real
/// (synthetic) sealed envelopes through `inspect_remote_bytes` /
/// `inspect_local_bytes`; no committed fixture is read or modified.
#[cfg(test)]
mod transition_tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::sync::{inspect_local_bytes, inspect_remote_bytes};
    use crate::vault::{
        data::{
            VaultData, VaultEntry, LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        },
        format::{create_envelope_with_key, reseal_envelope, SecretKey, VaultEnvelope},
    };

    const LOCAL: &str = "synthetic/local/LOCAL-MARKER.lvault";
    const TARGET: &str = "synthetic/remote/TARGET-MARKER.lvault";
    const OTHER: &str = "synthetic/other/OTHER-MARKER.lvault";

    const VAULT_ID: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    const FOREIGN_VAULT_ID: Uuid = Uuid::from_u128(0x0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_0f0f);
    const BINDING: Uuid = Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555);
    const INTENT: Uuid = Uuid::from_u128(0xaaaa_aaaa_bbbb_4ccc_8ddd_eeee_eeee_eeee);

    const MASTER: &str = "transition-test-only-master-password";
    const SECRET: &str = "TRANSITION_TEST_ONLY_SECRET";
    const NOW_MS: i64 = 1_700_000_000_000;

    // ---- evidence rig -------------------------------------------------------

    struct Rig {
        template: VaultEnvelope,
        key: SecretKey,
        base: VaultData,
    }

    impl Rig {
        fn build(vault_id: Uuid) -> Self {
            let mut base = VaultData::new(NOW_MS).unwrap();
            base.vault_id = vault_id;

            let mut entry = VaultEntry::new("Base Entry", NOW_MS).unwrap();
            entry.password = SECRET.to_owned();
            base.entries.push(entry);

            base.revision = 1;
            base.validate().unwrap();

            let (template, key) =
                create_envelope_with_key(MASTER, &serde_json::to_vec(&base).unwrap()).unwrap();

            Self {
                template,
                key,
                base,
            }
        }

        fn seal(&self, data: &VaultData) -> VaultEnvelope {
            reseal_envelope(
                &self.template,
                &self.key,
                &serde_json::to_vec(data).unwrap(),
            )
            .unwrap()
        }

        /// Raw bytes of a fresh envelope. Encryption is randomized, so every call
        /// returns different bytes; tests keep what they need.
        fn raw_with(&self, revision: u64, title: &str) -> Vec<u8> {
            let mut data = self.base.clone();
            data.revision = revision;
            data.entries[0].title = title.to_owned();

            serde_json::to_vec(&self.seal(&data)).unwrap()
        }

        fn raw_at(&self, revision: u64) -> Vec<u8> {
            self.raw_with(revision, "Base Entry")
        }

        fn legacy_raw(&self, schema: u16) -> Vec<u8> {
            let mut data = self.base.clone();
            data.schema_version = schema;
            data.revision = 0;

            serde_json::to_vec(&self.seal(&data)).unwrap()
        }
    }

    fn rig() -> &'static Rig {
        static RIG: OnceLock<Rig> = OnceLock::new();
        RIG.get_or_init(|| Rig::build(VAULT_ID))
    }

    fn foreign() -> &'static Rig {
        static RIG: OnceLock<Rig> = OnceLock::new();
        RIG.get_or_init(|| Rig::build(FOREIGN_VAULT_ID))
    }

    /// Fixed envelope versions shared by every test.
    struct Versions {
        s7: Vec<u8>,
        s7_resealed: Vec<u8>,
        s7_rewrapped: Vec<u8>,
        s7_pretty: Vec<u8>,
        s7_conflict: Vec<u8>,
        l5: Vec<u8>,
        l6: Vec<u8>,
        l8: Vec<u8>,
        t9: Vec<u8>,
        l10: Vec<u8>,
        r12: Vec<u8>,
        legacy: Vec<u8>,
    }

    fn v() -> &'static Versions {
        static VERSIONS: OnceLock<Versions> = OnceLock::new();
        VERSIONS.get_or_init(|| {
            let rig = rig();
            let s7 = rig.raw_at(7);

            let mut rewrapped: VaultEnvelope = serde_json::from_slice(&s7).unwrap();
            rewrapped.kdf_salt[0] ^= 0x01;

            let parsed: VaultEnvelope = serde_json::from_slice(&s7).unwrap();

            Versions {
                s7_resealed: rig.raw_at(7),
                s7_rewrapped: serde_json::to_vec(&rewrapped).unwrap(),
                s7_pretty: serde_json::to_vec_pretty(&parsed).unwrap(),
                s7_conflict: rig.raw_with(7, "Conflicting Entry"),
                l5: rig.raw_at(5),
                l6: rig.raw_at(6),
                l8: rig.raw_at(8),
                t9: rig.raw_at(9),
                l10: rig.raw_at(10),
                r12: rig.raw_at(12),
                legacy: rig.legacy_raw(PRE_REVISION_VAULT_DATA_SCHEMA_VERSION),
                s7,
            }
        })
    }

    fn fp_of(raw: &[u8]) -> EnvelopeFingerprint {
        EnvelopeFingerprint::of_bytes(raw)
    }

    fn bound(local: &[u8], remote: &[u8]) -> BoundInspection {
        inspect_remote_bytes(&rig().key, VAULT_ID, local, remote, None).unwrap()
    }

    fn snapshot(local: &[u8]) -> LocalSnapshot {
        inspect_local_bytes(&rig().key, VAULT_ID, local).unwrap()
    }

    // ---- state builders -----------------------------------------------------

    fn salt(seed: u8) -> [u8; BINDING_SALT_LEN] {
        std::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    fn loc(value: &str) -> Locator {
        Locator::new(value).unwrap()
    }

    fn locs() -> (Locator, Locator) {
        (loc(LOCAL), loc(TARGET))
    }

    fn tag() -> VaultBindingTag {
        VaultBindingTag::derive(salt(0), VAULT_ID).unwrap()
    }

    fn checkpoint(synced: &[u8], revision: u64, high_water: u64) -> SyncCheckpoint {
        SyncCheckpoint::new(fp_of(synced), revision, RemoteHighWater::new(high_water)).unwrap()
    }

    fn pending(baseline: PushBaseline, intended: &[u8], revision: u64) -> PendingPush {
        PendingPush::new(
            INTENT,
            PushIntent::new(baseline, fp_of(intended)).unwrap(),
            revision,
        )
        .unwrap()
    }

    fn build(base: SyncBase, pending_push: Option<PendingPush>) -> SyncState {
        SyncState::new(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(LOCAL),
            loc(TARGET),
            base,
            pending_push,
        )
        .unwrap()
    }

    /// Synced S (revision 7), high-water 7, nothing pending.
    fn based() -> SyncState {
        build(SyncBase::Based(checkpoint(&v().s7, 7, 7)), None)
    }

    /// As [`based`], with a push of L (revision 8) pending.
    fn based_pending() -> SyncState {
        build(
            SyncBase::Based(checkpoint(&v().s7, 7, 7)),
            Some(pending(PushBaseline::Present(fp_of(&v().s7)), &v().l8, 8)),
        )
    }

    /// An initial publication of L (revision 8) pending.
    fn unbased_pending() -> SyncState {
        build(
            SyncBase::Unbased,
            Some(pending(PushBaseline::Absent, &v().l8, 8)),
        )
    }

    // ---- transition shorthands ---------------------------------------------

    fn push(state: &SyncState, remote: RemoteEvidence<'_>) -> Result<SyncState, TransitionRefusal> {
        let (l, t) = locs();
        begin_push(state, &l, &t, remote, INTENT)
    }

    fn reconcile(
        state: &SyncState,
        remote: RemoteEvidence<'_>,
    ) -> Result<PushResolution, TransitionRefusal> {
        let (l, t) = locs();
        reconcile_pending_push(state, &l, &t, remote)
    }

    fn observe(
        state: &SyncState,
        observation: &BoundInspection,
    ) -> Result<HighWaterOutcome, TransitionRefusal> {
        let (l, t) = locs();
        record_remote_observation(state, &l, &t, observation)
    }

    fn new_binding<'a>(local: &'a Locator, target: &'a Locator) -> NewBinding<'a> {
        NewBinding {
            binding_id: BINDING,
            tag_salt: salt(0),
            local_locator: local,
            target_locator: target,
        }
    }

    fn publish(
        prior: &SyncStateLoad,
        approval: UserApproval,
        remote: RemoteObservation,
        local: &LocalSnapshot,
    ) -> Result<SyncState, TransitionRefusal> {
        let (l, t) = locs();
        plan_initial_publication(prior, approval, remote, local, &new_binding(&l, &t), INTENT)
    }

    fn bind(
        prior: &SyncStateLoad,
        approval: UserApproval,
        remote: RemoteEvidence<'_>,
    ) -> Result<SyncState, TransitionRefusal> {
        let (l, t) = locs();
        bind_identical_remote(prior, approval, remote, &new_binding(&l, &t))
    }

    fn checkpoint_of(state: &SyncState) -> SyncCheckpoint {
        match state.base() {
            SyncBase::Based(checkpoint) => *checkpoint,
            SyncBase::Unbased => panic!("expected a based state"),
        }
    }

    fn assert_round_trips(state: &SyncState) {
        assert_eq!(&SyncState::decode(&state.encode().unwrap()).unwrap(), state);
    }

    // ---- initial binding: confirmed absent remote ---------------------------

    #[test]
    fn a_confirmed_absent_remote_yields_an_unbased_state_with_a_pending_initial_publication() {
        let local = snapshot(&v().l8);
        let (l, t) = locs();

        let state = publish(
            &SyncStateLoad::NotConfigured,
            UserApproval::Granted,
            RemoteObservation::Absent,
            &local,
        )
        .unwrap();

        assert_eq!(state.base(), &SyncBase::Unbased);
        assert_eq!(state.binding_id().uuid(), BINDING);
        assert_eq!(state.local_locator(), &l);
        assert_eq!(state.target_locator(), &t);

        let pending = state.pending_push().unwrap();
        assert_eq!(pending.intent_id(), INTENT);
        assert_eq!(pending.intent().baseline(), &PushBaseline::Absent);
        assert_eq!(pending.intent().intended(), &fp_of(&v().l8));
        assert_eq!(pending.intended_revision(), 8);

        // The tag follows the authenticated identity of the evidence.
        assert!(state.vault_tag().matches_vault(VAULT_ID));
        assert!(!state.vault_tag().matches_vault(FOREIGN_VAULT_ID));

        assert_round_trips(&state);
    }

    #[test]
    fn the_binding_identity_comes_from_the_evidence_not_from_the_caller() {
        let foreign_raw = foreign().raw_at(2);
        let foreign_snapshot =
            inspect_local_bytes(&foreign().key, FOREIGN_VAULT_ID, &foreign_raw).unwrap();

        let state = publish(
            &SyncStateLoad::NotConfigured,
            UserApproval::Granted,
            RemoteObservation::Absent,
            &foreign_snapshot,
        )
        .unwrap();

        assert!(state.vault_tag().matches_vault(FOREIGN_VAULT_ID));
        assert!(!state.vault_tag().matches_vault(VAULT_ID));
    }

    #[test]
    fn initial_publication_of_revision_zero_is_a_valid_counter() {
        let raw = rig().raw_at(0);

        let state = publish(
            &SyncStateLoad::NotConfigured,
            UserApproval::Granted,
            RemoteObservation::Absent,
            &snapshot(&raw),
        )
        .unwrap();

        assert_eq!(state.pending_push().unwrap().intended_revision(), 0);
    }

    #[test]
    fn initial_publication_refuses_every_other_remote_observation() {
        let local = snapshot(&v().l8);

        for (remote, expected) in [
            (
                RemoteObservation::Present(fp_of(&v().s7)),
                TransitionRefusal::RemoteNotAbsent,
            ),
            (
                RemoteObservation::Present(fp_of(&v().l8)),
                TransitionRefusal::RemoteNotAbsent,
            ),
            (
                RemoteObservation::Unavailable,
                TransitionRefusal::RemoteUnavailable,
            ),
        ] {
            assert_eq!(
                publish(
                    &SyncStateLoad::NotConfigured,
                    UserApproval::Granted,
                    remote,
                    &local
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn initial_publication_refuses_a_withheld_approval() {
        assert_eq!(
            publish(
                &SyncStateLoad::NotConfigured,
                UserApproval::Withheld,
                RemoteObservation::Absent,
                &snapshot(&v().l8),
            ),
            Err(TransitionRefusal::ApprovalWithheld)
        );
    }

    #[test]
    fn initial_publication_refuses_a_legacy_unversioned_payload() {
        for schema in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let raw = rig().legacy_raw(schema);

            assert_eq!(
                publish(
                    &SyncStateLoad::NotConfigured,
                    UserApproval::Granted,
                    RemoteObservation::Absent,
                    &snapshot(&raw),
                ),
                Err(TransitionRefusal::LocalUnversioned)
            );
        }
    }

    #[test]
    fn initial_publication_validates_the_caller_supplied_identity_material() {
        let local = snapshot(&v().l8);
        let (l, t) = locs();

        let mut nil_binding = new_binding(&l, &t);
        nil_binding.binding_id = Uuid::nil();

        assert_eq!(
            plan_initial_publication(
                &SyncStateLoad::NotConfigured,
                UserApproval::Granted,
                RemoteObservation::Absent,
                &local,
                &nil_binding,
                INTENT,
            ),
            Err(TransitionRefusal::InvalidState(
                SyncStateError::NilBindingId
            ))
        );

        assert_eq!(
            plan_initial_publication(
                &SyncStateLoad::NotConfigured,
                UserApproval::Granted,
                RemoteObservation::Absent,
                &local,
                &new_binding(&l, &l),
                INTENT,
            ),
            Err(TransitionRefusal::InvalidState(
                SyncStateError::IdenticalLocators
            ))
        );

        assert_eq!(
            plan_initial_publication(
                &SyncStateLoad::NotConfigured,
                UserApproval::Granted,
                RemoteObservation::Absent,
                &local,
                &new_binding(&l, &t),
                Uuid::nil(),
            ),
            Err(TransitionRefusal::InvalidState(SyncStateError::NilIntentId))
        );
    }

    // ---- initial binding: identical existing remote -------------------------

    #[test]
    fn an_identical_authenticated_remote_binds_at_its_revision() {
        let evidence = bound(&v().s7, &v().s7);

        let state = bind(
            &SyncStateLoad::NotConfigured,
            UserApproval::Granted,
            RemoteEvidence::Inspected(&evidence),
        )
        .unwrap();

        let checkpoint = checkpoint_of(&state);
        assert_eq!(checkpoint.synced(), &fp_of(&v().s7));
        assert_eq!(checkpoint.synced_revision(), 7);
        assert_eq!(checkpoint.high_water(), RemoteHighWater::new(7));
        assert!(state.pending_push().is_none());
        assert!(state.vault_tag().matches_vault(VAULT_ID));
        assert!(!state.vault_tag().matches_vault(FOREIGN_VAULT_ID));

        assert_round_trips(&state);
    }

    #[test]
    fn identical_binding_requires_byte_identity_not_just_equal_content() {
        // Same authenticated content, different bytes: refused.
        for other in [&v().s7_resealed, &v().s7_rewrapped, &v().s7_pretty] {
            let evidence = bound(&v().s7, other);

            assert_eq!(
                bind(
                    &SyncStateLoad::NotConfigured,
                    UserApproval::Granted,
                    RemoteEvidence::Inspected(&evidence),
                ),
                Err(TransitionRefusal::RemoteDiffers)
            );
        }

        // A different version altogether.
        let evidence = bound(&v().l8, &v().s7);

        assert_eq!(
            bind(
                &SyncStateLoad::NotConfigured,
                UserApproval::Granted,
                RemoteEvidence::Inspected(&evidence),
            ),
            Err(TransitionRefusal::RemoteDiffers)
        );
    }

    #[test]
    fn identical_binding_refuses_absent_and_unavailable_remotes() {
        assert_eq!(
            bind(
                &SyncStateLoad::NotConfigured,
                UserApproval::Granted,
                RemoteEvidence::Absent
            ),
            Err(TransitionRefusal::RemoteAbsent)
        );
        assert_eq!(
            bind(
                &SyncStateLoad::NotConfigured,
                UserApproval::Granted,
                RemoteEvidence::Unavailable
            ),
            Err(TransitionRefusal::RemoteUnavailable)
        );
    }

    #[test]
    fn identical_binding_refuses_a_legacy_payload_and_a_withheld_approval() {
        for schema in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let raw = rig().legacy_raw(schema);
            let evidence = bound(&raw, &raw);

            assert_eq!(
                bind(
                    &SyncStateLoad::NotConfigured,
                    UserApproval::Granted,
                    RemoteEvidence::Inspected(&evidence),
                ),
                Err(TransitionRefusal::LocalUnversioned)
            );
        }

        let evidence = bound(&v().s7, &v().s7);

        assert_eq!(
            bind(
                &SyncStateLoad::NotConfigured,
                UserApproval::Withheld,
                RemoteEvidence::Inspected(&evidence),
            ),
            Err(TransitionRefusal::ApprovalWithheld)
        );
    }

    #[test]
    fn a_corrupt_or_foreign_remote_never_yields_evidence_to_bind_with() {
        let mut corrupt: VaultEnvelope = serde_json::from_slice(&v().s7).unwrap();
        corrupt.payload.ciphertext[0] ^= 0x01;
        let corrupt = serde_json::to_vec(&corrupt).unwrap();

        assert!(inspect_remote_bytes(&rig().key, VAULT_ID, &v().s7, &corrupt, None).is_err());

        let foreign_raw = foreign().raw_at(7);

        assert!(inspect_remote_bytes(&rig().key, VAULT_ID, &v().s7, &foreign_raw, None).is_err());
    }

    // ---- the prior load outcome is never reinterpreted ----------------------

    #[test]
    fn only_not_configured_authorizes_an_initial_binding() {
        let local = snapshot(&v().l8);
        let evidence = bound(&v().s7, &v().s7);

        let priors = [
            (
                SyncStateLoad::Loaded(Box::new(based())),
                TransitionRefusal::ExistingBinding,
            ),
            (
                SyncStateLoad::Loaded(Box::new(unbased_pending())),
                TransitionRefusal::ExistingBinding,
            ),
            (
                SyncStateLoad::Unreadable,
                TransitionRefusal::PriorStateUnknown,
            ),
            (SyncStateLoad::Corrupt, TransitionRefusal::PriorStateUnknown),
            (
                SyncStateLoad::UnsupportedVersion,
                TransitionRefusal::PriorStateUnknown,
            ),
            (
                SyncStateLoad::from_bytes(b"not a sync state"),
                TransitionRefusal::PriorStateUnknown,
            ),
            (
                SyncStateLoad::from_bytes(&[]),
                TransitionRefusal::PriorStateUnknown,
            ),
        ];

        for (prior, expected) in priors {
            assert_eq!(
                publish(
                    &prior,
                    UserApproval::Granted,
                    RemoteObservation::Absent,
                    &local
                ),
                Err(expected)
            );
            assert_eq!(
                bind(
                    &prior,
                    UserApproval::Granted,
                    RemoteEvidence::Inspected(&evidence)
                ),
                Err(expected)
            );
        }
    }

    // ---- high-water observations -------------------------------------------

    #[test]
    fn a_newer_authenticated_observation_raises_only_the_high_water() {
        let state = based();
        let before = state.clone();

        let outcome = observe(&state, &bound(&v().s7, &v().r12)).unwrap();

        let HighWaterOutcome::Raised(proposed) = outcome else {
            panic!("expected a raised high-water");
        };

        let checkpoint = checkpoint_of(&proposed);
        assert_eq!(checkpoint.high_water(), RemoteHighWater::new(12));
        // The synchronized baseline did not move, and nothing was authorized.
        assert_eq!(checkpoint.synced(), &fp_of(&v().s7));
        assert_eq!(checkpoint.synced_revision(), 7);
        assert!(proposed.pending_push().is_none());
        assert_eq!(proposed.binding_id(), before.binding_id());
        assert_eq!(proposed.local_locator(), before.local_locator());
        assert_eq!(proposed.target_locator(), before.target_locator());

        // The input was not mutated: until a proposal is persisted, the old
        // state is the truth (a failed persistence leaves it so).
        assert_eq!(state, before);
        assert_ne!(*proposed, state);
        assert_eq!(checkpoint_of(&state).high_water(), RemoteHighWater::new(7));

        assert_round_trips(&proposed);
    }

    #[test]
    fn an_equal_observation_changes_nothing() {
        assert_eq!(
            observe(&based(), &bound(&v().s7, &v().s7_resealed)),
            Ok(HighWaterOutcome::Unchanged)
        );
    }

    #[test]
    fn an_older_observation_never_lowers_the_high_water_and_reports_a_regression() {
        let state = based();

        for older in [&v().l5, &v().l6] {
            assert_eq!(
                observe(&state, &bound(&v().s7, older)),
                Ok(HighWaterOutcome::KnownRegression)
            );
        }

        assert_eq!(checkpoint_of(&state).high_water(), RemoteHighWater::new(7));
    }

    #[test]
    fn the_high_water_never_decreases_across_a_sequence_of_observations() {
        let mut state = based();
        let mut seen = checkpoint_of(&state).high_water().revision();

        for remote in [&v().t9, &v().l5, &v().r12, &v().s7, &v().l10, &v().l6] {
            if let Ok(HighWaterOutcome::Raised(next)) = observe(&state, &bound(&v().s7, remote)) {
                state = *next;
            }

            let now = checkpoint_of(&state).high_water().revision();
            assert!(now >= seen);
            seen = now;
        }

        assert_eq!(seen, 12);
        assert_eq!(checkpoint_of(&state).synced(), &fp_of(&v().s7));
        assert_eq!(checkpoint_of(&state).synced_revision(), 7);
    }

    #[test]
    fn a_pending_push_blocks_observation_based_changes_and_is_left_intact() {
        let state = based_pending();
        let before = state.clone();

        assert_eq!(
            observe(&state, &bound(&v().s7, &v().r12)),
            Err(TransitionRefusal::PendingIntentExists)
        );
        // Not even a regression report is produced while an intent is pending.
        assert_eq!(
            observe(&state, &bound(&v().s7, &v().l5)),
            Err(TransitionRefusal::PendingIntentExists)
        );
        assert_eq!(state, before);
        assert!(state.pending_push().is_some());
    }

    #[test]
    fn an_unbased_state_is_not_treated_as_a_checkpoint() {
        assert_eq!(
            observe(&unbased_pending(), &bound(&v().s7, &v().r12)),
            Err(TransitionRefusal::NotBased)
        );
    }

    #[test]
    fn observations_require_a_schema_three_remote_and_the_right_binding() {
        assert_eq!(
            observe(&based(), &bound(&v().s7, &v().legacy)),
            Err(TransitionRefusal::RemoteUnversioned)
        );

        // Evidence authenticated for another vault.
        let foreign_evidence = inspect_remote_bytes(
            &foreign().key,
            FOREIGN_VAULT_ID,
            &foreign().raw_at(7),
            &foreign().raw_at(12),
            None,
        )
        .unwrap();

        assert_eq!(
            observe(&based(), &foreign_evidence),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::VaultIdentity
            ))
        );

        let (_, t) = locs();
        let other = loc(OTHER);
        let evidence = bound(&v().s7, &v().r12);

        assert_eq!(
            record_remote_observation(&based(), &other, &t, &evidence),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::LocalLocator
            ))
        );

        let (l, _) = locs();

        assert_eq!(
            record_remote_observation(&based(), &l, &other, &evidence),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::TargetLocator
            ))
        );
    }

    // ---- begin push ---------------------------------------------------------

    #[test]
    fn a_local_ahead_vault_above_the_high_water_yields_a_pending_push() {
        let state = based();
        let before = state.clone();
        let evidence = bound(&v().l8, &v().s7);

        let proposed = push(&state, RemoteEvidence::Inspected(&evidence)).unwrap();

        let pending = proposed.pending_push().unwrap();
        assert_eq!(pending.intent_id(), INTENT);
        assert_eq!(
            pending.intent().baseline(),
            &PushBaseline::Present(fp_of(&v().s7))
        );
        assert_eq!(pending.intent().intended(), &fp_of(&v().l8));
        assert_eq!(pending.intended_revision(), 8);

        // The checkpoint is untouched; only the intent was added.
        assert_eq!(proposed.base(), state.base());
        assert_eq!(proposed.binding_id(), state.binding_id());
        assert_eq!(state, before);
        assert!(state.pending_push().is_none());

        assert_round_trips(&proposed);
    }

    #[test]
    fn begin_push_is_deterministic_and_does_not_depend_on_the_evidence_checkpoint() {
        let state = based();
        let evidence = bound(&v().l8, &v().s7);

        let first = push(&state, RemoteEvidence::Inspected(&evidence)).unwrap();
        let second = push(&state, RemoteEvidence::Inspected(&evidence)).unwrap();
        assert_eq!(first, second);

        // The inspection's own checkpoint comparison depends on a mark the
        // evidence does not record; whatever it says, the decision uses the
        // state's own mark.
        for claimed in [0, 7, 8, 100] {
            let with_mark = inspect_remote_bytes(
                &rig().key,
                VAULT_ID,
                &v().l8,
                &v().s7,
                Some(RemoteHighWater::new(claimed)),
            )
            .unwrap();

            assert_eq!(
                push(&state, RemoteEvidence::Inspected(&with_mark)),
                Ok(first.clone()),
                "claimed mark {claimed}"
            );
        }
    }

    #[test]
    fn a_non_nil_intent_id_is_required() {
        let evidence = bound(&v().l8, &v().s7);
        let (l, t) = locs();

        assert_eq!(
            begin_push(
                &based(),
                &l,
                &t,
                RemoteEvidence::Inspected(&evidence),
                Uuid::nil()
            ),
            Err(TransitionRefusal::InvalidState(SyncStateError::NilIntentId))
        );
    }

    #[test]
    fn begin_push_refuses_a_vault_that_did_not_change() {
        let evidence = bound(&v().s7, &v().s7);

        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&evidence)),
            Err(TransitionRefusal::NoLocalChanges)
        );
    }

    #[test]
    fn begin_push_refuses_wrapper_only_and_reencryption_changes() {
        // Same payload bytes, only the wrapper differs; same content re-sealed
        // with a fresh nonce; and pure whitespace changes of the same envelope.
        for local in [&v().s7_rewrapped, &v().s7_resealed, &v().s7_pretty] {
            let evidence = bound(local, &v().s7);

            assert_ne!(
                evidence.local_fingerprint(),
                evidence.candidate_fingerprint()
            );
            assert_eq!(
                push(&based(), RemoteEvidence::Inspected(&evidence)),
                Err(TransitionRefusal::WrapperChangeBlocked)
            );
        }
    }

    #[test]
    fn begin_push_refuses_a_same_revision_conflict() {
        // Local equals the high-water revision but with different content.
        let evidence = bound(&v().s7_conflict, &v().s7);

        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&evidence)),
            Err(TransitionRefusal::SameRevisionConflict)
        );
    }

    #[test]
    fn begin_push_requires_the_local_revision_strictly_above_the_high_water() {
        // Below the mark (and behind the remote).
        let behind = bound(&v().l6, &v().s7);

        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&behind)),
            Err(TransitionRefusal::NotStrictlyAboveHighWater)
        );

        // Exactly at the mark, with different content, is a conflict, not an
        // advance.
        let at_mark = bound(&v().s7_conflict, &v().s7);

        assert!(push(&based(), RemoteEvidence::Inspected(&at_mark)).is_err());

        // One above is the smallest acceptable revision.
        let one_above = bound(&v().l8, &v().s7);

        assert!(push(&based(), RemoteEvidence::Inspected(&one_above)).is_ok());
    }

    #[test]
    fn begin_push_refuses_a_remote_below_the_high_water() {
        // The mark is 9, but the remote is back at the synchronized revision 7.
        let state = build(SyncBase::Based(checkpoint(&v().s7, 7, 9)), None);

        for local in [&v().l8, &v().l10] {
            let evidence = bound(local, &v().s7);

            assert_eq!(
                push(&state, RemoteEvidence::Inspected(&evidence)),
                Err(TransitionRefusal::KnownRegression)
            );
        }
    }

    #[test]
    fn begin_push_refuses_a_remote_that_changed() {
        let ahead = bound(&v().s7, &v().t9);
        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&ahead)),
            Err(TransitionRefusal::RemoteAhead)
        );

        let diverged = bound(&v().l8, &v().t9);
        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&diverged)),
            Err(TransitionRefusal::Diverged)
        );

        let converged = bound(&v().l8, &v().l8);
        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&converged)),
            Err(TransitionRefusal::Converged)
        );
    }

    #[test]
    fn begin_push_refuses_an_absent_or_unavailable_remote() {
        assert_eq!(
            push(&based(), RemoteEvidence::Absent),
            Err(TransitionRefusal::RemoteDisappeared)
        );
        assert_eq!(
            push(&based(), RemoteEvidence::Unavailable),
            Err(TransitionRefusal::RemoteUnavailable)
        );
    }

    #[test]
    fn begin_push_refuses_unversioned_payloads_on_either_side() {
        let legacy_local = bound(&v().legacy, &v().s7);
        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&legacy_local)),
            Err(TransitionRefusal::LocalUnversioned)
        );

        let legacy_remote = bound(&v().l8, &v().legacy);
        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&legacy_remote)),
            Err(TransitionRefusal::RemoteUnversioned)
        );
    }

    #[test]
    fn begin_push_refuses_a_remote_whose_revision_disagrees_with_the_record() {
        // The recorded revision (5) disagrees with what the bytes authenticate
        // to (7): the state is inconsistent with the evidence.
        let state = build(SyncBase::Based(checkpoint(&v().s7, 5, 5)), None);
        let evidence = bound(&v().l8, &v().s7);

        assert_eq!(
            push(&state, RemoteEvidence::Inspected(&evidence)),
            Err(TransitionRefusal::BaselineRevisionMismatch)
        );
    }

    #[test]
    fn begin_push_refuses_when_a_push_is_pending_or_the_state_is_unbased() {
        let evidence = bound(&v().l8, &v().s7);

        assert_eq!(
            push(&based_pending(), RemoteEvidence::Inspected(&evidence)),
            Err(TransitionRefusal::PendingIntentExists)
        );
        assert_eq!(
            push(&unbased_pending(), RemoteEvidence::Inspected(&evidence)),
            Err(TransitionRefusal::NotBased)
        );
    }

    #[test]
    fn begin_push_refuses_every_binding_mismatch() {
        let evidence = bound(&v().l8, &v().s7);
        let other = loc(OTHER);
        let (l, t) = locs();

        assert_eq!(
            begin_push(
                &based(),
                &other,
                &t,
                RemoteEvidence::Inspected(&evidence),
                INTENT
            ),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::LocalLocator
            ))
        );
        assert_eq!(
            begin_push(
                &based(),
                &l,
                &other,
                RemoteEvidence::Inspected(&evidence),
                INTENT
            ),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::TargetLocator
            ))
        );
        // Locators are also checked when there is no inspected evidence.
        assert_eq!(
            begin_push(&based(), &other, &t, RemoteEvidence::Absent, INTENT),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::LocalLocator
            ))
        );

        // Authenticated evidence of a different vault.
        let foreign_evidence = inspect_remote_bytes(
            &foreign().key,
            FOREIGN_VAULT_ID,
            &foreign().raw_at(8),
            &foreign().raw_at(7),
            None,
        )
        .unwrap();

        assert_eq!(
            push(&based(), RemoteEvidence::Inspected(&foreign_evidence)),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::VaultIdentity
            ))
        );
    }

    #[test]
    fn every_refused_push_leaves_the_state_untouched() {
        let state = based();
        let before = state.clone();

        for local_and_remote in [
            (&v().s7, &v().s7),
            (&v().l6, &v().s7),
            (&v().l8, &v().t9),
            (&v().s7_conflict, &v().s7),
            (&v().s7_rewrapped, &v().s7),
        ] {
            let evidence = bound(local_and_remote.0, local_and_remote.1);

            assert!(push(&state, RemoteEvidence::Inspected(&evidence)).is_err());
            assert_eq!(state, before);
        }
    }

    // ---- reconciliation -----------------------------------------------------

    #[test]
    fn a_published_push_advances_the_checkpoint_and_clears_the_intent_in_one_state() {
        let state = based_pending();
        let before = state.clone();
        let evidence = bound(&v().l8, &v().l8);

        let resolution = reconcile(&state, RemoteEvidence::Inspected(&evidence)).unwrap();

        let PushResolution::Finalize {
            intent_id,
            state: proposed,
        } = resolution
        else {
            panic!("expected a finalized state");
        };

        assert_eq!(intent_id, INTENT);

        let checkpoint = checkpoint_of(&proposed);
        assert_eq!(checkpoint.synced(), &fp_of(&v().l8));
        assert_eq!(checkpoint.synced_revision(), 8);
        assert_eq!(checkpoint.high_water(), RemoteHighWater::new(8));
        assert!(proposed.pending_push().is_none());
        assert_eq!(proposed.binding_id(), state.binding_id());

        assert_eq!(state, before);
        assert_round_trips(&proposed);
    }

    #[test]
    fn the_high_water_is_raised_monotonically_when_finalizing() {
        // The recorded mark (8) is already above the previous one; a finalize
        // may never lower it. Intended revision 9 exceeds a mark of 8.
        let state = build(
            SyncBase::Based(checkpoint(&v().s7, 7, 8)),
            Some(pending(PushBaseline::Present(fp_of(&v().s7)), &v().t9, 9)),
        );
        let evidence = bound(&v().t9, &v().t9);

        let PushResolution::Finalize {
            state: proposed, ..
        } = reconcile(&state, RemoteEvidence::Inspected(&evidence)).unwrap()
        else {
            panic!("expected a finalized state");
        };

        assert_eq!(
            checkpoint_of(&proposed).high_water(),
            RemoteHighWater::new(9)
        );
        assert_eq!(checkpoint_of(&proposed).synced_revision(), 9);
    }

    #[test]
    fn a_published_initial_publication_becomes_a_based_checkpoint() {
        let state = unbased_pending();
        let evidence = bound(&v().l8, &v().l8);

        let PushResolution::Finalize {
            state: proposed, ..
        } = reconcile(&state, RemoteEvidence::Inspected(&evidence)).unwrap()
        else {
            panic!("expected a finalized state");
        };

        let checkpoint = checkpoint_of(&proposed);
        assert_eq!(checkpoint.synced(), &fp_of(&v().l8));
        assert_eq!(checkpoint.synced_revision(), 8);
        assert_eq!(checkpoint.high_water(), RemoteHighWater::new(8));
        assert!(proposed.pending_push().is_none());
        assert_round_trips(&proposed);
    }

    #[test]
    fn reconciliation_is_repeatable_and_never_applies_the_revision_twice() {
        let state = based_pending();
        let evidence = bound(&v().l8, &v().l8);

        let first = reconcile(&state, RemoteEvidence::Inspected(&evidence)).unwrap();
        // An interrupted attempt (the proposal was never persisted) repeats to
        // exactly the same proposal.
        let again = reconcile(&state, RemoteEvidence::Inspected(&evidence)).unwrap();
        assert_eq!(first, again);

        let PushResolution::Finalize { state: applied, .. } = first else {
            panic!("expected a finalized state");
        };

        // Once applied, there is nothing left to reconcile: no second advance.
        assert_eq!(
            reconcile(&applied, RemoteEvidence::Inspected(&evidence)),
            Err(TransitionRefusal::NoPendingPush)
        );
        assert_eq!(checkpoint_of(&applied).synced_revision(), 8);
        assert_eq!(
            checkpoint_of(&applied).high_water(),
            RemoteHighWater::new(8)
        );
    }

    #[test]
    fn a_published_fingerprint_with_the_wrong_authenticated_revision_is_not_accepted() {
        // The pending record claims revision 9, but these bytes authenticate to 8.
        let state = build(
            SyncBase::Based(checkpoint(&v().s7, 7, 7)),
            Some(pending(PushBaseline::Present(fp_of(&v().s7)), &v().l8, 9)),
        );
        let evidence = bound(&v().l8, &v().l8);

        assert_eq!(
            reconcile(&state, RemoteEvidence::Inspected(&evidence)),
            Ok(PushResolution::StillPending { intent_id: INTENT })
        );

        // A legacy payload carries no counter to compare at all.
        let legacy_state = build(
            SyncBase::Based(checkpoint(&v().s7, 7, 7)),
            Some(pending(
                PushBaseline::Present(fp_of(&v().s7)),
                &v().legacy,
                8,
            )),
        );
        let legacy_evidence = bound(&v().legacy, &v().legacy);

        assert_eq!(
            reconcile(&legacy_state, RemoteEvidence::Inspected(&legacy_evidence)),
            Ok(PushResolution::StillPending { intent_id: INTENT })
        );
    }

    #[test]
    fn a_push_still_at_its_baseline_proposes_only_clearing_the_intent() {
        let state = based_pending();
        let before = state.clone();
        let evidence = bound(&v().l8, &v().s7);

        let resolution = reconcile(&state, RemoteEvidence::Inspected(&evidence)).unwrap();

        let PushResolution::ClearIntent {
            intent_id,
            state: proposed,
        } = resolution
        else {
            panic!("expected an intent-clear proposal");
        };

        assert_eq!(intent_id, INTENT);
        assert!(proposed.pending_push().is_none());
        // Checkpoint and high-water are exactly as they were.
        assert_eq!(proposed.base(), state.base());
        assert_eq!(checkpoint_of(&proposed).synced_revision(), 7);
        assert_eq!(
            checkpoint_of(&proposed).high_water(),
            RemoteHighWater::new(7)
        );

        assert_eq!(state, before);
        assert_round_trips(&proposed);
    }

    #[test]
    fn not_published_never_authorizes_a_retry() {
        let state = based_pending();
        let evidence = bound(&v().l8, &v().s7);

        let PushResolution::ClearIntent { state: cleared, .. } =
            reconcile(&state, RemoteEvidence::Inspected(&evidence)).unwrap()
        else {
            panic!("expected an intent-clear proposal");
        };

        // The proposal carries no new intent; a retry would be a separate,
        // explicitly decided `begin_push` on the cleared state ...
        assert!(cleared.pending_push().is_none());

        // ... and until that proposal is applied, the pending state still
        // blocks any push, even against a remote at the baseline.
        assert_eq!(
            push(&state, RemoteEvidence::Inspected(&evidence)),
            Err(TransitionRefusal::PendingIntentExists)
        );
    }

    #[test]
    fn an_initial_publication_that_never_happened_proposes_deleting_the_record() {
        assert_eq!(
            reconcile(&unbased_pending(), RemoteEvidence::Absent),
            Ok(PushResolution::DeleteUnbasedRecord { intent_id: INTENT })
        );
    }

    #[test]
    fn a_baseline_with_the_wrong_authenticated_revision_is_not_a_clean_not_published() {
        // The record says the baseline was revision 6; the bytes say 7.
        let state = build(
            SyncBase::Based(checkpoint(&v().s7, 6, 6)),
            Some(pending(PushBaseline::Present(fp_of(&v().s7)), &v().l8, 8)),
        );
        let evidence = bound(&v().l8, &v().s7);

        assert_eq!(
            reconcile(&state, RemoteEvidence::Inspected(&evidence)),
            Ok(PushResolution::StillPending { intent_id: INTENT })
        );
    }

    #[test]
    fn an_unexpected_remote_keeps_the_intent_and_decides_nothing() {
        let third = bound(&v().l8, &v().t9);

        for (state, remote) in [
            (based_pending(), RemoteEvidence::Inspected(&third)),
            (based_pending(), RemoteEvidence::Absent),
            (based_pending(), RemoteEvidence::Unavailable),
            (unbased_pending(), RemoteEvidence::Inspected(&third)),
            (unbased_pending(), RemoteEvidence::Unavailable),
        ] {
            let before = state.clone();

            assert_eq!(
                reconcile(&state, remote),
                Ok(PushResolution::StillPending { intent_id: INTENT })
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn reconciliation_requires_a_pending_push_and_the_right_binding() {
        let evidence = bound(&v().l8, &v().l8);

        assert_eq!(
            reconcile(&based(), RemoteEvidence::Inspected(&evidence)),
            Err(TransitionRefusal::NoPendingPush)
        );

        let other = loc(OTHER);
        let (l, t) = locs();

        assert_eq!(
            reconcile_pending_push(
                &based_pending(),
                &l,
                &other,
                RemoteEvidence::Inspected(&evidence)
            ),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::TargetLocator
            ))
        );
        assert_eq!(
            reconcile_pending_push(&based_pending(), &other, &t, RemoteEvidence::Absent),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::LocalLocator
            ))
        );

        let foreign_evidence = inspect_remote_bytes(
            &foreign().key,
            FOREIGN_VAULT_ID,
            &foreign().raw_at(8),
            &foreign().raw_at(8),
            None,
        )
        .unwrap();

        assert_eq!(
            reconcile(
                &based_pending(),
                RemoteEvidence::Inspected(&foreign_evidence)
            ),
            Err(TransitionRefusal::BindingMismatch(
                BindingMismatch::VaultIdentity
            ))
        );
    }

    // ---- crash-state decision matrix ---------------------------------------

    #[derive(Clone, Copy, Debug)]
    enum Observed {
        Baseline,
        Intended,
        Third,
        Missing,
        Unavailable,
    }

    const OBSERVATIONS: [Observed; 5] = [
        Observed::Baseline,
        Observed::Intended,
        Observed::Third,
        Observed::Missing,
        Observed::Unavailable,
    ];

    fn evidence_for(observed: Observed) -> Option<BoundInspection> {
        match observed {
            Observed::Baseline => Some(bound(&v().l8, &v().s7)),
            Observed::Intended => Some(bound(&v().l8, &v().l8)),
            Observed::Third => Some(bound(&v().l8, &v().t9)),
            Observed::Missing | Observed::Unavailable => None,
        }
    }

    fn remote_of<'a>(
        observed: Observed,
        evidence: &'a Option<BoundInspection>,
    ) -> RemoteEvidence<'a> {
        match (observed, evidence) {
            (_, Some(inspected)) => RemoteEvidence::Inspected(inspected),
            (Observed::Missing, None) => RemoteEvidence::Absent,
            (_, None) => RemoteEvidence::Unavailable,
        }
    }

    fn kind(result: &Result<PushResolution, TransitionRefusal>) -> &'static str {
        match result {
            Ok(PushResolution::Finalize { .. }) => "finalize",
            Ok(PushResolution::ClearIntent { .. }) => "clear",
            Ok(PushResolution::DeleteUnbasedRecord { .. }) => "delete",
            Ok(PushResolution::StillPending { .. }) => "pending",
            Err(TransitionRefusal::NoPendingPush) => "no-pending",
            Err(_) => "refused",
        }
    }

    #[test]
    fn crash_state_matrix_never_authorizes_an_unsafe_publication() {
        for observed in OBSERVATIONS {
            let evidence = evidence_for(observed);
            let remote = remote_of(observed, &evidence);

            // Only a based, nothing-pending state with a remote still at its
            // baseline may start a new push.
            for (name, state) in [
                ("unbased+pending", unbased_pending()),
                ("based", based()),
                ("based+pending", based_pending()),
            ] {
                let result = push(&state, remote);
                let allowed = name == "based" && matches!(observed, Observed::Baseline);

                assert_eq!(result.is_ok(), allowed, "{name} / {observed:?}");
            }

            // Reconciliation, per durable state.
            let expected_unbased = match observed {
                Observed::Missing => "delete",
                Observed::Intended => "finalize",
                _ => "pending",
            };
            let expected_based_pending = match observed {
                Observed::Baseline => "clear",
                Observed::Intended => "finalize",
                _ => "pending",
            };

            assert_eq!(
                kind(&reconcile(&unbased_pending(), remote)),
                expected_unbased,
                "unbased+pending / {observed:?}"
            );
            assert_eq!(
                kind(&reconcile(&based(), remote)),
                "no-pending",
                "based / {observed:?}"
            );
            assert_eq!(
                kind(&reconcile(&based_pending(), remote)),
                expected_based_pending,
                "based+pending / {observed:?}"
            );
        }
    }

    #[test]
    fn crash_state_matrix_for_an_unbound_vault_only_allows_the_two_approved_bindings() {
        let local = snapshot(&v().l8);

        for observed in OBSERVATIONS {
            let evidence = evidence_for(observed);
            let remote = remote_of(observed, &evidence);

            let publication = publish(
                &SyncStateLoad::NotConfigured,
                UserApproval::Granted,
                match observed {
                    Observed::Missing => RemoteObservation::Absent,
                    Observed::Unavailable => RemoteObservation::Unavailable,
                    Observed::Baseline => RemoteObservation::Present(fp_of(&v().s7)),
                    Observed::Intended => RemoteObservation::Present(fp_of(&v().l8)),
                    Observed::Third => RemoteObservation::Present(fp_of(&v().t9)),
                },
                &local,
            );
            assert_eq!(
                publication.is_ok(),
                matches!(observed, Observed::Missing),
                "{observed:?}"
            );

            // Binding to an existing remote needs byte-identical, inspected
            // evidence: here that is only the pair (L, L).
            assert_eq!(
                bind(&SyncStateLoad::NotConfigured, UserApproval::Granted, remote).is_ok(),
                matches!(observed, Observed::Intended),
                "{observed:?}"
            );
        }
    }

    // ---- no implicit resets, opacity and redaction --------------------------

    #[test]
    fn no_transition_resets_or_replaces_an_existing_binding() {
        let local = snapshot(&v().l8);
        let evidence = bound(&v().s7, &v().s7);

        for existing in [based(), based_pending(), unbased_pending()] {
            let prior = SyncStateLoad::Loaded(Box::new(existing));

            assert_eq!(
                publish(
                    &prior,
                    UserApproval::Granted,
                    RemoteObservation::Absent,
                    &local
                ),
                Err(TransitionRefusal::ExistingBinding)
            );
            assert_eq!(
                bind(
                    &prior,
                    UserApproval::Granted,
                    RemoteEvidence::Inspected(&evidence)
                ),
                Err(TransitionRefusal::ExistingBinding)
            );
        }
    }

    fn assert_free_of_content(text: &str) {
        for forbidden in [
            "LOCAL-MARKER",
            "TARGET-MARKER",
            "OTHER-MARKER",
            "synthetic",
            SECRET,
            "Base Entry",
            MASTER,
            &VAULT_ID.to_string(),
            &VAULT_ID.simple().to_string(),
            &FOREIGN_VAULT_ID.to_string(),
        ] {
            assert!(!text.contains(forbidden), "{forbidden:?} leaked: {text}");
        }
    }

    #[test]
    fn refusals_and_outcomes_never_show_identities_locators_or_content() {
        let refusals = [
            TransitionRefusal::ApprovalWithheld,
            TransitionRefusal::ExistingBinding,
            TransitionRefusal::PriorStateUnknown,
            TransitionRefusal::RemoteNotAbsent,
            TransitionRefusal::RemoteAbsent,
            TransitionRefusal::RemoteDisappeared,
            TransitionRefusal::RemoteUnavailable,
            TransitionRefusal::RemoteDiffers,
            TransitionRefusal::LocalUnversioned,
            TransitionRefusal::RemoteUnversioned,
            TransitionRefusal::BindingMismatch(BindingMismatch::VaultIdentity),
            TransitionRefusal::BindingMismatch(BindingMismatch::LocalLocator),
            TransitionRefusal::BindingMismatch(BindingMismatch::TargetLocator),
            TransitionRefusal::NotBased,
            TransitionRefusal::NoPendingPush,
            TransitionRefusal::PendingIntentExists,
            TransitionRefusal::NoLocalChanges,
            TransitionRefusal::RemoteAhead,
            TransitionRefusal::Diverged,
            TransitionRefusal::Converged,
            TransitionRefusal::WrapperChangeBlocked,
            TransitionRefusal::SameRevisionConflict,
            TransitionRefusal::AmbiguousChange,
            TransitionRefusal::BaselineRevisionMismatch,
            TransitionRefusal::KnownRegression,
            TransitionRefusal::NotStrictlyAboveHighWater,
            TransitionRefusal::InvalidState(SyncStateError::NilIntentId),
        ];

        for refusal in refusals {
            assert_free_of_content(&format!("{refusal} | {refusal:?}"));
        }

        // Real outcomes, including full proposed states.
        let evidence = bound(&v().l8, &v().l8);
        let local = snapshot(&v().l8);
        let (l, t) = locs();

        let rendered = [
            format!("{:?}", new_binding(&l, &t)),
            format!("{:?}", RemoteEvidence::Inspected(&evidence)),
            format!(
                "{:?}",
                reconcile(&based_pending(), RemoteEvidence::Inspected(&evidence))
            ),
            format!(
                "{:?}",
                reconcile(&unbased_pending(), RemoteEvidence::Absent)
            ),
            format!("{:?}", observe(&based(), &bound(&v().s7, &v().r12))),
            format!(
                "{:?}",
                push(
                    &based(),
                    RemoteEvidence::Inspected(&bound(&v().l8, &v().s7))
                )
            ),
            format!(
                "{:?}",
                publish(
                    &SyncStateLoad::NotConfigured,
                    UserApproval::Granted,
                    RemoteObservation::Absent,
                    &local
                )
            ),
        ];

        for text in rendered {
            assert_free_of_content(&text);
        }
    }

    #[test]
    fn transitions_accept_only_core_produced_evidence() {
        // The only values that carry revisions and fingerprints into a
        // transition are `BoundInspection` and `LocalSnapshot`; both come from
        // authenticated raw bytes. A byte string that does not authenticate
        // yields no evidence at all, so no revision can be injected.
        let forged = serde_json::to_vec(&{
            let mut envelope: VaultEnvelope = serde_json::from_slice(&v().l8).unwrap();
            envelope.payload.ciphertext[0] ^= 0x01;
            envelope
        })
        .unwrap();

        assert!(inspect_local_bytes(&rig().key, VAULT_ID, &forged).is_err());
        assert!(inspect_remote_bytes(&rig().key, VAULT_ID, &v().l8, &forged, None).is_err());
        assert!(inspect_remote_bytes(&rig().key, VAULT_ID, &forged, &v().s7, None).is_err());

        // And the vault key of another vault authenticates neither side.
        assert!(inspect_local_bytes(&foreign().key, VAULT_ID, &v().l8).is_err());
    }

    // ---- B3c-1: states with exchange records are never silently rewritten -----

    fn exchange_anchor(seed: u8) -> ObjectAnchor {
        ObjectAnchor::new(&[seed; 16]).unwrap()
    }

    /// Synced S (7), nothing pending, one retained entry below it.
    fn retained_only() -> SyncState {
        SyncState::new_with_exchange_records(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(LOCAL),
            loc(TARGET),
            SyncBase::Based(checkpoint(&v().s7, 7, 7)),
            None,
            None,
            vec![retained_entry()],
        )
        .unwrap()
    }

    fn retained_entry() -> RetainedPrevious {
        RetainedPrevious::new(
            Uuid::from_u128(0xbbbb_bbbb_cccc_4ddd_8eee_ffff_ffff_ffff),
            fp_of(&v().l5),
            5,
            exchange_anchor(1),
            exchange_anchor(2),
        )
        .unwrap()
    }

    /// As [`based_pending`], plus an exchange intent and optionally a retained entry.
    fn exchange_pending(with_retained: bool) -> SyncState {
        SyncState::new_with_exchange_records(
            BindingId::new(BINDING).unwrap(),
            tag(),
            loc(LOCAL),
            loc(TARGET),
            SyncBase::Based(checkpoint(&v().s7, 7, 7)),
            Some(pending(PushBaseline::Present(fp_of(&v().s7)), &v().l8, 8)),
            Some(ExchangeIntent::new(
                ExchangeScheme::RetainAndPublishV1,
                exchange_anchor(3),
                exchange_anchor(4),
            )),
            if with_retained {
                vec![retained_entry()]
            } else {
                Vec::new()
            },
        )
        .unwrap()
    }

    #[test]
    fn transitions_refuse_states_with_exchange_records_and_never_drop_them() {
        let refusal =
            TransitionRefusal::InvalidState(SyncStateError::ExchangeRecordsUnsupportedByTransition);

        // The same evidence is accepted on the same state without records, so
        // the refusals below come from the records and from nothing else.
        let begin_evidence = bound(&v().l8, &v().s7);
        let finalize_evidence = bound(&v().l8, &v().l8);
        let raise_evidence = bound(&v().s7, &v().r12);
        assert!(push(&based(), RemoteEvidence::Inspected(&begin_evidence)).is_ok());
        assert!(matches!(
            reconcile(
                &based_pending(),
                RemoteEvidence::Inspected(&finalize_evidence)
            ),
            Ok(PushResolution::Finalize { .. })
        ));
        assert!(matches!(
            observe(&based(), &raise_evidence),
            Ok(HighWaterOutcome::Raised(_))
        ));

        for (name, state) in [
            ("retained only", retained_only()),
            ("exchange only", exchange_pending(false)),
            ("exchange and retained", exchange_pending(true)),
        ] {
            let before = state.clone();
            assert!(state.has_exchange_records(), "{name}");

            assert_eq!(
                push(&state, RemoteEvidence::Inspected(&begin_evidence)),
                Err(refusal),
                "begin_push / {name}"
            );
            assert_eq!(
                push(&state, RemoteEvidence::Absent),
                Err(refusal),
                "begin_push absent / {name}"
            );
            assert_eq!(
                reconcile(&state, RemoteEvidence::Inspected(&finalize_evidence)),
                Err(refusal),
                "reconcile finalize / {name}"
            );
            assert_eq!(
                reconcile(&state, RemoteEvidence::Inspected(&begin_evidence)),
                Err(refusal),
                "reconcile clear / {name}"
            );
            assert_eq!(
                reconcile(&state, RemoteEvidence::Unavailable),
                Err(refusal),
                "reconcile unavailable / {name}"
            );
            assert_eq!(
                observe(&state, &raise_evidence).map(|_| ()),
                Err(refusal),
                "record_remote_observation / {name}"
            );

            // The private builder refuses as well (defense in depth).
            assert_eq!(
                state.with_parts(*state.base(), None),
                Err(SyncStateError::ExchangeRecordsUnsupportedByTransition),
                "with_parts / {name}"
            );

            // Nothing was mutated.
            assert_eq!(state, before, "{name}");
        }
    }

    #[test]
    fn a_state_with_exchange_records_is_an_existing_binding_for_the_initial_transitions() {
        let local = snapshot(&v().l8);
        let evidence = bound(&v().s7, &v().s7);

        for state in [retained_only(), exchange_pending(true)] {
            let prior = SyncStateLoad::Loaded(Box::new(state));

            assert_eq!(
                publish(
                    &prior,
                    UserApproval::Granted,
                    RemoteObservation::Absent,
                    &local
                ),
                Err(TransitionRefusal::ExistingBinding)
            );
            assert_eq!(
                bind(
                    &prior,
                    UserApproval::Granted,
                    RemoteEvidence::Inspected(&evidence)
                ),
                Err(TransitionRefusal::ExistingBinding)
            );
        }
    }

    #[test]
    fn the_new_refusal_is_free_of_content() {
        let refusal =
            TransitionRefusal::InvalidState(SyncStateError::ExchangeRecordsUnsupportedByTransition);

        assert_free_of_content(&format!("{refusal} | {refusal:?}"));
    }
}
