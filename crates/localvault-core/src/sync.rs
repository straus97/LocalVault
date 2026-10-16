//! Pure, provider-independent synchronization-state evaluation.
//!
//! The fingerprint, classification and push-intent items (Stage 1U-1) compare
//! SHA-256 fingerprints of the *exact raw bytes* of an encrypted vault
//! envelope. They decrypt nothing and never touch `VaultData` or the vault
//! format.
//!
//! The authenticated inspection items at the end of this module (Stage 1U-3,
//! [`inspect_remote_candidate`]) are the only part that decrypts. They are a
//! separate, read-only layer: see the "Authenticated remote inspection"
//! section below.
//!
//! Nothing in this module performs I/O, reads a clock, or knows a device
//! identity, path, provider or transport.
//!
//! # What a fingerprint is (and is not)
//!
//! An [`EnvelopeFingerprint`] proves **byte identity and nothing else**. Equal
//! fingerprints mean equal bytes; they do not show that the bytes are a valid,
//! authentic or trusted LocalVault envelope, or that they belong to the
//! expected vault. Those checks belong to later slices.
//!
//! # Classification never authorizes an action
//!
//! [`classify`] and [`PushIntent::reconcile`] only *describe* an observed
//! state. No variant is an instruction to upload, download, replace or delete
//! anything; a caller must apply its own explicit, user-confirmed policy.
//!
//! # Remote I/O failure is not remote absence
//!
//! A remote file that was *confirmed* missing is [`RemoteObservation::Absent`].
//! A remote that could not be read (I/O error, permission, timeout, ...) is
//! [`RemoteObservation::Unavailable`]. Adapters own the I/O and must map any
//! failure to `Unavailable`, never to `Absent`; every function here treats
//! `Unavailable` conservatively and never as a basis for a decision.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::vault::{
    data::{VaultData, VaultDataError, VAULT_DATA_SCHEMA_VERSION},
    format::{open_payload_with_key, CryptoError, SecretKey, VaultEnvelope, VaultError},
};

const FINGERPRINT_LEN: usize = 32;
const FINGERPRINT_HEX_LEN: usize = FINGERPRINT_LEN * 2;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// SHA-256 of the exact raw bytes of an encrypted vault envelope.
///
/// Byte identity only: see the module documentation. The value is a public,
/// non-secret identifier (it is derived from ciphertext), so ordinary
/// (non-constant-time) equality is appropriate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvelopeFingerprint([u8; FINGERPRINT_LEN]);

impl EnvelopeFingerprint {
    /// Fingerprint of the exact `raw` envelope bytes as stored. Callers must
    /// pass the file bytes untouched, never parsed-and-reserialized JSON and
    /// never plaintext vault data.
    pub fn of_bytes(raw: &[u8]) -> Self {
        Self(Sha256::digest(raw).into())
    }

    /// The raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    /// Canonical encoding: exactly 64 lowercase hexadecimal characters.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(FINGERPRINT_HEX_LEN);
        for byte in self.0 {
            out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        out
    }

    /// Strict inverse of [`to_hex`](Self::to_hex): exactly 64 lowercase
    /// hexadecimal characters, with no prefix, whitespace or uppercase.
    pub fn from_hex(text: &str) -> Result<Self, FingerprintParseError> {
        let bytes = text.as_bytes();
        if bytes.len() != FINGERPRINT_HEX_LEN {
            return Err(FingerprintParseError::InvalidLength {
                actual: bytes.len(),
            });
        }

        let mut digest = [0u8; FINGERPRINT_LEN];
        for (index, slot) in digest.iter_mut().enumerate() {
            let high = nibble(bytes[index * 2], index * 2)?;
            let low = nibble(bytes[index * 2 + 1], index * 2 + 1)?;
            *slot = (high << 4) | low;
        }
        Ok(Self(digest))
    }
}

fn nibble(byte: u8, index: usize) -> Result<u8, FingerprintParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(FingerprintParseError::UppercaseCharacter { index }),
        _ => Err(FingerprintParseError::InvalidCharacter { index }),
    }
}

impl fmt::Display for EnvelopeFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for EnvelopeFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnvelopeFingerprint({})", self.to_hex())
    }
}

impl FromStr for EnvelopeFingerprint {
    type Err = FingerprintParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_hex(text)
    }
}

/// Why a fingerprint string was rejected. Positions are byte offsets; the
/// offending character itself is deliberately not echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FingerprintParseError {
    #[error("fingerprint must be exactly 64 hexadecimal characters (got {actual} bytes)")]
    InvalidLength { actual: usize },
    #[error("invalid hexadecimal character at byte {index}")]
    InvalidCharacter { index: usize },
    #[error("uppercase hexadecimal at byte {index}; the canonical form is lowercase")]
    UppercaseCharacter { index: usize },
}

/// What an adapter observed about the remote encrypted file.
///
/// There is intentionally no `From<Option<_>>` and no `From<Result<_, _>>`:
/// turning a read failure into [`Absent`](Self::Absent) must be a visible,
/// deliberate act in the adapter, not an accident of `.ok()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteObservation {
    /// The remote file was positively confirmed not to exist.
    Absent,
    /// The remote file was read; this is the fingerprint of its raw bytes.
    Present(EnvelopeFingerprint),
    /// The remote could not be read or its state could not be established.
    /// Never equivalent to `Absent`.
    Unavailable,
}

/// How the local file, the remote file and the last successful sync relate.
///
/// A description only; none of these variants authorizes any action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncClassification {
    /// No prior sync; the remote is confirmed absent. A candidate for an
    /// initial publication, which still requires explicit user confirmation.
    RemoteMissing,
    /// No prior sync; remote bytes equal local bytes. Identical bytes, but
    /// **not** an automatic trusted binding between this device and the remote.
    UnbasedMatch,
    /// No prior sync; remote bytes differ from local bytes. No common base
    /// exists, so neither side can be called ahead.
    UnbasedDifference,
    /// A prior sync exists but the remote is now confirmed absent.
    RemoteDisappeared,
    /// Local and remote both still equal the last synced bytes.
    InSync,
    /// Only local changed since the last sync.
    LocalAhead,
    /// Only remote changed since the last sync.
    RemoteAhead,
    /// Both changed since the last sync, to identical bytes.
    Converged,
    /// Both changed since the last sync, to different bytes.
    Diverged,
    /// The remote could not be observed; nothing can be concluded.
    RemoteUnavailable,
}

/// Classify the relationship between the last successfully synchronized
/// envelope, the current local envelope and the observed remote.
///
/// `last_synced` is `None` only when this device has no recorded successful
/// sync. Pure and deterministic.
pub fn classify(
    last_synced: Option<&EnvelopeFingerprint>,
    local: &EnvelopeFingerprint,
    remote: &RemoteObservation,
) -> SyncClassification {
    let remote = match remote {
        RemoteObservation::Unavailable => return SyncClassification::RemoteUnavailable,
        RemoteObservation::Absent => {
            return match last_synced {
                None => SyncClassification::RemoteMissing,
                Some(_) => SyncClassification::RemoteDisappeared,
            };
        }
        RemoteObservation::Present(remote) => remote,
    };

    match last_synced {
        None if local == remote => SyncClassification::UnbasedMatch,
        None => SyncClassification::UnbasedDifference,
        Some(base) => match (local != base, remote != base) {
            (false, false) => SyncClassification::InSync,
            (true, false) => SyncClassification::LocalAhead,
            (false, true) => SyncClassification::RemoteAhead,
            (true, true) if local == remote => SyncClassification::Converged,
            (true, true) => SyncClassification::Diverged,
        },
    }
}

/// The remote state a push was started against. Unlike [`RemoteObservation`]
/// there is no `Unavailable`: a push may only be recorded against a baseline
/// that was actually established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushBaseline {
    /// The remote was confirmed absent (initial publication).
    Absent,
    /// The remote was confirmed to hold exactly these bytes.
    Present(EnvelopeFingerprint),
}

/// Why a [`PushIntent`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PushIntentError {
    /// Baseline and intended bytes are identical: after such a push the remote
    /// would look the same whether or not it happened, so it could never be
    /// reconciled. A no-op push should not be recorded at all.
    #[error("push intent would not change the remote")]
    NoChange,
}

/// A recorded intent to replace the remote baseline with a new envelope. Used
/// to reconcile an interrupted push; holds fingerprints only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushIntent {
    baseline: PushBaseline,
    intended: EnvelopeFingerprint,
}

impl PushIntent {
    pub fn new(
        baseline: PushBaseline,
        intended: EnvelopeFingerprint,
    ) -> Result<Self, PushIntentError> {
        if baseline == PushBaseline::Present(intended) {
            return Err(PushIntentError::NoChange);
        }
        Ok(Self { baseline, intended })
    }

    pub fn baseline(&self) -> &PushBaseline {
        &self.baseline
    }

    pub fn intended(&self) -> &EnvelopeFingerprint {
        &self.intended
    }

    /// Compare a fresh remote observation with this intent.
    ///
    /// A pure snapshot judgement: it does not clear any journal, does not
    /// prove a write is no longer in flight, and does not authorize a retry.
    pub fn reconcile(&self, observed: &RemoteObservation) -> PushReconciliation {
        match observed {
            RemoteObservation::Present(remote) if remote == &self.intended => {
                PushReconciliation::Published
            }
            RemoteObservation::Present(remote)
                if self.baseline == PushBaseline::Present(*remote) =>
            {
                PushReconciliation::NotPublished
            }
            RemoteObservation::Absent if self.baseline == PushBaseline::Absent => {
                PushReconciliation::NotPublished
            }
            // Differs from both endpoints, vanished after a present baseline,
            // or could not be read at all.
            _ => PushReconciliation::Unknown,
        }
    }
}

/// Outcome of [`PushIntent::reconcile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushReconciliation {
    /// The remote holds exactly the intended bytes.
    Published,
    /// The remote still matches the baseline the push started from.
    NotPublished,
    /// Anything else, including an unreadable remote: someone else may have
    /// written, or the state is unknown. Requires the caller's own recovery.
    Unknown,
}

// ---------------------------------------------------------------------------
// Authenticated remote inspection (Stage 1U-3)
// ---------------------------------------------------------------------------
//
// A *read-only* check of a candidate remote envelope against the unlocked
// Vault Key. It authenticates and validates the candidate and describes how it
// relates to the local envelope and to a caller-supplied trusted checkpoint.
//
// What it is not: it does not adopt, merge, upload, download, persist or
// resolve anything; it never migrates a candidate and never calls
// `VaultData::prepare_for_write`; it holds no binding or state; and its
// results never authorize an action.
//
// Serialization boundary (decision D10, approved): the adapters keep parsing
// the outer `VaultEnvelope` JSON exactly as on the open path, and hand core the
// parsed envelopes. Core itself authenticates the payload bytes and then
// deserializes them with `serde_json` into `VaultData`, so deserialization is
// only ever applied to bytes core has just authenticated. There is no
// caller-supplied parser, and the only way to obtain a `RemoteInspection` is
// through `inspect_remote_candidate`; a caller cannot present deserialized data
// and call it authenticated.
//
// Stage 1U-4 A2a narrows that boundary additively: `inspect_remote_bytes` takes
// the *raw* envelope bytes, fingerprints and parses those same slices itself,
// and returns an opaque `BoundInspection`. `inspect_remote_candidate` is
// unchanged and remains the only authenticated-validation implementation.

/// Why one side of an inspection was rejected.
///
/// Deliberately coarse: it never carries deserializer error details, field
/// values or any decrypted content, and a wrong key, corruption and forgery are one
/// indistinguishable [`AuthenticationFailed`](Self::AuthenticationFailed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PayloadRejection {
    /// The envelope header is unsupported or malformed (magic, version or
    /// out-of-range KDF parameters). Decided before any decryption.
    #[error("unsupported or malformed vault envelope")]
    UnsupportedFormat,
    /// The payload did not authenticate under the Vault Key.
    #[error("payload did not authenticate under the Vault Key")]
    AuthenticationFailed,
    /// The payload authenticated, but its plaintext could not be deserialized
    /// as a vault payload (malformed JSON, a malformed or misplaced revision,
    /// missing fields).
    #[error("authenticated payload is not a readable vault payload")]
    MalformedPayload,
    /// The payload authenticated and parsed, but its schema is not supported
    /// (for example a future schema).
    #[error("authenticated payload uses an unsupported schema")]
    UnsupportedSchema,
    /// The payload authenticated and parsed, but failed `VaultData::validate`.
    #[error("authenticated payload failed vault data validation")]
    InvalidData,
    /// The payload authenticated and validated, but its `vault_id` is not the
    /// expected one.
    #[error("authenticated payload belongs to a different vault")]
    VaultIdMismatch,
}

/// A failed inspection, naming which input was at fault so that a problem with
/// the caller's own local envelope is never reported as a bad remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InspectionError {
    #[error("remote candidate rejected: {0}")]
    Candidate(PayloadRejection),
    #[error("local reference rejected: {0}")]
    LocalReference(PayloadRejection),
}

/// The revision state of an authenticated payload.
///
/// Legacy payloads (schema 1 and 2) predate the revision counter. Their
/// effective revision is 0 in memory, but that is **not** the same thing as a
/// schema-3 vault at revision 0, so it is never represented as
/// `Counter(0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedRevision {
    /// Schema 1 or 2: no revision counter exists, so no ordering claim can be
    /// made from it.
    Unversioned { schema_version: u16 },
    /// Schema 3: the authenticated write counter.
    Counter(u64),
}

impl AuthenticatedRevision {
    fn of(data: &VaultData) -> Self {
        if data.schema_version >= VAULT_DATA_SCHEMA_VERSION {
            Self::Counter(data.revision)
        } else {
            Self::Unversioned {
                schema_version: data.schema_version,
            }
        }
    }
}

/// A revision that the caller holds durable, authenticated evidence the
/// **remote** artifact has reached: for example the highest authenticated
/// remote revision it has previously inspected, or the revision it last
/// successfully synchronized.
///
/// It is not interchangeable with any of these, and the caller must not build
/// one from them:
///
/// * the **local** revision - a remote behind the local revision usually just
///   means local changes are not published yet;
/// * an unverified or never-authenticated revision;
/// * a value derived from an untrusted header, file name or provider label.
///
/// Persisting and updating the checkpoint is the caller's job; this crate
/// stores nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteHighWater(u64);

impl RemoteHighWater {
    pub const fn new(revision: u64) -> Self {
        Self(revision)
    }

    pub const fn revision(self) -> u64 {
        self.0
    }
}

/// The candidate's authenticated revision against the caller's trusted
/// [`RemoteHighWater`].
///
/// Even `At`/`Above` do **not** prove the candidate is the latest version: a
/// provider can replay any older authentic envelope, and without a checkpoint
/// freshness is not established at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointComparison {
    /// No checkpoint was supplied. Freshness is **not** established.
    NoCheckpoint,
    /// The candidate's counter is below the checkpoint: the remote is known to
    /// have held something newer. A known regression relative to the
    /// checkpoint (a replayed or restored older copy), not a diagnosis of why.
    BelowCheckpoint,
    /// Equal to the checkpoint: consistent with it, not proof of freshness.
    AtCheckpoint,
    /// Above the checkpoint: the remote has advanced past what the caller
    /// knew.
    AboveCheckpoint,
    /// A checkpoint exists but the candidate is a legacy (schema 1 or 2)
    /// payload with no counter. It is **not** treated as revision 0 and no
    /// ordering is claimed; a caller must not treat it as satisfying the
    /// checkpoint.
    UnversionedCandidate,
}

/// How the candidate's *authenticated payload* relates to the local
/// envelope's. Describes only; none of these variants authorizes adopting,
/// overwriting or merging anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadRelation {
    /// The encrypted payload blobs (nonce and ciphertext) are identical, so the
    /// authenticated state is identical.
    IdenticalCiphertext,
    /// The ciphertext differs but the authenticated, decrypted contents are
    /// identical: encryption is randomized, so a payload re-sealed without a
    /// logical change looks different on the wire. Not a fork.
    EquivalentContentDifferentCiphertext,
    /// Both sides carry the same schema-3 counter but different authenticated
    /// contents: two histories claim the same revision. A conflict indicator;
    /// no side can be called newer.
    SameRevisionDifferentContent,
    /// The candidate's counter is higher. Does not show the candidate descends
    /// from the local state.
    CandidateHigherRevision,
    /// The candidate's counter is lower than the local one. This is **not** by
    /// itself a rollback: the local side may simply have unpublished changes.
    /// Only a [`CheckpointComparison`] can speak of a known regression.
    CandidateLowerRevision,
    /// At least one side is a legacy payload with no counter and the contents
    /// differ, so no ordering or equivalence can be established.
    Unordered,
}

/// How the candidate's outer wrapper (`magic`, `version`, `kdf`, `kdf_salt`,
/// `wrapped_vault_key`) compares with the local one, by parsed field equality.
///
/// An observation only. The candidate's wrapper is **not** authenticated by
/// this inspection and `Different` is not evidence of a correctly performed
/// master-password change: it could equally be a malformed or hostile wrapper.
/// Raw JSON formatting differences are invisible here (use
/// [`EnvelopeFingerprint`] for byte identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperRelation {
    Identical,
    Different,
}

/// The outcome of [`inspect_remote_candidate`]: facts about an authenticated,
/// valid candidate. It exposes no decrypted content, and can only be created
/// by [`inspect_remote_candidate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteInspection {
    candidate_revision: AuthenticatedRevision,
    local_revision: AuthenticatedRevision,
    checkpoint: CheckpointComparison,
    payload: PayloadRelation,
    wrapper: WrapperRelation,
}

impl RemoteInspection {
    pub fn candidate_revision(&self) -> AuthenticatedRevision {
        self.candidate_revision
    }

    pub fn local_revision(&self) -> AuthenticatedRevision {
        self.local_revision
    }

    pub fn checkpoint(&self) -> CheckpointComparison {
        self.checkpoint
    }

    pub fn payload(&self) -> PayloadRelation {
        self.payload
    }

    pub fn wrapper(&self) -> WrapperRelation {
        self.wrapper
    }
}

/// Authenticate a candidate remote envelope under the unlocked Vault Key and
/// describe how it relates to the local envelope and a trusted checkpoint.
///
/// # Authentication boundary
///
/// Both `local` and `candidate` payloads are decrypted with the existing
/// payload AEAD and associated data; a payload that does not authenticate is
/// rejected before any deserialization. The master password is not needed.
/// Only the authenticated plaintext is deserialized, by core, with
/// `serde_json::from_slice::<VaultData>`; the result is then checked with
/// `VaultData::validate` (which also rejects unsupported schemas and malformed
/// revision metadata) and its `vault_id` compared with `expected_vault_id`.
///
/// The decrypted serialized bytes are held in a zeroizing buffer and dropped
/// as soon as deserialization returns, and `VaultData` zeroizes itself on drop.
/// Deserializer errors are discarded, never stored or displayed. Transient
/// scratch memory inside `serde_json` itself (for example string-unescaping
/// buffers) is outside this crate's control.
///
/// `expected_vault_id` must come from the caller's trusted local state, never
/// from a file name, URI, remote path, provider label or other unencrypted
/// metadata. `local` must be the caller's own committed local envelope for the
/// same vault; it is authenticated and checked the same way, and a failure is
/// reported as [`InspectionError::LocalReference`].
///
/// # What this does not establish
///
/// * **Freshness.** A revision counter is not a freshness proof. Without
///   `high_water` nothing is known about whether the candidate is the latest;
///   with it, only a *known* regression is detectable.
/// * **Wrapper trust.** The candidate's wrapper is not verified (see
///   [`WrapperRelation`]).
/// * **Legacy guarantees.** A schema 1 or 2 candidate is reported as
///   [`AuthenticatedRevision::Unversioned`], never migrated and never given
///   counter semantics.
///
/// The inspection is read-only: it takes shared references, performs no I/O,
/// and calls neither `prepare_for_write` nor any migration, so repeating it has
/// no effect.
pub fn inspect_remote_candidate(
    vault_key: &SecretKey,
    expected_vault_id: Uuid,
    local: &VaultEnvelope,
    candidate: &VaultEnvelope,
    high_water: Option<RemoteHighWater>,
) -> Result<RemoteInspection, InspectionError> {
    let local_data = authenticate_vault_data(local, vault_key, expected_vault_id)
        .map_err(InspectionError::LocalReference)?;

    let candidate_data = authenticate_vault_data(candidate, vault_key, expected_vault_id)
        .map_err(InspectionError::Candidate)?;

    let local_revision = AuthenticatedRevision::of(&local_data);
    let candidate_revision = AuthenticatedRevision::of(&candidate_data);

    Ok(RemoteInspection {
        candidate_revision,
        local_revision,
        checkpoint: compare_checkpoint(candidate_revision, high_water),
        payload: relate_payloads(
            local,
            &local_data,
            local_revision,
            candidate,
            &candidate_data,
            candidate_revision,
        ),
        wrapper: relate_wrappers(local, candidate),
    })
}

fn authenticate_vault_data(
    envelope: &VaultEnvelope,
    vault_key: &SecretKey,
    expected_vault_id: Uuid,
) -> Result<VaultData, PayloadRejection> {
    let plaintext = open_payload_with_key(envelope, vault_key).map_err(|error| match error {
        VaultError::UnsupportedFormat | VaultError::Crypto(CryptoError::InvalidKdfParameters) => {
            PayloadRejection::UnsupportedFormat
        }
        // Wrong key, corruption and forgery are deliberately one outcome;
        // anything unexpected also fails closed as an authentication failure.
        _ => PayloadRejection::AuthenticationFailed,
    })?;

    // Only authenticated bytes reach the deserializer. The error is discarded
    // on purpose: it can quote positions and content of the plaintext.
    let parsed = serde_json::from_slice::<VaultData>(plaintext.as_slice());

    // Zeroizes the decrypted serialized bytes now rather than at scope end.
    drop(plaintext);

    let data = parsed.map_err(|_| PayloadRejection::MalformedPayload)?;

    data.validate().map_err(|error| match error {
        VaultDataError::UnsupportedSchemaVersion => PayloadRejection::UnsupportedSchema,
        _ => PayloadRejection::InvalidData,
    })?;

    if data.vault_id != expected_vault_id {
        return Err(PayloadRejection::VaultIdMismatch);
    }

    Ok(data)
}

fn compare_checkpoint(
    candidate: AuthenticatedRevision,
    high_water: Option<RemoteHighWater>,
) -> CheckpointComparison {
    match (high_water, candidate) {
        (None, _) => CheckpointComparison::NoCheckpoint,
        (Some(_), AuthenticatedRevision::Unversioned { .. }) => {
            CheckpointComparison::UnversionedCandidate
        }
        (Some(high_water), AuthenticatedRevision::Counter(revision)) => {
            match revision.cmp(&high_water.revision()) {
                std::cmp::Ordering::Less => CheckpointComparison::BelowCheckpoint,
                std::cmp::Ordering::Equal => CheckpointComparison::AtCheckpoint,
                std::cmp::Ordering::Greater => CheckpointComparison::AboveCheckpoint,
            }
        }
    }
}

fn relate_payloads(
    local: &VaultEnvelope,
    local_data: &VaultData,
    local_revision: AuthenticatedRevision,
    candidate: &VaultEnvelope,
    candidate_data: &VaultData,
    candidate_revision: AuthenticatedRevision,
) -> PayloadRelation {
    if local.payload == candidate.payload {
        return PayloadRelation::IdenticalCiphertext;
    }

    // Different ciphertext does not imply different content: both sides are
    // authenticated, so equal decrypted state is equivalence, not a fork.
    if local_data == candidate_data {
        return PayloadRelation::EquivalentContentDifferentCiphertext;
    }

    match (local_revision, candidate_revision) {
        (AuthenticatedRevision::Counter(local), AuthenticatedRevision::Counter(candidate)) => {
            match candidate.cmp(&local) {
                std::cmp::Ordering::Greater => PayloadRelation::CandidateHigherRevision,
                std::cmp::Ordering::Less => PayloadRelation::CandidateLowerRevision,
                std::cmp::Ordering::Equal => PayloadRelation::SameRevisionDifferentContent,
            }
        }
        _ => PayloadRelation::Unordered,
    }
}

fn relate_wrappers(local: &VaultEnvelope, candidate: &VaultEnvelope) -> WrapperRelation {
    let identical = local.magic == candidate.magic
        && local.version == candidate.version
        && local.kdf == candidate.kdf
        && local.kdf_salt == candidate.kdf_salt
        && local.wrapped_vault_key == candidate.wrapped_vault_key;

    if identical {
        WrapperRelation::Identical
    } else {
        WrapperRelation::Different
    }
}

// ---------------------------------------------------------------------------
// Byte-bound remote inspection (Stage 1U-4 A2a)
// ---------------------------------------------------------------------------

/// Largest raw envelope, in bytes, that [`inspect_remote_bytes`] will look at.
///
/// Mirrors the desktop vault-file limit (32 MiB). The check is on the length of
/// the supplied slice and happens before any hashing, parsing or
/// authentication; a longer input is rejected, never truncated.
pub const MAX_ENVELOPE_BYTES: usize = 32 * 1024 * 1024;

/// Which input of [`inspect_remote_bytes`] an error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeInput {
    /// The caller's own committed local envelope (`local_raw`).
    LocalReference,
    /// The remote candidate (`candidate_raw`).
    Candidate,
}

impl fmt::Display for EnvelopeInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LocalReference => "local reference",
            Self::Candidate => "remote candidate",
        })
    }
}

/// Why [`inspect_remote_bytes`] failed.
///
/// Carries only the input that was at fault, lengths and the coarse
/// [`InspectionError`]; never input bytes, deserializer error text or any
/// decrypted content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BoundInspectionError {
    /// The input is longer than [`MAX_ENVELOPE_BYTES`]. Decided from the length
    /// alone, before anything is hashed, parsed or authenticated.
    #[error("{input} envelope is {actual} bytes, over the {limit}-byte limit")]
    InputTooLarge {
        input: EnvelopeInput,
        actual: usize,
        limit: usize,
    },
    /// The input is not a parseable `VaultEnvelope` (not JSON, truncated, wrong
    /// shape or types, trailing data). Header problems in an envelope that does
    /// parse are reported through [`Inspection`](Self::Inspection) instead.
    #[error("{input} is not a readable vault envelope")]
    MalformedEnvelope { input: EnvelopeInput },
    /// Both inputs parsed; authenticated inspection rejected one of them.
    #[error(transparent)]
    Inspection(InspectionError),
}

/// An authenticated [`RemoteInspection`] together with the SHA-256 fingerprints
/// of the exact raw bytes it was computed from.
///
/// The only way to obtain one is [`inspect_remote_bytes`]: the fields are
/// private, there is no constructor, no `From`/`Default` and no mutable access,
/// so fingerprints and inspection cannot be assembled from different file
/// versions or from caller-supplied values. Later transitions are meant to
/// accept this type instead of independent fingerprints and inspections.
///
/// Byte identity and authenticated identity are separate facts: two different
/// raw representations of the same envelope have different fingerprints but the
/// same inspection. A fingerprint here still proves byte identity only.
///
/// ```compile_fail,E0451
/// use localvault_core::sync::{BoundInspection, EnvelopeFingerprint, RemoteInspection};
///
/// fn forge(fingerprint: EnvelopeFingerprint, inspection: RemoteInspection) -> BoundInspection {
///     BoundInspection {
///         local_fingerprint: fingerprint,
///         candidate_fingerprint: fingerprint,
///         inspection,
///     }
/// }
/// ```
///
/// ```compile_fail,E0599
/// use localvault_core::sync::{BoundInspection, EnvelopeFingerprint, RemoteInspection};
///
/// fn forge(fingerprint: EnvelopeFingerprint, inspection: RemoteInspection) -> BoundInspection {
///     BoundInspection::new(fingerprint, fingerprint, inspection)
/// }
/// ```
///
/// ```compile_fail,E0277
/// use localvault_core::sync::{BoundInspection, EnvelopeFingerprint, RemoteInspection};
///
/// fn forge(fingerprint: EnvelopeFingerprint, inspection: RemoteInspection) -> BoundInspection {
///     BoundInspection::from((fingerprint, fingerprint, inspection))
/// }
/// ```
///
/// ```compile_fail,E0616
/// use localvault_core::sync::{BoundInspection, EnvelopeFingerprint};
///
/// fn tamper(bound: &mut BoundInspection, fingerprint: EnvelopeFingerprint) {
///     bound.candidate_fingerprint = fingerprint;
/// }
/// ```
///
/// # Verified vault identity (Stage 1U-4 A2b)
///
/// A `BoundInspection` also remembers the `vault_id` that **both** payloads
/// were authenticated against. It is set only by [`inspect_remote_bytes`], from
/// the `expected_vault_id` that call has just checked against the authenticated,
/// validated local and candidate payloads (a mismatch fails before any value
/// exists). It is readable only inside this crate, so that
/// [`sync_state`](crate::sync_state) transitions can check a stored vault tag
/// against the evidence itself instead of trusting a separate caller-supplied
/// id. It is never exposed publicly and never printed.
///
/// ```compile_fail,E0624
/// use localvault_core::sync::BoundInspection;
///
/// fn leak(bound: &BoundInspection) {
///     let _ = bound.authenticated_vault_id();
/// }
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoundInspection {
    local_fingerprint: EnvelopeFingerprint,
    candidate_fingerprint: EnvelopeFingerprint,
    inspection: RemoteInspection,
    vault_id: Uuid,
}

impl BoundInspection {
    /// The vault identity both inspected payloads were authenticated against.
    /// Crate-private on purpose: see the type documentation.
    pub(crate) fn authenticated_vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Fingerprint of the exact `local_raw` bytes that were inspected.
    pub fn local_fingerprint(&self) -> &EnvelopeFingerprint {
        &self.local_fingerprint
    }

    /// Fingerprint of the exact `candidate_raw` bytes that were inspected.
    pub fn candidate_fingerprint(&self) -> &EnvelopeFingerprint {
        &self.candidate_fingerprint
    }

    /// The authenticated inspection of those two byte strings.
    pub fn inspection(&self) -> &RemoteInspection {
        &self.inspection
    }
}

// Fingerprints and relation facts only: no decrypted content is reachable from
// this type. `Debug` is written out field by field so that a field added later
// cannot reach the output through a derive.
impl fmt::Debug for BoundInspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundInspection")
            .field("local_fingerprint", &self.local_fingerprint)
            .field("candidate_fingerprint", &self.candidate_fingerprint)
            .field("inspection", &self.inspection)
            .finish()
    }
}

/// Fingerprint, parse and authenticate two raw envelopes as one operation.
///
/// # Same-bytes guarantee
///
/// `local_raw` and `candidate_raw` are borrowed once. Each slice is measured,
/// parsed with `serde_json` into a [`VaultEnvelope`] and hashed with SHA-256
/// from that same borrow; nothing is re-read, re-serialized or accepted from the
/// caller. A shared borrow cannot change underneath the call, so the returned
/// fingerprints describe exactly the bytes whose parsed form was authenticated.
/// The fingerprints are of the raw bytes, not of the parsed envelope: reformatting
/// the same JSON changes the fingerprint and nothing else.
///
/// # Order of checks
///
/// 1. Both lengths against [`MAX_ENVELOPE_BYTES`] (local first). Nothing is
///    hashed or parsed until both pass.
/// 2. Parse the local, then the candidate, envelope.
/// 3. Fingerprint both slices.
/// 4. [`inspect_remote_candidate`], unchanged, for authentication, payload
///    validation, vault identity, revision, checkpoint and wrapper relations.
///
/// When several inputs are at fault the first applicable error in that order is
/// returned, so a local-reference problem is never reported as a remote one.
///
/// All of the security semantics of [`inspect_remote_candidate`] apply: no
/// freshness claim without a trusted `high_water`, a candidate behind local is
/// not by itself a rollback, and a different wrapper is only an observation. The
/// function is read-only and performs no I/O.
pub fn inspect_remote_bytes(
    vault_key: &SecretKey,
    expected_vault_id: Uuid,
    local_raw: &[u8],
    candidate_raw: &[u8],
    high_water: Option<RemoteHighWater>,
) -> Result<BoundInspection, BoundInspectionError> {
    check_envelope_len(EnvelopeInput::LocalReference, local_raw)?;
    check_envelope_len(EnvelopeInput::Candidate, candidate_raw)?;

    let local = parse_envelope(EnvelopeInput::LocalReference, local_raw)?;
    let candidate = parse_envelope(EnvelopeInput::Candidate, candidate_raw)?;

    let local_fingerprint = EnvelopeFingerprint::of_bytes(local_raw);
    let candidate_fingerprint = EnvelopeFingerprint::of_bytes(candidate_raw);

    let inspection =
        inspect_remote_candidate(vault_key, expected_vault_id, &local, &candidate, high_water)
            .map_err(BoundInspectionError::Inspection)?;

    // `inspect_remote_candidate` has authenticated, validated and compared the
    // `vault_id` of both payloads with `expected_vault_id`; reaching this point
    // means that identity is verified, not merely claimed.
    Ok(BoundInspection {
        local_fingerprint,
        candidate_fingerprint,
        inspection,
        vault_id: expected_vault_id,
    })
}

// ---------------------------------------------------------------------------
// Local-only authenticated snapshot (Stage 1U-4 A2b)
// ---------------------------------------------------------------------------

/// An authenticated view of the **local** envelope alone, for the case where no
/// remote candidate exists (an initial publication to a remote that is absent).
///
/// It carries exactly three facts, all derived from the same borrowed byte slice
/// by [`inspect_local_bytes`]: the SHA-256 fingerprint of those exact raw bytes,
/// the authenticated [`AuthenticatedRevision`] of the decrypted payload, and the
/// verified vault identity. There is no constructor, no `Default`, no `From`
/// and no mutable access, so a snapshot cannot be fabricated from caller-chosen
/// values, and a revision cannot be paired with a fingerprint of other bytes.
///
/// Like [`BoundInspection`], the vault identity is readable only inside this
/// crate and `Debug` never shows it. A fingerprint here still proves byte
/// identity only.
///
/// ```compile_fail,E0451
/// use localvault_core::sync::{AuthenticatedRevision, EnvelopeFingerprint, LocalSnapshot};
///
/// fn forge(fingerprint: EnvelopeFingerprint) -> LocalSnapshot {
///     LocalSnapshot {
///         fingerprint,
///         revision: AuthenticatedRevision::Counter(1),
///         vault_id: uuid::Uuid::nil(),
///     }
/// }
/// ```
///
/// ```compile_fail,E0599
/// use localvault_core::sync::{AuthenticatedRevision, EnvelopeFingerprint, LocalSnapshot};
///
/// fn forge(fingerprint: EnvelopeFingerprint) -> LocalSnapshot {
///     LocalSnapshot::new(fingerprint, AuthenticatedRevision::Counter(1))
/// }
/// ```
///
/// ```compile_fail,E0599
/// use localvault_core::sync::LocalSnapshot;
///
/// fn forge() -> LocalSnapshot {
///     LocalSnapshot::default()
/// }
/// ```
///
/// ```compile_fail,E0277
/// use localvault_core::sync::{AuthenticatedRevision, EnvelopeFingerprint, LocalSnapshot};
///
/// fn forge(fingerprint: EnvelopeFingerprint) -> LocalSnapshot {
///     LocalSnapshot::from((fingerprint, AuthenticatedRevision::Counter(1)))
/// }
/// ```
///
/// ```compile_fail,E0616
/// use localvault_core::sync::{AuthenticatedRevision, LocalSnapshot};
///
/// fn tamper(snapshot: &mut LocalSnapshot) {
///     snapshot.revision = AuthenticatedRevision::Counter(u64::MAX);
/// }
/// ```
///
/// ```compile_fail,E0624
/// use localvault_core::sync::LocalSnapshot;
///
/// fn leak(snapshot: &LocalSnapshot) {
///     let _ = snapshot.authenticated_vault_id();
/// }
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalSnapshot {
    fingerprint: EnvelopeFingerprint,
    revision: AuthenticatedRevision,
    vault_id: Uuid,
}

impl LocalSnapshot {
    /// Fingerprint of the exact `local_raw` bytes that were authenticated.
    pub fn fingerprint(&self) -> &EnvelopeFingerprint {
        &self.fingerprint
    }

    /// The authenticated revision of the local payload: a schema-3 counter, or
    /// an explicit [`AuthenticatedRevision::Unversioned`] for a legacy payload.
    pub fn revision(&self) -> AuthenticatedRevision {
        self.revision
    }

    /// The vault identity the payload was authenticated against. Crate-private
    /// on purpose: see the type documentation.
    pub(crate) fn authenticated_vault_id(&self) -> Uuid {
        self.vault_id
    }
}

// Fingerprint and revision only; the vault identity is deliberately absent, and
// written out field by field so that a field added later cannot reach the output
// through a derive.
impl fmt::Debug for LocalSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSnapshot")
            .field("fingerprint", &self.fingerprint)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// Fingerprint, parse and authenticate one raw **local** envelope.
///
/// The counterpart of [`inspect_remote_bytes`] for when no candidate exists. It
/// takes the same borrow once and derives everything from it:
///
/// 1. the length against [`MAX_ENVELOPE_BYTES`], before anything is hashed,
///    parsed or decrypted;
/// 2. the `VaultEnvelope` parse (a failure is
///    [`MalformedEnvelope`](BoundInspectionError::MalformedEnvelope) of the
///    [`LocalReference`](EnvelopeInput::LocalReference) input);
/// 3. the SHA-256 fingerprint of the same slice;
/// 4. the existing private `authenticate_vault_data`, unchanged: payload AEAD
///    under `vault_key`, deserialization of only the authenticated bytes,
///    `VaultData::validate` (supported schema, well-formed revision) and the
///    `vault_id` comparison with `expected_vault_id`;
/// 5. the [`AuthenticatedRevision`] of the validated payload.
///
/// Every failure is attributed to the local reference, never to a remote
/// candidate, and carries no input bytes, parser text or decrypted content. The
/// decrypted buffer is zeroized as soon as it is parsed and `VaultData`
/// zeroizes itself on drop. No payload is migrated and
/// `VaultData::prepare_for_write` is never called. The function is read-only and
/// performs no I/O.
pub fn inspect_local_bytes(
    vault_key: &SecretKey,
    expected_vault_id: Uuid,
    local_raw: &[u8],
) -> Result<LocalSnapshot, BoundInspectionError> {
    check_envelope_len(EnvelopeInput::LocalReference, local_raw)?;

    let local = parse_envelope(EnvelopeInput::LocalReference, local_raw)?;

    let fingerprint = EnvelopeFingerprint::of_bytes(local_raw);

    let data = authenticate_vault_data(&local, vault_key, expected_vault_id).map_err(|reason| {
        BoundInspectionError::Inspection(InspectionError::LocalReference(reason))
    })?;

    Ok(LocalSnapshot {
        fingerprint,
        revision: AuthenticatedRevision::of(&data),
        // Authenticated and compared with `expected_vault_id` just above.
        vault_id: data.vault_id,
    })
}

fn check_envelope_len(input: EnvelopeInput, raw: &[u8]) -> Result<(), BoundInspectionError> {
    if raw.len() > MAX_ENVELOPE_BYTES {
        return Err(BoundInspectionError::InputTooLarge {
            input,
            actual: raw.len(),
            limit: MAX_ENVELOPE_BYTES,
        });
    }
    Ok(())
}

fn parse_envelope(input: EnvelopeInput, raw: &[u8]) -> Result<VaultEnvelope, BoundInspectionError> {
    // The deserializer error is discarded on purpose: it can quote positions
    // and fragments of the input.
    serde_json::from_slice::<VaultEnvelope>(raw)
        .map_err(|_| BoundInspectionError::MalformedEnvelope { input })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA1_FIXTURE: &[u8] =
        include_bytes!("../../../src-tauri/tests/fixtures/compat/schema1_baseline.envelope.json");
    const SCHEMA2_FIXTURE: &[u8] =
        include_bytes!("../../../src-tauri/tests/fixtures/compat/schema2_baseline.envelope.json");

    /// Distinct, deterministic fingerprints for table tests.
    fn fp(tag: u8) -> EnvelopeFingerprint {
        EnvelopeFingerprint::of_bytes(&[tag])
    }

    fn present(tag: u8) -> RemoteObservation {
        RemoteObservation::Present(fp(tag))
    }

    // ---- SHA-256 known answers --------------------------------------------

    #[test]
    fn sha256_known_answer_vectors() {
        let vectors: [(&[u8], &str); 3] = [
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (input, expected) in vectors {
            assert_eq!(EnvelopeFingerprint::of_bytes(input).to_hex(), expected);
        }
    }

    #[test]
    fn sha256_one_million_a_vector() {
        let input = vec![b'a'; 1_000_000];
        assert_eq!(
            EnvelopeFingerprint::of_bytes(&input).to_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn committed_fixtures_match_independently_computed_hashes() {
        // Expected values computed outside this module with `sha256sum` on the
        // committed files; the fixtures have no line-ending conversion.
        assert_eq!(
            EnvelopeFingerprint::of_bytes(SCHEMA1_FIXTURE).to_hex(),
            "17edf060385cca1a778b2236842ecfa44d21aa174d9b70092c1d9cbdd0fcb9a8"
        );
        assert_eq!(
            EnvelopeFingerprint::of_bytes(SCHEMA2_FIXTURE).to_hex(),
            "f5bf1fcdb11115f0fa39598389a7a8ce3b9c44b78ddfd5295b57845b52155f55"
        );
    }

    #[test]
    fn fingerprint_covers_exact_raw_bytes_not_parsed_json() {
        // Same JSON document, different bytes: the fingerprint must differ.
        let mut with_newline = SCHEMA2_FIXTURE.to_vec();
        with_newline.push(b'\n');
        let mut with_leading_space = vec![b' '];
        with_leading_space.extend_from_slice(SCHEMA2_FIXTURE);

        let base = EnvelopeFingerprint::of_bytes(SCHEMA2_FIXTURE);
        assert_ne!(base, EnvelopeFingerprint::of_bytes(&with_newline));
        assert_ne!(base, EnvelopeFingerprint::of_bytes(&with_leading_space));
    }

    // ---- equality ----------------------------------------------------------

    #[test]
    fn equal_bytes_give_equal_fingerprints_and_different_bytes_do_not() {
        assert_eq!(
            EnvelopeFingerprint::of_bytes(b"envelope"),
            EnvelopeFingerprint::of_bytes(b"envelope")
        );
        assert_ne!(
            EnvelopeFingerprint::of_bytes(b"envelope"),
            EnvelopeFingerprint::of_bytes(b"envelopf")
        );
        assert_ne!(
            EnvelopeFingerprint::of_bytes(b""),
            EnvelopeFingerprint::of_bytes(b"\0")
        );
        assert_ne!(SCHEMA1_FIXTURE, SCHEMA2_FIXTURE);
        assert_ne!(
            EnvelopeFingerprint::of_bytes(SCHEMA1_FIXTURE),
            EnvelopeFingerprint::of_bytes(SCHEMA2_FIXTURE)
        );
    }

    // ---- hex encoding ------------------------------------------------------

    #[test]
    fn hex_is_64_lowercase_characters() {
        let hex = fp(7).to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn hex_round_trips_canonically() {
        let all_bytes: [u8; 32] = std::array::from_fn(|i| (i as u8) * 8 + 3);
        let samples = [
            fp(0),
            fp(255),
            EnvelopeFingerprint::of_bytes(SCHEMA1_FIXTURE),
            EnvelopeFingerprint::of_bytes(SCHEMA2_FIXTURE),
            EnvelopeFingerprint(all_bytes),
            EnvelopeFingerprint([0u8; 32]),
            EnvelopeFingerprint([0xff; 32]),
        ];
        for sample in samples {
            let hex = sample.to_hex();
            assert_eq!(EnvelopeFingerprint::from_hex(&hex), Ok(sample));
            assert_eq!(hex.parse::<EnvelopeFingerprint>(), Ok(sample));
            assert_eq!(sample.to_string(), hex);
        }
    }

    #[test]
    fn hex_decoding_matches_known_bytes() {
        let parsed = EnvelopeFingerprint::from_hex(
            "00010203040506070809101112131415161718191a1b1c1d1e1f202122232425",
        )
        .unwrap();
        assert_eq!(parsed.as_bytes()[0], 0x00);
        assert_eq!(parsed.as_bytes()[9], 0x09);
        assert_eq!(parsed.as_bytes()[10], 0x10);
        assert_eq!(parsed.as_bytes()[20], 0x1a);
        assert_eq!(parsed.as_bytes()[26], 0x20);
        assert_eq!(parsed.as_bytes()[31], 0x25);
    }

    #[test]
    fn debug_output_is_hex_not_raw_array() {
        assert_eq!(
            format!("{:?}", EnvelopeFingerprint([0xab; 32])),
            format!("EnvelopeFingerprint({})", "ab".repeat(32))
        );
    }

    #[test]
    fn rejects_invalid_hex_characters() {
        let good = "a".repeat(64);
        for bad in ['g', 'z', 'x', ' ', '-', '\n', '\0'] {
            let mut text = good.clone();
            text.replace_range(10..11, &bad.to_string());
            assert_eq!(
                EnvelopeFingerprint::from_hex(&text),
                Err(FingerprintParseError::InvalidCharacter { index: 10 }),
                "char {bad:?}"
            );
        }
        // A two-byte character keeps the byte length at 64 but is not hex.
        let mut text = "a".repeat(62);
        text.push('é');
        assert_eq!(text.len(), 64);
        assert_eq!(
            EnvelopeFingerprint::from_hex(&text),
            Err(FingerprintParseError::InvalidCharacter { index: 62 })
        );
        // Prefix and padding forms are not accepted.
        let prefixed = format!("0x{}", "a".repeat(62));
        assert_eq!(
            EnvelopeFingerprint::from_hex(&prefixed),
            Err(FingerprintParseError::InvalidCharacter { index: 1 })
        );
        let padded = format!(" {}", "a".repeat(63));
        assert_eq!(
            EnvelopeFingerprint::from_hex(&padded),
            Err(FingerprintParseError::InvalidCharacter { index: 0 })
        );
    }

    #[test]
    fn rejects_wrong_length_encodings() {
        for len in [0usize, 1, 31, 32, 62, 63, 65, 66, 128] {
            let text = "a".repeat(len);
            assert_eq!(
                EnvelopeFingerprint::from_hex(&text),
                Err(FingerprintParseError::InvalidLength { actual: len }),
                "length {len}"
            );
        }
        let trailing_newline = format!("{}\n", "a".repeat(64));
        assert_eq!(
            EnvelopeFingerprint::from_hex(&trailing_newline),
            Err(FingerprintParseError::InvalidLength { actual: 65 })
        );
    }

    #[test]
    fn rejects_noncanonical_uppercase_encodings() {
        let canonical = fp(1).to_hex();
        let upper = canonical.to_uppercase();
        // Only reject when uppercase actually changes the text.
        assert!(canonical.bytes().any(|b| (b'a'..=b'f').contains(&b)));
        assert!(matches!(
            EnvelopeFingerprint::from_hex(&upper),
            Err(FingerprintParseError::UppercaseCharacter { .. })
        ));

        let mixed = format!("{}F{}", "0".repeat(20), "0".repeat(43));
        assert_eq!(
            EnvelopeFingerprint::from_hex(&mixed),
            Err(FingerprintParseError::UppercaseCharacter { index: 20 })
        );
        // A digits-only fingerprint has no case, so it is canonical either way.
        let digits = "7".repeat(64);
        assert!(EnvelopeFingerprint::from_hex(&digits).is_ok());
    }

    #[test]
    fn parse_errors_do_not_echo_input() {
        let secretish = format!("{}hunter2{}", "a".repeat(10), "a".repeat(47));
        let message = EnvelopeFingerprint::from_hex(&secretish)
            .unwrap_err()
            .to_string();
        assert!(!message.contains("hunter2"));
    }

    // ---- classification ----------------------------------------------------

    #[test]
    fn classification_decision_table() {
        use SyncClassification::*;

        // (label, last_synced tag, local tag, remote, expected)
        let table: &[(&str, Option<u8>, u8, RemoteObservation, SyncClassification)] = &[
            // No previous sync.
            (
                "initial, remote absent",
                None,
                1,
                RemoteObservation::Absent,
                RemoteMissing,
            ),
            (
                "initial, remote identical",
                None,
                1,
                present(1),
                UnbasedMatch,
            ),
            (
                "initial, remote different",
                None,
                1,
                present(2),
                UnbasedDifference,
            ),
            // Previous sync, remote gone.
            (
                "synced, remote gone, local unchanged",
                Some(1),
                1,
                RemoteObservation::Absent,
                RemoteDisappeared,
            ),
            (
                "synced, remote gone, local changed",
                Some(1),
                2,
                RemoteObservation::Absent,
                RemoteDisappeared,
            ),
            // Previous sync, remote present.
            ("in sync", Some(1), 1, present(1), InSync),
            ("local changed only", Some(1), 2, present(1), LocalAhead),
            ("remote changed only", Some(1), 1, present(2), RemoteAhead),
            (
                "both changed, same bytes",
                Some(1),
                2,
                present(2),
                Converged,
            ),
            (
                "both changed, different bytes",
                Some(1),
                2,
                present(3),
                Diverged,
            ),
            ("both changed, swapped", Some(1), 3, present(2), Diverged),
            // Local reverted to the base while the remote moved on.
            (
                "remote changed, local equals base",
                Some(2),
                2,
                present(3),
                RemoteAhead,
            ),
            // Unreadable remote is never a decision input.
            (
                "initial, remote unavailable",
                None,
                1,
                RemoteObservation::Unavailable,
                RemoteUnavailable,
            ),
            (
                "synced, remote unavailable",
                Some(1),
                1,
                RemoteObservation::Unavailable,
                RemoteUnavailable,
            ),
            (
                "synced, local changed, remote unavailable",
                Some(1),
                2,
                RemoteObservation::Unavailable,
                RemoteUnavailable,
            ),
        ];

        for (label, last, local, remote, expected) in table {
            let last = last.map(fp);
            assert_eq!(
                classify(last.as_ref(), &fp(*local), remote),
                *expected,
                "{label}"
            );
        }
    }

    #[test]
    fn classification_invariants_hold_over_every_input_combination() {
        use SyncClassification::*;

        let tags = [1u8, 2, 3];
        let lasts = [None, Some(1u8), Some(2), Some(3)];

        for last in lasts {
            let last = last.map(fp);
            for local in tags {
                // Absent and Unavailable depend on nothing but `last_synced`.
                assert_eq!(
                    classify(last.as_ref(), &fp(local), &RemoteObservation::Unavailable),
                    RemoteUnavailable
                );
                assert_eq!(
                    classify(last.as_ref(), &fp(local), &RemoteObservation::Absent),
                    if last.is_some() {
                        RemoteDisappeared
                    } else {
                        RemoteMissing
                    }
                );

                for remote in tags {
                    let got = classify(last.as_ref(), &fp(local), &present(remote));

                    // A readable remote never yields the absent/unreadable outcomes.
                    assert!(!matches!(
                        got,
                        RemoteMissing | RemoteDisappeared | RemoteUnavailable
                    ));

                    // Swapping local and remote mirrors the outcome.
                    let mirrored = classify(last.as_ref(), &fp(remote), &present(local));
                    let expected_mirror = match got {
                        LocalAhead => RemoteAhead,
                        RemoteAhead => LocalAhead,
                        other => other,
                    };
                    assert_eq!(mirrored, expected_mirror);

                    // Identical bytes on both sides can only be agreement.
                    if local == remote {
                        assert!(matches!(got, InSync | Converged | UnbasedMatch));
                    }
                    // Agreement on the recorded base is the only InSync.
                    assert_eq!(got == InSync, last == Some(fp(local)) && local == remote);
                    // Diverged needs three distinct fingerprints.
                    if got == Diverged {
                        assert!(last != Some(fp(local)) && last != Some(fp(remote)));
                        assert_ne!(local, remote);
                    }
                }
            }
        }
    }

    // ---- push-intent reconciliation ---------------------------------------

    fn intent(baseline: PushBaseline, intended: u8) -> PushIntent {
        PushIntent::new(baseline, fp(intended)).unwrap()
    }

    #[test]
    fn push_reconcile_published_when_remote_equals_intended() {
        let from_present = intent(PushBaseline::Present(fp(1)), 2);
        assert_eq!(
            from_present.reconcile(&present(2)),
            PushReconciliation::Published
        );

        let initial = intent(PushBaseline::Absent, 2);
        assert_eq!(
            initial.reconcile(&present(2)),
            PushReconciliation::Published
        );
    }

    #[test]
    fn push_reconcile_not_published_when_remote_equals_baseline() {
        let from_present = intent(PushBaseline::Present(fp(1)), 2);
        assert_eq!(
            from_present.reconcile(&present(1)),
            PushReconciliation::NotPublished
        );
    }

    #[test]
    fn push_reconcile_unknown_when_remote_differs_from_both() {
        let from_present = intent(PushBaseline::Present(fp(1)), 2);
        assert_eq!(
            from_present.reconcile(&present(3)),
            PushReconciliation::Unknown
        );

        let initial = intent(PushBaseline::Absent, 2);
        assert_eq!(initial.reconcile(&present(3)), PushReconciliation::Unknown);
    }

    #[test]
    fn initial_publication_push_intent_behavior() {
        let initial = intent(PushBaseline::Absent, 2);
        assert_eq!(initial.baseline(), &PushBaseline::Absent);
        assert_eq!(initial.intended(), &fp(2));

        // Still absent: the push did not land.
        assert_eq!(
            initial.reconcile(&RemoteObservation::Absent),
            PushReconciliation::NotPublished
        );
        // Landed.
        assert_eq!(
            initial.reconcile(&present(2)),
            PushReconciliation::Published
        );
        // Someone else created a different file meanwhile.
        assert_eq!(initial.reconcile(&present(1)), PushReconciliation::Unknown);
    }

    #[test]
    fn remote_vanishing_after_a_present_baseline_is_unknown_not_not_published() {
        let from_present = intent(PushBaseline::Present(fp(1)), 2);
        assert_eq!(
            from_present.reconcile(&RemoteObservation::Absent),
            PushReconciliation::Unknown
        );
    }

    #[test]
    fn unreadable_remote_is_never_published_or_not_published() {
        let intents = [
            intent(PushBaseline::Absent, 2),
            intent(PushBaseline::Present(fp(1)), 2),
        ];
        for intent in intents {
            assert_eq!(
                intent.reconcile(&RemoteObservation::Unavailable),
                PushReconciliation::Unknown
            );
        }
    }

    #[test]
    fn push_intent_rejects_a_push_that_changes_nothing() {
        assert_eq!(
            PushIntent::new(PushBaseline::Present(fp(1)), fp(1)),
            Err(PushIntentError::NoChange)
        );
        // From an absent remote, any intended bytes are a real change.
        assert!(PushIntent::new(PushBaseline::Absent, fp(1)).is_ok());
    }

    // ---- confirmed absence vs unreadable remote ----------------------------

    #[test]
    fn confirmed_absence_and_unreadable_remote_are_distinct_at_the_api_boundary() {
        assert_ne!(RemoteObservation::Absent, RemoteObservation::Unavailable);

        let local = fp(1);
        for last in [None, Some(fp(1))] {
            let absent = classify(last.as_ref(), &local, &RemoteObservation::Absent);
            let unavailable = classify(last.as_ref(), &local, &RemoteObservation::Unavailable);
            assert_ne!(absent, unavailable);
            assert_eq!(unavailable, SyncClassification::RemoteUnavailable);
            assert!(matches!(
                absent,
                SyncClassification::RemoteMissing | SyncClassification::RemoteDisappeared
            ));
        }

        // Push reconciliation: absence can mean "not published" for an initial
        // push; an unreadable remote never can.
        let initial = intent(PushBaseline::Absent, 2);
        assert_eq!(
            initial.reconcile(&RemoteObservation::Absent),
            PushReconciliation::NotPublished
        );
        assert_eq!(
            initial.reconcile(&RemoteObservation::Unavailable),
            PushReconciliation::Unknown
        );
    }
}

/// Stage 1U-3 tests. Kept apart from the 1U-1 `tests` module, which is
/// unchanged. Synthetic data only; the committed fixtures are read-only.
#[cfg(test)]
mod inspection_tests {
    use super::*;
    use crate::vault::{
        data::{
            VaultEntry, LEGACY_VAULT_DATA_SCHEMA_VERSION, PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        },
        format::{
            create_envelope_with_key, open_envelope_with_key, reseal_envelope,
            rewrap_envelope_master_password,
        },
    };

    const SCHEMA1_FIXTURE: &[u8] =
        include_bytes!("../../../src-tauri/tests/fixtures/compat/schema1_baseline.envelope.json");
    const SCHEMA2_FIXTURE: &[u8] =
        include_bytes!("../../../src-tauri/tests/fixtures/compat/schema2_baseline.envelope.json");
    const SCHEMA3_FIXTURE: &[u8] =
        include_bytes!("../../../src-tauri/tests/fixtures/compat/schema3_baseline.envelope.json");

    const FIXTURE_PASSWORD: &str = "compat-baseline-master-password-test-only";
    const MASTER: &str = "inspection-test-only-master-password";
    const NEW_MASTER: &str = "inspection-test-only-new-master-password";
    const SECRET: &str = "INSPECTION_TEST_ONLY_SECRET";
    const NOW_MS: i64 = 1_700_000_000_000;

    fn bytes_of(data: &VaultData) -> Vec<u8> {
        serde_json::to_vec(data).unwrap()
    }

    /// One vault: its Vault Key, id and a local envelope at revision 3.
    struct Rig {
        local: VaultEnvelope,
        key: SecretKey,
        base: VaultData,
    }

    impl Rig {
        fn new() -> Self {
            let mut base = VaultData::new(NOW_MS).unwrap();

            let mut entry = VaultEntry::new("Inspection Entry", NOW_MS).unwrap();
            entry.password = SECRET.to_owned();
            base.entries.push(entry);

            base.revision = 3;
            base.validate().unwrap();

            let (local, key) = create_envelope_with_key(MASTER, &bytes_of(&base)).unwrap();

            Self { local, key, base }
        }

        fn id(&self) -> Uuid {
            self.base.vault_id
        }

        fn data(&self, revision: u64) -> VaultData {
            let mut data = self.base.clone();
            data.revision = revision;
            data
        }

        fn legacy(&self, schema_version: u16) -> VaultData {
            let mut data = self.base.clone();
            data.schema_version = schema_version;
            data.revision = 0;
            data
        }

        fn seal(&self, data: &VaultData) -> VaultEnvelope {
            self.seal_raw(&bytes_of(data))
        }

        fn seal_raw(&self, plaintext: &[u8]) -> VaultEnvelope {
            reseal_envelope(&self.local, &self.key, plaintext).unwrap()
        }

        fn at(&self, revision: u64) -> VaultEnvelope {
            self.seal(&self.data(revision))
        }

        fn inspect(
            &self,
            local: &VaultEnvelope,
            candidate: &VaultEnvelope,
            high_water: Option<RemoteHighWater>,
        ) -> Result<RemoteInspection, InspectionError> {
            inspect_remote_candidate(&self.key, self.id(), local, candidate, high_water)
        }

        fn inspect_local(
            &self,
            candidate: &VaultEnvelope,
        ) -> Result<RemoteInspection, InspectionError> {
            self.inspect(&self.local, candidate, None)
        }
    }

    fn high_water(revision: u64) -> Option<RemoteHighWater> {
        Some(RemoteHighWater::new(revision))
    }

    fn rejected_candidate(reason: PayloadRejection) -> InspectionError {
        InspectionError::Candidate(reason)
    }

    // ---- 1. valid candidate ------------------------------------------------

    #[test]
    fn valid_authenticated_candidate_is_described_without_exposing_content() {
        let rig = Rig::new();
        let candidate = rig.at(5);

        let inspection = rig.inspect(&rig.local, &candidate, None).unwrap();

        assert_eq!(
            inspection.candidate_revision(),
            AuthenticatedRevision::Counter(5)
        );
        assert_eq!(
            inspection.local_revision(),
            AuthenticatedRevision::Counter(3)
        );
        assert_eq!(
            inspection.payload(),
            PayloadRelation::CandidateHigherRevision
        );
        assert_eq!(inspection.wrapper(), WrapperRelation::Identical);
        assert_eq!(inspection.checkpoint(), CheckpointComparison::NoCheckpoint);

        // Nothing decrypted is reachable from the result or its Debug output.
        let rendered = format!("{inspection:?}");
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains("Inspection Entry"));
        assert!(!rendered.contains(&rig.id().to_string()));
    }

    // ---- 2./3. corruption, wrong key --------------------------------------

    #[test]
    fn corrupt_candidate_payload_is_rejected() {
        let rig = Rig::new();

        let mut flipped_ciphertext = rig.at(5);
        flipped_ciphertext.payload.ciphertext[0] ^= 0x01;

        let mut flipped_nonce = rig.at(5);
        flipped_nonce.payload.nonce[0] ^= 0x01;

        let mut flipped_tag = rig.at(5);
        *flipped_tag.payload.ciphertext.last_mut().unwrap() ^= 0x01;

        let mut truncated = rig.at(5);
        truncated.payload.ciphertext.truncate(10);

        let mut emptied = rig.at(5);
        emptied.payload.ciphertext.clear();

        for candidate in [
            flipped_ciphertext,
            flipped_nonce,
            flipped_tag,
            truncated,
            emptied,
        ] {
            assert_eq!(
                rig.inspect_local(&candidate),
                Err(rejected_candidate(PayloadRejection::AuthenticationFailed))
            );
        }
    }

    #[test]
    fn authentication_precedes_deserialization() {
        let rig = Rig::new();

        // Authentic bytes that are not a vault payload are a deserialization
        // failure ...
        let authentic = rig.seal_raw(b"this is not json");

        assert_eq!(
            rig.inspect_local(&authentic),
            Err(rejected_candidate(PayloadRejection::MalformedPayload))
        );

        // ... but the very same payload with one flipped bit never reaches the
        // deserializer: it is an authentication failure, not a malformed one.
        for tamper in [
            |envelope: &mut VaultEnvelope| envelope.payload.ciphertext[0] ^= 0x01,
            |envelope: &mut VaultEnvelope| envelope.payload.nonce[0] ^= 0x01,
        ] {
            let mut tampered = authentic.clone();
            tamper(&mut tampered);

            assert_eq!(
                rig.inspect_local(&tampered),
                Err(rejected_candidate(PayloadRejection::AuthenticationFailed))
            );
        }

        // The same holds for a payload sealed under a different Vault Key.
        let other = Rig::new();
        let foreign = other.seal_raw(b"this is not json");

        assert_eq!(
            rig.inspect_local(&foreign),
            Err(rejected_candidate(PayloadRejection::AuthenticationFailed))
        );
    }

    #[test]
    fn candidate_sealed_under_another_vault_key_is_rejected() {
        let rig = Rig::new();
        let other = Rig::new();

        // `other` has its own Vault Key; its envelopes cannot authenticate
        // under `rig.key` even though the structure is perfectly valid.
        let foreign = other.at(5);

        assert_eq!(
            rig.inspect_local(&foreign),
            Err(rejected_candidate(PayloadRejection::AuthenticationFailed))
        );

        // Same outcome with the right candidate but the wrong key: the error
        // is the same class as corruption, so the two are indistinguishable.
        let candidate = rig.at(5);

        assert_eq!(
            inspect_remote_candidate(&other.key, rig.id(), &rig.local, &candidate, None),
            Err(InspectionError::LocalReference(
                PayloadRejection::AuthenticationFailed
            ))
        );
    }

    // ---- 4. vault identity -------------------------------------------------

    #[test]
    fn candidate_from_a_different_vault_id_is_rejected_after_authentication() {
        let rig = Rig::new();

        // Authentic under the right key, valid, but a different vault_id: the
        // identity comes from the authenticated payload, never from metadata.
        let mut other_vault = rig.data(5);
        other_vault.vault_id = Uuid::new_v4();

        assert_ne!(other_vault.vault_id, rig.id());

        let candidate = rig.seal(&other_vault);

        assert_eq!(
            rig.inspect_local(&candidate),
            Err(rejected_candidate(PayloadRejection::VaultIdMismatch))
        );
    }

    #[test]
    fn local_reference_of_another_vault_is_blamed_on_the_local_side() {
        let rig = Rig::new();

        let mut other_vault = rig.data(3);
        other_vault.vault_id = Uuid::new_v4();
        let other_local = rig.seal(&other_vault);

        assert_eq!(
            rig.inspect(&other_local, &rig.at(5), None),
            Err(InspectionError::LocalReference(
                PayloadRejection::VaultIdMismatch
            ))
        );

        // A nil expected id can never match a valid payload: fail closed.
        assert_eq!(
            inspect_remote_candidate(&rig.key, Uuid::nil(), &rig.local, &rig.at(5), None),
            Err(InspectionError::LocalReference(
                PayloadRejection::VaultIdMismatch
            ))
        );
    }

    // ---- 5. unsupported schema ---------------------------------------------

    #[test]
    fn future_and_zero_schemas_are_unsupported_not_downgraded() {
        let rig = Rig::new();

        for schema in [0u64, 4, 5, u64::from(u16::MAX)] {
            let mut value = serde_json::to_value(rig.data(5)).unwrap();
            value["schema_version"] = serde_json::json!(schema);

            let candidate = rig.seal_raw(&serde_json::to_vec(&value).unwrap());

            assert_eq!(
                rig.inspect_local(&candidate),
                Err(rejected_candidate(PayloadRejection::UnsupportedSchema)),
                "schema {schema}"
            );
        }
    }

    // ---- 6. malformed payloads ---------------------------------------------

    #[test]
    fn authentic_but_malformed_payloads_are_rejected() {
        let rig = Rig::new();

        let schema3_missing_revision = {
            let mut value = serde_json::to_value(rig.data(5)).unwrap();
            value.as_object_mut().unwrap().remove("revision");
            serde_json::to_vec(&value).unwrap()
        };

        let legacy_carrying_revision = {
            let mut value = serde_json::to_value(rig.legacy(2)).unwrap();
            value["revision"] = serde_json::json!(1);
            serde_json::to_vec(&value).unwrap()
        };

        let revision_as_string = {
            let mut value = serde_json::to_value(rig.data(5)).unwrap();
            value["revision"] = serde_json::json!("5");
            serde_json::to_vec(&value).unwrap()
        };

        let samples: [&[u8]; 7] = [
            b"",
            b"not json",
            b"{}",
            br#"{"schema_version":3}"#,
            &schema3_missing_revision,
            &legacy_carrying_revision,
            &revision_as_string,
        ];

        for plaintext in samples {
            let candidate = rig.seal_raw(plaintext);

            assert_eq!(
                rig.inspect_local(&candidate),
                Err(rejected_candidate(PayloadRejection::MalformedPayload))
            );
        }
    }

    #[test]
    fn authentic_and_parseable_but_invalid_data_is_rejected() {
        let rig = Rig::new();

        let mut duplicate_entry = rig.data(5);
        let copy = duplicate_entry.entries[0].clone();
        duplicate_entry.entries.push(copy);

        let mut empty_title = rig.data(5);
        empty_title.entries[0].title = String::new();

        let mut nil_vault_id = rig.data(5);
        nil_vault_id.vault_id = Uuid::nil();

        for invalid in [duplicate_entry, empty_title, nil_vault_id] {
            assert_eq!(
                rig.inspect_local(&rig.seal(&invalid)),
                Err(rejected_candidate(PayloadRejection::InvalidData))
            );
        }
    }

    #[test]
    fn malformed_authenticated_local_reference_is_blamed_on_the_local_side() {
        let rig = Rig::new();

        let malformed_local = rig.seal_raw(b"{ not json");

        // The local reference is read first, so that is where it surfaces.
        assert_eq!(
            rig.inspect(&malformed_local, &rig.at(5), None),
            Err(InspectionError::LocalReference(
                PayloadRejection::MalformedPayload
            ))
        );
    }

    #[test]
    fn malformed_schema_revisions_are_rejected_in_core() {
        let rig = Rig::new();

        let malformed = [
            serde_json::json!(null),
            serde_json::json!("5"),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!(true),
            serde_json::json!([5]),
            // One past u64::MAX.
            serde_json::from_str::<serde_json::Value>("18446744073709551616").unwrap(),
        ];

        for schema_version in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
            VAULT_DATA_SCHEMA_VERSION,
        ] {
            for revision in &malformed {
                let mut value = serde_json::to_value(rig.data(5)).unwrap();
                value["schema_version"] = serde_json::json!(schema_version);
                value["revision"] = revision.clone();

                let candidate = rig.seal_raw(&serde_json::to_vec(&value).unwrap());

                assert_eq!(
                    rig.inspect_local(&candidate),
                    Err(rejected_candidate(PayloadRejection::MalformedPayload)),
                    "schema {schema_version} accepted revision {revision}"
                );
            }
        }
    }

    #[test]
    fn core_deserializes_valid_authenticated_json_whatever_its_formatting() {
        let rig = Rig::new();

        // Pretty-printed, with the keys in a different order than the
        // serializer emits them: only the content matters.
        let mut value = serde_json::to_value(rig.data(11)).unwrap();
        let revision = value.as_object_mut().unwrap().remove("revision").unwrap();
        let entries = value.as_object_mut().unwrap().remove("entries").unwrap();

        let mut reordered = serde_json::Map::new();
        reordered.insert("revision".to_owned(), revision);
        reordered.insert("entries".to_owned(), entries);
        reordered.extend(value.as_object().unwrap().clone());

        let candidate = rig
            .seal_raw(&serde_json::to_vec_pretty(&serde_json::Value::Object(reordered)).unwrap());

        let inspection = rig.inspect_local(&candidate).unwrap();

        assert_eq!(
            inspection.candidate_revision(),
            AuthenticatedRevision::Counter(11)
        );
        assert_eq!(
            inspection.payload(),
            PayloadRelation::CandidateHigherRevision
        );
    }

    #[test]
    fn the_inspection_result_comes_only_from_the_authenticated_payload() {
        // The function is not generic and takes no parser or deserialized data:
        // this only type-checks for exactly this signature, so a caller cannot
        // influence what core "reads" from the authenticated bytes.
        type ExactSignature = fn(
            &SecretKey,
            Uuid,
            &VaultEnvelope,
            &VaultEnvelope,
            Option<RemoteHighWater>,
        ) -> Result<RemoteInspection, InspectionError>;

        let _signature: ExactSignature = inspect_remote_candidate;

        // Two candidates differing only in their authenticated plaintext give
        // results that follow that plaintext.
        let rig = Rig::new();

        for revision in [1u64, 4, 99] {
            assert_eq!(
                rig.inspect_local(&rig.at(revision))
                    .unwrap()
                    .candidate_revision(),
                AuthenticatedRevision::Counter(revision)
            );
        }
    }

    #[test]
    fn deserializer_errors_never_reach_the_error_or_debug_output() {
        let rig = Rig::new();

        // Malformed JSON that embeds secret-looking content: serde_json would
        // quote positions and sometimes fragments in its own error text.
        let sentinel = "MALFORMED_JSON_SENTINEL_SECRET";
        let plaintext = format!(r#"{{"schema_version":3,"password":"{sentinel}","revision":"#);

        let candidate = rig.seal_raw(plaintext.as_bytes());
        let error = rig.inspect_local(&candidate).unwrap_err();

        assert_eq!(
            error,
            rejected_candidate(PayloadRejection::MalformedPayload)
        );

        for text in [format!("{error}"), format!("{error:?}")] {
            assert!(!text.contains(sentinel));
            assert!(!text.contains("line"));
            assert!(!text.contains("column"));
            assert!(!text.contains("EOF"));
        }

        // A wrong-typed field name and value are not quoted either.
        let wrong_type = rig.seal_raw(format!(r#"{{"schema_version":"{sentinel}"}}"#).as_bytes());
        let error = rig.inspect_local(&wrong_type).unwrap_err();

        for text in [format!("{error}"), format!("{error:?}")] {
            assert!(!text.contains(sentinel));
            assert!(!text.contains("schema_version"));
        }
    }

    // ---- 7./8./9. schema handling ------------------------------------------

    #[test]
    fn legacy_candidates_are_unversioned_never_counter_zero_and_never_migrated() {
        let rig = Rig::new();

        for schema in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let legacy_plaintext = bytes_of(&rig.legacy(schema));
            let candidate = rig.seal_raw(&legacy_plaintext);
            let before = candidate.clone();

            let inspection = rig.inspect(&rig.local, &candidate, high_water(0)).unwrap();

            assert_eq!(
                inspection.candidate_revision(),
                AuthenticatedRevision::Unversioned {
                    schema_version: schema
                }
            );
            assert_ne!(
                inspection.candidate_revision(),
                AuthenticatedRevision::Counter(0)
            );
            assert_ne!(
                inspection.candidate_revision(),
                AuthenticatedRevision::Counter(1)
            );

            // No ordering is claimed against a counter, and a legacy candidate
            // is never treated as satisfying a checkpoint (not even 0).
            assert_eq!(inspection.payload(), PayloadRelation::Unordered);
            assert_eq!(
                inspection.checkpoint(),
                CheckpointComparison::UnversionedCandidate
            );

            // The candidate is untouched: still the same legacy plaintext, with
            // no schema upgrade and no revision field written.
            assert_eq!(candidate, before);
            let reread = open_payload_with_key(&candidate, &rig.key).unwrap();
            assert_eq!(reread.as_slice(), legacy_plaintext.as_slice());
            assert!(
                serde_json::from_slice::<serde_json::Value>(reread.as_slice())
                    .unwrap()
                    .get("revision")
                    .is_none()
            );
        }
    }

    #[test]
    fn schema_three_candidate_reports_its_authenticated_counter() {
        let rig = Rig::new();

        for revision in [0u64, 1, 3, u64::MAX] {
            let inspection = rig.inspect_local(&rig.at(revision)).unwrap();

            assert_eq!(
                inspection.candidate_revision(),
                AuthenticatedRevision::Counter(revision)
            );
        }
    }

    #[test]
    fn legacy_against_legacy_distinguishes_equivalent_from_unordered() {
        let rig = Rig::new();

        let local = rig.seal(&rig.legacy(2));

        // Same content, re-sealed: equivalence is established.
        let same_content = rig.seal(&rig.legacy(2));
        assert_ne!(local.payload, same_content.payload);
        assert_eq!(
            rig.inspect(&local, &same_content, None).unwrap().payload(),
            PayloadRelation::EquivalentContentDifferentCiphertext
        );

        // Different content with no counter on either side: no ordering, and
        // never reported as a same-revision fork or a newer/older state.
        let mut changed = rig.legacy(2);
        changed.entries[0].password = "changed".to_owned();
        assert_eq!(
            rig.inspect(&local, &rig.seal(&changed), None)
                .unwrap()
                .payload(),
            PayloadRelation::Unordered
        );
    }

    #[test]
    fn committed_fixtures_of_every_schema_are_inspected_read_only() {
        for (fixture, legacy_schema) in [
            (SCHEMA1_FIXTURE, Some(LEGACY_VAULT_DATA_SCHEMA_VERSION)),
            (
                SCHEMA2_FIXTURE,
                Some(PRE_REVISION_VAULT_DATA_SCHEMA_VERSION),
            ),
            (SCHEMA3_FIXTURE, None),
        ] {
            let candidate: VaultEnvelope = serde_json::from_slice(fixture).unwrap();
            let (key, plaintext) = open_envelope_with_key(FIXTURE_PASSWORD, &candidate).unwrap();
            let data: VaultData = serde_json::from_slice(plaintext.as_slice()).unwrap();

            // A local state of the same vault, ahead of the fixture.
            let mut ahead = data.clone();
            ahead.schema_version = VAULT_DATA_SCHEMA_VERSION;
            ahead.revision = data.revision + 5;
            let local = reseal_envelope(&candidate, &key, &bytes_of(&ahead)).unwrap();

            let before = candidate.clone();

            let inspection =
                inspect_remote_candidate(&key, data.vault_id, &local, &candidate, high_water(0))
                    .unwrap();

            assert_eq!(
                inspection.local_revision(),
                AuthenticatedRevision::Counter(data.revision + 5)
            );
            assert_eq!(inspection.wrapper(), WrapperRelation::Identical);

            match legacy_schema {
                Some(schema_version) => {
                    assert_eq!(
                        inspection.candidate_revision(),
                        AuthenticatedRevision::Unversioned { schema_version }
                    );
                    assert_eq!(inspection.payload(), PayloadRelation::Unordered);
                    assert_eq!(
                        inspection.checkpoint(),
                        CheckpointComparison::UnversionedCandidate
                    );
                }
                None => {
                    assert_eq!(
                        inspection.candidate_revision(),
                        AuthenticatedRevision::Counter(data.revision)
                    );
                    assert_eq!(
                        inspection.payload(),
                        PayloadRelation::CandidateLowerRevision
                    );
                }
            }

            // Fixture envelope and its decrypted payload are exactly as before.
            assert_eq!(candidate, before);
            let reread = open_payload_with_key(&candidate, &key).unwrap();
            assert_eq!(reread.as_slice(), plaintext.as_slice());
        }
    }

    // ---- 10./11./12. checkpoint semantics ----------------------------------

    #[test]
    fn candidate_below_the_trusted_checkpoint_is_a_known_regression() {
        let rig = Rig::new();

        // Local is at 2, the candidate at 4 is *ahead* of local, yet it is
        // below what the remote is known to have reached (6).
        let local = rig.at(2);
        let candidate = rig.at(4);

        let inspection = rig.inspect(&local, &candidate, high_water(6)).unwrap();

        assert_eq!(
            inspection.checkpoint(),
            CheckpointComparison::BelowCheckpoint
        );
        assert_eq!(
            inspection.payload(),
            PayloadRelation::CandidateHigherRevision
        );
    }

    #[test]
    fn candidate_lower_than_local_is_not_a_rollback_without_a_checkpoint() {
        let rig = Rig::new();

        // Local has unpublished changes (9); the remote simply sits at 4.
        let local = rig.at(9);
        let candidate = rig.at(4);

        let without = rig.inspect(&local, &candidate, None).unwrap();
        assert_eq!(without.payload(), PayloadRelation::CandidateLowerRevision);
        assert_eq!(without.checkpoint(), CheckpointComparison::NoCheckpoint);

        // The remote is exactly where it was last known to be: behind local,
        // but not regressed.
        let at = rig.inspect(&local, &candidate, high_water(4)).unwrap();
        assert_eq!(at.payload(), PayloadRelation::CandidateLowerRevision);
        assert_eq!(at.checkpoint(), CheckpointComparison::AtCheckpoint);

        // Only a checkpoint above the candidate makes it a regression.
        let regressed = rig.inspect(&local, &candidate, high_water(5)).unwrap();
        assert_eq!(
            regressed.checkpoint(),
            CheckpointComparison::BelowCheckpoint
        );
    }

    #[test]
    fn candidate_newer_than_the_checkpoint_is_above_it() {
        let rig = Rig::new();

        let candidate = rig.at(7);

        for (checkpoint, expected) in [
            (6, CheckpointComparison::AboveCheckpoint),
            (7, CheckpointComparison::AtCheckpoint),
            (8, CheckpointComparison::BelowCheckpoint),
            (0, CheckpointComparison::AboveCheckpoint),
        ] {
            assert_eq!(
                rig.inspect(&rig.local, &candidate, high_water(checkpoint))
                    .unwrap()
                    .checkpoint(),
                expected,
                "checkpoint {checkpoint}"
            );
        }

        let at_max = rig.at(u64::MAX);
        assert_eq!(
            rig.inspect(&rig.local, &at_max, high_water(u64::MAX))
                .unwrap()
                .checkpoint(),
            CheckpointComparison::AtCheckpoint
        );
    }

    #[test]
    fn checkpoint_comparison_does_not_depend_on_the_local_revision() {
        let rig = Rig::new();
        let candidate = rig.at(5);

        let results: Vec<_> = [0u64, 5, 99]
            .into_iter()
            .map(|local_revision| {
                rig.inspect(&rig.at(local_revision), &candidate, high_water(5))
                    .unwrap()
                    .checkpoint()
            })
            .collect();

        assert!(results
            .iter()
            .all(|result| *result == CheckpointComparison::AtCheckpoint));
    }

    // ---- 13.-16. same-revision / different-bytes ---------------------------

    #[test]
    fn same_payload_and_same_wrapper_is_identical() {
        let rig = Rig::new();

        let reparsed: VaultEnvelope =
            serde_json::from_slice(&serde_json::to_vec(&rig.local).unwrap()).unwrap();

        for candidate in [rig.local.clone(), reparsed] {
            let inspection = rig.inspect_local(&candidate).unwrap();

            assert_eq!(inspection.payload(), PayloadRelation::IdenticalCiphertext);
            assert_eq!(inspection.wrapper(), WrapperRelation::Identical);
            assert_eq!(inspection.candidate_revision(), inspection.local_revision());
        }
    }

    #[test]
    fn master_password_rewrap_is_a_wrapper_only_difference() {
        let rig = Rig::new();

        let rewrapped = rewrap_envelope_master_password(&rig.local, &rig.key, NEW_MASTER).unwrap();

        // The fingerprints differ, but the payload (and revision) do not.
        assert_ne!(
            EnvelopeFingerprint::of_bytes(&serde_json::to_vec(&rewrapped).unwrap()),
            EnvelopeFingerprint::of_bytes(&serde_json::to_vec(&rig.local).unwrap())
        );
        assert_eq!(rewrapped.payload, rig.local.payload);

        let inspection = rig.inspect_local(&rewrapped).unwrap();

        assert_eq!(inspection.payload(), PayloadRelation::IdenticalCiphertext);
        assert_eq!(inspection.wrapper(), WrapperRelation::Different);
        assert_eq!(
            inspection.candidate_revision(),
            AuthenticatedRevision::Counter(3)
        );
        assert_eq!(inspection.candidate_revision(), inspection.local_revision());
    }

    #[test]
    fn each_wrapper_field_difference_is_observed() {
        let rig = Rig::new();

        let mut salt = rig.local.clone();
        salt.kdf_salt[0] ^= 0x01;

        let mut wrapped = rig.local.clone();
        wrapped.wrapped_vault_key.nonce[0] ^= 0x01;

        let mut kdf = rig.local.clone();
        kdf.kdf.iterations += 1;

        for candidate in [salt, wrapped, kdf] {
            let inspection = rig.inspect_local(&candidate).unwrap();

            assert_eq!(inspection.wrapper(), WrapperRelation::Different);
            assert_eq!(inspection.payload(), PayloadRelation::IdenticalCiphertext);
        }
    }

    #[test]
    fn same_revision_with_different_authenticated_content_is_a_conflict() {
        let rig = Rig::new();

        let mut diverged = rig.data(3);
        diverged.entries[0].password = "a-different-password".to_owned();

        let inspection = rig.inspect_local(&rig.seal(&diverged)).unwrap();

        assert_eq!(
            inspection.payload(),
            PayloadRelation::SameRevisionDifferentContent
        );
        assert_eq!(inspection.candidate_revision(), inspection.local_revision());
    }

    #[test]
    fn randomized_ciphertext_alone_is_neither_identical_nor_a_conflict() {
        let rig = Rig::new();

        // Same logical state sealed again: a fresh nonce changes every byte of
        // the payload blob.
        let resealed = rig.at(3);

        assert_ne!(resealed.payload, rig.local.payload);
        assert_ne!(resealed.payload.nonce, rig.local.payload.nonce);
        assert_ne!(resealed.payload.ciphertext, rig.local.payload.ciphertext);

        let inspection = rig.inspect_local(&resealed).unwrap();

        assert_eq!(
            inspection.payload(),
            PayloadRelation::EquivalentContentDifferentCiphertext
        );
        assert_eq!(inspection.wrapper(), WrapperRelation::Identical);

        // And two seals of the same state never look identical to each other.
        let first = rig.at(5);
        let second = rig.at(5);
        assert_ne!(first.payload, second.payload);
        assert_eq!(
            rig.inspect(&first, &second, None).unwrap().payload(),
            PayloadRelation::EquivalentContentDifferentCiphertext
        );
    }

    #[test]
    fn a_legacy_side_blocks_any_ordering_claim_against_a_counter() {
        let rig = Rig::new();

        let legacy_local = rig.seal(&rig.legacy(2));

        assert_eq!(
            rig.inspect(&legacy_local, &rig.at(1), None)
                .unwrap()
                .payload(),
            PayloadRelation::Unordered
        );
        assert_eq!(
            rig.inspect(&rig.local, &rig.seal(&rig.legacy(2)), None)
                .unwrap()
                .payload(),
            PayloadRelation::Unordered
        );
    }

    // ---- 17. wrapper is not trusted ----------------------------------------

    #[test]
    fn a_changed_wrapper_is_not_evidence_of_a_valid_master_password_change() {
        let rig = Rig::new();

        // A wrapper that cannot unwrap anything: the payload still
        // authenticates under the known Vault Key, so inspection succeeds and
        // can only report that the wrapper differs.
        let mut broken = rig.local.clone();
        broken.wrapped_vault_key.ciphertext[0] ^= 0x01;

        let inspection = rig.inspect_local(&broken).unwrap();

        assert_eq!(inspection.wrapper(), WrapperRelation::Different);
        assert_eq!(inspection.payload(), PayloadRelation::IdenticalCiphertext);

        // ... while the very same candidate cannot be opened by any password.
        assert!(open_envelope_with_key(MASTER, &broken).is_err());
        assert!(open_envelope_with_key(NEW_MASTER, &broken).is_err());

        // A genuine rewrap yields the identical observation, so the result
        // alone cannot tell a legitimate change from a malformed wrapper.
        let genuine = rewrap_envelope_master_password(&rig.local, &rig.key, NEW_MASTER).unwrap();
        let genuine_inspection = rig.inspect_local(&genuine).unwrap();

        assert_eq!(inspection, genuine_inspection);
        assert!(open_envelope_with_key(NEW_MASTER, &genuine).is_ok());
    }

    // ---- 18. no side effects -----------------------------------------------

    #[test]
    fn repeated_inspection_has_no_side_effects() {
        let rig = Rig::new();

        let local = rig.local.clone();
        let candidate = rig.at(5);

        let local_before = local.clone();
        let candidate_before = candidate.clone();
        let candidate_fingerprint =
            EnvelopeFingerprint::of_bytes(&serde_json::to_vec(&candidate).unwrap());

        let first = rig.inspect(&local, &candidate, high_water(4)).unwrap();

        for _ in 0..3 {
            assert_eq!(
                rig.inspect(&local, &candidate, high_water(4)).unwrap(),
                first
            );
        }

        assert_eq!(local, local_before);
        assert_eq!(candidate, candidate_before);
        assert_eq!(
            EnvelopeFingerprint::of_bytes(&serde_json::to_vec(&candidate).unwrap()),
            candidate_fingerprint
        );

        // A rejected inspection leaves no state behind either.
        let mut corrupt = candidate.clone();
        corrupt.payload.ciphertext[0] ^= 0x01;

        for _ in 0..2 {
            assert_eq!(
                rig.inspect(&local, &corrupt, None),
                Err(rejected_candidate(PayloadRejection::AuthenticationFailed))
            );
        }

        assert_eq!(
            rig.inspect(&local, &candidate, high_water(4)).unwrap(),
            first
        );
    }

    // ---- 19. malformed / untrusted input fails closed ----------------------

    #[test]
    fn malformed_candidate_envelopes_fail_closed() {
        let rig = Rig::new();

        let mut wrong_magic = rig.at(5);
        wrong_magic.magic = "NOTVAULT".to_owned();

        let mut wrong_version = rig.at(5);
        wrong_version.version += 1;

        let mut kdf_too_large = rig.at(5);
        kdf_too_large.kdf.memory_kib = u32::MAX;

        let mut kdf_zero = rig.at(5);
        kdf_zero.kdf.iterations = 0;

        for candidate in [wrong_magic, wrong_version, kdf_too_large, kdf_zero] {
            assert_eq!(
                rig.inspect_local(&candidate),
                Err(rejected_candidate(PayloadRejection::UnsupportedFormat))
            );
        }

        let mut zero_nonce = rig.at(5);
        zero_nonce.payload.nonce = [0u8; 24];

        let mut swapped_blobs = rig.at(5);
        swapped_blobs.payload = swapped_blobs.wrapped_vault_key.clone();

        for candidate in [zero_nonce, swapped_blobs] {
            assert_eq!(
                rig.inspect_local(&candidate),
                Err(rejected_candidate(PayloadRejection::AuthenticationFailed))
            );
        }
    }

    #[test]
    fn an_invalid_local_reference_is_never_reported_as_a_remote_fault() {
        let rig = Rig::new();

        let mut corrupt_local = rig.local.clone();
        corrupt_local.payload.ciphertext[0] ^= 0x01;

        assert_eq!(
            rig.inspect(&corrupt_local, &rig.at(5), None),
            Err(InspectionError::LocalReference(
                PayloadRejection::AuthenticationFailed
            ))
        );
    }

    #[test]
    fn rejections_do_not_echo_payload_content() {
        let rig = Rig::new();

        let mut invalid = rig.data(5);
        invalid.entries[0].title = String::new();

        let error = rig.inspect_local(&rig.seal(&invalid)).unwrap_err();

        for text in [format!("{error}"), format!("{error:?}")] {
            assert!(!text.contains(SECRET));
            assert!(!text.contains(&rig.id().to_string()));
        }
    }
}

/// Stage 1U-4 A2a tests. Kept apart from the accepted 1U-1 and 1U-3 modules,
/// which are unchanged. Synthetic data only; the committed fixtures are
/// read-only.
#[cfg(test)]
mod bound_inspection_tests {
    use super::*;
    use crate::vault::{
        data::{
            VaultEntry, LEGACY_VAULT_DATA_SCHEMA_VERSION, PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        },
        format::{
            create_envelope_with_key, open_envelope_with_key, reseal_envelope,
            rewrap_envelope_master_password,
        },
    };

    const SCHEMA1_FIXTURE: &[u8] =
        include_bytes!("../../../src-tauri/tests/fixtures/compat/schema1_baseline.envelope.json");
    const SCHEMA2_FIXTURE: &[u8] =
        include_bytes!("../../../src-tauri/tests/fixtures/compat/schema2_baseline.envelope.json");
    const SCHEMA3_FIXTURE: &[u8] =
        include_bytes!("../../../src-tauri/tests/fixtures/compat/schema3_baseline.envelope.json");

    // Computed outside this module with `Get-FileHash` on the committed files.
    const SCHEMA1_SHA256: &str = "17edf060385cca1a778b2236842ecfa44d21aa174d9b70092c1d9cbdd0fcb9a8";
    const SCHEMA2_SHA256: &str = "f5bf1fcdb11115f0fa39598389a7a8ce3b9c44b78ddfd5295b57845b52155f55";
    const SCHEMA3_SHA256: &str = "71d2efb0150e7f818cf1acf61ce25f6e1dda06370f8df85056dc671fdc3e81c8";

    const FIXTURE_PASSWORD: &str = "compat-baseline-master-password-test-only";
    const MASTER: &str = "bound-inspection-test-only-master-password";
    const NEW_MASTER: &str = "bound-inspection-test-only-new-master-password";
    const SECRET: &str = "BOUND_INSPECTION_TEST_ONLY_SECRET";
    const TITLE: &str = "Bound Inspection Entry";
    const SENTINEL: &str = "RAW_INPUT_SENTINEL_SECRET";
    const NOW_MS: i64 = 1_700_000_000_000;

    fn bytes_of(data: &VaultData) -> Vec<u8> {
        serde_json::to_vec(data).unwrap()
    }

    fn raw(envelope: &VaultEnvelope) -> Vec<u8> {
        serde_json::to_vec(envelope).unwrap()
    }

    /// SHA-256 computed directly with the `sha2` crate, independent of
    /// `EnvelopeFingerprint`.
    fn independent_sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn high_water(revision: u64) -> Option<RemoteHighWater> {
        Some(RemoteHighWater::new(revision))
    }

    fn candidate_error(reason: PayloadRejection) -> BoundInspectionError {
        BoundInspectionError::Inspection(InspectionError::Candidate(reason))
    }

    fn local_error(reason: PayloadRejection) -> BoundInspectionError {
        BoundInspectionError::Inspection(InspectionError::LocalReference(reason))
    }

    fn malformed(input: EnvelopeInput) -> BoundInspectionError {
        BoundInspectionError::MalformedEnvelope { input }
    }

    /// One vault: its Vault Key, id and a local envelope at revision 3.
    struct Rig {
        local: VaultEnvelope,
        key: SecretKey,
        base: VaultData,
    }

    impl Rig {
        fn new() -> Self {
            let mut base = VaultData::new(NOW_MS).unwrap();

            let mut entry = VaultEntry::new(TITLE, NOW_MS).unwrap();
            entry.password = SECRET.to_owned();
            base.entries.push(entry);

            base.revision = 3;
            base.validate().unwrap();

            let (local, key) = create_envelope_with_key(MASTER, &bytes_of(&base)).unwrap();

            Self { local, key, base }
        }

        fn id(&self) -> Uuid {
            self.base.vault_id
        }

        fn data(&self, revision: u64) -> VaultData {
            let mut data = self.base.clone();
            data.revision = revision;
            data
        }

        fn legacy(&self, schema_version: u16) -> VaultData {
            let mut data = self.base.clone();
            data.schema_version = schema_version;
            data.revision = 0;
            data
        }

        fn seal(&self, data: &VaultData) -> VaultEnvelope {
            self.seal_plaintext(&bytes_of(data))
        }

        fn seal_plaintext(&self, plaintext: &[u8]) -> VaultEnvelope {
            reseal_envelope(&self.local, &self.key, plaintext).unwrap()
        }

        fn at(&self, revision: u64) -> VaultEnvelope {
            self.seal(&self.data(revision))
        }

        fn inspect(
            &self,
            local_raw: &[u8],
            candidate_raw: &[u8],
            high_water: Option<RemoteHighWater>,
        ) -> Result<BoundInspection, BoundInspectionError> {
            inspect_remote_bytes(&self.key, self.id(), local_raw, candidate_raw, high_water)
        }

        /// The unchanged 1U-3 result for the same two envelopes.
        fn reference(
            &self,
            local: &VaultEnvelope,
            candidate: &VaultEnvelope,
            high_water: Option<RemoteHighWater>,
        ) -> Result<RemoteInspection, InspectionError> {
            inspect_remote_candidate(&self.key, self.id(), local, candidate, high_water)
        }
    }

    // ---- 1./2. valid input, exact-byte fingerprints ------------------------

    #[test]
    fn valid_raw_envelopes_are_inspected_and_bound_to_their_exact_bytes() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);
        let candidate_envelope = rig.at(5);
        let candidate_raw = raw(&candidate_envelope);

        let bound = rig.inspect(&local_raw, &candidate_raw, None).unwrap();

        assert_eq!(
            bound.inspection().candidate_revision(),
            AuthenticatedRevision::Counter(5)
        );
        assert_eq!(
            bound.inspection().local_revision(),
            AuthenticatedRevision::Counter(3)
        );
        assert_eq!(
            bound.inspection().payload(),
            PayloadRelation::CandidateHigherRevision
        );
        assert_eq!(bound.inspection().wrapper(), WrapperRelation::Identical);
        assert_eq!(
            bound.inspection().checkpoint(),
            CheckpointComparison::NoCheckpoint
        );

        // Independently computed SHA-256 of exactly the supplied slices.
        assert_eq!(
            bound.local_fingerprint().as_bytes(),
            &independent_sha256(&local_raw)
        );
        assert_eq!(
            bound.candidate_fingerprint().as_bytes(),
            &independent_sha256(&candidate_raw)
        );
        assert_ne!(bound.local_fingerprint(), bound.candidate_fingerprint());

        // The inspection is exactly the unchanged 1U-3 result.
        assert_eq!(
            Ok(*bound.inspection()),
            rig.reference(&rig.local, &candidate_envelope, None)
        );
    }

    #[test]
    fn local_and_candidate_fingerprints_are_not_interchangeable() {
        let rig = Rig::new();
        let a = raw(&rig.at(4));
        let b = raw(&rig.at(6));

        let forward = rig.inspect(&a, &b, None).unwrap();
        let backward = rig.inspect(&b, &a, None).unwrap();

        assert_eq!(
            forward.local_fingerprint(),
            backward.candidate_fingerprint()
        );
        assert_eq!(
            forward.candidate_fingerprint(),
            backward.local_fingerprint()
        );
        assert_ne!(forward.local_fingerprint(), forward.candidate_fingerprint());
        assert_eq!(
            forward.inspection().payload(),
            PayloadRelation::CandidateHigherRevision
        );
        assert_eq!(
            backward.inspection().payload(),
            PayloadRelation::CandidateLowerRevision
        );
    }

    // ---- 3. raw representation vs authenticated identity -------------------

    #[test]
    fn whitespace_changes_the_fingerprint_but_not_the_inspection() {
        let rig = Rig::new();
        let compact = raw(&rig.local);

        let pretty = serde_json::to_vec_pretty(&rig.local).unwrap();
        let mut trailing_newline = compact.clone();
        trailing_newline.push(b'\n');
        let mut trailing_crlf = compact.clone();
        trailing_crlf.extend_from_slice(b"\r\n");
        let mut leading_space = vec![b' '];
        leading_space.extend_from_slice(&compact);

        let representations = [
            compact.clone(),
            pretty,
            trailing_newline,
            trailing_crlf,
            leading_space,
        ];

        // Every representation parses to the very same envelope ...
        for representation in &representations {
            assert_eq!(
                serde_json::from_slice::<VaultEnvelope>(representation).unwrap(),
                rig.local
            );
        }

        let baseline = rig.inspect(&compact, &compact, None).unwrap();
        assert_eq!(
            baseline.inspection().payload(),
            PayloadRelation::IdenticalCiphertext
        );
        assert_eq!(
            baseline.local_fingerprint(),
            baseline.candidate_fingerprint()
        );

        for (index, representation) in representations.iter().enumerate() {
            let bound = rig.inspect(&compact, representation, None).unwrap();

            // ... so the authenticated facts never change ...
            assert_eq!(bound.inspection(), baseline.inspection(), "form {index}");

            // ... while the candidate fingerprint follows the exact bytes.
            assert_eq!(
                bound.candidate_fingerprint().as_bytes(),
                &independent_sha256(representation),
                "form {index}"
            );
            assert_eq!(bound.local_fingerprint(), baseline.local_fingerprint());

            for (other_index, other) in representations.iter().enumerate() {
                assert_eq!(
                    bound.candidate_fingerprint() == &EnvelopeFingerprint::of_bytes(other),
                    representation == other,
                    "forms {index} and {other_index}"
                );
            }
        }
    }

    // ---- 4./5. malformed envelopes -----------------------------------------

    fn malformed_samples(valid: &[u8]) -> Vec<Vec<u8>> {
        let mut trailing_data = valid.to_vec();
        trailing_data.extend_from_slice(b" trailing");

        vec![
            Vec::new(),
            b"not json".to_vec(),
            b"{}".to_vec(),
            b"[]".to_vec(),
            b"null".to_vec(),
            vec![0xff, 0xfe, 0x00, 0x01],
            format!(r#"{{"magic":"{SENTINEL}","version":"{SENTINEL}"}}"#).into_bytes(),
            format!(r#"{{"magic":"LOCALVAULT","version":1,"kdf":"{SENTINEL}"}}"#).into_bytes(),
            trailing_data,
        ]
    }

    #[test]
    fn malformed_candidate_bytes_are_rejected_as_the_candidate() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);

        for sample in malformed_samples(&raw(&rig.at(5))) {
            let error = rig.inspect(&local_raw, &sample, None).unwrap_err();

            assert_eq!(error, malformed(EnvelopeInput::Candidate));

            for text in [format!("{error}"), format!("{error:?}")] {
                assert!(!text.contains(SENTINEL));
                assert!(!text.contains("line"));
                assert!(!text.contains("column"));
                assert!(!text.contains("EOF"));
            }
        }
    }

    #[test]
    fn malformed_local_bytes_are_rejected_as_the_local_reference() {
        let rig = Rig::new();
        let candidate_raw = raw(&rig.at(5));

        for sample in malformed_samples(&raw(&rig.local)) {
            let error = rig.inspect(&sample, &candidate_raw, None).unwrap_err();

            assert_eq!(error, malformed(EnvelopeInput::LocalReference));

            for text in [format!("{error}"), format!("{error:?}")] {
                assert!(!text.contains(SENTINEL));
            }
        }
    }

    #[test]
    fn the_local_reference_is_blamed_first_when_both_inputs_are_malformed() {
        let rig = Rig::new();

        assert_eq!(
            rig.inspect(b"{", b"[", None),
            Err(malformed(EnvelopeInput::LocalReference))
        );
    }

    #[test]
    fn a_parseable_envelope_with_a_bad_header_keeps_its_1u3_classification() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);

        let mut wrong_magic = rig.at(5);
        wrong_magic.magic = "NOTVAULT".to_owned();

        let mut wrong_version = rig.at(5);
        wrong_version.version += 1;

        let mut kdf_too_large = rig.at(5);
        kdf_too_large.kdf.memory_kib = u32::MAX;

        for candidate in [wrong_magic, wrong_version, kdf_too_large] {
            assert_eq!(
                rig.inspect(&local_raw, &raw(&candidate), None),
                Err(candidate_error(PayloadRejection::UnsupportedFormat))
            );
        }

        let mut wrong_magic_local = rig.local.clone();
        wrong_magic_local.magic = "NOTVAULT".to_owned();

        assert_eq!(
            rig.inspect(&raw(&wrong_magic_local), &raw(&rig.at(5)), None),
            Err(local_error(PayloadRejection::UnsupportedFormat))
        );
    }

    // ---- 6./7. size limits --------------------------------------------------

    #[test]
    fn the_limit_is_the_32_mib_desktop_vault_file_limit() {
        assert_eq!(MAX_ENVELOPE_BYTES, 33_554_432);
    }

    #[test]
    fn oversized_local_input_is_rejected_with_its_length() {
        let rig = Rig::new();
        let candidate_raw = raw(&rig.at(5));

        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        let error = rig.inspect(&oversized, &candidate_raw, None).unwrap_err();

        assert_eq!(
            error,
            BoundInspectionError::InputTooLarge {
                input: EnvelopeInput::LocalReference,
                actual: MAX_ENVELOPE_BYTES + 1,
                limit: MAX_ENVELOPE_BYTES,
            }
        );
        assert!(format!("{error}").contains("local reference"));
        assert!(format!("{error}").contains("33554433"));
    }

    #[test]
    fn oversized_candidate_input_is_rejected_with_its_length() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);

        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        let error = rig.inspect(&local_raw, &oversized, None).unwrap_err();

        assert_eq!(
            error,
            BoundInspectionError::InputTooLarge {
                input: EnvelopeInput::Candidate,
                actual: MAX_ENVELOPE_BYTES + 1,
                limit: MAX_ENVELOPE_BYTES,
            }
        );
        assert!(format!("{error}").contains("remote candidate"));
    }

    #[test]
    fn both_lengths_are_checked_before_either_input_is_parsed() {
        let rig = Rig::new();
        let oversized = vec![b'x'; MAX_ENVELOPE_BYTES + 1];

        // A malformed (tiny) local reference does not hide an oversized
        // candidate: the size verdict comes first, and it is the candidate's.
        assert_eq!(
            rig.inspect(b"not json", &oversized, None),
            Err(BoundInspectionError::InputTooLarge {
                input: EnvelopeInput::Candidate,
                actual: MAX_ENVELOPE_BYTES + 1,
                limit: MAX_ENVELOPE_BYTES,
            })
        );

        // An oversized input is a size error even though it is also not JSON.
        assert!(matches!(
            rig.inspect(&oversized, &raw(&rig.local), None),
            Err(BoundInspectionError::InputTooLarge {
                input: EnvelopeInput::LocalReference,
                ..
            })
        ));

        // With both over the limit the local reference is reported first.
        assert!(matches!(
            rig.inspect(&oversized, &oversized, None),
            Err(BoundInspectionError::InputTooLarge {
                input: EnvelopeInput::LocalReference,
                ..
            })
        ));
    }

    #[test]
    fn input_of_exactly_the_limit_is_accepted_and_hashed_in_full() {
        let rig = Rig::new();

        let pad_to_limit = |envelope: &VaultEnvelope| {
            let mut bytes = raw(envelope);
            bytes.resize(MAX_ENVELOPE_BYTES, b' ');
            bytes
        };

        let local_raw = pad_to_limit(&rig.local);
        let candidate_raw = pad_to_limit(&rig.at(5));
        assert_eq!(local_raw.len(), MAX_ENVELOPE_BYTES);
        assert_eq!(candidate_raw.len(), MAX_ENVELOPE_BYTES);

        let bound = rig.inspect(&local_raw, &candidate_raw, None).unwrap();

        // Nothing was truncated: the digest covers every padding byte.
        assert_eq!(
            bound.local_fingerprint().as_bytes(),
            &independent_sha256(&local_raw)
        );
        assert_eq!(
            bound.candidate_fingerprint().as_bytes(),
            &independent_sha256(&candidate_raw)
        );
        assert_eq!(
            bound.inspection().payload(),
            PayloadRelation::CandidateHigherRevision
        );
    }

    // ---- 8. truncation ------------------------------------------------------

    #[test]
    fn every_truncation_of_a_valid_envelope_is_malformed() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);
        let candidate_raw = raw(&rig.at(5));

        assert!(rig.inspect(&local_raw, &candidate_raw, None).is_ok());

        for length in 0..candidate_raw.len() {
            assert_eq!(
                rig.inspect(&local_raw, &candidate_raw[..length], None),
                Err(malformed(EnvelopeInput::Candidate)),
                "candidate truncated to {length} bytes"
            );
        }

        for length in 0..local_raw.len() {
            assert_eq!(
                rig.inspect(&local_raw[..length], &candidate_raw, None),
                Err(malformed(EnvelopeInput::LocalReference)),
                "local truncated to {length} bytes"
            );
        }
    }

    // ---- 9. wrong key -------------------------------------------------------

    #[test]
    fn wrong_vault_key_is_an_authentication_failure_of_the_local_reference() {
        let rig = Rig::new();
        let other = Rig::new();

        // The local reference is read first, so it is the first to fail to
        // authenticate under the wrong key.
        assert_eq!(
            inspect_remote_bytes(
                &other.key,
                rig.id(),
                &raw(&rig.local),
                &raw(&rig.at(5)),
                None
            ),
            Err(local_error(PayloadRejection::AuthenticationFailed))
        );
    }

    #[test]
    fn candidate_sealed_under_another_key_is_an_authentication_failure() {
        let rig = Rig::new();
        let other = Rig::new();

        assert_eq!(
            rig.inspect(&raw(&rig.local), &raw(&other.at(5)), None),
            Err(candidate_error(PayloadRejection::AuthenticationFailed))
        );
    }

    #[test]
    fn tampered_candidate_bytes_fail_authentication_not_parsing() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);

        let mut flipped_ciphertext = rig.at(5);
        flipped_ciphertext.payload.ciphertext[0] ^= 0x01;

        let mut flipped_nonce = rig.at(5);
        flipped_nonce.payload.nonce[0] ^= 0x01;

        for candidate in [flipped_ciphertext, flipped_nonce] {
            assert_eq!(
                rig.inspect(&local_raw, &raw(&candidate), None),
                Err(candidate_error(PayloadRejection::AuthenticationFailed))
            );
        }
    }

    // ---- 10. invalid authenticated payloads ---------------------------------

    #[test]
    fn authenticated_but_invalid_payloads_stay_distinct_from_authentication_failure() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);

        // Authentic bytes that are not a vault payload.
        assert_eq!(
            rig.inspect(&local_raw, &raw(&rig.seal_plaintext(b"{ not json")), None),
            Err(candidate_error(PayloadRejection::MalformedPayload))
        );

        // Authentic, parseable, but fails vault-data validation.
        let mut empty_title = rig.data(5);
        empty_title.entries[0].title = String::new();

        assert_eq!(
            rig.inspect(&local_raw, &raw(&rig.seal(&empty_title)), None),
            Err(candidate_error(PayloadRejection::InvalidData))
        );

        // Authentic, parseable, from a schema this build does not know.
        let mut future_schema = serde_json::to_value(rig.data(5)).unwrap();
        future_schema["schema_version"] = serde_json::json!(4);

        assert_eq!(
            rig.inspect(
                &local_raw,
                &raw(&rig.seal_plaintext(&serde_json::to_vec(&future_schema).unwrap())),
                None
            ),
            Err(candidate_error(PayloadRejection::UnsupportedSchema))
        );

        // The same defect on the local side is blamed on the local reference.
        assert_eq!(
            rig.inspect(
                &raw(&rig.seal_plaintext(b"{ not json")),
                &raw(&rig.at(5)),
                None
            ),
            Err(local_error(PayloadRejection::MalformedPayload))
        );
    }

    // ---- 11. vault identity -------------------------------------------------

    #[test]
    fn a_different_vault_id_is_rejected_after_authentication() {
        let rig = Rig::new();

        let mut other_vault = rig.data(5);
        other_vault.vault_id = Uuid::new_v4();
        assert_ne!(other_vault.vault_id, rig.id());

        assert_eq!(
            rig.inspect(&raw(&rig.local), &raw(&rig.seal(&other_vault)), None),
            Err(candidate_error(PayloadRejection::VaultIdMismatch))
        );

        let mut other_local = rig.data(3);
        other_local.vault_id = Uuid::new_v4();

        assert_eq!(
            rig.inspect(&raw(&rig.seal(&other_local)), &raw(&rig.at(5)), None),
            Err(local_error(PayloadRejection::VaultIdMismatch))
        );

        // A nil expected id can never match a valid payload.
        assert_eq!(
            inspect_remote_bytes(
                &rig.key,
                Uuid::nil(),
                &raw(&rig.local),
                &raw(&rig.at(5)),
                None
            ),
            Err(local_error(PayloadRejection::VaultIdMismatch))
        );
    }

    // ---- 12./13. committed fixtures, byte for byte --------------------------

    #[test]
    fn committed_fixtures_are_fingerprinted_as_the_exact_file_bytes() {
        for (fixture, expected_sha256, legacy_schema) in [
            (
                SCHEMA1_FIXTURE,
                SCHEMA1_SHA256,
                Some(LEGACY_VAULT_DATA_SCHEMA_VERSION),
            ),
            (
                SCHEMA2_FIXTURE,
                SCHEMA2_SHA256,
                Some(PRE_REVISION_VAULT_DATA_SCHEMA_VERSION),
            ),
            (SCHEMA3_FIXTURE, SCHEMA3_SHA256, None),
        ] {
            let envelope: VaultEnvelope = serde_json::from_slice(fixture).unwrap();
            let (key, plaintext) = open_envelope_with_key(FIXTURE_PASSWORD, &envelope).unwrap();
            let data: VaultData = serde_json::from_slice(plaintext.as_slice()).unwrap();

            // A local state of the same vault, ahead of the fixture.
            let mut ahead = data.clone();
            ahead.schema_version = VAULT_DATA_SCHEMA_VERSION;
            ahead.revision = data.revision + 5;
            let local = reseal_envelope(&envelope, &key, &bytes_of(&ahead)).unwrap();
            let local_raw = raw(&local);

            // The fixture file bytes are passed as they are on disk.
            let bound =
                inspect_remote_bytes(&key, data.vault_id, &local_raw, fixture, high_water(0))
                    .unwrap();

            assert_eq!(
                bound.candidate_fingerprint().to_hex(),
                expected_sha256,
                "fixture fingerprint"
            );
            assert_eq!(
                bound.local_fingerprint().as_bytes(),
                &independent_sha256(&local_raw)
            );
            assert_eq!(
                bound.inspection().local_revision(),
                AuthenticatedRevision::Counter(data.revision + 5)
            );
            assert_eq!(bound.inspection().wrapper(), WrapperRelation::Identical);

            match legacy_schema {
                Some(schema_version) => {
                    assert_eq!(
                        bound.inspection().candidate_revision(),
                        AuthenticatedRevision::Unversioned { schema_version }
                    );
                    assert_eq!(bound.inspection().payload(), PayloadRelation::Unordered);
                    assert_eq!(
                        bound.inspection().checkpoint(),
                        CheckpointComparison::UnversionedCandidate
                    );
                }
                None => {
                    assert_eq!(
                        bound.inspection().candidate_revision(),
                        AuthenticatedRevision::Counter(data.revision)
                    );
                    assert_eq!(
                        bound.inspection().payload(),
                        PayloadRelation::CandidateLowerRevision
                    );
                }
            }

            // Same envelopes through the unchanged 1U-3 entry point.
            assert_eq!(
                Ok(*bound.inspection()),
                inspect_remote_candidate(&key, data.vault_id, &local, &envelope, high_water(0))
            );
        }
    }

    // ---- 14. checkpoint -----------------------------------------------------

    #[test]
    fn known_rollback_is_reported_against_the_supplied_checkpoint_only() {
        let rig = Rig::new();

        // Candidate (4) is ahead of local (2) but behind what the remote is
        // known to have reached (6).
        let regressed = rig
            .inspect(&raw(&rig.at(2)), &raw(&rig.at(4)), high_water(6))
            .unwrap();
        assert_eq!(
            regressed.inspection().checkpoint(),
            CheckpointComparison::BelowCheckpoint
        );
        assert_eq!(
            regressed.inspection().payload(),
            PayloadRelation::CandidateHigherRevision
        );

        // Behind local without a checkpoint is not a rollback.
        let behind_local = rig
            .inspect(&raw(&rig.at(9)), &raw(&rig.at(4)), None)
            .unwrap();
        assert_eq!(
            behind_local.inspection().payload(),
            PayloadRelation::CandidateLowerRevision
        );
        assert_eq!(
            behind_local.inspection().checkpoint(),
            CheckpointComparison::NoCheckpoint
        );

        // Exactly at the checkpoint: consistent, not a regression.
        let at = rig
            .inspect(&raw(&rig.at(9)), &raw(&rig.at(4)), high_water(4))
            .unwrap();
        assert_eq!(
            at.inspection().checkpoint(),
            CheckpointComparison::AtCheckpoint
        );
    }

    // ---- 15./16./17. same-revision, wrapper, randomized ciphertext ----------

    #[test]
    fn same_revision_with_different_content_is_a_conflict_indicator() {
        let rig = Rig::new();

        let mut diverged = rig.data(3);
        diverged.entries[0].password = "a-different-password".to_owned();

        let bound = rig
            .inspect(&raw(&rig.local), &raw(&rig.seal(&diverged)), None)
            .unwrap();

        assert_eq!(
            bound.inspection().payload(),
            PayloadRelation::SameRevisionDifferentContent
        );
        assert_ne!(bound.local_fingerprint(), bound.candidate_fingerprint());
    }

    #[test]
    fn wrapper_only_change_differs_in_bytes_and_wrapper_but_not_in_payload() {
        let rig = Rig::new();
        let rewrapped = rewrap_envelope_master_password(&rig.local, &rig.key, NEW_MASTER).unwrap();
        assert_eq!(rewrapped.payload, rig.local.payload);

        let local_raw = raw(&rig.local);
        let rewrapped_raw = raw(&rewrapped);

        let bound = rig.inspect(&local_raw, &rewrapped_raw, None).unwrap();

        assert_ne!(bound.local_fingerprint(), bound.candidate_fingerprint());
        assert_eq!(
            bound.candidate_fingerprint().as_bytes(),
            &independent_sha256(&rewrapped_raw)
        );
        assert_eq!(
            bound.inspection().payload(),
            PayloadRelation::IdenticalCiphertext
        );
        assert_eq!(bound.inspection().wrapper(), WrapperRelation::Different);
        assert_eq!(
            bound.inspection().candidate_revision(),
            bound.inspection().local_revision()
        );
    }

    #[test]
    fn equivalent_content_under_randomized_encryption_is_not_a_fork() {
        let rig = Rig::new();

        let resealed = rig.at(3);
        assert_ne!(resealed.payload, rig.local.payload);

        let bound = rig
            .inspect(&raw(&rig.local), &raw(&resealed), None)
            .unwrap();

        assert_ne!(bound.local_fingerprint(), bound.candidate_fingerprint());
        assert_eq!(
            bound.inspection().payload(),
            PayloadRelation::EquivalentContentDifferentCiphertext
        );
        assert_eq!(bound.inspection().wrapper(), WrapperRelation::Identical);
    }

    #[test]
    fn identical_bytes_give_identical_fingerprints_and_identical_payloads() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);

        let bound = rig.inspect(&local_raw, &local_raw, None).unwrap();

        assert_eq!(bound.local_fingerprint(), bound.candidate_fingerprint());
        assert_eq!(
            bound.inspection().payload(),
            PayloadRelation::IdenticalCiphertext
        );
    }

    // ---- 18. nothing sensitive in Debug or errors ---------------------------

    #[test]
    fn debug_and_error_output_expose_no_contents_or_secrets() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);
        let candidate_raw = raw(&rig.at(5));

        let bound = rig
            .inspect(&local_raw, &candidate_raw, high_water(4))
            .unwrap();

        let rendered = format!("{bound:?}");
        assert!(rendered.starts_with("BoundInspection"));
        assert!(rendered.contains(&bound.local_fingerprint().to_hex()));
        assert!(rendered.contains(&bound.candidate_fingerprint().to_hex()));

        let mut empty_title = rig.data(5);
        empty_title.entries[0].title = String::new();

        let errors = [
            rig.inspect(b"{", &candidate_raw, None).unwrap_err(),
            rig.inspect(&local_raw, SENTINEL.as_bytes(), None)
                .unwrap_err(),
            rig.inspect(&local_raw, &vec![b' '; MAX_ENVELOPE_BYTES + 1], None)
                .unwrap_err(),
            rig.inspect(&local_raw, &raw(&rig.seal(&empty_title)), None)
                .unwrap_err(),
            inspect_remote_bytes(&Rig::new().key, rig.id(), &local_raw, &candidate_raw, None)
                .unwrap_err(),
        ];

        let mut texts = vec![rendered];
        for error in errors {
            texts.push(format!("{error}"));
            texts.push(format!("{error:?}"));
        }

        for text in texts {
            for forbidden in [
                SECRET,
                TITLE,
                SENTINEL,
                MASTER,
                NEW_MASTER,
                FIXTURE_PASSWORD,
                "password",
            ] {
                assert!(!text.contains(forbidden), "{forbidden} leaked in {text}");
            }
            assert!(!text.contains(&rig.id().to_string()));
        }
    }

    // ---- 19. the bound type cannot be assembled by a caller -----------------

    #[test]
    fn the_only_producer_is_the_byte_taking_entry_point() {
        // Exactly this signature: raw slices in, no fingerprints and no parsed
        // envelopes accepted. (The negative construction claims -- no struct
        // literal, constructor, `From` or field mutation -- are compile_fail
        // doctests on `BoundInspection`.)
        type ExactSignature = fn(
            &SecretKey,
            Uuid,
            &[u8],
            &[u8],
            Option<RemoteHighWater>,
        ) -> Result<BoundInspection, BoundInspectionError>;

        let _signature: ExactSignature = inspect_remote_bytes;

        // A bound value is read-only: accessors hand out shared references.
        let rig = Rig::new();
        let bound = rig
            .inspect(&raw(&rig.local), &raw(&rig.at(5)), None)
            .unwrap();
        let copy = bound;

        assert_eq!(copy, bound);
        assert_eq!(copy.local_fingerprint(), bound.local_fingerprint());
        assert_eq!(copy.inspection(), bound.inspection());
    }

    // ---- no side effects ----------------------------------------------------

    #[test]
    fn repeated_inspection_is_deterministic_and_leaves_inputs_untouched() {
        let rig = Rig::new();

        let local_raw = raw(&rig.local);
        let candidate_raw = raw(&rig.at(5));
        let local_before = local_raw.clone();
        let candidate_before = candidate_raw.clone();

        let first = rig
            .inspect(&local_raw, &candidate_raw, high_water(4))
            .unwrap();

        for _ in 0..3 {
            assert_eq!(
                rig.inspect(&local_raw, &candidate_raw, high_water(4))
                    .unwrap(),
                first
            );
        }

        assert_eq!(local_raw, local_before);
        assert_eq!(candidate_raw, candidate_before);

        // A rejected call leaves nothing behind that affects the next one.
        assert!(rig.inspect(&local_raw, b"{", high_water(4)).is_err());
        assert_eq!(
            rig.inspect(&local_raw, &candidate_raw, high_water(4))
                .unwrap(),
            first
        );
    }

    #[test]
    fn legacy_candidates_are_not_migrated_by_byte_inspection() {
        let rig = Rig::new();

        for schema in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let legacy_plaintext = bytes_of(&rig.legacy(schema));
            let candidate = rig.seal_plaintext(&legacy_plaintext);
            let candidate_raw = raw(&candidate);

            let bound = rig
                .inspect(&raw(&rig.local), &candidate_raw, high_water(0))
                .unwrap();

            assert_eq!(
                bound.inspection().candidate_revision(),
                AuthenticatedRevision::Unversioned {
                    schema_version: schema
                }
            );
            assert_eq!(
                bound.inspection().checkpoint(),
                CheckpointComparison::UnversionedCandidate
            );

            // The supplied bytes (and the payload they carry) are exactly as before.
            assert_eq!(raw(&candidate), candidate_raw);
            assert_eq!(
                open_payload_with_key(&candidate, &rig.key)
                    .unwrap()
                    .as_slice(),
                legacy_plaintext.as_slice()
            );
        }
    }
}

/// Stage 1U-4 A2b tests: [`LocalSnapshot`] and the verified vault identity of
/// [`BoundInspection`]. Synthetic data only; no committed fixture is touched.
#[cfg(test)]
mod local_snapshot_tests {
    use super::*;
    use crate::vault::{
        data::{
            VaultEntry, LEGACY_VAULT_DATA_SCHEMA_VERSION, PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
            VAULT_DATA_SCHEMA_VERSION,
        },
        format::{create_envelope_with_key, reseal_envelope},
    };

    const MASTER: &str = "local-snapshot-test-only-master-password";
    const SECRET: &str = "LOCAL_SNAPSHOT_TEST_ONLY_SECRET";
    const TITLE: &str = "Local Snapshot Entry";
    const SENTINEL: &str = "LOCAL_RAW_INPUT_SENTINEL";
    const NOW_MS: i64 = 1_700_000_000_000;

    fn bytes_of(data: &VaultData) -> Vec<u8> {
        serde_json::to_vec(data).unwrap()
    }

    fn raw(envelope: &VaultEnvelope) -> Vec<u8> {
        serde_json::to_vec(envelope).unwrap()
    }

    fn local_error(reason: PayloadRejection) -> BoundInspectionError {
        BoundInspectionError::Inspection(InspectionError::LocalReference(reason))
    }

    fn candidate_error(reason: PayloadRejection) -> BoundInspectionError {
        BoundInspectionError::Inspection(InspectionError::Candidate(reason))
    }

    /// One vault: its Vault Key, id and a local envelope at revision 3.
    struct Rig {
        local: VaultEnvelope,
        key: SecretKey,
        base: VaultData,
    }

    impl Rig {
        fn new() -> Self {
            let mut base = VaultData::new(NOW_MS).unwrap();

            let mut entry = VaultEntry::new(TITLE, NOW_MS).unwrap();
            entry.password = SECRET.to_owned();
            base.entries.push(entry);

            base.revision = 3;
            base.validate().unwrap();

            let (local, key) = create_envelope_with_key(MASTER, &bytes_of(&base)).unwrap();

            Self { local, key, base }
        }

        fn id(&self) -> Uuid {
            self.base.vault_id
        }

        fn data(&self, revision: u64) -> VaultData {
            let mut data = self.base.clone();
            data.revision = revision;
            data
        }

        fn seal_plaintext(&self, plaintext: &[u8]) -> VaultEnvelope {
            reseal_envelope(&self.local, &self.key, plaintext).unwrap()
        }

        fn raw_at(&self, revision: u64) -> Vec<u8> {
            raw(&self.seal_plaintext(&bytes_of(&self.data(revision))))
        }

        fn raw_of(&self, data: &VaultData) -> Vec<u8> {
            raw(&self.seal_plaintext(&bytes_of(data)))
        }

        fn snapshot(&self, local_raw: &[u8]) -> Result<LocalSnapshot, BoundInspectionError> {
            inspect_local_bytes(&self.key, self.id(), local_raw)
        }
    }

    #[test]
    fn a_valid_schema_three_envelope_yields_a_bound_snapshot_without_any_remote() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);

        let snapshot = rig.snapshot(&local_raw).unwrap();

        assert_eq!(snapshot.revision(), AuthenticatedRevision::Counter(3));
        assert_eq!(snapshot.authenticated_vault_id(), rig.id());

        // Independently computed SHA-256 of exactly the supplied slice.
        let independent: [u8; 32] = Sha256::digest(&local_raw).into();
        assert_eq!(snapshot.fingerprint().as_bytes(), &independent);

        // It is the very same authenticated evidence a two-sided inspection
        // reports for its local side.
        let candidate_raw = rig.raw_at(5);
        let bound =
            inspect_remote_bytes(&rig.key, rig.id(), &local_raw, &candidate_raw, None).unwrap();

        assert_eq!(snapshot.fingerprint(), bound.local_fingerprint());
        assert_eq!(snapshot.revision(), bound.inspection().local_revision());
        assert_eq!(
            snapshot.authenticated_vault_id(),
            bound.authenticated_vault_id()
        );
    }

    #[test]
    fn the_fingerprint_follows_the_exact_raw_bytes_not_the_parsed_envelope() {
        let rig = Rig::new();
        let compact = raw(&rig.local);
        let pretty = serde_json::to_vec_pretty(&rig.local).unwrap();

        let from_compact = rig.snapshot(&compact).unwrap();
        let from_pretty = rig.snapshot(&pretty).unwrap();

        assert_ne!(from_compact.fingerprint(), from_pretty.fingerprint());
        assert_eq!(
            from_pretty.fingerprint(),
            &EnvelopeFingerprint::of_bytes(&pretty)
        );
        assert_eq!(from_compact.revision(), from_pretty.revision());
    }

    #[test]
    fn revision_zero_is_a_counter_and_legacy_schemas_are_unversioned() {
        let rig = Rig::new();

        assert_eq!(
            rig.snapshot(&rig.raw_at(0)).unwrap().revision(),
            AuthenticatedRevision::Counter(0)
        );

        for schema in [
            LEGACY_VAULT_DATA_SCHEMA_VERSION,
            PRE_REVISION_VAULT_DATA_SCHEMA_VERSION,
        ] {
            let mut legacy = rig.data(0);
            legacy.schema_version = schema;

            let snapshot = rig.snapshot(&rig.raw_of(&legacy)).unwrap();

            // Never mistaken for a schema-3 vault at revision 0, and not migrated.
            assert_eq!(
                snapshot.revision(),
                AuthenticatedRevision::Unversioned {
                    schema_version: schema
                }
            );
            assert_ne!(snapshot.revision(), AuthenticatedRevision::Counter(0));
        }
    }

    #[test]
    fn a_wrong_vault_key_is_an_authentication_failure_of_the_local_reference() {
        let rig = Rig::new();
        let other = Rig::new();

        assert_eq!(
            inspect_local_bytes(&other.key, rig.id(), &raw(&rig.local)),
            Err(local_error(PayloadRejection::AuthenticationFailed))
        );

        // An envelope of another vault, sealed under another key.
        assert_eq!(
            rig.snapshot(&raw(&other.local)),
            Err(local_error(PayloadRejection::AuthenticationFailed))
        );
    }

    #[test]
    fn corruption_is_indistinguishable_from_a_wrong_key() {
        let rig = Rig::new();

        let mut ciphertext = rig.local.clone();
        ciphertext.payload.ciphertext[0] ^= 0x01;

        let mut nonce = rig.local.clone();
        nonce.payload.nonce[0] ^= 0x01;

        for tampered in [ciphertext, nonce] {
            assert_eq!(
                rig.snapshot(&raw(&tampered)),
                Err(local_error(PayloadRejection::AuthenticationFailed))
            );
        }
    }

    #[test]
    fn a_wrong_expected_vault_id_is_rejected_after_authentication() {
        let rig = Rig::new();
        let wrong = Uuid::new_v4();

        assert_ne!(wrong, rig.id());
        assert_eq!(
            inspect_local_bytes(&rig.key, wrong, &raw(&rig.local)),
            Err(local_error(PayloadRejection::VaultIdMismatch))
        );

        // A payload that authenticates but carries another vault_id.
        let mut foreign = rig.data(4);
        foreign.vault_id = Uuid::new_v4();

        assert_eq!(
            rig.snapshot(&rig.raw_of(&foreign)),
            Err(local_error(PayloadRejection::VaultIdMismatch))
        );
    }

    #[test]
    fn malformed_local_bytes_are_a_local_failure_and_echo_nothing() {
        let rig = Rig::new();
        let valid = raw(&rig.local);

        let mut trailing = valid.clone();
        trailing.extend_from_slice(b" trailing");

        let samples: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"not json".to_vec(),
            b"{}".to_vec(),
            b"null".to_vec(),
            vec![0xff, 0xfe, 0x00, 0x01],
            format!(r#"{{"magic":"{SENTINEL}","version":"{SENTINEL}"}}"#).into_bytes(),
            trailing,
        ];

        for sample in samples {
            let error = rig.snapshot(&sample).unwrap_err();

            assert_eq!(
                error,
                BoundInspectionError::MalformedEnvelope {
                    input: EnvelopeInput::LocalReference
                }
            );

            for text in [format!("{error}"), format!("{error:?}")] {
                assert!(!text.contains(SENTINEL));
                assert!(!text.contains("line"));
                assert!(!text.contains("column"));
                assert!(!text.contains("EOF"));
            }
        }
    }

    #[test]
    fn oversized_local_input_is_rejected_by_length_before_any_parsing() {
        let rig = Rig::new();

        // Not even JSON: only the length can have decided this.
        let oversized = vec![b'x'; MAX_ENVELOPE_BYTES + 1];

        assert_eq!(
            rig.snapshot(&oversized),
            Err(BoundInspectionError::InputTooLarge {
                input: EnvelopeInput::LocalReference,
                actual: MAX_ENVELOPE_BYTES + 1,
                limit: MAX_ENVELOPE_BYTES,
            })
        );
    }

    #[test]
    fn invalid_authenticated_payloads_are_rejected_with_the_existing_reasons() {
        let rig = Rig::new();

        // Authentic, but not a vault payload.
        assert_eq!(
            rig.snapshot(&raw(&rig.seal_plaintext(b"this is not json"))),
            Err(local_error(PayloadRejection::MalformedPayload))
        );

        // Authentic and well-formed, but an unsupported (future) schema.
        let mut future = rig.data(4);
        future.schema_version = VAULT_DATA_SCHEMA_VERSION + 1;

        assert_eq!(
            rig.snapshot(&rig.raw_of(&future)),
            Err(local_error(PayloadRejection::UnsupportedSchema))
        );

        // Authentic and well-formed, but failing `VaultData::validate`.
        let mut invalid = rig.data(4);
        invalid.entries[0].title = String::new();

        assert_eq!(
            rig.snapshot(&rig.raw_of(&invalid)),
            Err(local_error(PayloadRejection::InvalidData))
        );

        // An unsupported envelope header is decided before any decryption.
        let mut wrong_magic = rig.local.clone();
        wrong_magic.magic = "NOTVAULT".to_owned();

        assert_eq!(
            rig.snapshot(&raw(&wrong_magic)),
            Err(local_error(PayloadRejection::UnsupportedFormat))
        );
    }

    #[test]
    fn the_snapshot_debug_output_is_redacted() {
        let rig = Rig::new();
        let snapshot = rig.snapshot(&raw(&rig.local)).unwrap();

        let rendered = format!("{snapshot:?}");

        assert!(rendered.contains(&snapshot.fingerprint().to_hex()));
        assert!(!rendered.contains(&rig.id().to_string()));
        assert!(!rendered.contains(&rig.id().simple().to_string()));
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains(TITLE));

        // Error values are equally free of content.
        let error = rig.snapshot(b"{").unwrap_err();
        let text = format!("{error} {error:?}");
        assert!(!text.contains(&rig.id().to_string()));
        assert!(!text.contains(SECRET));
    }

    #[test]
    fn inspecting_is_read_only_and_repeatable() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);
        let before = local_raw.clone();

        let first = rig.snapshot(&local_raw).unwrap();

        for _ in 0..3 {
            assert_eq!(rig.snapshot(&local_raw).unwrap(), first);
        }

        assert_eq!(local_raw, before);
        assert!(rig.snapshot(b"{").is_err());
        assert_eq!(rig.snapshot(&local_raw).unwrap(), first);
    }

    // ---- BoundInspection verified vault identity --------------------------

    #[test]
    fn a_bound_inspection_carries_the_vault_id_both_payloads_were_checked_against() {
        let rig = Rig::new();

        let bound =
            inspect_remote_bytes(&rig.key, rig.id(), &raw(&rig.local), &rig.raw_at(5), None)
                .unwrap();

        assert_eq!(bound.authenticated_vault_id(), rig.id());

        let rendered = format!("{bound:?}");
        assert!(!rendered.contains(&rig.id().to_string()));
        assert!(!rendered.contains(&rig.id().simple().to_string()));
    }

    #[test]
    fn identity_mismatches_are_rejected_before_any_bound_inspection_exists() {
        let rig = Rig::new();
        let local_raw = raw(&rig.local);
        let candidate_raw = rig.raw_at(5);

        // A wrong expected id fails against the local payload first.
        assert_eq!(
            inspect_remote_bytes(&rig.key, Uuid::new_v4(), &local_raw, &candidate_raw, None),
            Err(local_error(PayloadRejection::VaultIdMismatch))
        );

        // A candidate that authenticates but belongs to another vault_id.
        let mut other_vault = rig.data(5);
        other_vault.vault_id = Uuid::new_v4();
        let other_vault_raw = rig.raw_of(&other_vault);

        assert_eq!(
            inspect_remote_bytes(&rig.key, rig.id(), &local_raw, &other_vault_raw, None),
            Err(candidate_error(PayloadRejection::VaultIdMismatch))
        );

        // A local payload that authenticates but belongs to another vault_id is
        // a local-reference failure, never blamed on the remote.
        assert_eq!(
            inspect_remote_bytes(&rig.key, rig.id(), &other_vault_raw, &candidate_raw, None),
            Err(local_error(PayloadRejection::VaultIdMismatch))
        );

        // A candidate sealed under another vault's key.
        let other = Rig::new();

        assert_eq!(
            inspect_remote_bytes(&rig.key, rig.id(), &local_raw, &raw(&other.local), None),
            Err(candidate_error(PayloadRejection::AuthenticationFailed))
        );
    }
}
