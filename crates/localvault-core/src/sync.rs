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
