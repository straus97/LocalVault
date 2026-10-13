//! Pure, provider-independent synchronization-state evaluation (Stage 1U-1).
//!
//! Everything here compares SHA-256 fingerprints of the *exact raw bytes* of an
//! encrypted vault envelope. The module performs no I/O, reads no clock,
//! decrypts nothing, knows no device identity, path, provider or transport, and
//! never touches `VaultData` or the vault format.
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
