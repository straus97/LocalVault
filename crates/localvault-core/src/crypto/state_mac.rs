//! Key derivation and message authentication for the dormant authenticated
//! sync-state record (Stage 1U-4, slice B3c-2a).
//!
//! The MAC key is derived from the Vault Key with HKDF-SHA256 (RFC 5869), so
//! the Vault Key itself is never used as an HMAC key; it stays an AEAD key.
//! The tag is HMAC-SHA256 (RFC 2104). Nothing here reads a clock, generates
//! randomness, performs I/O or logs; every failure is a fixed
//! [`CryptoError`] category.
//!
//! The internal HMAC/HKDF state of the `hmac`/`hkdf` crates (pad blocks, the
//! pseudo-random key) is not zeroized by those crates on drop. That is the
//! same residual as the existing TOTP HMAC use; only the derived key and the
//! output buffer handed back here are zeroizing.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::keys::{SecretKey, KEY_LEN};
use super::CryptoError;

/// HKDF `info` of the sync-state MAC key. Distinct from every AEAD AAD label
/// and from the binding-tag domain.
pub(crate) const STATE_MAC_KEY_INFO: &[u8] = b"LocalVault/sync-state-mac-key/v1";

/// Length of an HMAC-SHA256 tag in bytes.
pub(crate) const STATE_MAC_LEN: usize = 32;

/// HKDF-SHA256 of the Vault Key: no salt (RFC 5869: `HashLen` zero bytes), the
/// fixed [`STATE_MAC_KEY_INFO`], 32 output bytes.
pub(crate) fn derive_state_mac_key(
    vault_key: &SecretKey,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, &vault_key[..]);

    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(STATE_MAC_KEY_INFO, &mut okm[..])
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(okm)
}

/// HMAC-SHA256 of `message` under `key`.
pub(crate) fn state_mac(
    key: &[u8; KEY_LEN],
    message: &[u8],
) -> Result<[u8; STATE_MAC_LEN], CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    mac.update(message);

    Ok(mac.finalize().into_bytes().into())
}

/// Constant-time verification of `tag` over `message`. A key that cannot be
/// used is a failed verification, never a pass. Tags are only ever compared
/// through [`Mac::verify_slice`].
pub(crate) fn verify_state_mac(
    key: &[u8; KEY_LEN],
    message: &[u8],
    tag: &[u8; STATE_MAC_LEN],
) -> bool {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    mac.update(message);

    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        HEXLOWER.encode(bytes)
    }

    fn unhex(text: &str) -> Vec<u8> {
        HEXLOWER.decode(text.as_bytes()).unwrap()
    }

    /// `0x00 0x01 .. 0x1f`.
    fn counting_key() -> SecretKey {
        Zeroizing::new(std::array::from_fn(|i| i as u8))
    }

    /// HMAC zero-pads a key shorter than the block size, so a short RFC key
    /// zero-extended to 32 bytes is the same key.
    fn padded(key: &[u8]) -> [u8; KEY_LEN] {
        let mut out = [0u8; KEY_LEN];
        out[..key.len()].copy_from_slice(key);
        out
    }

    // ---- independent standard vectors ----------------------------------------

    #[test]
    fn rfc_4231_test_cases_1_and_2_through_state_mac() {
        let tc1 = state_mac(&padded(&[0x0b; 20]), b"Hi There").unwrap();
        assert_eq!(
            hex(&tc1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        let tc2 = state_mac(&padded(b"Jefe"), b"what do ya want for nothing?").unwrap();
        assert_eq!(
            hex(&tc2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc_5869_test_case_1_through_the_hkdf_api() {
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");

        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm[..32]),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    #[test]
    fn rfc_5869_test_case_3_and_the_none_salt_equivalence() {
        let ikm = [0x0b; 22];

        let (prk, hkdf) = Hkdf::<Sha256>::extract(None, &ikm);
        assert_eq!(
            hex(&prk),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );

        let mut okm = [0u8; 42];
        hkdf.expand(&[], &mut okm).unwrap();
        assert_eq!(
            hex(&okm[..32]),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );

        // `None`, an explicit zero salt of HashLen bytes and an empty salt are
        // one and the same PRK.
        let (zero, _) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &ikm);
        let (empty, _) = Hkdf::<Sha256>::extract(Some(&[]), &ikm);
        assert_eq!(prk, zero);
        assert_eq!(prk, empty);
    }

    // ---- derivation ------------------------------------------------------------

    #[test]
    fn the_derived_key_matches_the_pinned_vectors() {
        let key = derive_state_mac_key(&counting_key()).unwrap();
        assert_eq!(
            hex(&key[..]),
            "a5d1adbbf9c6f329fce9f5a6bfede16fea8c873974f429bc6e48a4b8e67e2f98"
        );

        let mut other = counting_key();
        other[0] = 0x01;
        let other_key = derive_state_mac_key(&other).unwrap();
        assert_eq!(
            hex(&other_key[..]),
            "bdf9405483d6f38b878a869b8f7766cf485e8d04d99a5c84ae8a3a2d164ab8ed"
        );
    }

    #[test]
    fn the_derived_key_is_never_the_vault_key_and_is_deterministic() {
        let vault_key = counting_key();
        let first = derive_state_mac_key(&vault_key).unwrap();

        assert_ne!(&first[..], &vault_key[..]);
        assert_eq!(first, derive_state_mac_key(&vault_key).unwrap());
        assert_eq!(STATE_MAC_KEY_INFO, b"LocalVault/sync-state-mac-key/v1");
        assert_eq!(STATE_MAC_LEN, 32);
    }

    #[test]
    fn the_info_label_separates_the_derivation() {
        let vault_key = counting_key();
        let derived = derive_state_mac_key(&vault_key).unwrap();

        let mut other = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(None, &vault_key[..])
            .expand(b"LocalVault/sync-state-mac-key/v2", &mut other)
            .unwrap();

        assert_ne!(&derived[..], &other[..]);
    }

    // ---- sign and verify -------------------------------------------------------

    #[test]
    fn a_correct_tag_verifies_and_every_deviation_fails() {
        let key = derive_state_mac_key(&counting_key()).unwrap();
        let message = b"a message to authenticate".to_vec();
        let tag = state_mac(&key, &message).unwrap();

        assert!(verify_state_mac(&key, &message, &tag));

        for bit in 0..(STATE_MAC_LEN * 8) {
            let mut flipped = tag;
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert!(!verify_state_mac(&key, &message, &flipped), "tag bit {bit}");
        }

        for index in 0..message.len() {
            let mut flipped = message.clone();
            flipped[index] ^= 0x01;
            assert!(
                !verify_state_mac(&key, &flipped, &tag),
                "message byte {index}"
            );
        }

        let mut truncated = message.clone();
        truncated.pop();
        assert!(!verify_state_mac(&key, &truncated, &tag));

        let mut extended = message.clone();
        extended.push(0);
        assert!(!verify_state_mac(&key, &extended, &tag));

        let mut wrong_key = *key;
        wrong_key[31] ^= 0x01;
        assert!(!verify_state_mac(&wrong_key, &message, &tag));
    }

    #[test]
    fn signing_is_deterministic_and_key_dependent() {
        let key = derive_state_mac_key(&counting_key()).unwrap();
        let first = state_mac(&key, b"m").unwrap();

        assert_eq!(first, state_mac(&key, b"m").unwrap());
        assert_ne!(first, state_mac(&key, b"n").unwrap());
        assert_ne!(first, state_mac(&[0u8; KEY_LEN], b"m").unwrap());
    }
}
