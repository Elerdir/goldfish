//! HMAC-SHA256 — used for the vault unlock verifier (constant-time compare).
//!
//! The verifier is `HMAC-SHA256(KEK, "goldfish-unlock-verifier")`, stored in
//! vault metadata. On unlock we recompute it from the password-derived KEK and
//! compare in constant time. A match proves the password is correct without
//! decrypting any entry; a mismatch reveals nothing about *why* it failed.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::key::SecretKey;

/// Length of the unlock verifier in bytes.
pub const VERIFIER_LEN: usize = 32;

/// Domain-separation label for the unlock verifier.
const VERIFIER_INFO: &[u8] = b"goldfish-unlock-verifier";

type HmacSha256 = Hmac<Sha256>;

/// Computes HMAC-SHA256 over `data` with `key`. The key may be any length.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Derives the unlock verifier from the KEK.
pub fn compute_verifier(kek: &SecretKey) -> [u8; VERIFIER_LEN] {
    hmac_sha256(kek.as_bytes(), VERIFIER_INFO)
}

/// Constant-time check that `kek` reproduces `expected`.
pub fn verify_verifier(kek: &SecretKey, expected: &[u8; VERIFIER_LEN]) -> bool {
    let actual = compute_verifier(kek);
    bool::from(actual.as_slice().ct_eq(expected.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KEY_LEN;

    /// KAT: RFC 4231 Test Case 1 (HMAC-SHA-256).
    /// Independent vector — proves our HMAC wiring is correct.
    #[test]
    fn kat_rfc4231_test_case_1() {
        let key = hex::decode("0b".repeat(20)).unwrap();
        let out = hmac_sha256(&key, b"Hi There");
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn verifier_matches_same_kek() {
        let kek = SecretKey::from_bytes([3u8; KEY_LEN]);
        let v = compute_verifier(&kek);
        assert!(verify_verifier(&kek, &v));
    }

    #[test]
    fn verifier_rejects_different_kek() {
        let kek = SecretKey::from_bytes([3u8; KEY_LEN]);
        let other = SecretKey::from_bytes([4u8; KEY_LEN]);
        let v = compute_verifier(&kek);
        assert!(!verify_verifier(&other, &v));
    }

    #[test]
    fn verifier_rejects_flipped_bit() {
        let kek = SecretKey::from_bytes([3u8; KEY_LEN]);
        let mut v = compute_verifier(&kek);
        v[0] ^= 0x01;
        assert!(!verify_verifier(&kek, &v));
    }
}
