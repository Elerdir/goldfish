//! HKDF-SHA256 — domain-separated subkey derivation from the KEK/DEK.
//!
//! Each vault entry gets its own AEAD subkey derived from the DEK with the
//! entry id as HKDF salt and a fixed `info` label for domain separation. This
//! means a nonce reuse on one entry's subkey cannot affect any other entry.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::key::{SecretKey, KEY_LEN};
use crate::CryptoError;

/// Low-level HKDF-SHA256 expand. `okm` is filled to its full length.
///
/// Exposed primarily so the RFC 5869 KAT can drive it directly with
/// arbitrary-length input keying material.
pub fn expand(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm).map_err(|_| CryptoError::KeyExpansion)
}

/// Derives a 32-byte subkey from a master key (KEK or DEK).
pub fn derive_subkey(
    master: &SecretKey,
    salt: &[u8],
    info: &[u8],
) -> Result<SecretKey, CryptoError> {
    let mut okm = [0u8; KEY_LEN];
    expand(master.as_bytes(), salt, info, &mut okm)?;
    Ok(SecretKey::from_bytes(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT: RFC 5869 Appendix A.1 (Test Case 1, SHA-256).
    /// Independent vector — proves our HKDF wiring is correct.
    /// Our 32-byte expansion equals the first 32 bytes of the 42-byte RFC OKM
    /// (HKDF block T(1) is identical regardless of total output length).
    #[test]
    fn kat_rfc5869_test_case_1() {
        let ikm = hex::decode("0b".repeat(22)).unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let mut okm = [0u8; 42];
        expand(&ikm, &salt, &info, &mut okm).unwrap();

        let expected = hex::decode(concat!(
            "3cb25f25faacd57a90434f64d0362f2a",
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
            "34007208d5b887185865",
        ))
        .unwrap();
        assert_eq!(okm.as_slice(), expected.as_slice());
    }

    #[test]
    fn subkey_is_deterministic() {
        let master = SecretKey::from_bytes([9u8; KEY_LEN]);
        let a = derive_subkey(&master, b"entry-id", b"info").unwrap();
        let b = derive_subkey(&master, b"entry-id", b"info").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_yields_different_subkey() {
        let master = SecretKey::from_bytes([9u8; KEY_LEN]);
        let a = derive_subkey(&master, b"entry-1", b"info").unwrap();
        let b = derive_subkey(&master, b"entry-2", b"info").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_info_yields_different_subkey() {
        let master = SecretKey::from_bytes([9u8; KEY_LEN]);
        let a = derive_subkey(&master, b"entry", b"info-a").unwrap();
        let b = derive_subkey(&master, b"entry", b"info-b").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
