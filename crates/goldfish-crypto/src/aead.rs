//! XChaCha20-Poly1305 AEAD wrappers — `seal` and `open` with explicit AAD.
//!
//! XChaCha20-Poly1305 uses a 192-bit (24-byte) nonce, which makes random nonce
//! selection safe at any realistic scale (collision probability is negligible
//! even after billions of messages — unlike AES-GCM's 96-bit nonce). Every
//! ciphertext carries an appended 16-byte Poly1305 tag and is bound to its
//! associated data (AAD); tampering with either fails authentication.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::key::SecretKey;
use crate::rng;
use crate::CryptoError;

/// XChaCha20 nonce length in bytes (192-bit).
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// A nonce paired with its ciphertext (ciphertext includes the appended tag).
#[derive(Debug, Clone)]
pub struct Sealed {
    /// The 24-byte random nonce used for this ciphertext.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

fn cipher_for(key: &SecretKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key is exactly 32 bytes")
}

/// Encrypts `plaintext` under `key` with the supplied `nonce` and binds `aad`.
///
/// The caller is responsible for nonce uniqueness; prefer [`seal_random_nonce`]
/// unless reproducing a fixed test vector.
pub fn seal(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    cipher_for(key)
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)
}

/// Encrypts `plaintext` with a freshly generated random nonce.
pub fn seal_random_nonce(
    key: &SecretKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Sealed, CryptoError> {
    let nonce: [u8; NONCE_LEN] = rng::generate();
    let ciphertext = seal(key, &nonce, plaintext, aad)?;
    Ok(Sealed { nonce, ciphertext })
}

/// Decrypts and authenticates `ciphertext`. Fails on wrong key, tampered
/// ciphertext, or mismatched `aad`.
pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    cipher_for(key)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_bytes([byte; 32])
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let k = key(1);
        let sealed = seal_random_nonce(&k, b"top secret", b"aad").unwrap();
        let opened = open(&k, &sealed.nonce, &sealed.ciphertext, b"aad").unwrap();
        assert_eq!(opened, b"top secret");
    }

    #[test]
    fn ciphertext_includes_tag() {
        let k = key(1);
        let sealed = seal_random_nonce(&k, b"x", b"").unwrap();
        assert_eq!(sealed.ciphertext.len(), 1 + TAG_LEN);
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal_random_nonce(&key(1), b"secret", b"aad").unwrap();
        let err = open(&key(2), &sealed.nonce, &sealed.ciphertext, b"aad").unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = key(1);
        let mut sealed = seal_random_nonce(&k, b"secret", b"aad").unwrap();
        sealed.ciphertext[0] ^= 0x01;
        let err = open(&k, &sealed.nonce, &sealed.ciphertext, b"aad").unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn mismatched_aad_fails() {
        let k = key(1);
        let sealed = seal_random_nonce(&k, b"secret", b"aad-one").unwrap();
        let err = open(&k, &sealed.nonce, &sealed.ciphertext, b"aad-two").unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn wrong_nonce_fails() {
        let k = key(1);
        let mut sealed = seal_random_nonce(&k, b"secret", b"aad").unwrap();
        sealed.nonce[0] ^= 0x01;
        let err = open(&k, &sealed.nonce, &sealed.ciphertext, b"aad").unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    /// KAT: IETF draft-irtf-cfrg-xchacha §A.3.1 (AEAD_XChaCha20_Poly1305).
    /// Independent vector — proves our AEAD wiring matches the spec.
    #[test]
    fn kat_xchacha20poly1305_draft_vector() {
        let key_bytes =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap();
        let k = SecretKey::from_slice(&key_bytes).unwrap();

        let nonce_vec = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_vec);

        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        assert_eq!(plaintext.len(), 114, "draft plaintext is 114 bytes");

        let expected = hex::decode(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49",
        ))
        .unwrap();

        let ct = seal(&k, &nonce, plaintext, &aad).unwrap();
        assert_eq!(ct, expected, "ciphertext||tag must match the draft vector");

        let pt = open(&k, &nonce, &ct, &aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    proptest! {
        #[test]
        fn seal_open_round_trip_any_input(
            plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
            aad in proptest::collection::vec(any::<u8>(), 0..128),
            key_byte in any::<u8>(),
        ) {
            let k = key(key_byte);
            let sealed = seal_random_nonce(&k, &plaintext, &aad).unwrap();
            let opened = open(&k, &sealed.nonce, &sealed.ciphertext, &aad).unwrap();
            prop_assert_eq!(opened, plaintext);
        }
    }
}
