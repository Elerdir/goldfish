//! Self-contained encrypted-export container (`.goldfish` file format).
//!
//! Unlike the vault keyset (which wraps a DEK behind the master password), an
//! export is a **standalone, password-protected blob**: anyone with the export
//! password can decrypt it on any device, with nothing else required. That makes
//! it a portable backup / migration artifact.
//!
//! ## On-disk layout
//!
//! A fixed 64-byte header followed by the AEAD ciphertext. The **entire header**
//! is fed in as associated data, so every framing byte (magic, versions,
//! algorithm ids, KDF parameters, salt, nonce) is authenticated — tampering with
//! any of it fails decryption.
//!
//! ```text
//! offset  size  field
//! ──────  ────  ─────────────────────────────────────────────
//!   0      8    magic = b"GOLDFISH"
//!   8      1    format version (= 1)
//!   9      1    KDF id (= 1: Argon2id)
//!  10      1    AEAD id (= 1: XChaCha20-Poly1305)
//!  11      1    reserved (= 0)
//!  12      4    Argon2 memory cost, KiB   (u32 LE)
//!  16      4    Argon2 iterations          (u32 LE)
//!  20      4    Argon2 parallelism         (u32 LE)
//!  24     16    Argon2 salt
//!  40     24    XChaCha20 nonce
//!  64      N    ciphertext ‖ 16-byte Poly1305 tag
//! ```
//!
//! Key derivation reuses the same Argon2id pipeline as the vault KEK, with a
//! fresh per-file salt; encryption reuses the same XChaCha20-Poly1305 AEAD.

use zeroize::Zeroizing;

use crate::aead::{self, NONCE_LEN, TAG_LEN};
use crate::kdf::{self, Argon2Params, SALT_LEN};
use crate::CryptoError;

/// File magic — first 8 bytes of every export.
pub const MAGIC: &[u8; 8] = b"GOLDFISH";

/// Current export container format version.
pub const FORMAT_VERSION: u8 = 1;

/// KDF identifier: Argon2id.
const KDF_ARGON2ID: u8 = 1;

/// AEAD identifier: XChaCha20-Poly1305.
const AEAD_XCHACHA20POLY1305: u8 = 1;

/// Total header length in bytes (everything before the ciphertext).
pub const HEADER_LEN: usize = 64;

// Field offsets within the header.
const OFF_MAGIC: usize = 0;
const OFF_FORMAT: usize = 8;
const OFF_KDF: usize = 9;
const OFF_AEAD: usize = 10;
const OFF_RESERVED: usize = 11;
const OFF_MEMORY: usize = 12;
const OFF_ITERATIONS: usize = 16;
const OFF_PARALLELISM: usize = 20;
const OFF_SALT: usize = 24;
const OFF_NONCE: usize = 40;

const _: () = assert!(OFF_SALT + SALT_LEN == OFF_NONCE, "salt must precede nonce");
const _: () = assert!(OFF_NONCE + NONCE_LEN == HEADER_LEN, "nonce ends the header");

/// Builds the 64-byte authenticated header for a fresh export.
fn build_header(
    params: Argon2Params,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[OFF_MAGIC..OFF_FORMAT].copy_from_slice(MAGIC);
    h[OFF_FORMAT] = FORMAT_VERSION;
    h[OFF_KDF] = KDF_ARGON2ID;
    h[OFF_AEAD] = AEAD_XCHACHA20POLY1305;
    h[OFF_RESERVED] = 0;
    h[OFF_MEMORY..OFF_ITERATIONS].copy_from_slice(&params.memory_kib().to_le_bytes());
    h[OFF_ITERATIONS..OFF_PARALLELISM].copy_from_slice(&params.iterations().to_le_bytes());
    h[OFF_PARALLELISM..OFF_SALT].copy_from_slice(&params.parallelism().to_le_bytes());
    h[OFF_SALT..OFF_NONCE].copy_from_slice(salt);
    h[OFF_NONCE..HEADER_LEN].copy_from_slice(nonce);
    h
}

/// Parsed, validated header of an export file.
struct ParsedHeader {
    params: Argon2Params,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

/// Validates and parses the header from `file`. Returns the framing parameters
/// needed to re-derive the key and decrypt.
fn parse_header(file: &[u8]) -> Result<ParsedHeader, CryptoError> {
    if file.len() < HEADER_LEN + TAG_LEN {
        return Err(CryptoError::InvalidFormat(
            "file shorter than minimum length",
        ));
    }
    if &file[OFF_MAGIC..OFF_FORMAT] != MAGIC {
        return Err(CryptoError::InvalidFormat(
            "not a Goldfish export (bad magic)",
        ));
    }
    if file[OFF_FORMAT] != FORMAT_VERSION {
        return Err(CryptoError::InvalidFormat(
            "unsupported export format version",
        ));
    }
    if file[OFF_KDF] != KDF_ARGON2ID {
        return Err(CryptoError::InvalidFormat("unsupported KDF"));
    }
    if file[OFF_AEAD] != AEAD_XCHACHA20POLY1305 {
        return Err(CryptoError::InvalidFormat("unsupported AEAD"));
    }

    let memory = read_u32_le(file, OFF_MEMORY);
    let iterations = read_u32_le(file, OFF_ITERATIONS);
    let parallelism = read_u32_le(file, OFF_PARALLELISM);

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&file[OFF_SALT..OFF_NONCE]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&file[OFF_NONCE..HEADER_LEN]);

    Ok(ParsedHeader {
        params: Argon2Params::new(memory, iterations, parallelism),
        salt,
        nonce,
    })
}

/// Seals `plaintext` into a complete `.goldfish` file protected by `password`.
///
/// A fresh random salt and nonce are generated; `params` controls the Argon2id
/// cost recorded in the header. The returned bytes are `header ‖ ciphertext`.
pub fn seal(
    password: &[u8],
    params: Argon2Params,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let salt: [u8; SALT_LEN] = crate::rng::generate();
    let nonce: [u8; NONCE_LEN] = crate::rng::generate();
    let header = build_header(params, &salt, &nonce);

    let key = kdf::derive_kek(password, &salt, params)?;
    let ciphertext = aead::seal(&key, &nonce, plaintext, &header)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a `.goldfish` file with `password`, returning the plaintext payload in
/// zeroizing storage.
///
/// Returns [`CryptoError::InvalidFormat`] if the framing is malformed or
/// unsupported, and [`CryptoError::Decryption`] if the password is wrong or the
/// ciphertext/header was tampered with (the two are intentionally
/// indistinguishable).
pub fn open(password: &[u8], file: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let parsed = parse_header(file)?;
    let header = &file[..HEADER_LEN];
    let ciphertext = &file[HEADER_LEN..];

    let key = kdf::derive_kek(password, &parsed.salt, parsed.params)?;
    let plaintext = aead::open(&key, &parsed.nonce, ciphertext, header)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn fast() -> Argon2Params {
        Argon2Params::new(256, 1, 1)
    }

    #[test]
    fn round_trip_recovers_payload() {
        let payload = b"{\"entries\":[\"secret\"]}";
        let file = seal(b"export-pw", fast(), payload).unwrap();
        let opened = open(b"export-pw", &file).unwrap();
        assert_eq!(opened.as_slice(), payload);
    }

    #[test]
    fn empty_payload_round_trips() {
        let file = seal(b"pw", fast(), b"").unwrap();
        assert_eq!(file.len(), HEADER_LEN + TAG_LEN);
        let opened = open(b"pw", &file).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn header_records_params() {
        let file = seal(b"pw", Argon2Params::new(512, 2, 1), b"x").unwrap();
        assert_eq!(&file[OFF_MAGIC..OFF_FORMAT], MAGIC);
        assert_eq!(file[OFF_FORMAT], FORMAT_VERSION);
        assert_eq!(read_u32_le(&file, OFF_MEMORY), 512);
        assert_eq!(read_u32_le(&file, OFF_ITERATIONS), 2);
        assert_eq!(read_u32_le(&file, OFF_PARALLELISM), 1);
    }

    #[test]
    fn wrong_password_fails_as_decryption() {
        let file = seal(b"correct", fast(), b"payload").unwrap();
        let err = open(b"wrong", &file).unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut file = seal(b"pw", fast(), b"payload").unwrap();
        let last = file.len() - 1;
        file[last] ^= 0x01;
        assert!(matches!(open(b"pw", &file), Err(CryptoError::Decryption)));
    }

    #[test]
    fn tampered_salt_fails() {
        // Salt is authenticated via the header AAD, so flipping it breaks auth.
        let mut file = seal(b"pw", fast(), b"payload").unwrap();
        file[OFF_SALT] ^= 0x01;
        assert!(matches!(open(b"pw", &file), Err(CryptoError::Decryption)));
    }

    #[test]
    fn tampered_params_fail() {
        // Params are public but authenticated via the header AAD. Flip the low
        // byte of the memory cost (256 -> 257): still a valid Argon2 parameter,
        // so derivation succeeds — but with a different key and a mutated AAD,
        // so authentication fails with `Decryption` (not a parameter error).
        let mut file = seal(b"pw", fast(), b"payload").unwrap();
        file[OFF_MEMORY] ^= 0x01;
        assert!(matches!(open(b"pw", &file), Err(CryptoError::Decryption)));
    }

    #[test]
    fn bad_magic_is_format_error() {
        let mut file = seal(b"pw", fast(), b"payload").unwrap();
        file[0] = b'X';
        assert!(matches!(
            open(b"pw", &file),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    #[test]
    fn unsupported_version_is_format_error() {
        let mut file = seal(b"pw", fast(), b"payload").unwrap();
        file[OFF_FORMAT] = 99;
        assert!(matches!(
            open(b"pw", &file),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    #[test]
    fn truncated_file_is_format_error() {
        let file = seal(b"pw", fast(), b"payload").unwrap();
        let err = open(b"pw", &file[..HEADER_LEN + TAG_LEN - 1]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidFormat(_)));
    }

    #[test]
    fn two_seals_of_same_input_differ() {
        // Fresh salt + nonce each time → different ciphertext, no determinism leak.
        let a = seal(b"pw", fast(), b"payload").unwrap();
        let b = seal(b"pw", fast(), b"payload").unwrap();
        assert_ne!(a, b);
    }

    proptest::proptest! {
        /// Opening arbitrary bytes must never panic — the header parser has to
        /// reject malformed input gracefully (Ok/Err, no slice or arithmetic panic).
        #[test]
        fn open_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)
        ) {
            let _ = open(b"password", &bytes);
        }
    }
}
