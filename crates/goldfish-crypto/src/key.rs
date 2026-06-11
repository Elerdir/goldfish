//! Symmetric key material — 32-byte keys held in zeroizing storage.
//!
//! `SecretKey` is the single representation for the KEK, the DEK, and every
//! derived subkey. It zeroizes its backing buffer on drop and refuses to print
//! its contents via `Debug`. Construction from raw bytes is crate-private so
//! that keys can only originate from a vetted source (RNG, KDF, or HKDF).

use std::fmt;

use zeroize::Zeroizing;

use crate::rng;
use crate::CryptoError;

/// Length of every symmetric key in bytes (256-bit).
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key. Zeroized on drop; never logged.
pub struct SecretKey {
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl SecretKey {
    /// Generates a fresh random key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            bytes: Zeroizing::new(rng::generate::<KEY_LEN>()),
        }
    }

    /// Wraps raw key bytes. Crate-private: keys must come from RNG/KDF/HKDF.
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Wraps key bytes from a slice, validating the length.
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut buf = [0u8; KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self::from_bytes(buf))
    }

    /// Borrows the raw key bytes. Crate-private — only crypto primitives touch this.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let k = SecretKey::from_bytes([7u8; KEY_LEN]);
        let s = format!("{k:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains('7'));
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        let err = SecretKey::from_slice(&[0u8; 16]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidLength {
                expected: 32,
                actual: 16
            }
        ));
    }

    #[test]
    fn from_slice_accepts_exact_length() {
        let k = SecretKey::from_slice(&[1u8; KEY_LEN]).unwrap();
        assert_eq!(k.as_bytes(), &[1u8; KEY_LEN]);
    }
}
