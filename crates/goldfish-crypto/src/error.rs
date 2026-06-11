//! Crypto errors. Generic by design — we do **not** want to leak which step
//! failed (potential oracle).

use thiserror::Error;

/// Crypto operation error.
///
/// Variants are intentionally coarse: callers should not branch on the
/// distinction between "wrong key" and "tampered ciphertext" because both
/// indicate the same outcome — refuse the operation.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD encryption failed (only on pathological input-size overflow).
    #[error("encryption failed")]
    Encryption,

    /// AEAD decryption / authentication failed (wrong key or tampering).
    #[error("decryption failed")]
    Decryption,

    /// Argon2id derivation failed (only happens on impossible parameter combos).
    #[error("key derivation failed")]
    KeyDerivation,

    /// HKDF expansion failed (impossible OKM length).
    #[error("key expansion failed")]
    KeyExpansion,

    /// Provided buffer had the wrong length.
    #[error("invalid input length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length received.
        actual: usize,
    },

    /// A serialized container (e.g. an encrypted export file) had a malformed or
    /// unsupported header. Unlike [`CryptoError::Decryption`], this is a parse
    /// failure on public framing — it carries no secret-dependent information,
    /// so a descriptive reason is safe to surface.
    #[error("invalid format: {0}")]
    InvalidFormat(&'static str),
}
