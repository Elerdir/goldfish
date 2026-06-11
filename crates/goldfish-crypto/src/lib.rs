//! Goldfish crypto primitives.
//!
//! Audit-isolated layer for everything cryptographic. The rest of the codebase
//! goes through this crate exclusively (or through ports that the application
//! layer wires). Direct use of `argon2` / `chacha20poly1305` outside this crate
//! is intentionally avoided.
//!
//! ### Primitives in use
//! - **KDF**: Argon2id, OWASP 2024 params (m=65_536 KiB, t=3, p=1) — see [`kdf`].
//! - **AEAD**: XChaCha20-Poly1305, 192-bit nonces (random is safe at any scale) — see [`aead`].
//! - **MAC**: HMAC-SHA256 — see [`mac`].
//! - **KDF expansion**: HKDF-SHA256 — see [`derive`].
//!
//! ### Composition
//! [`vault::VaultKeyset`] ties the primitives into the full key hierarchy
//! (KEK → wrapped DEK → per-entry subkeys). Most callers only need that type.
//!
//! All secret material is wrapped in [`zeroize::Zeroizing`] and constant-time
//! compared via `subtle`.

pub mod aead;
pub mod derive;
pub mod error;
pub mod export;
pub mod kdf;
pub mod key;
pub mod mac;
pub mod rng;
pub mod vault;

pub use aead::{Sealed, NONCE_LEN, TAG_LEN};
pub use error::CryptoError;
pub use kdf::{Argon2Params, SALT_LEN};
pub use key::{SecretKey, KEY_LEN};
pub use mac::VERIFIER_LEN;
pub use vault::{
    generate_recovery_code, BiometricMaterial, NewVaultMaterial, RecoveryMaterial, UnlockMaterial,
    VaultKeyset,
};
