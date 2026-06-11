//! Vault-level metadata. The vault is the container that holds entries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Argon2id parameters. Stored in vault metadata so they can be re-tuned and
/// the vault upgraded transparently when the user unlocks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB. OWASP 2024: ≥ 19 MiB; we default to `65_536` (64 MiB).
    pub memory_kib: u32,
    /// Time cost (iterations). OWASP 2024: ≥ 2; we default to 3.
    pub iterations: u32,
    /// Parallelism. Default 1 (single-thread, deterministic on small devices).
    pub parallelism: u32,
}

impl KdfParams {
    /// Current default parameters. Conservative side of OWASP 2024.
    pub const DEFAULT: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_owasp_2024_recommendation() {
        let p = KdfParams::default();
        // OWASP 2024: m ≥ 19 MiB. We deliberately exceed it.
        assert!(
            p.memory_kib >= 19 * 1024,
            "memory cost must meet OWASP minimum"
        );
        assert!(p.iterations >= 2, "iteration count must meet OWASP minimum");
        assert!(p.parallelism >= 1, "parallelism must be at least 1");
    }

    #[test]
    fn default_trait_returns_same_as_const() {
        assert_eq!(KdfParams::default(), KdfParams::DEFAULT);
    }

    #[test]
    fn default_concrete_values() {
        let p = KdfParams::DEFAULT;
        assert_eq!(p.memory_kib, 65_536);
        assert_eq!(p.iterations, 3);
        assert_eq!(p.parallelism, 1);
    }
}

/// DEK sealed under the biometric protection key.
///
/// The protection key itself lives in the OS keystore; this struct is present
/// only when biometric unlock is enabled. It is useless without the keystore
/// key, so it is safe to store in the plaintext sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricWrap {
    /// Nonce for the sealed DEK.
    pub nonce: [u8; 24],
    /// DEK sealed under the biometric protection key (includes the AEAD tag).
    pub wrapped_dek: Vec<u8>,
}

/// DEK sealed under a key derived from the recovery code.
///
/// Present only when recovery-code unlock is enabled. Useless without the
/// (never-stored) recovery code, so safe in the plaintext sidecar. Enabling
/// recovery adds a *second* path to the DEK — vault security then also depends on
/// keeping the recovery code secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryWrap {
    /// Argon2id salt for deriving the recovery key from the code.
    pub salt: [u8; 16],
    /// DEK sealed under the recovery key (includes the AEAD tag).
    pub wrapped_dek: Vec<u8>,
    /// Nonce used to wrap the DEK.
    pub nonce: [u8; 24],
}

/// Vault metadata persisted as a plaintext sidecar (none of it is secret on
/// its own). Serialized to disk by the `VaultMetadataRepository`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Schema version of the on-disk format.
    pub schema_version: u32,
    /// Argon2id parameters used to derive the KEK from the master password.
    pub kdf_params: KdfParams,
    /// 16-byte salt for Argon2id. Public, but unique per vault.
    pub kdf_salt: [u8; 16],
    /// DEK wrapped under KEK with XChaCha20-Poly1305.
    pub wrapped_dek: Vec<u8>,
    /// 24-byte nonce used to wrap the DEK.
    pub wrapped_dek_nonce: [u8; 24],
    /// HMAC-SHA256(KEK, "goldfish-unlock-verifier") — constant-time comparison
    /// lets us test the master password without decrypting any entry.
    pub verifier: [u8; 32],
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
    /// Biometric-unlock material, if enabled. Defaults to `None` for vaults
    /// created before biometrics existed.
    #[serde(default)]
    pub biometric: Option<BiometricWrap>,
    /// Recovery-code material, if enabled. Defaults to `None`.
    #[serde(default)]
    pub recovery: Option<RecoveryWrap>,
    /// Consecutive failed unlocks, persisted so the backoff survives an app
    /// restart (an attacker can't reset the throttle by relaunching). Cleared on
    /// a successful unlock. Defaults to `0`.
    #[serde(default)]
    pub unlock_failures: u32,
    /// Epoch-ms until which unlocking is throttled, persisted alongside
    /// [`Self::unlock_failures`]. `None` when not throttled.
    #[serde(default)]
    pub unlock_locked_until_ms: Option<i64>,
}

impl VaultMetadata {
    /// Current on-disk schema version. Bumped when the persisted format changes;
    /// also bound into the DEK-wrap AAD to prevent downgrade attacks.
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;
}
