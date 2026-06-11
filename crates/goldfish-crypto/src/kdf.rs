//! Argon2id master-password → key-encryption-key.
//!
//! Uses Argon2id (hybrid: data-dependent + data-independent memory access) in
//! raw-KDF mode (`hash_password_into`) — we want a deterministic 32-byte key
//! from `(password, salt, params)`, not a PHC verification string.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::key::{SecretKey, KEY_LEN};
use crate::CryptoError;

/// Length of the Argon2id salt in bytes. Public, unique per vault.
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters.
///
/// This is the crypto layer's own type — the domain's `KdfParams` maps onto it
/// at the infrastructure boundary, keeping this crate free of upper-layer deps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Argon2Params {
    /// OWASP-2024-aligned defaults: m = 64 MiB, t = 3, p = 1.
    pub const DEFAULT: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };

    /// Constructs parameters from raw cost values.
    pub const fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
        }
    }

    /// Memory cost in KiB.
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Time cost (number of passes).
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Degree of parallelism (lanes).
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }

    /// Picks Argon2id parameters whose derivation takes at least `target_millis`
    /// on this machine, scaling memory up from the [`DEFAULT`](Self::DEFAULT)
    /// floor (64 MiB) toward a 256 MiB cap. Never returns below the floor, so a
    /// fast machine gets stronger parameters while a slow one keeps the default.
    ///
    /// Intended to run once at vault creation (it benchmarks Argon2id a few
    /// times, so it is not free — call it off the UI thread).
    #[must_use]
    pub fn calibrate(target_millis: u64) -> Self {
        use std::time::Instant;

        /// Memory floor — OWASP 2024 default, never go below it.
        const FLOOR_KIB: u32 = 65_536;
        /// Memory ceiling so we never over-allocate on capable machines.
        const CEIL_KIB: u32 = 262_144; // 256 MiB

        let salt = [0u8; SALT_LEN];
        let mut memory_kib = FLOOR_KIB;
        loop {
            let params = Self::new(memory_kib, 3, 1);
            let start = Instant::now();
            // Ignore the result; we only care about the wall-clock cost.
            let _ = derive_kek(b"goldfish-calibration", &salt, params);
            let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

            if elapsed >= target_millis || memory_kib >= CEIL_KIB {
                return params;
            }
            memory_kib = memory_kib.saturating_mul(2).min(CEIL_KIB);
        }
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Derives the 32-byte key-encryption-key (KEK) from the master password.
///
/// `salt` should be [`SALT_LEN`] bytes (Argon2 requires ≥ 8). The output length
/// is fixed at [`KEY_LEN`].
pub fn derive_kek(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<SecretKey, CryptoError> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::KeyDerivation)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(SecretKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Low-cost params keep tests fast; correctness of Argon2id itself is
    /// covered by the `argon2` crate's own RFC 9106 KATs.
    const fn fast() -> Argon2Params {
        Argon2Params::new(256, 1, 1)
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_kek(b"correct horse", b"saltsaltsaltsalt", fast()).unwrap();
        let b = derive_kek(b"correct horse", b"saltsaltsaltsalt", fast()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_password_yields_different_key() {
        let a = derive_kek(b"password-a", b"saltsaltsaltsalt", fast()).unwrap();
        let b = derive_kek(b"password-b", b"saltsaltsaltsalt", fast()).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_yields_different_key() {
        let a = derive_kek(b"same-password", b"salt-aaaaaaaaaaa", fast()).unwrap();
        let b = derive_kek(b"same-password", b"salt-bbbbbbbbbbb", fast()).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_params_yield_different_key() {
        let a = derive_kek(b"pw", b"saltsaltsaltsalt", Argon2Params::new(256, 1, 1)).unwrap();
        let b = derive_kek(b"pw", b"saltsaltsaltsalt", Argon2Params::new(256, 2, 1)).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn default_params_succeed() {
        // Exercises the real 64 MiB / t=3 cost once to confirm the mapping holds.
        let k = derive_kek(b"master", b"saltsaltsaltsalt", Argon2Params::DEFAULT).unwrap();
        assert_eq!(k.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn default_params_match_owasp_floor() {
        let p = Argon2Params::DEFAULT;
        assert!(p.memory_kib() >= 19 * 1024);
        assert!(p.iterations() >= 2);
        assert!(p.parallelism() >= 1);
    }

    #[test]
    fn calibrate_never_drops_below_floor() {
        // target 0 returns immediately on the first (floor) measurement.
        let p = Argon2Params::calibrate(0);
        assert_eq!(p.memory_kib(), 65_536);
        assert!(p.memory_kib() >= Argon2Params::DEFAULT.memory_kib());
        assert!(p.iterations() >= 2);
    }
}
