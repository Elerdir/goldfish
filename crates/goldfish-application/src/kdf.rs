//! KDF policy helpers — bridge crypto's Argon2id calibration to domain params.

use goldfish_domain::KdfParams;

/// Benchmarks Argon2id on this machine and returns domain [`KdfParams`] whose
/// derivation takes at least `target_millis`, never below the OWASP default.
///
/// Run once at vault creation, off the UI thread (it derives a few times).
#[must_use]
pub fn calibrate_kdf(target_millis: u64) -> KdfParams {
    let params = goldfish_crypto::Argon2Params::calibrate(target_millis);
    KdfParams {
        memory_kib: params.memory_kib(),
        iterations: params.iterations(),
        parallelism: params.parallelism(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_never_returns_below_default() {
        // target 0 returns on the first (floor) measurement — deterministic.
        let p = calibrate_kdf(0);
        assert!(p.memory_kib >= KdfParams::DEFAULT.memory_kib);
        assert!(p.iterations >= KdfParams::DEFAULT.iterations);
    }
}
