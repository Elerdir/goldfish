//! OS CSPRNG adapter for the `SecureRandom` port.

use goldfish_application::SecureRandom;

/// A [`SecureRandom`] backed by the OS CSPRNG (via `goldfish-crypto`).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSecureRandom;

impl SecureRandom for OsSecureRandom {
    fn fill(&self, dst: &mut [u8]) {
        goldfish_crypto::rng::fill(dst);
    }
}
