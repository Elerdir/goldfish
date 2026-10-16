//! OS-CSPRNG wrappers. Centralized so we can audit every entropy source.
//!
//! All randomness in Goldfish flows through this module. It calls the operating
//! system's cryptographically secure generator directly (`getrandom`), which draws
//! from the kernel CSPRNG (BCryptGenRandom / getrandom(2) / arc4random).

/// Fills `dst` with cryptographically secure random bytes.
///
/// # Panics
/// If the OS generator is unavailable — there is no safe fallback for key material.
pub fn fill(dst: &mut [u8]) {
    getrandom::fill(dst).expect("OS CSPRNG unavailable");
}

/// Returns a fresh array of `N` cryptographically secure random bytes.
pub fn generate<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    fill(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        // Probabilistic, but a collision on 32 random bytes is ~2^-256.
        let a: [u8; 32] = generate();
        let b: [u8; 32] = generate();
        assert_ne!(a, b);
    }

    #[test]
    fn fill_writes_all_bytes() {
        let mut buf = [0u8; 16];
        fill(&mut buf);
        // Not all-zero with overwhelming probability.
        assert_ne!(buf, [0u8; 16]);
    }
}
