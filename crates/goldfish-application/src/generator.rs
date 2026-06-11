//! Password generation use case.
//!
//! Draws characters from the policy's candidate set using **rejection sampling**
//! over raw CSPRNG bytes, which avoids the modulo bias a naive `byte % n` would
//! introduce. Entropy comes from the injected [`SecureRandom`] port.

use goldfish_domain::{PassphrasePolicy, PasswordPolicy, PlaintextSecret};
use zeroize::Zeroizing;

use crate::ports::SecureRandom;
use crate::ApplicationError;

/// Generates a password matching `policy`.
///
/// # Errors
/// Returns [`ApplicationError::Domain`] if the policy is unsatisfiable.
pub fn generate_password(
    rng: &dyn SecureRandom,
    policy: &PasswordPolicy,
) -> Result<PlaintextSecret, ApplicationError> {
    policy.validate().map_err(ApplicationError::Domain)?;

    let charset = policy.charset();
    let bytes = charset.as_bytes();
    let n = bytes.len(); // 1..=92, always < 256

    // Largest multiple of `n` that fits in a byte; bytes >= threshold are
    // rejected so every character is equally likely.
    let threshold = 256 - (256 % n);

    let mut out = String::with_capacity(policy.length);
    let mut buf = Zeroizing::new([0u8; 64]);
    let mut pos = buf.len();

    while out.len() < policy.length {
        if pos >= buf.len() {
            rng.fill(&mut buf[..]);
            pos = 0;
        }
        let candidate = buf[pos] as usize;
        pos += 1;
        if candidate < threshold {
            out.push(bytes[candidate % n] as char);
        }
    }

    Ok(PlaintextSecret::from(out))
}

/// Draws a uniform index in `0..bound` from the CSPRNG using rejection sampling
/// over a `u32`, avoiding modulo bias. `bound` must be non-zero.
fn uniform_index(rng: &dyn SecureRandom, bound: usize) -> usize {
    let bound = bound as u64;
    // Largest multiple of `bound` that fits in a u32; draws at or above it are
    // rejected so every index is equally likely.
    let limit = (1u64 << 32) - ((1u64 << 32) % bound);
    let mut b = Zeroizing::new([0u8; 4]);
    loop {
        rng.fill(&mut b[..]);
        let v = u64::from(u32::from_le_bytes(*b));
        if v < limit {
            return usize::try_from(v % bound).unwrap_or(0);
        }
    }
}

/// Title-cases the first character of `word` (ASCII-friendly, Unicode-correct).
fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

/// Generates a Diceware passphrase matching `policy` from the EFF large word list.
///
/// Words are chosen with unbiased rejection sampling. With the 7776-word list
/// each word adds ~12.9 bits of entropy, so the 6-word default is ~77 bits.
///
/// # Errors
/// Returns [`ApplicationError::Domain`] if the policy is unsatisfiable.
pub fn generate_passphrase(
    rng: &dyn SecureRandom,
    policy: &PassphrasePolicy,
) -> Result<PlaintextSecret, ApplicationError> {
    policy.validate().map_err(ApplicationError::Domain)?;

    let list = eff_wordlist::large::LIST; // &[(dice_roll, word)]
    let separator = policy.separator.to_string();

    // If a number is requested, pick which word carries it and which digit.
    let number_word = policy
        .include_number
        .then(|| uniform_index(rng, policy.words));
    let digit = policy
        .include_number
        .then(|| char::from(b'0' + u8::try_from(uniform_index(rng, 10)).unwrap_or(0)));

    let mut words: Vec<String> = Vec::with_capacity(policy.words);
    for i in 0..policy.words {
        let (_, word) = list[uniform_index(rng, list.len())];
        let mut word = if policy.capitalize {
            capitalize(word)
        } else {
            word.to_owned()
        };
        if number_word == Some(i) {
            if let Some(d) = digit {
                word.push(d);
            }
        }
        words.push(word);
    }

    Ok(PlaintextSecret::from(words.join(&separator)))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use super::*;

    /// Deterministic, Send+Sync CSPRNG stand-in that cycles through all byte
    /// values, exercising the rejection path.
    struct CounterRng(AtomicU8);

    impl SecureRandom for CounterRng {
        fn fill(&self, dst: &mut [u8]) {
            for b in dst.iter_mut() {
                *b = self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn rng() -> CounterRng {
        CounterRng(AtomicU8::new(0))
    }

    #[test]
    fn produces_requested_length() {
        let p = PasswordPolicy {
            length: 32,
            ..PasswordPolicy::default()
        };
        let pw = generate_password(&rng(), &p).unwrap();
        assert_eq!(pw.expose().chars().count(), 32);
    }

    #[test]
    fn only_uses_charset_characters() {
        let p = PasswordPolicy {
            length: 64,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        let pw = generate_password(&rng(), &p).unwrap();
        assert!(pw.expose().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn excludes_ambiguous_characters() {
        let p = PasswordPolicy {
            length: 100,
            exclude_ambiguous: true,
            ..PasswordPolicy::default()
        };
        let pw = generate_password(&rng(), &p).unwrap();
        assert!(pw.expose().chars().all(|c| !"Il1O0o".contains(c)));
    }

    #[test]
    fn invalid_policy_errors() {
        let p = PasswordPolicy {
            length: 16,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let err = generate_password(&rng(), &p).unwrap_err();
        assert!(matches!(err, ApplicationError::Domain(_)));
    }

    #[test]
    fn passphrase_has_requested_word_count() {
        let p = PassphrasePolicy {
            words: 5,
            separator: '-',
            capitalize: false,
            include_number: false,
        };
        let pw = generate_passphrase(&rng(), &p).unwrap();
        // EFF words are lowercase a–z, so the separator can't appear inside one.
        assert_eq!(pw.expose().split('-').count(), 5);
    }

    #[test]
    fn passphrase_capitalizes_each_word() {
        let p = PassphrasePolicy {
            words: 4,
            separator: '.',
            capitalize: true,
            include_number: false,
        };
        let pw = generate_passphrase(&rng(), &p).unwrap();
        for word in pw.expose().split('.') {
            assert!(word.chars().next().unwrap().is_uppercase());
        }
    }

    #[test]
    fn passphrase_includes_a_digit_when_requested() {
        let p = PassphrasePolicy {
            words: 4,
            separator: '-',
            capitalize: false,
            include_number: true,
        };
        let pw = generate_passphrase(&rng(), &p).unwrap();
        assert!(pw.expose().chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn passphrase_invalid_policy_errors() {
        let p = PassphrasePolicy {
            words: 0,
            ..PassphrasePolicy::default()
        };
        let err = generate_passphrase(&rng(), &p).unwrap_err();
        assert!(matches!(err, ApplicationError::Domain(_)));
    }
}
