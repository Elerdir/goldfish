//! Password-generation policy — a pure value type.
//!
//! Describes which characters a generated password may contain. The actual
//! (RNG-driven) generation lives in the application layer; this module only
//! defines and validates the policy and builds the candidate character set.

use serde::{Deserialize, Serialize};

use crate::DomainError;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Symbol set deliberately excludes quotes, backslash, backtick, pipe, slash and
/// whitespace — characters that web forms and shells frequently mishandle.
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:;,.?";
/// Characters that are easy to confuse visually, removed when requested.
const AMBIGUOUS: &str = "Il1O0o";

/// A configurable password-generation policy.
///
/// The character-class toggles are intentionally individual booleans — this is
/// a user-facing options struct, not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Desired length in characters.
    pub length: usize,
    /// Include lowercase letters.
    pub lowercase: bool,
    /// Include uppercase letters.
    pub uppercase: bool,
    /// Include digits.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
    /// Drop visually ambiguous characters (`Il1O0o`).
    pub exclude_ambiguous: bool,
}

impl PasswordPolicy {
    /// Minimum permitted length.
    pub const MIN_LENGTH: usize = 4;
    /// Maximum permitted length.
    pub const MAX_LENGTH: usize = 128;

    /// Builds the candidate character set from the enabled options.
    #[must_use]
    pub fn charset(&self) -> String {
        let mut set = String::new();
        if self.lowercase {
            set.push_str(LOWERCASE);
        }
        if self.uppercase {
            set.push_str(UPPERCASE);
        }
        if self.digits {
            set.push_str(DIGITS);
        }
        if self.symbols {
            set.push_str(SYMBOLS);
        }
        if self.exclude_ambiguous {
            set.retain(|c| !AMBIGUOUS.contains(c));
        }
        set
    }

    /// Validates the policy is satisfiable.
    ///
    /// # Errors
    /// [`DomainError::InvalidPolicy`] if the length is out of range or no
    /// character set is selected.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.length < Self::MIN_LENGTH || self.length > Self::MAX_LENGTH {
            return Err(DomainError::InvalidPolicy {
                reason: "length out of range",
            });
        }
        if self.charset().is_empty() {
            return Err(DomainError::InvalidPolicy {
                reason: "no character set selected",
            });
        }
        Ok(())
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

/// A word-based (Diceware) passphrase policy — easier to type and remember than a
/// random-character password at comparable entropy.
///
/// The word list lives in the application layer (it is data, not a domain
/// invariant); this struct only describes and validates the shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphrasePolicy {
    /// Number of words to draw.
    pub words: usize,
    /// Character placed between words (e.g. `-`).
    pub separator: char,
    /// Title-case each word.
    pub capitalize: bool,
    /// Append a random digit to one word (helps satisfy "must contain a number").
    pub include_number: bool,
}

impl PassphrasePolicy {
    /// Minimum word count (below this the entropy is too low to bother).
    pub const MIN_WORDS: usize = 3;
    /// Maximum word count.
    pub const MAX_WORDS: usize = 12;

    /// Validates the policy is satisfiable.
    ///
    /// # Errors
    /// [`DomainError::InvalidPolicy`] if the word count is out of range or the
    /// separator is a control character.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.words < Self::MIN_WORDS || self.words > Self::MAX_WORDS {
            return Err(DomainError::InvalidPolicy {
                reason: "word count out of range",
            });
        }
        if self.separator.is_control() {
            return Err(DomainError::InvalidPolicy {
                reason: "separator must be a printable character",
            });
        }
        Ok(())
    }
}

impl Default for PassphrasePolicy {
    fn default() -> Self {
        Self {
            words: 6,
            separator: '-',
            capitalize: false,
            include_number: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid_and_uses_all_classes() {
        let p = PasswordPolicy::default();
        assert!(p.validate().is_ok());
        let cs = p.charset();
        assert!(cs.contains('a') && cs.contains('A') && cs.contains('5') && cs.contains('!'));
    }

    #[test]
    fn digits_only_charset() {
        let p = PasswordPolicy {
            length: 10,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert_eq!(p.charset(), DIGITS);
    }

    #[test]
    fn exclude_ambiguous_removes_confusables() {
        let p = PasswordPolicy {
            exclude_ambiguous: true,
            ..PasswordPolicy::default()
        };
        let cs = p.charset();
        for c in AMBIGUOUS.chars() {
            assert!(!cs.contains(c), "ambiguous char {c} must be excluded");
        }
    }

    #[test]
    fn rejects_no_charset() {
        let p = PasswordPolicy {
            length: 16,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(matches!(
            p.validate(),
            Err(DomainError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn rejects_length_out_of_range() {
        let too_short = PasswordPolicy {
            length: 1,
            ..PasswordPolicy::default()
        };
        assert!(too_short.validate().is_err());
        let too_long = PasswordPolicy {
            length: 1000,
            ..PasswordPolicy::default()
        };
        assert!(too_long.validate().is_err());
    }

    #[test]
    fn passphrase_default_is_valid() {
        assert!(PassphrasePolicy::default().validate().is_ok());
    }

    #[test]
    fn passphrase_rejects_word_count_out_of_range() {
        assert!(PassphrasePolicy {
            words: 1,
            ..PassphrasePolicy::default()
        }
        .validate()
        .is_err());
        assert!(PassphrasePolicy {
            words: 99,
            ..PassphrasePolicy::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn passphrase_rejects_control_separator() {
        assert!(PassphrasePolicy {
            separator: '\n',
            ..PassphrasePolicy::default()
        }
        .validate()
        .is_err());
    }
}
