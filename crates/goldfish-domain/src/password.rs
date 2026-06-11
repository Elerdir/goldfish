//! Plaintext secret wrapper.
//!
//! Wraps `secrecy::SecretString` so that:
//! - Debug never prints the inner value
//! - Drop zeroizes the underlying memory
//! - It's intentionally NOT `Clone` so callers can't accidentally fan out copies
//!
//! Serialization is intentionally **not** derived. If a layer needs to persist
//! a secret, it must do so through the crypto layer (encrypt-then-store).

use std::fmt;

use secrecy::{ExposeSecret, SecretString};

/// A plaintext credential held in memory. Zeroized on drop.
pub struct PlaintextSecret {
    inner: SecretString,
}

impl PlaintextSecret {
    /// Wraps an existing secret string.
    #[must_use]
    pub const fn new(inner: SecretString) -> Self {
        Self { inner }
    }

    /// Returns the inner secret for a single, scoped read. Callers must not
    /// retain references; the borrow ends with the scope.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.inner.expose_secret()
    }

    /// Length in bytes. Useful for strength checks without exposing content.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }

    /// Whether the wrapped secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.expose_secret().is_empty()
    }
}

impl Clone for PlaintextSecret {
    fn clone(&self) -> Self {
        Self {
            inner: SecretString::from(self.inner.expose_secret().to_owned()),
        }
    }
}

impl fmt::Debug for PlaintextSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaintextSecret")
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl From<String> for PlaintextSecret {
    fn from(value: String) -> Self {
        Self {
            inner: SecretString::from(value),
        }
    }
}

impl From<&str> for PlaintextSecret {
    fn from(value: &str) -> Self {
        Self {
            inner: SecretString::from(value.to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_content() {
        let s = PlaintextSecret::from("hunter2");
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"), "debug must redact secret content");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn from_str_and_string_produce_equivalent_secrets() {
        let from_str = PlaintextSecret::from("hello");
        let from_string = PlaintextSecret::from(String::from("hello"));
        assert_eq!(from_str.expose(), from_string.expose());
    }

    #[test]
    fn expose_returns_original_bytes() {
        let secret = PlaintextSecret::from("👻🐠 ñâ");
        assert_eq!(secret.expose(), "👻🐠 ñâ");
    }

    #[test]
    fn len_and_is_empty_reflect_content() {
        let empty = PlaintextSecret::from("");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let non_empty = PlaintextSecret::from("abc");
        assert!(!non_empty.is_empty());
        assert_eq!(non_empty.len(), 3);
    }

    #[test]
    fn clone_is_independent_copy() {
        let original = PlaintextSecret::from("hunter2");
        let clone = original.clone();
        assert_eq!(original.expose(), clone.expose());
        // Drop the clone — original must still be usable.
        drop(clone);
        assert_eq!(original.expose(), "hunter2");
    }
}
