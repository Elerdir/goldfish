//! Tags are free-form labels attached to entries (many-to-many), complementary
//! to folders (which are one-to-many). Tag names are plaintext metadata shown in
//! the UI — never secret.

use uuid::Uuid;

use crate::DomainError;

/// Maximum length of a tag name, in Unicode scalar values.
pub const MAX_TAG_NAME: usize = 50;

/// A named label that can be applied to many entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// Stable identifier (UUID v7).
    pub id: Uuid,
    /// Display name (trimmed, non-empty, ≤ [`MAX_TAG_NAME`] chars).
    pub name: String,
}

impl Tag {
    /// Creates a tag with a fresh id, validating the name.
    ///
    /// # Errors
    /// [`DomainError::EmptyField`] if blank; [`DomainError::FieldTooLong`] if the
    /// name exceeds [`MAX_TAG_NAME`].
    pub fn new(name: &str) -> Result<Self, DomainError> {
        Ok(Self {
            id: Uuid::now_v7(),
            name: Self::validate_name(name)?,
        })
    }

    /// Validates and normalizes a tag name (trim + length checks).
    ///
    /// # Errors
    /// As [`Tag::new`].
    pub fn validate_name(name: &str) -> Result<String, DomainError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(DomainError::EmptyField { field: "tag name" });
        }
        if name.chars().count() > MAX_TAG_NAME {
            return Err(DomainError::FieldTooLong {
                field: "tag name",
                max: MAX_TAG_NAME,
            });
        }
        Ok(name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trims_and_accepts_valid_name() {
        assert_eq!(Tag::new("  work  ").unwrap().name, "work");
    }

    #[test]
    fn new_rejects_blank() {
        assert!(matches!(
            Tag::new("  "),
            Err(DomainError::EmptyField { field: "tag name" })
        ));
    }

    #[test]
    fn new_rejects_too_long() {
        let long = "x".repeat(MAX_TAG_NAME + 1);
        assert!(matches!(
            Tag::new(&long),
            Err(DomainError::FieldTooLong {
                field: "tag name",
                ..
            })
        ));
    }
}
