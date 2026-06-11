//! Domain-level errors. Pure value type — no I/O context leaks across the boundary.

use thiserror::Error;

/// Errors raised by domain invariants.
///
/// Wrapping `InfrastructureError` / `CryptoError` is intentionally not done here:
/// upper layers translate those to domain errors at their boundary so the domain
/// stays I/O-free.
#[derive(Debug, Error)]
pub enum DomainError {
    /// A required field was empty or only whitespace.
    #[error("field `{field}` must not be empty")]
    EmptyField {
        /// Field name (e.g. `title`).
        field: &'static str,
    },

    /// A field exceeded its maximum allowed length.
    #[error("field `{field}` exceeds maximum length of {max} characters")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Maximum allowed length (inclusive).
        max: usize,
    },

    /// Master-password complexity policy violation.
    #[error("master password does not meet complexity requirements: {reason}")]
    WeakMasterPassword {
        /// Human-readable reason. Never include the password itself.
        reason: String,
    },

    /// A password-generator policy is unsatisfiable (e.g. no character set).
    #[error("invalid password policy: {reason}")]
    InvalidPolicy {
        /// Static reason describing why the policy is invalid.
        reason: &'static str,
    },

    /// A field held a structurally invalid value (e.g. a non-hex color).
    #[error("field `{field}` is invalid: {reason}")]
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Static reason describing why the value is invalid.
        reason: &'static str,
    },
}
