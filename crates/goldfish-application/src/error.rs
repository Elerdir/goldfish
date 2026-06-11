//! Application-level errors. Boundaries translate adapter errors to these.

use thiserror::Error;

use goldfish_domain::DomainError;

/// Error type returned by use cases.
///
/// The application layer must not leak adapter-specific error types (rusqlite,
/// reqwest, …) — adapters translate at their boundary. This keeps the layer's
/// public surface stable across infrastructure changes.
#[derive(Debug, Error)]
pub enum ApplicationError {
    /// A domain invariant was violated.
    #[error(transparent)]
    Domain(#[from] DomainError),

    /// Vault is locked — caller must unlock first.
    #[error("vault is locked")]
    VaultLocked,

    /// Attempted to create a vault when one already exists.
    #[error("a vault already exists")]
    VaultAlreadyExists,

    /// Master password verification failed.
    #[error("master password is incorrect")]
    InvalidMasterPassword,

    /// Too many failed unlock attempts; the caller must wait before retrying.
    #[error("too many attempts; retry in {retry_after_secs}s")]
    UnlockThrottled {
        /// Seconds the caller must wait before another unlock is allowed.
        retry_after_secs: u64,
    },

    /// Vault file is missing or unreadable.
    #[error("vault not found")]
    VaultNotFound,

    /// Persistence-layer failure (translated from infrastructure).
    #[error("storage error: {0}")]
    Storage(String),

    /// Cryptographic failure (translated from `goldfish-crypto`).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Entry with the requested id was not found.
    #[error("entry not found: {0}")]
    EntryNotFound(uuid::Uuid),

    /// Optimistic-lock conflict on update.
    #[error("entry was modified concurrently (version mismatch)")]
    VersionConflict,

    /// A TOTP/authenticator secret could not be parsed or used.
    #[error("invalid authenticator key: {0}")]
    Totp(String),

    /// Biometric unlock is not available on this device.
    #[error("biometrics are not available on this device")]
    BiometricUnavailable,

    /// Biometric unlock has not been enabled for this vault.
    #[error("biometric unlock is not enabled")]
    BiometricNotEnabled,

    /// Biometric verification failed or was cancelled.
    #[error("biometric verification failed: {0}")]
    BiometricFailed(String),

    /// Recovery-code unlock has not been enabled for this vault.
    #[error("recovery is not enabled")]
    RecoveryNotEnabled,

    /// The recovery code was incorrect (or the material was tampered with —
    /// the two are intentionally indistinguishable).
    #[error("incorrect recovery code")]
    InvalidRecoveryCode,

    /// A network request failed (e.g. the HIBP breach check).
    #[error("network error: {0}")]
    Network(String),

    /// An import file could not be parsed.
    #[error("import failed: {0}")]
    Import(String),

    /// An encrypted export (`.goldfish`) file was malformed or unsupported.
    #[error("export error: {0}")]
    Export(String),

    /// The password for an encrypted export was incorrect (or the file was
    /// corrupted/tampered — the two are intentionally indistinguishable).
    #[error("incorrect export password")]
    InvalidExportPassword,
}
