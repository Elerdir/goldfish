//! Application layer — use cases orchestrate the domain through ports.
//!
//! This crate exposes [`VaultService`] (the use-case surface) and the ports it
//! depends on. It uses [`goldfish_crypto`] directly (cryptography is a
//! foundational leaf, never mocked) and abstracts only I/O behind ports.
//!
//! Concrete port adapters (SQLite/SQLCipher, OS keystore) live in
//! `goldfish-infrastructure`; the Tauri layer wires them together.

pub mod error;
pub mod export;
pub mod generator;
pub mod health;
pub mod hibp;
pub mod import;
pub mod kdf;
pub mod ports;
pub mod service;
pub mod session;
pub mod strength;
pub mod throttle;
pub mod totp;
pub mod use_cases;

pub use error::ApplicationError;
pub use export::{EncryptedExport, ExportBundle, ExportEntry};
pub use generator::{generate_passphrase, generate_password};
pub use health::{HealthItem, HealthReport, ReusedGroup};
pub use hibp::{check_pwned, check_pwned_hash, BreachItem, BreachTarget};
pub use import::{parse_import, ImportFormat};
pub use kdf::calibrate_kdf;
pub use ports::{
    BackupInfo, Clock, EntryRepository, OsKeyStore, PwnedRangeSource, SecureRandom,
    VaultMetadataRepository, VaultStore,
};
pub use service::VaultService;
pub use session::VaultSession;
pub use strength::estimate_strength;
pub use throttle::UnlockThrottle;
pub use totp::{generate_totp, validate_totp, TotpCode};
