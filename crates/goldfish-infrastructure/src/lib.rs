//! Goldfish infrastructure — concrete adapters.
//!
//! Each adapter implements one or more ports defined in `goldfish-application`.
//! The application/Tauri layer wires them via dependency injection at startup.
//!
//! - [`SqliteEntryStore`] — SQLCipher-backed `EntryRepository` + `VaultStore`.
//! - [`FileVaultMetadataRepository`] — plaintext sidecar `VaultMetadataRepository`.
//! - [`SystemClock`] — wall-clock `Clock`.
//! - [`OsSecureRandom`] — OS CSPRNG `SecureRandom`.
//! - [`KeyringStore`] — OS credential store + Windows Hello `OsKeyStore`.
//! - [`HibpClient`] — HIBP Pwned-Passwords range source.
//!
//! Later phases add: CSV importers (11).

pub mod clock;
pub mod hibp;
pub mod keystore;
pub mod metadata;
pub mod random;
pub mod sqlite;

pub use clock::SystemClock;
pub use hibp::HibpClient;
pub use keystore::KeyringStore;
pub use metadata::FileVaultMetadataRepository;
pub use random::OsSecureRandom;
pub use sqlite::SqliteEntryStore;
