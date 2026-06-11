//! Goldfish domain layer.
//!
//! Pure types and invariants — **no I/O, no async, no infrastructure**. This crate
//! is the only one with full freedom to change its dependencies; everyone else
//! pulls from here. Per the architecture rule, this crate must **never** depend
//! on `tauri`, `rusqlite`, `reqwest`, or any side-effectful library.

pub mod entry;
pub mod error;
pub mod folder;
pub mod generator;
pub mod password;
pub mod record;
pub mod tag;
pub mod vault;

pub use entry::{
    CustomField, Entry, EntryDraft, EntryId, EntryKind, PasswordHistoryEntry, MAX_CUSTOM_FIELDS,
    MAX_DESCRIPTION, MAX_FIELD_LABEL, MAX_TITLE, MAX_URL, MAX_USERNAME,
};
pub use error::DomainError;
pub use folder::{Appearance, Folder, MAX_FOLDER_NAME};
pub use generator::{PassphrasePolicy, PasswordPolicy};
pub use password::PlaintextSecret;
pub use record::{
    AttachmentMeta, EntrySummary, SealedAttachment, SealedEntry, SealedField,
    SealedPasswordHistory, MAX_ATTACHMENT_SIZE,
};
pub use tag::{Tag, MAX_TAG_NAME};
pub use vault::{BiometricWrap, KdfParams, RecoveryWrap, VaultMetadata};
