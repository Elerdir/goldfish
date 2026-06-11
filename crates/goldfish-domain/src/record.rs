//! At-rest (encrypted) projections of [`crate::Entry`].
//!
//! The repository persists and loads these — it never sees plaintext. The
//! application layer maps between [`crate::Entry`] (decrypted, in-memory) and
//! [`SealedEntry`] (encrypted, on-disk) using the vault keyset.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{EntryId, EntryKind};

/// One encrypted field: a nonce plus ciphertext (the AEAD tag is appended to
/// the ciphertext). Just bytes — no crypto logic lives in the domain.
#[derive(Debug, Clone)]
pub struct SealedField {
    /// AEAD nonce used to seal this field.
    pub nonce: Vec<u8>,
    /// Ciphertext with the appended authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Encrypted at-rest representation of an [`crate::Entry`].
///
/// Plaintext-searchable metadata (`title`, `url`, …) is stored in the clear so
/// the UI can list and search without unlocking; the credential fields are
/// sealed.
#[derive(Debug, Clone)]
pub struct SealedEntry {
    /// Stable identifier.
    pub id: EntryId,
    /// Entry kind (plaintext metadata).
    pub kind: EntryKind,
    /// Plaintext title.
    pub title: String,
    /// Plaintext description.
    pub description: Option<String>,
    /// Plaintext URL.
    pub url: Option<String>,
    /// Plaintext application name.
    pub app_name: Option<String>,
    /// Optional folder grouping.
    pub folder_id: Option<Uuid>,
    /// Favorite flag.
    pub favorite: bool,
    /// Optimistic-lock version, also bound into each field's AAD.
    pub version: u32,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp.
    pub updated_at: DateTime<Utc>,
    /// Sealed username.
    pub username: SealedField,
    /// Sealed password.
    pub password: SealedField,
    /// Sealed notes, if present.
    pub notes: Option<SealedField>,
    /// Sealed TOTP secret, if present.
    pub totp_secret: Option<SealedField>,
    /// Sealed JSON blob of the entry's custom fields (labels included), if any.
    pub custom: Option<SealedField>,
    /// Ids of tags applied to this entry (plaintext metadata, many-to-many).
    pub tags: Vec<Uuid>,
}

/// Maximum size of a single attachment's plaintext, in bytes (10 MiB). Larger
/// files are rejected — the vault is for secrets, not bulk storage.
pub const MAX_ATTACHMENT_SIZE: usize = 10 * 1024 * 1024;

/// Plaintext metadata for one attachment (no file bytes) — enough to list
/// attachments without decrypting them.
#[derive(Debug, Clone)]
pub struct AttachmentMeta {
    /// Stable identifier (UUID v7).
    pub id: Uuid,
    /// Original file name.
    pub name: String,
    /// Plaintext size in bytes.
    pub size: u64,
}

/// An attachment with its file bytes sealed. The `name`/`size` are plaintext
/// metadata (like an entry's title); only the contents are encrypted.
#[derive(Debug, Clone)]
pub struct SealedAttachment {
    /// Stable identifier (UUID v7, bound into the blob's AAD).
    pub id: Uuid,
    /// The entry this attachment belongs to.
    pub entry_id: EntryId,
    /// Original file name.
    pub name: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// The sealed file bytes.
    pub blob: SealedField,
}

/// Encrypted past-password snapshot for an entry, persisted in its own table.
/// Recorded whenever an entry's password changes.
#[derive(Debug, Clone)]
pub struct SealedPasswordHistory {
    /// Stable identifier of this history row (UUID v7, also bound into its AAD).
    pub id: Uuid,
    /// The entry this snapshot belongs to.
    pub entry_id: EntryId,
    /// The sealed previous password.
    pub password: SealedField,
    /// When the password was replaced.
    pub changed_at: DateTime<Utc>,
}

/// Plaintext-only projection for list views — carries no secrets and needs no
/// decryption, so the list can render while the vault is locked.
#[derive(Debug, Clone)]
pub struct EntrySummary {
    /// Stable identifier.
    pub id: EntryId,
    /// Entry kind (for the list icon).
    pub kind: EntryKind,
    /// Plaintext title.
    pub title: String,
    /// Plaintext URL.
    pub url: Option<String>,
    /// Plaintext application name.
    pub app_name: Option<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Optional folder grouping.
    pub folder_id: Option<Uuid>,
    /// Ids of tags applied to this entry (for chips / filtering).
    pub tags: Vec<Uuid>,
    /// Last modification timestamp (for sorting).
    pub updated_at: DateTime<Utc>,
}
