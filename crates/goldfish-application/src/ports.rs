//! Ports — traits the application depends on. Adapters implement these.
//!
//! Ports abstract **I/O and side effects** (persistence, OS keystore, clock).
//! Cryptography is deliberately *not* a port: it has a single audited
//! implementation ([`goldfish_crypto`]) and must never be mocked, so the
//! application depends on it directly.

use async_trait::async_trait;
use goldfish_domain::{
    Appearance, AttachmentMeta, EntryId, EntrySummary, Folder, SealedAttachment, SealedEntry,
    SealedPasswordHistory, Tag, VaultMetadata,
};
use uuid::Uuid;

use crate::ApplicationError;

/// Persistence for vault entries. Operates exclusively on the **encrypted**
/// [`SealedEntry`] — the repository never sees plaintext.
#[async_trait]
pub trait EntryRepository: Send + Sync {
    /// Inserts a new sealed entry.
    async fn insert(&self, entry: &SealedEntry) -> Result<(), ApplicationError>;

    /// Updates an existing entry with optimistic locking.
    ///
    /// `entry.version` is the **new** version. The implementation must update
    /// the row only if its stored version equals `entry.version - 1`, returning
    /// [`ApplicationError::VersionConflict`] otherwise and
    /// [`ApplicationError::EntryNotFound`] if no such row exists.
    async fn update(&self, entry: &SealedEntry) -> Result<(), ApplicationError>;

    /// Loads a single sealed entry by id, or `None` if absent.
    async fn get(&self, id: EntryId) -> Result<Option<SealedEntry>, ApplicationError>;

    /// Lists plaintext summaries (no secrets), optionally filtered by folder.
    async fn list_summaries(
        &self,
        folder_id: Option<Uuid>,
    ) -> Result<Vec<EntrySummary>, ApplicationError>;

    /// Deletes an entry by id. Idempotent — deleting a missing entry is `Ok`.
    async fn delete(&self, id: EntryId) -> Result<(), ApplicationError>;

    /// Appends a sealed previous-password snapshot for an entry.
    async fn add_password_history(
        &self,
        record: &SealedPasswordHistory,
    ) -> Result<(), ApplicationError>;

    /// Lists an entry's sealed password history, newest first.
    async fn list_password_history(
        &self,
        entry_id: EntryId,
    ) -> Result<Vec<SealedPasswordHistory>, ApplicationError>;

    /// Inserts a folder.
    async fn create_folder(&self, folder: &Folder) -> Result<(), ApplicationError>;

    /// Lists all folders, ordered by name.
    async fn list_folders(&self) -> Result<Vec<Folder>, ApplicationError>;

    /// Renames a folder.
    async fn rename_folder(&self, id: Uuid, name: &str) -> Result<(), ApplicationError>;

    /// Replaces a folder's appearance overrides.
    async fn set_folder_appearance(
        &self,
        id: Uuid,
        appearance: &Appearance,
    ) -> Result<(), ApplicationError>;

    /// Deletes a folder and unassigns it from any entries (their `folder_id`
    /// becomes `NULL`); the entries themselves are kept.
    async fn delete_folder(&self, id: Uuid) -> Result<(), ApplicationError>;

    /// Persists a manual ordering for one view. `folder_id` selects the view:
    /// `None` is the "all entries" ordering, `Some(id)` a folder's. `ids` is the
    /// full ordered list of entry ids for that view; each entry's stored position
    /// becomes its index. The two orderings are independent.
    async fn reorder_entries(
        &self,
        folder_id: Option<Uuid>,
        ids: &[EntryId],
    ) -> Result<(), ApplicationError>;

    /// Moves an entry into `folder_id` (`None` = unfiled), appending it to the
    /// end of that folder's ordering. The all-entries ordering is unchanged.
    async fn move_entry_to_folder(
        &self,
        id: EntryId,
        folder_id: Option<Uuid>,
    ) -> Result<(), ApplicationError>;

    /// Inserts a tag.
    async fn create_tag(&self, tag: &Tag) -> Result<(), ApplicationError>;

    /// Lists all tags, ordered by name.
    async fn list_tags(&self) -> Result<Vec<Tag>, ApplicationError>;

    /// Renames a tag.
    async fn rename_tag(&self, id: Uuid, name: &str) -> Result<(), ApplicationError>;

    /// Deletes a tag and removes it from every entry it was applied to.
    async fn delete_tag(&self, id: Uuid) -> Result<(), ApplicationError>;

    /// Stores a sealed attachment.
    async fn add_attachment(&self, attachment: &SealedAttachment) -> Result<(), ApplicationError>;

    /// Lists an entry's attachment metadata (no file bytes), oldest first.
    async fn list_attachments(
        &self,
        entry_id: EntryId,
    ) -> Result<Vec<AttachmentMeta>, ApplicationError>;

    /// Loads a single sealed attachment by id, or `None` if absent.
    async fn get_attachment(&self, id: Uuid) -> Result<Option<SealedAttachment>, ApplicationError>;

    /// Deletes an attachment by id. Idempotent.
    async fn delete_attachment(&self, id: Uuid) -> Result<(), ApplicationError>;
}

/// Metadata about one rolling backup snapshot (an encrypted copy of the vault
/// database file). Carries no secret material.
#[derive(Debug, Clone)]
pub struct BackupInfo {
    /// File name of the snapshot (e.g. `vault-20260605-101500.db`). Opaque id used
    /// to request a restore; never a path.
    pub file_name: String,
    /// Last-modified time, Unix milliseconds.
    pub created_at_ms: i64,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// Lifecycle for the encrypted entry store.
///
/// Kept separate from data operations per the interface-segregation principle.
/// The single concrete adapter (`SqliteEntryStore`) implements both this and
/// [`EntryRepository`].
#[async_trait]
pub trait VaultStore: Send + Sync {
    /// Opens (or creates) the encrypted store with the given 32-byte database
    /// key, applying it and running pending migrations. Idempotent.
    async fn open(&self, db_key: &[u8; 32]) -> Result<(), ApplicationError>;

    /// Closes the store, dropping all connections and the in-memory key.
    async fn close(&self) -> Result<(), ApplicationError>;

    /// Whether the store is currently open (unlocked).
    async fn is_open(&self) -> bool;

    /// Lists the available rolling backup snapshots, newest first.
    async fn list_backups(&self) -> Result<Vec<BackupInfo>, ApplicationError>;

    /// Restores the vault database from the named snapshot, replacing the live
    /// file. The store must be closed first. The current database is itself
    /// snapshotted beforehand, so a restore is reversible. `file_name` must be one
    /// of the names returned by [`Self::list_backups`].
    async fn restore_backup(&self, file_name: &str) -> Result<(), ApplicationError>;
}

/// Persistence for vault-level metadata (single row).
#[async_trait]
pub trait VaultMetadataRepository: Send + Sync {
    /// Loads metadata. `None` if the vault has never been initialized.
    async fn load(&self) -> Result<Option<VaultMetadata>, ApplicationError>;

    /// Replaces the metadata row (used on init and on master-password change).
    async fn save(&self, meta: &VaultMetadata) -> Result<(), ApplicationError>;
}

/// OS-backed credential store used for biometric / "remember me" unlock.
///
/// Implementations: Windows Credential Manager + Windows Hello, macOS Keychain
/// + Touch ID, Linux libsecret (+ optional fprintd). Lands in Phase 9.
#[async_trait]
pub trait OsKeyStore: Send + Sync {
    /// Whether the platform has a biometric capability we can use.
    fn biometrics_available(&self) -> bool;

    /// Stores a blob under a stable label, gated by biometric auth on retrieval.
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), ApplicationError>;

    /// Retrieves a stored blob. Triggers biometric prompt on supporting platforms.
    async fn retrieve(&self, label: &str) -> Result<Vec<u8>, ApplicationError>;

    /// Removes a stored blob.
    async fn delete(&self, label: &str) -> Result<(), ApplicationError>;
}

/// Clock abstraction — lets tests freeze time.
pub trait Clock: Send + Sync {
    /// Current UTC time.
    fn now(&self) -> chrono::DateTime<chrono::Utc>;
}

/// Cryptographically secure random source abstraction (for password generation
/// in later phases; crypto self-sources entropy for keys/nonces).
pub trait SecureRandom: Send + Sync {
    /// Fills `dst` with cryptographically secure random bytes.
    fn fill(&self, dst: &mut [u8]);
}

/// Source of a Pwned-Passwords range response (HIBP k-anonymity). Abstracted so
/// the HTTP client can be mocked in tests.
#[async_trait]
pub trait PwnedRangeSource: Send + Sync {
    /// Fetches the range body for a 5-hex-char SHA-1 prefix. The body is lines of
    /// `SUFFIX:COUNT`. Only the prefix — never the password or full hash — is
    /// sent over the network.
    async fn fetch_range(&self, prefix: &str) -> Result<String, ApplicationError>;
}
