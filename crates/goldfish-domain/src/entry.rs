//! Password vault entries — the core domain object.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DomainError, PlaintextSecret};

/// Opaque, K-sortable identifier of an entry (UUID v7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryId(pub Uuid);

impl EntryId {
    /// Creates a fresh time-ordered identifier.
    ///
    /// UUID v7 embeds a millisecond timestamp + random tail — collision-resistant
    /// and naturally sorts by creation time, which makes pagination cheap.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for EntryId {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum length of the `title` field, in Unicode scalar values.
pub const MAX_TITLE: usize = 200;
/// Maximum length of the `description` field.
pub const MAX_DESCRIPTION: usize = 2_000;
/// Maximum length of the `url` field.
pub const MAX_URL: usize = 2_048;
/// Maximum length of the `username` field.
pub const MAX_USERNAME: usize = 500;
/// Maximum length of a custom-field label.
pub const MAX_FIELD_LABEL: usize = 200;
/// Maximum number of custom fields per entry.
pub const MAX_CUSTOM_FIELDS: usize = 64;

/// What kind of secret an entry holds. Drives the UI (icon, default fields) and
/// which health checks apply; stored as plaintext metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EntryKind {
    /// Website / app login (the default — username + password + URL + TOTP).
    #[default]
    Login,
    /// Free-form secure note.
    SecureNote,
    /// Payment card.
    Card,
    /// SSH key (private/public/passphrase live in custom fields).
    SshKey,
    /// API token / key.
    ApiToken,
}

impl EntryKind {
    /// Stable lower-case identifier used in storage and at the IPC boundary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::SecureNote => "note",
            Self::Card => "card",
            Self::SshKey => "ssh",
            Self::ApiToken => "token",
        }
    }

    /// Parses an identifier, falling back to [`EntryKind::Login`] for unknown or
    /// legacy values (so older rows decode cleanly).
    #[must_use]
    pub fn from_id(id: &str) -> Self {
        match id {
            "note" => Self::SecureNote,
            "card" => Self::Card,
            "ssh" => Self::SshKey,
            "token" => Self::ApiToken,
            _ => Self::Login,
        }
    }
}

/// A user-defined extra field on an entry. The label is metadata; the value is a
/// secret (sealed at rest like any credential). `hidden` only controls UI masking.
#[derive(Debug, Clone)]
pub struct CustomField {
    /// Field label (e.g. "Card number"). Sealed at rest along with the value.
    pub label: String,
    /// Field value (plaintext in memory; encrypted at rest).
    pub value: PlaintextSecret,
    /// Whether the UI should mask the value by default (reveal on demand).
    pub hidden: bool,
}

/// A vault entry as the user sees it. **Plaintext only inside this struct** —
/// it must never be serialized to disk; the application layer encrypts on save
/// and decrypts on load.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Stable identifier.
    pub id: EntryId,
    /// What kind of secret this is (login, note, card, …).
    pub kind: EntryKind,
    /// Human-readable title (e.g. "GitHub").
    pub title: String,
    /// Optional free-form description.
    pub description: Option<String>,
    /// Web URL associated with the credential, if any.
    pub url: Option<String>,
    /// Application name (for non-web credentials like SSH).
    pub app_name: Option<String>,
    /// Username / login identifier (plaintext in memory; encrypted at rest).
    pub username: String,
    /// Password (plaintext in memory; encrypted at rest).
    pub password: PlaintextSecret,
    /// Free-form notes (plaintext in memory; encrypted at rest).
    pub notes: Option<PlaintextSecret>,
    /// Base32-encoded TOTP secret if 2FA is configured.
    pub totp_secret: Option<PlaintextSecret>,
    /// Optional folder grouping.
    pub folder_id: Option<Uuid>,
    /// User flag.
    pub favorite: bool,
    /// User-defined extra fields (sealed at rest).
    pub custom_fields: Vec<CustomField>,
    /// Ids of tags applied to this entry (plaintext metadata, many-to-many).
    pub tags: Vec<Uuid>,
    /// Optimistic-lock version, also used as AAD for AEAD.
    pub version: u32,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp.
    pub updated_at: DateTime<Utc>,
}

/// A decrypted past password together with the time it was replaced. Returned
/// by the password-history use case for display in the entry detail view.
#[derive(Debug, Clone)]
pub struct PasswordHistoryEntry {
    /// When this password was replaced by a newer one.
    pub changed_at: DateTime<Utc>,
    /// The previous password (plaintext in memory; sealed at rest).
    pub password: PlaintextSecret,
}

/// Validated input for creating a new entry. Construct via [`EntryDraft::new`]
/// to enforce invariants; the application layer then assigns id/timestamps.
#[derive(Debug, Clone)]
pub struct EntryDraft {
    /// What kind of secret this is. Defaults to [`EntryKind::Login`].
    pub kind: EntryKind,
    /// Human-readable title (e.g. "GitHub"). Required, ≤ [`MAX_TITLE`] chars.
    pub title: String,
    /// Optional free-form description, ≤ [`MAX_DESCRIPTION`] chars.
    pub description: Option<String>,
    /// Optional web URL, ≤ [`MAX_URL`] chars. Format validation is the UI's job.
    pub url: Option<String>,
    /// Optional application name for non-web credentials (SSH, RDP, …).
    pub app_name: Option<String>,
    /// Username / login identifier, ≤ [`MAX_USERNAME`] chars.
    pub username: String,
    /// Password (kept in memory as [`PlaintextSecret`]; encrypted on save).
    pub password: PlaintextSecret,
    /// Optional free-form notes (encrypted on save).
    pub notes: Option<PlaintextSecret>,
    /// Optional Base32-encoded TOTP shared secret (encrypted on save).
    pub totp_secret: Option<PlaintextSecret>,
    /// Optional folder grouping.
    pub folder_id: Option<Uuid>,
    /// Whether the user has flagged this entry as favorite.
    pub favorite: bool,
    /// User-defined extra fields (sealed on save).
    pub custom_fields: Vec<CustomField>,
    /// Ids of tags to apply (plaintext metadata, many-to-many).
    pub tags: Vec<Uuid>,
}

impl EntryDraft {
    /// Validates and constructs a draft.
    ///
    /// # Errors
    /// Returns [`DomainError::EmptyField`] / [`DomainError::FieldTooLong`] if
    /// invariants are violated.
    pub fn new(
        title: &str,
        username: &str,
        password: PlaintextSecret,
    ) -> Result<Self, DomainError> {
        let title = title.trim();
        if title.is_empty() {
            return Err(DomainError::EmptyField { field: "title" });
        }
        if title.chars().count() > MAX_TITLE {
            return Err(DomainError::FieldTooLong {
                field: "title",
                max: MAX_TITLE,
            });
        }
        let username = username.trim();
        if username.chars().count() > MAX_USERNAME {
            return Err(DomainError::FieldTooLong {
                field: "username",
                max: MAX_USERNAME,
            });
        }
        Ok(Self {
            kind: EntryKind::Login,
            title: title.to_owned(),
            description: None,
            url: None,
            app_name: None,
            username: username.to_owned(),
            password,
            notes: None,
            totp_secret: None,
            folder_id: None,
            favorite: false,
            custom_fields: Vec::new(),
            tags: Vec::new(),
        })
    }

    /// Attaches an optional description (validated length).
    ///
    /// # Errors
    /// Returns [`DomainError::FieldTooLong`] if the description exceeds
    /// [`MAX_DESCRIPTION`].
    pub fn with_description(mut self, description: Option<String>) -> Result<Self, DomainError> {
        if let Some(d) = description.as_ref() {
            if d.chars().count() > MAX_DESCRIPTION {
                return Err(DomainError::FieldTooLong {
                    field: "description",
                    max: MAX_DESCRIPTION,
                });
            }
        }
        self.description = description;
        Ok(self)
    }

    /// Attaches an optional URL (validated length; format validation is the UI's job).
    ///
    /// # Errors
    /// Returns [`DomainError::FieldTooLong`] if the URL exceeds [`MAX_URL`].
    pub fn with_url(mut self, url: Option<String>) -> Result<Self, DomainError> {
        if let Some(u) = url.as_ref() {
            if u.chars().count() > MAX_URL {
                return Err(DomainError::FieldTooLong {
                    field: "url",
                    max: MAX_URL,
                });
            }
        }
        self.url = url;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn secret(s: &str) -> PlaintextSecret {
        PlaintextSecret::new(SecretString::from(s.to_owned()))
    }

    // --- EntryId --------------------------------------------------------------

    #[test]
    fn entry_id_is_time_ordered() {
        let a = EntryId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = EntryId::new();
        assert!(a.0 < b.0, "UUID v7 must be monotonic across time");
    }

    #[test]
    fn entry_id_default_is_fresh_id() {
        let a = EntryId::default();
        let b = EntryId::default();
        assert_ne!(a, b, "two defaults must not collide");
    }

    // --- EntryDraft::new (positive path) --------------------------------------

    #[test]
    fn draft_minimum_valid_inputs_succeed() {
        let d = EntryDraft::new("GitHub", "octocat", secret("p")).unwrap();
        assert_eq!(d.title, "GitHub");
        assert_eq!(d.username, "octocat");
        assert!(d.description.is_none());
        assert!(d.url.is_none());
        assert!(d.app_name.is_none());
        assert!(d.notes.is_none());
        assert!(d.totp_secret.is_none());
        assert!(d.folder_id.is_none());
        assert!(!d.favorite);
    }

    #[test]
    fn draft_trims_whitespace_from_title_and_username() {
        let d = EntryDraft::new("  GitHub \n", "\t octocat  ", secret("p")).unwrap();
        assert_eq!(d.title, "GitHub");
        assert_eq!(d.username, "octocat");
    }

    #[test]
    fn draft_accepts_title_at_max_length() {
        let title: String = "a".repeat(MAX_TITLE);
        let d = EntryDraft::new(&title, "u", secret("p")).unwrap();
        assert_eq!(d.title.chars().count(), MAX_TITLE);
    }

    #[test]
    fn draft_accepts_unicode_title() {
        let d = EntryDraft::new("🐠 Goldfish — můj účet", "u", secret("p")).unwrap();
        assert_eq!(d.title, "🐠 Goldfish — můj účet");
    }

    // --- EntryDraft::new (negative path) --------------------------------------

    #[test]
    fn draft_rejects_empty_title() {
        let err = EntryDraft::new("   ", "u", secret("p")).unwrap_err();
        assert!(matches!(err, DomainError::EmptyField { field: "title" }));
    }

    #[test]
    fn draft_rejects_pure_tab_title_as_empty() {
        let err = EntryDraft::new("\t\n\r", "u", secret("p")).unwrap_err();
        assert!(matches!(err, DomainError::EmptyField { field: "title" }));
    }

    #[test]
    fn draft_rejects_title_one_over_max() {
        let long = "a".repeat(MAX_TITLE + 1);
        let err = EntryDraft::new(&long, "u", secret("p")).unwrap_err();
        assert!(matches!(
            err,
            DomainError::FieldTooLong { field: "title", max } if max == MAX_TITLE
        ));
    }

    #[test]
    fn draft_rejects_username_too_long() {
        let long = "u".repeat(MAX_USERNAME + 1);
        let err = EntryDraft::new("title", &long, secret("p")).unwrap_err();
        assert!(matches!(
            err,
            DomainError::FieldTooLong { field: "username", max } if max == MAX_USERNAME
        ));
    }

    // --- EntryDraft::with_description ----------------------------------------

    #[test]
    fn with_description_none_preserves_none() {
        let d = EntryDraft::new("t", "u", secret("p"))
            .unwrap()
            .with_description(None)
            .unwrap();
        assert!(d.description.is_none());
    }

    #[test]
    fn with_description_short_accepted() {
        let d = EntryDraft::new("t", "u", secret("p"))
            .unwrap()
            .with_description(Some("a note".to_owned()))
            .unwrap();
        assert_eq!(d.description.as_deref(), Some("a note"));
    }

    #[test]
    fn with_description_at_max_accepted() {
        let body = "x".repeat(MAX_DESCRIPTION);
        let d = EntryDraft::new("t", "u", secret("p"))
            .unwrap()
            .with_description(Some(body.clone()))
            .unwrap();
        assert_eq!(d.description.as_ref().map(String::len), Some(body.len()));
    }

    #[test]
    fn with_description_over_max_rejected() {
        let body = "x".repeat(MAX_DESCRIPTION + 1);
        let err = EntryDraft::new("t", "u", secret("p"))
            .unwrap()
            .with_description(Some(body))
            .unwrap_err();
        assert!(matches!(
            err,
            DomainError::FieldTooLong {
                field: "description",
                ..
            }
        ));
    }

    // --- EntryDraft::with_url ------------------------------------------------

    #[test]
    fn with_url_short_accepted() {
        let d = EntryDraft::new("t", "u", secret("p"))
            .unwrap()
            .with_url(Some("https://example.com".to_owned()))
            .unwrap();
        assert_eq!(d.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn with_url_over_max_rejected() {
        let body = "https://example.com/".to_owned() + &"a".repeat(MAX_URL);
        let err = EntryDraft::new("t", "u", secret("p"))
            .unwrap()
            .with_url(Some(body))
            .unwrap_err();
        assert!(matches!(
            err,
            DomainError::FieldTooLong { field: "url", .. }
        ));
    }
}
