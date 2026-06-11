//! Encrypted-export payload schema and (de)serialization.
//!
//! The portable [`ExportBundle`] is the plaintext document that gets sealed into
//! a `.goldfish` file by [`goldfish_crypto::export`]. It is the symmetric
//! counterpart to [`crate::import`]: export turns the vault into a bundle, import
//! turns a foreign file into [`EntryDraft`]s.
//!
//! ### Why secrets are plain `String` here
//! Domain [`Entry`] keeps credentials in [`PlaintextSecret`] precisely so they
//! can never be serialized by accident. This module is the **one** intentional
//! serialization boundary, so it uses plain strings. The serialized buffer is
//! zeroized by the caller immediately after sealing; on import the deserialized
//! bundle is short-lived and converted straight into zeroizing [`EntryDraft`]s.
//!
//! ### Semantics
//! Ids, versions, timestamps, folder ids and tags are **not** carried (those are
//! vault-local organization): an export is a portable credential bundle, and
//! re-importing creates fresh entries (new id, version 1, current timestamps) —
//! the same contract as [`crate::import`]. **Attachments are** carried (name +
//! bytes) so a backup is a complete copy of the secrets.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use goldfish_domain::{CustomField, Entry, EntryDraft, EntryKind, PlaintextSecret};

use crate::totp::validate_totp;
use crate::ApplicationError;

/// Marker string identifying the JSON payload (independent of the file header).
const PAYLOAD_FORMAT: &str = "goldfish-export";

/// Default `kind` for payloads written before entry kinds existed.
fn default_kind() -> String {
    "login".to_owned()
}

/// Current payload schema version.
const PAYLOAD_VERSION: u32 = 1;

/// Result of an encrypted export: the complete file bytes plus the entry count.
pub struct EncryptedExport {
    /// Full `.goldfish` file bytes (authenticated header + ciphertext).
    pub bytes: Vec<u8>,
    /// Number of entries serialized into the export.
    pub entry_count: usize,
}

/// The plaintext export document, sealed inside a `.goldfish` file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportBundle {
    /// Payload marker — must equal [`PAYLOAD_FORMAT`].
    pub format: String,
    /// Payload schema version.
    pub version: u32,
    /// When the export was produced.
    pub exported_at: DateTime<Utc>,
    /// The exported credentials.
    pub entries: Vec<ExportEntry>,
}

/// One exported custom field (sealed inside the bundle ciphertext).
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportCustomField {
    /// Field label.
    pub label: String,
    /// Field value.
    pub value: String,
    /// UI masking hint.
    #[serde(default)]
    pub hidden: bool,
}

/// One exported attachment (file bytes live inside the bundle ciphertext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportAttachment {
    /// Original file name.
    pub name: String,
    /// Raw file bytes.
    pub data: Vec<u8>,
}

/// One exported credential. Optional fields are omitted when empty to keep the
/// payload compact and human-auditable once decrypted.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportEntry {
    /// Entry kind identifier (`login`, `note`, `card`, `ssh`, `token`).
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Entry title.
    pub title: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Optional application name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    /// Username / login identifier.
    pub username: String,
    /// Password (plaintext within the sealed payload).
    pub password: String,
    /// Optional free-form notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Optional Base32 TOTP secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    /// Favorite flag.
    #[serde(default)]
    pub favorite: bool,
    /// User-defined custom fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_fields: Vec<ExportCustomField>,
    /// Encrypted-at-rest file attachments (carried as plaintext within the
    /// sealed bundle).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<ExportAttachment>,
}

impl ExportEntry {
    fn from_entry(entry: &Entry) -> Self {
        Self {
            kind: entry.kind.as_str().to_owned(),
            title: entry.title.clone(),
            description: entry.description.clone(),
            url: entry.url.clone(),
            app_name: entry.app_name.clone(),
            username: entry.username.clone(),
            password: entry.password.expose().to_owned(),
            notes: entry.notes.as_ref().map(|n| n.expose().to_owned()),
            totp_secret: entry.totp_secret.as_ref().map(|t| t.expose().to_owned()),
            favorite: entry.favorite,
            custom_fields: entry
                .custom_fields
                .iter()
                .map(|f| ExportCustomField {
                    label: f.label.clone(),
                    value: f.value.expose().to_owned(),
                    hidden: f.hidden,
                })
                .collect(),
            // Filled in by the service after it decrypts the entry's attachments.
            attachments: Vec::new(),
        }
    }

    /// Converts to a validated draft, or `None` if the title is invalid (an
    /// unexpected, defensive case for our own format — skip rather than abort).
    /// An invalid TOTP secret is dropped while the rest of the entry is kept.
    fn into_draft(self) -> Option<EntryDraft> {
        let mut draft = EntryDraft::new(
            &self.title,
            &self.username,
            PlaintextSecret::from(self.password),
        )
        .and_then(|d| d.with_description(self.description))
        .and_then(|d| d.with_url(self.url))
        .ok()?;
        draft.kind = EntryKind::from_id(&self.kind);
        draft.app_name = self.app_name;
        draft.notes = self.notes.map(PlaintextSecret::from);
        draft.totp_secret = self
            .totp_secret
            .filter(|t| validate_totp(t).is_ok())
            .map(PlaintextSecret::from);
        draft.favorite = self.favorite;
        draft.custom_fields = self
            .custom_fields
            .into_iter()
            .map(|c| CustomField {
                label: c.label,
                value: PlaintextSecret::from(c.value),
                hidden: c.hidden,
            })
            .collect();
        Some(draft)
    }
}

impl ExportBundle {
    /// Builds a bundle from decrypted entries.
    pub fn from_entries(now: DateTime<Utc>, entries: &[Entry]) -> Self {
        Self {
            format: PAYLOAD_FORMAT.to_owned(),
            version: PAYLOAD_VERSION,
            exported_at: now,
            entries: entries.iter().map(ExportEntry::from_entry).collect(),
        }
    }

    /// Converts the bundle into importable drafts, skipping any entry whose title
    /// fails validation.
    pub fn into_drafts(self) -> Vec<EntryDraft> {
        self.entries
            .into_iter()
            .filter_map(ExportEntry::into_draft)
            .collect()
    }

    /// Like [`Self::into_drafts`] but also returns each entry's attachments, so
    /// the importer can recreate them once the new entry id exists.
    pub fn into_drafts_with_attachments(self) -> Vec<(EntryDraft, Vec<ExportAttachment>)> {
        self.entries
            .into_iter()
            .filter_map(|e| {
                let attachments = e.attachments.clone();
                e.into_draft().map(|draft| (draft, attachments))
            })
            .collect()
    }

    /// Validates the payload marker and version after deserialization.
    fn validate(&self) -> Result<(), ApplicationError> {
        if self.format != PAYLOAD_FORMAT {
            return Err(ApplicationError::Export(
                "not a Goldfish export payload".to_owned(),
            ));
        }
        if self.version > PAYLOAD_VERSION {
            return Err(ApplicationError::Export(format!(
                "unsupported export payload version: {}",
                self.version
            )));
        }
        Ok(())
    }
}

/// Serializes a bundle to JSON bytes (zeroizing — the buffer holds plaintext).
pub(crate) fn serialize_bundle(
    bundle: &ExportBundle,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ApplicationError> {
    let bytes = serde_json::to_vec(bundle).map_err(|e| ApplicationError::Export(e.to_string()))?;
    Ok(zeroize::Zeroizing::new(bytes))
}

/// Deserializes and validates a bundle from JSON bytes.
pub(crate) fn deserialize_bundle(json: &[u8]) -> Result<ExportBundle, ApplicationError> {
    let bundle: ExportBundle =
        serde_json::from_slice(json).map_err(|e| ApplicationError::Export(e.to_string()))?;
    bundle.validate()?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(title: &str, user: &str, pass: &str) -> ExportEntry {
        ExportEntry {
            kind: "login".to_owned(),
            title: title.to_owned(),
            description: None,
            url: None,
            app_name: None,
            username: user.to_owned(),
            password: pass.to_owned(),
            notes: None,
            totp_secret: None,
            favorite: false,
            custom_fields: Vec::new(),
            attachments: Vec::new(),
        }
    }

    fn bundle(entries: Vec<ExportEntry>) -> ExportBundle {
        ExportBundle {
            format: PAYLOAD_FORMAT.to_owned(),
            version: PAYLOAD_VERSION,
            exported_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            entries,
        }
    }

    #[test]
    fn serialize_then_deserialize_round_trips() {
        let mut e = entry("GitHub", "octocat", "hunter2");
        e.url = Some("https://github.com".to_owned());
        e.favorite = true;
        let json = serialize_bundle(&bundle(vec![e])).unwrap();
        let back = deserialize_bundle(&json).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].title, "GitHub");
        assert_eq!(back.entries[0].password, "hunter2");
        assert_eq!(back.entries[0].url.as_deref(), Some("https://github.com"));
        assert!(back.entries[0].favorite);
    }

    #[test]
    fn into_drafts_preserves_fields() {
        let mut e = entry("Mail", "alice", "s3cret");
        e.notes = Some("a note".to_owned());
        let drafts = bundle(vec![e]).into_drafts();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].title, "Mail");
        assert_eq!(drafts[0].username, "alice");
        assert_eq!(drafts[0].password.expose(), "s3cret");
        assert_eq!(
            drafts[0]
                .notes
                .as_ref()
                .map(|n| n.expose().to_owned())
                .as_deref(),
            Some("a note")
        );
    }

    #[test]
    fn into_drafts_drops_invalid_totp_but_keeps_entry() {
        let mut e = entry("X", "u", "p");
        e.totp_secret = Some("not-base32!!!".to_owned());
        let drafts = bundle(vec![e]).into_drafts();
        assert_eq!(drafts.len(), 1);
        assert!(drafts[0].totp_secret.is_none());
    }

    #[test]
    fn into_drafts_skips_invalid_title() {
        let drafts = bundle(vec![entry("   ", "u", "p")]).into_drafts();
        assert!(drafts.is_empty());
    }

    #[test]
    fn deserialize_rejects_foreign_payload() {
        let json = br#"{"format":"something-else","version":1,"exported_at":"2023-11-14T22:13:20Z","entries":[]}"#;
        assert!(matches!(
            deserialize_bundle(json),
            Err(ApplicationError::Export(_))
        ));
    }

    #[test]
    fn deserialize_rejects_future_version() {
        let json = br#"{"format":"goldfish-export","version":999,"exported_at":"2023-11-14T22:13:20Z","entries":[]}"#;
        assert!(matches!(
            deserialize_bundle(json),
            Err(ApplicationError::Export(_))
        ));
    }
}
