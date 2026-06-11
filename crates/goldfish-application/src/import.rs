//! Import parsers for other password managers.
//!
//! Pure parsing: an export file (string) becomes a list of validated
//! [`EntryDraft`]s. Supported: Bitwarden (unencrypted JSON), KeePassXC (CSV),
//! 1Password (CSV). Rows that carry nothing meaningful, or whose title fails
//! validation, are skipped rather than imported as junk.

use std::collections::HashMap;

use serde::Deserialize;

use goldfish_domain::{EntryDraft, PlaintextSecret};

use crate::totp::validate_totp;
use crate::ApplicationError;

/// Supported import source formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    /// Bitwarden unencrypted JSON export.
    Bitwarden,
    /// KeePassXC CSV export.
    KeePassXc,
    /// 1Password CSV export.
    OnePassword,
}

impl ImportFormat {
    /// Parses a stable identifier (`bitwarden` / `keepassxc` / `onepassword`).
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "bitwarden" => Some(Self::Bitwarden),
            "keepassxc" => Some(Self::KeePassXc),
            "onepassword" => Some(Self::OnePassword),
            _ => None,
        }
    }
}

/// Parses `data` in the given format into validated drafts.
pub fn parse_import(format: ImportFormat, data: &str) -> Result<Vec<EntryDraft>, ApplicationError> {
    match format {
        ImportFormat::Bitwarden => parse_bitwarden(data),
        ImportFormat::KeePassXc => parse_csv(
            data,
            &["title"],
            &["username"],
            &["password"],
            &["url"],
            &["notes"],
            &["totp"],
        ),
        ImportFormat::OnePassword => parse_csv(
            data,
            &["title"],
            &["username"],
            &["password"],
            &["url", "website"],
            &["notes"],
            &["otpauth", "one-time password", "otp"],
        ),
    }
}

/// Builds a draft, applying a title fallback and dropping empty/invalid bits.
/// Returns `None` to skip a row that carries nothing worth importing.
fn make_draft(
    name: &str,
    username: &str,
    password: &str,
    url: Option<String>,
    notes: Option<String>,
    totp: Option<String>,
    favorite: bool,
) -> Option<EntryDraft> {
    let name = name.trim();
    let username = username.trim();
    let url = url.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    let notes = notes.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    let totp = totp.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());

    // Skip rows that have nothing meaningful at all.
    if name.is_empty()
        && username.is_empty()
        && password.is_empty()
        && url.is_none()
        && notes.is_none()
        && totp.is_none()
    {
        return None;
    }

    let title = if !name.is_empty() {
        name.to_owned()
    } else if let Some(u) = &url {
        u.clone()
    } else if !username.is_empty() {
        username.to_owned()
    } else {
        "Imported entry".to_owned()
    };

    let mut draft =
        EntryDraft::new(&title, username, PlaintextSecret::from(password.to_owned())).ok()?;
    draft.url = url;
    draft.notes = notes.map(PlaintextSecret::from);
    draft.totp_secret = totp
        .filter(|t| validate_totp(t).is_ok())
        .map(PlaintextSecret::from);
    draft.favorite = favorite;
    Some(draft)
}

// ---------- Bitwarden JSON ----------

#[derive(Deserialize)]
struct BwExport {
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Deserialize)]
struct BwItem {
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    login: Option<BwLogin>,
}

#[derive(Deserialize, Default)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

fn parse_bitwarden(data: &str) -> Result<Vec<EntryDraft>, ApplicationError> {
    let export: BwExport =
        serde_json::from_str(data).map_err(|e| ApplicationError::Import(e.to_string()))?;
    let mut drafts = Vec::new();
    for item in export.items {
        let login = item.login.unwrap_or_default();
        let url = login
            .uris
            .and_then(|uris| uris.into_iter().find_map(|u| u.uri));
        if let Some(draft) = make_draft(
            &item.name,
            login.username.as_deref().unwrap_or(""),
            login.password.as_deref().unwrap_or(""),
            url,
            item.notes,
            login.totp,
            item.favorite,
        ) {
            drafts.push(draft);
        }
    }
    Ok(drafts)
}

// ---------- CSV (KeePassXC / 1Password) ----------

fn parse_csv(
    data: &str,
    title_keys: &[&str],
    user_keys: &[&str],
    pass_keys: &[&str],
    url_keys: &[&str],
    notes_keys: &[&str],
    totp_keys: &[&str],
) -> Result<Vec<EntryDraft>, ApplicationError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(data.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| ApplicationError::Import(e.to_string()))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();

    let mut drafts = Vec::new();
    for record in reader.records() {
        let record = record.map_err(|e| ApplicationError::Import(e.to_string()))?;
        let mut row: HashMap<&str, &str> = HashMap::new();
        for (i, field) in record.iter().enumerate() {
            if let Some(h) = headers.get(i) {
                row.insert(h.as_str(), field);
            }
        }

        let pick = |keys: &[&str]| -> Option<String> {
            keys.iter().find_map(|k| {
                row.get(k)
                    .map(|v| (*v).to_owned())
                    .filter(|s| !s.is_empty())
            })
        };

        if let Some(draft) = make_draft(
            pick(title_keys).as_deref().unwrap_or(""),
            pick(user_keys).as_deref().unwrap_or(""),
            pick(pass_keys).as_deref().unwrap_or(""),
            pick(url_keys),
            pick(notes_keys),
            pick(totp_keys),
            false,
        ) {
            drafts.push(draft);
        }
    }
    Ok(drafts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bitwarden_login() {
        let json = r#"{
            "items": [
                {
                    "name": "GitHub",
                    "favorite": true,
                    "notes": "work account",
                    "login": {
                        "username": "octocat",
                        "password": "hunter2",
                        "uris": [{"uri": "https://github.com"}]
                    }
                },
                { "name": "Empty type", "type": 2 }
            ]
        }"#;
        let drafts = parse_import(ImportFormat::Bitwarden, json).unwrap();
        assert_eq!(drafts.len(), 2);
        let gh = &drafts[0];
        assert_eq!(gh.title, "GitHub");
        assert_eq!(gh.username, "octocat");
        assert_eq!(gh.password.expose(), "hunter2");
        assert_eq!(gh.url.as_deref(), Some("https://github.com"));
        assert!(gh.favorite);
        // The note-only item keeps its title.
        assert_eq!(drafts[1].title, "Empty type");
    }

    #[test]
    fn parses_keepassxc_csv() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\
                   \"Root\",\"Mail\",\"alice\",\"s3cret\",\"https://mail.example\",\"hello\",\"\"\n";
        let drafts = parse_import(ImportFormat::KeePassXc, csv).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].title, "Mail");
        assert_eq!(drafts[0].username, "alice");
        assert_eq!(drafts[0].password.expose(), "s3cret");
        assert_eq!(drafts[0].url.as_deref(), Some("https://mail.example"));
    }

    #[test]
    fn parses_onepassword_csv_with_website_column() {
        let csv = "Title,Website,Username,Password,Notes\n\
                   Bank,https://bank.example,bob,p@ss,note text\n";
        let drafts = parse_import(ImportFormat::OnePassword, csv).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].title, "Bank");
        assert_eq!(drafts[0].url.as_deref(), Some("https://bank.example"));
    }

    #[test]
    fn skips_fully_empty_rows() {
        let csv = "Title,Username,Password\n,,\nReal,u,p\n";
        let drafts = parse_import(ImportFormat::KeePassXc, csv).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].title, "Real");
    }

    #[test]
    fn drops_invalid_totp() {
        let csv = "Title,Username,Password,TOTP\nX,u,p,not-base32!!!\n";
        let drafts = parse_import(ImportFormat::KeePassXc, csv).unwrap();
        assert_eq!(drafts.len(), 1);
        assert!(drafts[0].totp_secret.is_none());
    }

    #[test]
    fn invalid_json_errors() {
        assert!(matches!(
            parse_import(ImportFormat::Bitwarden, "{ not json"),
            Err(ApplicationError::Import(_))
        ));
    }

    #[test]
    fn format_from_id() {
        assert_eq!(
            ImportFormat::from_id("bitwarden"),
            Some(ImportFormat::Bitwarden)
        );
        assert_eq!(ImportFormat::from_id("nope"), None);
    }

    proptest::proptest! {
        /// Parsing untrusted import data must never panic — only return Ok/Err.
        #[test]
        fn parse_import_never_panics(data in ".*") {
            for fmt in [
                ImportFormat::Bitwarden,
                ImportFormat::KeePassXc,
                ImportFormat::OnePassword,
            ] {
                let _ = parse_import(fmt, &data);
            }
        }
    }
}
