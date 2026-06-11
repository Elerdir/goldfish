//! Vault health analysis — weak, reused, stale, and 2FA-less credentials.
//!
//! Operates on already-decrypted [`Entry`] values (the caller holds the unlocked
//! session). The report never carries any password: reuse is detected by hashing,
//! and only entry ids/titles are returned.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sha1::{Digest, Sha1};
use uuid::Uuid;

use goldfish_domain::{Entry, EntryKind};

use crate::strength::estimate_strength;

/// A single entry referenced by a health finding (no secret material).
#[derive(Debug, Clone)]
pub struct HealthItem {
    /// Entry id.
    pub id: Uuid,
    /// Entry title (for display).
    pub title: String,
}

/// A set of entries that share the same password.
#[derive(Debug, Clone)]
pub struct ReusedGroup {
    /// How many entries share this password.
    pub count: usize,
    /// The entries (id + title only).
    pub entries: Vec<HealthItem>,
}

/// Result of a vault-health scan.
#[derive(Debug, Clone, Default)]
pub struct HealthReport {
    /// Total entries scanned.
    pub total: usize,
    /// Entries whose password scores below the weakness threshold.
    pub weak: Vec<HealthItem>,
    /// Groups of entries that reuse the same password.
    pub reused: Vec<ReusedGroup>,
    /// Entries not changed within the staleness window.
    pub stale: Vec<HealthItem>,
    /// Entries without a configured TOTP secret.
    pub without_totp: Vec<HealthItem>,
}

/// Analyzes `entries`, flagging passwords weaker than `weak_below` (a 0–4 zxcvbn
/// score), reused passwords, entries older than `stale_after_days`, and entries
/// without 2FA.
#[must_use]
pub fn analyze(
    entries: &[Entry],
    now: DateTime<Utc>,
    weak_below: u8,
    stale_after_days: i64,
) -> HealthReport {
    let item = |e: &Entry| HealthItem {
        id: e.id.0,
        title: e.title.clone(),
    };

    let mut weak = Vec::new();
    let mut stale = Vec::new();
    let mut without_totp = Vec::new();
    // Group by a hash of the password so plaintext is never used as a map key.
    let mut by_password: HashMap<[u8; 20], Vec<HealthItem>> = HashMap::new();

    for entry in entries {
        let password = entry.password.expose();
        if !password.is_empty() {
            let score =
                estimate_strength(password, &[entry.title.as_str(), entry.username.as_str()]);
            if score < weak_below {
                weak.push(item(entry));
            }
            let digest: [u8; 20] = Sha1::digest(password.as_bytes()).into();
            by_password.entry(digest).or_default().push(item(entry));
        }
        // 2FA only makes sense for logins; notes/cards/keys aren't flagged.
        if entry.kind == EntryKind::Login && entry.totp_secret.is_none() {
            without_totp.push(item(entry));
        }
        if (now - entry.updated_at).num_days() > stale_after_days {
            stale.push(item(entry));
        }
    }

    let mut reused: Vec<ReusedGroup> = by_password
        .into_values()
        .filter(|group| group.len() >= 2)
        .map(|group| ReusedGroup {
            count: group.len(),
            entries: group,
        })
        .collect();
    reused.sort_by_key(|group| std::cmp::Reverse(group.count));

    HealthReport {
        total: entries.len(),
        weak,
        reused,
        stale,
        without_totp,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use secrecy::SecretString;

    use goldfish_domain::{EntryId, PlaintextSecret};

    use super::*;

    fn entry(title: &str, password: &str, days_old: i64, totp: bool, now: DateTime<Utc>) -> Entry {
        Entry {
            id: EntryId::new(),
            kind: goldfish_domain::EntryKind::Login,
            title: title.to_owned(),
            description: None,
            url: None,
            app_name: None,
            username: "user".to_owned(),
            password: PlaintextSecret::new(SecretString::from(password.to_owned())),
            notes: None,
            totp_secret: totp.then(|| PlaintextSecret::from("JBSWY3DPEHPK3PXP")),
            folder_id: None,
            favorite: false,
            custom_fields: Vec::new(),
            tags: Vec::new(),
            version: 1,
            created_at: now,
            updated_at: now - Duration::days(days_old),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_900_000_000, 0).unwrap()
    }

    #[test]
    fn flags_weak_reused_stale_and_missing_totp() {
        let now = now();
        let entries = vec![
            entry("A", "password", 0, false, now), // weak, reused, no totp
            entry("B", "password", 400, false, now), // weak, reused, no totp, stale
            entry("C", "9!qX#2vL8@mZ4wR^7tB&", 0, true, now), // strong, has totp
        ];
        let report = analyze(&entries, now, 3, 365);

        assert_eq!(report.total, 3);
        // A and B are weak; C is strong.
        assert_eq!(report.weak.len(), 2);
        // A and B share "password".
        assert_eq!(report.reused.len(), 1);
        assert_eq!(report.reused[0].count, 2);
        // Only B is older than a year.
        assert_eq!(report.stale.len(), 1);
        assert_eq!(report.stale[0].title, "B");
        // A and B lack TOTP; C has it.
        assert_eq!(report.without_totp.len(), 2);
    }

    #[test]
    fn clean_vault_has_no_findings() {
        let now = now();
        let entries = vec![
            entry("A", "9!qX#2vL8@mZ4wR^7tB&", 1, true, now),
            entry("B", "Zk7$Rt2&Yp9!Lm4#Qw8x", 1, true, now),
        ];
        let report = analyze(&entries, now, 3, 365);
        assert!(report.weak.is_empty());
        assert!(report.reused.is_empty());
        assert!(report.stale.is_empty());
        assert!(report.without_totp.is_empty());
    }
}
