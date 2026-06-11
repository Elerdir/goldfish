//! Have I Been Pwned breach check via k-anonymity.
//!
//! The password is SHA-1 hashed locally; only the first 5 hex characters of the
//! hash (the "range prefix") are sent to the API. The response lists hash
//! suffixes with breach counts; we match our suffix locally. The password and
//! its full hash never leave the device.

use uuid::Uuid;

use crate::ports::PwnedRangeSource;
use crate::ApplicationError;

/// One entry whose password was found in a breach during a vault-wide scan.
#[derive(Debug, Clone)]
pub struct BreachItem {
    /// Entry id.
    pub id: Uuid,
    /// Entry title (no secret material).
    pub title: String,
    /// How many times the password appears in known breaches.
    pub count: u64,
}

/// An entry queued for a vault-wide breach scan.
///
/// Carries the **pre-computed** upper-hex SHA-1 of the password (not the
/// plaintext), so the network phase can run without the decrypted password and
/// without holding the session lock.
#[derive(Debug, Clone)]
pub struct BreachTarget {
    /// Entry id.
    pub id: Uuid,
    /// Entry title (no secret material).
    pub title: String,
    /// Upper-hex SHA-1 of the password (40 chars).
    pub sha1: String,
}

pub(crate) fn sha1_hex_upper(input: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    use std::fmt::Write as _;

    let digest = Sha1::digest(input);
    let mut hex = String::with_capacity(40);
    for &b in &digest {
        let _ = write!(hex, "{b:02X}");
    }
    hex
}

/// Returns how many times `password` appears in known breaches (0 = not found).
pub async fn check_pwned(
    source: &dyn PwnedRangeSource,
    password: &str,
) -> Result<u64, ApplicationError> {
    if password.is_empty() {
        return Ok(0);
    }

    check_pwned_hash(source, &sha1_hex_upper(password.as_bytes())).await
}

/// Like [`check_pwned`] but takes a **pre-computed** upper-hex SHA-1 hash.
///
/// Callers that already hashed the password — e.g. a vault-wide scan that hashes
/// under the session lock and then queries the network without it — reuse this so
/// neither the plaintext nor the unlocked session is needed for the network phase.
/// Only the 5-char prefix is sent.
pub async fn check_pwned_hash(
    source: &dyn PwnedRangeSource,
    hash: &str,
) -> Result<u64, ApplicationError> {
    if hash.len() < 5 {
        return Ok(0);
    }
    let (prefix, suffix) = hash.split_at(5);

    let body = source.fetch_range(prefix).await?;
    for line in body.lines() {
        let mut parts = line.trim().splitn(2, ':');
        let line_suffix = parts.next().unwrap_or_default();
        if line_suffix.eq_ignore_ascii_case(suffix) {
            let count = parts
                .next()
                .and_then(|c| c.trim().parse::<u64>().ok())
                .unwrap_or(0);
            return Ok(count);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;

    /// Records the requested prefix and returns a canned body.
    struct MockSource {
        body: String,
        seen_prefix: Mutex<Option<String>>,
    }

    impl MockSource {
        fn new(body: &str) -> Self {
            Self {
                body: body.to_owned(),
                seen_prefix: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl PwnedRangeSource for MockSource {
        async fn fetch_range(&self, prefix: &str) -> Result<String, ApplicationError> {
            *self.seen_prefix.lock().unwrap() = Some(prefix.to_owned());
            Ok(self.body.clone())
        }
    }

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    const PASSWORD_PREFIX: &str = "5BAA6";
    const PASSWORD_SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[tokio::test]
    async fn sends_only_the_prefix() {
        let source = MockSource::new("0000000000000000000000000000000000A:1\r\n");
        let _ = check_pwned(&source, "password").await.unwrap();
        assert_eq!(
            source.seen_prefix.lock().unwrap().as_deref(),
            Some(PASSWORD_PREFIX)
        );
    }

    #[tokio::test]
    async fn returns_count_when_found() {
        let body = format!("ABCDEF0000000000000000000000000000A:3\r\n{PASSWORD_SUFFIX}:99999\r\n");
        let count = check_pwned(&MockSource::new(&body), "password")
            .await
            .unwrap();
        assert_eq!(count, 99999);
    }

    #[tokio::test]
    async fn suffix_match_is_case_insensitive() {
        let body = format!("{}:42\r\n", PASSWORD_SUFFIX.to_lowercase());
        let count = check_pwned(&MockSource::new(&body), "password")
            .await
            .unwrap();
        assert_eq!(count, 42);
    }

    #[tokio::test]
    async fn returns_zero_when_not_found() {
        let body = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:7\r\n";
        let count = check_pwned(&MockSource::new(body), "password")
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn empty_password_is_zero_without_a_request() {
        let source = MockSource::new("");
        let count = check_pwned(&source, "").await.unwrap();
        assert_eq!(count, 0);
        assert!(source.seen_prefix.lock().unwrap().is_none());
    }
}
