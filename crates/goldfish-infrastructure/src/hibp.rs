//! HIBP Pwned-Passwords range client (`PwnedRangeSource`) over HTTPS.
//!
//! Sends only the 5-hex-char SHA-1 prefix and sets `Add-Padding: true` so the
//! response size does not leak how many suffixes share the prefix.

use async_trait::async_trait;
use goldfish_application::{ApplicationError, PwnedRangeSource};

const RANGE_ENDPOINT: &str = "https://api.pwnedpasswords.com/range/";

/// Reqwest-backed HIBP range source (rustls TLS).
#[derive(Debug, Clone)]
pub struct HibpClient {
    client: reqwest::Client,
}

impl HibpClient {
    /// Creates a client with a reusable connection pool.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for HibpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PwnedRangeSource for HibpClient {
    async fn fetch_range(&self, prefix: &str) -> Result<String, ApplicationError> {
        let url = format!("{RANGE_ENDPOINT}{prefix}");
        self.client
            .get(url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| ApplicationError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| ApplicationError::Network(e.to_string()))?
            .text()
            .await
            .map_err(|e| ApplicationError::Network(e.to_string()))
    }
}
