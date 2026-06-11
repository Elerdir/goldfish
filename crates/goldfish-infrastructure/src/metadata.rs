//! Plaintext sidecar adapter for the `VaultMetadataRepository` port.
//!
//! Vault metadata (salt, KDF params, wrapped DEK, verifier) is **not secret on
//! its own** — it is stored as a JSON sidecar next to the encrypted database so
//! the app can read the KDF salt and unwrap the DEK *before* it has the key to
//! open the SQLCipher store (resolving the bootstrap chicken-and-egg).

use std::path::PathBuf;

use async_trait::async_trait;
use goldfish_application::{ApplicationError, VaultMetadataRepository};
use goldfish_domain::VaultMetadata;

/// Stores [`VaultMetadata`] as a JSON file. Writes are atomic (temp + rename).
#[derive(Debug, Clone)]
pub struct FileVaultMetadataRepository {
    path: PathBuf,
}

impl FileVaultMetadataRepository {
    /// Creates a repository backed by the file at `path`.
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

fn storage_err(e: impl std::fmt::Display) -> ApplicationError {
    ApplicationError::Storage(e.to_string())
}

#[async_trait]
impl VaultMetadataRepository for FileVaultMetadataRepository {
    async fn load(&self) -> Result<Option<VaultMetadata>, ApplicationError> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || match std::fs::read(&path) {
            Ok(bytes) => {
                let meta = serde_json::from_slice(&bytes).map_err(storage_err)?;
                Ok(Some(meta))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(storage_err(e)),
        })
        .await
        .map_err(storage_err)?
    }

    async fn save(&self, meta: &VaultMetadata) -> Result<(), ApplicationError> {
        let path = self.path.clone();
        let bytes = serde_json::to_vec_pretty(meta).map_err(storage_err)?;
        tokio::task::spawn_blocking(move || {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, &bytes).map_err(storage_err)?;
            std::fs::rename(&tmp, &path).map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }
}
