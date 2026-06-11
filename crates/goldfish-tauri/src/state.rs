//! Tauri-managed application state.

use std::sync::Arc;

use tokio::sync::Mutex;

use goldfish_application::{PwnedRangeSource, VaultService, VaultSession};

/// Shared state managed by Tauri. Holds the wired [`VaultService`], the current
/// unlocked [`VaultSession`] (`None` while locked), and the HIBP breach-check
/// source.
///
/// The session is guarded by a `tokio::sync::Mutex` so commands can hold it
/// across `.await` points (e.g. while a repository operation runs) without
/// cloning the session — and therefore without duplicating the DEK in memory.
pub struct AppState {
    /// The wired vault service (clones share the same adapters).
    pub service: VaultService,
    /// The unlocked session, or `None` when the vault is locked.
    pub session: Mutex<Option<VaultSession>>,
    /// Source for HIBP password breach checks.
    pub pwned: Arc<dyn PwnedRangeSource>,
}

impl AppState {
    /// Creates fresh, locked state around the given service and breach source.
    pub fn new(service: VaultService, pwned: Arc<dyn PwnedRangeSource>) -> Self {
        Self {
            service,
            session: Mutex::new(None),
            pwned,
        }
    }
}
