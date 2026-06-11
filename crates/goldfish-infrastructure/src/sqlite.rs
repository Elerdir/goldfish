//! SQLite + SQLCipher adapter implementing both [`VaultStore`] (lifecycle) and
//! [`EntryRepository`] (data).
//!
//! The connection pool is keyed with `PRAGMA key = "x'<hex>'"` (raw 32-byte key
//! — we already ran Argon2id, so SQLCipher skips its own KDF) applied on every
//! new connection. Pages are AES-256-CBC + HMAC-SHA512 encrypted at rest,
//! transparently to queries. The pool lives in an `RwLock<Option<_>>` so the
//! store can be opened (unlock) and dropped (lock) without recreating the
//! adapter.
//!
//! rusqlite is synchronous; each async port method runs its work on a
//! `spawn_blocking` thread so the async runtime is never blocked on disk I/O.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use goldfish_application::{ApplicationError, BackupInfo, EntryRepository, VaultStore};
use goldfish_domain::{
    Appearance, AttachmentMeta, EntryId, EntryKind, EntrySummary, Folder, SealedAttachment,
    SealedEntry, SealedField, SealedPasswordHistory, Tag,
};
use parking_lot::RwLock;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

mod embedded {
    refinery::embed_migrations!("migrations");
}

type Pool = r2d2::Pool<SqliteConnectionManager>;

// New entries are appended to the end of both orderings: `all_pos` is one past
// the global max, `folder_pos` one past the max within the target folder. The
// subqueries read the same table (the new row is not yet inserted).
const INSERT_SQL: &str = "\
    INSERT INTO entries (id, title, description, url, app_name, folder_id, favorite, version, \
        created_at, updated_at, username_nonce, username_ct, password_nonce, password_ct, \
        notes_nonce, notes_ct, totp_nonce, totp_ct, kind, custom_nonce, custom_ct, \
        all_pos, folder_pos) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
        ?19, ?20, ?21, \
        (SELECT COALESCE(MAX(all_pos) + 1, 0) FROM entries), \
        (SELECT COALESCE(MAX(folder_pos) + 1, 0) FROM entries WHERE folder_id IS ?6))";

// `folder_pos` is recomputed only when the folder changes: SQLite evaluates all
// RHS expressions against the row's *pre-update* values, so `folder_id IS ?5`
// compares the old folder to the new one (?5). A move appends to the new
// folder's end; an in-place edit keeps the existing position. `all_pos` is never
// touched here — the All-entries order is independent of edits.
const UPDATE_SQL: &str = "\
    UPDATE entries SET title=?1, description=?2, url=?3, app_name=?4, folder_id=?5, favorite=?6, \
        version=?7, created_at=?8, updated_at=?9, username_nonce=?10, username_ct=?11, \
        password_nonce=?12, password_ct=?13, notes_nonce=?14, notes_ct=?15, totp_nonce=?16, \
        totp_ct=?17, kind=?18, custom_nonce=?19, custom_ct=?20, \
        folder_pos = CASE WHEN folder_id IS ?5 THEN folder_pos \
            ELSE (SELECT COALESCE(MAX(e2.folder_pos) + 1, 0) FROM entries e2 \
                  WHERE e2.folder_id IS ?5 AND e2.id != ?21) END \
    WHERE id=?21 AND version=?22";

const SELECT_BY_ID: &str = "\
    SELECT id, title, description, url, app_name, folder_id, favorite, version, created_at, \
        updated_at, username_nonce, username_ct, password_nonce, password_ct, notes_nonce, \
        notes_ct, totp_nonce, totp_ct, kind, custom_nonce, custom_ct \
    FROM entries WHERE id = ?1";

// The All-entries view (?1 IS NULL) orders by `all_pos`; a folder view orders by
// `folder_pos`. Title is a stable tie-breaker for rows that share a position
// (e.g. right after the backfill migration).
const SELECT_SUMMARIES: &str = "\
    SELECT id, title, url, app_name, favorite, folder_id, updated_at, kind \
    FROM entries WHERE (?1 IS NULL OR folder_id = ?1) \
    ORDER BY (CASE WHEN ?1 IS NULL THEN all_pos ELSE folder_pos END), title COLLATE NOCASE";

const INSERT_HISTORY_SQL: &str = "\
    INSERT INTO password_history (id, entry_id, password_nonce, password_ct, changed_at) \
    VALUES (?1, ?2, ?3, ?4, ?5)";

const SELECT_HISTORY_SQL: &str = "\
    SELECT id, entry_id, password_nonce, password_ct, changed_at \
    FROM password_history WHERE entry_id = ?1 ORDER BY changed_at DESC";

/// SQLCipher-backed entry store.
#[derive(Clone)]
pub struct SqliteEntryStore {
    db_path: PathBuf,
    pool: Arc<RwLock<Option<Pool>>>,
}

impl SqliteEntryStore {
    /// Creates a store backed by the database file at `db_path`. The store is
    /// closed until [`VaultStore::open`] is called.
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            pool: Arc::new(RwLock::new(None)),
        }
    }

    fn require_pool(&self) -> Result<Pool, ApplicationError> {
        self.pool
            .read()
            .clone()
            .ok_or(ApplicationError::VaultLocked)
    }
}

fn storage_err(e: impl std::fmt::Display) -> ApplicationError {
    ApplicationError::Storage(e.to_string())
}

fn to_hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn uuid_from(bytes: &[u8]) -> Result<Uuid, ApplicationError> {
    Uuid::from_slice(bytes).map_err(storage_err)
}

/// Replaces an entry's tag links with `tags` (delete-then-insert). Must run
/// inside the same transaction as the entry insert/update.
fn replace_entry_tags(
    conn: &rusqlite::Connection,
    entry_id: &[u8],
    tags: &[Uuid],
) -> Result<(), ApplicationError> {
    conn.execute(
        "DELETE FROM entry_tags WHERE entry_id = ?1",
        params![entry_id],
    )
    .map_err(storage_err)?;
    let mut stmt = conn
        .prepare("INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)")
        .map_err(storage_err)?;
    for tag in tags {
        stmt.execute(params![entry_id, tag.as_bytes().to_vec()])
            .map_err(storage_err)?;
    }
    Ok(())
}

/// Loads the tag ids linked to a single entry.
fn load_entry_tags(
    conn: &rusqlite::Connection,
    entry_id: &[u8],
) -> Result<Vec<Uuid>, ApplicationError> {
    let mut stmt = conn
        .prepare("SELECT tag_id FROM entry_tags WHERE entry_id = ?1")
        .map_err(storage_err)?;
    let raw = stmt
        .query_map(params![entry_id], |row| row.get::<_, Vec<u8>>(0))
        .map_err(storage_err)?
        .collect::<rusqlite::Result<Vec<Vec<u8>>>>()
        .map_err(storage_err)?;
    raw.iter().map(|b| uuid_from(b)).collect()
}

/// Runs `PRAGMA quick_check`. A wrong key or a corrupt file surfaces here as an
/// error or a non-`ok` result, so we fail fast instead of operating on garbage.
fn verify_integrity(conn: &rusqlite::Connection) -> Result<(), ApplicationError> {
    let result: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(storage_err)?;
    if result == "ok" {
        Ok(())
    } else {
        Err(ApplicationError::Storage(format!(
            "vault integrity check failed: {result}"
        )))
    }
}

/// Folds the WAL back into the main file so a file-level copy is self-consistent.
fn checkpoint(conn: &rusqlite::Connection) {
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

/// Rolling, best-effort vault backups. The database file is already
/// SQLCipher-encrypted, so a plain file copy is a safe encrypted snapshot.
mod backup {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    /// Keep at most this many rolling snapshots.
    const KEEP: usize = 10;
    /// Don't snapshot more than once per this interval (avoid one per unlock).
    const MIN_INTERVAL: Duration = Duration::from_secs(3600);

    fn snapshots(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("db"))
                    && p.file_stem()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s.starts_with("vault-"))
            })
            .collect();
        found.sort(); // timestamped names sort chronologically
        Ok(found)
    }

    fn made_recently(snaps: &[PathBuf]) -> bool {
        let Some(newest) = snaps.last() else {
            return false;
        };
        let Ok(modified) = std::fs::metadata(newest).and_then(|m| m.modified()) else {
            return false;
        };
        SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age < MIN_INTERVAL)
    }

    /// Copies `db_path` into a sibling `backups/` directory (named by timestamp)
    /// and prunes all but the newest [`KEEP`]. No-ops if a backup was made within
    /// [`MIN_INTERVAL`].
    pub fn rotate(db_path: &Path) -> std::io::Result<()> {
        let Some(parent) = db_path.parent() else {
            return Ok(());
        };
        let dir = parent.join("backups");
        std::fs::create_dir_all(&dir)?;

        let mut snaps = snapshots(&dir)?;
        if made_recently(&snaps) {
            return Ok(());
        }

        let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let dest = dir.join(format!("vault-{stamp}.db"));
        std::fs::copy(db_path, &dest)?;

        snaps.push(dest);
        snaps.sort();
        let excess = snaps.len().saturating_sub(KEEP);
        for old in snaps.into_iter().take(excess) {
            let _ = std::fs::remove_file(old);
        }
        Ok(())
    }

    /// Lists snapshots as `(file_name, modified_unix_ms, size_bytes)`, newest
    /// first. Returns an empty list if there is no `backups/` directory yet.
    pub fn list(db_path: &Path) -> std::io::Result<Vec<(String, i64, u64)>> {
        let Some(parent) = db_path.parent() else {
            return Ok(Vec::new());
        };
        let dir = parent.join("backups");
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for path in snapshots(&dir)? {
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
                .and_then(|d| i64::try_from(d.as_millis()).ok())
                .unwrap_or(0);
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            out.push((name.to_owned(), modified_ms, meta.len()));
        }
        out.reverse(); // snapshots() sorts ascending; we want newest first
        Ok(out)
    }

    /// Restores the live database from the named snapshot in `backups/`.
    ///
    /// Snapshots the current database first (so the restore is reversible), then
    /// copies the chosen snapshot over the live file and removes any stale WAL/SHM
    /// sidecars (which belong to the replaced database and would corrupt the
    /// restored one). `file_name` is validated to be a plain snapshot name — no
    /// path separators and the expected `vault-*.db` shape — to prevent traversal.
    pub fn restore(db_path: &Path, file_name: &str) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};

        let valid = !file_name.contains('/')
            && !file_name.contains('\\')
            && file_name.starts_with("vault-")
            && Path::new(file_name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("db"));
        if !valid {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid backup name"));
        }

        let Some(parent) = db_path.parent() else {
            return Err(Error::new(ErrorKind::NotFound, "vault has no parent dir"));
        };
        let dir = parent.join("backups");
        let src = dir.join(file_name);
        if !src.exists() {
            return Err(Error::new(ErrorKind::NotFound, "backup not found"));
        }

        // Snapshot the current DB first so a mistaken restore can be undone.
        if db_path.exists() {
            std::fs::create_dir_all(&dir)?;
            let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
            let _ = std::fs::copy(db_path, dir.join(format!("vault-{stamp}-prerestore.db")));
        }

        std::fs::copy(&src, db_path)?;

        // Drop stale WAL/SHM belonging to the replaced DB.
        for suffix in ["-wal", "-shm"] {
            let mut side = db_path.as_os_str().to_owned();
            side.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(side));
        }
        Ok(())
    }
}

fn millis_to_dt(ms: i64) -> Result<DateTime<Utc>, ApplicationError> {
    DateTime::from_timestamp_millis(ms).ok_or_else(|| storage_err("timestamp out of range"))
}

#[async_trait]
impl VaultStore for SqliteEntryStore {
    async fn open(&self, db_key: &[u8; 32]) -> Result<(), ApplicationError> {
        let path = self.db_path.clone();
        let hex = to_hex(db_key);
        let pool = tokio::task::spawn_blocking(move || -> Result<Pool, ApplicationError> {
            let existed = path.exists();

            // WAL + NORMAL synchronous: durable against power loss without an
            // fsync per write. busy_timeout lets pooled connections wait out a
            // brief writer lock instead of erroring. (PRAGMA key must come first
            // so the header is readable before any other pragma touches it.)
            //
            // cipher_memory_security = ON makes SQLCipher wipe its internal page
            // buffers and working memory when freed (it defaults OFF in
            // SQLCipher 4 for performance). The small per-query cost is worth it
            // for a password vault: it limits how long decrypted page contents
            // linger in process RAM (and thus in any swap/hibernation image).
            let pragma = format!(
                "PRAGMA key = \"x'{hex}'\"; \
                 PRAGMA cipher_memory_security = ON; \
                 PRAGMA foreign_keys = ON; \
                 PRAGMA journal_mode = WAL; \
                 PRAGMA busy_timeout = 5000; \
                 PRAGMA synchronous = NORMAL;"
            );
            let manager =
                SqliteConnectionManager::file(&path).with_init(move |c| c.execute_batch(&pragma));
            let pool = r2d2::Pool::builder()
                .max_size(8)
                .build(manager)
                .map_err(storage_err)?;
            let mut conn = pool.get().map_err(storage_err)?;

            // Confirm the database decrypts and is structurally intact before use.
            verify_integrity(&conn)?;

            // Roll a backup of an existing vault before touching its schema.
            if existed {
                checkpoint(&conn);
                if let Err(e) = backup::rotate(&path) {
                    tracing::warn!(error = %e, "vault backup skipped");
                }
            }

            embedded::migrations::runner()
                .run(&mut *conn)
                .map_err(storage_err)?;
            Ok(pool)
        })
        .await
        .map_err(storage_err)??;

        *self.pool.write() = Some(pool);
        Ok(())
    }

    async fn close(&self) -> Result<(), ApplicationError> {
        *self.pool.write() = None;
        Ok(())
    }

    async fn is_open(&self) -> bool {
        self.pool.read().is_some()
    }

    async fn list_backups(&self) -> Result<Vec<BackupInfo>, ApplicationError> {
        let path = self.db_path.clone();
        let rows = tokio::task::spawn_blocking(move || backup::list(&path))
            .await
            .map_err(storage_err)?
            .map_err(storage_err)?;
        Ok(rows
            .into_iter()
            .map(|(file_name, created_at_ms, size_bytes)| BackupInfo {
                file_name,
                created_at_ms,
                size_bytes,
            })
            .collect())
    }

    async fn restore_backup(&self, file_name: &str) -> Result<(), ApplicationError> {
        // The store must be closed before swapping the file. We don't enforce it
        // here (the service closes first); the swap itself only touches the file.
        let path = self.db_path.clone();
        let name = file_name.to_owned();
        tokio::task::spawn_blocking(move || backup::restore(&path, &name))
            .await
            .map_err(storage_err)?
            .map_err(storage_err)
    }
}

#[async_trait]
impl EntryRepository for SqliteEntryStore {
    async fn insert(&self, entry: &SealedEntry) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let e = entry.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let mut conn = pool.get().map_err(storage_err)?;
            let id = e.id.0.as_bytes().to_vec();
            let folder = e.folder_id.map(|u| u.as_bytes().to_vec());
            let created = e.created_at.timestamp_millis();
            let updated = e.updated_at.timestamp_millis();
            let notes_n = e.notes.as_ref().map(|f| f.nonce.clone());
            let notes_c = e.notes.as_ref().map(|f| f.ciphertext.clone());
            let totp_n = e.totp_secret.as_ref().map(|f| f.nonce.clone());
            let totp_c = e.totp_secret.as_ref().map(|f| f.ciphertext.clone());
            let custom_n = e.custom.as_ref().map(|f| f.nonce.clone());
            let custom_c = e.custom.as_ref().map(|f| f.ciphertext.clone());
            let tx = conn.transaction().map_err(storage_err)?;
            tx.execute(
                INSERT_SQL,
                params![
                    id,
                    e.title,
                    e.description,
                    e.url,
                    e.app_name,
                    folder,
                    e.favorite,
                    e.version,
                    created,
                    updated,
                    e.username.nonce,
                    e.username.ciphertext,
                    e.password.nonce,
                    e.password.ciphertext,
                    notes_n,
                    notes_c,
                    totp_n,
                    totp_c,
                    e.kind.as_str(),
                    custom_n,
                    custom_c,
                ],
            )
            .map_err(storage_err)?;
            replace_entry_tags(&tx, &id, &e.tags)?;
            tx.commit().map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn update(&self, entry: &SealedEntry) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let e = entry.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let mut conn = pool.get().map_err(storage_err)?;
            let id = e.id.0.as_bytes().to_vec();
            let prev_version = e
                .version
                .checked_sub(1)
                .ok_or_else(|| storage_err("version underflow on update"))?;
            let folder = e.folder_id.map(|u| u.as_bytes().to_vec());
            let created = e.created_at.timestamp_millis();
            let updated = e.updated_at.timestamp_millis();
            let notes_n = e.notes.as_ref().map(|f| f.nonce.clone());
            let notes_c = e.notes.as_ref().map(|f| f.ciphertext.clone());
            let totp_n = e.totp_secret.as_ref().map(|f| f.nonce.clone());
            let totp_c = e.totp_secret.as_ref().map(|f| f.ciphertext.clone());
            let custom_n = e.custom.as_ref().map(|f| f.nonce.clone());
            let custom_c = e.custom.as_ref().map(|f| f.ciphertext.clone());

            let tx = conn.transaction().map_err(storage_err)?;
            let affected = tx
                .execute(
                    UPDATE_SQL,
                    params![
                        e.title,
                        e.description,
                        e.url,
                        e.app_name,
                        folder,
                        e.favorite,
                        e.version,
                        created,
                        updated,
                        e.username.nonce,
                        e.username.ciphertext,
                        e.password.nonce,
                        e.password.ciphertext,
                        notes_n,
                        notes_c,
                        totp_n,
                        totp_c,
                        e.kind.as_str(),
                        custom_n,
                        custom_c,
                        id,
                        prev_version,
                    ],
                )
                .map_err(storage_err)?;

            if affected == 0 {
                let exists: Option<i64> = tx
                    .query_row("SELECT 1 FROM entries WHERE id = ?1", params![id], |r| {
                        r.get(0)
                    })
                    .optional()
                    .map_err(storage_err)?;
                return if exists.is_some() {
                    Err(ApplicationError::VersionConflict)
                } else {
                    Err(ApplicationError::EntryNotFound(e.id.0))
                };
            }
            replace_entry_tags(&tx, &id, &e.tags)?;
            tx.commit().map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn get(&self, id: EntryId) -> Result<Option<SealedEntry>, ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.0.as_bytes().to_vec();
        let loaded = tokio::task::spawn_blocking(
            move || -> Result<Option<(RawRow, Vec<Uuid>)>, ApplicationError> {
                let conn = pool.get().map_err(storage_err)?;
                let mut stmt = conn.prepare(SELECT_BY_ID).map_err(storage_err)?;
                let row = stmt
                    .query_row(params![id_bytes], RawRow::from_row)
                    .optional()
                    .map_err(storage_err)?;
                match row {
                    None => Ok(None),
                    Some(r) => {
                        let tags = load_entry_tags(&conn, &id_bytes)?;
                        Ok(Some((r, tags)))
                    }
                }
            },
        )
        .await
        .map_err(storage_err)??;

        match loaded {
            None => Ok(None),
            Some((raw, tags)) => {
                let mut sealed = SealedEntry::try_from(raw)?;
                sealed.tags = tags;
                Ok(Some(sealed))
            }
        }
    }

    async fn list_summaries(
        &self,
        folder_id: Option<Uuid>,
    ) -> Result<Vec<EntrySummary>, ApplicationError> {
        let pool = self.require_pool()?;
        let folder = folder_id.map(|u| u.as_bytes().to_vec());
        tokio::task::spawn_blocking(move || -> Result<Vec<EntrySummary>, ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            let mut stmt = conn.prepare(SELECT_SUMMARIES).map_err(storage_err)?;
            let raws = stmt
                .query_map(params![folder], RawSummary::from_row)
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<RawSummary>>>()
                .map_err(storage_err)?;
            let mut summaries: Vec<EntrySummary> = raws
                .into_iter()
                .map(EntrySummary::try_from)
                .collect::<Result<_, _>>()?;

            // Attach tag ids in one pass over the (small) join table.
            let mut by_entry: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
            let mut tag_stmt = conn
                .prepare("SELECT entry_id, tag_id FROM entry_tags")
                .map_err(storage_err)?;
            let links = tag_stmt
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>>>()
                .map_err(storage_err)?;
            for (entry_id, tag_id) in links {
                by_entry
                    .entry(uuid_from(&entry_id)?)
                    .or_default()
                    .push(uuid_from(&tag_id)?);
            }
            for summary in &mut summaries {
                if let Some(tags) = by_entry.remove(&summary.id.0) {
                    summary.tags = tags;
                }
            }
            Ok(summaries)
        })
        .await
        .map_err(storage_err)?
    }

    async fn delete(&self, id: EntryId) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.0.as_bytes().to_vec();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute("DELETE FROM entries WHERE id = ?1", params![id_bytes])
                .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn add_password_history(
        &self,
        record: &SealedPasswordHistory,
    ) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let r = record.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute(
                INSERT_HISTORY_SQL,
                params![
                    r.id.as_bytes().to_vec(),
                    r.entry_id.0.as_bytes().to_vec(),
                    r.password.nonce,
                    r.password.ciphertext,
                    r.changed_at.timestamp_millis(),
                ],
            )
            .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn list_password_history(
        &self,
        entry_id: EntryId,
    ) -> Result<Vec<SealedPasswordHistory>, ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = entry_id.0.as_bytes().to_vec();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<SealedPasswordHistory>, ApplicationError> {
                let conn = pool.get().map_err(storage_err)?;
                let mut stmt = conn.prepare(SELECT_HISTORY_SQL).map_err(storage_err)?;
                let raws = stmt
                    .query_map(params![id_bytes], RawHistory::from_row)
                    .map_err(storage_err)?
                    .collect::<rusqlite::Result<Vec<RawHistory>>>()
                    .map_err(storage_err)?;
                raws.into_iter()
                    .map(SealedPasswordHistory::try_from)
                    .collect()
            },
        )
        .await
        .map_err(storage_err)?
    }

    async fn create_folder(&self, folder: &Folder) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id = folder.id.as_bytes().to_vec();
        let name = folder.name.clone();
        let a = folder.appearance.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute(
                "INSERT INTO folders (id, name, bg, fg, bold, italic, font_size) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    name,
                    a.background,
                    a.text_color,
                    a.bold,
                    a.italic,
                    a.font_size
                ],
            )
            .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn list_folders(&self) -> Result<Vec<Folder>, ApplicationError> {
        let pool = self.require_pool()?;
        tokio::task::spawn_blocking(move || -> Result<Vec<Folder>, ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, bg, fg, bold, italic, font_size \
                     FROM folders ORDER BY name COLLATE NOCASE",
                )
                .map_err(storage_err)?;
            let raws = stmt
                .query_map([], RawFolder::from_row)
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<RawFolder>>>()
                .map_err(storage_err)?;
            raws.into_iter().map(Folder::try_from).collect()
        })
        .await
        .map_err(storage_err)?
    }

    async fn rename_folder(&self, id: Uuid, name: &str) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.as_bytes().to_vec();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute(
                "UPDATE folders SET name = ?2 WHERE id = ?1",
                params![id_bytes, name],
            )
            .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn set_folder_appearance(
        &self,
        id: Uuid,
        appearance: &Appearance,
    ) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.as_bytes().to_vec();
        let a = appearance.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute(
                "UPDATE folders SET bg = ?2, fg = ?3, bold = ?4, italic = ?5, font_size = ?6 \
                 WHERE id = ?1",
                params![
                    id_bytes,
                    a.background,
                    a.text_color,
                    a.bold,
                    a.italic,
                    a.font_size
                ],
            )
            .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn delete_folder(&self, id: Uuid) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.as_bytes().to_vec();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let mut conn = pool.get().map_err(storage_err)?;
            let tx = conn.transaction().map_err(storage_err)?;
            // Unassign entries first, then drop the folder (atomic).
            tx.execute(
                "UPDATE entries SET folder_id = NULL WHERE folder_id = ?1",
                params![id_bytes],
            )
            .map_err(storage_err)?;
            tx.execute("DELETE FROM folders WHERE id = ?1", params![id_bytes])
                .map_err(storage_err)?;
            tx.commit().map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn reorder_entries(
        &self,
        folder_id: Option<Uuid>,
        ids: &[EntryId],
    ) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        // `folder_id` selects which ordering to persist: the All-entries view
        // (None) writes `all_pos`, a folder view writes `folder_pos`. The column
        // name is a fixed literal — never user input — so there is no injection.
        let column = if folder_id.is_some() {
            "folder_pos"
        } else {
            "all_pos"
        };
        let id_bytes: Vec<Vec<u8>> = ids.iter().map(|e| e.0.as_bytes().to_vec()).collect();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let mut conn = pool.get().map_err(storage_err)?;
            let tx = conn.transaction().map_err(storage_err)?;
            {
                let sql = format!("UPDATE entries SET {column} = ?2 WHERE id = ?1");
                let mut stmt = tx.prepare(&sql).map_err(storage_err)?;
                for (pos, id) in id_bytes.iter().enumerate() {
                    let pos = i64::try_from(pos).map_err(storage_err)?;
                    stmt.execute(params![id, pos]).map_err(storage_err)?;
                }
            }
            tx.commit().map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn move_entry_to_folder(
        &self,
        id: EntryId,
        folder_id: Option<Uuid>,
    ) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.0.as_bytes().to_vec();
        let folder = folder_id.map(|u| u.as_bytes().to_vec());
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            // Reassign the folder and append to the end of the target folder's
            // ordering (excluding self). `all_pos` is left untouched, so the
            // entry keeps its place in the All-entries view. `folder_id` is not
            // bound into any field's AAD, so no re-sealing is needed.
            conn.execute(
                "UPDATE entries SET folder_id = ?2, \
                    folder_pos = (SELECT COALESCE(MAX(folder_pos) + 1, 0) FROM entries \
                        WHERE folder_id IS ?2 AND id != ?1) \
                 WHERE id = ?1",
                params![id_bytes, folder],
            )
            .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn create_tag(&self, tag: &Tag) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id = tag.id.as_bytes().to_vec();
        let name = tag.name.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute(
                "INSERT INTO tags (id, name) VALUES (?1, ?2)",
                params![id, name],
            )
            .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn list_tags(&self) -> Result<Vec<Tag>, ApplicationError> {
        let pool = self.require_pool()?;
        tokio::task::spawn_blocking(move || -> Result<Vec<Tag>, ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            let mut stmt = conn
                .prepare("SELECT id, name FROM tags ORDER BY name COLLATE NOCASE")
                .map_err(storage_err)?;
            let raws = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<(Vec<u8>, String)>>>()
                .map_err(storage_err)?;
            raws.into_iter()
                .map(|(id, name)| {
                    Ok(Tag {
                        id: uuid_from(&id)?,
                        name,
                    })
                })
                .collect()
        })
        .await
        .map_err(storage_err)?
    }

    async fn rename_tag(&self, id: Uuid, name: &str) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.as_bytes().to_vec();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute(
                "UPDATE tags SET name = ?2 WHERE id = ?1",
                params![id_bytes, name],
            )
            .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn delete_tag(&self, id: Uuid) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.as_bytes().to_vec();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            // entry_tags rows cascade away via the FK (foreign_keys = ON).
            conn.execute("DELETE FROM tags WHERE id = ?1", params![id_bytes])
                .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn add_attachment(&self, attachment: &SealedAttachment) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let a = attachment.clone();
        let created = chrono::Utc::now().timestamp_millis();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute(
                "INSERT INTO attachments (id, entry_id, name, size, blob_nonce, blob_ct, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    a.id.as_bytes().to_vec(),
                    a.entry_id.0.as_bytes().to_vec(),
                    a.name,
                    i64::try_from(a.size).unwrap_or(i64::MAX),
                    a.blob.nonce,
                    a.blob.ciphertext,
                    created,
                ],
            )
            .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn list_attachments(
        &self,
        entry_id: EntryId,
    ) -> Result<Vec<AttachmentMeta>, ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = entry_id.0.as_bytes().to_vec();
        tokio::task::spawn_blocking(move || -> Result<Vec<AttachmentMeta>, ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            // `id` is a UUID v7, so ordering by it is chronological (oldest first).
            let mut stmt = conn
                .prepare("SELECT id, name, size FROM attachments WHERE entry_id = ?1 ORDER BY id")
                .map_err(storage_err)?;
            let raws = stmt
                .query_map(params![id_bytes], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(storage_err)?
                .collect::<rusqlite::Result<Vec<(Vec<u8>, String, i64)>>>()
                .map_err(storage_err)?;
            raws.into_iter()
                .map(|(id, name, size)| {
                    Ok(AttachmentMeta {
                        id: uuid_from(&id)?,
                        name,
                        size: u64::try_from(size).unwrap_or(0),
                    })
                })
                .collect()
        })
        .await
        .map_err(storage_err)?
    }

    async fn get_attachment(&self, id: Uuid) -> Result<Option<SealedAttachment>, ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.as_bytes().to_vec();
        tokio::task::spawn_blocking(
            move || -> Result<Option<SealedAttachment>, ApplicationError> {
                let conn = pool.get().map_err(storage_err)?;
                let mut stmt = conn
                    .prepare(
                        "SELECT id, entry_id, name, size, blob_nonce, blob_ct \
                         FROM attachments WHERE id = ?1",
                    )
                    .map_err(storage_err)?;
                let row = stmt
                    .query_row(params![id_bytes], |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                        ))
                    })
                    .optional()
                    .map_err(storage_err)?;
                row.map(|(id, entry_id, name, size, nonce, ciphertext)| {
                    Ok(SealedAttachment {
                        id: uuid_from(&id)?,
                        entry_id: EntryId(uuid_from(&entry_id)?),
                        name,
                        size: u64::try_from(size).unwrap_or(0),
                        blob: SealedField { nonce, ciphertext },
                    })
                })
                .transpose()
            },
        )
        .await
        .map_err(storage_err)?
    }

    async fn delete_attachment(&self, id: Uuid) -> Result<(), ApplicationError> {
        let pool = self.require_pool()?;
        let id_bytes = id.as_bytes().to_vec();
        tokio::task::spawn_blocking(move || -> Result<(), ApplicationError> {
            let conn = pool.get().map_err(storage_err)?;
            conn.execute("DELETE FROM attachments WHERE id = ?1", params![id_bytes])
                .map_err(storage_err)?;
            Ok(())
        })
        .await
        .map_err(storage_err)?
    }
}

// ---- raw row mapping (rusqlite-native types -> domain types) ----

struct RawRow {
    id: Vec<u8>,
    title: String,
    description: Option<String>,
    url: Option<String>,
    app_name: Option<String>,
    folder_id: Option<Vec<u8>>,
    favorite: bool,
    version: i64,
    created_at: i64,
    updated_at: i64,
    username_nonce: Vec<u8>,
    username_ct: Vec<u8>,
    password_nonce: Vec<u8>,
    password_ct: Vec<u8>,
    notes_nonce: Option<Vec<u8>>,
    notes_ct: Option<Vec<u8>>,
    totp_nonce: Option<Vec<u8>>,
    totp_ct: Option<Vec<u8>>,
    kind: String,
    custom_nonce: Option<Vec<u8>>,
    custom_ct: Option<Vec<u8>>,
}

impl RawRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            title: row.get(1)?,
            description: row.get(2)?,
            url: row.get(3)?,
            app_name: row.get(4)?,
            folder_id: row.get(5)?,
            favorite: row.get(6)?,
            version: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
            username_nonce: row.get(10)?,
            username_ct: row.get(11)?,
            password_nonce: row.get(12)?,
            password_ct: row.get(13)?,
            notes_nonce: row.get(14)?,
            notes_ct: row.get(15)?,
            totp_nonce: row.get(16)?,
            totp_ct: row.get(17)?,
            kind: row.get(18)?,
            custom_nonce: row.get(19)?,
            custom_ct: row.get(20)?,
        })
    }
}

impl TryFrom<RawRow> for SealedEntry {
    type Error = ApplicationError;

    fn try_from(r: RawRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: EntryId(uuid_from(&r.id)?),
            kind: EntryKind::from_id(&r.kind),
            title: r.title,
            description: r.description,
            url: r.url,
            app_name: r.app_name,
            folder_id: r.folder_id.map(|b| uuid_from(&b)).transpose()?,
            favorite: r.favorite,
            version: u32::try_from(r.version).map_err(storage_err)?,
            created_at: millis_to_dt(r.created_at)?,
            updated_at: millis_to_dt(r.updated_at)?,
            username: SealedField {
                nonce: r.username_nonce,
                ciphertext: r.username_ct,
            },
            password: SealedField {
                nonce: r.password_nonce,
                ciphertext: r.password_ct,
            },
            notes: r
                .notes_nonce
                .zip(r.notes_ct)
                .map(|(nonce, ciphertext)| SealedField { nonce, ciphertext }),
            totp_secret: r
                .totp_nonce
                .zip(r.totp_ct)
                .map(|(nonce, ciphertext)| SealedField { nonce, ciphertext }),
            custom: r
                .custom_nonce
                .zip(r.custom_ct)
                .map(|(nonce, ciphertext)| SealedField { nonce, ciphertext }),
            // Tag ids are loaded separately (join table) and attached by `get`.
            tags: Vec::new(),
        })
    }
}

struct RawSummary {
    id: Vec<u8>,
    title: String,
    url: Option<String>,
    app_name: Option<String>,
    favorite: bool,
    folder_id: Option<Vec<u8>>,
    updated_at: i64,
    kind: String,
}

impl RawSummary {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            title: row.get(1)?,
            url: row.get(2)?,
            app_name: row.get(3)?,
            favorite: row.get(4)?,
            folder_id: row.get(5)?,
            updated_at: row.get(6)?,
            kind: row.get(7)?,
        })
    }
}

impl TryFrom<RawSummary> for EntrySummary {
    type Error = ApplicationError;

    fn try_from(r: RawSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            id: EntryId(uuid_from(&r.id)?),
            kind: EntryKind::from_id(&r.kind),
            title: r.title,
            url: r.url,
            app_name: r.app_name,
            favorite: r.favorite,
            folder_id: r.folder_id.map(|b| uuid_from(&b)).transpose()?,
            // Tag ids are attached by `list_summaries` after this conversion.
            tags: Vec::new(),
            updated_at: millis_to_dt(r.updated_at)?,
        })
    }
}

struct RawHistory {
    id: Vec<u8>,
    entry_id: Vec<u8>,
    password_nonce: Vec<u8>,
    password_ct: Vec<u8>,
    changed_at: i64,
}

impl RawHistory {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            entry_id: row.get(1)?,
            password_nonce: row.get(2)?,
            password_ct: row.get(3)?,
            changed_at: row.get(4)?,
        })
    }
}

impl TryFrom<RawHistory> for SealedPasswordHistory {
    type Error = ApplicationError;

    fn try_from(r: RawHistory) -> Result<Self, Self::Error> {
        Ok(Self {
            id: uuid_from(&r.id)?,
            entry_id: EntryId(uuid_from(&r.entry_id)?),
            password: SealedField {
                nonce: r.password_nonce,
                ciphertext: r.password_ct,
            },
            changed_at: millis_to_dt(r.changed_at)?,
        })
    }
}

struct RawFolder {
    id: Vec<u8>,
    name: String,
    bg: Option<String>,
    fg: Option<String>,
    bold: bool,
    italic: bool,
    font_size: Option<i64>,
}

impl RawFolder {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name: row.get(1)?,
            bg: row.get(2)?,
            fg: row.get(3)?,
            bold: row.get(4)?,
            italic: row.get(5)?,
            font_size: row.get(6)?,
        })
    }
}

impl TryFrom<RawFolder> for Folder {
    type Error = ApplicationError;

    fn try_from(r: RawFolder) -> Result<Self, Self::Error> {
        Ok(Self {
            id: uuid_from(&r.id)?,
            name: r.name,
            appearance: Appearance {
                background: r.bg,
                text_color: r.fg,
                bold: r.bold,
                italic: r.italic,
                font_size: r.font_size.and_then(|n| u16::try_from(n).ok()),
            },
        })
    }
}

#[cfg(test)]
mod backup_tests {
    use std::fs;

    use super::backup;

    #[test]
    fn restore_swaps_file_clears_wal_and_rejects_bad_names() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        fs::write(&db, b"CURRENT").unwrap();
        // Stale WAL/SHM sidecars that must be removed on restore.
        fs::write(dir.path().join("vault.db-wal"), b"stale").unwrap();
        fs::write(dir.path().join("vault.db-shm"), b"stale").unwrap();

        let backups = dir.path().join("backups");
        fs::create_dir_all(&backups).unwrap();
        fs::write(backups.join("vault-20260101-000000.db"), b"SNAPSHOT").unwrap();

        // list() sees the snapshot.
        let listed = backup::list(&db).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "vault-20260101-000000.db");

        // Path traversal / unexpected names / missing files are rejected.
        assert!(backup::restore(&db, "../evil.db").is_err());
        assert!(backup::restore(&db, "notabackup.txt").is_err());
        assert!(backup::restore(&db, "vault-missing.db").is_err());

        // A valid restore swaps content, clears WAL/SHM, and keeps a prerestore copy.
        backup::restore(&db, "vault-20260101-000000.db").unwrap();
        assert_eq!(fs::read(&db).unwrap(), b"SNAPSHOT");
        assert!(!dir.path().join("vault.db-wal").exists());
        assert!(!dir.path().join("vault.db-shm").exists());
        assert!(backup::list(&db)
            .unwrap()
            .iter()
            .any(|(name, _, _)| name.contains("prerestore")));
    }
}
