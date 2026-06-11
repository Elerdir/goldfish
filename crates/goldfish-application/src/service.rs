//! `VaultService` — the application's use-case surface.
//!
//! Each public method is one use case. The service holds its I/O dependencies
//! as ports ([`EntryRepository`], [`VaultMetadataRepository`], [`Clock`]) and
//! uses [`goldfish_crypto`] directly for cryptography. Returned [`VaultSession`]
//! values carry the unlocked keyset and are passed back in for entry operations.

use std::sync::Arc;

use chrono::DateTime;
use goldfish_crypto::{Argon2Params, UnlockMaterial, VaultKeyset};
use goldfish_domain::{
    Appearance, AttachmentMeta, BiometricWrap, Entry, EntryDraft, EntryId, EntrySummary, Folder,
    KdfParams, PasswordHistoryEntry, RecoveryWrap, SealedAttachment, SealedPasswordHistory, Tag,
    VaultMetadata, MAX_ATTACHMENT_SIZE,
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Normalizes a recovery code for key derivation: keep alphanumerics, uppercase,
/// and map Crockford look-alikes (I/L → 1, O → 0) so spacing/case/typos of those
/// characters don't change the derived key.
fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect()
}

use crate::export::{EncryptedExport, ExportBundle};
use crate::ports::{
    Clock, EntryRepository, OsKeyStore, PwnedRangeSource, VaultMetadataRepository, VaultStore,
};
use crate::session::VaultSession;
use crate::throttle::UnlockThrottle;
use crate::ApplicationError;

/// OS keystore label under which the biometric protection key is stored.
const BIOMETRIC_KEY_LABEL: &str = "biometric-dek-key";

/// Maps the domain's persisted KDF policy onto the crypto layer's parameters.
const fn to_argon(params: KdfParams) -> Argon2Params {
    Argon2Params::new(params.memory_kib, params.iterations, params.parallelism)
}

/// Orchestrates vault and entry use cases over injected ports.
#[derive(Clone)]
pub struct VaultService {
    entries: Arc<dyn EntryRepository>,
    store: Arc<dyn VaultStore>,
    meta: Arc<dyn VaultMetadataRepository>,
    clock: Arc<dyn Clock>,
    keystore: Arc<dyn OsKeyStore>,
    /// Process-wide backoff against online master-password guessing. Shared
    /// across clones so the throttle is global, not per-handle.
    throttle: Arc<parking_lot::Mutex<UnlockThrottle>>,
    /// KDF cost floor. A vault unlocked with weaker parameters is transparently
    /// re-wrapped up to this. Defaults to [`KdfParams::DEFAULT`].
    kdf_floor: KdfParams,
}

impl VaultService {
    /// Constructs the service from its port dependencies. `entries` and `store`
    /// are typically the same concrete adapter held as two trait objects.
    pub fn new(
        entries: Arc<dyn EntryRepository>,
        store: Arc<dyn VaultStore>,
        meta: Arc<dyn VaultMetadataRepository>,
        clock: Arc<dyn Clock>,
        keystore: Arc<dyn OsKeyStore>,
    ) -> Self {
        Self {
            entries,
            store,
            meta,
            clock,
            keystore,
            throttle: Arc::new(parking_lot::Mutex::new(UnlockThrottle::new())),
            kdf_floor: KdfParams::DEFAULT,
        }
    }

    /// Overrides the KDF upgrade floor. Production keeps the default; tests use a
    /// low floor so unlocking does not run the full-cost KDF.
    #[must_use]
    pub const fn with_kdf_floor(mut self, floor: KdfParams) -> Self {
        self.kdf_floor = floor;
        self
    }

    /// Whether a vault has already been initialized.
    pub async fn vault_exists(&self) -> Result<bool, ApplicationError> {
        Ok(self.meta.load().await?.is_some())
    }

    /// Creates a brand-new vault with the given master password and KDF policy.
    /// Fails with [`ApplicationError::VaultAlreadyExists`] if one exists.
    pub async fn create_vault(
        &self,
        password: &str,
        params: KdfParams,
    ) -> Result<VaultSession, ApplicationError> {
        if self.meta.load().await?.is_some() {
            return Err(ApplicationError::VaultAlreadyExists);
        }

        let schema = VaultMetadata::CURRENT_SCHEMA_VERSION;
        let (keyset, material) = VaultKeyset::create(password.as_bytes(), to_argon(params), schema)
            .map_err(|e| ApplicationError::Crypto(e.to_string()))?;

        // Open (create) the encrypted store before persisting metadata, so a
        // store-creation failure leaves no dangling sidecar.
        let db_key = keyset.derive_db_key();
        self.store.open(&db_key).await?;

        let now = self.clock.now();
        let meta = VaultMetadata {
            schema_version: schema,
            kdf_params: params,
            kdf_salt: material.salt,
            wrapped_dek: material.wrapped_dek,
            wrapped_dek_nonce: material.wrapped_dek_nonce,
            verifier: material.verifier,
            created_at: now,
            updated_at: now,
            biometric: None,
            recovery: None,
            unlock_failures: 0,
            unlock_locked_until_ms: None,
        };
        self.meta.save(&meta).await?;

        Ok(VaultSession::new(keyset))
    }

    /// Unlocks the vault with the master password. Fails with
    /// [`ApplicationError::VaultNotFound`] if uninitialized, or
    /// [`ApplicationError::InvalidMasterPassword`] on a wrong password.
    pub async fn unlock_vault(&self, password: &str) -> Result<VaultSession, ApplicationError> {
        let mut meta = self
            .meta
            .load()
            .await?
            .ok_or(ApplicationError::VaultNotFound)?;

        // Reconcile the in-memory throttle with the persisted backoff so an app
        // restart can't clear it; keep whichever window blocks longer.
        let now = self.clock.now();
        {
            let mut throttle = self.throttle.lock();
            let persisted = UnlockThrottle::restore(
                meta.unlock_failures,
                meta.unlock_locked_until_ms
                    .and_then(DateTime::from_timestamp_millis),
            );
            if persisted.retry_after(now) >= throttle.retry_after(now) {
                *throttle = persisted;
            }
        }

        // Online brute-force guard: reject (before spending Argon2id) while a
        // backoff window from prior failures is still open.
        let wait = self.throttle.lock().retry_after(now);
        if wait > 0 {
            return Err(ApplicationError::UnlockThrottled {
                retry_after_secs: wait,
            });
        }

        let material = UnlockMaterial {
            salt: &meta.kdf_salt,
            wrapped_dek: &meta.wrapped_dek,
            wrapped_dek_nonce: &meta.wrapped_dek_nonce,
            verifier: &meta.verifier,
        };
        let Ok(keyset) = VaultKeyset::unlock(
            password.as_bytes(),
            material,
            to_argon(meta.kdf_params),
            meta.schema_version,
        ) else {
            let (failures, until) = {
                let mut throttle = self.throttle.lock();
                throttle.record_failure(self.clock.now());
                throttle.snapshot()
            };
            // Persist the armed backoff (best-effort) so it survives a restart.
            meta.unlock_failures = failures;
            meta.unlock_locked_until_ms = until.map(|d| d.timestamp_millis());
            let _ = self.meta.save(&meta).await;
            return Err(ApplicationError::InvalidMasterPassword);
        };
        self.throttle.lock().record_success();

        // Clear any persisted backoff on success.
        if meta.unlock_failures != 0 || meta.unlock_locked_until_ms.is_some() {
            meta.unlock_failures = 0;
            meta.unlock_locked_until_ms = None;
            let _ = self.meta.save(&meta).await;
        }

        let db_key = keyset.derive_db_key();
        self.store.open(&db_key).await?;

        // Transparently strengthen the KDF if this vault predates the floor.
        self.maybe_upgrade_kdf(&keyset, password, &meta).await;

        Ok(VaultSession::new(keyset))
    }

    /// Re-wraps the vault under [`Self::kdf_floor`] when it was created with
    /// weaker Argon2id parameters. Best-effort: any failure here is logged and
    /// swallowed so it never blocks an otherwise-successful unlock.
    async fn maybe_upgrade_kdf(&self, keyset: &VaultKeyset, password: &str, meta: &VaultMetadata) {
        let floor = self.kdf_floor;
        let stored = meta.kdf_params;
        if stored.memory_kib >= floor.memory_kib && stored.iterations >= floor.iterations {
            return; // already at or above the floor
        }

        let Ok(material) = keyset.rewrap(password.as_bytes(), to_argon(floor), meta.schema_version)
        else {
            tracing::warn!("KDF upgrade skipped: re-wrap failed");
            return;
        };

        let mut updated = meta.clone();
        updated.kdf_params = floor;
        updated.kdf_salt = material.salt;
        updated.wrapped_dek = material.wrapped_dek;
        updated.wrapped_dek_nonce = material.wrapped_dek_nonce;
        updated.verifier = material.verifier;
        updated.updated_at = self.clock.now();

        if let Err(e) = self.meta.save(&updated).await {
            tracing::warn!(error = %e, "KDF upgrade skipped: metadata save failed");
        } else {
            tracing::info!("vault KDF parameters upgraded");
        }
    }

    /// Locks the vault: closes the encrypted store (drops connections and the
    /// in-memory DB key). The caller should also drop its [`VaultSession`].
    pub async fn lock(&self) -> Result<(), ApplicationError> {
        self.store.close().await
    }

    /// Lists the available rolling backup snapshots, newest first.
    pub async fn list_backups(&self) -> Result<Vec<crate::ports::BackupInfo>, ApplicationError> {
        self.store.list_backups().await
    }

    /// Restores the vault database from the named snapshot.
    ///
    /// Closes the store first (so the file swap doesn't race an open handle), then
    /// delegates the swap. The caller must drop its [`VaultSession`] and have the
    /// user unlock again afterwards (the DEK is unchanged across snapshots, so the
    /// current master password still works).
    pub async fn restore_backup(&self, file_name: &str) -> Result<(), ApplicationError> {
        self.store.close().await?;
        self.store.restore_backup(file_name).await
    }

    // ---------- biometric unlock ----------

    /// Whether this device supports biometric verification.
    pub fn biometric_available(&self) -> bool {
        self.keystore.biometrics_available()
    }

    /// Whether biometric unlock has been enabled for the vault.
    pub async fn biometric_enabled(&self) -> Result<bool, ApplicationError> {
        Ok(self.meta.load().await?.and_then(|m| m.biometric).is_some())
    }

    /// Enables biometric unlock from an unlocked session: generates a protection
    /// key (stored in the OS keystore) and persists the DEK sealed under it.
    pub async fn enable_biometric(&self, session: &VaultSession) -> Result<(), ApplicationError> {
        if !self.keystore.biometrics_available() {
            return Err(ApplicationError::BiometricUnavailable);
        }
        let material = session.export_biometric_material()?;
        self.keystore
            .store(BIOMETRIC_KEY_LABEL, &material.key[..])
            .await?;

        let mut meta = self
            .meta
            .load()
            .await?
            .ok_or(ApplicationError::VaultNotFound)?;
        meta.biometric = Some(BiometricWrap {
            nonce: material.nonce,
            wrapped_dek: material.wrapped_dek,
        });
        meta.updated_at = self.clock.now();
        self.meta.save(&meta).await
    }

    /// Disables biometric unlock: removes the keystore key and clears metadata.
    pub async fn disable_biometric(&self) -> Result<(), ApplicationError> {
        // Best-effort keystore removal — proceed even if the key is already gone.
        let _ = self.keystore.delete(BIOMETRIC_KEY_LABEL).await;
        if let Some(mut meta) = self.meta.load().await? {
            meta.biometric = None;
            meta.updated_at = self.clock.now();
            self.meta.save(&meta).await?;
        }
        Ok(())
    }

    /// Unlocks the vault using biometrics. Retrieving the keystore key triggers
    /// the platform biometric prompt.
    pub async fn unlock_biometric(&self) -> Result<VaultSession, ApplicationError> {
        let meta = self
            .meta
            .load()
            .await?
            .ok_or(ApplicationError::VaultNotFound)?;
        let bio = meta
            .biometric
            .ok_or(ApplicationError::BiometricNotEnabled)?;

        let key_bytes = self.keystore.retrieve(BIOMETRIC_KEY_LABEL).await?;
        let key: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ApplicationError::Crypto("biometric key has wrong length".to_owned()))?;

        let keyset = VaultKeyset::from_biometric_material(&key, &bio.nonce, &bio.wrapped_dek)
            .map_err(|e| ApplicationError::Crypto(e.to_string()))?;

        let db_key = keyset.derive_db_key();
        self.store.open(&db_key).await?;
        Ok(VaultSession::new(keyset))
    }

    // ---------- recovery code ----------

    /// Whether recovery-code unlock is enabled for the vault.
    pub async fn recovery_enabled(&self) -> Result<bool, ApplicationError> {
        Ok(self.meta.load().await?.and_then(|m| m.recovery).is_some())
    }

    /// Enables recovery-code unlock from an unlocked session: generates a fresh
    /// recovery code, wraps the DEK under it, and persists the wrap. Returns the
    /// code to display **once** — it is never stored.
    pub async fn enable_recovery(
        &self,
        session: &VaultSession,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        let mut meta = self
            .meta
            .load()
            .await?
            .ok_or(ApplicationError::VaultNotFound)?;

        let code = goldfish_crypto::generate_recovery_code();
        let normalized = normalize_recovery_code(&code);
        let material = session.export_recovery_material(
            normalized.as_bytes(),
            to_argon(meta.kdf_params),
            meta.schema_version,
        )?;

        meta.recovery = Some(RecoveryWrap {
            salt: material.salt,
            wrapped_dek: material.wrapped_dek,
            nonce: material.wrapped_dek_nonce,
        });
        meta.updated_at = self.clock.now();
        self.meta.save(&meta).await?;
        Ok(code)
    }

    /// Disables recovery-code unlock (clears the stored wrap).
    pub async fn disable_recovery(&self) -> Result<(), ApplicationError> {
        if let Some(mut meta) = self.meta.load().await? {
            meta.recovery = None;
            meta.updated_at = self.clock.now();
            self.meta.save(&meta).await?;
        }
        Ok(())
    }

    /// Unlocks via the recovery code and **resets the master password** to
    /// `new_master_password` (re-wrapping the DEK under it). The recovery wrap is
    /// left intact. Fails with [`ApplicationError::InvalidRecoveryCode`] on a
    /// wrong code.
    pub async fn unlock_with_recovery(
        &self,
        code: &str,
        new_master_password: &str,
    ) -> Result<VaultSession, ApplicationError> {
        let meta = self
            .meta
            .load()
            .await?
            .ok_or(ApplicationError::VaultNotFound)?;
        let recovery = meta
            .recovery
            .clone()
            .ok_or(ApplicationError::RecoveryNotEnabled)?;

        let normalized = normalize_recovery_code(code);
        let keyset = VaultKeyset::from_recovery_material(
            normalized.as_bytes(),
            &recovery.salt,
            &recovery.wrapped_dek,
            &recovery.nonce,
            to_argon(meta.kdf_params),
            meta.schema_version,
        )
        .map_err(|_| ApplicationError::InvalidRecoveryCode)?;

        // Reset the master password by re-wrapping the (unchanged) DEK under it.
        let material = keyset
            .rewrap(
                new_master_password.as_bytes(),
                to_argon(meta.kdf_params),
                meta.schema_version,
            )
            .map_err(|e| ApplicationError::Crypto(e.to_string()))?;
        let mut updated = meta.clone();
        updated.kdf_salt = material.salt;
        updated.wrapped_dek = material.wrapped_dek;
        updated.wrapped_dek_nonce = material.wrapped_dek_nonce;
        updated.verifier = material.verifier;
        updated.updated_at = self.clock.now();
        // A successful recovery also clears the (persisted) unlock backoff.
        updated.unlock_failures = 0;
        updated.unlock_locked_until_ms = None;
        self.meta.save(&updated).await?;

        self.throttle.lock().record_success();

        let db_key = keyset.derive_db_key();
        self.store.open(&db_key).await?;
        Ok(VaultSession::new(keyset))
    }

    /// Builds a fresh [`Entry`] (id, version 1, timestamps) from a draft.
    fn entry_from_draft(&self, draft: EntryDraft) -> Entry {
        let now = self.clock.now();
        Entry {
            id: EntryId::new(),
            kind: draft.kind,
            title: draft.title,
            description: draft.description,
            url: draft.url,
            app_name: draft.app_name,
            username: draft.username,
            password: draft.password,
            notes: draft.notes,
            totp_secret: draft.totp_secret,
            folder_id: draft.folder_id,
            favorite: draft.favorite,
            custom_fields: draft.custom_fields,
            tags: draft.tags,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Adds a new entry from a validated draft. Returns the created entry
    /// (with its assigned id, version 1, and timestamps).
    pub async fn add_entry(
        &self,
        session: &VaultSession,
        draft: EntryDraft,
    ) -> Result<Entry, ApplicationError> {
        let entry = self.entry_from_draft(draft);
        let sealed = session.seal_entry(&entry)?;
        self.entries.insert(&sealed).await?;
        Ok(entry)
    }

    /// Bulk-inserts imported drafts. Returns how many entries were added.
    pub async fn import_entries(
        &self,
        session: &VaultSession,
        drafts: Vec<EntryDraft>,
    ) -> Result<usize, ApplicationError> {
        let mut count = 0usize;
        for draft in drafts {
            let entry = self.entry_from_draft(draft);
            let sealed = session.seal_entry(&entry)?;
            self.entries.insert(&sealed).await?;
            count += 1;
        }
        Ok(count)
    }

    // ---------- encrypted export / import ----------

    /// Exports the entire vault as an encrypted `.goldfish` blob protected by
    /// `export_password` — a password independent of the master password, so the
    /// backup can be shared or re-imported without revealing the master secret.
    /// Requires an unlocked session. Returns the file bytes plus the entry count.
    pub async fn export_vault(
        &self,
        session: &VaultSession,
        export_password: &str,
        params: KdfParams,
    ) -> Result<EncryptedExport, ApplicationError> {
        // Collect and decrypt every entry across all folders.
        let summaries = self.entries.list_summaries(None).await?;
        let mut entries = Vec::with_capacity(summaries.len());
        for summary in summaries {
            let sealed = self
                .entries
                .get(summary.id)
                .await?
                .ok_or(ApplicationError::EntryNotFound(summary.id.0))?;
            entries.push(session.open_entry(&sealed)?);
        }

        let mut bundle = ExportBundle::from_entries(self.clock.now(), &entries);
        // Decrypt and attach each entry's files (1:1 order with `entries`).
        for (export_entry, entry) in bundle.entries.iter_mut().zip(&entries) {
            let metas = self.entries.list_attachments(entry.id).await?;
            let mut atts = Vec::with_capacity(metas.len());
            for meta in metas {
                if let Some(sealed) = self.entries.get_attachment(meta.id).await? {
                    let bytes =
                        session.open_attachment(sealed.entry_id, sealed.id, &sealed.blob)?;
                    atts.push(crate::export::ExportAttachment {
                        name: sealed.name,
                        data: bytes.to_vec(),
                    });
                }
            }
            export_entry.attachments = atts;
        }
        // `json` is zeroizing storage — the plaintext buffer is wiped on drop.
        let json = crate::export::serialize_bundle(&bundle)?;
        let bytes = goldfish_crypto::export::seal(
            export_password.as_bytes(),
            to_argon(params),
            json.as_slice(),
        )
        .map_err(|e| ApplicationError::Crypto(e.to_string()))?;

        Ok(EncryptedExport {
            bytes,
            entry_count: entries.len(),
        })
    }

    /// Imports entries from an encrypted `.goldfish` blob into the vault, returning
    /// how many were added. Requires an unlocked session. A wrong password (or a
    /// tampered file) yields [`ApplicationError::InvalidExportPassword`]; a
    /// malformed/unsupported container yields [`ApplicationError::Export`].
    pub async fn import_vault_file(
        &self,
        session: &VaultSession,
        file: &[u8],
        export_password: &str,
    ) -> Result<usize, ApplicationError> {
        let json = goldfish_crypto::export::open(export_password.as_bytes(), file).map_err(
            |e| match e {
                goldfish_crypto::CryptoError::Decryption => ApplicationError::InvalidExportPassword,
                goldfish_crypto::CryptoError::InvalidFormat(reason) => {
                    ApplicationError::Export(reason.to_owned())
                }
                other => ApplicationError::Crypto(other.to_string()),
            },
        )?;
        let bundle = crate::export::deserialize_bundle(&json)?;
        // Each entry is created first (to get its id), then its attachments are
        // re-sealed under that id.
        let mut count = 0usize;
        for (draft, attachments) in bundle.into_drafts_with_attachments() {
            let entry = self.entry_from_draft(draft);
            let sealed = session.seal_entry(&entry)?;
            self.entries.insert(&sealed).await?;
            for att in attachments {
                if att.data.len() > MAX_ATTACHMENT_SIZE {
                    continue; // defensive: skip anything over the cap
                }
                let attachment_id = Uuid::now_v7();
                let blob = session.seal_attachment(entry.id, attachment_id, &att.data)?;
                self.entries
                    .add_attachment(&SealedAttachment {
                        id: attachment_id,
                        entry_id: entry.id,
                        name: att.name,
                        size: u64::try_from(att.data.len()).unwrap_or(u64::MAX),
                        blob,
                    })
                    .await?;
            }
            count += 1;
        }
        Ok(count)
    }

    /// Scans the whole vault for weak/reused/stale passwords and missing 2FA.
    /// Requires an unlocked session. `weak_below` is a 0–4 zxcvbn threshold and
    /// `stale_after_days` the staleness window.
    pub async fn vault_health(
        &self,
        session: &VaultSession,
        weak_below: u8,
        stale_after_days: i64,
    ) -> Result<crate::health::HealthReport, ApplicationError> {
        let summaries = self.entries.list_summaries(None).await?;
        let mut entries = Vec::with_capacity(summaries.len());
        for summary in summaries {
            let sealed = self
                .entries
                .get(summary.id)
                .await?
                .ok_or(ApplicationError::EntryNotFound(summary.id.0))?;
            entries.push(session.open_entry(&sealed)?);
        }
        Ok(crate::health::analyze(
            &entries,
            self.clock.now(),
            weak_below,
            stale_after_days,
        ))
    }

    /// Phase 1 of a vault-wide breach scan: hash every password, no network I/O.
    ///
    /// Decrypts every entry and pre-computes the SHA-1 of each non-empty password,
    /// returning one [`crate::hibp::BreachTarget`] per entry. This is the only
    /// phase that needs the unlocked session, so the caller can run it under the
    /// session lock and then **release the lock** before
    /// [`Self::scan_breach_targets`]. The plaintext password never leaves this
    /// method — only its SHA-1 hash does.
    pub async fn collect_breach_targets(
        &self,
        session: &VaultSession,
    ) -> Result<Vec<crate::hibp::BreachTarget>, ApplicationError> {
        let summaries = self.entries.list_summaries(None).await?;
        let mut targets = Vec::new();
        for summary in summaries {
            let sealed = self
                .entries
                .get(summary.id)
                .await?
                .ok_or(ApplicationError::EntryNotFound(summary.id.0))?;
            let entry = session.open_entry(&sealed)?;
            let sha1 = {
                let password = entry.password.expose();
                if password.is_empty() {
                    continue;
                }
                crate::hibp::sha1_hex_upper(password.as_bytes())
            };
            targets.push(crate::hibp::BreachTarget {
                id: summary.id.0,
                title: entry.title.clone(),
                sha1,
            });
        }
        Ok(targets)
    }

    /// Phase 2 of a vault-wide breach scan: query HIBP, needs **no session**.
    ///
    /// Returns the targets found in known breaches (newest count). Unique passwords
    /// are checked once (duplicate hashes reuse the result), and only the SHA-1
    /// prefix of each leaves the device. Run it after releasing the session lock so
    /// a slow network scan never blocks other vault operations.
    pub async fn scan_breach_targets(
        &self,
        targets: Vec<crate::hibp::BreachTarget>,
        pwned: &dyn PwnedRangeSource,
    ) -> Result<Vec<crate::hibp::BreachItem>, ApplicationError> {
        let mut cache: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut out = Vec::new();
        for target in targets {
            let count = if let Some(cached) = cache.get(&target.sha1).copied() {
                cached
            } else {
                let fresh = crate::hibp::check_pwned_hash(pwned, &target.sha1).await?;
                cache.insert(target.sha1.clone(), fresh);
                fresh
            };
            if count > 0 {
                out.push(crate::hibp::BreachItem {
                    id: target.id,
                    title: target.title,
                    count,
                });
            }
        }
        Ok(out)
    }

    /// Loads and decrypts a single entry.
    pub async fn get_entry(
        &self,
        session: &VaultSession,
        id: EntryId,
    ) -> Result<Entry, ApplicationError> {
        let sealed = self
            .entries
            .get(id)
            .await?
            .ok_or(ApplicationError::EntryNotFound(id.0))?;
        session.open_entry(&sealed)
    }

    /// Lists plaintext entry summaries (no secrets decrypted).
    pub async fn list_entries(
        &self,
        folder_id: Option<Uuid>,
    ) -> Result<Vec<EntrySummary>, ApplicationError> {
        self.entries.list_summaries(folder_id).await
    }

    /// Re-seals and persists an updated entry, bumping its version and
    /// `updated_at`. Enforces optimistic locking via the repository.
    pub async fn update_entry(
        &self,
        session: &VaultSession,
        mut entry: Entry,
    ) -> Result<Entry, ApplicationError> {
        // Snapshot the previous password into history if it actually changed.
        if let Some(current) = self.entries.get(entry.id).await? {
            let previous = session.open_entry(&current)?;
            if previous.password.expose() != entry.password.expose() {
                let history_id = Uuid::now_v7();
                let sealed = session.seal_history_password(
                    entry.id,
                    history_id,
                    previous.password.expose(),
                )?;
                self.entries
                    .add_password_history(&SealedPasswordHistory {
                        id: history_id,
                        entry_id: entry.id,
                        password: sealed,
                        changed_at: self.clock.now(),
                    })
                    .await?;
            }
        }

        entry.version = entry.version.saturating_add(1);
        entry.updated_at = self.clock.now();
        let sealed = session.seal_entry(&entry)?;
        self.entries.update(&sealed).await?;
        Ok(entry)
    }

    /// Returns an entry's previous passwords (newest first), decrypted. Requires
    /// an unlocked session.
    pub async fn password_history(
        &self,
        session: &VaultSession,
        id: EntryId,
    ) -> Result<Vec<PasswordHistoryEntry>, ApplicationError> {
        let rows = self.entries.list_password_history(id).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let password = session.open_history_password(row.entry_id, row.id, &row.password)?;
            out.push(PasswordHistoryEntry {
                changed_at: row.changed_at,
                password,
            });
        }
        Ok(out)
    }

    /// Deletes an entry by id (idempotent).
    pub async fn delete_entry(&self, id: EntryId) -> Result<(), ApplicationError> {
        self.entries.delete(id).await
    }

    // ---------- folders ----------

    /// Creates a folder from a (validated) name.
    pub async fn create_folder(&self, name: &str) -> Result<Folder, ApplicationError> {
        let folder = Folder::new(name)?;
        self.entries.create_folder(&folder).await?;
        Ok(folder)
    }

    /// Lists all folders.
    pub async fn list_folders(&self) -> Result<Vec<Folder>, ApplicationError> {
        self.entries.list_folders().await
    }

    /// Renames a folder (name re-validated).
    pub async fn rename_folder(&self, id: Uuid, name: &str) -> Result<(), ApplicationError> {
        let name = Folder::validate_name(name)?;
        self.entries.rename_folder(id, &name).await
    }

    /// Sets a folder's appearance overrides (colors validated, font size clamped).
    pub async fn set_folder_appearance(
        &self,
        id: Uuid,
        appearance: Appearance,
    ) -> Result<(), ApplicationError> {
        let appearance = appearance.sanitized()?;
        self.entries.set_folder_appearance(id, &appearance).await
    }

    /// Deletes a folder; its entries are kept and become unfiled.
    pub async fn delete_folder(&self, id: Uuid) -> Result<(), ApplicationError> {
        self.entries.delete_folder(id).await
    }

    // ---------- attachments ----------

    /// Attaches a file to an entry: validates the size, seals the bytes (bound to
    /// the entry and a fresh attachment id), and stores it. Returns the new
    /// attachment's metadata. Requires an unlocked session.
    pub async fn add_attachment(
        &self,
        session: &VaultSession,
        entry_id: EntryId,
        name: &str,
        bytes: &[u8],
    ) -> Result<AttachmentMeta, ApplicationError> {
        if bytes.len() > MAX_ATTACHMENT_SIZE {
            return Err(ApplicationError::Domain(
                goldfish_domain::DomainError::InvalidField {
                    field: "attachment",
                    reason: "file exceeds the maximum attachment size",
                },
            ));
        }
        let id = Uuid::now_v7();
        let blob = session.seal_attachment(entry_id, id, bytes)?;
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let name = name.to_owned();
        self.entries
            .add_attachment(&SealedAttachment {
                id,
                entry_id,
                name: name.clone(),
                size,
                blob,
            })
            .await?;
        Ok(AttachmentMeta { id, name, size })
    }

    /// Lists an entry's attachment metadata (no file bytes).
    pub async fn list_attachments(
        &self,
        entry_id: EntryId,
    ) -> Result<Vec<AttachmentMeta>, ApplicationError> {
        self.entries.list_attachments(entry_id).await
    }

    /// Opens an attachment, returning its file name and decrypted bytes (zeroized
    /// on drop). Requires an unlocked session.
    pub async fn open_attachment(
        &self,
        session: &VaultSession,
        id: Uuid,
    ) -> Result<(String, Zeroizing<Vec<u8>>), ApplicationError> {
        let sealed = self
            .entries
            .get_attachment(id)
            .await?
            .ok_or(ApplicationError::EntryNotFound(id))?;
        let bytes = session.open_attachment(sealed.entry_id, sealed.id, &sealed.blob)?;
        Ok((sealed.name, bytes))
    }

    /// Deletes an attachment by id (idempotent).
    pub async fn delete_attachment(&self, id: Uuid) -> Result<(), ApplicationError> {
        self.entries.delete_attachment(id).await
    }

    // ---------- tags ----------

    /// Creates a tag from a (validated) name.
    pub async fn create_tag(&self, name: &str) -> Result<Tag, ApplicationError> {
        let tag = Tag::new(name)?;
        self.entries.create_tag(&tag).await?;
        Ok(tag)
    }

    /// Lists all tags.
    pub async fn list_tags(&self) -> Result<Vec<Tag>, ApplicationError> {
        self.entries.list_tags().await
    }

    /// Renames a tag (name re-validated).
    pub async fn rename_tag(&self, id: Uuid, name: &str) -> Result<(), ApplicationError> {
        let name = Tag::validate_name(name)?;
        self.entries.rename_tag(id, &name).await
    }

    /// Deletes a tag; it is removed from any entries it was applied to.
    pub async fn delete_tag(&self, id: Uuid) -> Result<(), ApplicationError> {
        self.entries.delete_tag(id).await
    }

    // ---------- manual ordering ----------

    /// Persists the user's manual ordering for one view. `folder_id` is `None`
    /// for the "all entries" view or `Some(id)` for a folder; `ids` is the full
    /// ordered list of entry ids in that view.
    pub async fn reorder_entries(
        &self,
        folder_id: Option<Uuid>,
        ids: &[EntryId],
    ) -> Result<(), ApplicationError> {
        self.entries.reorder_entries(folder_id, ids).await
    }

    /// Moves an entry to a folder (`None` = unfiled), appending it to the end of
    /// that folder's ordering.
    pub async fn move_entry_to_folder(
        &self,
        id: EntryId,
        folder_id: Option<Uuid>,
    ) -> Result<(), ApplicationError> {
        self.entries.move_entry_to_folder(id, folder_id).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use goldfish_domain::{EntrySummary, PlaintextSecret, SealedEntry};

    use super::*;
    use crate::ports::{EntryRepository, OsKeyStore, VaultMetadataRepository, VaultStore};

    // ---- in-memory port implementations (real crypto, fake I/O) ----

    #[derive(Default)]
    struct InMemEntries {
        rows: Mutex<HashMap<Uuid, SealedEntry>>,
        history: Mutex<Vec<SealedPasswordHistory>>,
        folders: Mutex<Vec<Folder>>,
        tags: Mutex<Vec<Tag>>,
        attachments: Mutex<Vec<SealedAttachment>>,
        all_pos: Mutex<HashMap<Uuid, i64>>,
        folder_pos: Mutex<HashMap<Uuid, i64>>,
        seq: Mutex<i64>,
    }

    #[async_trait]
    impl EntryRepository for InMemEntries {
        async fn insert(&self, entry: &SealedEntry) -> Result<(), ApplicationError> {
            self.rows.lock().unwrap().insert(entry.id.0, entry.clone());
            // Append to the end of both orderings. A monotonic counter keeps the
            // relative order within any folder as well as across all entries.
            let mut seq = self.seq.lock().unwrap();
            let pos = *seq;
            *seq += 1;
            self.all_pos.lock().unwrap().insert(entry.id.0, pos);
            self.folder_pos.lock().unwrap().insert(entry.id.0, pos);
            Ok(())
        }

        async fn update(&self, entry: &SealedEntry) -> Result<(), ApplicationError> {
            let mut rows = self.rows.lock().unwrap();
            let old_folder = match rows.get(&entry.id.0) {
                None => return Err(ApplicationError::EntryNotFound(entry.id.0)),
                Some(existing) => {
                    if existing.version.saturating_add(1) != entry.version {
                        return Err(ApplicationError::VersionConflict);
                    }
                    existing.folder_id
                }
            };
            rows.insert(entry.id.0, entry.clone());
            // A folder change appends to the end of the new folder's ordering.
            if old_folder != entry.folder_id {
                let mut fpos = self.folder_pos.lock().unwrap();
                let max = rows
                    .values()
                    .filter(|e| e.id != entry.id && e.folder_id == entry.folder_id)
                    .filter_map(|e| fpos.get(&e.id.0).copied())
                    .max();
                fpos.insert(entry.id.0, max.map_or(0, |m| m + 1));
            }
            Ok(())
        }

        async fn get(&self, id: EntryId) -> Result<Option<SealedEntry>, ApplicationError> {
            Ok(self.rows.lock().unwrap().get(&id.0).cloned())
        }

        async fn list_summaries(
            &self,
            folder_id: Option<Uuid>,
        ) -> Result<Vec<EntrySummary>, ApplicationError> {
            let rows = self.rows.lock().unwrap();
            let all_pos = self.all_pos.lock().unwrap();
            let folder_pos = self.folder_pos.lock().unwrap();
            let mut out: Vec<(i64, EntrySummary)> = rows
                .values()
                .filter(|e| folder_id.is_none_or(|f| e.folder_id == Some(f)))
                .map(|e| {
                    let pos = if folder_id.is_none() {
                        all_pos.get(&e.id.0).copied().unwrap_or(0)
                    } else {
                        folder_pos.get(&e.id.0).copied().unwrap_or(0)
                    };
                    (
                        pos,
                        EntrySummary {
                            id: e.id,
                            kind: e.kind,
                            title: e.title.clone(),
                            url: e.url.clone(),
                            app_name: e.app_name.clone(),
                            favorite: e.favorite,
                            folder_id: e.folder_id,
                            tags: e.tags.clone(),
                            updated_at: e.updated_at,
                        },
                    )
                })
                .collect();
            // Order by the view's position, with title as a stable tie-breaker.
            out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.title.cmp(&b.1.title)));
            Ok(out.into_iter().map(|(_, s)| s).collect())
        }

        async fn delete(&self, id: EntryId) -> Result<(), ApplicationError> {
            self.rows.lock().unwrap().remove(&id.0);
            self.all_pos.lock().unwrap().remove(&id.0);
            self.folder_pos.lock().unwrap().remove(&id.0);
            self.attachments
                .lock()
                .unwrap()
                .retain(|a| a.entry_id != id);
            Ok(())
        }

        async fn add_password_history(
            &self,
            record: &SealedPasswordHistory,
        ) -> Result<(), ApplicationError> {
            self.history.lock().unwrap().push(record.clone());
            Ok(())
        }

        async fn list_password_history(
            &self,
            entry_id: EntryId,
        ) -> Result<Vec<SealedPasswordHistory>, ApplicationError> {
            let mut rows: Vec<SealedPasswordHistory> = self
                .history
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.entry_id == entry_id)
                .cloned()
                .collect();
            rows.sort_by_key(|r| std::cmp::Reverse(r.changed_at));
            Ok(rows)
        }

        async fn create_folder(&self, folder: &Folder) -> Result<(), ApplicationError> {
            self.folders.lock().unwrap().push(folder.clone());
            Ok(())
        }

        async fn list_folders(&self) -> Result<Vec<Folder>, ApplicationError> {
            let mut folders = self.folders.lock().unwrap().clone();
            folders.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(folders)
        }

        async fn rename_folder(&self, id: Uuid, name: &str) -> Result<(), ApplicationError> {
            if let Some(f) = self.folders.lock().unwrap().iter_mut().find(|f| f.id == id) {
                f.name = name.to_owned();
            }
            Ok(())
        }

        async fn set_folder_appearance(
            &self,
            id: Uuid,
            appearance: &goldfish_domain::Appearance,
        ) -> Result<(), ApplicationError> {
            if let Some(f) = self.folders.lock().unwrap().iter_mut().find(|f| f.id == id) {
                f.appearance = appearance.clone();
            }
            Ok(())
        }

        async fn delete_folder(&self, id: Uuid) -> Result<(), ApplicationError> {
            self.folders.lock().unwrap().retain(|f| f.id != id);
            for entry in self.rows.lock().unwrap().values_mut() {
                if entry.folder_id == Some(id) {
                    entry.folder_id = None;
                }
            }
            Ok(())
        }

        async fn add_attachment(
            &self,
            attachment: &SealedAttachment,
        ) -> Result<(), ApplicationError> {
            self.attachments.lock().unwrap().push(attachment.clone());
            Ok(())
        }

        async fn list_attachments(
            &self,
            entry_id: EntryId,
        ) -> Result<Vec<AttachmentMeta>, ApplicationError> {
            Ok(self
                .attachments
                .lock()
                .unwrap()
                .iter()
                .filter(|a| a.entry_id == entry_id)
                .map(|a| AttachmentMeta {
                    id: a.id,
                    name: a.name.clone(),
                    size: a.size,
                })
                .collect())
        }

        async fn get_attachment(
            &self,
            id: Uuid,
        ) -> Result<Option<SealedAttachment>, ApplicationError> {
            Ok(self
                .attachments
                .lock()
                .unwrap()
                .iter()
                .find(|a| a.id == id)
                .cloned())
        }

        async fn delete_attachment(&self, id: Uuid) -> Result<(), ApplicationError> {
            self.attachments.lock().unwrap().retain(|a| a.id != id);
            Ok(())
        }

        async fn create_tag(&self, tag: &Tag) -> Result<(), ApplicationError> {
            self.tags.lock().unwrap().push(tag.clone());
            Ok(())
        }

        async fn list_tags(&self) -> Result<Vec<Tag>, ApplicationError> {
            let mut tags = self.tags.lock().unwrap().clone();
            tags.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(tags)
        }

        async fn rename_tag(&self, id: Uuid, name: &str) -> Result<(), ApplicationError> {
            if let Some(t) = self.tags.lock().unwrap().iter_mut().find(|t| t.id == id) {
                t.name = name.to_owned();
            }
            Ok(())
        }

        async fn delete_tag(&self, id: Uuid) -> Result<(), ApplicationError> {
            self.tags.lock().unwrap().retain(|t| t.id != id);
            for entry in self.rows.lock().unwrap().values_mut() {
                entry.tags.retain(|t| *t != id);
            }
            Ok(())
        }

        async fn reorder_entries(
            &self,
            folder_id: Option<Uuid>,
            ids: &[EntryId],
        ) -> Result<(), ApplicationError> {
            let mut map = if folder_id.is_none() {
                self.all_pos.lock().unwrap()
            } else {
                self.folder_pos.lock().unwrap()
            };
            for (i, id) in ids.iter().enumerate() {
                map.insert(id.0, i64::try_from(i).unwrap());
            }
            Ok(())
        }

        async fn move_entry_to_folder(
            &self,
            id: EntryId,
            folder_id: Option<Uuid>,
        ) -> Result<(), ApplicationError> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(e) = rows.get_mut(&id.0) {
                e.folder_id = folder_id;
            }
            let mut fpos = self.folder_pos.lock().unwrap();
            let max = rows
                .values()
                .filter(|e| e.id != id && e.folder_id == folder_id)
                .filter_map(|e| fpos.get(&e.id.0).copied())
                .max();
            fpos.insert(id.0, max.map_or(0, |m| m + 1));
            Ok(())
        }
    }

    // In-memory store: the key/lifecycle is a no-op (data lives in `rows`).
    #[async_trait]
    impl VaultStore for InMemEntries {
        async fn open(&self, _db_key: &[u8; 32]) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn close(&self) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn is_open(&self) -> bool {
            true
        }

        async fn list_backups(&self) -> Result<Vec<crate::ports::BackupInfo>, ApplicationError> {
            Ok(Vec::new())
        }

        async fn restore_backup(&self, _file_name: &str) -> Result<(), ApplicationError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct InMemMeta {
        row: Mutex<Option<VaultMetadata>>,
    }

    #[async_trait]
    impl VaultMetadataRepository for InMemMeta {
        async fn load(&self) -> Result<Option<VaultMetadata>, ApplicationError> {
            Ok(self.row.lock().unwrap().clone())
        }

        async fn save(&self, meta: &VaultMetadata) -> Result<(), ApplicationError> {
            *self.row.lock().unwrap() = Some(meta.clone());
            Ok(())
        }
    }

    struct FixedClock(DateTime<Utc>);

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// In-memory keystore. `available` toggles biometric support; secrets live
    /// in a map (no real biometric prompt in tests).
    struct InMemKeystore {
        available: bool,
        secrets: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl InMemKeystore {
        fn new(available: bool) -> Self {
            Self {
                available,
                secrets: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl OsKeyStore for InMemKeystore {
        fn biometrics_available(&self) -> bool {
            self.available
        }

        async fn store(&self, label: &str, secret: &[u8]) -> Result<(), ApplicationError> {
            self.secrets
                .lock()
                .unwrap()
                .insert(label.to_owned(), secret.to_vec());
            Ok(())
        }

        async fn retrieve(&self, label: &str) -> Result<Vec<u8>, ApplicationError> {
            self.secrets
                .lock()
                .unwrap()
                .get(label)
                .cloned()
                .ok_or(ApplicationError::BiometricNotEnabled)
        }

        async fn delete(&self, label: &str) -> Result<(), ApplicationError> {
            self.secrets.lock().unwrap().remove(label);
            Ok(())
        }
    }

    // ---- helpers ----

    /// Low-cost KDF so the suite stays fast (real vaults use `KdfParams::DEFAULT`).
    fn fast_params() -> KdfParams {
        KdfParams {
            memory_kib: 256,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn service_with(keystore: Arc<dyn OsKeyStore>) -> VaultService {
        let entries = Arc::new(InMemEntries::default());
        VaultService::new(
            entries.clone(),
            entries,
            Arc::new(InMemMeta::default()),
            Arc::new(FixedClock(
                DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            )),
            keystore,
        )
        // Keep the upgrade floor at the test cost so unlocking stays cheap.
        .with_kdf_floor(fast_params())
    }

    fn service() -> VaultService {
        service_with(Arc::new(InMemKeystore::new(true)))
    }

    fn draft(title: &str, user: &str, pass: &str) -> EntryDraft {
        EntryDraft::new(title, user, PlaintextSecret::from(pass)).unwrap()
    }

    /// Returns a canned HIBP range body for every prefix and counts the calls, so
    /// tests can assert deduplication and that the network phase ran.
    struct MockPwned {
        body: String,
        calls: Mutex<usize>,
    }

    #[async_trait]
    impl crate::ports::PwnedRangeSource for MockPwned {
        async fn fetch_range(&self, _prefix: &str) -> Result<String, ApplicationError> {
            *self.calls.lock().unwrap() += 1;
            Ok(self.body.clone())
        }
    }

    // ---- vault lifecycle ----

    #[tokio::test]
    async fn vault_does_not_exist_initially() {
        let svc = service();
        assert!(!svc.vault_exists().await.unwrap());
    }

    #[tokio::test]
    async fn create_marks_vault_as_existing() {
        let svc = service();
        svc.create_vault("master", fast_params()).await.unwrap();
        assert!(svc.vault_exists().await.unwrap());
    }

    #[tokio::test]
    async fn create_twice_fails() {
        let svc = service();
        svc.create_vault("master", fast_params()).await.unwrap();
        let err = svc.create_vault("master", fast_params()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::VaultAlreadyExists));
    }

    #[tokio::test]
    async fn unlock_without_vault_fails() {
        let svc = service();
        let err = svc.unlock_vault("master").await.unwrap_err();
        assert!(matches!(err, ApplicationError::VaultNotFound));
    }

    #[tokio::test]
    async fn unlock_with_correct_password_succeeds() {
        let svc = service();
        svc.create_vault("master", fast_params()).await.unwrap();
        assert!(svc.unlock_vault("master").await.is_ok());
    }

    #[tokio::test]
    async fn unlock_with_wrong_password_fails() {
        let svc = service();
        svc.create_vault("master", fast_params()).await.unwrap();
        let err = svc.unlock_vault("WRONG").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidMasterPassword));
    }

    #[tokio::test]
    async fn unlock_upgrades_weak_kdf_parameters() {
        let entries = Arc::new(InMemEntries::default());
        let meta = Arc::new(InMemMeta::default());
        let svc = VaultService::new(
            entries.clone(),
            entries,
            meta.clone(),
            Arc::new(FixedClock(
                DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            )),
            Arc::new(InMemKeystore::new(true)),
        )
        .with_kdf_floor(KdfParams {
            memory_kib: 512,
            iterations: 1,
            parallelism: 1,
        });

        // Create with parameters below the floor.
        let weak = KdfParams {
            memory_kib: 256,
            iterations: 1,
            parallelism: 1,
        };
        svc.create_vault("master", weak).await.unwrap();
        let before = meta.load().await.unwrap().unwrap();
        assert_eq!(before.kdf_params, weak);

        // Unlocking transparently re-wraps the vault up to the floor.
        let session = svc.unlock_vault("master").await.unwrap();
        let after = meta.load().await.unwrap().unwrap();
        assert_eq!(after.kdf_params.memory_kib, 512);
        assert_ne!(after.kdf_salt, before.kdf_salt);

        // The vault still works after the re-wrap (DEK unchanged).
        let created = svc
            .add_entry(&session, draft("X", "u", "secret"))
            .await
            .unwrap();
        let loaded = svc.get_entry(&session, created.id).await.unwrap();
        assert_eq!(loaded.password.expose(), "secret");

        // A fresh unlock now finds params at the floor — no second upgrade.
        drop(session);
        svc.unlock_vault("master").await.unwrap();
        let after2 = meta.load().await.unwrap().unwrap();
        assert_eq!(after2.kdf_salt, after.kdf_salt);
    }

    #[tokio::test]
    async fn repeated_wrong_password_is_throttled() {
        let svc = service();
        svc.create_vault("master", fast_params()).await.unwrap();

        // First wrong attempt fails normally and arms the backoff window.
        let first = svc.unlock_vault("WRONG").await.unwrap_err();
        assert!(matches!(first, ApplicationError::InvalidMasterPassword));

        // The fixed test clock does not advance, so the window is still open:
        // the next attempt is throttled — even with the *correct* password
        // (the guard runs before the password is checked).
        let second = svc.unlock_vault("WRONG").await.unwrap_err();
        assert!(matches!(
            second,
            ApplicationError::UnlockThrottled { retry_after_secs } if retry_after_secs >= 1
        ));
        let correct = svc.unlock_vault("master").await.unwrap_err();
        assert!(matches!(correct, ApplicationError::UnlockThrottled { .. }));
    }

    #[tokio::test]
    async fn unlock_throttle_survives_restart() {
        // Two service instances over the SAME metadata simulate an app restart:
        // a backoff armed by the first must still block the second (a fresh
        // in-memory throttle), so relaunching can't reset the window.
        let entries = Arc::new(InMemEntries::default());
        let meta = Arc::new(InMemMeta::default());
        let clock = Arc::new(FixedClock(
            DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        ));
        let make = || {
            VaultService::new(
                entries.clone(),
                entries.clone(),
                meta.clone(),
                clock.clone(),
                Arc::new(InMemKeystore::new(true)),
            )
            .with_kdf_floor(fast_params())
        };

        let svc1 = make();
        svc1.create_vault("master", fast_params()).await.unwrap();
        assert!(matches!(
            svc1.unlock_vault("WRONG").await.unwrap_err(),
            ApplicationError::InvalidMasterPassword
        ));

        // Fresh instance, correct password, same frozen instant: still throttled
        // because the backoff was persisted.
        let svc2 = make();
        assert!(matches!(
            svc2.unlock_vault("master").await.unwrap_err(),
            ApplicationError::UnlockThrottled { .. }
        ));
    }

    // ---- entry CRUD ----

    #[tokio::test]
    async fn add_then_get_round_trips_secrets() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();

        let created = svc
            .add_entry(&session, draft("GitHub", "octocat", "hunter2"))
            .await
            .unwrap();

        let loaded = svc.get_entry(&session, created.id).await.unwrap();
        assert_eq!(loaded.title, "GitHub");
        assert_eq!(loaded.username, "octocat");
        assert_eq!(loaded.password.expose(), "hunter2");
        assert_eq!(loaded.version, 1);
    }

    #[tokio::test]
    async fn entry_kind_and_custom_fields_round_trip() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();

        let mut draft = draft("Visa", "", "");
        draft.kind = goldfish_domain::EntryKind::Card;
        draft.custom_fields = vec![
            goldfish_domain::CustomField {
                label: "Card number".to_owned(),
                value: PlaintextSecret::from("4111111111111111"),
                hidden: true,
            },
            goldfish_domain::CustomField {
                label: "Expiry".to_owned(),
                value: PlaintextSecret::from("12/29"),
                hidden: false,
            },
        ];

        let created = svc.add_entry(&session, draft).await.unwrap();
        let loaded = svc.get_entry(&session, created.id).await.unwrap();
        assert_eq!(loaded.kind, goldfish_domain::EntryKind::Card);
        assert_eq!(loaded.custom_fields.len(), 2);
        assert_eq!(loaded.custom_fields[0].label, "Card number");
        assert_eq!(loaded.custom_fields[0].value.expose(), "4111111111111111");
        assert!(loaded.custom_fields[0].hidden);
        assert_eq!(loaded.custom_fields[1].value.expose(), "12/29");
        assert!(!loaded.custom_fields[1].hidden);
    }

    #[tokio::test]
    async fn entry_added_in_one_session_decrypts_after_relock() {
        let svc = service();
        let create_session = svc.create_vault("master", fast_params()).await.unwrap();
        let created = svc
            .add_entry(&create_session, draft("Bank", "alice", "s3cret"))
            .await
            .unwrap();
        drop(create_session);

        // Fresh unlock — proves the DEK is stable across sessions.
        let unlock_session = svc.unlock_vault("master").await.unwrap();
        let loaded = svc.get_entry(&unlock_session, created.id).await.unwrap();
        assert_eq!(loaded.password.expose(), "s3cret");
    }

    #[tokio::test]
    async fn get_missing_entry_errors() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let err = svc.get_entry(&session, EntryId::new()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::EntryNotFound(_)));
    }

    #[tokio::test]
    async fn list_returns_summaries_without_decrypting() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        svc.add_entry(&session, draft("Zeta", "u", "p"))
            .await
            .unwrap();
        svc.add_entry(&session, draft("Alpha", "u", "p"))
            .await
            .unwrap();

        let list = svc.list_entries(None).await.unwrap();
        assert_eq!(list.len(), 2);
        // New entries append to the end — default order is insertion order.
        assert_eq!(list[0].title, "Zeta");
        assert_eq!(list[1].title, "Alpha");
    }

    #[tokio::test]
    async fn reorder_persists_independently_per_view() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let folder = svc.create_folder("Work").await.unwrap();

        let mut a = draft("A", "u", "p");
        a.folder_id = Some(folder.id);
        let a = svc.add_entry(&session, a).await.unwrap();
        let mut b = draft("B", "u", "p");
        b.folder_id = Some(folder.id);
        let b = svc.add_entry(&session, b).await.unwrap();
        let mut c = draft("C", "u", "p");
        c.folder_id = Some(folder.id);
        let c = svc.add_entry(&session, c).await.unwrap();

        let titles =
            |list: Vec<EntrySummary>| list.into_iter().map(|e| e.title).collect::<Vec<_>>();

        // Reorder the All-entries view to C, A, B.
        svc.reorder_entries(None, &[c.id, a.id, b.id])
            .await
            .unwrap();
        assert_eq!(
            titles(svc.list_entries(None).await.unwrap()),
            ["C", "A", "B"]
        );

        // The folder view keeps its own (still insertion) order — independent.
        assert_eq!(
            titles(svc.list_entries(Some(folder.id)).await.unwrap()),
            ["A", "B", "C"]
        );

        // Reordering the folder view does not disturb the All-entries order.
        svc.reorder_entries(Some(folder.id), &[b.id, c.id, a.id])
            .await
            .unwrap();
        assert_eq!(
            titles(svc.list_entries(Some(folder.id)).await.unwrap()),
            ["B", "C", "A"]
        );
        assert_eq!(
            titles(svc.list_entries(None).await.unwrap()),
            ["C", "A", "B"]
        );
    }

    #[tokio::test]
    async fn move_entry_to_folder_appends_and_keeps_all_order() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let folder = svc.create_folder("Work").await.unwrap();

        let mut x = draft("X", "u", "p");
        x.folder_id = Some(folder.id);
        svc.add_entry(&session, x).await.unwrap();
        // Y starts unfiled, then moves into the folder.
        let y = svc.add_entry(&session, draft("Y", "u", "p")).await.unwrap();

        assert_eq!(svc.list_entries(Some(folder.id)).await.unwrap().len(), 1);

        svc.move_entry_to_folder(y.id, Some(folder.id))
            .await
            .unwrap();
        let in_folder: Vec<_> = svc
            .list_entries(Some(folder.id))
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.title)
            .collect();
        // Appended to the end of the folder.
        assert_eq!(in_folder, ["X", "Y"]);

        // Moving out (unfiled) removes it from the folder view.
        svc.move_entry_to_folder(y.id, None).await.unwrap();
        assert_eq!(svc.list_entries(Some(folder.id)).await.unwrap().len(), 1);
        assert_eq!(svc.list_entries(None).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn update_bumps_version_and_persists_changes() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let mut entry = svc
            .add_entry(&session, draft("Mail", "bob", "old-pass"))
            .await
            .unwrap();

        entry.password = PlaintextSecret::from("new-pass");
        let updated = svc.update_entry(&session, entry).await.unwrap();
        assert_eq!(updated.version, 2);

        let loaded = svc.get_entry(&session, updated.id).await.unwrap();
        assert_eq!(loaded.password.expose(), "new-pass");
        assert_eq!(loaded.version, 2);
    }

    #[tokio::test]
    async fn stale_update_conflicts() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let entry = svc
            .add_entry(&session, draft("Mail", "bob", "p"))
            .await
            .unwrap();

        // First update succeeds (v1 -> v2).
        svc.update_entry(&session, entry.clone()).await.unwrap();
        // Second update uses the stale v1 copy -> conflict.
        let err = svc.update_entry(&session, entry).await.unwrap_err();
        assert!(matches!(err, ApplicationError::VersionConflict));
    }

    #[tokio::test]
    async fn changing_password_records_history() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let mut entry = svc
            .add_entry(&session, draft("Mail", "bob", "old-pass"))
            .await
            .unwrap();
        let id = entry.id;

        // Nothing recorded yet.
        assert!(svc.password_history(&session, id).await.unwrap().is_empty());

        // Changing the password snapshots the old one.
        entry.password = PlaintextSecret::from("new-pass");
        let updated = svc.update_entry(&session, entry).await.unwrap();
        let history = svc.password_history(&session, id).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].password.expose(), "old-pass");

        // Saving again without changing the password records nothing new.
        svc.update_entry(&session, updated).await.unwrap();
        assert_eq!(svc.password_history(&session, id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn folder_crud_and_filtering() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();

        let folder = svc.create_folder("  Work  ").await.unwrap();
        assert_eq!(folder.name, "Work"); // trimmed
        assert_eq!(svc.list_folders().await.unwrap().len(), 1);

        let mut filed = draft("A", "u", "p");
        filed.folder_id = Some(folder.id);
        svc.add_entry(&session, filed).await.unwrap();
        svc.add_entry(&session, draft("B", "u", "p")).await.unwrap();

        // Filtering by folder returns only the filed entry.
        let in_folder = svc.list_entries(Some(folder.id)).await.unwrap();
        assert_eq!(in_folder.len(), 1);
        assert_eq!(in_folder[0].title, "A");

        svc.rename_folder(folder.id, "Personal").await.unwrap();
        assert_eq!(svc.list_folders().await.unwrap()[0].name, "Personal");

        // Appearance overrides round-trip (colors validated, font clamped).
        svc.set_folder_appearance(
            folder.id,
            Appearance {
                background: Some("#102030".to_owned()),
                bold: true,
                font_size: Some(999),
                ..Appearance::default()
            },
        )
        .await
        .unwrap();
        let styled = svc.list_folders().await.unwrap()[0].appearance.clone();
        assert_eq!(styled.background.as_deref(), Some("#102030"));
        assert!(styled.bold);
        assert_eq!(styled.font_size, Some(Appearance::MAX_FONT));

        // Deleting a folder keeps its entries (now unfiled).
        svc.delete_folder(folder.id).await.unwrap();
        assert!(svc.list_folders().await.unwrap().is_empty());
        assert_eq!(svc.list_entries(None).await.unwrap().len(), 2);
        assert!(svc.list_entries(Some(folder.id)).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn attachment_round_trips_and_enforces_size() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let entry = svc.add_entry(&session, draft("X", "u", "p")).await.unwrap();

        let bytes = b"\x00\x01\x02 secret file contents \xff";
        let meta = svc
            .add_attachment(&session, entry.id, "notes.bin", bytes)
            .await
            .unwrap();
        assert_eq!(meta.name, "notes.bin");
        assert_eq!(meta.size, bytes.len() as u64);

        let list = svc.list_attachments(entry.id).await.unwrap();
        assert_eq!(list.len(), 1);

        let (name, data) = svc.open_attachment(&session, meta.id).await.unwrap();
        assert_eq!(name, "notes.bin");
        assert_eq!(data.as_slice(), bytes);

        // Oversized files are rejected.
        let huge = vec![0u8; goldfish_domain::MAX_ATTACHMENT_SIZE + 1];
        let err = svc
            .add_attachment(&session, entry.id, "huge.bin", &huge)
            .await
            .unwrap_err();
        assert!(matches!(err, ApplicationError::Domain(_)));

        // Deleting the entry cascades its attachments.
        svc.delete_entry(entry.id).await.unwrap();
        assert!(svc.list_attachments(entry.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_removes_entry() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let entry = svc.add_entry(&session, draft("X", "u", "p")).await.unwrap();

        svc.delete_entry(entry.id).await.unwrap();
        let err = svc.get_entry(&session, entry.id).await.unwrap_err();
        assert!(matches!(err, ApplicationError::EntryNotFound(_)));
    }

    #[tokio::test]
    async fn tampering_with_stored_ciphertext_is_detected() {
        // Simulates on-disk corruption / tampering: flipping a ciphertext byte
        // must make decryption fail (AEAD authentication).
        let entries = Arc::new(InMemEntries::default());
        let svc = VaultService::new(
            entries.clone(),
            entries.clone(),
            Arc::new(InMemMeta::default()),
            Arc::new(FixedClock(
                DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            )),
            Arc::new(InMemKeystore::new(true)),
        );
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let entry = svc.add_entry(&session, draft("X", "u", "p")).await.unwrap();

        // Corrupt the stored password ciphertext.
        {
            let mut rows = entries.rows.lock().unwrap();
            let row = rows.get_mut(&entry.id.0).unwrap();
            row.password.ciphertext[0] ^= 0x01;
        }

        let err = svc.get_entry(&session, entry.id).await.unwrap_err();
        assert!(matches!(err, ApplicationError::Crypto(_)));
    }

    // ---- encrypted export / import ----

    #[tokio::test]
    async fn export_then_import_into_fresh_vault_round_trips() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let gh = svc
            .add_entry(&session, draft("GitHub", "octocat", "hunter2"))
            .await
            .unwrap();
        svc.add_entry(&session, draft("Mail", "alice", "s3cret"))
            .await
            .unwrap();
        // Attach a file to one entry — it must survive the export/import.
        svc.add_attachment(&session, gh.id, "key.bin", b"\x00\xde\xad\xbe\xef")
            .await
            .unwrap();

        let export = svc
            .export_vault(&session, "export-pw", fast_params())
            .await
            .unwrap();
        assert_eq!(export.entry_count, 2);

        // Import into a brand-new vault with a different master password.
        let svc2 = service();
        let session2 = svc2
            .create_vault("other-master", fast_params())
            .await
            .unwrap();
        let count = svc2
            .import_vault_file(&session2, &export.bytes, "export-pw")
            .await
            .unwrap();
        assert_eq!(count, 2);

        let list = svc2.list_entries(None).await.unwrap();
        assert_eq!(list.len(), 2);
        let gh = list.iter().find(|e| e.title == "GitHub").unwrap();
        let loaded = svc2.get_entry(&session2, gh.id).await.unwrap();
        assert_eq!(loaded.username, "octocat");
        assert_eq!(loaded.password.expose(), "hunter2");

        // The attachment round-tripped, re-sealed under the new vault's key.
        let atts = svc2.list_attachments(gh.id).await.unwrap();
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].name, "key.bin");
        let (_, bytes) = svc2.open_attachment(&session2, atts[0].id).await.unwrap();
        assert_eq!(bytes.as_slice(), b"\x00\xde\xad\xbe\xef");
    }

    #[tokio::test]
    async fn import_with_wrong_password_fails() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        svc.add_entry(&session, draft("X", "u", "p")).await.unwrap();
        let export = svc
            .export_vault(&session, "right-pw", fast_params())
            .await
            .unwrap();

        let err = svc
            .import_vault_file(&session, &export.bytes, "wrong-pw")
            .await
            .unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidExportPassword));
    }

    #[tokio::test]
    async fn vault_health_flags_weak_and_reused() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        svc.add_entry(&session, draft("A", "u", "password"))
            .await
            .unwrap();
        svc.add_entry(&session, draft("B", "u", "password"))
            .await
            .unwrap();

        let report = svc.vault_health(&session, 3, 365).await.unwrap();
        assert_eq!(report.total, 2);
        assert_eq!(report.weak.len(), 2); // "password" is weak
        assert_eq!(report.reused.len(), 1); // both share "password"
        assert_eq!(report.reused[0].count, 2);
        assert_eq!(report.without_totp.len(), 2);
    }

    #[tokio::test]
    async fn import_malformed_file_is_export_error() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let err = svc
            .import_vault_file(&session, b"definitely not a goldfish export file", "pw")
            .await
            .unwrap_err();
        assert!(matches!(err, ApplicationError::Export(_)));
    }

    // ---- biometric ----

    #[tokio::test]
    async fn biometric_disabled_by_default() {
        let svc = service();
        svc.create_vault("master", fast_params()).await.unwrap();
        assert!(!svc.biometric_enabled().await.unwrap());
    }

    #[tokio::test]
    async fn enable_then_unlock_with_biometrics() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let created = svc
            .add_entry(&session, draft("GitHub", "octocat", "hunter2"))
            .await
            .unwrap();

        svc.enable_biometric(&session).await.unwrap();
        assert!(svc.biometric_enabled().await.unwrap());

        drop(session);
        svc.lock().await.unwrap();

        // Biometric unlock recovers the same DEK — entry decrypts.
        let bio_session = svc.unlock_biometric().await.unwrap();
        let loaded = svc.get_entry(&bio_session, created.id).await.unwrap();
        assert_eq!(loaded.password.expose(), "hunter2");
    }

    #[tokio::test]
    async fn enable_biometric_fails_when_unavailable() {
        let svc = service_with(Arc::new(InMemKeystore::new(false)));
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        let err = svc.enable_biometric(&session).await.unwrap_err();
        assert!(matches!(err, ApplicationError::BiometricUnavailable));
    }

    #[tokio::test]
    async fn unlock_biometric_fails_when_not_enabled() {
        let svc = service();
        svc.create_vault("master", fast_params()).await.unwrap();
        svc.lock().await.unwrap();
        let err = svc.unlock_biometric().await.unwrap_err();
        assert!(matches!(err, ApplicationError::BiometricNotEnabled));
    }

    #[tokio::test]
    async fn breach_scan_hashes_then_matches_without_session() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let suffix = &sha1[5..];

        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        // Two entries share the breached password; one has a unique password.
        svc.add_entry(&session, draft("Email", "a@x", "password"))
            .await
            .unwrap();
        svc.add_entry(&session, draft("Forum", "b@x", "password"))
            .await
            .unwrap();
        svc.add_entry(&session, draft("Bank", "c@x", "Str0ng-Unique!"))
            .await
            .unwrap();

        // Phase 1 (needs the session): only SHA-1 hashes leave — no plaintext.
        let targets = svc.collect_breach_targets(&session).await.unwrap();
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|t| t.sha1.len() == 40));
        assert_eq!(
            targets.iter().filter(|t| t.sha1.as_str() == sha1).count(),
            2
        );

        // Phase 2 (no session): HIBP reports the shared password 42×, unique absent.
        let pwned = MockPwned {
            body: format!("{suffix}:42\r\n"),
            calls: Mutex::new(0),
        };
        let hits = svc.scan_breach_targets(targets, &pwned).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.count == 42));
        // Duplicate hash fetched once + the unique hash once = 2 network calls.
        assert_eq!(*pwned.calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn disable_biometric_clears_it() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        svc.enable_biometric(&session).await.unwrap();
        svc.disable_biometric().await.unwrap();
        assert!(!svc.biometric_enabled().await.unwrap());
    }

    // ---- recovery code ----

    #[tokio::test]
    async fn recovery_unlocks_and_resets_master_password() {
        let svc = service();
        let session = svc.create_vault("old-master", fast_params()).await.unwrap();
        let created = svc
            .add_entry(&session, draft("X", "u", "secret"))
            .await
            .unwrap();

        let code = svc.enable_recovery(&session).await.unwrap();
        assert!(svc.recovery_enabled().await.unwrap());
        drop(session);
        svc.lock().await.unwrap();

        // Recover with the code, choosing a new master password.
        let recovered = svc.unlock_with_recovery(&code, "new-master").await.unwrap();
        let loaded = svc.get_entry(&recovered, created.id).await.unwrap();
        assert_eq!(loaded.password.expose(), "secret"); // same DEK
        drop(recovered);
        svc.lock().await.unwrap();

        // The new master password now works (throttle was cleared on recovery).
        let again = svc.unlock_vault("new-master").await.unwrap();
        drop(again);
        svc.lock().await.unwrap();

        // The old master password no longer opens the vault.
        let err = svc.unlock_vault("old-master").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidMasterPassword));
    }

    #[tokio::test]
    async fn recovery_with_wrong_code_fails() {
        let svc = service();
        let session = svc.create_vault("master", fast_params()).await.unwrap();
        svc.enable_recovery(&session).await.unwrap();
        let err = svc
            .unlock_with_recovery("WRONG-CODE-0000", "new-master")
            .await
            .unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidRecoveryCode));
    }

    #[tokio::test]
    async fn recovery_unlock_fails_when_not_enabled() {
        let svc = service();
        svc.create_vault("master", fast_params()).await.unwrap();
        let err = svc
            .unlock_with_recovery("ABCD-EFGH", "new-master")
            .await
            .unwrap_err();
        assert!(matches!(err, ApplicationError::RecoveryNotEnabled));
    }
}
