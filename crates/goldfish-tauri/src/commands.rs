//! Tauri command surface — thin wrappers that delegate to the [`VaultService`].
//!
//! Domain types carry non-serializable secrets ([`PlaintextSecret`]), so the IPC
//! boundary uses dedicated camelCase DTOs. Decrypted secrets cross to the
//! frontend only in [`EntryDto`] (for the detail view / clipboard) — never in
//! list summaries.

use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use zeroize::Zeroize;

use goldfish_application::ApplicationError;
use goldfish_domain::{
    Appearance, CustomField, Entry, EntryDraft, EntryId, EntryKind, EntrySummary, KdfParams,
    PassphrasePolicy, PasswordPolicy, PlaintextSecret,
};
use goldfish_infrastructure::OsSecureRandom;
use uuid::Uuid;

use crate::state::AppState;

/// Serializable error returned to the frontend. `kind` is a stable machine code
/// the UI maps to a localized message; `message` is a developer-facing detail.
#[derive(Debug, Serialize)]
pub struct CommandError {
    /// Stable error code (e.g. `invalid_password`).
    pub kind: String,
    /// Human-readable detail (English; not localized).
    pub message: String,
}

impl CommandError {
    fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_owned(),
            message: message.into(),
        }
    }
}

impl From<ApplicationError> for CommandError {
    fn from(err: ApplicationError) -> Self {
        let kind = match &err {
            ApplicationError::Domain(_) => "domain",
            ApplicationError::VaultLocked => "locked",
            ApplicationError::VaultAlreadyExists => "vault_exists",
            ApplicationError::InvalidMasterPassword => "invalid_password",
            ApplicationError::UnlockThrottled { .. } => "throttled",
            ApplicationError::VaultNotFound => "vault_not_found",
            ApplicationError::Storage(_) => "storage",
            ApplicationError::Crypto(_) => "crypto",
            ApplicationError::EntryNotFound(_) => "entry_not_found",
            ApplicationError::VersionConflict => "version_conflict",
            ApplicationError::Totp(_) => "totp",
            ApplicationError::BiometricUnavailable => "biometric_unavailable",
            ApplicationError::BiometricNotEnabled => "biometric_not_enabled",
            ApplicationError::BiometricFailed(_) => "biometric_failed",
            ApplicationError::RecoveryNotEnabled => "recovery_not_enabled",
            ApplicationError::InvalidRecoveryCode => "invalid_recovery_code",
            ApplicationError::Network(_) => "network",
            ApplicationError::Import(_) => "import",
            ApplicationError::Export(_) => "export",
            ApplicationError::InvalidExportPassword => "invalid_export_password",
        };
        Self {
            kind: kind.to_owned(),
            message: err.to_string(),
        }
    }
}

type CmdResult<T> = Result<T, CommandError>;

// ---------- DTOs ----------

/// A custom field crossing to the webview (carries its secret value).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldDto {
    pub label: String,
    pub value: String,
    pub hidden: bool,
}

/// A custom field coming from the form.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldInput {
    pub label: String,
    pub value: String,
    pub hidden: bool,
}

/// Plaintext list projection (no secrets).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummaryDto {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub url: Option<String>,
    pub app_name: Option<String>,
    pub favorite: bool,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub updated_at_ms: i64,
}

/// Full decrypted entry for the detail view. Carries secrets.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDto {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub app_name: Option<String>,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub custom_fields: Vec<CustomFieldDto>,
    pub tags: Vec<String>,
    pub version: u32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// Input for creating an entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewEntryInput {
    #[serde(default)]
    pub kind: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub app_name: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldInput>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Input for editing an existing entry (id identifies the row).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditEntryInput {
    pub id: String,
    #[serde(default)]
    pub kind: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub app_name: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldInput>,
    #[serde(default)]
    pub tags: Vec<String>,
}

// ---------- mapping helpers ----------

fn parse_id(s: &str) -> CmdResult<EntryId> {
    Uuid::parse_str(s)
        .map(EntryId)
        .map_err(|e| CommandError::new("bad_id", e.to_string()))
}

fn parse_uuid(s: &str) -> CmdResult<Uuid> {
    Uuid::parse_str(s).map_err(|e| CommandError::new("bad_id", e.to_string()))
}

fn summary_to_dto(s: EntrySummary) -> EntrySummaryDto {
    EntrySummaryDto {
        id: s.id.0.to_string(),
        kind: s.kind.as_str().to_owned(),
        title: s.title,
        url: s.url,
        app_name: s.app_name,
        favorite: s.favorite,
        folder_id: s.folder_id.map(|u| u.to_string()),
        tags: s.tags.iter().map(ToString::to_string).collect(),
        updated_at_ms: s.updated_at.timestamp_millis(),
    }
}

fn entry_to_dto(e: Entry) -> EntryDto {
    EntryDto {
        id: e.id.0.to_string(),
        kind: e.kind.as_str().to_owned(),
        title: e.title,
        description: e.description,
        url: e.url,
        app_name: e.app_name,
        username: e.username,
        password: e.password.expose().to_owned(),
        notes: e.notes.map(|n| n.expose().to_owned()),
        totp_secret: e.totp_secret.map(|t| t.expose().to_owned()),
        folder_id: e.folder_id.map(|u| u.to_string()),
        favorite: e.favorite,
        custom_fields: e
            .custom_fields
            .into_iter()
            .map(|f| CustomFieldDto {
                label: f.label,
                value: f.value.expose().to_owned(),
                hidden: f.hidden,
            })
            .collect(),
        tags: e.tags.iter().map(ToString::to_string).collect(),
        version: e.version,
        created_at_ms: e.created_at.timestamp_millis(),
        updated_at_ms: e.updated_at.timestamp_millis(),
    }
}

/// Builds a validated draft from create input, then fills the non-validated
/// optional fields.
fn draft_from_new(input: NewEntryInput) -> CmdResult<EntryDraft> {
    // Reject an unparseable authenticator key up front, with a clear error.
    if let Some(totp) = input.totp_secret.as_deref() {
        goldfish_application::validate_totp(totp)?;
    }
    let mut draft = EntryDraft::new(
        &input.title,
        &input.username,
        PlaintextSecret::from(input.password),
    )
    .and_then(|d| d.with_description(input.description))
    .and_then(|d| d.with_url(input.url))
    .map_err(ApplicationError::Domain)?;
    draft.kind = input
        .kind
        .as_deref()
        .map_or(EntryKind::Login, EntryKind::from_id);
    draft.app_name = input.app_name;
    draft.notes = input.notes.map(PlaintextSecret::from);
    draft.totp_secret = input.totp_secret.map(PlaintextSecret::from);
    draft.folder_id = match input.folder_id {
        Some(fid) => Some(parse_uuid(&fid)?),
        None => None,
    };
    draft.favorite = input.favorite;
    draft.custom_fields = input
        .custom_fields
        .into_iter()
        .map(|c| CustomField {
            label: c.label,
            value: PlaintextSecret::from(c.value),
            hidden: c.hidden,
        })
        .collect();
    draft.tags = input
        .tags
        .iter()
        .map(|s| parse_uuid(s))
        .collect::<CmdResult<Vec<_>>>()?;
    Ok(draft)
}

// ---------- vault lifecycle ----------

/// Liveness probe — frontend calls this on startup to confirm IPC works.
#[tauri::command]
pub fn ping() -> &'static str {
    "pong"
}

/// Excludes the calling window from screen capture / recording (Windows only,
/// best-effort; no-op elsewhere). Each sub-window — settings, logs, entry editor
/// — calls this on mount so it gets the same protection as the main window
/// (which is excluded at startup). Sync so it runs on the UI thread that owns the
/// window.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri injects the calling window by value
pub fn protect_window(window: tauri::WebviewWindow) {
    crate::apply_capture_exclusion(&window);
}

/// The application version (from the crate metadata), e.g. `1.0.0`.
#[tauri::command]
pub fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Returns the tail (last ~128 KB) of the most recent log file for the in-app
/// viewer. Logs never contain secrets (credential types redact their `Debug`).
#[tauri::command]
pub async fn read_logs(app: tauri::AppHandle) -> CmdResult<String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| CommandError::new("storage", e.to_string()))?
        .join("logs");
    tokio::task::spawn_blocking(move || read_log_tail(&dir))
        .await
        .map_err(|e| CommandError::new("storage", e.to_string()))?
}

/// Opens the logs folder in the OS file manager.
#[tauri::command]
pub async fn open_logs_dir(app: tauri::AppHandle) -> CmdResult<()> {
    use tauri_plugin_opener::OpenerExt;

    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| CommandError::new("storage", e.to_string()))?
        .join("logs");
    let _ = std::fs::create_dir_all(&dir);
    app.opener()
        .open_path(dir.to_string_lossy().into_owned(), None::<&str>)
        .map_err(|e| CommandError::new("opener", e.to_string()))?;
    Ok(())
}

fn read_log_tail(dir: &std::path::Path) -> CmdResult<String> {
    const MAX: usize = 128 * 1024;
    // Daily files sort chronologically by name, so the max is the newest.
    let newest = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("log")))
        .max();
    let Some(path) = newest else {
        return Ok(String::new());
    };
    let bytes = std::fs::read(&path).map_err(|e| CommandError::new("storage", e.to_string()))?;
    let start = bytes.len().saturating_sub(MAX);
    Ok(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

/// Whether a vault has already been initialized on this device.
#[tauri::command]
pub async fn vault_exists(state: State<'_, AppState>) -> CmdResult<bool> {
    Ok(state.service.vault_exists().await?)
}

/// Whether the vault is currently unlocked.
#[tauri::command]
pub async fn is_unlocked(state: State<'_, AppState>) -> CmdResult<bool> {
    Ok(state.session.lock().await.is_some())
}

/// Creates a new vault with the given master password and unlocks it. The
/// Argon2id cost is calibrated to this device (≈250 ms) so faster machines get
/// stronger parameters than the floor.
#[tauri::command]
pub async fn create_vault(state: State<'_, AppState>, mut password: String) -> CmdResult<()> {
    let params = tokio::task::spawn_blocking(|| goldfish_application::calibrate_kdf(250))
        .await
        .map_err(|e| CommandError::new("crypto", e.to_string()))?;
    let result = state.service.create_vault(&password, params).await;
    password.zeroize();
    let session = result?;
    *state.session.lock().await = Some(session);
    tracing::info!(memory_kib = params.memory_kib, "vault created and unlocked");
    Ok(())
}

/// Unlocks an existing vault with the master password.
#[tauri::command]
pub async fn unlock_vault(state: State<'_, AppState>, mut password: String) -> CmdResult<()> {
    let result = state.service.unlock_vault(&password).await;
    password.zeroize();
    let session = result?;
    *state.session.lock().await = Some(session);
    tracing::info!("vault unlocked");
    Ok(())
}

/// Locks the vault: closes the encrypted store and drops the session.
#[tauri::command]
pub async fn lock_vault(state: State<'_, AppState>) -> CmdResult<()> {
    state.service.lock().await?;
    *state.session.lock().await = None;
    tracing::info!("vault locked");
    Ok(())
}

// ---------- biometric unlock ----------

/// Whether this device supports biometric verification.
#[tauri::command]
pub async fn biometric_available(state: State<'_, AppState>) -> CmdResult<bool> {
    Ok(state.service.biometric_available())
}

/// Whether biometric unlock is enabled for the vault.
#[tauri::command]
pub async fn biometric_enabled(state: State<'_, AppState>) -> CmdResult<bool> {
    Ok(state.service.biometric_enabled().await?)
}

/// Enables biometric unlock (requires an unlocked vault).
#[tauri::command]
pub async fn enable_biometric(state: State<'_, AppState>) -> CmdResult<()> {
    let guard = state.session.lock().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
    state.service.enable_biometric(session).await?;
    tracing::info!("biometric unlock enabled");
    Ok(())
}

/// Disables biometric unlock.
#[tauri::command]
pub async fn disable_biometric(state: State<'_, AppState>) -> CmdResult<()> {
    state.service.disable_biometric().await?;
    tracing::info!("biometric unlock disabled");
    Ok(())
}

/// Unlocks the vault via biometrics (triggers the platform prompt).
#[tauri::command]
pub async fn unlock_biometric(state: State<'_, AppState>) -> CmdResult<()> {
    let session = state.service.unlock_biometric().await?;
    *state.session.lock().await = Some(session);
    tracing::info!("vault unlocked (biometric)");
    Ok(())
}

// ---------- recovery code ----------

/// Whether recovery-code unlock is enabled for the vault.
#[tauri::command]
pub async fn recovery_enabled(state: State<'_, AppState>) -> CmdResult<bool> {
    Ok(state.service.recovery_enabled().await?)
}

/// Enables recovery and returns the one-time recovery code to display. Requires
/// an unlocked vault. The code is never persisted.
#[tauri::command]
pub async fn enable_recovery(state: State<'_, AppState>) -> CmdResult<String> {
    let guard = state.session.lock().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
    let code = state.service.enable_recovery(session).await?;
    tracing::info!("recovery code enabled");
    Ok(code.as_str().to_owned())
}

/// Disables recovery-code unlock.
#[tauri::command]
pub async fn disable_recovery(state: State<'_, AppState>) -> CmdResult<()> {
    state.service.disable_recovery().await?;
    tracing::info!("recovery code disabled");
    Ok(())
}

/// Unlocks the vault with a recovery code and resets the master password to
/// `new_password`. Both inputs are zeroized after use.
#[tauri::command]
pub async fn unlock_with_recovery(
    state: State<'_, AppState>,
    mut code: String,
    mut new_password: String,
) -> CmdResult<()> {
    let result = state
        .service
        .unlock_with_recovery(&code, &new_password)
        .await;
    code.zeroize();
    new_password.zeroize();
    let session = result?;
    *state.session.lock().await = Some(session);
    tracing::info!("vault unlocked via recovery; master password reset");
    Ok(())
}

/// Checks a password against Have I Been Pwned (k-anonymity). Returns how many
/// times it appears in known breaches (0 = not found). Stateless; only the
/// SHA-1 prefix leaves the device.
#[tauri::command]
pub async fn check_pwned(state: State<'_, AppState>, mut password: String) -> CmdResult<u64> {
    let result = goldfish_application::check_pwned(state.pwned.as_ref(), &password).await;
    password.zeroize();
    Ok(result?)
}

/// Imports entries from another manager's export file at `path`. The plaintext
/// export is read in Rust (never crossing to the webview) and zeroized after
/// parsing. Returns how many entries were imported. Requires an unlocked vault.
#[tauri::command]
pub async fn import_file(
    state: State<'_, AppState>,
    format: String,
    path: String,
) -> CmdResult<usize> {
    let fmt = goldfish_application::ImportFormat::from_id(&format)
        .ok_or_else(|| CommandError::new("import", format!("unknown format: {format}")))?;

    let mut data = tokio::task::spawn_blocking(move || std::fs::read_to_string(path))
        .await
        .map_err(|e| CommandError::new("import", e.to_string()))?
        .map_err(|e| CommandError::new("import", e.to_string()))?;

    let drafts = goldfish_application::parse_import(fmt, &data)?;
    data.zeroize();

    let guard = state.session.lock().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
    let count = state.service.import_entries(session, drafts).await?;
    tracing::info!(count, "imported entries");
    Ok(count)
}

/// Exports the entire vault to an encrypted `.goldfish` file at `path`, protected
/// by `export_password` (independent of the master password). The decrypted
/// bundle is built and sealed entirely in Rust — plaintext never crosses to the
/// webview, and only ciphertext is written to disk. Requires an unlocked vault.
/// Returns the number of entries exported.
#[tauri::command]
pub async fn export_vault(
    state: State<'_, AppState>,
    mut export_password: String,
    path: String,
) -> CmdResult<usize> {
    let result = {
        let guard = state.session.lock().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
        state
            .service
            .export_vault(session, &export_password, KdfParams::DEFAULT)
            .await
    };
    export_password.zeroize();
    let export = result?;

    let count = export.entry_count;
    let bytes = export.bytes;
    tokio::task::spawn_blocking(move || std::fs::write(path, bytes))
        .await
        .map_err(|e| CommandError::new("export", e.to_string()))?
        .map_err(|e| CommandError::new("export", e.to_string()))?;

    tracing::info!(count, "vault exported (encrypted)");
    Ok(count)
}

/// Imports entries from an encrypted `.goldfish` file at `path`, protected by
/// `export_password`. The file is read and decrypted entirely in Rust; the
/// plaintext bundle never reaches the webview. Returns how many entries were
/// imported. Requires an unlocked vault.
#[tauri::command]
pub async fn import_vault_file(
    state: State<'_, AppState>,
    mut export_password: String,
    path: String,
) -> CmdResult<usize> {
    let bytes = tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(|e| CommandError::new("export", e.to_string()))?
        .map_err(|e| CommandError::new("export", e.to_string()))?;

    let result = {
        let guard = state.session.lock().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
        state
            .service
            .import_vault_file(session, &bytes, &export_password)
            .await
    };
    export_password.zeroize();
    let count = result?;
    tracing::info!(count, "imported entries from encrypted export");
    Ok(count)
}

// ---------- rolling backups ----------

/// Metadata about one rolling backup snapshot (no secret material).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfoDto {
    pub file_name: String,
    pub created_at_ms: i64,
    pub size_bytes: u64,
}

/// Lists the available rolling backup snapshots (newest first). Each is an
/// encrypted copy of the vault DB; no secrets cross the boundary.
#[tauri::command]
pub async fn list_backups(state: State<'_, AppState>) -> CmdResult<Vec<BackupInfoDto>> {
    let items = state.service.list_backups().await?;
    Ok(items
        .into_iter()
        .map(|b| BackupInfoDto {
            file_name: b.file_name,
            created_at_ms: b.created_at_ms,
            size_bytes: b.size_bytes,
        })
        .collect())
}

/// Restores the vault database from the named snapshot, then locks the vault. The
/// current database is snapshotted first, so the restore is reversible. The user
/// must unlock again afterwards (the DEK is unchanged, so the master password
/// still works). Works whether the vault is currently locked or unlocked.
#[tauri::command]
pub async fn restore_backup(state: State<'_, AppState>, file_name: String) -> CmdResult<()> {
    // Drop the session first, then let the service close the store and swap files.
    *state.session.lock().await = None;
    state.service.restore_backup(&file_name).await?;
    tracing::info!("vault restored from a backup snapshot");
    Ok(())
}

// ---------- vault health ----------

/// One entry referenced by a health finding (no secret material).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthItemDto {
    pub id: String,
    pub title: String,
}

/// A group of entries that share the same password.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReusedGroupDto {
    pub count: usize,
    pub entries: Vec<HealthItemDto>,
}

/// Vault-health scan result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthReportDto {
    pub total: usize,
    pub weak: Vec<HealthItemDto>,
    pub reused: Vec<ReusedGroupDto>,
    pub stale: Vec<HealthItemDto>,
    pub without_totp: Vec<HealthItemDto>,
}

fn map_health_items(items: Vec<goldfish_application::HealthItem>) -> Vec<HealthItemDto> {
    items
        .into_iter()
        .map(|i| HealthItemDto {
            id: i.id.to_string(),
            title: i.title,
        })
        .collect()
}

/// Scans the unlocked vault for weak/reused/stale passwords and missing 2FA.
/// Weakness threshold is a zxcvbn score < 3; staleness is older than one year.
#[tauri::command]
pub async fn vault_health(
    state: State<'_, AppState>,
    stale_after_days: Option<i64>,
) -> CmdResult<HealthReportDto> {
    let guard = state.session.lock().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
    let stale_window = stale_after_days.unwrap_or(365).max(1);
    let report = state.service.vault_health(session, 3, stale_window).await?;
    Ok(HealthReportDto {
        total: report.total,
        weak: map_health_items(report.weak),
        reused: report
            .reused
            .into_iter()
            .map(|g| ReusedGroupDto {
                count: g.count,
                entries: map_health_items(g.entries),
            })
            .collect(),
        stale: map_health_items(report.stale),
        without_totp: map_health_items(report.without_totp),
    })
}

/// One breached entry returned by a vault-wide HIBP scan (no secret material).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachItemDto {
    pub id: String,
    pub title: String,
    pub count: u64,
}

/// Checks every entry's password against Have I Been Pwned and returns those
/// found in breaches. Only SHA-1 prefixes leave the device; duplicate passwords
/// are checked once. Requires an unlocked vault.
#[tauri::command]
pub async fn vault_breach_scan(state: State<'_, AppState>) -> CmdResult<Vec<BreachItemDto>> {
    // Phase 1 — decrypt + hash every password while holding the session lock
    // (local, fast). We then drop the guard so the slow network phase below does
    // not block other vault operations (reads, edits) for the whole scan.
    let targets = {
        let guard = state.session.lock().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
        state.service.collect_breach_targets(session).await?
    };

    // Phase 2 — query HIBP without the session lock; only SHA-1 prefixes leave.
    let items = state
        .service
        .scan_breach_targets(targets, state.pwned.as_ref())
        .await?;
    Ok(items
        .into_iter()
        .map(|i| BreachItemDto {
            id: i.id.to_string(),
            title: i.title,
            count: i.count,
        })
        .collect())
}

// ---------- entries ----------

/// Lists plaintext entry summaries (no secrets), optionally filtered by folder.
#[tauri::command]
pub async fn list_entries(
    state: State<'_, AppState>,
    folder_id: Option<String>,
) -> CmdResult<Vec<EntrySummaryDto>> {
    let folder = match folder_id {
        Some(s) => Some(parse_uuid(&s)?),
        None => None,
    };
    let summaries = state.service.list_entries(folder).await?;
    Ok(summaries.into_iter().map(summary_to_dto).collect())
}

/// Loads and decrypts a single entry (requires an unlocked vault).
#[tauri::command]
pub async fn get_entry(state: State<'_, AppState>, id: String) -> CmdResult<EntryDto> {
    let entry_id = parse_id(&id)?;
    let guard = state.session.lock().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
    let entry = state.service.get_entry(session, entry_id).await?;
    Ok(entry_to_dto(entry))
}

/// Creates a new entry and returns it.
#[tauri::command]
pub async fn add_entry(state: State<'_, AppState>, input: NewEntryInput) -> CmdResult<EntryDto> {
    let draft = draft_from_new(input)?;
    let guard = state.session.lock().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
    let entry = state.service.add_entry(session, draft).await?;
    Ok(entry_to_dto(entry))
}

/// Updates an existing entry (preserving id, version base, and creation time).
#[tauri::command]
pub async fn update_entry(
    state: State<'_, AppState>,
    input: EditEntryInput,
) -> CmdResult<EntryDto> {
    let entry_id = parse_id(&input.id)?;
    let guard = state.session.lock().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;

    let current = state.service.get_entry(session, entry_id).await?;
    let draft = draft_from_new(NewEntryInput {
        kind: input.kind,
        title: input.title,
        username: input.username,
        password: input.password,
        description: input.description,
        url: input.url,
        app_name: input.app_name,
        notes: input.notes,
        totp_secret: input.totp_secret,
        folder_id: input.folder_id,
        favorite: input.favorite,
        custom_fields: input.custom_fields,
        tags: input.tags,
    })?;

    let updated = Entry {
        id: current.id,
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
        version: current.version,
        created_at: current.created_at,
        updated_at: current.updated_at,
    };
    let saved = state.service.update_entry(session, updated).await?;
    Ok(entry_to_dto(saved))
}

/// Deletes an entry by id (idempotent).
#[tauri::command]
pub async fn delete_entry(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    state.service.delete_entry(parse_id(&id)?).await?;
    Ok(())
}

/// Persists the manual order of one view. `folder_id` is `None` for the
/// "all entries" view or a folder id; `ids` is the full ordered list for it.
#[tauri::command]
pub async fn reorder_entries(
    state: State<'_, AppState>,
    folder_id: Option<String>,
    ids: Vec<String>,
) -> CmdResult<()> {
    let folder = match folder_id {
        Some(s) => Some(parse_uuid(&s)?),
        None => None,
    };
    let entry_ids = ids
        .iter()
        .map(|s| parse_id(s))
        .collect::<CmdResult<Vec<_>>>()?;
    state.service.reorder_entries(folder, &entry_ids).await?;
    Ok(())
}

/// Moves an entry into a folder (`folder_id` = `None` unfiles it), appending it
/// to the end of that folder's order. The all-entries order is unchanged.
#[tauri::command]
pub async fn move_entry_to_folder(
    state: State<'_, AppState>,
    id: String,
    folder_id: Option<String>,
) -> CmdResult<()> {
    let entry_id = parse_id(&id)?;
    let folder = match folder_id {
        Some(s) => Some(parse_uuid(&s)?),
        None => None,
    };
    state.service.move_entry_to_folder(entry_id, folder).await?;
    Ok(())
}

/// One past password with the epoch-ms time it was replaced. Carries a secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryDto {
    pub password: String,
    pub changed_at_ms: i64,
}

/// Returns an entry's previous passwords, newest first (requires unlock).
#[tauri::command]
pub async fn password_history(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<Vec<PasswordHistoryDto>> {
    let entry_id = parse_id(&id)?;
    let guard = state.session.lock().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
    let history = state.service.password_history(session, entry_id).await?;
    Ok(history
        .into_iter()
        .map(|h| PasswordHistoryDto {
            password: h.password.expose().to_owned(),
            changed_at_ms: h.changed_at.timestamp_millis(),
        })
        .collect())
}

// ---------- folders ----------

/// Per-view appearance overrides crossing the IPC boundary.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppearanceDto {
    pub background: Option<String>,
    pub text_color: Option<String>,
    pub bold: bool,
    pub italic: bool,
    pub font_size: Option<u16>,
}

impl From<Appearance> for AppearanceDto {
    fn from(a: Appearance) -> Self {
        Self {
            background: a.background,
            text_color: a.text_color,
            bold: a.bold,
            italic: a.italic,
            font_size: a.font_size,
        }
    }
}

impl From<AppearanceDto> for Appearance {
    fn from(a: AppearanceDto) -> Self {
        Self {
            background: a.background,
            text_color: a.text_color,
            bold: a.bold,
            italic: a.italic,
            font_size: a.font_size,
        }
    }
}

/// A folder (plaintext metadata, no secrets).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderDto {
    pub id: String,
    pub name: String,
    pub appearance: AppearanceDto,
}

fn folder_to_dto(f: goldfish_domain::Folder) -> FolderDto {
    FolderDto {
        id: f.id.to_string(),
        name: f.name,
        appearance: f.appearance.into(),
    }
}

/// Lists all folders (requires an open vault).
#[tauri::command]
pub async fn list_folders(state: State<'_, AppState>) -> CmdResult<Vec<FolderDto>> {
    let folders = state.service.list_folders().await?;
    Ok(folders.into_iter().map(folder_to_dto).collect())
}

/// Creates a folder and returns it.
#[tauri::command]
pub async fn create_folder(state: State<'_, AppState>, name: String) -> CmdResult<FolderDto> {
    let folder = state.service.create_folder(&name).await?;
    Ok(folder_to_dto(folder))
}

/// Replaces a folder's appearance overrides (colors validated, font clamped).
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn set_folder_appearance(
    state: State<'_, AppState>,
    id: String,
    appearance: AppearanceDto,
) -> CmdResult<()> {
    state
        .service
        .set_folder_appearance(parse_uuid(&id)?, appearance.into())
        .await?;
    Ok(())
}

/// A tag (plaintext label, no secrets).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TagDto {
    pub id: String,
    pub name: String,
}

/// Lists all tags (requires an open vault).
#[tauri::command]
pub async fn list_tags(state: State<'_, AppState>) -> CmdResult<Vec<TagDto>> {
    let tags = state.service.list_tags().await?;
    Ok(tags
        .into_iter()
        .map(|t| TagDto {
            id: t.id.to_string(),
            name: t.name,
        })
        .collect())
}

/// Creates a tag and returns it.
#[tauri::command]
pub async fn create_tag(state: State<'_, AppState>, name: String) -> CmdResult<TagDto> {
    let tag = state.service.create_tag(&name).await?;
    Ok(TagDto {
        id: tag.id.to_string(),
        name: tag.name,
    })
}

/// Renames a tag.
#[tauri::command]
pub async fn rename_tag(state: State<'_, AppState>, id: String, name: String) -> CmdResult<()> {
    state.service.rename_tag(parse_uuid(&id)?, &name).await?;
    Ok(())
}

/// Deletes a tag; it is removed from every entry it was applied to.
#[tauri::command]
pub async fn delete_tag(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    state.service.delete_tag(parse_uuid(&id)?).await?;
    Ok(())
}

// ---------- attachments ----------

/// Attachment metadata crossing to the webview (no file bytes).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentDto {
    pub id: String,
    pub name: String,
    pub size: u64,
}

/// Attaches the file at `path` to an entry. The bytes are read in Rust, sealed,
/// and zeroized — they never cross to the webview. Returns the new attachment's
/// metadata. Requires an unlocked vault.
#[tauri::command]
pub async fn add_attachment(
    state: State<'_, AppState>,
    entry_id: String,
    path: String,
) -> CmdResult<AttachmentDto> {
    let entry = parse_id(&entry_id)?;
    let name = std::path::Path::new(&path).file_name().map_or_else(
        || "attachment".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );

    let mut bytes = tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(|e| CommandError::new("storage", e.to_string()))?
        .map_err(|e| CommandError::new("storage", e.to_string()))?;

    let result = {
        let guard = state.session.lock().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
        state
            .service
            .add_attachment(session, entry, &name, &bytes)
            .await
    };
    bytes.zeroize();
    let meta = result?;
    tracing::info!(size = meta.size, "attachment added");
    Ok(AttachmentDto {
        id: meta.id.to_string(),
        name: meta.name,
        size: meta.size,
    })
}

/// Attaches a file whose bytes come from the webview — used for drag-and-drop on
/// the detail view, where the OS file path is unavailable. The bytes are sealed
/// and zeroized in Rust exactly like the path-based [`add_attachment`]; only the
/// encrypted blob is stored. The oversize cap is enforced by the service.
/// Requires an unlocked vault.
#[tauri::command]
pub async fn add_attachment_bytes(
    state: State<'_, AppState>,
    entry_id: String,
    name: String,
    mut data: Vec<u8>,
) -> CmdResult<AttachmentDto> {
    let entry = parse_id(&entry_id)?;
    // Keep only the file name component — never a caller-supplied path.
    let name = std::path::Path::new(&name).file_name().map_or_else(
        || "attachment".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );

    let result = {
        let guard = state.session.lock().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
        state
            .service
            .add_attachment(session, entry, &name, &data)
            .await
    };
    data.zeroize();
    let meta = result?;
    tracing::info!(size = meta.size, "attachment added (bytes)");
    Ok(AttachmentDto {
        id: meta.id.to_string(),
        name: meta.name,
        size: meta.size,
    })
}

/// Lists an entry's attachment metadata (no file bytes).
#[tauri::command]
pub async fn list_attachments(
    state: State<'_, AppState>,
    entry_id: String,
) -> CmdResult<Vec<AttachmentDto>> {
    let metas = state.service.list_attachments(parse_id(&entry_id)?).await?;
    Ok(metas
        .into_iter()
        .map(|m| AttachmentDto {
            id: m.id.to_string(),
            name: m.name,
            size: m.size,
        })
        .collect())
}

/// Decrypts an attachment and writes it to `path`. The plaintext is produced and
/// written entirely in Rust (zeroized after) and never crosses to the webview.
/// Requires an unlocked vault.
#[tauri::command]
pub async fn save_attachment(
    state: State<'_, AppState>,
    id: String,
    path: String,
) -> CmdResult<()> {
    let attachment_id = parse_uuid(&id)?;
    let result = {
        let guard = state.session.lock().await;
        let session = guard
            .as_ref()
            .ok_or_else(|| CommandError::from(ApplicationError::VaultLocked))?;
        state.service.open_attachment(session, attachment_id).await
    };
    let (_, data) = result?; // `data` is zeroized on drop
    tokio::task::spawn_blocking(move || std::fs::write(path, &data))
        .await
        .map_err(|e| CommandError::new("storage", e.to_string()))?
        .map_err(|e| CommandError::new("storage", e.to_string()))?;
    Ok(())
}

/// Deletes an attachment by id (idempotent).
#[tauri::command]
pub async fn delete_attachment(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    state.service.delete_attachment(parse_uuid(&id)?).await?;
    Ok(())
}

/// Renames a folder.
#[tauri::command]
pub async fn rename_folder(state: State<'_, AppState>, id: String, name: String) -> CmdResult<()> {
    state.service.rename_folder(parse_uuid(&id)?, &name).await?;
    Ok(())
}

/// Deletes a folder; its entries are kept and become unfiled.
#[tauri::command]
pub async fn delete_folder(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    state.service.delete_folder(parse_uuid(&id)?).await?;
    Ok(())
}

/// Generator policy received from the frontend.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenPolicyInput {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

/// Estimates password strength (0–4) via zxcvbn. Stateless.
#[tauri::command]
pub fn estimate_strength(mut password: String) -> u8 {
    let score = goldfish_application::estimate_strength(&password, &[]);
    password.zeroize();
    score
}

/// Current TOTP code with timing for the UI countdown.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpDto {
    pub code: String,
    pub period: u64,
    pub remaining: u64,
}

/// Generates the current TOTP code for an authenticator secret. Stateless.
#[tauri::command]
pub fn generate_totp(mut secret: String) -> CmdResult<TotpDto> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CommandError::new("totp", e.to_string()))?
        .as_secs();
    let result = goldfish_application::generate_totp(&secret, now);
    secret.zeroize();
    let code = result?;
    Ok(TotpDto {
        code: code.code,
        period: code.period,
        remaining: code.remaining,
    })
}

/// Generates a password according to `policy`. Stateless — does not require an
/// unlocked vault.
// Tauri deserializes command args by value; the by-value-but-borrowed pattern
// clippy flags here is required.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn generate_password(policy: GenPolicyInput) -> CmdResult<String> {
    let p = PasswordPolicy {
        length: policy.length,
        lowercase: policy.lowercase,
        uppercase: policy.uppercase,
        digits: policy.digits,
        symbols: policy.symbols,
        exclude_ambiguous: policy.exclude_ambiguous,
    };
    let secret = goldfish_application::generate_password(&OsSecureRandom, &p)?;
    Ok(secret.expose().to_owned())
}

/// Passphrase-generator policy received from the frontend.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphrasePolicyInput {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

/// Generates a Diceware passphrase according to `policy`. Stateless — does not
/// require an unlocked vault.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn generate_passphrase(policy: PassphrasePolicyInput) -> CmdResult<String> {
    let p = PassphrasePolicy {
        words: policy.words,
        // Use the first character of the separator string (default to '-').
        separator: policy.separator.chars().next().unwrap_or('-'),
        capitalize: policy.capitalize,
        include_number: policy.include_number,
    };
    let secret = goldfish_application::generate_passphrase(&OsSecureRandom, &p)?;
    Ok(secret.expose().to_owned())
}

/// Opens `url` in the OS default browser. Only `http`/`https` is allowed, so a
/// stored `file://` / `javascript:` value can never be launched.
#[tauri::command]
pub async fn open_external(app: tauri::AppHandle, url: String) -> CmdResult<()> {
    use tauri_plugin_opener::OpenerExt;

    let lower = url.trim().to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(CommandError::new(
            "bad_url",
            "only http(s) URLs can be opened",
        ));
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| CommandError::new("opener", e.to_string()))?;
    Ok(())
}

/// Copies a value to the clipboard and clears it after `clear_ms` — but only if
/// the clipboard still holds exactly that value (so we never wipe something the
/// user copied in the meantime). On Windows the entry is flagged so Clipboard
/// History (Win+V) and Cloud Clipboard skip it.
#[tauri::command]
pub async fn copy_secret(app: tauri::AppHandle, value: String, clear_ms: u64) -> CmdResult<()> {
    write_secret_to_clipboard(&app, &value)?;

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        use tauri_plugin_clipboard_manager::ClipboardExt;
        tokio::time::sleep(std::time::Duration::from_millis(clear_ms)).await;
        if let Ok(current) = handle.clipboard().read_text() {
            if current == value {
                let _ = handle.clipboard().clear();
            }
        }
    });
    Ok(())
}

/// Writes a secret to the clipboard. On Windows it tags the data so Clipboard
/// History and Cloud Clipboard ignore it; on failure (or other platforms) it
/// falls back to the cross-platform plugin write so copying never breaks.
fn write_secret_to_clipboard(app: &tauri::AppHandle, value: &str) -> CmdResult<()> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    #[cfg(windows)]
    {
        if write_clipboard_excluded_windows(value).is_ok() {
            return Ok(());
        }
        // Native path failed — fall through to the plugin below.
    }

    app.clipboard()
        .write_text(value.to_owned())
        .map_err(|e| CommandError::new("clipboard", e.to_string()))
}

/// Writes `value` as CF_UNICODETEXT plus the
/// `ExcludeClipboardContentFromMonitorProcessing` marker, which keeps the entry
/// out of Clipboard History and Cloud Clipboard. Both are set within one
/// clipboard session so the marker applies to the text we just wrote.
#[cfg(windows)]
fn write_clipboard_excluded_windows(value: &str) -> Result<(), ()> {
    use clipboard_win::{raw, register_format, Clipboard};

    let _clip = Clipboard::new_attempts(10).map_err(|_| ())?;
    raw::set_string(value).map_err(|_| ())?;
    if let Some(fmt) = register_format("ExcludeClipboardContentFromMonitorProcessing") {
        // Empty payload — presence of the format is the signal. Don't clear, so
        // the text we just set survives.
        let _ = raw::set_without_clear(fmt.get(), &[0u8]);
    }
    Ok(())
}
