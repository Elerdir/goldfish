/**
 * Typed wrappers around Tauri IPC commands.
 *
 * Every Rust `#[tauri::command]` gets exactly one hand-written wrapper here so
 * the boundary stays type-checked and contract drift surfaces in review.
 */

import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";

/** Event emitted to other windows when vault data (entries/folders/tags) changes. */
export const VAULT_CHANGED_EVENT = "goldfish:vault-changed";

/** Event emitted by sub-windows on user activity, to keep the main window's
 * idle auto-lock from firing while the user is busy in another window. */
export const ACTIVITY_EVENT = "goldfish:activity";

/** Error shape returned by backend commands (see `commands::CommandError`). */
export interface CommandError {
    kind: string;
    message: string;
}

/** Kind of secret an entry holds (mirrors the Rust `EntryKind`). */
export type EntryKind = "login" | "note" | "card" | "ssh" | "token";

/** A user-defined extra field. `value` is a secret; `hidden` masks it in the UI. */
export interface CustomField {
    label: string;
    value: string;
    hidden: boolean;
}

/** Plaintext list projection (no secrets). */
export interface EntrySummary {
    id: string;
    kind: EntryKind;
    title: string;
    url: string | null;
    appName: string | null;
    favorite: boolean;
    folderId: string | null;
    tags: string[];
    updatedAtMs: number;
}

/** Full decrypted entry (detail view / clipboard). */
export interface Entry {
    id: string;
    kind: EntryKind;
    title: string;
    description: string | null;
    url: string | null;
    appName: string | null;
    username: string;
    password: string;
    notes: string | null;
    totpSecret: string | null;
    folderId: string | null;
    favorite: boolean;
    customFields: CustomField[];
    tags: string[];
    version: number;
    createdAtMs: number;
    updatedAtMs: number;
}

/** Editable fields shared by create and edit forms. */
export interface EntryInput {
    kind: EntryKind;
    title: string;
    username: string;
    password: string;
    description: string | null;
    url: string | null;
    appName: string | null;
    notes: string | null;
    totpSecret: string | null;
    folderId: string | null;
    favorite: boolean;
    customFields: CustomField[];
    tags: string[];
}

/**
 * Per-view visual overrides (mirrors the Rust `Appearance`). `null`/`false`
 * fields mean "inherit the app theme". Colors are hex strings; `fontSize` is px.
 */
export interface Appearance {
    background: string | null;
    textColor: string | null;
    bold: boolean;
    italic: boolean;
    fontSize: number | null;
}

/** An appearance with no overrides (everything inherits the theme). */
export const EMPTY_APPEARANCE: Appearance = {
    background: null,
    textColor: null,
    bold: false,
    italic: false,
    fontSize: null,
};

/** A folder (plaintext metadata for grouping entries). */
export interface Folder {
    id: string;
    name: string;
    appearance: Appearance;
}

/** A tag (plaintext label applied to entries, many-to-many). */
export interface Tag {
    id: string;
    name: string;
}

/** Whether we are running inside the Tauri webview (vs. a plain browser). */
export function isTauri(): boolean {
    return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Narrows an unknown caught value to a {@link CommandError}. */
export function asCommandError(err: unknown): CommandError {
    if (typeof err === "object" && err !== null && "kind" in err && typeof err.kind === "string") {
        const message = "message" in err && typeof err.message === "string" ? err.message : "";
        return { kind: err.kind, message };
    }
    return { kind: "unknown", message: typeof err === "string" ? err : "unknown error" };
}

export async function ping(): Promise<string> {
    return invoke<string>("ping");
}

/**
 * Excludes the current window from screen capture / recording (Windows only,
 * best-effort). Called by each sub-window on mount so settings, logs and the
 * entry editor get the same protection as the main window.
 */
export async function protectWindow(): Promise<void> {
    if (!isTauri()) return;
    try {
        await invoke("protect_window");
    } catch {
        // Best-effort hardening — never block the UI if it's unavailable.
    }
}

/** The application version string (e.g. `1.0.0`). */
export async function appVersion(): Promise<string> {
    return invoke<string>("app_version");
}

/** Returns the tail of the most recent log file (never contains secrets). */
export async function readLogs(): Promise<string> {
    return invoke<string>("read_logs");
}

/** Opens the logs folder in the OS file manager. */
export async function openLogsDir(): Promise<void> {
    await invoke("open_logs_dir");
}

/** Label of the standalone log-viewer window. */
const LOGS_WINDOW_LABEL = "goldfish-logs";

/**
 * Opens (or focuses) the standalone, resizable log-viewer window. It loads the
 * app shell with `?view=logs`, which renders only the log screen.
 */
export async function openLogsWindow(): Promise<void> {
    if (!isTauri()) return;
    const existing = await WebviewWindow.getByLabel(LOGS_WINDOW_LABEL);
    if (existing) {
        await existing.setFocus();
        return;
    }
    const win = new WebviewWindow(LOGS_WINDOW_LABEL, {
        url: "index.html?view=logs",
        title: "Goldfish — Logs",
        width: 900,
        height: 600,
        minWidth: 520,
        minHeight: 360,
        resizable: true,
        center: true,
    });
    // Attach (and ignore) the error event so a failed creation doesn't reject
    // into the caller's flow.
    void win.once("tauri://error", () => {});
}

/** Opens (or focuses) the standalone Settings window. */
export async function openSettingsWindow(): Promise<void> {
    if (!isTauri()) return;
    const label = "goldfish-settings";
    const existing = await WebviewWindow.getByLabel(label);
    if (existing) {
        await existing.setFocus();
        return;
    }
    const win = new WebviewWindow(label, {
        url: "index.html?view=settings",
        title: "Goldfish — Settings",
        width: 760,
        height: 720,
        minWidth: 520,
        minHeight: 480,
        resizable: true,
        center: true,
    });
    void win.once("tauri://error", () => {});
}

/**
 * Opens (or focuses) the standalone entry window. `entryId` edits an existing
 * entry; omit it (or `null`) to add a new one. Each entry gets its own window.
 */
export async function openEntryWindow(entryId?: string | null): Promise<void> {
    if (!isTauri()) return;
    const id = entryId ?? "new";
    const label = `goldfish-entry-${id}`;
    const existing = await WebviewWindow.getByLabel(label);
    if (existing) {
        await existing.setFocus();
        return;
    }
    const win = new WebviewWindow(label, {
        url: `index.html?view=entry&id=${encodeURIComponent(id)}`,
        title: "Goldfish",
        width: 720,
        height: 780,
        minWidth: 480,
        minHeight: 480,
        resizable: true,
        center: true,
    });
    void win.once("tauri://error", () => {});
}

/** Notifies other windows (the main vault view) that vault data changed. */
export async function emitVaultChanged(): Promise<void> {
    await emit(VAULT_CHANGED_EVENT);
}

/** Pings the main window that the user is active (resets its idle auto-lock). */
export async function emitActivity(): Promise<void> {
    await emit(ACTIVITY_EVENT);
}

export async function vaultExists(): Promise<boolean> {
    return invoke<boolean>("vault_exists");
}

export async function isUnlocked(): Promise<boolean> {
    return invoke<boolean>("is_unlocked");
}

/** Metadata about one rolling backup snapshot (no secret material). */
export interface BackupInfo {
    fileName: string;
    createdAtMs: number;
    sizeBytes: number;
}

/** Lists the available rolling backup snapshots (newest first). */
export async function listBackups(): Promise<BackupInfo[]> {
    return invoke<BackupInfo[]>("list_backups");
}

/**
 * Restores the vault DB from a snapshot and locks the vault. The current DB is
 * snapshotted first (reversible). Afterwards the user unlocks the restored vault
 * with the same master password (the DEK is unchanged across snapshots).
 */
export async function restoreBackup(fileName: string): Promise<void> {
    await invoke("restore_backup", { fileName });
}

export async function createVault(password: string): Promise<void> {
    await invoke("create_vault", { password });
}

export async function unlockVault(password: string): Promise<void> {
    await invoke("unlock_vault", { password });
}

export async function lockVault(): Promise<void> {
    await invoke("lock_vault");
}

export async function listEntries(folderId: string | null = null): Promise<EntrySummary[]> {
    return invoke<EntrySummary[]>("list_entries", { folderId });
}

export async function getEntry(id: string): Promise<Entry> {
    return invoke<Entry>("get_entry", { id });
}

/** A past password with the epoch-ms time it was replaced. */
export interface PasswordHistoryItem {
    password: string;
    changedAtMs: number;
}

/** Returns an entry's previous passwords, newest first. */
export async function passwordHistory(id: string): Promise<PasswordHistoryItem[]> {
    return invoke<PasswordHistoryItem[]>("password_history", { id });
}

export async function addEntry(input: EntryInput): Promise<Entry> {
    return invoke<Entry>("add_entry", { input });
}

export async function updateEntry(id: string, input: EntryInput): Promise<Entry> {
    return invoke<Entry>("update_entry", { input: { id, ...input } });
}

export async function deleteEntry(id: string): Promise<void> {
    await invoke("delete_entry", { id });
}

/**
 * Persists the manual order of one view. `folderId` is `null` for the
 * "all entries" view; `ids` is the full ordered list of entry ids in that view.
 * The all-entries and per-folder orders are remembered independently.
 */
export async function reorderEntries(folderId: string | null, ids: string[]): Promise<void> {
    await invoke("reorder_entries", { folderId, ids });
}

/**
 * Moves an entry into a folder (`folderId` = `null` unfiles it), appending it to
 * the end of that folder's order. The all-entries order is left unchanged.
 */
export async function moveEntryToFolder(id: string, folderId: string | null): Promise<void> {
    await invoke("move_entry_to_folder", { id, folderId });
}

export async function listFolders(): Promise<Folder[]> {
    return invoke<Folder[]>("list_folders");
}

export async function createFolder(name: string): Promise<Folder> {
    return invoke<Folder>("create_folder", { name });
}

export async function renameFolder(id: string, name: string): Promise<void> {
    await invoke("rename_folder", { id, name });
}

/** Sets a folder's appearance overrides (colors validated & font clamped in Rust). */
export async function setFolderAppearance(id: string, appearance: Appearance): Promise<void> {
    await invoke("set_folder_appearance", { id, appearance });
}

export async function deleteFolder(id: string): Promise<void> {
    await invoke("delete_folder", { id });
}

export async function listTags(): Promise<Tag[]> {
    return invoke<Tag[]>("list_tags");
}

export async function createTag(name: string): Promise<Tag> {
    return invoke<Tag>("create_tag", { name });
}

export async function renameTag(id: string, name: string): Promise<void> {
    await invoke("rename_tag", { id, name });
}

export async function deleteTag(id: string): Promise<void> {
    await invoke("delete_tag", { id });
}

/** Metadata for one encrypted attachment (no file bytes). */
export interface AttachmentMeta {
    id: string;
    name: string;
    size: number;
}

/**
 * Attaches the file at `path` to an entry. Bytes are read & sealed in Rust (never
 * crossing to the webview) and zeroized. Returns the new attachment's metadata.
 */
export async function addAttachment(entryId: string, path: string): Promise<AttachmentMeta> {
    return invoke<AttachmentMeta>("add_attachment", { entryId, path });
}

/** Lists an entry's attachment metadata (no file bytes). */
export async function listAttachments(entryId: string): Promise<AttachmentMeta[]> {
    return invoke<AttachmentMeta[]>("list_attachments", { entryId });
}

/** Decrypts an attachment and writes it to `path` (done entirely in Rust). */
export async function saveAttachment(id: string, path: string): Promise<void> {
    await invoke("save_attachment", { id, path });
}

export async function deleteAttachment(id: string): Promise<void> {
    await invoke("delete_attachment", { id });
}

/** Copies `value` to the clipboard; the backend clears it after `clearMs`. */
export async function copySecret(value: string, clearMs: number): Promise<void> {
    await invoke("copy_secret", { value, clearMs });
}

/** Opens an http(s) URL in the OS default browser (validated in Rust). */
export async function openExternal(url: string): Promise<void> {
    await invoke("open_external", { url });
}

/** Password-generator policy mirrored from the Rust `GenPolicyInput`. */
export interface GenPolicy {
    length: number;
    lowercase: boolean;
    uppercase: boolean;
    digits: boolean;
    symbols: boolean;
    excludeAmbiguous: boolean;
}

export async function generatePassword(policy: GenPolicy): Promise<string> {
    return invoke<string>("generate_password", { policy });
}

/** Passphrase-generator policy mirrored from the Rust `PassphrasePolicyInput`. */
export interface PassphrasePolicy {
    words: number;
    separator: string;
    capitalize: boolean;
    includeNumber: boolean;
}

/** Generates a Diceware passphrase (EFF word list) according to `policy`. */
export async function generatePassphrase(policy: PassphrasePolicy): Promise<string> {
    return invoke<string>("generate_passphrase", { policy });
}

/** Current TOTP code with countdown timing. */
export interface TotpCode {
    code: string;
    period: number;
    remaining: number;
}

export async function generateTotp(secret: string): Promise<TotpCode> {
    return invoke<TotpCode>("generate_totp", { secret });
}

export async function biometricAvailable(): Promise<boolean> {
    return invoke<boolean>("biometric_available");
}

export async function biometricEnabled(): Promise<boolean> {
    return invoke<boolean>("biometric_enabled");
}

export async function enableBiometric(): Promise<void> {
    await invoke("enable_biometric");
}

export async function disableBiometric(): Promise<void> {
    await invoke("disable_biometric");
}

export async function unlockBiometric(): Promise<void> {
    await invoke("unlock_biometric");
}

export async function recoveryEnabled(): Promise<boolean> {
    return invoke<boolean>("recovery_enabled");
}

/** Enables recovery and returns the one-time recovery code to show the user. */
export async function enableRecovery(): Promise<string> {
    return invoke<string>("enable_recovery");
}

export async function disableRecovery(): Promise<void> {
    await invoke("disable_recovery");
}

/** Unlocks with a recovery code and resets the master password. */
export async function unlockWithRecovery(code: string, newPassword: string): Promise<void> {
    await invoke("unlock_with_recovery", { code, newPassword });
}

/** Returns how many times `password` appears in HIBP breaches (0 = not found). */
export async function checkPwned(password: string): Promise<number> {
    return invoke<number>("check_pwned", { password });
}

/** An entry referenced by a health finding (no secrets). */
export interface HealthItem {
    id: string;
    title: string;
}

/** A group of entries sharing the same password. */
export interface ReusedGroup {
    count: number;
    entries: HealthItem[];
}

/** Vault-health scan result. */
export interface HealthReport {
    total: number;
    weak: HealthItem[];
    reused: ReusedGroup[];
    stale: HealthItem[];
    withoutTotp: HealthItem[];
}

/**
 * Scans the unlocked vault for weak/reused/stale passwords and missing 2FA.
 * `staleAfterDays` sets the "not changed in…" window (defaults to 365 in Rust).
 */
export async function vaultHealth(staleAfterDays?: number): Promise<HealthReport> {
    return invoke<HealthReport>("vault_health", { staleAfterDays: staleAfterDays ?? null });
}

/** One entry whose password appears in a breach (from a vault-wide HIBP scan). */
export interface BreachItem {
    id: string;
    title: string;
    count: number;
}

/**
 * Checks every entry's password against Have I Been Pwned (k-anonymity), returning
 * the breached ones. Only SHA-1 prefixes leave the device; can be slow for large
 * vaults (one request per unique password).
 */
export async function vaultBreachScan(): Promise<BreachItem[]> {
    return invoke<BreachItem[]>("vault_breach_scan");
}

/** Import source identifiers accepted by the backend. */
export type ImportFormat = "bitwarden" | "keepassxc" | "onepassword";

/** Imports entries from an export file; returns how many were added. */
export async function importFile(format: ImportFormat, path: string): Promise<number> {
    return invoke<number>("import_file", { format, path });
}

/**
 * Exports the whole vault to an encrypted `.goldfish` file at `path`, protected
 * by an independent `exportPassword`. Returns how many entries were exported.
 * The decrypted bundle never leaves Rust — only ciphertext is written.
 */
export async function exportVault(exportPassword: string, path: string): Promise<number> {
    return invoke<number>("export_vault", { exportPassword, path });
}

/**
 * Imports entries from an encrypted `.goldfish` file at `path`, unlocked with
 * `exportPassword`. Returns how many entries were imported.
 */
export async function importVaultFile(exportPassword: string, path: string): Promise<number> {
    return invoke<number>("import_vault_file", { exportPassword, path });
}
