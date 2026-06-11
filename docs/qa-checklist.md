# Goldfish manual QA checklist

Automated tests cover the crypto, application, and infrastructure layers, plus
frontend hooks/providers (Vitest + RTL). This checklist covers what they **can't**
reach without real hardware/OS integration: platform APIs (Windows Hello, macOS
Touch ID, tray, screen capture, clipboard), the live network, file dialogs, and
the packaged installers.

Run it before a release, and after any change to the Tauri shell, capabilities,
window config, or platform `cfg(...)` code. Mark per platform.

Legend: ✅ pass · ❌ fail · ➖ n/a on this platform

## 0. Build & launch

- [ ] `cargo tauri dev` launches; main window opens centered, non-resizable.
- [ ] `cargo tauri build --bundles msi,nsis` (Win) / `dmg` (mac) / `deb,appimage`
      (Linux) produces installers without errors.
- [ ] Installed app launches; single-instance (second launch focuses the first).

## 1. Onboarding & unlock

- [ ] Fresh profile → onboarding; weak/short/mismatched passwords are rejected
      (zxcvbn ≥ 3 required).
- [ ] Create vault → lands unlocked.
- [ ] Lock → unlock with correct password works; wrong password shows an error.
- [ ] Repeated wrong passwords throttle (increasing delay); throttle **survives an
      app restart**.
- [ ] Recovery code: enable (shown once), lock, unlock-with-recovery resets the
      master password.

## 2. Biometric unlock

- **Windows Hello** (requires Hello PIN/biometric enrolled — `dsregcmd /status`
  shows `NgcSet: YES`):
  - [ ] Settings shows the biometric toggle **enabled** (not greyed). If greyed,
        the log window states the reason.
  - [ ] Enable while unlocked → no error.
  - [ ] Lock → unlock screen shows the fingerprint button → click → **Hello prompt
        appears** → verifying unlocks the vault.
  - [ ] Disable removes it (toggle off; next lock has no biometric button).
- **macOS Touch ID** (Mac with Touch ID):
  - [ ] Toggle appears only when Touch ID is enrolled.
  - [ ] Unlock triggers the Touch ID sheet; success unlocks.

## 3. Auto-lock

- [ ] Idle for the configured minutes → locks. Setting 0 disables idle lock.
- [ ] Lock-on-blur (if enabled) locks shortly after focus loss; opening a
      sub-window (settings/entry) does **not** lock behind it.
- [ ] Sleep/hibernate the machine while unlocked → on resume the vault is locked.

## 4. Clipboard

- [ ] Copy username/password → clears after the configured seconds.
- [ ] Lock or quit clears the clipboard immediately.
- [ ] **Windows**: the copied secret does **not** appear in Clipboard History
      (`Win+V`) or cloud clipboard.

## 5. Screen-capture exclusion (Windows)

For **each** window — main, Settings, Logs, entry editor:

- [ ] A screenshot (`Win+Shift+S`) of the window is blank/black.
- [ ] Sharing the screen in Teams/Zoom shows the window blank to others.
- ➖ macOS/Linux: no-op by design (documented).

## 6. System tray (minimize to tray)

- [ ] Minimizing the main window hides it from the taskbar; the tray icon remains.
- [ ] Left-clicking the tray icon (or "Show Goldfish") restores + focuses it.
- [ ] "Quit" exits the app.
- [ ] Sub-windows minimize normally (stay in the taskbar).

## 7. Title-bar theme

- [ ] Switching theme to Dark turns the native title bar (app name + min/close)
      dark — on **every** window. Light reverts it. "System" follows the OS.

## 8. Backups & restore

- [ ] Using the app over time creates snapshots under `backups/` (≤ 10 kept).
- [ ] Unlock screen → "Restore from a backup" lists snapshots (newest first).
- [ ] Restoring swaps the DB, creates a `*-prerestore` snapshot, and the vault
      unlocks with the **current** master password afterwards.
- [ ] A restored vault from before a schema change opens (migrations re-run).

## 9. Breach scan & HIBP (live network)

- [ ] Entry detail breach check returns a result for a known-pwned password
      (e.g. `password`) and "safe" for a strong unique one.
- [ ] Vault-wide breach scan completes; **the UI stays responsive during the scan**
      (other entries open/edit while it runs — verifies the lock isn't held over
      the network).

## 10. Import / export & portability

- [ ] Encrypted export (`.goldfish`) → import on a **fresh** vault round-trips all
      entries (and attachments).
- [ ] Import from Bitwarden JSON / KeePassXC CSV / 1Password CSV.
- [ ] Move an export from Windows → macOS (or vice versa) and import it — confirms
      cross-platform portability.

## 11. Multi-window & sync

- [ ] Settings and entry editor open as their own OS windows (full size).
- [ ] Editing/saving in a sub-window refreshes the main window lists.
- [ ] Theme/language/settings changes sync across open windows.

## 12. Features regression

- [ ] TOTP code shows + counts down; copy works.
- [ ] Attachments add/save/delete (≤ 10 MiB enforced).
- [ ] Tags create/assign/filter/delete; folders create/rename/delete/select.
- [ ] Drag-and-drop reorders entries and moves them between folders.
- [ ] Per-view appearance (folder + all-entries) applies to panel and rail.
- [ ] Password & passphrase generators; strength meter.
- [ ] Open-URL-in-browser from an entry.

## 13. Installer hygiene

- [ ] MSI and NSIS install and uninstall cleanly (Windows).
- [ ] App data lives under the `com.goldfish.desktop` identifier dir; uninstall
      leaves the vault (user data) intact unless explicitly removed.
