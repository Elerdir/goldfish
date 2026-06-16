//! Tauri shell and composition root.
//!
//! Wires the concrete infrastructure adapters into a [`VaultService`], manages
//! application state, and registers the command surface that the frontend
//! invokes over IPC.

use std::path::Path;
use std::sync::Arc;

use tauri::Manager;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use goldfish_application::VaultService;
use goldfish_infrastructure::{
    FileVaultMetadataRepository, HibpClient, KeyringStore, SqliteEntryStore, SystemClock,
};

mod commands;
mod state;

use state::AppState;

/// Entry point invoked by `main.rs` and (on mobile) by the platform wrapper.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Must be registered first: a second launch focuses the running window
        // instead of opening another process against the same vault file.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_opener::init())
        // Minimize-to-tray: when the main window is minimized, hide it from the
        // taskbar — it stays reachable via the tray icon. Other windows minimize
        // normally.
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let tauri::WindowEvent::Resized(_) = event {
                    if window.is_minimized().unwrap_or(false) {
                        let _ = window.hide();
                    }
                }
            }
        })
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            init_tracing(&data_dir.join("logs"));

            let state = build_state(app.handle())?;
            app.manage(state);
            exclude_from_capture(app.handle());
            if let Err(e) = setup_tray(app.handle()) {
                tracing::warn!(error = %e, "failed to set up the system tray icon");
            }
            tracing::info!(version = env!("CARGO_PKG_VERSION"), "Goldfish starting");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::ping,
            commands::protect_window,
            commands::app_version,
            commands::read_logs,
            commands::open_logs_dir,
            commands::vault_exists,
            commands::is_unlocked,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::list_entries,
            commands::get_entry,
            commands::add_entry,
            commands::update_entry,
            commands::delete_entry,
            commands::reorder_entries,
            commands::move_entry_to_folder,
            commands::copy_secret,
            commands::open_external,
            commands::generate_password,
            commands::generate_passphrase,
            commands::estimate_strength,
            commands::generate_totp,
            commands::biometric_available,
            commands::biometric_enabled,
            commands::enable_biometric,
            commands::disable_biometric,
            commands::unlock_biometric,
            commands::recovery_enabled,
            commands::enable_recovery,
            commands::disable_recovery,
            commands::unlock_with_recovery,
            commands::check_pwned,
            commands::import_file,
            commands::export_vault,
            commands::import_vault_file,
            commands::vault_health,
            commands::vault_breach_scan,
            commands::list_backups,
            commands::restore_backup,
            commands::password_history,
            commands::list_folders,
            commands::create_folder,
            commands::rename_folder,
            commands::delete_folder,
            commands::set_folder_appearance,
            commands::list_tags,
            commands::create_tag,
            commands::rename_tag,
            commands::delete_tag,
            commands::add_attachment,
            commands::add_attachment_bytes,
            commands::list_attachments,
            commands::save_attachment,
            commands::delete_attachment,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Goldfish");
}

/// Hides a single window from screen capture / recording so a shared screen or
/// capture malware cannot read the open vault. Best-effort: requires Windows 10
/// 2004+ (older systems ignore it), and is a no-op on other platforms.
///
/// Applied to the main window at startup and to each sub-window (settings, logs,
/// entry editor) from the frontend via the `protect_window` command, so every
/// Goldfish window carries the same protection.
#[cfg(windows)]
pub(crate) fn apply_capture_exclusion(window: &tauri::WebviewWindow) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
    };

    if let Ok(handle) = window.hwnd() {
        // Tauri returns an `HWND` from its own `windows`-crate version; bridge it
        // to ours via the raw pointer (the numeric handle is the same).
        let hwnd = HWND(handle.0.cast());
        // SAFETY: `hwnd` is a live window handle owned by this process for the
        // duration of the call.
        unsafe {
            let _ = SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn apply_capture_exclusion(_window: &tauri::WebviewWindow) {}

/// Excludes the main window from screen capture at startup.
fn exclude_from_capture(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        apply_capture_exclusion(&window);
    }
}

/// Builds the system-tray icon: a Show/Quit menu plus left-click to restore the
/// main window. Together with the minimize-to-tray handler, this keeps Goldfish
/// reachable from the tray when minimized.
fn setup_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let show = MenuItem::with_id(app, "show", "Show Goldfish", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let mut builder = TrayIconBuilder::with_id("goldfish-tray")
        .tooltip("Goldfish")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// Restores the main window from the tray (or a minimized/hidden state).
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Builds the vault service from concrete adapters rooted at the app data dir.
fn build_state(app: &tauri::AppHandle) -> Result<AppState, Box<dyn std::error::Error>> {
    let data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;

    let db_path = data_dir.join("vault.db");
    let meta_path = data_dir.join("vault.meta.json");

    let store = Arc::new(SqliteEntryStore::new(db_path));
    let meta = Arc::new(FileVaultMetadataRepository::new(meta_path));
    let service = VaultService::new(
        store.clone(),
        store,
        meta,
        Arc::new(SystemClock),
        Arc::new(KeyringStore::new()),
    );

    Ok(AppState::new(service, Arc::new(HibpClient::new())))
}

/// Initializes tracing to both the console and a daily-rotated log file under
/// `log_dir` (keeping the last week). The file uses no ANSI colors so it stays
/// readable in the in-app log viewer. No secrets are ever logged — credential
/// types redact their `Debug` output.
fn init_tracing(log_dir: &Path) {
    let _ = std::fs::create_dir_all(log_dir);
    let filter = EnvFilter::try_from_env("GOLDFISH_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,goldfish=debug"));

    let file_layer = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("goldfish")
        .filename_suffix("log")
        .max_log_files(7)
        .build(log_dir)
        .ok()
        .map(|writer| {
            fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_target(true)
        });

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true).with_thread_ids(false))
        .with(file_layer)
        .try_init();
}
