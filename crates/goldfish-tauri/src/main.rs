// Hide the console window on Windows release builds (keep it on debug for diagnostics).
#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

fn main() {
    goldfish_tauri_lib::run();
}
