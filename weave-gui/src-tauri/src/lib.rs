//! Tauri backend for weave-gui.
//!
//! Exposes IPC commands that the Svelte frontend calls via `invoke()`.
//! Phase 5 initial scaffold — commands are stubbed and will be wired to
//! `weave-installer` and `weave-desktop` in the next task.

/// Returns the number of installed Windows application prefixes.
///
/// Phase 5 stub — returns 0 until wired to weave-installer.
#[tauri::command]
fn count_apps() -> u32 {
    0
}

/// Returns the names of all installed application prefixes.
///
/// Phase 5 stub — returns an empty list until wired to weave-installer.
#[tauri::command]
fn list_apps() -> Vec<String> {
    vec![]
}

/// Launches a Windows application by its prefix name.
///
/// Phase 5 stub — returns an error until wired to weave-cli.
#[tauri::command]
fn launch_app(prefix_name: String) -> Result<(), String> {
    let _ = prefix_name;
    Err("launch not yet implemented".to_string())
}

/// Tauri application entry point — called from `main.rs`.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![count_apps, list_apps, launch_app])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}