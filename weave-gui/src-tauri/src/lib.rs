//! Tauri backend for weave-gui.
//!
//! Exposes IPC commands that the Svelte frontend calls via `invoke()`.
//! All commands delegate to `weave-installer` for prefix management and
//! to the `weave` CLI binary for launching applications.

use std::path::Path;
use weave_installer::PrefixManager;

/// Returns the number of installed application prefixes.
#[tauri::command]
fn count_apps() -> Result<u32, String> {
    let mgr = PrefixManager::new().map_err(|e| e.to_string())?;
    let list = mgr.list().map_err(|e| e.to_string())?;
    Ok(list.len() as u32)
}

/// Returns the names of all installed application prefixes.
#[tauri::command]
fn list_apps() -> Result<Vec<String>, String> {
    let mgr = PrefixManager::new().map_err(|e| e.to_string())?;
    let list = mgr.list().map_err(|e| e.to_string())?;
    Ok(list.into_iter().map(|p| p.name).collect())
}

/// Creates a new application prefix.
///
/// `exe_path` is the Windows-style path to the main executable within the
/// prefix's drive_c (e.g. `C:\Program Files\App\app.exe`). May be empty
/// if the exe location is not yet known.
#[tauri::command]
fn create_prefix(name: String, exe_path: String) -> Result<(), String> {
    let mgr = PrefixManager::new().map_err(|e| e.to_string())?;
    let prefix = mgr.create(&name).map_err(|e| e.to_string())?;
    if !exe_path.is_empty() {
        prefix
            .set_exe_path(Path::new(&exe_path))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Deletes an application prefix and all its contents.
#[tauri::command]
fn delete_prefix(name: String) -> Result<(), String> {
    let mgr = PrefixManager::new().map_err(|e| e.to_string())?;
    mgr.delete(&name).map_err(|e| e.to_string())
}

/// Launches the application associated with the given prefix.
///
/// Reads the exe path from `<prefix>/exe.txt`, then spawns
/// `weave run <exe_path>` as a background process.
#[tauri::command]
fn launch_app(prefix_name: String) -> Result<(), String> {
    let mgr = PrefixManager::new().map_err(|e| e.to_string())?;
    let prefix = mgr.get(&prefix_name).map_err(|e| e.to_string())?;
    let exe_path = prefix
        .get_exe_path()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no executable configured for prefix '{prefix_name}'"))?;
    std::process::Command::new("weave")
        .arg("run")
        .arg(&exe_path)
        .spawn()
        .map_err(|e| format!("failed to launch weave: {e}"))?;
    Ok(())
}

/// Tauri application entry point — called from `main.rs`.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            count_apps,
            list_apps,
            create_prefix,
            delete_prefix,
            launch_app,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
