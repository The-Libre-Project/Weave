//! Tauri backend for weave-gui.
//!
//! Exposes IPC commands that the Svelte frontend calls via `invoke()`.
//! Orchestrates weave-installer (prefix lifecycle) and weave-desktop
//! (app menu integration) so creating a prefix also installs a .desktop
//! entry and deleting one removes it.

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

/// Creates a new application prefix and installs a `.desktop` menu entry.
///
/// If `exe_path` is non-empty, also stores it on the prefix and generates
/// a `.desktop` file so the app appears in the Linux application menu.
/// The desktop database is updated automatically.
#[tauri::command]
fn create_prefix(name: String, exe_path: String) -> Result<(), String> {
    let mgr = PrefixManager::new().map_err(|e| e.to_string())?;
    let prefix = mgr.create(&name).map_err(|e| e.to_string())?;

    if !exe_path.is_empty() {
        prefix
            .set_exe_path(Path::new(&exe_path))
            .map_err(|e| e.to_string())?;

        // Best-effort icon extraction — silently ignore failures so that
        // apps without embedded icons (or with unreadable .exe files) still
        // get a working .desktop entry using the default Weave icon.
        let icon_path = weave_desktop::extract_and_install_icon(&name, Path::new(&exe_path))
            .ok()
            .flatten();

        let exec_cmd = format!("weave run {exe_path}");
        let content =
            weave_desktop::generate_desktop_file(&name, &exec_cmd, icon_path.as_deref(), "Wine;");
        weave_desktop::install_desktop_file(&name, &content)
            .map_err(|e| e.to_string())?;
        weave_desktop::update_desktop_database()
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Deletes an application prefix and removes its `.desktop` menu entry.
#[tauri::command]
fn delete_prefix(name: String) -> Result<(), String> {
    let mgr = PrefixManager::new().map_err(|e| e.to_string())?;
    weave_desktop::uninstall_desktop_file(&name)
        .map_err(|e| e.to_string())?;
    weave_desktop::update_desktop_database()
        .map_err(|e| e.to_string())?;
    mgr.delete(&name).map_err(|e| e.to_string())
}

/// Launches the application associated with the given prefix.
///
/// Reads the exe path from `<prefix>/exe.txt`, then spawns
/// `weave run <exe_path>` as a detached background process.
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

/// Registers Weave as the default handler for `.exe` files via xdg-mime.
///
/// This is a one-time setup step. After calling this, double-clicking a
/// `.exe` file in the Linux file manager will open it with Weave.
/// Returns `Ok(())` silently if xdg-mime is not installed.
#[tauri::command]
fn register_exe_handler() -> Result<(), String> {
    weave_desktop::register_exe_handler().map_err(|e| e.to_string())
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
            register_exe_handler,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
