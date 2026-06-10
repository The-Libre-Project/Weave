//! Global Weave prefix path.
//!
//! The "prefix" is the directory that acts as the virtual Windows filesystem
//! root for a running application. Drive `C:` maps to `{prefix}/drive_c/`,
//! drive `D:` to `{prefix}/drive_d/`, and so on — the same convention Wine uses.
//!
//! `set()` is called once by `weave-cli` before launching the PE. After that,
//! `translator()` returns a `WinPathTranslator` ready to use from any stub.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use weave_common::path::WinPathTranslator;

static PREFIX: OnceLock<PathBuf> = OnceLock::new();

/// Set the Weave prefix directory. Must be called before any file I/O stubs
/// run. Subsequent calls are silently ignored — the prefix is immutable once
/// set.
pub fn set(path: PathBuf) {
    let _ = PREFIX.set(path);
}

/// Return the active prefix path.
///
/// If `set()` has never been called, a sensible default is used:
/// `$HOME/.weave/default` (or `/tmp/.weave/default` if `$HOME` is unset).
pub fn get() -> &'static Path {
    PREFIX.get_or_init(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".weave").join("default")
    })
}

/// Create a `WinPathTranslator` for the current prefix.
///
/// This is cheap — it just clones the prefix `PathBuf` into the translator.
/// Call it per-operation; no need to cache.
pub fn translator() -> WinPathTranslator {
    WinPathTranslator::new(get().to_path_buf())
}

/// Return the path to the virtual `C:\Windows\System32` directory.
///
/// This is where DLLs shipped with the prefix (e.g. DXVK's `d3d11.dll`)
/// should be placed.
pub fn system32() -> PathBuf {
    get().join("drive_c").join("Windows").join("System32")
}

/// Ensure the basic prefix directory skeleton exists.
///
/// Creates `drive_c/` (and `drive_c/Windows/Temp`) so that apps can
/// create files with relative paths (which map to `drive_c/`) without
/// failing because the parent directory doesn't exist.
///
/// Called once at startup by weave-cli before the PE runs.
pub fn ensure_dirs() {
    let prefix = get();
    let _ = std::fs::create_dir_all(prefix.join("drive_c"));
    let _ = std::fs::create_dir_all(prefix.join("drive_c/Windows/System32"));
    let _ = std::fs::create_dir_all(prefix.join("drive_c/Windows/Temp"));
    let _ = std::fs::create_dir_all(prefix.join("drive_c/users/weave/AppData/Local/Temp"));
}

/// Return the path to the prefix's plugin directory (`{prefix}/plugins/`).
///
/// Reserved for a future signed-plugin model. The runtime `.so` loader was
/// removed for security reasons; this directory is created but not scanned.
/// No callers in-tree as of 2026-06-09.
pub fn plugins_dir() -> PathBuf {
    get().join("plugins")
}
