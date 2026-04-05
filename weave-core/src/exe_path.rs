//! Storage for the real path of the exe being run under Weave.
//!
//! Set once at startup by `weave-cli` before jumping to the entry point.
//! Read by `GetModuleFileNameW/A(NULL)` so the guest can find its own location.

use std::sync::OnceLock;

static EXE_PATH: OnceLock<String> = OnceLock::new();

/// Register the exe path as a Windows path (e.g. `Z:\path\to\app.exe`).
/// Subsequent calls are ignored.
pub fn set(win_path: &str) {
    let _ = EXE_PATH.set(win_path.to_string());
}

/// Return the Windows-style exe path set at startup, or `None` if not set.
pub fn get() -> Option<&'static str> {
    EXE_PATH.get().map(|s| s.as_str())
}

/// Return the directory containing the exe (everything up to the last `\`).
pub fn exe_dir() -> Option<String> {
    let p = get()?;
    let sep = p.rfind('\\')?;
    Some(p[..sep].to_string())
}
