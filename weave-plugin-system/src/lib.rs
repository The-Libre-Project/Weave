//! Weave plugin system.
//!
//! Plugins are native Linux `.so` files placed in `{prefix}/plugins/`. Each
//! plugin exports one C-ABI entry point:
//!
//! ```c
//! int weave_plugin_init(const WeavePluginApi *api);
//! ```
//!
//! The plugin calls `api->register_fn` for every Windows API function it
//! wants to override, then returns 0 on success or non-zero on failure.
//!
//! Plugin overrides take priority over Weave's built-in stubs.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

// ── Global override registry ──────────────────────────────────────────────────

/// (lowercase dll name, function name) → function address.
static OVERRIDES: OnceLock<Mutex<HashMap<(String, String), usize>>> = OnceLock::new();

fn overrides() -> &'static Mutex<HashMap<(String, String), usize>> {
    OVERRIDES.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── C ABI surface ─────────────────────────────────────────────────────────────

/// Registration callback passed to plugins.
///
/// # Safety
/// `dll` and `func` must point to valid UTF-8 data of `dll_len` / `func_len`
/// bytes respectively. `addr` must be a valid function pointer.
pub type RegisterFn = unsafe extern "C" fn(
    dll: *const u8,
    dll_len: usize,
    func: *const u8,
    func_len: usize,
    addr: usize,
);

/// API object passed to every plugin's `weave_plugin_init`.
///
/// The layout is stable: new fields are only ever appended.
#[repr(C)]
pub struct WeavePluginApi {
    /// Always 1 for this release.
    pub version: u32,
    /// Register a dll!func → addr override.
    pub register_fn: RegisterFn,
}

/// The C-ABI registration callback implementation.
///
/// Plugins call this via the function pointer in `WeavePluginApi`.
///
/// # Safety
/// `dll` and `func` must be valid UTF-8 slices of the given lengths.
/// `addr` is stored as-is and is assumed to be a valid function address.
unsafe extern "C" fn register_override(
    dll: *const u8,
    dll_len: usize,
    func: *const u8,
    func_len: usize,
    addr: usize,
) {
    let dll_str =
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(dll, dll_len)) };
    let func_str =
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(func, func_len)) };
    overrides()
        .lock()
        .unwrap()
        .insert((dll_str.to_lowercase(), func_str.to_string()), addr);
}

// ── Plugin loader ─────────────────────────────────────────────────────────────

/// Load all `.so` plugins from `plugins_dir`.
///
/// For each `.so` found, the library is opened with `libloading`, the symbol
/// `weave_plugin_init` is resolved, and the function is called with a
/// `WeavePluginApi` reference. Libraries are intentionally leaked so that
/// plugin code stays mapped for the lifetime of the process.
///
/// Missing or unreadable plugin files are silently skipped. A plugin that
/// returns a non-zero value is logged and skipped; it does not abort startup.
///
/// If `plugins_dir` does not exist this function returns immediately.
pub fn load_plugins(plugins_dir: &Path) {
    let entries = match std::fs::read_dir(plugins_dir) {
        Ok(e) => e,
        Err(_) => return, // directory missing — no plugins installed
    };

    let api = WeavePluginApi {
        version: 1,
        register_fn: register_override,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("so") {
            continue;
        }

        // Safety: we are opening a trusted plugin from the user's prefix.
        let lib = match unsafe { libloading::Library::new(&path) } {
            Ok(l) => l,
            Err(e) => {
                eprintln!("weave: plugin: could not open {}: {e}", path.display());
                continue;
            }
        };

        // Safety: the symbol type matches the contract documented in this
        // module's top-level doc comment.
        let init: libloading::Symbol<unsafe extern "C" fn(*const WeavePluginApi) -> i32> =
            match unsafe { lib.get(b"weave_plugin_init\0") } {
                Ok(s) => s,
                Err(_) => {
                    eprintln!(
                        "weave: plugin: {} has no weave_plugin_init — skipped",
                        path.display()
                    );
                    continue;
                }
            };

        let rc = unsafe { init(&api as *const WeavePluginApi) };
        if rc != 0 {
            eprintln!(
                "weave: plugin: {} returned error {rc} — skipped",
                path.display()
            );
            continue;
        }

        eprintln!("weave: plugin: loaded {}", path.display());

        // Leak the Library so the .so stays mapped for the process lifetime.
        std::mem::forget(lib);
    }
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Look up a plugin-registered override for `dll!func`.
///
/// Returns `Some(addr)` if a plugin registered an override, `None` otherwise.
/// `dll` is matched case-insensitively.
pub fn lookup(dll: &str, func: &str) -> Option<usize> {
    overrides()
        .lock()
        .unwrap()
        .get(&(dll.to_lowercase(), func.to_string()))
        .copied()
}
