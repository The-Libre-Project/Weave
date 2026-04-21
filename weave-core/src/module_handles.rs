//! Fake HMODULE registry for Weave's dynamic DLL loading stubs.
//!
//! Windows apps call `LoadLibraryExW` and then `GetProcAddress(hModule, name)`.
//! Weave cannot load arbitrary Windows DLLs, but it returns a synthetic
//! HMODULE and back-maps it to a DLL name when `GetProcAddress` is called.
//!
//! Handle space: values start at `HANDLE_BASE` (0x7FFF_0001) and increment by
//! one per unique DLL. This range is outside the normal user-space mmap area,
//! so synthetic handles will not collide with real mapped pointers.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const HANDLE_BASE: usize = 0x7FFF_0001;

struct HandleTable {
    /// DLL name (lowercase, e.g. `"shell32.dll"`) → synthetic handle.
    name_to_handle: HashMap<String, usize>,
    /// Synthetic handle → DLL name.
    handle_to_name: HashMap<usize, String>,
    /// Handle → loaded base address of the mapped PE image.
    ///
    /// Populated via `register_with_base` (task 09 step 3). The resource
    /// walker reads this to convert an `HMODULE` into the image base it
    /// needs for directory traversal. Only populated for modules whose
    /// image Weave actually mapped — plain `register()` does not set it.
    handle_to_base: HashMap<usize, usize>,
    /// Next handle to assign.
    next: usize,
}

static TABLE: Mutex<Option<HandleTable>> = Mutex::new(None);

fn with_table<F, R>(fallback: R, f: F) -> R
where
    F: FnOnce(&mut HandleTable) -> R,
{
    let mut guard = match TABLE
        .lock()
        .map_err(|e| eprintln!("weave: weave-core: module handle table mutex poisoned: {e}"))
    {
        Ok(g) => g,
        Err(_) => return fallback,
    };
    let table = guard.get_or_insert_with(|| HandleTable {
        name_to_handle: HashMap::new(),
        handle_to_name: HashMap::new(),
        handle_to_base: HashMap::new(),
        next: HANDLE_BASE,
    });
    f(table)
}

/// Register `dll_name` (case-insensitive) and return a synthetic HMODULE.
///
/// If the same DLL was registered before, returns the existing handle.
/// `dll_name` may include a path — only the final component (basename) is used.
pub fn register(dll_name: &str) -> usize {
    let key = dll_basename(dll_name);
    with_table(0, |t| {
        if let Some(&existing) = t.name_to_handle.get(&key) {
            return existing;
        }
        let handle = t.next;
        t.next += 1;
        t.name_to_handle.insert(key.clone(), handle);
        t.handle_to_name.insert(handle, key);
        handle
    })
}

/// Look up the DLL name for an HMODULE returned by `register()` or
/// `register_with_handle()`. Returns `None` if the handle is unknown.
pub fn lookup(handle: usize) -> Option<String> {
    if handle == 0 {
        return None;
    }
    with_table(None, |t| t.handle_to_name.get(&handle).cloned())
}

/// Register `dll_name` with a caller-supplied handle value.
///
/// Used by the dynamic DLL loader to record the real base address of a
/// PE image as its HMODULE (Windows convention: HMODULE == image base).
/// If `dll_name` was already registered with a different handle, the new
/// handle replaces the old mapping.
pub fn register_with_handle(dll_name: &str, handle: usize) {
    let key = dll_basename(dll_name);
    with_table((), |t| {
        t.name_to_handle.insert(key.clone(), handle);
        t.handle_to_name.insert(handle, key);
    });
}

/// Register `dll_name` (case-insensitive), allocate (or reuse) a synthetic
/// HMODULE, and record the loaded base address of the mapped PE image.
///
/// Used by the loader for the guest exe (task 09 step 3). Downstream code
/// — in particular the resource walker — looks up the base via
/// `base_of(handle)` to convert an `HMODULE` back into the image base
/// pointer needed for directory traversal.
///
/// Returns the synthetic handle. If `dll_name` was previously registered
/// via plain `register`, the existing handle is reused and its base is
/// populated in place.
pub fn register_with_base(dll_name: &str, base: usize) -> usize {
    let key = dll_basename(dll_name);
    with_table(0, |t| {
        let handle = if let Some(&existing) = t.name_to_handle.get(&key) {
            existing
        } else {
            let h = t.next;
            t.next += 1;
            t.name_to_handle.insert(key.clone(), h);
            t.handle_to_name.insert(h, key);
            h
        };
        t.handle_to_base.insert(handle, base);
        handle
    })
}

/// Return the loaded base address previously recorded for `handle` via
/// `register_with_base`. Returns `None` for handles registered without a
/// base (plain `register` / `register_with_handle`) or for unknown
/// handles.
pub fn base_of(handle: usize) -> Option<usize> {
    if handle == 0 {
        return None;
    }
    with_table(None, |t| t.handle_to_base.get(&handle).copied())
}

/// Register an identity mapping where the HMODULE value *is* the loaded
/// base address (Windows convention: HMODULE == image base for a mapped
/// PE). After this call, `base_of(base)` returns `Some(base)`.
///
/// This is what the loader uses for the guest exe: real Win32 code reaches
/// into resources via `LoadStringW(GetModuleHandleW(NULL), ...)` which
/// resolves to `seh::pe_base()` — the actual loaded base, not a synthetic
/// handle. Without this mapping the resource walker can't translate.
///
/// No name is recorded — callers that also want a name lookup should use
/// `register_with_handle` separately.
pub fn register_image_base(base: usize) {
    if base == 0 {
        return;
    }
    with_table((), |t| {
        t.handle_to_base.insert(base, base);
    });
}

/// Register a preferred-base alias so that `base_of(alias)` returns `actual`.
///
/// Used when a PE is rebased away from its `OptionalHeader.ImageBase`
/// (preferred base). The MSVC CRT reads `ImageBase` directly from the mapped
/// PE header and passes it unchanged as the `hInst` argument to resource
/// APIs (`LoadStringW`, `FindResourceW`, etc.). If `MAP_FIXED_NOREPLACE`
/// failed and the image landed at a different address, callers using the
/// preferred base as HMODULE would get `base_of` → `None` and every resource
/// call would return 0.
///
/// After this call, `base_of(alias)` returns `Some(actual)` so the resource
/// walker can resolve the image regardless of whether the caller uses the
/// preferred base or the real mapped base.
///
/// No-ops when `alias == actual` (identity already covered by
/// `register_image_base`) or when either argument is 0.
pub fn register_image_base_alias(alias: usize, actual: usize) {
    if alias == 0 || actual == 0 || alias == actual {
        return;
    }
    with_table((), |t| {
        t.handle_to_base.insert(alias, actual);
    });
}

// ---------------------------------------------------------------------------
// Path → base registry
// ---------------------------------------------------------------------------
//
// GetFileVersionInfoSizeW / GetFileVersionInfoW receive a **filesystem path**
// (not an HMODULE). We need to map that back to a loaded image base so the
// resource walker can find the RT_VERSION resource.
//
// The registry is populated by `register_image_path` (called from the loader
// alongside `register_image_base`). It indexes both the full normalized path
// and the bare filename so that "notepad.exe" queries succeed even if the
// caller passed just the basename.
//
// Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoSizeExW opens the
// file via LoadLibraryExW(LOAD_LIBRARY_AS_IMAGE_RESOURCE) and then uses
// FindResourceW / SizeofResource. Weave instead looks up the already-loaded
// base; if the module is not loaded we return 0 gracefully.

static PATH_TO_BASE: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn path_to_base_map() -> &'static Mutex<HashMap<String, usize>> {
    PATH_TO_BASE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a loaded module's filesystem path → image base mapping.
///
/// Called by the loader immediately after mapping the guest PE, alongside
/// `register_image_base`. Both the full normalized path and the bare filename
/// are indexed so that callers using either form succeed.
///
/// Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoSizeExW / ExW
/// open the file by path to locate RT_VERSION; Weave pre-registers the path
/// at load time so we avoid re-opening the file from disk.
pub fn register_image_path(path: &str, base: usize) {
    // Normalize: lowercase, forward-slashes, strip Windows drive prefix.
    let norm = path.to_ascii_lowercase().replace('\\', "/");
    let filename = norm.rsplit('/').next().unwrap_or(&norm).to_string();
    if let Ok(mut m) = path_to_base_map().lock() {
        m.insert(norm, base);
        // Also index by bare filename so "notepad.exe" queries work.
        m.insert(filename, base);
    }
}

/// Look up a loaded base by path or bare filename.
///
/// Returns `None` if the module was never registered (module not yet loaded
/// or loaded without a path). The caller should return 0 gracefully.
///
/// Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoSizeExW returns 0
/// (ERROR_RESOURCE_DATA_NOT_FOUND) when the resource cannot be located;
/// Weave mirrors this by returning None → 0.
pub fn base_by_path(path: &str) -> Option<usize> {
    let norm = path.to_ascii_lowercase().replace('\\', "/");
    let filename = norm.rsplit('/').next().unwrap_or(&norm).to_string();
    if let Ok(m) = path_to_base_map().lock() {
        m.get(&norm).or_else(|| m.get(&filename)).copied()
    } else {
        None
    }
}

/// Extract the lowercase DLL basename from a path or bare name.
///
/// `r"C:\Windows\System32\SHELL32.DLL"` → `"shell32.dll"`
/// `"shell32.dll"` → `"shell32.dll"`
fn dll_basename(name: &str) -> String {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    base.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_returns_nonzero() {
        let h = register("test_nonzero.dll");
        assert!(h >= HANDLE_BASE);
    }

    #[test]
    fn register_same_dll_same_handle() {
        let h1 = register("test_same_a.dll");
        let h2 = register("TEST_SAME_A.DLL");
        assert_eq!(h1, h2);
    }

    #[test]
    fn register_strips_path() {
        let h1 = register("test_strip.dll");
        let h2 = register(r"C:\Windows\System32\TEST_STRIP.DLL");
        assert_eq!(h1, h2);
    }

    #[test]
    fn lookup_returns_dll_name() {
        let h = register("test_lookup.dll");
        assert_eq!(lookup(h).as_deref(), Some("test_lookup.dll"));
    }

    #[test]
    fn lookup_zero_returns_none() {
        assert!(lookup(0).is_none());
    }

    #[test]
    fn dll_basename_simple() {
        assert_eq!(dll_basename("KERNEL32.DLL"), "kernel32.dll");
    }

    #[test]
    fn dll_basename_with_path() {
        assert_eq!(dll_basename(r"C:\Windows\System32\ntdll.dll"), "ntdll.dll");
    }

    #[test]
    fn register_with_base_stores_and_returns_base() {
        let h = register_with_base("test_base_a.dll", 0x1234_5000);
        assert!(h >= HANDLE_BASE);
        assert_eq!(base_of(h), Some(0x1234_5000));
    }

    #[test]
    fn base_of_unknown_handle_returns_none() {
        // Pick a handle clearly outside anything we've allocated.
        assert!(base_of(0xDEAD_BEEF).is_none());
        assert!(base_of(0).is_none());
    }

    #[test]
    fn plain_register_has_no_base() {
        let h = register("test_base_nobase.dll");
        assert!(base_of(h).is_none());
    }

    #[test]
    fn register_with_base_reuses_existing_handle() {
        let h1 = register("test_base_reuse.dll");
        let h2 = register_with_base("test_base_reuse.dll", 0xAABB_C000);
        assert_eq!(h1, h2);
        assert_eq!(base_of(h2), Some(0xAABB_C000));
    }

    #[test]
    fn register_image_base_is_identity() {
        // The guest exe's HMODULE is its loaded base — `LoadStringW(GetModuleHandleW(NULL), ...)`
        // passes the real base. After registration, `base_of(base)` must return the base.
        let base: usize = 0x0000_0001_4000_0000;
        register_image_base(base);
        assert_eq!(base_of(base), Some(base));
    }

    #[test]
    fn register_image_base_zero_noop() {
        // Defensive — never insert 0 as a base.
        register_image_base(0);
        assert!(base_of(0).is_none());
    }

    #[test]
    fn register_image_base_alias_maps_preferred_to_actual() {
        // Simulates a PE rebased away from its preferred ImageBase.
        // base_of(preferred) must return the actual mapped base.
        let preferred: usize = 0x0000_0001_4000_0000; // typical MSVC x64 preferred base
        let actual: usize = 0x0000_7F00_0000_0000; // where mmap actually landed
        register_image_base(actual);
        register_image_base_alias(preferred, actual);
        assert_eq!(base_of(preferred), Some(actual));
        assert_eq!(base_of(actual), Some(actual));
    }

    #[test]
    fn register_image_base_alias_identity_is_noop() {
        // When preferred == actual no extra entry is inserted; the identity
        // mapping registered by register_image_base still satisfies the lookup.
        let base: usize = 0x0000_0001_4000_1000;
        register_image_base(base);
        register_image_base_alias(base, base); // must not panic or overwrite
        assert_eq!(base_of(base), Some(base));
    }
}
