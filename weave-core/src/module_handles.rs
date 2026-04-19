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
use std::sync::Mutex;

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
}
