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
    /// Next handle to assign.
    next: usize,
}

static TABLE: Mutex<Option<HandleTable>> = Mutex::new(None);

fn with_table<F, R>(f: F) -> R
where
    F: FnOnce(&mut HandleTable) -> R,
{
    let mut guard = TABLE.lock().unwrap();
    let table = guard.get_or_insert_with(|| HandleTable {
        name_to_handle: HashMap::new(),
        handle_to_name: HashMap::new(),
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
    with_table(|t| {
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

/// Look up the DLL name for a synthetic HMODULE returned by `register()`.
///
/// Returns `None` if the handle is unknown (e.g. 0 or a real pointer outside
/// the synthetic range).
pub fn lookup(handle: usize) -> Option<String> {
    if handle < HANDLE_BASE {
        return None;
    }
    with_table(|t| t.handle_to_name.get(&handle).cloned())
}

/// Extract the lowercase DLL basename from a path or bare name.
///
/// `r"C:\Windows\System32\SHELL32.DLL"` → `"shell32.dll"`
/// `"shell32.dll"` → `"shell32.dll"`
fn dll_basename(name: &str) -> String {
    let base = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name);
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
        assert_eq!(
            dll_basename(r"C:\Windows\System32\ntdll.dll"),
            "ntdll.dll"
        );
    }
}
