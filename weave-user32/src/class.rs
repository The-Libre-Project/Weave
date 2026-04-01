//! Window class registry.
//!
//! Maps class names (case-insensitive) to registered WNDCLASSW data.
//! `RegisterClassW` stores here; `CreateWindowExW` looks up here.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Data stored for each registered window class.
#[derive(Clone)]
pub struct ClassEntry {
    /// The window procedure — stored as `usize` and called via transmute
    /// with `extern "win64"` ABI.
    pub wnd_proc: usize,
    pub style: u32,
    pub h_cursor: usize,
    pub hbr_background: usize,
}

// ── Global class table ────────────────────────────────────────────────────────

static CLASSES: OnceLock<Mutex<HashMap<String, ClassEntry>>> = OnceLock::new();

fn table() -> &'static Mutex<HashMap<String, ClassEntry>> {
    CLASSES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a window class. Uses the lowercase class name as the key so
/// lookups are case-insensitive (matching Windows registry-like behaviour).
///
/// Returns `true` if the class was newly registered, `false` if it replaced
/// an existing registration with the same name.
pub fn register(name: &str, entry: ClassEntry) -> bool {
    let key = name.to_ascii_lowercase();
    let mut guard = table().lock().unwrap();
    let replaced = guard.contains_key(&key);
    guard.insert(key, entry);
    !replaced
}

/// Look up a registered window class by name (case-insensitive).
pub fn find(name: &str) -> Option<ClassEntry> {
    let key = name.to_ascii_lowercase();
    table().lock().unwrap().get(&key).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy() -> ClassEntry {
        ClassEntry {
            wnd_proc: 0x1234,
            style: 0,
            h_cursor: 0,
            hbr_background: 0,
        }
    }

    #[test]
    fn register_and_find() {
        register("MyApp", dummy());
        assert!(find("MyApp").is_some());
        assert!(find("myapp").is_some()); // case-insensitive
        assert!(find("MYAPP").is_some());
    }

    #[test]
    fn find_unknown_returns_none() {
        assert!(find("__NonExistent__").is_none());
    }

    #[test]
    fn register_replaces_existing() {
        register(
            "ReplacedClass",
            ClassEntry {
                wnd_proc: 1,
                ..dummy()
            },
        );
        let newly_registered = register(
            "ReplacedClass",
            ClassEntry {
                wnd_proc: 2,
                ..dummy()
            },
        );
        assert!(!newly_registered);
        assert_eq!(find("replacedclass").unwrap().wnd_proc, 2);
    }
}
