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

/// Stub window proc for built-in and common-control classes.
///
/// Handles the minimum messages needed to allow window creation and destruction.
/// Returns TRUE for WM_NCCREATE (allows creation), 0 for everything else.
extern "win64" fn builtin_control_wnd_proc(
    _hwnd: usize,
    msg: u32,
    _wparam: usize,
    _lparam: usize,
) -> usize {
    match msg {
        0x0081 => 1, // WM_NCCREATE → TRUE
        _ => 0,
    }
}

/// Returns true if `name` (lowercase) is a Windows predefined class or
/// common control class that should be available without explicit registration.
fn is_builtin_class(name: &str) -> bool {
    matches!(
        name,
        // Win32 predefined classes
        "button"
            | "static"
            | "edit"
            | "listbox"
            | "combobox"
            | "scrollbar"
            | "combolbox"
            // Common controls (comctl32)
            | "syslistview32"
            | "systreeview32"
            | "toolbarwindow32"
            | "msctls_statusbar32"
            | "msctls_progress32"
            | "msctls_trackbar32"
            | "msctls_updown32"
            | "systabcontrol32"
            | "sysheader32"
            | "sysanimate32"
            | "sysipaddress32"
            | "sysmonthcal32"
            | "sysdatetimepick32"
            | "rebarwindow32"
            | "nativefontctl"
            | "tooltips_class32"
            // Rich edit (various versions)
            | "richedit"
            | "richedit_class"
            | "richedit20a"
            | "richedit20w"
            | "richedit50w"
    )
}

/// Look up a registered window class by name (case-insensitive).
///
/// If not found in the registered table, returns a stub entry for built-in
/// Windows predefined classes and common control classes, so that apps that
/// call `CreateWindowExW` on these class names without explicit registration
/// get a valid (no-op) window proc rather than immediate failure.
pub fn find(name: &str) -> Option<ClassEntry> {
    let key = name.to_ascii_lowercase();
    if let Some(e) = table().lock().unwrap().get(&key).cloned() {
        return Some(e);
    }
    if is_builtin_class(&key) {
        return Some(ClassEntry {
            wnd_proc: builtin_control_wnd_proc as *const () as usize,
            style: 0,
            h_cursor: 0,
            hbr_background: 0,
        });
    }
    None
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
    fn find_builtin_classes_return_stub() {
        // Predefined Win32 classes
        assert!(find("Button").is_some());
        assert!(find("BUTTON").is_some());
        assert!(find("Static").is_some());
        assert!(find("Edit").is_some());
        assert!(find("ListBox").is_some());
        assert!(find("ComboBox").is_some());
        assert!(find("ScrollBar").is_some());
        // Common controls
        assert!(find("SysListView32").is_some());
        assert!(find("SysTreeView32").is_some());
        assert!(find("ToolbarWindow32").is_some());
        assert!(find("msctls_statusbar32").is_some());
        assert!(find("msctls_progress32").is_some());
        // Truly unknown class still returns None
        assert!(find("__NonExistentClass__").is_none());
    }

    #[test]
    fn builtin_stub_wnd_proc_nccreate() {
        // WM_NCCREATE (0x0081) must return TRUE (1) to allow window creation.
        let result = builtin_control_wnd_proc(0, 0x0081, 0, 0);
        assert_eq!(result, 1);
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
