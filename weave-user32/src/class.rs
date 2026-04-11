//! Window class registry.
//!
//! Maps class names (case-insensitive) to registered WNDCLASSW data.
//! `RegisterClassW` stores here; `CreateWindowExW` looks up here.

use crate::defs::{
    decode_wide, EM_GETLIMITTEXT, EM_GETSEL, EM_REPLACESEL, EM_SETLIMITTEXT, EM_SETSEL, WM_GETTEXT,
    WM_GETTEXTLENGTH, WM_NCCREATE, WM_SETTEXT,
};
use crate::window;
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
    /// Number of extra bytes to allocate per window (cbWndExtra).
    pub cb_wnd_extra: u32,
}

// ── Global class table ────────────────────────────────────────────────────────

static CLASSES: OnceLock<Mutex<HashMap<String, ClassEntry>>> = OnceLock::new();

fn table() -> &'static Mutex<HashMap<String, ClassEntry>> {
    CLASSES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_table(
    m: &Mutex<HashMap<String, ClassEntry>>,
) -> Option<std::sync::MutexGuard<'_, HashMap<String, ClassEntry>>> {
    m.lock()
        .map_err(|e| eprintln!("weave: user32: class table mutex poisoned: {e}"))
        .ok()
}

fn lock_edit_state(
    m: &Mutex<HashMap<usize, EditState>>,
) -> Option<std::sync::MutexGuard<'_, HashMap<usize, EditState>>> {
    m.lock()
        .map_err(|e| eprintln!("weave: user32: edit state mutex poisoned: {e}"))
        .ok()
}

/// Register a window class. Uses the lowercase class name as the key so
/// lookups are case-insensitive (matching Windows registry-like behaviour).
///
/// Returns `true` if the class was newly registered, `false` if it replaced
/// an existing registration with the same name.
pub fn register(name: &str, entry: ClassEntry) -> bool {
    let key = name.to_ascii_lowercase();
    let mut guard = match lock_table(table()) {
        Some(g) => g,
        None => return false,
    };
    let replaced = guard.contains_key(&key);
    guard.insert(key, entry);
    !replaced
}

// ── Edit control state ────────────────────────────────────────────────────────

/// Per-window selection state for built-in EDIT controls.
struct EditState {
    sel_start: u32,
    sel_end: u32,
    limit: u32,
}

static EDIT_STATE: OnceLock<Mutex<HashMap<usize, EditState>>> = OnceLock::new();

fn edit_state() -> &'static Mutex<HashMap<usize, EditState>> {
    EDIT_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Window procedure for the built-in EDIT window class.
///
/// Wine ref: dlls/user32/edit.c —
///   WM_SETTEXT: selects all (EM_SetSel 0..-1), replaces with new text via EM_ReplaceSel,
///     resets EF_MODIFIED flag, resets x_offset to 0, sends EN_UPDATE/EN_CHANGE for SL.
///     Weave: store text in window title field; reset selection to 0.
///   WM_GETTEXT: EDIT_WM_GetText — if count==0 returns 0; lstrcpynW(dst, es->text, count);
///     returns lstrlenW(dst). Weave: copies from title, returns UTF-16 code unit count.
///   WM_GETTEXTLENGTH: returns lstrlenW(es->text). Weave: encode_utf16().count().
///   EM_SETSEL: EDIT_EM_SetSel — preserves order (start can be > end). If start==-1,
///     both go to current sel_end (collapse). Values clamped to text length.
///   EM_GETSEL: EDIT_EM_GetSel — stores start/end into out-pointers if non-null;
///     returns MAKELONG(start, end).
///   EM_REPLACESEL: EDIT_EM_ReplaceSel — ORDER_UINT(s,e); replaces [s,e) with new text;
///     cursor placed after inserted text; sends EN_CHANGE if send_update set.
///   EM_SETLIMITTEXT: EDIT_EM_SetLimitText — if limit==0 use 0x7FFF (SL default).
///   EM_GETLIMITTEXT: returns es->buffer_limit.
///
/// # Safety
/// Called from guest code with win64 ABI. lParam pointer arguments must be valid.
unsafe extern "win64" fn edit_wnd_proc(
    hwnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    match msg {
        WM_NCCREATE => {
            // Initialise per-window edit state on creation.
            if let Some(mut g) = lock_edit_state(edit_state()) {
                g.insert(
                    hwnd,
                    EditState {
                        sel_start: 0,
                        sel_end: 0,
                        limit: 0x7FFF_FFFF,
                    },
                );
            }
            1 // TRUE — allow creation
        }

        WM_SETTEXT => {
            // lParam: LPCWSTR (may be null → clear text).
            // Wine ref: dlls/user32/edit.c::EDIT_WM_SetText — EM_SetSel(0,-1) then
            // EM_ReplaceSel, resets x_offset and EF_MODIFIED, EN_UPDATE/EN_CHANGE for SL.
            let text = unsafe { decode_wide(l_param as *const u16) };
            window::with_mut(hwnd, |e| e.title = text);
            if let Some(mut g) = lock_edit_state(edit_state()) {
                if let Some(s) = g.get_mut(&hwnd) {
                    s.sel_start = 0;
                    s.sel_end = 0;
                }
            }
            1 // TRUE
        }

        WM_GETTEXT => {
            // wParam: max char count (including null); lParam: LPWSTR buffer.
            // Wine ref: dlls/user32/edit.c::EDIT_WM_GetText — returns 0 if count==0;
            // lstrcpynW(dst, es->text, count); returns lstrlenW(dst).
            let max_count = w_param;
            if max_count == 0 || l_param == 0 {
                return 0;
            }
            let text = window::with(hwnd, |e| e.title.clone()).unwrap_or_default();
            let wide: Vec<u16> = text.encode_utf16().collect();
            let dst = l_param as *mut u16;
            let copy_len = wide.len().min(max_count.saturating_sub(1));
            unsafe {
                for (i, &cu) in wide[..copy_len].iter().enumerate() {
                    *dst.add(i) = cu;
                }
                *dst.add(copy_len) = 0;
            }
            copy_len as isize
        }

        WM_GETTEXTLENGTH => {
            // Wine ref: dlls/user32/edit.c — returns lstrlenW(es->text) (UTF-16 code units).
            let len = window::with(hwnd, |e| e.title.encode_utf16().count()).unwrap_or(0);
            len as isize
        }

        EM_GETSEL => {
            // wParam: optional *u32 start; lParam: optional *u32 end.
            // Wine ref: dlls/user32/edit.c::EDIT_EM_GetSel — writes to out-ptrs, returns
            // MAKELONG(start, end).
            let (start, end) = match lock_edit_state(edit_state()) {
                Some(g) => g.get(&hwnd).map(|s| (s.sel_start, s.sel_end)).unwrap_or((0, 0)),
                None => (0, 0),
            };
            if w_param != 0 {
                unsafe {
                    *(w_param as *mut u32) = start;
                }
            }
            if l_param != 0 {
                unsafe {
                    *(l_param as *mut u32) = end;
                }
            }
            (((end as isize) & 0xFFFF) << 16) | ((start as isize) & 0xFFFF)
        }

        EM_SETSEL => {
            // wParam: start (i32); lParam: end (i32). -1 for start collapses to sel_end;
            // -1 for end means "end of text".
            // Wine ref: dlls/user32/edit.c::EDIT_EM_SetSel — start==-1 means move both to
            // selection_end; values clamped to text length; order preserved as-is.
            let text_len =
                window::with(hwnd, |e| e.title.encode_utf16().count()).unwrap_or(0) as u32;
            let raw_start = w_param as i32;
            let raw_end = l_param as i32;
            let (sel_start, sel_end) = if raw_start == -1 {
                let old_end = lock_edit_state(edit_state())
                    .and_then(|g| g.get(&hwnd).map(|s| s.sel_end))
                    .unwrap_or(0);
                (old_end, old_end)
            } else {
                let s = (raw_start as u32).min(text_len);
                let e = if raw_end == -1 {
                    text_len
                } else {
                    (raw_end as u32).min(text_len)
                };
                (s, e)
            };
            if let Some(mut g) = lock_edit_state(edit_state()) {
                if let Some(state) = g.get_mut(&hwnd) {
                    state.sel_start = sel_start;
                    state.sel_end = sel_end;
                }
            }
            0
        }

        EM_REPLACESEL => {
            // wParam: can_undo BOOL; lParam: LPCWSTR replacement (null → empty).
            // Wine ref: dlls/user32/edit.c::EDIT_EM_ReplaceSel — ORDER_UINT(s,e); replaces
            // [s,e) with new text; cursor placed after inserted text (s+strl); sets
            // EF_MODIFIED; sends EN_CHANGE if send_update.
            let replacement = unsafe { decode_wide(l_param as *const u16) };
            let repl_chars: Vec<char> = replacement.chars().collect();

            // Read text and selection separately to avoid nested mutex locks.
            let current_text = window::with(hwnd, |e| e.title.clone()).unwrap_or_default();
            let (raw_start, raw_end) = match lock_edit_state(edit_state()) {
                Some(g) => g.get(&hwnd).map(|s| (s.sel_start, s.sel_end)).unwrap_or((0, 0)),
                None => (0, 0),
            };

            // ORDER_UINT: ensure start <= end.
            let (sel_start, sel_end) = if raw_start <= raw_end {
                (raw_start as usize, raw_end as usize)
            } else {
                (raw_end as usize, raw_start as usize)
            };

            // Work on char (Unicode scalar) level — close enough for ASCII/Latin text.
            let chars: Vec<char> = current_text.chars().collect();
            let s = sel_start.min(chars.len());
            let e = sel_end.min(chars.len());
            let mut new_chars: Vec<char> =
                Vec::with_capacity(chars.len() - (e - s) + repl_chars.len());
            new_chars.extend_from_slice(&chars[..s]);
            new_chars.extend_from_slice(&repl_chars);
            new_chars.extend_from_slice(&chars[e..]);
            let new_text: String = new_chars.iter().collect();
            let new_cursor = (s + repl_chars.len()) as u32;

            window::with_mut(hwnd, |e| e.title = new_text);
            if let Some(mut g) = lock_edit_state(edit_state()) {
                if let Some(state) = g.get_mut(&hwnd) {
                    state.sel_start = new_cursor;
                    state.sel_end = new_cursor;
                }
            }
            0
        }

        EM_SETLIMITTEXT => {
            // wParam: new limit; 0 means use default (0x7FFF for single-line).
            // Wine ref: dlls/user32/edit.c::EDIT_EM_SetLimitText — if limit==0, use 0x7FFFFFFE
            // for multi-line or MAXSHORT for single-line. Weave uses 0x7FFF as the simple default.
            let limit = if w_param == 0 {
                0x7FFF
            } else {
                w_param.min(0x7FFF_FFFF) as u32
            };
            if let Some(mut g) = lock_edit_state(edit_state()) {
                if let Some(state) = g.get_mut(&hwnd) {
                    state.limit = limit;
                }
            }
            0
        }

        EM_GETLIMITTEXT => {
            // Wine ref: dlls/user32/edit.c — returns es->buffer_limit.
            match lock_edit_state(edit_state()) {
                Some(g) => g.get(&hwnd).map(|s| s.limit as isize).unwrap_or(0x7FFF),
                None => 0x7FFF,
            }
        }

        _ => builtin_control_wnd_proc(hwnd, msg, w_param, l_param as usize) as isize,
    }
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
    if let Some(e) = lock_table(table())?.get(&key).cloned() {
        return Some(e);
    }
    if is_builtin_class(&key) {
        // EDIT controls get a real window proc that stores text and selection.
        //
        // SAFETY: These are concrete Rust functions with `extern "win64"` ABI,
        // coerced to a raw pointer and then widened to `usize` for opaque storage
        // in `ClassEntry::wnd_proc`. The only consumer is `call_wnd_proc` in
        // api.rs, which transmutes the stored `usize` back to
        // `unsafe extern "win64" fn(usize, u32, usize, isize) -> isize` — exactly
        // the signature of both `edit_wnd_proc` and `builtin_control_wnd_proc`.
        // The round-trip is valid because: (a) the ABI is identical on both sides,
        // (b) the pointer was never modified between storage and retrieval, and
        // (c) these are static functions whose lifetime is `'static`.
        let wnd_proc = if key == "edit" {
            edit_wnd_proc as *const () as usize
        } else {
            builtin_control_wnd_proc as *const () as usize
        };
        return Some(ClassEntry {
            wnd_proc,
            style: 0,
            h_cursor: 0,
            hbr_background: 0,
            cb_wnd_extra: 0,
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
            cb_wnd_extra: 0,
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
