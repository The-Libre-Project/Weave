//! In-process Win32 clipboard emulation.
//!
//! # Phase 2 scope
//!
//! Implements the Win32 clipboard API using a simple in-process store. No
//! X11 selection integration — clipboard data is only accessible within the
//! same Weave process. This is sufficient for applications that copy/paste
//! within themselves (e.g. a text editor copying to its own clipboard).
//!
//! X11 clipboard (PRIMARY + CLIPBOARD selections) is deferred to Phase 3.
//!
//! # Win32 clipboard memory model
//!
//! Win32 clipboard data is passed as `HGLOBAL` handles. In our implementation
//! `HGLOBAL == raw pointer` (GlobalAlloc returns a real heap address and
//! GlobalLock returns it unchanged). SetClipboardData transfers ownership of
//! the memory to the clipboard; GetClipboardData returns the same handle
//! (pointer) without copying. EmptyClipboard leaks the old handles in Phase 2
//! (correct behaviour would free them, but we don't track sizes).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ── Clipboard state ───────────────────────────────────────────────────────────

struct ClipState {
    /// Whether OpenClipboard has been called.
    open: bool,
    /// HWND that called OpenClipboard (informational only).
    owner_hwnd: usize,
    /// Map from CF_* format → HGLOBAL (raw pointer).
    data: HashMap<u32, usize>,
}

fn state() -> &'static Mutex<ClipState> {
    static S: OnceLock<Mutex<ClipState>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(ClipState {
            open: false,
            owner_hwnd: 0,
            data: HashMap::new(),
        })
    })
}

// ── Win32 clipboard format constants ──────────────────────────────────────────

pub const CF_TEXT: u32 = 1;
pub const CF_BITMAP: u32 = 2;
pub const CF_UNICODETEXT: u32 = 13;
pub const CF_HDROP: u32 = 15;

// ── Public API ────────────────────────────────────────────────────────────────

/// OpenClipboard: open the clipboard for examination or modification.
///
/// Returns TRUE on success. Phase 2: always succeeds (no contention).
pub extern "win64" fn open_clipboard(h_wnd_new_owner: usize) -> i32 {
    let mut s = state().lock().unwrap();
    s.open = true;
    s.owner_hwnd = h_wnd_new_owner;
    1 // TRUE
}

/// CloseClipboard: close the clipboard.
pub extern "win64" fn close_clipboard() -> i32 {
    let mut s = state().lock().unwrap();
    s.open = false;
    1 // TRUE
}

/// EmptyClipboard: clear all clipboard contents.
///
/// Phase 2: leaks any previously stored HGLOBAL handles (caller should
/// have already freed them before calling EmptyClipboard).
pub extern "win64" fn empty_clipboard() -> i32 {
    let mut s = state().lock().unwrap();
    s.data.clear();
    1 // TRUE
}

/// SetClipboardData: place data on the clipboard in the specified format.
///
/// Takes ownership of `h_mem` (the caller must not use it afterwards).
/// Returns `h_mem` on success, 0 on failure.
pub extern "win64" fn set_clipboard_data(u_format: u32, h_mem: usize) -> usize {
    let mut s = state().lock().unwrap();
    if !s.open {
        return 0;
    }
    s.data.insert(u_format, h_mem);
    h_mem
}

/// GetClipboardData: retrieve a handle to the data in the specified format.
///
/// Returns the stored HGLOBAL (pointer), or 0 if the format is unavailable.
pub extern "win64" fn get_clipboard_data(u_format: u32) -> usize {
    let s = state().lock().unwrap();
    if !s.open {
        return 0;
    }
    s.data.get(&u_format).copied().unwrap_or(0)
}

/// IsClipboardFormatAvailable: check whether a clipboard format is available.
pub extern "win64" fn is_clipboard_format_available(u_format: u32) -> i32 {
    let s = state().lock().unwrap();
    s.data.contains_key(&u_format) as i32
}

/// CountClipboardFormats: return the number of formats currently on the clipboard.
pub extern "win64" fn count_clipboard_formats() -> i32 {
    state().lock().unwrap().data.len() as i32
}

/// GetClipboardOwner: return the HWND of the current clipboard owner.
pub extern "win64" fn get_clipboard_owner() -> usize {
    state().lock().unwrap().owner_hwnd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize all clipboard tests — they share global state.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_clipboard() {
        let mut s = super::state().lock().unwrap();
        s.open = false;
        s.owner_hwnd = 0;
        s.data.clear();
    }

    #[test]
    fn open_close_cycle() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_clipboard();
        assert_eq!(open_clipboard(1), 1);
        assert_eq!(close_clipboard(), 1);
    }

    #[test]
    fn set_and_get_format() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_clipboard();
        open_clipboard(0);
        let fake_ptr = 0xDEAD_BEEFusize;
        assert_eq!(set_clipboard_data(CF_UNICODETEXT, fake_ptr), fake_ptr);
        assert_eq!(get_clipboard_data(CF_UNICODETEXT), fake_ptr);
        assert_eq!(is_clipboard_format_available(CF_UNICODETEXT), 1);
        assert_eq!(is_clipboard_format_available(CF_TEXT), 0);
        empty_clipboard();
        assert_eq!(get_clipboard_data(CF_UNICODETEXT), 0);
        close_clipboard();
    }

    #[test]
    fn get_without_open_returns_zero() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_clipboard();
        assert_eq!(get_clipboard_data(CF_TEXT), 0);
    }
}
