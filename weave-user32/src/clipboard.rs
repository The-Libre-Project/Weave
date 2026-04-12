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

fn lock_state(m: &Mutex<ClipState>) -> Option<std::sync::MutexGuard<'_, ClipState>> {
    m.lock()
        .map_err(|e| eprintln!("weave: user32: clipboard mutex poisoned: {e}"))
        .ok()
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
// Wine ref: server/clipboard.c:360 — server validates window handle; sets
// STATUS_INVALID_LOCK_SEQUENCE if already open by a different window (not thread).
// Records open_seqno=seqno on first open; resets rendering=0 on re-open by new thread.
pub extern "win64" fn open_clipboard(h_wnd_new_owner: usize) -> i32 {
    let mut s = match lock_state(state()) {
        Some(g) => g,
        None => return 0,
    };
    s.open = true;
    s.owner_hwnd = h_wnd_new_owner;
    1 // TRUE
}

/// CloseClipboard: close the clipboard.
// Wine ref: dlls/win32u/clipboard.c:208 — server call; on success reply carries viewer
// and owner handles; client sends WM_DRAWCLIPBOARD to the viewer chain after close.
pub extern "win64" fn close_clipboard() -> i32 {
    let mut s = match lock_state(state()) {
        Some(g) => g,
        None => return 0,
    };
    s.open = false;
    1 // TRUE
}

/// EmptyClipboard: clear all clipboard contents.
///
/// Phase 2: leaks any previously stored HGLOBAL handles (caller should
/// have already freed them before calling EmptyClipboard).
// Wine ref: server/clipboard.c — empty_clipboard server handler increments seqno,
// clears all format data, and sets clipboard->owner to the opening thread's process.
// Clipboard must be open or the call fails with STATUS_ACCESS_DENIED.
pub extern "win64" fn empty_clipboard() -> i32 {
    let mut s = match lock_state(state()) {
        Some(g) => g,
        None => return 0,
    };
    s.data.clear();
    1 // TRUE
}

/// SetClipboardData: place data on the clipboard in the specified format.
///
/// Takes ownership of `h_mem` (the caller must not use it afterwards).
/// Returns `h_mem` on success, 0 on failure.
// Wine ref: dlls/win32u/clipboard.c:596 — server_set_clipboard_data passes raw bytes
// via wine_server_add_data; stores reply->seqno in the local cache entry for delayed
// rendering detection. Caller must have called EmptyClipboard first or be the owner.
pub extern "win64" fn set_clipboard_data(u_format: u32, h_mem: usize) -> usize {
    let mut s = match lock_state(state()) {
        Some(g) => g,
        None => return 0,
    };
    if !s.open {
        return 0;
    }
    s.data.insert(u_format, h_mem);
    h_mem
}

/// GetClipboardData: retrieve a handle to the data in the specified format.
///
/// Returns the stored HGLOBAL (pointer), or 0 if the format is unavailable.
// Wine ref: dlls/win32u/clipboard.c:641 — checks local cache first (by seqno match);
// on cache miss sends get_clipboard_data server request with render=TRUE to trigger
// WM_RENDERFORMAT to the owner if data hasn't been rendered yet.
pub extern "win64" fn get_clipboard_data(u_format: u32) -> usize {
    let s = match lock_state(state()) {
        Some(g) => g,
        None => return 0,
    };
    if !s.open {
        return 0;
    }
    s.data.get(&u_format).copied().unwrap_or(0)
}

/// IsClipboardFormatAvailable: check whether a clipboard format is available.
// Wine ref: dlls/win32u/clipboard.c — get_clipboard_formats server request; does NOT
// require the clipboard to be open (unlike GetClipboardData). Returns TRUE if the
// format is in the server's format list (including synthesized CF_TEXT↔CF_UNICODETEXT).
pub extern "win64" fn is_clipboard_format_available(u_format: u32) -> i32 {
    match lock_state(state()) {
        Some(s) => s.data.contains_key(&u_format) as i32,
        None => 0,
    }
}

/// CountClipboardFormats: return the number of formats currently on the clipboard.
// Wine ref: dlls/win32u/main.c:1301 — NtUserCountClipboardFormats; server-side count
// includes synthesized formats (CF_TEXT auto-synthesized from CF_UNICODETEXT and vice
// versa), so count may exceed explicitly set formats.
pub extern "win64" fn count_clipboard_formats() -> i32 {
    match lock_state(state()) {
        Some(s) => s.data.len() as i32,
        None => 0,
    }
}

/// GetClipboardOwner: return the HWND of the current clipboard owner.
// Wine ref: server/clipboard.c — owner is the process that last called EmptyClipboard;
// does NOT require clipboard to be open. Returns NULL if clipboard has never been
// emptied or if the owning process has exited.
pub extern "win64" fn get_clipboard_owner() -> usize {
    match lock_state(state()) {
        Some(s) => s.owner_hwnd,
        None => 0,
    }
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
