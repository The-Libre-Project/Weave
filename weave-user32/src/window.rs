//! Window table — maps HWND values to window state.
//!
//! Each created window gets a monotonically-incrementing HWND. On Linux the
//! entry also stores the x11rb window ID so it can be manipulated via X11.
//!
//! HWNDs start at HWND_OFFSET (0x0001_0000) to keep them well clear of NULL
//! and INVALID_HANDLE_VALUE, and visually distinct from file handles.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const HWND_OFFSET: usize = 0x0001_0000;

/// State stored for each created window.
pub struct WindowEntry {
    pub class_name: String,
    pub wnd_proc: usize, // called as extern "win64" fn(HWND, u32, usize, isize) -> isize
    pub title: String,
    pub style: u32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub visible: bool,
    /// X11 window ID — only meaningful on Linux.
    pub xcb_id: u32,
    /// Attached menu bar (0 = none).
    pub h_menu: usize,
}

// ── Global table ──────────────────────────────────────────────────────────────

struct WindowTable {
    next_hwnd: usize,
    entries: HashMap<usize, WindowEntry>,
}

impl WindowTable {
    fn new() -> Self {
        Self {
            next_hwnd: HWND_OFFSET,
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, entry: WindowEntry) -> usize {
        let hwnd = self.next_hwnd;
        self.next_hwnd += 1;
        self.entries.insert(hwnd, entry);
        hwnd
    }
}

static WINDOWS: OnceLock<Mutex<WindowTable>> = OnceLock::new();

fn table() -> &'static Mutex<WindowTable> {
    WINDOWS.get_or_init(|| Mutex::new(WindowTable::new()))
}

fn lock_table(m: &Mutex<WindowTable>) -> Option<std::sync::MutexGuard<'_, WindowTable>> {
    m.lock()
        .map_err(|e| eprintln!("weave: user32: window table mutex poisoned: {e}"))
        .ok()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Create a new window entry and return its HWND.
pub fn create(entry: WindowEntry) -> usize {
    match lock_table(table()) {
        Some(mut g) => g.insert(entry),
        None => 0,
    }
}

/// Look up a window by HWND. Calls `f` with a reference to the entry.
/// Returns `None` if the HWND is unknown.
pub fn with<R, F: FnOnce(&WindowEntry) -> R>(hwnd: usize, f: F) -> Option<R> {
    let guard = lock_table(table())?;
    guard.entries.get(&hwnd).map(f)
}

/// Look up a window by HWND for mutation.
pub fn with_mut<R, F: FnOnce(&mut WindowEntry) -> R>(hwnd: usize, f: F) -> Option<R> {
    let mut guard = lock_table(table())?;
    guard.entries.get_mut(&hwnd).map(f)
}

/// Remove a window entry. Returns `true` if the HWND was known.
pub fn remove(hwnd: usize) -> bool {
    match lock_table(table()) {
        Some(mut g) => g.entries.remove(&hwnd).is_some(),
        None => false,
    }
}

/// Return the XCB window ID for an HWND (0 if not found or not on Linux).
pub fn xcb_id(hwnd: usize) -> u32 {
    with(hwnd, |e| e.xcb_id).unwrap_or(0)
}

/// Collect all HWNDs currently registered (for event dispatch to all windows).
pub fn all_hwnds() -> Vec<usize> {
    match lock_table(table()) {
        Some(g) => g.entries.keys().copied().collect(),
        None => Vec::new(),
    }
}

/// Look up a HWND by XCB window ID. Returns 0 if not found.
pub fn hwnd_for_xcb(xcb_window_id: u32) -> usize {
    let guard = match lock_table(table()) {
        Some(g) => g,
        None => return 0,
    };
    guard
        .entries
        .iter()
        .find(|(_, e)| e.xcb_id == xcb_window_id)
        .map(|(&h, _)| h)
        .unwrap_or(0)
}

/// Return the first HWND that has a valid (non-zero) XCB window ID.
///
/// Used as a last-resort fallback when `CreateCompatibleDC(NULL)` is called
/// before any `BeginPaint` — e.g. Scintilla creates its off-screen DCs during
/// class initialisation, before the first WM_PAINT cycle. Without this fallback
/// all GDI drawing on those DCs would be silently dropped.
pub fn first_hwnd_with_xcb() -> usize {
    let guard = match lock_table(table()) {
        Some(g) => g,
        None => return 0,
    };
    guard
        .entries
        .iter()
        .find(|(_, e)| e.xcb_id != 0)
        .map(|(&h, _)| h)
        .unwrap_or(0)
}
