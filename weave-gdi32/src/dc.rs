//! DC (Device Context) state table.
//!
//! Each DC carries an optional X11 Pixmap for memory DCs. When a bitmap is
//! selected into a DC via SelectObject, a Pixmap of the same dimensions is
//! allocated. Drawing functions resolve the drawable via `DcState::drawable()`,
//! which returns the Pixmap if present, or the X11 window ID otherwise.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::defs::*;
use crate::objects;

// ── DC state ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct DcState {
    pub hwnd: usize,
    /// Text foreground color (Win32 COLORREF 0x00BBGGRR). Default: black.
    pub text_color: u32,
    /// Text background color (Win32 COLORREF 0x00BBGGRR). Default: white.
    pub bk_color: u32,
    /// Background mode: TRANSPARENT or OPAQUE. Default: OPAQUE.
    pub bk_mode: i32,
    /// Text alignment flags (TA_*). Default: TA_LEFT|TA_TOP = 0.
    ///
    /// Wine ref: dlls/win32u/dc.c — NtGdiSetTextAlign stores flags in
    /// dc->attr.text_align; TA_UPDATECP(1) advances current position on draw.
    /// Key flags: TA_LEFT=0, TA_RIGHT=2, TA_CENTER=6, TA_TOP=0, TA_BOTTOM=8,
    /// TA_BASELINE=24. Scintilla uses TA_TOP|TA_LEFT (0) for its editor area.
    pub text_align: u32,
    /// Currently selected brush handle.
    pub h_brush: usize,
    /// Currently selected pen handle.
    pub h_pen: usize,
    /// Currently selected font handle.
    pub h_font: usize,
    pub selected_bitmap: usize,
    pub pixmap: Option<u32>,
}

impl DcState {
    fn default_for(hwnd: usize) -> Self {
        DcState {
            hwnd,
            text_color: 0x0000_0000,
            bk_color: 0x00FF_FFFF,
            bk_mode: OPAQUE,
            text_align: 0, // TA_LEFT | TA_TOP
            h_brush: objects::stock_handle(WHITE_BRUSH),
            h_pen: objects::stock_handle(BLACK_PEN),
            h_font: objects::stock_handle(SYSTEM_FONT),
            selected_bitmap: 0,
            pixmap: None,
        }
    }
}

// ── Global DC table ───────────────────────────────────────────────────────────

fn table() -> &'static Mutex<HashMap<usize, DcState>> {
    static T: OnceLock<Mutex<HashMap<usize, DcState>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read a DC state, or a fresh default if no DC was explicitly created.
pub fn with<F, R>(hdc: usize, f: F) -> R
where
    F: FnOnce(&DcState) -> R,
{
    let t = table().lock().unwrap();
    if let Some(dc) = t.get(&hdc) {
        return f(dc);
    }
    drop(t);
    f(&DcState::default_for(hdc))
}

/// Modify a DC state; creates a default entry if one does not exist.
pub fn with_mut<F>(hdc: usize, f: F)
where
    F: FnOnce(&mut DcState),
{
    let mut t = table().lock().unwrap();
    let dc = t.entry(hdc).or_insert_with(|| DcState::default_for(hdc));
    f(dc);
}

/// Remove a DC entry (called from DeleteDC / ReleaseDC).
pub fn remove(hdc: usize) {
    table().lock().unwrap().remove(&hdc);
    dc_save_stacks().lock().unwrap().remove(&hdc);
}

// ── DC save/restore stack ─────────────────────────────────────────────────────

/// Per-HDC stack of saved DC states (pushed by SaveDC, popped by RestoreDC).
fn dc_save_stacks() -> &'static Mutex<HashMap<usize, Vec<DcState>>> {
    static S: OnceLock<Mutex<HashMap<usize, Vec<DcState>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// SaveDC: push the current state onto the per-HDC stack.
///
/// Wine ref: dlls/win32u/dc.c — NtGdiSaveDC clones the DC object and pushes
/// it onto an internal save-state list; the save level is incremented and
/// returned (1 = first save). Returns 0 on failure.
pub fn save(hdc: usize) -> i32 {
    // Capture current state (or default if none exists yet).
    let current = {
        let t = table().lock().unwrap();
        t.get(&hdc)
            .cloned()
            .unwrap_or_else(|| DcState::default_for(hdc))
    };
    let mut stacks = dc_save_stacks().lock().unwrap();
    let stack = stacks.entry(hdc).or_default();
    stack.push(current);
    stack.len() as i32 // save level is 1-based depth
}

/// RestoreDC: pop the stack to the given level and restore that state.
///
/// Wine ref: dlls/win32u/dc.c — NtGdiRestoreDC accepts a positive save level
/// (absolute) or a negative value (relative: -1 = most recent). All states
/// more recent than the target are discarded. Returns TRUE on success.
pub fn restore(hdc: usize, level: i32) -> i32 {
    let mut stacks = dc_save_stacks().lock().unwrap();
    let stack = match stacks.get_mut(&hdc) {
        Some(s) if !s.is_empty() => s,
        _ => return 0,
    };
    let depth = stack.len() as i32;
    let target = if level < 0 {
        // -1 = most recent, -2 = one before that, etc.
        depth + level
    } else {
        level - 1 // 1-based → 0-based index
    };
    if target < 0 || target >= depth {
        return 0;
    }
    let target_idx = target as usize;
    // Restore to that state and discard everything more recent.
    let saved = stack[target_idx].clone();
    stack.truncate(target_idx); // pop target and everything above it
    drop(stacks);
    // Write the restored state into the active DC table.
    with_mut(hdc, |dc| *dc = saved);
    1
}

impl DcState {
    /// Return the X11 drawable for this DC.
    ///
    /// Priority:
    /// 1. The Pixmap allocated for a memory DC (SelectObject + compatible bitmap).
    /// 2. The X11 window ID of the associated HWND.
    /// 3. If hwnd is 0 (memory DC created before any windows — Scintilla's
    ///    pattern), fall back to the current BeginPaint HWND, then the first
    ///    window with a valid XCB ID.
    pub fn drawable(&self) -> u32 {
        if let Some(pixmap) = self.pixmap {
            return pixmap;
        }
        let hwnd = if self.hwnd == 0 {
            let from_paint = weave_user32::api::current_paint_hwnd();
            if from_paint != 0 {
                from_paint
            } else {
                weave_user32::window::first_hwnd_with_xcb()
            }
        } else {
            self.hwnd
        };
        weave_user32::window::xcb_id(hwnd)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test uses a distinct HWND value to avoid cross-test state leakage.
    /// We pick values far above the real HWND range used in production.
    const TEST_HDC_BASE: usize = 0xDEAD_0000;

    #[test]
    fn default_text_color_is_black() {
        let hdc = TEST_HDC_BASE + 1;
        let color = with(hdc, |dc| dc.text_color);
        assert_eq!(color, 0x0000_0000);
    }

    #[test]
    fn default_bk_color_is_white() {
        let hdc = TEST_HDC_BASE + 2;
        let color = with(hdc, |dc| dc.bk_color);
        assert_eq!(color, 0x00FF_FFFF);
    }

    #[test]
    fn default_bk_mode_is_opaque() {
        let hdc = TEST_HDC_BASE + 3;
        let mode = with(hdc, |dc| dc.bk_mode);
        assert_eq!(mode, OPAQUE);
    }

    #[test]
    fn with_mut_sets_text_color() {
        let hdc = TEST_HDC_BASE + 4;
        with_mut(hdc, |dc| dc.text_color = 0x00FF_0000);
        let color = with(hdc, |dc| dc.text_color);
        assert_eq!(color, 0x00FF_0000);
        remove(hdc);
    }

    #[test]
    fn with_mut_sets_bk_color() {
        let hdc = TEST_HDC_BASE + 5;
        with_mut(hdc, |dc| dc.bk_color = 0x0000_00FF);
        let color = with(hdc, |dc| dc.bk_color);
        assert_eq!(color, 0x0000_00FF);
        remove(hdc);
    }

    #[test]
    fn with_mut_sets_bk_mode_to_transparent() {
        let hdc = TEST_HDC_BASE + 6;
        with_mut(hdc, |dc| dc.bk_mode = TRANSPARENT);
        let mode = with(hdc, |dc| dc.bk_mode);
        assert_eq!(mode, TRANSPARENT);
        remove(hdc);
    }

    #[test]
    fn remove_resets_to_default() {
        let hdc = TEST_HDC_BASE + 7;
        with_mut(hdc, |dc| dc.text_color = 0x00AA_BB_CC);
        remove(hdc);
        // After removal, with() creates a fresh default
        let color = with(hdc, |dc| dc.text_color);
        assert_eq!(color, 0x0000_0000);
    }

    #[test]
    fn independent_hdcs_have_independent_state() {
        let hdc_a = TEST_HDC_BASE + 8;
        let hdc_b = TEST_HDC_BASE + 9;
        with_mut(hdc_a, |dc| dc.text_color = 0x0000_00FF);
        with_mut(hdc_b, |dc| dc.text_color = 0x00FF_0000);
        assert_eq!(with(hdc_a, |dc| dc.text_color), 0x0000_00FF);
        assert_eq!(with(hdc_b, |dc| dc.text_color), 0x00FF_0000);
        remove(hdc_a);
        remove(hdc_b);
    }

    // ── WS5: SaveDC / RestoreDC ───────────────────────────────────────────────

    #[test]
    fn save_returns_one_based_level() {
        let hdc = TEST_HDC_BASE + 10;
        assert_eq!(save(hdc), 1);
        assert_eq!(save(hdc), 2);
        assert_eq!(save(hdc), 3);
        remove(hdc);
    }

    #[test]
    fn restore_absolute_level_restores_state() {
        let hdc = TEST_HDC_BASE + 11;
        with_mut(hdc, |dc| dc.text_color = 0x0000_00FF);
        save(hdc); // level 1 — saved color is blue
        with_mut(hdc, |dc| dc.text_color = 0x00FF_0000); // change to red
        save(hdc); // level 2 — saved color is red
        with_mut(hdc, |dc| dc.text_color = 0x0000_FF00); // change to green

        // Restore to absolute level 1 — should get blue back
        let ok = restore(hdc, 1);
        assert_eq!(ok, 1);
        let color = with(hdc, |dc| dc.text_color);
        assert_eq!(
            color, 0x0000_00FF,
            "expected blue after restoring to level 1"
        );
        remove(hdc);
    }

    #[test]
    fn restore_relative_minus_one_restores_most_recent() {
        let hdc = TEST_HDC_BASE + 12;
        with_mut(hdc, |dc| dc.text_color = 0x0000_00FF);
        save(hdc); // level 1
        with_mut(hdc, |dc| dc.text_color = 0x00FF_0000); // change to red

        let ok = restore(hdc, -1); // most recent = level 1
        assert_eq!(ok, 1);
        assert_eq!(with(hdc, |dc| dc.text_color), 0x0000_00FF);
        remove(hdc);
    }

    #[test]
    fn restore_empty_stack_returns_zero() {
        let hdc = TEST_HDC_BASE + 13;
        assert_eq!(restore(hdc, 1), 0);
        assert_eq!(restore(hdc, -1), 0);
        remove(hdc);
    }

    #[test]
    fn restore_out_of_range_level_returns_zero() {
        let hdc = TEST_HDC_BASE + 14;
        save(hdc); // level 1
        assert_eq!(restore(hdc, 5), 0, "level 5 > depth 1 should fail");
        assert_eq!(restore(hdc, -5), 0, "level -5 beyond depth should fail");
        remove(hdc);
    }
}
