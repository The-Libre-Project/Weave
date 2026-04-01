//! DC (Device Context) state table.
//!
//! In Phase 2, the HDC is identical to the HWND (the window handle) — a
//! simplification that avoids a full GDI surface abstraction. Drawing functions
//! resolve the XCB window id via `weave_user32::window::xcb_id(hdc)`.

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
    /// Currently selected brush handle.
    pub h_brush: usize,
    /// Currently selected pen handle.
    pub h_pen: usize,
    /// Currently selected font handle.
    pub h_font: usize,
}

impl DcState {
    fn default_for(hwnd: usize) -> Self {
        DcState {
            hwnd,
            text_color: 0x0000_0000,
            bk_color: 0x00FF_FFFF,
            bk_mode: OPAQUE,
            h_brush: objects::stock_handle(WHITE_BRUSH),
            h_pen: objects::stock_handle(BLACK_PEN),
            h_font: objects::stock_handle(SYSTEM_FONT),
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
}
