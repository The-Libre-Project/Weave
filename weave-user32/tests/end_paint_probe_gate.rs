//! Probe gate for `EndPaint` / `BeginPaint` paint-cycle invariant.
//!
//! Verifies:
//!   1. `BeginPaint` stores hwnd into `CURRENT_PAINT_HWND` and fills ps.hdc.
//!   2. `EndPaint` clears `CURRENT_PAINT_HWND` to 0 and returns TRUE (1).
//!
//! This gate catches the pre-fix regression where EndPaint left CURRENT_PAINT_HWND
//! set after the paint cycle, causing gdi32::create_compatible_dc to route
//! subsequent GDI calls to a stale paint target.

use std::mem::MaybeUninit;
use weave_user32::api::{begin_paint, current_paint_hwnd, end_paint};
use weave_user32::defs::PaintStruct;

const FAKE_HWND: usize = 0x1234_5678;

#[test]
fn begin_sets_current_paint_hwnd() {
    let mut ps: MaybeUninit<PaintStruct> = MaybeUninit::zeroed();
    unsafe {
        begin_paint(FAKE_HWND, ps.as_mut_ptr());
    }
    assert_eq!(
        current_paint_hwnd(),
        FAKE_HWND,
        "BeginPaint must store hwnd into CURRENT_PAINT_HWND"
    );
    // cleanup
    unsafe {
        end_paint(FAKE_HWND, ps.as_ptr());
    }
}

#[test]
fn begin_fills_hdc_with_hwnd() {
    let mut ps: MaybeUninit<PaintStruct> = MaybeUninit::zeroed();
    let hdc = unsafe { begin_paint(FAKE_HWND, ps.as_mut_ptr()) };
    let ps = unsafe { ps.assume_init() };
    assert_eq!(
        hdc, FAKE_HWND,
        "BeginPaint return value must equal hwnd (fake HDC)"
    );
    assert_eq!(ps.hdc, FAKE_HWND, "ps.hdc must equal hwnd");
    // cleanup
    unsafe {
        end_paint(FAKE_HWND, &ps as *const PaintStruct);
    }
}

#[test]
fn end_paint_clears_current_paint_hwnd() {
    let mut ps: MaybeUninit<PaintStruct> = MaybeUninit::zeroed();
    unsafe {
        begin_paint(FAKE_HWND, ps.as_mut_ptr());
    }
    assert_ne!(
        current_paint_hwnd(),
        0,
        "precondition: CURRENT_PAINT_HWND set by BeginPaint"
    );
    let ret = unsafe { end_paint(FAKE_HWND, ps.as_ptr()) };
    assert_eq!(ret, 1, "EndPaint must return TRUE (1)");
    assert_eq!(
        current_paint_hwnd(),
        0,
        "EndPaint must clear CURRENT_PAINT_HWND to 0"
    );
}
