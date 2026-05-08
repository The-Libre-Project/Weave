//! Probe gate for `GetDCEx` — validates delegation to GetDC contract.
//!
//! Verifies:
//!   1. Non-zero hwnd returns hwnd (same as GetDC).
//!   2. Zero hwnd returns SCREEN_HDC (non-zero sentinel).
//!   3. Clip region and DCX_* flags are ignored — result equals GetDC.

use weave_user32::api::{get_dc, get_dc_ex};

const FAKE_HWND: usize = 0xBEEF_0001;
const DCX_CACHE: u32 = 0x0000_0002;
const DCX_WINDOW: u32 = 0x0000_0001;

#[test]
fn nonzero_hwnd_matches_get_dc() {
    let expected = get_dc(FAKE_HWND);
    let actual = unsafe { get_dc_ex(FAKE_HWND, 0, 0) };
    assert_eq!(
        actual, expected,
        "GetDCEx must return same as GetDC for non-zero hwnd"
    );
}

#[test]
fn zero_hwnd_returns_screen_hdc() {
    let screen = get_dc(0);
    let actual = unsafe { get_dc_ex(0, 0, 0) };
    assert_eq!(actual, screen, "GetDCEx(0) must return SCREEN_HDC");
    assert_ne!(actual, 0, "SCREEN_HDC must be non-zero");
}

#[test]
fn flags_do_not_change_result() {
    let base = unsafe { get_dc_ex(FAKE_HWND, 0, 0) };
    let with_flags = unsafe { get_dc_ex(FAKE_HWND, 0xDEAD, DCX_CACHE | DCX_WINDOW) };
    assert_eq!(base, with_flags, "DCX flags must not alter the returned DC");
}
