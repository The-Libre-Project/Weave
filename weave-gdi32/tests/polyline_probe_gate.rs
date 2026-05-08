//! Probe gate for `Polyline` — validates input guards and return contract.
//!
//! Verifies:
//!   1. NULL lpt returns FALSE.
//!   2. c_pt < 2 returns FALSE.
//!   3. Valid point array (c_pt >= 2) returns TRUE.
//!   4. Struct size of POINT is 8 bytes (Win64 layout invariant).
//!
//! Pixel-round-trip assertions are not made here — drawing to X11 requires
//! a live display connection not available in CI. The gate pins the input-
//! validation contract that callers (NPP, PuTTY) depend on.

use weave_gdi32::defs::Point;
use weave_gdi32::polyline;

fn make_points(n: usize) -> Vec<Point> {
    (0..n)
        .map(|i| Point {
            x: i as i32 * 10,
            y: i as i32 * 5,
        })
        .collect()
}

#[test]
fn point_size_is_8() {
    assert_eq!(
        std::mem::size_of::<Point>(),
        8,
        "POINT must be 8 bytes on x64"
    );
}

#[test]
fn null_ptr_returns_false() {
    let ret = unsafe { polyline(0, std::ptr::null(), 4) };
    assert_eq!(ret, 0, "NULL lpt must return FALSE");
}

#[test]
fn c_pt_zero_returns_false() {
    let pts = make_points(4);
    let ret = unsafe { polyline(0, pts.as_ptr() as *const i32, 0) };
    assert_eq!(ret, 0, "c_pt=0 must return FALSE");
}

#[test]
fn c_pt_one_returns_false() {
    let pts = make_points(4);
    let ret = unsafe { polyline(0, pts.as_ptr() as *const i32, 1) };
    assert_eq!(ret, 0, "c_pt=1 must return FALSE (need at least 2 points)");
}

#[test]
fn two_points_returns_true() {
    let pts = make_points(2);
    let ret = unsafe { polyline(0, pts.as_ptr() as *const i32, 2) };
    assert_eq!(ret, 1, "c_pt=2 with valid ptr must return TRUE");
}

#[test]
fn five_points_returns_true() {
    let pts = make_points(5);
    let ret = unsafe { polyline(0, pts.as_ptr() as *const i32, 5) };
    assert_eq!(ret, 1, "c_pt=5 with valid ptr must return TRUE");
}
