//! Task 18 probe gate — `StretchBlt` dispatches COLORONCOLOR nearest-neighbor
//! scaling and honours the Task-17 ROP dispatch contract.
//!
//! Dispatch-only — pixel round-trip through the destination bitmap's
//! `bits_ptr` is not asserted: the final server-side upload goes through a
//! temporary X11 Pixmap and `XCopyArea` to the destination drawable, neither
//! of which writes back to CPU memory. Same caveat Task 17 documented.
//!
//! Covered:
//!   * COLORONCOLOR + SRCCOPY with valid src bitmap → returns 1.
//!   * Non-COLORONCOLOR modes (HALFTONE, BLACKONWHITE, WHITEONBLACK) → 0 with
//!     a one-line trace, mode is still stored so `set_stretch_blt_mode`
//!     round-trips.
//!   * Zero-dim src or dst → returns 0 without dispatch.
//!   * Negative w/h on destination and source is accepted (mirror path
//!     drives the dest walk in reverse).
//!   * `set_stretch_blt_mode` returns the previous mode on each call.
//!   * Unsupported source bpp (non-32) returns 0.
//!   * Unknown ROP with COLORONCOLOR falls through to the "lie TRUE" arm —
//!     mirrors the bit_blt dispatcher contract.

use weave_gdi32::defs::{
    BLACKNESS, BLACKONWHITE, COLORONCOLOR, DSTINVERT, HALFTONE, NOTSRCCOPY, SRCAND, SRCCOPY,
    SRCINVERT, SRCPAINT, WHITEONBLACK,
};
use weave_gdi32::objects::{self, GdiKind};
use weave_gdi32::{
    create_compatible_bitmap, create_compatible_dc, delete_object, select_object,
    set_stretch_blt_mode, stretch_blt,
};

/// Build two memory DCs each with a 4×4 32-bit compatible bitmap selected.
fn make_pair() -> (usize, usize, usize, usize) {
    let src_dc = create_compatible_dc(0);
    let dst_dc = create_compatible_dc(0);
    let src_bm = create_compatible_bitmap(src_dc, 4, 4);
    let dst_bm = create_compatible_bitmap(dst_dc, 8, 8);
    let _ = select_object(src_dc, src_bm);
    let _ = select_object(dst_dc, dst_bm);
    (src_dc, dst_dc, src_bm, dst_bm)
}

#[test]
fn coloroncolor_srccopy_returns_true() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    // Default mode is COLORONCOLOR (set in DcState::default_for).
    let r = stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, SRCCOPY);
    assert_eq!(r, 1, "StretchBlt(COLORONCOLOR, SRCCOPY) should return 1");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn unsupported_modes_return_zero() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    for mode in [HALFTONE, BLACKONWHITE, WHITEONBLACK] {
        let prev = set_stretch_blt_mode(dst_dc, mode);
        // previous was whatever we set last (or default COLORONCOLOR on the
        // first iteration); we only care that stretch_blt then returns 0.
        let _ = prev;
        let r = stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, SRCCOPY);
        assert_eq!(r, 0, "StretchBlt mode={mode} should return 0");
    }
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn set_stretch_blt_mode_returns_previous() {
    let dc = create_compatible_dc(0);
    // First set — previous is the default (COLORONCOLOR).
    let p0 = set_stretch_blt_mode(dc, HALFTONE);
    assert_eq!(p0, COLORONCOLOR, "first call should report default");
    let p1 = set_stretch_blt_mode(dc, BLACKONWHITE);
    assert_eq!(p1, HALFTONE, "second call should report HALFTONE");
    let p2 = set_stretch_blt_mode(dc, COLORONCOLOR);
    assert_eq!(p2, BLACKONWHITE, "third call should report BLACKONWHITE");
    let _ = delete_object(dc);
}

#[test]
fn zero_dim_returns_false() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    assert_eq!(
        stretch_blt(dst_dc, 0, 0, 0, 8, src_dc, 0, 0, 4, 4, SRCCOPY),
        0
    );
    assert_eq!(
        stretch_blt(dst_dc, 0, 0, 8, 0, src_dc, 0, 0, 4, 4, SRCCOPY),
        0
    );
    assert_eq!(
        stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 0, 4, SRCCOPY),
        0
    );
    assert_eq!(
        stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 0, SRCCOPY),
        0
    );
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn negative_dimensions_accepted() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    // Negative w_dest → mirror horizontally.
    let r = stretch_blt(dst_dc, 8, 0, -8, 8, src_dc, 0, 0, 4, 4, SRCCOPY);
    assert_eq!(r, 1, "negative w_dest should mirror and return 1");
    // Negative h_dest → mirror vertically.
    let r = stretch_blt(dst_dc, 0, 8, 8, -8, src_dc, 0, 0, 4, 4, SRCCOPY);
    assert_eq!(r, 1, "negative h_dest should mirror and return 1");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn unknown_rop_with_coloroncolor_lies_true() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    // 0x00AA_0029 (D) — same unsupported ROP the bit_blt gate uses.
    let r = stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, 0x00AA_0029);
    assert_eq!(r, 1, "unknown ROP should lie TRUE (same policy as bit_blt)");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn known_source_rops_return_true() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    for rop in [SRCCOPY, NOTSRCCOPY, SRCINVERT, SRCAND, SRCPAINT] {
        let r = stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, rop);
        assert_eq!(r, 1, "StretchBlt ROP {rop:#010x} should return 1");
    }
    // DSTINVERT and BLACKNESS (pattern-only) fall into the unknown-ROP arm
    // on this first cut — they still lie TRUE per the task-17 policy.
    for rop in [DSTINVERT, BLACKNESS] {
        let r = stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, rop);
        assert_eq!(r, 1, "pattern-only ROP {rop:#010x} lies TRUE");
    }
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn non_32bpp_source_returns_false() {
    // Hand-roll a DibSection-style bitmap with bpp=24 to hit the rejection.
    let src_dc = create_compatible_dc(0);
    let dst_dc = create_compatible_dc(0);

    // Allocate a 4×4×3-byte buffer, leak it, and register as a DibSection
    // with bpp=24. Mirrors what create_dib_section does for BITMAPINFOHEADER
    // bpp=24 callers.
    let buf = vec![0u8; 4 * 4 * 3].into_boxed_slice();
    let ptr = buf.as_ptr() as usize;
    Box::leak(buf);
    let src_bm = objects::alloc(GdiKind::DibSection {
        width: 4,
        height: 4,
        bits_ptr: ptr,
        bpp: 24,
    });
    let dst_bm = create_compatible_bitmap(dst_dc, 8, 8);
    let _ = select_object(src_dc, src_bm);
    let _ = select_object(dst_dc, dst_bm);

    let r = stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, SRCCOPY);
    assert_eq!(r, 0, "24bpp source should return 0");

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn no_source_bitmap_returns_false() {
    // Source DC with no bitmap selected — stretch_blt should return 0.
    let src_dc = create_compatible_dc(0);
    let dst_dc = create_compatible_dc(0);
    let dst_bm = create_compatible_bitmap(dst_dc, 8, 8);
    let _ = select_object(dst_dc, dst_bm);
    // Explicitly clear any implicit bitmap on src by NOT selecting one.
    weave_gdi32::dc::with_mut(src_dc, |dc| dc.selected_bitmap = 0);
    let r = stretch_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, SRCCOPY);
    assert_eq!(r, 0, "no src bitmap should return 0");

    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}
