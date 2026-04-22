//! Task 20 probe gate — `AlphaBlend` implements source-over composite for
//! 32-bit ARGB memory-DC source + dest at equal dimensions.
//!
//! Unlike BitBlt / StretchBlt probe gates (Tasks 17/18) which cannot verify
//! pixel results because the upload writes to an X11 Pixmap, AlphaBlend
//! operates on the DEST memory DC's CPU-side `bits_ptr` directly, so a
//! pixel round-trip through the backing buffer is observable here.
//!
//! Covered:
//!   * AC_SRC_OVER + AC_SRC_ALPHA premultiplied 4x4 composite → dst bits match
//!     the Wine MulDiv255 formula with ±1 per-channel tolerance.
//!   * w_src != w_dest (scale request) → returns 0.
//!   * Non-32bpp dest via no selected bitmap fallback → returns 0.
//!   * BlendOp != 0 → returns 0.
//!   * BlendFlags != 0 → returns 0.
//!   * Window-DC dest (no memory bitmap selected) → returns 0.
//!   * Zero-area rectangles → returns 0.
//!
//! BLENDFUNCTION u64 packing: `op | (flags<<8) | (sca<<16) | (fmt<<24)`.

use weave_gdi32::{
    alpha_blend, create_compatible_bitmap, create_compatible_dc, delete_object, select_object,
};

const AC_SRC_OVER: u64 = 0x00;
const AC_SRC_ALPHA: u64 = 0x01;

fn pack_blend(op: u8, flags: u8, sca: u8, fmt: u8) -> u64 {
    (op as u64) | ((flags as u64) << 8) | ((sca as u64) << 16) | ((fmt as u64) << 24)
}

/// Build a memory DC with a freshly allocated 32bpp DDB of the given size.
/// Returns `(hdc, hbm, bits_ptr)` so the test can read/write pixels directly.
fn make_mem_dc(w: i32, h: i32) -> (usize, usize, *mut u8) {
    let hdc = create_compatible_dc(0);
    let hbm = create_compatible_bitmap(hdc, w, h);
    let _ = select_object(hdc, hbm);
    // The bits_ptr is stored inside the GdiKind::Bitmap; fish it out via the
    // same path AlphaBlend uses. We duplicate the pattern here rather than
    // expose internals from weave-gdi32.
    let bits_ptr = weave_gdi32::objects::get(hbm, |k| match k {
        weave_gdi32::objects::GdiKind::Bitmap { bits_ptr, .. }
        | weave_gdi32::objects::GdiKind::DibSection { bits_ptr, .. } => Some(*bits_ptr),
        _ => None,
    })
    .flatten()
    .unwrap() as *mut u8;
    (hdc, hbm, bits_ptr)
}

fn fill_bgra(ptr: *mut u8, w: i32, h: i32, b: u8, g: u8, r: u8, a: u8) {
    let n = (w * h) as usize;
    for i in 0..n {
        unsafe {
            *ptr.add(i * 4) = b;
            *ptr.add(i * 4 + 1) = g;
            *ptr.add(i * 4 + 2) = r;
            *ptr.add(i * 4 + 3) = a;
        }
    }
}

#[test]
fn premultiplied_source_over_4x4_matches_wine_formula() {
    // Source ARGB premultiplied (A=0x80, R=0x80, G=0x00, B=0x00) — half-alpha red.
    // In BGRA memory order: (B=0x00, G=0x00, R=0x80, A=0x80).
    let (src_dc, src_bm, src_bits) = make_mem_dc(4, 4);
    fill_bgra(src_bits, 4, 4, 0x00, 0x00, 0x80, 0x80);

    // Dest ARGB (A=0xFF, R=0x00, G=0x00, B=0xFF) — opaque blue.
    // In BGRA memory order: (B=0xFF, G=0x00, R=0x00, A=0xFF).
    let (dst_dc, dst_bm, dst_bits) = make_mem_dc(4, 4);
    fill_bgra(dst_bits, 4, 4, 0xFF, 0x00, 0x00, 0xFF);

    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, AC_SRC_ALPHA as u8);
    let r = unsafe { alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 1, "AC_SRC_OVER + AC_SRC_ALPHA 4x4 should return TRUE");

    // Expected BGRA (per Wine MulDiv255): B=0x7F, G=0x00, R=0x80, A=0xFF.
    // Allow ±1 per channel for rounding slack.
    for i in 0..16 {
        let (b, g, r, a) = unsafe {
            (
                *dst_bits.add(i * 4),
                *dst_bits.add(i * 4 + 1),
                *dst_bits.add(i * 4 + 2),
                *dst_bits.add(i * 4 + 3),
            )
        };
        assert!(
            (b as i32 - 0x7F).abs() <= 1,
            "pixel {i} B={b:#x} expected ~0x7F"
        );
        assert_eq!(g, 0x00, "pixel {i} G={g:#x} expected 0x00");
        assert!(
            (r as i32 - 0x80).abs() <= 1,
            "pixel {i} R={r:#x} expected ~0x80"
        );
        assert_eq!(a, 0xFF, "pixel {i} A={a:#x} expected 0xFF");
    }

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn mismatched_dimensions_returns_false() {
    let (src_dc, src_bm, _) = make_mem_dc(4, 4);
    let (dst_dc, dst_bm, _) = make_mem_dc(8, 8);
    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, AC_SRC_ALPHA as u8);
    let r = unsafe { alpha_blend(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 0, "scale requests not yet supported, must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn nonzero_blend_op_returns_false() {
    let (src_dc, src_bm, _) = make_mem_dc(4, 4);
    let (dst_dc, dst_bm, _) = make_mem_dc(4, 4);
    // BlendOp=0x01 is not AC_SRC_OVER; Wine / Windows only define BlendOp=0.
    let bf = pack_blend(0x01, 0, 0xFF, AC_SRC_ALPHA as u8);
    let r = unsafe { alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 0, "BlendOp != AC_SRC_OVER must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn nonzero_blend_flags_returns_false() {
    let (src_dc, src_bm, _) = make_mem_dc(4, 4);
    let (dst_dc, dst_bm, _) = make_mem_dc(4, 4);
    let bf = pack_blend(AC_SRC_OVER as u8, 0x01, 0xFF, AC_SRC_ALPHA as u8);
    let r = unsafe { alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 0, "BlendFlags != 0 must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn window_dc_dest_returns_false() {
    // Source is a memory DC; dest is a bare DC with no bitmap selected →
    // dc.selected_bitmap == 0 → AlphaBlend treats it as a window DC and
    // bails because we don't do XGetImage round-trip yet.
    let (src_dc, src_bm, _) = make_mem_dc(4, 4);
    let dst_dc = create_compatible_dc(0); // no SelectObject
    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, AC_SRC_ALPHA as u8);
    let r = unsafe { alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 0, "window-DC dest without bits_ptr must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn zero_area_returns_false() {
    let (src_dc, src_bm, _) = make_mem_dc(4, 4);
    let (dst_dc, dst_bm, _) = make_mem_dc(4, 4);
    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, AC_SRC_ALPHA as u8);
    let r = unsafe { alpha_blend(dst_dc, 0, 0, 0, 4, src_dc, 0, 0, 0, 4, bf) };
    assert_eq!(r, 0, "zero-width rectangle must return FALSE");
    let r = unsafe { alpha_blend(dst_dc, 0, 0, 4, 0, src_dc, 0, 0, 4, 0, bf) };
    assert_eq!(r, 0, "zero-height rectangle must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}
