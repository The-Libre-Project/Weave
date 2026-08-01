//! Task 17 probe gate — `GdiAlphaBlend` implements AC_SRC_OVER source-over
//! composite for 32-bit ARGB memory-DC source + destination, sharing the
//! `blend_and_upload` engine with msimg32's `AlphaBlend` (task 20).
//!
//! Unlike BitBlt / StretchBlt probe gates (Tasks 17/18) which cannot verify
//! pixel results because the upload writes to an X11 Pixmap, GdiAlphaBlend
//! operates on the DEST memory DC's CPU-side `bits_ptr` directly, so a
//! pixel round-trip through the backing buffer is observable here.
//!
//! Covered:
//!   * Constant-alpha (no AC_SRC_ALPHA): red source over white dest at
//!     SCA=128 → ~(255,128,128) (MulDiv255 rounding gives 127, ±1 tolerance).
//!   * SCA=0 → dest unchanged; SCA=255 → dest = source.
//!   * AC_SRC_ALPHA per-pixel premultiplied source over white → ~(128,128,128).
//!   * Scale (2x2 source → 4x4 dest) with COLORONCOLOR nearest-neighbour.
//!   * Invalid DC handle → FALSE.
//!   * Zero-area rectangles → TRUE (no-op).
//!
//! BLENDFUNCTION u64 packing: `op | (flags<<8) | (sca<<16) | (fmt<<24)`.

use weave_gdi32::{
    create_compatible_bitmap, create_compatible_dc, delete_object, gdi_alpha_blend, select_object,
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

fn read_bgra(ptr: *const u8, idx: usize) -> (u8, u8, u8, u8) {
    unsafe {
        (
            *ptr.add(idx * 4),
            *ptr.add(idx * 4 + 1),
            *ptr.add(idx * 4 + 2),
            *ptr.add(idx * 4 + 3),
        )
    }
}

fn write_bgra(ptr: *mut u8, idx: usize, b: u8, g: u8, r: u8, a: u8) {
    unsafe {
        *ptr.add(idx * 4) = b;
        *ptr.add(idx * 4 + 1) = g;
        *ptr.add(idx * 4 + 2) = r;
        *ptr.add(idx * 4 + 3) = a;
    }
}

/// Wine's `muldiv255(a,b) = (a*b + 127) / 255` — the exact idiom the
/// implementation uses, so we can pin exact expected values.
fn muldiv255(a: u32, b: u32) -> u32 {
    ((a * b) + 127) / 255
}

#[test]
fn constant_alpha_128_red_over_white() {
    // Source: opaque red. BGRA memory order: (B=0, G=0, R=255, A=255).
    let (src_dc, src_bm, src_bits) = make_mem_dc(4, 4);
    fill_bgra(src_bits, 4, 4, 0x00, 0x00, 0xFF, 0xFF);

    // Dest: opaque white. BGRA: (B=255, G=255, R=255, A=255).
    let (dst_dc, dst_bm, dst_bits) = make_mem_dc(4, 4);
    fill_bgra(dst_bits, 4, 4, 0xFF, 0xFF, 0xFF, 0xFF);

    // Straight alpha, SCA=128, no AC_SRC_ALPHA.
    let bf = pack_blend(AC_SRC_OVER as u8, 0, 128, 0);
    let r = unsafe { gdi_alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 1, "constant-alpha 4x4 should return TRUE");

    // sa_eff = muldiv255(255,128) = 128; inv_a = 127.
    // R = muldiv255(255,128) + muldiv255(255,127) = 128 + 127 = 255.
    // G = muldiv255(0,128)   + muldiv255(255,127) =   0 + 127 = 127.
    // B = 127. A = 128 + 127 = 255.
    let expected_r = muldiv255(255, 128) + muldiv255(255, 127);
    let expected_g = muldiv255(0, 128) + muldiv255(255, 127);
    let expected_b = muldiv255(0, 128) + muldiv255(255, 127);
    for i in 0..16 {
        let (b, g, r, a) = read_bgra(dst_bits as *const u8, i);
        assert!(
            (r as u32).abs_diff(expected_r) <= 1,
            "pixel {i} R={r:#x} expected ~{expected_r:#x}"
        );
        assert!(
            (g as u32).abs_diff(expected_g) <= 1,
            "pixel {i} G={g:#x} expected ~{expected_g:#x}"
        );
        assert!(
            (b as u32).abs_diff(expected_b) <= 1,
            "pixel {i} B={b:#x} expected ~{expected_b:#x}"
        );
        assert_eq!(a, 0xFF, "pixel {i} A={a:#x} expected 0xFF");
    }

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn constant_alpha_0_leaves_dest_unchanged() {
    let (src_dc, src_bm, src_bits) = make_mem_dc(4, 4);
    fill_bgra(src_bits, 4, 4, 0x00, 0x00, 0xFF, 0xFF);

    let (dst_dc, dst_bm, dst_bits) = make_mem_dc(4, 4);
    fill_bgra(dst_bits, 4, 4, 0xFF, 0x00, 0x00, 0xFF); // solid blue

    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0, 0);
    let r = unsafe { gdi_alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 1, "SCA=0 must return TRUE");

    // sa_eff = 0, inv_a = 255 → output equals destination exactly.
    for i in 0..16 {
        assert_eq!(
            read_bgra(dst_bits as *const u8, i),
            (0xFF, 0x00, 0x00, 0xFF),
            "pixel {i}: dest must be unchanged at SCA=0"
        );
    }

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn constant_alpha_255_copies_source() {
    let (src_dc, src_bm, src_bits) = make_mem_dc(4, 4);
    fill_bgra(src_bits, 4, 4, 0x00, 0x00, 0xFF, 0xFF); // opaque red

    let (dst_dc, dst_bm, dst_bits) = make_mem_dc(4, 4);
    fill_bgra(dst_bits, 4, 4, 0xFF, 0xFF, 0xFF, 0xFF); // opaque white

    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, 0);
    let r = unsafe { gdi_alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 1, "SCA=255 must return TRUE");

    // sa_eff = 255, inv_a = 0 → output equals source exactly.
    for i in 0..16 {
        assert_eq!(
            read_bgra(dst_bits as *const u8, i),
            (0x00, 0x00, 0xFF, 0xFF),
            "pixel {i}: dest must equal source at SCA=255"
        );
    }

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn ac_src_alpha_per_pixel_half_alpha_black_over_white() {
    // Premultiplied source: black at half alpha. In BGRA memory order:
    // (B=0x00, G=0x00, R=0x00, A=0x80).
    let (src_dc, src_bm, src_bits) = make_mem_dc(4, 4);
    fill_bgra(src_bits, 4, 4, 0x00, 0x00, 0x00, 0x80);

    let (dst_dc, dst_bm, dst_bits) = make_mem_dc(4, 4);
    fill_bgra(dst_bits, 4, 4, 0xFF, 0xFF, 0xFF, 0xFF); // opaque white

    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, AC_SRC_ALPHA as u8);
    let r = unsafe { gdi_alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 1, "AC_SRC_ALPHA 4x4 should return TRUE");

    // sa_eff = muldiv255(0x80, 0xFF) = 0x80; inv_a = 0x7F.
    // R = muldiv255(0,255) + muldiv255(255,127) = 0 + 127 = 127.
    // G = B = 127. A = 128 + 127 = 255.
    let expected = muldiv255(0, 255) + muldiv255(255, 127);
    for i in 0..16 {
        let (b, g, r, a) = read_bgra(dst_bits as *const u8, i);
        assert!(
            (r as u32).abs_diff(expected) <= 1,
            "pixel {i} R={r:#x} expected ~{expected:#x}"
        );
        assert_eq!(g, b, "pixel {i}: grey must be neutral G={g:#x} B={b:#x}");
        assert!(
            (b as u32).abs_diff(expected) <= 1,
            "pixel {i} B={b:#x} expected ~{expected:#x}"
        );
        assert_eq!(a, 0xFF, "pixel {i} A={a:#x} expected 0xFF");
    }

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn scale_2x2_to_4x4_nearest_neighbour() {
    // 2x2 source with four distinct quadrants.
    let (src_dc, src_bm, src_bits) = make_mem_dc(2, 2);
    write_bgra(src_bits, 0, 0x00, 0x00, 0xFF, 0xFF); // (0,0) red
    write_bgra(src_bits, 1, 0x00, 0xFF, 0x00, 0xFF); // (1,0) green
    write_bgra(src_bits, 2, 0xFF, 0x00, 0x00, 0xFF); // (0,1) blue
    write_bgra(src_bits, 3, 0xFF, 0xFF, 0xFF, 0xFF); // (1,1) white

    let (dst_dc, dst_bm, dst_bits) = make_mem_dc(4, 4);
    fill_bgra(dst_bits, 4, 4, 0x00, 0x00, 0x00, 0x00);

    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, 0);
    let r = unsafe { gdi_alpha_blend(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 2, 2, bf) };
    assert_eq!(r, 1, "2x2 -> 4x4 scale should return TRUE");

    // COLORONCOLOR nearest: sx = src_x + dx * w_src / w_dest. dx 0,1 → sx 0;
    // dx 2,3 → sx 1. So dest quadrants map to the four source quadrants.
    // Red (B=0,G=0,R=255), green (B=0,G=255,R=0), blue (B=255,G=0,R=0), white.
    for i in 0..16 {
        let x = i % 4;
        let y = i / 4;
        let (b, g, r, a) = read_bgra(dst_bits as *const u8, i);
        let expected: (u8, u8, u8, u8) = if x < 2 && y < 2 {
            (0x00, 0x00, 0xFF, 0xFF)
        } else if x >= 2 && y < 2 {
            (0x00, 0xFF, 0x00, 0xFF)
        } else if x < 2 && y >= 2 {
            (0xFF, 0x00, 0x00, 0xFF)
        } else {
            (0xFF, 0xFF, 0xFF, 0xFF)
        };
        assert_eq!((b, g, r, a), expected, "pixel {i} ({x},{y})");
    }

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn invalid_dc_handle_returns_false() {
    let (src_dc, src_bm, src_bits) = make_mem_dc(4, 4);
    fill_bgra(src_bits, 4, 4, 0x00, 0x00, 0xFF, 0xFF);
    let (dst_dc, dst_bm, _) = make_mem_dc(4, 4);

    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, AC_SRC_ALPHA as u8);

    // Bogus dest handle.
    let r = unsafe { gdi_alpha_blend(0xDEAD_BEEF, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, bf) };
    assert_eq!(r, 0, "invalid dest DC must return FALSE");

    // Bogus source handle.
    let r = unsafe { gdi_alpha_blend(dst_dc, 0, 0, 4, 4, 0xDEAD_BEEF, 0, 0, 4, 4, bf) };
    assert_eq!(r, 0, "invalid source DC must return FALSE");

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn zero_size_returns_true() {
    let (src_dc, src_bm, src_bits) = make_mem_dc(4, 4);
    fill_bgra(src_bits, 4, 4, 0x00, 0x00, 0xFF, 0xFF);
    let (dst_dc, dst_bm, _) = make_mem_dc(4, 4);

    let bf = pack_blend(AC_SRC_OVER as u8, 0, 0xFF, AC_SRC_ALPHA as u8);

    let r = unsafe { gdi_alpha_blend(dst_dc, 0, 0, 0, 4, src_dc, 0, 0, 0, 4, bf) };
    assert_eq!(r, 1, "zero-width rectangle is a no-op TRUE");

    let r = unsafe { gdi_alpha_blend(dst_dc, 0, 0, 4, 0, src_dc, 0, 0, 4, 0, bf) };
    assert_eq!(r, 1, "zero-height rectangle is a no-op TRUE");

    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}
