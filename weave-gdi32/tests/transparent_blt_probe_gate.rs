//! Task 21 probe gate — `TransparentBlt` implements color-key skip for
//! 32-bit ARGB memory-DC source + dest at equal dimensions.
//!
//! Like AlphaBlend (task 20) and unlike BitBlt/StretchBlt, the composited
//! result lives in the destination memory DC's CPU-side `bits_ptr`, so a
//! pixel round-trip through the backing buffer is directly observable.
//!
//! Covered:
//!   * 4x4 magenta-keyed source over solid-blue dest → keyed pixels leave
//!     dest unchanged; non-keyed pixels overwrite dest.
//!   * Mismatched dimensions → returns FALSE.
//!   * Non-32bpp dest (24bpp DIB section) → FALSE.
//!   * Window-DC dest (no selected bitmap) → FALSE.
//!   * Zero-area rectangles → FALSE.

use weave_gdi32::{
    create_compatible_bitmap, create_compatible_dc, create_dib_section, delete_object,
    select_object, transparent_blt,
};

/// Build a memory DC with a freshly allocated 32bpp DDB of the given size.
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

/// Build a memory DC backed by a 24bpp DIB section — used to exercise the
/// bpp-rejection branch.
fn make_mem_dc_24bpp(w: i32, h: i32) -> (usize, usize) {
    let hdc = create_compatible_dc(0);
    // BITMAPINFOHEADER — just the first 40 bytes matter for create_dib_section.
    let mut bmi = [0u8; 40];
    bmi[0..4].copy_from_slice(&40u32.to_le_bytes()); // biSize
    bmi[4..8].copy_from_slice(&w.to_le_bytes()); // biWidth
    bmi[8..12].copy_from_slice(&h.to_le_bytes()); // biHeight
    bmi[12..14].copy_from_slice(&1u16.to_le_bytes()); // biPlanes
    bmi[14..16].copy_from_slice(&24u16.to_le_bytes()); // biBitCount, biCompression=BI_RGB=0
    let mut bits: usize = 0;
    let hbm =
        unsafe { create_dib_section(hdc, bmi.as_ptr() as usize, 0, &mut bits as *mut _, 0, 0) };
    let _ = select_object(hdc, hbm);
    (hdc, hbm)
}

fn write_bgra(ptr: *mut u8, idx: usize, b: u8, g: u8, r: u8, a: u8) {
    unsafe {
        *ptr.add(idx * 4) = b;
        *ptr.add(idx * 4 + 1) = g;
        *ptr.add(idx * 4 + 2) = r;
        *ptr.add(idx * 4 + 3) = a;
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

fn fill_bgra(ptr: *mut u8, w: i32, h: i32, b: u8, g: u8, r: u8, a: u8) {
    let n = (w * h) as usize;
    for i in 0..n {
        write_bgra(ptr, i, b, g, r, a);
    }
}

#[test]
fn magenta_key_leaves_dest_unchanged_where_matched() {
    // Source: 4x4 chequerboard — even indices magenta (keyed), odd green.
    // Magenta as BGRA memory: B=0xFF, G=0x00, R=0xFF, A=0xFF → little-endian
    // u32 = 0xFFFF00FF, low-24 = 0x00FF00FF.
    // Green as BGRA: B=0x00, G=0xFF, R=0x00, A=0xFF.
    let (src_dc, src_bm, src_bits) = make_mem_dc(4, 4);
    for i in 0..16 {
        if i % 2 == 0 {
            write_bgra(src_bits, i, 0xFF, 0x00, 0xFF, 0xFF); // magenta
        } else {
            write_bgra(src_bits, i, 0x00, 0xFF, 0x00, 0xFF); // green
        }
    }

    // Dest: solid opaque blue. BGRA: B=0xFF, G=0x00, R=0x00, A=0xFF.
    let (dst_dc, dst_bm, dst_bits) = make_mem_dc(4, 4);
    fill_bgra(dst_bits, 4, 4, 0xFF, 0x00, 0x00, 0xFF);

    // COLORREF 0x00BBGGRR for magenta: B=0xFF, G=0x00, R=0xFF → 0x00FF00FF.
    let cr_magenta: u32 = 0x00FF_00FF;
    let r = unsafe { transparent_blt(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, cr_magenta) };
    assert_eq!(r, 1, "TransparentBlt 4x4 should return TRUE");

    for i in 0..16 {
        let (b, g, r, a) = read_bgra(dst_bits as *const u8, i);
        if i % 2 == 0 {
            // Magenta keyed → dest unchanged (blue).
            assert_eq!(
                (b, g, r, a),
                (0xFF, 0x00, 0x00, 0xFF),
                "pixel {i} keyed: dest must remain blue"
            );
        } else {
            // Green non-keyed → dest overwritten with source green.
            assert_eq!(
                (b, g, r, a),
                (0x00, 0xFF, 0x00, 0xFF),
                "pixel {i} non-keyed: dest must be source green"
            );
        }
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
    let r = unsafe { transparent_blt(dst_dc, 0, 0, 8, 8, src_dc, 0, 0, 4, 4, 0x00FF_00FF) };
    assert_eq!(r, 0, "stretch-and-key not yet supported, must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn non_32bpp_dest_returns_false() {
    let (src_dc, src_bm, _) = make_mem_dc(4, 4);
    let (dst_dc, dst_bm) = make_mem_dc_24bpp(4, 4);
    let r = unsafe { transparent_blt(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, 0x00FF_00FF) };
    assert_eq!(r, 0, "24bpp dest must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn window_dc_dest_returns_false() {
    // Dest is a bare DC with no bitmap selected → treated as window DC,
    // which we don't round-trip through XGetImage yet.
    let (src_dc, src_bm, _) = make_mem_dc(4, 4);
    let dst_dc = create_compatible_dc(0);
    let r = unsafe { transparent_blt(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 4, 4, 0x00FF_00FF) };
    assert_eq!(r, 0, "window-DC dest must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn zero_area_returns_false() {
    let (src_dc, src_bm, _) = make_mem_dc(4, 4);
    let (dst_dc, dst_bm, _) = make_mem_dc(4, 4);
    let r = unsafe { transparent_blt(dst_dc, 0, 0, 0, 4, src_dc, 0, 0, 0, 4, 0x00FF_00FF) };
    assert_eq!(r, 0, "zero-width must return FALSE");
    let r = unsafe { transparent_blt(dst_dc, 0, 0, 4, 0, src_dc, 0, 0, 4, 0, 0x00FF_00FF) };
    assert_eq!(r, 0, "zero-height must return FALSE");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}
