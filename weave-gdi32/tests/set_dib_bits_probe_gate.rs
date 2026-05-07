//! Task 19 probe gate — `SetDIBitsToDevice` parses BITMAPINFOHEADER, slices
//! the `uStartScan`/`cLines` band, and dispatches to the backend upload path.
//!
//! Dispatch-only — pixel round-trip through the destination bitmap's
//! `bits_ptr` is not asserted: upload goes to an X11 Pixmap via put_image,
//! which does not write back to CPU memory. Same caveat Tasks 17 + 18
//! documented for memory-DC probe gates.
//!
//! Covered:
//!   * Valid 32-bit BI_RGB DIB → returns c_lines.
//!   * biBitCount=24 → returns c_lines (24-bit BGR supported).
//!   * biCompression=BI_BITFIELDS (3) → returns 0 (unsupported compression).
//!   * Null lp_v_bits → returns 0 without panicking.
//!   * Null lpbmi → returns 0 without panicking.
//!   * DIB_PAL_COLORS (color_use=1) → returns 0.
//!   * start_scan >= height → returns 0.
//!   * start_scan + c_lines > height → clamped to height-start_scan.

use weave_gdi32::{
    create_compatible_bitmap, create_compatible_dc, delete_object, select_object,
    set_dib_bits_to_device,
};

/// Build a BITMAPINFOHEADER in a 40-byte buffer with the given fields.
/// Layout (little-endian, packed):
///   +0  biSize (u32 = 40)
///   +4  biWidth (i32)
///   +8  biHeight (i32) — negative = top-down
///   +12 biPlanes (u16 = 1)
///   +14 biBitCount (u16)
///   +16 biCompression (u32) — BI_RGB = 0, BI_BITFIELDS = 3
///   +20 biSizeImage (u32)
///   +24 biXPelsPerMeter (i32)
///   +28 biYPelsPerMeter (i32)
///   +32 biClrUsed (u32)
///   +36 biClrImportant (u32)
fn make_bi(width: i32, height: i32, bit_count: u16, compression: u32) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[0..4].copy_from_slice(&40u32.to_le_bytes());
    buf[4..8].copy_from_slice(&width.to_le_bytes());
    buf[8..12].copy_from_slice(&height.to_le_bytes());
    buf[12..14].copy_from_slice(&1u16.to_le_bytes());
    buf[14..16].copy_from_slice(&bit_count.to_le_bytes());
    buf[16..20].copy_from_slice(&compression.to_le_bytes());
    buf
}

fn make_dc() -> (usize, usize) {
    let dc = create_compatible_dc(0);
    let bm = create_compatible_bitmap(dc, 16, 16);
    let _ = select_object(dc, bm);
    (dc, bm)
}

#[test]
fn valid_32bit_birgb_returns_clines() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let pixels = [0u8; 4 * 4 * 4]; // 4x4 BGRA
    let r = unsafe {
        set_dib_bits_to_device(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            0,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 4, "32bpp BI_RGB should return c_lines");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn top_down_dib_returns_clines() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, -4, 32, 0); // negative height = top-down
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        set_dib_bits_to_device(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            0,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 4, "top-down DIB should dispatch and return c_lines");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn valid_24bit_birgb_returns_clines() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 24, 0);
    let pixels = [0u8; 4 * 4 * 3]; // 4x4 BGR (3 bytes/pixel)
    let r = unsafe {
        set_dib_bits_to_device(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            0,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 4, "24bpp BI_RGB should return c_lines");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn compression_bitfields_rejected() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 3); // BI_BITFIELDS
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        set_dib_bits_to_device(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            0,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 0, "BI_BITFIELDS compression should be rejected");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn null_bits_returns_zero() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let r = unsafe {
        set_dib_bits_to_device(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            0,
            4,
            std::ptr::null(),
            bi.as_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 0, "null bits pointer should return 0 without panic");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn null_bmi_returns_zero() {
    let (dc, bm) = make_dc();
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe { set_dib_bits_to_device(dc, 0, 0, 4, 4, 0, 0, 0, 4, pixels.as_ptr(), 0, 0) };
    assert_eq!(
        r, 0,
        "null BITMAPINFO pointer should return 0 without panic"
    );
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn pal_colors_rejected() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        set_dib_bits_to_device(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            0,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            1, // DIB_PAL_COLORS
        )
    };
    assert_eq!(
        r, 0,
        "DIB_PAL_COLORS should be rejected (DIB_RGB_COLORS only)"
    );
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn startscan_past_height_returns_zero() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        set_dib_bits_to_device(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            10, // start_scan >= height(4)
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 0, "start_scan >= height should return 0 (Wine behavior)");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn clines_clamped_to_height_minus_startscan() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let pixels = [0u8; 4 * 4 * 4];
    // start_scan=1, c_lines=10 but height=4 → clamps to 3.
    let r = unsafe {
        set_dib_bits_to_device(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            1,
            10,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
        )
    };
    assert_eq!(
        r, 3,
        "c_lines should clamp to height - start_scan (4 - 1 = 3)"
    );
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}
