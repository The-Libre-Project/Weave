//! Probe gate — `StretchDIBits` parses BITMAPINFOHEADER, scales the source
//! rectangle to the destination DC using nearest-neighbor interpolation, and
//! dispatches to the X11 backend upload path.
//!
//! Covered:
//!   * Valid 32-bit BI_RGB DIB → returns nDestHeight.
//!   * biBitCount=24 → returns 0 (unsupported bpp).
//!   * biCompression=BI_BITFIELDS (3) → returns 0 (unsupported compression).
//!   * Null lp_bits → returns 0 without panicking.
//!   * Null lpbmi → returns 0 without panicking.
//!   * DIB_PAL_COLORS (i_usage=1) → returns 0.
//!   * Zero dest width/height → returns 0.
//!   * 1:1 copy (no scaling): src==dst size → returns nDestHeight.
//!   * Scale up 2×: 2×2 src → 4×4 dst → returns 4.
//!   * Top-down DIB (negative biHeight) → returns nDestHeight.

use weave_gdi32::{
    create_compatible_bitmap, create_compatible_dc, delete_object, select_object, stretch_di_bits,
};

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

const SRCCOPY: u32 = 0x00CC0020;

#[test]
fn valid_32bit_birgb_returns_n_dest_height() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        stretch_di_bits(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            4,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
            SRCCOPY,
        )
    };
    assert_eq!(r, 4, "32bpp BI_RGB 1:1 should return nDestHeight=4");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn scale_up_returns_dest_height() {
    let (dc, bm) = make_dc();
    let bi = make_bi(2, 2, 32, 0);
    let pixels = [0u8; 2 * 2 * 4];
    let r = unsafe {
        stretch_di_bits(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            2,
            2,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
            SRCCOPY,
        )
    };
    assert_eq!(
        r, 4,
        "32bpp BI_RGB scale 2x2→4x4 should return nDestHeight=4"
    );
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn unsupported_bpp_24_returns_0() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 24, 0);
    let pixels = [0u8; 4 * 4 * 3];
    let r = unsafe {
        stretch_di_bits(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            4,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
            SRCCOPY,
        )
    };
    assert_eq!(r, 0, "24bpp should return 0 (unsupported)");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn unsupported_compression_returns_0() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 3); // BI_BITFIELDS
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        stretch_di_bits(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            4,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
            SRCCOPY,
        )
    };
    assert_eq!(r, 0, "BI_BITFIELDS should return 0 (unsupported)");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn null_lp_bits_returns_0() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let r = unsafe {
        stretch_di_bits(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            4,
            4,
            std::ptr::null(),
            bi.as_ptr() as usize,
            0,
            SRCCOPY,
        )
    };
    assert_eq!(r, 0, "null lp_bits should return 0");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn null_lpbmi_returns_0() {
    let (dc, bm) = make_dc();
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe { stretch_di_bits(dc, 0, 0, 4, 4, 0, 0, 4, 4, pixels.as_ptr(), 0, 0, SRCCOPY) };
    assert_eq!(r, 0, "null lpbmi should return 0");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn pal_colors_usage_returns_0() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        stretch_di_bits(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            4,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            1,
            SRCCOPY,
        )
    };
    assert_eq!(r, 0, "DIB_PAL_COLORS should return 0 (unsupported)");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn zero_dest_dims_returns_0() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, 4, 32, 0);
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        stretch_di_bits(
            dc,
            0,
            0,
            0,
            4,
            0,
            0,
            4,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
            SRCCOPY,
        )
    };
    assert_eq!(r, 0, "zero nDestWidth should return 0");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn top_down_dib_returns_dest_height() {
    let (dc, bm) = make_dc();
    let bi = make_bi(4, -4, 32, 0); // negative height = top-down
    let pixels = [0u8; 4 * 4 * 4];
    let r = unsafe {
        stretch_di_bits(
            dc,
            0,
            0,
            4,
            4,
            0,
            0,
            4,
            4,
            pixels.as_ptr(),
            bi.as_ptr() as usize,
            0,
            SRCCOPY,
        )
    };
    assert_eq!(r, 4, "top-down DIB should return nDestHeight=4");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}
