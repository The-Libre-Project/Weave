//! Probe gate — `GetDIBits` reads internal BGRA bitmap data and writes it to
//! a caller-supplied buffer, converting to the format specified in the
//! BITMAPINFOHEADER. Query mode (lp_vbits=0) fills the header and returns
//! bmp_h without copying.
//!
//! Covered:
//!   * Query mode biBitCount=32 → fills header with 32, returns bmp_h.
//!   * Query mode biBitCount=24 → fills header with 24 and 24-bit sizeImage.
//!   * Copy mode biBitCount=32 → returns c_lines.
//!   * Copy mode biBitCount=24 → returns c_lines (BGRA→BGR expansion).
//!   * Null h_bm → returns 0.
//!   * Null lpbmi → returns 0.
//!   * start >= bmp_h → returns 0.

use weave_gdi32::{
    create_compatible_bitmap, create_compatible_dc, delete_object, get_dib_bits, select_object,
};

fn make_bi(bit_count: u16) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[0..4].copy_from_slice(&40u32.to_le_bytes());
    buf[12..14].copy_from_slice(&1u16.to_le_bytes()); // biPlanes
    buf[14..16].copy_from_slice(&bit_count.to_le_bytes());
    buf
}

fn make_bitmap(w: i32, h: i32) -> (usize, usize) {
    let dc = create_compatible_dc(0);
    let bm = create_compatible_bitmap(dc, w, h);
    let _ = select_object(dc, bm);
    (dc, bm)
}

#[test]
fn query_mode_32bit_fills_header_returns_height() {
    let (dc, bm) = make_bitmap(4, 4);
    let mut bi = make_bi(32);
    let r = unsafe { get_dib_bits(dc, bm, 0, 4, 0, bi.as_mut_ptr() as usize, 0) };
    let bpp = u16::from_le_bytes([bi[14], bi[15]]);
    assert_eq!(r, 4, "query mode should return bmp_h");
    assert_eq!(bpp, 32, "query mode should write biBitCount=32");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn query_mode_24bit_fills_header_returns_height() {
    let (dc, bm) = make_bitmap(4, 4);
    let mut bi = make_bi(24);
    let r = unsafe { get_dib_bits(dc, bm, 0, 4, 0, bi.as_mut_ptr() as usize, 0) };
    let bpp = u16::from_le_bytes([bi[14], bi[15]]);
    let size_image = u32::from_le_bytes([bi[20], bi[21], bi[22], bi[23]]);
    // 24-bit stride for 4px wide = ((4*24+31)/32)*4 = 12 bytes; 4 rows → 48
    assert_eq!(r, 4, "query mode should return bmp_h");
    assert_eq!(
        bpp, 24,
        "query mode should write biBitCount=24 when requested"
    );
    assert_eq!(size_image, 48, "24-bit sizeImage for 4x4 = 48 bytes");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn copy_32bit_returns_lines() {
    let (dc, bm) = make_bitmap(4, 4);
    let mut bi = make_bi(32);
    // bottom-up output (biHeight > 0, already 0 from make_bi default)
    let mut buf = vec![0u8; 4 * 4 * 4]; // 64 bytes
    let r = unsafe {
        get_dib_bits(
            dc,
            bm,
            0,
            4,
            buf.as_mut_ptr() as usize,
            bi.as_mut_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 4, "32bpp copy should return c_lines=4");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn copy_24bit_returns_lines() {
    let (dc, bm) = make_bitmap(4, 4);
    let mut bi = make_bi(24);
    let mut buf = vec![0u8; 4 * 4 * 3]; // 48 bytes (24-bit stride = 12 per row)
    let r = unsafe {
        get_dib_bits(
            dc,
            bm,
            0,
            4,
            buf.as_mut_ptr() as usize,
            bi.as_mut_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 4, "24bpp copy should return c_lines=4");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn null_hbm_returns_0() {
    let mut bi = make_bi(32);
    let mut buf = vec![0u8; 64];
    let r = unsafe {
        get_dib_bits(
            0,
            0,
            0,
            4,
            buf.as_mut_ptr() as usize,
            bi.as_mut_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 0, "null h_bm should return 0");
}

#[test]
fn null_lpbmi_returns_0() {
    let (dc, bm) = make_bitmap(4, 4);
    let mut buf = vec![0u8; 64];
    let r = unsafe { get_dib_bits(dc, bm, 0, 4, buf.as_mut_ptr() as usize, 0, 0) };
    assert_eq!(r, 0, "null lpbmi should return 0");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}

#[test]
fn start_past_height_returns_0() {
    let (dc, bm) = make_bitmap(4, 4);
    let mut bi = make_bi(32);
    let mut buf = vec![0u8; 64];
    let r = unsafe {
        get_dib_bits(
            dc,
            bm,
            10,
            4,
            buf.as_mut_ptr() as usize,
            bi.as_mut_ptr() as usize,
            0,
        )
    };
    assert_eq!(r, 0, "start >= bmp_h should return 0");
    let _ = delete_object(bm);
    let _ = delete_object(dc);
}
