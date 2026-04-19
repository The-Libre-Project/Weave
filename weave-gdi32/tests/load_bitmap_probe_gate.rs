//! Task 13 probe gate — `LoadBitmapW` / `LoadBitmapA` end-to-end against a
//! synthetic PE carrying RT_BITMAP at ordinal 1. Validates:
//!
//!   * `LoadBitmapW(hInst, MAKEINTRESOURCEW(1))` returns a non-zero HBITMAP
//!     whose `image_handles` entry is `ImageKind::Bitmap` with the recorded
//!     width/height/bpp from the fixture's BITMAPINFOHEADER.
//!   * `LoadBitmapA` ordinal-path returns the same handle (LR_SHARED dedup
//!     via `LoadImageW(IMAGE_BITMAP)`).
//!
//! Per KNOWN-BUG-CLASSES "Scaffold lying — two-Vec rel32 truncation": the
//! synthetic PE fixture lives in a single contiguous `Vec<u8>`. No second
//! allocation, no split image.

use weave_core::module_handles::register_with_base;
use weave_gdi32::{load_bitmap_a, load_bitmap_w};
use weave_user32::image_handles::{self, ImageKind};

const HIGH_BIT: u32 = 0x8000_0000;

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Build a PE32+ image carrying a single RT_BITMAP at ordinal 1 with a
/// 24×24 32bpp BITMAPINFOHEADER payload.
fn build_image() -> Vec<u8> {
    const SECTION_ALIGN: usize = 0x1000;
    let mut buf = vec![0u8; SECTION_ALIGN * 4];

    // DOS + PE headers.
    w16(&mut buf, 0, 0x5A4D);
    w32(&mut buf, 0x3c, 0x80);
    let pe_off = 0x80usize;
    w32(&mut buf, pe_off, 0x0000_4550);
    let fh_off = pe_off + 4;
    w16(&mut buf, fh_off, 0x8664);
    w16(&mut buf, fh_off + 2, 1);
    w16(&mut buf, fh_off + 16, 0xF0);
    let opt_off = fh_off + 20;
    w16(&mut buf, opt_off, 0x20b);

    let rsrc_rva: u32 = 0x1000;
    let rsrc_size: u32 = (SECTION_ALIGN * 2) as u32;
    let dd_off = opt_off + 0x70;
    w32(&mut buf, dd_off + 2 * 8, rsrc_rva);
    w32(&mut buf, dd_off + 2 * 8 + 4, rsrc_size);

    let rsrc = rsrc_rva as usize;

    // Type directory: single RT_BITMAP=2 entry.
    w16(&mut buf, rsrc + 12, 0); // named count
    w16(&mut buf, rsrc + 14, 1); // id count

    let name_dir_bitmap: u32 = 0x100;
    w32(&mut buf, rsrc + 16, 2); // RT_BITMAP
    w32(&mut buf, rsrc + 20, HIGH_BIT | name_dir_bitmap);

    // Name dir → ordinal 1 → lang dir → data entry.
    let bmp_lang: u32 = 0x140;
    let bmp_data: u32 = 0x180;
    let bmp_payload_rva: u32 = rsrc_rva + 0x300;

    let n = rsrc + name_dir_bitmap as usize;
    w16(&mut buf, n + 12, 0);
    w16(&mut buf, n + 14, 1);
    w32(&mut buf, n + 16, 1); // ordinal 1
    w32(&mut buf, n + 20, HIGH_BIT | bmp_lang);

    let l = rsrc + bmp_lang as usize;
    w16(&mut buf, l + 12, 0);
    w16(&mut buf, l + 14, 1);
    w32(&mut buf, l + 16, 0); // lang 0
    w32(&mut buf, l + 20, bmp_data);

    let b = rsrc + bmp_data as usize;
    w32(&mut buf, b, bmp_payload_rva);
    w32(&mut buf, b + 4, 40);
    w32(&mut buf, b + 8, 0);

    // BITMAPINFOHEADER payload: biSize=40, biWidth=24, biHeight=24, biPlanes=1, biBitCount=32.
    let bp = rsrc + 0x300;
    w32(&mut buf, bp, 40);
    w32(&mut buf, bp + 4, 24);
    w32(&mut buf, bp + 8, 24);
    w16(&mut buf, bp + 12, 1);
    w16(&mut buf, bp + 14, 32);

    buf
}

#[test]
fn load_bitmap_w_resolves_rt_bitmap() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_bitmap_probe_gate.dll", base);
    assert!(hmodule != 0);

    // SAFETY: ordinal path — no deref.
    let hbm = unsafe { load_bitmap_w(hmodule, std::ptr::without_provenance::<u16>(1)) };
    assert!(hbm != 0, "LoadBitmapW returned 0");

    let entry = image_handles::get(hbm).expect("HBITMAP entry missing");
    assert_eq!(entry.kind, ImageKind::Bitmap);
    assert_eq!(entry.width, 24);
    assert_eq!(entry.height, 24);
    assert_eq!(entry.bpp, 32);
}

#[test]
fn load_bitmap_a_ordinal_matches_w() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_bitmap_probe_gate_a.dll", base);

    // SAFETY: ordinal-as-pointer convention.
    let h_a = unsafe { load_bitmap_a(hmodule, std::ptr::without_provenance::<u8>(1)) };
    let h_w = unsafe { load_bitmap_w(hmodule, std::ptr::without_provenance::<u16>(1)) };
    assert!(h_a != 0);
    assert_eq!(
        h_a, h_w,
        "LoadBitmapA ordinal path should hit same LR_SHARED slot as W"
    );
}

#[test]
fn load_bitmap_w_missing_returns_zero() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_bitmap_probe_missing.dll", base);
    // SAFETY: ordinal path.
    let h = unsafe { load_bitmap_w(hmodule, std::ptr::without_provenance::<u16>(9999)) };
    assert_eq!(h, 0);
}
