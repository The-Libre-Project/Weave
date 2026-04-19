//! Task 10 probe gate — end-to-end validation of `LoadIconW` / `LoadCursorW` /
//! `LoadImageW` against a synthetic PE carrying real RT_GROUP_ICON + RT_ICON
//! + RT_BITMAP resources. Validates:
//!
//!   * handle-table allocation returns distinct non-zero handles per call,
//!   * `LR_SHARED` dedup: two `LoadIconW` calls with the same `(hInst, name)`
//!     return the same handle,
//!   * each handle's recorded `ImageKind` matches the requested type.
//!
//! Per KNOWN-BUG-CLASSES "Scaffold lying — two-Vec rel32 truncation": the
//! synthetic PE fixture lives in a single contiguous `Vec<u8>`. No second
//! allocation, no split image.

use weave_core::module_handles::register_with_base;
use weave_user32::api::{load_cursor_w, load_icon_w, load_image_w};
use weave_user32::image_handles::{self, ImageKind};

const HIGH_BIT: u32 = 0x8000_0000;

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Build a PE32+ image carrying:
///   RT_GROUP_ICON (14), ordinal 1, lang 0
///     → 1-entry GRPICONDIR with nId=100
///   RT_ICON (3), ordinal 100, lang 0
///     → 40-byte BITMAPINFOHEADER-style blob (just unique bytes).
///   RT_GROUP_CURSOR (12), ordinal 1, lang 0
///     → 1-entry directory with nId=200
///   RT_CURSOR (1), ordinal 200, lang 0
///     → 40-byte blob
///   RT_BITMAP (2), ordinal 1, lang 0
///     → 40-byte BITMAPINFOHEADER with width=16, height=16, bpp=32
fn build_image() -> Vec<u8> {
    const SECTION_ALIGN: usize = 0x1000;
    let mut buf = vec![0u8; SECTION_ALIGN * 8];

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
    let rsrc_size: u32 = (SECTION_ALIGN * 6) as u32;
    let dd_off = opt_off + 0x70;
    w32(&mut buf, dd_off + 2 * 8, rsrc_rva);
    w32(&mut buf, dd_off + 2 * 8 + 4, rsrc_size);

    let rsrc = rsrc_rva as usize;

    // ── Type directory: 5 id entries ──────────────────────────────────────
    // RT_CURSOR=1, RT_BITMAP=2, RT_ICON=3, RT_GROUP_CURSOR=12, RT_GROUP_ICON=14
    // Per Wine/PE, entries must be sorted by id. We'll write them sorted.
    w16(&mut buf, rsrc + 12, 0); // named
    w16(&mut buf, rsrc + 14, 5); // id

    // Offsets (within .rsrc) for per-type Name directories.
    let name_dir_cursor: u32 = 0x100;
    let name_dir_bitmap: u32 = 0x140;
    let name_dir_icon: u32 = 0x180;
    let name_dir_grp_cursor: u32 = 0x1C0;
    let name_dir_grp_icon: u32 = 0x200;

    w32(&mut buf, rsrc + 16, 1); // RT_CURSOR
    w32(&mut buf, rsrc + 20, HIGH_BIT | name_dir_cursor);
    w32(&mut buf, rsrc + 24, 2); // RT_BITMAP
    w32(&mut buf, rsrc + 28, HIGH_BIT | name_dir_bitmap);
    w32(&mut buf, rsrc + 32, 3); // RT_ICON
    w32(&mut buf, rsrc + 36, HIGH_BIT | name_dir_icon);
    w32(&mut buf, rsrc + 40, 12); // RT_GROUP_CURSOR
    w32(&mut buf, rsrc + 44, HIGH_BIT | name_dir_grp_cursor);
    w32(&mut buf, rsrc + 48, 14); // RT_GROUP_ICON
    w32(&mut buf, rsrc + 52, HIGH_BIT | name_dir_grp_icon);

    // Helper: emit a name-dir at `off` with a single id entry pointing to a
    // lang-dir at `lang_off`; the lang-dir then points to a leaf data-entry
    // at `data_off`. Returns nothing; caller wires the actual payload.
    let emit_single_chain =
        |buf: &mut [u8], name_off: u32, res_id: u32, lang_off: u32, data_off: u32| {
            let n = rsrc + name_off as usize;
            w16(buf, n + 12, 0);
            w16(buf, n + 14, 1);
            w32(buf, n + 16, res_id);
            w32(buf, n + 20, HIGH_BIT | lang_off);

            let l = rsrc + lang_off as usize;
            w16(buf, l + 12, 0);
            w16(buf, l + 14, 1);
            w32(buf, l + 16, 0); // lang 0
            w32(buf, l + 20, data_off); // leaf (high bit clear)
        };

    // Group-icon name-dir (ordinal 1) → lang @0x240 → data-entry @0x280 → payload @0x500
    let grp_icon_lang: u32 = 0x240;
    let grp_icon_data: u32 = 0x280;
    let grp_icon_payload_rva: u32 = rsrc_rva + 0x500;
    emit_single_chain(&mut buf, name_dir_grp_icon, 1, grp_icon_lang, grp_icon_data);

    // Icon name-dir (ordinal 100) → lang @0x2C0 → data-entry @0x300 → payload @0x600
    let icon_lang: u32 = 0x2C0;
    let icon_data: u32 = 0x300;
    let icon_payload_rva: u32 = rsrc_rva + 0x600;
    emit_single_chain(&mut buf, name_dir_icon, 100, icon_lang, icon_data);

    // Group-cursor name-dir (ordinal 1) → lang @0x340 → data-entry @0x380 → payload @0x700
    let grp_cur_lang: u32 = 0x340;
    let grp_cur_data: u32 = 0x380;
    let grp_cur_payload_rva: u32 = rsrc_rva + 0x700;
    emit_single_chain(&mut buf, name_dir_grp_cursor, 1, grp_cur_lang, grp_cur_data);

    // Cursor name-dir (ordinal 200) → lang @0x3C0 → data-entry @0x400 → payload @0x800
    let cur_lang: u32 = 0x3C0;
    let cur_data: u32 = 0x400;
    let cur_payload_rva: u32 = rsrc_rva + 0x800;
    emit_single_chain(&mut buf, name_dir_cursor, 200, cur_lang, cur_data);

    // Bitmap name-dir (ordinal 1) → lang @0x440 → data-entry @0x480 → payload @0x900
    let bmp_lang: u32 = 0x440;
    let bmp_data: u32 = 0x480;
    let bmp_payload_rva: u32 = rsrc_rva + 0x900;
    emit_single_chain(&mut buf, name_dir_bitmap, 1, bmp_lang, bmp_data);

    // ── Fill in IMAGE_RESOURCE_DATA_ENTRY leaves ──────────────────────────
    // Group-icon: GRPICONDIR = {reserved(2), type(2), count(2)} + 14-byte GRPICONDIRENTRY
    // Size = 6 + 14 = 20 bytes.
    let g = rsrc + grp_icon_data as usize;
    w32(&mut buf, g, grp_icon_payload_rva);
    w32(&mut buf, g + 4, 20);
    w32(&mut buf, g + 8, 0);

    let i = rsrc + icon_data as usize;
    w32(&mut buf, i, icon_payload_rva);
    w32(&mut buf, i + 4, 40);
    w32(&mut buf, i + 8, 0);

    let gc = rsrc + grp_cur_data as usize;
    w32(&mut buf, gc, grp_cur_payload_rva);
    w32(&mut buf, gc + 4, 20);
    w32(&mut buf, gc + 8, 0);

    let c = rsrc + cur_data as usize;
    w32(&mut buf, c, cur_payload_rva);
    w32(&mut buf, c + 4, 40);
    w32(&mut buf, c + 8, 0);

    let b = rsrc + bmp_data as usize;
    w32(&mut buf, b, bmp_payload_rva);
    w32(&mut buf, b + 4, 40);
    w32(&mut buf, b + 8, 0);

    // ── Payloads ──────────────────────────────────────────────────────────
    // GRPICONDIR at +0x500: reserved=0, type=1 (icon), count=1
    let gp = rsrc + 0x500;
    w16(&mut buf, gp, 0);
    w16(&mut buf, gp + 2, 1);
    w16(&mut buf, gp + 4, 1);
    // GRPICONDIRENTRY: width=32, height=32, colorCount=0, reserved=0,
    //   planes=1, bitCount=32, bytesInRes=40, nId=100
    let ge = gp + 6;
    buf[ge] = 32;
    buf[ge + 1] = 32;
    buf[ge + 2] = 0;
    buf[ge + 3] = 0;
    w16(&mut buf, ge + 4, 1);
    w16(&mut buf, ge + 6, 32);
    w32(&mut buf, ge + 8, 40);
    w16(&mut buf, ge + 12, 100);

    // Icon payload at +0x600: opaque 40 bytes.
    buf[rsrc + 0x600..rsrc + 0x600 + 4].copy_from_slice(b"ICO!");

    // GRPCURSORDIR at +0x700: reserved=0, type=2 (cursor), count=1
    let gcp = rsrc + 0x700;
    w16(&mut buf, gcp, 0);
    w16(&mut buf, gcp + 2, 2);
    w16(&mut buf, gcp + 4, 1);
    // GRPCURSORDIRENTRY (14 bytes; we read same offsets as icon):
    let gce = gcp + 6;
    buf[gce] = 32;
    buf[gce + 1] = 32;
    buf[gce + 2] = 0;
    buf[gce + 3] = 0;
    w16(&mut buf, gce + 4, 1);
    w16(&mut buf, gce + 6, 1);
    w32(&mut buf, gce + 8, 40);
    w16(&mut buf, gce + 12, 200);

    // Cursor payload at +0x800: opaque 40 bytes.
    buf[rsrc + 0x800..rsrc + 0x800 + 4].copy_from_slice(b"CUR!");

    // Bitmap payload at +0x900: BITMAPINFOHEADER (biSize=40, biWidth=16,
    // biHeight=16, biPlanes=1, biBitCount=32).
    let bp = rsrc + 0x900;
    w32(&mut buf, bp, 40); // biSize
    w32(&mut buf, bp + 4, 16); // biWidth
    w32(&mut buf, bp + 8, 16); // biHeight
    w16(&mut buf, bp + 12, 1); // biPlanes
    w16(&mut buf, bp + 14, 32); // biBitCount

    buf
}

#[test]
fn load_image_family_end_to_end() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;

    let hmodule = register_with_base("load_image_probe_gate_module.dll", base);
    assert!(hmodule != 0);

    // IMAGE_ICON via LoadIconW (integer resource 1).
    // SAFETY: ordinal path — no deref.
    let h_icon = unsafe { load_icon_w(hmodule, 1usize) };
    assert!(h_icon != 0, "LoadIconW returned 0");
    let e_icon = image_handles::get(h_icon).expect("HICON entry missing");
    assert_eq!(e_icon.kind, ImageKind::Icon);
    assert_eq!(e_icon.data_size, 40);

    // IMAGE_CURSOR via LoadCursorW (integer resource 1).
    // SAFETY: ordinal path.
    let h_cursor = unsafe { load_cursor_w(hmodule, 1usize) };
    assert!(h_cursor != 0, "LoadCursorW returned 0");
    let e_cursor = image_handles::get(h_cursor).expect("HCURSOR entry missing");
    assert_eq!(e_cursor.kind, ImageKind::Cursor);
    assert_eq!(e_cursor.data_size, 40);

    // IMAGE_BITMAP via LoadImageW (integer resource 1, no LR_SHARED).
    // SAFETY: ordinal path.
    let h_bitmap = unsafe {
        load_image_w(hmodule, 1usize, 0 /* IMAGE_BITMAP */, 0, 0, 0)
    };
    assert!(h_bitmap != 0, "LoadImageW(BITMAP) returned 0");
    let e_bitmap = image_handles::get(h_bitmap).expect("HBITMAP entry missing");
    assert_eq!(e_bitmap.kind, ImageKind::Bitmap);
    assert_eq!(e_bitmap.width, 16);
    assert_eq!(e_bitmap.height, 16);
    assert_eq!(e_bitmap.bpp, 32);

    // All three must be distinct.
    assert_ne!(h_icon, h_cursor);
    assert_ne!(h_icon, h_bitmap);
    assert_ne!(h_cursor, h_bitmap);

    // LR_SHARED dedup: second LoadIconW with the same (hInst, name) returns
    // the exact same handle, per Wine LR_SHARED semantics.
    // SAFETY: ordinal path.
    let h_icon_2 = unsafe { load_icon_w(hmodule, 1usize) };
    assert_eq!(h_icon, h_icon_2, "LR_SHARED dedup failed");
}

#[test]
fn load_image_missing_resource_returns_zero() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_image_probe_missing.dll", base);
    // Ordinal 9999 is not present in the fixture.
    // SAFETY: ordinal path.
    let h = unsafe { load_icon_w(hmodule, 9999usize) };
    assert_eq!(h, 0, "expected 0 for missing RT_GROUP_ICON/9999");
}
