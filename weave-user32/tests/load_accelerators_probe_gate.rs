//! Probe gate — end-to-end validation of `LoadAcceleratorsW` /
//! `LoadAcceleratorsA` against a synthetic PE carrying a real
//! RT_ACCELERATOR resource. Validates:
//!
//!   * present resource returns non-null, stable HACCEL,
//!   * HACCEL comes from the `accel_handles` slab (ACCEL_HANDLE_BASE range),
//!   * duplicate call with same `(hinst, name)` dedups to the same handle,
//!   * missing resource returns NULL,
//!   * NULL hInst returns NULL,
//!   * LoadAcceleratorsA IS_INTRESOURCE ordinal trampolines to W and
//!     returns the same handle.
//!
//! Per KNOWN-BUG-CLASSES "Scaffold lying — two-Vec rel32 truncation": the
//! synthetic PE fixture lives in a single contiguous `Vec<u8>`. No second
//! allocation, no split image.

use weave_core::module_handles::register_with_base;
use weave_user32::accel_handles::ACCEL_HANDLE_BASE;
use weave_user32::api::{load_accelerators_a, load_accelerators_w};

const HIGH_BIT: u32 = 0x8000_0000;

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Build a PE32+ image carrying RT_ACCELERATOR (ord 9) ordinal 1, neutral
/// lang, 24 bytes of opaque PE_ACCEL-shaped payload (three 8-byte entries,
/// not parsed by Weave).
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

    // ── Type directory: 1 id entry (RT_ACCELERATOR = 9) ──────────────────
    w16(&mut buf, rsrc + 12, 0); // named count
    w16(&mut buf, rsrc + 14, 1); // id count

    let name_dir_off: u32 = 0x40;
    w32(&mut buf, rsrc + 16, 9); // RT_ACCELERATOR
    w32(&mut buf, rsrc + 20, HIGH_BIT | name_dir_off);

    // ── Name directory: 1 id entry (ordinal 1) ───────────────────────────
    let name_dir = rsrc + name_dir_off as usize;
    w16(&mut buf, name_dir + 12, 0);
    w16(&mut buf, name_dir + 14, 1);
    let lang_dir_off: u32 = 0x80;
    w32(&mut buf, name_dir + 16, 1); // accel ordinal 1
    w32(&mut buf, name_dir + 20, HIGH_BIT | lang_dir_off);

    // ── Lang directory: one neutral (lang 0) leaf ────────────────────────
    let lang_dir = rsrc + lang_dir_off as usize;
    w16(&mut buf, lang_dir + 12, 0);
    w16(&mut buf, lang_dir + 14, 1);
    let data_entry_off: u32 = 0xC0;
    w32(&mut buf, lang_dir + 16, 0);
    w32(&mut buf, lang_dir + 20, data_entry_off);

    // ── Accel payload at +0x200 (opaque bytes — not parsed) ──────────────
    //    Three 8-byte PE_ACCEL-shaped entries = 24 bytes.
    let payload_off: u32 = 0x200;
    let payload_rva: u32 = rsrc_rva + payload_off;
    let payload_start = rsrc + payload_off as usize;
    for i in 0..24 {
        buf[payload_start + i] = 0;
    }
    let payload_size: u32 = 24;

    // ── IMAGE_RESOURCE_DATA_ENTRY at +0xC0 ───────────────────────────────
    let de = rsrc + data_entry_off as usize;
    w32(&mut buf, de, payload_rva);
    w32(&mut buf, de + 4, payload_size);
    w32(&mut buf, de + 8, 0);

    buf
}

/// MAKEINTRESOURCEW(n) — cast a small integer to an LPCWSTR for ordinal
/// resource lookups. Bare `as *const u16` preserves the integer value.
fn makeintresource_w(n: u16) -> *const u16 {
    n as usize as *const u16
}

#[test]
fn load_accelerators_w_present_returns_nonnull() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_accel_probe_present.dll", base);
    assert!(hmodule != 0);

    // SAFETY: ordinal path — no deref of the name pointer.
    let h = unsafe { load_accelerators_w(hmodule, makeintresource_w(1)) };
    assert!(h != 0, "LoadAcceleratorsW(MAKEINTRESOURCE(1)) expected non-null");
    assert!(
        h >= ACCEL_HANDLE_BASE,
        "HACCEL must come from the accel_handles slab"
    );
    // Slab range must not collide with neighbouring slabs.
    assert!(h < 0x5FFF_0001, "HACCEL must not overlap MENU_HANDLE_BASE");
}

#[test]
fn load_accelerators_w_duplicate_call_dedups() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_accel_probe_dedup.dll", base);

    // SAFETY: ordinal path.
    let h1 = unsafe { load_accelerators_w(hmodule, makeintresource_w(1)) };
    let h2 = unsafe { load_accelerators_w(hmodule, makeintresource_w(1)) };
    assert_ne!(h1, 0);
    assert_eq!(h1, h2, "duplicate LoadAcceleratorsW must return the same HACCEL");
}

#[test]
fn load_accelerators_w_missing_returns_null() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_accel_probe_missing.dll", base);

    // Ordinal 999 is not in the fixture.
    // SAFETY: ordinal path.
    let h = unsafe { load_accelerators_w(hmodule, makeintresource_w(999)) };
    assert_eq!(h, 0, "LoadAcceleratorsW on absent ordinal must return NULL");
}

#[test]
fn load_accelerators_w_null_hinstance_returns_null() {
    // SAFETY: ordinal path — no deref.
    let h = unsafe { load_accelerators_w(0, makeintresource_w(1)) };
    assert_eq!(h, 0);
}

#[test]
fn load_accelerators_a_ordinal_trampoline_matches_w() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_accel_probe_ansi.dll", base);

    // SAFETY: ordinal path — no deref.
    let h_w = unsafe { load_accelerators_w(hmodule, makeintresource_w(1)) };
    // IS_INTRESOURCE(1) is true, so load_accelerators_a must reinterpret
    // the argument as an ordinal and hit the same cache entry.
    // SAFETY: ordinal path.
    let h_a = unsafe { load_accelerators_a(hmodule, 1usize as *const u8) };
    assert_ne!(h_w, 0);
    assert_eq!(h_w, h_a, "LoadAcceleratorsA ordinal path must share the HACCEL from W");
}
