//! Task 11 probe gate — end-to-end validation of `LoadStringW` / `LoadStringA`
//! against a synthetic PE carrying a real RT_STRING bundle. Validates:
//!
//!   * normal copy path (cchBufferMax > 0) returns the correct WCHAR count
//!     and null-terminates the destination,
//!   * empty-slot (length==0) returns 0,
//!   * missing bundle (ID outside populated range) returns 0,
//!   * cchBufferMax == 0 pointer-return special case writes a pointer into
//!     the PE and returns the string's character count,
//!   * LoadStringA trampoline converts to CP_ACP.
//!
//! Per KNOWN-BUG-CLASSES "Scaffold lying — two-Vec rel32 truncation": the
//! synthetic PE fixture lives in a single contiguous `Vec<u8>`. No second
//! allocation, no split image.

use weave_core::module_handles::register_with_base;
use weave_user32::api::{load_string_a, load_string_w};

const HIGH_BIT: u32 = 0x8000_0000;

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Build a PE32+ image carrying RT_STRING bundle ordinal 1 (ids 0..15).
///
/// Populated slots in the bundle (by `id & 0x0F`):
///   slot 0 → "" (empty, u16 zero length)
///   slot 1 → "Hello"
///   slot 2 → "Weave"
///   slots 3..15 → empty (u16 zero)
///
/// RT_STRING layout: bundle payload is a flat sequence of `u16 length;
/// WCHAR[length]` entries — no headers, no null terminators.
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

    // ── Type directory: 1 id entry (RT_STRING = 6) ────────────────────────
    w16(&mut buf, rsrc + 12, 0); // named
    w16(&mut buf, rsrc + 14, 1); // id

    let name_dir_off: u32 = 0x40;
    w32(&mut buf, rsrc + 16, 6); // RT_STRING
    w32(&mut buf, rsrc + 20, HIGH_BIT | name_dir_off);

    // ── Name directory: 1 id entry (ordinal 1 = bundle for ids 0..15) ────
    let name_dir = rsrc + name_dir_off as usize;
    w16(&mut buf, name_dir + 12, 0);
    w16(&mut buf, name_dir + 14, 1);
    let lang_dir_off: u32 = 0x80;
    w32(&mut buf, name_dir + 16, 1); // bundle ordinal
    w32(&mut buf, name_dir + 20, HIGH_BIT | lang_dir_off);

    // ── Lang directory: one neutral (lang 0) leaf ────────────────────────
    let lang_dir = rsrc + lang_dir_off as usize;
    w16(&mut buf, lang_dir + 12, 0);
    w16(&mut buf, lang_dir + 14, 1);
    let data_entry_off: u32 = 0xC0;
    w32(&mut buf, lang_dir + 16, 0); // lang 0
    w32(&mut buf, lang_dir + 20, data_entry_off); // leaf

    // ── Bundle payload at +0x200 ─────────────────────────────────────────
    // Layout: 16 length-prefixed UTF-16 entries, in id-order.
    let payload_off: u32 = 0x200;
    let payload_rva: u32 = rsrc_rva + payload_off;
    let payload_start = rsrc + payload_off as usize;

    let entries: [&str; 16] = [
        "", "Hello", "Weave", "", "", "", "", "", "", "", "", "", "", "", "", "",
    ];
    let mut cursor = payload_start;
    for s in entries.iter() {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        w16(&mut buf, cursor, utf16.len() as u16);
        cursor += 2;
        for ch in &utf16 {
            w16(&mut buf, cursor, *ch);
            cursor += 2;
        }
    }
    let payload_size = (cursor - payload_start) as u32;

    // ── IMAGE_RESOURCE_DATA_ENTRY at +0xC0 ───────────────────────────────
    let de = rsrc + data_entry_off as usize;
    w32(&mut buf, de, payload_rva);
    w32(&mut buf, de + 4, payload_size);
    w32(&mut buf, de + 8, 0); // codepage

    buf
}

#[test]
fn load_string_w_normal_copy() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_string_probe_normal.dll", base);
    assert!(hmodule != 0);

    let mut out = [0u16; 64];

    // ID 1 → "Hello"
    // SAFETY: buffer is writable for 64 WCHARs.
    let n = unsafe { load_string_w(hmodule, 1, out.as_mut_ptr(), 64) };
    assert_eq!(n, 5, "LoadStringW(id=1) expected 5 chars");
    let got: String = String::from_utf16_lossy(&out[..n as usize]);
    assert_eq!(got, "Hello");
    assert_eq!(out[n as usize], 0, "null terminator missing");

    // ID 2 → "Weave"
    let mut out2 = [0u16; 64];
    // SAFETY: as above.
    let n = unsafe { load_string_w(hmodule, 2, out2.as_mut_ptr(), 64) };
    assert_eq!(n, 5);
    assert_eq!(String::from_utf16_lossy(&out2[..n as usize]), "Weave");
    assert_eq!(out2[n as usize], 0);
}

#[test]
fn load_string_w_empty_slot_returns_zero() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_string_probe_empty.dll", base);

    let mut out = [0xAAu16; 64];
    // Slot 0 is an empty string in our fixture.
    // SAFETY: buffer is writable.
    let n = unsafe { load_string_w(hmodule, 0, out.as_mut_ptr(), 64) };
    assert_eq!(n, 0, "LoadStringW(id=0) expected 0 for empty slot");
    assert_eq!(out[0], 0, "empty-slot failure must null-terminate buffer");
}

#[test]
fn load_string_w_missing_returns_zero() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_string_probe_missing.dll", base);

    let mut out = [0xAAu16; 64];
    // ID 999 → bundle ordinal (999>>4)+1 = 63, which isn't in the fixture.
    // SAFETY: buffer is writable.
    let n = unsafe { load_string_w(hmodule, 999, out.as_mut_ptr(), 64) };
    assert_eq!(n, 0, "LoadStringW(id=999) expected 0 for missing bundle");
    assert_eq!(out[0], 0);
}

#[test]
fn load_string_w_pointer_return_mode() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_string_probe_ptr.dll", base);

    // cchBufferMax == 0: lp_buffer is LPWSTR*. Write a *const u16 into it
    // and return character count.
    let mut ptr_out: *const u16 = core::ptr::null();
    let slot: *mut *const u16 = &mut ptr_out;
    // SAFETY: slot is writable for one pointer; LoadStringW treats it as LPWSTR*.
    let n = unsafe { load_string_w(hmodule, 1, slot as *mut u16, 0) };
    assert_eq!(n, 5, "pointer-return mode should return char count");
    assert!(!ptr_out.is_null());

    // SAFETY: ptr_out points into the PE fixture, readable for n WCHARs.
    let chars = unsafe { core::slice::from_raw_parts(ptr_out, n as usize) };
    let got = String::from_utf16_lossy(chars);
    assert_eq!(got, "Hello");
}

#[test]
fn load_string_w_null_hinstance_returns_zero() {
    let mut out = [0xAAu16; 32];
    // SAFETY: buffer is writable.
    let n = unsafe { load_string_w(0, 1, out.as_mut_ptr(), 32) };
    assert_eq!(n, 0);
    assert_eq!(out[0], 0);
}

#[test]
fn load_string_a_trampoline() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_string_probe_ansi.dll", base);

    let mut out = [0u8; 64];
    // SAFETY: buffer is writable for 64 bytes.
    let n = unsafe { load_string_a(hmodule, 1, out.as_mut_ptr(), 64) };
    assert_eq!(n, 5, "LoadStringA(id=1) expected 5 bytes");
    assert_eq!(&out[..5], b"Hello");
    assert_eq!(out[5], 0, "null terminator missing");
}

#[test]
fn load_string_a_zero_buflen_returns_minus_one() {
    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_string_probe_ansi_zero.dll", base);

    // Wine: `if (!buflen) return -1;` — LoadStringA does not support the
    // pointer-return mode that LoadStringW exposes.
    // SAFETY: n_buffer_max==0 path does not deref lp_buffer.
    let n = unsafe { load_string_a(hmodule, 1, core::ptr::null_mut(), 0) };
    assert_eq!(n, -1);
}

/// Verify that `load_string_w` behaves correctly when `WEAVE_RESOURCE_TRACE=1`
/// is set. The restrace! macro must not alter return values or corrupt output.
///
/// Note: the OnceLock in `weave_core::resource_trace::enabled()` caches the
/// env-var state on first call. In a test binary, this test may run after
/// `enabled_matches_env` has already initialized the lock to `false`. The
/// behavior-under-trace path is validated here; the env-gate itself is
/// covered by `weave_core::resource_trace::tests::enabled_matches_env`.
///
/// To observe actual restrace output: run with `WEAVE_RESOURCE_TRACE=1`.
#[test]
fn load_string_w_with_trace_env_returns_correct_values() {
    // Set env before any call in this binary initializes the OnceLock.
    // SAFETY: single-threaded test environment.
    unsafe { std::env::set_var("WEAVE_RESOURCE_TRACE", "1") };

    let buf = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("load_string_probe_trace.dll", base);
    assert!(hmodule != 0);

    let mut out = [0u16; 64];

    // Behavior must be identical regardless of trace state.
    // SAFETY: buffer is writable for 64 WCHARs.
    let n = unsafe { load_string_w(hmodule, 1, out.as_mut_ptr(), 64) };
    assert_eq!(n, 5, "LoadStringW(id=1) must return 5 with trace enabled");
    let got = String::from_utf16_lossy(&out[..n as usize]);
    assert_eq!(got, "Hello");
    assert_eq!(out[n as usize], 0, "null terminator must be present");

    // ID 2 → "Weave"
    let mut out2 = [0u16; 64];
    // SAFETY: as above.
    let n2 = unsafe { load_string_w(hmodule, 2, out2.as_mut_ptr(), 64) };
    assert_eq!(n2, 5);
    assert_eq!(String::from_utf16_lossy(&out2[..n2 as usize]), "Weave");
}
