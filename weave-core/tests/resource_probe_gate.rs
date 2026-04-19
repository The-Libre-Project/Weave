//! Task 09 resource-family probe gate.
//!
//! End-to-end validation of the FindResource -> LoadResource -> SizeofResource
//! chain that `weave-kernel32` exposes to guest binaries. The kernel32 FFI
//! exports are a thin translation layer over two weave-core primitives:
//!
//!   * `weave_core::module_handles::{register_with_base, base_of}`
//!   * `weave_core::resource::{find_resource_entry, resource_entry_size,
//!                             resource_entry_data}`
//!
//! We validate the chain through the core API rather than by invoking the
//! `extern "win64"` exports directly — the calling-convention hop is covered
//! by the PE loader tests, and a pure-Rust probe keeps the gate portable to
//! macOS where `cargo test -p weave-core` runs natively.
//!
//! Per KNOWN-BUG-CLASSES ("Scaffold lying — two-Vec rel32 truncation
//! segfault"): the synthetic PE fixture is built in a single contiguous
//! `Vec<u8>`. No second allocation, no split image.

use weave_core::module_handles::{base_of, register_with_base};
use weave_core::resource::{
    find_resource_entry, resource_entry_data, resource_entry_size, ResourceId,
};

const HIGH_BIT: u32 = 0x8000_0000;

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Build a minimal PE32+ image with a single `RT_VERSION` (16) resource
/// keyed by ordinal 1, language-neutral. Everything lives in one Vec.
///
/// Resource layout inside .rsrc (single contiguous buffer):
///   0x000  Type directory       (1 id entry: RT_VERSION=16 -> 0x040)
///   0x040  Name directory       (1 id entry: ordinal 1 -> 0x080)
///   0x080  Lang directory       (1 id entry: lang=0 -> 0x100)
///   0x100  IMAGE_RESOURCE_DATA_ENTRY (OffsetToData=rsrc_rva+0x200, Size=payload.len())
///   0x200  payload bytes
fn build_image() -> (Vec<u8>, u32 /*rsrc_rva*/) {
    const SECTION_ALIGN: usize = 0x1000;
    let payload: &[u8] = b"VS_VERSION_INFO-probe-payload";
    let mut buf = vec![0u8; SECTION_ALIGN * 4];

    // ---------------- PE headers ----------------
    w16(&mut buf, 0, 0x5A4D); // MZ
    w32(&mut buf, 0x3c, 0x80); // e_lfanew -> PE header at 0x80

    let pe_off = 0x80usize;
    w32(&mut buf, pe_off, 0x0000_4550); // "PE\0\0"

    let fh_off = pe_off + 4;
    w16(&mut buf, fh_off, 0x8664); // Machine = amd64
    w16(&mut buf, fh_off + 2, 1); // NumberOfSections
    w16(&mut buf, fh_off + 16, 0xF0); // SizeOfOptionalHeader (PE32+)

    let opt_off = fh_off + 20;
    w16(&mut buf, opt_off, 0x20b); // PE32+ magic

    let rsrc_rva: u32 = 0x1000;
    let rsrc_size: u32 = (SECTION_ALIGN * 2) as u32;
    let dd_off = opt_off + 0x70;
    w32(&mut buf, dd_off + 2 * 8, rsrc_rva);
    w32(&mut buf, dd_off + 2 * 8 + 4, rsrc_size);

    // ---------------- .rsrc ----------------
    let rsrc = rsrc_rva as usize;

    // Type directory: one id entry, RT_VERSION = 16
    let type_dir = rsrc;
    w16(&mut buf, type_dir + 12, 0); // NumberOfNamedEntries
    w16(&mut buf, type_dir + 14, 1); // NumberOfIdEntries
    let name_dir_off: u32 = 0x40;
    w32(&mut buf, type_dir + 16, 16); // RT_VERSION
    w32(&mut buf, type_dir + 16 + 4, HIGH_BIT | name_dir_off);

    // Name directory: one id entry, ordinal 1
    let name_dir = rsrc + name_dir_off as usize;
    w16(&mut buf, name_dir + 12, 0);
    w16(&mut buf, name_dir + 14, 1);
    let lang_dir_off: u32 = 0x80;
    w32(&mut buf, name_dir + 16, 1);
    w32(&mut buf, name_dir + 16 + 4, HIGH_BIT | lang_dir_off);

    // Lang directory: one id entry, lang=0 (neutral)
    let lang_dir = rsrc + lang_dir_off as usize;
    w16(&mut buf, lang_dir + 12, 0);
    w16(&mut buf, lang_dir + 14, 1);
    let data_entry_off: u32 = 0x100;
    w32(&mut buf, lang_dir + 16, 0);
    w32(&mut buf, lang_dir + 16 + 4, data_entry_off); // leaf: high bit clear

    // IMAGE_RESOURCE_DATA_ENTRY at rsrc+0x100.
    let data_entry_abs = rsrc + data_entry_off as usize;
    let payload_rva = rsrc_rva + 0x200;
    w32(&mut buf, data_entry_abs, payload_rva); // OffsetToData
    w32(&mut buf, data_entry_abs + 4, payload.len() as u32); // Size
    w32(&mut buf, data_entry_abs + 8, 0); // CodePage
    w32(&mut buf, data_entry_abs + 12, 0); // Reserved

    // Payload bytes
    let payload_abs = rsrc + 0x200;
    buf[payload_abs..payload_abs + payload.len()].copy_from_slice(payload);

    (buf, rsrc_rva)
}

#[test]
fn find_load_size_chain_via_core_api() {
    let (buf, rsrc_rva) = build_image();
    let base = buf.as_ptr() as usize;

    // Step 1: register the synthetic PE's base under a unique module name.
    // kernel32's FindResource* translation layer looks this up via base_of.
    let module_name = "resource_probe_gate_module.dll";
    let hmodule = register_with_base(module_name, base);
    assert!(hmodule != 0);
    assert_eq!(base_of(hmodule), Some(base));

    // Step 2: FindResource(RT_VERSION, 1) — what kernel32::find_resource_w does.
    let resolved_base = base_of(hmodule).expect("registered base must resolve");
    let hrsrc = find_resource_entry(
        resolved_base,
        ResourceId::Id(16), // RT_VERSION
        ResourceId::Id(1),
        0, // MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)
    )
    .expect("probe: FindResource should locate RT_VERSION/1/neutral");

    // HRSRC = address of IMAGE_RESOURCE_DATA_ENTRY (Wine identity scheme).
    assert_eq!(hrsrc, base + rsrc_rva as usize + 0x100);

    // Step 3: SizeofResource — reads `Size` field from the HRSRC.
    // SAFETY: hrsrc points into `buf` at a valid IMAGE_RESOURCE_DATA_ENTRY.
    let size = unsafe { resource_entry_size(hrsrc) };
    assert_eq!(size, b"VS_VERSION_INFO-probe-payload".len() as u32);

    // Step 4: LoadResource — returns image_base + OffsetToData.
    // SAFETY: same as above.
    let hglobal = unsafe { resource_entry_data(resolved_base, hrsrc) };
    assert_eq!(hglobal, base + rsrc_rva as usize + 0x200);

    // Step 5: dereference the HGLOBAL and confirm the payload bytes.
    // SAFETY: hglobal lies within `buf` at the payload we wrote.
    let payload = unsafe { std::slice::from_raw_parts(hglobal as *const u8, size as usize) };
    assert_eq!(payload, b"VS_VERSION_INFO-probe-payload");
}

#[test]
fn unregistered_module_returns_none() {
    // Kernel32's FindResource* returns 0 + ERROR_RESOURCE_NAME_NOT_FOUND
    // when base_of fails. Validate the base_of side of that contract.
    let bogus_handle: usize = 0x1234_5678;
    assert!(base_of(bogus_handle).is_none());
}

#[test]
fn missing_resource_returns_none() {
    let (buf, _) = build_image();
    let base = buf.as_ptr() as usize;
    let hmodule = register_with_base("resource_probe_missing.dll", base);
    let resolved = base_of(hmodule).unwrap();

    // Request a resource that does not exist in the synthetic image.
    let hrsrc = find_resource_entry(resolved, ResourceId::Id(16), ResourceId::Id(9999), 0);
    assert!(hrsrc.is_none());
}
