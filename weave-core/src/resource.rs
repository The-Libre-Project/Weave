//! PE `.rsrc` directory walker.
//!
//! Mirrors Wine's `LdrFindResource_U` / `find_entry` (dlls/ntdll/resource.c):
//! three-level walk Type -> Name -> Language over
//! `IMAGE_RESOURCE_DIRECTORY` nodes, with named entries sorted first and
//! ID entries after. Language level uses the fallback order:
//! exact lang -> LANG_NEUTRAL (0) -> first available.
//!
//! Wine ref: dlls/ntdll/resource.c — `find_entry`, `find_entry_by_name`,
//! `find_entry_by_id`, `find_first_entry`. `IS_INTRESOURCE(x)` is
//! `(((ULONG_PTR)(x)) >> 16) == 0`; Weave's [`ResourceId`] encodes that
//! distinction as a Rust enum rather than smuggling ordinals through a
//! pointer's low bits.
//!
//! Named-vs-id ordering (quoted verbatim from Wine, `find_entry_by_name`):
//!   `entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);`
//!   `min = 0;`
//!   `max = dir->NumberOfNamedEntries - 1;`
//! and `find_entry_by_id`:
//!   `min = dir->NumberOfNamedEntries;`
//!   `max = min + dir->NumberOfIdEntries - 1;`
//! so named entries occupy `[0 .. NumberOfNamedEntries)` and id entries
//! occupy `[NumberOfNamedEntries .. +NumberOfIdEntries)`, both sorted.
//!
//! This module is intentionally a pure function over a memory image — it
//! has no callers yet. Task 09 step 3/4 wires `weave-kernel32::FindResourceW`
//! through here.

// IMAGE_RESOURCE_DIRECTORY layout (Win32):
//   DWORD Characteristics
//   DWORD TimeDateStamp
//   WORD  MajorVersion
//   WORD  MinorVersion
//   WORD  NumberOfNamedEntries
//   WORD  NumberOfIdEntries
// Size: 16 bytes.
const RESDIR_SIZE: usize = 16;

// IMAGE_RESOURCE_DIRECTORY_ENTRY layout:
//   DWORD Name / Id       (high bit of the DWORD set => name entry, low 31 bits = NameOffset)
//   DWORD OffsetToData    (high bit set => points to another directory, low 31 bits = offset)
// Size: 8 bytes.
const RESDIR_ENTRY_SIZE: usize = 8;
const HIGH_BIT: u32 = 0x8000_0000;

// IMAGE_RESOURCE_DATA_ENTRY layout:
//   DWORD OffsetToData
//   DWORD Size
//   DWORD CodePage
//   DWORD Reserved
const RESDATA_ENTRY_SIZE: usize = 16;

/// A resource type/name identifier.
///
/// Wine's `IS_INTRESOURCE(x)` macro distinguishes a 16-bit ordinal (`Id`)
/// from a UTF-16 string pointer (`Name`). We encode the same distinction
/// explicitly so callers never risk treating a small integer as a pointer.
#[derive(Debug, Clone)]
pub enum ResourceId {
    /// A numeric ordinal (e.g. `RT_VERSION = 16`, `MAKEINTRESOURCE(1)`).
    Id(u16),
    /// A UTF-16 resource name (no terminator; matched by length + codepoints).
    Name(Vec<u16>),
}

/// Location of a resource's bytes within the loaded PE image.
///
/// `data_rva` is the RVA of the first byte of the resource blob. `size` is
/// `IMAGE_RESOURCE_DATA_ENTRY.Size`. `codepage` is the per-resource code page
/// declared in the leaf entry (0 = default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLocator {
    pub data_rva: u32,
    pub size: u32,
    pub codepage: u32,
}

/// Walk the `.rsrc` directory of a loaded PE image.
///
/// `image_base` is the loaded base address of the PE image in this process.
/// Returns `None` if the image has no resource directory, or if the requested
/// (type, name, lang) triple is not present.
///
/// Language fallback matches Wine's order: exact `lang` -> `LANG_NEUTRAL` (0)
/// -> first available. Weave skips Wine's system/thread locale fallbacks
/// (steps 4-9 of `find_entry`) because Weave does not model guest locales.
///
/// # Safety
///
/// This function reads raw PE memory starting at `image_base`. The caller
/// must ensure:
///   * `image_base` points to a valid, fully mapped PE image,
///   * the entire image (headers + resource section) is readable,
///   * the resource directory RVAs stay within the mapped image.
///
/// Malformed directory offsets are rejected by bounds-checking against the
/// section containing the resource directory; we never read outside the
/// resource section's RVA span.
pub fn find_resource(
    image_base: usize,
    type_: ResourceId,
    name: ResourceId,
    lang: u16,
) -> Option<ResourceLocator> {
    // SAFETY: caller contract above.
    let image = unsafe { ImageView::from_base(image_base)? };
    let root = image.resource_root()?;

    // Level 1: Type
    let type_dir_off = find_entry(root, &image, &type_, /*want_dir=*/ true)?;
    let type_dir = image.dir_at(type_dir_off)?;

    // Level 2: Name
    let name_dir_off = find_entry(type_dir, &image, &name, /*want_dir=*/ true)?;
    let name_dir = image.dir_at(name_dir_off)?;

    // Level 3: Language (leaf). Wine order: exact -> neutral -> first.
    let leaf_off = find_lang_entry(name_dir, &image, lang)?;
    image.data_entry_at(leaf_off)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// A view over a loaded PE image limited to the `.rsrc` section span.
///
/// Holds `image_base` plus the [rsrc_rva, rsrc_rva + rsrc_size) window so
/// every directory-offset read can be bounds-checked against the section
/// rather than the (possibly enormous) full image.
struct ImageView {
    image_base: usize,
    rsrc_rva: u32,
    rsrc_size: u32,
}

impl ImageView {
    /// # Safety
    /// Caller guarantees `image_base` is a valid mapped PE image.
    unsafe fn from_base(image_base: usize) -> Option<Self> {
        // DOS header: 'MZ' at 0, e_lfanew at 0x3c.
        let mz = read_u16_at(image_base, 0)?;
        if mz != 0x5A4D {
            return None;
        }
        let e_lfanew = read_u32_at(image_base, 0x3c)? as usize;

        // NT headers: 'PE\0\0' signature.
        let sig = read_u32_at(image_base, e_lfanew)?;
        if sig != 0x0000_4550 {
            return None;
        }

        // FileHeader starts at e_lfanew + 4.
        //   WORD Machine, WORD NumberOfSections, DWORD TimeDateStamp,
        //   DWORD PointerToSymbolTable, DWORD NumberOfSymbols,
        //   WORD SizeOfOptionalHeader, WORD Characteristics.
        // FileHeader size = 20 bytes -> OptionalHeader at e_lfanew + 24.
        let file_header_off = e_lfanew + 4;
        let machine = read_u16_at(image_base, file_header_off)?;
        let num_sections = read_u16_at(image_base, file_header_off + 2)? as usize;
        let size_of_opt = read_u16_at(image_base, file_header_off + 16)? as usize;
        let opt_off = file_header_off + 20;

        // Magic at start of OptionalHeader: 0x10b = PE32, 0x20b = PE32+.
        let magic = read_u16_at(image_base, opt_off)?;
        let is_pe32_plus = match magic {
            0x10b => false,
            0x20b => true,
            _ => return None,
        };
        let _ = machine; // currently unused; kept for future i386/amd64 routing.

        // DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] = index 2.
        // DataDirectory base offset from start of OptionalHeader:
        //   PE32:  0x60
        //   PE32+: 0x70
        // Each entry is 8 bytes (RVA, Size); index 2 adds 2*8 = 0x10.
        let dd_base = if is_pe32_plus { 0x70 } else { 0x60 };
        let data_dir_off = dd_base + 2 * 8;
        if data_dir_off + 8 > size_of_opt {
            return None;
        }
        let rsrc_rva = read_u32_at(image_base, opt_off + data_dir_off)?;
        let rsrc_size = read_u32_at(image_base, opt_off + data_dir_off + 4)?;
        if rsrc_rva == 0 || rsrc_size < RESDIR_SIZE as u32 {
            return None;
        }

        // Sanity-check: the resource section must be covered by a section
        // header (and since we read via `image_base + RVA`, the PE must be
        // memory-mapped such that RVA == VA offset). We don't translate
        // RVA -> file offset here — we assume the caller handed us a
        // loader-mapped image, same as Wine's `RtlImageDirectoryEntryToData`
        // does on the live module base.
        let _ = num_sections;

        Some(ImageView {
            image_base,
            rsrc_rva,
            rsrc_size,
        })
    }

    /// Return the root resource directory, if any.
    fn resource_root(&self) -> Option<&'static [u8]> {
        self.rsrc_slice(0, RESDIR_SIZE)
    }

    /// A `dir_offset` from an `IMAGE_RESOURCE_DIRECTORY_ENTRY` is **relative
    /// to the start of the resource section** (Wine: `(char*)root + off`).
    fn dir_at(&self, off: u32) -> Option<&'static [u8]> {
        self.rsrc_slice(off as usize, RESDIR_SIZE)
    }

    /// Read an `IMAGE_RESOURCE_DATA_ENTRY` at `off` (offset from resource root).
    fn data_entry_at(&self, off: u32) -> Option<ResourceLocator> {
        let slice = self.rsrc_slice(off as usize, RESDATA_ENTRY_SIZE)?;
        let data_rva = u32::from_le_bytes(slice[0..4].try_into().ok()?);
        let size = u32::from_le_bytes(slice[4..8].try_into().ok()?);
        let codepage = u32::from_le_bytes(slice[8..12].try_into().ok()?);
        Some(ResourceLocator {
            data_rva,
            size,
            codepage,
        })
    }

    /// Slice of `len` bytes starting at `off` bytes into the resource section.
    /// Bounds-checked against the section size declared in the data directory.
    fn rsrc_slice(&self, off: usize, len: usize) -> Option<&'static [u8]> {
        let end = off.checked_add(len)?;
        if end > self.rsrc_size as usize {
            return None;
        }
        let ptr = self
            .image_base
            .checked_add(self.rsrc_rva as usize)?
            .checked_add(off)?;
        // SAFETY: image_base + rsrc_rva is within the caller-provided mapped
        // image; `end <= rsrc_size` keeps us inside the resource section.
        Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, len) })
    }

    /// Slice an arbitrary `len` starting at `off` bytes into the resource
    /// section — used for reading `IMAGE_RESOURCE_DIR_STRING_U` names whose
    /// length is known only after reading the first 2 bytes.
    fn rsrc_slice_dyn(&self, off: usize, len: usize) -> Option<&'static [u8]> {
        self.rsrc_slice(off, len)
    }
}

/// Match one resource-directory node against a [`ResourceId`] and return the
/// matched child's `OffsetToDirectory` (or `OffsetToData` for a leaf).
fn find_entry(dir: &[u8], image: &ImageView, id: &ResourceId, want_dir: bool) -> Option<u32> {
    let (num_named, num_id) = dir_counts(dir)?;
    let dir_base_off = dir_offset_in_rsrc(image, dir)?;

    // entries[] follows the directory header immediately.
    let entries_start = dir_base_off + RESDIR_SIZE;

    match id {
        ResourceId::Id(want) => {
            // Wine `find_entry_by_id`: linear search over the id range.
            // Named entries occupy [0, num_named); id entries occupy
            // [num_named, num_named + num_id). The Wine binary-search assumes
            // ids are sorted; we don't require that here (linker output is
            // sorted, but our tests don't need to bake that invariant in —
            // a linear scan over the id range matches the same entries).
            for i in num_named..(num_named + num_id) {
                let entry_off = entries_start + i * RESDIR_ENTRY_SIZE;
                let entry = image.rsrc_slice_dyn(entry_off, RESDIR_ENTRY_SIZE)?;
                let name_or_id = u32::from_le_bytes(entry[0..4].try_into().ok()?);
                let offset_to_data = u32::from_le_bytes(entry[4..8].try_into().ok()?);
                if (name_or_id & HIGH_BIT) != 0 {
                    continue; // string-named entry; Id() cannot match
                }
                let entry_id = (name_or_id & 0xFFFF) as u16;
                if entry_id != *want {
                    continue;
                }
                let is_dir = (offset_to_data & HIGH_BIT) != 0;
                if is_dir != want_dir {
                    return None;
                }
                return Some(offset_to_data & !HIGH_BIT);
            }
            None
        }
        ResourceId::Name(want) => {
            // Wine `find_entry_by_name`: compare against
            // IMAGE_RESOURCE_DIR_STRING_U { WORD Length; WCHAR NameString[Length]; }
            for i in 0..num_named {
                let entry_off = entries_start + i * RESDIR_ENTRY_SIZE;
                let entry = image.rsrc_slice_dyn(entry_off, RESDIR_ENTRY_SIZE)?;
                let name_or_id = u32::from_le_bytes(entry[0..4].try_into().ok()?);
                let offset_to_data = u32::from_le_bytes(entry[4..8].try_into().ok()?);
                if (name_or_id & HIGH_BIT) == 0 {
                    continue; // id entry, skip (shouldn't happen in named range)
                }
                let name_off = (name_or_id & !HIGH_BIT) as usize;
                let hdr = image.rsrc_slice_dyn(name_off, 2)?;
                let nlen = u16::from_le_bytes(hdr[0..2].try_into().ok()?) as usize;
                let chars = image.rsrc_slice_dyn(name_off + 2, nlen * 2)?;
                if nlen != want.len() {
                    continue;
                }
                let mut ok = true;
                for (j, w) in want.iter().enumerate() {
                    let ch = u16::from_le_bytes(chars[j * 2..j * 2 + 2].try_into().ok()?);
                    if ch != *w {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    continue;
                }
                let is_dir = (offset_to_data & HIGH_BIT) != 0;
                if is_dir != want_dir {
                    return None;
                }
                return Some(offset_to_data & !HIGH_BIT);
            }
            None
        }
    }
}

/// Language level: Wine order is exact -> LANG_NEUTRAL -> first available.
/// Returns the leaf `OffsetToData` for an `IMAGE_RESOURCE_DATA_ENTRY`.
fn find_lang_entry(dir: &[u8], image: &ImageView, lang: u16) -> Option<u32> {
    // 1. exact language
    if let Some(off) = find_entry(dir, image, &ResourceId::Id(lang), false) {
        return Some(off);
    }
    // 2. LANG_NEUTRAL (only if different from the requested lang)
    if lang != 0 {
        if let Some(off) = find_entry(dir, image, &ResourceId::Id(0), false) {
            return Some(off);
        }
    }
    // 3. first available non-directory entry (mirrors Wine's find_first_entry
    //    call when PRIMARYLANGID(info->Language) == LANG_NEUTRAL; we apply it
    //    unconditionally as a last-resort — weave doesn't model locales).
    let (num_named, num_id) = dir_counts(dir)?;
    let dir_base_off = dir_offset_in_rsrc(image, dir)?;
    let entries_start = dir_base_off + RESDIR_SIZE;
    for i in 0..(num_named + num_id) {
        let entry_off = entries_start + i * RESDIR_ENTRY_SIZE;
        let entry = image.rsrc_slice_dyn(entry_off, RESDIR_ENTRY_SIZE)?;
        let offset_to_data = u32::from_le_bytes(entry[4..8].try_into().ok()?);
        if (offset_to_data & HIGH_BIT) == 0 {
            return Some(offset_to_data & !HIGH_BIT);
        }
    }
    None
}

fn dir_counts(dir: &[u8]) -> Option<(usize, usize)> {
    if dir.len() < RESDIR_SIZE {
        return None;
    }
    let named = u16::from_le_bytes(dir[12..14].try_into().ok()?) as usize;
    let id = u16::from_le_bytes(dir[14..16].try_into().ok()?) as usize;
    Some((named, id))
}

/// Offset (in bytes, from the start of the resource section) of a directory
/// slice we were previously handed. Recovers the offset by pointer arithmetic.
fn dir_offset_in_rsrc(image: &ImageView, dir: &[u8]) -> Option<usize> {
    let dir_ptr = dir.as_ptr() as usize;
    let rsrc_start = image.image_base.checked_add(image.rsrc_rva as usize)?;
    dir_ptr.checked_sub(rsrc_start)
}

// ---------------------------------------------------------------------------
// Unsafe primitives
// ---------------------------------------------------------------------------

unsafe fn read_u16_at(base: usize, off: usize) -> Option<u16> {
    let ptr = base.checked_add(off)? as *const u8;
    // SAFETY: caller contract on `from_base` covers this; off is always a
    // small header constant.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, 2) };
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

unsafe fn read_u32_at(base: usize, off: usize) -> Option<u32> {
    let ptr = base.checked_add(off)? as *const u8;
    // SAFETY: caller contract on `from_base` covers this; off is always a
    // small header constant.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, 4) };
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

// ---------------------------------------------------------------------------
// Tests — synthetic PE image built in ONE contiguous Vec<u8>.
// Per KNOWN-BUG-CLASSES "two-Vec rel32 truncation": do NOT split the image
// across multiple heap allocations. Everything lives in `buf` below.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a little-endian u16/u32 at a byte offset.
    fn w16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Build a minimal synthetic PE32+ image with a `.rsrc` section that
    /// contains:
    ///   Type RT_STRING (6):
    ///     Name by ID 42:
    ///       Lang 0x0409 -> data blob "ENGLISH"
    ///       Lang 0      -> data blob "NEUTRAL"
    ///     Name "HELLO" (UTF-16):
    ///       Lang 0x0409 -> data blob "NAMED-EN"
    ///
    /// Layout is a single Vec<u8>, RVA == file offset.
    fn build_image() -> (Vec<u8>, u32 /*rsrc_rva*/) {
        const SECTION_ALIGN: usize = 0x1000;
        let mut buf = vec![0u8; SECTION_ALIGN * 4]; // headers + .rsrc (1 page each padded)

        // DOS header: MZ + e_lfanew at 0x3c pointing to PE header at 0x80.
        w16(&mut buf, 0, 0x5A4D); // MZ
        w32(&mut buf, 0x3c, 0x80);

        // PE header at 0x80.
        let pe_off = 0x80usize;
        w32(&mut buf, pe_off, 0x0000_4550); // "PE\0\0"

        // FileHeader at pe_off + 4.
        let fh_off = pe_off + 4;
        w16(&mut buf, fh_off + 0, 0x8664); // Machine = amd64
        w16(&mut buf, fh_off + 2, 1); // NumberOfSections = 1
        w16(&mut buf, fh_off + 16, 0xF0); // SizeOfOptionalHeader (PE32+ = 240)
                                          // Characteristics left as 0 — not inspected by the walker.

        // OptionalHeader at fh_off + 20. PE32+ magic.
        let opt_off = fh_off + 20;
        w16(&mut buf, opt_off, 0x20b); // PE32+ magic
                                       // Most fields not read by the walker; we only fill DataDirectory[2]
                                       // (Resource). DataDirectory for PE32+ starts at opt_off + 0x70.
                                       // We build the .rsrc at file/RVA offset 0x1000, size = one page.
        let rsrc_rva: u32 = 0x1000;
        let rsrc_size: u32 = (SECTION_ALIGN * 2) as u32;
        let dd_off = opt_off + 0x70;
        w32(&mut buf, dd_off + 2 * 8, rsrc_rva);
        w32(&mut buf, dd_off + 2 * 8 + 4, rsrc_size);

        // -------------------- .rsrc section (RVA == file off 0x1000) -------
        // Type directory at offset 0:
        //   1 named? 0    1 id? 1 (RT_STRING=6)
        let rsrc = rsrc_rva as usize;

        // Type directory: 1 id entry (RT_STRING=6)
        let type_dir = rsrc;
        w16(&mut buf, type_dir + 12, 0); // NumberOfNamedEntries
        w16(&mut buf, type_dir + 14, 1); // NumberOfIdEntries
                                         // Entry #0: Id=6, OffsetToDirectory -> Name-level dir
        let name_dir_off: u32 = 0x40; // offset from rsrc base
        w32(&mut buf, type_dir + 16, 6);
        w32(&mut buf, type_dir + 16 + 4, HIGH_BIT | name_dir_off);

        // Name directory at offset 0x40:
        //   1 named ("HELLO"), 1 id (42)
        let name_dir = rsrc + name_dir_off as usize;
        w16(&mut buf, name_dir + 12, 1); // NumberOfNamedEntries
        w16(&mut buf, name_dir + 14, 1); // NumberOfIdEntries

        // Named entry "HELLO" -> lang dir at 0x100
        let hello_name_str_off: u32 = 0x200; // where IMAGE_RESOURCE_DIR_STRING_U lives
        let named_lang_dir_off: u32 = 0x100;
        w32(&mut buf, name_dir + 16, HIGH_BIT | hello_name_str_off);
        w32(&mut buf, name_dir + 16 + 4, HIGH_BIT | named_lang_dir_off);

        // Id entry 42 -> lang dir at 0x180
        let id_lang_dir_off: u32 = 0x180;
        w32(&mut buf, name_dir + 16 + 8, 42);
        w32(&mut buf, name_dir + 16 + 12, HIGH_BIT | id_lang_dir_off);

        // Named lang dir (for HELLO) at 0x100: one id entry, lang=0x0409
        let named_lang_dir = rsrc + named_lang_dir_off as usize;
        w16(&mut buf, named_lang_dir + 12, 0);
        w16(&mut buf, named_lang_dir + 14, 1);
        // Entry: Id=0x0409 -> data entry at 0x300
        let named_data_off: u32 = 0x300;
        w32(&mut buf, named_lang_dir + 16, 0x0409);
        w32(&mut buf, named_lang_dir + 16 + 4, named_data_off); // leaf: high bit clear

        // Id lang dir (for id=42) at 0x180: two id entries, lang 0x0409 and 0
        let id_lang_dir = rsrc + id_lang_dir_off as usize;
        w16(&mut buf, id_lang_dir + 12, 0);
        w16(&mut buf, id_lang_dir + 14, 2);
        let id_data_en_off: u32 = 0x320;
        let id_data_neutral_off: u32 = 0x340;
        w32(&mut buf, id_lang_dir + 16, 0x0409);
        w32(&mut buf, id_lang_dir + 16 + 4, id_data_en_off);
        w32(&mut buf, id_lang_dir + 16 + 8, 0);
        w32(&mut buf, id_lang_dir + 16 + 12, id_data_neutral_off);

        // IMAGE_RESOURCE_DIR_STRING_U for "HELLO" at 0x200:
        //   WORD Length = 5 ; WCHAR[5] "HELLO"
        let hello_str = rsrc + hello_name_str_off as usize;
        w16(&mut buf, hello_str, 5);
        for (i, ch) in "HELLO".encode_utf16().enumerate() {
            w16(&mut buf, hello_str + 2 + i * 2, ch);
        }

        // Data entries (IMAGE_RESOURCE_DATA_ENTRY) at 0x300, 0x320, 0x340.
        // Each: OffsetToData (absolute RVA), Size, CodePage, Reserved.
        let named_payload_rva = rsrc_rva + 0x400;
        let en_payload_rva = rsrc_rva + 0x420;
        let neutral_payload_rva = rsrc_rva + 0x440;

        let named_data_abs = rsrc + named_data_off as usize;
        w32(&mut buf, named_data_abs, named_payload_rva);
        w32(&mut buf, named_data_abs + 4, 8); // size of "NAMED-EN"
        w32(&mut buf, named_data_abs + 8, 1200); // codepage

        let en_data_abs = rsrc + id_data_en_off as usize;
        w32(&mut buf, en_data_abs, en_payload_rva);
        w32(&mut buf, en_data_abs + 4, 7); // "ENGLISH"
        w32(&mut buf, en_data_abs + 8, 1252);

        let neutral_data_abs = rsrc + id_data_neutral_off as usize;
        w32(&mut buf, neutral_data_abs, neutral_payload_rva);
        w32(&mut buf, neutral_data_abs + 4, 7); // "NEUTRAL"
        w32(&mut buf, neutral_data_abs + 8, 0);

        // Actual payload bytes (purely for future tests that dereference
        // data_rva; find_resource itself only returns the locator).
        buf[rsrc + 0x400..rsrc + 0x400 + 8].copy_from_slice(b"NAMED-EN");
        buf[rsrc + 0x420..rsrc + 0x420 + 7].copy_from_slice(b"ENGLISH");
        buf[rsrc + 0x440..rsrc + 0x440 + 7].copy_from_slice(b"NEUTRAL");

        (buf, rsrc_rva)
    }

    #[test]
    fn finds_by_id_exact_lang() {
        let (buf, rsrc_rva) = build_image();
        let base = buf.as_ptr() as usize;
        let loc = find_resource(base, ResourceId::Id(6), ResourceId::Id(42), 0x0409)
            .expect("should find RT_STRING/42/en-US");
        assert_eq!(loc.size, 7);
        assert_eq!(loc.codepage, 1252);
        assert_eq!(loc.data_rva, rsrc_rva + 0x420);
    }

    #[test]
    fn falls_back_to_lang_neutral() {
        let (buf, rsrc_rva) = build_image();
        let base = buf.as_ptr() as usize;
        // Ask for a lang that doesn't exist; should fall back to neutral (0).
        let loc = find_resource(base, ResourceId::Id(6), ResourceId::Id(42), 0x040C)
            .expect("should fall back to LANG_NEUTRAL");
        assert_eq!(loc.codepage, 0);
        assert_eq!(loc.data_rva, rsrc_rva + 0x440);
    }

    #[test]
    fn finds_by_named_entry() {
        let (buf, rsrc_rva) = build_image();
        let base = buf.as_ptr() as usize;
        let hello: Vec<u16> = "HELLO".encode_utf16().collect();
        let loc = find_resource(base, ResourceId::Id(6), ResourceId::Name(hello), 0x0409)
            .expect("should find named HELLO resource");
        assert_eq!(loc.size, 8);
        assert_eq!(loc.codepage, 1200);
        assert_eq!(loc.data_rva, rsrc_rva + 0x400);
    }

    #[test]
    fn missing_type_returns_none() {
        let (buf, _) = build_image();
        let base = buf.as_ptr() as usize;
        assert!(find_resource(base, ResourceId::Id(99), ResourceId::Id(42), 0x0409).is_none());
    }

    #[test]
    fn missing_name_returns_none() {
        let (buf, _) = build_image();
        let base = buf.as_ptr() as usize;
        assert!(find_resource(base, ResourceId::Id(6), ResourceId::Id(9999), 0x0409).is_none());
    }
}
