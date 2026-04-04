//! PE resource parser for icon extraction.
//!
//! Walks the three-level resource directory tree inside a PE binary to locate
//! `RT_GROUP_ICON` (type 14) and `RT_ICON` (type 3) resources, then
//! reassembles them into a self-contained `.ico` file returned as raw bytes.

use goblin::pe::{section_table::SectionTable, PE};

const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;

// ── Low-level byte helpers ────────────────────────────────────────────────────

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ── RVA → file offset ─────────────────────────────────────────────────────────

fn rva_to_file_off(rva: u32, sections: &[SectionTable]) -> Option<usize> {
    for s in sections {
        let va = s.virtual_address;
        // Some linkers leave virtual_size as 0; fall back to size_of_raw_data.
        let vs = if s.virtual_size == 0 {
            s.size_of_raw_data
        } else {
            s.virtual_size
        };
        if rva >= va && rva < va + vs {
            return Some((rva - va + s.pointer_to_raw_data) as usize);
        }
    }
    None
}

// ── Resource directory helpers ────────────────────────────────────────────────

/// Find a directory entry with a specific integer ID and return the offset
/// its value points to (either a subdirectory or a data entry — caller decides).
///
/// `dir_off` is the offset of an `IMAGE_RESOURCE_DIRECTORY` within `rsrc`.
/// Only scans ID entries (not named entries); named entries come first and are
/// skipped by counting `NumberOfNamedEntries`.
fn find_id_entry_value(rsrc: &[u8], dir_off: usize, id: u32) -> Option<u32> {
    let named = read_u16(rsrc, dir_off + 12)? as usize;
    let id_count = read_u16(rsrc, dir_off + 14)? as usize;
    let entries_start = dir_off + 16;
    for i in 0..id_count {
        let e = entries_start + (named + i) * 8;
        if read_u32(rsrc, e)? == id {
            return read_u32(rsrc, e + 4);
        }
    }
    None
}

/// Return the value of the first entry in a directory (named or ID).
fn first_entry_value(rsrc: &[u8], dir_off: usize) -> Option<u32> {
    let named = read_u16(rsrc, dir_off + 12)? as usize;
    let id_count = read_u16(rsrc, dir_off + 14)? as usize;
    if named + id_count == 0 {
        return None;
    }
    read_u32(rsrc, dir_off + 16 + 4) // first entry's value field
}

/// Follow a directory entry value that MUST be a subdirectory pointer
/// (high bit set). Returns the subdirectory offset.
fn as_subdir(v: u32) -> Option<usize> {
    if v & 0x8000_0000 != 0 {
        Some((v & 0x7FFF_FFFF) as usize)
    } else {
        None
    }
}

/// Follow a directory entry value that MUST be a data entry pointer
/// (high bit clear). Returns the data entry offset.
fn as_data_entry(v: u32) -> Option<usize> {
    if v & 0x8000_0000 == 0 {
        Some(v as usize)
    } else {
        None
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Extract the best available icon group from a PE executable as raw `.ico`
/// bytes.
///
/// Returns `None` if the file has no icon resources, cannot be parsed as a PE,
/// or if the resource directory is absent or empty.
pub fn extract_icon(exe_bytes: &[u8]) -> Option<Vec<u8>> {
    let pe = PE::parse(exe_bytes).ok()?;

    // Locate the resource data directory.
    let res_rva = pe
        .header
        .optional_header?
        .data_directories
        .get_resource_table()?
        .virtual_address;
    if res_rva == 0 {
        return None;
    }

    let res_off = rva_to_file_off(res_rva, &pe.sections)?;
    // `rsrc` is a slice starting at the resource section — all directory
    // offsets within the resource tree are relative to this slice's start.
    let rsrc = exe_bytes.get(res_off..)?;

    // ── Level 1 → 2: find RT_GROUP_ICON ──────────────────────────────────────
    let v1 = find_id_entry_value(rsrc, 0, RT_GROUP_ICON)?;
    let grp_type_subdir = as_subdir(v1)?;

    // ── Level 2 → 3: first group icon (any name / ID) ────────────────────────
    let v2 = first_entry_value(rsrc, grp_type_subdir)?;
    let grp_name_subdir = as_subdir(v2)?;

    // ── Level 3 → data: first language ───────────────────────────────────────
    let v3 = first_entry_value(rsrc, grp_name_subdir)?;
    let grp_data_off = as_data_entry(v3)?;

    // Read IMAGE_RESOURCE_DATA_ENTRY for the group icon.
    let grp_rva = read_u32(rsrc, grp_data_off)?;
    let grp_size = read_u32(rsrc, grp_data_off + 4)? as usize;
    let grp_file_off = rva_to_file_off(grp_rva, &pe.sections)?;
    let grp_bytes = exe_bytes.get(grp_file_off..grp_file_off + grp_size)?;

    // ── Parse GRPICONDIR ──────────────────────────────────────────────────────
    // Layout: reserved(u16) + type(u16) + count(u16)
    let count = read_u16(grp_bytes, 4)? as usize;
    if count == 0 {
        return None;
    }

    // ── Find RT_ICON type directory (used for all individual icons) ───────────
    let v_icon_type = find_id_entry_value(rsrc, 0, RT_ICON)?;
    let icon_type_subdir = as_subdir(v_icon_type)?;

    // ── Collect GRPICONDIRENTRY records and their raw icon data ───────────────
    // GRPICONDIRENTRY (14 bytes each, starting at offset 6 in grp_bytes):
    //   bWidth(1) bHeight(1) bColorCount(1) bReserved(1)
    //   wPlanes(2) wBitCount(2) dwBytesInRes(4) nId(2)
    struct Entry {
        width: u8,
        height: u8,
        color_count: u8,
        planes: u16,
        bit_count: u16,
        data: Vec<u8>,
    }

    let mut entries: Vec<Entry> = Vec::with_capacity(count);
    for i in 0..count {
        let base = 6 + i * 14;
        let width = *grp_bytes.get(base)?;
        let height = *grp_bytes.get(base + 1)?;
        let color_count = *grp_bytes.get(base + 2)?;
        let planes = read_u16(grp_bytes, base + 4)?;
        let bit_count = read_u16(grp_bytes, base + 6)?;
        let nid = read_u16(grp_bytes, base + 12)? as u32;

        // Look up individual RT_ICON resource by nId.
        let vi = find_id_entry_value(rsrc, icon_type_subdir, nid)?;
        let icon_name_subdir = as_subdir(vi)?;
        let vi2 = first_entry_value(rsrc, icon_name_subdir)?;
        let icon_data_off = as_data_entry(vi2)?;

        let icon_rva = read_u32(rsrc, icon_data_off)?;
        let icon_size = read_u32(rsrc, icon_data_off + 4)? as usize;
        let icon_file_off = rva_to_file_off(icon_rva, &pe.sections)?;
        let raw = exe_bytes
            .get(icon_file_off..icon_file_off + icon_size)?
            .to_vec();

        entries.push(Entry {
            width,
            height,
            color_count,
            planes,
            bit_count,
            data: raw,
        });
    }

    if entries.is_empty() {
        return None;
    }

    // ── Reconstruct .ico file ─────────────────────────────────────────────────
    // ICONDIR header (6 bytes):
    //   reserved(2) + type=1(2) + count(2)
    //
    // ICONDIRENTRY per icon (16 bytes):
    //   bWidth(1) bHeight(1) bColorCount(1) bReserved(1)
    //   wPlanes(2) wBitCount(2) dwBytesInRes(4) dwImageOffset(4)
    //
    // Followed by the raw image data for each icon.
    let n = entries.len();
    let data_start: usize = 6 + n * 16;
    let total: usize = data_start + entries.iter().map(|e| e.data.len()).sum::<usize>();
    let mut ico = vec![0u8; total];

    // ICONDIR
    ico[2..4].copy_from_slice(&1u16.to_le_bytes()); // type = ICO
    ico[4..6].copy_from_slice(&(n as u16).to_le_bytes());

    let mut data_off = data_start;
    for (i, entry) in entries.iter().enumerate() {
        let e = 6 + i * 16;
        ico[e] = entry.width;
        ico[e + 1] = entry.height;
        ico[e + 2] = entry.color_count;
        // ico[e + 3] = 0  (reserved, already zeroed)
        ico[e + 4..e + 6].copy_from_slice(&entry.planes.to_le_bytes());
        ico[e + 6..e + 8].copy_from_slice(&entry.bit_count.to_le_bytes());
        ico[e + 8..e + 12].copy_from_slice(&(entry.data.len() as u32).to_le_bytes());
        ico[e + 12..e + 16].copy_from_slice(&(data_off as u32).to_le_bytes());
        ico[data_off..data_off + entry.data.len()].copy_from_slice(&entry.data);
        data_off += entry.data.len();
    }

    Some(ico)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_helpers_basic() {
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(read_u16(&data, 0), Some(0x0201));
        assert_eq!(read_u32(&data, 0), Some(0x04030201));
    }

    #[test]
    fn read_helpers_out_of_bounds() {
        let data = [0x01u8, 0x02];
        assert_eq!(read_u16(&data, 1), None); // only 1 byte remaining
        assert_eq!(read_u32(&data, 0), None); // only 2 bytes available
    }

    #[test]
    fn extract_icon_empty_returns_none() {
        assert!(extract_icon(&[]).is_none());
    }

    #[test]
    fn extract_icon_invalid_pe_returns_none() {
        assert!(extract_icon(b"MZ but not a real PE").is_none());
    }
}
