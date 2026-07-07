//! Scans all PE DLLs in the audacity fixture and reports imports that
//! Weave's resolver chain cannot satisfy.
//!
//! Usage: cargo run --manifest-path Cargo.toml --bin audacity-unresolved-imports
//! (or: rustc scripts/audacity-unresolved-imports.rs -o /tmp/scan && ./scan)
//!
//! This is a standalone analysis tool, not part of the Weave build.

fn main() {
    let fixture = "tests/fixtures/audacity";
    let dir = std::path::Path::new(fixture);
    if !dir.is_dir() {
        eprintln!("Fixture dir not found: {fixture}");
        std::process::exit(1);
    }

    // Collect all DLLs
    let mut dlls: Vec<std::path::PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "dll") || path.extension().map_or(false, |e| e == "exe") {
            dlls.push(path);
        }
    }
    dlls.sort();

    // Build the set of known DLLs and their exports
    let mut known_exports: std::collections::HashMap<String, std::collections::HashSet<String>> = std::collections::HashMap::new();
    // Parse each DLL to get its exports
    for dll in &dlls {
        let name = dll.file_name().unwrap().to_str().unwrap().to_lowercase();
        let bytes = match std::fs::read(dll) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let exports = parse_pe_exports(&bytes);
        known_exports.insert(name, exports);
    }

    // Now scan each DLL for imports and check resolution
    let all_dll_names: std::collections::HashSet<String> = known_exports.keys().cloned().collect();
    let system_dlls = [
        "ntdll.dll","kernel32.dll","advapi32.dll","user32.dll","gdi32.dll",
        "shell32.dll","ole32.dll","mmdevapi.dll","xinput1_3.dll","winmm.dll",
        "setupapi.dll","ucrtbase.dll","msvcp140.dll","mfc140u.dll","vulkan-1.dll",
        "ws2_32.dll","comctl32.dll","oleaut32.dll","imm32.dll","shlwapi.dll",
        "gdiplus.dll","dwrite.dll","ddraw.dll","crypt32.dll","wldap32.dll",
        "normaliz.dll","secur32.dll","bcrypt.dll","bcryptprimitives.dll",
        "powrprof.dll","msvcp140_1.dll","msvcp140_2.dll","msvcp140_atomic_wait.dll",
        "msvcp140_codecvt_ids.dll","vcruntime140.dll","vcruntime140_1.dll",
        "concrt140.dll","d3d9.dll","dxgi.dll","d3d11.dll","dcomp.dll",
        "uxtheme.dll","version.dll","msimg32.dll","dwmapi.dll","oleacc.dll",
        "rpcrt4.dll",
    ];
    let system_set: std::collections::HashSet<&str> = system_dlls.iter().cloned().collect();

    // Also handle the DLLs that are side-by-side but not in the fixture
    let mut all_available = all_dll_names.clone();
    for sd in &system_dlls {
        all_available.insert(sd.to_string());
    }

    let mut total_unresolved = 0u64;

    for dll in &dlls {
        let dll_name = dll.file_name().unwrap().to_str().unwrap().to_lowercase();
        let bytes = match std::fs::read(dll) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let imports = parse_pe_imports(&bytes);
        for (import_dll, import_names) in &imports {
            let import_dll_lower = import_dll.to_lowercase();
            if !all_available.contains(&import_dll_lower) {
                // Not a known DLL at all
                continue;
            }
            for name in import_names {
                let resolved = if let Some(exports) = known_exports.get(&import_dll_lower) {
                    exports.contains(name)
                } else if system_set.contains(import_dll_lower.as_str()) {
                    // System DLL — assume Weave's resolver handles it
                    true
                } else {
                    false
                };
                if !resolved {
                    println!("unresolved: {dll_name} -> {import_dll_lower}!{name}");
                    total_unresolved += 1;
                }
            }
        }
    }

    println!("\nTotal unresolved: {total_unresolved}");
}

fn parse_pe_exports(bytes: &[u8]) -> std::collections::HashSet<String> {
    let mut exports = std::collections::HashSet::new();
    let pe_offset = read_u16(bytes, 0x3c) as usize;
    if pe_offset + 4 > bytes.len() { return exports; }
    if &bytes[pe_offset..pe_offset+4] != b"PE\0\0" { return exports; }

    let coff = &bytes[pe_offset + 4..];
    let num_sections = read_u16(coff, 2) as usize;
    let opt_hdr_size = read_u16(coff, 16) as usize;
    let opt_offset = 20;

    // Optional header magic
    if opt_offset + opt_hdr_size > coff.len() { return exports; }
    let magic = read_u16(coff, opt_offset);
    let is_pe32plus = magic == 0x20b;
    let export_rva_offset = if is_pe32plus { 112 } else { 96 };

    let data_dir_offset = opt_offset + if is_pe32plus { 104 } else { 96 };
    // Find export directory
    let export_dir_rva = read_u32(coff, data_dir_offset) as usize;
    let export_dir_size = read_u32(coff, data_dir_offset + 4) as usize;
    if export_dir_rva == 0 || export_dir_size == 0 { return exports; }

    // Find section that contains the export directory
    let sections_offset = opt_offset + opt_hdr_size;
    for i in 0..num_sections {
        let section = &coff[sections_offset + i * 40..];
        let section_rva = read_u32(section, 12) as usize;
        let section_size = read_u32(section, 8) as usize;
        let section_offset = read_u32(section, 20) as usize;

        if export_dir_rva >= section_rva && export_dir_rva < section_rva + section_size {
            let edata_offset = export_dir_rva - section_rva + section_offset;
            if edata_offset + 40 > bytes.len() { return exports; }

            let name_count = read_u32(bytes, edata_offset + 24) as usize;
            let addr_of_fns = read_u32(bytes, edata_offset + 28) as usize;
            let addr_of_names = read_u32(bytes, edata_offset + 32) as usize;
            let addr_of_ordinals = read_u32(bytes, edata_offset + 36) as usize;

            fn rva_to_offset(rva: usize, sections_offset: usize, coff: &[u8], num_sections: usize) -> Option<usize> {
                for i in 0..num_sections {
                    let s = &coff[sections_offset + i * 40..];
                    let srva = read_u32(s, 12) as usize;
                    let ssize = read_u32(s, 8) as usize;
                    if rva >= srva && rva < srva + ssize {
                        return Some(rva - srva + read_u32(s, 20) as usize);
                    }
                }
                None
            }

            for i in 0..std::cmp::min(name_count, 10000) {
                let name_rva = read_u32(bytes, rva_to_offset(addr_of_names, sections_offset, coff, num_sections).unwrap_or(0) + i * 4) as usize;
                if let Some(name_off) = rva_to_offset(name_rva, sections_offset, coff, num_sections) {
                    let name = read_cstring(bytes, name_off);
                    if !name.is_empty() {
                        exports.insert(name);
                    }
                }
            }
            break;
        }
    }
    exports
}

fn parse_pe_imports(bytes: &[u8]) -> std::collections::HashMap<String, Vec<String>> {
    let mut imports: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let pe_offset = read_u16(bytes, 0x3c) as usize;
    if pe_offset + 4 > bytes.len() { return imports; }
    if &bytes[pe_offset..pe_offset+4] != b"PE\0\0" { return imports; }

    let coff = &bytes[pe_offset + 4..];
    let num_sections = read_u16(coff, 2) as usize;
    let opt_hdr_size = read_u16(coff, 16) as usize;
    let opt_offset = 20;
    if opt_offset + opt_hdr_size > coff.len() { return imports; }

    let sections_offset = opt_offset + opt_hdr_size;
    let data_dir_offset = opt_offset + if read_u16(coff, opt_offset) == 0x20b { 104 } else { 96 };
    let import_rva = read_u32(coff, data_dir_offset + 8) as usize;

    fn rva_to_offset(rva: usize, sections_offset: usize, coff: &[u8], num_sections: usize) -> Option<usize> {
        for i in 0..num_sections {
            let s = &coff[sections_offset + i * 40..];
            let srva = read_u32(s, 12) as usize;
            let ssize = read_u32(s, 8) as usize;
            if rva >= srva && rva < srva + ssize {
                return Some(rva - srva + read_u32(s, 20) as usize);
            }
        }
        None
    }

    let import_off = match rva_to_offset(import_rva, sections_offset, coff, num_sections) {
        Some(o) => o,
        None => return imports,
    };

    // Walk IID array (null-terminated)
    let mut i = 0;
    loop {
        let entry = import_off + i * 20;
        if entry + 20 > bytes.len() { break; }
        let ogrva = read_u32(bytes, entry);
        let name_rva = read_u32(bytes, entry + 12);
        if ogrva == 0 && name_rva == 0 { break; }

        let dll_name = if let Some(noff) = rva_to_offset(name_rva as usize, sections_offset, coff, num_sections) {
            read_cstring(bytes, noff).to_lowercase()
        } else {
            i += 1;
            continue;
        };

        let thunk_rva = ogrva as usize;
        let thunk_off = match rva_to_offset(thunk_rva, sections_offset, coff, num_sections) {
            Some(o) => o,
            None => { i += 1; continue; }
        };

        let mut thunk_i = 0;
        loop {
            let t_entry = thunk_off + thunk_i * 8;
            if t_entry + 8 > bytes.len() { break; }
            let val = read_u64(bytes, t_entry);
            if val == 0 { break; }
            // Check if it's an ordinal import (MSB set for PE32+)
            if val & 0x8000000000000000 != 0 {
                let ordinal = val & 0xffff;
                imports.entry(dll_name.clone()).or_default().push(format!("#{ordinal}"));
            } else if val & 0x7fffffff != 0 {
                // Hint/Name import
                let name_off = match rva_to_offset(val as usize & 0x7fffffff, sections_offset, coff, num_sections) {
                    Some(o) => o,
                    None => { thunk_i += 1; continue; }
                };
                let name = read_cstring(bytes, name_off + 2); // skip 2-byte hint
                if !name.is_empty() {
                    imports.entry(dll_name.clone()).or_default().push(name);
                }
            }
            thunk_i += 1;
        }

        i += 1;
    }
    imports
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    if off + 2 > buf.len() { return 0; }
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    if off + 4 > buf.len() { return 0; }
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    if off + 8 > buf.len() { return 0; }
    u64::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3], buf[off+4], buf[off+5], buf[off+6], buf[off+7]])
}

fn read_cstring(buf: &[u8], off: usize) -> String {
    let mut s = String::new();
    let mut i = off;
    while i < buf.len() && buf[i] != 0 {
        s.push(buf[i] as char);
        i += 1;
    }
    s
}
