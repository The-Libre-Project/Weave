use goblin::pe::PE;
use std::collections::HashMap;
use std::ptr;

/// A PE binary successfully loaded into memory.
///
/// Dropping this value unmaps the memory.
pub struct LoadedImage {
    /// Actual base address in our process's memory.
    pub base: *mut u8,
    /// Total size of the mapped region (from SizeOfImage in the PE header).
    pub size: usize,
    /// Actual virtual address of the entry point (base + entry RVA).
    pub entry_point: *const u8,
    /// Pointer to the start of the TLS raw data in the loaded image, and its
    /// byte length.  Both are zero/null if the PE has no TLS directory.
    pub tls_data: *const u8,
    pub tls_data_size: usize,
    /// RVA and byte size of the .pdata exception table (0/0 if absent).
    /// Used by the SEH signal handler to identify which function faulted.
    pub pdata_rva: usize,
    pub pdata_size: usize,
}

// Safety: the mapped region is owned exclusively by this struct.
unsafe impl Send for LoadedImage {}

impl Drop for LoadedImage {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.size);
        }
    }
}

/// Load a PE binary from raw bytes into memory.
///
/// Steps:
///   1. Reserve a contiguous block of virtual memory for the full image.
///   2. Copy each section from the file into its virtual address slot.
///   3. Apply base relocations if ASLR placed us at a different address than preferred.
///   4. Set final memory permissions on each section (code=rx, data=rw, rodata=r).
pub fn load(bytes: &[u8]) -> Result<LoadedImage, String> {
    let pe = PE::parse(bytes).map_err(|e| format!("parse error: {e}"))?;

    let opt = pe
        .header
        .optional_header
        .ok_or("no optional header — not a valid executable")?;

    let entry_rva = opt.standard_fields.address_of_entry_point as usize;

    let (base, _actual_base) = map_sections(bytes, &pe, &opt)?;

    let (tls_data, tls_data_size) = init_tls(base, bytes, &pe);

    let (pdata_rva, pdata_size) = pe
        .sections
        .iter()
        .find(|s| s.name().ok() == Some(".pdata"))
        .map(|s| (s.virtual_address as usize, s.virtual_size as usize))
        .unwrap_or((0, 0));

    Ok(LoadedImage {
        base,
        size: opt.windows_fields.size_of_image as usize,
        entry_point: unsafe { base.add(entry_rva) },
        tls_data,
        tls_data_size,
        pdata_rva,
        pdata_size,
    })
}

/// Load a PE DLL from raw bytes and return its image and export table.
///
/// The export table maps exported function names to their absolute addresses
/// in the loaded image. Ordinal-only exports are omitted.
///
/// DllMain is not called — the caller is responsible for any initialisation
/// the DLL requires.
pub fn load_dll(bytes: &[u8]) -> Result<(LoadedImage, HashMap<String, usize>), String> {
    let pe = PE::parse(bytes).map_err(|e| format!("parse error: {e}"))?;

    let opt = pe
        .header
        .optional_header
        .ok_or("no optional header — not a valid DLL")?;

    let (base, actual_base) = map_sections(bytes, &pe, &opt)?;

    let mut exports: HashMap<String, usize> = HashMap::new();
    for exp in &pe.exports {
        if let Some(name) = exp.name {
            // exp.rva is relative to image base; actual_base is where we loaded.
            exports.insert(name.to_string(), actual_base + exp.rva);
        }
    }

    let image = LoadedImage {
        base,
        size: opt.windows_fields.size_of_image as usize,
        entry_point: std::ptr::null(),
        tls_data: std::ptr::null(),
        tls_data_size: 0,
        pdata_rva: 0,
        pdata_size: 0,
    };

    Ok((image, exports))
}

/// Reserve memory, copy sections, apply relocations, and set permissions.
/// Returns `(base pointer, actual_base usize)`.
fn map_sections(
    bytes: &[u8],
    pe: &PE,
    opt: &goblin::pe::optional_header::OptionalHeader,
) -> Result<(*mut u8, usize), String> {
    let preferred_base = opt.windows_fields.image_base as usize;
    let image_size = opt.windows_fields.size_of_image as usize;

    let actual_base = reserve_memory(preferred_base, image_size)?;
    let base = actual_base as *mut u8;
    let delta = actual_base as i64 - preferred_base as i64;

    // Make the whole image writable so we can populate it.
    unsafe {
        libc::mprotect(
            base as *mut libc::c_void,
            image_size,
            libc::PROT_READ | libc::PROT_WRITE,
        );
    }

    // Copy sections from file into their virtual address slots.
    for section in &pe.sections {
        let vaddr = section.virtual_address as usize;
        let vsize = if section.virtual_size == 0 {
            section.size_of_raw_data as usize
        } else {
            section.virtual_size as usize
        };
        let raw_off = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;

        let dest = unsafe { base.add(vaddr) };

        let copy_size = raw_size.min(vsize);
        if copy_size > 0 && raw_off.saturating_add(copy_size) <= bytes.len() {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr().add(raw_off), dest, copy_size);
            }
        }
        if vsize > copy_size {
            unsafe {
                ptr::write_bytes(dest.add(copy_size), 0, vsize - copy_size);
            }
        }
    }

    if delta != 0 {
        apply_relocations(base, pe, delta)?;
    }

    // Set final section permissions.
    for section in &pe.sections {
        let vaddr = section.virtual_address as usize;
        let vsize = page_align_up(if section.virtual_size == 0 {
            section.size_of_raw_data as usize
        } else {
            section.virtual_size as usize
        });
        if vsize == 0 {
            continue;
        }
        let prot = section_prot(section.characteristics);
        unsafe {
            libc::mprotect(base.add(vaddr) as *mut libc::c_void, vsize, prot);
        }
    }

    Ok((base, actual_base))
}

/// Reserve `size` bytes of virtual address space, preferring `preferred_base`.
fn reserve_memory(
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] preferred_base: usize,
    size: usize,
) -> Result<usize, String> {
    unsafe {
        #[cfg(target_os = "linux")]
        {
            let p = libc::mmap(
                preferred_base as *mut libc::c_void,
                size,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            );
            if p != libc::MAP_FAILED {
                return Ok(p as usize);
            }
        }

        let p = libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            return Err(format!("mmap failed: {}", std::io::Error::last_os_error()));
        }
        Ok(p as usize)
    }
}

/// Initialise TLS for the loaded PE.
fn init_tls(base: *mut u8, bytes: &[u8], pe: &PE) -> (*const u8, usize) {
    let tls = match &pe.tls_data {
        Some(t) => t,
        None => return (std::ptr::null(), 0),
    };

    let dir = &tls.image_tls_directory;
    let raw_start = dir.start_address_of_raw_data as usize;
    let raw_end = dir.end_address_of_raw_data as usize;
    let addr_of_index = dir.address_of_index as usize;

    if addr_of_index != 0 {
        unsafe { *(addr_of_index as *mut u32) = 0 };
    }

    let raw_size = raw_end.saturating_sub(raw_start);
    if raw_size == 0 || raw_start == 0 {
        return (std::ptr::null(), 0);
    }

    let _ = (base, bytes);
    (raw_start as *const u8, raw_size)
}

/// Walk the `.reloc` section and add `delta` to every 64-bit absolute address.
fn apply_relocations(base: *mut u8, pe: &PE, delta: i64) -> Result<(), String> {
    let opt = pe.header.optional_header.unwrap();
    let (reloc_rva, reloc_size) = match opt.data_directories.get_base_relocation_table() {
        Some(d) if d.size > 0 => (d.virtual_address as usize, d.size as usize),
        _ => return Ok(()),
    };

    let reloc_bytes = unsafe { std::slice::from_raw_parts(base.add(reloc_rva), reloc_size) };

    let mut cursor = 0usize;
    while cursor + 8 <= reloc_bytes.len() {
        let page_rva =
            u32::from_le_bytes(reloc_bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        let block_size =
            u32::from_le_bytes(reloc_bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;

        if block_size < 8 {
            break;
        }

        let n_entries = (block_size - 8) / 2;
        for i in 0..n_entries {
            let e_off = cursor + 8 + i * 2;
            if e_off + 2 > reloc_bytes.len() {
                break;
            }
            let entry = u16::from_le_bytes(reloc_bytes[e_off..e_off + 2].try_into().unwrap());
            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as usize;

            match reloc_type {
                0 => {}
                10 => {
                    let target = unsafe { base.add(page_rva + reloc_offset) as *mut i64 };
                    unsafe { *target = (*target).wrapping_add(delta) };
                }
                t => {
                    return Err(format!(
                        "unsupported relocation type {t} at rva {:#x}",
                        page_rva + reloc_offset
                    ))
                }
            }
        }

        cursor += block_size;
    }

    Ok(())
}

/// Convert PE section characteristic flags to Unix memory protection flags.
fn section_prot(characteristics: u32) -> libc::c_int {
    let mut prot = libc::PROT_NONE;
    if characteristics & 0x4000_0000 != 0 {
        prot |= libc::PROT_READ;
    }
    if characteristics & 0x8000_0000 != 0 {
        prot |= libc::PROT_WRITE;
    }
    if characteristics & 0x2000_0000 != 0 {
        prot |= libc::PROT_EXEC;
    }
    prot
}

fn page_align_up(size: usize) -> usize {
    const PAGE: usize = 4096;
    (size + PAGE - 1) & !(PAGE - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_minimal_bytes() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/bin/hello_minimal.exe"
        );
        std::fs::read(path).expect("hello_minimal.exe not found — run Step 0 first")
    }

    #[test]
    fn load_hello_minimal() {
        let bytes = hello_minimal_bytes();
        let image = load(&bytes).expect("load failed");

        assert!(!image.base.is_null(), "base address is null");

        let entry_offset = image.entry_point as usize - image.base as usize;
        assert!(
            entry_offset < image.size,
            "entry point {:#x} is outside image bounds (size={:#x})",
            entry_offset,
            image.size
        );

        assert!(image.size > 0);
    }

    #[test]
    fn text_section_is_readable() {
        let bytes = hello_minimal_bytes();
        let image = load(&bytes).expect("load failed");

        let first_byte = unsafe { std::ptr::read_volatile(image.entry_point) };
        assert_ne!(first_byte, 0x00, "entry point looks like unmapped memory");
    }
}
