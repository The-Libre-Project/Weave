use goblin::pe::PE;
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

    let preferred_base = opt.windows_fields.image_base as usize;
    let image_size = opt.windows_fields.size_of_image as usize;
    let entry_rva = opt.standard_fields.address_of_entry_point as usize;

    // ── 1. Reserve address space ───────────────────────────────────────────
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

    // ── 2. Copy sections ───────────────────────────────────────────────────
    for section in &pe.sections {
        let vaddr = section.virtual_address as usize;
        // Some linkers set virtual_size = 0; fall back to size_of_raw_data.
        let vsize = if section.virtual_size == 0 {
            section.size_of_raw_data as usize
        } else {
            section.virtual_size as usize
        };
        let raw_off = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;

        let dest = unsafe { base.add(vaddr) };

        // Copy file content.
        let copy_size = raw_size.min(vsize);
        if copy_size > 0 && raw_off.saturating_add(copy_size) <= bytes.len() {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr().add(raw_off), dest, copy_size);
            }
        }
        // Zero the gap between file data and virtual size (.bss pattern).
        if vsize > copy_size {
            unsafe {
                ptr::write_bytes(dest.add(copy_size), 0, vsize - copy_size);
            }
        }
    }

    // ── 3. Apply base relocations (if ASLR moved us) ──────────────────────
    if delta != 0 {
        apply_relocations(base, &pe, delta)?;
    }

    // ── 4. Initialise TLS ─────────────────────────────────────────────────
    let (tls_data, tls_data_size) = init_tls(base, bytes, &pe);

    // ── 5. Set final section permissions ──────────────────────────────────
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

    Ok(LoadedImage {
        base,
        size: image_size,
        entry_point: unsafe { base.add(entry_rva) },
        tls_data,
        tls_data_size,
    })
}

/// Reserve `size` bytes of virtual address space, preferring `preferred_base`.
///
/// On Linux we try `MAP_FIXED_NOREPLACE` first (requires kernel 4.17+); if
/// the address is already occupied we fall back to a kernel-chosen address.
/// On other platforms (macOS dev builds) we go straight to kernel-chosen.
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
            // Preferred base unavailable — fall through to kernel-chosen.
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
///
/// Reads the TLS data directory from the parsed PE (from the raw file bytes, as
/// goblin parses it from the file). For PE64 binaries the directory contains
/// absolute VAs — after our loader has applied base relocations those VAs are
/// valid in our process address space.
///
/// Steps:
///   1. Find the TLS data directory; return early if absent.
///   2. Write 0 to *AddressOfIndex — set the TLS slot index to 0 for the main
///      thread (we only ever have one thread in Phase 1).
///   3. Return a pointer to the raw TLS data block and its size so the TEB
///      setup code can copy it into the per-thread TLS slot.
fn init_tls(base: *mut u8, bytes: &[u8], pe: &PE) -> (*const u8, usize) {
    let tls = match &pe.tls_data {
        Some(t) => t,
        None => return (std::ptr::null(), 0),
    };

    let dir = &tls.image_tls_directory;
    let raw_start = dir.start_address_of_raw_data as usize;
    let raw_end = dir.end_address_of_raw_data as usize;
    let addr_of_index = dir.address_of_index as usize;

    // addr_of_index is an absolute VA in the loaded image.  After apply_relocations
    // it is correct in our address space.  Write TLS slot 0.
    if addr_of_index != 0 {
        unsafe { *(addr_of_index as *mut u32) = 0 };
    }

    // Compute the raw data size; both are absolute VAs pointing into the loaded
    // image.
    let raw_size = raw_end.saturating_sub(raw_start);
    if raw_size == 0 || raw_start == 0 {
        return (std::ptr::null(), 0);
    }

    // raw_start is an absolute VA in our process — it already points into the
    // mapped image after relocations.
    let _ = (base, bytes); // kept in signature for symmetry; not needed here
    (raw_start as *const u8, raw_size)
}

/// Walk the `.reloc` section and add `delta` to every 64-bit absolute address.
///
/// PE base relocations are stored as blocks, each covering a 4KB page.
/// Entry type 10 (IMAGE_REL_BASED_DIR64) means "add delta to the 64-bit
/// value at page_base + offset". Type 0 is padding; we error on anything else
/// since PE64 binaries should only contain these two types.
fn apply_relocations(base: *mut u8, pe: &PE, delta: i64) -> Result<(), String> {
    let opt = pe.header.optional_header.unwrap();
    let (reloc_rva, reloc_size) = match opt.data_directories.get_base_relocation_table() {
        Some(d) if d.size > 0 => (d.virtual_address as usize, d.size as usize),
        _ => return Ok(()), // no reloc section — position-independent or stripped
    };

    // Read from the already-mapped image (populated in step 2).
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
                0 => {} // IMAGE_REL_BASED_ABSOLUTE — padding, skip
                10 => {
                    // IMAGE_REL_BASED_DIR64 — patch a 64-bit VA
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

    /// Load the Phase 0 test binary and verify the image is in a sane state.
    #[test]
    fn load_hello_minimal() {
        let bytes = hello_minimal_bytes();
        let image = load(&bytes).expect("load failed");

        assert!(!image.base.is_null(), "base address is null");

        // Entry point must fall within the mapped image.
        let entry_offset = image.entry_point as usize - image.base as usize;
        assert!(
            entry_offset < image.size,
            "entry point {:#x} is outside image bounds (size={:#x})",
            entry_offset,
            image.size
        );

        // The image must be at least as large as SizeOfImage from the header.
        assert!(image.size > 0);
    }

    /// The .text section must be readable after loading.
    /// (We can't assert execute permission from userspace without running it.)
    #[test]
    fn text_section_is_readable() {
        let bytes = hello_minimal_bytes();
        let image = load(&bytes).expect("load failed");

        // Reading the first byte of the entry point must not segfault.
        // If section permissions were wrong this would crash the test process.
        let first_byte = unsafe { std::ptr::read_volatile(image.entry_point) };
        // x86-64 functions typically start with PUSH RBP (0x55) or a MOV.
        // We just assert it's a plausible instruction byte, not all-zeros.
        assert_ne!(first_byte, 0x00, "entry point looks like unmapped memory");
    }
}
