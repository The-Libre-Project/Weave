use goblin::pe::export::ExportAddressTableEntry;
use goblin::pe::PE;
use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

static PHASE_LOADED_PE: AtomicBool = AtomicBool::new(false);

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
    /// Pointer to the null-terminated array of TLS callback function pointers
    /// in the loaded image.  Null if the PE has no TLS callbacks.
    ///
    /// Each entry points to an `extern "win64" fn(usize, u32, usize)` (void
    /// return) — the same calling convention as DllMain but returning nothing.
    /// The array is terminated by a null pointer (u64 = 0 for 64-bit PEs,
    /// u32 = 0 for 32-bit PEs).
    pub tls_callbacks: *const u8,
    /// RVA and byte size of the .pdata exception table (0/0 if absent).
    /// Used by the SEH signal handler to identify which function faulted.
    pub pdata_rva: usize,
    pub pdata_size: usize,
    /// IMAGE_FILE_HEADER.Machine value from the COFF header.
    /// 0x014c = IMAGE_FILE_MACHINE_I386 (32-bit x86 PE).
    /// 0x8664 = IMAGE_FILE_MACHINE_AMD64 (64-bit x86-64 PE).
    pub machine: u16,
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
    load_impl(bytes)
}

/// Like [`load`], but also registers the resulting PE's loaded base in
/// `module_handles` under `name` (task 09 step 3).
///
/// `name` is used as the module-handle key — typically the basename of
/// the exe path (e.g. `"hello.exe"`). Pass an empty string to skip the
/// registration; this keeps the fuzzer and any future byte-only caller
/// free of side effects on the global handle table.
///
/// Existing callers of `load(bytes)` keep working unchanged — they
/// simply do not record a base.
pub fn load_with_name(bytes: &[u8], name: &str) -> Result<LoadedImage, String> {
    let image = load_impl(bytes)?;
    if !name.is_empty() {
        // HMODULE for the guest exe is the loaded base (Windows convention);
        // record both the base and a synthetic handle under the exe name so
        // kernel32 can reverse-lookup via `module_handles::base_of`.
        let base = image.base as usize;
        crate::module_handles::register_with_base(name, base);
        // Also register the path so GetFileVersionInfoSizeW / GetFileVersionInfoW
        // can locate the RT_VERSION resource without re-opening the file from disk.
        // Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoSizeExW opens
        // the file by path via LoadLibraryExW; Weave uses the already-mapped base.
        //
        // Loader: shared path-registry convention with weave-kernel32's
        // `load_library_impl` (LoadLibraryW dispatch). `register_image_path`
        // normalizes to lowercase + forward-slashes and also indexes the bare
        // basename, so a guest passing either a bare name or a full Windows
        // path resolves to the same registry entry regardless of which loader
        // site mapped the image. Any third loader site must call this too.
        crate::module_handles::register_image_path(name, base);
    }
    Ok(image)
}

fn load_impl(bytes: &[u8]) -> Result<LoadedImage, String> {
    // Goblin's TLS parser can SIGSEGV on a near-exhausted host stack
    // (observed with Foobar2000 component loading).  Running PE::parse on
    // a dedicated thread with a large stack avoids this while keeping the
    // parsed data accessible on the calling thread (via a leaked copy).
    let owned = bytes.to_vec().into_boxed_slice();
    let static_ref: &'static [u8] = Box::leak(owned);
    let pe = {
        let copy_ptr = static_ref.as_ptr() as usize;
        let copy_len = static_ref.len();
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .name("weave-pe-parse".into())
            .spawn(move || {
                let slice: &[u8] =
                    unsafe { std::slice::from_raw_parts(copy_ptr as *const u8, copy_len) };
                std::panic::catch_unwind(|| PE::parse(slice))
                    .unwrap_or_else(|_| {
                        Err(goblin::error::Error::Malformed(
                            "goblin panicked".to_string(),
                        ))
                    })
                    .map_err(|e| format!("parse error: {e}"))
            })
            .map_err(|e| format!("PE parse thread spawn: {e}"))?
            .join()
            .map_err(|_| "PE parser thread panicked".to_string())??
    };

    let opt = pe
        .header
        .optional_header
        .ok_or("no optional header — not a valid executable")?;

    let entry_rva = opt.standard_fields.address_of_entry_point as usize;

    let (base, _actual_base) = map_sections(bytes, &pe, &opt)?;

    let (tls_data, tls_data_size) = init_tls(base, bytes, &pe);

    // Compute TLS callback array address in the loaded image.
    let preferred_base = opt.windows_fields.image_base as i64;
    let actual_base = base as i64;
    let delta = actual_base - preferred_base;
    let tls_callbacks = match &pe.tls_data {
        Some(t) if t.image_tls_directory.address_of_callbacks != 0 => {
            let cb_va = t.image_tls_directory.address_of_callbacks as i64;
            ((cb_va + delta) as usize) as *const u8
        }
        _ => std::ptr::null(),
    };

    let (pdata_rva, pdata_size) = pe
        .sections
        .iter()
        .find(|s| s.name().ok() == Some(".pdata"))
        .map(|s| (s.virtual_address as usize, s.virtual_size as usize))
        .unwrap_or((0, 0));

    if !PHASE_LOADED_PE.swap(true, Ordering::Relaxed) {
        crate::progress::mark_phase("loaded_pe");
    }

    crate::module_handles::register_image_base(base as usize);
    crate::module_handles::register_image_base_alias(preferred_base as usize, base as usize);

    Ok(LoadedImage {
        base,
        size: opt.windows_fields.size_of_image as usize,
        entry_point: unsafe { base.add(entry_rva) },
        tls_data,
        tls_data_size,
        tls_callbacks,
        pdata_rva,
        pdata_size,
        machine: pe.header.coff_header.machine,
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
    // Wrap in catch_unwind: goblin's TLS/reloc parsers can panic on crafted input.
    let pe = std::panic::catch_unwind(|| PE::parse(bytes))
        .unwrap_or_else(|_| {
            Err(goblin::error::Error::Malformed(
                "goblin panicked".to_string(),
            ))
        })
        .map_err(|e| format!("parse error: {e}"))?;

    let opt = pe
        .header
        .optional_header
        .ok_or("no optional header — not a valid DLL")?;

    let (base, _actual_base) = map_sections(bytes, &pe, &opt)?;
    // Derive loaded base from the mapped pointer — this is the single source of
    // truth for where the image lives.  Using a separate `actual_base` usize
    // from map_sections is redundant and has historically caused base-address
    // confusion when the preferred base coincided with another loaded image.
    let dll_loaded_base = base as usize;
    let preferred_base = opt.windows_fields.image_base as usize;

    let mut exports: HashMap<String, usize> = HashMap::new();
    // Collect named exports and their addresses.
    for exp in &pe.exports {
        if let Some(name) = exp.name {
            // exp.rva is the raw RVA from the Export Address Table — a 32-bit
            // byte offset from image base 0, regardless of where the image
            // actually loaded.  Absolute address = dll_loaded_base + rva.
            //
            // Defensive: some DLLs (particularly debug builds or unusual
            // linkers) store preferred-base VAs rather than RVAs in the EAT.
            // If exp.rva >= preferred_base it cannot be a true RVA (no PE
            // image is that large), so strip the preferred base first.
            // Wine ref: dlls/ntdll/loader.c — export RVAs are always relative
            // to the module base; IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
            // entries are u32 RVAs, never absolute VAs in conforming PEs.
            let rva = if exp.rva >= preferred_base {
                exp.rva - preferred_base
            } else {
                exp.rva
            };
            let addr = dll_loaded_base + rva;
            exports.insert(name.to_string(), addr);
        }
    }
    // Register ordinal #N entries for named exports.
    // export_ordinal_table[i] is the ordinal for the i-th named export.
    if let Some(ed) = &pe.export_data {
        for (i, exp) in pe
            .exports
            .iter()
            .enumerate()
            .take(ed.export_ordinal_table.len())
        {
            if let Some(name) = exp.name {
                if let Some(&addr) = exports.get(name) {
                    exports.insert(format!("#{}", ed.export_ordinal_table[i]), addr);
                }
            }
        }
    }
    // Also register every entry in the export address table by ordinal.
    // This catches ordinal-only exports (no name in the Name Pointer Table)
    // and ensures ordinal imports resolve correctly even when the ordinal
    // table has gaps (e.g. portaudio_x64.dll exports at ordinals 1-34 and
    // 52-75, leaving 35-51 unused — but the address table covers them all).
    if let Some(ed) = &pe.export_data {
        for (i, entry) in ed.export_address_table.iter().enumerate() {
            let ordinal = ed.export_directory_table.ordinal_base as u16 + i as u16;
            if let ExportAddressTableEntry::ExportRVA(rva) = entry {
                let adj_rva = if *rva as usize >= preferred_base {
                    *rva as usize - preferred_base
                } else {
                    *rva as usize
                };
                exports.insert(format!("#{ordinal}"), dll_loaded_base + adj_rva);
            }
        }
    }

    // DLLs have an optional entry point (DllMain). AddressOfEntryPoint == 0
    // means the DLL has no DllMain — leave the pointer null.
    let entry_rva = opt.standard_fields.address_of_entry_point as usize;
    let entry_point = if entry_rva != 0 {
        unsafe { base.add(entry_rva) as *const u8 }
    } else {
        std::ptr::null()
    };

    let image = LoadedImage {
        base,
        size: opt.windows_fields.size_of_image as usize,
        entry_point,
        tls_data: std::ptr::null(),
        tls_data_size: 0,
        tls_callbacks: std::ptr::null(),
        pdata_rva: 0,
        pdata_size: 0,
        machine: pe.header.coff_header.machine,
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

    // Copy PE headers to base + 0.  Windows always maps the first SizeOfHeaders
    // bytes at ImageBase + 0; the resource walker reads the MZ/NT headers there.
    let headers_size = opt.windows_fields.size_of_headers as usize;
    let headers_copy = headers_size.min(bytes.len());
    if headers_copy > 0 {
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), base, headers_copy);
        }
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

    // Defensive .data init diagnostic (loop-arcs/E3-M5b-data-init-guard.md).
    // The preceding loop copies RS bytes per section from file offset RO to VA,
    // then zeros BSS tail (VS - RS).
    //
    // Q-Dir .data: VA=0x146000 VS=0x18e08 RS=0x3600 RO=0x143c00
    //   - RVA 0x146e70 (off=0xe70): in file-backed portion => correct PE value 0xa.
    //   - RVA 0x1531e0 (off=0xd1e0): past RS => BSS => correct value is zero.
    //     On-disk 0x13e4d0 at file off 0x150de0 belongs to .pdata (RVA 0x168be0).
    if image_size == 0x001f_3000 {
        // Q-Dir only — safe, no 0x78xxx code RVAs touched.
        let counter = unsafe { ptr::read_volatile(base.add(0x146e70) as *const u32) };
        let freelist_head = unsafe { ptr::read_volatile(base.add(0x1531e0) as *const u64) };
        if counter != 0xa || freelist_head != 0 {
            eprintln!(
                "weave: .data init DIAG: RVA0x146e70=0x{counter:x} want 0xa; RVA0x1531e0=0x{freelist_head:x} want 0 (BSS)"
            );
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

/// Walk and call TLS callbacks for the given loaded image.
///
/// Each callback is called with (DllHandle, DLL_PROCESS_ATTACH, 0).
/// The array is terminated by a null pointer.
///
/// Safe to call on an image with no TLS callbacks (returns immediately).
pub fn run_tls_callbacks(image: &LoadedImage) {
    // Wine ref: dlls/ntdll/loader.c — LdrpCallTlsInitializers calls each
    // TLS callback with (DllHandle=module_base, Reason=DLL_PROCESS_ATTACH,
    // Reserved=0) in the order they appear in the callback array.
    let ptr = image.tls_callbacks;
    if ptr.is_null() {
        return;
    }

    let base = image.base as usize;
    let reason: u32 = 1; // DLL_PROCESS_ATTACH
    let reserved: usize = 0;

    let is_64 = image.machine == 0x8664; // IMAGE_FILE_MACHINE_AMD64
    let stride = if is_64 { 8usize } else { 4usize };

    let mut offset = 0usize;
    loop {
        let entry_ptr = unsafe { ptr.add(offset) };
        let va: u64 = if is_64 {
            unsafe { *(entry_ptr as *const u64) }
        } else {
            unsafe { *(entry_ptr as *const u32) as u64 }
        };

        if va == 0 {
            break;
        }

        #[cfg(target_os = "linux")]
        type TlsCb = unsafe extern "win64" fn(usize, u32, usize);
        #[cfg(not(target_os = "linux"))]
        type TlsCb = unsafe extern "C" fn(usize, u32, usize);
        let func: TlsCb = unsafe { std::mem::transmute(va as usize) };
        unsafe { func(base, reason, reserved) };

        offset += stride;
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

    // Security: addr_of_index is a VA from the PE file. Only write through it
    // if it falls within the mapped image — otherwise a crafted PE could use
    // this to write 0 to an arbitrary kernel address.
    let image_start = base as usize;
    let image_end = image_start + (bytes.len()); // conservative bound
    if addr_of_index != 0
        && addr_of_index >= image_start
        && addr_of_index.saturating_add(4) <= image_end
    {
        unsafe { *(addr_of_index as *mut u32) = 0 };
    }

    let raw_size = raw_end.saturating_sub(raw_start);
    if raw_size == 0 || raw_start == 0 {
        return (std::ptr::null(), 0);
    }

    let _ = bytes;
    (raw_start as *const u8, raw_size)
}

/// Walk the `.reloc` section and add `delta` to every 64-bit absolute address.
fn apply_relocations(base: *mut u8, pe: &PE, delta: i64) -> Result<(), String> {
    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| "apply_relocations: PE has no optional header".to_string())?;
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

    // ── TLS callbacks ──────────────────────────────────────────────────

    use std::sync::atomic::{AtomicBool, Ordering};
    static TLS_CB_CALLED: AtomicBool = AtomicBool::new(false);

    #[cfg(target_os = "linux")]
    extern "win64" fn test_tls_callback(_hinst: usize, reason: u32, _reserved: usize) {
        TLS_CB_CALLED.store(true, Ordering::SeqCst);
        assert_eq!(reason, 1, "TLS callback reason must be DLL_PROCESS_ATTACH");
    }

    #[cfg(not(target_os = "linux"))]
    extern "C" fn test_tls_callback(_hinst: usize, reason: u32, _reserved: usize) {
        TLS_CB_CALLED.store(true, Ordering::SeqCst);
        assert_eq!(reason, 1, "TLS callback reason must be DLL_PROCESS_ATTACH");
    }

    #[test]
    fn tls_callbacks_fire() {
        TLS_CB_CALLED.store(false, Ordering::SeqCst);

        // Allocate a fake image base (any readable/writable page).
        let page_size = 4096usize;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED, "mmap for test image base failed");

        // Build a callback array: [test_fn_ptr, null_terminator]
        let cb_addr = test_tls_callback as *const () as usize;
        let callback_array: Vec<u64> = vec![cb_addr as u64, 0u64];
        let callbacks_ptr = callback_array.as_ptr() as *const u8;

        let image = LoadedImage {
            base: base as *mut u8,
            size: page_size,
            entry_point: std::ptr::null(),
            tls_data: std::ptr::null(),
            tls_data_size: 0,
            tls_callbacks: callbacks_ptr,
            pdata_rva: 0,
            pdata_size: 0,
            machine: 0x8664, // IMAGE_FILE_MACHINE_AMD64
        };

        run_tls_callbacks(&image);

        assert!(
            TLS_CB_CALLED.load(Ordering::SeqCst),
            "TLS callback must have been called"
        );

        // Prevent LoadedImage::drop from munmap'ing our manually-set-up base
        // (the callback_array vec on the heap is dropped normally).
        std::mem::forget(image);
        unsafe { libc::munmap(base, page_size) };
    }

    #[test]
    fn tls_callbacks_noop_when_null() {
        // Must not crash or panic when tls_callbacks is null.
        let page_size = 4096usize;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED, "mmap for test image base failed");

        let image = LoadedImage {
            base: base as *mut u8,
            size: page_size,
            entry_point: std::ptr::null(),
            tls_data: std::ptr::null(),
            tls_data_size: 0,
            tls_callbacks: std::ptr::null(),
            pdata_rva: 0,
            pdata_size: 0,
            machine: 0x8664,
        };

        run_tls_callbacks(&image);

        std::mem::forget(image);
        unsafe { libc::munmap(base, page_size) };
    }
}
