//! IAT (Import Address Table) patching.
//!
//! After loading a PE binary into memory, every imported function's slot in the
//! IAT still contains a hint/name pointer from the original file. This module
//! walks the import descriptors, looks up each function in our stub table, and
//! overwrites the IAT entries with Rust function pointers.
//!
//! The IAT lives in the (normally read-only) `.idata` section. We briefly
//! mprotect each IAT page to read+write, write the stub address, then restore
//! it to read-only.

use goblin::pe::PE;

/// IMAGE_IMPORT_DESCRIPTOR — one entry per imported DLL (20 bytes, C layout).
#[repr(C)]
struct ImportDescriptor {
    original_first_thunk: u32, // RVA of Import Name Table (INT)
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,        // RVA of the DLL name string
    first_thunk: u32, // RVA of Import Address Table (IAT) — we patch this
}

/// Resolve all imports in the loaded image.
///
/// `bytes` is the raw PE file (used to locate the import directory RVA via
/// goblin). `base` is the start of the loaded image in our process memory.
/// `resolve` maps `(dll_name, function_name)` to a function pointer address.
/// # Safety
/// `base` must point to a fully loaded PE image with valid import descriptors.
pub unsafe fn patch(
    bytes: &[u8],
    base: *mut u8,
    resolve: impl Fn(&str, &str) -> Option<usize>,
) -> Result<(), String> {
    patch_inner(bytes, base, resolve, false, |_, _, _| {})
}

/// Safe no-op stub written into IAT slots that we cannot resolve.
///
/// Returns 0 (NULL/FALSE/0) for any call signature.  This prevents a hard
/// crash when pre-loaded DLLs (e.g. DXVK) call an import that Weave has no
/// stub for — they will get a failure result instead of jumping into garbage.
///
/// Logs the caller's return address AND the value of rax at call time.  For
/// indirect virtual calls of the form `call [rax+N]`, rax holds the vtable
/// pointer and rax+N is the IAT slot — logging rax lets us identify which
/// specific IAT slot was dispatched through.
///
/// Must be a naked function: a normal function prologue adjusts RSP before
/// any inline asm runs, so `[rsp]` would read a saved register or shadow
/// space rather than the actual return address pushed by the caller's CALL.
#[cfg(target_arch = "x86_64")]
#[allow(unused)]
#[unsafe(naked)]
pub unsafe extern "win64" fn unresolved_import_stub() -> u64 {
    // On entry (naked — no prologue):
    //   [rsp] = return address of caller
    //   rax   = whatever the caller had in rax (for `call [rax+N]` patterns,
    //           this is the vtable/function-table pointer; rax+N is the IAT slot)
    //   rcx, rdx, r8, r9 = caller's first four arguments (preserved for ABI)
    core::arch::naked_asm!(
        // Save rax (vtable pointer) before we clobber it reading [rsp].
        "mov  r10, rax",
        // Read return address from top of stack.
        "mov  rax, [rsp]",
        // Allocate shadow space + 16-byte align.
        "sub  rsp, 0x28",
        // arg1 (rcx) = return address
        "mov  rcx, rax",
        // arg2 (rdx) = original rax (vtable / base pointer)
        "mov  rdx, r10",
        "call {log}",
        // Return 0 for all unresolved imports.
        "xor  eax, eax",
        "add  rsp, 0x28",
        "ret",
        log = sym unresolved_import_stub_log,
    )
}

/// Logging half of `unresolved_import_stub` — called from the naked trampoline.
///
/// `ret_addr` is the instruction after the call into this stub (inside the
/// calling code).  `rax_at_call` is the value of rax at stub entry — for a
/// virtual-dispatch pattern `call [rax+N]`, this is the vtable pointer and
/// `rax_at_call + N` is the IAT slot that was patched.
extern "win64" fn unresolved_import_stub_log(ret_addr: usize, rax_at_call: usize) {
    eprintln!(
        "weave: unresolved_import_stub called (ret={ret_addr:#x}, rax={rax_at_call:#x})"
    );
}

/// Like `patch`, but skips unresolved imports rather than failing.
///
/// `on_miss` is called for each import that could not be resolved, allowing
/// the caller to log or track missing symbols. Unresolved IAT slots are
/// patched with the address of `unresolved_import_stub` (returns 0) so that
/// calling an unresolved function is safe — callers see a failure return
/// rather than jumping into garbage and crashing.
///
/// Use this when loading pre-built DLLs where some imports may not be needed
/// at runtime.
///
/// # Safety
/// `base` must point to a fully loaded PE image with valid import descriptors.
/// The `on_miss` callback receives `(dll_name, func_name, iat_slot_va)` where
/// `iat_slot_va` is the absolute virtual address of the unresolved IAT slot
/// (image_base + RVA).  This can be used to correlate unresolved imports with
/// observed `unresolved_import_stub` calls: if a stub call logs
/// `rax=V`, the calling instruction was `call [rax+N]`, so the IAT slot is
/// `V+N`.  Comparing `V+N` against the reported `iat_slot_va` values
/// identifies which specific import was dispatched.
pub unsafe fn patch_best_effort(
    bytes: &[u8],
    base: *mut u8,
    resolve: impl Fn(&str, &str) -> Option<usize>,
    on_miss: impl FnMut(&str, &str, usize),
) {
    let _ = patch_inner(bytes, base, resolve, true, on_miss);
}

unsafe fn patch_inner(
    bytes: &[u8],
    base: *mut u8,
    resolve: impl Fn(&str, &str) -> Option<usize>,
    lenient: bool,
    mut on_miss: impl FnMut(&str, &str, usize),
) -> Result<(), String> {
    let pe = PE::parse(bytes).map_err(|e| format!("IAT patch: parse error: {e}"))?;

    let opt = pe
        .header
        .optional_header
        .ok_or("IAT patch: no optional header")?;

    let import_rva = match opt.data_directories.get_import_table() {
        Some(d) if d.size > 0 => d.virtual_address as usize,
        _ => return Ok(()), // no imports
    };

    // Walk IMAGE_IMPORT_DESCRIPTORs from the loaded image.
    // The array is null-terminated (all-zero entry marks the end).
    let mut desc_offset = import_rva;
    loop {
        let desc = unsafe { &*(base.add(desc_offset) as *const ImportDescriptor) };

        // Null terminator: first_thunk == 0 signals end of the descriptor array.
        if desc.first_thunk == 0 {
            break;
        }

        let dll_name = unsafe { read_cstr(base.add(desc.name as usize)) };

        // Use OriginalFirstThunk (INT) to read import names.
        // Fall back to FirstThunk if the linker didn't write an INT.
        let int_rva = if desc.original_first_thunk != 0 {
            desc.original_first_thunk as usize
        } else {
            desc.first_thunk as usize
        };
        let iat_rva = desc.first_thunk as usize;

        // Temporarily make the IAT page(s) writable.
        let iat_va = unsafe { base.add(iat_rva) };
        let page_start = page_align_down(iat_va as usize);
        // Cover at least 2 pages in case the IAT straddles a page boundary.
        unsafe {
            libc::mprotect(
                page_start as *mut libc::c_void,
                PAGE * 2,
                libc::PROT_READ | libc::PROT_WRITE,
            );
        }

        // Walk INT + IAT in lock-step.
        // Use read_unaligned / write_unaligned throughout: the PE spec does not
        // guarantee 8-byte alignment of thunk arrays (they live in .idata which
        // may only be 4-byte aligned), and Rust debug builds trap misaligned
        // pointer dereferences.
        let mut i = 0usize;
        loop {
            let thunk =
                unsafe { std::ptr::read_unaligned(base.add(int_rva + i * 8) as *const u64) };
            if thunk == 0 {
                break; // end of this DLL's import list
            }

            let func_name = if thunk >> 63 != 0 {
                // Ordinal import — format as "#N"
                format!("#{}", thunk & 0xFFFF)
            } else {
                // Named import — thunk is an RVA to IMAGE_IMPORT_BY_NAME.
                // Skip the 2-byte hint field, then read the null-terminated name.
                let name_rva = (thunk & 0x7FFF_FFFF_FFFF_FFFF) as usize;
                unsafe { read_cstr(base.add(name_rva + 2)) }
            };

            match resolve(&dll_name, &func_name) {
                Some(addr) => unsafe {
                    std::ptr::write_unaligned(base.add(iat_rva + i * 8) as *mut u64, addr as u64);
                },
                None if lenient => {
                    let iat_slot_va = base as usize + iat_rva + i * 8;
                    on_miss(&dll_name, &func_name, iat_slot_va);
                    // Write a safe no-op stub so the DLL won't crash if it
                    // calls this import.  The stub returns 0 (NULL/FALSE/error)
                    // which the caller should treat as a failure.
                    #[cfg(target_arch = "x86_64")]
                    unsafe {
                        std::ptr::write_unaligned(
                            base.add(iat_rva + i * 8) as *mut u64,
                            unresolved_import_stub as *const () as u64,
                        );
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    unsafe {
                        std::ptr::write_unaligned(base.add(iat_rva + i * 8) as *mut u64, 0);
                    }
                }
                None => {
                    return Err(format!("unresolved import: {dll_name}!{func_name}"));
                }
            }

            i += 1;
        }

        // Restore IAT to read-only.
        unsafe {
            libc::mprotect(page_start as *mut libc::c_void, PAGE * 2, libc::PROT_READ);
        }

        desc_offset += std::mem::size_of::<ImportDescriptor>();
    }

    Ok(())
}

/// Read a null-terminated ASCII string from a raw pointer.
///
/// # Safety
/// `ptr` must point to valid memory containing a null-terminated string.
unsafe fn read_cstr(ptr: *const u8) -> String {
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
}

const PAGE: usize = 4096;

fn page_align_down(addr: usize) -> usize {
    addr & !(PAGE - 1)
}
