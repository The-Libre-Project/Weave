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
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Global map: unresolved IAT slot VA → "dll::func".
/// Populated at `patch_best_effort` time; queried by `unresolved_import_stub_log`
/// at call time to identify which function fired.
static UNRESOLVED_SLOT_MAP: OnceLock<Mutex<HashMap<usize, String>>> = OnceLock::new();

fn slot_map() -> &'static Mutex<HashMap<usize, String>> {
    UNRESOLVED_SLOT_MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up the function name for an unresolved IAT slot by its absolute VA.
pub fn lookup_unresolved_slot(slot_va: usize) -> Option<String> {
    slot_map().lock().ok()?.get(&slot_va).cloned()
}

// ---------------------------------------------------------------------------
// IAT-every-call tracer
// ---------------------------------------------------------------------------
//
// Opt-in at process start via `WEAVE_IAT_TRACE=1`.  When enabled, each IAT
// slot that Weave successfully resolves is redirected through
// `trace_import_stub` instead of being written with the real function
// pointer.  The stub logs `weave/iat-trace: <dll>::<func>` to stderr and
// tail-jmps into the real function, preserving all win64 register/stack
// arguments and the real function's return value.
//
// When the env var is unset the code paths here are never entered — the
// existing `patch_best_effort` behavior is unchanged and zero-overhead.
//
// Missing evidence this unlocks: Task 01b's wget SIGABRT investigation needs
// per-call IAT ordering, which the existing `unresolved_import_stub` log
// only provides for *unresolved* calls.  The tracer provides the same for
// *resolved* calls.

/// Global map: resolved IAT slot VA → ("dll::func", real function pointer).
/// Populated in `patch_inner` when the tracer is enabled; queried by
/// `trace_import_stub_log` at call time to look up both the display name and
/// the real function pointer to tail-jmp into.
static RESOLVED_SLOT_MAP: OnceLock<Mutex<HashMap<usize, (String, usize)>>> = OnceLock::new();

fn resolved_slot_map() -> &'static Mutex<HashMap<usize, (String, usize)>> {
    RESOLVED_SLOT_MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Cache the env-var read so we don't do a syscall-ish lookup on every call.
static TRACER_ENABLED: OnceLock<bool> = OnceLock::new();

/// Returns true iff `WEAVE_IAT_TRACE=1` was set when this process started.
/// The result is cached after first call.
pub fn tracer_enabled() -> bool {
    *TRACER_ENABLED.get_or_init(|| {
        std::env::var("WEAVE_IAT_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Test-only helper: record a resolved slot as if the tracer had patched it.
/// Exposed for the unit tests in this module so they can drive
/// `trace_import_stub_log` without needing a real PE.
#[cfg(test)]
fn tracer_record_for_test(slot_va: usize, name: String, real_fn: usize) {
    if let Ok(mut map) = resolved_slot_map().lock() {
        map.insert(slot_va, (name, real_fn));
    }
}

/// Fallback target used when the tracer stub fires but the resolved-slot
/// lookup fails (slot decode failed, map entry missing, etc.).  Returns 0
/// for any signature, mirroring `unresolved_import_stub`'s safety model:
/// the calling code sees a failure return instead of jumping into garbage.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "win64" fn trace_lookup_miss_stub() -> u64 {
    core::arch::naked_asm!("xor eax, eax", "ret",)
}

/// Logging half of `trace_import_stub` — called from the naked trampoline.
///
/// `ret_addr` is the instruction after the CALL that reached this stub (i.e.
/// inside the guest code); `rax_at_call` is the caller's rax at the moment
/// of entry.  For the standard `call [rax+N]` IAT dispatch pattern used by
/// most PE code, `rax_at_call + N` is the IAT slot VA.
///
/// Decodes the CALL bytes before `ret_addr`, looks up `(name, real_fn)` in
/// `RESOLVED_SLOT_MAP`, emits one stderr line, and returns the real function
/// pointer to tail-jmp into.
///
/// If decoding or lookup fails, falls back to `trace_lookup_miss_stub` so
/// the caller sees a safe 0-return rather than a crash.
///
/// This function is NOT `#[cfg(target_arch = "x86_64")]`-gated so the unit
/// tests in this file can exercise its decode+lookup logic on aarch64 macOS
/// hosts.  The naked tail-jmp trampoline that calls it IS x86_64-gated.
/// On non-x86_64 hosts the ABI falls back to `extern "C"`; the trampoline
/// does not exist on those targets so the ABI choice is irrelevant outside
/// unit-test code paths.
#[cfg(target_arch = "x86_64")]
extern "win64" fn trace_import_stub_log(ret_addr: usize, rax_at_call: usize) -> usize {
    trace_import_stub_log_impl(ret_addr, rax_at_call)
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn trace_import_stub_log(ret_addr: usize, rax_at_call: usize) -> usize {
    trace_import_stub_log_impl(ret_addr, rax_at_call)
}

fn trace_import_stub_log_impl(ret_addr: usize, rax_at_call: usize) -> usize {
    let slot_va = unsafe { decode_call_iat_slot(ret_addr, rax_at_call) };
    let entry = slot_va.and_then(|va| {
        resolved_slot_map()
            .lock()
            .ok()
            .and_then(|m| m.get(&va).cloned())
    });
    match entry {
        Some((name, real_fn)) => {
            eprintln!("weave/iat-trace: {name}");
            real_fn
        }
        None => {
            eprintln!(
                "weave/iat-trace: <lookup-miss> (ret={ret_addr:#x} rax={rax_at_call:#x} slot={:#x})",
                slot_va.unwrap_or(0)
            );
            #[cfg(target_arch = "x86_64")]
            {
                trace_lookup_miss_stub as *const () as usize
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                0
            }
        }
    }
}

/// Naked tracer trampoline written into IAT slots when
/// `WEAVE_IAT_TRACE=1`.
///
/// On entry (just like `unresolved_import_stub` — see its comment for the
/// authoritative template):
///   [rsp] = return address of caller
///   rax   = caller's rax (for `call [rax+N]` patterns this is the vtable /
///           IAT-base pointer; rax+N is the IAT slot)
///   rcx, rdx, r8, r9    = caller's first four integer args
///   xmm0, xmm1, xmm2, xmm3 = caller's first four float args
///   stack args above the return address = unchanged
///
/// win64 ABI notes this stub relies on:
///   - rcx/rdx/r8/r9 AND xmm0..xmm3 are volatile — any C-ABI call out of
///     this stub is permitted to clobber them.  We therefore save/restore
///     all eight before/after the `trace_import_stub_log` call.
///   - On entry rsp is 8-byte-misaligned modulo 16 (caller's CALL pushed
///     the 8-byte return addr onto a 16-aligned stack).  Our `sub rsp, 0xA8`
///     leaves rsp 16-byte aligned, satisfying the callee's alignment
///     precondition.
///   - xmm saves use `movdqu`: `movdqa` would require the dest to be
///     16-aligned; `[rsp+0x40]` is 16-aligned after the 0xA8 adjustment
///     but `movdqu` is used for defensiveness (identical correctness, near-
///     identical perf on modern x86).
///   - Before the tail-`jmp`, the 0xA8 scratch frame is fully unwound so
///     [rsp] is once again the original return address.  This makes the
///     real function's own `ret` return directly to the original caller,
///     yielding a zero-frame tail-call.
///
/// # Safety
/// Must only be written into an IAT slot by `patch_inner` when
/// `tracer_enabled()` was true at patch time.  Requires that the slot VA
/// is resolvable via `decode_call_iat_slot` from the caller's return
/// address — true for all standard PE IAT dispatch patterns.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub unsafe extern "win64" fn trace_import_stub() -> u64 {
    core::arch::naked_asm!(
        // ------------------------------------------------------------------
        // Prologue: save return-addr-derived inputs to log, allocate scratch.
        // ------------------------------------------------------------------
        // Stash caller's rax (IAT base for `call [rax+N]`) in r10 before we
        // clobber rax reading [rsp].  r10 is volatile and unused by callers.
        "mov  r10, rax",
        // Read return address from top of stack.
        "mov  rax, [rsp]",
        // Allocate 0xA8 of scratch.  rsp was 8-mod-16 on entry; 0xA8 is
        // 8-mod-16, so rsp becomes 0-mod-16 — callee alignment OK.
        "sub  rsp, 0xA8",
        // ------------------------------------------------------------------
        // Save volatile regs the log callout may clobber.
        //   [rsp+0x00..0x1F] shadow space for callee (written by it, not us)
        //   [rsp+0x20] rcx  [rsp+0x28] rdx  [rsp+0x30] r8  [rsp+0x38] r9
        //   [rsp+0x40..0x4F] xmm0
        //   [rsp+0x50..0x5F] xmm1
        //   [rsp+0x60..0x6F] xmm2
        //   [rsp+0x70..0x7F] xmm3
        //   [rsp+0x80] real_fn slot (filled from log return)
        // ------------------------------------------------------------------
        "mov  [rsp+0x20], rcx",
        "mov  [rsp+0x28], rdx",
        "mov  [rsp+0x30], r8",
        "mov  [rsp+0x38], r9",
        "movdqu [rsp+0x40], xmm0",
        "movdqu [rsp+0x50], xmm1",
        "movdqu [rsp+0x60], xmm2",
        "movdqu [rsp+0x70], xmm3",
        // ------------------------------------------------------------------
        // Call trace_import_stub_log(ret_addr, rax_at_call) -> real_fn.
        // arg1 (rcx) = return address (still in rax from above)
        // arg2 (rdx) = original rax (stashed in r10)
        // ------------------------------------------------------------------
        "mov  rcx, rax",
        "mov  rdx, r10",
        "call {log}",
        // Return value (real_fn pointer) is in rax — stash it; we need rax
        // free while restoring guest regs, and we cannot leave it clobbered
        // (the guest's `call [rax+N]` convention means rax was a parameter
        // to the dispatch, not an arg to the callee — the callee itself
        // treats rax as volatile, so clobbering is fine, but we still need
        // the value somewhere across the restore.)
        "mov  [rsp+0x80], rax",
        // ------------------------------------------------------------------
        // Restore volatile regs exactly as the guest caller left them.
        // ------------------------------------------------------------------
        "mov  rcx, [rsp+0x20]",
        "mov  rdx, [rsp+0x28]",
        "mov  r8,  [rsp+0x30]",
        "mov  r9,  [rsp+0x38]",
        "movdqu xmm0, [rsp+0x40]",
        "movdqu xmm1, [rsp+0x50]",
        "movdqu xmm2, [rsp+0x60]",
        "movdqu xmm3, [rsp+0x70]",
        // Load real_fn into a scratch register (r10 is volatile, unused by
        // callee convention for args).
        "mov  r10, [rsp+0x80]",
        // ------------------------------------------------------------------
        // Epilogue: unwind scratch so [rsp] is the original ret addr again,
        // then tail-jmp.  The real function's final `ret` will pop that
        // ret addr and return directly to the guest caller.
        // ------------------------------------------------------------------
        "add  rsp, 0xA8",
        "jmp  r10",
        log = sym trace_import_stub_log,
    )
}

/// Decode a CALL instruction immediately before `ret_addr` to recover the IAT
/// slot VA.  Handles four encodings:
/// - `FF 90 dd dd dd dd` (6 bytes, `call [rax+disp32]`)
/// - `FF 15 dd dd dd dd` (6 bytes, `call [rip+disp32]` — MinGW's dominant
///   IAT dispatch form on x86_64; the slot is at `ret_addr + disp32`)
/// - `FF 50 dd`          (3 bytes, `call [rax+disp8]`)
/// - `FF 10`             (2 bytes, `call [rax]`)
///
/// Returns `None` if the bytes don't match any known pattern or the address
/// range is inaccessible.
///
/// # Safety
/// `ret_addr` must be a valid mapped address with at least 6 readable bytes
/// preceding it.  This is always true when called from `unresolved_import_stub`
/// because `ret_addr` came from `[rsp]` inside a real CALL instruction.
///
/// Not `#[cfg]`-gated: the decode logic is pure byte arithmetic and has no
/// architecture-specific behavior, so it's compiled on all targets.  This
/// allows the unit tests in this file to exercise it on aarch64 macOS host
/// builds.  On non-x86_64 targets the only concern is that a caller must
/// supply bytes that match one of the four patterns and a `ret_addr` that
/// is a valid pointer — the function does not assume the host is x86.
unsafe fn decode_call_iat_slot(ret_addr: usize, rax: usize) -> Option<usize> {
    if ret_addr < 6 {
        return None;
    }
    // Read the 6 bytes immediately before ret_addr.
    //   bytes[0] = *(ret_addr - 6)
    //   bytes[5] = *(ret_addr - 1)
    let bytes = unsafe { std::slice::from_raw_parts((ret_addr - 6) as *const u8, 6) };

    // FF 90 dd dd dd dd → call [rax+disp32]  (6 bytes, starts at ret_addr-6)
    if bytes[0] == 0xFF && bytes[1] == 0x90 {
        let disp = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        return Some((rax as i64 + disp as i64) as usize);
    }

    // FF 15 dd dd dd dd → call [rip+disp32]  (6 bytes, starts at ret_addr-6)
    // This is the dominant MinGW x86_64 IAT dispatch encoding.  RIP at decode
    // time of the CALL is the address of the NEXT instruction = `ret_addr`.
    // So `slot_va = ret_addr + disp32`.  `rax` is ignored for this form.
    if bytes[0] == 0xFF && bytes[1] == 0x15 {
        let disp = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        return Some(ret_addr.wrapping_add_signed(disp as isize));
    }

    // FF 50 dd → call [rax+disp8]  (3 bytes, starts at ret_addr-3)
    if bytes[3] == 0xFF && bytes[4] == 0x50 {
        let disp = bytes[5] as i8;
        return Some((rax as i64 + disp as i64) as usize);
    }

    // FF 10 → call [rax]  (2 bytes, starts at ret_addr-2)
    if bytes[4] == 0xFF && bytes[5] == 0x10 {
        return Some(rax);
    }

    None
}

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
///
/// # Safety
///
/// Must be called via an IAT entry patched by Weave's loader. Assumes:
/// - Stack is 8-byte aligned before entry (ABI requirement for win64 calls)
/// - Caller passed a valid return address on the stack
/// - RAX holds the IAT slot address or vtable pointer (preserved by loader)
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
/// `call [rax+N]` pattern, this is the table base and `rax_at_call + N` is
/// the IAT slot.  We decode the CALL bytes before `ret_addr` to recover N,
/// then look up the slot in the global map to log the function name directly.
#[cfg(target_arch = "x86_64")]
extern "win64" fn unresolved_import_stub_log(ret_addr: usize, rax_at_call: usize) {
    let slot_va = unsafe { decode_call_iat_slot(ret_addr, rax_at_call) };
    let name = slot_va.and_then(lookup_unresolved_slot);
    match name {
        Some(n) => eprintln!(
            "weave: unresolved: {n} (ret={ret_addr:#x} rax={rax_at_call:#x})"
        ),
        None => eprintln!(
            "weave: unresolved import stub fired (ret={ret_addr:#x} rax={rax_at_call:#x} slot={:#x})",
            slot_va.unwrap_or(0)
        ),
    }
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

        // Diagnostic: log which DLL we are patching and how many imports it has.
        // TODO: remove after curl_ws2_gate passes.
        if dll_name.to_ascii_lowercase().contains("crt-runtime")
            || dll_name.to_ascii_lowercase().contains("kernel32")
        {
            eprintln!("weave/iat: patching {dll_name} INT={int_rva:#x} IAT={iat_rva:#x} first_thunk_in_desc={:#x} orig={:#x}", desc.first_thunk, desc.original_first_thunk);
        }

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
                    // IAT-every-call tracer: if WEAVE_IAT_TRACE=1 was set at
                    // process start, record (slot_va, name, real_fn) and
                    // write the tracer trampoline into the IAT slot instead
                    // of `addr`.  The trampoline logs, then tail-jmps into
                    // `addr`.  Default path is unchanged.
                    #[cfg(target_arch = "x86_64")]
                    let write_addr: u64 = if tracer_enabled() {
                        let slot_va = base as usize + iat_rva + i * 8;
                        if let Ok(mut map) = resolved_slot_map().lock() {
                            map.insert(slot_va, (format!("{dll_name}::{func_name}"), addr));
                        }
                        trace_import_stub as *const () as u64
                    } else {
                        addr as u64
                    };
                    #[cfg(not(target_arch = "x86_64"))]
                    let write_addr: u64 = addr as u64;

                    std::ptr::write_unaligned(base.add(iat_rva + i * 8) as *mut u64, write_addr);
                    // Diagnostic: log ALL kernel32 and CRT patches to confirm CreateThread resolution.
                    // TODO: remove after curl_ws2_gate passes.
                    if dll_name.to_ascii_lowercase().contains("kernel32")
                        || func_name == "__p___argc"
                        || func_name == "_configure_narrow_argv"
                        || func_name == "_initterm"
                    {
                        eprintln!("weave/iat: patched {dll_name}!{func_name} → {addr:#x} at IAT slot {:#x}", base as usize + iat_rva + i * 8);
                    }
                },
                None if lenient => {
                    let iat_slot_va = base as usize + iat_rva + i * 8;
                    on_miss(&dll_name, &func_name, iat_slot_va);
                    // Record in global map so unresolved_import_stub_log can
                    // identify the function name at call time.
                    if let Ok(mut map) = slot_map().lock() {
                        map.insert(iat_slot_va, format!("{dll_name}::{func_name}"));
                    }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an in-memory byte buffer ending in a `call [rax+disp32]`
    /// instruction whose effective slot VA is `slot_va` when rax == `rax_base`.
    /// Returns (buffer, ret_addr) where ret_addr points just past the CALL.
    fn build_call_iat_disp32(rax_base: usize, slot_va: usize) -> (Vec<u8>, usize) {
        let disp = (slot_va as i64 - rax_base as i64) as i32;
        let mut buf: Vec<u8> = Vec::with_capacity(32);
        // 16 leading NOPs so (ret_addr - 6) is well within the buffer.
        buf.extend(std::iter::repeat(0x90u8).take(16));
        // FF 90 dd dd dd dd : call [rax + disp32]
        buf.push(0xFF);
        buf.push(0x90);
        buf.extend_from_slice(&disp.to_le_bytes());
        let ret_addr = buf.as_ptr() as usize + buf.len();
        (buf, ret_addr)
    }

    #[test]
    fn decode_call_iat_slot_disp32_roundtrip() {
        let rax_base = 0x1000_0000usize;
        let slot_va = 0x1000_0080usize;
        let (_buf, ret_addr) = build_call_iat_disp32(rax_base, slot_va);
        let decoded = unsafe { decode_call_iat_slot(ret_addr, rax_base) };
        assert_eq!(decoded, Some(slot_va));
    }

    /// Build a buffer ending in `FF 15 disp32` where disp32 is chosen after
    /// the buffer is allocated so that `ret_addr + disp32 == target_slot_va`.
    /// Takes a closure that computes the target from the known ret_addr.
    fn build_call_iat_rip_relative(
        compute_slot: impl Fn(usize) -> usize,
    ) -> (Vec<u8>, usize, usize) {
        let mut buf: Vec<u8> = Vec::with_capacity(32);
        buf.extend(std::iter::repeat(0x90u8).take(16));
        buf.push(0xFF);
        buf.push(0x15);
        buf.extend_from_slice(&0i32.to_le_bytes());
        let ret_addr = buf.as_ptr() as usize + buf.len();
        let slot_va = compute_slot(ret_addr);
        let disp = (slot_va as isize - ret_addr as isize) as i32;
        let len = buf.len();
        buf[len - 4..len].copy_from_slice(&disp.to_le_bytes());
        (buf, ret_addr, slot_va)
    }

    #[test]
    fn decode_call_iat_slot_rip_disp32_positive() {
        // Positive disp32: slot sits ahead of ret_addr.
        let (_buf, ret_addr, slot_va) = build_call_iat_rip_relative(|ret_addr| ret_addr + 0x4000);
        // rax is ignored for FF 15 — pass a bogus value to prove it.
        let decoded = unsafe { decode_call_iat_slot(ret_addr, 0xDEAD_BEEFusize) };
        assert_eq!(decoded, Some(slot_va));
    }

    #[test]
    fn decode_call_iat_slot_rip_disp32_negative() {
        // Negative disp32: slot sits behind ret_addr.
        let (_buf, ret_addr, slot_va) =
            build_call_iat_rip_relative(|ret_addr| ret_addr.wrapping_sub(0x1000));
        let decoded = unsafe { decode_call_iat_slot(ret_addr, 0) };
        assert_eq!(decoded, Some(slot_va));
    }

    #[test]
    fn decode_call_iat_slot_unmatched_pattern_returns_none() {
        // A buffer of bytes that matches none of the four known CALL encodings.
        // Use sixteen 0x90 NOPs so (ret_addr-6..ret_addr) is all 0x90 —
        // which is not a valid CALL opcode and should decode to None.
        let buf: Vec<u8> = vec![0x90u8; 32];
        let ret_addr = buf.as_ptr() as usize + buf.len();
        let decoded = unsafe { decode_call_iat_slot(ret_addr, 0x1000_0000usize) };
        assert_eq!(decoded, None);
    }

    #[test]
    fn trace_import_stub_log_returns_real_fn_on_hit() {
        // Populate the resolved-slot map with a synthetic entry, then call
        // trace_import_stub_log with a ret_addr whose preceding bytes decode
        // to that slot VA.  Assert the returned pointer matches real_fn.
        let rax_base = 0x2000_0000usize;
        let slot_va = 0x2000_0040usize;
        let (_buf, ret_addr) = build_call_iat_disp32(rax_base, slot_va);

        let real_fn: usize = 0xDEAD_BEEF_CAFE_F00Dusize;
        tracer_record_for_test(slot_va, "test_dll.dll::TestFunc".to_string(), real_fn);

        let returned = trace_import_stub_log(ret_addr, rax_base);
        assert_eq!(returned, real_fn);
    }

    #[test]
    fn trace_import_stub_log_returns_miss_stub_on_decode_failure() {
        // ret_addr=0 cannot possibly decode — the function should fall back
        // to a non-crashing pointer.  We only check that it returns a
        // non-zero address on x86_64 (the miss stub) or 0 elsewhere.
        let returned = trace_import_stub_log(0, 0);
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(returned, trace_lookup_miss_stub as *const () as usize);
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            assert_eq!(returned, 0);
        }
    }

    #[test]
    fn trace_import_stub_log_returns_miss_stub_on_lookup_miss() {
        // Decode succeeds, but there is no entry in the resolved map for
        // this slot VA.  Expect the miss-stub fallback.
        let rax_base = 0x3000_0000usize;
        let slot_va = 0x3000_0100usize; // intentionally NOT inserted
        let (_buf, ret_addr) = build_call_iat_disp32(rax_base, slot_va);

        // Make sure the slot really isn't in the map from a prior test.
        {
            let mut m = resolved_slot_map().lock().unwrap();
            m.remove(&slot_va);
        }

        let returned = trace_import_stub_log(ret_addr, rax_base);
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(returned, trace_lookup_miss_stub as *const () as usize);
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            assert_eq!(returned, 0);
        }
    }

    #[test]
    fn tracer_enabled_defaults_false_when_unset() {
        // NOTE: tracer_enabled() uses OnceLock, so this test asserts the
        // *cached* state.  In CI/local runs where WEAVE_IAT_TRACE is not set,
        // the first invocation (whichever test gets there first) returns
        // false and caches it.  We re-read std::env directly to corroborate
        // the observed state matches the environment, rather than relying
        // on test ordering.
        let env_is_one = std::env::var("WEAVE_IAT_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false);
        assert_eq!(tracer_enabled(), env_is_one);
    }
}
