//! Control Flow Guard / XFG (eXtended Flow Guard) dispatch setup.
//!
//! MSVC-compiled PEs using XFG encode indirect call targets at link time with
//! the MSVC default security cookie (0x2B992DDFA232):
//!
//!   encoded = ROL(target XOR cookie, cookie & 0x3f)   [link-time]
//!
//! At the call site (PuTTY's disassembly confirms this), the compiler emits:
//!
//!   1. null check:  `cmp [stored_encoded], [live_cookie]` / `je null_path`
//!   2. inline decode: `xor rax, [stored_encoded]` then `ror rax, cl`
//!   3. call [_guard_dispatch_icall_fptr]   ; rax = decoded target
//!
//! So our dispatch stub receives the ALREADY-DECODED function pointer in RAX.
//! It only needs to null-check and tail-call.
//!
//! The critical invariant: the null check in step 1 only works when
//! [live_cookie] == DEFAULT.  MSVC's __security_init_cookie (compiled into the
//! PE) randomises the cookie at startup — but link-time null pointers are still
//! encoded with DEFAULT.  After randomisation, DEFAULT ≠ new_cookie, so the
//! null check fails, the code tries to decode a null as a real pointer, and
//! jumps to garbage.
//!
//! This module:
//!  1. Reads the Load Config Directory to find the security cookie VA and the
//!     `_guard_check_icall_fptr` / `_guard_dispatch_icall_fptr` slots.
//!  2. Scans executable sections for the MOV instruction that stores the
//!     randomised cookie and NOPs it out, keeping the cookie at DEFAULT.
//!  3. Overwrites the dispatch/check slots with `weave_cfg_dispatch_stub`, a
//!     minimal naked stub that null-checks RAX and tail-calls it.

use std::sync::atomic::{AtomicUsize, Ordering};

/// MSVC default security cookie: the value every XFG-encoded null pointer uses
/// at link time, and the value we keep the live cookie at (by NOPing
/// `__security_init_cookie`).
const DEFAULT_COOKIE: u64 = 0x0000_2b99_2ddf_a232;

// VA of __security_cookie inside the loaded PE image.
// Written once by `setup`, read by the naked stub at every CFG indirect call.
static SECURITY_COOKIE_VA: AtomicUsize = AtomicUsize::new(0);

// Total CFG dispatch stub invocations.  Incremented on every call (even after
// the log limit).  Readable via `cfg_dispatch_count()` for crash reports.
#[cfg(target_arch = "x86_64")]
static CFG_DEBUG_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Return the total number of CFG dispatch stub invocations so far.
#[cfg(target_arch = "x86_64")]
pub fn cfg_dispatch_count() -> usize {
    CFG_DEBUG_COUNT.load(Ordering::Relaxed)
}
#[cfg(not(target_arch = "x86_64"))]
pub fn cfg_dispatch_count() -> usize {
    0
}

/// Called from `weave_cfg_dispatch_stub` for every indirect dispatch.
///
/// Logs the decoded target and the call-site return address (the instruction
/// after `call [_guard_dispatch_icall_fptr]` in the PE, which identifies which
/// XFG call site is dispatching).  Only prints the first few calls.
///
/// Win64 ABI: RCX = decoded RAX, RDX = caller return address (from [RSP] on entry).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
unsafe extern "win64" fn weave_cfg_do_debug(rax_val: usize, caller_rip: usize) {
    const MAX_LOG: usize = 500;
    let n = CFG_DEBUG_COUNT.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_LOG {
        if n == MAX_LOG {
            eprintln!("weave: CFG dispatch: hit log limit ({MAX_LOG}), suppressing further output");
        }
        return;
    }
    let cookie_va = SECURITY_COOKIE_VA.load(Ordering::Relaxed);
    let live_cookie: u64 = if cookie_va != 0 {
        unsafe { *(cookie_va as *const u64) }
    } else {
        0
    };
    let canonical = (rax_val >> 47) == 0 && rax_val != 0;
    eprintln!(
        "weave: CFG dispatch[{n}]: target={rax_val:#018x} caller={caller_rip:#018x} \
         cookie={live_cookie:#018x} {}",
        if canonical { "OK→jmp" } else { "BAD→ret0" }
    );
}

/// Find the CFG function-pointer slots in the PE's Load Config Directory and
/// patch them to point to Weave's decode-and-call stub.
///
/// `pe_bytes` is the raw PE file; `base` is where it was mapped.
/// Must be called after the image is loaded but before jumping to entry.
pub fn setup(pe_bytes: &[u8], base: *mut u8) {
    let lc = match find_load_config(pe_bytes) {
        Some(x) => x,
        None => {
            eprintln!("weave: CFG: no Load Config Directory — skipping CFG setup");
            return;
        }
    };

    let LoadConfig {
        security_cookie_va,
        check_fptr_va,
        dispatch_fptr_va,
    } = lc;

    if security_cookie_va == 0 {
        eprintln!("weave: CFG: SecurityCookie VA is 0 — skipping CFG setup");
        return;
    }

    // Verify the security cookie VA is within the mapped image (sanity check).
    let base_usize = base as usize;
    if security_cookie_va < base_usize {
        eprintln!(
            "weave: CFG: SecurityCookie VA {security_cookie_va:#x} below image base — skipping"
        );
        return;
    }

    SECURITY_COOKIE_VA.store(security_cookie_va, Ordering::Relaxed);
    let initial_cookie = unsafe { *(security_cookie_va as *const u64) };
    eprintln!("weave: CFG: security cookie VA = {security_cookie_va:#x}, initial value = {initial_cookie:#018x}");

    // NOP out __security_init_cookie's store to [security_cookie_va].
    //
    // XFG null pointers are encoded at link time with the DEFAULT cookie.  The
    // null-check at each call site is:  cmp [stored_null], [live_cookie].
    // This works only if live_cookie == DEFAULT.  If __security_init_cookie
    // randomises the cookie, DEFAULT ≠ new_cookie, the null check fails, and
    // the code decodes DEFAULT-encoded null as a garbage address → crash.
    //
    // Patching out the store keeps live_cookie == DEFAULT for the lifetime of
    // the process.  All XFG call sites then see consistent null semantics.
    nop_security_cookie_stores(pe_bytes, base, security_cookie_va);

    // Also disable __security_check_cookie — the per-function epilog GS check
    // that compares the on-stack cookie against __security_cookie and calls
    // __report_gsfailure (→ __fastfail → int 29h → SIGSEGV on Linux).
    //
    // The Linux/Windows ABI mismatch at RSP-check time means the on-stack
    // cookie slot does not reliably match __security_cookie, so every epilog
    // check mispredicts as failure. Patch the function to a single RET.
    disable_security_check_cookie(pe_bytes, base, security_cookie_va);

    // Patch _guard_check_icall_fptr and _guard_dispatch_icall_fptr to our stub.
    // Both slots are writable .data-like pages (in the .00cfg section which is r+w on Linux
    // after mprotect). We temporarily make them writable if needed.
    let stub_addr = weave_cfg_dispatch_stub as *const () as usize;

    for &slot_va in &[check_fptr_va, dispatch_fptr_va] {
        if slot_va == 0 {
            continue;
        }
        let slot_ptr = slot_va as *mut usize;

        // Make the page writable, write the stub address, restore to read-only.
        let page_size = 4096usize;
        let page_base = (slot_va & !(page_size - 1)) as *mut libc::c_void;
        unsafe {
            libc::mprotect(page_base, page_size, libc::PROT_READ | libc::PROT_WRITE);
            *slot_ptr = stub_addr;
            libc::mprotect(page_base, page_size, libc::PROT_READ);
        }
        eprintln!("weave: CFG: patched slot {slot_va:#x} → weave_cfg_dispatch ({stub_addr:#x})");
    }

    // Also patch every non-zero slot in the .00cfg section.
    // The Load Config Directory only names two slots (check + dispatch), but
    // MSVC XFG adds additional "xfg_dispatch_nop" variants at further offsets
    // (e.g. [+0x18], [+0x20]).  Those can point to addresses beyond the .text
    // VirtualSize that are zero-filled by the loader — executing zeros silently
    // corrupts the CRT init chain (_initterm_e dispatches through them).
    patch_cfg_section_slots(pe_bytes, base, stub_addr);

    // Prime XFG lazy-init slots in BSS with the DEFAULT security cookie value.
    //
    // MSVC XFG protects function pointers with an encoding:
    //   encoded = live_cookie XOR ROL(target_va, live_cookie & 0x3f)
    //
    // Call sites that use these pointers store them in BSS (zero-initialised in
    // the PE file).  A "lazy-init" helper function is called once per pointer to
    // fill the slot: it checks `[slot] == live_cookie`, and only if true
    // (slot currently holds the null-encoded value) does it write the encoded
    // real pointer.  The null-encoded value for a NULL pointer is `live_cookie`
    // itself (ROL(0, n) == 0, so null encoded = cookie XOR 0 = cookie).
    //
    // On real Windows the loader writes `live_cookie` (the randomised cookie)
    // into every BSS XFG slot before the entry point runs, making the null-check
    // pass on the first call.  Since Weave keeps the cookie at DEFAULT and does
    // not run the Windows loader's XFG-slot initialisation, slots stay at 0.
    // 0 != DEFAULT_COOKIE → the check fails → slot stays 0 → every XFG call
    // through that slot dispatches a garbage decoded address → crash.
    //
    // Fix: scan executable sections for the `CMP [BSS_addr], r64; JZ/JNZ`
    // pattern and write DEFAULT_COOKIE into each matching BSS location.
    init_xfg_lazy_slots(pe_bytes, base);
}

// ── Load Config parser ─────────────────────────────────────────────────────────

struct LoadConfig {
    security_cookie_va: usize,
    check_fptr_va: usize,    // VA of _guard_check_icall_fptr slot
    dispatch_fptr_va: usize, // VA of _guard_dispatch_icall_fptr slot
}

/// Parse the PE's Load Config Directory (data directory index 10) and return
/// the CFG-relevant fields.  Returns None if there is no Load Config or the
/// directory is too small to contain CFG fields.
fn find_load_config(bytes: &[u8]) -> Option<LoadConfig> {
    // Minimal PE header parsing — goblin is not available here without pulling
    // it in again, so we do raw offset arithmetic.
    let pe_off = read_u32(bytes, 0x3c)? as usize;
    let num_sections = read_u16(bytes, pe_off + 6)? as usize;
    let opt_off = pe_off + 24;
    let magic = read_u16(bytes, opt_off)?;
    if magic != 0x020b {
        return None; // Not PE32+
    }

    // Data directories start at opt_off + 112 for PE32+.
    let dd_off = opt_off + 112;
    let lc_rva = read_u32(bytes, dd_off + 10 * 8)? as usize;
    let lc_sz = read_u32(bytes, dd_off + 10 * 8 + 4)? as usize;
    if lc_rva == 0 || lc_sz < 0x78 + 8 {
        // Need at least up to GuardCFDispatchFunctionPointer (offset 0x78)
        return None;
    }

    let sec_off = opt_off + 240; // section table for PE32+
    let lc_foff = rva_to_foff(bytes, lc_rva, num_sections, sec_off)?;

    // IMAGE_LOAD_CONFIG_DIRECTORY64 offsets:
    //   0x00  Size (DWORD)
    //   0x58  SecurityCookie (QWORD VA)
    //   0x70  GuardCFCheckFunctionPointer (QWORD VA of the fptr slot)
    //   0x78  GuardCFDispatchFunctionPointer (QWORD VA of the fptr slot)
    let sc_va = read_u64(bytes, lc_foff + 0x58)? as usize;
    let check_va = read_u64(bytes, lc_foff + 0x70)? as usize;
    let dispatch_va = read_u64(bytes, lc_foff + 0x78)? as usize;

    Some(LoadConfig {
        security_cookie_va: sc_va,
        check_fptr_va: check_va,
        dispatch_fptr_va: dispatch_va,
    })
}

/// Scan every executable section of the loaded PE for
/// `MOV QWORD PTR [rip+disp32], reg` instructions whose effective address
/// equals `security_cookie_va`, and overwrite each with 7 NOP bytes.
///
/// This prevents `__security_init_cookie` (compiled into the PE) from
/// randomising the security cookie.  The cookie must stay at the MSVC default
/// (0x2B992DDFA232) so that XFG null-pointer checks work: link-time null
/// pointers are encoded as DEFAULT, and the per-call-site check
/// `cmp [stored_null], [live_cookie]` only succeeds when they are equal.
fn nop_security_cookie_stores(pe_bytes: &[u8], base: *mut u8, security_cookie_va: usize) {
    let base_usize = base as usize;

    let pe_off = match read_u32(pe_bytes, 0x3c) {
        Some(x) => x as usize,
        None => return,
    };
    let num_sections = match read_u16(pe_bytes, pe_off + 6) {
        Some(x) => x as usize,
        None => return,
    };
    // Section table immediately follows the optional header.
    // COFF header = 24 bytes; PE32+ optional header = 240 bytes.
    let sec_table_off = pe_off + 24 + 240;

    let mut nop_count = 0usize;

    for i in 0..num_sections {
        let s = sec_table_off + i * 40;

        // IMAGE_SECTION_HEADER offsets:
        //   +12  VirtualAddress   (RVA of section in memory)
        //   +16  SizeOfRawData
        //   +20  PointerToRawData
        //   +36  Characteristics
        let characteristics = match read_u32(pe_bytes, s + 36) {
            Some(x) => x,
            None => continue,
        };
        // Only scan sections with IMAGE_SCN_MEM_EXECUTE (0x20000000).
        if characteristics & 0x2000_0000 == 0 {
            continue;
        }

        let sec_va = match read_u32(pe_bytes, s + 12) {
            Some(x) => x as usize,
            None => continue,
        };
        let sec_fsz = match read_u32(pe_bytes, s + 16) {
            Some(x) => x as usize,
            None => continue,
        };
        let sec_foff = match read_u32(pe_bytes, s + 20) {
            Some(x) => x as usize,
            None => continue,
        };

        if sec_foff >= pe_bytes.len() || sec_fsz == 0 {
            continue;
        }
        let avail = pe_bytes.len() - sec_foff;
        // Need at least 7 bytes per candidate instruction.
        let scan_len = sec_fsz.min(avail).saturating_sub(6);

        let sec_bytes = &pe_bytes[sec_foff..sec_foff + scan_len + 6];

        for offset in 0..scan_len {
            // Pattern: REX.W (0x48–0x4F) + store-opcode + ModRM (mod=00, rm=5)
            //
            // All x86-64 "op [rip+disp32], reg" instructions follow this layout:
            //   byte 0: REX.W prefix (0x48–0x4F)
            //   byte 1: opcode (one of the ALU or MOV "r/m ← r" forms)
            //   byte 2: ModRM with mod=00 (bits 7:6) and rm=101 (bits 2:0)
            //           i.e. (b2 & 0xC7) == 0x05
            //   bytes 3-6: 32-bit signed displacement
            //
            // MSVC's __security_init_cookie may use any of these opcodes to
            // write (or XOR/OR/AND) the cookie into its memory slot:
            //   0x01  ADD  [rip+d], reg
            //   0x09  OR   [rip+d], reg
            //   0x21  AND  [rip+d], reg
            //   0x29  SUB  [rip+d], reg
            //   0x31  XOR  [rip+d], reg
            //   0x89  MOV  [rip+d], reg
            let b0 = sec_bytes[offset];
            let b1 = sec_bytes[offset + 1];
            let b2 = sec_bytes[offset + 2];

            if !(0x48..=0x4F).contains(&b0) {
                continue; // REX.W prefix
            }
            let is_store_opcode = matches!(b1, 0x01 | 0x09 | 0x21 | 0x29 | 0x31 | 0x89);
            if !is_store_opcode {
                continue; // not a store-to-memory opcode
            }
            if b2 & 0xC7 != 0x05 {
                continue; // not RIP-relative addressing
            }

            let disp = i32::from_le_bytes([
                sec_bytes[offset + 3],
                sec_bytes[offset + 4],
                sec_bytes[offset + 5],
                sec_bytes[offset + 6],
            ]);

            // Effective address = VA of next instruction + signed disp.
            // Next instruction is at base + sec_va + offset + 7.
            let next_va = base_usize
                .wrapping_add(sec_va)
                .wrapping_add(offset)
                .wrapping_add(7);
            let ea = next_va.wrapping_add_signed(disp as isize);

            if ea != security_cookie_va {
                continue;
            }

            // Found a store to __security_cookie.
            // Rather than NOP-ing just this instruction (which might miss other
            // write forms like LEA+MOV-indirect), disable the entire enclosing
            // function by writing RET at its start address from .pdata.
            let instr_va = base_usize.wrapping_add(sec_va).wrapping_add(offset);
            let instr_rva = instr_va.wrapping_sub(base_usize) as u32;
            eprintln!(
                "weave: CFG: found __security_cookie store at {instr_va:#x} (rva {instr_rva:#x})"
            );
            if disable_function_containing(pe_bytes, base, instr_rva) {
                nop_count += 1;
            } else {
                // .pdata lookup failed — fall back to NOP-ing just this instruction.
                let page_size = 4096usize;
                let page_base = (instr_va & !(page_size - 1)) as *mut libc::c_void;
                unsafe {
                    libc::mprotect(
                        page_base,
                        page_size,
                        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    );
                    let ptr = instr_va as *mut u8;
                    for k in 0..7usize {
                        ptr.add(k).write(0x90); // NOP
                    }
                    libc::mprotect(page_base, page_size, libc::PROT_READ | libc::PROT_EXEC);
                }
                eprintln!(
                    "weave: CFG: NOP'd store at {instr_va:#x} (pdata lookup failed, \
                     store-only fallback — cookie may still be randomised)"
                );
                nop_count += 1;
            }
        }
    }

    if nop_count == 0 {
        eprintln!(
            "weave: CFG: warning: no __security_cookie store found in executable sections \
             — cookie may be randomised"
        );
    }
}

/// Look up `target_rva` in the PE's .pdata exception table to find the
/// enclosing function, then write a single `RET` (0xC3) at the function start.
///
/// This is more reliable than NOP-ing only the store instruction because MSVC
/// may write the cookie via a register-indirect form (`lea reg, [cookie]` then
/// `mov [reg], rax`) that our RIP-relative scanner does not detect.
///
/// Returns `true` if the function was successfully disabled.
fn disable_function_containing(pe_bytes: &[u8], base: *mut u8, target_rva: u32) -> bool {
    let base_usize = base as usize;

    // Locate the .pdata section (exception table, data directory index 3).
    let pe_off = match read_u32(pe_bytes, 0x3c) {
        Some(x) => x as usize,
        None => return false,
    };
    let opt_off = pe_off + 24;
    let dd_off = opt_off + 112; // data directories start here for PE32+

    // Data directory entry 3 = exception table (.pdata)
    let pdata_rva = match read_u32(pe_bytes, dd_off + 3 * 8) {
        Some(x) => x as usize,
        None => return false,
    };
    let pdata_sz = match read_u32(pe_bytes, dd_off + 3 * 8 + 4) {
        Some(x) => x as usize,
        None => return false,
    };

    if pdata_rva == 0 || pdata_sz < 12 {
        return false;
    }

    // .pdata is mapped into the process at base + pdata_rva.
    // Each RUNTIME_FUNCTION entry is 12 bytes (three DWORDs):
    //   [0] BeginAddress  — RVA of first instruction
    //   [1] EndAddress    — RVA one past the last instruction
    //   [2] UnwindInfo    — RVA of UNWIND_INFO (not used here)
    let count = pdata_sz / 12;
    let pdata_base = base_usize + pdata_rva;

    for i in 0..count {
        let entry = pdata_base + i * 12;
        let begin = unsafe { *(entry as *const u32) };
        let end = unsafe { *((entry + 4) as *const u32) };
        if target_rva >= begin && target_rva < end {
            // Found the function that contains the cookie store.
            // Write RET (0xC3) at its start to short-circuit it entirely.
            let func_va = base_usize + begin as usize;
            let page_size = 4096usize;
            let page_base = (func_va & !(page_size - 1)) as *mut libc::c_void;
            unsafe {
                libc::mprotect(
                    page_base,
                    page_size,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                );
                (func_va as *mut u8).write(0xC3); // RET
                libc::mprotect(page_base, page_size, libc::PROT_READ | libc::PROT_EXEC);
            }
            eprintln!(
                "weave: CFG: disabled __security_init_cookie at {func_va:#x} \
                 (rva {begin:#x}..{end:#x}) with RET"
            );
            return true;
        }
    }

    eprintln!(
        "weave: CFG: warning: RVA {target_rva:#x} not found in .pdata — \
         __security_init_cookie not fully disabled"
    );
    false
}

/// Return the .pdata `(BeginAddress, EndAddress)` RVA range of the runtime
/// function that contains `target_rva`, or `None` if the RVA is not covered
/// by any entry.
fn function_start_rva(pe_bytes: &[u8], base: *mut u8, target_rva: u32) -> Option<(u32, u32)> {
    let base_usize = base as usize;
    let pe_off = read_u32(pe_bytes, 0x3c)? as usize;
    let opt_off = pe_off + 24;
    let dd_off = opt_off + 112;
    let pdata_rva = read_u32(pe_bytes, dd_off + 3 * 8)? as usize;
    let pdata_sz = read_u32(pe_bytes, dd_off + 3 * 8 + 4)? as usize;
    if pdata_rva == 0 || pdata_sz < 12 {
        return None;
    }
    let count = pdata_sz / 12;
    let pdata_base = base_usize + pdata_rva;
    for i in 0..count {
        let entry = pdata_base + i * 12;
        let begin = unsafe { *(entry as *const u32) };
        let end = unsafe { *((entry + 4) as *const u32) };
        if target_rva >= begin && target_rva < end {
            return Some((begin, end));
        }
    }
    None
}

/// Locate `__security_check_cookie` (the per-function epilog GS check) and
/// patch its first byte with `RET` (0xC3).
///
/// Strategy: scan executable sections for a 7-byte RIP-relative load
/// `REX.W MOV r64, [rip+disp32]` (`48 8B <modrm> <disp32>`, with
/// `modrm & 0xC7 == 0x05`) whose effective address equals the PE's
/// `__security_cookie` slot. `__security_check_cookie` is MSVC's canonical
/// reader of that slot, so the runtime function containing such a load is
/// our target; patch its first byte with `RET` via temporary mprotect RW+X.
fn disable_security_check_cookie(pe_bytes: &[u8], base: *mut u8, security_cookie_va: usize) {
    let base_usize = base as usize;

    let pe_off = match read_u32(pe_bytes, 0x3c) {
        Some(x) => x as usize,
        None => return,
    };
    let num_sections = match read_u16(pe_bytes, pe_off + 6) {
        Some(x) => x as usize,
        None => return,
    };
    let sec_table_off = pe_off + 24 + 240;

    for i in 0..num_sections {
        let s = sec_table_off + i * 40;
        let characteristics = match read_u32(pe_bytes, s + 36) {
            Some(x) => x,
            None => continue,
        };
        if characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let sec_va = match read_u32(pe_bytes, s + 12) {
            Some(x) => x as usize,
            None => continue,
        };
        let sec_fsz = match read_u32(pe_bytes, s + 16) {
            Some(x) => x as usize,
            None => continue,
        };
        let sec_foff = match read_u32(pe_bytes, s + 20) {
            Some(x) => x as usize,
            None => continue,
        };
        if sec_foff >= pe_bytes.len() || sec_fsz == 0 {
            continue;
        }
        let avail = pe_bytes.len() - sec_foff;
        if avail < 7 {
            continue;
        }
        let scan_len = sec_fsz.min(avail) - 7;
        let sec_bytes = &pe_bytes[sec_foff..sec_foff + scan_len + 7];

        for offset in 0..=scan_len {
            // REX.W MOV r64, [rip+disp32]:
            //   byte 0: 0x48  (REX.W, no R/X/B — register encoded in ModRM.reg)
            //   byte 1: 0x8B  (MOV r64, r/m64)
            //   byte 2: ModRM with mod=00, rm=101  →  (b2 & 0xC7) == 0x05
            //   bytes 3..7: 32-bit signed disp
            if sec_bytes[offset] != 0x48 || sec_bytes[offset + 1] != 0x8B {
                continue;
            }
            if sec_bytes[offset + 2] & 0xC7 != 0x05 {
                continue;
            }
            let disp = i32::from_le_bytes([
                sec_bytes[offset + 3],
                sec_bytes[offset + 4],
                sec_bytes[offset + 5],
                sec_bytes[offset + 6],
            ]);
            let next_va = base_usize
                .wrapping_add(sec_va)
                .wrapping_add(offset)
                .wrapping_add(7);
            let ea = next_va.wrapping_add_signed(disp as isize);
            if ea != security_cookie_va {
                continue;
            }

            let instr_rva = (sec_va + offset) as u32;
            let (begin, end) = match function_start_rva(pe_bytes, base, instr_rva) {
                Some(r) => r,
                None => continue,
            };

            // Filter A: MSVC __security_check_cookie is a tiny stub (12–20 bytes).
            // Skip any function ≥ 32 bytes.
            let func_len = end.saturating_sub(begin) as usize;
            if func_len >= 32 {
                continue;
            }

            // Filter B: __security_check_cookie contains a conditional branch
            // (JNE 0x75 rel8, or 0F 85 rel32) to __report_gsfailure. Reject
            // any candidate whose body contains neither opcode.
            let func_va = base_usize + begin as usize;
            let func_bytes =
                unsafe { std::slice::from_raw_parts(func_va as *const u8, func_len) };
            let mut has_jne = false;
            let mut k = 0usize;
            while k < func_len {
                let b = func_bytes[k];
                if b == 0x75 {
                    has_jne = true;
                    break;
                }
                if b == 0x0F && k + 1 < func_len && func_bytes[k + 1] == 0x85 {
                    has_jne = true;
                    break;
                }
                k += 1;
            }
            if !has_jne {
                continue;
            }
            let page_size = 4096usize;
            let page_base = (func_va & !(page_size - 1)) as *mut libc::c_void;
            unsafe {
                libc::mprotect(
                    page_base,
                    page_size,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                );
                (func_va as *mut u8).write(0xC3); // RET
                libc::mprotect(page_base, page_size, libc::PROT_READ | libc::PROT_EXEC);
            }
            eprintln!(
                "weave: CFG: disabled __security_check_cookie at {func_va:#x} \
                 (rva {begin:#x}) with RET"
            );
            return;
        }
    }

    eprintln!(
        "weave: CFG: warning: __security_check_cookie not patched — \
         no REX.W MOV r64, [rip+__security_cookie] load found"
    );
}

/// Scan the .00cfg section of the loaded PE image and patch every non-zero
/// 8-byte slot to `stub_addr`.
///
/// The Load Config Directory only names `_guard_check_icall_fptr` and
/// `_guard_dispatch_icall_fptr`, but MSVC XFG also emits additional
/// "xfg_dispatch_nop" variants at the next offsets.  Those slots contain VAs
/// that can fall beyond the .text section's VirtualSize — the loader
/// zero-fills that region, so calling through them executes zeros and silently
/// short-circuits the CRT static-initializer chain.
fn patch_cfg_section_slots(pe_bytes: &[u8], base: *mut u8, stub_addr: usize) {
    let base_usize = base as usize;

    let pe_off = match read_u32(pe_bytes, 0x3c) {
        Some(x) => x as usize,
        None => return,
    };
    let num_sections = match read_u16(pe_bytes, pe_off + 6) {
        Some(x) => x as usize,
        None => return,
    };
    // Section table immediately follows COFF header (24 bytes) + PE32+ optional
    // header (240 bytes).
    let sec_table_off = pe_off + 24 + 240;

    for i in 0..num_sections {
        let s = sec_table_off + i * 40;
        // Section name: 8 bytes at offset 0, null-padded.
        let name_bytes = match pe_bytes.get(s..s + 8) {
            Some(b) => b,
            None => continue,
        };
        if name_bytes != b".00cfg\0\0" {
            continue;
        }

        let sec_va = match read_u32(pe_bytes, s + 12) {
            Some(x) => x as usize,
            None => return,
        };
        let sec_vsz = match read_u32(pe_bytes, s + 16) {
            Some(x) => x as usize,
            None => return,
        };

        let slot_count = sec_vsz / 8;
        let sec_map_base = base_usize + sec_va;
        let page_size = 4096usize;

        eprintln!("weave: CFG: scanning .00cfg section at {sec_map_base:#x} ({slot_count} slots)");

        for j in 0..slot_count {
            let slot_va = sec_map_base + j * 8;
            let current = unsafe { *(slot_va as *const usize) };
            if current == 0 || current == stub_addr {
                continue; // null or already patched
            }
            let page_base = (slot_va & !(page_size - 1)) as *mut libc::c_void;
            unsafe {
                libc::mprotect(page_base, page_size, libc::PROT_READ | libc::PROT_WRITE);
                *(slot_va as *mut usize) = stub_addr;
                libc::mprotect(page_base, page_size, libc::PROT_READ);
            }
            eprintln!(
                "weave: CFG: .00cfg[{j}] [{slot_va:#x}] was {current:#x} → stub {stub_addr:#x}"
            );
        }
        return;
    }
}

/// Scan executable sections for XFG lazy-init slots in BSS and prime each one
/// with `DEFAULT_COOKIE`.
///
/// MSVC XFG lazy-init helpers guard function-pointer slots with this check:
///
///   `CMP qword ptr [slot], live_cookie`   ; is slot == null-encoded?
///   `JNZ / JZ  skip`                      ; only initialise if null-encoded
///
/// The Windows loader pre-fills BSS XFG slots with the (randomised) live cookie
/// before the entry point runs.  That makes `[slot] == live_cookie` true, so
/// the first call to the helper initialises the slot with the real encoded
/// pointer.
///
/// Weave keeps the cookie at DEFAULT and never runs the loader's slot
/// pre-fill step.  BSS slots stay at 0, so `0 == DEFAULT_COOKIE` is false,
/// the helper skips initialisation, the slot stays 0, and every XFG indirect
/// call through that slot decodes garbage → crash.
///
/// This function detects the pattern and writes `DEFAULT_COOKIE` into every
/// matching BSS slot, restoring the invariant the Windows loader normally
/// provides.
fn init_xfg_lazy_slots(pe_bytes: &[u8], base: *mut u8) {
    let base_usize = base as usize;

    let pe_off = match read_u32(pe_bytes, 0x3c) {
        Some(x) => x as usize,
        None => return,
    };
    let num_sections = match read_u16(pe_bytes, pe_off + 6) {
        Some(x) => x as usize,
        None => return,
    };
    let sec_table_off = pe_off + 24 + 240;

    // Collect BSS ranges: non-executable writable sections where
    // virtual_size > size_of_raw_data (zero-initialised tail).
    let mut bss_ranges: Vec<(usize, usize)> = Vec::new();
    for i in 0..num_sections {
        let s = sec_table_off + i * 40;
        let chars = match read_u32(pe_bytes, s + 36) {
            Some(x) => x,
            None => continue,
        };
        if chars & 0x2000_0000 != 0 {
            continue; // skip executable sections
        }
        // Must be readable or writable.
        if chars & 0xC000_0000 == 0 {
            continue;
        }
        let va = match read_u32(pe_bytes, s + 12) {
            Some(x) => x as usize,
            None => continue,
        };
        let vsize = match read_u32(pe_bytes, s + 8) {
            Some(x) => x as usize,
            None => continue,
        };
        let raw = match read_u32(pe_bytes, s + 16) {
            Some(x) => x as usize,
            None => continue,
        };
        if vsize > raw {
            // BSS: [va + raw, va + vsize) mapped as zeroes
            let bss_lo = base_usize.wrapping_add(va).wrapping_add(raw);
            let bss_hi = base_usize.wrapping_add(va).wrapping_add(vsize);
            bss_ranges.push((bss_lo, bss_hi));
        }
    }

    if bss_ranges.is_empty() {
        return;
    }

    let mut slot_count = 0usize;

    // Scan executable sections for the XFG lazy-init null-check pattern:
    //   REX.W  CMP [RIP+disp32], r64   (opcode 0x39, ModRM mod=00 rm=101)
    //   JZ or JNZ (0x74 or 0x75)
    // where the effective address falls inside a BSS range.
    for i in 0..num_sections {
        let s = sec_table_off + i * 40;
        let chars = match read_u32(pe_bytes, s + 36) {
            Some(x) => x,
            None => continue,
        };
        if chars & 0x2000_0000 == 0 {
            continue; // skip non-executable
        }

        let sec_va = match read_u32(pe_bytes, s + 12) {
            Some(x) => x as usize,
            None => continue,
        };
        let sec_fsz = match read_u32(pe_bytes, s + 16) {
            Some(x) => x as usize,
            None => continue,
        };
        let sec_foff = match read_u32(pe_bytes, s + 20) {
            Some(x) => x as usize,
            None => continue,
        };

        if sec_foff >= pe_bytes.len() || sec_fsz == 0 {
            continue;
        }
        let avail = pe_bytes.len() - sec_foff;
        // Need at least 9 bytes: 7 (CMP [RIP+disp]) + 1 (opcode) + 1 (disp8 of Jcc)
        let scan_len = sec_fsz.min(avail).saturating_sub(8);

        let sec_bytes = &pe_bytes[sec_foff..sec_foff + scan_len + 8];

        for offset in 0..scan_len {
            // Byte 0: REX.W prefix (0x48–0x4F)
            let b0 = sec_bytes[offset];
            if !(0x48..=0x4F).contains(&b0) {
                continue;
            }
            // Byte 1: CMP r/m, r (0x39) — stores register into memory operand
            if sec_bytes[offset + 1] != 0x39 {
                continue;
            }
            // Byte 2: ModRM — mod=00, rm=101 means [RIP+disp32]
            if sec_bytes[offset + 2] & 0xC7 != 0x05 {
                continue;
            }
            // Bytes 3–6: 32-bit signed displacement
            let disp = i32::from_le_bytes([
                sec_bytes[offset + 3],
                sec_bytes[offset + 4],
                sec_bytes[offset + 5],
                sec_bytes[offset + 6],
            ]);
            // Byte 7: must be JZ (0x74) or JNZ (0x75)
            let b7 = sec_bytes[offset + 7];
            if b7 != 0x74 && b7 != 0x75 {
                continue;
            }

            // Effective address = (RVA of next instruction) + disp + image base
            let next_rva = sec_va.wrapping_add(offset).wrapping_add(7);
            let ea_rva = next_rva.wrapping_add_signed(disp as isize);
            let ea_va = match base_usize.checked_add(ea_rva) {
                Some(v) => v,
                None => continue, // overflow — not a valid BSS slot
            };

            // Check EA falls in a BSS range
            if !bss_ranges.iter().any(|&(lo, hi)| ea_va >= lo && ea_va < hi) {
                continue;
            }

            // False-positive filter: if there is a `MOV [same_EA], r64` within the
            // 64 bytes immediately before this CMP, the pattern is not XFG lazy-init
            // but rather an ordinary "write then check" sequence (e.g. storing an
            // allocation result and then comparing it).  In genuine XFG lazy-init
            // the CMP always precedes the write.
            let check_start = offset.saturating_sub(64);
            let has_preceding_write = (check_start..offset).any(|prev| {
                let pb0 = sec_bytes[prev];
                let pb1 = sec_bytes[prev + 1];
                let pb2 = sec_bytes[prev + 2];
                if !(0x48..=0x4F).contains(&pb0) || pb1 != 0x89 || pb2 & 0xC7 != 0x05 {
                    return false;
                }
                if prev + 7 > sec_bytes.len() {
                    return false;
                }
                let d2 = i32::from_le_bytes([
                    sec_bytes[prev + 3],
                    sec_bytes[prev + 4],
                    sec_bytes[prev + 5],
                    sec_bytes[prev + 6],
                ]);
                let ea2 = sec_va
                    .wrapping_add(prev)
                    .wrapping_add(7)
                    .wrapping_add_signed(d2 as isize)
                    & 0xFFFF_FFFF;
                ea2 == ea_rva
            });
            if has_preceding_write {
                continue;
            }

            // Prime the slot: only write if it is still zero (genuine BSS).
            let slot_ptr = ea_va as *mut u64;
            let current = unsafe { *slot_ptr };
            if current == 0 {
                unsafe {
                    *slot_ptr = DEFAULT_COOKIE;
                }
                slot_count += 1;
                eprintln!("weave: CFG: primed XFG BSS slot {ea_va:#x} with DEFAULT_COOKIE");
            }
        }
    }

    if slot_count > 0 {
        eprintln!("weave: CFG: primed {slot_count} XFG BSS slot(s) with DEFAULT_COOKIE");
    }
}

fn rva_to_foff(bytes: &[u8], rva: usize, num_sections: usize, sec_off: usize) -> Option<usize> {
    for i in 0..num_sections {
        let s = sec_off + i * 40;
        let va = read_u32(bytes, s + 12)? as usize;
        let vsz = read_u32(bytes, s + 16)? as usize;
        let foff = read_u32(bytes, s + 20)? as usize;
        let fsz = read_u32(bytes, s + 24)? as usize;
        if va > 0 && rva >= va && rva < va + vsz.max(fsz) {
            return Some(foff + (rva - va));
        }
    }
    None
}

fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    bytes
        .get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], off: usize) -> Option<u64> {
    bytes
        .get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

// ── CFG / XFG dispatch stub ───────────────────────────────────────────────────
//
// PuTTY's call sites perform the full XFG decode INLINE before reaching here:
//
//   ; rax = [live_cookie]
//   ; cmp [stored_encoded], rax     ← null check (encoded null == live_cookie)
//   ; je  null_path
//   ; mov ecx, eax  /  and ecx, 0x3f
//   ; xor rax, [stored_encoded]     ← XOR first
//   ; ror rax, cl                   ← then rotate
//   ; call [_guard_dispatch_icall_fptr]   ← rax = decoded target
//
// By the time we are called, RAX already holds the decoded function pointer.
// We only need to null-check it (in case something slips through) and jump.

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "win64" fn weave_cfg_dispatch_stub() {
    std::arch::naked_asm!(
        // RAX = decoded target (PuTTY XFG call sites decode inline before us).
        //
        // Stack alignment on entry:
        //   - Caller had RSP ≡ 0 (mod 16) before `call [dispatch_fptr]`
        //   - That `call` pushed 8 bytes → RSP ≡ 8 (mod 16)
        //   - 7 pushes × 8 = 56 bytes → RSP ≡ 8+56 = 64 ≡ 0 (mod 16) ✓
        //   - sub rsp, 32 → RSP still ≡ 0 (mod 16) ✓
        //
        // Stack layout after sub rsp,32:
        //   [rsp+ 0..31]  shadow space
        //   [rsp+32]      r11
        //   [rsp+40]      r10
        //   [rsp+48]      r9
        //   [rsp+56]      r8
        //   [rsp+64]      rdx
        //   [rsp+72]      rcx
        //   [rsp+80]      rax  ← original decoded target
        //   [rsp+88]      return address in PE (instruction after the call)
        "push rax",
        "push rcx",
        "push rdx",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "sub rsp, 32",
        "mov rcx, [rsp + 80]",   // Win64 arg1 = decoded target (original RAX)
        "mov rdx, [rsp + 88]",   // Win64 arg2 = caller return address (call-site in PE)
        "call {debug}",
        "add rsp, 32",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdx",
        "pop rcx",
        "pop rax",
        // ── Guard 1: explicit null ─────────────────────────────────────────
        "test rax, rax",
        "jz 2f",
        // ── Guard 2: canonical user-space address (bits 63:47 must be zero) ─
        // R11 is Win64 caller-saved — scratch use is fine here.
        "mov r11, rax",
        "shr r11, 47",
        "jnz 2f",
        "jmp rax",
        // ── Fail path: bad target — return 0 so callers see a clean NULL ──
        "2:",
        "xor eax, eax",
        "ret",
        debug = sym weave_cfg_do_debug,
    )
}

// On non-x86_64 (macOS ARM64 build for unit tests) provide a no-op.
#[cfg(not(target_arch = "x86_64"))]
fn weave_cfg_dispatch_stub() {}
