//! Control Flow Guard (CFG) stub setup.
//!
//! Windows PEs compiled with CFG encode indirect call targets using the
//! process's security cookie:
//!
//!   encoded = ROR(target XOR cookie, cookie & 0x3f)
//!
//! Before calling an encoded pointer, MSVC-generated code puts `encoded` in
//! RAX and calls `_guard_dispatch_icall_fptr` (via a wrapper stub). On
//! Windows, ntdll replaces that pointer with a function that decodes RAX and
//! validates the target against the CFG bitmap before calling it.
//!
//! Weave does not implement CFG validation, but it must implement the decode
//! step — otherwise CFG-compiled code jumps to the encoded (garbage) address
//! and crashes immediately.
//!
//! This module:
//!  1. Reads the Load Config Directory to find the security cookie VA and the
//!     `_guard_check_icall_fptr` / `_guard_dispatch_icall_fptr` slots.
//!  2. Stores the security cookie VA for use by the decode stub.
//!  3. Overwrites those slots with the address of `weave_cfg_dispatch`, a
//!     minimal naked-function stub that decodes RAX and tail-calls the target.

use std::sync::atomic::{AtomicUsize, Ordering};

// VA of __security_cookie inside the loaded PE image.
// Written once by `setup`, read by the naked stub at every CFG indirect call.
static SECURITY_COOKIE_VA: AtomicUsize = AtomicUsize::new(0);

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

    let LoadConfig { security_cookie_va, check_fptr_va, dispatch_fptr_va } = lc;

    if security_cookie_va == 0 {
        eprintln!("weave: CFG: SecurityCookie VA is 0 — skipping CFG setup");
        return;
    }

    // Verify the security cookie VA is within the mapped image (sanity check).
    let base_usize = base as usize;
    if security_cookie_va < base_usize {
        eprintln!("weave: CFG: SecurityCookie VA {security_cookie_va:#x} below image base — skipping");
        return;
    }

    SECURITY_COOKIE_VA.store(security_cookie_va, Ordering::Relaxed);
    let initial_cookie = unsafe { *(security_cookie_va as *const u64) };
    eprintln!("weave: CFG: security cookie VA = {security_cookie_va:#x}, initial value = {initial_cookie:#018x}");

    // Do NOT pre-set the security cookie.
    //
    // The cookie starts as MSVC's DEFAULT (0x2B992DDFA232) baked into the PE.
    // Our decode stub reads the live cookie at [security_cookie_va] on every call,
    // so it automatically tracks whatever __security_init_cookie writes.
    //
    // Callers encode using the same live cookie → decode is always consistent.
    // Clobbering the cookie with DEFAULT+1 would shift the rotation count by 1
    // (0x32→0x33), corrupting every dispatch call made with the original value.

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
    let lc_sz  = read_u32(bytes, dd_off + 10 * 8 + 4)? as usize;
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
    let sc_va       = read_u64(bytes, lc_foff + 0x58)? as usize;
    let check_va    = read_u64(bytes, lc_foff + 0x70)? as usize;
    let dispatch_va = read_u64(bytes, lc_foff + 0x78)? as usize;

    Some(LoadConfig {
        security_cookie_va: sc_va,
        check_fptr_va: check_va,
        dispatch_fptr_va: dispatch_va,
    })
}

fn rva_to_foff(bytes: &[u8], rva: usize, num_sections: usize, sec_off: usize) -> Option<usize> {
    for i in 0..num_sections {
        let s = sec_off + i * 40;
        let va   = read_u32(bytes, s + 12)? as usize;
        let vsz  = read_u32(bytes, s + 16)? as usize;
        let foff = read_u32(bytes, s + 20)? as usize;
        let fsz  = read_u32(bytes, s + 24)? as usize;
        if va > 0 && rva >= va && rva < va + vsz.max(fsz) {
            return Some(foff + (rva - va));
        }
    }
    None
}

fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    bytes.get(off..off + 2).map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    bytes.get(off..off + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], off: usize) -> Option<u64> {
    bytes.get(off..off + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

// ── CFG decode-and-call stub ──────────────────────────────────────────────────
//
// Windows x64 CFG encoding:
//   encoded = ROR(target XOR cookie, cookie & 0x3f)
//   decoded = ROL(encoded, cookie & 0x3f) XOR cookie
//
// This stub is installed as both _guard_check_icall_fptr and
// _guard_dispatch_icall_fptr.  It receives the encoded pointer in RAX,
// decodes it using the live security cookie, and tail-calls the result.
//
// Register constraints (Win64 ABI):
//   - RAX  = encoded pointer on entry; decoded target after decoding
//   - RCX, RDX, R8, R9 = potential arguments to the target — must be preserved
//   - R11  = scratch (caller-saved per Win64 — not used for arguments)
//   - Stack must remain 8-mod-16 at the jmp (same alignment as on entry)
//   - EFLAGS don't matter — this is a tail call, not a return
//
// We use only R11 as scratch (no push/pop needed for a jmp-to-target path).
// CL (low byte of RCX) is used for the rotation, so we save/restore RCX
// around the rol.

// The decode-and-call stub — naked so we control the exact instruction sequence.
// Must be a standalone fn so it has a stable address.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "win64" fn weave_cfg_dispatch_stub() {
    std::arch::naked_asm!(
        // R11 = value of SECURITY_COOKIE_VA (= VA of __security_cookie in PE),
        // loaded via RIP-relative addressing so we stay PIC/PIE-compatible.
        "mov r11, qword ptr [rip + {sc_va_static}]",
        // If zero (no CFG), skip decode and just call RAX directly
        "test r11, r11",
        "jz 2f",
        // R11 = __security_cookie value (the live cookie, may have changed after init)
        "mov r11, qword ptr [r11]",
        // Decode: decoded = ROL(encoded, cookie & 0x3f) XOR cookie
        // Need CL = cookie & 0x3f.  Save/restore RCX around rol since target
        // may need RCX as its first argument.
        "push rcx",
        "mov ecx, r11d",        // ECX = lower 32 bits of cookie
        "and ecx, 0x3f",        // ECX = cookie & 0x3f  (rotation amount)
        "rol rax, cl",          // RAX = ROL(encoded, cookie & 0x3f)
        "xor rax, r11",         // RAX = decoded target
        "pop rcx",
        "2:",
        // If decoded target is null, this is a CFG null-check (deliberately
        // calling null → CFG violation on Windows). Just return instead of
        // crashing — the caller continues its error handling path.
        "test rax, rax",
        "jz 3f",
        "jmp rax",
        "3:",
        "ret",
        sc_va_static = sym SECURITY_COOKIE_VA,
    )
}

// On non-x86_64 (macOS ARM64 build for unit tests) provide a no-op.
#[cfg(not(target_arch = "x86_64"))]
fn weave_cfg_dispatch_stub() {}
