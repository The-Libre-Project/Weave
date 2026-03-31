//! kernel32.dll stubs for Weave — the 15 functions hello.exe needs.
//!
//! Critical section stubs are no-ops (Phase 1 is single-threaded).
//! VirtualProtect/VirtualQuery delegate to mprotect/mincore.
//! WriteConsoleW converts UTF-16 to UTF-8 and writes to the Linux fd.

#![allow(non_snake_case)]

use std::cell::Cell;
use weave_common::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};

// Per-thread last error, shared across GetLastError / SetLastError.
thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

// ── Windows page-protection flags ─────────────────────────────────────────────

fn win_prot_to_linux(protect: u32) -> i32 {
    match protect & 0xFF {
        0x01 => libc::PROT_NONE,
        0x02 => libc::PROT_READ,
        0x04 => libc::PROT_READ | libc::PROT_WRITE,
        0x08 => libc::PROT_READ | libc::PROT_WRITE,
        0x10 => libc::PROT_EXEC,
        0x20 => libc::PROT_READ | libc::PROT_EXEC,
        0x40 | 0x80 => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        _ => libc::PROT_READ | libc::PROT_WRITE,
    }
}

// ── Stubs ─────────────────────────────────────────────────────────────────────

/// GetStdHandle: return the Linux fd for stdin/stdout/stderr.
pub extern "win64" fn get_std_handle(n_std_handle: u32) -> usize {
    match n_std_handle {
        STD_INPUT_HANDLE => 0,
        STD_OUTPUT_HANDLE => 1,
        STD_ERROR_HANDLE => 2,
        _ => usize::MAX, // INVALID_HANDLE_VALUE
    }
}

/// WriteConsoleW: write a UTF-16 buffer to the console handle (Linux fd).
///
/// # Safety
/// `lp_buffer` must be valid for `n_chars` UTF-16 code units.
pub unsafe extern "win64" fn write_console_w(
    h_console_output: usize,
    lp_buffer: *const u16,
    n_chars: u32,
    lp_chars_written: *mut u32,
    _lp_reserved: usize,
) -> i32 {
    let fd = h_console_output as i32;
    let slice = unsafe { std::slice::from_raw_parts(lp_buffer, n_chars as usize) };
    let s = String::from_utf16_lossy(slice);
    let bytes = s.as_bytes();
    let n = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    if !lp_chars_written.is_null() {
        unsafe { *lp_chars_written = if n >= 0 { n_chars } else { 0 } };
    }
    (n >= 0) as i32
}

/// ExitProcess: terminate the process with the given exit code.
pub extern "win64" fn exit_process(u_exit_code: u32) -> ! {
    unsafe { libc::exit(u_exit_code as i32) }
}

/// GetLastError: return the calling thread's last error code.
pub extern "win64" fn get_last_error() -> u32 {
    LAST_ERROR.with(|e| e.get())
}

/// SetLastError: set the calling thread's last error code.
pub extern "win64" fn set_last_error(dw_err_code: u32) {
    LAST_ERROR.with(|e| e.set(dw_err_code));
}

/// VirtualProtect: change memory protection on a region.
///
/// # Safety
/// `lp_address` must point into a valid mapped region.
pub unsafe extern "win64" fn virtual_protect(
    lp_address: *mut u8,
    dw_size: usize,
    fl_new_protect: u32,
    lpfl_old_protect: *mut u32,
) -> i32 {
    if !lpfl_old_protect.is_null() {
        unsafe { *lpfl_old_protect = 0x40 }; // report old prot as PAGE_EXECUTE_READWRITE
    }
    let prot = win_prot_to_linux(fl_new_protect);
    let page_addr = (lp_address as usize) & !(4096 - 1);
    let page_size = (dw_size + 4095) & !4095;
    let ret = unsafe { libc::mprotect(page_addr as *mut libc::c_void, page_size, prot) };
    (ret == 0) as i32
}

/// VirtualQuery: return basic info about a memory region.
///
/// Returns a minimal MEMORY_BASIC_INFORMATION (48 bytes) that satisfies
/// the CRT stack-guard introspection. Every page is reported as committed
/// and read-write private.
///
/// # Safety
/// `lp_buffer` must be writable for at least `dw_length` bytes (minimum 48).
pub unsafe extern "win64" fn virtual_query(
    lp_address: *const u8,
    lp_buffer: *mut u8,
    dw_length: usize,
) -> usize {
    const MBI_SIZE: usize = 48;
    if lp_buffer.is_null() || dw_length < MBI_SIZE {
        return 0;
    }
    let page_addr = (lp_address as usize) & !(4096 - 1);
    unsafe {
        std::ptr::write_bytes(lp_buffer, 0, MBI_SIZE);
        *(lp_buffer as *mut usize) = page_addr; // BaseAddress
        *(lp_buffer.add(8) as *mut usize) = page_addr; // AllocationBase
        *(lp_buffer.add(16) as *mut u32) = 0x04; // AllocationProtect = PAGE_READWRITE
        *(lp_buffer.add(24) as *mut usize) = 4096; // RegionSize
        *(lp_buffer.add(32) as *mut u32) = 0x1000; // State = MEM_COMMIT
        *(lp_buffer.add(36) as *mut u32) = 0x04; // Protect = PAGE_READWRITE
        *(lp_buffer.add(40) as *mut u32) = 0x20000; // Type = MEM_PRIVATE
    }
    MBI_SIZE
}

/// Sleep: suspend the calling thread for the given number of milliseconds.
pub extern "win64" fn sleep(dw_milliseconds: u32) {
    let ts = libc::timespec {
        tv_sec: (dw_milliseconds / 1000) as i64,
        tv_nsec: ((dw_milliseconds % 1000) * 1_000_000) as i64,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
}

/// TlsGetValue: return the value stored in a TLS slot.
///
/// Phase 1 stubs — TLS slots always return null (CRT handles this gracefully).
pub extern "win64" fn tls_get_value(_dw_tls_index: u32) -> *mut u8 {
    std::ptr::null_mut()
}

/// InitializeCriticalSection: zero-initialise the CRITICAL_SECTION struct.
///
/// # Safety
/// `lp_critical_section` must point to at least 40 bytes of writable memory.
pub unsafe extern "win64" fn initialize_critical_section(lp_critical_section: *mut u8) {
    unsafe { std::ptr::write_bytes(lp_critical_section, 0, 40) };
    // LockCount at offset 8 should be -1 (unlocked)
    unsafe { *(lp_critical_section.add(8) as *mut i32) = -1 };
}

/// EnterCriticalSection: acquire the critical section.
///
/// Phase 1: single-threaded no-op.
pub extern "win64" fn enter_critical_section(_lp_critical_section: *mut u8) {}

/// LeaveCriticalSection: release the critical section.
///
/// Phase 1: single-threaded no-op.
pub extern "win64" fn leave_critical_section(_lp_critical_section: *mut u8) {}

/// DeleteCriticalSection: free resources associated with a critical section.
///
/// Phase 1: no-op.
pub extern "win64" fn delete_critical_section(_lp_critical_section: *mut u8) {}

/// SetUnhandledExceptionFilter: install a top-level exception filter.
///
/// Phase 1: accepted and ignored — returns null (no previous filter).
pub extern "win64" fn set_unhandled_exception_filter(_lp_top_level_handler: usize) -> usize {
    0
}

/// __C_specific_handler: SEH C-specific exception filter.
///
/// Returns ExceptionContinueSearch (1) — Weave does not implement SEH in Phase 1.
pub extern "win64" fn c_specific_handler(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    1 // ExceptionContinueSearch
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Resolve a kernel32.dll import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("kernel32.dll") {
        return None;
    }
    match func {
        "GetStdHandle" => Some(get_std_handle as *const () as usize),
        "WriteConsoleW" => Some(
            write_console_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "ExitProcess" => Some(exit_process as *const () as usize),
        "GetLastError" => Some(get_last_error as *const () as usize),
        "SetLastError" => Some(set_last_error as *const () as usize),
        "VirtualProtect" => {
            Some(virtual_protect as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "VirtualQuery" => {
            Some(virtual_query as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "Sleep" => Some(sleep as *const () as usize),
        "TlsGetValue" => Some(tls_get_value as *const () as usize),
        "InitializeCriticalSection" => {
            Some(initialize_critical_section as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "EnterCriticalSection" => Some(enter_critical_section as *const () as usize),
        "LeaveCriticalSection" => Some(leave_critical_section as *const () as usize),
        "DeleteCriticalSection" => Some(delete_critical_section as *const () as usize),
        "SetUnhandledExceptionFilter" => Some(set_unhandled_exception_filter as *const () as usize),
        "__C_specific_handler" => Some(c_specific_handler as *const () as usize),
        _ => None,
    }
}
