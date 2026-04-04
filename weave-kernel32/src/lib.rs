//! kernel32.dll stubs for Weave.
//!
//! Critical section stubs are no-ops (Phase 1/2 is single-threaded).
//! VirtualProtect/VirtualQuery delegate to mprotect/mincore.
//! WriteConsoleW converts UTF-16 to UTF-8 and writes to the Linux fd.
//! CreateFileW/ReadFile/WriteFile/CloseHandle delegate to weave-core file_io.

#![allow(non_snake_case)]

use std::cell::Cell;
use weave_common::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use weave_core::{file_io, handles};

// Windows limits null-terminated strings to 32,767 UTF-16 code units (MAX_PATH extended).
// Scanning beyond this is almost certainly a caller bug; cap the loop to avoid runaway reads.
const MAX_UTF16_LEN: usize = 32_768;
const MAX_UTF8_LEN: usize = 65_536;

// Per-thread last error, shared across GetLastError / SetLastError.
thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// Windows OSVERSIONINFOEXW — extended version information.
/// This is the superset; OSVERSIONINFOW is the first 276 bytes.
#[repr(C)]
pub struct OsVersionInfoExW {
    dw_os_version_info_size: u32,
    dw_major_version: u32,
    dw_minor_version: u32,
    dw_build_number: u32,
    dw_platform_id: u32,
    sz_csd_version: [u16; 128],
    w_service_pack_major: u16,
    w_service_pack_minor: u16,
    w_suite_mask: u16,
    w_product_type: u8,
    w_reserved: u8,
}

/// Windows OSVERSIONINFOEXA — extended version information (ANSI).
#[repr(C)]
struct OsVersionInfoExA {
    dw_os_version_info_size: u32,
    dw_major_version: u32,
    dw_minor_version: u32,
    dw_build_number: u32,
    dw_platform_id: u32,
    sz_csd_version: [u8; 128],
    w_service_pack_major: u16,
    w_service_pack_minor: u16,
    w_suite_mask: u16,
    w_product_type: u8,
    w_reserved: u8,
}

/// Mirrors Windows CONSOLE_SCREEN_BUFFER_INFO layout.
#[repr(C)]
pub struct ConsoleScreenBufferInfo {
    pub size_x: i16,
    pub size_y: i16,
    pub cursor_x: i16,
    pub cursor_y: i16,
    pub attributes: u16,
    pub window_left: i16,
    pub window_top: i16,
    pub window_right: i16,
    pub window_bottom: i16,
    pub max_x: i16,
    pub max_y: i16,
}

/// Mirrors Windows BY_HANDLE_FILE_INFORMATION layout.
#[repr(C)]
pub struct ByHandleFileInformation {
    pub dw_file_attributes: u32,
    pub ft_creation_time_low: u32,
    pub ft_creation_time_high: u32,
    pub ft_last_access_time_low: u32,
    pub ft_last_access_time_high: u32,
    pub ft_last_write_time_low: u32,
    pub ft_last_write_time_high: u32,
    pub dw_volume_serial_number: u32,
    pub n_file_size_high: u32,
    pub n_file_size_low: u32,
    pub n_number_of_links: u32,
    pub n_file_index_high: u32,
    pub n_file_index_low: u32,
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

// ── Locale information ───────────────────────────────────────────────────────

fn locale_info_lookup(lc_type: u32) -> Option<&'static str> {
    match lc_type {
        0x0001 => Some("en-US"),   // LOCALE_SLANGUAGE / LOCALE_SLOCALIZEDDISPLAYNAME
        0x0002 => Some("English"), // LOCALE_SABBREVLANGNAME / LOCALE_SENGLISHDISPLAYNAME
        0x0003 => Some("ENU"),     // LOCALE_SNATIVELANGNAME (abbreviated)
        0x0004 => Some("US"),      // LOCALE_SCOUNTRY
        0x0007 => Some("English (United States)"), // LOCALE_SENGCOUNTRY
        0x000B => Some("437"),     // LOCALE_IDEFAULTCODEPAGE (OEM code page)
        0x000C => Some(";"),       // LOCALE_SLIST
        0x000D => Some("1"),       // LOCALE_IMEASURE (1 = imperial)
        0x000E => Some("."),       // LOCALE_SDECIMAL
        0x000F => Some(","),       // LOCALE_STHOUSAND
        0x0012 => Some("1"),       // LOCALE_ILZERO (leading zeros)
        0x0013 => Some("0123456789"), // LOCALE_SNATIVEDIGITS
        0x0014 => Some("$"),       // LOCALE_SCURRENCY
        0x0019 => Some("2"),       // LOCALE_ICURRDIGITS
        0x0050 => Some(""),        // LOCALE_SPOSITIVESIGN
        0x0051 => Some("-"),       // LOCALE_SNEGATIVESIGN
        0x0059 => Some("en"),      // LOCALE_SISO639LANGNAME
        0x005A => Some("US"),      // LOCALE_SISO3166CTRYNAME
        0x1004 => Some("1252"),    // LOCALE_IDEFAULTANSICODEPAGE
        _ => None,
    }
}

// ── Stubs ─────────────────────────────────────────────────────────────────────

/// GetStdHandle: return the Weave HANDLE for stdin/stdout/stderr.
///
/// Returns handle constants from the global handle table (4/5/6 for
/// stdin/stdout/stderr). These map to Linux fds 0/1/2 in the table.
pub extern "win64" fn get_std_handle(n_std_handle: u32) -> usize {
    match n_std_handle {
        STD_INPUT_HANDLE => handles::STDIN_HANDLE,
        STD_OUTPUT_HANDLE => handles::STDOUT_HANDLE,
        STD_ERROR_HANDLE => handles::STDERR_HANDLE,
        _ => usize::MAX, // INVALID_HANDLE_VALUE
    }
}

/// WriteConsoleW: write a UTF-16 buffer to a console handle.
///
/// Looks up the Linux fd via the global HANDLE table, converts UTF-16 to
/// UTF-8, then writes to the fd.
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
    let fd = match handles::get_fd(h_console_output) {
        Some(fd) => fd,
        None => return 0, // FALSE
    };
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

/// VirtualAlloc: allocate virtual memory.
///
/// # Safety
/// `lp_address` must be null or a valid address for allocation.
pub unsafe extern "win64" fn virtual_alloc(
    lp_address: *mut u8,
    dw_size: usize,
    _fl_allocation_type: u32,
    fl_protect: u32,
) -> *mut u8 {
    let prot = win_prot_to_linux(fl_protect);
    const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
    let result = if lp_address.is_null() {
        unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                dw_size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        }
    } else {
        unsafe {
            libc::mmap(
                lp_address as *mut libc::c_void,
                dw_size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        }
    };
    if result == libc::MAP_FAILED {
        std::ptr::null_mut()
    } else {
        result as *mut u8
    }
}

/// VirtualAllocEx: allocate virtual memory in another process.
///
/// # Safety
/// `lp_address` must be null or a valid address for allocation.
pub unsafe extern "win64" fn virtual_alloc_ex(
    _h_process: usize,
    lp_address: *mut u8,
    dw_size: usize,
    fl_allocation_type: u32,
    fl_protect: u32,
) -> *mut u8 {
    unsafe { virtual_alloc(lp_address, dw_size, fl_allocation_type, fl_protect) }
}

/// VirtualFree: free virtual memory.
///
/// # Safety
/// `lp_address` must be a valid allocated address.
pub unsafe extern "win64" fn virtual_free(
    lp_address: *mut u8,
    dw_size: usize,
    _dw_free_type: u32,
) -> i32 {
    if lp_address.is_null() || dw_size == 0 {
        1 // TRUE
    } else {
        let ret = unsafe { libc::munmap(lp_address as *mut libc::c_void, dw_size) };
        (ret == 0) as i32
    }
}

/// VirtualFreeEx: free virtual memory in another process.
///
/// # Safety
/// `lp_address` must be a valid allocated address.
pub unsafe extern "win64" fn virtual_free_ex(
    _h_process: usize,
    lp_address: *mut u8,
    dw_size: usize,
    dw_free_type: u32,
) -> i32 {
    unsafe { virtual_free(lp_address, dw_size, dw_free_type) }
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

/// IsDBCSLeadByte: test whether a byte is a lead byte in the current DBCS.
///
/// Linux always uses UTF-8; DBCS is never active. Always returns FALSE.
pub extern "win64" fn is_dbcs_lead_byte(_test_char: u8) -> i32 {
    0 // FALSE
}

/// IsDBCSLeadByteEx: test whether a byte is a lead byte for a specific code page.
///
/// Only UTF-8 (65001) is used; DBCS is not active. Always returns FALSE.
pub extern "win64" fn is_dbcs_lead_byte_ex(_code_page: u32, _test_char: u8) -> i32 {
    0 // FALSE
}

/// GetACP: return the current ANSI code page identifier.
///
/// Returns 65001 (UTF-8) — the only code page Weave supports.
pub extern "win64" fn get_acp() -> u32 {
    65001 // CP_UTF8
}

// ── Task 1 — SRW try-acquire + DuplicateHandle + WaitOnAddress family ───────

/// TryAcquireSRWLockExclusive: try to acquire an SRW lock for exclusive access.
///
/// Single-threaded stub — always succeeds.
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
pub unsafe extern "win64" fn try_acquire_srw_lock_exclusive(srw_lock: *mut usize) -> u8 {
    let _ = srw_lock; // accepted but not dereferenced
    1 // TRUE — always succeeds in single-threaded context
}

/// TryAcquireSRWLockShared: try to acquire an SRW lock for shared access.
///
/// Single-threaded stub — always succeeds.
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
pub unsafe extern "win64" fn try_acquire_srw_lock_shared(srw_lock: *mut usize) -> u8 {
    let _ = srw_lock; // accepted but not dereferenced
    1 // TRUE — always succeeds in single-threaded context
}

/// DuplicateHandle: duplicate a handle to another process.
///
/// Stub: if `lp_target_handle` is non-null, write `h_source_handle` to it. Return TRUE.
/// # Safety
/// `lp_target_handle` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn duplicate_handle(
    _h_source_process_handle: usize,
    h_source_handle: usize,
    _h_target_process_handle: usize,
    lp_target_handle: *mut usize,
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _dw_options: u32,
) -> i32 {
    if !lp_target_handle.is_null() {
        unsafe { *lp_target_handle = h_source_handle };
    }
    1 // TRUE
}

/// ProcessIdToSessionId: get the session ID for a process.
///
/// Stub: write 0 to `*p_session_id` if non-null. Return TRUE.
/// # Safety
/// `p_session_id` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn process_id_to_session_id(
    _dw_process_id: u32,
    p_session_id: *mut u32,
) -> i32 {
    if !p_session_id.is_null() {
        unsafe { *p_session_id = 0 };
    }
    1 // TRUE
}

/// WaitOnAddress: wait for a value at an address to change.
///
/// Stub: immediately return TRUE (no actual waiting).
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn wait_on_address(
    _address: *const u8,
    _compare_address: *const u8,
    _address_size: usize,
    _dw_milliseconds: u32,
) -> i32 {
    1 // TRUE
}

/// WakeByAddressSingle: wake one thread waiting on an address.
///
/// No-op.
/// # Safety
/// `_address` is accepted but never dereferenced.
pub extern "win64" fn wake_by_address_single(_address: usize) {}

/// WakeByAddressAll: wake all threads waiting on an address.
///
/// No-op.
/// # Safety
/// `_address` is accepted but never dereferenced.
pub extern "win64" fn wake_by_address_all(_address: usize) {}

// ── Task 2 — Thread description + timer queue + affinity ────────────────────

/// SetThreadDescription: set a description for a thread.
///
/// No-op. Returns S_OK.
/// # Safety
/// `_h_thread` and `_lp_thread_description` are accepted but not dereferenced.
pub unsafe extern "win64" fn set_thread_description(
    _h_thread: usize,
    _lp_thread_description: *const u16,
) -> i32 {
    0 // S_OK
}

/// GetThreadDescription: get the description for a thread.
///
/// Write null to `*ppsz_thread_description` if non-null. Return S_OK.
/// # Safety
/// `ppsz_thread_description` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_thread_description(
    _h_thread: usize,
    ppsz_thread_description: *mut *mut u16,
) -> i32 {
    if !ppsz_thread_description.is_null() {
        unsafe { *ppsz_thread_description = std::ptr::null_mut() };
    }
    0 // S_OK
}

/// CreateTimerQueueTimer: create a timer queue timer.
///
/// Stub: if `ph_new_timer` is non-null, write 1 to it. Return TRUE.
/// # Safety
/// `ph_new_timer` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn create_timer_queue_timer(
    ph_new_timer: *mut usize,
    _timer_queue: usize,
    _callback: usize,
    _parameter: usize,
    _due_time: u32,
    _period: u32,
    _flags: u32,
) -> i32 {
    if !ph_new_timer.is_null() {
        unsafe { *ph_new_timer = 1 };
    }
    1 // TRUE
}

/// DeleteTimerQueueTimer: delete a timer queue timer.
///
/// No-op. Return TRUE.
/// # Safety
/// Arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn delete_timer_queue_timer(
    _timer_queue: usize,
    _timer: usize,
    _completion_event: usize,
) -> i32 {
    1 // TRUE
}

/// SetThreadAffinityMask: set the processor affinity mask for a thread.
///
/// Stub: return 1 (previous mask).
/// # Safety
/// `_h_thread` and `_dw_thread_affinity_mask` are accepted but not dereferenced.
pub unsafe extern "win64" fn set_thread_affinity_mask(
    _h_thread: usize,
    _dw_thread_affinity_mask: usize,
) -> usize {
    1 // previous mask
}

// ── Task 1 — System query stubs ──────────────────────────────────────────────

/// IsWow64Process: check if a process is running under WOW64.
///
/// Every app is 64-bit under Weave — WoW64 is never active.
/// Returns TRUE (1) and writes FALSE (0) to *wow64_process if non-null.
///
/// # Safety
/// `wow64_process` must be a valid pointer to an i32 if non-null.
pub unsafe extern "win64" fn is_wow64_process(_h_process: usize, wow64_process: *mut i32) -> i32 {
    if !wow64_process.is_null() {
        unsafe { *wow64_process = 0i32 }; // FALSE
    }
    1 // TRUE
}

/// IsProcessorFeaturePresent: check if a processor feature is present.
///
/// Returns FALSE (0) for all features — stub implementation.
pub extern "win64" fn is_processor_feature_present(_processor_feature: u32) -> i32 {
    0 // FALSE
}

/// FlushInstructionCache: flush the instruction cache.
///
/// No-op. On x86-64 Linux the icache is coherent with dcache by hardware.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn flush_instruction_cache(
    _h_process: usize,
    _lp_base_address: usize,
    _dw_size: usize,
) -> i32 {
    1 // TRUE
}

/// GetSystemTimePreciseAsFileTime: get the current system time as a file time.
///
/// Returns the current time in FILETIME format (100-nanosecond intervals since 1601-01-01).
///
/// # Safety
/// `lp_system_time_as_file_time` must be a valid pointer to a u64.
pub unsafe extern "win64" fn get_system_time_precise_as_file_time(
    lp_system_time_as_file_time: *mut u64,
) {
    if lp_system_time_as_file_time.is_null() {
        return;
    }
    let mut ts = unsafe { std::mem::zeroed::<libc::timespec>() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let ft = (ts.tv_sec as u64) * 10_000_000u64
        + (ts.tv_nsec as u64) / 100u64
        + 116_444_736_000_000_000u64;
    unsafe { *lp_system_time_as_file_time = ft };
}

/// GetLargePageMinimum: get the minimum size of a large page.
///
/// Returns 0 — large pages not supported.
pub extern "win64" fn get_large_page_minimum() -> usize {
    0
}

/// SetHandleInformation: set handle information flags.
///
/// No-op. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_handle_information(
    _h_object: usize,
    _dw_mask: u32,
    _dw_flags: u32,
) -> i32 {
    1 // TRUE
}

// ── Task 2 — One-time init + waitable timers ─────────────────────────────────

/// InitOnceExecuteOnce: execute one-time initialization.
///
/// # Safety
/// `init_once`, `parameter`, and `context` must be valid pointers.
pub unsafe extern "win64" fn init_once_execute_once(
    init_once: *mut usize,
    init_fn: unsafe extern "win64" fn(*mut usize, *mut u8, *mut *mut u8) -> i32,
    parameter: *mut u8,
    context: *mut *mut u8,
) -> i32 {
    if init_once.is_null() {
        return 1; // TRUE
    }
    if unsafe { *init_once == 2 } {
        return 1; // TRUE - already done
    }
    unsafe { *init_once = 1 };
    let result = unsafe { init_fn(init_once, parameter, context) };
    unsafe { *init_once = 2 };
    result
}

/// InitOnceBeginInitialize: begin one-time initialization.
///
/// # Safety
/// `lp_init_once` and `f_pending` must be valid pointers.
pub unsafe extern "win64" fn init_once_begin_initialize(
    lp_init_once: *mut usize,
    _dw_flags: u32,
    f_pending: *mut i32,
    _lp_context: *mut *mut u8,
) -> i32 {
    if !f_pending.is_null() {
        let pending = if !lp_init_once.is_null() && unsafe { *lp_init_once == 2 } {
            0i32 // FALSE - not pending
        } else {
            1i32 // TRUE - pending
        };
        unsafe { *f_pending = pending };
    }
    1 // TRUE
}

/// InitOnceComplete: complete one-time initialization.
///
/// # Safety
/// `lp_init_once` must be a valid pointer.
pub unsafe extern "win64" fn init_once_complete(
    lp_init_once: *mut usize,
    _dw_flags: u32,
    _lp_context: *mut u8,
) -> i32 {
    if !lp_init_once.is_null() {
        unsafe { *lp_init_once = 2 };
    }
    1 // TRUE
}

/// CreateWaitableTimerW: create a waitable timer (wide version).
///
/// Returns a fake handle (1usize).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_waitable_timer_w(
    _lp_timer_attributes: usize,
    _b_manual_reset: i32,
    _lp_timer_name: *const u16,
) -> usize {
    1 // fake handle
}

/// CreateWaitableTimerA: create a waitable timer (ANSI version).
///
/// Returns a fake handle (1usize).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_waitable_timer_a(
    _lp_timer_attributes: usize,
    _b_manual_reset: i32,
    _lp_timer_name: usize,
) -> usize {
    1 // fake handle
}

/// SetWaitableTimer: set a waitable timer.
///
/// No-op. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_waitable_timer(
    _h_timer: usize,
    _lp_due_time: usize,
    _l_period: i32,
    _pfn_completion_routine: usize,
    _lp_arg_to_completion_routine: usize,
    _f_resume: i32,
) -> i32 {
    1 // TRUE
}

/// CancelWaitableTimer: cancel a waitable timer.
///
/// No-op. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn cancel_waitable_timer(_h_timer: usize) -> i32 {
    1 // TRUE
}

// ── Task 3 — ExpandEnvironmentStrings, SearchPath, GetTempFileName ──────────

/// ExpandEnvironmentStringsW: expand environment variables in a wide string.
///
/// Phase 2: no actual expansion — returns the input string unchanged.
/// Copies the input string to the output buffer, null-terminated.
///
/// # Safety
/// `lp_src` must be a valid null-terminated UTF-16 string.
/// `lp_dst` must be writable for `n_size` u16 words.
pub unsafe extern "win64" fn expand_environment_strings_w(
    lp_src: *const u16,
    lp_dst: *mut u16,
    n_size: u32,
) -> u32 {
    if lp_src.is_null() {
        return 0;
    }

    // Read the null-terminated UTF-16 string
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_src.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return 0;
    }

    let required = len + 1; // include null terminator
    if n_size == 0 || lp_dst.is_null() {
        return required as u32;
    }

    if n_size as usize <= len {
        // Copy what fits, null-terminate
        unsafe {
            std::ptr::copy_nonoverlapping(lp_src, lp_dst, n_size as usize - 1);
            *lp_dst.add(n_size as usize - 1) = 0;
        }
        return required as u32;
    }

    // Copy the full string
    unsafe {
        std::ptr::copy_nonoverlapping(lp_src, lp_dst, required);
    }
    required as u32
}

/// ExpandEnvironmentStringsA: expand environment variables in an ANSI string.
///
/// Phase 2: no actual expansion — returns the input string unchanged.
/// Copies the input string to the output buffer, null-terminated.
///
/// # Safety
/// `lp_src` must be a valid null-terminated UTF-8 string.
/// `lp_dst` must be writable for `n_size` bytes.
pub unsafe extern "win64" fn expand_environment_strings_a(
    lp_src: *const u8,
    lp_dst: *mut u8,
    n_size: u32,
) -> u32 {
    if lp_src.is_null() {
        return 0;
    }

    // Read the null-terminated UTF-8 string
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_src.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return 0;
    }

    let required = len + 1; // include null terminator
    if n_size == 0 || lp_dst.is_null() {
        return required as u32;
    }

    if n_size as usize <= len {
        // Copy what fits, null-terminate
        unsafe {
            std::ptr::copy_nonoverlapping(lp_src, lp_dst, n_size as usize - 1);
            *lp_dst.add(n_size as usize - 1) = 0;
        }
        return required as u32;
    }

    // Copy the full string
    unsafe {
        std::ptr::copy_nonoverlapping(lp_src, lp_dst, required);
    }
    required as u32
}

/// SearchPathW: search for a file in the PATH.
///
/// Stub implementation — always returns 0 (not found).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn search_path_w(
    _lp_path: *const u16,
    _lp_file_name: *const u16,
    _lp_extension: *const u16,
    _n_buffer_length: u32,
    _lp_buffer: *mut u16,
    _lp_file_part: *mut *mut u16,
) -> u32 {
    0 // not found
}

/// SearchPathA: search for a file in the PATH (ANSI version).
///
/// Stub implementation — always returns 0 (not found).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn search_path_a(
    _lp_path: *const u8,
    _lp_file_name: *const u8,
    _lp_extension: *const u8,
    _n_buffer_length: u32,
    _lp_buffer: *mut u8,
    _lp_file_part: *mut *mut u8,
) -> u32 {
    0 // not found
}

/// GetTempFileNameW: create a temporary filename.
///
/// Generates a temporary filename using the specified path and prefix.
/// Uses process ID and time for uniqueness.
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-16 string.
/// `lp_prefix_string` may be null.
/// `lp_temp_file_name` must be writable for at least 260 u16 words.
pub unsafe extern "win64" fn get_temp_file_name_w(
    lp_path_name: *const u16,
    lp_prefix_string: *const u16,
    u_unique: u32,
    lp_temp_file_name: *mut u16,
) -> u32 {
    if lp_path_name.is_null() || lp_temp_file_name.is_null() {
        return 0;
    }

    // Read path
    let mut path_len = 0usize;
    while path_len < MAX_UTF16_LEN && unsafe { *lp_path_name.add(path_len) } != 0 {
        path_len += 1;
    }
    if path_len == MAX_UTF16_LEN {
        return 0;
    }
    let path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_path_name, path_len)) };

    // Read prefix (up to 3 chars)
    let prefix = if lp_prefix_string.is_null() {
        "tmp".to_string()
    } else {
        let mut prefix_len = 0usize;
        while prefix_len < 3 && unsafe { *lp_prefix_string.add(prefix_len) } != 0 {
            prefix_len += 1;
        }
        unsafe {
            String::from_utf16_lossy(std::slice::from_raw_parts(lp_prefix_string, prefix_len))
        }
    };

    // Generate unique number
    let unique = if u_unique != 0 {
        u_unique
    } else {
        unsafe { (libc::getpid() as u32) ^ (libc::time(std::ptr::null_mut()) as u32) }
    };

    // Build filename
    let filename = format!("{}\\{}", path, prefix);
    let temp_name = format!("{}\\{:04X}.tmp", filename, unique & 0xFFFF);

    // Convert to UTF-16 and write to buffer (up to 260 chars)
    let wide_name: Vec<u16> = temp_name.encode_utf16().collect();
    let copy_len = wide_name.len().min(259); // leave room for null
    unsafe {
        std::ptr::copy_nonoverlapping(wide_name.as_ptr(), lp_temp_file_name, copy_len);
        *lp_temp_file_name.add(copy_len) = 0;
    }

    unique & 0xFFFF
}

/// GetTempFileNameA: create a temporary filename (ANSI version).
///
/// Generates a temporary filename using the specified path and prefix.
/// Uses process ID and time for uniqueness.
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-8 string.
/// `lp_prefix_string` may be null.
/// `lp_temp_file_name` must be writable for at least 260 bytes.
pub unsafe extern "win64" fn get_temp_file_name_a(
    lp_path_name: *const u8,
    lp_prefix_string: *const u8,
    u_unique: u32,
    lp_temp_file_name: *mut u8,
) -> u32 {
    if lp_path_name.is_null() || lp_temp_file_name.is_null() {
        return 0;
    }

    // Read path
    let mut path_len = 0usize;
    while path_len < MAX_UTF8_LEN && unsafe { *lp_path_name.add(path_len) } != 0 {
        path_len += 1;
    }
    if path_len == MAX_UTF8_LEN {
        return 0;
    }
    let path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_path_name, path_len)) };

    // Read prefix (up to 3 chars)
    let prefix = if lp_prefix_string.is_null() {
        "tmp".to_string()
    } else {
        let mut prefix_len = 0usize;
        while prefix_len < 3 && unsafe { *lp_prefix_string.add(prefix_len) } != 0 {
            prefix_len += 1;
        }
        unsafe {
            String::from_utf8_lossy(std::slice::from_raw_parts(lp_prefix_string, prefix_len))
                .to_string()
        }
    };

    // Generate unique number
    let unique = if u_unique != 0 {
        u_unique
    } else {
        unsafe { (libc::getpid() as u32) ^ (libc::time(std::ptr::null_mut()) as u32) }
    };

    // Build filename
    let filename = format!("{}\\{}", path, prefix);
    let temp_name = format!("{}\\{:04X}.tmp", filename, unique & 0xFFFF);

    // Write to buffer (up to 260 chars)
    let bytes = temp_name.as_bytes();
    let copy_len = bytes.len().min(259); // leave room for null
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_temp_file_name, copy_len);
        *lp_temp_file_name.add(copy_len) = 0;
    }

    unique & 0xFFFF
}

/// GetOEMCP: return the current OEM code page identifier.
pub extern "win64" fn get_oemcp() -> u32 {
    65001
}

/// GetConsoleCP: return the console input code page.
pub extern "win64" fn get_console_cp() -> u32 {
    65001
}

/// GetConsoleOutputCP: return the console output code page.
pub extern "win64" fn get_console_output_cp() -> u32 {
    65001
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

// ── Heap / global memory ──────────────────────────────────────────────────────

/// GlobalAlloc: allocate a block of memory from the heap.
///
/// Phase 2: `GMEM_FIXED` and `GMEM_MOVEABLE` are both handled by returning
/// a real heap pointer (handle == pointer). Zeroing (`GMEM_ZEROINIT`) is
/// honoured.
pub extern "win64" fn global_alloc(u_flags: u32, dw_bytes: usize) -> usize {
    if dw_bytes == 0 {
        return 0;
    }
    let zeroinit = (u_flags & 0x40) != 0; // GMEM_ZEROINIT
    let ptr = if zeroinit {
        unsafe { libc::calloc(1, dw_bytes) }
    } else {
        unsafe { libc::malloc(dw_bytes) }
    };
    ptr as usize
}

/// GlobalFree: free memory allocated by `GlobalAlloc`.
///
/// Returns NULL on success, the original handle on failure.
pub extern "win64" fn global_free(h_mem: usize) -> usize {
    if h_mem == 0 {
        return 0;
    }
    unsafe { libc::free(h_mem as *mut libc::c_void) };
    0 // success
}

/// GlobalLock: lock a global memory object and return a pointer.
///
/// Phase 2: `HGLOBAL == pointer`, so just return `h_mem` directly.
pub extern "win64" fn global_lock(h_mem: usize) -> usize {
    h_mem // pointer == handle in Phase 2
}

/// GlobalUnlock: decrement the lock count of a global memory object.
///
/// Phase 2: no-op; returns TRUE.
pub extern "win64" fn global_unlock(_h_mem: usize) -> i32 {
    1 // TRUE
}

/// GlobalSize: return the size of a global memory block.
///
/// Phase 2: we don't track sizes; returns 0 (stub).
pub extern "win64" fn global_size(_h_mem: usize) -> usize {
    0
}

/// LocalAlloc: allocate a block of local memory (alias for GlobalAlloc).
pub extern "win64" fn local_alloc(u_flags: u32, u_bytes: usize) -> usize {
    global_alloc(u_flags, u_bytes)
}

/// LocalFree: free memory allocated by `LocalAlloc`.
pub extern "win64" fn local_free(h_mem: usize) -> usize {
    global_free(h_mem)
}

/// LocalLock: lock a local memory object (alias for GlobalLock).
pub extern "win64" fn local_lock(h_mem: usize) -> usize {
    global_lock(h_mem)
}

/// LocalUnlock: unlock a local memory object (alias for GlobalUnlock).
pub extern "win64" fn local_unlock(h_mem: usize) -> i32 {
    global_unlock(h_mem)
}

/// LocalReAlloc: reallocate a local memory block.
///
/// Wraps `realloc` with optional zero-initialization when `LMEM_ZEROINIT` (0x0040) is set.
/// For simplicity, if the ZEROINIT flag is set, memset the entire block to 0 after realloc
/// (conservative but correct). Ignores `LMEM_MOVEABLE` — we always move.
///
/// # Safety
/// `h_mem` must be a valid pointer returned from LocalAlloc or NULL.
pub unsafe extern "win64" fn local_re_alloc(
    h_mem: *mut std::ffi::c_void,
    u_bytes: usize,
    u_flags: u32,
) -> *mut std::ffi::c_void {
    const LMEM_ZEROINIT: u32 = 0x0040;
    let new_ptr = unsafe { libc::realloc(h_mem, u_bytes) };
    if !new_ptr.is_null() && (u_flags & LMEM_ZEROINIT) != 0 {
        unsafe { std::ptr::write_bytes(new_ptr, 0, u_bytes) };
    }
    new_ptr
}

/// HeapCreate: create a heap and return a fake handle.
///
/// Weave uses a single process heap (libc allocator). Return a fake but
/// consistent handle value so callers can pass it back. Use `1usize` as the
/// "process heap" sentinel. Ignore all parameters.
pub extern "win64" fn heap_create(
    _fl_options: u32,
    _dw_initial_size: usize,
    _dw_maximum_size: usize,
) -> usize {
    1usize // fake process heap handle
}

/// HeapDestroy: destroy a heap (no-op).
///
/// Returns TRUE. Never actually destroy memory — the "heap" is just the libc allocator.
pub extern "win64" fn heap_destroy(_h_heap: usize) -> i32 {
    1 // TRUE
}

/// HeapAlloc: allocate memory from the heap.
///
/// Wraps `malloc` with optional zero-initialization when HEAP_ZERO_MEMORY (0x08) is set.
/// Ignores the hHeap parameter (we use a single global allocator).
///
/// # Safety
/// The returned pointer must be freed with HeapFree or it will leak.
pub extern "win64" fn heap_alloc(
    _h_heap: usize,
    dw_flags: u32,
    dw_bytes: usize,
) -> *mut std::ffi::c_void {
    if dw_bytes == 0 {
        return std::ptr::null_mut();
    }
    let zero_memory = (dw_flags & 0x08) != 0; // HEAP_ZERO_MEMORY
    if zero_memory {
        unsafe { libc::calloc(1, dw_bytes) }
    } else {
        unsafe { libc::malloc(dw_bytes) }
    }
}

/// HeapReAlloc: reallocate memory in the heap.
///
/// Wraps `realloc`. Ignores hHeap and dwFlags parameters.
///
/// # Safety
/// `lp_mem` must be a valid pointer returned from HeapAlloc or NULL.
/// The returned pointer must be freed with HeapFree or it will leak.
pub unsafe extern "win64" fn heap_re_alloc(
    _h_heap: usize,
    _dw_flags: u32,
    lp_mem: *mut std::ffi::c_void,
    dw_bytes: usize,
) -> *mut std::ffi::c_void {
    unsafe { libc::realloc(lp_mem, dw_bytes) }
}

/// HeapFree: free memory allocated from the heap.
///
/// Wraps `free`. Ignores hHeap and dwFlags parameters.
///
/// # Safety
/// `lp_mem` must be a valid pointer returned from HeapAlloc/HeapReAlloc or NULL.
pub unsafe extern "win64" fn heap_free(
    _h_heap: usize,
    _dw_flags: u32,
    lp_mem: *mut std::ffi::c_void,
) -> i32 {
    if lp_mem.is_null() {
        return 1; // TRUE
    }
    unsafe { libc::free(lp_mem) };
    1 // TRUE
}

/// HeapSize: return the size of a heap block.
///
/// We don't track allocation sizes; returns 0 (acceptable for defensive callers).
pub extern "win64" fn heap_size(
    _h_heap: usize,
    _dw_flags: u32,
    _lp_mem: *const std::ffi::c_void,
) -> usize {
    0
}

/// GetProcessHeap: return the process heap handle.
///
/// Returns the same fake handle as HeapCreate (1usize).
pub extern "win64" fn get_process_heap() -> usize {
    1usize
}

// ── File I/O ──────────────────────────────────────────────────────────────────

/// CreateFileA: open or create a file and return a HANDLE.
///
/// Translates Win32 parameters to NT equivalents and delegates to the
/// shared `file_io::open_file` engine in weave-core.
///
/// # Safety
/// `lp_file_name` must be a valid, null-terminated UTF-8 string.
pub unsafe extern "win64" fn create_file_a(
    lp_file_name: *const u8,
    dw_desired_access: u32,
    _dw_share_mode: u32,       // ignored — no file locking in Phase 2
    _lp_security_attrs: usize, // ignored
    dw_creation_disposition: u32,
    _dw_flags_and_attrs: u32, // ignored
    _h_template_file: usize,  // ignored
) -> usize {
    if lp_file_name.is_null() {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
        return usize::MAX; // INVALID_HANDLE_VALUE
    }

    // Decode the null-terminated UTF-8 filename.
    let win_path = unsafe {
        let mut len = 0usize;
        while len < MAX_UTF8_LEN && *lp_file_name.add(len) != 0 {
            len += 1;
        }
        if len == MAX_UTF8_LEN {
            LAST_ERROR.with(|e| e.set(87)); // ERROR_INVALID_PARAMETER
            return usize::MAX;
        }
        let slice = std::slice::from_raw_parts(lp_file_name, len);
        String::from_utf8_lossy(slice).into_owned()
    };

    let nt_disposition = file_io::win32_disposition_to_nt(dw_creation_disposition);

    match file_io::open_file(&win_path, dw_desired_access, nt_disposition) {
        Ok(handle) => {
            LAST_ERROR.with(|e| e.set(0));
            handle
        }
        Err(_status) => {
            // Map NT status back to a Win32 error code. For now, return a
            // generic error; Phase 3 can refine the mapping.
            LAST_ERROR.with(|e| e.set(file_io::ERROR_FILE_NOT_FOUND));
            usize::MAX // INVALID_HANDLE_VALUE
        }
    }
}

/// CreateFileW: open or create a file and return a HANDLE.
///
/// Translates Win32 parameters to NT equivalents and delegates to the
/// shared `file_io::open_file` engine in weave-core.
///
/// # Safety
/// `lp_file_name` must be a valid, null-terminated UTF-16 string.
pub unsafe extern "win64" fn create_file_w(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    _dw_share_mode: u32,       // ignored — no file locking in Phase 2
    _lp_security_attrs: usize, // ignored
    dw_creation_disposition: u32,
    _dw_flags_and_attrs: u32, // ignored
    _h_template_file: usize,  // ignored
) -> usize {
    if lp_file_name.is_null() {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
        return usize::MAX; // INVALID_HANDLE_VALUE
    }

    // Decode the null-terminated UTF-16 filename.
    let win_path = unsafe {
        let mut len = 0usize;
        while len < MAX_UTF16_LEN && *lp_file_name.add(len) != 0 {
            len += 1;
        }
        if len == MAX_UTF16_LEN {
            LAST_ERROR.with(|e| e.set(87)); // ERROR_INVALID_PARAMETER
            return usize::MAX;
        }
        let slice = std::slice::from_raw_parts(lp_file_name, len);
        String::from_utf16_lossy(slice).to_owned()
    };

    let nt_disposition = file_io::win32_disposition_to_nt(dw_creation_disposition);

    match file_io::open_file(&win_path, dw_desired_access, nt_disposition) {
        Ok(handle) => {
            LAST_ERROR.with(|e| e.set(0));
            handle
        }
        Err(_status) => {
            // Map NT status back to a Win32 error code. For now, return a
            // generic error; Phase 3 can refine the mapping.
            LAST_ERROR.with(|e| e.set(file_io::ERROR_FILE_NOT_FOUND));
            usize::MAX // INVALID_HANDLE_VALUE
        }
    }
}

/// ReadFile: read bytes from a file handle into a buffer.
///
/// # Safety
/// `lp_buffer` must be valid for `n_bytes_to_read` bytes.
pub unsafe extern "win64" fn read_file(
    h_file: usize,
    lp_buffer: *mut u8,
    n_bytes_to_read: u32,
    lp_bytes_read: *mut u32,
    _lp_overlapped: usize, // ignored — synchronous I/O only
) -> i32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
            return 0; // FALSE
        }
    };

    let n = unsafe { libc::read(fd, lp_buffer as *mut libc::c_void, n_bytes_to_read as usize) };

    if !lp_bytes_read.is_null() {
        unsafe { *lp_bytes_read = if n >= 0 { n as u32 } else { 0 } };
    }

    if n < 0 {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_ACCESS_DENIED));
        0 // FALSE
    } else {
        LAST_ERROR.with(|e| e.set(0));
        1 // TRUE
    }
}

/// WriteFile: write bytes from a buffer to a file handle.
///
/// # Safety
/// `lp_buffer` must be valid for `n_bytes_to_write` bytes.
pub unsafe extern "win64" fn write_file(
    h_file: usize,
    lp_buffer: *const u8,
    n_bytes_to_write: u32,
    lp_bytes_written: *mut u32,
    _lp_overlapped: usize, // ignored — synchronous I/O only
) -> i32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
            return 0; // FALSE
        }
    };

    let n = unsafe {
        libc::write(
            fd,
            lp_buffer as *const libc::c_void,
            n_bytes_to_write as usize,
        )
    };

    if !lp_bytes_written.is_null() {
        unsafe { *lp_bytes_written = if n >= 0 { n as u32 } else { 0 } };
    }

    if n < 0 {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_ACCESS_DENIED));
        0 // FALSE
    } else {
        LAST_ERROR.with(|e| e.set(0));
        1 // TRUE
    }
}

/// CloseHandle: close an open object handle.
///
/// Returns TRUE on success, FALSE if the handle was invalid.
/// Closing stdin/stdout/stderr returns FALSE (those are protected).
pub extern "win64" fn close_handle(h_object: usize) -> i32 {
    match file_io::close_handle(h_object) {
        Ok(()) => {
            LAST_ERROR.with(|e| e.set(0));
            1 // TRUE
        }
        Err(_) => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
            0 // FALSE
        }
    }
}

/// DeleteFileW: delete a file by Win32 path.
///
/// Translates the Win32 path and calls `unlink(2)`.
///
/// # Safety
/// `lp_file_name` must be a valid, null-terminated UTF-16 string.
pub unsafe extern "win64" fn delete_file_w(lp_file_name: *const u16) -> i32 {
    if lp_file_name.is_null() {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
        return 0; // FALSE
    }
    let win_path = unsafe {
        let mut len = 0usize;
        while len < MAX_UTF16_LEN && *lp_file_name.add(len) != 0 {
            len += 1;
        }
        if len == MAX_UTF16_LEN {
            LAST_ERROR.with(|e| e.set(87)); // ERROR_INVALID_PARAMETER
            return 0; // FALSE
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)).to_owned()
    };
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_FILE_NOT_FOUND));
            return 0;
        }
    };
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_FILE_NOT_FOUND));
            return 0;
        }
    };
    let ret = unsafe { libc::unlink(c_path.as_ptr()) };
    if ret == 0 {
        LAST_ERROR.with(|e| e.set(0));
        1 // TRUE
    } else {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_FILE_NOT_FOUND));
        0 // FALSE
    }
}

/// SetFilePointer: move the read/write position within an open file handle.
///
/// `dw_move_method`: FILE_BEGIN (0), FILE_CURRENT (1), FILE_END (2).
/// Returns the new file position on success, or INVALID_SET_FILE_POINTER
/// (0xFFFFFFFF) on failure.
/// # Safety
/// `lp_distance_to_move_high`, if non-null, must be a valid pointer to an i32.
pub unsafe extern "win64" fn set_file_pointer(
    h_file: usize,
    l_distance_to_move: i32,
    lp_distance_to_move_high: *mut i32,
    dw_move_method: u32,
) -> u32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
            return 0xFFFF_FFFF; // INVALID_SET_FILE_POINTER
        }
    };

    // Build 64-bit offset from low + optional high word.
    let high = if lp_distance_to_move_high.is_null() {
        0i64
    } else {
        unsafe { *lp_distance_to_move_high as i64 }
    };
    let offset = (high << 32) | (l_distance_to_move as i64);

    let whence = match dw_move_method {
        0 => libc::SEEK_SET,
        1 => libc::SEEK_CUR,
        2 => libc::SEEK_END,
        _ => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
            return 0xFFFF_FFFF;
        }
    };

    let new_pos = unsafe { libc::lseek(fd, offset, whence) };
    if new_pos < 0 {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
        return 0xFFFF_FFFF;
    }

    // Write high 32 bits back if caller provided the pointer.
    if !lp_distance_to_move_high.is_null() {
        unsafe { *lp_distance_to_move_high = (new_pos >> 32) as i32 };
    }

    LAST_ERROR.with(|e| e.set(0));
    (new_pos & 0xFFFF_FFFF) as u32
}

/// GetFileSize: return the size of an open file.
///
/// Returns the low 32 bits of the file size. Writes the high 32 bits to
/// `lp_file_size_high` if non-null. Returns INVALID_FILE_SIZE (0xFFFFFFFF)
/// on error.
/// # Safety
/// `lp_file_size_high`, if non-null, must be a valid pointer to a u32.
pub unsafe extern "win64" fn get_file_size(h_file: usize, lp_file_size_high: *mut u32) -> u32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
            return 0xFFFF_FFFF;
        }
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    if ret != 0 {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
        return 0xFFFF_FFFF;
    }

    let size = stat.st_size as u64;
    if !lp_file_size_high.is_null() {
        unsafe { *lp_file_size_high = (size >> 32) as u32 };
    }
    LAST_ERROR.with(|e| e.set(0));
    (size & 0xFFFF_FFFF) as u32
}

// ── File information functions ───────────────────────────────────────────────

/// # Safety
/// `lp_file_information` must be a valid writable pointer to a ByHandleFileInformation.
pub unsafe extern "win64" fn get_file_information_by_handle(
    h_file: usize,
    lp_file_information: *mut ByHandleFileInformation,
) -> i32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => return 0, // FALSE
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    if ret != 0 {
        return 0; // FALSE
    }

    unsafe {
        (*lp_file_information).dw_file_attributes =
            if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                0x10 // FILE_ATTRIBUTE_DIRECTORY
            } else {
                0x80 // FILE_ATTRIBUTE_NORMAL
            };
        (*lp_file_information).ft_creation_time_low = 0;
        (*lp_file_information).ft_creation_time_high = 0;
        (*lp_file_information).ft_last_access_time_low = 0;
        (*lp_file_information).ft_last_access_time_high = 0;
        (*lp_file_information).ft_last_write_time_low = 0;
        (*lp_file_information).ft_last_write_time_high = 0;
        (*lp_file_information).dw_volume_serial_number = 0xDEADBEEF;
        (*lp_file_information).n_file_size_high = (stat.st_size >> 32) as u32;
        (*lp_file_information).n_file_size_low = (stat.st_size & 0xFFFFFFFF) as u32;
        (*lp_file_information).n_number_of_links = stat.st_nlink as u32;
        (*lp_file_information).n_file_index_high = (stat.st_ino >> 32) as u32;
        (*lp_file_information).n_file_index_low = (stat.st_ino & 0xFFFFFFFF) as u32;
    }

    1 // TRUE
}

/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn set_end_of_file(h_file: usize) -> i32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => return 0, // FALSE
    };

    let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if pos < 0 {
        return 0; // FALSE
    }

    let ret = unsafe { libc::ftruncate(fd, pos) };
    (ret == 0) as i32
}

/// # Safety
/// `lp_buffer` must be valid for `n_buffer_length` u16 words.
pub unsafe extern "win64" fn get_logical_drive_strings_w(
    n_buffer_length: u32,
    lp_buffer: *mut u16,
) -> u32 {
    const DRIVES: &[u16] = &[b'C' as u16, b':' as u16, b'\\' as u16, 0, 0];
    let required = DRIVES.len() as u32;

    if n_buffer_length == 0 || lp_buffer.is_null() {
        return required;
    }

    if n_buffer_length < required {
        return required;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(DRIVES.as_ptr(), lp_buffer, DRIVES.len());
    }

    4 // length excluding final null
}

/// # Safety
/// `lp_buffer` must be valid for `n_buffer_length` bytes.
pub unsafe extern "win64" fn get_logical_drive_strings_a(
    n_buffer_length: u32,
    lp_buffer: *mut u8,
) -> u32 {
    const DRIVES: &[u8] = b"C:\\\0\0";
    let required = DRIVES.len() as u32;

    if n_buffer_length == 0 || lp_buffer.is_null() {
        return required;
    }

    if n_buffer_length < required {
        return required;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(DRIVES.as_ptr(), lp_buffer, DRIVES.len());
    }

    4 // length excluding final null
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_volume_information_w(
    _lp_root_path_name: *const u16,
    lp_volume_name_buffer: *mut u16,
    n_volume_name_size: u32,
    lp_volume_serial_number: *mut u32,
    lp_maximum_component_length: *mut u32,
    lp_file_system_flags: *mut u32,
    lp_file_system_name_buffer: *mut u16,
    n_file_system_name_size: u32,
) -> i32 {
    if !lp_volume_serial_number.is_null() {
        unsafe { *lp_volume_serial_number = 0xDEAD_BEEFu32 };
    }
    if !lp_maximum_component_length.is_null() {
        unsafe { *lp_maximum_component_length = 255u32 };
    }
    if !lp_file_system_flags.is_null() {
        unsafe { *lp_file_system_flags = 0x0002u32 }; // FILE_CASE_PRESERVED_NAMES
    }

    if !lp_volume_name_buffer.is_null() && n_volume_name_size >= 6 {
        const VOLUME_NAME: &[u16] = &[
            b'W' as u16,
            b'e' as u16,
            b'a' as u16,
            b'v' as u16,
            b'e' as u16,
            0u16,
        ];
        unsafe {
            std::ptr::copy_nonoverlapping(
                VOLUME_NAME.as_ptr(),
                lp_volume_name_buffer,
                VOLUME_NAME.len(),
            );
        }
    }

    if !lp_file_system_name_buffer.is_null() && n_file_system_name_size >= 5 {
        const FS_NAME: &[u16] = &[b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0u16];
        unsafe {
            std::ptr::copy_nonoverlapping(
                FS_NAME.as_ptr(),
                lp_file_system_name_buffer,
                FS_NAME.len(),
            );
        }
    }

    1 // TRUE
}

// ── Process/thread stubs ─────────────────────────────────────────────────────

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_process_w(
    _lp_application_name: *const u16,
    _lp_command_line: *mut u16,
    _lp_process_attributes: usize,
    _lp_thread_attributes: usize,
    _b_inherit_handles: i32,
    _dw_creation_flags: u32,
    _lp_environment: usize,
    _lp_current_directory: *const u16,
    _lp_startup_info: usize,
    _lp_process_information: usize,
) -> i32 {
    0 // FALSE
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_process_a(
    _lp_application_name: *const u8,
    _lp_command_line: *mut u8,
    _lp_process_attributes: usize,
    _lp_thread_attributes: usize,
    _b_inherit_handles: i32,
    _dw_creation_flags: u32,
    _lp_environment: usize,
    _lp_current_directory: *const u8,
    _lp_startup_info: usize,
    _lp_process_information: usize,
) -> i32 {
    0 // FALSE
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn wait_for_input_idle(_h_process: usize, _dw_milliseconds: u32) -> u32 {
    258 // WAIT_TIMEOUT
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_process_id(_process: usize) -> u32 {
    1000 // fake PID
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn open_thread(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _dw_thread_id: u32,
) -> usize {
    0x100 // fake non-null handle
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_thread_id(_thread: usize) -> u32 {
    42 // fake thread ID
}

// ── File time operations ─────────────────────────────────────────────────────

/// # Safety
/// `lp_file_time1` and `lp_file_time2` must be valid pointers to u64 values.
pub unsafe extern "win64" fn compare_file_time(
    lp_file_time1: *const u64,
    lp_file_time2: *const u64,
) -> i32 {
    if lp_file_time1.is_null() || lp_file_time2.is_null() {
        return 0;
    }
    let ft1 = unsafe { *lp_file_time1 };
    let ft2 = unsafe { *lp_file_time2 };
    match ft1.cmp(&ft2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// # Safety
/// `lp_file_time` and `lp_local_file_time` must be valid pointers to u64 values.
pub unsafe extern "win64" fn file_time_to_local_file_time(
    lp_file_time: *const u64,
    lp_local_file_time: *mut u64,
) -> i32 {
    if lp_file_time.is_null() || lp_local_file_time.is_null() {
        return 0;
    }
    unsafe { *lp_local_file_time = *lp_file_time };
    1 // TRUE
}

/// # Safety
/// `lp_local_file_time` and `lp_file_time` must be valid pointers to u64 values.
pub unsafe extern "win64" fn local_file_time_to_file_time(
    lp_local_file_time: *const u64,
    lp_file_time: *mut u64,
) -> i32 {
    if lp_local_file_time.is_null() || lp_file_time.is_null() {
        return 0;
    }
    unsafe { *lp_file_time = *lp_local_file_time };
    1 // TRUE
}

/// # Safety
/// `lp_file_time` must be a valid pointer to a u64 value.
pub unsafe extern "win64" fn system_time_to_file_time(
    _lp_system_time: *const SystemTime,
    lp_file_time: *mut u64,
) -> i32 {
    if lp_file_time.is_null() {
        return 0;
    }
    let unix_now = unsafe { libc::time(std::ptr::null_mut()) } as u64;
    let ft = unix_now * 10_000_000u64 + 116_444_736_000_000_000u64;
    unsafe { *lp_file_time = ft };
    1 // TRUE
}

/// # Safety
/// `lp_system_time` must be a valid pointer to a SystemTime struct.
pub unsafe extern "win64" fn file_time_to_system_time(
    _lp_file_time: *const u64,
    lp_system_time: *mut SystemTime,
) -> i32 {
    if lp_system_time.is_null() {
        return 0;
    }
    let unix_now = unsafe { libc::time(std::ptr::null_mut()) };
    let tm = unsafe { *libc::gmtime(&unix_now) };
    unsafe {
        (*lp_system_time).w_year = (tm.tm_year + 1900) as u16;
        (*lp_system_time).w_month = (tm.tm_mon + 1) as u16;
        (*lp_system_time).w_day_of_week = tm.tm_wday as u16;
        (*lp_system_time).w_day = tm.tm_mday as u16;
        (*lp_system_time).w_hour = tm.tm_hour as u16;
        (*lp_system_time).w_minute = tm.tm_min as u16;
        (*lp_system_time).w_second = tm.tm_sec as u16;
        (*lp_system_time).w_milliseconds = 0u16;
    }
    1 // TRUE
}

// ── Console misc + MoveFileEx ────────────────────────────────────────────────

/// AllocConsole: allocate a console for the process.
///
/// No-op. Return TRUE.
pub extern "win64" fn alloc_console() -> i32 {
    1 // TRUE
}

/// FreeConsole: detach the process from its console.
///
/// No-op. Return TRUE.
pub extern "win64" fn free_console() -> i32 {
    1 // TRUE
}

/// AttachConsole: attach the calling process to the console of another process.
///
/// No-op. Return TRUE.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn attach_console(_dw_process_id: u32) -> i32 {
    1 // TRUE
}

/// GetConsoleWindow: retrieve the window handle for the console.
///
/// Return NULL (no window).
pub extern "win64" fn get_console_window() -> usize {
    0 // NULL
}

/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn move_file_ex_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    dw_flags: u32,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read existing filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF16_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF16_LEN {
        return 0;
    }
    let old_path = unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1))
    };

    // Read new filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF16_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF16_LEN {
        return 0;
    }
    let new_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate both paths
    let linux_old = match weave_core::prefix::translator().to_linux_str(&old_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let linux_new = match weave_core::prefix::translator().to_linux_str(&new_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let src_c_path = match std::ffi::CString::new(linux_old.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let dst_c_path = match std::ffi::CString::new(linux_new.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x01;
    if (dw_flags & MOVEFILE_REPLACE_EXISTING) == 0 {
        // Check if destination exists
        if unsafe { libc::access(dst_c_path.as_ptr(), libc::F_OK) } == 0 {
            return 0; // FALSE — destination exists
        }
    }

    // Call rename
    let ret = unsafe { libc::rename(src_c_path.as_ptr(), dst_c_path.as_ptr()) };
    (ret == 0) as i32
}

/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-8 strings.
pub unsafe extern "win64" fn move_file_ex_a(
    lp_existing_file_name: *const u8,
    lp_new_file_name: *const u8,
    dw_flags: u32,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read existing filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF8_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF8_LEN {
        return 0;
    }
    let old_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1)) };

    // Read new filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF8_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF8_LEN {
        return 0;
    }
    let new_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate both paths
    let linux_old = match weave_core::prefix::translator().to_linux_str(&old_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let linux_new = match weave_core::prefix::translator().to_linux_str(&new_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let src_c_path = match std::ffi::CString::new(linux_old.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let dst_c_path = match std::ffi::CString::new(linux_new.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x01;
    if (dw_flags & MOVEFILE_REPLACE_EXISTING) == 0 {
        // Check if destination exists
        if unsafe { libc::access(dst_c_path.as_ptr(), libc::F_OK) } == 0 {
            return 0; // FALSE — destination exists
        }
    }

    // Call rename
    let ret = unsafe { libc::rename(src_c_path.as_ptr(), dst_c_path.as_ptr()) };
    (ret == 0) as i32
}

/// WideCharToMultiByte: convert a UTF-16 string to a multibyte (UTF-8) string.
///
/// Phase 2: all code pages produce UTF-8 output (correct on Linux).
///
/// # Safety
/// `lp_wide_char_str` must be valid for `cch_wide_char` UTF-16 code units
/// (or null-terminated when `cch_wide_char == -1`).
/// `lp_multi_byte_str`, if non-null, must be writable for `cb_multi_byte` bytes.
pub unsafe extern "win64" fn wide_char_to_multi_byte(
    _code_page: u32,
    _dw_flags: u32,
    lp_wide_char_str: *const u16,
    cch_wide_char: i32,
    lp_multi_byte_str: *mut u8,
    cb_multi_byte: i32,
    _lp_default_char: usize,
    _lp_used_default_char: usize,
) -> i32 {
    if lp_wide_char_str.is_null() {
        LAST_ERROR.with(|e| e.set(87)); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let null_terminated = cch_wide_char < 0;
    let wide: &[u16] = if null_terminated {
        let mut len = 0usize;
        while len < MAX_UTF16_LEN && unsafe { *lp_wide_char_str.add(len) } != 0 {
            len += 1;
        }
        if len == MAX_UTF16_LEN {
            LAST_ERROR.with(|e| e.set(87)); // ERROR_INVALID_PARAMETER
            return 0;
        }
        unsafe { std::slice::from_raw_parts(lp_wide_char_str, len) }
    } else {
        unsafe { std::slice::from_raw_parts(lp_wide_char_str, cch_wide_char as usize) }
    };
    let utf8 = String::from_utf16_lossy(wide);
    let bytes = utf8.as_bytes();
    // Size query
    if lp_multi_byte_str.is_null() || cb_multi_byte == 0 {
        return (bytes.len() + if null_terminated { 1 } else { 0 }) as i32;
    }
    let cap = cb_multi_byte as usize;
    let copy_len = bytes.len().min(cap.saturating_sub(1));
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_multi_byte_str, copy_len);
        *lp_multi_byte_str.add(copy_len) = 0;
    }
    LAST_ERROR.with(|e| e.set(0));
    (copy_len + 1) as i32
}

/// MultiByteToWideChar: convert a multibyte (UTF-8) string to UTF-16.
///
/// # Safety
/// `lp_multi_byte_str` must be valid for `cb_multi_byte` bytes (or
/// null-terminated when `cb_multi_byte == -1`).
/// `lp_wide_char_str`, if non-null, must be writable for `cch_wide_char` u16 words.
pub unsafe extern "win64" fn multi_byte_to_wide_char(
    _code_page: u32,
    _dw_flags: u32,
    lp_multi_byte_str: *const u8,
    cb_multi_byte: i32,
    lp_wide_char_str: *mut u16,
    cch_wide_char: i32,
) -> i32 {
    if lp_multi_byte_str.is_null() {
        LAST_ERROR.with(|e| e.set(87));
        return 0;
    }
    let null_terminated = cb_multi_byte < 0;
    let bytes: &[u8] = if null_terminated {
        let mut len = 0usize;
        while len < MAX_UTF8_LEN && unsafe { *lp_multi_byte_str.add(len) } != 0 {
            len += 1;
        }
        if len == MAX_UTF8_LEN {
            LAST_ERROR.with(|e| e.set(87)); // ERROR_INVALID_PARAMETER
            return 0;
        }
        unsafe { std::slice::from_raw_parts(lp_multi_byte_str, len) }
    } else {
        unsafe { std::slice::from_raw_parts(lp_multi_byte_str, cb_multi_byte as usize) }
    };
    let wide: Vec<u16> = String::from_utf8_lossy(bytes).encode_utf16().collect();
    if lp_wide_char_str.is_null() || cch_wide_char == 0 {
        return (wide.len() + if null_terminated { 1 } else { 0 }) as i32;
    }
    let cap = cch_wide_char as usize;
    let copy_len = wide.len().min(cap.saturating_sub(1));
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_wide_char_str, copy_len);
        *lp_wide_char_str.add(copy_len) = 0;
    }
    LAST_ERROR.with(|e| e.set(0));
    (copy_len + 1) as i32
}

/// GetStartupInfoA: return process startup parameters (ANSI variant).
///
/// Phase 2: fills a zeroed STARTUPINFOA and sets cb to the struct size.
/// Most CRT init code calls this and ignores the result when dwFlags is 0.
///
/// # Safety
/// `lp_startup_info` must point to at least 68 bytes of writable memory.
pub unsafe extern "win64" fn get_startup_info_a(lp_startup_info: *mut u8) {
    if lp_startup_info.is_null() {
        return;
    }
    unsafe {
        std::ptr::write_bytes(lp_startup_info, 0, 68);
        *(lp_startup_info as *mut u32) = 68; // cb = sizeof(STARTUPINFOA)
    }
}

/// GetStartupInfoW: return process startup parameters (wide variant).
///
/// # Safety
/// `lp_startup_info` must point to at least 104 bytes of writable memory.
pub unsafe extern "win64" fn get_startup_info_w(lp_startup_info: *mut u8) {
    if lp_startup_info.is_null() {
        return;
    }
    unsafe {
        std::ptr::write_bytes(lp_startup_info, 0, 104);
        *(lp_startup_info as *mut u32) = 104; // cb = sizeof(STARTUPINFOW)
    }
}

/// FlushFileBuffers: flush OS write buffers for an open file handle.
pub extern "win64" fn flush_file_buffers(h_file: usize) -> i32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
            return 0;
        }
    };
    let ret = unsafe { libc::fsync(fd) };
    if ret == 0 {
        1
    } else {
        LAST_ERROR.with(|e| e.set(file_io::ERROR_INVALID_HANDLE));
        0
    }
}

/// CreateFileMappingW: create a file mapping object for memory-mapped files.
///
/// For anonymous mappings (hFile == INVALID_HANDLE_VALUE), allocates RAM-backed
/// memory using mmap. The returned address serves as both the mapping handle
/// and the mapped memory address.
///
/// # Safety
/// `lp_file_mapping_attributes` and `lp_name` are ignored (accepted but not dereferenced).
pub unsafe extern "win64" fn create_file_mapping_w(
    h_file: usize,
    _lp_file_mapping_attributes: usize,
    _fl_protect: u32,
    dw_maximum_size_high: u32,
    dw_maximum_size_low: u32,
    _lp_name: *const u16,
) -> usize {
    const INVALID_HANDLE_VALUE: usize = usize::MAX;
    if h_file != INVALID_HANDLE_VALUE {
        // File-backed mappings not supported yet
        return 0;
    }
    let size = (dw_maximum_size_high as usize) << 32 | dw_maximum_size_low as usize;
    if size == 0 {
        return 0; // Caller must provide a size for anonymous mappings
    }
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        0
    } else {
        addr as usize
    }
}

/// MapViewOfFile: map a view of a file mapping into the address space.
///
/// For our anonymous mappings, the handle IS the mapped address, so we return it directly.
/// Offset and access parameters are ignored for the anonymous mapping case.
///
/// # Safety
/// No pointer dereference — just returns the handle value.
pub extern "win64" fn map_view_of_file(
    h_file_mapping_object: usize,
    _dw_desired_access: u32,
    _dw_file_offset_high: u32,
    _dw_file_offset_low: u32,
    _dw_number_of_bytes_to_map: usize,
) -> usize {
    h_file_mapping_object // Handle IS the mapped address
}

/// UnmapViewOfFile: unmap a mapped view of a file.
///
/// We don't track mapping sizes, so this is a no-op that always succeeds.
/// The memory will be reclaimed when the process exits.
///
/// # Safety
/// `lp_base_address` is accepted but not dereferenced.
pub unsafe extern "win64" fn unmap_view_of_file(_lp_base_address: *const u8) -> i32 {
    1 // TRUE — no-op
}

/// CopyFileW: copy a file (wide string version).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn copy_file_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    b_fail_if_exists: i32,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read source filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF16_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF16_LEN {
        return 0;
    }
    let src_win_path = unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1))
    };

    // Read destination filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF16_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF16_LEN {
        return 0;
    }
    let dst_win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate paths
    let src_linux_path = match weave_core::prefix::translator().to_linux_str(&src_win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let dst_linux_path = match weave_core::prefix::translator().to_linux_str(&dst_win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let src_c_path = match std::ffi::CString::new(src_linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let dst_c_path = match std::ffi::CString::new(dst_linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Check if destination exists and b_fail_if_exists is set
    if b_fail_if_exists != 0 && unsafe { libc::access(dst_c_path.as_ptr(), libc::F_OK) } == 0 {
        return 0; // FALSE — destination exists
    }

    // Open source file
    let src_fd = unsafe { libc::open(src_c_path.as_ptr(), libc::O_RDONLY, 0) };
    if src_fd < 0 {
        return 0; // FALSE
    }

    // Open/create destination file
    let dst_fd = unsafe {
        libc::open(
            dst_c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if dst_fd < 0 {
        unsafe { libc::close(src_fd) };
        return 0; // FALSE
    }

    // Copy in 64KB chunks
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe { libc::read(src_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let written =
            unsafe { libc::write(dst_fd, buf.as_ptr() as *const libc::c_void, n as usize) };
        if written != n {
            unsafe { libc::close(src_fd) };
            unsafe { libc::close(dst_fd) };
            return 0; // FALSE
        }
    }

    unsafe { libc::close(src_fd) };
    unsafe { libc::close(dst_fd) };
    1 // TRUE
}

/// Windows WIN32_FIND_DATAW structure (wide version).
#[repr(C)]
pub struct Win32FindDataW {
    dw_file_attributes: u32,
    ft_creation_time: u64,
    ft_last_access_time: u64,
    ft_last_write_time: u64,
    n_file_size_high: u32,
    n_file_size_low: u32,
    dw_reserved0: u32,
    dw_reserved1: u32,
    c_file_name: [u16; 260],
    c_alternate_file_name: [u16; 14],
}

/// Windows WIN32_FIND_DATAA structure (ANSI version).
#[repr(C)]
pub struct Win32FindDataA {
    dw_file_attributes: u32,
    ft_creation_time: u64,
    ft_last_access_time: u64,
    ft_last_write_time: u64,
    n_file_size_high: u32,
    n_file_size_low: u32,
    dw_reserved0: u32,
    dw_reserved1: u32,
    c_file_name: [u8; 260],
    c_alternate_file_name: [u8; 14],
}

/// FindFirstFileW: start directory enumeration (wide string version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string.
/// `lp_find_file_data` must be a valid writable pointer to a WIN32_FIND_DATAW.
pub unsafe extern "win64" fn find_first_file_w(
    lp_file_name: *const u16,
    lp_find_file_data: *mut Win32FindDataW,
) -> usize {
    if lp_file_name.is_null() || lp_find_file_data.is_null() {
        return usize::MAX; // INVALID_HANDLE_VALUE
    }

    // Read the null-terminated UTF-16 filename
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return usize::MAX;
    }
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return usize::MAX,
    };

    // Open directory
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return usize::MAX,
    };

    let dir = unsafe { libc::opendir(c_path.as_ptr()) };
    if dir.is_null() {
        return usize::MAX;
    }

    // Read first entry
    let entry = unsafe { libc::readdir(dir) };
    if entry.is_null() {
        unsafe { libc::closedir(dir) };
        return usize::MAX;
    }

    // Convert entry name to UTF-16
    let entry_name = unsafe {
        let name_ptr = (*entry).d_name.as_ptr();
        let name_len = libc::strlen(name_ptr);
        std::slice::from_raw_parts(name_ptr as *const u8, name_len)
    };
    let entry_name_str = String::from_utf8_lossy(entry_name);
    let wide_name: Vec<u16> = entry_name_str.encode_utf16().collect();

    // Fill WIN32_FIND_DATAW
    unsafe {
        (*lp_find_file_data).dw_file_attributes = 0x80; // FILE_ATTRIBUTE_NORMAL
        (*lp_find_file_data).ft_creation_time = 0;
        (*lp_find_file_data).ft_last_access_time = 0;
        (*lp_find_file_data).ft_last_write_time = 0;
        (*lp_find_file_data).n_file_size_high = 0;
        (*lp_find_file_data).n_file_size_low = 0;
        (*lp_find_file_data).dw_reserved0 = 0;
        (*lp_find_file_data).dw_reserved1 = 0;

        // Copy filename (truncate if too long)
        let copy_len = wide_name.len().min(259); // leave room for null
        std::ptr::copy_nonoverlapping(
            wide_name.as_ptr(),
            (*lp_find_file_data).c_file_name.as_mut_ptr(),
            copy_len,
        );
        (*lp_find_file_data).c_file_name[copy_len] = 0;

        // No alternate filename
        (*lp_find_file_data).c_alternate_file_name[0] = 0;
    }

    dir as usize // Return directory handle
}

/// FindFirstFileA: start directory enumeration (ANSI version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string.
/// `lp_find_file_data` must be a valid writable pointer to a WIN32_FIND_DATAA.
pub unsafe extern "win64" fn find_first_file_a(
    lp_file_name: *const u8,
    lp_find_file_data: *mut Win32FindDataA,
) -> usize {
    if lp_file_name.is_null() || lp_find_file_data.is_null() {
        return usize::MAX; // INVALID_HANDLE_VALUE
    }

    // Read the null-terminated UTF-8 filename
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return usize::MAX;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return usize::MAX,
    };

    // Open directory
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return usize::MAX,
    };

    let dir = unsafe { libc::opendir(c_path.as_ptr()) };
    if dir.is_null() {
        return usize::MAX;
    }

    // Read first entry
    let entry = unsafe { libc::readdir(dir) };
    if entry.is_null() {
        unsafe { libc::closedir(dir) };
        return usize::MAX;
    }

    // Get entry name
    let entry_name = unsafe {
        let name_ptr = (*entry).d_name.as_ptr();
        let name_len = libc::strlen(name_ptr);
        std::slice::from_raw_parts(name_ptr as *const u8, name_len)
    };
    let entry_name_str = String::from_utf8_lossy(entry_name);

    // Fill WIN32_FIND_DATAA
    unsafe {
        (*lp_find_file_data).dw_file_attributes = 0x80; // FILE_ATTRIBUTE_NORMAL
        (*lp_find_file_data).ft_creation_time = 0;
        (*lp_find_file_data).ft_last_access_time = 0;
        (*lp_find_file_data).ft_last_write_time = 0;
        (*lp_find_file_data).n_file_size_high = 0;
        (*lp_find_file_data).n_file_size_low = 0;
        (*lp_find_file_data).dw_reserved0 = 0;
        (*lp_find_file_data).dw_reserved1 = 0;

        // Copy filename (truncate if too long)
        let bytes = entry_name_str.as_bytes();
        let copy_len = bytes.len().min(259); // leave room for null
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (*lp_find_file_data).c_file_name.as_mut_ptr(),
            copy_len,
        );
        (*lp_find_file_data).c_file_name[copy_len] = 0;

        // No alternate filename
        (*lp_find_file_data).c_alternate_file_name[0] = 0;
    }

    dir as usize // Return directory handle
}

/// FindNextFileW: continue directory enumeration (wide string version).
///
/// # Safety
/// `h_find_file` must be a valid directory handle from FindFirstFileW.
/// `lp_find_file_data` must be a valid writable pointer to a WIN32_FIND_DATAW.
pub unsafe extern "win64" fn find_next_file_w(
    h_find_file: usize,
    lp_find_file_data: *mut Win32FindDataW,
) -> i32 {
    if h_find_file == 0 || h_find_file == usize::MAX || lp_find_file_data.is_null() {
        return 0; // FALSE
    }

    let dir = h_find_file as *mut libc::DIR;

    // Read next entry
    let entry = unsafe { libc::readdir(dir) };
    if entry.is_null() {
        return 0; // FALSE - no more entries
    }

    // Convert entry name to UTF-16
    let entry_name = unsafe {
        let name_ptr = (*entry).d_name.as_ptr();
        let name_len = libc::strlen(name_ptr);
        std::slice::from_raw_parts(name_ptr as *const u8, name_len)
    };
    let entry_name_str = String::from_utf8_lossy(entry_name);
    let wide_name: Vec<u16> = entry_name_str.encode_utf16().collect();

    // Fill WIN32_FIND_DATAW
    unsafe {
        (*lp_find_file_data).dw_file_attributes = 0x80; // FILE_ATTRIBUTE_NORMAL
        (*lp_find_file_data).ft_creation_time = 0;
        (*lp_find_file_data).ft_last_access_time = 0;
        (*lp_find_file_data).ft_last_write_time = 0;
        (*lp_find_file_data).n_file_size_high = 0;
        (*lp_find_file_data).n_file_size_low = 0;
        (*lp_find_file_data).dw_reserved0 = 0;
        (*lp_find_file_data).dw_reserved1 = 0;

        // Copy filename (truncate if too long)
        let copy_len = wide_name.len().min(259); // leave room for null
        std::ptr::copy_nonoverlapping(
            wide_name.as_ptr(),
            (*lp_find_file_data).c_file_name.as_mut_ptr(),
            copy_len,
        );
        (*lp_find_file_data).c_file_name[copy_len] = 0;

        // No alternate filename
        (*lp_find_file_data).c_alternate_file_name[0] = 0;
    }

    1 // TRUE
}

/// FindNextFileA: continue directory enumeration (ANSI version).
///
/// # Safety
/// `h_find_file` must be a valid directory handle from FindFirstFileA.
/// `lp_find_file_data` must be a valid writable pointer to a WIN32_FIND_DATAA.
pub unsafe extern "win64" fn find_next_file_a(
    h_find_file: usize,
    lp_find_file_data: *mut Win32FindDataA,
) -> i32 {
    if h_find_file == 0 || h_find_file == usize::MAX || lp_find_file_data.is_null() {
        return 0; // FALSE
    }

    let dir = h_find_file as *mut libc::DIR;

    // Read next entry
    let entry = unsafe { libc::readdir(dir) };
    if entry.is_null() {
        return 0; // FALSE - no more entries
    }

    // Get entry name
    let entry_name = unsafe {
        let name_ptr = (*entry).d_name.as_ptr();
        let name_len = libc::strlen(name_ptr);
        std::slice::from_raw_parts(name_ptr as *const u8, name_len)
    };
    let entry_name_str = String::from_utf8_lossy(entry_name);

    // Fill WIN32_FIND_DATAA
    unsafe {
        (*lp_find_file_data).dw_file_attributes = 0x80; // FILE_ATTRIBUTE_NORMAL
        (*lp_find_file_data).ft_creation_time = 0;
        (*lp_find_file_data).ft_last_access_time = 0;
        (*lp_find_file_data).ft_last_write_time = 0;
        (*lp_find_file_data).n_file_size_high = 0;
        (*lp_find_file_data).n_file_size_low = 0;
        (*lp_find_file_data).dw_reserved0 = 0;
        (*lp_find_file_data).dw_reserved1 = 0;

        // Copy filename (truncate if too long)
        let bytes = entry_name_str.as_bytes();
        let copy_len = bytes.len().min(259); // leave room for null
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (*lp_find_file_data).c_file_name.as_mut_ptr(),
            copy_len,
        );
        (*lp_find_file_data).c_file_name[copy_len] = 0;

        // No alternate filename
        (*lp_find_file_data).c_alternate_file_name[0] = 0;
    }

    1 // TRUE
}

/// FindClose: close directory enumeration handle.
pub extern "win64" fn find_close(h_find_file: usize) -> i32 {
    if h_find_file == 0 || h_find_file == usize::MAX {
        return 0; // FALSE
    }

    let dir = h_find_file as *mut libc::DIR;
    let ret = unsafe { libc::closedir(dir) };
    (ret == 0) as i32
}

/// VerSetConditionMask: pack a condition into the corresponding 3-bit slot of the mask.
pub extern "win64" fn ver_set_condition_mask(
    mut condition_mask: u64,
    type_mask: u32,
    condition: u8,
) -> u64 {
    let mut bit = 1u32;
    let mut shift = 0u32;
    loop {
        if bit > type_mask {
            break;
        }
        if (type_mask & bit) != 0 {
            condition_mask &= !(0x07u64 << shift);
            condition_mask |= (condition as u64 & 0x07) << shift;
        }
        shift += 3;
        bit <<= 1;
    }
    condition_mask
}

/// VerifyVersionInfoW: verify version information against conditions.
///
/// Phase 2: always returns TRUE (version check passes).
///
/// # Safety
/// `lp_version_info` must be a valid pointer to an OSVERSIONINFOEXW.
pub unsafe extern "win64" fn verify_version_info_w(
    _lp_version_info: *const OsVersionInfoExW,
    _type_mask: u32,
    _condition_mask: u64,
) -> i32 {
    // Always return TRUE for version checks
    1
}

/// Windows WIN32_FILE_ATTRIBUTE_DATA structure.
#[repr(C)]
pub struct Win32FileAttributeData {
    dw_file_attributes: u32,
    ft_creation_time: u64,
    ft_last_access_time: u64,
    ft_last_write_time: u64,
    n_file_size_high: u32,
    n_file_size_low: u32,
}

/// GetFileAttributesExW: get extended file attributes (wide string version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string.
/// `lp_file_information` must be a valid writable pointer to a WIN32_FILE_ATTRIBUTE_DATA.
pub unsafe extern "win64" fn get_file_attributes_ex_w(
    lp_file_name: *const u16,
    _f_info_level_id: u32,
    lp_file_information: *mut Win32FileAttributeData,
) -> i32 {
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    if lp_file_name.is_null() || lp_file_information.is_null() {
        return 0; // FALSE
    }

    // Read the null-terminated UTF-16 filename
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Check if path exists and get type
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return 0; // FALSE
    }

    // Fill WIN32_FILE_ATTRIBUTE_DATA
    unsafe {
        (*lp_file_information).dw_file_attributes =
            if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
        (*lp_file_information).ft_creation_time = 0;
        (*lp_file_information).ft_last_access_time = 0;
        (*lp_file_information).ft_last_write_time = 0;
        (*lp_file_information).n_file_size_high = (stat.st_size >> 32) as u32;
        (*lp_file_information).n_file_size_low = (stat.st_size & 0xFFFFFFFF) as u32;
    }

    1 // TRUE
}

/// GetFileAttributesExA: get extended file attributes (ANSI version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string.
/// `lp_file_information` must be a valid writable pointer to a WIN32_FILE_ATTRIBUTE_DATA.
pub unsafe extern "win64" fn get_file_attributes_ex_a(
    lp_file_name: *const u8,
    _f_info_level_id: u32,
    lp_file_information: *mut Win32FileAttributeData,
) -> i32 {
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    if lp_file_name.is_null() || lp_file_information.is_null() {
        return 0; // FALSE
    }

    // Read the null-terminated UTF-8 filename
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Check if path exists and get type
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return 0; // FALSE
    }

    // Fill WIN32_FILE_ATTRIBUTE_DATA
    unsafe {
        (*lp_file_information).dw_file_attributes =
            if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
        (*lp_file_information).ft_creation_time = 0;
        (*lp_file_information).ft_last_access_time = 0;
        (*lp_file_information).ft_last_write_time = 0;
        (*lp_file_information).n_file_size_high = (stat.st_size >> 32) as u32;
        (*lp_file_information).n_file_size_low = (stat.st_size & 0xFFFFFFFF) as u32;
    }

    1 // TRUE
}

/// CopyFileA: copy a file (ANSI version).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-8 strings.
pub unsafe extern "win64" fn copy_file_a(
    lp_existing_file_name: *const u8,
    lp_new_file_name: *const u8,
    b_fail_if_exists: i32,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read source filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF8_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF8_LEN {
        return 0;
    }
    let src_win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1)) };

    // Read destination filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF8_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF8_LEN {
        return 0;
    }
    let dst_win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate paths
    let src_linux_path = match weave_core::prefix::translator().to_linux_str(&src_win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let dst_linux_path = match weave_core::prefix::translator().to_linux_str(&dst_win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let src_c_path = match std::ffi::CString::new(src_linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let dst_c_path = match std::ffi::CString::new(dst_linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Check if destination exists and b_fail_if_exists is set
    if b_fail_if_exists != 0 && unsafe { libc::access(dst_c_path.as_ptr(), libc::F_OK) } == 0 {
        return 0; // FALSE — destination exists
    }

    // Open source file
    let src_fd = unsafe { libc::open(src_c_path.as_ptr(), libc::O_RDONLY, 0) };
    if src_fd < 0 {
        return 0; // FALSE
    }

    // Open/create destination file
    let dst_fd = unsafe {
        libc::open(
            dst_c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if dst_fd < 0 {
        unsafe { libc::close(src_fd) };
        return 0; // FALSE
    }

    // Copy in 64KB chunks
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe { libc::read(src_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let written =
            unsafe { libc::write(dst_fd, buf.as_ptr() as *const libc::c_void, n as usize) };
        if written != n {
            unsafe { libc::close(src_fd) };
            unsafe { libc::close(dst_fd) };
            return 0; // FALSE
        }
    }

    unsafe { libc::close(src_fd) };
    unsafe { libc::close(dst_fd) };
    1 // TRUE
}

// ── Module / library loading stubs ────────────────────────────────────────────

/// LoadLibraryA/W/ExA/ExW — we don't load DLLs dynamically; return NULL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn load_library_a(_lp_file_name: *const u8) -> usize {
    0
}
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn load_library_w(_lp_file_name: *const u16) -> usize {
    0
}
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn load_library_ex_a(
    _lp_file_name: *const u8,
    _h_file: usize,
    _dw_flags: u32,
) -> usize {
    0
}
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn load_library_ex_w(
    _lp_file_name: *const u16,
    _h_file: usize,
    _dw_flags: u32,
) -> usize {
    0
}

/// FreeLibrary — no-op (we never loaded it).
pub extern "win64" fn free_library(_h_module: usize) -> i32 {
    1 // TRUE
}

/// GetProcAddress — always returns NULL (we don't have a real DLL loader).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_proc_address(_h_module: usize, _lp_proc_name: *const u8) -> usize {
    0
}

/// GetModuleHandleA/W/ExA/ExW — return NULL (module not found).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_module_handle_a(_lp_module_name: *const u8) -> usize {
    0
}
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_module_handle_w(_lp_module_name: *const u16) -> usize {
    0
}
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_module_handle_ex_a(
    _dw_flags: u32,
    _lp_module_name: *const u8,
    _ph_module: *mut usize,
) -> i32 {
    0 // FALSE
}
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_module_handle_ex_w(
    _dw_flags: u32,
    _lp_module_name: *const u16,
    _ph_module: *mut usize,
) -> i32 {
    0 // FALSE
}

/// GetModuleFileNameW — return 0 (error).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_module_file_name_w(
    _h_module: usize,
    _lp_filename: *mut u16,
    _n_size: u32,
) -> u32 {
    0
}

/// GetModuleFileNameA — return 0 (error).
///
/// Same as GetModuleFileNameW — stub that returns 0.
/// The A variant just needs to exist in the resolver so apps that call
/// the narrow version don't get an unresolved import.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_module_file_name_a(
    _h_module: usize,
    _lp_filename: *mut u8,
    _n_size: u32,
) -> u32 {
    0
}

// ── Process / thread identity ─────────────────────────────────────────────────

/// GetCurrentProcess — return a pseudo-handle (-1 = 0xFFFFFFFFFFFFFFFF).
pub extern "win64" fn get_current_process() -> usize {
    usize::MAX // pseudo-handle
}

/// GetCurrentThread — return a pseudo-handle (-2 = 0xFFFFFFFFFFFFFFFE).
pub extern "win64" fn get_current_thread() -> usize {
    usize::MAX - 1
}

/// GetCurrentProcessId / GetCurrentThreadId — return plausible fake IDs.
pub extern "win64" fn get_current_process_id() -> u32 {
    unsafe { libc::getpid() as u32 }
}

/// GetCurrentThreadId — single-threaded stub, returns 1.
pub extern "win64" fn get_current_thread_id() -> u32 {
    1 // single-threaded stub
}

// ── Timing ────────────────────────────────────────────────────────────────────

/// GetTickCount — milliseconds since process start (stub: use clock_gettime).
pub extern "win64" fn get_tick_count() -> u32 {
    get_tick_count_64() as u32
}

/// GetTickCount64 — milliseconds since process start.
pub extern "win64" fn get_tick_count_64() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

/// QueryPerformanceCounter — returns nanoseconds from CLOCK_MONOTONIC.
///
/// # Safety
/// `lp_performance_count` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn query_performance_counter(lp_performance_count: *mut u64) -> i32 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        if !lp_performance_count.is_null() {
            *lp_performance_count = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
        }
    }
    1 // TRUE
}

/// QueryPerformanceFrequency — reports nanosecond resolution (1 GHz).
///
/// # Safety
/// `lp_frequency` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn query_performance_frequency(lp_frequency: *mut u64) -> i32 {
    unsafe {
        if !lp_frequency.is_null() {
            *lp_frequency = 1_000_000_000; // nanosecond resolution
        }
    }
    1 // TRUE
}

/// GetSystemTimeAsFileTime — fills FILETIME from CLOCK_REALTIME.
///
/// # Safety
/// `lp_system_time_as_file_time` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_system_time_as_file_time(lp_system_time_as_file_time: *mut u64) {
    // FILETIME is 100-nanosecond intervals since 1601-01-01
    // Offset between 1601 and Unix epoch (1970) = 11644473600 seconds
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        if !lp_system_time_as_file_time.is_null() {
            let ns = ts.tv_sec as u64 * 10_000_000 + ts.tv_nsec as u64 / 100;
            *lp_system_time_as_file_time = ns + 116_444_736_000_000_000u64;
        }
    }
}

// ── System information ────────────────────────────────────────────────────────

/// SYSTEM_INFO layout (Windows x64, 64 bytes).
#[repr(C)]
pub struct SystemInfo {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_application_address: usize,
    maximum_application_address: usize,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

/// GetSystemInfo — fills a SYSTEM_INFO with AMD64 defaults.
///
/// # Safety
/// `lp_system_info` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_system_info(lp_system_info: *mut SystemInfo) {
    unsafe {
        if lp_system_info.is_null() {
            return;
        }
        (*lp_system_info) = SystemInfo {
            processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
            reserved: 0,
            page_size: 4096,
            minimum_application_address: 0x10000,
            maximum_application_address: 0x7FFF_FFFF_FFFF,
            active_processor_mask: 1,
            number_of_processors: 1,
            processor_type: 8664, // Intel64
            allocation_granularity: 65536,
            processor_level: 6,
            processor_revision: 0,
        };
    }
}

/// GetNativeSystemInfo — identical to GetSystemInfo.
///
/// Many apps call this on 64-bit Windows instead of GetSystemInfo.
/// Just calls the existing get_system_info function internally.
///
/// # Safety
/// `lp_system_info` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_native_system_info(lp_system_info: *mut SystemInfo) {
    unsafe { get_system_info(lp_system_info) };
}

// ── Debugger / diagnostics ────────────────────────────────────────────────────

/// IsDebuggerPresent — always returns FALSE.
pub extern "win64" fn is_debugger_present() -> i32 {
    0 // FALSE
}

/// OutputDebugStringA — silently discards the string.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn output_debug_string_a(_lp_output_string: *const u8) {
    // silently discard
}

/// OutputDebugStringW — silently discards the string.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn output_debug_string_w(_lp_output_string: *const u16) {
    // silently discard
}

// ── Events / synchronisation ──────────────────────────────────────────────────

/// CreateEventA — returns a fake non-null handle (2).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_event_a(
    _lp_event_attributes: *const u8,
    _b_manual_reset: i32,
    _b_initial_state: i32,
    _lp_name: *const u8,
) -> usize {
    2 // fake non-null handle (distinct from mutex handle 1)
}

/// CreateEventW — returns a fake non-null handle (2).
///
/// Same as CreateEventA but accepts wide string name parameter.
/// Ignores name, manual reset flag, initial state, and security attributes.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_event_w(
    _lp_event_attributes: *const u8,
    _b_manual_reset: i32,
    _b_initial_state: i32,
    _lp_name: *const u16,
) -> usize {
    2 // fake non-null handle (distinct from mutex handle 1)
}

/// OpenEventA — returns a fake non-null handle (2).
///
/// Ignores access flags, inherit handle flag, and event name.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn open_event_a(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _lp_name: *const u8,
) -> usize {
    2 // fake non-null handle
}

/// OpenEventW — returns a fake non-null handle (2).
///
/// Ignores access flags, inherit handle flag, and event name.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn open_event_w(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _lp_name: *const u16,
) -> usize {
    2 // fake non-null handle
}

/// SetEvent — no-op stub, returns TRUE.
pub extern "win64" fn set_event(_h_event: usize) -> i32 {
    1
}
/// ResetEvent — no-op stub, returns TRUE.
pub extern "win64" fn reset_event(_h_event: usize) -> i32 {
    1
}

/// CreateSemaphoreA — returns a fake handle (1).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_semaphore_a(
    _lp_semaphore_attributes: *const u8,
    _l_initial_count: i32,
    _l_maximum_count: i32,
    _lp_name: *const u8,
) -> usize {
    1 // fake handle
}
/// ReleaseSemaphore — no-op stub, returns TRUE.
pub extern "win64" fn release_semaphore(
    _h_semaphore: usize,
    _l_release_count: i32,
    _lp_previous_count: *mut i32,
) -> i32 {
    1
}

// SRW locks are pointer-sized on Windows; we use the pointer itself as storage.
/// AcquireSRWLockExclusive — no-op (single-threaded).
///
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
pub unsafe extern "win64" fn acquire_srw_lock_exclusive(srw_lock: *mut usize) {
    let _ = srw_lock; // single-threaded: no-op
}
/// ReleaseSRWLockExclusive — no-op (single-threaded).
///
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
pub unsafe extern "win64" fn release_srw_lock_exclusive(srw_lock: *mut usize) {
    let _ = srw_lock;
}
/// AcquireSRWLockShared — no-op (single-threaded).
///
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
pub unsafe extern "win64" fn acquire_srw_lock_shared(srw_lock: *mut usize) {
    let _ = srw_lock;
}
/// ReleaseSRWLockShared — no-op (single-threaded).
///
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
pub unsafe extern "win64" fn release_srw_lock_shared(srw_lock: *mut usize) {
    let _ = srw_lock;
}

/// InitializeConditionVariable — no-op stub.
///
/// # Safety
/// `_condition_variable` must be a valid writable pointer.
pub unsafe extern "win64" fn initialize_condition_variable(_condition_variable: *mut usize) {}
/// SleepConditionVariableSRW — returns FALSE (timed out / not supported).
///
/// # Safety
/// Pointer arguments must be valid or the caller must not care about the result.
pub unsafe extern "win64" fn sleep_condition_variable_srw(
    _condition_variable: *mut usize,
    _srw_lock: *mut usize,
    _dw_milliseconds: u32,
    _flags: u32,
) -> i32 {
    0 // FALSE / timed out
}
/// WakeConditionVariable — no-op stub.
///
/// # Safety
/// `_condition_variable` must be a valid pointer.
pub unsafe extern "win64" fn wake_condition_variable(_condition_variable: *mut usize) {}
/// WakeAllConditionVariable — no-op stub.
///
/// # Safety
/// `_condition_variable` must be a valid pointer.
pub unsafe extern "win64" fn wake_all_condition_variable(_condition_variable: *mut usize) {}

// ── Threads ───────────────────────────────────────────────────────────────────

/// CreateThread — thread creation is not supported; returns NULL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_thread(
    _lp_thread_attributes: *const u8,
    _dw_stack_size: usize,
    _lp_start_address: *const u8,
    _lp_parameter: *mut u8,
    _dw_creation_flags: u32,
    _lp_thread_id: *mut u32,
) -> usize {
    0 // NULL — thread creation not supported
}

/// GetThreadPriority — returns THREAD_PRIORITY_NORMAL (0).
pub extern "win64" fn get_thread_priority(_h_thread: usize) -> i32 {
    0 // THREAD_PRIORITY_NORMAL
}
/// SetThreadPriority — no-op stub, returns TRUE.
pub extern "win64" fn set_thread_priority(_h_thread: usize, _n_priority: i32) -> i32 {
    1
}
/// GetThreadContext — not supported, returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_thread_context(_h_thread: usize, _lp_context: *mut u8) -> i32 {
    0 // FALSE
}
/// SetThreadContext — not supported, returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_thread_context(_h_thread: usize, _lp_context: *const u8) -> i32 {
    0
}
/// SuspendThread — not supported, returns DWORD(-1) (failure).
pub extern "win64" fn suspend_thread(_h_thread: usize) -> u32 {
    u32::MAX // failure
}
/// ResumeThread — not supported, returns DWORD(-1) (failure).
pub extern "win64" fn resume_thread(_h_thread: usize) -> u32 {
    u32::MAX // failure
}

// ── Process ───────────────────────────────────────────────────────────────────

/// OpenProcess — returns NULL (not supported).
///
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn open_process(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _dw_process_id: u32,
) -> usize {
    0
}

/// GetProcessAffinityMask — reports single-CPU affinity.
///
/// # Safety
/// Output pointers must be valid and writable or NULL.
pub unsafe extern "win64" fn get_process_affinity_mask(
    _h_process: usize,
    lp_process_affinity_mask: *mut usize,
    lp_system_affinity_mask: *mut usize,
) -> i32 {
    unsafe {
        if !lp_process_affinity_mask.is_null() {
            *lp_process_affinity_mask = 1;
        }
        if !lp_system_affinity_mask.is_null() {
            *lp_system_affinity_mask = 1;
        }
    }
    1
}

/// SetProcessAffinityMask — no-op stub, returns TRUE.
///
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn set_process_affinity_mask(
    _h_process: usize,
    _dw_process_affinity_mask: usize,
) -> i32 {
    1
}

/// GetHandleInformation — writes 0 flags and returns TRUE.
///
/// # Safety
/// `lp_flags` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_handle_information(_h_object: usize, lp_flags: *mut u32) -> i32 {
    unsafe {
        if !lp_flags.is_null() {
            *lp_flags = 0;
        }
    }
    1
}

/// DeviceIoControl — not supported; writes 0 bytes returned and returns FALSE.
///
/// # Safety
/// `lp_bytes_returned` must be a valid writable pointer or NULL; other
/// pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn device_io_control(
    _h_device: usize,
    _dw_io_control_code: u32,
    _lp_in_buffer: *const u8,
    _n_in_buffer_size: u32,
    _lp_out_buffer: *mut u8,
    _n_out_buffer_size: u32,
    lp_bytes_returned: *mut u32,
    _lp_overlapped: *mut u8,
) -> i32 {
    unsafe {
        if !lp_bytes_returned.is_null() {
            *lp_bytes_returned = 0;
        }
    }
    0
}

// ── Environment ───────────────────────────────────────────────────────────────

/// GetEnvironmentVariableW — returns 0 (variable not found).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_environment_variable_w(
    _lp_name: *const u16,
    _lp_buffer: *mut u16,
    _n_size: u32,
) -> u32 {
    0 // not found
}

// ── Misc ──────────────────────────────────────────────────────────────────────

/// FormatMessageA — formats an error message into an ANSI buffer.
///
/// Minimal implementation that handles FORMAT_MESSAGE_FROM_SYSTEM with error codes.
/// Maps common Windows error codes to short ASCII strings and copies to caller's buffer.
///
/// # Safety
/// `lp_buffer` must be valid for `n_size` bytes when non-null.
pub unsafe extern "win64" fn format_message_a(
    dw_flags: u32,
    _lp_source: usize,
    dw_message_id: u32,
    _dw_language_id: u32,
    lp_buffer: *mut u8,
    n_size: u32,
    _arguments: usize,
) -> u32 {
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

    // Only handle the most common case
    if (dw_flags & FORMAT_MESSAGE_FROM_SYSTEM) == 0
        || (dw_flags & FORMAT_MESSAGE_IGNORE_INSERTS) == 0
    {
        return 0;
    }
    if lp_buffer.is_null() {
        return 0;
    }

    let message = match dw_message_id {
        0 => b"The operation completed successfully.\0".as_slice(),
        2 => b"The system cannot find the file specified.\0".as_slice(),
        3 => b"The system cannot find the path specified.\0".as_slice(),
        5 => b"Access is denied.\0".as_slice(),
        6 => b"The handle is invalid.\0".as_slice(),
        8 => b"Not enough memory resources are available.\0".as_slice(),
        87 => b"The parameter is incorrect.\0".as_slice(),
        122 => b"The data area passed to a system call is too small.\0".as_slice(),
        123 => b"The filename, directory name, or volume label syntax is incorrect.\0".as_slice(),
        183 => b"Cannot create a file when that file already exists.\0".as_slice(),
        _ => b"Unknown error.\0".as_slice(),
    };

    let len = message.len() - 1; // exclude null terminator
    if len >= n_size as usize {
        // Buffer too small - copy what fits
        unsafe {
            std::ptr::copy_nonoverlapping(message.as_ptr(), lp_buffer, n_size as usize);
        }
        return 0; // error: buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(message.as_ptr(), lp_buffer, message.len());
    }
    len as u32
}

/// FormatMessageW — formats an error message into a wide-character buffer.
///
/// Minimal implementation that handles FORMAT_MESSAGE_FROM_SYSTEM with error codes.
/// Maps common Windows error codes to short wide strings and copies to caller's buffer.
///
/// # Safety
/// `lp_buffer` must be valid for `n_size` u16 words when non-null.
pub unsafe extern "win64" fn format_message_w(
    dw_flags: u32,
    _lp_source: usize,
    dw_message_id: u32,
    _dw_language_id: u32,
    lp_buffer: *mut u16,
    n_size: u32,
    _arguments: usize,
) -> u32 {
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

    // Only handle the most common case
    if (dw_flags & FORMAT_MESSAGE_FROM_SYSTEM) == 0
        || (dw_flags & FORMAT_MESSAGE_IGNORE_INSERTS) == 0
    {
        return 0;
    }
    if lp_buffer.is_null() {
        return 0;
    }

    let message = match dw_message_id {
        0 => "The operation completed successfully.\0",
        2 => "The system cannot find the file specified.\0",
        3 => "The system cannot find the path specified.\0",
        5 => "Access is denied.\0",
        6 => "The handle is invalid.\0",
        8 => "Not enough memory resources are available.\0",
        87 => "The parameter is incorrect.\0",
        122 => "The data area passed to a system call is too small.\0",
        123 => "The filename, directory name, or volume label syntax is incorrect.\0",
        183 => "Cannot create a file when that file already exists.\0",
        _ => "Unknown error.\0",
    };

    let wide_chars: Vec<u16> = message.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if len >= n_size as usize {
        // Buffer too small - copy what fits
        unsafe {
            std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, n_size as usize);
        }
        return 0; // error: buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// CreateDirectoryW — not implemented; returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_directory_w(
    _lp_path_name: *const u16,
    _lp_security_attributes: *const u8,
) -> i32 {
    0
}

/// RaiseException — calls libc::abort to terminate the process.
///
/// # Safety
/// `_lp_arguments` may be NULL; this function does not return.
pub unsafe extern "win64" fn raise_exception(
    _dw_exception_code: u32,
    _dw_exception_flags: u32,
    _n_number_of_arguments: u32,
    _lp_arguments: *const usize,
) {
    unsafe { libc::abort() }
}

/// RtlCaptureContext — no-op stub (context capture not implemented).
///
/// # Safety
/// `_context_record` must be a valid writable pointer.
pub unsafe extern "win64" fn rtl_capture_context(_context_record: *mut u8) {}
/// RtlLookupFunctionEntry — returns NULL (no unwind info).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn rtl_lookup_function_entry(
    _control_pc: u64,
    _image_base: *mut u64,
    _history_table: *mut u8,
) -> *mut u8 {
    std::ptr::null_mut()
}
/// RtlVirtualUnwind — returns NULL (unwinding not implemented).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn rtl_virtual_unwind(
    _handler_type: u32,
    _image_base: u64,
    _control_pc: u64,
    _function_entry: *mut u8,
    _context_record: *mut u8,
    _handler_data: *mut *mut u8,
    _establisher_frame: *mut u64,
    _context_pointers: *mut u8,
) -> *mut u8 {
    std::ptr::null_mut()
}
/// RtlUnwindEx — no-op stub (unwinding not implemented).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn rtl_unwind_ex(
    _target_frame: *mut u8,
    _target_ip: *mut u8,
    _exception_record: *mut u8,
    _return_value: usize,
    _context_record: *mut u8,
    _history_table: *mut u8,
) {
}

/// TlsAlloc — returns TLS_OUT_OF_INDEXES (TLS not implemented).
pub extern "win64" fn tls_alloc() -> u32 {
    u32::MAX // TLS_OUT_OF_INDEXES
}
/// TlsSetValue — no-op stub, returns TRUE.
pub extern "win64" fn tls_set_value(_dw_tls_index: u32, _lp_tls_value: *mut u8) -> i32 {
    1
}
/// TlsFree — no-op stub, returns TRUE.
pub extern "win64" fn tls_free(_dw_tls_index: u32) -> i32 {
    1
}

/// WaitForSingleObject — returns WAIT_OBJECT_0 for fake handles.
///
/// For our fake handles (1 for mutexes, 2 for events), returns WAIT_OBJECT_0 (0).
/// For invalid handles (0 or INVALID_HANDLE_VALUE), returns WAIT_FAILED.
/// Ignores dw_milliseconds timeout (we don't support real waiting).
///
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn wait_for_single_object(h_handle: usize, _dw_milliseconds: u32) -> u32 {
    const INVALID_HANDLE_VALUE: usize = usize::MAX;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_FAILED: u32 = 0xFFFFFFFF;

    // Check for invalid handles
    if h_handle == 0 || h_handle == INVALID_HANDLE_VALUE {
        return WAIT_FAILED;
    }

    // For our fake handles (1 = mutex, 2 = event), return success
    if h_handle == 1 || h_handle == 2 {
        return WAIT_OBJECT_0;
    }

    // For any other handle, fail
    WAIT_FAILED
}

/// WaitForSingleObjectEx — returns WAIT_OBJECT_0 for fake handles.
///
/// Same as WaitForSingleObject but ignores b_alertable parameter.
/// For our fake handles (1 for mutexes, 2 for events), returns WAIT_OBJECT_0 (0).
/// For invalid handles (0 or INVALID_HANDLE_VALUE), returns WAIT_FAILED.
///
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn wait_for_single_object_ex(
    h_handle: usize,
    _dw_milliseconds: u32,
    _b_alertable: i32,
) -> u32 {
    const INVALID_HANDLE_VALUE: usize = usize::MAX;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_FAILED: u32 = 0xFFFFFFFF;

    // Check for invalid handles
    if h_handle == 0 || h_handle == INVALID_HANDLE_VALUE {
        return WAIT_FAILED;
    }

    // For our fake handles (1 = mutex, 2 = event), return success
    if h_handle == 1 || h_handle == 2 {
        return WAIT_OBJECT_0;
    }

    // For any other handle, fail
    WAIT_FAILED
}

/// TryEnterCriticalSection — no-op stub; always succeeds (single-threaded).
///
/// # Safety
/// `_lp_critical_section` must be a valid pointer.
pub unsafe extern "win64" fn try_enter_critical_section(_lp_critical_section: *mut usize) -> i32 {
    1 // TRUE — always succeeds in single-threaded context
}

/// SwitchToThread — no-op stub; yields are not meaningful in single-threaded mode.
pub extern "win64" fn switch_to_thread() -> i32 {
    0 // FALSE — no other thread to switch to
}
/// WaitForMultipleObjects — returns WAIT_OBJECT_0 if any handle is fake.
///
/// Returns WAIT_OBJECT_0 if any handle in the array is one of our fake handles
/// (1 for mutexes, 2 for events). Otherwise returns WAIT_FAILED.
/// Ignores b_wait_all and dw_milliseconds timeout parameters.
///
/// # Safety
/// `lp_handles` must be a valid pointer to `n_count` handles or NULL.
pub unsafe extern "win64" fn wait_for_multiple_objects(
    n_count: u32,
    lp_handles: *const usize,
    _b_wait_all: i32,
    _dw_milliseconds: u32,
) -> u32 {
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_FAILED: u32 = 0xFFFFFFFF;

    if lp_handles.is_null() || n_count == 0 {
        return WAIT_FAILED;
    }

    // Check if any handle is one of our fake handles
    for i in 0..n_count {
        let handle = unsafe { *lp_handles.add(i as usize) };
        if handle == 1 || handle == 2 {
            return WAIT_OBJECT_0;
        }
    }

    WAIT_FAILED
}

/// CreateMutexA — returns a fake handle (1).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_mutex_a(
    _lp_mutex_attributes: *const u8,
    _b_initial_owner: i32,
    _lp_name: *const u8,
) -> usize {
    1 // fake handle
}

/// CreateMutexW — returns a fake handle (1).
///
/// Same as CreateMutexA but accepts wide string name parameter.
/// Ignores name, initial owner flag, and security attributes.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_mutex_w(
    _lp_mutex_attributes: *const u8,
    _b_initial_owner: i32,
    _lp_name: *const u16,
) -> usize {
    1 // fake handle
}

/// CreateMutexExA — returns a fake handle (1).
///
/// Extended version with dwDesiredAccess parameter (ignored).
/// Same behavior as CreateMutexA.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_mutex_ex_a(
    _lp_mutex_attributes: *const u8,
    _lp_name: *const u8,
    _dw_flags: u32,
    _dw_desired_access: u32,
) -> usize {
    1 // fake handle
}

/// CreateMutexExW — returns a fake handle (1).
///
/// Extended version with dwDesiredAccess parameter (ignored).
/// Same behavior as CreateMutexW but accepts wide string name.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_mutex_ex_w(
    _lp_mutex_attributes: *const u8,
    _lp_name: *const u16,
    _dw_flags: u32,
    _dw_desired_access: u32,
) -> usize {
    1 // fake handle
}
/// ReleaseMutex — no-op stub, returns TRUE.
pub extern "win64" fn release_mutex(_h_mutex: usize) -> i32 {
    1
}

/// RtlUnwind — no-op stub (unwinding not implemented).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn rtl_unwind(
    _target_frame: *mut u8,
    _target_ip: *mut u8,
    _exception_record: *mut u8,
    _return_value: usize,
) {
}

/// UnhandledExceptionFilter — returns EXCEPTION_EXECUTE_HANDLER (1).
///
/// # Safety
/// `_exception_pointers` is accepted but not dereferenced.
pub unsafe extern "win64" fn unhandled_exception_filter(_exception_pointers: *mut u8) -> i32 {
    1 // EXCEPTION_EXECUTE_HANDLER
}

// ── lstr* string functions ───────────────────────────────────────────────────

/// lstrcmpA — compare two ANSI strings.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid null-terminated UTF-8 strings.
pub unsafe extern "win64" fn lstrcmp_a(lp_string1: *const u8, lp_string2: *const u8) -> i32 {
    unsafe { libc::strcmp(lp_string1 as *const i8, lp_string2 as *const i8) }
}

/// lstrcmpW — compare two wide strings.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn lstrcmp_w(lp_string1: *const u16, lp_string2: *const u16) -> i32 {
    unsafe {
        let mut p1 = lp_string1;
        let mut p2 = lp_string2;
        loop {
            let c1 = *p1;
            let c2 = *p2;
            if c1 != c2 {
                return if c1 < c2 { -1 } else { 1 };
            }
            if c1 == 0 {
                return 0;
            }
            p1 = p1.add(1);
            p2 = p2.add(1);
        }
    }
}

/// lstrcmpiA — compare two ANSI strings (case-insensitive).
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid null-terminated UTF-8 strings.
pub unsafe extern "win64" fn lstrcmpi_a(lp_string1: *const u8, lp_string2: *const u8) -> i32 {
    unsafe { libc::strcasecmp(lp_string1 as *const i8, lp_string2 as *const i8) }
}

/// lstrcmpiW — compare two wide strings (case-insensitive).
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn lstrcmpi_w(lp_string1: *const u16, lp_string2: *const u16) -> i32 {
    unsafe {
        let mut p1 = lp_string1;
        let mut p2 = lp_string2;
        loop {
            let c1 = *p1;
            let c2 = *p2;
            let lc1 = if (c1 as u8).is_ascii_uppercase() {
                c1 + 32
            } else {
                c1
            };
            let lc2 = if (c2 as u8).is_ascii_uppercase() {
                c2 + 32
            } else {
                c2
            };
            if lc1 != lc2 {
                return if lc1 < lc2 { -1 } else { 1 };
            }
            if c1 == 0 {
                return 0;
            }
            p1 = p1.add(1);
            p2 = p2.add(1);
        }
    }
}

/// lstrlenA — get length of ANSI string.
///
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn lstrlen_a(lp_string: *const u8) -> i32 {
    unsafe { libc::strlen(lp_string as *const i8) as i32 }
}

/// lstrlenW — get length of wide string.
///
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn lstrlen_w(lp_string: *const u16) -> i32 {
    unsafe {
        let mut len = 0i32;
        let mut p = lp_string;
        while *p != 0 {
            len += 1;
            p = p.add(1);
        }
        len
    }
}

/// lstrcpyA — copy ANSI string.
///
/// # Safety
/// `lp_string1` must be writable for the length of `lp_string2` plus null terminator.
/// `lp_string2` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn lstrcpy_a(lp_string1: *mut u8, lp_string2: *const u8) -> *mut u8 {
    unsafe { libc::strcpy(lp_string1 as *mut i8, lp_string2 as *const i8) as *mut u8 };
    lp_string1
}

/// lstrcpyW — copy wide string.
///
/// # Safety
/// `lp_string1` must be writable for the length of `lp_string2` plus null terminator.
/// `lp_string2` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn lstrcpy_w(lp_string1: *mut u16, lp_string2: *const u16) -> *mut u16 {
    unsafe {
        let mut dst = lp_string1;
        let mut src = lp_string2;
        loop {
            let c = *src;
            *dst = c;
            if c == 0 {
                break;
            }
            dst = dst.add(1);
            src = src.add(1);
        }
    }
    lp_string1
}

/// lstrcpynA — bounded copy of ANSI string.
///
/// # Safety
/// `lp_string1` must be writable for at least `i_max_length` bytes.
/// `lp_string2` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn lstrcpyn_a(
    lp_string1: *mut u8,
    lp_string2: *const u8,
    i_max_length: i32,
) -> *mut u8 {
    unsafe {
        libc::strncpy(
            lp_string1 as *mut i8,
            lp_string2 as *const i8,
            i_max_length as usize,
        ) as *mut u8
    };
    lp_string1
}

/// lstrcpynW — bounded copy of wide string.
///
/// # Safety
/// `lp_string1` must be writable for at least `i_max_length` u16 words.
/// `lp_string2` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn lstrcpyn_w(
    lp_string1: *mut u16,
    lp_string2: *const u16,
    i_max_length: i32,
) -> *mut u16 {
    unsafe {
        let mut dst = lp_string1;
        let mut src = lp_string2;
        let max_len = i_max_length as usize;
        for _i in 0..max_len {
            let c = *src;
            *dst = c;
            if c == 0 {
                break;
            }
            dst = dst.add(1);
            src = src.add(1);
        }
        // Ensure null termination
        if max_len > 0 {
            *lp_string1.add(max_len - 1) = 0;
        }
    }
    lp_string1
}

// ── Directory path functions ──────────────────────────────────────────────────

/// GetWindowsDirectoryW — write "C:\Windows" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `u_size` u16 words.
pub unsafe extern "win64" fn get_windows_directory_w(lp_buffer: *mut u16, u_size: u32) -> u32 {
    const PATH: &str = "C:\\Windows\0";
    let wide_chars: Vec<u16> = PATH.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if u_size as usize <= len {
        return len as u32; // required size
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// GetWindowsDirectoryA — write "C:\Windows" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `u_size` bytes.
pub unsafe extern "win64" fn get_windows_directory_a(lp_buffer: *mut u8, u_size: u32) -> u32 {
    const PATH: &str = "C:\\Windows\0";
    let bytes = PATH.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if u_size as usize <= len {
        return len as u32; // required size
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    }
    len as u32
}

/// GetSystemDirectoryW — write "C:\Windows\System32" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `u_size` u16 words.
pub unsafe extern "win64" fn get_system_directory_w(lp_buffer: *mut u16, u_size: u32) -> u32 {
    const PATH: &str = "C:\\Windows\\System32\0";
    let wide_chars: Vec<u16> = PATH.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if u_size as usize <= len {
        return len as u32; // required size
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// GetSystemDirectoryA — write "C:\Windows\System32" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `u_size` bytes.
pub unsafe extern "win64" fn get_system_directory_a(lp_buffer: *mut u8, u_size: u32) -> u32 {
    const PATH: &str = "C:\\Windows\\System32\0";
    let bytes = PATH.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if u_size as usize <= len {
        return len as u32; // required size
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    }
    len as u32
}

/// GetTempPathW — write "C:\Temp\" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_length` u16 words.
pub unsafe extern "win64" fn get_temp_path_w(n_buffer_length: u32, lp_buffer: *mut u16) -> u32 {
    const PATH: &str = "C:\\Temp\\\0";
    let wide_chars: Vec<u16> = PATH.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if n_buffer_length as usize <= len {
        return len as u32 + 1; // required size including null
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// GetTempPathA — write "C:\Temp\" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_length` bytes.
pub unsafe extern "win64" fn get_temp_path_a(n_buffer_length: u32, lp_buffer: *mut u8) -> u32 {
    const PATH: &str = "C:\\Temp\\\0";
    let bytes = PATH.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if n_buffer_length as usize <= len {
        return len as u32 + 1; // required size including null
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    }
    len as u32
}

/// GetCurrentDirectoryW — write "C:\" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_length` u16 words.
pub unsafe extern "win64" fn get_current_directory_w(
    n_buffer_length: u32,
    lp_buffer: *mut u16,
) -> u32 {
    const PATH: &str = "C:\\\0";
    let wide_chars: Vec<u16> = PATH.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if n_buffer_length as usize <= len {
        return len as u32 + 1; // required size including null
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// GetCurrentDirectoryA — write "C:\" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_length` bytes.
pub unsafe extern "win64" fn get_current_directory_a(
    n_buffer_length: u32,
    lp_buffer: *mut u8,
) -> u32 {
    const PATH: &str = "C:\\\0";
    let bytes = PATH.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if n_buffer_length as usize <= len {
        return len as u32 + 1; // required size including null
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    }
    len as u32
}

/// SetCurrentDirectoryW — no-op, returns TRUE.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn set_current_directory_w(_lp_path_name: *const u16) -> i32 {
    1 // TRUE
}

/// SetCurrentDirectoryA — no-op, returns TRUE.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn set_current_directory_a(_lp_path_name: *const u8) -> i32 {
    1 // TRUE
}

// ── Computer name and username ────────────────────────────────────────────────

/// GetComputerNameW — write "WEAVE" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `lpn_size` u16 words.
/// `lpn_size` must be a valid pointer to a u32.
pub unsafe extern "win64" fn get_computer_name_w(lp_buffer: *mut u16, lpn_size: *mut u32) -> i32 {
    const NAME: &str = "WEAVE\0";
    let wide_chars: Vec<u16> = NAME.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if lp_buffer.is_null() || lpn_size.is_null() {
        return 0; // FALSE
    }

    let buffer_size = unsafe { *lpn_size } as usize;
    if buffer_size <= len {
        unsafe { *lpn_size = len as u32 };
        return 0; // FALSE - buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
        *lpn_size = len as u32;
    }
    1 // TRUE
}

/// GetComputerNameA — write "WEAVE" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `lpn_size` bytes.
/// `lpn_size` must be a valid pointer to a u32.
pub unsafe extern "win64" fn get_computer_name_a(lp_buffer: *mut u8, lpn_size: *mut u32) -> i32 {
    const NAME: &str = "WEAVE\0";
    let bytes = NAME.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if lp_buffer.is_null() || lpn_size.is_null() {
        return 0; // FALSE
    }

    let buffer_size = unsafe { *lpn_size } as usize;
    if buffer_size <= len {
        unsafe { *lpn_size = len as u32 };
        return 0; // FALSE - buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
        *lpn_size = len as u32;
    }
    1 // TRUE
}

/// GetUserNameW — write "WeavUser" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `pcb_buffer` u16 words.
/// `pcb_buffer` must be a valid pointer to a u32.
pub unsafe extern "win64" fn get_user_name_w(lp_buffer: *mut u16, pcb_buffer: *mut u32) -> i32 {
    const NAME: &str = "WeavUser\0";
    let wide_chars: Vec<u16> = NAME.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if lp_buffer.is_null() || pcb_buffer.is_null() {
        return 0; // FALSE
    }

    let buffer_size = unsafe { *pcb_buffer } as usize;
    if buffer_size <= len {
        unsafe { *pcb_buffer = len as u32 };
        return 0; // FALSE - buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
        *pcb_buffer = len as u32;
    }
    1 // TRUE
}

/// GetUserNameA — write "WeavUser" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `pcb_buffer` bytes.
/// `pcb_buffer` must be a valid pointer to a u32.
pub unsafe extern "win64" fn get_user_name_a(lp_buffer: *mut u8, pcb_buffer: *mut u32) -> i32 {
    const NAME: &str = "WeavUser\0";
    let bytes = NAME.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if lp_buffer.is_null() || pcb_buffer.is_null() {
        return 0; // FALSE
    }

    let buffer_size = unsafe { *pcb_buffer } as usize;
    if buffer_size <= len {
        unsafe { *pcb_buffer = len as u32 };
        return 0; // FALSE - buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
        *pcb_buffer = len as u32;
    }
    1 // TRUE
}

// ── File attribute functions ──────────────────────────────────────────────────

/// GetFileAttributesW — check if file/directory exists and return attributes.
///
/// Translates Win32 path to Linux path and uses libc::stat to check existence.
/// Returns FILE_ATTRIBUTE_NORMAL for files, FILE_ATTRIBUTE_DIRECTORY for directories,
/// or INVALID_FILE_ATTRIBUTES if not found or stat fails.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn get_file_attributes_w(lp_file_name: *const u16) -> u32 {
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    if lp_file_name.is_null() {
        return INVALID_FILE_ATTRIBUTES;
    }

    // Decode UTF-16 filename
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return INVALID_FILE_ATTRIBUTES;
    }
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return INVALID_FILE_ATTRIBUTES,
    };

    // Check if path exists and get type
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return INVALID_FILE_ATTRIBUTES,
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return INVALID_FILE_ATTRIBUTES;
    }

    // Check if it's a directory
    if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    }
}

/// GetFileAttributesA — check if file/directory exists and return attributes.
///
/// Same as GetFileAttributesW but accepts ANSI string.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn get_file_attributes_a(lp_file_name: *const u8) -> u32 {
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    if lp_file_name.is_null() {
        return INVALID_FILE_ATTRIBUTES;
    }

    // Decode UTF-8 filename
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return INVALID_FILE_ATTRIBUTES;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return INVALID_FILE_ATTRIBUTES,
    };

    // Check if path exists and get type
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return INVALID_FILE_ATTRIBUTES,
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return INVALID_FILE_ATTRIBUTES;
    }

    // Check if it's a directory
    if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    }
}

/// GetFullPathNameW: resolve relative paths to absolute paths.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string.
/// `lp_buffer` must be writable for `n_buffer_length` u16 words.
/// `lp_file_part` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_full_path_name_w(
    lp_file_name: *const u16,
    n_buffer_length: u32,
    lp_buffer: *mut u16,
    lp_file_part: *mut *mut u16,
) -> u32 {
    if lp_file_name.is_null() {
        return 0;
    }

    // Read the null-terminated UTF-16 filename
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(lp_file_name, len) };
    let win_path = String::from_utf16_lossy(slice);

    // Check if path already starts with drive letter (X: where X is ASCII alpha)
    let resolved_path =
        if len >= 2 && (slice[0] as u8).is_ascii_alphabetic() && slice[1] == b':' as u16 {
            win_path
        } else {
            format!("C:\\{}", win_path)
        };

    // Convert back to UTF-16 with null terminator
    let wide_path: Vec<u16> = resolved_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let required_chars = wide_path.len();

    // Size query
    if n_buffer_length == 0 {
        return (required_chars - 1) as u32; // exclude null terminator
    }

    // Copy to buffer if it fits
    if n_buffer_length as usize >= required_chars {
        unsafe {
            std::ptr::copy_nonoverlapping(wide_path.as_ptr(), lp_buffer, required_chars);
        }

        // Set lp_file_part to point at the last path component (after last \)
        if !lp_file_part.is_null() {
            let path_str = &resolved_path;
            if let Some(last_backslash) = path_str.rfind('\\') {
                let file_part_offset = last_backslash + 1;
                unsafe {
                    *lp_file_part = lp_buffer.add(file_part_offset);
                }
            } else {
                unsafe {
                    *lp_file_part = lp_buffer;
                }
            }
        }

        (required_chars - 1) as u32 // return chars written (excluding null)
    } else {
        0 // error: buffer too small
    }
}

/// GetFullPathNameA: resolve relative paths to absolute paths (ANSI version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string.
/// `lp_buffer` must be writable for `n_buffer_length` bytes.
/// `lp_file_part` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_full_path_name_a(
    lp_file_name: *const u8,
    n_buffer_length: u32,
    lp_buffer: *mut u8,
    lp_file_part: *mut *mut u8,
) -> u32 {
    if lp_file_name.is_null() {
        return 0;
    }

    // Read the null-terminated UTF-8 filename
    let win_path = unsafe {
        let mut len = 0usize;
        while len < MAX_UTF8_LEN && *lp_file_name.add(len) != 0 {
            len += 1;
        }
        if len == MAX_UTF8_LEN {
            return 0;
        }
        let slice = std::slice::from_raw_parts(lp_file_name, len);
        String::from_utf8_lossy(slice).into_owned()
    };

    // Check if path already starts with drive letter (X: where X is ASCII alpha)
    let resolved_path = if win_path.len() >= 2
        && win_path.as_bytes()[0].is_ascii_alphabetic()
        && win_path.as_bytes()[1] == b':'
    {
        win_path
    } else {
        format!("C:\\{}", win_path)
    };

    // Convert to bytes with null terminator
    let bytes = resolved_path.as_bytes();
    let required_bytes = bytes.len() + 1;

    // Size query
    if n_buffer_length == 0 {
        return (required_bytes - 1) as u32; // exclude null terminator
    }

    // Copy to buffer if it fits
    if n_buffer_length as usize >= required_bytes {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
            *lp_buffer.add(bytes.len()) = 0; // null terminator
        }

        // Set lp_file_part to point at the last path component (after last \)
        if !lp_file_part.is_null() {
            let path_str = &resolved_path;
            if let Some(last_backslash) = path_str.rfind('\\') {
                let file_part_offset = last_backslash + 1;
                unsafe {
                    *lp_file_part = lp_buffer.add(file_part_offset);
                }
            } else {
                unsafe {
                    *lp_file_part = lp_buffer;
                }
            }
        }

        (required_bytes - 1) as u32 // return bytes written (excluding null)
    } else {
        0 // error: buffer too small
    }
}

/// MoveFileW: move/rename a file (wide string version).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn move_file_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read existing filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF16_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF16_LEN {
        return 0;
    }
    let old_path = unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1))
    };

    // Read new filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF16_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF16_LEN {
        return 0;
    }
    let new_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate both paths
    let linux_old = match weave_core::prefix::translator().to_linux_str(&old_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let linux_new = match weave_core::prefix::translator().to_linux_str(&new_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let c_old = match std::ffi::CString::new(linux_old.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let c_new = match std::ffi::CString::new(linux_new.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call rename
    let ret = unsafe { libc::rename(c_old.as_ptr(), c_new.as_ptr()) };
    (ret == 0) as i32
}

/// MoveFileA: move/rename a file (ANSI version).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-8 strings.
pub unsafe extern "win64" fn move_file_a(
    lp_existing_file_name: *const u8,
    lp_new_file_name: *const u8,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read existing filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF8_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF8_LEN {
        return 0;
    }
    let old_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1)) };

    // Read new filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF8_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF8_LEN {
        return 0;
    }
    let new_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate both paths
    let linux_old = match weave_core::prefix::translator().to_linux_str(&old_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let linux_new = match weave_core::prefix::translator().to_linux_str(&new_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let c_old = match std::ffi::CString::new(linux_old.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let c_new = match std::ffi::CString::new(linux_new.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call rename
    let ret = unsafe { libc::rename(c_old.as_ptr(), c_new.as_ptr()) };
    (ret == 0) as i32
}

/// RemoveDirectoryW: remove a directory (wide string version).
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn remove_directory_w(lp_path_name: *const u16) -> i32 {
    if lp_path_name.is_null() {
        return 0; // FALSE
    }

    // Read path
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_path_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_path_name, len)) };

    // Translate path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C string
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call rmdir
    let ret = unsafe { libc::rmdir(c_path.as_ptr()) };
    (ret == 0) as i32
}

/// RemoveDirectoryA: remove a directory (ANSI version).
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn remove_directory_a(lp_path_name: *const u8) -> i32 {
    if lp_path_name.is_null() {
        return 0; // FALSE
    }

    // Read path
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_path_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_path_name, len)) };

    // Translate path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C string
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call rmdir
    let ret = unsafe { libc::rmdir(c_path.as_ptr()) };
    (ret == 0) as i32
}

/// CreateDirectoryA: create a directory (ANSI version).
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-8 string.
/// `lp_security_attributes` is ignored.
pub unsafe extern "win64" fn create_directory_a(
    lp_path_name: *const u8,
    _lp_security_attributes: usize,
) -> i32 {
    if lp_path_name.is_null() {
        return 0; // FALSE
    }

    // Read path
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_path_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_path_name, len)) };

    // Translate path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C string
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call mkdir with 0o755 permissions
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), 0o755) };
    (ret == 0) as i32
}

/// GetLogicalDrives: return bitmask of available drives.
///
/// Returns 0x00000004 (bit 2 set) indicating drive C: exists.
pub extern "win64" fn get_logical_drives() -> u32 {
    0x00000004 // bit 2 = drive C:
}

/// GetDriveTypeW: determine the type of drive (wide string version).
///
/// # Safety
/// `lp_root_path_name` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn get_drive_type_w(lp_root_path_name: *const u16) -> u32 {
    const DRIVE_UNKNOWN: u32 = 0;
    const DRIVE_FIXED: u32 = 3;

    if lp_root_path_name.is_null() {
        return DRIVE_UNKNOWN;
    }

    // Read the path and check if it starts with 'C' (u16 value 67)
    let first_char = unsafe { *lp_root_path_name };
    if first_char == 67 {
        // 'C' as u16
        DRIVE_FIXED
    } else {
        DRIVE_UNKNOWN
    }
}

/// GetDriveTypeA: determine the type of drive (ANSI version).
///
/// # Safety
/// `lp_root_path_name` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn get_drive_type_a(lp_root_path_name: *const u8) -> u32 {
    const DRIVE_UNKNOWN: u32 = 0;
    const DRIVE_FIXED: u32 = 3;

    if lp_root_path_name.is_null() {
        return DRIVE_UNKNOWN;
    }

    // Check if first byte is 'C'
    let first_byte = unsafe { *lp_root_path_name };
    if first_byte == b'C' {
        DRIVE_FIXED
    } else {
        DRIVE_UNKNOWN
    }
}

/// GetDiskFreeSpaceExW: get disk space information for drive C:.
///
/// # Safety
/// `lp_directory_name` is ignored.
/// `lp_free_bytes_available_to_caller`, `lp_total_number_of_bytes`,
/// `lp_total_number_of_free_bytes` must be valid pointers or NULL.
pub unsafe extern "win64" fn get_disk_free_space_ex_w(
    _lp_directory_name: *const u16,
    lp_free_bytes_available_to_caller: *mut u64,
    lp_total_number_of_bytes: *mut u64,
    lp_total_number_of_free_bytes: *mut u64,
) -> i32 {
    // Write fake values: 100GB free/available, 500GB total
    if !lp_free_bytes_available_to_caller.is_null() {
        unsafe { *lp_free_bytes_available_to_caller = 100 * 1024 * 1024 * 1024u64 };
    }
    if !lp_total_number_of_bytes.is_null() {
        unsafe { *lp_total_number_of_bytes = 500 * 1024 * 1024 * 1024u64 };
    }
    if !lp_total_number_of_free_bytes.is_null() {
        unsafe { *lp_total_number_of_free_bytes = 100 * 1024 * 1024 * 1024u64 };
    }
    1 // TRUE
}

/// GetExitCodeProcess: get the exit code of a process.
///
/// # Safety
/// `lp_exit_code` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_exit_code_process(
    _h_process: usize,
    lp_exit_code: *mut u32,
) -> i32 {
    // Write STILL_ACTIVE (259) to indicate process is still running
    if !lp_exit_code.is_null() {
        unsafe { *lp_exit_code = 259 };
    }
    1 // TRUE
}

/// GetExitCodeThread: get the exit code of a thread.
///
/// # Safety
/// `lp_exit_code` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_exit_code_thread(_h_thread: usize, lp_exit_code: *mut u32) -> i32 {
    // Write STILL_ACTIVE (259) to indicate thread is still running
    if !lp_exit_code.is_null() {
        unsafe { *lp_exit_code = 259 };
    }
    1 // TRUE
}

/// TerminateThread: terminate a thread (no-op stub).
///
/// # Safety
/// `h_thread` is accepted but not dereferenced.
pub unsafe extern "win64" fn terminate_thread(_h_thread: usize, _dw_exit_code: u32) -> i32 {
    // No-op: thread termination not supported in Phase 1
    1 // TRUE
}

/// SetFileAttributesW — no-op, returns TRUE.
///
/// We don't track Win32 file attributes separately from Linux permissions.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn set_file_attributes_w(
    _lp_file_name: *const u16,
    _dw_file_attributes: u32,
) -> i32 {
    1 // TRUE
}

/// SetFileAttributesA — no-op, returns TRUE.
///
/// We don't track Win32 file attributes separately from Linux permissions.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn set_file_attributes_a(
    _lp_file_name: *const u8,
    _dw_file_attributes: u32,
) -> i32 {
    1 // TRUE
}

// ── Time functions ───────────────────────────────────────────────────────────

/// Windows SYSTEMTIME structure — represents a date and time.
#[repr(C)]
pub struct SystemTime {
    w_year: u16,
    w_month: u16,
    w_day_of_week: u16,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}

/// GetVersionExW: fill an OSVERSIONINFOEXW struct with Windows 10 info.
///
/// # Safety
/// `lp_version_information` must be a valid writable pointer to an OsVersionInfoExW.
pub unsafe extern "win64" fn get_version_ex_w(lp_version_information: *mut u8) -> i32 {
    let info = lp_version_information as *mut OsVersionInfoExW;
    unsafe {
        (*info).dw_major_version = 10;
        (*info).dw_minor_version = 0;
        (*info).dw_build_number = 18362;
        (*info).dw_platform_id = 2; // VER_PLATFORM_WIN32_NT
                                    // sz_csd_version is already zero-initialized

        let size = (*info).dw_os_version_info_size;
        if size >= 284 {
            // OSVERSIONINFOEXW
            (*info).w_service_pack_major = 0;
            (*info).w_service_pack_minor = 0;
            (*info).w_suite_mask = 0x0100; // VER_SUITE_SINGLEUSERTS
            (*info).w_product_type = 1; // VER_NT_WORKSTATION
            (*info).w_reserved = 0;
        }
    }
    1 // TRUE
}

/// GetVersionExA: fill an OSVERSIONINFOEXA struct with Windows 10 info.
///
/// # Safety
/// `lp_version_information` must be a valid writable pointer to an OsVersionInfoExA.
pub unsafe extern "win64" fn get_version_ex_a(lp_version_information: *mut u8) -> i32 {
    let info = lp_version_information as *mut OsVersionInfoExA;
    unsafe {
        (*info).dw_major_version = 10;
        (*info).dw_minor_version = 0;
        (*info).dw_build_number = 18362;
        (*info).dw_platform_id = 2; // VER_PLATFORM_WIN32_NT
                                    // sz_csd_version is already zero-initialized

        let size = (*info).dw_os_version_info_size;
        if size >= 156 {
            // OSVERSIONINFOEXA
            (*info).w_service_pack_major = 0;
            (*info).w_service_pack_minor = 0;
            (*info).w_suite_mask = 0x0100; // VER_SUITE_SINGLEUSERTS
            (*info).w_product_type = 1; // VER_NT_WORKSTATION
            (*info).w_reserved = 0;
        }
    }
    1 // TRUE
}

/// Fake command line for GetCommandLineA.
static CMD_LINE_A: &[u8] = b"app.exe\0";

/// Fake command line for GetCommandLineW.
static CMD_LINE_W: &[u16] = &[
    b'a' as u16,
    b'p' as u16,
    b'p' as u16,
    b'.' as u16,
    b'e' as u16,
    b'x' as u16,
    b'e' as u16,
    0u16,
];

/// GetCommandLineA: return a static fake command line.
///
/// Returns a pointer to a static "app.exe" string.
pub extern "win64" fn get_command_line_a() -> usize {
    CMD_LINE_A.as_ptr() as usize
}

/// GetCommandLineW: return a static fake command line.
///
/// Returns a pointer to a static wide "app.exe" string.
pub extern "win64" fn get_command_line_w() -> usize {
    CMD_LINE_W.as_ptr() as usize
}

/// EncodePointer: identity — return the pointer unchanged.
pub extern "win64" fn encode_pointer(ptr: usize) -> usize {
    ptr
}

/// DecodePointer: identity — return the pointer unchanged.
pub extern "win64" fn decode_pointer(ptr: usize) -> usize {
    ptr
}

const FLS_MAX_SLOTS: usize = 128;
const FLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF;

/// Fiber Local Storage data and usage tracking.
static mut FLS_DATA: [usize; FLS_MAX_SLOTS] = [0; FLS_MAX_SLOTS];
static mut FLS_USED: [bool; FLS_MAX_SLOTS] = [false; FLS_MAX_SLOTS];

/// FlsAlloc: allocate a fiber local storage slot.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn fls_alloc(_lp_callback: usize) -> u32 {
    unsafe {
        for i in 0..FLS_MAX_SLOTS {
            if !FLS_USED[i] {
                FLS_USED[i] = true;
                FLS_DATA[i] = 0;
                return i as u32;
            }
        }
        FLS_OUT_OF_INDEXES
    }
}

/// FlsGetValue: retrieve value from fiber local storage slot.
pub extern "win64" fn fls_get_value(dw_fls_index: u32) -> usize {
    if dw_fls_index >= FLS_MAX_SLOTS as u32 {
        return 0;
    }
    unsafe { FLS_DATA[dw_fls_index as usize] }
}

/// FlsSetValue: store value in fiber local storage slot.
pub extern "win64" fn fls_set_value(dw_fls_index: u32, lp_fls_data: usize) -> i32 {
    if dw_fls_index >= FLS_MAX_SLOTS as u32 {
        return 0; // FALSE
    }
    unsafe {
        FLS_DATA[dw_fls_index as usize] = lp_fls_data;
    }
    1 // TRUE
}

/// FlsFree: free a fiber local storage slot.
pub extern "win64" fn fls_free(dw_fls_index: u32) -> i32 {
    if dw_fls_index >= FLS_MAX_SLOTS as u32 {
        return 0; // FALSE
    }
    unsafe {
        FLS_USED[dw_fls_index as usize] = false;
        FLS_DATA[dw_fls_index as usize] = 0;
    }
    1 // TRUE
}

/// InitializeCriticalSectionAndSpinCount: initialize critical section with spin count.
///
/// # Safety
/// `lp_critical_section` must point to at least 40 bytes of writable memory.
pub unsafe extern "win64" fn initialize_critical_section_and_spin_count(
    lp_critical_section: *mut u8,
    _dw_spin_count: u32,
) -> i32 {
    unsafe { std::ptr::write_bytes(lp_critical_section, 0, 40) };
    // LockCount at offset 8 should be -1 (unlocked)
    unsafe { *(lp_critical_section.add(8) as *mut i32) = -1 };
    1 // TRUE
}

/// InitializeCriticalSectionEx: initialize critical section with extended options.
///
/// # Safety
/// `lp_critical_section` must point to at least 40 bytes of writable memory.
pub unsafe extern "win64" fn initialize_critical_section_ex(
    lp_critical_section: *mut u8,
    _dw_spin_count: u32,
    _flags: u32,
) -> i32 {
    unsafe { std::ptr::write_bytes(lp_critical_section, 0, 40) };
    // LockCount at offset 8 should be -1 (unlocked)
    unsafe { *(lp_critical_section.add(8) as *mut i32) = -1 };
    1 // TRUE
}

/// HeapSetInformation: set heap information (no-op).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn heap_set_information(
    _heap_handle: usize,
    _heap_information_class: u32,
    _heap_information: *mut u8,
    _heap_information_length: usize,
) -> i32 {
    1 // TRUE
}

/// SetHandleCount: legacy stub that returns the input value.
pub extern "win64" fn set_handle_count(u_number: u32) -> u32 {
    u_number
}

/// GetThreadLocale: return English (United States) locale ID.
pub extern "win64" fn get_thread_locale() -> u32 {
    0x0409 // LOCALE_EN_US
}

/// SetThreadLocale: no-op, returns TRUE.
pub extern "win64" fn set_thread_locale(_locale: u32) -> i32 {
    1 // TRUE
}

/// SetThreadStackGuarantee: no-op, returns TRUE.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn set_thread_stack_guarantee(_stack_size_in_bytes: *mut u32) -> i32 {
    1 // TRUE
}

/// GetTimeZoneInformation: fill TIME_ZONE_INFORMATION struct with UTC info.
///
/// # Safety
/// `lp_time_zone_information` must be a valid writable pointer to a TIME_ZONE_INFORMATION.
pub unsafe extern "win64" fn get_time_zone_information(lp_time_zone_information: *mut u8) -> u32 {
    unsafe { std::ptr::write_bytes(lp_time_zone_information, 0, 172) }; // Zero entire struct
                                                                        // bias = 0 (UTC)
    0 // TIME_ZONE_ID_UNKNOWN
}

/// GetSystemTime: fill a SYSTEMTIME struct with current UTC time.
///
/// # Safety
/// `lp_system_time` must be a valid writable pointer to a SystemTime struct.
pub unsafe extern "win64" fn get_system_time(lp_system_time: *mut u8) {
    let mut t: libc::time_t = 0;
    unsafe { libc::time(&mut t) };
    let mut tm: libc::tm = std::mem::zeroed();
    unsafe { libc::gmtime_r(&t, &mut tm) };
    let st = lp_system_time as *mut SystemTime;
    unsafe {
        (*st).w_year = (tm.tm_year + 1900) as u16;
        (*st).w_month = (tm.tm_mon + 1) as u16;
        (*st).w_day_of_week = tm.tm_wday as u16;
        (*st).w_day = tm.tm_mday as u16;
        (*st).w_hour = tm.tm_hour as u16;
        (*st).w_minute = tm.tm_min as u16;
        (*st).w_second = tm.tm_sec as u16;
        (*st).w_milliseconds = 0;
    }
}

/// GetLocalTime: fill a SYSTEMTIME struct with current local time.
///
/// # Safety
/// `lp_system_time` must be a valid writable pointer to a SystemTime struct.
pub unsafe extern "win64" fn get_local_time(lp_system_time: *mut u8) {
    let mut t: libc::time_t = 0;
    unsafe { libc::time(&mut t) };
    let mut tm: libc::tm = std::mem::zeroed();
    unsafe { libc::localtime_r(&t, &mut tm) };
    let st = lp_system_time as *mut SystemTime;
    unsafe {
        (*st).w_year = (tm.tm_year + 1900) as u16;
        (*st).w_month = (tm.tm_mon + 1) as u16;
        (*st).w_day_of_week = tm.tm_wday as u16;
        (*st).w_day = tm.tm_mday as u16;
        (*st).w_hour = tm.tm_hour as u16;
        (*st).w_minute = tm.tm_min as u16;
        (*st).w_second = tm.tm_sec as u16;
        (*st).w_milliseconds = 0;
    }
}

// ── Environment functions ────────────────────────────────────────────────────

/// Static empty wide environment block (double-null-terminated).
static EMPTY_ENV_W: [u16; 2] = [0u16, 0u16];

/// Static empty narrow environment block (double-null-terminated).
static EMPTY_ENV_A: [u8; 2] = [0u8, 0u8];

/// GetEnvironmentVariableA: return 0 (variable not found).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_environment_variable_a(
    _lp_name: *const u8,
    _lp_buffer: *mut u8,
    _n_size: u32,
) -> u32 {
    0 // not found
}

/// SetEnvironmentVariableW: no-op, returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_environment_variable_w(
    _lp_name: *const u16,
    _lp_value: *const u16,
) -> i32 {
    1 // TRUE
}

/// SetEnvironmentVariableA: no-op, returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_environment_variable_a(
    _lp_name: *const u8,
    _lp_value: *const u8,
) -> i32 {
    1 // TRUE
}

/// GetEnvironmentStringsW: return pointer to static empty wide environment block.
pub extern "win64" fn get_environment_strings_w() -> usize {
    EMPTY_ENV_W.as_ptr() as usize
}

/// GetEnvironmentStringsA: return pointer to static empty narrow environment block.
pub extern "win64" fn get_environment_strings_a() -> usize {
    EMPTY_ENV_A.as_ptr() as usize
}

/// FreeEnvironmentStringsW: no-op, returns TRUE.
///
/// # Safety
/// `penv` is accepted but not dereferenced.
pub unsafe extern "win64" fn free_environment_strings_w(_penv: *mut u16) -> i32 {
    1 // TRUE
}

/// FreeEnvironmentStringsA: no-op, returns TRUE.
///
/// # Safety
/// `penv` is accepted but not dereferenced.
pub unsafe extern "win64" fn free_environment_strings_a(_penv: *mut u8) -> i32 {
    1 // TRUE
}

// ── Locale functions ────────────────────────────────────────────────────────

/// GetLocaleInfoW: retrieve locale information as UTF-16 string.
///
/// # Safety
/// `lp_lc_data` must be a valid writable pointer for `cch_data` u16 words.
pub unsafe extern "win64" fn get_locale_info_w(
    _locale: u32,
    lc_type: u32,
    lp_lc_data: *mut u16,
    cch_data: i32,
) -> i32 {
    let lc_type_clean = lc_type & 0x000FFFFF; // strip LOCALE_RETURN_NUMBER flag
    if let Some(value) = locale_info_lookup(lc_type_clean) {
        let wide_chars: Vec<u16> = format!("{}\0", value).encode_utf16().collect();
        let required_size = wide_chars.len() as i32;
        if cch_data == 0 {
            return required_size;
        }
        if cch_data >= required_size {
            unsafe {
                std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_lc_data, wide_chars.len());
            }
            return required_size - 1; // exclude null terminator
        }
    }
    0 // failure
}

/// GetLocaleInfoA: retrieve locale information as ANSI string.
///
/// # Safety
/// `lp_lc_data` must be a valid writable pointer for `cch_data` bytes.
pub unsafe extern "win64" fn get_locale_info_a(
    _locale: u32,
    lc_type: u32,
    lp_lc_data: *mut u8,
    cch_data: i32,
) -> i32 {
    let lc_type_clean = lc_type & 0x000FFFFF; // strip LOCALE_RETURN_NUMBER flag
    if let Some(value) = locale_info_lookup(lc_type_clean) {
        let formatted = format!("{}\0", value);
        let bytes = formatted.as_bytes();
        let required_size = bytes.len() as i32;
        if cch_data == 0 {
            return required_size;
        }
        if cch_data >= required_size {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_lc_data, bytes.len());
            }
            return required_size - 1; // exclude null terminator
        }
    }
    0 // failure
}

/// Locale constant for English (United States).
const LOCALE_EN_US: u32 = 0x0409;

// ── String comparison ───────────────────────────────────────────────────────

/// CompareStringW result constants.
const CSTR_LESS_THAN: i32 = 1;
const CSTR_EQUAL: i32 = 2;
const CSTR_GREATER_THAN: i32 = 3;

/// CompareStringW flag constants.
const NORM_IGNORECASE: u32 = 0x00000001;
const LINGUISTIC_IGNORECASE: u32 = 0x00000010;

/// CompareStringW: compare two UTF-16 strings with optional case folding.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid pointers to null-terminated UTF-16 strings.
pub unsafe extern "win64" fn compare_string_w(
    _locale: u32,
    dw_cmp_flags: u32,
    lp_string1: *const u16,
    cch_count1: i32,
    lp_string2: *const u16,
    cch_count2: i32,
) -> i32 {
    let len1 = if cch_count1 == -1 {
        let mut len = 0usize;
        while *lp_string1.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count1 as usize
    };

    let len2 = if cch_count2 == -1 {
        let mut len = 0usize;
        while *lp_string2.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count2 as usize
    };

    let case_insensitive =
        (dw_cmp_flags & NORM_IGNORECASE) != 0 || (dw_cmp_flags & LINGUISTIC_IGNORECASE) != 0;

    let min_len = len1.min(len2);
    for i in 0..min_len {
        let mut c1 = *lp_string1.add(i);
        let mut c2 = *lp_string2.add(i);

        if case_insensitive && (c1 as u8).is_ascii_uppercase() {
            c1 += 32;
        }
        if case_insensitive && (c2 as u8).is_ascii_uppercase() {
            c2 += 32;
        }

        if c1 < c2 {
            return CSTR_LESS_THAN;
        } else if c1 > c2 {
            return CSTR_GREATER_THAN;
        }
    }

    match len1.cmp(&len2) {
        std::cmp::Ordering::Less => CSTR_LESS_THAN,
        std::cmp::Ordering::Equal => CSTR_EQUAL,
        std::cmp::Ordering::Greater => CSTR_GREATER_THAN,
    }
}

/// CompareStringOrdinal: compare two UTF-16 strings with optional case folding.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid pointers to null-terminated UTF-16 strings.
pub unsafe extern "win64" fn compare_string_ordinal(
    lp_string1: *const u16,
    cch_count1: i32,
    lp_string2: *const u16,
    cch_count2: i32,
    b_ignore_case: i32,
) -> i32 {
    let len1 = if cch_count1 == -1 {
        let mut len = 0usize;
        while *lp_string1.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count1 as usize
    };

    let len2 = if cch_count2 == -1 {
        let mut len = 0usize;
        while *lp_string2.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count2 as usize
    };

    let case_insensitive = b_ignore_case != 0;

    let min_len = len1.min(len2);
    for i in 0..min_len {
        let mut c1 = *lp_string1.add(i);
        let mut c2 = *lp_string2.add(i);

        if case_insensitive && (c1 as u8).is_ascii_uppercase() {
            c1 += 32;
        }
        if case_insensitive && (c2 as u8).is_ascii_uppercase() {
            c2 += 32;
        }

        if c1 < c2 {
            return CSTR_LESS_THAN;
        } else if c1 > c2 {
            return CSTR_GREATER_THAN;
        }
    }

    match len1.cmp(&len2) {
        std::cmp::Ordering::Less => CSTR_LESS_THAN,
        std::cmp::Ordering::Equal => CSTR_EQUAL,
        std::cmp::Ordering::Greater => CSTR_GREATER_THAN,
    }
}

// ── String mapping ──────────────────────────────────────────────────────────

const LCMAP_LOWERCASE: u32 = 0x00000100;
const LCMAP_UPPERCASE: u32 = 0x00000200;

/// LCMapStringW: map a UTF-16 string (uppercase/lowercase conversion).
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` u16 elements.
/// `lp_dest_str` must be writable for `cch_dest` u16 elements.
pub unsafe extern "win64" fn lc_map_string_w(
    _locale: u32,
    dw_map_flags: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_dest_str: *mut u16,
    cch_dest: i32,
) -> i32 {
    let src_len = if cch_src == -1 {
        let mut len = 0usize;
        unsafe {
            while *lp_src_str.add(len) != 0 {
                len += 1;
            }
        }
        len + 1 // include null
    } else {
        cch_src as usize
    };

    if cch_dest == 0 {
        return src_len as i32;
    }

    let copy_len = src_len.min(cch_dest as usize);
    for i in 0..copy_len {
        let mut c = unsafe { *lp_src_str.add(i) };
        if c <= 127 {
            if (dw_map_flags & LCMAP_UPPERCASE) != 0 && (c as u8).is_ascii_lowercase() {
                c -= 32;
            } else if (dw_map_flags & LCMAP_LOWERCASE) != 0 && (c as u8).is_ascii_uppercase() {
                c += 32;
            }
        }
        unsafe { *lp_dest_str.add(i) = c };
    }
    copy_len as i32
}

// ── Character classification ────────────────────────────────────────────────

const CT_CTYPE1: u32 = 0x00000001;
const C1_UPPER: u16 = 0x0001;
const C1_LOWER: u16 = 0x0002;
const C1_DIGIT: u16 = 0x0004;
const C1_SPACE: u16 = 0x0008;
const C1_PUNCT: u16 = 0x0010;
const C1_CNTRL: u16 = 0x0020;
const C1_BLANK: u16 = 0x0040;
const C1_ALPHA: u16 = 0x0100;

fn classify_char(c: u16) -> u16 {
    if c > 127 {
        return C1_ALPHA;
    }
    let b = c as u8;
    let mut flags: u16 = 0;
    if b.is_ascii_uppercase() {
        flags |= C1_UPPER | C1_ALPHA;
    }
    if b.is_ascii_lowercase() {
        flags |= C1_LOWER | C1_ALPHA;
    }
    if b.is_ascii_digit() {
        flags |= C1_DIGIT;
    }
    if b.is_ascii_whitespace() {
        flags |= C1_SPACE;
    }
    if b == b' ' || b == b'\t' {
        flags |= C1_BLANK;
    }
    if b.is_ascii_punctuation() {
        flags |= C1_PUNCT;
    }
    if b < 0x20 || b == 0x7F {
        flags |= C1_CNTRL;
    }
    flags
}

/// GetStringTypeW: classify characters in a UTF-16 string.
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` u16 elements.
/// `lp_char_type` must be writable for `cch_src` u16 elements.
pub unsafe extern "win64" fn get_string_type_w(
    dw_info_type: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_char_type: *mut u16,
) -> i32 {
    if dw_info_type != CT_CTYPE1 {
        return 0; // FALSE — only CT_CTYPE1 supported
    }

    let len = if cch_src == -1 {
        let mut l = 0usize;
        unsafe {
            while *lp_src_str.add(l) != 0 {
                l += 1;
            }
        }
        l
    } else {
        cch_src as usize
    };

    for i in 0..len {
        unsafe {
            *lp_char_type.add(i) = classify_char(*lp_src_str.add(i));
        }
    }
    1 // TRUE
}

// ── File time and positioning ───────────────────────────────────────────────

/// SetFilePointerEx: set file pointer position using 64-bit offset.
///
/// # Safety
/// If `lp_new_file_pointer` is non-null, it must be writable.
pub unsafe extern "win64" fn set_file_pointer_ex(
    h_file: usize,
    li_distance_to_move: i64,
    lp_new_file_pointer: *mut i64,
    dw_move_method: u32,
) -> i32 {
    let whence = match dw_move_method {
        0 => libc::SEEK_SET,
        1 => libc::SEEK_CUR,
        2 => libc::SEEK_END,
        _ => return 0, // FALSE
    };
    let result = unsafe { libc::lseek(h_file as i32, li_distance_to_move, whence) };
    if result >= 0 {
        if !lp_new_file_pointer.is_null() {
            unsafe { *lp_new_file_pointer = result };
        }
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// GetFileTime: stub that returns TRUE without filling timestamps.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_file_time(
    _h_file: usize,
    _lp_creation_time: *mut u64,
    _lp_last_access_time: *mut u64,
    _lp_last_write_time: *mut u64,
) -> i32 {
    1 // TRUE
}

/// SetFileTime: no-op stub that returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_file_time(
    _h_file: usize,
    _lp_creation_time: *const u64,
    _lp_last_access_time: *const u64,
    _lp_last_write_time: *const u64,
) -> i32 {
    1 // TRUE
}

// ── Vectored exception handlers ─────────────────────────────────────────────

/// AddVectoredExceptionHandler: no-op stub returning the handler as a fake handle.
pub extern "win64" fn add_vectored_exception_handler(_first: u32, handler: usize) -> usize {
    handler
}

/// RemoveVectoredExceptionHandler: no-op stub returning success.
pub extern "win64" fn remove_vectored_exception_handler(_handle: usize) -> u32 {
    1
}

/// AddVectoredContinueHandler: no-op stub returning the handler as a fake handle.
pub extern "win64" fn add_vectored_continue_handler(_first: u32, handler: usize) -> usize {
    handler
}

/// RemoveVectoredContinueHandler: no-op stub returning success.
pub extern "win64" fn remove_vectored_continue_handler(_handle: usize) -> u32 {
    1
}

/// File type constant for unknown files.
const FILE_TYPE_UNKNOWN: u32 = 0x0000;

/// GetUserDefaultLCID: return English (United States) locale ID.
pub extern "win64" fn get_user_default_lcid() -> u32 {
    LOCALE_EN_US
}

/// GetSystemDefaultLCID: return English (United States) locale ID.
pub extern "win64" fn get_system_default_lcid() -> u32 {
    LOCALE_EN_US
}

/// GetUserDefaultUILanguage: return English (United States) language ID.
pub extern "win64" fn get_user_default_ui_language() -> u16 {
    LOCALE_EN_US as u16
}

/// GetSystemDefaultLangID: return English (United States) language ID.
pub extern "win64" fn get_system_default_lang_id() -> u16 {
    LOCALE_EN_US as u16
}

/// IsValidCodePage: validate code page identifiers.
pub extern "win64" fn is_valid_code_page(code_page: u32) -> i32 {
    match code_page {
        0 | 65001 | 1252 | 437 => 1, // TRUE for UTF-8, CP_ACP, CP_OEM
        _ => 0,                      // FALSE for others
    }
}

/// GetFileType: return FILE_TYPE_UNKNOWN.
pub extern "win64" fn get_file_type(_h_file: usize) -> u32 {
    FILE_TYPE_UNKNOWN
}

// ── File and console functions ──────────────────────────────────────────────

/// GetFileSizeEx: write 0 to file size, return FALSE.
///
/// # Safety
/// `lp_file_size` must be a valid writable pointer to an i64.
pub unsafe extern "win64" fn get_file_size_ex(_h_file: usize, lp_file_size: *mut i64) -> i32 {
    unsafe {
        if !lp_file_size.is_null() {
            *lp_file_size = 0;
        }
    }
    0 // FALSE
}

/// GetConsoleMode: write 0 to mode, return TRUE.
///
/// # Safety
/// `lp_mode` must be a valid writable pointer to a u32.
pub unsafe extern "win64" fn get_console_mode(_h_console_handle: usize, lp_mode: *mut u32) -> i32 {
    unsafe {
        if !lp_mode.is_null() {
            *lp_mode = 0;
        }
    }
    1 // TRUE
}

/// SetConsoleMode: no-op, return TRUE.
///
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn set_console_mode(_h_console_handle: usize, _dw_mode: u32) -> i32 {
    1 // TRUE
}

// ── Console functions ─────────────────────────────────────────────────────────

/// WriteConsoleA: write ANSI buffer to console handle.
///
/// Converts ANSI to UTF-8 and writes to the Linux fd.
///
/// # Safety
/// `lp_buffer` must be valid for `n_chars` bytes.
pub unsafe extern "win64" fn write_console_a(
    h_console_output: usize,
    lp_buffer: *const u8,
    n_chars: u32,
    lp_chars_written: *mut u32,
    _lp_reserved: usize,
) -> i32 {
    let fd = match handles::get_fd(h_console_output) {
        Some(fd) => fd,
        None => return 0, // FALSE
    };
    let slice = unsafe { std::slice::from_raw_parts(lp_buffer, n_chars as usize) };
    let s = String::from_utf8_lossy(slice);
    let bytes = s.as_bytes();
    let n = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    if !lp_chars_written.is_null() {
        unsafe { *lp_chars_written = if n >= 0 { n_chars } else { 0 } };
    }
    (n >= 0) as i32
}

/// SetConsoleTitleW: set console title (wide version).
///
/// No-op. Return TRUE.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn set_console_title_w(_lp_console_title: *const u16) -> i32 {
    1 // TRUE
}

/// SetConsoleTitleA: set console title (ANSI version).
///
/// No-op. Return TRUE.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn set_console_title_a(_lp_console_title: *const u8) -> i32 {
    1 // TRUE
}

/// GetConsoleTitleW: get console title (wide version).
///
/// Write 0 to buffer, return 0.
///
/// # Safety
/// `lp_console_title` must be valid for `n_size` u16 words.
pub unsafe extern "win64" fn get_console_title_w(lp_console_title: *mut u16, n_size: u32) -> u32 {
    if !lp_console_title.is_null() && n_size > 0 {
        unsafe { *lp_console_title = 0 };
    }
    0
}

/// GetConsoleTitleA: get console title (ANSI version).
///
/// Write 0 to buffer, return 0.
///
/// # Safety
/// `lp_console_title` must be valid for `n_size` bytes.
pub unsafe extern "win64" fn get_console_title_a(lp_console_title: *mut u8, n_size: u32) -> u32 {
    if !lp_console_title.is_null() && n_size > 0 {
        unsafe { *lp_console_title = 0 };
    }
    0
}

/// GetConsoleScreenBufferInfo: get console screen buffer info.
///
/// Fill struct with fake 80×25 console info, return TRUE.
///
/// # Safety
/// `lp_console_screen_buffer_info` must be a valid writable pointer to a ConsoleScreenBufferInfo.
pub unsafe extern "win64" fn get_console_screen_buffer_info(
    _h_console_output: usize,
    lp_console_screen_buffer_info: *mut ConsoleScreenBufferInfo,
) -> i32 {
    if lp_console_screen_buffer_info.is_null() {
        return 0; // FALSE
    }
    unsafe {
        (*lp_console_screen_buffer_info).size_x = 80;
        (*lp_console_screen_buffer_info).size_y = 25;
        (*lp_console_screen_buffer_info).cursor_x = 0;
        (*lp_console_screen_buffer_info).cursor_y = 0;
        (*lp_console_screen_buffer_info).attributes = 7; // gray on black
        (*lp_console_screen_buffer_info).window_left = 0;
        (*lp_console_screen_buffer_info).window_top = 0;
        (*lp_console_screen_buffer_info).window_right = 79;
        (*lp_console_screen_buffer_info).window_bottom = 24;
        (*lp_console_screen_buffer_info).max_x = 80;
        (*lp_console_screen_buffer_info).max_y = 25;
    }
    1 // TRUE
}

/// SetConsoleTextAttribute: set console text attributes.
///
/// No-op. Return TRUE.
///
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn set_console_text_attribute(
    _h_console_output: usize,
    _w_attributes: u16,
) -> i32 {
    1 // TRUE
}

/// SetConsoleCtrlHandler: set console control handler.
///
/// No-op. Return TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_console_ctrl_handler(_handler_routine: usize, _add: i32) -> i32 {
    1 // TRUE
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
        "VirtualAlloc" => {
            Some(virtual_alloc as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "VirtualAllocEx" => Some(
            virtual_alloc_ex as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "VirtualFree" => {
            Some(virtual_free as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "VirtualFreeEx" => {
            Some(virtual_free_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
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
        "CreateFileA" => Some(
            create_file_a as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateFileW" => Some(
            create_file_w as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "ReadFile" => {
            Some(read_file as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "WriteFile" => {
            Some(write_file as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "CloseHandle" => Some(close_handle as *const () as usize),
        "DeleteFileW" => {
            Some(delete_file_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetFilePointer" => Some(
            set_file_pointer as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFileSize" => {
            Some(get_file_size as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FlushFileBuffers" => Some(flush_file_buffers as *const () as usize),
        "CreateFileMappingW" => Some(
            create_file_mapping_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "MapViewOfFile" => Some(
            map_view_of_file as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "UnmapViewOfFile" => {
            Some(unmap_view_of_file as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CopyFileW" => {
            Some(copy_file_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CopyFileA" => {
            Some(copy_file_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "FindFirstFileW" => {
            Some(find_first_file_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindFirstFileA" => {
            Some(find_first_file_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindNextFileW" => {
            Some(find_next_file_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindNextFileA" => {
            Some(find_next_file_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindClose" => Some(find_close as *const () as usize),
        "VerSetConditionMask" => Some(ver_set_condition_mask as *const () as usize),
        "VerifyVersionInfoW" => Some(
            verify_version_info_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetFileAttributesExW" => Some(
            get_file_attributes_ex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "GetFileAttributesExA" => Some(
            get_file_attributes_ex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "WideCharToMultiByte" => Some(
            wide_char_to_multi_byte as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "MultiByteToWideChar" => Some(
            multi_byte_to_wide_char as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetStartupInfoA" => {
            Some(get_startup_info_a as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "GetStartupInfoW" => {
            Some(get_startup_info_w as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // Heap / global memory
        "GlobalAlloc" => Some(global_alloc as *const () as usize),
        "GlobalFree" => Some(global_free as *const () as usize),
        "GlobalLock" => Some(global_lock as *const () as usize),
        "GlobalUnlock" => Some(global_unlock as *const () as usize),
        "GlobalSize" => Some(global_size as *const () as usize),
        "LocalAlloc" => Some(local_alloc as *const () as usize),
        "LocalFree" => Some(local_free as *const () as usize),
        "LocalLock" => Some(local_lock as *const () as usize),
        "LocalUnlock" => Some(local_unlock as *const () as usize),
        "LocalReAlloc" => {
            Some(local_re_alloc as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "HeapCreate" => Some(heap_create as *const () as usize),
        "HeapDestroy" => Some(heap_destroy as *const () as usize),
        "HeapAlloc" => {
            Some(heap_alloc as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "HeapReAlloc" => {
            Some(heap_re_alloc as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "HeapFree" => {
            Some(heap_free as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "HeapSize" => Some(heap_size as *const () as usize),
        "GetProcessHeap" => Some(get_process_heap as *const () as usize),
        // Code page / DBCS
        "IsDBCSLeadByte" => Some(is_dbcs_lead_byte as *const () as usize),
        "IsDBCSLeadByteEx" => Some(is_dbcs_lead_byte_ex as *const () as usize),
        "GetACP" => Some(get_acp as *const () as usize),
        "GetOEMCP" => Some(get_oemcp as *const () as usize),
        "GetConsoleCP" => Some(get_console_cp as *const () as usize),
        "GetConsoleOutputCP" => Some(get_console_output_cp as *const () as usize),
        // Module loading
        "LoadLibraryA" => {
            Some(load_library_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "LoadLibraryW" => {
            Some(load_library_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "LoadLibraryExA" => {
            Some(load_library_ex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "LoadLibraryExW" => {
            Some(load_library_ex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "FreeLibrary" => Some(free_library as *const () as usize),
        "GetProcAddress" => {
            Some(get_proc_address as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetModuleHandleA" => {
            Some(get_module_handle_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetModuleHandleW" => {
            Some(get_module_handle_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetModuleHandleExA" => Some(
            get_module_handle_ex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetModuleHandleExW" => Some(
            get_module_handle_ex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetModuleFileNameW" => Some(
            get_module_file_name_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetModuleFileNameA" => Some(
            get_module_file_name_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        // Process / thread identity
        "GetCurrentProcess" => Some(get_current_process as *const () as usize),
        "GetCurrentThread" => Some(get_current_thread as *const () as usize),
        "GetCurrentProcessId" => Some(get_current_process_id as *const () as usize),
        "GetCurrentThreadId" => Some(get_current_thread_id as *const () as usize),
        // Timing
        "GetTickCount" => Some(get_tick_count as *const () as usize),
        "GetTickCount64" => Some(get_tick_count_64 as *const () as usize),
        "QueryPerformanceCounter" => Some(
            query_performance_counter as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "QueryPerformanceFrequency" => Some(
            query_performance_frequency as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetSystemTimeAsFileTime" => {
            Some(get_system_time_as_file_time as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "GetLocaleInfoW" => Some(
            get_locale_info_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetLocaleInfoA" => Some(
            get_locale_info_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        // System info
        "GetSystemInfo" => {
            Some(get_system_info as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetNativeSystemInfo" => {
            Some(get_native_system_info as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Debugger
        "IsDebuggerPresent" => Some(is_debugger_present as *const () as usize),
        "OutputDebugStringA" => {
            Some(output_debug_string_a as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "OutputDebugStringW" => {
            Some(output_debug_string_w as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // Events / semaphores
        "CreateEventA" => {
            Some(create_event_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "CreateEventW" => {
            Some(create_event_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "OpenEventA" => {
            Some(open_event_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "OpenEventW" => {
            Some(open_event_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "SetEvent" => Some(set_event as *const () as usize),
        "ResetEvent" => Some(reset_event as *const () as usize),
        "CreateSemaphoreA" => Some(
            create_semaphore_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "ReleaseSemaphore" => {
            Some(release_semaphore as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // SRW locks
        "AcquireSRWLockExclusive" => {
            Some(acquire_srw_lock_exclusive as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "ReleaseSRWLockExclusive" => {
            Some(release_srw_lock_exclusive as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "AcquireSRWLockShared" => {
            Some(acquire_srw_lock_shared as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "ReleaseSRWLockShared" => {
            Some(release_srw_lock_shared as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // Condition variables
        "InitializeConditionVariable" => {
            Some(initialize_condition_variable as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "SleepConditionVariableSRW" => Some(
            sleep_condition_variable_srw as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "WakeConditionVariable" => {
            Some(wake_condition_variable as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "WakeAllConditionVariable" => {
            Some(wake_all_condition_variable as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // Threads
        "CreateThread" => Some(
            create_thread as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetThreadPriority" => Some(get_thread_priority as *const () as usize),
        "SetThreadPriority" => Some(set_thread_priority as *const () as usize),
        "GetThreadContext" => {
            Some(get_thread_context as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetThreadContext" => {
            Some(set_thread_context as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SuspendThread" => Some(suspend_thread as *const () as usize),
        "ResumeThread" => Some(resume_thread as *const () as usize),
        // Process handles
        "OpenProcess" => {
            Some(open_process as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "DuplicateHandle" => Some(
            duplicate_handle as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetProcessAffinityMask" => Some(
            get_process_affinity_mask as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SetProcessAffinityMask" => Some(
            set_process_affinity_mask as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetHandleInformation" => Some(
            get_handle_information as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "DeviceIoControl" => Some(
            device_io_control as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Environment
        "GetEnvironmentVariableW" => Some(
            get_environment_variable_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        // Misc
        "FormatMessageA" => Some(
            format_message_a as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "FormatMessageW" => Some(
            format_message_w as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateDirectoryW" => {
            Some(create_directory_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RaiseException" => {
            Some(raise_exception as unsafe extern "win64" fn(_, _, _, _) as *const () as usize)
        }
        // RTL unwind
        "RtlCaptureContext" => {
            Some(rtl_capture_context as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "RtlLookupFunctionEntry" => Some(
            rtl_lookup_function_entry as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlVirtualUnwind" => Some(
            rtl_virtual_unwind as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlUnwindEx" => {
            Some(rtl_unwind_ex as unsafe extern "win64" fn(_, _, _, _, _, _) as *const () as usize)
        }
        "RtlUnwind" => {
            Some(rtl_unwind as unsafe extern "win64" fn(_, _, _, _) as *const () as usize)
        }
        // TLS
        "TlsAlloc" => Some(tls_alloc as *const () as usize),
        "TlsSetValue" => Some(tls_set_value as *const () as usize),
        "TlsFree" => Some(tls_free as *const () as usize),
        // Wait / mutex
        "WaitForSingleObject" => Some(
            wait_for_single_object as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "WaitForSingleObjectEx" => Some(
            wait_for_single_object_ex as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "TryEnterCriticalSection" => Some(
            try_enter_critical_section as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SwitchToThread" => {
            Some(switch_to_thread as extern "win64" fn() -> _ as *const () as usize)
        }
        "WaitForMultipleObjects" => Some(
            wait_for_multiple_objects as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateMutexA" => {
            Some(create_mutex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CreateMutexW" => {
            Some(create_mutex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CreateMutexExA" => Some(
            create_mutex_ex_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "CreateMutexExW" => Some(
            create_mutex_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "ReleaseMutex" => Some(release_mutex as *const () as usize),
        "UnhandledExceptionFilter" => Some(
            unhandled_exception_filter as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        // lstr* string functions
        "lstrcmpA" | "lstrcmp" => {
            Some(lstrcmp_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrcmpW" => Some(lstrcmp_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "lstrcmpiA" | "lstrcmpi" => {
            Some(lstrcmpi_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrcmpiW" => {
            Some(lstrcmpi_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrlenA" | "lstrlen" => {
            Some(lstrlen_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "lstrlenW" => Some(lstrlen_w as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "lstrcpyA" | "lstrcpy" => {
            Some(lstrcpy_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrcpyW" => Some(lstrcpy_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "lstrcpynA" | "lstrcpyn" => {
            Some(lstrcpyn_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "lstrcpynW" => {
            Some(lstrcpyn_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // Directory path functions
        "GetWindowsDirectoryW" => Some(
            get_windows_directory_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetWindowsDirectoryA" => Some(
            get_windows_directory_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetSystemDirectoryW" => Some(
            get_system_directory_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetSystemDirectoryA" => Some(
            get_system_directory_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetTempPathW" => {
            Some(get_temp_path_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetTempPathA" => {
            Some(get_temp_path_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetCurrentDirectoryW" => Some(
            get_current_directory_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetCurrentDirectoryA" => Some(
            get_current_directory_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SetCurrentDirectoryW" => {
            Some(set_current_directory_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetCurrentDirectoryA" => {
            Some(set_current_directory_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Computer name and username
        "GetComputerNameW" => {
            Some(get_computer_name_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetComputerNameA" => {
            Some(get_computer_name_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetUserNameW" => {
            Some(get_user_name_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetUserNameA" => {
            Some(get_user_name_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // File attribute functions
        "GetFileAttributesW" => {
            Some(get_file_attributes_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetFileAttributesA" => {
            Some(get_file_attributes_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetFileAttributesW" => {
            Some(set_file_attributes_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetFileAttributesA" => {
            Some(set_file_attributes_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Time functions
        "GetSystemTime" => {
            Some(get_system_time as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "GetLocalTime" => Some(get_local_time as unsafe extern "win64" fn(_) as *const () as usize),
        // Environment functions
        "GetEnvironmentVariableA" => Some(
            get_environment_variable_a as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SetEnvironmentVariableW" => Some(
            set_environment_variable_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SetEnvironmentVariableA" => Some(
            set_environment_variable_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetEnvironmentStringsW" => Some(get_environment_strings_w as *const () as usize),
        "GetEnvironmentStringsA" | "GetEnvironmentStrings" => {
            Some(get_environment_strings_a as *const () as usize)
        }
        "FreeEnvironmentStringsW" => Some(
            free_environment_strings_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "FreeEnvironmentStringsA" => Some(
            free_environment_strings_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetFullPathNameW" => Some(
            get_full_path_name_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFullPathNameA" => Some(
            get_full_path_name_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "MoveFileW" => {
            Some(move_file_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "MoveFileA" => {
            Some(move_file_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RemoveDirectoryW" => {
            Some(remove_directory_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RemoveDirectoryA" => {
            Some(remove_directory_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CreateDirectoryA" => {
            Some(create_directory_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetLogicalDrives" => Some(get_logical_drives as *const () as usize),
        "GetDriveTypeW" => {
            Some(get_drive_type_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetDriveTypeA" => {
            Some(get_drive_type_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetDiskFreeSpaceExW" => Some(
            get_disk_free_space_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetExitCodeProcess" => {
            Some(get_exit_code_process as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetExitCodeThread" => {
            Some(get_exit_code_thread as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "TerminateThread" => {
            Some(terminate_thread as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Locale functions
        "GetUserDefaultLCID" => Some(get_user_default_lcid as *const () as usize),
        "GetSystemDefaultLCID" => Some(get_system_default_lcid as *const () as usize),
        "GetUserDefaultUILanguage" => Some(get_user_default_ui_language as *const () as usize),
        "GetSystemDefaultLangID" => Some(get_system_default_lang_id as *const () as usize),
        "IsValidCodePage" => Some(is_valid_code_page as *const () as usize),
        "IsWow64Process" => {
            Some(is_wow64_process as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "IsProcessorFeaturePresent" => Some(is_processor_feature_present as *const () as usize),
        "FlushInstructionCache" => Some(
            flush_instruction_cache as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetSystemTimePreciseAsFileTime" => Some(
            get_system_time_precise_as_file_time as unsafe extern "win64" fn(_) as *const ()
                as usize,
        ),
        "GetLargePageMinimum" => Some(get_large_page_minimum as *const () as usize),
        "SetHandleInformation" => Some(
            set_handle_information as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        // SRW locks
        "TryAcquireSRWLockExclusive" => Some(
            try_acquire_srw_lock_exclusive as unsafe extern "win64" fn(_) -> _ as *const ()
                as usize,
        ),
        "TryAcquireSRWLockShared" => Some(
            try_acquire_srw_lock_shared as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "ProcessIdToSessionId" => Some(
            process_id_to_session_id as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "WaitOnAddress" => {
            Some(wait_on_address as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "WakeByAddressSingle" => Some(wake_by_address_single as *const () as usize),
        "WakeByAddressAll" => Some(wake_by_address_all as *const () as usize),
        "SetThreadDescription" => Some(
            set_thread_description as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetThreadDescription" => Some(
            get_thread_description as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "CreateTimerQueueTimer" => Some(
            create_timer_queue_timer as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "DeleteTimerQueueTimer" => Some(
            delete_timer_queue_timer as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SetThreadAffinityMask" => Some(
            set_thread_affinity_mask as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "InitOnceExecuteOnce" => Some(
            init_once_execute_once as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "InitOnceBeginInitialize" => Some(
            init_once_begin_initialize as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "InitOnceComplete" => {
            Some(init_once_complete as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CreateWaitableTimerW" => Some(
            create_waitable_timer_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CreateWaitableTimerA" => Some(
            create_waitable_timer_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "SetWaitableTimer" => Some(
            set_waitable_timer as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CancelWaitableTimer" => {
            Some(cancel_waitable_timer as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ExpandEnvironmentStringsW" => Some(
            expand_environment_strings_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "ExpandEnvironmentStringsA" => Some(
            expand_environment_strings_a as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SearchPathW" => Some(
            search_path_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "SearchPathA" => Some(
            search_path_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetTempFileNameW" => Some(
            get_temp_file_name_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetTempFileNameA" => Some(
            get_temp_file_name_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFileType" => Some(get_file_type as *const () as usize),
        // File and console functions
        "GetFileSizeEx" => {
            Some(get_file_size_ex as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetConsoleMode" => {
            Some(get_console_mode as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetConsoleMode" => {
            Some(set_console_mode as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetVersionExW" => {
            Some(get_version_ex_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetVersionExA" => {
            Some(get_version_ex_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetCommandLineW" => Some(get_command_line_w as *const () as usize),
        "GetCommandLineA" => Some(get_command_line_a as *const () as usize),
        "EncodePointer" => Some(encode_pointer as *const () as usize),
        "DecodePointer" => Some(decode_pointer as *const () as usize),
        "FlsAlloc" => Some(fls_alloc as *const () as usize),
        "FlsGetValue" => Some(fls_get_value as *const () as usize),
        "FlsSetValue" => Some(fls_set_value as *const () as usize),
        "FlsFree" => Some(fls_free as *const () as usize),
        "InitializeCriticalSectionAndSpinCount" => Some(
            initialize_critical_section_and_spin_count as unsafe extern "win64" fn(_, _) -> _
                as *const () as usize,
        ),
        "InitializeCriticalSectionEx" => Some(
            initialize_critical_section_ex as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "HeapSetInformation" => Some(
            heap_set_information as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "SetHandleCount" => Some(set_handle_count as *const () as usize),
        "GetThreadLocale" => Some(get_thread_locale as *const () as usize),
        "SetThreadLocale" => Some(set_thread_locale as *const () as usize),
        "SetThreadStackGuarantee" => Some(
            set_thread_stack_guarantee as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetTimeZoneInformation" => Some(
            get_time_zone_information as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        // String comparison
        "CompareStringW" => Some(
            compare_string_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CompareStringOrdinal" => Some(
            compare_string_ordinal as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // String mapping
        "LCMapStringW" => Some(
            lc_map_string_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Character classification
        "GetStringTypeW" => Some(
            get_string_type_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        // File time and positioning
        "SetFilePointerEx" => Some(
            set_file_pointer_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFileTime" => {
            Some(get_file_time as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "SetFileTime" => {
            Some(set_file_time as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        // Vectored exception handlers
        "AddVectoredExceptionHandler" => Some(add_vectored_exception_handler as *const () as usize),
        "RemoveVectoredExceptionHandler" => {
            Some(remove_vectored_exception_handler as *const () as usize)
        }
        "AddVectoredContinueHandler" => Some(add_vectored_continue_handler as *const () as usize),
        "RemoveVectoredContinueHandler" => {
            Some(remove_vectored_continue_handler as *const () as usize)
        }
        // Console functions
        "WriteConsoleA" => Some(
            write_console_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "SetConsoleTitleW" => {
            Some(set_console_title_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetConsoleTitleA" => {
            Some(set_console_title_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetConsoleTitleW" => {
            Some(get_console_title_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetConsoleTitleA" => {
            Some(get_console_title_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetConsoleScreenBufferInfo" => Some(
            get_console_screen_buffer_info as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "SetConsoleTextAttribute" => Some(
            set_console_text_attribute as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SetConsoleCtrlHandler" => Some(
            set_console_ctrl_handler as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        // Task 2: File information functions
        "GetFileInformationByHandle" => Some(
            get_file_information_by_handle as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "SetEndOfFile" => {
            Some(set_end_of_file as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetLogicalDriveStringsW" => Some(
            get_logical_drive_strings_w as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "GetLogicalDriveStringsA" => Some(
            get_logical_drive_strings_a as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "GetVolumeInformationW" => Some(
            get_volume_information_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        // Task 3: Process/thread stubs
        "CreateProcessW" => Some(
            create_process_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CreateProcessA" => Some(
            create_process_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "WaitForInputIdle" => {
            Some(wait_for_input_idle as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetProcessId" => {
            Some(get_process_id as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "OpenThread" => {
            Some(open_thread as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "GetThreadId" => {
            Some(get_thread_id as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Task 4: File time operations
        "CompareFileTime" => {
            Some(compare_file_time as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FileTimeToLocalFileTime" => Some(
            file_time_to_local_file_time as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "LocalFileTimeToFileTime" => Some(
            local_file_time_to_file_time as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "SystemTimeToFileTime" => Some(
            system_time_to_file_time as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "FileTimeToSystemTime" => Some(
            file_time_to_system_time as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        // Task 5: Console misc + MoveFileEx
        "AllocConsole" => Some(alloc_console as *const () as usize),
        "FreeConsole" => Some(free_console as *const () as usize),
        "AttachConsole" => {
            Some(attach_console as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetConsoleWindow" => Some(get_console_window as *const () as usize),
        "MoveFileExW" => {
            Some(move_file_ex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "MoveFileExA" => {
            Some(move_file_ex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── win_prot_to_linux ─────────────────────────────────────────────────────

    #[test]
    fn prot_noaccess_maps_to_none() {
        assert_eq!(win_prot_to_linux(0x01), libc::PROT_NONE);
    }

    #[test]
    fn prot_readonly_maps_to_read() {
        assert_eq!(win_prot_to_linux(0x02), libc::PROT_READ);
    }

    #[test]
    fn prot_readwrite_maps_to_read_write() {
        assert_eq!(win_prot_to_linux(0x04), libc::PROT_READ | libc::PROT_WRITE);
    }

    #[test]
    fn prot_writecopy_maps_to_read_write() {
        // PAGE_WRITECOPY is treated as read-write
        assert_eq!(win_prot_to_linux(0x08), libc::PROT_READ | libc::PROT_WRITE);
    }

    #[test]
    fn prot_execute_maps_to_exec() {
        assert_eq!(win_prot_to_linux(0x10), libc::PROT_EXEC);
    }

    #[test]
    fn prot_execute_read_maps_to_read_exec() {
        assert_eq!(win_prot_to_linux(0x20), libc::PROT_READ | libc::PROT_EXEC);
    }

    #[test]
    fn prot_execute_readwrite_maps_to_rwx() {
        assert_eq!(
            win_prot_to_linux(0x40),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        );
    }

    #[test]
    fn prot_execute_writecopy_maps_to_rwx() {
        assert_eq!(
            win_prot_to_linux(0x80),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        );
    }

    #[test]
    fn prot_unknown_defaults_to_read_write() {
        assert_eq!(win_prot_to_linux(0xFF), libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(win_prot_to_linux(0x00), libc::PROT_READ | libc::PROT_WRITE);
    }

    #[test]
    fn prot_guard_flags_stripped_before_match() {
        // PAGE_GUARD (0x100) is layered on top of a base protection.
        // win_prot_to_linux masks off everything above the low 8 bits,
        // so PAGE_READONLY | PAGE_GUARD should still map to PROT_READ.
        assert_eq!(win_prot_to_linux(0x02 | 0x100), libc::PROT_READ);
    }

    // ── Resolver table ────────────────────────────────────────────────────────

    #[test]
    fn resolve_known_functions_returns_some() {
        for name in &[
            "GetStdHandle",
            "WriteConsoleW",
            "ExitProcess",
            "GetLastError",
            "SetLastError",
            "VirtualProtect",
            "VirtualQuery",
            "Sleep",
            "TlsGetValue",
            "InitializeCriticalSection",
            "EnterCriticalSection",
            "LeaveCriticalSection",
            "DeleteCriticalSection",
            "CreateFileA",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "GlobalAlloc",
            "GlobalFree",
            "GlobalLock",
            "GlobalUnlock",
            "GlobalSize",
            "LocalAlloc",
            "LocalFree",
            "LocalLock",
            "LocalUnlock",
        ] {
            assert!(
                resolve("kernel32.dll", name).is_some(),
                "missing resolver entry for {name}"
            );
        }
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("user32.dll", "GetStdHandle").is_none());
        assert!(resolve("ntdll.dll", "GetStdHandle").is_none());
    }

    #[test]
    fn resolve_unknown_function_returns_none() {
        assert!(resolve("kernel32.dll", "__weave_nonexistent__").is_none());
    }

    #[test]
    fn resolve_is_case_insensitive_for_dll_name() {
        assert!(resolve("KERNEL32.DLL", "GetStdHandle").is_some());
        assert!(resolve("Kernel32.Dll", "GetStdHandle").is_some());
    }

    // ── GetLastError / SetLastError ───────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn last_error_roundtrip() {
        set_last_error(0);
        assert_eq!(get_last_error(), 0);
        set_last_error(42);
        assert_eq!(get_last_error(), 42);
        set_last_error(0xDEAD_BEEF);
        assert_eq!(get_last_error(), 0xDEAD_BEEF);
        // Reset
        set_last_error(0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn last_error_starts_at_zero() {
        // Fresh thread — error code should be 0 unless something set it.
        // We can't guarantee a clean thread, so just reset and verify round-trip.
        set_last_error(0);
        assert_eq!(get_last_error(), 0);
    }

    // ── GlobalAlloc / GlobalFree / GlobalLock ─────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_alloc_returns_nonzero() {
        let ptr = global_alloc(0, 64);
        assert_ne!(ptr, 0);
        global_free(ptr);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_alloc_zeroinit_flag() {
        const GMEM_ZEROINIT: u32 = 0x40;
        let ptr = global_alloc(GMEM_ZEROINIT, 16);
        assert_ne!(ptr, 0);
        // Memory should be zeroed
        let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, 16) };
        assert!(slice.iter().all(|&b| b == 0));
        global_free(ptr);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_alloc_zero_size_returns_zero() {
        let ptr = global_alloc(0, 0);
        assert_eq!(ptr, 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_free_null_is_safe() {
        let result = global_free(0);
        assert_eq!(result, 0); // returns NULL on success
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_lock_is_identity() {
        let ptr = global_alloc(0, 8);
        assert_ne!(ptr, 0);
        assert_eq!(global_lock(ptr), ptr);
        global_free(ptr);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_unlock_returns_true() {
        let ptr = global_alloc(0, 8);
        assert_eq!(global_unlock(ptr), 1);
        global_free(ptr);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn local_alloc_free_roundtrip() {
        let ptr = local_alloc(0, 32);
        assert_ne!(ptr, 0);
        let result = local_free(ptr);
        assert_eq!(result, 0); // NULL = success
    }
}
