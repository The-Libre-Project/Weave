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

/// DuplicateHandle — returns FALSE (not supported).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn duplicate_handle(
    _h_source_process: usize,
    _h_source_handle: usize,
    _h_target_process: usize,
    _lp_target_handle: *mut usize,
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _dw_options: u32,
) -> i32 {
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
