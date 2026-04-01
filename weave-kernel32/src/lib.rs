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

// ── File I/O ──────────────────────────────────────────────────────────────────

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
        while *lp_file_name.add(len) != 0 {
            len += 1;
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
        while *lp_file_name.add(len) != 0 {
            len += 1;
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
        while unsafe { *lp_wide_char_str.add(len) } != 0 {
            len += 1;
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
        while unsafe { *lp_multi_byte_str.add(len) } != 0 {
            len += 1;
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
        // Code page / DBCS
        "IsDBCSLeadByte" => Some(is_dbcs_lead_byte as *const () as usize),
        "IsDBCSLeadByteEx" => Some(is_dbcs_lead_byte_ex as *const () as usize),
        "GetACP" => Some(get_acp as *const () as usize),
        "GetOEMCP" => Some(get_oemcp as *const () as usize),
        "GetConsoleCP" => Some(get_console_cp as *const () as usize),
        "GetConsoleOutputCP" => Some(get_console_output_cp as *const () as usize),
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
