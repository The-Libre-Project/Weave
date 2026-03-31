//! Phase 0 NT API stubs — the three functions hello_minimal.exe needs.
//!
//! All functions use `extern "win64"` — the Windows x86-64 calling convention.
//! This differs from the Linux System V ABI: the first four integer arguments
//! come in RCX, RDX, R8, R9 (not RDI, RSI, RDX, RCX). Getting this wrong
//! silently corrupts arguments, so every stub here must carry this attribute.

/// Windows UNICODE_STRING — a UTF-16 string with explicit length fields.
/// Layout must match the Windows ABI exactly.
#[repr(C)]
pub struct UnicodeString {
    length: u16,          // byte length, NOT including null terminator
    maximum_length: u16,  // byte length of the buffer
    _pad: u32,
    buffer: *const u16,   // UTF-16 data
}

/// Windows IO_STATUS_BLOCK — NtWriteFile writes its result here.
#[repr(C)]
pub struct IoStatusBlock {
    status: i32,
    _pad: u32,
    information: usize, // bytes written on success
}

/// RtlInitUnicodeString: initialise a UNICODE_STRING from a UTF-16 literal.
///
/// Counts the length of `src`, fills in `dest.length`, `dest.maximum_length`,
/// and `dest.buffer`. A null `src` zeroes out the struct.
pub unsafe extern "win64" fn rtl_init_unicode_string(dest: *mut UnicodeString, src: *const u16) {
    unsafe {
        if src.is_null() {
            (*dest).length = 0;
            (*dest).maximum_length = 0;
            (*dest).buffer = std::ptr::null();
            return;
        }
        let mut len = 0usize;
        while *src.add(len) != 0 {
            len += 1;
        }
        (*dest).length = (len * 2) as u16;
        (*dest).maximum_length = ((len + 1) * 2) as u16;
        (*dest).buffer = src;
    }
}

/// NtWriteFile: write bytes to a file handle.
///
/// Weave maps handle values directly to Linux file descriptors for Phase 0:
/// handle 1 = stdout, handle 2 = stderr.
pub unsafe extern "win64" fn nt_write_file(
    file_handle: usize, // HANDLE — used as Linux fd
    _event: usize,
    _apc_routine: usize,
    _apc_context: usize,
    io_status_block: *mut IoStatusBlock,
    buffer: *const u8,
    length: u32,
    _byte_offset: usize, // PLARGE_INTEGER — ignored (sequential write)
    _key: usize,
) -> i32 {
    let fd = file_handle as i32;
    let n = unsafe { libc::write(fd, buffer as *const libc::c_void, length as usize) };

    if !io_status_block.is_null() {
        unsafe {
            if n < 0 {
                (*io_status_block).status = STATUS_UNSUCCESSFUL;
                (*io_status_block).information = 0;
            } else {
                (*io_status_block).status = STATUS_SUCCESS;
                (*io_status_block).information = n as usize;
            }
        }
    }

    if n < 0 { STATUS_UNSUCCESSFUL } else { STATUS_SUCCESS }
}

/// NtTerminateProcess: exit the current process.
///
/// `process_handle` of 0 (NULL) means the calling process.
/// `exit_status` is passed straight to Linux exit().
pub extern "win64" fn nt_terminate_process(_process_handle: usize, exit_status: i32) -> i32 {
    unsafe { libc::exit(exit_status) }
}

/// Look up a stub address by DLL + function name.
///
/// Returns `None` for anything not yet implemented — the caller decides
/// whether to abort or install an unimplemented-trap stub.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    match (dll.to_ascii_lowercase().as_str(), func) {
        ("ntdll.dll", "RtlInitUnicodeString") => {
            Some(rtl_init_unicode_string as unsafe extern "win64" fn(_, _) as *const () as usize)
        }
        ("ntdll.dll", "NtWriteFile") => {
            Some(nt_write_file as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _ as *const () as usize)
        }
        ("ntdll.dll", "NtTerminateProcess") => {
            Some(nt_terminate_process as *const () as usize)
        }
        _ => None,
    }
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC0000001_u32 as i32;
