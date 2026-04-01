//! ntdll.dll stubs for Weave.
//!
//! All functions use `extern "win64"` — the Windows x86-64 calling convention.
//! This differs from the Linux System V ABI: the first four integer arguments
//! come in RCX, RDX, R8, R9 (not RDI, RSI, RDX, RCX). Getting this wrong
//! silently corrupts arguments, so every stub here must carry this attribute.

use weave_common::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use weave_core::{file_io, handles};

// ── Windows NT structures ─────────────────────────────────────────────────────

/// Windows UNICODE_STRING — a UTF-16 string with explicit length fields.
/// Layout must match the Windows ABI exactly.
#[repr(C)]
pub struct UnicodeString {
    length: u16,         // byte length, NOT including null terminator
    maximum_length: u16, // byte capacity of the buffer
    _pad: u32,
    buffer: *const u16, // UTF-16 data
}

impl UnicodeString {
    /// Decode the buffer to a Rust `String`. Returns `None` if the pointer is null.
    ///
    /// # Safety
    /// `buffer` must be valid for `length / 2` UTF-16 code units.
    unsafe fn to_string(&self) -> Option<String> {
        if self.buffer.is_null() {
            return None;
        }
        let count = (self.length / 2) as usize;
        let slice = unsafe { std::slice::from_raw_parts(self.buffer, count) };
        Some(String::from_utf16_lossy(slice))
    }
}

/// Windows IO_STATUS_BLOCK — NtWriteFile/NtReadFile write their result here.
#[repr(C)]
pub struct IoStatusBlock {
    status: i32,
    _pad: u32,
    information: usize, // bytes transferred on success
}

/// Windows OBJECT_ATTRIBUTES — passed to NtCreateFile to specify the target
/// path and object flags. Layout for 64-bit Windows (48 bytes total).
#[repr(C)]
pub struct ObjectAttributes {
    length: u32,                       // offset 0  — must be sizeof(OBJECT_ATTRIBUTES)
    _pad0: u32,                        // offset 4  — alignment padding
    root_directory: usize,             // offset 8  — optional root directory handle
    object_name: *const UnicodeString, // offset 16 — the file path
    attributes: u32,                   // offset 24 — OBJ_CASE_INSENSITIVE etc.
    _pad1: u32,                        // offset 28 — alignment padding
    _security_descriptor: usize,       // offset 32
    _security_qos: usize,              // offset 40
} // total: 48 bytes

// ── RtlInitUnicodeString ──────────────────────────────────────────────────────

/// RtlInitUnicodeString: initialise a UNICODE_STRING from a UTF-16 literal.
///
/// # Safety
/// `dest` must be a valid, non-null pointer to a `UnicodeString`. `src`, if
/// non-null, must point to a null-terminated UTF-16 string.
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

// ── NtCreateFile ─────────────────────────────────────────────────────────────

/// NtCreateFile: open or create a file.
///
/// This is the NT-level file open function. `CreateFileW` in kernel32 is a
/// thin wrapper over this function (via Weave's internal `file_io` module).
///
/// # Safety
/// `file_handle` must be a valid, writable pointer. `object_attrs` must be a
/// valid `ObjectAttributes` with a non-null `object_name` pointer.
pub unsafe extern "win64" fn nt_create_file(
    file_handle: *mut usize, // out: receives the new handle
    desired_access: u32,     // ACCESS_MASK: GENERIC_READ / GENERIC_WRITE / …
    object_attrs: *const ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    _allocation_size: usize, // ignored for Phase 2
    _file_attributes: u32,   // ignored (always use 0o666 on Linux)
    _share_access: u32,      // ignored (Phase 2: no locking)
    create_disposition: u32, // FILE_OPEN, FILE_CREATE, …
    _create_options: u32,    // ignored for Phase 2
    _ea_buffer: usize,       // ignored (extended attributes)
    _ea_length: u32,
) -> i32 {
    if file_handle.is_null() || object_attrs.is_null() {
        return STATUS_UNSUCCESSFUL;
    }

    // Extract the path from ObjectAttributes.object_name (UNICODE_STRING).
    let win_path = unsafe {
        let oa = &*object_attrs;
        if oa.object_name.is_null() {
            return STATUS_UNSUCCESSFUL;
        }
        match (*oa.object_name).to_string() {
            Some(p) => p,
            None => return STATUS_UNSUCCESSFUL,
        }
    };

    match file_io::open_file(&win_path, desired_access, create_disposition) {
        Ok(handle) => {
            unsafe { *file_handle = handle };
            if !io_status_block.is_null() {
                unsafe {
                    (*io_status_block).status = STATUS_SUCCESS;
                    // FILE_OPENED (1) or FILE_CREATED (2) — report FILE_OPENED for now.
                    (*io_status_block).information = 1;
                }
            }
            STATUS_SUCCESS
        }
        Err(status) => {
            if !io_status_block.is_null() {
                unsafe {
                    (*io_status_block).status = status;
                    (*io_status_block).information = 0;
                }
            }
            status
        }
    }
}

// ── NtReadFile ────────────────────────────────────────────────────────────────

/// NtReadFile: read bytes from a file handle.
///
/// # Safety
/// `buffer` must be valid for `length` bytes. `io_status_block`, if non-null,
/// must point to a valid `IoStatusBlock`.
pub unsafe extern "win64" fn nt_read_file(
    file_handle: usize,
    _event: usize,
    _apc_routine: usize,
    _apc_context: usize,
    io_status_block: *mut IoStatusBlock,
    buffer: *mut u8,
    length: u32,
    _byte_offset: usize,
    _key: usize,
) -> i32 {
    let fd = match handles::get_fd(file_handle) {
        Some(fd) => fd,
        None => return STATUS_UNSUCCESSFUL,
    };

    let n = unsafe { libc::read(fd, buffer as *mut libc::c_void, length as usize) };

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

    if n < 0 {
        STATUS_UNSUCCESSFUL
    } else {
        STATUS_SUCCESS
    }
}

// ── NtWriteFile ───────────────────────────────────────────────────────────────

/// NtWriteFile: write bytes to a file handle.
///
/// The handle is looked up in the global HANDLE table. Handles 4/5/6 map to
/// stdin/stdout/stderr (Linux fds 0/1/2).
///
/// # Safety
/// `buffer` must be valid for `length` bytes. `io_status_block`, if non-null,
/// must point to a valid `IoStatusBlock`.
pub unsafe extern "win64" fn nt_write_file(
    file_handle: usize,
    _event: usize,
    _apc_routine: usize,
    _apc_context: usize,
    io_status_block: *mut IoStatusBlock,
    buffer: *const u8,
    length: u32,
    _byte_offset: usize,
    _key: usize,
) -> i32 {
    let fd = match handles::get_fd(file_handle) {
        Some(fd) => fd,
        None => return STATUS_UNSUCCESSFUL,
    };

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

    if n < 0 {
        STATUS_UNSUCCESSFUL
    } else {
        STATUS_SUCCESS
    }
}

// ── NtClose ───────────────────────────────────────────────────────────────────

/// NtClose: close an open handle and release its kernel object.
///
/// Closing stdin/stdout/stderr (handles 4/5/6) returns STATUS_UNSUCCESSFUL —
/// those handles are protected.
pub extern "win64" fn nt_close(handle: usize) -> i32 {
    match file_io::close_handle(handle) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

// ── NtTerminateProcess ────────────────────────────────────────────────────────

/// NtTerminateProcess: exit the current process.
///
/// `process_handle` of 0 (NULL) means the calling process.
pub extern "win64" fn nt_terminate_process(_process_handle: usize, exit_status: i32) -> i32 {
    unsafe { libc::exit(exit_status) }
}

// ── Resolver ──────────────────────────────────────────────────────────────────

pub fn resolve(func: &str) -> Option<usize> {
    match func {
        "RtlInitUnicodeString" => {
            Some(rtl_init_unicode_string as unsafe extern "win64" fn(_, _) as *const () as usize)
        }
        "NtCreateFile" => Some(
            nt_create_file as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "NtReadFile" => Some(
            nt_read_file as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "NtWriteFile" => Some(
            nt_write_file as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "NtClose" => Some(nt_close as *const () as usize),
        "NtTerminateProcess" => Some(nt_terminate_process as *const () as usize),
        _ => None,
    }
}
