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

/// Windows ANSI_STRING — a narrow string with explicit length fields.
#[repr(C)]
pub struct AnsiString {
    length: u16,         // byte length, NOT including null terminator
    maximum_length: u16, // byte capacity of the buffer
    _pad: u32,
    buffer: *mut u8,
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

// ── NT virtual memory helpers ─────────────────────────────────────────────────

/// Convert NT PAGE_* protection flags to Linux PROT_* values.
fn nt_prot_to_linux(protect: u32) -> i32 {
    match protect {
        1 => 0,                                                       // PAGE_NOACCESS → PROT_NONE
        2 => libc::PROT_READ,                                         // PAGE_READONLY
        4 => libc::PROT_READ | libc::PROT_WRITE,                      // PAGE_READWRITE
        0x10 => libc::PROT_EXEC,                                      // PAGE_EXECUTE
        0x20 => libc::PROT_READ | libc::PROT_EXEC,                    // PAGE_EXECUTE_READ
        0x40 => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, // PAGE_EXECUTE_READWRITE
        _ => libc::PROT_READ | libc::PROT_WRITE,
    }
}

const STATUS_NO_MEMORY: u32 = 0xC0000017;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC0000002;

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

// ── RTL heap functions ────────────────────────────────────────────────────────

/// RtlAllocateHeap: allocate memory from the heap.
///
/// Wraps `malloc` with optional zero-initialization when HEAP_ZERO_MEMORY (0x08) is set.
/// Ignores HeapHandle parameter (we use a single global allocator).
///
/// # Safety
/// The returned pointer must be freed with RtlFreeHeap or it will leak.
pub extern "win64" fn rtl_allocate_heap(
    _heap_handle: usize,
    flags: u32,
    size: usize,
) -> *mut std::ffi::c_void {
    if size == 0 {
        return std::ptr::null_mut();
    }
    let zero_memory = (flags & 0x08) != 0; // HEAP_ZERO_MEMORY
    if zero_memory {
        unsafe { libc::calloc(1, size) }
    } else {
        unsafe { libc::malloc(size) }
    }
}

/// RtlFreeHeap: free memory allocated from the heap.
///
/// Wraps `free`. Ignores HeapHandle and Flags parameters.
///
/// # Safety
/// `base_address` must be a valid pointer returned from RtlAllocateHeap/RtlReAllocateHeap or NULL.
pub extern "win64" fn rtl_free_heap(
    _heap_handle: usize,
    _flags: u32,
    base_address: *mut std::ffi::c_void,
) -> u8 {
    if base_address.is_null() {
        return 1; // TRUE
    }
    unsafe { libc::free(base_address) };
    1 // TRUE
}

/// RtlReAllocateHeap: reallocate memory in the heap.
///
/// Wraps `realloc`. Ignores HeapHandle and Flags parameters.
///
/// # Safety
/// `base_address` must be a valid pointer returned from RtlAllocateHeap or NULL.
/// The returned pointer must be freed with RtlFreeHeap or it will leak.
pub extern "win64" fn rtl_re_allocate_heap(
    _heap_handle: usize,
    _flags: u32,
    base_address: *mut std::ffi::c_void,
    size: usize,
) -> *mut std::ffi::c_void {
    unsafe { libc::realloc(base_address, size) }
}

// ── RTL version and error functions ───────────────────────────────────────────

/// Windows RTL_OSVERSIONINFOW structure.
#[repr(C)]
pub struct RtlOsVersionInfoW {
    dw_os_version_info_size: u32,
    dw_major_version: u32,
    dw_minor_version: u32,
    dw_build_number: u32,
    dw_platform_id: u32,
    sz_csd_version: [u16; 128],
}

/// RtlGetVersion: fills an RTL_OSVERSIONINFOW struct with Windows 10 info.
///
/// # Safety
/// `lp_version_information` must be a valid writable pointer to an RtlOsVersionInfoW.
pub unsafe extern "win64" fn rtl_get_version(
    lp_version_information: *mut RtlOsVersionInfoW,
) -> i32 {
    unsafe {
        (*lp_version_information).dw_os_version_info_size =
            std::mem::size_of::<RtlOsVersionInfoW>() as u32;
        (*lp_version_information).dw_major_version = 10;
        (*lp_version_information).dw_minor_version = 0;
        (*lp_version_information).dw_build_number = 19041;
        (*lp_version_information).dw_platform_id = 2; // VER_PLATFORM_WIN32_NT
                                                      // sz_csd_version is already zero-initialized
    }
    STATUS_SUCCESS
}

/// RtlNtStatusToDosError: maps NT status codes to Win32 error codes.
pub extern "win64" fn rtl_nt_status_to_dos_error(status: u32) -> u32 {
    match status {
        0x00000000 => 0,  // STATUS_SUCCESS -> ERROR_SUCCESS
        0xC0000005 => 5,  // STATUS_ACCESS_VIOLATION -> ERROR_ACCESS_DENIED
        0xC0000034 => 2,  // STATUS_OBJECT_NAME_NOT_FOUND -> ERROR_FILE_NOT_FOUND
        0xC000003A => 3,  // STATUS_OBJECT_PATH_NOT_FOUND -> ERROR_PATH_NOT_FOUND
        0xC0000008 => 6,  // STATUS_INVALID_HANDLE -> ERROR_INVALID_HANDLE
        0xC0000017 => 8,  // STATUS_NO_MEMORY -> ERROR_NOT_ENOUGH_MEMORY
        0xC000000D => 87, // STATUS_INVALID_PARAMETER -> ERROR_INVALID_PARAMETER
        _ => 317,         // STATUS_MR_MID_NOT_FOUND -> ERROR_MR_MID_NOT_FOUND
    }
}

// ── RTL string functions ─────────────────────────────────────────────────────

/// RtlInitAnsiString: initialize an ANSI_STRING from a null-terminated C string.
///
/// # Safety
/// `destination_string` must be a valid writable pointer to an AnsiString.
/// `source_string` must be a valid null-terminated UTF-8 string or NULL.
pub unsafe extern "win64" fn rtl_init_ansi_string(
    destination_string: *mut AnsiString,
    source_string: *const u8,
) {
    unsafe {
        if source_string.is_null() {
            (*destination_string).length = 0;
            (*destination_string).maximum_length = 0;
            (*destination_string).buffer = std::ptr::null_mut();
            return;
        }
        let len = libc::strlen(source_string as *const i8) as u16;
        (*destination_string).length = len;
        (*destination_string).maximum_length = len + 1;
        (*destination_string).buffer = source_string as *mut u8;
    }
}

/// RtlCopyUnicodeString: copy a Unicode string with length limits.
///
/// # Safety
/// `destination_string` and `source_string` must be valid pointers.
/// `destination_string.buffer` must have capacity for the copy operation.
pub unsafe extern "win64" fn rtl_copy_unicode_string(
    destination_string: *mut UnicodeString,
    source_string: *const UnicodeString,
) {
    unsafe {
        if source_string.is_null() {
            (*destination_string).length = 0;
            return;
        }
        let src = &*source_string;
        let dst = &mut *destination_string;
        let copy_len = (src.length as usize).min(dst.maximum_length as usize);
        if copy_len > 0 {
            libc::memcpy(
                dst.buffer as *mut libc::c_void,
                src.buffer as *const libc::c_void,
                copy_len,
            );
        }
        dst.length = copy_len as u16;
    }
}

/// RtlEqualUnicodeString: compare two Unicode strings.
///
/// # Safety
/// `string1` and `string2` must be valid pointers to UnicodeString structs.
/// Their buffer pointers must be valid for their respective lengths.
pub unsafe extern "win64" fn rtl_equal_unicode_string(
    string1: *const UnicodeString,
    string2: *const UnicodeString,
    case_insensitive: u8,
) -> u8 {
    unsafe {
        let s1 = &*string1;
        let s2 = &*string2;

        if s1.length != s2.length {
            return 0; // FALSE
        }

        let len = (s1.length / 2) as usize;
        for i in 0..len {
            let mut c1 = *s1.buffer.add(i);
            let mut c2 = *s2.buffer.add(i);

            if case_insensitive != 0 {
                if (c1 as u8).is_ascii_uppercase() {
                    c1 += 32;
                }
                if (c2 as u8).is_ascii_uppercase() {
                    c2 += 32;
                }
            }

            if c1 != c2 {
                return 0; // FALSE
            }
        }

        1 // TRUE
    }
}

/// RtlAnsiStringToUnicodeString: convert ANSI string to Unicode string.
///
/// # Safety
/// `destination_string` and `source_string` must be valid pointers.
/// If `allocate_destination_string` is non-zero, memory will be allocated.
pub unsafe extern "win64" fn rtl_ansi_string_to_unicode_string(
    destination_string: *mut UnicodeString,
    source_string: *const AnsiString,
    allocate_destination_string: u8,
) -> u32 {
    unsafe {
        let src = &*source_string;
        let dst = &mut *destination_string;

        let src_len = src.length as usize;
        let wide_len = src_len * 2;

        if allocate_destination_string != 0 {
            let alloc_size = wide_len + 2; // +2 for null terminator
            let buffer = libc::malloc(alloc_size) as *mut u16;
            if buffer.is_null() {
                return 0xC0000017; // STATUS_NO_MEMORY
            }
            dst.buffer = buffer;
            dst.maximum_length = alloc_size as u16;
        } else {
            if dst.maximum_length < (wide_len + 2) as u16 {
                return 0xC0000023; // STATUS_BUFFER_TOO_SMALL
            }
        }

        // Convert each byte to u16
        let dst_buf = dst.buffer as *mut u16;
        let src_buf = src.buffer;
        for i in 0..src_len {
            *dst_buf.add(i) = *src_buf.add(i) as u16;
        }
        *dst_buf.add(src_len) = 0; // null terminator

        dst.length = wide_len as u16;
        0 // STATUS_SUCCESS
    }
}

/// RtlUnicodeStringToAnsiString: convert Unicode string to ANSI string.
///
/// # Safety
/// `destination_string` and `source_string` must be valid pointers.
/// If `allocate_destination_string` is non-zero, memory will be allocated.
pub unsafe extern "win64" fn rtl_unicode_string_to_ansi_string(
    destination_string: *mut AnsiString,
    source_string: *const UnicodeString,
    allocate_destination_string: u8,
) -> u32 {
    unsafe {
        let src = &*source_string;
        let dst = &mut *destination_string;

        let src_len = (src.length / 2) as usize;
        let narrow_len = src_len;

        if allocate_destination_string != 0 {
            let alloc_size = narrow_len + 1; // +1 for null terminator
            let buffer = libc::malloc(alloc_size);
            if buffer.is_null() {
                return 0xC0000017; // STATUS_NO_MEMORY
            }
            dst.buffer = buffer as *mut u8;
            dst.maximum_length = alloc_size as u16;
        } else {
            if dst.maximum_length < (narrow_len + 1) as u16 {
                return 0xC0000023; // STATUS_BUFFER_TOO_SMALL
            }
        }

        // Convert each u16 to u8 (keep low byte)
        let dst_buf = dst.buffer;
        let src_buf = src.buffer;
        for i in 0..narrow_len {
            *dst_buf.add(i) = *src_buf.add(i) as u8;
        }
        *dst_buf.add(narrow_len) = 0; // null terminator

        dst.length = narrow_len as u16;
        0 // STATUS_SUCCESS
    }
}

/// RtlFreeUnicodeString: free a Unicode string buffer.
///
/// # Safety
/// `unicode_string` must be a valid pointer. If buffer was allocated, it will be freed.
pub unsafe extern "win64" fn rtl_free_unicode_string(unicode_string: *mut UnicodeString) {
    unsafe {
        let us = &mut *unicode_string;
        if !us.buffer.is_null() {
            libc::free(us.buffer as *mut libc::c_void);
        }
        us.length = 0;
        us.maximum_length = 0;
        us.buffer = std::ptr::null();
    }
}

// ── System information functions ─────────────────────────────────────────────

/// NtQuerySystemInformation: stub that returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn nt_query_system_information(
    _system_information_class: u32,
    _system_information: *mut std::ffi::c_void,
    _system_information_length: u32,
    _return_length: *mut u32,
) -> u32 {
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC0000002;
    STATUS_NOT_IMPLEMENTED
}

// ── Process and thread information ───────────────────────────────────────────

/// NtQueryInformationProcess: query process information.
///
/// # Safety
/// If `process_information_class == 0` and length >= 48, writes to `process_information`.
/// If `return_length` is non-null, writes the return length.
pub unsafe extern "win64" fn nt_query_information_process(
    _handle: usize,
    process_information_class: u32,
    process_information: *mut std::ffi::c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> u32 {
    // ProcessBasicInformation = 0, struct size = 48 bytes
    if process_information_class == 0 && process_information_length >= 48 {
        let buf = process_information as *mut u8;
        unsafe {
            std::ptr::write_bytes(buf, 0, 48);
            // Write fake PID at offset 16 (UniqueProcessId field)
            *(buf.add(16) as *mut usize) = 1000;
            if !return_length.is_null() {
                *return_length = 48;
            }
        }
        return 0; // STATUS_SUCCESS
    }
    0xC0000002 // STATUS_NOT_IMPLEMENTED
}

/// NtQueryInformationThread: stub returning STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn nt_query_information_thread(
    _handle: usize,
    _thread_information_class: u32,
    _thread_information: *mut std::ffi::c_void,
    _thread_information_length: u32,
    _return_length: *mut u32,
) -> u32 {
    0xC0000002 // STATUS_NOT_IMPLEMENTED
}

/// RtlCompareUnicodeString: compare two Unicode strings.
///
/// # Safety
/// `string1` and `string2` must be valid pointers to UnicodeString structs.
/// Their buffer pointers must be valid for their respective lengths.
pub unsafe extern "win64" fn rtl_compare_unicode_string(
    string1: *const UnicodeString,
    string2: *const UnicodeString,
    case_insensitive: u8,
) -> i32 {
    unsafe {
        let s1 = &*string1;
        let s2 = &*string2;

        let len1 = (s1.length / 2) as usize;
        let len2 = (s2.length / 2) as usize;
        let min_len = len1.min(len2);

        // Compare char-by-char for min length
        for i in 0..min_len {
            let mut c1 = *s1.buffer.add(i);
            let mut c2 = *s2.buffer.add(i);

            if case_insensitive != 0 {
                if (c1 as u8).is_ascii_uppercase() {
                    c1 += 32; // convert to lowercase
                }
                if (c2 as u8).is_ascii_uppercase() {
                    c2 += 32; // convert to lowercase
                }
            }

            if c1 != c2 {
                return (c1 as i32) - (c2 as i32);
            }
        }

        // If all compared chars are equal, return length difference
        (s1.length as i32) - (s2.length as i32)
    }
}

/// NtYieldExecution: yield the processor to another thread.
pub extern "win64" fn nt_yield_execution() -> u32 {
    unsafe { libc::sched_yield() };
    0 // STATUS_SUCCESS
}

/// NtSetInformationThread: set thread information (stub).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn nt_set_information_thread(
    _thread_handle: usize,
    _thread_information_class: u32,
    _thread_information: *mut std::ffi::c_void,
    _thread_information_length: u32,
) -> u32 {
    0xC0000002 // STATUS_NOT_IMPLEMENTED
}

/// LdrLoadDll: load a DLL into the process address space.
///
/// Phase 2: dynamic loading is not supported; always returns STATUS_DLL_NOT_FOUND.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn ldr_load_dll(
    _path_to_file: *const u16,
    _flags: u32,
    _module_file_name: *const UnicodeString,
    _module_handle: *mut usize,
) -> u32 {
    // Dynamic loading not supported in Phase 2
    const STATUS_DLL_NOT_FOUND: u32 = 0xC0000135;
    STATUS_DLL_NOT_FOUND
}

/// LdrGetProcedureAddress: get the address of a procedure in a loaded DLL.
///
/// Phase 2: dynamic loading is not supported; always returns STATUS_PROCEDURE_NOT_FOUND.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn ldr_get_procedure_address(
    _module_handle: usize,
    _function_name: *const AnsiString,
    _ordinal: u16,
    _function_address: *mut usize,
) -> u32 {
    // Dynamic loading not supported in Phase 2
    const STATUS_PROCEDURE_NOT_FOUND: u32 = 0xC000007A;
    STATUS_PROCEDURE_NOT_FOUND
}

/// NtAllocateVirtualMemory: allocate virtual memory.
///
/// # Safety
/// `base_address` must be a valid pointer to a pointer. `region_size` must be a valid pointer.
pub unsafe extern "win64" fn nt_allocate_virtual_memory(
    _process_handle: usize,
    base_address: *mut *mut u8,
    _zero_bits: usize,
    region_size: *mut usize,
    _allocation_type: u32,
    protect: u32,
) -> u32 {
    unsafe {
        if base_address.is_null() || region_size.is_null() {
            return 0u32; // STATUS_SUCCESS
        }

        let prot = nt_prot_to_linux(protect);
        const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;

        let result = if (*base_address).is_null() {
            libc::mmap(
                std::ptr::null_mut(),
                *region_size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        } else {
            libc::mmap(
                *base_address as *mut libc::c_void,
                *region_size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };

        if result == libc::MAP_FAILED {
            STATUS_NO_MEMORY
        } else {
            *base_address = result as *mut u8;
            0u32 // STATUS_SUCCESS
        }
    }
}

/// NtFreeVirtualMemory: free virtual memory.
///
/// # Safety
/// `base_address` and `region_size` must be valid pointers.
pub unsafe extern "win64" fn nt_free_virtual_memory(
    _process_handle: usize,
    base_address: *mut *mut u8,
    region_size: *mut usize,
    _free_type: u32,
) -> u32 {
    unsafe {
        if base_address.is_null() || region_size.is_null() {
            return 0u32; // STATUS_SUCCESS
        }
        libc::munmap(*base_address as *mut libc::c_void, *region_size);
        0u32 // STATUS_SUCCESS
    }
}

/// NtProtectVirtualMemory: change memory protection.
///
/// # Safety
/// `base_address`, `number_of_bytes_to_protect`, and `old_access_protection` must be valid pointers.
pub unsafe extern "win64" fn nt_protect_virtual_memory(
    _process_handle: usize,
    base_address: *mut *mut u8,
    number_of_bytes_to_protect: *mut usize,
    new_access_protection: u32,
    old_access_protection: *mut u32,
) -> u32 {
    unsafe {
        if !old_access_protection.is_null() {
            *old_access_protection = 0x40; // PAGE_EXECUTE_READWRITE
        }

        if base_address.is_null() || number_of_bytes_to_protect.is_null() {
            return 0u32; // STATUS_SUCCESS
        }

        let prot = nt_prot_to_linux(new_access_protection);
        libc::mprotect(
            *base_address as *mut libc::c_void,
            *number_of_bytes_to_protect,
            prot,
        );
        0u32 // STATUS_SUCCESS
    }
}

/// NtQueryVirtualMemory: query virtual memory information (stub).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn nt_query_virtual_memory(
    _process_handle: usize,
    _base_address: *const u8,
    _memory_information_class: u32,
    _memory_information: *mut u8,
    _memory_information_length: usize,
    _return_length: *mut usize,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
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
        // RTL heap functions
        "RtlAllocateHeap" => {
            Some(rtl_allocate_heap as extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "RtlFreeHeap" => {
            Some(rtl_free_heap as extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "RtlReAllocateHeap" => {
            Some(rtl_re_allocate_heap as extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        // RTL version and error functions
        "RtlGetVersion" => {
            Some(rtl_get_version as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RtlNtStatusToDosError" => {
            Some(rtl_nt_status_to_dos_error as extern "win64" fn(_) -> _ as *const () as usize)
        }
        // RTL string functions
        "RtlInitAnsiString" => {
            Some(rtl_init_ansi_string as unsafe extern "win64" fn(_, _) as *const () as usize)
        }
        "RtlCopyUnicodeString" => {
            Some(rtl_copy_unicode_string as unsafe extern "win64" fn(_, _) as *const () as usize)
        }
        "RtlEqualUnicodeString" => Some(
            rtl_equal_unicode_string as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlAnsiStringToUnicodeString" => Some(
            rtl_ansi_string_to_unicode_string as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlUnicodeStringToAnsiString" => Some(
            rtl_unicode_string_to_ansi_string as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlFreeUnicodeString" => {
            Some(rtl_free_unicode_string as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // System information functions
        "NtQuerySystemInformation" => Some(
            nt_query_system_information as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Process and thread information
        "NtQueryInformationProcess" => Some(
            nt_query_information_process as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        "NtQueryInformationThread" => Some(
            nt_query_information_thread as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlCompareUnicodeString" => Some(
            rtl_compare_unicode_string as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "NtYieldExecution" => Some(nt_yield_execution as *const () as usize),
        "NtSetInformationThread" => Some(
            nt_set_information_thread as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "LdrLoadDll" => {
            Some(ldr_load_dll as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "LdrGetProcedureAddress" => Some(
            ldr_get_procedure_address as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        // NT virtual memory functions
        "NtAllocateVirtualMemory" => Some(
            nt_allocate_virtual_memory as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "NtFreeVirtualMemory" => Some(
            nt_free_virtual_memory as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "NtProtectVirtualMemory" => Some(
            nt_protect_virtual_memory as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "NtQueryVirtualMemory" => Some(
            nt_query_virtual_memory as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        _ => None,
    }
}
