//! ntdll.dll stubs for Weave.
//!
//! All functions use `extern "win64"` — the Windows x86-64 calling convention.
//! This differs from the Linux System V ABI: the first four integer arguments
//! come in RCX, RDX, R8, R9 (not RDI, RSI, RDX, RCX). Getting this wrong
//! silently corrupts arguments, so every stub here must carry this attribute.

use std::sync::atomic::{AtomicUsize, Ordering};
use weave_common::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use weave_core::{file_io, handles};

// ── Task 3 — NT timing + shutdown flag ───────────────────────────────────────

/// RtlDllShutdownInProgress: check if DLL shutdown is in progress.
///
/// Return 0 (process is not shutting down). No parameters. Not `unsafe`.
// Wine ref: dlls/ntdll/loader.c:3815 — reads a static `process_detaching` bool set during
// DLL unload phase; returns TRUE only after process shutdown has been initiated.
pub extern "win64" fn rtl_dll_shutdown_in_progress() -> u8 {
    0
}

/// NtQueryPerformanceCounter: get performance counter and frequency.
///
/// Fill `*performance_counter` with a monotonic 100-ns tick count using `clock_gettime(CLOCK_MONOTONIC)`.
/// If `performance_frequency` is non-null, write `10_000_000i64` to it.
/// Return `0u32` (STATUS_SUCCESS). Mark `unsafe`.
///
/// # Safety
/// `performance_counter` and `performance_frequency` must be valid pointers or NULL.
// Wine ref: ReactOS ntoskrnl/ex/profile.c:278 — calls KeQueryPerformanceCounter internally;
// probes both output pointers in SEH before writing; raises the exception code (not
// STATUS_INVALID_PARAMETER) if the pointer access faults.
pub unsafe extern "win64" fn nt_query_performance_counter(
    performance_counter: *mut i64,
    performance_frequency: *mut i64,
) -> u32 {
    if !performance_counter.is_null() {
        let mut ts = unsafe { std::mem::zeroed::<libc::timespec>() };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        let counter = ts.tv_sec * 10_000_000 + ts.tv_nsec / 100;
        unsafe { *performance_counter = counter };
    }

    if !performance_frequency.is_null() {
        unsafe { *performance_frequency = 10_000_000i64 };
    }

    0u32 // STATUS_SUCCESS
}

/// NtQuerySystemTime: get current system time.
///
/// Fill `*system_time` with current UTC as 100-ns intervals since 1601-01-01, using
/// `clock_gettime(CLOCK_REALTIME)`. Return `0u32`. Mark `unsafe`.
///
/// # Safety
/// `system_time` must be a valid writable pointer.
// Wine ref: Wine syscall (ntsyscalls.h) — on real Windows reads from KUSER_SHARED_DATA
// at fixed user-space address 0x7ffe0014 (SystemTime field), avoiding a kernel transition.
// Weave uses clock_gettime(CLOCK_REALTIME) + Windows epoch offset instead.
pub unsafe extern "win64" fn nt_query_system_time(system_time: *mut i64) -> u32 {
    if system_time.is_null() {
        return 0u32;
    }
    let mut ts = unsafe { std::mem::zeroed::<libc::timespec>() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let value = ts.tv_sec * 10_000_000 + ts.tv_nsec / 100 + 116_444_736_000_000_000;
    unsafe { *system_time = value };
    0u32 // STATUS_SUCCESS
}

/// NtDelayExecution: delay execution for a specified interval.
///
/// Yield the CPU once with `libc::sched_yield()`. Do not inspect or dereference
/// `delay_interval` — just yield and return `0u32`. Mark `unsafe`.
///
/// # Safety
/// `delay_interval` is accepted but not dereferenced.
// Wine ref: ReactOS ntoskrnl/ke/wait.c:876 — probes and captures DelayInterval via SEH in
// user mode; delegates to KeDelayExecutionThread(PreviousMode, Alertable, DelayInterval).
// Weave stub yields once then returns immediately — does not honour the interval.
pub unsafe extern "win64" fn nt_delay_execution(
    _alertable: u8,
    _delay_interval: *const i64,
) -> u32 {
    unsafe { libc::sched_yield() };
    0u32 // STATUS_SUCCESS
}

// ── Task 4 — NT event stubs ──────────────────────────────────────────────────

/// Global handle counter for NT event objects.
static NT_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x9000_0000);

fn next_nt_handle() -> usize {
    NT_HANDLE_COUNTER.fetch_add(4, Ordering::Relaxed)
}

/// NtCreateEvent: create an event object.
///
/// Returns a fake handle (incrementing counter). Ignores all parameters.
///
/// # Safety
/// `event_handle` must be a valid writable pointer.
/// Other pointer arguments are accepted but not dereferenced.
// Wine ref: ReactOS ntoskrnl/ex/event.c:96 — validates EventType: only NotificationEvent(0)
// or SynchronizationEvent(1) accepted; returns STATUS_INVALID_PARAMETER for other values.
// Creates KEVENT via ObCreateObject + KeInitializeEvent; Weave returns fake handle, no validation.
pub unsafe extern "win64" fn nt_create_event(
    event_handle: *mut usize,
    _desired_access: u32,
    _object_attributes: usize,
    _event_type: u32,
    _initial_state: u8,
) -> u32 {
    if !event_handle.is_null() {
        unsafe { *event_handle = next_nt_handle() };
    }
    0u32 // STATUS_SUCCESS
}

/// NtOpenEvent: open an existing event object by name.
///
/// Returns a fake handle. Ignores the object name.
///
/// # Safety
/// `event_handle` must be a valid writable pointer or NULL.
// Wine ref: ReactOS ntoskrnl/ex/event.c:185 — opens by name via ObOpenObjectByName;
// returns STATUS_OBJECT_NAME_NOT_FOUND for unknown names. Weave returns fake handle
// with no name lookup or object-manager validation.
pub unsafe extern "win64" fn nt_open_event(
    event_handle: *mut usize,
    _desired_access: u32,
    _object_attributes: usize,
) -> u32 {
    if !event_handle.is_null() {
        unsafe { *event_handle = next_nt_handle() };
    }
    0u32 // STATUS_SUCCESS
}

/// NtClearEvent: clear an event object to the non-signaled state.
///
/// No-op. Returns STATUS_SUCCESS.
///
/// # Safety
/// `_event_handle` is a handle value, not dereferenced.
// Wine ref: ReactOS ntoskrnl/ex/event.c — equivalent to NtResetEvent; looks up handle via
// ObReferenceObjectByHandle with EVENT_MODIFY_STATE; calls KeResetEvent; no previous-state output.
pub unsafe extern "win64" fn nt_clear_event(_event_handle: usize) -> u32 {
    0u32 // STATUS_SUCCESS
}

/// NtPulseEvent: pulse an event object (set then immediately reset).
///
/// No-op. Returns STATUS_SUCCESS.
///
/// # Safety
/// `_event_handle` is a handle value. `previous_state` written if non-null.
// Wine ref: ReactOS ntoskrnl/ex/event.c:247 — calls KePulseEvent with EVENT_INCREMENT boost;
// writes previous state to PreviousState if non-null; invalid handle → STATUS_INVALID_HANDLE.
pub unsafe extern "win64" fn nt_pulse_event(_event_handle: usize, previous_state: *mut i32) -> u32 {
    if !previous_state.is_null() {
        unsafe { *previous_state = 0 };
    }
    0u32 // STATUS_SUCCESS
}

/// NtSetEvent: set an event object to the signaled state.
///
/// No-op. Returns STATUS_SUCCESS.
///
/// # Safety
/// `_event_handle` is accepted but not dereferenced.
// Wine ref: ReactOS ntoskrnl/ex/event.c:450 — calls KeSetEvent with EVENT_INCREMENT priority
// boost; writes previous signaled state to PreviousState if non-null; invalid handle →
// STATUS_INVALID_HANDLE.
pub unsafe extern "win64" fn nt_set_event(_event_handle: usize, _previous_state: *mut u32) -> u32 {
    0u32 // STATUS_SUCCESS
}

/// NtResetEvent: reset an event object to the non-signaled state.
///
/// No-op. Returns STATUS_SUCCESS.
///
/// # Safety
/// `_event_handle` is accepted but not dereferenced.
// Wine ref: ReactOS ntoskrnl/ex/event.c:392 — calls KeResetEvent; writes previous signaled
// state to PreviousState if non-null; invalid handle → STATUS_INVALID_HANDLE.
pub unsafe extern "win64" fn nt_reset_event(
    _event_handle: usize,
    _previous_state: *mut u32,
) -> u32 {
    0u32 // STATUS_SUCCESS
}

/// NtWaitForSingleObject: wait for an object to become signaled.
///
/// No-op. Returns STATUS_SUCCESS (object is always signaled).
///
/// # Safety
/// `_object` is accepted but not dereferenced.
/// `_timeout` is accepted but not dereferenced.
// Wine ref: Wine syscall (ntsyscalls.h) — delegates to KeWaitForSingleObject; returns
// WAIT_OBJECT_0 (0) on signal, WAIT_TIMEOUT (0x102) on timeout, STATUS_ALERTED if alertable
// and APC queued. Weave always returns STATUS_SUCCESS — no real wait.
pub unsafe extern "win64" fn nt_wait_for_single_object(
    _object: usize,
    _alertable: u8,
    _timeout: usize,
) -> u32 {
    0u32 // STATUS_SUCCESS
}

// ── Task 5 — RtlWaitOnAddress family ──────────────────────────────────────────

/// RtlWaitOnAddress: wait for a value at an address to change.
///
/// Stub: immediately return STATUS_SUCCESS (no actual waiting).
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/ntdll/sync.c:878 — size must be 1/2/4/8 else STATUS_INVALID_PARAMETER;
// comparison done inside spinlock to reduce spurious wakeups; delegates to
// NtWaitForAlertByThreadId; maps STATUS_ALERTED → STATUS_SUCCESS on return.
pub unsafe extern "win64" fn rtl_wait_on_address(
    _address: *const u8,
    _compare_address: *const u8,
    _address_size: usize,
    _timeout: usize,
) -> u32 {
    0u32 // STATUS_SUCCESS
}

/// RtlWakeByAddressSingle: wake one thread waiting on an address.
///
/// No-op.
/// # Safety
/// `_address` is accepted but never dereferenced.
// Wine ref: dlls/ntdll/sync.c:967 — no-op if addr==NULL; wakes first matching entry in futex
// queue via NtAlertThreadByThreadId called outside the spinlock to avoid syscall under lock.
pub unsafe extern "win64" fn rtl_wake_by_address_single(_address: usize) {}

/// RtlWakeByAddressAll: wake all threads waiting on an address.
///
/// No-op.
/// # Safety
/// `_address` is accepted but never dereferenced.
// Wine ref: dlls/ntdll/sync.c:930 — no-op if addr==NULL; collects up to 256 TIDs under
// spinlock then calls NtAlertMultipleThreadByThreadId after releasing lock.
pub unsafe extern "win64" fn rtl_wake_by_address_all(_address: usize) {}

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
// Wine ref: dlls/ntdll/rtlstr.c:173 — sets Buffer=src; if src non-null, Length=wcslen*2
// capped at 0xfffc, MaximumLength=Length+2; if src null, all fields zero.
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
        // Wine caps byte length at 0xfffc to avoid overflow in the u16 Length field.
        let byte_len = (len * 2).min(0xfffc);
        (*dest).length = byte_len as u16;
        (*dest).maximum_length = (byte_len + 2) as u16;
        (*dest).buffer = src;
    }
}

// ── NtCreateFile ─────────────────────────────────────────────────────────────

// Wine ref: dlls/ntdll/unix/file.c — NtCreateFile translates OBJECT_ATTRIBUTES.ObjectName
// (a UNICODE_STRING NT path like \??\C:\foo) to a Unix path, opens via open(2) with flags
// derived from DesiredAccess + CreateDisposition, writes FILE_OPENED/FILE_CREATED/FILE_SUPERSEDED
// (1/2/5) into io->Information on success. Returns STATUS_OBJECT_NAME_NOT_FOUND for missing
// files when CreateDisposition==FILE_OPEN, STATUS_ACCESS_DENIED on permission failure.
// Known gap: Weave path translation is simplified (strips \??\ prefix only); CreateDisposition
// values FILE_SUPERSEDE/FILE_OVERWRITE_IF not handled distinctly.
/// NtCreateFile: open or create a file.
///
/// This is the NT-level file open function. `CreateFileW` in kernel32 is a
/// thin wrapper over this function (via Weave's internal `file_io` module).
///
/// # Safety
/// `file_handle` must be a valid, writable pointer. `object_attrs` must be a
/// valid `ObjectAttributes` with a non-null `object_name` pointer.
// Wine ref: dlls/ntdll/unix/file.c — translates ObjectAttributes.ObjectName (NT path \??\C:\foo)
// to Unix path; writes FILE_OPENED(1)/FILE_CREATED(2)/FILE_SUPERSEDED(5) into io->Information;
// returns STATUS_OBJECT_NAME_NOT_FOUND for missing files when CreateDisposition==FILE_OPEN.
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

// Wine ref: dlls/ntdll/unix/file.c:6021 — returns STATUS_ACCESS_VIOLATION (not STATUS_UNSUCCESSFUL)
// when io == NULL; validates buffer with virtual_check_buffer_for_write; writes bytes transferred
// into io->Information on success; returns STATUS_END_OF_FILE (not 0) when read returns 0.
// Known gap: Weave returns STATUS_UNSUCCESSFUL for null io instead of STATUS_ACCESS_VIOLATION;
// STATUS_END_OF_FILE not returned (returns STATUS_UNSUCCESSFUL on read=0).
/// NtReadFile: read bytes from a file handle.
///
/// # Safety
/// `buffer` must be valid for `length` bytes. `io_status_block`, if non-null,
/// must point to a valid `IoStatusBlock`.
// Wine ref: dlls/ntdll/unix/file.c:6021 — returns STATUS_ACCESS_VIOLATION (not STATUS_UNSUCCESSFUL)
// when io==NULL; validates buffer with virtual_check_buffer_for_write; returns STATUS_END_OF_FILE
// (not 0) when read() returns 0 bytes.
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

// Wine ref: dlls/ntdll/unix/file.c:6298 — same structure as NtReadFile; returns
// STATUS_ACCESS_VIOLATION for null io; writes bytes written into io->Information.
// Known gap: same as NtReadFile — null io returns STATUS_UNSUCCESSFUL, not STATUS_ACCESS_VIOLATION.
/// NtWriteFile: write bytes to a file handle.
///
/// The handle is looked up in the global HANDLE table. Handles 4/5/6 map to
/// stdin/stdout/stderr (Linux fds 0/1/2).
///
/// # Safety
/// `buffer` must be valid for `length` bytes. `io_status_block`, if non-null,
/// must point to a valid `IoStatusBlock`.
// Wine ref: dlls/ntdll/unix/file.c:6298 — same structure as NtReadFile; returns
// STATUS_ACCESS_VIOLATION for null io; writes bytes written into io->Information.
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

// Wine ref: dlls/ntdll/unix/server.c — NtClose calls close_handle() on the wine server;
// invalid handles return STATUS_INVALID_HANDLE. Weave maps this to file_io::close_handle
// which returns STATUS_INVALID_HANDLE for unknown handles — behaviorally correct.
/// NtClose: close an open handle and release its kernel object.
///
/// Closing stdin/stdout/stderr (handles 4/5/6) returns STATUS_UNSUCCESSFUL —
/// those handles are protected.
// Wine ref: dlls/ntdll/unix/server.c — NtClose calls close_handle() on the wine server;
// invalid handles return STATUS_INVALID_HANDLE (0xC0000008).
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
// Wine ref: Wine syscall (ntsyscalls.h) — ProcessHandle==NULL terminates calling process;
// exit_status propagated to parent via NtQueryInformationProcess(ProcessExitStatus).
pub extern "win64" fn nt_terminate_process(_process_handle: usize, exit_status: i32) -> i32 {
    unsafe { libc::exit(exit_status) }
}

// ── NtDeviceIoControlFile ──────────────────────────────────────────────────────

/// NtDeviceIoControlFile: send a control code to a device driver.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED. Callers (Chromium/Signal) check
/// existence of this function via GetProcAddress to detect a real Windows ntdll
/// (which always has it). We return a real function pointer that returns
/// STATUS_NOT_IMPLEMENTED so the existence check passes but any actual I/O
/// control request will fail cleanly.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid for their declared
/// buffer sizes (IoStatusBlock, InputBuffer, OutputBuffer, etc.).
// Wine ref: dlls/ntdll/unix/device.c — NtDeviceIoControlFile delegates to
// the wine server's IOCTL dispatch; STATUS_NOT_SUPPORTED for unknown codes.
pub unsafe extern "win64" fn nt_device_io_control_file(
    _file_handle: usize,
    _event: usize,
    _apc_routine: usize,
    _apc_context: usize,
    io_status_block: *mut i8,
    _io_control_code: u32,
    _input_buffer: *const u8,
    _input_buffer_len: u32,
    _output_buffer: *mut u8,
    _output_buffer_len: u32,
) -> i32 {
    if !io_status_block.is_null() {
        // SAFETY: io_status_block is non-null, caller guarantees alignment.
        unsafe { *(io_status_block as *mut usize) = STATUS_NOT_IMPLEMENTED as usize };
    }
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtQueryInformationFile ─────────────────────────────────────────────────────

/// NtQueryInformationFile: query file information by handle.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED. Required by Chromium/Signal
/// during its ntdll capability probe — it checks existence via GetProcAddress
/// and the check fails (returns NULL) without this function.
///
/// # Safety
/// Caller must ensure `io_status_block` and `file_information` point to buffers
/// of at least their declared sizes.
// Wine ref: dlls/ntdll/unix/file.c — NtQueryInformationFile calls
// server_get_file_info; returns STATUS_NOT_SUPPORTED for unknown info classes.
pub unsafe extern "win64" fn nt_query_information_file(
    _file_handle: usize,
    io_status_block: *mut i8,
    _file_information: *mut u8,
    _length: u32,
    _file_information_class: u32,
) -> i32 {
    if !io_status_block.is_null() {
        // SAFETY: io_status_block is non-null, caller guarantees alignment.
        unsafe { *(io_status_block as *mut usize) = STATUS_NOT_IMPLEMENTED as usize };
    }
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtSetInformationFile ──────────────────────────────────────────────────────

/// NtSetInformationFile: set file information by handle.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure `io_status_block` and `file_information` point to valid
/// buffers of at least their declared sizes.
// Wine ref: dlls/ntdll/unix/file.c — NtSetInformationFile calls
// server_set_file_info; returns STATUS_NOT_SUPPORTED for unknown info classes.
pub unsafe extern "win64" fn nt_set_information_file(
    _file_handle: usize,
    io_status_block: *mut i8,
    _file_information: *mut u8,
    _length: u32,
    _file_information_class: u32,
) -> i32 {
    if !io_status_block.is_null() {
        // SAFETY: io_status_block is non-null, caller guarantees alignment.
        unsafe { *(io_status_block as *mut usize) = STATUS_NOT_IMPLEMENTED as usize };
    }
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtQueryInformationToken ────────────────────────────────────────────────────

/// NtQueryInformationToken: query token information.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure `token_information` points to a valid buffer.
// Wine ref: dlls/ntdll/unix/token.c — NtQueryInformationToken calls
// server_get_token_info; STATUS_NOT_SUPPORTED for unknown info classes.
pub unsafe extern "win64" fn nt_query_information_token(
    _token_handle: usize,
    _token_information_class: u32,
    _token_information: *mut u8,
    _token_information_length: u32,
    _return_length: *mut u32,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtDuplicateObject ──────────────────────────────────────────────────────────

/// NtDuplicateObject: duplicate an object handle.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
// Wine ref: dlls/ntdll/unix/server.c — NtDuplicateObject calls
// server_duplicate_handle; returns proper error for invalid source handle.
pub unsafe extern "win64" fn nt_duplicate_object(
    _source_process_handle: usize,
    _source_handle: usize,
    _target_process_handle: usize,
    _target_handle: *mut usize,
    _desired_access: u32,
    _handle_attributes: u32,
    _options: u32,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtQueryVolumeInformationFile ──────────────────────────────────────────────

/// NtQueryVolumeInformationFile: query volume information by file handle.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure `io_status_block` and `volume_information` point to
/// valid buffers.
// Wine ref: dlls/ntdll/unix/file.c — NtQueryVolumeInformationFile returns
// STATUS_NOT_SUPPORTED for unknown info classes.
pub unsafe extern "win64" fn nt_query_volume_information_file(
    _file_handle: usize,
    io_status_block: *mut i8,
    _volume_information: *mut u8,
    _length: u32,
    _fs_information_class: u32,
) -> i32 {
    if !io_status_block.is_null() {
        // SAFETY: io_status_block is non-null, caller guarantees alignment.
        unsafe { *(io_status_block as *mut usize) = STATUS_NOT_IMPLEMENTED as usize };
    }
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtQueryDirectoryFile ──────────────────────────────────────────────────────

/// NtQueryDirectoryFile: query directory file information.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
// Wine ref: dlls/ntdll/unix/file.c — NtQueryDirectoryFile returns
// STATUS_NO_MORE_FILES when no more entries exist.
pub unsafe extern "win64" fn nt_query_directory_file(
    _file_handle: usize,
    _event: usize,
    _apc_routine: usize,
    _apc_context: usize,
    io_status_block: *mut i8,
    _file_information: *mut u8,
    _length: u32,
    _file_information_class: u32,
    _return_single_entry: u8,
    _file_name: *const u16,
    _restart_scan: u8,
) -> i32 {
    if !io_status_block.is_null() {
        // SAFETY: io_status_block is non-null, caller guarantees alignment.
        unsafe { *(io_status_block as *mut usize) = STATUS_NOT_IMPLEMENTED as usize };
    }
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtCreateSection ──────────────────────────────────────────────────────────

/// NtCreateSection: create a section object.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
// Wine ref: dlls/ntdll/unix/file.c — NtCreateSection creates a file mapping.
pub unsafe extern "win64" fn nt_create_section(
    _section_handle: *mut usize,
    _desired_access: u32,
    _object_attributes: *mut u8,
    _maximum_size: *mut i64,
    _section_page_protection: u32,
    _allocation_attributes: u32,
    _file_handle: usize,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtMapViewOfSection ───────────────────────────────────────────────────────

/// NtMapViewOfSection: map a view of a section object into virtual address space.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
// Wine ref: dlls/ntdll/unix/virtual.c — NtMapViewOfSection calls mmap.
pub unsafe extern "win64" fn nt_map_view_of_section(
    _section_handle: usize,
    _process_handle: usize,
    _base_address: *mut *mut u8,
    _zero_bits: usize,
    _commit_size: usize,
    _section_offset: *mut i64,
    _view_size: *mut usize,
    _inherit_disposition: u32,
    _allocation_type: u32,
    _win32_protect: u32,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtUnmapViewOfSection ─────────────────────────────────────────────────────

/// NtUnmapViewOfSection: unmap a view of a section.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure `base_address` is a valid mapped address.
// Wine ref: dlls/ntdll/unix/virtual.c — NtUnmapViewOfSection calls munmap.
pub unsafe extern "win64" fn nt_unmap_view_of_section(
    _process_handle: usize,
    _base_address: *mut u8,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtOpenProcessToken ───────────────────────────────────────────────────────

/// NtOpenProcessToken: open the access token of a process.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure `token_handle` is non-null and writable.
// Wine ref: dlls/ntdll/unix/token.c — NtOpenProcessToken calls
// server_open_token; returns STATUS_ACCESS_DENIED for system PID 4.
pub unsafe extern "win64" fn nt_open_process_token(
    _process_handle: usize,
    _desired_access: u32,
    _token_handle: *mut usize,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtOpenThreadToken ────────────────────────────────────────────────────────

/// NtOpenThreadToken: open the access token of a thread.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure `token_handle` is non-null and writable.
// Wine ref: dlls/ntdll/unix/token.c — NtOpenThreadToken returns
// STATUS_NO_TOKEN if the thread has no impersonation token.
pub unsafe extern "win64" fn nt_open_thread_token(
    _thread_handle: usize,
    _desired_access: u32,
    _open_as_self: u8,
    _token_handle: *mut usize,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtOpenProcess ────────────────────────────────────────────────────────────

/// NtOpenProcess: open a handle to a process.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure `process_handle` is non-null and writable.
// Wine ref: dlls/ntdll/unix/process.c — NtOpenProcess returns
// STATUS_INVALID_PARAMETER for invalid client ID.
pub unsafe extern "win64" fn nt_open_process(
    _process_handle: *mut usize,
    _desired_access: u32,
    _object_attributes: *mut u8,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtCreateThreadEx ─────────────────────────────────────────────────────────

/// NtCreateThreadEx: create a new thread.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
// Wine ref: dlls/ntdll/unix/thread.c — NtCreateThreadEx creates a
// new thread with a specified start address.
pub unsafe extern "win64" fn nt_create_thread_ex(
    _thread_handle: *mut usize,
    _desired_access: u32,
    _object_attributes: *mut u8,
    _process_handle: usize,
    _start_routine: usize,
    _argument: *mut u8,
    _create_flags: u32,
    _zero_bits: usize,
    _stack_size: usize,
    _maximum_stack_size: usize,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── NtResumeThread ──────────────────────────────────────────────────────────

/// NtResumeThread: resume a suspended thread.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// Caller must ensure `suspend_count` is non-null or valid to skip.
// Wine ref: dlls/ntdll/unix/thread.c — NtResumeThread decrements the
// suspend count and returns the previous count.
pub unsafe extern "win64" fn nt_resume_thread(
    _thread_handle: usize,
    _suspend_count: *mut u32,
) -> i32 {
    STATUS_NOT_IMPLEMENTED as i32
}

// ── RTL heap functions ────────────────────────────────────────────────────────

// Wine ref: dlls/ntdll/heap.c:2038 — uses heap_get_block_size which returns ~0U for size==0
// on some configurations, falling through to STATUS_NO_MEMORY; on others returns minimum block.
// HEAP_ZERO_MEMORY (0x08) zeroes the block via calloc equivalent. Returns NULL on alloc failure
// (not a crash). Wine uses a real heap structure with LFH; Weave delegates to malloc/calloc.
// Known gap: size==0 returns NULL in Weave; Wine may return a minimum-size pointer.
/// RtlAllocateHeap: allocate memory from the heap.
///
/// Wraps `malloc` with optional zero-initialization when HEAP_ZERO_MEMORY (0x08) is set.
/// Ignores HeapHandle parameter (we use a single global allocator).
///
/// # Safety
/// The returned pointer must be freed with RtlFreeHeap or it will leak.
// Wine ref: dlls/ntdll/heap.c:2038 — HEAP_ZERO_MEMORY (0x08) zeroes via calloc;
// size==0 may return a minimum-size pointer in Wine (not NULL as Weave does).
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

// Wine ref: dlls/ntdll/heap.c — RtlFreeHeap returns TRUE (1) for NULL pointers (no-op);
// invalid heap handles call heap_set_status which may raise STATUS_ACCESS_VIOLATION with
// HEAP_GENERATE_EXCEPTIONS. Weave returns TRUE for NULL (correct); no exception on bad handle.
/// RtlFreeHeap: free memory allocated from the heap.
///
/// Wraps `free`. Ignores HeapHandle and Flags parameters.
///
/// # Safety
/// `base_address` must be a valid pointer returned from RtlAllocateHeap/RtlReAllocateHeap or NULL.
// Wine ref: dlls/ntdll/heap.c — returns TRUE for NULL pointer (no-op, correct);
// HEAP_GENERATE_EXCEPTIONS flag may raise STATUS_ACCESS_VIOLATION on bad handle.
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
// Wine ref: dlls/ntdll/heap.c:2229 — returns NULL if ptr==NULL (not a fresh alloc);
// HEAP_REALLOC_IN_PLACE_ONLY → STATUS_NO_MEMORY if in-place resize fails; copies old data
// via memcpy then frees old block when relocating.
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

// Wine ref: dlls/ntdll/version.c:578 — fills dwMajorVersion/dwMinorVersion/dwBuildNumber/
// dwPlatformId and szCSDVersion from current_version global; if dwOSVersionInfoSize ==
// sizeof(RTL_OSVERSIONINFOEXW) also fills wServicePackMajor/Minor, wSuiteMask, wProductType.
// Always returns STATUS_SUCCESS (no error path).
/// RtlGetVersion: fills an RTL_OSVERSIONINFOW struct with Windows 10 info.
///
/// # Safety
/// `lp_version_information` must be a valid writable pointer to an RtlOsVersionInfoW.
// Wine ref: dlls/ntdll/version.c:578 — fills from current_version global; if size==
// sizeof(RTL_OSVERSIONINFOEXW) also fills wServicePackMajor/Minor, wSuiteMask, wProductType;
// always returns STATUS_SUCCESS (no error path).
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

/// RtlVerifyVersionInfo — low-level Windows version check (bypasses compat shims).
///
/// curl and other callers use this (when available) in preference to VerifyVersionInfoW.
/// When GetProcAddress returns NULL for this function, callers fall back to
/// VerifyVersionInfoW. We implement it to always return STATUS_SUCCESS so that
/// version checks (e.g., "Vista or later") always pass.
///
/// # Safety
/// Arguments are accepted but ignored.
// Wine ref: dlls/ntdll/version.c — RtlVerifyVersionInfo validates VersionInfo fields
// against the current OS using ConditionMask; returns STATUS_SUCCESS or STATUS_REVISION_MISMATCH.
pub unsafe extern "win64" fn rtl_verify_version_info(
    _lp_version_info: *const u8,
    _type_mask: u32,
    _condition_mask: u64,
) -> i32 {
    STATUS_SUCCESS
}

// Wine ref: dlls/ntdll/error.c:77 — writes status to NtCurrentTeb()->LastStatusValue before
// calling RtlNtStatusToDosErrorNoTeb. RtlNtStatusToDosErrorNoTeb strips 0xd→0xc prefix,
// handles HIWORD(status)==0xc001/0x8007/0xc007 by returning LOWORD(status), then does a full
// table lookup via map_status; unknown codes → ERROR_MR_MID_NOT_FOUND (317).
// Known gap: Weave has no TEB LastStatusValue; 0xd-prefix stripping and HIWORD special cases
// are missing; only 7 codes are in the map (real Wine covers ~600+).
/// RtlNtStatusToDosError: maps NT status codes to Win32 error codes.
// Wine ref: dlls/ntdll/error.c:77 — writes status to TEB LastStatusValue first;
// HIWORD 0xc001/0x8007/0xc007 returns LOWORD directly; unknown codes → ERROR_MR_MID_NOT_FOUND (317).
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
// Wine ref: dlls/ntdll/rtlstr.c:56 — sets Buffer=source, Length=strlen(source),
// MaximumLength=Length+1; no length cap (unlike RtlInitAnsiStringEx which caps at 0xffff
// and returns STATUS_NAME_TOO_LONG).
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
// Wine ref: dlls/ntdll/rtlstr.c:290 — copies min(src->Length, dst->MaximumLength) bytes;
// if space remains appends null terminator at dst->Buffer[len/sizeof(WCHAR)];
// src==NULL sets dst->Length=0 only (buffer untouched).
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
// Wine ref: dlls/ntdll/rtlstr.c:447 — returns FALSE immediately if lengths differ;
// delegates to RtlCompareUnicodeString (full locale-aware compare) rather than inline comparison.
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
// Wine ref: dlls/ntdll/rtlstr.c:563 — returns STATUS_INVALID_PARAMETER_2 (not
// STATUS_INVALID_PARAMETER) if result >0xffff; uses RtlMultiByteToUnicodeN (not simple byte
// widening); always writes null terminator after converted data.
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
// Wine ref: dlls/ntdll/rtlstr.c:637 — if buffer too small and doalloc==FALSE, sets
// ansi->Length = MaximumLength-1 and returns STATUS_BUFFER_OVERFLOW (not STATUS_BUFFER_TOO_SMALL);
// uses RtlUnicodeToMultiByteN for conversion.
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
// Wine ref: dlls/ntdll/rtlstr.c:272 — calls RtlFreeHeap on Buffer if non-null; then
// zeroes the entire UNICODE_STRING struct via RtlZeroMemory (not just the Buffer field).
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

// ── RTL memory helpers ───────────────────────────────────────────────────────

/// # Safety
/// `destination` and `source` must be valid for `length` bytes.
// Wine ref: dlls/ntdll/string.c:265 — direct memmove wrapper; no null/length checks;
// handles overlapping regions correctly via memmove semantics.
pub unsafe extern "win64" fn rtl_move_memory(
    destination: *mut u8,
    source: *const u8,
    length: usize,
) {
    unsafe {
        libc::memmove(
            destination as *mut libc::c_void,
            source as *const libc::c_void,
            length,
        );
    }
}

/// # Safety
/// `destination` and `source` must be valid for `length` bytes.
// Wine ref: dlls/ntdll/string.c — direct memcpy wrapper; macro #undef'd before definition;
// no overlap handling — use RtlMoveMemory for overlapping regions.
pub unsafe extern "win64" fn rtl_copy_memory(
    destination: *mut u8,
    source: *const u8,
    length: usize,
) {
    unsafe {
        libc::memcpy(
            destination as *mut libc::c_void,
            source as *const libc::c_void,
            length,
        );
    }
}

/// # Safety
/// `destination` must be valid for `length` bytes.
// Wine ref: dlls/ntdll/string.c:274 — direct memset wrapper; macro #undef'd before definition
// to expose as real function rather than inline.
pub unsafe extern "win64" fn rtl_fill_memory(destination: *mut u8, length: usize, fill: u8) {
    unsafe {
        libc::memset(destination as *mut libc::c_void, fill as i32, length);
    }
}

/// # Safety
/// `destination` must be valid for `length` bytes.
// Wine ref: dlls/ntdll/string.c:281 — memset(dest, 0) wrapper; macro #undef'd before
// definition; identical to RtlFillMemory(dest, len, 0).
pub unsafe extern "win64" fn rtl_zero_memory(destination: *mut u8, length: usize) {
    unsafe {
        libc::memset(destination as *mut libc::c_void, 0, length);
    }
}

/// # Safety
/// `source1` and `source2` must be valid for `length` bytes.
// Wine ref: dlls/ntdll/string.c:289 — returns count of matching bytes from start (NOT a signed
// comparator like memcmp); stops at first mismatch; no null pointer checks.
pub unsafe extern "win64" fn rtl_compare_memory(
    source1: *const u8,
    source2: *const u8,
    length: usize,
) -> usize {
    // Pointer validation: null pointers or zero length → 0 matching bytes.
    if source1.is_null() || source2.is_null() || length == 0 {
        return 0;
    }
    // Sanity cap: 256MB is more than any legitimate single comparison.
    const MAX_COMPARE: usize = 256 * 1024 * 1024;
    let length = length.min(MAX_COMPARE);
    let s1 = unsafe { std::slice::from_raw_parts(source1, length) };
    let s2 = unsafe { std::slice::from_raw_parts(source2, length) };
    s1.iter().zip(s2.iter()).take_while(|(a, b)| a == b).count()
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/ntdll/heap.c:2377 — returns FALSE for invalid handle; acquires heap lock;
// validates specific ptr if non-null, else validates entire heap structure; returns BOOLEAN
// TRUE/FALSE, not a STATUS code.
pub unsafe extern "win64" fn rtl_validate_heap(
    _heap_handle: usize,
    _flags: u32,
    _base_address: usize,
) -> i32 {
    1 // TRUE
}

// ── System information functions ─────────────────────────────────────────────

/// SYSTEM_BASIC_INFORMATION (class 0) — 64-byte struct on 64-bit Windows.
///
/// Wine ref: include/winternl.h — __WINESRC__ layout:
///   unknown(u32), KeMaximumIncrement(u32), PageSize(u32),
///   MmNumberOfPhysicalPages(u32), MmLowestPhysicalPage(u32),
///   MmHighestPhysicalPage(u32), AllocationGranularity(usize=8),
///   LowestUserAddress(usize=8), HighestUserAddress(usize=8),
///   ActiveProcessorsAffinityMask(usize=8), NumberOfProcessors(u8) + 7 pad = 64 bytes total.
#[repr(C)]
struct SystemBasicInformation {
    unknown: u32,
    ke_maximum_increment: u32,
    page_size: u32,
    mm_number_of_physical_pages: u32,
    mm_lowest_physical_page: u32,
    mm_highest_physical_page: u32,
    allocation_granularity: usize,
    lowest_user_address: usize,
    highest_user_address: usize,
    active_processors_affinity_mask: usize,
    number_of_processors: u8,
    _pad: [u8; 7],
}

/// SYSTEM_CPU_INFORMATION (class 1) — 12-byte struct.
///
/// Wine ref: include/winternl.h SYSTEM_CPU_INFORMATION:
///   ProcessorArchitecture(u16), ProcessorLevel(u16), ProcessorRevision(u16),
///   MaximumProcessors(u16), ProcessorFeatureBits(u32) = 12 bytes total.
#[repr(C)]
struct SystemCpuInformation {
    processor_architecture: u16,
    processor_level: u16,
    processor_revision: u16,
    maximum_processors: u16,
    processor_feature_bits: u32,
}

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC0000004;

// Wine ref: dlls/ntdll/unix/system.c — large switch on SYSTEM_INFORMATION_CLASS;
// returns STATUS_INFO_LENGTH_MISMATCH when size doesn't match; STATUS_ACCESS_VIOLATION
// when info==NULL and size is correct; SystemBasicInformation(0)/SystemCpuInformation(1) always handled.
// SystemProcessInformation(5) returns a linked list of SYSTEM_PROCESS_INFORMATION entries;
// callers that only want to know "is it supported?" check for STATUS_INFO_LENGTH_MISMATCH
// (not STATUS_NOT_IMPLEMENTED) as the signal that the class is recognized.
/// NtQuerySystemInformation: fill system information for classes 0, 1, 5.
///
/// # Safety
/// `system_information` must be a valid writable pointer of at least
/// `system_information_length` bytes, or NULL. `return_length` must be valid or NULL.
pub unsafe extern "win64" fn nt_query_system_information(
    system_information_class: u32,
    system_information: *mut std::ffi::c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> u32 {
    match system_information_class {
        // SystemBasicInformation = 0
        // Wine ref: include/winternl.h SYSTEM_BASIC_INFORMATION — 64 bytes on 64-bit.
        // Fields filled from sysconf(3): page size, nprocs, physical pages, address ranges.
        0 => {
            const REQUIRED: u32 = std::mem::size_of::<SystemBasicInformation>() as u32;
            if !return_length.is_null() {
                unsafe { *return_length = REQUIRED };
            }
            if system_information_length < REQUIRED {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            if system_information.is_null() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let info = system_information as *mut SystemBasicInformation;
            unsafe {
                let page_size = libc::sysconf(libc::_SC_PAGESIZE) as u32;
                let nprocs = libc::sysconf(libc::_SC_NPROCESSORS_ONLN).max(1) as u32;
                let phys_pages = libc::sysconf(libc::_SC_PHYS_PAGES).max(1) as u32;
                (*info).unknown = 0;
                (*info).ke_maximum_increment = 0x0002_625A; // 100ns intervals per tick (Wine default)
                (*info).page_size = page_size;
                (*info).mm_number_of_physical_pages = phys_pages;
                (*info).mm_lowest_physical_page = 1;
                (*info).mm_highest_physical_page = phys_pages;
                (*info).allocation_granularity = 65536; // Windows always reports 64 KiB
                (*info).lowest_user_address = 0x0001_0000; // 64 KiB — standard Windows value
                (*info).highest_user_address = 0x7FFF_FFFF_0000; // canonical user-space ceiling
                (*info).active_processors_affinity_mask = (1usize << nprocs) - 1;
                (*info).number_of_processors = nprocs as u8;
                (*info)._pad = [0u8; 7];
            }
            0 // STATUS_SUCCESS
        }

        // SystemCpuInformation = 1  (Wine calls this SystemProcessorInformation)
        // Wine ref: include/winternl.h SYSTEM_CPU_INFORMATION — 12 bytes.
        // ProcessorArchitecture=9 (PROCESSOR_ARCHITECTURE_AMD64), Level=6 (Skylake family),
        // Revision=0x5e03 (model 94 step 3 — common Skylake encoding), MaximumProcessors=nprocs.
        1 => {
            const REQUIRED: u32 = std::mem::size_of::<SystemCpuInformation>() as u32;
            if !return_length.is_null() {
                unsafe { *return_length = REQUIRED };
            }
            if system_information_length < REQUIRED {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            if system_information.is_null() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let info = system_information as *mut SystemCpuInformation;
            unsafe {
                let nprocs = libc::sysconf(libc::_SC_NPROCESSORS_ONLN).max(1) as u16;
                (*info).processor_architecture = 9; // PROCESSOR_ARCHITECTURE_AMD64
                (*info).processor_level = 6; // Intel family 6 (Skylake)
                (*info).processor_revision = 0x5e03; // model 94, step 3
                (*info).maximum_processors = nprocs;
                (*info).processor_feature_bits = 0x0000_7FFF; // common feature set
            }
            0 // STATUS_SUCCESS
        }

        // SystemProcessInformation = 5
        // Wine ref: include/winternl.h SYSTEM_PROCESS_INFORMATION — variable-length linked list.
        // Returning a full process list is out of scope (class 5 is a multi-entry linked list
        // with embedded UNICODE_STRING process names and SYSTEM_THREAD_INFORMATION arrays).
        // Callers that only need to detect "this class is supported" distinguish
        // STATUS_INFO_LENGTH_MISMATCH from STATUS_NOT_IMPLEMENTED. We report the minimum
        // useful buffer size (one SYSTEM_PROCESS_INFORMATION header, 184 bytes on 64-bit)
        // so GetSystemInfo-style probers get the right signal.
        5 => {
            // Minimum: one SYSTEM_PROCESS_INFORMATION header with no threads.
            // 64-bit layout: NextEntryOffset(4)+dwThreadCount(4)+WorkingSetPrivateSize(8)+
            // HardFaultCount(4)+NumberOfThreadsHighWatermark(4)+CycleTime(8)+
            // CreationTime(8)+UserTime(8)+KernelTime(8)+
            // ProcessName UNICODE_STRING(16)+dwBasePriority(4)+pad(4)+
            // UniqueProcessId(8)+ParentProcessId(8)+HandleCount(4)+SessionId(4)+
            // UniqueProcessKey(8)+vmCounters(64)+ioCounters(64) = 272 bytes, no ti[] entries.
            // Wine uses 0xb8 (184) for the base on 32-bit; on 64-bit it is 0x100 (256)+threads.
            // We report 256 as the minimum to prompt callers to reallocate rather than crash.
            const MIN_SIZE: u32 = 256;
            if !return_length.is_null() {
                unsafe { *return_length = MIN_SIZE };
            }
            STATUS_INFO_LENGTH_MISMATCH
        }

        // All other classes: not implemented.
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

// ── Process and thread information ───────────────────────────────────────────

/// NtQueryInformationProcess: query process information.
///
/// # Safety
/// If `process_information_class == 0` and length >= 48, writes to `process_information`.
/// If `return_length` is non-null, writes the return length.
// Wine ref: Wine syscall — ProcessBasicInformation (class 0) returns PEB address, UniqueProcessId
// at offset 16, InheritedFromUniqueProcessId, AffinityMask, BasePriority; wrong size →
// STATUS_INFO_LENGTH_MISMATCH.
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
// Wine ref: ReactOS ntoskrnl/ps/query.c:2985 — ThreadBasicInformation writes ExitStatus,
// TebBaseAddress (Tcb.Teb), ClientId, AffinityMask, Priority, BasePriority;
// STATUS_INFO_LENGTH_MISMATCH if buffer size wrong.
pub unsafe extern "win64" fn nt_query_information_thread(
    _handle: usize,
    _thread_information_class: u32,
    _thread_information: *mut std::ffi::c_void,
    _thread_information_length: u32,
    _return_length: *mut u32,
) -> u32 {
    0xC0000002 // STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/ntdll/rtlstr.c:414 — delegates to RtlCompareUnicodeStrings(s1->Buffer,
// s1->Length/sizeof(WCHAR), s2->Buffer, s2->Length/sizeof(WCHAR), CaseInsensitive).
// RtlCompareUnicodeStrings uses locale-aware Unicode case folding (RtlUpcaseUnicodeChar)
// not ASCII bit-twiddling. Returns negative/zero/positive like memcmp.
// Known gap: Weave's case-insensitive path folds only ASCII A-Z (adds 32); non-ASCII
// codepoints (accented chars, Cyrillic, etc.) will compare case-sensitively.
/// RtlCompareUnicodeString: compare two Unicode strings.
///
/// # Safety
/// `string1` and `string2` must be valid pointers to UnicodeString structs.
/// Their buffer pointers must be valid for their respective lengths.
// Wine ref: dlls/ntdll/rtlstr.c:414 — delegates to RtlCompareUnicodeStrings; uses
// locale-aware RtlUpcaseUnicodeChar for case folding, not ASCII bit-twiddling (Weave gap).
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
// Wine ref: ReactOS ntoskrnl/ke/thrdschd.c:887 — returns STATUS_NO_YIELD_PERFORMED if
// ReadySummary==0 (no ready threads at any priority); raises IRQL to SynchLevel before
// selecting next thread. Weave's sched_yield() is a reasonable approximation.
pub extern "win64" fn nt_yield_execution() -> u32 {
    unsafe { libc::sched_yield() };
    0 // STATUS_SUCCESS
}

/// NtSetInformationThread: set thread information (stub).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: ReactOS ntoskrnl/ps/query.c:2269 — large switch on THREADINFOCLASS; ThreadPriority
// requires SeIncreaseBasePriorityPrivilege for realtime values (>=LOW_REALTIME_PRIORITY);
// validates class/size via PsThreadInfoClass table; STATUS_INFO_LENGTH_MISMATCH for wrong size.
pub unsafe extern "win64" fn nt_set_information_thread(
    _thread_handle: usize,
    _thread_information_class: u32,
    _thread_information: *mut std::ffi::c_void,
    _thread_information_length: u32,
) -> u32 {
    0xC0000002 // STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/ntdll/loader.c:3442 — appends ".dll" if missing, resolves the DLL search
// path via LdrGetDllPath, acquires loader_section critical section, calls load_dll then
// process_attach (runs DllMain with DLL_PROCESS_ATTACH). On attach failure, calls LdrUnloadDll.
// Writes wm->ldr.DllBase into *hModule on success.
// Known gap: Weave registers a synthetic handle and returns STATUS_SUCCESS for any non-empty
// name — no actual DllMain invocation, no search path resolution, no loader lock.
/// LdrLoadDll: load a DLL into the process address space.
///
/// Returns a synthetic module handle via the global handle registry and
/// resolves functions through the runtime resolver chain.
///
/// # Safety
/// `module_file_name` must be null or a valid pointer to a `UnicodeString`.
/// `module_handle` must be a valid writable pointer.
// Wine ref: dlls/ntdll/loader.c:3442 — appends ".dll" if missing; acquires loader_section
// critical section; calls load_dll then runs DllMain DLL_PROCESS_ATTACH; on attach failure
// calls LdrUnloadDll; writes wm->ldr.DllBase into *hModule on success.
pub unsafe extern "win64" fn ldr_load_dll(
    _path_to_file: *const u16,
    _flags: u32,
    module_file_name: *const UnicodeString,
    module_handle: *mut usize,
) -> u32 {
    let name = if !module_file_name.is_null() {
        unsafe { (*module_file_name).to_string() }.unwrap_or_default()
    } else {
        String::new()
    };
    if name.is_empty() {
        return 0xC0000135; // STATUS_DLL_NOT_FOUND
    }
    let handle = weave_core::module_handles::register(&name);
    if !module_handle.is_null() {
        unsafe { *module_handle = handle };
    }
    eprintln!("weave/ntdll: LdrLoadDll({name:?}) → {handle:#x}");
    0 // STATUS_SUCCESS
}

// Wine ref: dlls/ntdll/loader.c — LdrGetProcedureAddress searches the module's export table
// for the named procedure; ordinal lookup supported via the Ordinal parameter (non-zero ordinal
// overrides name). Returns STATUS_PROCEDURE_NOT_FOUND if not found.
// Known gap: Weave uses its runtime resolve chain rather than the module's actual export table;
// ordinal lookup not implemented (Ordinal parameter ignored).
/// LdrGetProcedureAddress: get the address of a procedure in a loaded DLL.
///
/// Maps the module handle back to a DLL name, then resolves via the global
/// resolver chain.
///
/// # Safety
/// `function_name` must be null or a valid pointer to an `AnsiString`.
/// `function_address` must be a valid writable pointer.
// Wine ref: dlls/ntdll/loader.c — ordinal lookup (non-zero Ordinal) takes priority over name;
// returns STATUS_PROCEDURE_NOT_FOUND if not found in the module's export table.
pub unsafe extern "win64" fn ldr_get_procedure_address(
    module_handle: usize,
    function_name: *const AnsiString,
    _ordinal: u16,
    function_address: *mut usize,
) -> u32 {
    let dll_name = match weave_core::module_handles::lookup(module_handle) {
        Some(name) => name,
        None => return 0xC000007A, // STATUS_PROCEDURE_NOT_FOUND
    };

    let func = if !function_name.is_null() {
        let ansi = unsafe { &*function_name };
        if ansi.buffer.is_null() || ansi.length == 0 {
            String::new()
        } else {
            let slice = unsafe {
                std::slice::from_raw_parts(ansi.buffer as *const u8, ansi.length as usize)
            };
            String::from_utf8_lossy(slice).into_owned()
        }
    } else {
        String::new()
    };

    if func.is_empty() {
        return 0xC000007A; // STATUS_PROCEDURE_NOT_FOUND
    }

    match weave_core::resolve::resolve(&dll_name, &func) {
        Some(addr) => {
            if !function_address.is_null() {
                unsafe { *function_address = addr };
            }
            eprintln!("weave/ntdll: LdrGetProcedureAddress({dll_name}!{func}) → {addr:#x}");
            0 // STATUS_SUCCESS
        }
        None => {
            eprintln!("weave/ntdll: LdrGetProcedureAddress({dll_name}!{func}) → NOT_FOUND");
            0xC000007A // STATUS_PROCEDURE_NOT_FOUND
        }
    }
}

// Wine ref: dlls/ntdll/unix/virtual.c:5193 — NtAllocateVirtualMemory returns
// STATUS_INVALID_PARAMETER for null base_address, null region_size, or *region_size == 0.
// On success writes the actual allocation base into *base_address.
/// NtAllocateVirtualMemory: allocate virtual memory.
///
/// # Safety
/// `base_address` must be a valid pointer to a pointer. `region_size` must be a valid pointer.
// Wine ref: dlls/ntdll/unix/virtual.c:5193 — returns STATUS_INVALID_PARAMETER for null
// base_address, null region_size, or *region_size==0; writes actual allocation base into
// *base_address on success.
pub unsafe extern "win64" fn nt_allocate_virtual_memory(
    _process_handle: usize,
    base_address: *mut *mut u8,
    _zero_bits: usize,
    region_size: *mut usize,
    _allocation_type: u32,
    protect: u32,
) -> u32 {
    const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
    unsafe {
        if base_address.is_null() || region_size.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        // Wine: if (!*size_ptr) return STATUS_INVALID_PARAMETER
        if *region_size == 0 {
            return STATUS_INVALID_PARAMETER;
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
// Wine ref: Wine syscall (ntsyscalls.h) — MEM_RELEASE (0x8000) frees entire allocation,
// size should be 0; MEM_DECOMMIT (0x4000) decommits only. Weave always calls munmap
// regardless of free_type — does not distinguish decommit vs release.
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
// Wine ref: Wine syscall (ntsyscalls.h) — rounds base/size down/up to page boundaries before
// calling mprotect; writes previous page protection flags into old_access_protection before
// applying new protection.
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
// Wine ref: Wine syscall (ntsyscalls.h) — MemoryBasicInformation (class 0) fills
// MEMORY_BASIC_INFORMATION with base, size, protection, type; MemoryMappedFilenameInformation
// (class 2) returns mapped file path; STATUS_INVALID_INFO_CLASS for unknown class.
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

// ── RtlRaiseException ─────────────────────────────────────────────────────────
//
// Wine ref: dlls/ntdll/signal_x86_64.c — RtlRaiseException calls NtRaiseException
// after capturing the full context. The exception_address is set to the return
// address (the throw site inside _CxxThrowException). We must capture RSP/RIP
// before any prolog runs so virtual_unwind can correctly reconstruct the throw
// frame.

/// Naked trampoline: captures the throw site (return address = [RSP]) and throw RSP
/// (RSP+8, i.e. RSP inside _CxxThrowException's body) before any prolog runs.
/// Win64 ABI: RCX = EXCEPTION_RECORD*
// Wine ref: dlls/ntdll/signal_x86_64.c — sets exception_address to the return address
// (throw site inside _CxxThrowException); RSP/RIP captured before any prolog runs so
// virtual_unwind can correctly reconstruct the throw frame.
#[unsafe(naked)]
pub unsafe extern "win64" fn rtl_raise_exception(
    _p_exception_record: *mut weave_core::unwind::ExceptionRecord,
) {
    core::arch::naked_asm!(
        // RCX = EXCEPTION_RECORD* (Win64 arg1)
        // [RSP] = return address into _CxxThrowException (throw_rip)
        // RSP+8 would be the RSP inside _CxxThrowException body after the CALL
        "mov rsi, [rsp]",    // throw_rip → Linux arg2 (rsi)
        "lea rdx, [rsp+8]",  // &throw_rsp → Linux arg3 (rdx); caller interprets as throw_rsp value
        "mov rdi, rcx",      // EXCEPTION_RECORD* → Linux arg1 (rdi)
        // rsi = throw_rip (Linux arg2)
        // rdx = throw_rsp (Linux arg3) — points to _CxxThrowException's stack frame top
        "jmp {impl_fn}",
        impl_fn = sym rtl_raise_exception_impl,
    );
}

unsafe extern "C" fn rtl_raise_exception_impl(
    p_exc: *mut weave_core::unwind::ExceptionRecord,
    throw_rip: u64,
    throw_rsp: u64,
) {
    let exc = unsafe { &mut *p_exc };
    exc.exception_address = throw_rip as *mut u8;
    let args_ptr = exc.exception_information.as_ptr();
    unsafe {
        weave_core::unwind::raise_exception_at(
            exc.exception_code,
            exc.exception_flags,
            exc.number_parameters,
            args_ptr,
            throw_rip,
            throw_rsp,
        );
    }
    unsafe { libc::abort() };
}

// ── Signal gap-fill: ntdll stubs ──────────────────────────────────────────────
//
// jcodemunch unavailable — Phase A stubs only, safe sentinel returns.

/// LdrLockLoaderLock: acquire the loader lock.
///
/// Phase A stub — returns STATUS_SUCCESS (no-op lock).
///
/// # Safety
/// `flags` and `cookie` must be valid pointers or NULL.
pub unsafe extern "win64" fn ldr_lock_loader_lock(_flags: u32, _cookie: *mut usize) -> u32 {
    0 // STATUS_SUCCESS
}

/// LdrUnlockLoaderLock: release the loader lock.
///
/// Phase A stub — returns STATUS_SUCCESS (no-op unlock).
///
/// # Safety
/// `cookie` must be non-zero if previously acquired.
pub unsafe extern "win64" fn ldr_unlock_loader_lock(_cookie: usize) -> u32 {
    0 // STATUS_SUCCESS
}

/// NtDeleteKey: delete a registry key.
///
/// Phase A stub — returns STATUS_SUCCESS (no-op).
///
/// # Safety
/// `key_handle` is accepted but not dereferenced.
pub unsafe extern "win64" fn nt_delete_key(_key_handle: usize) -> u32 {
    eprintln!("weave/ntdll_stub: NtDeleteKey");
    0 // STATUS_SUCCESS
}

/// NtQueryObject: query object information.
///
/// Phase A stub — returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// All pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn nt_query_object(
    _handle: usize,
    _object_information_class: u32,
    _object_information: *mut u8,
    _object_information_length: u32,
    _return_length: *mut u32,
) -> u32 {
    eprintln!("weave/ntdll_stub: NtQueryObject");
    STATUS_NOT_IMPLEMENTED
}

/// RtlGetLastNtStatus: get the last NT status code from the TEB.
///
/// Phase A stub — returns 0 (STATUS_SUCCESS).
pub extern "win64" fn rtl_get_last_nt_status() -> u32 {
    0 // STATUS_SUCCESS
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
        "RtlVerifyVersionInfo" => Some(
            rtl_verify_version_info as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
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
        // RTL memory helpers
        "RtlMoveMemory" => {
            Some(rtl_move_memory as unsafe extern "win64" fn(_, _, _) as *const () as usize)
        }
        "RtlCopyMemory" => {
            Some(rtl_copy_memory as unsafe extern "win64" fn(_, _, _) as *const () as usize)
        }
        "RtlFillMemory" => {
            Some(rtl_fill_memory as unsafe extern "win64" fn(_, _, _) as *const () as usize)
        }
        "RtlZeroMemory" => {
            Some(rtl_zero_memory as unsafe extern "win64" fn(_, _) as *const () as usize)
        }
        "RtlCompareMemory" => {
            Some(rtl_compare_memory as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "RtlValidateHeap" => {
            Some(rtl_validate_heap as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
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
        // Task 3: NT timing + shutdown flag
        "RtlDllShutdownInProgress" => Some(rtl_dll_shutdown_in_progress as *const () as usize),
        "NtQueryPerformanceCounter" => Some(
            nt_query_performance_counter as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "NtQuerySystemTime" => {
            Some(nt_query_system_time as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "NtDelayExecution" => {
            Some(nt_delay_execution as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Task 4: NT event stubs (requires adding handle counter)
        "NtCreateEvent" => Some(
            nt_create_event as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "NtOpenEvent" => {
            Some(nt_open_event as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "NtSetEvent" => {
            Some(nt_set_event as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "NtResetEvent" => {
            Some(nt_reset_event as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "NtClearEvent" => {
            Some(nt_clear_event as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "NtPulseEvent" => {
            Some(nt_pulse_event as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "NtWaitForSingleObject" => Some(
            nt_wait_for_single_object as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        // Task 5: RtlWaitOnAddress family
        "RtlWaitOnAddress" => Some(
            rtl_wait_on_address as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "RtlWakeByAddressSingle" => {
            Some(rtl_wake_by_address_single as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "RtlWakeByAddressAll" => {
            Some(rtl_wake_by_address_all as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // RTL exception/unwind — real implementations in weave_core::unwind
        "RtlCaptureContext" => Some(
            weave_core::unwind::rtl_capture_context_export as unsafe extern "win64" fn(_)
                as *const () as usize,
        ),
        "RtlLookupFunctionEntry" => Some(
            weave_core::unwind::rtl_lookup_function_entry_export
                as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "RtlVirtualUnwind" => Some(
            weave_core::unwind::rtl_virtual_unwind_export
                as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlUnwindEx" => Some(
            weave_core::unwind::rtl_unwind_ex_export as unsafe extern "win64" fn(_, _, _, _, _, _)
                as *const () as usize,
        ),
        "RtlRaiseException" => {
            Some(rtl_raise_exception as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // Wine presence marker — DXVK calls GetProcAddress(ntdll, "__wine_dbg_output") to
        // detect whether it's running under Wine.  Returning a non-NULL address causes DXVK
        // to use its Wine/winevulkan Vulkan-loading path, which is what Weave supports.
        "__wine_dbg_output" => {
            Some(wine_dbg_output as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // ── Signal gap-fill: 5 ntdll stubs ──
        "LdrLockLoaderLock" => {
            Some(ldr_lock_loader_lock as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LdrUnlockLoaderLock" => {
            Some(ldr_unlock_loader_lock as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "NtDeleteKey" => {
            Some(nt_delete_key as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "NtQueryObject" => Some(
            nt_query_object as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "RtlGetLastNtStatus" => Some(rtl_get_last_nt_status as *const () as usize),
        // NtDeviceIoControlFile — device I/O control (Signal/Chromium capability check)
        "NtDeviceIoControlFile" => Some(
            nt_device_io_control_file as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "NtQueryInformationFile" => Some(
            nt_query_information_file as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "NtSetInformationFile" => Some(
            nt_set_information_file as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Chromium sandbox/capability probe — need to exist with a real pointer
        "NtQueryInformationToken" => Some(
            nt_query_information_token as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "NtDuplicateObject" => Some(
            nt_duplicate_object as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "NtQueryVolumeInformationFile" => Some(
            nt_query_volume_information_file as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        "NtQueryDirectoryFile" => Some(
            nt_query_directory_file
                as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "NtCreateSection" => Some(
            nt_create_section as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "NtMapViewOfSection" => Some(
            nt_map_view_of_section as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "NtUnmapViewOfSection" => Some(
            nt_unmap_view_of_section as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "NtOpenProcessToken" => Some(
            nt_open_process_token as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "NtOpenThreadToken" => Some(
            nt_open_thread_token as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "NtOpenProcess" => {
            Some(nt_open_process as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "NtCreateThreadEx" => Some(
            nt_create_thread_ex as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "NtResumeThread" => {
            Some(nt_resume_thread as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        _ => None,
    }
}

/// __wine_dbg_output — Wine debug output sink.
///
/// DXVK calls GetProcAddress(ntdll, "__wine_dbg_output") to detect Wine.
/// Weave exposes this so DXVK uses the Wine/winevulkan Vulkan-loading path.
///
/// # Safety
/// `str` must be null or a valid null-terminated UTF-8/ASCII string.
pub unsafe extern "win64" fn wine_dbg_output(_str: *const u8) -> i32 {
    0
}

// ── NtQuerySystemInformation unit tests ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Class 0 (SystemBasicInformation): correct buffer size → STATUS_SUCCESS,
    /// NumberOfProcessors must be >= 1 and PageSize must be a power of two.
    #[test]
    fn class0_basic_information_success() {
        let mut buf = std::mem::MaybeUninit::<SystemBasicInformation>::uninit();
        let mut ret_len: u32 = 0;
        let status = unsafe {
            nt_query_system_information(
                0,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                std::mem::size_of::<SystemBasicInformation>() as u32,
                &mut ret_len,
            )
        };
        assert_eq!(status, 0, "expected STATUS_SUCCESS for class 0");
        assert_eq!(
            ret_len as usize,
            std::mem::size_of::<SystemBasicInformation>()
        );
        let info = unsafe { buf.assume_init() };
        assert!(
            info.number_of_processors >= 1,
            "NumberOfProcessors must be >= 1"
        );
        assert!(
            info.page_size >= 4096 && info.page_size.is_power_of_two(),
            "PageSize must be a power-of-two >= 4096, got {}",
            info.page_size
        );
        assert_eq!(info.allocation_granularity, 65536);
    }

    /// Class 0: buffer too small → STATUS_INFO_LENGTH_MISMATCH, not STATUS_NOT_IMPLEMENTED.
    #[test]
    fn class0_too_small_returns_mismatch() {
        let mut buf = [0u8; 4]; // far too small
        let status = unsafe {
            nt_query_system_information(
                0,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            status, STATUS_INFO_LENGTH_MISMATCH,
            "expected STATUS_INFO_LENGTH_MISMATCH for class 0 with tiny buffer"
        );
    }

    /// Class 1 (SystemCpuInformation): correct buffer size → STATUS_SUCCESS,
    /// ProcessorArchitecture must be 9 (AMD64) and MaximumProcessors >= 1.
    #[test]
    fn class1_cpu_information_success() {
        let mut buf = std::mem::MaybeUninit::<SystemCpuInformation>::uninit();
        let mut ret_len: u32 = 0;
        let status = unsafe {
            nt_query_system_information(
                1,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                std::mem::size_of::<SystemCpuInformation>() as u32,
                &mut ret_len,
            )
        };
        assert_eq!(status, 0, "expected STATUS_SUCCESS for class 1");
        assert_eq!(
            ret_len as usize,
            std::mem::size_of::<SystemCpuInformation>()
        );
        let info = unsafe { buf.assume_init() };
        assert_eq!(
            info.processor_architecture, 9,
            "ProcessorArchitecture must be 9 (AMD64)"
        );
        assert!(
            info.maximum_processors >= 1,
            "MaximumProcessors must be >= 1"
        );
    }

    /// Class 1: buffer too small → STATUS_INFO_LENGTH_MISMATCH.
    #[test]
    fn class1_too_small_returns_mismatch() {
        let mut buf = [0u8; 2]; // too small
        let status = unsafe {
            nt_query_system_information(
                1,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            status, STATUS_INFO_LENGTH_MISMATCH,
            "expected STATUS_INFO_LENGTH_MISMATCH for class 1 with tiny buffer"
        );
    }

    /// Class 5 (SystemProcessInformation): any buffer → STATUS_INFO_LENGTH_MISMATCH
    /// (not STATUS_NOT_IMPLEMENTED — the class is recognized).
    #[test]
    fn class5_process_information_mismatch_not_not_implemented() {
        let mut buf = [0u8; 8]; // deliberately too small
        let mut ret_len: u32 = 0;
        let status = unsafe {
            nt_query_system_information(
                5,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as u32,
                &mut ret_len,
            )
        };
        assert_eq!(
            status, STATUS_INFO_LENGTH_MISMATCH,
            "class 5 must return STATUS_INFO_LENGTH_MISMATCH, not STATUS_NOT_IMPLEMENTED"
        );
        assert!(
            ret_len > 0,
            "ReturnLength must be set to minimum buffer hint"
        );
    }

    /// Unknown class → STATUS_NOT_IMPLEMENTED (no regression).
    #[test]
    fn unknown_class_still_returns_not_implemented() {
        let mut buf = [0u8; 64];
        let status = unsafe {
            nt_query_system_information(
                99,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            status, STATUS_NOT_IMPLEMENTED,
            "unknown class must still return STATUS_NOT_IMPLEMENTED"
        );
    }

    /// Struct size assertions — callers depend on exact sizes.
    #[test]
    fn struct_sizes_are_canonical() {
        assert_eq!(
            std::mem::size_of::<SystemBasicInformation>(),
            64,
            "SYSTEM_BASIC_INFORMATION must be 64 bytes on 64-bit"
        );
        assert_eq!(
            std::mem::size_of::<SystemCpuInformation>(),
            12,
            "SYSTEM_CPU_INFORMATION must be 12 bytes"
        );
    }

    /// All 11 Signal Desktop ntdll imports resolve successfully.
    #[test]
    fn resolve_all_signal_ntdll_imports() {
        let all = [
            "LdrLockLoaderLock",
            "LdrUnlockLoaderLock",
            "NtDeleteKey",
            "NtQueryInformationProcess",
            "NtQueryInformationThread",
            "NtQueryObject",
            "NtQuerySystemInformation",
            "NtWriteFile",
            "RtlGetLastNtStatus",
            "RtlInitUnicodeString",
            "RtlNtStatusToDosError",
        ];
        for f in &all {
            assert!(resolve(f).is_some(), "missing {f}");
        }
    }

    /// 5 new Signal gap-fill stubs resolve.
    #[test]
    fn resolve_signal_gap_fill_stubs() {
        let new_funcs = [
            "LdrLockLoaderLock",
            "LdrUnlockLoaderLock",
            "NtDeleteKey",
            "NtQueryObject",
            "RtlGetLastNtStatus",
        ];
        for f in &new_funcs {
            assert!(resolve(f).is_some(), "missing {f}");
        }
    }

    /// Unknown function returns None.
    #[test]
    fn resolve_nonexistent_returns_none() {
        assert!(resolve("__nonexistent__ntdll_func__").is_none());
    }
}
