//! Stubs for the api-ms-win-crt-* DLL family (27 functions).
//!
//! These are the Universal CRT (UCRT) API-set forwarding DLLs used by every
//! MinGW-compiled binary. On real Windows they forward to ucrtbase.dll.
//! Weave implements the minimum surface needed for CRT initialisation to
//! complete and for hello.exe to print output and exit.
//!
//! Strategy:
//!   - Heap functions delegate to libc malloc/calloc/free.
//!   - _initterm / _initterm_e actually call the function-pointer table —
//!     these run global constructors and must not be stubbed as no-ops.
//!   - Everything else is a harmless no-op or returns a safe sentinel.

// Windows API names use double/triple underscores; Rust snake_case rules don't apply.
#![allow(non_snake_case)]

// ── Static CRT state ──────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

static COMMODE: AtomicI32 = AtomicI32::new(0);
static FMODE: AtomicI32 = AtomicI32::new(0);
static ARGC: AtomicI32 = AtomicI32::new(1);
static ENVIRON_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

// Command-line strings for __p__acmdln / __p__wcmdln.
// A minimal "weave\0" ANSI command line and the equivalent UTF-16.
static ACMDLN: &[u8] = b"weave\0";
// UTF-16LE encoding of "weave\0\0" (null terminator is two bytes).
static WCMDLN: &[u16] = &[
    b'w' as u16,
    b'e' as u16,
    b'a' as u16,
    b'v' as u16,
    b'e' as u16,
    0u16,
];
// Pointers that __p__acmdln/__p__wcmdln return (pointer to the string pointer).
static ACMDLN_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static WCMDLN_PTR: AtomicPtr<u16> = AtomicPtr::new(std::ptr::null_mut());

// argv layout (what the CRT expects):
//   __p___argv()  →  &ARGV_VAR        (char ***)
//   ARGV_VAR      →  &ARGV_ARRAY[0]   (char **)
//   ARGV_ARRAY[0] →  ARGV0_STR        (char *)
//   ARGV0_STR     =  "weave\0"
//   ARGV_ARRAY[1] =  null
//
// Using usize so the array is always pointer-sized (avoids *const u8: !Sync).
static ARGV0_STR: &[u8] = b"weave\0";
// [ptr_to_argv0_string, null] as usize — filled once at first call.
static mut ARGV_ARRAY: [usize; 2] = [0; 2];
// char** = pointer to ARGV_ARRAY[0]; stored here so we can return &ARGV_VAR.
static mut ARGV_VAR: usize = 0;
static ARGV_ONCE: std::sync::Once = std::sync::Once::new();

/// Fake FILE — enough storage that the CRT doesn't stray out of bounds.
/// The CRT only calls setvbuf / fflush on these; both are no-ops.
#[repr(C)]
pub(super) struct FakeFile {
    fd: i32,
    _pad: [u8; 60],
}

static FAKE_STDIN: FakeFile = FakeFile {
    fd: 0,
    _pad: [0; 60],
};
static FAKE_STDOUT: FakeFile = FakeFile {
    fd: 1,
    _pad: [0; 60],
};
static FAKE_STDERR: FakeFile = FakeFile {
    fd: 2,
    _pad: [0; 60],
};

// ── api-ms-win-crt-heap ───────────────────────────────────────────────────────

/// malloc: allocate heap memory.
///
/// # Safety
/// Delegates to libc malloc.
pub unsafe extern "win64" fn crt_malloc(size: usize) -> *mut u8 {
    unsafe { libc::malloc(size) as *mut u8 }
}

/// calloc: allocate zeroed heap memory.
///
/// # Safety
/// Delegates to libc calloc.
pub unsafe extern "win64" fn crt_calloc(count: usize, size: usize) -> *mut u8 {
    unsafe { libc::calloc(count, size) as *mut u8 }
}

/// free: release heap memory.
///
/// # Safety
/// `ptr` must have been returned by malloc/calloc/realloc, or be null.
pub unsafe extern "win64" fn crt_free(ptr: *mut u8) {
    unsafe { libc::free(ptr as *mut libc::c_void) }
}

/// _set_new_mode: set the C++ new-handler behaviour mode. No-op.
pub extern "win64" fn set_new_mode(_mode: i32) -> i32 {
    0
}

// ── api-ms-win-crt-private ────────────────────────────────────────────────────

/// memcpy: copy bytes between non-overlapping regions.
///
/// # Safety
/// `dst` and `src` must be valid for `n` bytes and must not overlap.
pub unsafe extern "win64" fn crt_memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { libc::memcpy(dst as *mut libc::c_void, src as *const libc::c_void, n) as *mut u8 }
}

// ── api-ms-win-crt-runtime ────────────────────────────────────────────────────

/// _initterm: call each non-null function pointer in [pfbegin, pfend).
///
/// Used by the CRT to run pre-initialisation hooks. Must actually call the
/// functions — a no-op here would prevent CRT init from completing.
///
/// # Safety
/// Each non-null pointer in the table must be a valid `extern "win64" fn()`.
pub unsafe extern "win64" fn initterm(pfbegin: *mut usize, pfend: *mut usize) {
    let mut ptr = pfbegin;
    while ptr < pfend {
        let addr = unsafe { *ptr };
        if addr != 0 {
            // SAFETY: `addr` is a non-zero entry from the CRT initialiser table
            // (the `__xi_a` / `__xi_z` or `__xc_a` / `__xc_z` sections).  The
            // MSVC/MinGW CRT ABI guarantees every non-null slot in this table
            // holds the address of a `void ()(void)` function compiled with the
            // Win64 calling convention.  The `unsafe` fn signature matches that
            // contract.  The caller's `# Safety` doc requires the table bounds to
            // be valid, so this transmute is sound under that precondition.
            let f: unsafe extern "win64" fn() = unsafe { std::mem::transmute(addr) };
            unsafe { f() };
        }
        ptr = unsafe { ptr.add(1) };
    }
}

/// _initterm_e: like _initterm but each function returns an int error code.
///
/// Returns the first non-zero error code, or 0 if all functions succeed.
///
/// # Safety
/// Each non-null pointer in the table must be a valid `extern "win64" fn() -> i32`.
pub unsafe extern "win64" fn initterm_e(pfbegin: *mut usize, pfend: *mut usize) -> i32 {
    let mut ptr = pfbegin;
    while ptr < pfend {
        let addr = unsafe { *ptr };
        if addr != 0 {
            // SAFETY: `addr` is a non-zero entry from the CRT error-checked
            // initialiser table (the `__xi_a` / `__xi_z` sections used by
            // `_initterm_e`).  The MSVC/MinGW CRT ABI guarantees every non-null
            // slot holds the address of an `int ()(void)` function compiled with
            // the Win64 calling convention — matching the `fn() -> i32` signature
            // declared here.  The caller's `# Safety` doc requires the table
            // bounds to be valid, making this transmute sound under that
            // precondition.
            let f: unsafe extern "win64" fn() -> i32 = unsafe { std::mem::transmute(addr) };
            let ret = unsafe { f() };
            if ret != 0 {
                return ret;
            }
        }
        ptr = unsafe { ptr.add(1) };
    }
    0
}

/// __p___argc: return a pointer to the process argc.
pub extern "win64" fn p___argc() -> *mut i32 {
    ARGC.as_ptr()
}

/// __p___argv: return a pointer to the argv array pointer (`char ***`).
///
/// # Safety
/// Initialises static argv state on first call (single-threaded, safe in Phase 1).
pub unsafe extern "win64" fn p___argv() -> *mut *mut u8 {
    ARGV_ONCE.call_once(|| unsafe {
        ARGV_ARRAY[0] = ARGV0_STR.as_ptr() as usize;
        ARGV_ARRAY[1] = 0;
        ARGV_VAR = std::ptr::addr_of!(ARGV_ARRAY) as usize;
    });
    // Return &ARGV_VAR (char ***), which the CRT dereferences to get char**.
    std::ptr::addr_of_mut!(ARGV_VAR).cast::<*mut u8>()
}

/// _configure_narrow_argv: configure argv mode. Returns 0 (success).
pub extern "win64" fn configure_narrow_argv(_mode: i32) -> i32 {
    0
}

/// _initialize_narrow_environment: init the process environment. Returns 0.
pub extern "win64" fn initialize_narrow_environment() -> i32 {
    0
}

/// _set_app_type: record whether this is a console or GUI app. No-op.
pub extern "win64" fn set_app_type(_at: i32) {}

/// _set_invalid_parameter_handler: install a handler. Returns null.
pub extern "win64" fn set_invalid_parameter_handler(_handler: usize) -> usize {
    0
}

/// _crt_atexit: register an atexit callback. Returns 0 (not called).
pub extern "win64" fn crt_atexit(_fn_ptr: usize) -> i32 {
    0
}

/// _cexit: clean exit without process termination. No-op.
pub extern "win64" fn cexit() {}

/// _exit: exit without atexit handlers.
pub extern "win64" fn crt_exit_no_cleanup(status: i32) -> ! {
    unsafe { libc::exit(status) }
}

/// exit: normal process exit.
pub extern "win64" fn crt_exit(status: i32) -> ! {
    unsafe { libc::exit(status) }
}

/// abort: abnormal process termination.
pub extern "win64" fn crt_abort() -> ! {
    unsafe { libc::abort() }
}

/// signal: register a signal handler. Returns SIG_DFL (0 = previous handler).
pub extern "win64" fn crt_signal(_sig: i32, _handler: usize) -> usize {
    0
}

// ── api-ms-win-crt-locale ─────────────────────────────────────────────────────

/// _configthreadlocale: configure per-thread locale. Returns -1 (not set).
pub extern "win64" fn configthreadlocale(_per_thread: i32) -> i32 {
    -1
}

// ── api-ms-win-crt-math ───────────────────────────────────────────────────────

/// __setusermatherr: install a math-error handler. Returns null.
pub extern "win64" fn setusermatherr(_pfn_new: usize) -> usize {
    0
}

// ── api-ms-win-crt-environment ────────────────────────────────────────────────

/// __p__environ: return a pointer to the environ array pointer (empty env).
pub extern "win64" fn p__environ() -> *mut *mut u8 {
    ENVIRON_PTR.as_ptr()
}

/// __p__acmdln: return a pointer to the ANSI command-line string pointer (`char **`).
pub extern "win64" fn p__acmdln() -> *mut *mut u8 {
    // Initialise once — store the address of the ACMDLN slice.
    let _ = ACMDLN_PTR.compare_exchange(
        std::ptr::null_mut(),
        ACMDLN.as_ptr() as *mut u8,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    ACMDLN_PTR.as_ptr()
}

/// __p__wcmdln: return a pointer to the wide command-line string pointer (`wchar_t **`).
pub extern "win64" fn p__wcmdln() -> *mut *mut u16 {
    let _ = WCMDLN_PTR.compare_exchange(
        std::ptr::null_mut(),
        WCMDLN.as_ptr() as *mut u16,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    WCMDLN_PTR.as_ptr()
}

// ── api-ms-win-crt-stdio ──────────────────────────────────────────────────────

/// __acrt_iob_func: return a pointer to a stdio FILE for index 0/1/2.
pub extern "win64" fn acrt_iob_func(index: u32) -> *const u8 {
    let file: *const FakeFile = match index {
        0 => &FAKE_STDIN,
        1 => &FAKE_STDOUT,
        2 => &FAKE_STDERR,
        _ => return std::ptr::null(),
    };
    file.cast()
}

/// __p__commode: return a pointer to the _commode global.
pub extern "win64" fn p__commode() -> *mut i32 {
    COMMODE.as_ptr()
}

/// __p__fmode: return a pointer to the _fmode global.
pub extern "win64" fn p__fmode() -> *mut i32 {
    FMODE.as_ptr()
}

/// __stdio_common_vfprintf: core vfprintf. Phase 1 stub — returns -1.
pub extern "win64" fn stdio_common_vfprintf(
    _options: u64,
    _stream: usize,
    _format: *const u8,
    _locale: usize,
    _arglist: usize,
) -> i32 {
    -1
}

/// fflush: flush a stdio stream. No-op — Weave writes directly via libc.
pub extern "win64" fn crt_fflush(_stream: usize) -> i32 {
    0
}

/// setvbuf: set buffering mode for a stdio stream. No-op.
pub extern "win64" fn crt_setvbuf(_stream: usize, _buf: *mut u8, _mode: i32, _size: usize) -> i32 {
    0
}

// ── api-ms-win-crt-string ─────────────────────────────────────────────────────

/// strlen: return the length of a null-terminated string.
///
/// # Safety
/// `s` must point to a valid null-terminated string.
pub unsafe extern "win64" fn crt_strlen(s: *const u8) -> usize {
    unsafe { libc::strlen(s as *const libc::c_char) }
}

/// strncmp: compare up to n bytes of two strings.
///
/// # Safety
/// Both `s1` and `s2` must be valid for at least `n` bytes.
pub unsafe extern "win64" fn crt_strncmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe { libc::strncmp(s1 as *const libc::c_char, s2 as *const libc::c_char, n) }
}

/// wcslen: return the length of a null-terminated UTF-16 string.
///
/// # Safety
/// `s` must point to a valid null-terminated array of u16.
pub unsafe extern "win64" fn crt_wcslen(s: *const u16) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0usize;
    // Pointer validation: cap to prevent walking into unmapped memory if the
    // guest passes a non-null-terminated string (e.g. from a crafted PE).
    const MAX_WCSLEN: usize = 1_048_576; // 1M wide chars = 2MB max
    while len < MAX_WCSLEN && unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}

/// wcscpy: copy a null-terminated UTF-16 string.
///
/// # Safety
/// `dst` must be writable for at least `wcslen(src)+1` u16 words.
/// `src` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn crt_wcscpy(dst: *mut u16, src: *const u16) -> *mut u16 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    let mut i = 0usize;
    loop {
        let c = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = c };
        if c == 0 {
            break;
        }
        i += 1;
    }
    dst
}

/// wcsncpy: copy up to n UTF-16 characters.
///
/// # Safety
/// `dst` must be writable for `n` u16 words. `src` must be valid.
pub unsafe extern "win64" fn crt_wcsncpy(dst: *mut u16, src: *const u16, n: usize) -> *mut u16 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }
    for i in 0..n {
        let c = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = c };
        if c == 0 {
            // Pad remainder with zeros
            for j in (i + 1)..n {
                unsafe { *dst.add(j) = 0 };
            }
            return dst;
        }
    }
    dst
}

/// wcscmp: compare two null-terminated UTF-16 strings.
///
/// # Safety
/// Both `s1` and `s2` must be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn crt_wcscmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    let mut i = 0usize;
    loop {
        let a = unsafe { *s1.add(i) };
        let b = unsafe { *s2.add(i) };
        if a != b {
            return (a as i32) - (b as i32);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

// ── Resolver ──────────────────────────────────────────────────────────────────

pub fn resolve(func: &str) -> Option<usize> {
    match func {
        // heap
        "malloc" => Some(crt_malloc as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "calloc" => Some(crt_calloc as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "free" => Some(crt_free as unsafe extern "win64" fn(_) as *const () as usize),
        "_set_new_mode" => Some(set_new_mode as *const () as usize),
        // private
        "memcpy" => {
            Some(crt_memcpy as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // runtime
        "_initterm" => Some(initterm as unsafe extern "win64" fn(_, _) as *const () as usize),
        "_initterm_e" => {
            Some(initterm_e as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "__p___argc" => Some(p___argc as *const () as usize),
        "__p___argv" => Some(p___argv as unsafe extern "win64" fn() -> _ as *const () as usize),
        "_configure_narrow_argv" => Some(configure_narrow_argv as *const () as usize),
        "_initialize_narrow_environment" => {
            Some(initialize_narrow_environment as *const () as usize)
        }
        "_set_app_type" => Some(set_app_type as *const () as usize),
        "_set_invalid_parameter_handler" => {
            Some(set_invalid_parameter_handler as *const () as usize)
        }
        "_crt_atexit" => Some(crt_atexit as *const () as usize),
        "_cexit" => Some(cexit as *const () as usize),
        "_exit" => Some(crt_exit_no_cleanup as *const () as usize),
        "exit" => Some(crt_exit as *const () as usize),
        "abort" => Some(crt_abort as *const () as usize),
        "signal" => Some(crt_signal as *const () as usize),
        // locale
        "_configthreadlocale" => Some(configthreadlocale as *const () as usize),
        // math
        "__setusermatherr" => Some(setusermatherr as *const () as usize),
        // environment / command line
        "__p__environ" => Some(p__environ as *const () as usize),
        "__p__acmdln" => Some(p__acmdln as *const () as usize),
        "__p__wcmdln" => Some(p__wcmdln as *const () as usize),
        // stdio
        "__acrt_iob_func" => Some(acrt_iob_func as *const () as usize),
        "__p__commode" => Some(p__commode as *const () as usize),
        "__p__fmode" => Some(p__fmode as *const () as usize),
        "__stdio_common_vfprintf" => Some(stdio_common_vfprintf as *const () as usize),
        "fflush" => Some(crt_fflush as *const () as usize),
        "setvbuf" => Some(crt_setvbuf as *const () as usize),
        // string
        "strlen" => Some(crt_strlen as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "strncmp" => {
            Some(crt_strncmp as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // wide string functions
        "wcslen" => Some(crt_wcslen as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "wcscpy" => Some(crt_wcscpy as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "wcsncpy" => {
            Some(crt_wcsncpy as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "wcscmp" => Some(crt_wcscmp as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        _ => None,
    }
}
