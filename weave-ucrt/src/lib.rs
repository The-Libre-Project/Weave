//! Stubs for the Windows Universal C Runtime (UCRT) and legacy MSVCRT.
//!
//! Windows apps compiled with MSVC or modern MinGW import C runtime functions
//! from a set of forwarding DLLs (`api-ms-win-crt-heap-l1-1-0.dll`, etc.) that
//! all redirect to `ucrtbase.dll`.  Weave implements the subset these apps
//! actually call, routing them to libc or providing minimal stubs.
//!
//! Handled DLL namespaces (case-insensitive):
//!   api-ms-win-crt-*   ucrtbase.dll   msvcrt.dll

use libc::c_void;

// ── Heap ──────────────────────────────────────────────────────────────────────

/// # Safety
/// No pointer requirements; wraps libc malloc. Caller must free the returned pointer with `ucrt_free`.
pub unsafe extern "win64" fn ucrt_malloc(size: usize) -> *mut c_void {
    let result = unsafe { libc::malloc(size) };
    if result.is_null() && size > 0 {
        eprintln!("weave: malloc({size}) returned NULL!");
    }
    result
}

/// # Safety
/// `ptr` must have been allocated by `ucrt_malloc`, `ucrt_calloc`, or `ucrt_realloc`, or be null.
pub unsafe extern "win64" fn ucrt_free(ptr: *mut c_void) {
    unsafe { libc::free(ptr) }
}

/// # Safety
/// No pointer requirements; wraps libc calloc. Caller must free the returned pointer with `ucrt_free`.
pub unsafe extern "win64" fn ucrt_calloc(count: usize, size: usize) -> *mut c_void {
    unsafe { libc::calloc(count, size) }
}

/// # Safety
/// `ptr` must have been allocated by `ucrt_malloc`, `ucrt_calloc`, or be null. Returned pointer must be freed with `ucrt_free`.
pub unsafe extern "win64" fn ucrt_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { libc::realloc(ptr, size) }
}

/// # Safety
/// No pointer requirements; wraps posix_memalign. Caller must free the returned pointer with `ucrt_aligned_free`.
pub unsafe extern "win64" fn ucrt_aligned_malloc(size: usize, alignment: usize) -> *mut c_void {
    unsafe {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = libc::posix_memalign(
            &mut ptr,
            alignment.max(std::mem::size_of::<*mut c_void>()),
            size,
        );
        if ret != 0 {
            std::ptr::null_mut()
        } else {
            ptr
        }
    }
}

/// # Safety
/// `ptr` must have been allocated by `ucrt_aligned_malloc`, or be null.
pub unsafe extern "win64" fn ucrt_aligned_free(ptr: *mut c_void) {
    unsafe { libc::free(ptr) }
}

pub extern "win64" fn ucrt_set_new_mode(_mode: i32) -> i32 {
    unsafe {
        libc::write(
            2,
            b"weave: stub _set_new_mode\n".as_ptr() as *const libc::c_void,
            26,
        )
    };
    0
}

// ── Memory ────────────────────────────────────────────────────────────────────

/// # Safety
/// `dst` must be writable for `n` bytes and must not overlap with `src`. `src` must be valid for `n` bytes.
pub unsafe extern "win64" fn ucrt_memcpy(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
) -> *mut c_void {
    unsafe { libc::memcpy(dst, src, n) }
}

/// # Safety
/// `dst` must be writable for `n` bytes. `src` must be valid for `n` bytes. Overlapping regions are permitted.
pub unsafe extern "win64" fn ucrt_memmove(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
) -> *mut c_void {
    unsafe { libc::memmove(dst, src, n) }
}

/// # Safety
/// `dst` must be writable for `n` bytes.
pub unsafe extern "win64" fn ucrt_memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { libc::memset(dst, c, n) }
}

/// # Safety
/// `s1` and `s2` must each be valid for `n` bytes.
pub unsafe extern "win64" fn ucrt_memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    unsafe { libc::memcmp(s1, s2, n) }
}

/// # Safety
/// `s` must be valid for `n` bytes.
pub unsafe extern "win64" fn ucrt_memchr(s: *const c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { libc::memchr(s, c, n) }
}

// ── Strings ───────────────────────────────────────────────────────────────────

/// # Safety
/// `s` must be a valid null-terminated byte string.
pub unsafe extern "win64" fn ucrt_strlen(s: *const u8) -> usize {
    unsafe { libc::strlen(s as _) }
}

/// # Safety
/// `s1` and `s2` must each be valid for at least `n` bytes, or null-terminated before `n`.
pub unsafe extern "win64" fn ucrt_strncmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe { libc::strncmp(s1 as _, s2 as _, n) }
}

/// # Safety
/// `s1` and `s2` must each be valid null-terminated byte strings.
pub unsafe extern "win64" fn ucrt_strcmp(s1: *const u8, s2: *const u8) -> i32 {
    unsafe { libc::strcmp(s1 as _, s2 as _) }
}

/// # Safety
/// `s` must be a valid null-terminated byte string.
pub unsafe extern "win64" fn ucrt_strchr(s: *const u8, c: i32) -> *mut u8 {
    unsafe { libc::strchr(s as _, c) as *mut u8 }
}

/// # Safety
/// `s` must be a valid null-terminated byte string. Caller must free the returned pointer with `ucrt_free`.
pub unsafe extern "win64" fn ucrt_strdup(s: *const u8) -> *mut u8 {
    unsafe { libc::strdup(s as _) as *mut u8 }
}

/// # Safety
/// `dst` must be writable for `n` bytes. `src` must be valid for `n` bytes or null-terminated before `n`.
pub unsafe extern "win64" fn ucrt_strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { libc::strncpy(dst as _, src as _, n) as *mut u8 }
}

/// # Safety
/// `s` must be valid for at least `maxlen` bytes.
pub unsafe extern "win64" fn ucrt_strnlen(s: *const u8, maxlen: usize) -> usize {
    unsafe {
        let mut i = 0;
        while i < maxlen && *s.add(i) != 0 {
            i += 1;
        }
        i
    }
}

/// # Safety
/// `s` must be a valid null-terminated UTF-16 (u16) string, or null.
pub unsafe extern "win64" fn ucrt_wcslen(s: *const u16) -> usize {
    if s.is_null() {
        return 0;
    }
    unsafe {
        let mut i = 0;
        while *s.add(i) != 0 {
            i += 1;
        }
        i
    }
}

/// # Safety
/// `s` must be valid for at least `maxlen` u16 units.
pub unsafe extern "win64" fn ucrt_wcsnlen(s: *const u16, maxlen: usize) -> usize {
    unsafe {
        let mut i = 0;
        while i < maxlen && *s.add(i) != 0 {
            i += 1;
        }
        i
    }
}

/// # Safety
/// `s` must be a valid null-terminated byte string. `endptr` must be writable if non-null.
pub unsafe extern "win64" fn ucrt_strtoul(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
    unsafe { libc::strtoul(s as _, endptr as _, base) as u64 }
}

// ── Wide strings ──────────────────────────────────────────────────────────────

/// # Safety
/// `s1` and `s2` must each be valid null-terminated UTF-16 (u16) strings.
pub unsafe extern "win64" fn ucrt_wcsicmp(s1: *const u16, s2: *const u16) -> i32 {
    unsafe {
        let mut i = 0usize;
        loop {
            let a = to_ascii_lower(*s1.add(i));
            let b = to_ascii_lower(*s2.add(i));
            if a != b {
                return a as i32 - b as i32;
            }
            if a == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

fn to_ascii_lower(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) {
        c + 32
    } else {
        c
    }
}

/// # Safety
/// `s1` and `s2` must each be valid for at least `n` u16 units, or null-terminated before `n`.
pub unsafe extern "win64" fn ucrt_wcsnicmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    unsafe {
        for i in 0..n {
            let a = to_ascii_lower(*s1.add(i));
            let b = to_ascii_lower(*s2.add(i));
            if a != b {
                return a as i32 - b as i32;
            }
            if a == 0 {
                return 0;
            }
        }
    }
    0
}

// ── Process / runtime ─────────────────────────────────────────────────────────

pub extern "win64" fn ucrt_exit(code: i32) -> ! {
    unsafe { libc::exit(code) }
}

#[allow(non_snake_case)]
pub extern "win64" fn ucrt__exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

pub extern "win64" fn ucrt_abort() -> ! {
    unsafe { libc::abort() }
}

pub extern "win64" fn ucrt_cexit() {
    unsafe {
        libc::write(
            2,
            b"weave: stub _cexit\n".as_ptr() as *const libc::c_void,
            19,
        )
    };
}

pub extern "win64" fn ucrt_set_app_type(_type: u32) {
    unsafe {
        libc::write(
            2,
            b"weave: stub __set_app_type\n".as_ptr() as *const libc::c_void,
            27,
        )
    };
}
pub extern "win64" fn ucrt_configure_narrow_argv(_mode: i32) -> i32 {
    unsafe {
        libc::write(
            2,
            b"weave: stub _configure_narrow_argv\n".as_ptr() as *const libc::c_void,
            35,
        )
    };
    0
}
pub extern "win64" fn ucrt_initialize_narrow_environment() -> i32 {
    unsafe {
        libc::write(
            2,
            b"weave: stub _initialize_narrow_environment\n".as_ptr() as *const libc::c_void,
            43,
        )
    };
    0
}
pub extern "win64" fn ucrt_set_invalid_parameter_handler(_fn: *const c_void) -> *const c_void {
    unsafe {
        libc::write(
            2,
            b"weave: stub _set_invalid_parameter_handler\n".as_ptr() as *const libc::c_void,
            43,
        )
    };
    std::ptr::null()
}
pub extern "win64" fn ucrt_configthreadlocale(_mode: i32) -> i32 {
    unsafe {
        libc::write(
            2,
            b"weave: stub _configthreadlocale\n".as_ptr() as *const libc::c_void,
            32,
        )
    };
    0
}
pub extern "win64" fn ucrt_setusermatherr(_fn: *const c_void) {
    unsafe {
        libc::write(
            2,
            b"weave: stub __setusermatherr\n".as_ptr() as *const libc::c_void,
            29,
        )
    };
}

// ── _initterm / _initterm_e — runs C++ static constructors ───────────────────
//
// Each entry is a function pointer (or NULL/padding).  _initterm calls void()
// functions; _initterm_e calls int() functions and aborts on non-zero return.

/// # Safety
/// `start` and `end` must be valid pointers into a table of function pointers (or null entries). Each non-null entry must be callable as `extern "win64" fn()`.
pub unsafe extern "win64" fn ucrt_initterm(start: *const *const c_void, end: *const *const c_void) {
    unsafe {
        libc::write(
            2,
            b"weave: stub _initterm\n".as_ptr() as *const libc::c_void,
            22,
        );
        let mut p = start;
        while p < end {
            let fn_ptr = *p;
            if !fn_ptr.is_null() {
                // SAFETY: `fn_ptr` is a non-null entry read from the CRT initialiser
                // table (`__xi_a`/`__xi_z` or `__xc_a`/`__xc_z`).  The MSVC/MinGW
                // UCRT ABI guarantees every such non-null slot holds the address of a
                // `void ()(void)` function compiled with the Win64 calling convention,
                // matching the `extern "win64" fn()` signature.  The caller's `# Safety`
                // precondition requires `start`..`end` to be a valid table, making the
                // cast from `*const c_void` to fn pointer sound.
                let f: extern "win64" fn() = std::mem::transmute(fn_ptr);
                f();
            }
            p = p.add(1);
        }
    }
}

/// # Safety
/// `start` and `end` must be valid pointers into a table of function pointers (or null entries). Each non-null entry must be callable as `extern "win64" fn() -> i32`.
pub unsafe extern "win64" fn ucrt_initterm_e(
    start: *const *const c_void,
    end: *const *const c_void,
) -> i32 {
    unsafe {
        libc::write(
            2,
            b"weave: stub _initterm_e\n".as_ptr() as *const libc::c_void,
            24,
        );
        let mut p = start;
        while p < end {
            let fn_ptr = *p;
            if !fn_ptr.is_null() {
                // SAFETY: `fn_ptr` is a non-null entry from the error-checked CRT
                // initialiser table used by `_initterm_e`.  The MSVC/MinGW UCRT ABI
                // specifies every non-null slot holds an `int ()(void)` function
                // compiled with the Win64 calling convention, matching `extern "win64"
                // fn() -> i32`.  The caller's `# Safety` precondition on `start`..`end`
                // ensures the table is valid, making the cast from `*const c_void` to
                // this fn-pointer type sound.
                let f: extern "win64" fn() -> i32 = std::mem::transmute(fn_ptr);
                let ret = f();
                if ret != 0 {
                    return ret;
                }
            }
            p = p.add(1);
        }
    }
    0
}

pub extern "win64" fn ucrt_crt_atexit(_fn: *const c_void) -> i32 {
    unsafe {
        libc::write(
            2,
            b"weave: stub _crt_atexit\n".as_ptr() as *const libc::c_void,
            24,
        )
    };
    0
}

pub extern "win64" fn ucrt_register_onexit_function(
    _table: *mut c_void,
    _fn: *const c_void,
) -> i32 {
    0
}

pub extern "win64" fn ucrt_execute_onexit_table(_table: *mut c_void) -> i32 {
    0
}

pub extern "win64" fn ucrt_initialize_onexit_table(_table: *mut c_void) -> i32 {
    0
}

/// signal — install a CRT signal handler; returns previous handler.
///
/// Wine ref: dlls/msvcrt/except.c:655 — validates sig is in the Windows-specific set
/// {SIGABRT=22,SIGFPE=8,SIGILL=4,SIGSEGV=11,SIGINT=2,SIGTERM=15,SIGBREAK=21}; stores
/// the new handler and returns the previous one. Unknown sig → SIG_ERR (-1 as ptr).
/// func==SIG_ERR returns SIG_ERR immediately without storing.
/// Weave returns SIG_DFL (null) as the "previous handler" on all valid signals (correct
/// for program startup), and usize::MAX as *const c_void (SIG_ERR) for invalid signals.
pub extern "win64" fn ucrt_signal(signum: i32, handler: *const c_void) -> *const c_void {
    // SIG_ERR passed as new handler → return SIG_ERR immediately (Wine behaviour).
    if handler as usize == usize::MAX {
        return usize::MAX as *const c_void;
    }
    // Windows CRT signal numbers (NOT POSIX — e.g. SIGABRT=22 not 6).
    match signum {
        2  // SIGINT
        | 4  // SIGILL
        | 8  // SIGFPE
        | 11 // SIGSEGV
        | 15 // SIGTERM
        | 21 // SIGBREAK (Windows Ctrl+Break — never generated on Linux, but valid to register)
        | 22 // SIGABRT
        => std::ptr::null(), // SIG_DFL — correct "previous handler" at program start
        _ => usize::MAX as *const c_void, // SIG_ERR
    }
}

// ── CRT global variable accessors ─────────────────────────────────────────────
//
// These accessors return pointers to CRT-global variables (__p___argc, etc.).
// The MinGW CRT startup writes through these pointers, so the storage MUST be
// writable.  Rust `static mut` can end up in a linker section that becomes
// read-only after RELRO is applied, causing SIGSEGV.  We heap-allocate the
// storage via Box::into_raw (leaked intentionally — process-lifetime) which
// guarantees the memory is always in a R+W page.

use std::sync::OnceLock;

static HEAP_COMMODE: OnceLock<usize> = OnceLock::new();
static HEAP_FMODE: OnceLock<usize> = OnceLock::new();
static HEAP_STDIO: OnceLock<[usize; 3]> = OnceLock::new();
/// Contiguous fake FILE[3] array for the msvcrt `_iob` DATA import.
/// 64 bytes per slot — generous enough for any MSVC FILE struct layout.
static IOB_ARRAY: OnceLock<Box<[u8; 192]>> = OnceLock::new();

/// Return the address of writable _fmode storage for DATA imports.
///
/// When MinGW imports `_fmode` from msvcrt.dll, the IAT slot should contain the
/// ADDRESS of an `int` variable (not a function pointer).  MinGW's internal
/// `__p__fmode()` wrapper simply returns this IAT value.
pub fn fmode_data_addr() -> usize {
    *HEAP_FMODE.get_or_init(|| Box::into_raw(Box::new(0i32)) as usize)
}

/// Return the address of writable _commode storage for DATA imports.
pub fn commode_data_addr() -> usize {
    *HEAP_COMMODE.get_or_init(|| Box::into_raw(Box::new(0i32)) as usize)
}

static HEAP_MB_CUR_MAX: OnceLock<usize> = OnceLock::new();
static HEAP_INITENV: OnceLock<usize> = OnceLock::new();
static HEAP_WINITENV: OnceLock<usize> = OnceLock::new();
static HEAP_ENVIRON: OnceLock<usize> = OnceLock::new();
static HEAP_WENVIRON: OnceLock<usize> = OnceLock::new();
static HEAP_IARGC: OnceLock<usize> = OnceLock::new();
static HEAP_IARGV: OnceLock<usize> = OnceLock::new();
static HEAP_ACMDLN: OnceLock<usize> = OnceLock::new();
static HEAP_WCMDLN: OnceLock<usize> = OnceLock::new();
static HEAP_PGMPTR: OnceLock<usize> = OnceLock::new();
static HEAP_WPGMPTR: OnceLock<usize> = OnceLock::new();
static HEAP_DOSERRNO: OnceLock<usize> = OnceLock::new();

/// Return the address of writable __mb_cur_max storage for DATA imports.
pub fn mb_cur_max_data_addr() -> usize {
    *HEAP_MB_CUR_MAX.get_or_init(|| Box::into_raw(Box::new(1i32)) as usize)
}

// DATA import address helpers — these return a heap address to put in the IAT slot.
// MinGW CRT startup code dereferences the IAT slot to get a data pointer, then
// writes through it. Putting a function pointer there causes a SIGSEGV because
// code pages are not writable.
pub fn initenv_data_addr() -> usize {
    *HEAP_INITENV.get_or_init(|| Box::into_raw(Box::new(0usize)) as usize)
}
pub fn winitenv_data_addr() -> usize {
    *HEAP_WINITENV.get_or_init(|| Box::into_raw(Box::new(0usize)) as usize)
}
pub fn environ_data_addr() -> usize {
    *HEAP_ENVIRON.get_or_init(|| Box::into_raw(Box::new(0usize)) as usize)
}
pub fn wenviron_data_addr() -> usize {
    *HEAP_WENVIRON.get_or_init(|| Box::into_raw(Box::new(0usize)) as usize)
}
pub fn argc_data_addr() -> usize {
    *HEAP_IARGC.get_or_init(|| Box::into_raw(Box::new(0i32)) as usize)
}
pub fn argv_data_addr() -> usize {
    *HEAP_IARGV.get_or_init(|| Box::into_raw(Box::new(0usize)) as usize)
}
pub fn acmdln_data_addr() -> usize {
    *HEAP_ACMDLN.get_or_init(|| {
        // _acmdln is msvcrt's ANSI command-line variable (a `char*`).
        // Double-dereference pattern: r11 = &_acmdln (IAT slot), r8 = *r11 (the char*).
        // Point at the shared cmdline from weave-core so it reflects real argv.
        let ptr = weave_core::cmdline::get_a() as usize;
        Box::into_raw(Box::new(ptr)) as usize
    })
}
pub fn wcmdln_data_addr() -> usize {
    *HEAP_WCMDLN.get_or_init(|| {
        // _wcmdln is msvcrt's wide command-line variable (a `wchar_t*`).
        let ptr = weave_core::cmdline::get_w() as usize;
        Box::into_raw(Box::new(ptr)) as usize
    })
}
pub fn pgmptr_data_addr() -> usize {
    *HEAP_PGMPTR.get_or_init(|| Box::into_raw(Box::new(0usize)) as usize)
}
pub fn wpgmptr_data_addr() -> usize {
    *HEAP_WPGMPTR.get_or_init(|| Box::into_raw(Box::new(0usize)) as usize)
}
pub fn doserrno_data_addr() -> usize {
    *HEAP_DOSERRNO.get_or_init(|| Box::into_raw(Box::new(0u32)) as usize)
}

/// # Safety
/// No pointer requirements; returns a pointer to heap-allocated CRT storage.
pub unsafe extern "win64" fn ucrt_p_argc() -> *mut i32 {
    libc::write(
        2,
        b"weave: stub __p__argc\n".as_ptr() as *const libc::c_void,
        22,
    );
    argc_data_addr() as *mut i32
}
/// # Safety
/// No pointer requirements; returns a pointer to heap-allocated CRT storage.
pub unsafe extern "win64" fn ucrt_p_argv() -> *mut *mut *mut u8 {
    libc::write(
        2,
        b"weave: stub __p__argv\n".as_ptr() as *const libc::c_void,
        22,
    );
    argv_data_addr() as *mut *mut *mut u8
}
/// # Safety
/// No pointer requirements; returns a pointer to heap-allocated CRT storage.
pub unsafe extern "win64" fn ucrt_p_acmdln() -> *mut *mut u8 {
    libc::write(
        2,
        b"weave: stub __p__acmdln\n".as_ptr() as *const libc::c_void,
        24,
    );
    acmdln_data_addr() as *mut *mut u8
}
/// # Safety
/// No pointer requirements; returns a pointer to heap-allocated CRT storage.
pub unsafe extern "win64" fn ucrt_p_environ() -> *mut *mut *mut u8 {
    libc::write(
        2,
        b"weave: stub __p__environ\n".as_ptr() as *const libc::c_void,
        25,
    );
    environ_data_addr() as *mut *mut *mut u8
}
/// # Safety
/// No pointer requirements; returns a pointer to heap-allocated CRT storage.
pub unsafe extern "win64" fn ucrt_p_commode() -> *mut i32 {
    libc::write(
        2,
        b"weave: stub __p__commode\n".as_ptr() as *const libc::c_void,
        25,
    );
    *HEAP_COMMODE.get_or_init(|| Box::into_raw(Box::new(0i32)) as usize) as *mut i32
}
/// # Safety
/// No pointer requirements; returns a pointer to heap-allocated CRT storage.
pub unsafe extern "win64" fn ucrt_p_fmode() -> *mut i32 {
    libc::write(
        2,
        b"weave: stub __p__fmode\n".as_ptr() as *const libc::c_void,
        23,
    );
    *HEAP_FMODE.get_or_init(|| Box::into_raw(Box::new(0i32)) as usize) as *mut i32
}

/// Return the address of the fake `_iob` array (DATA import for msvcrt.dll).
///
/// `_iob` in msvcrt.dll is a contiguous array of FILE structs. The IAT slot
/// holds the array's base address directly (not address-of-pointer).
/// 7-Zip and other msvcrt.dll users access stdin/stdout/stderr as `_iob + N*64`.
pub fn iob_data_addr() -> usize {
    IOB_ARRAY.get_or_init(|| Box::new([0u8; 192])).as_ptr() as usize
}

/// Map a FILE* to a Linux fd number.
///
/// Assumes 64-byte stride between _iob entries. Falls back to fd 1 (stdout)
/// for any unrecognised pointer — sufficient for archive listing output.
fn stream_to_fd(stream: *const c_void) -> i32 {
    let base = iob_data_addr();
    let s = stream as usize;
    if s == base {
        return 0; // stdin
    }
    if s == base + 64 {
        return 1; // stdout
    }
    if s == base + 128 {
        return 2; // stderr
    }
    1 // default: stdout
}

// ── stdio ─────────────────────────────────────────────────────────────────────

/// fputc — write a character to a FILE stream.
///
/// Routes to the Linux fd corresponding to the FILE* from `_iob`.
///
/// # Safety
/// `stream` must be a valid pointer (may be one of the fake `_iob` entries).
pub unsafe extern "win64" fn ms_fputc(c: i32, stream: *mut c_void) -> i32 {
    let fd = stream_to_fd(stream);
    let byte = c as u8;
    unsafe { libc::write(fd, &byte as *const u8 as *const libc::c_void, 1) };
    c & 0xFF
}

/// fputs — write a null-terminated string to a FILE stream.
///
/// # Safety
/// `s` must be a valid null-terminated ANSI string or null.
pub unsafe extern "win64" fn ms_fputs(s: *const u8, stream: *mut c_void) -> i32 {
    if s.is_null() {
        return -1;
    }
    let fd = stream_to_fd(stream);
    let mut len = 0usize;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
        if len > 0 {
            libc::write(fd, s as *const libc::c_void, len);
        }
    }
    0
}

/// fgetc — read a character from a FILE stream. Returns EOF (-1) as stub.
///
/// # Safety
/// `stream` is accepted but stdin reads are not implemented.
pub unsafe extern "win64" fn ms_fgetc(_stream: *mut c_void) -> i32 {
    -1 // EOF
}

/// fflush — flush a FILE stream. Returns 0 (success). No-op stub.
///
/// # Safety
/// `stream` is ignored.
pub unsafe extern "win64" fn ms_fflush(_stream: *mut c_void) -> i32 {
    0
}

pub extern "win64" fn ucrt_acrt_iob_func(fd: u32) -> *mut c_void {
    // Heap-allocated 256-byte buffers for fake FILE structs.  MinGW CRT writes
    // into these immediately after calling __acrt_iob_func; heap memory is
    // always R+W so this avoids the RELRO SIGSEGV issue with static mut.
    let ptrs = HEAP_STDIO.get_or_init(|| {
        [
            Box::into_raw(Box::new([0u8; 256])) as usize,
            Box::into_raw(Box::new([0u8; 256])) as usize,
            Box::into_raw(Box::new([0u8; 256])) as usize,
        ]
    });
    unsafe {
        libc::write(
            2,
            b"weave: stub __acrt_iob_func\n".as_ptr() as *const libc::c_void,
            28,
        )
    };
    match fd {
        0 => ptrs[0] as *mut c_void,
        1 => ptrs[1] as *mut c_void,
        2 => ptrs[2] as *mut c_void,
        _ => std::ptr::null_mut(),
    }
}

/// _amsg_exit — abnormal CRT termination (e.g. failed _onexit registration).
/// Never returns — exits immediately.
pub extern "win64" fn ucrt_amsg_exit(_msg_num: i32) -> ! {
    unsafe { libc::exit(255) }
}

/// _onexit — register a function to be called at process exit.
///
/// On success returns the passed function pointer; NULL on failure.
/// We don't maintain a real atexit list — just return the pointer so
/// MinGW CRT startup sees "success" and doesn't call _amsg_exit.
pub extern "win64" fn ucrt_onexit(fn_ptr: usize) -> usize {
    fn_ptr
}

/// fprintf — formatted print to a FILE* (legacy msvcrt.dll variant).
///
/// We can't safely bridge the variadic Windows ABI to Linux, so this is a
/// no-op stub. hello.exe never calls fprintf directly — the CRT startup only
/// uses it on error paths that we bypass by making _onexit succeed.
pub extern "win64" fn ucrt_fprintf(_stream: *mut c_void, _fmt: *const u8) -> i32 {
    -1
}

/// vfprintf — variadic-list variant of fprintf.
pub extern "win64" fn ucrt_vfprintf(
    _stream: *mut c_void,
    _fmt: *const u8,
    _args: *mut c_void,
) -> i32 {
    -1
}

/// fwrite — write binary data to a FILE* (legacy msvcrt.dll variant).
///
/// # Safety
/// `ptr` must be valid for `size * count` bytes.
pub unsafe extern "win64" fn ucrt_fwrite(
    ptr: *const c_void,
    size: usize,
    count: usize,
    stream: *mut c_void,
) -> usize {
    if ptr.is_null() || size == 0 || count == 0 {
        return 0;
    }
    let fd = stream_to_fd(stream);
    let total = size.saturating_mul(count);
    let n = unsafe { libc::write(fd, ptr, total) };
    if n > 0 {
        n as usize / size
    } else {
        0
    }
}

pub extern "win64" fn ucrt_stdio_common_vfprintf(
    _options: u64,
    _stream: *mut c_void,
    _format: *const u8,
    _locale: *const c_void,
    _args: *mut c_void,
) -> i32 {
    0
}

pub extern "win64" fn ucrt_stdio_common_vsprintf(
    _options: u64,
    _buf: *mut u8,
    _buf_count: usize,
    _format: *const u8,
    _locale: *const c_void,
    _args: *mut c_void,
) -> i32 {
    0
}

/// # Safety
/// `stream` must be a valid `FILE*` obtained from a libc-backed stdio function, or null to flush all streams.
pub unsafe extern "win64" fn ucrt_fflush(stream: *mut c_void) -> i32 {
    // Pass the stream through. NULL flushes all (per C standard); non-NULL flushes that stream.
    // This is correct when stream is a FILE* obtained from our libc-backed stubs.
    unsafe { libc::fflush(stream as *mut libc::FILE) };
    0
}

pub extern "win64" fn ucrt_setvbuf(
    _stream: *mut c_void,
    _buf: *mut u8,
    _mode: i32,
    _size: usize,
) -> i32 {
    unsafe {
        libc::write(
            2,
            b"weave: stub setvbuf\n".as_ptr() as *const libc::c_void,
            20,
        )
    };
    0
}

pub extern "win64" fn ucrt_errno() -> *mut i32 {
    unsafe { libc::__errno_location() }
}

/// strerror — return a pointer to the error message string for errnum.
///
/// Wine ref: dlls/msvcrt/errno.c:272 — uses a thread-local 256-byte buffer; copies from
/// _sys_errlist[]; clamps out-of-range errnum to _sys_nerr ("Unknown error").
/// Weave delegates to libc strerror() which uses the same POSIX error table and manages
/// its own thread-local buffer. Returns non-null for all valid errnum values.
pub extern "win64" fn ucrt_strerror(errnum: i32) -> *mut u8 {
    // libc strerror() returns a pointer to a static/thread-local C string — valid to return.
    unsafe { libc::strerror(errnum) as *mut u8 }
}

/// # Safety
/// `_expr` and `_file` must be valid null-terminated byte strings if non-null (they are not read — this stub calls abort immediately).
pub unsafe extern "win64" fn ucrt_assert(_expr: *const u8, _file: *const u8, _line: u32) {
    unsafe { libc::abort() }
}

/// _beginthreadex — create a Windows thread.
///
/// Returns a fake non-zero handle (1) so callers treat thread creation as
/// successful. The thread never actually runs; WaitForSingleObject(1) returns
/// WAIT_OBJECT_0 immediately, which is correct for single-threaded listing
/// mode where worker threads sit idle anyway.
/// # Safety
/// `thread_id` must be null or a valid pointer to a writable `u32`.
pub unsafe extern "win64" fn ucrt_beginthreadex(
    _security: *const c_void,
    _stack_size: u32,
    _start: *const c_void,
    _arg: *const c_void,
    _flags: u32,
    thread_id: *mut u32,
) -> usize {
    unsafe {
        libc::write(
            2,
            b"weave: stub _beginthreadex -> 1\n".as_ptr() as *const libc::c_void,
            31,
        );
    }
    if !thread_id.is_null() {
        unsafe { *thread_id = 1 };
    }
    1 // fake thread handle — WaitForSingleObject(1) returns WAIT_OBJECT_0
}

pub extern "win64" fn ucrt_endthreadex(_exit_code: u32) {}

/// `__intrinsic_setjmpex` — save the SEH frame pointer to jmp_buf->Frame.
///
/// Wine ref: dlls/ntdll/signal_x86_64.c — __wine_setjmpex saves frame (RDX in Win64)
/// to jmp_buf->Frame at offset 0x00.  The integer registers are already saved inline
/// by the compiler before this function is called.
///
/// Weave: we write 0 to buf->Frame so that longjmp always takes the direct
/// register-restore path instead of the RtlUnwind path.  This is safe because
/// our longjmp implementation does a full register restore and does not need the
/// SEH unwind machinery.
///
/// # Safety
/// `buf` must be a valid, writable pointer to a `JUMP_BUFFER` (at least 8 bytes).
pub unsafe extern "win64" fn ucrt_intrinsic_setjmpex(
    buf: *mut c_void,
    _frame: *const c_void,
) -> i32 {
    // Zero buf->Frame so longjmp skips RtlUnwind and restores registers directly.
    unsafe { *(buf as *mut u64) = 0 };
    0
}

/// `longjmp` — restore CPU state saved by `setjmp` and return `val` to the caller.
///
/// Wine ref: dlls/ntdll/signal_x86_64.c — longjmp_regs (direct-restore path, Frame==0):
///   restore Rbx/Rbp/Rsi/Rdi/R12-R15 from jmp_buf offsets 0x08/0x18/0x20/0x28/0x30-0x48,
///   restore Rsp from 0x10, jump to Rip at 0x50.
///
/// MSVC _JUMP_BUFFER x64 layout (include/msvcrt/setjmp.h):
///   +0x00 Frame  +0x08 Rbx  +0x10 Rsp  +0x18 Rbp
///   +0x20 Rsi   +0x28 Rdi  +0x30 R12  +0x38 R13
///   +0x40 R14   +0x48 R15  +0x50 Rip  +0x58 MxCsr  +0x5c FpCsr
///   +0x60 Xmm6  +0x70 Xmm7  +0x80 Xmm8  +0x90 Xmm9
///   +0xa0 Xmm10 +0xb0 Xmm11 +0xc0 Xmm12 +0xd0 Xmm13
///   +0xe0 Xmm14 +0xf0 Xmm15
///
/// XMM6–XMM15 are non-volatile (callee-save) in Win64. MSVC's setjmp inline-saves
/// them so longjmp must restore them — otherwise those registers are corrupted
/// on return, which is fatal if NPP's longjmp recovery path uses them.
///
/// Win64 entry: RCX = jmp_buf ptr, EDX = retval
///
/// # Safety
/// `buf` must point to a `JUMP_BUFFER` previously initialised by `setjmp`/`__intrinsic_setjmpex`.
/// This function never returns — it restores CPU state and jumps to the saved `Rip`.
#[unsafe(naked)]
pub unsafe extern "win64" fn ucrt_longjmp(_buf: *mut c_void, _val: i32) -> ! {
    core::arch::naked_asm!(
        // C standard: if retval == 0, force to 1
        "test  edx, edx",
        "jnz   1f",
        "mov   edx, 1",
        "1:",
        "mov   rax, rdx", // rax = return value (preserved through all restores)
        "mov   rbx, qword ptr [rcx + 0x08]", // restore Rbx
        "mov   rbp, qword ptr [rcx + 0x18]", // restore Rbp
        "mov   rsi, qword ptr [rcx + 0x20]", // restore Rsi
        "mov   rdi, qword ptr [rcx + 0x28]", // restore Rdi
        "mov   r12, qword ptr [rcx + 0x30]", // restore R12
        "mov   r13, qword ptr [rcx + 0x38]", // restore R13
        "mov   r14, qword ptr [rcx + 0x40]", // restore R14
        "mov   r15, qword ptr [rcx + 0x48]", // restore R15
        "mov   r11, qword ptr [rcx + 0x50]", // r11 = saved Rip (jump target)
        "ldmxcsr dword ptr [rcx + 0x58]", // restore MxCsr
        "fnclex",         // clear FPU exceptions
        "fldcw  word ptr [rcx + 0x5c]", // restore FpCsr
        // Restore non-volatile XMM registers (XMM6–XMM15, 16 bytes each at +0x60)
        "movdqu xmm6,  xmmword ptr [rcx + 0x60]",
        "movdqu xmm7,  xmmword ptr [rcx + 0x70]",
        "movdqu xmm8,  xmmword ptr [rcx + 0x80]",
        "movdqu xmm9,  xmmword ptr [rcx + 0x90]",
        "movdqu xmm10, xmmword ptr [rcx + 0xa0]",
        "movdqu xmm11, xmmword ptr [rcx + 0xb0]",
        "movdqu xmm12, xmmword ptr [rcx + 0xc0]",
        "movdqu xmm13, xmmword ptr [rcx + 0xd0]",
        "movdqu xmm14, xmmword ptr [rcx + 0xe0]",
        "movdqu xmm15, xmmword ptr [rcx + 0xf0]",
        "mov   rsp, qword ptr [rcx + 0x10]", // restore Rsp LAST (rcx now invalid)
        "jmp   r11",                         // jump to saved Rip
    )
}

// locale / multibyte stubs
pub extern "win64" fn ucrt_mb_cur_max_func() -> usize {
    1
}
pub extern "win64" fn ucrt_localeconv() -> *const c_void {
    std::ptr::null()
}
/// setlocale — set or query the locale for the given category.
///
/// Wine ref: dlls/msvcrt/locale.c:2015 — LC_MIN/LC_MAX bounds check → NULL on bad category;
/// NULL locale queries and returns the current locale name string; "C"/"POSIX" sets C locale.
/// Weave always reports the "C" locale — full locale switching is not implemented.
/// Apps that check `setlocale(LC_ALL, "") != NULL` will now get a valid non-null return.
pub extern "win64" fn ucrt_setlocale(_cat: i32, _locale: *const u8) -> *mut u8 {
    // Return pointer to static "C\0" string. Safe: static lifetime, read-only by callers.
    static C_LOCALE: &[u8] = b"C\0";
    C_LOCALE.as_ptr() as *mut u8
}
/// # Safety
/// No pointer requirements; `c` is passed by value.
pub unsafe extern "win64" fn ucrt_btowc(c: i32) -> u32 {
    c as u32
}
/// # Safety
/// No pointer requirements; `c` is passed by value.
pub unsafe extern "win64" fn ucrt_wctob(c: u32) -> i32 {
    if c <= 0xFF {
        c as i32
    } else {
        -1
    }
}
/// # Safety
/// `_pwc` must be writable if non-null. `_s` must be valid for `_n` bytes if non-null. `_ps` is accepted but not read.
pub unsafe extern "win64" fn ucrt_mbrtowc(
    _pwc: *mut u16,
    _s: *const u8,
    _n: usize,
    _ps: *mut c_void,
) -> usize {
    0
}
/// # Safety
/// `_dst` must be writable for `_n` u16 units if non-null. `_src` must point to a valid string pointer if non-null. `_ps` is accepted but not read.
pub unsafe extern "win64" fn ucrt_mbsrtowcs(
    _dst: *mut u16,
    _src: *mut *const u8,
    _n: usize,
    _ps: *mut c_void,
) -> usize {
    0
}
/// # Safety
/// `_s` must be writable for at least one byte if non-null. `_ps` is accepted but not read.
pub unsafe extern "win64" fn ucrt_wcrtomb(_s: *mut u8, _wc: u16, _ps: *mut c_void) -> usize {
    0
}

/// towlower — convert a wide character to lowercase.
///
/// Wine ref: dlls/ntdll/locale.c:846 — ch >= 0x100 returned unchanged; otherwise uses
/// casemap(LowerCaseTable, ch). Weave implements the ASCII [A-Z] and Latin-1 uppercase
/// blocks (À–Ö 0xC0–0xD6, Ø–Þ 0xD8–0xDE) which map to lowercase by +0x20.
/// Codepoints >= 0x100 returned unchanged (matching Wine's early-exit).
pub extern "win64" fn ucrt_towlower(c: u32) -> u32 {
    let ch = c as u16;
    if (b'A' as u16..=b'Z' as u16).contains(&ch) {
        return (ch + 0x20) as u32;
    }
    // Latin-1 uppercase: À(0xC0)–Ö(0xD6) and Ø(0xD8)–Þ(0xDE) → lowercase +0x20
    if (0xC0u16..=0xD6).contains(&ch) || (0xD8u16..=0xDE).contains(&ch) {
        return (ch + 0x20) as u32;
    }
    c // includes ch >= 0x100: returned unchanged per Wine
}

/// towupper — convert a wide character to uppercase.
///
/// Wine ref: dlls/ntdll/locale.c:856 — uses casemap(UpperCaseTable, ch) if table loaded,
/// else casemap_ascii (ASCII only). Weave implements ASCII [a-z] and Latin-1 lowercase
/// blocks (à–ö 0xE0–0xF6, ø–þ 0xF8–0xFE) which map to uppercase by -0x20.
pub extern "win64" fn ucrt_towupper(c: u32) -> u32 {
    let ch = c as u16;
    if (b'a' as u16..=b'z' as u16).contains(&ch) {
        return (ch - 0x20) as u32;
    }
    // Latin-1 lowercase: à(0xE0)–ö(0xF6) and ø(0xF8)–þ(0xFE) → uppercase -0x20
    if (0xE0u16..=0xF6).contains(&ch) || (0xF8u16..=0xFEu16).contains(&ch) {
        return (ch - 0x20) as u32;
    }
    c
}

// math
pub extern "win64" fn ucrt_powf(x: f32, y: f32) -> f32 {
    x.powf(y)
}

// filesystem stubs
pub extern "win64" fn ucrt_lock_file(_stream: *mut c_void) {}
pub extern "win64" fn ucrt_unlock_file(_stream: *mut c_void) {}
pub extern "win64" fn ucrt_remove(_path: *const u8) -> i32 {
    0
}
pub extern "win64" fn ucrt_fstat64(_fd: i32, _stat: *mut c_void) -> i32 {
    -1
}
pub extern "win64" fn ucrt_fdopen(_fd: i32, _mode: *const u8) -> *mut c_void {
    std::ptr::null_mut()
}

/// _fseeki64 / fseek — seek to a position in a libc-backed FILE stream.
///
/// # Safety
/// `stream` must be a valid `FILE*` obtained from `ucrt_fopen` or `ucrt_wfopen`.
pub unsafe extern "win64" fn ucrt_fseeki64(stream: *mut c_void, offset: i64, origin: i32) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fseeko(stream as *mut libc::FILE, offset as libc::off_t, origin) }
}

/// _ftelli64 / ftell — return the current position in a libc-backed FILE stream.
///
/// # Safety
/// `stream` must be a valid `FILE*` obtained from `ucrt_fopen` or `ucrt_wfopen`.
pub unsafe extern "win64" fn ucrt_ftelli64(stream: *mut c_void) -> i64 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::ftello(stream as *mut libc::FILE) as i64 }
}

pub extern "win64" fn ucrt_get_osfhandle(_fd: i32) -> isize {
    -1
}

// ── CRT stdio file I/O (fopen / fread / fclose / feof / ferror) ───────────────

/// Helper: decode a null-terminated UTF-16 string (up to `max_len` chars).
/// Returns None if the pointer is null or the string exceeds `max_len`.
fn decode_wide(ptr: *const u16, max_len: usize) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while len < max_len && *ptr.add(len) != 0 {
            len += 1;
        }
    }
    if len >= max_len {
        return None;
    }
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(ptr, len)
    }))
}

/// fopen — open a file by narrow (ANSI/UTF-8) path, translating the Windows
/// path to its Linux equivalent.
///
/// # Safety
/// `path` must be a valid null-terminated byte string. `mode` must be a valid
/// null-terminated ASCII mode string (e.g. "r", "rb", "w").
pub unsafe extern "win64" fn ucrt_fopen(path: *const u8, mode: *const u8) -> *mut c_void {
    use std::os::unix::ffi::OsStrExt;
    if path.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }
    let win_path = unsafe {
        let len = libc::strlen(path as *const libc::c_char);
        String::from_utf8_lossy(std::slice::from_raw_parts(path, len)).into_owned()
    };
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };
    let path_cstr = match std::ffi::CString::new(linux_path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let result = unsafe { libc::fopen(path_cstr.as_ptr(), mode as *const libc::c_char) };
    result as *mut c_void
}

/// _wfopen — open a file by wide (UTF-16) path, translating the Windows path
/// to its Linux equivalent.
///
/// # Safety
/// `path` must be a valid null-terminated UTF-16 string. `mode` must be a
/// valid null-terminated UTF-16 mode string (e.g. L"r", L"rb").
pub unsafe extern "win64" fn ucrt_wfopen(path: *const u16, mode: *const u16) -> *mut c_void {
    use std::os::unix::ffi::OsStrExt;
    let win_path = match decode_wide(path, 32_768) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let mode_str = match decode_wide(mode, 64) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };
    let path_cstr = match std::ffi::CString::new(linux_path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let mode_cstr = match std::ffi::CString::new(mode_str.as_bytes()) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let result = unsafe { libc::fopen(path_cstr.as_ptr(), mode_cstr.as_ptr()) };
    result as *mut c_void
}

/// fread — read `count` items of `size` bytes from a libc-backed FILE stream.
///
/// # Safety
/// `buf` must be writable for `size * count` bytes. `stream` must be a valid
/// `FILE*` obtained from `ucrt_fopen` or `ucrt_wfopen`.
pub unsafe extern "win64" fn ucrt_fread(
    buf: *mut c_void,
    size: usize,
    count: usize,
    stream: *mut c_void,
) -> usize {
    if buf.is_null() || stream.is_null() || size == 0 {
        return 0;
    }
    unsafe { libc::fread(buf, size, count, stream as *mut libc::FILE) }
}

/// fclose — close a libc-backed FILE stream.
///
/// # Safety
/// `stream` must be a valid `FILE*` obtained from `ucrt_fopen` or `ucrt_wfopen`.
pub unsafe extern "win64" fn ucrt_fclose(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { libc::fclose(stream as *mut libc::FILE) }
}

/// feof — test end-of-file indicator on a libc-backed FILE stream.
///
/// # Safety
/// `stream` must be a valid `FILE*`.
pub unsafe extern "win64" fn ucrt_feof(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return 1;
    }
    unsafe { libc::feof(stream as *mut libc::FILE) }
}

/// ferror — test error indicator on a libc-backed FILE stream.
///
/// # Safety
/// `stream` must be a valid `FILE*`.
pub unsafe extern "win64" fn ucrt_ferror(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return 1;
    }
    unsafe { libc::ferror(stream as *mut libc::FILE) }
}

// __C_specific_handler — identical stub as in kernel32
pub extern "win64" fn ucrt_c_specific_handler(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    1 // ExceptionContinueSearch
}

/// rand_s — generate a cryptographically secure random 32-bit value.
///
/// Wine ref: dlls/msvcrt/misc.c — null pval → sets *_errno()=EINVAL, returns EINVAL.
/// On success calls RtlGenRandom(pval, 4) and returns 0.
/// Weave uses the getrandom(2) syscall (Linux 3.17+) as the equivalent of RtlGenRandom.
///
/// # Safety
/// `rand_val` must be a valid writable pointer to u32, or null (returns EINVAL).
pub unsafe extern "win64" fn ucrt_rand_s(rand_val: *mut u32) -> i32 {
    if rand_val.is_null() {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return libc::EINVAL;
    }
    // getrandom(buf, 4, 0) — blocks until kernel entropy pool is ready, then fills buf.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            rand_val as *mut libc::c_void,
            4usize,
            0u32,
        )
    };
    if ret != 4 {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return libc::EINVAL;
    }
    0
}

// ── Legacy MSVCRT entry-point helpers ────────────────────────────────────────

/// __getmainargs — legacy MSVCRT function that fills in argc/argv/envp for main().
///
/// Old MinGW-compiled executables call this to retrieve the parsed command line
/// before calling main(). We return a minimal (empty) argument vector so the
/// program sees argv=[""] with no extra args.
///
/// Signature: int __getmainargs(int *argc, char ***argv, char ***envp, int expand_wildcards, int *new_mode)
///
/// # Safety
/// All pointer arguments must be valid or NULL.
pub unsafe extern "win64" fn ucrt_getmainargs(
    p_argc: *mut i32,
    p_argv: *mut *mut *mut u8,
    p_envp: *mut *mut *mut u8,
    _expand_wildcards: i32,
    _p_new_mode: *mut i32,
) -> i32 {
    libc::write(
        2,
        b"weave: stub __getmainargs\n".as_ptr() as *const libc::c_void,
        26,
    );
    // Provide a minimal argv = [""] with no env vars.
    // These buffers live for the program lifetime — leaked intentionally.
    static EMPTY_ARG: u8 = 0;
    // argv[0] = ptr to empty string, argv[1] = NULL
    let argv = Box::into_raw(Box::new([
        &EMPTY_ARG as *const u8 as *mut u8,
        std::ptr::null_mut::<u8>(),
    ])) as *mut *mut u8;
    // envp[0] = NULL
    let envp = Box::into_raw(Box::new([std::ptr::null_mut::<u8>()])) as *mut *mut u8;
    if !p_argc.is_null() {
        *p_argc = 1;
    }
    if !p_argv.is_null() {
        *p_argv = argv;
    }
    if !p_envp.is_null() {
        *p_envp = envp;
    }
    0
}

/// __wgetmainargs — wide-char variant of __getmainargs.
///
/// # Safety
/// All pointer arguments must be valid or NULL.
pub unsafe extern "win64" fn ucrt_wgetmainargs(
    p_argc: *mut i32,
    p_argv: *mut *mut *mut u16,
    p_envp: *mut *mut *mut u16,
    _expand_wildcards: i32,
    _p_new_mode: *mut i32,
) -> i32 {
    static EMPTY_WARG: u16 = 0;
    let argv = Box::into_raw(Box::new([
        &EMPTY_WARG as *const u16 as *mut u16,
        std::ptr::null_mut::<u16>(),
    ])) as *mut *mut u16;
    let envp = Box::into_raw(Box::new([std::ptr::null_mut::<u16>()])) as *mut *mut u16;
    if !p_argc.is_null() {
        *p_argc = 1;
    }
    if !p_argv.is_null() {
        *p_argv = argv;
    }
    if !p_envp.is_null() {
        *p_envp = envp;
    }
    0
}

// ── Legacy MSVCRT global data exports ────────────────────────────────────────

/// __initenv — MSVCRT global: pointer to the initial environment block (char**).
///
/// Some MinGW CRT startup sequences import this as a data symbol to initialise
/// their own `environ` variable. We expose a pointer to a null-terminated
/// empty environment (same as __p__environ).
///
/// # Safety
/// No pointer requirements; returns a pointer to static null-terminated environment storage.
pub unsafe extern "win64" fn ucrt_initenv() -> *mut *mut u8 {
    // A static null pointer (usize is Sync, raw pointers are not).
    static NULL_ENV: usize = 0;
    &NULL_ENV as *const usize as *mut *mut u8
}

/// __winitenv — wide-char variant (wchar_t**).
///
/// # Safety
/// No pointer requirements; returns a pointer to static null-terminated wide environment storage.
pub unsafe extern "win64" fn ucrt_winitenv() -> *mut *mut u16 {
    static NULL_WENV: usize = 0;
    &NULL_WENV as *const usize as *mut *mut u16
}

// ── Task 4 — ucrt C string + numeric stubs ───────────────────────────────────

/// strcpy: copy a null-terminated string.
///
/// # Safety
/// `dst` must be writable for the length of `src` plus null terminator.
pub unsafe extern "win64" fn ucrt_strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    unsafe { libc::strcpy(dst as _, src as _) as *mut u8 }
}

/// strcat: concatenate two null-terminated strings.
///
/// # Safety
/// `dst` must be writable for the combined length of both strings plus null terminator.
pub unsafe extern "win64" fn ucrt_strcat(dst: *mut u8, src: *const u8) -> *mut u8 {
    unsafe { libc::strcat(dst as _, src as _) as *mut u8 }
}

/// strstr: find the first occurrence of needle in haystack.
///
/// # Safety
/// `haystack` and `needle` must be valid null-terminated strings.
pub unsafe extern "win64" fn ucrt_strstr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    unsafe { libc::strstr(haystack as _, needle as _) as *mut u8 }
}

/// strrchr: find the last occurrence of c in s.
///
/// # Safety
/// `s` must be a valid null-terminated string.
pub unsafe extern "win64" fn ucrt_strrchr(s: *const u8, c: i32) -> *mut u8 {
    unsafe { libc::strrchr(s as _, c) as *mut u8 }
}

/// atoi: convert string to integer.
///
/// # Safety
/// `s` must be a valid null-terminated string.
pub unsafe extern "win64" fn ucrt_atoi(s: *const u8) -> i32 {
    unsafe { libc::atoi(s as _) }
}

/// atof: convert string to double.
///
/// # Safety
/// `s` must be a valid null-terminated string.
pub unsafe extern "win64" fn ucrt_atof(s: *const u8) -> f64 {
    unsafe { libc::atof(s as _) }
}

/// strtod: convert string to double with end pointer.
///
/// # Safety
/// `s` must be a valid null-terminated string.
/// `endptr` must be writable if non-null.
pub unsafe extern "win64" fn ucrt_strtod(s: *const u8, endptr: *mut *mut u8) -> f64 {
    unsafe { libc::strtod(s as _, endptr as _) }
}

/// strtol: convert string to long integer.
///
/// # Safety
/// `s` must be a valid null-terminated string.
/// `endptr` must be writable if non-null.
pub unsafe extern "win64" fn ucrt_strtol(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
    unsafe { libc::strtol(s as _, endptr as _, base) as i64 }
}

/// strtoll: convert string to long long integer.
///
/// # Safety
/// `s` must be a valid null-terminated string.
/// `endptr` must be writable if non-null.
pub unsafe extern "win64" fn ucrt_strtoll(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
    unsafe { libc::strtoll(s as _, endptr as _, base) }
}

/// rand: generate a pseudo-random number.
pub extern "win64" fn ucrt_rand() -> i32 {
    unsafe { libc::rand() }
}

/// srand: seed the pseudo-random number generator.
pub extern "win64" fn ucrt_srand(seed: u32) {
    unsafe { libc::srand(seed) }
}

/// abs: compute the absolute value of an integer.
pub extern "win64" fn ucrt_abs(x: i64) -> i64 {
    x.abs()
}

// ── Task 5 — ucrt wide string + char-class stubs ─────────────────────────────

/// wcscpy: copy a null-terminated UTF-16 string.
///
/// # Safety
/// `dst` must be writable for the length of `src` plus null terminator (u16 units).
pub unsafe extern "win64" fn ucrt_wcscpy(dst: *mut u16, src: *const u16) -> *mut u16 {
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

/// wcscat: concatenate two null-terminated UTF-16 strings.
///
/// # Safety
/// `dst` must be writable for the combined length of both strings plus null terminator.
pub unsafe extern "win64" fn ucrt_wcscat(dst: *mut u16, src: *const u16) -> *mut u16 {
    // find end of dst
    let mut end = 0usize;
    while unsafe { *dst.add(end) } != 0 {
        end += 1;
    }
    // copy src
    let mut i = 0usize;
    loop {
        let c = unsafe { *src.add(i) };
        unsafe { *dst.add(end + i) = c };
        if c == 0 {
            break;
        }
        i += 1;
    }
    dst
}

/// wcschr: find the first occurrence of a character in a UTF-16 string.
///
/// # Safety
/// `s` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn ucrt_wcschr(s: *const u16, c: u16) -> *mut u16 {
    let mut i = 0usize;
    loop {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            return unsafe { s.add(i) as *mut u16 };
        }
        if ch == 0 {
            return std::ptr::null_mut();
        }
        i += 1;
    }
}

/// wcsrchr: find the last occurrence of a character in a UTF-16 string.
///
/// # Safety
/// `s` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn ucrt_wcsrchr(s: *const u16, c: u16) -> *mut u16 {
    let mut last: *mut u16 = std::ptr::null_mut();
    let mut i = 0usize;
    loop {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = unsafe { s.add(i) as *mut u16 };
        }
        if ch == 0 {
            break;
        }
        i += 1;
    }
    last
}

/// wcsstr: find the first occurrence of needle in haystack (UTF-16).
///
/// # Safety
/// `haystack` and `needle` must be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn ucrt_wcsstr(haystack: *const u16, needle: *const u16) -> *mut u16 {
    // empty needle matches at start
    if unsafe { *needle } == 0 {
        return haystack as *mut u16;
    }
    let mut i = 0usize;
    loop {
        let ch = unsafe { *haystack.add(i) };
        if ch == 0 {
            return std::ptr::null_mut();
        }
        // try to match needle at position i
        let mut j = 0usize;
        loop {
            let nc = unsafe { *needle.add(j) };
            if nc == 0 {
                return unsafe { haystack.add(i) as *mut u16 };
            }
            let hc = unsafe { *haystack.add(i + j) };
            if hc != nc {
                break;
            }
            j += 1;
        }
        i += 1;
    }
}

/// _wtoi: convert a null-terminated UTF-16 string to an integer.
///
/// # Safety
/// `s` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn ucrt_wtoi(s: *const u16) -> i32 {
    if s.is_null() {
        return 0;
    }
    // skip leading whitespace
    let mut i = 0usize;
    while matches!(unsafe { *s.add(i) }, 0x09 | 0x0A | 0x0D | 0x20) {
        i += 1;
    }
    // optional sign
    let negative = match unsafe { *s.add(i) } {
        0x2D => {
            i += 1;
            true
        }
        0x2B => {
            i += 1;
            false
        }
        _ => false,
    };
    // digits
    let mut result: i32 = 0;
    loop {
        let ch = unsafe { *s.add(i) };
        if ch < b'0' as u16 || ch > b'9' as u16 {
            break;
        }
        result = result
            .wrapping_mul(10)
            .wrapping_add((ch - b'0' as u16) as i32);
        i += 1;
    }
    if negative {
        result.wrapping_neg()
    } else {
        result
    }
}

/// tolower: convert a character to lowercase.
pub extern "win64" fn ucrt_tolower(c: i32) -> i32 {
    unsafe { libc::tolower(c) }
}

/// toupper: convert a character to uppercase.
pub extern "win64" fn ucrt_toupper(c: i32) -> i32 {
    unsafe { libc::toupper(c) }
}

/// isalpha: test if character is alphabetic.
pub extern "win64" fn ucrt_isalpha(c: i32) -> i32 {
    unsafe { libc::isalpha(c) }
}

/// isdigit: test if character is a decimal digit.
pub extern "win64" fn ucrt_isdigit(c: i32) -> i32 {
    unsafe { libc::isdigit(c) }
}

/// isspace: test if character is whitespace.
pub extern "win64" fn ucrt_isspace(c: i32) -> i32 {
    unsafe { libc::isspace(c) }
}

/// isalnum: test if character is alphanumeric.
pub extern "win64" fn ucrt_isalnum(c: i32) -> i32 {
    unsafe { libc::isalnum(c) }
}

/// isupper: test if character is uppercase.
pub extern "win64" fn ucrt_isupper(c: i32) -> i32 {
    unsafe { libc::isupper(c) }
}

/// islower: test if character is lowercase.
pub extern "win64" fn ucrt_islower(c: i32) -> i32 {
    unsafe { libc::islower(c) }
}

/// isprint: test if character is printable.
pub extern "win64" fn ucrt_isprint(c: i32) -> i32 {
    unsafe { libc::isprint(c) }
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Returns true for any DLL name this crate handles.
fn is_ucrt_dll(dll: &str) -> bool {
    let lower = dll.to_ascii_lowercase();
    lower.starts_with("api-ms-win-crt-")
        || lower == "ucrtbase.dll"
        || lower == "msvcrt.dll"
        || lower == "vcruntime140.dll"
}

// ── msvcrt C++ runtime stubs ─────────────────────────────────────────────────

/// wcscmp — compare two null-terminated wide strings.
///
/// Returns negative, 0, or positive.
///
/// # Safety
/// `s1` and `s2` must each be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn ucrt_wcscmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1.is_null() { -1 } else { 1 };
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

/// _c_exit — perform C runtime cleanup without terminating. No-op stub.
pub extern "win64" fn ucrt_c_exit() {}

/// __dllonexit — register a callback to be called on DLL detach. Returns NULL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn ucrt_dllonexit(
    _func: *const u8,
    _pbegin: *mut *const u8,
    _pend: *mut *const u8,
) -> *const u8 {
    std::ptr::null()
}

/// _purecall — called when a pure virtual function is invoked. Aborts.
pub extern "win64" fn ucrt_purecall() -> ! {
    unsafe { libc::abort() }
}

/// _XcptFilter — MSVC SEH exception filter. Returns EXCEPTION_CONTINUE_SEARCH (0).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn ucrt_xcpt_filter(_xno: u32, _pxcptinfoptrs: *const u8) -> i32 {
    0 // EXCEPTION_CONTINUE_SEARCH
}

/// _CxxThrowException — throw a C++ exception via SEH dispatch.
///
/// This is a naked trampoline: before any prolog runs, it captures [RSP]
/// (the return address into NPP code = throw_rip) and RSP+8 (NPP's RSP
/// before the CALL = throw_rsp), then tail-calls the real implementation
/// with those values as extra arguments.
///
/// This avoids the false-positive problem in stack scanning: by the time
/// the real impl runs, we already have the exact throw site context.
///
/// # Safety
/// Called only via Win64 IAT from PE code.
#[unsafe(naked)]
pub unsafe extern "win64" fn ucrt_cxx_throw_exception(
    _p_exception_object: *mut u8,
    _p_throw_info: *const u8,
) {
    // Win64 entry state:
    //   RCX = p_exception_object  (Win64 arg1)
    //   RDX = p_throw_info        (Win64 arg2)
    //   [RSP] = return address into NPP  (= throw_rip)
    //   RSP+8 = NPP's RSP before the CALL  (= throw_rsp)
    //
    // We convert to Linux ABI for the tail call to ucrt_cxx_throw_exception_impl:
    //   RDI = p_exception_object  (Linux arg1)
    //   RSI = p_throw_info        (Linux arg2)
    //   RDX = throw_rip           (Linux arg3)
    //   RCX = throw_rsp           (Linux arg4)
    core::arch::naked_asm!(
        "mov r8,  [rsp]",   // r8  = throw_rip
        "lea r9,  [rsp+8]", // r9  = throw_rsp
        "mov rdi, rcx",     // p_exception_object → Linux arg1
        "mov rsi, rdx",     // p_throw_info       → Linux arg2
        "mov rdx, r8",      // throw_rip          → Linux arg3
        "mov rcx, r9",      // throw_rsp          → Linux arg4
        "jmp {inner}",
        inner = sym ucrt_cxx_throw_exception_impl,
    );
}

/// Inner (Linux ABI) implementation called by the naked trampoline above.
///
/// Receives the exact throw-site RIP and RSP captured before any prolog ran,
/// so no stack scanning is needed.
///
/// # Safety
/// `throw_rip` and `throw_rsp` must be the NPP throw-site values from the
/// naked trampoline.
unsafe extern "C" fn ucrt_cxx_throw_exception_impl(
    p_exception_object: *mut u8,
    p_throw_info: *const u8,
    throw_rip: u64,
    throw_rsp: u64,
) {
    let image_base = weave_core::seh::pe_base();

    eprintln!(
        "weave: _CxxThrowException obj={:#x} throw_info={:#x} image_base={image_base:#x} rip={throw_rip:#x} rsp={throw_rsp:#x}",
        p_exception_object as usize,
        p_throw_info as usize,
    );

    // MSVC C++ exception: RaiseException(0xE06D7363, NONCONTINUABLE, 4, params)
    // params[0] = MSVC magic (0x19930520 for x64)
    // params[1] = pointer to exception object
    // params[2] = pointer to ThrowInfo
    // params[3] = image base (for RVA resolution)
    let params: [u64; 4] = [
        0x19930520,
        p_exception_object as u64,
        p_throw_info as u64,
        image_base as u64,
    ];

    unsafe {
        weave_core::unwind::raise_exception_at(
            0xE06D7363, // EH_EXCEPTION_NUMBER ("msc")
            1,          // EXCEPTION_NONCONTINUABLE
            4,
            params.as_ptr(),
            throw_rip,
            throw_rsp,
        );
    }

    eprintln!("weave: _CxxThrowException: no handler found — terminating");
    unsafe { libc::exit(1) }
}

/// __CxxFrameHandler — MSVC C++ frame handler for exception unwinding.
///
/// Delegates to the real implementation in weave-core.
///
/// # Safety
/// Pointer arguments must be valid Windows x64 SEH structures.
pub unsafe extern "win64" fn ucrt_cxx_frame_handler(
    p_exc_rec: *mut weave_core::unwind::ExceptionRecord,
    est_frame: u64,
    p_context: *mut weave_core::unwind::Context,
    p_dispatch: *mut weave_core::unwind::DispatcherContext,
) -> i32 {
    unsafe { weave_core::unwind::cxx_frame_handler(p_exc_rec, est_frame, p_context, p_dispatch) }
}

/// ?terminate@@YAXXZ — C++ std::terminate(). Aborts the process.
pub extern "win64" fn ucrt_terminate() -> ! {
    unsafe { libc::abort() }
}

// ── Named stubs for previously catch-all functions ────────────────────────────
// Each function gets its own stub so the log line names it.  The log uses
// libc::write so it is guaranteed to flush before any potential abort.

macro_rules! named_stub {
    ($name:ident, $label:expr) => {
        pub extern "win64" fn $name() {
            unsafe {
                let msg = concat!("weave: stub ", $label, "\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
            }
        }
    };
}

named_stub!(ucrt_isatty_stub, "_isatty");
named_stub!(ucrt_get_doserrno_stub, "_get_doserrno");
named_stub!(ucrt_set_doserrno_stub, "_set_doserrno");

/// _get_errno — copy the thread-local CRT errno value into *pValue.
///
/// Wine ref: dlls/msvcrt/errno.c:230 — null pValue → return EINVAL (no errno set);
/// otherwise *pValue = *_errno(); return 0.
///
/// # Safety
/// `p_value` must be a valid writable pointer to i32, or null (returns EINVAL).
pub unsafe extern "win64" fn ucrt_get_errno(p_value: *mut i32) -> i32 {
    if p_value.is_null() {
        return libc::EINVAL;
    }
    unsafe { *p_value = *libc::__errno_location() };
    0
}

/// _set_errno — write value into the thread-local CRT errno.
///
/// Wine ref: dlls/msvcrt/errno.c:254 — *_errno() = value; return 0. No bounds check.
pub extern "win64" fn ucrt_set_errno(value: i32) -> i32 {
    unsafe { *libc::__errno_location() = value };
    0
}
named_stub!(ucrt_sopen_s_stub, "_sopen_s");
named_stub!(ucrt_close_stub, "_close");
named_stub!(ucrt_dup_stub, "_dup");
named_stub!(ucrt_dup2_stub, "_dup2");
named_stub!(ucrt_flushall_stub, "_flushall");
named_stub!(ucrt_chkstk_stub, "_chkstk");

/// ??1type_info@@UEAA@XZ — type_info destructor. No-op (no real RTTI objects).
///
/// # Safety
/// `this` is accepted but not dereferenced.
pub unsafe extern "win64" fn ucrt_type_info_dtor(_this: *mut u8) {}

/// Resolve a UCRT import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !is_ucrt_dll(dll) {
        return None;
    }
    macro_rules! stub {
        ($f:expr) => {
            Some($f as *const () as usize)
        };
    }
    match func {
        // heap
        "malloc" => stub!(ucrt_malloc as unsafe extern "win64" fn(_) -> _),
        "free" => stub!(ucrt_free as unsafe extern "win64" fn(_)),
        "calloc" => stub!(ucrt_calloc as unsafe extern "win64" fn(_, _) -> _),
        "realloc" => stub!(ucrt_realloc as unsafe extern "win64" fn(_, _) -> _),
        "_aligned_malloc" => stub!(ucrt_aligned_malloc as unsafe extern "win64" fn(_, _) -> _),
        "_aligned_free" => stub!(ucrt_aligned_free as unsafe extern "win64" fn(_)),
        "_set_new_mode" => stub!(ucrt_set_new_mode as extern "win64" fn(_) -> _),
        // memory
        "memcpy" | "memmove_s" | "memcpy_s" => {
            stub!(ucrt_memcpy as unsafe extern "win64" fn(_, _, _) -> _)
        }
        "memmove" => stub!(ucrt_memmove as unsafe extern "win64" fn(_, _, _) -> _),
        "memset" => stub!(ucrt_memset as unsafe extern "win64" fn(_, _, _) -> _),
        "memcmp" => stub!(ucrt_memcmp as unsafe extern "win64" fn(_, _, _) -> _),
        "memchr" => stub!(ucrt_memchr as unsafe extern "win64" fn(_, _, _) -> _),
        // strings
        "strlen" => stub!(ucrt_strlen as unsafe extern "win64" fn(_) -> _),
        "wcslen" => stub!(ucrt_wcslen as unsafe extern "win64" fn(_) -> _),
        "strncmp" => stub!(ucrt_strncmp as unsafe extern "win64" fn(_, _, _) -> _),
        "strcmp" | "strcoll" | "strxfrm" => {
            stub!(ucrt_strcmp as unsafe extern "win64" fn(_, _) -> _)
        }
        "strchr" => stub!(ucrt_strchr as unsafe extern "win64" fn(_, _) -> _),
        "_strdup" => stub!(ucrt_strdup as unsafe extern "win64" fn(_) -> _),
        "strncpy" => stub!(ucrt_strncpy as unsafe extern "win64" fn(_, _, _) -> _),
        "strnlen" => stub!(ucrt_strnlen as unsafe extern "win64" fn(_, _) -> _),
        "strtoul" => stub!(ucrt_strtoul as unsafe extern "win64" fn(_, _, _) -> _),
        // wide strings
        "_wcsicmp" => stub!(ucrt_wcsicmp as unsafe extern "win64" fn(_, _) -> _),
        "_wcsnicmp" => stub!(ucrt_wcsnicmp as unsafe extern "win64" fn(_, _, _) -> _),
        "wcsnlen" => stub!(ucrt_wcsnlen as unsafe extern "win64" fn(_, _) -> _),
        "wcscoll" | "wcsxfrm" => stub!(ucrt_wcsicmp as unsafe extern "win64" fn(_, _) -> _),
        "towlower" => stub!(ucrt_towlower as extern "win64" fn(_) -> _),
        "towupper" => stub!(ucrt_towupper as extern "win64" fn(_) -> _),
        "iswctype" | "wctype" => stub!(ucrt_wctob as unsafe extern "win64" fn(_) -> _),
        // process
        "exit" => stub!(ucrt_exit as extern "win64" fn(_) -> !),
        "_exit" => stub!(ucrt__exit as extern "win64" fn(_) -> !),
        "abort" => stub!(ucrt_abort as extern "win64" fn() -> !),
        "_cexit" => stub!(ucrt_cexit as extern "win64" fn()),
        "_set_app_type" | "__set_app_type" => stub!(ucrt_set_app_type as extern "win64" fn(_)),
        "_configure_narrow_argv" => {
            stub!(ucrt_configure_narrow_argv as extern "win64" fn(_) -> _)
        }
        "_initialize_narrow_environment" => {
            stub!(ucrt_initialize_narrow_environment as extern "win64" fn() -> _)
        }
        "_set_invalid_parameter_handler" => {
            stub!(ucrt_set_invalid_parameter_handler as extern "win64" fn(_) -> _)
        }
        "_configthreadlocale" => stub!(ucrt_configthreadlocale as extern "win64" fn(_) -> _),
        "__setusermatherr" => stub!(ucrt_setusermatherr as extern "win64" fn(_)),
        "signal" => stub!(ucrt_signal as extern "win64" fn(_, _) -> _),
        // initterm
        "_initterm" => stub!(ucrt_initterm as unsafe extern "win64" fn(_, _)),
        "_initterm_e" => stub!(ucrt_initterm_e as unsafe extern "win64" fn(_, _) -> _),
        "_crt_atexit" => stub!(ucrt_crt_atexit as extern "win64" fn(_) -> _),
        "_register_onexit_function" => {
            stub!(ucrt_register_onexit_function as extern "win64" fn(_, _) -> _)
        }
        "_execute_onexit_table" => {
            stub!(ucrt_execute_onexit_table as extern "win64" fn(_) -> _)
        }
        "_initialize_onexit_table" => {
            stub!(ucrt_initialize_onexit_table as extern "win64" fn(_) -> _)
        }
        "_beginthreadex" => {
            stub!(ucrt_beginthreadex as unsafe extern "win64" fn(_, _, _, _, _, _) -> _)
        }
        "_endthreadex" => stub!(ucrt_endthreadex as extern "win64" fn(_)),
        "_assert" => stub!(ucrt_assert as unsafe extern "win64" fn(_, _, _)),
        // CRT globals
        "__p___argc" => stub!(ucrt_p_argc as unsafe extern "win64" fn() -> _),
        "__p___argv" => stub!(ucrt_p_argv as unsafe extern "win64" fn() -> _),
        "__p__acmdln" => stub!(ucrt_p_acmdln as unsafe extern "win64" fn() -> _),
        "__p__environ" => stub!(ucrt_p_environ as unsafe extern "win64" fn() -> _),
        "__p__commode" => stub!(ucrt_p_commode as unsafe extern "win64" fn() -> _),
        "__p__fmode" => stub!(ucrt_p_fmode as unsafe extern "win64" fn() -> _),
        // stdio
        "__acrt_iob_func" | "__iob_func" => stub!(ucrt_acrt_iob_func as extern "win64" fn(_) -> _),
        // Legacy msvcrt.dll CRT startup functions
        "_amsg_exit" => stub!(ucrt_amsg_exit as extern "win64" fn(_) -> !),
        "_onexit" => stub!(ucrt_onexit as extern "win64" fn(_) -> _),
        "fprintf" => stub!(ucrt_fprintf as extern "win64" fn(_, _) -> _),
        "vfprintf" => stub!(ucrt_vfprintf as extern "win64" fn(_, _, _) -> _),
        "fwrite" => stub!(ucrt_fwrite as unsafe extern "win64" fn(_, _, _, _) -> _),
        "__stdio_common_vfprintf" | "__stdio_common_vfwprintf" => {
            stub!(ucrt_stdio_common_vfprintf as extern "win64" fn(_, _, _, _, _) -> _)
        }
        "__stdio_common_vsprintf" | "__stdio_common_vswprintf" => {
            stub!(ucrt_stdio_common_vsprintf as extern "win64" fn(_, _, _, _, _, _) -> _)
        }
        "_iob" => Some(iob_data_addr()),
        "fputc" => Some(ms_fputc as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "fputs" => Some(ms_fputs as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "fgetc" => Some(ms_fgetc as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "fflush" => Some(ms_fflush as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "setvbuf" => stub!(ucrt_setvbuf as extern "win64" fn(_, _, _, _) -> _),
        "_errno" => stub!(ucrt_errno as extern "win64" fn() -> _),
        "strerror" => stub!(ucrt_strerror as extern "win64" fn(_) -> _),
        "_get_osfhandle" => stub!(ucrt_get_osfhandle as extern "win64" fn(_) -> _),
        "_fseeki64" | "fseek" => {
            stub!(ucrt_fseeki64 as unsafe extern "win64" fn(_, _, _) -> _)
        }
        "_ftelli64" | "ftell" => stub!(ucrt_ftelli64 as unsafe extern "win64" fn(_) -> _),
        "_fdopen" => stub!(ucrt_fdopen as extern "win64" fn(_, _) -> _),
        "_lock_file" => stub!(ucrt_lock_file as extern "win64" fn(_)),
        "_unlock_file" => stub!(ucrt_unlock_file as extern "win64" fn(_)),
        "remove" => stub!(ucrt_remove as extern "win64" fn(_) -> _),
        "_fstat64" => stub!(ucrt_fstat64 as extern "win64" fn(_, _) -> _),
        "fopen" => stub!(ucrt_fopen as unsafe extern "win64" fn(_, _) -> _),
        "_wfopen" => stub!(ucrt_wfopen as unsafe extern "win64" fn(_, _) -> _),
        "fread" => stub!(ucrt_fread as unsafe extern "win64" fn(_, _, _, _) -> _),
        "fclose" => stub!(ucrt_fclose as unsafe extern "win64" fn(_) -> _),
        "feof" => stub!(ucrt_feof as unsafe extern "win64" fn(_) -> _),
        "ferror" => stub!(ucrt_ferror as unsafe extern "win64" fn(_) -> _),
        // locale / mb
        "___mb_cur_max_func" => stub!(ucrt_mb_cur_max_func as extern "win64" fn() -> _),
        "localeconv" => stub!(ucrt_localeconv as extern "win64" fn() -> _),
        "setlocale" => stub!(ucrt_setlocale as extern "win64" fn(_, _) -> _),
        "btowc" => stub!(ucrt_btowc as unsafe extern "win64" fn(_) -> _),
        "wctob" => stub!(ucrt_wctob as unsafe extern "win64" fn(_) -> _),
        "mbrtowc" => stub!(ucrt_mbrtowc as unsafe extern "win64" fn(_, _, _, _) -> _),
        "mbsrtowcs" => stub!(ucrt_mbsrtowcs as unsafe extern "win64" fn(_, _, _, _) -> _),
        "wcrtomb" => stub!(ucrt_wcrtomb as unsafe extern "win64" fn(_, _, _) -> _),
        // math
        "powf" => stub!(ucrt_powf as extern "win64" fn(_, _) -> _),
        // setjmp/longjmp
        "__intrinsic_setjmpex" => {
            stub!(ucrt_intrinsic_setjmpex as unsafe extern "win64" fn(_, _) -> _)
        }
        "longjmp" => stub!(ucrt_longjmp as unsafe extern "win64" fn(_, _) -> !),
        // exception handler
        "__C_specific_handler" => {
            stub!(ucrt_c_specific_handler as extern "win64" fn(_, _, _, _) -> _)
        }
        // misc
        "rand_s" => stub!(ucrt_rand_s as unsafe extern "win64" fn(_) -> _),
        "strcpy" => stub!(ucrt_strcpy as unsafe extern "win64" fn(_, _) -> _),
        "strcat" => stub!(ucrt_strcat as unsafe extern "win64" fn(_, _) -> _),
        "strstr" => stub!(ucrt_strstr as unsafe extern "win64" fn(_, _) -> _),
        "strrchr" => stub!(ucrt_strrchr as unsafe extern "win64" fn(_, _) -> _),
        "atoi" => stub!(ucrt_atoi as unsafe extern "win64" fn(_) -> _),
        "atof" => stub!(ucrt_atof as unsafe extern "win64" fn(_) -> _),
        "strtod" => stub!(ucrt_strtod as unsafe extern "win64" fn(_, _) -> _),
        "strtol" => stub!(ucrt_strtol as unsafe extern "win64" fn(_, _, _) -> _),
        "strtoll" => stub!(ucrt_strtoll as unsafe extern "win64" fn(_, _, _) -> _),
        "rand" => stub!(ucrt_rand as extern "win64" fn() -> _),
        "srand" => stub!(ucrt_srand as extern "win64" fn(_)),
        "abs" => stub!(ucrt_abs as extern "win64" fn(_) -> _),
        "wcscpy" => stub!(ucrt_wcscpy as unsafe extern "win64" fn(_, _) -> _),
        "wcscat" => stub!(ucrt_wcscat as unsafe extern "win64" fn(_, _) -> _),
        "wcschr" => stub!(ucrt_wcschr as unsafe extern "win64" fn(_, _) -> _),
        "wcsrchr" => stub!(ucrt_wcsrchr as unsafe extern "win64" fn(_, _) -> _),
        "wcsstr" => stub!(ucrt_wcsstr as unsafe extern "win64" fn(_, _) -> _),
        "_wtoi" => stub!(ucrt_wtoi as unsafe extern "win64" fn(_) -> _),
        "tolower" => stub!(ucrt_tolower as extern "win64" fn(_) -> _),
        "toupper" => stub!(ucrt_toupper as extern "win64" fn(_) -> _),
        "isalpha" => stub!(ucrt_isalpha as extern "win64" fn(_) -> _),
        "isdigit" => stub!(ucrt_isdigit as extern "win64" fn(_) -> _),
        "isspace" => stub!(ucrt_isspace as extern "win64" fn(_) -> _),
        "isalnum" => stub!(ucrt_isalnum as extern "win64" fn(_) -> _),
        "isupper" => stub!(ucrt_isupper as extern "win64" fn(_) -> _),
        "islower" => stub!(ucrt_islower as extern "win64" fn(_) -> _),
        "isprint" => stub!(ucrt_isprint as extern "win64" fn(_) -> _),
        "strftime" | "wcsftime" => stub!(ucrt_cexit as extern "win64" fn()),
        // legacy MSVCRT entry-point helpers
        "__getmainargs" => stub!(ucrt_getmainargs as unsafe extern "win64" fn(_, _, _, _, _) -> _),
        "__wgetmainargs" => {
            stub!(ucrt_wgetmainargs as unsafe extern "win64" fn(_, _, _, _, _) -> _)
        }
        "__initenv" => Some(initenv_data_addr()),
        "__winitenv" => Some(winitenv_data_addr()),
        "_environ" => Some(environ_data_addr()),
        "_wenviron" => Some(wenviron_data_addr()),
        "__argc" => Some(argc_data_addr()),
        "__argv" => Some(argv_data_addr()),
        "_acmdln" => Some(acmdln_data_addr()),
        "_wcmdln" => Some(wcmdln_data_addr()),
        "_pgmptr" => Some(pgmptr_data_addr()),
        "_wpgmptr" => Some(wpgmptr_data_addr()),
        "_doserrno" | "__doserrno" => Some(doserrno_data_addr()),
        // Legacy MSVCRT aliases — older MinGW CRT startup code uses these names
        "_fmode" => Some(fmode_data_addr()),
        "_commode" => Some(commode_data_addr()),
        "__mb_cur_max" => Some(mb_cur_max_data_addr()),
        "_stricmp" | "_strcmpi" => stub!(ucrt_strcmp as unsafe extern "win64" fn(_, _) -> _),
        "_wcsdup" => stub!(ucrt_strdup as unsafe extern "win64" fn(_) -> _),
        "_flushall" => stub!(ucrt_flushall_stub as extern "win64" fn()),
        "_filbuf" | "_flsbuf" => stub!(ucrt_cexit as extern "win64" fn()),
        "_isatty" => stub!(ucrt_isatty_stub as extern "win64" fn()),
        "_get_errno" => stub!(ucrt_get_errno as unsafe extern "win64" fn(_) -> _),
        "_set_errno" => stub!(ucrt_set_errno as extern "win64" fn(_) -> _),
        "_get_doserrno" => stub!(ucrt_get_doserrno_stub as extern "win64" fn()),
        "_set_doserrno" => stub!(ucrt_set_doserrno_stub as extern "win64" fn()),
        "_sopen_s" => stub!(ucrt_sopen_s_stub as extern "win64" fn()),
        "_close" => stub!(ucrt_close_stub as extern "win64" fn()),
        "_dup" => stub!(ucrt_dup_stub as extern "win64" fn()),
        "_dup2" => stub!(ucrt_dup2_stub as extern "win64" fn()),
        "_chkstk" | "__chkstk" | "_alloca_probe" | "__alloca_probe" => {
            stub!(ucrt_chkstk_stub as extern "win64" fn())
        }
        // Additional MSVCRT startup symbols seen in MinGW-compiled binaries.
        // All are no-ops or aliases — the CRT startup just needs them to resolve.
        "__getmainargs_to_utf8"
        | "__wgetmainargs_to_utf8"
        | "_get_pgmptr"
        | "_get_wpgmptr"
        | "__set_errno"
        | "_Getdays"
        | "_Getmonths"
        | "_Gettnames"
        | "_Strftime"
        | "_Wcsftime"
        | "_wassert"
        | "__fpclassify"
        | "__fpclassifyf"
        | "_clearfp"
        | "_controlfp"
        | "_controlfp_s"
        | "_statusfp"
        | "_fpreset"
        | "__stdio_common_vfscanf"
        | "__stdio_common_vsscanf"
        | "__stdio_common_vfwscanf"
        | "__stdio_common_vswscanf"
        | "_pipe"
        | "_cwait"
        | "_spawnl"
        | "_spawnle"
        | "_spawnlp"
        | "_spawnlpe"
        | "_spawnv"
        | "_spawnve"
        | "_spawnvp"
        | "_spawnvpe"
        | "__crt_locale_data_public"
        | "__crt_locale_pointers"
        | "_Mbrtowc"
        | "_Wctomb" => Some(ucrt_cexit as extern "win64" fn() as *const () as usize),
        "wcscmp" => Some(ucrt_wcscmp as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "_c_exit" => Some(ucrt_c_exit as extern "win64" fn() as *const () as usize),
        "__dllonexit" => {
            Some(ucrt_dllonexit as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "_purecall" => Some(ucrt_purecall as extern "win64" fn() -> ! as *const () as usize),
        "_XcptFilter" => {
            Some(ucrt_xcpt_filter as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "_CxxThrowException" => {
            Some(ucrt_cxx_throw_exception as unsafe extern "win64" fn(_, _) as *const () as usize)
        }
        "__CxxFrameHandler" | "__CxxFrameHandler3" | "__CxxFrameHandler4" => Some(
            ucrt_cxx_frame_handler as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "?terminate@@YAXXZ" => {
            Some(ucrt_terminate as extern "win64" fn() -> ! as *const () as usize)
        }
        "??1type_info@@UEAA@XZ" => {
            Some(ucrt_type_info_dtor as unsafe extern "win64" fn(_) as *const () as usize)
        }
        _ => None,
    }
}
