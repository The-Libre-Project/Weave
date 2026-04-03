//! Stubs for the Windows Universal C Runtime (UCRT) and legacy MSVCRT.
//!
//! Windows apps compiled with MSVC or modern MinGW import C runtime functions
//! from a set of forwarding DLLs (`api-ms-win-crt-heap-l1-1-0.dll`, etc.) that
//! all redirect to `ucrtbase.dll`.  Weave implements the subset these apps
//! actually call, routing them to libc or providing minimal stubs.
//!
//! Handled DLL namespaces (case-insensitive):
//!   api-ms-win-crt-*   ucrtbase.dll   msvcrt.dll

#![allow(clippy::missing_safety_doc)]

use libc::c_void;

// ── Heap ──────────────────────────────────────────────────────────────────────

pub unsafe extern "win64" fn ucrt_malloc(size: usize) -> *mut c_void {
    unsafe { libc::malloc(size) }
}

pub unsafe extern "win64" fn ucrt_free(ptr: *mut c_void) {
    unsafe { libc::free(ptr) }
}

pub unsafe extern "win64" fn ucrt_calloc(count: usize, size: usize) -> *mut c_void {
    unsafe { libc::calloc(count, size) }
}

pub unsafe extern "win64" fn ucrt_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { libc::realloc(ptr, size) }
}

pub unsafe extern "win64" fn ucrt_aligned_malloc(size: usize, alignment: usize) -> *mut c_void {
    unsafe {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = libc::posix_memalign(
            &mut ptr,
            alignment.max(std::mem::size_of::<*mut c_void>()),
            size,
        );
        if ret != 0 { std::ptr::null_mut() } else { ptr }
    }
}

pub unsafe extern "win64" fn ucrt_aligned_free(ptr: *mut c_void) {
    unsafe { libc::free(ptr) }
}

pub extern "win64" fn ucrt_set_new_mode(_mode: i32) -> i32 {
    0
}

// ── Memory ────────────────────────────────────────────────────────────────────

pub unsafe extern "win64" fn ucrt_memcpy(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
) -> *mut c_void {
    unsafe { libc::memcpy(dst, src, n) }
}

pub unsafe extern "win64" fn ucrt_memmove(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
) -> *mut c_void {
    unsafe { libc::memmove(dst, src, n) }
}

pub unsafe extern "win64" fn ucrt_memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { libc::memset(dst, c, n) }
}

pub unsafe extern "win64" fn ucrt_memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    unsafe { libc::memcmp(s1, s2, n) }
}

pub unsafe extern "win64" fn ucrt_memchr(s: *const c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { libc::memchr(s, c, n) }
}

// ── Strings ───────────────────────────────────────────────────────────────────

pub unsafe extern "win64" fn ucrt_strlen(s: *const u8) -> usize {
    unsafe { libc::strlen(s as _) }
}

pub unsafe extern "win64" fn ucrt_strncmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe { libc::strncmp(s1 as _, s2 as _, n) }
}

pub unsafe extern "win64" fn ucrt_strcmp(s1: *const u8, s2: *const u8) -> i32 {
    unsafe { libc::strcmp(s1 as _, s2 as _) }
}

pub unsafe extern "win64" fn ucrt_strchr(s: *const u8, c: i32) -> *mut u8 {
    unsafe { libc::strchr(s as _, c) as *mut u8 }
}

pub unsafe extern "win64" fn ucrt_strdup(s: *const u8) -> *mut u8 {
    unsafe { libc::strdup(s as _) as *mut u8 }
}

pub unsafe extern "win64" fn ucrt_strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { libc::strncpy(dst as _, src as _, n) as *mut u8 }
}

pub unsafe extern "win64" fn ucrt_strnlen(s: *const u8, maxlen: usize) -> usize {
    unsafe {
        let mut i = 0;
        while i < maxlen && *s.add(i) != 0 {
            i += 1;
        }
        i
    }
}

pub unsafe extern "win64" fn ucrt_wcsnlen(s: *const u16, maxlen: usize) -> usize {
    unsafe {
        let mut i = 0;
        while i < maxlen && *s.add(i) != 0 {
            i += 1;
        }
        i
    }
}

pub unsafe extern "win64" fn ucrt_strtoul(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
    unsafe { libc::strtoul(s as _, endptr as _, base) as u64 }
}

// ── Wide strings ──────────────────────────────────────────────────────────────

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

pub extern "win64" fn ucrt_cexit() {}

pub extern "win64" fn ucrt_set_app_type(_type: u32) {}
pub extern "win64" fn ucrt_configure_narrow_argv(_mode: i32) -> i32 {
    0
}
pub extern "win64" fn ucrt_initialize_narrow_environment() -> i32 {
    0
}
pub extern "win64" fn ucrt_set_invalid_parameter_handler(_fn: *const c_void) -> *const c_void {
    std::ptr::null()
}
pub extern "win64" fn ucrt_configthreadlocale(_mode: i32) -> i32 {
    0
}
pub extern "win64" fn ucrt_setusermatherr(_fn: *const c_void) {}

// ── _initterm / _initterm_e — runs C++ static constructors ───────────────────
//
// Each entry is a function pointer (or NULL/padding).  _initterm calls void()
// functions; _initterm_e calls int() functions and aborts on non-zero return.

pub unsafe extern "win64" fn ucrt_initterm(start: *const *const c_void, end: *const *const c_void) {
    unsafe {
        let mut p = start;
        while p < end {
            let fn_ptr = *p;
            if !fn_ptr.is_null() {
                let f: extern "win64" fn() = std::mem::transmute(fn_ptr);
                f();
            }
            p = p.add(1);
        }
    }
}

pub unsafe extern "win64" fn ucrt_initterm_e(
    start: *const *const c_void,
    end: *const *const c_void,
) -> i32 {
    unsafe {
        let mut p = start;
        while p < end {
            let fn_ptr = *p;
            if !fn_ptr.is_null() {
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

pub extern "win64" fn ucrt_signal(_signum: i32, _handler: *const c_void) -> *const c_void {
    std::ptr::null()
}

// ── CRT global variable accessors ─────────────────────────────────────────────

static mut CRT_ARGC: i32 = 0;
static mut CRT_ARGV_PTR: *mut *mut u8 = std::ptr::null_mut();
static mut CRT_ACMDLN: *mut u8 = std::ptr::null_mut();
static mut CRT_ENVIRON: *mut *mut u8 = std::ptr::null_mut();
static mut CRT_COMMODE: i32 = 0;
static mut CRT_FMODE: i32 = 0;

pub unsafe extern "win64" fn ucrt_p_argc() -> *mut i32 {
    std::ptr::addr_of_mut!(CRT_ARGC)
}
pub unsafe extern "win64" fn ucrt_p_argv() -> *mut *mut *mut u8 {
    std::ptr::addr_of_mut!(CRT_ARGV_PTR)
}
pub unsafe extern "win64" fn ucrt_p_acmdln() -> *mut *mut u8 {
    std::ptr::addr_of_mut!(CRT_ACMDLN)
}
pub unsafe extern "win64" fn ucrt_p_environ() -> *mut *mut *mut u8 {
    std::ptr::addr_of_mut!(CRT_ENVIRON)
}
pub unsafe extern "win64" fn ucrt_p_commode() -> *mut i32 {
    std::ptr::addr_of_mut!(CRT_COMMODE)
}
pub unsafe extern "win64" fn ucrt_p_fmode() -> *mut i32 {
    std::ptr::addr_of_mut!(CRT_FMODE)
}

// ── stdio ─────────────────────────────────────────────────────────────────────

pub extern "win64" fn ucrt_acrt_iob_func(_fd: u32) -> *mut c_void {
    std::ptr::null_mut()
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
    0
}

pub extern "win64" fn ucrt_errno() -> *mut i32 {
    unsafe { libc::__errno_location() }
}

pub extern "win64" fn ucrt_strerror(_errnum: i32) -> *mut u8 {
    std::ptr::null_mut()
}

pub unsafe extern "win64" fn ucrt_assert(_expr: *const u8, _file: *const u8, _line: u32) {
    unsafe { libc::abort() }
}

pub extern "win64" fn ucrt_beginthreadex(
    _security: *const c_void,
    _stack_size: u32,
    _start: *const c_void,
    _arg: *const c_void,
    _flags: u32,
    _thread_id: *mut u32,
) -> usize {
    0
}

pub extern "win64" fn ucrt_endthreadex(_exit_code: u32) {}

pub unsafe extern "win64" fn ucrt_intrinsic_setjmpex(
    _buf: *mut c_void,
    _frame: *const c_void,
) -> i32 {
    0
}

pub extern "win64" fn ucrt_longjmp(_buf: *mut c_void, _val: i32) -> ! {
    unsafe { libc::abort() }
}

// locale / multibyte stubs
pub extern "win64" fn ucrt_mb_cur_max_func() -> usize {
    1
}
pub extern "win64" fn ucrt_localeconv() -> *const c_void {
    std::ptr::null()
}
pub extern "win64" fn ucrt_setlocale(_cat: i32, _locale: *const u8) -> *mut u8 {
    std::ptr::null_mut()
}
pub unsafe extern "win64" fn ucrt_btowc(c: i32) -> u32 {
    c as u32
}
pub unsafe extern "win64" fn ucrt_wctob(c: u32) -> i32 {
    if c <= 0xFF {
        c as i32
    } else {
        -1
    }
}
pub unsafe extern "win64" fn ucrt_mbrtowc(
    _pwc: *mut u16,
    _s: *const u8,
    _n: usize,
    _ps: *mut c_void,
) -> usize {
    0
}
pub unsafe extern "win64" fn ucrt_mbsrtowcs(
    _dst: *mut u16,
    _src: *mut *const u8,
    _n: usize,
    _ps: *mut c_void,
) -> usize {
    0
}
pub unsafe extern "win64" fn ucrt_wcrtomb(_s: *mut u8, _wc: u16, _ps: *mut c_void) -> usize {
    0
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
pub extern "win64" fn ucrt_fseeki64(_stream: *mut c_void, _offset: i64, _origin: i32) -> i32 {
    -1
}
pub extern "win64" fn ucrt_ftelli64(_stream: *mut c_void) -> i64 {
    -1
}
pub extern "win64" fn ucrt_get_osfhandle(_fd: i32) -> isize {
    -1
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

pub extern "win64" fn ucrt_rand_s(_rand_val: *mut u32) -> i32 {
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
    if !p_argc.is_null() { *p_argc = 1; }
    if !p_argv.is_null() { *p_argv = argv; }
    if !p_envp.is_null() { *p_envp = envp; }
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
    if !p_argc.is_null() { *p_argc = 1; }
    if !p_argv.is_null() { *p_argv = argv; }
    if !p_envp.is_null() { *p_envp = envp; }
    0
}

// ── Legacy MSVCRT global data exports ────────────────────────────────────────

/// __initenv — MSVCRT global: pointer to the initial environment block (char**).
///
/// Some MinGW CRT startup sequences import this as a data symbol to initialise
/// their own `environ` variable. We expose a pointer to a null-terminated
/// empty environment (same as __p__environ).
pub unsafe extern "win64" fn ucrt_initenv() -> *mut *mut u8 {
    // A static null pointer (usize is Sync, raw pointers are not).
    static NULL_ENV: usize = 0;
    &NULL_ENV as *const usize as *mut *mut u8
}

/// __winitenv — wide-char variant (wchar_t**).
pub unsafe extern "win64" fn ucrt_winitenv() -> *mut *mut u16 {
    static NULL_WENV: usize = 0;
    &NULL_WENV as *const usize as *mut *mut u16
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
        "towlower" | "iswctype" | "wctype" => stub!(ucrt_wctob as unsafe extern "win64" fn(_) -> _),
        "towupper" => stub!(ucrt_btowc as unsafe extern "win64" fn(_) -> _),
        // process
        "exit" => stub!(ucrt_exit as extern "win64" fn(_) -> !),
        "_exit" => stub!(ucrt__exit as extern "win64" fn(_) -> !),
        "abort" => stub!(ucrt_abort as extern "win64" fn() -> !),
        "_cexit" => stub!(ucrt_cexit as extern "win64" fn()),
        "_set_app_type" => stub!(ucrt_set_app_type as extern "win64" fn(_)),
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
        "_beginthreadex" => stub!(ucrt_beginthreadex as extern "win64" fn(_, _, _, _, _, _) -> _),
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
        "__stdio_common_vfprintf" | "__stdio_common_vfwprintf" => {
            stub!(ucrt_stdio_common_vfprintf as extern "win64" fn(_, _, _, _, _) -> _)
        }
        "__stdio_common_vsprintf" | "__stdio_common_vswprintf" => {
            stub!(ucrt_stdio_common_vsprintf as extern "win64" fn(_, _, _, _, _, _) -> _)
        }
        "fflush" => stub!(ucrt_fflush as unsafe extern "win64" fn(_) -> _),
        "setvbuf" => stub!(ucrt_setvbuf as extern "win64" fn(_, _, _, _) -> _),
        "_errno" => stub!(ucrt_errno as extern "win64" fn() -> _),
        "strerror" => stub!(ucrt_strerror as extern "win64" fn(_) -> _),
        "_get_osfhandle" => stub!(ucrt_get_osfhandle as extern "win64" fn(_) -> _),
        "_fseeki64" => stub!(ucrt_fseeki64 as extern "win64" fn(_, _, _) -> _),
        "_ftelli64" => stub!(ucrt_ftelli64 as extern "win64" fn(_) -> _),
        "_fdopen" => stub!(ucrt_fdopen as extern "win64" fn(_, _) -> _),
        "_lock_file" => stub!(ucrt_lock_file as extern "win64" fn(_)),
        "_unlock_file" => stub!(ucrt_unlock_file as extern "win64" fn(_)),
        "remove" => stub!(ucrt_remove as extern "win64" fn(_) -> _),
        "_fstat64" => stub!(ucrt_fstat64 as extern "win64" fn(_, _) -> _),
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
        "longjmp" => stub!(ucrt_longjmp as extern "win64" fn(_, _) -> !),
        // exception handler
        "__C_specific_handler" => {
            stub!(ucrt_c_specific_handler as extern "win64" fn(_, _, _, _) -> _)
        }
        // misc
        "rand_s" => stub!(ucrt_rand_s as extern "win64" fn(_) -> _),
        "strftime" | "wcsftime" => stub!(ucrt_cexit as extern "win64" fn()),
        // legacy MSVCRT entry-point helpers
        "__getmainargs" => stub!(ucrt_getmainargs as unsafe extern "win64" fn(_, _, _, _, _) -> _),
        "__wgetmainargs" => stub!(ucrt_wgetmainargs as unsafe extern "win64" fn(_, _, _, _, _) -> _),
        "__initenv" => stub!(ucrt_initenv as unsafe extern "win64" fn() -> _),
        "__winitenv" => stub!(ucrt_winitenv as unsafe extern "win64" fn() -> _),
        // Legacy MSVCRT aliases — older MinGW CRT startup code uses these names
        "_fmode" => stub!(ucrt_p_fmode as unsafe extern "win64" fn() -> _),
        "_commode" => stub!(ucrt_p_commode as unsafe extern "win64" fn() -> _),
        "__mb_cur_max" => stub!(ucrt_mb_cur_max_func as extern "win64" fn() -> _),
        "_stricmp" | "_strcmpi" => stub!(ucrt_strcmp as unsafe extern "win64" fn(_, _) -> _),
        "_wcsdup" => stub!(ucrt_strdup as unsafe extern "win64" fn(_) -> _),
        "_flushall" | "_filbuf" | "_flsbuf" => stub!(ucrt_cexit as extern "win64" fn()),
        _ => None,
    }
}
