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

// ── Linux x86-64 ABI helpers ──────────────────────────────────────────────────
//
// Linux x86-64 va_list layout (SysV ABI §3.5.7).  Used to reconstruct a Linux
// va_list from a Windows-x64 va_list pointer so we can delegate to vsnprintf.
//
// Windows x64 va_list is a char* pointing to a contiguous 8-byte-aligned arg
// spill area.  Setting gp_offset=48 and fp_offset=176 marks all registers
// exhausted, so vsnprintf reads every argument from overflow_arg_area — which
// is exactly the Windows arg layout.
#[repr(C)]
struct VaListTag {
    gp_offset: u32,                 // 48 → all 6 GP regs exhausted
    fp_offset: u32,                 // 176 → all 8 XMM regs exhausted (48 + 8×16)
    overflow_arg_area: *mut c_void, // Windows va_list pointer goes here
    reg_save_area: *mut c_void,     // null (no GP/FP reg save needed)
}

extern "C" {
    // Linux x86-64: va_list is *__va_list_tag — passed as *mut VaListTag.
    fn vsnprintf(s: *mut u8, n: usize, format: *const u8, ap: *mut VaListTag) -> i32;
    // POSIX wchar classification (wctype_t is unsigned long = u64 on Linux).
    fn iswctype(c: u32, type_: u64) -> i32;
    fn wctype(name: *const libc::c_char) -> u64;
}

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

/// _wcsdup — duplicate a wide (UTF-16LE) string.
///
/// libc::wcsdup cannot be used here: on Linux wchar_t is 4 bytes but Windows
/// WCHAR is 2 bytes, so wcsdup would mis-count.  We count u16 units manually,
/// malloc (len+1)*2 bytes, and copy — identical to the MSVCRT behavior.
///
/// # Safety
/// `s` must be a valid null-terminated UTF-16LE string, or null.
/// Caller must free the returned pointer with `ucrt_free` / `free`.
pub unsafe extern "win64" fn ucrt_wcsdup(s: *const u16) -> *mut u16 {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut len = 0usize;
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    let size = (len + 1) * std::mem::size_of::<u16>();
    let buf = unsafe { libc::malloc(size) } as *mut u16;
    if buf.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { std::ptr::copy_nonoverlapping(s, buf, len + 1) };
    buf
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
    eprintln!("weave/ucrt: exit({code}) called");
    unsafe { libc::exit(code) }
}

#[allow(non_snake_case)]
pub extern "win64" fn ucrt__exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

/// abort — abnormal program termination.
///
/// Matches Wine's `dlls/msvcrt/exit.c:abort` (line 252) which calls
/// `raise(SIGABRT)` and then falls through to `_exit(3)`.  Using `libc::abort`
/// here is incorrect: glibc's abort() routes through `__libc_message`, tries
/// to flush stdio (`_IO_list_all` walk), and ends up in `__vfscanf_internal`
/// stream-cleanup territory.  When the guest's msvcrt-linked stdio has any
/// partially-initialised FILE state, glibc abort's stdio flush dereferences
/// through offsets that don't match Weave's stub FILE layout and raises
/// SIGABRT inside glibc internals — masking the real abort call site.
///
/// Wine ref: dlls/msvcrt/exit.c:252 — abort() calls raise(SIGABRT) and then
/// `_aexit_rtn(3)` (which is `_exit` by default, see line 60 of that file).
pub extern "win64" fn ucrt_abort() -> ! {
    unsafe {
        libc::raise(libc::SIGABRT);
        libc::_exit(3);
    }
}

/// raise — send a signal to the current process.
///
/// Wine ref: dlls/msvcrt/except.c — raise delegates to the host's signal
/// machinery; on Linux that is libc::raise which dispatches through the
/// installed sigaction handlers.
pub extern "win64" fn ucrt_raise(sig: i32) -> i32 {
    unsafe { libc::raise(sig) }
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
    eprintln!("weave: stub _configure_narrow_argv called");
    0
}
pub extern "win64" fn ucrt_initialize_narrow_environment() -> i32 {
    eprintln!("weave: stub _initialize_narrow_environment called");
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

// ── CRT runtime stubs — NXEngine / MSVC CRT startup path ────────────────────
//
// These are called by the MSVC CRT startup (exe_common.inl) before WinMain.
// Returning wrong values here causes the startup to call exit(0) or crash.

/// _get_narrow_winmain_command_line — returns the ANSI command line string.
///
/// Wine ref: dlls/msvcrt/wincmdln.c — returns a `char*` to the command-line
/// string used by the narrow WinMain entry point.  A NULL return causes the
/// MSVC CRT startup to crash (it calls GetCommandLineA and parses it; the
/// exe_common.inl path unconditionally passes the result to main()).
/// Safe stub: return a pointer to a static null-terminated empty string.
static NARROW_CMDLINE: [u8; 1] = [0u8];
pub unsafe extern "win64" fn ucrt_get_narrow_winmain_command_line() -> *const u8 {
    NARROW_CMDLINE.as_ptr()
}

/// _invalid_parameter_noinfo — called by MSVC CRT on invalid parameters (no info).
///
/// Wine ref: dlls/msvcrt/except.c — void no-op stub; callers do not check
/// the return value, they abort independently if needed.
pub unsafe extern "win64" fn ucrt_invalid_parameter_noinfo() {}

/// _invalid_parameter_noinfo_noreturn — same as above, marked noreturn in MSVC.
///
/// Wine ref: dlls/msvcrt/except.c — safe to return on Linux (the caller may
/// call exit() itself, but returning is not UB for our stub).
pub unsafe extern "win64" fn ucrt_invalid_parameter_noinfo_noreturn() {}

/// _register_thread_local_exe_atexit_callback — register per-thread atexit fn.
///
/// Wine ref: dlls/msvcrt/exit.c — registers a callback for thread-local
/// cleanup at exe exit.  Safe stub: ignore the function pointer, return 0.
pub unsafe extern "win64" fn ucrt_register_thread_local_exe_atexit_callback(
    _fn: *const c_void,
) -> i32 {
    0
}

/// _seh_filter_exe — SEH exception filter for EXE modules.
///
/// Wine ref: dlls/msvcrt/except.c — called from the SEH __except filter
/// expression in exe_common.inl.  Returns EXCEPTION_EXECUTE_HANDLER (1)
/// to execute the handler (which calls exit()).  Returning 0 would mean
/// EXCEPTION_CONTINUE_SEARCH and propagate the exception.
pub unsafe extern "win64" fn ucrt_seh_filter_exe(_code: u32, _info: *const c_void) -> i32 {
    1 // EXCEPTION_EXECUTE_HANDLER
}

/// _callnewh — call the new_handler if allocation fails.
///
/// Wine ref: dlls/msvcrt/heap.c — calls the installed new_handler(size).
/// Safe stub: no new_handler installed, return 0 (handler not called).
pub unsafe extern "win64" fn ucrt_callnewh(_size: usize) -> i32 {
    0
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
            b"weave: _initterm running\n".as_ptr() as *const libc::c_void,
            25,
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
            b"weave: _initterm_e running\n".as_ptr() as *const libc::c_void,
            27,
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
/// Contiguous fake FILE[3] array shared by both the msvcrt `_iob` DATA import
/// and the `__acrt_iob_func` FUNCTION import.
///
/// 64 bytes per slot — generous enough for any MSVC FILE struct layout.
/// Before, `_iob` used this array but `__acrt_iob_func` returned three
/// separate zero-initialised heap buffers.  That broke `stream_to_fd` (which
/// assumes `stdin/stdout/stderr` are at consecutive +64 offsets in one array)
/// and meant the FILE* returned by `__acrt_iob_func` had `_file`=0 for all
/// three streams.  libc's fortified stdio path derefs those fields during
/// `fprintf`/buffered I/O and faulted.
///
/// Wine ref: `dlls/msvcrt/file.c:265` — `__acrt_iob_func(idx)` returns
/// `&MSVCRT__iob[idx].file` (or `&MSVCRT__iob[idx]` pre-_MSVCR_VER 140), so
/// the three streams ARE contiguous entries of one array, not separate
/// allocations.
///
/// Wine ref: `dlls/msvcrt/msvcrt.h:26-35` — FILE layout is
/// `{char* _ptr; char* _base; int _cnt; int _flag; int _file; int _charbuf;
///   int _bufsiz; char* _tmpfname;}` — `_file` at byte offset 24.
///
/// Wine ref: `include/msvcrt/corecrt_wstdio.h:26` — under `_UCRT` the FILE
/// is opaque `{void* _Placeholder}`, so MinGW-against-ucrt only reads the
/// pointer identity (no field deref).  Populating `_file` covers both the
/// classic-msvcrt layout and the ucrt layout without harm.
static IOB_ARRAY: OnceLock<usize> = OnceLock::new();

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

/// _set_fmode — set the default file translation mode (_O_TEXT or _O_BINARY).
///
/// Wine ref: dlls/msvcrt/file.c — writes the value to the global _fmode variable.
/// Returns 0 on success, errno on failure (EINVAL if mode is invalid).
/// Safe stub: write to our heap-backed _fmode storage, return 0.
pub extern "win64" fn ucrt_set_fmode(mode: i32) -> i32 {
    let addr = fmode_data_addr() as *mut i32;
    unsafe { *addr = mode };
    0
}

static HEAP_MB_CUR_MAX: OnceLock<usize> = OnceLock::new();
static HEAP_INITENV: OnceLock<usize> = OnceLock::new();
static HEAP_WINITENV: OnceLock<usize> = OnceLock::new();
static HEAP_ENVIRON: OnceLock<usize> = OnceLock::new();
static HEAP_WENVIRON: OnceLock<usize> = OnceLock::new();
// HEAP_IARGC and HEAP_IARGV removed — argc/argv now parsed from cmdline in parsed_argc_argv().
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
/// Lazily-initialized argc/argv storage, pre-populated from the Weave command line.
///
/// The MinGW CRT startup reads `__argc` and `__argv` DATA imports directly.
/// We parse the command line at first access (which happens after cmdline::set()
/// has been called during IAT patching) so the guest sees real arguments.
///
/// Stored as `usize` pairs (raw-pointer-as-integer) to satisfy OnceLock's
/// Sync requirement — raw pointers are not Sync.
static HEAP_ARGV_PARSED: OnceLock<(usize, usize)> = OnceLock::new();

fn parsed_argc_argv() -> (usize, usize) {
    *HEAP_ARGV_PARSED.get_or_init(|| {
        let cmdline_ptr = weave_core::cmdline::get_a();
        // Safety: cmdline_ptr is valid null-terminated ANSI from weave_core::cmdline.
        let len = unsafe { libc::strlen(cmdline_ptr as *const libc::c_char) };
        let s = unsafe { std::slice::from_raw_parts(cmdline_ptr, len) };
        let s = std::str::from_utf8(s).unwrap_or("");
        let args = split_cmdline(s);
        let argc = args.len() as i32;
        // Build argv array: null-terminated list of null-terminated strings.
        let mut ptrs: Vec<*mut u8> = args
            .into_iter()
            .map(|arg| {
                let mut buf: Vec<u8> = arg.bytes().collect();
                buf.push(0);
                let boxed = buf.into_boxed_slice();
                Box::into_raw(boxed) as *mut u8
            })
            .collect();
        ptrs.push(std::ptr::null_mut()); // null terminator
        let argv = ptrs.as_mut_ptr() as usize;
        std::mem::forget(ptrs); // leak: process-lifetime
        let argc_box = Box::into_raw(Box::new(argc)) as usize;
        (argc_box, argv)
    })
}

pub fn argc_data_addr() -> usize {
    // Return pointer to the argc i32 (writable, heap).
    parsed_argc_argv().0
}
pub fn argv_data_addr() -> usize {
    // Return pointer to the argv pointer (writable, heap).
    // The DATA import slot holds the address of a `char**` variable.
    // We allocate a writable pointer cell pointing at the argv array.
    static HEAP_ARGV_PTR: OnceLock<usize> = OnceLock::new();
    *HEAP_ARGV_PTR.get_or_init(|| {
        let argv = parsed_argc_argv().1 as *mut *mut u8;
        Box::into_raw(Box::new(argv)) as usize
    })
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
    let ptr = argc_data_addr() as *mut i32;
    let val = unsafe { *ptr };
    eprintln!("weave: stub __p___argc called → ptr={ptr:?} argc={val}");
    ptr
}
/// # Safety
/// No pointer requirements; returns a pointer to heap-allocated CRT storage.
pub unsafe extern "win64" fn ucrt_p_argv() -> *mut *mut *mut u8 {
    let ptr = argv_data_addr() as *mut *mut *mut u8;
    eprintln!("weave: stub __p___argv called → ptr={ptr:?}");
    ptr
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
///
/// The same 192-byte array is used by `__acrt_iob_func` — see `IOB_ARRAY` doc.
/// The array is heap-allocated (writable) and populated with a minimal
/// MinGW-compatible layout: `_file` (byte offset 24) holds the fd number,
/// `_flag` (byte offset 20) holds `_IOREAD | _IOWRT` so callers can tell the
/// struct is initialised.
pub fn iob_data_addr() -> usize {
    *IOB_ARRAY.get_or_init(|| {
        // Leak a 192-byte writable buffer: three 64-byte FILE slots.
        let buf: Box<[u8; 192]> = Box::new([0u8; 192]);
        let base = Box::into_raw(buf) as *mut u8;
        // Populate `_file` (int at byte offset 24) and `_flag`
        // (int at byte offset 20) per the classic msvcrt `struct _iobuf`
        // layout (see `IOB_ARRAY` doc).  Harmless for the ucrt opaque
        // layout (those 8 bytes are past the single pointer field and
        // nobody reads them under `_UCRT`).
        //
        // _IOREAD = 0x0001, _IOWRT = 0x0002  — Wine `dlls/msvcrt/msvcrt.h:38`.
        const FLAG_RD: i32 = 0x0001;
        const FLAG_WR: i32 = 0x0002;
        unsafe {
            for (i, flag) in [FLAG_RD, FLAG_WR, FLAG_WR].iter().enumerate() {
                let slot = base.add(i * 64);
                let flag_ptr = slot.add(20) as *mut i32;
                let file_ptr = slot.add(24) as *mut i32;
                *flag_ptr = *flag;
                *file_ptr = i as i32; // stdin=0, stdout=1, stderr=2
            }
        }
        base as usize
    })
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

/// `__acrt_iob_func(idx)` — return `FILE*` for stdin (0), stdout (1),
/// stderr (2).
///
/// Returns a pointer into the shared `IOB_ARRAY` at stride 64 — the same
/// array backing the `_iob` DATA import — so `stream_to_fd` and all stdio
/// stubs that dispatch off the returned FILE* agree on the identity and fd
/// of each stream.
///
/// Before this fix, this stub handed back three separate zero-initialised
/// 256-byte heap buffers.  libc's fortified stdio path (called from
/// wget's MinGW startup) dereferenced the returned FILE*'s `_file` and
/// `_flag` fields: all three structs looked like stdin (fd=0, flag=0),
/// which broke invariants and surfaced as a SIGSEGV downstream.
///
/// Wine ref: `dlls/msvcrt/file.c:265` —
/// `static FILE* iob_get_file(int i) { return &MSVCRT__iob[i].file; }`
/// and `dlls/msvcrt/file.c:981` — `__acrt_iob_func` is the ucrt alias.
///
/// Wine ref: `include/msvcrt/corecrt_wstdio.h:50-52` —
/// `#define stdin  (__acrt_iob_func(0))`, stdout=1, stderr=2.
///
/// For out-of-range indices (wget passes only 0/1/2 but other callers
/// may probe), we fall back to the stdout slot rather than NULL — NULL
/// would re-introduce the fortified-deref SIGSEGV class that motivated
/// this fix.
pub extern "win64" fn ucrt_acrt_iob_func(fd: u32) -> *mut c_void {
    let base = iob_data_addr();
    let slot = match fd {
        0..=2 => fd as usize,
        _ => 1, // fall back to stdout rather than NULL
    };
    (base + slot * 64) as *mut c_void
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

/// __stdio_common_vfprintf — core vfprintf dispatch used by UCRT and MinGW CRT.
///
/// Wine ref: dlls/ucrtbase/__stdio_common_vfprintf.c — options bit 0 enables
/// legacy mode (no BOM stripping, no locale override). For our purposes, options
/// and locale are both ignored; we delegate directly to vsnprintf + write.
///
/// # Safety
/// `stream` must be a valid FILE* or one of the three standard streams.
/// `format` must be a valid null-terminated C format string.
/// `args` must be a valid Windows-x64 va_list for the given format.
pub unsafe extern "win64" fn ucrt_stdio_common_vfprintf(
    _options: u64,
    stream: *mut c_void,
    format: *const u8,
    _locale: *const c_void,
    args: *mut c_void,
) -> i32 {
    if format.is_null() {
        return -1;
    }
    // Count how many bytes the formatted output needs.
    let mut va_tag = VaListTag {
        gp_offset: 48,
        fp_offset: 176,
        overflow_arg_area: args,
        reg_save_area: std::ptr::null_mut(),
    };
    let needed = unsafe { vsnprintf(std::ptr::null_mut(), 0, format, &mut va_tag) };
    if needed <= 0 {
        return needed;
    }
    let buf_len = needed as usize + 1;
    let mut buf: Vec<u8> = vec![0u8; buf_len];
    // Re-init va_tag — vsnprintf consumed it above.
    let mut va_tag2 = VaListTag {
        gp_offset: 48,
        fp_offset: 176,
        overflow_arg_area: args,
        reg_save_area: std::ptr::null_mut(),
    };
    let written = unsafe { vsnprintf(buf.as_mut_ptr(), buf_len, format, &mut va_tag2) };
    if written > 0 {
        let fd = stream_to_fd(stream);
        unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, written as usize) };
    }
    written
}

/// __stdio_common_vsprintf — core sprintf dispatch used by UCRT and MinGW CRT.
///
/// Implementation: Windows x64 va_list is a char* into a contiguous 8-byte
/// argument spill area.  We construct a Linux x86-64 va_list with gp_offset=48
/// and fp_offset=176 (all registers exhausted) so vsnprintf reads every arg
/// from overflow_arg_area, which maps exactly onto the Windows arg layout.
/// Integer, pointer, and double (promoted float) args are all 8 bytes in both
/// ABIs when spilled to the overflow area.
///
/// # Safety
/// `buf` must be writable for `buf_count` bytes if non-null.
/// `format` must be a valid null-terminated C format string.
/// `args` must be a valid Windows-x64 va_list for the given format.
pub unsafe extern "win64" fn ucrt_stdio_common_vsprintf(
    _options: u64,
    buf: *mut u8,
    buf_count: usize,
    format: *const u8,
    _locale: *const c_void,
    args: *mut c_void,
) -> i32 {
    if format.is_null() {
        return -1;
    }
    let mut va_tag = VaListTag {
        gp_offset: 48,  // 6 GP regs × 8 bytes = 48 → all exhausted
        fp_offset: 176, // 48 + 8 XMM regs × 16 bytes = 176 → all exhausted
        overflow_arg_area: args,
        reg_save_area: std::ptr::null_mut(),
    };
    if buf.is_null() || buf_count == 0 {
        // Count-only mode: return number of chars that would be written.
        unsafe { vsnprintf(std::ptr::null_mut(), 0, format, &mut va_tag) }
    } else {
        unsafe { vsnprintf(buf, buf_count, format, &mut va_tag) }
    }
}

// ── snprintf / sprintf / printf / fprintf / puts / putchar ───────────────────

/// snprintf — write at most `count` bytes of formatted output into `buf`.
///
/// Wine ref: dlls/msvcrt/printf.c — snprintf delegates to __stdio_common_vsprintf
/// with options=0; buf/count/format/args passthrough. Null-terminates if count>0.
///
/// # Safety
/// `buf` must be writable for `count` bytes. `format` must be a null-terminated C string.
/// `args` must be a valid Windows-x64 va_list.
pub unsafe extern "win64" fn ucrt_snprintf(
    buf: *mut u8,
    count: usize,
    format: *const u8,
    args: *mut c_void,
) -> i32 {
    if format.is_null() {
        return -1;
    }
    let mut va_tag = VaListTag {
        gp_offset: 48,
        fp_offset: 176,
        overflow_arg_area: args,
        reg_save_area: std::ptr::null_mut(),
    };
    if buf.is_null() || count == 0 {
        unsafe { vsnprintf(std::ptr::null_mut(), 0, format, &mut va_tag) }
    } else {
        unsafe { vsnprintf(buf, count, format, &mut va_tag) }
    }
}

/// sprintf — write formatted output into `buf` (no size limit).
///
/// Wine ref: dlls/msvcrt/printf.c — sprintf calls vsnprintf with SIZE_MAX as the
/// count; callers are responsible for ensuring buf is large enough.
///
/// # Safety
/// `buf` must point to a buffer large enough for the formatted output.
/// `format` must be a null-terminated C string. `args` must be a valid Windows-x64 va_list.
pub unsafe extern "win64" fn ucrt_sprintf(
    buf: *mut u8,
    format: *const u8,
    args: *mut c_void,
) -> i32 {
    if format.is_null() || buf.is_null() {
        return -1;
    }
    let mut va_tag = VaListTag {
        gp_offset: 48,
        fp_offset: 176,
        overflow_arg_area: args,
        reg_save_area: std::ptr::null_mut(),
    };
    unsafe { vsnprintf(buf, usize::MAX, format, &mut va_tag) }
}

/// printf — write formatted output to stdout.
///
/// Wine ref: dlls/msvcrt/printf.c — printf calls vfprintf(stdout, fmt, args).
/// Weave: formats to a heap buffer via vsnprintf, then writes to fd 1.
///
/// # Safety
/// `format` must be a null-terminated C string. `args` must be a valid Windows-x64 va_list.
pub unsafe extern "win64" fn ucrt_printf(format: *const u8, args: *mut c_void) -> i32 {
    if format.is_null() {
        return -1;
    }
    let mut va_tag = VaListTag {
        gp_offset: 48,
        fp_offset: 176,
        overflow_arg_area: args,
        reg_save_area: std::ptr::null_mut(),
    };
    let needed = unsafe { vsnprintf(std::ptr::null_mut(), 0, format, &mut va_tag) };
    if needed <= 0 {
        return needed;
    }
    let buf_len = needed as usize + 1;
    let mut buf: Vec<u8> = vec![0u8; buf_len];
    let mut va_tag2 = VaListTag {
        gp_offset: 48,
        fp_offset: 176,
        overflow_arg_area: args,
        reg_save_area: std::ptr::null_mut(),
    };
    let written = unsafe { vsnprintf(buf.as_mut_ptr(), buf_len, format, &mut va_tag2) };
    if written > 0 {
        unsafe { libc::write(1, buf.as_ptr() as *const libc::c_void, written as usize) };
    }
    written
}

/// fprintf — write formatted output to a FILE* stream.
///
/// Wine ref: dlls/msvcrt/printf.c — fprintf routes through __stdio_common_vfprintf.
///
/// # Safety
/// `stream` must be a valid FILE*. `format` must be null-terminated. `args` must be a valid Windows-x64 va_list.
pub unsafe extern "win64" fn ucrt_fprintf_va(
    stream: *mut c_void,
    format: *const u8,
    args: *mut c_void,
) -> i32 {
    unsafe { ucrt_stdio_common_vfprintf(0, stream, format, std::ptr::null(), args) }
}

/// puts — write a string followed by a newline to stdout.
///
/// Wine ref: dlls/msvcrt/file.c — puts calls fwrite(s, 1, len, stdout) then
/// fwrite("\n", 1, 1, stdout). Returns non-negative on success, EOF on error.
///
/// # Safety
/// `s` must be a valid null-terminated C string.
pub unsafe extern "win64" fn ucrt_puts(s: *const u8) -> i32 {
    if s.is_null() {
        return -1;
    }
    let len = unsafe { libc::strlen(s as *const libc::c_char) };
    let r1 = unsafe { libc::write(1, s as *const libc::c_void, len) };
    let newline = b"\n";
    let r2 = unsafe { libc::write(1, newline.as_ptr() as *const libc::c_void, 1) };
    if r1 < 0 || r2 < 0 {
        -1
    } else {
        0
    }
}

/// putchar — write a single character to stdout.
///
/// Wine ref: dlls/msvcrt/file.c — putchar calls fputc(c, stdout).
pub extern "win64" fn ucrt_putchar(c: i32) -> i32 {
    let byte = (c & 0xFF) as u8;
    let r = unsafe { libc::write(1, &byte as *const u8 as *const libc::c_void, 1) };
    if r < 0 {
        -1
    } else {
        c
    }
}

// ── getenv / _wgetenv ─────────────────────────────────────────────────────────

/// getenv — look up an environment variable by narrow name.
///
/// Wine ref: dlls/msvcrt/environ.c — getenv calls libc getenv; returns null
/// if the variable is not set.
///
/// # Safety
/// `name` must be a valid null-terminated C string.
pub unsafe extern "win64" fn ucrt_getenv(name: *const u8) -> *const u8 {
    if name.is_null() {
        return std::ptr::null();
    }
    unsafe { libc::getenv(name as *const libc::c_char) as *const u8 }
}

/// _wgetenv — look up an environment variable by wide (UTF-16LE) name.
///
/// Wine ref: dlls/msvcrt/environ.c — _wgetenv converts the wide name to ANSI,
/// calls getenv, then converts the result back to a wide string in a static
/// per-thread buffer. We convert to UTF-8 via a heap buffer, call getenv,
/// then convert the result to a heap-allocated wide string. Returns null if
/// not found. The returned pointer is valid until the next call to _wgetenv.
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16LE string.
pub unsafe extern "win64" fn ucrt_wgetenv(name: *const u16) -> *const u16 {
    if name.is_null() {
        return std::ptr::null();
    }
    // Convert wide name to a narrow UTF-8 string.
    let mut len = 0usize;
    unsafe {
        while *name.add(len) != 0 {
            len += 1;
        }
    }
    let wide_slice = unsafe { std::slice::from_raw_parts(name, len) };
    let narrow: String = wide_slice
        .iter()
        .map(|&c| if c < 128 { c as u8 as char } else { '?' })
        .collect();
    let narrow_cstr = match std::ffi::CString::new(narrow) {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };
    let val = unsafe { libc::getenv(narrow_cstr.as_ptr()) };
    if val.is_null() {
        return std::ptr::null();
    }
    // Convert the narrow result to a heap-allocated wide (UTF-16LE) string.
    let val_bytes = unsafe { std::ffi::CStr::from_ptr(val) }.to_bytes();
    let mut wide: Vec<u16> = val_bytes.iter().map(|&b| b as u16).collect();
    wide.push(0);
    // Leak the allocation — the caller must not free it (Windows convention for getenv).
    Box::into_raw(wide.into_boxed_slice()) as *const u16
}

// ── math functions ─────────────────────────────────────────────────────────────

// Double-precision (f64) math delegates — each uses Rust's f64 methods.
pub extern "win64" fn ucrt_sin(x: f64) -> f64 {
    x.sin()
}
pub extern "win64" fn ucrt_cos(x: f64) -> f64 {
    x.cos()
}
pub extern "win64" fn ucrt_tan(x: f64) -> f64 {
    x.tan()
}
pub extern "win64" fn ucrt_sqrt(x: f64) -> f64 {
    x.sqrt()
}
pub extern "win64" fn ucrt_floor(x: f64) -> f64 {
    x.floor()
}
pub extern "win64" fn ucrt_ceil(x: f64) -> f64 {
    x.ceil()
}
pub extern "win64" fn ucrt_log(x: f64) -> f64 {
    x.ln()
}
pub extern "win64" fn ucrt_log2(x: f64) -> f64 {
    x.log2()
}
pub extern "win64" fn ucrt_log10(x: f64) -> f64 {
    x.log10()
}
pub extern "win64" fn ucrt_exp(x: f64) -> f64 {
    x.exp()
}
pub extern "win64" fn ucrt_pow(base: f64, exp: f64) -> f64 {
    base.powf(exp)
}
pub extern "win64" fn ucrt_fabs(x: f64) -> f64 {
    x.abs()
}
pub extern "win64" fn ucrt_fmod(x: f64, y: f64) -> f64 {
    x % y
}
pub extern "win64" fn ucrt_atan(x: f64) -> f64 {
    x.atan()
}
pub extern "win64" fn ucrt_atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}
pub extern "win64" fn ucrt_asin(x: f64) -> f64 {
    x.asin()
}
pub extern "win64" fn ucrt_acos(x: f64) -> f64 {
    x.acos()
}

// Single-precision (f32) math delegates.
pub extern "win64" fn ucrt_sinf(x: f32) -> f32 {
    x.sin()
}
pub extern "win64" fn ucrt_cosf(x: f32) -> f32 {
    x.cos()
}
pub extern "win64" fn ucrt_tanf(x: f32) -> f32 {
    x.tan()
}
pub extern "win64" fn ucrt_sqrtf(x: f32) -> f32 {
    x.sqrt()
}
pub extern "win64" fn ucrt_floorf(x: f32) -> f32 {
    x.floor()
}
pub extern "win64" fn ucrt_ceilf(x: f32) -> f32 {
    x.ceil()
}
pub extern "win64" fn ucrt_fabsf(x: f32) -> f32 {
    x.abs()
}
pub extern "win64" fn ucrt_fmodf(x: f32, y: f32) -> f32 {
    x % y
}
pub extern "win64" fn ucrt_atan2f(y: f32, x: f32) -> f32 {
    y.atan2(x)
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

/// perror — write `s: <errno-message>\n` to stderr.
///
/// Wine ref: dlls/msvcrt/file.c — perror fetches the thread-local errno,
/// formats "<prefix>: <strerror(errno)>\n", and writes it to stderr without
/// buffering. When `s` is null, only the errno message is emitted.
///
/// # Safety
/// `s`, if non-null, must be a valid null-terminated C string.
pub unsafe extern "win64" fn ucrt_perror(s: *const u8) {
    let errnum = unsafe { *libc::__errno_location() };
    let msg = unsafe { libc::strerror(errnum) };
    unsafe {
        if !s.is_null() {
            let plen = libc::strlen(s as *const libc::c_char);
            if plen > 0 {
                libc::write(2, s as *const libc::c_void, plen);
            }
            libc::write(2, b": ".as_ptr() as *const libc::c_void, 2);
        }
        if !msg.is_null() {
            let mlen = libc::strlen(msg);
            libc::write(2, msg as *const libc::c_void, mlen);
        }
        libc::write(2, b"\n".as_ptr() as *const libc::c_void, 1);
    }
}

/// # Safety
/// `_expr` and `_file` must be valid null-terminated byte strings if non-null (they are not read — this stub calls abort immediately).
pub unsafe extern "win64" fn ucrt_assert(_expr: *const u8, _file: *const u8, _line: u32) {
    unsafe { libc::abort() }
}

/// _beginthreadex — create a Windows thread backed by a real OS thread.
///
/// Wine ref: dlls/msvcrt/thread.c — _beginthreadex calls CreateThread with a
/// trampoline; trampoline calls start_address_ex(arglist) then _endthreadex(retval).
/// On x86-64 the start routine is `unsigned int (__stdcall *)(void *)` which is
/// identical to `extern "win64" fn(*mut u8) -> u32`.  Returns 0 on failure,
/// the thread handle (uintptr_t) on success.  _flags / initflag is forwarded to
/// CreateThread (CREATE_SUSPENDED=0x4 defers start); Weave ignores it as
/// kernel32::create_thread does.
///
/// # Safety
/// `start` must be a valid `extern "win64"` function pointer for the duration
/// of the spawned thread.  `arg` is forwarded as the sole argument and must
/// remain valid for the thread's lifetime.  `thread_id` must be null or a
/// valid pointer to a writable `u32`.
pub unsafe extern "win64" fn ucrt_beginthreadex(
    _security: *const c_void,
    _stack_size: u32,
    start: *const c_void,
    arg: *const c_void,
    _flags: u32,
    thread_id: *mut u32,
) -> usize {
    if start.is_null() {
        return 0;
    }

    let fn_addr = start as usize;
    let param_addr = arg as usize;

    eprintln!("weave/_beginthreadex: fn={start:p} arg={arg:p} (spawning thread)");

    let completion = std::sync::Arc::new(weave_core::handles::ThreadCompletion {
        result: std::sync::Mutex::new(None),
        condvar: std::sync::Condvar::new(),
    });
    let completion_clone = std::sync::Arc::clone(&completion);

    // SAFETY: `fn_addr` is a Win64-ABI function pointer in the mapped PE image.
    // The PE image stays mapped for the process lifetime, so the pointer is valid
    // for the duration of the spawned thread.  `param_addr` is forwarded as the
    // sole RCX argument, matching the _beginthreadex start-routine signature
    // `unsigned int (__stdcall *)(void *)` on x86-64.
    let join_handle = std::thread::spawn(move || {
        let fn_ptr: unsafe extern "win64" fn(*mut u8) -> u32 =
            unsafe { std::mem::transmute(fn_addr as *const u8) };
        let ret = unsafe { fn_ptr(param_addr as *mut u8) };
        eprintln!("weave/_beginthreadex: fn={fn_addr:#x} thread returned {ret}");
        let mut guard = completion_clone.result.lock().unwrap();
        *guard = Some(ret);
        completion_clone.condvar.notify_all();
    });

    let handle = weave_core::handles::alloc_thread(completion, join_handle);

    if !thread_id.is_null() {
        unsafe { *thread_id = 1 };
    }
    handle
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

/// `___lc_codepage_func` — return the current thread locale's ANSI codepage.
///
/// Wine ref: `dlls/msvcrt/locale.c:1045-1049` —
/// ```c
/// unsigned int CDECL ___lc_codepage_func(void)
/// {
///     return get_locinfo()->lc_codepage;
/// }
/// ```
///
/// Weave has no per-thread locinfo; wget (MinGW CRT) calls this during
/// stdio init to pick an MBCS codepage for its `fprintf` path.  Returning
/// `1252` (Windows-1252 / CP_ACP on en-US) matches the default MSVCRT
/// "C" locale codepage observed on Windows and satisfies wget's decoder
/// without pulling in a locale subsystem.  Returning 0 (unresolved) made
/// wget loop in its retry-backoff init because the codepage probe failed.
pub extern "win64" fn ucrt_lc_codepage_func() -> u32 {
    1252
}
/// localeconv: return pointer to locale formatting structure.
///
/// SDL2 (MinGW) calls localeconv() to get the decimal separator and
/// numeric formatting. Returning NULL causes SDL2 to crash when it
/// dereferences the lconv* pointer. Delegate to the host libc so callers
/// get a valid, fully-populated struct lconv (decimal_point = "." etc.).
pub extern "win64" fn ucrt_localeconv() -> *const c_void {
    unsafe { libc::localeconv() as *const c_void }
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

// ── msvcrt _lock / _unlock — recursive per-slot critical sections ────────────
//
// Wine ref: `dlls/msvcrt/lock.c:83` — `_lock(int locknum)` lazy-initialises
// `lock_table[locknum].crit` (a Win32 CRITICAL_SECTION, which is recursive),
// then `EnterCriticalSection`. `_unlock(int locknum)` calls `LeaveCriticalSection`.
// MinGW-linked binaries that use msvcrt.dll for stdio synchronisation rely on
// these to serialise file I/O across threads. MSVCRT's lock table has
// `_TOTAL_LOCKS = 64` slots (mingw-w64 `mtdll.h`).
//
// When unresolved, wget (and any MinGW CRT consumer) silently skips the lock
// and later corrupts shared msvcrt state — the corruption surfaces as a
// SIGABRT inside libc's fortified-read path, far from the missing lock call.
//
// Weave implementation: `pthread_mutex_t` with `PTHREAD_MUTEX_RECURSIVE` to
// match CRITICAL_SECTION semantics exactly. Lazy-initialised per slot via
// `OnceLock`. Negative or out-of-range locknum is silently ignored — matches
// msvcrt's lenient behaviour for trace callers passing speculative indices.

#[cfg(target_os = "linux")]
const MSVCRT_TOTAL_LOCKS: usize = 64;

#[cfg(target_os = "linux")]
struct RecursiveCs(std::cell::UnsafeCell<libc::pthread_mutex_t>);

// SAFETY: pthread_mutex_t is designed for cross-thread access; we initialise
// with PTHREAD_MUTEX_RECURSIVE and only ever call pthread_mutex_{lock,unlock}
// on the same heap-stable address. The `UnsafeCell` is only needed because
// libc's functions take `*mut` but we share the reference as `&'static`.
#[cfg(target_os = "linux")]
unsafe impl Sync for RecursiveCs {}

#[cfg(target_os = "linux")]
impl RecursiveCs {
    fn new() -> Self {
        let cell =
            std::cell::UnsafeCell::new(unsafe { std::mem::zeroed::<libc::pthread_mutex_t>() });
        unsafe {
            let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
            if libc::pthread_mutexattr_init(&mut attr) == 0 {
                libc::pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);
                libc::pthread_mutex_init(cell.get(), &attr);
                libc::pthread_mutexattr_destroy(&mut attr);
            }
        }
        Self(cell)
    }
    /// # Safety
    /// Must be paired with a matching `unlock` on the same thread.
    unsafe fn lock(&self) {
        unsafe { libc::pthread_mutex_lock(self.0.get()) };
    }
    /// # Safety
    /// Caller must currently hold the lock on this thread.
    unsafe fn unlock(&self) {
        unsafe { libc::pthread_mutex_unlock(self.0.get()) };
    }
}

#[cfg(target_os = "linux")]
fn msvcrt_lock_table() -> &'static [std::sync::OnceLock<RecursiveCs>; MSVCRT_TOTAL_LOCKS] {
    static TABLE: std::sync::OnceLock<[std::sync::OnceLock<RecursiveCs>; MSVCRT_TOTAL_LOCKS]> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| std::array::from_fn(|_| std::sync::OnceLock::new()))
}

#[cfg(target_os = "linux")]
fn msvcrt_cs(n: usize) -> &'static RecursiveCs {
    msvcrt_lock_table()[n].get_or_init(RecursiveCs::new)
}

/// msvcrt `_lock(int locknum)` — acquire the recursive critical section for
/// slot `locknum`. Lazy-init on first use. No-op for out-of-range indices.
pub extern "win64" fn ucrt_lock(locknum: i32) {
    #[cfg(target_os = "linux")]
    {
        if locknum < 0 {
            return;
        }
        let n = locknum as usize;
        if n >= MSVCRT_TOTAL_LOCKS {
            return;
        }
        unsafe { msvcrt_cs(n).lock() };
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = locknum;
    }
}

/// msvcrt `_unlock(int locknum)` — release the recursive critical section for
/// slot `locknum`. No-op for out-of-range indices or non-held locks.
pub extern "win64" fn ucrt_unlock(locknum: i32) {
    #[cfg(target_os = "linux")]
    {
        if locknum < 0 {
            return;
        }
        let n = locknum as usize;
        if n >= MSVCRT_TOTAL_LOCKS {
            return;
        }
        unsafe { msvcrt_cs(n).unlock() };
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = locknum;
    }
}
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

/// _open_osfhandle — wrap a Windows HANDLE in a CRT file descriptor.
///
/// Wine ref: dlls/msvcrt/file.c:2711-2745 — allocates a new CRT fd entry
/// for the given HANDLE, sets WX_TTY/WX_PIPE/WX_OPEN flags based on
/// GetFileType(), and returns the fd. Returns -1 on error.
///
/// In Weave, `ws_socket` returns the Linux fd directly as the "HANDLE"
/// (see weave-ws2/src/lib.rs:324), so the HANDLE value IS already a valid
/// int fd. We therefore round-trip it unchanged: `_open_osfhandle` returns
/// `handle as i32`, and `_get_osfhandle` reverses it as `fd as isize`.
/// This matches Wine's contract for the MinGW-static wget.exe path where
/// the caller (`WSASocketW` → `_open_osfhandle` → `_get_osfhandle` →
/// `setsockopt`) only requires that the fd round-trips to the original
/// SOCKET value.
///
/// Oflags are ignored — Weave does not track CRT-level _O_BINARY/_O_TEXT
/// distinctions. Returns -1 only if `handle` is negative (would collide
/// with error sentinel).
pub extern "win64" fn ucrt_open_osfhandle(handle: isize, _oflags: i32) -> i32 {
    if handle < 0 {
        return -1;
    }
    handle as i32
}

/// _get_osfhandle — retrieve the Windows HANDLE for a CRT file descriptor.
///
/// Wine ref: dlls/msvcrt/file.c — `_get_osfhandle(fd)` returns the HANDLE
/// stored in the CRT ioinfo table for `fd`, or `INVALID_HANDLE_VALUE`
/// (-1) if `fd` is out of range.
///
/// Inverse of `ucrt_open_osfhandle`: since sockets are the only case
/// exercised by wget and ws_socket returns the Linux fd as the HANDLE,
/// the fd value IS the HANDLE. Round-trip is identity.
pub extern "win64" fn ucrt_get_osfhandle(fd: i32) -> isize {
    if fd < 0 {
        return -1;
    }
    fd as isize
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
    eprintln!(
        "weave/ucrt_fopen: {:?} → {:?}",
        linux_path,
        if result.is_null() { "NULL" } else { "OK" }
    );
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

// ── Command-line argument parsing helpers ────────────────────────────────────
//
// Windows CRT __getmainargs / __wgetmainargs supply the parsed argc/argv to
// the guest main(). We parse the full command line stored in weave_core::cmdline
// so the guest sees real arguments, not a stub [""].
//
// Parsing rules (simplified Windows CmdLineToArgvW semantics):
//   - Arguments separated by spaces/tabs.
//   - Quoted strings: content between "" is a single argument.
//   - No backslash-escaping (handles the common case; full MSVC rules not needed).

/// Parse a null-terminated ANSI command line into a Vec of owned byte-strings.
/// Each string is null-terminated and lives in its own Box<[u8]>.
fn parse_cmdline_a(cmdline: *const u8) -> Vec<*mut u8> {
    // Safety: cmdline is a valid null-terminated string from weave_core::cmdline::get_a()
    let s = unsafe {
        let len = libc::strlen(cmdline as *const libc::c_char);
        std::slice::from_raw_parts(cmdline, len)
    };
    let s = std::str::from_utf8(s).unwrap_or("");
    let args = split_cmdline(s);
    let mut ptrs: Vec<*mut u8> = args
        .into_iter()
        .map(|arg| {
            let mut buf: Vec<u8> = arg.bytes().collect();
            buf.push(0);
            let boxed = buf.into_boxed_slice();
            Box::into_raw(boxed) as *mut u8
        })
        .collect();
    ptrs.push(std::ptr::null_mut()); // null terminator for argv
    ptrs
}

/// Parse a null-terminated wide command line into a Vec of owned u16-strings.
fn parse_cmdline_w(cmdline: *const u16) -> Vec<*mut u16> {
    // Safety: cmdline is a valid null-terminated wide string from weave_core::cmdline::get_w()
    let len = unsafe {
        let mut p = cmdline;
        while *p != 0 {
            p = p.add(1);
        }
        p.offset_from(cmdline) as usize
    };
    let s = unsafe { std::slice::from_raw_parts(cmdline, len) };
    let s = String::from_utf16_lossy(s);
    let args = split_cmdline(&s);
    let mut ptrs: Vec<*mut u16> = args
        .into_iter()
        .map(|arg| {
            let mut buf: Vec<u16> = arg.encode_utf16().collect();
            buf.push(0);
            let boxed = buf.into_boxed_slice();
            Box::into_raw(boxed) as *mut u16
        })
        .collect();
    ptrs.push(std::ptr::null_mut()); // null terminator for argv
    ptrs
}

/// Split a Windows command-line string into individual argument strings.
/// Handles quoted arguments and whitespace separators.
fn split_cmdline(s: &str) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// __getmainargs — legacy MSVCRT function that fills in argc/argv/envp for main().
///
/// Old MinGW-compiled executables call this to retrieve the parsed command line
/// before calling main(). We parse the Weave command line from weave_core::cmdline.
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
    // Parse actual command line so the guest sees real arguments.
    let cmdline_ptr = weave_core::cmdline::get_a();
    let mut arg_ptrs = parse_cmdline_a(cmdline_ptr);
    let argc = (arg_ptrs.len() - 1) as i32; // exclude null terminator
    let argv = arg_ptrs.as_mut_ptr();
    // Leak: argv lives for program lifetime.
    std::mem::forget(arg_ptrs);
    // envp[0] = NULL
    let envp = Box::into_raw(Box::new([std::ptr::null_mut::<u8>()])) as *mut *mut u8;
    if !p_argc.is_null() {
        unsafe {
            *p_argc = argc;
        }
    }
    if !p_argv.is_null() {
        unsafe {
            *p_argv = argv;
        }
    }
    if !p_envp.is_null() {
        unsafe {
            *p_envp = envp;
        }
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
    // Parse actual wide command line so the guest sees real arguments.
    let cmdline_ptr = weave_core::cmdline::get_w();
    let mut arg_ptrs = parse_cmdline_w(cmdline_ptr);
    let argc = (arg_ptrs.len() - 1) as i32; // exclude null terminator
    let argv = arg_ptrs.as_mut_ptr();
    // Leak: argv lives for program lifetime.
    std::mem::forget(arg_ptrs);
    // envp[0] = NULL
    let envp = Box::into_raw(Box::new([std::ptr::null_mut::<u16>()])) as *mut *mut u16;
    if !p_argc.is_null() {
        unsafe {
            *p_argc = argc;
        }
    }
    if !p_argv.is_null() {
        unsafe {
            *p_argv = argv;
        }
    }
    if !p_envp.is_null() {
        unsafe {
            *p_envp = envp;
        }
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

/// `__std_terminate` — VCRUNTIME140.dll terminate hook. Calls abort().
/// Wine ref: dlls/msvcp140/msvcp140.c — __std_terminate calls terminate() → abort().
pub unsafe extern "win64" fn ucrt_std_terminate() -> ! {
    libc::abort()
}

/// `__vcrt_InitializeCriticalSectionEx` — VCRUNTIME140.dll internal CS init.
/// Called by the MSVC CRT to initialise its own CRITICAL_SECTION during startup.
/// Calls pthread_mutex_init directly — does not go through the kernel32 handle table.
/// Returns TRUE (1).
pub unsafe extern "win64" fn ucrt_vcrt_init_cs(
    cs: *mut libc::pthread_mutex_t,
    _spin: u32,
    _flags: u32,
) -> i32 {
    libc::pthread_mutex_init(cs, core::ptr::null());
    1 // TRUE
}

/// `__std_exception_copy` — copy an MSVC exception object.
/// No-op is safe for NXEngine which uses C++ exceptions only on error paths.
pub unsafe extern "win64" fn ucrt_std_exception_copy(_src: *const (), _dst: *mut ()) {}

/// `__std_exception_destroy` — destroy an MSVC exception object.
/// No-op is safe for NXEngine which uses C++ exceptions only on error paths.
pub unsafe extern "win64" fn ucrt_std_exception_destroy(_exc: *mut ()) {}

// ── Sprint A: confirmed bug fixes ─────────────────────────────────────────────

/// _isatty — test whether a CRT fd refers to a terminal.
///
/// SDL2 and MinGW CRT startup call _isatty to decide buffering mode.
/// On Linux under Weave the CRT fd table is not yet implemented, so we
/// conservatively return 0 (not a terminal) for all fds.  This avoids
/// the previous void-stub behaviour that returned garbage in RAX.
pub extern "win64" fn ucrt_isatty(_fd: i32) -> i32 {
    0
}

/// iswctype — test if a wide character belongs to a character class.
///
/// Delegates to Linux libc iswctype.  On Linux wctype_t is u64; Windows
/// passes a u32-truncated value which we zero-extend — safe because glibc
/// wctype() return values fit in 16 bits.
pub extern "win64" fn ucrt_iswctype(c: u32, desc: u64) -> i32 {
    unsafe { iswctype(c, desc) }
}

/// wctype — return character-class descriptor for a named class.
///
/// Delegates to Linux libc wctype.  The returned u64 will be truncated
/// to u32 by the Windows caller, but glibc values are small and lossless.
///
/// # Safety
/// `name` must be a valid null-terminated ASCII string.
pub unsafe extern "win64" fn ucrt_wctype_fn(name: *const u8) -> u64 {
    unsafe { wctype(name as *const libc::c_char) }
}

/// strftime — format a broken-down time into a string.
///
/// Delegates to libc strftime.  Windows struct tm and POSIX struct tm share
/// the same 9 standard fields at the same offsets on x86-64, so the pointer
/// can be passed directly.  Format codes using the glibc-only tm_gmtoff /
/// tm_zone fields (%z, %Z) may produce empty output — acceptable for Sprint A.
///
/// # Safety
/// `s` must be writable for `max` bytes. `format` must be null-terminated.
/// `tm` must point to a valid Windows struct tm (at minimum 9 int fields).
pub unsafe extern "win64" fn ucrt_strftime(
    s: *mut u8,
    max: usize,
    format: *const u8,
    tm: *const c_void,
) -> usize {
    if s.is_null() || max == 0 || format.is_null() || tm.is_null() {
        return 0;
    }
    unsafe {
        libc::strftime(
            s as *mut libc::c_char,
            max,
            format as *const libc::c_char,
            tm as *const libc::tm,
        )
    }
}

/// wcsftime — wide-character strftime.
///
/// Not delegated to libc: Linux wcsftime uses 4-byte wchar_t while Windows
/// uses 2-byte WCHAR.  Returns 0 (empty output) which is safe and prevents
/// the previous garbage-in-RAX from the ucrt_cexit alias.
pub extern "win64" fn ucrt_wcsftime(
    _s: *mut u16,
    _max: usize,
    _format: *const u16,
    _tm: *const c_void,
) -> usize {
    0
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

// ── __stdio_common_v*scanf family ────────────────────────────────────────────
//
// These are UCRTBASE exports that MinGW's stdio.h inline wrappers call for
// sscanf / vsscanf / fscanf / vfscanf / swscanf / vswscanf / fwscanf / vfwscanf.
//
// Signature per Wine dlls/msvcrt/scanf.c:667 (`__stdio_common_vsscanf`) and
// line 707 (`__stdio_common_vfscanf`):
//
//     int __cdecl __stdio_common_vsscanf(u64 options, const char *input,
//                                        size_t length, const char *format,
//                                        _locale_t locale, va_list valist);
//     int __cdecl __stdio_common_vfscanf(u64 options, FILE *file,
//                                        const char *format,
//                                        _locale_t locale, va_list valist);
//
// Return value: number of successful conversions (0..N), or `EOF` on input
// failure per Wine's vsnscanf_s_l delegation. Callers often check
// `ret == EOF` (−1) or `ret >= expected_count`.
//
// Weave does not implement scanf parsing.  Returning 0 (zero conversions)
// is safe — it matches "no input matched" and the caller handles it as
// a non-fatal parse failure.
//
// Prior bug: these symbols were aliased to `ucrt_cexit` (a `void()` stub),
// violating the `int(...)` ABI.  The first GP register return value was
// whatever RAX held after `libc::write` returned (typically the count of
// bytes written, ~19).  A caller reading that as a scanf conversion count
// would treat it as "19 conversions succeeded" and dereference uninitialised
// output buffers — a latent "stub returns value caller dereferences without
// validation" instance (KNOWN-BUG-CLASSES:795).
pub extern "win64" fn ucrt_stdio_common_vsscanf(
    _options: u64,
    _input: *const u8,
    _length: usize,
    _format: *const u8,
    _locale: *const c_void,
    _valist: *const c_void,
) -> i32 {
    0
}

pub extern "win64" fn ucrt_stdio_common_vfscanf(
    _options: u64,
    _file: *mut c_void,
    _format: *const u8,
    _locale: *const c_void,
    _valist: *const c_void,
) -> i32 {
    0
}

pub extern "win64" fn ucrt_stdio_common_vswscanf(
    _options: u64,
    _input: *const u16,
    _length: usize,
    _format: *const u16,
    _locale: *const c_void,
    _valist: *const c_void,
) -> i32 {
    0
}

pub extern "win64" fn ucrt_stdio_common_vfwscanf(
    _options: u64,
    _file: *mut c_void,
    _format: *const u16,
    _locale: *const c_void,
    _valist: *const c_void,
) -> i32 {
    0
}

/// ??1type_info@@UEAA@XZ — type_info destructor. No-op (no real RTTI objects).
///
/// # Safety
/// `this` is accepted but not dereferenced.
pub unsafe extern "win64" fn ucrt_type_info_dtor(_this: *mut u8) {}

// ── Additional string functions (Task 01 — curl) ─────────────────────────────

/// strncpy_s — bounded strcpy with null-termination guarantee. Returns 0 on success.
///
/// Wine ref: dlls/msvcrt/string.c — strncpy_s copies at most count chars, always
/// null-terminates dst[0] on failure, returns EINVAL(22) or ERANGE(34).
///
/// # Safety
/// `dst` must be a writable buffer of `size_dst` bytes. `src` must be readable.
pub unsafe extern "win64" fn ucrt_strncpy_s(
    dst: *mut u8,
    size_dst: usize,
    src: *const u8,
    count: usize,
) -> i32 {
    if dst.is_null() || size_dst == 0 {
        return 22; // EINVAL
    }
    if src.is_null() {
        *dst = 0;
        return 22; // EINVAL
    }
    let copy_max = count.min(size_dst - 1);
    let mut i = 0usize;
    while i < copy_max {
        let c = *src.add(i);
        *dst.add(i) = c;
        if c == 0 {
            return 0;
        }
        i += 1;
    }
    *dst.add(i) = 0;
    // If count > copy_max and src still has chars, truncation occurred = ERANGE
    if count > copy_max && !src.add(i).is_null() && *src.add(i) != 0 {
        *dst = 0; // truncate-to-empty on overflow (strncpy_s MSVCRT behavior)
        return 34; // ERANGE
    }
    0
}

/// _strnicmp — case-insensitive bounded string compare. Delegates to strncasecmp.
///
/// Wine ref: dlls/msvcrt/string.c — _strnicmp uses locale-aware case fold on
/// Windows; on Linux we use strncasecmp which matches the C locale behavior.
///
/// # Safety
/// `s1` and `s2` must be readable for at least `n` bytes.
pub unsafe extern "win64" fn ucrt_strnicmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    if n == 0 {
        return 0;
    }
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    libc::strncasecmp(s1 as *const libc::c_char, s2 as *const libc::c_char, n)
}

/// strcspn — return the length of the initial segment not containing any char in `reject`.
///
/// Wine ref: dlls/msvcrt/string.c — delegates directly to POSIX strcspn.
///
/// # Safety
/// `s` and `reject` must be null-terminated byte strings.
pub unsafe extern "win64" fn ucrt_strcspn(s: *const u8, reject: *const u8) -> usize {
    libc::strcspn(s as *const libc::c_char, reject as *const libc::c_char)
}

/// strpbrk — find the first occurrence of any char from `accept` in `s`.
///
/// Wine ref: dlls/msvcrt/string.c — delegates to POSIX strpbrk.
///
/// # Safety
/// `s` and `accept` must be null-terminated byte strings.
pub unsafe extern "win64" fn ucrt_strpbrk(s: *const u8, accept: *const u8) -> *mut u8 {
    libc::strpbrk(s as *const libc::c_char, accept as *const libc::c_char) as *mut u8
}

/// strspn — return the length of the initial segment containing only chars from `accept`.
///
/// Wine ref: dlls/msvcrt/string.c — delegates to POSIX strspn.
///
/// # Safety
/// `s` and `accept` must be null-terminated byte strings.
pub unsafe extern "win64" fn ucrt_strspn(s: *const u8, accept: *const u8) -> usize {
    libc::strspn(s as *const libc::c_char, accept as *const libc::c_char)
}

/// mbrlen — determine the number of bytes in the next multibyte character.
///
/// Wine ref: dlls/msvcrt/mbcs.c — mbrlen calls mbrtowc with internal state.
/// Stub: treats input as single-byte locale, returns 1 for non-null bytes.
///
/// # Safety
/// `s` must point to at least `n` readable bytes, or be null.
pub unsafe extern "win64" fn ucrt_mbrlen(s: *const u8, n: usize, _ps: *mut u8) -> usize {
    if s.is_null() || n == 0 {
        return 0;
    }
    if *s == 0 {
        return 0; // null char
    }
    1 // single-byte locale stub
}

/// strerror_s — write the error string for `errnum` into `buf`.
///
/// Wine ref: dlls/msvcrt/errno.c — strerror_s copies strerror(errnum) into buf,
/// truncating if necessary; always null-terminates. Returns 0 on success.
///
/// # Safety
/// `buf` must be a writable buffer of at least `buf_size` bytes.
pub unsafe extern "win64" fn ucrt_strerror_s(buf: *mut u8, buf_size: usize, errnum: i32) -> i32 {
    if buf.is_null() || buf_size == 0 {
        return 22; // EINVAL
    }
    let msg = libc::strerror(errnum);
    if msg.is_null() {
        *buf = 0;
        return 0;
    }
    let len = libc::strlen(msg);
    let copy = len.min(buf_size - 1);
    std::ptr::copy_nonoverlapping(msg as *const u8, buf, copy);
    *buf.add(copy) = 0;
    0
}

// ── Additional wide string functions ─────────────────────────────────────────

/// wcsncmp — compare at most n wide chars of two strings.
///
/// Wine ref: dlls/msvcrt/wcs.c — wcsncmp compares up to n wchar_t elements.
///
/// # Safety
/// `s1` and `s2` must be readable for at least `n` wide chars.
pub unsafe extern "win64" fn ucrt_wcsncmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    if n == 0 {
        return 0;
    }
    for i in 0..n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return (a as i32) - (b as i32);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

/// wcsncpy_s — bounded wcscpy with null-termination guarantee. Returns 0 on success.
///
/// Wine ref: dlls/msvcrt/wcs.c — wcsncpy_s mirrors strncpy_s for wide chars.
///
/// # Safety
/// `dst` must be writable for `size_dst` wide chars. `src` must be readable.
pub unsafe extern "win64" fn ucrt_wcsncpy_s(
    dst: *mut u16,
    size_dst: usize,
    src: *const u16,
    count: usize,
) -> i32 {
    if dst.is_null() || size_dst == 0 {
        return 22; // EINVAL
    }
    if src.is_null() {
        *dst = 0;
        return 22; // EINVAL
    }
    let copy_max = count.min(size_dst - 1);
    let mut i = 0usize;
    while i < copy_max {
        let c = *src.add(i);
        *dst.add(i) = c;
        if c == 0 {
            return 0;
        }
        i += 1;
    }
    *dst.add(i) = 0;
    0
}

/// wcscpy_s — bounded wcscpy with null-termination guarantee. Returns 0 on success.
///
/// Wine ref: dlls/msvcrt/wcs.c — wcscpy_s is wcsncpy_s with count = RSIZE_MAX.
///
/// # Safety
/// `dst` must be writable for `size_dst` wide chars. `src` must be a valid wide string.
pub unsafe extern "win64" fn ucrt_wcscpy_s(dst: *mut u16, size_dst: usize, src: *const u16) -> i32 {
    ucrt_wcsncpy_s(dst, size_dst, src, usize::MAX)
}

// ── Additional char classification ───────────────────────────────────────────

/// isxdigit — test if a character is a hex digit (0-9, a-f, A-F).
///
/// Wine ref: dlls/msvcrt/ctype.c — isxdigit delegates to the C locale table.
pub extern "win64" fn ucrt_isxdigit(c: i32) -> i32 {
    let c = c as u8;
    if c.is_ascii_hexdigit() {
        1
    } else {
        0
    }
}

// ── Time functions ────────────────────────────────────────────────────────────

/// _time64 — return the current time as a 64-bit Unix timestamp (seconds since epoch).
///
/// Wine ref: dlls/msvcrt/time.c — _time64 calls NtQuerySystemTime and converts
/// to Unix time. Weave delegates to libc::time().
///
/// # Safety
/// `timer` may be null or a pointer to a writable i64.
pub unsafe extern "win64" fn ucrt_time64(timer: *mut i64) -> i64 {
    let t = unsafe { libc::time(std::ptr::null_mut()) } as i64;
    if !timer.is_null() {
        *timer = t;
    }
    t
}

/// _difftime64 — compute the difference between two _time64_t values.
///
/// Wine ref: dlls/msvcrt/time.c — _difftime64(t1, t0) returns (double)(t1 - t0).
pub extern "win64" fn ucrt_difftime64(t1: i64, t0: i64) -> f64 {
    (t1 - t0) as f64
}

// Layout of MSVCRT tm struct on Windows x64 (same as Linux but 32-bit year):
// int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst
// = 9 × i32 = 36 bytes

unsafe fn unix_tm_to_win(tm: *const libc::tm, out: *mut u8) {
    if out.is_null() || tm.is_null() {
        return;
    }
    let fields: [i32; 9] = [
        (*tm).tm_sec,
        (*tm).tm_min,
        (*tm).tm_hour,
        (*tm).tm_mday,
        (*tm).tm_mon,
        (*tm).tm_year,
        (*tm).tm_wday,
        (*tm).tm_yday,
        (*tm).tm_isdst,
    ];
    std::ptr::copy_nonoverlapping(fields.as_ptr() as *const u8, out, 36);
}

/// _localtime64_s — convert _time64_t to local time, thread-safe.
///
/// Wine ref: dlls/msvcrt/time.c — _localtime64_s calls localtime_r and fills
/// the tm struct. Returns 0 on success, EINVAL on null pointers.
///
/// # Safety
/// `result` must be a writable buffer of at least 36 bytes (Win MSVCRT tm struct).
/// `time` must be a valid pointer to a _time64_t value.
pub unsafe extern "win64" fn ucrt_localtime64_s(result: *mut u8, time: *const i64) -> i32 {
    if result.is_null() || time.is_null() {
        return 22; // EINVAL
    }
    let t = *time as libc::time_t;
    let mut linux_tm: libc::tm = std::mem::zeroed();
    if libc::localtime_r(&t, &mut linux_tm).is_null() {
        return 22; // EINVAL
    }
    unix_tm_to_win(&linux_tm, result);
    0
}

/// _gmtime64_s — convert _time64_t to UTC time, thread-safe.
///
/// Wine ref: dlls/msvcrt/time.c — _gmtime64_s calls gmtime_r and fills tm struct.
/// Returns 0 on success.
///
/// # Safety
/// `result` must be a writable buffer of at least 36 bytes.
/// `time` must be a valid pointer to a _time64_t value.
pub unsafe extern "win64" fn ucrt_gmtime64_s(result: *mut u8, time: *const i64) -> i32 {
    if result.is_null() || time.is_null() {
        return 22; // EINVAL
    }
    let t = *time as libc::time_t;
    let mut linux_tm: libc::tm = std::mem::zeroed();
    if libc::gmtime_r(&t, &mut linux_tm).is_null() {
        return 22; // EINVAL
    }
    unix_tm_to_win(&linux_tm, result);
    0
}

// Thread-local scratch buffers for the non-`_s` variants (_localtime64 /
// _gmtime64 / _ctime64). Wine's msvcrt keeps these in `thread_data_t`
// (dlls/msvcrt/time.c:_localtime64 → `msvcrt_get_thread_data()->time_buffer`).
// The returned pointer is valid until the next call on the same thread from
// the same family — matching MSVCRT's documented contract.
thread_local! {
    static LOCALTIME_TM_BUF: std::cell::UnsafeCell<[u8; 36]>
        = const { std::cell::UnsafeCell::new([0u8; 36]) };
    static GMTIME_TM_BUF: std::cell::UnsafeCell<[u8; 36]>
        = const { std::cell::UnsafeCell::new([0u8; 36]) };
}

/// _localtime64 — convert _time64_t to local time, returning a thread-local
/// struct tm*.
///
/// Wine ref: dlls/msvcrt/time.c:413-424 — `_localtime64` fetches a per-thread
/// `time_buffer`, delegates to `_localtime64_s` to fill it, and returns the
/// buffer pointer (or NULL on invalid input). Callers (MinGW's `time.h`
/// inline `localtime`, `ctime`, wget's startup code) dereference the returned
/// `struct tm*` directly — so the value must be a real, populated buffer.
///
/// Before this implementation landed, `_localtime64` was an unresolved
/// import: the IAT patcher wrote a null/trampoline pointer that wget's
/// caller then dereferenced, aborting inside libc's fortified read. See
/// `docs/findings/task-01b-wget-trace-3c-B-gdb.md`.
///
/// # Safety
/// `time` may be null (returns NULL) or a pointer to a _time64_t.
pub unsafe extern "win64" fn ucrt_localtime64(time: *const i64) -> *mut u8 {
    if time.is_null() {
        return std::ptr::null_mut();
    }
    LOCALTIME_TM_BUF.with(|cell| {
        let buf = cell.get() as *mut u8;
        if ucrt_localtime64_s(buf, time) != 0 {
            std::ptr::null_mut()
        } else {
            buf
        }
    })
}

/// _gmtime64 — convert _time64_t to UTC, returning a thread-local struct tm*.
///
/// Wine ref: dlls/msvcrt/time.c:507-519 — same per-thread buffer pattern as
/// `_localtime64`, delegating to `_gmtime64_s`.
///
/// # Safety
/// `time` may be null (returns NULL) or a pointer to a _time64_t.
pub unsafe extern "win64" fn ucrt_gmtime64(time: *const i64) -> *mut u8 {
    if time.is_null() {
        return std::ptr::null_mut();
    }
    GMTIME_TM_BUF.with(|cell| {
        let buf = cell.get() as *mut u8;
        if ucrt_gmtime64_s(buf, time) != 0 {
            std::ptr::null_mut()
        } else {
            buf
        }
    })
}

/// _mkgmtime64 — inverse of `_gmtime64`: interpret a `struct tm` as UTC and
/// return the corresponding _time64_t.
///
/// Wine ref: dlls/msvcrt/time.c:346-353 — `_mkgmtime64` delegates to
/// `mktime_helper(tm, FALSE)`, which builds a SYSTEMTIME→FILETIME and
/// converts to Unix seconds. POSIX equivalent is `timegm(3)`; we use that
/// via libc. `tm_isdst` is ignored per the Wine comment.
///
/// Returns -1 on error.
///
/// # Safety
/// `tm` must point to a readable 36-byte MSVCRT `struct tm`.
pub unsafe extern "win64" fn ucrt_mkgmtime64(tm: *mut u8) -> i64 {
    if tm.is_null() {
        return -1;
    }
    let fields = tm as *const i32;
    let mut linux_tm: libc::tm = std::mem::zeroed();
    linux_tm.tm_sec = *fields;
    linux_tm.tm_min = *fields.add(1);
    linux_tm.tm_hour = *fields.add(2);
    linux_tm.tm_mday = *fields.add(3);
    linux_tm.tm_mon = *fields.add(4);
    linux_tm.tm_year = *fields.add(5);
    linux_tm.tm_wday = *fields.add(6);
    linux_tm.tm_yday = *fields.add(7);
    linux_tm.tm_isdst = -1; // ignored by timegm, matches Wine's "ignored" note
    let ret = libc::timegm(&mut linux_tm);
    if ret == -1 {
        return -1;
    }
    // Write normalized fields back so the caller observes the canonical form
    // (Wine's mktime_helper does this via GetSystemTimeAsFileTime roundtrip).
    let out = tm as *mut i32;
    *out = linux_tm.tm_sec;
    *out.add(1) = linux_tm.tm_min;
    *out.add(2) = linux_tm.tm_hour;
    *out.add(3) = linux_tm.tm_mday;
    *out.add(4) = linux_tm.tm_mon;
    *out.add(5) = linux_tm.tm_year;
    *out.add(6) = linux_tm.tm_wday;
    *out.add(7) = linux_tm.tm_yday;
    *out.add(8) = linux_tm.tm_isdst;
    ret as i64
}

/// `clock` — wall-clock ticks since the MSVCRT "process start" reference
/// point.  Units are `CLOCKS_PER_SEC = 1000` per Windows MSVCRT headers.
///
/// Wine ref: `dlls/msvcrt/time.c:698-704` —
/// ```c
/// clock_t CDECL clock(void)
/// {
///     LARGE_INTEGER systime;
///     NtQuerySystemTime(&systime);
///     return (systime.QuadPart - init_time) / (TICKSPERSEC / CLOCKS_PER_SEC);
/// }
/// ```
/// `init_time` is captured once by `msvcrt_init_clock` at DLL init
/// (`dlls/msvcrt/time.c:49-55`).  `TICKSPERSEC = 10_000_000` (100-ns NT
/// ticks), `CLOCKS_PER_SEC = 1000` on Windows, so the divisor collapses
/// to 10_000 — i.e. the result is milliseconds since process start.
///
/// Weave uses a lazily-initialised `std::time::Instant` anchor as its
/// process-start reference, which is the closest `std` equivalent.
///
/// wget's retry-backoff loop (callsites 0x14005bb4b, 0x14005b496) calls
/// `clock()` twice per iteration to compute elapsed time.  Returning 0
/// (unresolved stub) made the loop never terminate.
pub extern "win64" fn ucrt_clock() -> i32 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    // Windows clock_t is a 32-bit signed long on x64.  Saturate to i32::MAX
    // after ~24 days — matches Windows' documented wrap behaviour adequately
    // for Weave's short-running-app use case.
    let ms = start.elapsed().as_millis();
    if ms > i32::MAX as u128 {
        i32::MAX
    } else {
        ms as i32
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// _byteswap_uint64 — swap byte order of a 64-bit unsigned integer.
///
/// Wine ref: dlls/msvcrt/math.c — maps directly to __builtin_bswap64.
pub extern "win64" fn ucrt_byteswap_uint64(val: u64) -> u64 {
    val.swap_bytes()
}

/// bsearch — binary search in a sorted array.
///
/// Wine ref: dlls/msvcrt/misc.c — bsearch delegates to POSIX bsearch.
///
/// # Safety
/// `key`, `base`, and the comparator must satisfy the bsearch preconditions.
pub unsafe extern "win64" fn ucrt_bsearch(
    key: *const u8,
    base: *const u8,
    num_elements: usize,
    element_size: usize,
    compare: unsafe extern "win64" fn(*const u8, *const u8) -> i32,
) -> *mut u8 {
    // Manual binary search to avoid calling libc bsearch with a win64-ABI comparator.
    if num_elements == 0 || element_size == 0 {
        return std::ptr::null_mut();
    }
    let mut lo = 0usize;
    let mut hi = num_elements;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let elem = base.add(mid * element_size);
        let cmp = compare(key, elem);
        if cmp == 0 {
            return elem as *mut u8;
        } else if cmp < 0 {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    std::ptr::null_mut()
}

/// qsort — sort an array in place using a comparator.
///
/// Wine ref: dlls/msvcrt/misc.c — qsort delegates to POSIX qsort.
/// We implement a simple insertion sort to avoid ABI issues with libc qsort.
///
/// # Safety
/// `base` must be writable for `num × size` bytes. `compare` must be a valid win64 fn.
pub unsafe extern "win64" fn ucrt_qsort(
    base: *mut u8,
    num_elements: usize,
    element_size: usize,
    compare: unsafe extern "win64" fn(*const u8, *const u8) -> i32,
) {
    if num_elements <= 1 || element_size == 0 {
        return;
    }
    // Insertion sort — O(n²) but correct across ABI boundaries.
    let mut tmp = vec![0u8; element_size];
    for i in 1..num_elements {
        std::ptr::copy_nonoverlapping(base.add(i * element_size), tmp.as_mut_ptr(), element_size);
        let mut j = i;
        while j > 0 && compare(base.add((j - 1) * element_size), tmp.as_ptr()) > 0 {
            let src = base.add((j - 1) * element_size);
            let dst = base.add(j * element_size);
            std::ptr::copy_nonoverlapping(src, dst, element_size);
            j -= 1;
        }
        std::ptr::copy_nonoverlapping(tmp.as_ptr(), base.add(j * element_size), element_size);
    }
}

/// strtoull — convert a string to an unsigned long long.
///
/// Wine ref: dlls/msvcrt/string.c — strtoull calls strtoul/strtoull from libc.
///
/// # Safety
/// `nptr` must be a null-terminated C string. `endptr` may be null.
pub unsafe extern "win64" fn ucrt_strtoull(
    nptr: *const u8,
    endptr: *mut *mut u8,
    base: i32,
) -> u64 {
    libc::strtoull(
        nptr as *const libc::c_char,
        endptr as *mut *mut libc::c_char,
        base,
    )
}

/// mbstowcs_s — convert multibyte string to wide string, safe version.
///
/// Wine ref: dlls/msvcrt/mbcs.c — mbstowcs_s calls mbstowcs_r and fills *retval
/// with the number of wide chars converted including the null terminator.
/// Returns 0 on success.
///
/// # Safety
/// `wcstr` must be writable for `size_in_words` wide chars. `mbstr` must be readable.
pub unsafe extern "win64" fn ucrt_mbstowcs_s(
    retval: *mut usize,
    wcstr: *mut u16,
    size_in_words: usize,
    mbstr: *const u8,
    count: usize,
) -> i32 {
    if mbstr.is_null() {
        if !retval.is_null() {
            *retval = 0;
        }
        return 22; // EINVAL
    }
    let mb_len = libc::strlen(mbstr as *const libc::c_char);
    let copy_chars = mb_len.min(count).min(if size_in_words > 0 {
        size_in_words - 1
    } else {
        0
    });
    if wcstr.is_null() {
        if !retval.is_null() {
            *retval = mb_len + 1;
        }
        return 0;
    }
    // ASCII path (single-byte locale) — extend each byte to u16.
    for i in 0..copy_chars {
        *wcstr.add(i) = *mbstr.add(i) as u16;
    }
    if size_in_words > copy_chars {
        *wcstr.add(copy_chars) = 0;
    }
    if !retval.is_null() {
        *retval = copy_chars + 1;
    }
    0
}

/// wcstombs_s — convert wide string to multibyte string, safe version.
///
/// Wine ref: dlls/msvcrt/mbcs.c — wcstombs_s calls wcstombs_r.
/// Returns 0 on success.
///
/// # Safety
/// `mbstr` must be writable for `size_in_bytes` bytes. `wcstr` must be readable.
pub unsafe extern "win64" fn ucrt_wcstombs_s(
    retval: *mut usize,
    mbstr: *mut u8,
    size_in_bytes: usize,
    wcstr: *const u16,
    count: usize,
) -> i32 {
    if wcstr.is_null() {
        if !retval.is_null() {
            *retval = 0;
        }
        return 22; // EINVAL
    }
    // Measure source length.
    let mut wlen = 0usize;
    while *wcstr.add(wlen) != 0 {
        wlen += 1;
    }
    let copy_bytes = wlen.min(count).min(if size_in_bytes > 0 {
        size_in_bytes - 1
    } else {
        0
    });
    if mbstr.is_null() {
        if !retval.is_null() {
            *retval = wlen + 1;
        }
        return 0;
    }
    // ASCII path (single-byte locale) — truncate each u16 to u8.
    for i in 0..copy_bytes {
        *mbstr.add(i) = (*wcstr.add(i) & 0xFF) as u8;
    }
    if size_in_bytes > copy_bytes {
        *mbstr.add(copy_bytes) = 0;
    }
    if !retval.is_null() {
        *retval = copy_bytes + 1;
    }
    0
}

// ── Console I/O ───────────────────────────────────────────────────────────────

/// _getch — read a single character from the console without echo. Returns 0.
///
/// Wine ref: dlls/msvcrt/console.c — _getch calls NtDeviceIoControlFile on
/// the console handle. Stub: return 0 (as if no key pressed / EOF).
pub extern "win64" fn ucrt_getch() -> i32 {
    0
}

// ── Additional stdio ──────────────────────────────────────────────────────────

/// fgets — read a line from a FILE stream into a buffer.
///
/// Wine ref: dlls/msvcrt/file.c — fgets reads until newline, EOF, or buf_size-1.
/// Returns buf on success, NULL on EOF or error.
///
/// # Safety
/// `buf` must be a writable buffer of `buf_size` bytes. `stream` must be a valid FILE*.
pub unsafe extern "win64" fn ucrt_fgets(
    buf: *mut u8,
    buf_size: i32,
    stream: *mut c_void,
) -> *mut u8 {
    if buf.is_null() || buf_size <= 0 || stream.is_null() {
        return std::ptr::null_mut();
    }
    let ret = libc::fgets(
        buf as *mut libc::c_char,
        buf_size,
        stream as *mut libc::FILE,
    );
    if ret.is_null() {
        std::ptr::null_mut()
    } else {
        buf
    }
}

/// freopen_s — reopen a file stream with a new path and mode, safe version.
///
/// Wine ref: dlls/msvcrt/file.c — freopen_s validates args, calls freopen.
/// Returns 0 on success, EINVAL on null pointers.
///
/// # Safety
/// `pfile` must be writable. `path` and `mode` must be null-terminated C strings.
pub unsafe extern "win64" fn ucrt_freopen_s(
    pfile: *mut *mut c_void,
    path: *const u8,
    mode: *const u8,
    stream: *mut c_void,
) -> i32 {
    if pfile.is_null() || path.is_null() || mode.is_null() {
        return 22; // EINVAL
    }
    let f = libc::freopen(
        path as *const libc::c_char,
        mode as *const libc::c_char,
        stream as *mut libc::FILE,
    );
    *pfile = f as *mut c_void;
    if f.is_null() {
        *libc::__errno_location()
    } else {
        0
    }
}

/// rewind — reset a FILE stream to its beginning. No return value.
///
/// Wine ref: dlls/msvcrt/file.c — rewind calls fseek(stream, 0, SEEK_SET) and clears error.
///
/// # Safety
/// `stream` must be a valid FILE*.
pub unsafe extern "win64" fn ucrt_rewind(stream: *mut c_void) {
    if !stream.is_null() {
        libc::rewind(stream as *mut libc::FILE);
    }
}

/// ungetc — push a character back onto a FILE stream.
///
/// Wine ref: dlls/msvcrt/file.c — ungetc calls POSIX ungetc.
///
/// # Safety
/// `stream` must be a valid FILE*.
pub unsafe extern "win64" fn ucrt_ungetc(c: i32, stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1; // EOF
    }
    libc::ungetc(c, stream as *mut libc::FILE)
}

/// getc — read a character from a FILE stream (macro alias for fgetc).
///
/// Wine ref: dlls/msvcrt/file.c — getc expands to fgetc in MSVCRT.
///
/// # Safety
/// `stream` must be a valid FILE*.
pub unsafe extern "win64" fn ucrt_getc(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1; // EOF
    }
    libc::fgetc(stream as *mut libc::FILE)
}

// ── Low-level file I/O ────────────────────────────────────────────────────────

/// _fileno — return the file descriptor associated with a FILE*.
///
/// Wine ref: dlls/msvcrt/file.c — _fileno(stream) calls fileno(stream) on POSIX.
///
/// # Safety
/// `stream` must be a valid FILE* or null.
pub unsafe extern "win64" fn ucrt_fileno(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    libc::fileno(stream as *mut libc::FILE)
}

/// _read — low-level fd read. Returns bytes read or -1 on error.
///
/// Wine ref: dlls/msvcrt/file.c — _read translates fd to handle and calls ReadFile.
/// Weave: delegates to POSIX read(2).
///
/// # Safety
/// `buf` must be a writable buffer of `count` bytes.
pub unsafe extern "win64" fn ucrt_read(fd: i32, buf: *mut c_void, count: u32) -> i32 {
    let ret = libc::read(fd, buf, count as usize);
    if weave_core::ws2_trace::enabled() {
        let e = if ret < 0 {
            *libc::__errno_location()
        } else {
            0
        };
        eprintln!("weave/ucrt_read: fd={fd} count={count} ret={ret} errno={e}");
    }
    ret as i32
}

/// _write — low-level fd write. Returns bytes written or -1 on error.
///
/// Wine ref: dlls/msvcrt/file.c — _write translates fd to handle and calls WriteFile.
/// Weave: delegates to POSIX write(2).
///
/// # Safety
/// `buf` must be a readable buffer of `count` bytes.
pub unsafe extern "win64" fn ucrt_write(fd: i32, buf: *const c_void, count: u32) -> i32 {
    if weave_core::ws2_trace::enabled() {
        eprintln!("weave/ucrt_write: fd={fd} count={count}");
    }
    let ret = libc::write(fd, buf, count as usize);
    ret as i32
}

/// _lseeki64 — seek on a file descriptor (64-bit offset). Returns new position.
///
/// Wine ref: dlls/msvcrt/file.c — _lseeki64 wraps lseek64.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
pub unsafe extern "win64" fn ucrt_lseeki64(fd: i32, offset: i64, origin: i32) -> i64 {
    let ret = libc::lseek(fd, offset as libc::off_t, origin);
    ret as i64
}

/// _setmode — set the translation mode for a file descriptor. Returns old mode.
///
/// Wine ref: dlls/msvcrt/file.c — _setmode sets binary (O_BINARY=0x8000) or
/// text (O_TEXT=0x4000) mode on Windows. On Linux, all fds are binary; return 0.
///
/// # Safety
/// No pointer arguments.
pub unsafe extern "win64" fn ucrt_setmode(_fd: i32, _mode: i32) -> i32 {
    0 // previous mode = binary (always on Linux)
}

/// _chsize_s — set the length of a file, 64-bit safe version. Returns 0 on success.
///
/// Wine ref: dlls/msvcrt/file.c — _chsize_s calls ftruncate on Linux.
///
/// # Safety
/// `fd` must be a valid open file descriptor.
pub unsafe extern "win64" fn ucrt_chsize_s(fd: i32, size: i64) -> i32 {
    let ret = libc::ftruncate(fd, size as libc::off_t);
    if ret < 0 {
        *libc::__errno_location()
    } else {
        0
    }
}

/// _fsopen — open a shared file (returns FILE*). Simplified: delegates to fopen.
///
/// Wine ref: dlls/msvcrt/file.c — _fsopen(path, mode, shflag) is like fopen
/// with optional sharing flags; sharing is ignored on Linux.
///
/// # Safety
/// `path` and `mode` must be null-terminated C strings.
pub unsafe extern "win64" fn ucrt_fsopen(
    path: *const u8,
    mode: *const u8,
    _sh_flag: i32,
) -> *mut c_void {
    if path.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }
    libc::fopen(path as *const libc::c_char, mode as *const libc::c_char) as *mut c_void
}

// ── Filesystem functions ──────────────────────────────────────────────────────

// WIN32_FIND_DATA / _finddata64i32_t layout (Windows x64, MSVCRT):
// DWORD dwFileAttributes (4)
// FILETIME ftCreationTime (8), ftLastAccessTime (8), ftLastWriteTime (8)
// DWORD nFileSizeHigh (4), nFileSizeLow (4)
// DWORD dwReserved0, dwReserved1 (8)
// WCHAR cFileName[260*2=520], cAlternateFileName[14*2=28]
// Total ≥ 572 bytes. We use an opaque struct; callers only get back errors.

/// _findfirst64i32 — start a file search. Returns a search handle or -1 on error.
///
/// Wine ref: dlls/msvcrt/dir.c — _findfirst64i32 calls FindFirstFileW and
/// converts WIN32_FIND_DATAW to _finddata64i32_t. Stub: returns -1 (not found).
///
/// # Safety
/// `file_spec` must be a null-terminated C string. `file_info` must be writable.
pub unsafe extern "win64" fn ucrt_findfirst64i32(
    _file_spec: *const u8,
    _file_info: *mut u8,
) -> i64 {
    unsafe { *libc::__errno_location() = libc::ENOENT };
    -1i64 // ENOENT — no match found
}

/// _findnext64i32 — find the next match. Returns 0 on success.
///
/// Wine ref: dlls/msvcrt/dir.c — _findnext64i32 calls FindNextFileW.
/// Stub: always returns -1 (no more files).
///
/// # Safety
/// `handle` is ignored. `file_info` must be writable.
pub unsafe extern "win64" fn ucrt_findnext64i32(_handle: i64, _file_info: *mut u8) -> i32 {
    unsafe { *libc::__errno_location() = libc::ENOENT };
    -1
}

/// _findclose — close a search handle. Returns 0 on success.
///
/// Wine ref: dlls/msvcrt/dir.c — _findclose calls FindClose(handle).
///
/// # Safety
/// `handle` is accepted but ignored for stubs.
pub unsafe extern "win64" fn ucrt_findclose(_handle: i64) -> i32 {
    0 // success (no-op; stub handles were never real)
}

/// _fullpath — return the absolute path of a relative path. Returns NULL on failure.
///
/// Wine ref: dlls/msvcrt/dir.c — _fullpath calls GetFullPathNameA.
/// Stub: returns NULL (not supported).
///
/// # Safety
/// Pointer arguments are not dereferenced.
pub unsafe extern "win64" fn ucrt_fullpath(
    _abs_path: *mut u8,
    _rel_path: *const u8,
    _max_length: usize,
) -> *mut u8 {
    std::ptr::null_mut()
}

/// _mkdir — create a directory. Returns 0 on success, -1 on failure.
///
/// Wine ref: dlls/msvcrt/dir.c — _mkdir calls CreateDirectoryA.
/// Weave: delegates to libc::mkdir with mode 0o755.
///
/// # Safety
/// `path` must be a null-terminated C string.
pub unsafe extern "win64" fn ucrt_mkdir(path: *const u8) -> i32 {
    if path.is_null() {
        return -1;
    }
    let ret = libc::mkdir(path as *const libc::c_char, 0o755);
    if ret < 0 {
        -1
    } else {
        0
    }
}

/// _stat64 — get file status (64-bit version). Returns 0 on success.
///
/// Wine ref: dlls/msvcrt/dir.c — _stat64 calls GetFileAttributesW and
/// fills a _stat64 struct. Stub: returns -1 (ENOENT).
///
/// # Safety
/// `path` must be a null-terminated C string. `buf` must be writable.
pub unsafe extern "win64" fn ucrt_stat64(_path: *const u8, _buf: *mut u8) -> i32 {
    unsafe { *libc::__errno_location() = libc::ENOENT };
    -1
}

/// _unlink — delete a file. Returns 0 on success.
///
/// Wine ref: dlls/msvcrt/dir.c — _unlink calls DeleteFileA.
/// Weave: delegates to libc::unlink.
///
/// # Safety
/// `path` must be a null-terminated C string.
pub unsafe extern "win64" fn ucrt_unlink(path: *const u8) -> i32 {
    if path.is_null() {
        return -1;
    }
    let ret = libc::unlink(path as *const libc::c_char);
    if ret < 0 {
        -1
    } else {
        0
    }
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
        "iswctype" => stub!(ucrt_iswctype as extern "win64" fn(_, _) -> _),
        "wctype" => stub!(ucrt_wctype_fn as unsafe extern "win64" fn(_) -> _),
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
        "_get_narrow_winmain_command_line" => {
            stub!(ucrt_get_narrow_winmain_command_line as unsafe extern "win64" fn() -> _)
        }
        "_invalid_parameter_noinfo" => {
            stub!(ucrt_invalid_parameter_noinfo as unsafe extern "win64" fn())
        }
        "_invalid_parameter_noinfo_noreturn" => {
            stub!(ucrt_invalid_parameter_noinfo_noreturn as unsafe extern "win64" fn())
        }
        "_register_thread_local_exe_atexit_callback" => {
            stub!(
                ucrt_register_thread_local_exe_atexit_callback as unsafe extern "win64" fn(_) -> _
            )
        }
        "_seh_filter_exe" => {
            stub!(ucrt_seh_filter_exe as unsafe extern "win64" fn(_, _) -> _)
        }
        "_callnewh" => {
            stub!(ucrt_callnewh as unsafe extern "win64" fn(_) -> _)
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
        "fprintf" => stub!(ucrt_fprintf_va as unsafe extern "win64" fn(_, _, _) -> _),
        "vfprintf" => stub!(ucrt_vfprintf as extern "win64" fn(_, _, _) -> _),
        "fwrite" => stub!(ucrt_fwrite as unsafe extern "win64" fn(_, _, _, _) -> _),
        "__stdio_common_vfprintf" | "__stdio_common_vfwprintf" => {
            stub!(ucrt_stdio_common_vfprintf as unsafe extern "win64" fn(_, _, _, _, _) -> _)
        }
        "__stdio_common_vsprintf" | "__stdio_common_vswprintf" => {
            stub!(ucrt_stdio_common_vsprintf as unsafe extern "win64" fn(_, _, _, _, _, _) -> _)
        }
        "_iob" => Some(iob_data_addr()),
        "fputc" => Some(ms_fputc as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "fputs" => Some(ms_fputs as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "fgetc" => Some(ms_fgetc as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "fflush" => Some(ms_fflush as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "setvbuf" => stub!(ucrt_setvbuf as extern "win64" fn(_, _, _, _) -> _),
        "_errno" => stub!(ucrt_errno as extern "win64" fn() -> _),
        "strerror" => stub!(ucrt_strerror as extern "win64" fn(_) -> _),
        "perror" => stub!(ucrt_perror as unsafe extern "win64" fn(_)),
        "raise" => stub!(ucrt_raise as extern "win64" fn(_) -> _),
        "_get_osfhandle" => stub!(ucrt_get_osfhandle as extern "win64" fn(_) -> _),
        "_open_osfhandle" => stub!(ucrt_open_osfhandle as extern "win64" fn(_, _) -> _),
        "_fseeki64" | "fseek" => {
            stub!(ucrt_fseeki64 as unsafe extern "win64" fn(_, _, _) -> _)
        }
        "_ftelli64" | "ftell" => stub!(ucrt_ftelli64 as unsafe extern "win64" fn(_) -> _),
        "_fdopen" => stub!(ucrt_fdopen as extern "win64" fn(_, _) -> _),
        "_lock_file" => stub!(ucrt_lock_file as extern "win64" fn(_)),
        "_unlock_file" => stub!(ucrt_unlock_file as extern "win64" fn(_)),
        "_lock" => stub!(ucrt_lock as extern "win64" fn(_)),
        "_unlock" => stub!(ucrt_unlock as extern "win64" fn(_)),
        "remove" => stub!(ucrt_remove as extern "win64" fn(_) -> _),
        "_fstat64" => stub!(ucrt_fstat64 as extern "win64" fn(_, _) -> _),
        "fopen" => stub!(ucrt_fopen as unsafe extern "win64" fn(_, _) -> _),
        "_wfopen" => stub!(ucrt_wfopen as unsafe extern "win64" fn(_, _) -> _),
        "fread" => stub!(ucrt_fread as unsafe extern "win64" fn(_, _, _, _) -> _),
        "fclose" => stub!(ucrt_fclose as unsafe extern "win64" fn(_) -> _),
        "feof" => stub!(ucrt_feof as unsafe extern "win64" fn(_) -> _),
        "ferror" => stub!(ucrt_ferror as unsafe extern "win64" fn(_) -> _),
        "snprintf" | "_snprintf" => {
            stub!(ucrt_snprintf as unsafe extern "win64" fn(_, _, _, _) -> _)
        }
        "sprintf" | "_sprintf" => stub!(ucrt_sprintf as unsafe extern "win64" fn(_, _, _) -> _),
        "printf" | "_printf" => stub!(ucrt_printf as unsafe extern "win64" fn(_, _) -> _),
        "fprintf_va" => stub!(ucrt_fprintf_va as unsafe extern "win64" fn(_, _, _) -> _),
        "puts" => stub!(ucrt_puts as unsafe extern "win64" fn(_) -> _),
        "putchar" | "_putchar" => stub!(ucrt_putchar as extern "win64" fn(_) -> _),
        "getenv" => stub!(ucrt_getenv as unsafe extern "win64" fn(_) -> _),
        "_wgetenv" => stub!(ucrt_wgetenv as unsafe extern "win64" fn(_) -> _),
        // locale / mb
        "___mb_cur_max_func" => stub!(ucrt_mb_cur_max_func as extern "win64" fn() -> _),
        "___lc_codepage_func" => stub!(ucrt_lc_codepage_func as extern "win64" fn() -> _),
        "localeconv" => stub!(ucrt_localeconv as extern "win64" fn() -> _),
        "setlocale" => stub!(ucrt_setlocale as extern "win64" fn(_, _) -> _),
        "btowc" => stub!(ucrt_btowc as unsafe extern "win64" fn(_) -> _),
        "wctob" => stub!(ucrt_wctob as unsafe extern "win64" fn(_) -> _),
        "mbrtowc" => stub!(ucrt_mbrtowc as unsafe extern "win64" fn(_, _, _, _) -> _),
        "mbsrtowcs" => stub!(ucrt_mbsrtowcs as unsafe extern "win64" fn(_, _, _, _) -> _),
        "wcrtomb" => stub!(ucrt_wcrtomb as unsafe extern "win64" fn(_, _, _) -> _),
        // math — double precision
        "sin" => stub!(ucrt_sin as extern "win64" fn(_) -> _),
        "cos" => stub!(ucrt_cos as extern "win64" fn(_) -> _),
        "tan" => stub!(ucrt_tan as extern "win64" fn(_) -> _),
        "sqrt" => stub!(ucrt_sqrt as extern "win64" fn(_) -> _),
        "floor" => stub!(ucrt_floor as extern "win64" fn(_) -> _),
        "ceil" => stub!(ucrt_ceil as extern "win64" fn(_) -> _),
        "log" => stub!(ucrt_log as extern "win64" fn(_) -> _),
        "log2" => stub!(ucrt_log2 as extern "win64" fn(_) -> _),
        "log10" => stub!(ucrt_log10 as extern "win64" fn(_) -> _),
        "exp" => stub!(ucrt_exp as extern "win64" fn(_) -> _),
        "pow" => stub!(ucrt_pow as extern "win64" fn(_, _) -> _),
        "fabs" => stub!(ucrt_fabs as extern "win64" fn(_) -> _),
        "fmod" => stub!(ucrt_fmod as extern "win64" fn(_, _) -> _),
        "atan" => stub!(ucrt_atan as extern "win64" fn(_) -> _),
        "atan2" => stub!(ucrt_atan2 as extern "win64" fn(_, _) -> _),
        "asin" => stub!(ucrt_asin as extern "win64" fn(_) -> _),
        "acos" => stub!(ucrt_acos as extern "win64" fn(_) -> _),
        // math — single precision
        "sinf" => stub!(ucrt_sinf as extern "win64" fn(_) -> _),
        "cosf" => stub!(ucrt_cosf as extern "win64" fn(_) -> _),
        "tanf" => stub!(ucrt_tanf as extern "win64" fn(_) -> _),
        "sqrtf" => stub!(ucrt_sqrtf as extern "win64" fn(_) -> _),
        "floorf" => stub!(ucrt_floorf as extern "win64" fn(_) -> _),
        "ceilf" => stub!(ucrt_ceilf as extern "win64" fn(_) -> _),
        "fabsf" => stub!(ucrt_fabsf as extern "win64" fn(_) -> _),
        "fmodf" => stub!(ucrt_fmodf as extern "win64" fn(_, _) -> _),
        "atan2f" => stub!(ucrt_atan2f as extern "win64" fn(_, _) -> _),
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
        "strftime" => stub!(ucrt_strftime as unsafe extern "win64" fn(_, _, _, _) -> _),
        "wcsftime" => stub!(ucrt_wcsftime as extern "win64" fn(_, _, _, _) -> _),
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
        "_set_fmode" => stub!(ucrt_set_fmode as extern "win64" fn(_) -> _),
        "_commode" => Some(commode_data_addr()),
        "__mb_cur_max" => Some(mb_cur_max_data_addr()),
        "_stricmp" | "_strcmpi" => stub!(ucrt_strcmp as unsafe extern "win64" fn(_, _) -> _),
        "_wcsdup" => stub!(ucrt_wcsdup as unsafe extern "win64" fn(_) -> _),
        "_flushall" => stub!(ucrt_flushall_stub as extern "win64" fn()),
        "_filbuf" | "_flsbuf" => stub!(ucrt_cexit as extern "win64" fn()),
        "_isatty" => stub!(ucrt_isatty as extern "win64" fn(_) -> _),
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
        // __stdio_common_v*scanf — UCRTBASE scanf backends.  Proper int-returning
        // stubs (return 0 = no conversions).  Previously aliased to ucrt_cexit
        // which violated the `int(...)` ABI; see ucrt_stdio_common_vsscanf
        // doc comment and Wine `dlls/msvcrt/scanf.c:667`.
        "__stdio_common_vsscanf" => {
            stub!(ucrt_stdio_common_vsscanf as extern "win64" fn(_, _, _, _, _, _) -> _)
        }
        "__stdio_common_vfscanf" => {
            stub!(ucrt_stdio_common_vfscanf as extern "win64" fn(_, _, _, _, _) -> _)
        }
        "__stdio_common_vswscanf" => {
            stub!(ucrt_stdio_common_vswscanf as extern "win64" fn(_, _, _, _, _, _) -> _)
        }
        "__stdio_common_vfwscanf" => {
            stub!(ucrt_stdio_common_vfwscanf as extern "win64" fn(_, _, _, _, _) -> _)
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
        // Task 01 additions — curl
        "strncpy_s" => stub!(ucrt_strncpy_s as unsafe extern "win64" fn(_, _, _, _) -> _),
        "_strnicmp" => stub!(ucrt_strnicmp as unsafe extern "win64" fn(_, _, _) -> _),
        "strcspn" => stub!(ucrt_strcspn as unsafe extern "win64" fn(_, _) -> _),
        "strpbrk" => stub!(ucrt_strpbrk as unsafe extern "win64" fn(_, _) -> _),
        "strspn" => stub!(ucrt_strspn as unsafe extern "win64" fn(_, _) -> _),
        "mbrlen" => stub!(ucrt_mbrlen as unsafe extern "win64" fn(_, _, _) -> _),
        "strerror_s" => stub!(ucrt_strerror_s as unsafe extern "win64" fn(_, _, _) -> _),
        "wcsncmp" => stub!(ucrt_wcsncmp as unsafe extern "win64" fn(_, _, _) -> _),
        "wcsncpy_s" => stub!(ucrt_wcsncpy_s as unsafe extern "win64" fn(_, _, _, _) -> _),
        "wcscpy_s" => stub!(ucrt_wcscpy_s as unsafe extern "win64" fn(_, _, _) -> _),
        "isxdigit" => stub!(ucrt_isxdigit as extern "win64" fn(_) -> _),
        "_time64" => stub!(ucrt_time64 as unsafe extern "win64" fn(_) -> _),
        "_difftime64" => stub!(ucrt_difftime64 as extern "win64" fn(_, _) -> _),
        "_localtime64_s" => stub!(ucrt_localtime64_s as unsafe extern "win64" fn(_, _) -> _),
        "_gmtime64_s" => stub!(ucrt_gmtime64_s as unsafe extern "win64" fn(_, _) -> _),
        "_localtime64" => stub!(ucrt_localtime64 as unsafe extern "win64" fn(_) -> _),
        "_gmtime64" => stub!(ucrt_gmtime64 as unsafe extern "win64" fn(_) -> _),
        "_mkgmtime64" => stub!(ucrt_mkgmtime64 as unsafe extern "win64" fn(_) -> _),
        "clock" => stub!(ucrt_clock as extern "win64" fn() -> _),
        "_byteswap_uint64" => stub!(ucrt_byteswap_uint64 as extern "win64" fn(_) -> _),
        "bsearch" => stub!(ucrt_bsearch as unsafe extern "win64" fn(_, _, _, _, _) -> _),
        "qsort" => stub!(ucrt_qsort as unsafe extern "win64" fn(_, _, _, _)),
        "strtoull" => stub!(ucrt_strtoull as unsafe extern "win64" fn(_, _, _) -> _),
        "mbstowcs_s" => stub!(ucrt_mbstowcs_s as unsafe extern "win64" fn(_, _, _, _, _) -> _),
        "wcstombs_s" => stub!(ucrt_wcstombs_s as unsafe extern "win64" fn(_, _, _, _, _) -> _),
        "_getch" => stub!(ucrt_getch as extern "win64" fn() -> _),
        "fgets" => stub!(ucrt_fgets as unsafe extern "win64" fn(_, _, _) -> _),
        "freopen_s" => stub!(ucrt_freopen_s as unsafe extern "win64" fn(_, _, _, _) -> _),
        "rewind" => stub!(ucrt_rewind as unsafe extern "win64" fn(_)),
        "ungetc" => stub!(ucrt_ungetc as unsafe extern "win64" fn(_, _) -> _),
        "getc" => stub!(ucrt_getc as unsafe extern "win64" fn(_) -> _),
        "_fileno" => stub!(ucrt_fileno as unsafe extern "win64" fn(_) -> _),
        "_read" => stub!(ucrt_read as unsafe extern "win64" fn(_, _, _) -> _),
        "_write" => stub!(ucrt_write as unsafe extern "win64" fn(_, _, _) -> _),
        "_lseeki64" => stub!(ucrt_lseeki64 as unsafe extern "win64" fn(_, _, _) -> _),
        "_setmode" => stub!(ucrt_setmode as unsafe extern "win64" fn(_, _) -> _),
        "_chsize_s" => stub!(ucrt_chsize_s as unsafe extern "win64" fn(_, _) -> _),
        "_fsopen" => stub!(ucrt_fsopen as unsafe extern "win64" fn(_, _, _) -> _),
        "_findfirst64i32" => stub!(ucrt_findfirst64i32 as unsafe extern "win64" fn(_, _) -> _),
        "_findnext64i32" => stub!(ucrt_findnext64i32 as unsafe extern "win64" fn(_, _) -> _),
        "_findclose" => stub!(ucrt_findclose as unsafe extern "win64" fn(_) -> _),
        "_fullpath" => stub!(ucrt_fullpath as unsafe extern "win64" fn(_, _, _) -> _),
        "_mkdir" => stub!(ucrt_mkdir as unsafe extern "win64" fn(_) -> _),
        "_stat64" => stub!(ucrt_stat64 as unsafe extern "win64" fn(_, _) -> _),
        "_unlink" => stub!(ucrt_unlink as unsafe extern "win64" fn(_) -> _),
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
        "terminate" | "?terminate@@YAXXZ" => {
            Some(ucrt_terminate as extern "win64" fn() -> ! as *const () as usize)
        }
        "??1type_info@@UEAA@XZ" => {
            Some(ucrt_type_info_dtor as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // VCRUNTIME140.dll gaps — TASK-4
        "__std_terminate" => {
            Some(ucrt_std_terminate as unsafe extern "win64" fn() -> ! as *const () as usize)
        }
        "__vcrt_InitializeCriticalSectionEx" => {
            Some(ucrt_vcrt_init_cs as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "__std_exception_copy" => {
            Some(ucrt_std_exception_copy as unsafe extern "win64" fn(_, _) as *const () as usize)
        }
        "__std_exception_destroy" => {
            Some(ucrt_std_exception_destroy as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "__intrinsic_setjmp" => {
            // Alias to the existing setjmpex implementation — same semantics, no "ex" suffix.
            Some(
                ucrt_intrinsic_setjmpex as unsafe extern "win64" fn(_, _) -> _ as *const ()
                    as usize,
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: decode the 9-int MSVCRT tm layout returned by _localtime64 /
    /// _gmtime64.
    unsafe fn read_tm(p: *const u8) -> [i32; 9] {
        let mut out = [0i32; 9];
        std::ptr::copy_nonoverlapping(p as *const i32, out.as_mut_ptr(), 9);
        out
    }

    #[test]
    fn gmtime64_epoch_fields() {
        // Unix epoch: 1970-01-01 00:00:00 UTC → tm_year=70 (years since 1900),
        // tm_mon=0 (Jan), tm_mday=1, rest zero.
        let t: i64 = 0;
        let p = unsafe { ucrt_gmtime64(&t as *const i64) };
        assert!(!p.is_null(), "_gmtime64(0) must not return NULL");
        let fields = unsafe { read_tm(p) };
        assert_eq!(fields[0], 0, "tm_sec");
        assert_eq!(fields[1], 0, "tm_min");
        assert_eq!(fields[2], 0, "tm_hour");
        assert_eq!(fields[3], 1, "tm_mday");
        assert_eq!(fields[4], 0, "tm_mon");
        assert_eq!(fields[5], 70, "tm_year (years since 1900)");
        assert_eq!(fields[7], 0, "tm_yday");
    }

    #[test]
    fn gmtime64_known_date() {
        // 2000-01-01 00:00:00 UTC = 946684800
        let t: i64 = 946684800;
        let p = unsafe { ucrt_gmtime64(&t as *const i64) };
        assert!(!p.is_null());
        let fields = unsafe { read_tm(p) };
        assert_eq!(fields[3], 1, "tm_mday");
        assert_eq!(fields[4], 0, "tm_mon");
        assert_eq!(fields[5], 100, "tm_year");
    }

    #[test]
    fn localtime64_returns_nonnull_for_valid_time() {
        // _localtime64 depends on the host timezone, so we only assert the
        // contract wget relies on: a non-null, dereferenceable pointer.
        let t: i64 = 1_700_000_000; // 2023-11-14 ~22:13 UTC
        let p = unsafe { ucrt_localtime64(&t as *const i64) };
        assert!(!p.is_null());
        let fields = unsafe { read_tm(p) };
        // Any valid tm has year >= 70 (1970+); mon in [0,11]; mday in [1,31].
        assert!(fields[4] >= 0 && fields[4] <= 11);
        assert!(fields[3] >= 1 && fields[3] <= 31);
        assert!(fields[5] >= 70);
    }

    #[test]
    fn localtime64_null_returns_null() {
        let p = unsafe { ucrt_localtime64(std::ptr::null()) };
        assert!(p.is_null());
    }

    #[test]
    fn localtime64_buffer_is_thread_local_and_stable() {
        let t: i64 = 1_700_000_000;
        let p1 = unsafe { ucrt_localtime64(&t as *const i64) };
        let p2 = unsafe { ucrt_localtime64(&t as *const i64) };
        // Same thread → same buffer address. This is the contract wget's
        // MinGW inline `localtime()` wrapper depends on.
        assert_eq!(p1, p2);
    }

    #[test]
    fn mkgmtime64_roundtrip() {
        // gmtime(t) then mkgmtime(tm) must yield t back.
        let t: i64 = 1_700_000_000;
        let p = unsafe { ucrt_gmtime64(&t as *const i64) };
        assert!(!p.is_null());
        // Copy out so we don't mutate the thread-local buffer underneath us.
        let mut tm_copy = [0u8; 36];
        unsafe { std::ptr::copy_nonoverlapping(p, tm_copy.as_mut_ptr(), 36) };
        let t2 = unsafe { ucrt_mkgmtime64(tm_copy.as_mut_ptr()) };
        assert_eq!(t2, t);
    }

    #[test]
    fn open_osfhandle_returns_handle_as_fd() {
        // A typical socket handle value from ws_socket (Linux fd, small int).
        assert_eq!(ucrt_open_osfhandle(7, 0x8002), 7);
        assert_eq!(ucrt_open_osfhandle(42, 0), 42);
        // Zero is a legal (if rare) fd.
        assert_eq!(ucrt_open_osfhandle(0, 0), 0);
    }

    #[test]
    fn open_osfhandle_negative_handle_returns_error() {
        // Negative handle is the Windows INVALID_HANDLE_VALUE sentinel (or
        // any error) — return -1 to signal failure per the Wine contract.
        assert_eq!(ucrt_open_osfhandle(-1, 0), -1);
        assert_eq!(ucrt_open_osfhandle(isize::MIN, 0), -1);
    }

    #[test]
    fn get_osfhandle_roundtrips_open_osfhandle() {
        // _open_osfhandle then _get_osfhandle must yield the original
        // handle value — this is the wget.exe path:
        //   fd = _open_osfhandle(WSASocketW_result, 0x8002)
        //   handle = _get_osfhandle(fd) → setsockopt(handle, ...)
        for h in [0isize, 1, 7, 42, 1000] {
            let fd = ucrt_open_osfhandle(h, 0x8002);
            assert_eq!(ucrt_get_osfhandle(fd) as isize, h);
        }
    }

    #[test]
    fn get_osfhandle_negative_fd_returns_error() {
        assert_eq!(ucrt_get_osfhandle(-1), -1);
    }

    #[test]
    fn open_osfhandle_resolves_via_resolver() {
        // Bug class: _open_osfhandle must be reachable through weave-ucrt's
        // resolve() so wget's MinGW socket wrapper gets the real stub, not a
        // no-op returning 0. Without this, wget spins in a retry loop
        // (Task 01b dispatch 3c-D).
        assert!(resolve("msvcrt.dll", "_open_osfhandle").is_some());
        assert!(resolve("ucrtbase.dll", "_open_osfhandle").is_some());
    }

    // ── Task 01b: __acrt_iob_func ────────────────────────────────────────────

    #[test]
    fn acrt_iob_func_returns_distinct_non_null_pointers_for_012() {
        // Contract wget's MinGW startup depends on: three DIFFERENT FILE*
        // values for stdin/stdout/stderr, every one dereferenceable without
        // faulting (libc's fortified stdio path reads _file / _flag).
        let p0 = ucrt_acrt_iob_func(0);
        let p1 = ucrt_acrt_iob_func(1);
        let p2 = ucrt_acrt_iob_func(2);
        assert!(!p0.is_null() && !p1.is_null() && !p2.is_null());
        assert_ne!(p0, p1);
        assert_ne!(p1, p2);
        assert_ne!(p0, p2);
    }

    #[test]
    fn acrt_iob_func_matches_iob_data_layout() {
        // Must share the same 192-byte contiguous array as the _iob DATA
        // import so `stream_to_fd` (and any future code that indexes
        // _iob + N*64) agrees on identity.  Before the fix, __acrt_iob_func
        // returned its own three heap allocations that had no relation to
        // iob_data_addr().
        let base = iob_data_addr();
        assert_eq!(ucrt_acrt_iob_func(0) as usize, base);
        assert_eq!(ucrt_acrt_iob_func(1) as usize, base + 64);
        assert_eq!(ucrt_acrt_iob_func(2) as usize, base + 128);
    }

    #[test]
    fn acrt_iob_func_populates_file_field() {
        // MinGW's _fileno(stdin)/_fileno(stdout)/_fileno(stderr) reads the
        // `_file` field at byte offset 24 of the FILE struct.  Must hold
        // 0/1/2 respectively.  Wine ref: dlls/msvcrt/msvcrt.h:26-35.
        for fd in [0u32, 1, 2] {
            let p = ucrt_acrt_iob_func(fd);
            let file_field = unsafe { *(p.cast::<u8>().add(24) as *const i32) };
            assert_eq!(
                file_field, fd as i32,
                "_file field at offset 24 for idx={fd}"
            );
        }
    }

    #[test]
    fn acrt_iob_func_out_of_range_falls_back_to_stdout() {
        // NULL is the dangerous return: libc fortified derefs on NULL
        // trigger SIGSEGV.  Falling back to stdout is safer for the
        // rare caller that probes indices > 2.
        let p = ucrt_acrt_iob_func(3);
        assert!(!p.is_null());
    }

    #[test]
    fn acrt_iob_func_is_stable_across_calls() {
        // Same index must return the same pointer every time — the FILE*
        // identity is used by _lock_file / _unlock_file and by buffered-I/O
        // state.  Before the fix, HEAP_STDIO satisfied this accidentally;
        // ensure the unified array does too.
        assert_eq!(ucrt_acrt_iob_func(0), ucrt_acrt_iob_func(0));
        assert_eq!(ucrt_acrt_iob_func(1), ucrt_acrt_iob_func(1));
        assert_eq!(ucrt_acrt_iob_func(2), ucrt_acrt_iob_func(2));
    }

    #[test]
    fn acrt_iob_func_resolves_via_resolver() {
        // Must be reachable through both msvcrt.dll and ucrtbase.dll DLL
        // names.  wget.exe imports __acrt_iob_func from msvcrt.dll via
        // MinGW's compat shim (dlls/msvcrt/iob.c in Wine).
        assert!(resolve("msvcrt.dll", "__acrt_iob_func").is_some());
        assert!(resolve("ucrtbase.dll", "__acrt_iob_func").is_some());
        // __iob_func is the legacy msvcrt alias; same implementation.
        assert!(resolve("msvcrt.dll", "__iob_func").is_some());
    }

    // ── Task 01b 3c-I: __stdio_common_v*scanf family ─────────────────────────

    #[test]
    fn stdio_common_vsscanf_returns_int_zero() {
        // Previously aliased to ucrt_cexit (void-returning).  Callers read
        // RAX as the conversion count.  Must return 0 (int) to signal
        // "no conversions" cleanly instead of garbage.
        // Wine ref: dlls/msvcrt/scanf.c:667 — int CDECL __stdio_common_vsscanf.
        let rc = ucrt_stdio_common_vsscanf(
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
        );
        assert_eq!(rc, 0);
    }

    #[test]
    fn stdio_common_vfscanf_returns_int_zero() {
        // Wine ref: dlls/msvcrt/scanf.c:707 — int CDECL __stdio_common_vfscanf.
        let rc = ucrt_stdio_common_vfscanf(
            0,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
        );
        assert_eq!(rc, 0);
    }

    #[test]
    fn stdio_common_vswscanf_returns_int_zero() {
        let rc = ucrt_stdio_common_vswscanf(
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
        );
        assert_eq!(rc, 0);
    }

    #[test]
    fn stdio_common_vfwscanf_returns_int_zero() {
        let rc = ucrt_stdio_common_vfwscanf(
            0,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
        );
        assert_eq!(rc, 0);
    }

    #[test]
    fn stdio_common_scanf_family_resolves_via_resolver() {
        // All four UCRTBASE scanf backends must resolve to real int-returning
        // stubs, not to the void-returning `ucrt_cexit` alias.  Prior to
        // Task 01b 3c-I these fell into the ucrt_cexit catch-all block which
        // leaked `libc::write`'s byte count into RAX — a latent "stub returns
        // value caller dereferences without validation" (KNOWN-BUG-CLASSES:795).
        for dll in ["msvcrt.dll", "ucrtbase.dll"] {
            assert!(
                resolve(dll, "__stdio_common_vsscanf").is_some(),
                "{dll}::__stdio_common_vsscanf"
            );
            assert!(
                resolve(dll, "__stdio_common_vfscanf").is_some(),
                "{dll}::__stdio_common_vfscanf"
            );
            assert!(
                resolve(dll, "__stdio_common_vswscanf").is_some(),
                "{dll}::__stdio_common_vswscanf"
            );
            assert!(
                resolve(dll, "__stdio_common_vfwscanf").is_some(),
                "{dll}::__stdio_common_vfwscanf"
            );
        }
    }

    #[test]
    fn stdio_common_scanf_family_not_aliased_to_cexit() {
        // Structural check: these must resolve to the dedicated int-returning
        // stubs, not to ucrt_cexit (which returns void and leaves garbage
        // in RAX).  Compares resolver-returned fn addresses against
        // ucrt_cexit's address.
        let cexit_addr = ucrt_cexit as *const () as usize;
        for name in [
            "__stdio_common_vsscanf",
            "__stdio_common_vfscanf",
            "__stdio_common_vswscanf",
            "__stdio_common_vfwscanf",
        ] {
            let resolved =
                resolve("msvcrt.dll", name).unwrap_or_else(|| panic!("{name} should resolve"));
            assert_ne!(
                resolved, cexit_addr,
                "{name} is incorrectly aliased to ucrt_cexit"
            );
        }
    }

    #[test]
    fn clock_resolves_and_returns_nonnegative_monotonic() {
        // Resolver must expose `clock` under both msvcrt.dll and ucrtbase.dll
        // since wget imports it from msvcrt.dll.
        assert!(
            resolve("msvcrt.dll", "clock").is_some(),
            "msvcrt.dll::clock must resolve"
        );
        assert!(
            resolve("ucrtbase.dll", "clock").is_some(),
            "ucrtbase.dll::clock must resolve"
        );
        let t0 = ucrt_clock();
        assert!(t0 >= 0, "clock() must be non-negative");
        // Busy-wait briefly so monotonicity is observable even on fast boxes.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t1 = ucrt_clock();
        assert!(t1 >= t0, "clock() must be monotonic: {t1} >= {t0}");
    }

    #[test]
    fn lc_codepage_func_resolves_and_returns_cp_acp() {
        assert!(
            resolve("msvcrt.dll", "___lc_codepage_func").is_some(),
            "msvcrt.dll::___lc_codepage_func must resolve"
        );
        assert!(
            resolve("ucrtbase.dll", "___lc_codepage_func").is_some(),
            "ucrtbase.dll::___lc_codepage_func must resolve"
        );
        // Default MSVCRT "C" locale codepage is CP_ACP=1252 on en-US.
        // wget's locale decoder accepts any plausible CP; we lock the
        // contract at 1252 so regressions surface.
        assert_eq!(ucrt_lc_codepage_func(), 1252);
    }
}
