//! MSVCP140.dll stubs for Weave.
//!
//! All 80 imports used by NXEngine-evo (nx.exe) are resolved here.
//! Function stubs are no-op — they accept any Win64 arguments and return 0.
//! Real pthread implementations for _Mtx_* and _Cnd_* added in TASK-3.
#![allow(clippy::missing_safety_doc)]
//! Real implementations of _Thrd_* come in TASK-4.
//!
//! Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_init_in_situ(mtx, flags),
//!   _Mtx_lock(mtx) returns _Thrd_success = 0.
//! Do NOT add warn_once logging here — these methods are called many times per frame.

/// Single no-op stub for all remaining function symbols.
/// Win64 ABI places return value in RAX; returning 0 covers void, ptr, and int return types.
pub unsafe extern "win64" fn msvcp_noop(_a: usize, _b: usize, _c: usize, _d: usize) -> usize {
    0
}

/// `std::_Fiopen(filename, mode, prot)` — open a file on behalf of std::ifstream/ofstream.
///
/// Wine ref: dlls/msvcp140/msvcp140.c — _Fiopen maps ios_base::openmode bits to fopen
/// mode string; prot (Win32 sharing flags) is ignored on Linux.
/// ios_base::openmode: in=0x01, out=0x02, ate=0x04, app=0x08, trunc=0x10, binary=0x20
pub unsafe extern "win64" fn msvcp_fiopen(
    filename: *const u16,
    mode: i32,
    _prot: i32,
) -> *mut libc::c_void {
    use std::os::unix::ffi::OsStrExt;
    if filename.is_null() {
        return std::ptr::null_mut();
    }
    let len = {
        let mut n = 0usize;
        while n < 32768 && *filename.add(n) != 0 {
            n += 1;
        }
        n
    };
    let wide = std::slice::from_raw_parts(filename, len);
    let win_path = String::from_utf16_lossy(wide).to_owned();
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };
    let path_cstr = match std::ffi::CString::new(linux_path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let r = (mode & 0x01) != 0;
    let w = (mode & 0x02) != 0;
    let a = (mode & 0x08) != 0;
    let t = (mode & 0x10) != 0;
    let b = (mode & 0x20) != 0;
    let mode_str: &[u8] = match (r, w, a, t, b) {
        (true, false, false, _, false) => b"r\0",
        (true, false, false, _, true) => b"rb\0",
        (false, true, false, _, false) => b"w\0",
        (false, true, false, _, true) => b"wb\0",
        (false, true, true, _, false) => b"a\0",
        (false, true, true, _, true) => b"ab\0",
        (true, true, false, false, false) => b"r+\0",
        (true, true, false, false, true) => b"r+b\0",
        (true, true, false, true, false) => b"w+\0",
        (true, true, false, true, true) => b"w+b\0",
        (true, true, true, _, false) => b"a+\0",
        (true, true, true, _, true) => b"a+b\0",
        _ => {
            if b {
                b"rb\0"
            } else {
                b"r\0"
            }
        }
    };
    let mut result = libc::fopen(path_cstr.as_ptr(), mode_str.as_ptr() as *const libc::c_char);
    if result.is_null() {
        // Case-fold + extension-prefix fallback (handles Win32 buffer truncation
        // where "font_1.fn" is passed but "font_1.fnt" exists on disk).
        if let Some(folded) = weave_core::file_io::case_fold_lookup(&linux_path) {
            result = libc::fopen(folded.as_ptr(), mode_str.as_ptr() as *const libc::c_char);
        }
    }
    eprintln!(
        "[weave:fio:fiopen] win={win_path:?} linux={linux_path:?} mode=0x{mode:02x} ok={}",
        !result.is_null()
    );
    result as *mut libc::c_void
}

// ── Real pthread-backed implementations ──────────────────────────────────────

/// _Mtx_init_in_situ — initialize a pthread_mutex_t at the caller-provided address.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_init_in_situ: in-place pthread_mutex_init;
///   flags&0x100=recursive; returns _Thrd_success=0.
/// The caller owns the memory. No Weave-side allocation occurs.
pub unsafe extern "win64" fn mtx_init_in_situ(mtx: *mut libc::c_void, flags: i32) -> i32 {
    #[cfg(target_os = "linux")]
    {
        let mut attr: libc::pthread_mutexattr_t = core::mem::zeroed();
        libc::pthread_mutexattr_init(&mut attr);
        if flags & 0x100 != 0 {
            libc::pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);
        }
        let ret = libc::pthread_mutex_init(mtx as *mut libc::pthread_mutex_t, &attr);
        libc::pthread_mutexattr_destroy(&mut attr);
        ret
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (mtx, flags);
        0
    }
}

/// _Mtx_destroy_in_situ — destroy the pthread_mutex_t at the caller-provided address.
/// Wine ref: dlls/msvcp140/msvcp140.c — calls pthread_mutex_destroy; caller owns memory.
pub unsafe extern "win64" fn mtx_destroy_in_situ(
    mtx: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_mutex_destroy(mtx as *mut libc::pthread_mutex_t);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mtx;
    }
    0
}

/// _Mtx_lock — pthread_mutex_lock on the caller-provided mutex.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_lock: pthread_mutex_lock; returns _Thrd_success=0.
pub unsafe extern "win64" fn mtx_lock(
    mtx: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_mutex_lock(mtx as *mut libc::pthread_mutex_t)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mtx;
        0
    }
}

/// _Mtx_unlock — pthread_mutex_unlock on the caller-provided mutex.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_unlock: pthread_mutex_unlock; returns _Thrd_success=0.
pub unsafe extern "win64" fn mtx_unlock(
    mtx: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_mutex_unlock(mtx as *mut libc::pthread_mutex_t)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mtx;
        0
    }
}

/// _Cnd_destroy_in_situ — destroy the pthread_cond_t at the caller-provided address.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Cnd_destroy_in_situ: pthread_cond_destroy; caller owns memory.
pub unsafe extern "win64" fn cnd_destroy_in_situ(
    cnd: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_cond_destroy(cnd as *mut libc::pthread_cond_t);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cnd;
    }
    0
}

// ── Real _Thrd_* and _Xtime_get_ticks implementations ────────────────────────

/// Heap-allocated context passed to pthread; carries the Win64 thread function + arg.
struct ThrdCtx {
    func: unsafe extern "win64" fn(*mut libc::c_void) -> i32,
    arg: *mut libc::c_void,
}

/// pthread start routine (System V ABI — arg in RDI).
/// Recovers ThrdCtx from the raw pointer, then calls the Win64 PE function with
/// arg in RCX (Rust's `extern "win64"` emits the correct call sequence).
extern "C" fn thrd_start(arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        let ctx = Box::from_raw(arg as *mut ThrdCtx);
        let result = (ctx.func)(ctx.arg);
        result as usize as *mut libc::c_void
    }
}

/// _Thrd_id — return current thread ID.
/// Wine ref: dlls/msvcp90/misc.c — _Thrd_id: returns GetCurrentThreadId(); maps to gettid() on Linux.
pub extern "win64" fn msvcp_thrd_id() -> u32 {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::gettid() as u32
    }
    #[cfg(not(target_os = "linux"))]
    1
}

/// _Thrd_create — create a native thread running proc(arg).
/// Wine ref: dlls/msvcp90/misc.c — _Thrd_create: wraps proc in thread_proc_wrapper, calls
///   _beginthreadex; thr->hnd=HANDLE, thr->id=thread_id; _THRD_ERROR=4.
/// _Thrd_t layout (Win64 x64): {void* hnd @ 0 (8 bytes), unsigned id @ 8 (4 bytes), pad 4}.
/// In Weave: pthread_create with Win64→SysV ABI trampoline; pthread_t stored at thr→hnd.
pub unsafe extern "win64" fn msvcp_thrd_create(
    thr: *mut libc::c_void,
    func: unsafe extern "win64" fn(*mut libc::c_void) -> i32,
    arg: *mut libc::c_void,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        let ctx = Box::new(ThrdCtx { func, arg });
        let ctx_ptr = Box::into_raw(ctx) as *mut libc::c_void;
        let mut pthread: libc::pthread_t = 0;
        let ret = libc::pthread_create(&mut pthread, std::ptr::null(), thrd_start, ctx_ptr);
        if ret == 0 {
            *(thr as *mut libc::pthread_t) = pthread;
            *((thr as *mut u8).add(8) as *mut u32) = 0;
            0
        } else {
            drop(Box::from_raw(ctx_ptr as *mut ThrdCtx));
            4 // _THRD_ERROR
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (thr, func, arg);
        4
    }
}

/// _Thrd_join — join a thread by its pthread handle stored in _Thrd_t.hnd.
/// Wine ref: dlls/msvcp90/misc.c — _Thrd_join: WaitForSingleObject(thr.hnd, INFINITE) +
///   GetExitCodeThread + CloseHandle; returns 0=success, _THRD_ERROR=4.
/// thr_ptr is an implicit pointer to _Thrd_t (Win64 passes 16-byte struct by hidden pointer).
pub unsafe extern "win64" fn msvcp_thrd_join(thr_ptr: usize, code: *mut i32) -> i32 {
    #[cfg(target_os = "linux")]
    {
        let pthread = *(thr_ptr as *const libc::pthread_t);
        if pthread == 0 {
            if !code.is_null() {
                *code = 0;
            }
            return 0;
        }
        let mut retval: *mut libc::c_void = std::ptr::null_mut();
        let ret = libc::pthread_join(pthread, &mut retval);
        if ret == 0 {
            if !code.is_null() {
                *code = retval as usize as i32;
            }
            0
        } else {
            4 // _THRD_ERROR
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = thr_ptr;
        if !code.is_null() {
            *code = 0;
        }
        0
    }
}

/// _Xtime_get_ticks — return 100-ns ticks since 1601-01-01 (FILETIME epoch).
/// Wine ref: dlls/msvcp140/msvcp140.c — _Xtime_get_ticks: FILETIME 100-ns intervals since 1601-01-01.
pub extern "win64" fn msvcp_xtime_get_ticks() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    let unix_100ns = ts.tv_sec as u64 * 10_000_000 + ts.tv_nsec as u64 / 100;
    unix_100ns + 116_444_736_000_000_000
}

/// _Cnd_signal — pthread_cond_signal on the caller-provided condition variable.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Cnd_signal: pthread_cond_signal; returns _Thrd_success=0.
pub unsafe extern "win64" fn cnd_signal(
    cnd: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_cond_signal(cnd as *mut libc::pthread_cond_t)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cnd;
        0
    }
}

// DATA symbols — callers read these addresses directly from the IAT.

/// ?_BADOFF@std@@3_JB — static streamoff constant = -1LL
static BADOFF: i64 = -1;

/// ?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A — the cerr global object.
/// 128 bytes covers the ostream object layout. Zero-initialized; callers that invoke
/// methods through cerr's vtable (offset 0) will get a null vtable pointer, which
/// may crash later — acceptable for TASK-2, fixed when ostream is implemented.
static CERR_OBJ: [u8; 128] = [0u8; 128];

/// ?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A — locale::id for codecvt<char,char>
static LOCALE_ID_CODECVT_DD: usize = 0;

/// ?id@?$codecvt@_WDU_Mbstatet@@@std@@2V0locale@2@A — locale::id for codecvt<wchar_t,char>
static LOCALE_ID_CODECVT_WD: usize = 0;

/// ?id@?$numpunct@D@std@@2V0locale@2@A — locale::id for numpunct<char>
static LOCALE_ID_NUMPUNCT: usize = 0;

/// Resolve a MSVCP140.dll import to a function or data address.
///
/// Returns `None` if the DLL is not msvcp140.dll.
/// Returns `Some(addr)` for every known import.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("msvcp140.dll") {
        return None;
    }

    let addr = match func {
        // ── DATA symbols ──────────────────────────────────────────────────────────
        "?_BADOFF@std@@3_JB" => {
            &BADOFF as *const i64 as usize
        }
        "?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A" => {
            CERR_OBJ.as_ptr() as usize
        }
        "?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A" => {
            &LOCALE_ID_CODECVT_DD as *const usize as usize
        }
        "?id@?$codecvt@_WDU_Mbstatet@@@std@@2V0locale@2@A" => {
            &LOCALE_ID_CODECVT_WD as *const usize as usize
        }
        "?id@?$numpunct@D@std@@2V0locale@2@A" => {
            &LOCALE_ID_NUMPUNCT as *const usize as usize
        }

        // ── Function symbols — all map to msvcp_noop ──────────────────────────────
        "??0?$basic_ios@DU?$char_traits@D@std@@@std@@IEAA@XZ"
        | "??0?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z"
        | "??0?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z"
        | "??0?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z"
        | "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@XZ"
        | "??0?$codecvt@_WDU_Mbstatet@@@std@@QEAA@_K@Z"
        | "??0_Locinfo@std@@QEAA@PEBD@Z"
        | "??0_Lockit@std@@QEAA@H@Z"
        | "??0facet@locale@std@@IEAA@_K@Z"
        | "??1?$basic_ios@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$basic_iostream@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$basic_istream@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$basic_ostream@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$codecvt@_WDU_Mbstatet@@@std@@MEAA@XZ"
        | "??1_Locinfo@std@@QEAA@XZ"
        | "??1_Lockit@std@@QEAA@XZ"
        | "??1facet@locale@std@@MEAA@XZ"
        | "??4?$_Yarn@D@std@@QEAAAEAV01@PEBD@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@I@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAVios_base@1@AEAV21@@Z@Z"
        | "??Bid@locale@std@@QEAA_KXZ"
        | "?_Addfac@_Locimp@locale@std@@AEAAXPEAVfacet@23@_K@Z"
        | "?_Decref@facet@locale@std@@UEAAPEAV_Facet_base@3@XZ"
        | "?_Getcat@?$codecvt@DDU_Mbstatet@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z"
        | "?_Getcvt@_Locinfo@std@@QEBA?AU_Cvtvec@@XZ"
        | "?_Getfalse@_Locinfo@std@@QEBAPEBDXZ"
        | "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ"
        | "?_Getlconv@_Locinfo@std@@QEBAPEBUlconv@@XZ"
        | "?_Gettrue@_Locinfo@std@@QEBAPEBDXZ"
        | "?_Incref@facet@locale@std@@UEAAXXZ"
        | "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXXZ"
        | "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z"
        | "?_Lock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ"
        | "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@AEBV123@@Z"
        | "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ"
        | "?_Throw_C_error@std@@YAXH@Z"
        | "?_Throw_Cpp_error@std@@YAXH@Z"
        | "?_Unlock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ"
        | "?_Xbad_alloc@std@@YAXXZ"
        | "?_Xbad_function_call@std@@YAXXZ"
        | "?_Xlength_error@std@@YAXPEBD@Z"
        | "?_Xout_of_range@std@@YAXPEBD@Z"
        | "?always_noconv@codecvt_base@std@@QEBA_NXZ"
        | "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z"
        | "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ"
        | "?getloc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEBA?AVlocale@2@XZ"
        | "?imbue@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAXAEBVlocale@2@@Z"
        | "?in@?$codecvt@DDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEBD1AEAPEBDPEAD3AEAPEAD@Z"
        | "?out@?$codecvt@DDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEBD1AEAPEBDPEAD3AEAPEAD@Z"
        | "?out@?$codecvt@_WDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEB_W1AEAPEB_WPEAD3AEAPEAD@Z"
        | "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z"
        | "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z"
        | "?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ"
        | "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_JH@Z"
        | "?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAPEAV12@PEAD_J@Z"
        | "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z"
        | "?setw@std@@YA?AU?$_Smanip@_J@1@_J@Z"
        | "?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JXZ"
        | "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z"
        | "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z"
        | "?sync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ"
        | "?tellg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ"
        | "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ"
        | "?uncaught_exception@std@@YA_NXZ"
        | "?unshift@?$codecvt@DDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEAD1AEAPEAD@Z"
        | "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z"
        | "?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEAD_J@Z"
        | "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEBD_J@Z"
        => msvcp_noop as *const () as usize,

        "?_Fiopen@std@@YAPEAU_iobuf@@PEB_WHH@Z" => {
            msvcp_fiopen as unsafe extern "win64" fn(*const u16, i32, i32) -> *mut libc::c_void
                as *const () as usize
        }

        "_Thrd_id" => msvcp_thrd_id as *const () as usize,
        "_Thrd_create" => msvcp_thrd_create as *const () as usize,
        "_Thrd_join" => msvcp_thrd_join as *const () as usize,
        "_Xtime_get_ticks" => msvcp_xtime_get_ticks as *const () as usize,

        "_Mtx_init_in_situ" => mtx_init_in_situ as *const () as usize,
        "_Mtx_destroy_in_situ" => mtx_destroy_in_situ as *const () as usize,
        "_Mtx_lock" => mtx_lock as *const () as usize,
        "_Mtx_unlock" => mtx_unlock as *const () as usize,
        "_Cnd_destroy_in_situ" => cnd_destroy_in_situ as *const () as usize,
        "_Cnd_signal" => cnd_signal as *const () as usize,

        _ => return None,
    };

    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_function_stub_is_some() {
        assert!(resolve("msvcp140.dll", "_Mtx_lock").is_some());
    }

    #[test]
    fn resolve_function_stub_nonzero() {
        let addr = resolve("msvcp140.dll", "_Mtx_lock").unwrap();
        assert_ne!(addr, 0, "stub address must be non-zero");
    }

    #[test]
    fn resolve_badoff_data_symbol() {
        let addr = resolve("msvcp140.dll", "?_BADOFF@std@@3_JB").unwrap();
        assert_ne!(addr, 0);
        let val = unsafe { *(addr as *const i64) };
        assert_eq!(val, -1);
    }

    #[test]
    fn resolve_cerr_data_symbol() {
        let addr = resolve(
            "msvcp140.dll",
            "?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A",
        )
        .unwrap();
        assert_ne!(addr, 0);
    }

    #[test]
    fn resolve_unknown_dll_returns_none() {
        assert!(resolve("kernel32.dll", "_Mtx_lock").is_none());
    }

    #[test]
    fn resolve_unknown_func_returns_none() {
        assert!(resolve("msvcp140.dll", "not_a_real_symbol").is_none());
    }
}
