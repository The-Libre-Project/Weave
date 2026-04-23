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
pub unsafe extern "win64" fn msvcp_noop(
    _a: usize,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    0
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

/// _Thrd_id — return current thread ID.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Thrd_id: returns GetCurrentThreadId(); maps to gettid() on Linux.
pub extern "win64" fn msvcp_thrd_id() -> u32 {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::gettid() as u32
    }
    #[cfg(not(target_os = "linux"))]
    1
}

/// _Thrd_join — join a thread by its OS handle.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Thrd_join: WaitForSingleObject + CloseHandle;
///   stub-safe since _Thrd_create is no-op returning 0 (handle == 0 → nothing to join).
pub unsafe extern "win64" fn msvcp_thrd_join(_thr: usize, code: *mut i32) -> i32 {
    if !code.is_null() {
        *code = 0;
    }
    0 // _Thrd_success
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
        | "?_Fiopen@std@@YAPEAU_iobuf@@PEB_WHH@Z"
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

        "_Thrd_id" => msvcp_thrd_id as *const () as usize,
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
        let addr = resolve("msvcp140.dll", "?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A").unwrap();
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
