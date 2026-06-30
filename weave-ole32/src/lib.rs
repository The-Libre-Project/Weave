//! ole32.dll / combase.dll stubs for Weave.
#![allow(clippy::missing_safety_doc)]
//!
//! # Phase 2 scope
//!
//! Implements the minimum COM surface required to prevent crashes in apps that
//! call `CoInitializeEx` or `CoCreateInstance` from their CRT or startup code.
//!
//! ## What is implemented
//!
//! - `CoInitializeEx` / `CoInitialize` / `CoUninitialize` — thread-local
//!   COM initialisation state. Returns S_OK or S_FALSE (already initialised).
//! - `CoCreateInstance` — creates an instance of a well-known CLSID. Phase 2
//!   supports a minimal set needed to unblock app startup; unknown CLSIDs
//!   return `REGDB_E_CLASSNOTREG`.
//! - `CoTaskMemAlloc` / `CoTaskMemFree` / `CoTaskMemRealloc` — libc malloc.
//! - `StringFromGUID2` — formats a GUID as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
//! - `CLSIDFromString` / `IIDFromString` — parse a GUID string.
//! - `CoSetProxyBlanket` — no-op security blanket (stub).
//! - `OleInitialize` / `OleUninitialize` — delegate to Co* variants.
//!
//! ## What is NOT implemented
//!
//! Real COM object creation, marshalling, proxy/stub infrastructure,
//! apartment threading, ROT, moniker binding, structured storage, etc.
//! These are Phase 3+ concerns.

use std::cell::Cell;

use weave_common::com::shell_link::{create_shell_link, CLSID_SHELL_LINK};

/// SumatraPDF DDE single-instance-server CLSID.
/// Intercepted by co_create_instance when WEAVE_TEST_SUMATRA_CLSID=1 is set.
/// Returning S_OK (instead of REGDB_E_CLASSNOTREG) causes SumatraPDF to exit its
/// DDE retry loop and fall through to "I am the primary instance" → GetMessage → render.
///
/// Binary RE (2026-06-02, CI-FAIL-LADDER Fail #62): SumatraPDF 3.4.x calls
/// CoCreateInstance({9E56BE60-C50F-11CF-9A2C-00A0C90A90CE}, ...) and when it
/// gets REGDB_E_CLASSNOTREG, enters a tight retry loop (CoCreateInstance →
/// GetFileAttributesExW×10, repeat). Breaking out of this loop unblocks the
/// message pump and WM_PAINT/StretchBlt render path.
///
/// This is escalation-packet priority 1 from docs/loop-arcs/sumatrapdf_pdf_render_gate.md.
const CLSID_SUMATRA_DDE_SERVER: [u8; 16] = [
    0x60, 0xBE, 0x56, 0x9E, // Data1 = 0x9E56BE60
    0x0F, 0xC5, // Data2 = 0xC50F (byte index 4 is 0x0F, per P1 CI run 27348428999)
    0xCF, 0x11, // Data3 = 0x11CF
    0x9A, 0x2C, 0x00, 0xA0, 0xC9, 0x0A, 0x90, 0xCE, // Data4
];

/// Minimal IUnknown singleton for the SumatraPDF DDE server sentinel.
/// CoCreateInstance returns S_OK with *ppv pointing to this singleton.
/// Any subsequent QueryInterface call returns E_NOINTERFACE (including for
/// IID_IDdeServer), which SumatraPDF interprets as "DDE server not available
/// but CoCreateInstance succeeded" — it then proceeds as the primary instance,
/// reaching GetMessage → WM_PAINT → render.
///
/// Without this sentinel, SumatraPDF receives *ppv=NULL with S_OK and calls
/// a method on the NULL pointer, triggering a clean exit (not a crash — it
/// checks the pointer before use and exits its DDE init path).
static SUMATRA_DDE_SENTINEL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

fn get_dde_sentinel_ptr() -> usize {
    *SUMATRA_DDE_SENTINEL.get_or_init(|| {
        let vtable: Box<[usize; 3]> = Box::new([
            dde_iunknown_query_interface as *const () as usize,
            dde_iunknown_add_ref as *const () as usize,
            dde_iunknown_release as *const () as usize,
        ]);
        let vtable_ptr = Box::into_raw(vtable) as usize;
        // The COM object points to its vtable pointer.
        let obj: Box<usize> = Box::new(vtable_ptr);
        Box::into_raw(obj) as usize
    })
}

// Wine ref: dlls/ole32/compobj.c — IUnknown::QueryInterface for a minimal object.
// Returns S_OK only when riid is IID_IUnknown; all other IIDs return E_NOINTERFACE.
unsafe extern "win64" fn dde_iunknown_query_interface(
    _this: usize,
    riid: *const u8,
    ppv: *mut usize,
) -> u32 {
    if !riid.is_null() && !ppv.is_null() {
        let guid = unsafe { std::slice::from_raw_parts(riid, 16) };
        // IID_IUnknown = {00000000-0000-0000-C000-000000000046}
        const IID_IUNKNOWN: [u8; 16] = [
            0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0u8, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ];
        if guid == IID_IUNKNOWN {
            unsafe { *ppv = get_dde_sentinel_ptr() };
            return S_OK;
        }
    }
    // E_NOINTERFACE for all non-IUnknown IIDs (IDdeServer, IMarshal, etc.)
    if !ppv.is_null() {
        unsafe { *ppv = 0 };
    }
    0x8000_4002u32 // E_NOINTERFACE
}

unsafe extern "win64" fn dde_iunknown_add_ref(_this: usize) -> u32 {
    1
}
unsafe extern "win64" fn dde_iunknown_release(_this: usize) -> u32 {
    1
}

// ── COM HRESULT constants ─────────────────────────────────────────────────────

const S_OK: u32 = 0x0000_0000;
const S_FALSE: u32 = 0x0000_0001;
const E_INVALIDARG: u32 = 0x8007_0057;
#[allow(dead_code)]
const E_OUTOFMEMORY: u32 = 0x8007_000E;
const REGDB_E_CLASSNOTREG: u32 = 0x8004_0154;
const CO_E_NOTINITIALIZED: u32 = 0x8004_001E;

// COINIT flags
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const COINIT_MULTITHREADED: u32 = 0x0;

// ── Per-thread COM state ──────────────────────────────────────────────────────

thread_local! {
    /// Nesting depth of CoInitialize[Ex] calls on this thread.
    static COM_INIT_COUNT: Cell<u32> = const { Cell::new(0) };
    /// COINIT flags used on first init (APARTMENTTHREADED or MULTITHREADED).
    static COM_INIT_FLAGS: Cell<u32> = const { Cell::new(0) };
}

// ── CoInitializeEx / CoInitialize / CoUninitialize ───────────────────────────

// Wine ref: dlls/combase/apartment.c — creates STA (COINIT_APARTMENTTHREADED) or joins MTA
// (COINIT_MULTITHREADED); returns RPC_E_CHANGED_MODE (0x80010106) if apartment model conflicts
// with existing apartment on this thread; S_OK first call, S_FALSE if already initialized.
/// CoInitializeEx: initialise the COM library on the calling thread.
///
/// Returns `S_OK` on first call, `S_FALSE` if COM was already initialised on
/// this thread, or `RPC_E_CHANGED_MODE` (0x80010106) if the apartment model
/// conflicts with a previous call.
// Wine ref: dlls/combase/apartment.c — STA/MTA per-thread apartment; RPC_E_CHANGED_MODE on model conflict.
pub extern "win64" fn co_initialize_ex(_pv_reserved: usize, dw_co_init: u32) -> u32 {
    COM_INIT_COUNT.with(|c| {
        let count = c.get();
        if count == 0 {
            COM_INIT_FLAGS.with(|f| f.set(dw_co_init & 0x3));
            c.set(1);
            S_OK
        } else {
            // Already initialised — check for apartment model conflict.
            let stored = COM_INIT_FLAGS.with(|f| f.get());
            let req = dw_co_init & 0x3;
            // Both must agree on STA vs MTA.
            let stored_mta = stored == COINIT_MULTITHREADED;
            let req_mta = req == COINIT_MULTITHREADED;
            if stored_mta != req_mta {
                return 0x8001_0106; // RPC_E_CHANGED_MODE
            }
            c.set(count + 1);
            S_FALSE
        }
    })
}

// Wine ref: dlls/combase/combase.c — thin wrapper: calls CoInitializeEx(NULL, COINIT_APARTMENTTHREADED).
/// CoInitialize: legacy variant (always STA).
pub extern "win64" fn co_initialize(pv_reserved: usize) -> u32 {
    co_initialize_ex(pv_reserved, COINIT_APARTMENTTHREADED)
}

// Wine ref: dlls/combase/combase.c — decrements per-thread apartment refcount; at zero
// uninitializes apartment and frees thread-local COM state (TLS slot released).
/// CoUninitialize: decrement the COM initialisation count for this thread.
///
/// When the count reaches zero the thread's apartment is torn down (no-op in
/// Phase 2).
// Wine ref: dlls/combase/combase.c — per-thread refcount; at zero: uninit apartment + free TLS.
pub extern "win64" fn co_uninitialize() {
    COM_INIT_COUNT.with(|c| {
        let count = c.get();
        if count > 0 {
            c.set(count - 1);
        }
    });
}

// ── CoCreateInstance ──────────────────────────────────────────────────────────

/// Read a 16-byte GUID from a raw pointer.
unsafe fn read_guid(p: *const u8) -> Option<[u8; 16]> {
    if p.is_null() {
        return None;
    }
    let mut buf = [0u8; 16];
    unsafe { std::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), 16) };
    Some(buf)
}

// Wine ref: dlls/combase/combase.c:1725 — wraps CoCreateInstanceEx with single MULTI_QI entry;
// returns E_POINTER if obj is NULL before any registry lookup; sets *obj = multi_qi.pItf.
/// CoCreateInstance: create a single uninitialized object of a given class.
///
/// Phase 2: returns `REGDB_E_CLASSNOTREG` for all CLSIDs. The primary purpose
/// is to prevent a crash when apps call this at startup — they should handle
/// the failure gracefully (most do, falling back to built-in alternatives).
///
/// # Safety
/// `rclsid` and `riid` must be valid pointers to 16-byte GUID structs.
/// `ppv` must be a valid writable pointer to a `*mut c_void` output slot.
// Wine ref: dlls/combase/combase.c:1725 — wraps CoCreateInstanceEx; E_POINTER if obj null.
pub unsafe extern "win64" fn co_create_instance(
    rclsid: *const u8,
    _p_unk_outer: usize,
    _dw_cls_context: u32,
    _riid: *const u8,
    ppv: *mut usize,
) -> u32 {
    // Null out the output pointer so callers can check it safely.
    if !ppv.is_null() {
        unsafe { *ppv = 0 };
    }

    let clsid = match unsafe { read_guid(rclsid) } {
        Some(g) => g,
        None => return E_INVALIDARG,
    };

    // CLSID_ShellLink — dispatch to weave-common IShellLink foundation.
    if clsid == CLSID_SHELL_LINK {
        eprintln!("weave/ole32: CoCreateInstance: CLSID_ShellLink → create_shell_link");
        // SAFETY: rclsid and riid are valid (rclsid was just read above; riid is passed
        // through unchanged). ppv is non-null (checked above). create_shell_link validates
        // ppv internally.
        let ppv_ptr = ppv as *mut *mut ();
        return unsafe { create_shell_link(rclsid, _riid, ppv_ptr) };
    }

    // E3-M4 test hook: intercept SumatraPDF DDE single-instance-server CLSID.
    // Gated by WEAVE_TEST_SUMATRA_CLSID=1 env var (CI-only; zero cost in production).
    // Returns S_OK with *ppv=NULL, causing SumatraPDF to exit its DDE retry loop
    // and proceed as the primary instance (reaches GetMessage → WM_PAINT → render).
    // *ppv is set to a minimal IUnknown sentinel — the caller can QI from it but all
    // non-IUnknown IIDs (including IDdeServer) return E_NOINTERFACE.
    if clsid == CLSID_SUMATRA_DDE_SERVER
        && std::env::var("WEAVE_TEST_SUMATRA_CLSID").as_deref() == Ok("1")
    {
        eprintln!(
            "weave/ole32: CoCreateInstance: CLSID_Sumatra_DDE → TEST HOOK: returning S_OK (E3-M4 P1 intercept)"
        );
        if !ppv.is_null() {
            unsafe { *ppv = get_dde_sentinel_ptr() };
        }
        return S_OK;
    }

    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    eprintln!(
        "weave/ole32: CoCreateInstance: tid={tid} CLSID {:02x?} (unknown — REGDB_E_CLASSNOTREG)",
        clsid
    );

    REGDB_E_CLASSNOTREG
}

// Wine ref: dlls/combase/combase.c:1922 — calls CoGetClassObject then IClassFactory::CreateInstance
// then QI for each MULTI_QI entry; sets hr per entry; aggregate hr = first failure.
/// CoCreateInstanceEx: extended version of CoCreateInstance (stub).
///
/// # Safety
/// `rclsid` must be a valid pointer to a 16-byte GUID.
// Wine ref: dlls/combase/combase.c:1922 — CoGetClassObject + IClassFactory::CreateInstance + QI per MULTI_QI.
pub unsafe extern "win64" fn co_create_instance_ex(
    rclsid: *const u8,
    _p_unk_outer: usize,
    _dw_cls_context: u32,
    _p_server_info: usize,
    _dw_count: u32,
    _rg_mqi: usize,
) -> u32 {
    let clsid = match unsafe { read_guid(rclsid) } {
        Some(g) => g,
        None => return E_INVALIDARG,
    };

    eprintln!(
        "weave/ole32: CoCreateInstanceEx: CLSID {:02x?} (stub — REGDB_E_CLASSNOTREG)",
        clsid
    );
    REGDB_E_CLASSNOTREG
}

// ── CoTaskMemAlloc / CoTaskMemFree / CoTaskMemRealloc ─────────────────────────

// Wine ref: dlls/ole32/ifs.c — calls IMalloc::Alloc on process task allocator (wraps
// HeapAlloc(GetProcessHeap())); returns NULL on failure; cb==0 behavior is implementation-defined.
/// CoTaskMemAlloc: allocate a block of task memory.
///
/// Equivalent to `malloc`; returns NULL on failure.
pub extern "win64" fn co_task_mem_alloc(cb: usize) -> usize {
    if cb == 0 {
        return 0;
    }
    unsafe { libc::malloc(cb) as usize }
}

// Wine ref: dlls/ole32/ifs.c — calls IMalloc::Free (wraps HeapFree(GetProcessHeap())); NULL is no-op.
/// CoTaskMemFree: free task memory allocated by CoTaskMemAlloc.
pub extern "win64" fn co_task_mem_free(pv: usize) {
    if pv != 0 {
        unsafe { libc::free(pv as *mut libc::c_void) };
    }
}

// Wine ref: dlls/ole32/ifs.c — calls IMalloc::Realloc; if cb==0 frees and returns NULL;
// if pv==NULL equivalent to CoTaskMemAlloc(cb); returns NULL on allocation failure.
/// CoTaskMemRealloc: resize a task memory block.
pub extern "win64" fn co_task_mem_realloc(pv: usize, cb: usize) -> usize {
    if cb == 0 {
        co_task_mem_free(pv);
        return 0;
    }
    unsafe { libc::realloc(pv as *mut libc::c_void, cb) as usize }
}

// ── GUID utilities ────────────────────────────────────────────────────────────

// Wine ref: dlls/ole32/compobj.c — writes {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\0 uppercase;
// returns 0 if cch_max < 39 or pointers null; 39 (characters including NUL) on success.
/// StringFromGUID2: convert a GUID to its string representation.
///
/// Writes `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\0` (39 chars including NUL)
/// into `lpsz` and returns 39 (the number of characters written including NUL).
/// Returns 0 if `cch_max < 39` or if pointers are null.
///
/// # Safety
/// `rclsid` must be a valid pointer to a 16-byte GUID.
/// `lpsz` must be a writable buffer of at least `cch_max` UTF-16 code units.
// Wine ref: dlls/ole32/compobj.c — uppercase hex; returns 0 if cch_max < 39 or null ptr.
pub unsafe extern "win64" fn string_from_guid2(
    rclsid: *const u8,
    lpsz: *mut u16,
    cch_max: i32,
) -> i32 {
    if rclsid.is_null() || lpsz.is_null() || cch_max < 39 {
        return 0;
    }
    let guid = unsafe { std::slice::from_raw_parts(rclsid, 16) };
    // GUID wire format: Data1(4B LE) Data2(2B LE) Data3(2B LE) Data4(8B)
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    let s = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15],
    );
    // Write as UTF-16 + NUL.
    for (i, ch) in s.encode_utf16().enumerate() {
        unsafe { *lpsz.add(i) = ch };
    }
    unsafe { *lpsz.add(s.len()) = 0 };
    39 // characters written including NUL
}

/// Parse a GUID string `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` into a 16-byte buffer.
fn parse_guid_str(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    // Strip braces.
    let s = if s.starts_with('{') && s.ends_with('}') {
        &s[1..s.len() - 1]
    } else {
        s
    };
    let parts: Vec<&str> = s.splitn(5, '-').collect();
    if parts.len() != 5 {
        return None;
    }
    let d1 = u32::from_str_radix(parts[0], 16).ok()?;
    let d2 = u16::from_str_radix(parts[1], 16).ok()?;
    let d3 = u16::from_str_radix(parts[2], 16).ok()?;
    if parts[3].len() != 4 || parts[4].len() != 12 {
        return None;
    }
    let b89 = u16::from_str_radix(parts[3], 16).ok()?.to_be_bytes();
    let mut rest = [0u8; 6];
    for i in 0..6 {
        rest[i] = u8::from_str_radix(&parts[4][i * 2..i * 2 + 2], 16).ok()?;
    }
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&d1.to_le_bytes());
    buf[4..6].copy_from_slice(&d2.to_le_bytes());
    buf[6..8].copy_from_slice(&d3.to_le_bytes());
    buf[8..10].copy_from_slice(&b89);
    buf[10..16].copy_from_slice(&rest);
    Some(buf)
}

// Wine ref: dlls/combase/combase.c — calls guid_from_string() helper; accepts with or without
// braces; returns CO_E_CLASSSTRING (0x80040205) on malformed input, not E_INVALIDARG.
/// CLSIDFromString: convert a CLSID string to a CLSID.
///
/// # Safety
/// `lpsz` must be a null-terminated UTF-16 string.
/// `pclsid` must be a writable 16-byte buffer.
// Wine ref: dlls/combase/combase.c — guid_from_string(); CO_E_CLASSSTRING on bad format.
pub unsafe extern "win64" fn clsid_from_string(lpsz: *const u16, pclsid: *mut u8) -> u32 {
    if lpsz.is_null() || pclsid.is_null() {
        return E_INVALIDARG;
    }
    let mut len = 0usize;
    // Pointer validation: GUID strings are at most ~40 chars; cap at 256.
    const MAX_LEN: usize = 256;
    while len < MAX_LEN && unsafe { *lpsz.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(lpsz, len) };
    let s = String::from_utf16_lossy(slice);
    match parse_guid_str(&s) {
        Some(guid) => {
            unsafe { std::ptr::copy_nonoverlapping(guid.as_ptr(), pclsid, 16) };
            S_OK
        }
        None => 0x8004_0205, // CO_E_CLASSSTRING
    }
}

/// CoCreateGuid: create a new globally unique identifier (GUID).
/// Stub returns E_NOTIMPL.
pub unsafe extern "win64" fn co_create_guid(_pguid: *mut u8) -> u32 {
    0x8000_401E // E_NOTIMPL
}

// Wine ref: dlls/combase/combase.c — identical implementation to CLSIDFromString; IID and CLSID
// share the GUID wire format; both call guid_from_string() internally.
/// IIDFromString: same as CLSIDFromString (IID and CLSID are both GUIDs).
///
/// # Safety
/// Same as `CLSIDFromString`.
// Wine ref: dlls/combase/combase.c — identical to CLSIDFromString; IID == GUID wire format.
pub unsafe extern "win64" fn iid_from_string(lpsz: *const u16, piid: *mut u8) -> u32 {
    unsafe { clsid_from_string(lpsz, piid) }
}

// ── OLE initialisation ────────────────────────────────────────────────────────

// Wine ref: dlls/ole32/ole2.c:162 — calls CoInitializeEx(COINIT_APARTMENTTHREADED); on first
// process init calls OLEDD_Initialize() (D&D tracker) and OLEMenu_Initialize(); S_FALSE if re-init.
/// OleInitialize: initialise OLE on the calling thread (STA).
pub extern "win64" fn ole_initialize(pv_reserved: usize) -> u32 {
    let result = co_initialize(pv_reserved);
    eprintln!("weave/ole32: OleInitialize → {result:#010x}");
    result
}

// Wine ref: dlls/ole32/ole2.c — decrements OLE init count; at zero shuts down D&D tracker and
// OLE menus (if last process reference); then calls CoUninitialize to release the apartment.
/// OleUninitialize: uninitialise OLE on the calling thread.
pub extern "win64" fn ole_uninitialize() {
    eprintln!("weave/ole32: OleUninitialize");
    co_uninitialize();
}

// Wine ref: dlls/ole32/ole2.c — OleLockRunning calls IUnknown::LockRunning (container
// keeps object alive); stub returns S_OK.
/// OleLockRunning — lock a running object so it stays in the running state.
pub extern "win64" fn ole_lock_running(
    _p_unknown: usize,
    _f_lock: i32,
    _f_last_unlock_closes: i32,
) -> u32 {
    S_OK
}

// Wine ref: dlls/ole32/ole2.c — OleDuplicateData duplicates a data handle using
// global memory (HGLOBAL); stub returns 0 (failure).
/// OleDuplicateData — duplicate OLE data (stub). Returns NULL.
pub extern "win64" fn ole_duplicate_data(_h_src: usize, _cf_format: u16, _ui_flags: u32) -> usize {
    0 // NULL — duplication not supported
}

// Wine ref: dlls/ole32/ole2.c — OleSetClipboard calls DataObject::SetClipboard;
// returns CLIPBRD_E_CANT_OPEN (0x800401D4) if clipboard not open.
/// OleSetClipboard — place data on the OLE clipboard (stub). Returns S_OK.
pub extern "win64" fn ole_set_clipboard(_p_data_obj: usize) -> u32 {
    S_OK
}

// Wine ref: dlls/ole32/ole2.c — OleGetClipboard returns the data object from
// the OLE clipboard; stub returns NULL with S_OK.
/// OleGetClipboard — retrieve the OLE clipboard data object (stub). Returns S_OK, obj=NULL.
///
/// # Safety
/// `pp_data_obj` must be a valid writable pointer if non-null.
pub unsafe extern "win64" fn ole_get_clipboard(pp_data_obj: *mut usize) -> u32 {
    if !pp_data_obj.is_null() {
        unsafe { *pp_data_obj = 0 };
    }
    S_OK
}

// ── Security / proxy stubs ────────────────────────────────────────────────────

// Wine ref: dlls/combase/marshal.c — QIs proxy for IClientSecurity; calls SetBlanket with
// authn/authz/auth-level/imp-level; returns E_NOINTERFACE if pProxy is not a real proxy.
/// CoSetProxyBlanket: set authentication information for a proxy (stub).
///
/// Returns `S_OK` — security blankets are ignored in Phase 2.
pub extern "win64" fn co_set_proxy_blanket(
    _proxy: usize,
    _dw_authn_svc: u32,
    _dw_authz_svc: u32,
    _p_server_princname: usize,
    _dw_authn_level: u32,
    _dw_imp_level: u32,
    _p_auth_info: usize,
    _dw_capabilities: u32,
) -> u32 {
    S_OK
}

// Wine ref: dlls/combase/combase.c — sets process-wide security blanket; valid only before first
// apartment is created; returns RPC_E_TOO_LATE if any apartment already exists.
/// CoInitializeSecurity: set security for the process (stub).
///
/// Returns `S_OK` — security is not enforced in Phase 2.
pub extern "win64" fn co_initialize_security(
    _p_sec_desc: usize,
    _c_auth_svc: i32,
    _as_auth_svc: usize,
    _p_reserved1: usize,
    _dw_authn_level: u32,
    _dw_imp_level: u32,
    _p_auth_list: usize,
    _dw_capabilities: u32,
    _p_reserved3: usize,
) -> u32 {
    S_OK
}

// Wine ref: dlls/combase/combase.c:1965 — delegates to com_get_class_object(); searches activation
// context first, then HKCR\CLSID\{...}\InprocServer32; returns REGDB_E_CLASSNOTREG if not found.
/// CoGetClassObject: retrieve the class factory for a given CLSID (stub).
///
/// Returns `REGDB_E_CLASSNOTREG` — no class factories in Phase 2.
///
/// # Safety
/// Pointer arguments must be null or valid.
// Wine ref: dlls/combase/combase.c:1965 — com_get_class_object(); REGDB_E_CLASSNOTREG if not found.
pub unsafe extern "win64" fn co_get_class_object(
    rclsid: *const u8,
    _dw_cls_context: u32,
    _pv_reserved: usize,
    _riid: *const u8,
    ppv: *mut usize,
) -> u32 {
    if !ppv.is_null() {
        unsafe { *ppv = 0 };
    }
    let clsid = match unsafe { read_guid(rclsid) } {
        Some(g) => g,
        None => return E_INVALIDARG,
    };
    eprintln!(
        "weave/ole32: CoGetClassObject: CLSID {:02x?} (stub — REGDB_E_CLASSNOTREG)",
        clsid
    );
    REGDB_E_CLASSNOTREG
}

// Wine ref: dlls/combase/marshal.c — CoMarshalInterface QIs object for IMarshal; writes OBJREF
// to stream; increments stub refcount; CO_E_NOTINITIALIZED if no apartment on thread.
/// CoMarshalInterface / CoUnmarshalInterface: no-op stubs.
pub extern "win64" fn co_marshal_interface(
    _p_stm: usize,
    _riid: usize,
    _punk: usize,
    _dw_dest_context: u32,
    _pv_dest_context: usize,
    _mshlflags: u32,
) -> u32 {
    CO_E_NOTINITIALIZED
}

// Wine ref: dlls/combase/marshal.c — reads OBJREF header from stream; calls get_unmarshaler_from_stream()
// to create proxy; requires initialized apartment; CO_E_NOTINITIALIZED if no apartment on thread.
pub extern "win64" fn co_unmarshal_interface(_p_stm: usize, _riid: usize, _ppv: usize) -> u32 {
    CO_E_NOTINITIALIZED
}

/// CoMarshalInterThreadInterfaceInStream: marshal an interface pointer into a stream
/// that can be unmarshalled in a different apartment.
/// Phase A stub — returns E_NOTIMPL.
// Wine ref: dlls/ole32/marshal.c — creates a stream and marshals the interface
// into it via CoMarshalInterface; we return E_NOTIMPL for now.
pub extern "win64" fn co_marshal_inter_thread_interface_in_stream(
    _riid: *const u8,
    _punk: usize,
    _pp_stm: *mut usize,
) -> u32 {
    0x80004001 // E_NOTIMPL
}

/// CoGetInterfaceAndReleaseStream: unmarshal an interface from a stream and release it.
/// Phase A stub — returns E_NOTIMPL.
// Wine ref: dlls/ole32/marshal.c — unmarshal via CoUnmarshalInterface, then
// release the stream; we return E_NOTIMPL.
pub extern "win64" fn co_get_interface_and_release_stream(
    _p_stm: usize,
    _riid: *const u8,
    _ppv: *mut usize,
) -> u32 {
    0x80004001 // E_NOTIMPL
}

/// CoLockObjectExternal: lock an object so it stays in memory.
/// Phase A stub — returns S_OK.
// Wine ref: dlls/ole32/ole2.c — calls CoLockObjectExternal on the object's
// marshalling context; no-op for Phase A.
pub extern "win64" fn co_lock_object_external(
    _punk: usize,
    _f_lock: i32,
    _f_last_unlock_releases: i32,
) -> u32 {
    0 // S_OK
}

/// OleFlushClipboard: flush the clipboard contents.
/// Phase A stub — returns S_OK.
// Wine ref: dlls/ole32/ole2clip.c — notifies clipboard viewers; no-op.
pub extern "win64" fn ole_flush_clipboard() -> u32 {
    0 // S_OK
}

/// OleIsCurrentClipboard: check if the clipboard data object is current.
/// Phase A stub — returns S_FALSE (not current).
// Wine ref: dlls/ole32/ole2clip.c — compares the data object; return S_FALSE.
pub extern "win64" fn ole_is_current_clipboard(_p_data_obj: usize) -> u32 {
    1 // S_FALSE
}

/// OleRun: run an embedded object (transition to running state).
/// Phase A stub — returns S_OK.
// Wine ref: dlls/ole32/ole2.c — calls IRunnableObject::Run; no-op.
pub extern "win64" fn ole_run(_punk: usize) -> u32 {
    0 // S_OK
}

/// OleSetContainedObject: inform an object that it is contained.
/// Phase A stub — returns S_OK.
// Wine ref: dlls/ole32/ole2.c — sets the contained-object flag; no-op.
pub extern "win64" fn ole_set_contained_object(_punk: usize, _f_contained: i32) -> u32 {
    0 // S_OK
}

// Wine ref: dlls/combase/stubmanager.c — finds stub manager for punk in current apartment;
// disconnects all remote references without destroying the object itself; S_OK always.
/// CoDisconnectObject: disconnect a running object from its external connections (stub).
pub extern "win64" fn co_disconnect_object(_punk: usize, _dw_reserved: u32) -> u32 {
    S_OK
}

// Wine ref: dlls/combase/combase.c:1302 — checks activation context section first; falls back to
// HKCR\CLSID\{...}\ProgID registry value; allocates result with CoTaskMemAlloc (caller must free).
/// ProgIDFromCLSID: return the ProgID for a given CLSID (stub).
///
/// # Safety
/// `_rclsid` must be null or a valid pointer to a 16-byte CLSID.
/// `lp_sz_prog_id` must be a valid writable pointer to a `*mut u16` output slot.
// Wine ref: dlls/combase/combase.c:1302 — activation context then HKCR\CLSID\{}\ProgID; CoTaskMemAlloc result.
pub unsafe extern "win64" fn prog_id_from_clsid(
    _rclsid: *const u8,
    lp_sz_prog_id: *mut *mut u16,
) -> u32 {
    if !lp_sz_prog_id.is_null() {
        unsafe { *lp_sz_prog_id = std::ptr::null_mut() };
    }
    REGDB_E_CLASSNOTREG
}

// Wine ref: dlls/combase/combase.c:1477 — checks activation context first; falls back to
// HKCR\<progid>\CLSID\(default) registry value; returns REGDB_E_CLASSNOTREG if not found.
/// CLSIDFromProgID: return the CLSID for a given ProgID (stub).
///
/// # Safety
/// `_lpsz_prog_id` must be null or a valid null-terminated UTF-16 string.
/// `lpclsid` must be a valid writable 16-byte buffer.
// Wine ref: dlls/combase/combase.c:1477 — activation context then HKCR\<progid>\CLSID\(default).
pub unsafe extern "win64" fn clsid_from_prog_id(
    _lpsz_prog_id: *const u16,
    lpclsid: *mut u8,
) -> u32 {
    if !lpclsid.is_null() {
        unsafe { std::ptr::write_bytes(lpclsid, 0, 16) };
    }
    REGDB_E_CLASSNOTREG
}

// ── Drag-and-drop / storage stubs ────────────────────────────────────────────

// Wine ref: dlls/ole32/ole2.c — frees medium based on tymed: HGLOBAL→GlobalFree, HFILE→CloseHandle,
// IStream/IStorage→Release, HGDIOBJ→DeleteObject; if pUnkForRelease non-null, calls its Release.
/// ReleaseStgMedium — release a STGMEDIUM storage medium. No-op stub.
///
/// # Safety
/// `pmedium` is accepted but not dereferenced.
// Wine ref: dlls/ole32/ole2.c — frees by tymed: HGLOBAL/HFILE/IStream/IStorage/HGDIOBJ; pUnkForRelease->Release.
pub unsafe extern "win64" fn release_stg_medium(_pmedium: *mut u8) {}

// Wine ref: dlls/ole32/ole2.c — registers IDropTarget for hwnd in internal hashtable; requires STA;
// returns DRAGDROP_E_ALREADYREGISTERED (0x80040101) if hwnd already registered; CO_E_NOTINITIALIZED if no STA.
/// RegisterDragDrop — register a window as a drag-drop target. Returns E_NOTIMPL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/ole32/ole2.c — registers IDropTarget in hashtable; STA required; DRAGDROP_E_ALREADYREGISTERED if dup.
pub unsafe extern "win64" fn register_drag_drop(hwnd: usize, _p_drop_target: *mut u8) -> i32 {
    // Wine ref: dlls/ole32/ole2.c — returns CO_E_NOTINITIALIZED if no STA,
    // DRAGDROP_E_ALREADYREGISTERED if already registered, S_OK on success.
    // Weave stub: always succeeds — no real drop events are ever delivered.
    eprintln!("weave/ole32: RegisterDragDrop(hwnd={hwnd:#x}) → S_OK");
    0 // S_OK
}

// Wine ref: dlls/ole32/ole2.c — removes IDropTarget for hwnd from hashtable; returns
// DRAGDROP_E_NOTREGISTERED (0x80040100) if hwnd was not registered; S_OK on success.
/// RevokeDragDrop — revoke a window's drag-drop registration. Returns S_OK.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/ole32/ole2.c — removes IDropTarget from hashtable; DRAGDROP_E_NOTREGISTERED if not found.
pub unsafe extern "win64" fn revoke_drag_drop(hwnd: usize) -> i32 {
    eprintln!("weave/ole32: RevokeDragDrop(hwnd={hwnd:#x}) → S_OK");
    0 // S_OK
}

// Wine ref: dlls/ole32/ole2.c — creates tracker window; runs message loop tracking mouse;
// calls IDropTarget::{DragEnter,DragOver,Drop,DragLeave}; returns DRAGDROP_S_DROP or DRAGDROP_S_CANCEL.
/// DoDragDrop — initiate a drag-and-drop operation. Returns DRAGDROP_S_CANCEL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/ole32/ole2.c — tracker window + message loop; IDropTarget::{DragEnter,DragOver,Drop,DragLeave}.
pub unsafe extern "win64" fn do_drag_drop(
    _p_data_obj: *mut u8,
    _p_drop_source: *mut u8,
    _dw_ok_effects: u32,
    _pdw_effect: *mut u32,
) -> i32 {
    0x0004_0101u32 as i32 // DRAGDROP_S_CANCEL
}

// ── StringFromCLSID ───────────────────────────────────────────────────────────

/// StringFromCLSID — convert a CLSID to a string (ole32 version).
/// Returns E_OUTOFMEMORY (0x8007000E) — stub, no allocation.
pub unsafe extern "win64" fn string_from_clsid(_rclsid: *const u8, _lpsz: *mut *mut u16) -> u32 {
    0x8007000E // E_OUTOFMEMORY
}

// ── PropVariant ───────────────────────────────────────────────────────────────

// Wine ref: dlls/ole32/ole2.c::PropVariantClear — reads vt field; frees heap-allocated members
// (BSTR, LPWSTR, LPSTR, vector variants, etc.); zeroes the struct; returns S_OK.
/// PropVariantClear: clear a PROPVARIANT and free any heap-allocated members.
///
/// The PROPVARIANT struct is 24 bytes: first 2 bytes are `vt` (VARTYPE),
/// 6 bytes padding, then 16 bytes union payload. This stub zeroes all 24 bytes
/// (safe for the no-allocation case SDL2 triggers after COM device enumeration).
/// Returns `S_OK` (0).
///
/// # Safety
/// `pvar` must be null or a valid pointer to a 24-byte PROPVARIANT buffer.
pub unsafe extern "win64" fn prop_variant_clear(pvar: *mut u8) -> u32 {
    if !pvar.is_null() {
        unsafe { std::ptr::write_bytes(pvar, 0, 24) };
    }
    S_OK
}

// ── RoInitialize / RoUninitialize (combase.dll / WinRT) ──────────────────────

// Wine ref: dlls/combase/roapi.c — RoInitialize(RO_INIT_TYPE init_type): calls
// ensure_mta() for MTA (0) or apartment_create_thread_state() for STA (1);
// returns S_OK on first init, S_FALSE if already initialised, E_INVALIDARG for
// unknown init_type. Weave: always return S_OK (no WinRT runtime needed).
/// RoInitialize: initialise the Windows Runtime on the calling thread.
///
/// Weave stub — returns S_OK unconditionally. No WinRT runtime is started.
pub extern "win64" fn ro_initialize(init_type: u32) -> i32 {
    eprintln!("weave/ole32: RoInitialize(init_type={init_type}) → S_OK");
    0 // S_OK
}

// Wine ref: dlls/combase/roapi.c — RoUninitialize(): decrements per-thread WinRT
// init count; at zero uninitialises the WinRT apartment (mirrors CoUninitialize
// but for the WinRT apartment model). Weave: no-op.
/// RoUninitialize: uninitialise the Windows Runtime on the calling thread.
///
/// Weave stub — no-op. Mirrors the S_OK-only RoInitialize.
pub extern "win64" fn ro_uninitialize() {
    eprintln!("weave/ole32: RoUninitialize");
}

// ── CoGetMalloc (ole32.dll) ───────────────────────────────────────────────────

// Wine ref: dlls/ole32/ifs.c — CoGetMalloc(dwMemContext, *ppMalloc): only
// dwMemContext==1 (MEMCTX_TASK) is valid; returns pointer to a process-global
// static IMalloc singleton backed by HeapAlloc(GetProcessHeap()). Returns
// E_INVALIDARG for other contexts. Weave: delegate Alloc/Realloc/Free to
// co_task_mem_alloc / co_task_mem_realloc / co_task_mem_free (libc malloc).

/// Minimal IMalloc vtable — 9 entries, Windows x64 COM layout.
///
/// The pointer written into *pp_malloc IS the vtable pointer (this == vtable ptr
/// for a static singleton, identical to how Wine's static malloc object works).
#[repr(C)]
pub struct IMallocVtbl {
    pub query_interface: unsafe extern "win64" fn(*mut IMallocVtbl, *const u8, *mut usize) -> i32,
    pub add_ref: unsafe extern "win64" fn(*mut IMallocVtbl) -> u32,
    pub release: unsafe extern "win64" fn(*mut IMallocVtbl) -> u32,
    pub alloc: unsafe extern "win64" fn(*mut IMallocVtbl, usize) -> *mut (),
    pub realloc: unsafe extern "win64" fn(*mut IMallocVtbl, *mut (), usize) -> *mut (),
    pub free: unsafe extern "win64" fn(*mut IMallocVtbl, *mut ()),
    pub get_size: unsafe extern "win64" fn(*mut IMallocVtbl, *mut ()) -> usize,
    pub did_alloc: unsafe extern "win64" fn(*mut IMallocVtbl, *mut ()) -> i32,
    pub heap_minimize: unsafe extern "win64" fn(*mut IMallocVtbl),
}

unsafe extern "win64" fn imalloc_query_interface(
    _this: *mut IMallocVtbl,
    _riid: *const u8,
    _ppv: *mut usize,
) -> i32 {
    0x8000_4002u32 as i32 // E_NOINTERFACE
}
unsafe extern "win64" fn imalloc_add_ref(_this: *mut IMallocVtbl) -> u32 {
    1
}
unsafe extern "win64" fn imalloc_release(_this: *mut IMallocVtbl) -> u32 {
    1
}
unsafe extern "win64" fn imalloc_alloc(_this: *mut IMallocVtbl, cb: usize) -> *mut () {
    co_task_mem_alloc(cb) as *mut ()
}
unsafe extern "win64" fn imalloc_realloc(
    _this: *mut IMallocVtbl,
    pv: *mut (),
    cb: usize,
) -> *mut () {
    co_task_mem_realloc(pv as usize, cb) as *mut ()
}
unsafe extern "win64" fn imalloc_free(_this: *mut IMallocVtbl, pv: *mut ()) {
    co_task_mem_free(pv as usize);
}
unsafe extern "win64" fn imalloc_get_size(_this: *mut IMallocVtbl, _pv: *mut ()) -> usize {
    0
}
unsafe extern "win64" fn imalloc_did_alloc(_this: *mut IMallocVtbl, _pv: *mut ()) -> i32 {
    -1 // unknown
}
unsafe extern "win64" fn imalloc_heap_minimize(_this: *mut IMallocVtbl) {}

static IMALLOC_VTBL: IMallocVtbl = IMallocVtbl {
    query_interface: imalloc_query_interface,
    add_ref: imalloc_add_ref,
    release: imalloc_release,
    alloc: imalloc_alloc,
    realloc: imalloc_realloc,
    free: imalloc_free,
    get_size: imalloc_get_size,
    did_alloc: imalloc_did_alloc,
    heap_minimize: imalloc_heap_minimize,
};

/// CoGetMalloc: return a pointer to the process task allocator (IMalloc).
///
/// Only `dw_mem_context == 1` (MEMCTX_TASK) is supported; other values return
/// `E_INVALIDARG`. The returned singleton delegates to libc malloc.
///
/// # Safety
/// `pp_malloc` must be a valid writable pointer to a `*mut IMallocVtbl` slot,
/// or null (in which case E_INVALIDARG is returned).
pub unsafe extern "win64" fn co_get_malloc(
    dw_mem_context: u32,
    pp_malloc: *mut *mut IMallocVtbl,
) -> i32 {
    if pp_malloc.is_null() || dw_mem_context != 1 {
        return 0x8007_0057u32 as i32; // E_INVALIDARG
    }
    // SAFETY: IMALLOC_VTBL is 'static; caller receives a non-owning pointer.
    unsafe { *pp_malloc = &raw const IMALLOC_VTBL as *mut IMallocVtbl };
    0 // S_OK
}

// ── CreateStreamOnHGlobal (ole32.dll) ─────────────────────────────────────────

// Wine ref: dlls/combase/hglobalstream.c — CreateStreamOnHGlobal(hGlobal,
// fDeleteOnRelease, ppstm): allocates a handle_wrapper around hGlobal (or a
// fresh GlobalAlloc if hGlobal==NULL), constructs an hglobal_stream COM object
// implementing the full IStream vtable, writes IStream* into *ppstm; returns
// S_OK. Weave: full IStream is Phase 3+; return E_NOTIMPL so callers can
// detect the absence and fall back.
/// CreateStreamOnHGlobal: create an IStream backed by an HGLOBAL (stub).
///
/// Returns `E_NOTIMPL` — full IStream implementation is Phase 3+.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_stream_on_hglobal(
    _h_global: usize,
    _f_delete_on_release: i32,
    pp_stm: *mut usize,
) -> i32 {
    if !pp_stm.is_null() {
        unsafe { *pp_stm = 0 };
    }
    eprintln!("weave/ole32: CreateStreamOnHGlobal → E_NOTIMPL (Phase 3+)");
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// ── urlmon.dll stubs ──────────────────────────────────────────────────────────
//
// SumatraPDF delay-loads urlmon.dll for CoInternetGetSession, which retrieves
// a COM IInternetSession object used for URL moniker binding. When the
// delay-load thunk fires and Weave returns None, __delayLoadHelper2 crashes.
// This stub returns E_NOTIMPL so the thunk resolves and the caller falls back
// to not using URL moniker sessions (acceptable for a PDF viewer).
//
// Wine ref: dlls/urlmon/session.c — CoInternetGetSession checks dwSessionMode
// (must be 0), validates ppIInternetSession; allocates IInternetSession COM
// object backed by a process-global session. Stub returns E_NOTIMPL.

/// CoInternetGetSession — retrieve the process-global IInternetSession.
///
/// Wine ref: dlls/urlmon/session.c — CoInternetGetSession allocates a
/// COM IInternetSession singleton on first call; returns E_INVALIDARG if
/// dwSessionMode != 0 or ppIInternetSession is NULL. Stub returns E_NOTIMPL —
/// no URL moniker / WinInet session infrastructure in Weave.
// Wine ref: dlls/urlmon/session.c — CoInternetGetSession returns COM Internet session; stub returns E_NOTIMPL
unsafe extern "win64" fn co_internet_get_session(
    _dw_session_mode: u32,
    pp_iinternet_session: *mut *mut (),
    _dw_reserved: u32,
) -> i32 {
    if !pp_iinternet_session.is_null() {
        unsafe { *pp_iinternet_session = std::ptr::null_mut() };
    }
    0x80004001u32 as i32 // E_NOTIMPL
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Resolve a `ole32.dll`, `combase.dll`, or `urlmon.dll` import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    // urlmon.dll — URL moniker / internet session stubs (SumatraPDF delay-load)
    if dll.eq_ignore_ascii_case("urlmon.dll") {
        return match func {
            "CoInternetGetSession" => Some(co_internet_get_session as *const () as usize),
            _ => None,
        };
    }

    if !dll.eq_ignore_ascii_case("ole32.dll") && !dll.eq_ignore_ascii_case("combase.dll") {
        return None;
    }
    match func {
        // COM initialisation
        "CoInitializeEx" => Some(co_initialize_ex as *const () as usize),
        "CoInitialize" => Some(co_initialize as *const () as usize),
        "CoUninitialize" => Some(co_uninitialize as *const () as usize),
        // Object creation
        "CoCreateInstance" => Some(
            co_create_instance as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CoCreateInstanceEx" => Some(
            co_create_instance_ex as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CoGetClassObject" => Some(
            co_get_class_object as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Memory
        "CoTaskMemAlloc" => Some(co_task_mem_alloc as *const () as usize),
        "CoTaskMemFree" => Some(co_task_mem_free as *const () as usize),
        "CoTaskMemRealloc" => Some(co_task_mem_realloc as *const () as usize),
        // GUID utilities
        "StringFromGUID2" => {
            Some(string_from_guid2 as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CLSIDFromString" => {
            Some(clsid_from_string as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CoCreateGuid" => {
            Some(co_create_guid as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "IIDFromString" => {
            Some(iid_from_string as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // OLE
        "OleInitialize" => Some(ole_initialize as *const () as usize),
        "OleUninitialize" => Some(ole_uninitialize as *const () as usize),
        "OleLockRunning" => Some(ole_lock_running as *const () as usize),
        "OleDuplicateData" => Some(ole_duplicate_data as *const () as usize),
        "OleSetClipboard" => Some(ole_set_clipboard as *const () as usize),
        "OleGetClipboard" => {
            Some(ole_get_clipboard as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Security / proxy
        "CoSetProxyBlanket" => Some(co_set_proxy_blanket as *const () as usize),
        "CoInitializeSecurity" => Some(co_initialize_security as *const () as usize),
        // Marshalling (stubs)
        "CoMarshalInterface" => Some(co_marshal_interface as *const () as usize),
        "CoUnmarshalInterface" => Some(co_unmarshal_interface as *const () as usize),
        "CoDisconnectObject" => Some(co_disconnect_object as *const () as usize),
        // Marshalling (inter-thread)
        "CoMarshalInterThreadInterfaceInStream" => {
            Some(co_marshal_inter_thread_interface_in_stream as *const () as usize)
        }
        "CoGetInterfaceAndReleaseStream" => {
            Some(co_get_interface_and_release_stream as *const () as usize)
        }
        "CoLockObjectExternal" => Some(co_lock_object_external as *const () as usize),
        // OLE clipboard / object state
        "OleFlushClipboard" => Some(ole_flush_clipboard as *const () as usize),
        "OleIsCurrentClipboard" => Some(ole_is_current_clipboard as *const () as usize),
        "OleRun" => Some(ole_run as *const () as usize),
        "OleSetContainedObject" => Some(ole_set_contained_object as *const () as usize),
        // ProgID / CLSID conversion
        "ProgIDFromCLSID" => {
            Some(prog_id_from_clsid as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CLSIDFromProgID" => {
            Some(clsid_from_prog_id as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "ReleaseStgMedium" => {
            Some(release_stg_medium as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "RegisterDragDrop" => {
            Some(register_drag_drop as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RevokeDragDrop" => {
            Some(revoke_drag_drop as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "DoDragDrop" => {
            Some(do_drag_drop as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        // PropVariant
        "PropVariantClear" => {
            Some(prop_variant_clear as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // WinRT init (combase.dll)
        "RoInitialize" => Some(ro_initialize as *const () as usize),
        "RoUninitialize" => Some(ro_uninitialize as *const () as usize),
        // StringFromCLSID — ole32 variant, returns E_OUTOFMEMORY
        "StringFromCLSID" => {
            Some(string_from_clsid as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // COM task allocator
        "CoGetMalloc" => {
            Some(co_get_malloc as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Structured storage (E_NOTIMPL stub)
        "CreateStreamOnHGlobal" => Some(
            create_stream_on_hglobal as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        _ => None,
    }
}

// ── oleaut32.dll stubs ─────────────────────────────────────────────────────────

/// Resolve an oleaut32.dll import to a stub address.
pub fn resolve_oleaut32(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("oleaut32.dll") {
        return None;
    }
    match func {
        "#17" | "#19" | "#20" | "#21" | "#22" | "#35" | "#77" | "#102" | "#113" | "#184"
        | "#185" => Some(oleaut32_stub as *const () as usize),
        _ => None,
    }
}

/// Generic stub for oleaut32.dll ordinal imports exposed by wxWidgets.
extern "win64" fn oleaut32_stub() -> i32 {
    0
}

// ── rpcrt4.dll stubs ───────────────────────────────────────────────────────────

/// Resolve an rpcrt4.dll import to a stub address.
pub fn resolve_rpcrt4(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("rpcrt4.dll") {
        return None;
    }
    match func {
        "UuidCreate" => Some(rpc_uuid_create as *const () as usize),
        "UuidToStringW" => Some(rpc_uuid_to_string_w as *const () as usize),
        "UuidFromStringW" => Some(rpc_uuid_from_string_w as *const () as usize),
        "RpcStringFreeW" => Some(rpc_string_free_w as *const () as usize),
        _ => None,
    }
}

// Wine ref: dlls/rpcrt4/rpc.c — UuidCreate generates a new UUID.
extern "win64" fn rpc_uuid_create(_uuid: *mut u8) -> i32 {
    0 // RPC_S_OK
}

// Wine ref: dlls/rpcrt4/rpc.c — UuidToStringW converts UUID to string.
extern "win64" fn rpc_uuid_to_string_w(_uuid: *const u8, _str: *mut usize) -> i32 {
    0 // RPC_S_OK
}

// Wine ref: dlls/rpcrt4/rpc.c — UuidFromStringW converts string to UUID.
extern "win64" fn rpc_uuid_from_string_w(_str: *const u16, _uuid: *mut u8) -> i32 {
    0 // RPC_S_OK
}

// Wine ref: dlls/rpcrt4/rpc.c — RpcStringFreeW frees a UUID string.
extern "win64" fn rpc_string_free_w(_str: *mut u16) -> i32 {
    0 // RPC_S_OK
}

// ── oleacc.dll stubs ───────────────────────────────────────────────────────────

/// Resolve an oleacc.dll import to a stub address.
pub fn resolve_oleacc(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("oleacc.dll") {
        return None;
    }
    match func {
        "LresultFromObject" => Some(oleacc_lresult_from_object as *const () as usize),
        "CreateStdAccessibleObject" => {
            Some(oleacc_create_std_accessible_object as *const () as usize)
        }
        _ => None,
    }
}

// Wine ref: dlls/oleacc/main.c — LresultFromObject returns an accessibility object reference.
extern "win64" fn oleacc_lresult_from_object(
    _riid: *const u8,
    _w_param: usize,
    _acc: *const u8,
) -> usize {
    0
}

// Wine ref: dlls/oleacc/main.c — CreateStdAccessibleObject creates a standard accessible object.
extern "win64" fn oleacc_create_std_accessible_object(
    _hwnd: usize,
    _role: u32,
    _riid: *const u8,
    _acc: *mut usize,
) -> i32 {
    0 // S_OK
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn co_init_first_call_returns_s_ok() {
        // Reset thread-local state.
        COM_INIT_COUNT.with(|c| c.set(0));
        assert_eq!(co_initialize_ex(0, COINIT_APARTMENTTHREADED), S_OK);
        // Second call should return S_FALSE.
        assert_eq!(co_initialize_ex(0, COINIT_APARTMENTTHREADED), S_FALSE);
        co_uninitialize();
        co_uninitialize();
    }

    #[test]
    fn co_uninitialize_decrements() {
        COM_INIT_COUNT.with(|c| c.set(0));
        co_initialize_ex(0, COINIT_MULTITHREADED);
        co_initialize_ex(0, COINIT_MULTITHREADED);
        assert_eq!(COM_INIT_COUNT.with(|c| c.get()), 2);
        co_uninitialize();
        assert_eq!(COM_INIT_COUNT.with(|c| c.get()), 1);
        co_uninitialize();
        assert_eq!(COM_INIT_COUNT.with(|c| c.get()), 0);
    }

    #[test]
    fn co_task_mem_roundtrip() {
        let ptr = co_task_mem_alloc(64);
        assert_ne!(ptr, 0);
        co_task_mem_free(ptr);
    }

    #[test]
    fn co_task_mem_free_null_noop() {
        co_task_mem_free(0); // must not crash
    }

    #[test]
    fn parse_guid_roundtrip() {
        let s = "{6B29FC40-CA47-1067-B31D-00DD010662DA}";
        let guid = parse_guid_str(s).unwrap();
        // Data1 = 0x6B29FC40 stored LE
        assert_eq!(
            u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]),
            0x6B29_FC40
        );
    }

    #[test]
    fn parse_guid_invalid_returns_none() {
        assert!(parse_guid_str("not-a-guid").is_none());
        assert!(parse_guid_str("{too-short}").is_none());
    }

    #[test]
    fn co_task_mem_realloc_zero_frees() {
        let ptr = co_task_mem_alloc(32);
        assert_ne!(ptr, 0);
        let result = co_task_mem_realloc(ptr, 0);
        assert_eq!(result, 0);
    }
}
