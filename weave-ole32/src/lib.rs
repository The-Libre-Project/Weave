//! ole32.dll / combase.dll stubs for Weave.
#![allow(clippy::missing_safety_doc)]
//!
//! # Phase 3 scope
//!
//! Implements the core COM infrastructure needed for class factory registration
//! and object creation.
//!
//! ## What is implemented
//!
//! - `CoInitializeEx` / `CoInitialize` / `CoUninitialize` — thread-local
//!   COM initialisation state. Returns S_OK or S_FALSE (already initialised).
//! - `CoCreateInstance` — creates an instance of a COM class via in-memory
//!   registered factories or registry-backed DLL lookup.
//! - `CoRegisterClassObject` / `CoRevokeClassObject` — in-memory class factory
//!   registration with cookie-based revocation and proper AddRef/Release.
//! - `CoGetClassObject` — finds a class factory for a CLSID.
//! - `CoTaskMemAlloc` / `CoTaskMemFree` / `CoTaskMemRealloc` — libc malloc.
//! - `StringFromGUID2` — formats a GUID as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
//! - `CLSIDFromString` / `IIDFromString` — parse a GUID string.
//! - `CoSetProxyBlanket` — no-op security blanket (stub).
//! - `OleInitialize` / `OleUninitialize` — delegate to Co* variants.
//! - `CoGetMalloc` — process task allocator (IMalloc singleton).
//! - `CreateStreamOnHGlobal` / `GetHGlobalFromStream` — an IStream over an
//!   HGLOBAL (full 14-slot vtable: Read/Write/Seek/SetSize/CopyTo/Commit/
//!   Revert/LockRegion/UnlockRegion/Stat/Clone).
//!
//! ## What is NOT implemented
//!
//! Marshalling, proxy/stub infrastructure, apartment threading, ROT,
//! moniker binding, structured storage (IStorage/compound files), etc.
//! These are Phase 4+ concerns.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::{Mutex, OnceLock};

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
const E_OUTOFMEMORY: u32 = 0x8007_000E;
const REGDB_E_CLASSNOTREG: u32 = 0x8004_0154;
const CO_E_NOTINITIALIZED: u32 = 0x8004_001E;
const E_NOTIMPL: u32 = 0x8000_4001;
const E_NOINTERFACE: u32 = 0x8000_4002;
const REGDB_E_IIDNOTREG: u32 = 0x8004_0164;
const RPC_E_CALL_REJECTED: u32 = 0x8001_0001;

// COINIT flags
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const COINIT_MULTITHREADED: u32 = 0x0;

const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;

// APTTYPE values for CoGetApartmentType
const APTTYPE_STA: i32 = 0;
const APTTYPE_MTA: i32 = 1;

// APTTYPEQUALIFIER values
const APTTYPEQUALIFIER_NONE: i32 = 0;

// ── Proxy/Stub CLSID Registry (PSClsid) ───────────────────────────────────────

static PS_CLSID_TABLE: OnceLock<Mutex<HashMap<[u8; 16], [u8; 16]>>> = OnceLock::new();

fn psclsid_table() -> &'static Mutex<HashMap<[u8; 16], [u8; 16]>> {
    PS_CLSID_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

// Wine ref: dlls/combase/marshal.c — CoRegisterPSClsid stores IID→CLSID mapping
// in an internal per-proc hash table; returns S_OK, E_INVALIDARG for null ptrs.
/// CoRegisterPSClsid: register a proxy/stub CLSID for an interface IID.
///
/// # Safety
/// `rclsid` and `riid` must be valid 16-byte GUID pointers.
pub unsafe extern "win64" fn co_register_ps_clsid(rclsid: *const u8, riid: *const u8) -> u32 {
    let clsid = match unsafe { read_guid(rclsid) } {
        Some(g) => g,
        None => return E_INVALIDARG,
    };
    let iid = match unsafe { read_guid(riid) } {
        Some(g) => g,
        None => return E_INVALIDARG,
    };
    let mut table = psclsid_table().lock().unwrap();
    table.insert(iid, clsid);
    eprintln!(
        "weave/ole32: CoRegisterPSClsid: IID {:02x?} → CLSID {:02x?}",
        iid, clsid
    );
    S_OK
}

// Wine ref: dlls/combase/marshal.c — CoGetPSClsid looks up IID in hash table;
// returns S_OK + CLSID via pClsid, or REGDB_E_IIDNOTREG if not found.
/// CoGetPSClsid: look up the proxy/stub CLSID for an interface IID.
///
/// # Safety
/// `riid` must be a valid 16-byte IID pointer.
/// `p_clsid` must be a valid writable 16-byte buffer.
pub unsafe extern "win64" fn co_get_ps_clsid(riid: *const u8, p_clsid: *mut u8) -> u32 {
    let iid = match unsafe { read_guid(riid) } {
        Some(g) => g,
        None => return E_INVALIDARG,
    };
    if p_clsid.is_null() {
        return E_INVALIDARG;
    }
    let table = psclsid_table().lock().unwrap();
    match table.get(&iid) {
        Some(clsid) => {
            unsafe { std::ptr::copy_nonoverlapping(clsid.as_ptr(), p_clsid, 16) };
            S_OK
        }
        None => REGDB_E_IIDNOTREG,
    }
}

// ── Per-thread COM state ──────────────────────────────────────────────────────

thread_local! {
    /// Nesting depth of CoInitialize[Ex] calls on this thread.
    static COM_INIT_COUNT: Cell<u32> = const { Cell::new(0) };
    /// COINIT flags used on first init (APARTMENTTHREADED or MULTITHREADED).
    static COM_INIT_FLAGS: Cell<u32> = const { Cell::new(0) };
}

// ── CLSCTX and REGCLS constants ──────────────────────────────────────────────

const CLSCTX_INPROC_SERVER: u32 = 1;

// ── COM helper functions for opaque vtable dispatch ──────────────────────────

/// Read the vtable pointer from a COM object (first field of any COM struct).
unsafe fn com_vtable(unk: *mut ()) -> *const usize {
    *(unk as *const *const usize)
}

/// Call IUnknown::AddRef (vtable slot 1) on any COM object pointer.
unsafe fn com_add_ref(unk: *mut ()) -> u32 {
    let vtbl = com_vtable(unk);
    let add_ref: unsafe extern "win64" fn(*mut ()) -> u32 = std::mem::transmute(*vtbl.add(1));
    add_ref(unk)
}

/// Call IUnknown::Release (vtable slot 2) on any COM object pointer.
unsafe fn com_release(unk: *mut ()) -> u32 {
    let vtbl = com_vtable(unk);
    let release: unsafe extern "win64" fn(*mut ()) -> u32 = std::mem::transmute(*vtbl.add(2));
    release(unk)
}

/// Call IClassFactory::CreateInstance (vtable slot 3) on an IClassFactory pointer.
unsafe fn factory_create_instance(
    factory: *mut (),
    outer: *mut (),
    riid: *const u8,
    ppv: *mut *mut (),
) -> u32 {
    let vtbl = com_vtable(factory);
    let create: unsafe extern "win64" fn(*mut (), *mut (), *const u8, *mut *mut ()) -> u32 =
        std::mem::transmute(*vtbl.add(3));
    create(factory, outer, riid, ppv)
}

// ── In-memory class factory registry (CoRegisterClassObject) ──────────────────

struct RegisteredFactory {
    cookie: u32,
    clsid: [u8; 16],
    factory_ptr: *mut (), // IClassFactory* COM pointer (owned ref)
    #[allow(dead_code)]
    dw_cls_context: u32,
    _flags: u32,
}

// SAFETY: factory_ptr is accessed only through the Mutex, making it thread-safe.
unsafe impl Send for RegisteredFactory {}
unsafe impl Sync for RegisteredFactory {}

static FACTORY_REGISTRY: OnceLock<Mutex<Vec<RegisteredFactory>>> = OnceLock::new();
static NEXT_COOKIE: AtomicU32 = AtomicU32::new(1);

fn factory_table() -> &'static Mutex<Vec<RegisteredFactory>> {
    FACTORY_REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// Look up a CLSID in the registered-factory table and call CreateInstance.
/// Returns `Some(HRESULT)` if found, `None` if no match.
unsafe fn resolve_from_factory_table(
    clsid: &[u8; 16],
    p_unk_outer: usize,
    riid: *const u8,
    ppv: *mut usize,
) -> Option<u32> {
    let table = factory_table().lock().unwrap();
    for entry in table.iter() {
        if entry.clsid == *clsid {
            let mut obj: *mut () = std::ptr::null_mut();
            let hr = unsafe {
                factory_create_instance(entry.factory_ptr, p_unk_outer as *mut (), riid, &mut obj)
            };
            if hr == 0 {
                unsafe { *ppv = obj as usize };
            }
            return Some(hr);
        }
    }
    None
}

// ── Registry-based CLSID→DLL lookup ──────────────────────────────────────────

// Wine ref: dlls/combase/combase.c — com_get_class_object() searches
// HKCR\CLSID\{clsid}\InprocServer32\(default) for the DLL path.
/// Look up the InprocServer32 DLL path for a CLSID in Weave's file-backed registry.
fn find_clsid_dll(clsid: &[u8; 16]) -> Option<String> {
    let hkcr = weave_core::registry::predefined_hive_path(weave_core::registry::HKEY_CLASSES_ROOT)?;

    let d1 = u32::from_le_bytes([clsid[0], clsid[1], clsid[2], clsid[3]]);
    let d2 = u16::from_le_bytes([clsid[4], clsid[5]]);
    let d3 = u16::from_le_bytes([clsid[6], clsid[7]]);
    let clsid_str = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1,
        d2,
        d3,
        clsid[8],
        clsid[9],
        clsid[10],
        clsid[11],
        clsid[12],
        clsid[13],
        clsid[14],
        clsid[15],
    );

    let subkey = format!(r"CLSID\{clsid_str}\InprocServer32");
    let key_dir = weave_core::registry::resolve_subkey(&hkcr, &subkey)?;
    let value_path = weave_core::registry::find_value_file(&key_dir, "")?;
    let (reg_type, data) = weave_core::registry::read_value_file(&value_path)?;

    if reg_type != weave_core::registry::REG_SZ {
        return None;
    }
    if data.len() < 2 || data.len() % 2 != 0 {
        return None;
    }

    let wide: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16(&wide).ok()
}

// Wine ref: dlls/combase/combase.c — load_dll() LoadLibraryW + GetProcAddress("DllGetClassObject"),
// then calls DllGetClassObject(clsid, IID_IClassFactory, ppv).
/// Load a COM DLL and call its DllGetClassObject to get an IClassFactory pointer.
/// Returns the HRESULT from DllGetClassObject, or None if the DLL was not found/resolved.
unsafe fn resolve_from_registry_dll(
    clsid: &[u8; 16],
    p_unk_outer: usize,
    riid: *const u8,
    ppv: *mut usize,
) -> Option<u32> {
    let dll_path = find_clsid_dll(clsid)?;

    let dll_name = std::path::Path::new(&dll_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&dll_path);

    // The DLL must have its DllGetClassObject registered in Weave's resolver.
    let func_ptr = weave_core::resolve::resolve(dll_name, "DllGetClassObject")?;

    // IID_IClassFactory wire bytes (little-endian): {00000001-0000-0000-C000-000000000046}
    let iid_class_factory: [u8; 16] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];

    let dll_get_class_object: unsafe extern "win64" fn(*const u8, *const u8, *mut *mut ()) -> u32 =
        unsafe { std::mem::transmute(func_ptr) };

    let mut factory: *mut () = std::ptr::null_mut();
    let hr =
        unsafe { dll_get_class_object(clsid.as_ptr(), iid_class_factory.as_ptr(), &mut factory) };

    if hr == 0 && !factory.is_null() {
        // Got an IClassFactory — call CreateInstance on it
        let mut obj: *mut () = std::ptr::null_mut();
        let hr2 =
            unsafe { factory_create_instance(factory, p_unk_outer as *mut (), riid, &mut obj) };
        unsafe { com_release(factory) };
        if hr2 == 0 {
            unsafe { *ppv = obj as usize };
        }
        return Some(hr2);
    }

    None
}

// ── CoRegisterClassObject / CoRevokeClassObject ──────────────────────────────

// Wine ref: dlls/combase/compobj.c — CoRegisterClassObject inserts factory into
// an internal per-CLSID table; returns a unique cookie via lpdwRegister.
/// CoRegisterClassObject: register a class factory for a CLSID.
///
/// Returns S_OK and writes a registration cookie into `lpdw_register`.
/// The cookie can be used with `CoRevokeClassObject` to remove the registration.
/// The factory pointer is AddRef'd on registration and Release'd on revocation.
///
/// # Safety
/// `rclsid` must be a valid 16-byte CLSID pointer.
/// `p_unk` must be a valid IClassFactory (or IUnknown implementing IClassFactory).
/// `lpdw_register` must be a valid writable u32 pointer.
// Wine ref: dlls/combase/compobj.c — inserts factory into per-CLSID table; returns unique cookie.
pub unsafe extern "win64" fn co_register_class_object(
    rclsid: *const u8,
    p_unk: *mut (),
    dw_cls_context: u32,
    _flags: u32,
    lpdw_register: *mut u32,
) -> u32 {
    if lpdw_register.is_null() {
        return E_INVALIDARG;
    }
    unsafe { *lpdw_register = 0 };

    let clsid = match unsafe { read_guid(rclsid) } {
        Some(g) => g,
        None => return E_INVALIDARG,
    };

    if p_unk.is_null() {
        return E_INVALIDARG;
    }

    unsafe { com_add_ref(p_unk) };

    let cookie = NEXT_COOKIE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let mut table = factory_table().lock().unwrap();
    table.push(RegisteredFactory {
        cookie,
        clsid,
        factory_ptr: p_unk,
        dw_cls_context,
        _flags: 0,
    });

    unsafe { *lpdw_register = cookie };
    S_OK
}

// Wine ref: dlls/combase/compobj.c — CoRevokeClassObject finds the registration
// matching the cookie, removes it, and releases the factory. Returns S_OK if found.
/// CoRevokeClassObject: revoke a class factory registration.
///
/// The factory's Release is called when the registration is removed.
/// Returns S_OK on success, E_INVALIDARG if the cookie is unknown.
// Wine ref: dlls/combase/compobj.c — removes registration + releases factory; S_OK on success.
pub unsafe extern "win64" fn co_revoke_class_object(dw_register: u32) -> u32 {
    let mut table = factory_table().lock().unwrap();
    let pos = table.iter().position(|r| r.cookie == dw_register);
    match pos {
        Some(idx) => {
            let entry = table.swap_remove(idx);
            unsafe { com_release(entry.factory_ptr) };
            S_OK
        }
        None => E_INVALIDARG,
    }
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
                return RPC_E_CHANGED_MODE;
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
/// When the count reaches zero the thread's apartment state is cleared.
// Wine ref: dlls/combase/combase.c — per-thread refcount; at zero: uninit apartment + free TLS.
pub extern "win64" fn co_uninitialize() {
    COM_INIT_COUNT.with(|c| {
        let count = c.get();
        if count > 0 {
            c.set(count - 1);
            if count == 1 {
                COM_INIT_FLAGS.with(|f| f.set(u32::MAX));
            }
        }
    });
}

// Wine ref: dlls/combase/apartment.c — reads apartment type from per-thread state;
// returns APTTYPE_STA or APTTYPE_MTA via pAptType, APTTYPEQUALIFIER_NONE via
// pAptQualifier; CO_E_NOTINITIALIZED if no apartment on this thread.
/// CoGetApartmentType: retrieve the COM apartment type for the calling thread.
///
/// Returns S_OK and writes APTTYPE/APTTYPEQUALIFIER on success, or
/// CO_E_NOTINITIALIZED if COM is not initialized on this thread.
///
/// # Safety
/// `p_apt_type` and `p_apt_qualifier` must be valid writable i32 pointers.
// Wine ref: dlls/combase/apartment.c — reads per-thread state; CO_E_NOTINITIALIZED if no apt.
pub unsafe extern "win64" fn co_get_apartment_type(
    p_apt_type: *mut i32,
    p_apt_qualifier: *mut i32,
) -> u32 {
    if p_apt_type.is_null() || p_apt_qualifier.is_null() {
        return E_INVALIDARG;
    }
    COM_INIT_COUNT.with(|c| {
        if c.get() == 0 {
            return CO_E_NOTINITIALIZED;
        }
        let apt_type = COM_INIT_FLAGS.with(|f| {
            if f.get() == COINIT_MULTITHREADED {
                APTTYPE_MTA
            } else {
                APTTYPE_STA
            }
        });
        unsafe {
            *p_apt_type = apt_type;
            *p_apt_qualifier = APTTYPEQUALIFIER_NONE;
        }
        S_OK
    })
}

// Wine ref: dlls/combase/compobj.c — returns a unique per-process identifier
// (GetCurrentProcessId on Windows). We use the OS PID for uniqueness.
/// CoGetCurrentProcess: return a unique identifier for the current process.
///
/// Used by COM internally for OXID resolution. Returns the process ID.
pub extern "win64" fn co_get_current_process() -> u32 {
    unsafe { libc::getpid() as u32 }
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
/// Resolution order:
///   1. In-memory registered factories (CoRegisterClassObject)
///   2. Well-known CLSIDs (ShellLink, SumatraPDF test hook)
///   3. Registry-based DLL lookup (HKCR\CLSID\{clsid}\InprocServer32)
///   4. REGDB_E_CLASSNOTREG if not found anywhere
///
/// # Safety
/// `rclsid` and `riid` must be valid pointers to 16-byte GUID structs.
/// `ppv` must be a valid writable pointer to a `*mut c_void` output slot.
// Wine ref: dlls/combase/combase.c:1725 — wraps CoCreateInstanceEx; E_POINTER if obj null.
pub unsafe extern "win64" fn co_create_instance(
    rclsid: *const u8,
    p_unk_outer: usize,
    dw_cls_context: u32,
    riid: *const u8,
    ppv: *mut usize,
) -> u32 {
    if !ppv.is_null() {
        unsafe { *ppv = 0 };
    }

    let clsid = match unsafe { read_guid(rclsid) } {
        Some(g) => g,
        None => return E_INVALIDARG,
    };

    // 1. Check in-memory registered factories first.
    if let Some(hr) = unsafe { resolve_from_factory_table(&clsid, p_unk_outer, riid, ppv) } {
        eprintln!(
            "weave/ole32: CoCreateInstance: CLSID {:02x?} → registered factory (hr={hr:#010x})",
            clsid
        );
        if hr == S_OK {
            log_cross_apartment_diagnostic();
        }
        return hr;
    }

    // 2. CLSID_ShellLink — dispatch to weave-common IShellLink foundation.
    if clsid == CLSID_SHELL_LINK {
        eprintln!("weave/ole32: CoCreateInstance: CLSID_ShellLink → create_shell_link");
        let ppv_ptr = ppv as *mut *mut ();
        return unsafe { create_shell_link(rclsid, riid, ppv_ptr) };
    }

    // 3. SumatraPDF DDE test hook (CI-only).
    if clsid == CLSID_SUMATRA_DDE_SERVER
        && std::env::var("WEAVE_TEST_SUMATRA_CLSID").as_deref() == Ok("1")
    {
        eprintln!("weave/ole32: CoCreateInstance: CLSID_Sumatra_DDE → TEST HOOK: returning S_OK");
        if !ppv.is_null() {
            unsafe { *ppv = get_dde_sentinel_ptr() };
        }
        return S_OK;
    }

    // 4. Try registry-based DLL lookup for INPROC_SERVER context.
    if dw_cls_context & CLSCTX_INPROC_SERVER != 0 {
        if let Some(hr) = unsafe { resolve_from_registry_dll(&clsid, p_unk_outer, riid, ppv) } {
            eprintln!(
                "weave/ole32: CoCreateInstance: CLSID {:02x?} → registry DLL (hr={hr:#010x})",
                clsid
            );
            if hr == S_OK {
                log_cross_apartment_diagnostic();
            }
            return hr;
        }
    }

    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    eprintln!(
        "weave/ole32: CoCreateInstance: tid={tid} CLSID {:02x?} (not found — REGDB_E_CLASSNOTREG)",
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

fn generate_uuid_v4() -> [u8; 16] {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let pid = unsafe { libc::getpid() as u64 };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u64 };
    let seed = now.as_nanos() as u64 ^ pid ^ tid;

    let mut state = seed;
    let mut buf = [0u8; 16];
    for b in buf.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (state >> 32) as u8;
    }
    buf[6] = (buf[6] & 0x0F) | 0x40;
    buf[8] = (buf[8] & 0x3F) | 0x80;
    buf
}

/// CoCreateGuid: create a new globally unique identifier (GUID).
/// Generates a random UUID v4.
///
/// # Safety
/// `pguid` must be a valid writable 16-byte buffer.
pub unsafe extern "win64" fn co_create_guid(pguid: *mut u8) -> u32 {
    if pguid.is_null() {
        return 0x8007_0057; // E_INVALIDARG
    }
    let guid = generate_uuid_v4();
    unsafe { std::ptr::copy_nonoverlapping(guid.as_ptr(), pguid, 16) };
    S_OK
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

// TODO(shim): Phase A — message filter needed by OpenMPT
// Wine ref: dlls/ole32/ole32.spec — CoRegisterMessageFilter registers/replaces
// the message filter for COM. Weave: stub returning S_OK.
pub unsafe extern "win64" fn co_register_message_filter(
    _lp_message_filter: usize,
    _lpl_prev_filter: *mut usize,
) -> i32 {
    0 // S_OK
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
// to stream; increments stub refcount; E_NOTIMPL in Phase A.
/// CoMarshalInterface: marshal an interface pointer into a stream (Phase A stub).
pub extern "win64" fn co_marshal_interface(
    _p_stm: usize,
    _riid: usize,
    _punk: usize,
    _dw_dest_context: u32,
    _pv_dest_context: usize,
    _mshlflags: u32,
) -> u32 {
    E_NOTIMPL
}

// Wine ref: dlls/combase/marshal.c — reads OBJREF header from stream; calls get_unmarshaler_from_stream()
// to create proxy; E_NOTIMPL in Phase A.
/// CoUnmarshalInterface: unmarshal an interface pointer from a stream (Phase A stub).
pub extern "win64" fn co_unmarshal_interface(_p_stm: usize, _riid: usize, _ppv: usize) -> u32 {
    E_NOTIMPL
}

// Wine ref: dlls/combase/marshal.c — CoMarshalHresult writes HRESULT as 4
// bytes via IStream::Write; returns S_OK or the stream's error.
/// CoMarshalHresult: marshal an HRESULT into a stream.
///
/// # Safety
/// `p_stm` must be a valid IStream pointer (vtable slot 4 = Write).
pub unsafe extern "win64" fn co_marshal_hresult(p_stm: usize, hresult: u32) -> u32 {
    if p_stm == 0 {
        return E_INVALIDARG;
    }
    let stm = p_stm as *mut ();
    let vtbl = *(stm as *const *const usize);
    let write: unsafe extern "win64" fn(*mut (), *const u8, u32, *mut u32) -> u32 =
        std::mem::transmute(*vtbl.add(4));
    let bytes = hresult.to_le_bytes();
    write(stm, bytes.as_ptr(), 4, std::ptr::null_mut())
}

// Wine ref: dlls/combase/marshal.c — CoUnmarshalHresult reads 4 bytes via
// IStream::Read and returns the value; returns S_OK or the stream's error.
/// CoUnmarshalHresult: unmarshal an HRESULT from a stream.
///
/// # Safety
/// `p_stm` must be a valid IStream pointer (vtable slot 3 = Read).
/// `phresult` must be a valid writable u32 pointer.
pub unsafe extern "win64" fn co_unmarshal_hresult(p_stm: usize, phresult: *mut u32) -> u32 {
    if p_stm == 0 || phresult.is_null() {
        return E_INVALIDARG;
    }
    let stm = p_stm as *mut ();
    let vtbl = *(stm as *const *const usize);
    let read: unsafe extern "win64" fn(*mut (), *mut u8, u32, *mut u32) -> u32 =
        std::mem::transmute(*vtbl.add(3));
    let mut buf = [0u8; 4];
    let hr = read(stm, buf.as_mut_ptr(), 4, std::ptr::null_mut());
    if hr == S_OK {
        unsafe { *phresult = u32::from_le_bytes(buf) };
    }
    hr
}

// Wine ref: dlls/combase/marshal.c — CoGetStandardMarshal QIs object for IMarshal
// and returns the standard marshaler; E_NOTIMPL in Phase A.
/// CoGetStandardMarshal: return the standard marshaler for an interface (stub).
///
/// # Safety
/// `ppv` must be a valid writable pointer.
pub unsafe extern "win64" fn co_get_standard_marshal(
    _riid: usize,
    _punk: usize,
    _dw_dest_context: u32,
    _pv_dest_context: usize,
    _mshlflags: u32,
    ppv: *mut usize,
) -> u32 {
    if !ppv.is_null() {
        unsafe { *ppv = 0 };
    }
    E_NOTIMPL
}

/// Log a diagnostic when a cross-apartment COM call is detected.
/// Phase A — logs instead of crashing; returns RPC_E_CALL_REJECTED.
fn log_cross_apartment_diagnostic() {
    let caller_apt = COM_INIT_FLAGS.with(|f| {
        if f.get() == COINIT_MULTITHREADED {
            "MTA"
        } else {
            "STA"
        }
    });
    eprintln!(
        "weave/ole32: cross-apartment COM call (apartment type {caller_apt} → ?) not supported — returning RPC_E_CALL_REJECTED ({:#010x})",
        RPC_E_CALL_REJECTED
    );
}

/// CoMarshalInterThreadInterfaceInStream: marshal an interface pointer into a stream
/// that can be unmarshalled in a different apartment.
/// Phase A stub — returns E_NOTIMPL.
// Wine ref: dlls/ole32/marshal.c — creates a stream and marshals the interface
// into it via CoMarshalInterface; we return E_NOTIMPL for now.
pub unsafe extern "win64" fn co_marshal_inter_thread_interface_in_stream(
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
pub unsafe extern "win64" fn co_get_interface_and_release_stream(
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

// Wine ref: dlls/ole32/ifs.c — StringFromCLSID calls StringFromGUID2 into a
// CoTaskMemAlloc'd buffer; caller must free with CoTaskMemFree.
/// StringFromCLSID — convert a CLSID to a string (ole32 version).
///
/// Allocates the output string with `CoTaskMemAlloc`; the caller must free
/// with `CoTaskMemFree`. Returns `S_OK` on success, `E_OUTOFMEMORY` if
/// allocation fails, `E_INVALIDARG` if either pointer is null.
///
/// # Safety
/// `rclsid` must be a valid pointer to a 16-byte GUID.
/// `lpsz` must be a valid writable pointer to a `*mut u16` output slot.
// Wine ref: dlls/ole32/ifs.c — StringFromGUID2 into CoTaskMemAlloc buffer.
pub unsafe extern "win64" fn string_from_clsid(rclsid: *const u8, lpsz: *mut *mut u16) -> u32 {
    if rclsid.is_null() || lpsz.is_null() {
        return E_INVALIDARG;
    }
    unsafe { *lpsz = std::ptr::null_mut() };

    let guid = unsafe { std::slice::from_raw_parts(rclsid, 16) };
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    let s = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15],
    );

    // Allocate buffer: UTF-16 chars + NUL terminator (2 bytes each).
    let buf_size = (s.len() + 1) * 2;
    let buf = co_task_mem_alloc(buf_size);
    if buf == 0 {
        return 0x8007000E; // E_OUTOFMEMORY
    }

    let buf_ptr = buf as *mut u16;
    for (i, ch) in s.encode_utf16().enumerate() {
        unsafe { *buf_ptr.add(i) = ch };
    }
    unsafe { *buf_ptr.add(s.len()) = 0 };
    unsafe { *lpsz = buf_ptr };
    S_OK
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

// ── CreateStreamOnHGlobal / GetHGlobalFromStream (ole32.dll) ─────────────────

// Wine ref: dlls/combase/hglobalstream.c — hglobal_stream implements the full
// IStream vtable (14 methods) over a refcounted handle_wrapper that owns the
// HGLOBAL. handle_wrapper refcount is shared across Clone'd streams; the
// HGLOBAL is GlobalFree'd when the last wrapper ref drops and delete_on_release
// is set. Behavioral contract from dlls/ole32/tests/hglobalstream.c:
//   - Read past EOF returns S_OK with *pcbRead == 0 (never S_FALSE)
//   - Seek uses only the low 32 bits of dlibMove (HighPart ignored), treats it
//     as a signed i32, and returns STG_E_SEEKERROR (0x80030019) when the target
//     would land before 0 or past 0xFFFFFFFF (win8 no-wrap behavior). The
//     stream position is unchanged on error, but *plibNewPosition is still set.
//   - SetSize uses only the low 32 bits of libNewSize
//   - LockRegion → STG_E_INVALIDFUNCTION; Commit/Revert/UnlockRegion → S_OK
//   - Clone shares the handle (handle_addref) and copies the stream position
//   - Stat zeroes the full STATSTG; type = STGTY_STREAM; cbSize = size;
//     pwcsName/clsid stay NULL / GUID_NULL
//   - CreateStreamOnHGlobal returns E_INVALIDARG when ppstm is NULL
//   - GetHGlobalFromStream returns E_INVALIDARG unless the stream was created
//     by CreateStreamOnHGlobal (vtable identity check)
//
// Weave Phase 2 note: HGLOBAL == raw heap pointer (see weave-kernel32
// global_alloc — handle == pointer, GlobalLock is identity, GlobalUnlock is a
// no-op), so the stream operates on the pointer directly and grows the block
// with libc::realloc. Caller-supplied handles are libc-malloc'd (they come
// from GlobalAlloc); malloc_usable_size mirrors Weave's GlobalSize.

// IID_IStream = {0000000C-0000-0000-C000-000000000046}
const IID_ISTREAM: [u8; 16] = [0x0C, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
// IID_ISequentialStream = {0C733A30-2A1C-11CE-ADE5-00AA0044773D}
const IID_ISEQUENTIALSTREAM: [u8; 16] = [
    0x30, 0x3A, 0x73, 0x0C, 0x1C, 0x2A, 0xCE, 0x11, 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D,
];
// IID_IUnknown = {00000000-0000-0000-C000-000000000046}
const IID_IUNKNOWN_BYTES: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];

// STG_E_* storage errors (winerror.h, FACILITY_STORAGE 0x8003_xxxx)
const STG_E_SEEKERROR: u32 = 0x8003_0019;
const STG_E_INVALIDFUNCTION: u32 = 0x8003_0001;
const STG_E_INVALIDPOINTER: u32 = 0x8003_0009;

const STGTY_STREAM: u32 = 2;
const STREAM_SEEK_SET: u32 = 0;
const STREAM_SEEK_CUR: u32 = 1;
const STREAM_SEEK_END: u32 = 2;

// STATSTG win64 layout: pwcsName(0,8) type(8,4) pad(12,4) cbSize(16,8)
// mtime(24,8) ctime(32,8) atime(40,8) grfMode(48,4) grfLocksSupported(52,4)
// clsid(56,16) grfStateBits(72,4) reserved(76,4) → 80 bytes total.
const STATSTG_SIZE: usize = 80;
const STATSTG_TYPE_OFFSET: usize = 8;
const STATSTG_CBSIZE_OFFSET: usize = 16;

/// IStream vtable — 14 methods after IUnknown's 3 (17 slots total).
///
/// Slot indices 3..=16 mirror the Windows `IStreamVtbl` order, which
/// `co_marshal_hresult` / `co_unmarshal_hresult` rely on (Read=3, Write=4).
#[repr(C)]
struct IStreamVtbl {
    query_interface: unsafe extern "win64" fn(*mut HGlobalStream, *const u8, *mut *mut ()) -> u32,
    add_ref: unsafe extern "win64" fn(*mut HGlobalStream) -> u32,
    release: unsafe extern "win64" fn(*mut HGlobalStream) -> u32,
    read: unsafe extern "win64" fn(*mut HGlobalStream, *mut u8, u32, *mut u32) -> u32,
    write: unsafe extern "win64" fn(*mut HGlobalStream, *const u8, u32, *mut u32) -> u32,
    seek: unsafe extern "win64" fn(*mut HGlobalStream, i64, u32, *mut u64) -> u32,
    set_size: unsafe extern "win64" fn(*mut HGlobalStream, u64) -> u32,
    copy_to: unsafe extern "win64" fn(*mut HGlobalStream, *mut (), u64, *mut u64, *mut u64) -> u32,
    commit: unsafe extern "win64" fn(*mut HGlobalStream, u32) -> u32,
    revert: unsafe extern "win64" fn(*mut HGlobalStream) -> u32,
    lock_region: unsafe extern "win64" fn(*mut HGlobalStream, u64, u64, u32) -> u32,
    unlock_region: unsafe extern "win64" fn(*mut HGlobalStream, u64, u64, u32) -> u32,
    stat: unsafe extern "win64" fn(*mut HGlobalStream, *mut u8, u32) -> u32,
    clone: unsafe extern "win64" fn(*mut HGlobalStream, *mut *mut ()) -> u32,
}

/// Refcounted owner of the HGLOBAL, shared across Clone'd streams.
///
/// The HGLOBAL (Phase 2: a libc-malloc'd pointer) is freed when the refcount
/// drops to zero *and* delete_on_release was set at creation. `size` is the
/// logical stream size (Wine's handle->size), always ≤ u32::MAX.
#[repr(C)]
struct HandleWrapper {
    ref_count: u32,
    hglobal: usize,
    size: u64,
    delete_on_release: bool,
}

/// The hglobal_stream COM object: an IStream backed by a shared HandleWrapper.
#[repr(C)]
struct HGlobalStream {
    vtable: *const IStreamVtbl,
    ref_count: u32,
    handle: *mut HandleWrapper,
    position: u64,
}

// SAFETY: ref_count and position are only mutated under the single-threaded
// process model the rest of this crate's COM objects assume (IUnknownImpl/
// IClassFactoryImpl in weave-common use the same plain-u32 pattern). The
// vtable is a 'static immutable.
unsafe impl Send for HandleWrapper {}
unsafe impl Sync for HandleWrapper {}
unsafe impl Send for HGlobalStream {}
unsafe impl Sync for HGlobalStream {}

unsafe fn handle_addref(handle: *mut HandleWrapper) {
    // SAFETY: handle is a valid HandleWrapper* from Box::into_raw, held alive
    // by the caller (stream construction or Clone) for the duration of this
    // call; ref_count < u32::MAX in practice.
    unsafe { (*handle).ref_count += 1 };
}

/// Drop one reference to the shared HGLOBAL wrapper. Frees the HGLOBAL when
/// the last ref drops and delete_on_release is set.
unsafe fn handle_release(handle: *mut HandleWrapper) {
    // SAFETY: handle is valid and every handle_release is balanced by a
    // handle_addref / initial ref of 1, so ref_count ≥ 1 here.
    let prev = unsafe { (*handle).ref_count };
    let new = prev - 1;
    if new == 0 {
        // SAFETY: fields are read before the wrapper is reclaimed below.
        let hg = unsafe { (*handle).hglobal };
        let delete = unsafe { (*handle).delete_on_release };
        if delete {
            // SAFETY: hg is a Phase 2 HGLOBAL (libc-malloc'd pointer) and this
            // wrapper is its sole owner; no other reference survives.
            unsafe { libc::free(hg as *mut libc::c_void) };
        }
        // SAFETY: handle was Box::into_raw'd in handle_create; refcount 0
        // means no other references remain, so reclaiming the Box is sound.
        unsafe { drop(Box::from_raw(handle)) };
    } else {
        // SAFETY: ref_count > 0, so the wrapper stays alive.
        unsafe { (*handle).ref_count = new };
    }
}

/// Create a refcounted wrapper around `hglobal`, or around a fresh block when
/// `hglobal` is 0. Returns NULL on allocation failure.
unsafe fn handle_create(hglobal: usize, delete_on_release: bool) -> *mut HandleWrapper {
    let hg = if hglobal != 0 {
        hglobal
    } else {
        // Wine ref: dlls/combase/hglobalstream.c handle_create — allocates
        // GlobalAlloc(GMEM_MOVEABLE|GMEM_NODISCARD|GMEM_SHARE, 0) when no
        // handle is supplied. Weave's global_alloc returns NULL for size 0, so
        // allocate a minimal 1-byte block; the logical size stays 0.
        // SAFETY: libc::malloc(1) either returns a valid owned block or NULL.
        let p = unsafe { libc::malloc(1) };
        if p.is_null() {
            return std::ptr::null_mut();
        }
        p as usize
    };
    let size = if hglobal != 0 {
        // Wine ref: handle_create stores GlobalSize(hglobal). Weave's
        // GlobalSize is malloc_usable_size (weave-kernel32 global_size), so
        // match Weave's notion of an external block's size.
        // SAFETY: hg is a live libc-malloc'd block (caller contract: an
        // HGLOBAL from GlobalAlloc), valid for the malloc_usable_size call.
        (unsafe { libc::malloc_usable_size(hg as *mut _) }) as u64
    } else {
        0
    };
    let wrapper = Box::new(HandleWrapper {
        ref_count: 1,
        hglobal: hg,
        size,
        delete_on_release,
    });
    Box::into_raw(wrapper)
}

fn hglobalstream_construct() -> *mut HGlobalStream {
    let obj = Box::new(HGlobalStream {
        vtable: &H_GLOBAL_STREAM_VTBL,
        ref_count: 1,
        handle: std::ptr::null_mut(),
        position: 0,
    });
    Box::into_raw(obj)
}

unsafe extern "win64" fn stream_query_interface(
    this: *mut HGlobalStream,
    riid: *const u8,
    ppv: *mut *mut (),
) -> u32 {
    if ppv.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: ppv validated non-null above; caller contract guarantees a
    // writable pointer slot.
    unsafe { *ppv = std::ptr::null_mut() };
    if riid.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: riid validated non-null above; the caller's # Safety contract
    // guarantees a 16-byte IID buffer.
    let iid = unsafe { std::ptr::read_unaligned(riid as *const [u8; 16]) };
    if iid == IID_IUNKNOWN_BYTES || iid == IID_ISEQUENTIALSTREAM || iid == IID_ISTREAM {
        // SAFETY: this is a live stream (IUnknown contract — ref_count > 0).
        unsafe {
            (*this).ref_count += 1;
            *ppv = this as *mut ();
        }
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "win64" fn stream_add_ref(this: *mut HGlobalStream) -> u32 {
    // SAFETY: this is a live stream (IUnknown contract).
    let count = unsafe { (*this).ref_count + 1 };
    // SAFETY: ref_count > 0 before the write, so the stream stays alive.
    unsafe { (*this).ref_count = count };
    count
}

unsafe extern "win64" fn stream_release(this: *mut HGlobalStream) -> u32 {
    // SAFETY: this is a live stream (IUnknown contract).
    let prev = unsafe { (*this).ref_count };
    let new = prev - 1;
    if new == 0 {
        // SAFETY: fields are read before the stream Box is reclaimed below;
        // the handle wrapper may free the HGLOBAL on its own last ref.
        let handle = unsafe { (*this).handle };
        unsafe { handle_release(handle) };
        // SAFETY: the stream was Box::into_raw'd at construction; no
        // references remain (refcount 0), so reclaiming the Box is sound.
        unsafe { drop(Box::from_raw(this)) };
    } else {
        // SAFETY: ref_count > 0, so the stream stays alive.
        unsafe { (*this).ref_count = new };
    }
    new
}

unsafe extern "win64" fn stream_read(
    this: *mut HGlobalStream,
    pv: *mut u8,
    cb: u32,
    pcb_read: *mut u32,
) -> u32 {
    // Wine ref: dlls/combase/hglobalstream.c stream_Read — clamps the copy to
    // (size - position), advances position, and returns S_OK even at EOF
    // (pcbRead == 0, never S_FALSE).
    let mut dummy: u32 = 0;
    let read_out = if pcb_read.is_null() {
        &mut dummy
    } else {
        pcb_read
    };
    // SAFETY: read_out is either the validated pcb_read or the stack dummy.
    unsafe { *read_out = 0 };

    if cb == 0 {
        return S_OK;
    }
    if pv.is_null() {
        return E_INVALIDARG;
    }

    // SAFETY: this is a live stream (IUnknown contract); the handle wrapper
    // outlives it (released after the stream in stream_release).
    let position = unsafe { (*this).position };
    let size = unsafe { (*(*this).handle).size };
    let len = if size >= position {
        (size - position).min(cb as u64)
    } else {
        0
    };
    if len > 0 {
        // SAFETY: the handle owns a libc-malloc'd block of at least `size`
        // bytes; len is clamped to size - position, so the copy stays in-block.
        // pv was validated non-null above (len > 0 implies cb > 0).
        let hg = unsafe { (*(*this).handle).hglobal } as *mut u8;
        unsafe { std::ptr::copy_nonoverlapping(hg.add(position as usize), pv, len as usize) };
        // SAFETY: this is a live stream; position += len ≤ size ≤ u32::MAX.
        unsafe { (*this).position = position + len };
        // SAFETY: read_out is valid (validated above).
        unsafe { *read_out = len as u32 };
    }
    S_OK
}

unsafe extern "win64" fn stream_write(
    this: *mut HGlobalStream,
    pv: *const u8,
    cb: u32,
    pcb_written: *mut u32,
) -> u32 {
    // Wine ref: dlls/combase/hglobalstream.c stream_Write — grows the block via
    // SetSize when position + cb exceeds size, then copies; S_OK with
    // *pcbWritten == cb. *pcbWritten is 0 on SetSize failure.
    let mut dummy: u32 = 0;
    let written_out = if pcb_written.is_null() {
        &mut dummy
    } else {
        pcb_written
    };
    // SAFETY: written_out is either the validated pcb_written or a stack dummy.
    unsafe { *written_out = 0 };

    if cb == 0 {
        return S_OK;
    }
    if pv.is_null() {
        return E_INVALIDARG;
    }

    // SAFETY: this is a live stream (IUnknown contract).
    let position = unsafe { (*this).position };
    let need = position + cb as u64;
    if need > 0xFFFF_FFFF {
        // The stream lives in a 32-bit position/size space (Wine uses LowPart
        // everywhere); a write needing more is out of range. Guard prevents an
        // out-of-bounds copy that the LowPart truncation would otherwise allow.
        return E_INVALIDARG;
    }
    let size = unsafe { (*(*this).handle).size };
    if need > size {
        let hr = stream_set_size(this, need);
        if hr != S_OK {
            return hr;
        }
    }
    // SAFETY: the block was grown (or already large enough) via SetSize, so
    // the copy at `position` of `cb` bytes stays in-block; pv validated above.
    let hg = unsafe { (*(*this).handle).hglobal } as *mut u8;
    unsafe { std::ptr::copy_nonoverlapping(pv, hg.add(position as usize), cb as usize) };
    // SAFETY: this is a live stream; position advances by exactly cb.
    unsafe { (*this).position = position + cb as u64 };
    // SAFETY: written_out is valid (validated above).
    unsafe { *written_out = cb };
    S_OK
}

unsafe extern "win64" fn stream_seek(
    this: *mut HGlobalStream,
    dlib_move: i64,
    origin: u32,
    plib_new_position: *mut u64,
) -> u32 {
    // Wine ref: dlls/combase/hglobalstream.c stream_Seek — only the low 32
    // bits of dlibMove are used, treated as a signed i32. STG_E_SEEKERROR when
    // the target lands before 0 or past u32::MAX (win8 no-wrap). Position is
    // unchanged on error; *plibNewPosition always receives the position.
    // SAFETY: this is a live stream (IUnknown contract).
    let base: i64 = match origin {
        STREAM_SEEK_SET => 0,
        STREAM_SEEK_CUR => (unsafe { (*this).position }) as i64,
        STREAM_SEEK_END => (unsafe { (*(*this).handle).size }) as i64,
        _ => {
            // SAFETY: plibNewPosition validated (or null) below.
            if !plib_new_position.is_null() {
                unsafe { *plib_new_position = (*this).position };
            }
            return STG_E_SEEKERROR;
        }
    };
    // Only the low 32 bits of the move are meaningful (Wine ignores HighPart).
    let m = dlib_move as i32 as i64;
    let target = base + m;
    if !(0..=0xFFFF_FFFF).contains(&target) {
        if !plib_new_position.is_null() {
            // SAFETY: plibNewPosition validated non-null above.
            unsafe { *plib_new_position = (*this).position };
        }
        return STG_E_SEEKERROR;
    }
    // SAFETY: this is a live stream; target is within [0, u32::MAX].
    unsafe { (*this).position = target as u64 };
    if !plib_new_position.is_null() {
        // SAFETY: plibNewPosition validated non-null above; it is a valid
        // writable ULARGE_INTEGER* per the caller's # Safety contract.
        unsafe { *plib_new_position = (*this).position };
    }
    S_OK
}

unsafe extern "win64" fn stream_set_size(this: *mut HGlobalStream, lib_new_size: u64) -> u32 {
    // Wine ref: dlls/combase/hglobalstream.c stream_SetSize — uses only the
    // low 32 bits (LowPart); GlobalReAlloc's the block; updates size on
    // success; E_OUTOFMEMORY when the realloc fails.
    let new_size = (lib_new_size as u32) as u64;
    // SAFETY: this is a live stream; the wrapper outlives it.
    let handle = unsafe { (*this).handle };
    let current = unsafe { (*handle).size };
    if current == new_size {
        return S_OK;
    }
    // SAFETY: hg is a live libc-malloc'd block owned by the wrapper; realloc
    // keeps ownership in the wrapper. A 0-size request gets a 1-byte block so
    // the pointer stays non-null (libc::realloc(p, 0) would free and return
    // NULL, which we must not store as an owned handle).
    let hg = unsafe { (*handle).hglobal };
    let alloc_size = new_size.max(1) as usize;
    let new_hg = unsafe { libc::realloc(hg as *mut libc::c_void, alloc_size) };
    if new_hg.is_null() {
        return E_OUTOFMEMORY;
    }
    // SAFETY: both wrapper fields are live (refcount > 0, held by this stream).
    unsafe {
        (*handle).hglobal = new_hg as usize;
        (*handle).size = new_size;
    }
    S_OK
}

unsafe extern "win64" fn stream_copy_to(
    this: *mut HGlobalStream,
    dest: *mut (),
    cb: u64,
    pcb_read: *mut u64,
    pcb_written: *mut u64,
) -> u32 {
    // Wine ref: dlls/combase/hglobalstream.c stream_CopyTo — chunked 128-byte
    // read/write loop; accumulates totals; stops on FAILED hr or when a read
    // returns fewer bytes than requested (EOF). dest must be a valid IStream.
    if dest.is_null() {
        return STG_E_INVALIDPOINTER;
    }
    let mut total_read: u64 = 0;
    let mut total_written: u64 = 0;
    let mut remaining = cb;
    let mut hr: u32 = S_OK;
    let mut buffer = [0u8; 128];
    while remaining > 0 {
        let chunk_size = remaining.min(128) as u32;
        let mut chunk_read: u32 = 0;
        hr = stream_read(this, buffer.as_mut_ptr(), chunk_size, &mut chunk_read);
        if hr >= 0x8000_0000 {
            break;
        }
        total_read += chunk_read as u64;
        if chunk_read > 0 {
            let mut chunk_written: u32 = 0;
            // SAFETY: dest validated non-null above; for any valid IStream the
            // vtable pointer and its slot 4 (Write) are readable — same layout
            // used by co_marshal_hresult and by IStreamVtbl above.
            let vtbl = unsafe { com_vtable(dest) };
            let write: unsafe extern "win64" fn(*mut (), *const u8, u32, *mut u32) -> u32 =
                unsafe { std::mem::transmute(*vtbl.add(4)) };
            hr = write(dest, buffer.as_ptr(), chunk_read, &mut chunk_written);
            if hr >= 0x8000_0000 {
                break;
            }
            total_written += chunk_written as u64;
        }
        if chunk_read != chunk_size {
            remaining = 0;
        } else {
            remaining -= chunk_read as u64;
        }
    }
    if !pcb_read.is_null() {
        // SAFETY: pcb_read validated non-null above; valid ULARGE_INTEGER*.
        unsafe { *pcb_read = total_read };
    }
    if !pcb_written.is_null() {
        // SAFETY: pcb_written validated non-null above; valid ULARGE_INTEGER*.
        unsafe { *pcb_written = total_written };
    }
    hr
}

unsafe extern "win64" fn stream_commit(_this: *mut HGlobalStream, _flags: u32) -> u32 {
    // Wine ref: stream_Commit — no-op for a memory-backed stream.
    S_OK
}

unsafe extern "win64" fn stream_revert(_this: *mut HGlobalStream) -> u32 {
    // Wine ref: stream_Revert — no-op for a memory-backed stream.
    S_OK
}

unsafe extern "win64" fn stream_lock_region(
    _this: *mut HGlobalStream,
    _offset: u64,
    _len: u64,
    _lock_type: u32,
) -> u32 {
    // Wine ref: stream_LockRegion — region locking unsupported on HGLOBAL streams.
    STG_E_INVALIDFUNCTION
}

unsafe extern "win64" fn stream_unlock_region(
    _this: *mut HGlobalStream,
    _offset: u64,
    _len: u64,
    _lock_type: u32,
) -> u32 {
    // Wine ref: stream_UnlockRegion — no-op, S_OK.
    S_OK
}

unsafe extern "win64" fn stream_stat(
    this: *mut HGlobalStream,
    pstatstg: *mut u8,
    _grf_stat_flag: u32,
) -> u32 {
    // Wine ref: stream_Stat — zeroes the whole STATSTG, sets type =
    // STGTY_STREAM and cbSize = size; pwcsName and clsid stay NULL / GUID_NULL.
    if pstatstg.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: pstatstg validated non-null above; the caller's # Safety
    // contract guarantees a writable buffer of at least sizeof(STATSTG) = 80
    // bytes (win64 layout).
    unsafe { std::ptr::write_bytes(pstatstg, 0, STATSTG_SIZE) };
    // SAFETY: pstatstg is valid for 80 bytes; offsets are the named STATSTG
    // layout constants; the stream/handle are live.
    unsafe {
        *(pstatstg.add(STATSTG_TYPE_OFFSET) as *mut u32) = STGTY_STREAM;
        *(pstatstg.add(STATSTG_CBSIZE_OFFSET) as *mut u64) = (*(*this).handle).size;
    }
    S_OK
}

unsafe extern "win64" fn stream_clone(this: *mut HGlobalStream, ppstm: *mut *mut ()) -> u32 {
    // Wine ref: stream_Clone — a new hglobal_stream sharing the same handle
    // (handle_addref) and the same position.
    if ppstm.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: ppstm validated non-null above; writable pointer slot.
    unsafe { *ppstm = std::ptr::null_mut() };
    let clone = hglobalstream_construct();
    if clone.is_null() {
        return E_OUTOFMEMORY;
    }
    // SAFETY: this is a live stream (IUnknown contract); handle outlives it.
    let handle = unsafe { (*this).handle };
    unsafe { handle_addref(handle) };
    // SAFETY: clone is a fresh Box::into_raw'd stream (refcount 1); assigning
    // the shared handle and copying the position is sound, and the handle ref
    // taken above balances the future handle_release.
    unsafe {
        (*clone).handle = handle;
        (*clone).position = (*this).position;
    }
    // SAFETY: ppstm validated non-null above; clone outlives this call.
    unsafe { *ppstm = clone as *mut () };
    S_OK
}

static H_GLOBAL_STREAM_VTBL: IStreamVtbl = IStreamVtbl {
    query_interface: stream_query_interface,
    add_ref: stream_add_ref,
    release: stream_release,
    read: stream_read,
    write: stream_write,
    seek: stream_seek,
    set_size: stream_set_size,
    copy_to: stream_copy_to,
    commit: stream_commit,
    revert: stream_revert,
    lock_region: stream_lock_region,
    unlock_region: stream_unlock_region,
    stat: stream_stat,
    clone: stream_clone,
};

// Wine ref: dlls/combase/hglobalstream.c — CreateStreamOnHGlobal returns
// E_INVALIDARG when ppstm is NULL; constructs the hglobal_stream (refcount 1)
// and a handle_wrapper around hGlobal (or a fresh allocation when hGlobal is
// NULL), then writes IStream* into *ppstm. fDeleteOnRelease is stored verbatim
// on the wrapper — Wine frees an internally-allocated handle only when TRUE.
/// CreateStreamOnHGlobal: create an IStream that reads/writes an HGLOBAL.
///
/// Returns `S_OK` and writes the IStream* into `pp_stm`. The HGLOBAL is
/// grown in place as the stream is written to (Phase 2 HGLOBAL == raw heap
/// pointer). When `h_global` is NULL a fresh block is allocated. When
/// `f_delete_on_release` is non-zero the stream frees the HGLOBAL when its
/// last reference (including any clones) is released.
///
/// # Safety
/// `pp_stm` must be a valid writable pointer to a `usize` output slot, or
/// null (in which case `E_INVALIDARG` is returned). `h_global` must be a
/// valid HGLOBAL from `GlobalAlloc` (Phase 2: a live heap pointer), or 0.
pub unsafe extern "win64" fn create_stream_on_hglobal(
    h_global: usize,
    f_delete_on_release: i32,
    pp_stm: *mut usize,
) -> i32 {
    if pp_stm.is_null() {
        return E_INVALIDARG as i32;
    }
    // SAFETY: pp_stm validated non-null above; writable output slot.
    unsafe { *pp_stm = 0 };

    let stream = hglobalstream_construct();
    // SAFETY: the wrapper may fail to allocate (returns NULL) — in that case
    // the stream is unowned and reclaimed here.
    let handle = unsafe { handle_create(h_global, f_delete_on_release != 0) };
    if handle.is_null() {
        // SAFETY: stream is a fresh Box::into_raw'd object with no other
        // references, so reclaiming it is sound.
        unsafe { drop(Box::from_raw(stream)) };
        return E_OUTOFMEMORY as i32;
    }
    // SAFETY: stream is a live Box::into_raw'd object (refcount 1).
    unsafe { (*stream).handle = handle };
    // SAFETY: pp_stm validated non-null above; stream outlives this call.
    unsafe { *pp_stm = stream as usize };
    eprintln!(
        "weave/ole32: CreateStreamOnHGlobal(h={h_global:#x}, delete={f_delete_on_release}) → S_OK"
    );
    S_OK as i32
}

// Wine ref: dlls/combase/hglobalstream.c — GetHGlobalFromStream returns
// E_INVALIDARG when either argument is NULL, or when the stream's vtable is
// not the hglobal_stream vtable (i.e. it was not created by
// CreateStreamOnHGlobal). Returns the backing HGLOBAL via *phglobal.
/// GetHGlobalFromStream: retrieve the HGLOBAL backing a stream.
///
/// Returns `S_OK` and writes the HGLOBAL into `ph_global`, or `E_INVALIDARG`
/// when the stream is NULL, `ph_global` is NULL, or the stream was not created
/// by `CreateStreamOnHGlobal`.
///
/// # Safety
/// `stream` must be a valid IStream* or 0. `ph_global` must be a valid
/// writable pointer to a `usize` output slot, or null.
pub unsafe extern "win64" fn get_hglobal_from_stream(stream: usize, ph_global: *mut usize) -> i32 {
    if stream == 0 || ph_global.is_null() {
        return E_INVALIDARG as i32;
    }
    let obj = stream as *mut HGlobalStream;
    // SAFETY: stream validated non-null above; reading the first field (the
    // vtable pointer) is sound for any COM object — we only compare it.
    let vtbl = unsafe { (*obj).vtable };
    if !std::ptr::eq(vtbl, &H_GLOBAL_STREAM_VTBL as *const IStreamVtbl) {
        // SAFETY: ph_global validated non-null above; writable output slot.
        unsafe { *ph_global = 0 };
        return E_INVALIDARG as i32;
    }
    // SAFETY: the vtable identity check proves obj is one of our live streams,
    // so its handle wrapper and hglobal are valid.
    let hg = unsafe { (*(*obj).handle).hglobal };
    // SAFETY: ph_global validated non-null above; writable output slot.
    unsafe { *ph_global = hg };
    S_OK as i32
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
        "CoGetApartmentType" => {
            Some(co_get_apartment_type as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CoGetCurrentProcess" => Some(co_get_current_process as *const () as usize),
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
        // Class factory registration
        "CoRegisterClassObject" => Some(
            co_register_class_object as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CoRevokeClassObject" => {
            Some(co_revoke_class_object as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
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
        // Proxy/stub CLSID registry
        "CoRegisterPSClsid" => {
            Some(co_register_ps_clsid as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CoGetPSClsid" => {
            Some(co_get_ps_clsid as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Marshalling (stubs)
        "CoMarshalInterface" => Some(co_marshal_interface as *const () as usize),
        "CoUnmarshalInterface" => Some(co_unmarshal_interface as *const () as usize),
        "CoMarshalHresult" => {
            Some(co_marshal_hresult as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CoUnmarshalHresult" => {
            Some(co_unmarshal_hresult as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CoGetStandardMarshal" => Some(
            co_get_standard_marshal as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
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
        "GetHGlobalFromStream" => Some(
            get_hglobal_from_stream as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        // TODO(shim): Phase A — message filter needed by OpenMPT
        "CoRegisterMessageFilter" => Some(
            co_register_message_filter as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        // TODO(shim): Phase A — free unused COM libraries needed by OpenMPT
        // Wine ref: dlls/ole32/ole32.c — CoFreeUnusedLibraries frees unused libs
        "CoFreeUnusedLibraries" => Some(co_free_unused_libraries as *const () as usize),
        _ => None,
    }
}

/// CoFreeUnusedLibraries — stub, no-op.
// Wine ref: dlls/ole32/ole32.c — CoFreeUnusedLibraries calls CoFreeUnusedLibrariesEx
extern "win64" fn co_free_unused_libraries() {
    // void
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
        "UuidCreateSequential" => Some(rpc_uuid_create_sequential as *const () as usize),
        "UuidToStringW" => Some(rpc_uuid_to_string_w as *const () as usize),
        "UuidFromStringW" => Some(rpc_uuid_from_string_w as *const () as usize),
        "UuidIsNil" => Some(rpc_uuid_is_nil as *const () as usize),
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

// TODO(shim): Phase A — sequential UUID creation needed by OpenMPT
// Wine ref: dlls/rpcrt4/rpc.c — UuidCreateSequential creates a UUID
extern "win64" fn rpc_uuid_create_sequential(_uuid: *mut u8) -> i32 {
    0 // RPC_S_OK
}

// TODO(shim): Phase A — UUID nil check needed by OpenMPT
// Wine ref: dlls/rpcrt4/rpc.c — UuidIsNil checks if UUID is nil
extern "win64" fn rpc_uuid_is_nil(_uuid: *const u8) -> i32 {
    1 // TRUE — claim nil (safest default)
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
        "AccessibleObjectFromWindow" => Some(
            oleacc_accessible_object_from_window as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
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

// TODO(shim): Phase A — accessible object from window needed by OpenMPT
// Wine ref: dlls/oleacc/main.c — AccessibleObjectFromWindow gets an accessibility
// object for a window. Weave stub returns S_OK and sets ppvObject to NULL.
extern "win64" fn oleacc_accessible_object_from_window(
    _hwnd: usize,
    _id_object: u32,
    _riid: *const u8,
    ppv_object: *mut usize,
) -> i32 {
    if !ppv_object.is_null() {
        unsafe { *ppv_object = 0 };
    }
    0 // S_OK
}

// ── oledlg.dll stubs ───────────────────────────────────────────────────────────┐
//                                                                               │
// oledlg.dll provides OLE common dialogs (busy dialog, insert object, etc.).   │
// OpenMPT imports OleUIBusyW. Phase A stub returning S_OK (0).                 │
//┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│

/// Resolve an oledlg.dll import to a stub address.
pub fn resolve_oledlg(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("oledlg.dll") {
        return None;
    }
    match func {
        "OleUIBusyW" => Some(
            ole_uibusy_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        _ => None,
    }
}

/// OleUIBusyW — display the OLE busy dialog.
///
/// Returns S_OK (0) without showing a dialog. The caller interprets this as
/// "the busy dialog was dismissed" and continues.
// Wine ref: dlls/oledlg/busydlg.c — OleUIBusyW creates and shows a modal dialog
// box that lets the user switch to the busy server or retry. Returns S_OK, S_FALSE,
// or OLEUI_CANCEL depending on user action.
pub unsafe extern "win64" fn ole_uibusy_w(
    _lp_ole_uibusy: *const u8,
    _hwnd: usize,
    _psz_filename: *const u16,
    _cb_filename: u32,
    _f_show: u32,
    _pfn_hook: usize,
) -> u32 {
    0 // S_OK
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_com_state() {
        COM_INIT_COUNT.with(|c| c.set(0));
        COM_INIT_FLAGS.with(|f| f.set(0));
    }

    #[test]
    fn co_init_first_call_returns_s_ok() {
        reset_com_state();
        assert_eq!(co_initialize_ex(0, COINIT_APARTMENTTHREADED), S_OK);
        assert_eq!(co_initialize_ex(0, COINIT_APARTMENTTHREADED), S_FALSE);
        co_uninitialize();
        co_uninitialize();
    }

    #[test]
    fn co_uninitialize_decrements() {
        reset_com_state();
        co_initialize_ex(0, COINIT_MULTITHREADED);
        co_initialize_ex(0, COINIT_MULTITHREADED);
        assert_eq!(COM_INIT_COUNT.with(|c| c.get()), 2);
        co_uninitialize();
        assert_eq!(COM_INIT_COUNT.with(|c| c.get()), 1);
        co_uninitialize();
        assert_eq!(COM_INIT_COUNT.with(|c| c.get()), 0);
    }

    #[test]
    fn co_uninitialize_clears_apartment_state() {
        reset_com_state();
        co_initialize_ex(0, COINIT_APARTMENTTHREADED);
        // After uninit, CoGetApartmentType should fail
        co_uninitialize();
        let mut apt_type: i32 = -1;
        let mut apt_qual: i32 = -1;
        let hr = unsafe { co_get_apartment_type(&mut apt_type, &mut apt_qual) };
        assert_eq!(hr, CO_E_NOTINITIALIZED);
        // Re-init should succeed with S_OK (fresh state)
        assert_eq!(co_initialize_ex(0, COINIT_MULTITHREADED), S_OK);
        co_uninitialize();
    }

    #[test]
    fn co_mta_after_sta_returns_changed_mode() {
        reset_com_state();
        co_initialize_ex(0, COINIT_APARTMENTTHREADED);
        assert_eq!(
            co_initialize_ex(0, COINIT_MULTITHREADED),
            RPC_E_CHANGED_MODE
        );
        co_uninitialize();
    }

    #[test]
    fn co_sta_after_mta_returns_changed_mode() {
        reset_com_state();
        co_initialize_ex(0, COINIT_MULTITHREADED);
        assert_eq!(
            co_initialize_ex(0, COINIT_APARTMENTTHREADED),
            RPC_E_CHANGED_MODE
        );
        co_uninitialize();
    }

    #[test]
    fn co_init_fresh_thread_mta_returns_s_ok() {
        // Spawn a fresh thread and initialize with MTA — must succeed.
        let handle = std::thread::spawn(|| {
            assert_eq!(co_initialize_ex(0, COINIT_MULTITHREADED), S_OK);
            co_uninitialize();
        });
        handle.join().expect("thread panicked");
    }

    #[test]
    fn co_init_fresh_thread_sta_returns_s_ok() {
        let handle = std::thread::spawn(|| {
            assert_eq!(co_initialize_ex(0, COINIT_APARTMENTTHREADED), S_OK);
            co_uninitialize();
        });
        handle.join().expect("thread panicked");
    }

    #[test]
    fn co_initialize_delegates_to_sta() {
        reset_com_state();
        assert_eq!(co_initialize(0), S_OK);
        // Second call with same mode should be S_FALSE
        assert_eq!(co_initialize_ex(0, COINIT_APARTMENTTHREADED), S_FALSE);
        co_uninitialize();
        co_uninitialize();
    }

    #[test]
    fn co_get_apartment_type_sta() {
        reset_com_state();
        let mut apt_type: i32 = -1;
        let mut apt_qual: i32 = -1;
        co_initialize_ex(0, COINIT_APARTMENTTHREADED);
        let hr = unsafe { co_get_apartment_type(&mut apt_type, &mut apt_qual) };
        assert_eq!(hr, S_OK);
        assert_eq!(apt_type, APTTYPE_STA);
        assert_eq!(apt_qual, APTTYPEQUALIFIER_NONE);
        co_uninitialize();
    }

    #[test]
    fn co_get_apartment_type_mta() {
        reset_com_state();
        let mut apt_type: i32 = -1;
        let mut apt_qual: i32 = -1;
        co_initialize_ex(0, COINIT_MULTITHREADED);
        let hr = unsafe { co_get_apartment_type(&mut apt_type, &mut apt_qual) };
        assert_eq!(hr, S_OK);
        assert_eq!(apt_type, APTTYPE_MTA);
        assert_eq!(apt_qual, APTTYPEQUALIFIER_NONE);
        co_uninitialize();
    }

    #[test]
    fn co_get_apartment_type_null_returns_invalidarg() {
        assert_eq!(
            unsafe { co_get_apartment_type(std::ptr::null_mut(), std::ptr::null_mut()) },
            E_INVALIDARG
        );
    }

    #[test]
    fn co_get_apartment_type_uninit_returns_notinit() {
        reset_com_state();
        let mut apt_type: i32 = -1;
        let mut apt_qual: i32 = -1;
        assert_eq!(
            unsafe { co_get_apartment_type(&mut apt_type, &mut apt_qual) },
            CO_E_NOTINITIALIZED
        );
    }

    #[test]
    fn co_get_current_process_returns_nonzero() {
        let pid = co_get_current_process();
        assert_ne!(pid, 0);
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

    #[test]
    fn co_create_guid_returns_nonzero() {
        let mut guid = [0u8; 16];
        let hr = unsafe { co_create_guid(&mut guid as *mut u8) };
        assert_eq!(hr, S_OK);
        assert_ne!(guid, [0u8; 16]);
        // Verify UUID v4: version nibble should be 4 in byte 6 high nibble
        assert_eq!(guid[6] >> 4, 4);
        // Verify RFC 4122 variant: byte 8 should be 0x80..0xBF
        assert!(guid[8] >= 0x80 && guid[8] <= 0xBF);
    }

    #[test]
    fn co_create_guid_null_returns_error() {
        let hr = unsafe { co_create_guid(std::ptr::null_mut()) };
        assert_eq!(hr, 0x8007_0057); // E_INVALIDARG
    }

    #[test]
    fn co_create_guid_unique_per_call() {
        let mut g1 = [0u8; 16];
        let mut g2 = [0u8; 16];
        let hr1 = unsafe { co_create_guid(&mut g1 as *mut u8) };
        let hr2 = unsafe { co_create_guid(&mut g2 as *mut u8) };
        assert_eq!(hr1, S_OK);
        assert_eq!(hr2, S_OK);
        assert_ne!(g1, g2);
    }

    // ── A3c: CoRegisterClassObject / CoCreateInstance tests ───────────────

    /// Minimal COM object used by the test factory's CreateInstance.
    #[repr(C)]
    struct TestObject {
        vtable: *const TestObjectVtbl,
        ref_count: u32,
    }

    #[repr(C)]
    struct TestObjectVtbl {
        query_interface: unsafe extern "win64" fn(*mut TestObject, *const u8, *mut *mut ()) -> u32,
        add_ref: unsafe extern "win64" fn(*mut TestObject) -> u32,
        release: unsafe extern "win64" fn(*mut TestObject) -> u32,
    }

    unsafe extern "win64" fn test_obj_qi(
        this: *mut TestObject,
        riid: *const u8,
        ppv: *mut *mut (),
    ) -> u32 {
        const IID_IUNKNOWN_BYTES: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
        if ppv.is_null() {
            return 0x8007_0057;
        }
        unsafe { *ppv = std::ptr::null_mut() };
        if riid.is_null() {
            return 0x8007_0057;
        }
        let iid = unsafe { std::ptr::read_unaligned(riid as *const [u8; 16]) };
        if iid == IID_IUNKNOWN_BYTES {
            unsafe {
                (*this).ref_count += 1;
                *ppv = this as *mut ();
            }
            0 // S_OK
        } else {
            0x8000_4002 // E_NOINTERFACE
        }
    }

    unsafe extern "win64" fn test_obj_add_ref(this: *mut TestObject) -> u32 {
        unsafe { (*this).ref_count += 1 };
        unsafe { (*this).ref_count }
    }

    unsafe extern "win64" fn test_obj_release(this: *mut TestObject) -> u32 {
        let prev = unsafe { (*this).ref_count };
        let new = prev - 1;
        if new == 0 {
            unsafe { drop(Box::from_raw(this)) };
        } else {
            unsafe { (*this).ref_count = new };
        }
        new
    }

    static TEST_OBJECT_VTBL: TestObjectVtbl = TestObjectVtbl {
        query_interface: test_obj_qi,
        add_ref: test_obj_add_ref,
        release: test_obj_release,
    };

    /// Minimal IClassFactory for testing.
    #[repr(C)]
    struct TestFactory {
        vtable: *const TestFactoryVtbl,
        ref_count: u32,
    }

    #[repr(C)]
    struct TestFactoryVtbl {
        query_interface: unsafe extern "win64" fn(*mut TestFactory, *const u8, *mut *mut ()) -> u32,
        add_ref: unsafe extern "win64" fn(*mut TestFactory) -> u32,
        release: unsafe extern "win64" fn(*mut TestFactory) -> u32,
        create_instance:
            unsafe extern "win64" fn(*mut TestFactory, *mut (), *const u8, *mut *mut ()) -> u32,
        lock_server: unsafe extern "win64" fn(*mut TestFactory, i32) -> u32,
    }

    unsafe extern "win64" fn test_factory_qi(
        this: *mut TestFactory,
        riid: *const u8,
        ppv: *mut *mut (),
    ) -> u32 {
        const IID_IUNKNOWN_BYTES: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
        const IID_ICLASSFACTORY_BYTES: [u8; 16] =
            [1, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
        if ppv.is_null() {
            return 0x8007_0057;
        }
        unsafe { *ppv = std::ptr::null_mut() };
        if riid.is_null() {
            return 0x8007_0057;
        }
        let iid = unsafe { std::ptr::read_unaligned(riid as *const [u8; 16]) };
        if iid == IID_IUNKNOWN_BYTES || iid == IID_ICLASSFACTORY_BYTES {
            unsafe {
                (*this).ref_count += 1;
                *ppv = this as *mut ();
            }
            0 // S_OK
        } else {
            0x8000_4002 // E_NOINTERFACE
        }
    }

    unsafe extern "win64" fn test_factory_add_ref(this: *mut TestFactory) -> u32 {
        unsafe { (*this).ref_count += 1 };
        unsafe { (*this).ref_count }
    }

    unsafe extern "win64" fn test_factory_release(this: *mut TestFactory) -> u32 {
        let prev = unsafe { (*this).ref_count };
        let new = prev - 1;
        if new == 0 {
            unsafe { drop(Box::from_raw(this)) };
        } else {
            unsafe { (*this).ref_count = new };
        }
        new
    }

    unsafe extern "win64" fn test_factory_create_instance(
        _this: *mut TestFactory,
        _p_unk_outer: *mut (),
        riid: *const u8,
        ppv: *mut *mut (),
    ) -> u32 {
        if ppv.is_null() || riid.is_null() {
            return 0x8007_0057;
        }
        unsafe { *ppv = std::ptr::null_mut() };

        // Create a TestComObject and QI it for the requested IID.
        let obj = Box::new(TestObject {
            vtable: &TEST_OBJECT_VTBL,
            ref_count: 1,
        });
        let ptr = Box::into_raw(obj);
        let hr = test_obj_qi(ptr, riid, ppv);
        if hr != 0 {
            // QI failed — release the object and propagate the error.
            unsafe { drop(Box::from_raw(ptr)) };
        }
        hr
    }

    unsafe extern "win64" fn test_factory_lock_server(
        _this: *mut TestFactory,
        _f_lock: i32,
    ) -> u32 {
        0 // S_OK
    }

    static TEST_FACTORY_VTBL: TestFactoryVtbl = TestFactoryVtbl {
        query_interface: test_factory_qi,
        add_ref: test_factory_add_ref,
        release: test_factory_release,
        create_instance: test_factory_create_instance,
        lock_server: test_factory_lock_server,
    };

    fn make_test_factory() -> *mut TestFactory {
        let f = Box::new(TestFactory {
            vtable: &TEST_FACTORY_VTBL,
            ref_count: 1,
        });
        Box::into_raw(f)
    }

    fn reset_factory_table() {
        let mut table = factory_table().lock().unwrap();
        for entry in table.drain(..) {
            unsafe { com_release(entry.factory_ptr) };
        }
    }

    // Unique CLSIDs for each test — no collisions between parallel tests.
    const CLSID_TEST_A: [u8; 16] = [
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA,
    ];
    const CLSID_TEST_B: [u8; 16] = [
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB,
    ];
    const CLSID_TEST_C: [u8; 16] = [
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC,
    ];

    #[test]
    fn co_register_and_create() {
        reset_factory_table();
        let factory = make_test_factory();
        let mut cookie: u32 = 0;

        let hr = unsafe {
            co_register_class_object(
                CLSID_TEST_A.as_ptr(),
                factory as *mut (),
                CLSCTX_INPROC_SERVER,
                0,
                &mut cookie,
            )
        };
        assert_eq!(hr, S_OK);
        assert_ne!(cookie, 0);

        // Now CoCreateInstance with the same CLSID should succeed.
        let mut obj: usize = 0xDEAD;
        let hr = unsafe {
            co_create_instance(
                CLSID_TEST_A.as_ptr(),
                0, // pUnkOuter
                CLSCTX_INPROC_SERVER,
                IID_IUNKNOWN_BYTES.as_ptr(),
                &mut obj,
            )
        };
        assert_eq!(hr, S_OK);
        assert_ne!(obj, 0);
        assert_ne!(obj, 0xDEAD);

        // Release the object we got.
        unsafe { com_release(obj as *mut ()) };

        // Clean up: revoke + release the factory owned by the table.
        unsafe { co_revoke_class_object(cookie) };
    }

    #[test]
    fn co_create_instance_unknown_clsid_returns_classnotreg() {
        reset_factory_table();
        let mut obj: usize = 0xDEAD;
        let hr = unsafe {
            co_create_instance(
                CLSID_TEST_C.as_ptr(),
                0,
                CLSCTX_INPROC_SERVER,
                IID_IUNKNOWN_BYTES.as_ptr(),
                &mut obj,
            )
        };
        assert_eq!(hr, REGDB_E_CLASSNOTREG);
        assert_eq!(obj, 0); // ppv is nulled on failure
    }

    #[test]
    fn co_revoke_prevents_further_creation() {
        reset_factory_table();
        let factory = make_test_factory();
        let mut cookie: u32 = 0;

        let hr = unsafe {
            co_register_class_object(
                CLSID_TEST_B.as_ptr(),
                factory as *mut (),
                CLSCTX_INPROC_SERVER,
                0,
                &mut cookie,
            )
        };
        assert_eq!(hr, S_OK);

        // Create once — should succeed.
        let mut obj: usize = 0;
        let hr = unsafe {
            co_create_instance(
                CLSID_TEST_B.as_ptr(),
                0,
                CLSCTX_INPROC_SERVER,
                IID_IUNKNOWN_BYTES.as_ptr(),
                &mut obj,
            )
        };
        assert_eq!(hr, S_OK);
        assert_ne!(obj, 0);
        unsafe { com_release(obj as *mut ()) };

        // Revoke the factory.
        let hr = unsafe { co_revoke_class_object(cookie) };
        assert_eq!(hr, S_OK);

        // Now CoCreateInstance should fail.
        let mut obj2: usize = 0xDEAD;
        let hr = unsafe {
            co_create_instance(
                CLSID_TEST_B.as_ptr(),
                0,
                CLSCTX_INPROC_SERVER,
                IID_IUNKNOWN_BYTES.as_ptr(),
                &mut obj2,
            )
        };
        assert_eq!(hr, REGDB_E_CLASSNOTREG);
        assert_eq!(obj2, 0);
    }

    #[test]
    fn co_revoke_class_object_invalid_cookie_returns_error() {
        let hr = unsafe { co_revoke_class_object(9999) };
        assert_eq!(hr, E_INVALIDARG);
    }

    // ── A3d: CoTaskMem / GUID / CoGetMalloc tests ──────────────────────

    #[test]
    fn co_task_mem_realloc_preserves_content() {
        let ptr = co_task_mem_alloc(8);
        assert_ne!(ptr, 0);
        // Write a pattern.
        unsafe { std::ptr::write_bytes(ptr as *mut u8, 0xAB, 8) };
        // Realloc to larger size — content should be preserved.
        let new_ptr = co_task_mem_realloc(ptr, 64);
        assert_ne!(new_ptr, 0);
        // First 8 bytes should still be 0xAB.
        let buf = unsafe { std::slice::from_raw_parts(new_ptr as *const u8, 8) };
        assert_eq!(buf, &[0xABu8; 8]);
        co_task_mem_free(new_ptr);
    }

    #[test]
    fn string_from_clsid_basic() {
        // {6B29FC40-CA47-1067-B31D-00DD010662DA}
        let guid_bytes: [u8; 16] = [
            0x40, 0xFC, 0x29, 0x6B, // Data1 = 0x6B29FC40 (LE)
            0x47, 0xCA, // Data2 = 0xCA47 (LE)
            0x67, 0x10, // Data3 = 0x1067 (LE)
            0xB3, 0x1D, 0x00, 0xDD, 0x01, 0x06, 0x62, 0xDA, // Data4
        ];
        let mut out_str: *mut u16 = std::ptr::null_mut();
        let hr = unsafe { string_from_clsid(guid_bytes.as_ptr(), &mut out_str) };
        assert_eq!(hr, S_OK);
        assert!(!out_str.is_null());
        let s = unsafe {
            let mut len = 0usize;
            while *out_str.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(out_str, len))
        };
        assert_eq!(s, "{6B29FC40-CA47-1067-B31D-00DD010662DA}");
        co_task_mem_free(out_str as usize);
    }

    #[test]
    fn string_from_clsid_roundtrip() {
        let guid_bytes: [u8; 16] = [
            0x60, 0xBE, 0x56, 0x9E, 0x0F, 0xC5, 0xCF, 0x11, 0x9A, 0x2C, 0x00, 0xA0, 0xC9, 0x0A,
            0x90, 0xCE,
        ];
        let mut out_str: *mut u16 = std::ptr::null_mut();
        let hr = unsafe { string_from_clsid(guid_bytes.as_ptr(), &mut out_str) };
        assert_eq!(hr, S_OK);
        assert!(!out_str.is_null());

        // Now parse it back.
        let mut parsed = [0u8; 16];
        let hr2 = unsafe { clsid_from_string(out_str, parsed.as_mut_ptr()) };
        assert_eq!(hr2, S_OK);
        assert_eq!(parsed, guid_bytes);

        co_task_mem_free(out_str as usize);
    }

    #[test]
    fn string_from_clsid_null_returns_error() {
        let mut out_str: *mut u16 = std::ptr::null_mut();
        let guid_bytes = [0u8; 16];
        // Null rclsid.
        let hr = unsafe { string_from_clsid(std::ptr::null(), &mut out_str) };
        assert_eq!(hr, E_INVALIDARG);
        // Null lpsz.
        let hr = unsafe { string_from_clsid(guid_bytes.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(hr, E_INVALIDARG);
    }

    #[test]
    fn clsid_from_string_no_braces() {
        let s = "6B29FC40-CA47-1067-B31D-00DD010662DA\0";
        let wide: Vec<u16> = s.encode_utf16().collect();
        let mut parsed = [0u8; 16];
        let hr = unsafe { clsid_from_string(wide.as_ptr(), parsed.as_mut_ptr()) };
        assert_eq!(hr, S_OK);
        let d1 = u32::from_le_bytes([parsed[0], parsed[1], parsed[2], parsed[3]]);
        assert_eq!(d1, 0x6B29_FC40);
    }

    #[test]
    fn clsid_from_string_lowercase() {
        let s = "{6b29fc40-ca47-1067-b31d-00dd010662da}\0";
        let wide: Vec<u16> = s.encode_utf16().collect();
        let mut parsed = [0u8; 16];
        let hr = unsafe { clsid_from_string(wide.as_ptr(), parsed.as_mut_ptr()) };
        assert_eq!(hr, S_OK);
        let d1 = u32::from_le_bytes([parsed[0], parsed[1], parsed[2], parsed[3]]);
        assert_eq!(d1, 0x6B29_FC40);
    }

    #[test]
    fn clsid_from_string_invalid_returns_error() {
        let s = "not-a-guid\0";
        let wide: Vec<u16> = s.encode_utf16().collect();
        let mut parsed = [0u8; 16];
        let hr = unsafe { clsid_from_string(wide.as_ptr(), parsed.as_mut_ptr()) };
        assert_eq!(hr, 0x8004_0205); // CO_E_CLASSSTRING
    }

    #[test]
    fn co_get_malloc_returns_interface() {
        let mut pp_malloc: *mut IMallocVtbl = std::ptr::null_mut();
        let hr = unsafe { co_get_malloc(1, &mut pp_malloc) };
        assert_eq!(hr, 0); // S_OK
        assert!(!pp_malloc.is_null());
    }

    #[test]
    fn co_get_malloc_invalid_context() {
        let mut pp_malloc: *mut IMallocVtbl = std::ptr::null_mut();
        // MEMCTX_MAKEFULL (0) — should fail.
        let hr = unsafe { co_get_malloc(0, &mut pp_malloc) };
        assert_eq!(hr, 0x8007_0057u32 as i32); // E_INVALIDARG
        assert!(pp_malloc.is_null());
    }

    #[test]
    fn co_get_malloc_null_returns_error() {
        let hr = unsafe { co_get_malloc(1, std::ptr::null_mut()) };
        assert_eq!(hr, 0x8007_0057u32 as i32); // E_INVALIDARG
    }

    #[test]
    fn co_get_malloc_alloc_free_via_imalloc() {
        let mut pp_malloc: *mut IMallocVtbl = std::ptr::null_mut();
        let hr = unsafe { co_get_malloc(1, &mut pp_malloc) };
        assert_eq!(hr, 0);
        assert!(!pp_malloc.is_null());

        // Call IMalloc::Alloc (vtable slot 3).
        let alloc_fn: unsafe extern "win64" fn(*mut IMallocVtbl, usize) -> *mut () =
            unsafe { std::mem::transmute((*pp_malloc).alloc) };
        let ptr = unsafe { alloc_fn(pp_malloc, 64) };
        assert!(!ptr.is_null());

        // Write a pattern and verify.
        unsafe { std::ptr::write_bytes(ptr, 0x42, 64) };

        // Call IMalloc::Free (vtable slot 5).
        let free_fn: unsafe extern "win64" fn(*mut IMallocVtbl, *mut ()) =
            unsafe { std::mem::transmute((*pp_malloc).free) };
        unsafe { free_fn(pp_malloc, ptr) };
        // No crash — success.
    }

    #[test]

    fn co_get_malloc_realloc_via_imalloc() {
        let mut pp_malloc: *mut IMallocVtbl = std::ptr::null_mut();
        let hr = unsafe { co_get_malloc(1, &mut pp_malloc) };
        assert_eq!(hr, 0);

        // Verify vtable dispatch works for alloc + free.
        let vtbl = unsafe { &*pp_malloc };
        let alloc_fn: unsafe extern "win64" fn(*mut IMallocVtbl, usize) -> *mut () =
            unsafe { std::mem::transmute(vtbl.alloc) };
        let free_fn: unsafe extern "win64" fn(*mut IMallocVtbl, *mut ()) =
            unsafe { std::mem::transmute(vtbl.free) };

        let ptr = unsafe { alloc_fn(pp_malloc, 16) };
        assert!(!ptr.is_null());
        unsafe { std::ptr::write_bytes(ptr, 0xAB, 16) };
        unsafe { free_fn(pp_malloc, ptr) };

        // Realloc verified by co_task_mem_realloc_preserves_content.
    }

    // ── A3f: Proxy/stub marshaling scaffolding tests ─────────────────

    const PS_CLSID_A: [u8; 16] = [
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11,
    ];
    const PS_IID_A: [u8; 16] = [
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA,
    ];

    #[test]
    fn co_register_ps_clsid_roundtrip() {
        let hr = unsafe { co_register_ps_clsid(PS_CLSID_A.as_ptr(), PS_IID_A.as_ptr()) };
        assert_eq!(hr, S_OK);

        let mut clsid_out = [0u8; 16];
        let hr = unsafe { co_get_ps_clsid(PS_IID_A.as_ptr(), clsid_out.as_mut_ptr()) };
        assert_eq!(hr, S_OK);
        assert_eq!(clsid_out, PS_CLSID_A);
    }

    #[test]
    fn co_get_ps_clsid_unregistered_returns_iidnotreg() {
        let iid: [u8; 16] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ];
        let mut clsid_out = [0u8; 16];
        let hr = unsafe { co_get_ps_clsid(iid.as_ptr(), clsid_out.as_mut_ptr()) };
        assert_eq!(hr, REGDB_E_IIDNOTREG);
        // pClsid not modified on error (left as zero)
        assert_eq!(clsid_out, [0u8; 16]);
    }

    #[test]
    fn co_register_ps_clsid_null_returns_error() {
        let hr = unsafe { co_register_ps_clsid(std::ptr::null(), PS_IID_A.as_ptr()) };
        assert_eq!(hr, E_INVALIDARG);
        let hr = unsafe { co_register_ps_clsid(PS_CLSID_A.as_ptr(), std::ptr::null()) };
        assert_eq!(hr, E_INVALIDARG);
    }

    #[test]
    fn co_get_ps_clsid_null_returns_error() {
        let hr = unsafe { co_get_ps_clsid(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(hr, E_INVALIDARG);
        let hr = unsafe { co_get_ps_clsid(PS_IID_A.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(hr, E_INVALIDARG);
    }

    #[test]
    fn co_marshal_interface_returns_e_notimpl() {
        let hr = co_marshal_interface(0, 0, 0, 0, 0, 0);
        assert_eq!(hr, E_NOTIMPL);
    }

    #[test]
    fn co_get_standard_marshal_returns_e_notimpl() {
        let mut ppv: usize = 0xDEAD;
        let hr = unsafe { co_get_standard_marshal(0, 0, 0, 0, 0, &mut ppv) };
        assert_eq!(hr, E_NOTIMPL);
        assert_eq!(ppv, 0);
    }

    #[test]
    fn co_register_ps_clsid_overwrite() {
        // Use a unique IID so this test does not race with
        // co_register_ps_clsid_roundtrip (both share the process-wide table).
        let overwrite_iid: [u8; 16] = [
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB,
        ];
        let clsid_a: [u8; 16] = [
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11,
        ];
        let hr = unsafe { co_register_ps_clsid(clsid_a.as_ptr(), overwrite_iid.as_ptr()) };
        assert_eq!(hr, S_OK);

        // Register same IID → different CLSID
        let clsid_b: [u8; 16] = [
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22,
        ];
        let hr = unsafe { co_register_ps_clsid(clsid_b.as_ptr(), overwrite_iid.as_ptr()) };
        assert_eq!(hr, S_OK);

        // Now CoGetPSClsid should return the new CLSID
        let mut clsid_out = [0u8; 16];
        let hr = unsafe { co_get_ps_clsid(overwrite_iid.as_ptr(), clsid_out.as_mut_ptr()) };
        assert_eq!(hr, S_OK);
        assert_eq!(clsid_out, clsid_b);
    }

    // ── CreateStreamOnHGlobal / IStream tests ─────────────────────────

    fn stream_vtbl(stm: *mut HGlobalStream) -> *const IStreamVtbl {
        unsafe { (*stm).vtable }
    }

    fn make_stream(delete_on_release: i32) -> *mut HGlobalStream {
        let mut stm: usize = 0;
        let hr = unsafe { create_stream_on_hglobal(0, delete_on_release, &mut stm) };
        assert_eq!(hr, S_OK as i32);
        assert_ne!(stm, 0);
        stm as *mut HGlobalStream
    }

    fn swrite(stm: *mut HGlobalStream, data: &[u8]) -> u32 {
        let vtbl = unsafe { &*stream_vtbl(stm) };
        let mut written: u32 = 0;
        let hr = unsafe { (vtbl.write)(stm, data.as_ptr(), data.len() as u32, &mut written) };
        assert_eq!(hr, S_OK);
        written
    }

    fn sread(stm: *mut HGlobalStream, buf: &mut [u8]) -> u32 {
        let vtbl = unsafe { &*stream_vtbl(stm) };
        let mut read: u32 = 0;
        let hr = unsafe { (vtbl.read)(stm, buf.as_mut_ptr(), buf.len() as u32, &mut read) };
        assert_eq!(hr, S_OK);
        read
    }

    fn sseek(stm: *mut HGlobalStream, mv: i64, origin: u32) -> (u32, u64) {
        let vtbl = unsafe { &*stream_vtbl(stm) };
        let mut pos: u64 = 0;
        let hr = unsafe { (vtbl.seek)(stm, mv, origin, &mut pos) };
        (hr, pos)
    }

    fn srelease(stm: *mut HGlobalStream) -> u32 {
        let vtbl = unsafe { &*stream_vtbl(stm) };
        unsafe { (vtbl.release)(stm) }
    }

    fn sclone(stm: *mut HGlobalStream) -> *mut HGlobalStream {
        let vtbl = unsafe { &*stream_vtbl(stm) };
        let mut out: *mut () = std::ptr::null_mut();
        let hr = unsafe { (vtbl.clone)(stm, &mut out) };
        assert_eq!(hr, S_OK);
        assert!(!out.is_null());
        out as *mut HGlobalStream
    }

    // STATSTG is 8-aligned in the Win32 ABI (first member is a pointer); a
    // plain [u8; 80] only guarantees alignment 1, which would trip the debug
    // misaligned-deref check in stream_stat. Mirror the real alignment.
    #[repr(align(8))]
    struct AlignedStatStg([u8; STATSTG_SIZE]);

    fn stat_buf() -> AlignedStatStg {
        AlignedStatStg([0u8; STATSTG_SIZE])
    }

    #[test]
    fn create_stream_null_returns_s_ok_and_nonnull() {
        let mut stm: usize = 0;
        let hr = unsafe { create_stream_on_hglobal(0, 1, &mut stm) };
        assert_eq!(hr, S_OK as i32);
        assert_ne!(stm, 0);
        assert_eq!(srelease(stm as *mut HGlobalStream), 0);
    }

    #[test]
    fn create_stream_null_ppstm_returns_e_invalidarg() {
        let hr = unsafe { create_stream_on_hglobal(0, 1, std::ptr::null_mut()) };
        assert_eq!(hr, E_INVALIDARG as i32);
    }

    #[test]
    fn write_then_seek_read_roundtrip() {
        let st = make_stream(1);
        let payload = b"hello weave stream";
        assert_eq!(swrite(st, payload), payload.len() as u32);

        // position is at the end after write
        let (hr, pos) = sseek(st, 0, STREAM_SEEK_CUR);
        assert_eq!(hr, S_OK);
        assert_eq!(pos, payload.len() as u64);

        // read at EOF → S_OK with 0 bytes (never S_FALSE)
        let mut buf = [0u8; 64];
        assert_eq!(sread(st, &mut buf), 0);

        // seek to 0 and read back
        let (hr, _) = sseek(st, 0, STREAM_SEEK_SET);
        assert_eq!(hr, S_OK);
        let mut out = vec![0u8; payload.len()];
        assert_eq!(sread(st, &mut out), payload.len() as u32);
        assert_eq!(&out[..], &payload[..]);

        // seek past EOF then read → 0 bytes
        let (hr, pos) = sseek(st, payload.len() as i64 + 16, STREAM_SEEK_SET);
        assert_eq!(hr, S_OK);
        assert_eq!(pos, payload.len() as u64 + 16);
        assert_eq!(sread(st, &mut buf), 0);

        assert_eq!(srelease(st), 0);
    }

    #[test]
    fn seek_semantics_set_cur_end() {
        let st = make_stream(1);
        swrite(st, b"0123456789"); // 10 bytes

        let (hr, pos) = sseek(st, 3, STREAM_SEEK_SET);
        assert_eq!(hr, S_OK);
        assert_eq!(pos, 3);
        let (hr, pos) = sseek(st, 4, STREAM_SEEK_CUR);
        assert_eq!(hr, S_OK);
        assert_eq!(pos, 7);
        let (hr, pos) = sseek(st, -7, STREAM_SEEK_CUR);
        assert_eq!(hr, S_OK);
        assert_eq!(pos, 0);
        let (hr, pos) = sseek(st, 0, STREAM_SEEK_END);
        assert_eq!(hr, S_OK);
        assert_eq!(pos, 10);
        let (hr, pos) = sseek(st, -5, STREAM_SEEK_END);
        assert_eq!(hr, S_OK);
        assert_eq!(pos, 5);

        assert_eq!(srelease(st), 0);
    }

    #[test]
    fn seek_before_start_returns_seekerror() {
        let st = make_stream(1);
        swrite(st, b"abcd"); // size 4

        // CUR -5 from 4 → -1
        let (hr, pos) = sseek(st, -5, STREAM_SEEK_CUR);
        assert_eq!(hr, STG_E_SEEKERROR);
        assert_eq!(pos, 4); // position unchanged on error
                            // invalid origin
        let (hr, pos) = sseek(st, 0, 3);
        assert_eq!(hr, STG_E_SEEKERROR);
        assert_eq!(pos, 4);
        // SET with low-32-bits-as-signed negative (0x80000000) → SEEKERROR
        let (hr, _) = sseek(st, 0x8000_0000, STREAM_SEEK_SET);
        assert_eq!(hr, STG_E_SEEKERROR);
        // forward seek into the 0x80000000 region is fine (positive move)
        let (hr, pos) = sseek(st, 0x8000_0000 - 4, STREAM_SEEK_CUR);
        assert_eq!(hr, S_OK);
        assert_eq!(pos, 0x8000_0000);

        assert_eq!(srelease(st), 0);
    }

    #[test]
    fn stat_reports_size_and_type() {
        let st = make_stream(1);
        swrite(st, b"0123456789ABCDEF");

        let vtbl = unsafe { &*stream_vtbl(st) };
        let hr = unsafe { (vtbl.set_size)(st, 0x8000) };
        assert_eq!(hr, S_OK);

        let mut statbuf = AlignedStatStg([0xEEu8; STATSTG_SIZE]);
        let hr = unsafe { (vtbl.stat)(st, statbuf.0.as_mut_ptr(), 0) };
        assert_eq!(hr, S_OK);
        assert_eq!(
            u32::from_le_bytes(
                statbuf.0[STATSTG_TYPE_OFFSET..STATSTG_TYPE_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            STGTY_STREAM
        );
        assert_eq!(
            u64::from_le_bytes(
                statbuf.0[STATSTG_CBSIZE_OFFSET..STATSTG_CBSIZE_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            0x8000
        );
        // pwcsName is NULL
        assert_eq!(u64::from_le_bytes(statbuf.0[0..8].try_into().unwrap()), 0);
        // clsid is GUID_NULL
        assert_eq!(u64::from_le_bytes(statbuf.0[56..64].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(statbuf.0[64..72].try_into().unwrap()), 0);

        assert_eq!(srelease(st), 0);
    }

    #[test]
    fn set_size_uses_low_32_bits_only() {
        let st = make_stream(1);
        swrite(st, b"data");
        let vtbl = unsafe { &*stream_vtbl(st) };
        // HighPart bits are ignored (Wine LowPart-only semantics) — a huge
        // QuadPart with LowPart == current size must be S_OK and keep size.
        let hr = unsafe { (vtbl.set_size)(st, 0xFFFF_FFFF_0000_0004) };
        assert_eq!(hr, S_OK);
        let mut statbuf = stat_buf();
        unsafe { (vtbl.stat)(st, statbuf.0.as_mut_ptr(), 0) };
        assert_eq!(
            u64::from_le_bytes(
                statbuf.0[STATSTG_CBSIZE_OFFSET..STATSTG_CBSIZE_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            4
        );
        assert_eq!(srelease(st), 0);
    }

    #[test]
    fn copy_to_copies_content() {
        let src = make_stream(1);
        let dst = make_stream(1);
        let payload = b"Copy me over";
        swrite(src, payload);
        let (hr, _) = sseek(src, 0, STREAM_SEEK_SET);
        assert_eq!(hr, S_OK);

        let vtbl = unsafe { &*stream_vtbl(src) };
        let mut read_out: u64 = 0;
        let mut written_out: u64 = 0;
        let hr = unsafe {
            (vtbl.copy_to)(
                src,
                dst as *mut (),
                payload.len() as u64,
                &mut read_out,
                &mut written_out,
            )
        };
        assert_eq!(hr, S_OK);
        assert_eq!(read_out, payload.len() as u64);
        assert_eq!(written_out, payload.len() as u64);

        // destination holds the same content
        let (hr, _) = sseek(dst, 0, STREAM_SEEK_SET);
        assert_eq!(hr, S_OK);
        let mut out = vec![0u8; payload.len()];
        assert_eq!(sread(dst, &mut out), payload.len() as u32);
        assert_eq!(&out[..], &payload[..]);

        assert_eq!(srelease(src), 0);
        assert_eq!(srelease(dst), 0);
    }

    #[test]
    fn copy_to_null_dest_returns_invalidpointer() {
        let src = make_stream(1);
        swrite(src, b"data");
        let vtbl = unsafe { &*stream_vtbl(src) };
        let hr = unsafe {
            (vtbl.copy_to)(
                src,
                std::ptr::null_mut(),
                4,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(hr, STG_E_INVALIDPOINTER);
        assert_eq!(srelease(src), 0);
    }

    #[test]
    fn clone_duplicates_position_and_shares_handle() {
        let mut stm: usize = 0;
        let hr = unsafe { create_stream_on_hglobal(0, 1, &mut stm) };
        assert_eq!(hr, S_OK as i32);
        let st = stm as *mut HGlobalStream;
        let payload = b"clone me";
        swrite(st, payload);

        // clone at current position (end of stream)
        let clone = sclone(st);
        let (hr, cpos) = sseek(clone, 0, STREAM_SEEK_CUR);
        assert_eq!(hr, S_OK);
        assert_eq!(cpos, payload.len() as u64);

        // both streams report the same backing HGLOBAL
        let mut h1: usize = 0;
        let mut h2: usize = 0;
        assert_eq!(
            unsafe { get_hglobal_from_stream(stm, &mut h1) },
            S_OK as i32
        );
        assert_eq!(
            unsafe { get_hglobal_from_stream(clone as usize, &mut h2) },
            S_OK as i32
        );
        assert_ne!(h1, 0);
        assert_eq!(h1, h2);

        // clone sees data written by the source (shared buffer)
        let (hr, _) = sseek(clone, 0, STREAM_SEEK_SET);
        assert_eq!(hr, S_OK);
        let mut out = vec![0u8; payload.len()];
        assert_eq!(sread(clone, &mut out), payload.len() as u32);
        assert_eq!(&out[..], &payload[..]);

        assert_eq!(srelease(clone), 0);
        assert_eq!(srelease(st), 0);
    }

    #[test]
    fn delete_on_release_false_keeps_hglobal() {
        // Caller-supplied HGLOBAL with fDeleteOnRelease=FALSE: the stream must
        // NOT free it — a subsequent libc::free here is a single free (a
        // double-free from a bug would abort).
        let hg = unsafe { libc::malloc(64) as usize };
        assert_ne!(hg, 0);
        let mut stm: usize = 0;
        let hr = unsafe { create_stream_on_hglobal(hg, 0, &mut stm) };
        assert_eq!(hr, S_OK as i32);
        let st = stm as *mut HGlobalStream;
        swrite(st, b"persistent");
        assert_eq!(srelease(st), 0);
        unsafe { libc::free(hg as *mut libc::c_void) };
    }

    #[test]
    fn delete_on_release_true_clone_keeps_handle_alive() {
        let st = make_stream(1);
        let payload = b"shared";
        swrite(st, payload);
        let clone = sclone(st);

        // Releasing the original stream drops only its own reference; the
        // shared HandleWrapper survives via the clone.
        assert_eq!(srelease(st), 0);

        // Clone still reads the shared buffer — the HGLOBAL was not freed.
        let (hr, _) = sseek(clone, 0, STREAM_SEEK_SET);
        assert_eq!(hr, S_OK);
        let mut out = vec![0u8; payload.len()];
        assert_eq!(sread(clone, &mut out), payload.len() as u32);
        assert_eq!(&out[..], &payload[..]);

        // Last release → HandleWrapper drops → HGLOBAL freed (no crash here).
        assert_eq!(srelease(clone), 0);
    }

    #[test]
    fn stream_qi_returns_requested_interfaces() {
        let st = make_stream(1);
        let vtbl = unsafe { &*stream_vtbl(st) };
        let mut ppv: *mut () = std::ptr::null_mut();

        for iid in [IID_ISTREAM, IID_ISEQUENTIALSTREAM, IID_IUNKNOWN_BYTES] {
            let hr = unsafe { (vtbl.query_interface)(st, iid.as_ptr(), &mut ppv) };
            assert_eq!(hr, S_OK);
            assert_eq!(ppv, st as *mut ());
        }

        let bogus: [u8; 16] = [0xAA; 16];
        let hr = unsafe { (vtbl.query_interface)(st, bogus.as_ptr(), &mut ppv) };
        assert_eq!(hr, E_NOINTERFACE);

        // 3 successful QIs added 3 refs → refcount 4 → 4 releases frees.
        assert_eq!(srelease(st), 3);
        assert_eq!(srelease(st), 2);
        assert_eq!(srelease(st), 1);
        assert_eq!(srelease(st), 0);
    }

    #[test]
    fn get_hglobal_from_stream_validation() {
        // null stream
        let mut hg: usize = 0;
        assert_eq!(
            unsafe { get_hglobal_from_stream(0, &mut hg) },
            E_INVALIDARG as i32
        );
        // null out param
        let mut stm: usize = 0;
        let hr = unsafe { create_stream_on_hglobal(0, 1, &mut stm) };
        assert_eq!(hr, S_OK as i32);
        assert_eq!(
            unsafe { get_hglobal_from_stream(stm, std::ptr::null_mut()) },
            E_INVALIDARG as i32
        );
        // foreign stream (an IUnknownImpl, not created by CreateStreamOnHGlobal)
        let foreign = weave_common::com::iunknown::IUnknownImpl::new();
        let fptr = Box::into_raw(foreign);
        assert_eq!(
            unsafe { get_hglobal_from_stream(fptr as usize, &mut hg) },
            E_INVALIDARG as i32
        );
        // release the foreign object through its own vtable
        let vtbl = unsafe { &*(*fptr).vtable };
        assert_eq!(unsafe { (vtbl.release)(fptr) }, 0);
        // valid stream → returns its backing HGLOBAL
        assert_eq!(
            unsafe { get_hglobal_from_stream(stm, &mut hg) },
            S_OK as i32
        );
        assert_ne!(hg, 0);
        assert_eq!(srelease(stm as *mut HGlobalStream), 0);
    }

    #[test]
    fn lock_region_commit_revert_contract() {
        let st = make_stream(1);
        swrite(st, b"data");
        let vtbl = unsafe { &*stream_vtbl(st) };
        assert_eq!(
            unsafe { (vtbl.lock_region)(st, 0, 4, 1) },
            STG_E_INVALIDFUNCTION
        );
        assert_eq!(unsafe { (vtbl.unlock_region)(st, 0, 4, 1) }, S_OK);
        assert_eq!(unsafe { (vtbl.commit)(st, 0) }, S_OK);
        assert_eq!(unsafe { (vtbl.revert)(st) }, S_OK);
        assert_eq!(srelease(st), 0);
    }
}
