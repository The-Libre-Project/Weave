//! ole32.dll / combase.dll stubs for Weave.
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

/// CoInitializeEx: initialise the COM library on the calling thread.
///
/// Returns `S_OK` on first call, `S_FALSE` if COM was already initialised on
/// this thread, or `RPC_E_CHANGED_MODE` (0x80010106) if the apartment model
/// conflicts with a previous call.
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

/// CoInitialize: legacy variant (always STA).
pub extern "win64" fn co_initialize(pv_reserved: usize) -> u32 {
    co_initialize_ex(pv_reserved, COINIT_APARTMENTTHREADED)
}

/// CoUninitialize: decrement the COM initialisation count for this thread.
///
/// When the count reaches zero the thread's apartment is torn down (no-op in
/// Phase 2).
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

/// CoCreateInstance: create a single uninitialized object of a given class.
///
/// Phase 2: returns `REGDB_E_CLASSNOTREG` for all CLSIDs. The primary purpose
/// is to prevent a crash when apps call this at startup — they should handle
/// the failure gracefully (most do, falling back to built-in alternatives).
///
/// # Safety
/// `rclsid` and `riid` must be valid pointers to 16-byte GUID structs.
/// `ppv` must be a valid writable pointer to a `*mut c_void` output slot.
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

    eprintln!(
        "weave/ole32: CoCreateInstance: CLSID {:02x?} (stub — REGDB_E_CLASSNOTREG)",
        clsid
    );

    REGDB_E_CLASSNOTREG
}

/// CoCreateInstanceEx: extended version of CoCreateInstance (stub).
///
/// # Safety
/// `rclsid` must be a valid pointer to a 16-byte GUID.
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

/// CoTaskMemAlloc: allocate a block of task memory.
///
/// Equivalent to `malloc`; returns NULL on failure.
pub extern "win64" fn co_task_mem_alloc(cb: usize) -> usize {
    if cb == 0 {
        return 0;
    }
    unsafe { libc::malloc(cb) as usize }
}

/// CoTaskMemFree: free task memory allocated by CoTaskMemAlloc.
pub extern "win64" fn co_task_mem_free(pv: usize) {
    if pv != 0 {
        unsafe { libc::free(pv as *mut libc::c_void) };
    }
}

/// CoTaskMemRealloc: resize a task memory block.
pub extern "win64" fn co_task_mem_realloc(pv: usize, cb: usize) -> usize {
    if cb == 0 {
        co_task_mem_free(pv);
        return 0;
    }
    unsafe { libc::realloc(pv as *mut libc::c_void, cb) as usize }
}

// ── GUID utilities ────────────────────────────────────────────────────────────

/// StringFromGUID2: convert a GUID to its string representation.
///
/// Writes `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\0` (39 chars including NUL)
/// into `lpsz` and returns 39 (the number of characters written including NUL).
/// Returns 0 if `cch_max < 39` or if pointers are null.
///
/// # Safety
/// `rclsid` must be a valid pointer to a 16-byte GUID.
/// `lpsz` must be a writable buffer of at least `cch_max` UTF-16 code units.
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

/// CLSIDFromString: convert a CLSID string to a CLSID.
///
/// # Safety
/// `lpsz` must be a null-terminated UTF-16 string.
/// `pclsid` must be a writable 16-byte buffer.
pub unsafe extern "win64" fn clsid_from_string(lpsz: *const u16, pclsid: *mut u8) -> u32 {
    if lpsz.is_null() || pclsid.is_null() {
        return E_INVALIDARG;
    }
    let mut len = 0usize;
    while unsafe { *lpsz.add(len) } != 0 {
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

/// IIDFromString: same as CLSIDFromString (IID and CLSID are both GUIDs).
///
/// # Safety
/// Same as `CLSIDFromString`.
pub unsafe extern "win64" fn iid_from_string(lpsz: *const u16, piid: *mut u8) -> u32 {
    unsafe { clsid_from_string(lpsz, piid) }
}

// ── OLE initialisation ────────────────────────────────────────────────────────

/// OleInitialize: initialise OLE on the calling thread (STA).
pub extern "win64" fn ole_initialize(pv_reserved: usize) -> u32 {
    co_initialize(pv_reserved)
}

/// OleUninitialize: uninitialise OLE on the calling thread.
pub extern "win64" fn ole_uninitialize() {
    co_uninitialize();
}

// ── Security / proxy stubs ────────────────────────────────────────────────────

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

/// CoGetClassObject: retrieve the class factory for a given CLSID (stub).
///
/// Returns `REGDB_E_CLASSNOTREG` — no class factories in Phase 2.
///
/// # Safety
/// Pointer arguments must be null or valid.
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

pub extern "win64" fn co_unmarshal_interface(_p_stm: usize, _riid: usize, _ppv: usize) -> u32 {
    CO_E_NOTINITIALIZED
}

/// CoDisconnectObject: disconnect a running object from its external connections (stub).
pub extern "win64" fn co_disconnect_object(_punk: usize, _dw_reserved: u32) -> u32 {
    S_OK
}

/// ProgIDFromCLSID: return the ProgID for a given CLSID (stub).
///
/// # Safety
/// `_rclsid` must be null or a valid pointer to a 16-byte CLSID.
/// `lp_sz_prog_id` must be a valid writable pointer to a `*mut u16` output slot.
pub unsafe extern "win64" fn prog_id_from_clsid(
    _rclsid: *const u8,
    lp_sz_prog_id: *mut *mut u16,
) -> u32 {
    if !lp_sz_prog_id.is_null() {
        unsafe { *lp_sz_prog_id = std::ptr::null_mut() };
    }
    REGDB_E_CLASSNOTREG
}

/// CLSIDFromProgID: return the CLSID for a given ProgID (stub).
///
/// # Safety
/// `_lpsz_prog_id` must be null or a valid null-terminated UTF-16 string.
/// `lpclsid` must be a valid writable 16-byte buffer.
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

/// ReleaseStgMedium — release a STGMEDIUM storage medium. No-op stub.
///
/// # Safety
/// `pmedium` is accepted but not dereferenced.
pub unsafe extern "win64" fn release_stg_medium(_pmedium: *mut u8) {}

/// RegisterDragDrop — register a window as a drag-drop target. Returns E_NOTIMPL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn register_drag_drop(_hwnd: usize, _p_drop_target: *mut u8) -> i32 {
    0x8000_4001u32 as i32 // E_NOTIMPL
}

/// RevokeDragDrop — revoke a window's drag-drop registration. Returns S_OK.
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn revoke_drag_drop(_hwnd: usize) -> i32 {
    0 // S_OK
}

/// DoDragDrop — initiate a drag-and-drop operation. Returns DRAGDROP_S_CANCEL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn do_drag_drop(
    _p_data_obj: *mut u8,
    _p_drop_source: *mut u8,
    _dw_ok_effects: u32,
    _pdw_effect: *mut u32,
) -> i32 {
    0x0004_0101u32 as i32 // DRAGDROP_S_CANCEL
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Resolve a `ole32.dll` or `combase.dll` import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
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
        "IIDFromString" => {
            Some(iid_from_string as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // OLE
        "OleInitialize" => Some(ole_initialize as *const () as usize),
        "OleUninitialize" => Some(ole_uninitialize as *const () as usize),
        // Security / proxy
        "CoSetProxyBlanket" => Some(co_set_proxy_blanket as *const () as usize),
        "CoInitializeSecurity" => Some(co_initialize_security as *const () as usize),
        // Marshalling (stubs)
        "CoMarshalInterface" => Some(co_marshal_interface as *const () as usize),
        "CoUnmarshalInterface" => Some(co_unmarshal_interface as *const () as usize),
        "CoDisconnectObject" => Some(co_disconnect_object as *const () as usize),
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
        _ => None,
    }
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
