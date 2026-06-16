//! oleaut32.dll stubs for Weave.
//!
//! OLEAUT32 is the OLE Automation DLL. 7-Zip imports several functions by
//! ordinal. The IAT patcher formats ordinal N as the string "#N", so the
//! resolver must match both "#N" and the named alias.
//!
//! Ordinal map (from Windows OLEAUT32 export table):
//!   #2   → SysAllocString
//!   #3   → SysReAllocString
//!   #4   → SysAllocStringLen
//!   #5   → SysReAllocStringLen
//!   #6   → SysFreeString
//!   #7   → SysStringLen
//!   #8   → SysStringByteLen
//!   #9   → VariantClear
//!   #10  → VariantInit
//!   #11  → VariantCopy
//!   #149 → (alias; #4 is the canonical SysAllocStringLen ordinal)

#![allow(non_snake_case)]

// ── BSTR functions ───────────────────────────────────────────────────────────

/// SysAllocString — allocate a BSTR from a null-terminated wide string.
///
/// A BSTR is a length-prefixed wide string. This stub allocates via libc and
/// returns a pointer past the 4-byte length prefix, matching the Windows ABI.
///
/// Returns NULL on failure or if `psz` is NULL.
///
/// # Safety
/// `psz` must be a valid null-terminated UTF-16 string or null.
pub unsafe extern "win64" fn sys_alloc_string(psz: *const u16) -> *mut u16 {
    if psz.is_null() {
        eprintln!("weave/SysAllocString: psz=NULL → NULL");
        return std::ptr::null_mut();
    }
    let mut len = 0usize;
    // Pointer validation: cap to prevent OOB read and huge allocations.
    const MAX_BSTR_LEN: usize = 65_536;
    while len < MAX_BSTR_LEN && unsafe { *psz.add(len) } != 0 {
        len += 1;
    }
    let byte_len = len * 2;
    let total_bytes = 4 + byte_len + 2; // prefix + chars + null
    let buf = unsafe { libc::malloc(total_bytes) as *mut u8 };
    if buf.is_null() {
        eprintln!("weave/SysAllocString: malloc({total_bytes}) failed → NULL");
        return std::ptr::null_mut();
    }
    unsafe { *(buf as *mut u32) = byte_len as u32 };
    let data = unsafe { buf.add(4) as *mut u16 };
    unsafe { std::ptr::copy_nonoverlapping(psz, data, len + 1) };
    // Show up to 16 ASCII-ish chars for diagnostic.
    let mut ascii = String::new();
    for i in 0..len.min(16) {
        let c = unsafe { *psz.add(i) };
        if (0x20..0x7f).contains(&c) {
            ascii.push(c as u8 as char);
        } else {
            ascii.push_str(&format!("\\u{c:04x}"));
        }
    }
    eprintln!("weave/SysAllocString: len={len} bstr={data:p} chars=\"{ascii}\"");
    data
}

/// SysAllocStringLen — allocate a BSTR of given length.
///
/// # Safety
/// If `psz` is non-null, it must be valid for at least `len` u16 elements.
pub unsafe extern "win64" fn sys_alloc_string_len(psz: *const u16, len: u32) -> *mut u16 {
    let byte_len = (len as usize) * 2;
    let total_bytes = 4 + byte_len + 2;
    let buf = unsafe { libc::malloc(total_bytes) as *mut u8 };
    if buf.is_null() {
        eprintln!("weave/SysAllocStringLen: malloc({total_bytes}) failed → NULL");
        return std::ptr::null_mut();
    }
    unsafe { *(buf as *mut u32) = byte_len as u32 };
    let data = unsafe { buf.add(4) as *mut u16 };
    if !psz.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(psz, data, len as usize) };
    } else {
        unsafe { std::ptr::write_bytes(data as *mut u8, 0, byte_len) };
    }
    unsafe { *data.add(len as usize) = 0 };
    let mut ascii = String::new();
    if !psz.is_null() {
        for i in 0..(len as usize).min(16) {
            let c = unsafe { *psz.add(i) };
            if (0x20..0x7f).contains(&c) {
                ascii.push(c as u8 as char);
            } else {
                ascii.push_str(&format!("\\u{c:04x}"));
            }
        }
    }
    eprintln!("weave/SysAllocStringLen: psz={psz:p} len={len} bstr={data:p} chars=\"{ascii}\"");
    data
}

/// SysFreeString — free a BSTR allocated by SysAllocString*.
///
/// # Safety
/// `bstr` must be a BSTR allocated by `sys_alloc_string*`, or null.
pub unsafe extern "win64" fn sys_free_string(bstr: *mut u16) {
    if bstr.is_null() {
        eprintln!("weave/SysFreeString: bstr=NULL");
        return;
    }
    let byte_len = unsafe { *((bstr as *const u8).sub(4) as *const u32) };
    eprintln!("weave/SysFreeString: bstr={bstr:p} byte_len={byte_len}");
    let alloc = unsafe { (bstr as *mut u8).sub(4) };
    unsafe { libc::free(alloc as *mut libc::c_void) };
}

/// SysStringLen — return the number of characters in a BSTR.
///
/// # Safety
/// `bstr` must be a valid BSTR or null.
pub unsafe extern "win64" fn sys_string_len(bstr: *const u16) -> u32 {
    if bstr.is_null() {
        return 0;
    }
    let prefix = unsafe { *((bstr as *const u8).sub(4) as *const u32) };
    prefix / 2 // bytes → char count
}

/// SysStringByteLen — return the byte length of a BSTR (excluding the null terminator).
///
/// Returns 0 if `bstr` is null.
///
/// # Safety
/// `bstr` must be a valid BSTR or null.
// Wine ref: dlls/oleaut32/oleaut.c — SysStringByteLen reads the 4-byte prefix
// stored by SysAllocStringByteLen/SysAllocString; returns 0 on NULL.
pub unsafe extern "win64" fn sys_string_byte_len(bstr: *const u16) -> u32 {
    if bstr.is_null() {
        return 0;
    }
    unsafe { *((bstr as *const u8).sub(4) as *const u32) } // raw byte count from prefix
}

// ── SafeArray ────────────────────────────────────────────────────────────────

/// SafeArrayCreate — create a safe array. Returns NULL (stub).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn safe_array_create(
    _vt: u16,
    _c_dims: u32,
    _rgsabound: *const u8,
) -> *mut u8 {
    std::ptr::null_mut() // stub — no real SafeArray
}

/// SafeArrayDestroy — destroy a safe array. Returns S_OK (0).
///
/// # Safety
/// `psa` is accepted but not dereferenced (stub does nothing).
pub unsafe extern "win64" fn safe_array_destroy(_psa: *mut u8) -> i32 {
    0 // S_OK
}

// ── VARIANT ──────────────────────────────────────────────────────────────────

/// VariantInit — initialise a VARIANT to VT_EMPTY. Zeroes the 16-byte struct.
///
/// # Safety
/// `pvar` must be a writable 16-byte buffer.
pub unsafe extern "win64" fn variant_init(pvar: *mut u8) {
    if !pvar.is_null() {
        unsafe { std::ptr::write_bytes(pvar, 0, 16) };
    }
}

/// VariantClear — clear a VARIANT and release any resources. Returns S_OK.
///
/// Sets vt = VT_EMPTY (offset 0..2) and zeroes the data union (offset 8..16).
/// The reserved fields wReserved1/2/3 (offset 2..8) are intentionally NOT
/// modified — real Windows VariantClear leaves them untouched.
///
/// Wine ref: dlls/oleaut32/variant.c — VariantClear calls VARIANT_ValidateType,
/// frees the inner type (BSTR/SafeArray/IUnknown/IRecordInfo), then sets
/// V_VT(pVarg) = VT_EMPTY and returns. Reserved fields are never written.
/// (Wine source line 627–666: `V_VT(pVarg) = VT_EMPTY;` is the only field
/// assignment after freeing the payload.)
///
/// MSVC's CPropVariant stores 0xff00 in wReserved2 as a validity sentinel.
/// Zeroing that field caused WriteHeader to return E_INVALIDARG on the M13
/// MSVC gate. Class: MSVC_ABI_MISMATCH — follow-up G (2026-05-15).
///
/// # Safety
/// `pvar` must be a writable 16-byte buffer.
pub unsafe extern "win64" fn variant_clear(pvar: *mut u8) -> i32 {
    if pvar.is_null() {
        eprintln!("weave/VariantClear: pvar=NULL");
        return 0;
    }
    // SAFETY: (a) pvar is non-null (checked above); the VARIANT struct is 16 bytes and
    // the offsets 0, 2, 4, 6, 8 all lie within that 16-byte layout; (b) guest heap —
    // caller owns the VARIANT buffer; (c) duration of this call; (d) gate:
    // sevenzip_m13_debug_e_gate (CI 26007699626).
    let prior_vt = unsafe { *(pvar as *const u16) };
    let res1 = unsafe { *(pvar.add(2) as *const u16) };
    let res2 = unsafe { *(pvar.add(4) as *const u16) };
    let res3 = unsafe { *(pvar.add(6) as *const u16) };
    let val_lo = unsafe { *(pvar.add(8) as *const u64) };
    eprintln!(
        "weave/VariantClear: pvar={pvar:p} vt={prior_vt} res=[{res1:#x},{res2:#x},{res3:#x}] val={val_lo:#018x}"
    );
    // For VT_BSTR (vt=8), free the BSTR; for VT_DISPATCH/UNKNOWN (9,13) we'd
    // need to call Release, but those aren't expected on the M13 path.
    const VT_BSTR: u16 = 8;
    if prior_vt == VT_BSTR && val_lo != 0 {
        let bstr = val_lo as *mut u16;
        // SAFETY: (a) bstr is non-null (val_lo != 0 checked above) and was allocated by
        // Weave's SysAllocStringLen via libc::malloc, which stores a 4-byte byte-length
        // prefix at offset -4 (Windows BSTR layout); (b) guest heap — BSTR was malloc'd
        // by this process's SysAllocStringLen; (c) duration of this call; (d) gate:
        // sevenzip_m13_debug_e_gate (CI 26007699626). LIMITATION: if the BSTR was
        // allocated by a non-Weave SysAllocString, the -4 byte offset assumption is
        // incorrect; no cross-allocator BSTR currently observed in Weave.
        let alloc = unsafe { (bstr as *mut u8).sub(4) };
        unsafe { libc::free(alloc as *mut libc::c_void) };
    }
    // Zero only vt (offset 0..2) and data union (offset 8..16).
    // wReserved1/2/3 (offset 2..8) are NOT touched — Windows does not write
    // them and MSVC CPropVariant relies on wReserved2=0xff00 surviving this call.
    // SAFETY: (a) pvar is non-null (checked at entry) and points to a 16-byte VARIANT
    // buffer; offsets 0 and 8 both lie within the 16-byte layout; (b) guest heap —
    // caller owns the VARIANT; (c) duration of this call; (d) gate:
    // sevenzip_m13_debug_e_gate (CI 26007699626).
    unsafe {
        std::ptr::write_bytes(pvar, 0, 2); // vt = VT_EMPTY
        std::ptr::write_bytes(pvar.add(8), 0, 8); // data union cleared
    }
    0 // S_OK
}

/// VariantCopy — copy a VARIANT, deep-cloning any reference-type payload.
///
/// Win32 layout (VARIANT, 16 bytes on x64):
///   offset 0..2   : VARTYPE vt
///   offset 2..8   : reserved (wReserved1/2/3, must be preserved or zeroed)
///   offset 8..16  : union (BSTR, IUnknown*, scalar, etc.)
///
/// 7-Zip's CPropVariant::Copy delegates to ::VariantCopy for non-simple types
/// including VT_BSTR. If unresolved, the destination stays VT_EMPTY and the
/// caller's encoder rejects the property with E_INVALIDARG — observed as the
/// M13 sevenzip_m13_roundtrip_gate failure path through LzmaEncoder.cpp:203.
///
/// This implementation handles the common VT codes used by 7-Zip:
///   • simple by-value (VT_EMPTY, VT_NULL, VT_I1..VT_UI8, VT_BOOL, VT_R4/R8,
///     VT_ERROR, VT_FILETIME, VT_DATE, VT_CY, VT_DECIMAL) → 16-byte memcpy
///   • VT_BSTR → SysAllocStringLen-equivalent deep copy
///
/// For unsupported reference types (VT_DISPATCH/UNKNOWN/SAFEARRAY/VARIANT/
/// pointer-to-anything), falls through to a 16-byte memcpy (matches what
/// "unresolved → S_OK" would have done, but at least produces a valid copy
/// of the discriminant — better than leaving the destination VT_EMPTY).
///
/// Returns S_OK on success, E_OUTOFMEMORY if the BSTR allocation fails.
///
/// # Safety
/// Both pointers must be valid 16-byte writable/readable VARIANT buffers.
// Wine ref: dlls/oleaut32/variant.c:696 — pvargDest cleared via VariantClear before copy;
// VT_BSTR deep-cloned via SysAllocStringByteLen; pvargSrc==pvargDest is a no-op (S_OK);
// shallow 16-byte copy for all other by-value types; DISP_E_BADVARTYPE on VT_CLSID or invalid vt.
pub unsafe extern "win64" fn variant_copy(pdest: *mut u8, psrc: *const u8) -> i32 {
    if pdest.is_null() || psrc.is_null() {
        return 0; // S_OK — Windows: VariantCopy with NULL returns DISP_E_BADVARTYPE,
                  // but the unresolved-stub fallback would have returned 0; keep that
                  // for the rare edge case to avoid behavior regressions.
    }
    // 1. Clear destination first (matches VariantClear semantics; releases any
    //    prior BSTR pointed at by pdest).
    // SAFETY: (a) pdest is non-null (checked above); (b) guest heap — caller owns the
    // VARIANT buffer; (c) duration of this call; (d) gate: sevenzip_m13_debug_e_gate
    // (CI 26007699626).
    let _ = unsafe { variant_clear(pdest) };
    // 2. Read source vt.
    // SAFETY: (a) psrc is non-null (checked above) and points to a 16-byte VARIANT buffer;
    // offset 0 (vt field) lies within that layout; (b) guest heap; (c) duration of call;
    // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let src_vt = unsafe { *(psrc as *const u16) };
    // 3. Handle VT_BSTR specially — deep-clone the string.
    const VT_BSTR: u16 = 8;
    if src_vt == VT_BSTR {
        // SAFETY: (a) psrc is non-null (checked above) and points to a 16-byte VARIANT;
        // offset 8 is the data union which holds the BSTR pointer for VT_BSTR;
        // (b) guest heap; (c) duration of call; (d) gate: sevenzip_m13_debug_e_gate
        // (CI 26007699626).
        let src_bstr = unsafe { *(psrc.add(8) as *const *const u16) };
        let new_bstr = if src_bstr.is_null() {
            std::ptr::null_mut()
        } else {
            // BSTR is preceded by a 4-byte byte-length prefix.
            // SAFETY: (a) src_bstr is non-null (checked above); the BSTR was allocated by
            // Weave's SysAllocStringLen via libc::malloc, which stores a 4-byte byte-length
            // prefix at offset -4 (Windows BSTR layout); (b) guest heap — BSTR was
            // malloc'd by this process's SysAllocStringLen; (c) duration of this call;
            // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626). LIMITATION: if
            // src_bstr was allocated by a non-Weave SysAllocString, this -4 byte offset
            // assumption is incorrect; no cross-allocator BSTR currently observed in Weave.
            let byte_len = unsafe { *((src_bstr as *const u8).sub(4) as *const u32) } as usize;
            let total = 4 + byte_len + 2;
            // SAFETY: (a) malloc returns a valid heap allocation or null; null is checked
            // below; (b) Weave process heap (libc::malloc); (c) duration of this call
            // and beyond — the allocation is handed off to the destination VARIANT;
            // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
            let buf = unsafe { libc::malloc(total) as *mut u8 };
            if buf.is_null() {
                return 0x8007_000Eu32 as i32; // E_OUTOFMEMORY
            }
            // SAFETY: (a) buf is non-null (checked above) and points to `total` bytes
            // allocated by libc::malloc; offset 0 (4-byte length prefix) is within the
            // allocation; (b) Weave process heap; (c) duration of this scope;
            // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
            unsafe { *(buf as *mut u32) = byte_len as u32 };
            // SAFETY: (a) buf is non-null and `total = 4 + byte_len + 2`; offset 4 is
            // within the allocation, aligned to 2 bytes (u16); (b) Weave process heap;
            // (c) duration of this scope; (d) same gate as above.
            let data = unsafe { buf.add(4) as *mut u16 };
            // SAFETY: (a) data points to `byte_len + 2` bytes within the malloc'd buf;
            // src_bstr points to `byte_len` valid bytes (its length was read from the
            // BSTR length prefix above); the +2 null-terminator lies within the allocation;
            // (b) src=guest heap, dst=Weave process heap; (c) duration of copy;
            // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
            unsafe {
                std::ptr::copy_nonoverlapping(src_bstr as *const u8, data as *mut u8, byte_len);
                *data.add(byte_len / 2) = 0;
            }
            data
        };
        // SAFETY: (a) pdest is non-null (checked at entry) and points to a 16-byte
        // VARIANT buffer; offsets 0 (vt), 2 (reserved), and 8 (data pointer) all lie
        // within that layout; (b) guest heap — caller owns pdest; (c) duration of call;
        // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
        unsafe {
            *(pdest as *mut u16) = VT_BSTR;
            // Zero wReserved1/2/3 (offset 2..8) per Windows spec.
            std::ptr::write_bytes(pdest.add(2), 0, 6);
            *(pdest.add(8) as *mut *mut u16) = new_bstr;
        }
        return 0; // S_OK
    }
    // 4. For everything else, do a flat 16-byte copy. Correct for all "by-value"
    //    variants; for VT_DISPATCH / VT_UNKNOWN this leaks a refcount but doesn't
    //    crash (7-Zip's create-archive path doesn't put interface pointers into
    //    CPropVariant values it then copies).
    // SAFETY: (a) both psrc and pdest are non-null (checked at entry) and each points
    // to a 16-byte VARIANT buffer; src and dst do not overlap because they are distinct
    // VARIANT allocations owned by the caller; (b) guest heap; (c) duration of call;
    // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    unsafe {
        std::ptr::copy_nonoverlapping(psrc, pdest, 16);
    }
    0 // S_OK
}

// ── Error info / SAFEARRAY / new stubs ────────────────────────────────────────

// Wine ref: dlls/oleaut32/errorinfo.c — GetErrorInfo retrieves the per-thread error
// object set by SetErrorInfo; clears the thread-local on success; returns S_OK(0) if
// an error object is set, S_FALSE(1) if no error object is set; pperrinfo zeroed on S_FALSE.
/// GetErrorInfo (oleaut32 #8) — retrieve the per-thread error object.
///
/// Returns S_FALSE (1) — no error object set (stub). Writes NULL to *pperrinfo if non-null.
///
/// # Safety
/// `pperrinfo` must be null or a valid writable pointer-to-pointer.
pub unsafe extern "win64" fn get_error_info(_dw_reserved: u32, pperrinfo: *mut *mut u8) -> i32 {
    // SAFETY: caller guarantees pperrinfo is null or a valid writable slot.
    if !pperrinfo.is_null() {
        unsafe { *pperrinfo = std::ptr::null_mut() };
    }
    1 // S_FALSE — no error object
}

// Wine ref: dlls/oleaut32/variant.c — VariantChangeType converts source variant to vt
// via VARIANT_Coerce; updates pdest in-place if pdest==psrc; returns DISP_E_TYPEMISMATCH
// if conversion not supported; calls VariantClear on pdest before writing new value.
/// VariantChangeType (oleaut32 #12) — convert a VARIANT to a new type.
///
/// Returns DISP_E_TYPEMISMATCH (0x80020005) — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn variant_change_type(
    _pvarg_dest: *mut u8,
    _pvarg_src: *const u8,
    _w_flags: u16,
    _vt: u16,
) -> i32 {
    0x80020005u32 as i32 // DISP_E_TYPEMISMATCH
}

// Wine ref: dlls/oleaut32/oleaut.c — SysAllocStringByteLen allocates a BSTR from raw bytes;
// length prefix stores the byte count (not char count); appends 2-byte null terminator;
// returns NULL if psz is NULL or allocation fails.
/// SysAllocStringByteLen (oleaut32 #16) — allocate a BSTR from a byte string.
///
/// Returns NULL (stub — Q-Dir startup path does not require a valid BSTR here).
///
/// # Safety
/// `psz` must be null or valid for `len` bytes.
pub unsafe extern "win64" fn sys_alloc_string_byte_len(psz: *const u8, len: u32) -> *mut u16 {
    if psz.is_null() {
        return std::ptr::null_mut();
    }
    // Allocate: 4-byte length prefix + len bytes + 2-byte null terminator.
    let total = 4 + (len as usize) + 2;
    // SAFETY: malloc returns a valid allocation or null; checked below.
    let buf = unsafe { libc::malloc(total) as *mut u8 };
    if buf.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: buf is non-null, total bytes allocated; offset 0 is within allocation.
    unsafe { *(buf as *mut u32) = len };
    // SAFETY: buf is non-null; offset 4 is within allocation.
    let data = unsafe { buf.add(4) };
    // SAFETY: psz valid for len bytes (caller contract); data has len+2 bytes available.
    unsafe {
        std::ptr::copy_nonoverlapping(psz, data, len as usize);
        *data.add(len as usize) = 0;
        *data.add(len as usize + 1) = 0;
    }
    data as *mut u16
}

// Wine ref: dlls/oleaut32/safearray.c — SafeArrayGetElement locks the array, computes
// element offset from indices, copies the element to pv; returns E_INVALIDARG if psa/pv
// null or indices out-of-bounds.
/// SafeArrayGetElement (oleaut32 #23) — retrieve one element from a safe array.
///
/// Returns E_INVALIDARG (0x80070057) — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn safe_array_get_element(
    _psa: *const u8,
    _rg_indices: *const i32,
    _pv: *mut u8,
) -> i32 {
    0x80070057u32 as i32 // E_INVALIDARG
}

// Wine ref: dlls/oleaut32/safearray.c — SafeArrayPutElement locks the array, computes
// element offset from indices, copies pv into the element slot; returns E_INVALIDARG if
// psa/pv null or indices out of bounds.
/// SafeArrayPutElement (oleaut32 #24) — store one element into a safe array.
///
/// Returns E_INVALIDARG (0x80070057) — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn safe_array_put_element(
    _psa: *mut u8,
    _rg_indices: *const i32,
    _pv: *const u8,
) -> i32 {
    0x80070057u32 as i32 // E_INVALIDARG
}

// Wine ref: dlls/oleaut32/errorinfo.c — SetErrorInfo stores the IErrorInfo pointer on the
// per-thread slot (via TlsGetValue/TlsSetValue); AddRef's on the new pointer; Release's
// the old one; dwReserved must be 0. Returns S_OK (0).
/// SetErrorInfo (oleaut32 #146) — set the per-thread error info object.
///
/// No-op, returns S_OK (0) — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_error_info(_dw_reserved: u32, _perrinfo: *const u8) -> i32 {
    0 // S_OK
}

// Wine ref: dlls/oleaut32/errorinfo.c — CreateErrorInfo creates a default ICreateErrorInfo
// implementation (IErrorInfoImpl); stores in *pperrinfo; AddRef'd on creation; caller must
// Release. Returns E_OUTOFMEMORY if allocation fails; E_POINTER if pperrinfo null.
/// CreateErrorInfo (oleaut32 #162) — create a new error info object.
///
/// Returns E_NOTIMPL (0x80004001), writes NULL to *pperrinfo if non-null — stub.
///
/// # Safety
/// `pperrinfo` must be null or a valid writable pointer-to-pointer.
pub unsafe extern "win64" fn create_error_info(pperrinfo: *mut *mut u8) -> i32 {
    // SAFETY: caller guarantees pperrinfo is null or a valid writable slot.
    if !pperrinfo.is_null() {
        unsafe { *pperrinfo = std::ptr::null_mut() };
    }
    0x80004001u32 as i32 // E_NOTIMPL
}

// Wine ref: none — ordinal #411 is undocumented / version-specific.
/// oleaut32 ordinal #411 — unknown undocumented ordinal.
///
/// Returns E_NOTIMPL (0x80004001) — stub.
pub extern "win64" fn oleaut32_ord411() -> i32 {
    0x80004001u32 as i32 // E_NOTIMPL
}

// Wine ref: none — ordinal #419 is undocumented / version-specific.
/// oleaut32 ordinal #419 — unknown undocumented ordinal.
///
/// Returns E_NOTIMPL (0x80004001) — stub.
pub extern "win64" fn oleaut32_ord419() -> i32 {
    0x80004001u32 as i32 // E_NOTIMPL
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/// Resolve an oleaut32.dll import (by name or ordinal string "#N").
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("oleaut32.dll") {
        return None;
    }
    match func {
        "SysAllocString" | "#2" => {
            Some(sys_alloc_string as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Ordinal 4 is SysAllocStringLen (confirmed from Windows export table and 7za binary analysis)
        "SysAllocStringLen" | "#4" | "#149" => {
            Some(sys_alloc_string_len as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SysFreeString" | "#6" => {
            Some(sys_free_string as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "SafeArrayDestroy" => {
            Some(safe_array_destroy as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SafeArrayCreate" | "#15" => {
            Some(safe_array_create as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // Ordinal 7 is SysStringLen
        "SysStringLen" | "#7" => {
            Some(sys_string_len as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // SysStringByteLen (ordinal 8 in Windows export table; "#8" is mapped to
        // GetErrorInfo in this resolver for Q-Dir compatibility)
        "SysStringByteLen" => {
            Some(sys_string_byte_len as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "VariantClear" | "#9" => {
            Some(variant_clear as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "VariantInit" | "#10" => {
            Some(variant_init as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "VariantCopy" | "#11" => {
            Some(variant_copy as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Q-Dir oleaut32 ordinals (#8, #12, #16, #23, #24, #146, #162, #411, #419)
        "GetErrorInfo" | "#8" => {
            Some(get_error_info as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "VariantChangeType" | "#12" => Some(
            variant_change_type as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "SysAllocStringByteLen" | "#16" => Some(
            sys_alloc_string_byte_len as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SafeArrayGetElement" | "#23" => Some(
            safe_array_get_element as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "SafeArrayPutElement" | "#24" => Some(
            safe_array_put_element as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "SetErrorInfo" | "#146" => {
            Some(set_error_info as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CreateErrorInfo" | "#162" => {
            Some(create_error_info as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "#411" => Some(oleaut32_ord411 as extern "win64" fn() -> _ as *const () as usize),
        "#419" => Some(oleaut32_ord419 as extern "win64" fn() -> _ as *const () as usize),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("ole32.dll", "SysAllocString").is_none());
    }

    #[test]
    fn resolve_unknown_function() {
        assert!(resolve("oleaut32.dll", "__nonexistent__").is_none());
    }

    #[test]
    fn resolve_by_name() {
        assert!(resolve("oleaut32.dll", "SysAllocString").is_some());
        assert!(resolve("oleaut32.dll", "VariantInit").is_some());
        assert!(resolve("oleaut32.dll", "VariantClear").is_some());
    }

    #[test]
    fn resolve_by_ordinal() {
        assert!(resolve("oleaut32.dll", "#2").is_some());
        assert!(resolve("oleaut32.dll", "#4").is_some());
        assert!(resolve("oleaut32.dll", "#7").is_some());
        assert!(resolve("oleaut32.dll", "#9").is_some());
        assert!(resolve("oleaut32.dll", "#10").is_some());
        assert!(resolve("oleaut32.dll", "#149").is_some());
    }

    #[test]
    fn resolve_q_dir_oleaut32_ordinals() {
        // Q-Dir oleaut32 ordinals: #8, #12, #16, #23, #24, #146, #162, #411, #419
        let ordinals = [
            "#8", "#12", "#16", "#23", "#24", "#146", "#162", "#411", "#419",
        ];
        for ord in &ordinals {
            assert!(
                resolve("oleaut32.dll", ord).is_some(),
                "oleaut32.dll!{ord} must resolve"
            );
        }
    }

    #[test]
    fn resolve_q_dir_oleaut32_by_name() {
        let named = [
            "GetErrorInfo",
            "VariantChangeType",
            "SysAllocStringByteLen",
            "SafeArrayGetElement",
            "SafeArrayPutElement",
            "SetErrorInfo",
            "CreateErrorInfo",
        ];
        for name in &named {
            assert!(
                resolve("oleaut32.dll", name).is_some(),
                "oleaut32.dll!{name} must resolve"
            );
        }
    }

    #[test]
    fn variant_init_zeroes_buffer() {
        let mut buf = [0xffu8; 16];
        unsafe { variant_init(buf.as_mut_ptr()) };
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn sys_string_len_null() {
        assert_eq!(unsafe { sys_string_len(std::ptr::null()) }, 0);
    }

    #[test]
    fn sys_string_byte_len_null() {
        assert_eq!(unsafe { sys_string_byte_len(std::ptr::null()) }, 0);
    }

    #[test]
    fn resolve_all_exports() {
        // Every named export in the resolver must resolve.
        let exports = [
            "SysAllocString",
            "SysAllocStringLen",
            "SysFreeString",
            "SafeArrayDestroy",
            "SafeArrayCreate",
            "SysStringLen",
            "SysStringByteLen",
            "VariantClear",
            "VariantInit",
            "VariantCopy",
            "GetErrorInfo",
            "VariantChangeType",
            "SysAllocStringByteLen",
            "SafeArrayGetElement",
            "SafeArrayPutElement",
            "SetErrorInfo",
            "CreateErrorInfo",
        ];
        for name in &exports {
            assert!(
                resolve("oleaut32.dll", name).is_some(),
                "oleaut32.dll!{name} must resolve"
            );
        }
    }

    #[test]
    fn resolve_all_ordinals() {
        // Every ordinal in the resolver must resolve.
        let ordinals = [
            "#2", "#4", "#6", "#7", "#8", "#9", "#10", "#11", "#12", "#15", "#16", "#23", "#24",
            "#146", "#149", "#162", "#411", "#419",
        ];
        for ord in &ordinals {
            assert!(
                resolve("oleaut32.dll", ord).is_some(),
                "oleaut32.dll!{ord} must resolve"
            );
        }
    }
}
