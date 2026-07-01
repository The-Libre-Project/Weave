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

#![allow(non_snake_case, clippy::missing_safety_doc)]

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

/// SysReAllocString — reallocate a BSTR, freeing the old and allocating new content.
///
/// Returns TRUE (1) on success, FALSE (0) on failure.
///
/// # Safety
/// `pbstr` must be a valid pointer to a BSTR (which may be null).
/// `psz` must be a valid null-terminated UTF-16 string or null.
// Wine ref: dlls/oleaut32/oleaut.c — SysReAllocString frees *pbstr, calls
// SysAllocString with psz, stores result in *pbstr; returns FALSE on NULL *pbstr.
pub unsafe extern "win64" fn sys_re_alloc_string(pbstr: *mut *mut u16, psz: *const u16) -> i32 {
    if pbstr.is_null() {
        return 0; // FALSE
    }
    // Free the existing BSTR.
    let old = unsafe { *pbstr };
    if !old.is_null() {
        unsafe { sys_free_string(old) };
    }
    // Allocate the new BSTR.
    let new_bstr = if psz.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { sys_alloc_string(psz) }
    };
    unsafe { *pbstr = new_bstr };
    1 // TRUE
}

/// SysReAllocStringLen — reallocate a BSTR with explicit length.
///
/// Returns TRUE (1) on success, FALSE (0) on failure.
///
/// # Safety
/// `pbstr` must be a valid pointer to a BSTR (which may be null).
/// If `psz` is non-null, it must be valid for at least `len` u16 elements.
// Wine ref: dlls/oleaut32/oleaut.c — SysReAllocStringLen frees *pbstr, calls
// SysAllocStringLen with psz/len, stores result in *pbstr.
pub unsafe extern "win64" fn sys_re_alloc_string_len(
    pbstr: *mut *mut u16,
    psz: *const u16,
    len: u32,
) -> i32 {
    if pbstr.is_null() {
        return 0; // FALSE
    }
    // Free the existing BSTR.
    let old = unsafe { *pbstr };
    if !old.is_null() {
        unsafe { sys_free_string(old) };
    }
    // Allocate the new BSTR with explicit length.
    let new_bstr = unsafe { sys_alloc_string_len(psz, len) };
    unsafe { *pbstr = new_bstr };
    1 // TRUE
}

// ── IDispatch vtable (COM dispatch interface) ─────────────────────────────────

const DISPID_UNKNOWN: i32 = -1;
const DISP_E_MEMBERNOTFOUND: i32 = 0x80020003u32 as i32;

/// IDispatch — the dispatch interface vtable.
///
/// Extends IUnknown with GetIDsOfNames and Invoke.
#[repr(C)]
pub struct IDispatchVtbl {
    pub query_interface:
        unsafe extern "win64" fn(*mut IDispatchImpl, *const u8, *mut *mut ()) -> u32,
    pub add_ref: unsafe extern "win64" fn(*mut IDispatchImpl) -> u32,
    pub release: unsafe extern "win64" fn(*mut IDispatchImpl) -> u32,
    pub get_ids_of_names: unsafe extern "win64" fn(
        *mut IDispatchImpl,
        *const u8,
        *mut *mut u16,
        u32,
        u32,
        *mut i32,
    ) -> u32,
    pub invoke: unsafe extern "win64" fn(
        *mut IDispatchImpl,
        i32,
        *const u8,
        u32,
        u16,
        *const u8,
        *mut u8,
        *mut u8,
        *mut u32,
    ) -> u32,
}

/// IDispatchImpl — a basic dispatch object.
///
/// This is a minimal implementation suitable as a base for scripting hosts.
/// It does not expose any methods by default — GetIDsOfNames returns
/// DISPID_UNKNOWN and Invoke returns DISP_E_MEMBERNOTFOUND.
#[repr(C)]
pub struct IDispatchImpl {
    pub vtable: *const IDispatchVtbl,
    pub ref_count: u32,
}

impl IDispatchImpl {
    pub fn new() -> Box<Self> {
        Box::new(IDispatchImpl {
            vtable: &IDISPATCH_VTBL,
            ref_count: 1,
        })
    }
}

unsafe impl Send for IDispatchImpl {}
unsafe impl Sync for IDispatchImpl {}

static IDISPATCH_VTBL: IDispatchVtbl = IDispatchVtbl {
    query_interface: idispatch_query_interface,
    add_ref: idispatch_add_ref,
    release: idispatch_release,
    get_ids_of_names: idispatch_get_ids_of_names,
    invoke: idispatch_invoke,
};

unsafe extern "win64" fn idispatch_query_interface(
    this: *mut IDispatchImpl,
    riid: *const u8,
    ppv: *mut *mut (),
) -> u32 {
    if ppv.is_null() {
        return 0x8007_0057;
    }
    unsafe { *ppv = std::ptr::null_mut() };
    if riid.is_null() {
        return 0x8007_0057;
    }
    // We accept IID_IUnknown (00000000-0000-0000-C000-000000000046)
    // and IID_IDispatch (00020400-0000-0000-C000-000000000046).
    let iid_bytes = unsafe { std::ptr::read_unaligned(riid as *const [u8; 16]) };
    let iid_iunknown: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    let iid_idispatch: [u8; 16] = [
        0x00, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    if iid_bytes == iid_iunknown || iid_bytes == iid_idispatch {
        unsafe {
            (*this).ref_count += 1;
            *ppv = this as *mut ();
        }
        0 // S_OK
    } else {
        0x8000_4002 // E_NOINTERFACE
    }
}

unsafe extern "win64" fn idispatch_add_ref(this: *mut IDispatchImpl) -> u32 {
    let count = unsafe { (*this).ref_count + 1 };
    unsafe { (*this).ref_count = count };
    count
}

unsafe extern "win64" fn idispatch_release(this: *mut IDispatchImpl) -> u32 {
    let prev = unsafe { (*this).ref_count };
    let new = prev - 1;
    if new == 0 {
        unsafe { drop(Box::from_raw(this)) };
    } else {
        unsafe { (*this).ref_count = new };
    }
    new
}

/// GetIDsOfNames — map method names to DISPIDs.
///
/// Basic implementation: returns DISPID_UNKNOWN for all names.
// Wine ref: dlls/oleaut32/dispatch.c — GetIDsOfNames looks up each name in
// the type info's name table; on failure sets *rgDispId to DISPID_UNKNOWN
// and returns DISP_E_UNKNOWNNAME.
unsafe extern "win64" fn idispatch_get_ids_of_names(
    _this: *mut IDispatchImpl,
    _riid: *const u8,
    rgsz_names: *mut *mut u16,
    c_names: u32,
    _lcid: u32,
    rg_disp_id: *mut i32,
) -> u32 {
    if rg_disp_id.is_null() || rgsz_names.is_null() {
        return 0x8007_0057; // E_INVALIDARG
    }
    for i in 0..c_names as isize {
        unsafe {
            *rg_disp_id.offset(i) = DISPID_UNKNOWN;
        }
    }
    0x80020006u32 as i32 as u32 // DISP_E_UNKNOWNNAME
}

/// Invoke — call a method by DISPID.
///
/// Basic implementation: returns DISP_E_MEMBERNOTFOUND for all DISPIDs.
// Wine ref: dlls/oleaut32/dispatch.c — Invoke validates the this pointer
// and riid (which must be IID_NULL), then dispatches via the type info;
// returns DISP_E_MEMBERNOTFOUND if the dispid is not in the type info.
unsafe extern "win64" fn idispatch_invoke(
    _this: *mut IDispatchImpl,
    _disp_id_member: i32,
    _riid: *const u8,
    _lcid: u32,
    _w_flags: u16,
    _p_disp_params: *const u8,
    _p_var_result: *mut u8,
    _p_excep_info: *mut u8,
    _pu_arg_err: *mut u32,
) -> u32 {
    DISP_E_MEMBERNOTFOUND as u32
}

// ── SafeArray ────────────────────────────────────────────────────────────────

/// SAFEARRAY layout offsets (x86_64):
///   offset 0: cDims (u16)
///   offset 2: fFeatures (u16)
///   offset 4: cbElements (u32)
///   offset 8: cLocks (u32)
///   offset 16: pvData (*mut u8) — 8 bytes, 8-byte aligned
///   = 24 bytes total (header)
///   offset 24: SAFEARRAYBOUND (cElements + lLbound, 8 bytes)
///   offset 32: element data
const SA_OFFSET_C_DIMS: usize = 0;
const SA_OFFSET_F_FEATURES: usize = 2;
const SA_OFFSET_CB_ELEMENTS: usize = 4;
const SA_OFFSET_C_LOCKS: usize = 8;
const SA_OFFSET_PV_DATA: usize = 16;
const SA_HEADER_SIZE: usize = 24;
const SA_BOUND_SIZE: usize = 8;
const SA_DATA_OFFSET: usize = SA_HEADER_SIZE + SA_BOUND_SIZE; // 32

unsafe fn sa_write_u16(base: *mut u8, offset: usize, val: u16) {
    unsafe { std::ptr::write(base.add(offset) as *mut u16, val) };
}

unsafe fn sa_write_u32(base: *mut u8, offset: usize, val: u32) {
    unsafe { std::ptr::write(base.add(offset) as *mut u32, val) };
}

unsafe fn sa_write_ptr(base: *mut u8, offset: usize, val: *mut u8) {
    unsafe { std::ptr::write(base.add(offset) as *mut *mut u8, val) };
}

/// SAFEARRAYBOUND — bounds descriptor.
#[repr(C)]
struct SafeArrayBound {
    c_elements: u32,
    l_lbound: i32,
}

/// FADF flags for SafeArray features.
const FADF_AUTO: u16 = 0x0001;
const FADF_FIXEDSIZE: u16 = 0x0010;

/// SafeArrayCreate — create a safe array. Returns NULL (stub — use CreateVector).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn safe_array_create(
    _vt: u16,
    _c_dims: u32,
    _rgsabound: *const u8,
) -> *mut u8 {
    std::ptr::null_mut() // stub — full multi-dim not implemented
}

/// SafeArrayCreateVector (oleaut32 #24 on some versions) — create a 1D safe array.
///
/// Returns a pointer to the SAFEARRAY, or NULL on allocation failure.
///
/// # Safety
/// `vt` must be a valid VARTYPE; `l_lbound` and `c_elements` define the array.
// Wine ref: dlls/oleaut32/safearray.c — SafeArrayCreateVector allocates a
// SAFEARRAY with cDims=1, sets cbElements based on vt, allocates pvData with
// SysAllocStringByteLen-like sizing, stores the data pointer.
pub unsafe extern "win64" fn safe_array_create_vector(
    vt: u16,
    l_lbound: i32,
    c_elements: u32,
) -> *mut u8 {
    // Calculate element size from VARTYPE.
    let elem_size: u32 = match vt {
        VT_I2 | VT_BOOL => 2,
        VT_I4 | VT_R4 | VT_ERROR => 4,
        VT_R8 => 8,
        VT_BSTR | VT_UNKNOWN | VT_DISPATCH => std::mem::size_of::<usize>() as u32,
        _ => return std::ptr::null_mut(), // unsupported type
    };
    let data_size = elem_size.saturating_mul(c_elements);
    let total = SA_DATA_OFFSET + data_size as usize;
    let buf = unsafe { libc::malloc(total) as *mut u8 };
    if buf.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        // Write SafeArrayHeader fields at fixed offsets.
        sa_write_u16(buf, SA_OFFSET_C_DIMS, 1);
        sa_write_u16(buf, SA_OFFSET_F_FEATURES, FADF_AUTO | FADF_FIXEDSIZE);
        sa_write_u32(buf, SA_OFFSET_CB_ELEMENTS, elem_size);
        sa_write_u32(buf, SA_OFFSET_C_LOCKS, 0);
        let pv_data = if data_size > 0 {
            buf.add(SA_DATA_OFFSET)
        } else {
            std::ptr::null_mut()
        };
        sa_write_ptr(buf, SA_OFFSET_PV_DATA, pv_data);
        // Write the single SAFEARRAYBOUND after the header.
        let bound = buf.add(SA_HEADER_SIZE) as *mut SafeArrayBound;
        (*bound).c_elements = c_elements;
        (*bound).l_lbound = l_lbound;
        // Zero the data region.
        if data_size > 0 {
            std::ptr::write_bytes(pv_data, 0, data_size as usize);
        }
    }
    buf
}

/// SafeArrayDestroy — destroy a safe array created by `safe_array_create_vector`.
///
/// The entire allocation (header + bound + data) is a single malloc block,
/// so we only free the root pointer. Interior `pv_data` is NOT freed separately.
///
/// # Safety
/// `psa` must be a SAFEARRAY allocated by `safe_array_create_vector` or null.
// Wine ref: dlls/oleaut32/safearray.c — SafeArrayDestroy frees pvData if
// not FADF_STATIC, then frees the header; decrements locks first.
// NOTE: Real Windows SafeArray uses separate allocations; Weave's single-block
// design means only ONE free is needed.
pub unsafe extern "win64" fn safe_array_destroy(psa: *mut u8) -> i32 {
    if psa.is_null() {
        return 0; // S_OK
    }
    // pvData is inside the same malloc block as psa — do NOT free separately.
    unsafe { libc::free(psa as *mut libc::c_void) };
    0 // S_OK
}

/// SafeArrayAccessData — lock a safe array and return a pointer to its data.
///
/// # Safety
/// `psa` must be a valid SAFEARRAY; `ppv_data` must be a valid writable pointer.
// Wine ref: dlls/oleaut32/safearray.c — SafeArrayAccessData increments lock
// count, returns pvData; fails if already locked above a threshold.
pub unsafe extern "win64" fn safe_array_access_data(psa: *mut u8, ppv_data: *mut *mut u8) -> i32 {
    if psa.is_null() || ppv_data.is_null() {
        return 0x8007_0057u32 as i32; // E_INVALIDARG
    }
    unsafe {
        // Increment lock count.
        let locks = std::ptr::read(psa.add(SA_OFFSET_C_LOCKS) as *const u32);
        std::ptr::write(
            psa.add(SA_OFFSET_C_LOCKS) as *mut u32,
            locks.wrapping_add(1),
        );
        // Return pv_data.
        *ppv_data = std::ptr::read(psa.add(SA_OFFSET_PV_DATA) as *const *mut u8);
    }
    0 // S_OK
}

/// SafeArrayUnaccessData — unlock a safe array's data.
///
/// # Safety
/// `psa` must be a valid SAFEARRAY.
// Wine ref: dlls/oleaut32/safearray.c — SafeArrayUnaccessData decrements lock
// count; returns E_INVALIDARG if psa is null.
pub unsafe extern "win64" fn safe_array_unaccess_data(psa: *mut u8) -> i32 {
    if psa.is_null() {
        return 0x8007_0057u32 as i32; // E_INVALIDARG
    }
    unsafe {
        let locks = std::ptr::read(psa.add(SA_OFFSET_C_LOCKS) as *const u32);
        if locks > 0 {
            std::ptr::write(
                psa.add(SA_OFFSET_C_LOCKS) as *mut u32,
                locks.wrapping_sub(1),
            );
        }
    }
    0 // S_OK
}

// ── VARIANT ──────────────────────────────────────────────────────────────────

// ── VARTYPE constants ─────────────────────────────────────────────────────────

const VT_EMPTY: u16 = 0;
const VT_NULL: u16 = 1;
const VT_I2: u16 = 2;
const VT_I4: u16 = 3;
const VT_R4: u16 = 4;
const VT_R8: u16 = 5;
const VT_BOOL: u16 = 11;
const VT_BSTR: u16 = 8;
const VT_UNKNOWN: u16 = 13;
const VT_DISPATCH: u16 = 9;
const VT_ARRAY: u16 = 0x2000;
const VT_BYREF: u16 = 0x4000;
const VT_ERROR: u16 = 10;

const DISP_E_TYPEMISMATCH: i32 = 0x80020005u32 as i32;
const DISP_E_BADVARTYPE: i32 = 0x80020008u32 as i32;
const E_OUTOFMEMORY: i32 = 0x8007000Eu32 as i32;

/// VARIANT — 16-byte discriminated union per the Windows x64 ABI.
///
/// Layout:
///   offset 0: VARTYPE vt (u16)
///   offset 2: wReserved1 (u16)
///   offset 4: wReserved2 (u16)
///   offset 6: wReserved3 (u16)
///   offset 8: __anon (8 bytes) — scalar, pointer, or BSTR
#[allow(dead_code)]
#[repr(C)]
struct Variant {
    vt: u16,
    w_reserved1: u16,
    w_reserved2: u16,
    w_reserved3: u16,
    data: VariantData,
}

#[allow(dead_code)]
#[repr(C)]
union VariantData {
    ll_val: i64,
    l_val: i32,
    ui_val: u32,
    b_val: u8,
    i_val: i16,
    flt_val: f32,
    dbl_val: f64,
    bool_val: i16,
    bstr_val: *mut u16,
    punk_val: *mut u8,
    pdisp_val: *mut u8,
    parray: *mut u8,
    byref: *mut u8,
    dec_val: [u8; 8],
}

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

/// VariantCopyInd — deep copy a VARIANT, resolving VT_BYREF indirection.
///
/// Returns S_OK (0) on success, E_OUTOFMEMORY on allocation failure.
///
/// # Safety
/// Both pointers must be valid 16-byte writable/readable VARIANT buffers.
// Wine ref: dlls/oleaut32/variant.c — VariantCopyInd clears the destination,
// then copies the source; if VT_BYREF is set, resolves the reference by
// reading the pointed-to value and storing it directly (without VT_BYREF).
pub unsafe extern "win64" fn variant_copy_ind(pdest: *mut u8, psrc: *const u8) -> i32 {
    if pdest.is_null() || psrc.is_null() {
        return 0; // S_OK (safe no-op)
    }
    // Clear destination first.
    let _ = unsafe { variant_clear(pdest) };
    // Read source vt.
    let src_vt = unsafe { *(psrc as *const u16) };
    let actual_vt = src_vt & !VT_BYREF;
    // If VT_BYREF is set, we need to dereference the pointer.
    if src_vt & VT_BYREF != 0 {
        let ptr_ref = unsafe { *(psrc.add(8) as *const *mut u8) };
        if ptr_ref.is_null() {
            // Null pointer indirect — set dest to VT_EMPTY.
            return 0;
        }
        // Build a temporary VARIANT from the pointed-to value.
        let mut tmp = [0u8; 16];
        unsafe {
            *(tmp.as_mut_ptr() as *mut u16) = actual_vt;
        }
        match actual_vt {
            VT_I2 | VT_BOOL => {
                let val = unsafe { *(ptr_ref as *const i16) };
                unsafe {
                    *(tmp.as_mut_ptr().add(8) as *mut i16) = val;
                }
            }
            VT_I4 | VT_ERROR => {
                let val = unsafe { *(ptr_ref as *const i32) };
                unsafe {
                    *(tmp.as_mut_ptr().add(8) as *mut i32) = val;
                }
            }
            VT_R4 => {
                let val = unsafe { *(ptr_ref as *const f32) };
                unsafe {
                    *(tmp.as_mut_ptr().add(8) as *mut f32) = val;
                }
            }
            VT_R8 => {
                let val = unsafe { *(ptr_ref as *const f64) };
                unsafe {
                    *(tmp.as_mut_ptr().add(8) as *mut f64) = val;
                }
            }
            VT_BSTR => {
                let src_bstr = unsafe { *(ptr_ref as *const *mut u16) };
                if !src_bstr.is_null() {
                    let byte_len =
                        unsafe { *((src_bstr as *const u8).sub(4) as *const u32) } as usize;
                    let total = 4 + byte_len + 2;
                    let buf = unsafe { libc::malloc(total) as *mut u8 };
                    if buf.is_null() {
                        return E_OUTOFMEMORY;
                    }
                    unsafe {
                        *(buf as *mut u32) = byte_len as u32;
                        let data = buf.add(4) as *mut u16;
                        std::ptr::copy_nonoverlapping(
                            src_bstr as *const u8,
                            data as *mut u8,
                            byte_len,
                        );
                        *data.add(byte_len / 2) = 0;
                        *(tmp.as_mut_ptr().add(8) as *mut *mut u16) = data;
                    }
                }
            }
            _ => {
                // For unrecognized types, copy raw bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        ptr_ref,
                        tmp.as_mut_ptr().add(8),
                        std::mem::size_of::<u64>(),
                    );
                }
            }
        }
        // Copy the temporary variant (without VT_BYREF) to destination.
        let _ = unsafe { variant_copy(pdest, tmp.as_ptr()) };
        return 0;
    }
    // No indirection — delegate to VariantCopy.
    unsafe { variant_copy(pdest, psrc) }
}

/// Parse a BSTR string into an i32. Returns None on failure.
#[allow(dead_code)]
unsafe fn bstr_to_i32(bstr: *const u16) -> Option<i32> {
    if bstr.is_null() {
        return None;
    }
    let len = unsafe { sys_string_len(bstr) } as usize;
    if len == 0 {
        return None;
    }
    let mut s = String::new();
    for i in 0..len {
        let c = unsafe { *bstr.add(i) };
        if c > 0x7f {
            return None;
        }
        s.push(c as u8 as char);
    }
    s.parse::<i32>().ok()
}

/// Parse a BSTR string into an f64. Returns None on failure.
#[allow(dead_code)]
unsafe fn bstr_to_f64(bstr: *const u16) -> Option<f64> {
    if bstr.is_null() {
        return None;
    }
    let len = unsafe { sys_string_len(bstr) } as usize;
    if len == 0 {
        return None;
    }
    let mut s = String::new();
    for i in 0..len {
        let c = unsafe { *bstr.add(i) };
        if c > 0x7f {
            return None;
        }
        s.push(c as u8 as char);
    }
    s.parse::<f64>().ok()
}

/// Format an i32 into a BSTR.
unsafe fn i32_to_bstr(val: i32) -> *mut u16 {
    let s = format!("{}", val);
    let u16_chars: Vec<u16> = s.encode_utf16().collect();
    let len = u16_chars.len() as u32;
    unsafe { sys_alloc_string_len(u16_chars.as_ptr(), len) }
}

/// Format an f64 into a BSTR.
unsafe fn f64_to_bstr(val: f64) -> *mut u16 {
    let s = format!("{}", val);
    let u16_chars: Vec<u16> = s.encode_utf16().collect();
    let len = u16_chars.len() as u32;
    unsafe { sys_alloc_string_len(u16_chars.as_ptr(), len) }
}

/// Read the data union (offset 8) from a potentially unaligned VARIANT pointer.
unsafe fn variant_read_u64(pvar: *const u8) -> u64 {
    unsafe { std::ptr::read_unaligned(pvar.add(8) as *const u64) }
}

unsafe fn variant_write_ptr(pvar: *mut u8, val: *mut u16) {
    unsafe { std::ptr::write_unaligned(pvar.add(8) as *mut *mut u16, val) };
}

unsafe fn variant_write_i32(pvar: *mut u8, val: i32) {
    unsafe { std::ptr::write_unaligned(pvar.add(8) as *mut i32, val) };
}

unsafe fn variant_write_i16(pvar: *mut u8, val: i16) {
    unsafe { std::ptr::write_unaligned(pvar.add(8) as *mut i16, val) };
}

unsafe fn variant_write_f64(pvar: *mut u8, val: f64) {
    unsafe { std::ptr::write_unaligned(pvar.add(8) as *mut f64, val) };
}

/// Perform an in-place type conversion on a VARIANT.
///
/// Supports: VT_EMPTY, VT_I4, VT_R8, VT_BSTR, VT_BOOL, VT_NULL.
/// For VT_BSTR sources, the string content is read before clearing.
///
/// Uses unaligned reads/writes for the data union (offset 8) to handle
/// any pointer alignment.
///
/// # Safety
/// `pvar` must point to a valid 16-byte VARIANT.
unsafe fn variant_convert_inplace(pvar: *mut u8, target_vt: u16) -> i32 {
    let src_vt = unsafe { *(pvar as *const u16) };
    if src_vt == target_vt {
        return 0; // S_OK — already the right type
    }
    // For VT_BSTR sources, extract and copy the string content before freeing.
    let mut saved_bstr: Option<String> = None;
    if src_vt == VT_BSTR {
        let bstr_ptr = unsafe { variant_read_u64(pvar) as *const u16 };
        if !bstr_ptr.is_null() {
            let len = unsafe { sys_string_len(bstr_ptr) } as usize;
            let mut s = String::with_capacity(len);
            for i in 0..len {
                let c = unsafe { *bstr_ptr.add(i) };
                if c <= 0x7f {
                    s.push(c as u8 as char);
                } else {
                    // If we can't represent as ASCII, store as replacement.
                    s.push('\u{FFFD}');
                }
            }
            saved_bstr = Some(s);
        }
    }
    // Read the source scalar value (for non-BSTR types).
    let src_val = if src_vt != VT_BSTR {
        unsafe { variant_read_u64(pvar) }
    } else {
        0
    };
    // Clear the VARIANT (frees BSTR if VT_BSTR).
    unsafe { variant_clear(pvar) };
    // Set target type.
    unsafe { *(pvar as *mut u16) = target_vt };
    match (src_vt, target_vt) {
        // VT_EMPTY/VT_NULL → anything: leave as zero/default
        (VT_EMPTY, _) | (VT_NULL, _) => {
            return 0;
        }
        // VT_I4 ↔ VT_BSTR
        (VT_I4, VT_BSTR) => {
            let val = src_val as i32;
            let bstr = unsafe { i32_to_bstr(val) };
            if bstr.is_null() {
                return E_OUTOFMEMORY;
            }
            unsafe { variant_write_ptr(pvar, bstr) };
        }
        (VT_BSTR, VT_I4) => {
            let s = saved_bstr.as_deref();
            match s.and_then(|s| s.parse::<i32>().ok()) {
                Some(val) => unsafe { variant_write_i32(pvar, val) },
                None => return DISP_E_TYPEMISMATCH,
            }
        }
        // VT_I4 ↔ VT_R8
        (VT_I4, VT_R8) => {
            unsafe { variant_write_f64(pvar, src_val as i32 as f64) };
        }
        (VT_R8, VT_I4) => {
            let val = f64::from_bits(src_val);
            unsafe { variant_write_i32(pvar, val as i32) };
        }
        // VT_R8 ↔ VT_BSTR
        (VT_R8, VT_BSTR) => {
            let val = f64::from_bits(src_val);
            let bstr = unsafe { f64_to_bstr(val) };
            if bstr.is_null() {
                return E_OUTOFMEMORY;
            }
            unsafe { variant_write_ptr(pvar, bstr) };
        }
        (VT_BSTR, VT_R8) => {
            let s = saved_bstr.as_deref();
            match s.and_then(|s| s.parse::<f64>().ok()) {
                Some(val) => unsafe { variant_write_f64(pvar, val) },
                None => return DISP_E_TYPEMISMATCH,
            }
        }
        // VT_BOOL ↔ VT_I4
        (VT_BOOL, VT_I4) => {
            let val = src_val as i16;
            unsafe { variant_write_i32(pvar, if val != 0 { -1 } else { 0 }) };
        }
        (VT_I4, VT_BOOL) => {
            let val = src_val as i32;
            unsafe { variant_write_i16(pvar, if val != 0 { -1 } else { 0 }) };
            unsafe { *(pvar as *mut u16) = VT_BOOL };
        }
        // VT_BOOL ↔ VT_BSTR
        (VT_BOOL, VT_BSTR) => {
            let val = src_val as i16;
            let s: &str = if val != 0 { "true" } else { "false" };
            let u16_chars: Vec<u16> = s.encode_utf16().collect();
            let bstr = unsafe { sys_alloc_string_len(u16_chars.as_ptr(), u16_chars.len() as u32) };
            if bstr.is_null() {
                return E_OUTOFMEMORY;
            }
            unsafe { variant_write_ptr(pvar, bstr) };
        }
        (VT_BSTR, VT_BOOL) => {
            let s = saved_bstr.as_deref().unwrap_or("");
            let is_true = s == "true"
                || s == "True"
                || s == "-1"
                || s.parse::<i32>().ok().is_some_and(|n| n != 0);
            unsafe { variant_write_i16(pvar, if is_true { -1 } else { 0 }) };
            unsafe { *(pvar as *mut u16) = VT_BOOL };
        }
        // VT_R8 ↔ VT_BOOL
        (VT_R8, VT_BOOL) => {
            let val = f64::from_bits(src_val);
            unsafe { variant_write_i16(pvar, if val != 0.0 { -1 } else { 0 }) };
            unsafe { *(pvar as *mut u16) = VT_BOOL };
        }
        (VT_BOOL, VT_R8) => {
            let val = src_val as i16;
            unsafe { variant_write_f64(pvar, if val != 0 { -1.0 } else { 0.0 }) };
            unsafe { *(pvar as *mut u16) = VT_R8 };
        }
        _ => return DISP_E_TYPEMISMATCH,
    }
    0 // S_OK
}

// Wine ref: dlls/oleaut32/variant.c — VariantChangeType converts source variant to vt
// via VARIANT_Coerce; updates pdest in-place if pdest==psrc; returns DISP_E_TYPEMISMATCH
// if conversion not supported; calls VariantClear on pdest before writing new value.
/// VariantChangeType (oleaut32 #12) — convert a VARIANT to a new type.
///
/// Supports: VT_EMPTY, VT_NULL, VT_I4, VT_R8, VT_BSTR, VT_BOOL conversions.
///
/// # Safety
/// Both pointers must be valid 16-byte VARIANT buffers. `pvarg_src` must be readable,
/// `pvarg_dest` writable.
pub unsafe extern "win64" fn variant_change_type(
    pvarg_dest: *mut u8,
    pvarg_src: *const u8,
    _w_flags: u16,
    vt: u16,
) -> i32 {
    if pvarg_dest.is_null() || pvarg_src.is_null() {
        return DISP_E_BADVARTYPE;
    }
    // Validate target type — must not contain VT_ARRAY or VT_BYREF for this simple impl.
    if vt & VT_ARRAY != 0 || vt & VT_BYREF != 0 {
        return DISP_E_TYPEMISMATCH;
    }
    // If dest == src (same pointer), convert in place.
    if std::ptr::eq(pvarg_dest, pvarg_src) {
        let src_vt = unsafe { *(pvarg_src as *const u16) };
        if src_vt == vt {
            return 0; // S_OK
        }
        return unsafe { variant_convert_inplace(pvarg_dest, vt) };
    }
    // Different pointers: clear dest, copy src, then convert.
    let _ = unsafe { variant_clear(pvarg_dest) };
    let _ = unsafe { variant_copy(pvarg_dest, pvarg_src) };
    let src_vt = unsafe { *(pvarg_dest as *const u16) };
    if src_vt == vt {
        return 0; // S_OK — already the right type
    }
    unsafe { variant_convert_inplace(pvarg_dest, vt) }
}

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

// Wine ref: dlls/oleaut32/typelib.c — CreateDispTypeInfo creates a dispatch
// interface from INTERFACEDATA; returns S_OK or E_OUTOFMEMORY; *ppunkDisp
// is AddRef'd on creation.
/// CreateDispTypeInfo (oleaut32 #23) — create dispatch type info from INTERFACEDATA.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_disp_type_info(
    _p_data: *const u8,
    _lcid: u32,
    _pp_dispatch: *mut *mut u8,
) -> i32 {
    if !_pp_dispatch.is_null() {
        unsafe { *_pp_dispatch = std::ptr::null_mut() };
    }
    0x80004001u32 as i32 // E_NOTIMPL
}

// Wine ref: dlls/oleaut32/typelib.c — CreateStdDispatch creates a default
// IDispatch implementation from an interface; returns S_OK or E_OUTOFMEMORY.
/// CreateStdDispatch (oleaut32 #38) — create a standard dispatch implementation.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_std_dispatch(
    _p_unk_outer: *mut u8,
    _pv_this: *mut u8,
    _p_type_info: *mut u8,
    _pp_dispatch: *mut *mut u8,
) -> i32 {
    if !_pp_dispatch.is_null() {
        unsafe { *_pp_dispatch = std::ptr::null_mut() };
    }
    0x80004001u32 as i32 // E_NOTIMPL
}

// Wine ref: none — ordinal #26 is undocumented / version-specific.
/// oleaut32 ordinal #26 — unknown undocumented ordinal.
///
/// Returns S_OK (0) — stub.
pub extern "win64" fn oleaut32_ord26() -> i32 {
    eprintln!("weave/oleaut32: ordinal #26 (stub → 0)");
    0 // S_OK
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
        "SafeArrayCreateVector" => Some(
            safe_array_create_vector as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SafeArrayAccessData" => Some(
            safe_array_access_data as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SafeArrayUnaccessData" => {
            Some(safe_array_unaccess_data as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SysReAllocString" | "#3" => {
            Some(sys_re_alloc_string as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SysReAllocStringLen" | "#5" => Some(
            sys_re_alloc_string_len as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "VariantCopyInd" => {
            Some(variant_copy_ind as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
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
        "CreateDispTypeInfo" => Some(
            create_disp_type_info as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CreateStdDispatch" => Some(
            create_std_dispatch as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "#26" => Some(oleaut32_ord26 as extern "win64" fn() -> _ as *const () as usize),
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
        assert!(resolve("oleaut32.dll", "SysReAllocString").is_some());
        assert!(resolve("oleaut32.dll", "SysReAllocStringLen").is_some());
        assert!(resolve("oleaut32.dll", "VariantCopyInd").is_some());
        assert!(resolve("oleaut32.dll", "SafeArrayCreateVector").is_some());
        assert!(resolve("oleaut32.dll", "SafeArrayAccessData").is_some());
        assert!(resolve("oleaut32.dll", "SafeArrayUnaccessData").is_some());
        assert!(resolve("oleaut32.dll", "CreateDispTypeInfo").is_some());
        assert!(resolve("oleaut32.dll", "CreateStdDispatch").is_some());
    }

    #[test]
    fn resolve_by_ordinal() {
        assert!(resolve("oleaut32.dll", "#2").is_some());
        assert!(resolve("oleaut32.dll", "#4").is_some());
        assert!(resolve("oleaut32.dll", "#7").is_some());
        assert!(resolve("oleaut32.dll", "#9").is_some());
        assert!(resolve("oleaut32.dll", "#10").is_some());
        assert!(resolve("oleaut32.dll", "#26").is_some());
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
        let mut buf = vec![0xffu8; 16];
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
            "SafeArrayCreateVector",
            "SafeArrayAccessData",
            "SafeArrayUnaccessData",
            "SysReAllocString",
            "SysReAllocStringLen",
            "VariantCopyInd",
            "CreateDispTypeInfo",
            "CreateStdDispatch",
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
            "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10", "#11", "#12", "#15", "#16",
            "#23", "#24", "#26", "#146", "#149", "#162", "#411", "#419",
        ];
        for ord in &ordinals {
            assert!(
                resolve("oleaut32.dll", ord).is_some(),
                "oleaut32.dll!{ord} must resolve"
            );
        }
    }

    // ── BSTR tests ─────────────────────────────────────────────────────────

    #[test]
    fn bstr_alloc_string_len_roundtrip() {
        unsafe {
            let s: Vec<u16> = "Hello".encode_utf16().collect();
            let bstr = sys_alloc_string(s.as_ptr());
            assert!(!bstr.is_null());
            let len = sys_string_len(bstr);
            assert_eq!(len, 5);
            for i in 0..5 {
                assert_eq!(*bstr.add(i), s[i]);
            }
            // Null terminated
            assert_eq!(*bstr.add(5), 0);
            sys_free_string(bstr);
        }
    }

    #[test]
    fn bstr_alloc_string_len_with_binary_null() {
        unsafe {
            // String with embedded null: "AB\0CD"
            let data = [b'A' as u16, b'B' as u16, 0, b'C' as u16, b'D' as u16, 0];
            let bstr = sys_alloc_string_len(data.as_ptr(), 5);
            assert!(!bstr.is_null());
            let len = sys_string_len(bstr);
            assert_eq!(len, 5);
            assert_eq!(*bstr.add(0), data[0]);
            assert_eq!(*bstr.add(1), data[1]);
            assert_eq!(*bstr.add(2), data[2]);
            assert_eq!(*bstr.add(3), data[3]);
            assert_eq!(*bstr.add(4), data[4]);
            // Past the explicit length, the null terminator should exist.
            assert_eq!(*bstr.add(5), 0);
            sys_free_string(bstr);
        }
    }

    #[test]
    fn bstr_re_alloc_string_preserves_content() {
        unsafe {
            let original: Vec<u16> = "First".encode_utf16().collect();
            let bstr = sys_alloc_string(original.as_ptr());
            assert!(!bstr.is_null());
            let mut pbstr: *mut u16 = bstr;

            let replacement: Vec<u16> = "Second".encode_utf16().collect();
            let ret = sys_re_alloc_string(&mut pbstr, replacement.as_ptr());
            assert_eq!(ret, 1); // TRUE
            let len = sys_string_len(pbstr);
            assert_eq!(len, 6);
            sys_free_string(pbstr);
        }
    }

    #[test]
    fn bstr_re_alloc_string_len_preserves_content() {
        unsafe {
            let original: Vec<u16> = "First".encode_utf16().collect();
            let bstr = sys_alloc_string(original.as_ptr());
            assert!(!bstr.is_null());
            let mut pbstr: *mut u16 = bstr;

            let replacement: Vec<u16> = "NewStr".encode_utf16().collect();
            let ret = sys_re_alloc_string_len(&mut pbstr, replacement.as_ptr(), 6);
            assert_eq!(ret, 1); // TRUE
            let len = sys_string_len(pbstr);
            assert_eq!(len, 6);
            sys_free_string(pbstr);
        }
    }

    #[test]
    fn bstr_alloc_string_null_returns_null() {
        let bstr = unsafe { sys_alloc_string(std::ptr::null()) };
        assert!(bstr.is_null());
    }

    #[test]
    fn bstr_string_len_null_returns_zero() {
        assert_eq!(unsafe { sys_string_len(std::ptr::null()) }, 0);
    }

    #[test]
    fn bstr_free_string_null_no_crash() {
        unsafe { sys_free_string(std::ptr::null_mut()) };
    }

    /// Helper: allocate an aligned 16-byte VARIANT buffer.
    /// Returns a pointer to the buffer (owned by the caller, freed when done).
    fn alloc_var() -> Vec<u8> {
        let v: Vec<u8> = vec![0u8; 16];
        // Vec<u8> is at least 8-byte aligned on x86_64, but guarantee it.
        assert!(v.as_ptr() as usize % 8 == 0, "vec must be 8-byte aligned");
        v
    }

    // ── VARIANT tests ───────────────────────────────────────────────────────

    #[test]
    fn variant_init_and_clear_no_crash() {
        unsafe {
            let mut var = alloc_var();
            variant_init(var.as_mut_ptr());
            assert_eq!(var[0], 0);
            assert_eq!(var[1], 0);
            let hr = variant_clear(var.as_mut_ptr());
            assert_eq!(hr, 0); // S_OK
        }
    }

    #[test]
    fn variant_init_zeroes_all_sixteen_bytes() {
        let mut buf = vec![0xffu8; 16];
        unsafe { variant_init(buf.as_mut_ptr()) };
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn variant_copy_between_two_variants() {
        unsafe {
            let mut src = alloc_var();
            let mut dst = alloc_var();
            // Setup source as VT_I4 with value 42.
            variant_init(src.as_mut_ptr());
            *(src.as_mut_ptr() as *mut u16) = VT_I4;
            *(src.as_mut_ptr().add(8) as *mut i32) = 42;
            // Copy to dest.
            let hr = variant_copy(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(hr, 0);
            let dst_vt = *(dst.as_ptr() as *const u16);
            assert_eq!(dst_vt, VT_I4);
            let dst_val = *(dst.as_ptr().add(8) as *const i32);
            assert_eq!(dst_val, 42);
        }
    }

    #[test]
    fn variant_copy_bstr_deep_copy() {
        unsafe {
            let hello: Vec<u16> = "Hello".encode_utf16().collect();
            let bstr = sys_alloc_string(hello.as_ptr());
            assert!(!bstr.is_null());

            let mut src = alloc_var();
            let mut dst = alloc_var();
            variant_init(src.as_mut_ptr());
            *(src.as_mut_ptr() as *mut u16) = VT_BSTR;
            *(src.as_mut_ptr().add(8) as *mut *mut u16) = bstr;

            let hr = variant_copy(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(hr, 0);
            let dst_vt = *(dst.as_ptr() as *const u16);
            assert_eq!(dst_vt, VT_BSTR);
            let dst_bstr = *(dst.as_ptr().add(8) as *const *mut u16);
            assert!(!dst_bstr.is_null());
            assert_ne!(dst_bstr, bstr); // deep copy — different pointer
            assert_eq!(sys_string_len(dst_bstr), 5);

            // Clean up both BSTRs.
            variant_clear(src.as_mut_ptr());
            variant_clear(dst.as_mut_ptr());
        }
    }

    #[test]
    fn variant_change_type_i4_to_bstr() {
        unsafe {
            let mut var = alloc_var();
            variant_init(var.as_mut_ptr());
            *(var.as_mut_ptr() as *mut u16) = VT_I4;
            *(var.as_mut_ptr().add(8) as *mut i32) = 12345;

            let hr = variant_change_type(var.as_mut_ptr(), var.as_ptr(), 0, VT_BSTR);
            assert_eq!(hr, 0, "VariantChangeType I4→BSTR failed");

            let vt = *(var.as_ptr() as *const u16);
            assert_eq!(vt, VT_BSTR);
            let bstr = *(var.as_ptr().add(8) as *const *mut u16);
            assert!(!bstr.is_null());
            let len = sys_string_len(bstr);
            assert_eq!(len, 5);
            // Verify content: "12345"
            assert_eq!(*bstr.add(0), '1' as u16);
            assert_eq!(*bstr.add(1), '2' as u16);
            assert_eq!(*bstr.add(2), '3' as u16);
            assert_eq!(*bstr.add(3), '4' as u16);
            assert_eq!(*bstr.add(4), '5' as u16);

            variant_clear(var.as_mut_ptr());
        }
    }

    #[test]
    fn variant_change_type_bstr_to_i4() {
        unsafe {
            let s: Vec<u16> = "6789".encode_utf16().collect();
            let bstr = sys_alloc_string(s.as_ptr());
            assert!(!bstr.is_null());

            let mut var = alloc_var();
            variant_init(var.as_mut_ptr());
            *(var.as_mut_ptr() as *mut u16) = VT_BSTR;
            *(var.as_mut_ptr().add(8) as *mut *mut u16) = bstr;

            let hr = variant_change_type(var.as_mut_ptr(), var.as_ptr(), 0, VT_I4);
            assert_eq!(hr, 0, "VariantChangeType BSTR→I4 failed");

            let vt = *(var.as_ptr() as *const u16);
            assert_eq!(vt, VT_I4);
            let val = *(var.as_ptr().add(8) as *const i32);
            assert_eq!(val, 6789);

            variant_clear(var.as_mut_ptr());
        }
    }

    #[test]
    fn variant_change_type_i4_to_r8() {
        unsafe {
            let mut var = alloc_var();
            variant_init(var.as_mut_ptr());
            *(var.as_mut_ptr() as *mut u16) = VT_I4;
            *(var.as_mut_ptr().add(8) as *mut i32) = 42;

            let hr = variant_change_type(var.as_mut_ptr(), var.as_ptr(), 0, VT_R8);
            assert_eq!(hr, 0);

            let vt = *(var.as_ptr() as *const u16);
            assert_eq!(vt, VT_R8);
            let val = *(var.as_ptr().add(8) as *const f64);
            assert!((val - 42.0).abs() < 1e-10);
        }
    }

    #[test]
    fn variant_copy_ind_basic() {
        unsafe {
            let mut src = alloc_var();
            let mut dst = alloc_var();
            variant_init(src.as_mut_ptr());
            *(src.as_mut_ptr() as *mut u16) = VT_I4;
            *(src.as_mut_ptr().add(8) as *mut i32) = 77;

            let hr = variant_copy_ind(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(hr, 0);
            let dst_vt = *(dst.as_ptr() as *const u16);
            assert_eq!(dst_vt, VT_I4);
            let dst_val = *(dst.as_ptr().add(8) as *const i32);
            assert_eq!(dst_val, 77);
        }
    }

    #[test]
    fn variant_clear_clears_vt_and_data() {
        unsafe {
            let mut var = alloc_var();
            variant_init(var.as_mut_ptr());
            *(var.as_mut_ptr() as *mut u16) = VT_I4;
            *(var.as_mut_ptr().add(8) as *mut i32) = 0xDEAD;
            let hr = variant_clear(var.as_mut_ptr());
            assert_eq!(hr, 0);
            // vt should be VT_EMPTY (0)
            assert_eq!(*(var.as_ptr() as *const u16), 0);
            // Data union (offset 8..16) cleared
            assert_eq!(*(var.as_ptr().add(8) as *const u64), 0);
        }
    }

    // ── IDispatch tests ─────────────────────────────────────────────────────

    #[test]
    fn idispatch_get_ids_of_names_returns_unknown() {
        let obj = IDispatchImpl::new();
        let ptr = Box::into_raw(obj);
        unsafe {
            let vtbl = &*(*ptr).vtable;
            let mut names: [*mut u16; 1] = [std::ptr::null_mut()];
            // Use a dummy name pointer.
            let dummy: Vec<u16> = "Foo".encode_utf16().collect();
            names[0] = dummy.as_ptr() as *mut u16;
            let mut disp_id: i32 = 999;
            let hr = (vtbl.get_ids_of_names)(
                ptr,
                std::ptr::null(),
                names.as_mut_ptr(),
                1,
                0,
                &mut disp_id,
            );
            assert_eq!(hr, 0x80020006u32); // DISP_E_UNKNOWNNAME
            assert_eq!(disp_id, DISPID_UNKNOWN);
            // Release
            (vtbl.release)(ptr);
        }
    }

    #[test]
    fn idispatch_invoke_returns_member_not_found() {
        let obj = IDispatchImpl::new();
        let ptr = Box::into_raw(obj);
        unsafe {
            let vtbl = &*(*ptr).vtable;
            let hr = (vtbl.invoke)(
                ptr,
                0,
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            assert_eq!(hr, 0x80020003u32); // DISP_E_MEMBERNOTFOUND
            (vtbl.release)(ptr);
        }
    }

    #[test]
    fn idispatch_query_interface_iunknown_succeeds() {
        let obj = IDispatchImpl::new();
        let ptr = Box::into_raw(obj);
        unsafe {
            let vtbl = &*(*ptr).vtable;
            let iid_iunknown: [u8; 16] = [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ];
            let mut ppv: *mut () = std::ptr::null_mut();
            let hr = (vtbl.query_interface)(ptr, iid_iunknown.as_ptr(), &mut ppv);
            assert_eq!(hr, 0); // S_OK
            assert!(!ppv.is_null());
            assert_eq!((*ptr).ref_count, 2);
            (vtbl.release)(ptr);
            (vtbl.release)(ptr);
        }
    }

    #[test]
    fn idispatch_ref_counting() {
        let obj = IDispatchImpl::new();
        let ptr = Box::into_raw(obj);
        unsafe {
            let vtbl = &*(*ptr).vtable;
            assert_eq!((*ptr).ref_count, 1);
            let c = (vtbl.add_ref)(ptr);
            assert_eq!(c, 2);
            assert_eq!((*ptr).ref_count, 2);
            let c = (vtbl.release)(ptr);
            assert_eq!(c, 1);
            let c = (vtbl.release)(ptr);
            assert_eq!(c, 0);
        }
    }

    // ── SafeArray tests ─────────────────────────────────────────────────────

    #[test]
    fn safe_array_create_vector_just_malloc() {
        // Minimal test: just verify we can allocate and free memory the same
        // way the safe_array functions do.
        let total = SA_DATA_OFFSET + (4 * 10);
        let buf = unsafe { libc::malloc(total) as *mut u8 };
        assert!(!buf.is_null());
        unsafe {
            sa_write_u16(buf, SA_OFFSET_C_DIMS, 1);
            sa_write_u16(buf, SA_OFFSET_F_FEATURES, FADF_AUTO | FADF_FIXEDSIZE);
            sa_write_u32(buf, SA_OFFSET_CB_ELEMENTS, 4);
            sa_write_u32(buf, SA_OFFSET_C_LOCKS, 0);
            let pv_data = buf.add(SA_DATA_OFFSET);
            sa_write_ptr(buf, SA_OFFSET_PV_DATA, pv_data);
            let val = std::ptr::read(buf.add(SA_OFFSET_C_DIMS) as *const u16);
            assert_eq!(val, 1);
            libc::free(buf as *mut libc::c_void);
        }
    }

    #[test]
    fn safe_array_create_local_equivalent() {
        // Test that the logic inside safe_array_create_vector works without
        // the extern "win64" wrapper.
        let c_elements = 10u32;
        let elem_size: u32 = 4;
        let data_size = elem_size * c_elements;
        let total = SA_DATA_OFFSET + data_size as usize;
        let buf = unsafe { libc::malloc(total) as *mut u8 };
        assert!(!buf.is_null());
        unsafe {
            sa_write_u16(buf, SA_OFFSET_C_DIMS, 1);
            sa_write_u16(buf, SA_OFFSET_F_FEATURES, FADF_AUTO | FADF_FIXEDSIZE);
            sa_write_u32(buf, SA_OFFSET_CB_ELEMENTS, elem_size);
            sa_write_u32(buf, SA_OFFSET_C_LOCKS, 0);
            let pv_data = buf.add(SA_DATA_OFFSET);
            sa_write_ptr(buf, SA_OFFSET_PV_DATA, pv_data);
            let bound = buf.add(SA_HEADER_SIZE) as *mut SafeArrayBound;
            (*bound).c_elements = c_elements;
            (*bound).l_lbound = 0;
            std::ptr::write_bytes(pv_data, 0, data_size as usize);
            // Single free — pv_data is inside the same block.
            libc::free(buf as *mut libc::c_void);
        }
    }

    #[test]
    fn safe_array_create_vector_and_destroy() {
        unsafe {
            let psa = safe_array_create_vector(VT_I4, 0, 10);
            assert!(!psa.is_null(), "SafeArrayCreateVector returned NULL");
            let hr = safe_array_destroy(psa);
            assert_eq!(hr, 0);
        }
    }

    #[test]
    fn safe_array_create_vector_access_data() {
        unsafe {
            let psa = safe_array_create_vector(VT_I4, 0, 5);
            assert!(!psa.is_null());
            let mut pdata: *mut u8 = std::ptr::null_mut();
            let hr = safe_array_access_data(psa, &mut pdata);
            assert_eq!(hr, 0);
            assert!(!pdata.is_null());
            // Write and verify some data.
            *(pdata as *mut i32) = 10;
            *(pdata.add(4) as *mut i32) = 20;
            assert_eq!(*(pdata as *const i32), 10);
            assert_eq!(*(pdata.add(4) as *const i32), 20);
            let hr = safe_array_unaccess_data(psa);
            assert_eq!(hr, 0);
            safe_array_destroy(psa);
        }
    }

    #[test]
    fn safe_array_destroy_null_no_crash() {
        let hr = unsafe { safe_array_destroy(std::ptr::null_mut()) };
        assert_eq!(hr, 0);
    }

    #[test]
    fn safe_array_create_vector_unsupported_type() {
        let psa = unsafe { safe_array_create_vector(0xFFFF, 0, 10) };
        assert!(psa.is_null());
    }
}
