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
        return std::ptr::null_mut();
    }
    unsafe { *(buf as *mut u32) = byte_len as u32 };
    let data = unsafe { buf.add(4) as *mut u16 };
    unsafe { std::ptr::copy_nonoverlapping(psz, data, len + 1) };
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
    data
}

/// SysFreeString — free a BSTR allocated by SysAllocString*.
///
/// # Safety
/// `bstr` must be a BSTR allocated by `sys_alloc_string*`, or null.
pub unsafe extern "win64" fn sys_free_string(bstr: *mut u16) {
    if bstr.is_null() {
        return;
    }
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
/// Stub: sets the VARIANT to VT_EMPTY (zeroes the buffer).
///
/// # Safety
/// `pvar` must be a writable 16-byte buffer.
pub unsafe extern "win64" fn variant_clear(pvar: *mut u8) -> i32 {
    if !pvar.is_null() {
        unsafe { std::ptr::write_bytes(pvar, 0, 16) };
    }
    0 // S_OK
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
        "VariantClear" | "#9" => {
            Some(variant_clear as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "VariantInit" | "#10" => {
            Some(variant_init as unsafe extern "win64" fn(_) as *const () as usize)
        }
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
    fn variant_init_zeroes_buffer() {
        let mut buf = [0xffu8; 16];
        unsafe { variant_init(buf.as_mut_ptr()) };
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn sys_string_len_null() {
        assert_eq!(unsafe { sys_string_len(std::ptr::null()) }, 0);
    }
}
