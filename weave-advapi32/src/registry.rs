//! Windows registry stubs for Weave.
//!
//! The registry is stored as a directory tree under `{prefix}/registry/`.
//! See `weave_core::registry` for the on-disk format.
//!
//! # Handle lifecycle
//!
//! `RegOpenKeyExW` / `RegCreateKeyExW` allocate a `HandleKind::RegistryKey`
//! entry in the global handle table and return it as an `HKEY`. `RegCloseKey`
//! frees the slot. The predefined root handles (HKEY_LOCAL_MACHINE etc.) are
//! not stored in the table — they are recognised by their numeric constant
//! values and resolved directly to their filesystem paths.
//!
//! # Error codes
//!
//! Registry functions return `LSTATUS` (an `i32` alias for Win32 error codes,
//! **not** NTSTATUS). `ERROR_SUCCESS` (0) means success.

#![allow(non_snake_case)]

use weave_core::handles::{self, HandleKind};
use weave_core::registry::{
    find_value_file, predefined_hive_path, read_value_file, resolve_subkey, REG_EXPAND_SZ,
    REG_NONE, REG_SZ,
};

// ── Win32 error codes for registry operations ─────────────────────────────────

const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_MORE_DATA: i32 = 234;
const ERROR_INVALID_HANDLE: i32 = 6;
const ERROR_INVALID_PARAMETER: i32 = 87;

// ── REGSAM (registry access rights) — accepted but ignored for now ────────────

// ── Key path resolution ───────────────────────────────────────────────────────

/// Resolve an HKEY (either a predefined constant or an opened handle) to its
/// on-disk directory path. Returns `None` for invalid handles.
fn key_to_path(hkey: usize) -> Option<std::path::PathBuf> {
    // Try predefined hive handle first.
    if let Some(p) = predefined_hive_path(hkey) {
        return Some(p);
    }
    // Fall back to the handle table.
    handles::get_registry_path(hkey)
}

// ── Decode null-terminated UTF-16 ────────────────────────────────────────────

/// Decode a null-terminated UTF-16 string pointer to a `String`.
/// Returns an empty string if the pointer is null.
///
/// # Safety
/// `ptr`, if non-null, must point to a valid null-terminated UTF-16 sequence.
unsafe fn decode_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

// ── RegOpenKeyExW ─────────────────────────────────────────────────────────────

/// RegOpenKeyExW: open a registry key and return a handle.
///
/// Returns `ERROR_SUCCESS` on success. The new handle is written to `phk_result`.
///
/// # Safety
/// `lp_sub_key`, if non-null, must be a valid null-terminated UTF-16 string.
/// `phk_result` must be a valid writable pointer.
pub unsafe extern "win64" fn reg_open_key_ex_w(
    h_key: usize,
    lp_sub_key: *const u16,
    ul_options: u32,   // reserved — ignored
    _sam_desired: u32, // access rights — ignored (all keys readable)
    phk_result: *mut usize,
) -> i32 {
    let _ = ul_options;
    if phk_result.is_null() {
        return ERROR_INVALID_HANDLE;
    }

    let base_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    let subkey = unsafe { decode_wide_ptr(lp_sub_key) };
    let key_path = match resolve_subkey(&base_path, &subkey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    if !key_path.is_dir() {
        return ERROR_FILE_NOT_FOUND;
    }

    let handle = handles::alloc(HandleKind::RegistryKey(key_path));
    unsafe { *phk_result = handle };
    ERROR_SUCCESS
}

// ── RegCreateKeyExW ───────────────────────────────────────────────────────────

/// RegCreateKeyExW: open an existing key or create it if it doesn't exist.
///
/// `lp_class`, `dw_options`, `sam_desired`, `lp_security_attrs` are ignored.
/// `lpdw_disposition` receives `REG_OPENED_EXISTING_KEY` (2) or
/// `REG_CREATED_NEW_KEY` (1).
///
/// # Safety
/// `lp_sub_key` and `lp_class` (if non-null) must be valid UTF-16 strings.
/// `phk_result` must be a valid writable pointer.
pub unsafe extern "win64" fn reg_create_key_ex_w(
    h_key: usize,
    lp_sub_key: *const u16,
    _reserved: u32,
    _lp_class: *const u16,
    _dw_options: u32,
    _sam_desired: u32,
    _lp_security_attrs: usize,
    phk_result: *mut usize,
    lpdw_disposition: *mut u32,
) -> i32 {
    if phk_result.is_null() {
        return ERROR_INVALID_HANDLE;
    }

    let base_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    let subkey = unsafe { decode_wide_ptr(lp_sub_key) };
    let key_path = match resolve_subkey(&base_path, &subkey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let existed = key_path.is_dir();
    if !existed && std::fs::create_dir_all(&key_path).is_err() {
        return ERROR_FILE_NOT_FOUND;
    }

    if !lpdw_disposition.is_null() {
        unsafe {
            *lpdw_disposition = if existed {
                2 // REG_OPENED_EXISTING_KEY
            } else {
                1 // REG_CREATED_NEW_KEY
            };
        }
    }

    let handle = handles::alloc(HandleKind::RegistryKey(key_path));
    unsafe { *phk_result = handle };
    ERROR_SUCCESS
}

// ── RegQueryValueExW ──────────────────────────────────────────────────────────

/// RegQueryValueExW: read a registry value.
///
/// If `lp_data` is null (or `lpcb_data` points to 0), fills `lp_type` and
/// `lpcb_data` with the value's type and byte length, then returns
/// `ERROR_SUCCESS`. The caller uses this to size a buffer before the real read.
///
/// If `lp_data` is non-null and the buffer is large enough, copies the data
/// and returns `ERROR_SUCCESS`.
///
/// If the buffer is too small, writes the required size to `lpcb_data` and
/// returns `ERROR_MORE_DATA`.
///
/// # Safety
/// All pointer arguments must be valid per their Windows API contracts.
pub unsafe extern "win64" fn reg_query_value_ex_w(
    h_key: usize,
    lp_value_name: *const u16,
    lp_reserved: *mut u32, // must be null per MSDN
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    // reserved must be null; non-null data without a size pointer is invalid.
    if !lp_reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if !lp_data.is_null() && lpcb_data.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

    let key_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    let value_name = unsafe { decode_wide_ptr(lp_value_name) };

    let value_file = match find_value_file(&key_path, &value_name) {
        Some(f) => f,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let (reg_type, data) = match read_value_file(&value_file) {
        Some(v) => v,
        None => return ERROR_FILE_NOT_FOUND,
    };

    // Write the type.
    if !lp_type.is_null() {
        unsafe { *lp_type = reg_type };
    }

    let data_len = data.len() as u32;

    if lp_data.is_null() {
        // Size-probe call: just report the required size.
        if !lpcb_data.is_null() {
            unsafe { *lpcb_data = data_len };
        }
        return ERROR_SUCCESS;
    }

    // Check buffer size.
    let buf_size = if lpcb_data.is_null() {
        0u32
    } else {
        unsafe { *lpcb_data }
    };

    if !lpcb_data.is_null() {
        unsafe { *lpcb_data = data_len };
    }

    if buf_size < data_len {
        return ERROR_MORE_DATA;
    }

    // Copy data into caller's buffer.
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), lp_data, data.len()) };

    // Wine behaviour: for string types, guarantee a UTF-16 null terminator at
    // the end of the buffer if the data doesn't already end with one and there
    // is room for two more bytes.
    if reg_type == REG_SZ || reg_type == REG_EXPAND_SZ {
        let len = data.len();
        let already_null = len >= 2 && data[len - 2] == 0 && data[len - 1] == 0;
        if !already_null && buf_size as usize >= len + 2 {
            unsafe {
                *lp_data.add(len) = 0;
                *lp_data.add(len + 1) = 0;
            }
        }
    }

    ERROR_SUCCESS
}

// ── RegSetValueExW ────────────────────────────────────────────────────────────

/// RegSetValueExW: write a registry value.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-16 string (or null for
/// the default value). `lp_data` must be valid for `cb_data` bytes.
pub unsafe extern "win64" fn reg_set_value_ex_w(
    h_key: usize,
    lp_value_name: *const u16,
    _reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> i32 {
    let key_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    if lp_data.is_null() && cb_data > 0 {
        return ERROR_FILE_NOT_FOUND;
    }

    let value_name = unsafe { decode_wide_ptr(lp_value_name) };
    let filename = if value_name.is_empty() {
        "@".to_string()
    } else {
        value_name
    };

    // Ensure the key directory exists.
    if std::fs::create_dir_all(&key_path).is_err() {
        return ERROR_FILE_NOT_FOUND;
    }

    let file_path = key_path.join(&filename);
    let data_slice = if cb_data == 0 || lp_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(lp_data, cb_data as usize) }
    };

    let mut content = dw_type.to_le_bytes().to_vec();
    content.extend_from_slice(data_slice);

    match std::fs::write(&file_path, &content) {
        Ok(_) => ERROR_SUCCESS,
        Err(_) => ERROR_FILE_NOT_FOUND,
    }
}

// ── RegDeleteValueW ───────────────────────────────────────────────────────────

/// RegDeleteValueW: delete a named value from an open key.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-16 string or null.
pub unsafe extern "win64" fn reg_delete_value_w(h_key: usize, lp_value_name: *const u16) -> i32 {
    let key_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    let value_name = unsafe { decode_wide_ptr(lp_value_name) };
    let value_file = match find_value_file(&key_path, &value_name) {
        Some(f) => f,
        None => return ERROR_FILE_NOT_FOUND,
    };

    match std::fs::remove_file(&value_file) {
        Ok(_) => ERROR_SUCCESS,
        Err(_) => ERROR_FILE_NOT_FOUND,
    }
}

// ── RegCloseKey ───────────────────────────────────────────────────────────────

/// RegCloseKey: close a registry key handle.
///
/// Predefined handles (HKLM, HKCU, etc.) are always valid and closing them is
/// a no-op that returns `ERROR_SUCCESS`.
pub extern "win64" fn reg_close_key(h_key: usize) -> i32 {
    // Predefined handles do not live in the table — silently succeed.
    if predefined_hive_path(h_key).is_some() {
        return ERROR_SUCCESS;
    }
    // For real opened handles, free the slot.
    handles::free(h_key);
    ERROR_SUCCESS
}

// ── RegQueryInfoKeyW ──────────────────────────────────────────────────────────

/// RegQueryInfoKeyW: return metadata about a key (subkey count, value count, …).
///
/// Phase 2: only fills in the value count and the max value name/data sizes.
/// Subkey enumeration data is zeroed — apps that enumerate subkeys will get an
/// empty list, which they must handle gracefully.
///
/// # Safety
/// All output pointer arguments may be null (callers pass null for fields they
/// don't need, per MSDN).
pub unsafe extern "win64" fn reg_query_info_key_w(
    h_key: usize,
    _lp_class: *mut u16,
    _lpcb_class: *mut u32,
    _lp_reserved: *mut u32,
    lpc_sub_keys: *mut u32,
    _lpcb_max_sub_key_len: *mut u32,
    _lpcb_max_class_len: *mut u32,
    lpc_values: *mut u32,
    lpcb_max_value_name_len: *mut u32,
    lpcb_max_value_len: *mut u32,
    _lpcb_security_descriptor: *mut u32,
    _lp_ft_last_write_time: *mut u64,
) -> i32 {
    let key_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    // Count values (files) and subkeys (dirs) in the key directory.
    let mut value_count = 0u32;
    let mut subkey_count = 0u32;
    let mut max_value_name = 0u32;
    let mut max_value_data = 0u32;

    if let Ok(entries) = std::fs::read_dir(&key_path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    subkey_count += 1;
                } else if meta.is_file() {
                    value_count += 1;
                    let name_len = entry.file_name().len() as u32;
                    max_value_name = max_value_name.max(name_len);
                    // File size - 4 (type header) = data size
                    let data_len = meta.len().saturating_sub(4) as u32;
                    max_value_data = max_value_data.max(data_len);
                }
            }
        }
    }

    if !lpc_sub_keys.is_null() {
        unsafe { *lpc_sub_keys = subkey_count };
    }
    if !lpc_values.is_null() {
        unsafe { *lpc_values = value_count };
    }
    if !lpcb_max_value_name_len.is_null() {
        unsafe { *lpcb_max_value_name_len = max_value_name };
    }
    if !lpcb_max_value_len.is_null() {
        unsafe { *lpcb_max_value_len = max_value_data };
    }

    ERROR_SUCCESS
}

// ── RegEnumValueW ─────────────────────────────────────────────────────────────

/// RegEnumValueW: enumerate the values of an open registry key.
///
/// `dw_index` is the zero-based index of the value to retrieve. Returns
/// `ERROR_NO_MORE_ITEMS` (259) when the index is out of range.
///
/// # Safety
/// `lp_value_name` must be valid for `*lpcb_value_name` UTF-16 code units.
/// `lp_data` (if non-null) must be valid for `*lpcb_data` bytes.
pub unsafe extern "win64" fn reg_enum_value_w(
    h_key: usize,
    dw_index: u32,
    lp_value_name: *mut u16,
    lpcb_value_name: *mut u32,
    _lp_reserved: *mut u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    const ERROR_NO_MORE_ITEMS: i32 = 259;

    let key_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    // Collect all value files (sorted for deterministic ordering).
    let mut values: Vec<std::path::PathBuf> = std::fs::read_dir(&key_path)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.metadata().map(|m| m.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    values.sort();

    let entry = match values.get(dw_index as usize) {
        Some(p) => p,
        None => return ERROR_NO_MORE_ITEMS,
    };

    // Value name: the filename (@ → empty string / default value).
    let raw_name = entry
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let display_name = if raw_name == "@" {
        String::new()
    } else {
        raw_name
    };

    // Encode name as UTF-16 (without null terminator for length check).
    let name_wide: Vec<u16> = display_name.encode_utf16().collect();
    let name_chars_needed = name_wide.len() as u32 + 1; // +1 for null

    if lpcb_value_name.is_null() {
        return ERROR_INVALID_HANDLE;
    }
    let buf_chars = unsafe { *lpcb_value_name };
    unsafe { *lpcb_value_name = name_chars_needed };

    if buf_chars < name_chars_needed {
        return ERROR_MORE_DATA;
    }

    // Copy name into caller buffer.
    if !lp_value_name.is_null() {
        for (i, &c) in name_wide.iter().enumerate() {
            unsafe { *lp_value_name.add(i) = c };
        }
        unsafe { *lp_value_name.add(name_wide.len()) = 0 }; // null terminator
    }

    // Read type + data.
    let (reg_type, data) = match read_value_file(entry) {
        Some(v) => v,
        None => (REG_NONE, vec![]),
    };

    if !lp_type.is_null() {
        unsafe { *lp_type = reg_type };
    }

    let data_len = data.len() as u32;
    if !lpcb_data.is_null() {
        let buf = unsafe { *lpcb_data };
        unsafe { *lpcb_data = data_len };
        if !lp_data.is_null() && buf >= data_len {
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), lp_data, data.len()) };
        } else if buf < data_len {
            return ERROR_MORE_DATA;
        }
    }

    ERROR_SUCCESS
}

// ── Resolver ──────────────────────────────────────────────────────────────────

pub fn resolve(func: &str) -> Option<usize> {
    match func {
        "RegOpenKeyExW" => Some(
            reg_open_key_ex_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "RegCreateKeyExW" => Some(
            reg_create_key_ex_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "RegQueryValueExW" => Some(
            reg_query_value_ex_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegSetValueExW" => Some(
            reg_set_value_ex_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegDeleteValueW" => {
            Some(reg_delete_value_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RegCloseKey" => Some(reg_close_key as *const () as usize),
        "RegQueryInfoKeyW" => Some(
            reg_query_info_key_w
                as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "RegEnumValueW" => Some(
            reg_enum_value_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Resolver table ────────────────────────────────────────────────────────

    #[test]
    fn resolve_all_registry_functions() {
        let expected = [
            "RegOpenKeyExW",
            "RegCreateKeyExW",
            "RegQueryValueExW",
            "RegSetValueExW",
            "RegDeleteValueW",
            "RegCloseKey",
            "RegQueryInfoKeyW",
            "RegEnumValueW",
        ];
        for name in &expected {
            assert!(resolve(name).is_some(), "missing resolver entry for {name}");
        }
    }

    #[test]
    fn resolve_unknown_function_returns_none() {
        assert!(resolve("__weave_nonexistent__").is_none());
        assert!(resolve("RegOpenKeyA").is_none()); // ASCII variant not implemented
    }

    // ── predefined_hive_path smoke test ───────────────────────────────────────

    #[test]
    fn predefined_hive_path_returns_some_for_known_roots() {
        // 64-bit sign-extended values as passed by MinGW-compiled binaries.
        // These constants are defined in weave-core.
        const HKEY_CLASSES_ROOT: usize = 0xFFFFFFFF80000000;
        const HKEY_CURRENT_USER: usize = 0xFFFFFFFF80000001;
        const HKEY_LOCAL_MACHINE: usize = 0xFFFFFFFF80000002;
        const HKEY_USERS: usize = 0xFFFFFFFF80000003;

        assert!(
            predefined_hive_path(HKEY_LOCAL_MACHINE).is_some(),
            "HKLM not recognised"
        );
        assert!(
            predefined_hive_path(HKEY_CURRENT_USER).is_some(),
            "HKCU not recognised"
        );
        assert!(
            predefined_hive_path(HKEY_CLASSES_ROOT).is_some(),
            "HKCR not recognised"
        );
        assert!(
            predefined_hive_path(HKEY_USERS).is_some(),
            "HKU not recognised"
        );
    }

    #[test]
    fn predefined_hive_path_returns_none_for_non_root() {
        // A plain handle value (not a predefined root) should return None
        assert!(predefined_hive_path(0).is_none());
        assert!(predefined_hive_path(4).is_none()); // looks like a real handle
        assert!(predefined_hive_path(0x7FFF_FFFF).is_none());
    }
}
