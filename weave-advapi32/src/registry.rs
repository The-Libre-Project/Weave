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

/// Decode a null-terminated UTF-8 string pointer to a `String`.
/// Returns an empty string if the pointer is null.
///
/// # Safety
/// `ptr`, if non-null, must point to a valid null-terminated UTF-8 sequence.
unsafe fn decode_narrow_ptr(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(slice).into_owned()
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

// ── RegDeleteKeyW ─────────────────────────────────────────────────────────────

/// RegDeleteKeyW: delete a registry key and all its subkeys/values.
///
/// # Safety
/// `lp_sub_key` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn reg_delete_key_w(h_key: usize, lp_sub_key: *const u16) -> i32 {
    let base_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    let subkey = unsafe { decode_wide_ptr(lp_sub_key) };
    let key_path = match resolve_subkey(&base_path, &subkey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    // Check if it's a directory (key)
    if !key_path.is_dir() {
        return ERROR_FILE_NOT_FOUND;
    }

    match std::fs::remove_dir_all(&key_path) {
        Ok(_) => ERROR_SUCCESS,
        Err(_) => ERROR_FILE_NOT_FOUND,
    }
}

// ── RegEnumKeyExW ─────────────────────────────────────────────────────────────

/// RegEnumKeyExW: enumerate the subkeys of an open registry key.
///
/// # Safety
/// `lp_name` must be valid for `*lpcch_name` UTF-16 code units.
/// Unused parameters are ignored.
pub unsafe extern "win64" fn reg_enum_key_ex_w(
    h_key: usize,
    dw_index: u32,
    lp_name: *mut u16,
    lpcch_name: *mut u32,
    _lp_reserved: *mut u32,
    _lp_class: *mut u16,
    _lpcch_class: *mut u32,
    _lp_ft_last_write_time: *mut u64,
) -> i32 {
    const ERROR_NO_MORE_ITEMS: i32 = 259;

    let key_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    // Collect subdirectories (subkeys), sorted for deterministic ordering
    let mut subkeys: Vec<std::path::PathBuf> = std::fs::read_dir(&key_path)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.metadata().map(|m| m.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    subkeys.sort();

    let entry = match subkeys.get(dw_index as usize) {
        Some(p) => p,
        None => return ERROR_NO_MORE_ITEMS,
    };

    // Get the directory name
    let name = entry
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    // Encode as UTF-16
    let wide: Vec<u16> = name.encode_utf16().collect();
    let required_chars = wide.len() as u32 + 1; // +1 for null terminator

    if lpcch_name.is_null() {
        return ERROR_INVALID_HANDLE;
    }

    let buf_capacity = unsafe { *lpcch_name };
    unsafe { *lpcch_name = required_chars };

    if buf_capacity < required_chars {
        return ERROR_MORE_DATA;
    }

    // Copy wide chars into caller's buffer
    for (i, &c) in wide.iter().enumerate() {
        unsafe { *lp_name.add(i) = c };
    }
    unsafe { *lp_name.add(wide.len()) = 0 }; // null terminator

    ERROR_SUCCESS
}

// ── RegDeleteKeyA ─────────────────────────────────────────────────────────────

/// RegDeleteKeyA: delete a registry key and all its subkeys/values (ANSI version).
///
/// Converts the ANSI subkey name to UTF-16 and calls RegDeleteKeyW.
///
/// # Safety
/// `lp_sub_key` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn reg_delete_key_a(h_key: usize, lp_sub_key: *const u8) -> i32 {
    // Convert ANSI subkey to UTF-16
    let subkey_utf8 = unsafe { decode_narrow_ptr(lp_sub_key) };
    let subkey_utf16: Vec<u16> = subkey_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe { reg_delete_key_w(h_key, subkey_utf16.as_ptr()) }
}

// ── RegEnumKeyExA ─────────────────────────────────────────────────────────────

/// RegEnumKeyExA: enumerate the subkeys of an open registry key (ANSI version).
///
/// Same logic as RegEnumKeyExW but output is ANSI.
///
/// # Safety
/// `lp_name` must be valid for `*lpcch_name` UTF-8 bytes.
/// Unused parameters are ignored.
pub unsafe extern "win64" fn reg_enum_key_ex_a(
    h_key: usize,
    dw_index: u32,
    lp_name: *mut u8,
    lpcch_name: *mut u32,
    _lp_reserved: *mut u32,
    _lp_class: *mut u8,
    _lpcch_class: *mut u32,
    _lp_ft_last_write_time: *mut u64,
) -> i32 {
    const ERROR_NO_MORE_ITEMS: i32 = 259;

    let key_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    // Collect subdirectories (subkeys), sorted for deterministic ordering
    let mut subkeys: Vec<std::path::PathBuf> = std::fs::read_dir(&key_path)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.metadata().map(|m| m.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    subkeys.sort();

    let entry = match subkeys.get(dw_index as usize) {
        Some(p) => p,
        None => return ERROR_NO_MORE_ITEMS,
    };

    // Get the directory name
    let name = entry
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    // Convert to UTF-8 bytes
    let narrow: Vec<u8> = name.into_bytes();
    let required_chars = narrow.len() as u32 + 1; // +1 for null terminator

    if lpcch_name.is_null() {
        return ERROR_INVALID_HANDLE;
    }

    let buf_capacity = unsafe { *lpcch_name };
    unsafe { *lpcch_name = required_chars };

    if buf_capacity < required_chars {
        return ERROR_MORE_DATA;
    }

    // Copy bytes into caller's buffer
    for (i, &c) in narrow.iter().enumerate() {
        unsafe { *lp_name.add(i) = c };
    }
    unsafe { *lp_name.add(narrow.len()) = 0 }; // null terminator

    ERROR_SUCCESS
}

// ── RegEnumKeyA ───────────────────────────────────────────────────────────────

/// RegEnumKeyA: legacy 3-parameter subkey enumeration (ANSI).
///
/// Wrapper around `RegEnumKeyExA` with no class or timestamp parameters.
///
/// # Safety
/// `lp_name` must be a writable buffer of at least `cch_name` bytes.
pub unsafe extern "win64" fn reg_enum_key_a(
    h_key: usize,
    dw_index: u32,
    lp_name: *mut u8,
    cch_name: u32,
) -> i32 {
    let mut cch = cch_name;
    unsafe {
        reg_enum_key_ex_a(
            h_key,
            dw_index,
            lp_name,
            &mut cch,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    }
}

// ── OpenProcessToken ──────────────────────────────────────────────────────────

/// OpenProcessToken: open the access token associated with a process.
///
/// Returns FALSE (0). No real process tokens are supported.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn open_process_token(
    _process_handle: usize,
    _desired_access: u32,
    _token_handle: *mut usize,
) -> i32 {
    0 // FALSE
}

// ── LookupPrivilegeValueW ─────────────────────────────────────────────────────

/// LookupPrivilegeValueW: retrieve the locally unique identifier (LUID) for a privilege.
///
/// Returns FALSE (0). Privilege lookup is not supported.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn lookup_privilege_value_w(
    _lp_system_name: *const u16,
    _lp_name: *const u16,
    _lp_luid: *mut u64,
) -> i32 {
    0 // FALSE
}

// ── AdjustTokenPrivileges ─────────────────────────────────────────────────────

/// AdjustTokenPrivileges: enable or disable privileges in the specified access token.
///
/// Returns TRUE (1). No-op implementation.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn adjust_token_privileges(
    _token_handle: usize,
    _disable_all_privileges: i32,
    _new_state: usize,
    _buffer_length: u32,
    _previous_state: usize,
    _return_length: *mut u32,
) -> i32 {
    1 // TRUE
}

// ── ANSI registry variants ────────────────────────────────────────────────────

/// RegOpenKeyExA: open a registry key and return a handle (ANSI version).
///
/// Converts the ANSI subkey name to UTF-16 and calls RegOpenKeyExW.
///
/// # Safety
/// `lp_sub_key`, if non-null, must be a valid null-terminated UTF-8 string.
/// `phk_result` must be a valid writable pointer.
pub unsafe extern "win64" fn reg_open_key_ex_a(
    h_key: usize,
    lp_sub_key: *const u8,
    ul_options: u32,
    sam_desired: u32,
    phk_result: *mut usize,
) -> i32 {
    // Convert ANSI subkey to UTF-16
    let subkey_utf8 = unsafe { decode_narrow_ptr(lp_sub_key) };
    let subkey_utf16: Vec<u16> = subkey_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        reg_open_key_ex_w(
            h_key,
            subkey_utf16.as_ptr(),
            ul_options,
            sam_desired,
            phk_result,
        )
    }
}

/// RegCreateKeyExA: open an existing key or create it if it doesn't exist (ANSI version).
///
/// Converts the ANSI subkey name to UTF-16 and calls RegCreateKeyExW.
///
/// # Safety
/// `lp_sub_key` and `lp_class` (if non-null) must be valid UTF-8 strings.
/// `phk_result` must be a valid writable pointer.
pub unsafe extern "win64" fn reg_create_key_ex_a(
    h_key: usize,
    lp_sub_key: *const u8,
    reserved: u32,
    lp_class: *const u8,
    dw_options: u32,
    sam_desired: u32,
    lp_security_attrs: usize,
    phk_result: *mut usize,
    lpdw_disposition: *mut u32,
) -> i32 {
    // Convert ANSI subkey to UTF-16
    let subkey_utf8 = unsafe { decode_narrow_ptr(lp_sub_key) };
    let subkey_utf16: Vec<u16> = subkey_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Convert ANSI class to UTF-16 (if provided)
    let class_utf16 = if lp_class.is_null() {
        vec![]
    } else {
        let class_utf8 = unsafe { decode_narrow_ptr(lp_class) };
        class_utf8
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    };

    unsafe {
        reg_create_key_ex_w(
            h_key,
            subkey_utf16.as_ptr(),
            reserved,
            if class_utf16.is_empty() {
                std::ptr::null()
            } else {
                class_utf16.as_ptr()
            },
            dw_options,
            sam_desired,
            lp_security_attrs,
            phk_result,
            lpdw_disposition,
        )
    }
}

/// RegQueryValueExA: read a registry value (ANSI version).
///
/// Converts the ANSI value name to UTF-16 and calls RegQueryValueExW.
/// For string data, converts the result back from UTF-16 to UTF-8.
///
/// # Safety
/// All pointer arguments must be valid per their Windows API contracts.
pub unsafe extern "win64" fn reg_query_value_ex_a(
    h_key: usize,
    lp_value_name: *const u8,
    lp_reserved: *mut u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    // Convert ANSI value name to UTF-16
    let value_name_utf8 = unsafe { decode_narrow_ptr(lp_value_name) };
    let value_name_utf16: Vec<u16> = value_name_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // First call to get the data size and type
    let mut data_type = 0u32;
    let mut data_size = 0u32;
    let result = unsafe {
        reg_query_value_ex_w(
            h_key,
            value_name_utf16.as_ptr(),
            lp_reserved,
            &mut data_type,
            std::ptr::null_mut(),
            &mut data_size,
        )
    };

    if result != ERROR_SUCCESS {
        return result;
    }

    // Write type back to caller
    if !lp_type.is_null() {
        unsafe { *lp_type = data_type };
    }

    // Size query
    if lp_data.is_null() {
        if !lpcb_data.is_null() {
            // For string types, convert UTF-16 size to UTF-8 size
            if data_type == REG_SZ || data_type == REG_EXPAND_SZ {
                // Estimate UTF-8 size (UTF-16 bytes / 2 * ~1.5 for worst case)
                let utf16_chars = data_size / 2;
                unsafe { *lpcb_data = utf16_chars * 3 }; // conservative estimate
            } else {
                unsafe { *lpcb_data = data_size };
            }
        }
        return ERROR_SUCCESS;
    }

    // Allocate buffer for UTF-16 data
    let mut utf16_buffer = vec![0u8; data_size as usize];
    let result = unsafe {
        reg_query_value_ex_w(
            h_key,
            value_name_utf16.as_ptr(),
            lp_reserved,
            std::ptr::null_mut(),
            utf16_buffer.as_mut_ptr(),
            &mut data_size,
        )
    };

    if result != ERROR_SUCCESS {
        return result;
    }

    // Convert UTF-16 data to UTF-8 if it's a string type
    if data_type == REG_SZ || data_type == REG_EXPAND_SZ {
        // Convert UTF-16 buffer to string
        let utf16_slice = unsafe {
            std::slice::from_raw_parts(utf16_buffer.as_ptr() as *const u16, data_size as usize / 2)
        };
        let utf8_string = String::from_utf16_lossy(utf16_slice);
        let utf8_bytes = utf8_string.as_bytes();

        // Check if caller's buffer is large enough
        let required_size = utf8_bytes.len() as u32 + 1; // +1 for null terminator
        if !lpcb_data.is_null() {
            unsafe { *lpcb_data = required_size };
        }

        let buffer_size = if lpcb_data.is_null() {
            0u32
        } else {
            unsafe { *lpcb_data }
        };

        if buffer_size < required_size {
            return ERROR_MORE_DATA;
        }

        // Copy UTF-8 data to caller's buffer
        unsafe {
            std::ptr::copy_nonoverlapping(utf8_bytes.as_ptr(), lp_data, utf8_bytes.len());
            *lp_data.add(utf8_bytes.len()) = 0; // null terminator
        }
    } else {
        // Non-string data - copy as-is
        if !lpcb_data.is_null() {
            unsafe { *lpcb_data = data_size };
        }

        let buffer_size = if lpcb_data.is_null() {
            0u32
        } else {
            unsafe { *lpcb_data }
        };

        if buffer_size < data_size {
            return ERROR_MORE_DATA;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(utf16_buffer.as_ptr(), lp_data, data_size as usize);
        }
    }

    ERROR_SUCCESS
}

/// RegSetValueExA: write a registry value (ANSI version).
///
/// Converts the ANSI value name to UTF-16 and calls RegSetValueExW.
/// For string data, converts the ANSI data to UTF-16.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-8 string (or null for
/// the default value). `lp_data` must be valid for `cb_data` bytes.
pub unsafe extern "win64" fn reg_set_value_ex_a(
    h_key: usize,
    lp_value_name: *const u8,
    reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> i32 {
    // Convert ANSI value name to UTF-16
    let value_name_utf8 = unsafe { decode_narrow_ptr(lp_value_name) };
    let value_name_utf16: Vec<u16> = value_name_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Convert data if it's a string type
    let (converted_data, converted_size) =
        if (dw_type == REG_SZ || dw_type == REG_EXPAND_SZ) && !lp_data.is_null() {
            // Convert ANSI string to UTF-16
            let data_slice = unsafe { std::slice::from_raw_parts(lp_data, cb_data as usize) };
            let data_string = String::from_utf8_lossy(data_slice);
            let utf16_data: Vec<u16> = data_string
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let utf16_bytes = unsafe {
                std::slice::from_raw_parts(utf16_data.as_ptr() as *const u8, utf16_data.len() * 2)
            };
            (utf16_bytes.as_ptr(), (utf16_data.len() * 2) as u32)
        } else {
            // Non-string data - pass through
            (lp_data, cb_data)
        };

    unsafe {
        reg_set_value_ex_w(
            h_key,
            value_name_utf16.as_ptr(),
            reserved,
            dw_type,
            converted_data,
            converted_size,
        )
    }
}

/// RegDeleteValueA: delete a named value from an open key (ANSI version).
///
/// Converts the ANSI value name to UTF-16 and calls RegDeleteValueW.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-8 string or null.
pub unsafe extern "win64" fn reg_delete_value_a(h_key: usize, lp_value_name: *const u8) -> i32 {
    // Convert ANSI value name to UTF-16
    let value_name_utf8 = unsafe { decode_narrow_ptr(lp_value_name) };
    let value_name_utf16: Vec<u16> = value_name_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe { reg_delete_value_w(h_key, value_name_utf16.as_ptr()) }
}

// ── LSA stubs ────────────────────────────────────────────────────────────────

/// LsaOpenPolicy — open a handle to the LSA Policy object. Returns an error.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn lsa_open_policy(
    _system_name: *const u8,
    _object_attributes: *const u8,
    _desired_access: u32,
    policy_handle: *mut usize,
) -> i32 {
    if !policy_handle.is_null() {
        unsafe { *policy_handle = 0 };
    }
    0xC000_0022u32 as i32 // STATUS_ACCESS_DENIED
}

/// LsaClose — close a LSA policy handle. Returns STATUS_SUCCESS.
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn lsa_close(_object_handle: usize) -> i32 {
    0 // STATUS_SUCCESS
}

/// LsaAddAccountRights — add privileges to an account. Returns STATUS_SUCCESS.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn lsa_add_account_rights(
    _policy_handle: usize,
    _account_sid: *const u8,
    _user_rights: *const u8,
    _count_of_rights: u32,
) -> i32 {
    0 // STATUS_SUCCESS
}

/// LookupAccountNameW — look up an account name and return its SID.
///
/// Returns FALSE — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn lookup_account_name_w(
    _lp_system_name: *const u16,
    _lp_account_name: *const u16,
    _sid: *mut u8,
    _cb_sid: *mut u32,
    _referenced_domain_name: *mut u16,
    _cch_referenced_domain_name: *mut u32,
    _pe_use: *mut u32,
) -> i32 {
    0 // FALSE
}

/// GetUserNameW — return the current user's name (Wide).
///
/// Writes "weave" into the caller's buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `*lpcb_buffer` characters.
/// `lpcb_buffer` must be writable.
pub unsafe extern "win64" fn get_user_name_w(lp_buffer: *mut u16, lpcb_buffer: *mut u32) -> i32 {
    let user: Vec<u16> = "weave\0".encode_utf16().collect();
    let needed = user.len() as u32;
    if lpcb_buffer.is_null() {
        return 0;
    }
    let available = unsafe { *lpcb_buffer };
    unsafe { *lpcb_buffer = needed };
    if available < needed {
        return 0;
    }
    if !lp_buffer.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(user.as_ptr(), lp_buffer, user.len()) };
    }
    1 // TRUE
}

/// RegDeleteKeyExW — delete a registry key with a 32/64-bit flag (Wide).
///
/// Delegates to RegDeleteKeyW (ignores sam_desired).
///
/// # Safety
/// `lp_sub_key` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn reg_delete_key_ex_w(
    h_key: usize,
    lp_sub_key: *const u16,
    _sam_desired: u32,
    _reserved: u32,
) -> i32 {
    unsafe { reg_delete_key_w(h_key, lp_sub_key) }
}

/// GetFileSecurityW — retrieve security information for a file (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_file_security_w(
    _lp_file_name: *const u16,
    _requested_information: u32,
    _p_security_descriptor: *mut u8,
    _n_length: u32,
    _lp_needed_length: *mut u32,
) -> i32 {
    0 // FALSE
}

/// SetFileSecurityW — set security information for a file (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_file_security_w(
    _lp_file_name: *const u16,
    _security_information: u32,
    _p_security_descriptor: *const u8,
) -> i32 {
    0 // FALSE
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
        // Additional registry and token functions
        "RegDeleteKeyW" => {
            Some(reg_delete_key_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RegDeleteKeyA" => {
            Some(reg_delete_key_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RegEnumKeyExW" => Some(
            reg_enum_key_ex_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegEnumKeyExA" => Some(
            reg_enum_key_ex_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegEnumKeyA" => {
            Some(reg_enum_key_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "OpenProcessToken" => {
            Some(open_process_token as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "LookupPrivilegeValueW" => Some(
            lookup_privilege_value_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "AdjustTokenPrivileges" => Some(
            adjust_token_privileges as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // ANSI registry variants
        "RegOpenKeyExA" => Some(
            reg_open_key_ex_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "RegCreateKeyExA" => Some(
            reg_create_key_ex_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "RegQueryValueExA" => Some(
            reg_query_value_ex_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegSetValueExA" => Some(
            reg_set_value_ex_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegDeleteValueA" => {
            Some(reg_delete_value_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // ── Security / SID stubs (PuTTY gap-fill) ────────────────────────
        "GetUserNameA" => {
            Some(get_user_name_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "AllocateAndInitializeSid" => Some(
            allocate_and_initialize_sid
                as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CopySid" => Some(copy_sid as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize),
        "EqualSid" => Some(equal_sid as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "GetLengthSid" => Some(get_length_sid as *const () as usize),
        "FreeSid" => Some(free_sid as *const () as usize),
        "InitializeSecurityDescriptor" => Some(
            initialize_security_descriptor as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "SetSecurityDescriptorDacl" => Some(
            set_security_descriptor_dacl as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetSecurityDescriptorOwner" => Some(
            set_security_descriptor_owner as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "LsaOpenPolicy" => {
            Some(lsa_open_policy as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "LsaClose" => Some(lsa_close as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "LsaAddAccountRights" => Some(
            lsa_add_account_rights as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "LookupAccountNameW" => Some(
            lookup_account_name_w as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetUserNameW" => {
            Some(get_user_name_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RegDeleteKeyExW" => Some(
            reg_delete_key_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFileSecurityW" => Some(
            get_file_security_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetFileSecurityW" => Some(
            set_file_security_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "SystemFunction036" => {
            Some(system_function_036 as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        _ => None,
    }
}

// ── Crypto stubs ──────────────────────────────────────────────────────────────

/// SystemFunction036 — RtlGenRandom; fills a buffer with pseudo-random bytes.
///
/// Used by 7-Zip and other apps for random seed generation. This stub fills
/// the buffer with bytes from `rand()` — not cryptographically secure but
/// sufficient for seeding hash tables and salt generation in a compatibility layer.
///
/// # Safety
/// `random_buffer` must be a writable buffer of at least `random_buffer_length` bytes.
pub unsafe extern "win64" fn system_function_036(
    random_buffer: *mut u8,
    random_buffer_length: u32,
) -> u8 {
    if random_buffer.is_null() || random_buffer_length == 0 {
        return 0; // FALSE
    }
    for i in 0..random_buffer_length as usize {
        unsafe { *random_buffer.add(i) = (libc::rand() & 0xFF) as u8 };
    }
    1 // TRUE
}

// ── Security / SID stubs ──────────────────────────────────────────────────────

/// GetUserNameA: return the login name of the current user.
///
/// # Safety
/// `lp_buffer` must be writable for `*lpcb_buffer` bytes; `lpcb_buffer` writable.
pub unsafe extern "win64" fn get_user_name_a(lp_buffer: *mut u8, lpcb_buffer: *mut u32) -> i32 {
    let user = b"weave\0";
    let needed = user.len() as u32;
    if lpcb_buffer.is_null() {
        return 0;
    }
    let avail = unsafe { *lpcb_buffer };
    unsafe { *lpcb_buffer = needed };
    if avail < needed || lp_buffer.is_null() {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(user.as_ptr(), lp_buffer, user.len()) };
    1
}

/// A minimal fake SID (Security Identifier) stored on the heap.
#[repr(C)]
pub struct FakeSid {
    revision: u8,
    sub_authority_count: u8,
    identifier_authority: [u8; 6],
    sub_authority: [u32; 8],
}

/// AllocateAndInitializeSid: create a SID with up to 8 sub-authorities.
///
/// # Safety
/// `pidentifier_authority` must be a valid 6-byte authority value.
/// `new_sid` must be a writable `*mut PSID`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn allocate_and_initialize_sid(
    pidentifier_authority: *const u8,
    n_sub_authority_count: u8,
    n_sub_authority0: u32,
    n_sub_authority1: u32,
    n_sub_authority2: u32,
    n_sub_authority3: u32,
    n_sub_authority4: u32,
    n_sub_authority5: u32,
    n_sub_authority6: u32,
    n_sub_authority7: u32,
    new_sid: *mut *mut FakeSid,
) -> i32 {
    if new_sid.is_null() {
        return 0;
    }
    let sid = Box::new(FakeSid {
        revision: 1,
        sub_authority_count: n_sub_authority_count.min(8),
        identifier_authority: if !pidentifier_authority.is_null() {
            unsafe { *(pidentifier_authority as *const [u8; 6]) }
        } else {
            [0u8; 6]
        },
        sub_authority: [
            n_sub_authority0,
            n_sub_authority1,
            n_sub_authority2,
            n_sub_authority3,
            n_sub_authority4,
            n_sub_authority5,
            n_sub_authority6,
            n_sub_authority7,
        ],
    });
    unsafe { *new_sid = Box::into_raw(sid) };
    1
}

/// CopySid: copy a SID to a buffer. Returns TRUE.
///
/// # Safety
/// Both pointers must be valid if non-null.
pub unsafe extern "win64" fn copy_sid(
    n_destination_sid_length: u32,
    p_destination_sid: *mut u8,
    p_source_sid: *const u8,
) -> i32 {
    if p_destination_sid.is_null() || p_source_sid.is_null() {
        return 0;
    }
    let copy = n_destination_sid_length as usize;
    unsafe { std::ptr::copy_nonoverlapping(p_source_sid, p_destination_sid, copy) };
    1
}

/// EqualSid: compare two SIDs. Returns FALSE (conservative — we can't know).
///
/// # Safety
/// Both pointers must be valid FakeSid pointers.
pub unsafe extern "win64" fn equal_sid(_sid1: *const FakeSid, _sid2: *const FakeSid) -> i32 {
    0
}

/// GetLengthSid: return the length of a SID in bytes. Returns size of FakeSid.
pub extern "win64" fn get_length_sid(_p_sid: *const u8) -> u32 {
    std::mem::size_of::<FakeSid>() as u32
}

/// FreeSid: free a SID allocated by AllocateAndInitializeSid. Returns NULL.
pub extern "win64" fn free_sid(p_sid: *mut FakeSid) -> *mut FakeSid {
    if !p_sid.is_null() {
        unsafe { drop(Box::from_raw(p_sid)) };
    }
    std::ptr::null_mut()
}

/// InitializeSecurityDescriptor: zero-initialise a security descriptor. Returns TRUE.
///
/// # Safety
/// `p_security_descriptor` must be writable for at least 20 bytes.
pub unsafe extern "win64" fn initialize_security_descriptor(
    p_security_descriptor: *mut u8,
    _dw_revision: u32,
) -> i32 {
    if p_security_descriptor.is_null() {
        return 0;
    }
    unsafe { std::ptr::write_bytes(p_security_descriptor, 0, 20) };
    1
}

/// SetSecurityDescriptorDacl: set the DACL in a security descriptor. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not fully validated.
pub unsafe extern "win64" fn set_security_descriptor_dacl(
    _p_security_descriptor: *mut u8,
    _b_dacl_present: i32,
    _p_dacl: *const u8,
    _b_dacl_defaulted: i32,
) -> i32 {
    1
}

/// SetSecurityDescriptorOwner: set the owner SID. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not fully validated.
pub unsafe extern "win64" fn set_security_descriptor_owner(
    _p_security_descriptor: *mut u8,
    _p_owner: *const u8,
    _b_owner_defaulted: i32,
) -> i32 {
    1
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
