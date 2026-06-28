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

use core::ptr::{read_unaligned, write_unaligned};
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
    // SAFETY: caller guarantees `ptr` points to a null-terminated UTF-16 sequence;
    // we advance through it one u16 at a time until the null terminator is found.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `ptr` is non-null (checked above) and valid for `len` u16 elements
    // (we just walked the entire string to find the null).  The slice does not
    // outlive this function — it is consumed by `from_utf16_lossy` immediately.
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
    // SAFETY: caller guarantees `ptr` points to a null-terminated byte sequence;
    // we scan byte-by-byte until the null terminator is found.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `ptr` is non-null (checked above) and valid for `len` bytes
    // (we just walked the entire string).  The slice is consumed immediately by
    // `from_utf8_lossy` and does not escape this function.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(slice).into_owned()
}

// ── RegOpenKeyExW ─────────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c:644 — if retkey is null returns ERROR_INVALID_PARAMETER
// (not ERROR_INVALID_HANDLE); if name is empty AND hkey is a predefined root, sets *retkey=hkey
// and returns ERROR_SUCCESS directly (no syscall); strips leading backslash for HKCU_CLASSES_ROOT.
/// RegOpenKeyExW: open a registry key and return a handle.
///
/// Returns `ERROR_SUCCESS` on success. The new handle is written to `phk_result`.
///
/// # Safety
/// `lp_sub_key`, if non-null, must be a valid null-terminated UTF-16 string.
/// `phk_result` must be a valid writable pointer.
// Wine ref: dlls/kernelbase/registry.c:644 — NULL retkey → ERROR_INVALID_PARAMETER; empty name + predefined root sets *retkey=hkey directly; strips leading backslash for HKCR
pub unsafe extern "win64" fn reg_open_key_ex_w(
    h_key: usize,
    lp_sub_key: *const u16,
    ul_options: u32,   // reserved — ignored
    _sam_desired: u32, // access rights — ignored (all keys readable)
    phk_result: *mut usize,
) -> i32 {
    let _ = ul_options;
    if phk_result.is_null() {
        return ERROR_INVALID_PARAMETER; // Wine: ERROR_INVALID_PARAMETER (not ERROR_INVALID_HANDLE)
    }

    let base_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    // SAFETY: RegOpenKeyExW: lp_sub_key is documented as optional (may be null for the root
    // key itself); decode_wide_ptr handles the null case.  When non-null, the Win32 API
    // contract requires callers to supply a valid null-terminated UTF-16 path.
    let subkey = unsafe { decode_wide_ptr(lp_sub_key) };
    let key_path = match resolve_subkey(&base_path, &subkey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    let is_putty_path = {
        let path_str = key_path.to_string_lossy();
        path_str.contains("PuTTY") || path_str.contains("SimonTatham")
    };

    if !key_path.is_dir() {
        if is_putty_path {
            eprintln!(
                "weave/advapi32: RegOpenKeyExW PuTTY key not found — expected on first launch"
            );
        }
        return ERROR_FILE_NOT_FOUND;
    }

    if is_putty_path {
        let path_str = key_path.to_string_lossy();
        eprintln!("weave/advapi32: RegOpenKeyExW key={path_str} → SUCCESS");
    }

    let handle = handles::alloc(HandleKind::RegistryKey(key_path));
    // SAFETY: phk_result non-null checked at function entry (returns ERROR_INVALID_PARAMETER
    // if null).  The Win32 API contract requires callers to provide a valid, writable HKEY*.
    unsafe { *phk_result = handle };
    ERROR_SUCCESS
}

// ── RegCreateKeyExW ───────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c:566 — if retkey is null returns ERROR_BADKEY (1010);
// if reserved != 0 returns ERROR_INVALID_PARAMETER; calls create_key() which calls
// NtCreateKey; writes REG_CREATED_NEW_KEY (1) or REG_OPENED_EXISTING_KEY (2) to *dispos.
/// RegCreateKeyExW: open an existing key or create it if it doesn't exist.
///
/// `lp_class`, `dw_options`, `sam_desired`, `lp_security_attrs` are ignored.
/// `lpdw_disposition` receives `REG_OPENED_EXISTING_KEY` (2) or
/// `REG_CREATED_NEW_KEY` (1).
///
/// # Safety
/// `lp_sub_key` and `lp_class` (if non-null) must be valid UTF-16 strings.
/// `phk_result` must be a valid writable pointer.
// Wine ref: dlls/kernelbase/registry.c:566 — NULL retkey → ERROR_BADKEY; reserved!=0 → ERROR_INVALID_PARAMETER; writes REG_CREATED_NEW_KEY(1) or REG_OPENED_EXISTING_KEY(2) to *dispos
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
        return 1010; // ERROR_BADKEY — Wine returns this, not ERROR_INVALID_HANDLE
    }

    let base_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    // SAFETY: RegCreateKeyExW: lp_sub_key is documented as optional (null means the key
    // itself); decode_wide_ptr handles null.  When non-null, callers must supply a valid
    // null-terminated UTF-16 path per the Win32 API contract.
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
        // SAFETY: lpdw_disposition is optional per MSDN; we only write through it
        // after confirming it is non-null.  The Win32 API contract requires that when
        // non-null, it points to a valid, writable DWORD (u32) aligned on a 4-byte
        // boundary.
        unsafe {
            *lpdw_disposition = if existed {
                2 // REG_OPENED_EXISTING_KEY
            } else {
                1 // REG_CREATED_NEW_KEY
            };
        }
    }

    let handle = handles::alloc(HandleKind::RegistryKey(key_path));
    // SAFETY: phk_result non-null checked at function entry (returns ERROR_BADKEY if null).
    // The Win32 API contract requires callers to provide a valid, writable HKEY*.
    unsafe { *phk_result = handle };
    ERROR_SUCCESS
}

// ── RegQueryValueExW ──────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c:1636 — (data && !count) || reserved → ERROR_INVALID_PARAMETER;
// for REG_SZ/REG_EXPAND_SZ, appends a null WCHAR if the stored data doesn't end with one and
// there's room in the buffer; fills *type and *count on success and on ERROR_MORE_DATA;
// calls NtQueryValueKey via KEY_VALUE_PARTIAL_INFORMATION.
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
// Wine ref: dlls/kernelbase/registry.c:1636 — appends NUL for REG_SZ if space allows; data+!count → ERROR_INVALID_PARAMETER; perf keys handled separately via query_perf_data
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

    // SAFETY: RegQueryValueExW: lp_value_name is documented as optional (null means the
    // default value ""); decode_wide_ptr handles the null case.  When non-null, callers
    // must supply a valid null-terminated UTF-16 string.
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
        // SAFETY: lp_type is optional per MSDN; written only after confirming non-null.
        // The Win32 API contract requires callers to provide a valid, writable DWORD*.
        unsafe { *lp_type = reg_type };
    }

    let data_len = data.len() as u32;

    if lp_data.is_null() {
        // Size-probe call: just report the required size.
        if !lpcb_data.is_null() {
            // SAFETY: lpcb_data is optional per MSDN (may be null for a pure type query);
            // written only after confirming non-null.  The Win32 API contract requires that
            // when non-null it points to a valid, writable DWORD*.
            unsafe { *lpcb_data = data_len };
        }
        return ERROR_SUCCESS;
    }

    // Check buffer size.
    let buf_size = if lpcb_data.is_null() {
        0u32
    } else {
        // SAFETY: lpcb_data is non-null here; the Win32 API contract requires callers to
        // provide a valid DWORD* when lp_data is also non-null (validated at function entry).
        unsafe { *lpcb_data }
    };

    if !lpcb_data.is_null() {
        // SAFETY: same as above — lpcb_data is non-null and points to a valid DWORD.
        unsafe { *lpcb_data = data_len };
    }

    if buf_size < data_len {
        return ERROR_MORE_DATA;
    }

    // Copy data into caller's buffer.
    // SAFETY: lp_data is non-null (checked above) and the Win32 API contract requires
    // callers to supply a buffer of at least *lpcb_data bytes.  We confirmed buf_size >=
    // data_len before reaching this point, so the write cannot overflow the buffer.
    // data.as_ptr() is a valid Rust slice — no aliasing with lp_data (caller-owned memory).
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), lp_data, data.len()) };

    // Wine behaviour: for string types, guarantee a UTF-16 null terminator at
    // the end of the buffer if the data doesn't already end with one and there
    // is room for two more bytes.
    if reg_type == REG_SZ || reg_type == REG_EXPAND_SZ {
        let len = data.len();
        let already_null = len >= 2 && data[len - 2] == 0 && data[len - 1] == 0;
        if !already_null && buf_size as usize >= len + 2 {
            // SAFETY: We checked buf_size >= len + 2, so writing two bytes past the end
            // of the data (but still within the caller's declared buffer) is safe.
            // lp_data is non-null and points into the caller-provided buffer.
            unsafe {
                *lp_data.add(len) = 0;
                *lp_data.add(len + 1) = 0;
            }
        }
    }

    ERROR_SUCCESS
}

// ── RegSetValueExW ────────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c:1209 — if (!data && count) returns ERROR_NOACCESS;
// auto-appends null WCHAR terminator for string types if count doesn't include it;
// calls NtSetValueKey. Weave returns ERROR_FILE_NOT_FOUND for null data+nonzero count;
// should be ERROR_NOACCESS.
// Known gap: Weave returns ERROR_FILE_NOT_FOUND for null data; Wine returns ERROR_NOACCESS.
/// RegSetValueExW: write a registry value.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-16 string (or null for
/// the default value). `lp_data` must be valid for `cb_data` bytes.
// Wine ref: dlls/kernelbase/registry.c:1209 — auto-extends count by sizeof(WCHAR) if string not NUL-terminated but space allows; data ptr >>16==0 → ERROR_NOACCESS
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

    // SAFETY: RegSetValueExW: lp_value_name is documented as optional (null means the
    // default value); decode_wide_ptr handles null.  When non-null, callers must supply a
    // valid null-terminated UTF-16 string per the Win32 API contract.
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
        // SAFETY: RegSetValueExW: lp_data is non-null and cb_data > 0 (both checked above).
        // The Win32 API contract requires callers to supply a valid buffer of at least
        // cb_data bytes containing the value data to write.
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

// Wine ref: dlls/kernelbase/registry.c — calls NtDeleteValueKey(hkey, &nameW);
// null value name deletes the default value ("").
/// RegDeleteValueW: delete a named value from an open key.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-16 string or null.
// Wine ref: dlls/kernelbase/registry.c — NtDeleteValueKey(hkey, &nameW); null value name deletes the default value ("")
pub unsafe extern "win64" fn reg_delete_value_w(h_key: usize, lp_value_name: *const u16) -> i32 {
    let key_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    // SAFETY: RegDeleteValueW: lp_value_name is documented as optional (null deletes the
    // default value); decode_wide_ptr handles null.  When non-null, callers must supply a
    // valid null-terminated UTF-16 string per the Win32 API contract.
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

// Wine ref: dlls/kernelbase/registry.c:1129 — if hkey == NULL returns ERROR_INVALID_HANDLE;
// if hkey >= 0x80000000 (predefined root) returns ERROR_SUCCESS immediately without NtClose;
// otherwise calls NtClose(hkey). Weave previously didn't check for NULL handle.
/// RegCloseKey: close a registry key handle.
///
/// Predefined handles (HKLM, HKCU, etc.) are always valid and closing them is
/// a no-op that returns `ERROR_SUCCESS`.
// Wine ref: dlls/kernelbase/registry.c:1129 — hkey>=0x80000000 returns ERROR_SUCCESS without NtClose; NULL → ERROR_INVALID_HANDLE
pub extern "win64" fn reg_close_key(h_key: usize) -> i32 {
    // Wine: NULL handle → ERROR_INVALID_HANDLE
    if h_key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    // Predefined handles do not live in the table — silently succeed.
    if predefined_hive_path(h_key).is_some() {
        return ERROR_SUCCESS;
    }
    // For real opened handles, free the slot.
    handles::free(h_key);
    ERROR_SUCCESS
}

// ── RegQueryInfoKeyW ──────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c:957 — if class != null && !class_len on WinNT returns
// ERROR_INVALID_PARAMETER; calls NtQueryKey(KeyFullInformation) which returns subkey count,
// value count, class name, max key/value sizes, and last write time.
// Known gap: Weave reads the filesystem (counts files/dirs) instead of a proper registry store;
// lp_ft_last_write_time always left as caller's value (not written); max_subkey_len not filled.
/// RegQueryInfoKeyW: return metadata about a key (subkey count, value count, …).
///
/// Phase 2: only fills in the value count and the max value name/data sizes.
/// Subkey enumeration data is zeroed — apps that enumerate subkeys will get an
/// empty list, which they must handle gracefully.
///
/// # Safety
/// All output pointer arguments may be null (callers pass null for fields they
/// don't need, per MSDN).
// Wine ref: dlls/kernelbase/registry.c — NtQueryKey(KeyFullInformation); fills all output fields; null output pointers are silently skipped
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

    // SAFETY (all four output writes below): RegQueryInfoKeyW documents every output
    // parameter as optional — callers pass null for fields they don't need (MSDN).
    // We only write through each pointer after confirming it is non-null.  The Win32 API
    // contract requires that when non-null, each pointer addresses a valid, writable DWORD.
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

// Wine ref: dlls/kernelbase/registry.c:2144 — returns ERROR_INVALID_PARAMETER when
// (data && !count) || reserved || !value || !val_count; calls NtEnumerateValueKey with
// KeyValueFullInformation; val_count is in WCHAR units (not bytes); fills *val_count with
// the number of chars (excluding null) on success.
/// RegEnumValueW: enumerate the values of an open registry key.
///
/// `dw_index` is the zero-based index of the value to retrieve. Returns
/// `ERROR_NO_MORE_ITEMS` (259) when the index is out of range.
///
/// # Safety
/// `lp_value_name` must be valid for `*lpcb_value_name` UTF-16 code units.
/// `lp_data` (if non-null) must be valid for `*lpcb_data` bytes.
// Wine ref: dlls/kernelbase/registry.c:2144 — val_count in WCHAR units; !value||!val_count → ERROR_INVALID_PARAMETER; KeyValueFullInformation; sets *val_count to chars excluding null on success
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

    // Wine: !value || !val_count → ERROR_INVALID_PARAMETER
    if lp_value_name.is_null() || lpcb_value_name.is_null() {
        return ERROR_INVALID_PARAMETER;
    }

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

    // lpcb_value_name null already checked above (ERROR_INVALID_PARAMETER)
    // SAFETY: lpcb_value_name non-null is enforced at function entry.  The Win32 API
    // contract requires callers to supply a valid DWORD* containing the buffer capacity
    // in characters; we read it once to get the available space and then overwrite it
    // with the required size (Wine behaviour: always updates even on ERROR_MORE_DATA).
    let buf_chars = unsafe { *lpcb_value_name };
    unsafe { *lpcb_value_name = name_chars_needed };

    if buf_chars < name_chars_needed {
        return ERROR_MORE_DATA;
    }

    // Copy name into caller buffer.
    if !lp_value_name.is_null() {
        for (i, &c) in name_wide.iter().enumerate() {
            // SAFETY: buf_chars >= name_chars_needed (checked above), so lp_value_name is
            // valid for at least name_wide.len() + 1 u16 elements.  The Win32 API contract
            // requires callers to supply a writable buffer large enough for *lpcb_value_name
            // characters (including the null terminator).
            unsafe { *lp_value_name.add(i) = c };
        }
        // SAFETY: same as above — the null terminator fits within the declared buffer.
        unsafe { *lp_value_name.add(name_wide.len()) = 0 }; // null terminator
    }

    // Read type + data.
    let (reg_type, data) = match read_value_file(entry) {
        Some(v) => v,
        None => (REG_NONE, vec![]),
    };

    if !lp_type.is_null() {
        // SAFETY: lp_type is optional per MSDN; written only after confirming non-null.
        // The Win32 API contract requires that when non-null it points to a valid DWORD*.
        unsafe { *lp_type = reg_type };
    }

    let data_len = data.len() as u32;
    if !lpcb_data.is_null() {
        // SAFETY: lpcb_data is optional per MSDN; we only read/write through it after
        // confirming non-null.  The Win32 API contract requires callers to supply a valid
        // DWORD* holding the data buffer capacity in bytes when lp_data is also provided.
        let buf = unsafe { *lpcb_data };
        unsafe { *lpcb_data = data_len };
        if !lp_data.is_null() && buf >= data_len {
            // SAFETY: lp_data is non-null and buf >= data_len, so the destination buffer
            // is large enough.  The Win32 API contract requires callers to supply a buffer
            // of at least *lpcb_data bytes.  data is a Rust-owned Vec — no aliasing.
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), lp_data, data.len()) };
        } else if buf < data_len {
            return ERROR_MORE_DATA;
        }
    }

    ERROR_SUCCESS
}

// ── RegDeleteKeyW ─────────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c — calls RegOpenKeyExW to get child handle,
// then NtDeleteKey; if the key has subkeys, must delete them first (Wine does this
// iteratively). Known gap: Weave uses remove_dir_all which handles recursion on the filesystem.
/// RegDeleteKeyW: delete a registry key and all its subkeys/values.
///
/// # Safety
/// `lp_sub_key` must be a valid null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/registry.c — RegOpenKeyExW to get child handle then NtDeleteKey; subkeys must be deleted first (NT has no recursive delete)
pub unsafe extern "win64" fn reg_delete_key_w(h_key: usize, lp_sub_key: *const u16) -> i32 {
    let base_path = match key_to_path(h_key) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };

    // SAFETY: RegDeleteKeyW: lp_sub_key is documented as required; decode_wide_ptr handles
    // null defensively.  When non-null, callers must supply a valid null-terminated UTF-16
    // string per the Win32 API contract.
    let subkey = unsafe { decode_wide_ptr(lp_sub_key) };
    let key_path = match resolve_subkey(&base_path, &subkey) {
        Some(p) => p,
        None => return ERROR_FILE_NOT_FOUND,
    };

    // Check if it's a directory (key)
    if !key_path.is_dir() {
        return ERROR_FILE_NOT_FOUND;
    }

    match remove_dir_no_follow(&key_path) {
        Ok(_) => ERROR_SUCCESS,
        Err(_) => ERROR_FILE_NOT_FOUND,
    }
}

/// Recursively delete a directory tree without following symlinks.
///
/// `std::fs::remove_dir_all` follows symlinks on some platforms, which
/// could allow a symlink planted inside the registry directory tree to
/// escape the prefix and delete host paths.  This implementation uses
/// `symlink_metadata` (no follow) to detect and skip symlinks rather
/// than descending into them.
fn remove_dir_no_follow(path: &std::path::Path) -> std::io::Result<()> {
    let meta = path.symlink_metadata()?;
    if meta.is_symlink() {
        // Refuse to delete through a symlink — this should never appear in
        // Weave's registry tree, so treat it as a permissions error.
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to remove symlink in registry tree",
        ));
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let child_meta = entry.path().symlink_metadata()?;
        if child_meta.is_dir() && !child_meta.is_symlink() {
            remove_dir_no_follow(&entry.path())?;
        } else {
            // File or symlink — remove without following.
            std::fs::remove_file(entry.path())?;
        }
    }
    std::fs::remove_dir(path)
}

// ── RegEnumKeyExW ─────────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c — calls NtEnumerateKey(KeyBasicInformation);
// returns ERROR_NO_MORE_ITEMS (259) when index out of range; writes subkey name
// (without path) into lp_name. lpcch_name is char count including null on input,
// set to char count excluding null on output.
/// RegEnumKeyExW: enumerate the subkeys of an open registry key.
///
/// # Safety
/// `lp_name` must be valid for `*lpcch_name` UTF-16 code units.
/// Unused parameters are ignored.
// Wine ref: dlls/kernelbase/registry.c — NtEnumerateKey(KeyBasicInformation); lpcch_name is chars including null on input, chars excluding null on output; ERROR_NO_MORE_ITEMS(259) when out of range
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

    // SAFETY: lpcch_name non-null is enforced at the check above (returns ERROR_INVALID_HANDLE
    // if null).  The Win32 API contract requires callers to supply a valid DWORD* containing
    // the buffer capacity in characters; we read it to check available space and then update
    // it with the required size (Wine behaviour: always updates *lpcch_name even on overflow).
    let buf_capacity = unsafe { *lpcch_name };
    unsafe { *lpcch_name = required_chars };

    if buf_capacity < required_chars {
        return ERROR_MORE_DATA;
    }

    // Copy wide chars into caller's buffer
    for (i, &c) in wide.iter().enumerate() {
        // SAFETY: buf_capacity >= required_chars (checked above), so lp_name is valid for
        // at least wide.len() + 1 u16 elements.  The Win32 API contract requires callers to
        // supply a writable buffer of at least *lpcch_name UTF-16 code units.
        unsafe { *lp_name.add(i) = c };
    }
    // SAFETY: same as above — the null terminator fits within the declared buffer.
    unsafe { *lp_name.add(wide.len()) = 0 }; // null terminator

    ERROR_SUCCESS
}

// ── RegDeleteKeyA ─────────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c — RegDeleteKeyA converts ANSI name via
// RtlAnsiStringToUnicodeString then calls RegDeleteKeyW. No behavioral difference
// from RegDeleteKeyW except ANSI→UTF-16 conversion.
/// RegDeleteKeyA: delete a registry key and all its subkeys/values (ANSI version).
///
/// Converts the ANSI subkey name to UTF-16 and calls RegDeleteKeyW.
///
/// # Safety
/// `lp_sub_key` must be a valid null-terminated UTF-8 string.
// Wine ref: dlls/kernelbase/registry.c — RegDeleteKeyA converts ANSI via RtlAnsiStringToUnicodeString then calls RegDeleteKeyW; no behavioral difference from W variant
pub unsafe extern "win64" fn reg_delete_key_a(h_key: usize, lp_sub_key: *const u8) -> i32 {
    // Convert ANSI subkey to UTF-16
    // SAFETY: RegDeleteKeyA: lp_sub_key is documented as required; decode_narrow_ptr handles
    // null defensively.  When non-null, callers must supply a valid null-terminated ANSI
    // (UTF-8 compatible) string per the Win32 API contract.
    let subkey_utf8 = unsafe { decode_narrow_ptr(lp_sub_key) };
    let subkey_utf16: Vec<u16> = subkey_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: subkey_utf16 is a locally-owned Vec with a null terminator appended above;
    // it outlives the call to reg_delete_key_w which does not store the pointer.
    unsafe { reg_delete_key_w(h_key, subkey_utf16.as_ptr()) }
}

// ── RegEnumKeyExA ─────────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c — RegEnumKeyExA converts output key name
// from Unicode to ANSI via RtlUnicodeStringToAnsiString; lpcchName is in chars
// (bytes for ANSI), same semantics as W variant. Wine updates *lpcchName to
// chars-excluding-null on success.
/// RegEnumKeyExA: enumerate the subkeys of an open registry key (ANSI version).
///
/// Same logic as RegEnumKeyExW but output is ANSI.
///
/// # Safety
/// `lp_name` must be valid for `*lpcch_name` UTF-8 bytes.
/// Unused parameters are ignored.
// Wine ref: dlls/kernelbase/registry.c — converts output name from Unicode via RtlUnicodeStringToAnsiString; lpcchName in bytes (chars for ANSI); same index semantics as W variant
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

    // SAFETY: lpcch_name non-null is enforced at the check above (returns ERROR_INVALID_HANDLE
    // if null).  The Win32 API contract requires callers to supply a valid DWORD* containing
    // the buffer capacity in bytes; we read it to check available space and then update it
    // with the required size (consistent with Wine's update-even-on-overflow behaviour).
    let buf_capacity = unsafe { *lpcch_name };
    unsafe { *lpcch_name = required_chars };

    if buf_capacity < required_chars {
        return ERROR_MORE_DATA;
    }

    // Copy bytes into caller's buffer
    for (i, &c) in narrow.iter().enumerate() {
        // SAFETY: buf_capacity >= required_chars (checked above), so lp_name is valid for
        // at least narrow.len() + 1 bytes.  The Win32 API contract requires callers to
        // supply a writable buffer of at least *lpcch_name bytes.
        unsafe { *lp_name.add(i) = c };
    }
    // SAFETY: same as above — the null terminator fits within the declared buffer.
    unsafe { *lp_name.add(narrow.len()) = 0 }; // null terminator

    ERROR_SUCCESS
}

// ── RegEnumKeyA ───────────────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c — RegEnumKeyA is a thin wrapper around
// RegEnumKeyExA with class and timestamp params set to NULL. Deprecated Win3.1
// API; Wine maps it directly.
/// RegEnumKeyA: legacy 3-parameter subkey enumeration (ANSI).
///
/// Wrapper around `RegEnumKeyExA` with no class or timestamp parameters.
///
/// # Safety
/// `lp_name` must be a writable buffer of at least `cch_name` bytes.
// Wine ref: dlls/kernelbase/registry.c — RegEnumKeyA thin wrapper around RegEnumKeyExA with class+timestamp NULL; deprecated Win3.1 API
pub unsafe extern "win64" fn reg_enum_key_a(
    h_key: usize,
    dw_index: u32,
    lp_name: *mut u8,
    cch_name: u32,
) -> i32 {
    let mut cch = cch_name;
    // SAFETY: lp_name is the caller's buffer passed through directly.  The Win32 API
    // contract for RegEnumKeyA requires lp_name to be writable for cch_name bytes.
    // &mut cch is a stack variable — always valid.  Null is passed for all optional
    // output parameters (class, class_len, last_write_time) that this legacy API omits.
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

// Wine ref: dlls/kernelbase/security.c:828 — NtOpenProcessToken
/// OpenProcessToken: open the access token associated with a process.
///
/// For the current process (pseudo-handle `-1` = `GetCurrentProcess()`), returns
/// a fake token handle (`0xCAFEBEE0`). Returns FALSE for any other process handle.
///
/// # Safety
/// `token_handle` must be a valid writable pointer (non-null).
// Wine ref: dlls/kernelbase/security.c:828 — NtOpenProcessToken
pub unsafe extern "win64" fn open_process_token(
    process_handle: usize,
    _desired_access: u32,
    token_handle: *mut usize,
) -> i32 {
    if token_handle.is_null() {
        weave_common::set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }
    // Accept ONLY the current-process pseudo-handle (usize::MAX == -1 / GetCurrentProcess()).
    // Reject any other handle — returning a fake token for a wrong process causes
    // callers (7-Zip, PuTTY) to SIGABRT when AdjustTokenPrivileges "succeeds" but the
    // operation then fails (no real privilege enforcement in Phase B).
    if process_handle == usize::MAX {
        // SAFETY: token_handle is non-null (checked above). Guest may pass an
        // unaligned pointer (e.g. 7-Zip on stack with 4-byte alignment), so use
        // write_unaligned.
        unsafe { write_unaligned(token_handle, 0xCAFEBEE0) };
        1 // TRUE
    } else {
        weave_common::set_last_error(5); // ERROR_ACCESS_DENIED
        0 // FALSE
    }
}

// ── LookupPrivilegeValueW ─────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/security.c:2841 — static privilege table
/// LookupPrivilegeValueW: retrieve the locally unique identifier (LUID) for a
/// privilege by name. Supports a static set of well-known privileges.
///
/// Returns TRUE on match and writes the LUID to `lp_luid`.
///
/// # Safety
/// `lp_name` must be a valid null-terminated UTF-16 string. `lp_luid` must be
/// a valid writable pointer. `lp_system_name` is ignored (remote lookup not
/// supported).
// Wine ref: dlls/kernelbase/security.c:2841 — static privilege table; real Wine reads from HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Data
pub unsafe extern "win64" fn lookup_privilege_value_w(
    lp_system_name: *const u16,
    lp_name: *const u16,
    lp_luid: *mut u64,
) -> i32 {
    if lp_name.is_null() || lp_luid.is_null() {
        weave_common::set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }
    if !lp_system_name.is_null() {
        // Remote system lookups are not supported.
        weave_common::set_last_error(1313); // ERROR_NO_SUCH_PRIVILEGE
        return 0; // FALSE
    }

    // SAFETY: lp_name is non-null (checked above).  The Win32 API contract for
    // LookupPrivilegeValueW requires callers to provide a valid null-terminated
    // UTF-16 string as the privilege name. decode_wide_ptr scans until the null
    // terminator and returns the decoded String.
    let name = unsafe { decode_wide_ptr(lp_name) };

    static TABLE: std::sync::OnceLock<Vec<(&'static str, u64)>> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        vec![
            ("SeDebugPrivilege", 1),
            ("SeBackupPrivilege", 2),
            ("SeRestorePrivilege", 3),
            ("SeShutdownPrivilege", 4),
            ("SeTakeOwnershipPrivilege", 5),
            ("SeLoadDriverPrivilege", 6),
            ("SeSecurityPrivilege", 7),
            ("SeSystemEnvironmentPrivilege", 8),
            ("SeSystemProfilePrivilege", 9),
            ("SeIncreaseQuotaPrivilege", 10),
            ("SeCreateTokenPrivilege", 11),
            ("SeTcbPrivilege", 12),
        ]
    });

    for &(privilege_name, luid) in table.iter() {
        if name == privilege_name {
            // SAFETY: lp_luid is non-null (checked above). Guest may pass an
            // unaligned pointer (7-Zip passes stack pointer at 4-byte alignment),
            // so use write_unaligned.
            unsafe { write_unaligned(lp_luid, luid) };
            return 1; // TRUE
        }
    }

    weave_common::set_last_error(1313); // ERROR_NO_SUCH_PRIVILEGE
    0 // FALSE
}

// ── AdjustTokenPrivileges ─────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/security.c:2970 — NtAdjustPrivilegesToken
/// AdjustTokenPrivileges: enable or disable privileges in the specified access
/// token.  Phase B: validates the fake token handle, then no-ops the adjustment.
///
/// Returns TRUE.  The caller may check `GetLastError` for `ERROR_NOT_ALL_ASSIGNED`
/// (we do not set it — all requested privileges are trivially "applied").
///
/// # Safety
/// `new_state` points to a `TOKEN_PRIVILEGES` structure if non-null.
/// `previous_state`, if non-null, receives the previous privilege state.
/// `return_length`, if non-null, receives the required buffer size.
// Wine ref: dlls/kernelbase/security.c:2970 — NtAdjustPrivilegesToken; returns TRUE even if not all privileges assigned (caller checks GetLastError for ERROR_NOT_ALL_ASSIGNED)
pub unsafe extern "win64" fn adjust_token_privileges(
    token_handle: usize,
    disable_all_privileges: i32,
    new_state: *const u8,
    _buffer_length: u32,
    previous_state: *mut u8,
    return_length: *mut u32,
) -> i32 {
    // Validate the token handle matches our fake token (0xCAFEBEE0).
    if token_handle != 0xCAFEBEE0 {
        weave_common::set_last_error(6); // ERROR_INVALID_HANDLE
        return 0; // FALSE
    }

    if disable_all_privileges != 0 {
        // Disable all — no-op, return success.
        return 1; // TRUE
    }

    if !new_state.is_null() {
        // SAFETY: new_state is non-null (checked above). Use read_unaligned
        // because guests may pass pointers at 4-byte alignment from stack frames.
        let _count = unsafe { read_unaligned(new_state as *const u32) };

        if !previous_state.is_null() {
            // SAFETY: previous_state is non-null.
            unsafe { write_unaligned(previous_state as *mut u32, 0) };
        }

        if !return_length.is_null() {
            // SAFETY: return_length is non-null.
            unsafe { write_unaligned(return_length, 16) };
        }
    }

    // Per MSDN, AdjustTokenPrivileges returns TRUE even when not all privileges
    // were assigned — caller must check GetLastError for ERROR_NOT_ALL_ASSIGNED
    // to detect partial success. We set this because no privileges were actually
    // applied (Phase B — no real privilege enforcement).
    weave_common::set_last_error(1300); // ERROR_NOT_ALL_ASSIGNED
    1 // TRUE
}

// ── ANSI registry variants ────────────────────────────────────────────────────

// Wine ref: dlls/kernelbase/registry.c:688 — RegOpenKeyExA converts ANSI name via
// RtlAnsiStringToUnicodeString into TEB->StaticUnicodeString then calls open_key;
// for a predefined root with empty name, sets *retkey=hkey and returns immediately.
/// RegOpenKeyExA: open a registry key and return a handle (ANSI version).
///
/// Converts the ANSI subkey name to UTF-16 and calls RegOpenKeyExW.
///
/// # Safety
/// `lp_sub_key`, if non-null, must be a valid null-terminated UTF-8 string.
/// `phk_result` must be a valid writable pointer.
// Wine ref: dlls/kernelbase/registry.c:688 — RtlAnsiStringToUnicodeString into TEB->StaticUnicodeString then open_key; predefined root + empty name → *retkey=hkey immediately
pub unsafe extern "win64" fn reg_open_key_ex_a(
    h_key: usize,
    lp_sub_key: *const u8,
    ul_options: u32,
    sam_desired: u32,
    phk_result: *mut usize,
) -> i32 {
    // Convert ANSI subkey to UTF-16
    // SAFETY: RegOpenKeyExA: lp_sub_key is optional (may be null for the root key);
    // decode_narrow_ptr handles null.  When non-null, callers must supply a valid
    // null-terminated ANSI string per the Win32 API contract.
    let subkey_utf8 = unsafe { decode_narrow_ptr(lp_sub_key) };
    let subkey_utf16: Vec<u16> = subkey_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: subkey_utf16 is a locally-owned Vec with a null terminator; it outlives
    // this call.  phk_result validity is enforced by reg_open_key_ex_w itself.
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

// Wine ref: dlls/kernelbase/registry.c:606 — RegCreateKeyExA converts ANSI name
// and class via RtlAnsiStringToUnicodeString then calls RegCreateKeyExW. Returns
// ERROR_BADKEY (not ERROR_INVALID_HANDLE) when retkey is null, same as W variant.
/// RegCreateKeyExA: open an existing key or create it if it doesn't exist (ANSI version).
///
/// Converts the ANSI subkey name to UTF-16 and calls RegCreateKeyExW.
///
/// # Safety
/// `lp_sub_key` and `lp_class` (if non-null) must be valid UTF-8 strings.
/// `phk_result` must be a valid writable pointer.
// Wine ref: dlls/kernelbase/registry.c:606 — RtlAnsiStringToUnicodeString for name+class then create_key; ERROR_BADKEY for NULL retkey (same as W variant)
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
    // SAFETY: RegCreateKeyExA: lp_sub_key is optional (null means the key itself);
    // decode_narrow_ptr handles null.  When non-null, callers must supply a valid
    // null-terminated ANSI string per the Win32 API contract.
    let subkey_utf8 = unsafe { decode_narrow_ptr(lp_sub_key) };
    let subkey_utf16: Vec<u16> = subkey_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Convert ANSI class to UTF-16 (if provided)
    let class_utf16 = if lp_class.is_null() {
        vec![]
    } else {
        // SAFETY: lp_class is optional per MSDN; here it is non-null.  Callers must supply
        // a valid null-terminated ANSI string when providing a class name.
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

// Wine ref: dlls/kernelbase/registry.c — RegQueryValueExA converts ANSI name to
// Unicode, calls NtQueryValueKey, then converts REG_SZ/REG_EXPAND_SZ data back to
// ANSI via RtlUnicodeToMultiByteN; *lpcbData reflects ANSI byte count on return.
/// RegQueryValueExA: read a registry value (ANSI version).
///
/// Converts the ANSI value name to UTF-16 and calls RegQueryValueExW.
/// For string data, converts the result back from UTF-16 to UTF-8.
///
/// # Safety
/// All pointer arguments must be valid per their Windows API contracts.
// Wine ref: dlls/kernelbase/registry.c:1730 — fetches string data even when not requested to compute ANSI length; Win9x sets *type=REG_NONE; *lpcbData reflects ANSI byte count on return
pub unsafe extern "win64" fn reg_query_value_ex_a(
    h_key: usize,
    lp_value_name: *const u8,
    lp_reserved: *mut u32,
    lp_type: *mut u32,
    lp_data: *mut u8,
    lpcb_data: *mut u32,
) -> i32 {
    // Convert ANSI value name to UTF-16
    // SAFETY: RegQueryValueExA: lp_value_name is optional (null means the default value);
    // decode_narrow_ptr handles null.  When non-null, callers must supply a valid
    // null-terminated ANSI string per the Win32 API contract.
    let value_name_utf8 = unsafe { decode_narrow_ptr(lp_value_name) };
    let value_name_utf16: Vec<u16> = value_name_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // First call to get the data size and type
    let mut data_type = 0u32;
    let mut data_size = 0u32;
    // SAFETY: value_name_utf16 is a locally-owned Vec with a null terminator appended
    // above; it outlives this call.  lp_reserved is passed through unchanged (its validity
    // is checked inside reg_query_value_ex_w).  &mut data_type and &mut data_size are
    // stack-allocated — always valid.
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
        // SAFETY: lp_type is optional per MSDN; written only after confirming non-null.
        // The Win32 API contract requires that when non-null it points to a valid DWORD*.
        unsafe { *lp_type = data_type };
    }

    // Size query
    if lp_data.is_null() {
        if !lpcb_data.is_null() {
            // For string types, convert UTF-16 size to UTF-8 size
            if data_type == REG_SZ || data_type == REG_EXPAND_SZ {
                // Estimate UTF-8 size (UTF-16 bytes / 2 * ~1.5 for worst case)
                let utf16_chars = data_size / 2;
                // SAFETY: lpcb_data is optional per MSDN; written only after confirming
                // non-null.  The Win32 API contract requires that when non-null it points
                // to a valid DWORD*.
                unsafe { *lpcb_data = utf16_chars * 3 }; // conservative estimate
            } else {
                // SAFETY: same as above.
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
        // SAFETY: utf16_buffer is a Rust Vec<u8> of length data_size bytes, allocated
        // and filled by the reg_query_value_ex_w call above.  Reinterpreting it as u16
        // values is valid: data_size is always an even number of bytes for string types
        // (UTF-16 is 2 bytes per code unit), and the pointer is 1-byte aligned which is
        // sufficient for a *const u16 read via from_raw_parts.  The slice does not outlive
        // utf16_buffer.
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
        // SAFETY: lp_data is non-null (checked before this code path) and buffer_size >=
        // required_size (checked just above).  The Win32 API contract requires callers to
        // supply a buffer of at least *lpcb_data bytes.  utf8_bytes is a Rust-owned slice —
        // no aliasing with lp_data (caller-owned memory).
        // The null terminator byte at lp_data.add(utf8_bytes.len()) is within the declared
        // buffer because buffer_size >= required_size = utf8_bytes.len() + 1.
        unsafe {
            std::ptr::copy_nonoverlapping(utf8_bytes.as_ptr(), lp_data, utf8_bytes.len());
            *lp_data.add(utf8_bytes.len()) = 0; // null terminator
        }
    } else {
        // Non-string data - copy as-is
        if !lpcb_data.is_null() {
            // SAFETY: lpcb_data is optional per MSDN; written only after confirming non-null.
            unsafe { *lpcb_data = data_size };
        }

        let buffer_size = if lpcb_data.is_null() {
            0u32
        } else {
            // SAFETY: lpcb_data is non-null here; just updated above.
            unsafe { *lpcb_data }
        };

        if buffer_size < data_size {
            return ERROR_MORE_DATA;
        }

        // SAFETY: lp_data is non-null (checked before this code path) and buffer_size >=
        // data_size (checked just above).  utf16_buffer is a Rust-owned Vec — no aliasing.
        unsafe {
            std::ptr::copy_nonoverlapping(utf16_buffer.as_ptr(), lp_data, data_size as usize);
        }
    }

    ERROR_SUCCESS
}

// Wine ref: dlls/kernelbase/registry.c — RegSetValueExA converts ANSI name via
// RtlAnsiStringToUnicodeString; for REG_SZ/REG_EXPAND_SZ converts ANSI data to
// UTF-16 via RtlAnsiStringToUnicodeString, appending null terminator if absent.
/// RegSetValueExA: write a registry value (ANSI version).
///
/// Converts the ANSI value name to UTF-16 and calls RegSetValueExW.
/// For string data, converts the ANSI data to UTF-16.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-8 string (or null for
/// the default value). `lp_data` must be valid for `cb_data` bytes.
// Wine ref: dlls/kernelbase/registry.c:1241 — REG_SZ/REG_EXPAND_SZ data converted from ANSI to UTF-16 via RtlMultiByteToUnicodeN; appends null if absent (NT behavior)
pub unsafe extern "win64" fn reg_set_value_ex_a(
    h_key: usize,
    lp_value_name: *const u8,
    reserved: u32,
    dw_type: u32,
    lp_data: *const u8,
    cb_data: u32,
) -> i32 {
    // Convert ANSI value name to UTF-16
    // SAFETY: RegSetValueExA: lp_value_name is optional (null means the default value);
    // decode_narrow_ptr handles null.  When non-null, callers must supply a valid
    // null-terminated ANSI string per the Win32 API contract.
    let value_name_utf8 = unsafe { decode_narrow_ptr(lp_value_name) };
    let value_name_utf16: Vec<u16> = value_name_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Convert data if it's a string type
    let (converted_data, converted_size) =
        if (dw_type == REG_SZ || dw_type == REG_EXPAND_SZ) && !lp_data.is_null() {
            // Convert ANSI string to UTF-16
            // SAFETY: lp_data is non-null (checked by the if-guard) and cb_data is the
            // caller-declared byte length.  The Win32 API contract requires callers to supply
            // a valid buffer of at least cb_data bytes.
            let data_slice = unsafe { std::slice::from_raw_parts(lp_data, cb_data as usize) };
            let data_string = String::from_utf8_lossy(data_slice);
            let utf16_data: Vec<u16> = data_string
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: utf16_data is a Rust-owned Vec<u16>; reinterpreting its bytes as u8
            // for the size calculation is valid because u16 is always 2 bytes and the Vec
            // is suitably aligned.  The resulting slice does not outlive utf16_data, which
            // is kept alive for the duration of this block.
            let utf16_bytes = unsafe {
                std::slice::from_raw_parts(utf16_data.as_ptr() as *const u8, utf16_data.len() * 2)
            };
            (utf16_bytes.as_ptr(), (utf16_data.len() * 2) as u32)
        } else {
            // Non-string data - pass through
            (lp_data, cb_data)
        };

    // SAFETY: value_name_utf16 is a locally-owned Vec with a null terminator; it outlives
    // this call.  converted_data either points into the local utf16_bytes slice (kept alive
    // by the enclosing block) or is the original caller-provided lp_data pointer — both are
    // valid for converted_size bytes per the analysis above.
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

// Wine ref: dlls/kernelbase/registry.c — RegDeleteValueA converts ANSI name via
// RtlAnsiStringToUnicodeString then calls NtDeleteValueKey. Null name deletes
// the default value, same as the W variant.
/// RegDeleteValueA: delete a named value from an open key (ANSI version).
///
/// Converts the ANSI value name to UTF-16 and calls RegDeleteValueW.
///
/// # Safety
/// `lp_value_name` must be a valid null-terminated UTF-8 string or null.
// Wine ref: dlls/kernelbase/registry.c — RegDeleteValueA converts ANSI via RtlAnsiStringToUnicodeString then NtDeleteValueKey; null name deletes default value
pub unsafe extern "win64" fn reg_delete_value_a(h_key: usize, lp_value_name: *const u8) -> i32 {
    // Convert ANSI value name to UTF-16
    // SAFETY: RegDeleteValueA: lp_value_name is optional (null deletes the default value);
    // decode_narrow_ptr handles null.  When non-null, callers must supply a valid
    // null-terminated ANSI string per the Win32 API contract.
    let value_name_utf8 = unsafe { decode_narrow_ptr(lp_value_name) };
    let value_name_utf16: Vec<u16> = value_name_utf8
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: value_name_utf16 is a locally-owned Vec with a null terminator appended
    // above; it outlives the call to reg_delete_value_w which does not store the pointer.
    unsafe { reg_delete_value_w(h_key, value_name_utf16.as_ptr()) }
}

// ── LSA stubs ────────────────────────────────────────────────────────────────

// Wine ref: dlls/advapi32/lsa.c — LsaOpenPolicy calls advapi32!LsaOpenPolicy which
// forwards to sechost; Wine talks to the wine server via an RPC handle. Returns
// STATUS_ACCESS_DENIED when the server rejects the access request. Weave has no
// security server, so we return STATUS_ACCESS_DENIED unconditionally.
/// LsaOpenPolicy — open a handle to the LSA Policy object. Returns an error.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/advapi32/lsa.c — forwards to sechost via RPC; Wine talks to wine server; STATUS_ACCESS_DENIED when server rejects access request
pub unsafe extern "win64" fn lsa_open_policy(
    _system_name: *const u8,
    _object_attributes: *const u8,
    _desired_access: u32,
    policy_handle: *mut usize,
) -> i32 {
    if !policy_handle.is_null() {
        // SAFETY: policy_handle is optional; written only after confirming non-null.
        // The Win32 API contract requires callers to provide a valid, writable LSA_HANDLE*
        // (a pointer-sized output parameter) when they need the handle value.
        unsafe { *policy_handle = 0 };
    }
    0xC000_0022u32 as i32 // STATUS_ACCESS_DENIED
}

// Wine ref: dlls/advapi32/lsa.c — LsaClose calls NtClose on the LSA policy handle.
// Returns STATUS_SUCCESS (0) even for invalid handles in some Wine paths; our
// stub has no real handle to close so we return STATUS_SUCCESS unconditionally.
/// LsaClose — close a LSA policy handle. Returns STATUS_SUCCESS.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/advapi32/lsa.c — NtClose on LSA policy handle; STATUS_SUCCESS even for invalid handles in some Wine code paths
pub unsafe extern "win64" fn lsa_close(_object_handle: usize) -> i32 {
    0 // STATUS_SUCCESS
}

// Wine ref: dlls/advapi32/lsa.c — LsaAddAccountRights calls LsaOpenAccount to get
// an account handle then LsaAddPrivilegesToAccount for each right string. Requires
// a valid policy handle. Our stub returns STATUS_SUCCESS (no-op) since we have no
// real account database.
/// LsaAddAccountRights — add privileges to an account. Returns STATUS_SUCCESS.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/advapi32/lsa.c — LsaOpenAccount then LsaAddPrivilegesToAccount for each right string; requires valid policy handle
pub unsafe extern "win64" fn lsa_add_account_rights(
    _policy_handle: usize,
    _account_sid: *const u8,
    _user_rights: *const u8,
    _count_of_rights: u32,
) -> i32 {
    0 // STATUS_SUCCESS
}

// Wine ref: dlls/advapi32/security.c:1104 — LookupAccountNameW calls
// lookup_user_account_name then lookup_computer_account_name then
// lookup_local_wellknown_name; falls back to LsaLookupNames2 for domain
// accounts. Each helper fills Sid + cbSid + domain + SID_NAME_USE.
// Weave returns FALSE (no account database).
/// LookupAccountNameW — look up an account name and return its SID.
///
/// Returns FALSE — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/advapi32/security.c:1104 — lookup_user_account_name then lookup_computer_account_name then lookup_local_wellknown_name; LsaLookupNames2 fallback for domain accounts
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

// Wine ref: dlls/sechost/security.c — GetUserNameW calls GetUserNameExW with
// NameSamCompatible, falls back to GetEnvironmentVariableW("USERNAME"); on
// failure sets ERROR_NOT_LOGGED_ON and returns FALSE. Returns char count
// including null terminator in *lpcbBuffer on success.
/// GetUserNameW — return the current user's name (Wide).
///
/// Writes "weave" into the caller's buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `*lpcb_buffer` characters.
/// `lpcb_buffer` must be writable.
// Wine ref: dlls/sechost/security.c — GetUserNameExW(NameSamCompatible) then GetEnvironmentVariableW("USERNAME") fallback; sets ERROR_NOT_LOGGED_ON on failure
pub unsafe extern "win64" fn get_user_name_w(lp_buffer: *mut u16, lpcb_buffer: *mut u32) -> i32 {
    let user: Vec<u16> = "weave\0".encode_utf16().collect();
    let needed = user.len() as u32;
    if lpcb_buffer.is_null() {
        return 0;
    }
    // SAFETY: lpcb_buffer is non-null (checked above).  GetUserNameW requires callers to
    // provide a valid DWORD* containing the buffer size in characters (UTF-16 code units);
    // we read it then update it with the required size (including the null terminator).
    let available = unsafe { *lpcb_buffer };
    unsafe { *lpcb_buffer = needed };
    if available < needed {
        return 0;
    }
    if !lp_buffer.is_null() {
        // SAFETY: lp_buffer is non-null and available >= needed u16 elements, so the buffer
        // is large enough for the entire "weave\0" string.  user is a locally-allocated Vec
        // — no aliasing with lp_buffer (caller-owned memory).
        unsafe { std::ptr::copy_nonoverlapping(user.as_ptr(), lp_buffer, user.len()) };
    }
    1 // TRUE
}

// Wine ref: dlls/kernelbase/registry.c — RegDeleteKeyExW is a wrapper around
// RegDeleteKeyW that accepts a samDesired view flag (KEY_WOW64_32KEY or
// KEY_WOW64_64KEY) for registry reflection; Wine passes it to NtDeleteKey.
// We ignore samDesired and delegate to our RegDeleteKeyW.
/// RegDeleteKeyExW — delete a registry key with a 32/64-bit flag (Wide).
///
/// Delegates to RegDeleteKeyW (ignores sam_desired).
///
/// # Safety
/// `lp_sub_key` must be a valid null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/registry.c — wrapper around RegDeleteKeyW; samDesired KEY_WOW64_32KEY/KEY_WOW64_64KEY selects registry view for reflection; passed to NtDeleteKey
pub unsafe extern "win64" fn reg_delete_key_ex_w(
    h_key: usize,
    lp_sub_key: *const u16,
    _sam_desired: u32,
    _reserved: u32,
) -> i32 {
    // SAFETY: lp_sub_key validity is the same as RegDeleteKeyW (null-terminated UTF-16
    // string, or null handled defensively by decode_wide_ptr inside reg_delete_key_w).
    // The sam_desired and reserved parameters are ignored — they are not dereferenced.
    unsafe { reg_delete_key_w(h_key, lp_sub_key) }
}

// Wine ref: dlls/advapi32/security.c:166 — GetFileSecurityW calls get_security_file
// to open the file with READ_CONTROL access, then GetKernelObjectSecurity to fill
// the security descriptor. Requires a real file handle and kernel SD support.
// Weave returns FALSE — no file security descriptor support.
/// GetFileSecurityW — retrieve security information for a file (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/advapi32/security.c:166 — get_security_file with READ_CONTROL then GetKernelObjectSecurity fills SD; requires real file handle + kernel SD support
pub unsafe extern "win64" fn get_file_security_w(
    _lp_file_name: *const u16,
    _requested_information: u32,
    _p_security_descriptor: *mut u8,
    _n_length: u32,
    _lp_needed_length: *mut u32,
) -> i32 {
    0 // FALSE
}

// Wine ref: dlls/advapi32/security.c — SetFileSecurityW calls get_security_file
// with WRITE_DAC|WRITE_OWNER access then SetKernelObjectSecurity. Requires a real
// kernel object. Weave returns FALSE — no file security support.
/// SetFileSecurityW — set security information for a file (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/advapi32/security.c — get_security_file with WRITE_DAC|WRITE_OWNER then SetKernelObjectSecurity; Weave returns FALSE (no kernel security object support)
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
        "CryptAcquireContextA" => Some(
            crypt_acquire_context_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CryptAcquireContextW" => Some(
            crypt_acquire_context_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CryptReleaseContext" => {
            Some(crypt_release_context as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CryptGenRandom" => {
            Some(crypt_gen_random as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // ── DXVK d3d9.dll gap stubs ────────────────────────────────────────
        "AllocateLocallyUniqueId" => Some(
            allocate_locally_unique_id as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "RegNotifyChangeKeyValue" => Some(
            reg_notify_change_key_value as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // ── wget Crypt* gap stubs ──────────────────────────────────────────────
        "CryptCreateHash" => Some(
            crypt_create_hash as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "CryptDecrypt" => Some(
            crypt_decrypt as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "CryptDestroyHash" => {
            Some(crypt_destroy_hash as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CryptDestroyKey" => {
            Some(crypt_destroy_key as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CryptEnumProvidersW" => Some(
            crypt_enum_providers_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CryptExportKey" => Some(
            crypt_export_key as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CryptGetProvParam" => Some(
            crypt_get_prov_param as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CryptGetUserKey" => {
            Some(crypt_get_user_key as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CryptSetHashParam" => Some(
            crypt_set_hash_param as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "CryptSignHashW" => Some(
            crypt_sign_hash_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // ── SumatraPDF Crypt/security gap stubs ───────────────────────────────
        "CryptHashData" => {
            Some(crypt_hash_data as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "CryptGetHashParam" => Some(
            crypt_get_hash_param as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegSetKeySecurity" => Some(
            reg_set_key_security as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CheckTokenMembership" => Some(
            check_token_membership as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "RegisterEventSourceW" => Some(
            register_event_source_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "DeregisterEventSource" => {
            Some(deregister_event_source as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ReportEventW" => Some(
            report_event_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Non-Ex registry wrappers — Phase A stubs for IrfanView (E3-M3)
        "RegCreateKeyW" => {
            Some(reg_create_key_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "RegSetValueW" => Some(
            reg_set_value_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "RegGetValueW" => Some(
            reg_get_value_w as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // ── Q-Dir Phase A stubs ───────────────────────────────────────────
        "RegOpenKeyW" => {
            Some(reg_open_key_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "GetTokenInformation" => Some(
            get_token_information as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // ── IrfanView IsTextUnicode ─────────────────────────────────────────
        "IsTextUnicode" => {
            Some(is_text_unicode as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // ── Security descriptor stubs ──────────────────────────────────────
        "ConvertStringSecurityDescriptorToSecurityDescriptorW" => Some(
            convert_string_sd_to_sd_w as unsafe extern "win64" fn(_, _, _, _) -> i32 as *const ()
                as usize,
        ),
        "BuildSecurityDescriptorW" => Some(
            build_security_descriptor_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> u32
                as *const () as usize,
        ),
        "BuildExplicitAccessWithNameW" => Some(
            build_explicit_access_with_name_w as unsafe extern "win64" fn(_, _, _, _, _) -> u32
                as *const () as usize,
        ),
        // ── Phase A stubs ─────────────────────────────────────────────────
        "RegEnumKeyW" => Some(
            reg_enum_key_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        _ => None,
    }
}

// ── Crypto stubs ──────────────────────────────────────────────────────────────

/// Fill `buf` with `len` cryptographically random bytes via `getrandom(2)`.
///
/// Returns `true` on success. Uses `GRND_DEFAULT` (flags=0): blocks until
/// the urandom pool is seeded, then returns non-blocking. Atomic for ≤256 bytes.
///
/// # Future seccomp note
/// `getrandom(2)` (syscall 318) must appear in the seccomp allowlist when
/// Phase 4 BPF filtering is implemented. Both RtlGenRandom and CryptGenRandom
/// funnel through this helper — one allowlist entry covers both.
///
/// # Safety
/// `buf` must be a writable buffer of at least `len` bytes.
unsafe fn fill_random(buf: *mut u8, len: usize) -> bool {
    if buf.is_null() || len == 0 {
        return false;
    }
    // SAFETY: buf is non-null (checked above); caller guarantees writable buf of `len` bytes.
    // getrandom(2) writes exactly `len` bytes on success for len ≤ 256 (atomic, no short-reads).
    let ret = unsafe { libc::getrandom(buf as *mut libc::c_void, len, 0) };
    ret >= 0 && ret as usize == len
}

/// SystemFunction036 — RtlGenRandom; fills a buffer with cryptographically random bytes.
///
/// Wine ref: dlls/advapi32/crypt.c — RtlGenRandom delegates to
/// NtQuerySystemInformation(SystemInterruptInformation) on NT; on Linux Wine
/// uses /dev/urandom; Weave uses getrandom(2) (modern equivalent, atomic for
/// ≤256 bytes, avoids fd management inside the sandbox).
///
/// # Safety
/// `random_buffer` must be a writable buffer of at least `random_buffer_length` bytes.
pub unsafe extern "win64" fn system_function_036(
    random_buffer: *mut u8,
    random_buffer_length: u32,
) -> u8 {
    unsafe { fill_random(random_buffer, random_buffer_length as usize) as u8 }
}

/// CryptAcquireContextA — open a cryptographic service provider context (ANSI).
///
/// # Safety
/// `ph_prov` must be a writable pointer to a `ULONG_PTR`-sized slot.
// Wine ref: dlls/advapi32/crypt.c — CryptAcquireContextA calls CryptAcquireContextW internally;
// writes a non-zero HCRYPTPROV to *phProv and returns TRUE. Flags like CRYPT_VERIFYCONTEXT are
// accepted without validation; error codes (e.g. NTE_BAD_PROV_TYPE) not needed for entropy path.
pub unsafe extern "win64" fn crypt_acquire_context_a(
    ph_prov: *mut usize,
    _psz_container: *const u8,
    _psz_provider: *const u8,
    _dw_prov_type: u32,
    _dw_flags: u32,
) -> i32 {
    if ph_prov.is_null() {
        return 0; // FALSE
    }
    // SAFETY: ph_prov is non-null (checked above); caller provides a writable HCRYPTPROV slot.
    unsafe { *ph_prov = 1 }; // non-zero fake provider handle
    1 // TRUE
}

/// CryptAcquireContextW — open a cryptographic service provider context (Unicode).
///
/// # Safety
/// `ph_prov` must be a writable pointer to a `ULONG_PTR`-sized slot.
// Wine ref: dlls/advapi32/crypt.c — CryptAcquireContextW; same semantics as A variant;
// returns TRUE with a fake non-zero HCRYPTPROV handle.
pub unsafe extern "win64" fn crypt_acquire_context_w(
    ph_prov: *mut usize,
    _psz_container: *const u16,
    _psz_provider: *const u16,
    _dw_prov_type: u32,
    _dw_flags: u32,
) -> i32 {
    if ph_prov.is_null() {
        return 0; // FALSE
    }
    // SAFETY: ph_prov is non-null (checked above); caller provides a writable HCRYPTPROV slot.
    unsafe { *ph_prov = 1 }; // non-zero fake provider handle
    1 // TRUE
}

/// CryptReleaseContext — release a cryptographic service provider context.
///
/// # Safety
/// No pointer dereferences needed; `h_prov` is treated as an opaque handle.
// Wine ref: dlls/advapi32/crypt.c — CryptReleaseContext; frees provider state and returns TRUE.
// Weave uses a fake handle so there is nothing to free.
pub unsafe extern "win64" fn crypt_release_context(_h_prov: usize, _dw_flags: u32) -> i32 {
    1 // TRUE
}

/// CryptGenRandom — fill a buffer with cryptographically random bytes.
///
/// Wine ref: dlls/advapi32/crypt.c — CryptGenRandom delegates to RtlGenRandom on NT;
/// Wine uses /dev/urandom; Weave uses getrandom(2) via fill_random (same helper as
/// SystemFunction036 / RtlGenRandom).
///
/// # Safety
/// `pb_buffer` must be a writable buffer of at least `dw_len` bytes.
pub unsafe extern "win64" fn crypt_gen_random(
    _h_prov: usize,
    dw_len: u32,
    pb_buffer: *mut u8,
) -> i32 {
    unsafe { fill_random(pb_buffer, dw_len as usize) as i32 }
}

// ── Security / SID stubs ──────────────────────────────────────────────────────

// Wine ref: dlls/sechost/security.c — GetUserNameA calls GetUserNameW then converts
// result via WideCharToMultiByte. Sets *lpcbBuffer to byte count including null on
// success; sets ERROR_INSUFFICIENT_BUFFER and returns FALSE if buffer too small.
/// GetUserNameA: return the login name of the current user.
///
/// # Safety
/// `lp_buffer` must be writable for `*lpcb_buffer` bytes; `lpcb_buffer` writable.
// Wine ref: dlls/sechost/security.c — GetUserNameA calls GetUserNameW then WideCharToMultiByte; sets *lpcbBuffer to byte count including null on success
pub unsafe extern "win64" fn get_user_name_a(lp_buffer: *mut u8, lpcb_buffer: *mut u32) -> i32 {
    let user = b"weave\0";
    let needed = user.len() as u32;
    if lpcb_buffer.is_null() {
        return 0;
    }
    // SAFETY: lpcb_buffer is non-null (checked above).  GetUserNameA requires callers to
    // provide a valid DWORD* containing the buffer size in bytes; we read it then update it
    // with the required size (including the null terminator).
    let avail = unsafe { *lpcb_buffer };
    unsafe { *lpcb_buffer = needed };
    if avail < needed || lp_buffer.is_null() {
        return 0;
    }
    // SAFETY: lp_buffer is non-null (checked above) and avail >= needed bytes, so the
    // buffer is large enough for the entire "weave\0" string (6 bytes).  user is a
    // static byte slice — no aliasing with lp_buffer (caller-owned memory).
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

// Wine ref: dlls/ntdll/sec.c — RtlAllocateAndInitializeSid allocates
// sizeof(SID) + (nSubAuthorityCount-1)*4 bytes via RtlAllocateHeap, sets
// Revision=1, SubAuthorityCount=n, IdentifierAuthority from pIdentifierAuthority,
// and fills SubAuthority[0..n-1]. Returns FALSE if nSubAuthorityCount > 8.
/// AllocateAndInitializeSid: create a SID with up to 8 sub-authorities.
///
/// # Safety
/// `pidentifier_authority` must be a valid 6-byte authority value.
/// `new_sid` must be a writable `*mut PSID`.
#[allow(clippy::too_many_arguments)]
// Wine ref: dlls/ntdll/sec.c — RtlAllocateAndInitializeSid allocates sizeof(SID)+(n-1)*4 bytes; sets Revision=1, SubAuthorityCount=n, copies IdentifierAuthority; FALSE if n>8
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
            // SAFETY: AllocateAndInitializeSid: pidentifier_authority is documented as a
            // required pointer to a SID_IDENTIFIER_AUTHORITY structure which is exactly 6
            // bytes.  The Win32 API contract requires callers to provide a valid, readable
            // 6-byte value when non-null; we copy it by value via an array cast.
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
    // SAFETY: new_sid is non-null (checked at function entry).  The Win32 API contract
    // requires callers to provide a valid PSID* (pointer to a pointer) that receives the
    // allocated SID.  Box::into_raw transfers ownership to the caller; they are responsible
    // for releasing it via FreeSid (which calls Box::from_raw).
    unsafe { *new_sid = Box::into_raw(sid) };
    1
}

// Wine ref: dlls/ntdll/sec.c — RtlCopySid checks nDestinationSidLength >=
// RtlLengthSid(pSourceSid), then memcpy. Returns STATUS_INVALID_SID (mapped to
// FALSE) if destination too small. Weave copies nDestinationSidLength bytes.
/// CopySid: copy a SID to a buffer. Returns TRUE.
///
/// # Safety
/// Both pointers must be valid if non-null.
// Wine ref: dlls/ntdll/sec.c — RtlCopySid checks nDestinationSidLength >= RtlLengthSid(pSourceSid) then memcpy; STATUS_INVALID_SID if destination too small
pub unsafe extern "win64" fn copy_sid(
    n_destination_sid_length: u32,
    p_destination_sid: *mut u8,
    p_source_sid: *const u8,
) -> i32 {
    if p_destination_sid.is_null() || p_source_sid.is_null() {
        return 0;
    }
    let copy = n_destination_sid_length as usize;
    // SAFETY: Both pointers are non-null (checked above).  The Win32 API contract for
    // CopySid requires callers to supply a destination buffer of at least
    // n_destination_sid_length bytes (documented to be >= GetLengthSid(p_source_sid)).
    // p_source_sid is a FakeSid allocated by AllocateAndInitializeSid — valid for at
    // least sizeof(FakeSid) bytes which equals n_destination_sid_length per MSDN contract.
    unsafe { std::ptr::copy_nonoverlapping(p_source_sid, p_destination_sid, copy) };
    1
}

// Wine ref: dlls/ntdll/sec.c — RtlEqualSid compares SubAuthorityCount and
// IdentifierAuthority, then SubAuthority[0..n-1] via memcmp. Returns FALSE if
// counts differ. Weave returns FALSE conservatively (we have no real SID store).
/// EqualSid: compare two SIDs. Returns FALSE (conservative — we can't know).
///
/// # Safety
/// Both pointers must be valid FakeSid pointers.
// Wine ref: dlls/ntdll/sec.c — RtlEqualSid compares SubAuthorityCount + IdentifierAuthority + SubAuthority[0..n-1] via memcmp; FALSE if counts differ
pub unsafe extern "win64" fn equal_sid(_sid1: *const FakeSid, _sid2: *const FakeSid) -> i32 {
    0
}

// Wine ref: dlls/ntdll/sec.c — RtlLengthSid returns
// sizeof(SID) + (SubAuthorityCount - 1) * sizeof(DWORD) by reading the
// SubAuthorityCount field from the SID header. Weave returns sizeof(FakeSid).
/// GetLengthSid: return the length of a SID in bytes. Returns size of FakeSid.
pub extern "win64" fn get_length_sid(_p_sid: *const u8) -> u32 {
    std::mem::size_of::<FakeSid>() as u32
}

// Wine ref: dlls/ntdll/sec.c — RtlFreeSid calls RtlFreeHeap on the SID pointer
// and returns NULL. No-op for NULL input. Weave mirrors this via Box::from_raw.
/// FreeSid: free a SID allocated by AllocateAndInitializeSid. Returns NULL.
pub extern "win64" fn free_sid(p_sid: *mut FakeSid) -> *mut FakeSid {
    if !p_sid.is_null() {
        // SAFETY: p_sid is non-null and was originally allocated by AllocateAndInitializeSid
        // via Box::into_raw.  FreeSid is the documented counterpart that transfers ownership
        // back to Rust; Box::from_raw is the correct way to reclaim and drop it.  The caller
        // must not use p_sid after calling FreeSid (per Win32 API contract).
        unsafe { drop(Box::from_raw(p_sid)) };
    }
    std::ptr::null_mut()
}

// Wine ref: dlls/ntdll/sec.c — RtlCreateSecurityDescriptor zeros
// SECURITY_DESCRIPTOR_MIN_LENGTH (20) bytes then sets Revision=SECURITY_DESCRIPTOR_REVISION (1).
// Returns STATUS_UNKNOWN_REVISION if dwRevision != 1. Weave zeros 20 bytes (revision
// field is at offset 0 and will be 0, which callers don't check strictly).
/// InitializeSecurityDescriptor: zero-initialise a security descriptor. Returns TRUE.
///
/// # Safety
/// `p_security_descriptor` must be writable for at least 20 bytes.
// Wine ref: dlls/ntdll/sec.c — RtlCreateSecurityDescriptor zeros SECURITY_DESCRIPTOR_MIN_LENGTH(20) bytes then sets Revision=1; STATUS_UNKNOWN_REVISION if dwRevision!=1
pub unsafe extern "win64" fn initialize_security_descriptor(
    p_security_descriptor: *mut u8,
    _dw_revision: u32,
) -> i32 {
    if p_security_descriptor.is_null() {
        return 0;
    }
    // SAFETY: p_security_descriptor is non-null (checked above).  The Win32 API contract
    // for InitializeSecurityDescriptor requires callers to supply a buffer of at least
    // SECURITY_DESCRIPTOR_MIN_LENGTH bytes (20 on both 32-bit and 64-bit Windows).
    // We zero exactly those 20 bytes; writing u8 values imposes no alignment requirements.
    unsafe { std::ptr::write_bytes(p_security_descriptor, 0, 20) };
    1
}

// Wine ref: dlls/ntdll/sec.c — RtlSetDaclSecurityDescriptor checks
// pSecurityDescriptor->Revision == SECURITY_DESCRIPTOR_REVISION (1); sets
// SE_DACL_PRESENT in Control if bDaclPresent; stores pDacl and sets SE_DACL_DEFAULTED
// from bDaclDefaulted. Weave no-ops (TRUE) — callers only check the return value.
/// SetSecurityDescriptorDacl: set the DACL in a security descriptor. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not fully validated.
// Wine ref: dlls/ntdll/sec.c — RtlSetDaclSecurityDescriptor checks Revision==1; sets SE_DACL_PRESENT in Control if bDaclPresent; stores pDacl pointer; SE_DACL_DEFAULTED from bDaclDefaulted
pub unsafe extern "win64" fn set_security_descriptor_dacl(
    _p_security_descriptor: *mut u8,
    _b_dacl_present: i32,
    _p_dacl: *const u8,
    _b_dacl_defaulted: i32,
) -> i32 {
    1
}

// Wine ref: dlls/ntdll/sec.c — RtlSetOwnerSecurityDescriptor stores pOwner in the
// SECURITY_DESCRIPTOR and sets/clears SE_OWNER_DEFAULTED in Control based on
// bOwnerDefaulted. Returns STATUS_SUCCESS unconditionally if Revision is valid.
// Weave no-ops (TRUE) — callers only check the return value.
/// SetSecurityDescriptorOwner: set the owner SID. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not fully validated.
// Wine ref: dlls/ntdll/sec.c — RtlSetOwnerSecurityDescriptor stores pOwner; sets/clears SE_OWNER_DEFAULTED in Control; STATUS_SUCCESS if Revision valid
pub unsafe extern "win64" fn set_security_descriptor_owner(
    _p_security_descriptor: *mut u8,
    _p_owner: *const u8,
    _b_owner_defaulted: i32,
) -> i32 {
    1
}

// ── DXVK d3d9.dll gap stubs ───────────────────────────────────────────────────

/// AllocateLocallyUniqueId — fill a LUID with zeros; return FALSE.
///
/// # Safety
/// `luid`, if non-null, must point to a writable 8-byte aligned u64.
pub unsafe extern "win64" fn allocate_locally_unique_id(luid: *mut u64) -> i32 {
    if !luid.is_null() {
        // SAFETY: caller guarantees `luid` is a valid writable u64 pointer.
        unsafe {
            *luid = 0;
        }
    }
    0 // FALSE
}

/// RegNotifyChangeKeyValue — not supported; return ERROR_NOT_SUPPORTED.
pub unsafe extern "win64" fn reg_notify_change_key_value(
    _key: usize,
    _subtree: i32,
    _filter: u32,
    _event: usize,
    _async: i32,
) -> i32 {
    50 // ERROR_NOT_SUPPORTED
}

// ── wget Crypt* / event-log stubs (CAPI + cleanup gap-fill) ─────────────────

/// CryptCreateHash — create a hash object. Returns FALSE + NTE_FAIL.
///
/// # Safety
/// `ph_hash`, if non-null, receives 0 (no hash created).
// Wine ref: dlls/advapi32/crypt.c — CryptCreateHash calls provider CPCreateHash;
// FALSE + NTE_FAIL if provider invalid or ALG_ID unsupported.
pub unsafe extern "win64" fn crypt_create_hash(
    _h_prov: usize,
    _alg_id: u32,
    _h_key: usize,
    _dw_flags: u32,
    ph_hash: *mut usize,
) -> i32 {
    if !ph_hash.is_null() {
        unsafe { *ph_hash = 0 };
    }
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// CryptDecrypt — decrypt data with a key. Returns FALSE + NTE_FAIL.
// Wine ref: dlls/advapi32/crypt.c — CryptDecrypt calls provider CPDecrypt;
// FALSE + NTE_FAIL if key invalid.
pub unsafe extern "win64" fn crypt_decrypt(
    _h_key: usize,
    _h_hash: usize,
    _final_: i32,
    _dw_flags: u32,
    _pb_data: *mut u8,
    _pdw_data_len: *mut u32,
) -> i32 {
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// CryptDestroyHash — release a hash object. Returns TRUE (no-op; no state to free).
// Wine ref: dlls/advapi32/crypt.c — CryptDestroyHash calls provider CPDestroyHash
// then frees internal hash object; TRUE on success.
pub unsafe extern "win64" fn crypt_destroy_hash(_h_hash: usize) -> i32 {
    1 // TRUE
}

/// CryptHashData — hash a block of data into an existing hash object. Returns FALSE + NTE_FAIL.
///
/// # Safety
/// All pointer arguments are ignored.
// Wine ref: dlls/advapi32/crypt.h PROVFUNCS::pCPHashData — CryptHashData dispatches to
// provider CPHashData(hProv, hHash, pbData, dwDataLen, dwFlags); FALSE + NTE_FAIL with no CSP.
pub unsafe extern "win64" fn crypt_hash_data(
    _h_hash: usize,
    _pb_data: *const u8,
    _dw_data_len: u32,
    _dw_flags: u32,
) -> i32 {
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// CryptGetHashParam — retrieve a hash object parameter. Returns FALSE + NTE_FAIL.
///
/// # Safety
/// All pointer arguments are ignored.
// Wine ref: dlls/advapi32/crypt.h PROVFUNCS::pCPGetHashParam — CryptGetHashParam dispatches to
// provider CPGetHashParam(hProv, hHash, dwParam, pbData, pdwDataLen, dwFlags); FALSE + NTE_FAIL with no CSP.
pub unsafe extern "win64" fn crypt_get_hash_param(
    _h_hash: usize,
    _dw_param: u32,
    _pb_data: *mut u8,
    _pdw_data_len: *mut u32,
    _dw_flags: u32,
) -> i32 {
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// RegSetKeySecurity — set security descriptor on a registry key. Returns ERROR_SUCCESS (no-op).
// Wine ref: dlls/kernelbase/registry.c — RegSetKeySecurity calls NtSetSecurityObject;
// stub returns ERROR_SUCCESS; no security enforcement in Weave.
pub unsafe extern "win64" fn reg_set_key_security(
    _h_key: usize,
    _security_info: u32,
    _p_security_descriptor: *const u8,
) -> u32 {
    0 // ERROR_SUCCESS
}

/// CheckTokenMembership — check whether a SID is enabled in a token. Returns TRUE; writes FALSE to *is_member.
///
/// # Safety
/// `is_member` must be a valid pointer to an i32 (Windows BOOL = 32-bit) if non-null.
// Wine ref: dlls/advapi32/tests/security.c::test_CheckTokenMembership — is_member is BOOL*
// (i32*); function returns TRUE on success and writes membership result; stub returns non-admin.
pub unsafe extern "win64" fn check_token_membership(
    _token_handle: usize,
    _sid_to_check: *const u8,
    is_member: *mut i32,
) -> i32 {
    if !is_member.is_null() {
        unsafe { *is_member = 0 }; // not a member
    }
    1 // TRUE (call succeeded; membership is FALSE)
}

/// CryptDestroyKey — release a key object. Returns TRUE (no-op; no state to free).
// Wine ref: dlls/advapi32/crypt.c — CryptDestroyKey calls provider CPDestroyKey
// then frees internal key object; TRUE on success.
pub unsafe extern "win64" fn crypt_destroy_key(_h_key: usize) -> i32 {
    1 // TRUE
}

/// CryptEnumProvidersW — enumerate installed CSPs. Returns FALSE + ERROR_NO_MORE_ITEMS.
///
/// # Safety
/// Pointer arguments are ignored.
// Wine ref: dlls/advapi32/crypt.c — CryptEnumProvidersW reads
// HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider registry; FALSE +
// ERROR_NO_MORE_ITEMS when dwIndex exceeds provider count. Weave has no CAPI providers.
pub unsafe extern "win64" fn crypt_enum_providers_w(
    _dw_index: u32,
    _pdw_reserved: *mut u32,
    _dw_flags: u32,
    _pdw_prov_type: *mut u32,
    _sz_prov_name: *mut u16,
    _pcb_prov_name: *mut u32,
) -> i32 {
    weave_common::set_last_error(259_u32); // ERROR_NO_MORE_ITEMS
    0 // FALSE
}

/// CryptExportKey — export a key from a provider. Returns FALSE + NTE_FAIL.
// Wine ref: dlls/advapi32/crypt.c — CryptExportKey calls provider CPExportKey;
// FALSE + NTE_FAIL if provider/key invalid.
pub unsafe extern "win64" fn crypt_export_key(
    _h_key: usize,
    _h_exp_key: usize,
    _dw_blob_type: u32,
    _dw_flags: u32,
    _pb_data: *mut u8,
    _pdw_data_len: *mut u32,
) -> i32 {
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// CryptGetProvParam — query a provider parameter. Returns FALSE + NTE_FAIL.
// Wine ref: dlls/advapi32/crypt.c — CryptGetProvParam calls provider CPGetProvParam;
// FALSE + NTE_FAIL if provider invalid.
pub unsafe extern "win64" fn crypt_get_prov_param(
    _h_prov: usize,
    _dw_param: u32,
    _pb_data: *mut u8,
    _pdw_data_len: *mut u32,
    _dw_flags: u32,
) -> i32 {
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// CryptGetUserKey — retrieve the user's key pair handle. Returns FALSE + NTE_FAIL.
// Wine ref: dlls/advapi32/crypt.c — CryptGetUserKey calls provider CPGetUserKey;
// FALSE + NTE_NO_KEY if no key pair exists.
pub unsafe extern "win64" fn crypt_get_user_key(
    _h_prov: usize,
    _dw_key_spec: u32,
    ph_user_key: *mut usize,
) -> i32 {
    if !ph_user_key.is_null() {
        unsafe { *ph_user_key = 0 };
    }
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// CryptSetHashParam — set a hash object parameter. Returns FALSE + NTE_FAIL.
// Wine ref: dlls/advapi32/crypt.c — CryptSetHashParam calls provider CPSetHashParam;
// FALSE + NTE_FAIL if hash invalid.
pub unsafe extern "win64" fn crypt_set_hash_param(
    _h_hash: usize,
    _dw_param: u32,
    _pb_data: *const u8,
    _dw_flags: u32,
) -> i32 {
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// CryptSignHashW — sign a hash. Returns FALSE + NTE_FAIL.
// Wine ref: dlls/advapi32/crypt.c — CryptSignHashW calls provider CPSignHash;
// FALSE + NTE_FAIL if hash/key invalid.
pub unsafe extern "win64" fn crypt_sign_hash_w(
    _h_hash: usize,
    _dw_key_spec: u32,
    _sz_description: *const u16,
    _dw_flags: u32,
    _pb_signature: *mut u8,
    _pdw_sig_len: *mut u32,
) -> i32 {
    weave_common::set_last_error(0x8009_0020_u32); // NTE_FAIL
    0 // FALSE
}

/// RegisterEventSourceW — open a handle to the event log. Returns NULL + ERROR_CALL_NOT_IMPLEMENTED.
// Wine ref: dlls/advapi32/eventlog.c — RegisterEventSourceW opens a handle to the
// Application event log; Weave has no event log subsystem.
pub unsafe extern "win64" fn register_event_source_w(
    _lp_uncserver_name: *const u16,
    _lp_source_name: *const u16,
) -> usize {
    weave_common::set_last_error(120_u32); // ERROR_CALL_NOT_IMPLEMENTED
    0 // NULL handle
}

/// DeregisterEventSource — close an event source handle. Returns TRUE (no-op).
// Wine ref: dlls/advapi32/eventlog.c — DeregisterEventSource closes the event log
// handle; TRUE on success.
pub unsafe extern "win64" fn deregister_event_source(_h_event_log: usize) -> i32 {
    1 // TRUE
}

/// ReportEventW — write an event log entry. Returns TRUE (no-op).
// Wine ref: dlls/advapi32/eventlog.c — ReportEventW writes to the event log;
// TRUE on success. Weave silently discards event log entries.
pub unsafe extern "win64" fn report_event_w(
    _h_event_log: usize,
    _w_type: u16,
    _w_category: u16,
    _dw_event_id: u32,
    _lp_user_sid: *const u8,
    _w_num_strings: u16,
    _dw_data_size: u32,
    _lp_strings: *const *const u16,
    _lp_raw_data: *const u8,
) -> i32 {
    1 // TRUE
}

// ── Non-Ex registry wrappers (Phase A stubs) ──────────────────────────────────

/// RegCreateKeyW — open or create a registry key (legacy non-Ex variant).
///
/// Delegates to `RegCreateKeyExW` with `dwOptions=REG_OPTION_NON_VOLATILE` and
/// `samDesired=MAXIMUM_ALLOWED`, matching Wine's behaviour.
///
/// # Safety
/// `lp_sub_key` must be null or a valid null-terminated UTF-16 string.
/// `phk_result` must be a writable pointer to a HKEY.
// Wine ref: dlls/advapi32/registry.c — RegCreateKeyW: validates phkResult != NULL,
// then calls RegCreateKeyExW(hkey, lpSubKey, 0, NULL, REG_OPTION_NON_VOLATILE,
// MAXIMUM_ALLOWED, NULL, phkResult, NULL).
// stub: Phase A — delegates to reg_create_key_ex_w; disposition and options ignored.
pub unsafe extern "win64" fn reg_create_key_w(
    h_key: usize,
    lp_sub_key: *const u16,
    phk_result: *mut usize,
) -> u32 {
    if phk_result.is_null() {
        return 87; // ERROR_INVALID_PARAMETER
    }
    // SAFETY: (a) phk_result non-null (checked above), caller-guaranteed writable HKEY*.
    // (b) lp_sub_key forwarded to reg_create_key_ex_w which handles null.
    // (c) Pointers valid for this call.  (d) Phase A — no Tier A gate yet.
    let ret = unsafe {
        reg_create_key_ex_w(
            h_key,
            lp_sub_key,
            0,                // reserved
            std::ptr::null(), // lpClass
            0,                // REG_OPTION_NON_VOLATILE
            0x02000000,       // MAXIMUM_ALLOWED
            0,                // lpSecurityAttributes
            phk_result,
            std::ptr::null_mut(), // lpdwDisposition
        )
    };
    ret as u32
}

/// RegGetValueW — retrieve data and type of a named registry value.
///
/// # Safety
/// `lp_sub_key`, `lp_value`, `p_type`, `pv_data`, and `pcb_data` must be valid or null.
// Wine ref: dlls/advapi32/registry.c — RegGetValueW opens the sub-key, queries the value
// via NtQueryValueKey, applies type filtering, then closes the sub-key. Weave has no real
// registry for non-standard keys; return ERROR_FILE_NOT_FOUND so callers use defaults.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn reg_get_value_w(
    _h_key: usize,
    _lp_sub_key: *const u16,
    _lp_value: *const u16,
    _dw_flags: u32,
    _p_type: *mut u32,
    _pv_data: *mut u8,
    _pcb_data: *mut u32,
) -> u32 {
    2 // ERROR_FILE_NOT_FOUND
}

/// RegSetValueW — set the default (unnamed) value of a key (legacy non-Ex variant).
///
/// # Safety
/// `lp_sub_key` must be null or a valid null-terminated UTF-16 string.
/// `lp_data` must be null or a valid null-terminated UTF-16 string.
// Wine ref: dlls/advapi32/registry.c — RegSetValueW: validates type==REG_SZ && data;
// calls RegSetKeyValueW(hkey, subkey, NULL, type, data, (lstrlenW(data)+1)*sizeof(WCHAR)).
// The NULL value-name writes the default value ('@' in Weave's key-dir layout).
pub unsafe extern "win64" fn reg_set_value_w(
    h_key: usize,
    lp_sub_key: *const u16,
    dw_type: u32,
    lp_data: *const u16,
    _cb_data: u32,
) -> u32 {
    if dw_type != REG_SZ || lp_data.is_null() {
        return 87; // ERROR_INVALID_PARAMETER
    }
    // Wine always recomputes byte count from string length (lstrlenW+1)*sizeof(WCHAR).
    let data_chars = {
        let mut n = 0usize;
        while unsafe { *lp_data.add(n) } != 0 {
            n += 1;
        }
        n + 1 // include NUL
    };
    let byte_count = (data_chars * 2) as u32;

    if lp_sub_key.is_null() {
        // Write default value directly on h_key (null value name → '@' internally).
        return unsafe {
            reg_set_value_ex_w(
                h_key,
                std::ptr::null(),
                0,
                REG_SZ,
                lp_data as *const u8,
                byte_count,
            ) as u32
        };
    }
    // Open (or create) the subkey, write, close.
    let mut sub_hkey: usize = 0;
    let ret = unsafe { reg_create_key_w(h_key, lp_sub_key, &mut sub_hkey) };
    if ret != 0 {
        return ret;
    }
    let write_ret = unsafe {
        reg_set_value_ex_w(
            sub_hkey,
            std::ptr::null(),
            0,
            REG_SZ,
            lp_data as *const u8,
            byte_count,
        ) as u32
    };
    reg_close_key(sub_hkey);
    write_ret
}

/// RegOpenKeyW — open a registry key (legacy non-Ex variant).
///
/// Phase A stub: returns ERROR_SUCCESS (0) but writes 0 into `phk_result` so
/// callers do not attempt to use a real handle. Callers that validate the handle
/// will observe a null HKEY; those that accept any non-ERROR_SUCCESS code will
/// see success and silently get null.
///
/// # Safety
/// `lp_sub_key` must be null or a valid null-terminated UTF-16 string.
/// `phk_result` must be a valid writable pointer.
// Wine ref: dlls/advapi32/registry.c — RegOpenKeyW is a thin wrapper calling
// RegOpenKeyExW(hKey, lpSubKey, 0, KEY_READ, phkResult); Weave does the same.
pub unsafe extern "win64" fn reg_open_key_w(
    h_key: usize,
    lp_sub_key: *const u16,
    phk_result: *mut usize,
) -> u32 {
    if phk_result.is_null() {
        return 87; // ERROR_INVALID_PARAMETER
    }
    // SAFETY: phk_result non-null (checked above), caller provides writable HKEY*.
    // lp_sub_key forwarded to reg_open_key_ex_w which handles null.
    unsafe { reg_open_key_ex_w(h_key, lp_sub_key, 0, 0x02000000, phk_result) as u32 }
}

/// GetTokenInformation — retrieve information about an access token.
///
/// Returns FALSE (0). Token queries are not supported; callers should check
/// `GetLastError` (not set) to detect the stub.
///
/// # Safety
/// `token_information` and `return_length` are accepted but not written.
// Wine ref: dlls/advapi32/security.c — GetTokenInformation calls
// NtQueryInformationToken; returns FALSE with ERROR_INSUFFICIENT_BUFFER when
// the caller's buffer is too small. Weave returns FALSE unconditionally.
pub unsafe extern "win64" fn get_token_information(
    _token_handle: usize,
    _token_info_class: u32,
    _token_information: *mut u8,
    _token_information_length: u32,
    _return_length: *mut u32,
) -> i32 {
    0 // FALSE
}

// ── IsTextUnicode ────────────────────────────────────────────────────────────

const IS_TEXT_UNICODE_ASCII16: u32 = 0x0001;
const IS_TEXT_UNICODE_STATISTICS: u32 = 0x0002;
const IS_TEXT_UNICODE_CONTROLS: u32 = 0x0004;
const IS_TEXT_UNICODE_SIGNATURE: u32 = 0x0008;
const IS_TEXT_UNICODE_ILLEGAL_CHARS: u32 = 0x0100;
const IS_TEXT_UNICODE_ODD_LENGTH: u32 = 0x0200;
const IS_TEXT_UNICODE_NULL_BYTES: u32 = 0x1000;

/// Determine whether a buffer is likely Unicode text.
///
/// Applies heuristic checks: BOM detection, null-bytes pattern
/// (strong UTF-16 indicator), ASCII16 pattern, odd-length rejection,
/// and illegal-character detection.
///
/// Returns TRUE (1) if the buffer appears to be Unicode text, FALSE (0) otherwise.
/// When `lpi_result` is non-null, the specific flags that matched are written.
///
/// # Safety
/// `lp_buffer` must be valid for at least `cb` bytes. `lpi_result` may be null.
// Wine ref: dlls/advapi32/misc.c IsTextUnicode — applies heuristic byte-pattern
// analysis: BOM check, null-bytes (UTF-16 strong signal), ASCII-range pairs,
// odd-length rejection, and illegal-char detection.
pub unsafe extern "win64" fn is_text_unicode(
    lp_buffer: *const u8,
    cb: i32,
    lpi_result: *mut u32,
) -> i32 {
    if lp_buffer.is_null() || cb < 2 {
        if !lpi_result.is_null() {
            unsafe { *lpi_result = 0 };
        }
        return 0; // FALSE
    }
    let cb = cb as usize;
    let buf = lp_buffer;
    let mut flags: u32 = 0;

    // 1 — BOM check (0xFEFF = UTF-16 LE BOM, 0xFFFE = UTF-16 BE BOM)
    let first_word = unsafe { u16::from_le_bytes([*buf, *buf.add(1)]) };
    if cb >= 2 && first_word == 0xFEFF {
        flags |= IS_TEXT_UNICODE_SIGNATURE;
    }

    // 2 — Odd-length rejection
    if cb & 1 != 0 {
        flags |= IS_TEXT_UNICODE_ODD_LENGTH;
    }

    // 3 — Scan for patterns
    let word_count = cb / 2;
    let mut null_byte_pairs = 0u32;
    let mut ascii16_pairs = 0u32;
    let mut illegal_chars = 0u32;

    for i in 0..word_count {
        let lo = unsafe { *buf.add(i * 2) };
        let hi = unsafe { *buf.add(i * 2 + 1) };
        let w = lo as u16 | ((hi as u16) << 8);

        if lo == 0 || hi == 0 {
            null_byte_pairs += 1;
        }
        // ASCII16: hi byte is 0x00, lo byte is printable ASCII
        if hi == 0 && (0x20..=0x7E).contains(&lo) {
            ascii16_pairs += 1;
        }
        // Illegal Unicode chars
        if w == 0xFFFE || w == 0xFFFF || (0xFDD0..=0xFDEF).contains(&w) {
            illegal_chars += 1;
        }
    }

    if null_byte_pairs > 0 {
        flags |= IS_TEXT_UNICODE_NULL_BYTES;
    }
    if ascii16_pairs > 0 {
        flags |= IS_TEXT_UNICODE_ASCII16;
    }
    if illegal_chars > 0 {
        flags |= IS_TEXT_UNICODE_ILLEGAL_CHARS;
    }

    // 4 — Weak statistical check: if >30% of WORDs have a null byte, likely UTF-16
    if word_count > 0 && null_byte_pairs > word_count as u32 / 3 {
        flags |= IS_TEXT_UNICODE_STATISTICS;
    }

    // 5 — Control character check (0x01..0x1F, not tab/newline)
    let mut controls = 0u32;
    for i in 0..word_count {
        let lo = unsafe { *buf.add(i * 2) };
        let hi = unsafe { *buf.add(i * 2 + 1) };
        if hi == 0 && (0x01..=0x1F).contains(&lo) && lo != b'\t' && lo != b'\n' && lo != b'\r' {
            controls += 1;
        }
    }
    if controls > 0 {
        flags |= IS_TEXT_UNICODE_CONTROLS;
    }

    // Write result flags
    if !lpi_result.is_null() {
        unsafe { *lpi_result = flags };
    }

    // Decision: TRUE if any strong indicator is present
    // Strong indicators: BOM, null bytes, statistics, controls, ASCII16
    // (odd-length alone with BOM is still TRUE)
    let strong_indicators = flags
        & (IS_TEXT_UNICODE_SIGNATURE
            | IS_TEXT_UNICODE_NULL_BYTES
            | IS_TEXT_UNICODE_STATISTICS
            | IS_TEXT_UNICODE_CONTROLS
            | IS_TEXT_UNICODE_ASCII16);
    if strong_indicators != 0 {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

// ── Security descriptor stubs ─────────────────────────────────────

// Wine ref: dlls/advapi32/sec.c — ConvertStringSecurityDescriptorToSecurityDescriptorW
// parses a string SDDL representation. Not stub-capable — needs real SDDL parser.
// Weave stub returns ERROR_INVALID_PARAMETER.
#[allow(unused_variables)]
pub unsafe extern "win64" fn convert_string_sd_to_sd_w(
    string_sd: *const u16,
    string_sd_revision: u32,
    security_descriptor: *mut *mut u8,
    security_descriptor_len: *mut u32,
) -> i32 {
    weave_common::set_last_error(87); // ERROR_INVALID_PARAMETER
    0 // FALSE
}

// Wine ref: dlls/advapi32/sec.c — BuildSecurityDescriptorW constructs a security
// descriptor from trustee and access entries. Not stub-capable.
// Weave stub returns ERROR_INVALID_PARAMETER.
#[allow(unused_variables)]
pub unsafe extern "win64" fn build_security_descriptor_w(
    p_owner: *const u8,
    p_group: *const u8,
    c_count_of_access_entries: u32,
    p_list_of_access_entries: *const u8,
    c_count_of_audit_entries: u32,
    p_list_of_audit_entries: *const u8,
    p_new_security_descriptor: *mut *mut u8,
    pcb_security_descriptor: *mut u32,
) -> u32 {
    87 // ERROR_INVALID_PARAMETER
}

// Wine ref: dlls/advapi32/sec.c — BuildExplicitAccessWithNameW constructs an
// EXPLICIT_ACCESS structure from a trustee name. Weave stub — ERROR_INVALID_PARAMETER.
#[allow(unused_variables)]
pub unsafe extern "win64" fn build_explicit_access_with_name_w(
    p_explicit_access: *mut u8,
    p_trustee_name: *const u16,
    access_permissions: u32,
    access_mode: u32,
    inheritance: u32,
) -> u32 {
    87 // ERROR_INVALID_PARAMETER
}

// ── Phase A stubs ─────────────────────────────────────────────────

#[allow(unused_variables)]
pub unsafe extern "win64" fn reg_enum_key_w(
    hkey: usize,
    dw_index: u32,
    lp_name: *mut u16,
    lpcch_name: *mut u32,
    lp_reserved: *mut u32,
    lp_class: *mut u16,
    lpcch_class: *mut u32,
    lpft_last_write_time: *mut u8,
) -> i32 {
    1 // ERROR_NO_MORE_ITEMS
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
