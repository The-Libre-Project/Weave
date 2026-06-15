//! Weave simple PIDL allocator and IL* helpers for shell32.
//!
//! Wine ref: dlls/shell32/pidl.c — ILGetSize walks cb-linked items; ILCombine
//! concatenates lists; SHGetPathFromIDListW resolves via shell namespace.
//! Weave stores UTF-16 paths in tagged items (magic `WEV1`) alloc'd via malloc.

const WEAVE_PIDL_MAGIC: u32 = 0x5745_5631; // "WEV1"
const MAX_PATH: usize = 260;

fn read_u16(ptr: *const u8) -> u16 {
    unsafe { u16::from_le_bytes([*ptr, *ptr.add(1)]) }
}

fn write_u16(ptr: *mut u8, value: u16) {
    unsafe {
        *ptr = (value & 0xFF) as u8;
        *ptr.add(1) = (value >> 8) as u8;
    }
}

fn read_u32(ptr: *const u8) -> u32 {
    unsafe { u32::from_le_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)]) }
}

fn write_u32(ptr: *mut u8, value: u32) {
    unsafe {
        let bytes = value.to_le_bytes();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, 4);
    }
}

fn decode_wide_null(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut units: Vec<u16> = Vec::new();
    let mut p = ptr;
    loop {
        let ch = unsafe { *p };
        if ch == 0 {
            break;
        }
        units.push(ch);
        p = unsafe { p.add(1) };
    }
    String::from_utf16_lossy(&units)
}

fn is_weave_item(item: *const u8) -> bool {
    let cb = read_u16(item);
    if cb < 8 {
        return false;
    }
    read_u32(unsafe { item.add(2) }) == WEAVE_PIDL_MAGIC
}

pub(crate) fn weave_item_path(item: *const u8) -> Option<String> {
    if !is_weave_item(item) {
        return None;
    }
    let cb = read_u16(item) as usize;
    if cb < 10 {
        return None;
    }
    let char_count = read_u16(unsafe { item.add(6) }) as usize;
    let data_off = 8usize;
    if data_off + char_count * 2 > cb {
        return None;
    }
    let mut units: Vec<u16> = Vec::with_capacity(char_count);
    for i in 0..char_count {
        let off = data_off + i * 2;
        let lo = unsafe { *item.add(off) } as u16;
        let hi = unsafe { *item.add(off + 1) } as u16;
        units.push(lo | (hi << 8));
    }
    Some(String::from_utf16_lossy(&units))
}

fn join_win_paths(base: &str, child: &str) -> String {
    if child.len() >= 2 && child.as_bytes()[1] == b':' {
        return child.to_string();
    }
    if child.starts_with('\\') {
        return child.to_string();
    }
    let base = base.trim_end_matches('\\');
    if base.is_empty() {
        child.to_string()
    } else {
        format!("{base}\\{}", child.trim_start_matches('\\'))
    }
}

pub(crate) fn pidl_path_from_list(pidl: *const u8) -> Option<String> {
    if pidl.is_null() {
        return None;
    }
    let mut item = pidl;
    let mut path: Option<String> = None;
    loop {
        let cb = read_u16(item);
        if cb == 0 {
            break;
        }
        if let Some(segment) = weave_item_path(item) {
            path = Some(match path {
                Some(existing) => join_win_paths(&existing, &segment),
                None => segment,
            });
        } else {
            return None;
        }
        item = unsafe { item.add(cb as usize) };
    }
    path
}

fn write_wide_to_buffer(dest: *mut u16, path: &str, max_chars: usize) -> i32 {
    let wide: Vec<u16> = path.encode_utf16().collect();
    let copy_len = wide.len().min(max_chars.saturating_sub(1));
    for (i, ch) in wide.iter().take(copy_len).enumerate() {
        unsafe {
            *dest.add(i) = *ch;
        }
    }
    unsafe {
        *dest.add(copy_len) = 0;
    }
    1
}

/// Allocate a single-item Weave PIDL containing `path`.
pub fn pidl_from_path_w(path: &str) -> *mut u8 {
    let wide: Vec<u16> = path.encode_utf16().collect();
    let char_count = wide.len();
    if char_count > u16::MAX as usize {
        return std::ptr::null_mut();
    }
    let item_size = 8 + char_count * 2;
    let item_size = (item_size + 1) & !1; // WORD align
    let total = item_size + 2; // + terminator
    let ptr = unsafe { libc::malloc(total) as *mut u8 };
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    // Wine: cb is the size of this item including the cb field itself.
    write_u16(ptr, item_size as u16);
    write_u32(unsafe { ptr.add(2) }, WEAVE_PIDL_MAGIC);
    write_u16(unsafe { ptr.add(6) }, char_count as u16);
    for (i, ch) in wide.iter().enumerate() {
        let off = 8 + i * 2;
        unsafe {
            *ptr.add(off) = (*ch & 0xFF) as u8;
            *ptr.add(off + 1) = (*ch >> 8) as u8;
        }
    }
    if item_size > 8 + char_count * 2 {
        unsafe {
            *ptr.add(8 + char_count * 2) = 0;
        }
    }
    write_u16(unsafe { ptr.add(item_size) }, 0);
    ptr
}

/// ILGetSize — byte size including terminator.
///
/// # Safety
/// `pidl` must be null or point at a valid PIDL chain.
// Wine ref: dlls/shell32/pidl.c::ILGetSize — sums each item cb, adds 2 for terminator.
pub unsafe extern "win64" fn il_get_size(pidl: *const u8) -> u32 {
    if pidl.is_null() {
        return 0;
    }
    let mut total = 0u32;
    let mut item = pidl;
    loop {
        let cb = read_u16(item);
        if cb == 0 {
            total += 2;
            break;
        }
        total += cb as u32;
        item = item.add(cb as usize);
    }
    total
}

/// ILGetNext — pointer to next item, or NULL at terminator.
///
/// # Safety
/// `pidl` must be null or point at a valid PIDL item.
// Wine ref: dlls/shell32/pidl.c::ILGetNext — advances by current cb; NULL if cb==0.
pub unsafe extern "win64" fn il_get_next(pidl: *const u8) -> *mut u8 {
    if pidl.is_null() {
        return std::ptr::null_mut();
    }
    let cb = read_u16(pidl);
    if cb == 0 {
        return std::ptr::null_mut();
    }
    unsafe { pidl.add(cb as usize) as *mut u8 }
}

/// ILFree — free a PIDL allocated by Weave shell helpers.
///
/// # Safety
/// `pidl` must be null or a PIDL pointer originally returned by `pidl_from_path_w` / `il_combine`.
// Wine ref: dlls/shell32/pidl.c::ILFree — SHFree/CoTaskMemFree; NULL is no-op.
pub unsafe extern "win64" fn il_free(pidl: *mut u8) {
    if !pidl.is_null() {
        unsafe { libc::free(pidl as *mut libc::c_void) };
    }
}

/// ILClone — duplicate a PIDL.
///
/// # Safety
/// `pidl` must be null or a valid PIDL chain.
// Wine ref: dlls/shell32/pidl.c::ILClone — SHAlloc + memcpy ILGetSize bytes.
pub unsafe extern "win64" fn il_clone(pidl: *const u8) -> *mut u8 {
    if pidl.is_null() {
        return std::ptr::null_mut();
    }
    let size = il_get_size(pidl) as usize;
    if size == 0 {
        return std::ptr::null_mut();
    }
    let dst = unsafe { libc::malloc(size) as *mut u8 };
    if dst.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(pidl, dst, size);
    }
    dst
}

/// ILCombine — concatenate two PIDL lists.
///
/// # Safety
/// Pointer arguments must be null or valid PIDL chains.
// Wine ref: dlls/shell32/pidl.c::ILCombine — memcpy pidl1 (minus terminator) + pidl2.
pub unsafe extern "win64" fn il_combine(pidl1: *const u8, pidl2: *const u8) -> *mut u8 {
    if pidl1.is_null() && pidl2.is_null() {
        return std::ptr::null_mut();
    }
    if pidl1.is_null() {
        return il_clone(pidl2);
    }
    if pidl2.is_null() {
        return il_clone(pidl1);
    }
    let len1 = il_get_size(pidl1) as usize - 2;
    let len2 = il_get_size(pidl2) as usize;
    let dst = unsafe { libc::malloc(len1 + len2) as *mut u8 };
    if dst.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(pidl1, dst, len1);
        std::ptr::copy_nonoverlapping(pidl2, dst.add(len1), len2);
    }
    dst
}

/// ILFindChild — return the portion of `pidl_child` relative to `pidl_parent`.
///
/// # Safety
/// Pointer arguments must be null or valid PIDL chains.
// Wine ref: dlls/shell32/pidl.c::ILFindChild — prefix match on serialized bytes.
pub unsafe extern "win64" fn il_find_child(
    pidl_parent: *const u8,
    pidl_child: *const u8,
) -> *mut u8 {
    if pidl_child.is_null() {
        return std::ptr::null_mut();
    }
    if pidl_parent.is_null() {
        return pidl_child as *mut u8;
    }
    let parent_bytes = il_get_size(pidl_parent) as usize - 2;
    if parent_bytes == 0 {
        return pidl_child as *mut u8;
    }
    let child_size = il_get_size(pidl_child) as usize;
    if child_size < parent_bytes {
        return std::ptr::null_mut();
    }
    let equal = unsafe {
        libc::memcmp(
            pidl_parent as *const libc::c_void,
            pidl_child as *const libc::c_void,
            parent_bytes,
        ) == 0
    };
    if equal {
        unsafe { pidl_child.add(parent_bytes) as *mut u8 }
    } else {
        std::ptr::null_mut()
    }
}

/// ILIsEqual — compare two PIDLs.
///
/// # Safety
/// Pointer arguments must be null or valid PIDL chains.
// Wine ref: dlls/shell32/pidl.c::ILIsEqual — ILGetSize then memcmp.
pub unsafe extern "win64" fn il_is_equal(pidl1: *const u8, pidl2: *const u8) -> i32 {
    if pidl1.is_null() && pidl2.is_null() {
        return 1;
    }
    if pidl1.is_null() || pidl2.is_null() {
        return 0;
    }
    let size1 = il_get_size(pidl1) as usize;
    let size2 = il_get_size(pidl2) as usize;
    if size1 != size2 {
        return 0;
    }
    let eq = unsafe {
        libc::memcmp(
            pidl1 as *const libc::c_void,
            pidl2 as *const libc::c_void,
            size1,
        ) == 0
    };
    eq as i32
}

/// ILCreateFromPathW (shell32 #190) — build a PIDL from a path string.
///
/// # Safety
/// `path` must be null or a valid null-terminated UTF-16 string.
// Wine ref: dlls/shell32/pidl.c::ILCreateFromPathW — SHILCreateFromPathW wrapper.
pub unsafe extern "win64" fn il_create_from_path_w(path: *const u16) -> *mut u8 {
    let path_str = decode_wide_null(path);
    if path_str.is_empty() {
        return std::ptr::null_mut();
    }
    pidl_from_path_w(&path_str)
}

/// SHGetPathFromIDListW — write the filesystem path for a PIDL.
///
/// # Safety
/// `pidl` and `psz_path` may be null; `psz_path` must have room for `MAX_PATH` wide chars.
// Wine ref: dlls/shell32/pidl.c::SHGetPathFromIDListW — SHGetPathFromIDListEx(MAX_PATH);
// Weave resolves tagged path items directly without IShellFolder.
pub unsafe extern "win64" fn sh_get_path_from_id_list_w(
    pidl: *const u8,
    psz_path: *mut u16,
) -> i32 {
    if !psz_path.is_null() {
        unsafe {
            *psz_path = 0;
        }
    }
    if pidl.is_null() || psz_path.is_null() {
        return 0;
    }
    pidl_path_from_list(pidl)
        .map(|path| write_wide_to_buffer(psz_path, &path, MAX_PATH))
        .unwrap_or(0)
}

/// ILFindLastID — find the last (non-terminator) item in a PIDL chain.
///
/// # Safety
/// `pidl` must be null or point at a valid PIDL chain.
// Wine ref: dlls/shell32/pidl.c::ILFindLastID
pub unsafe extern "win64" fn il_find_last_id(pidl: *const u8) -> *mut u8 {
    if pidl.is_null() {
        return std::ptr::null_mut();
    }
    let mut last: *const u8 = std::ptr::null();
    let mut item = pidl;
    loop {
        let cb = read_u16(item);
        if cb == 0 {
            break;
        }
        last = item;
        item = unsafe { item.add(cb as usize) };
    }
    last as *mut u8
}

/// ILRemoveLastID — remove the last item from a PIDL by overwriting its cb with a terminator.
///
/// # Safety
/// `pidl` must be null or point at a valid PIDL chain.
// Wine ref: dlls/shell32/pidl.c::ILRemoveLastID
pub unsafe extern "win64" fn il_remove_last_id(pidl: *mut u8) -> i32 {
    if pidl.is_null() {
        return 0;
    }
    let mut last: *mut u8 = std::ptr::null_mut();
    let mut item = pidl;
    loop {
        let cb = read_u16(item);
        if cb == 0 {
            break;
        }
        last = item;
        item = unsafe { item.add(cb as usize) };
    }
    if last.is_null() {
        return 0;
    }
    write_u16(last, 0);
    write_u16(unsafe { last.add(2) }, 0);
    1
}

/// ILIsParent — check if `pidl_parent` is a parent of `pidl_child`.
///
/// # Safety
/// Pointer arguments must be null or valid PIDL chains.
// Wine ref: dlls/shell32/pidl.c::ILIsParent
pub unsafe extern "win64" fn il_is_parent(
    pidl_parent: *const u8,
    pidl_child: *const u8,
    immediate: i32,
) -> i32 {
    if pidl_parent.is_null() || pidl_child.is_null() {
        return 0;
    }
    // Count items in parent
    let mut parent_count = 0u32;
    let mut item = pidl_parent;
    loop {
        let cb = read_u16(item);
        if cb == 0 {
            break;
        }
        parent_count += 1;
        item = unsafe { item.add(cb as usize) };
    }
    if parent_count == 0 {
        return 0;
    }
    // Count items in child
    let mut child_count = 0u32;
    item = pidl_child;
    loop {
        let cb = read_u16(item);
        if cb == 0 {
            break;
        }
        child_count += 1;
        item = unsafe { item.add(cb as usize) };
    }
    if child_count < parent_count {
        return 0;
    }
    if immediate != 0 && child_count != parent_count + 1 {
        return 0;
    }
    // Prefix match: compare parent bytes (minus terminator) against child's start
    let parent_bytes = il_get_size(pidl_parent) as usize - 2;
    let eq = unsafe {
        libc::memcmp(
            pidl_parent as *const libc::c_void,
            pidl_child as *const libc::c_void,
            parent_bytes,
        ) == 0
    };
    eq as i32
}

/// ILAppendID — append an ID to a PIDL.
///
/// # Safety
/// `ppidl` must be a valid pointer to a PIDL pointer (may be null).
/// `pidl_add` must be a valid non-terminator PIDL item.
// Wine ref: dlls/shell32/pidl.c::ILAppendID
pub unsafe extern "win64" fn il_append_id(
    ppidl: *mut *mut u8,
    pidl_add: *const u8,
    _flags: u32,
) -> i32 {
    if ppidl.is_null() || pidl_add.is_null() {
        return 0;
    }
    let old_pidl = *ppidl;
    let add_cb = read_u16(pidl_add);
    if add_cb == 0 {
        return 0;
    }
    let add_size = add_cb as usize;
    // Size of existing PIDL minus its terminator
    let old_size = if old_pidl.is_null() {
        0
    } else {
        il_get_size(old_pidl) as usize - 2
    };
    // Allocate: old content + new item + terminator
    let new_size = old_size + add_size + 2;
    let new_pidl = unsafe { libc::malloc(new_size) as *mut u8 };
    if new_pidl.is_null() {
        return 0;
    }
    if old_size > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(old_pidl, new_pidl, old_size);
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(pidl_add, new_pidl.add(old_size), add_size);
    }
    // Write terminator
    write_u16(unsafe { new_pidl.add(old_size + add_size) }, 0);
    // Free old PIDL and update pointer
    if !old_pidl.is_null() {
        unsafe { il_free(old_pidl) };
    }
    *ppidl = new_pidl;
    1
}

/// ILCloneFull — full clone (delegates to ILClone).
///
/// # Safety
/// `pidl` must be null or a valid PIDL chain.
// Wine ref: dlls/shell32/pidl.c::ILCloneFull — returns ILClone
pub unsafe extern "win64" fn il_clone_full(pidl: *const u8) -> *mut u8 {
    unsafe { il_clone(pidl) }
}

/// SHGetPathFromIDListEx — write the filesystem path for a PIDL with caller-supplied buffer size.
///
/// # Safety
/// `pidl` and `psz_path` may be null; `psz_path` must have room for `max_path` wide chars.
// Wine ref: dlls/shell32/pidl.c::SHGetPathFromIDListEx
pub unsafe extern "win64" fn sh_get_path_from_id_list_ex(
    pidl: *const u8,
    psz_path: *mut u16,
    max_path: u32,
) -> i32 {
    if !psz_path.is_null() {
        unsafe {
            *psz_path = 0;
        }
    }
    if pidl.is_null() || psz_path.is_null() {
        return 0;
    }
    pidl_path_from_list(pidl)
        .map(|path| write_wide_to_buffer(psz_path, &path, max_path as usize))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidl_roundtrip_path() {
        let pidl = pidl_from_path_w(r"C:\Users\test");
        assert!(!pidl.is_null());
        unsafe {
            assert_eq!(il_get_size(pidl), 36);
            let mut buf = [0u16; MAX_PATH];
            assert_eq!(sh_get_path_from_id_list_w(pidl, buf.as_mut_ptr()), 1);
            let back =
                String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(0)]);
            assert_eq!(back, r"C:\Users\test");
            il_free(pidl);
        }
    }

    #[test]
    fn il_combine_preserves_child_path() {
        let parent = pidl_from_path_w(r"C:\Dir");
        let child = pidl_from_path_w("file.txt");
        unsafe {
            let combined = il_combine(parent, child);
            assert!(!combined.is_null());
            let mut buf = [0u16; MAX_PATH];
            assert_eq!(sh_get_path_from_id_list_w(combined, buf.as_mut_ptr()), 1);
            let path =
                String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(0)]);
            assert_eq!(path, r"C:\Dir\file.txt");
            il_free(parent);
            il_free(child);
            il_free(combined);
        }
    }
}
