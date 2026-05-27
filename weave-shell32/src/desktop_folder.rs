//! Minimal desktop `IShellFolder` + `IEnumIDList` for Q-Dir file-pane (E3-M5b).
//!
//! Wine ref: dlls/shell32/shfldr_desktop.c — SHGetDesktopFolder singleton;
//! dlls/shell32/shfldr.c — IShellFolder::EnumObjects creates IEnumIDList;
//! dlls/shell32/enumidlist.c — IEnumIDList::Next returns PIDLs.

use crate::pidl;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;
use weave_core::progress::mark_shell_enum_first;

const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const E_POINTER: i32 = 0x8000_4003u32 as i32;
const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;

static DESKTOP_FOLDER: OnceLock<usize> = OnceLock::new();

struct EnumState {
    items: Vec<usize>,
    index: usize,
}

fn cwd_child_pidls() -> Vec<usize> {
    let Ok(cwd) = std::env::current_dir() else {
        return Vec::new();
    };
    let Ok(read) = std::fs::read_dir(&cwd) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in read.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let path = cwd.join(&name);
        let win_path = path.to_string_lossy().replace('/', "\\");
        let pidl = pidl::pidl_from_path_w(&win_path);
        if !pidl.is_null() {
            out.push(pidl as usize);
        }
        if out.len() >= 64 {
            break;
        }
    }
    out
}

fn get_desktop_folder_ptr() -> usize {
    *DESKTOP_FOLDER.get_or_init(|| {
        let vtable: Box<[usize; 13]> = Box::new([
            sf_query_interface as *const () as usize,
            sf_add_ref as *const () as usize,
            sf_release as *const () as usize,
            sf_parse_display_name as *const () as usize,
            sf_enum_objects as *const () as usize,
            sf_bind_to_object as *const () as usize,
            sf_bind_to_storage as *const () as usize,
            sf_compare_ids as *const () as usize,
            sf_create_view_object as *const () as usize,
            sf_get_attributes_of as *const () as usize,
            sf_get_ui_object_of as *const () as usize,
            sf_get_display_name_of as *const () as usize,
            sf_set_name_of as *const () as usize,
        ]);
        let vtable_ptr = Box::into_raw(vtable) as usize;
        let obj: Box<usize> = Box::new(vtable_ptr);
        Box::into_raw(obj) as usize
    })
}

fn get_enum_ptr(items: Vec<usize>) -> usize {
    let state = Box::new(EnumState { items, index: 0 });
    let state_ptr = Box::into_raw(state) as usize;
    let vtable: Box<[usize; 7]> = Box::new([
        enum_query_interface as *const () as usize,
        enum_add_ref as *const () as usize,
        enum_release as *const () as usize,
        enum_next as *const () as usize,
        enum_skip as *const () as usize,
        enum_reset as *const () as usize,
        enum_clone as *const () as usize,
    ]);
    let vtable_ptr = Box::into_raw(vtable) as usize;
    // COM layout: [0] vtable*, [1] private state pointer.
    let obj: Box<[usize; 2]> = Box::new([vtable_ptr, state_ptr]);
    Box::into_raw(obj) as usize
}

unsafe extern "win64" fn sf_query_interface(
    _this: usize,
    _riid: *const u8,
    ppv: *mut usize,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }
    unsafe { *ppv = _this };
    S_OK
}

unsafe extern "win64" fn sf_add_ref(_this: usize) -> u32 {
    let _ = _this;
    1
}

unsafe extern "win64" fn sf_release(_this: usize) -> u32 {
    let _ = _this;
    1
}

unsafe extern "win64" fn sf_parse_display_name(
    _this: usize,
    _hwnd: usize,
    _pbc: usize,
    _display: *const u16,
    _pch: *mut u32,
    _ppidl: *mut *mut u8,
    _attrs: *mut u32,
) -> i32 {
    E_NOINTERFACE
}

/// IShellFolder::EnumObjects — enumerate children of the process CWD as WEV1 PIDLs.
///
/// # Safety
/// `ppenum` must be a valid writable pointer when non-null.
// Wine ref: dlls/shell32/shfldr.c — EnumObjects allocates IEnumIDList; desktop uses child PIDLs.
unsafe extern "win64" fn sf_enum_objects(
    _this: usize,
    _hwnd: usize,
    _grf_flags: u32,
    ppenum: *mut usize,
) -> i32 {
    if ppenum.is_null() {
        return E_POINTER;
    }
    let items = cwd_child_pidls();
    let enum_ptr = get_enum_ptr(items);
    unsafe { *ppenum = enum_ptr };
    S_OK
}

unsafe extern "win64" fn sf_bind_to_object(
    _this: usize,
    _pidl: *const u8,
    _pbc: usize,
    _riid: *const u8,
    _ppv: *mut usize,
) -> i32 {
    E_NOINTERFACE
}

unsafe extern "win64" fn sf_bind_to_storage(
    _this: usize,
    _pidl: *const u8,
    _pbc: usize,
    _riid: *const u8,
    _ppv: *mut usize,
) -> i32 {
    E_NOINTERFACE
}

unsafe extern "win64" fn sf_compare_ids(_this: usize, _pidl1: *const u8, _pidl2: *const u8) -> i32 {
    let _ = (_this, _pidl1, _pidl2);
    0
}

unsafe extern "win64" fn sf_create_view_object(
    _this: usize,
    _hwnd: usize,
    _riid: *const u8,
    _ppv: *mut usize,
) -> i32 {
    E_NOINTERFACE
}

unsafe extern "win64" fn sf_get_attributes_of(
    _this: usize,
    _count: u32,
    _pidls: *const *const u8,
    _attrs: *mut u32,
) -> i32 {
    let _ = (_this, _count, _pidls, _attrs);
    E_NOINTERFACE
}

unsafe extern "win64" fn sf_get_ui_object_of(
    _this: usize,
    _hwnd: usize,
    _count: u32,
    _pidls: *const *const u8,
    _riid: *const u8,
    _reserved: *mut u32,
    _ppv: *mut usize,
) -> i32 {
    E_NOINTERFACE
}

unsafe extern "win64" fn sf_get_display_name_of(
    _this: usize,
    _pidl: *const u8,
    _flags: u32,
    _name: *mut u8,
) -> i32 {
    E_NOINTERFACE
}

unsafe extern "win64" fn sf_set_name_of(
    _this: usize,
    _hwnd: usize,
    _pidl: *const u8,
    _name: *const u16,
    _flags: u32,
    _new_pidl: *mut *mut u8,
) -> i32 {
    E_NOINTERFACE
}

fn enum_state(this: usize) -> Option<&'static mut EnumState> {
    if this == 0 {
        return None;
    }
    let state_ptr = unsafe { *((this as *const usize).add(1)) };
    if state_ptr == 0 {
        return None;
    }
    Some(unsafe { &mut *(state_ptr as *mut EnumState) })
}

static ENUM_REFS: AtomicU32 = AtomicU32::new(1);

unsafe extern "win64" fn enum_query_interface(
    _this: usize,
    _riid: *const u8,
    ppv: *mut usize,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }
    unsafe { *ppv = _this };
    S_OK
}

unsafe extern "win64" fn enum_add_ref(_this: usize) -> u32 {
    let _ = _this;
    ENUM_REFS.fetch_add(1, Ordering::Relaxed)
}

unsafe extern "win64" fn enum_release(_this: usize) -> u32 {
    let _ = _this;
    ENUM_REFS.fetch_sub(1, Ordering::Relaxed).saturating_sub(0)
}

/// IEnumIDList::Next — return one PIDL per call until exhausted.
///
/// # Safety
/// `rgelt` and `pcelt_fetched` per COM contract when non-null.
// Wine ref: dlls/shell32/enumidlist.c — Next copies PIDLs; returns S_FALSE when done.
unsafe extern "win64" fn enum_next(
    this: usize,
    celt: u32,
    rgelt: *mut usize,
    pcelt_fetched: *mut u32,
) -> i32 {
    if celt == 0 || rgelt.is_null() {
        return E_POINTER;
    }
    let Some(state) = enum_state(this) else {
        return E_POINTER;
    };
    if state.index >= state.items.len() {
        if !pcelt_fetched.is_null() {
            unsafe { *pcelt_fetched = 0 };
        }
        return S_FALSE;
    }
    let pidl = state.items[state.index];
    state.index += 1;
    unsafe {
        *rgelt = pidl;
        if !pcelt_fetched.is_null() {
            *pcelt_fetched = 1;
        }
    }
    mark_shell_enum_first();
    S_OK
}

unsafe extern "win64" fn enum_skip(this: usize, celt: u32) -> i32 {
    let Some(state) = enum_state(this) else {
        return E_POINTER;
    };
    state.index = state.index.saturating_add(celt as usize);
    if state.index >= state.items.len() {
        S_FALSE
    } else {
        S_OK
    }
}

unsafe extern "win64" fn enum_reset(this: usize) -> i32 {
    if let Some(state) = enum_state(this) {
        state.index = 0;
        S_OK
    } else {
        E_POINTER
    }
}

unsafe extern "win64" fn enum_clone(_this: usize, _ppenum: *mut usize) -> i32 {
    let _ = _this;
    E_NOINTERFACE
}

/// Return the desktop `IShellFolder*` singleton (process lifetime).
pub fn desktop_folder_ptr() -> usize {
    get_desktop_folder_ptr()
}
