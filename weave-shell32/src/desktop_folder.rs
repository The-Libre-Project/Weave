//! Minimal desktop `IShellFolder` + `IEnumIDList` for Q-Dir file-pane (E3-M5b).
//!
//! Wine ref: dlls/shell32/shfldr_desktop.c — SHGetDesktopFolder singleton;
//! dlls/shell32/shfldr.c — IShellFolder::EnumObjects creates IEnumIDList;
//! dlls/shell32/enumidlist.c — IEnumIDList::Next returns PIDLs.

use crate::pidl;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;
use weave_core::progress::{mark_shell_enum_first, mark_shell_folder_enum_objects_first};

const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const E_POINTER: i32 = 0x8000_4003u32 as i32;
const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;
/// IID_IShellView = {000214E3-0000-0000-C000-000000000046}
/// Wire format: Data1(LE) Data2(LE) Data3(LE) Data4
const IID_ISHELL_VIEW: [u8; 16] = [
    0xE3, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

static DESKTOP_FOLDER: OnceLock<usize> = OnceLock::new();
static SHELL_VIEW: OnceLock<usize> = OnceLock::new();

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
    *DESKTOP_FOLDER.get_or_init(|| new_shell_folder_instance(None))
}

/// Create a new IShellFolder COM object.
///
/// Object layout: `[vtable_ptr, data_ptr]` — a 2-element usize array.
/// `data_ptr == 0`: desktop folder, enumerates CWD children.
/// `data_ptr != 0`: bound subfolder, `data_ptr` is `Box::into_raw(Box::new(String))`
/// containing the filesystem path to enumerate children from.
fn new_shell_folder_instance(bound_path: Option<String>) -> usize {
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
    let data_ptr = match bound_path {
        Some(p) => Box::into_raw(Box::new(p)) as usize,
        None => 0,
    };
    let obj: Box<[usize; 2]> = Box::new([vtable_ptr, data_ptr]);
    Box::into_raw(obj) as usize
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

unsafe extern "win64" fn sf_add_ref(this: usize) -> u32 {
    let data_ptr = unsafe { *(this as *const usize).add(1) };
    if data_ptr == 0 {
        // Desktop folder singleton — returns 1 (no real refcount).
        1
    } else {
        2
    }
}

unsafe extern "win64" fn sf_release(this: usize) -> u32 {
    let data_ptr = unsafe { *(this as *const usize).add(1) };
    if data_ptr != 0 {
        // Bound subfolder — free the per-instance path String and the 2-element array.
        let _ = unsafe { Box::from_raw(data_ptr as *mut String) };
        let _ = unsafe { Box::from_raw(this as *mut [usize; 2]) };
    }
    1
}

// Wine ref: dlls/shell32/shfldr.c — ParseDisplayName returns S_FALSE with NULL ppidl for unknown names.
unsafe extern "win64" fn sf_parse_display_name(
    _this: usize,
    _hwnd: usize,
    _pbc: usize,
    _display: *const u16,
    _pch: *mut u32,
    ppidl: *mut *mut u8,
    _attrs: *mut u32,
) -> i32 {
    if ppidl.is_null() {
        return E_POINTER;
    }
    unsafe { *ppidl = std::ptr::null_mut() };
    S_FALSE
}

/// IShellFolder::EnumObjects — enumerate children as WEV1 PIDLs.
///
/// Reads the per-instance bound path from `this + 8`. If the path is `None`
/// (desktop folder), enumerates the process CWD. If bound to a subdirectory,
/// enumerates that directory's children.
///
/// # Safety
/// `ppenum` must be a valid writable pointer when non-null.
// Wine ref: dlls/shell32/shfldr.c — EnumObjects allocates IEnumIDList; desktop uses child PIDLs.
unsafe extern "win64" fn sf_enum_objects(
    this: usize,
    _hwnd: usize,
    _grf_flags: u32,
    ppenum: *mut usize,
) -> i32 {
    if ppenum.is_null() {
        return E_POINTER;
    }
    mark_shell_folder_enum_objects_first();
    let data_ptr = unsafe { *(this as *const usize).add(1) };
    let items = if data_ptr == 0 {
        cwd_child_pidls()
    } else {
        let path = unsafe { &*(data_ptr as *const String) };
        dir_child_pidls(path)
    };
    let enum_ptr = get_enum_ptr(items);
    unsafe { *ppenum = enum_ptr };
    S_OK
}

/// Enumerate children of a specific directory path.
fn dir_child_pidls(dir_win_path: &str) -> Vec<usize> {
    let linux_path = dir_win_path.replace('\\', "/");
    let Ok(read) = std::fs::read_dir(&linux_path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in read.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let child_path = format!("{}\\{}", dir_win_path.trim_end_matches('\\'), name);
        let pidl = pidl::pidl_from_path_w(&child_path);
        if !pidl.is_null() {
            out.push(pidl as usize);
        }
        if out.len() >= 64 {
            break;
        }
    }
    out
}

// Wine ref: dlls/shell32/shfldr.c — BindToObject creates a child IShellFolder for a sub-PIDL.
// Phase B: for filesystem directories, creates a new IShellFolder bound to the directory.
unsafe extern "win64" fn sf_bind_to_object(
    _this: usize,
    pidl: *const u8,
    _pbc: usize,
    riid: *const u8,
    ppv: *mut usize,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }
    unsafe { *ppv = 0 };

    // Resolve the PIDL to a filesystem path.
    // Try Weave-native path extraction first, then fall back to PIDL-list resolution.
    let path_str = pidl::weave_item_path(pidl).or_else(|| pidl::pidl_path_from_list(pidl));

    let Some(ref path) = path_str else {
        return E_NOINTERFACE;
    };

    // Check the resolved path is a filesystem directory.
    let linux_path = path.replace('\\', "/");
    if !std::path::Path::new(&linux_path).is_dir() {
        return E_NOINTERFACE;
    }

    // Check riid == IID_IShellFolder if non-null.
    // IID_IShellFolder = {000214E6-0000-0000-C000-000000000046}
    if !riid.is_null() {
        let guid = unsafe { std::slice::from_raw_parts(riid, 16) };
        let iid_shell_folder: [u8; 16] = [
            0xE6, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ];
        if guid != iid_shell_folder {
            return E_NOINTERFACE;
        }
    }

    let bound = new_shell_folder_instance(Some(path.clone()));
    // The caller's `this` is the parent folder. We need its ref count to be
    // independent — the bound folder is a new instance.
    unsafe { *ppv = bound };
    S_OK
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

// Wine ref: dlls/shell32/shfldr.c — CreateViewObject creates a view for the folder.
// For desktop folder, return our minimal IShellView singleton when riid matches.
unsafe extern "win64" fn sf_create_view_object(
    _this: usize,
    _hwnd: usize,
    riid: *const u8,
    ppv: *mut usize,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }
    if !riid.is_null() {
        let guid = unsafe { std::slice::from_raw_parts(riid, 16) };
        if guid == IID_ISHELL_VIEW {
            unsafe { *ppv = get_shell_view_ptr() };
            return S_OK;
        }
    }
    // Unknown IID — return S_FALSE with NULL so caller knows no view is available
    // but does not treat it as a hard error.
    unsafe { *ppv = 0 };
    S_FALSE
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

// Wine ref: dlls/shell32/shfldr.c — GetUIObjectOf returns S_FALSE with NULL ppv when no object matches.
unsafe extern "win64" fn sf_get_ui_object_of(
    _this: usize,
    _hwnd: usize,
    _count: u32,
    _pidls: *const *const u8,
    _riid: *const u8,
    _reserved: *mut u32,
    ppv: *mut usize,
) -> i32 {
    if ppv.is_null() {
        return E_POINTER;
    }
    unsafe { *ppv = 0 };
    S_FALSE
}

unsafe extern "win64" fn sf_get_display_name_of(
    _this: usize,
    pidl: *const u8,
    _flags: u32,
    name: *mut u8,
) -> i32 {
    const STRRET_CSTR: u32 = 2;
    const STRRET_WSTR: u32 = 0;
    if name.is_null() || pidl.is_null() {
        return E_POINTER;
    }
    // Try Weave-native path extraction first.
    if let Some(path) = pidl::weave_item_path(pidl) {
        // Use STRRET_WSTR — allocate a CoTaskMemAlloc copy for maximum compatibility.
        let wide: Vec<u16> = path.encode_utf16().collect();
        let byte_len = (wide.len() + 1) * 2;
        let alloc = unsafe { libc::malloc(byte_len) as *mut u16 };
        if alloc.is_null() {
            return 0x8007_000Eu32 as i32; // E_OUTOFMEMORY
        }
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr(), alloc, wide.len());
            *alloc.add(wide.len()) = 0;
        }
        unsafe {
            let utype_ptr = name as *mut u32;
            *utype_ptr = STRRET_WSTR;
            let p_ole_str_ptr = name.add(8) as *mut usize;
            *p_ole_str_ptr = alloc as usize;
        }
        return S_OK;
    }
    // Fallback: try SHGetPathFromIDListW, write as STRRET_CSTR.
    let mut wide_buf = [0u16; 260];
    let ret = unsafe { crate::pidl::sh_get_path_from_id_list_w(pidl, wide_buf.as_mut_ptr()) };
    if ret == 0 {
        unsafe {
            let utype_ptr = name as *mut u32;
            *utype_ptr = STRRET_CSTR;
            let cstr_ptr = name.add(8);
            *cstr_ptr = 0;
        }
        return S_OK;
    }
    // Convert wide path to ANSI and write as STRRET_CSTR.
    let utf8 = String::from_utf16_lossy(
        unsafe { std::slice::from_raw_parts(wide_buf.as_ptr(), 260) }
            .split(|&c| c == 0)
            .next()
            .unwrap_or(&[]),
    );
    let ansi_bytes = utf8.as_bytes();
    let copy_len = ansi_bytes.len().min(259);
    unsafe {
        let utype_ptr = name as *mut u32;
        *utype_ptr = STRRET_CSTR;
        let cstr_ptr = name.add(8);
        std::ptr::copy_nonoverlapping(ansi_bytes.as_ptr(), cstr_ptr, copy_len);
        *cstr_ptr.add(copy_len) = 0;
    }
    S_OK
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

// ── IShellView minimal stub ──────────────────────────────────────────────────
// Wine ref: dlls/shell32/shview.c — IShellView vtable: 13 slots (3 IUnknown + 10 shell).
// All shell methods return S_OK as no-op stubs.

fn get_shell_view_ptr() -> usize {
    *SHELL_VIEW.get_or_init(|| {
        let vtable: Box<[usize; 13]> = Box::new([
            sv_query_interface as *const () as usize,
            sv_add_ref as *const () as usize,
            sv_release as *const () as usize,
            sv_get_window as *const () as usize,
            sv_create_view_window2 as *const () as usize,
            sv_translate_accelerator_a as *const () as usize,
            sv_translate_accelerator_w as *const () as usize,
            sv_get_current_info as *const () as usize,
            sv_add_property_sheet_page as *const () as usize,
            sv_save_view_state as *const () as usize,
            sv_refresh as *const () as usize,
            sv_select_item as *const () as usize,
            sv_destroy_view_window as *const () as usize,
        ]);
        let vtable_ptr = Box::into_raw(vtable) as usize;
        let obj: Box<usize> = Box::new(vtable_ptr);
        Box::into_raw(obj) as usize
    })
}

unsafe extern "win64" fn sv_query_interface(
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

unsafe extern "win64" fn sv_add_ref(_this: usize) -> u32 {
    let _ = _this;
    1
}

unsafe extern "win64" fn sv_release(_this: usize) -> u32 {
    let _ = _this;
    1
}

// Wine ref: dlls/shell32/shview.c — GetWindow returns the view's parent HWND.
// Stub: returns S_OK with NULL hwnd (safe sentinel, caller may use NULL as "no window").
unsafe extern "win64" fn sv_get_window(_this: usize, hwnd: *mut usize) -> i32 {
    let _ = _this;
    if hwnd.is_null() {
        return E_POINTER;
    }
    unsafe { *hwnd = 0 };
    S_OK
}

// Wine ref: dlls/shell32/shview.c — Store view settings from the CREATEVIEWSTRUCT2.
unsafe extern "win64" fn sv_create_view_window2(_this: usize, _lpcs: usize) -> i32 {
    let _ = _this;
    S_OK
}

// Wine ref: dlls/shell32/shview.c — TranslateAcceleratorA dispatches keyboard shortcuts.
unsafe extern "win64" fn sv_translate_accelerator_a(_this: usize, _lpmsg: *const u8) -> i32 {
    let _ = _this;
    S_FALSE
}

// Wine ref: dlls/shell32/shview.c — TranslateAcceleratorW (wide variant).
unsafe extern "win64" fn sv_translate_accelerator_w(_this: usize, _lpmsg: *const u8) -> i32 {
    let _ = _this;
    S_FALSE
}

// Wine ref: dlls/shell32/shview.c — GetCurrentInfo copies FOLDERSETTINGS to caller.
unsafe extern "win64" fn sv_get_current_info(_this: usize, _lpfs: *mut u8) -> i32 {
    let _ = _this;
    S_OK
}

unsafe extern "win64" fn sv_add_property_sheet_page(
    _this: usize,
    _pfn: usize,
    _lparam: usize,
) -> i32 {
    let _ = _this;
    S_OK
}

unsafe extern "win64" fn sv_save_view_state(_this: usize) -> i32 {
    let _ = _this;
    S_OK
}

unsafe extern "win64" fn sv_refresh(_this: usize) -> i32 {
    let _ = _this;
    S_OK
}

unsafe extern "win64" fn sv_select_item(_this: usize, _pidl: *const u8, _uflags: u32) -> i32 {
    let _ = _this;
    S_OK
}

unsafe extern "win64" fn sv_destroy_view_window(_this: usize) -> i32 {
    let _ = _this;
    S_OK
}
