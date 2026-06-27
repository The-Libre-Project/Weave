//! comctl32.dll stubs for Weave — Common Controls library.
//!
//! Provides load-time import resolution for applications that link against
//! comctl32.dll. Functions are stubs that return plausible values without
//! implementing real window classes or message loops.
//!
//! For Phase 6: PuTTY and 7-Zip need these imports resolved at load time.
//! Real common control behaviour (SysTreeView32, SysListView32 window procs)
//! is deferred to a later phase.
//!
//! # Crate boundary note
//!
//! `weave-comctl32` directly imports `weave-user32`. This violates the general
//! architecture rule that DLL crates should not import each other (shared types
//! belong in `weave-common`). The exception is intentional and mirrors real
//! Windows: comctl32 common-control classes (ImageList, TreeView, ListView,
//! StatusBar) are real Win32 window classes whose creation flows through
//! `CreateWindowExW`. Because window class registration and HWND lifetime are
//! owned by user32, comctl32 must call directly into user32's API surface to
//! create those windows — it cannot go through weave-common, which has no
//! Win32 window-management types.
//!
//! Extraction was considered: moving `CreateWindowExW` to `weave-common` would
//! hollow user32 (all window state lives there) or create a circular dependency
//! (common needing user32 internals). The coupling is accepted as-is. Do not
//! add further DLL→DLL imports without a similar written justification.

#![allow(non_snake_case, dead_code, clippy::missing_safety_doc)]

// ── Initialisation ────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

use weave_user32::api::def_window_proc_w;
use weave_user32::class::{self, ClassEntry};

// ── Common control window class registration ────────────────────────────────

// Correct Windows SDK TB_* constants (TB_FIRST = 0x0400).
const TB_ENABLEBUTTON: u32 = 0x0401; // TB_FIRST + 1
const TB_CHECKBUTTON: u32 = 0x0402; // TB_FIRST + 2
const TB_PRESSBUTTON: u32 = 0x0403; // TB_FIRST + 3
const TB_HIDEBUTTON: u32 = 0x0404; // TB_FIRST + 4
const TB_ISBUTTONENABLED: u32 = 0x0409; // TB_FIRST + 9
const TB_BUTTONCOUNT: u32 = 0x0412; // TB_FIRST + 18
const TB_ADDBUTTONSA: u32 = 0x0414; // TB_FIRST + 20
const TB_DELETEBUTTON: u32 = 0x0416; // TB_FIRST + 22
const TB_GETBUTTONINFOW: u32 = 0x041e;
const TB_SETBUTTONINFOW: u32 = 0x0420;
const TB_GETBUTTONTEXT: u32 = 0x0433;
const TB_GETRECT: u32 = 0x043f;
const TB_AUTOSIZE: u32 = 0x0411;
const TB_SETIMAGELIST: u32 = 0x0430;
const TB_SETEXTENDEDSTYLE: u32 = 0x0454;
const TB_SETBUTTONSIZE: u32 = 0x0440;
const TB_GETMAXSIZE: u32 = 0x041d;
const TB_GETDRAWTEXTFLAGS: u32 = 0x0454;
const TB_SETDRAWTEXTFLAGS: u32 = 0x0455;
const TB_GETSTRING: u32 = 0x0466;
const TB_SETSTRING: u32 = 0x0465;
const TB_ADDBUTTONSW: u32 = 0x0444;

// Correct Windows SDK TCM_* constants (TCM_FIRST = 0x1300).
const TCM_GETIMAGELIST: u32 = 0x1302; // TCM_FIRST + 2
const TCM_SETIMAGELIST: u32 = 0x1303; // TCM_FIRST + 3
const TCM_GETITEMCOUNT: u32 = 0x1304; // TCM_FIRST + 4
const TCM_GETITEMA: u32 = 0x1305; // TCM_FIRST + 5
const TCM_INSERTITEMA: u32 = 0x1307; // TCM_FIRST + 7
const TCM_DELETEALLITEMS: u32 = 0x1309; // TCM_FIRST + 9
const TCM_GETITEMRECT: u32 = 0x130a; // TCM_FIRST + 10
const TCM_GETCURSEL: u32 = 0x130b; // TCM_FIRST + 11
const TCM_SETCURSEL: u32 = 0x130c; // TCM_FIRST + 12
const TCM_ADJUSTRECT: u32 = 0x1328; // TCM_FIRST + 40
const TCM_SETITEMSIZE: u32 = 0x1329; // TCM_FIRST + 41
const TCM_GETROWCOUNT: u32 = 0x132c; // TCM_FIRST + 44
const TCM_GETITEMW: u32 = 0x133c; // TCM_FIRST + 60
const TCM_SETITEMW: u32 = 0x133d; // TCM_FIRST + 61
const TCM_INSERTITEMW: u32 = 0x133e; // TCM_FIRST + 62

// ── SysListView32 constants ──────────────────────────────────────────────────

const LVM_FIRST: u32 = 0x1000;
const LVM_GETIMAGELIST: u32 = LVM_FIRST + 2;
const LVM_SETIMAGELIST: u32 = LVM_FIRST + 3;
const LVM_GETITEMCOUNT: u32 = LVM_FIRST + 4;
const LVM_GETITEMW: u32 = LVM_FIRST + 5;
const LVM_SETITEMW: u32 = LVM_FIRST + 6;
const LVM_INSERTITEMW: u32 = LVM_FIRST + 7;
const LVM_DELETEITEM: u32 = LVM_FIRST + 8;
const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 9;
const LVM_GETCALLBACKMASK: u32 = LVM_FIRST + 10;
const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;
const LVM_ENSUREVISIBLE: u32 = LVM_FIRST + 19;
const LVM_GETCOLUMNW: u32 = LVM_FIRST + 31; // 0x101F
const LVM_SETCOLUMNW: u32 = LVM_FIRST + 32; // 0x1020
const LVM_GETVIEW: u32 = LVM_FIRST + 31; // same value as GETCOLUMNW — disambiguated by usage
const LVM_GETHEADER: u32 = LVM_FIRST + 31; // same value — disambiguated by param
const LVM_GETCOLUMNWIDTH: u32 = LVM_FIRST + 29; // 0x101D
const LVM_SETCOLUMNWIDTH: u32 = LVM_FIRST + 30; // 0x101E
const LVM_INSERTCOLUMNW: u32 = LVM_FIRST + 29; // same value as GETCOLUMNWIDTH
const LVM_GETITEMSTATE: u32 = LVM_FIRST + 44; // 0x102C
const LVM_SETITEMSTATE: u32 = LVM_FIRST + 43; // 0x102B
const LVM_GETITEMTEXTW: u32 = LVM_FIRST + 45; // 0x102D
const LVM_SETITEMTEXTW: u32 = LVM_FIRST + 46; // 0x102E
const LVM_GETTOPINDEX: u32 = LVM_FIRST + 39; // 0x1027
const LVM_GETCOUNTPERPAGE: u32 = LVM_FIRST + 40; // 0x1028
const LVM_GETSELECTEDCOUNT: u32 = LVM_FIRST + 50; // 0x1032
const LVM_REDRAWITEMS: u32 = LVM_FIRST + 21; // 0x1015
const LVM_GETESTIMATEDLISTVIEWSIZE: u32 = 0x1664;

const LVIF_TEXT: u32 = 0x0001;
const LVIF_IMAGE: u32 = 0x0002;
const LVIF_PARAM: u32 = 0x0004;
const LVIF_STATE: u32 = 0x0008;

const LVIS_SELECTED: u32 = 0x0002;
const LVIS_FOCUSED: u32 = 0x0001;

const LVNI_ALL: u32 = 0x0000;
const LVNI_FOCUSED: u32 = 0x0001;
const LVNI_SELECTED: u32 = 0x0002;

const LVSIL_NORMAL: u32 = 0;
const LVSIL_SMALL: u32 = 1;
const LVSIL_STATE: u32 = 2;

const LVSCW_AUTOSIZE: i32 = -1;
const LVSCW_AUTOSIZE_USE_HEADER: i32 = -2;

// ── SysTreeView32 constants ──────────────────────────────────────────────
const TV_FIRST: u32 = 0x1100;
const TVM_GETIMAGELIST: u32 = TV_FIRST + 8; // 0x1108
const TVM_SETIMAGELIST: u32 = TV_FIRST + 9; // 0x1109
const TVM_INSERTITEMW: u32 = TV_FIRST + 50; // 0x1132
const TVM_DELETEITEM: u32 = TV_FIRST + 1; // 0x1101
const TVM_EXPAND: u32 = TV_FIRST + 2; // 0x1102
const TVM_GETITEM: u32 = TV_FIRST + 12; // 0x110C
const TVM_SETITEM: u32 = TV_FIRST + 63; // 0x113F
const TVM_GETNEXTITEM: u32 = TV_FIRST + 10; // 0x110A
const TVM_SELECTITEM: u32 = TV_FIRST + 11; // 0x110B
const TVM_GETITEMCOUNT: u32 = TV_FIRST + 3; // 0x1103
const TVM_GETVISIBLECOUNT: u32 = TV_FIRST + 16; // 0x1110
const TVM_ENSUREVISIBLE: u32 = TV_FIRST + 20; // 0x1114
const TVM_GETCOUNT: u32 = TV_FIRST + 5; // 0x1105
const TVM_DELETEALLITEMS: u32 = TV_FIRST + 1; // same as DELETEITEM — by convention w_param=0 means all

const TVGN_ROOT: usize = 0x0000;
const TVGN_NEXT: usize = 0x0001;
const TVGN_PREVIOUS: usize = 0x0002;
const TVGN_PARENT: usize = 0x0003;
const TVGN_CHILD: usize = 0x0004;
const TVGN_FIRSTVISIBLE: usize = 0x0005;
const TVGN_NEXTVISIBLE: usize = 0x0006;
const TVGN_PREVIOUSVISIBLE: usize = 0x0007;
const TVGN_DROPHILITE: usize = 0x0008;
const TVGN_CARET: usize = 0x0009;
const TVGN_LASTVISIBLE: usize = 0x000A;

const TVIS_SELECTED: u32 = 0x0002;
const TVIS_EXPANDED: u32 = 0x0020;
const TVIS_EXPANDEDONCE: u32 = 0x0040;

const TVE_EXPAND: u32 = 0x0001;
const TVE_COLLAPSE: u32 = 0x0002;
const TVE_TOGGLE: u32 = 0x0003;

const TVIF_TEXT: u32 = 0x0001;
const TVIF_IMAGE: u32 = 0x0002;
const TVIF_PARAM: u32 = 0x0004;
const TVIF_STATE: u32 = 0x0008;
const TVIF_HANDLE: u32 = 0x0010;
const TVIF_SELECTEDIMAGE: u32 = 0x0020;
const TVIF_CHILDREN: u32 = 0x0040;

const I_CHILDRENCALLBACK: i32 = -1;

const TLS_IMAGELIST: u32 = 0;
const TVSIL_NORMAL: u32 = 0;
const TVSIL_STATE: u32 = 2;

const WM_ERASEBKGND: u32 = 0x0014;
const WM_GETTEXTLENGTH: u32 = 0x000E;

#[allow(dead_code)]
struct ToolbarButton {
    id_command: i32,
    i_bitmap: i32,
    fs_state: u8,
    fs_style: u8,
    i_string: isize,
}

struct ToolbarState {
    buttons: Vec<ToolbarButton>,
    button_size: (i32, i32),
    himl: usize,
    extended_style: u32,
}

#[allow(dead_code)]
struct TabItem {
    text_ptr: usize,
    i_image: i32,
    l_param: isize,
}

#[allow(dead_code)]
struct TabState {
    items: Vec<TabItem>,
    cur_sel: i32,
    himl: usize,
}

#[allow(dead_code)]
struct ListViewColumn {
    fmt: i32,
    cx: i32,
    text: Option<String>,
    i_sub_item: i32,
}

#[allow(dead_code)]
struct ListViewItem {
    i_item: i32,
    i_sub_item: i32,
    state: u32,
    text: Option<String>,
    i_image: i32,
    l_param: isize,
}

#[allow(dead_code)]
struct ListViewState {
    columns: Vec<ListViewColumn>,
    items: Vec<ListViewItem>,
    image_list_small: usize,
    image_list_large: usize,
    image_list_state: usize,
}

#[allow(dead_code)]
struct TreeViewState {
    items: Vec<TreeViewItem>,
}

#[allow(dead_code)]
struct TreeViewItem {
    mask: u32,
    h_item: usize,
    state: u32,
    state_mask: u32,
    psz_text: Option<String>,
    i_image: i32,
    i_selected_image: i32,
    c_children: i32,
    l_param: isize,
    h_parent: usize,
}

#[allow(dead_code)]
enum ComctlState {
    Toolbar(ToolbarState),
    Tab(TabState),
    ListView(ListViewState),
    TreeView(TreeViewState),
}

static COMCTL_STATE: OnceLock<Mutex<HashMap<usize, ComctlState>>> = OnceLock::new();

fn get_state() -> &'static Mutex<HashMap<usize, ComctlState>> {
    COMCTL_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

extern "win64" fn toolbar_wnd_proc(hwnd: usize, msg: u32, w_param: usize, l_param: isize) -> isize {
    match msg {
        WM_NCDESTROY => {
            if let Ok(mut map) = get_state().lock() {
                map.remove(&hwnd);
            }
            def_window_proc_w(hwnd, msg, w_param, l_param)
        }
        WM_GETFONT => 0,
        WM_GETTEXT => 0,
        // Button state modifiers — no-op stubs (return TRUE to prevent DefWindowProc
        // from returning -1 which guests may interpret as error).
        TB_ENABLEBUTTON | TB_CHECKBUTTON | TB_PRESSBUTTON | TB_HIDEBUTTON => 1,
        TB_ISBUTTONENABLED => 1,
        TB_ADDBUTTONSA | TB_ADDBUTTONSW => {
            if l_param == 0 || w_param == 0 {
                return 0;
            }
            let count = w_param;
            let mut map = get_state().lock().unwrap();
            let btn = map
                .entry(hwnd)
                .or_insert(ComctlState::Toolbar(ToolbarState {
                    buttons: Vec::new(),
                    button_size: (23, 22),
                    himl: 0,
                    extended_style: 0,
                }));
            if let ComctlState::Toolbar(ref mut tb) = btn {
                for i in 0..count {
                    let off = i * 24;
                    let base = l_param as usize;
                    let id_cmd =
                        unsafe { std::ptr::read_unaligned((base + off + 4) as *const i32) };
                    let fs_state =
                        unsafe { std::ptr::read_unaligned((base + off + 8) as *const u8) };
                    let fs_style =
                        unsafe { std::ptr::read_unaligned((base + off + 9) as *const u8) };
                    let i_str =
                        unsafe { std::ptr::read_unaligned((base + off + 16) as *const isize) };
                    let i_bmp = unsafe { std::ptr::read_unaligned((base + off) as *const i32) };
                    tb.buttons.push(ToolbarButton {
                        id_command: id_cmd,
                        i_bitmap: i_bmp,
                        fs_state,
                        fs_style,
                        i_string: i_str,
                    });
                }
            }
            1
        }
        TB_DELETEBUTTON => {
            let idx = w_param as i32;
            if let Ok(mut map) = get_state().lock() {
                if let Some(ComctlState::Toolbar(ref mut tb)) = map.get_mut(&hwnd) {
                    if idx >= 0 && (idx as usize) < tb.buttons.len() {
                        tb.buttons.remove(idx as usize);
                        return 1;
                    }
                }
            }
            0
        }
        TB_BUTTONCOUNT => {
            if let Ok(map) = get_state().lock() {
                if let Some(ComctlState::Toolbar(ref tb)) = map.get(&hwnd) {
                    return tb.buttons.len() as isize;
                }
            }
            0
        }
        TB_GETBUTTONINFOW => {
            // Returns button info at lParam (TBBUTTONINFOW). Stub: clear and return FALSE.
            // lParam points to a TBBUTTONINFOW that we fill with zeroes.
            if l_param != 0 {
                unsafe { std::ptr::write_bytes(l_param as *mut u8, 0, 64) };
            }
            0 // FALSE
        }
        TB_SETBUTTONINFOW => {
            -1 // FALSE
        }
        TB_GETBUTTONTEXT => {
            -1 // FALSE — no text available
        }
        TB_GETRECT => {
            // Return a default button rect. lParam points to RECT.
            if l_param != 0 {
                unsafe {
                    std::ptr::write_unaligned(l_param as *mut i32, 0);
                    std::ptr::write_unaligned((l_param + 4) as *mut i32, 0);
                    std::ptr::write_unaligned((l_param + 8) as *mut i32, 23);
                    std::ptr::write_unaligned((l_param + 12) as *mut i32, 22);
                }
            }
            1 // TRUE
        }
        TB_AUTOSIZE => 0,
        TB_SETIMAGELIST => {
            if let Ok(mut map) = get_state().lock() {
                if let Some(ComctlState::Toolbar(ref mut tb)) = map.get_mut(&hwnd) {
                    tb.himl = w_param;
                }
            }
            0
        }
        TB_SETEXTENDEDSTYLE => {
            if let Ok(mut map) = get_state().lock() {
                if let Some(ComctlState::Toolbar(ref mut tb)) = map.get_mut(&hwnd) {
                    tb.extended_style = w_param as u32;
                }
            }
            0
        }
        TB_SETBUTTONSIZE => {
            if let Ok(mut map) = get_state().lock() {
                if let Some(ComctlState::Toolbar(ref mut tb)) = map.get_mut(&hwnd) {
                    tb.button_size = (w_param as i32, l_param as i32);
                }
            }
            0
        }
        TB_GETMAXSIZE => {
            if l_param != 0 {
                let cnt = {
                    if let Ok(map) = get_state().lock() {
                        if let Some(ComctlState::Toolbar(ref tb)) = map.get(&hwnd) {
                            tb.buttons.len().max(1)
                        } else {
                            1
                        }
                    } else {
                        1
                    }
                };
                unsafe {
                    std::ptr::write_unaligned(l_param as *mut i32, 23 * cnt as i32);
                    std::ptr::write_unaligned((l_param + 4) as *mut i32, 22);
                }
            }
            0
        }
        TB_SETDRAWTEXTFLAGS => 0,
        TB_GETSTRING => 0,
        TB_SETSTRING => 0,
        _ => def_window_proc_w(hwnd, msg, w_param, l_param),
    }
}

extern "win64" fn tab_wnd_proc(hwnd: usize, msg: u32, w_param: usize, l_param: isize) -> isize {
    match msg {
        WM_NCDESTROY => {
            if let Ok(mut map) = get_state().lock() {
                map.remove(&hwnd);
            }
            def_window_proc_w(hwnd, msg, w_param, l_param)
        }
        WM_GETFONT => 0,
        WM_GETTEXT => 0,
        TCM_GETITEMCOUNT => {
            if let Ok(map) = get_state().lock() {
                if let Some(ComctlState::Tab(ref tab)) = map.get(&hwnd) {
                    return tab.items.len() as isize;
                }
            }
            0
        }
        TCM_GETCURSEL => {
            if let Ok(map) = get_state().lock() {
                if let Some(ComctlState::Tab(ref tab)) = map.get(&hwnd) {
                    if tab.items.is_empty() {
                        return 0;
                    }
                    return tab.cur_sel as isize;
                }
            }
            0
        }
        TCM_SETCURSEL => {
            if let Ok(mut map) = get_state().lock() {
                if let Some(ComctlState::Tab(ref mut tab)) = map.get_mut(&hwnd) {
                    tab.cur_sel = w_param as i32;
                }
            }
            0
        }
        TCM_GETIMAGELIST => {
            if let Ok(map) = get_state().lock() {
                if let Some(ComctlState::Tab(ref tab)) = map.get(&hwnd) {
                    return tab.himl as isize;
                }
            }
            0
        }
        TCM_ADJUSTRECT => {
            // Adjust the display rectangle for tab presence. No-op stub.
            1 // TRUE
        }
        TCM_GETROWCOUNT => 1,
        TCM_GETITEMRECT => {
            // Return a default tab item rect at lParam (RECT*). Stub: zero rect.
            if l_param != 0 {
                unsafe { std::ptr::write_bytes(l_param as *mut u8, 0, 16) };
            }
            1 // TRUE
        }
        TCM_GETITEMW => {
            // Fill TCITEMW struct at lParam with stored tab item data.
            // Wine ref: dlls/comctl32/tab.c::TAB_GetItemT — returns FALSE (0)
            // when iItem >= uNumItem (empty control or out-of-range index).
            // NPP reads TCITEMW.lParam even on TRUE and crashes with a corrupted
            // pointer from uninitialized bytes (rva 0xe3caf). Return FALSE so NPP
            // skips the struct dereference. Zero the struct regardless for safety.
            if l_param != 0 {
                let idx = w_param;
                if let Ok(map) = get_state().lock() {
                    if let Some(ComctlState::Tab(ref tab)) = map.get(&hwnd) {
                        if idx < tab.items.len() {
                            let item = &tab.items[idx];
                            unsafe {
                                std::ptr::write_unaligned(l_param as *mut u32, !0u32); // mask
                                std::ptr::write_unaligned(
                                    (l_param + 12) as *mut usize,
                                    item.text_ptr,
                                );
                                std::ptr::write_unaligned((l_param + 24) as *mut i32, item.i_image);
                                std::ptr::write_unaligned(
                                    (l_param + 28) as *mut isize,
                                    item.l_param,
                                );
                            }
                            return 1;
                        }
                    }
                }
                unsafe { std::ptr::write_bytes(l_param as *mut u8, 0, 36) };
            }
            0 // FALSE — item not found
        }
        TCM_SETITEMW => {
            // Update Vec<TabItem> from TCITEMW at lParam.
            if l_param != 0 {
                let idx = w_param;
                let psz_text = unsafe { std::ptr::read_unaligned((l_param + 12) as *const usize) };
                let i_image = unsafe { std::ptr::read_unaligned((l_param + 24) as *const i32) };
                let item_lparam =
                    unsafe { std::ptr::read_unaligned((l_param + 28) as *const isize) };
                if let Ok(mut map) = get_state().lock() {
                    if let Some(ComctlState::Tab(ref mut tab)) = map.get_mut(&hwnd) {
                        if idx < tab.items.len() {
                            tab.items[idx].text_ptr = psz_text;
                            tab.items[idx].i_image = i_image;
                            tab.items[idx].l_param = item_lparam;
                            return 1;
                        }
                    }
                }
            }
            1 // TRUE
        }
        TCM_DELETEALLITEMS => {
            if let Ok(mut map) = get_state().lock() {
                if let Some(ComctlState::Tab(ref mut tab)) = map.get_mut(&hwnd) {
                    tab.items.clear();
                    tab.cur_sel = -1;
                }
            }
            1 // TRUE
        }
        TCM_INSERTITEMW => {
            if l_param == 0 {
                return 0;
            }
            unsafe {
                let _mask = std::ptr::read_unaligned(l_param as *const u32);
                let psz_text = std::ptr::read_unaligned((l_param + 12) as *const usize);
                let _cch_max = std::ptr::read_unaligned((l_param + 20) as *const i32);
                let i_image = std::ptr::read_unaligned((l_param + 24) as *const i32);
                let item_lparam = std::ptr::read_unaligned((l_param + 28) as *const isize);
                let mut map = get_state().lock().unwrap();
                let tab = map.entry(hwnd).or_insert(ComctlState::Tab(TabState {
                    items: Vec::new(),
                    cur_sel: -1,
                    himl: 0,
                }));
                if let ComctlState::Tab(ref mut tab) = tab {
                    let idx = tab.items.len();
                    tab.items.push(TabItem {
                        text_ptr: psz_text,
                        i_image,
                        l_param: item_lparam,
                    });
                    return idx as isize;
                }
            }
            0
        }
        _ => def_window_proc_w(hwnd, msg, w_param, l_param),
    }
}

// ── SysListView32 helpers ─────────────────────────────────────────────────────

/// Read the text field from an LVITEMW or LVCOLUMNW at the given guest pointer.
/// Returns the copied string if LVIF_TEXT is set and pszText is non-null.
unsafe fn read_item_text(l_param: isize, text_offset: usize, mask_offset: usize) -> Option<String> {
    let base = l_param as usize;
    if base == 0 {
        return None;
    }
    let mask = std::ptr::read_unaligned((base + mask_offset) as *const u32);
    if mask & LVIF_TEXT == 0 {
        return None;
    }
    let psz_text = std::ptr::read_unaligned((base + text_offset) as *const usize);
    if psz_text == 0 {
        return None;
    }
    let cch_max = std::ptr::read_unaligned((base + text_offset + 8) as *const i32);
    if cch_max <= 0 {
        return None;
    }
    let mut chars = Vec::with_capacity(cch_max as usize);
    for i in 0..cch_max as usize {
        let c = std::ptr::read_unaligned((psz_text + i * 2) as *const u16);
        if c == 0 {
            break;
        }
        chars.push(c);
    }
    Some(String::from_utf16_lossy(&chars))
}

/// Write text from a stored string into the guest's LVITEMW buffer.
unsafe fn write_item_text(psz_text: usize, cch_max: i32, text: &str) -> i32 {
    if psz_text == 0 || cch_max <= 0 {
        return 0;
    }
    let mut written = 0;
    for (i, ch) in text.encode_utf16().enumerate() {
        if i + 1 >= cch_max as usize {
            break;
        }
        std::ptr::write_unaligned((psz_text + i * 2) as *mut u16, ch);
        written = i + 1;
    }
    std::ptr::write_unaligned((psz_text + written * 2) as *mut u16, 0u16);
    written as i32
}

// ── SysListView32 WndProc ────────────────────────────────────────────────────

/// WndProc for the SysListView32 common control.
///
/// Maintains a per-HWND ListViewState with columns, items, and image lists.
/// Handles all standard LVM_* messages and falls through to def_window_proc_w.
extern "win64" fn listview_wnd_proc(
    hwnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    match msg {
        WM_NCDESTROY => {
            if let Ok(mut map) = get_state().lock() {
                map.remove(&hwnd);
            }
            def_window_proc_w(hwnd, msg, w_param, l_param)
        }
        WM_ERASEBKGND => 1,
        WM_GETFONT => 0,
        WM_GETTEXT => 0,
        WM_GETTEXTLENGTH => 0,
        LVM_GETIMAGELIST => {
            let mut map = get_state().lock().unwrap();
            let lv = map
                .entry(hwnd)
                .or_insert(ComctlState::ListView(ListViewState {
                    columns: Vec::new(),
                    items: Vec::new(),
                    image_list_small: 0,
                    image_list_large: 0,
                    image_list_state: 0,
                }));
            if let ComctlState::ListView(ref state) = lv {
                match w_param as u32 {
                    LVSIL_NORMAL => state.image_list_large as isize,
                    LVSIL_SMALL => state.image_list_small as isize,
                    LVSIL_STATE => state.image_list_state as isize,
                    _ => 0,
                }
            } else {
                0
            }
        }
        LVM_SETIMAGELIST => {
            let mut map = get_state().lock().unwrap();
            let lv = map
                .entry(hwnd)
                .or_insert(ComctlState::ListView(ListViewState {
                    columns: Vec::new(),
                    items: Vec::new(),
                    image_list_small: 0,
                    image_list_large: 0,
                    image_list_state: 0,
                }));
            if let ComctlState::ListView(ref mut state) = lv {
                let prev = match w_param as u32 {
                    LVSIL_NORMAL => state.image_list_large,
                    LVSIL_SMALL => state.image_list_small,
                    LVSIL_STATE => state.image_list_state,
                    _ => 0,
                };
                match w_param as u32 {
                    LVSIL_NORMAL => state.image_list_large = l_param as usize,
                    LVSIL_SMALL => state.image_list_small = l_param as usize,
                    LVSIL_STATE => state.image_list_state = l_param as usize,
                    _ => {}
                }
                prev as isize
            } else {
                0
            }
        }
        LVM_GETITEMCOUNT => {
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref state)) = map.get(&hwnd) {
                state.items.len() as isize
            } else {
                0
            }
        }
        LVM_GETITEMW => {
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let i_item: i32 = unsafe { std::ptr::read_unaligned((base + 4) as *const i32) };
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref state)) = map.get(&hwnd) {
                if i_item < 0 || i_item as usize >= state.items.len() {
                    return 0;
                }
                let item = &state.items[i_item as usize];
                let mask: u32 = unsafe { std::ptr::read_unaligned(base as *const u32) };
                if mask & LVIF_TEXT != 0 {
                    let psz_text: usize =
                        unsafe { std::ptr::read_unaligned((base + 24) as *const usize) };
                    let cch_max: i32 =
                        unsafe { std::ptr::read_unaligned((base + 32) as *const i32) };
                    if let Some(ref text) = item.text {
                        unsafe {
                            write_item_text(psz_text, cch_max, text);
                        }
                    }
                }
                if mask & LVIF_IMAGE != 0 {
                    unsafe {
                        std::ptr::write_unaligned((base + 36) as *mut i32, item.i_image);
                    }
                }
                if mask & LVIF_PARAM != 0 {
                    unsafe {
                        std::ptr::write_unaligned((base + 40) as *mut isize, item.l_param);
                    }
                }
                if mask & LVIF_STATE != 0 {
                    unsafe {
                        std::ptr::write_unaligned((base + 12) as *mut u32, item.state);
                    }
                }
                1
            } else {
                0
            }
        }
        LVM_SETITEMW => {
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let i_item: i32 = unsafe { std::ptr::read_unaligned((base + 4) as *const i32) };
            let mut map = get_state().lock().unwrap();
            let lv = map
                .entry(hwnd)
                .or_insert(ComctlState::ListView(ListViewState {
                    columns: Vec::new(),
                    items: Vec::new(),
                    image_list_small: 0,
                    image_list_large: 0,
                    image_list_state: 0,
                }));
            if let ComctlState::ListView(ref mut state) = lv {
                if i_item >= 0 && (i_item as usize) < state.items.len() {
                    let idx = i_item as usize;
                    let text = unsafe { read_item_text(l_param, 24, 0) };
                    if let Some(t) = text {
                        state.items[idx].text = Some(t);
                    }
                }
                1
            } else {
                0
            }
        }
        LVM_INSERTITEMW => {
            let base = l_param as usize;
            if base == 0 {
                return -1;
            }
            let i_item: i32 = unsafe { std::ptr::read_unaligned((base + 4) as *const i32) };
            let text = unsafe { read_item_text(l_param, 24, 0) };
            let i_image: i32 = unsafe { std::ptr::read_unaligned((base + 36) as *const i32) };
            let l_param_val: isize =
                unsafe { std::ptr::read_unaligned((base + 40) as *const isize) };
            let state_val: u32 = unsafe { std::ptr::read_unaligned((base + 12) as *const u32) };
            let item = ListViewItem {
                i_item,
                i_sub_item: 0,
                state: state_val,
                text,
                i_image,
                l_param: l_param_val,
            };
            let mut map = get_state().lock().unwrap();
            let lv = map
                .entry(hwnd)
                .or_insert(ComctlState::ListView(ListViewState {
                    columns: Vec::new(),
                    items: Vec::new(),
                    image_list_small: 0,
                    image_list_large: 0,
                    image_list_state: 0,
                }));
            if let ComctlState::ListView(ref mut state) = lv {
                let idx = if i_item < 0 || i_item as usize >= state.items.len() {
                    state.items.push(item);
                    state.items.len() - 1
                } else {
                    state.items.insert(i_item as usize, item);
                    i_item as usize
                };
                idx as isize
            } else {
                -1
            }
        }
        LVM_DELETEITEM => {
            let mut map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref mut state)) = map.get_mut(&hwnd) {
                if w_param < state.items.len() {
                    state.items.remove(w_param);
                    1
                } else {
                    0
                }
            } else {
                0
            }
        }
        LVM_DELETEALLITEMS => {
            let mut map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref mut state)) = map.get_mut(&hwnd) {
                state.items.clear();
                1
            } else {
                0
            }
        }
        LVM_GETCALLBACKMASK => 0,
        LVM_GETNEXTITEM => {
            let start = w_param as i32;
            let flags = l_param as u32;
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref state)) = map.get(&hwnd) {
                if state.items.is_empty() {
                    return -1;
                }
                let begin = if start < 0 { 0 } else { (start + 1) as usize };
                if flags & LVNI_SELECTED != 0 {
                    for i in begin..state.items.len() {
                        if state.items[i].state & LVIS_SELECTED != 0 {
                            return i as isize;
                        }
                    }
                } else if flags & LVNI_FOCUSED != 0 {
                    for i in begin..state.items.len() {
                        if state.items[i].state & LVIS_FOCUSED != 0 {
                            return i as isize;
                        }
                    }
                } else {
                    if begin < state.items.len() {
                        return begin as isize;
                    }
                }
                -1
            } else {
                -1
            }
        }
        LVM_GETITEMTEXTW => {
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let i_item: i32 = unsafe { std::ptr::read_unaligned((base + 4) as *const i32) };
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref state)) = map.get(&hwnd) {
                if i_item >= 0 && (i_item as usize) < state.items.len() {
                    let psz_text: usize =
                        unsafe { std::ptr::read_unaligned((base + 24) as *const usize) };
                    let cch_max: i32 =
                        unsafe { std::ptr::read_unaligned((base + 32) as *const i32) };
                    if let Some(ref text) = state.items[i_item as usize].text {
                        unsafe { write_item_text(psz_text, cch_max, text) as isize }
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            }
        }
        LVM_SETITEMTEXTW => {
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let i_item: i32 = unsafe { std::ptr::read_unaligned((base + 4) as *const i32) };
            let mut map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref mut state)) = map.get_mut(&hwnd) {
                if i_item >= 0 && (i_item as usize) < state.items.len() {
                    let text = unsafe { read_item_text(l_param, 24, 0) };
                    state.items[i_item as usize].text = text;
                }
                1
            } else {
                0
            }
        }
        LVM_GETITEMSTATE => {
            let i_item = w_param as i32;
            let mask = l_param as u32;
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref state)) = map.get(&hwnd) {
                if i_item >= 0 && (i_item as usize) < state.items.len() {
                    (state.items[i_item as usize].state & mask) as isize
                } else {
                    0
                }
            } else {
                0
            }
        }
        LVM_SETITEMSTATE => {
            let i_item = w_param as i32;
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let mut map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref mut state)) = map.get_mut(&hwnd) {
                if i_item >= 0 && (i_item as usize) < state.items.len() {
                    let new_state: u32 =
                        unsafe { std::ptr::read_unaligned((base + 12) as *const u32) };
                    let state_mask: u32 =
                        unsafe { std::ptr::read_unaligned((base + 16) as *const u32) };
                    let current = state.items[i_item as usize].state;
                    state.items[i_item as usize].state =
                        (current & !state_mask) | (new_state & state_mask);
                }
                1
            } else {
                0
            }
        }
        LVM_GETSELECTEDCOUNT => {
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref state)) = map.get(&hwnd) {
                let count = state
                    .items
                    .iter()
                    .filter(|item| item.state & LVIS_SELECTED != 0)
                    .count();
                count as isize
            } else {
                0
            }
        }
        LVM_GETCOLUMNW => {
            // LVM_GETCOLUMNW (0x101F) shares its message value with LVM_GETVIEW and LVM_GETHEADER.
            // Heuristic: if w_param is small (< 20), it's a column operation; otherwise view/header.
            if w_param >= 20 {
                // LVM_GETVIEW or LVM_GETHEADER
                return if w_param < 100 {
                    0 /* LVM_GETHEADER */
                } else {
                    3 /* LVM_GETVIEW */
                };
            }
            let col_idx = w_param;
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref state)) = map.get(&hwnd) {
                if col_idx < state.columns.len() {
                    let col = &state.columns[col_idx];
                    let mask: u32 = unsafe { std::ptr::read_unaligned(base as *const u32) };
                    if mask & 0x0001 != 0 {
                        // LVCF_FMT
                        unsafe {
                            std::ptr::write_unaligned((base + 4) as *mut i32, col.fmt);
                        }
                    }
                    if mask & 0x0002 != 0 {
                        // LVCF_WIDTH
                        unsafe {
                            std::ptr::write_unaligned((base + 8) as *mut i32, col.cx);
                        }
                    }
                    if mask & 0x0004 != 0 {
                        // LVCF_TEXT
                        let psz_text: usize =
                            unsafe { std::ptr::read_unaligned((base + 16) as *const usize) };
                        let cch_max: i32 =
                            unsafe { std::ptr::read_unaligned((base + 24) as *const i32) };
                        if let Some(ref text) = col.text {
                            unsafe {
                                write_item_text(psz_text, cch_max, text);
                            }
                        }
                    }
                    if mask & 0x0008 != 0 {
                        // LVCF_SUBITEM
                        unsafe {
                            std::ptr::write_unaligned((base + 28) as *mut i32, col.i_sub_item);
                        }
                    }
                    1
                } else {
                    0
                }
            } else {
                0
            }
        }
        LVM_SETCOLUMNW => {
            let col_idx = w_param;
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let mut map = get_state().lock().unwrap();
            let lv = map
                .entry(hwnd)
                .or_insert(ComctlState::ListView(ListViewState {
                    columns: Vec::new(),
                    items: Vec::new(),
                    image_list_small: 0,
                    image_list_large: 0,
                    image_list_state: 0,
                }));
            if let ComctlState::ListView(ref mut state) = lv {
                let mask: u32 = unsafe { std::ptr::read_unaligned(base as *const u32) };
                while state.columns.len() <= col_idx {
                    state.columns.push(ListViewColumn {
                        fmt: 0,
                        cx: 100,
                        text: None,
                        i_sub_item: col_idx as i32,
                    });
                }
                let col = &mut state.columns[col_idx];
                if mask & 0x0001 != 0 {
                    col.fmt = unsafe { std::ptr::read_unaligned((base + 4) as *const i32) };
                }
                if mask & 0x0002 != 0 {
                    col.cx = unsafe { std::ptr::read_unaligned((base + 8) as *const i32) };
                }
                if mask & 0x0004 != 0 {
                    let text = unsafe { read_item_text(l_param, 16, 0) };
                    col.text = text;
                }
                if mask & 0x0008 != 0 {
                    col.i_sub_item = unsafe { std::ptr::read_unaligned((base + 28) as *const i32) };
                }
                1
            } else {
                0
            }
        }
        LVM_INSERTCOLUMNW => {
            // LVM_INSERTCOLUMNW (0x101D) shares its value with LVM_GETCOLUMNWIDTH.
            // Heuristic: if l_param > 1024, treat as struct ptr (INSERTCOLUMNW).
            // Otherwise treat as width result (GETCOLUMNWIDTH).
            if (l_param as usize) > 1024 {
                // LVM_INSERTCOLUMNW
                let col_idx = w_param;
                let base = l_param as usize;
                if base == 0 {
                    return -1;
                }
                let mut map = get_state().lock().unwrap();
                let lv = map
                    .entry(hwnd)
                    .or_insert(ComctlState::ListView(ListViewState {
                        columns: Vec::new(),
                        items: Vec::new(),
                        image_list_small: 0,
                        image_list_large: 0,
                        image_list_state: 0,
                    }));
                if let ComctlState::ListView(ref mut state) = lv {
                    while state.columns.len() <= col_idx {
                        state.columns.push(ListViewColumn {
                            fmt: 0,
                            cx: 100,
                            text: None,
                            i_sub_item: state.columns.len() as i32,
                        });
                    }
                    let mask: u32 = unsafe { std::ptr::read_unaligned(base as *const u32) };
                    if mask != 0 {
                        let col = &mut state.columns[col_idx];
                        if mask & 0x0001 != 0 {
                            col.fmt = unsafe { std::ptr::read_unaligned((base + 4) as *const i32) };
                        }
                        if mask & 0x0002 != 0 {
                            col.cx = unsafe { std::ptr::read_unaligned((base + 8) as *const i32) };
                        }
                        if mask & 0x0004 != 0 {
                            let text = unsafe { read_item_text(l_param, 16, 0) };
                            col.text = text;
                        }
                    }
                    col_idx as isize
                } else {
                    -1
                }
            } else {
                // LVM_GETCOLUMNWIDTH
                let col_idx = w_param;
                let map = get_state().lock().unwrap();
                if let Some(ComctlState::ListView(ref state)) = map.get(&hwnd) {
                    if col_idx < state.columns.len() {
                        state.columns[col_idx].cx as isize
                    } else {
                        100
                    }
                } else {
                    100
                }
            }
        }
        LVM_SETCOLUMNWIDTH => {
            let col_idx = w_param;
            let mut map = get_state().lock().unwrap();
            if let Some(ComctlState::ListView(ref mut state)) = map.get_mut(&hwnd) {
                let new_width = if l_param as i32 == LVSCW_AUTOSIZE
                    || l_param as i32 == LVSCW_AUTOSIZE_USE_HEADER
                {
                    120
                } else {
                    l_param as i32
                };
                while state.columns.len() <= col_idx {
                    state.columns.push(ListViewColumn {
                        fmt: 0,
                        cx: 120,
                        text: None,
                        i_sub_item: state.columns.len() as i32,
                    });
                }
                state.columns[col_idx].cx = new_width;
                1
            } else {
                0
            }
        }
        LVM_ENSUREVISIBLE => 1,
        LVM_REDRAWITEMS => 1,
        LVM_GETTOPINDEX => 0,
        LVM_GETCOUNTPERPAGE => 30,
        _ => def_window_proc_w(hwnd, msg, w_param, l_param),
    }
}

// ── SysTreeView32 WndProc ─────────────────────────────────────────────────

/// WndProc for the SysTreeView32 common control.
///
/// Maintains a per-HWND TreeViewState with items.
/// Handles standard TVM_* messages and falls through to def_window_proc_w.
extern "win64" fn treeview_wnd_proc(
    hwnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    match msg {
        WM_NCDESTROY => {
            if let Ok(mut map) = get_state().lock() {
                map.remove(&hwnd);
            }
            def_window_proc_w(hwnd, msg, w_param, l_param)
        }
        WM_ERASEBKGND => 1,
        WM_GETFONT => 0,
        WM_GETTEXT => 0,
        WM_GETTEXTLENGTH => 0,
        TVM_GETIMAGELIST => 0, // No image list
        TVM_SETIMAGELIST => 0,
        TVM_GETCOUNT | TVM_GETITEMCOUNT => {
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::TreeView(ref state)) = map.get(&hwnd) {
                state.items.len() as isize
            } else {
                0
            }
        }
        TVM_GETVISIBLECOUNT => 10,
        TVM_INSERTITEMW => {
            // l_param points to TVINSERTSTRUCTW
            // TVINSERTSTRUCTW layout (x64):
            //   hParent(usize)=0, hInsertAfter(usize)=8, item(TVITEMW)=16
            // TVITEMW layout (x64):
            //   mask(u32)=0, hItem(usize)=8, state(u32)=16, stateMask(u32)=20,
            //   pszText(*mut u16)=24, cchTextMax(i32)=32,
            //   iImage(i32)=36, iSelectedImage(i32)=40,
            //   cChildren(i32)=44, lParam(isize)=48
            let base = l_param as usize;
            if base == 0 {
                return -1;
            }
            let h_parent: usize = unsafe { std::ptr::read_unaligned(base as *const usize) };
            // Read text from the inserted item
            let item_base = base + 16;
            let mask: u32 = unsafe { std::ptr::read_unaligned(item_base as *const u32) };
            let text = if mask & TVIF_TEXT != 0 {
                let psz: usize =
                    unsafe { std::ptr::read_unaligned((item_base + 24) as *const usize) };
                if psz != 0 {
                    read_treeview_text(psz, item_base + 32)
                } else {
                    None
                }
            } else {
                None
            };
            let i_image: i32 = unsafe { std::ptr::read_unaligned((item_base + 36) as *const i32) };
            let i_sel: i32 = unsafe { std::ptr::read_unaligned((item_base + 40) as *const i32) };
            let c_children: i32 =
                unsafe { std::ptr::read_unaligned((item_base + 44) as *const i32) };
            let l_param_val: isize =
                unsafe { std::ptr::read_unaligned((item_base + 48) as *const isize) };
            let state: u32 = unsafe { std::ptr::read_unaligned((item_base + 16) as *const u32) };

            let item = TreeViewItem {
                mask,
                h_item: 0,
                state,
                state_mask: 0,
                psz_text: text,
                i_image,
                i_selected_image: i_sel,
                c_children,
                l_param: l_param_val,
                h_parent,
            };
            let mut map = get_state().lock().unwrap();
            let tv = map
                .entry(hwnd)
                .or_insert(ComctlState::TreeView(TreeViewState { items: Vec::new() }));
            if let ComctlState::TreeView(ref mut state) = tv {
                let new_id = state.items.len();
                let item = TreeViewItem {
                    h_item: new_id + 1,
                    ..item
                };
                state.items.push(item);
                (new_id + 1) as isize // HTREEITEM is 1-based non-zero handle
            } else {
                -1
            }
        }
        TVM_DELETEITEM => {
            // TVM_DELETEITEM (0x1101) shares its value with TVM_DELETEALLITEMS.
            // w_param=0 → delete all items (TVI_ROOT). Otherwise delete specific item.
            let mut map = get_state().lock().unwrap();
            if let Some(ComctlState::TreeView(ref mut state)) = map.get_mut(&hwnd) {
                if w_param == 0 {
                    state.items.clear();
                } else {
                    state.items.retain(|item| item.h_item != w_param);
                }
                1
            } else {
                0
            }
        }
        TVM_EXPAND => {
            // TVE_EXPAND, TVE_COLLAPSE, TVE_TOGGLE — no-op, return TRUE
            1
        }
        TVM_GETITEM => {
            // Fill TVITEMW at l_param from stored state
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let h_item: usize = unsafe { std::ptr::read_unaligned((base + 8) as *const usize) };
            let mask: u32 = unsafe { std::ptr::read_unaligned(base as *const u32) };
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::TreeView(ref state)) = map.get(&hwnd) {
                if let Some(item) = state.items.iter().find(|it| it.h_item == h_item) {
                    if mask & TVIF_TEXT != 0 {
                        let psz: usize =
                            unsafe { std::ptr::read_unaligned((base + 24) as *const usize) };
                        let cch: i32 =
                            unsafe { std::ptr::read_unaligned((base + 32) as *const i32) };
                        if let Some(ref t) = item.psz_text {
                            write_treeview_text(psz, cch, t);
                        }
                    }
                    if mask & TVIF_IMAGE != 0 {
                        unsafe {
                            std::ptr::write_unaligned((base + 36) as *mut i32, item.i_image);
                        }
                    }
                    if mask & TVIF_SELECTEDIMAGE != 0 {
                        unsafe {
                            std::ptr::write_unaligned(
                                (base + 40) as *mut i32,
                                item.i_selected_image,
                            );
                        }
                    }
                    if mask & TVIF_PARAM != 0 {
                        unsafe {
                            std::ptr::write_unaligned((base + 48) as *mut isize, item.l_param);
                        }
                    }
                    if mask & TVIF_STATE != 0 {
                        unsafe {
                            std::ptr::write_unaligned((base + 16) as *mut u32, item.state);
                        }
                    }
                    if mask & TVIF_CHILDREN != 0 {
                        unsafe {
                            std::ptr::write_unaligned((base + 44) as *mut i32, item.c_children);
                        }
                    }
                    return 1;
                }
            }
            0
        }
        TVM_SETITEM => {
            let base = l_param as usize;
            if base == 0 {
                return 0;
            }
            let h_item: usize = unsafe { std::ptr::read_unaligned((base + 8) as *const usize) };
            let mut map = get_state().lock().unwrap();
            if let Some(ComctlState::TreeView(ref mut state)) = map.get_mut(&hwnd) {
                if let Some(item) = state.items.iter_mut().find(|it| it.h_item == h_item) {
                    let mask: u32 = unsafe { std::ptr::read_unaligned(base as *const u32) };
                    if mask & TVIF_TEXT != 0 {
                        let psz: usize =
                            unsafe { std::ptr::read_unaligned((base + 24) as *const usize) };
                        if psz != 0 {
                            item.psz_text = read_treeview_text(psz, base + 32);
                        }
                    }
                    if mask & TVIF_IMAGE != 0 {
                        item.i_image =
                            unsafe { std::ptr::read_unaligned((base + 36) as *const i32) };
                    }
                    if mask & TVIF_PARAM != 0 {
                        item.l_param =
                            unsafe { std::ptr::read_unaligned((base + 48) as *const isize) };
                    }
                    return 1;
                }
            }
            0
        }
        TVM_GETNEXTITEM => {
            // w_param = relationship (TVGN_*), l_param = hItem
            let h_item = l_param as usize;
            let relation = w_param;
            let map = get_state().lock().unwrap();
            if let Some(ComctlState::TreeView(ref state)) = map.get(&hwnd) {
                if state.items.is_empty() {
                    return 0;
                }
                match relation {
                    TVGN_ROOT => {
                        // Return first root item (h_parent == 0)
                        state
                            .items
                            .iter()
                            .find(|it| it.h_parent == 0)
                            .map(|it| it.h_item)
                            .unwrap_or(0) as isize
                    }
                    TVGN_NEXT => {
                        if let Some(pos) = state.items.iter().position(|it| it.h_item == h_item) {
                            state.items.get(pos + 1).map(|it| it.h_item).unwrap_or(0) as isize
                        } else {
                            0
                        }
                    }
                    TVGN_PREVIOUS => {
                        if let Some(pos) = state.items.iter().position(|it| it.h_item == h_item) {
                            if pos > 0 {
                                state.items[pos - 1].h_item as isize
                            } else {
                                0
                            }
                        } else {
                            0
                        }
                    }
                    TVGN_PARENT => state
                        .items
                        .iter()
                        .find(|it| it.h_item == h_item)
                        .and_then(|item| {
                            if item.h_parent == 0 {
                                None
                            } else {
                                state.items.iter().find(|it| it.h_item == item.h_parent)
                            }
                        })
                        .map(|it| it.h_item)
                        .unwrap_or(0) as isize,
                    TVGN_CHILD => state
                        .items
                        .iter()
                        .find(|it| it.h_parent == h_item)
                        .map(|it| it.h_item)
                        .unwrap_or(0) as isize,
                    TVGN_CARET | TVGN_FIRSTVISIBLE => {
                        state.items.first().map(|it| it.h_item).unwrap_or(0) as isize
                    }
                    _ => state.items.first().map(|it| it.h_item).unwrap_or(0) as isize,
                }
            } else {
                0
            }
        }
        TVM_SELECTITEM => {
            // Select an item — no-op visual, return TRUE
            1
        }
        TVM_ENSUREVISIBLE => 1,
        _ => def_window_proc_w(hwnd, msg, w_param, l_param),
    }
}

fn read_treeview_text(psz_text: usize, cch_max_addr: usize) -> Option<String> {
    let cch_max: i32 = unsafe { std::ptr::read_unaligned(cch_max_addr as *const i32) };
    if psz_text == 0 || cch_max <= 0 {
        return None;
    }
    let mut chars = Vec::new();
    for i in 0..cch_max as usize {
        let c = unsafe { std::ptr::read_unaligned((psz_text + i * 2) as *const u16) };
        if c == 0 {
            break;
        }
        chars.push(c);
    }
    Some(String::from_utf16_lossy(&chars))
}

fn write_treeview_text(psz_text: usize, cch_max: i32, text: &str) {
    if psz_text == 0 || cch_max <= 0 {
        return;
    }
    let mut i = 0;
    for ch in text.encode_utf16() {
        if i >= cch_max as usize - 1 {
            break;
        }
        unsafe {
            std::ptr::write_unaligned((psz_text + i * 2) as *mut u16, ch);
        }
        i += 1;
    }
    unsafe {
        std::ptr::write_unaligned((psz_text + i * 2) as *mut u16, 0);
    }
}

/// InitCommonControls — register common control window classes.
///
/// Registers ToolbarWindow32 and SysTabControl32 classes so the guest can
/// create them and receive message replies without crashing.
pub extern "win64" fn init_common_controls() {
    register_comctl32_classes();
}

/// InitCommonControlsEx — register a specific set of common control classes.
///
/// # Safety
/// `p_icc` may be null (some callers pass null). Ignored.
pub unsafe extern "win64" fn init_common_controls_ex(_p_icc: *const u8) -> i32 {
    register_comctl32_classes();
    1 // TRUE
}

fn register_comctl32_classes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static REGISTERED: AtomicBool = AtomicBool::new(false);
    if REGISTERED.swap(true, Ordering::Relaxed) {
        return;
    }
    let toolbar_entry = ClassEntry {
        wnd_proc: toolbar_wnd_proc as *const () as usize,
        style: 0,
        h_cursor: 0,
        hbr_background: 0,
        cb_wnd_extra: 0,
        h_icon: 0,
        h_icon_sm: 0,
    };
    class::register("ToolbarWindow32", toolbar_entry);
    let tab_entry = ClassEntry {
        wnd_proc: tab_wnd_proc as *const () as usize,
        style: 0,
        h_cursor: 0,
        hbr_background: 0,
        cb_wnd_extra: 0,
        h_icon: 0,
        h_icon_sm: 0,
    };
    class::register("SysTabControl32", tab_entry);
    let listview_entry = ClassEntry {
        wnd_proc: listview_wnd_proc as *const () as usize,
        style: 0,
        h_cursor: 0,
        hbr_background: 0,
        cb_wnd_extra: 0,
        h_icon: 0,
        h_icon_sm: 0,
    };
    class::register("SysListView32", listview_entry);
    let treeview_entry = ClassEntry {
        wnd_proc: treeview_wnd_proc as *const () as usize,
        style: 0,
        h_cursor: 0,
        hbr_background: 0,
        cb_wnd_extra: 0,
        h_icon: 0,
        h_icon_sm: 0,
    };
    class::register("SysTreeView32", treeview_entry);
}

const WM_NCDESTROY: u32 = 0x0082;
const WM_GETFONT: u32 = 0x0030;
const WM_GETTEXT: u32 = 0x000c;

const CLR_DEFAULT: u32 = 0xFF00_0000;
const CLR_NONE: u32 = 0xFFFF_0000;

// ── ImageList state backend ───────────────────────────────────────────────────

struct ImageListState {
    cx: i32,
    cy: i32,
    flags: u32,
    count: i32,
    bk_color: u32,
}

static IMAGE_LISTS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<usize, ImageListState>>,
> = std::sync::OnceLock::new();

fn image_lists() -> &'static std::sync::Mutex<std::collections::HashMap<usize, ImageListState>> {
    IMAGE_LISTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

static NEXT_IMAGELIST_HANDLE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0x1000_0001);

fn alloc_imagelist_handle() -> usize {
    NEXT_IMAGELIST_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ── ImageList ─────────────────────────────────────────────────────────────────

/// ImageList_Create — create a new image list.
///
/// Returns a non-zero HIMAGELIST handle tracking the size and flags.
///
/// # Safety
/// No pointer arguments.
pub unsafe extern "win64" fn image_list_create(
    cx: i32,
    cy: i32,
    flags: u32,
    _c_initial: i32,
    _c_grow: i32,
) -> usize {
    let handle = alloc_imagelist_handle();
    let mut map = image_lists().lock().unwrap();
    map.insert(
        handle,
        ImageListState {
            cx,
            cy,
            flags,
            count: 0,
            bk_color: CLR_DEFAULT,
        },
    );
    handle
}

/// ImageList_Destroy — destroy an image list.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_destroy(himl: usize) -> i32 {
    let mut map = image_lists().lock().unwrap();
    if map.remove(&himl).is_some() {
        1
    } else {
        0
    }
}

/// ImageList_Add — add a bitmap to an image list. Returns image index.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_add(
    himl: usize,
    _hbm_image: usize,
    _hbm_mask: usize,
) -> i32 {
    let mut map = image_lists().lock().unwrap();
    if let Some(il) = map.get_mut(&himl) {
        let idx = il.count;
        il.count += 1;
        idx
    } else {
        -1
    }
}

/// ImageList_AddIcon — add an icon to an image list. Returns image index.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_add_icon(himl: usize, _hicon: usize) -> i32 {
    let mut map = image_lists().lock().unwrap();
    if let Some(il) = map.get_mut(&himl) {
        let idx = il.count;
        il.count += 1;
        idx
    } else {
        -1
    }
}

/// ImageList_AddMasked — add a bitmap using a mask colour. Returns image index.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_add_masked(
    himl: usize,
    _hbm_image: usize,
    _cr_mask: u32,
) -> i32 {
    let mut map = image_lists().lock().unwrap();
    if let Some(il) = map.get_mut(&himl) {
        let idx = il.count;
        il.count += 1;
        idx
    } else {
        -1
    }
}

/// ImageList_ReplaceIcon — replace or add an icon in an image list.
///
/// Returns the image index, or -1 on invalid handle.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_replace_icon(himl: usize, i: i32, _hicon: usize) -> i32 {
    let mut map = image_lists().lock().unwrap();
    if let Some(il) = map.get_mut(&himl) {
        let count = il.count;
        if i >= 0 && i < count {
            i // replace existing
        } else {
            il.count += 1;
            count // append, return new index
        }
    } else {
        -1
    }
}

/// ImageList_GetImageCount — return the number of images in a list.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_get_image_count(himl: usize) -> i32 {
    let map = image_lists().lock().unwrap();
    map.get(&himl).map_or(0, |il| il.count)
}

/// ImageList_SetImageCount — resize an image list.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_set_image_count(himl: usize, u_new_count: u32) -> i32 {
    let mut map = image_lists().lock().unwrap();
    if let Some(il) = map.get_mut(&himl) {
        il.count = u_new_count as i32;
        1
    } else {
        0
    }
}

/// ImageList_Draw — draw an image from a list onto a DC.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_draw(
    _himl: usize,
    _i: i32,
    _hdc_dst: usize,
    _x: i32,
    _y: i32,
    _f_style: u32,
) -> i32 {
    0 // FALSE — nothing drawn
}

/// ImageList_DrawEx — draw an image with extended options.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_draw_ex(
    _himl: usize,
    _i: i32,
    _hdc_dst: usize,
    _x: i32,
    _y: i32,
    _dx: i32,
    _dy: i32,
    _rgb_bk: u32,
    _rgb_fg: u32,
    _f_style: u32,
) -> i32 {
    0
}

/// ImageList_LoadImageW — load an image list from a resource (Wide).
///
/// Returns a fake non-zero handle.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_load_image_w(
    _hi: usize,
    _lp_bmp: *const u16,
    _cx: i32,
    _c_grow: i32,
    _cr_mask: u32,
    _u_type: u32,
    _u_flags: u32,
) -> usize {
    1 // fake HIMAGELIST
}

/// ImageList_LoadImageA — load an image list from a resource (ANSI).
///
/// Returns a fake non-zero handle.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_load_image_a(
    _hi: usize,
    _lp_bmp: *const u8,
    _cx: i32,
    _c_grow: i32,
    _cr_mask: u32,
    _u_type: u32,
    _u_flags: u32,
) -> usize {
    1 // fake HIMAGELIST
}

// ── Status bar ────────────────────────────────────────────────────────────────

/// CreateStatusWindowW — create a status bar window (Wide).
///
/// Wine ref: comctl32/status.c — CreateStatusWindowW is a thin wrapper around
/// CreateWindowExW(0, STATUSCLASSNAME, lpszText, style, ...) where STATUSCLASSNAME
/// is "msctls_statusbar32". SciTE checks `if (!statusBar_) return false` after
/// this call, so returning NULL causes an immediate clean exit before GetMessageW.
///
/// # Safety
/// lp_sz_text, if non-null, must be a valid null-terminated UTF-16 string.
/// hwnd_parent must be a valid HWND or 0.
pub unsafe extern "win64" fn create_status_window_w(
    style: i32,
    lp_sz_text: *const u16,
    hwnd_parent: usize,
    wid: u32,
) -> usize {
    // "msctls_statusbar32\0" as a wide string literal for the class name.
    let class_name: Vec<u16> = "msctls_statusbar32\0".encode_utf16().collect();
    let empty_title = [0u16; 1];
    let title_ptr = if lp_sz_text.is_null() {
        empty_title.as_ptr()
    } else {
        lp_sz_text
    };
    // WS_CHILD (0x4000_0000) must be set so user32 treats it as a child window.
    let adjusted_style = (style as u32) | 0x4000_0000u32;
    weave_user32::api::create_window_ex_w(
        0,                    // dwExStyle
        class_name.as_ptr(),  // "msctls_statusbar32"
        title_ptr,            // lpWindowName
        adjusted_style,       // dwStyle | WS_CHILD
        0,                    // x
        0,                    // y
        0,                    // nWidth (sized by parent on WM_SIZE)
        20,                   // nHeight (typical status bar height)
        hwnd_parent,          // hWndParent
        wid as usize,         // hMenu (child window ID)
        0,                    // hInstance
        std::ptr::null_mut(), // lpParam
    )
}

/// CreateStatusWindowA — create a status bar window (ANSI).
///
/// Forwards to the wide variant; the initial text is not significant for
/// Gate 5 (SciTE sets parts/text via SB_* messages after creation).
///
/// # Safety
/// hwnd_parent must be a valid HWND or 0.
pub unsafe extern "win64" fn create_status_window_a(
    style: i32,
    _lp_sz_text: *const u8,
    hwnd_parent: usize,
    wid: u32,
) -> usize {
    create_status_window_w(style, std::ptr::null(), hwnd_parent, wid)
}

/// DrawStatusTextW — draw status bar text into a DC (Wide). No-op.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn draw_status_text_w(
    _hdc: usize,
    _lp_rc: *mut u8,
    _sz_text: *const u16,
    _u_flags: u32,
) {
}

/// DrawStatusTextA — draw status bar text into a DC (ANSI). No-op.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn draw_status_text_a(
    _hdc: usize,
    _lp_rc: *mut u8,
    _sz_text: *const u8,
    _u_flags: u32,
) {
}

// ── Toolbar ───────────────────────────────────────────────────────────────────

/// CreateToolbarEx — create a toolbar window.
///
/// Returns NULL HWND. Apps degrade gracefully.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn create_toolbar_ex(
    _hwnd: usize,
    _ws: u32,
    _wid: u32,
    _n_bitmaps: i32,
    _h_bm_inst: usize,
    _w_bm_id: usize,
    _lp_buttons: *const u8,
    _i_num_buttons: i32,
    _dx_button: i32,
    _dy_button: i32,
    _dx_bitmap: i32,
    _dy_bitmap: i32,
    _u_struct_size: u32,
) -> usize {
    0 // NULL HWND
}

/// CreateMappedBitmap — create a bitmap, mapping colours from a table.
///
/// Returns NULL HBITMAP.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn create_mapped_bitmap(
    _h_instance: usize,
    _id_bitmap: isize,
    _w_flags: u32,
    _lp_color_map: *const u8,
    _i_num_maps: i32,
) -> usize {
    0 // NULL HBITMAP
}

// ── Mouse tracking ────────────────────────────────────────────────────────────

/// _TrackMouseEvent — request WM_MOUSELEAVE / WM_MOUSEHOVER messages.
///
/// Returns TRUE (success). Since we don't have a real message loop,
/// the events won't actually fire, but callers treat this as optional.
///
/// # Safety
/// `lp_event_track` is ignored.
pub unsafe extern "win64" fn track_mouse_event(_lp_event_track: *mut u8) -> i32 {
    1 // TRUE
}

// ── Property sheets ───────────────────────────────────────────────────────────

/// PropertySheetW — display a property sheet dialog (Wide).
///
/// Returns -1 (error). Apps should handle gracefully.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn property_sheet_w(_lp_psh: *const u8) -> isize {
    -1
}

/// PropertySheetA — display a property sheet dialog (ANSI).
///
/// Returns -1 (error).
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn property_sheet_a(_lp_psh: *const u8) -> isize {
    -1
}

// Wine ref: dlls/comctl32/propsheet.c — CreatePropertySheetPageW allocates a copy of the
// PROPSHEETPAGEW struct via Alloc(); returns an opaque HPROPSHEETPAGE handle (pointer to
// the allocated struct), or NULL on allocation failure. The returned handle is passed to
// PropertySheetW or AddPropertySheetPage. Since Weave has no property-sheet dialog loop,
// returning NULL is the safe failure sentinel — callers that check for NULL skip the page.
/// CreatePropertySheetPageW — create a property sheet page handle (Wide).
///
/// Returns NULL (stub — no property sheet dialog subsystem in Weave).
/// Callers must check for NULL before passing the handle to PropertySheetW.
///
/// # Safety
/// `lp_psp` is ignored.
// stub: Phase A — no dialog subsystem; always returns NULL.
pub unsafe extern "win64" fn create_property_sheet_page_w(_lp_psp: *const u8) -> usize {
    0 // NULL HPROPSHEETPAGE
}

/// CreatePropertySheetPageA — create a property sheet page handle (ANSI).
///
/// Returns NULL — stub, mirrors CreatePropertySheetPageW.
///
/// # Safety
/// `lp_psp` is ignored.
// stub: Phase A — no dialog subsystem; always returns NULL.
pub unsafe extern "win64" fn create_property_sheet_page_a(_lp_psp: *const u8) -> usize {
    0 // NULL HPROPSHEETPAGE
}

/// DestroyPropertySheetPage — destroy a property sheet page handle.
///
/// Returns TRUE — stub; nothing to free since CreatePropertySheetPage* always returns NULL.
///
/// # Safety
/// `hpsp` is ignored.
// stub: Phase A — no handle table; returns TRUE (no-op destroy).
pub unsafe extern "win64" fn destroy_property_sheet_page(_hpsp: usize) -> i32 {
    1 // TRUE
}

// ── Flat scrollbars ───────────────────────────────────────────────────────────

/// InitializeFlatSB — initialise flat scroll bars for a window.
///
/// Returns TRUE.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn initialize_flat_sb(_hwnd: usize) -> i32 {
    1 // TRUE
}

/// UninitializeFlatSB — remove flat scroll bars from a window.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn uninitialize_flat_sb(_hwnd: usize) -> i32 {
    1 // S_OK (0 is also acceptable; apps rarely check this)
}

/// ImageList_GetIcon — create an icon from an image list entry.
///
/// Returns NULL HICON — stub.
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_get_icon(_himl: usize, _i: i32, _flags: u32) -> usize {
    0 // NULL HICON
}

/// ImageList_BeginDrag — begin dragging an image. Returns TRUE (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_begin_drag(
    _himl_track: usize,
    _i_track: i32,
    _dx_hotspot: i32,
    _dy_hotspot: i32,
) -> i32 {
    1 // TRUE
}

/// ImageList_EndDrag — end a drag operation (stub, no-op).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_end_drag() {}

/// ImageList_DragEnter — lock window updates and display drag image (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_drag_enter(_hwnd_lock: usize, _x: i32, _y: i32) -> i32 {
    1 // TRUE
}

/// ImageList_DragLeave — unlocks window updates (stub, no-op).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_drag_leave(_hwnd_lock: usize) -> i32 {
    1 // TRUE
}

/// ImageList_DragMove — moves the image being dragged (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_drag_move(_x: i32, _y: i32) -> i32 {
    1 // TRUE
}

/// ImageList_DragShowNolock — shows or hides drag image without locking window (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_drag_show_nolock(_f_show: i32) -> i32 {
    1 // TRUE
}

/// ImageList_Remove — removes an image from an image list. Returns TRUE (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_remove(_himl: usize, _i: i32) -> i32 {
    1 // TRUE
}

/// ImageList_SetIconSize — sets the icon dimensions for an image list. Returns TRUE (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_set_icon_size(_himl: usize, _cx: i32, _cy: i32) -> i32 {
    1 // TRUE
}

/// ImageList_GetIconSize — get the image dimensions for an image list.
///
/// # Safety
/// `himl` must be a handle from image_list_create. `pcx` and `pcy` must be
/// valid writable pointers if non-null.
pub unsafe extern "win64" fn image_list_get_icon_size(
    himl: usize,
    pcx: *mut i32,
    pcy: *mut i32,
) -> i32 {
    let map = image_lists().lock().unwrap();
    if let Some(il) = map.get(&himl) {
        if !pcx.is_null() {
            pcx.write(il.cx);
        }
        if !pcy.is_null() {
            pcy.write(il.cy);
        }
        1
    } else {
        0
    }
}

/// ImageList_GetBkColor — get the background colour of an image list.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_get_bk_color(himl: usize) -> u32 {
    let map = image_lists().lock().unwrap();
    map.get(&himl).map_or(CLR_NONE, |il| il.bk_color)
}

/// ImageList_SetBkColor — set the background colour of an image list.
///
/// Returns the previous background colour, or CLR_NONE on invalid handle.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_set_bk_color(himl: usize, clr_bk: u32) -> u32 {
    let mut map = image_lists().lock().unwrap();
    if let Some(il) = map.get_mut(&himl) {
        let prev = il.bk_color;
        il.bk_color = clr_bk;
        prev
    } else {
        CLR_NONE
    }
}

/// ImageList_GetFlags — get the flags of an image list.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_get_flags(himl: usize) -> u32 {
    let map = image_lists().lock().unwrap();
    map.get(&himl).map_or(0, |il| il.flags)
}

/// ImageList_SetFlags — set the flags of an image list.
///
/// # Safety
/// `himl` must be a handle from image_list_create.
pub unsafe extern "win64" fn image_list_set_flags(himl: usize, flags: u32) -> u32 {
    let mut map = image_lists().lock().unwrap();
    if let Some(il) = map.get_mut(&himl) {
        let prev = il.flags;
        il.flags = flags;
        prev
    } else {
        0
    }
}

/// ImageList_GetImageInfo — retrieve information about an image in an image list.
///
/// Stub: returns FALSE (0). No image info is provided.
///
/// # Safety
/// `himl` must be a valid handle. `pii` is ignored.
/// Wine ref: dlls/comctl32/imagelist.c — fills IMAGEINFO struct from the image list entry
pub unsafe extern "win64" fn image_list_get_image_info(
    _himl: usize,
    _i: i32,
    _pii: *mut u8,
) -> i32 {
    0
}

// ── TaskDialog ─────────────────────────────────────────────────────────────────

/// TaskDialogIndirect: create and show a task dialog (stub).
///
/// Stubbed to S_OK so callers proceed as if the dialog was dismissed.
/// The #345 ordinal is how SumatraPDF imports TaskDialogIndirect.
///
/// # Safety
/// All pointer arguments are ignored.
// Wine ref: dlls/comctl32/taskdialog.c — TaskDialogIndirect creates a modal
// task dialog with custom buttons, icon, and content.
pub unsafe extern "win64" fn task_dialog_indirect(
    _p_task_config: *const u8,
    _pn_button: *mut i32,
    _pn_radio: *mut i32,
    _pf_verification: *mut i32,
) -> i32 {
    0 // S_OK
}

/// TaskDialog: simplified task dialog with a fixed button set (stub).
///
/// # Safety
/// All pointer arguments are ignored.
// Wine ref: dlls/comctl32/taskdialog.c — wraps TaskDialogIndirect.
pub unsafe extern "win64" fn task_dialog(
    _hwnd_parent: usize,
    _h_instance: usize,
    _window_title: *const u16,
    _main_instruction: *const u16,
    _buttons: u32,
    _icon: *const u16,
    _pn_button: *mut i32,
) -> i32 {
    0 // S_OK
}

// ── DLL Resolver ─────────────────────────────────────────────────────────────

/// Resolve a comctl32.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("comctl32.dll") {
        return None;
    }

    match func {
        "InitCommonControls" => Some(init_common_controls as *const () as usize),
        "InitCommonControlsEx" => Some(init_common_controls_ex as *const () as usize),
        "ImageList_Create" => Some(image_list_create as *const () as usize),
        "ImageList_Destroy" => Some(image_list_destroy as *const () as usize),
        "ImageList_Add" => Some(image_list_add as *const () as usize),
        "ImageList_AddIcon" => Some(image_list_add_icon as *const () as usize),
        "ImageList_AddMasked" => Some(image_list_add_masked as *const () as usize),
        "ImageList_ReplaceIcon" => Some(image_list_replace_icon as *const () as usize),
        "ImageList_GetImageCount" => Some(image_list_get_image_count as *const () as usize),
        "ImageList_SetImageCount" => Some(image_list_set_image_count as *const () as usize),
        "ImageList_Draw" => Some(image_list_draw as *const () as usize),
        "ImageList_DrawEx" => Some(image_list_draw_ex as *const () as usize),
        "ImageList_LoadImageW" => Some(image_list_load_image_w as *const () as usize),
        "ImageList_LoadImageA" => Some(image_list_load_image_a as *const () as usize),
        "CreateStatusWindowW" => Some(create_status_window_w as *const () as usize),
        "CreateStatusWindowA" => Some(create_status_window_a as *const () as usize),
        "DrawStatusTextW" => Some(draw_status_text_w as *const () as usize),
        "DrawStatusTextA" => Some(draw_status_text_a as *const () as usize),
        "CreateToolbarEx" => Some(create_toolbar_ex as *const () as usize),
        "CreateMappedBitmap" => Some(create_mapped_bitmap as *const () as usize),
        "_TrackMouseEvent" => Some(track_mouse_event as *const () as usize),
        "PropertySheetW" => Some(property_sheet_w as *const () as usize),
        "PropertySheetA" => Some(property_sheet_a as *const () as usize),
        "InitializeFlatSB" => Some(initialize_flat_sb as *const () as usize),
        "UninitializeFlatSB" => Some(uninitialize_flat_sb as *const () as usize),
        "ImageList_GetIcon" | "#17" => Some(
            image_list_get_icon as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "ImageList_BeginDrag" => Some(image_list_begin_drag as *const () as usize),
        "ImageList_EndDrag" => Some(image_list_end_drag as *const () as usize),
        "ImageList_DragEnter" => Some(image_list_drag_enter as *const () as usize),
        "ImageList_DragLeave" => Some(image_list_drag_leave as *const () as usize),
        "ImageList_DragMove" => Some(image_list_drag_move as *const () as usize),
        "ImageList_DragShowNolock" => Some(image_list_drag_show_nolock as *const () as usize),
        "ImageList_Remove" => Some(image_list_remove as *const () as usize),
        "ImageList_SetIconSize" => Some(image_list_set_icon_size as *const () as usize),
        "ImageList_GetIconSize" => Some(image_list_get_icon_size as *const () as usize),
        "ImageList_GetBkColor" => Some(image_list_get_bk_color as *const () as usize),
        "ImageList_SetBkColor" => Some(image_list_set_bk_color as *const () as usize),
        "ImageList_GetFlags" => Some(image_list_get_flags as *const () as usize),
        "ImageList_SetFlags" => Some(image_list_set_flags as *const () as usize),
        // Ordinals seen in Notepad++ imports — map to their named equivalents.
        // #381 = ImageList_BeginDrag, #410/#411/#412/#413 = drag show/move/enter/leave variants.
        "#381" => Some(image_list_begin_drag as *const () as usize),
        "#410" => Some(image_list_drag_enter as *const () as usize),
        "#411" => Some(image_list_drag_leave as *const () as usize),
        "#412" => Some(image_list_drag_move as *const () as usize),
        "#413" => Some(image_list_drag_show_nolock as *const () as usize),
        // Property sheet page creation — SumatraPDF and printer dialogs use these.
        "CreatePropertySheetPageW" => Some(create_property_sheet_page_w as *const () as usize),
        "CreatePropertySheetPageA" => Some(create_property_sheet_page_a as *const () as usize),
        "DestroyPropertySheetPage" => Some(destroy_property_sheet_page as *const () as usize),
        "#345" => Some(task_dialog_indirect as *const () as usize),
        "TaskDialogIndirect" => Some(task_dialog_indirect as *const () as usize),
        "TaskDialog" => Some(task_dialog as *const () as usize),
        "ImageList_GetImageInfo" => Some(
            image_list_get_image_info as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "ImageList_Copy" => Some(image_list_copy as *const () as usize),
        "ImageList_Replace" => Some(image_list_replace as *const () as usize),
        "ImageList_SetDragCursorImage" => {
            Some(image_list_set_drag_cursor_image as *const () as usize)
        }
        _ => None,
    }
}

// Wine ref: dlls/comctl32/imagelist.c — ImageList_Copy copies images within image list.
extern "win64" fn image_list_copy(
    _himl_dst: usize,
    _dst: i32,
    _himl_src: usize,
    _src: i32,
    _color: u32,
) -> i32 {
    0 // FALSE
}

// Wine ref: dlls/comctl32/imagelist.c — ImageList_Replace replaces an image.
extern "win64" fn image_list_replace(_himl: usize, _i: i32, _image: usize, _mask: usize) -> i32 {
    0 // FALSE
}

// Wine ref: dlls/comctl32/imagelist.c — ImageList_SetDragCursorImage creates a drag cursor.
extern "win64" fn image_list_set_drag_cursor_image(
    _himl: usize,
    _i: i32,
    _dx: i32,
    _dy: i32,
    _color: u32,
) -> usize {
    0
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "InitCommonControls").is_none());
    }

    #[test]
    fn resolve_unknown_function() {
        assert!(resolve("comctl32.dll", "__nonexistent__").is_none());
    }

    #[test]
    fn resolve_all_exports() {
        let funcs = [
            "InitCommonControls",
            "InitCommonControlsEx",
            "ImageList_Create",
            "ImageList_Destroy",
            "ImageList_Add",
            "ImageList_AddIcon",
            "ImageList_AddMasked",
            "ImageList_ReplaceIcon",
            "ImageList_GetImageCount",
            "ImageList_SetImageCount",
            "ImageList_Draw",
            "ImageList_DrawEx",
            "ImageList_LoadImageW",
            "ImageList_LoadImageA",
            "CreateStatusWindowW",
            "CreateStatusWindowA",
            "DrawStatusTextW",
            "DrawStatusTextA",
            "CreateToolbarEx",
            "CreateMappedBitmap",
            "_TrackMouseEvent",
            "PropertySheetW",
            "PropertySheetA",
            "InitializeFlatSB",
            "UninitializeFlatSB",
            "ImageList_GetIcon",
            "ImageList_BeginDrag",
            "ImageList_EndDrag",
            "ImageList_DragEnter",
            "ImageList_DragLeave",
            "ImageList_DragMove",
            "ImageList_DragShowNolock",
            "ImageList_Remove",
            "ImageList_SetIconSize",
            "ImageList_GetIconSize",
            "ImageList_GetBkColor",
            "ImageList_SetBkColor",
            "ImageList_GetFlags",
            "ImageList_SetFlags",
            "#381",
            "#410",
            "#411",
            "#412",
            "#413",
            "CreatePropertySheetPageW",
            "CreatePropertySheetPageA",
            "DestroyPropertySheetPage",
            "ImageList_GetImageInfo",
        ];
        for f in &funcs {
            assert!(resolve("comctl32.dll", f).is_some(), "missing: {f}");
        }
    }

    #[test]
    fn image_list_state_tracking() {
        // Create an image list with known parameters.
        let himl = unsafe { image_list_create(16, 16, 0x0001, 4, 4) };
        assert_ne!(himl, 0, "image list handle must be non-zero");

        // GetIconSize should return the dimensions.
        let mut cx: i32 = 0;
        let mut cy: i32 = 0;
        let ret = unsafe { image_list_get_icon_size(himl, &mut cx, &mut cy) };
        assert_eq!(ret, 1, "GetIconSize should succeed");
        assert_eq!(cx, 16);
        assert_eq!(cy, 16);

        // Initially empty.
        assert_eq!(unsafe { image_list_get_image_count(himl) }, 0);

        // Add an image, count increments.
        let idx = unsafe { image_list_add(himl, 0x1234, 0) };
        assert_eq!(idx, 0);
        assert_eq!(unsafe { image_list_get_image_count(himl) }, 1);

        // Add another image.
        let idx = unsafe { image_list_add_icon(himl, 0x5678) };
        assert_eq!(idx, 1);
        assert_eq!(unsafe { image_list_get_image_count(himl) }, 2);

        // ReplaceIcon with valid index.
        let idx = unsafe { image_list_replace_icon(himl, 0, 0x9999) };
        assert_eq!(idx, 0, "replace existing should return same index");
        assert_eq!(unsafe { image_list_get_image_count(himl) }, 2);

        // ReplaceIcon with -1 appends.
        let idx = unsafe { image_list_replace_icon(himl, -1, 0xAAAA) };
        assert_eq!(idx, 2);
        assert_eq!(unsafe { image_list_get_image_count(himl) }, 3);

        // Get/SetBkColor.
        let prev = unsafe { image_list_set_bk_color(himl, 0x00FF0000) };
        assert_eq!(prev, CLR_DEFAULT);
        let bk = unsafe { image_list_get_bk_color(himl) };
        assert_eq!(bk, 0x00FF0000);

        // Get/SetFlags.
        let prev_flags = unsafe { image_list_set_flags(himl, 0x0002) };
        assert_eq!(prev_flags, 0x0001);
        let flags = unsafe { image_list_get_flags(himl) };
        assert_eq!(flags, 0x0002);

        // SetImageCount.
        let ret = unsafe { image_list_set_image_count(himl, 10) };
        assert_eq!(ret, 1);
        assert_eq!(unsafe { image_list_get_image_count(himl) }, 10);

        // Destroy.
        let ret = unsafe { image_list_destroy(himl) };
        assert_eq!(ret, 1, "destroy should succeed");

        // Operations on destroyed handle return safe defaults.
        assert_eq!(unsafe { image_list_get_image_count(himl) }, 0);
        assert_eq!(
            unsafe { image_list_get_icon_size(himl, &mut cx, &mut cy) },
            0
        );
        assert_eq!(unsafe { image_list_destroy(himl) }, 0);
    }

    #[test]
    fn resolve_case_insensitive_dll_name() {
        assert!(resolve("ComCtl32.DLL", "InitCommonControls").is_some());
        assert!(resolve("COMCTL32.DLL", "ImageList_Create").is_some());
    }

    #[test]
    fn resolve_uxtheme_all_stubs() {
        let stubs = [
            "OpenThemeData",
            "CloseThemeData",
            "DrawThemeBackground",
            "DrawThemeText",
            "SetWindowTheme",
            "IsThemeActive",
            "IsAppThemed",
            "GetWindowTheme",
            "EnableThemeDialogTexture",
            "EnableTheming",
            "GetThemePartSize",
            "GetThemeTextExtent",
            "GetThemeBackgroundContentRect",
            "GetThemeBackgroundExtent",
            "GetThemeColor",
            "GetThemeMetric",
            "GetThemeBool",
            "GetThemeSysColor",
            "GetThemeSysFont",
            "GetThemeSysSize",
            "GetThemeSysBool",
            "DrawThemeParentBackground",
            "GetThemeTransitionDuration",
            "GetThemeInt",
            "DrawThemeEdge",
        ];
        for s in &stubs {
            assert!(
                resolve_uxtheme("uxtheme.dll", s).is_some(),
                "uxtheme.dll!{s} must resolve"
            );
        }
    }

    #[test]
    fn resolve_uxtheme_case_insensitive() {
        assert!(resolve_uxtheme("UXTHEME.DLL", "OpenThemeData").is_some());
        assert!(resolve_uxtheme("UxTheme.DLL", "IsThemeActive").is_some());
    }

    #[test]
    fn resolve_uxtheme_wrong_dll_returns_none() {
        assert!(resolve_uxtheme("kernel32.dll", "OpenThemeData").is_none());
        assert!(resolve_uxtheme("uxtheme.dll", "__nonexistent__").is_none());
    }
}

// ── uxtheme.dll stubs ─────────────────────────────────────────────────────────
//
// Wine ref: dlls/uxtheme/uxtheme.c — theme API functions.
// All stubs return safe sentinel values (NULL handle, S_OK, FALSE).

const S_OK: i32 = 0;

/// Resolve a uxtheme.dll import to a stub address.
pub fn resolve_uxtheme(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("uxtheme.dll") {
        return None;
    }
    match func {
        "OpenThemeData" => Some(open_theme_data as *const () as usize),
        "CloseThemeData" => Some(close_theme_data as *const () as usize),
        "DrawThemeBackground" => Some(draw_theme_background as *const () as usize),
        "DrawThemeText" => Some(draw_theme_text as *const () as usize),
        "SetWindowTheme" => Some(set_window_theme as *const () as usize),
        "IsThemeActive" => Some(is_theme_active as *const () as usize),
        "IsAppThemed" => Some(is_app_themed as *const () as usize),
        "GetWindowTheme" => Some(get_window_theme as *const () as usize),
        "EnableThemeDialogTexture" => Some(enable_theme_dialog_texture as *const () as usize),
        "EnableTheming" => Some(enable_theming as *const () as usize),
        // ── Additional uxtheme stubs ──
        "GetThemePartSize" => Some(get_theme_part_size as *const () as usize),
        "GetThemeTextExtent" => Some(get_theme_text_extent as *const () as usize),
        "GetThemeBackgroundContentRect" => {
            Some(get_theme_background_content_rect as *const () as usize)
        }
        "GetThemeBackgroundExtent" => Some(get_theme_background_extent as *const () as usize),
        "GetThemeColor" => Some(get_theme_color as *const () as usize),
        "GetThemeMetric" => Some(get_theme_metric as *const () as usize),
        "GetThemeBool" => Some(get_theme_bool as *const () as usize),
        "GetThemeSysColor" => Some(get_theme_sys_color as *const () as usize),
        "GetThemeSysFont" => Some(get_theme_sys_font as *const () as usize),
        "GetThemeSysSize" => Some(get_theme_sys_size as *const () as usize),
        "GetThemeSysBool" => Some(get_theme_sys_bool as *const () as usize),
        "DrawThemeParentBackground" => Some(draw_theme_parent_background as *const () as usize),
        "GetThemeTransitionDuration" => Some(get_theme_transition_duration as *const () as usize),
        "GetThemeInt" => Some(get_theme_int as *const () as usize),
        "DrawThemeEdge" => Some(draw_theme_edge as *const () as usize),
        "GetCurrentThemeName" => Some(get_current_theme_name as *const () as usize),
        "GetThemeMargins" => Some(get_theme_margins as *const () as usize),
        _ => None,
    }
}

// Wine ref: dlls/uxtheme/theme.c — OpenThemeData returns HTHEME handle or NULL.
extern "win64" fn open_theme_data(_hwnd: usize, _class: *const u16) -> usize {
    0 // NULL — no theme available
}

// Wine ref: dlls/uxtheme/theme.c — CloseThemeData frees theme handle resources.
extern "win64" fn close_theme_data(_h_theme: usize) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — DrawThemeBackground draws themed background.
extern "win64" fn draw_theme_background(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _rect: *const u8,
    _clip: *const u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — DrawThemeText draws themed text.
extern "win64" fn draw_theme_text(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _str: *const u16,
    _len: i32,
    _flags: u32,
    _flags2: u32,
    _rect: *const u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — SetWindowTheme sets/clears theme per window.
extern "win64" fn set_window_theme(_hwnd: usize, _app: *const u16, _sub: *const u16) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — IsThemeActive returns TRUE if themes active.
extern "win64" fn is_theme_active() -> i32 {
    0 // FALSE — no themes active
}

// Wine ref: dlls/uxtheme/theme.c — IsAppThemed returns TRUE if app is themed.
extern "win64" fn is_app_themed() -> i32 {
    0 // FALSE — not themed
}

// Wine ref: dlls/uxtheme/theme.c — GetWindowTheme returns theme handle for window.
extern "win64" fn get_window_theme(_hwnd: usize) -> usize {
    0 // NULL — no theme assigned
}

// Wine ref: dlls/uxtheme/theme.c — EnableThemeDialogTexture enables background texture.
extern "win64" fn enable_theme_dialog_texture(_hwnd: usize, _flags: u32) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — EnableTheming enables/disables visual styles.
extern "win64" fn enable_theming(_enable: i32) -> i32 {
    S_OK
}

// ── Additional uxtheme stubs ──────────────────────────────────────────────
// Wine ref: dlls/uxtheme/theme.c — GetThemePartSize returns the size of a theme part.
extern "win64" fn get_theme_part_size(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _rect: *const u8,
    _size: *mut u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeTextExtent calculates text bounding rect.
extern "win64" fn get_theme_text_extent(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _text: *const u16,
    _len: i32,
    _flags: u32,
    _rect: *const u8,
    _extent: *mut u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeBackgroundContentRect returns content area.
extern "win64" fn get_theme_background_content_rect(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _rect: *const u8,
    _content: *mut u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeBackgroundExtent returns background area.
extern "win64" fn get_theme_background_extent(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _rect: *const u8,
    _extent: *mut u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeColor returns a COLORREF for a theme color.
extern "win64" fn get_theme_color(
    _h_theme: usize,
    _part: i32,
    _state: i32,
    _prop: i32,
    _color: *mut u32,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeMetric returns an int metric value.
extern "win64" fn get_theme_metric(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _prop: i32,
    _val: *mut i32,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeBool returns a boolean theme property.
extern "win64" fn get_theme_bool(
    _h_theme: usize,
    _part: i32,
    _state: i32,
    _prop: i32,
    _val: *mut i32,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeSysColor returns a system color index.
extern "win64" fn get_theme_sys_color(_h_theme: usize, _color: i32) -> u32 {
    0 // COLORREF 0 = black
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeSysFont fills a LOGFONTW with system font info.
extern "win64" fn get_theme_sys_font(_h_theme: usize, _font: i32, _lf: *mut u8) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeSysSize returns a system size in pixels.
extern "win64" fn get_theme_sys_size(_h_theme: usize, _size: i32) -> i32 {
    0
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeSysBool returns a boolean system property.
extern "win64" fn get_theme_sys_bool(_h_theme: usize, _prop: i32) -> i32 {
    0
} // FALSE

// Wine ref: dlls/uxtheme/theme.c — DrawThemeParentBackground draws parent background pixels.
extern "win64" fn draw_theme_parent_background(_hwnd: usize, _hdc: usize, _rect: *const u8) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeTransitionDuration returns transition timing.
extern "win64" fn get_theme_transition_duration(
    _h_theme: usize,
    _part: i32,
    _state_from: i32,
    _state_to: i32,
    _prop: i32,
    _dur: *mut u32,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeInt returns an int property.
extern "win64" fn get_theme_int(
    _h_theme: usize,
    _part: i32,
    _state: i32,
    _prop: i32,
    _val: *mut i32,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — DrawThemeEdge draws themed edge styling.
extern "win64" fn draw_theme_edge(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _dest: *const u8,
    _clip: *const u8,
    _edge: u32,
    _flags: u32,
    _rect: *mut u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetCurrentThemeName returns theme name strings.
extern "win64" fn get_current_theme_name(
    _name: *mut u16,
    _name_len: i32,
    _color: *mut u16,
    _color_len: i32,
    _size: *mut u16,
    _size_len: i32,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — GetThemeMargins returns S_OK with zeroed margins.
extern "win64" fn get_theme_margins(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _prop: i32,
    _rect: *const u8,
    _margins: *mut u8,
) -> i32 {
    S_OK
}
