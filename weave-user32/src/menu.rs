//! Win32 menu stubs for Weave.
//!
//! Phase 2 scope: in-memory menu tree. No X11 rendering — menus are stored
//! and queryable but not visually drawn. This is sufficient for apps that
//! create menus and check whether items are enabled, without crashing.
//!
//! Phase 3 will add X11 rendering (menu bar drawn at top of window,
//! popup menus via override-redirect windows).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ── Menu item ─────────────────────────────────────────────────────────────────

pub struct MenuItem {
    /// MF_POPUP | MF_STRING | MF_SEPARATOR | MF_GRAYED | MF_CHECKED etc.
    pub flags: u32,
    /// For MF_STRING: the display text. For MF_POPUP: unused.
    pub text: String,
    /// For MF_POPUP: the submenu HMENU. For commands: the item id (u16).
    pub id_or_submenu: usize,
}

// ── Menu table ────────────────────────────────────────────────────────────────

struct MenuTable {
    next_id: usize,
    menus: HashMap<usize, Vec<MenuItem>>,
}

fn menus() -> &'static Mutex<MenuTable> {
    static M: OnceLock<Mutex<MenuTable>> = OnceLock::new();
    M.get_or_init(|| {
        Mutex::new(MenuTable {
            next_id: 0x4000_0001, // avoid collision with HWND range
            menus: HashMap::new(),
        })
    })
}

fn alloc_menu() -> usize {
    let mut m = menus().lock().unwrap();
    let id = m.next_id;
    m.next_id += 1;
    m.menus.insert(id, Vec::new());
    id
}

// ── Win32 menu flag constants ─────────────────────────────────────────────────

pub const MF_STRING: u32 = 0x0000;
pub const MF_POPUP: u32 = 0x0010;
pub const MF_SEPARATOR: u32 = 0x0800;
pub const MF_GRAYED: u32 = 0x0001;
pub const MF_DISABLED: u32 = 0x0002;
pub const MF_CHECKED: u32 = 0x0008;
pub const MF_BYCOMMAND: u32 = 0x0000;
pub const MF_BYPOSITION: u32 = 0x0400;

// ── Public API ────────────────────────────────────────────────────────────────

/// CreateMenu: create an empty menu bar.
pub extern "win64" fn create_menu() -> usize {
    alloc_menu()
}

/// CreatePopupMenu: create an empty popup (context) menu.
///
/// In the Win32 model, popup menus and menu bars have identical storage;
/// the difference is only how they're displayed. We treat them the same.
pub extern "win64" fn create_popup_menu() -> usize {
    alloc_menu()
}

/// AppendMenuW: append an item to a menu.
///
/// # Safety
/// `lp_new_item`, when flags include MF_STRING, must be a valid
/// null-terminated UTF-16 string pointer.
pub unsafe extern "win64" fn append_menu_w(
    h_menu: usize,
    u_flags: u32,
    u_id_new_item: usize,
    lp_new_item: *const u16,
) -> i32 {
    let text = if u_flags & MF_SEPARATOR == 0 && !lp_new_item.is_null() {
        let mut len = 0usize;
        // Pointer validation: cap string walk to avoid OOB read on unterminated input.
        while len < crate::defs::MAX_GUEST_STR_LEN && unsafe { *lp_new_item.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(lp_new_item, len) };
        String::from_utf16_lossy(slice)
    } else {
        String::new()
    };

    let mut m = menus().lock().unwrap();
    let items = match m.menus.get_mut(&h_menu) {
        Some(v) => v,
        None => return 0, // invalid HMENU
    };
    items.push(MenuItem {
        flags: u_flags,
        text,
        id_or_submenu: u_id_new_item,
    });
    1 // TRUE
}

/// InsertMenuItemW: insert a menu item by position or command id.
///
/// Phase 2: delegates to AppendMenuW (ignores position, always appends).
///
/// # Safety
/// Same as append_menu_w.
pub unsafe extern "win64" fn insert_menu_item_w(
    h_menu: usize,
    _u_item: u32,
    _f_by_position: i32,
    lpmii: *const MenuItemInfoW,
) -> i32 {
    if lpmii.is_null() || h_menu == 0 {
        return 0;
    }
    let info = unsafe { &*lpmii };
    let flags = if info.f_type & MFT_SEPARATOR != 0 {
        MF_SEPARATOR
    } else {
        MF_STRING
    };
    let text_ptr = if info.dw_type_data.is_null() {
        std::ptr::null()
    } else {
        info.dw_type_data
    };
    unsafe { append_menu_w(h_menu, flags, info.w_id as usize, text_ptr) }
}

/// SetMenu: attach a menu bar to a window.
///
/// Phase 2: stored in window table; not rendered. Returns TRUE.
pub extern "win64" fn set_menu(hwnd: usize, h_menu: usize) -> i32 {
    crate::window::with_mut(hwnd, |w| {
        w.h_menu = h_menu;
    });
    1
}

/// GetMenu: return the menu handle attached to a window.
pub extern "win64" fn get_menu(hwnd: usize) -> usize {
    crate::window::with(hwnd, |w| w.h_menu).unwrap_or(0)
}

/// DestroyMenu: free a menu and all its items.
pub extern "win64" fn destroy_menu(h_menu: usize) -> i32 {
    let mut m = menus().lock().unwrap();
    m.menus.remove(&h_menu).map(|_| 1).unwrap_or(0)
}

/// TrackPopupMenu: display a popup menu at a screen position.
///
/// Phase 2 stub: does nothing visually, returns 0 (no item selected).
pub extern "win64" fn track_popup_menu(
    _h_menu: usize,
    _u_flags: u32,
    _x: i32,
    _y: i32,
    _n_reserved: i32,
    _h_wnd: usize,
    _p_rc_rect: usize,
) -> i32 {
    0
}

/// TrackPopupMenuEx: extended popup tracking (Phase 2 stub).
pub extern "win64" fn track_popup_menu_ex(
    _h_menu: usize,
    _u_flags: u32,
    _x: i32,
    _y: i32,
    _hwnd: usize,
    _lptpm: usize,
) -> i32 {
    0
}

/// append_menu_raw: internal helper used by AppendMenuA.
///
/// Like AppendMenuW but takes an already-decoded Rust String.
pub fn append_menu_raw(h_menu: usize, u_flags: u32, u_id_new_item: usize, text: String) -> i32 {
    let mut m = menus().lock().unwrap();
    let items = match m.menus.get_mut(&h_menu) {
        Some(v) => v,
        None => return 0,
    };
    items.push(MenuItem {
        flags: u_flags,
        text,
        id_or_submenu: u_id_new_item,
    });
    1
}

/// delete_item: remove a menu item by position or command id.
pub fn delete_item(h_menu: usize, u_position: u32, u_flags: u32) {
    let mut m = menus().lock().unwrap();
    let items = match m.menus.get_mut(&h_menu) {
        Some(v) => v,
        None => return,
    };
    let by_pos = u_flags & MF_BYPOSITION != 0;
    if by_pos {
        if (u_position as usize) < items.len() {
            items.remove(u_position as usize);
        }
    } else {
        items.retain(|item| item.id_or_submenu as u32 != u_position);
    }
}

/// GetMenuItemCount: return the number of items in a menu.
pub extern "win64" fn get_menu_item_count(h_menu: usize) -> i32 {
    let m = menus().lock().unwrap();
    m.menus.get(&h_menu).map(|v| v.len() as i32).unwrap_or(-1)
}

/// CheckMenuItem: set or clear the checked state on a menu item.
///
/// Phase 2: mutates stored flags, returns previous check state.
pub extern "win64" fn check_menu_item(h_menu: usize, u_id_check_item: u32, u_check: u32) -> u32 {
    let mut m = menus().lock().unwrap();
    let items = match m.menus.get_mut(&h_menu) {
        Some(v) => v,
        None => return u32::MAX, // MF_ERROR
    };
    let by_pos = u_check & MF_BYPOSITION != 0;
    for (i, item) in items.iter_mut().enumerate() {
        let matches = if by_pos {
            i as u32 == u_id_check_item
        } else {
            item.id_or_submenu as u32 == u_id_check_item
        };
        if matches {
            let prev = item.flags & MF_CHECKED;
            if u_check & MF_CHECKED != 0 {
                item.flags |= MF_CHECKED;
            } else {
                item.flags &= !MF_CHECKED;
            }
            return prev;
        }
    }
    u32::MAX // item not found
}

/// EnableMenuItem: enable or grey a menu item.
pub extern "win64" fn enable_menu_item(h_menu: usize, u_id_enable_item: u32, u_enable: u32) -> i32 {
    let mut m = menus().lock().unwrap();
    let items = match m.menus.get_mut(&h_menu) {
        Some(v) => v,
        None => return -1,
    };
    let by_pos = u_enable & MF_BYPOSITION != 0;
    for (i, item) in items.iter_mut().enumerate() {
        let matches = if by_pos {
            i as u32 == u_id_enable_item
        } else {
            item.id_or_submenu as u32 == u_id_enable_item
        };
        if matches {
            let prev = (item.flags & (MF_GRAYED | MF_DISABLED)) as i32;
            item.flags &= !(MF_GRAYED | MF_DISABLED);
            if u_enable & MF_GRAYED != 0 {
                item.flags |= MF_GRAYED;
            }
            if u_enable & MF_DISABLED != 0 {
                item.flags |= MF_DISABLED;
            }
            return prev;
        }
    }
    -1
}

// ── MENUITEMINFOW layout ──────────────────────────────────────────────────────

/// Minimal MENUITEMINFOW for InsertMenuItemW.
/// Only fields needed for Phase 2 text/separator items.
#[repr(C)]
pub struct MenuItemInfoW {
    pub cb_size: u32,
    pub f_mask: u32,
    pub f_type: u32,
    pub f_state: u32,
    pub w_id: u32,
    pub h_sub_menu: usize,
    pub h_bmp_checked: usize,
    pub h_bmp_unchecked: usize,
    pub dw_item_data: usize,
    pub dw_type_data: *const u16,
    pub cch: u32,
    pub h_bmp_item: usize,
}

pub const MFT_STRING: u32 = 0x0000;
pub const MFT_SEPARATOR: u32 = 0x0800;
pub const MIIM_STRING: u32 = 0x0040;
pub const MIIM_ID: u32 = 0x0002;
pub const MIIM_TYPE: u32 = 0x0010;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_destroy_menu() {
        let h = create_menu();
        assert_ne!(h, 0);
        assert_eq!(destroy_menu(h), 1);
        assert_eq!(destroy_menu(h), 0); // second destroy fails
    }

    #[test]
    fn create_popup_is_distinct() {
        let h1 = create_menu();
        let h2 = create_popup_menu();
        assert_ne!(h1, h2);
        destroy_menu(h1);
        destroy_menu(h2);
    }

    #[test]
    fn append_and_count() {
        let h = create_menu();
        // Append a separator (no string needed)
        let sep_text: Vec<u16> = vec![0];
        unsafe {
            append_menu_w(h, MF_SEPARATOR, 0, sep_text.as_ptr());
        }
        assert_eq!(get_menu_item_count(h), 1);
        destroy_menu(h);
    }

    #[test]
    fn append_string_item() {
        let h = create_popup_menu();
        let text: Vec<u16> = "Open\0".encode_utf16().collect();
        unsafe {
            append_menu_w(h, MF_STRING, 1001, text.as_ptr());
        }
        assert_eq!(get_menu_item_count(h), 1);
        destroy_menu(h);
    }

    #[test]
    fn count_invalid_menu_returns_minus_one() {
        assert_eq!(get_menu_item_count(0xDEAD_BEEF), -1);
    }

    #[test]
    fn check_uncheck_item() {
        let h = create_popup_menu();
        let text: Vec<u16> = "Item\0".encode_utf16().collect();
        unsafe {
            append_menu_w(h, MF_STRING, 42, text.as_ptr());
        }
        // Initially unchecked → prev state = 0
        let prev = check_menu_item(h, 42, MF_CHECKED | MF_BYCOMMAND);
        assert_eq!(prev, 0);
        // Now checked → prev state = MF_CHECKED
        let prev2 = check_menu_item(h, 42, MF_BYCOMMAND);
        assert_eq!(prev2, MF_CHECKED);
        destroy_menu(h);
    }
}
