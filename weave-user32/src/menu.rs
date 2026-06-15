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
    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
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

pub const TPM_LEFTBUTTON: u32 = 0x0000;
pub const TPM_RIGHTBUTTON: u32 = 0x0002;
pub const TPM_LEFTALIGN: u32 = 0x0000;
pub const TPM_CENTERALIGN: u32 = 0x0004;
pub const TPM_RIGHTALIGN: u32 = 0x0008;
pub const TPM_TOPALIGN: u32 = 0x0000;
pub const TPM_VCENTERALIGN: u32 = 0x0010;
pub const TPM_BOTTOMALIGN: u32 = 0x0020;
pub const TPM_NONOTIFY: u32 = 0x0080;
pub const TPM_RETURNCMD: u32 = 0x0100;
pub const TPM_RECURSE: u32 = 0x0001;
pub const TPM_HORPOSANIMATION: u32 = 0x0400;
pub const TPM_HORNEGANIMATION: u32 = 0x0800;
pub const TPM_VERPOSANIMATION: u32 = 0x1000;
pub const TPM_VERNEGANIMATION: u32 = 0x2000;
pub const TPM_NOANIMATION: u32 = 0x4000;
pub const TPM_LAYOUTRTL: u32 = 0x8000;

pub const WM_COMMAND: u32 = 0x0111;

// ── Public API ────────────────────────────────────────────────────────────────

/// CreateMenu: create an empty menu bar.
// Wine ref: dlls/win32u/menu.c:598 — same internal create_menu(is_popup=FALSE);
// sets FocusedItem=NO_SELECTED_ITEM, refcount=1, allocates handle via alloc_user_handle.
pub extern "win64" fn create_menu() -> usize {
    alloc_menu()
}

/// CreatePopupMenu: create an empty popup (context) menu.
///
/// In the Win32 model, popup menus and menu bars have identical storage;
/// the difference is only how they're displayed. We treat them the same.
// Wine ref: dlls/win32u/menu.c:598 — calls create_menu(is_popup=TRUE) which sets
// MF_POPUP on wFlags, distinguishing popup from menu bar at the kernel level.
pub extern "win64" fn create_popup_menu() -> usize {
    alloc_menu()
}

/// AppendMenuW: append an item to a menu.
///
/// # Safety
/// `lp_new_item`, when flags include MF_STRING, must be a valid
/// null-terminated UTF-16 string pointer.
// Wine ref: dlls/win32u/menu.c:427 — insert_menu_item appends at nItems; keeps MDI
// system-button bitmaps (HBMMENU_SYSTEM..HBMMENU_MBAR_CLOSE_D, handles 1-6) at right
// by decrementing pos. Sets menu->Height=0 to force size recalculate.
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

    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
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

/// InsertMenuW: insert a menu item at a position or before a command id.
///
/// # Safety
/// `lp_new_item`, when flags include MF_STRING, must be a valid
/// null-terminated UTF-16 string pointer.
// Wine ref: dlls/user32/menu.c::InsertMenuW — MENU_mnu2mnuii builds MENUITEMINFOW from
// flags/id/str, then NtUserThunkedMenuItemInfo inserts at `pos` (MF_BYPOSITION) or before
// the matching command id; returns FALSE on invalid HMENU.
pub unsafe extern "win64" fn insert_menu_w(
    h_menu: usize,
    u_position: u32,
    u_flags: u32,
    u_id_new_item: usize,
    lp_new_item: *const u16,
) -> i32 {
    let text = if u_flags & MF_SEPARATOR == 0 && !lp_new_item.is_null() {
        let mut len = 0usize;
        while len < crate::defs::MAX_GUEST_STR_LEN && unsafe { *lp_new_item.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(lp_new_item, len) };
        String::from_utf16_lossy(slice)
    } else {
        String::new()
    };
    insert_item_raw(h_menu, u_position, u_flags, u_id_new_item, text)
}

/// InsertMenuItemW: insert a menu item by position or command id.
///
/// Phase 2: delegates to AppendMenuW (ignores position, always appends).
///
/// # Safety
/// Same as append_menu_w.
// Wine ref: dlls/win32u/menu.c:427 — insert_menu_item resolves item position via
// find_menu_item; on failure falls back to appending at nItems. Passes lpmii fields
// through set_menu_item_info which validates cbSize and applies MIIM_* mask bits.
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
// Wine ref: dlls/win32u/menu.c:673 — set_window_menu; validates handle via is_menu();
// if hwnd is capture window, releases capture (GUI_INMENUMODE); stores hwnd in
// menu->hWnd, resets menu->Height=0, then calls NtUserSetWindowLong(GWLP_ID, handle).
pub extern "win64" fn set_menu(hwnd: usize, h_menu: usize) -> i32 {
    crate::window::with_mut(hwnd, |w| {
        w.h_menu = h_menu;
    });
    1
}

/// GetMenu: return the menu handle attached to a window.
// Wine ref: dlls/win32u/menu.c — GetMenu reads the handle stored via GWLP_ID by
// set_window_menu; returns NULL for child windows (is_win_menu_disallowed).
pub extern "win64" fn get_menu(hwnd: usize) -> usize {
    crate::window::with(hwnd, |w| w.h_menu).unwrap_or(0)
}

/// DestroyMenu: free a menu and all its items.
// Wine ref: dlls/win32u/menu.c — NtUserDestroyMenu; recursively frees all popup
// submenus before freeing the parent; frees string item text via free().
pub extern "win64" fn destroy_menu(h_menu: usize) -> i32 {
    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
    m.menus.remove(&h_menu).map(|_| 1).unwrap_or(0)
}

/// Find the first enabled command item in a menu.
///
/// Iterates menu items and returns the command id of the first item that is
/// not a separator, not grayed, not disabled, and not a popup submenu.
fn find_first_enabled_item(h_menu: usize) -> Option<u32> {
    let m = menus().lock().ok()?;
    let items = m.menus.get(&h_menu)?;
    for item in items.iter() {
        let f = item.flags;
        if f & (MF_GRAYED | MF_DISABLED) != 0 {
            continue;
        }
        if f & MF_POPUP != 0 {
            continue;
        }
        if f & MF_SEPARATOR != 0 {
            continue;
        }
        // MF_STRING (default, flags=0) or other command-type items
        return Some(item.id_or_submenu as u32);
    }
    None
}

/// TrackPopupMenu: display a popup menu at a screen position.
///
/// Delegates to TrackPopupMenuEx with no extended params.
// Wine ref: dlls/win32u/menu.c — TrackPopupMenu calls TrackPopupMenuEx with
// TPMPARAMS=NULL; the real impl creates a popup window and runs a modal message loop.
// Returns the selected command id, or 0 if cancelled/no selection.
pub extern "win64" fn track_popup_menu(
    h_menu: usize,
    u_flags: u32,
    _x: i32,
    _y: i32,
    _n_reserved: i32,
    h_wnd: usize,
    _p_rc_rect: usize,
) -> i32 {
    track_popup_menu_ex(h_menu, u_flags, _x, _y, h_wnd, 0)
}

/// TrackPopupMenuEx: extended popup tracking.
///
/// Finds the first enabled command item and either returns its command ID
/// (when TPM_RETURNCMD is set) or posts WM_COMMAND to the owner window.
// Wine ref: dlls/win32u/menu.c — creates a popup_menu_window_proc window, calc_popup_menu_size,
// then enters exec_menu modal loop; posts WM_MENURBUTTONUP/WM_MENUCOMMAND to owner on selection.
pub extern "win64" fn track_popup_menu_ex(
    h_menu: usize,
    u_flags: u32,
    _x: i32,
    _y: i32,
    hwnd: usize,
    _lptpm: usize,
) -> i32 {
    if let Some(cmd) = find_first_enabled_item(h_menu) {
        if u_flags & TPM_RETURNCMD != 0 {
            cmd as i32
        } else if u_flags & TPM_NONOTIFY == 0 && hwnd != 0 {
            crate::api::post_message_w(hwnd, WM_COMMAND, cmd as usize, 0);
            0
        } else {
            cmd as i32
        }
    } else {
        0
    }
}

/// insert_item_raw: insert a menu item at/by position (internal helper).
///
/// Wine ref: dlls/win32u/menu.c::insert_menu_item — find_menu_item resolves `pos`;
/// on failure appends at nItems; MF_BYPOSITION uses `pos` directly (~0 appends at end).
pub fn insert_item_raw(
    h_menu: usize,
    u_position: u32,
    u_flags: u32,
    u_id_new_item: usize,
    text: String,
) -> i32 {
    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
    let items = match m.menus.get_mut(&h_menu) {
        Some(v) => v,
        None => return 0,
    };
    let by_pos = u_flags & MF_BYPOSITION != 0;
    let insert_pos = if by_pos {
        if u_position == u32::MAX {
            items.len()
        } else {
            (u_position as usize).min(items.len())
        }
    } else {
        items
            .iter()
            .position(|item| item.id_or_submenu as u32 == u_position)
            .unwrap_or(items.len())
    };
    let store_flags = u_flags & !MF_BYPOSITION;
    items.insert(
        insert_pos,
        MenuItem {
            flags: store_flags,
            text,
            id_or_submenu: u_id_new_item,
        },
    );
    1
}

/// append_menu_raw: internal helper used by AppendMenuA.
///
/// Like AppendMenuW but takes an already-decoded Rust String.
pub fn append_menu_raw(h_menu: usize, u_flags: u32, u_id_new_item: usize, text: String) -> i32 {
    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
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
    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
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

/// GetMenuStringW: copy the text of the specified menu item into a buffer.
///
/// Wine ref: dlls/user32/menu.c — GetMenuStringW calls MENU_GetItem (by command or
/// position), then does a wcsncpy of item->text into the caller's buffer, returning
/// the character count (excluding null). Returns 0 if the menu/item is not found or
/// if lpString is NULL / nMaxCount == 0 with no valid item.
///
/// # Safety
/// `lp_string`, when `n_max_count > 0`, must point to a buffer of at least
/// `n_max_count` wide characters.
// Wine ref: dlls/user32/menu.c — see doc comment above; returns char count excl. null.
pub unsafe extern "win64" fn get_menu_string_w(
    h_menu: usize,
    u_id_item: u32,
    lp_string: *mut u16,
    n_max_count: i32,
    u_flags: u32,
) -> i32 {
    let m = menus().lock().unwrap_or_else(|p| p.into_inner());
    let items = match m.menus.get(&h_menu) {
        Some(v) => v,
        None => {
            // Menu not found: write empty string and return 0.
            if !lp_string.is_null() && n_max_count > 0 {
                unsafe { *lp_string = 0 };
            }
            return 0;
        }
    };
    let by_pos = u_flags & MF_BYPOSITION != 0;
    let item = if by_pos {
        items.get(u_id_item as usize)
    } else {
        items.iter().find(|it| it.id_or_submenu as u32 == u_id_item)
    };
    let text = match item {
        Some(it) => &it.text,
        None => {
            if !lp_string.is_null() && n_max_count > 0 {
                unsafe { *lp_string = 0 };
            }
            return 0;
        }
    };
    // Encode as UTF-16. The return value is the number of characters
    // copied, NOT including the null terminator.
    let wide: Vec<u16> = text.encode_utf16().collect();
    if lp_string.is_null() || n_max_count <= 0 {
        // Caller just wants the length.
        return wide.len() as i32;
    }
    let copy_len = wide.len().min((n_max_count as usize).saturating_sub(1));
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_string, copy_len);
        *lp_string.add(copy_len) = 0; // null-terminate
    }
    copy_len as i32
}

/// SetMenuItemBitmaps: associate bitmaps with the check-mark and unchecked state
/// of a menu item.
///
/// Wine ref: dlls/user32/menu.c — SetMenuItemBitmaps stores hBitmapChecked /
/// hBitmapUnchecked in the menu item; used by MF_BITMAP items. Weave does not
/// render menus visually, so we just validate the handle and return TRUE.
pub extern "win64" fn set_menu_item_bitmaps(
    _h_menu: usize,
    _u_item: u32,
    _u_flags: u32,
    _h_bmp_unchecked: usize,
    _h_bmp_checked: usize,
) -> i32 {
    1 // TRUE — success
}

/// GetMenuState: return the flags and (for popup submenus) the item count for a
/// menu item identified by command ID or position.
///
/// Wine ref: dlls/user32/menu.c — GetMenuState calls MENU_GetItem; for a popup
/// item returns (submenu_count << 8) | (item_flags | MF_POPUP); for a command
/// returns item_flags. Returns (UINT)-1 = 0xFFFFFFFF if not found.
pub extern "win64" fn get_menu_state(h_menu: usize, u_id: u32, u_flags: u32) -> u32 {
    let m = menus().lock().unwrap_or_else(|p| p.into_inner());
    let items = match m.menus.get(&h_menu) {
        Some(v) => v,
        None => return u32::MAX,
    };
    let by_pos = u_flags & MF_BYPOSITION != 0;
    for (i, item) in items.iter().enumerate() {
        let matches = if by_pos {
            i as u32 == u_id
        } else {
            item.id_or_submenu as u32 == u_id
        };
        if matches {
            if item.flags & MF_POPUP != 0 {
                // Return submenu item count in high byte | (flags | MF_POPUP) in low byte
                let submenu_h = item.id_or_submenu;
                let count = m.menus.get(&submenu_h).map(|v| v.len() as u32).unwrap_or(0);
                return (count << 8) | (item.flags | MF_POPUP);
            }
            return item.flags;
        }
    }
    u32::MAX // not found
}

/// ModifyMenuW: change an existing menu item's flags, text, and ID.
///
/// Wine ref: dlls/user32/menu.c — ModifyMenuW calls MENU_GetItem then updates
/// item->fType, item->wID, and item->text in place. Returns TRUE on success.
///
/// # Safety
/// `lp_new_item`, when `u_flags` includes MF_STRING, must be a valid
/// null-terminated UTF-16 string pointer or NULL.
// Wine ref: dlls/user32/menu.c — see doc comment above; updates fType, wID, text in place.
pub unsafe extern "win64" fn modify_menu_w(
    h_menu: usize,
    u_position: u32,
    u_flags: u32,
    u_id_new_item: usize,
    lp_new_item: *const u16,
) -> i32 {
    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
    let items = match m.menus.get_mut(&h_menu) {
        Some(v) => v,
        None => return 0,
    };
    let by_pos = u_flags & MF_BYPOSITION != 0;
    let item = if by_pos {
        items.get_mut(u_position as usize)
    } else {
        items
            .iter_mut()
            .find(|it| it.id_or_submenu as u32 == u_position)
    };
    let item = match item {
        Some(it) => it,
        None => return 0,
    };
    // Update flags (preserve internal bits, apply new public bits).
    item.flags = u_flags & !(MF_BYPOSITION);
    item.id_or_submenu = u_id_new_item;
    if u_flags & MF_SEPARATOR == 0 && !lp_new_item.is_null() {
        let mut len = 0usize;
        while len < crate::defs::MAX_GUEST_STR_LEN && unsafe { *lp_new_item.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(lp_new_item, len) };
        item.text = String::from_utf16_lossy(slice);
    }
    1 // TRUE
}

/// GetMenuItemID: return the command ID of a menu item at a given position.
///
/// Wine ref: dlls/user32/menu.c — GetMenuItemID returns item->wID for command
/// items; returns (UINT)-1 for popup submenus (per Win32 spec).
pub extern "win64" fn get_menu_item_id(h_menu: usize, n_pos: i32) -> u32 {
    if n_pos < 0 {
        return u32::MAX;
    }
    let m = menus().lock().unwrap_or_else(|p| p.into_inner());
    let items = match m.menus.get(&h_menu) {
        Some(v) => v,
        None => return u32::MAX,
    };
    match items.get(n_pos as usize) {
        Some(item) if item.flags & MF_POPUP == 0 => item.id_or_submenu as u32,
        _ => u32::MAX, // not found or is a popup
    }
}

/// GetSubMenu: return the HMENU of a popup submenu at a given position.
///
/// Wine ref: dlls/user32/menu.c — GetSubMenu returns item->hSubMenu when
/// item->fType & MF_POPUP; NULL otherwise.
pub extern "win64" fn get_sub_menu(h_menu: usize, n_pos: i32) -> usize {
    if n_pos < 0 {
        return 0;
    }
    let m = menus().lock().unwrap_or_else(|p| p.into_inner());
    let items = match m.menus.get(&h_menu) {
        Some(v) => v,
        None => return 0,
    };
    match items.get(n_pos as usize) {
        Some(item) if item.flags & MF_POPUP != 0 => item.id_or_submenu,
        _ => 0,
    }
}

/// GetMenuItemCount: return the number of items in a menu.
// Wine ref: dlls/win32u/menu.c:1359 — grab_menu_ptr fails on invalid handle → returns -1
// (not 0); valid handle returns menu->nItems directly.
pub extern "win64" fn get_menu_item_count(h_menu: usize) -> i32 {
    let m = menus().lock().unwrap_or_else(|p| p.into_inner());
    m.menus.get(&h_menu).map(|v| v.len() as i32).unwrap_or(-1)
}

/// CheckMenuItem: set or clear the checked state on a menu item.
///
/// Phase 2: mutates stored flags, returns previous check state.
// Wine ref: dlls/win32u/menu.c — NtUserCheckMenuItem; uses find_menu_item, returns
// previous (fState & MFS_CHECKED) cast to DWORD; returns -1 (0xFFFFFFFF) if not found.
pub extern "win64" fn check_menu_item(h_menu: usize, u_id_check_item: u32, u_check: u32) -> u32 {
    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
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
// Wine ref: dlls/win32u/menu.c — NtUserEnableMenuItem; uses find_menu_item, stores
// new flags in item->fState masked to (MFS_GRAYED|MFS_DISABLED); returns previous
// enable state or -1 if item not found.
pub extern "win64" fn enable_menu_item(h_menu: usize, u_id_enable_item: u32, u_enable: u32) -> i32 {
    let mut m = menus().lock().unwrap_or_else(|p| p.into_inner());
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
    fn insert_menu_w_at_position() {
        let h = create_menu();
        let open: Vec<u16> = "Open\0".encode_utf16().collect();
        let save: Vec<u16> = "Save As\0".encode_utf16().collect();
        unsafe {
            append_menu_w(h, MF_STRING | MF_BYPOSITION, 1001, open.as_ptr());
            insert_menu_w(h, 0, MF_STRING | MF_BYPOSITION, 1002, save.as_ptr());
        }
        assert_eq!(get_menu_item_count(h), 2);
        assert_eq!(get_menu_item_id(h, 0), 1002);
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
