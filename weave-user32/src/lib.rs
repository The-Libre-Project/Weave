//! user32.dll stubs for Weave.
//!
//! Phase 2 scope: window creation, message loop, basic input, paint stubs.
//! Graphics (GDI) are in weave-gdi32 (Phase 2 Step 4).
//!
//! # Architecture
//!
//! - `defs`    — Win32 struct layouts and constants
//! - `class`   — window class registry (`RegisterClassW` → here)
//! - `window`  — HWND table (one entry per created window)
//! - `queue`   — global message queue (VecDeque<MsgEntry>)
//! - `backend` — X11 connection + event translation (Linux-only via x11rb)
//! - `api`     — Win32 API function implementations

pub mod api;
pub mod backend;
pub mod class;
pub mod clipboard;
pub mod defs;
pub mod menu;
pub mod queue;
pub mod window;

/// Resolve a user32.dll import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("user32.dll") {
        return None;
    }
    use api::*;
    match func {
        // Window class registration
        "RegisterClassW" => {
            Some(register_class_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RegisterClassExW" => {
            Some(register_class_ex_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Window lifecycle
        "CreateWindowExW" => Some(
            create_window_ex_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "ShowWindow" => Some(show_window as *const () as usize),
        "UpdateWindow" => Some(update_window as *const () as usize),
        "DestroyWindow" => Some(destroy_window as *const () as usize),
        // Message loop
        "GetMessageW" => {
            Some(get_message_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "PeekMessageW" => Some(
            peek_message_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "TranslateMessage" => {
            Some(translate_message as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "DispatchMessageW" => {
            Some(dispatch_message_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "PostQuitMessage" => Some(post_quit_message as *const () as usize),
        "PostMessageW" => Some(post_message_w as *const () as usize),
        "SendMessageW" => Some(send_message_w as *const () as usize),
        // Default window procedure
        "DefWindowProcW" => Some(def_window_proc_w as *const () as usize),
        // Geometry
        "GetClientRect" => {
            Some(get_client_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetWindowRect" => {
            Some(get_window_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "InvalidateRect" => {
            Some(invalidate_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "MoveWindow" => Some(move_window as *const () as usize),
        "AdjustWindowRect" => {
            Some(adjust_window_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "AdjustWindowRectEx" => Some(
            adjust_window_rect_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Window title
        "SetWindowTextW" => {
            Some(set_window_text_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetWindowTextW" => {
            Some(get_window_text_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // System metrics
        "GetSystemMetrics" => Some(get_system_metrics as *const () as usize),
        // Cursor / icon
        "LoadCursorW" => {
            Some(load_cursor_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LoadIconW" => {
            Some(load_icon_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LoadImageW" => Some(
            load_image_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "SetCursor" => Some(set_cursor as *const () as usize),
        "ShowCursor" => Some(show_cursor as *const () as usize),
        // Message box
        "MessageBoxW" => {
            Some(message_box_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        // DC (user32 owns GetDC/ReleaseDC, not gdi32)
        "GetDC" => Some(get_dc as *const () as usize),
        "ReleaseDC" => Some(release_dc as *const () as usize),
        // Paint
        "BeginPaint" => {
            Some(begin_paint as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "EndPaint" => Some(end_paint as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        // Foreground / desktop
        "GetForegroundWindow" => Some(get_foreground_window as *const () as usize),
        "SetForegroundWindow" => Some(set_foreground_window as *const () as usize),
        "GetDesktopWindow" => Some(get_desktop_window as *const () as usize),
        // Clipboard
        "OpenClipboard" => Some(clipboard::open_clipboard as *const () as usize),
        "CloseClipboard" => Some(clipboard::close_clipboard as *const () as usize),
        "EmptyClipboard" => Some(clipboard::empty_clipboard as *const () as usize),
        "SetClipboardData" => Some(clipboard::set_clipboard_data as *const () as usize),
        "GetClipboardData" => Some(clipboard::get_clipboard_data as *const () as usize),
        "IsClipboardFormatAvailable" => {
            Some(clipboard::is_clipboard_format_available as *const () as usize)
        }
        "CountClipboardFormats" => Some(clipboard::count_clipboard_formats as *const () as usize),
        "GetClipboardOwner" => Some(clipboard::get_clipboard_owner as *const () as usize),
        // Menus
        "CreateMenu" => Some(menu::create_menu as *const () as usize),
        "CreatePopupMenu" => Some(menu::create_popup_menu as *const () as usize),
        "AppendMenuW" => {
            Some(menu::append_menu_w as unsafe fn(_, _, _, _) -> _ as *const () as usize)
        }
        "InsertMenuItemW" => {
            Some(menu::insert_menu_item_w as unsafe fn(_, _, _, _) -> _ as *const () as usize)
        }
        "SetMenu" => Some(menu::set_menu as *const () as usize),
        "GetMenu" => Some(menu::get_menu as *const () as usize),
        "DestroyMenu" => Some(menu::destroy_menu as *const () as usize),
        "TrackPopupMenu" => Some(menu::track_popup_menu as *const () as usize),
        "TrackPopupMenuEx" => Some(menu::track_popup_menu_ex as *const () as usize),
        "GetMenuItemCount" => Some(menu::get_menu_item_count as *const () as usize),
        "CheckMenuItem" => Some(menu::check_menu_item as *const () as usize),
        "EnableMenuItem" => Some(menu::enable_menu_item as *const () as usize),
        _ => None,
    }
}
