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
pub mod font;
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
        "LoadCursorA" | "LoadCursorW" => {
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
        // Display and mode enumeration
        "EnumDisplayDevicesW" => Some(
            enum_display_devices_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "EnumDisplaySettingsW" => Some(
            enum_display_settings_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "EnumDisplaySettingsExW" => Some(
            enum_display_settings_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "ChangeDisplaySettingsW" => Some(
            change_display_settings_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "ChangeDisplaySettingsExW" => Some(
            change_display_settings_ex_w as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        // Monitor handle functions
        "MonitorFromWindow" => Some(monitor_from_window as *const () as usize),
        "MonitorFromPoint" => Some(monitor_from_point as *const () as usize),
        "MonitorFromRect" => {
            Some(monitor_from_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetMonitorInfoW" => {
            Some(get_monitor_info_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "EnumDisplayMonitors" => Some(
            enum_display_monitors as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Window long + SetWindowPos
        "GetWindowLongW" => Some(get_window_long_w as *const () as usize),
        "GetWindowLongPtrW" => Some(get_window_long_ptr_w as *const () as usize),
        "SetWindowLongW" => Some(set_window_long_w as *const () as usize),
        "SetWindowLongPtrW" => Some(set_window_long_ptr_w as *const () as usize),
        "SetWindowPos" => Some(set_window_pos as *const () as usize),
        // Window queries
        "FindWindowW" => {
            Some(find_window_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindWindowA" => {
            Some(find_window_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "IsWindow" => Some(is_window as *const () as usize),
        "IsWindowVisible" => Some(is_window_visible as *const () as usize),
        "GetWindowThreadProcessId" => Some(
            get_window_thread_process_id as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "ScreenToClient" => {
            Some(screen_to_client as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "ClientToScreen" => {
            Some(client_to_screen as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Cursor + misc window ops
        "GetCursorPos" => {
            Some(get_cursor_pos as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetCursorPos" => Some(set_cursor_pos as *const () as usize),
        "EnableWindow" => Some(enable_window as *const () as usize),
        "IsWindowEnabled" => Some(is_window_enabled as *const () as usize),
        "GetParent" => Some(get_parent as *const () as usize),
        "SetParent" => Some(set_parent as *const () as usize),
        "BringWindowToTop" => Some(bring_window_to_top as *const () as usize),
        "WindowFromPoint" => Some(window_from_point as *const () as usize),
        _ => None,
    }
}
