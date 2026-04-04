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
        "SetWindowTextA" => {
            Some(set_window_text_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetWindowTextW" => {
            Some(get_window_text_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // Focus
        "SetFocus" => Some(set_focus as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "SetKeyboardState" => {
            Some(set_keyboard_state as unsafe extern "win64" fn(_) -> _ as *const () as usize)
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
        // DPI awareness stubs
        "SetProcessDPIAware" => Some(set_process_dpi_aware as *const () as usize),
        "GetDpiForWindow" => Some(get_dpi_for_window as *const () as usize),
        "GetDpiForSystem" => Some(get_dpi_for_system as *const () as usize),
        "AdjustWindowRectExForDpi" => Some(
            adjust_window_rect_ex_for_dpi as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        "SetProcessDpiAwarenessContext" => {
            Some(set_process_dpi_awareness_context as *const () as usize)
        }
        "GetDpiAwarenessContextForProcess" => {
            Some(get_dpi_awareness_context_for_process as *const () as usize)
        }
        "AreDpiAwarenessContextsEqual" => {
            Some(are_dpi_awareness_contexts_equal as *const () as usize)
        }
        // Input state stubs
        "GetKeyState" => Some(get_key_state as *const () as usize),
        "GetAsyncKeyState" => Some(get_async_key_state as *const () as usize),
        "MapVirtualKeyW" => Some(map_virtual_key_w as *const () as usize),
        "MapVirtualKeyExW" => Some(map_virtual_key_ex_w as *const () as usize),
        "GetKeyboardLayout" => Some(get_keyboard_layout as *const () as usize),
        "GetKeyboardLayoutList" => Some(
            get_keyboard_layout_list as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "VkKeyScanW" => Some(vk_key_scan_w as *const () as usize),
        "GetKeyboardState" => {
            Some(get_keyboard_state as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ToUnicodeEx" => Some(
            to_unicode_ex as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // ── ANSI window class wrappers ───────────────────────────��────────
        "RegisterClassA" => {
            Some(register_class_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RegisterClassExA" => {
            Some(register_class_ex_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // ── ANSI window creation ──────────────────────────────────────────
        "CreateWindowExA" => Some(
            create_window_ex_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        // ── ANSI message loop ─────────────────────────────────────────────
        "GetMessageA" => {
            Some(get_message_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "PeekMessageA" => Some(
            peek_message_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "DispatchMessageA" => {
            Some(dispatch_message_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "PostMessageA" => Some(post_message_a as *const () as usize),
        "SendMessageA" => Some(send_message_a as *const () as usize),
        "DefWindowProcA" => Some(def_window_proc_a as *const () as usize),
        // ── ANSI window text / class ──────────────────────────────────────
        "GetWindowTextA" => {
            Some(get_window_text_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "GetWindowTextLengthA" => Some(get_window_text_length_a as *const () as usize),
        "GetWindowLongPtrA" => Some(get_window_long_ptr_a as *const () as usize),
        "SetWindowLongPtrA" => Some(set_window_long_ptr_a as *const () as usize),
        "SetClassLongPtrA" => Some(
            set_class_long_ptr_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        // ── ANSI resource loading ─────────────────────────────────────────
        "LoadIconA" => {
            Some(load_icon_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LoadImageA" => Some(
            load_image_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "DestroyIcon" => Some(destroy_icon as *const () as usize),
        // ── ANSI message box ──────────────────────────────────────────────
        "MessageBoxA" => {
            Some(message_box_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "MessageBoxIndirectW" => {
            Some(message_box_indirect_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // ── ANSI menu helpers ─────────────────────────────────────────────
        "AppendMenuA" => {
            Some(append_menu_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "InsertMenuA" => Some(
            insert_menu_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetSystemMenu" => Some(get_system_menu as *const () as usize),
        "DeleteMenu" => Some(delete_menu as *const () as usize),
        // ── Dialog stubs ──────────────────────────────────────────────────
        "DefDlgProcA" => Some(def_dlg_proc_a as *const () as usize),
        "DialogBoxParamA" => Some(
            dialog_box_param_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateDialogParamA" => Some(
            create_dialog_param_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "EndDialog" => Some(end_dialog as *const () as usize),
        "GetDlgItem" => Some(get_dlg_item as *const () as usize),
        "GetDlgItemTextA" => Some(
            get_dlg_item_text_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetDlgItemTextW" => Some(
            get_dlg_item_text_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "SetDlgItemTextA" => Some(
            set_dlg_item_text_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "SetDlgItemTextW" => Some(
            set_dlg_item_text_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "SendDlgItemMessageA" => Some(send_dlg_item_message_a as *const () as usize),
        "CheckDlgButton" => Some(check_dlg_button as *const () as usize),
        "IsDlgButtonChecked" => Some(is_dlg_button_checked as *const () as usize),
        "CheckRadioButton" => Some(check_radio_button as *const () as usize),
        "IsDialogMessageA" => {
            Some(is_dialog_message_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "MapDialogRect" => {
            Some(map_dialog_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // ── Window state ──────────────────────────────────────────────────
        "IsIconic" => Some(is_iconic as *const () as usize),
        "IsZoomed" => Some(is_zoomed as *const () as usize),
        "FlashWindow" => Some(flash_window as *const () as usize),
        "GetWindowPlacement" => {
            Some(get_window_placement as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetWindowPlacement" => {
            Some(set_window_placement as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // ── Timers ────────────────────────────────────────────────────────
        "SetTimer" => {
            Some(set_timer as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "KillTimer" => Some(kill_timer as *const () as usize),
        // ── Message helpers ───────────────────────────────────────────────
        "GetMessageTime" => Some(get_message_time as *const () as usize),
        "GetQueueStatus" => Some(get_queue_status as *const () as usize),
        "MsgWaitForMultipleObjects" => Some(
            msg_wait_for_multiple_objects as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        // ── Mouse capture ─────────────────────────────────────────────────
        "GetCapture" => Some(get_capture as *const () as usize),
        "SetCapture" => Some(set_capture as *const () as usize),
        "ReleaseCapture" => Some(release_capture as *const () as usize),
        "SetActiveWindow" => Some(set_active_window as *const () as usize),
        // ── System colors ─────────────────────────────────────────────────
        "GetSysColor" => Some(get_sys_color as *const () as usize),
        "GetSysColorBrush" => Some(get_sys_color_brush as *const () as usize),
        // ── Scrollbar ───────────────────────────────���────────────────────
        "GetScrollInfo" => {
            Some(get_scroll_info as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "SetScrollInfo" => {
            Some(set_scroll_info as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        // ── Caret ────────────────────────────────────────────────────────
        "CreateCaret" => Some(create_caret as *const () as usize),
        "DestroyCaret" => Some(destroy_caret as *const () as usize),
        "ShowCaret" => Some(show_caret as *const () as usize),
        "HideCaret" => Some(hide_caret as *const () as usize),
        "SetCaretPos" => Some(set_caret_pos as *const () as usize),
        "GetCaretBlinkTime" => Some(get_caret_blink_time as *const () as usize),
        // ── Misc ──────────────────────────────────────────────────────────
        "MessageBeep" => Some(message_beep as *const () as usize),
        "GetDoubleClickTime" => Some(get_double_click_time as *const () as usize),
        "OffsetRect" => {
            Some(offset_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "DrawEdge" => {
            Some(draw_edge as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "DrawIconEx" => Some(
            draw_icon_ex as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegisterClipboardFormatA" => Some(
            register_clipboard_format_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "RegisterWindowMessageA" => Some(
            register_window_message_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SystemParametersInfoA" => Some(
            system_parameters_info_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "ToAsciiEx" => Some(
            to_ascii_ex as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        _ => None,
    }
}
