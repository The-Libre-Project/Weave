//! shell32.dll, comdlg32.dll, and winspool.drv stubs for Weave.
//!
//! # Phase 2 scope
//!
//! - `comdlg32.dll`: `GetOpenFileNameW`, `GetSaveFileNameW` — native file
//!   picker via `zenity` / `kdialog` subprocess; falls back to "cancelled"
//!   on headless systems.
//! - `shell32.dll`: `SHGetFolderPathW`, `SHGetSpecialFolderPathW`,
//!   `SHGetKnownFolderPath`, `ShellExecuteW`, `CommandLineToArgvW`,
//!   `CoTaskMemFree`.
//! - `WINSPOOL.DRV`: printer enumeration stubs — return "no printers
//!   available" without touching the spooler.
//!
//! # Crate boundary note
//! This crate depends on `weave-notify` (a thin `notify-send` subprocess bridge).
//! `weave-notify` is an infrastructure utility crate, not a Windows DLL crate —
//! it has no Win32 API surface. This is NOT a DLL-to-DLL import violation.
//! See `weave-gdi32/src/lib.rs` for the convention on documenting crate exceptions.

mod dialogs;
mod shell;
mod winspool;

/// Resolve a `shell32.dll`, `comdlg32.dll`, or `WINSPOOL.DRV` import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if dll.eq_ignore_ascii_case("comdlg32.dll") {
        return resolve_comdlg32(func);
    }
    if dll.eq_ignore_ascii_case("shell32.dll") {
        return resolve_shell32(func);
    }
    // ole32.dll CoTaskMemFree is often resolved alongside shell functions.
    if dll.eq_ignore_ascii_case("ole32.dll") {
        return match func {
            "CoTaskMemFree" => Some(shell::co_task_mem_free as *const () as usize),
            _ => None,
        };
    }
    // WINSPOOL.DRV — printer spooler stubs (no-printer-available sentinels).
    if dll.eq_ignore_ascii_case("winspool.drv") {
        return winspool::resolve(func);
    }
    None
}

fn resolve_comdlg32(func: &str) -> Option<usize> {
    match func {
        "GetOpenFileNameW" => Some(
            dialogs::get_open_file_name_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetSaveFileNameW" => Some(
            dialogs::get_save_file_name_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetOpenFileNameA" => Some(
            dialogs::get_open_file_name_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetSaveFileNameA" => Some(
            dialogs::get_save_file_name_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "ChooseFontA" => {
            Some(dialogs::choose_font_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ChooseColorA" => {
            Some(dialogs::choose_color_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CommDlgExtendedError" => {
            Some(dialogs::comm_dlg_extended_error as extern "win64" fn() -> _ as *const () as usize)
        }
        "PrintDlgExW" => {
            Some(dialogs::print_dlg_ex_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        _ => None,
    }
}

fn resolve_shell32(func: &str) -> Option<usize> {
    match func {
        "SHGetFolderPathA" => Some(
            shell::sh_get_folder_path_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SHGetFolderPathW" => Some(
            shell::sh_get_folder_path_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SHGetSpecialFolderPathW" => Some(
            shell::sh_get_special_folder_path_w as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "SHGetKnownFolderPath" => Some(
            shell::sh_get_known_folder_path as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "CoTaskMemFree" => Some(shell::co_task_mem_free as *const () as usize),
        "ShellExecuteW" => Some(
            shell::shell_execute_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CommandLineToArgvW" => Some(
            shell::command_line_to_argv_w as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "Shell_NotifyIconW" => Some(
            shell::shell_notify_icon_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "ShellExecuteA" => Some(
            shell::shell_execute_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SHBrowseForFolderW" => Some(
            shell::sh_browse_for_folder_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SHGetPathFromIDListW" => Some(
            shell::sh_get_path_from_id_list_w as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "DragAcceptFiles" => {
            Some(shell::drag_accept_files as extern "win64" fn(_, _) as *const () as usize)
        }
        "DragQueryFileW" => Some(
            shell::drag_query_file_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "DragFinish" => Some(shell::drag_finish as extern "win64" fn(_) as *const () as usize),
        "ExtractIconExW" => Some(
            shell::extract_icon_ex_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SHGetDesktopFolder" => Some(
            shell::sh_get_desktop_folder as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SHGetSpecialFolderLocation" => Some(
            shell::sh_get_special_folder_location as unsafe extern "win64" fn(_, _, _) -> _
                as *const () as usize,
        ),
        "SHGetFileInfoW" => Some(
            shell::sh_get_file_info_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SHFileOperationW" => Some(
            shell::sh_file_operation_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SHChangeNotify" => Some(
            shell::sh_change_notify as unsafe extern "win64" fn(_, _, _, _) as *const () as usize,
        ),
        "ShellExecuteExW" => Some(
            shell::shell_execute_ex_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        _ => None,
    }
}
