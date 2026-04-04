//! shell32.dll and comdlg32.dll stubs for Weave.
//!
//! # Phase 2 scope
//!
//! - `comdlg32.dll`: `GetOpenFileNameW`, `GetSaveFileNameW` — native file
//!   picker via `zenity` / `kdialog` subprocess; falls back to "cancelled"
//!   on headless systems.
//! - `shell32.dll`: `SHGetFolderPathW`, `SHGetSpecialFolderPathW`,
//!   `SHGetKnownFolderPath`, `ShellExecuteW`, `CommandLineToArgvW`,
//!   `CoTaskMemFree`.

mod dialogs;
mod shell;

/// Resolve a `shell32.dll` or `comdlg32.dll` import to a stub address.
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
        _ => None,
    }
}

fn resolve_shell32(func: &str) -> Option<usize> {
    match func {
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
            shell::shell_notify_icon_w as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        _ => None,
    }
}
