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
        "PrintDlgW" => {
            Some(dialogs::print_dlg_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ChooseColorW" => {
            Some(dialogs::choose_color_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "PageSetupDlgW" => {
            Some(dialogs::page_setup_dlg_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
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
        // Q-Dir PIDL ordinals (#2, #4, #16, #17, #18, #21, #25, #68, #88, #155, #190)
        "ILFindChild" | "#2" => Some(
            shell::il_find_child as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "ILGetSize" | "#4" => Some(
            shell::il_get_size as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "ILClone" | "#16" => Some(
            shell::il_clone as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "ILFree" | "#17" => Some(
            shell::il_free as unsafe extern "win64" fn(_) as *const () as usize,
        ),
        "ILGetNext" | "#18" => Some(
            shell::il_get_next as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "ILIsEqual" | "#21" => Some(
            shell::il_is_equal as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "ILCombine" | "#25" => Some(
            shell::il_combine as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SHMapPIDLToSystemImageListIndex" | "#68" => Some(
            shell::sh_map_pidl_to_image_index as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "NTSHChangeNotifyRegister" | "#88" => Some(
            shell::nt_sh_change_notify_register
                as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "#155" => Some(shell::shell32_ord155 as unsafe extern "win64" fn() -> _ as *const () as usize),
        "#190" => Some(shell::shell32_ord190 as unsafe extern "win64" fn() -> _ as *const () as usize),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_comdlg32_q_dir_imports() {
        // Q-Dir requires these five comdlg32 symbols to resolve.
        let required = [
            "GetOpenFileNameW",
            "GetSaveFileNameW",
            "ChooseColorW",
            "PageSetupDlgW",
            "PrintDlgW",
        ];
        for sym in &required {
            assert!(
                resolve("comdlg32.dll", sym).is_some(),
                "comdlg32.dll!{sym} must resolve"
            );
        }
    }

    #[test]
    fn resolve_comdlg32_case_insensitive() {
        assert!(resolve("COMDLG32.DLL", "GetOpenFileNameW").is_some());
    }

    #[test]
    fn resolve_comdlg32_unknown_returns_none() {
        assert!(resolve("comdlg32.dll", "NonExistent").is_none());
    }

    #[test]
    fn resolve_shell32_pidl_ordinals() {
        // Q-Dir PIDL ordinals: #2, #4, #16, #17, #18, #21, #25, #68, #88, #155, #190
        let ordinals = ["#2", "#4", "#16", "#17", "#18", "#21", "#25", "#68", "#88", "#155", "#190"];
        for ord in &ordinals {
            assert!(
                resolve("shell32.dll", ord).is_some(),
                "shell32.dll!{ord} must resolve"
            );
        }
    }

    #[test]
    fn resolve_shell32_pidl_by_name() {
        let named = [
            "ILFindChild",
            "ILGetSize",
            "ILClone",
            "ILFree",
            "ILGetNext",
            "ILIsEqual",
            "ILCombine",
            "SHMapPIDLToSystemImageListIndex",
            "NTSHChangeNotifyRegister",
        ];
        for name in &named {
            assert!(
                resolve("shell32.dll", name).is_some(),
                "shell32.dll!{name} must resolve"
            );
        }
    }
}
