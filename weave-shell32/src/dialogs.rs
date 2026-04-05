//! File dialog stubs for Weave.
//!
//! `GetOpenFileNameW` and `GetSaveFileNameW` live in `comdlg32.dll`.
//!
//! # Implementation
//!
//! On Linux: attempts to open a native file picker by spawning `zenity`
//! (GTK) or `kdialog` (KDE) as a child process. If neither is available
//! (e.g. headless CI), returns FALSE (user cancelled).
//!
//! The selected path is converted from the Linux prefix tree back to a
//! Windows path before being written into `lpstrFile`.

use weave_core::prefix;

// ── OPENFILENAMEW layout (152 bytes on Win64) ─────────────────────────────────

/// The subset of OPENFILENAMEW fields we actually read.
///
/// Using raw byte offsets avoids the fragile repr(C) padding dance.
#[allow(dead_code)]
struct Ofn {
    /// `lpstrFile`: output buffer pointer.
    lp_str_file: *mut u16,
    /// `nMaxFile`: capacity of `lpstrFile` in `u16` code units.
    n_max_file: u32,
    /// `lpstrInitialDir`: optional starting directory (Win32 path).
    lp_str_initial_dir: *const u16,
    /// `lpstrTitle`: optional dialog title.
    lp_str_title: *const u16,
    /// `lpstrFilter`: optional filter string (double-NUL terminated pairs).
    lp_str_filter: *const u16,
    /// `lpstrDefExt`: optional default extension.
    lp_str_def_ext: *const u16,
}

unsafe fn read_ofn(p: *const u8) -> Ofn {
    unsafe {
        Ofn {
            lp_str_file: *(p.add(48) as *const *mut u16),
            n_max_file: *(p.add(56) as *const u32),
            lp_str_initial_dir: *(p.add(80) as *const *const u16),
            lp_str_title: *(p.add(88) as *const *const u16),
            lp_str_filter: *(p.add(24) as *const *const u16),
            lp_str_def_ext: *(p.add(104) as *const *const u16),
        }
    }
}

// ── Wide string helpers ───────────────────────────────────────────────────────

/// Decode a null-terminated UTF-16 pointer to a Rust String.
unsafe fn decode_wide_ptr(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(p, len);
        Some(String::from_utf16_lossy(slice).to_owned())
    }
}

/// Encode a Rust string into a UTF-16 buffer (null-terminated, truncated to `cap`).
fn encode_wide_into(s: &str, buf: *mut u16, cap: u32) {
    if buf.is_null() || cap == 0 {
        return;
    }
    let cap = cap as usize;
    let mut i = 0usize;
    for ch in s.encode_utf16() {
        if i + 1 >= cap {
            break;
        }
        unsafe { *buf.add(i) = ch };
        i += 1;
    }
    unsafe { *buf.add(i) = 0 };
}

// ── Reverse path translation (Linux → Windows) ───────────────────────────────

/// Convert an absolute Linux path back to a Win32 path if it lives inside the
/// Weave prefix. Returns `None` if the path is outside the prefix.
///
/// `{prefix}/drive_c/foo/bar` → `C:\foo\bar`
fn linux_to_win_path(linux: &str) -> Option<String> {
    let prefix = prefix::get().to_string_lossy().into_owned();
    // Strip trailing slash from prefix for clean joining.
    let prefix = prefix.trim_end_matches('/');

    // Pattern: {prefix}/drive_{letter}/...
    for ch in b'a'..=b'z' {
        let letter = ch as char;
        let root = format!("{}/drive_{}/", prefix, letter);
        if linux.starts_with(&root) {
            let rest = &linux[root.len()..];
            let win_rest = rest.replace('/', "\\");
            return Some(format!(
                "{}:\\{}",
                letter.to_uppercase().next().unwrap(),
                win_rest
            ));
        }
        // Also handle paths that exactly equal the drive root.
        let root_exact = format!("{}/drive_{}", prefix, letter);
        if linux == root_exact {
            return Some(format!("{}:\\", letter.to_uppercase().next().unwrap()));
        }
    }
    // Path is outside the prefix (e.g. /home/user/...). Return as-is with a
    // fake drive letter Z: so the app can still see the path.
    Some(format!(
        "Z:\\{}",
        linux.trim_start_matches('/').replace('/', "\\")
    ))
}

// ── zenity / kdialog subprocess invocation ───────────────────────────────────

/// Attempt to open a file picker using `zenity` or `kdialog`.
/// Returns the selected Linux path on success, or `None` if cancelled / unavailable.
fn run_file_dialog(save: bool, title: Option<&str>, initial_dir: Option<&str>) -> Option<String> {
    // Try zenity first (GTK).
    let zenity_result = run_zenity(save, title, initial_dir);
    if zenity_result.is_some() {
        return zenity_result;
    }
    // Fall back to kdialog (KDE).
    run_kdialog(save, title, initial_dir)
}

fn run_zenity(save: bool, title: Option<&str>, initial_dir: Option<&str>) -> Option<String> {
    let mut cmd = std::process::Command::new("zenity");
    cmd.arg("--file-selection");
    if save {
        cmd.arg("--save");
        cmd.arg("--confirm-overwrite");
    }
    if let Some(t) = title {
        cmd.arg(format!("--title={t}"));
    }
    if let Some(dir) = initial_dir {
        cmd.arg(format!("--filename={dir}/"));
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

fn run_kdialog(save: bool, title: Option<&str>, initial_dir: Option<&str>) -> Option<String> {
    let mut cmd = std::process::Command::new("kdialog");
    if save {
        cmd.arg("--getsavefilename");
    } else {
        cmd.arg("--getopenfilename");
    }
    if let Some(dir) = initial_dir {
        cmd.arg(dir);
    } else {
        cmd.arg(".");
    }
    if let Some(t) = title {
        cmd.arg("--title");
        cmd.arg(t);
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

// ── Win32 API functions ───────────────────────────────────────────────────────

// ── ANSI stubs ────────────────────────────────────────────────────────────────

/// GetOpenFileNameA — ANSI variant. Returns 0 (cancelled/unsupported).
///
/// # Safety
/// `lp_ofn` is ignored.
pub unsafe extern "win64" fn get_open_file_name_a(_lp_ofn: *mut u8) -> i32 {
    0 // FALSE — not implemented; apps fall back or show error
}

/// GetSaveFileNameA — ANSI variant. Returns 0 (cancelled/unsupported).
///
/// # Safety
/// `lp_ofn` is ignored.
pub unsafe extern "win64" fn get_save_file_name_a(_lp_ofn: *mut u8) -> i32 {
    0
}

/// ChooseFontA — display the font chooser dialog. Returns 0 (cancelled).
///
/// # Safety
/// `lp_cf` is ignored.
pub unsafe extern "win64" fn choose_font_a(_lp_cf: *mut u8) -> i32 {
    0
}

/// ChooseColorA — display the color chooser dialog. Returns 0 (cancelled).
///
/// # Safety
/// `lp_cc` is ignored.
pub unsafe extern "win64" fn choose_color_a(_lp_cc: *mut u8) -> i32 {
    0
}

/// GetOpenFileNameW: display the system Open dialog box.
///
/// Returns TRUE if the user selects a file; FALSE if cancelled or on error.
///
/// # Safety
/// `lp_ofn` must be a valid pointer to an `OPENFILENAMEW` struct.
pub unsafe extern "win64" fn get_open_file_name_w(lp_ofn: *mut u8) -> i32 {
    if lp_ofn.is_null() {
        return 0;
    }
    let ofn = unsafe { read_ofn(lp_ofn) };

    let title = unsafe { decode_wide_ptr(ofn.lp_str_title) };
    let initial_dir_win = unsafe { decode_wide_ptr(ofn.lp_str_initial_dir) };

    // Translate initial directory from Windows to Linux if provided.
    let initial_dir_linux = initial_dir_win.as_deref().and_then(|win| {
        weave_common::path::WinPathTranslator::new(prefix::get().to_path_buf())
            .to_linux_str(win)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    });

    let result = run_file_dialog(false, title.as_deref(), initial_dir_linux.as_deref());

    match result {
        None => 0, // cancelled
        Some(linux_path) => {
            let win_path = match linux_to_win_path(&linux_path) {
                Some(p) => p,
                None => return 0,
            };
            encode_wide_into(&win_path, ofn.lp_str_file, ofn.n_max_file);
            1
        }
    }
}

// ── CommDlgExtendedError ──────────────────────────────────────────────────────

/// CommDlgExtendedError — return the last common dialog error code.
///
/// Returns 0 (no error) — stub.
pub extern "win64" fn comm_dlg_extended_error() -> u32 {
    0
}

/// GetSaveFileNameW: display the system Save dialog box.
///
/// Returns TRUE if the user selects a filename; FALSE if cancelled or on error.
///
/// # Safety
/// `lp_ofn` must be a valid pointer to an `OPENFILENAMEW` struct.
pub unsafe extern "win64" fn get_save_file_name_w(lp_ofn: *mut u8) -> i32 {
    if lp_ofn.is_null() {
        return 0;
    }
    let ofn = unsafe { read_ofn(lp_ofn) };

    let title = unsafe { decode_wide_ptr(ofn.lp_str_title) };
    let initial_dir_win = unsafe { decode_wide_ptr(ofn.lp_str_initial_dir) };

    let initial_dir_linux = initial_dir_win.as_deref().and_then(|win| {
        weave_common::path::WinPathTranslator::new(prefix::get().to_path_buf())
            .to_linux_str(win)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    });

    // If a default extension was provided and the filename buffer has an
    // initial value, we could pass it to zenity as --filename. For Phase 2,
    // we just open the dialog at the initial directory.
    let result = run_file_dialog(true, title.as_deref(), initial_dir_linux.as_deref());

    match result {
        None => 0,
        Some(mut linux_path) => {
            // Append default extension if the user didn't type one.
            if let Some(ext_wide) = unsafe { decode_wide_ptr(ofn.lp_str_def_ext) } {
                if !ext_wide.is_empty() && !linux_path.contains('.') {
                    linux_path = format!("{}.{}", linux_path, ext_wide);
                }
            }
            let win_path = match linux_to_win_path(&linux_path) {
                Some(p) => p,
                None => return 0,
            };
            encode_wide_into(&win_path, ofn.lp_str_file, ofn.n_max_file);
            1
        }
    }
}
