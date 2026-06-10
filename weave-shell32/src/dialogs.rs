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
//
// Win64 field offsets (MSDN OPENFILENAMEW member order + 8-byte pointer alignment):
//   lpstrFilter @24, nFilterIndex @44, lpstrFile @48, nMaxFile @56,
//   lpstrInitialDir @80, lpstrTitle @88, lpstrDefExt @104.
// Ref: https://learn.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-openfilenamew
// Wine: dlls/comdlg32/filedlg.c uses ofn->nFilterIndex on return (1-based pair index).

/// The subset of OPENFILENAMEW fields we actually read.
///
/// Using raw byte offsets avoids the fragile repr(C) padding dance.
#[allow(dead_code)]
struct Ofn {
    /// `lpstrFile`: output buffer pointer.
    lp_str_file: *mut u16,
    /// `nMaxFile`: capacity of `lpstrFile` in `u16` code units.
    n_max_file: u32,
    /// `nFilterIndex`: 1-based index of the selected filter pair (MSDN: first pair = 1).
    n_filter_index: u32,
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
            n_filter_index: *(p.add(44) as *const u32),
            lp_str_initial_dir: *(p.add(80) as *const *const u16),
            lp_str_title: *(p.add(88) as *const *const u16),
            lp_str_filter: *(p.add(24) as *const *const u16),
            lp_str_def_ext: *(p.add(104) as *const *const u16),
        }
    }
}

/// Write `nFilterIndex` back into the guest OPENFILENAMEW blob (offset 44).
unsafe fn write_n_filter_index(p: *mut u8, index: u32) {
    unsafe {
        *(p.add(44) as *mut u32) = index;
    }
}

/// Decode one null-terminated UTF-16 slice starting at `start` (in `u16` units).
unsafe fn decode_wide_at(base: *const u16, start: usize) -> Option<String> {
    let mut len = 0usize;
    unsafe {
        while *base.add(start + len) != 0 {
            len += 1;
        }
        if len == 0 {
            return None;
        }
        let slice = std::slice::from_raw_parts(base.add(start), len);
        Some(String::from_utf16_lossy(slice))
    }
}

/// Parse `lpstrFilter` double-NUL display/pattern pairs into `(display, pattern)` strings.
unsafe fn decode_filter_pairs(filter_ptr: *const u16) -> Vec<(String, String)> {
    if filter_ptr.is_null() {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    let mut i = 0usize;
    // SAFETY: caller-owned OPENFILENAMEW filter buffer; scan until NUL / double-NUL.
    while let Some(display) = unsafe { decode_wide_at(filter_ptr, i) } {
        i += display.encode_utf16().count() + 1;

        let pattern = match unsafe { decode_wide_at(filter_ptr, i) } {
            Some(s) => s,
            None => break,
        };
        i += pattern.encode_utf16().count() + 1;

        pairs.push((display, pattern));
    }
    pairs
}

/// Return true when a filter pair targets PNG output (display name or pattern).
fn filter_pair_is_png(display: &str, pattern: &str) -> bool {
    let display_lc = display.to_ascii_lowercase();
    let pattern_lc = pattern.to_ascii_lowercase();
    display_lc.contains("png") || pattern_lc.contains(".png")
}

/// Find the 1-based `nFilterIndex` for the PNG entry in an `lpstrFilter` pair list.
///
/// MSDN: the first display/pattern pair has index 1; returns `None` when no PNG pair exists.
fn png_filter_index_from_pairs(pairs: &[(String, String)]) -> Option<u32> {
    pairs
        .iter()
        .position(|(display, pattern)| filter_pair_is_png(display, pattern))
        .map(|i| (i + 1) as u32)
}

/// Find PNG `nFilterIndex` from a guest `lpstrFilter` pointer.
unsafe fn find_png_filter_index(filter_ptr: *const u16) -> Option<u32> {
    let pairs = unsafe { decode_filter_pairs(filter_ptr) };
    png_filter_index_from_pairs(&pairs)
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
    encode_wide_into_cap(s, buf, cap as usize);
}

/// Encode a null-terminated UTF-16 string into a guest buffer with a `u16` capacity.
fn encode_wide_into_cap(s: &str, buf: *mut u16, cap: usize) {
    if buf.is_null() || cap == 0 {
        return;
    }
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

/// Image extensions IrfanView may place in `lpstrFile` before Save As appends `lpstrDefExt`.
const KNOWN_IMAGE_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "jpe", "jfif", "gif", "bmp", "tiff", "tif", "webp",
];

/// Strip a trailing known image extension from the basename of a Win32 path.
///
/// Wine `dlls/comdlg32/filedlg.c` appends `lpstrDefExt` only when the typed filename
/// has no extension; returning an extensionless `lpstrFile` plus `lpstrDefExt="png"`
/// avoids `.png.jpg` double-suffix when the guest defaults to JPEG.
fn strip_known_image_extension(path: &str) -> String {
    let (dir, sep, basename) = match path.rsplit_once(['\\', '/']) {
        Some((d, b)) => {
            let sep = if path.contains('\\') { '\\' } else { '/' };
            (d, sep, b)
        }
        None => return path.to_string(),
    };
    let Some(dot) = basename.rfind('.') else {
        return path.to_string();
    };
    let ext = basename[dot + 1..].to_ascii_lowercase();
    if KNOWN_IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        format!("{dir}{sep}{}", &basename[..dot])
    } else {
        path.to_string()
    }
}

/// Overwrite guest `lpstrDefExt` with a new extension (no leading dot).
///
/// SAFETY: `def_ext_ptr` must point at a caller-owned writable wide buffer (OPENFILENAMEW contract).
unsafe fn overwrite_lpstr_def_ext(def_ext_ptr: *const u16, new_ext: &str) -> bool {
    if def_ext_ptr.is_null() {
        return false;
    }
    // IrfanView allocates a small wchar buffer for lpstrDefExt; 16 code units is ample for "png".
    const MAX_DEFEXT_CHARS: usize = 16;
    encode_wide_into_cap(new_ext, def_ext_ptr as *mut u16, MAX_DEFEXT_CHARS);
    true
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

// Wine ref: dlls/comdlg32/filedlg.c:4167 — validates lStructSize first (CDERR_STRUCTSIZE if wrong);
// OFN_FILEMUSTEXIST implies OFN_PATHMUSTEXIST; writes selected path(s) into ofn->lpstrFile
// (null-separated for OFN_ALLOWMULTISELECT); sets CommDlgExtendedError on failure.
// Known gap: Weave uses zenity/kdialog subprocess; no OFN_ALLOWMULTISELECT; no filter; no
// lStructSize validation; CommDlgExtendedError always 0.
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

// Wine ref: dlls/comdlg32/printdlg.c — PrintDlgExW returns HRESULT; returns E_FAIL (0x80004005)
// when no printer is configured (observed in Wine test_PrintDlgExW: "res == E_FAIL → skip").
// Returns E_INVALIDARG for a malformed lStructSize; returns S_OK with filled hDevMode/hDevNames
// when a default printer is available. Since Weave has no printer spooler, E_FAIL is the
// correct "no printer available" sentinel — callers treat it as a skip/skip-print condition.
/// PrintDlgExW — display an extended print dialog (Wide).
///
/// Returns E_FAIL (no printers configured). Callers that use PD_RETURNDEFAULT
/// skip the dialog and fall back to a "no printer" code path.
///
/// # Safety
/// `lp_pdex` is ignored.
// TODO(shim): Phase A — no spooler; always returns E_FAIL (no-printer sentinel).
pub unsafe extern "win64" fn print_dlg_ex_w(_lp_pdex: *const u8) -> i32 {
    // E_FAIL = 0x80004005 — "no printer available" sentinel per Wine test_PrintDlgExW.
    // Callers that pass PD_RETURNDEFAULT detect E_FAIL and skip printing gracefully.
    0x80004005u32 as i32
}

// Wine ref: dlls/comdlg32/printdlg.c — PrintDlgW returns BOOL (not HRESULT); returns FALSE
// with CommDlgExtendedError() == PDERR_NODEFAULTPRN when no default printer is configured.
// Weave has no spooler: return FALSE (cancelled/no-printer) with CommDlgExtendedError == 0.
/// PrintDlgW — display the standard print dialog (Wide).
///
/// Returns 0 (FALSE — no printers available / cancelled stub).
///
/// # Safety
/// `lp_pd` is a guest-supplied pointer; not read (stub).
pub unsafe extern "win64" fn print_dlg_w(_lp_pd: *mut u8) -> i32 {
    // §3 BOOL shape: FALSE = cancelled/no-printer.
    // CommDlgExtendedError() == 0 already (comm_dlg_extended_error returns 0).
    0
}

// Wine ref: dlls/comdlg32/colordlg.c — ChooseColorW returns FALSE when user cancels;
// CommDlgExtendedError() == 0 on cancel. lStructSize validated first.
// Stub: return FALSE (cancelled), error == 0.
/// ChooseColorW — display the color chooser dialog (Wide).
///
/// Returns 0 (FALSE — cancelled stub).
///
/// # Safety
/// `lp_cc` is a guest-supplied pointer; not read (stub).
pub unsafe extern "win64" fn choose_color_w(_lp_cc: *mut u8) -> i32 {
    // §3 BOOL shape: FALSE = cancelled.
    0
}

// Wine ref: dlls/comdlg32/printdlg.c — PageSetupDlgW returns FALSE when cancelled;
// CommDlgExtendedError() == 0 on cancel; PDERR_NODEFAULTPRN when no printer.
// Stub: return FALSE.
/// PageSetupDlgW — display the page setup dialog (Wide).
///
/// Returns 0 (FALSE — cancelled stub).
///
/// # Safety
/// `lp_psd` is a guest-supplied pointer; not read (stub).
pub unsafe extern "win64" fn page_setup_dlg_w(_lp_psd: *mut u8) -> i32 {
    // §3 BOOL shape: FALSE = cancelled/no-printer.
    0
}

// SHIM NOTE (E3-M9): Test harness / gate support via WEAVE_TEST_SAVE_RESULT env var.
// When set to a host or Win32 path, skip zenity and write the translated path into
// lpstrFile (appending lpstrDefExt when the basename has no extension). This lets
// IrfanView Save-As-PNG gates complete under Xvfb/CI without a blocking save dialog.

// Wine ref: dlls/comdlg32/filedlg.c:4232 — GetSaveFileNameW returns BOOL (TRUE=1/FALSE=0);
// on success writes the selected path into ofn->lpstrFile (null-terminated, capped by nMaxFile);
// user cancel returns FALSE with CommDlgExtendedError()==0; lpstrDefExt is appended when the
// typed filename has no extension (see filedlg.c tests/filedlg.c test_extension_helper).
/// GetSaveFileNameW: display the system Save dialog box.
///
/// If `WEAVE_TEST_SAVE_RESULT` is set, returns TRUE and writes that path into `lpstrFile`
/// without opening zenity/kdialog. Otherwise opens the native save dialog.
///
/// Returns TRUE if the user selects a filename; FALSE if cancelled or on error.
///
/// # Safety
/// `lp_ofn` must be a valid pointer to an `OPENFILENAMEW` struct.
pub unsafe extern "win64" fn get_save_file_name_w(lp_ofn: *mut u8) -> i32 {
    if lp_ofn.is_null() {
        return 0;
    }
    // SAFETY: lp_ofn is non-null (checked above); caller supplies a valid OPENFILENAMEW buffer.
    let ofn = unsafe { read_ofn(lp_ofn) };

    if let Ok(test_path) = std::env::var("WEAVE_TEST_SAVE_RESULT") {
        if !test_path.is_empty() {
            return get_save_file_name_w_test_hook(lp_ofn, ofn, &test_path);
        }
    }

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

/// Env-gated test hook: translate `test_path` to Win32, optionally append `lpstrDefExt`,
/// force PNG `nFilterIndex` when `lpstrFilter` contains a PNG pair, write into `lpstrFile`,
/// log, and return TRUE.
fn get_save_file_name_w_test_hook(lp_ofn: *mut u8, ofn: Ofn, test_path: &str) -> i32 {
    let mut win_path = if test_path.len() >= 2 && test_path.as_bytes()[1] == b':' {
        test_path.replace('/', "\\")
    } else {
        match linux_to_win_path(test_path) {
            Some(p) => p,
            None => return 0,
        }
    };

    let filter_null = ofn.lp_str_filter.is_null();
    let def_ext_decoded = unsafe { decode_wide_ptr(ofn.lp_str_def_ext) };
    eprintln!(
        "weave/GetSaveFileNameW: test hook diagnostics lpstrFilter_null={filter_null} nFilterIndex={} lpstrDefExt={}",
        ofn.n_filter_index,
        def_ext_decoded.as_deref().unwrap_or("(null)")
    );

    // Force PNG encoder selection: IrfanView Save As defaults to JPEG (nFilterIndex=1)
    // and appends `.jpg` even when lpstrFile already ends in `.png`.
    // SAFETY: lp_str_filter is guest-owned; find_png_filter_index only reads until double-NUL.
    if let Some(png_idx) = unsafe { find_png_filter_index(ofn.lp_str_filter) } {
        // SAFETY: lp_str_def_ext is a guest-owned LPCWSTR; decode_wide_ptr scans until NUL within
        // caller-allocated storage (standard OPENFILENAMEW contract).
        if let Some(ext_wide) = unsafe { decode_wide_ptr(ofn.lp_str_def_ext) } {
            let basename = win_path.rsplit(['\\', '/']).next().unwrap_or("");
            if !ext_wide.is_empty() && !basename.contains('.') {
                win_path = format!("{}.{}", win_path, ext_wide);
            }
        }
        // SAFETY: lp_ofn is the same guest OPENFILENAMEW buffer read by read_ofn.
        unsafe { write_n_filter_index(lp_ofn, png_idx) };
        eprintln!(
            "weave/GetSaveFileNameW: test hook → TRUE path={win_path} nFilterIndex={png_idx} (was {})",
            ofn.n_filter_index
        );
    } else {
        // lpstrFilter null or unparseable: cannot set nFilterIndex. Per Wine filedlg.c defext
        // behavior, return an extensionless lpstrFile and overwrite lpstrDefExt to "png" so the
        // guest appends `.png` once instead of `.png.jpg` from the JPEG default format.
        // SAFETY: lp_str_def_ext points at caller-owned writable storage (OPENFILENAMEW contract).
        unsafe { overwrite_lpstr_def_ext(ofn.lp_str_def_ext, "png") };
        win_path = strip_known_image_extension(&win_path);
        eprintln!(
            "weave/GetSaveFileNameW: test hook → TRUE path={win_path} (extensionless, lpstrDefExt→png)"
        );
    }

    // SAFETY: lp_str_file/n_max_file are guest-owned output buffer fields from OPENFILENAMEW.
    encode_wide_into(&win_path, ofn.lp_str_file, ofn.n_max_file);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode an IrfanView-style `lpstrFilter` double-NUL pair list.
    fn encode_filter_pairs(pairs: &[(&str, &str)]) -> Vec<u16> {
        let mut wide = Vec::new();
        for (display, pattern) in pairs {
            wide.extend(display.encode_utf16());
            wide.push(0);
            wide.extend(pattern.encode_utf16());
            wide.push(0);
        }
        wide.push(0);
        wide
    }

    /// Build a minimal OPENFILENAMEW byte blob with lpstrFile, nMaxFile, and optional fields.
    fn make_minimal_ofn(
        file_buf: &mut [u16],
        def_ext: Option<&str>,
        filter: Option<&[(&str, &str)]>,
        n_filter_index: Option<u32>,
    ) -> (Vec<u8>, Option<Vec<u16>>, Option<Vec<u16>>) {
        let mut ofn_bytes = vec![0u8; 152];
        let file_ptr = file_buf.as_mut_ptr() as usize;
        ofn_bytes[48..56].copy_from_slice(&file_ptr.to_le_bytes());
        let n_max_file: u32 = file_buf.len() as u32;
        ofn_bytes[56..60].copy_from_slice(&n_max_file.to_le_bytes());

        if let Some(idx) = n_filter_index {
            ofn_bytes[44..48].copy_from_slice(&idx.to_le_bytes());
        }

        let ext_storage: Option<Vec<u16>> =
            def_ext.map(|e| e.encode_utf16().chain(std::iter::once(0)).collect());
        if let Some(ref ext) = ext_storage {
            let ext_ptr = ext.as_ptr() as usize;
            ofn_bytes[104..112].copy_from_slice(&ext_ptr.to_le_bytes());
        }

        let filter_storage: Option<Vec<u16>> = filter.map(|pairs| encode_filter_pairs(pairs));
        if let Some(ref filt) = filter_storage {
            let filt_ptr = filt.as_ptr() as usize;
            ofn_bytes[24..32].copy_from_slice(&filt_ptr.to_le_bytes());
        }

        (ofn_bytes, ext_storage, filter_storage)
    }

    #[test]
    fn png_filter_index_selects_png_pair_from_irfanview_style_filter() {
        let pairs = vec![
            ("All Files (*.*)".to_string(), "*.*".to_string()),
            (
                "JPEG - JPG/JFIF".to_string(),
                "*.JPG;*.JPEG;*.JPE;*.JFIF".to_string(),
            ),
            (
                "PNG - Portable Network Graphics".to_string(),
                "*.PNG".to_string(),
            ),
            ("GIF - CompuServe".to_string(), "*.GIF".to_string()),
        ];
        assert_eq!(png_filter_index_from_pairs(&pairs), Some(3));

        let filter_wide = encode_filter_pairs(&[
            ("All Files (*.*)", "*.*"),
            ("JPEG - JPG/JFIF", "*.JPG;*.JPEG;*.JPE;*.JFIF"),
            ("PNG - Portable Network Graphics", "*.PNG"),
            ("GIF - CompuServe", "*.GIF"),
        ]);
        let decoded = unsafe { decode_filter_pairs(filter_wide.as_ptr()) };
        assert_eq!(decoded, pairs);
        assert_eq!(
            unsafe { find_png_filter_index(filter_wide.as_ptr()) },
            Some(3)
        );
    }

    #[test]
    fn get_save_file_name_w_returns_true_for_test_result_env() {
        let old = std::env::var("WEAVE_TEST_SAVE_RESULT").ok();
        std::env::set_var("WEAVE_TEST_SAVE_RESULT", r"C:\Save\Out\image");

        let mut file_buf: [u16; 260] = [0; 260];
        let (ofn_bytes, ext_storage, filter_storage) =
            make_minimal_ofn(&mut file_buf, Some("png"), None, None);

        let ret = unsafe { get_save_file_name_w(ofn_bytes.as_ptr() as *mut u8) };
        assert_eq!(
            ret, 1,
            "GetSaveFileNameW must return TRUE when WEAVE_TEST_SAVE_RESULT is set"
        );

        let end = file_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(file_buf.len());
        let path = String::from_utf16_lossy(&file_buf[..end]);
        assert!(
            !path.is_empty(),
            "lpstrFile must be non-empty after TRUE return"
        );
        assert_eq!(
            path, r"C:\Save\Out\image",
            "null lpstrFilter: hook writes extensionless lpstrFile; guest appends lpstrDefExt"
        );

        drop(ext_storage);
        drop(filter_storage);
        match old {
            Some(v) => std::env::set_var("WEAVE_TEST_SAVE_RESULT", v),
            None => std::env::remove_var("WEAVE_TEST_SAVE_RESULT"),
        }
    }

    #[test]
    fn strip_known_image_extension_removes_trailing_png() {
        assert_eq!(
            strip_known_image_extension(r"C:\Save\Out\image.png"),
            r"C:\Save\Out\image"
        );
        assert_eq!(
            strip_known_image_extension(r"Z:/gate/save_png_gate_7864.png"),
            r"Z:/gate/save_png_gate_7864"
        );
        assert_eq!(
            strip_known_image_extension(r"C:\Save\Out\image"),
            r"C:\Save\Out\image"
        );
    }

    #[test]
    fn get_save_file_name_w_test_hook_overwrites_defext_when_filter_null() {
        let old = std::env::var("WEAVE_TEST_SAVE_RESULT").ok();
        std::env::set_var("WEAVE_TEST_SAVE_RESULT", r"C:\Save\Out\image.png");

        let mut file_buf: [u16; 260] = [0; 260];
        let (ofn_bytes, ext_storage, filter_storage) =
            make_minimal_ofn(&mut file_buf, Some("jpg"), None, Some(1));

        let ret = unsafe { get_save_file_name_w(ofn_bytes.as_ptr() as *mut u8) };
        assert_eq!(ret, 1, "test hook must return TRUE");

        let end = file_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(file_buf.len());
        let path = String::from_utf16_lossy(&file_buf[..end]);
        assert_eq!(
            path, r"C:\Save\Out\image",
            "lpstrFile must be extensionless when lpstrFilter is null"
        );

        let def_ext = ext_storage.as_ref().expect("lpstrDefExt storage");
        let def_end = def_ext
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(def_ext.len());
        let def_ext_str = String::from_utf16_lossy(&def_ext[..def_end]);
        assert_eq!(
            def_ext_str, "png",
            "hook must overwrite guest lpstrDefExt from jpg to png"
        );

        let n_filter_index =
            u32::from_le_bytes(ofn_bytes[44..48].try_into().expect("nFilterIndex bytes"));
        assert_eq!(
            n_filter_index, 1,
            "nFilterIndex unchanged when lpstrFilter is null"
        );

        drop(ext_storage);
        drop(filter_storage);
        match old {
            Some(v) => std::env::set_var("WEAVE_TEST_SAVE_RESULT", v),
            None => std::env::remove_var("WEAVE_TEST_SAVE_RESULT"),
        }
    }

    #[test]
    fn get_save_file_name_w_test_hook_writes_png_n_filter_index() {
        let old = std::env::var("WEAVE_TEST_SAVE_RESULT").ok();
        std::env::set_var("WEAVE_TEST_SAVE_RESULT", r"C:\Save\Out\image.png");

        let mut file_buf: [u16; 260] = [0; 260];
        let filter_pairs = [
            ("JPEG - JPG/JFIF", "*.JPG;*.JPEG"),
            ("PNG - Portable Network Graphics", "*.PNG"),
        ];
        let (ofn_bytes, ext_storage, filter_storage) =
            make_minimal_ofn(&mut file_buf, None, Some(&filter_pairs), Some(1));

        let ret = unsafe { get_save_file_name_w(ofn_bytes.as_ptr() as *mut u8) };
        assert_eq!(ret, 1, "test hook must return TRUE");

        let n_filter_index =
            u32::from_le_bytes(ofn_bytes[44..48].try_into().expect("nFilterIndex bytes"));
        assert_eq!(
            n_filter_index, 2,
            "test hook must force PNG nFilterIndex (pair 2) over incoming JPEG index 1"
        );

        drop(ext_storage);
        drop(filter_storage);
        match old {
            Some(v) => std::env::set_var("WEAVE_TEST_SAVE_RESULT", v),
            None => std::env::remove_var("WEAVE_TEST_SAVE_RESULT"),
        }
    }
}
