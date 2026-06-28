//! shlwapi.dll stubs for Weave.
//!
//! shlwapi provides path manipulation helpers (PathCombineW, PathIsRelativeW,
//! PathFindFileNameW, ...) and a handful of colour utilities. Most path
//! functions operate entirely on wide strings in-place; they do not touch the
//! filesystem, so they work correctly without any prefix translation.

#![allow(non_snake_case, clippy::missing_safety_doc)]

// ── Wide-string helpers ───────────────────────────────────────────────────────

/// Read a null-terminated UTF-16 string from a raw pointer.
unsafe fn read_wide(p: *const u16) -> Vec<u16> {
    if p.is_null() {
        return Vec::new();
    }
    let mut len = 0usize;
    // Pointer validation: cap to prevent OOB read from unterminated strings.
    const MAX_LEN: usize = 65_536;
    while len < MAX_LEN && unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    unsafe { std::slice::from_raw_parts(p, len) }.to_vec()
}

/// Write a Vec<u16> (without null) into a buffer, appending a null terminator.
/// Returns the number of characters written (excluding the null).
unsafe fn write_wide(buf: *mut u16, buf_len: usize, s: &[u16]) -> usize {
    if buf.is_null() || buf_len == 0 {
        return 0;
    }
    let copy_len = s.len().min(buf_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr(), buf, copy_len);
        *buf.add(copy_len) = 0;
    }
    copy_len
}

/// Decode a Vec<u16> to a Rust String (lossy).
fn decode(s: &[u16]) -> String {
    String::from_utf16_lossy(s)
}

/// Encode a &str to Vec<u16> (without null terminator).
fn encode(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

// ── PathCombineW ──────────────────────────────────────────────────────────────

/// PathCombineW — concatenate a directory path and a filename.
///
/// Writes the combined path into `lp_sz_dest` (MAX_PATH = 260 chars).
/// Returns `lp_sz_dest` on success, NULL on failure.
///
/// # Safety
/// `lp_sz_dest` must be a writable buffer of at least MAX_PATH wide chars.
/// `lp_sz_dir` and `lp_sz_file` must be valid null-terminated wide strings
/// or NULL.
#[no_mangle]
pub unsafe extern "win64" fn PathCombineW(
    lp_sz_dest: *mut u16,
    lp_sz_dir: *const u16,
    lp_sz_file: *const u16,
) -> *mut u16 {
    if lp_sz_dest.is_null() {
        return std::ptr::null_mut();
    }

    let dir = if lp_sz_dir.is_null() {
        String::new()
    } else {
        decode(&unsafe { read_wide(lp_sz_dir) })
    };
    let file = if lp_sz_file.is_null() {
        String::new()
    } else {
        decode(&unsafe { read_wide(lp_sz_file) })
    };

    // If file is absolute (starts with \ or has drive letter) or dir is empty,
    // use file directly.
    let combined = if file.starts_with('\\')
        || (file.len() >= 2 && file.as_bytes()[1] == b':')
        || dir.is_empty()
    {
        file
    } else {
        let dir_trimmed = dir.trim_end_matches('\\');
        if file.is_empty() {
            dir_trimmed.to_string()
        } else {
            format!("{}\\{}", dir_trimmed, file)
        }
    };

    let wide = encode(&combined);
    unsafe { write_wide(lp_sz_dest, 260, &wide) };
    lp_sz_dest
}

// ── PathAppendW ───────────────────────────────────────────────────────────────

/// PathAppendW — append a path component to an existing path in-place.
///
/// # Safety
/// `lp_path` must be a writable buffer of at least MAX_PATH chars.
/// `lp_more` must be a valid null-terminated wide string.
pub unsafe extern "win64" fn path_append_w(lp_path: *mut u16, lp_more: *const u16) -> i32 {
    if lp_path.is_null() {
        return 0;
    }
    let mut path = decode(&unsafe { read_wide(lp_path as *const u16) });
    let more = if lp_more.is_null() {
        String::new()
    } else {
        decode(&unsafe { read_wide(lp_more) })
    };

    if !more.is_empty() {
        let more_stripped = more.trim_start_matches('\\');
        if !path.ends_with('\\') {
            path.push('\\');
        }
        path.push_str(more_stripped);
    }

    let wide = encode(&path);
    unsafe { write_wide(lp_path, 260, &wide) };
    1 // TRUE
}

// ── PathRemoveFileSpecW ───────────────────────────────────────────────────────

/// PathRemoveFileSpecW — remove the trailing filename from a path, leaving the
/// directory (with trailing backslash stripped).
///
/// # Safety
/// `lp_path` must be a writable null-terminated wide string.
pub unsafe extern "win64" fn path_remove_file_spec_w(lp_path: *mut u16) -> i32 {
    if lp_path.is_null() {
        return 0;
    }
    let path = decode(&unsafe { read_wide(lp_path as *const u16) });
    // Find the last backslash.
    let result = if let Some(pos) = path.rfind('\\') {
        // Keep up to (but not including) the last backslash, unless it's a
        // drive root like "C:\".
        if pos == 2 && path.as_bytes().get(1) == Some(&b':') {
            // "C:\" — keep the trailing slash (root of drive)
            path[..=pos].to_string()
        } else {
            path[..pos].to_string()
        }
    } else {
        // No backslash — path is just a filename; clear to empty.
        String::new()
    };
    let changed = result != path;
    let wide = encode(&result);
    unsafe { write_wide(lp_path, 260, &wide) };
    changed as i32
}

// ── PathFindFileNameW ─────────────────────────────────────────────────────────

/// PathFindFileNameW — return a pointer to the filename component of a path.
///
/// # Safety
/// `lp_path` must be a valid null-terminated wide string.
pub unsafe extern "win64" fn path_find_file_name_w(lp_path: *const u16) -> *const u16 {
    if lp_path.is_null() {
        return lp_path;
    }
    let mut last_sep = lp_path;
    let mut p = lp_path;
    loop {
        let ch = unsafe { *p };
        if ch == 0 {
            break;
        }
        if ch == b'\\' as u16 || ch == b'/' as u16 {
            last_sep = unsafe { p.add(1) };
        }
        p = unsafe { p.add(1) };
    }
    last_sep
}

// ── PathFindExtensionW ────────────────────────────────────────────────────────

/// PathFindExtensionW — return a pointer to the extension (including '.') of a
/// path, or a pointer to the null terminator if no extension.
///
/// # Safety
/// `lp_path` must be a valid null-terminated wide string.
pub unsafe extern "win64" fn path_find_extension_w(lp_path: *const u16) -> *const u16 {
    if lp_path.is_null() {
        return lp_path;
    }
    // Walk from the end of the filename looking for '.' after the last '\'.
    let file_start = unsafe { path_find_file_name_w(lp_path) };
    let mut p = file_start;
    let mut last_dot: *const u16 = std::ptr::null();
    loop {
        let ch = unsafe { *p };
        if ch == 0 {
            break;
        }
        if ch == b'.' as u16 {
            last_dot = p;
        }
        p = unsafe { p.add(1) };
    }
    if last_dot.is_null() {
        p // return pointer to null terminator
    } else {
        last_dot
    }
}

// ── PathRemoveExtensionW ──────────────────────────────────────────────────────

/// PathRemoveExtensionW — remove the file extension from a path in-place.
///
/// # Safety
/// `lp_path` must be a writable null-terminated wide string.
pub unsafe extern "win64" fn path_remove_extension_w(lp_path: *mut u16) {
    if lp_path.is_null() {
        return;
    }
    let ext = unsafe { path_find_extension_w(lp_path as *const u16) };
    if !ext.is_null() {
        let ch = unsafe { *ext };
        if ch == b'.' as u16 {
            // Truncate at the dot.
            unsafe { *(ext as *mut u16) = 0 };
        }
    }
}

// ── PathStripPathW ────────────────────────────────────────────────────────────

/// PathStripPathW — remove the path component, leaving just the filename.
///
/// Operates in-place by moving the filename to the start of the buffer.
///
/// # Safety
/// `lp_sz_path` must be a writable null-terminated wide string.
pub unsafe extern "win64" fn path_strip_path_w(lp_sz_path: *mut u16) {
    if lp_sz_path.is_null() {
        return;
    }
    let filename_ptr = unsafe { path_find_file_name_w(lp_sz_path as *const u16) };
    if std::ptr::eq(filename_ptr, lp_sz_path as *const u16) {
        return; // nothing to strip
    }
    // Move filename to the front.
    let mut src = filename_ptr;
    let mut dst = lp_sz_path;
    loop {
        let ch = unsafe { *src };
        unsafe { *dst = ch };
        if ch == 0 {
            break;
        }
        src = unsafe { src.add(1) };
        dst = unsafe { dst.add(1) };
    }
}

// ── PathIsRelativeW ───────────────────────────────────────────────────────────

/// PathIsRelativeW — return TRUE if the path is relative (no drive letter or
/// leading backslash).
///
/// # Safety
/// `lp_path` must be a valid null-terminated wide string or NULL.
pub unsafe extern "win64" fn path_is_relative_w(lp_path: *const u16) -> i32 {
    if lp_path.is_null() {
        return 1; // NULL treated as relative
    }
    let path = decode(&unsafe { read_wide(lp_path) });
    let is_abs = path.starts_with('\\')
        || (path.len() >= 2
            && path.as_bytes()[0].is_ascii_alphabetic()
            && path.as_bytes()[1] == b':');
    (!is_abs) as i32
}

// ── PathIsNetworkPathW ────────────────────────────────────────────────────────

/// PathIsNetworkPathW — return TRUE if the path is a UNC network path.
///
/// # Safety
/// `lp_path` must be a valid null-terminated wide string or NULL.
pub unsafe extern "win64" fn path_is_network_path_w(lp_path: *const u16) -> i32 {
    if lp_path.is_null() {
        return 0;
    }
    let path = decode(&unsafe { read_wide(lp_path) });
    path.starts_with("\\\\") as i32
}

// ── PathGetDriveNumberW ───────────────────────────────────────────────────────

/// PathGetDriveNumberW — extract the drive number from a path (A=0, B=1, ...).
/// Returns -1 if no drive letter.
///
/// # Safety
/// `lp_path` must be a valid null-terminated wide string or NULL.
pub unsafe extern "win64" fn path_get_drive_number_w(lp_path: *const u16) -> i32 {
    if lp_path.is_null() {
        return -1;
    }
    let path = decode(&unsafe { read_wide(lp_path) });
    if path.len() >= 2 && path.as_bytes()[0].is_ascii_alphabetic() && path.as_bytes()[1] == b':' {
        (path.as_bytes()[0].to_ascii_uppercase() - b'A') as i32
    } else {
        -1
    }
}

// ── PathMatchSpecW ────────────────────────────────────────────────────────────

/// PathMatchSpecW — match a path against a wildcard spec (e.g. "*.txt").
///
/// Very basic implementation: supports `*` (any chars) and `?` (single char).
///
/// # Safety
/// `psz_file` and `psz_spec` must be valid null-terminated wide strings.
pub unsafe extern "win64" fn path_match_spec_w(psz_file: *const u16, psz_spec: *const u16) -> i32 {
    if psz_file.is_null() || psz_spec.is_null() {
        return 0;
    }
    let file = decode(&unsafe { read_wide(psz_file) });
    let spec = decode(&unsafe { read_wide(psz_spec) });
    // Only compare against the filename component.
    let fname = file
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&file)
        .to_ascii_lowercase();
    let spec_lo = spec.to_ascii_lowercase();
    wildcard_match(&fname, &spec_lo) as i32
}

fn wildcard_match(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let mut ti = 0usize;
    let mut pi = 0usize;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ── PathCompactPathExW ────────────────────────────────────────────────────────

/// PathCompactPathExW — truncate a path to fit in a given number of characters.
///
/// Simplified: truncate with "..." in the middle.
///
/// # Safety
/// `psz_out` must be a writable buffer of at least `cch_max` wide chars.
/// `psz_src` must be a valid null-terminated wide string.
pub unsafe extern "win64" fn path_compact_path_ex_w(
    psz_out: *mut u16,
    psz_src: *const u16,
    cch_max: u32,
    _dw_flags: u32,
) -> i32 {
    if psz_out.is_null() || psz_src.is_null() || cch_max == 0 {
        return 0;
    }
    let src = decode(&unsafe { read_wide(psz_src) });
    let max = cch_max as usize;
    let result = if src.len() < max {
        src.clone()
    } else if max <= 4 {
        src[..max.saturating_sub(1)].to_string()
    } else {
        let keep = max - 4; // room for "...\0"
        let half = keep / 2;
        format!("{}...{}", &src[..half], &src[src.len() - (keep - half)..])
    };
    let wide = encode(&result);
    unsafe { write_wide(psz_out, max, &wide) };
    1
}

// ── PathFileExistsW ───────────────────────────────────────────────────────────

/// PathFileExistsW — return TRUE if the file or directory exists.
///
/// Used by Notepad++ and many other apps to check for config files before
/// deciding whether to run in portable mode.  Translates the Windows path to
/// a Linux path via the Weave path translator.
///
/// # Safety
/// `psz_path` must be a valid null-terminated UTF-16 string or NULL.
pub unsafe extern "win64" fn path_file_exists_w(psz_path: *const u16) -> i32 {
    if psz_path.is_null() {
        return 0;
    }
    let path_str = decode(&unsafe { read_wide(psz_path) });
    // Translate via weave_core so Z: → / and prefix drives work correctly.
    let exists = weave_core::file_io::translate_win_path(&path_str)
        .map(|p| p.exists())
        .unwrap_or(false);
    eprintln!("weave/shlwapi: PathFileExistsW({path_str:?}) → {exists}");
    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok() {
        let lower = path_str.to_ascii_lowercase();
        if lower.contains("plugins") || lower.contains("optipng") {
            eprintln!("weave/E3-M9-trace: PathFileExistsW({path_str:?}) → {exists}");
        }
    }
    exists as i32
}

// ── AssocQueryStringW ─────────────────────────────────────────────────────────

/// AssocQueryStringW — query shell file association strings (file type, verb, etc.)
///
/// Stub: returns E_NOTIMPL. Apps use this for "Open with" type queries; failure
/// is graceful (app falls back to built-in defaults).
///
/// # Safety
/// All pointer arguments are unused; the function is a no-op stub.
pub unsafe extern "win64" fn assoc_query_string_w(
    _flags: u32,
    _str: u32,
    _psz_assoc: *const u16,
    _psz_extra: *const u16,
    _psz_out: *mut u16,
    _pcch_out: *mut u32,
) -> i32 {
    0x80004001u32 as i32 // E_NOTIMPL
}

// ── Color functions ───────────────────────────────────────────────────────────

/// ColorRGBToHLS — convert RGB to HLS.
/// Returns the hue, luminosity, and saturation in the out parameters.
///
/// # Safety
/// `pw_hue`, `pw_luminance`, `pw_saturation` must be valid writable pointers.
pub unsafe extern "win64" fn color_rgb_to_hls(
    clr_rgb: u32,
    pw_hue: *mut u16,
    pw_luminance: *mut u16,
    pw_saturation: *mut u16,
) {
    let r = ((clr_rgb) & 0xFF) as f64 / 255.0;
    let g = ((clr_rgb >> 8) & 0xFF) as f64 / 255.0;
    let b = ((clr_rgb >> 16) & 0xFF) as f64 / 255.0;

    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let delta = max - min;
    let l = (max + min) / 2.0;

    let (h, s) = if delta < 1e-10 {
        (0.0f64, 0.0f64)
    } else {
        let s = if l < 0.5 {
            delta / (max + min)
        } else {
            delta / (2.0 - max - min)
        };
        let h = if (r - max).abs() < 1e-10 {
            (g - b) / delta + if g < b { 6.0 } else { 0.0 }
        } else if (g - max).abs() < 1e-10 {
            (b - r) / delta + 2.0
        } else {
            (r - g) / delta + 4.0
        } / 6.0;
        (h, s)
    };

    if !pw_hue.is_null() {
        unsafe { *pw_hue = (h * 240.0) as u16 };
    }
    if !pw_luminance.is_null() {
        unsafe { *pw_luminance = (l * 240.0) as u16 };
    }
    if !pw_saturation.is_null() {
        unsafe { *pw_saturation = (s * 240.0) as u16 };
    }
}

fn hue_to_rgb(p: f64, q: f64, t: f64) -> f64 {
    let t = t.rem_euclid(1.0);
    if t < 1.0 / 6.0 {
        p + (q - p) * 6.0 * t
    } else if t < 1.0 / 2.0 {
        q
    } else if t < 2.0 / 3.0 {
        p + (q - p) * (2.0 / 3.0 - t) * 6.0
    } else {
        p
    }
}

/// ColorHLSToRGB — convert HLS to RGB (COLORREF).
/// HLS values are in the range 0-240.
pub extern "win64" fn color_hls_to_rgb(h: u16, l: u16, s: u16) -> u32 {
    let h = h as f64 / 240.0;
    let l = l as f64 / 240.0;
    let s = s as f64 / 240.0;

    let (r, g, b) = if s < 1e-10 {
        (l, l, l)
    } else {
        let q = if l < 0.5 {
            l * (1.0 + s)
        } else {
            l + s - l * s
        };
        let p = 2.0 * l - q;
        (
            hue_to_rgb(p, q, h + 1.0 / 3.0),
            hue_to_rgb(p, q, h),
            hue_to_rgb(p, q, h - 1.0 / 3.0),
        )
    };

    ((r * 255.0) as u32) | (((g * 255.0) as u32) << 8) | (((b * 255.0) as u32) << 16)
}

/// ColorAdjustLuma — adjust the luminance of a colour by a given amount.
/// `n` is in the range -1000 to 1000. `use_hl` selects the algorithm.
pub extern "win64" fn color_adjust_luma(clr_rgb: u32, n: i32, _use_hl: i32) -> u32 {
    let mut h: u16 = 0;
    let mut l: u16 = 0;
    let mut s: u16 = 0;
    unsafe { color_rgb_to_hls(clr_rgb, &mut h, &mut l, &mut s) };
    let l_new = (l as i32 + n * 240 / 1000).clamp(0, 240) as u16;
    color_hls_to_rgb(h, l_new, s)
}

// ── PathRelativePathToW ───────────────────────────────────────────────────────

// Wine ref: dlls/shlwapi/path.c — PathRelativePathToW builds a relative path from
// psz_from to psz_to by stripping common prefix components; returns FALSE if both
// are not on the same drive/root. Sets last error to ERROR_INVALID_PARAMETER (87)
// when it cannot build a relative path. Stub: always return FALSE + error 87.
/// PathRelativePathToW — build a relative path between two absolute paths.
///
/// Stub: returns 0 (FALSE) and sets last error to 87 (ERROR_INVALID_PARAMETER).
///
/// # Safety
/// `psz_path` is a guest-supplied writable buffer; not written (stub returns FALSE immediately).
/// All other pointer arguments are guest-supplied; not read (stub).
pub unsafe extern "win64" fn path_relative_path_to_w(
    _psz_path: *mut u16,
    _psz_from: *const u16,
    _dw_attr_from: u32,
    _psz_to: *const u16,
    _dw_attr_to: u32,
) -> i32 {
    // §3 BOOL shape: FALSE + SetLastError(ERROR_INVALID_PARAMETER).
    weave_common::set_last_error(87);
    0
}

// ── StrCpyW ───────────────────────────────────────────────────────────────────

// Wine ref: dlls/shlwapi/string.c — StrCpyW is a thin wrapper around lstrcpyW /
// wcscpy; copies the null-terminated wide string at psz_src into psz_dest and
// returns psz_dest. No bounds checking (caller's responsibility per Win32 contract).
/// StrCpyW — copy a null-terminated wide string (like wcscpy).
///
/// Returns `psz_dest`.
///
/// # Safety
/// `psz_dest` must be a writable buffer large enough to hold all characters of
/// `psz_src` plus a null terminator. `psz_src` must be a valid null-terminated
/// wide string. Both must be valid for their respective operations.
pub unsafe extern "win64" fn str_cpy_w(psz_dest: *mut u16, psz_src: *const u16) -> *mut u16 {
    if psz_dest.is_null() || psz_src.is_null() {
        return psz_dest;
    }
    // SAFETY: caller guarantees psz_src is null-terminated and psz_dest has
    // sufficient capacity. We walk src until null, writing each char to dest.
    let mut src = psz_src;
    let mut dst = psz_dest;
    loop {
        let ch = unsafe { *src };
        unsafe { *dst = ch };
        if ch == 0 {
            break;
        }
        src = unsafe { src.add(1) };
        dst = unsafe { dst.add(1) };
    }
    psz_dest
}

// ── SHAutoComplete ────────────────────────────────────────────────────────────

/// SHAutoComplete — stub, always succeeds (returns S_OK).
/// Wine ref: dlls/shlwapi/shlwapi_main.c — enables auto-complete on an edit control
/// based on dw_flags (SHACF_*). Stub returns S_OK as a no-op.
pub extern "win64" fn sh_auto_complete(_hwnd_edit: usize, _dw_flags: u32) -> u32 {
    0 // S_OK
}

// ── SHRegGetUSValueW ──────────────────────────────────────────────────────────

/// SHRegGetUSValueW — stub, returns ERROR_FILE_NOT_FOUND.
/// Wine ref: dlls/shlwapi/reg.c — queries a registry value under HKEY_CURRENT_USER
/// or HKEY_LOCAL_MACHINE (user/machine split). Stub returns 0x80070002 to signal
/// "value not present", which callers handle gracefully.
pub unsafe extern "win64" fn sh_reg_get_us_value_w(
    _hkey: *const u8,
    _psz_sub_key: *const u16,
    _psz_value: *const u16,
    _pdw_type: *mut u32,
    _pv_data: *mut u8,
    _pcb_data: *mut u32,
    _pdefault_data: *const u8,
    _default_data_size: u32,
) -> u32 {
    0x80070002 // ERROR_FILE_NOT_FOUND
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/// Resolve a shlwapi.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("shlwapi.dll") {
        return None;
    }
    Some(match func {
        "PathCombineW" => PathCombineW as *const () as usize,
        "PathAppendW" => path_append_w as *const () as usize,
        "PathRemoveFileSpecW" => path_remove_file_spec_w as *const () as usize,
        "PathFindFileNameW" => path_find_file_name_w as *const () as usize,
        "PathFindExtensionW" => path_find_extension_w as *const () as usize,
        "PathRemoveExtensionW" => path_remove_extension_w as *const () as usize,
        "PathStripPathW" => path_strip_path_w as *const () as usize,
        "PathIsRelativeW" => path_is_relative_w as *const () as usize,
        "PathIsNetworkPathW" => path_is_network_path_w as *const () as usize,
        "PathGetDriveNumberW" => path_get_drive_number_w as *const () as usize,
        "PathMatchSpecW" => path_match_spec_w as *const () as usize,
        "PathCompactPathExW" => path_compact_path_ex_w as *const () as usize,
        "PathFileExistsW" => path_file_exists_w as *const () as usize,
        "AssocQueryStringW" => assoc_query_string_w as *const () as usize,
        "ColorRGBToHLS" => color_rgb_to_hls as *const () as usize,
        "ColorHLSToRGB" => color_hls_to_rgb as *const () as usize,
        "ColorAdjustLuma" => color_adjust_luma as *const () as usize,
        "PathRelativePathToW" => path_relative_path_to_w as *const () as usize,
        "StrCpyW" => str_cpy_w as *const () as usize,
        "SHAutoComplete" => sh_auto_complete as *const () as usize,
        "SHRegGetUSValueW" => sh_reg_get_us_value_w as *const () as usize,
        _ => return None,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_functions() {
        let funcs = [
            "PathCombineW",
            "PathAppendW",
            "PathRemoveFileSpecW",
            "PathFindFileNameW",
            "PathFindExtensionW",
            "PathRemoveExtensionW",
            "PathStripPathW",
            "PathIsRelativeW",
            "PathIsNetworkPathW",
            "PathGetDriveNumberW",
            "PathMatchSpecW",
            "PathCompactPathExW",
            "PathFileExistsW",
            "AssocQueryStringW",
            "ColorRGBToHLS",
            "ColorHLSToRGB",
            "ColorAdjustLuma",
            "PathRelativePathToW",
            "StrCpyW",
            "SHAutoComplete",
            "SHRegGetUSValueW",
        ];
        for f in &funcs {
            assert!(resolve("shlwapi.dll", f).is_some(), "missing: {f}");
        }
    }

    #[test]
    fn resolve_shlwapi_q_dir_imports() {
        // Q-Dir requires these two shlwapi symbols to resolve.
        assert!(
            resolve("shlwapi.dll", "PathRelativePathToW").is_some(),
            "PathRelativePathToW must resolve"
        );
        assert!(
            resolve("shlwapi.dll", "StrCpyW").is_some(),
            "StrCpyW must resolve"
        );
    }

    #[test]
    fn str_cpy_w_basic() {
        let src: Vec<u16> = "hello".encode_utf16().chain([0]).collect();
        let mut dest = [0u16; 16];
        let ret = unsafe { str_cpy_w(dest.as_mut_ptr(), src.as_ptr()) };
        assert_eq!(ret, dest.as_mut_ptr());
        let s = String::from_utf16_lossy(
            &dest[..dest.iter().position(|&c| c == 0).unwrap_or(dest.len())],
        );
        assert_eq!(s, "hello");
    }

    #[test]
    fn path_relative_path_to_w_returns_false() {
        // Stub always returns FALSE (0).
        let result = unsafe {
            path_relative_path_to_w(
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(result, 0);
    }

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "PathCombineW").is_none());
    }

    #[test]
    fn resolve_case_insensitive() {
        assert!(resolve("SHLWAPI.DLL", "PathCombineW").is_some());
    }

    #[test]
    fn path_combine_basic() {
        let mut dest = [0u16; 260];
        let dir: Vec<u16> = "Z:\\foo".encode_utf16().chain([0]).collect();
        let file: Vec<u16> = "bar.txt".encode_utf16().chain([0]).collect();
        let result = unsafe { PathCombineW(dest.as_mut_ptr(), dir.as_ptr(), file.as_ptr()) };
        assert!(!result.is_null());
        let s = String::from_utf16_lossy(
            &dest[..dest.iter().position(|&c| c == 0).unwrap_or(dest.len())],
        );
        assert_eq!(s, "Z:\\foo\\bar.txt");
    }

    #[test]
    fn path_combine_absolute_file() {
        let mut dest = [0u16; 260];
        let dir: Vec<u16> = "Z:\\foo".encode_utf16().chain([0]).collect();
        let file: Vec<u16> = "Z:\\abs\\bar.txt".encode_utf16().chain([0]).collect();
        let result = unsafe { PathCombineW(dest.as_mut_ptr(), dir.as_ptr(), file.as_ptr()) };
        assert!(!result.is_null());
        let s = String::from_utf16_lossy(
            &dest[..dest.iter().position(|&c| c == 0).unwrap_or(dest.len())],
        );
        assert_eq!(s, "Z:\\abs\\bar.txt");
    }

    #[test]
    fn path_find_file_name_basic() {
        let path: Vec<u16> = "Z:\\foo\\bar.txt".encode_utf16().chain([0]).collect();
        let p = unsafe { path_find_file_name_w(path.as_ptr()) };
        let s = unsafe {
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        };
        assert_eq!(s, "bar.txt");
    }

    #[test]
    fn path_is_relative_cases() {
        let abs: Vec<u16> = "Z:\\foo".encode_utf16().chain([0]).collect();
        let rel: Vec<u16> = "foo\\bar".encode_utf16().chain([0]).collect();
        assert_eq!(unsafe { path_is_relative_w(abs.as_ptr()) }, 0);
        assert_eq!(unsafe { path_is_relative_w(rel.as_ptr()) }, 1);
    }

    #[test]
    fn path_get_drive_number() {
        let path: Vec<u16> = "C:\\foo".encode_utf16().chain([0]).collect();
        assert_eq!(unsafe { path_get_drive_number_w(path.as_ptr()) }, 2); // C = 2
        let path_z: Vec<u16> = "Z:\\foo".encode_utf16().chain([0]).collect();
        assert_eq!(unsafe { path_get_drive_number_w(path_z.as_ptr()) }, 25); // Z = 25
    }

    #[test]
    fn wildcard_star() {
        assert!(wildcard_match("hello.txt", "*.txt"));
        assert!(!wildcard_match("hello.rs", "*.txt"));
        assert!(wildcard_match("abc", "*"));
    }

    #[test]
    fn color_roundtrip() {
        let rgb: u32 = 0x0040FF80; // R=0x80 G=0xFF B=0x40 (note COLORREF is BGR)
        let mut h = 0u16;
        let mut l = 0u16;
        let mut s = 0u16;
        unsafe { color_rgb_to_hls(rgb, &mut h, &mut l, &mut s) };
        let back = color_hls_to_rgb(h, l, s);
        // Allow ±2 per channel due to rounding
        for shift in [0u32, 8, 16] {
            let orig = (rgb >> shift) & 0xFF;
            let got = (back >> shift) & 0xFF;
            assert!(
                (orig as i32 - got as i32).abs() <= 2,
                "channel mismatch at shift {shift}"
            );
        }
    }
}
