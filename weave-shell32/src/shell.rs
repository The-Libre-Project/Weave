//! shell32.dll stubs for Weave.

#![allow(unsafe_op_in_unsafe_fn)]
//!
//! Covers folder path queries, ShellExecute, and CommandLineToArgvW.

use weave_core::prefix;

// ── Shell_NotifyIconW constants ───────────────────────────────────────────────

const NIM_MODIFY: u32 = 0x00000001;
const NIF_INFO: u32 = 0x00000010;

// ── NOTIFYICONDATAW struct (Windows x64 layout) ───────────────────────────────
//
// Only the fields up to dwInfoFlags are needed. Offsets (verified against SDK):
//   +0    cbSize               u32
//   +4    _pad0                u32  (align hWnd to 8)
//   +8    hWnd                 usize
//   +16   uID                  u32
//   +20   uFlags               u32
//   +24   uCallbackMessage     u32
//   +28   _pad1                u32  (align hIcon to 8)
//   +32   hIcon                usize
//   +40   szTip[128]           [u16; 128]   = 256 bytes → end at 296
//   +296  dwState              u32
//   +300  dwStateMask          u32
//   +304  szInfo[256]          [u16; 256]   = 512 bytes → end at 816
//   +816  uTimeoutOrVersion    u32
//   +820  szInfoTitle[64]      [u16; 64]    = 128 bytes → end at 948
//   +948  dwInfoFlags          u32
//   total: 952 bytes

#[repr(C)]
pub(crate) struct NotifyIconDataW {
    cb_size: u32,
    _pad0: u32,
    h_wnd: usize,
    u_id: u32,
    u_flags: u32,
    u_callback_message: u32,
    _pad1: u32,
    h_icon: usize,
    sz_tip: [u16; 128],
    dw_state: u32,
    dw_state_mask: u32,
    sz_info: [u16; 256],
    u_timeout_or_version: u32,
    sz_info_title: [u16; 64],
    dw_info_flags: u32,
}

// ── CSIDL constants ───────────────────────────────────────────────────────────

const CSIDL_DESKTOP: i32 = 0x0000;
const CSIDL_PERSONAL: i32 = 0x0005; // My Documents
const CSIDL_APPDATA: i32 = 0x001a; // Roaming AppData
const CSIDL_LOCAL_APPDATA: i32 = 0x001c;
const CSIDL_PROGRAM_FILES: i32 = 0x0026;
const CSIDL_WINDOWS: i32 = 0x0024;
const CSIDL_SYSTEM: i32 = 0x0025;
const CSIDL_PROGRAM_FILES_X86: i32 = 0x002a;
const CSIDL_COMMON_APPDATA: i32 = 0x0023;
const CSIDL_PROFILE: i32 = 0x0028; // user profile root

// ── KNOWNFOLDERID GUIDs (as raw byte arrays for comparison) ──────────────────
// Only the most common ones used by Win32 apps.

const FOLDERID_DESKTOP: [u8; 16] = [
    0xB4, 0xBF, 0xCE, 0xB6, 0xA1, 0xB8, 0x1A, 0x4E, 0xB6, 0x00, 0x58, 0x61, 0x28, 0xB6, 0xB4, 0x56,
];
const FOLDERID_DOCUMENTS: [u8; 16] = [
    0xEC, 0x4F, 0x2D, 0xFD, 0xD5, 0x26, 0x29, 0x4C, 0x96, 0x25, 0x9B, 0x82, 0x87, 0xCE, 0x50, 0x6E,
];
const FOLDERID_ROAMING_APP_DATA: [u8; 16] = [
    0x3E, 0xB6, 0x85, 0xDB, 0x65, 0xF9, 0xF0, 0x40, 0x9D, 0xDE, 0x8C, 0x16, 0xAE, 0x37, 0xE4, 0x01,
];
const FOLDERID_LOCAL_APP_DATA: [u8; 16] = [
    0xF1, 0xB3, 0x2B, 0xF7, 0x07, 0xBB, 0xFC, 0x4A, 0xA6, 0x00, 0x1F, 0x34, 0xB4, 0x47, 0xD3, 0x62,
];
const FOLDERID_PROGRAM_FILES: [u8; 16] = [
    0x19, 0x55, 0xAA, 0x90, 0xE3, 0xAF, 0xD3, 0x11, 0xA0, 0xEA, 0x00, 0x80, 0xC7, 0x39, 0x1E, 0xA7,
];
const FOLDERID_WINDOWS: [u8; 16] = [
    0xF3, 0x8B, 0xF4, 0x1C, 0xBC, 0xE3, 0xD1, 0x11, 0xB4, 0xBF, 0x00, 0x80, 0xC7, 0x39, 0x1E, 0xA7,
];
const FOLDERID_SYSTEM: [u8; 16] = [
    0xF4, 0x8B, 0xF4, 0x1C, 0xBC, 0xE3, 0xD1, 0x11, 0xB4, 0xBF, 0x00, 0x80, 0xC7, 0x39, 0x1E, 0xA7,
];

// ── Helper: Win32 path → UTF-16 buffer ───────────────────────────────────────

fn write_win_path(win_path: &str, buf: *mut u16, capacity: usize) {
    if buf.is_null() || capacity == 0 {
        return;
    }
    let mut i = 0usize;
    for ch in win_path.encode_utf16() {
        if i + 1 >= capacity {
            break;
        }
        unsafe { *buf.add(i) = ch };
        i += 1;
    }
    unsafe { *buf.add(i) = 0 };
}

/// Map a CSIDL to its Win32 path relative to the fake Windows root.
fn csidl_to_win_path(n_folder: i32) -> Option<String> {
    match n_folder & 0xFF {
        CSIDL_DESKTOP => Some(r"C:\Users\User\Desktop".to_string()),
        CSIDL_PERSONAL => Some(r"C:\Users\User\Documents".to_string()),
        CSIDL_APPDATA => Some(r"C:\Users\User\AppData\Roaming".to_string()),
        CSIDL_LOCAL_APPDATA => Some(r"C:\Users\User\AppData\Local".to_string()),
        CSIDL_PROGRAM_FILES => Some(r"C:\Program Files".to_string()),
        CSIDL_PROGRAM_FILES_X86 => Some(r"C:\Program Files (x86)".to_string()),
        CSIDL_WINDOWS => Some(r"C:\Windows".to_string()),
        CSIDL_SYSTEM => Some(r"C:\Windows\System32".to_string()),
        CSIDL_COMMON_APPDATA => Some(r"C:\ProgramData".to_string()),
        CSIDL_PROFILE => Some(r"C:\Users\User".to_string()),
        _ => None,
    }
}

/// Map a KNOWNFOLDERID (16-byte GUID) to a Win32 path.
fn known_folder_guid_to_win_path(guid: &[u8; 16]) -> Option<String> {
    if guid == &FOLDERID_DESKTOP {
        return Some(r"C:\Users\User\Desktop".to_string());
    }
    if guid == &FOLDERID_DOCUMENTS {
        return Some(r"C:\Users\User\Documents".to_string());
    }
    if guid == &FOLDERID_ROAMING_APP_DATA {
        return Some(r"C:\Users\User\AppData\Roaming".to_string());
    }
    if guid == &FOLDERID_LOCAL_APP_DATA {
        return Some(r"C:\Users\User\AppData\Local".to_string());
    }
    if guid == &FOLDERID_PROGRAM_FILES {
        return Some(r"C:\Program Files".to_string());
    }
    if guid == &FOLDERID_WINDOWS {
        return Some(r"C:\Windows".to_string());
    }
    if guid == &FOLDERID_SYSTEM {
        return Some(r"C:\Windows\System32".to_string());
    }
    None
}

/// Ensure the on-disk directory for a Win32 path exists in the prefix.
fn ensure_linux_dir(win_path: &str) {
    let translator = weave_common::path::WinPathTranslator::new(prefix::get().to_path_buf());
    if let Ok(p) = translator.to_linux_str(win_path) {
        let _ = std::fs::create_dir_all(&p);
    }
}

// ── Shell_NotifyIconW ─────────────────────────────────────────────────────────

/// Decode a null-terminated slice of UTF-16 code units to a `String`.
fn decode_wide_slice(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

/// Shell_NotifyIconW: add, modify, or delete a taskbar notification icon.
///
/// Weave maps balloon tips (NIM_MODIFY + NIF_INFO) to Linux desktop
/// notifications via `notify-send`. All other operations (NIM_ADD, NIM_DELETE)
/// silently succeed. The icon handle is ignored — only text is surfaced.
///
/// # Safety
/// `lp_data` must be null or point to a valid `NOTIFYICONDATAW` struct.
pub unsafe extern "win64" fn shell_notify_icon_w(
    dw_message: u32,
    lp_data: *const NotifyIconDataW,
) -> i32 {
    if lp_data.is_null() {
        return 0; // FALSE
    }
    if dw_message == NIM_MODIFY {
        let data = unsafe { &*lp_data };
        if data.u_flags & NIF_INFO != 0 {
            let title = decode_wide_slice(&data.sz_info_title);
            let body = decode_wide_slice(&data.sz_info);
            if !title.is_empty() || !body.is_empty() {
                let _ = weave_notify::send(&title, &body);
            }
        }
    }
    1 // TRUE — NIM_ADD, NIM_DELETE, and unhandled cases always report success
}

// ── Win32 API functions ───────────────────────────────────────────────────────

/// SHGetFolderPathW: return the path of a special shell folder.
///
/// Supports the most common CSIDL values. Returns `S_OK` (0) on success,
/// `E_FAIL` (0x80004005) if the CSIDL is unknown.
///
/// # Safety
/// `psz_path` must be a writable buffer of at least `MAX_PATH` (260) wide chars.
pub unsafe extern "win64" fn sh_get_folder_path_w(
    _h_wnd: usize,
    n_folder: i32,
    _h_token: usize,
    _dw_flags: u32,
    psz_path: *mut u16,
) -> u32 {
    match csidl_to_win_path(n_folder) {
        Some(win_path) => {
            ensure_linux_dir(&win_path);
            write_win_path(&win_path, psz_path, 260);
            0 // S_OK
        }
        None => {
            eprintln!("weave/shell32: SHGetFolderPathW: unknown CSIDL {n_folder:#x}");
            0x8000_4005 // E_FAIL
        }
    }
}

/// SHGetSpecialFolderPathW: older variant of SHGetFolderPathW.
///
/// # Safety
/// `psz_path` must be writable for at least 260 wide chars.
pub unsafe extern "win64" fn sh_get_special_folder_path_w(
    _h_wnd: usize,
    psz_path: *mut u16,
    n_folder: i32,
    _b_create: i32,
) -> i32 {
    match csidl_to_win_path(n_folder) {
        Some(win_path) => {
            ensure_linux_dir(&win_path);
            write_win_path(&win_path, psz_path, 260);
            1 // TRUE
        }
        None => {
            eprintln!("weave/shell32: SHGetSpecialFolderPathW: unknown CSIDL {n_folder:#x}");
            0 // FALSE
        }
    }
}

/// SHGetKnownFolderPath: retrieve the full path of a known folder by GUID.
///
/// Allocates the result with `CoTaskMemAlloc` (emulated as a malloc'd buffer).
/// The caller is responsible for freeing via `CoTaskMemFree`.
///
/// Returns `S_OK` (0) on success, `E_FAIL` if the GUID is unknown.
///
/// # Safety
/// `rfid` must be a pointer to a 16-byte KNOWNFOLDERID GUID.
/// `ppsz_path` must be a valid pointer to a `*mut u16` output slot.
pub unsafe extern "win64" fn sh_get_known_folder_path(
    rfid: *const [u8; 16],
    _dw_flags: u32,
    _h_token: usize,
    ppsz_path: *mut *mut u16,
) -> u32 {
    if rfid.is_null() || ppsz_path.is_null() {
        return 0x8000_4003; // E_POINTER
    }
    let guid = unsafe { &*rfid };
    match known_folder_guid_to_win_path(guid) {
        Some(win_path) => {
            ensure_linux_dir(&win_path);
            // Allocate a UTF-16 buffer for the result (CoTaskMemAlloc compatible).
            let units: Vec<u16> = win_path.encode_utf16().chain(std::iter::once(0)).collect();
            let byte_len = units.len() * 2;
            let ptr = unsafe { libc::malloc(byte_len) as *mut u16 };
            if ptr.is_null() {
                return 0x8000_4005; // E_FAIL
            }
            unsafe {
                std::ptr::copy_nonoverlapping(units.as_ptr(), ptr, units.len());
                *ppsz_path = ptr;
            }
            0 // S_OK
        }
        None => {
            eprintln!(
                "weave/shell32: SHGetKnownFolderPath: unknown GUID {:02x?}",
                guid
            );
            0x8000_4005 // E_FAIL
        }
    }
}

/// CoTaskMemFree: free memory allocated by COM task allocator.
///
/// In Weave, CoTaskMemAlloc == libc malloc, so we just call libc::free.
pub extern "win64" fn co_task_mem_free(pv: *mut u8) {
    if !pv.is_null() {
        unsafe { libc::free(pv as *mut libc::c_void) };
    }
}

/// ShellExecuteW: perform an operation on a file (open, run, etc.).
///
/// Phase 2 stub: logs the operation and returns a fake HINSTANCE > 32
/// (indicating success per Win32 convention).
///
/// # Safety
/// All pointer arguments must be null or valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn shell_execute_w(
    _h_wnd: usize,
    lp_operation: *const u16,
    lp_file: *const u16,
    _lp_parameters: *const u16,
    _lp_directory: *const u16,
    _n_show_cmd: i32,
) -> usize {
    let op = unsafe { decode_wide_opt(lp_operation) }.unwrap_or_else(|| "open".to_string());
    let file = unsafe { decode_wide_opt(lp_file) }.unwrap_or_default();
    eprintln!("weave/shell32: ShellExecuteW: op={op:?} file={file:?} (stub)");
    33 // SE_ERR_SUCCESS (any value > 32 means success)
}

/// CommandLineToArgvW: parse a command-line string into an argv array.
///
/// Returns a pointer to an array of wide string pointers allocated with a
/// single `LocalAlloc`-style allocation. The caller must free it with
/// `LocalFree`.
///
/// # Safety
/// `lp_cmd_line` must be a null-terminated UTF-16 string.
/// `p_num_args` must be a valid writable pointer to an `i32`.
pub unsafe extern "win64" fn command_line_to_argv_w(
    lp_cmd_line: *const u16,
    p_num_args: *mut i32,
) -> *mut *mut u16 {
    if p_num_args.is_null() {
        return std::ptr::null_mut();
    }

    let cmd = match unsafe { decode_wide_opt(lp_cmd_line) } {
        Some(s) => s,
        None => {
            unsafe { *p_num_args = 0 };
            return std::ptr::null_mut();
        }
    };

    // Simple tokeniser: splits on whitespace, respects double-quoted spans.
    let args = tokenise_cmd_line(&cmd);
    let n = args.len();

    if n == 0 {
        unsafe { *p_num_args = 0 };
        return std::ptr::null_mut();
    }

    // Compute total bytes: n pointer-slots + all null-terminated u16 strings.
    let ptr_block = n * std::mem::size_of::<*mut u16>();
    let str_bytes: usize = args.iter().map(|a| (a.len() + 1) * 2).sum();
    let total = ptr_block + str_bytes;

    let base = unsafe { libc::malloc(total) as *mut u8 };
    if base.is_null() {
        unsafe { *p_num_args = 0 };
        return std::ptr::null_mut();
    }

    // Fill pointer table and string data.
    let ptrs = base as *mut *mut u16;
    let mut str_ptr = unsafe { base.add(ptr_block) as *mut u16 };
    for (i, arg) in args.iter().enumerate() {
        unsafe { *ptrs.add(i) = str_ptr };
        for ch in arg.encode_utf16() {
            unsafe { *str_ptr = ch };
            str_ptr = unsafe { str_ptr.add(1) };
        }
        unsafe { *str_ptr = 0 };
        str_ptr = unsafe { str_ptr.add(1) };
    }

    unsafe { *p_num_args = n as i32 };
    ptrs
}

// ── Private helpers ───────────────────────────────────────────────────────────

unsafe fn decode_wide_opt(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    Some(String::from_utf16_lossy(slice).to_owned())
}

/// Tokenise a Win32 command-line string into a Vec of argument strings.
/// Handles double-quoted arguments; does not handle escape sequences.
fn tokenise_cmd_line(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars = s.chars().peekable();
    for c in chars {
        match c {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenise_simple() {
        let args = tokenise_cmd_line("foo bar baz");
        assert_eq!(args, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn tokenise_quoted() {
        let args = tokenise_cmd_line(r#"foo "bar baz" qux"#);
        assert_eq!(args, vec!["foo", "bar baz", "qux"]);
    }

    #[test]
    fn tokenise_empty() {
        assert!(tokenise_cmd_line("").is_empty());
    }

    #[test]
    fn csidl_personal_known() {
        assert!(csidl_to_win_path(CSIDL_PERSONAL).is_some());
    }

    #[test]
    fn csidl_unknown_returns_none() {
        assert!(csidl_to_win_path(0x99).is_none());
    }

    #[test]
    fn decode_wide_slice_basic() {
        let wide: Vec<u16> = "Hello".encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(decode_wide_slice(&wide), "Hello");
    }

    #[test]
    fn decode_wide_slice_no_null() {
        // Slice with no null terminator — should decode all chars.
        let wide: Vec<u16> = "Hi".encode_utf16().collect();
        assert_eq!(decode_wide_slice(&wide), "Hi");
    }
}
