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
const CSIDL_MYMUSIC: i32 = 0x000D;
const CSIDL_MYVIDEO: i32 = 0x000E;
const CSIDL_DESKTOPDIRECTORY: i32 = 0x0010; // filesystem Desktop dir
const CSIDL_MYPICTURES: i32 = 0x0027;
const CSIDL_APPDATA: i32 = 0x001a; // Roaming AppData
const CSIDL_LOCAL_APPDATA: i32 = 0x001c;
const CSIDL_PROGRAM_FILES: i32 = 0x0026;
const CSIDL_WINDOWS: i32 = 0x0024;
const CSIDL_SYSTEM: i32 = 0x0025;
const CSIDL_PROGRAM_FILES_X86: i32 = 0x002a;
const CSIDL_COMMON_APPDATA: i32 = 0x0023;
const CSIDL_PROFILE: i32 = 0x0028; // user profile root

// ── KNOWNFOLDERID GUIDs (as raw byte arrays for comparison) ──────────────────
// Little-endian byte representation matching the Windows GUID layout.

// {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
const FOLDERID_DESKTOP: [u8; 16] = [
    0x3A, 0xCC, 0xBF, 0xB4, 0x2C, 0xDB, 0x4C, 0x42, 0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41,
];
// {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
const FOLDERID_DOCUMENTS: [u8; 16] = [
    0xD0, 0x9A, 0xD3, 0xFD, 0x8F, 0x23, 0xAF, 0x46, 0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7,
];
// {4BD8D571-6D19-48D3-BE97-422220080E43}
const FOLDERID_MUSIC: [u8; 16] = [
    0x71, 0xD5, 0xD8, 0x4B, 0x19, 0x6D, 0xD3, 0x48, 0xBE, 0x97, 0x42, 0x22, 0x20, 0x08, 0x0E, 0x43,
];
// {33E28130-4E1E-4676-835A-98395C3BC3BB}
const FOLDERID_PICTURES: [u8; 16] = [
    0x30, 0x81, 0xE2, 0x33, 0x1E, 0x4E, 0x76, 0x46, 0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB,
];
// {18989B1D-99B5-455B-841C-AB7C74E4DDFC}
const FOLDERID_VIDEOS: [u8; 16] = [
    0x1D, 0x9B, 0x98, 0x18, 0xB5, 0x99, 0x5B, 0x45, 0x84, 0x1C, 0xAB, 0x7C, 0x74, 0xE4, 0xDD, 0xFC,
];
// {374DE290-123F-4565-9164-39C4925E467B}
const FOLDERID_DOWNLOADS: [u8; 16] = [
    0x90, 0xE2, 0x4D, 0x37, 0x3F, 0x12, 0x65, 0x45, 0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B,
];
// {3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}
const FOLDERID_ROAMING_APP_DATA: [u8; 16] = [
    0x3E, 0xB6, 0x85, 0xDB, 0x65, 0xF9, 0xF0, 0x40, 0x9D, 0xDE, 0x8C, 0x16, 0xAE, 0x37, 0xE4, 0x01,
];
// {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
const FOLDERID_LOCAL_APP_DATA: [u8; 16] = [
    0xF1, 0xB3, 0x2B, 0xF7, 0x07, 0xBB, 0xFC, 0x4A, 0xA6, 0x00, 0x1F, 0x34, 0xB4, 0x47, 0xD3, 0x62,
];
// {905e63b6-c1bf-494e-b29c-65b732d3d21a}
const FOLDERID_PROGRAM_FILES: [u8; 16] = [
    0x19, 0x55, 0xAA, 0x90, 0xE3, 0xAF, 0xD3, 0x11, 0xA0, 0xEA, 0x00, 0x80, 0xC7, 0x39, 0x1E, 0xA7,
];
// {F38BF404-1D43-42F2-9305-67DE0B28FC23}
const FOLDERID_WINDOWS: [u8; 16] = [
    0xF3, 0x8B, 0xF4, 0x1C, 0xBC, 0xE3, 0xD1, 0x11, 0xB4, 0xBF, 0x00, 0x80, 0xC7, 0x39, 0x1E, 0xA7,
];
// {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}
const FOLDERID_SYSTEM: [u8; 16] = [
    0xF4, 0x8B, 0xF4, 0x1C, 0xBC, 0xE3, 0xD1, 0x11, 0xB4, 0xBF, 0x00, 0x80, 0xC7, 0x39, 0x1E, 0xA7,
];

// ── XDG user-dir resolver ─────────────────────────────────────────────────────
//
// Returns the real Linux path for a named user directory (e.g. "DOCUMENTS").
// Tries `xdg-user-dir <name>` first; falls back to `$HOME/<fallback>` if the
// command is unavailable or returns an empty result.

fn xdg_user_dir(name: &str, fallback: &str) -> String {
    // Try xdg-user-dir first (available on most Linux desktops).
    if let Ok(output) = std::process::Command::new("xdg-user-dir")
        .arg(name)
        .output()
    {
        if output.status.success() {
            let raw = String::from_utf8_lossy(&output.stdout);
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    // Fall back to $HOME/<fallback>.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    format!("{home}/{fallback}")
}

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

/// Map a CSIDL to a path string.
///
/// Bridged CSIDLs (Documents, Desktop, Music, Pictures, Videos) return the
/// real Linux XDG directory path so that the Windows app reads/writes the
/// user's actual home directories. Non-bridged CSIDLs return prefix-relative
/// Windows paths as before.
fn csidl_to_win_path(n_folder: i32) -> Option<String> {
    match n_folder & 0xFF {
        // Bridged: return real Linux XDG paths (Landlock-allowed by weave-cli).
        CSIDL_PERSONAL => Some(xdg_user_dir("DOCUMENTS", "Documents")),
        CSIDL_DESKTOPDIRECTORY => Some(xdg_user_dir("DESKTOP", "Desktop")),
        CSIDL_MYMUSIC => Some(xdg_user_dir("MUSIC", "Music")),
        CSIDL_MYPICTURES => Some(xdg_user_dir("PICTURES", "Pictures")),
        CSIDL_MYVIDEO => Some(xdg_user_dir("VIDEOS", "Videos")),
        // Non-bridged: prefix-relative fake Windows paths.
        CSIDL_DESKTOP => Some(r"C:\Users\User\Desktop".to_string()),
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

/// Map a KNOWNFOLDERID (16-byte GUID) to a path string.
///
/// Bridged FOLDERIDs (Documents, Desktop, Music, Pictures, Videos, Downloads)
/// return the real Linux XDG directory path. Non-bridged GUIDs return
/// prefix-relative Windows paths as before.
fn known_folder_guid_to_win_path(guid: &[u8; 16]) -> Option<String> {
    // Bridged: return real Linux XDG paths.
    if guid == &FOLDERID_DOCUMENTS {
        return Some(xdg_user_dir("DOCUMENTS", "Documents"));
    }
    if guid == &FOLDERID_DESKTOP {
        return Some(xdg_user_dir("DESKTOP", "Desktop"));
    }
    if guid == &FOLDERID_MUSIC {
        return Some(xdg_user_dir("MUSIC", "Music"));
    }
    if guid == &FOLDERID_PICTURES {
        return Some(xdg_user_dir("PICTURES", "Pictures"));
    }
    if guid == &FOLDERID_VIDEOS {
        return Some(xdg_user_dir("VIDEOS", "Videos"));
    }
    if guid == &FOLDERID_DOWNLOADS {
        return Some(xdg_user_dir("DOWNLOAD", "Downloads"));
    }
    // Non-bridged: prefix-relative Windows paths.
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

/// Ensure the on-disk directory for a path exists.
///
/// Accepts either a real Linux path (bridged dirs) or a Windows-style path
/// (prefix-relative dirs). Linux paths (starting with `/`) are used directly;
/// Windows paths are translated via `WinPathTranslator`.
fn ensure_linux_dir(path: &str) {
    if path.starts_with('/') {
        // Real Linux path — bridged user dir.
        let _ = std::fs::create_dir_all(path);
    } else {
        // Windows-style prefix-relative path.
        let translator = weave_common::path::WinPathTranslator::new(prefix::get().to_path_buf());
        if let Ok(p) = translator.to_linux_str(path) {
            let _ = std::fs::create_dir_all(&p);
        }
    }
}

// ── Shell_NotifyIconW ─────────────────────────────────────────────────────────

/// Decode a null-terminated slice of UTF-16 code units to a `String`.
fn decode_wide_slice(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

// Wine ref: dlls/shell32/systray.c — Shell_NotifyIconW routes to the tray window via
// SendNotifyMessage; balloon tip text (NIM_MODIFY + NIF_INFO + szInfo) is displayed
// using the system balloon tip mechanism. Weave uses notify-send as a Linux equivalent.
// Wine ref: dlls/shell32/systray.c — routes NIM_ADD/MODIFY/DELETE to tray window via SendNotifyMessage;
// balloon (NIM_MODIFY+NIF_INFO+szInfo) displayed via system tooltip; see full ref above.
/// Shell_NotifyIconW: add, modify, or delete a taskbar notification icon.
///
/// Weave maps balloon tips (NIM_MODIFY + NIF_INFO) to Linux desktop
/// notifications via `notify-send`. All other operations (NIM_ADD, NIM_DELETE)
/// silently succeed. The icon handle is ignored — only text is surfaced.
///
/// # Safety
/// `lp_data` must be null or point to a valid `NOTIFYICONDATAW` struct.
// Wine ref: dlls/shell32/systray.c — NIM_ADD/MODIFY/DELETE via SendNotifyMessage to tray window.
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

// Wine ref: dlls/shell32/shellpath.c:2862 — delegates to SHGetFolderPathAndSubDirW which
// reads from registry (User Shell Folders / Shell Folders) with %USERPROFILE% expansion;
// converts ERROR_PATH_NOT_FOUND → ERROR_FILE_NOT_FOUND in the result; creates directory
// if CSIDL_FLAG_CREATE (0x8000) is set in nFolder. Weave uses hardcoded paths — acceptable
// since we're a synthetic environment with a fixed prefix layout.
// Wine ref: dlls/shell32/shellpath.c:2862 — reads registry User Shell Folders/%USERPROFILE%;
// creates dir if CSIDL_FLAG_CREATE set; see full behavioral ref in block comment above.
/// SHGetFolderPathW: return the path of a special shell folder.
///
/// Supports the most common CSIDL values. Returns `S_OK` (0) on success,
/// `E_FAIL` (0x80004005) if the CSIDL is unknown.
///
/// # Safety
/// `psz_path` must be a writable buffer of at least `MAX_PATH` (260) wide chars.
// Wine ref: dlls/shell32/shellpath.c:2862 — registry User Shell Folders; creates dir if CSIDL_FLAG_CREATE.
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

// Wine ref: dlls/shell32/shellpath.c:2838 — SHGetFolderPathA is a thin wrapper around
// SHGetFolderPathW; it calls the W variant then converts the wide result to ANSI via
// WideCharToMultiByte(CP_ACP). Our fake paths are pure ASCII so a direct byte copy
// suffices — no multi-byte conversion needed.
/// SHGetFolderPathA: ANSI variant of SHGetFolderPathW.
///
/// Returns `S_OK` (0) on success, `E_FAIL` (0x80004005) if the CSIDL is unknown.
///
/// # Safety
/// `psz_path` must be a writable buffer of at least `MAX_PATH` (260) bytes.
// Wine ref: dlls/shell32/shellpath.c:2838 — calls SHGetFolderPathW then WideCharToMultiByte(CP_ACP).
pub unsafe extern "win64" fn sh_get_folder_path_a(
    _h_wnd: usize,
    n_folder: i32,
    _h_token: usize,
    _dw_flags: u32,
    psz_path: *mut u8,
) -> u32 {
    match csidl_to_win_path(n_folder) {
        Some(win_path) => {
            ensure_linux_dir(&win_path);
            if !psz_path.is_null() {
                let bytes = win_path.as_bytes();
                let len = bytes.len().min(259);
                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), psz_path, len);
                    *psz_path.add(len) = 0;
                }
            }
            0 // S_OK
        }
        None => {
            eprintln!("weave/shell32: SHGetFolderPathA: unknown CSIDL {n_folder:#x}");
            0x8000_4005 // E_FAIL
        }
    }
}

// Wine ref: dlls/shell32/shellpath.c — SHGetSpecialFolderPathW wraps SHGetFolderPathW
// with SHGFP_TYPE_CURRENT; uses SHGetFolderPathA/W depending on Unicode flag.
// Returns TRUE/FALSE (not HRESULT) — same as Weave's impl.
// Wine ref: dlls/shell32/shellpath.c — wraps SHGetFolderPathW(SHGFP_TYPE_CURRENT);
// returns TRUE/FALSE (not HRESULT); see full ref in block comment above.
/// SHGetSpecialFolderPathW: older variant of SHGetFolderPathW.
///
/// # Safety
/// `psz_path` must be writable for at least 260 wide chars.
// Wine ref: dlls/shell32/shellpath.c — wraps SHGetFolderPathW(SHGFP_TYPE_CURRENT); returns TRUE/FALSE.
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

// Wine ref: dlls/shell32/shellpath.c:3552 — zeroes *ret_path before any work; converts GUID
// to CSIDL via csidl_from_id(), validates flags (E_INVALIDARG for unknown flag bits); allocates
// with CoTaskMemAlloc (caller must free with CoTaskMemFree). Returns E_POINTER if rfid/ret_path
// null; HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) for unknown GUIDs.
// Weave allocates with libc::malloc — compatible since co_task_mem_free uses libc::free.
// Wine ref: dlls/shell32/shellpath.c:3552 — zeroes *ret_path before work; converts GUID to CSIDL;
// allocates with CoTaskMemAlloc (caller frees); E_POINTER if rfid/ret_path null; see full ref above.
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
// Wine ref: dlls/shell32/shellpath.c:3552 — CoTaskMemAlloc result; E_POINTER if rfid/ppsz_path null.
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

// Wine ref: dlls/shell32/brsfolder.c — SHBrowseForFolderW creates a dialog via DialogBoxParamW;
// returns a PIDL (Shell Item ID List) allocated by CoTaskMemAlloc, or NULL if user cancelled.
// Callers always check return value before calling SHGetPathFromIDListW. Weave returns NULL
// (cancel) which apps handle as "user cancelled" — functionally correct as a stub.
// Wine ref: dlls/shell32/brsfolder.c — creates dialog via DialogBoxParamW; returns CoTaskMemAlloc'd
// PIDL or NULL if cancelled; caller must ILFree() the PIDL; see full ref above.
/// SHBrowseForFolderW: display a folder browser dialog.
///
/// Returns NULL (no folder selected / not implemented). Callers must handle
/// NULL gracefully — they check return value before calling SHGetPathFromIDListW.
///
/// # Safety
/// `lp_bi` may be null or a pointer to a BROWSEINFOW struct. Ignored.
// Wine ref: dlls/shell32/brsfolder.c — DialogBoxParamW; returns CoTaskMemAlloc'd PIDL or NULL on cancel.
pub unsafe extern "win64" fn sh_browse_for_folder_w(_lp_bi: *const u8) -> *mut u8 {
    std::ptr::null_mut() // NULL PIDL — user "cancelled"
}

// Wine ref: dlls/shell32/pidl.c — calls SHGetDesktopFolder then BindToObject to walk PIDL;
// returns FALSE if PIDL is NULL or not a filesystem item; zeros output buffer on failure.
/// SHGetPathFromIDListW: convert an item ID list (PIDL) to a path.
///
/// Returns FALSE. Since `sh_browse_for_folder_w` always returns NULL,
/// callers should never reach this with a valid PIDL. If they do, we
/// have no PIDL implementation, so we return FALSE and zero the buffer.
///
/// # Safety
/// `pidl` and `psz_path` may be null. If `psz_path` is non-null we zero it.
// Wine ref: dlls/shell32/pidl.c — SHGetDesktopFolder + BindToObject; FALSE if PIDL null or non-filesystem.
pub unsafe extern "win64" fn sh_get_path_from_id_list_w(
    _pidl: *const u8,
    psz_path: *mut u16,
) -> i32 {
    // Zero the output buffer so the caller gets an empty string, not garbage.
    if !psz_path.is_null() {
        unsafe { *psz_path = 0 };
    }
    0 // FALSE
}

// Wine ref: dlls/shell32/shellreg.c / user32 — sets/clears WS_EX_ACCEPTFILES style on hwnd;
// WM_DROPFILES is posted to the window when files are dropped onto it.
/// DragAcceptFiles: register (or unregister) a window as a drop target.
///
/// No-op — Weave has no drag-and-drop pipeline yet.
pub extern "win64" fn drag_accept_files(_hwnd: usize, _f_accept: i32) {}

// Wine ref: dlls/shell32/shelllink.c — reads HDROP (GlobalLock'd DROPFILES struct); iFile==0xFFFFFFFF
// returns total count; otherwise copies filename[iFile] to lpsz; returns char count copied.
/// DragQueryFileW: retrieve information about a dropped file.
///
/// Returns 0 (no files in drop). Since `DragAcceptFiles` is a no-op,
/// callers should not receive WM_DROPFILES and should not reach this.
///
/// # Safety
/// `lpsz_file` is not dereferenced unless iFile == 0xFFFFFFFF.
// Wine ref: dlls/shell32/shelllink.c — GlobalLock'd DROPFILES; 0xFFFFFFFF returns count; else copy path[i].
pub unsafe extern "win64" fn drag_query_file_w(
    _h_drop: usize,
    _i_file: u32,
    lpsz_file: *mut u16,
    _cch: u32,
) -> u32 {
    if !lpsz_file.is_null() {
        unsafe { *lpsz_file = 0 };
    }
    0 // 0 files
}

// Wine ref: dlls/shell32/shelllink.c — calls GlobalFree on the HDROP handle; must be called
// after WM_DROPFILES processing to release the shell-allocated DROPFILES buffer.
/// DragFinish: release resources for a dropped-files handle.
///
/// No-op.
pub extern "win64" fn drag_finish(_h_drop: usize) {}

// Wine ref: dlls/ole32/ifs.c — CoTaskMemFree calls IMalloc::Free on the task allocator;
// the task allocator wraps HeapFree(GetProcessHeap(), ...). NULL pointer is a no-op.
// Weave uses libc::free since SHGetKnownFolderPath allocates with libc::malloc — correct.
// Wine ref: dlls/ole32/ifs.c — calls IMalloc::Free on the task allocator (HeapFree(GetProcessHeap()));
// NULL is a no-op; see block comment above for context.
/// CoTaskMemFree: free memory allocated by COM task allocator.
///
/// In Weave, CoTaskMemAlloc == libc malloc, so we just call libc::free.
pub extern "win64" fn co_task_mem_free(pv: *mut u8) {
    if !pv.is_null() {
        unsafe { libc::free(pv as *mut libc::c_void) };
    }
}

// Wine ref: dlls/shell32/shlexec.c:2064 — builds SHELLEXECUTEINFOW, calls SHELL_execute
// then ShellExecuteExW; returns sei.hInstApp which is the module instance if launched or
// an error code ≤ 32 on failure. Any return value > 32 means success.
// Known gap: Weave always returns 33 (success) without actually launching anything.
// Wine ref: dlls/shell32/shlexec.c:2064 — builds SHELLEXECUTEINFOW, calls ShellExecuteExW;
// return > 32 means success; see block comment above for hInstApp encoding detail.
/// ShellExecuteW: perform an operation on a file (open, run, etc.).
///
/// Phase 2 stub: logs the operation and returns a fake HINSTANCE > 32
/// (indicating success per Win32 convention).
///
/// # Safety
/// All pointer arguments must be null or valid null-terminated UTF-16 strings.
// Wine ref: dlls/shell32/shlexec.c:2064 — builds SHELLEXECUTEINFOW + calls ShellExecuteExW; >32 = success.
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

// Wine ref: dlls/shell32/shlexec.c — converts ANSI args to Unicode via MultiByteToWideChar then
// calls ShellExecuteExW; returns hInstApp encoded as uintptr_t (> 32 = success, ≤ 32 = error code).
/// ShellExecuteA: ANSI variant of ShellExecuteW.
///
/// # Safety
/// All pointer arguments must be null or valid null-terminated ANSI strings.
// Wine ref: dlls/shell32/shlexec.c — MultiByteToWideChar then ShellExecuteExW; >32 = success.
pub unsafe extern "win64" fn shell_execute_a(
    _h_wnd: usize,
    _lp_operation: *const u8,
    _lp_file: *const u8,
    _lp_parameters: *const u8,
    _lp_directory: *const u8,
    _n_show_cmd: i32,
) -> usize {
    33 // SE_ERR_SUCCESS
}

// Wine ref: dlls/shcore/main.c:292 — if !numargs sets ERROR_INVALID_PARAMETER; if cmdline
// is empty, returns argv[0] = GetModuleFileName() (the executable path); handles backslash
// escape sequences inside double-quoted args (\\→\, \"→"); first arg (exe path) follows
// different quoting rules (only double-quote terminates, no backslash escape).
// Known gap: Weave's tokeniser doesn't handle backslash escapes; empty cmdline returns NULL
// instead of [executable_path].
// Wine ref: dlls/shcore/main.c:292 — if numargs null sets ERROR_INVALID_PARAMETER; empty cmdline
// returns [GetModuleFileName()]; handles backslash escapes inside quotes; see full ref above.
/// CommandLineToArgvW: parse a command-line string into an argv array.
///
/// Returns a pointer to an array of wide string pointers allocated with a
/// single `LocalAlloc`-style allocation. The caller must free it with
/// `LocalFree`.
///
/// # Safety
/// `lp_cmd_line` must be a null-terminated UTF-16 string.
/// `p_num_args` must be a valid writable pointer to an `i32`.
// Wine ref: dlls/shcore/main.c:292 — empty cmdline → [GetModuleFileName()]; backslash escapes in quotes.
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
    // Pointer validation: cap to prevent OOB read from unterminated input.
    const MAX_LEN: usize = 65_536;
    while len < MAX_LEN && unsafe { *p.add(len) } != 0 {
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

// ── Shell icon / info stubs ───────────────────────────────────────────────────

// Wine ref: dlls/user32/exticon.c:249 — ICO_ExtractIconExW loads icon from PE resource; nIconIndex
// < 0 means icon ID; 0xFFFFFFFF returns total count without extracting; fills phicon_large/small.
/// ExtractIconExW — extract icon handles from a file (Wide).
///
/// Returns 0 (no icons extracted) — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/user32/exticon.c:249 — ICO_ExtractIconExW; nIconIndex<0 means icon ID; 0xFFFFFFFF→count.
pub unsafe extern "win64" fn extract_icon_ex_w(
    _lp_sz_file: *const u16,
    _n_icon_index: i32,
    _phicon_large: *mut usize,
    _phicon_small: *mut usize,
    _n_icons: u32,
) -> u32 {
    0
}

// Wine ref: dlls/shell32/shfldr_desktop.c — returns singleton IShellFolder for the desktop
// namespace; creates on first call; AddRef'd before returning; E_POINTER if ppshf is NULL.
/// SHGetDesktopFolder — return the shell's desktop IShellFolder.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// `ppshf` is accepted but not dereferenced.
// Wine ref: dlls/shell32/shfldr_desktop.c — singleton IShellFolder; created on first call; AddRef'd.
pub unsafe extern "win64" fn sh_get_desktop_folder(_ppshf: *mut *mut u8) -> i32 {
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// Wine ref: dlls/shell32/shellpath.c — wraps SHGetFolderLocation(nFolder, 0); allocates PIDL
// with CoTaskMemAlloc; caller must ILFree(); E_INVALIDARG if ppidl is NULL.
/// SHGetSpecialFolderLocation — return the PIDL for a special folder.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// `ppidl` is accepted but not dereferenced.
// Wine ref: dlls/shell32/shellpath.c — SHGetFolderLocation(nFolder, 0); CoTaskMemAlloc PIDL; caller ILFree.
pub unsafe extern "win64" fn sh_get_special_folder_location(
    _hwnd_owner: usize,
    _n_folder: i32,
    _ppidl: *mut *mut u8,
) -> i32 {
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// Wine ref: dlls/shell32/shell32_main.c — queries icon index, display name, type name per uFlags;
// SHGFI_USEFILEATTRIBUTES skips disk access; returns HIMAGELIST handle or 0 on failure.
/// SHGetFileInfoW — retrieve information about an object in the shell namespace (Wide).
///
/// Returns 0 — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/shell32/shell32_main.c — icon index/display name/type by uFlags; SHGFI_USEFILEATTRIBUTES skips disk.
pub unsafe extern "win64" fn sh_get_file_info_w(
    _psz_path: *const u16,
    _dw_file_attributes: u32,
    _psfi: *mut u8,
    _cb_file_info: u32,
    _u_flags: u32,
) -> usize {
    0
}

// Wine ref: dlls/shell32/shlfileop.c — parses SHFILEOPSTRUCTW; dispatches to copy/delete/rename/move
// helpers; FOF_* flags control confirmation dialogs; returns 0 on success, non-zero on cancel/error.
/// SHFileOperationW — perform a file operation (copy/move/delete/rename) (Wide).
///
/// Returns 1 (operation aborted) — stub.
///
/// # Safety
/// `lpfo` is accepted but not dereferenced.
// Wine ref: dlls/shell32/shlfileop.c — parses SHFILEOPSTRUCTW; copy/delete/rename/move; 0=success.
pub unsafe extern "win64" fn sh_file_operation_w(_lpfo: *mut u8) -> i32 {
    1 // DE_OPCANCELLED — operation aborted
}

// Wine ref: dlls/shell32/changenotify.c — broadcasts SHCNE_* event to SHChangeNotifyRegister
// listeners; SHCNF_FLUSH waits for all recipients to process before returning.
/// SHChangeNotify — notify the shell of a change to the namespace.
///
/// No-op stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/shell32/changenotify.c — SHCNE_* event to registered listeners; SHCNF_FLUSH waits.
pub unsafe extern "win64" fn sh_change_notify(
    _w_event_id: i32,
    _u_flags: u32,
    _dw_item1: *const u8,
    _dw_item2: *const u8,
) {
}

// Wine ref: dlls/shell32/shlexec.c:2053 — calls SHELL_execute(sei, SHELL_ExecuteW); stores result
// in sei->hInstApp; returns TRUE if hInstApp > 32 (success), FALSE otherwise.
/// ShellExecuteExW — execute a shell operation (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// `lp_exec_info` is accepted but not dereferenced.
// Wine ref: dlls/shell32/shlexec.c:2053 — SHELL_execute(sei, SHELL_ExecuteW); TRUE if hInstApp > 32.
pub unsafe extern "win64" fn shell_execute_ex_w(_lp_exec_info: *mut u8) -> i32 {
    0 // FALSE
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
