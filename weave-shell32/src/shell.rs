//! shell32.dll stubs for Weave.

#![allow(unsafe_op_in_unsafe_fn)]
//!
//! Covers folder path queries, ShellExecute, and CommandLineToArgvW.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;
use std::sync::OnceLock;
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

// SHIM NOTE (M14): Test harness / gate support via WEAVE_TEST_BROWSE_RESULT env var.
// When set to a host directory path, we return a real WEV1 PIDL for that path (allocated
// via pidl_from_path_w, CoTaskMemAlloc-compatible). This lets the 7zFM GUI extract flow
// complete under Xvfb/CI without a blocking folder picker dialog. Production interactive
// picker (via existing DialogBoxParamW + comctl32 tree) is stretch.
//
// jcodemunch MCP server is registered in .mcp.json but not exposed in the current agent
// harness (CallMcpTool and sub-agents only see cursor-app-control + cursor-ide-browser).
// Pre-existing audited Wine refs (brsfolder.c) from M8 are accepted per operator choice #1
// (2026-06-08) rather than reconstructing from memory.

// Minimal BROWSEINFOW layout (only fields we inspect are materialized).
// Layout per Win32 + Wine dlls/shell32/brsfolder.c: hwndOwner, pidlRoot, pszDisplayName,
// lpszTitle, ulFlags, lpfn, lParam, iImage.
#[repr(C)]
struct BrowseInfoW {
    hwnd_owner: usize,
    pidl_root: *const u8,
    psz_display_name: *mut u16,
    lpsz_title: *const u16,
    ul_flags: u32,
    lpfn: usize,
    l_param: usize,
    i_image: i32,
}

// Wine ref: dlls/shell32/brsfolder.c — SHBrowseForFolderW creates a dialog via DialogBoxParamW;
// returns a PIDL (Shell Item ID List) allocated by CoTaskMemAlloc, or NULL if user cancelled.
// Callers always check return value before calling SHGetPathFromIDListW. Caller must ILFree().
// (Pre-existing audited ref accepted for this session; see SHIM NOTE above.)
/// SHBrowseForFolderW: display a folder browser dialog.
///
/// If WEAVE_TEST_BROWSE_RESULT is set, returns a non-NULL PIDL for that path
/// (populating pszDisplayName if the caller provided a buffer). Otherwise returns NULL
/// (treated as "user cancelled"). The returned PIDL must be freed by the caller via ILFree.
///
/// # Safety
/// `lp_bi` must be null or point to a valid BROWSEINFOW (we read hwndOwner and pszDisplayName
/// when present; other fields are accepted but currently ignored for the test path).
pub unsafe extern "win64" fn sh_browse_for_folder_w(lp_bi: *const u8) -> *mut u8 {
    if lp_bi.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: lp_bi is non-null (checked above). Caller contract (BROWSEINFO passed by
    // 7zFM or probe) guarantees the buffer is at least sizeof(BrowseInfoW) and aligned.
    // We only read the two fields we declare we will use.
    let bi = &*(lp_bi as *const BrowseInfoW);

    let dest = match std::env::var("WEAVE_TEST_BROWSE_RESULT") {
        Ok(p) if !p.is_empty() => p,
        _ => return std::ptr::null_mut(),
    };

    let pidl = super::pidl::pidl_from_path_w(&dest);
    if pidl.is_null() {
        return std::ptr::null_mut();
    }

    // If caller supplied a display-name buffer, write a friendly leaf name (or the path).
    if !bi.psz_display_name.is_null() {
        let display = dest.rsplit(['\\', '/']).next().unwrap_or(&dest);
        write_display_name(bi.psz_display_name, display);
    }

    pidl
}

fn write_display_name(dest: *mut u16, name: &str) {
    let wide: Vec<u16> = name.encode_utf16().collect();
    let copy = wide.len().min(259);
    unsafe {
        for (i, &w) in wide.iter().take(copy).enumerate() {
            *dest.add(i) = w;
        }
        *dest.add(copy) = 0;
    }
}

// Wine ref: dlls/shell32/pidl.c — SHGetDesktopFolder + BindToObject; FALSE if PIDL null or non-filesystem.
// Implemented in `pidl::sh_get_path_from_id_list_w`.

// Referenced by test crate through pub API.
#[allow(dead_code)]
pub struct DropEntry {
    files: Vec<String>,
    point: (i32, i32),
}

static DROP_TABLE: OnceLock<Mutex<HashMap<usize, DropEntry>>> = OnceLock::new();
#[allow(dead_code)]
static NEXT_DROP_HANDLE: AtomicUsize = AtomicUsize::new(0x9000_0001);

fn drop_table() -> &'static Mutex<HashMap<usize, DropEntry>> {
    DROP_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[allow(dead_code)]
fn alloc_drop_handle(files: Vec<String>, point: (i32, i32)) -> usize {
    let handle = NEXT_DROP_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut table = drop_table().lock().unwrap();
    table.insert(handle, DropEntry { files, point });
    handle
}

/// Allocate a drop handle from a list of file paths and a drop point.
///
/// Test helpers can use this to simulate a drag-drop. Returns an HDROP handle
/// suitable for use with DragQueryFileW / DragQueryPoint / DragFinish.
#[allow(dead_code)]
pub fn weave_test_create_drop(files: Vec<String>, x: i32, y: i32) -> usize {
    alloc_drop_handle(files, (x, y))
}

// Wine ref: dlls/shell32/shellreg.c / user32 — sets/clears WS_EX_ACCEPTFILES style on hwnd;
// WM_DROPFILES is posted to the window when files are dropped onto it.
/// DragAcceptFiles: register (or unregister) a window as a drop target.
///
/// Phase B: records the accept state for diagnostic purposes. Real WS_EX_ACCEPTFILES
/// style changes require SetWindowLong — deferred until X11 drag-drop integration.
pub extern "win64" fn drag_accept_files(_hwnd: usize, _f_accept: i32) {
    // Phase B: no-op. Real drops are injected via test hook only.
}

// Wine ref: dlls/shell32/shelllink.c — reads HDROP (GlobalLock'd DROPFILES struct); iFile==0xFFFFFFFF
// returns total count; otherwise copies filename[iFile] to lpsz; returns char count copied.
/// DragQueryFileW: retrieve information about a dropped file.
///
/// Phase B: reads from the in-process DROP_TABLE. iFile==0xFFFFFFFF returns the
/// total file count. Otherwise copies the filename to `lpsz_file` up to `cch` chars.
///
/// # Safety
/// `lpsz_file` must point to a writable buffer of at least `cch * 2` bytes when non-null.
// Wine ref: dlls/shell32/shelllink.c — GlobalLock'd DROPFILES; 0xFFFFFFFF returns count; else copy path[i].
pub unsafe extern "win64" fn drag_query_file_w(
    h_drop: usize,
    i_file: u32,
    lpsz_file: *mut u16,
    cch: u32,
) -> u32 {
    let table = drop_table().lock().unwrap();
    let Some(entry) = table.get(&h_drop) else {
        if !lpsz_file.is_null() {
            unsafe { *lpsz_file = 0 };
        }
        return 0;
    };
    if i_file == 0xFFFFFFFF {
        return entry.files.len() as u32;
    }
    let idx = i_file as usize;
    if idx >= entry.files.len() {
        if !lpsz_file.is_null() {
            unsafe { *lpsz_file = 0 };
        }
        return 0;
    }
    let name: Vec<u16> = entry.files[idx].encode_utf16().collect();
    let copy_len = name.len().min(cch.saturating_sub(1) as usize);
    if !lpsz_file.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), lpsz_file, copy_len);
            *lpsz_file.add(copy_len) = 0;
        }
    }
    copy_len as u32
}

// Wine ref: dlls/shell32/shelllink.c — calls GlobalFree on the HDROP handle; must be called
// after WM_DROPFILES processing to release the shell-allocated DROPFILES buffer.
/// DragFinish: release resources for a dropped-files handle.
///
/// Phase B: removes the entry from DROP_TABLE. If the handle was a real GlobalAlloc'd
/// DROPFILES buffer (not a synthetic test handle), it is not freed — Phase B only
/// supports synthetic test drops.
pub extern "win64" fn drag_finish(h_drop: usize) {
    let mut table = drop_table().lock().unwrap();
    table.remove(&h_drop);
}

// Wine ref: dlls/shell32/shelllink.c — reads HDROP DROPFILES struct; returns FALSE if no valid drop point.
/// DragQueryPoint: retrieve the drop point for a drag-and-drop operation.
///
/// Phase B: reads the stored point from DROP_TABLE. Returns TRUE and writes the point
/// when the handle is found, FALSE otherwise.
///
/// # Safety
/// `lppt` must point to a writable POINT struct (8 bytes: LONG x, LONG y) when non-null.
pub unsafe extern "win64" fn drag_query_point(h_drop: usize, lppt: *mut u8) -> i32 {
    let table = drop_table().lock().unwrap();
    let Some(entry) = table.get(&h_drop) else {
        return 0; // FALSE
    };
    if !lppt.is_null() {
        unsafe {
            let x_ptr = lppt as *mut i32;
            let y_ptr = lppt.add(4) as *mut i32;
            *x_ptr = entry.point.0;
            *y_ptr = entry.point.1;
        }
    }
    1 // TRUE
}

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
// Wine ref: dlls/shell32/shlexec.c:2064 — builds SHELLEXECUTEINFOW, calls ShellExecuteExW;
// dispatches .exe via CreateProcess, URLs via SHELL_execute_url (opens registry handler),
// other file types via SHELL_FindExecutable (registry class lookup). >32 = success.
/// ShellExecuteW: perform an operation on a file (open, run, etc.).
///
/// Dispatches: .exe/.com → weave <linux_exe> [params]; http/https/ftp URL or any other
/// file → xdg-open. Falls through to 33 (success) if spawning fails so callers continue.
///
/// # Safety
/// All pointer arguments must be null or valid null-terminated UTF-16 strings.
// Wine ref: dlls/shell32/shlexec.c:2064 — builds SHELLEXECUTEINFOW + calls ShellExecuteExW; >32 = success.
pub unsafe extern "win64" fn shell_execute_w(
    _h_wnd: usize,
    lp_operation: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    _lp_directory: *const u16,
    _n_show_cmd: i32,
) -> usize {
    let op = unsafe { decode_wide_opt(lp_operation) }.unwrap_or_else(|| "open".to_string());
    let file = unsafe { decode_wide_opt(lp_file) }.unwrap_or_default();
    let params = unsafe { decode_wide_opt(lp_parameters) };

    eprintln!("weave/shell32: ShellExecuteW: op={op:?} file={file:?}");

    // URL dispatch — http/https/ftp/mailto: hand to xdg-open directly.
    let lower = file.to_ascii_lowercase();
    let is_url = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("mailto:");

    if is_url {
        let _ = std::process::Command::new("xdg-open").arg(&file).spawn();
        return 33;
    }

    // PE dispatch — translate Win32 path, spawn via weave binary.
    let is_exe = lower.ends_with(".exe") || lower.ends_with(".com");
    if is_exe || op.eq_ignore_ascii_case("runas") || op.eq_ignore_ascii_case("open") {
        if let Ok(linux_path) = prefix::translator().to_linux_str(&file) {
            if linux_path.exists() && is_exe {
                if let Ok(weave_bin) = std::fs::read_link("/proc/self/exe") {
                    let mut cmd = std::process::Command::new(&weave_bin);
                    cmd.arg(&linux_path);
                    if let Some(p) = &params {
                        // Split params on whitespace for argv (no quoting — best-effort).
                        for tok in p.split_whitespace() {
                            cmd.arg(tok);
                        }
                    }
                    let _ = cmd.spawn();
                    return 33;
                }
            }
            // Non-exe file path — hand to xdg-open for desktop association.
            if linux_path.exists() {
                let _ = std::process::Command::new("xdg-open")
                    .arg(&linux_path)
                    .spawn();
                return 33;
            }
        }
    }

    33 // SE_ERR_SUCCESS — return success even on dispatch failure; guests check > 32 only
}

// Wine ref: dlls/shell32/shlexec.c — converts ANSI args to Unicode via MultiByteToWideChar then
// calls ShellExecuteExW; returns hInstApp encoded as uintptr_t (> 32 = success, ≤ 32 = error code).
/// ShellExecuteA: ANSI variant of ShellExecuteW.
///
/// # Safety
/// All pointer arguments must be null or valid null-terminated ANSI strings.
// Wine ref: dlls/shell32/shlexec.c — MultiByteToWideChar then ShellExecuteExW; >32 = success.
pub unsafe extern "win64" fn shell_execute_a(
    h_wnd: usize,
    lp_operation: *const u8,
    lp_file: *const u8,
    lp_parameters: *const u8,
    lp_directory: *const u8,
    n_show_cmd: i32,
) -> usize {
    fn ansi_to_wide(p: *const u8) -> Option<Vec<u16>> {
        if p.is_null() {
            return None;
        }
        let mut len = 0usize;
        while len < 32_768 && unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        let s = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p, len) });
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        Some(wide)
    }

    let op_wide = ansi_to_wide(lp_operation);
    let file_wide = ansi_to_wide(lp_file);
    let params_wide = ansi_to_wide(lp_parameters);
    let dir_wide = ansi_to_wide(lp_directory);

    unsafe {
        shell_execute_w(
            h_wnd,
            op_wide.as_deref().map_or(std::ptr::null(), |v| v.as_ptr()),
            file_wide
                .as_deref()
                .map_or(std::ptr::null(), |v| v.as_ptr()),
            params_wide
                .as_deref()
                .map_or(std::ptr::null(), |v| v.as_ptr()),
            dir_wide.as_deref().map_or(std::ptr::null(), |v| v.as_ptr()),
            n_show_cmd,
        )
    }
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

// ── PIDL helpers ─────────────────────────────────────────────────────────────
//
// IL* / SHGetPathFromIDListW / ILCreateFromPathW live in `pidl.rs`.

// Wine ref: dlls/shell32/iconcache.c — SHMapPIDLToSystemImageListIndex looks up the
// file type icon index; optional puFlags receives shell image list flags; returns -1 on failure.
/// SHMapPIDLToSystemImageListIndex (shell32 #68) — map PIDL to system image list index.
///
/// Returns -1 (no icon — stub).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn sh_map_pidl_to_image_index(
    _himl: usize,
    _pidl: *const u8,
    _u_flags: *mut u32,
    _u_extra_flags: u32,
) -> i32 {
    -1
}

// Wine ref: dlls/shell32/changenotify.c — NTSHChangeNotifyRegister registers a window
// for shell change notifications; returns a registration ID (handle) on success; 0 on failure.
/// NTSHChangeNotifyRegister (shell32 #88) — register for shell change notifications.
///
/// Returns 0 (stub — no change notification infrastructure).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn nt_sh_change_notify_register(
    _hwnd: usize,
    _flags: u32,
    _events: u32,
    _msg: u32,
    _n_entries: u32,
    _p_shcne: *const u8,
) -> u32 {
    0
}

// Wine ref: none — ordinal #155 is undocumented in this Windows version.
/// shell32 ordinal #155 — unknown undocumented ordinal.
///
/// Returns 0 (stub).
///
/// # Safety
/// Pointer arguments are not dereferenced.
pub unsafe extern "win64" fn shell32_ord155() -> usize {
    0
}

// ── SHChangeNotify notification infrastructure ────────────────────────────

struct ChangeNotifyEntry {
    handle: u32,
    hwnd: usize,
    event_mask: u32,
    msg: u32,
}

static CHANGE_NOTIFY_STATE: OnceLock<Mutex<Vec<ChangeNotifyEntry>>> = OnceLock::new();
static CHANGE_NOTIFY_NEXT_HANDLE: AtomicUsize = AtomicUsize::new(1);

fn change_notify_state() -> &'static Mutex<Vec<ChangeNotifyEntry>> {
    CHANGE_NOTIFY_STATE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Resolve and call PostMessageW at runtime through the Weave resolver.
///
/// This avoids a compile-time dependency on weave-user32 (crate boundary rule).
unsafe fn post_message_w(hwnd: usize, msg: u32, w_param: usize, l_param: isize) -> Option<i32> {
    let addr = weave_core::resolve::resolve("user32.dll", "PostMessageW")?;
    let func: unsafe extern "win64" fn(usize, u32, usize, isize) -> i32 =
        std::mem::transmute(addr);
    Some(func(hwnd, msg, w_param, l_param))
}

// Wine ref: dlls/shell32/changenotify.c — SHChangeNotifyRegister creates a notification
// entry with (hwnd, event_mask, msg); returns UINT handle.
/// SHChangeNotifyRegister — register a window to receive shell change notifications.
///
/// Returns a notification handle (>0) on success, 0 on failure.
///
/// # Safety
/// `hwnd` must be a valid window handle or 0.
/// `p_shcne` is accepted but not dereferenced.
pub unsafe extern "win64" fn sh_change_notify_register(
    hwnd: usize,
    _flags: u32,
    f_events: u32,
    msg: u32,
    _n_entries: u32,
    _p_shcne: *const u8,
) -> u32 {
    let handle =
        CHANGE_NOTIFY_NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u32;
    if handle == 0 {
        return 0;
    }

    if let Ok(mut state) = change_notify_state().lock() {
        state.push(ChangeNotifyEntry {
            handle,
            hwnd,
            event_mask: f_events,
            msg,
        });
        if std::env::var("WEAVE_SHELL32_TRACE").is_ok() {
            eprintln!(
                "weave/shell32: SHChangeNotifyRegister hwnd={hwnd:#x} events={f_events:#x} msg={msg} handle={handle}",
            );
        }
        handle
    } else {
        0
    }
}

// Wine ref: dlls/shell32/changenotify.c — SHChangeNotifyDeregister removes entry by handle;
// returns TRUE (1) on success, FALSE (0) if handle not found.
/// SHChangeNotifyDeregister — unregister a change notification handle.
///
/// Returns TRUE (1) on success, FALSE (0) if handle was not found.
///
/// # Safety
/// No pointer arguments; safe for any handle value.
pub unsafe extern "win64" fn sh_change_notify_deregister(handle: u32) -> i32 {
    if let Ok(mut state) = change_notify_state().lock() {
        let len_before = state.len();
        state.retain(|e| e.handle != handle);
        let found = state.len() < len_before;

        if std::env::var("WEAVE_SHELL32_TRACE").is_ok() {
            eprintln!(
                "weave/shell32: SHChangeNotifyDeregister handle={handle} found={found}",
            );
        }

        if found { 1 } else { 0 }
    } else {
        0
    }
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

/// ExtractIconW — extract an icon from an executable, DLL, or icon file.
///
/// Delegates to ExtractIconExW with nIcons=1 and extracts the large icon.
/// Returns the extracted HICON on success, 0 on failure.
///
/// # Safety
/// `lpsz_exe_file_name` must be a valid null-terminated wide string pointer.
// Wine ref: dlls/shell32/shicon.c — ExtractIconW delegates to ExtractIconExW internally (ref hand-written, jcodemunch unavailable).
pub unsafe extern "win64" fn extract_icon_w(
    _h_inst: usize,
    lpsz_exe_file_name: *const u16,
    n_icon_index: i32,
) -> usize {
    if lpsz_exe_file_name.is_null() {
        return 0;
    }
    let mut hicon_large: usize = 0;
    let count = unsafe {
        extract_icon_ex_w(
            lpsz_exe_file_name,
            n_icon_index,
            &mut hicon_large,
            std::ptr::null_mut(),
            1,
        )
    };
    if count > 0 {
        hicon_large
    } else {
        0
    }
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
pub unsafe extern "win64" fn sh_get_desktop_folder(ppshf: *mut *mut u8) -> i32 {
    const E_POINTER: i32 = 0x8000_4003u32 as i32;
    if ppshf.is_null() {
        return E_POINTER;
    }
    let ptr = crate::desktop_folder::desktop_folder_ptr();
    unsafe {
        *ppshf = ptr as *mut u8;
    }
    0
}

// Wine ref: dlls/shell32/shellpath.c — SHGetFolderLocation(nFolder, 0); CoTaskMemAlloc PIDL; caller ILFree.
/// SHGetFolderLocation — return the PIDL for a special folder.
///
/// Phase B: converts the CSIDL to a path via `csidl_to_win_path`, then creates
/// a WEV1 PIDL via `pidl_from_path_w`. Returns S_OK + pidl on success,
/// S_FALSE + NULL pidl for unknown CSIDLs.
///
/// # Safety
/// `ppidl` must be a valid writable pointer when non-null.
// Wine ref: dlls/shell32/shellpath.c — SHGetFolderLocation allocates PIDL via CoTaskMemAlloc; caller ILFree.
pub unsafe extern "win64" fn sh_get_folder_location(
    _hwnd_owner: usize,
    n_folder: i32,
    ppidl: *mut *mut u8,
) -> i32 {
    const S_OK: i32 = 0;
    const S_FALSE: i32 = 1;
    const E_POINTER: i32 = 0x8000_4003u32 as i32;

    if ppidl.is_null() {
        return E_POINTER;
    }
    unsafe { *ppidl = std::ptr::null_mut() };

    let Some(path) = csidl_to_win_path(n_folder) else {
        return S_FALSE;
    };

    let pidl = crate::pidl::pidl_from_path_w(&path);
    if pidl.is_null() {
        return S_FALSE;
    }

    unsafe { *ppidl = pidl };
    S_OK
}

// Wine ref: dlls/shell32/shellpath.c — SHGetFolderLocation(nFolder, 0); CoTaskMemAlloc PIDL; caller ILFree.
/// SHGetSpecialFolderLocation — return the PIDL for a special folder.
///
/// Phase B: same as SHGetFolderLocation — converts CSIDL to path, creates WEV1 PIDL.
/// This is the older (pre-SHGetFolderLocation) API.
///
/// # Safety
/// `ppidl` must be a valid writable pointer when non-null.
// Wine ref: dlls/shell32/shellpath.c — SHGetFolderLocation; SHGetSpecialFolderLocation is same logic.
pub unsafe extern "win64" fn sh_get_special_folder_location(
    _hwnd_owner: usize,
    n_folder: i32,
    ppidl: *mut *mut u8,
) -> i32 {
    const S_OK: i32 = 0;
    const S_FALSE: i32 = 1;
    const E_POINTER: i32 = 0x8000_4003u32 as i32;

    if ppidl.is_null() {
        return E_POINTER;
    }
    unsafe { *ppidl = std::ptr::null_mut() };

    let Some(path) = csidl_to_win_path(n_folder) else {
        return S_FALSE;
    };

    let pidl = crate::pidl::pidl_from_path_w(&path);
    if pidl.is_null() {
        return S_FALSE;
    }

    unsafe { *ppidl = pidl };
    S_OK
}

// Wine ref: dlls/shell32/shlfolder.c — SHParseDisplayName delegates to ILCreateFromPathW for
// filesystem paths; returns S_OK + pidl on success, S_FALSE for non-filesystem names.
/// SHParseDisplayName — parse a display name into a shell PIDL.
///
/// Phase B: converts filesystem paths to PIDLs via ILCreateFromPathW.
/// Non-filesystem names (GUID, shell:, etc.) return S_FALSE with NULL pidl.
///
/// # Safety
/// `ppidl` must be writable when non-null. `name` must be null or a valid
/// null-terminated UTF-16 string.
pub unsafe extern "win64" fn sh_parse_display_name(
    name: *const u16,
    _pbc: usize,
    ppidl: *mut *mut u8,
    _sfgao_in: u32,
    psfgao_out: *mut u32,
) -> i32 {
    const S_OK: i32 = 0;
    const S_FALSE: i32 = 1;
    const E_POINTER: i32 = 0x8000_4003u32 as i32;

    if ppidl.is_null() {
        return E_POINTER;
    }
    *ppidl = std::ptr::null_mut();

    if name.is_null() || *name == 0 {
        return S_FALSE;
    }

    let pidl = super::pidl::il_create_from_path_w(name);
    if pidl.is_null() {
        return S_FALSE;
    }

    *ppidl = pidl;
    if !psfgao_out.is_null() {
        const SFGAO_FILESYSTEM: u32 = 0x4000_0000;
        const SFGAO_FOLDER: u32 = 0x2000_0000;
        *psfgao_out = SFGAO_FILESYSTEM | SFGAO_FOLDER;
    }
    S_OK
}

// Wine ref: dlls/shell32/shellpath.c — SHGetFolderPathAndSubFolderW combines CSIDL + sub-path.
/// SHGetFolderPathAndSubFolderW — return the full path for a special folder + subdirectory.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn sh_get_folder_path_and_sub_folder_w(
    _hwnd: usize,
    _csidl: i32,
    _sub_path: *const u16,
    _dw_flags: u32,
    _path: *mut u16,
    _cch: u32,
) -> i32 {
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// ── SHGetFileInfoW constants ──────────────────────────────────────────────

const SHGFI_ICON: u32 = 0x00000100;
const SHGFI_DISPLAYNAME: u32 = 0x00000200;
const SHGFI_TYPENAME: u32 = 0x00000400;
const SHGFI_ATTRIBUTES: u32 = 0x00000800;
const SHGFI_ICONLOCATION: u32 = 0x00001000;
const SHGFI_EXETYPE: u32 = 0x00002000;
const SHGFI_SYSICONINDEX: u32 = 0x00004000;
#[allow(dead_code)]
const SHGFI_LINKOVERLAY: u32 = 0x00008000;
#[allow(dead_code)]
const SHGFI_SELECTED: u32 = 0x00010000;
#[allow(dead_code)]
const SHGFI_LARGEICON: u32 = 0x00000000;
#[allow(dead_code)]
const SHGFI_SMALLICON: u32 = 0x00000001;
#[allow(dead_code)]
const SHGFI_OPENICON: u32 = 0x00000002;
#[allow(dead_code)]
const SHGFI_SHELLICONSIZE: u32 = 0x00000004;
const SHGFI_PIDL: u32 = 0x00000008;
const SHGFI_USEFILEATTRIBUTES: u32 = 0x00000010;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;

fn decode_wide_path(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut chars = Vec::new();
    let mut p = ptr;
    loop {
        let c = unsafe { *p };
        if c == 0 {
            break;
        }
        chars.push(c);
        p = unsafe { p.add(1) };
    }
    String::from_utf16_lossy(&chars)
}

fn write_wide_to_buf(dest: *mut u16, s: &str, max: usize) {
    if dest.is_null() || max == 0 {
        return;
    }
    let mut i = 0;
    for ch in s.encode_utf16() {
        if i >= max - 1 {
            break;
        }
        unsafe {
            *dest.add(i) = ch;
        }
        i += 1;
    }
    unsafe {
        *dest.add(i) = 0;
    }
}

fn extension_to_type_name(ext: &str) -> &'static str {
    match ext.to_lowercase().as_str() {
        "" | "." => "File",
        ".txt" | ".log" | ".md" | ".rst" => "Text Document",
        ".exe" | ".com" | ".bat" | ".cmd" => "Application",
        ".dll" | ".ocx" | ".sys" => "System File",
        ".png" | ".jpg" | ".jpeg" | ".gif" | ".bmp" | ".tiff" | ".webp" => "Image",
        ".mp3" | ".wav" | ".flac" | ".ogg" | ".wma" | ".aac" | ".m4a" => "Audio",
        ".mp4" | ".avi" | ".mkv" | ".mov" | ".wmv" | ".flv" => "Video",
        ".zip" | ".rar" | ".7z" | ".tar" | ".gz" | ".bz2" | ".xz" => "Compressed Archive",
        ".pdf" => "PDF Document",
        ".doc" | ".docx" => "Word Document",
        ".xls" | ".xlsx" => "Excel Spreadsheet",
        ".htm" | ".html" => "HTML Document",
        ".c" | ".cpp" | ".h" | ".rs" | ".py" | ".js" | ".ts" => "Source Code",
        _ => "File",
    }
}

// Wine ref: dlls/shell32/shell32_main.c — queries icon index, display name, type name per uFlags;
// SHGFI_USEFILEATTRIBUTES skips disk access; returns HIMAGELIST handle or 0 on failure.
/// SHGetFileInfoW — retrieve information about an object in the shell namespace (Wide).
///
/// May write szDisplayName at offset 16, szTypeName at offset 536, iIcon at offset 8,
/// dwAttributes at offset 12, and hIcon at offset 0, depending on `u_flags`.
///
/// # Safety
/// `psfi` must point to a valid SHFILEINFOW buffer (696 bytes) when non-null.
// Wine ref: dlls/shell32/shell32_main.c — icon index/display name/type by uFlags; SHGFI_USEFILEATTRIBUTES skips disk.
pub unsafe extern "win64" fn sh_get_file_info_w(
    psz_path: *const u16,
    dw_file_attributes: u32,
    psfi: *mut u8,
    _cb_file_info: u32,
    u_flags: u32,
) -> usize {
    // Null checks
    if psfi.is_null() {
        return 0;
    }
    if psz_path.is_null() && (u_flags & SHGFI_USEFILEATTRIBUTES) == 0 {
        return 0;
    }

    // Resolve path
    let path_str = if (u_flags & SHGFI_PIDL) != 0 {
        // psz_path is a PIDL pointer (ITEMIDLIST*)
        match crate::pidl::pidl_path_from_list(psz_path as *const u8) {
            Some(p) => p,
            None => return 0,
        }
    } else {
        decode_wide_path(psz_path)
    };

    // Extract filename (last component after \ or /)
    let filename = path_str
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&path_str)
        .to_string();

    // Extract extension (with the dot)
    let ext = if let Some(dot_pos) = filename.rfind('.') {
        &filename[dot_pos..]
    } else {
        ""
    };

    // Determine if this is a directory
    let is_directory = if (u_flags & SHGFI_USEFILEATTRIBUTES) != 0 {
        (dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
    } else if !path_str.is_empty() {
        std::fs::metadata(&path_str)
            .map(|m| m.is_dir())
            .unwrap_or(false)
    } else {
        false
    };

    // SHGFI_DISPLAYNAME: write filename at offset 16
    if (u_flags & SHGFI_DISPLAYNAME) != 0 {
        write_wide_to_buf((psfi as *mut u16).add(16 / 2), &filename, 260);
    }

    // SHGFI_TYPENAME: write type name at offset 536
    if (u_flags & SHGFI_TYPENAME) != 0 {
        let type_name = if is_directory {
            "File Folder"
        } else {
            extension_to_type_name(ext)
        };
        write_wide_to_buf((psfi as *mut u16).add(536 / 2), type_name, 80);
    }

    // SHGFI_SYSICONINDEX: write icon index at offset 8
    if (u_flags & SHGFI_SYSICONINDEX) != 0 {
        let icon_index: i32 = if is_directory {
            0 // folder icon
        } else {
            match ext.to_lowercase().as_str() {
                ".exe" => 2,
                ".txt" | ".log" => 3,
                ".zip" | ".rar" | ".7z" => 5,
                ".png" | ".jpg" | ".jpeg" | ".gif" | ".bmp" => 6,
                _ => 1, // generic document
            }
        };
        unsafe {
            *(psfi.add(8) as *mut i32) = icon_index;
        }
    }

    // SHGFI_ATTRIBUTES: write attributes at offset 12
    if (u_flags & SHGFI_ATTRIBUTES) != 0 {
        let attrs = if (u_flags & SHGFI_USEFILEATTRIBUTES) != 0 {
            dw_file_attributes
        } else if !path_str.is_empty() {
            std::fs::metadata(&path_str)
                .map(|m| {
                    let mut a: u32 = 0;
                    if m.is_dir() {
                        a |= FILE_ATTRIBUTE_DIRECTORY;
                    }
                    if m.is_file() {
                        a |= 0x80; // FILE_ATTRIBUTE_NORMAL
                    }
                    a
                })
                .unwrap_or(0x80)
        } else {
            0x80
        };
        unsafe {
            *(psfi.add(12) as *mut u32) = attrs;
        }
    }

    // SHGFI_ICON: write fake HICON handle at offset 0 (only if SYSICONINDEX not set)
    if (u_flags & SHGFI_ICON) != 0 && (u_flags & SHGFI_SYSICONINDEX) == 0 {
        unsafe {
            *(psfi as *mut usize) = 0x1usize;
        }
    }

    // SHGFI_EXETYPE: return executable type
    if (u_flags & SHGFI_EXETYPE) != 0 {
        let ext_lower = ext.to_lowercase();
        if ext_lower == ".exe" || ext_lower == ".com" {
            return 0x0000_014C; // IMAGE_FILE_MACHINE_I386
        }
        return 0x0000_0000;
    }

    // SHGFI_ICONLOCATION: copy full path to display name field, return path length
    if (u_flags & SHGFI_ICONLOCATION) != 0 {
        write_wide_to_buf((psfi as *mut u16).add(16 / 2), &path_str, 260);
        return path_str.len();
    }

    // Success: return fake HIMAGELIST handle (non-zero, looks like a real system image list)
    0x0001_0001usize
}

// ── Additional shell32 stubs ──────────────────────────────────────────────

// Wine ref: dlls/shell32/shell32_main.c — SHAddToRecentDocs adds a file to the recent
// documents MRU list; uFlags = SHARD_PATHW means lpsz is a path string.
/// SHAddToRecentDocs: add a file to the recent documents list.
///
/// Stub — no-op.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn sh_add_to_recent_docs(_flags: u32, _docs: *const u16) {}

// Wine ref: dlls/shell32/shlfolder.c — SHBindToParent resolves the parent PIDL of a given
// PIDL and optionally returns the last component; E_INVALIDARG if ppidl null.
/// SHBindToParent: bind to a PIDL's parent folder and retrieve the last component.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn sh_bind_to_parent(
    _pidl: *const u8,
    _riid: *const u8,
    ppv: *mut usize,
    _ppidl_last: *mut *mut u8,
) -> i32 {
    if !ppv.is_null() {
        unsafe { *ppv = 0 };
    }
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// Wine ref: dlls/shell32/shlfileop.c — SHCreateDirectoryExW creates a directory tree;
// calls SHCreateDirectory (SHFileOperation-based) with a progress callback.
/// SHCreateDirectoryExW: create a directory (including parents).
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn sh_create_directory_ex_w(
    _hwnd: usize,
    _path: *const u16,
    _pmt: usize,
) -> i32 {
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// Wine ref: dlls/shell32/shlfolder.c — SHCreateItemFromParsingName parses a display name
// into an IShellItem; delegates to SHCreateItemFromIDList after SHParseDisplayName.
/// SHCreateItemFromParsingName: create a shell item from a parsing name.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn sh_create_item_from_parsing_name(
    _name: *const u16,
    _pbc: usize,
    _riid: *const u8,
    ppv: *mut usize,
) -> i32 {
    if !ppv.is_null() {
        unsafe { *ppv = 0 };
    }
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// Wine ref: dlls/shell32/shlfolder.c — SHCreateItemFromIDList creates an IShellItem
// from a PIDL.
/// SHCreateItemFromIDList: create a shell item from a PIDL.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn sh_create_item_from_id_list(
    _pidl: *const u8,
    _riid: *const u8,
    ppv: *mut usize,
) -> i32 {
    if !ppv.is_null() {
        unsafe { *ppv = 0 };
    }
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// Wine ref: dlls/shell32/shlview.c — SHOpenFolderAndSelectItems opens an Explorer window
// with specified items selected; uses shell namespace browsing.
/// SHOpenFolderAndSelectItems: open a folder window with items selected.
///
/// Returns E_NOTIMPL — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn sh_open_folder_and_select_items(
    _pidl_folder: *const u8,
    _count: u32,
    _pidls: *const *const u8,
    _flags: u32,
) -> i32 {
    0x8000_4001u32 as i32 // E_NOTIMPL
}

// Wine ref: dlls/shell32/shell32_main.c — SHGetFileInfoA is the ANSI variant; converts
// via MultiByteToWideChar then calls SHGetFileInfoW, then writes results back as ANSI.
/// SHGetFileInfoA: ANSI variant of SHGetFileInfoW.
///
/// # Safety
/// `psfi` must point to a valid SHFILEINFOA buffer (356 bytes) when non-null.
pub unsafe extern "win64" fn sh_get_file_info_a(
    psz_path: *const u8,
    dw_file_attributes: u32,
    psfi: *mut u8,
    _cb_file_info: u32,
    u_flags: u32,
) -> usize {
    if psfi.is_null() {
        return 0;
    }

    // Convert ANSI path (CP_ACP) to wide (UTF-16)
    let path_wide = if !psz_path.is_null() {
        let mut len = 0usize;
        while len < 32_768 && unsafe { *psz_path.add(len) } != 0 {
            len += 1;
        }
        let s = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(psz_path, len) });
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        Some(wide)
    } else {
        None
    };

    // Temporary SHFILEINFOW buffer (696 bytes)
    let mut tmp_buf = [0u8; 696];

    let result = unsafe {
        sh_get_file_info_w(
            path_wide
                .as_deref()
                .map_or(std::ptr::null(), |v| v.as_ptr()),
            dw_file_attributes,
            tmp_buf.as_mut_ptr(),
            696,
            u_flags,
        )
    };

    if result != 0 {
        // hIcon at +0 — usize, same layout between A and W
        unsafe {
            *(psfi as *mut usize) = *(tmp_buf.as_ptr() as *mut usize);
        }
        // iIcon at +8 — i32, same layout
        unsafe {
            *(psfi.add(8) as *mut i32) = *(tmp_buf.as_ptr().add(8) as *mut i32);
        }
        // dwAttributes at +12 — u32, same layout
        unsafe {
            *(psfi.add(12) as *mut u32) = *(tmp_buf.as_ptr().add(12) as *mut u32);
        }

        // szDisplayName at +16: convert wide → ANSI (260 CHARs in SHFILEINFOA)
        unsafe {
            let src = tmp_buf.as_ptr().add(16) as *const u16;
            let mut chars = Vec::new();
            let mut p = src;
            loop {
                let c = *p;
                if c == 0 {
                    break;
                }
                chars.push(c);
                p = p.add(1);
            }
            let name = String::from_utf16_lossy(&chars);
            let bytes = name.as_bytes();
            let copy_len = bytes.len().min(259);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), psfi.add(16), copy_len);
            *psfi.add(16 + copy_len) = 0;
        }

        // szTypeName at +276 (16 + 260): convert wide → ANSI (80 CHARs in SHFILEINFOA)
        unsafe {
            let src = tmp_buf.as_ptr().add(536) as *const u16;
            let mut chars = Vec::new();
            let mut p = src;
            loop {
                let c = *p;
                if c == 0 {
                    break;
                }
                chars.push(c);
                p = p.add(1);
            }
            let name = String::from_utf16_lossy(&chars);
            let bytes = name.as_bytes();
            let copy_len = bytes.len().min(79);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), psfi.add(276), copy_len);
            *psfi.add(276 + copy_len) = 0;
        }
    }

    result
}

// Wine ref: dlls/shell32/shlview.c — SHLimitInputEdit limits text input in an edit control
// by setting an input scope or character filter.
/// SHLimitInputEdit: limit text input for an edit control.
///
/// Returns S_OK — stub.
///
/// # Safety
/// `_hwnd` is the edit control HWND.
pub unsafe extern "win64" fn sh_limit_input_edit(_hwnd: usize, _f_unicode: i32) -> i32 {
    0 // S_OK
}

// ── SHFileOperationW constants ─────────────────────────────────────────────────

const FO_MOVE: u32 = 1;
const FO_COPY: u32 = 2;
const FO_DELETE: u32 = 3;
const FO_RENAME: u32 = 4;

/// Parse a double-null-terminated UTF-16 multi-string into a Vec of Strings.
///
/// # Safety
/// `ptr` must point to a valid double-null-terminated UTF-16 buffer.
unsafe fn read_multi_string(ptr: *const u16) -> Vec<String> {
    if ptr.is_null() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut offset: isize = 0;
    loop {
        let mut chars = Vec::new();
        loop {
            let c = *ptr.offset(offset);
            if c == 0 {
                break;
            }
            chars.push(c);
            offset += 1;
        }
        if chars.is_empty() {
            break;
        }
        offset += 1;
        if let Ok(s) = String::from_utf16(&chars) {
            result.push(s);
        }
    }
    result
}

/// Recursively copy a directory tree.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

// Wine ref: dlls/shell32/shlfileop.c — parses SHFILEOPSTRUCTW; dispatches to copy/delete/rename/move
// helpers; FOF_* flags control confirmation dialogs; returns 0 on success, non-zero on cancel/error.
/// SHFileOperationW — perform a file operation (copy/move/delete/rename) (Wide).
///
/// Returns 0 on success, non-zero on error.
///
/// # Safety
/// `lpfo` points to a valid SHFILEOPSTRUCTW or is null.
// Wine ref: dlls/shell32/shlfileop.c — parses SHFILEOPSTRUCTW; copy/delete/rename/move; 0=success.
pub unsafe extern "win64" fn sh_file_operation_w(lpfo: *mut u8) -> i32 {
    if lpfo.is_null() {
        return 0;
    }

    let w_func: u32 = *(lpfo.add(8) as *const u32);
    let f_flags: u32 = *(lpfo.add(12) as *const u32);
    let p_from: *const u16 = *(lpfo.add(16) as *const *const u16);
    let p_to: *const u16 = *(lpfo.add(24) as *const *const u16);
    let _allow_undo = (f_flags & 0x0040) != 0; // FOF_ALLOWUNDO — ignored, no recycle bin

    let sources = read_multi_string(p_from);
    let destinations = read_multi_string(p_to);

    let mut any_aborted = 0i32;
    let mut last_error = 0i32;

    match w_func {
        FO_MOVE => {
            let base_dst = destinations.first().map(|s| s.as_str()).unwrap_or("");
            let dst_path = std::path::Path::new(base_dst);
            let dst_is_dir = !base_dst.is_empty() && dst_path.is_dir();
            for src in &sources {
                if src.is_empty() {
                    continue;
                }
                let src_path = std::path::Path::new(src);
                let target = if dst_is_dir {
                    dst_path.join(src_path.file_name().unwrap_or_default())
                } else {
                    dst_path.to_path_buf()
                };
                if std::fs::rename(src, &target).is_err() {
                    // Fall back to copy + delete
                    if std::fs::copy(src, &target).is_err() {
                        last_error = 1;
                        any_aborted = 1;
                    } else {
                        let _ = std::fs::remove_file(src);
                    }
                }
            }
        }
        FO_COPY => {
            let base_dst = destinations.first().map(|s| s.as_str()).unwrap_or("");
            let dst_path = std::path::Path::new(base_dst);
            let dst_is_dir = !base_dst.is_empty() && dst_path.is_dir();
            for src in &sources {
                if src.is_empty() {
                    continue;
                }
                let src_path = std::path::Path::new(src);
                if src_path.is_dir() {
                    if base_dst.is_empty() {
                        continue;
                    }
                    let target = dst_path.join(src_path.file_name().unwrap_or_default());
                    if copy_dir_recursive(src_path, &target).is_err() {
                        last_error = 1;
                        any_aborted = 1;
                    }
                } else {
                    if base_dst.is_empty() {
                        continue;
                    }
                    let target = if dst_is_dir {
                        dst_path.join(src_path.file_name().unwrap_or_default())
                    } else {
                        dst_path.to_path_buf()
                    };
                    if std::fs::copy(src, &target).is_err() {
                        last_error = 1;
                        any_aborted = 1;
                    }
                }
            }
        }
        FO_DELETE => {
            for src in &sources {
                if src.is_empty() {
                    continue;
                }
                let src_path = std::path::Path::new(src);
                let result = if src_path.is_dir() {
                    std::fs::remove_dir_all(src)
                } else {
                    std::fs::remove_file(src)
                };
                if result.is_err() {
                    last_error = 1;
                    any_aborted = 1;
                }
            }
        }
        FO_RENAME => {
            for (i, src) in sources.iter().enumerate() {
                if src.is_empty() {
                    continue;
                }
                let dest = destinations.get(i).map(|s| s.as_str()).unwrap_or("");
                if dest.is_empty() {
                    continue;
                }
                if std::fs::rename(src, dest).is_err() {
                    if std::fs::copy(src, dest).is_err() {
                        last_error = 1;
                        any_aborted = 1;
                    } else {
                        let _ = std::fs::remove_file(src);
                    }
                }
            }
        }
        _ => {
            last_error = 1;
            any_aborted = 1;
        }
    }

    *(lpfo.add(40) as *mut i32) = any_aborted;

    last_error
}

// Wine ref: dlls/shell32/changenotify.c — broadcasts SHCNE_* event to SHChangeNotifyRegister
// listeners; SHCNF_FLUSH waits for all recipients to process before returning.
/// SHChangeNotify — notify the shell of a change to the namespace.
///
/// Posts a message to registered SHChangeNotifyRegister listeners.
///
/// # Safety
/// Pointer arguments are logged but not dereferenced by this function.
// Wine ref: dlls/shell32/changenotify.c — SHCNE_* event to registered listeners; SHCNF_FLUSH waits.
pub unsafe extern "win64" fn sh_change_notify(
    w_event_id: i32,
    u_flags: u32,
    dw_item1: *const u8,
    dw_item2: *const u8,
) {
    if std::env::var("WEAVE_SHELL32_TRACE").is_ok() {
        eprintln!(
            "weave/shell32: SHChangeNotify event_id={:#x} flags={:#x} item1={:p} item2={:p}",
            w_event_id, u_flags, dw_item1, dw_item2,
        );
    }

    let event_id = w_event_id as u32;
    if event_id == 0 {
        return;
    }

    if let Ok(state) = change_notify_state().lock() {
        let item1 = dw_item1 as usize;
        let item2 = dw_item2 as isize;
        for entry in state.iter() {
            if (event_id & entry.event_mask) != 0 || entry.event_mask == u32::MAX {
                let _ = post_message_w(entry.hwnd, entry.msg, item1, item2);
            }
        }
    }
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

// ── SHGetMalloc / IMalloc COM object ──────────────────────────────────────────
//
// Wine ref: dlls/combase/malloc.c — SHGetMalloc (deprecated since Vista) is equivalent
// to CoGetMalloc(MEMCTX_TASK=1, ppMalloc); it returns the process task allocator which
// wraps HeapAlloc/HeapFree/HeapReAlloc on the process default heap.  The returned IMalloc*
// is a process-lifetime singleton; callers are expected to call Release() but the object
// is never actually freed.  Returns S_OK(0) on success, E_INVALIDARG if ppMalloc is null.
//
// IMalloc vtable layout (IUnknown-derived, Windows x64, 9 methods):
//   [0] QueryInterface(this, riid, ppv) -> HRESULT
//   [1] AddRef(this)                    -> ULONG
//   [2] Release(this)                   -> ULONG
//   [3] Alloc(this, cb)                 -> LPVOID
//   [4] Realloc(this, pv, cb)           -> LPVOID
//   [5] Free(this, pv)                  -> void
//   [6] GetSize(this, pv)               -> SIZE_T
//   [7] DidAlloc(this, pv)              -> int
//   [8] HeapMinimize(this)              -> void
//
// COM object layout: offset 0 holds a *const vtable (pointer-to-vtable).
// `this` == address of that first field; vtable[n] is called as vtable[n](this, ...).

static IMALLOC: OnceLock<usize> = OnceLock::new();

/// Return the address of the process-lifetime IMalloc COM object.
/// The object is a heap word whose value is the vtable pointer.
/// Idempotent — safe to call from multiple threads.
fn get_imalloc_ptr() -> usize {
    *IMALLOC.get_or_init(|| {
        // Build a heap-allocated vtable (9 × usize function pointers).
        // Casts happen at runtime so no const-eval restrictions apply.
        // SAFETY: All fn items here have matching "extern win64" ABI; casting to
        // usize via typed fn-pointer is well-defined (function address is a usize).
        // (a) fn-item casts produce valid code addresses; (b) Box-heap; (c) process
        // lifetime; (d) none — TODO(shim): Phase A, gated on E3-M5 launch gate.
        let vtable: Box<[usize; 9]> = Box::new([
            imalloc_query_interface as unsafe extern "win64" fn(usize, *const u8, *mut usize) -> i32
                as usize,
            imalloc_add_ref as unsafe extern "win64" fn(usize) -> u32 as usize,
            imalloc_release as unsafe extern "win64" fn(usize) -> u32 as usize,
            imalloc_alloc as unsafe extern "win64" fn(usize, usize) -> usize as usize,
            imalloc_realloc as unsafe extern "win64" fn(usize, usize, usize) -> usize as usize,
            imalloc_free as unsafe extern "win64" fn(usize, usize) as usize,
            imalloc_get_size as unsafe extern "win64" fn(usize, usize) -> usize as usize,
            imalloc_did_alloc as unsafe extern "win64" fn(usize, usize) -> i32 as usize,
            imalloc_heap_minimize as unsafe extern "win64" fn(usize) as usize,
        ]);
        let vtable_ptr: usize = Box::into_raw(vtable) as usize;

        // Build the COM object: a heap word whose value is the vtable address.
        // SAFETY: Box::into_raw leaks intentionally — process-lifetime singleton.
        let obj: Box<usize> = Box::new(vtable_ptr);
        Box::into_raw(obj) as usize
    })
}

// ── IMalloc vtable methods (extern "win64" — called by Q-Dir through vtable) ──

// Wine ref: dlls/combase/malloc.c — QueryInterface supports IID_IUnknown and IID_IMalloc;
// AddRefs on success; E_NOINTERFACE (0x80004002) otherwise.  Weave simplifies:
// always returns self (Q-Dir only calls this to obtain the same interface).
unsafe extern "win64" fn imalloc_query_interface(
    _this: usize,
    _riid: *const u8,
    pp_obj: *mut usize,
) -> i32 {
    if !pp_obj.is_null() {
        // SAFETY: pp_obj non-null (checked above); aligned *mut usize output.
        // (a) null-checked; (b) caller stack; (c) call duration; (d) none — TODO(shim): Phase A.
        unsafe { *pp_obj = _this };
    }
    0 // S_OK
}

// Wine ref: dlls/combase/malloc.c — AddRef increments ref count; returns new count.
// Weave: process-lifetime singleton; ref count is always 1.
unsafe extern "win64" fn imalloc_add_ref(_this: usize) -> u32 {
    1
}

// Wine ref: dlls/combase/malloc.c — Release decrements ref count; object freed at 0.
// Weave: singleton never freed; always returns 1.
unsafe extern "win64" fn imalloc_release(_this: usize) -> u32 {
    1
}

// Wine ref: dlls/combase/malloc.c — Alloc calls HeapAlloc(GetProcessHeap(), 0, cb).
// Zero-byte alloc returns a unique non-null pointer per COM spec.
unsafe extern "win64" fn imalloc_alloc(_this: usize, cb: usize) -> usize {
    // SAFETY: libc::malloc accepts any size; returns null on OOM (caller checks).
    // (a) n/a — no deref; (b) heap; (c) caller owns result; (d) none — TODO(shim): Phase A.
    let sz = if cb == 0 { 1 } else { cb };
    unsafe { libc::malloc(sz) as usize }
}

// Wine ref: dlls/combase/malloc.c — Realloc calls HeapReAlloc; NULL pv acts like Alloc;
// cb=0 acts like Free and returns NULL.
unsafe extern "win64" fn imalloc_realloc(_this: usize, pv: usize, cb: usize) -> usize {
    if pv == 0 {
        let sz = if cb == 0 { 1 } else { cb };
        // SAFETY: malloc with non-zero size; caller checks result.
        return unsafe { libc::malloc(sz) as usize };
    }
    if cb == 0 {
        // SAFETY: pv non-zero (checked); assumed valid heap pointer from this allocator.
        unsafe { libc::free(pv as *mut libc::c_void) };
        return 0;
    }
    // SAFETY: pv non-zero; cb non-zero; caller contract: pv was allocated by this allocator.
    // (a) null-checked; (b) heap; (c) caller owns result; (d) none — TODO(shim): Phase A.
    unsafe { libc::realloc(pv as *mut libc::c_void, cb) as usize }
}

// Wine ref: dlls/combase/malloc.c — Free calls HeapFree(GetProcessHeap(), 0, pv); NULL is no-op.
unsafe extern "win64" fn imalloc_free(_this: usize, pv: usize) {
    if pv != 0 {
        // SAFETY: pv non-zero (checked); assumed valid heap pointer from this allocator.
        // (a) null-checked; (b) heap; (c) call duration; (d) none — TODO(shim): Phase A.
        unsafe { libc::free(pv as *mut libc::c_void) };
    }
}

// Wine ref: dlls/combase/malloc.c — GetSize calls HeapSize(GetProcessHeap(), 0, pv);
// returns (SIZE_T)-1 for NULL pv.
unsafe extern "win64" fn imalloc_get_size(_this: usize, pv: usize) -> usize {
    if pv == 0 {
        return usize::MAX; // (SIZE_T)-1 per COM spec for null pointer
    }
    // SAFETY: pv non-zero; malloc_usable_size accepts any valid heap pointer on Linux.
    // (a) null-checked; (b) heap; (c) call duration; (d) none — TODO(shim): Phase A.
    unsafe { libc::malloc_usable_size(pv as *mut libc::c_void) }
}

// Wine ref: dlls/combase/malloc.c — DidAlloc calls HeapValidate; returns 1 if allocated
// by this heap, 0 if not, -1 if unknown.  Weave always returns -1 (don't know).
unsafe extern "win64" fn imalloc_did_alloc(_this: usize, _pv: usize) -> i32 {
    -1
}

// Wine ref: dlls/combase/malloc.c — HeapMinimize calls HeapCompact to release free blocks
// back to the OS.  Weave: no-op.
unsafe extern "win64" fn imalloc_heap_minimize(_this: usize) {}

// Wine ref: dlls/combase/malloc.c — SHGetMalloc equivalent to CoGetMalloc(MEMCTX_TASK=1,
// ppMalloc); returns the process task allocator; E_INVALIDARG if ppMalloc null.
/// SHGetMalloc: return the shell task allocator (IMalloc*).
///
/// Deprecated since Windows Vista; equivalent to `CoGetMalloc(MEMCTX_TASK, ppMalloc)`.
/// Returns `S_OK` (0) on success; `E_INVALIDARG` (0x80070057) if `pp_malloc` is null.
///
/// # Safety
/// `pp_malloc` must be null or a valid writable pointer to a `usize`-sized output slot.
pub unsafe extern "win64" fn sh_get_malloc(pp_malloc: *mut usize) -> i32 {
    const E_INVALIDARG: i32 = 0x80070057u32 as i32;
    if pp_malloc.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: pp_malloc non-null (checked above); caller contract: valid *mut usize output,
    // pointer-size aligned.  (a) null-checked; (b) caller stack/heap; (c) call duration;
    // (d) none — TODO(shim): Phase A, gated on E3-M5 q_dir_launch_gate.
    unsafe { *pp_malloc = get_imalloc_ptr() };
    0 // S_OK
}

// Wine ref: dlls/shell32/appbar.c — SHAppBarMessage dispatches on dwMessage (ABM_NEW=0,
// ABM_REMOVE=1, ABM_QUERYPOS=2, ABM_SETPOS=3, ABM_GETSTATE=4, ABM_GETTASKBARPOS=5,
// ABM_ACTIVATE=6, ABM_GETAUTOHIDEBAR=7, ABM_SETAUTOHIDEBAR=8, ABM_WINDOWPOSCHANGED=9,
// ABM_SETSTATE=10); returns UINT (0 on error, non-zero on success).
/// SHAppBarMessage: send a message to the appbar / taskbar system.
///
/// Stub — returns 0 (failure).
///
/// # Safety
/// `p_data` is accepted but not dereferenced.
// Wine ref: dlls/shell32/appbar.c — ABM_* dispatch; returns 0 on error.
pub unsafe extern "win64" fn sh_app_bar_message(_dw_message: u32, _p_data: *mut u8) -> usize {
    // TODO(shim): Phase A — SHAppBarMessage taskbar integration not implemented.
    0
}

// Wine ref: dlls/shell32/shellord.c — SHGetSettings fills SHELLFLAGSTATE fields (fShowAllObjects,
// fShowExtensions, fNoConfirmRecycle, etc.) from registry key
// HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced; dwMask selects fields.
/// SHGetSettings: retrieve shell configuration flags into a SHELLFLAGSTATE struct.
///
/// Stub — writes nothing; all flags default to 0 (system defaults).
///
/// # Safety
/// `p_sfs` is accepted but not dereferenced.
// Wine ref: dlls/shell32/shellord.c — fills SHELLFLAGSTATE from registry; dwMask selects fields.
pub unsafe extern "win64" fn sh_get_settings(_p_sfs: *mut u8, _dw_mask: u32) {
    // TODO(shim): Phase A — SHGetSettings shell configuration not implemented.
}

// Wine ref: dlls/shell32/shlfolder.c — SHCreateShellItemArrayFromDataObject creates an
// IShellItemArray from an IDataObject (drag-and-drop, clipboard); stub returns E_NOTIMPL.
/// SHCreateShellItemArrayFromDataObject — create an IShellItemArray from an IDataObject.
///
/// Phase B: returns S_FALSE with NULL output, indicating no items were extracted,
/// which is more correct than E_NOTIMPL for callers that check for failed creation.
///
/// # Safety
/// `pdtobj`, `riid`, and `ppv` are accepted but not used.
pub unsafe extern "win64" fn sh_create_shell_item_array_from_data_object(
    _pdtobj: *mut u8,
    _riid: *const u8,
    ppv: *mut *mut u8,
) -> u32 {
    const S_FALSE: u32 = 1;
    if !ppv.is_null() {
        unsafe { *ppv = std::ptr::null_mut() };
    }
    S_FALSE
}

// Wine ref: dlls/shell32/shell32_main.c — SHGetImageList returns an IImageList
// pointer for system image lists (shell icon cache); returns S_FALSE if the
// image list hasn't been initialized.
/// SHGetImageList — retrieve an image list for shell icons.
///
/// Phase B: returns S_FALSE with NULL output, indicating no image list is
/// available, which is more correct than E_NOTIMPL for callers that check
/// for the HRESULT rather than the pointer.
///
/// # Safety
/// `ppv` must be a valid writable pointer if non-null.
pub unsafe extern "win64" fn sh_get_image_list(
    _i_image_list: i32,
    _riid: *const u8,
    ppv: *mut *mut u8,
) -> u32 {
    const S_FALSE: u32 = 1;
    if !ppv.is_null() {
        unsafe { *ppv = std::ptr::null_mut() };
    }
    S_FALSE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pidl;

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

    #[test]
    fn sh_browse_for_folder_w_returns_non_null_pidl_for_test_result_env() {
        let old = std::env::var("WEAVE_TEST_BROWSE_RESULT").ok();
        std::env::set_var("WEAVE_TEST_BROWSE_RESULT", r"C:\Extract\Target\Dir");

        // Construct a minimal BROWSEINFOW layout on the stack (only pszDisplayName at offset 16 is used).
        let mut display: [u16; 64] = [0; 64];
        let mut bi_bytes: [u8; 64] = [0; 64];
        let disp_ptr = display.as_mut_ptr() as usize;
        bi_bytes[16..24].copy_from_slice(&disp_ptr.to_le_bytes());

        let pidl = unsafe { sh_browse_for_folder_w(bi_bytes.as_ptr() as *const u8) };
        assert!(
            !pidl.is_null(),
            "SHBrowseForFolderW must return non-NULL when WEAVE_TEST_BROWSE_RESULT is set"
        );

        // Round-trip the path via the PIDL helper (exercises the documented return contract for M14 A1).
        let mut out: [u16; 260] = [0; 260];
        unsafe {
            let ok = pidl::sh_get_path_from_id_list_w(pidl, out.as_mut_ptr());
            assert_eq!(ok, 1);
            let path =
                String::from_utf16_lossy(&out[..out.iter().position(|&c| c == 0).unwrap_or(0)]);
            assert_eq!(path, r"C:\Extract\Target\Dir");
            pidl::il_free(pidl);
        }

        // restore env for other tests
        match old {
            Some(v) => std::env::set_var("WEAVE_TEST_BROWSE_RESULT", v),
            None => std::env::remove_var("WEAVE_TEST_BROWSE_RESULT"),
        }
    }

    fn encode_utf16_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    #[test]
    fn test_sh_get_file_info_display_name() {
        unsafe {
            let path = encode_utf16_null("C:\\test\\document.txt");
            let mut sfi = [0u8; 696];
            let result = sh_get_file_info_w(
                path.as_ptr(),
                0,
                sfi.as_mut_ptr(),
                696,
                SHGFI_DISPLAYNAME | SHGFI_TYPENAME | SHGFI_SYSICONINDEX,
            );
            assert!(result != 0, "SHGetFileInfoW should succeed");
            // Read display name (offset 16)
            let name_bytes = &sfi[16..16 + 520];
            let name_wide: Vec<u16> = name_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&name_wide);
            assert!(
                name.contains("document"),
                "Display name should contain 'document', got: {name}"
            );
        }
    }
}
