//! Registry path resolution and default key population.
//!
//! The Weave registry is a directory tree under `{prefix}/registry/`:
//!
//!   {prefix}/registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/
//!   {prefix}/registry/HKCU/Software/Microsoft/Windows/CurrentVersion/
//!   …
//!
//! Each registry key is a directory. Each value is a file in that directory:
//!   - filename  = value name (empty-string value uses the filename `@`)
//!   - content   = 4-byte little-endian REG_TYPE followed by the raw value data
//!
//! All filenames are stored with their original casing. Lookups normalise to
//! lowercase before searching, so registry access is effectively
//! case-insensitive (matching Windows behaviour for key and value names).
//!
//! # Value types
//!
//! | Constant     | Value | Encoding in file                         |
//! |--------------|-------|------------------------------------------|
//! | REG_SZ       | 1     | UTF-16 LE with null terminator            |
//! | REG_EXPAND_SZ| 2     | UTF-16 LE with null terminator            |
//! | REG_BINARY   | 3     | raw bytes                                 |
//! | REG_DWORD    | 4     | 4 bytes, little-endian                    |
//! | REG_MULTI_SZ | 7     | UTF-16 LE, double-null terminated         |
//! | REG_QWORD    | 11    | 8 bytes, little-endian                    |

use std::path::{Path, PathBuf};

use crate::prefix;

// ── Registry type constants ───────────────────────────────────────────────────

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

// ── Predefined hive handles (Windows constants) ───────────────────────────────

// On 64-bit Windows these are sign-extended from (LONG): 0x8000000x → 0xFFFFFFFF8000000x.
// MinGW-compiled binaries pass the 64-bit sign-extended form.
pub const HKEY_CLASSES_ROOT: usize = 0xFFFFFFFF80000000;
pub const HKEY_CURRENT_USER: usize = 0xFFFFFFFF80000001;
pub const HKEY_LOCAL_MACHINE: usize = 0xFFFFFFFF80000002;
pub const HKEY_USERS: usize = 0xFFFFFFFF80000003;
pub const HKEY_CURRENT_CONFIG: usize = 0xFFFFFFFF80000005;

// ── Special filename for the default (unnamed) value ─────────────────────────

const DEFAULT_VALUE_FILENAME: &str = "@";

// ── Path resolution ───────────────────────────────────────────────────────────

/// Return the on-disk directory path for a predefined hive handle, or `None`
/// if `handle` is not a predefined Windows HKEY constant.
pub fn predefined_hive_path(handle: usize) -> Option<PathBuf> {
    let reg_root = prefix::get().join("registry");
    let hive = match handle {
        HKEY_CLASSES_ROOT => "HKCR",
        HKEY_CURRENT_USER => "HKCU",
        HKEY_LOCAL_MACHINE => "HKLM",
        HKEY_USERS => "HKU",
        HKEY_CURRENT_CONFIG => "HKCC",
        _ => return None,
    };
    Some(reg_root.join(hive))
}

/// Resolve a Windows registry key subpath (backslash-separated) relative to a
/// base directory, returning the resulting filesystem path.
///
/// Rejects components that would escape the registry root (e.g. `..`).
pub fn resolve_subkey(base: &Path, subkey: &str) -> Option<PathBuf> {
    if subkey.is_empty() {
        return Some(base.to_path_buf());
    }
    let mut result = base.to_path_buf();
    for component in subkey.split('\\') {
        match component {
            "" | "." => {}
            ".." => return None, // traversal attempt — reject
            c => result.push(c),
        }
    }
    Some(result)
}

/// Find a value file under `key_dir` whose name matches `value_name`
/// case-insensitively. Returns the full path if found.
///
/// The empty string maps to the special filename `@`.
pub fn find_value_file(key_dir: &Path, value_name: &str) -> Option<PathBuf> {
    let target_filename = if value_name.is_empty() {
        DEFAULT_VALUE_FILENAME.to_string()
    } else {
        value_name.to_string()
    };
    let target_lower = target_filename.to_ascii_lowercase();

    let entries = std::fs::read_dir(key_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.to_ascii_lowercase() == target_lower {
            return Some(entry.path());
        }
    }
    None
}

/// Read a value file and return `(reg_type, data_bytes)`.
/// The file format is: 4-byte little-endian type, then raw data.
pub fn read_value_file(path: &Path) -> Option<(u32, Vec<u8>)> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() < 4 {
        return None;
    }
    let reg_type = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Some((reg_type, bytes[4..].to_vec()))
}

// ── Value encoding helpers ────────────────────────────────────────────────────

/// Encode a REG_SZ (or REG_EXPAND_SZ) value as UTF-16 LE with null terminator.
pub fn encode_sz(s: &str) -> Vec<u8> {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0); // null terminator
    wide.iter().flat_map(|c| c.to_le_bytes()).collect()
}

/// Encode a REG_DWORD value as 4 bytes, little-endian.
pub fn encode_dword(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

// ── Default registry population ───────────────────────────────────────────────

/// Write a value file to disk. Creates parent directories as needed.
/// The file format: 4-byte LE type header, then `data`.
fn write_value(key_dir: &Path, name: &str, reg_type: u32, data: &[u8]) {
    let filename = if name.is_empty() {
        DEFAULT_VALUE_FILENAME
    } else {
        name
    };
    // Create the directory (and all parents) if it doesn't exist.
    let _ = std::fs::create_dir_all(key_dir);
    let path = key_dir.join(filename);
    let mut content = reg_type.to_le_bytes().to_vec();
    content.extend_from_slice(data);
    let _ = std::fs::write(path, content);
}

/// Helper: write a REG_SZ value.
fn sz(key_dir: &Path, name: &str, value: &str) {
    write_value(key_dir, name, REG_SZ, &encode_sz(value));
}

/// Helper: write a REG_EXPAND_SZ value.
fn expand_sz(key_dir: &Path, name: &str, value: &str) {
    write_value(key_dir, name, REG_EXPAND_SZ, &encode_sz(value));
}

/// Helper: write a REG_DWORD value.
fn dword(key_dir: &Path, name: &str, value: u32) {
    write_value(key_dir, name, REG_DWORD, &encode_dword(value));
}

/// Populate the registry with the default keys and values that Windows
/// applications commonly read at startup.
///
/// Called once by `weave-cli` before jumping to the PE entry point.
/// Safe to call multiple times — existing files are overwritten with the
/// same values, which is harmless.
pub fn populate() {
    let reg = prefix::get().join("registry");

    // ── HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion ─────────────────
    let cur_ver = reg.join("HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion");
    sz(&cur_ver, "ProductName", "Windows 10 Enterprise");
    sz(&cur_ver, "CurrentVersion", "6.3");
    sz(&cur_ver, "CurrentBuild", "19041");
    sz(&cur_ver, "CurrentBuildNumber", "19041");
    sz(&cur_ver, "ReleaseId", "2009");
    sz(&cur_ver, "UBR", "1415"); // Update Build Revision
    sz(&cur_ver, "EditionID", "Enterprise");
    sz(&cur_ver, "InstallationType", "Client");
    sz(&cur_ver, "RegisteredOwner", "Weave User");
    sz(&cur_ver, "RegisteredOrganization", "");
    sz(&cur_ver, "PathName", r"C:\Windows");
    sz(&cur_ver, "SystemRoot", r"C:\Windows");
    // CSDVersion: blank on Win10 (was "Service Pack N" on XP/7)
    sz(&cur_ver, "CSDVersion", "");

    // ── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion ────────────────────
    let win_cur = reg.join("HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion");
    sz(&win_cur, "ProgramFilesDir", r"C:\Program Files");
    sz(&win_cur, "ProgramFilesDir (x86)", r"C:\Program Files (x86)");
    sz(&win_cur, "CommonFilesDir", r"C:\Program Files\Common Files");
    sz(&win_cur, "ProgramW6432Dir", r"C:\Program Files");
    sz(&win_cur, "SystemRoot", r"C:\Windows");
    sz(&win_cur, "SM_GamesName", "Games");

    // ── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall ─────────
    // Applications look here to check if something is already installed.
    // Leave empty for now — apps that enumerate this key should handle it.
    let _ = std::fs::create_dir_all(
        reg.join("HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall"),
    );

    // ── HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language ────────────────
    let nls_lang = reg.join("HKLM/SYSTEM/CurrentControlSet/Control/Nls/Language");
    sz(&nls_lang, "Default", "0409"); // en-US
    sz(&nls_lang, "InstallLanguage", "0409");

    // ── HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment ─
    let sys_env = reg.join("HKLM/SYSTEM/CurrentControlSet/Control/Session Manager/Environment");
    expand_sz(&sys_env, "TEMP", r"%USERPROFILE%\AppData\Local\Temp");
    expand_sz(&sys_env, "TMP", r"%USERPROFILE%\AppData\Local\Temp");
    expand_sz(&sys_env, "SystemRoot", r"C:\Windows");
    expand_sz(&sys_env, "windir", r"C:\Windows");
    expand_sz(&sys_env, "ComSpec", r"C:\Windows\system32\cmd.exe");
    sz(&sys_env, "NUMBER_OF_PROCESSORS", "4");
    sz(&sys_env, "PROCESSOR_ARCHITECTURE", "AMD64");
    sz(&sys_env, "OS", "Windows_NT");

    // ── HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName ───
    let computer_name = reg.join("HKLM/SYSTEM/CurrentControlSet/Control/ComputerName/ComputerName");
    sz(&computer_name, "ComputerName", "WEAVE");

    // ── HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters ──────────
    let tcpip = reg.join("HKLM/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters");
    sz(&tcpip, "HostName", "weave");
    sz(&tcpip, "Domain", "");

    // ── HKLM\SOFTWARE\Microsoft\Ole ───────────────────────────────────────
    // COM/OLE checks this for activation policy.
    let _ = std::fs::create_dir_all(reg.join("HKLM/SOFTWARE/Microsoft/Ole"));

    // ── HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer ──────────
    let explorer = reg.join("HKCU/Software/Microsoft/Windows/CurrentVersion/Explorer");
    dword(&explorer, "EnableAutoTray", 1);

    // ── HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    let shell_folders =
        reg.join("HKCU/Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders");
    sz(&shell_folders, "Desktop", r"C:\Users\Weave\Desktop");
    sz(&shell_folders, "Personal", r"C:\Users\Weave\Documents");
    sz(&shell_folders, "My Pictures", r"C:\Users\Weave\Pictures");
    sz(&shell_folders, "My Music", r"C:\Users\Weave\Music");
    sz(&shell_folders, "My Video", r"C:\Users\Weave\Videos");
    sz(&shell_folders, "AppData", r"C:\Users\Weave\AppData\Roaming");
    sz(
        &shell_folders,
        "Local AppData",
        r"C:\Users\Weave\AppData\Local",
    );
    sz(
        &shell_folders,
        "Cache",
        r"C:\Users\Weave\AppData\Local\Microsoft\Windows\INetCache",
    );
    sz(&shell_folders, "Fonts", r"C:\Windows\Fonts");
    sz(&shell_folders, "Temp", r"C:\Users\Weave\AppData\Local\Temp");
    sz(
        &shell_folders,
        "Startup",
        r"C:\Users\Weave\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    );

    // ── HKCU\Control Panel\Desktop ────────────────────────────────────────
    let cp_desktop = reg.join("HKCU/Control Panel/Desktop");
    sz(&cp_desktop, "FontSmoothing", "2"); // ClearType
    sz(&cp_desktop, "FontSmoothingType", "2");
    dword(&cp_desktop, "LogPixels", 96); // DPI: 96 = 100%

    // ── HKCU\Control Panel\International ─────────────────────────────────
    let cp_intl = reg.join("HKCU/Control Panel/International");
    sz(&cp_intl, "Locale", "00000409");
    sz(&cp_intl, "LocaleName", "en-US");
    sz(&cp_intl, "sLanguage", "ENU");
    sz(&cp_intl, "sCountry", "United States");
    sz(&cp_intl, "iCountry", "1");
    sz(&cp_intl, "sDate", "/");
    sz(&cp_intl, "sTime", ":");
    sz(&cp_intl, "iDate", "0");
    sz(&cp_intl, "iTime", "0");
    sz(&cp_intl, "iTLZero", "0");
    sz(&cp_intl, "sShortDate", "M/d/yyyy");
    sz(&cp_intl, "sLongDate", "dddd, MMMM d, yyyy");

    // ── HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows ─────────
    let hkcu_nt_win = reg.join("HKCU/Software/Microsoft/Windows NT/CurrentVersion/Windows");
    sz(&hkcu_nt_win, "NullPort", "None");

    // ── HKCR root (empty but must exist for COM lookups) ─────────────────
    let _ = std::fs::create_dir_all(reg.join("HKCR"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn resolve_subkey_basic() {
        let base = PathBuf::from("/prefix/registry/HKLM");
        let result = resolve_subkey(&base, r"SOFTWARE\Microsoft\Windows");
        assert_eq!(
            result,
            Some(PathBuf::from(
                "/prefix/registry/HKLM/SOFTWARE/Microsoft/Windows"
            ))
        );
    }

    #[test]
    fn resolve_subkey_empty() {
        let base = PathBuf::from("/prefix/registry/HKCU");
        assert_eq!(resolve_subkey(&base, ""), Some(base.clone()));
    }

    #[test]
    fn resolve_subkey_rejects_traversal() {
        let base = PathBuf::from("/prefix/registry/HKLM");
        assert_eq!(resolve_subkey(&base, r"foo\..\..\..\etc"), None);
    }

    #[test]
    fn encode_sz_null_terminated() {
        let data = encode_sz("hello");
        // "hello" = 5 UTF-16 code units + 1 null = 6 × 2 bytes = 12
        assert_eq!(data.len(), 12);
        // Last two bytes must be the null terminator (0x00 0x00)
        assert_eq!(&data[data.len() - 2..], &[0x00, 0x00]);
        // First two bytes = 'h' in UTF-16 LE = 0x68 0x00
        assert_eq!(&data[..2], &[0x68, 0x00]);
    }

    #[test]
    fn encode_dword_little_endian() {
        assert_eq!(encode_dword(0x00_09_04_00), vec![0x00, 0x04, 0x09, 0x00]);
    }

    #[test]
    fn read_value_file_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let val_path = dir.path().join("TestValue");
        let data = encode_sz("hello");
        let mut content = REG_SZ.to_le_bytes().to_vec();
        content.extend_from_slice(&data);
        std::fs::write(&val_path, &content).unwrap();

        let (reg_type, bytes) = read_value_file(&val_path).unwrap();
        assert_eq!(reg_type, REG_SZ);
        assert_eq!(bytes, data);
    }
}
