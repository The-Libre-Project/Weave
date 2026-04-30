//! Shared file I/O engine for Weave stubs.
//!
//! Both `weave-ntdll` and `weave-kernel32` translate Windows file operations
//! into Linux equivalents. The shared logic lives here so neither crate
//! duplicates it.
//!
//! # Design
//!
//! All functions operate on Windows path strings (already decoded from UTF-16
//! by the caller). They use the global `prefix::translator()` to convert to a
//! Linux path, then call `libc` directly.
//!
//! The NT `create_disposition` vocabulary is used as the canonical internal
//! interface. Callers using the Win32 vocabulary (`dwCreationDisposition`) must
//! convert first via `win32_disposition_to_nt()`.

use crate::{handles, prefix};
use weave_common::path::identify_device;

// ── NT create-disposition constants ──────────────────────────────────────────

pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;

// ── Win32 create-disposition constants ───────────────────────────────────────

pub const CREATE_NEW: u32 = 1;
pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;
pub const TRUNCATE_EXISTING: u32 = 5;

// ── Win32 desired-access flags ────────────────────────────────────────────────

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;

// ── Win32 error codes (returned by CreateFileW etc.) ─────────────────────────

pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_ACCESS_DENIED: u32 = 5;

// ── NT status codes (returned by NtCreateFile etc.) ──────────────────────────

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC0000034_u32 as i32;
pub const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC0000035_u32 as i32;
pub const STATUS_ACCESS_DENIED: i32 = 0xC0000022_u32 as i32;
pub const STATUS_UNSUCCESSFUL: i32 = 0xC0000001_u32 as i32;

/// Convert a Win32 `dwCreationDisposition` value to its NT equivalent.
///
/// Wine ref: dlls/kernelbase/file.c:795 — CreateFileW uses the table
/// { CREATE_NEW→FILE_CREATE, CREATE_ALWAYS→FILE_OVERWRITE_IF,
///   OPEN_EXISTING→FILE_OPEN, OPEN_ALWAYS→FILE_OPEN_IF,
///   TRUNCATE_EXISTING→FILE_OVERWRITE }. CREATE_ALWAYS is FILE_OVERWRITE_IF
/// (not FILE_SUPERSEDE) — the practical oflag mapping is identical
/// (O_CREAT|O_TRUNC) but the NT disposition must match for io.Information
/// to return FILE_OVERWRITTEN, which is what Wine uses to set
/// ERROR_ALREADY_EXISTS on CREATE_ALWAYS success.
pub fn win32_disposition_to_nt(win32: u32) -> u32 {
    match win32 {
        CREATE_NEW => FILE_CREATE,
        CREATE_ALWAYS => FILE_OVERWRITE_IF,
        OPEN_EXISTING => FILE_OPEN,
        OPEN_ALWAYS => FILE_OPEN_IF,
        TRUNCATE_EXISTING => FILE_OVERWRITE,
        _ => FILE_OPEN, // safe default
    }
}

/// Translate a Windows path to a Linux path, with a fallback for native Linux
/// absolute paths that have been passed through a Windows application.
///
/// When a Linux host passes an absolute path (e.g. `/abs/path/test.7z`) as a
/// CLI argument to a Windows PE, the app typically converts forward slashes to
/// backslashes internally (`\abs\path\test.7z`).  Our Windows path translator
/// then maps this to `{prefix}/drive_c/abs/path/test.7z`, which doesn't exist.
///
/// This function first tries the standard Windows path translation.  If the
/// result doesn't exist on disk, it checks whether the path — with all
/// backslashes replaced by forward slashes — is a valid Linux absolute path
/// that does exist, and returns that instead.
pub fn translate_win_path(win_path: &str) -> Result<std::path::PathBuf, i32> {
    let translated = prefix::translator()
        .to_linux_str(win_path)
        .map_err(|_| STATUS_UNSUCCESSFUL)?;

    // Fast path: the translated path exists — use it directly.
    if translated.exists() {
        return Ok(translated);
    }

    // Fallback 1: try the path as a native Linux absolute path.
    let candidate = win_path.replace('\\', "/");
    if candidate.starts_with('/') {
        let p = std::path::PathBuf::from(&candidate);
        if p.exists() {
            return Ok(p);
        }
    }

    // Fallback 2: relative path (no drive letter, no leading backslash) →
    // try resolving against the real Linux CWD.  This lets apps like testsprite2
    // open "moose.bmp" / "icon.bmp" from the directory they were launched from
    // without needing a full Windows path.
    if !win_path.contains(':') && !win_path.starts_with('\\') && !win_path.starts_with('/') {
        let rel = win_path.replace('\\', "/");
        if let Ok(cwd) = std::env::current_dir() {
            let cwd_candidate = cwd.join(&rel);
            if cwd_candidate.exists() {
                return Ok(cwd_candidate);
            }
        }
    }

    // Return the (non-existent) translated path so callers get the right error.
    Ok(translated)
}

/// Open or create a file and return a Windows HANDLE.
///
/// `win_path`    — Windows path (already decoded from UTF-16 if needed)
/// `desired_access` — Windows `ACCESS_MASK` (GENERIC_READ / GENERIC_WRITE / …)
/// `nt_disposition` — NT create-disposition (FILE_OPEN, FILE_CREATE, …)
///
/// Returns `Ok(handle)` on success, `Err(nt_status)` on failure.
pub fn open_file(win_path: &str, desired_access: u32, nt_disposition: u32) -> Result<usize, i32> {
    // ── 1. Device paths (NUL, CON, …) ─────────────────────────────────────
    if let Some(device) = identify_device(win_path) {
        return open_device(device);
    }

    // ── 2. Translate Windows path → Linux path ────────────────────────────
    let linux_path = translate_win_path(win_path)?;

    let path_cstr = match path_to_cstring(&linux_path) {
        Some(s) => s,
        None => return Err(STATUS_UNSUCCESSFUL),
    };

    // ── 3. Build libc open flags ──────────────────────────────────────────
    let oflags = build_oflags(desired_access, nt_disposition);

    // ── 4. Open the file ──────────────────────────────────────────────────
    let mut fd = unsafe { libc::open(path_cstr.as_ptr(), oflags, 0o666_i32) };
    if fd < 0 {
        // Windows is case-insensitive; try a case-folded filename lookup on ENOENT.
        let errno = std::io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::ENOENT) {
            if let Some(folded) = case_fold_lookup(std::path::Path::new(&linux_path)) {
                fd = unsafe { libc::open(folded.as_ptr(), oflags, 0o666_i32) };
            }
        }
        if fd < 0 {
            return Err(errno_to_ntstatus());
        }
    }

    // ── 5. Register in the HANDLE table ──────────────────────────────────
    Ok(handles::alloc(handles::HandleKind::File(fd)))
}

/// Close a handle. Returns `Ok(())` on success, `Err(STATUS_INVALID_HANDLE)`
/// if the handle is unknown or one of the protected standard handles.
pub fn close_handle(handle: usize) -> Result<(), i32> {
    // Retrieve the fd before freeing the slot.
    let fd = handles::get_fd(handle).ok_or(STATUS_UNSUCCESSFUL)?;

    // Try to free the slot — fails for stdin/stdout/stderr.
    if !handles::free(handle) {
        return Err(STATUS_UNSUCCESSFUL);
    }

    // Close the underlying fd.
    let ret = unsafe { libc::close(fd) };
    if ret != 0 {
        Err(STATUS_UNSUCCESSFUL)
    } else {
        Ok(())
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Map a device name to a Linux fd and allocate a handle for it.
fn open_device(device: &str) -> Result<usize, i32> {
    let linux_path: &std::ffi::CStr = match device {
        "NUL" => c"/dev/null",
        "CON" | "CONOUT$" => c"/dev/tty",
        _ => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
    };
    let fd = unsafe { libc::open(linux_path.as_ptr(), libc::O_RDWR, 0) };
    if fd < 0 {
        Err(errno_to_ntstatus())
    } else {
        Ok(handles::alloc(handles::HandleKind::File(fd)))
    }
}

/// Build libc open flags from a Windows access mask and NT create disposition.
fn build_oflags(desired_access: u32, nt_disposition: u32) -> libc::c_int {
    // Access direction
    let has_read = (desired_access & GENERIC_READ) != 0
        || (desired_access & FILE_READ_DATA) != 0
        || desired_access == 0; // treat no-access as read-only
    let has_write =
        (desired_access & GENERIC_WRITE) != 0 || (desired_access & FILE_WRITE_DATA) != 0;

    let access_flags = match (has_read, has_write) {
        (true, true) => libc::O_RDWR,
        (false, true) => libc::O_WRONLY,
        _ => libc::O_RDONLY,
    };

    // Create/open disposition
    let create_flags = match nt_disposition {
        FILE_SUPERSEDE => libc::O_CREAT | libc::O_TRUNC,
        FILE_OPEN => 0,
        FILE_CREATE => libc::O_CREAT | libc::O_EXCL,
        FILE_OPEN_IF => libc::O_CREAT,
        FILE_OVERWRITE => libc::O_TRUNC,
        FILE_OVERWRITE_IF => libc::O_CREAT | libc::O_TRUNC,
        _ => 0,
    };

    access_flags | create_flags
}

/// Convert the current errno to the closest NT status code.
fn errno_to_ntstatus() -> i32 {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => STATUS_OBJECT_NAME_NOT_FOUND,
        Some(libc::EEXIST) => STATUS_OBJECT_NAME_COLLISION,
        Some(libc::EACCES) | Some(libc::EPERM) => STATUS_ACCESS_DENIED,
        _ => STATUS_UNSUCCESSFUL,
    }
}

/// Convert a `PathBuf` to a null-terminated `Vec<u8>` suitable for libc calls.
/// Returns `None` if the path contains interior null bytes.
fn path_to_cstring(path: &std::path::Path) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).ok()
}

/// Case-insensitive path lookup: scan the parent directory for an entry whose
/// name matches `path`'s filename component case-insensitively.
///
/// Windows is case-insensitive; Linux is not. When a direct `open()` fails with
/// ENOENT, this function lets us recover by finding the actual on-disk name.
/// Only the final component is folded — callers needing full-depth folding must
/// call this recursively on each component (deferred to Phase 3).
fn case_fold_lookup(path: &std::path::Path) -> Option<std::ffi::CString> {
    let parent = path.parent()?;
    let filename = path.file_name()?;
    let filename_lower = filename.to_string_lossy().to_lowercase();

    for entry in std::fs::read_dir(parent).ok()?.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().to_lowercase() == filename_lower {
            return path_to_cstring(&parent.join(name));
        }
    }
    None
}
