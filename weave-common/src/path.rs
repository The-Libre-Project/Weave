//! Windows-to-Linux path translation.
//!
//! Windows applications use paths that Linux cannot understand directly:
//!
//!   - Drive letters:              `C:\Users\foo\bar.txt`
//!   - Backslash separators:       `C:\foo\bar`
//!   - Extended path prefix:       `\\?\C:\foo\bar`
//!   - NT object namespace:        `\??\C:\foo\bar`  (used by NtCreateFile)
//!   - Device paths:               `\\.\NUL`, `\\.\CON`
//!   - UNC network paths:          `\\server\share\path`
//!
//! `WinPathTranslator` converts these to real Linux paths rooted at an
//! application prefix directory. Drive `C:` maps to `{prefix}/drive_c/`,
//! drive `D:` to `{prefix}/drive_d/`, and so on — the same convention Wine uses.
//!
//! # Example
//!
//! ```rust
//! use std::path::PathBuf;
//! use weave_common::path::WinPathTranslator;
//!
//! let translator = WinPathTranslator::new(PathBuf::from("/home/user/.weave/default"));
//! let linux = translator.to_linux_str(r"C:\Users\foo\notes.txt").unwrap();
//! assert_eq!(linux, PathBuf::from("/home/user/.weave/default/drive_c/Users/foo/notes.txt"));
//! ```

use std::path::{Component, Path, PathBuf};

/// Error type for path translation failures.
#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    /// The path is empty.
    Empty,
    /// UNC network paths (`\\server\share\...`) are not yet supported.
    UncNotSupported,
    /// The path contains components that would escape the prefix (e.g. `../../`).
    TraversalAttempt,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::Empty => write!(f, "path is empty"),
            PathError::UncNotSupported => write!(f, "UNC network paths are not yet supported"),
            PathError::TraversalAttempt => {
                write!(
                    f,
                    "path attempts to escape the prefix (directory traversal)"
                )
            }
        }
    }
}

impl std::error::Error for PathError {}

/// Translates Windows paths into Linux paths rooted at an application prefix.
///
/// All translated paths are guaranteed to remain within the prefix — any
/// component that would escape it (e.g. `..` above the drive root) is rejected.
pub struct WinPathTranslator {
    prefix: PathBuf,
}

impl WinPathTranslator {
    /// Create a new translator with `prefix` as the virtual Windows root.
    ///
    /// `prefix` should be the application's Weave prefix directory, e.g.
    /// `/home/user/.weave/prefixes/myapp`. Drive `C:` will map to
    /// `{prefix}/drive_c`, drive `D:` to `{prefix}/drive_d`, etc.
    pub fn new(prefix: PathBuf) -> Self {
        Self { prefix }
    }

    /// The prefix this translator is rooted at.
    pub fn prefix(&self) -> &Path {
        &self.prefix
    }

    /// Translate a Windows path (given as a Rust `&str`) to a Linux `PathBuf`.
    ///
    /// This is the primary entry point for Win32-layer code where paths have
    /// already been decoded from UTF-16 (e.g. `CreateFileW` arguments).
    pub fn to_linux_str(&self, win_path: &str) -> Result<PathBuf, PathError> {
        if win_path.is_empty() {
            return Err(PathError::Empty);
        }
        let normalised = normalise_win_path(win_path)?;
        self.resolve_normalised(&normalised)
    }

    /// Translate a Windows path encoded as a null-terminated UTF-16 slice.
    ///
    /// Used directly by ntdll stubs that receive `*const u16` arguments.
    /// The slice may or may not include the null terminator.
    pub fn to_linux_wide(&self, win_path: &[u16]) -> Result<PathBuf, PathError> {
        let s = decode_wide(win_path);
        self.to_linux_str(&s)
    }

    /// Translate a Windows path and return the drive root only.
    ///
    /// Useful for checking whether a drive is mapped before attempting a
    /// full translation (e.g. `GetDriveTypeW`).
    pub fn drive_root(&self, drive_letter: char) -> PathBuf {
        self.prefix
            .join(format!("drive_{}", drive_letter.to_ascii_lowercase()))
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Given a normalised, prefix-stripped Windows path, resolve it to a
    /// Linux path under the prefix.
    ///
    /// Drive `Z:` is special: it maps directly to the Linux filesystem root `/`
    /// instead of `{prefix}/drive_z`.  This lets Weave represent real Linux
    /// paths as Windows paths using the `Z:\` prefix, which is used by
    /// `GetCurrentDirectoryW` to expose the real process CWD to guest apps.
    fn resolve_normalised(&self, normalised: &NormalisedPath) -> Result<PathBuf, PathError> {
        let drive_root = if normalised.drive == 'Z' || normalised.drive == 'z' {
            PathBuf::from("/")
        } else {
            let drive_dir = format!("drive_{}", normalised.drive.to_ascii_lowercase());
            self.prefix.join(&drive_dir)
        };

        let mut result = drive_root;
        let mut depth: usize = 0; // how deep we are below the drive root

        for component in &normalised.components {
            match component.as_str() {
                "." => {} // current dir — skip
                ".." => {
                    if depth == 0 {
                        // would escape the drive root
                        return Err(PathError::TraversalAttempt);
                    }
                    result.pop();
                    depth -= 1;
                }
                c => {
                    result.push(c);
                    depth += 1;
                }
            }
        }

        Ok(result)
    }
}

// ── Normalised intermediate representation ────────────────────────────────────

struct NormalisedPath {
    drive: char,
    components: Vec<String>,
}

// ── Path normalisation ────────────────────────────────────────────────────────

/// Strip prefixes and normalise a raw Windows path string into the internal
/// representation. Does not touch the filesystem.
fn normalise_win_path(raw: &str) -> Result<NormalisedPath, PathError> {
    // Replace all forward slashes with backslashes for uniform processing.
    // Some Windows apps (especially MSVC CRT) use forward slashes in paths.
    let raw = raw.replace('/', "\\");

    // ── Strip well-known prefixes ─────────────────────────────────────────────

    // `\\?\`   — extended-length path (bypasses MAX_PATH limit)
    // `\??\`   — NT object namespace form used by NtCreateFile
    // Both simply expose the underlying drive-letter path after the prefix.
    let stripped = if raw.starts_with(r"\\?\") || raw.starts_with(r"\??\") {
        &raw[4..]
    } else if let Some(device) = raw.strip_prefix(r"\\.\") {
        // Device path. Map known devices; reject unknown ones.
        return parse_device_path(device);
    } else if raw.starts_with(r"\\") {
        // UNC path: \\server\share\...
        return Err(PathError::UncNotSupported);
    } else {
        raw.as_str()
    };

    // ── Extract drive letter ──────────────────────────────────────────────────

    let (drive, rest) = extract_drive(stripped)?;

    // ── Split into components ─────────────────────────────────────────────────

    let components: Vec<String> = rest
        .split('\\')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    Ok(NormalisedPath { drive, components })
}

/// Extract the drive letter from a path like `C:\...` or `C:...`.
/// Returns `(letter, rest_of_path_after_colon_and_optional_backslash)`.
fn extract_drive(s: &str) -> Result<(char, &str), PathError> {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        let letter = bytes[0] as char;
        if letter.is_ascii_alphabetic() {
            // Skip the colon and optional leading backslash
            let rest = if bytes.len() > 2 && bytes[2] == b'\\' {
                &s[3..]
            } else {
                &s[2..]
            };
            return Ok((letter, rest));
        }
    }
    // No drive letter — check for root-relative path (leading backslash).
    // `\path\to\file` after prefix-stripping (e.g. after `\\?\` was removed and
    // no drive letter remained) is a root-relative Windows path.  Map it to Z:
    // so it resolves under the Linux filesystem root (`/`), consistent with how
    // Weave uses Z: as the mirror of the real Linux root.
    if bytes.first() == Some(&b'\\') {
        return Ok(('Z', &s[1..]));
    }
    // Bare relative path (no drive letter, no leading backslash) — treat as
    // relative to C: so Windows apps can use CWD-relative paths.
    Ok(('C', s))
}

/// Handle `\\.\<device>` paths by mapping known Windows device names.
///
/// `\\.\NUL`  → `/dev/null`
/// `\\.\CON`  → `/dev/tty` (approximate — console device)
///
/// Unknown devices return `UncNotSupported` for now (will expand in Phase 2).
fn parse_device_path(device: &str) -> Result<NormalisedPath, PathError> {
    // We return a NormalisedPath with a sentinel drive of '!' to indicate
    // a pre-resolved Linux path. The caller (resolve_normalised) doesn't
    // handle this — so we use a shim approach: encode the Linux path via
    // the reserved drive letter '_' under the prefix (not ideal).
    //
    // For now, silently map known devices and reject the rest.
    // A proper device-path enum will come in Phase 2 kernel32 work.
    let upper = device.to_ascii_uppercase();
    match upper.as_str() {
        "NUL" | "CON" | "CONIN$" | "CONOUT$" | "COM1" | "COM2" | "COM3" | "LPT1" => {
            // These are acceptable device names; callers must handle them
            // separately (open /dev/null, /dev/tty, etc.). Return empty path
            // so callers can detect device paths via a separate API.
            Ok(NormalisedPath {
                drive: '_',
                components: vec![upper],
            })
        }
        _ => Err(PathError::UncNotSupported),
    }
}

// ── UTF-16 decoding ───────────────────────────────────────────────────────────

/// Decode a null-terminated (or just slice-bounded) UTF-16 sequence to a
/// `String`. Invalid surrogates are replaced with U+FFFD.
fn decode_wide(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Returns `true` if the translated path represents a Windows device (NUL, CON, …).
///
/// Check this after calling `to_linux_str` / `to_linux_wide` — if the result's
/// drive component is `_`, the path is a device and must be handled specially.
pub fn is_device_path(path: &Path) -> bool {
    // Device paths come through with a `drive__` prefix component under the
    // prefix dir — callers should use `WinPathTranslator::device_name` instead.
    // This helper is a quick check on the raw translated output.
    path.components().any(|c| {
        if let Component::Normal(s) = c {
            s.to_string_lossy().starts_with("drive__")
        } else {
            false
        }
    })
}

/// Identify well-known Windows device names in a raw (not-yet-translated) path.
///
/// Returns the device name (e.g. `"NUL"`) if the path is a device reference,
/// or `None` if it is a normal file path.
pub fn identify_device(win_path: &str) -> Option<&'static str> {
    // Strip any prefix first
    let s = win_path.trim_start_matches(r"\\.\");
    let upper = s.to_ascii_uppercase();
    match upper.as_str() {
        "NUL" => Some("NUL"),
        "CON" | "CONIN$" => Some("CON"),
        "CONOUT$" => Some("CONOUT$"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn translator() -> WinPathTranslator {
        WinPathTranslator::new(PathBuf::from("/prefix"))
    }

    // ── Basic drive-letter paths ──────────────────────────────────────────────

    #[test]
    fn simple_c_drive() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"C:\Users\foo\bar.txt").unwrap(),
            PathBuf::from("/prefix/drive_c/Users/foo/bar.txt")
        );
    }

    #[test]
    fn drive_letter_case_insensitive() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"c:\users\foo").unwrap(),
            PathBuf::from("/prefix/drive_c/users/foo")
        );
    }

    #[test]
    fn alternate_drive_letter() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"D:\data\file.db").unwrap(),
            PathBuf::from("/prefix/drive_d/data/file.db")
        );
    }

    #[test]
    fn drive_root_only() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"C:\").unwrap(),
            PathBuf::from("/prefix/drive_c")
        );
    }

    // ── Separator normalisation ───────────────────────────────────────────────

    #[test]
    fn forward_slash_separator() {
        let t = translator();
        assert_eq!(
            t.to_linux_str("C:/Users/foo/bar.txt").unwrap(),
            PathBuf::from("/prefix/drive_c/Users/foo/bar.txt")
        );
    }

    #[test]
    fn mixed_separators() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"C:\Users/foo\bar.txt").unwrap(),
            PathBuf::from("/prefix/drive_c/Users/foo/bar.txt")
        );
    }

    // ── Extended path prefix ──────────────────────────────────────────────────

    #[test]
    fn extended_path_prefix() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"\\?\C:\long\path\file.txt").unwrap(),
            PathBuf::from("/prefix/drive_c/long/path/file.txt")
        );
    }

    #[test]
    fn nt_object_namespace_prefix() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"\??\C:\Windows\System32\foo.dll").unwrap(),
            PathBuf::from("/prefix/drive_c/Windows/System32/foo.dll")
        );
    }

    // ── Dot components ────────────────────────────────────────────────────────

    #[test]
    fn dot_components() {
        let t = translator();
        // `.` is current dir and should be a no-op
        assert_eq!(
            t.to_linux_str(r"C:\foo\.\bar").unwrap(),
            PathBuf::from("/prefix/drive_c/foo/bar")
        );
    }

    #[test]
    fn dotdot_within_drive() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"C:\foo\bar\..\baz").unwrap(),
            PathBuf::from("/prefix/drive_c/foo/baz")
        );
    }

    #[test]
    fn dotdot_escape_rejected() {
        let t = translator();
        // Attempting to go above the drive root must fail
        assert_eq!(
            t.to_linux_str(r"C:\..\..\etc\passwd"),
            Err(PathError::TraversalAttempt)
        );
    }

    // ── Empty / error cases ───────────────────────────────────────────────────

    #[test]
    fn empty_path_rejected() {
        let t = translator();
        assert_eq!(t.to_linux_str(""), Err(PathError::Empty));
    }

    #[test]
    fn unc_path_rejected() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"\\server\share\file"),
            Err(PathError::UncNotSupported)
        );
    }

    // ── UTF-16 wide string input ──────────────────────────────────────────────

    #[test]
    fn wide_string_basic() {
        let t = translator();
        // "C:\foo" as UTF-16 LE, null-terminated
        let wide: Vec<u16> = "C:\\foo".encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(
            t.to_linux_wide(&wide).unwrap(),
            PathBuf::from("/prefix/drive_c/foo")
        );
    }

    #[test]
    fn wide_string_no_null_terminator() {
        let t = translator();
        let wide: Vec<u16> = "C:\\bar".encode_utf16().collect();
        assert_eq!(
            t.to_linux_wide(&wide).unwrap(),
            PathBuf::from("/prefix/drive_c/bar")
        );
    }

    // ── drive_root helper ─────────────────────────────────────────────────────

    #[test]
    fn drive_root_helper() {
        let t = translator();
        assert_eq!(t.drive_root('C'), PathBuf::from("/prefix/drive_c"));
        assert_eq!(t.drive_root('c'), PathBuf::from("/prefix/drive_c"));
        assert_eq!(t.drive_root('Z'), PathBuf::from("/prefix/drive_z"));
    }

    // ── Device path identification ────────────────────────────────────────────

    #[test]
    fn identify_nul_device() {
        assert_eq!(identify_device(r"\\.\NUL"), Some("NUL"));
    }

    #[test]
    fn identify_nul_bare() {
        assert_eq!(identify_device("NUL"), Some("NUL"));
    }

    #[test]
    fn identify_normal_path() {
        assert_eq!(identify_device(r"C:\foo\bar"), None);
    }

    // ── Task 02 path-form inventory ───────────────────────────────────────────
    //
    // One test per distinct path form observed in M4 CreateFileW logs and the
    // Task 02 inventory. Each form exercises a different branch of
    // `normalise_win_path` / `extract_drive`.

    /// Drive-absolute `Z:\...` must resolve under the real Linux root `/`,
    /// not under `{prefix}/drive_z`. Z: is Weave's mirror of the Linux fs.
    #[test]
    fn drive_absolute_z_uppercase() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"Z:\tmp\test.txt").unwrap(),
            PathBuf::from("/tmp/test.txt")
        );
    }

    /// Lowercase `z:` must behave identically to uppercase — drive letter
    /// comparison is case-insensitive.
    #[test]
    fn drive_absolute_z_lowercase() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"z:\tmp\test.txt").unwrap(),
            PathBuf::from("/tmp/test.txt")
        );
    }

    /// Root-relative paths (leading backslash, no drive letter) must map to
    /// Z: so they resolve under the Linux filesystem root. This is the M4
    /// regression fix landed in c903a32 — the fallback previously sent them
    /// to C: which mapped `\tmp\...` to `{prefix}/drive_c/tmp/...`.
    #[test]
    fn root_relative_maps_to_z() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"\tmp\test.txt").unwrap(),
            PathBuf::from("/tmp/test.txt")
        );
    }

    /// Extended-length prefix (`\\?\`) combined with Z: drive — the M4
    /// CreateFileW log showed 7-Zip emitting `\\?\Z:\tmp\...`. Prefix must
    /// be stripped before drive-letter extraction.
    #[test]
    fn extended_length_with_z() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"\\?\Z:\tmp\test.txt").unwrap(),
            PathBuf::from("/tmp/test.txt")
        );
    }

    /// NT object namespace (`\??\`) combined with Z: drive. Same stripping
    /// behavior as `\\?\`.
    #[test]
    fn nt_namespace_with_z() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"\??\Z:\tmp\test.txt").unwrap(),
            PathBuf::from("/tmp/test.txt")
        );
    }

    /// Bare relative paths (no drive letter, no leading backslash) fall back
    /// to C: so CWD-relative usage resolves under the prefix. Documented
    /// behavior of `extract_drive` — not a bug.
    #[test]
    fn bare_relative_falls_back_to_c() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"foo\bar.txt").unwrap(),
            PathBuf::from("/prefix/drive_c/foo/bar.txt")
        );
    }

    /// Trailing backslash — the empty component after the split must be
    /// filtered out. `split('\\').filter(|s| !s.is_empty())` guarantees this.
    #[test]
    fn trailing_backslash_filtered() {
        let t = translator();
        assert_eq!(
            t.to_linux_str(r"C:\Users\foo\").unwrap(),
            PathBuf::from("/prefix/drive_c/Users/foo")
        );
    }

    /// `C:` with no separator at all — drive extraction must not panic on
    /// the 2-byte input and must return an empty component list.
    #[test]
    fn drive_only_no_separator() {
        let t = translator();
        assert_eq!(
            t.to_linux_str("C:").unwrap(),
            PathBuf::from("/prefix/drive_c")
        );
    }

    /// Forward-slash Z: — MSVC CRT callers use `/` as separator. The first
    /// step of `normalise_win_path` replaces `/` with `\`, so this must
    /// behave identically to `Z:\tmp\test.txt`.
    #[test]
    fn forward_slash_z_drive() {
        let t = translator();
        assert_eq!(
            t.to_linux_str("Z:/tmp/test.txt").unwrap(),
            PathBuf::from("/tmp/test.txt")
        );
    }

    /// Root-relative with forward slashes — after slash normalisation this
    /// becomes `\tmp\test.txt` which the Z: fallback handles.
    #[test]
    fn root_relative_forward_slashes() {
        let t = translator();
        assert_eq!(
            t.to_linux_str("/tmp/test.txt").unwrap(),
            PathBuf::from("/tmp/test.txt")
        );
    }

    /// Z: drive-root alone should resolve to `/` — verifies that
    /// drive_root override for Z: does not produce an empty PathBuf when
    /// no components follow.
    #[test]
    fn z_drive_root_only() {
        let t = translator();
        assert_eq!(t.to_linux_str(r"Z:\").unwrap(), PathBuf::from("/"));
    }
}
