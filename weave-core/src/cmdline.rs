//! Guest command-line storage.
//!
//! `set()` is called once from the Weave CLI before IAT patching. All stubs
//! that need the Windows command line — `GetCommandLineA/W`, `_acmdln`,
//! `_wcmdln` — read from here instead of using hardcoded strings.

use std::sync::OnceLock;

struct CmdLine {
    /// Null-terminated ANSI command line (full string, all args).
    ansi: Vec<u8>,
    /// Null-terminated wide command line (full string, all args).
    wide: Vec<u16>,
}

static CMD_LINE: OnceLock<CmdLine> = OnceLock::new();

/// Store the Windows command line built from the exe name and any trailing args.
///
/// Must be called before IAT patching so that `_acmdln`/`_wcmdln` data
/// imports and `GetCommandLineA/W` all see the correct value.
///
/// Calling this more than once has no effect (OnceLock).
pub fn set(exe_name: &str, args: &[String]) {
    CMD_LINE.get_or_init(|| {
        let mut s = String::new();
        // argv[0]: quote if it contains a space.
        if exe_name.contains(' ') {
            s.push('"');
            s.push_str(exe_name);
            s.push('"');
        } else {
            s.push_str(exe_name);
        }
        for arg in args {
            s.push(' ');
            if arg.contains(' ') {
                s.push('"');
                s.push_str(arg);
                s.push('"');
            } else {
                s.push_str(arg);
            }
        }
        let mut ansi: Vec<u8> = s.bytes().collect();
        ansi.push(0);
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        CmdLine { ansi, wide }
    });
}

/// Return a pointer to the null-terminated ANSI command line.
///
/// Falls back to `"app.exe\0"` if `set()` was never called.
pub fn get_a() -> *const u8 {
    static FALLBACK: &[u8] = b"app.exe\0";
    CMD_LINE
        .get()
        .map(|c| c.ansi.as_ptr())
        .unwrap_or(FALLBACK.as_ptr())
}

/// Return a pointer to the null-terminated wide command line.
///
/// Falls back to `L"app.exe\0"` if `set()` was never called.
pub fn get_w() -> *const u16 {
    static FALLBACK: &[u16] = &[
        b'a' as u16,
        b'p' as u16,
        b'p' as u16,
        b'.' as u16,
        b'e' as u16,
        b'x' as u16,
        b'e' as u16,
        0u16,
    ];
    CMD_LINE
        .get()
        .map(|c| c.wide.as_ptr())
        .unwrap_or(FALLBACK.as_ptr())
}
