//! Guest command-line storage.
//!
//! `set()` is called once from the Weave CLI before IAT patching. All stubs
//! that need the Windows command line — `GetCommandLineA/W`, `_acmdln`,
//! `_wcmdln` — read from here instead of using hardcoded strings.
//!
//! Also stores the individual argv strings so that `__p___argc` and
//! `__p___argv` CRT stubs can return the real argument count and array.

use std::sync::OnceLock;

struct CmdLine {
    /// Null-terminated ANSI command line (full string, all args).
    ansi: Vec<u8>,
    /// Null-terminated wide command line (full string, all args).
    wide: Vec<u16>,
    /// Number of arguments (argc), including argv[0] (exe name).
    argc: i32,
    /// Individual argv strings, each null-terminated. Stored on the heap
    /// inside the OnceLock so they never move after construction.
    /// Never read directly — exists solely to keep the heap allocations alive
    /// so that the raw pointers in `argv_ptrs` remain valid.
    #[allow(dead_code)]
    argv_strings: Vec<Vec<u8>>,
    /// Pointers into `argv_strings` + a null terminator sentinel.
    /// Built once and never reallocated, so the raw pointers remain valid
    /// for the lifetime of the process (OnceLock is never dropped).
    argv_ptrs: Vec<*mut u8>,
}

// SAFETY: CmdLine is stored in a OnceLock and never mutated after
// initialisation. The raw `*mut u8` pointers in `argv_ptrs` point into
// `argv_strings` which live in the same allocation. We never expose these
// pointers across a thread boundary other than via the public API below,
// where callers treat the data as read-only.
unsafe impl Send for CmdLine {}
unsafe impl Sync for CmdLine {}

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

        // Build argv_strings: argv[0] = exe_name, argv[1..] = args.
        // Each string is null-terminated ANSI bytes.
        let mut argv_strings: Vec<Vec<u8>> = std::iter::once(exe_name)
            .map(|s| s.to_owned())
            .chain(args.iter().map(|a| a.to_owned()))
            .map(|s| {
                let mut b: Vec<u8> = s.into_bytes();
                b.push(0);
                b
            })
            .collect();

        // Build argv_ptrs: pointers into the strings above + null sentinel.
        // We take the pointers AFTER constructing all strings so no
        // reallocation can occur between pointer capture and use.
        let mut argv_ptrs: Vec<*mut u8> = argv_strings
            .iter_mut()
            .map(|v| v.as_mut_ptr())
            .collect();
        argv_ptrs.push(std::ptr::null_mut()); // null terminator (argv[argc])

        let argc = (argv_ptrs.len() - 1) as i32; // exclude the null sentinel

        CmdLine { ansi, wide, argc, argv_strings, argv_ptrs }
    });
}

/// Return the argument count (argc), including argv[0].
///
/// Falls back to 1 if `set()` was never called.
pub fn get_argc() -> i32 {
    CMD_LINE.get().map(|c| c.argc).unwrap_or(1)
}

/// Return a pointer to the null-terminated argv pointer array (`char **`).
///
/// The returned pointer is valid for the lifetime of the process.
/// Falls back to `null` if `set()` was never called (callers must handle this).
///
/// # Safety
/// The caller must not write through the returned pointer or free it.
pub fn get_argv() -> *mut *mut u8 {
    CMD_LINE
        .get()
        .map(|c| c.argv_ptrs.as_ptr() as *mut *mut u8)
        .unwrap_or(std::ptr::null_mut())
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
