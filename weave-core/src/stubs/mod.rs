//! Windows API stub registry.
//!
//! `resolve(dll, func)` is the single entry point used by the IAT patcher.
//! It dispatches to the per-DLL resolver modules below.
//!
//! Phase 1 DLL coverage:
//!   - ntdll.dll       — 3 functions (NtWriteFile, NtTerminateProcess, RtlInitUnicodeString)
//!   - KERNEL32.dll    — 15 functions
//!   - api-ms-win-crt-* — 27 functions across 7 UCRT API-set DLLs

mod crt;
mod kernel32;
mod ntdll;

use std::cell::Cell;

// Shared NT status codes used by ntdll stubs.
const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC0000001_u32 as i32;

// Shared thread-local last-error used by kernel32 stubs.
thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// Resolve a Windows import to a Weave stub address.
///
/// Returns `None` for unimplemented functions — the IAT patcher will abort
/// with a clear "unresolved import" message rather than jumping to garbage.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    match dll.to_ascii_lowercase().as_str() {
        "ntdll.dll" => ntdll::resolve(func),
        "kernel32.dll" => kernel32::resolve(func),
        // All seven UCRT API-set forwarding DLLs share the same resolver.
        s if s.starts_with("api-ms-win-crt-") => crt::resolve(func),
        _ => None,
    }
}
