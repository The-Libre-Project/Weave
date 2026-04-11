//! Per-thread last error — shared TLS backing for GetLastError / SetLastError.
//!
//! Defined here in weave-common so that any DLL crate (advapi32, user32, etc.)
//! can set the thread error code without importing weave-kernel32 directly.
//! The Win32 exports `GetLastError` / `SetLastError` in weave-kernel32 are thin
//! wrappers over these functions.

use std::cell::Cell;

thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// Set the calling thread's last Win32 error code.
pub fn set_last_error(code: u32) {
    LAST_ERROR.with(|e| e.set(code));
}

/// Return the calling thread's last Win32 error code.
pub fn get_last_error() -> u32 {
    LAST_ERROR.with(|e| e.get())
}
