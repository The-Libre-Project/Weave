//! winmm.dll stubs for Weave.
//!
//! Covers the Windows Multimedia API: high-resolution timers (`timeGetTime`,
//! `timeBeginPeriod`, `timeEndPeriod`), wave audio device queries, and
//! joystick stubs. All functions use `extern "win64"`.

#![allow(non_snake_case)]

/// Returns true for any DLL name this crate handles.
fn is_winmm_dll(dll: &str) -> bool {
    dll.eq_ignore_ascii_case("winmm.dll")
}

/// Resolve a winmm.dll import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !is_winmm_dll(dll) {
        return None;
    }
    // Grok implements these in GROK-TASK-13
    let _ = func;
    None
}
