//! bcrypt.dll stubs for Weave — Cryptography Next Generation (CNG) primitives.
//!
//! curl.exe imports BCryptGenRandom for entropy generation. This stub returns
//! STATUS_NOT_IMPLEMENTED (0xC0000002). Entropy is sourced via other means
//! (getrandom/urandom) at the TLS library layer; this stub exists for IAT
//! resolution only.

#![allow(unused_variables, non_snake_case, clippy::missing_safety_doc)]

/// BCryptGenRandom — generate random bytes using CNG.
///
/// Returns STATUS_NOT_IMPLEMENTED (0xC0000002). curl falls back to other
/// entropy sources when this fails.
pub unsafe extern "win64" fn BCryptGenRandom(
    _hAlgorithm: usize,
    _pbBuffer: usize,
    _cbBuffer: u32,
    _dwFlags: u32,
) -> u32 {
    0xC0000002u32 // STATUS_NOT_IMPLEMENTED
}

/// Resolve a bcrypt.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("bcrypt.dll") {
        return None;
    }
    match func {
        "BCryptGenRandom" => Some(BCryptGenRandom as *const () as usize),
        _ => None,
    }
}
