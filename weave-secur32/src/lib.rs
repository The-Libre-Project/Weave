//! secur32.dll stubs for Weave — Security Support Provider Interface (SSPI).
//!
//! curl.exe imports InitSecurityInterfaceA to obtain the SSPI dispatch table
//! for NTLM/Kerberos authentication. This stub returns NULL (no SSPI table).
//! SSPI-based authentication is not supported; stubs exist for IAT resolution.

#![allow(unused_variables, non_snake_case, clippy::missing_safety_doc)]

/// InitSecurityInterfaceA — retrieve the SSPI function dispatch table (ANSI).
///
/// Returns NULL — no SSPI provider available.
pub unsafe extern "win64" fn InitSecurityInterfaceA() -> usize {
    0
}

/// Resolve a secur32.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("secur32.dll") {
        return None;
    }
    match func {
        "InitSecurityInterfaceA" => Some(InitSecurityInterfaceA as *const () as usize),
        _ => None,
    }
}
