//! secur32.dll stubs for Weave — Security Support Provider Interface (SSPI).

#![allow(non_snake_case)]
//!
//! curl.exe imports InitSecurityInterfaceA to obtain the SSPI dispatch table
//! for NTLM/Kerberos authentication. This stub returns NULL (no SSPI table).
//! SSPI-based authentication is not supported; stubs exist for IAT resolution.

/// InitSecurityInterfaceA — retrieve the SSPI function dispatch table (ANSI).
///
/// On Windows, returns a pointer to a `SECURITY_FUNCTION_TABLE_A` struct
/// containing function pointers for all SSPI functions (InitializeSecurityContext,
/// AcceptSecurityContext, AcquireCredentialsHandle, etc.).
///
/// Weave returns NULL — no SSPI provider is available on Linux. Applications
/// that support alternative TLS libraries (e.g. curl with NSS/OpenSSL) will
/// fall back through their own TLS negotiation.
///
/// Returns NULL (0).
///
/// # Safety
/// This function takes no pointer arguments and has no memory safety
/// requirements. The caller is expected to check the return value.
// Wine ref: dlls/secur32/secur32.c — InitSecurityInterfaceA allocates and
// populates a SECURITY_FUNCTION_TABLE_A backed by Wine's SSPI implementation
// (ntlm, kerberos, negotiate). Returns NULL if the allocation fails or if no
// security package is registered.
pub unsafe extern "win64" fn InitSecurityInterfaceA() -> usize {
    0
}

/// Resolve a secur32.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("secur32.dll") {
        return None;
    }
    match func {
        "InitSecurityInterfaceA" => {
            Some(InitSecurityInterfaceA as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "InitSecurityInterfaceA").is_none());
    }

    #[test]
    fn resolve_unknown_function() {
        assert!(resolve("secur32.dll", "__nonexistent__").is_none());
    }

    #[test]
    fn resolve_init_security_interface_a() {
        assert!(resolve("secur32.dll", "InitSecurityInterfaceA").is_some());
    }

    #[test]
    fn init_security_interface_a_returns_null() {
        unsafe {
            let ptr = InitSecurityInterfaceA();
            assert_eq!(ptr, 0);
        }
    }
}
