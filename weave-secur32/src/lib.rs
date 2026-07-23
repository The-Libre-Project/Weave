//! secur32.dll stubs for Weave — Security Support Provider Interface (SSPI).

#![allow(non_snake_case, clippy::missing_safety_doc)]
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

/// InitSecurityInterfaceW — retrieve the SSPI function dispatch table (Unicode).
/// Phase A stub — returns NULL (no SSPI provider).
// Wine ref: dlls/secur32/secur32.c — InitSecurityInterfaceW same as A variant.
pub unsafe extern "win64" fn InitSecurityInterfaceW() -> usize {
    0
}

const SEC_E_UNSUPPORTED_FUNCTION: i32 = -2146893054; // 0x80090302

/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubAcquireCredentialsHandleW() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubInitializeSecurityContextW() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubAcceptSecurityContext() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubDeleteSecurityContext() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubFreeContextBuffer() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubQueryContextAttributesW() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubFreeCredentialsHandle() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubEncryptMessage() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubDecryptMessage() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubMakeSignature() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}
/// stub — returns SEC_E_UNSUPPORTED_FUNCTION.
pub unsafe extern "win64" fn StubVerifySignature() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
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
        "InitSecurityInterfaceW" => {
            Some(InitSecurityInterfaceW as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        "AcquireCredentialsHandleW" => Some(
            StubAcquireCredentialsHandleW as unsafe extern "win64" fn() -> _ as *const () as usize,
        ),
        "InitializeSecurityContextW" => Some(
            StubInitializeSecurityContextW as unsafe extern "win64" fn() -> _ as *const () as usize,
        ),
        "AcceptSecurityContext" => {
            Some(StubAcceptSecurityContext as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        "DeleteSecurityContext" => {
            Some(StubDeleteSecurityContext as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        "FreeContextBuffer" => {
            Some(StubFreeContextBuffer as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        "QueryContextAttributesW" => Some(
            StubQueryContextAttributesW as unsafe extern "win64" fn() -> _ as *const () as usize,
        ),
        "FreeCredentialsHandle" => {
            Some(StubFreeCredentialsHandle as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        "EncryptMessage" => {
            Some(StubEncryptMessage as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        "DecryptMessage" => {
            Some(StubDecryptMessage as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        "MakeSignature" => {
            Some(StubMakeSignature as unsafe extern "win64" fn() -> _ as *const () as usize)
        }
        "VerifySignature" => {
            Some(StubVerifySignature as unsafe extern "win64" fn() -> _ as *const () as usize)
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
