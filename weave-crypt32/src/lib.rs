//! crypt32.dll stubs for Weave — certificate and cryptographic message services.
//!
//! curl.exe imports 6 certificate-store symbols for HTTPS/TLS certificate
//! validation. These are no-op stubs returning 0/false/null. Certificate
//! validation is delegated to the TLS library; these stubs exist solely to
//! satisfy IAT resolution.
//!
//! NOTE: weave-advapi32 handles crypt32.dll resolution for NPP (Crypt* entropy
//! functions: CryptAcquireContextA, CryptGenRandom, CryptReleaseContext). This
//! crate covers the certificate-store API surface that advapi32 does not handle.

#![allow(unused_variables, non_snake_case, clippy::missing_safety_doc)]

/// CertCloseStore — close a certificate store handle.
pub unsafe extern "win64" fn CertCloseStore(_hCertStore: usize, _dwFlags: u32) -> i32 {
    1 // TRUE
}

/// CertEnumCertificatesInStore — enumerate certificates in a store.
pub unsafe extern "win64" fn CertEnumCertificatesInStore(
    _hCertStore: usize,
    _pPrevCertContext: usize,
) -> usize {
    0 // NULL — no certificates
}

/// CertFreeCertificateContext — free a certificate context.
pub unsafe extern "win64" fn CertFreeCertificateContext(_pCertContext: usize) -> i32 {
    1 // TRUE
}

/// CertGetEnhancedKeyUsage — retrieve enhanced key usage extension.
pub unsafe extern "win64" fn CertGetEnhancedKeyUsage(
    _pCertContext: usize,
    _dwFlags: u32,
    _pUsage: usize,
    _pcbUsage: usize,
) -> i32 {
    0 // FALSE
}

/// CertGetIntendedKeyUsage — retrieve key usage bits from certificate.
pub unsafe extern "win64" fn CertGetIntendedKeyUsage(
    _dwCertEncodingType: u32,
    _pCertInfo: usize,
    _pbKeyUsage: usize,
    _cbKeyUsage: u32,
) -> i32 {
    0 // FALSE
}

/// CertOpenSystemStoreA — open the system certificate store by name (ANSI).
pub unsafe extern "win64" fn CertOpenSystemStoreA(
    _hprov: usize,
    _szSubsystemProtocol: usize,
) -> usize {
    0 // NULL — store unavailable
}

/// CertGetNameStringA — retrieve the subject or issuer name from a certificate context (ANSI).
///
/// # Safety
/// `p_cert_context` is accepted but not used; `psz_name_string` may be null (size query).
// Wine ref: dlls/crypt32/cert.c — CertGetNameStringA calls CertGetNameStringW and converts.
// Weave: no certificate store — return 0 (failure).
pub unsafe extern "win64" fn CertGetNameStringA(
    _p_cert_context: usize,
    _dw_type: u32,
    _dw_flags: u32,
    _pv_type_para: usize,
    _psz_name_string: *mut u8,
    _cch_name_string: u32,
) -> u32 {
    0 // failure: no certificate context
}

/// Resolve a crypt32.dll import to a function pointer.
///
/// NOTE: weave-advapi32 also resolves crypt32.dll (CryptAcquireContextA,
/// CryptGenRandom, CryptReleaseContext, and several Cert* APIs for NPP).
/// Place this resolver AFTER weave_advapi32::resolve in the chain so
/// advapi32's real impls win for overlapping symbols.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("crypt32.dll") {
        return None;
    }
    match func {
        "CertCloseStore" => Some(CertCloseStore as *const () as usize),
        "CertEnumCertificatesInStore" => Some(CertEnumCertificatesInStore as *const () as usize),
        "CertFreeCertificateContext" => Some(CertFreeCertificateContext as *const () as usize),
        "CertGetEnhancedKeyUsage" => Some(CertGetEnhancedKeyUsage as *const () as usize),
        "CertGetIntendedKeyUsage" => Some(CertGetIntendedKeyUsage as *const () as usize),
        "CertOpenSystemStoreA" => Some(CertOpenSystemStoreA as *const () as usize),
        "CertGetNameStringA" => Some(
            CertGetNameStringA as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        _ => None,
    }
}
