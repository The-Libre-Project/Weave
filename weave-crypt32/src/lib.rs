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
pub unsafe extern "win64" fn CertOpenSystemStoreA(_hprov: usize, _szSubsystemProtocol: usize) -> usize {
    0 // NULL — store unavailable
}
