//! bcrypt.dll stubs for Weave — Cryptography Next Generation (CNG) primitives.
//!
//! curl.exe (and any TLS stack using SChannel / OpenSSL CNG provider) imports
//! BCryptGenRandom for entropy. BCryptGenRandom is implemented for real via
//! the Linux `getrandom(2)` syscall so TLS sessions are seeded with kernel
//! CSPRNG output rather than the prior STATUS_NOT_IMPLEMENTED stub.

#![allow(non_snake_case)]

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// BCryptGenRandom — generate random bytes using CNG.
///
/// # Safety
/// `pbBuffer` must be null or writable for `cbBuffer` bytes.
//
// Wine ref: dlls/bcrypt/bcrypt_main.c:313 — NULL buffer → STATUS_INVALID_PARAMETER;
// count == 0 → STATUS_SUCCESS (no write); otherwise RtlGenRandom fills buffer and
// returns STATUS_SUCCESS. Algorithm handle is ignored when BCRYPT_USE_SYSTEM_PREFERRED_RNG
// is set (the curl/SChannel call pattern); Weave ignores it unconditionally since no
// algorithm-handle tracking is implemented.
pub unsafe extern "win64" fn BCryptGenRandom(
    _hAlgorithm: usize,
    pbBuffer: usize,
    cbBuffer: u32,
    _dwFlags: u32,
) -> u32 {
    if pbBuffer == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if cbBuffer == 0 {
        return STATUS_SUCCESS;
    }
    let buf = pbBuffer as *mut u8;
    let mut written = 0usize;
    let want = cbBuffer as usize;
    while written < want {
        let n =
            unsafe { libc::getrandom(buf.add(written) as *mut libc::c_void, want - written, 0) };
        if n < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // EINTR is the only retryable case; anything else is fatal here.
            if errno == libc::EINTR {
                continue;
            }
            return STATUS_NOT_IMPLEMENTED;
        }
        if n == 0 {
            return STATUS_NOT_IMPLEMENTED;
        }
        written += n as usize;
    }
    STATUS_SUCCESS
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn null_buffer_returns_invalid_parameter() {
        let r = unsafe { BCryptGenRandom(0, 0, 16, 0) };
        assert_eq!(r, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn zero_count_returns_success_no_write() {
        let mut buf = [0xAAu8; 4];
        let r = unsafe { BCryptGenRandom(0, buf.as_mut_ptr() as usize, 0, 0) };
        assert_eq!(r, STATUS_SUCCESS);
        assert_eq!(buf, [0xAA; 4], "zero count must not touch buffer");
    }

    #[test]
    fn fills_buffer_with_entropy() {
        let mut buf = [0u8; 64];
        let r = unsafe { BCryptGenRandom(0, buf.as_mut_ptr() as usize, 64, 0) };
        assert_eq!(r, STATUS_SUCCESS);
        // Probabilistic: 64 zero bytes from getrandom has p ≈ 2^-512. Reject.
        assert!(buf.iter().any(|&b| b != 0), "buffer should contain entropy");
    }
}
