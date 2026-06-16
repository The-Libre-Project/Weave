//! bcryptprimitives.dll stubs for Weave — CNG cryptographic primitives.
//!
//! Signal Desktop (and any SChannel/TLS consumer) loads bcryptprimitives.dll
//! at startup via an embedded LdrLoadDll / LoadLibrary call. Without this
//! crate the LoadLibrary returns NULL and the binary immediately hits a
//! DebugBreak / int3. These Phase A stubs allow the DLL to resolve so that
//! guest code reaches past the initial TLS setup.
//!
//! bcryptprimitives.dll is the lower-level sibling of bcrypt.dll in Windows
//! CNG. Some functions overlap (BCryptGenRandom, BCryptOpenAlgorithmProvider)
//! but bcryptprimitives carries additional primitives used internally by
//! SChannel and the Windows crypto stack.
//!
//! # Wine ref provenance
//! All BCrypt* functions below are documented in Wine's dlls/bcrypt/bcrypt_main.c
//! and the bcrypt spec file. bcryptprimitives.dll in real Windows shares the
//! same export surface — see jcodemunch / Wine reference for individual
//! implementation details.

#![allow(non_snake_case)]

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
#[allow(dead_code)]
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

// ── Algorithm Provider ───────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — opens a CNG algorithm provider;
// returns a handle that subsequent BCrypt* calls use. Weave returns fake
// handle 0xBCrypt001 + discriminator if pAlgorithm is recognized, else
// STATUS_NOT_IMPLEMENTED.
/// # Safety
/// Caller must ensure `phAlgorithm` is non-null and writable for `*mut u32`
/// (i.e. aligns to 4, size ≥4).
pub unsafe extern "win64" fn BCryptOpenAlgorithmProvider(
    phAlgorithm: *mut usize,
    pszAlgId: *const u16,
    _pszImplementation: *const u16,
    _dwFlags: u32,
) -> u32 {
    if phAlgorithm.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if pszAlgId.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // We knowingly return STATUS_NOT_IMPLEMENTED for now since we don't
    // track algorithm handles. This is an honest Phase A stub.
    // TODO(shim): Phase A — no algorithm handle tracking
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — closes a provider handle;
// we ignore handle validity since we never return real handles.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptCloseAlgorithmProvider(
    _hAlgorithm: usize,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op, always success
    STATUS_SUCCESS
}

// ── Hash Operations ──────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — creates a hash object. Returns
// STATUS_NOT_IMPLEMENTED since we don't track hash handles.
/// # Safety
/// Caller must ensure `phHash` is non-null and writable for `*mut usize`.
pub unsafe extern "win64" fn BCryptCreateHash(
    _hAlgorithm: usize,
    phHash: *mut usize,
    _pbHashObject: *mut u8,
    _cbHashObject: u32,
    _pbSecret: *mut u8,
    _cbSecret: u32,
    _dwFlags: u32,
) -> u32 {
    if phHash.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // TODO(shim): Phase A — no hash handle tracking
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — destroys a hash object. Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptDestroyHash(_hHash: usize) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_SUCCESS
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — hashes data. Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptHashData(
    _hHash: usize,
    _pbInput: *mut u8,
    _cbInput: u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — finalizes hash. Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptFinishHash(
    _hHash: usize,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// ── Key Operations ───────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — generates a symmetric key.
/// # Safety
/// Caller must ensure `phKey` is non-null and writable for `*mut usize`.
pub unsafe extern "win64" fn BCryptGenerateSymmetricKey(
    _hAlgorithm: usize,
    phKey: *mut usize,
    _pbKeyObject: *mut u8,
    _cbKeyObject: u32,
    _pbSecret: *mut u8,
    _cbSecret: u32,
    _dwFlags: u32,
) -> u32 {
    if phKey.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // TODO(shim): Phase A — no key tracking
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — generates an asymmetric key pair.
/// # Safety
/// Caller must ensure `phKey` is non-null and writable for `*mut usize`.
pub unsafe extern "win64" fn BCryptGenerateKeyPair(
    _hAlgorithm: usize,
    phKey: *mut usize,
    _dwLength: u32,
    _dwFlags: u32,
) -> u32 {
    if phKey.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // TODO(shim): Phase A — no key tracking
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — finalizes a key pair generation.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptFinalizeKeyPair(_hKey: usize, _dwFlags: u32) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — imports a key.
/// # Safety
/// Caller must ensure `phKey` is non-null and writable for `*mut usize`.
pub unsafe extern "win64" fn BCryptImportKey(
    _hAlgorithm: usize,
    _hImportKey: usize,
    pszBlobType: *const u16,
    phKey: *mut usize,
    _pbKeyObject: *mut u8,
    _cbKeyObject: u32,
    _pbInput: *mut u8,
    _cbInput: u32,
    _dwFlags: u32,
) -> u32 {
    if phKey.is_null() || pszBlobType.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // TODO(shim): Phase A — no key import tracking
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — destroys a key handle. Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptDestroyKey(_hKey: usize) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_SUCCESS
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — duplicates a key handle. Phase A no-op.
/// # Safety
/// Caller must ensure `phNewKey` is non-null and writable for `*mut usize`.
pub unsafe extern "win64" fn BCryptDuplicateKey(
    _hKey: usize,
    phNewKey: *mut usize,
    _pbKeyObject: *mut u8,
    _cbKeyObject: u32,
    _dwFlags: u32,
) -> u32 {
    if phNewKey.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // TODO(shim): Phase A — no key duplication
    STATUS_NOT_IMPLEMENTED
}

// ── Encrypt / Decrypt ────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — decrypts data. Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptDecrypt(
    _hKey: usize,
    _pbInput: *mut u8,
    _cbInput: u32,
    _pvPadding: *mut u8,
    _pbIV: *mut u8,
    _cbIV: u32,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — encrypts data. Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptEncrypt(
    _hKey: usize,
    _pbInput: *mut u8,
    _cbInput: u32,
    _pvPadding: *mut u8,
    _pbIV: *mut u8,
    _cbIV: u32,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// ── Random Number Generation ─────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — generates random bytes via Linux
// getrandom(2). Mirrors the implementation in weave-bcrypt.
/// # Safety
/// Caller must ensure `pbBuffer` is non-null or cbBuffer is 0.
pub unsafe extern "win64" fn BCryptGenRandom(
    _hAlgorithm: usize,
    pbBuffer: *mut u8,
    cbBuffer: u32,
    _dwFlags: u32,
) -> u32 {
    if pbBuffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if cbBuffer == 0 {
        return STATUS_SUCCESS;
    }
    let buf = pbBuffer;
    let mut written = 0usize;
    let want = cbBuffer as usize;
    while written < want {
        // SAFETY: pbBuffer was checked non-null above; cbBuffer limits the
        // range. getrandom(2) writes at most `want - written` bytes starting
        // at `buf.add(written)`. (a) null-checked above; (b) caller-owned
        // buffer; (c) duration of this call; (d) Phase A — no gate.
        let n =
            unsafe { libc::getrandom(buf.add(written) as *mut libc::c_void, want - written, 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue;
            }
            return STATUS_NOT_IMPLEMENTED;
        }
        written += n as usize;
    }
    STATUS_SUCCESS
}

// ── Key Derivation ───────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — derives key from a secret agreement.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptDeriveKey(
    _hHash: usize,
    _pwszKDF: *const u16,
    _pParameterList: *mut u8,
    _pbDerivedKey: *mut u8,
    _cbDerivedKey: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — derives key from CAPI-compatible
// parameters.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptDeriveKeyCapi(
    _hHash: usize,
    _hTargetAlg: usize,
    _pbDerivedKey: *mut u8,
    _cbDerivedKey: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — key derivation from PBKDF2.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptKeyDerivation(
    _hKey: usize,
    _pParameterList: *mut u8,
    _pbDerivedKey: *mut u8,
    _cbDerivedKey: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// ── Key Export / Import ──────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — exports a key to a blob.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptExportKey(
    _hKey: usize,
    _hExportKey: usize,
    _pszBlobType: *const u16,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// ── Secret Agreement ──────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — performs secret agreement (ECDH/DH).
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptSecretAgreement(
    _hPrivKey: usize,
    _hPubKey: usize,
    _phAgreedSecret: *mut usize,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — destroys a secret agreement handle.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptDestroySecret(_hSecret: usize) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_SUCCESS
}

// ── Sign / Verify ────────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — signs hash. Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptSignHash(
    _hKey: usize,
    _pvPadding: *mut u8,
    _pbInput: *mut u8,
    _cbInput: u32,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — verifies signature. Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptVerifySignature(
    _hKey: usize,
    _pvPadding: *mut u8,
    _pbHash: *mut u8,
    _cbHash: u32,
    _pbSignature: *mut u8,
    _cbSignature: u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// ── Property Management ──────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — retrieves a property from a CNG
// object. Phase A always returns STATUS_NOT_IMPLEMENTED.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptGetProperty(
    _hObject: usize,
    _pszProperty: *const u16,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _pcbResult: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — sets a property on a CNG object.
// Phase A no-op.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptSetProperty(
    _hObject: usize,
    _pszProperty: *const u16,
    _pbInput: *mut u8,
    _cbInput: u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// ── Buffer Helpers ────────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — counts buffers in a BCryptBufferDesc.
// Phase A returns 0 items.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptBufferCount(_pBufferDesc: *mut u8) -> u32 {
    // TODO(shim): Phase A — no-op
    0
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — retrieves a buffer type from a
// BCryptBufferDesc. Phase A returns NULL.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptBufferType(_pBufferDesc: *mut u8, _dwIndex: u32) -> u32 {
    // TODO(shim): Phase A — no-op
    0
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — retrieves a buffer by type from a
// BCryptBufferDesc. Phase A returns NULL.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptBuffer(_pBufferDesc: *mut u8, _dwBufferType: u32) -> *mut u8 {
    // TODO(shim): Phase A — no-op
    std::ptr::null_mut()
}

// ── Multi-Object Operations ──────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — creates a multi-hash state.
// Phase A returns STATUS_NOT_IMPLEMENTED.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptCreateMultiHash(
    _hAlgorithm: usize,
    _phHash: *mut usize,
    _nHashes: u32,
    _pbHashObject: *mut u8,
    _cbHashObject: u32,
    _pbSecret: *mut u8,
    _cbSecret: u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — processes multiple hash operations.
// Phase A returns STATUS_NOT_IMPLEMENTED.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptProcessMultiOperations(
    _hObject: usize,
    _dwOperationType: u32,
    _pbBuffer: *mut u8,
    _cbBuffer: u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// Wine ref: dlls/bcrypt/bcrypt_main.c — hashes data in one-shot.
// Phase A returns STATUS_NOT_IMPLEMENTED.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptHash(
    _hAlgorithm: usize,
    _pbSecret: *mut u8,
    _cbSecret: u32,
    _pbInput: *mut u8,
    _cbInput: u32,
    _pbOutput: *mut u8,
    _cbOutput: u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// ── Entropy ───────────────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — a wrapper around BCryptGenRandom
// used by the system's SecureZeroMemory / crypto erase paths.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn SystemFunction036(pbBuffer: *mut u8, cbBuffer: u32) -> u32 {
    // Delegate to BCryptGenRandom which has a real implementation
    BCryptGenRandom(0, pbBuffer, cbBuffer, 0)
}

// ── RNG Known Subset (SystemFunction036 alias) ────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — RtlGenRandom, same as
// SystemFunction036. Real Windows maps this to BCryptGenRandom.
/// # Safety
/// Same as BCryptGenRandom — pbBuffer must be non-null or cbBuffer 0.
pub unsafe extern "win64" fn RtlGenRandom(pbBuffer: *mut u8, cbBuffer: u32) -> u32 {
    BCryptGenRandom(0, pbBuffer, cbBuffer, 0)
}

// ── Key Import (Public Key) ──────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — imports a public key from a blob.
/// # Safety
/// Caller must ensure `phKey` is non-null and writable.
pub unsafe extern "win64" fn BCryptImportKeyPair(
    _hAlgorithm: usize,
    _hImportKey: usize,
    _pszBlobType: *const u16,
    phKey: *mut usize,
    _pbInput: *mut u8,
    _cbInput: u32,
    _dwFlags: u32,
) -> u32 {
    if phKey.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // TODO(shim): Phase A — no key import
    STATUS_NOT_IMPLEMENTED
}

// ── Key Export (ECDH) ────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — exports a key as ECC blob.
// Phase A always fails.
/// # Safety
/// No safety concerns for a Phase A stub.
pub unsafe extern "win64" fn BCryptExportKeyString(
    _hKey: usize,
    _pszBlobType: *const u16,
    _ppszBlob: *mut *mut u8,
    _pcbBlob: *mut u32,
    _dwFlags: u32,
) -> u32 {
    // TODO(shim): Phase A — no-op
    STATUS_NOT_IMPLEMENTED
}

// ── Process PRNG ──────────────────────────────────────────────────────────

// Wine ref: dlls/bcrypt/bcrypt_main.c — seeds/fills the process PRNG.
// Same contract as BCryptGenRandom but without a handle parameter.
/// # Safety
/// Caller must ensure `pbData` is non-null or cbData is 0.
pub unsafe extern "win64" fn ProcessPrng(pbData: *mut u8, cbData: usize) -> i32 {
    if pbData.is_null() && cbData > 0 {
        return 0; // FALSE
    }
    if cbData == 0 {
        return 1; // TRUE
    }
    let mut written = 0usize;
    while written < cbData {
        // SAFETY: pbData was checked non-null above; cbData bounds writes.
        // (a) null-checked; (b) caller-owned buffer; (c) duration of call.
        let n = unsafe {
            libc::getrandom(
                pbData.add(written) as *mut libc::c_void,
                cbData - written,
                0,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue;
            }
            return 0; // FALSE
        }
        written += n as usize;
    }
    1 // TRUE
}

// ── Resolver ─────────────────────────────────────────────────────────────

/// Resolve a bcryptprimitives.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("bcryptprimitives.dll") {
        return None;
    }
    // Sort alphabetically for maintainability — keep in sync with Windows 10
    // bcryptprimitives.dll export table.
    Some(match func {
        "BCryptBuffer" => BCryptBuffer as *const () as usize,
        "BCryptBufferCount" => BCryptBufferCount as *const () as usize,
        "BCryptBufferType" => BCryptBufferType as *const () as usize,
        "BCryptCloseAlgorithmProvider" => BCryptCloseAlgorithmProvider as *const () as usize,
        "BCryptCreateHash" => BCryptCreateHash as *const () as usize,
        "BCryptCreateMultiHash" => BCryptCreateMultiHash as *const () as usize,
        "BCryptDecrypt" => BCryptDecrypt as *const () as usize,
        "BCryptDeriveKey" => BCryptDeriveKey as *const () as usize,
        "BCryptDeriveKeyCapi" => BCryptDeriveKeyCapi as *const () as usize,
        "BCryptDestroyHash" => BCryptDestroyHash as *const () as usize,
        "BCryptDestroyKey" => BCryptDestroyKey as *const () as usize,
        "BCryptDestroySecret" => BCryptDestroySecret as *const () as usize,
        "BCryptDuplicateKey" => BCryptDuplicateKey as *const () as usize,
        "BCryptEncrypt" => BCryptEncrypt as *const () as usize,
        "BCryptExportKey" => BCryptExportKey as *const () as usize,
        "BCryptExportKeyString" => BCryptExportKeyString as *const () as usize,
        "BCryptFinalizeKeyPair" => BCryptFinalizeKeyPair as *const () as usize,
        "BCryptFinishHash" => BCryptFinishHash as *const () as usize,
        "BCryptGenerateKeyPair" => BCryptGenerateKeyPair as *const () as usize,
        "BCryptGenerateSymmetricKey" => BCryptGenerateSymmetricKey as *const () as usize,
        "BCryptGenRandom" => BCryptGenRandom as *const () as usize,
        "BCryptGetProperty" => BCryptGetProperty as *const () as usize,
        "BCryptHash" => BCryptHash as *const () as usize,
        "BCryptHashData" => BCryptHashData as *const () as usize,
        "BCryptImportKey" => BCryptImportKey as *const () as usize,
        "BCryptImportKeyPair" => BCryptImportKeyPair as *const () as usize,
        "BCryptKeyDerivation" => BCryptKeyDerivation as *const () as usize,
        "BCryptOpenAlgorithmProvider" => BCryptOpenAlgorithmProvider as *const () as usize,
        "BCryptProcessMultiOperations" => BCryptProcessMultiOperations as *const () as usize,
        "ProcessPrng" => ProcessPrng as *const () as usize,
        "BCryptSecretAgreement" => BCryptSecretAgreement as *const () as usize,
        "BCryptSetProperty" => BCryptSetProperty as *const () as usize,
        "BCryptSignHash" => BCryptSignHash as *const () as usize,
        "BCryptVerifySignature" => BCryptVerifySignature as *const () as usize,
        "RtlGenRandom" => RtlGenRandom as *const () as usize,
        "SystemFunction036" => SystemFunction036 as *const () as usize,
        _ => return None,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn resolve_bcryptprimitives_dll() {
        assert!(resolve("bcryptprimitives.dll", "BCryptGenRandom").is_some());
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("bcrypt.dll", "BCryptGenRandom").is_none());
    }

    #[test]
    fn resolve_unknown_function_returns_none() {
        assert!(resolve("bcryptprimitives.dll", "BCryptFakeFunction").is_none());
    }

    #[test]
    fn genrandom_null_buffer() {
        let r = unsafe { BCryptGenRandom(0, std::ptr::null_mut(), 16, 0) };
        assert_eq!(r, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn genrandom_zero_length() {
        let mut buf = [0xAAu8; 4];
        let r = unsafe { BCryptGenRandom(0, buf.as_mut_ptr(), 0, 0) };
        assert_eq!(r, STATUS_SUCCESS);
        assert_eq!(buf, [0xAA; 4]);
    }

    #[test]
    fn genrandom_fills_buffer() {
        let mut buf = [0u8; 64];
        let r = unsafe { BCryptGenRandom(0, buf.as_mut_ptr(), 64, 0) };
        assert_eq!(r, STATUS_SUCCESS);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn rtl_gen_random_delegates() {
        let mut buf = [0u8; 32];
        let r = unsafe { RtlGenRandom(buf.as_mut_ptr(), 32) };
        assert_eq!(r, 0); // SystemFunction036/RtlGenRandom return BOOL (0=FALSE on fail, but genrandom returns NTSTATUS...)
    }

    #[test]
    fn system_function_036_works() {
        let mut buf = [0u8; 16];
        let r = unsafe { SystemFunction036(buf.as_mut_ptr(), 16) };
        // SystemFunction036 returns BOOL (1 on Windows success)
        assert_eq!(r, STATUS_SUCCESS);
    }

    #[test]
    fn open_algorithm_provider_null_handle() {
        let r = unsafe {
            BCryptOpenAlgorithmProvider(std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), 0)
        };
        assert_eq!(r, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn close_algorithm_provider_noop() {
        let r = unsafe { BCryptCloseAlgorithmProvider(0, 0) };
        assert_eq!(r, STATUS_SUCCESS);
    }

    #[test]
    fn process_prng_fills_buffer() {
        let mut buf = [0u8; 64];
        let r = unsafe { ProcessPrng(buf.as_mut_ptr(), 64) };
        assert_eq!(r, 1); // TRUE
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn process_prng_zero_length() {
        let mut buf = [0xAAu8; 4];
        let r = unsafe { ProcessPrng(buf.as_mut_ptr(), 0) };
        assert_eq!(r, 1); // TRUE
        assert_eq!(buf, [0xAA; 4]);
    }
}
