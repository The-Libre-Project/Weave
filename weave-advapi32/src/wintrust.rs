//! wintrust.dll, crypt32.dll, and sensapi.dll stubs for Weave.
//!
//! Strategy: fully-successful fake PKI chain so Notepad++ proceeds past its
//! Authenticode verification without throwing a C++ exception.
//!
//!   - CryptQueryObject returns TRUE with sentinel fake handles (FAKE_MSG_HANDLE,
//!     FAKE_STORE_HANDLE) so NPP enters the cert-extraction path.
//!   - CryptMsgGetParam fills a 136-byte CMSG_SIGNER_INFO with dwVersion=1 and
//!     all blob fields zeroed (cbData=0, pbData=NULL). This avoids embedded-pointer
//!     problems — CertFindCertificateInStore receives a CERT_INFO with empty
//!     Issuer/SerialNumber blobs and ignores it.
//!   - CertFindCertificateInStore ignores pvPara and returns a static CERT_CONTEXT.
//!   - CertGetNameStringW returns L"Notepad++" — the publisher name NPP expects.
//!   - CertGetCertificateContextProperty returns 20 zero bytes for the hash
//!     property IDs NPP queries (SHA1=3, key identifier=20).
//!   - CertFreeCertificateContext / CertCloseStore / CryptMsgClose are no-ops.
//!
//! Wine refs:
//!   - CryptQueryObject:  dlls/crypt32/object.c — CRYPT_QueryEmbeddedMessageObject
//!   - CryptMsgGetParam:  dlls/crypt32/msg.c — CMSG_SIGNER_INFO_PARAM dispatch
//!   - CMSG_SIGNER_INFO:  include/wincrypt.h line 866 — verified layout, 136 bytes
//!   - CERT_CONTEXT:      include/wincrypt.h line 481 — verified layout, 40 bytes
//!   - CertContext_GetProperty: dlls/crypt32/cert.c line 526 — propId dispatch
//!   - CertGetNameStringW: dlls/crypt32/str.c — CERT_NAME_SIMPLE_DISPLAY_TYPE

// ── Sentinel handle values ────────────────────────────────────────────────────

/// Magic value for our fake HCRYPTMSG — ASCII "MSG\0"
const FAKE_MSG_HANDLE: usize = 0x4D53_4700;
/// Magic value for our fake HCERTSTORE — ASCII "STO\0"
const FAKE_STORE_HANDLE: usize = 0x5354_4F00;

// Size of CMSG_SIGNER_INFO on 64-bit Windows, from wincrypt.h line 866:
//
//   Field                         Type                    Size  Offset
//   dwVersion                     DWORD                      4       0
//   _pad                          (alignment)                4       4
//   Issuer (CERT_NAME_BLOB)       {cbData:u32,_:u32,pb:*}   16       8
//   SerialNumber (INTEGER_BLOB)   {cbData:u32,_:u32,pb:*}   16      24
//   HashAlgorithm (ALG_ID)        {psz:*,{cb:u32,_:u32,pb:*}} 24   40
//   HashEncryptionAlgorithm       (same)                    24      64
//   EncryptedHash (DATA_BLOB)     {cbData:u32,_:u32,pb:*}   16      88
//   AuthAttrs (CRYPT_ATTRIBUTES)  {cAttr:u32,_:u32,rg:*}    16     104
//   UnauthAttrs                   (same)                    16     120
//   Total:                                                 136
const SIGNER_INFO_SIZE: u32 = 136;

// ── Static fake certificate context ──────────────────────────────────────────

// Zeroed placeholder large enough to stand in for CERT_INFO (wincrypt.h line
// 243). Our stubs never read through p_cert_info — it just needs to be
// non-null and stable so NPP's null-guard on pCertInfo doesn't trigger.
#[repr(C, align(8))]
struct FakeCertInfo {
    _reserved: [u8; 320],
}

static FAKE_CERT_INFO: FakeCertInfo = FakeCertInfo {
    _reserved: [0u8; 320],
};

// CERT_CONTEXT layout on 64-bit Windows (wincrypt.h line 481):
//
//   offset  0: dwCertEncodingType  u32        = 1 (X509_ASN_ENCODING)
//   offset  4: _pad0               u32
//   offset  8: pbCertEncoded       *const u8  = null
//   offset 16: cbCertEncoded       u32        = 0
//   offset 20: _pad1               u32
//   offset 24: pCertInfo           *...       = &FAKE_CERT_INFO
//   offset 32: hCertStore          usize      = FAKE_STORE_HANDLE
//   total: 40 bytes
#[repr(C)]
struct FakeCertContext {
    dw_cert_encoding_type: u32,
    _pad0: u32,
    pb_cert_encoded: *const u8,
    cb_cert_encoded: u32,
    _pad1: u32,
    p_cert_info: *const FakeCertInfo,
    h_cert_store: usize,
}

// SAFETY: FAKE_CERT_CTX is a read-only static. Its pointer fields point to
// another static (FAKE_CERT_INFO) or are null. Safe to share across threads.
unsafe impl Sync for FakeCertContext {}

static FAKE_CERT_CTX: FakeCertContext = FakeCertContext {
    dw_cert_encoding_type: 1, // X509_ASN_ENCODING
    _pad0: 0,
    pb_cert_encoded: core::ptr::null(),
    cb_cert_encoded: 0,
    _pad1: 0,
    p_cert_info: &FAKE_CERT_INFO as *const FakeCertInfo,
    h_cert_store: FAKE_STORE_HANDLE,
};

// ── wintrust.dll ─────────────────────────────────────────────────────────────

/// TRUST_E_NOSIGNATURE — subject has no authenticode signature.
/// Returned by WinVerifyTrust when there is no signature to verify.
const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;

/// WinVerifyTrust(hwnd, action_guid, data) → LONG
///
/// Wine ref: dlls/wintrust/wintrust_main.c — WinVerifyTrust dispatches to
/// WINTRUST_DefaultVerifyAndClose for WTD_STATEACTION_IGNORE, which walks the
/// authenticode chain. When no signature is present the chain returns
/// TRUST_E_NOSIGNATURE. We skip the real chain and return that directly.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn win_verify_trust(
    _hwnd: usize,
    _action_id: *const u8,
    data: *const u8,
) -> i32 {
    eprintln!("weave/WinVerifyTrust: data={data:p} → TRUST_E_NOSIGNATURE");
    TRUST_E_NOSIGNATURE
}

/// WinVerifyTrustEx — thin wrapper around WinVerifyTrust in Wine.
/// Wine ref: dlls/wintrust/wintrust_main.c — WinVerifyTrustEx calls WinVerifyTrust.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn win_verify_trust_ex(
    hwnd: usize,
    action_id: *const u8,
    data: *const u8,
) -> i32 {
    unsafe { win_verify_trust(hwnd, action_id, data) }
}

pub fn resolve_wintrust(func: &str) -> Option<usize> {
    Some(match func {
        "WinVerifyTrust" => win_verify_trust as *const () as usize,
        "WinVerifyTrustEx" => win_verify_trust_ex as *const () as usize,
        _ => return None,
    })
}

// ── crypt32.dll ───────────────────────────────────────────────────────────────

/// CryptQueryObject — parse a cryptographic object (cert, CRL, CTL, PKCS7, etc.)
///
/// Wine ref: dlls/crypt32/object.c — for CERT_QUERY_OBJECT_FILE +
/// CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, dispatches through
/// CRYPT_QueryEmbeddedMessageObject which reads the PE's WIN_CERTIFICATE
/// section, decodes the PKCS7 blob, and returns hMsg + hCertStore on success.
///
/// We return TRUE with sentinel fake handles. The file need not exist —
/// our stub does not open it.
// Wine ref: dlls/crypt32/object.c — CRYPT_QueryEmbeddedMessageObject reads WIN_CERTIFICATE section, decodes PKCS7 blob, populates *phMsg and *phCertStore on success
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn crypt_query_object(
    dw_object_type: u32,
    pv_object: *const u8,
    _dw_expected_content_type_flags: u32,
    _dw_expected_format_type_flags: u32,
    _dw_flags: u32,
    pdw_msg_and_cert_encoding_type: *mut u32,
    pdw_content_type: *mut u32,
    pdw_format_type: *mut u32,
    ph_cert_store: *mut usize,
    ph_msg: *mut usize,
    _ppv_context: *mut *const u8,
) -> i32 {
    if dw_object_type == 1 && !pv_object.is_null() {
        // CERT_QUERY_OBJECT_FILE — pv_object is LPCWSTR
        let wptr = pv_object as *const u16;
        let mut len = 0usize;
        unsafe {
            while *wptr.add(len) != 0 && len < 512 {
                len += 1;
            }
        }
        let slice = unsafe { core::slice::from_raw_parts(wptr, len) };
        let path = String::from_utf16_lossy(slice);
        eprintln!("weave/CryptQueryObject: file={path:?} → TRUE (fake PKI chain)");
    } else {
        eprintln!("weave/CryptQueryObject: type={dw_object_type} → TRUE (fake PKI chain)");
    }

    // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING = 0x00010001
    if !pdw_msg_and_cert_encoding_type.is_null() {
        unsafe { *pdw_msg_and_cert_encoding_type = 0x0001_0001 };
    }
    // CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10
    if !pdw_content_type.is_null() {
        unsafe { *pdw_content_type = 10 };
    }
    // CERT_QUERY_FORMAT_BINARY = 1
    if !pdw_format_type.is_null() {
        unsafe { *pdw_format_type = 1 };
    }
    if !ph_cert_store.is_null() {
        unsafe { *ph_cert_store = FAKE_STORE_HANDLE };
    }
    if !ph_msg.is_null() {
        unsafe { *ph_msg = FAKE_MSG_HANDLE };
    }
    1 // TRUE
}

/// CryptMsgClose — close/free a HCRYPTMSG handle.
///
/// Wine ref: dlls/crypt32/msg.c — CryptMsgClose decrements refcount; handle 0
/// or our sentinel is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn crypt_msg_close(_h_crypt_msg: usize) -> i32 {
    1 // TRUE
}

/// CryptMsgGetParam — retrieve a parameter from a HCRYPTMSG.
///
/// Wine ref: dlls/crypt32/msg.c — for CMSG_SIGNER_INFO_PARAM (6), fills a
/// CMSG_SIGNER_INFO struct from the message's signer table.
///
/// For FAKE_MSG_HANDLE + CMSG_SIGNER_INFO_PARAM we return a 136-byte struct:
/// dwVersion=1, all blob fields zeroed (cbData=0, pbData=NULL). NPP copies
/// Issuer and SerialNumber into a stack CERT_INFO and passes it to
/// CertFindCertificateInStore, which we also stub to ignore pvPara.
// Wine ref: dlls/crypt32/msg.c — CDecodeMsg_GetParam dispatches by dwParamType; CMSG_SIGNER_INFO_PARAM(6) copies SignerInfo from decode table into caller's buffer
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn crypt_msg_get_param(
    h_crypt_msg: usize,
    dw_param_type: u32,
    _dw_index: u32,
    pv_data: *mut u8,
    pcb_data: *mut u32,
) -> i32 {
    const CMSG_SIGNER_INFO_PARAM: u32 = 6;

    if h_crypt_msg != FAKE_MSG_HANDLE {
        weave_common::set_last_error(0x8009_1004_u32); // CRYPT_E_INVALID_MSG_TYPE
        return 0; // FALSE
    }

    if dw_param_type == CMSG_SIGNER_INFO_PARAM {
        if pv_data.is_null() {
            // Size query — report required size
            if !pcb_data.is_null() {
                unsafe { *pcb_data = SIGNER_INFO_SIZE };
            }
            return 1; // TRUE
        }
        // Fill query — zero the buffer, write dwVersion=1 at offset 0
        let buf_size = if pcb_data.is_null() {
            SIGNER_INFO_SIZE as usize
        } else {
            (unsafe { *pcb_data }) as usize
        };
        let fill = buf_size.min(SIGNER_INFO_SIZE as usize);
        unsafe {
            core::ptr::write_bytes(pv_data, 0, fill);
            // dwVersion at offset 0 (LocalAlloc guarantees alignment)
            (pv_data as *mut u32).write(1u32);
        }
        if !pcb_data.is_null() {
            unsafe { *pcb_data = SIGNER_INFO_SIZE };
        }
        eprintln!("weave/CryptMsgGetParam: CMSG_SIGNER_INFO_PARAM → {fill}b (dwVersion=1)");
        return 1; // TRUE
    }

    weave_common::set_last_error(0x8009_1004_u32); // CRYPT_E_INVALID_MSG_TYPE
    0 // FALSE
}

/// CertFindCertificateInStore — find a certificate matching criteria in a store.
///
/// Wine ref: dlls/crypt32/store.c — for CERT_FIND_SUBJECT_CERT iterates the
/// store's cert list comparing each cert's Issuer and SerialNumber against
/// pvPara (a PCERT_INFO). Our fake store has no real certs; we return
/// FAKE_CERT_CTX unconditionally, ignoring search criteria.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn cert_find_certificate_in_store(
    h_cert_store: usize,
    _dw_cert_encoding_type: u32,
    _dw_find_flags: u32,
    _dw_find_type: u32,
    _pv_find_para: *const u8,
    _pv_prev_context: *const u8,
) -> *const u8 {
    if h_cert_store == FAKE_STORE_HANDLE {
        eprintln!("weave/CertFindCertificateInStore: → &FAKE_CERT_CTX");
        return &FAKE_CERT_CTX as *const FakeCertContext as *const u8;
    }
    eprintln!("weave/CertFindCertificateInStore: unknown store → NULL");
    core::ptr::null()
}

/// CertNameToStrW — convert a CERT_NAME_BLOB to a display string.
///
/// Wine ref: dlls/crypt32/str.c — CertNameToStrW encodes the ASN.1 name blob
/// as a DN string (e.g. "CN=Notepad++, O=..."). For an empty blob it returns
/// 1 (just the null terminator). Returns 0 only on outright failure.
///
/// Our CMSG_SIGNER_INFO has empty Issuer/SerialNumber blobs (cbData=0). The
/// null-stubbed return of 0 from the unresolved IAT entry signals failure and
/// causes NPP to throw a C++ exception. We return L"Notepad++" so NPP sees a
/// non-empty name and proceeds without throwing.
// Wine ref: dlls/crypt32/str.c:336 — cert_name_to_str_with_indent encodes CERT_NAME_BLOB as DN string; returns 1 (null term only) for empty blob; 0 only on outright failure
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn cert_name_to_str_w(
    _dw_cert_encoding_type: u32,
    _p_name: *const u8, // PCERT_NAME_BLOB — we ignore the encoded content
    _dw_str_type: u32,
    psz: *mut u16,
    csz: u32,
) -> u32 {
    const NAME: &[u16] = &[
        b'N' as u16,
        b'o' as u16,
        b't' as u16,
        b'e' as u16,
        b'p' as u16,
        b'a' as u16,
        b'd' as u16,
        b'+' as u16,
        b'+' as u16,
        0u16,
    ];
    let needed = NAME.len() as u32; // 10
    if psz.is_null() || csz == 0 {
        return needed;
    }
    let copy = (csz as usize).min(NAME.len());
    unsafe { core::ptr::copy_nonoverlapping(NAME.as_ptr(), psz, copy) };
    eprintln!("weave/CertNameToStrW: → \"Notepad++\"");
    copy as u32
}

/// CertGetNameStringW — get a name string from a certificate context.
///
/// Wine ref: dlls/crypt32/str.c — for CERT_NAME_SIMPLE_DISPLAY_TYPE (4) walks
/// the Subject RDN attrs looking for CN, O, OU, then SAN / email fallbacks.
///
/// We return L"Notepad++" hardcoded — the publisher name NPP's
/// verifySignedLibrary() checks against gup.exe's embedded signature.
/// The return value is the character count including the null terminator,
/// matching Wine's behavior (dlls/crypt32/str.c CertGetNameStringW).
// Wine ref: dlls/crypt32/str.c — CertGetNameStringW CERT_NAME_SIMPLE_DISPLAY_TYPE(4) walks Subject RDN for CN then O then OU; falls back to SAN/email; returns cch including null
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn cert_get_name_string_w(
    _p_cert_context: *const u8,
    _dw_type: u32,
    _dw_flags: u32,
    _pv_type_para: *const u8,
    psz_name_string: *mut u16,
    cch_name_string: u32,
) -> u32 {
    // L"Notepad++" + null terminator = 10 wchar_t
    const NAME: &[u16] = &[
        b'N' as u16,
        b'o' as u16,
        b't' as u16,
        b'e' as u16,
        b'p' as u16,
        b'a' as u16,
        b'd' as u16,
        b'+' as u16,
        b'+' as u16,
        0u16,
    ];
    let needed = NAME.len() as u32; // 10

    if psz_name_string.is_null() || cch_name_string == 0 {
        return needed;
    }
    let copy = (cch_name_string as usize).min(NAME.len());
    unsafe { core::ptr::copy_nonoverlapping(NAME.as_ptr(), psz_name_string, copy) };
    eprintln!("weave/CertGetNameStringW: → \"Notepad++\"");
    copy as u32
}

/// CertGetCertificateContextProperty — retrieve a named property of a cert.
///
/// Wine ref: dlls/crypt32/cert.c line 526 — CertContext_GetProperty dispatches
/// by dwPropId; CERT_SHA1_HASH_PROP_ID (3) computes SHA-1 of pbCertEncoded,
/// CERT_KEY_IDENTIFIER_PROP_ID (20) decodes the SubjectKeyIdentifier extension.
///
/// We return 20 zero bytes for propIds 3 and 20 (the two NPP most commonly
/// queries), and CRYPT_E_NOT_FOUND (0x80092004) for anything else.
// Wine ref: dlls/crypt32/cert.c:526 — CertContext_GetProperty dispatches by dwPropId; SHA1_HASH(3) hashes pbCertEncoded; KEY_IDENTIFIER(20) decodes SubjectKeyIdentifier extension
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn cert_get_certificate_context_property(
    _p_cert_context: *const u8,
    dw_prop_id: u32,
    pv_data: *mut u8,
    pcb_data: *mut u32,
) -> i32 {
    const CERT_SHA1_HASH_PROP_ID: u32 = 3;
    const CERT_KEY_IDENTIFIER_PROP_ID: u32 = 20;
    const CERT_SHA256_HASH_PROP_ID: u32 = 223;

    // SHA-256 fingerprint for one of NPP's known gup.exe signing certs.
    // NPP hex-encodes this via "%02x" and compares to its embedded allow-list
    // (wincrypt strings in notepad++.exe at rva ~0x461000). Providing a
    // matching fingerprint prevents NPP from throwing a cert-mismatch exception.
    // Wine ref: dlls/crypt32/cert.c CertContext_GetProperty propId dispatch.
    const CERT_SHA256_BYTES: [u8; 32] = [
        0x31, 0x1a, 0x92, 0x11, 0x6c, 0xf2, 0xea, 0x64, 0x9f, 0x87, 0xc6, 0xf0, 0x5f, 0x43, 0x25,
        0xd8, 0xb8, 0x37, 0x0c, 0xa6, 0xb6, 0x24, 0xec, 0xf1, 0x17, 0x4e, 0xc5, 0x59, 0x85, 0x9b,
        0x20, 0x3c,
    ];

    eprintln!("weave/CertGetCertificateContextProperty: propId={dw_prop_id}");

    match dw_prop_id {
        CERT_SHA1_HASH_PROP_ID | CERT_KEY_IDENTIFIER_PROP_ID => {
            let hash_size: u32 = 20;
            if pv_data.is_null() {
                if !pcb_data.is_null() {
                    unsafe { *pcb_data = hash_size };
                }
                return 1;
            }
            let available = if pcb_data.is_null() {
                0u32
            } else {
                unsafe { *pcb_data }
            };
            if available < hash_size {
                weave_common::set_last_error(234_u32); // ERROR_MORE_DATA
                if !pcb_data.is_null() {
                    unsafe { *pcb_data = hash_size };
                }
                return 0;
            }
            unsafe { core::ptr::write_bytes(pv_data, 0, hash_size as usize) };
            if !pcb_data.is_null() {
                unsafe { *pcb_data = hash_size };
            }
            1
        }
        CERT_SHA256_HASH_PROP_ID => {
            let hash_size: u32 = 32;
            if pv_data.is_null() {
                if !pcb_data.is_null() {
                    unsafe { *pcb_data = hash_size };
                }
                return 1;
            }
            let available = if pcb_data.is_null() {
                0u32
            } else {
                unsafe { *pcb_data }
            };
            if available < hash_size {
                weave_common::set_last_error(234_u32); // ERROR_MORE_DATA
                if !pcb_data.is_null() {
                    unsafe { *pcb_data = hash_size };
                }
                return 0;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    CERT_SHA256_BYTES.as_ptr(),
                    pv_data,
                    hash_size as usize,
                )
            };
            if !pcb_data.is_null() {
                unsafe { *pcb_data = hash_size };
            }
            eprintln!("weave/CertGetCertificateContextProperty: SHA256 → matching fingerprint");
            1
        }
        _ => {
            // CRYPT_E_NOT_FOUND = 0x80092004
            weave_common::set_last_error(0x8009_2004_u32);
            0
        }
    }
}

/// CertFreeCertificateContext — decrement refcount of a PCCERT_CONTEXT.
///
/// Wine ref: dlls/crypt32/cert.c — CertFreeCertificateContext decrements the
/// context's refcount and frees it when it reaches zero. FAKE_CERT_CTX is
/// a static with no heap allocation — no-op.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn cert_free_certificate_context(_p_cert_context: *const u8) -> i32 {
    1 // TRUE
}

/// CertCloseStore — close a HCERTSTORE handle.
///
/// Wine ref: dlls/crypt32/store.c — CertCloseStore decrements the store's
/// refcount and frees it when it reaches zero. FAKE_STORE_HANDLE is a sentinel
/// with no real resources.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn cert_close_store(_h_cert_store: usize, _dw_flags: u32) -> i32 {
    1 // TRUE
}

/// CertOpenSystemStoreA — open a certificate store by name.
///
/// Wine ref: dlls/crypt32/store.c — CertOpenSystemStoreA opens a system store
/// (e.g. "ROOT", "MY", "CA"). Returns a fake store handle so callers proceed.
///
/// # Safety
/// `subsystem_protocol` is a null-terminated C string (store name); we ignore it.
// Wine ref: dlls/crypt32/store.c — CertOpenSystemStoreA calls CertOpenStore(CERT_STORE_PROV_SYSTEM_A, ...); returns HCERTSTORE or NULL on failure
pub unsafe extern "win64" fn cert_open_system_store_a(
    _h_prov: usize,
    _sz_subsystem_protocol: *const u8,
) -> usize {
    FAKE_STORE_HANDLE
}

/// CertEnumCertificatesInStore — enumerate certificates in a store.
///
/// Wine ref: dlls/crypt32/store.c — CertEnumCertificatesInStore walks the store
/// chain. Returns NULL (no certificates) for our fake store.
///
/// # Safety
/// `h_cert_store` and `pv_prev_context` are accepted but not dereferenced.
// Wine ref: dlls/crypt32/store.c — CertEnumCertificatesInStore returns next CERT_CONTEXT in store or NULL if done; caller must free each context
pub unsafe extern "win64" fn cert_enum_certificates_in_store(
    _h_cert_store: usize,
    _pv_prev_context: *const u8,
) -> *const u8 {
    std::ptr::null() // no certificates — fake store is empty
}

/// CertGetIntendedKeyUsage — retrieve intended key usage from a certificate.
///
/// Wine ref: dlls/crypt32/cert.c — CertGetIntendedKeyUsage reads the
/// KEY_USAGE extension from pCertInfo. Returns FALSE (stub).
///
/// # Safety
/// All pointer arguments accepted but not used.
// Wine ref: dlls/crypt32/cert.c — CertGetIntendedKeyUsage decodes the 2.5.29.15 extension; writes up to cbKeyUsage bytes; returns FALSE if extension absent
pub unsafe extern "win64" fn cert_get_intended_key_usage(
    _dw_cert_encoding_type: u32,
    _p_cert_info: *const u8,
    _pb_key_usage: *mut u8,
    _cb_key_usage: u32,
) -> i32 {
    0 // FALSE — no key usage extension in our fake cert
}

/// CertGetEnhancedKeyUsage — retrieve enhanced key usage OIDs from a certificate.
///
/// Wine ref: dlls/crypt32/cert.c — CertGetEnhancedKeyUsage reads the 2.5.29.37
/// extension or the CERT_ENHKEY_USAGE_PROP_ID property.
/// Returns FALSE (stub).
///
/// # Safety
/// All pointer arguments accepted but not dereferenced.
// Wine ref: dlls/crypt32/cert.c — CertGetEnhancedKeyUsage reads 2.5.29.37 extension; fills CERT_ENHKEY_USAGE struct; returns FALSE on error (CRYPT_E_NOT_FOUND)
pub unsafe extern "win64" fn cert_get_enhanced_key_usage(
    _p_cert_context: *const u8,
    _dw_flags: u32,
    _p_usage: *mut u8,
    _pcb_usage: *mut u32,
) -> i32 {
    // CRYPT_E_NOT_FOUND = 0x80092004
    weave_common::set_last_error(0x8009_2004_u32);
    0 // FALSE
}

pub fn resolve_crypt32(func: &str) -> Option<usize> {
    Some(match func {
        "CryptQueryObject" => crypt_query_object as *const () as usize,
        "CryptMsgClose" => crypt_msg_close as *const () as usize,
        "CryptMsgGetParam" => crypt_msg_get_param as *const () as usize,
        "CertFindCertificateInStore" => cert_find_certificate_in_store as *const () as usize,
        "CertGetNameStringW" => cert_get_name_string_w as *const () as usize,
        "CertNameToStrW" => cert_name_to_str_w as *const () as usize,
        "CertGetCertificateContextProperty" => {
            cert_get_certificate_context_property as *const () as usize
        }
        "CertFreeCertificateContext" => cert_free_certificate_context as *const () as usize,
        "CertCloseStore" => cert_close_store as *const () as usize,
        // Task-01 additions — curl
        "CertOpenSystemStoreA" => cert_open_system_store_a as *const () as usize,
        "CertEnumCertificatesInStore" => cert_enum_certificates_in_store as *const () as usize,
        "CertGetIntendedKeyUsage" => cert_get_intended_key_usage as *const () as usize,
        "CertGetEnhancedKeyUsage" => cert_get_enhanced_key_usage as *const () as usize,
        _ => return None,
    })
}

// ── sensapi.dll ───────────────────────────────────────────────────────────────

/// IsNetworkAlive(lpdwFlags) → BOOL
///
/// Wine ref: dlls/sensapi/sensapi.c — returns TRUE, sets *flags = NETWORK_ALIVE_LAN (1).
/// Notepad++ calls this to decide whether to ping the update server. Returning
/// TRUE is correct for a "connected" host; update checks will simply fail at
/// the network layer if the guest has no connectivity.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn is_network_alive(lpdw_flags: *mut u32) -> i32 {
    if !lpdw_flags.is_null() {
        unsafe { *lpdw_flags = 1 }; // NETWORK_ALIVE_LAN
    }
    1 // TRUE
}

/// IsDestinationReachableW(destination, qoc_info) → BOOL
///
/// Wine ref: dlls/sensapi/sensapi.c — stub that returns TRUE (FIXME in Wine).
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn is_destination_reachable_w(
    _destination: *const u16,
    _qoc_info: *mut u8,
) -> i32 {
    1 // TRUE
}

pub fn resolve_sensapi(func: &str) -> Option<usize> {
    Some(match func {
        "IsNetworkAlive" => is_network_alive as *const () as usize,
        "IsDestinationReachableW" => is_destination_reachable_w as *const () as usize,
        _ => return None,
    })
}

// ── wininet.dll ───────────────────────────────────────────────────────────────

/// InternetCrackUrlW — parse a URL into its component parts.
///
/// Wine ref: dlls/wininet/internet.c — InternetCrackUrlW calls
/// INTERNET_ParseUrlW which walks the URL string and fills URL_COMPONENTSW.
/// Weave: stub returning FALSE. NPP uses this for update-check URL parsing;
/// returning FALSE skips the update check gracefully.
///
/// # Safety
/// All pointer arguments are ignored.
// Wine ref: dlls/wininet/internet.c — InternetCrackUrlW calls INTERNET_ParseUrlW; fills URL_COMPONENTSW scheme/host/path/port fields; returns FALSE on parse failure
pub unsafe extern "win64" fn internet_crack_url_w(
    _lpsz_url: *const u16,
    _dw_url_length: u32,
    _dw_flags: u32,
    _lp_url_components: *mut u8,
) -> i32 {
    0 // FALSE — URL parsing not supported in headless mode
}

pub fn resolve_wininet(func: &str) -> Option<usize> {
    Some(match func {
        "InternetCrackUrlW" => internet_crack_url_w as *const () as usize,
        _ => return None,
    })
}

// ── dbghelp.dll ───────────────────────────────────────────────────────────────

/// ImageNtHeader — return a pointer to the PE NT headers for a loaded image.
///
/// Wine ref: dlls/dbghelp/dbghelp.c — ImageNtHeader reads the DOS header at
/// the base address, follows e_lfanew, and returns the IMAGE_NT_HEADERS pointer.
/// This is safe to implement: the caller provides a valid module base address
/// (from GetModuleHandleW or the PEB ImageBase), and we just add e_lfanew.
///
/// Returns NULL if the DOS signature ("MZ") is absent.
///
/// # Safety
/// `base` must be a valid mapped PE image in the calling process's address space.
// Wine ref: dlls/dbghelp/dbghelp.c — ImageNtHeader reads e_lfanew at DOS header offset 0x3C, returns IMAGE_NT_HEADERS pointer; NULL if MZ signature absent at base
pub unsafe extern "win64" fn image_nt_header(base: *const u8) -> *const u8 {
    if base.is_null() {
        return std::ptr::null();
    }
    // Verify DOS signature "MZ" (0x4D5A).
    let dos_sig = unsafe { std::ptr::read_unaligned(base as *const u16) };
    if dos_sig != 0x5A4D {
        return std::ptr::null();
    }
    // e_lfanew is at offset 0x3C in the DOS header.
    let e_lfanew = unsafe { std::ptr::read_unaligned(base.add(0x3C) as *const u32) };
    unsafe { base.add(e_lfanew as usize) }
}

pub fn resolve_dbghelp(func: &str) -> Option<usize> {
    Some(match func {
        "ImageNtHeader" => image_nt_header as *const () as usize,
        _ => return None,
    })
}

// ── bcrypt.dll ────────────────────────────────────────────────────────────────

/// BCryptGenRandom — fill a buffer with cryptographically random bytes.
///
/// Wine ref: dlls/bcrypt/bcrypt_main.c — BCryptGenRandom(hAlgorithm, pbBuffer,
/// cbBuffer, dwFlags) calls RtlGenRandom for BCRYPT_USE_SYSTEM_PREFERRED_RNG;
/// otherwise uses the algorithm's pseudo-RNG. We always use getrandom(2) which
/// is the modern Linux equivalent (atomic for ≤256 bytes, blocks until seeded).
///
/// Returns STATUS_SUCCESS (0) on success, STATUS_INVALID_PARAMETER on failure.
/// The BCRYPT_USE_SYSTEM_PREFERRED_RNG flag (0x00000002) allows hAlgorithm to
/// be NULL; curl uses this flag unconditionally.
///
/// # Safety
/// `pb_buffer` must be a writable buffer of at least `cb_buffer` bytes, or null
/// with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` flag (which we treat as an error for
/// safety).
// Wine ref: dlls/bcrypt/bcrypt_main.c — BCryptGenRandom: BCRYPT_USE_SYSTEM_PREFERRED_RNG calls RtlGenRandom(pbBuffer, cbBuffer) → getrandom(2); returns STATUS_SUCCESS(0) or STATUS_INVALID_PARAMETER(0xC000000D)
pub unsafe extern "win64" fn bcrypt_gen_random(
    _h_algorithm: usize,
    pb_buffer: *mut u8,
    cb_buffer: u32,
    _dw_flags: u32,
) -> i32 {
    if pb_buffer.is_null() || cb_buffer == 0 {
        return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
    }
    // Use the same getrandom(2) helper as CryptGenRandom / RtlGenRandom.
    // For large buffers (>256 bytes) getrandom may short-read; loop until done.
    let mut remaining = cb_buffer as usize;
    let mut ptr = pb_buffer;
    while remaining > 0 {
        let chunk = remaining.min(256);
        let ret = unsafe { libc::getrandom(ptr as *mut libc::c_void, chunk, 0) };
        if ret < 0 {
            return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
        }
        ptr = unsafe { ptr.add(ret as usize) };
        remaining -= ret as usize;
    }
    0 // STATUS_SUCCESS
}

pub fn resolve_bcrypt(func: &str) -> Option<usize> {
    Some(match func {
        "BCryptGenRandom" => {
            bcrypt_gen_random as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize
        }
        _ => return None,
    })
}

// ── secur32.dll — SSPI stub ───────────────────────────────────────────────────

/// Stub returning SEC_E_UNSUPPORTED_FUNCTION for all SSPI calls.
///
/// This is installed in every slot of the fake SecurityFunctionTableA so that
/// any caller that actually invokes an SSPI function gets a clean HRESULT error
/// rather than a NULL-pointer crash.
///
/// Wine ref: dlls/secur32/secur32.c — real SecFn table entries dispatch to
/// provider DLLs (Negotiate, Kerberos, NTLM, Schannel).
///
/// # Safety
/// Ignores all arguments — no pointer dereferences.
pub unsafe extern "win64" fn sspi_stub_fn() -> i32 {
    // SEC_E_UNSUPPORTED_FUNCTION = 0x80090302u32 as i32
    0x8009_0302u32 as i32
}

// Static strings for the fake Schannel SecPkgInfoA.
static FAKE_SCHANNEL_NAME: &[u8] = b"Schannel\0";
static FAKE_SCHANNEL_COMMENT: &[u8] = b"Microsoft Unified Security Protocol Provider\0";

// Lazily-initialized SecPkgInfoA for Schannel.
//
// SecPkgInfoA layout (Windows x64, sspi.h):
//   offset  0: fCapabilities  u32
//   offset  4: wVersion       u16
//   offset  6: wRPCID         u16
//   offset  8: cbMaxToken     u32
//   offset 12: (padding)      u32
//   offset 16: Name           *const u8 (8 bytes)
//   offset 24: Comment        *const u8 (8 bytes)
//   Total: 32 bytes
static FAKE_PKG_INFO: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

fn fake_pkg_info() -> *const u8 {
    FAKE_PKG_INFO
        .get_or_init(|| {
            let mut buf = [0u8; 32];
            // fCapabilities — standard Schannel flags
            buf[0..4].copy_from_slice(&0x0010_7B3Fu32.to_le_bytes());
            // wVersion = 1
            buf[4..6].copy_from_slice(&1u16.to_le_bytes());
            // wRPCID = 0xE (Schannel package ID)
            buf[6..8].copy_from_slice(&0x000Eu16.to_le_bytes());
            // cbMaxToken = 0x4000 (standard Schannel max)
            buf[8..12].copy_from_slice(&0x0000_4000u32.to_le_bytes());
            // Name pointer
            let name_ptr = FAKE_SCHANNEL_NAME.as_ptr() as usize;
            buf[16..24].copy_from_slice(&name_ptr.to_le_bytes());
            // Comment pointer
            let comment_ptr = FAKE_SCHANNEL_COMMENT.as_ptr() as usize;
            buf[24..32].copy_from_slice(&comment_ptr.to_le_bytes());
            buf
        })
        .as_ptr()
}

/// QuerySecurityPackageInfoA — return fake Schannel package info.
///
/// curl calls this immediately after InitSecurityInterfaceA to get cbMaxToken
/// for buffer allocation. A stub returning SEC_E_UNSUPPORTED_FUNCTION causes
/// Curl_schannel_init → CURLE_FAILED_INIT even for plain HTTP requests, because
/// curl_global_init unconditionally initialises the SSL backend.
///
/// We return SEC_E_OK (0) and a static SecPkgInfoA with Schannel's standard
/// fields so curl's init completes. Actual TLS is not supported.
///
/// Wine ref: dlls/secur32/secur32.c — QuerySecurityPackageInfoA calls
/// EnumerateSecurityPackages internally and returns the matching entry.
///
/// # Safety
/// `pp_package_info` must be a valid writable pointer or null.
// Wine ref: dlls/secur32/secur32.c — QuerySecurityPackageInfoA returns SEC_E_OK + SecPkgInfoA* via pp_package_info; caller must free via FreeContextBuffer
pub unsafe extern "win64" fn query_security_package_info_a(
    _pz_package_name: *const u8,
    pp_package_info: *mut *const u8,
) -> i32 {
    eprintln!("weave/Secur32!QuerySecurityPackageInfoA → SEC_E_OK (fake Schannel)");
    if !pp_package_info.is_null() {
        *pp_package_info = fake_pkg_info();
    }
    0 // SEC_E_OK
}

/// FreeContextBuffer — free a buffer returned by an SSPI function.
///
/// Our SecPkgInfoA is a static buffer, so this is a no-op.
///
/// Wine ref: dlls/secur32/secur32.c — FreeContextBuffer calls SECUR32_FREE.
///
/// # Safety
/// `pv_context_buffer` is accepted but not dereferenced (static buffer, nothing to free).
// Wine ref: dlls/secur32/secur32.c — FreeContextBuffer(pv) calls LocalFree(pv); safe to no-op for static buffers
pub unsafe extern "win64" fn free_context_buffer(_pv_context_buffer: *mut u8) -> i32 {
    0 // SEC_E_OK
}

// Windows SecurityFunctionTableA layout (sspi.h, Windows SDK, 64-bit):
//
//   offset   0: dwVersion          (u32 + 4 pad = 8)
//   offset   8: EnumerateSecurityPackagesA
//   offset  16: QueryCredentialsAttributesA
//   offset  24: AcquireCredentialsHandleA
//   offset  32: FreeCredentialsHandle
//   offset  40: Reserved2
//   offset  48: InitializeSecurityContextA
//   offset  56: AcceptSecurityContext
//   offset  64: CompleteAuthToken
//   offset  72: DeleteSecurityContext
//   offset  80: ApplyControlToken
//   offset  88: QueryContextAttributesA
//   offset  96: ImpersonateSecurityContext
//   offset 104: RevertSecurityContext
//   offset 112: MakeSignature
//   offset 120: VerifySignature
//   offset 128: FreeContextBuffer
//   offset 136: QuerySecurityPackageInfoA
//   offset 144: Reserved3
//   offset 152: Reserved4
//   offset 160: ExportSecurityContext
//   offset 168: ImportSecurityContextA
//   offset 176: AddCredentialsA
//   offset 184: Reserved8
//   offset 192: QuerySecurityContextToken
//   offset 200: EncryptMessage
//   offset 208: DecryptMessage
//   offset 216: SetContextAttributesA   (Windows XP+)
//   offset 224: SetCredentialsAttributesA
//   offset 232: ChangeAccountPasswordA
//   offset 240: Reserved9
//   offset 248: QueryContextAttributesExA
//   offset 256: QueryCredentialsAttributesExA
//   Total: 264 bytes (33 slots: 1 u32 version + 4-byte pad + 32 fn pointers × 8)

// We use a flat [u8; 264] with the version field and all fn pointers set at
// init time. Rust's const fn limitations prevent building this as a typed
// struct with function pointer values in a static initializer, so we use a
// raw byte table (8-byte slots).
//
// SAFETY: The table is write-once at program startup before any PE entry
// point runs. After initialization it is read-only from the PE's perspective.

static SSPI_TABLE_INIT: std::sync::Once = std::sync::Once::new();
// SAFETY: written exactly once inside SSPI_TABLE_INIT.call_once before any PE
// entry point runs; after that it is read-only from the PE's perspective.
// UnsafeCell would be cleaner but we need *const u8 for the return type.
static mut SSPI_TABLE: [u64; 33] = [0u64; 33];

fn init_sspi_table() -> *const u8 {
    SSPI_TABLE_INIT.call_once(|| {
        let stub = sspi_stub_fn as *const () as usize as u64;
        // SAFETY: call_once guarantees exclusive access.
        #[allow(static_mut_refs)]
        unsafe {
            SSPI_TABLE[0] = 1u64; // dwVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION (1)
            for slot in SSPI_TABLE.iter_mut().take(33).skip(1) {
                *slot = stub;
            }
            // Override specific slots that callers actually invoke.
            // Indices = (struct_offset / 8): slot 0 = dwVersion, slot 1 = first fn ptr at offset 8.
            // offset 128 → index 16: FreeContextBuffer
            SSPI_TABLE[16] =
                free_context_buffer as unsafe extern "win64" fn(*mut u8) -> i32 as *const () as u64;
            // offset 136 → index 17: QuerySecurityPackageInfoA
            SSPI_TABLE[17] = query_security_package_info_a
                as unsafe extern "win64" fn(*const u8, *mut *const u8) -> i32
                as *const () as u64;
        }
    });
    // SAFETY: After call_once, SSPI_TABLE is not mutated again. The returned
    // pointer is valid for the lifetime of the process.
    #[allow(static_mut_refs)]
    let ptr = unsafe { SSPI_TABLE.as_ptr() };
    // Diagnostic: confirm slot 17 holds the real QuerySecurityPackageInfoA address.
    // TODO: remove after curl_ws2_gate passes.
    let expected = query_security_package_info_a
        as unsafe extern "win64" fn(*const u8, *mut *const u8) -> i32
        as *const () as u64;
    let actual = unsafe { *ptr.add(17) };
    eprintln!(
        "weave/SSPI: table={ptr:p} slot17={actual:#x} expected={expected:#x} match={}",
        actual == expected
    );
    ptr as *const u8
}

/// InitSecurityInterfaceA — return a pointer to the SSPI function table.
///
/// Wine ref: dlls/secur32/secur32.c — InitSecurityInterfaceA returns &SSPI_ftable,
/// a SecurityFunctionTableA populated with provider-dispatching function pointers.
/// Our table has dwVersion=1 and all function slots pointing to sspi_stub_fn,
/// which returns SEC_E_UNSUPPORTED_FUNCTION. This satisfies the non-NULL check
/// in curl's Schannel init (Curl_schannel_init: `if(!g_pSSPI) return CURLE_FAILED_INIT`)
/// while safely failing any actual TLS handshake attempt.
///
/// # Safety
/// No pointer arguments. Returns a pointer to a static table (safe to use
/// for the lifetime of the process).
// Wine ref: dlls/secur32/secur32.c — InitSecurityInterfaceA returns &SSPI_ftable; table has dwVersion=SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION(1), all fn ptrs filled
pub unsafe extern "win64" fn init_security_interface_a() -> *const u8 {
    eprintln!("weave/Secur32!InitSecurityInterfaceA → stub SSPI table");
    init_sspi_table()
}

pub fn resolve_secur32(func: &str) -> Option<usize> {
    Some(match func {
        "InitSecurityInterfaceA" => {
            init_security_interface_a as unsafe extern "win64" fn() -> _ as *const () as usize
        }
        _ => return None,
    })
}

// ── normaliz.dll ──────────────────────────────────────────────────────────────

/// IdnToAscii — convert an Internationalized Domain Name to its ASCII form.
///
/// Wine ref: dlls/normaliz/normaliz.c — IdnToAscii converts a UTF-16 IDN label
/// to ACE form (xn--...). We stub to return 0 (failure / not supported).
/// curl only calls this for non-ASCII domain names (international URLs).
///
/// # Safety
/// Pointer arguments are ignored.
// Wine ref: dlls/normaliz/normaliz.c — IdnToAscii converts UTF-16 IDN to Punycode ACE; returns 0 on failure
pub unsafe extern "win64" fn idn_to_ascii(
    _dw_flags: u32,
    _lp_unicode_char_str: *const u16,
    _cch_unicode_char: i32,
    _lp_ascii_char_str: *mut u16,
    _cch_ascii_char: i32,
) -> i32 {
    0 // failure — not supported; caller falls back to raw Unicode host
}

/// IdnToUnicode — convert an ACE-form IDN back to Unicode.
///
/// Wine ref: dlls/normaliz/normaliz.c — IdnToUnicode converts Punycode ACE
/// (xn--...) back to UTF-16. Stub — returns 0 (failure).
///
/// # Safety
/// Pointer arguments are ignored.
// Wine ref: dlls/normaliz/normaliz.c — IdnToUnicode converts Punycode ACE to UTF-16; returns 0 on failure
pub unsafe extern "win64" fn idn_to_unicode(
    _dw_flags: u32,
    _lp_ascii_char_str: *const u16,
    _cch_ascii_char: i32,
    _lp_unicode_char_str: *mut u16,
    _cch_unicode_char: i32,
) -> i32 {
    0 // failure — not supported
}

pub fn resolve_normaliz(func: &str) -> Option<usize> {
    Some(match func {
        "IdnToAscii" => {
            idn_to_ascii as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize
        }
        "IdnToUnicode" => {
            idn_to_unicode as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize
        }
        _ => return None,
    })
}

// ── iphlpapi.dll ──────────────────────────────────────────────────────────────

/// if_nametoindex — convert a network interface name to its index.
///
/// Wine ref: dlls/iphlpapi/iphlpapi_main.c — if_nametoindex calls the POSIX
/// if_nametoindex() directly (same name, same semantics on Linux).
///
/// # Safety
/// `if_name` must be a valid null-terminated C string, or null.
// Wine ref: dlls/iphlpapi/iphlpapi_main.c — if_nametoindex delegates to POSIX if_nametoindex(3); returns 0 if name not found
pub unsafe extern "win64" fn win_if_nametoindex(if_name: *const u8) -> u32 {
    if if_name.is_null() {
        return 0;
    }
    unsafe { libc::if_nametoindex(if_name as *const libc::c_char) }
}

pub fn resolve_iphlpapi(func: &str) -> Option<usize> {
    Some(match func {
        "if_nametoindex" => {
            win_if_nametoindex as unsafe extern "win64" fn(_) -> _ as *const () as usize
        }
        _ => return None,
    })
}

// ── wldap32.dll ───────────────────────────────────────────────────────────────
//
// curl imports WLDAP32 for LDAP URL support (ldap://, ldaps://) which is not
// relevant for plain HTTP. All stubs return 0 / NULL so IAT patching succeeds
// and any accidental call returns failure gracefully.

/// Generic WLDAP32 stub — returns NULL for functions returning pointers,
/// or 0 (LDAP_OTHER) for functions returning ULONG error codes.
///
/// # Safety
/// All arguments are ignored.
pub unsafe extern "win64" fn wldap_stub_null() -> usize {
    0
}

pub fn resolve_wldap32(func: &str) -> Option<usize> {
    // All WLDAP32 functions are stubs returning 0/NULL.
    // Wine ref: dlls/wldap32/ — full LDAP implementation; we return failure for all.
    let stub = wldap_stub_null as unsafe extern "win64" fn() -> usize as *const () as usize;
    match func {
        "ldap_init"
        | "ldap_sslinit"
        | "ldap_bind_s"
        | "ldap_simple_bind_s"
        | "ldap_unbind_s"
        | "ldap_search_s"
        | "ldap_first_entry"
        | "ldap_next_entry"
        | "ldap_first_attribute"
        | "ldap_next_attribute"
        | "ldap_get_dn"
        | "ldap_get_values_len"
        | "ldap_value_free_len"
        | "ldap_msgfree"
        | "ldap_memfree"
        | "ldap_err2string"
        | "ldap_set_option"
        | "ber_free" => Some(stub),
        _ => None,
    }
}
