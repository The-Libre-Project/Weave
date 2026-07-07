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

// ── Existing functions (pre-Signal) ──────────────────────────────────────────

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

/// CertGetNameStringA — retrieve the subject or issuer name (ANSI).
///
/// # Safety
/// `p_cert_context` is accepted but not used; `psz_name_string` may be null.
// Wine ref: dlls/crypt32/cert.c — CertGetNameStringA calls CertGetNameStringW and converts.
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

// ── Signal gap-fill: 23 crypt32 Phase B stubs ────────────────────────────────

/// CertAddCertificateContextToStore — add a certificate context to a store.
///
/// # Safety
/// `p_cert_context` must be a valid certificate context handle; `pp_store_context`
/// must be a valid pointer to a `usize` or null if not needed.
// Wine ref: dlls/crypt32/cert.c — CertAddCertificateContextToStore
pub unsafe extern "win64" fn CertAddCertificateContextToStore(
    _h_store: usize,
    _p_cert_context: usize,
    _dw_add_disposition: u32,
    _pp_store_context: *mut usize,
) -> i32 {
    0
}

/// CertAddEncodedCertificateToStore — add an encoded certificate to a store.
///
/// # Safety
/// `pb_cert_encoded` must point to at least `cb_cert_encoded` readable bytes;
/// `pp_store_context` must be a valid pointer or null.
// Wine ref: dlls/crypt32/cert.c — CertAddEncodedCertificateToStore
pub unsafe extern "win64" fn CertAddEncodedCertificateToStore(
    _h_store: usize,
    _dw_encoding_type: u32,
    _pb_cert_encoded: *const u8,
    _cb_cert_encoded: u32,
    _dw_add_disposition: u32,
    _pp_store_context: *mut usize,
) -> i32 {
    0
}

/// CertAddStoreToCollection — add a certificate store to a collection.
///
/// # Safety
/// Both store handles must be valid (acquired from CertOpenStore or equivalent).
// Wine ref: dlls/crypt32/cert.c — CertAddStoreToCollection
pub unsafe extern "win64" fn CertAddStoreToCollection(
    _h_collection_store: usize,
    _h_sibling_store: usize,
    _dw_update_flag: u32,
    _dw_priority: u32,
) -> i32 {
    0
}

/// CertCompareCertificateName — compare two certificate names.
///
/// # Safety
/// `pb_cert_name` and `pb_cert_name2` must point to valid encoded name blobs.
// Wine ref: dlls/crypt32/cert.c — CertCompareCertificateName
pub unsafe extern "win64" fn CertCompareCertificateName(
    _dw_encoding_type: u32,
    _pb_cert_name: *const u8,
    _pb_cert_name2: *const u8,
) -> i32 {
    0
}

/// CertControlStore — control operations on a certificate store.
///
/// # Safety
/// `pv_control_para` must point to a valid control-parameter structure matching
/// `dw_control_type`, or be null if the operation takes no parameters.
// Wine ref: dlls/crypt32/cert.c — CertControlStore
pub unsafe extern "win64" fn CertControlStore(
    _h_store: usize,
    _dw_flags: u32,
    _dw_control_type: u32,
    _pv_control_para: *const u8,
) -> i32 {
    0
}

/// CertFindCertificateInStore — find a certificate in a store.
///
/// # Safety
/// `pv_find_para` must point to valid data matching `dw_find_type`;
/// `p_prev_cert_context` must be a valid context handle or null for first call.
// Wine ref: dlls/crypt32/cert.c — CertFindCertificateInStore
pub unsafe extern "win64" fn CertFindCertificateInStore(
    _h_store: usize,
    _dw_encoding_type: u32,
    _dw_find_flags: u32,
    _dw_find_type: u32,
    _pv_find_para: *const u8,
    _p_prev_cert_context: usize,
) -> usize {
    0
}

/// CertFindChainInStore — find a certificate chain in a store.
///
/// # Safety
/// `pv_find_para` must point to valid data matching `dw_find_type`;
/// `p_prev_chain_context` must be a valid chain handle or null.
// Wine ref: dlls/crypt32/cert.c — CertFindChainInStore
pub unsafe extern "win64" fn CertFindChainInStore(
    _h_store: usize,
    _dw_encoding_type: u32,
    _dw_find_flags: u32,
    _dw_find_type: u32,
    _pv_find_para: *const u8,
    _p_prev_chain_context: usize,
) -> usize {
    0
}

/// CertFreeCertificateChain — free a certificate chain context.
///
/// # Safety
/// `p_chain_context` must be a valid chain context handle previously obtained
/// from CertGetCertificateChain or CertFindChainInStore, or null (no-op).
// Wine ref: dlls/crypt32/cert.c — CertFreeCertificateChain
pub unsafe extern "win64" fn CertFreeCertificateChain(_p_chain_context: usize) -> i32 {
    1
}

/// CertFreeCertificateChainEngine — free a certificate chain engine.
/// Phase A stub — no-op.
// Wine ref: dlls/crypt32/cert.c — CertFreeCertificateChainEngine
pub unsafe extern "win64" fn CertFreeCertificateChainEngine(_h_chain_engine: usize) {}

/// PFXImportCertStore — import a PFX blob as a certificate store.
/// Phase A stub — returns NULL (store not imported).
// Wine ref: dlls/crypt32/cert.c — PFXImportCertStore
pub unsafe extern "win64" fn PFXImportCertStore(
    _p_pfx: *const u8,
    _sz_password: *const u16,
    _dw_flags: u32,
) -> usize {
    0
}

/// CryptDecodeObjectEx — decode a cryptographic object from BER/DER encoding.
/// Phase A stub — returns FALSE.
// Wine ref: dlls/crypt32/encode.c — CryptDecodeObjectEx
pub unsafe extern "win64" fn CryptDecodeObjectEx(
    _dw_cert_encoding: u32,
    _lpsz_struct_type: *const u8,
    _pb_encoded: *const u8,
    _cb_encoded: u32,
    _dw_flags: u32,
    _p_decode_para: *const u8,
    _pv_decoded: *mut u8,
    _pcb_decoded: *mut u32,
) -> i32 {
    0
}

/// CertFindExtension — find an extension in a CTL or cert by OID.
/// Phase A stub — returns NULL (extension not found).
// Wine ref: dlls/crypt32/cert.c — CertFindExtension
pub unsafe extern "win64" fn CertFindExtension(
    _psz_obj_id: *const u8,
    _c_extensions: u32,
    _rg_extensions: *const u8,
) -> usize {
    0
}

/// CertCreateCertificateChainEngine — create a certificate chain engine.
/// Phase A stub — returns FALSE (engine not created).
// Wine ref: dlls/crypt32/cert.c — CertCreateCertificateChainEngine
pub unsafe extern "win64" fn CertCreateCertificateChainEngine(
    _p_config: *const u8,
    _ph_chain_engine: *mut usize,
) -> i32 {
    0
}

/// CertGetCertificateChain — build a certificate chain context.
///
/// # Safety
/// `p_cert_context` must be a valid certificate context; `p_time` must point to
/// a valid `FILETIME` or be null; `p_chain_para` must point to a valid
/// `CERT_CHAIN_PARA` or be null; `pp_chain_context` must be a valid pointer
/// to receive the chain handle.
// Wine ref: dlls/crypt32/cert.c — CertGetCertificateChain
pub unsafe extern "win64" fn CertGetCertificateChain(
    _h_chain_engine: usize,
    _p_cert_context: usize,
    _p_time: *const u8,
    _h_additional_store: usize,
    _p_chain_para: *const u8,
    _dw_flags: u32,
    _pv_reserved: *const u8,
    _pp_chain_context: *mut usize,
) -> i32 {
    0
}

/// CertGetCertificateContextProperty — get a property from a certificate context.
///
/// # Safety
/// `p_cert_context` must be a valid certificate context; `pv_data` must point
/// to a buffer of size `*pcb_data` or be null to query size; `pcb_data` must
/// be a valid pointer.
// Wine ref: dlls/crypt32/cert.c — CertGetCertificateContextProperty
pub unsafe extern "win64" fn CertGetCertificateContextProperty(
    _p_cert_context: usize,
    _dw_prop_id: u32,
    _pv_data: *mut u8,
    _pcb_data: *mut u32,
) -> i32 {
    0
}

/// CertGetNameStringW — retrieve subject or issuer name from cert (Wide).
///
/// # Safety
/// `p_cert_context` must be a valid certificate context; `pv_type_para` must
/// point to valid data if non-null; `psz_name_string` must point to a buffer
/// of at least `cch_name_string` wide characters, or be null.
// Wine ref: dlls/crypt32/cert.c — CertGetNameStringW
pub unsafe extern "win64" fn CertGetNameStringW(
    _p_cert_context: usize,
    _dw_type: u32,
    _dw_flags: u32,
    _pv_type_para: *const u8,
    _psz_name_string: *mut u16,
    _cch_name_string: u32,
) -> u32 {
    0
}

/// CertOpenStore — open a certificate store (extended).
///
/// # Safety
/// `lpsz_store_provider` must be a valid null-terminated string or well-known
/// atom; `pv_para` must point to provider-specific data or be null.
// Wine ref: dlls/crypt32/cert.c — CertOpenStore
pub unsafe extern "win64" fn CertOpenStore(
    _lpsz_store_provider: *const u8,
    _dw_encoding_type: u32,
    _h_crypto_prov: usize,
    _dw_flags: u32,
    _pv_para: *const u8,
) -> usize {
    0
}

/// CertOpenSystemStoreW — open a system certificate store by name (Wide).
///
/// # Safety
/// `sz_subsystem_protocol` must be a valid null-terminated wide string.
// Wine ref: dlls/crypt32/cert.c — CertOpenSystemStoreW delegates to CertOpenStore
pub unsafe extern "win64" fn CertOpenSystemStoreW(
    _hprov: usize,
    _sz_subsystem_protocol: *const u16,
) -> usize {
    0
}

/// CertVerifyTimeValidity — verify certificate time validity.
///
/// # Safety
/// `p_time_info` must point to a valid `FILETIME` or be null (use current time);
/// `p_cert_info` must point to a valid `CERT_INFO` structure.
// Wine ref: dlls/crypt32/cert.c — CertVerifyTimeValidity
pub unsafe extern "win64" fn CertVerifyTimeValidity(
    _p_time_info: *const u8,
    _p_cert_info: *const u8,
) -> i32 {
    0
}

/// CryptAcquireCertificatePrivateKey — acquire private key for a certificate.
///
/// # Safety
/// `p_cert` must be a valid certificate context; `ph_crypt_prov_or_ncrypt_key`,
/// `pdw_key_spec`, and `pf_caller_free_prov` must be valid output pointers.
// Wine ref: dlls/crypt32/crypt.c — CryptAcquireCertificatePrivateKey
pub unsafe extern "win64" fn CryptAcquireCertificatePrivateKey(
    _p_cert: usize,
    _dw_flags: u32,
    _pv_parameters: *const u8,
    _ph_crypt_prov_or_ncrypt_key: *mut usize,
    _pdw_key_spec: *mut u32,
    _pf_caller_free_prov: *mut i32,
) -> i32 {
    0
}

/// CryptMsgClose — close a cryptographic message handle.
///
/// # Safety
/// `h_crypt_msg` must be a valid cryptographic message handle or 0 (no-op).
// Wine ref: dlls/crypt32/crypt.c — CryptMsgClose
pub unsafe extern "win64" fn CryptMsgClose(_h_crypt_msg: usize) -> i32 {
    1
}

/// CryptMsgGetParam — get a parameter from a cryptographic message.
///
/// # Safety
/// `h_crypt_msg` must be a valid cryptographic message handle; `pv_data` must
/// point to a buffer of size `*pcb_data` or be null to query size; `pcb_data`
/// must be a valid pointer.
// Wine ref: dlls/crypt32/crypt.c — CryptMsgGetParam
pub unsafe extern "win64" fn CryptMsgGetParam(
    _h_crypt_msg: usize,
    _dw_param_type: u32,
    _dw_index: u32,
    _pv_data: *mut u8,
    _pcb_data: *mut u32,
) -> i32 {
    0
}

/// CryptProtectData — protect (encrypt) data via DPAPI.
///
/// # Safety
/// `p_data_in` must point to a valid `DATA_BLOB`; `sz_data_descr` must be a
/// valid null-terminated wide string or null; `p_optional_entropy` must point
/// to a valid `DATA_BLOB` or null; `p_prompt_struct` must point to a valid
/// `CRYPTPROTECT_PROMPTSTRUCT` or null; `p_data_out` must be a valid pointer
/// to a `DATA_BLOB` that will receive the output.
// Wine ref: dlls/crypt32/crypt.c — CryptProtectData (DPAPI)
pub unsafe extern "win64" fn CryptProtectData(
    _p_data_in: *const u8,
    _sz_data_descr: *const u16,
    _p_optional_entropy: *const u8,
    _pv_reserved: usize,
    _p_prompt_struct: *const u8,
    _dw_flags: u32,
    _p_data_out: *mut u8,
) -> i32 {
    0
}

/// CryptProtectMemory — protect memory with a session key.
///
/// # Safety
/// `p_data` must point to a readable/writable buffer of at least `cb_data` bytes.
// Wine ref: dlls/crypt32/crypt.c — CryptProtectMemory (DPAPI)
pub unsafe extern "win64" fn CryptProtectMemory(
    _p_data: *mut u8,
    _cb_data: u32,
    _dw_flags: u32,
) -> i32 {
    1
}

/// CryptQueryObject — query a certificate object (file, blob, etc.).
///
/// # Safety
/// `pv_object` must point to valid data per `dw_object_type`; all output pointer
/// parameters (`pdw_msg_and_cert_encoding`, `pdw_content_type`, `pdw_format_type`,
/// `ph_cert_store`, `ph_msg`, `pv_context`) must be valid or null if not needed.
// Wine ref: dlls/crypt32/crypt.c — CryptQueryObject
pub unsafe extern "win64" fn CryptQueryObject(
    _dw_object_type: u32,
    _pv_object: *const u8,
    _dw_expected_content_type_flags: u32,
    _dw_expected_format_type_flags: u32,
    _dw_flags: u32,
    _pdw_msg_and_cert_encoding: *mut u32,
    _pdw_content_type: *mut u32,
    _pdw_format_type: *mut u32,
    _ph_cert_store: *mut usize,
    _ph_msg: *mut usize,
    _pv_context: *mut *const u8,
) -> i32 {
    0
}

/// CryptUnprotectData — unprotect (decrypt) data via DPAPI.
///
/// # Safety
/// `p_data_in` must point to a valid `DATA_BLOB`; `ppsz_data_descr` must be a
/// valid pointer to receive a wide string or null; `p_optional_entropy` must
/// point to a valid `DATA_BLOB` or null; `p_prompt_struct` must point to a
/// valid `CRYPTPROTECT_PROMPTSTRUCT` or null; `p_data_out` must be a valid
/// pointer to a `DATA_BLOB` that will receive the output.
// Wine ref: dlls/crypt32/crypt.c — CryptUnprotectData (DPAPI)
pub unsafe extern "win64" fn CryptUnprotectData(
    _p_data_in: *const u8,
    _ppsz_data_descr: *mut *mut u16,
    _p_optional_entropy: *const u8,
    _pv_reserved: usize,
    _p_prompt_struct: *const u8,
    _dw_flags: u32,
    _p_data_out: *mut u8,
) -> i32 {
    0
}

/// CryptUnprotectMemory — unprotect memory previously protected.
///
/// # Safety
/// `p_data` must point to a readable/writable buffer of at least `cb_data` bytes.
// Wine ref: dlls/crypt32/crypt.c — CryptUnprotectMemory (DPAPI)
pub unsafe extern "win64" fn CryptUnprotectMemory(
    _p_data: *mut u8,
    _cb_data: u32,
    _dw_flags: u32,
) -> i32 {
    1
}

/// CryptVerifyCertificateSignatureEx — verify a certificate signature.
///
/// # Safety
/// `pv_aux_info` must point to a valid auxiliary info structure or be null;
/// `pv_reserved` must be null.
// Wine ref: dlls/crypt32/crypt.c — CryptVerifyCertificateSignatureEx
pub unsafe extern "win64" fn CryptVerifyCertificateSignatureEx(
    _h_crypto_prov: usize,
    _dw_encoding_type: u32,
    _dw_flags: u32,
    _pv_aux_info: *const u8,
    _pv_reserved: *const u8,
) -> i32 {
    0
}

/// CertGetSubjectCertificateFromStore — locate a subject certificate in a store.
///
/// # Safety
/// `p_cert_id` must be a valid pointer to a CERT_ID struct.
// Wine ref: dlls/crypt32/cert.c — CertGetSubjectCertificateFromStore
pub unsafe extern "win64" fn CertGetSubjectCertificateFromStore(
    _h_cert_store: usize,
    _dw_cert_encoding_type: u32,
    _p_cert_id: usize,
) -> usize {
    0 // NULL — no matching certificate
}

/// CryptStringToBinaryW — decode a string (base64, hex, etc.) to binary.
///
/// # Safety
/// `psz_string` must be a valid wide string pointer; `pb_binary` must be a valid
/// buffer or null for size query; `pcb_binary` must be valid if non-null.
// Wine ref: dlls/crypt32/crypt.c — CryptStringToBinaryW
pub unsafe extern "win64" fn CryptStringToBinaryW(
    _psz_string: *const u16,
    _cch_string: u32,
    _dw_flags: u32,
    _pb_binary: *mut u8,
    _pcb_binary: *mut u32,
    _pdw_skip: *mut u32,
    _pdw_flags: *mut u32,
) -> i32 {
    0 // FALSE — decode failed
}

/// CertCreateCertificateContext — create a certificate context from encoded bytes.
///
/// # Safety
/// `pb_cert_encoded` must point to at least `cb_cert_encoded` valid bytes.
// Wine ref: dlls/crypt32/cert.c — CertCreateCertificateContext
pub unsafe extern "win64" fn CertCreateCertificateContext(
    _dw_cert_encoding_type: u32,
    _pb_cert_encoded: *const u8,
    _cb_cert_encoded: u32,
) -> usize {
    0 // NULL — failed to create context
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Resolve a crypt32.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("crypt32.dll") {
        return None;
    }
    match func {
        // Original stubs (pre-Signal)
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
        // Signal gap-fill: 23 crypt32 Phase A stubs
        "CertAddCertificateContextToStore" => Some(
            CertAddCertificateContextToStore as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "CertAddEncodedCertificateToStore" => Some(
            CertAddEncodedCertificateToStore as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CertAddStoreToCollection" => Some(
            CertAddStoreToCollection as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CertCompareCertificateName" => Some(
            CertCompareCertificateName as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "CertControlStore" => Some(
            CertControlStore as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "CertFindCertificateInStore" => Some(
            CertFindCertificateInStore as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CertFindChainInStore" => Some(
            CertFindChainInStore as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CertFreeCertificateChain" => {
            Some(CertFreeCertificateChain as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CertGetCertificateChain" => Some(
            CertGetCertificateChain as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CertGetCertificateContextProperty" => Some(
            CertGetCertificateContextProperty as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "CertGetNameStringW" => Some(
            CertGetNameStringW as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CertOpenStore" => Some(
            CertOpenStore as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "CertOpenSystemStoreW" => {
            Some(CertOpenSystemStoreW as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CertVerifyTimeValidity" => Some(
            CertVerifyTimeValidity as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "CryptAcquireCertificatePrivateKey" => Some(
            CryptAcquireCertificatePrivateKey as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CryptMsgClose" => Some(CryptMsgClose as *const () as usize),
        "CryptMsgGetParam" => Some(
            CryptMsgGetParam as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "CryptProtectData" => Some(
            CryptProtectData as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CryptProtectMemory" => {
            Some(CryptProtectMemory as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CryptQueryObject" => Some(
            CryptQueryObject as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CryptUnprotectData" => Some(
            CryptUnprotectData as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CryptUnprotectMemory" => Some(
            CryptUnprotectMemory as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CryptVerifyCertificateSignatureEx" => Some(
            CryptVerifyCertificateSignatureEx as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CertGetSubjectCertificateFromStore" => Some(
            CertGetSubjectCertificateFromStore as unsafe extern "win64" fn(_, _, _) -> _
                as *const () as usize,
        ),
        "CryptStringToBinaryW" => Some(
            CryptStringToBinaryW as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CertCreateCertificateContext" => Some(
            CertCreateCertificateContext as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "CertCreateCertificateChainEngine" => Some(
            CertCreateCertificateChainEngine as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "CertFindExtension" => {
            Some(CertFindExtension as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CertFreeCertificateChainEngine" => Some(
            CertFreeCertificateChainEngine as unsafe extern "win64" fn(_) -> _ as *const ()
                as usize,
        ),
        "CryptDecodeObjectEx" => Some(
            CryptDecodeObjectEx as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "PFXImportCertStore" => {
            Some(PFXImportCertStore as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::resolve;

    #[test]
    fn resolve_original_stubs() {
        let funcs = [
            "CertCloseStore",
            "CertEnumCertificatesInStore",
            "CertFreeCertificateContext",
            "CertGetEnhancedKeyUsage",
            "CertGetIntendedKeyUsage",
            "CertOpenSystemStoreA",
            "CertGetNameStringA",
        ];
        for f in &funcs {
            assert!(resolve("crypt32.dll", f).is_some(), "missing {f}");
        }
    }

    #[test]
    fn resolve_signal_gap_fill_stubs() {
        let funcs = [
            "CertAddCertificateContextToStore",
            "CertAddEncodedCertificateToStore",
            "CertAddStoreToCollection",
            "CertCompareCertificateName",
            "CertControlStore",
            "CertFindCertificateInStore",
            "CertFindChainInStore",
            "CertFreeCertificateChain",
            "CertGetCertificateChain",
            "CertGetCertificateContextProperty",
            "CertGetNameStringW",
            "CertOpenStore",
            "CertOpenSystemStoreW",
            "CertVerifyTimeValidity",
            "CryptAcquireCertificatePrivateKey",
            "CryptMsgClose",
            "CryptMsgGetParam",
            "CryptProtectData",
            "CryptProtectMemory",
            "CryptQueryObject",
            "CryptUnprotectData",
            "CryptUnprotectMemory",
            "CryptVerifyCertificateSignatureEx",
            "CertGetSubjectCertificateFromStore",
            "CryptStringToBinaryW",
            "CertCreateCertificateContext",
        ];
        for f in &funcs {
            assert!(resolve("crypt32.dll", f).is_some(), "missing {f}");
        }
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("kernel32.dll", "CertCloseStore").is_none());
        assert!(resolve("crypt32.dll", "__nonexistent__").is_none());
    }
}
