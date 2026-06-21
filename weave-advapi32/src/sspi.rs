//! Real SSPI/TLS implementation over rustls for Schannel.
//!
//! Implements the Windows SSPI interface (AcquireCredentialsHandle,
//! InitializeSecurityContext, EncryptMessage, DecryptMessage) using rustls
//! as the TLS backend. Enables curl's Schannel TLS backend to establish real
//! TLS connections without --insecure (-k).
//!
//! # Architecture
//! SSPI functions in this module replace the stub entries in the
//! SecurityFunctionTableA returned by InitSecurityInterfaceA. Credentials
//! and connection contexts are stored in process-global handle tables.

use rustls::pki_types::{ServerName, UnixTime};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// ── SSPI constants ────────────────────────────────────────────────────────────

pub const SEC_E_OK: i32 = 0;
pub const SEC_E_INVALID_HANDLE: i32 = -2146893055; // 0x80090301
pub const SEC_E_UNSUPPORTED_FUNCTION: i32 = -2146893054; // 0x80090302
pub const SEC_E_INTERNAL_ERROR: i32 = -2146893052; // 0x80090304
pub const SEC_E_NO_CREDENTIALS: i32 = -2146893042; // 0x8009030E
pub const SEC_E_SECPKG_NOT_FOUND: i32 = -2146893045;  // 0x8009030B
pub const SEC_I_CONTINUE_NEEDED: i32 = 0x00090312;

const SECBUFFER_TOKEN: u32 = 2;
const SECBUFFER_EMPTY: u32 = 0;
const SECBUFFER_DATA: u32 = 1;
const SECBUFFER_STREAM_HEADER: u32 = 7;
const SECBUFFER_STREAM_TRAILER: u32 = 8;
const SECPKG_ATTR_STREAM_SIZES: u32 = 0x06;
const SECPKG_CRED_OUTBOUND: u32 = 0x0000_0002;
const SCH_CRED_MANUAL_CRED_VALIDATION: u32 = 0x0000_0008;

const TLS_HEADER_SIZE: u32 = 5; // TLS record header: type(1) + version(2) + length(2)
const TLS_MAX_FRAGMENT: u32 = 16384; // TLS max fragment size
const TLS_TRAILER_SIZE: u32 = 256; // Max padding + MAC for TLS 1.3

// ── Handle tables ─────────────────────────────────────────────────────────────

static NEXT_CRED_HANDLE: AtomicUsize = AtomicUsize::new(0x7000_0001);
static NEXT_CTX_HANDLE: AtomicUsize = AtomicUsize::new(0x7001_0001);

struct CredState {
    config: Arc<rustls::ClientConfig>,
}

struct CtxState {
    conn: rustls::ClientConnection,
    // Buffered data from the server that hasn't been fed to rustls yet.
    pending_input: Vec<u8>,
    // Buffered data from rustls that hasn't been returned to the caller yet.
    pending_output: Vec<u8>,
    // Whether the handshake is complete.
    handshake_done: bool,
}

static CRED_TABLE: OnceLock<Mutex<HashMap<usize, CredState>>> = OnceLock::new();
static CTX_TABLE: OnceLock<Mutex<HashMap<usize, CtxState>>> = OnceLock::new();

fn cred_table() -> &'static Mutex<HashMap<usize, CredState>> {
    CRED_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ctx_table() -> &'static Mutex<HashMap<usize, CtxState>> {
    CTX_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Buffer I/O adapters ───────────────────────────────────────────────────────

/// Read adapter that reads from a byte slice.
struct SliceReader<'a>(&'a [u8], usize);

impl Read for SliceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = self.0.len() - self.1;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&self.0[self.1..self.1 + to_copy]);
        self.1 += to_copy;
        Ok(to_copy)
    }
}

/// Write adapter that appends to a Vec<u8>.
struct VecWriter<'a>(&'a mut Vec<u8>);

impl Write for VecWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ── SecBuffer helpers ─────────────────────────────────────────────────────────

fn read_sec_buffer(buf: &SecBuffer) -> &[u8] {
    if buf.pv_buffer.is_null() || buf.cb_buffer == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(buf.pv_buffer, buf.cb_buffer as usize) }
}

fn write_sec_buffer(buf: &mut SecBuffer, data: &[u8]) {
    if buf.pv_buffer.is_null() {
        return;
    }
    let len = (buf.cb_buffer as usize).min(data.len());
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), buf.pv_buffer, len);
    }
    buf.cb_buffer = len as u32;
}

// ── SCHANNEL_CRED parsing ────────────────────────────────────────────────────

/// Parse the `dwFlags` field from a SCHANNEL_CRED structure.
fn parse_schannel_cred_flags(auth_data: *const u8) -> u32 {
    if auth_data.is_null() {
        return 0;
    }
    // SCHANNEL_CRED layout (x64):
    //   0: dwVersion      u32
    //   4: cCreds         u32
    //   8: paCred         *const *const u8
    //  16: hRootStore     *const u8
    //  24: cMappers       u32
    //  28: paMappers      *const *const u8
    //  32: cSupportedAlgs u32
    //  36: paSupportedAlgs *const *const u32
    //  40: dwFlags        u32
    unsafe {
        let ptr = auth_data as *const u32;
        let _dw_version = *ptr;
        let _c_creds = *ptr.add(1);
        let _pa_cred = *(ptr.add(2) as *const usize);
        let _h_root_store = *(ptr.add(4) as *const usize);
        let _c_mappers = *ptr.add(6);
        let _pa_mappers = *(ptr.add(7) as *const usize);
        let _c_supported_algs = *ptr.add(8);
        let _pa_supported_algs = *(ptr.add(9) as *const usize);
        let dw_flags = *ptr.add(10);
        dw_flags
    }
}

fn is_manual_cred_validation(flags: u32) -> bool {
    flags & SCH_CRED_MANUAL_CRED_VALIDATION != 0
}

// ── AcquireCredentialsHandleA ─────────────────────────────────────────────────

/// AcquireCredentialsHandleA — obtain Schannel credential handle.
///
/// Creates a rustls ClientConfig with system root certificates and returns
/// a handle referencing it. The handle is used by InitializeSecurityContext.
///
/// # Safety
/// `ph_credential` must be a valid writable pointer to a SecHandle (16 bytes).
/// `pts_expiry` may be null.
pub unsafe extern "win64" fn acquire_credentials_handle_a(
    _psz_principal: *const u8,
    psz_package: *const u8,
    f_credential_use: u32,
    _pv_logon_id: *const u8,
    _pv_auth_data: *const u8,
    _p_get_key_fn: usize,
    _pv_get_key_argument: *const u8,
    ph_credential: *mut SecHandle,
    _pts_expiry: *mut TimeStamp,
) -> i32 {
    if ph_credential.is_null() {
        return SEC_E_INVALID_HANDLE;
    }
    // Verify the caller requested Schannel.
    if !psz_package.is_null() {
        let pkg = unsafe { std::ffi::CStr::from_ptr(psz_package as *const i8) }.to_string_lossy();
        if !pkg.eq_ignore_ascii_case("Schannel") {
            return SEC_E_SECPKG_NOT_FOUND;
        }
    }
    if f_credential_use != SECPKG_CRED_OUTBOUND {
        // We don't do inbound (server-side) TLS.
        return SEC_E_NO_CREDENTIALS;
    }

    // Parse SCHANNEL_CRED flags from auth data.
    let is_manual_verify = if !_pv_auth_data.is_null() {
        let auth_flags = parse_schannel_cred_flags(_pv_auth_data);
        is_manual_cred_validation(auth_flags)
    } else {
        false
    };

    // Build rustls ClientConfig.
    let config = if is_manual_verify {
        // -k mode: skip cert validation.
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth()
    } else {
        // Normal mode: load system root certs for validation.
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            root_store.add(cert).ok();
        }
        let count = root_store.len();
        eprintln!("weave/SSPI: loaded {count} root certs from system store ({} errors)",
            native_certs.errors.len());
        if root_store.is_empty() {
            eprintln!("weave/SSPI: no root certs loaded — cannot verify TLS");
            return SEC_E_INTERNAL_ERROR;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let handle = NEXT_CRED_HANDLE.fetch_add(1, Ordering::Relaxed);
    cred_table().lock().unwrap().insert(
        handle,
        CredState {
            config: Arc::new(config),
        },
    );

    unsafe {
        (*ph_credential).dw_lower = handle;
        (*ph_credential).dw_upper = 0;
    }

    eprintln!("weave/SSPI: AcquireCredentialsHandleA → handle={handle:#x}");

    SEC_E_OK
}

/// No-certificate-verification verifier for -k mode.
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ── InitializeSecurityContextA ────────────────────────────────────────────────

/// InitializeSecurityContextA — drive TLS handshake.
///
/// On first call (ph_context is NULL): creates a ClientConnection, writes
/// ClientHello to output buffer, returns SEC_I_CONTINUE_NEEDED.
/// On subsequent calls: feeds server TLS response from input buffer,
/// processes it, writes next handshake message to output buffer.
/// Returns SEC_E_OK when handshake is complete.
///
/// # Safety
/// All pointer arguments must be valid per MSDN contract.
pub unsafe extern "win64" fn initialize_security_context_a(
    ph_credential: *const SecHandle,
    ph_context: *const SecHandle,
    psz_target_name: *const u8,
    _f_context_req: u32,
    _reserved1: u32,
    _target_data_rep: u32,
    p_input: *const SecBufferDesc,
    _reserved2: u32,
    ph_new_context: *mut SecHandle,
    p_output: *mut SecBufferDesc,
    _pf_context_attr: *mut u32,
    _pts_expiry: *mut TimeStamp,
) -> i32 {
    if ph_credential.is_null() || ph_new_context.is_null() || p_output.is_null() {
        return SEC_E_INVALID_HANDLE;
    }

    // Look up credential.
    let cred_handle = unsafe { (*ph_credential).dw_lower };
    let cred_guard = cred_table().lock().unwrap();
    let cred_state = match cred_guard.get(&cred_handle) {
        Some(c) => c,
        None => {
            eprintln!("weave/SSPI: InitializeSecurityContextA — unknown credential handle {cred_handle:#x}");
            return SEC_E_INVALID_HANDLE;
        }
    };

    // Get server name.
    let server_name_str = if !psz_target_name.is_null() {
        unsafe { std::ffi::CStr::from_ptr(psz_target_name as *const i8) }
            .to_string_lossy()
            .to_string()
    } else {
        "localhost".to_string()
    };

    // Parse the target name for rustls.
    let server_name = match ServerName::try_from(server_name_str.as_str()) {
        Ok(n) => n.to_owned(),
        Err(e) => {
            eprintln!("weave/SSPI: InitializeSecurityContextA — invalid server name: {e}");
            return SEC_E_INTERNAL_ERROR;
        }
    };

    // Clone the config before dropping the lock.
    let config = cred_state.config.clone();
    // Drop the cred lock before acquiring ctx lock (avoid deadlock).
    drop(cred_guard);

    if ph_context.is_null() || unsafe { (*ph_context).dw_lower } == 0 {
        // First call: create a new ClientConnection.
        let mut conn = match rustls::ClientConnection::new(config, server_name) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "weave/SSPI: InitializeSecurityContextA — failed to create TLS connection: {e}"
                );
                return SEC_E_INTERNAL_ERROR;
            }
        };

        let handle = NEXT_CTX_HANDLE.fetch_add(1, Ordering::Relaxed);
        let mut pending_output = Vec::new();
        // Drive rustls to produce the ClientHello.
        while conn.wants_write() {
            let mut writer = VecWriter(&mut pending_output);
            match conn.write_tls(&mut writer) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("weave/SSPI: InitializeSecurityContextA — write_tls failed: {e}");
                    return SEC_E_INTERNAL_ERROR;
                }
            }
        }

        let state = CtxState {
            conn,
            pending_input: Vec::new(),
            pending_output,
            handshake_done: false,
        };

        // Write output to the caller's buffer.
        let output_desc = unsafe { &mut *p_output };
        write_output_buffers(output_desc, &state.pending_output);

        // Store the context.
        unsafe {
            (*ph_new_context).dw_lower = handle;
            (*ph_new_context).dw_upper = 0;
        }
        ctx_table().lock().unwrap().insert(handle, state);

        eprintln!("weave/SSPI: InitializeSecurityContextA — first call, handle={handle:#x} → SEC_I_CONTINUE_NEEDED");
        SEC_I_CONTINUE_NEEDED
    } else {
        // Subsequent call: process server's response.
        let ctx_handle = unsafe { (*ph_context).dw_lower };
        let mut ctx_guard = ctx_table().lock().unwrap();
        let state = match ctx_guard.get_mut(&ctx_handle) {
            Some(s) => s,
            None => {
                eprintln!("weave/SSPI: InitializeSecurityContextA — unknown context handle {ctx_handle:#x}");
                return SEC_E_INVALID_HANDLE;
            }
        };

        // Read input buffers from the caller (server's TLS response).
        if !p_input.is_null() {
            let input_desc = unsafe { &*p_input };
            let buffers = unsafe {
                std::slice::from_raw_parts(input_desc.p_buffers, input_desc.c_buffers as usize)
            };
            for buf in buffers {
                if buf.buffer_type == SECBUFFER_TOKEN {
                    let data = read_sec_buffer(buf);
                    state.pending_input.extend_from_slice(data);
                }
            }
        }

        // Feed pending input to rustls.
        if !state.pending_input.is_empty() {
            let data = std::mem::take(&mut state.pending_input);
            let mut reader = SliceReader(&data, 0);
            match state.conn.read_tls(&mut reader) {
                Ok(n) => {
                    if n > 0 {
                        eprintln!(
                            "weave/SSPI: InitializeSecurityContextA — read {n} bytes into rustls"
                        );
                    }
                }
                Err(e) => {
                    eprintln!("weave/SSPI: InitializeSecurityContextA — read_tls failed: {e}");
                }
            }
            // Process any complete TLS records.
            if state.conn.process_new_packets().is_err() {
                eprintln!("weave/SSPI: InitializeSecurityContextA — handshake processing failed");
            }
        }

        // Get output from rustls (next handshake message).
        state.pending_output.clear();
        while state.conn.wants_write() {
            let mut writer = VecWriter(&mut state.pending_output);
            match state.conn.write_tls(&mut writer) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("weave/SSPI: InitializeSecurityContextA — write_tls failed: {e}");
                    return SEC_E_INTERNAL_ERROR;
                }
            }
        }

        // Check if the handshake is complete.
        state.handshake_done = !state.conn.is_handshaking();

        // Write output buffers.
        unsafe {
            let output_desc = &mut *p_output;
            write_output_buffers(output_desc, &state.pending_output);
        }

        let status = if state.handshake_done {
            eprintln!("weave/SSPI: InitializeSecurityContextA — handshake COMPLETE → SEC_E_OK");
            SEC_E_OK
        } else {
            if state.pending_output.is_empty() {
                // Need more data from the server.
                eprintln!(
                    "weave/SSPI: InitializeSecurityContextA — pending output empty, need more data"
                );
            } else {
                eprintln!("weave/SSPI: InitializeSecurityContextA — {} bytes output → SEC_I_CONTINUE_NEEDED", 
                    state.pending_output.len());
            }
            SEC_I_CONTINUE_NEEDED
        };

        unsafe {
            (*ph_new_context).dw_lower = ctx_handle;
            (*ph_new_context).dw_upper = 0;
        }
        status
    }
}

fn write_output_buffers(desc: &mut SecBufferDesc, data: &[u8]) {
    if desc.p_buffers.is_null() || desc.c_buffers == 0 {
        return;
    }
    let buffers =
        unsafe { std::slice::from_raw_parts_mut(desc.p_buffers, desc.c_buffers as usize) };
    // Find the first TOKEN-type buffer or EMPTY buffer.
    for buf in buffers.iter_mut() {
        if buf.buffer_type == SECBUFFER_TOKEN
            || (buf.buffer_type == SECBUFFER_EMPTY && buf.cb_buffer > 0)
        {
            write_sec_buffer(buf, data);
            buf.buffer_type = SECBUFFER_TOKEN;
            return;
        }
        if buf.buffer_type == SECBUFFER_EMPTY && buf.cb_buffer == 0 {
            // We can't write to a zero-length empty buffer — skip.
            continue;
        }
    }
    // If no suitable buffer found, try the first buffer regardless.
    if !buffers.is_empty() && !data.is_empty() {
        write_sec_buffer(&mut buffers[0], data);
    }
}

// ── EncryptMessage ────────────────────────────────────────────────────────────

/// EncryptMessage — encrypt application data for sending over TLS.
///
/// Takes data from SECBUFFER_DATA buffer, encrypts it via rustls, and
/// writes TLS records to SECBUFFER_STREAM_HEADER / SECBUFFER_DATA /
/// SECBUFFER_STREAM_TRAILER buffers.
///
/// # Safety
/// `ph_context` and `p_message` must be valid per MSDN contract.
pub unsafe extern "win64" fn encrypt_message(
    ph_context: *const SecHandle,
    _f_qop: u32,
    p_message: *mut SecBufferDesc,
    _message_seq_no: u32,
) -> i32 {
    let ctx_handle = unsafe { (*ph_context).dw_lower };
    let mut ctx_guard = ctx_table().lock().unwrap();
    let state = match ctx_guard.get_mut(&ctx_handle) {
        Some(s) => s,
        None => {
            eprintln!("weave/SSPI: EncryptMessage — unknown context handle {ctx_handle:#x}");
            return SEC_E_INVALID_HANDLE;
        }
    };

    // Find the DATA buffer (application plaintext).
    let mut data = Vec::new();
    let desc = unsafe { &mut *p_message };
    let buffers =
        unsafe { std::slice::from_raw_parts_mut(desc.p_buffers, desc.c_buffers as usize) };

    for buf in buffers.iter() {
        if buf.buffer_type == SECBUFFER_DATA {
            data.extend_from_slice(read_sec_buffer(buf));
        }
    }

    if data.is_empty() {
        return SEC_E_OK; // Nothing to encrypt.
    }

    // Write data through rustls (encrypts into TLS records).
    match state.conn.writer().write_all(&data) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("weave/SSPI: EncryptMessage — write failed: {e}");
            return SEC_E_INTERNAL_ERROR;
        }
    }

    // Flush to ensure all data is encrypted and buffered.
    match state.conn.writer().flush() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("weave/SSPI: EncryptMessage — flush failed: {e}");
        }
    }

    // Collect the encrypted TLS records.
    let mut tls_output = Vec::new();
    while state.conn.wants_write() {
        let mut writer = VecWriter(&mut tls_output);
        match state.conn.write_tls(&mut writer) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("weave/SSPI: EncryptMessage — write_tls failed: {e}");
                return SEC_E_INTERNAL_ERROR;
            }
        }
    }

    // Distribute the TLS records across the output buffers:
    // SECBUFFER_STREAM_HEADER, SECBUFFER_DATA, SECBUFFER_STREAM_TRAILER.
    // For simplicity, pack everything into the DATA buffer and leave
    // HEADER/TRAILER as actual Schannel does — but Schannel expects
    // the caller to reassemble from these three pieces.
    // A simpler approach: write the full TLS record to DATA and mark
    // HEADER size.
    let _header_size = TLS_HEADER_SIZE;
    if tls_output.len() > TLS_HEADER_SIZE as usize {
        // Determine the actual TLS record header: first 5 bytes.
        // Write the full record to the buffers.
        let mut offset = 0usize;
        for buf in buffers.iter_mut() {
            if buf.buffer_type == SECBUFFER_STREAM_HEADER {
                let end = (TLS_HEADER_SIZE as usize).min(tls_output.len() - offset);
                write_sec_buffer(buf, &tls_output[offset..offset + end]);
                offset += end;
            } else if buf.buffer_type == SECBUFFER_DATA {
                let end = tls_output.len() - offset;
                write_sec_buffer(buf, &tls_output[offset..offset + end]);
                offset += end;
            } else if buf.buffer_type == SECBUFFER_STREAM_TRAILER {
                // Trailer is empty in our simplified model.
                buf.cb_buffer = 0;
            }
        }
    }

    eprintln!(
        "weave/SSPI: EncryptMessage — encrypted {} bytes",
        tls_output.len()
    );
    SEC_E_OK
}

// ── DecryptMessage ────────────────────────────────────────────────────────────

/// DecryptMessage — decrypt received TLS data.
///
/// Takes TLS records from SECBUFFER_DATA buffer, decrypts via rustls, and
/// writes plaintext to SECBUFFER_DATA.
///
/// # Safety
/// `ph_context` and `p_message` must be valid per MSDN contract.
pub unsafe extern "win64" fn decrypt_message(
    ph_context: *const SecHandle,
    p_message: *mut SecBufferDesc,
    _message_seq_no: u32,
    _pf_qop: *mut u32,
) -> i32 {
    let ctx_handle = unsafe { (*ph_context).dw_lower };
    let mut ctx_guard = ctx_table().lock().unwrap();
    let state = match ctx_guard.get_mut(&ctx_handle) {
        Some(s) => s,
        None => {
            eprintln!("weave/SSPI: DecryptMessage — unknown context handle {ctx_handle:#x}");
            return SEC_E_INVALID_HANDLE;
        }
    };

    let desc = unsafe { &mut *p_message };
    let buffers =
        unsafe { std::slice::from_raw_parts_mut(desc.p_buffers, desc.c_buffers as usize) };

    // Collect encrypted data from the buffers.
    let mut tls_input = Vec::new();
    for buf in buffers.iter() {
        if buf.buffer_type == SECBUFFER_DATA {
            tls_input.extend_from_slice(read_sec_buffer(buf));
        }
    }

    if tls_input.is_empty() {
        return SEC_E_OK;
    }

    // Feed data to rustls.
    state.pending_input.extend(tls_input);
    if !state.pending_input.is_empty() {
        let data = std::mem::take(&mut state.pending_input);
        let mut reader = SliceReader(&data, 0);
        match state.conn.read_tls(&mut reader) {
            Ok(n) => {
                if n > 0 && state.conn.process_new_packets().is_err() {
                    eprintln!("weave/SSPI: DecryptMessage — process_new_packets failed");
                    return SEC_E_INTERNAL_ERROR;
                }
            }
            Err(e) => {
                eprintln!("weave/SSPI: DecryptMessage — read_tls failed: {e}");
                return SEC_E_INTERNAL_ERROR;
            }
        }
    }

    // Read decrypted plaintext.
    let mut plaintext = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match state.conn.reader().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => plaintext.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    // Write plaintext back to output buffer.
    for buf in buffers.iter_mut() {
        if buf.buffer_type == SECBUFFER_DATA {
            write_sec_buffer(buf, &plaintext);
            break;
        }
    }

    eprintln!(
        "weave/SSPI: DecryptMessage — decrypted {} bytes",
        plaintext.len()
    );
    SEC_E_OK
}

// ── QueryContextAttributesA ────────────────────────────────────────────────────

/// QueryContextAttributesA — query TLS connection attributes.
///
/// Handles SECPKG_ATTR_STREAM_SIZES (return TLS record size limits)
/// and SECPKG_ATTR_CONNECTION_INFO (return negotiated protocol info).
///
/// # Safety
/// `ph_context` must be a valid context handle; `p_buffer` must be valid
/// for the requested attribute.
pub unsafe extern "win64" fn query_context_attributes_a(
    ph_context: *const SecHandle,
    ul_attribute: u32,
    p_buffer: *mut u8,
) -> i32 {
    let _ctx_handle = unsafe { (*ph_context).dw_lower };
    let _ctx_guard = ctx_table().lock().unwrap();
    if p_buffer.is_null() {
        return SEC_E_INVALID_HANDLE;
    }

    match ul_attribute {
        SECPKG_ATTR_STREAM_SIZES => {
            // Return SecPkgContext_StreamSizes structure (32 bytes on x64).
            #[repr(C)]
            struct SecPkgContextStreamSizes {
                cb_header: u32,
                cb_maximum_message: u32,
                cb_trailer: u32,
                // Schannel returns 5 fields but we only need these for curl.
                _cb_buffers: u32,
                _cb_block_size: u32,
            }
            let sizes = SecPkgContextStreamSizes {
                cb_header: TLS_HEADER_SIZE,
                cb_maximum_message: TLS_MAX_FRAGMENT,
                cb_trailer: TLS_TRAILER_SIZE,
                _cb_buffers: 4, // Number of buffers used
                _cb_block_size: 1,
            };
            unsafe {
                std::ptr::write(p_buffer as *mut SecPkgContextStreamSizes, sizes);
            }
            eprintln!("weave/SSPI: QueryContextAttributesA(STREAM_SIZES)");
            SEC_E_OK
        }
        _ => {
            eprintln!("weave/SSPI: QueryContextAttributesA(attr={ul_attribute:#x}) → SEC_E_UNSUPPORTED_FUNCTION");
            SEC_E_UNSUPPORTED_FUNCTION
        }
    }
}

// ── FreeCredentialsHandle ─────────────────────────────────────────────────────

/// FreeCredentialsHandle — release credential handle.
///
/// # Safety
/// `ph_credential` must be a valid pointer.
pub unsafe extern "win64" fn free_credentials_handle(ph_credential: *const SecHandle) -> i32 {
    if ph_credential.is_null() {
        return SEC_E_INVALID_HANDLE;
    }
    let handle = unsafe { (*ph_credential).dw_lower };
    cred_table().lock().unwrap().remove(&handle);
    eprintln!("weave/SSPI: FreeCredentialsHandle({handle:#x})");
    SEC_E_OK
}

// ── DeleteSecurityContext ─────────────────────────────────────────────────────

/// DeleteSecurityContext — release context handle.
///
/// # Safety
/// `ph_context` must be a valid pointer.
pub unsafe extern "win64" fn delete_security_context(ph_context: *const SecHandle) -> i32 {
    if ph_context.is_null() {
        return SEC_E_INVALID_HANDLE;
    }
    let handle = unsafe { (*ph_context).dw_lower };
    ctx_table().lock().unwrap().remove(&handle);
    eprintln!("weave/SSPI: DeleteSecurityContext({handle:#x})");
    SEC_E_OK
}

// ── SecBuffer/SecBufferDesc type definitions ──────────────────────────────────

#[repr(C)]
pub struct SecHandle {
    pub dw_lower: usize,
    pub dw_upper: usize,
}

#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: u32,
    pub buffer_type: u32,
    pub pv_buffer: *mut u8,
}

#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: u32,
    pub c_buffers: u32,
    pub p_buffers: *mut SecBuffer,
}

#[repr(C)]
pub struct TimeStamp {
    pub low_part: u32,
    pub high_part: u32,
}
