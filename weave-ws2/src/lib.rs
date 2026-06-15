//! ws2_32.dll / wsock32.dll stubs for Weave — Winsock2 networking.
//!
//! Maps Windows Winsock2 functions to Linux POSIX socket calls via libc.
//! Handles SOCKET ↔ fd conversion, AF_INET6 address family translation,
//! fd_set layout differences, timeval size differences, and socket option
//! level/name remapping.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use weave_core::handles;

// ── POSIX functions not exposed by the libc crate on all host platforms ──────
// inet_ntop is available on Linux (our target) but not always through libc crate
// on macOS (build host). Declare it directly so cargo check passes on macOS.
extern "C" {
    fn inet_ntop(
        af: libc::c_int,
        src: *const libc::c_void,
        dst: *mut libc::c_char,
        size: libc::socklen_t,
    ) -> *const libc::c_char;
    fn inet_pton(af: libc::c_int, src: *const libc::c_char, dst: *mut libc::c_void) -> libc::c_int;
}

// ── Constants ────────────────────────────────────────────────────────────────

/// `INVALID_SOCKET` on Win64.
pub const INVALID_SOCKET: usize = usize::MAX;

/// `SOCKET_ERROR` — returned by most Winsock functions on failure.
pub const SOCKET_ERROR: i32 = -1;

// Address family translation (Windows ↔ Linux).
// AF_UNSPEC (0) and AF_INET (2) are identical on both platforms.
// AF_INET6 differs: 23 on Windows, 10 on Linux.
const AF_INET6_WIN: i32 = 23;
const AF_INET6_LINUX: i32 = 10;

// ioctlsocket command codes (Windows values).
const FIONBIO_WIN: u32 = 0x8004667E;

// Socket option level remapping.
const SOL_SOCKET_WIN: i32 = 0xFFFF;
const SOL_SOCKET_LINUX: i32 = 1;

// SOL_SOCKET option name remapping (Windows → Linux).
const SO_REUSEADDR_WIN: i32 = 0x0004;
const SO_REUSEADDR_LINUX: i32 = 2;
const SO_KEEPALIVE_WIN: i32 = 0x0008;
const SO_KEEPALIVE_LINUX: i32 = 9;
const SO_SNDBUF_WIN: i32 = 0x1001;
const SO_SNDBUF_LINUX: i32 = 7;
const SO_RCVBUF_WIN: i32 = 0x1002;
const SO_RCVBUF_LINUX: i32 = 8;
// SO_EXCLUSIVEADDRUSE: Windows-only option defined as ~SO_REUSEADDR = 0xFFFFFFFB = -5 (i32).
// Wine ref: dlls/ws2_32/socket.c — SO_EXCLUSIVEADDRUSE is silently ignored on Wine/Linux
// because Linux sockets are exclusive by default (no SO_REUSEADDR = exclusive ownership).
// Returning 0 without calling setsockopt is the correct no-op translation.
const SO_EXCLUSIVEADDRUSE_WIN: i32 = -5; // = ~SO_REUSEADDR_WIN = (int)(~0x0004)

// Windows fd_set layout: count(u32) + padding(u32) + SOCKET[FD_SETSIZE].
// FD_SETSIZE is 64 on Windows.
const WIN_FD_SETSIZE: usize = 64;

/// Whether WSAStartup has been called.
static WSA_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Map from socket fd (as usize) → (event_handle, network_events_mask).
/// Populated by WSAEventSelect. Queried by WSAWaitForMultipleEvents and
/// WSAEnumNetworkEvents to poll the real socket fd.
static SOCKET_EVENT_MAP: Mutex<Option<HashMap<usize, (usize, u32)>>> = Mutex::new(None);

fn socket_event_map() -> std::sync::MutexGuard<'static, Option<HashMap<usize, (usize, u32)>>> {
    let mut g = SOCKET_EVENT_MAP.lock().unwrap_or_else(|p| p.into_inner());
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    g
}

// ── Thread-local Winsock error ───────────────────────────────────────────────

thread_local! {
    static LAST_WSA_ERROR: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

fn set_last_error(err: i32) {
    LAST_WSA_ERROR.with(|c| c.set(err));
}

fn save_errno() {
    let e = unsafe { *libc::__errno_location() };
    set_last_error(errno_to_wsa(e));
}

fn errno_to_wsa(e: i32) -> i32 {
    // Wine ref: dlls/ws2_32/socket.c — wsaErrno() mapping
    // EINPROGRESS on non-blocking connect → WSAEWOULDBLOCK (10035), not WSAEINPROGRESS (10036).
    // Windows returns WSAEWOULDBLOCK for non-blocking connect(); PuTTY/plink checks exactly 10035.
    match e {
        libc::EINPROGRESS => 10035, // WSAEWOULDBLOCK (non-blocking connect in progress)
        libc::EWOULDBLOCK => 10035, // WSAEWOULDBLOCK
        libc::ECONNREFUSED => 10061, // WSAECONNREFUSED
        libc::ECONNRESET => 10054,  // WSAECONNRESET
        libc::ECONNABORTED => 10053, // WSAECONNABORTED
        libc::ETIMEDOUT => 10060,   // WSAETIMEDOUT
        libc::EHOSTUNREACH => 10065, // WSAEHOSTUNREACH
        libc::ENETUNREACH => 10051, // WSAENETUNREACH
        libc::EADDRINUSE => 10048,  // WSAEADDRINUSE
        libc::ENOBUFS => 10055,     // WSAENOBUFS
        libc::EAFNOSUPPORT => 10047, // WSAEAFNOSUPPORT
        libc::ENOTCONN => 10057,    // WSAENOTCONN
        libc::EMSGSIZE => 10040,    // WSAEMSGSIZE
        libc::EOPNOTSUPP => 10045,  // WSAEOPNOTSUPP
        libc::ENOTSOCK => 10038,    // WSAENOTSOCK
        libc::EBADF => 10009,       // WSAEBADF
        libc::EFAULT => 10014,      // WSAEFAULT
        libc::EINVAL => 10022,      // WSAEINVAL
        libc::EACCES => 10013,      // WSAEACCES
        libc::ENOMEM => 10055,      // WSAENOBUFS (closest match)
        libc::EPIPE => 10054,       // WSAECONNRESET (broken pipe = connection reset)
        libc::EPROTO => 10004,      // WSAEPROTOTYPE
        libc::EPROTOTYPE => 10041,  // WSAEPROTOTYPE
        libc::ENOPROTOOPT => 10042, // WSAENOPROTOOPT
        _ => e,                     // pass through unknown errnos as-is
    }
}

// ── Address family translation ───────────────────────────────────────────────

fn af_win_to_linux(af: i32) -> i32 {
    if af == AF_INET6_WIN {
        AF_INET6_LINUX
    } else {
        af
    }
}

fn af_linux_to_win(af: i32) -> i32 {
    if af == AF_INET6_LINUX {
        AF_INET6_WIN
    } else {
        af
    }
}

// ── Socket option translation ────────────────────────────────────────────────

fn translate_sockopt_level(level: i32) -> i32 {
    if level == SOL_SOCKET_WIN {
        SOL_SOCKET_LINUX
    } else {
        level
    }
}

fn translate_sockopt_name(win_level: i32, name: i32) -> i32 {
    if win_level == SOL_SOCKET_WIN {
        match name {
            SO_REUSEADDR_WIN => SO_REUSEADDR_LINUX,
            SO_KEEPALIVE_WIN => SO_KEEPALIVE_LINUX,
            SO_SNDBUF_WIN => SO_SNDBUF_LINUX,
            SO_RCVBUF_WIN => SO_RCVBUF_LINUX,
            other => other,
        }
    } else {
        name
    }
}

// ── sockaddr family byte patching ────────────────────────────────────────────

/// Copy a sockaddr buffer and translate sa_family from Windows to Linux.
unsafe fn copy_sockaddr_win_to_linux(src: *const u8, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
    if len >= 2 {
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        let linux_family = af_win_to_linux(family as i32) as u16;
        buf[0..2].copy_from_slice(&linux_family.to_ne_bytes());
    }
    buf
}

/// Patch sa_family in a sockaddr buffer from Linux to Windows, in place.
unsafe fn patch_sockaddr_linux_to_win(buf: *mut u8, len: usize) {
    if len >= 2 {
        let family = u16::from_ne_bytes([*buf, *buf.add(1)]);
        let win_family = af_linux_to_win(family as i32) as u16;
        let bytes = win_family.to_ne_bytes();
        *buf = bytes[0];
        *buf.add(1) = bytes[1];
    }
}

// ── Windows fd_set ↔ Linux fd_set translation ────────────────────────────────

/// Read a Windows fd_set and produce a Linux fd_set. Returns the max fd seen.
unsafe fn win_fdset_to_linux(win: *const u8) -> (libc::fd_set, i32) {
    let mut lfs: libc::fd_set = std::mem::zeroed();
    let mut max_fd: i32 = -1;
    if win.is_null() {
        return (lfs, max_fd);
    }
    let count = *(win as *const u32) as usize;
    let arr = win.add(8); // skip count(4) + padding(4)
    for i in 0..count.min(WIN_FD_SETSIZE) {
        let sock = *(arr.add(i * 8) as *const usize);
        let fd = sock as i32;
        if fd >= 0 && (fd as usize) < libc::FD_SETSIZE {
            libc::FD_SET(fd, &mut lfs);
            if fd > max_fd {
                max_fd = fd;
            }
        }
    }
    (lfs, max_fd)
}

/// After select(), filter the Windows fd_set to contain only ready fds.
unsafe fn filter_win_fdset(win: *mut u8, lfs: &libc::fd_set) {
    if win.is_null() {
        return;
    }
    let count = *(win as *const u32) as usize;
    let arr = win.add(8);
    let mut new_count: u32 = 0;
    for i in 0..count.min(WIN_FD_SETSIZE) {
        let sock = *(arr.add(i * 8) as *const usize);
        let fd = sock as i32;
        if fd >= 0 && (fd as usize) < libc::FD_SETSIZE && libc::FD_ISSET(fd, lfs) {
            *(arr.add(new_count as usize * 8) as *mut usize) = sock;
            new_count += 1;
        }
    }
    *(win as *mut u32) = new_count;
}

// ── Structures ───────────────────────────────────────────────────────────────

const WSADESCRIPTION_LEN: usize = 256;
const WSASYS_STATUS_LEN: usize = 128;

/// Win64 WSADATA structure (Winsock 2 field order).
///
/// In Winsock 2, `iMaxSockets` / `iMaxUdpDg` / `lpVendorInfo` come before the
/// description strings (unlike Winsock 1.1 where they came after).
#[repr(C)]
pub struct WsaData {
    pub w_version: u16,
    pub w_high_version: u16,
    pub i_max_sockets: u16,
    pub i_max_udp_dg: u16,
    pub lp_vendor_info: usize,
    pub sz_description: [u8; WSADESCRIPTION_LEN + 1],
    pub sz_system_status: [u8; WSASYS_STATUS_LEN + 1],
}

/// Win64 `addrinfo` structure.
///
/// Layout differs from Linux:
/// - `ai_addrlen` is `size_t` (8 bytes) vs Linux `socklen_t` (4 bytes)
/// - `ai_canonname` comes before `ai_addr` (reversed on Linux)
#[repr(C)]
pub struct WinAddrInfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: usize,
    pub ai_canonname: *mut u8,
    pub ai_addr: *mut u8,
    pub ai_next: *mut WinAddrInfo,
}

// ── Winsock API: startup / shutdown / errors ─────────────────────────────────

/// WSAStartup — initialise Winsock. On Linux this fills WSADATA and returns 0.
///
/// # Safety
/// `lp_wsa_data` must point to a writable `WsaData`.
pub unsafe extern "win64" fn wsa_startup(
    w_version_requested: u16,
    lp_wsa_data: *mut WsaData,
) -> i32 {
    if lp_wsa_data.is_null() {
        return -1;
    }
    std::ptr::write_bytes(lp_wsa_data as *mut u8, 0, std::mem::size_of::<WsaData>());
    let data = &mut *lp_wsa_data;
    data.w_version = w_version_requested;
    data.w_high_version = 0x0202; // Winsock 2.2
    let desc = b"Weave Winsock";
    data.sz_description[..desc.len()].copy_from_slice(desc);
    WSA_INITIALIZED.store(true, Ordering::SeqCst);
    0
}

/// WSACleanup — shut down Winsock. No-op on Linux.
pub extern "win64" fn wsa_cleanup() -> i32 {
    WSA_INITIALIZED.store(false, Ordering::SeqCst);
    0
}

/// WSAGetLastError — return the last Winsock error code for this thread.
pub extern "win64" fn wsa_get_last_error() -> i32 {
    LAST_WSA_ERROR.with(|c| c.get())
}

/// WSASetLastError — set the Winsock error code for this thread.
pub extern "win64" fn wsa_set_last_error(err: i32) {
    set_last_error(err);
}

// ── Winsock API: core socket operations ──────────────────────────────────────

/// socket — create a socket.
///
/// # Safety
/// No pointer arguments.
pub unsafe extern "win64" fn ws_socket(af: i32, type_: i32, protocol: i32) -> usize {
    if weave_core::ws2_trace::enabled() {
        eprintln!("weave/ws_socket: af={af} type={type_} protocol={protocol}");
    }
    let fd = libc::socket(af_win_to_linux(af), type_, protocol);
    if fd < 0 {
        save_errno();
        INVALID_SOCKET
    } else {
        fd as usize
    }
}

/// WSASocketW — create a socket (wide / extended form).
///
/// Windows SDK `winsock2.h`:
///   SOCKET WSAAPI WSASocketW(int af, int type, int protocol,
///                            LPWSAPROTOCOL_INFOW lpProtocolInfo,
///                            GROUP g, DWORD dwFlags);
///
/// When `lpProtocolInfo` is NULL (curl always passes NULL) the call is
/// identical to `socket(af, type, protocol)`.  dwFlags (overlapped I/O
/// flags) are ignored — overlapped I/O is not implemented.
///
/// # Safety
/// `lpProtocolInfo` is unused (ignored when NULL); no other pointer args.
pub unsafe extern "win64" fn ws_wsa_socket_w(
    af: i32,
    type_: i32,
    protocol: i32,
    _lp_protocol_info: usize, // LPWSAPROTOCOL_INFOW — ignored when NULL
    _g: u32,                  // GROUP — reserved, always 0
    _dw_flags: u32,           // WSA_FLAG_* — overlapped I/O not yet implemented
) -> usize {
    // Wine ref: dlls/ws2_32/socket.c WSASocketW — when lpProtocolInfo==NULL,
    // delegates to a socket() call with the supplied af/type/protocol.
    ws_socket(af, type_, protocol)
}

/// WSASocketA — ANSI alias for WSASocketW.  Identical ABI; af/type/protocol
/// are integers so there is no string-conversion difference between A and W.
///
/// # Safety
/// Same as `ws_wsa_socket_w`.
pub unsafe extern "win64" fn ws_wsa_socket_a(
    af: i32,
    type_: i32,
    protocol: i32,
    _lp_protocol_info: usize,
    _g: u32,
    _dw_flags: u32,
) -> usize {
    ws_wsa_socket_w(af, type_, protocol, _lp_protocol_info, _g, _dw_flags)
}

/// closesocket — close a socket.
///
/// # Safety
/// `s` must be a valid socket handle.
pub unsafe extern "win64" fn ws_closesocket(s: usize) -> i32 {
    eprintln!("weave/ws_closesocket: entry s={s}");
    // Clear all per-fd state before close so a recycled fd cannot inherit
    // stale listening/connecting/write-armed tracking from its previous owner.
    // Wine ref: dlls/ws2_32/socket.c — sock_reselect_notify on socket close
    // clears the socket's pending event mask and SS_LISTENING/SS_CONNECTING bits.
    let fd = s as i32;
    weave_common::socket_event::unmark_socket_listening(fd);
    weave_common::socket_event::clear_socket_connecting(fd);
    weave_common::socket_event::disarm_socket_write(fd);
    if libc::close(fd) < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

/// connect — establish a connection to a remote address.
///
/// # Safety
/// `name` must point to a valid sockaddr of at least `namelen` bytes.
pub unsafe extern "win64" fn ws_connect(s: usize, name: *const u8, namelen: i32) -> i32 {
    if weave_core::ws2_trace::enabled() {
        eprintln!("weave/ws_connect: s={s} namelen={namelen}");
    }
    if name.is_null() {
        set_last_error(10014); // WSAEFAULT
        return SOCKET_ERROR;
    }
    let addr = copy_sockaddr_win_to_linux(name, namelen as usize);
    let ret = libc::connect(
        s as i32,
        addr.as_ptr() as *const libc::sockaddr,
        namelen as libc::socklen_t,
    );
    if ret < 0 {
        let e = *libc::__errno_location();
        if e == libc::EINPROGRESS {
            // Non-blocking connect in progress — mark socket as connecting so
            // WSAEnumNetworkEvents can report FD_CONNECT (0x10) instead of
            // FD_WRITE (0x2) when POLLOUT fires on connect completion.
            // Wine ref: dlls/ws2_32/socket.c — SS_CONNECTING state transition;
            // sock_get_events maps POLLOUT+SS_CONNECTING → POLLEVENT_CONNECT (FD_CONNECT).
            weave_common::socket_event::mark_socket_connecting(s as i32);
        }
        set_last_error(errno_to_wsa(e));
        SOCKET_ERROR
    } else {
        // Synchronous connect success — Wine's sock_reselect arms the socket's
        // write-pending state (hmask |= POLLEVENT_WRITE) on the SOCK_CONNECTING →
        // SOCK_CONNECTED transition so the first WSAEnumNetworkEvents reports
        // FD_CONNECT|FD_WRITE. Our EINPROGRESS/clear_connecting path fires on
        // POLLOUT, but a same-process sync connect (loopback, pre-resolved IP)
        // never passes through the connecting state and would leave
        // SOCKET_WRITE_ARMED empty — gnulib/wget then spins because FD_WRITE
        // never lights up. Record the terminal armed state here.
        // Wine ref: server/sock.c:1125 get_poll_flags — POLLOUT is mapped to
        // AFD_POLL_WRITE unconditionally for any non-SOCK_UNCONNECTED socket;
        // a sync-connected socket is SOCK_CONNECTED so POLLOUT → AFD_POLL_WRITE.
        weave_common::socket_event::clear_socket_connecting(s as i32);
        weave_common::socket_event::arm_socket_write(s as i32);
        0
    }
}

/// send — send data on a connected socket.
///
/// # Safety
/// `buf` must point to at least `len` readable bytes.
pub unsafe extern "win64" fn ws_send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    if weave_core::ws2_trace::enabled() {
        eprintln!("weave/ws_send: s={s} len={len} flags={flags:#x}");
    }
    let ret = libc::send(s as i32, buf as *const libc::c_void, len as usize, flags);
    if ret < 0 {
        let e = *libc::__errno_location();
        // Re-arm FD_WRITE edge trigger when send buffer is full.
        // Wine ref: dlls/ws2_32/socket.c — when send() returns EWOULDBLOCK,
        // the socket's write-pending bit (hmask POLLEVENT_WRITE) is re-set so
        // that FD_WRITE fires again once the kernel signals write-space available.
        // This is the "re-arm after EWOULDBLOCK" step of the edge-triggered contract.
        if e == libc::EWOULDBLOCK || e == libc::EAGAIN {
            weave_common::socket_event::arm_socket_write(s as i32);
        }
        set_last_error(errno_to_wsa(e));
        SOCKET_ERROR
    } else {
        ret as i32
    }
}

/// recv — receive data from a connected socket.
///
/// # Safety
/// `buf` must point to at least `len` writable bytes.
pub unsafe extern "win64" fn ws_recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32 {
    if weave_core::ws2_trace::enabled() {
        eprintln!("weave/ws_recv: s={s} len={len} flags={flags:#x}");
    }
    let ret = libc::recv(s as i32, buf as *mut libc::c_void, len as usize, flags);
    if ret < 0 {
        save_errno();
        return SOCKET_ERROR;
    }
    ret as i32
}

/// bind — bind a socket to a local address.
///
/// # Safety
/// `name` must point to a valid sockaddr of at least `namelen` bytes.
pub unsafe extern "win64" fn ws_bind(s: usize, name: *const u8, namelen: i32) -> i32 {
    if name.is_null() {
        set_last_error(10014);
        return SOCKET_ERROR;
    }
    let addr = copy_sockaddr_win_to_linux(name, namelen as usize);
    let ret = libc::bind(
        s as i32,
        addr.as_ptr() as *const libc::sockaddr,
        namelen as libc::socklen_t,
    );
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

/// listen — mark a socket as listening for incoming connections.
///
/// # Safety
/// `s` must be a valid bound socket.
pub unsafe extern "win64" fn ws_listen(s: usize, backlog: i32) -> i32 {
    if libc::listen(s as i32, backlog) < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        weave_common::socket_event::mark_socket_listening(s as i32);
        0
    }
}

/// accept — accept an incoming connection.
///
/// # Safety
/// `addr` and `addrlen` may be null. If non-null, `addr` must point to a
/// writable buffer and `addrlen` must point to its size.
pub unsafe extern "win64" fn ws_accept(s: usize, addr: *mut u8, addrlen: *mut i32) -> usize {
    let mut linux_len: libc::socklen_t = if !addrlen.is_null() {
        *addrlen as libc::socklen_t
    } else {
        0
    };
    let fd = libc::accept(
        s as i32,
        if addr.is_null() {
            std::ptr::null_mut()
        } else {
            addr as *mut libc::sockaddr
        },
        if addrlen.is_null() {
            std::ptr::null_mut()
        } else {
            &mut linux_len
        },
    );
    if fd < 0 {
        save_errno();
        INVALID_SOCKET
    } else {
        if !addr.is_null() {
            patch_sockaddr_linux_to_win(addr, linux_len as usize);
        }
        if !addrlen.is_null() {
            *addrlen = linux_len as i32;
        }
        fd as usize
    }
}

/// shutdown — disable sends and/or receives on a socket.
///
/// # Safety
/// `s` must be a valid socket handle.
pub unsafe extern "win64" fn ws_shutdown(s: usize, how: i32) -> i32 {
    // SD_RECEIVE=0, SD_SEND=1, SD_BOTH=2 are identical on both platforms.
    if libc::shutdown(s as i32, how) < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

/// getpeername — retrieve the address of the peer connected to a socket.
///
/// # Safety
/// `name` must point to a writable buffer. `namelen` must point to its size.
pub unsafe extern "win64" fn ws_getpeername(s: usize, name: *mut u8, namelen: *mut i32) -> i32 {
    if name.is_null() || namelen.is_null() {
        set_last_error(10014);
        return SOCKET_ERROR;
    }
    let mut linux_len = *namelen as libc::socklen_t;
    let ret = libc::getpeername(s as i32, name as *mut libc::sockaddr, &mut linux_len);
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        patch_sockaddr_linux_to_win(name, linux_len as usize);
        *namelen = linux_len as i32;
        0
    }
}

/// getsockname — retrieve the local address of a socket.
///
/// # Safety
/// `name` must point to a writable buffer. `namelen` must point to its size.
pub unsafe extern "win64" fn ws_getsockname(s: usize, name: *mut u8, namelen: *mut i32) -> i32 {
    if name.is_null() || namelen.is_null() {
        set_last_error(10014);
        return SOCKET_ERROR;
    }
    let mut linux_len = *namelen as libc::socklen_t;
    let ret = libc::getsockname(s as i32, name as *mut libc::sockaddr, &mut linux_len);
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        patch_sockaddr_linux_to_win(name, linux_len as usize);
        *namelen = linux_len as i32;
        0
    }
}

// ── Winsock API: select ──────────────────────────────────────────────────────

/// select — check socket readiness for reading, writing, or exceptions.
///
/// Translates between Windows fd_set layout (counted array of SOCKET handles)
/// and Linux fd_set layout (bitmask). Also translates Windows timeval (two i32)
/// to Linux timeval (two i64 on x86_64).
///
/// # Safety
/// Non-null `readfds`, `writefds`, `exceptfds` must point to valid Windows
/// fd_set structures. `timeout` must point to a Windows timeval (8 bytes).
pub unsafe extern "win64" fn ws_select(
    _nfds: i32,
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
    timeout: *const u8,
) -> i32 {
    if weave_core::ws2_trace::enabled() {
        eprintln!(
            "weave/ws_select: r={:p} w={:p} e={:p} t={:p}",
            readfds, writefds, exceptfds, timeout
        );
    }
    let (mut lr, max_r) = win_fdset_to_linux(readfds);
    let (mut lw, max_w) = win_fdset_to_linux(writefds);
    let (mut le, max_e) = win_fdset_to_linux(exceptfds);
    let nfds = [max_r, max_w, max_e].into_iter().max().unwrap_or(-1) + 1;

    // Windows timeval: long(4) + long(4) = 8 bytes.
    // Linux timeval: time_t(8) + suseconds_t(8) = 16 bytes on x86_64.
    let mut linux_tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let tv_ptr = if timeout.is_null() {
        std::ptr::null_mut()
    } else {
        let win_sec = *(timeout as *const i32);
        let win_usec = *((timeout as *const i32).add(1));
        linux_tv.tv_sec = win_sec as libc::time_t;
        linux_tv.tv_usec = win_usec as libc::suseconds_t;
        &mut linux_tv as *mut libc::timeval
    };

    let ret = libc::select(
        nfds,
        if readfds.is_null() {
            std::ptr::null_mut()
        } else {
            &mut lr
        },
        if writefds.is_null() {
            std::ptr::null_mut()
        } else {
            &mut lw
        },
        if exceptfds.is_null() {
            std::ptr::null_mut()
        } else {
            &mut le
        },
        tv_ptr,
    );
    if ret < 0 {
        save_errno();
        return SOCKET_ERROR;
    }
    filter_win_fdset(readfds, &lr);
    filter_win_fdset(writefds, &lw);
    filter_win_fdset(exceptfds, &le);
    ret
}

// ── Winsock API: name resolution ─────────────────────────────────────────────

/// getaddrinfo — resolve a hostname and/or service name.
///
/// Calls `libc::getaddrinfo`, then converts the Linux-layout result linked list
/// into Windows-layout `WinAddrInfo` nodes with translated `ai_family` values
/// and patched `sa_family` bytes in each sockaddr.
///
/// # Safety
/// `p_node_name` and `p_service_name` are null-terminated byte strings (may be null).
/// `p_hints` may be null. `pp_result` must be a valid non-null pointer.
pub unsafe extern "win64" fn ws_getaddrinfo(
    p_node_name: *const u8,
    p_service_name: *const u8,
    p_hints: *const WinAddrInfo,
    pp_result: *mut *mut WinAddrInfo,
) -> i32 {
    if weave_core::ws2_trace::enabled() {
        eprintln!(
            "weave/ws_getaddrinfo: node={:p} service={:p}",
            p_node_name, p_service_name
        );
    }
    if pp_result.is_null() {
        return 10014; // WSAEFAULT
    }

    // Build Linux-layout hints from Windows-layout hints.
    let mut linux_hints: libc::addrinfo = std::mem::zeroed();
    let hints_ptr = if p_hints.is_null() {
        std::ptr::null()
    } else {
        linux_hints.ai_flags = (*p_hints).ai_flags;
        linux_hints.ai_family = af_win_to_linux((*p_hints).ai_family);
        linux_hints.ai_socktype = (*p_hints).ai_socktype;
        linux_hints.ai_protocol = (*p_hints).ai_protocol;
        &linux_hints as *const libc::addrinfo
    };

    let mut linux_result: *mut libc::addrinfo = std::ptr::null_mut();
    let ret = libc::getaddrinfo(
        p_node_name as *const libc::c_char,
        p_service_name as *const libc::c_char,
        hints_ptr,
        &mut linux_result,
    );
    if ret != 0 {
        *pp_result = std::ptr::null_mut();
        return ret;
    }

    // Convert Linux addrinfo linked list → Windows WinAddrInfo linked list.
    let mut head: *mut WinAddrInfo = std::ptr::null_mut();
    let mut tail: *mut WinAddrInfo = std::ptr::null_mut();
    let mut cur = linux_result;

    while !cur.is_null() {
        let la = &*cur;

        // Copy sockaddr data and translate sa_family (Linux → Windows).
        let (addr_ptr, addr_len) = if !la.ai_addr.is_null() && la.ai_addrlen > 0 {
            let len = la.ai_addrlen as usize;
            let mut buf = vec![0u8; len];
            std::ptr::copy_nonoverlapping(la.ai_addr as *const u8, buf.as_mut_ptr(), len);
            if len >= 2 {
                let family = u16::from_ne_bytes([buf[0], buf[1]]);
                let win_family = af_linux_to_win(family as i32) as u16;
                buf[0..2].copy_from_slice(&win_family.to_ne_bytes());
            }
            let boxed = buf.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *mut u8;
            (ptr, len)
        } else {
            (std::ptr::null_mut(), 0)
        };

        let node = Box::into_raw(Box::new(WinAddrInfo {
            ai_flags: la.ai_flags,
            ai_family: af_linux_to_win(la.ai_family),
            ai_socktype: la.ai_socktype,
            ai_protocol: la.ai_protocol,
            ai_addrlen: addr_len,
            ai_canonname: std::ptr::null_mut(),
            ai_addr: addr_ptr,
            ai_next: std::ptr::null_mut(),
        }));

        if head.is_null() {
            head = node;
        } else {
            (*tail).ai_next = node;
        }
        tail = node;
        cur = la.ai_next;
    }

    libc::freeaddrinfo(linux_result);
    *pp_result = head;
    0
}

/// freeaddrinfo — free the linked list returned by `getaddrinfo`.
///
/// # Safety
/// `p_addr_info` must be a pointer previously returned by `ws_getaddrinfo`,
/// or null.
pub unsafe extern "win64" fn ws_freeaddrinfo(p_addr_info: *mut WinAddrInfo) {
    let mut cur = p_addr_info;
    while !cur.is_null() {
        let node = Box::from_raw(cur);
        if !node.ai_addr.is_null() && node.ai_addrlen > 0 {
            let slice = std::ptr::slice_from_raw_parts_mut(node.ai_addr, node.ai_addrlen);
            drop(Box::from_raw(slice));
        }
        cur = node.ai_next;
    }
}

// ── Winsock API: socket options ──────────────────────────────────────────────

/// ioctlsocket — control socket I/O mode. Currently handles FIONBIO only.
///
/// # Safety
/// `argp` must be a valid non-null pointer to a u32.
pub unsafe extern "win64" fn ws_ioctlsocket(s: usize, cmd: u32, argp: *mut u32) -> i32 {
    if weave_core::ws2_trace::enabled() {
        eprintln!("weave/ws_ioctlsocket: s={s} cmd={cmd:#x}");
    }
    if argp.is_null() {
        set_last_error(10014);
        return SOCKET_ERROR;
    }
    match cmd {
        FIONBIO_WIN => {
            let nonblock = *argp != 0;
            let mut flags = libc::fcntl(s as i32, libc::F_GETFL);
            if flags < 0 {
                save_errno();
                return SOCKET_ERROR;
            }
            if nonblock {
                flags |= libc::O_NONBLOCK;
            } else {
                flags &= !libc::O_NONBLOCK;
            }
            if libc::fcntl(s as i32, libc::F_SETFL, flags) < 0 {
                save_errno();
                SOCKET_ERROR
            } else {
                0
            }
        }
        _ => {
            set_last_error(10045); // WSAEOPNOTSUPP
            SOCKET_ERROR
        }
    }
}

/// setsockopt — set a socket option.
///
/// Translates Windows socket option levels and names to Linux equivalents.
///
/// # Safety
/// `optval` must point to at least `optlen` readable bytes.
pub unsafe extern "win64" fn ws_setsockopt(
    s: usize,
    level: i32,
    optname: i32,
    optval: *const u8,
    optlen: i32,
) -> i32 {
    // SO_EXCLUSIVEADDRUSE is Windows-only (~SO_REUSEADDR = -5). Linux sockets are
    // exclusive by default (absence of SO_REUSEADDR = exclusive ownership), so this
    // option is a no-op on Linux.
    // Wine ref: dlls/ws2_32/socket.c — SO_EXCLUSIVEADDRUSE silently ignored; Linux
    // default socket behavior already provides exclusivity without needing a setsockopt call.
    if level == SOL_SOCKET_WIN && optname == SO_EXCLUSIVEADDRUSE_WIN {
        return 0;
    }
    let linux_level = translate_sockopt_level(level);
    let linux_name = translate_sockopt_name(level, optname);
    let ret = libc::setsockopt(
        s as i32,
        linux_level,
        linux_name,
        optval as *const libc::c_void,
        optlen as libc::socklen_t,
    );
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

/// getsockopt — get a socket option value.
///
/// # Safety
/// `optval` must point to a writable buffer. `optlen` must point to its size.
pub unsafe extern "win64" fn ws_getsockopt(
    s: usize,
    level: i32,
    optname: i32,
    optval: *mut u8,
    optlen: *mut i32,
) -> i32 {
    let linux_level = translate_sockopt_level(level);
    let linux_name = translate_sockopt_name(level, optname);
    let mut linux_len: libc::socklen_t = if !optlen.is_null() {
        *optlen as libc::socklen_t
    } else {
        0
    };
    let ret = libc::getsockopt(
        s as i32,
        linux_level,
        linux_name,
        optval as *mut libc::c_void,
        &mut linux_len,
    );
    if !optlen.is_null() {
        *optlen = linux_len as i32;
    }
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

// ── Winsock API: byte-order helpers ──────────────────────────────────────────

/// htons — host to network short (16-bit).
pub extern "win64" fn ws_htons(hostshort: u16) -> u16 {
    hostshort.to_be()
}

/// htonl — host to network long (32-bit).
pub extern "win64" fn ws_htonl(hostlong: u32) -> u32 {
    hostlong.to_be()
}

/// ntohs — network to host short (16-bit).
pub extern "win64" fn ws_ntohs(netshort: u16) -> u16 {
    u16::from_be(netshort)
}

/// ntohl — network to host long (32-bit).
pub extern "win64" fn ws_ntohl(netlong: u32) -> u32 {
    u32::from_be(netlong)
}

/// inet_addr — convert IPv4 dotted-decimal string to network-order u32.
///
/// # Safety
/// `cp` must be a valid null-terminated byte string, or null.
pub unsafe extern "win64" fn ws_inet_addr(cp: *const u8) -> u32 {
    if cp.is_null() {
        return u32::MAX; // INADDR_NONE
    }
    let c_str = std::ffi::CStr::from_ptr(cp as *const libc::c_char);
    let s = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return u32::MAX,
    };
    // Parse dotted-decimal IPv4 and return in network byte order.
    let mut parts = [0u8; 4];
    let mut idx = 0;
    for octet_str in s.split('.') {
        if idx >= 4 {
            return u32::MAX;
        }
        match octet_str.parse::<u8>() {
            Ok(v) => parts[idx] = v,
            Err(_) => return u32::MAX,
        }
        idx += 1;
    }
    if idx != 4 {
        return u32::MAX;
    }
    u32::from_ne_bytes(parts)
}

// ── Winsock API: legacy name-resolution (hostent/servent) ────────────────────

/// gethostname — retrieve the local machine's hostname.
///
/// Wine ref: dlls/ws2_32/unixlib.c:1042 — unix_gethostname calls gethostname(params->name,
/// params->size); returns 0 on success or errno_from_unix(errno) on failure.
///
/// # Safety
/// `name` must point to a writable buffer of at least `namelen` bytes.
pub unsafe extern "win64" fn ws_gethostname(name: *mut u8, namelen: i32) -> i32 {
    if name.is_null() || namelen <= 0 {
        set_last_error(10014); // WSAEFAULT
        return SOCKET_ERROR;
    }
    let ret = libc::gethostname(name as *mut libc::c_char, namelen as libc::size_t);
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

// Windows HOSTENT layout (64-bit):
//   h_name      *c_char  (8 bytes)
//   h_aliases   **c_char (8 bytes)
//   h_addrtype  i16      (2 bytes) + h_length i16 (2 bytes) + pad (4 bytes)
//   h_addr_list **c_char (8 bytes)
// Total: 32 bytes, plus heap storage for strings and addr arrays.
//
// We use a thread-local static buffer so the pointer remains valid after return,
// which is what the real Winsock does (not thread-safe across threads, same as
// the real Windows gethostbyname).

thread_local! {
    static HOSTENT_BUF: std::cell::RefCell<Option<HostentStorage>> =
        const { std::cell::RefCell::new(None) };
}

struct HostentStorage {
    // The flat Windows HOSTENT structure (32 bytes on 64-bit).
    hostent: [u8; 32],
    // Heap-allocated name (NUL-terminated).
    name: Vec<u8>,
    // Heap-allocated addr bytes (4 bytes for IPv4).
    addr: Vec<u8>,
    // Pointer array: [*addr, null].
    addr_list: Vec<*mut u8>,
    // Pointer array: [null] (no aliases).
    aliases: Vec<*mut u8>,
}

unsafe impl Send for HostentStorage {}

/// gethostbyname — resolve a hostname to a HOSTENT structure.
///
/// Wine ref: dlls/ws2_32/unixlib.c:981 — unix_gethostbyname uses gethostbyname_r,
/// then hostent_from_unix to convert the Linux hostent to a Windows layout.
/// Returns NULL and sets last error on failure.
///
/// # Safety
/// `name` must be a valid null-terminated byte string, or null.
pub unsafe extern "win64" fn ws_gethostbyname(name: *const u8) -> *mut u8 {
    if name.is_null() {
        set_last_error(10014); // WSAEFAULT
        return std::ptr::null_mut();
    }
    let c_str = std::ffi::CStr::from_ptr(name as *const libc::c_char);

    // Use getaddrinfo to resolve — works for both names and dotted-decimal.
    let mut hints: libc::addrinfo = std::mem::zeroed();
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = libc::getaddrinfo(c_str.as_ptr(), std::ptr::null(), &hints, &mut res);
    if rc != 0 || res.is_null() {
        set_last_error(11001); // WSAHOST_NOT_FOUND
        return std::ptr::null_mut();
    }

    // Extract first IPv4 address.
    let sin = &*((*res).ai_addr as *const libc::sockaddr_in);
    let addr_bytes = sin.sin_addr.s_addr.to_ne_bytes();

    // Build name string (use the input name as canonical).
    let name_bytes: Vec<u8> = c_str.to_bytes_with_nul().to_vec();

    HOSTENT_BUF.with(|cell| {
        let mut storage = HostentStorage {
            hostent: [0u8; 32],
            name: name_bytes,
            addr: addr_bytes.to_vec(),
            addr_list: vec![std::ptr::null_mut(); 2], // [ptr, null]
            aliases: vec![std::ptr::null_mut()],      // [null]
        };
        // Point addr_list[0] at addr bytes.
        storage.addr_list[0] = storage.addr.as_mut_ptr();

        // Build Windows HOSTENT (little-endian 64-bit layout):
        //  offset 0:  h_name        *u8  (8)
        //  offset 8:  h_aliases     **u8 (8)
        //  offset 16: h_addrtype    i16  (2)
        //  offset 18: h_length      i16  (2)
        //  offset 20: pad           (4)
        //  offset 24: h_addr_list   **u8 (8)
        let h = &mut storage.hostent;
        let name_ptr = storage.name.as_ptr() as usize;
        let aliases_ptr = storage.aliases.as_ptr() as usize;
        let addr_list_ptr = storage.addr_list.as_ptr() as usize;
        h[0..8].copy_from_slice(&name_ptr.to_ne_bytes());
        h[8..16].copy_from_slice(&aliases_ptr.to_ne_bytes());
        h[16..18].copy_from_slice(&(2i16).to_ne_bytes()); // AF_INET = 2
        h[18..20].copy_from_slice(&(4i16).to_ne_bytes()); // IPv4 addr len = 4
        h[24..32].copy_from_slice(&addr_list_ptr.to_ne_bytes());

        *cell.borrow_mut() = Some(storage);
        libc::freeaddrinfo(res);
    });

    HOSTENT_BUF.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|s| s.hostent.as_ptr() as *mut u8)
            .unwrap_or(std::ptr::null_mut())
    })
}

// Windows SERVENT layout (64-bit):
//   s_name    *c_char  (8 bytes)
//   s_aliases **c_char (8 bytes)
//   s_port    i16      (2 bytes) + pad (6 bytes)
//   s_proto   *c_char  (8 bytes)
// Total: 32 bytes.

thread_local! {
    static SERVENT_BUF: std::cell::RefCell<Option<ServentStorage>> =
        const { std::cell::RefCell::new(None) };
}

struct ServentStorage {
    servent: [u8; 32],
    name: Vec<u8>,
    proto: Vec<u8>,
    aliases: Vec<*mut u8>,
}

unsafe impl Send for ServentStorage {}

/// getservbyname — look up a service by name and protocol.
///
/// Wine ref: dlls/ws2_32/async.c:78 — async_query_getservbyname struct shows the
/// fields: name, proto, port. The sync path calls the POSIX getservbyname and
/// packages the result into a Windows SERVENT. Returns NULL on failure.
///
/// # Safety
/// `name` and `proto` must be null-terminated byte strings (proto may be null).
pub unsafe extern "win64" fn ws_getservbyname(name: *const u8, proto: *const u8) -> *mut u8 {
    if name.is_null() {
        set_last_error(10014); // WSAEFAULT
        return std::ptr::null_mut();
    }
    let proto_ptr = if proto.is_null() {
        std::ptr::null()
    } else {
        proto as *const libc::c_char
    };
    let se = libc::getservbyname(name as *const libc::c_char, proto_ptr);
    if se.is_null() {
        set_last_error(11001); // WSAHOST_NOT_FOUND (service not found)
        return std::ptr::null_mut();
    }

    // Extract fields from libc servent.
    let sname: Vec<u8> = std::ffi::CStr::from_ptr((*se).s_name)
        .to_bytes_with_nul()
        .to_vec();
    let sproto: Vec<u8> = std::ffi::CStr::from_ptr((*se).s_proto)
        .to_bytes_with_nul()
        .to_vec();
    // Port: Linux stores in network byte order, Windows also stores network byte order.
    let port_ne = (*se).s_port as i16;

    SERVENT_BUF.with(|cell| {
        let mut storage = ServentStorage {
            servent: [0u8; 32],
            name: sname,
            proto: sproto,
            aliases: vec![std::ptr::null_mut()],
        };

        let name_ptr = storage.name.as_ptr() as usize;
        let aliases_ptr = storage.aliases.as_ptr() as usize;
        let proto_ptr2 = storage.proto.as_ptr() as usize;
        let h = &mut storage.servent;
        h[0..8].copy_from_slice(&name_ptr.to_ne_bytes());
        h[8..16].copy_from_slice(&aliases_ptr.to_ne_bytes());
        h[16..18].copy_from_slice(&port_ne.to_ne_bytes());
        h[24..32].copy_from_slice(&proto_ptr2.to_ne_bytes());

        *cell.borrow_mut() = Some(storage);
    });

    SERVENT_BUF.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|s| s.servent.as_ptr() as *mut u8)
            .unwrap_or(std::ptr::null_mut())
    })
}

// ── Winsock API: address formatting ──────────────────────────────────────────

/// inet_ntoa — convert an IPv4 in-addr structure to a dotted-decimal string.
///
/// Wine ref: dlls/ws2_32/socket.c — WS_inet_ntoa returns a pointer to a thread-local
/// static buffer formatted as "a.b.c.d". The input is a struct in_addr (u32 in
/// network byte order). Returns a pointer to the static string.
///
/// # Safety
/// `in_addr` is passed by value as a u32 (Windows calling convention passes
/// small structs in registers).
pub extern "win64" fn ws_inet_ntoa(in_addr: u32) -> *const u8 {
    thread_local! {
        static INET_NTOA_BUF: std::cell::RefCell<[u8; 16]> =
            const { std::cell::RefCell::new([0u8; 16]) };
    }
    let bytes = in_addr.to_ne_bytes(); // already network byte order
    let s = std::format!("{}.{}.{}.{}\0", bytes[0], bytes[1], bytes[2], bytes[3]);
    INET_NTOA_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        let len = s.len().min(16);
        buf[..len].copy_from_slice(&s.as_bytes()[..len]);
        buf.as_ptr()
    })
}

/// inet_ntop — convert a binary network address to a presentation string.
///
/// Wine ref: dlls/ws2_32/socket.c — WS_InetNtopW/A call the POSIX inet_ntop.
/// Returns the buffer pointer on success, NULL on failure (sets WSAEINVAL or
/// WSAEAFNOSUPPORT).
///
/// # Safety
/// `src` must point to a valid network address (4 bytes for AF_INET, 16 for AF_INET6).
/// `dst` must point to a writable buffer of at least `size` bytes.
pub unsafe extern "win64" fn ws_inet_ntop(
    af: i32,
    src: *const u8,
    dst: *mut u8,
    size: u32,
) -> *const u8 {
    if src.is_null() || dst.is_null() {
        set_last_error(10014); // WSAEFAULT
        return std::ptr::null();
    }
    let linux_af = af_win_to_linux(af);
    let ret = inet_ntop(
        linux_af,
        src as *const libc::c_void,
        dst as *mut libc::c_char,
        size as libc::socklen_t,
    );
    if ret.is_null() {
        save_errno();
        std::ptr::null()
    } else {
        dst as *const u8
    }
}

/// getnameinfo — resolve a socket address to a host/service name.
///
/// Wine ref: dlls/ws2_32/unixlib.c:1052 — unix_getnameinfo converts sockaddr via
/// sockaddr_to_unix then calls POSIX getnameinfo, translating flags via
/// nameinfo_flags_to_unix. Returns 0 on success, error code on failure.
///
/// # Safety
/// `sa` must point to a valid sockaddr of `salen` bytes.
pub unsafe extern "win64" fn ws_getnameinfo(
    sa: *const u8,
    salen: i32,
    host: *mut u8,
    hostlen: u32,
    serv: *mut u8,
    servlen: u32,
    flags: i32,
) -> i32 {
    if sa.is_null() {
        set_last_error(10014); // WSAEFAULT
        return 10014;
    }
    // Translate sockaddr from Windows to Linux format.
    let addr = copy_sockaddr_win_to_linux(sa, salen as usize);
    let ret = libc::getnameinfo(
        addr.as_ptr() as *const libc::sockaddr,
        salen as libc::socklen_t,
        host as *mut libc::c_char,
        hostlen,
        serv as *mut libc::c_char,
        servlen,
        flags, // NI_* flags have the same values on Linux and Windows
    );
    if ret != 0 {
        save_errno();
        set_last_error(ret);
    }
    ret
}

/// WSAAddressToStringA — convert a sockaddr to a human-readable string.
///
/// Wine ref: dlls/ws2_32/socket.c — WSAAddressToStringA validates lpsaAddress and
/// lpdwAddressStringLength, then formats as "a.b.c.d:port" for IPv4 or
/// "[addr]:port" for IPv6. Returns 0 on success, SOCKET_ERROR on failure.
///
/// # Safety
/// `lp_address` must point to a valid sockaddr of `dw_address_length` bytes.
/// `lpsz_address_string` must point to a writable buffer.
/// `lpdw_address_string_length` must be a valid pointer to the buffer size.
pub unsafe extern "win64" fn ws_wsa_address_to_string_a(
    lp_address: *const u8,
    dw_address_length: u32,
    _lp_protocol_info: *const u8, // ignored
    lpsz_address_string: *mut u8,
    lpdw_address_string_length: *mut u32,
) -> i32 {
    if lp_address.is_null() || lpdw_address_string_length.is_null() {
        set_last_error(10014); // WSAEFAULT
        return SOCKET_ERROR;
    }
    // Read Windows address family from sockaddr.
    let family = if dw_address_length >= 2 {
        u16::from_ne_bytes([*lp_address, *lp_address.add(1)]) as i32
    } else {
        set_last_error(10022); // WSAEINVAL
        return SOCKET_ERROR;
    };

    let result_str = match family {
        2 => {
            // AF_INET: sockaddr_in = family(2) + port(2) + addr(4) + pad(8)
            if dw_address_length < 8 {
                set_last_error(10022); // WSAEINVAL
                return SOCKET_ERROR;
            }
            let port = u16::from_be_bytes([*lp_address.add(2), *lp_address.add(3)]);
            let a = *lp_address.add(4);
            let b = *lp_address.add(5);
            let c = *lp_address.add(6);
            let d = *lp_address.add(7);
            if port != 0 {
                std::format!("{a}.{b}.{c}.{d}:{port}")
            } else {
                std::format!("{a}.{b}.{c}.{d}")
            }
        }
        23 => {
            // AF_INET6 (Windows = 23): use inet_ntop for the address.
            if dw_address_length < 16 {
                set_last_error(10022); // WSAEINVAL
                return SOCKET_ERROR;
            }
            let mut buf = [0u8; 64];
            let addr_ptr = lp_address.add(8); // skip family(2)+port(2)+flowinfo(4)
            let ret = inet_ntop(
                libc::AF_INET6,
                addr_ptr as *const libc::c_void,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len() as libc::socklen_t,
            );
            if ret.is_null() {
                save_errno();
                return SOCKET_ERROR;
            }
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            std::format!("[{}]", std::str::from_utf8(&buf[..len]).unwrap_or(""))
        }
        _ => {
            set_last_error(10047); // WSAEAFNOSUPPORT
            return SOCKET_ERROR;
        }
    };

    let needed = (result_str.len() + 1) as u32;
    let provided = *lpdw_address_string_length;
    *lpdw_address_string_length = needed;

    if lpsz_address_string.is_null() || provided < needed {
        set_last_error(10055); // WSAENOBUFS (buffer too small)
        return SOCKET_ERROR;
    }

    let bytes = result_str.as_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), lpsz_address_string, bytes.len());
    *lpsz_address_string.add(bytes.len()) = 0;
    0
}

/// WSAIoctl — control socket I/O mode (extended ioctlsocket).
///
/// Wine ref: dlls/ws2_32/socket.c:debugstr_wsaioctl shows known codes; the main
/// WSAIoctl handler routes known codes (SIO_GET_EXTENSION_FUNCTION_POINTER,
/// FIONBIO, etc.) and returns WSAEOPNOTSUPP for unrecognised ones.
/// Stub: handle FIONBIO (same as ioctlsocket), return WSAEOPNOTSUPP for rest.
///
/// # Safety
/// Pointer arguments are only dereferenced when non-null.
pub unsafe extern "win64" fn ws_wsa_ioctl(
    s: usize,
    dw_ioctl_code: u32,
    lp_vb_in_buffer: *const u8,
    cb_in_buffer: u32,
    _lp_vb_out_buffer: *mut u8,
    _cb_out_buffer: u32,
    lpcb_bytes_returned: *mut u32,
    _lp_overlapped: *const u8,
    _lp_completion_routine: *const u8,
) -> i32 {
    // FIONBIO (0x8004667E) — same semantics as ioctlsocket FIONBIO.
    if dw_ioctl_code == FIONBIO_WIN {
        if lp_vb_in_buffer.is_null() || cb_in_buffer < 4 {
            set_last_error(10014); // WSAEFAULT
            return SOCKET_ERROR;
        }
        let nonblock = *(lp_vb_in_buffer as *const u32) != 0;
        let mut flags = libc::fcntl(s as i32, libc::F_GETFL);
        if flags < 0 {
            save_errno();
            return SOCKET_ERROR;
        }
        if nonblock {
            flags |= libc::O_NONBLOCK;
        } else {
            flags &= !libc::O_NONBLOCK;
        }
        if libc::fcntl(s as i32, libc::F_SETFL, flags) < 0 {
            save_errno();
            return SOCKET_ERROR;
        }
        if !lpcb_bytes_returned.is_null() {
            *lpcb_bytes_returned = 0;
        }
        return 0;
    }

    eprintln!("weave: WSAIoctl: unsupported ioctl code {dw_ioctl_code:#010x}");
    set_last_error(10045); // WSAEOPNOTSUPP
    SOCKET_ERROR
}

/// WSAAsyncSelect — request event notification for a socket (message-based).
///
/// Wine ref: dlls/ws2_32/socket.c:3885 — WSAAsyncSelect uses IOCTL_AFD_EVENT_SELECT
/// (an NT kernel I/O control) to register interest in events; the socket enters
/// non-blocking mode. Weave has no Win32 message queue, so this is a no-op stub
/// that returns 0 (success), allowing callers that use it only to set up async I/O
/// to proceed normally.
///
/// # Safety
/// Arguments are not dereferenced.
pub unsafe extern "win64" fn ws_wsa_async_select(
    s: usize,
    h_wnd: usize,
    w_msg: u32,
    l_event: i32,
) -> i32 {
    let _ = (s, h_wnd, w_msg, l_event);
    0 // success — no-op
}

// ── Winsock API: async-event model ───────────────────────────────────────────

// WSA_INVALID_EVENT is the null/invalid WSAEVENT sentinel (0).
const WSA_INVALID_EVENT: usize = 0;

// Error codes used by async-event functions.
const WSAEINVAL: i32 = 10022;
const WSA_WAIT_FAILED: u32 = 0xFFFF_FFFF;
const WSA_WAIT_EVENT_0: u32 = 0;

/// WSACreateEvent — create a manual-reset, initially-unsignaled socket event object.
///
/// Wine ref: dlls/ws2_32/socket.c:3988 — WSACreateEvent calls CreateEventW(NULL,
/// TRUE, FALSE, NULL); returns the resulting HANDLE as WSAEVENT.
/// Weave: backed by eventfd(EFD_NONBLOCK|EFD_CLOEXEC), stored in the global
/// handle table as HandleKind::Event so WaitForMultipleObjects can poll it.
pub extern "win64" fn wsa_create_event() -> usize {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let efd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
            if efd < 0 {
                set_last_error(WSAEINVAL);
                return WSA_INVALID_EVENT;
            }
            let handle = handles::alloc_event(efd);
            eprintln!("weave/WSACreateEvent: eventfd={efd} handle={handle:#x}");
            handle
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS build host — return stable fake handle for cargo check.
        1
    }
}

/// WSACloseEventObject — close a socket event object created by WSACreateEvent.
///
/// Wine ref: dlls/ws2_32/socket.c:4000 — WSACloseEvent calls CloseHandle(event);
/// returns BOOL. Weave: frees the handle table entry (closes underlying eventfd).
pub extern "win64" fn wsa_close_event_object(event: usize) -> i32 {
    if event == WSA_INVALID_EVENT {
        set_last_error(WSAEINVAL);
        return 0; // FALSE
    }
    #[cfg(target_os = "linux")]
    if let Some(efd) = handles::get_event_fd(event) {
        unsafe { libc::close(efd) };
    }
    handles::free(event);
    1 // TRUE
}

/// WSAEventSelect — associate network events on a socket with a WSAEVENT object.
///
/// Wine ref: dlls/ws2_32/socket.c:3885 — WSAEventSelect(SOCKET s, WSAEVENT event,
/// LONG mask) uses IOCTL_AFD_EVENT_SELECT via NtDeviceIoControlFile. The socket
/// enters non-blocking mode and network events are posted to the event object.
/// Weave: stores socket→(event_handle, mask) in SOCKET_EVENT_MAP so that
/// WSAWaitForMultipleEvents and WSAEnumNetworkEvents can poll the real socket fd.
/// Also sets the socket to non-blocking mode (matches Wine behaviour).
///
/// # Safety
/// `s` must be a valid socket fd. `event` is the WSAEVENT handle.
pub unsafe extern "win64" fn wsa_event_select(s: usize, event: usize, mask: i32) -> i32 {
    eprintln!("weave/WSAEventSelect: socket={s} event={event:#x} mask={mask:#010x}");
    // Set socket non-blocking (Wine does this implicitly via AFD_EVENT_SELECT).
    // Wine ref: dlls/ws2_32/socket.c:3885 — WSAEventSelect transitions the socket to
    // non-blocking mode and clears all previous events regardless of arm/disarm.
    let flags = libc::fcntl(s as i32, libc::F_GETFL);
    if flags >= 0 {
        libc::fcntl(s as i32, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    eprintln!("weave/WSAEventSelect: fcntl done");
    // Store or remove the socket→(event, mask) association.
    //
    // Disarm case (mask == 0 OR event == 0): Windows callers use
    // WSAEventSelect(s, NULL, 0) to clear all event associations from a socket.
    // The map entry must be REMOVED — not overwritten with (0, 0) — so that the
    // WFMO event-resolution path never sees a stale (socket → null-handle) entry.
    // We also capture the previous event handle so we can deregister it from the
    // weave-common reverse map (EVENT_SOCKET_MAP).  Passing event=0 to
    // deregister_socket_event would remove key 0 which was never inserted, leaving
    // the actual reverse-map entry (old_event → socket_fd) permanently stale.
    let mut g = socket_event_map();
    eprintln!("weave/WSAEventSelect: map locked");
    let prev_event = if let Some(ref mut map) = *g {
        if mask == 0 || event == 0 {
            // Disarm: remove the entry, capture the previous event handle.
            map.remove(&s).map(|(prev_ev, _)| prev_ev)
        } else {
            // Arm: insert/update.  Capture the previous handle so we can clean
            // up any stale reverse-map entry if the event handle changed.
            map.insert(s, (event, mask as u32))
                .map(|(prev_ev, _)| prev_ev)
        }
    } else {
        None
    };
    eprintln!("weave/WSAEventSelect: map op done prev={:?}", prev_event);
    drop(g);
    eprintln!("weave/WSAEventSelect: map dropped");

    // Update the weave-common reverse map (event_handle → socket_fd).
    if mask != 0 && event != 0 {
        // Arm: register the new event handle.  If the event handle changed,
        // remove the old reverse-map entry first to avoid phantom socket mappings.
        if let Some(prev) = prev_event {
            if prev != event && prev != 0 {
                weave_common::socket_event::deregister_socket_event(prev as u64);
            }
        }
        weave_common::socket_event::register_socket_event(event as u64, s as i32);
    } else {
        // Disarm: deregister using the PREVIOUS event handle.  Passing the new
        // (null) event handle to deregister would miss the actual map entry.
        if let Some(prev) = prev_event {
            if prev != 0 {
                weave_common::socket_event::deregister_socket_event(prev as u64);
            }
        }
        // Also clear edge-triggered write state so a recycled fd doesn't fire
        // a phantom FD_WRITE after being dissociated from its event object.
        weave_common::socket_event::disarm_socket_write(s as i32);
    }
    eprintln!("weave/WSAEventSelect: common cleanup done");

    // Arm FD_WRITE edge-trigger if the caller requested FD_WRITE (0x2) events.
    // Wine ref: dlls/ws2_32/socket.c — WSAEventSelect arms the socket's write-pending
    // state (hmask |= POLLEVENT_WRITE) so FD_WRITE fires once on the initial connect
    // completion, then only again after a send() returns EWOULDBLOCK + buffer drains.
    if (mask & 0x2) != 0 {
        weave_common::socket_event::arm_socket_write(s as i32);
    }
    eprintln!("weave/WSAEventSelect: returning 0");
    0 // success
}

/// WSAWaitForMultipleEvents — wait on one or more WSAEVENT objects.
///
/// Wine ref: include/winsock2.h:1199 —
/// DWORD WINAPI WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT *lphEvents,
///     BOOL fWaitAll, DWORD dwTimeout, BOOL fAlertable);
/// Returns WSA_WAIT_EVENT_0 + index of first signalled event, or
/// WSA_WAIT_FAILED (0xFFFFFFFF) on error.
///
/// Weave: for each event handle, look up the associated socket fd in
/// SOCKET_EVENT_MAP and poll for I/O readiness. The event that becomes ready
/// first determines the return value.
///
/// # Safety
/// `lph_events` must point to `c_events` WSAEVENT handles or be null.
pub unsafe extern "win64" fn wsa_wait_for_multiple_events(
    c_events: u32,
    lph_events: *const usize,
    _f_wait_all: i32,
    dw_timeout: u32,
    _f_alertable: i32,
) -> u32 {
    if c_events == 0 || lph_events.is_null() {
        set_last_error(WSAEINVAL);
        return WSA_WAIT_FAILED;
    }

    // Collect (event_index, socket_fd, mask) for all events we know about.
    let mut pollfds: Vec<libc::pollfd> = Vec::new();
    // Map from pollfd index → event index in lph_events
    let mut pfd_to_event: Vec<u32> = Vec::new();

    {
        let g = socket_event_map();
        let map_opt = g.as_ref();
        for ei in 0..c_events {
            let ev_handle = unsafe { *lph_events.add(ei as usize) };

            // Try socket-backed event: find socket_fd where map[fd] = (ev_handle, _)
            if let Some(map) = map_opt {
                for (&sock_fd, &(ref_handle, _mask)) in map.iter() {
                    if ref_handle == ev_handle {
                        // Edge-triggered FD_WRITE: only include POLLOUT when write is armed.
                        // Wine ref: dlls/ws2_32/socket.c — WFMO wakes only on events in
                        // the socket's pending hmask. Listening sockets and idle connected
                        // sockets always have POLLOUT ready on Linux; including it
                        // unconditionally floods WSAWait with empty wakeups.
                        let mut sock_events = libc::POLLIN | libc::POLLHUP;
                        if weave_common::socket_event::is_socket_write_armed(sock_fd as i32) {
                            sock_events |= libc::POLLOUT;
                        }
                        pollfds.push(libc::pollfd {
                            fd: sock_fd as i32,
                            events: sock_events,
                            revents: 0,
                        });
                        pfd_to_event.push(ei);
                        break;
                    }
                }
            }

            // Try eventfd-backed event (CreateEvent/WSACreateEvent handles).
            #[cfg(target_os = "linux")]
            if let Some(efd) = handles::get_event_fd(ev_handle) {
                pollfds.push(libc::pollfd {
                    fd: efd,
                    events: libc::POLLIN,
                    revents: 0,
                });
                pfd_to_event.push(ei);
            }
        }
    }

    if pollfds.is_empty() {
        // No known events — return event 0 immediately (safe fallback).
        eprintln!("weave/WSAWait: no pollable events, returning WSA_WAIT_EVENT_0");
        return WSA_WAIT_EVENT_0;
    }

    let timeout_ms: i32 = if dw_timeout == 0xFFFF_FFFF {
        -1 // INFINITE → block until ready
    } else {
        dw_timeout.min(i32::MAX as u32) as i32
    };

    eprintln!(
        "weave/WSAWait: polling {} fds timeout={}ms",
        pollfds.len(),
        timeout_ms
    );

    let ret = libc::poll(
        pollfds.as_mut_ptr(),
        pollfds.len() as libc::nfds_t,
        timeout_ms,
    );

    if ret > 0 {
        for (pi, pfd) in pollfds.iter().enumerate() {
            if pfd.revents != 0 {
                let ei = pfd_to_event[pi];
                eprintln!(
                    "weave/WSAWait: event[{ei}] ready (revents={:#x})",
                    pfd.revents
                );
                let result = WSA_WAIT_EVENT_0 + ei;
                eprintln!("weave/WSAWait: returning {result:#x}");
                return result;
            }
        }
    }
    if ret == 0 {
        set_last_error(258); // WSA_WAIT_TIMEOUT
        eprintln!("weave/WSAWait: returning 258 (WSA_WAIT_TIMEOUT)");
        return 258; // WSA_WAIT_TIMEOUT
    }

    eprintln!("weave/WSAWait: returning WSA_WAIT_FAILED ({WSA_WAIT_FAILED:#x})");
    set_last_error(WSAEINVAL);
    WSA_WAIT_FAILED
}

/// WSAEnumNetworkEvents — retrieve and reset socket network events.
///
/// Wine ref: dlls/ws2_32/socket.c:3815 —
/// int WINAPI WSAEnumNetworkEvents(SOCKET s, WSAEVENT event, WSANETWORKEVENTS *ret_events)
/// uses IOCTL_AFD_GET_EVENTS to read which events fired and clears them.
/// WSANETWORKEVENTS layout (from winsock2.h):
///   typedef struct _WSANETWORKEVENTS {
///     long lNetworkEvents;   // offset 0, 4 bytes — bitmask of FD_* events
///     int  iErrorCode[10];   // offset 4, 40 bytes — per-event error codes
///   } WSANETWORKEVENTS;      // total 44 bytes
/// FD_READ=1, FD_WRITE=2, FD_OOB=4, FD_ACCEPT=8, FD_CONNECT=16, FD_CLOSE=32.
///
/// Weave: performs a non-blocking poll(2) on the socket fd to determine what events
/// are actually available, then writes the real bitmask into lNetworkEvents.
///
/// # Safety
/// `lp_network_events` must be null or point to a writable WSANETWORKEVENTS (44 bytes).
pub unsafe extern "win64" fn wsa_enum_network_events(
    s: usize,
    _event: usize,
    lp_network_events: *mut u8,
) -> i32 {
    if lp_network_events.is_null() {
        return 0;
    }

    // Non-blocking poll on the socket fd to get real readiness.
    // IMPORTANT: do NOT touch the caller's struct until we know we have events
    // to write. Gnulib's rpl_select (lib/select.c) seeds lNetworkEvents with
    // 0xDEADBEEF before calling us and then checks whether the sentinel was
    // overwritten to detect "this API actually wrote something". Our earlier
    // unconditional zero-fill destroyed the sentinel even on no-events, which
    // made gnulib take the "events returned, but no match" branch and fall
    // through to an arm-then-wait path that never wakes. Preserve the sentinel
    // on no-events so gnulib's je at rpl_select's inner loop fires and the
    // socket is pushed into the MsgWait handle array directly.
    let mut pfd = libc::pollfd {
        fd: s as i32,
        events: libc::POLLIN | libc::POLLOUT | libc::POLLHUP | libc::POLLRDHUP,
        revents: 0,
    };
    let ret = libc::poll(&mut pfd, 1, 0); // timeout=0 → non-blocking

    if ret <= 0 {
        // No events ready or error — return WITHOUT touching the struct so
        // gnulib's 0xDEADBEEF sentinel stays intact.
        return 0;
    }

    let mut mask: i32 = 0;
    // iErrorCode[FD_CONNECT_BIT=4] value; Some(code) iff FD_CONNECT is set.
    let mut connect_ierr: Option<i32> = None;

    if (pfd.revents & libc::POLLIN) != 0 {
        // Wine ref: dlls/ws2_32/socket.c — sock_get_events: SS_LISTENING sockets
        // map POLLIN to POLLEVENT_ACCEPT (FD_ACCEPT=8); connected sockets map to
        // POLLEVENT_READ (FD_READ=1).
        if weave_common::socket_event::is_socket_listening(s as i32) {
            mask |= 8; // FD_ACCEPT
        } else {
            mask |= 1; // FD_READ
        }
    }
    if (pfd.revents & libc::POLLOUT) != 0 {
        // Wine ref: dlls/ws2_32/socket.c — sock_get_events / get_sock_fd_events:
        // When socket is in SS_CONNECTING state and POLLOUT fires, Wine reports
        // FD_CONNECT (POLLEVENT_CONNECT). After the connect completes the socket
        // transitions to SS_CONNECTED; subsequent POLLOUT maps to FD_WRITE.
        // We mirror this with SOCKET_CONNECTING in weave-common/socket_event.rs.
        if weave_common::socket_event::is_socket_connecting(s as i32) {
            // Confirm connect succeeded via SO_ERROR getsockopt.
            let mut so_err: libc::c_int = 0;
            let mut so_err_len: libc::socklen_t =
                std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = libc::getsockopt(
                s as i32,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_err as *mut libc::c_int as *mut libc::c_void,
                &mut so_err_len,
            );
            let connect_err = if rc == 0 { so_err } else { libc::ECONNREFUSED };
            // Transition out of connecting state regardless of outcome.
            weave_common::socket_event::clear_socket_connecting(s as i32);
            mask |= 0x10; // FD_CONNECT
            connect_ierr = Some(if connect_err == 0 {
                0
            } else {
                errno_to_wsa(connect_err)
            });
        // Do NOT set FD_WRITE on this call — connect completion != write-ready.
        // plink will receive FD_WRITE on the next WSAEnumNetworkEvents call once
        // the socket is in the connected (not connecting) state.
        } else {
            // Connected socket with POLLOUT.
            // Wine ref: server/sock.c:1125 get_poll_flags —
            //   if (event & POLLOUT) flags |= AFD_POLL_WRITE;
            // is unconditional for any non-SOCK_UNCONNECTED socket. Wine does
            // NOT gate AFD_POLL_WRITE on the edge-trigger hmask at this layer;
            // that gating happens one level up in sock_dispatch_events, which
            // filters against the pending-mask AFTER the poll flags have been
            // computed. A connection-mode fd whose send buffer has space must
            // surface FD_WRITE to gnulib/wget on the first WSAEnumNetworkEvents
            // call after connect, otherwise gnulib's rpl_select loop concludes
            // "nothing actionable" and falls into its abort() path.
            //
            // We still disarm SOCKET_WRITE_ARMED after reporting so that WFMO /
            // WSAWaitForMultipleEvents (which include POLLOUT in the poll mask
            // only when armed) do not flood with level-triggered POLLOUT wakes
            // on an idle, connected, send-buffer-empty socket. The arm bit is
            // re-set by ws_send on EWOULDBLOCK/EAGAIN for the drain case.
            mask |= 2; // FD_WRITE
            weave_common::socket_event::disarm_socket_write(s as i32);
        }
    }
    if (pfd.revents & (libc::POLLHUP | libc::POLLRDHUP)) != 0 {
        mask |= 32; // FD_CLOSE
    }

    if weave_core::ws2_trace::enabled() {
        eprintln!(
            "weave/WSAEnumNetworkEvents: socket={s} revents={:#x} mask={mask:#x}",
            pfd.revents
        );
    }

    // If no events to report, leave the struct untouched so gnulib's
    // 0xDEADBEEF sentinel is preserved (see comment at entry).
    if mask == 0 {
        return 0;
    }

    // Events to report: zero the whole 44-byte struct, then write mask at
    // offset 0 and iErrorCode[4] at offset 20 for FD_CONNECT.
    // WSANETWORKEVENTS: long lNetworkEvents (4) + int iErrorCode[10] (40).
    std::ptr::write_bytes(lp_network_events, 0, 44);
    std::ptr::copy_nonoverlapping(mask.to_le_bytes().as_ptr(), lp_network_events, 4);
    if let Some(ierr) = connect_ierr {
        // iErrorCode[FD_CONNECT_BIT=4] at offset 4 + 4*4 = 20.
        std::ptr::copy_nonoverlapping(
            ierr.to_le_bytes().as_ptr(),
            lp_network_events.add(4 + 4 * 4),
            4,
        );
    }
    0 // success
}

// ── Winsock API: additional socket I/O ───────────────────────────────────────

/// sendto — send data to a specific destination (UDP / unconnected sockets).
///
/// Wine ref: dlls/ws2_32/socket.c — WS_sendto translates sockaddr Windows→Linux
/// then calls POSIX sendto(). Flags are passed through unchanged.
///
/// # Safety
/// `buf` must point to `len` readable bytes. `to` must point to a valid sockaddr
/// of `tolen` bytes, or be null for connected sockets.
pub unsafe extern "win64" fn ws_sendto(
    s: usize,
    buf: *const u8,
    len: i32,
    flags: i32,
    to: *const u8,
    tolen: i32,
) -> i32 {
    if to.is_null() || tolen == 0 {
        // Connected socket — use send() path.
        let ret = libc::send(s as i32, buf as *const libc::c_void, len as usize, flags);
        if ret < 0 {
            save_errno();
            return SOCKET_ERROR;
        }
        return ret as i32;
    }
    let addr = copy_sockaddr_win_to_linux(to, tolen as usize);
    let ret = libc::sendto(
        s as i32,
        buf as *const libc::c_void,
        len as usize,
        flags,
        addr.as_ptr() as *const libc::sockaddr,
        tolen as libc::socklen_t,
    );
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        ret as i32
    }
}

/// recvfrom — receive data and capture the sender's address.
///
/// Wine ref: dlls/ws2_32/socket.c — WS_recvfrom translates the returned
/// sockaddr Linux→Windows and updates `fromlen`.
///
/// # Safety
/// `buf` must point to `len` writable bytes. `from` and `fromlen` may be null
/// for callers that don't need the sender's address.
pub unsafe extern "win64" fn ws_recvfrom(
    s: usize,
    buf: *mut u8,
    len: i32,
    flags: i32,
    from: *mut u8,
    fromlen: *mut i32,
) -> i32 {
    let mut linux_len: libc::socklen_t = if !fromlen.is_null() {
        *fromlen as libc::socklen_t
    } else {
        0
    };
    let ret = libc::recvfrom(
        s as i32,
        buf as *mut libc::c_void,
        len as usize,
        flags,
        if from.is_null() {
            std::ptr::null_mut()
        } else {
            from as *mut libc::sockaddr
        },
        if fromlen.is_null() {
            std::ptr::null_mut()
        } else {
            &mut linux_len
        },
    );
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        if !from.is_null() {
            patch_sockaddr_linux_to_win(from, linux_len as usize);
        }
        if !fromlen.is_null() {
            *fromlen = linux_len as i32;
        }
        ret as i32
    }
}

/// inet_pton — convert a presentation-form IP address to binary.
///
/// Wine ref: dlls/ws2_32/socket.c — WS_InetPtonW/A delegate to POSIX inet_pton()
/// with AF family translation (AF_INET6: Win=23 → Linux=10).
///
/// # Safety
/// `src` must be a null-terminated C string. `dst` must be a writable buffer
/// of at least 4 bytes (AF_INET) or 16 bytes (AF_INET6).
// Wine ref: dlls/ws2_32/socket.c — WS_InetPtonA/W translate af then call POSIX inet_pton; returns 1 on success, 0 on invalid input, -1 on AF error (sets WSAEINVAL)
pub unsafe extern "win64" fn ws_inet_pton(af: i32, src: *const u8, dst: *mut u8) -> i32 {
    if src.is_null() || dst.is_null() {
        set_last_error(10014); // WSAEFAULT
        return -1;
    }
    let linux_af = af_win_to_linux(af);
    let ret = inet_pton(
        linux_af,
        src as *const libc::c_char,
        dst as *mut libc::c_void,
    );
    if ret < 0 {
        set_last_error(10047); // WSAEAFNOSUPPORT
    } else if ret == 0 {
        // valid call, invalid address string — no WSA error set on Windows either
    }
    ret
}

/// WSACloseEvent — alias for CloseHandle on a WSAEVENT.
///
/// Wine ref: dlls/ws2_32/socket.c:4000 — WSACloseEvent calls CloseHandle(event).
/// Returns BOOL. Weave: same implementation as WSACloseEventObject — free handle.
///
/// # Safety
/// No pointer arguments.
// Wine ref: dlls/ws2_32/socket.c:4000 — WSACloseEvent(event) calls CloseHandle(event); returns TRUE on success
pub extern "win64" fn wsa_close_event(event: usize) -> i32 {
    // Delegate to WSACloseEventObject (same implementation).
    wsa_close_event_object(event)
}

/// WSAResetEvent — reset (clear) a manual-reset WSAEVENT object.
///
/// Wine ref: dlls/ws2_32/socket.c:4014 — WSAResetEvent calls ResetEvent(event).
/// Weave: clears the eventfd counter by reading it (draining all notifications).
/// Returns BOOL (1 = success, 0 = failure).
///
/// # Safety
/// No pointer arguments.
// Wine ref: dlls/ws2_32/socket.c:4014 — WSAResetEvent calls ResetEvent(hEvent); clears the eventfd counter
pub unsafe extern "win64" fn wsa_reset_event(event: usize) -> i32 {
    #[cfg(target_os = "linux")]
    {
        if let Some(efd) = weave_core::handles::get_event_fd(event) {
            let mut buf = [0u8; 8];
            // Non-blocking drain — ignore EAGAIN (already drained).
            let _ = libc::read(efd, buf.as_mut_ptr() as *mut libc::c_void, 8);
        }
    }
    1 // TRUE
}

/// WSAStringToAddressW — parse a wide string into a SOCKADDR.
///
/// Wine ref: dlls/ws2_32/socket.c — WSAStringToAddressW parses "a.b.c.d[:port]"
/// for AF_INET or "[addr]:port" for AF_INET6 into a SOCKADDR. Stub: return
/// SOCKET_ERROR + WSAEINVAL. curl uses this only when connecting via string
/// address (rare path, not used for example.com lookup).
///
/// # Safety
/// Pointer arguments are not dereferenced.
// Wine ref: dlls/ws2_32/socket.c — WSAStringToAddressW parses dotted-decimal/colon-hex into sockaddr; returns SOCKET_ERROR+WSAEINVAL on parse failure
pub unsafe extern "win64" fn ws_wsa_string_to_address_w(
    _lp_addr_string: *const u16,
    _dw_address_family: i32,
    _lp_protocol_info: *const u8,
    _lp_address: *mut u8,
    _lp_address_length: *mut i32,
) -> i32 {
    set_last_error(10022); // WSAEINVAL
    SOCKET_ERROR
}

/// __WSAFDIsSet — test whether a socket fd is in an fd_set.
///
/// Wine ref: dlls/ws2_32/socket.c — __WSAFDIsSet(SOCKET s, fd_set *set) walks
/// the Windows fd_set counted array and returns non-zero if `s` is found.
///
/// # Safety
/// `set` must be a valid Windows fd_set (counted SOCKET array).
// Wine ref: dlls/ws2_32/socket.c — __WSAFDIsSet walks the Windows fd_set array (count + SOCKET[FD_SETSIZE]) and returns 1 if the socket is found
pub unsafe extern "win64" fn ws_fd_is_set(s: usize, set: *const u8) -> i32 {
    if set.is_null() {
        return 0;
    }
    let count = *(set as *const u32) as usize;
    let arr = set.add(8); // skip count(4) + padding(4)
    for i in 0..count.min(WIN_FD_SETSIZE) {
        let sock = *(arr.add(i * 8) as *const usize);
        if sock == s {
            return 1;
        }
    }
    0
}

// ── Signal gap-fill: WS2_32 Phase A stubs ────────────────────────────────────
//
// jcodemunch unavailable — Phase A stubs only, safe sentinel returns.
// Wine ref comments deferred to jcodemunch-available session.

// ── AddrInfo family ────────────────────────────────────────────────────────────

/// FreeAddrInfoExW: free extended address info (getaddrinfo family).
///
/// Phase A stub — no-op.
///
/// # Safety
/// `addr_info` is accepted but not dereferenced.
pub unsafe extern "win64" fn free_addr_info_ex_w(_addr_info: *mut u8) {}

/// FreeAddrInfoW: free address info (wide variant of freeaddrinfo).
///
/// Delegates to the real `ws_freeaddrinfo` implementation.
///
/// # Safety
/// `p_addr_info` must be a pointer previously returned by `GetAddrInfoW`,
/// or null.
pub unsafe extern "win64" fn free_addr_info_w(p_addr_info: *mut WinAddrInfo) {
    ws_freeaddrinfo(p_addr_info);
}

/// GetAddrInfoExCancel: cancel an async GetAddrInfoExW request.
///
/// Phase A stub — returns WSASYSNOTREADY.
pub unsafe extern "win64" fn get_addr_info_ex_cancel(
    _cancel_handle: usize,
) -> i32 {
    SOCKET_ERROR
}

/// GetAddrInfoExW: extended async getaddrinfo (wide).
///
/// Phase A stub — returns WSASYSNOTREADY.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
pub unsafe extern "win64" fn get_addr_info_ex_w(
    _node_name: *const u16,
    _service_name: *const u16,
    _dw_namespace: u32,
    _lp_nsp_id: usize,
    _hints: *const u8,
    _results: *mut u8,
    _timeout: usize,
    _overlapped: usize,
    _completion_routine: usize,
    _handle: *mut usize,
) -> i32 {
    SOCKET_ERROR
}

/// GetAddrInfoW: wide-char getaddrinfo.
///
/// Converts UTF-16 node/service names to UTF-8 byte strings and delegates
/// to the real `ws_getaddrinfo` implementation.
///
/// # Safety
/// `p_node_name` and `p_service_name` must be valid null-terminated UTF-16
/// strings or null. `p_hints` may be null. `pp_result` must be a valid
/// non-null pointer.
pub unsafe extern "win64" fn get_addr_info_w(
    p_node_name: *const u16,
    p_service_name: *const u16,
    p_hints: *const WinAddrInfo,
    pp_result: *mut *mut WinAddrInfo,
) -> i32 {
    if pp_result.is_null() {
        return 10014; // WSAEFAULT
    }

    let node_cstr = if p_node_name.is_null() {
        None
    } else {
        let len = (0..).take_while(|&i| *p_node_name.add(i) != 0).count();
        let slice = std::slice::from_raw_parts(p_node_name, len);
        let utf8 = String::from_utf16_lossy(slice);
        Some(CString::new(utf8).unwrap_or_else(|_| CString::new("").unwrap()))
    };

    let service_cstr = if p_service_name.is_null() {
        None
    } else {
        let len = (0..).take_while(|&i| *p_service_name.add(i) != 0).count();
        let slice = std::slice::from_raw_parts(p_service_name, len);
        let utf8 = String::from_utf16_lossy(slice);
        Some(CString::new(utf8).unwrap_or_else(|_| CString::new("").unwrap()))
    };

    let node_ptr = node_cstr.as_ref().map_or(std::ptr::null(), |c| {
        c.as_ptr() as *const u8
    });
    let service_ptr = service_cstr.as_ref().map_or(std::ptr::null(), |c| {
        c.as_ptr() as *const u8
    });

    ws_getaddrinfo(node_ptr, service_ptr, p_hints, pp_result)
}

/// GetNameInfoW: wide-char getnameinfo.
///
/// Translates sockaddr from Windows to Linux format, calls libc::getnameinfo(),
/// then converts the result to UTF-16 wide strings.
///
/// Returns 0 on success, SOCKET_ERROR on failure.
///
/// # Safety
/// `sa` must point to a valid sockaddr of `sa_len` bytes.
/// `host` must point to a writable buffer of `host_len` wide chars (or be null).
/// `serv` must point to a writable buffer of `serv_len` wide chars (or be null).
pub unsafe extern "win64" fn get_name_info_w(
    sa: *const u8,
    sa_len: u32,
    host: *mut u16,
    host_len: u32,
    serv: *mut u16,
    serv_len: u32,
    flags: i32,
) -> i32 {
    const NI_MAXHOST: usize = 1025;
    const NI_MAXSERV: usize = 32;

    if sa.is_null() {
        set_last_error(10014); // WSAEFAULT
        return SOCKET_ERROR;
    }

    let addr = copy_sockaddr_win_to_linux(sa, sa_len as usize);

    let mut host_bytes = vec![0u8; NI_MAXHOST];
    let mut serv_bytes = vec![0u8; NI_MAXSERV];

    let ret = libc::getnameinfo(
        addr.as_ptr() as *const libc::sockaddr,
        sa_len as libc::socklen_t,
        host_bytes.as_mut_ptr() as *mut libc::c_char,
        NI_MAXHOST as u32,
        serv_bytes.as_mut_ptr() as *mut libc::c_char,
        NI_MAXSERV as u32,
        flags,
    );

    if ret != 0 {
        save_errno();
        set_last_error(ret);
        return SOCKET_ERROR;
    }

    // Convert UTF-8 result to UTF-16 and copy into caller's buffers.
    if !host.is_null() && host_len > 0 {
        let end = host_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(NI_MAXHOST);
        let utf8 = std::str::from_utf8(&host_bytes[..end]).unwrap_or("");
        let wide: Vec<u16> = utf8.encode_utf16().collect();
        let to_copy = wide.len().min((host_len - 1) as usize);
        std::ptr::copy_nonoverlapping(wide.as_ptr(), host, to_copy);
        *host.add(to_copy) = 0;
    }

    if !serv.is_null() && serv_len > 0 {
        let end = serv_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(NI_MAXSERV);
        let utf8 = std::str::from_utf8(&serv_bytes[..end]).unwrap_or("");
        let wide: Vec<u16> = utf8.encode_utf16().collect();
        let to_copy = wide.len().min((serv_len - 1) as usize);
        std::ptr::copy_nonoverlapping(wide.as_ptr(), serv, to_copy);
        *serv.add(to_copy) = 0;
    }

    0
}

// ── Overlapped I/O ─────────────────────────────────────────────────────────────

/// `WSABUF` — scatter/gather buffer descriptor used by WSASend/WSARecv.
///
/// Layout on x64: `{ u32 len, u32 pad, *mut u8 buf }` = 16 bytes.
/// `#[repr(C)]` produces the correct alignment (8-byte aligned pointer after
/// 4-byte len + 4-byte padding), matching MSVC's default packing.
#[repr(C)]
struct WSABUF {
    len: u32,
    buf: *mut u8,
}

/// WSARecv: overlapped receive from a socket.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
pub unsafe extern "win64" fn wsa_recv(
    _s: usize,
    _buffers: *mut u8,
    _dw_buffer_count: u32,
    _lp_number_of_bytes_recvd: *mut u32,
    _lp_flags: *mut u32,
    _lp_overlapped: usize,
    _lp_completion_routine: usize,
) -> i32 {
    eprintln!("weave/ws2_stub: WSARecv");
    SOCKET_ERROR
}

/// WSARecvFrom: overlapped receive from, with source address.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
pub unsafe extern "win64" fn wsa_recv_from(
    _s: usize,
    _buffers: *mut u8,
    _dw_buffer_count: u32,
    _lp_number_of_bytes_recvd: *mut u32,
    _lp_flags: *mut u32,
    _lp_from: *mut u8,
    _lp_from_len: *mut i32,
    _lp_overlapped: usize,
    _lp_completion_routine: usize,
) -> i32 {
    eprintln!("weave/ws2_stub: WSARecvFrom");
    SOCKET_ERROR
}

/// WSASend: overlapped send on a socket.
///
/// Phase B — supports synchronous mode (lp_overlapped == NULL).
/// Overlapped mode returns WSAEOPNOTSUPP with a warning.
///
/// Gather-writes over the WSABUF array using repeated libc::send calls.
/// On EWOULDBLOCK/EAGAIN, re-arms FD_WRITE (edge-triggered contract).
/// On intermediate-buffer failure after partial progress, reports
/// accumulated bytes_sent and returns SOCKET_ERROR.
///
/// Wine ref: dlls/ws2_32/socket.c — zero-buffer-count sends an empty
/// datagram (MSG_EOF-equivalent) via a zero-length send call. The
/// EWOULDBLOCK re-arm matches the existing ws_send pattern.
///
/// # Safety
/// Caller must ensure lp_buffers is valid for dw_buffer_count WSABUF entries,
/// and lp_number_of_bytes_sent points to a valid u32.
pub unsafe extern "win64" fn wsa_send(
    s: usize,
    lp_buffers: *mut u8,
    dw_buffer_count: u32,
    lp_number_of_bytes_sent: *mut u32,
    dw_flags: u32,
    lp_overlapped: usize,
    _lp_completion_routine: usize,
) -> i32 {
    if weave_core::ws2_trace::enabled() {
        eprintln!(
            "weave/ws2: WSASend s={s} count={dw_buffer_count} flags={dw_flags:#x} overlapped={lp_overlapped}"
        );
    }

    // lp_number_of_bytes_sent must be non-null.
    if lp_number_of_bytes_sent.is_null() {
        set_last_error(10014); // WSAEFAULT
        return SOCKET_ERROR;
    }

    // Overlapped mode is async; not supported in Phase B.
    if lp_overlapped != 0 {
        eprintln!("weave/ws2_stub: WSASend overlapped mode not supported");
        set_last_error(10045); // WSAEOPNOTSUPP
        return SOCKET_ERROR;
    }

    // Synchronous gather-write.
    let buffers = lp_buffers as *const WSABUF;
    let mut total_sent: u32 = 0;

    if dw_buffer_count == 0 {
        // Wine ref: dlls/ws2_32/socket.c — zero buffers sends an empty datagram.
        let ret = libc::send(s as i32, std::ptr::null(), 0, 0);
        if ret < 0 {
            let e = *libc::__errno_location();
            if e == libc::EWOULDBLOCK || e == libc::EAGAIN {
                weave_common::socket_event::arm_socket_write(s as i32);
            }
            save_errno();
            return SOCKET_ERROR;
        }
        *lp_number_of_bytes_sent = 0;
        return 0;
    }

    for i in 0..dw_buffer_count as usize {
        let buf = buffers.add(i).read();
        let ret = libc::send(
            s as i32,
            buf.buf as *const libc::c_void,
            buf.len as usize,
            dw_flags as i32,
        );
        if ret < 0 {
            let e = *libc::__errno_location();
            // Re-arm FD_WRITE edge trigger when send buffer is full.
            if e == libc::EWOULDBLOCK || e == libc::EAGAIN {
                weave_common::socket_event::arm_socket_write(s as i32);
            }
            // Report partial progress on intermediate failure.
            *lp_number_of_bytes_sent = total_sent;
            save_errno();
            return SOCKET_ERROR;
        }
        total_sent += ret as u32;
    }

    *lp_number_of_bytes_sent = total_sent;
    0
}

/// WSASendTo: overlapped sendto, with destination address.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid.
pub unsafe extern "win64" fn wsa_send_to(
    _s: usize,
    _buffers: *mut u8,
    _dw_buffer_count: u32,
    _lp_number_of_bytes_sent: *mut u32,
    _dw_flags: u32,
    _lp_to: *const u8,
    _i_to_len: i32,
    _lp_overlapped: usize,
    _lp_completion_routine: usize,
) -> i32 {
    eprintln!("weave/ws2_stub: WSASendTo");
    SOCKET_ERROR
}

/// WSAGetOverlappedResult: get result of an overlapped operation.
///
/// Phase A stub — returns FALSE (not completed).
///
/// # Safety
/// Caller must ensure `lp_overlapped` and `lpcb_transfer` are valid.
pub unsafe extern "win64" fn wsa_get_overlapped_result(
    _s: usize,
    _lp_overlapped: usize,
    _lpcb_transfer: *mut u32,
    _f_wait: i32,
    _lpdw_flags: *mut u32,
) -> i32 {
    0
}

// ── Socket Management ──────────────────────────────────────────────────────────

/// WSADuplicateSocketW: create a socket descriptor for a target process.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// `lp_protocol_info` is accepted but not dereferenced.
pub unsafe extern "win64" fn wsa_duplicate_socket_w(
    _s: usize,
    _dw_process_id: u32,
    _lp_protocol_info: *mut u8,
) -> i32 {
    eprintln!("weave/ws2_stub: WSADuplicateSocketW");
    SOCKET_ERROR
}

/// WSAEnumProtocolsW: enumerate available network protocols.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// `lp_protocol_buffer` and `lpdw_buffer_length` are accepted but not dereferenced.
pub unsafe extern "win64" fn wsa_enum_protocols_w(
    _lpi_protocols: *mut i32,
    _lp_protocol_buffer: *mut u8,
    _lpdw_buffer_length: *mut u32,
) -> i32 {
    eprintln!("weave/ws2_stub: WSAEnumProtocolsW");
    SOCKET_ERROR
}

/// WSASetEvent: set a WSAEVENT object to signaled state.
///
/// Phase A stub — returns FALSE.
pub extern "win64" fn wsa_set_event(_event: usize) -> i32 {
    eprintln!("weave/ws2_stub: WSASetEvent");
    0
}

// ── Service Discovery ──────────────────────────────────────────────────────────

/// WSALookupServiceBeginW: begin a service discovery query.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// `lpqs_restrictions`, `lpsz_service_instance`, and `lp_lookup_handle` are
/// accepted but not dereferenced.
pub unsafe extern "win64" fn wsa_lookup_service_begin_w(
    _lpqs_restrictions: *const u8,
    _dw_control_flags: u32,
    _lp_lookup_handle: *mut usize,
) -> i32 {
    eprintln!("weave/ws2_stub: WSALookupServiceBeginW");
    SOCKET_ERROR
}

/// WSALookupServiceNextW: retrieve next service discovery result.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// `lpqs_results` and `lpdw_buffer_length` are accepted but not dereferenced.
pub unsafe extern "win64" fn wsa_lookup_service_next_w(
    _lookup_handle: usize,
    _dw_control_flags: u32,
    _lpqs_results: *mut u8,
    _lpdw_buffer_length: *mut u32,
) -> i32 {
    eprintln!("weave/ws2_stub: WSALookupServiceNextW");
    SOCKET_ERROR
}

/// WSALookupServiceEnd: end a service discovery query.
///
/// Phase A stub — returns SOCKET_ERROR.
pub extern "win64" fn wsa_lookup_service_end(_lookup_handle: usize) -> i32 {
    eprintln!("weave/ws2_stub: WSALookupServiceEnd");
    SOCKET_ERROR
}

/// WSASetServiceW: register or unregister a service instance.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// `lpqs_reg_info` is accepted but not dereferenced.
pub unsafe extern "win64" fn wsa_set_service_w(
    _lpqs_reg_info: *const u8,
    _ess_operation: u32,
    _dw_control_flags: u32,
) -> i32 {
    eprintln!("weave/ws2_stub: WSASetServiceW");
    SOCKET_ERROR
}

// ── Ordinal stubs (WS2 extension ordinals imported by Signal) ──────────────

/// #112 (WSAEnumProtocolsA): enumerate protocols (ANSI).
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// `lp_protocol_buffer` and `lpdw_buffer_length` are accepted but not dereferenced.
pub unsafe extern "win64" fn wsa_enum_protocols_a(
    _lpi_protocols: *mut i32,
    _lp_protocol_buffer: *mut u8,
    _lpdw_buffer_length: *mut u32,
) -> i32 {
    eprintln!("weave/ws2_stub: WSAEnumProtocolsA (#112)");
    SOCKET_ERROR
}

/// #115 (WSCEnumProtocols): enumerate catalog protocols.
///
/// Phase A stub — returns SOCKET_ERROR.
///
/// # Safety
/// `lp_protocols` and `lp_protocol_buffer` and `lpdw_buffer_length` are accepted but not dereferenced.
pub unsafe extern "win64" fn wsc_enum_protocols(
    _lpi_protocols: *mut i32,
    _lp_protocol_buffer: *mut u8,
    _lpdw_buffer_length: *mut u32,
) -> i32 {
    eprintln!("weave/ws2_stub: WSCEnumProtocols (#115)");
    SOCKET_ERROR
}

// ── WSAPoll ────────────────────────────────────────────────────────────────────

/// Layout-compatible with Windows `WSAPOLLFD` (Win64).
///
/// SOCKET is pointer-sized (8 bytes on x64), followed by i16 events/revents.
/// Total size: 12 bytes. NOT layout-compatible with `libc::pollfd` (8 bytes on x86-64).
#[repr(C)]
pub struct WSAPOLLFD {
    fd: i64,
    events: i16,
    revents: i16,
}

/// WSAPoll: Winsock equivalent of POSIX poll(2).
///
/// Iterates the `WSAPOLLFD` array, skips entries whose fd is `INVALID_SOCKET`,
/// builds a temporary `libc::pollfd` array, calls `libc::poll()`, and writes
/// the resulting revents back to the original `WSAPOLLFD` entries.
///
/// Returns the number of ready fds (same as libc::poll), or `SOCKET_ERROR` on
/// failure with the last error set via `save_errno()`.
///
/// # Safety
/// Caller must ensure `fd_array` points to at least `nfds` valid `WSAPOLLFD`
/// entries when `nfds > 0`.
pub unsafe extern "win64" fn ws_wsa_poll(
    fd_array: *mut WSAPOLLFD,
    nfds: u32,
    timeout: i32,
) -> i32 {
    if nfds == 0 {
        return 0;
    }

    if fd_array.is_null() {
        set_last_error(10014); // WSAEFAULT
        return SOCKET_ERROR;
    }

    // Build a compact libc::pollfd array, skipping INVALID_SOCKET entries.
    let count = nfds as usize;
    let slice = unsafe { std::slice::from_raw_parts_mut(fd_array, count) };

    let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(count);
    for entry in slice.iter() {
        if entry.fd == INVALID_SOCKET as i64 {
            continue;
        }
        pfds.push(libc::pollfd {
            fd: entry.fd as libc::c_int,
            events: entry.events as i16,
            revents: 0,
        });
    }

    if pfds.is_empty() {
        return 0;
    }

    let ret = libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout);
    if ret < 0 {
        save_errno();
        return SOCKET_ERROR;
    }

    // Write revents back to the matching WSAPOLLFD entries.
    let mut pfd_idx = 0;
    for entry in slice.iter_mut() {
        if entry.fd == INVALID_SOCKET as i64 {
            entry.revents = 0;
            continue;
        }
        entry.revents = pfds[pfd_idx].revents as i16;
        pfd_idx += 1;
    }

    ret
}

// ── DLL Resolver ─────────────────────────────────────────────────────────────

/// Resolve a ws2_32.dll or wsock32.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("ws2_32.dll") && !dll.eq_ignore_ascii_case("wsock32.dll") {
        return None;
    }

    match func {
        "WSAStartup" => Some(wsa_startup as *const () as usize),
        "WSACleanup" => Some(wsa_cleanup as *const () as usize),
        "WSAGetLastError" => Some(wsa_get_last_error as *const () as usize),
        "WSASetLastError" => Some(wsa_set_last_error as *const () as usize),
        "socket" => Some(ws_socket as *const () as usize),
        "closesocket" => Some(ws_closesocket as *const () as usize),
        "connect" => Some(ws_connect as *const () as usize),
        "send" => Some(ws_send as *const () as usize),
        "recv" => Some(ws_recv as *const () as usize),
        "bind" => Some(ws_bind as *const () as usize),
        "listen" => Some(ws_listen as *const () as usize),
        "accept" => Some(ws_accept as *const () as usize),
        "shutdown" => Some(ws_shutdown as *const () as usize),
        "getpeername" => Some(ws_getpeername as *const () as usize),
        "getsockname" => Some(ws_getsockname as *const () as usize),
        "select" => Some(ws_select as *const () as usize),
        "getaddrinfo" => Some(ws_getaddrinfo as *const () as usize),
        "freeaddrinfo" => Some(ws_freeaddrinfo as *const () as usize),
        "ioctlsocket" => Some(ws_ioctlsocket as *const () as usize),
        "setsockopt" => Some(ws_setsockopt as *const () as usize),
        "getsockopt" => Some(ws_getsockopt as *const () as usize),
        "htons" => Some(ws_htons as *const () as usize),
        "htonl" => Some(ws_htonl as *const () as usize),
        "ntohs" => Some(ws_ntohs as *const () as usize),
        "ntohl" => Some(ws_ntohl as *const () as usize),
        "inet_addr" => Some(ws_inet_addr as *const () as usize),
        // Legacy name-resolution (M3 — plink/PuTTY).
        "gethostname" => Some(ws_gethostname as *const () as usize),
        "gethostbyname" => Some(ws_gethostbyname as *const () as usize),
        "getservbyname" => Some(ws_getservbyname as *const () as usize),
        "inet_ntoa" => Some(ws_inet_ntoa as *const () as usize),
        "inet_ntop" => Some(ws_inet_ntop as *const () as usize),
        "getnameinfo" => Some(ws_getnameinfo as *const () as usize),
        "WSAAddressToStringA" => Some(ws_wsa_address_to_string_a as *const () as usize),
        "WSAIoctl" => Some(ws_wsa_ioctl as *const () as usize),
        "WSAAsyncSelect" => Some(ws_wsa_async_select as *const () as usize),
        // Async-event stubs (M3 — PuTTY SSH engine).
        "WSACreateEvent" => Some(wsa_create_event as *const () as usize),
        "WSACloseEventObject" => Some(wsa_close_event_object as *const () as usize),
        "WSAEventSelect" => Some(wsa_event_select as *const () as usize),
        "WSAWaitForMultipleEvents" => Some(wsa_wait_for_multiple_events as *const () as usize),
        "WSAEnumNetworkEvents" => Some(wsa_enum_network_events as *const () as usize),
        // Additional socket I/O (curl — Task 01).
        "sendto" => Some(ws_sendto as *const () as usize),
        "recvfrom" => Some(ws_recvfrom as *const () as usize),
        "inet_pton" => Some(ws_inet_pton as *const () as usize),
        "WSACloseEvent" => Some(wsa_close_event as *const () as usize),
        "WSAResetEvent" => Some(wsa_reset_event as *const () as usize),
        "WSAStringToAddressW" => Some(ws_wsa_string_to_address_w as *const () as usize),
        "__WSAFDIsSet" => Some(ws_fd_is_set as *const () as usize),
        // WSASocket variants (curl — loopback socket-pair setup).
        "WSASocketW" => Some(ws_wsa_socket_w as *const () as usize),
        "WSASocketA" => Some(ws_wsa_socket_a as *const () as usize),
        // ── Signal gap-fill: 18 named + 28 ordinal WS2_32 stubs ──
        // AddrInfo family
        "FreeAddrInfoExW" => Some(free_addr_info_ex_w as *const () as usize),
        "FreeAddrInfoW" => Some(free_addr_info_w as *const () as usize),
        "GetAddrInfoExCancel" => Some(get_addr_info_ex_cancel as *const () as usize),
        "GetAddrInfoExW" => Some(get_addr_info_ex_w as *const () as usize),
        "GetAddrInfoW" => Some(get_addr_info_w as *const () as usize),
        "GetNameInfoW" => Some(get_name_info_w as *const () as usize),
        // Overlapped I/O
        "WSARecv" => Some(wsa_recv as *const () as usize),
        "WSARecvFrom" => Some(wsa_recv_from as *const () as usize),
        "WSASend" => Some(wsa_send as *const () as usize),
        "WSASendTo" => Some(wsa_send_to as *const () as usize),
        "WSAGetOverlappedResult" => Some(wsa_get_overlapped_result as *const () as usize),
        // Socket management
        "WSADuplicateSocketW" => Some(wsa_duplicate_socket_w as *const () as usize),
        "WSAEnumProtocolsW" => Some(wsa_enum_protocols_w as *const () as usize),
        "WSASetEvent" => Some(wsa_set_event as *const () as usize),
        // Socket polling (Electron/Chromium — async I/O multiplexing).
        "WSAPoll" => Some(
            ws_wsa_poll as unsafe extern "win64" fn(*mut WSAPOLLFD, u32, i32) -> i32
                as *const () as usize,
        ),
        // Service discovery
        "WSALookupServiceBeginW" => Some(wsa_lookup_service_begin_w as *const () as usize),
        "WSALookupServiceEnd" => Some(wsa_lookup_service_end as *const () as usize),
        "WSALookupServiceNextW" => Some(wsa_lookup_service_next_w as *const () as usize),
        "WSASetServiceW" => Some(wsa_set_service_w as *const () as usize),
        // Ordinal aliases (classic Winsock 1.1 — map to existing implementations)
        "#1" => Some(ws_socket as *const () as usize),
        "#2" => Some(ws_connect as *const () as usize),
        "#3" => Some(ws_closesocket as *const () as usize),
        "#4" => Some(ws_accept as *const () as usize),
        "#5" => Some(ws_listen as *const () as usize),
        "#6" => Some(ws_bind as *const () as usize),
        "#7" => Some(ws_select as *const () as usize),
        "#8" => Some(ws_getpeername as *const () as usize),
        "#9" => Some(ws_getsockname as *const () as usize),
        "#10" => Some(ws_getsockopt as *const () as usize),
        "#11" => Some(ws_htonl as *const () as usize),
        "#12" => Some(ws_htons as *const () as usize),
        "#13" => Some(ws_ioctlsocket as *const () as usize),
        "#14" => Some(ws_inet_addr as *const () as usize),
        "#15" => Some(ws_inet_ntoa as *const () as usize),
        "#16" => Some(ws_ntohl as *const () as usize),
        "#17" => Some(ws_ntohs as *const () as usize),
        "#18" => Some(ws_recv as *const () as usize),
        "#19" => Some(ws_recvfrom as *const () as usize),
        "#20" => Some(ws_send as *const () as usize),
        "#21" => Some(ws_sendto as *const () as usize),
        "#22" => Some(ws_setsockopt as *const () as usize),
        "#23" => Some(ws_shutdown as *const () as usize),
        "#57" => Some(ws_gethostname as *const () as usize),
        // Ordinal stubs (WS2 extension — not yet implemented by name).
        "#111" => Some(wsa_enum_protocols_w as *const () as usize),
        "#112" => Some(wsa_enum_protocols_a as *const () as usize),
        "#115" => Some(wsc_enum_protocols as *const () as usize),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn af_translation_ipv6() {
        assert_eq!(af_win_to_linux(23), 10);
        assert_eq!(af_linux_to_win(10), 23);
    }

    #[test]
    fn af_translation_ipv4_unchanged() {
        assert_eq!(af_win_to_linux(2), 2);
        assert_eq!(af_linux_to_win(2), 2);
    }

    #[test]
    fn af_translation_unspec_unchanged() {
        assert_eq!(af_win_to_linux(0), 0);
        assert_eq!(af_linux_to_win(0), 0);
    }

    #[test]
    fn sockopt_level_translation() {
        assert_eq!(translate_sockopt_level(0xFFFF), 1); // SOL_SOCKET
        assert_eq!(translate_sockopt_level(6), 6); // IPPROTO_TCP unchanged
    }

    #[test]
    fn sockopt_name_translation() {
        assert_eq!(translate_sockopt_name(0xFFFF, 0x0004), 2); // SO_REUSEADDR
        assert_eq!(translate_sockopt_name(0xFFFF, 0x0008), 9); // SO_KEEPALIVE
        assert_eq!(translate_sockopt_name(0xFFFF, 0x1001), 7); // SO_SNDBUF
        assert_eq!(translate_sockopt_name(0xFFFF, 0x1002), 8); // SO_RCVBUF
        assert_eq!(translate_sockopt_name(6, 1), 1); // TCP_NODELAY unchanged
    }

    #[test]
    fn byte_order_roundtrip() {
        assert_eq!(ws_ntohs(ws_htons(0x1234)), 0x1234);
        assert_eq!(ws_ntohl(ws_htonl(0x12345678)), 0x12345678);
    }

    #[test]
    fn htons_known_value() {
        // Port 80 = 0x0050. In network byte order on little-endian: 0x5000.
        assert_eq!(ws_htons(80), 0x5000);
    }

    #[test]
    fn resolve_known_ws2_functions() {
        let funcs = [
            "WSAStartup",
            "WSACleanup",
            "WSAGetLastError",
            "WSASetLastError",
            "socket",
            "closesocket",
            "connect",
            "send",
            "recv",
            "bind",
            "listen",
            "accept",
            "shutdown",
            "getpeername",
            "getsockname",
            "select",
            "getaddrinfo",
            "freeaddrinfo",
            "ioctlsocket",
            "setsockopt",
            "getsockopt",
            "htons",
            "htonl",
            "ntohs",
            "ntohl",
            "inet_addr",
            "gethostname",
            "gethostbyname",
            "getservbyname",
            "inet_ntoa",
            "inet_ntop",
            "getnameinfo",
            "WSAAddressToStringA",
            "WSAIoctl",
            "WSAAsyncSelect",
            "WSASocketW",
            "WSASocketA",
        ];
        for f in &funcs {
            assert!(resolve("ws2_32.dll", f).is_some(), "missing {f}");
        }
    }

    #[test]
    fn resolve_wsock32_alias() {
        assert!(resolve("wsock32.dll", "socket").is_some());
        assert!(resolve("wsock32.dll", "WSAStartup").is_some());
    }

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "socket").is_none());
    }

    #[test]
    fn resolve_unknown_function() {
        assert!(resolve("ws2_32.dll", "__nonexistent__").is_none());
    }

    #[test]
    fn resolve_signal_gap_fill_stubs() {
        let named = [
            "FreeAddrInfoExW",
            "FreeAddrInfoW",
            "GetAddrInfoExCancel",
            "GetAddrInfoExW",
            "GetAddrInfoW",
            "GetNameInfoW",
            "WSARecv",
            "WSARecvFrom",
            "WSASend",
            "WSASendTo",
            "WSAGetOverlappedResult",
            "WSADuplicateSocketW",
            "WSAEnumProtocolsW",
            "WSASetEvent",
            "WSALookupServiceBeginW",
            "WSALookupServiceEnd",
            "WSALookupServiceNextW",
            "WSASetServiceW",
        ];
        let ordinals = [
            "#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10",
            "#11", "#12", "#13", "#14", "#15", "#16", "#17", "#18", "#19",
            "#20", "#21", "#22", "#23", "#57", "#111", "#112", "#115",
        ];
        for &name in &named {
            assert!(
                resolve("ws2_32.dll", name).is_some(),
                "ws2_32.dll!{name} must resolve"
            );
        }
        for &ord in &ordinals {
            assert!(
                resolve("ws2_32.dll", ord).is_some(),
                "ws2_32.dll!{ord} must resolve"
            );
        }
    }

    // ── FD_WRITE / sync-connect arming regression tests ────────────────────
    //
    // These exercise the Wine server/sock.c:1125 get_poll_flags alignment:
    //   - A connected socket with POLLOUT must surface FD_WRITE regardless
    //     of whether SOCKET_WRITE_ARMED was previously set (matches Wine's
    //     unconditional `if (event & POLLOUT) flags |= AFD_POLL_WRITE`).
    //   - A synchronous ws_connect success path must record the terminal
    //     SOCKET_WRITE_ARMED state so WFMO (which gates POLLOUT on the arm
    //     bit to avoid flood wake-ups) includes POLLOUT on the first wait.
    //
    // The tests run on Linux (sockets) and are skipped on macOS.

    #[cfg(target_os = "linux")]
    #[test]
    fn sync_connect_arms_fd_write() {
        // Bring up a listener on 127.0.0.1:ephemeral, then ws_connect to it.
        // After the sync success return, is_socket_write_armed(fd) must be true.
        unsafe {
            let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(listener >= 0);
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as u16;
            addr.sin_port = 0;
            addr.sin_addr.s_addr = u32::to_be(0x7F000001);
            assert_eq!(
                libc::bind(
                    listener,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                ),
                0
            );
            assert_eq!(libc::listen(listener, 1), 0);
            let mut out_addr: libc::sockaddr_in = std::mem::zeroed();
            let mut out_len: u32 = std::mem::size_of::<libc::sockaddr_in>() as u32;
            assert_eq!(
                libc::getsockname(
                    listener,
                    &mut out_addr as *mut _ as *mut libc::sockaddr,
                    &mut out_len,
                ),
                0
            );

            let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(client >= 0);

            // Build a Windows-layout sockaddr_in (same 16-byte layout as Linux
            // for AF_INET so copy_sockaddr_win_to_linux is an identity copy).
            let mut win_addr = [0u8; 16];
            win_addr[0] = libc::AF_INET as u8;
            win_addr[1] = 0;
            win_addr[2..4].copy_from_slice(&out_addr.sin_port.to_ne_bytes());
            win_addr[4..8].copy_from_slice(&out_addr.sin_addr.s_addr.to_ne_bytes());

            // Ensure pre-state is NOT armed.
            weave_common::socket_event::disarm_socket_write(client);
            assert!(!weave_common::socket_event::is_socket_write_armed(client));

            let rc = ws_connect(client as usize, win_addr.as_ptr(), 16);
            assert_eq!(rc, 0, "ws_connect to local listener should succeed");
            assert!(
                weave_common::socket_event::is_socket_write_armed(client),
                "sync ws_connect success must arm FD_WRITE",
            );
            assert!(
                !weave_common::socket_event::is_socket_connecting(client),
                "sync ws_connect success must clear the connecting state",
            );

            libc::close(client);
            libc::close(listener);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn connected_pollout_yields_fd_write_even_when_disarmed() {
        // Wine's server/sock.c get_poll_flags emits AFD_POLL_WRITE unconditionally
        // on POLLOUT for connection-mode sockets. Verify our wsa_enum_network_events
        // mirrors this: a connected socket with an empty send buffer + no prior arm
        // must still report FD_WRITE (mask bit 0x2) to the caller.
        unsafe {
            let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(listener >= 0);
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as u16;
            addr.sin_port = 0;
            addr.sin_addr.s_addr = u32::to_be(0x7F000001);
            assert_eq!(
                libc::bind(
                    listener,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                ),
                0
            );
            assert_eq!(libc::listen(listener, 1), 0);
            let mut out_addr: libc::sockaddr_in = std::mem::zeroed();
            let mut out_len: u32 = std::mem::size_of::<libc::sockaddr_in>() as u32;
            assert_eq!(
                libc::getsockname(
                    listener,
                    &mut out_addr as *mut _ as *mut libc::sockaddr,
                    &mut out_len,
                ),
                0
            );

            let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(client >= 0);
            assert_eq!(
                libc::connect(
                    client,
                    &out_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                ),
                0
            );

            // Force the socket into the "connected, not armed, not connecting,
            // not listening" state — the exact condition that previously made
            // wsa_enum_network_events swallow POLLOUT and return mask=0.
            weave_common::socket_event::disarm_socket_write(client);
            weave_common::socket_event::clear_socket_connecting(client);
            weave_common::socket_event::unmark_socket_listening(client);

            // WSANETWORKEVENTS = 44 bytes. Seed with gnulib's 0xDEADBEEF sentinel.
            let mut events = [0u8; 44];
            events[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

            let rc = wsa_enum_network_events(client as usize, 0, events.as_mut_ptr());
            assert_eq!(rc, 0);

            let mask = u32::from_le_bytes([events[0], events[1], events[2], events[3]]);
            assert!(
                mask & 0x2 != 0,
                "connected socket with POLLOUT must surface FD_WRITE (mask={mask:#x})",
            );

            libc::close(client);
            libc::close(listener);
        }
    }

    // ── GetAddrInfoW / FreeAddrInfoW ───────────────────────────────────────

    #[test]
    fn get_addr_info_w_null_pp_result() {
        unsafe {
            let ret = get_addr_info_w(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
            );
            assert_eq!(ret, 10014); // WSAEFAULT
        }
    }

    #[test]
    fn get_addr_info_w_both_null_returns_nonzero() {
        unsafe {
            let mut result: *mut WinAddrInfo = std::ptr::null_mut();
            let ret = get_addr_info_w(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                &mut result,
            );
            // Both null → should fail (EAI_NONAME → non-zero).
            assert_ne!(ret, 0, "GetAddrInfoW(null, null) should fail");
        }
    }

    #[test]
    fn free_addr_info_w_null_does_not_crash() {
        unsafe {
            free_addr_info_w(std::ptr::null_mut());
        }
    }

    // ── WSAPoll ────────────────────────────────────────────────────────────

    #[test]
    fn wsa_poll_empty_set_returns_zero() {
        unsafe {
            // nfds=0 should return 0 immediately (no error).
            let ret = ws_wsa_poll(std::ptr::null_mut(), 0, 0);
            assert_eq!(ret, 0);
        }
    }

    #[test]
    fn wsa_poll_null_ptr_with_fds_returns_error() {
        unsafe {
            // Null fd_array with nfds>0 → WSAEFAULT.
            let ret = ws_wsa_poll(std::ptr::null_mut(), 1, 0);
            assert_eq!(ret, SOCKET_ERROR);
            assert_eq!(wsa_get_last_error(), 10014); // WSAEFAULT
        }
    }

    #[test]
    fn wsa_poll_invalid_socket_is_skipped() {
        unsafe {
            let mut fds = [WSAPOLLFD {
                fd: -1i64, // INVALID_SOCKET
                events: 1, // POLLIN
                revents: 0,
            }];
            let ret = ws_wsa_poll(fds.as_mut_ptr(), 1, 0);
            // INVALID_SOCKET is skipped, so no fds are polled → return 0.
            assert_eq!(ret, 0);
            assert_eq!(fds[0].revents, 0);
        }
    }
}
