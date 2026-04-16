//! ws2_32.dll / wsock32.dll stubs for Weave — Winsock2 networking.
//!
//! Maps Windows Winsock2 functions to Linux POSIX socket calls via libc.
//! Handles SOCKET ↔ fd conversion, AF_INET6 address family translation,
//! fd_set layout differences, timeval size differences, and socket option
//! level/name remapping.

#![allow(non_snake_case)]

use std::sync::atomic::{AtomicBool, Ordering};

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

// Windows fd_set layout: count(u32) + padding(u32) + SOCKET[FD_SETSIZE].
// FD_SETSIZE is 64 on Windows.
const WIN_FD_SETSIZE: usize = 64;

/// Whether WSAStartup has been called.
static WSA_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ── Thread-local Winsock error ───────────────────────────────────────────────

thread_local! {
    static LAST_WSA_ERROR: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

fn set_last_error(err: i32) {
    LAST_WSA_ERROR.with(|c| c.set(err));
}

fn save_errno() {
    let e = unsafe { *libc::__errno_location() };
    set_last_error(e);
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
    let fd = libc::socket(af_win_to_linux(af), type_, protocol);
    if fd < 0 {
        save_errno();
        INVALID_SOCKET
    } else {
        fd as usize
    }
}

/// closesocket — close a socket.
///
/// # Safety
/// `s` must be a valid socket handle.
pub unsafe extern "win64" fn ws_closesocket(s: usize) -> i32 {
    if libc::close(s as i32) < 0 {
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
        save_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

/// send — send data on a connected socket.
///
/// # Safety
/// `buf` must point to at least `len` readable bytes.
pub unsafe extern "win64" fn ws_send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    let ret = libc::send(s as i32, buf as *const libc::c_void, len as usize, flags);
    if ret < 0 {
        save_errno();
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
    let ret = libc::recv(s as i32, buf as *mut libc::c_void, len as usize, flags);
    if ret < 0 {
        save_errno();
        SOCKET_ERROR
    } else {
        ret as i32
    }
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
            eprintln!("weave: ioctlsocket: unknown command {cmd:#x}");
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

// ── Winsock API: async-event stubs ───────────────────────────────────────────

// WSA_INVALID_EVENT is the null/invalid WSAEVENT sentinel (0).
const WSA_INVALID_EVENT: usize = 0;

// Error codes used by async-event stubs.
const WSAEINVAL: i32 = 10022;
const WSA_WAIT_FAILED: u32 = 0xFFFF_FFFF;
const WSA_WAIT_EVENT_0: u32 = 0;

/// WSACreateEvent — create a manual-reset, initially-unsignaled socket event object.
///
/// Wine ref: dlls/ws2_32/socket.c:3988 — WSACreateEvent calls CreateEventW(NULL,
/// TRUE, FALSE, NULL); returns the resulting HANDLE as WSAEVENT.
/// Stub: we have no Win32 HANDLE infrastructure yet; return a fake non-null
/// sentinel (1) so callers treat it as valid. Callers that pass it to
/// WSAWaitForMultipleEvents will get WSA_WAIT_EVENT_0 back immediately.
pub extern "win64" fn wsa_create_event() -> usize {
    // Any value != WSA_INVALID_EVENT (0) is accepted as a valid WSAEVENT by callers.
    // Return 1 as a stable fake handle.
    1
}

/// WSACloseEventObject — close a socket event object created by WSACreateEvent.
///
/// Wine ref: dlls/ws2_32/socket.c:4000 — WSACloseEvent calls CloseHandle(event);
/// returns BOOL. Stub: nothing to close; always succeeds.
pub extern "win64" fn wsa_close_event_object(event: usize) -> i32 {
    if event == WSA_INVALID_EVENT {
        set_last_error(WSAEINVAL);
        return 0; // FALSE
    }
    1 // TRUE
}

/// WSAEventSelect — associate network events on a socket with a WSAEVENT object.
///
/// Wine ref: dlls/ws2_32/socket.c:3885 — WSAEventSelect(SOCKET s, WSAEVENT event,
/// LONG mask) uses IOCTL_AFD_EVENT_SELECT via NtDeviceIoControlFile. The socket
/// enters non-blocking mode and network events are posted to the event object.
/// Stub: no-op; PuTTY's SSH engine will call this before any I/O; returning 0
/// (success) allows the SSH handshake path to continue to WSAWaitForMultipleEvents.
///
/// # Safety
/// `s` must be a valid socket fd. `event` is opaque.
pub unsafe extern "win64" fn wsa_event_select(s: usize, event: usize, mask: i32) -> i32 {
    // Validate basic args — Wine returns WSAEINVAL for null/bad socket.
    let _ = (s, event, mask); // suppress unused warnings
    0 // success
}

/// WSAWaitForMultipleEvents — wait on one or more WSAEVENT objects.
///
/// Wine ref: include/winsock2.h:1199 —
/// DWORD WINAPI WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT *lphEvents,
///     BOOL fWaitAll, DWORD dwTimeout, BOOL fAlertable);
/// Returns WSA_WAIT_EVENT_0 + index of first signalled event, or
/// WSA_WAIT_FAILED (0xFFFFFFFF) on error. Stub: return WSA_WAIT_EVENT_0 (0)
/// immediately (first event is "signalled") so callers proceed to
/// WSAEnumNetworkEvents without blocking.
///
/// # Safety
/// `lph_events` may be null (only checked, never dereferenced beyond count).
pub unsafe extern "win64" fn wsa_wait_for_multiple_events(
    c_events: u32,
    _lph_events: *const usize,
    _f_wait_all: i32,
    _dw_timeout: u32,
    _f_alertable: i32,
) -> u32 {
    if c_events == 0 {
        set_last_error(WSAEINVAL);
        return WSA_WAIT_FAILED;
    }
    // Signal event 0 immediately — callers enter their WSAEnumNetworkEvents path.
    WSA_WAIT_EVENT_0
}

/// WSAEnumNetworkEvents — retrieve and reset socket network events.
///
/// Wine ref: dlls/ws2_32/socket.c:3815 —
/// int WINAPI WSAEnumNetworkEvents(SOCKET s, WSAEVENT event, WSANETWORKEVENTS *ret_events)
/// uses IOCTL_AFD_GET_EVENTS to read which events fired and clears them.
/// WSANETWORKEVENTS layout: lNetworkEvents (LONG) + iErrorCode[FD_MAX_EVENTS] (10 ints).
/// Stub: zero out ret_events (no events fired), return 0 (success). Callers will
/// see an empty event mask and loop back to WSAWaitForMultipleEvents. This is the
/// correct safe behaviour: no events available, no crash.
///
/// # Safety
/// `lp_network_events` must be null or point to a writable WSANETWORKEVENTS (44 bytes).
pub unsafe extern "win64" fn wsa_enum_network_events(
    _s: usize,
    _event: usize,
    lp_network_events: *mut u8,
) -> i32 {
    if !lp_network_events.is_null() {
        // WSANETWORKEVENTS = LONG lNetworkEvents (4) + int iErrorCode[10] (40) = 44 bytes.
        std::ptr::write_bytes(lp_network_events, 0, 44);
    }
    0 // success
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
}
