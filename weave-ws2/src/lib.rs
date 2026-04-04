//! ws2_32.dll / wsock32.dll stubs for Weave — Winsock2 networking.
//!
//! Maps Windows Winsock2 functions to Linux POSIX socket calls via libc.
//! Handles SOCKET ↔ fd conversion, AF_INET6 address family translation,
//! fd_set layout differences, timeval size differences, and socket option
//! level/name remapping.

#![allow(non_snake_case)]

use std::sync::atomic::{AtomicBool, Ordering};

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
