//! Reverse map from WSAEventSelect: event_handle → socket_fd.
//!
//! WSAEventSelect in weave-ws2 stores socket→(event_handle, mask).
//! WFMO in weave-kernel32 needs the reverse: event_handle → socket_fd,
//! so it can poll the real socket fd instead of the (never-written) eventfd.
//!
//! This module is the shared rendezvous point. weave-ws2 writes; weave-kernel32 reads.
//! Neither crate imports the other — they communicate through this map.
//!
//! Also tracks which socket fds are in the "connecting" state (non-blocking connect
//! has returned EINPROGRESS but has not yet completed). Used by WSAEnumNetworkEvents
//! to distinguish POLLOUT-as-connect-complete from POLLOUT-as-write-ready.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::sync::Mutex;

#[cfg(target_os = "linux")]
static EVENT_SOCKET_MAP: Mutex<Option<HashMap<u64, i32>>> = Mutex::new(None);

#[cfg(target_os = "linux")]
fn map() -> std::sync::MutexGuard<'static, Option<HashMap<u64, i32>>> {
    let mut g = EVENT_SOCKET_MAP.lock().unwrap();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    g
}

/// Record that `event_handle` was registered via WSAEventSelect for `socket_fd`.
/// Called by weave-ws2 when mask != 0.
#[cfg(target_os = "linux")]
pub fn register_socket_event(event_handle: u64, socket_fd: i32) {
    let mut g = map();
    if let Some(ref mut m) = *g {
        m.insert(event_handle, socket_fd);
    }
}

/// Remove the mapping for `event_handle`.
/// Called by weave-ws2 when mask == 0 (deregistration).
#[cfg(target_os = "linux")]
pub fn deregister_socket_event(event_handle: u64) {
    let mut g = map();
    if let Some(ref mut m) = *g {
        m.remove(&event_handle);
    }
}

/// Return the socket_fd associated with `event_handle`, if any.
/// Called by weave-kernel32 WFMO before deciding which fd to poll.
#[cfg(target_os = "linux")]
pub fn get_socket_for_event(event_handle: u64) -> Option<i32> {
    let g = map();
    g.as_ref().and_then(|m| m.get(&event_handle).copied())
}

// No-op stubs for non-Linux targets (macOS cross-compile check).
#[cfg(not(target_os = "linux"))]
pub fn register_socket_event(_event_handle: u64, _socket_fd: i32) {}
#[cfg(not(target_os = "linux"))]
pub fn deregister_socket_event(_event_handle: u64) {}
#[cfg(not(target_os = "linux"))]
pub fn get_socket_for_event(_event_handle: u64) -> Option<i32> {
    None
}

// ── Socket connecting state ───────────────────────────────────────────────────
//
// Tracks socket fds whose non-blocking connect() returned EINPROGRESS.
// WSAEnumNetworkEvents uses this to distinguish:
//   POLLOUT while connecting → FD_CONNECT (0x10), not FD_WRITE (0x2)
//   POLLOUT after connected  → FD_WRITE (0x2)
//
// Wine ref: dlls/ws2_32/socket.c — sock_get_events / get_sock_fd_events:
//   When socket is in SS_CONNECTING state and POLLOUT fires, Wine sets
//   POLLEVENT_CONNECT (FD_CONNECT). After connect completes the socket
//   transitions to SS_CONNECTED and subsequent POLLOUT maps to FD_WRITE.

#[cfg(target_os = "linux")]
static SOCKET_CONNECTING: Mutex<Option<HashSet<i32>>> = Mutex::new(None);

#[cfg(target_os = "linux")]
fn connecting_set() -> std::sync::MutexGuard<'static, Option<HashSet<i32>>> {
    let mut g = SOCKET_CONNECTING.lock().unwrap();
    if g.is_none() {
        *g = Some(HashSet::new());
    }
    g
}

/// Mark `fd` as being in a non-blocking connect (EINPROGRESS returned).
/// Called by ws_connect when libc::connect returns EINPROGRESS.
#[cfg(target_os = "linux")]
pub fn mark_socket_connecting(fd: i32) {
    let mut g = connecting_set();
    if let Some(ref mut s) = *g {
        s.insert(fd);
    }
}

/// Remove `fd` from the connecting set (connect completed or socket closed).
/// Called by wsa_enum_network_events after reporting FD_CONNECT.
#[cfg(target_os = "linux")]
pub fn clear_socket_connecting(fd: i32) {
    let mut g = connecting_set();
    if let Some(ref mut s) = *g {
        s.remove(&fd);
    }
}

/// Return true if `fd` has a non-blocking connect in progress.
/// Called by wsa_enum_network_events to decide POLLOUT → FD_CONNECT vs FD_WRITE.
#[cfg(target_os = "linux")]
pub fn is_socket_connecting(fd: i32) -> bool {
    let g = connecting_set();
    g.as_ref().map(|s| s.contains(&fd)).unwrap_or(false)
}

// No-op stubs for non-Linux targets.
#[cfg(not(target_os = "linux"))]
pub fn mark_socket_connecting(_fd: i32) {}
#[cfg(not(target_os = "linux"))]
pub fn clear_socket_connecting(_fd: i32) {}
#[cfg(not(target_os = "linux"))]
pub fn is_socket_connecting(_fd: i32) -> bool {
    false
}

// ── Socket write-armed state ──────────────────────────────────────────────────
//
// Implements edge-triggered FD_WRITE semantics matching Windows behaviour.
//
// Windows FD_WRITE contract (Wine ref: dlls/ws2_32/socket.c — sock_get_events,
// sock_reselect, hmask handling):
//   - FD_WRITE fires once on connect completion (initial arm).
//   - After FD_WRITE is reported via WSAEnumNetworkEvents, the bit is cleared
//     from the socket's pending event set (hmask). It will not fire again until
//     the socket's send() returns EWOULDBLOCK and the kernel later signals that
//     write-space is available (re-arm on drain).
//   - This is edge-triggered: fires on transitions, not on level (not on every
//     POLLOUT call). Linux POLLOUT is level-triggered; this set enforces the
//     Windows edge semantics on top of Linux poll.
//
// FD_WRITE lifecycle:
//   arm   → WSAEventSelect called with FD_WRITE in mask (initial connection arm)
//   arm   → ws_send returns WSAEWOULDBLOCK/EAGAIN (re-arm after drain)
//   disarm → wsa_enum_network_events reports FD_WRITE (consume the event)
//
// WFMO uses is_socket_write_armed to decide whether to include POLLOUT in the
// socket's poll events bitmask — preventing wake-up floods on a connected,
// idle send buffer.

#[cfg(target_os = "linux")]
static SOCKET_WRITE_ARMED: Mutex<Option<HashSet<i32>>> = Mutex::new(None);

#[cfg(target_os = "linux")]
fn write_armed_set() -> std::sync::MutexGuard<'static, Option<HashSet<i32>>> {
    let mut g = SOCKET_WRITE_ARMED.lock().unwrap();
    if g.is_none() {
        *g = Some(HashSet::new());
    }
    g
}

/// Arm FD_WRITE for `fd`. Called by WSAEventSelect (initial arm) and ws_send
/// when send() returns EWOULDBLOCK (re-arm after drain).
#[cfg(target_os = "linux")]
pub fn arm_socket_write(fd: i32) {
    let mut g = write_armed_set();
    if let Some(ref mut s) = *g {
        s.insert(fd);
    }
}

/// Disarm FD_WRITE for `fd`. Called by wsa_enum_network_events after reporting
/// FD_WRITE so it does not fire again until re-armed.
#[cfg(target_os = "linux")]
pub fn disarm_socket_write(fd: i32) {
    let mut g = write_armed_set();
    if let Some(ref mut s) = *g {
        s.remove(&fd);
    }
}

/// Return true if FD_WRITE is armed for `fd` (i.e., the next WSAEnumNetworkEvents
/// should report FD_WRITE when POLLOUT is set). Called by wsa_enum_network_events
/// and WFMO to implement edge-triggered semantics.
#[cfg(target_os = "linux")]
pub fn is_socket_write_armed(fd: i32) -> bool {
    let g = write_armed_set();
    g.as_ref().map(|s| s.contains(&fd)).unwrap_or(false)
}

// No-op stubs for non-Linux targets.
#[cfg(not(target_os = "linux"))]
pub fn arm_socket_write(_fd: i32) {}
#[cfg(not(target_os = "linux"))]
pub fn disarm_socket_write(_fd: i32) {}
#[cfg(not(target_os = "linux"))]
pub fn is_socket_write_armed(_fd: i32) -> bool {
    false
}
