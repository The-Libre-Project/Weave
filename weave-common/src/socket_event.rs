//! Reverse map from WSAEventSelect: event_handle → socket_fd.
//!
//! WSAEventSelect in weave-ws2 stores socket→(event_handle, mask).
//! WFMO in weave-kernel32 needs the reverse: event_handle → socket_fd,
//! so it can poll the real socket fd instead of the (never-written) eventfd.
//!
//! This module is the shared rendezvous point. weave-ws2 writes; weave-kernel32 reads.
//! Neither crate imports the other — they communicate through this map.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
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
