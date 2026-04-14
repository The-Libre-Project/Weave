//! Global Win32 message queue.
//!
//! A single per-process queue backed by a VecDeque. In Phase 2 Weave is
//! single-threaded so this is sufficient. When multi-threading is added
//! (Phase 3+) this becomes a per-thread queue indexed by thread ID.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

// ── Wake pipe (Linux only) ────────────────────────────────────────────────────
//
// A self-pipe used to unblock GetMessageW's poll() when a message is posted
// from a background thread.  The write end is written by `post()`; the read
// end is polled by `backend::wait_event()` alongside the X11 fd.

#[cfg(target_os = "linux")]
mod wake {
    use std::os::unix::io::RawFd;
    use std::sync::OnceLock;

    static WAKE_PIPE: OnceLock<(RawFd, RawFd)> = OnceLock::new(); // (read_fd, write_fd)

    pub fn init() {
        WAKE_PIPE.get_or_init(|| {
            let mut fds = [0i32; 2];
            unsafe { libc::pipe(fds.as_mut_ptr()) };
            // Non-blocking write end so post() never blocks on a full pipe buffer.
            unsafe { libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK) };
            (fds[0], fds[1])
        });
    }

    pub fn read_fd() -> RawFd {
        WAKE_PIPE.get().expect("wake pipe not initialized").0
    }

    pub fn signal() {
        if let Some(&(_, write_fd)) = WAKE_PIPE.get() {
            unsafe { libc::write(write_fd, b"\x01".as_ptr() as *const _, 1) };
        }
    }
}

/// An internal message entry (the fields of Win32 MSG, minus the padding).
#[derive(Clone, Debug)]
pub struct MsgEntry {
    pub hwnd: usize,
    pub message: u32,
    pub w_param: usize,
    pub l_param: isize,
    pub time: u32,
    pub pt_x: i32,
    pub pt_y: i32,
}

static QUEUE: OnceLock<Mutex<VecDeque<MsgEntry>>> = OnceLock::new();

fn queue() -> &'static Mutex<VecDeque<MsgEntry>> {
    QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn lock_queue(
    m: &Mutex<VecDeque<MsgEntry>>,
) -> Option<std::sync::MutexGuard<'_, VecDeque<MsgEntry>>> {
    m.lock()
        .map_err(|e| eprintln!("weave: user32: message queue mutex poisoned: {e}"))
        .ok()
}

/// Initialise the wake pipe.  Must be called before the first `wait_event`.
/// Idempotent — safe to call multiple times.
#[cfg(target_os = "linux")]
pub fn init_wake_pipe() {
    wake::init();
}

/// Return the read end of the wake pipe for use in poll().
#[cfg(target_os = "linux")]
pub fn wake_fd_read() -> std::os::unix::io::RawFd {
    wake::read_fd()
}

/// Push a message onto the back of the queue.
pub fn post(msg: MsgEntry) {
    if let Some(mut g) = lock_queue(queue()) {
        g.push_back(msg);
    }
    // Signal the wake pipe so that a blocked poll() in wait_event() wakes up.
    #[cfg(target_os = "linux")]
    wake::signal();
}

/// Pop the front message, returning `None` if the queue is empty.
pub fn pop() -> Option<MsgEntry> {
    lock_queue(queue())?.pop_front()
}

/// Peek at the front message without removing it.
pub fn peek() -> Option<MsgEntry> {
    lock_queue(queue())?.front().cloned()
}

/// Returns `true` if the queue currently has at least one message.
pub fn has_message() -> bool {
    match lock_queue(queue()) {
        Some(g) => !g.is_empty(),
        None => false,
    }
}

/// Returns `true` if there is already a WM_PAINT message queued for `hwnd`.
/// Used by InvalidateRect to coalesce multiple invalidations into one paint.
pub fn has_paint_for(hwnd: usize) -> bool {
    const WM_PAINT: u32 = 0x000F;
    match lock_queue(queue()) {
        Some(g) => g.iter().any(|m| m.hwnd == hwnd && m.message == WM_PAINT),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(message: u32) -> MsgEntry {
        MsgEntry {
            hwnd: 0,
            message,
            w_param: 0,
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
        }
    }

    #[test]
    fn post_and_pop() {
        let q = Mutex::new(VecDeque::<MsgEntry>::new());
        q.lock().unwrap().push_back(msg(1));
        q.lock().unwrap().push_back(msg(2));
        assert_eq!(q.lock().unwrap().pop_front().unwrap().message, 1);
        assert_eq!(q.lock().unwrap().pop_front().unwrap().message, 2);
        assert!(q.lock().unwrap().pop_front().is_none());
    }
}
