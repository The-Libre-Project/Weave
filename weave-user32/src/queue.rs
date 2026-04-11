//! Global Win32 message queue.
//!
//! A single per-process queue backed by a VecDeque. In Phase 2 Weave is
//! single-threaded so this is sufficient. When multi-threading is added
//! (Phase 3+) this becomes a per-thread queue indexed by thread ID.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

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

/// Push a message onto the back of the queue.
pub fn post(msg: MsgEntry) {
    if let Some(mut g) = lock_queue(queue()) {
        g.push_back(msg);
    }
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
