//! Per-thread user APC queues.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

/// One queued guest APC. The callback uses the Win64 `VOID (CALLBACK *)(ULONG_PTR)` ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApcRecord {
    pub callback: usize,
    pub data: usize,
}

/// APC state shared by a thread handle and the corresponding guest thread.
pub struct ThreadApcState {
    queue: Mutex<VecDeque<ApcRecord>>,
    wake_fd: i32,
}

impl std::fmt::Debug for ThreadApcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadApcState")
            .field("pending", &self.queue.lock().map(|q| q.len()).unwrap_or(0))
            .field("wake_fd", &self.wake_fd)
            .finish()
    }
}

impl ThreadApcState {
    pub fn new() -> Arc<Self> {
        // SAFETY: eventfd has no pointer arguments and the returned descriptor is
        // owned by this state until Drop.
        let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(wake_fd >= 0, "eventfd failed while creating APC state");
        Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            wake_fd,
        })
    }

    pub fn wake_fd(&self) -> i32 {
        self.wake_fd
    }

    pub fn enqueue(&self, record: ApcRecord) {
        self.queue.lock().unwrap().push_back(record);
        let one = 1u64;
        // SAFETY: wake_fd is a valid eventfd owned by this state and `one` is a
        // valid eight-byte eventfd write buffer.
        unsafe {
            libc::write(
                self.wake_fd,
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }

    pub fn drain(&self) -> Vec<ApcRecord> {
        let mut value = 0u64;
        // SAFETY: wake_fd is a valid eventfd and value is an eight-byte read buffer.
        unsafe {
            libc::read(
                self.wake_fd,
                &mut value as *mut u64 as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }
        self.queue.lock().unwrap().drain(..).collect()
    }

    pub fn has_pending(&self) -> bool {
        !self.queue.lock().unwrap().is_empty()
    }
}

impl Drop for ThreadApcState {
    fn drop(&mut self) {
        // SAFETY: wake_fd is owned exclusively by this state during Drop.
        unsafe { libc::close(self.wake_fd) };
    }
}

thread_local! {
    static CURRENT_APC_STATE: OnceLock<Arc<ThreadApcState>> = const { OnceLock::new() };
}

/// Register the APC queue belonging to the current guest thread.
pub fn register_current_thread(state: Arc<ThreadApcState>) {
    CURRENT_APC_STATE.with(|slot| {
        let _ = slot.set(state);
    });
}

/// Return the APC queue registered for the current guest thread.
pub fn current_thread() -> Option<Arc<ThreadApcState>> {
    CURRENT_APC_STATE.with(|slot| slot.get().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_round_trip_and_wake() {
        let state = ThreadApcState::new();
        state.enqueue(ApcRecord {
            callback: 0x1234,
            data: 0x5678,
        });
        assert!(state.has_pending());
        assert_eq!(
            state.drain(),
            vec![ApcRecord {
                callback: 0x1234,
                data: 0x5678
            }]
        );
        assert!(!state.has_pending());
    }
}
