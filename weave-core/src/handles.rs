//! Global HANDLE table.
//!
//! Windows HANDLE values are opaque integers. Weave encodes them as:
//!
//!   handle_value = slot_index + HANDLE_OFFSET
//!
//! where `HANDLE_OFFSET = 4`, so the smallest valid handle is 4.  This keeps
//! handle 0 (NULL) and `usize::MAX` (INVALID_HANDLE_VALUE) permanently free.
//!
//! The table is lazily initialized on first access. Slots 0/1/2 are
//! pre-populated for stdin/stdout/stderr (handles 4/5/6).  All other slots
//! start empty and are filled as files are opened.
//!
//! Callers must use `STDIN_HANDLE`, `STDOUT_HANDLE`, `STDERR_HANDLE` (or call
//! `get_fd(handle)`) — never assume a handle value equals a Linux fd number.

use std::sync::{Mutex, MutexGuard, OnceLock};

/// Offset added to a slot index to produce the public handle value.
/// Ensures 0 (NULL) is never returned as a valid open handle.
const HANDLE_OFFSET: usize = 4;

/// The resource bound to a handle slot.
#[derive(Debug)]
pub enum HandleKind {
    /// A Linux file descriptor owned by Weave. Closed when the handle is freed.
    File(i32),
    /// An open registry key. Stores the on-disk path to the key's directory.
    RegistryKey(std::path::PathBuf),
}

impl HandleKind {
    /// Return the underlying Linux fd. `None` for non-file handles.
    pub fn as_fd(&self) -> Option<i32> {
        match self {
            HandleKind::File(fd) => Some(*fd),
            _ => None,
        }
    }

    /// Return the registry key path. `None` for non-registry handles.
    pub fn as_registry_path(&self) -> Option<&std::path::Path> {
        match self {
            HandleKind::RegistryKey(p) => Some(p),
            _ => None,
        }
    }
}

// ── Internal table ────────────────────────────────────────────────────────────

struct HandleTable {
    slots: Vec<Option<HandleKind>>,
}

impl HandleTable {
    fn new() -> Self {
        let mut t = Self { slots: Vec::new() };
        // Pre-populate stdin/stdout/stderr at fixed slots.
        t.slots.push(Some(HandleKind::File(0))); // slot 0 → stdin  → handle STDIN_HANDLE
        t.slots.push(Some(HandleKind::File(1))); // slot 1 → stdout → handle STDOUT_HANDLE
        t.slots.push(Some(HandleKind::File(2))); // slot 2 → stderr → handle STDERR_HANDLE
        t
    }

    /// Allocate a new slot. Returns the handle value (slot index + HANDLE_OFFSET).
    fn alloc(&mut self, kind: HandleKind) -> usize {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(kind);
                return i + HANDLE_OFFSET;
            }
        }
        self.slots.push(Some(kind));
        self.slots.len() - 1 + HANDLE_OFFSET
    }

    /// Return the Linux fd for a handle, or `None` if the handle is invalid.
    fn get_fd(&self, handle: usize) -> Option<i32> {
        let index = handle.checked_sub(HANDLE_OFFSET)?;
        self.slots.get(index)?.as_ref().and_then(|k| k.as_fd())
    }

    /// Free a handle slot. Returns `false` if the handle was already free or
    /// out of range. stdin/stdout/stderr (slots 0–2) cannot be freed.
    fn free(&mut self, handle: usize) -> bool {
        let index = match handle.checked_sub(HANDLE_OFFSET) {
            Some(i) => i,
            None => return false,
        };
        // Protect the standard handles from being closed.
        if index < 3 {
            return false;
        }
        match self.slots.get_mut(index) {
            Some(slot @ Some(_)) => {
                *slot = None;
                true
            }
            _ => false,
        }
    }
}

// ── Global state ──────────────────────────────────────────────────────────────

static HANDLES: OnceLock<Mutex<HandleTable>> = OnceLock::new();

fn table() -> &'static Mutex<HandleTable> {
    HANDLES.get_or_init(|| Mutex::new(HandleTable::new()))
}

fn lock_table<'a>(m: &'a Mutex<HandleTable>) -> Option<MutexGuard<'a, HandleTable>> {
    m.lock()
        .map_err(|e| eprintln!("weave: weave-core: handle table mutex poisoned: {e}"))
        .ok()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// The handle value for standard input (always valid; cannot be closed).
pub const STDIN_HANDLE: usize = HANDLE_OFFSET;
/// The handle value for standard output (always valid; cannot be closed).
pub const STDOUT_HANDLE: usize = 1 + HANDLE_OFFSET;
/// The handle value for standard error (always valid; cannot be closed).
pub const STDERR_HANDLE: usize = 2 + HANDLE_OFFSET;

/// Allocate a new handle for the given resource. The table is initialised on
/// first call.
pub fn alloc(kind: HandleKind) -> usize {
    lock_table(table())
        .map(|mut g| g.alloc(kind))
        .unwrap_or(0)
}

/// Return the Linux file descriptor for a handle. Returns `None` if the handle
/// is invalid or not a file handle.
pub fn get_fd(handle: usize) -> Option<i32> {
    lock_table(table())?.get_fd(handle)
}

/// Return the registry key path for a handle. Returns `None` if the handle is
/// invalid or not a registry key handle.
pub fn get_registry_path(handle: usize) -> Option<std::path::PathBuf> {
    let guard = lock_table(table())?;
    let index = handle.checked_sub(HANDLE_OFFSET)?;
    guard
        .slots
        .get(index)?
        .as_ref()
        .and_then(|k| k.as_registry_path().map(|p| p.to_path_buf()))
}

/// Free a handle. Returns `true` if the handle was valid and freed.
/// stdin/stdout/stderr handles are never freed (returns `false`).
pub fn free(handle: usize) -> bool {
    lock_table(table())
        .map(|mut g| g.free(handle))
        .unwrap_or(false)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> HandleTable {
        HandleTable::new()
    }

    #[test]
    fn std_handles_prepopulated() {
        let t = fresh();
        assert_eq!(t.get_fd(STDIN_HANDLE), Some(0));
        assert_eq!(t.get_fd(STDOUT_HANDLE), Some(1));
        assert_eq!(t.get_fd(STDERR_HANDLE), Some(2));
    }

    #[test]
    fn null_handle_is_invalid() {
        let t = fresh();
        assert_eq!(t.get_fd(0), None);
    }

    #[test]
    fn invalid_handle_value_is_invalid() {
        let t = fresh();
        assert_eq!(t.get_fd(usize::MAX), None);
    }

    #[test]
    fn alloc_and_lookup() {
        let mut t = fresh();
        let h = t.alloc(HandleKind::File(42));
        assert!(h >= HANDLE_OFFSET);
        assert_eq!(t.get_fd(h), Some(42));
    }

    #[test]
    fn freed_slot_is_recycled() {
        let mut t = fresh();
        let h1 = t.alloc(HandleKind::File(10));
        assert!(t.free(h1));
        let h2 = t.alloc(HandleKind::File(20));
        assert_eq!(h1, h2, "freed slot should be reused");
        assert_eq!(t.get_fd(h2), Some(20));
    }

    #[test]
    fn stdin_cannot_be_freed() {
        let mut t = fresh();
        assert!(!t.free(STDIN_HANDLE));
        assert_eq!(t.get_fd(STDIN_HANDLE), Some(0));
    }

    #[test]
    fn stdout_cannot_be_freed() {
        let mut t = fresh();
        assert!(!t.free(STDOUT_HANDLE));
    }

    #[test]
    fn free_zero_returns_false() {
        let mut t = fresh();
        assert!(!t.free(0));
    }

    #[test]
    fn free_invalid_handle_value_returns_false() {
        let mut t = fresh();
        assert!(!t.free(usize::MAX));
    }

    #[test]
    fn multiple_allocs_get_distinct_handles() {
        let mut t = fresh();
        let h1 = t.alloc(HandleKind::File(10));
        let h2 = t.alloc(HandleKind::File(11));
        let h3 = t.alloc(HandleKind::File(12));
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_eq!(t.get_fd(h1), Some(10));
        assert_eq!(t.get_fd(h2), Some(11));
        assert_eq!(t.get_fd(h3), Some(12));
    }

    #[test]
    fn lookup_after_free_returns_none() {
        let mut t = fresh();
        let h = t.alloc(HandleKind::File(99));
        assert!(t.free(h));
        assert_eq!(t.get_fd(h), None);
    }
}
