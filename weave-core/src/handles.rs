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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};

/// Caller-owned state retained from an overlapped directory-watch request.
/// Guest addresses are stored as integers so cleanup never dereferences guest
/// memory after cancellation or handle close.
#[derive(Clone, Debug)]
pub struct PendingDirectoryOperation {
    pub buffer: usize,
    pub buffer_len: u32,
    pub overlapped: usize,
    pub completion_routine: usize,
    pub apc: Option<Arc<crate::apc::ThreadApcState>>,
}

impl PartialEq for PendingDirectoryOperation {
    fn eq(&self, other: &Self) -> bool {
        self.buffer == other.buffer
            && self.buffer_len == other.buffer_len
            && self.overlapped == other.overlapped
            && self.completion_routine == other.completion_routine
    }
}

impl Eq for PendingDirectoryOperation {}

/// Lifetime-owned state for a directory handle's future watcher.
#[derive(Debug)]
pub struct DirectoryWatchState {
    path: std::path::PathBuf,
    watcher_fd: Option<i32>,
    pending: Option<PendingDirectoryOperation>,
}

impl DirectoryWatchState {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            watcher_fd: None,
            pending: None,
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn pending(&self) -> Option<PendingDirectoryOperation> {
        self.pending.clone()
    }

    pub fn set_pending(&mut self, operation: PendingDirectoryOperation) -> bool {
        if self.pending.is_some() {
            return false;
        }
        self.pending = Some(operation);
        true
    }

    pub fn take_pending(&mut self) -> Option<PendingDirectoryOperation> {
        self.pending.take()
    }

    /// Adopt a watcher descriptor once inotify registration is implemented.
    pub fn set_watcher_fd(&mut self, fd: i32) -> bool {
        if self.watcher_fd.is_some() {
            return false;
        }
        self.watcher_fd = Some(fd);
        true
    }

    pub fn watcher_fd(&self) -> Option<i32> {
        self.watcher_fd
    }
}

impl Drop for DirectoryWatchState {
    fn drop(&mut self) {
        if let Some(fd) = self.watcher_fd.take() {
            // SAFETY: watcher_fd is owned by this state after explicit adoption
            // and is closed exactly once when the directory handle is dropped.
            unsafe { libc::close(fd) };
        }
        // The pending operation contains guest addresses only; dropping it
        // intentionally performs no guest-memory access.
        self.pending.take();
    }
}

/// Offset added to a slot index to produce the public handle value.
/// Ensures 0 (NULL) is never returned as a valid open handle.
const HANDLE_OFFSET: usize = 4;

/// Completion state shared between a spawned thread and any WFSO waiters.
pub struct ThreadCompletion {
    /// `None` while running; `Some(exit_code)` after the thread function returns.
    pub result: Mutex<Option<u32>>,
    pub condvar: Condvar,
}

/// Start gate shared by a newly-created thread and its Win32 thread handle.
#[derive(Debug)]
pub struct ThreadStartGate {
    suspend_count: Mutex<u32>,
    condvar: Condvar,
    /// Set by TerminateThread so the trampoline exits without running guest
    /// code (or overwriting the TerminateThread exit code).
    terminate_requested: AtomicBool,
}

impl ThreadStartGate {
    pub fn new(suspended: bool) -> Self {
        Self {
            suspend_count: Mutex::new(u32::from(suspended)),
            condvar: Condvar::new(),
            terminate_requested: AtomicBool::new(false),
        }
    }

    pub fn wait_until_resumed(&self) {
        let mut count = self.suspend_count.lock().unwrap();
        while *count != 0 && !self.terminate_requested.load(Ordering::Acquire) {
            count = self.condvar.wait(count).unwrap();
        }
    }

    /// Request termination of a thread created via this gate.  The trampoline
    /// observes the flag after the start gate and after the guest function
    /// returns, so a CREATE_SUSPENDED thread is woken and exits without ever
    /// running guest code, and the TerminateThread exit code is not
    /// overwritten when a running guest later returns.
    pub fn request_terminate(&self) {
        self.terminate_requested.store(true, Ordering::Release);
        self.condvar.notify_all();
    }

    pub fn is_terminate_requested(&self) -> bool {
        self.terminate_requested.load(Ordering::Acquire)
    }

    /// Increment the suspend count and return its prior value.
    pub fn suspend(&self) -> u32 {
        let mut count = self.suspend_count.lock().unwrap();
        let previous = *count;
        *count += 1;
        previous
    }

    /// Decrement the start-suspend count and return its prior value.
    pub fn resume(&self) -> u32 {
        let mut count = self.suspend_count.lock().unwrap();
        let previous = *count;
        if previous != 0 {
            *count -= 1;
            if *count == 0 {
                self.condvar.notify_all();
            }
        }
        previous
    }
}

impl std::fmt::Debug for ThreadCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = self.result.lock().ok().and_then(|g| *g);
        f.debug_struct("ThreadCompletion")
            .field("result", &r)
            .finish()
    }
}

/// The resource bound to a handle slot.
#[derive(Debug)]
pub enum HandleKind {
    /// A Linux file descriptor owned by Weave. Closed when the handle is freed.
    File(i32),
    /// An open directory with path identity and owned async-watch state.
    Directory {
        fd: i32,
        path: std::path::PathBuf,
        watch: DirectoryWatchState,
    },
    /// An open registry key. Stores the on-disk path to the key's directory.
    RegistryKey(std::path::PathBuf),
    /// A spawned OS thread.  The join handle is stored so that dropping it
    /// (on CloseHandle) detaches the thread gracefully.
    Thread {
        completion: Arc<ThreadCompletion>,
        start_gate: Arc<ThreadStartGate>,
        apc: Arc<crate::apc::ThreadApcState>,
        join_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    },
    /// A Win32 event object backed by a Linux eventfd (on Linux target).
    /// The i32 is the raw eventfd file descriptor.
    Event(i32),
    /// A named pipe endpoint. `server` distinguishes the `CreateNamedPipeW`
    /// handle from the client-side handle returned by `CreateFileW` on a
    /// `\\.\pipe\` path. The Arc is shared with the global pipe registry.
    NamedPipe {
        instance: Arc<crate::named_pipe::PipeInstance>,
        server: bool,
    },
}

impl HandleKind {
    /// Return the underlying Linux fd. `None` for non-file handles.
    pub fn as_fd(&self) -> Option<i32> {
        match self {
            HandleKind::File(fd) => Some(*fd),
            HandleKind::Directory { fd, .. } => Some(*fd),
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

    pub fn as_directory_path(&self) -> Option<&std::path::Path> {
        match self {
            HandleKind::Directory { path, .. } => Some(path),
            _ => None,
        }
    }

    /// Return the eventfd file descriptor. `None` for non-event handles.
    pub fn as_event_fd(&self) -> Option<i32> {
        match self {
            HandleKind::Event(fd) => Some(*fd),
            _ => None,
        }
    }

    /// Return the shared pipe instance and server/client role for a named pipe
    /// handle. `None` for non-pipe handles.
    pub fn as_named_pipe(&self) -> Option<(Arc<crate::named_pipe::PipeInstance>, bool)> {
        match self {
            HandleKind::NamedPipe { instance, server } => Some((Arc::clone(instance), *server)),
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

    fn get_directory_path(&self, handle: usize) -> Option<std::path::PathBuf> {
        let index = handle.checked_sub(HANDLE_OFFSET)?;
        self.slots
            .get(index)?
            .as_ref()
            .and_then(|kind| kind.as_directory_path().map(std::path::Path::to_path_buf))
    }

    fn set_pending_directory_watch(
        &mut self,
        handle: usize,
        operation: PendingDirectoryOperation,
    ) -> bool {
        let index = match handle.checked_sub(HANDLE_OFFSET) {
            Some(index) => index,
            None => return false,
        };
        match self.slots.get_mut(index).and_then(Option::as_mut) {
            Some(HandleKind::Directory { watch, .. }) => watch.set_pending(operation),
            _ => false,
        }
    }

    fn pending_directory_watch(&self, handle: usize) -> Option<PendingDirectoryOperation> {
        let index = handle.checked_sub(HANDLE_OFFSET)?;
        match self.slots.get(index)?.as_ref()? {
            HandleKind::Directory { watch, .. } => watch.pending(),
            _ => None,
        }
    }

    fn take_pending_directory_watch(&mut self, handle: usize) -> Option<PendingDirectoryOperation> {
        let index = handle.checked_sub(HANDLE_OFFSET)?;
        match self.slots.get_mut(index)?.as_mut()? {
            HandleKind::Directory { watch, .. } => watch.take_pending(),
            _ => None,
        }
    }

    fn cancel_pending_directory_watch(
        &mut self,
        handle: usize,
        overlapped: usize,
    ) -> Option<PendingDirectoryOperation> {
        let operation = self.take_pending_directory_watch(handle)?;
        if overlapped != 0 && operation.overlapped != overlapped {
            let index = handle.checked_sub(HANDLE_OFFSET)?;
            if let Some(HandleKind::Directory { watch, .. }) =
                self.slots.get_mut(index).and_then(Option::as_mut)
            {
                let _ = watch.set_pending(operation);
            }
            return None;
        }
        Some(operation)
    }

    fn set_directory_watcher_fd(&mut self, handle: usize, fd: i32) -> bool {
        let index = match handle.checked_sub(HANDLE_OFFSET) {
            Some(index) => index,
            None => return false,
        };
        match self.slots.get_mut(index).and_then(Option::as_mut) {
            Some(HandleKind::Directory { watch, .. }) => watch.set_watcher_fd(fd),
            _ => false,
        }
    }

    fn directory_watcher_fds(&self) -> Vec<(usize, i32)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| match slot.as_ref()? {
                HandleKind::Directory { watch, .. } => {
                    watch.watcher_fd().map(|fd| (index + HANDLE_OFFSET, fd))
                }
                _ => None,
            })
            .collect()
    }

    /// Return the eventfd for an Event handle, or `None` if not an Event.
    fn get_event_fd(&self, handle: usize) -> Option<i32> {
        let index = handle.checked_sub(HANDLE_OFFSET)?;
        self.slots
            .get(index)?
            .as_ref()
            .and_then(|k| k.as_event_fd())
    }

    fn get_named_pipe(
        &self,
        handle: usize,
    ) -> Option<(Arc<crate::named_pipe::PipeInstance>, bool)> {
        let index = handle.checked_sub(HANDLE_OFFSET)?;
        self.slots.get(index)?.as_ref()?.as_named_pipe()
    }

    fn take_named_pipe(
        &mut self,
        handle: usize,
    ) -> Option<(Arc<crate::named_pipe::PipeInstance>, bool)> {
        let index = handle.checked_sub(HANDLE_OFFSET)?;
        match self.slots.get(index) {
            Some(Some(HandleKind::NamedPipe { instance, server })) => {
                let pair = (Arc::clone(instance), *server);
                self.slots[index] = None;
                Some(pair)
            }
            _ => None,
        }
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
    lock_table(table()).map(|mut g| g.alloc(kind)).unwrap_or(0)
}

/// Return the Linux file descriptor for a handle. Returns `None` if the handle
/// is invalid or not a file handle.
pub fn get_fd(handle: usize) -> Option<i32> {
    lock_table(table())?.get_fd(handle)
}

/// Return the translated Linux identity retained for an open directory.
pub fn get_directory_path(handle: usize) -> Option<std::path::PathBuf> {
    let guard = lock_table(table())?;
    guard.get_directory_path(handle)
}

/// Retain one pending directory operation without touching guest memory.
pub fn set_pending_directory_watch(handle: usize, operation: PendingDirectoryOperation) -> bool {
    lock_table(table())
        .map(|mut guard| guard.set_pending_directory_watch(handle, operation))
        .unwrap_or(false)
}

/// Inspect the retained pending operation for diagnostics and completion code.
pub fn pending_directory_watch(handle: usize) -> Option<PendingDirectoryOperation> {
    let guard = lock_table(table())?;
    guard.pending_directory_watch(handle)
}

/// Remove a pending operation by handle. Dropping the handle also removes it.
pub fn take_pending_directory_watch(handle: usize) -> Option<PendingDirectoryOperation> {
    lock_table(table())?.take_pending_directory_watch(handle)
}

/// Remove the matching pending operation without touching guest memory.
pub fn cancel_pending_directory_watch(
    handle: usize,
    overlapped: usize,
) -> Option<PendingDirectoryOperation> {
    lock_table(table())?.cancel_pending_directory_watch(handle, overlapped)
}

/// Transfer ownership of an inotify descriptor to a directory handle.
pub fn set_directory_watcher_fd(handle: usize, fd: i32) -> bool {
    lock_table(table())
        .map(|mut guard| guard.set_directory_watcher_fd(handle, fd))
        .unwrap_or(false)
}

/// Return registered directory watcher descriptors for the wait integration.
pub fn directory_watcher_fds() -> Vec<(usize, i32)> {
    lock_table(table())
        .map(|guard| guard.directory_watcher_fds())
        .unwrap_or_default()
}

/// Allocate a new Event handle backed by the given eventfd fd.
pub fn alloc_event(fd: i32) -> usize {
    alloc(HandleKind::Event(fd))
}

/// Return the eventfd file descriptor for an Event handle. Returns `None` if the
/// handle is invalid or not an Event handle.
pub fn get_event_fd(handle: usize) -> Option<i32> {
    lock_table(table())?.get_event_fd(handle)
}

/// Return the shared pipe instance and server/client role for a named pipe
/// handle. Returns `None` if the handle is invalid or not a pipe handle.
pub fn get_named_pipe(handle: usize) -> Option<(Arc<crate::named_pipe::PipeInstance>, bool)> {
    lock_table(table())?.get_named_pipe(handle)
}

/// Free a named pipe handle. When the handle is a server pipe, the instance is
/// unregistered from the global pipe registry. Returns `false` for non-pipe
/// handles (the caller should try other handle types).
pub fn free_if_named_pipe(handle: usize) -> bool {
    let instance = match lock_table(table()).and_then(|mut g| g.take_named_pipe(handle)) {
        Some(pair) => pair,
        None => return false,
    };
    if instance.1 {
        crate::named_pipe::unregister(&instance.0);
    }
    true
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

/// Allocate a new thread handle.  The caller provides the completion Arc and
/// the JoinHandle so they are owned by the handle table.
pub fn alloc_thread(
    completion: Arc<ThreadCompletion>,
    start_gate: Arc<ThreadStartGate>,
    apc: Arc<crate::apc::ThreadApcState>,
    join_handle: std::thread::JoinHandle<()>,
) -> usize {
    alloc(HandleKind::Thread {
        completion,
        start_gate,
        apc,
        join_handle: Mutex::new(Some(join_handle)),
    })
}

/// Return a clone of the APC state associated with a thread handle.
pub fn get_thread_apc(handle: usize) -> Option<Arc<crate::apc::ThreadApcState>> {
    let guard = lock_table(table())?;
    let index = handle.checked_sub(HANDLE_OFFSET)?;
    match guard.slots.get(index)?.as_ref()? {
        HandleKind::Thread { apc, .. } => Some(Arc::clone(apc)),
        _ => None,
    }
}

/// Return a clone of the `ThreadCompletion` Arc for a thread handle.
/// Returns `None` if the handle is not a Thread handle.
pub fn get_thread_completion(handle: usize) -> Option<Arc<ThreadCompletion>> {
    let guard = lock_table(table())?;
    let index = handle.checked_sub(HANDLE_OFFSET)?;
    match guard.slots.get(index)?.as_ref()? {
        HandleKind::Thread { completion, .. } => Some(Arc::clone(completion)),
        _ => None,
    }
}

/// Return the start gate for a thread handle.
pub fn get_thread_start_gate(handle: usize) -> Option<Arc<ThreadStartGate>> {
    let guard = lock_table(table())?;
    let index = handle.checked_sub(HANDLE_OFFSET)?;
    match guard.slots.get(index)?.as_ref()? {
        HandleKind::Thread { start_gate, .. } => Some(Arc::clone(start_gate)),
        _ => None,
    }
}

/// Free the handle if it is a Thread handle.  Returns `true` on success.
/// Returns `false` if the handle is not a Thread handle (caller should try
/// other handle types).
pub fn free_if_thread(handle: usize) -> bool {
    let mut guard = match lock_table(table()) {
        Some(g) => g,
        None => return false,
    };
    let index = match handle.checked_sub(HANDLE_OFFSET) {
        Some(i) => i,
        None => return false,
    };
    match guard.slots.get(index) {
        Some(Some(HandleKind::Thread { .. })) => {
            guard.slots[index] = None;
            true
        }
        _ => false,
    }
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
    fn named_pipe_handle_retains_instance_and_role() {
        let mut t = fresh();
        let name = format!(r"\\.\pipe\weave-handles-{}", std::process::id());
        let instance = crate::named_pipe::create_server_instance(&name, 1).expect("create");
        let h = t.alloc(HandleKind::NamedPipe {
            instance: Arc::clone(&instance),
            server: true,
        });
        let (got, server) = t.get_named_pipe(h).expect("pipe handle resolves");
        assert!(server, "server pipe handle role");
        assert!(Arc::ptr_eq(&got, &instance));

        let h_client = t.alloc(HandleKind::NamedPipe {
            instance: Arc::clone(&instance),
            server: false,
        });
        let (_c, server) = t.get_named_pipe(h_client).expect("client handle resolves");
        assert!(!server, "client pipe handle role");

        assert!(t.take_named_pipe(h).is_some());
        assert!(t.take_named_pipe(h).is_none(), "second take must fail");
        assert!(t.get_named_pipe(h).is_none());
        assert!(t.take_named_pipe(h_client).is_some());
    }

    #[test]
    fn directory_handle_retains_path_and_pending_state() {
        let mut t = fresh();
        let path = std::path::PathBuf::from("/tmp/weave-watch");
        let h = t.alloc(HandleKind::Directory {
            fd: 42,
            path: path.clone(),
            watch: DirectoryWatchState::new(path.clone()),
        });
        assert_eq!(t.get_fd(h), Some(42));
        assert_eq!(t.get_directory_path(h), Some(path));
        let operation = PendingDirectoryOperation {
            buffer: 0x1000,
            buffer_len: 128,
            overlapped: 0x2000,
            completion_routine: 0x3000,
            apc: None,
        };
        assert!(t.set_pending_directory_watch(h, operation.clone()));
        assert_eq!(t.pending_directory_watch(h), Some(operation.clone()));
        assert!(!t.set_pending_directory_watch(h, operation));
    }

    #[test]
    fn freeing_directory_handle_discards_guest_addresses_without_access() {
        let mut t = fresh();
        let h = t.alloc(HandleKind::Directory {
            fd: 42,
            path: std::path::PathBuf::from("/tmp/weave-watch"),
            watch: DirectoryWatchState::new(std::path::PathBuf::from("/tmp/weave-watch")),
        });
        assert!(t.set_pending_directory_watch(
            h,
            PendingDirectoryOperation {
                buffer: usize::MAX,
                buffer_len: u32::MAX,
                overlapped: usize::MAX,
                completion_routine: usize::MAX,
                apc: None,
            },
        ));
        assert!(t.free(h));
        assert_eq!(t.get_directory_path(h), None);
        assert_eq!(t.pending_directory_watch(h), None);
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
