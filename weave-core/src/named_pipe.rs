//! In-process named pipe registry and connection state machine.
//!
//! Weave's in-process execution model has no kernel and no Wineserver, so named
//! pipe client/server rendezvous happens entirely inside the process. A global
//! registry maps each canonical pipe name (`\\.\pipe\name`) to the live server
//! instances created by `CreateNamedPipeW`. A client open
//! (`CreateFileW("\\.\pipe\name")`) resolves an instance and drives the
//! connection state machine; `ConnectNamedPipe` is the server-side half of that
//! rendezvous.
//!
//! Guest OVERLAPPED addresses are stored as integers and never dereferenced
//! here — the calling DLL performs the completion writes, mirroring how
//! `handles::PendingDirectoryOperation` defers guest-memory access.
//!
//! Win32 error codes used by this module are kept local so weave-core does not
//! depend on weave-kernel32.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};

/// ERROR_INVALID_PARAMETER (87).
pub const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_INVALID_FUNCTION (1) — operation not valid on this handle/endpoint.
pub const ERROR_INVALID_FUNCTION: u32 = 1;
/// ERROR_INVALID_HANDLE (6).
pub const ERROR_INVALID_HANDLE: u32 = 6;
/// ERROR_INVALID_NAME (123) — pipe name lacks the `\\.\pipe\` prefix.
pub const ERROR_INVALID_NAME: u32 = 123;
/// ERROR_FILE_NOT_FOUND (2) — no instance exists for the pipe name.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
/// ERROR_PIPE_BUSY (231) — every instance is already attached to a client.
pub const ERROR_PIPE_BUSY: u32 = 231;
/// ERROR_PIPE_LIMIT_REACHED (232) — `n_max_instances` instances exist already.
pub const ERROR_PIPE_LIMIT_REACHED: u32 = 232;
/// ERROR_PIPE_CONNECTED (535) — a client connected before the server listened.
pub const ERROR_PIPE_CONNECTED: u32 = 535;
/// ERROR_PIPE_NOT_CONNECTED (233) — no client attached.
pub const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
/// ERROR_IO_PENDING (997) — overlapped request registered.
pub const ERROR_IO_PENDING: u32 = 997;
/// ERROR_SEM_TIMEOUT (121) — a wait timed out.
pub const ERROR_SEM_TIMEOUT: u32 = 121;

/// NT `STATUS_PENDING` — written to OVERLAPPED.Internal for async requests.
pub const STATUS_PENDING: usize = 0x103;

/// `CreateNamedPipeW` treats any instance count at or above this as unlimited.
pub const PIPE_UNLIMITED_INSTANCES: u32 = 255;

/// `WaitNamedPipeW` timeout values.
pub const NMPWAIT_WAIT_FOREVER: u32 = 0xFFFF_FFFF;
pub const NMPWAIT_USE_DEFAULT_WAIT: u32 = 0x0000_0000;

/// Server-side connection state of a single named pipe instance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PipeState {
    /// Created by `CreateNamedPipeW`, never connected, not listening. A client
    /// open completes the connection immediately (Wine `dlls/kernel32/tests/
    /// pipe.c` test at line 215: client opens right after CreateNamedPipeW).
    Idle,
    /// The server is inside `ConnectNamedPipe` waiting for a client.
    Listening,
    /// A client is attached. This is the stable state for data flow (future
    /// work); a new client open fails with ERROR_PIPE_BUSY and a re-listening
    /// `ConnectNamedPipe` fails with ERROR_PIPE_CONNECTED.
    Connected,
    /// After `DisconnectNamedPipe`; the instance accepts no new client until
    /// the server calls `ConnectNamedPipe` again.
    Disconnected,
}

/// A server `ConnectNamedPipe` submitted with an OVERLAPPED that is still
/// waiting for a client. Guest addresses are stored as integers so cleanup
/// never dereferences guest memory after cancellation or handle close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingConnect {
    /// Guest OVERLAPPED address.
    pub overlapped: usize,
    /// `hEvent` handle to signal on completion (0 when NULL).
    pub event: usize,
}

#[derive(Debug)]
struct PipeInstanceInner {
    state: PipeState,
    pending_connect: Option<PendingConnect>,
}

/// A single server-created pipe instance. Cloned Arcs are shared between the
/// server handle, the connected client handle, and the registry.
#[derive(Debug)]
pub struct PipeInstance {
    name: String,
    inner: Mutex<PipeInstanceInner>,
    condvar: Condvar,
}

type Registry = HashMap<String, Vec<Arc<PipeInstance>>>;

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
static REGISTRY_CONDVAR: Condvar = Condvar::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_registry() -> Option<MutexGuard<'static, Registry>> {
    registry()
        .lock()
        .map_err(|e| eprintln!("weave: weave-core: pipe registry mutex poisoned: {e}"))
        .ok()
}

/// Wake every `WaitNamedPipeW`/creation waiter so it can re-scan.
fn notify_pipe_change() {
    REGISTRY_CONDVAR.notify_all();
}

/// Validate a pipe name and return its canonical form. The `\\.\pipe\` prefix
/// and the pipe name are case-insensitive on Windows; registry lookups lowercase
/// the key.
pub fn canonical_name(name: &str) -> Option<String> {
    if name.to_lowercase().starts_with(r"\\.\pipe\") {
        Some(name.to_string())
    } else {
        None
    }
}

/// Create and register a new server pipe instance (`CreateNamedPipeW`).
///
/// * `max_instances` of 0 → ERROR_INVALID_PARAMETER (Wine rejects `instances`
///   values that make the instance count limit zero).
/// * A name without the `\\.\pipe\` prefix → ERROR_INVALID_NAME.
/// * When `max_instances` live instances already exist → ERROR_PIPE_LIMIT_REACHED.
pub fn create_server_instance(name: &str, max_instances: u32) -> Result<Arc<PipeInstance>, u32> {
    if max_instances == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let canonical = canonical_name(name).ok_or(ERROR_INVALID_NAME)?;
    let key = canonical.to_lowercase();
    let mut guard = lock_registry().ok_or(ERROR_INVALID_HANDLE)?;
    let instances = guard.entry(key).or_default();
    if max_instances < PIPE_UNLIMITED_INSTANCES && instances.len() >= max_instances as usize {
        return Err(ERROR_PIPE_LIMIT_REACHED);
    }
    let instance = Arc::new(PipeInstance {
        name: canonical,
        inner: Mutex::new(PipeInstanceInner {
            state: PipeState::Idle,
            pending_connect: None,
        }),
        condvar: Condvar::new(),
    });
    instances.push(Arc::clone(&instance));
    notify_pipe_change();
    Ok(instance)
}

/// Server side of the rendezvous (`ConnectNamedPipe`).
///
/// * `pending` is `Some` for an overlapped request: the instance begins
///   listening and returns ERROR_IO_PENDING immediately.
/// * `pending` is `None` for a blocking request: the caller waits on the
///   instance condvar until a client attaches.
///
/// Returns:
/// * `Ok(())` — connection established (blocking request).
/// * `Err(ERROR_IO_PENDING)` — overlapped request registered; the returned
///   `PendingConnect` is completed by the client open that attaches.
/// * `Err(ERROR_PIPE_CONNECTED)` — a client already connected (either the
///   client arrived first, or the instance is already listening).
pub fn server_connect(instance: &PipeInstance, pending: Option<PendingConnect>) -> Result<(), u32> {
    let mut guard = match instance.inner.lock() {
        Ok(g) => g,
        Err(_) => return Err(ERROR_INVALID_HANDLE),
    };
    match guard.state {
        PipeState::Connected | PipeState::Listening => return Err(ERROR_PIPE_CONNECTED),
        PipeState::Idle | PipeState::Disconnected => {}
    }
    guard.state = PipeState::Listening;
    if let Some(request) = pending {
        guard.pending_connect = Some(request);
        notify_pipe_change();
        return Err(ERROR_IO_PENDING);
    }
    // Blocking path: wait until a client attaches (state leaves Listening).
    while guard.state == PipeState::Listening {
        guard = match instance.condvar.wait(guard) {
            Ok(g) => g,
            Err(_) => return Err(ERROR_INVALID_HANDLE),
        };
    }
    Ok(())
}

/// Client side of the rendezvous (`CreateFileW` on a `\\.\pipe\` path).
///
/// Transitions the first connectable instance (Idle or Listening) to Connected
/// and returns it together with any server overlapped connect this open
/// completes (so the caller can write the OVERLAPPED completion).
///
/// Returns ERROR_FILE_NOT_FOUND when no instance exists and ERROR_PIPE_BUSY
/// when every instance is already attached.
pub fn client_open(name: &str) -> Result<(Arc<PipeInstance>, Option<PendingConnect>), u32> {
    let canonical = canonical_name(name).ok_or(ERROR_INVALID_NAME)?;
    let key = canonical.to_lowercase();
    let guard = lock_registry().ok_or(ERROR_INVALID_HANDLE)?;
    let instances = guard.get(&key).ok_or(ERROR_FILE_NOT_FOUND)?;
    for instance in instances {
        let mut inner = instance.inner.lock().unwrap();
        if matches!(inner.state, PipeState::Idle | PipeState::Listening) {
            let completed = inner.pending_connect.take();
            inner.state = PipeState::Connected;
            instance.condvar.notify_all();
            notify_pipe_change();
            return Ok((Arc::clone(instance), completed));
        }
    }
    Err(ERROR_PIPE_BUSY)
}

/// Disconnect a client from a server instance (`DisconnectNamedPipe`).
///
/// Returns `Ok(())` when a client was attached; `Err(ERROR_PIPE_NOT_CONNECTED)`
/// when the instance has no client (Wine `test_DisconnectNamedPipe` asserts the
/// second disconnect fails with ERROR_PIPE_NOT_CONNECTED).
pub fn server_disconnect(instance: &PipeInstance) -> Result<(), u32> {
    let mut guard = instance.inner.lock().unwrap();
    if guard.state != PipeState::Connected {
        return Err(ERROR_PIPE_NOT_CONNECTED);
    }
    guard.pending_connect = None;
    guard.state = PipeState::Disconnected;
    instance.condvar.notify_all();
    notify_pipe_change();
    Ok(())
}

/// Remove a server instance from the registry (`CloseHandle` on the server
/// handle). A connected client retains its own Arc, so the instance object
/// survives; a later client open sees no instance for the name.
pub fn unregister(instance: &Arc<PipeInstance>) {
    if let Some(mut guard) = lock_registry() {
        let key = instance.name.to_lowercase();
        if let Some(instances) = guard.get_mut(&key) {
            instances.retain(|i| !Arc::ptr_eq(i, instance));
            if instances.is_empty() {
                guard.remove(&key);
            }
            notify_pipe_change();
        }
    }
}

/// Current connection state of an instance.
pub fn state(instance: &PipeInstance) -> PipeState {
    instance.inner.lock().unwrap().state
}

/// Whether an instance accepts a new client in the given state.
pub fn is_connectable(state: PipeState) -> bool {
    matches!(state, PipeState::Idle | PipeState::Listening)
}

/// Client wait for a pipe instance to become connectable (`WaitNamedPipeW`).
///
/// Returns Ok(()) when an instance is (or becomes) connectable within the
/// timeout; Err(ERROR_SEM_TIMEOUT) on timeout. `NMPWAIT_WAIT_FOREVER` blocks
/// until an instance appears and is connectable.
pub fn wait_named_pipe(name: &str, timeout_ms: u32) -> Result<(), u32> {
    let canonical = canonical_name(name).ok_or(ERROR_INVALID_NAME)?;
    let key = canonical.to_lowercase();
    let deadline = if timeout_ms == NMPWAIT_WAIT_FOREVER {
        None
    } else {
        Some(std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64))
    };

    loop {
        // Fast path: any instance already connectable?
        {
            let guard = lock_registry().ok_or(ERROR_INVALID_HANDLE)?;
            if let Some(list) = guard.get(&key) {
                for instance in list {
                    let inner = instance.inner.lock().unwrap();
                    if is_connectable(inner.state) {
                        return Ok(());
                    }
                }
            }
        }
        // No connectable instance — wait for any pipe change (instance created,
        // client detached, server re-listening) and re-scan.
        let remaining = deadline.map(|d| {
            let now = std::time::Instant::now();
            d.saturating_duration_since(now)
                .as_millis()
                .min(u64::MAX as u128) as u64
        });
        let guard = lock_registry().ok_or(ERROR_INVALID_HANDLE)?;
        match remaining {
            Some(ms) => {
                let (_guard, timed_out) = REGISTRY_CONDVAR
                    .wait_timeout(guard, std::time::Duration::from_millis(ms))
                    .unwrap();
                if timed_out.timed_out() {
                    return Err(ERROR_SEM_TIMEOUT);
                }
            }
            None => {
                let _guard = REGISTRY_CONDVAR.wait(guard).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

    fn pipe_name() -> String {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\weave-unit-{}-{seq}", std::process::id())
    }

    #[test]
    fn create_rejects_bad_name_prefix() {
        assert_eq!(
            create_server_instance("not-a-pipe", 1).unwrap_err(),
            ERROR_INVALID_NAME
        );
    }

    #[test]
    fn create_rejects_zero_instances() {
        assert_eq!(
            create_server_instance(&pipe_name(), 0).unwrap_err(),
            ERROR_INVALID_PARAMETER
        );
    }

    #[test]
    fn create_and_register_is_findable() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");
        assert!(is_connectable(state(&inst)));
        let (found, _) = client_open(&name).expect("client must attach to Idle instance");
        assert!(Arc::ptr_eq(&found, &inst));
    }

    #[test]
    fn client_first_then_server_connect_returns_pipe_connected() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");
        let _client = client_open(&name).expect("client attaches to Idle instance");
        assert_eq!(server_connect(&inst, None), Err(ERROR_PIPE_CONNECTED));
    }

    #[test]
    fn server_listen_first_then_client_connects_blocking() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");
        let inst2 = Arc::clone(&inst);
        let server = std::thread::spawn(move || server_connect(&inst2, None));
        // Give the listener a moment to enter Listening, then attach a client.
        while state(&inst) != PipeState::Listening {
            std::thread::yield_now();
        }
        let (_client, completed) = client_open(&name).expect("client attaches to Listening");
        assert!(
            completed.is_none(),
            "blocking listen has no pending connect"
        );
        assert_eq!(server.join().expect("server thread"), Ok(()));
        assert_eq!(state(&inst), PipeState::Connected);
    }

    #[test]
    fn server_listen_first_then_client_connects_overlapped() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");
        let request = PendingConnect {
            overlapped: 0x1_0000,
            event: 0x1_0008,
        };
        assert_eq!(server_connect(&inst, Some(request)), Err(ERROR_IO_PENDING));
        assert_eq!(state(&inst), PipeState::Listening);
        let (_client, completed) = client_open(&name).expect("client attaches to Listening");
        assert_eq!(completed.expect("pending connect completes"), request);
        assert_eq!(state(&inst), PipeState::Connected);
    }

    #[test]
    fn busy_and_disconnected_instances_reject_new_clients() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");
        let _client = client_open(&name).expect("attach");
        assert_eq!(client_open(&name).unwrap_err(), ERROR_PIPE_BUSY);

        assert!(server_disconnect(&inst).is_ok());
        // Wine case 3: after DisconnectNamedPipe but before ConnectNamedPipe a
        // client open must fail with ERROR_PIPE_BUSY.
        assert_eq!(client_open(&name).unwrap_err(), ERROR_PIPE_BUSY);
    }

    #[test]
    fn reconnect_cycle_with_disconnect_between_clients() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");

        // Cycle 1: server listens, client attaches, server disconnects.
        let inst2 = Arc::clone(&inst);
        let server = std::thread::spawn(move || server_connect(&inst2, None));
        while state(&inst) != PipeState::Listening {
            std::thread::yield_now();
        }
        let (_client1, _) = client_open(&name).expect("first client");
        assert_eq!(server.join().expect("server"), Ok(()));
        assert!(server_disconnect(&inst).is_ok());

        // Cycle 2: re-listen and attach a second client.
        let inst3 = Arc::clone(&inst);
        let server2 = std::thread::spawn(move || server_connect(&inst3, None));
        while state(&inst) != PipeState::Listening {
            std::thread::yield_now();
        }
        let (_client2, _) = client_open(&name).expect("second client");
        assert_eq!(server2.join().expect("server"), Ok(()));
    }

    #[test]
    fn double_disconnect_fails_with_pipe_not_connected() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");
        let _client = client_open(&name).expect("attach");
        assert!(server_disconnect(&inst).is_ok());
        assert_eq!(
            server_disconnect(&inst).unwrap_err(),
            ERROR_PIPE_NOT_CONNECTED
        );
    }

    #[test]
    fn unregister_removes_instance_from_registry() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");
        unregister(&inst);
        assert_eq!(client_open(&name).unwrap_err(), ERROR_FILE_NOT_FOUND);
    }

    #[test]
    fn instance_limit_is_enforced() {
        let name = pipe_name();
        let _a = create_server_instance(&name, 2).expect("instance 1");
        let _b = create_server_instance(&name, 2).expect("instance 2");
        assert_eq!(
            create_server_instance(&name, 2).unwrap_err(),
            ERROR_PIPE_LIMIT_REACHED
        );
    }

    #[test]
    fn unlimited_instances_never_hit_the_limit() {
        let name = pipe_name();
        let _a = create_server_instance(&name, PIPE_UNLIMITED_INSTANCES).expect("instance 1");
        let _b = create_server_instance(&name, PIPE_UNLIMITED_INSTANCES).expect("instance 2");
        assert!(create_server_instance(&name, PIPE_UNLIMITED_INSTANCES).is_ok());
    }

    #[test]
    fn client_open_is_case_insensitive() {
        let name = pipe_name();
        let _inst = create_server_instance(&name, 1).expect("create");
        let upper = name.to_uppercase();
        assert!(
            client_open(&upper).is_ok(),
            "pipe names must resolve case-insensitively"
        );
    }

    #[test]
    fn wait_named_pipe_returns_immediately_when_connectable() {
        let name = pipe_name();
        let _inst = create_server_instance(&name, 1).expect("create");
        assert!(wait_named_pipe(&name, 1000).is_ok());
    }

    #[test]
    fn wait_named_pipe_times_out_on_busy_pipe() {
        let name = pipe_name();
        let inst = create_server_instance(&name, 1).expect("create");
        let _client = client_open(&name).expect("attach");
        assert_eq!(state(&inst), PipeState::Connected);
        assert_eq!(wait_named_pipe(&name, 50), Err(ERROR_SEM_TIMEOUT));
    }

    #[test]
    fn wait_named_pipe_waits_for_server_creation() {
        let name = pipe_name();
        assert_eq!(wait_named_pipe(&name, 0).unwrap_err(), ERROR_SEM_TIMEOUT);
        let name_for_thread = name.clone();
        let server = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            create_server_instance(&name_for_thread, 1)
        });
        let server_result = server.join().expect("creator");
        let created = server_result.expect("create");
        assert!(is_connectable(state(&created)));
        assert!(wait_named_pipe(&name, 1000).is_ok());
    }
}
