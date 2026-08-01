// Gate test — ConnectNamedPipe + named pipe rendezvous (rank #18).
//
// Only runs on Linux x86_64 where the win64 calling convention is available.
//
// Covers:
//   A1 — CreateNamedPipeW then blocking ConnectNamedPipe with a matching
//        client (CreateFileW on the \\.\pipe\ path) → TRUE.
//   A2 — ConnectNamedPipe on an invalid handle → FALSE + ERROR_INVALID_HANDLE.
//   A3 — ConnectNamedPipe twice (DisconnectNamedPipe between clients) works.
//   A4 — Overlapped ConnectNamedPipe → FALSE + ERROR_IO_PENDING with
//        OVERLAPPED.Internal = STATUS_PENDING; completed on client attach
//        (Internal = 0, hEvent signaled).
//   B1 — ConnectNamedPipe on a client handle → ERROR_INVALID_FUNCTION.
//   B2 — ConnectNamedPipe after client connected first → ERROR_PIPE_CONNECTED.
//   B3 — Client open on attached / disconnected-instance → ERROR_PIPE_BUSY.
//   B4 — Double DisconnectNamedPipe → ERROR_PIPE_NOT_CONNECTED.
//   B5 — CloseHandle(server) unregisters → client open → ERROR_FILE_NOT_FOUND.
//   B6 — GetFileType on a pipe handle → FILE_TYPE_PIPE.
//   B7 — WaitNamedPipeW: fresh instance → TRUE; busy instance times out.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ptr::null;
use std::sync::atomic::{AtomicU32, Ordering};

use weave_kernel32::{
    close_handle, connect_named_pipe, create_event_w, create_file_w, create_named_pipe_w,
    disconnect_named_pipe, get_file_type, get_last_error, set_last_error, wait_for_single_object,
    wait_named_pipe_w,
};

const GENERIC_READ_WRITE: u32 = 0xC000_0000; // GENERIC_READ | GENERIC_WRITE
const OPEN_EXISTING: u32 = 3;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_FUNCTION: u32 = 1;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PIPE_BUSY: u32 = 231;
const ERROR_PIPE_CONNECTED: u32 = 535;
const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
const ERROR_IO_PENDING: u32 = 997;
const ERROR_SEM_TIMEOUT: u32 = 121;
const STATUS_PENDING: usize = 0x103;
const FILE_TYPE_PIPE: u32 = 0x0003;
const WAIT_OBJECT_0: u32 = 0;

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

fn pipe_name() -> String {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\weave-connect-gate-{}-{seq}", std::process::id())
}

fn wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn create_server(name: &str) -> usize {
    let name_wide = wide(name);
    unsafe { create_named_pipe_w(name_wide.as_ptr(), 3, 0, 1, 1024, 1024, 0, 0) }
}

fn open_client(name: &str) -> usize {
    let name_wide = wide(name);
    unsafe {
        create_file_w(
            name_wide.as_ptr(),
            GENERIC_READ_WRITE,
            0,
            0,
            OPEN_EXISTING,
            0,
            0,
        )
    }
}

/// A1 — blocking ConnectNamedPipe returns TRUE when a client attaches.
#[test]
fn connect_named_pipe_blocks_until_client_connects() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX, "CreateNamedPipeW must succeed");

    // Resolve the shared instance so the main thread can wait for the listener
    // to reach the Listening state (deterministic server-first ordering).
    let (instance, _) = weave_core::handles::get_named_pipe(server).expect("server pipe handle");
    let listener = std::thread::spawn(move || unsafe { connect_named_pipe(server, 0) });

    while weave_core::named_pipe::state(&instance) != weave_core::named_pipe::PipeState::Listening {
        std::thread::yield_now();
    }

    let client = open_client(&name);
    assert_ne!(
        client,
        usize::MAX,
        "client must attach to a listening instance"
    );
    let server_ret = listener.join().expect("listener thread");
    assert_eq!(server_ret, 1, "blocking ConnectNamedPipe must return TRUE");

    assert_eq!(close_handle(client), 1);
    assert_eq!(close_handle(server), 1);
}

/// A2 — ConnectNamedPipe on an invalid handle → FALSE + ERROR_INVALID_HANDLE.
#[test]
fn connect_named_pipe_invalid_handle() {
    set_last_error(0);
    let ret = unsafe { connect_named_pipe(0xDEAD, 0) };
    assert_eq!(ret, 0, "invalid handle must fail");
    assert_eq!(get_last_error(), ERROR_INVALID_HANDLE);
}

/// A3 — ConnectNamedPipe twice works when DisconnectNamedPipe re-arms between
/// client cycles.
#[test]
fn connect_named_pipe_twice_after_disconnect() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX);

    for cycle in 0..2 {
        let (instance, _) = weave_core::handles::get_named_pipe(server).expect("server pipe");
        let listener = std::thread::spawn(move || unsafe { connect_named_pipe(server, 0) });
        while weave_core::named_pipe::state(&instance)
            != weave_core::named_pipe::PipeState::Listening
        {
            std::thread::yield_now();
        }
        let client = open_client(&name);
        assert_ne!(client, usize::MAX, "cycle {cycle}: client attaches");
        let server_ret = listener.join().expect("listener");
        assert_eq!(
            server_ret, 1,
            "cycle {cycle}: ConnectNamedPipe returns TRUE"
        );
        assert_eq!(close_handle(client), 1);
        assert_eq!(
            disconnect_named_pipe(server),
            1,
            "cycle {cycle}: DisconnectNamedPipe re-arms the instance"
        );
    }
    assert_eq!(close_handle(server), 1);
}

/// A4 — Overlapped ConnectNamedPipe returns FALSE + ERROR_IO_PENDING, marks
/// OVERLAPPED.Internal as STATUS_PENDING, and completes (Internal = 0, hEvent
/// signaled) when the client attaches.
#[test]
fn connect_named_pipe_overlapped_pending() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX);

    let event = unsafe { create_event_w(null(), 1, 0, null()) };
    assert_ne!(event, 0, "event must back the OVERLAPPED.hEvent");

    // OVERLAPPED layout on x64: Internal(+0) InternalHigh(+8) Offset(+16)
    // OffsetHigh(+20) hEvent(+24).
    let mut overlapped = [0usize; 4];
    overlapped[3] = event;

    set_last_error(0);
    let ret = unsafe { connect_named_pipe(server, overlapped.as_ptr() as usize) };
    assert_eq!(ret, 0, "overlapped ConnectNamedPipe returns FALSE");
    assert_eq!(get_last_error(), ERROR_IO_PENDING);
    assert_eq!(
        overlapped[0], STATUS_PENDING,
        "Internal must be STATUS_PENDING"
    );

    let client = open_client(&name);
    assert_ne!(client, usize::MAX, "client attaches to the pending listen");
    assert_eq!(
        overlapped[0], 0,
        "Internal must be STATUS_SUCCESS on connect"
    );
    assert_eq!(overlapped[1], 0, "InternalHigh must be 0 bytes transferred");

    let wait = unsafe { wait_for_single_object(event, 5000) };
    assert_eq!(wait, WAIT_OBJECT_0, "hEvent must be signaled on connect");

    assert_eq!(close_handle(client), 1);
    assert_eq!(close_handle(server), 1);
    // Event handles have no CloseHandle path in Weave (eventfd is process-
    // lifetime); not asserted here.
}

/// B1 — ConnectNamedPipe on a client handle → ERROR_INVALID_FUNCTION.
/// B2 — ConnectNamedPipe after the client connected first → ERROR_PIPE_CONNECTED.
#[test]
fn connect_named_pipe_client_handle_and_already_connected() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX);

    let client = open_client(&name);
    assert_ne!(client, usize::MAX, "client attaches to the Idle instance");

    set_last_error(0);
    let ret = unsafe { connect_named_pipe(client, 0) };
    assert_eq!(ret, 0);
    assert_eq!(get_last_error(), ERROR_INVALID_FUNCTION);

    set_last_error(0);
    let ret = unsafe { connect_named_pipe(server, 0) };
    assert_eq!(ret, 0);
    assert_eq!(get_last_error(), ERROR_PIPE_CONNECTED);

    assert_eq!(close_handle(client), 1);
    assert_eq!(close_handle(server), 1);
}

/// B3 — Client open on an attached instance (before and after the client
/// closes) and on a disconnected-but-not-listening instance → ERROR_PIPE_BUSY.
#[test]
fn named_pipe_busy_and_reconnect_semantics() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX);

    let client = open_client(&name);
    assert_ne!(client, usize::MAX);

    // Case 1: client still attached → busy.
    set_last_error(0);
    let second = open_client(&name);
    assert_eq!(second, usize::MAX);
    assert_eq!(get_last_error(), ERROR_PIPE_BUSY);

    // Case 2: client closed, server not disconnected → still busy.
    assert_eq!(close_handle(client), 1);
    set_last_error(0);
    let second = open_client(&name);
    assert_eq!(second, usize::MAX);
    assert_eq!(get_last_error(), ERROR_PIPE_BUSY);

    // Case 3: server disconnected but not re-listening → still busy.
    assert_eq!(disconnect_named_pipe(server), 1);
    set_last_error(0);
    let second = open_client(&name);
    assert_eq!(second, usize::MAX);
    assert_eq!(get_last_error(), ERROR_PIPE_BUSY);

    assert_eq!(close_handle(server), 1);
}

/// B4 — Double DisconnectNamedPipe → second call FALSE + ERROR_PIPE_NOT_CONNECTED.
#[test]
fn disconnect_named_pipe_twice_fails() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX);

    let client = open_client(&name);
    assert_ne!(client, usize::MAX);
    assert_eq!(disconnect_named_pipe(server), 1);

    set_last_error(0);
    let ret = disconnect_named_pipe(server);
    assert_eq!(ret, 0);
    assert_eq!(get_last_error(), ERROR_PIPE_NOT_CONNECTED);

    assert_eq!(close_handle(client), 1);
    assert_eq!(close_handle(server), 1);
}

/// B5 — CloseHandle on the server handle unregisters the instance; a later
/// client open finds no instance → ERROR_FILE_NOT_FOUND.
#[test]
fn close_handle_server_unregisters_pipe() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX);
    assert_eq!(close_handle(server), 1);

    set_last_error(0);
    let client = open_client(&name);
    assert_eq!(client, usize::MAX);
    assert_eq!(get_last_error(), ERROR_FILE_NOT_FOUND);
}

/// B6 — GetFileType on a pipe handle → FILE_TYPE_PIPE.
#[test]
fn get_file_type_returns_pipe() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX);
    assert_eq!(get_file_type(server), FILE_TYPE_PIPE);
    assert_eq!(close_handle(server), 1);
}

/// B7 — WaitNamedPipeW: fresh instance → TRUE; busy instance → ERROR_SEM_TIMEOUT.
#[test]
fn wait_named_pipe_connectable_then_busy() {
    let name = pipe_name();
    let server = create_server(&name);
    assert_ne!(server, usize::MAX);
    let name_wide = wide(&name);

    set_last_error(0);
    let ret = unsafe { wait_named_pipe_w(name_wide.as_ptr(), 2000) };
    assert_eq!(ret, 1, "WaitNamedPipeW on a fresh instance succeeds");

    let client = open_client(&name);
    assert_ne!(client, usize::MAX);

    set_last_error(0);
    let ret = unsafe { wait_named_pipe_w(name_wide.as_ptr(), 50) };
    assert_eq!(ret, 0, "busy instance must time out");
    assert_eq!(get_last_error(), ERROR_SEM_TIMEOUT);

    assert_eq!(close_handle(client), 1);
    assert_eq!(close_handle(server), 1);
}
