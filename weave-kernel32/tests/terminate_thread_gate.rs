// Probe gate — TerminateThread: force-terminate a thread handle.
//
// Only runs on Linux x86_64 where the win64 calling convention is available.
//
// Test plan (mirrors Wine dlls/kernel32/tests/thread.c::test_TerminateThread):
//   1. TerminateThread on a running thread → TRUE.
//   2. After TerminateThread, WaitForSingleObject(thread) → WAIT_OBJECT_0.
//   3. GetExitCodeThread returns the dwExitCode passed to TerminateThread.
//   4. Invalid handle (NULL / INVALID_HANDLE_VALUE / non-thread handle)
//      → FALSE + ERROR_INVALID_HANDLE.
//   5. TerminateThread on a CREATE_SUSPENDED thread → TRUE; thread never
//      runs guest code; WFSO → WAIT_OBJECT_0; exit code retrievable.
//   6. A guest that returns after TerminateThread must not overwrite the
//      TerminateThread exit code.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use weave_kernel32::{
    create_semaphore_w, create_thread, get_exit_code_thread, get_last_error, terminate_thread,
    wait_for_single_object,
};

const WAIT_OBJECT_0: u32 = 0;
const STILL_ACTIVE: u32 = 259;
const ERROR_INVALID_HANDLE: u32 = 6;
const CREATE_SUSPENDED: u32 = 0x4;

// ── Guest procs ──────────────────────────────────────────────────────────────

static RUNNING_GUEST_STARTED: AtomicBool = AtomicBool::new(false);

/// Guest that signals it is running, then loops forever.
unsafe extern "win64" fn running_guest(_param: *mut u8) -> u32 {
    RUNNING_GUEST_STARTED.store(true, Ordering::SeqCst);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

static SUSPENDED_GUEST_RAN: AtomicBool = AtomicBool::new(false);

/// Guest for the CREATE_SUSPENDED case — must never run.
unsafe extern "win64" fn suspended_guest(_param: *mut u8) -> u32 {
    SUSPENDED_GUEST_RAN.store(true, Ordering::SeqCst);
    0
}

static BLOCKED_GUEST_STARTED: AtomicBool = AtomicBool::new(false);
static BLOCKED_GUEST_PROCEED: AtomicBool = AtomicBool::new(false);

/// Guest that signals it started, then blocks until released.
unsafe extern "win64" fn blocked_guest(_param: *mut u8) -> u32 {
    BLOCKED_GUEST_STARTED.store(true, Ordering::SeqCst);
    while !BLOCKED_GUEST_PROCEED.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    0xCAFE
}

fn spin_until(flag: &AtomicBool, what: &str) {
    for _ in 0..5000 {
        if flag.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("timed out waiting for {what}");
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn terminate_thread_running_thread_signals_handle_and_sets_exit_code() {
    // Assertion 1-3: terminate a genuinely running thread.
    let handle = unsafe {
        create_thread(
            null(),
            0,
            running_guest as *const () as *const u8,
            null_mut(),
            0,
            null_mut(),
        )
    };
    assert_ne!(handle, 0, "CreateThread must return a non-NULL handle");
    spin_until(&RUNNING_GUEST_STARTED, "running guest to start");

    let ok = unsafe { terminate_thread(handle, 0x1_DEAD) };
    assert_ne!(
        ok, 0,
        "TerminateThread on a running thread must return TRUE"
    );

    let r = unsafe { wait_for_single_object(handle, 5000) };
    assert_eq!(
        r, WAIT_OBJECT_0,
        "WFSO after TerminateThread must be WAIT_OBJECT_0, got {r:#x}"
    );

    let mut code = 0u32;
    let ok2 = unsafe { get_exit_code_thread(handle, &mut code) };
    assert_ne!(ok2, 0, "GetExitCodeThread must return TRUE");
    assert_ne!(
        code, STILL_ACTIVE,
        "TerminateThread must not leave the thread STILL_ACTIVE"
    );
    assert_eq!(
        code, 0x1_DEAD,
        "GetExitCodeThread must return the TerminateThread exit code, got {code:#x}"
    );
}

#[test]
fn terminate_thread_suspended_thread_never_runs_guest() {
    // Assertion 5: terminate before start (CREATE_SUSPENDED).
    let handle = unsafe {
        create_thread(
            null(),
            0,
            suspended_guest as *const () as *const u8,
            null_mut(),
            CREATE_SUSPENDED,
            null_mut(),
        )
    };
    assert_ne!(handle, 0, "CreateThread must return a non-NULL handle");

    let ok = unsafe { terminate_thread(handle, 0xBEEF) };
    assert_ne!(
        ok, 0,
        "TerminateThread on a suspended thread must return TRUE"
    );

    let r = unsafe { wait_for_single_object(handle, 5000) };
    assert_eq!(
        r, WAIT_OBJECT_0,
        "WFSO after TerminateThread of suspended thread must be WAIT_OBJECT_0, got {r:#x}"
    );

    let mut code = 0u32;
    let ok2 = unsafe { get_exit_code_thread(handle, &mut code) };
    assert_ne!(ok2, 0, "GetExitCodeThread must return TRUE");
    assert_eq!(
        code, 0xBEEF,
        "GetExitCodeThread must return the TerminateThread exit code, got {code:#x}"
    );

    // Give the trampoline a window to observe the flag; the guest must never run.
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        !SUSPENDED_GUEST_RAN.load(Ordering::SeqCst),
        "suspended guest must never run after TerminateThread"
    );
}

#[test]
fn terminate_thread_then_guest_return_does_not_overwrite_exit_code() {
    // Assertion 6: a guest that returns after TerminateThread must not clobber
    // the TerminateThread exit code (no DLL_THREAD_DETACH, no result overwrite).
    let handle = unsafe {
        create_thread(
            null(),
            0,
            blocked_guest as *const () as *const u8,
            null_mut(),
            0,
            null_mut(),
        )
    };
    assert_ne!(handle, 0, "CreateThread must return a non-NULL handle");
    spin_until(&BLOCKED_GUEST_STARTED, "blocked guest to start");

    let ok = unsafe { terminate_thread(handle, 0xDEAD) };
    assert_ne!(ok, 0, "TerminateThread must return TRUE");

    let r = unsafe { wait_for_single_object(handle, 5000) };
    assert_eq!(
        r, WAIT_OBJECT_0,
        "WFSO must be WAIT_OBJECT_0 while the guest is still blocked, got {r:#x}"
    );

    // Release the guest; it returns 0xCAFE. The trampoline must not overwrite.
    BLOCKED_GUEST_PROCEED.store(true, Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut code = 0u32;
    let ok2 = unsafe { get_exit_code_thread(handle, &mut code) };
    assert_ne!(ok2, 0, "GetExitCodeThread must return TRUE");
    assert_eq!(
        code, 0xDEAD,
        "guest return value must not overwrite the TerminateThread exit code, got {code:#x}"
    );
}

#[test]
fn terminate_thread_invalid_handle_returns_false_invalid_handle() {
    // Assertion 4: NULL handle.
    weave_kernel32::set_last_error(0);
    let ok = unsafe { terminate_thread(0, 0x99) };
    assert_eq!(ok, 0, "NULL handle → FALSE");
    assert_eq!(
        get_last_error(),
        ERROR_INVALID_HANDLE,
        "NULL handle → ERROR_INVALID_HANDLE, got {}",
        get_last_error()
    );

    // INVALID_HANDLE_VALUE (usize::MAX).
    weave_kernel32::set_last_error(0);
    let ok = unsafe { terminate_thread(usize::MAX, 0x99) };
    assert_eq!(ok, 0, "INVALID_HANDLE_VALUE → FALSE");
    assert_eq!(
        get_last_error(),
        ERROR_INVALID_HANDLE,
        "INVALID_HANDLE_VALUE → ERROR_INVALID_HANDLE"
    );

    // A valid handle that is not a thread handle.
    let sem = unsafe { create_semaphore_w(null(), 1, 1, null()) };
    assert_ne!(sem, 0, "semaphore handle must be valid");
    weave_kernel32::set_last_error(0);
    let ok = unsafe { terminate_thread(sem, 0x99) };
    assert_eq!(ok, 0, "non-thread handle → FALSE");
    assert_eq!(
        get_last_error(),
        ERROR_INVALID_HANDLE,
        "non-thread handle → ERROR_INVALID_HANDLE"
    );
}

#[test]
fn get_exit_code_thread_returns_natural_exit_code() {
    // A thread that exits normally must report its return value (not
    // STILL_ACTIVE) via GetExitCodeThread once it completes.
    static NATURAL_GUEST_RAN: AtomicBool = AtomicBool::new(false);
    unsafe extern "win64" fn natural_guest(_param: *mut u8) -> u32 {
        NATURAL_GUEST_RAN.store(true, Ordering::SeqCst);
        42
    }

    let handle = unsafe {
        create_thread(
            null(),
            0,
            natural_guest as *const () as *const u8,
            null_mut(),
            0,
            null_mut(),
        )
    };
    assert_ne!(handle, 0, "CreateThread must return a non-NULL handle");

    let r = unsafe { wait_for_single_object(handle, 5000) };
    assert_eq!(
        r, WAIT_OBJECT_0,
        "WFSO must be WAIT_OBJECT_0 after natural exit, got {r:#x}"
    );

    let mut code = 0u32;
    let ok = unsafe { get_exit_code_thread(handle, &mut code) };
    assert_ne!(ok, 0, "GetExitCodeThread must return TRUE");
    assert_eq!(
        code, 42,
        "GetExitCodeThread must return the thread's natural exit code, got {code}"
    );
}
