// Probe gate — TASK-1: GetFileTime + SetFileTime round-trip.
//
// Only runs on Linux x86_64 where futimens(2) is available and the win64
// calling convention is supported.
//
// Test plan:
//   1. Create a temp file via std::fs, extract its raw fd.
//   2. Register the fd in the Weave handle table to get a HANDLE.
//   3. Call SetFileTime with a known write timestamp (2020-01-01T00:00:00Z).
//   4. Call GetFileTime and assert the write timestamp matches within ±1 second
//      (one FILETIME tick = 100 ns; 1-second tolerance = 10_000_000 ticks).
//   5. Verify that SetFileTime with only creation time set returns TRUE (no-op).
//   6. Verify GetFileTime with all-NULL pointers returns TRUE.
//   7. Verify GetFileTime/SetFileTime on an invalid handle return FALSE.
//   8. Clean up: close_handle (closes fd), delete temp file.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::os::unix::io::IntoRawFd;

use weave_core::file_io::close_handle as weave_close_handle;
use weave_core::handles::{alloc, HandleKind};
use weave_kernel32::{get_file_time, set_file_time};

/// FILETIME for 2020-01-01T00:00:00Z.
///
/// Derivation: seconds from 1601-01-01 to 2020-01-01 = 13,190,400 days × 86400
/// = 1_139_385_600 + offset_seconds.
/// Python: int((datetime(2020,1,1,tzinfo=timezone.utc) - datetime(1601,1,1)).total_seconds() * 10_000_000)
/// = 132_225_888_000_000_000
const FILETIME_2020_01_01: u64 = 132_225_888_000_000_000;

/// One second expressed in FILETIME units (100-ns intervals).
const ONE_SECOND_FT: u64 = 10_000_000;

#[test]
fn set_and_get_file_time_round_trip() {
    // ── 1. Create temp file ──────────────────────────────────────────────────
    let dir = std::env::temp_dir();
    let path = dir.join("weave_file_time_probe.tmp");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("failed to create temp file");

    // Extract the raw Linux fd and register it in the Weave handle table.
    let raw_fd = file.into_raw_fd();
    let handle = alloc(HandleKind::File(raw_fd));
    assert!(handle != 0, "handle must be non-zero");

    // ── 2. SetFileTime — write timestamp only ────────────────────────────────
    let write_ft: u64 = FILETIME_2020_01_01;
    let ret = unsafe {
        set_file_time(
            handle,
            std::ptr::null(), // creation — NULL (skip)
            std::ptr::null(), // access   — NULL (skip)
            &write_ft as *const u64,
        )
    };
    assert_eq!(ret, 1, "SetFileTime must return TRUE");

    // ── 3. GetFileTime — read back write timestamp ───────────────────────────
    let mut got_creation: u64 = 0;
    let mut got_access: u64 = 0;
    let mut got_write: u64 = 0;
    let ret = unsafe {
        get_file_time(
            handle,
            &mut got_creation as *mut u64,
            &mut got_access as *mut u64,
            &mut got_write as *mut u64,
        )
    };
    assert_eq!(ret, 1, "GetFileTime must return TRUE");

    // Assert write timestamp is within ±1 second of what we set.
    let diff = if got_write >= write_ft {
        got_write - write_ft
    } else {
        write_ft - got_write
    };
    assert!(
        diff <= ONE_SECOND_FT,
        "write timestamp mismatch: set={write_ft} got={got_write} diff={diff} (> 1s tolerance)"
    );

    // ── 4. SetFileTime — creation time only → must succeed (no-op on Linux) ──
    let creation_ft: u64 = FILETIME_2020_01_01;
    let ret = unsafe {
        set_file_time(
            handle,
            &creation_ft as *const u64,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(
        ret, 1,
        "SetFileTime with creation-only must return TRUE (Linux no-op)"
    );

    // ── 5. GetFileTime with all-NULL pointers must not crash ─────────────────
    let ret = unsafe {
        get_file_time(
            handle,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        ret, 1,
        "GetFileTime with all-NULL output pointers must return TRUE"
    );

    // ── 6. Invalid handle returns FALSE ──────────────────────────────────────
    let mut dummy: u64 = 0;
    let ret = unsafe {
        get_file_time(
            usize::MAX, // INVALID_HANDLE_VALUE
            &mut dummy as *mut u64,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(ret, 0, "GetFileTime on invalid handle must return FALSE");

    let ret = unsafe {
        set_file_time(
            usize::MAX,
            std::ptr::null(),
            std::ptr::null(),
            &dummy as *const u64,
        )
    };
    assert_eq!(ret, 0, "SetFileTime on invalid handle must return FALSE");

    // ── Cleanup ──────────────────────────────────────────────────────────────
    // close_handle frees the table slot and closes the underlying Linux fd.
    let _ = weave_close_handle(handle);
    let _ = std::fs::remove_file(&path);
}
