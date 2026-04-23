// Probe gate — TASK-1: CreateSemaphoreW/A — real POSIX semaphore backing.
//
// Only runs on Linux x86_64 where the win64 calling convention and POSIX
// semaphores are both available.
//
// Test plan:
//   TASK-1 assertions (semaphore_create_probe_gate):
//   1. CreateSemaphoreW(null, initial=2, max=5, null) returns a non-zero handle.
//   2. Returned handle is not the old fake value (1).
//   3. sem_getvalue on the backing sem_t equals initial_count (2).
//   4. CreateSemaphoreW(null, 6, 5, null) returns 0  (initial > max → NULL).
//   5. CreateSemaphoreW(null, 0, 0, null) returns 0  (max = 0 → NULL).
//
//   TASK-2 assertions (semaphore_release_probe_gate):
//   6. ReleaseSemaphore post increments count; previous count written correctly.
//   7. Releasing up to max succeeds; sem value equals max_count.
//   8. Releasing beyond max returns FALSE; value unchanged at max_count.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ptr::{null, null_mut};
use weave_kernel32::{
    create_semaphore_a, create_semaphore_w, release_semaphore, semaphore_getvalue,
};

#[test]
fn semaphore_create_probe_gate() {
    // Assertion 1 & 2: handle is non-zero and not the old fake value.
    let handle = unsafe { create_semaphore_w(null(), 2, 5, null()) };
    assert_ne!(handle, 0, "handle must be non-NULL");
    assert_ne!(handle, 1, "handle must not be the old fake value");

    // Assertion 3: backing sem_t value == initial_count.
    let val = semaphore_getvalue(handle).expect("handle must be in SEMAPHORE_TABLE");
    assert_eq!(
        val, 2,
        "sem_getvalue must equal initial_count (2), got {val}"
    );

    // Assertion 4: initial > max → NULL.
    let bad = unsafe { create_semaphore_w(null(), 6, 5, null()) };
    assert_eq!(bad, 0, "initial > max must return NULL, got {bad:#x}");

    // Assertion 5: max = 0 → NULL.
    let bad2 = unsafe { create_semaphore_w(null(), 0, 0, null()) };
    assert_eq!(bad2, 0, "max=0 must return NULL, got {bad2:#x}");
}

#[test]
fn semaphore_create_a_trampoline() {
    // CreateSemaphoreA must delegate to the real implementation and return a
    // valid handle (not 0, not the old fake 1).
    let handle = unsafe { create_semaphore_a(null(), 3, 10, null()) };
    assert_ne!(handle, 0, "CreateSemaphoreA handle must be non-NULL");
    assert_ne!(
        handle, 1,
        "CreateSemaphoreA handle must not be the old fake value"
    );

    let val =
        semaphore_getvalue(handle).expect("CreateSemaphoreA handle must be in SEMAPHORE_TABLE");
    assert_eq!(
        val, 3,
        "CreateSemaphoreA: sem_getvalue must equal initial_count (3), got {val}"
    );
}

#[test]
fn semaphore_release_probe_gate() {
    // create with initial=0, max=3
    let handle = unsafe { create_semaphore_w(null(), 0, 3, null()) };
    assert_ne!(handle, 0);

    let mut prev: i32 = -1;

    // release once → prev should be 0, value should be 1
    let ok = unsafe { release_semaphore(handle, 1, &mut prev) };
    assert_ne!(ok, 0, "ReleaseSemaphore must return TRUE");
    assert_eq!(prev, 0, "previous count must be 0 before first release");
    assert_eq!(semaphore_getvalue(handle).unwrap(), 1);

    // release twice more → value should be 3 (at max)
    let ok = unsafe { release_semaphore(handle, 2, null_mut()) };
    assert_ne!(ok, 0);
    assert_eq!(semaphore_getvalue(handle).unwrap(), 3);

    // release beyond max → FALSE + ERROR_TOO_MANY_POSTS
    let ok = unsafe { release_semaphore(handle, 1, null_mut()) };
    assert_eq!(ok, 0, "over-max release must return FALSE");
    // value must not have changed
    assert_eq!(semaphore_getvalue(handle).unwrap(), 3);
}
