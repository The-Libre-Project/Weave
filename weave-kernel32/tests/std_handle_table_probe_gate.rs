// Probe gate — TASK-3: SetStdHandle → real process-global handle table.
//
// Only runs on Linux x86_64 where the win64 calling convention is supported.
//
// Test plan (5 Tier A assertions):
//   1. GetStdHandle(STD_OUTPUT_HANDLE) returns a non-MAX value initially
//      (the existing constant — no override set yet).
//   2. SetStdHandle(STD_OUTPUT_HANDLE, 0xDEAD_BEEFusize) returns TRUE (1).
//   3. GetStdHandle(STD_OUTPUT_HANDLE) returns 0xDEAD_BEEFusize (the override).
//   4. After restoring with SetStdHandle(STD_OUTPUT_HANDLE, STDOUT_HANDLE),
//      GetStdHandle(STD_OUTPUT_HANDLE) returns STDOUT_HANDLE again.
//   5. SetStdHandle(0xBEEFu32, 0) returns FALSE (0) — invalid nStdHandle.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use weave_core::handles;
use weave_kernel32::{get_std_handle, set_std_handle};

const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5u32;

#[test]
fn get_std_handle_returns_default_before_override() {
    // Tier A assertion 1: initial value is not INVALID_HANDLE_VALUE (usize::MAX).
    // The default constant must be a real handle value.
    let initial = unsafe { get_std_handle(STD_OUTPUT_HANDLE) };
    assert_ne!(
        initial,
        usize::MAX,
        "GetStdHandle(STD_OUTPUT_HANDLE) must return a non-MAX default handle, got {initial:#x}"
    );
    assert_eq!(
        initial,
        handles::STDOUT_HANDLE,
        "GetStdHandle(STD_OUTPUT_HANDLE) must return STDOUT_HANDLE before any override, got {initial:#x}"
    );
}

#[test]
fn set_std_handle_returns_true_for_valid_std_handle() {
    // Tier A assertion 2: SetStdHandle with a valid nStdHandle returns TRUE (1).
    let ret = unsafe { set_std_handle(STD_OUTPUT_HANDLE, 0xDEAD_BEEFusize) };
    assert_eq!(
        ret, 1,
        "SetStdHandle(STD_OUTPUT_HANDLE, 0xDEADBEEF) must return TRUE (1), got {ret}"
    );
    // Restore so this test doesn't pollute subsequent tests.
    unsafe { set_std_handle(STD_OUTPUT_HANDLE, handles::STDOUT_HANDLE) };
}

#[test]
fn get_std_handle_returns_override_after_set() {
    // Tier A assertion 3: GetStdHandle returns the value written by SetStdHandle.
    unsafe { set_std_handle(STD_OUTPUT_HANDLE, 0xDEAD_BEEFusize) };
    let overridden = unsafe { get_std_handle(STD_OUTPUT_HANDLE) };
    assert_eq!(
        overridden, 0xDEAD_BEEFusize,
        "GetStdHandle(STD_OUTPUT_HANDLE) must return 0xDEADBEEF after SetStdHandle, got {overridden:#x}"
    );
    // Restore.
    unsafe { set_std_handle(STD_OUTPUT_HANDLE, handles::STDOUT_HANDLE) };
}

#[test]
fn get_std_handle_returns_default_after_restore() {
    // Tier A assertion 4: After restoring the original handle, GetStdHandle returns it.
    unsafe { set_std_handle(STD_OUTPUT_HANDLE, 0xDEAD_BEEFusize) };
    unsafe { set_std_handle(STD_OUTPUT_HANDLE, handles::STDOUT_HANDLE) };
    let restored = unsafe { get_std_handle(STD_OUTPUT_HANDLE) };
    assert_eq!(
        restored,
        handles::STDOUT_HANDLE,
        "GetStdHandle(STD_OUTPUT_HANDLE) must return STDOUT_HANDLE after restore, got {restored:#x}"
    );
}

#[test]
fn set_std_handle_returns_false_for_invalid_std_handle() {
    // Tier A assertion 5: SetStdHandle with an unknown nStdHandle returns FALSE (0).
    let ret = unsafe { set_std_handle(0xBEEFu32, 0) };
    assert_eq!(
        ret, 0,
        "SetStdHandle(0xBEEF, 0) must return FALSE (0) for invalid nStdHandle, got {ret}"
    );
}

#[test]
fn set_std_handle_invalid_handle_value_is_stored_not_cleared() {
    // Tier A assertion 6 (TASK-4): SetStdHandle(STD_OUTPUT_HANDLE, INVALID_HANDLE_VALUE)
    // must store usize::MAX as a real override, not silently clear the slot.
    // Previously the NO_OVERRIDE sentinel was usize::MAX, causing INVALID_HANDLE_VALUE
    // to be misinterpreted as "no override". After the fix, the sentinel is usize::MAX - 1.
    let invalid_handle_value: usize = usize::MAX; // INVALID_HANDLE_VALUE on Win32
    unsafe { set_std_handle(STD_OUTPUT_HANDLE, invalid_handle_value) };
    let result = unsafe { get_std_handle(STD_OUTPUT_HANDLE) };
    assert_eq!(
        result, usize::MAX,
        "GetStdHandle(STD_OUTPUT_HANDLE) must return INVALID_HANDLE_VALUE (usize::MAX) \
         after SetStdHandle(STD_OUTPUT_HANDLE, INVALID_HANDLE_VALUE), got {result:#x}"
    );
    // Restore slot to NO_OVERRIDE sentinel so subsequent tests see the default constant.
    // NO_OVERRIDE = usize::MAX - 1 — the only value that cannot be a real Win32 handle.
    let no_override_sentinel: usize = usize::MAX - 1;
    unsafe { set_std_handle(STD_OUTPUT_HANDLE, no_override_sentinel) };
    // Confirm the slot is back to the default constant after restore.
    let restored = unsafe { get_std_handle(STD_OUTPUT_HANDLE) };
    assert_eq!(
        restored,
        handles::STDOUT_HANDLE,
        "GetStdHandle(STD_OUTPUT_HANDLE) must return STDOUT_HANDLE after restoring \
         NO_OVERRIDE sentinel, got {restored:#x}"
    );
}
