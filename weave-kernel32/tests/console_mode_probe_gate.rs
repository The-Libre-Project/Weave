// Probe gate — TASK-2: SetConsoleMode → real tcsetattr() implementation.
//
// Only runs on Linux x86_64 where the win64 calling convention is supported.
//
// Test plan:
//   1. Call set_console_mode with STDIN_HANDLE and flags 0x0007
//      (ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT).
//      Assert: returns TRUE (1) — whether stdin is a TTY or a pipe in the test
//      runner, the call must succeed.
//   2. Call set_console_mode with STDOUT_HANDLE and ENABLE_PROCESSED_OUTPUT
//      (0x0001). Assert: returns TRUE (1) — output flags are a no-op, still success.
//   3. Call set_console_mode with usize::MAX (INVALID_HANDLE_VALUE) and flags 0.
//      Assert: returns TRUE (1) — unknown/invalid handles are a silent no-op.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use weave_core::handles;
use weave_kernel32::set_console_mode;

#[test]
fn set_console_mode_stdin_cooked_returns_true() {
    // ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT
    let ret = unsafe { set_console_mode(handles::STDIN_HANDLE, 0x0007) };
    assert_eq!(
        ret, 1,
        "SetConsoleMode(STDIN_HANDLE, cooked) must return TRUE (1), got {ret}"
    );
}

#[test]
fn set_console_mode_stdout_processed_output_returns_true() {
    // ENABLE_PROCESSED_OUTPUT — no termios equivalent, must still succeed
    let ret = unsafe { set_console_mode(handles::STDOUT_HANDLE, 0x0001) };
    assert_eq!(
        ret, 1,
        "SetConsoleMode(STDOUT_HANDLE, ENABLE_PROCESSED_OUTPUT) must return TRUE (1), got {ret}"
    );
}

#[test]
fn set_console_mode_invalid_handle_returns_true() {
    // INVALID_HANDLE_VALUE — unknown handle → silent no-op, not an error
    let ret = unsafe { set_console_mode(usize::MAX, 0) };
    assert_eq!(
        ret, 1,
        "SetConsoleMode(INVALID_HANDLE_VALUE, 0) must return TRUE (1), got {ret}"
    );
}
