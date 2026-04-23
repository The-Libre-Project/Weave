// Probe gate — TASK-4: SetUnhandledExceptionFilter + UnhandledExceptionFilter store/call handler.
//
// Only runs on Linux x86_64 where the win64 calling convention is supported.
//
// Test plan:
//   1. Install a no-op filter via SetUnhandledExceptionFilter.
//      Assert: returns 0 (no previous handler).
//   2. Call UnhandledExceptionFilter with null ptr.
//      Assert: filter was called and returned 42.
//   3. Clear the handler via SetUnhandledExceptionFilter(0).
//      Assert: returns the previous filter address (test_filter as usize).
//   4. Call UnhandledExceptionFilter again.
//      Assert: returns 0 (EXCEPTION_CONTINUE_SEARCH — no handler installed).

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use weave_kernel32::{set_unhandled_exception_filter, unhandled_exception_filter};

unsafe extern "win64" fn test_filter(_p: *mut u8) -> i32 {
    42
}

#[test]
fn install_filter_returns_previous_handler() {
    // Tier A assertion 1: no previous handler → returns 0.
    let prev = set_unhandled_exception_filter(test_filter as usize);
    assert_eq!(
        prev, 0,
        "SetUnhandledExceptionFilter must return 0 when no previous handler was installed"
    );

    // Tier A assertion 2: UnhandledExceptionFilter calls the installed filter and returns 42.
    let result = unsafe { unhandled_exception_filter(std::ptr::null_mut()) };
    assert_eq!(
        result, 42,
        "UnhandledExceptionFilter must call the installed filter and return its result (42)"
    );

    // Tier A assertion 3: clearing the handler returns the address of test_filter.
    let cleared = set_unhandled_exception_filter(0);
    assert_eq!(
        cleared, test_filter as usize,
        "SetUnhandledExceptionFilter(0) must return the previously installed filter address"
    );

    // Tier A assertion 4: after clearing, UnhandledExceptionFilter returns EXCEPTION_CONTINUE_SEARCH (0).
    let after_clear = unsafe { unhandled_exception_filter(std::ptr::null_mut()) };
    assert_eq!(
        after_clear, 0,
        "UnhandledExceptionFilter must return EXCEPTION_CONTINUE_SEARCH (0) when no handler is installed"
    );
}
