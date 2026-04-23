// console_ctrl_probe_gate — registration/deregistration contract only.
//
// This gate does NOT fire SIGINT or SIGTERM.  Signal delivery in Docker CI is
// unreliable (Xvfb sandbox, PID 1 signal masking) so liveness of the dispatch
// chain is out of scope here.  The gate verifies only the handler-list
// semantics that SetConsoleCtrlHandler exposes via its return value and
// ERROR_INVALID_PARAMETER last-error.
//
// Behavioral contract (Wine ref: dlls/kernelbase/console.c:1502):
//   - func≠NULL, add=TRUE  → prepend to list, return TRUE
//   - func≠NULL, add=FALSE → remove first match, return TRUE
//   - func≠NULL, add=FALSE (not in list) → ERROR_INVALID_PARAMETER + FALSE
//   - func=NULL,  add=TRUE  → set CTRL_IGNORE, return TRUE
//   - func=NULL,  add=FALSE → clear CTRL_IGNORE, return TRUE

use weave_kernel32::{get_last_error, set_console_ctrl_handler};

#[test]
fn console_ctrl_probe_gate() {
    // Win64 handler fn
    unsafe extern "win64" fn test_handler(_event: u32) -> i32 {
        1
    }

    // Register → TRUE
    let ok = unsafe { set_console_ctrl_handler(test_handler as usize, 1) };
    assert_ne!(ok, 0, "register must return TRUE");

    // Deregister → TRUE
    let ok = unsafe { set_console_ctrl_handler(test_handler as usize, 0) };
    assert_ne!(ok, 0, "deregister must return TRUE");

    // Deregister again (not in list) → FALSE + ERROR_INVALID_PARAMETER
    let ok = unsafe { set_console_ctrl_handler(test_handler as usize, 0) };
    assert_eq!(ok, 0, "deregister of missing handler must return FALSE");
    let err = unsafe { get_last_error() };
    assert_eq!(
        err, 0x57,
        "last error must be ERROR_INVALID_PARAMETER (0x57)"
    );

    // NULL func add=TRUE → TRUE (sets CTRL_IGNORE)
    let ok = unsafe { set_console_ctrl_handler(0, 1) };
    assert_ne!(ok, 0, "NULL handler set-ignore must return TRUE");

    // NULL func add=FALSE → TRUE (clears CTRL_IGNORE)
    let ok = unsafe { set_console_ctrl_handler(0, 0) };
    assert_ne!(ok, 0, "NULL handler clear-ignore must return TRUE");
}
