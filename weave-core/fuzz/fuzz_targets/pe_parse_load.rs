#![no_main]

//! Fuzz target for weave-core's PE parser and loader.
//!
//! Exercises the full parse-and-load path with arbitrary input bytes.
//! On Linux, also attempts loader::load() after a successful parse.
//!
//! # Why the panic hook override?
//! libfuzzer-sys 0.4 installs a panic hook that calls libc::abort() immediately
//! when any Rust panic fires, before catch_unwind can intercept it. This means
//! goblin's TLS parser panic (tls.rs:228: range end index out of bounds on
//! crafted VA arithmetic) terminates the process as a "deadly signal" crash.
//!
//! In production code (the actual weave binary), weave_core::pe::parse wraps
//! goblin in catch_unwind, so the panic is caught and converted to Err gracefully.
//! For the fuzzer to reflect that reality, we need to let catch_unwind work.
//!
//! We install a one-time no-op panic hook (via std::sync::Once) so that
//! catch_unwind can catch goblin panics. Real memory faults (SIGSEGV, SIGBUS)
//! are still caught by libFuzzer's signal handlers — this only affects Rust
//! panics. Any panic that escapes our catch_unwind (i.e. from OUR code, not
//! goblin's) will be caught by libFuzzer's outer catch_unwind and reported.

use libfuzzer_sys::fuzz_target;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

/// Install a no-op panic hook exactly once so that catch_unwind works inside
/// the fuzz target. libfuzzer-sys's default panic hook calls libc::abort()
/// which bypasses catch_unwind entirely; this replaces it.
///
/// The no-op hook means goblin panics will unwind normally and be caught by
/// our catch_unwind calls. libFuzzer's signal handlers still catch SIGSEGV/
/// SIGBUS/SIGILL so real memory-safety bugs are still reported.
static HOOK_INIT: Once = Once::new();

fn init_hook() {
    HOOK_INIT.call_once(|| {
        panic::set_hook(Box::new(|_| {
            // Intentionally empty: let catch_unwind below handle goblin panics.
            // Real crashes (signals) bypass this and go to libFuzzer's handlers.
        }));
    });
}

fuzz_target!(|data: &[u8]| {
    init_hook();

    // --- pe::parse exerciser ---
    // This exercises the full PE metadata parsing path via goblin. Any input
    // that causes a panic in goblin's parsers will be caught here and reported
    // as an Err, matching the production behaviour of weave_core::pe::parse.
    let parse_result = panic::catch_unwind(AssertUnwindSafe(|| {
        weave_core::pe::parse(data)
    }));

    // If our catch_unwind itself got a panic (Err variant), that means the
    // production-level catch_unwind in pe::parse also failed — a real bug.
    // Surface it as an explicit panic so libFuzzer captures it.
    if parse_result.is_err() {
        panic!("pe::parse panicked despite its catch_unwind wrapper — bug in Weave");
    }

    // --- loader::load exerciser (Linux only, MZ-prefix gate) ---
    // loader::load() mmaps memory, so only attempt it when the input looks like
    // a plausible PE (starts with MZ magic). The loader must return Err, not panic.
    #[cfg(target_os = "linux")]
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        let load_result = panic::catch_unwind(AssertUnwindSafe(|| {
            weave_core::loader::load(data)
        }));
        if load_result.is_err() {
            panic!("loader::load panicked despite its catch_unwind wrapper — bug in Weave");
        }
    }
});
