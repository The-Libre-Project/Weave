//! Once-per-name stub warning utility.
//!
//! Any Win32 stub that has not yet been given a real implementation should call
//! `warn_once("FunctionName")` at the top of its body. The warning is printed
//! to stderr exactly once per unique function name across the lifetime of the
//! process — not once per call — to avoid log spam while still surfacing
//! coverage gaps during real-app testing.
//!
//! Usage:
//! ```rust,no_run
//! // Only valid for x86_64 Linux targets; shown as reference only.
//! // pub extern "win64" fn some_unimplemented_fn(arg: u32) -> u32 {
//! //     weave_common::stub::warn_once("SomeUnimplementedFn");
//! //     0
//! // }
//! ```

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn seen() -> &'static Mutex<HashSet<&'static str>> {
    static S: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

fn lock_seen<'a>(
    m: &'a Mutex<HashSet<&'static str>>,
) -> Option<MutexGuard<'a, HashSet<&'static str>>> {
    m.lock()
        .map_err(|e| eprintln!("weave: weave-common: stub-seen mutex poisoned: {e}"))
        .ok()
}

/// Emit a one-time stderr warning for an unimplemented stub.
///
/// The warning is printed at most once per `name` value per process lifetime.
/// Subsequent calls with the same `name` are silent.
pub fn warn_once(name: &'static str) {
    if let Some(mut s) = lock_seen(seen()) {
        if s.insert(name) {
            eprintln!("weave: stub not yet implemented: {name}");
        }
    }
}
