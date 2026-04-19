//! Runtime-gated tracer for Winsock/MsgWait/CRT I/O paths.
//!
//! Mirrors `iat::tracer_enabled` — when `WEAVE_WS2_TRACE=1` is set in the
//! environment at process start, call-site `eprintln!`s in `weave-ws2`,
//! `weave-user32` (MsgWait), `weave-ucrt` (read/write), and `weave-kernel32`
//! (SetEvent / WaitForSingleObject) become active. Default off.
//!
//! Usage:
//! ```ignore
//! if weave_core::ws2_trace::enabled() {
//!     eprintln!("weave/ws_send: s={s} len={len}");
//! }
//! ```
//!
//! The env-var read is cached in a `OnceLock` so the check is a single atomic
//! load after first use — safe to call from hot paths (e.g. every MsgWait).

use std::sync::OnceLock;

static WS2_TRACE_ENABLED: OnceLock<bool> = OnceLock::new();

/// Returns true iff `WEAVE_WS2_TRACE=1` was set when this process started.
/// The result is cached after the first call.
pub fn enabled() -> bool {
    *WS2_TRACE_ENABLED.get_or_init(|| {
        std::env::var("WEAVE_WS2_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_matches_env() {
        // enabled() uses OnceLock so this test asserts only the cached value
        // matches the environment at the moment OnceLock first initializes.
        let env_is_one = std::env::var("WEAVE_WS2_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false);
        assert_eq!(enabled(), env_is_one);
    }
}
