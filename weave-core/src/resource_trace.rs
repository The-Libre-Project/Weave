//! Runtime-gated tracer for Win32 resource API paths.
//!
//! When `WEAVE_RESOURCE_TRACE=1` is set, resource API call sites emit one
//! `restrace: ...` line per call to stderr. Default off; zero overhead when unset.
//!
//! Precedent: `weave-core::ws2_trace`.

use std::sync::OnceLock;

static RESOURCE_TRACE_ENABLED: OnceLock<bool> = OnceLock::new();

/// Returns true iff `WEAVE_RESOURCE_TRACE=1` was set when this process started.
/// The result is cached after the first call.
pub fn enabled() -> bool {
    *RESOURCE_TRACE_ENABLED.get_or_init(|| {
        std::env::var("WEAVE_RESOURCE_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Maps standard RT_* constants to their name strings.
pub fn resource_type_name(rt: u32) -> &'static str {
    match rt {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        _ => "RT_UNKNOWN",
    }
}

/// Emit a restrace line to stderr if `WEAVE_RESOURCE_TRACE=1`.
#[macro_export]
macro_rules! restrace {
    ($($arg:tt)*) => {
        if $crate::resource_trace::enabled() {
            eprintln!("restrace: {}", format_args!($($arg)*));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_matches_env() {
        let env_is_one = std::env::var("WEAVE_RESOURCE_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false);
        assert_eq!(enabled(), env_is_one);
    }

    #[test]
    fn resource_type_name_rt_string() {
        assert_eq!(resource_type_name(6), "RT_STRING");
    }

    #[test]
    fn resource_type_name_unknown() {
        assert_eq!(resource_type_name(99), "RT_UNKNOWN");
    }
}
