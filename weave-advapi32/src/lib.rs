//! advapi32.dll stubs for Weave.
//!
//! Phase 2 scope: registry read/write operations. Security and service
//! management APIs are stubbed as no-ops for now.

mod registry;

/// Resolve an advapi32.dll import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("advapi32.dll") {
        return None;
    }
    registry::resolve(func)
}
