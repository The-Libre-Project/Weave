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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_correct_dll_name_routes_to_registry() {
        assert!(resolve("advapi32.dll", "RegCloseKey").is_some());
        assert!(resolve("ADVAPI32.DLL", "RegCloseKey").is_some());
        assert!(resolve("Advapi32.dll", "RegCloseKey").is_some());
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("kernel32.dll", "RegCloseKey").is_none());
        assert!(resolve("user32.dll", "RegCloseKey").is_none());
    }

    #[test]
    fn resolve_unknown_func_returns_none() {
        assert!(resolve("advapi32.dll", "__weave_nonexistent__").is_none());
    }
}
