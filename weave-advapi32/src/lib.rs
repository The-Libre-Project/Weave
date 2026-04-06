//! advapi32.dll stubs for Weave.
//!
//! Phase 2 scope: registry read/write operations. Security and service
//! management APIs are stubbed as no-ops for now.
//!
//! Also hosts wintrust.dll, crypt32.dll, and sensapi.dll stubs — they share
//! the security/PKI domain and have no separate crate of their own.

mod registry;
mod wintrust;

/// Resolve an advapi32.dll import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    match dll.to_ascii_lowercase().as_str() {
        "advapi32.dll" => registry::resolve(func),
        "wintrust.dll" => wintrust::resolve_wintrust(func),
        "crypt32.dll" => wintrust::resolve_crypt32(func),
        "sensapi.dll" => wintrust::resolve_sensapi(func),
        _ => None,
    }
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
