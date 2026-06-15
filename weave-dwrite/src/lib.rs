//! dwrite.dll stubs for Weave — DirectWrite font/text factory.
//!
//! Signal Desktop imports DWriteCreateFactory for DirectWrite text rendering.
//! Phase A stub returns CLASS_E_CLASSNOTAVAILABLE; DirectWrite rendering is
//! a Phase B+ target (requires D2D/D3D interop).

#![allow(non_snake_case)]

/// DWriteCreateFactory: create a DirectWrite factory object.
///
/// Phase A stub — returns CLASS_E_CLASSNOTAVAILABLE (no DirectWrite support).
///
/// # Safety
/// `factory` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn dwrite_create_factory(
    _factory_type: u32,
    _iid: *const u8,
    _factory: *mut *mut u8,
) -> i32 {
    eprintln!("weave/dwrite_stub: DWriteCreateFactory (CLASS_E_CLASSNOTAVAILABLE)");
    0x80040111u32 as i32 // CLASS_E_CLASSNOTAVAILABLE
}

/// Resolve a dwrite.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("dwrite.dll") {
        return None;
    }
    Some(match func {
        "DWriteCreateFactory" => dwrite_create_factory as *const () as usize,
        _ => return None,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_dwrite_create_factory() {
        assert!(resolve("dwrite.dll", "DWriteCreateFactory").is_some());
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("kernel32.dll", "DWriteCreateFactory").is_none());
        assert!(resolve("dwrite.dll", "__nonexistent__").is_none());
    }

    #[test]
    fn resolve_case_insensitive() {
        assert!(resolve("DWRITE.DLL", "DWriteCreateFactory").is_some());
    }
}
