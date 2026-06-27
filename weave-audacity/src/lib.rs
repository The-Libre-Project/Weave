//! Audacity internal DLL stubs for Weave.
//!
//! Audacity ships internal DLLs (lib-theme-resources.dll, lib-wx-init.dll)
//! alongside its EXE. These DLLs export C++ mangled symbols. When the fixture
//! doesn't include these DLLs as PE files, the resolver needs explicit entries
//! so imports resolve to a return-0 stub instead of being stubbed to null.
//!
//! Phase A stubs — return 0/false or write an empty object to the return slot.

#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::ffi::c_void;

// ── lib-theme-resources.dll ──────────────────────────────────────────────

/// ThemeResources::Load() — Phase A stub. Returns normally (does nothing).
pub unsafe extern "win64" fn ThemeResources_Load() {}

// ── lib-wx-init.dll — SettingsWX ─────────────────────────────────────────

/// SettingsWX::Read(wxString const& key, wxString* value) const — Phase A stub, returns false.
pub unsafe extern "win64" fn SettingsWX_Read(
    _this: *mut c_void,
    _key: *const c_void,
    _value: *mut c_void,
) -> bool {
    false
}

/// SettingsWX::Clear() — Phase A stub.
pub unsafe extern "win64" fn SettingsWX_Clear() {}

/// SettingsWX::Remove(wxString const& key) — Phase A stub, returns false.
pub unsafe extern "win64" fn SettingsWX_Remove(_this: *mut c_void, _key: *const c_void) -> bool {
    false
}

/// SettingsWX::HasGroup(wxString const& group) const — Phase A stub, returns false.
pub unsafe extern "win64" fn SettingsWX_HasGroup(
    _this: *mut c_void,
    _group: *const c_void,
) -> bool {
    false
}

/// SettingsWX::HasEntry(wxString const& entry) const — Phase A stub, returns false.
pub unsafe extern "win64" fn SettingsWX_HasEntry(
    _this: *mut c_void,
    _entry: *const c_void,
) -> bool {
    false
}

/// SettingsWX::GetChildKeys() const — Phase A stub.
///
/// Returns by value (wxArrayString). Writes an empty value to the return slot
/// (zero-initialized pointer region) to avoid using uninitialized stack memory.
pub unsafe extern "win64" fn SettingsWX_GetChildKeys(
    _this: *mut c_void,
    return_slot: *mut c_void,
) -> *mut c_void {
    if !return_slot.is_null() {
        core::ptr::write_bytes(return_slot, 0, 8);
    }
    return_slot
}

/// SettingsWX::GetChildGroups() const — Phase A stub.
///
/// Same return-by-value pattern as GetChildKeys.
pub unsafe extern "win64" fn SettingsWX_GetChildGroups(
    _this: *mut c_void,
    return_slot: *mut c_void,
) -> *mut c_void {
    if !return_slot.is_null() {
        core::ptr::write_bytes(return_slot, 0, 8);
    }
    return_slot
}

/// SettingsWX::GetGroup() const — Phase A stub.
///
/// Returns wxString by value. Writes zeroes to the return slot for an empty string.
pub unsafe extern "win64" fn SettingsWX_GetGroup(
    _this: *mut c_void,
    return_slot: *mut c_void,
) -> *mut c_void {
    if !return_slot.is_null() {
        core::ptr::write_bytes(return_slot, 0, 8);
    }
    return_slot
}

// ── Resolver ─────────────────────────────────────────────────────────────

/// Resolve an Audacity internal DLL import to a function address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    match dll.to_lowercase().as_str() {
        "lib-theme-resources.dll" => match func {
            "?Load@ThemeResources@@YAXXZ" => {
                Some(ThemeResources_Load as unsafe extern "win64" fn() as *const () as usize)
            }
            _ => None,
        },
        "lib-wx-init.dll" => match func {
            "?Read@SettingsWX@@UEBA_NAEBVwxString@@PEAV2@@Z" => Some(
                SettingsWX_Read as unsafe extern "win64" fn(*mut _, *const _, *mut _) -> bool
                    as *const () as usize,
            ),
            "?Clear@SettingsWX@@UEAAXXZ" => {
                Some(SettingsWX_Clear as unsafe extern "win64" fn() as *const () as usize)
            }
            "?Remove@SettingsWX@@UEAA_NAEBVwxString@@@Z" => Some(
                SettingsWX_Remove as unsafe extern "win64" fn(*mut _, *const _) -> bool as *const ()
                    as usize,
            ),
            "?HasGroup@SettingsWX@@UEBA_NAEBVwxString@@@Z" => Some(
                SettingsWX_HasGroup as unsafe extern "win64" fn(*mut _, *const _) -> bool
                    as *const () as usize,
            ),
            "?HasEntry@SettingsWX@@UEBA_NAEBVwxString@@@Z" => Some(
                SettingsWX_HasEntry as unsafe extern "win64" fn(*mut _, *const _) -> bool
                    as *const () as usize,
            ),
            "?GetChildKeys@SettingsWX@@UEBA?AVwxArrayString@@XZ" => Some(
                SettingsWX_GetChildKeys as unsafe extern "win64" fn(*mut _, *mut _) -> *mut c_void
                    as *const () as usize,
            ),
            "?GetChildGroups@SettingsWX@@UEBA?AVwxArrayString@@XZ" => Some(
                SettingsWX_GetChildGroups as unsafe extern "win64" fn(*mut _, *mut _) -> *mut c_void
                    as *const () as usize,
            ),
            "?GetGroup@SettingsWX@@UEBA?AVwxString@@XZ" => Some(
                SettingsWX_GetGroup as unsafe extern "win64" fn(*mut _, *mut _) -> *mut c_void
                    as *const () as usize,
            ),
            _ => None,
        },
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_lib_theme_resources_load() {
        assert!(resolve("lib-theme-resources.dll", "?Load@ThemeResources@@YAXXZ").is_some());
    }

    #[test]
    fn resolve_lib_wx_init_read() {
        assert!(resolve(
            "lib-wx-init.dll",
            "?Read@SettingsWX@@UEBA_NAEBVwxString@@PEAV2@@Z"
        )
        .is_some());
    }

    #[test]
    fn resolve_lib_wx_init_clear() {
        assert!(resolve("lib-wx-init.dll", "?Clear@SettingsWX@@UEAAXXZ").is_some());
    }

    #[test]
    fn resolve_lib_wx_init_remove() {
        assert!(resolve(
            "lib-wx-init.dll",
            "?Remove@SettingsWX@@UEAA_NAEBVwxString@@@Z"
        )
        .is_some());
    }

    #[test]
    fn resolve_lib_wx_init_has_group() {
        assert!(resolve(
            "lib-wx-init.dll",
            "?HasGroup@SettingsWX@@UEBA_NAEBVwxString@@@Z"
        )
        .is_some());
    }

    #[test]
    fn resolve_lib_wx_init_get_child_keys() {
        assert!(resolve(
            "lib-wx-init.dll",
            "?GetChildKeys@SettingsWX@@UEBA?AVwxArrayString@@XZ"
        )
        .is_some());
    }

    #[test]
    fn resolve_unknown_dll() {
        assert!(resolve("nonexistent.dll", "?Fake@@YAXXZ").is_none());
    }

    #[test]
    fn resolve_unknown_func() {
        assert!(resolve("lib-wx-init.dll", "?Fake@@YAXXZ").is_none());
    }

    #[test]
    fn theme_resources_load_noop() {
        unsafe { ThemeResources_Load() }
    }

    #[test]
    fn settings_wx_read_returns_false() {
        unsafe {
            let key: [u8; 8] = [0; 8];
            let mut val: [u8; 8] = [0; 8];
            assert!(!SettingsWX_Read(
                std::ptr::null_mut(),
                key.as_ptr() as *const c_void,
                val.as_mut_ptr() as *mut c_void,
            ));
        }
    }

    #[test]
    fn settings_wx_get_child_keys_returns_slot() {
        unsafe {
            let mut slot: [u8; 16] = [0xFF; 16];
            let ret =
                SettingsWX_GetChildKeys(std::ptr::null_mut(), slot.as_mut_ptr() as *mut c_void);
            assert_eq!(ret, slot.as_mut_ptr() as *mut c_void);
            assert_eq!(slot[0..8], [0u8; 8]);
        }
    }
}
