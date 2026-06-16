// ── powrprof.dll stubs for Weave ──────────────────────────────────────────────
//
// Power management function stubs. All Phase A — return NOT_SUPPORTED or
// equivalent sentinels so callers can continue without crashing.

const ERROR_SUCCESS: u32 = 0;
const ERROR_NOT_SUPPORTED: u32 = 0x32;

// ── Power Notification ───────────────────────────────────────────────────────

/// PowerRegisterSuspendResumeNotification — register for power event callbacks.
///
/// Phase A stub — always succeeds (registers nothing), indicating power
/// notifications are not supported.
///
/// # Safety
/// Caller must ensure `flags` is valid and `registration_handle` is non-null.
// Wine ref: dlls/powrprof/powrprof.c — stub returns ERROR_SUCCESS.
pub unsafe extern "win64" fn power_register_suspend_resume_notification(
    _flags: u32,
    _recipient: *mut u8,
    registration_handle: *mut usize,
) -> u32 {
    if !registration_handle.is_null() {
        // SAFETY: caller guarantees non-null writable handle.
        unsafe { *registration_handle = 0 };
    }
    ERROR_SUCCESS
}

/// PowerUnregisterSuspendResumeNotification — unregister power callback.
///
/// Phase A stub — always succeeds.
///
/// # Safety
/// No safety requirements for this no-op stub.
// Wine ref: dlls/powrprof/powrprof.c — stub returns ERROR_SUCCESS.
pub unsafe extern "win64" fn power_unregister_suspend_resume_notification(
    _registration_handle: usize,
) -> u32 {
    ERROR_SUCCESS
}

// ── Power Information ────────────────────────────────────────────────────────

/// PowerReadACValue — read AC power setting. Phase A stub.
///
/// # Safety
/// No safety requirements for this no-op stub.
pub unsafe extern "win64" fn power_read_ac_value(
    _root_power_key: usize,
    _sub_group_of_power_settings: *const u8,
    _power_setting: *const u8,
    _type: *mut u32,
    _buffer: *mut u8,
    _buffer_size: *mut u32,
) -> u32 {
    ERROR_NOT_SUPPORTED
}

/// PowerReadDCValue — read DC power setting. Phase A stub.
///
/// # Safety
/// No safety requirements for this no-op stub.
pub unsafe extern "win64" fn power_read_dc_value(
    _root_power_key: usize,
    _sub_group_of_power_settings: *const u8,
    _power_setting: *const u8,
    _type: *mut u32,
    _buffer: *mut u8,
    _buffer_size: *mut u32,
) -> u32 {
    ERROR_NOT_SUPPORTED
}

// ── Resolver ─────────────────────────────────────────────────────────────────

pub fn resolve(_dll: &str, func: &str) -> Option<usize> {
    match func {
        "PowerRegisterSuspendResumeNotification" => Some(
            power_register_suspend_resume_notification
                as unsafe extern "win64" fn(_, _, _) -> _
                as *const ()
                as usize,
        ),
        "PowerUnregisterSuspendResumeNotification" => Some(
            power_unregister_suspend_resume_notification
                as unsafe extern "win64" fn(_) -> _
                as *const ()
                as usize,
        ),
        "PowerReadACValue" => Some(
            power_read_ac_value
                as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const ()
                as usize,
        ),
        "PowerReadDCValue" => Some(
            power_read_dc_value
                as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const ()
                as usize,
        ),
        _ => None,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn resolve_powrprof_dll() {
        assert!(resolve("powrprof.dll", "PowerRegisterSuspendResumeNotification").is_some());
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("kernel32.dll", "PowerRegisterSuspendResumeNotification").is_none());
    }

    #[test]
    fn resolve_unknown_function_returns_none() {
        assert!(resolve("powrprof.dll", "FakeFunction").is_none());
    }

    #[test]
    fn register_null_handle() {
        let r = unsafe { power_register_suspend_resume_notification(0, std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(r, ERROR_SUCCESS);
    }

    #[test]
    fn register_writes_zero_handle() {
        let mut handle: usize = 0xDEAD;
        let r = unsafe { power_register_suspend_resume_notification(0, std::ptr::null_mut(), &mut handle) };
        assert_eq!(r, ERROR_SUCCESS);
        assert_eq!(handle, 0);
    }

    #[test]
    fn unregister_noop() {
        let r = unsafe { power_unregister_suspend_resume_notification(0) };
        assert_eq!(r, ERROR_SUCCESS);
    }

    #[test]
    fn read_ac_value_not_supported() {
        let r = unsafe { power_read_ac_value(0, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(r, ERROR_NOT_SUPPORTED);
    }

    #[test]
    fn read_dc_value_not_supported() {
        let r = unsafe { power_read_dc_value(0, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(r, ERROR_NOT_SUPPORTED);
    }
}
