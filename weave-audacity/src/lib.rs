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

// ── wxWidgets data stubs ─────────────────────────────────────────────────
//
// When wxWidgets DLLs are not present as PE files, data exports like
// wxDefaultPosition are IAT-resolved through the stub chain.  These static
// objects provide valid (zeroed) addresses so that reading the data does not
// crash.  The zero values are safe defaults for phase-A probing.

/// wxDefaultPosition (wxPoint) — static zero-initialised 8 bytes.
#[no_mangle]
static WX_DEFAULT_POSITION: [u8; 16] = [0u8; 16];

/// wxDefaultSize (wxSize) — static zero-initialised 8 bytes.
#[no_mangle]
static WX_DEFAULT_SIZE: [u8; 16] = [0u8; 16];

/// wxDefaultValidator (wxValidator) — static zero-initialised 128 bytes.
#[no_mangle]
static WX_DEFAULT_VALIDATOR: [u8; 128] = [0u8; 128];

/// wxDefaultDateTime — static zero-initialised 32 bytes.
#[no_mangle]
static WX_DEFAULT_DATE_TIME: [u8; 32] = [0u8; 32];

/// wxDefaultDateTimeFormat — static null string pointer.
#[no_mangle]
static WX_DEFAULT_DATE_TIME_FORMAT: [u8; 16] = [0u8; 16];

/// wxDefaultTimeSpanFormat — static null string pointer.
#[no_mangle]
static WX_DEFAULT_TIME_SPAN_FORMAT: [u8; 16] = [0u8; 16];

/// wxDefaultPosition wxPoint(0, 0) and similar static constants in wxbase.
#[no_mangle]
static WXBASE_DEFAULT_POSITION: [u8; 16] = [0u8; 16];

/// typeDefault@wxTextBuffer — wxTextFileType enum (int, default 0 = text).
#[no_mangle]
static WX_TYPE_DEFAULT: [u8; 8] = [0u8; 8];

/// VCRUNTIME140 stubs (no dedicated crate exists — handled here for now).
/// __current_exception → return null (no current exception).
pub unsafe extern "win64" fn vcruntime_current_exception() -> u64 {
    0
}
/// __current_exception_context → return null (no current exception context).
pub unsafe extern "win64" fn vcruntime_current_exception_context() -> u64 {
    0
}
/// __RTtypeid → return a dummy non-null type_info pointer.
/// Without this, RTTI queries (used heavily by wxWidgets) crash.
pub unsafe extern "win64" fn vcruntime_rttypeid() -> usize {
    &VCRT_DUMMY_TYPEINFO as *const u8 as usize
}
/// __RTDynamicCast → return null (cast failed). Safe default.
pub unsafe extern "win64" fn vcruntime_rtdynamiccast() -> usize {
    0
}
/// __std_type_info_compare → return 0 (equal). Safe default.
pub unsafe extern "win64" fn vcruntime_type_info_compare() -> i32 {
    0
}
/// __std_type_info_destroy_list → no-op.
pub unsafe extern "win64" fn vcruntime_type_info_destroy_list() {}

/// VCRUNTIME140_1 stubs
/// __CxxFrameHandler4 → return ExceptionContinueSearch (1).
/// Without this, exception handling crashes and triggers SEH runaway / stack overflow.
pub unsafe extern "win64" fn vcruntime_cxx_frame_handler4(
    _rec: *const u8, _frame: *const u8, _ctx: *const u8, _dispatch: *const u8
) -> i32 {
    1  // ExceptionContinueSearch
}

/// Dummy type_info object for __RTtypeid.
#[no_mangle]
static VCRT_DUMMY_TYPEINFO: [u8; 32] = [0u8; 32];

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
        "portaudio_x64.dll" => {
            // Intercept PortAudio API to skip audio hardware probing.
            // PortAudio in the Docker CI has no real audio hardware, and
            // probing may crash (dlopen → PulseAudio → crash in system
            // library). Return paNoError but stub all device enumeration
            // and stream functions to return 0 / empty.
            // NOTE: lib-audio-devices.dll imports portaudio by ORDINAL,
            // not by name. Both the ordinal (#N) and name (Pa_*) forms
            // are registered here since the resolve chain handles both.
            match func {
                "Pa_Initialize" | "#4" => Some(portaudio_pa_initialize as *const () as usize),
                "Pa_Terminate" | "#5" => Some(portaudio_pa_terminate as *const () as usize),
                "Pa_GetDeviceCount" | "#12" => {
                    Some(portaudio_pa_get_device_count as *const () as usize)
                }
                "Pa_GetDefaultInputDevice" | "#13" => {
                    Some(portaudio_pa_get_default_input_device as *const () as usize)
                }
                "Pa_GetDefaultOutputDevice" | "#14" => {
                    Some(portaudio_pa_get_default_output_device as *const () as usize)
                }
                "Pa_GetDeviceInfo" | "#15" => {
                    Some(portaudio_pa_get_device_info as *const () as usize)
                }
                "Pa_OpenDefaultStream" | "#18" => {
                    Some(portaudio_pa_open_default_stream as *const () as usize)
                }
                "Pa_StartStream" | "#21" => Some(portaudio_pa_start_stream as *const () as usize),
                "Pa_StopStream" | "#22" => Some(portaudio_pa_stop_stream as *const () as usize),
                "Pa_CloseStream" | "#19" => Some(portaudio_pa_close_stream as *const () as usize),
                "Pa_IsStreamStopped" | "#24" => {
                    Some(portaudio_pa_is_stream_stopped as *const () as usize)
                }
                "Pa_IsStreamActive" | "#25" => {
                    Some(portaudio_pa_is_stream_active as *const () as usize)
                }
                "Pa_GetSampleSize" | "#33" => {
                    Some(portaudio_pa_get_sample_size as *const () as usize)
                }
                "Pa_Sleep" | "#34" => Some(portaudio_pa_sleep as *const () as usize),
                "Pa_GetVersion" | "#1" => Some(portaudio_pa_get_version as *const () as usize),
                "Pa_GetVersionText" | "#2" => {
                    Some(portaudio_pa_get_version_text as *const () as usize)
                }
                "Pa_GetHostApiCount" | "#6" => {
                    Some(portaudio_pa_get_host_api_count as *const () as usize)
                }
                "Pa_GetHostApiInfo" | "#8" => {
                    Some(portaudio_pa_get_host_api_info as *const () as usize)
                }
                "Pa_GetErrorText" | "#3" => Some(portaudio_pa_stub as *const () as usize),
                "Pa_HostApiDeviceIndexToDeviceIndex" | "#10" => {
                    Some(portaudio_pa_stub_i32 as *const () as usize)
                }
                "Pa_IsFormatSupported" | "#16" => Some(portaudio_pa_stub_i32 as *const () as usize),
                "Pa_OpenStream" | "#17" => Some(portaudio_pa_stub_i32 as *const () as usize),
                "PaWasapi_GetIMMDevice" | "#70" => {
                    Some(portaudio_pa_stub_ptr as *const () as usize)
                }
                "PaWinMME_GetStreamInputHandleCount" | "#72" => {
                    Some(portaudio_pa_stub_u32 as *const () as usize)
                }
                "PaWinMME_GetStreamOutputHandleCount" | "#74" => {
                    Some(portaudio_pa_stub_u32 as *const () as usize)
                }
                "PaWinDS_GetDeviceGUID" | "#75" => {
                    Some(portaudio_pa_stub_ptr as *const () as usize)
                }
                _ => None,
            }
        }
        // ── VCRUNTIME140.dll ───────────────────────────────────────────────
        "vcruntime140.dll" => match func {
            "__current_exception" => {
                Some(vcruntime_current_exception as unsafe extern "win64" fn() -> u64
                    as *const () as usize)
            }
            "__current_exception_context" => {
                Some(vcruntime_current_exception_context as unsafe extern "win64" fn() -> u64
                    as *const () as usize)
            }
            "__RTtypeid" => {
                Some(vcruntime_rttypeid as unsafe extern "win64" fn() -> usize
                    as *const () as usize)
            }
            "__RTDynamicCast" => {
                Some(vcruntime_rtdynamiccast as unsafe extern "win64" fn() -> usize
                    as *const () as usize)
            }
            "__std_type_info_compare" => {
                Some(vcruntime_type_info_compare as unsafe extern "win64" fn() -> i32
                    as *const () as usize)
            }
            "__std_type_info_destroy_list" => {
                Some(vcruntime_type_info_destroy_list as unsafe extern "win64" fn()
                    as *const () as usize)
            }
            _ => None,
        },
        // ── VCRUNTIME140_1.dll ─────────────────────────────────────────────
        "vcruntime140_1.dll" => match func {
            "__CxxFrameHandler4" => {
                Some(vcruntime_cxx_frame_handler4
                    as unsafe extern "win64" fn(*const u8, *const u8, *const u8, *const u8) -> i32
                    as *const () as usize)
            }
            _ => None,
        },
        // ── wxWidgets base DLL (wxbase313u_vc_x64_custom.dll) ──────────────
        "wxbase313u_vc_x64_custom.dll" => match func {
            "?wxDefaultDateTime@@3VwxDateTime@@B" => {
                Some(&WX_DEFAULT_DATE_TIME as *const u8 as usize)
            }
            "?wxDefaultDateTimeFormat@@3QBDB" => {
                Some(&WX_DEFAULT_DATE_TIME_FORMAT as *const u8 as usize)
            }
            "?wxDefaultTimeSpanFormat@@3QBDB" => {
                Some(&WX_DEFAULT_TIME_SPAN_FORMAT as *const u8 as usize)
            }
            "?typeDefault@wxTextBuffer@@2W4wxTextFileType@@B" => {
                Some(&WX_TYPE_DEFAULT as *const u8 as usize)
            }
            _ => None,
        },
        // ── wxWidgets core DLL (wxmsw313u_core_vc_x64_custom.dll) ─────────
        "wxmsw313u_core_vc_x64_custom.dll" => match func {
            "?wxDefaultPosition@@3VwxPoint@@B" => Some(&WX_DEFAULT_POSITION as *const u8 as usize),
            "?wxDefaultSize@@3VwxSize@@B" => Some(&WX_DEFAULT_SIZE as *const u8 as usize),
            "?wxDefaultValidator@@3VwxValidator@@B" => {
                Some(&WX_DEFAULT_VALIDATOR as *const u8 as usize)
            }
            _ => None,
        },
        _ => None,
    }
}

// ── PortAudio stubs ─────────────────────────────────────────────────────
// PortAudio is a cross-platform audio library. In headless Docker CI there
// is no real audio hardware. These stubs prevent PortAudio from probing
// system audio libraries (PulseAudio/ALSA) which crash in the Docker
// environment. Returning paNoError (0) with 0 devices avoids the crash.

// paNotInitialized = -1 — tell callers PortAudio was not initialized
// (no audio hardware available in headless Docker CI).
const PA_NOT_INITIALIZED: i32 = -1;

extern "win64" fn portaudio_pa_initialize() -> i32 {
    PA_NOT_INITIALIZED
}

extern "win64" fn portaudio_pa_terminate() -> i32 {
    0
}

extern "win64" fn portaudio_pa_get_device_count() -> i32 {
    0
}

extern "win64" fn portaudio_pa_get_default_input_device() -> i32 {
    PA_NOT_INITIALIZED
}

extern "win64" fn portaudio_pa_get_default_output_device() -> i32 {
    PA_NOT_INITIALIZED
}

extern "win64" fn portaudio_pa_get_device_info(_dev: i32) -> usize {
    0
}

// Stream functions
extern "win64" fn portaudio_pa_open_default_stream(
    _stream: usize,
    _in_dev: i32,
    _in_config: usize,
    _out_dev: i32,
    _out_config: usize,
    _sample_rate: f64,
    _frames: u32,
    _flags: u32,
    _callback: usize,
    _userdata: usize,
) -> i32 {
    -4
} // paInvalidDevice (no devices)

extern "win64" fn portaudio_pa_start_stream(_stream: usize) -> i32 {
    0
}

extern "win64" fn portaudio_pa_stop_stream(_stream: usize) -> i32 {
    0
}

extern "win64" fn portaudio_pa_close_stream(_stream: usize) -> i32 {
    0
}

extern "win64" fn portaudio_pa_is_stream_stopped(_stream: usize) -> i32 {
    1
}

extern "win64" fn portaudio_pa_is_stream_active(_stream: usize) -> i32 {
    0
}

extern "win64" fn portaudio_pa_get_sample_size(_format: i32) -> i32 {
    2
}

extern "win64" fn portaudio_pa_sleep(_msec: u32) {}

extern "win64" fn portaudio_pa_get_version() -> i32 {
    0x1900
} // 19.0.0

extern "win64" fn portaudio_pa_get_version_text() -> usize {
    0
}

extern "win64" fn portaudio_pa_get_host_api_count() -> i32 {
    0
}

extern "win64" fn portaudio_pa_get_host_api_info(_host_api: i32) -> usize {
    0
}

// Generic stubs for portaudio functions not used during audio-free startup.
extern "win64" fn portaudio_pa_stub() -> i32 {
    0
}
extern "win64" fn portaudio_pa_stub_i32() -> i32 {
    PA_NOT_INITIALIZED
}
extern "win64" fn portaudio_pa_stub_ptr() -> usize {
    0
}
extern "win64" fn portaudio_pa_stub_u32() -> u32 {
    0
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
