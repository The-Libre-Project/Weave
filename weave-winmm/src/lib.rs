//! winmm.dll stubs for Weave.
//!
//! Covers the Windows Multimedia API: high-resolution timers (`timeGetTime`,
//! `timeBeginPeriod`, `timeEndPeriod`), wave audio device queries, and
//! joystick stubs. All functions use `extern "win64"`.

#![allow(non_snake_case)]

use std::time::{SystemTime, UNIX_EPOCH};

// ── Timer functions ──────────────────────────────────────────────────────────

/// timeGetTime: return milliseconds since an arbitrary epoch.
pub extern "win64" fn time_get_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u32)
        .unwrap_or(0)
}

/// timeBeginPeriod: set the minimum timer resolution (no-op).
pub extern "win64" fn time_begin_period(_u_period: u32) -> u32 {
    0 // TIMERR_NOERROR
}

/// timeEndPeriod: clear the minimum timer resolution (no-op).
pub extern "win64" fn time_end_period(_u_period: u32) -> u32 {
    0 // TIMERR_NOERROR
}

/// # Safety
/// `ptc` must be a valid pointer to a TIMECAPS struct if non-null.
pub unsafe extern "win64" fn time_get_dev_caps(ptc: *mut u32, cbtc: u32) -> u32 {
    if !ptc.is_null() && cbtc >= 8 {
        unsafe {
            *ptc = 1; // wPeriodMin
            *ptc.add(1) = 1_000_000; // wPeriodMax
        }
    }
    0 // MMSYSERR_NOERROR
}

// ── Wave audio + MCI stubs ───────────────────────────────────────────────────

/// waveOutGetNumDevs: return the number of wave output devices.
pub extern "win64" fn wave_out_get_num_devs() -> u32 {
    0
}

/// waveInGetNumDevs: return the number of wave input devices.
pub extern "win64" fn wave_in_get_num_devs() -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn wave_out_get_volume(_hwo: usize, _pdw_volume: usize) -> u32 {
    6 // MMSYSERR_NODRIVER
}

/// waveOutSetVolume: set the volume for a wave output device.
pub extern "win64" fn wave_out_set_volume(_hwo: usize, _dw_volume: u32) -> u32 {
    6 // MMSYSERR_NODRIVER
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn play_sound_w(
    _psz_sound: *const u16,
    _hmod: usize,
    _fdw_sound: u32,
) -> i32 {
    0 // FALSE
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn play_sound_a(
    _psz_sound: *const u8,
    _hmod: usize,
    _fdw_sound: u32,
) -> i32 {
    0 // FALSE
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn mci_send_string_w(
    _lpsz_command: *const u16,
    _lpsz_return_string: usize,
    _cch_return: u32,
    _hwnd_callback: usize,
) -> u32 {
    257 // MCIERR_INVALID_DEVICE_NAME
}

/// mciSendCommandW: send a command to an MCI device.
pub extern "win64" fn mci_send_command_w(
    _mci_id: u32,
    _u_msg: u32,
    _dw_param1: usize,
    _dw_param2: usize,
) -> u32 {
    257 // MCIERR_INVALID_DEVICE_NAME
}

/// Returns true for any DLL name this crate handles.
fn is_winmm_dll(dll: &str) -> bool {
    dll.eq_ignore_ascii_case("winmm.dll")
}

/// Resolve a winmm.dll import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !is_winmm_dll(dll) {
        return None;
    }
    match func {
        "timeGetTime" => Some(time_get_time as extern "win64" fn() -> u32 as *const () as usize),
        "timeBeginPeriod" => {
            Some(time_begin_period as extern "win64" fn(u32) -> u32 as *const () as usize)
        }
        "timeEndPeriod" => {
            Some(time_end_period as extern "win64" fn(u32) -> u32 as *const () as usize)
        }
        "timeGetDevCaps" => Some(
            time_get_dev_caps as unsafe extern "win64" fn(*mut u32, u32) -> u32 as *const ()
                as usize,
        ),
        "waveOutGetNumDevs" => {
            Some(wave_out_get_num_devs as extern "win64" fn() -> u32 as *const () as usize)
        }
        "waveInGetNumDevs" => {
            Some(wave_in_get_num_devs as extern "win64" fn() -> u32 as *const () as usize)
        }
        "waveOutGetVolume" => Some(
            wave_out_get_volume as unsafe extern "win64" fn(usize, usize) -> u32 as *const ()
                as usize,
        ),
        "waveOutSetVolume" => {
            Some(wave_out_set_volume as extern "win64" fn(usize, u32) -> u32 as *const () as usize)
        }
        "PlaySoundW" => Some(
            play_sound_w as unsafe extern "win64" fn(*const u16, usize, u32) -> i32 as *const ()
                as usize,
        ),
        "PlaySoundA" => Some(
            play_sound_a as unsafe extern "win64" fn(*const u8, usize, u32) -> i32 as *const ()
                as usize,
        ),
        "mciSendStringW" => Some(
            mci_send_string_w as unsafe extern "win64" fn(*const u16, usize, u32, usize) -> u32
                as *const () as usize,
        ),
        "mciSendCommandW" => Some(
            mci_send_command_w as extern "win64" fn(u32, u32, usize, usize) -> u32 as *const ()
                as usize,
        ),
        _ => None,
    }
}
