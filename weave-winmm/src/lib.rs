//! winmm.dll stubs for Weave.
//!
//! Covers the Windows Multimedia API: high-resolution timers (`timeGetTime`,
//! `timeBeginPeriod`, `timeEndPeriod`), wave audio device queries, and
//! joystick stubs. All functions use `extern "win64"`.

#![allow(non_snake_case)]

use std::time::{SystemTime, UNIX_EPOCH};

// ── waveOut structs ──────────────────────────────────────────────────────────
// Wine ref: include/mmsystem.h — WAVEFORMATEX struct layout (line 500)
#[repr(C)]
pub struct WAVEFORMATEX {
    pub wFormatTag: u16,
    pub nChannels: u16,
    pub nSamplesPerSec: u32,
    pub nAvgBytesPerSec: u32,
    pub nBlockAlign: u16,
    pub wBitsPerSample: u16,
    pub cbSize: u16,
}

// Wine ref: include/mmsystem.h — WAVEHDR struct layout (line 330)
#[repr(C)]
pub struct WAVEHDR {
    pub lpData: *mut u8,
    pub dwBufferLength: u32,
    pub dwBytesRecorded: u32,
    pub dwUser: usize,
    pub dwFlags: u32,
    pub dwLoops: u32,
    pub lpNext: *mut WAVEHDR,
    pub reserved: usize,
}

// WAVEHDR dwFlags bits — Wine ref: include/mmsystem.h
const WHDR_DONE: u32 = 0x00000001;
const WHDR_PREPARED: u32 = 0x00000002;
const WHDR_INQUEUE: u32 = 0x00000010;

// waveOut callback flags — Wine ref: include/mmsystem.h / dlls/winmm/waveform.c
const CALLBACK_FUNCTION: u32 = 0x00030000;
const CALLBACK_TYPEMASK: u32 = 0x00070000;

// WOM messages — Wine ref: include/mmsystem.h
const WOM_OPEN: u32 = 0x3BB;

// Wine ref: include/mmsystem.h — WAVEOUTCAPSA struct layout (line 347)
// MAXPNAMELEN = 32
#[repr(C)]
pub struct WAVEOUTCAPSA {
    pub wMid: u16,
    pub wPid: u16,
    pub vDriverVersion: u32,
    pub szPname: [u8; 32],
    pub dwFormats: u32,
    pub wChannels: u16,
    pub wReserved1: u16,
    pub dwSupport: u32,
}

// Wine ref: include/mmsystem.h — WAVEOUTCAPSW struct layout (line 358)
#[repr(C)]
pub struct WAVEOUTCAPSW {
    pub wMid: u16,
    pub wPid: u16,
    pub vDriverVersion: u32,
    pub szPname: [u16; 32],
    pub dwFormats: u32,
    pub wChannels: u16,
    pub wReserved1: u16,
    pub dwSupport: u32,
}

// Pseudo-handle value written to *phwo on success.
const WAVE_OUT_HANDLE: usize = 0x0001_0001;

/// Invoke a CALLBACK_FUNCTION-style waveOut callback if flags indicate it.
/// Wine ref: dlls/winmm/waveform.c WINMM_NotifyClient — callback invoked with
/// (hwo, msg, dwInstance, param1, param2); CALLBACK_FUNCTION = 0x30000.
///
/// # Safety
/// `callback` must be a valid fn pointer when `flags & CALLBACK_TYPEMASK == CALLBACK_FUNCTION`.
unsafe fn maybe_notify(hwo: usize, msg: u32, callback: usize, instance: usize, flags: u32) {
    if flags & CALLBACK_TYPEMASK == CALLBACK_FUNCTION && callback != 0 {
        let f: extern "win64" fn(usize, u32, usize, usize, usize) = std::mem::transmute(callback);
        f(hwo, msg, instance, 0, 0);
    }
}

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

// ── waveOut core stubs ───────────────────────────────────────────────────────

/// waveOutOpen: open a wave output device.
/// Wine ref: dlls/winmm/waveform.c WOD_Open / WINMM_OpenDevice —
///   writes handle to *phwo, invokes callback with WOM_OPEN on success.
///
/// # Safety
/// `phwo` must be null or a valid pointer to a usize. `pwfx` is accepted but
/// not read. `callback` is invoked only when flags indicate CALLBACK_FUNCTION.
pub unsafe extern "win64" fn wave_out_open(
    phwo: *mut usize,
    _dev_id: u32,
    _pwfx: *const WAVEFORMATEX,
    callback: usize,
    instance: usize,
    flags: u32,
) -> u32 {
    if !phwo.is_null() {
        unsafe {
            *phwo = WAVE_OUT_HANDLE;
        }
    }
    unsafe {
        maybe_notify(WAVE_OUT_HANDLE, WOM_OPEN, callback, instance, flags);
    }
    0 // MMSYSERR_NOERROR
}

/// waveOutClose: close a wave output device.
/// Wine ref: dlls/winmm/waveform.c WOD_Close — invokes WOM_CLOSE callback.
/// Callback state is not preserved in this stub; close is a no-op.
pub extern "win64" fn wave_out_close(_hwo: usize) -> u32 {
    0 // MMSYSERR_NOERROR
}

/// waveOutPrepareHeader: prepare a wave header for playback.
/// Wine ref: dlls/winmm/waveform.c — sets WHDR_PREPARED in dwFlags.
///
/// # Safety
/// `pwh` must be a valid pointer to a WAVEHDR if non-null.
pub unsafe extern "win64" fn wave_out_prepare_header(
    _hwo: usize,
    pwh: *mut WAVEHDR,
    _cbwh: u32,
) -> u32 {
    if !pwh.is_null() {
        unsafe {
            (*pwh).dwFlags |= WHDR_PREPARED;
        }
    }
    0 // MMSYSERR_NOERROR
}

/// waveOutUnprepareHeader: unprepare a wave header.
/// Wine ref: dlls/winmm/waveform.c — clears WHDR_PREPARED from dwFlags.
///
/// # Safety
/// `pwh` must be a valid pointer to a WAVEHDR if non-null.
pub unsafe extern "win64" fn wave_out_unprepare_header(
    _hwo: usize,
    pwh: *mut WAVEHDR,
    _cbwh: u32,
) -> u32 {
    if !pwh.is_null() {
        unsafe {
            (*pwh).dwFlags &= !WHDR_PREPARED;
        }
    }
    0 // MMSYSERR_NOERROR
}

/// waveOutWrite: submit a buffer for playback (silent stub).
/// Wine ref: dlls/winmm/waveform.c — marks WHDR_INQUEUE while queued,
///   marks WHDR_DONE when buffer completes. Stub marks done immediately
///   (no audio produced; app does not deadlock waiting for completion).
///
/// # Safety
/// `pwh` must be a valid pointer to a WAVEHDR if non-null.
pub unsafe extern "win64" fn wave_out_write(_hwo: usize, pwh: *mut WAVEHDR, _cbwh: u32) -> u32 {
    if !pwh.is_null() {
        unsafe {
            (*pwh).dwFlags |= WHDR_INQUEUE;
            (*pwh).dwFlags |= WHDR_DONE;
            (*pwh).dwFlags &= !WHDR_INQUEUE;
        }
    }
    0 // MMSYSERR_NOERROR
}

/// waveOutReset: reset a wave output device.
pub extern "win64" fn wave_out_reset(_hwo: usize) -> u32 {
    0 // MMSYSERR_NOERROR
}

/// waveOutPause: pause a wave output device.
pub extern "win64" fn wave_out_pause(_hwo: usize) -> u32 {
    0 // MMSYSERR_NOERROR
}

/// waveOutRestart: restart a paused wave output device.
pub extern "win64" fn wave_out_restart(_hwo: usize) -> u32 {
    0 // MMSYSERR_NOERROR
}

/// waveOutGetDevCapsA: get capabilities of a wave output device (ANSI).
/// Wine ref: include/mmsystem.h WAVEOUTCAPSA — fills name, channels,
///   dwFormats with standard PCM format flags, dwSupport = 0.
///
/// # Safety
/// `pwoc` must be null or a valid pointer to at least `cbwoc` bytes.
pub unsafe extern "win64" fn wave_out_get_dev_caps_a(
    _dev_id: u32,
    pwoc: *mut WAVEOUTCAPSA,
    cbwoc: u32,
) -> u32 {
    if !pwoc.is_null() && cbwoc as usize >= std::mem::size_of::<WAVEOUTCAPSA>() {
        unsafe {
            let caps = &mut *pwoc;
            caps.wMid = 0;
            caps.wPid = 0;
            caps.vDriverVersion = 0x0100;
            // "Weave Audio" in ASCII, null-padded
            let name = b"Weave Audio\0";
            caps.szPname[..name.len()].copy_from_slice(name);
            // PCM formats: 44100/16/stereo + common variants
            caps.dwFormats = 0x000FFFFF;
            caps.wChannels = 2;
            caps.wReserved1 = 0;
            caps.dwSupport = 0;
        }
    }
    0 // MMSYSERR_NOERROR
}

/// waveOutGetDevCapsW: get capabilities of a wave output device (Wide).
/// Wine ref: include/mmsystem.h WAVEOUTCAPSW — same as A but wide name.
///
/// # Safety
/// `pwoc` must be null or a valid pointer to at least `cbwoc` bytes.
pub unsafe extern "win64" fn wave_out_get_dev_caps_w(
    _dev_id: u32,
    pwoc: *mut WAVEOUTCAPSW,
    cbwoc: u32,
) -> u32 {
    if !pwoc.is_null() && cbwoc as usize >= std::mem::size_of::<WAVEOUTCAPSW>() {
        unsafe {
            let caps = &mut *pwoc;
            caps.wMid = 0;
            caps.wPid = 0;
            caps.vDriverVersion = 0x0100;
            // "Weave Audio" as UTF-16LE, null-padded
            let name: &[u16] = &[
                b'W' as u16,
                b'e' as u16,
                b'a' as u16,
                b'v' as u16,
                b'e' as u16,
                b' ' as u16,
                b'A' as u16,
                b'u' as u16,
                b'd' as u16,
                b'i' as u16,
                b'o' as u16,
                0u16,
            ];
            caps.szPname[..name.len()].copy_from_slice(name);
            caps.dwFormats = 0x000FFFFF;
            caps.wChannels = 2;
            caps.wReserved1 = 0;
            caps.dwSupport = 0;
        }
    }
    0 // MMSYSERR_NOERROR
}

/// waveOutGetPosition: get the current playback position.
/// Wine ref: dlls/winmm/waveform.c — returns TIME_BYTES position; stub returns 0.
///
/// # Safety
/// Pointer arguments accepted but not dereferenced beyond null check.
pub unsafe extern "win64" fn wave_out_get_position(
    _hwo: usize,
    _pmmt: *mut u32,
    _cbmmt: u32,
) -> u32 {
    0 // MMSYSERR_NOERROR (position = 0)
}

/// waveOutBreakLoop: break a looping wave output.
pub extern "win64" fn wave_out_break_loop(_hwo: usize) -> u32 {
    0 // MMSYSERR_NOERROR
}

/// waveOutGetID: get the device ID for a wave output handle.
///
/// # Safety
/// `pud_device_id` must be null or a valid pointer to a u32.
pub unsafe extern "win64" fn wave_out_get_id(_hwo: usize, pud_device_id: *mut u32) -> u32 {
    if !pud_device_id.is_null() {
        unsafe {
            *pud_device_id = 0;
        }
    }
    0 // MMSYSERR_NOERROR
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
        "waveOutOpen" => Some(
            wave_out_open
                as unsafe extern "win64" fn(
                    *mut usize,
                    u32,
                    *const WAVEFORMATEX,
                    usize,
                    usize,
                    u32,
                ) -> u32 as *const () as usize,
        ),
        "waveOutClose" => {
            Some(wave_out_close as extern "win64" fn(usize) -> u32 as *const () as usize)
        }
        "waveOutPrepareHeader" => Some(
            wave_out_prepare_header as unsafe extern "win64" fn(usize, *mut WAVEHDR, u32) -> u32
                as *const () as usize,
        ),
        "waveOutUnprepareHeader" => Some(
            wave_out_unprepare_header as unsafe extern "win64" fn(usize, *mut WAVEHDR, u32) -> u32
                as *const () as usize,
        ),
        "waveOutWrite" => Some(
            wave_out_write as unsafe extern "win64" fn(usize, *mut WAVEHDR, u32) -> u32 as *const ()
                as usize,
        ),
        "waveOutReset" => {
            Some(wave_out_reset as extern "win64" fn(usize) -> u32 as *const () as usize)
        }
        "waveOutPause" => {
            Some(wave_out_pause as extern "win64" fn(usize) -> u32 as *const () as usize)
        }
        "waveOutRestart" => {
            Some(wave_out_restart as extern "win64" fn(usize) -> u32 as *const () as usize)
        }
        "waveOutGetDevCapsA" => Some(
            wave_out_get_dev_caps_a as unsafe extern "win64" fn(u32, *mut WAVEOUTCAPSA, u32) -> u32
                as *const () as usize,
        ),
        "waveOutGetDevCapsW" => Some(
            wave_out_get_dev_caps_w as unsafe extern "win64" fn(u32, *mut WAVEOUTCAPSW, u32) -> u32
                as *const () as usize,
        ),
        "waveOutGetPosition" => Some(
            wave_out_get_position as unsafe extern "win64" fn(usize, *mut u32, u32) -> u32
                as *const () as usize,
        ),
        "waveOutBreakLoop" => {
            Some(wave_out_break_loop as extern "win64" fn(usize) -> u32 as *const () as usize)
        }
        "waveOutGetID" => Some(
            wave_out_get_id as unsafe extern "win64" fn(usize, *mut u32) -> u32 as *const ()
                as usize,
        ),
        _ => None,
    }
}
