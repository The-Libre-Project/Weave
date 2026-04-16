//! winmm.dll stubs for Weave.
//!
//! Covers the Windows Multimedia API: high-resolution timers (`timeGetTime`,
//! `timeBeginPeriod`, `timeEndPeriod`), wave audio device queries, and
//! joystick stubs. All functions use `extern "win64"`.

#![allow(non_snake_case)]

use std::time::{SystemTime, UNIX_EPOCH};

// ── PipeWire ring buffer (pipewire-audio feature) ────────────────────────────

#[cfg(feature = "pipewire-audio")]
use std::sync::{Arc, Mutex};

/// Lock-free-ish ring buffer for PCM audio data.
/// Copied verbatim from weave-mmdevapi — no external deps.
#[cfg(feature = "pipewire-audio")]
struct RingBuf {
    data: Vec<u8>,
    /// Number of bytes currently available to read.
    available: usize,
    /// Write cursor (byte offset into `data`).
    write_pos: usize,
    /// Read cursor (byte offset into `data`).
    read_pos: usize,
    /// Bytes per audio frame (channels x bytes_per_sample).
    frame_size: usize,
}

#[cfg(feature = "pipewire-audio")]
impl RingBuf {
    fn new(capacity_bytes: usize, frame_size: usize) -> Self {
        Self {
            data: vec![0u8; capacity_bytes.max(4096)],
            available: 0,
            write_pos: 0,
            read_pos: 0,
            frame_size,
        }
    }

    /// Read up to `dst.len()` bytes into `dst`.  Returns bytes actually copied.
    fn read_into(&mut self, dst: &mut [u8]) -> usize {
        let max_bytes = dst.len();
        let to_copy = max_bytes.min(self.available);
        if to_copy == 0 {
            return 0;
        }
        let capacity = self.data.len();
        let first_chunk = (capacity - self.read_pos).min(to_copy);
        dst[..first_chunk].copy_from_slice(&self.data[self.read_pos..self.read_pos + first_chunk]);
        if first_chunk < to_copy {
            let second_chunk = to_copy - first_chunk;
            dst[first_chunk..first_chunk + second_chunk]
                .copy_from_slice(&self.data[..second_chunk]);
        }
        self.read_pos = (self.read_pos + to_copy) % capacity;
        self.available -= to_copy;
        to_copy
    }

    /// Write `src` into the ring buffer. Discards overflow if the buffer is full.
    fn write_from(&mut self, src: &[u8]) {
        if src.is_empty() {
            return;
        }
        let capacity = self.data.len();
        let free = capacity.saturating_sub(self.available);
        let to_write = src.len().min(free);
        if to_write == 0 {
            // Buffer full — discard.
            return;
        }
        let src = &src[..to_write];
        let first_chunk = (capacity - self.write_pos).min(to_write);
        self.data[self.write_pos..self.write_pos + first_chunk]
            .copy_from_slice(&src[..first_chunk]);
        if first_chunk < to_write {
            let second_chunk = to_write - first_chunk;
            self.data[..second_chunk]
                .copy_from_slice(&src[first_chunk..first_chunk + second_chunk]);
        }
        self.write_pos = (self.write_pos + to_write) % capacity;
        self.available += to_write;
    }
}

// ── PipeWire stream state ────────────────────────────────────────────────────

/// Live PipeWire objects for one waveOut session.
///
/// PipeWire objects use `Rc` internally and are therefore `!Send`.  We drive
/// them from the ThreadLoop's internal thread; all other access is gated by
/// the ThreadLoop lock.
///
/// `_listener` is box-erased to `dyn Any` so we don't propagate a generic
/// parameter out of this struct.
#[cfg(feature = "pipewire-audio")]
struct PwState {
    thread_loop: pipewire::thread_loop::ThreadLoop,
    /// Raw stream pointer so we can call pw_stream_destroy in Drop before
    /// stopping the thread loop.
    stream: Option<*mut pipewire::sys::pw_stream>,
    /// Type-erased StreamListener — must be dropped before the stream.
    _listener: Option<Box<dyn std::any::Any>>,
}

#[cfg(feature = "pipewire-audio")]
impl Drop for PwState {
    fn drop(&mut self) {
        self._listener = None;
        if let Some(ptr) = self.stream.take() {
            unsafe { pipewire::sys::pw_stream_destroy(ptr) };
        }
        self.thread_loop.stop();
    }
}

// SAFETY: accessed only while holding the ThreadLoop lock or from within the
// ThreadLoop's process callback.  Drop is only called after Stop().
#[cfg(feature = "pipewire-audio")]
unsafe impl Send for PwState {}

// ── waveOut global session ───────────────────────────────────────────────────

#[cfg(feature = "pipewire-audio")]
struct WaveOutSession {
    ring_buf: Arc<Mutex<RingBuf>>,
    pw_state: Option<PwState>,
    // callback info for WOM_DONE
    callback: usize,
    instance: usize,
    flags: u32,
}

#[cfg(feature = "pipewire-audio")]
static WAVE_OUT_SESSION: std::sync::OnceLock<Mutex<Option<WaveOutSession>>> =
    std::sync::OnceLock::new();

#[cfg(feature = "pipewire-audio")]
fn wave_out_session_mutex() -> &'static Mutex<Option<WaveOutSession>> {
    WAVE_OUT_SESSION.get_or_init(|| Mutex::new(None))
}

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
#[cfg(feature = "pipewire-audio")]
const WOM_DONE: u32 = 0x3BD;

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
    #[cfg_attr(not(feature = "pipewire-audio"), allow(unused_variables))] pwfx: *const WAVEFORMATEX,
    callback: usize,
    instance: usize,
    flags: u32,
) -> u32 {
    #[cfg(feature = "pipewire-audio")]
    {
        use pipewire as pw;
        use pw::spa;

        // Read format from caller; fall back to a safe 44100/16/stereo default.
        let (channels, sample_rate, bits_per_sample, frame_size) = if !pwfx.is_null() {
            let f = &*pwfx;
            (
                f.nChannels as u32,
                f.nSamplesPerSec,
                f.wBitsPerSample,
                f.nBlockAlign as usize,
            )
        } else {
            (2u32, 44100u32, 16u16, 4usize)
        };

        // 2-second ring buffer.
        let ring_capacity = (sample_rate as usize) * (frame_size) * 2;
        let ring_buf = Arc::new(Mutex::new(RingBuf::new(ring_capacity, frame_size)));

        pw::init();

        let pw_state: Option<PwState> = (|| -> Option<PwState> {
            let thread_loop =
                unsafe { pw::thread_loop::ThreadLoop::new(Some("weave-waveout"), None) }.ok()?;
            let _lock = thread_loop.lock();
            let context = pw::context::Context::new(&thread_loop).ok()?;
            let core = context.connect(None).ok()?;

            let stream = pw::stream::Stream::new(
                &core,
                "weave-waveout",
                pw::properties::properties! {
                    *pw::keys::MEDIA_TYPE     => "Audio",
                    *pw::keys::MEDIA_ROLE     => "Music",
                    *pw::keys::MEDIA_CATEGORY => "Playback",
                },
            )
            .ok()?;

            let rb_clone = Arc::clone(&ring_buf);
            let listener = stream
                .add_local_listener_with_user_data(())
                .process(move |stream, _| {
                    let mut buf = match stream.dequeue_buffer() {
                        Some(b) => b,
                        None => return,
                    };
                    let datas = buf.datas_mut();
                    let d = &mut datas[0];
                    let total = match d.data() {
                        Some(slice) => slice.len(),
                        None => return,
                    };
                    let raw_ptr = d.as_raw().data as *mut u8;
                    if !raw_ptr.is_null() {
                        let dst = unsafe { std::slice::from_raw_parts_mut(raw_ptr, total) };
                        if let Ok(mut ring) = rb_clone.lock() {
                            let copied = ring.read_into(dst);
                            dst[copied..].fill(0);
                        }
                    }
                    let chunk = d.chunk_mut();
                    *chunk.offset_mut() = 0;
                    *chunk.stride_mut() = frame_size as i32;
                    *chunk.size_mut() = total as u32;
                })
                .register()
                .ok()?;

            let spa_fmt = match bits_per_sample {
                16 => spa::param::audio::AudioFormat::S16LE,
                24 => spa::param::audio::AudioFormat::S24LE,
                32 => spa::param::audio::AudioFormat::S32LE,
                _ => spa::param::audio::AudioFormat::S16LE,
            };

            let mut audio_info = spa::param::audio::AudioInfoRaw::new();
            audio_info.set_format(spa_fmt);
            audio_info.set_rate(sample_rate);
            audio_info.set_channels(channels);

            let values: Vec<u8> = pw::spa::pod::serialize::PodSerializer::serialize(
                std::io::Cursor::new(Vec::new()),
                &pw::spa::pod::Value::Object(pw::spa::pod::Object {
                    type_: pw::spa::sys::SPA_TYPE_OBJECT_Format,
                    id: pw::spa::sys::SPA_PARAM_EnumFormat,
                    properties: audio_info.into(),
                }),
            )
            .ok()?
            .0
            .into_inner();

            let pod = spa::pod::Pod::from_bytes(&values)?;
            let mut params = [pod];

            stream
                .connect(
                    spa::utils::Direction::Output,
                    None,
                    pw::stream::StreamFlags::AUTOCONNECT
                        | pw::stream::StreamFlags::MAP_BUFFERS
                        | pw::stream::StreamFlags::RT_PROCESS,
                    &mut params,
                )
                .ok()?;

            let stream_raw = stream.into_raw();
            let listener_any: Box<dyn std::any::Any> = Box::new(listener);

            thread_loop.start();
            drop(_lock);

            Some(PwState {
                thread_loop,
                stream: Some(stream_raw),
                _listener: Some(listener_any),
            })
        })();

        if pw_state.is_some() {
            eprintln!("weave/waveOut: PipeWire stream connected");
        } else {
            eprintln!("weave/waveOut: PipeWire unavailable — silent mode");
        }

        let session = WaveOutSession {
            ring_buf,
            pw_state,
            callback,
            instance,
            flags,
        };
        wave_out_session_mutex().lock().unwrap().replace(session);

        if !phwo.is_null() {
            unsafe {
                *phwo = WAVE_OUT_HANDLE;
            }
        }
        unsafe {
            maybe_notify(WAVE_OUT_HANDLE, WOM_OPEN, callback, instance, flags);
        }
        return 0;
    }

    #[cfg(not(feature = "pipewire-audio"))]
    {
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
}

/// waveOutClose: close a wave output device.
/// Wine ref: dlls/winmm/waveform.c WOD_Close — invokes WOM_CLOSE callback.
pub extern "win64" fn wave_out_close(_hwo: usize) -> u32 {
    #[cfg(feature = "pipewire-audio")]
    {
        if let Some(m) = WAVE_OUT_SESSION.get() {
            if let Ok(mut guard) = m.lock() {
                guard.take(); // drops WaveOutSession → drops PwState → stops ThreadLoop
            }
        }
        return 0;
    }
    #[cfg(not(feature = "pipewire-audio"))]
    {
        0 // MMSYSERR_NOERROR
    }
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

/// waveOutWrite: submit a buffer for playback.
/// Wine ref: dlls/winmm/waveform.c — marks WHDR_INQUEUE while queued,
///   marks WHDR_DONE when buffer completes.
/// With pipewire-audio: pushes PCM data into the ring buffer consumed by the
/// PipeWire process callback. WOM_DONE is fired immediately after queuing
/// (approximate — real WinMM fires after playback completes).
///
/// # Safety
/// `pwh` must be a valid pointer to a WAVEHDR if non-null.
pub unsafe extern "win64" fn wave_out_write(_hwo: usize, pwh: *mut WAVEHDR, _cbwh: u32) -> u32 {
    #[cfg(feature = "pipewire-audio")]
    {
        if let Ok(guard) = wave_out_session_mutex().lock() {
            if let Some(ref session) = *guard {
                if !pwh.is_null() {
                    let hdr = &mut *pwh;
                    hdr.dwFlags |= WHDR_INQUEUE | WHDR_DONE;
                    if !hdr.lpData.is_null() && hdr.dwBufferLength > 0 {
                        let slice = std::slice::from_raw_parts(
                            hdr.lpData as *const u8,
                            hdr.dwBufferLength as usize,
                        );
                        if let Ok(mut ring) = session.ring_buf.lock() {
                            ring.write_from(slice);
                        }
                    }
                }
                maybe_notify(
                    WAVE_OUT_HANDLE,
                    WOM_DONE,
                    session.callback,
                    session.instance,
                    session.flags,
                );
            }
        }
        return 0;
    }

    #[cfg(not(feature = "pipewire-audio"))]
    {
        if !pwh.is_null() {
            unsafe {
                (*pwh).dwFlags |= WHDR_INQUEUE;
                (*pwh).dwFlags |= WHDR_DONE;
                (*pwh).dwFlags &= !WHDR_INQUEUE;
            }
        }
        0 // MMSYSERR_NOERROR
    }
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
