//! winmm.dll stubs for Weave.
//!
//! Covers the Windows Multimedia API: high-resolution timers (`timeGetTime`,
//! `timeBeginPeriod`, `timeEndPeriod`), wave audio device queries, and
//! joystick stubs. All functions use `extern "win64"`.

#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::time::{SystemTime, UNIX_EPOCH};

// ── PipeWire ring buffer (pipewire-audio feature) ────────────────────────────

#[cfg(feature = "pipewire-audio")]
use std::collections::VecDeque;

// WAVEHDR contains raw pointers but is only accessed under the session mutex.
// The PipeWire capture callback runs on a different thread; the WAVEHDR pointer
// is valid until the guest calls waveInUnprepareHeader. Safe because the Mutex
// serializes all access.
#[cfg(feature = "pipewire-audio")]
#[repr(transparent)]
struct SendWaveHdr(*mut crate::WAVEHDR);
#[cfg(feature = "pipewire-audio")]
unsafe impl Send for SendWaveHdr {}
#[cfg(feature = "pipewire-audio")]
unsafe impl Sync for SendWaveHdr {}
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

// ── waveIn global session ────────────────────────────────────────────────────

#[cfg(feature = "pipewire-audio")]
struct WaveInSession {
    ring_buf: Arc<Mutex<RingBuf>>,
    buffer_queue: Arc<Mutex<VecDeque<SendWaveHdr>>>,
    pw_state: Option<PwState>,
    callback: usize,
    instance: usize,
    flags: u32,
}

#[cfg(feature = "pipewire-audio")]
static WAVE_IN_SESSION: std::sync::OnceLock<Mutex<Option<WaveInSession>>> =
    std::sync::OnceLock::new();

#[cfg(feature = "pipewire-audio")]
fn wave_in_session_mutex() -> &'static Mutex<Option<WaveInSession>> {
    WAVE_IN_SESSION.get_or_init(|| Mutex::new(None))
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

// WIM messages — Wine ref: include/mmsystem.h
#[cfg(feature = "pipewire-audio")]
const WIM_OPEN: u32 = 0x3BE;
#[cfg(feature = "pipewire-audio")]
const WIM_CLOSE: u32 = 0x3BF;
#[cfg(feature = "pipewire-audio")]
const WIM_DATA: u32 = 0x3C0;

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

// Wine ref: include/mmsystem.h — WAVEINCAPSW struct layout (line 430)
#[repr(C)]
pub struct WAVEINCAPSW {
    pub wMid: u16,
    pub wPid: u16,
    pub vDriverVersion: u32,
    pub szPname: [u16; 32],
    pub dwFormats: u32,
    pub wChannels: u16,
    pub wReserved1: u16,
}

// Pseudo-handle value written to *phwo on success.
const WAVE_OUT_HANDLE: usize = 0x0001_0001;

// Pseudo-handle value written to *phwi on success.
#[cfg(feature = "pipewire-audio")]
const WAVE_IN_HANDLE: usize = 0x0002_0001;

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

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn wave_out_get_volume(_hwo: usize, _pdw_volume: usize) -> u32 {
    6 // MMSYSERR_NODRIVER
}

/// waveOutSetVolume: set the volume for a wave output device.
pub extern "win64" fn wave_out_set_volume(_hwo: usize, _dw_volume: u32) -> u32 {
    6 // MMSYSERR_NODRIVER
}

// Wine ref: dlls/winmm/waveform.c — PlaySoundA/W delegates to waveOut for file playback.
// Supports SND_FILENAME (path to .wav file) + SND_SYNC/SND_ASYNC.
// SND_ALIAS, SND_MEMORY, SND_LOOP, SND_NODEFAULT, SND_NOSTOP, SND_PURGE deferred.
const SND_FILENAME: u32 = 0x00020000;
const SND_ASYNC: u32 = 0x0001;
const _SND_SYNC: u32 = 0x0000; // deferred: sync-flag comparison
const SND_NODEFAULT: u32 = 0x0002;
const _SND_NOSTOP: u32 = 0x0010; // deferred: SND_NOSTOP
const _SND_LOOP: u32 = 0x0008; // deferred: looping playback

/// Parse a WAV file and play it via waveOut.
///
/// # Safety
/// `psz_sound` must be a null-terminated wide string pointing to a .wav file path.
pub unsafe extern "win64" fn play_sound_w(
    psz_sound: *const u16,
    _hmod: usize,
    fdw_sound: u32,
) -> i32 {
    // Only SND_FILENAME is implemented.
    if psz_sound.is_null() || (fdw_sound & SND_FILENAME) == 0 {
        // SND_ALIAS, SND_MEMORY, and default sound events are not implemented.
        // Return TRUE for SND_NODEFAULT? No — SND_NODEFAULT means don't fall back to default sound.
        // Without SND_FILENAME, we have nothing to play.
        return if (fdw_sound & SND_NODEFAULT) != 0 {
            1
        } else {
            0
        };
    }

    // Walk the null-terminated wide string to find its length.
    let mut path_len = 0usize;
    while unsafe { *psz_sound.add(path_len) } != 0 {
        path_len += 1;
    }
    let path_wide = unsafe { std::slice::from_raw_parts(psz_sound, path_len) };
    let path_str = String::from_utf16_lossy(path_wide);
    let linux_path = path_str.replace('\\', "/");
    // Strip Z: drive prefix if present.
    let linux_path = linux_path
        .strip_prefix("Z:/")
        .or(linux_path.strip_prefix("Z:\\"))
        .unwrap_or(&linux_path);

    eprintln!("weave/PlaySoundW: playing '{linux_path}' flags={fdw_sound:#x}");

    // Read the WAV file.
    let wav_data = match std::fs::read(linux_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("weave/PlaySoundW: failed to read '{linux_path}': {e}");
            return 0; // FALSE
        }
    };
    if wav_data.len() < 44 {
        eprintln!("weave/PlaySoundW: file too small for WAV header");
        return 0;
    }

    // Parse RIFF/WAV header.
    // Offset 0: "RIFF", offset 8: "WAVE", offset 12: "fmt ", offset 16: fmt chunk size
    if &wav_data[..4] != b"RIFF" || &wav_data[8..12] != b"WAVE" {
        eprintln!("weave/PlaySoundW: not a WAV file");
        return 0;
    }

    // Find the fmt chunk.
    let mut fmt_offset = 12;
    loop {
        if fmt_offset + 8 > wav_data.len() {
            eprintln!("weave/PlaySoundW: no fmt chunk found");
            return 0;
        }
        let chunk_id = &wav_data[fmt_offset..fmt_offset + 4];
        let chunk_size = u32::from_le_bytes([
            wav_data[fmt_offset + 4],
            wav_data[fmt_offset + 5],
            wav_data[fmt_offset + 6],
            wav_data[fmt_offset + 7],
        ]) as usize;
        if chunk_id == b"fmt " {
            break;
        }
        fmt_offset += 8 + chunk_size;
        // Round to even boundary per RIFF spec.
        if !chunk_size.is_multiple_of(2) {
            fmt_offset += 1;
        }
    }

    let fmt_data = &wav_data[fmt_offset + 8..];
    let format_tag = u16::from_le_bytes([fmt_data[0], fmt_data[1]]);
    if format_tag != 1 {
        // Only PCM (format 1) is supported.
        eprintln!("weave/PlaySoundW: unsupported format {format_tag} (only PCM/1 supported)");
        return 0;
    }
    let channels = u16::from_le_bytes([fmt_data[2], fmt_data[3]]) as u32;
    let sample_rate = u32::from_le_bytes([fmt_data[4], fmt_data[5], fmt_data[6], fmt_data[7]]);
    let bits_per_sample = u16::from_le_bytes([fmt_data[14], fmt_data[15]]);

    // Find the data chunk by scanning after the fmt chunk.
    let fmt_chunk_size = u32::from_le_bytes([
        wav_data[fmt_offset + 4],
        wav_data[fmt_offset + 5],
        wav_data[fmt_offset + 6],
        wav_data[fmt_offset + 7],
    ]) as usize;
    let mut scan_off = fmt_offset + 8 + fmt_chunk_size;
    if !fmt_chunk_size.is_multiple_of(2) {
        scan_off += 1;
    }
    loop {
        if scan_off + 8 > wav_data.len() {
            eprintln!("weave/PlaySoundW: no data chunk found");
            return 0;
        }
        let chunk_id = &wav_data[scan_off..scan_off + 4];
        let chunk_size = u32::from_le_bytes([
            wav_data[scan_off + 4],
            wav_data[scan_off + 5],
            wav_data[scan_off + 6],
            wav_data[scan_off + 7],
        ]) as usize;
        if chunk_id == b"data" {
            scan_off += 8; // skip past the chunk header to the data
            break;
        }
        scan_off += 8 + chunk_size;
        if !chunk_size.is_multiple_of(2) {
            scan_off += 1;
        }
    }
    let data_offset = scan_off;

    let pcm_data = &wav_data[data_offset..];
    let data_len = pcm_data.len();

    if data_len == 0 || channels == 0 || sample_rate == 0 || bits_per_sample == 0 {
        eprintln!("weave/PlaySoundW: invalid WAV parameters");
        return 0;
    }

    eprintln!("weave/PlaySoundW: {sample_rate} Hz {bits_per_sample}-bit {channels}ch {data_len} bytes PCM");

    // Build WAVEFORMATEX.
    let block_align = (channels as u16) * (bits_per_sample / 8);
    let avg_bytes_per_sec = sample_rate * block_align as u32;
    let fmt_ex = crate::WAVEFORMATEX {
        wFormatTag: 1, // WAVE_FORMAT_PCM
        nChannels: channels as u16,
        nSamplesPerSec: sample_rate,
        nAvgBytesPerSec: avg_bytes_per_sec,
        nBlockAlign: block_align,
        wBitsPerSample: bits_per_sample,
        cbSize: 0,
    };

    // Open waveOut with the parsed format.
    let mut hwo: usize = 0;
    let result = crate::wave_out_open(
        &mut hwo as *mut usize,
        0xFFFF_FFFF, // WAVE_MAPPER
        &fmt_ex as *const crate::WAVEFORMATEX,
        0, // dwCallback (CALLBACK_NULL)
        0, // dwInstance
        0, // fdwOpen
    );
    if result != 0 {
        eprintln!("weave/PlaySoundW: waveOutOpen failed {result}");
        return 0;
    }

    // Prepare WAVEHDR pointing to the PCM data.
    let mut header = crate::WAVEHDR {
        lpData: pcm_data.as_ptr() as *mut u8,
        dwBufferLength: data_len as u32,
        dwBytesRecorded: 0,
        dwUser: 0,
        dwFlags: 0,
        dwLoops: 0,
        lpNext: std::ptr::null_mut(),
        reserved: 0,
    };

    let prep = crate::wave_out_prepare_header(
        hwo,
        &mut header as *mut crate::WAVEHDR,
        std::mem::size_of::<crate::WAVEHDR>() as u32,
    );
    if prep != 0 {
        eprintln!("weave/PlaySoundW: waveOutPrepareHeader failed {prep}");
        crate::wave_out_close(hwo);
        return 0;
    }

    let write = crate::wave_out_write(
        hwo,
        &mut header as *mut crate::WAVEHDR,
        std::mem::size_of::<crate::WAVEHDR>() as u32,
    );
    if write != 0 {
        eprintln!("weave/PlaySoundW: waveOutWrite failed {write}");
    }

    if (fdw_sound & SND_ASYNC) != 0 {
        std::mem::forget(wav_data);
        eprintln!("weave/PlaySoundW: async playback started");
    } else {
        let duration_ms = (data_len as u64 * 1000) / avg_bytes_per_sec as u64;
        eprintln!("weave/PlaySoundW: sync playback ~{duration_ms}ms");
        std::thread::sleep(std::time::Duration::from_millis(duration_ms.min(30_000)));

        crate::wave_out_unprepare_header(
            hwo,
            &mut header as *mut crate::WAVEHDR,
            std::mem::size_of::<crate::WAVEHDR>() as u32,
        );
        crate::wave_out_close(hwo);
    }

    eprintln!("weave/PlaySoundW: done");
    1 // TRUE
}

/// # Safety
/// `psz_sound` must be a null-terminated ANSI string pointing to a .wav file path.
pub unsafe extern "win64" fn play_sound_a(
    psz_sound: *const u8,
    _hmod: usize,
    fdw_sound: u32,
) -> i32 {
    // Convert ANSI path to wide before delegating to the W variant.
    if psz_sound.is_null() || (fdw_sound & SND_FILENAME) == 0 {
        return if (fdw_sound & SND_NODEFAULT) != 0 {
            1
        } else {
            0
        };
    }
    let path_bytes = unsafe { std::ffi::CStr::from_ptr(psz_sound as *const i8) }.to_bytes();
    let path_str = String::from_utf8_lossy(path_bytes);
    let wide: Vec<u16> = path_str.encode_utf16().collect();
    let mut null_terminated: Vec<u16> = wide.clone();
    null_terminated.push(0);
    unsafe { play_sound_w(null_terminated.as_ptr(), _hmod, fdw_sound) }
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
        wave_out_session_mutex()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(session);

        if !phwo.is_null() {
            unsafe {
                *phwo = WAVE_OUT_HANDLE;
            }
        }
        unsafe {
            maybe_notify(WAVE_OUT_HANDLE, WOM_OPEN, callback, instance, flags);
        }
        0
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
        0
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
        0
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

// ── waveIn PipeWire helper ───────────────────────────────────────────────────

#[cfg(feature = "pipewire-audio")]
unsafe fn drain_capture_buffers(
    ring: &mut RingBuf,
    queue: &mut VecDeque<SendWaveHdr>,
    callback: usize,
    instance: usize,
    flags: u32,
) {
    while ring.available > 0 {
        let hdr_ptr = match queue.pop_front() {
            Some(p) => p,
            None => break,
        };
        let hdr = &mut *hdr_ptr.0;
        let cap = hdr.dwBufferLength as usize;
        if cap == 0 || hdr.lpData.is_null() {
            continue;
        }
        let dst = std::slice::from_raw_parts_mut(hdr.lpData, cap);
        let copied = ring.read_into(dst);
        hdr.dwBytesRecorded = copied as u32;
        hdr.dwFlags |= WHDR_DONE;
        hdr.dwFlags &= !WHDR_INQUEUE;
        maybe_notify(WAVE_IN_HANDLE, WIM_DATA, callback, instance, flags);
    }
}

// ── waveIn implementations ───────────────────────────────────────────────────

/// waveInGetNumDevs: return the number of wave input devices.
/// Wine ref: dlls/winmm/waveform.c — returns 1 when a capture device is present.
pub extern "win64" fn wave_in_get_num_devs() -> u32 {
    #[cfg(feature = "pipewire-audio")]
    {
        1
    }
    #[cfg(not(feature = "pipewire-audio"))]
    {
        0
    }
}

/// waveInOpen: open a waveform-audio input device.
/// Wine ref: dlls/winmm/waveform.c::waveInOpen — writes handle to *phwi,
///   invokes callback with WIM_OPEN on success.
///
/// # Safety
/// `phwi` must be null or a valid pointer to a usize. `pwfx` is read to
/// determine capture format. `callback` is invoked when flags indicate
/// CALLBACK_FUNCTION.
#[allow(unused_variables)]
pub unsafe extern "win64" fn wave_in_open(
    phwi: *mut usize,
    _dev_id: u32,
    pwfx: *const WAVEFORMATEX,
    callback: usize,
    instance: usize,
    flags: u32,
) -> u32 {
    #[cfg(feature = "pipewire-audio")]
    {
        use pipewire as pw;
        use pw::spa;

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

        let ring_capacity = (sample_rate as usize) * (frame_size) * 2;
        let ring_buf = Arc::new(Mutex::new(RingBuf::new(ring_capacity, frame_size)));
        let buffer_queue: Arc<Mutex<VecDeque<SendWaveHdr>>> = Arc::new(Mutex::new(VecDeque::new()));

        pw::init();

        let pw_state: Option<PwState> = (|| -> Option<PwState> {
            let thread_loop =
                unsafe { pw::thread_loop::ThreadLoop::new(Some("weave-wavein"), None) }.ok()?;
            let _lock = thread_loop.lock();
            let context = pw::context::Context::new(&thread_loop).ok()?;
            let core = context.connect(None).ok()?;

            let stream = pw::stream::Stream::new(
                &core,
                "weave-wavein",
                pw::properties::properties! {
                    *pw::keys::MEDIA_TYPE     => "Audio",
                    *pw::keys::MEDIA_ROLE     => "Music",
                    *pw::keys::MEDIA_CATEGORY => "Capture",
                },
            )
            .ok()?;

            let rb_clone = Arc::clone(&ring_buf);
            let bq_clone = Arc::clone(&buffer_queue);
            let cb_callback = callback;
            let cb_instance = instance;
            let cb_flags = flags;

            let listener = stream
                .add_local_listener_with_user_data(())
                .process(move |_stream, _| {
                    // In capture mode, PW delivers audio data. Copy it into the
                    // ring buffer, then drain into any queued WAVEHDR buffers.
                    let mut buf = match _stream.dequeue_buffer() {
                        Some(b) => b,
                        None => return,
                    };
                    let datas = buf.datas_mut();
                    let d = &mut datas[0];
                    let raw_ptr = d.as_raw().data as *mut u8;
                    if raw_ptr.is_null() {
                        return;
                    }
                    let total = match d.data() {
                        Some(slice) => slice.len(),
                        None => return,
                    };
                    let chunk = d.chunk();
                    let chunk_offset = chunk.offset() as usize;
                    let chunk_size = chunk.size() as usize;
                    let data_start = chunk_offset.min(total);
                    let data_end = (chunk_offset + chunk_size).min(total);
                    if data_end <= data_start {
                        return;
                    }
                    let src = unsafe { std::slice::from_raw_parts(raw_ptr, total) };
                    let actual_data = &src[data_start..data_end];

                    if let Ok(mut ring) = rb_clone.lock() {
                        ring.write_from(actual_data);
                        if let Ok(mut queue) = bq_clone.lock() {
                            unsafe {
                                drain_capture_buffers(
                                    &mut ring,
                                    &mut queue,
                                    cb_callback,
                                    cb_instance,
                                    cb_flags,
                                );
                            }
                        }
                    }
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
                    spa::utils::Direction::Input,
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
            eprintln!("weave/waveIn: PipeWire stream connected");
        } else {
            eprintln!("weave/waveIn: PipeWire unavailable — no capture");
        }

        let session = WaveInSession {
            ring_buf,
            buffer_queue,
            pw_state,
            callback,
            instance,
            flags,
        };
        wave_in_session_mutex()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(session);

        if !phwi.is_null() {
            unsafe {
                *phwi = WAVE_IN_HANDLE;
            }
        }
        unsafe {
            maybe_notify(WAVE_IN_HANDLE, WIM_OPEN, callback, instance, flags);
        }
        0
    }

    #[cfg(not(feature = "pipewire-audio"))]
    {
        6 // MMSYSERR_NODRIVER
    }
}

/// waveInClose: close a waveform-audio input device.
/// Wine ref: dlls/winmm/waveform.c::waveInClose — invokes WIM_CLOSE callback.
pub extern "win64" fn wave_in_close(_hwi: usize) -> u32 {
    #[cfg(feature = "pipewire-audio")]
    {
        if let Some(m) = WAVE_IN_SESSION.get() {
            if let Ok(mut guard) = m.lock() {
                guard.take();
            }
        }
        0
    }
    #[cfg(not(feature = "pipewire-audio"))]
    {
        0
    }
}

/// waveInPrepareHeader: prepare a buffer for audio capture.
/// Wine ref: dlls/winmm/waveform.c — sets WHDR_PREPARED in dwFlags.
///
/// # Safety
/// `pwh` must be a valid pointer to a WAVEHDR if non-null.
pub unsafe extern "win64" fn wave_in_prepare_header(
    _hwi: usize,
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

/// waveInUnprepareHeader: unprepare a capture buffer.
/// Wine ref: dlls/winmm/waveform.c — clears WHDR_PREPARED from dwFlags.
///
/// # Safety
/// `pwh` must be a valid pointer to a WAVEHDR if non-null.
pub unsafe extern "win64" fn wave_in_unprepare_header(
    _hwi: usize,
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

/// waveInAddBuffer: queue a buffer for capture.
/// Wine ref: dlls/winmm/waveform.c — marks WHDR_INQUEUE, fires WIM_DATA when
///   filled with captured audio data.
///
/// # Safety
/// `pwh` must be a valid pointer to a WAVEHDR if non-null.
pub unsafe extern "win64" fn wave_in_add_buffer(_hwi: usize, pwh: *mut WAVEHDR, _cbwh: u32) -> u32 {
    #[cfg(feature = "pipewire-audio")]
    {
        if let Ok(guard) = wave_in_session_mutex().lock() {
            if let Some(ref session) = *guard {
                if !pwh.is_null() {
                    let hdr = &mut *pwh;
                    hdr.dwFlags |= WHDR_INQUEUE;
                    let mut queue = session
                        .buffer_queue
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    queue.push_back(SendWaveHdr(pwh));
                    // Attempt to drain any accumulated audio into the queued buffer.
                    if let Ok(mut ring) = session.ring_buf.lock() {
                        unsafe {
                            drain_capture_buffers(
                                &mut ring,
                                &mut queue,
                                session.callback,
                                session.instance,
                                session.flags,
                            );
                        }
                    }
                }
            }
        }
        0
    }

    #[cfg(not(feature = "pipewire-audio"))]
    {
        if !pwh.is_null() {
            unsafe {
                (*pwh).dwFlags |= WHDR_INQUEUE;
            }
        }
        0
    }
}

/// waveInStart: start audio capture.
/// Wine ref: dlls/winmm/waveform.c — stream already started in open.
pub extern "win64" fn wave_in_start(_hwi: usize) -> u32 {
    0 // MMSYSERR_NOERROR
}

/// waveInStop: stop audio capture.
/// Wine ref: dlls/winmm/waveform.c.
pub extern "win64" fn wave_in_stop(_hwi: usize) -> u32 {
    0 // MMSYSERR_NOERROR
}

/// waveInReset: stop capture and reset the device.
/// Wine ref: dlls/winmm/waveform.c — stops capture, clears queued buffers.
pub extern "win64" fn wave_in_reset(_hwi: usize) -> u32 {
    #[cfg(feature = "pipewire-audio")]
    {
        if let Some(m) = WAVE_IN_SESSION.get() {
            if let Ok(mut guard) = m.lock() {
                if let Some(ref mut session) = *guard {
                    let mut queue = session
                        .buffer_queue
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    while let Some(hdr_wrapper) = queue.pop_front() {
                        unsafe {
                            let hdr = &mut *hdr_wrapper.0;
                            hdr.dwBytesRecorded = 0;
                            hdr.dwFlags |= WHDR_DONE;
                            hdr.dwFlags &= !WHDR_INQUEUE;
                            maybe_notify(
                                WAVE_IN_HANDLE,
                                WIM_DATA,
                                session.callback,
                                session.instance,
                                session.flags,
                            );
                        }
                    }
                }
            }
        }
        0
    }

    #[cfg(not(feature = "pipewire-audio"))]
    {
        0
    }
}

/// waveInGetDevCapsW: get capabilities of a wave input device (Wide).
/// Wine ref: dlls/winmm/waveform.c — fills a WAVEINCAPSW struct.
///
/// # Safety
/// `pwic` must be null or a valid pointer to at least `cbwic` bytes.
pub unsafe extern "win64" fn wave_in_get_dev_caps_w(
    _dev_id: u32,
    pwic: *mut WAVEINCAPSW,
    cbwic: u32,
) -> u32 {
    if !pwic.is_null() && cbwic as usize >= std::mem::size_of::<WAVEINCAPSW>() {
        unsafe {
            let caps = &mut *pwic;
            caps.wMid = 0;
            caps.wPid = 0;
            caps.vDriverVersion = 0x0100;
            // "Weave Audio Input" as UTF-16LE, null-padded
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
                b' ' as u16,
                b'I' as u16,
                b'n' as u16,
                b'p' as u16,
                b'u' as u16,
                b't' as u16,
                0u16,
            ];
            caps.szPname[..name.len()].copy_from_slice(name);
            caps.dwFormats = 0x000FFFFF;
            caps.wChannels = 2;
            caps.wReserved1 = 0;
        }
    }
    0 // MMSYSERR_NOERROR
}

/// waveInGetErrorTextW: get a text description of a waveIn error.
/// Wine ref: dlls/winmm/winmm.c — writes "Unknown error\0" for any error code.
///
/// # Safety
/// `psz_text` must be null or a valid pointer to at least `cch_text` u16 values.
pub unsafe extern "win64" fn wave_in_get_error_text_w(
    _err: u32,
    psz_text: *mut u16,
    cch_text: u32,
) -> u32 {
    const UNKNOWN: [u16; 14] = [
        85, 110, 107, 110, 111, 119, 110, 32, 101, 114, 114, 111, 114, 0,
    ];
    if !psz_text.is_null() && cch_text > 0 {
        let to_copy = (cch_text as usize).min(UNKNOWN.len());
        unsafe {
            std::ptr::copy_nonoverlapping(UNKNOWN.as_ptr(), psz_text, to_copy);
        }
    }
    0 // MMSYSERR_NOERROR
}

/// waveOutGetErrorTextW: get a text description of a waveOut error.
/// Wine ref: dlls/winmm/winmm.c::waveOutGetErrorTextW — writes error string into pszText.
/// Writes "Unknown error\0" as UTF-16LE for any error code.
///
/// # Safety
/// `psz_text` must be null or a valid pointer to at least `cch_text` u16 values.
pub unsafe extern "win64" fn wave_out_get_error_text_w(
    _err: u32,
    psz_text: *mut u16,
    cch_text: u32,
) -> u32 {
    // "Unknown error\0" as UTF-16LE (13 chars + NUL = 14 u16 values)
    const UNKNOWN: [u16; 14] = [
        85, 110, 107, 110, 111, 119, 110, 32, 101, 114, 114, 111, 114, 0,
    ];
    if !psz_text.is_null() && cch_text > 0 {
        let to_copy = (cch_text as usize).min(UNKNOWN.len());
        unsafe {
            std::ptr::copy_nonoverlapping(UNKNOWN.as_ptr(), psz_text, to_copy);
        }
    }
    0 // MMSYSERR_NOERROR
}

// ── Signal gap-fill: MIDI stubs ───────────────────────────────────────────────
//
// jcodemunch unavailable — Phase A stubs only, safe sentinel returns.
// Wine ref comments deferred to jcodemunch-available session.

const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_NODRIVER: u32 = 6;

// ── MIDI Input — Phase B (no devices available) ───────────────────────────────
// Reports 0 input devices and returns MMSYSERR_NOERROR for no-op operations.
// No real MIDI hardware emulation — stubs return clean "no device" codes.

/// midiInGetNumDevs: get number of MIDI input devices.
pub extern "win64" fn midi_in_get_num_devs() -> u32 {
    0
}

/// midiInGetDevCapsW: get MIDI input device capabilities (Wide).
/// No devices — returns NODRIVER.
///
/// # Safety
/// Caller must ensure `pmic` points to a buffer of at least `cb_mic` bytes.
pub unsafe extern "win64" fn midi_in_get_dev_caps_w(
    _u_device_id: u32,
    _pmic: *mut u8,
    _cb_mic: u32,
) -> u32 {
    MMSYSERR_NODRIVER
}

/// midiInOpen: open a MIDI input device — no devices available.
///
/// # Safety
/// Caller must ensure `phmi` is a valid output pointer.
pub unsafe extern "win64" fn midi_in_open(
    _phmi: *mut usize,
    _u_device_id: u32,
    _dw_callback: usize,
    _dw_instance: usize,
    _fdw_open: u32,
) -> u32 {
    MMSYSERR_NODRIVER
}

/// midiInClose: close a MIDI input device — no-op (no devices).
pub extern "win64" fn midi_in_close(_hmi: usize) -> u32 {
    MMSYSERR_NOERROR
}

/// midiInPrepareHeader: prepare a MIDI input buffer — no-op.
///
/// # Safety
/// Caller must ensure `pmh` is a valid pointer.
pub unsafe extern "win64" fn midi_in_prepare_header(
    _hmi: usize,
    _pmh: *mut u8,
    _cb_mh: u32,
) -> u32 {
    MMSYSERR_NOERROR
}

/// midiInUnprepareHeader: unprepare a MIDI input buffer — no-op.
///
/// # Safety
/// Caller must ensure `pmh` is a valid pointer.
pub unsafe extern "win64" fn midi_in_unprepare_header(
    _hmi: usize,
    _pmh: *mut u8,
    _cb_mh: u32,
) -> u32 {
    MMSYSERR_NOERROR
}

/// midiInAddBuffer: add buffer to MIDI input — no-op (no capture).
///
/// # Safety
/// Caller must ensure `pmh` is a valid pointer.
pub unsafe extern "win64" fn midi_in_add_buffer(_hmi: usize, _pmh: *mut u8, _cb_mh: u32) -> u32 {
    MMSYSERR_NOERROR
}

/// midiInStart: start MIDI input — no-op (no devices).
pub extern "win64" fn midi_in_start(_hmi: usize) -> u32 {
    MMSYSERR_NOERROR
}

/// midiInReset: reset MIDI input — no-op.
pub extern "win64" fn midi_in_reset(_hmi: usize) -> u32 {
    MMSYSERR_NOERROR
}

// ── MIDI Output — Phase B (no devices available) ──────────────────────────────
// Reports 0 output devices. Open returns NODRIVER; no-ops return NOERROR.

/// midiOutGetNumDevs: get number of MIDI output devices.
pub extern "win64" fn midi_out_get_num_devs() -> u32 {
    0
}

/// midiOutGetDevCapsW: get MIDI output device capabilities (Wide).
/// No devices — returns NODRIVER.
///
/// # Safety
/// Caller must ensure `pmoc` points to a buffer of at least `cb_moc` bytes.
pub unsafe extern "win64" fn midi_out_get_dev_caps_w(
    _u_device_id: u32,
    _pmoc: *mut u8,
    _cb_moc: u32,
) -> u32 {
    MMSYSERR_NODRIVER
}

/// midiOutOpen: open a MIDI output device — no devices available.
///
/// # Safety
/// Caller must ensure `phmo` is a valid output pointer.
pub unsafe extern "win64" fn midi_out_open(
    _phmo: *mut usize,
    _u_device_id: u32,
    _dw_callback: usize,
    _dw_instance: usize,
    _fdw_open: u32,
) -> u32 {
    MMSYSERR_NODRIVER
}

/// midiOutClose: close a MIDI output device — no-op.
pub extern "win64" fn midi_out_close(_hmo: usize) -> u32 {
    MMSYSERR_NOERROR
}

/// midiOutPrepareHeader: prepare a MIDI output buffer — no-op.
///
/// # Safety
/// Caller must ensure `pmh` is a valid pointer.
pub unsafe extern "win64" fn midi_out_prepare_header(
    _hmo: usize,
    _pmh: *mut u8,
    _cb_mh: u32,
) -> u32 {
    MMSYSERR_NOERROR
}

/// midiOutUnprepareHeader: unprepare a MIDI output buffer — no-op.
///
/// # Safety
/// Caller must ensure `pmh` is a valid pointer.
pub unsafe extern "win64" fn midi_out_unprepare_header(
    _hmo: usize,
    _pmh: *mut u8,
    _cb_mh: u32,
) -> u32 {
    MMSYSERR_NOERROR
}

/// midiOutShortMsg: send a short MIDI message — discarded (no devices).
pub extern "win64" fn midi_out_short_msg(_hmo: usize, _dw_msg: u32) -> u32 {
    MMSYSERR_NOERROR
}

/// midiOutLongMsg: send a long (system exclusive) MIDI message — discarded.
///
/// # Safety
/// Caller must ensure `pmh` is a valid pointer.
pub unsafe extern "win64" fn midi_out_long_msg(_hmo: usize, _pmh: *mut u8, _cb_mh: u32) -> u32 {
    MMSYSERR_NOERROR
}

/// midiOutReset: reset MIDI output — no-op.
pub extern "win64" fn midi_out_reset(_hmo: usize) -> u32 {
    MMSYSERR_NOERROR
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
        "waveInOpen" => Some(
            wave_in_open
                as unsafe extern "win64" fn(
                    *mut usize,
                    u32,
                    *const WAVEFORMATEX,
                    usize,
                    usize,
                    u32,
                ) -> u32 as *const () as usize,
        ),
        "waveInClose" => {
            Some(wave_in_close as extern "win64" fn(usize) -> u32 as *const () as usize)
        }
        "waveInPrepareHeader" => Some(
            wave_in_prepare_header as unsafe extern "win64" fn(usize, *mut WAVEHDR, u32) -> u32
                as *const () as usize,
        ),
        "waveInUnprepareHeader" => Some(
            wave_in_unprepare_header as unsafe extern "win64" fn(usize, *mut WAVEHDR, u32) -> u32
                as *const () as usize,
        ),
        "waveInAddBuffer" => Some(
            wave_in_add_buffer as unsafe extern "win64" fn(usize, *mut WAVEHDR, u32) -> u32
                as *const () as usize,
        ),
        "waveInStart" => {
            Some(wave_in_start as extern "win64" fn(usize) -> u32 as *const () as usize)
        }
        "waveInStop" => Some(wave_in_stop as extern "win64" fn(usize) -> u32 as *const () as usize),
        "waveInReset" => {
            Some(wave_in_reset as extern "win64" fn(usize) -> u32 as *const () as usize)
        }
        "waveInGetDevCapsW" => Some(
            wave_in_get_dev_caps_w as unsafe extern "win64" fn(u32, *mut WAVEINCAPSW, u32) -> u32
                as *const () as usize,
        ),
        "waveInGetErrorTextW" => Some(
            wave_in_get_error_text_w as unsafe extern "win64" fn(u32, *mut u16, u32) -> u32
                as *const () as usize,
        ),
        "waveOutGetErrorTextW" => Some(
            wave_out_get_error_text_w as unsafe extern "win64" fn(u32, *mut u16, u32) -> u32
                as *const () as usize,
        ),
        // ── Signal gap-fill: 18 MIDI Phase A stubs ──
        "midiInGetNumDevs" => Some(midi_in_get_num_devs as *const () as usize),
        "midiInGetDevCapsW" => Some(
            midi_in_get_dev_caps_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "midiInOpen" => {
            Some(midi_in_open as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "midiInClose" => Some(midi_in_close as extern "win64" fn(_) -> _ as *const () as usize),
        "midiInPrepareHeader" => Some(
            midi_in_prepare_header as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "midiInUnprepareHeader" => Some(
            midi_in_unprepare_header as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "midiInAddBuffer" => {
            Some(midi_in_add_buffer as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "midiInStart" => Some(midi_in_start as extern "win64" fn(_) -> _ as *const () as usize),
        "midiInReset" => Some(midi_in_reset as extern "win64" fn(_) -> _ as *const () as usize),
        "midiOutGetNumDevs" => Some(midi_out_get_num_devs as *const () as usize),
        "midiOutGetDevCapsW" => Some(
            midi_out_get_dev_caps_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "midiOutOpen" => Some(
            midi_out_open as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "midiOutClose" => Some(midi_out_close as extern "win64" fn(_) -> _ as *const () as usize),
        "midiOutPrepareHeader" => Some(
            midi_out_prepare_header as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "midiOutUnprepareHeader" => Some(
            midi_out_unprepare_header as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "midiOutShortMsg" => {
            Some(midi_out_short_msg as extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "midiOutLongMsg" => {
            Some(midi_out_long_msg as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "midiOutReset" => Some(midi_out_reset as extern "win64" fn(_) -> _ as *const () as usize),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::resolve;

    #[test]
    fn resolve_known_functions() {
        let funcs = [
            "timeGetTime",
            "timeBeginPeriod",
            "timeEndPeriod",
            "waveOutGetNumDevs",
            "waveOutOpen",
            "waveOutClose",
            "waveOutPrepareHeader",
            "waveOutUnprepareHeader",
            "waveOutWrite",
            "waveOutReset",
            "waveOutPause",
            "waveOutRestart",
            "waveInGetNumDevs",
            "waveInOpen",
            "waveInClose",
            "waveInPrepareHeader",
            "waveInUnprepareHeader",
            "waveInAddBuffer",
            "waveInStart",
            "waveInStop",
            "waveInReset",
            "waveInGetDevCapsW",
            "waveInGetErrorTextW",
        ];
        for f in &funcs {
            assert!(resolve("winmm.dll", f).is_some(), "missing {f}");
        }
    }

    #[test]
    fn resolve_midi_stubs() {
        let midi = [
            "midiInGetNumDevs",
            "midiInGetDevCapsW",
            "midiInOpen",
            "midiInClose",
            "midiInPrepareHeader",
            "midiInUnprepareHeader",
            "midiInAddBuffer",
            "midiInStart",
            "midiInReset",
            "midiOutGetNumDevs",
            "midiOutGetDevCapsW",
            "midiOutOpen",
            "midiOutClose",
            "midiOutPrepareHeader",
            "midiOutUnprepareHeader",
            "midiOutShortMsg",
            "midiOutLongMsg",
            "midiOutReset",
        ];
        for f in &midi {
            assert!(resolve("winmm.dll", f).is_some(), "missing {f}");
        }
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("kernel32.dll", "timeGetTime").is_none());
        assert!(resolve("winmm.dll", "__nonexistent__").is_none());
    }
}
