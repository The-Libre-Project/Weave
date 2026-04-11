//! mmdevapi.dll stubs for Weave.
//!
//! Implements WASAPI (Windows Audio Session API) backed by PipeWire on Linux.
//! Also provides DirectSound as a thin layer on top of WASAPI.
//!
//! Audio streaming architecture:
//! - `IAudioClient::Initialize` calculates the ring buffer size and stores format info.
//! - `IAudioRenderClient::GetBuffer` returns a pointer into a per-client scratch buffer.
//! - `IAudioRenderClient::ReleaseBuffer` copies the scratch data into a ring buffer shared
//!   with the PipeWire process callback.
//! - `IAudioClient::Start` (Linux only) spawns a PipeWire ThreadLoop, creates a Stream,
//!   and registers a `process` callback that drains the ring buffer into PipeWire buffers.
//! - `IAudioClient::Stop` (Linux only) stops the PipeWire ThreadLoop.
//! - `IAudioClient::Reset` flushes the ring buffer.

#![allow(non_snake_case)]

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

// ── Ring Buffer ──────────────────────────────────────────────────────────────
//
// A simple lock-based ring buffer shared between the COM thread (writer)
// and the PipeWire callback thread (reader). The write pointer is advanced by
// ReleaseBuffer; the read pointer is advanced inside the PipeWire process
// callback. Both sides hold an Arc<Mutex<RingBuf>>.

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

    /// Return a mutable pointer into the ring buffer's write region for
    /// `num_frames` frames.  Grows the buffer if necessary; drops the oldest
    /// data if the ring is full (best-effort overrun handling).
    fn write_ptr_mut(&mut self, num_frames: usize) -> Option<*mut u8> {
        let needed = num_frames * self.frame_size;
        if needed == 0 {
            return None;
        }
        let capacity = self.data.len();

        if needed > capacity {
            // Buffer is too small — grow it.
            self.data.resize(needed * 2, 0);
        }

        let free = capacity.saturating_sub(self.available);
        if needed > free {
            // Not enough space; discard the oldest bytes to make room.
            let overflow = needed - free;
            self.read_pos = (self.read_pos + overflow) % self.data.len();
            self.available = self.available.saturating_sub(overflow);
        }

        Some(unsafe { self.data.as_mut_ptr().add(self.write_pos) })
    }

    /// Advance the write pointer by `num_frames` (called after data is written
    /// via the pointer returned by `write_ptr_mut`).
    fn commit_write(&mut self, num_frames: usize) {
        let bytes = num_frames * self.frame_size;
        let capacity = self.data.len();
        self.write_pos = (self.write_pos + bytes) % capacity;
        self.available = (self.available + bytes).min(capacity);
    }

    /// Read up to `dst.len()` bytes into `dst`.  Returns bytes actually copied.
    #[cfg(feature = "pipewire-audio")]
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

    /// Flush the ring buffer (reset all pointers, zero the data).
    fn reset(&mut self) {
        self.available = 0;
        self.write_pos = 0;
        self.read_pos = 0;
        self.data.fill(0);
    }
}

// ── Audio device state ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AudioDevice {
    id: String,
    #[allow(dead_code)]
    name: String,
    is_default: bool,
}

static AUDIO_DEVICES: Mutex<Vec<AudioDevice>> = Mutex::new(Vec::new());

fn lock_audio_devices<'a>(
    m: &'a Mutex<Vec<AudioDevice>>,
) -> Option<std::sync::MutexGuard<'a, Vec<AudioDevice>>> {
    m.lock()
        .map_err(|e| eprintln!("weave: weave-mmdevapi: audio devices mutex poisoned: {e}"))
        .ok()
}

fn lock_ring_buf<'a>(
    m: &'a Mutex<RingBuf>,
) -> Option<std::sync::MutexGuard<'a, RingBuf>> {
    m.lock()
        .map_err(|e| eprintln!("weave: weave-mmdevapi: ring buf mutex poisoned: {e}"))
        .ok()
}

fn ensure_devices_initialized() {
    let mut devices = match lock_audio_devices(&AUDIO_DEVICES) {
        Some(g) => g,
        None => return,
    };
    if devices.is_empty() {
        devices.push(AudioDevice {
            id: "default".to_string(),
            name: "Default Audio Device".to_string(),
            is_default: true,
        });
    }
}

// ── PipeWire stream state (Linux only) ──────────────────────────────────────

/// Live PipeWire objects for one IAudioClient session.
///
/// PipeWire objects use `Rc` internally and are therefore `!Send`.  We drive
/// them from the ThreadLoop's internal thread; the COM thread only touches them
/// while holding the ThreadLoop lock (via `thread_loop.lock()`).
///
/// The `listener` field holds the `StreamListener<()>` registration that
/// keeps the process callback alive.  We box-erase it to `dyn Any` so we
/// don't have to propagate the `D` generic parameter out of this struct.
#[cfg(feature = "pipewire-audio")]
struct PwState {
    thread_loop: pipewire::thread_loop::ThreadLoop,
    /// Raw stream pointer so we can call pw_stream_destroy in Drop before
    /// stopping the thread loop.  Wrapped in Option so Drop can clear it.
    stream: Option<*mut pipewire::sys::pw_stream>,
    /// Type-erased StreamListener<()> — must be dropped before the stream.
    _listener: Option<Box<dyn std::any::Any>>,
}

#[cfg(feature = "pipewire-audio")]
impl Drop for PwState {
    fn drop(&mut self) {
        // Drop the listener first (it holds raw pointers into the stream).
        self._listener = None;
        // Then destroy the stream.
        if let Some(ptr) = self.stream.take() {
            unsafe { pipewire::sys::pw_stream_destroy(ptr) };
        }
        self.thread_loop.stop();
    }
}

// SAFETY: We access PwState only while holding the ThreadLoop lock (COM thread)
// or from within the ThreadLoop's own process callback.  Drop is only called
// from the COM thread after `Stop()` (which stops the PW thread first).
#[cfg(feature = "pipewire-audio")]
unsafe impl Send for PwState {}

// ── Windows Audio Structures ─────────────────────────────────────────────────

/// WAVEFORMATEX
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WaveFormatEx {
    pub w_format_tag: u16,
    pub n_channels: u16,
    pub n_samples_per_sec: u32,
    pub n_avg_bytes_per_sec: u32,
    pub n_block_align: u16,
    pub w_bits_per_sample: u16,
    pub cb_size: u16,
}

pub const AUDCLNT_SHAREMODE_SHARED: u32 = 0;
pub const AUDCLNT_SHAREMODE_EXCLUSIVE: u32 = 1;
pub const AUDCLNT_STREAMFLAGS_EVENTCALLBACK: u32 = 0x00040000;
pub const AUDCLNT_STREAMFLAGS_LOOPBACK: u32 = 0x00020000;
pub const AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM: u32 = 0x80000000;
pub const AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY: u32 = 0x08000000;

// ── COM Vtable types ─────────────────────────────────────────────────────────

#[repr(C)]
pub struct IUnknownVtable {
    pub query_interface: unsafe extern "win64" fn(*mut usize, *const u8, *mut *mut usize) -> i32,
    pub add_ref: unsafe extern "win64" fn(*mut usize) -> u32,
    pub release: unsafe extern "win64" fn(*mut usize) -> u32,
}

#[repr(C)]
pub struct IMMDeviceVtable {
    pub parent: IUnknownVtable,
    pub activate:
        unsafe extern "win64" fn(*mut usize, *const u8, u32, *const usize, *mut *mut usize) -> i32,
    pub open_property_store: unsafe extern "win64" fn(*mut usize, u32, *mut *mut usize) -> i32,
    pub get_id: unsafe extern "win64" fn(*mut usize, *mut *mut u16) -> i32,
    pub get_state: unsafe extern "win64" fn(*mut usize, *mut u32) -> i32,
}

#[repr(C)]
pub struct IMMDeviceEnumeratorVtable {
    pub parent: IUnknownVtable,
    pub enum_audio_endpoints:
        unsafe extern "win64" fn(*mut usize, u32, u32, *mut *mut usize) -> i32,
    pub get_default_audio_endpoint:
        unsafe extern "win64" fn(*mut usize, u32, u32, *mut *mut usize) -> i32,
    pub get_device: unsafe extern "win64" fn(*mut usize, *const u16, *mut *mut usize) -> i32,
    pub register_endpoint_notification_callback:
        unsafe extern "win64" fn(*mut usize, *mut usize) -> i32,
    pub unregister_endpoint_notification_callback:
        unsafe extern "win64" fn(*mut usize, *mut usize) -> i32,
}

#[repr(C)]
pub struct IAudioClientVtable {
    pub parent: IUnknownVtable,
    pub initialize: unsafe extern "win64" fn(
        *mut usize,
        u32,
        u64,
        *const WaveFormatEx,
        *const WaveFormatEx,
    ) -> i32,
    pub get_buffer_size: unsafe extern "win64" fn(*mut usize, *mut u32) -> i32,
    pub get_stream_latency: unsafe extern "win64" fn(*mut usize, *mut i64) -> i32,
    pub get_current_padding: unsafe extern "win64" fn(*mut usize, *mut u32) -> i32,
    pub is_format_supported: unsafe extern "win64" fn(
        *mut usize,
        u32,
        *const WaveFormatEx,
        *mut *mut WaveFormatEx,
    ) -> i32,
    pub get_mix_format: unsafe extern "win64" fn(*mut usize, *mut *mut WaveFormatEx) -> i32,
    pub get_device_period: unsafe extern "win64" fn(*mut usize, *mut i64, *mut i64) -> i32,
    pub start: unsafe extern "win64" fn(*mut usize) -> i32,
    pub stop: unsafe extern "win64" fn(*mut usize) -> i32,
    pub reset: unsafe extern "win64" fn(*mut usize) -> i32,
    pub set_event_handle: unsafe extern "win64" fn(*mut usize, usize) -> i32,
    pub get_service: unsafe extern "win64" fn(*mut usize, *const u8, *mut *mut usize) -> i32,
}

#[repr(C)]
pub struct IAudioRenderClientVtable {
    pub parent: IUnknownVtable,
    pub get_buffer: unsafe extern "win64" fn(*mut usize, u32, *mut *mut u8) -> i32,
    pub release_buffer: unsafe extern "win64" fn(*mut usize, u32, u32) -> i32,
}

// ── COM Object structs ───────────────────────────────────────────────────────

struct MMDevice {
    device: AudioDevice,
    ref_count: RefCell<u32>,
}

impl MMDevice {
    fn new(device: AudioDevice) -> Self {
        Self {
            device,
            ref_count: RefCell::new(1),
        }
    }
}

struct MMDeviceEnumerator {
    ref_count: RefCell<u32>,
}

impl MMDeviceEnumerator {
    fn new() -> Self {
        Self {
            ref_count: RefCell::new(1),
        }
    }
}

/// IAudioClient state.
///
/// `ring_buf` is shared with the `IAudioRenderClient` (and on Linux with the
/// PipeWire process callback).  Audio written by the app through
/// GetBuffer/ReleaseBuffer lands here; the PW callback drains it.
struct AudioClient {
    #[allow(dead_code)]
    device_id: String,
    format: Option<WaveFormatEx>,
    /// Frame count reported to the app via GetBufferSize (100 ms).
    buffer_frames: u32,
    /// Bytes per frame: channels x bytes_per_sample.
    frame_size: usize,
    ref_count: RefCell<u32>,
    ring_buf: Arc<Mutex<RingBuf>>,
    /// PipeWire stream state — Linux only.
    #[cfg(feature = "pipewire-audio")]
    pw_state: Option<Box<PwState>>,
}

impl AudioClient {
    fn new(device_id: String) -> Self {
        let frame_size = 4; // 2ch x 2 bytes; updated in Initialize
        let ring_capacity = 48000 * frame_size; // 1 s at 48 kHz stereo 16-bit
        Self {
            device_id,
            format: None,
            buffer_frames: 0,
            frame_size,
            ref_count: RefCell::new(1),
            ring_buf: Arc::new(Mutex::new(RingBuf::new(ring_capacity, frame_size))),
            #[cfg(feature = "pipewire-audio")]
            pw_state: None,
        }
    }
}

/// IAudioRenderClient state.
///
/// Holds a clone of the `AudioClient`'s `ring_buf` Arc so ReleaseBuffer can
/// push data without a pointer back to AudioClient.  `write_buf` is a scratch
/// buffer whose pointer is handed to the Windows app by GetBuffer.
struct AudioRenderClient {
    ref_count: RefCell<u32>,
    ring_buf: Arc<Mutex<RingBuf>>,
    /// Scratch buffer: written by app, copied into ring_buf by ReleaseBuffer.
    write_buf: Vec<u8>,
    frame_size: usize,
}

impl AudioRenderClient {
    fn new(ring_buf: Arc<Mutex<RingBuf>>, frame_size: usize) -> Self {
        Self {
            ref_count: RefCell::new(1),
            ring_buf,
            write_buf: Vec::new(),
            frame_size,
        }
    }
}

// ── IMMDevice COM methods ────────────────────────────────────────────────────

unsafe extern "win64" fn imm_device_query_interface(
    _this: *mut usize,
    _riid: *const u8,
    ppv_object: *mut *mut usize,
) -> i32 {
    *ppv_object = std::ptr::null_mut();
    -2147467262 // E_NOINTERFACE
}

unsafe extern "win64" fn imm_device_add_ref(this: *mut usize) -> u32 {
    let d = &mut *(this as *mut MMDevice);
    let mut rc = d.ref_count.borrow_mut();
    *rc += 1;
    *rc
}

unsafe extern "win64" fn imm_device_release(this: *mut usize) -> u32 {
    let d = &mut *(this as *mut MMDevice);
    let mut rc = d.ref_count.borrow_mut();
    *rc -= 1;
    let cur = *rc;
    if cur == 0 {
        drop(Box::from_raw(this as *mut MMDevice));
    }
    cur
}

unsafe extern "win64" fn imm_device_activate(
    this: *mut usize,
    iid: *const u8,
    _dw_cls_ctx: u32,
    _p_activation_params: *const usize,
    pp_interface: *mut *mut usize,
) -> i32 {
    let device = &*(this as *mut MMDevice);
    let requested_iid = std::slice::from_raw_parts(iid, 16);
    // IID_IAudioClient: 1CB9AD4C-64ED-4138-8B7D-287E08262B18
    if requested_iid
        == [
            0x4C, 0xAD, 0xB9, 0x1C, 0xED, 0x64, 0x38, 0x41, 0x8B, 0x7D, 0x28, 0x7E, 0x08, 0x26,
            0x2B, 0x18,
        ]
    {
        let client = Box::new(AudioClient::new(device.device.id.clone()));
        let ptr = Box::into_raw(client) as *mut usize;
        *(ptr as *mut *const IAudioClientVtable) = &IAUDIO_CLIENT_VTABLE;
        *pp_interface = ptr;
        return 0;
    }
    *pp_interface = std::ptr::null_mut();
    -2147467262
}

unsafe extern "win64" fn imm_device_open_property_store(
    _this: *mut usize,
    _stgm_access: u32,
    _pp_properties: *mut *mut usize,
) -> i32 {
    -2147467263
}

unsafe extern "win64" fn imm_device_get_id(this: *mut usize, ppstr_id: *mut *mut u16) -> i32 {
    let device = &*(this as *mut MMDevice);
    let wide: Vec<u16> = device
        .device
        .id
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let ptr = wide.as_ptr() as *mut u16;
    std::mem::forget(wide);
    *ppstr_id = ptr;
    0
}

unsafe extern "win64" fn imm_device_get_state(_this: *mut usize, _pdw_state: *mut u32) -> i32 {
    -2147467263
}

// ── IMMDeviceEnumerator COM methods ──────────────────────────────────────────

unsafe extern "win64" fn imm_device_enumerator_query_interface(
    this: *mut usize,
    riid: *const u8,
    ppv_object: *mut *mut usize,
) -> i32 {
    let iid = std::slice::from_raw_parts(riid, 16);
    // IID_IMMDeviceEnumerator: A95664D2-9614-4F35-A746-DE8DB63617E6
    if iid
        == [
            0xD2, 0x64, 0x56, 0xA9, 0x14, 0x96, 0x35, 0x4F, 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36,
            0x17, 0xE6,
        ]
    {
        *ppv_object = this;
        imm_device_enumerator_add_ref(this);
        return 0;
    }
    *ppv_object = std::ptr::null_mut();
    -2147467262
}

unsafe extern "win64" fn imm_device_enumerator_add_ref(this: *mut usize) -> u32 {
    let e = &mut *(this as *mut MMDeviceEnumerator);
    let mut rc = e.ref_count.borrow_mut();
    *rc += 1;
    *rc
}

unsafe extern "win64" fn imm_device_enumerator_release(this: *mut usize) -> u32 {
    let e = &mut *(this as *mut MMDeviceEnumerator);
    let mut rc = e.ref_count.borrow_mut();
    *rc -= 1;
    let cur = *rc;
    if cur == 0 {
        drop(Box::from_raw(this as *mut MMDeviceEnumerator));
    }
    cur
}

unsafe extern "win64" fn imm_device_enumerator_enum_audio_endpoints(
    _this: *mut usize,
    _data_flow: u32,
    _dw_state_mask: u32,
    _pp_devices: *mut *mut usize,
) -> i32 {
    -2147467263
}

unsafe extern "win64" fn imm_device_enumerator_get_default_audio_endpoint(
    _this: *mut usize,
    _data_flow: u32,
    _role: u32,
    pp_endpoint: *mut *mut usize,
) -> i32 {
    ensure_devices_initialized();
    let devices = match lock_audio_devices(&AUDIO_DEVICES) {
        Some(g) => g,
        None => return -2147023728,
    };
    if let Some(dev) = devices.iter().find(|d| d.is_default) {
        let device = Box::new(MMDevice::new(dev.clone()));
        let ptr = Box::into_raw(device) as *mut usize;
        *(ptr as *mut *const IMMDeviceVtable) = &IMM_DEVICE_VTABLE;
        *pp_endpoint = ptr;
        return 0;
    }
    *pp_endpoint = std::ptr::null_mut();
    -2147023728
}

unsafe extern "win64" fn imm_device_enumerator_get_device(
    _this: *mut usize,
    _pwstr_id: *const u16,
    pp_device: *mut *mut usize,
) -> i32 {
    ensure_devices_initialized();
    let devices = match lock_audio_devices(&AUDIO_DEVICES) {
        Some(g) => g,
        None => return -2147023728,
    };
    if let Some(dev) = devices.iter().find(|d| d.is_default) {
        let device = Box::new(MMDevice::new(dev.clone()));
        let ptr = Box::into_raw(device) as *mut usize;
        *(ptr as *mut *const IMMDeviceVtable) = &IMM_DEVICE_VTABLE;
        *pp_device = ptr;
        return 0;
    }
    *pp_device = std::ptr::null_mut();
    -2147023728
}

unsafe extern "win64" fn imm_device_enumerator_register_endpoint_notification_callback(
    _this: *mut usize,
    _p_client: *mut usize,
) -> i32 {
    -2147467263
}

unsafe extern "win64" fn imm_device_enumerator_unregister_endpoint_notification_callback(
    _this: *mut usize,
    _p_client: *mut usize,
) -> i32 {
    -2147467263
}

// ── Vtable statics ───────────────────────────────────────────────────────────

static IMM_DEVICE_VTABLE: IMMDeviceVtable = IMMDeviceVtable {
    parent: IUnknownVtable {
        query_interface: imm_device_query_interface,
        add_ref: imm_device_add_ref,
        release: imm_device_release,
    },
    activate: imm_device_activate,
    open_property_store: imm_device_open_property_store,
    get_id: imm_device_get_id,
    get_state: imm_device_get_state,
};

static IMM_DEVICE_ENUMERATOR_VTABLE: IMMDeviceEnumeratorVtable = IMMDeviceEnumeratorVtable {
    parent: IUnknownVtable {
        query_interface: imm_device_enumerator_query_interface,
        add_ref: imm_device_enumerator_add_ref,
        release: imm_device_enumerator_release,
    },
    enum_audio_endpoints: imm_device_enumerator_enum_audio_endpoints,
    get_default_audio_endpoint: imm_device_enumerator_get_default_audio_endpoint,
    get_device: imm_device_enumerator_get_device,
    register_endpoint_notification_callback:
        imm_device_enumerator_register_endpoint_notification_callback,
    unregister_endpoint_notification_callback:
        imm_device_enumerator_unregister_endpoint_notification_callback,
};

// ── IAudioClient COM methods ─────────────────────────────────────────────────

unsafe extern "win64" fn iaudio_client_query_interface(
    this: *mut usize,
    riid: *const u8,
    ppv_object: *mut *mut usize,
) -> i32 {
    let iid = std::slice::from_raw_parts(riid, 16);
    if iid
        == [
            0x4C, 0xAD, 0xB9, 0x1C, 0xED, 0x64, 0x38, 0x41, 0x8B, 0x7D, 0x28, 0x7E, 0x08, 0x26,
            0x2B, 0x18,
        ]
    {
        *ppv_object = this;
        iaudio_client_add_ref(this);
        return 0;
    }
    *ppv_object = std::ptr::null_mut();
    -2147467262
}

unsafe extern "win64" fn iaudio_client_add_ref(this: *mut usize) -> u32 {
    let c = &mut *(this as *mut AudioClient);
    let mut rc = c.ref_count.borrow_mut();
    *rc += 1;
    *rc
}

unsafe extern "win64" fn iaudio_client_release(this: *mut usize) -> u32 {
    let c = &mut *(this as *mut AudioClient);
    let mut rc = c.ref_count.borrow_mut();
    *rc -= 1;
    let cur = *rc;
    if cur == 0 {
        drop(Box::from_raw(this as *mut AudioClient));
    }
    cur
}

/// IAudioClient::Initialize -- set up format and ring buffer.
///
/// Vtable signature matches what was already present: five params after `this`.
unsafe extern "win64" fn iaudio_client_initialize(
    this: *mut usize,
    _share_mode: u32,
    _stream_flags: u64,
    p_format: *const WaveFormatEx,
    _audio_session_guid: *const WaveFormatEx,
) -> i32 {
    let client = &mut *(this as *mut AudioClient);
    if p_format.is_null() {
        return -2147024809; // E_INVALIDARG
    }
    let format = *p_format;

    let channels = format.n_channels as usize;
    let bytes_per_sample = (format.w_bits_per_sample as usize).div_ceil(8);
    let frame_size = channels * bytes_per_sample;

    // 100 ms buffer as seen by the app
    let buffer_frames = (format.n_samples_per_sec as f64 * 0.1) as u32;
    // 1-second ring buffer to absorb scheduling jitter
    let ring_capacity_bytes = format.n_samples_per_sec as usize * frame_size;

    client.format = Some(format);
    client.buffer_frames = buffer_frames;
    client.frame_size = frame_size;
    client.ring_buf = Arc::new(Mutex::new(RingBuf::new(ring_capacity_bytes, frame_size)));

    0
}

unsafe extern "win64" fn iaudio_client_get_buffer_size(
    this: *mut usize,
    p_num_buffer_frames: *mut u32,
) -> i32 {
    let c = &*(this as *mut AudioClient);
    *p_num_buffer_frames = c.buffer_frames;
    0
}

unsafe extern "win64" fn iaudio_client_get_stream_latency(
    _this: *mut usize,
    p_latency: *mut i64,
) -> i32 {
    *p_latency = 100_000; // 10 ms in 100-ns units
    0
}

unsafe extern "win64" fn iaudio_client_get_current_padding(
    this: *mut usize,
    p_num_padding_frames: *mut u32,
) -> i32 {
    let c = &*(this as *mut AudioClient);
    if c.frame_size == 0 {
        *p_num_padding_frames = 0;
        return 0;
    }
    let available = match lock_ring_buf(&c.ring_buf) {
        Some(g) => g.available,
        None => {
            *p_num_padding_frames = 0;
            return 0;
        }
    };
    *p_num_padding_frames = (available / c.frame_size) as u32;
    0
}

unsafe extern "win64" fn iaudio_client_is_format_supported(
    _this: *mut usize,
    _share_mode: u32,
    p_format: *const WaveFormatEx,
    _pp_closest_match: *mut *mut WaveFormatEx,
) -> i32 {
    let f = &*p_format;
    if f.w_format_tag == 1
        && (f.n_samples_per_sec == 44100 || f.n_samples_per_sec == 48000)
        && (f.w_bits_per_sample == 16 || f.w_bits_per_sample == 24 || f.w_bits_per_sample == 32)
        && f.n_channels <= 2
    {
        0
    } else {
        -2147024809
    }
}

unsafe extern "win64" fn iaudio_client_get_mix_format(
    _this: *mut usize,
    pp_device_format: *mut *mut WaveFormatEx,
) -> i32 {
    let f = Box::new(WaveFormatEx {
        w_format_tag: 1,
        n_channels: 2,
        n_samples_per_sec: 44100,
        n_avg_bytes_per_sec: 44100 * 4,
        n_block_align: 4,
        w_bits_per_sample: 16,
        cb_size: 0,
    });
    *pp_device_format = Box::into_raw(f);
    0
}

unsafe extern "win64" fn iaudio_client_get_device_period(
    _this: *mut usize,
    p_hns_default_device_period: *mut i64,
    p_hns_minimum_device_period: *mut i64,
) -> i32 {
    *p_hns_default_device_period = 100_000;
    *p_hns_minimum_device_period = 100_000;
    0
}

/// IAudioClient::Start -- begin audio playback.
///
/// On Linux: initialise PipeWire, create a ThreadLoop, build a Stream in the
/// format negotiated by Initialize, register a process callback that drains
/// the shared ring buffer into PipeWire, then start the loop.
///
/// On non-Linux: the ring buffer is still operational; audio is collected but
/// discarded (silent output).
/// TODO: connect to a platform audio backend here when porting to other OSes.
unsafe extern "win64" fn iaudio_client_start(_this: *mut usize) -> i32 {
    #[cfg(feature = "pipewire-audio")]
    {
        let this = _this;
        use pipewire as pw;
        use pw::spa;

        let client = &mut *(this as *mut AudioClient);

        // Already started.
        if client.pw_state.is_some() {
            return 0;
        }

        let format = match client.format {
            Some(f) => f,
            None => return -2147467263, // E_NOTIMPL -- not initialized
        };

        let ring_buf = Arc::clone(&client.ring_buf);
        let frame_size = client.frame_size;
        let channels = format.n_channels as u32;
        let sample_rate = format.n_samples_per_sec;

        let spa_fmt = match format.w_bits_per_sample {
            16 => spa::param::audio::AudioFormat::S16LE,
            24 => spa::param::audio::AudioFormat::S24LE,
            32 => spa::param::audio::AudioFormat::S32LE,
            _ => spa::param::audio::AudioFormat::S16LE,
        };

        // Initialize PipeWire (idempotent).
        pw::init();

        // ThreadLoop drives the PipeWire event loop on a dedicated thread.
        let thread_loop =
            match unsafe { pw::thread_loop::ThreadLoop::new(Some("weave-audio"), None) } {
                Ok(tl) => tl,
                Err(_) => return -2147023728,
            };

        // Hold the lock while we set up -- the PW thread hasn't started yet.
        let _lock = thread_loop.lock();

        let context = match pw::context::Context::new(&thread_loop) {
            Ok(c) => c,
            Err(_) => return -2147023728,
        };
        let core = match context.connect(None) {
            Ok(c) => c,
            Err(_) => return -2147023728,
        };

        let stream = match pw::stream::Stream::new(
            &core,
            "weave-audio",
            pw::properties::properties! {
                *pw::keys::MEDIA_TYPE     => "Audio",
                *pw::keys::MEDIA_ROLE     => "Music",
                *pw::keys::MEDIA_CATEGORY => "Playback",
            },
        ) {
            Ok(s) => s,
            Err(_) => return -2147023728,
        };

        // Process callback: runs on the PW thread every graph cycle.
        // Drains the ring buffer into the PipeWire output buffer.
        let listener = stream
            .add_local_listener_with_user_data(())
            .process(move |stream, _| {
                let mut buf = match stream.dequeue_buffer() {
                    Some(b) => b,
                    None => return,
                };
                let datas = buf.datas_mut();
                let d = &mut datas[0];

                // Determine total capacity from data().
                let total = match d.data() {
                    Some(slice) => slice.len(),
                    None => return,
                };

                // Fill the buffer: drain ring into the data pointer directly.
                // We use the raw pointer to avoid re-borrowing `d` after `.data()`.
                let raw_ptr = d.as_raw().data as *mut u8;
                if !raw_ptr.is_null() {
                    let dst = unsafe { std::slice::from_raw_parts_mut(raw_ptr, total) };
                    let mut ring = match lock_ring_buf(&ring_buf) {
                        Some(g) => g,
                        None => return,
                    };
                    let copied = ring.read_into(dst);
                    // Silence any un-filled portion (underrun).
                    dst[copied..].fill(0);
                }

                let chunk = d.chunk_mut();
                *chunk.offset_mut() = 0;
                *chunk.stride_mut() = frame_size as i32;
                *chunk.size_mut() = total as u32;
            })
            .register();

        let listener = match listener {
            Ok(l) => l,
            Err(_) => return -2147023728,
        };

        // Serialize the SPA format pod.
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
        .unwrap()
        .0
        .into_inner();

        let pod = match spa::pod::Pod::from_bytes(&values) {
            Some(p) => p,
            None => return -2147023728,
        };
        let mut params = [pod];

        if stream
            .connect(
                spa::utils::Direction::Output,
                None,
                pw::stream::StreamFlags::AUTOCONNECT
                    | pw::stream::StreamFlags::MAP_BUFFERS
                    | pw::stream::StreamFlags::RT_PROCESS,
                &mut params,
            )
            .is_err()
        {
            return -2147023728;
        }

        let stream_raw = stream.into_raw();

        // Erase the listener's generic parameter so we can store it in PwState.
        let listener_any: Box<dyn std::any::Any> = Box::new(listener);

        // Start the thread loop -- the PW thread begins processing.
        thread_loop.start();
        // Release the lock so the PW thread can run.
        drop(_lock);

        client.pw_state = Some(Box::new(PwState {
            thread_loop,
            stream: Some(stream_raw),
            _listener: Some(listener_any),
        }));
    }

    0
}

/// IAudioClient::Stop -- tear down the PipeWire stream.
unsafe extern "win64" fn iaudio_client_stop(_this: *mut usize) -> i32 {
    #[cfg(feature = "pipewire-audio")]
    {
        let client = &mut *(_this as *mut AudioClient);
        // Dropping PwState stops the thread loop and destroys the stream.
        client.pw_state = None;
    }
    0
}

/// IAudioClient::Reset -- flush the ring buffer.
///
/// WASAPI requires the stream to be stopped before calling Reset.
unsafe extern "win64" fn iaudio_client_reset(this: *mut usize) -> i32 {
    let client = &mut *(this as *mut AudioClient);
    if let Some(mut ring) = lock_ring_buf(&client.ring_buf) {
        ring.reset();
    }
    0
}

unsafe extern "win64" fn iaudio_client_set_event_handle(
    _this: *mut usize,
    _event_handle: usize,
) -> i32 {
    // Event-driven mode not implemented; GetCurrentPadding polling works instead.
    0
}

unsafe extern "win64" fn iaudio_client_get_service(
    this: *mut usize,
    riid: *const u8,
    ppv: *mut *mut usize,
) -> i32 {
    let client = &*(this as *mut AudioClient);
    let iid = std::slice::from_raw_parts(riid, 16);
    // IID_IAudioRenderClient: F2942B86-0D2E-4F45-8ECF-0011D00001
    if iid
        == [
            0x86, 0x2B, 0x94, 0xF2, 0x2E, 0x0D, 0x45, 0x4F, 0x8E, 0xCF, 0x00, 0x11, 0xD0, 0x00,
            0x00, 0x01,
        ]
    {
        let rc = Box::new(AudioRenderClient::new(
            Arc::clone(&client.ring_buf),
            client.frame_size,
        ));
        let ptr = Box::into_raw(rc) as *mut usize;
        *(ptr as *mut *const IAudioRenderClientVtable) = &IAUDIO_RENDER_CLIENT_VTABLE;
        *ppv = ptr;
        return 0;
    }
    *ppv = std::ptr::null_mut();
    -2147467262
}

// ── IAudioRenderClient COM methods ───────────────────────────────────────────

unsafe extern "win64" fn iaudio_render_client_query_interface(
    this: *mut usize,
    riid: *const u8,
    ppv_object: *mut *mut usize,
) -> i32 {
    let iid = std::slice::from_raw_parts(riid, 16);
    if iid
        == [
            0x86, 0x2B, 0x94, 0xF2, 0x2E, 0x0D, 0x45, 0x4F, 0x8E, 0xCF, 0x00, 0x11, 0xD0, 0x00,
            0x00, 0x01,
        ]
    {
        *ppv_object = this;
        iaudio_render_client_add_ref(this);
        return 0;
    }
    *ppv_object = std::ptr::null_mut();
    -2147467262
}

unsafe extern "win64" fn iaudio_render_client_add_ref(this: *mut usize) -> u32 {
    let c = &mut *(this as *mut AudioRenderClient);
    let mut rc = c.ref_count.borrow_mut();
    *rc += 1;
    *rc
}

unsafe extern "win64" fn iaudio_render_client_release(this: *mut usize) -> u32 {
    let c = &mut *(this as *mut AudioRenderClient);
    let mut rc = c.ref_count.borrow_mut();
    *rc -= 1;
    let cur = *rc;
    if cur == 0 {
        drop(Box::from_raw(this as *mut AudioRenderClient));
    }
    cur
}

/// IAudioRenderClient::GetBuffer
///
/// Returns a pointer to `num_frames_requested * frame_size` bytes of writable
/// scratch space.  The app fills this with PCM audio, then calls ReleaseBuffer.
unsafe extern "win64" fn iaudio_render_client_get_buffer(
    this: *mut usize,
    num_frames_requested: u32,
    pp_data: *mut *mut u8,
) -> i32 {
    let client = &mut *(this as *mut AudioRenderClient);
    let needed = num_frames_requested as usize * client.frame_size;
    // Resize scratch buffer (zero = silence on a partial write).
    client.write_buf.resize(needed, 0);
    *pp_data = client.write_buf.as_mut_ptr();
    0
}

/// IAudioRenderClient::ReleaseBuffer
///
/// Copies the audio data written since the last GetBuffer into the ring buffer.
/// On Linux the PipeWire process callback drains the ring buffer each graph cycle.
unsafe extern "win64" fn iaudio_render_client_release_buffer(
    this: *mut usize,
    num_frames_written: u32,
    dw_flags: u32,
) -> i32 {
    let client = &mut *(this as *mut AudioRenderClient);
    if num_frames_written == 0 {
        return 0;
    }

    const AUDCLNT_BUFFERFLAGS_SILENT: u32 = 0x0000_0002;
    let bytes = num_frames_written as usize * client.frame_size;

    let mut ring = match lock_ring_buf(&client.ring_buf) {
        Some(g) => g,
        None => return 0,
    };
    let dst_ptr = match ring.write_ptr_mut(num_frames_written as usize) {
        Some(p) => p,
        None => return 0,
    };

    if dw_flags & AUDCLNT_BUFFERFLAGS_SILENT != 0 {
        // App signalled silence: zero the ring buffer region.
        std::ptr::write_bytes(dst_ptr, 0, bytes);
    } else {
        // Copy from scratch buffer.
        let src_len = bytes.min(client.write_buf.len());
        std::ptr::copy_nonoverlapping(client.write_buf.as_ptr(), dst_ptr, src_len);
        // Silence any remainder if write buffer was shorter than expected.
        if src_len < bytes {
            std::ptr::write_bytes(dst_ptr.add(src_len), 0, bytes - src_len);
        }
    }

    ring.commit_write(num_frames_written as usize);
    0
}

static IAUDIO_CLIENT_VTABLE: IAudioClientVtable = IAudioClientVtable {
    parent: IUnknownVtable {
        query_interface: iaudio_client_query_interface,
        add_ref: iaudio_client_add_ref,
        release: iaudio_client_release,
    },
    initialize: iaudio_client_initialize,
    get_buffer_size: iaudio_client_get_buffer_size,
    get_stream_latency: iaudio_client_get_stream_latency,
    get_current_padding: iaudio_client_get_current_padding,
    is_format_supported: iaudio_client_is_format_supported,
    get_mix_format: iaudio_client_get_mix_format,
    get_device_period: iaudio_client_get_device_period,
    start: iaudio_client_start,
    stop: iaudio_client_stop,
    reset: iaudio_client_reset,
    set_event_handle: iaudio_client_set_event_handle,
    get_service: iaudio_client_get_service,
};

static IAUDIO_RENDER_CLIENT_VTABLE: IAudioRenderClientVtable = IAudioRenderClientVtable {
    parent: IUnknownVtable {
        query_interface: iaudio_render_client_query_interface,
        add_ref: iaudio_render_client_add_ref,
        release: iaudio_render_client_release,
    },
    get_buffer: iaudio_render_client_get_buffer,
    release_buffer: iaudio_render_client_release_buffer,
};

// ── DLL Exports ──────────────────────────────────────────────────────────────

/// CoCreateInstance for CLSID_MMDeviceEnumerator -- main WASAPI entry point.
///
/// # Safety
/// `rclsid` must point to a valid 16-byte CLSID. `ppv` must be a valid
/// non-null pointer to a location that can receive a COM interface pointer.
pub unsafe extern "win64" fn co_create_instance(
    rclsid: *const u8,
    _p_unk_outer: usize,
    _dw_cls_context: u32,
    _riid: *const u8,
    ppv: *mut *mut usize,
) -> i32 {
    // CLSID_MMDeviceEnumerator: BCDE0395-E52F-467C-8E3D-C4579291692E
    let clsid = unsafe { std::slice::from_raw_parts(rclsid, 16) };
    if clsid
        == [
            0x95, 0x03, 0xDE, 0xBC, 0x2F, 0xE5, 0x7C, 0x46, 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91,
            0x69, 0x2E,
        ]
    {
        ensure_devices_initialized();
        let e = Box::new(MMDeviceEnumerator::new());
        let ptr = Box::into_raw(e) as *mut usize;
        unsafe {
            *(ptr as *mut *const IMMDeviceEnumeratorVtable) = &IMM_DEVICE_ENUMERATOR_VTABLE;
            *ppv = ptr;
        }
        return 0;
    }
    unsafe { *ppv = std::ptr::null_mut() };
    -2147221231 // CLASS_E_CLASSNOTAVAILABLE
}

/// Resolve an mmdevapi.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("mmdevapi.dll") {
        return None;
    }
    match func {
        "CoCreateInstance" => Some(co_create_instance as *const () as usize),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_functions_returns_some() {
        assert!(resolve("mmdevapi.dll", "CoCreateInstance").is_some());
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("kernel32.dll", "CoCreateInstance").is_none());
    }

    #[test]
    fn resolve_unknown_function_returns_none() {
        assert!(resolve("mmdevapi.dll", "__weave_nonexistent__").is_none());
    }

    #[cfg(feature = "pipewire-audio")]
    #[test]
    fn ring_buf_write_read_roundtrip() {
        let mut rb = RingBuf::new(4096, 4);
        {
            let ptr = rb.write_ptr_mut(8).unwrap();
            for i in 0..32usize {
                unsafe { *ptr.add(i) = i as u8 };
            }
        }
        rb.commit_write(8);
        assert_eq!(rb.available, 32);

        let mut dst = vec![0u8; 32];
        let copied = rb.read_into(&mut dst);
        assert_eq!(copied, 32);
        for (i, &b) in dst.iter().enumerate() {
            assert_eq!(b, i as u8, "byte {i} mismatch");
        }
        assert_eq!(rb.available, 0);
    }

    #[test]
    fn ring_buf_reset_clears_data() {
        let mut rb = RingBuf::new(64, 4);
        let ptr = rb.write_ptr_mut(4).unwrap();
        unsafe { std::ptr::write_bytes(ptr, 0xFF, 16) };
        rb.commit_write(4);
        rb.reset();
        assert_eq!(rb.available, 0);
        assert!(rb.data.iter().all(|&b| b == 0));
    }
}
