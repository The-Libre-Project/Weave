//! mmdevapi.dll stubs for Weave.
//!
//! Implements WASAPI (Windows Audio Session API) backed by PipeWire.
//! Also provides DirectSound as a thin layer on top of WASAPI.

#![allow(non_snake_case)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;

// Audio device state
#[derive(Debug, Clone)]
struct AudioDevice {
    id: String,
    name: String,
    is_default: bool,
}

// Global device list
static AUDIO_DEVICES: Mutex<Vec<AudioDevice>> = Mutex::new(Vec::new());

fn init_pipewire() -> Result<(), Box<dyn std::error::Error>> {
    // TODO(Step 4): Connect to PipeWire here on Linux.
    // All PipeWire code must be in #[cfg(target_os = "linux")] blocks.
    let mut devices = AUDIO_DEVICES.lock().unwrap();
    if devices.is_empty() {
        devices.push(AudioDevice {
            id: "default".to_string(),
            name: "Default Audio Device".to_string(),
            is_default: true,
        });
    }
    Ok(())
}

// ── Windows Audio Structures ─────────────────────────────────────────────

// WAVEFORMATEX structure
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

// AUDCLNT_SHAREMODE
pub const AUDCLNT_SHAREMODE_SHARED: u32 = 0;
pub const AUDCLNT_SHAREMODE_EXCLUSIVE: u32 = 1;

// AUDCLNT_STREAMFLAGS
pub const AUDCLNT_STREAMFLAGS_EVENTCALLBACK: u32 = 0x00040000;
pub const AUDCLNT_STREAMFLAGS_LOOPBACK: u32 = 0x00020000;
pub const AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM: u32 = 0x80000000;
pub const AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY: u32 = 0x08000000;

// ── COM Interfaces ──────────────────────────────────────────────────────

// IUnknown vtable
#[repr(C)]
pub struct IUnknownVtable {
    pub query_interface: unsafe extern "win64" fn(*mut usize, *const u8, *mut *mut usize) -> i32,
    pub add_ref: unsafe extern "win64" fn(*mut usize) -> u32,
    pub release: unsafe extern "win64" fn(*mut usize) -> u32,
}

// IMMDevice vtable (inherits from IUnknown)
#[repr(C)]
pub struct IMMDeviceVtable {
    pub parent: IUnknownVtable,
    pub activate: unsafe extern "win64" fn(*mut usize, *const u8, u32, *const usize, *mut *mut usize) -> i32,
    pub open_property_store: unsafe extern "win64" fn(*mut usize, u32, *mut *mut usize) -> i32,
    pub get_id: unsafe extern "win64" fn(*mut usize, *mut *mut u16) -> i32,
    pub get_state: unsafe extern "win64" fn(*mut usize, *mut u32) -> i32,
}

// IMMDeviceEnumerator vtable (inherits from IUnknown)
#[repr(C)]
pub struct IMMDeviceEnumeratorVtable {
    pub parent: IUnknownVtable,
    pub enum_audio_endpoints: unsafe extern "win64" fn(*mut usize, u32, u32, *mut *mut usize) -> i32,
    pub get_default_audio_endpoint: unsafe extern "win64" fn(*mut usize, u32, u32, *mut *mut usize) -> i32,
    pub get_device: unsafe extern "win64" fn(*mut usize, *const u16, *mut *mut usize) -> i32,
    pub register_endpoint_notification_callback: unsafe extern "win64" fn(*mut usize, *mut usize) -> i32,
    pub unregister_endpoint_notification_callback: unsafe extern "win64" fn(*mut usize, *mut usize) -> i32,
}

// IAudioClient vtable (inherits from IUnknown)
#[repr(C)]
pub struct IAudioClientVtable {
    pub parent: IUnknownVtable,
    pub initialize: unsafe extern "win64" fn(*mut usize, u32, u64, *const WaveFormatEx, *const WaveFormatEx) -> i32,
    pub get_buffer_size: unsafe extern "win64" fn(*mut usize, *mut u32) -> i32,
    pub get_stream_latency: unsafe extern "win64" fn(*mut usize, *mut i64) -> i32,
    pub get_current_padding: unsafe extern "win64" fn(*mut usize, *mut u32) -> i32,
    pub is_format_supported: unsafe extern "win64" fn(*mut usize, u32, *const WaveFormatEx, *mut *mut WaveFormatEx) -> i32,
    pub get_mix_format: unsafe extern "win64" fn(*mut usize, *mut *mut WaveFormatEx) -> i32,
    pub get_device_period: unsafe extern "win64" fn(*mut usize, *mut i64, *mut i64) -> i32,
    pub start: unsafe extern "win64" fn(*mut usize) -> i32,
    pub stop: unsafe extern "win64" fn(*mut usize) -> i32,
    pub reset: unsafe extern "win64" fn(*mut usize) -> i32,
    pub set_event_handle: unsafe extern "win64" fn(*mut usize, usize) -> i32,
    pub get_service: unsafe extern "win64" fn(*mut usize, *const u8, *mut *mut usize) -> i32,
}

// IAudioRenderClient vtable (inherits from IUnknown)
#[repr(C)]
pub struct IAudioRenderClientVtable {
    pub parent: IUnknownVtable,
    pub get_buffer: unsafe extern "win64" fn(*mut usize, u32, *mut *mut u8) -> i32,
    pub release_buffer: unsafe extern "win64" fn(*mut usize, u32, u32) -> i32,
}

// ── COM Interface Implementations ───────────────────────────────────────

// IMMDevice implementation
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

// IMMDeviceEnumerator implementation
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

// IAudioClient implementation
struct AudioClient {
    device_id: String,
    format: Option<WaveFormatEx>,
    buffer_size: u32,
    ref_count: RefCell<u32>,
}

impl AudioClient {
    fn new(device_id: String) -> Self {
        Self {
            device_id,
            format: None,
            buffer_size: 0,
            ref_count: RefCell::new(1),
        }
    }
}

// IAudioRenderClient implementation
struct AudioRenderClient {
    ref_count: RefCell<u32>,
}

impl AudioRenderClient {
    fn new() -> Self {
        Self {
            ref_count: RefCell::new(1),
        }
    }
}

// ── COM Method Implementations ──────────────────────────────────────────

// IUnknown for IMMDevice
unsafe extern "win64" fn imm_device_query_interface(
    this: *mut usize,
    riid: *const u8,
    ppv_object: *mut *mut usize,
) -> i32 {
    // Simplified - just return E_NOINTERFACE for now
    *ppv_object = std::ptr::null_mut();
    -2147467262 // E_NOINTERFACE
}

unsafe extern "win64" fn imm_device_add_ref(this: *mut usize) -> u32 {
    let device = &mut *(this as *mut MMDevice);
    let mut ref_count = device.ref_count.borrow_mut();
    *ref_count += 1;
    *ref_count
}

unsafe extern "win64" fn imm_device_release(this: *mut usize) -> u32 {
    let device = &mut *(this as *mut MMDevice);
    let mut ref_count = device.ref_count.borrow_mut();
    *ref_count -= 1;
    let current = *ref_count;
    if current == 0 {
        // Free the device
        drop(Box::from_raw(this as *mut MMDevice));
    }
    current
}

unsafe extern "win64" fn imm_device_activate(
    this: *mut usize,
    iid: *const u8,
    _dw_cls_ctx: u32,
    _p_activation_params: *const usize,
    pp_interface: *mut *mut usize,
) -> i32 {
    let device = &*(this as *mut MMDevice);

    // Check if requesting IAudioClient interface
    let requested_iid = std::slice::from_raw_parts(iid, 16);
    // IID_IAudioClient: 1CB9AD4C-64ED-4138-8B7D-287E08262B18
    if requested_iid == [0x4C, 0xAD, 0xB9, 0x1C, 0xED, 0x64, 0x38, 0x41, 0x8B, 0x7D, 0x28, 0x7E, 0x08, 0x26, 0x2B, 0x18] {
        let audio_client = Box::new(AudioClient::new(device.device.id.clone()));
        let client_ptr = Box::into_raw(audio_client) as *mut usize;

        // Set the vtable pointer
        unsafe {
            *(client_ptr as *mut *const IAudioClientVtable) = &IAUDIO_CLIENT_VTABLE;
        }

        *pp_interface = client_ptr;
        return 0; // S_OK
    }

    *pp_interface = std::ptr::null_mut();
    -2147467262 // E_NOINTERFACE
}

unsafe extern "win64" fn imm_device_open_property_store(
    _this: *mut usize,
    _stgm_access: u32,
    _pp_properties: *mut *mut usize,
) -> i32 {
    -2147467263 // E_NOTIMPL
}

unsafe extern "win64" fn imm_device_get_id(
    this: *mut usize,
    ppstr_id: *mut *mut u16,
) -> i32 {
    let device = &*(this as *mut MMDevice);
    // Convert device ID to UTF-16
    let wide_id: Vec<u16> = device.device.id.encode_utf16().chain(std::iter::once(0)).collect();
    let ptr = wide_id.as_ptr() as *mut u16;
    std::mem::forget(wide_id); // Leak the string for now
    *ppstr_id = ptr;
    0 // S_OK
}

unsafe extern "win64" fn imm_device_get_state(
    _this: *mut usize,
    _pdw_state: *mut u32,
) -> i32 {
    -2147467263 // E_NOTIMPL
}

// IMMDeviceEnumerator methods
unsafe extern "win64" fn imm_device_enumerator_query_interface(
    this: *mut usize,
    riid: *const u8,
    ppv_object: *mut *mut usize,
) -> i32 {
    // Check if requesting IMMDeviceEnumerator interface
    let iid = std::slice::from_raw_parts(riid, 16);
    // IID_IMMDeviceEnumerator: A95664D2-9614-4F35-A746-DE8DB63617E6
    if iid == [0xD2, 0x64, 0x56, 0xA9, 0x14, 0x96, 0x35, 0x4F, 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6] {
        *ppv_object = this;
        imm_device_enumerator_add_ref(this);
        return 0; // S_OK
    }
    *ppv_object = std::ptr::null_mut();
    -2147467262 // E_NOINTERFACE
}

unsafe extern "win64" fn imm_device_enumerator_add_ref(this: *mut usize) -> u32 {
    let enumerator = &mut *(this as *mut MMDeviceEnumerator);
    let mut ref_count = enumerator.ref_count.borrow_mut();
    *ref_count += 1;
    *ref_count
}

unsafe extern "win64" fn imm_device_enumerator_release(this: *mut usize) -> u32 {
    let enumerator = &mut *(this as *mut MMDeviceEnumerator);
    let mut ref_count = enumerator.ref_count.borrow_mut();
    *ref_count -= 1;
    let current = *ref_count;
    if current == 0 {
        drop(Box::from_raw(this as *mut MMDeviceEnumerator));
    }
    current
}

unsafe extern "win64" fn imm_device_enumerator_enum_audio_endpoints(
    _this: *mut usize,
    _data_flow: u32,
    _dw_state_mask: u32,
    _pp_devices: *mut *mut usize,
) -> i32 {
    -2147467263 // E_NOTIMPL
}

unsafe extern "win64" fn imm_device_enumerator_get_default_audio_endpoint(
    _this: *mut usize,
    _data_flow: u32,
    _role: u32,
    pp_endpoint: *mut *mut usize,
) -> i32 {
    // Return the default device
    let devices = AUDIO_DEVICES.lock().unwrap();
    if let Some(default_device) = devices.iter().find(|d| d.is_default) {
        let device = Box::new(MMDevice::new(default_device.clone()));
        *pp_endpoint = Box::into_raw(device) as *mut usize;
        return 0; // S_OK
    }
    *pp_endpoint = std::ptr::null_mut();
    -2147023728 // E_FAIL
}

unsafe extern "win64" fn imm_device_enumerator_get_device(
    _this: *mut usize,
    _pwstr_id: *const u16,
    pp_device: *mut *mut usize,
) -> i32 {
    // Return the default device for now
    let devices = AUDIO_DEVICES.lock().unwrap();
    if let Some(default_device) = devices.iter().find(|d| d.is_default) {
        let device = Box::new(MMDevice::new(default_device.clone()));
        *pp_device = Box::into_raw(device) as *mut usize;
        return 0; // S_OK
    }
    *pp_device = std::ptr::null_mut();
    -2147023728 // E_FAIL
}

unsafe extern "win64" fn imm_device_enumerator_register_endpoint_notification_callback(
    _this: *mut usize,
    _p_client: *mut usize,
) -> i32 {
    -2147467263 // E_NOTIMPL
}

unsafe extern "win64" fn imm_device_enumerator_unregister_endpoint_notification_callback(
    _this: *mut usize,
    _p_client: *mut usize,
) -> i32 {
    -2147467263 // E_NOTIMPL
}

// ── Vtable Definitions ──────────────────────────────────────────────────

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
    register_endpoint_notification_callback: imm_device_enumerator_register_endpoint_notification_callback,
    unregister_endpoint_notification_callback: imm_device_enumerator_unregister_endpoint_notification_callback,
};

// IAudioClient methods
unsafe extern "win64" fn iaudio_client_query_interface(
    this: *mut usize,
    riid: *const u8,
    ppv_object: *mut *mut usize,
) -> i32 {
    // Check if requesting IAudioClient interface
    let iid = std::slice::from_raw_parts(riid, 16);
    // IID_IAudioClient: 1CB9AD4C-64ED-4138-8B7D-287E08262B18
    if iid == [0x4C, 0xAD, 0xB9, 0x1C, 0xED, 0x64, 0x38, 0x41, 0x8B, 0x7D, 0x28, 0x7E, 0x08, 0x26, 0x2B, 0x18] {
        *ppv_object = this;
        iaudio_client_add_ref(this);
        return 0; // S_OK
    }
    *ppv_object = std::ptr::null_mut();
    -2147467262 // E_NOINTERFACE
}

unsafe extern "win64" fn iaudio_client_add_ref(this: *mut usize) -> u32 {
    let client = &mut *(this as *mut AudioClient);
    let mut ref_count = client.ref_count.borrow_mut();
    *ref_count += 1;
    *ref_count
}

unsafe extern "win64" fn iaudio_client_release(this: *mut usize) -> u32 {
    let client = &mut *(this as *mut AudioClient);
    let mut ref_count = client.ref_count.borrow_mut();
    *ref_count -= 1;
    let current = *ref_count;
    if current == 0 {
        drop(Box::from_raw(this as *mut AudioClient));
    }
    current
}

unsafe extern "win64" fn iaudio_client_initialize(
    this: *mut usize,
    _share_mode: u32,
    _stream_flags: u64,
    p_format: *const WaveFormatEx,
    _p_audio_session_guid: *const WaveFormatEx,
) -> i32 {
    let client = &mut *(this as *mut AudioClient);
    if !p_format.is_null() {
        let format = *p_format;
        // Calculate buffer size: 100ms worth of audio frames.
        let buffer_size = format.n_samples_per_sec / 10;
        client.format = Some(format);
        client.buffer_size = buffer_size;
    }
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_get_buffer_size(
    this: *mut usize,
    p_num_buffer_frames: *mut u32,
) -> i32 {
    let client = &*(this as *mut AudioClient);
    *p_num_buffer_frames = client.buffer_size;
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_get_stream_latency(
    _this: *mut usize,
    p_latency: *mut i64,
) -> i32 {
    *p_latency = 100000; // 10ms in 100ns units
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_get_current_padding(
    _this: *mut usize,
    p_num_padding_frames: *mut u32,
) -> i32 {
    *p_num_padding_frames = 0; // No padding for now
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_is_format_supported(
    _this: *mut usize,
    _share_mode: u32,
    p_format: *const WaveFormatEx,
    _pp_closest_match: *mut *mut WaveFormatEx,
) -> i32 {
    // Accept common formats
    let format = &*p_format;
    if format.w_format_tag == 1 && // WAVE_FORMAT_PCM
       (format.n_samples_per_sec == 44100 || format.n_samples_per_sec == 48000) &&
       (format.w_bits_per_sample == 16 || format.w_bits_per_sample == 24 || format.w_bits_per_sample == 32) &&
       format.n_channels <= 2 {
        0 // S_OK
    } else {
        -2147024809 // E_FAIL
    }
}

unsafe extern "win64" fn iaudio_client_get_mix_format(
    _this: *mut usize,
    pp_device_format: *mut *mut WaveFormatEx,
) -> i32 {
    // Return 44.1kHz, 16-bit, stereo
    let format = Box::new(WaveFormatEx {
        w_format_tag: 1, // WAVE_FORMAT_PCM
        n_channels: 2,
        n_samples_per_sec: 44100,
        n_avg_bytes_per_sec: 44100 * 2 * 2, // 44100 * channels * bytes_per_sample
        n_block_align: 4, // channels * bytes_per_sample
        w_bits_per_sample: 16,
        cb_size: 0,
    });
    *pp_device_format = Box::into_raw(format);
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_get_device_period(
    _this: *mut usize,
    p_hns_default_device_period: *mut i64,
    p_hns_minimum_device_period: *mut i64,
) -> i32 {
    *p_hns_default_device_period = 100000; // 10ms in 100ns units
    *p_hns_minimum_device_period = 100000; // 10ms minimum
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_start(_this: *mut usize) -> i32 {
    // In real implementation: start PipeWire stream
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_stop(_this: *mut usize) -> i32 {
    // In real implementation: stop PipeWire stream
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_reset(_this: *mut usize) -> i32 {
    // In real implementation: flush PipeWire buffers
    0 // S_OK
}

unsafe extern "win64" fn iaudio_client_set_event_handle(
    _this: *mut usize,
    _event_handle: usize,
) -> i32 {
    0 // S_OK - ignore for now
}

unsafe extern "win64" fn iaudio_client_get_service(
    this: *mut usize,
    riid: *const u8,
    ppv: *mut *mut usize,
) -> i32 {
    // Check if requesting IAudioRenderClient interface
    let requested_iid = std::slice::from_raw_parts(riid, 16);
    // IID_IAudioRenderClient: F2942B86-0D2E-4F45-8ECF-0011D00001
    if requested_iid == [0x86, 0x2B, 0x94, 0xF2, 0x2E, 0x0D, 0x45, 0x4F, 0x8E, 0xCF, 0x00, 0x11, 0xD0, 0x00, 0x00, 0x01] {
        let render_client = Box::new(AudioRenderClient::new());
        let client_ptr = Box::into_raw(render_client) as *mut usize;

        // Set the vtable pointer
        unsafe {
            *(client_ptr as *mut *const IAudioRenderClientVtable) = &IAUDIO_RENDER_CLIENT_VTABLE;
        }

        *ppv = client_ptr;
        return 0; // S_OK
    }

    *ppv = std::ptr::null_mut();
    -2147467262 // E_NOINTERFACE
}

// IAudioRenderClient methods
unsafe extern "win64" fn iaudio_render_client_query_interface(
    this: *mut usize,
    riid: *const u8,
    ppv_object: *mut *mut usize,
) -> i32 {
    // Check if requesting IAudioRenderClient interface
    let iid = std::slice::from_raw_parts(riid, 16);
    // IID_IAudioRenderClient: F2942B86-0D2E-4F45-8ECF-0011D00001
    if iid == [0x86, 0x2B, 0x94, 0xF2, 0x2E, 0x0D, 0x45, 0x4F, 0x8E, 0xCF, 0x00, 0x11, 0xD0, 0x00, 0x00, 0x01] {
        *ppv_object = this;
        iaudio_render_client_add_ref(this);
        return 0; // S_OK
    }
    *ppv_object = std::ptr::null_mut();
    -2147467262 // E_NOINTERFACE
}

unsafe extern "win64" fn iaudio_render_client_add_ref(this: *mut usize) -> u32 {
    let client = &mut *(this as *mut AudioRenderClient);
    let mut ref_count = client.ref_count.borrow_mut();
    *ref_count += 1;
    *ref_count
}

unsafe extern "win64" fn iaudio_render_client_release(this: *mut usize) -> u32 {
    let client = &mut *(this as *mut AudioRenderClient);
    let mut ref_count = client.ref_count.borrow_mut();
    *ref_count -= 1;
    let current = *ref_count;
    if current == 0 {
        drop(Box::from_raw(this as *mut AudioRenderClient));
    }
    current
}

unsafe extern "win64" fn iaudio_render_client_get_buffer(
    _this: *mut usize,
    _num_frames_requested: u32,
    pp_data: *mut *mut u8,
) -> i32 {
    // In real implementation: get buffer from PipeWire
    // For now, return a dummy buffer
    static mut DUMMY_BUFFER: [u8; 4096] = [0; 4096];
    *pp_data = DUMMY_BUFFER.as_mut_ptr();
    0 // S_OK
}

unsafe extern "win64" fn iaudio_render_client_release_buffer(
    _this: *mut usize,
    _num_frames_written: u32,
    _dw_flags: u32,
) -> i32 {
    // In real implementation: commit buffer to PipeWire
    0 // S_OK
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

// ── DLL Exports ─────────────────────────────────────────────────────────

/// CoCreateInstance for CLSID_MMDeviceEnumerator
///
/// This is the main entry point for WASAPI audio.
pub unsafe extern "win64" fn co_create_instance(
    rclsid: *const u8,
    _p_unk_outer: usize,
    _dw_cls_context: u32,
    _riid: *const u8,
    ppv: *mut *mut usize,
) -> i32 {
    if ppv.is_null() {
        return -2147024809i32; // E_INVALIDARG
    }

    // Check CLSID_MMDeviceEnumerator: BCDE0395-E52F-467C-8E3D-C4579291692E
    if !rclsid.is_null() {
        let clsid = std::slice::from_raw_parts(rclsid, 16);
        if clsid == [0x95, 0x03, 0xDE, 0xBC, 0x2F, 0xE5, 0x7C, 0x46, 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E] {
            let _ = init_pipewire(); // best-effort; failure is non-fatal

            let enumerator = Box::new(MMDeviceEnumerator::new());
            let enumerator_ptr = Box::into_raw(enumerator) as *mut usize;
            *(enumerator_ptr as *mut *const IMMDeviceEnumeratorVtable) = &IMM_DEVICE_ENUMERATOR_VTABLE;

            *ppv = enumerator_ptr;
            return 0; // S_OK
        }
    }

    *ppv = std::ptr::null_mut();
    -2147221231i32 // CLASS_E_CLASSNOTAVAILABLE
}

/// Resolve an mmdevapi.dll import to a stub address.
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
}
