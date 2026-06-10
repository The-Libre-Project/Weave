//! vulkan-1.dll shim for Weave.
//!
//! Intercepts Vulkan imports from Windows PE binaries and forwards them to
//! the native Linux Vulkan loader (`libvulkan.so.1`).
//!
//! # Surface mapping
//!
//! Windows Vulkan apps create surfaces via `vkCreateWin32SurfaceKHR`, passing
//! an HWND. We translate this to `vkCreateXcbSurfaceKHR` by:
//!   1. Looking up the XCB window ID for the HWND via `weave_user32::window::xcb_id`.
//!   2. Obtaining a raw XCB connection via `dlopen("libxcb.so.1")` + `xcb_connect`.
//!
//! # Crate boundary note
//!
//! `weave-vulkan` depends on `weave-user32` — a sibling DLL crate. This is a
//! documented exception to the "DLL crates must not import sibling DLL crates"
//! rule, mirroring the gdi32 → user32 and comctl32 → user32 exceptions.
//!
//! Rationale: Vulkan surface creation requires translating an HWND to an
//! `xcb_window_t`. The HWND → XCB window mapping is owned by `weave_user32::window`
//! (the registry built when `CreateWindowExW` allocates the XCB window). There is
//! no clean way to extract this mapping into `weave-common` — `weave-user32::window`
//! owns the full XCB connection lifecycle, the X11 atom cache, the window-procedure
//! table, and the event-loop dispatch. Pulling out only the HWND → xcb_window_t
//! lookup would either hollow `weave-user32` (move the table to common, break
//! encapsulation) or create a circular dependency (common needs window types that
//! reference user32's WindowEntry).
//!
//! Surface evaluated 2026-05-27. Single import: `weave_user32::window::xcb_id`.
//! Do not add further DLL → DLL imports without a similar written justification.
//!
//! # Calling conventions
//!
//! The Windows PE guest calls our stubs using the Windows x64 (MS ABI) calling
//! convention. We declare all exported stubs `extern "win64"`. The real Linux
//! Vulkan functions use System V AMD64 ABI (`extern "C"`). Rust emits the
//! correct register-shuffling glue between the two for each wrapper.

#![allow(non_snake_case)]
// Internal Vulkan structs appear in extern "win64" signatures but are only
// ever accessed via raw pointer from the guest — pub visibility is intentional.
#![allow(private_interfaces)]
// dlsym transmutes are inherently untyped; we verify the symbols by name.
#![allow(clippy::missing_transmute_annotations)]
// b"...\0" vs c"" — manual null bytes are fine; the c"" change is cosmetic.
#![allow(clippy::manual_c_str_literals)]
// Safety docs on Vulkan shim functions: callers are Windows PE binaries via IAT,
// not Rust callers, so rustdoc safety sections add no value here.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    OnceLock,
};

// ── Vulkan type aliases ───────────────────────────────────────────────────────

#[allow(non_camel_case_types)]
type PFN_vkVoidFunction = *const c_void;

type VkResult = i32;
type VkInstance = *mut c_void;
type VkPhysicalDevice = *mut c_void;
type VkDevice = *mut c_void;
type VkQueue = *mut c_void;
type VkCommandBuffer = *mut c_void;
type VkSurfaceKHR = u64;
type VkSwapchainKHR = u64;
type VkCommandPool = u64;
type VkRenderPass = u64;
type VkFramebuffer = u64;
type VkPipeline = u64;
type VkPipelineLayout = u64;
type VkPipelineCache = u64;
type VkShaderModule = u64;
type VkDescriptorSetLayout = u64;
type VkDescriptorPool = u64;
type VkDescriptorSet = u64;
type VkDescriptorUpdateTemplate = u64;
type VkBuffer = u64;
type VkImage = u64;
type VkImageView = u64;
type VkBufferView = u64;
type VkDeviceMemory = u64;
type VkSampler = u64;
type VkFence = u64;
type VkSemaphore = u64;
type VkEvent = u64;
type VkQueryPool = u64;
type VkDeviceSize = u64;
type VkDeviceAddress = u64;
type VkMemoryMapFlags = u32;
type VkQueryResultFlags = u32;
type VkPipelineBindPoint = u32;
type VkSubpassContents = u32;
type VkPipelineStageFlags = u32;
type VkIndexType = u32;
type VkStencilFaceFlags = u32;
type VkCommandBufferResetFlags = u32;
type VkCommandPoolResetFlags = u32;
type VkDescriptorPoolResetFlags = u32;
type VkShaderStageFlags = u32;
type VkFormat = u32;

const VK_SUCCESS: VkResult = 0;
const VK_ERROR_FEATURE_NOT_PRESENT: VkResult = -8;
const VK_ERROR_EXTENSION_NOT_PRESENT: VkResult = -7;

const VK_STRUCTURE_TYPE_XCB_SURFACE_CREATE_INFO_KHR: u32 = 1_000_005_000;

const EXT_WIN32_SURFACE: &[u8] = b"VK_KHR_win32_surface\0";
const EXT_XCB_SURFACE: &[u8] = b"VK_KHR_xcb_surface\0";

static D3D9_TRACE_ENABLED: OnceLock<bool> = OnceLock::new();
static D3D9_TRACE_START: OnceLock<std::time::Instant> = OnceLock::new();
static D3D9_SUBMIT_COUNT: AtomicU64 = AtomicU64::new(0);
static D3D9_PRESENT_COUNT: AtomicU64 = AtomicU64::new(0);
static D3D9_DRAW_COUNT: AtomicU64 = AtomicU64::new(0);
static D3D9_CLEAR_COUNT: AtomicU64 = AtomicU64::new(0);
static D3D9_UPLOAD_COUNT: AtomicU64 = AtomicU64::new(0);
static D3D9_BEGIN_RENDERING_LOGGED: AtomicBool = AtomicBool::new(false);
static D3D9_BEGIN_RENDERING_COUNT: AtomicU64 = AtomicU64::new(0);
static D3D9_CLEAR_TRACE: OnceLock<bool> = OnceLock::new();
static D3D9_SURFACE_XCB: AtomicU32 = AtomicU32::new(0);
static D3D9_LAST_DEVICE: AtomicU64 = AtomicU64::new(0);
static D3D9_SWAP_W: AtomicU32 = AtomicU32::new(0);
static D3D9_SWAP_H: AtomicU32 = AtomicU32::new(0);
static D3D9_BACKBUFFER_DUMP: OnceLock<bool> = OnceLock::new();
static D3D9_BLIT_TRACE: OnceLock<bool> = OnceLock::new();
static D3D9_BARRIER_TRACE: OnceLock<bool> = OnceLock::new();
static D3D9_DESC_TRACE: OnceLock<bool> = OnceLock::new();
static D3D9_PRESENT_SOURCE_TRACE: OnceLock<bool> = OnceLock::new();
static D3D9_DESC_LAST_BIND_SET: AtomicU64 = AtomicU64::new(0);
static D3D9_DESC_LAST_BIND_LAYOUT: AtomicU64 = AtomicU64::new(0);
static D3D9_DESC_LAST_UPDATE_IMAGEVIEW: AtomicU64 = AtomicU64::new(0);
static D3D9_DESC_LAST_UPDATE_SAMPLER: AtomicU64 = AtomicU64::new(0);
static D3D9_DESC_LAST_UPDATE_BINDING: AtomicU32 = AtomicU32::new(0);

fn d3d9_blit_trace_enabled() -> bool {
    *D3D9_BLIT_TRACE.get_or_init(|| {
        std::env::var("WEAVE_D3D9_BLIT_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

fn d3d9_barrier_trace_enabled() -> bool {
    *D3D9_BARRIER_TRACE.get_or_init(|| {
        std::env::var("WEAVE_D3D9_BARRIER_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

fn d3d9_desc_trace_enabled() -> bool {
    *D3D9_DESC_TRACE.get_or_init(|| {
        std::env::var("WEAVE_D3D9_DESC_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

fn d3d9_present_source_trace_enabled() -> bool {
    *D3D9_PRESENT_SOURCE_TRACE.get_or_init(|| {
        std::env::var("WEAVE_D3D9_PRESENT_SOURCE_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Parse one VkWriteDescriptorSet (64 B, 64-bit) and log image/sampler bindings.
///
/// # Safety
/// `p_write` must point at a valid `VkWriteDescriptorSet` when image info is present.
unsafe fn d3d9_desc_log_write(p_write: *const u8, write_idx: u32) {
    if p_write.is_null() {
        return;
    }
    let dst_binding = unsafe { (p_write.add(24) as *const u32).read() };
    let dst_array = unsafe { (p_write.add(28) as *const u32).read() };
    let desc_count = unsafe { (p_write.add(32) as *const u32).read() };
    let desc_type = unsafe { (p_write.add(36) as *const u32).read() };
    let p_image_info = unsafe { (p_write.add(40) as *const *const u8).read() };
    if p_image_info.is_null() {
        return;
    }
    let presents = D3D9_PRESENT_COUNT.load(Ordering::Relaxed);
    let t = d3d9_trace_ms();
    for j in 0..desc_count.min(4) {
        let info = unsafe { p_image_info.add(j as usize * 24) };
        let sampler = unsafe { (info.add(0) as *const u64).read() };
        let image_view = unsafe { (info.add(8) as *const u64).read() };
        let layout = unsafe { (info.add(16) as *const u32).read() };
        D3D9_DESC_LAST_UPDATE_SAMPLER.store(sampler, Ordering::Relaxed);
        D3D9_DESC_LAST_UPDATE_IMAGEVIEW.store(image_view, Ordering::Relaxed);
        D3D9_DESC_LAST_UPDATE_BINDING.store(dst_binding, Ordering::Relaxed);
        eprintln!(
            "weave/d3d9-desc t={t}ms presents={presents} UpdateDescriptorSets \
             write#{write_idx} binding={dst_binding} array={} type={desc_type} \
             sampler=0x{sampler:x} imageView=0x{image_view:x} layout={layout}",
            dst_array + j,
        );
    }
}

fn d3d9_clear_trace_enabled() -> bool {
    *D3D9_CLEAR_TRACE.get_or_init(|| {
        std::env::var("WEAVE_D3D9_CLEAR_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

fn d3d9_clear_log(msg: impl std::fmt::Display) {
    eprintln!(
        "weave/d3d9-clear t={}ms presents={} {}",
        d3d9_trace_ms(),
        D3D9_PRESENT_COUNT.load(Ordering::Relaxed),
        msg
    );
}

fn d3d9_backbuffer_dump_enabled() -> bool {
    *D3D9_BACKBUFFER_DUMP.get_or_init(|| {
        std::env::var("WEAVE_D3D9_BACKBUFFER_DUMP")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Log 16 BGRA bytes at the window center (falsification receipt).
fn d3d9_log_bytes16(label: &str, present_seq: u64, data: *const u8, width: u16, height: u16) {
    if data.is_null() || width == 0 || height == 0 {
        eprintln!(
            "weave/d3d9-falsif {label} present=#{present_seq} t={}ms bytes16=SKIP null-data",
            d3d9_trace_ms()
        );
        return;
    }
    let cx = (width as usize / 2) & !3;
    let cy = height as usize / 2;
    let stride = width as usize * 4;
    let idx = cy * stride + cx;
    let mut hex = String::with_capacity(48);
    for i in 0..16 {
        if i > 0 {
            hex.push(' ');
        }
        hex.push_str(&format!("{:02x}", unsafe { *data.add(idx + i) }));
    }
    eprintln!(
        "weave/d3d9-falsif {label} present=#{present_seq} t={}ms center=({cx},{cy}) bytes16=[{hex}]",
        d3d9_trace_ms()
    );
}

/// Parse `VkPresentInfoKHR` and log swapchain + image index (pre-present Vulkan target).
fn d3d9_dump_vulkan_present_target(
    device: VkDevice,
    p_present_info: *const c_void,
    present_seq: u64,
) {
    if p_present_info.is_null() {
        eprintln!(
            "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms SKIP null-present-info",
            d3d9_trace_ms()
        );
        return;
    }
    let base = p_present_info as *const u8;
    let (swapchain, image_index) = unsafe {
        let count = (base.add(32) as *const u32).read();
        if count == 0 {
            eprintln!(
                "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms SKIP swapchain_count=0",
                d3d9_trace_ms()
            );
            return;
        }
        let p_swapchains = (base.add(40) as *const *const VkSwapchainKHR).read();
        let p_indices = (base.add(48) as *const *const u32).read();
        if p_swapchains.is_null() || p_indices.is_null() {
            eprintln!(
                "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms SKIP null swapchains/indices",
                d3d9_trace_ms()
            );
            return;
        }
        (*p_swapchains, *p_indices)
    };
    let img_w = D3D9_SWAP_W.load(Ordering::Relaxed);
    let img_h = D3D9_SWAP_H.load(Ordering::Relaxed);
    eprintln!(
        "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms swapchain=0x{swapchain:x} \
         imageIndex={image_index} extent={img_w}x{img_h}",
        d3d9_trace_ms()
    );
    if device.is_null() {
        eprintln!(
            "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms SKIP no-stored-device",
            d3d9_trace_ms()
        );
        return;
    }
    let get_images = real_device_fn(device, "vkGetSwapchainImagesKHR");
    if get_images.is_null() {
        eprintln!(
            "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms SKIP vkGetSwapchainImagesKHR",
            d3d9_trace_ms()
        );
        return;
    }
    let get_images: unsafe extern "C" fn(
        VkDevice,
        VkSwapchainKHR,
        *mut u32,
        *mut VkImage,
    ) -> VkResult = unsafe { std::mem::transmute(get_images) };
    let mut count = 0u32;
    let r0 = unsafe { get_images(device, swapchain, &mut count, std::ptr::null_mut()) };
    if count == 0 {
        eprintln!(
            "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms image_count_query r={r0} count=0",
            d3d9_trace_ms()
        );
        return;
    }
    if image_index >= count {
        eprintln!(
            "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms SKIP imageIndex={image_index} >= count={count}",
            d3d9_trace_ms()
        );
        return;
    }
    let mut images = vec![0u64; count as usize];
    let r1 = unsafe {
        get_images(
            device,
            swapchain,
            &mut count,
            images.as_mut_ptr() as *mut VkImage,
        )
    };
    let image = images[image_index as usize];
    eprintln!(
        "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms VkImage=0x{image:x} getImages r={r1}",
        d3d9_trace_ms()
    );
    let get_layout = real_device_fn(device, "vkGetImageSubresourceLayout");
    if get_layout.is_null() {
        return;
    }
    #[repr(C)]
    struct VkImageSubresource {
        aspect_mask: u32,
        mip_level: u32,
        array_layer: u32,
    }
    #[repr(C)]
    struct VkSubresourceLayout {
        offset: u64,
        size: u64,
        row_pitch: u64,
        array_pitch: u64,
        depth_pitch: u64,
    }
    let sub = VkImageSubresource {
        aspect_mask: 1, // VK_IMAGE_ASPECT_COLOR_BIT
        mip_level: 0,
        array_layer: 0,
    };
    let mut layout = VkSubresourceLayout {
        offset: 0,
        size: 0,
        row_pitch: 0,
        array_pitch: 0,
        depth_pitch: 0,
    };
    let get_layout: unsafe extern "C" fn(
        VkDevice,
        VkImage,
        *const VkImageSubresource,
        *mut VkSubresourceLayout,
    ) -> () = unsafe { std::mem::transmute(get_layout) };
    unsafe { get_layout(device, image, &sub, &mut layout) };
    eprintln!(
        "weave/d3d9-falsif PRE-VULKAN present=#{present_seq} t={}ms subresourceLayout \
         offset={} size={} rowPitch={} (GPU mmap not attempted — use XCB bytes16 for color)",
        d3d9_trace_ms(),
        layout.offset,
        layout.size,
        layout.row_pitch
    );
}

/// Sample pixels from the presentation XCB window (same threshold/grid as gate sampler).
fn d3d9_xcb_sample_surface(label: &str, present_seq: u64) {
    let window = D3D9_SURFACE_XCB.load(Ordering::Relaxed);
    if window == 0 {
        eprintln!(
            "weave/d3d9-falsif {label} present=#{present_seq} t={}ms SKIP no-surface-xcb",
            d3d9_trace_ms()
        );
        return;
    }
    let conn = match xcb_connection() {
        Some(c) => c,
        None => {
            eprintln!(
                "weave/d3d9-falsif {label} present=#{present_seq} t={}ms SKIP no-xcb-conn",
                d3d9_trace_ms()
            );
            return;
        }
    };
    let lib = unsafe {
        let h = libc::dlopen(b"libxcb.so.1\0".as_ptr() as _, libc::RTLD_LAZY);
        if h.is_null() {
            libc::dlopen(b"libxcb.so\0".as_ptr() as _, libc::RTLD_LAZY)
        } else {
            h
        }
    };
    if lib.is_null() {
        eprintln!(
            "weave/d3d9-falsif {label} present=#{present_seq} t={}ms SKIP dlopen-xcb",
            d3d9_trace_ms()
        );
        return;
    }
    type XcbGetImageCookie = u32;
    type XcbGetImage =
        unsafe extern "C" fn(*mut c_void, u8, u32, i16, i16, u16, u16, u32) -> XcbGetImageCookie;
    type XcbGetImageReply =
        unsafe extern "C" fn(*mut c_void, XcbGetImageCookie, *mut *mut c_void) -> *mut c_void;
    type XcbGetImageData = unsafe extern "C" fn(*const c_void) -> *const u8;
    type XcbFree = unsafe extern "C" fn(*mut c_void);
    let get_image: XcbGetImage =
        unsafe { std::mem::transmute(libc::dlsym(lib, b"xcb_get_image\0".as_ptr() as _)) };
    let get_reply: XcbGetImageReply =
        unsafe { std::mem::transmute(libc::dlsym(lib, b"xcb_get_image_reply\0".as_ptr() as _)) };
    let get_data: XcbGetImageData =
        unsafe { std::mem::transmute(libc::dlsym(lib, b"xcb_get_image_data\0".as_ptr() as _)) };
    let xcb_free: XcbFree =
        unsafe { std::mem::transmute(libc::dlsym(lib, b"free\0".as_ptr() as _)) };
    if get_image as usize == 0
        || get_reply as usize == 0
        || get_data as usize == 0
        || xcb_free as usize == 0
    {
        eprintln!(
            "weave/d3d9-falsif {label} present=#{present_seq} t={}ms SKIP xcb-syms",
            d3d9_trace_ms()
        );
        return;
    }
    const XCB_IMAGE_FORMAT_Z_PIXMAP: u8 = 2;
    const PLANE_MASK: u32 = 0x00FF_FFFF;
    const THRESHOLD: u32 = 0x0014_1414;
    let mut width = D3D9_SWAP_W.load(Ordering::Relaxed) as u16;
    let mut height = D3D9_SWAP_H.load(Ordering::Relaxed) as u16;
    if width == 0 || height == 0 {
        width = 646;
        height = 509;
    }
    let cookie = unsafe {
        get_image(
            conn,
            XCB_IMAGE_FORMAT_Z_PIXMAP,
            window,
            0,
            0,
            width,
            height,
            PLANE_MASK,
        )
    };
    let reply = unsafe { get_reply(conn, cookie, std::ptr::null_mut()) };
    if reply.is_null() {
        eprintln!(
            "weave/d3d9-falsif {label} present=#{present_seq} t={}ms xcb_win={window:#x} FAIL get_image_reply=null",
            d3d9_trace_ms()
        );
        return;
    }
    let data = unsafe { get_data(reply) };
    if present_seq <= 4 {
        d3d9_log_bytes16(label, present_seq, data, width, height);
    }
    let stride = width as usize * 4;
    let mut sampled = 0u32;
    let mut bright = 0u32;
    let mut min_px = u32::MAX;
    let mut max_px = 0u32;
    let mut yi = 0u16;
    while yi < height {
        let mut xi = 0u16;
        while xi < width {
            let idx = yi as usize * stride + xi as usize * 4;
            let b = unsafe { *data.add(idx) } as u32;
            let g = unsafe { *data.add(idx + 1) } as u32;
            let r = unsafe { *data.add(idx + 2) } as u32;
            let px = (r << 16) | (g << 8) | b;
            sampled += 1;
            if px < min_px {
                min_px = px;
            }
            if px > max_px {
                max_px = px;
            }
            if px > THRESHOLD {
                bright += 1;
            }
            xi = xi.saturating_add(16);
        }
        yi = yi.saturating_add(16);
    }
    unsafe { xcb_free(reply) };
    let (_, _, draws, _, _) = d3d9_trace_counts();
    eprintln!(
        "weave/d3d9-falsif {label} present=#{present_seq} t={}ms xcb_win={window:#x} \
         sampled={sampled} bright={bright} min_px={min_px:#010x} max_px={max_px:#010x} draws={draws}",
        d3d9_trace_ms()
    );
}

fn d3d9_trace_enabled() -> bool {
    *D3D9_TRACE_ENABLED.get_or_init(|| {
        std::env::var("WEAVE_D3D9_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

fn d3d9_trace_ms() -> u128 {
    D3D9_TRACE_START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis()
}

fn d3d9_trace_counts() -> (u64, u64, u64, u64, u64) {
    (
        D3D9_SUBMIT_COUNT.load(Ordering::Relaxed),
        D3D9_PRESENT_COUNT.load(Ordering::Relaxed),
        D3D9_DRAW_COUNT.load(Ordering::Relaxed),
        D3D9_CLEAR_COUNT.load(Ordering::Relaxed),
        D3D9_UPLOAD_COUNT.load(Ordering::Relaxed),
    )
}

macro_rules! d3d9_trace {
    ($($arg:tt)*) => {
        if d3d9_trace_enabled() {
            eprintln!("weave/d3d9-trace t={}ms {}", d3d9_trace_ms(), format_args!($($arg)*));
        }
    };
}

// ── Vulkan structures ─────────────────────────────────────────────────────────

#[repr(C)]
pub struct VkInstanceCreateInfo {
    s_type: u32,
    p_next: *const c_void,
    flags: u32,
    p_application_info: *const c_void,
    enabled_layer_count: u32,
    pp_enabled_layer_names: *const *const c_char,
    enabled_extension_count: u32,
    pp_enabled_extension_names: *const *const c_char,
}

#[repr(C)]
pub struct VkWin32SurfaceCreateInfoKHR {
    s_type: u32,
    p_next: *const c_void,
    flags: u32,
    hinstance: *mut c_void,
    hwnd: usize,
}

#[repr(C)]
struct VkXcbSurfaceCreateInfoKHR {
    s_type: u32,
    p_next: *const c_void,
    flags: u32,
    connection: *mut c_void,
    window: u32,
}

// ── Runtime-loaded Vulkan function pointers ───────────────────────────────────

struct VulkanLoader {
    get_instance_proc_addr:
        unsafe extern "C" fn(instance: VkInstance, name: *const c_char) -> PFN_vkVoidFunction,
    create_instance: unsafe extern "C" fn(
        p_create_info: *const VkInstanceCreateInfo,
        p_allocator: *const c_void,
        p_instance: *mut VkInstance,
    ) -> VkResult,
    enumerate_instance_extension_properties: unsafe extern "C" fn(
        p_layer_name: *const c_char,
        p_property_count: *mut u32,
        p_properties: *mut c_void,
    ) -> VkResult,
    enumerate_instance_layer_properties:
        unsafe extern "C" fn(p_property_count: *mut u32, p_properties: *mut c_void) -> VkResult,
    enumerate_instance_version: Option<unsafe extern "C" fn(p_api_version: *mut u32) -> VkResult>,
    get_device_proc_addr:
        unsafe extern "C" fn(device: VkDevice, name: *const c_char) -> PFN_vkVoidFunction,
}

static VULKAN: OnceLock<Option<VulkanLoader>> = OnceLock::new();

fn load_vulkan() -> Option<VulkanLoader> {
    let lib = unsafe {
        let h = libc::dlopen(
            b"libvulkan.so.1\0".as_ptr() as _,
            libc::RTLD_LAZY | libc::RTLD_GLOBAL,
        );
        if h.is_null() {
            let h2 = libc::dlopen(
                b"libvulkan.so\0".as_ptr() as _,
                libc::RTLD_LAZY | libc::RTLD_GLOBAL,
            );
            if h2.is_null() {
                return None;
            }
            h2
        } else {
            h
        }
    };

    /// Load a required symbol; return None if missing.
    macro_rules! sym {
        ($name:literal) => {{
            let ptr = unsafe { libc::dlsym(lib, concat!($name, "\0").as_ptr() as _) };
            if ptr.is_null() {
                return None;
            }
            // SAFETY: `ptr` was returned by `dlsym` for the symbol named by `$name`
            // in `libvulkan.so.1` (the system Vulkan loader).  The target type of this
            // transmute is always a typed `unsafe extern "C" fn(...)` whose signature
            // matches the Vulkan specification for `$name`.  `dlsym` guarantees the
            // pointer is non-null (checked above) and correctly aligned for code.
            // Vulkan loader symbols always use the System V AMD64 ABI (`extern "C"`).
            unsafe { std::mem::transmute(ptr) }
        }};
        (opt $name:literal) => {{
            let ptr = unsafe { libc::dlsym(lib, concat!($name, "\0").as_ptr() as _) };
            if ptr.is_null() {
                None
            } else {
                // SAFETY: Same as the required variant above — `ptr` is a non-null
                // `dlsym` result for `$name` in `libvulkan.so.1`, cast to the typed
                // `extern "C"` fn pointer whose signature matches the Vulkan spec.
                // The `Option` wrapper is used for symbols that may be absent in
                // older Vulkan loader versions (e.g. `vkEnumerateInstanceVersion`).
                Some(unsafe { std::mem::transmute(ptr) })
            }
        }};
    }

    Some(VulkanLoader {
        get_instance_proc_addr: sym!("vkGetInstanceProcAddr"),
        create_instance: sym!("vkCreateInstance"),
        enumerate_instance_extension_properties: sym!("vkEnumerateInstanceExtensionProperties"),
        enumerate_instance_layer_properties: sym!("vkEnumerateInstanceLayerProperties"),
        enumerate_instance_version: sym!(opt "vkEnumerateInstanceVersion"),
        get_device_proc_addr: sym!("vkGetDeviceProcAddr"),
    })
}

fn vulkan() -> Option<&'static VulkanLoader> {
    VULKAN.get_or_init(load_vulkan).as_ref()
}

// ── XCB connection for surface creation ──────────────────────────────────────

struct XcbState {
    connection: *mut c_void,
}

unsafe impl Send for XcbState {}
unsafe impl Sync for XcbState {}

static XCB: OnceLock<Option<XcbState>> = OnceLock::new();

fn xcb_connection() -> Option<*mut c_void> {
    XCB.get_or_init(|| {
        let lib = unsafe {
            let h = libc::dlopen(b"libxcb.so.1\0".as_ptr() as _, libc::RTLD_LAZY);
            if h.is_null() {
                libc::dlopen(b"libxcb.so\0".as_ptr() as _, libc::RTLD_LAZY)
            } else {
                h
            }
        };
        if lib.is_null() {
            return None;
        }
        // SAFETY: `libc::dlsym` is called with the literal symbol name `xcb_connect`
        // from `libxcb.so.1` (or `libxcb.so`), which was successfully opened above.
        // The XCB API specifies `xcb_connect(const char *displayname, int *screenp)`
        // returning `xcb_connection_t *`, matching the `extern "C" fn(*const c_char,
        // *mut i32) -> *mut c_void` signature here.  The result of `dlsym` is cast to
        // a fn pointer; if `dlsym` returns null the subsequent call would be UB, but
        // `xcb_connect` is a mandatory export of libxcb so its absence means the
        // library is corrupt — the connection check `if conn.is_null()` acts as a
        // runtime guard for the success of the call itself.
        let connect: unsafe extern "C" fn(*const c_char, *mut i32) -> *mut c_void =
            unsafe { std::mem::transmute(libc::dlsym(lib, b"xcb_connect\0".as_ptr() as _)) };
        let conn = unsafe { connect(std::ptr::null(), std::ptr::null_mut()) };
        if conn.is_null() {
            None
        } else {
            Some(XcbState { connection: conn })
        }
    })
    .as_ref()
    .map(|s| s.connection)
}

// ── Stored VkInstance for physical-device and device-level queries ────────────
//
// Physical-device queries need a VkInstance to call vkGetInstanceProcAddr.
// We store it when vkCreateInstance succeeds (single-instance assumption,
// which covers all games).

use std::sync::atomic::AtomicUsize;
static INSTANCE: AtomicUsize = AtomicUsize::new(0);

fn stored_instance() -> VkInstance {
    INSTANCE.load(Ordering::Acquire) as VkInstance
}

// ── Helper: look up a function from the real Vulkan loader ───────────────────

fn real_fn(instance: VkInstance, name: &str) -> PFN_vkVoidFunction {
    let vk = match vulkan() {
        Some(v) => v,
        None => return std::ptr::null(),
    };
    let cname = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };
    unsafe { (vk.get_instance_proc_addr)(instance, cname.as_ptr()) }
}

fn real_device_fn(device: VkDevice, name: &str) -> PFN_vkVoidFunction {
    let vk = match vulkan() {
        Some(v) => v,
        None => return std::ptr::null(),
    };
    let cname = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };
    unsafe { (vk.get_device_proc_addr)(device, cname.as_ptr()) }
}

// ── Win64→SysV thunks for device/physical-device functions ───────────────────
//
// vkGetInstanceProcAddr returns SysV ABI pointers from the real loader.
// Windows PE guest code invokes them with Windows x64 ABI — ABI mismatch →
// crash.  For every function we expect DXVK to call we must provide a
// win64-declared wrapper that delegates to the real SysV function.
//
// Macro: thunk!(Name, RetTy, (arg: ArgTy, ...)) generates:
//   pub unsafe extern "win64" fn vk_##name(...) { real(instance/device, "vk##Name")(...) }

// Physical-device thunks (use stored instance)
macro_rules! inst_thunk {
    ($name:ident, $real:literal, $ret:ty, ($($arg:ident : $ty:ty),*)) => {
        pub unsafe extern "win64" fn $name($($arg: $ty),*) -> $ret {
            let f = real_fn(stored_instance(), $real);
            if f.is_null() { return std::mem::zeroed(); }
            // SAFETY: `f` is the `PFN_vkVoidFunction` returned by
            // `vkGetInstanceProcAddr` for the symbol `$real`.  The Vulkan
            // specification defines the signature for `$real` to match the
            // `extern "C" fn($($ty),*) -> $ret` type declared here.  The
            // null-pointer guard above ensures `f` is a valid code address.
            let f: unsafe extern "C" fn($($ty),*) -> $ret = unsafe { std::mem::transmute(f) };
            unsafe { f($($arg),*) }
        }
    };
    (void $name:ident, $real:literal, ($($arg:ident : $ty:ty),*)) => {
        pub unsafe extern "win64" fn $name($($arg: $ty),*) {
            let f = real_fn(stored_instance(), $real);
            if f.is_null() { return; }
            // SAFETY: `f` is the `PFN_vkVoidFunction` returned by
            // `vkGetInstanceProcAddr` for the symbol `$real`.  The Vulkan
            // specification defines the (void-returning) signature for `$real`
            // to match the `extern "C" fn($($ty),*)` type declared here.
            // The null-pointer guard above ensures `f` is a valid code address.
            let f: unsafe extern "C" fn($($ty),*) = unsafe { std::mem::transmute(f) };
            unsafe { f($($arg),*) }
        }
    };
}

// Device thunks (first arg is VkDevice)
macro_rules! dev_thunk {
    ($name:ident, $real:literal, $ret:ty, ($dev:ident, $($arg:ident : $ty:ty),*)) => {
        pub unsafe extern "win64" fn $name($dev: VkDevice, $($arg: $ty),*) -> $ret {
            let f = real_device_fn($dev, $real);
            if f.is_null() { return std::mem::zeroed(); }
            // SAFETY: `f` is the `PFN_vkVoidFunction` returned by
            // `vkGetDeviceProcAddr` for the symbol `$real` on device `$dev`.
            // The Vulkan specification defines the signature for `$real` to
            // match `extern "C" fn(VkDevice, $($ty),*) -> $ret`.  The
            // null-pointer guard above ensures `f` is a valid code address.
            let f: unsafe extern "C" fn(VkDevice, $($ty),*) -> $ret = unsafe { std::mem::transmute(f) };
            unsafe { f($dev, $($arg),*) }
        }
    };
    (void $name:ident, $real:literal, ($dev:ident, $($arg:ident : $ty:ty),*)) => {
        pub unsafe extern "win64" fn $name($dev: VkDevice, $($arg: $ty),*) {
            let f = real_device_fn($dev, $real);
            if f.is_null() { return; }
            // SAFETY: `f` is the `PFN_vkVoidFunction` returned by
            // `vkGetDeviceProcAddr` for the symbol `$real` on device `$dev`.
            // The Vulkan specification defines the (void-returning) signature
            // for `$real` to match `extern "C" fn(VkDevice, $($ty),*)`.
            // The null-pointer guard above ensures `f` is a valid code address.
            let f: unsafe extern "C" fn(VkDevice, $($ty),*) = unsafe { std::mem::transmute(f) };
            unsafe { f($dev, $($arg),*) }
        }
    };
}

// Command-buffer thunks (first arg is VkCommandBuffer)
macro_rules! cmd_thunk {
    (void $name:ident, $real:literal, ($cb:ident, $($arg:ident : $ty:ty),*)) => {
        pub unsafe extern "win64" fn $name($cb: VkCommandBuffer, $($arg: $ty),*) {
            let f = real_fn(stored_instance(), $real);
            if f.is_null() { return; }
            // SAFETY: `f` is the `PFN_vkVoidFunction` for the command-buffer
            // function `$real`, obtained via `vkGetInstanceProcAddr`.  The
            // Vulkan specification defines the (void-returning) signature for
            // `$real` to match `extern "C" fn(VkCommandBuffer, $($ty),*)`.
            // The null-pointer guard above ensures `f` is a valid code address.
            let f: unsafe extern "C" fn(VkCommandBuffer, $($ty),*) = unsafe { std::mem::transmute(f) };
            unsafe { f($cb, $($arg),*) }
        }
    };
    ($name:ident, $real:literal, $ret:ty, ($cb:ident, $($arg:ident : $ty:ty),*)) => {
        pub unsafe extern "win64" fn $name($cb: VkCommandBuffer, $($arg: $ty),*) -> $ret {
            let f = real_fn(stored_instance(), $real);
            if f.is_null() { return std::mem::zeroed(); }
            // SAFETY: `f` is the `PFN_vkVoidFunction` for the command-buffer
            // function `$real`, obtained via `vkGetInstanceProcAddr`.  The
            // Vulkan specification defines the signature for `$real` to match
            // `extern "C" fn(VkCommandBuffer, $($ty),*) -> $ret`.  The
            // null-pointer guard above ensures `f` is a valid code address.
            let f: unsafe extern "C" fn(VkCommandBuffer, $($ty),*) -> $ret = unsafe { std::mem::transmute(f) };
            unsafe { f($cb, $($arg),*) }
        }
    };
}

// EXT command-buffer thunks (DXVK D3D9 render path)
cmd_thunk!(void vk_cmd_set_depth_bias2_ext, "vkCmdSetDepthBias2EXT", (command_buffer, p_depth_bias_info: *const c_void));
// Transform feedback (DXVK uses for d3d9 stream-out)
cmd_thunk!(void vk_cmd_bind_transform_feedback_buffers_ext, "vkCmdBindTransformFeedbackBuffersEXT", (command_buffer, first_binding: u32, binding_count: u32, p_buffers: *const c_void, p_offsets: *const c_void, p_sizes: *const c_void));
cmd_thunk!(void vk_cmd_begin_transform_feedback_ext, "vkCmdBeginTransformFeedbackEXT", (command_buffer, first_counter_buffer: u32, counter_buffer_count: u32, p_counter_buffers: *const c_void, p_counter_buffer_offsets: *const c_void));
cmd_thunk!(void vk_cmd_end_transform_feedback_ext, "vkCmdEndTransformFeedbackEXT", (command_buffer, first_counter_buffer: u32, counter_buffer_count: u32, p_counter_buffers: *const c_void, p_counter_buffer_offsets: *const c_void));
cmd_thunk!(void vk_cmd_draw_indirect_byte_count_ext, "vkCmdDrawIndirectByteCountEXT", (command_buffer, instance_count: u32, first_instance: u32, counter_buffer: u64, counter_buffer_offset: u64, counter_offset: u32, vertex_stride: u32));
cmd_thunk!(void vk_cmd_begin_query_indexed_ext, "vkCmdBeginQueryIndexedEXT", (command_buffer, query_pool: u64, query: u32, flags: u32, index: u32));
cmd_thunk!(void vk_cmd_end_query_indexed_ext, "vkCmdEndQueryIndexedEXT", (command_buffer, query_pool: u64, query: u32, index: u32));
// Conditional rendering
cmd_thunk!(void vk_cmd_begin_conditional_rendering_ext, "vkCmdBeginConditionalRenderingEXT", (command_buffer, p_conditional_rendering_begin: *const c_void));
cmd_thunk!(void vk_cmd_end_conditional_rendering_ext, "vkCmdEndConditionalRenderingEXT", (command_buffer,));
// Extended dynamic state 3
cmd_thunk!(void vk_cmd_set_tessellation_domain_origin_ext, "vkCmdSetTessellationDomainOriginEXT", (command_buffer, domain_origin: u32));
cmd_thunk!(void vk_cmd_set_depth_clamp_enable_ext, "vkCmdSetDepthClampEnableEXT", (command_buffer, depth_clamp_enable: u32));
cmd_thunk!(void vk_cmd_set_polygon_mode_ext, "vkCmdSetPolygonModeEXT", (command_buffer, polygon_mode: u32));
cmd_thunk!(void vk_cmd_set_rasterization_samples_ext, "vkCmdSetRasterizationSamplesEXT", (command_buffer, rasterization_samples: u32));
cmd_thunk!(void vk_cmd_set_sample_mask_ext, "vkCmdSetSampleMaskEXT", (command_buffer, samples: u32, p_sample_mask: *const u32));
cmd_thunk!(void vk_cmd_set_alpha_to_coverage_enable_ext, "vkCmdSetAlphaToCoverageEnableEXT", (command_buffer, alpha_to_coverage_enable: u32));
cmd_thunk!(void vk_cmd_set_alpha_to_one_enable_ext, "vkCmdSetAlphaToOneEnableEXT", (command_buffer, alpha_to_one_enable: u32));
cmd_thunk!(void vk_cmd_set_logic_op_enable_ext, "vkCmdSetLogicOpEnableEXT", (command_buffer, logic_op_enable: u32));
cmd_thunk!(void vk_cmd_set_color_blend_enable_ext, "vkCmdSetColorBlendEnableEXT", (command_buffer, first_attachment: u32, attachment_count: u32, p_color_blend_enables: *const u32));
cmd_thunk!(void vk_cmd_set_color_blend_equation_ext, "vkCmdSetColorBlendEquationEXT", (command_buffer, first_attachment: u32, attachment_count: u32, p_color_blend_equations: *const c_void));
cmd_thunk!(void vk_cmd_set_color_write_mask_ext, "vkCmdSetColorWriteMaskEXT", (command_buffer, first_attachment: u32, attachment_count: u32, p_color_write_masks: *const u32));
cmd_thunk!(void vk_cmd_set_rasterization_stream_ext, "vkCmdSetRasterizationStreamEXT", (command_buffer, rasterization_stream: u32));
cmd_thunk!(void vk_cmd_set_conservative_rasterization_mode_ext, "vkCmdSetConservativeRasterizationModeEXT", (command_buffer, conservative_rasterization_mode: u32));
cmd_thunk!(void vk_cmd_set_extra_primitive_overestimation_size_ext, "vkCmdSetExtraPrimitiveOverestimationSizeEXT", (command_buffer, extra_primitive_overestimation_size: f32));
cmd_thunk!(void vk_cmd_set_line_rasterization_mode_ext, "vkCmdSetLineRasterizationModeEXT", (command_buffer, line_rasterization_mode: u32));
// Debug-utils labels (cmd-buffer level)
cmd_thunk!(void vk_cmd_begin_debug_utils_label_ext, "vkCmdBeginDebugUtilsLabelEXT", (command_buffer, p_label_info: *const c_void));
cmd_thunk!(void vk_cmd_end_debug_utils_label_ext, "vkCmdEndDebugUtilsLabelEXT", (command_buffer,));
cmd_thunk!(void vk_cmd_insert_debug_utils_label_ext, "vkCmdInsertDebugUtilsLabelEXT", (command_buffer, p_label_info: *const c_void));
// EXT queue thunks
inst_thunk!(void vk_queue_bind_sparse, "vkQueueBindSparse", (queue: VkQueue, bind_info_count: u32, p_bind_info: *const c_void, fence: u64));
inst_thunk!(void vk_queue_begin_debug_utils_label_ext, "vkQueueBeginDebugUtilsLabelEXT", (queue: VkQueue, p_label_info: *const c_void));
inst_thunk!(void vk_queue_end_debug_utils_label_ext, "vkQueueEndDebugUtilsLabelEXT", (queue: VkQueue));
inst_thunk!(void vk_queue_insert_debug_utils_label_ext, "vkQueueInsertDebugUtilsLabelEXT", (queue: VkQueue, p_label_info: *const c_void));
// EXT device thunks
dev_thunk!(void vk_get_shader_module_identifier_ext, "vkGetShaderModuleIdentifierEXT", (dev, shader_module: u64, p_identifier: *mut c_void));
dev_thunk!(void vk_get_shader_module_create_info_identifier_ext, "vkGetShaderModuleCreateInfoIdentifierEXT", (dev, p_create_info: *const c_void, p_identifier: *mut c_void));
dev_thunk!(void vk_set_debug_utils_object_name_ext, "vkSetDebugUtilsObjectNameEXT", (dev, p_name_info: *const c_void));
dev_thunk!(void vk_set_debug_utils_object_tag_ext, "vkSetDebugUtilsObjectTagEXT", (dev, p_tag_info: *const c_void));

// Physical-device functions
pub unsafe extern "win64" fn vk_enumerate_physical_devices(
    instance: VkInstance,
    p_count: *mut u32,
    p_devices: *mut VkPhysicalDevice,
) -> VkResult {
    eprintln!("weave-vulkan: vk_enumerate_physical_devices ENTER");
    let f = real_fn(stored_instance(), "vkEnumeratePhysicalDevices");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkInstance, *mut u32, *mut VkPhysicalDevice) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(instance, p_count, p_devices) };
    eprintln!(
        "weave-vulkan: vk_enumerate_physical_devices RETURN result={}",
        r
    );
    if !p_count.is_null() {
        eprintln!(
            "weave-vulkan: vk_enumerate_physical_devices count={}",
            unsafe { *p_count }
        );
    }
    r
}
inst_thunk!(void vk_get_physical_device_properties, "vkGetPhysicalDeviceProperties", (physical_device: VkPhysicalDevice, p_properties: *mut c_void));
inst_thunk!(void vk_get_physical_device_features, "vkGetPhysicalDeviceFeatures", (physical_device: VkPhysicalDevice, p_features: *mut c_void));
inst_thunk!(void vk_get_physical_device_features2, "vkGetPhysicalDeviceFeatures2", (physical_device: VkPhysicalDevice, p_features: *mut c_void));
inst_thunk!(void vk_get_physical_device_properties2, "vkGetPhysicalDeviceProperties2", (physical_device: VkPhysicalDevice, p_properties: *mut c_void));
inst_thunk!(void vk_get_physical_device_memory_properties, "vkGetPhysicalDeviceMemoryProperties", (physical_device: VkPhysicalDevice, p_properties: *mut c_void));
inst_thunk!(void vk_get_physical_device_memory_properties2, "vkGetPhysicalDeviceMemoryProperties2", (physical_device: VkPhysicalDevice, p_properties: *mut c_void));
inst_thunk!(void vk_get_physical_device_queue_family_properties, "vkGetPhysicalDeviceQueueFamilyProperties", (physical_device: VkPhysicalDevice, p_count: *mut u32, p_properties: *mut c_void));
inst_thunk!(void vk_get_physical_device_queue_family_properties2, "vkGetPhysicalDeviceQueueFamilyProperties2", (physical_device: VkPhysicalDevice, p_count: *mut u32, p_properties: *mut c_void));
inst_thunk!(void vk_get_physical_device_format_properties, "vkGetPhysicalDeviceFormatProperties", (physical_device: VkPhysicalDevice, format: VkFormat, p_properties: *mut c_void));
inst_thunk!(void vk_get_physical_device_format_properties2, "vkGetPhysicalDeviceFormatProperties2", (physical_device: VkPhysicalDevice, format: VkFormat, p_properties: *mut c_void));
inst_thunk!(vk_get_physical_device_image_format_properties, "vkGetPhysicalDeviceImageFormatProperties", VkResult, (physical_device: VkPhysicalDevice, format: u32, ty: u32, tiling: u32, usage: u32, flags: u32, p_properties: *mut c_void));
inst_thunk!(vk_get_physical_device_image_format_properties2, "vkGetPhysicalDeviceImageFormatProperties2", VkResult, (physical_device: VkPhysicalDevice, p_info: *const c_void, p_properties: *mut c_void));
pub unsafe extern "win64" fn vk_enumerate_device_extension_properties(
    physical_device: VkPhysicalDevice,
    p_layer: *const c_char,
    p_count: *mut u32,
    p_properties: *mut c_void,
) -> VkResult {
    let f = real_fn(stored_instance(), "vkEnumerateDeviceExtensionProperties");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(
        VkPhysicalDevice,
        *const c_char,
        *mut u32,
        *mut c_void,
    ) -> VkResult = unsafe { std::mem::transmute(f) };
    let r = unsafe { f(physical_device, p_layer, p_count, p_properties) };
    // Dump the list once, when DXVK fills the array (p_properties != NULL).
    // VkExtensionProperties layout: char extensionName[256]; uint32_t specVersion;
    if !p_properties.is_null() && !p_count.is_null() {
        let count = unsafe { *p_count } as usize;
        eprintln!(
            "weave-vulkan: vk_enumerate_device_extension_properties returned {count} extensions:"
        );
        let stride: usize = 256 + 4;
        for i in 0..count {
            let entry = unsafe { (p_properties as *const u8).add(i * stride) } as *const c_char;
            let name = unsafe { CStr::from_ptr(entry) }.to_string_lossy();
            let spec = unsafe { *(entry.add(256) as *const u32) };
            eprintln!("weave-vulkan:   ext[{i}] {name} v{spec}");
        }
    }
    r
}
inst_thunk!(vk_enumerate_device_layer_properties, "vkEnumerateDeviceLayerProperties", VkResult, (physical_device: VkPhysicalDevice, p_count: *mut u32, p_properties: *mut c_void));
pub unsafe extern "win64" fn vk_create_device(
    physical_device: VkPhysicalDevice,
    p_create_info: *const c_void,
    p_allocator: *const c_void,
    p_device: *mut VkDevice,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_create_device ENTER physical_device={:p}",
        physical_device as *const ()
    );
    let f = real_fn(stored_instance(), "vkCreateDevice");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(
        VkPhysicalDevice,
        *const c_void,
        *const c_void,
        *mut VkDevice,
    ) -> VkResult = unsafe { std::mem::transmute(f) };
    eprintln!("weave-vulkan: vk_create_device calling real vkCreateDevice");
    let r = unsafe { f(physical_device, p_create_info, p_allocator, p_device) };
    eprintln!("weave-vulkan: vk_create_device RETURN result={}", r);
    r
}
inst_thunk!(void vk_destroy_instance, "vkDestroyInstance", (instance: VkInstance, p_allocator: *const c_void));
pub unsafe extern "win64" fn vk_get_physical_device_surface_support_khr(
    physical_device: VkPhysicalDevice,
    queue_family_index: u32,
    surface: VkSurfaceKHR,
    p_supported: *mut u32,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_get_physical_device_surface_support_khr ENTER pdev={:p} qfi={queue_family_index} surface=0x{surface:x}",
        physical_device as *const ()
    );
    let f = real_fn(stored_instance(), "vkGetPhysicalDeviceSurfaceSupportKHR");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkPhysicalDevice, u32, VkSurfaceKHR, *mut u32) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(physical_device, queue_family_index, surface, p_supported) };
    eprintln!("weave-vulkan: vk_get_physical_device_surface_support_khr RETURN {r}");
    r
}
pub unsafe extern "win64" fn vk_get_physical_device_surface_capabilities_khr(
    physical_device: VkPhysicalDevice,
    surface: VkSurfaceKHR,
    p_capabilities: *mut c_void,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_get_physical_device_surface_capabilities_khr ENTER pdev={:p} surface=0x{surface:x}",
        physical_device as *const ()
    );
    let f = real_fn(
        stored_instance(),
        "vkGetPhysicalDeviceSurfaceCapabilitiesKHR",
    );
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkPhysicalDevice, VkSurfaceKHR, *mut c_void) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(physical_device, surface, p_capabilities) };
    eprintln!("weave-vulkan: vk_get_physical_device_surface_capabilities_khr RETURN {r}");
    r
}
pub unsafe extern "win64" fn vk_get_physical_device_surface_formats_khr(
    physical_device: VkPhysicalDevice,
    surface: VkSurfaceKHR,
    p_count: *mut u32,
    p_formats: *mut c_void,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_get_physical_device_surface_formats_khr ENTER pdev={:p} surface=0x{surface:x} p_formats={p_formats:p}",
        physical_device as *const ()
    );
    let f = real_fn(stored_instance(), "vkGetPhysicalDeviceSurfaceFormatsKHR");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkPhysicalDevice, VkSurfaceKHR, *mut u32, *mut c_void) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(physical_device, surface, p_count, p_formats) };
    eprintln!("weave-vulkan: vk_get_physical_device_surface_formats_khr RETURN {r}");
    r
}
pub unsafe extern "win64" fn vk_get_physical_device_surface_present_modes_khr(
    physical_device: VkPhysicalDevice,
    surface: VkSurfaceKHR,
    p_count: *mut u32,
    p_modes: *mut u32,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_get_physical_device_surface_present_modes_khr ENTER pdev={:p} surface=0x{surface:x} p_modes={p_modes:p}",
        physical_device as *const ()
    );
    let f = real_fn(
        stored_instance(),
        "vkGetPhysicalDeviceSurfacePresentModesKHR",
    );
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkPhysicalDevice, VkSurfaceKHR, *mut u32, *mut u32) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(physical_device, surface, p_count, p_modes) };
    eprintln!("weave-vulkan: vk_get_physical_device_surface_present_modes_khr RETURN {r}");
    r
}
inst_thunk!(vk_get_physical_device_surface_capabilities2_khr, "vkGetPhysicalDeviceSurfaceCapabilities2KHR", VkResult, (physical_device: VkPhysicalDevice, p_surface_info: *const c_void, p_capabilities: *mut c_void));
inst_thunk!(vk_get_physical_device_calibrateable_time_domains_ext, "vkGetPhysicalDeviceCalibrateableTimeDomainsEXT", VkResult, (physical_device: VkPhysicalDevice, p_count: *mut u32, p_domains: *mut u32));
inst_thunk!(vk_get_physical_device_sparse_image_format_properties, "vkGetPhysicalDeviceSparseImageFormatProperties", VkResult, (physical_device: VkPhysicalDevice, format: u32, ty: u32, samples: u32, usage: u32, tiling: u32, p_count: *mut u32, p_properties: *mut c_void));
inst_thunk!(void vk_get_physical_device_sparse_image_format_properties2,
    "vkGetPhysicalDeviceSparseImageFormatProperties2",
    (physical_device: VkPhysicalDevice, p_format_info: *const c_void, p_property_count: *mut u32, p_properties: *mut c_void));
inst_thunk!(vk_get_physical_device_surface_formats2_khr,
    "vkGetPhysicalDeviceSurfaceFormats2KHR", VkResult,
    (physical_device: VkPhysicalDevice, p_surface_info: *const c_void, p_surface_format_count: *mut u32, p_surface_formats: *mut c_void));
inst_thunk!(vk_get_physical_device_surface_present_modes2_ext,
    "vkGetPhysicalDeviceSurfacePresentModes2EXT", VkResult,
    (physical_device: VkPhysicalDevice, p_surface_info: *const c_void, p_present_mode_count: *mut u32, p_present_modes: *mut c_void));
dev_thunk!(vk_release_swapchain_images_ext,
    "vkReleaseSwapchainImagesEXT", VkResult,
    (device, p_release_info: *const c_void));
/// vkGetPhysicalDeviceWin32PresentationSupportKHR — manual implementation.
/// VK_KHR_win32_surface is Windows-only and the Linux Vulkan loader does not expose it.
/// Passing through via inst_thunk! would return null and silently yield VK_FALSE.
/// Weave translates Win32 HWND surfaces to XCB surfaces, so presentation is always
/// supported: return VK_TRUE (1).
pub unsafe extern "win64" fn vk_get_physical_device_win32_presentation_support_khr(
    _physical_device: VkPhysicalDevice,
    _queue_family_index: u32,
) -> u32 {
    eprintln!("weave-vulkan: vk_get_physical_device_win32_presentation_support_khr ENTER");
    // Win32→XCB translation: we always have a valid XCB surface for any HWND,
    // so presentation is always supported.
    1
}

// Device functions
dev_thunk!(void vk_destroy_device, "vkDestroyDevice", (device, p_allocator: *const c_void));
dev_thunk!(void vk_get_device_queue, "vkGetDeviceQueue", (device, queue_family_index: u32, queue_index: u32, p_queue: *mut VkQueue));
dev_thunk!(void vk_get_device_queue2, "vkGetDeviceQueue2", (device, p_info: *const c_void, p_queue: *mut VkQueue));
dev_thunk!(vk_device_wait_idle, "vkDeviceWaitIdle", VkResult, (device,));
// Queue-first thunks: real Vulkan signature has VkQueue as the first arg, not
// VkDevice.  We resolve via vkGetInstanceProcAddr (which since 1.2 returns
// dispatchable-trampoline pointers for device-level procs).
pub unsafe extern "win64" fn vk_queue_submit(
    queue: VkQueue,
    submit_count: u32,
    p_submits: *const c_void,
    fence: VkFence,
) -> VkResult {
    let seq = if d3d9_trace_enabled() {
        Some(D3D9_SUBMIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
    } else {
        None
    };
    if let Some(seq) = seq {
        let (_, presents, draws, clears, uploads) = d3d9_trace_counts();
        d3d9_trace!(
            "vkQueueSubmit#{seq} ENTER submits={submit_count} fence=0x{fence:x} draws={draws} clears={clears} uploads={uploads} presents={presents}"
        );
    }
    eprintln!(
        "weave-vulkan: vk_queue_submit ENTER queue={:p} count={submit_count} fence=0x{fence:x}",
        queue as *const ()
    );
    let f = real_fn(stored_instance(), "vkQueueSubmit");
    if f.is_null() {
        eprintln!("weave-vulkan: vk_queue_submit: real fn NULL");
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkQueue, u32, *const c_void, VkFence) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(queue, submit_count, p_submits, fence) };
    if let Some(seq) = seq {
        d3d9_trace!("vkQueueSubmit#{seq} RETURN {r}");
    }
    eprintln!("weave-vulkan: vk_queue_submit RETURN {r}");
    r
}
pub unsafe extern "win64" fn vk_queue_submit2(
    queue: VkQueue,
    submit_count: u32,
    p_submits: *const c_void,
    fence: VkFence,
) -> VkResult {
    let seq = if d3d9_trace_enabled() {
        Some(D3D9_SUBMIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
    } else {
        None
    };
    if let Some(seq) = seq {
        let (_, presents, draws, clears, uploads) = d3d9_trace_counts();
        d3d9_trace!(
            "vkQueueSubmit2#{seq} ENTER submits={submit_count} fence=0x{fence:x} draws={draws} clears={clears} uploads={uploads} presents={presents}"
        );
    }
    eprintln!(
        "weave-vulkan: vk_queue_submit2 ENTER queue={:p} count={submit_count} fence=0x{fence:x}",
        queue as *const ()
    );
    let f = real_fn(stored_instance(), "vkQueueSubmit2");
    if f.is_null() {
        eprintln!("weave-vulkan: vk_queue_submit2: real fn NULL");
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkQueue, u32, *const c_void, VkFence) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(queue, submit_count, p_submits, fence) };
    if let Some(seq) = seq {
        d3d9_trace!("vkQueueSubmit2#{seq} RETURN {r}");
    }
    eprintln!("weave-vulkan: vk_queue_submit2 RETURN {r}");
    r
}
pub unsafe extern "win64" fn vk_queue_wait_idle(queue: VkQueue) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_queue_wait_idle ENTER queue={:p}",
        queue as *const ()
    );
    let f = real_fn(stored_instance(), "vkQueueWaitIdle");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkQueue) -> VkResult = unsafe { std::mem::transmute(f) };
    let r = unsafe { f(queue) };
    eprintln!("weave-vulkan: vk_queue_wait_idle RETURN {r}");
    r
}
pub unsafe extern "win64" fn vk_queue_present_khr(
    queue: VkQueue,
    p_present_info: *const c_void,
) -> VkResult {
    let seq = if d3d9_trace_enabled() || d3d9_backbuffer_dump_enabled() {
        Some(D3D9_PRESENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
    } else {
        None
    };
    if let Some(seq) = seq {
        let (submits, _, draws, clears, uploads) = d3d9_trace_counts();
        d3d9_trace!(
            "vkQueuePresentKHR#{seq} ENTER submits={submits} draws={draws} clears={clears} uploads={uploads}"
        );
    }
    eprintln!(
        "weave-vulkan: vk_queue_present_khr ENTER queue={:p} info={p_present_info:p}",
        queue as *const ()
    );
    let dump = d3d9_backbuffer_dump_enabled();
    let dump_this = dump && seq.is_some_and(|s| s <= 4);
    if dump_this {
        if let Some(s) = seq {
            let device = D3D9_LAST_DEVICE.load(Ordering::Relaxed) as *mut c_void;
            d3d9_dump_vulkan_present_target(device, p_present_info, s);
            d3d9_xcb_sample_surface("PRE-PRESENT", s);
        }
    }
    let f = real_fn(stored_instance(), "vkQueuePresentKHR");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkQueue, *const c_void) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(queue, p_present_info) };
    if dump_this {
        if let Some(s) = seq {
            d3d9_xcb_sample_surface("POST-PRESENT", s);
        }
    }
    if let Some(seq) = seq {
        let (submits, presents, draws, clears, uploads) = d3d9_trace_counts();
        d3d9_trace!(
            "vkQueuePresentKHR#{seq} RETURN {r} totals submits={submits} presents={presents} draws={draws} clears={clears} uploads={uploads}"
        );
    }
    eprintln!("weave-vulkan: vk_queue_present_khr RETURN {r}");
    r
}
dev_thunk!(vk_allocate_memory, "vkAllocateMemory", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_memory: *mut VkDeviceMemory));
dev_thunk!(void vk_free_memory, "vkFreeMemory", (device, memory: VkDeviceMemory, p_allocator: *const c_void));
dev_thunk!(vk_map_memory, "vkMapMemory", VkResult, (device, memory: VkDeviceMemory, offset: VkDeviceSize, size: VkDeviceSize, flags: VkMemoryMapFlags, pp_data: *mut *mut c_void));
dev_thunk!(void vk_unmap_memory, "vkUnmapMemory", (device, memory: VkDeviceMemory));
dev_thunk!(vk_flush_mapped_memory_ranges, "vkFlushMappedMemoryRanges", VkResult, (device, memory_range_count: u32, p_memory_ranges: *const c_void));
dev_thunk!(vk_invalidate_mapped_memory_ranges, "vkInvalidateMappedMemoryRanges", VkResult, (device, memory_range_count: u32, p_memory_ranges: *const c_void));
dev_thunk!(vk_bind_buffer_memory, "vkBindBufferMemory", VkResult, (device, buffer: VkBuffer, memory: VkDeviceMemory, memory_offset: VkDeviceSize));
dev_thunk!(vk_bind_buffer_memory2, "vkBindBufferMemory2", VkResult, (device, bind_info_count: u32, p_bind_infos: *const c_void));
dev_thunk!(vk_bind_image_memory, "vkBindImageMemory", VkResult, (device, image: VkImage, memory: VkDeviceMemory, memory_offset: VkDeviceSize));
dev_thunk!(vk_bind_image_memory2, "vkBindImageMemory2", VkResult, (device, bind_info_count: u32, p_bind_infos: *const c_void));
dev_thunk!(void vk_get_buffer_memory_requirements, "vkGetBufferMemoryRequirements", (device, buffer: VkBuffer, p_requirements: *mut c_void));
dev_thunk!(void vk_get_buffer_memory_requirements2, "vkGetBufferMemoryRequirements2", (device, p_info: *const c_void, p_requirements: *mut c_void));
dev_thunk!(void vk_get_image_memory_requirements, "vkGetImageMemoryRequirements", (device, image: VkImage, p_requirements: *mut c_void));
dev_thunk!(void vk_get_image_memory_requirements2, "vkGetImageMemoryRequirements2", (device, p_info: *const c_void, p_requirements: *mut c_void));
// Core 1.3 unparameterised mem-req queries (DXVK 2.x dispatch table) + sparse fallthrough.
dev_thunk!(void vk_get_device_buffer_memory_requirements, "vkGetDeviceBufferMemoryRequirements", (device, p_info: *const c_void, p_requirements: *mut c_void));
dev_thunk!(void vk_get_device_image_memory_requirements, "vkGetDeviceImageMemoryRequirements", (device, p_info: *const c_void, p_requirements: *mut c_void));
dev_thunk!(void vk_get_device_image_sparse_memory_requirements, "vkGetDeviceImageSparseMemoryRequirements", (device, p_info: *const c_void, p_count: *mut u32, p_props: *mut c_void));
dev_thunk!(void vk_get_image_sparse_memory_requirements, "vkGetImageSparseMemoryRequirements", (device, image: VkImage, p_count: *mut u32, p_props: *mut c_void));
dev_thunk!(void vk_get_image_sparse_memory_requirements2, "vkGetImageSparseMemoryRequirements2", (device, p_info: *const c_void, p_count: *mut u32, p_props: *mut c_void));
dev_thunk!(vk_get_pipeline_cache_data, "vkGetPipelineCacheData", VkResult, (device, cache: VkPipelineCache, p_size: *mut usize, p_data: *mut c_void));
dev_thunk!(vk_merge_pipeline_caches, "vkMergePipelineCaches", VkResult, (device, dst: VkPipelineCache, src_count: u32, p_src: *const VkPipelineCache));
dev_thunk!(vk_create_buffer, "vkCreateBuffer", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_buffer: *mut VkBuffer));
dev_thunk!(void vk_destroy_buffer, "vkDestroyBuffer", (device, buffer: VkBuffer, p_allocator: *const c_void));
pub unsafe extern "win64" fn vk_create_image(
    device: VkDevice,
    p_info: *const c_void,
    p_allocator: *const c_void,
    p_image: *mut VkImage,
) -> VkResult {
    // VkImageCreateInfo offsets (spec, 64-bit):
    //   0: sType(u32), 8: pNext(*), 16: flags(u32), 20: imageType(u32),
    //   24: format(u32), 28: extent.width(u32), 32: extent.height(u32)
    if d3d9_trace_enabled() && !p_info.is_null() {
        let base = p_info as *const u8;
        let fmt = unsafe { (base.add(24) as *const u32).read() };
        let w = unsafe { (base.add(28) as *const u32).read() };
        let h = unsafe { (base.add(32) as *const u32).read() };
        d3d9_trace!("vkCreateImage fmt={fmt} {w}x{h}");
    }
    let f = real_device_fn(device, "vkCreateImage");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkDevice, *const c_void, *const c_void, *mut VkImage) -> VkResult =
        unsafe { std::mem::transmute(f) };
    unsafe { f(device, p_info, p_allocator, p_image) }
}
dev_thunk!(void vk_destroy_image, "vkDestroyImage", (device, image: VkImage, p_allocator: *const c_void));
dev_thunk!(void vk_get_image_subresource_layout, "vkGetImageSubresourceLayout", (device, image: VkImage, p_subresource: *const c_void, p_layout: *mut c_void));
dev_thunk!(vk_create_image_view, "vkCreateImageView", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_view: *mut VkImageView));
dev_thunk!(void vk_destroy_image_view, "vkDestroyImageView", (device, image_view: VkImageView, p_allocator: *const c_void));
dev_thunk!(vk_create_buffer_view, "vkCreateBufferView", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_view: *mut VkBufferView));
dev_thunk!(void vk_destroy_buffer_view, "vkDestroyBufferView", (device, buffer_view: VkBufferView, p_allocator: *const c_void));
dev_thunk!(vk_create_shader_module, "vkCreateShaderModule", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_module: *mut VkShaderModule));
dev_thunk!(void vk_destroy_shader_module, "vkDestroyShaderModule", (device, module: VkShaderModule, p_allocator: *const c_void));
dev_thunk!(vk_create_pipeline_cache, "vkCreatePipelineCache", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_cache: *mut VkPipelineCache));
dev_thunk!(void vk_destroy_pipeline_cache, "vkDestroyPipelineCache", (device, cache: VkPipelineCache, p_allocator: *const c_void));
dev_thunk!(vk_create_graphics_pipelines, "vkCreateGraphicsPipelines", VkResult, (device, cache: VkPipelineCache, count: u32, p_infos: *const c_void, p_allocator: *const c_void, p_pipelines: *mut VkPipeline));
dev_thunk!(vk_create_compute_pipelines, "vkCreateComputePipelines", VkResult, (device, cache: VkPipelineCache, count: u32, p_infos: *const c_void, p_allocator: *const c_void, p_pipelines: *mut VkPipeline));
dev_thunk!(void vk_destroy_pipeline, "vkDestroyPipeline", (device, pipeline: VkPipeline, p_allocator: *const c_void));
dev_thunk!(vk_create_pipeline_layout, "vkCreatePipelineLayout", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_layout: *mut VkPipelineLayout));
dev_thunk!(void vk_destroy_pipeline_layout, "vkDestroyPipelineLayout", (device, layout: VkPipelineLayout, p_allocator: *const c_void));
dev_thunk!(vk_create_sampler, "vkCreateSampler", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_sampler: *mut VkSampler));
dev_thunk!(void vk_destroy_sampler, "vkDestroySampler", (device, sampler: VkSampler, p_allocator: *const c_void));
dev_thunk!(vk_create_descriptor_set_layout, "vkCreateDescriptorSetLayout", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_set_layout: *mut VkDescriptorSetLayout));
dev_thunk!(void vk_destroy_descriptor_set_layout, "vkDestroyDescriptorSetLayout", (device, descriptor_set_layout: VkDescriptorSetLayout, p_allocator: *const c_void));
dev_thunk!(vk_create_descriptor_pool, "vkCreateDescriptorPool", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_descriptor_pool: *mut VkDescriptorPool));
dev_thunk!(void vk_destroy_descriptor_pool, "vkDestroyDescriptorPool", (device, descriptor_pool: VkDescriptorPool, p_allocator: *const c_void));
dev_thunk!(vk_reset_descriptor_pool, "vkResetDescriptorPool", VkResult, (device, descriptor_pool: VkDescriptorPool, flags: VkDescriptorPoolResetFlags));
dev_thunk!(vk_allocate_descriptor_sets, "vkAllocateDescriptorSets", VkResult, (device, p_info: *const c_void, p_descriptor_sets: *mut VkDescriptorSet));
dev_thunk!(vk_free_descriptor_sets, "vkFreeDescriptorSets", VkResult, (device, descriptor_pool: VkDescriptorPool, descriptor_set_count: u32, p_descriptor_sets: *const VkDescriptorSet));
/// # Safety
/// Caller must ensure all pointer arguments are valid.
pub unsafe extern "win64" fn vk_update_descriptor_sets(
    device: VkDevice,
    write_count: u32,
    p_writes: *const c_void,
    copy_count: u32,
    p_copies: *const c_void,
) {
    if d3d9_desc_trace_enabled() && write_count > 0 && !p_writes.is_null() {
        for i in 0..write_count.min(16) {
            let p_write = unsafe { (p_writes as *const u8).add(i as usize * 64) };
            unsafe { d3d9_desc_log_write(p_write, i) };
        }
    }
    let f = real_device_fn(device, "vkUpdateDescriptorSets");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkDevice, u32, *const c_void, u32, *const c_void) =
        unsafe { std::mem::transmute(f) };
    unsafe { f(device, write_count, p_writes, copy_count, p_copies) }
}
dev_thunk!(vk_create_descriptor_update_template, "vkCreateDescriptorUpdateTemplate", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_descriptor_update_template: *mut VkDescriptorUpdateTemplate));
dev_thunk!(void vk_destroy_descriptor_update_template, "vkDestroyDescriptorUpdateTemplate", (device, descriptor_update_template: VkDescriptorUpdateTemplate, p_allocator: *const c_void));
dev_thunk!(void vk_update_descriptor_set_with_template, "vkUpdateDescriptorSetWithTemplate", (device, descriptor_set: VkDescriptorSet, descriptor_update_template: VkDescriptorUpdateTemplate, p_data: *const c_void));
dev_thunk!(vk_create_render_pass, "vkCreateRenderPass", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_render_pass: *mut VkRenderPass));
dev_thunk!(vk_create_render_pass2, "vkCreateRenderPass2", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_render_pass: *mut VkRenderPass));
dev_thunk!(void vk_destroy_render_pass, "vkDestroyRenderPass", (device, render_pass: VkRenderPass, p_allocator: *const c_void));
dev_thunk!(vk_create_framebuffer, "vkCreateFramebuffer", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_framebuffer: *mut VkFramebuffer));
dev_thunk!(void vk_destroy_framebuffer, "vkDestroyFramebuffer", (device, framebuffer: VkFramebuffer, p_allocator: *const c_void));
dev_thunk!(vk_create_command_pool, "vkCreateCommandPool", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_command_pool: *mut VkCommandPool));
dev_thunk!(void vk_destroy_command_pool, "vkDestroyCommandPool", (device, command_pool: VkCommandPool, p_allocator: *const c_void));
dev_thunk!(vk_reset_command_pool, "vkResetCommandPool", VkResult, (device, command_pool: VkCommandPool, flags: VkCommandPoolResetFlags));
dev_thunk!(vk_allocate_command_buffers, "vkAllocateCommandBuffers", VkResult, (device, p_info: *const c_void, p_command_buffers: *mut VkCommandBuffer));
dev_thunk!(void vk_free_command_buffers, "vkFreeCommandBuffers", (device, command_pool: VkCommandPool, command_buffer_count: u32, p_command_buffers: *const VkCommandBuffer));
dev_thunk!(vk_create_fence, "vkCreateFence", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_fence: *mut VkFence));
dev_thunk!(void vk_destroy_fence, "vkDestroyFence", (device, fence: VkFence, p_allocator: *const c_void));
dev_thunk!(vk_reset_fences, "vkResetFences", VkResult, (device, fence_count: u32, p_fences: *const VkFence));
dev_thunk!(vk_get_fence_status, "vkGetFenceStatus", VkResult, (device, fence: VkFence));
dev_thunk!(vk_wait_for_fences, "vkWaitForFences", VkResult, (device, fence_count: u32, p_fences: *const VkFence, wait_all: u32, timeout: u64));
dev_thunk!(vk_create_semaphore, "vkCreateSemaphore", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_semaphore: *mut VkSemaphore));
dev_thunk!(void vk_destroy_semaphore, "vkDestroySemaphore", (device, semaphore: VkSemaphore, p_allocator: *const c_void));
dev_thunk!(vk_get_semaphore_counter_value, "vkGetSemaphoreCounterValue", VkResult, (device, semaphore: VkSemaphore, p_value: *mut u64));
dev_thunk!(vk_wait_semaphores, "vkWaitSemaphores", VkResult, (device, p_wait_info: *const c_void, timeout: u64));
dev_thunk!(vk_signal_semaphore, "vkSignalSemaphore", VkResult, (device, p_signal_info: *const c_void));
dev_thunk!(vk_create_event, "vkCreateEvent", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_event: *mut VkEvent));
dev_thunk!(void vk_destroy_event, "vkDestroyEvent", (device, event: VkEvent, p_allocator: *const c_void));
dev_thunk!(vk_get_event_status, "vkGetEventStatus", VkResult, (device, event: VkEvent));
dev_thunk!(vk_set_event, "vkSetEvent", VkResult, (device, event: VkEvent));
dev_thunk!(vk_reset_event, "vkResetEvent", VkResult, (device, event: VkEvent));
dev_thunk!(vk_create_query_pool, "vkCreateQueryPool", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_query_pool: *mut VkQueryPool));
dev_thunk!(void vk_destroy_query_pool, "vkDestroyQueryPool", (device, query_pool: VkQueryPool, p_allocator: *const c_void));
dev_thunk!(vk_get_query_pool_results, "vkGetQueryPoolResults", VkResult, (device, query_pool: VkQueryPool, first_query: u32, query_count: u32, data_size: usize, p_data: *mut c_void, stride: VkDeviceSize, flags: VkQueryResultFlags));
dev_thunk!(void vk_reset_query_pool, "vkResetQueryPool", (device, query_pool: VkQueryPool, first_query: u32, query_count: u32));
pub unsafe extern "win64" fn vk_create_swapchain_khr(
    device: VkDevice,
    p_info: *const c_void,
    p_allocator: *const c_void,
    p_swapchain: *mut VkSwapchainKHR,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_create_swapchain_khr ENTER device={:p} p_info={p_info:p} p_swapchain={p_swapchain:p}",
        device as *const ()
    );
    // Log D3D9 CreateDevice-equivalent parameters: backbuffer format, extent, present mode.
    // VkSwapchainCreateInfoKHR field offsets (Vulkan spec, 64-bit):
    //   36: imageFormat (u32), 44: imageExtent.width (u32), 48: imageExtent.height (u32),
    //   88: presentMode (u32)
    if !p_info.is_null() {
        let base = p_info as *const u8;
        let img_fmt = unsafe { (base.add(36) as *const u32).read() };
        let img_w = unsafe { (base.add(44) as *const u32).read() };
        let img_h = unsafe { (base.add(48) as *const u32).read() };
        D3D9_LAST_DEVICE.store(device as u64, Ordering::Relaxed);
        D3D9_SWAP_W.store(img_w, Ordering::Relaxed);
        D3D9_SWAP_H.store(img_h, Ordering::Relaxed);
        if d3d9_trace_enabled() {
            let present_mode = unsafe { (base.add(88) as *const u32).read() };
            d3d9_trace!(
                "vkCreateSwapchainKHR fmt={img_fmt} extent={img_w}x{img_h} present_mode={present_mode}"
            );
        }
    }
    let f = real_device_fn(device, "vkCreateSwapchainKHR");
    if f.is_null() {
        eprintln!("weave-vulkan: vk_create_swapchain_khr: real fn NULL");
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(
        VkDevice,
        *const c_void,
        *const c_void,
        *mut VkSwapchainKHR,
    ) -> VkResult = unsafe { std::mem::transmute(f) };
    eprintln!("weave-vulkan: vk_create_swapchain_khr: calling real");
    let r = unsafe { f(device, p_info, p_allocator, p_swapchain) };
    eprintln!(
        "weave-vulkan: vk_create_swapchain_khr RETURN {r}, swapchain=0x{:x}",
        if p_swapchain.is_null() {
            0
        } else {
            unsafe { *p_swapchain }
        }
    );
    r
}
dev_thunk!(void vk_destroy_swapchain_khr, "vkDestroySwapchainKHR", (device, swapchain: VkSwapchainKHR, p_allocator: *const c_void));
pub unsafe extern "win64" fn vk_get_swapchain_images_khr(
    device: VkDevice,
    swapchain: VkSwapchainKHR,
    p_count: *mut u32,
    p_images: *mut VkImage,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_get_swapchain_images_khr ENTER swapchain=0x{swapchain:x} p_images={p_images:p}"
    );
    let f = real_device_fn(device, "vkGetSwapchainImagesKHR");
    if f.is_null() {
        return unsafe { std::mem::zeroed() };
    }
    let f: unsafe extern "C" fn(VkDevice, VkSwapchainKHR, *mut u32, *mut VkImage) -> VkResult =
        unsafe { std::mem::transmute(f) };
    let r = unsafe { f(device, swapchain, p_count, p_images) };
    eprintln!("weave-vulkan: vk_get_swapchain_images_khr RETURN {r}");
    r
}
dev_thunk!(vk_acquire_next_image_khr, "vkAcquireNextImageKHR", VkResult, (device, swapchain: VkSwapchainKHR, timeout: u64, semaphore: VkSemaphore, fence: VkFence, p_image_index: *mut u32));
dev_thunk!(vk_acquire_next_image2_khr, "vkAcquireNextImage2KHR", VkResult, (device, p_info: *const c_void, p_image_index: *mut u32));
dev_thunk!(vk_get_device_group_present_capabilities_khr, "vkGetDeviceGroupPresentCapabilitiesKHR", VkResult, (device, p_device_group_present_capabilities: *mut c_void));
dev_thunk!(vk_get_device_group_surface_present_modes_khr, "vkGetDeviceGroupSurfacePresentModesKHR", VkResult, (device, surface: VkSurfaceKHR, p_modes: *mut u32));
dev_thunk!(vk_get_device_group_surface_present_modes2_ext, "vkGetDeviceGroupSurfacePresentModes2EXT", VkResult, (device, p_surface_info: *const c_void, p_modes: *mut u32));
dev_thunk!(vk_acquire_full_screen_exclusive_mode_ext, "vkAcquireFullScreenExclusiveModeEXT", VkResult, (device, swapchain: VkSwapchainKHR));
dev_thunk!(vk_release_full_screen_exclusive_mode_ext, "vkReleaseFullScreenExclusiveModeEXT", VkResult, (device, swapchain: VkSwapchainKHR));
dev_thunk!(void vk_get_device_memory_commitment, "vkGetDeviceMemoryCommitment", (device, memory: VkDeviceMemory, p_committed: *mut VkDeviceSize));
dev_thunk!(vk_get_device_memory_opaque_capture_address, "vkGetDeviceMemoryOpaqueCaptureAddress", VkDeviceAddress, (device, p_info: *const c_void));
dev_thunk!(vk_get_buffer_device_address, "vkGetBufferDeviceAddress", VkDeviceAddress, (device, p_info: *const c_void));
dev_thunk!(vk_get_buffer_opaque_capture_address, "vkGetBufferOpaqueCaptureAddress", u64, (device, p_info: *const c_void));
dev_thunk!(void vk_get_render_area_granularity, "vkGetRenderAreaGranularity", (device, render_pass: VkRenderPass, p_granularity: *mut c_void));
dev_thunk!(void vk_get_rendering_area_granularity_khr, "vkGetRenderingAreaGranularityKHR", (device, p_rendering_area_info: *const c_void, p_granularity: *mut c_void));
dev_thunk!(void vk_get_device_image_subresource_layout_khr, "vkGetDeviceImageSubresourceLayoutKHR", (device, p_info: *const c_void, p_layout: *mut c_void));
dev_thunk!(void vk_get_image_subresource_layout2_khr, "vkGetImageSubresourceLayout2KHR", (device, image: VkImage, p_subresource: *const c_void, p_layout: *mut c_void));
dev_thunk!(vk_get_calibrated_timestamps_ext, "vkGetCalibratedTimestampsEXT", VkResult, (device, timestamp_count: u32, p_timestamp_infos: *const c_void, p_timestamps: *mut u64, p_max_deviation: *mut u64));
dev_thunk!(vk_create_private_data_slot, "vkCreatePrivateDataSlot", VkResult, (device, p_info: *const c_void, p_allocator: *const c_void, p_private_data_slot: *mut u64));
dev_thunk!(void vk_destroy_private_data_slot, "vkDestroyPrivateDataSlot", (device, private_data_slot: u64, p_allocator: *const c_void));
dev_thunk!(vk_set_private_data, "vkSetPrivateData", VkResult, (device, object_type: u32, object_handle: u64, private_data_slot: u64, data: u64));
dev_thunk!(void vk_get_private_data, "vkGetPrivateData", (device, object_type: u32, object_handle: u64, private_data_slot: u64, p_data: *mut u64));
dev_thunk!(void vk_set_hdr_metadata_ext, "vkSetHdrMetadataEXT", (device, swapchain_count: u32, p_swapchains: *const VkSwapchainKHR, p_metadata: *const c_void));
dev_thunk!(vk_wait_for_present_khr, "vkWaitForPresentKHR", VkResult, (device, swapchain: VkSwapchainKHR, present_id: u64, timeout: u64));
dev_thunk!(vk_get_memory_win32_handle_khr, "vkGetMemoryWin32HandleKHR", VkResult, (device, p_info: *const c_void, p_handle: *mut c_void));
dev_thunk!(vk_get_memory_win32_handle_properties_khr, "vkGetMemoryWin32HandlePropertiesKHR", VkResult, (device, handle_type: u32, handle: *mut c_void, p_memory_win32_handle_properties: *mut c_void));
dev_thunk!(vk_get_semaphore_win32_handle_khr, "vkGetSemaphoreWin32HandleKHR", VkResult, (device, p_info: *const c_void, p_handle: *mut c_void));
dev_thunk!(vk_import_semaphore_win32_handle_khr, "vkImportSemaphoreWin32HandleKHR", VkResult, (device, p_info: *const c_void));

// Command buffer functions (use stored instance for dispatch)
cmd_thunk!(void vk_begin_command_buffer, "vkBeginCommandBuffer", (command_buffer, p_begin_info: *const c_void));
cmd_thunk!(
    vk_end_command_buffer,
    "vkEndCommandBuffer",
    VkResult,
    (command_buffer,)
);
cmd_thunk!(vk_reset_command_buffer, "vkResetCommandBuffer", VkResult, (command_buffer, flags: VkCommandBufferResetFlags));
cmd_thunk!(void vk_cmd_bind_pipeline, "vkCmdBindPipeline", (command_buffer, pipeline_bind_point: VkPipelineBindPoint, pipeline: VkPipeline));
cmd_thunk!(void vk_cmd_set_viewport, "vkCmdSetViewport", (command_buffer, first_viewport: u32, viewport_count: u32, p_viewports: *const c_void));
cmd_thunk!(void vk_cmd_set_scissor, "vkCmdSetScissor", (command_buffer, first_scissor: u32, scissor_count: u32, p_scissors: *const c_void));
cmd_thunk!(void vk_cmd_set_line_width, "vkCmdSetLineWidth", (command_buffer, line_width: f32));
cmd_thunk!(void vk_cmd_set_depth_bias, "vkCmdSetDepthBias", (command_buffer, depth_bias_constant_factor: f32, depth_bias_clamp: f32, depth_bias_slope_factor: f32));
cmd_thunk!(void vk_cmd_set_blend_constants, "vkCmdSetBlendConstants", (command_buffer, blend_constants: *const f32));
cmd_thunk!(void vk_cmd_set_depth_bounds, "vkCmdSetDepthBounds", (command_buffer, min_depth_bounds: f32, max_depth_bounds: f32));
cmd_thunk!(void vk_cmd_set_stencil_compare_mask, "vkCmdSetStencilCompareMask", (command_buffer, face_mask: VkStencilFaceFlags, compare_mask: u32));
cmd_thunk!(void vk_cmd_set_stencil_write_mask, "vkCmdSetStencilWriteMask", (command_buffer, face_mask: VkStencilFaceFlags, write_mask: u32));
cmd_thunk!(void vk_cmd_set_stencil_reference, "vkCmdSetStencilReference", (command_buffer, face_mask: VkStencilFaceFlags, reference: u32));
/// # Safety
/// Caller must ensure all pointer arguments are valid.
pub unsafe extern "win64" fn vk_cmd_bind_descriptor_sets(
    command_buffer: VkCommandBuffer,
    pipeline_bind_point: VkPipelineBindPoint,
    layout: VkPipelineLayout,
    first_set: u32,
    descriptor_set_count: u32,
    p_descriptor_sets: *const VkDescriptorSet,
    dynamic_offset_count: u32,
    p_dynamic_offsets: *const u32,
) {
    if d3d9_desc_trace_enabled() && descriptor_set_count > 0 && !p_descriptor_sets.is_null() {
        let presents = D3D9_PRESENT_COUNT.load(Ordering::Relaxed);
        let t = d3d9_trace_ms();
        D3D9_DESC_LAST_BIND_LAYOUT.store(layout, Ordering::Relaxed);
        for i in 0..descriptor_set_count.min(4) {
            let set = unsafe { p_descriptor_sets.add(i as usize).read() };
            if i == 0 {
                D3D9_DESC_LAST_BIND_SET.store(set, Ordering::Relaxed);
            }
            eprintln!(
                "weave/d3d9-desc t={t}ms presents={presents} BindDescriptorSets \
                 bindPoint={pipeline_bind_point} layout=0x{layout:x} firstSet={first_set} \
                 set[{i}]=0x{set:x} dynamicOffsets={dynamic_offset_count}"
            );
        }
    }
    let f = real_fn(stored_instance(), "vkCmdBindDescriptorSets");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(
        VkCommandBuffer,
        VkPipelineBindPoint,
        VkPipelineLayout,
        u32,
        u32,
        *const VkDescriptorSet,
        u32,
        *const u32,
    ) = unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            pipeline_bind_point,
            layout,
            first_set,
            descriptor_set_count,
            p_descriptor_sets,
            dynamic_offset_count,
            p_dynamic_offsets,
        )
    }
}
cmd_thunk!(void vk_cmd_bind_index_buffer, "vkCmdBindIndexBuffer", (command_buffer, buffer: VkBuffer, offset: VkDeviceSize, index_type: VkIndexType));
cmd_thunk!(void vk_cmd_bind_index_buffer2_khr, "vkCmdBindIndexBuffer2KHR", (command_buffer, buffer: VkBuffer, offset: VkDeviceSize, size: VkDeviceSize, index_type: VkIndexType));
cmd_thunk!(void vk_cmd_bind_vertex_buffers, "vkCmdBindVertexBuffers", (command_buffer, first_binding: u32, binding_count: u32, p_buffers: *const VkBuffer, p_offsets: *const VkDeviceSize));
cmd_thunk!(void vk_cmd_bind_vertex_buffers2, "vkCmdBindVertexBuffers2", (command_buffer, first_binding: u32, binding_count: u32, p_buffers: *const VkBuffer, p_offsets: *const VkDeviceSize, p_sizes: *const VkDeviceSize, p_strides: *const VkDeviceSize));
cmd_thunk!(void vk_cmd_set_cull_mode, "vkCmdSetCullMode", (command_buffer, cull_mode: u32));
cmd_thunk!(void vk_cmd_set_front_face, "vkCmdSetFrontFace", (command_buffer, front_face: u32));
cmd_thunk!(void vk_cmd_set_primitive_topology, "vkCmdSetPrimitiveTopology", (command_buffer, primitive_topology: u32));
cmd_thunk!(void vk_cmd_set_viewport_with_count, "vkCmdSetViewportWithCount", (command_buffer, viewport_count: u32, p_viewports: *const c_void));
cmd_thunk!(void vk_cmd_set_scissor_with_count, "vkCmdSetScissorWithCount", (command_buffer, scissor_count: u32, p_scissors: *const c_void));
cmd_thunk!(void vk_cmd_set_depth_test_enable, "vkCmdSetDepthTestEnable", (command_buffer, depth_test_enable: u32));
cmd_thunk!(void vk_cmd_set_depth_write_enable, "vkCmdSetDepthWriteEnable", (command_buffer, depth_write_enable: u32));
cmd_thunk!(void vk_cmd_set_depth_compare_op, "vkCmdSetDepthCompareOp", (command_buffer, depth_compare_op: u32));
cmd_thunk!(void vk_cmd_set_depth_bounds_test_enable, "vkCmdSetDepthBoundsTestEnable", (command_buffer, depth_bounds_test_enable: u32));
cmd_thunk!(void vk_cmd_set_stencil_test_enable, "vkCmdSetStencilTestEnable", (command_buffer, stencil_test_enable: u32));
cmd_thunk!(void vk_cmd_set_stencil_op, "vkCmdSetStencilOp", (command_buffer, face_mask: VkStencilFaceFlags, fail_op: u32, pass_op: u32, depth_fail_op: u32, compare_op: u32));
cmd_thunk!(void vk_cmd_set_rasterizer_discard_enable, "vkCmdSetRasterizerDiscardEnable", (command_buffer, rasterizer_discard_enable: u32));
cmd_thunk!(void vk_cmd_set_depth_bias_enable, "vkCmdSetDepthBiasEnable", (command_buffer, depth_bias_enable: u32));
cmd_thunk!(void vk_cmd_set_primitive_restart_enable, "vkCmdSetPrimitiveRestartEnable", (command_buffer, primitive_restart_enable: u32));
pub unsafe extern "win64" fn vk_cmd_draw(
    command_buffer: VkCommandBuffer,
    vertex_count: u32,
    instance_count: u32,
    first_vertex: u32,
    first_instance: u32,
) {
    let seq = if d3d9_trace_enabled() {
        Some(D3D9_DRAW_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
    } else {
        None
    };
    if let Some(seq) = seq {
        d3d9_trace!(
            "vkCmdDraw#{seq} vertices={vertex_count} instances={instance_count} first_vertex={first_vertex} first_instance={first_instance}"
        );
    }
    if d3d9_desc_trace_enabled()
        && (vertex_count == 3 || D3D9_PRESENT_COUNT.load(Ordering::Relaxed) >= 1)
    {
        eprintln!(
            "weave/d3d9-desc t={}ms presents={} vkCmdDraw vertices={} \
             lastBindSet=0x{:x} lastBindLayout=0x{:x} \
             lastUpdateImageView=0x{:x} lastUpdateSampler=0x{:x} lastUpdateBinding={}",
            d3d9_trace_ms(),
            D3D9_PRESENT_COUNT.load(Ordering::Relaxed),
            vertex_count,
            D3D9_DESC_LAST_BIND_SET.load(Ordering::Relaxed),
            D3D9_DESC_LAST_BIND_LAYOUT.load(Ordering::Relaxed),
            D3D9_DESC_LAST_UPDATE_IMAGEVIEW.load(Ordering::Relaxed),
            D3D9_DESC_LAST_UPDATE_SAMPLER.load(Ordering::Relaxed),
            D3D9_DESC_LAST_UPDATE_BINDING.load(Ordering::Relaxed),
        );
    }
    let f = real_fn(stored_instance(), "vkCmdDraw");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, u32, u32, u32, u32) =
        unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            vertex_count,
            instance_count,
            first_vertex,
            first_instance,
        )
    }
}

pub unsafe extern "win64" fn vk_cmd_draw_indexed(
    command_buffer: VkCommandBuffer,
    index_count: u32,
    instance_count: u32,
    first_index: u32,
    vertex_offset: i32,
    first_instance: u32,
) {
    let seq = if d3d9_trace_enabled() {
        Some(D3D9_DRAW_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
    } else {
        None
    };
    if let Some(seq) = seq {
        d3d9_trace!(
            "vkCmdDrawIndexed#{seq} indices={index_count} instances={instance_count} first_index={first_index} vertex_offset={vertex_offset} first_instance={first_instance}"
        );
    }
    let f = real_fn(stored_instance(), "vkCmdDrawIndexed");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, u32, u32, u32, i32, u32) =
        unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            index_count,
            instance_count,
            first_index,
            vertex_offset,
            first_instance,
        )
    }
}
cmd_thunk!(void vk_cmd_draw_indirect, "vkCmdDrawIndirect", (command_buffer, buffer: VkBuffer, offset: VkDeviceSize, draw_count: u32, stride: u32));
cmd_thunk!(void vk_cmd_draw_indirect_count, "vkCmdDrawIndirectCount", (command_buffer, buffer: VkBuffer, offset: VkDeviceSize, count_buffer: VkBuffer, count_buffer_offset: VkDeviceSize, max_draw_count: u32, stride: u32));
cmd_thunk!(void vk_cmd_draw_indexed_indirect, "vkCmdDrawIndexedIndirect", (command_buffer, buffer: VkBuffer, offset: VkDeviceSize, draw_count: u32, stride: u32));
cmd_thunk!(void vk_cmd_draw_indexed_indirect_count, "vkCmdDrawIndexedIndirectCount", (command_buffer, buffer: VkBuffer, offset: VkDeviceSize, count_buffer: VkBuffer, count_buffer_offset: VkDeviceSize, max_draw_count: u32, stride: u32));
cmd_thunk!(void vk_cmd_dispatch, "vkCmdDispatch", (command_buffer, group_count_x: u32, group_count_y: u32, group_count_z: u32));
cmd_thunk!(void vk_cmd_dispatch_indirect, "vkCmdDispatchIndirect", (command_buffer, buffer: VkBuffer, offset: VkDeviceSize));
cmd_thunk!(void vk_cmd_copy_buffer, "vkCmdCopyBuffer", (command_buffer, src_buffer: VkBuffer, dst_buffer: VkBuffer, region_count: u32, p_regions: *const c_void));
cmd_thunk!(void vk_cmd_copy_buffer2, "vkCmdCopyBuffer2", (command_buffer, p_copy_buffer_info: *const c_void));
cmd_thunk!(void vk_cmd_copy_image, "vkCmdCopyImage", (command_buffer, src_image: VkImage, src_layout: u32, dst_image: VkImage, dst_layout: u32, region_count: u32, p_regions: *const c_void));
cmd_thunk!(void vk_cmd_copy_image2, "vkCmdCopyImage2", (command_buffer, p_copy_image_info: *const c_void));
pub unsafe extern "win64" fn vk_cmd_blit_image(
    command_buffer: VkCommandBuffer,
    src_image: VkImage,
    src_layout: u32,
    dst_image: VkImage,
    dst_layout: u32,
    region_count: u32,
    p_regions: *const c_void,
    filter: u32,
) {
    if d3d9_blit_trace_enabled() {
        let seq = D3D9_PRESENT_COUNT.load(Ordering::Relaxed);
        // VkImageBlit layout (spec, 64-bit):
        //   srcSubresource: VkImageSubresourceLayers (4×u32 = 16 bytes)
        //   srcOffsets[2]:  2×VkOffset3D (2×12 bytes = 24 bytes)
        //   dstSubresource: VkImageSubresourceLayers (16 bytes)
        //   dstOffsets[2]:  2×VkOffset3D (24 bytes)
        // Total stride = 16+24+16+24 = 80 bytes per region.
        // src extent = srcOffsets[1] - srcOffsets[0]; offsets at byte 16.
        // dst extent = dstOffsets[1] - dstOffsets[0]; offsets at byte 16+24+16 = 56.
        if !p_regions.is_null() && region_count > 0 {
            let base = p_regions as *const u8;
            let src_x1 = unsafe { (base.add(16) as *const i32).read() };
            let src_y1 = unsafe { (base.add(20) as *const i32).read() };
            let src_x2 = unsafe { (base.add(28) as *const i32).read() };
            let src_y2 = unsafe { (base.add(32) as *const i32).read() };
            let dst_x1 = unsafe { (base.add(56) as *const i32).read() };
            let dst_y1 = unsafe { (base.add(60) as *const i32).read() };
            let dst_x2 = unsafe { (base.add(68) as *const i32).read() };
            let dst_y2 = unsafe { (base.add(72) as *const i32).read() };
            let src_w = src_x2 - src_x1;
            let src_h = src_y2 - src_y1;
            let dst_w = dst_x2 - dst_x1;
            let dst_h = dst_y2 - dst_y1;
            eprintln!(
                "weave/d3d9-blit vkCmdBlitImage presents={seq} t={}ms \
                 src=0x{src_image:x} src_layout={src_layout} src_extent={src_w}x{src_h} \
                 dst=0x{dst_image:x} dst_layout={dst_layout} dst_extent={dst_w}x{dst_h} \
                 regions={region_count} filter={filter}",
                d3d9_trace_ms()
            );
        } else {
            eprintln!(
                "weave/d3d9-blit vkCmdBlitImage presents={seq} t={}ms \
                 src=0x{src_image:x} dst=0x{dst_image:x} regions={region_count} p_regions=null-or-zero",
                d3d9_trace_ms()
            );
        }
    }
    let f = real_fn(stored_instance(), "vkCmdBlitImage");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(
        VkCommandBuffer,
        VkImage,
        u32,
        VkImage,
        u32,
        u32,
        *const c_void,
        u32,
    ) = unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            src_image,
            src_layout,
            dst_image,
            dst_layout,
            region_count,
            p_regions,
            filter,
        )
    }
}
pub unsafe extern "win64" fn vk_cmd_blit_image2(
    command_buffer: VkCommandBuffer,
    p_blit_image_info: *const c_void,
) {
    if d3d9_blit_trace_enabled() {
        let seq = D3D9_PRESENT_COUNT.load(Ordering::Relaxed);
        // VkBlitImageInfo2 layout (spec, 64-bit):
        //   0:  sType(u32), 4: pad, 8: pNext(*), 16: srcImage(u64), 24: srcImageLayout(u32),
        //   28: pad, 32: dstImage(u64), 40: dstImageLayout(u32), 44: regionCount(u32),
        //   48: pRegions(*)
        // VkImageBlit2 has the same geometry as VkImageBlit plus a sType+pNext header (16 bytes).
        // src offsets at byte 16+16=32; dst offsets at byte 16+16+24+16=72.
        if !p_blit_image_info.is_null() {
            let base = p_blit_image_info as *const u8;
            let src_image = unsafe { (base.add(16) as *const u64).read() };
            let src_layout = unsafe { (base.add(24) as *const u32).read() };
            let dst_image = unsafe { (base.add(32) as *const u64).read() };
            let dst_layout = unsafe { (base.add(40) as *const u32).read() };
            let region_count = unsafe { (base.add(44) as *const u32).read() };
            let p_regions_ptr = unsafe { (base.add(48) as *const *const u8).read() };
            let (src_w, src_h, dst_w, dst_h) = if !p_regions_ptr.is_null() && region_count > 0 {
                // VkImageBlit2: sType(u32)+pad(4)+pNext(*ptr) = 16 bytes header,
                // then same layout as VkImageBlit: srcSubresource(16)+srcOffsets(24)+dstSubresource(16)+dstOffsets(24)
                let r = p_regions_ptr;
                let sx1 = unsafe { (r.add(32) as *const i32).read() };
                let sy1 = unsafe { (r.add(36) as *const i32).read() };
                let sx2 = unsafe { (r.add(44) as *const i32).read() };
                let sy2 = unsafe { (r.add(48) as *const i32).read() };
                let dx1 = unsafe { (r.add(72) as *const i32).read() };
                let dy1 = unsafe { (r.add(76) as *const i32).read() };
                let dx2 = unsafe { (r.add(84) as *const i32).read() };
                let dy2 = unsafe { (r.add(88) as *const i32).read() };
                (sx2 - sx1, sy2 - sy1, dx2 - dx1, dy2 - dy1)
            } else {
                (0, 0, 0, 0)
            };
            eprintln!(
                "weave/d3d9-blit vkCmdBlitImage2 presents={seq} t={}ms \
                 src=0x{src_image:x} src_layout={src_layout} src_extent={src_w}x{src_h} \
                 dst=0x{dst_image:x} dst_layout={dst_layout} dst_extent={dst_w}x{dst_h} \
                 regions={region_count}",
                d3d9_trace_ms()
            );
        } else {
            eprintln!(
                "weave/d3d9-blit vkCmdBlitImage2 presents={seq} t={}ms p_blit_image_info=null",
                d3d9_trace_ms()
            );
        }
    }
    let f = real_fn(stored_instance(), "vkCmdBlitImage2");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, *const c_void) = unsafe { std::mem::transmute(f) };
    unsafe { f(command_buffer, p_blit_image_info) }
}
pub unsafe extern "win64" fn vk_cmd_copy_buffer_to_image(
    command_buffer: VkCommandBuffer,
    src_buffer: VkBuffer,
    dst_image: VkImage,
    dst_layout: u32,
    region_count: u32,
    p_regions: *const c_void,
) {
    let seq = if d3d9_trace_enabled() {
        Some(D3D9_UPLOAD_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
    } else {
        None
    };
    if let Some(seq) = seq {
        d3d9_trace!(
            "vkCmdCopyBufferToImage#{seq} src=0x{src_buffer:x} dst=0x{dst_image:x} layout={dst_layout} regions={region_count}"
        );
    }
    let f = real_fn(stored_instance(), "vkCmdCopyBufferToImage");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, VkBuffer, VkImage, u32, u32, *const c_void) =
        unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            src_buffer,
            dst_image,
            dst_layout,
            region_count,
            p_regions,
        )
    }
}
pub unsafe extern "win64" fn vk_cmd_copy_buffer_to_image2(
    command_buffer: VkCommandBuffer,
    p_copy_buffer_to_image_info: *const c_void,
) {
    let seq = if d3d9_trace_enabled() {
        Some(D3D9_UPLOAD_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
    } else {
        None
    };
    if let Some(seq) = seq {
        d3d9_trace!("vkCmdCopyBufferToImage2#{seq}");
    }
    let f = real_fn(stored_instance(), "vkCmdCopyBufferToImage2");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, *const c_void) = unsafe { std::mem::transmute(f) };
    unsafe { f(command_buffer, p_copy_buffer_to_image_info) }
}
cmd_thunk!(void vk_cmd_copy_image_to_buffer, "vkCmdCopyImageToBuffer", (command_buffer, src_image: VkImage, src_layout: u32, dst_buffer: VkBuffer, region_count: u32, p_regions: *const c_void));
cmd_thunk!(void vk_cmd_copy_image_to_buffer2, "vkCmdCopyImageToBuffer2", (command_buffer, p_copy_image_to_buffer_info: *const c_void));
cmd_thunk!(void vk_cmd_update_buffer, "vkCmdUpdateBuffer", (command_buffer, dst_buffer: VkBuffer, dst_offset: VkDeviceSize, data_size: VkDeviceSize, p_data: *const c_void));
cmd_thunk!(void vk_cmd_fill_buffer, "vkCmdFillBuffer", (command_buffer, dst_buffer: VkBuffer, dst_offset: VkDeviceSize, size: VkDeviceSize, data: u32));
pub unsafe extern "win64" fn vk_cmd_clear_color_image(
    command_buffer: VkCommandBuffer,
    image: VkImage,
    image_layout: u32,
    p_color: *const c_void,
    range_count: u32,
    p_ranges: *const c_void,
) {
    let log_clear = d3d9_trace_enabled() || d3d9_clear_trace_enabled();
    let seq = if log_clear {
        D3D9_CLEAR_COUNT.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        0
    };
    if d3d9_trace_enabled() && log_clear {
        // VkClearColorValue is a [f32; 4] / [i32; 4] / [u32; 4] union — read as f32.
        let color_str = if !p_color.is_null() {
            let c = unsafe { std::ptr::read(p_color as *const [f32; 4]) };
            format!("[{:.3},{:.3},{:.3},{:.3}]", c[0], c[1], c[2], c[3])
        } else {
            "null".to_string()
        };
        d3d9_trace!(
            "vkCmdClearColorImage#{seq} image=0x{image:x} layout={image_layout} ranges={range_count} color={color_str}"
        );
    }
    if d3d9_clear_trace_enabled() {
        let color_str = if !p_color.is_null() {
            let c = unsafe { std::ptr::read(p_color as *const [f32; 4]) };
            format!("color=[{:.3},{:.3},{:.3},{:.3}]", c[0], c[1], c[2], c[3])
        } else {
            "color=null".to_string()
        };
        d3d9_clear_log(format!(
            "ClearColorImage#{seq} image=0x{image:x} layout={image_layout} ranges={range_count} {color_str}"
        ));
    }
    let f = real_fn(stored_instance(), "vkCmdClearColorImage");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, VkImage, u32, *const c_void, u32, *const c_void) =
        unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            image,
            image_layout,
            p_color,
            range_count,
            p_ranges,
        )
    }
}

pub unsafe extern "win64" fn vk_cmd_clear_depth_stencil_image(
    command_buffer: VkCommandBuffer,
    image: VkImage,
    image_layout: u32,
    p_depth_stencil: *const c_void,
    range_count: u32,
    p_ranges: *const c_void,
) {
    let seq = if d3d9_trace_enabled() {
        Some(D3D9_CLEAR_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
    } else {
        None
    };
    if let Some(seq) = seq {
        d3d9_trace!(
            "vkCmdClearDepthStencilImage#{seq} image=0x{image:x} layout={image_layout} ranges={range_count}"
        );
    }
    let f = real_fn(stored_instance(), "vkCmdClearDepthStencilImage");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, VkImage, u32, *const c_void, u32, *const c_void) =
        unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            image,
            image_layout,
            p_depth_stencil,
            range_count,
            p_ranges,
        )
    }
}

pub unsafe extern "win64" fn vk_cmd_clear_attachments(
    command_buffer: VkCommandBuffer,
    attachment_count: u32,
    p_attachments: *const c_void,
    rect_count: u32,
    p_rects: *const c_void,
) {
    let log_clear = d3d9_trace_enabled() || d3d9_clear_trace_enabled();
    let seq = if log_clear {
        D3D9_CLEAR_COUNT.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        0
    };
    if d3d9_trace_enabled() && log_clear {
        // VkClearAttachment layout: aspectMask(u32) + colorAttachment(u32) + clearValue([f32;4])
        // Total: 24 bytes per entry. clearValue starts at offset 8.
        let color_str = if !p_attachments.is_null() && attachment_count > 0 {
            let base = p_attachments as *const u8;
            let aspect = unsafe { (base as *const u32).read() };
            let color = unsafe { std::ptr::read(base.add(8) as *const [f32; 4]) };
            format!(
                "aspect=0x{aspect:x} color=[{:.3},{:.3},{:.3},{:.3}]",
                color[0], color[1], color[2], color[3]
            )
        } else {
            "null".to_string()
        };
        d3d9_trace!(
            "vkCmdClearAttachments#{seq} attachments={attachment_count} rects={rect_count} {color_str}"
        );
    }
    if d3d9_clear_trace_enabled() {
        let color_str = if !p_attachments.is_null() && attachment_count > 0 {
            let base = p_attachments as *const u8;
            let aspect = unsafe { (base as *const u32).read() };
            let color = unsafe { std::ptr::read(base.add(8) as *const [f32; 4]) };
            format!(
                "aspect=0x{aspect:x} color=[{:.3},{:.3},{:.3},{:.3}]",
                color[0], color[1], color[2], color[3]
            )
        } else {
            "color=null".to_string()
        };
        let rect_str = if !p_rects.is_null() && rect_count > 0 {
            let r = p_rects as *const u8;
            let x = unsafe { (r as *const i32).read() };
            let y = unsafe { (r.add(4) as *const i32).read() };
            let w = unsafe { (r.add(8) as *const u32).read() };
            let h = unsafe { (r.add(12) as *const u32).read() };
            format!(" rect[0]={x},{y},{w}x{h}")
        } else {
            String::new()
        };
        d3d9_clear_log(format!(
            "ClearAttachments#{seq} attachments={attachment_count} rects={rect_count} {color_str}{rect_str}"
        ));
    }
    let f = real_fn(stored_instance(), "vkCmdClearAttachments");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, u32, *const c_void, u32, *const c_void) =
        unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            attachment_count,
            p_attachments,
            rect_count,
            p_rects,
        )
    }
}
pub unsafe extern "win64" fn vk_cmd_resolve_image(
    command_buffer: VkCommandBuffer,
    src_image: VkImage,
    src_layout: u32,
    dst_image: VkImage,
    dst_layout: u32,
    region_count: u32,
    p_regions: *const c_void,
) {
    if d3d9_blit_trace_enabled() {
        let seq = D3D9_PRESENT_COUNT.load(Ordering::Relaxed);
        // VkImageResolve layout (spec, 64-bit):
        //   srcSubresource: VkImageSubresourceLayers (4×u32 = 16 bytes)
        //   srcOffset:      VkOffset3D (12 bytes)
        //   dstSubresource: VkImageSubresourceLayers (16 bytes)
        //   dstOffset:      VkOffset3D (12 bytes)
        //   extent:         VkExtent3D (12 bytes)
        // Total stride = 16+12+16+12+12 = 68 bytes.
        // extent.width at byte 16+12+16+12 = 56; extent.height at 60.
        if !p_regions.is_null() && region_count > 0 {
            let base = p_regions as *const u8;
            let ext_w = unsafe { (base.add(56) as *const u32).read() };
            let ext_h = unsafe { (base.add(60) as *const u32).read() };
            eprintln!(
                "weave/d3d9-blit vkCmdResolveImage presents={seq} t={}ms \
                 src=0x{src_image:x} src_layout={src_layout} \
                 dst=0x{dst_image:x} dst_layout={dst_layout} \
                 resolve_extent={ext_w}x{ext_h} regions={region_count}",
                d3d9_trace_ms()
            );
        } else {
            eprintln!(
                "weave/d3d9-blit vkCmdResolveImage presents={seq} t={}ms \
                 src=0x{src_image:x} dst=0x{dst_image:x} regions={region_count} p_regions=null-or-zero",
                d3d9_trace_ms()
            );
        }
    }
    let f = real_fn(stored_instance(), "vkCmdResolveImage");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, VkImage, u32, VkImage, u32, u32, *const c_void) =
        unsafe { std::mem::transmute(f) };
    unsafe {
        f(
            command_buffer,
            src_image,
            src_layout,
            dst_image,
            dst_layout,
            region_count,
            p_regions,
        )
    }
}
pub unsafe extern "win64" fn vk_cmd_resolve_image2(
    command_buffer: VkCommandBuffer,
    p_resolve_image_info: *const c_void,
) {
    if d3d9_blit_trace_enabled() {
        let seq = D3D9_PRESENT_COUNT.load(Ordering::Relaxed);
        // VkResolveImageInfo2 layout (spec, 64-bit):
        //   0:  sType(u32), 4: pad, 8: pNext(*), 16: srcImage(u64), 24: srcImageLayout(u32),
        //   28: pad, 32: dstImage(u64), 40: dstImageLayout(u32), 44: regionCount(u32),
        //   48: pRegions(*)
        // VkImageResolve2: sType(u32)+pad(4)+pNext(*) = 16-byte header, then same as VkImageResolve.
        // extent.width at byte 16+56=72; extent.height at 76.
        if !p_resolve_image_info.is_null() {
            let base = p_resolve_image_info as *const u8;
            let src_image = unsafe { (base.add(16) as *const u64).read() };
            let src_layout = unsafe { (base.add(24) as *const u32).read() };
            let dst_image = unsafe { (base.add(32) as *const u64).read() };
            let dst_layout = unsafe { (base.add(40) as *const u32).read() };
            let region_count = unsafe { (base.add(44) as *const u32).read() };
            let p_regions_ptr = unsafe { (base.add(48) as *const *const u8).read() };
            let (ext_w, ext_h) = if !p_regions_ptr.is_null() && region_count > 0 {
                let r = p_regions_ptr;
                let w = unsafe { (r.add(72) as *const u32).read() };
                let h = unsafe { (r.add(76) as *const u32).read() };
                (w, h)
            } else {
                (0, 0)
            };
            eprintln!(
                "weave/d3d9-blit vkCmdResolveImage2 presents={seq} t={}ms \
                 src=0x{src_image:x} src_layout={src_layout} \
                 dst=0x{dst_image:x} dst_layout={dst_layout} \
                 resolve_extent={ext_w}x{ext_h} regions={region_count}",
                d3d9_trace_ms()
            );
        } else {
            eprintln!(
                "weave/d3d9-blit vkCmdResolveImage2 presents={seq} t={}ms p_resolve_image_info=null",
                d3d9_trace_ms()
            );
        }
    }
    let f = real_fn(stored_instance(), "vkCmdResolveImage2");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, *const c_void) = unsafe { std::mem::transmute(f) };
    unsafe { f(command_buffer, p_resolve_image_info) }
}
cmd_thunk!(void vk_cmd_set_event, "vkCmdSetEvent", (command_buffer, event: VkEvent, stage_mask: VkPipelineStageFlags));
cmd_thunk!(void vk_cmd_set_event2, "vkCmdSetEvent2", (command_buffer, event: VkEvent, p_dependency_info: *const c_void));
cmd_thunk!(void vk_cmd_reset_event, "vkCmdResetEvent", (command_buffer, event: VkEvent, stage_mask: VkPipelineStageFlags));
cmd_thunk!(void vk_cmd_reset_event2, "vkCmdResetEvent2", (command_buffer, event: VkEvent, stage_mask: u64));
cmd_thunk!(void vk_cmd_wait_events, "vkCmdWaitEvents", (command_buffer, event_count: u32, p_events: *const VkEvent, src_stage_mask: VkPipelineStageFlags, dst_stage_mask: VkPipelineStageFlags, memory_barrier_count: u32, p_memory_barriers: *const c_void, buffer_barrier_count: u32, p_buffer_barriers: *const c_void, image_barrier_count: u32, p_image_barriers: *const c_void));
cmd_thunk!(void vk_cmd_wait_events2, "vkCmdWaitEvents2", (command_buffer, event_count: u32, p_events: *const VkEvent, p_dependency_infos: *const c_void));
cmd_thunk!(void vk_cmd_pipeline_barrier, "vkCmdPipelineBarrier", (command_buffer, src_stage_mask: VkPipelineStageFlags, dst_stage_mask: VkPipelineStageFlags, dependency_flags: u32, memory_barrier_count: u32, p_memory_barriers: *const c_void, buffer_memory_barrier_count: u32, p_buffer_memory_barriers: *const c_void, image_memory_barrier_count: u32, p_image_memory_barriers: *const c_void));
pub unsafe extern "win64" fn vk_cmd_pipeline_barrier2(
    command_buffer: VkCommandBuffer,
    p_dependency_info: *const c_void,
) {
    // VkDependencyInfo offsets (spec, 64-bit):
    //   0: sType(u32), 8: pNext(*), 16: dependencyFlags(u32)
    //   20: memoryBarrierCount(u32), 24: pMemoryBarriers(*)
    //   32: bufferMemoryBarrierCount(u32), 40: pBufferMemoryBarriers(*)
    //   48: imageMemoryBarrierCount(u32), 56: pImageMemoryBarriers(*)
    // VkImageMemoryBarrier2 offsets (spec, 64-bit):
    //   0: sType(u32), 8: pNext(*), 16: srcStageMask(u64), 24: srcAccessMask(u64)
    //   32: dstStageMask(u64), 40: dstAccessMask(u64)
    //   48: oldLayout(u32), 52: newLayout(u32)
    //   56: srcQueueFamilyIndex(u32), 60: dstQueueFamilyIndex(u32)
    //   64: image(u64), 72: subresourceRange(VkImageSubresourceRange=20B)
    //   total: 96 bytes
    if d3d9_barrier_trace_enabled() && !p_dependency_info.is_null() {
        let base = p_dependency_info as *const u8;
        let img_count = unsafe { (base.add(48) as *const u32).read() };
        let p_img_barriers = unsafe { (base.add(56) as *const *const u8).read() };
        if img_count > 0 && !p_img_barriers.is_null() {
            let presents = D3D9_PRESENT_COUNT.load(Ordering::Relaxed);
            let t = d3d9_trace_ms();
            for i in 0..img_count.min(8) {
                let b = unsafe { p_img_barriers.add(i as usize * 96) };
                let old_layout = unsafe { (b.add(48) as *const u32).read() };
                let new_layout = unsafe { (b.add(52) as *const u32).read() };
                let image = unsafe { (b.add(64) as *const u64).read() };
                eprintln!(
                    "weave/d3d9-barrier t={t}ms presents={presents} \
                     imageBarrier#{i} image=0x{image:x} \
                     oldLayout={old_layout} newLayout={new_layout}"
                );
            }
        }
    }
    let f = real_fn(stored_instance(), "vkCmdPipelineBarrier2");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, *const c_void) = unsafe { std::mem::transmute(f) };
    unsafe { f(command_buffer, p_dependency_info) }
}
cmd_thunk!(void vk_cmd_begin_query, "vkCmdBeginQuery", (command_buffer, query_pool: VkQueryPool, query: u32, flags: u32));
cmd_thunk!(void vk_cmd_end_query, "vkCmdEndQuery", (command_buffer, query_pool: VkQueryPool, query: u32));
cmd_thunk!(void vk_cmd_reset_query_pool, "vkCmdResetQueryPool", (command_buffer, query_pool: VkQueryPool, first_query: u32, query_count: u32));
cmd_thunk!(void vk_cmd_write_timestamp, "vkCmdWriteTimestamp", (command_buffer, pipeline_stage: VkPipelineStageFlags, query_pool: VkQueryPool, query: u32));
cmd_thunk!(void vk_cmd_write_timestamp2, "vkCmdWriteTimestamp2", (command_buffer, stage: u64, query_pool: VkQueryPool, query: u32));
cmd_thunk!(void vk_cmd_copy_query_pool_results, "vkCmdCopyQueryPoolResults", (command_buffer, query_pool: VkQueryPool, first_query: u32, query_count: u32, dst_buffer: VkBuffer, dst_offset: VkDeviceSize, stride: VkDeviceSize, flags: VkQueryResultFlags));
cmd_thunk!(void vk_cmd_push_constants, "vkCmdPushConstants", (command_buffer, layout: VkPipelineLayout, stage_flags: VkShaderStageFlags, offset: u32, size: u32, p_values: *const c_void));
pub unsafe extern "win64" fn vk_cmd_begin_render_pass(
    command_buffer: VkCommandBuffer,
    p_render_pass_begin: *const c_void,
    contents: VkSubpassContents,
) {
    // VkRenderPassBeginInfo offsets (spec, 64-bit):
    //   0: sType(u32), 8: pNext(*), 16: renderPass(u64), 24: framebuffer(u64),
    //   32: renderArea(VkRect2D=16B), 48: clearValueCount(u32), 56: pClearValues(*)
    // VkClearValue = 16 bytes (union); first attachment color at pClearValues[0].
    if d3d9_trace_enabled() && !p_render_pass_begin.is_null() {
        let base = p_render_pass_begin as *const u8;
        let clear_count = unsafe { (base.add(48) as *const u32).read() };
        let p_clear_values = unsafe { (base.add(56) as *const *const u8).read() };
        let color_str = if clear_count > 0 && !p_clear_values.is_null() {
            let c = unsafe { std::ptr::read(p_clear_values as *const [f32; 4]) };
            format!("[{:.3},{:.3},{:.3},{:.3}]", c[0], c[1], c[2], c[3])
        } else {
            "none".to_string()
        };
        d3d9_trace!("vkCmdBeginRenderPass clear_count={clear_count} clear[0]={color_str}");
    }
    let f = real_fn(stored_instance(), "vkCmdBeginRenderPass");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, *const c_void, VkSubpassContents) =
        unsafe { std::mem::transmute(f) };
    unsafe { f(command_buffer, p_render_pass_begin, contents) }
}
cmd_thunk!(void vk_cmd_begin_render_pass2, "vkCmdBeginRenderPass2", (command_buffer, p_render_pass_begin: *const c_void, p_subpass_begin_info: *const c_void));
cmd_thunk!(void vk_cmd_next_subpass, "vkCmdNextSubpass", (command_buffer, contents: VkSubpassContents));
cmd_thunk!(void vk_cmd_next_subpass2, "vkCmdNextSubpass2", (command_buffer, p_subpass_begin_info: *const c_void, p_subpass_end_info: *const c_void));
cmd_thunk!(void vk_cmd_end_render_pass, "vkCmdEndRenderPass", (command_buffer,));
cmd_thunk!(void vk_cmd_end_render_pass2, "vkCmdEndRenderPass2", (command_buffer, p_subpass_end_info: *const c_void));
pub unsafe extern "win64" fn vk_cmd_begin_rendering(
    command_buffer: VkCommandBuffer,
    p_rendering_info: *const c_void,
) {
    // VkRenderingInfo offsets (spec, 64-bit):
    //   0: sType(u32), 8: pNext(*), 16: flags(u32), 20: renderArea(VkRect2D=16B),
    //   36: layerCount(u32), 40: viewMask(u32), 44: colorAttachmentCount(u32),
    //   48: pColorAttachments(*), 56: pDepthAttachment(*), 64: pStencilAttachment(*)
    // VkRenderingAttachmentInfo offsets:
    //   44: loadOp(u32, CLEAR=1), 52: clearValue([f32;4])
    // Log only the first BeginRendering call — avoid eprintln! overhead on every render pass.
    if d3d9_trace_enabled()
        && !p_rendering_info.is_null()
        && !D3D9_BEGIN_RENDERING_LOGGED.swap(true, Ordering::Relaxed)
    {
        let base = p_rendering_info as *const u8;
        let color_count = unsafe { (base.add(44) as *const u32).read() };
        let p_color = unsafe { (base.add(48) as *const *const u8).read() };
        let color_str = if color_count > 0 && !p_color.is_null() {
            let load_op = unsafe { (p_color.add(44) as *const u32).read() };
            let clear = unsafe { std::ptr::read(p_color.add(52) as *const [f32; 4]) };
            format!(
                "loadOp={load_op} clear=[{:.3},{:.3},{:.3},{:.3}]",
                clear[0], clear[1], clear[2], clear[3]
            )
        } else {
            "no-color".to_string()
        };
        d3d9_trace!("vkCmdBeginRendering[first] color_att={color_count} {color_str}");
    }
    if d3d9_clear_trace_enabled() && !p_rendering_info.is_null() {
        let seq = D3D9_BEGIN_RENDERING_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        let base = p_rendering_info as *const u8;
        let area_w = unsafe { (base.add(28) as *const u32).read() };
        let area_h = unsafe { (base.add(32) as *const u32).read() };
        let color_count = unsafe { (base.add(44) as *const u32).read() };
        let p_color = unsafe { (base.add(48) as *const *const u8).read() };
        let detail = if color_count > 0 && !p_color.is_null() {
            let load_op = unsafe { (p_color.add(44) as *const u32).read() };
            let store_op = unsafe { (p_color.add(48) as *const u32).read() };
            let clear = unsafe { std::ptr::read(p_color.add(52) as *const [f32; 4]) };
            format!(
                "loadOp={load_op} storeOp={store_op} clear=[{:.3},{:.3},{:.3},{:.3}] area={area_w}x{area_h}",
                clear[0], clear[1], clear[2], clear[3]
            )
        } else {
            format!("no-color-att area={area_w}x{area_h}")
        };
        d3d9_clear_log(format!("BeginRendering#{seq} {detail}"));
    }
    // VkRenderingAttachmentInfo offsets (spec, 64-bit):
    //   0: sType(u32), 8: pNext(*), 16: imageView(u64), 24: imageLayout(u32)
    //   28: resolveMode(u32), 32: resolveImageView(u64), 40: resolveImageLayout(u32)
    //   44: loadOp(u32), 48: storeOp(u32), 52: clearValue([f32;4])
    if d3d9_barrier_trace_enabled() && !p_rendering_info.is_null() {
        let base = p_rendering_info as *const u8;
        let area_w = unsafe { (base.add(28) as *const u32).read() };
        let area_h = unsafe { (base.add(32) as *const u32).read() };
        let color_count = unsafe { (base.add(44) as *const u32).read() };
        let p_color = unsafe { (base.add(48) as *const *const u8).read() };
        if color_count > 0 && !p_color.is_null() {
            let image_view = unsafe { (p_color.add(16) as *const u64).read() };
            let image_layout = unsafe { (p_color.add(24) as *const u32).read() };
            let load_op = unsafe { (p_color.add(44) as *const u32).read() };
            eprintln!(
                "weave/d3d9-barrier t={}ms presents={} BeginRendering \
                 area={area_w}x{area_h} colorAtt[0] imageView=0x{image_view:x} \
                 imageLayout={image_layout} loadOp={load_op}",
                d3d9_trace_ms(),
                D3D9_PRESENT_COUNT.load(Ordering::Relaxed),
            );

            // Higher-signal correlation for the failing present: when this BeginRendering
            // is for the swapchain extent (the surface that will be handed to vkQueuePresentKHR),
            // log it explicitly so we can compare its imageView directly against the RT's.
            if (d3d9_present_source_trace_enabled() || d3d9_barrier_trace_enabled())
                && area_w == D3D9_SWAP_W.load(Ordering::Relaxed)
                && area_h == D3D9_SWAP_H.load(Ordering::Relaxed)
                && D3D9_PRESENT_COUNT.load(Ordering::Relaxed) >= 1
            {
                eprintln!(
                    "weave/d3d9-present-source t={}ms presents={} SwapchainFillSource imageView=0x{:x} layout={} loadOp={} (attachment for the imageIndex presented next — compare to RT imageView)",
                    d3d9_trace_ms(),
                    D3D9_PRESENT_COUNT.load(Ordering::Relaxed),
                    image_view,
                    image_layout,
                    load_op
                );
            }
        }
    }
    let f = real_fn(stored_instance(), "vkCmdBeginRendering");
    if f.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(VkCommandBuffer, *const c_void) = unsafe { std::mem::transmute(f) };
    unsafe { f(command_buffer, p_rendering_info) }
}
cmd_thunk!(void vk_cmd_end_rendering, "vkCmdEndRendering", (command_buffer,));
cmd_thunk!(void vk_cmd_execute_commands, "vkCmdExecuteCommands", (command_buffer, command_buffer_count: u32, p_command_buffers: *const VkCommandBuffer));
cmd_thunk!(void vk_cmd_bind_descriptor_sets2, "vkCmdBindDescriptorSets2", (command_buffer, p_bind_descriptor_sets_info: *const c_void));
cmd_thunk!(void vk_cmd_push_constants2, "vkCmdPushConstants2", (command_buffer, p_push_constants_info: *const c_void));
cmd_thunk!(void vk_cmd_push_descriptor_set_khr, "vkCmdPushDescriptorSetKHR", (command_buffer, pipeline_bind_point: VkPipelineBindPoint, layout: VkPipelineLayout, set: u32, descriptor_write_count: u32, p_descriptor_writes: *const c_void));
cmd_thunk!(void vk_cmd_push_descriptor_set_with_template_khr, "vkCmdPushDescriptorSetWithTemplateKHR", (command_buffer, descriptor_update_template: VkDescriptorUpdateTemplate, layout: VkPipelineLayout, set: u32, p_data: *const c_void));
cmd_thunk!(void vk_cmd_debug_marker_begin_ext, "vkCmdDebugMarkerBeginEXT", (command_buffer, p_marker_info: *const c_void));
cmd_thunk!(void vk_cmd_debug_marker_end_ext, "vkCmdDebugMarkerEndEXT", (command_buffer,));
cmd_thunk!(void vk_cmd_debug_marker_insert_ext, "vkCmdDebugMarkerInsertEXT", (command_buffer, p_marker_info: *const c_void));
// VK_EXT_depth_clip_enable — lavapipe v1; DXVK calls during D3D9 first render frame.
// Wine ref: dlls/vulkan-1/vulkan.c — pass-through to ICDs; no side effects beyond
// recording the dynamic-state command in the command buffer.
cmd_thunk!(void vk_cmd_set_depth_clip_enable_ext, "vkCmdSetDepthClipEnableEXT", (command_buffer, depth_clip_enable: u32));

// ── Exported Vulkan stubs (extern "win64") ────────────────────────────────────

/// vkGetInstanceProcAddr — primary Vulkan function loader.
///
/// Returns our `extern "win64"` wrapper for every intercepted function.
/// Returns NULL for any function not in the dispatch table — never returns a
/// raw SysV host-library pointer, which would cause an ABI mismatch crash when
/// DXVK (Win64 caller) invokes it.
pub unsafe extern "win64" fn vk_get_instance_proc_addr(
    _instance: VkInstance,
    p_name: *const c_char,
) -> PFN_vkVoidFunction {
    if p_name.is_null() {
        return std::ptr::null();
    }
    let name = match unsafe { CStr::from_ptr(p_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };
    let result: PFN_vkVoidFunction = match name {
        "vkGetInstanceProcAddr" => vk_get_instance_proc_addr as PFN_vkVoidFunction,
        "vkCreateInstance" => vk_create_instance as PFN_vkVoidFunction,
        "vkEnumerateInstanceExtensionProperties" => {
            vk_enumerate_instance_extension_properties as PFN_vkVoidFunction
        }
        "vkEnumerateInstanceLayerProperties" => {
            vk_enumerate_instance_layer_properties as PFN_vkVoidFunction
        }
        "vkEnumerateInstanceVersion" => vk_enumerate_instance_version as PFN_vkVoidFunction,
        "vkCreateWin32SurfaceKHR" => vk_create_win32_surface_khr as PFN_vkVoidFunction,
        "vkDestroySurfaceKHR" => vk_destroy_surface_khr as PFN_vkVoidFunction,
        "vkGetDeviceProcAddr" => vk_get_device_proc_addr as PFN_vkVoidFunction,
        // Physical-device thunks
        "vkDestroyInstance" => vk_destroy_instance as PFN_vkVoidFunction,
        "vkEnumeratePhysicalDevices" => vk_enumerate_physical_devices as PFN_vkVoidFunction,
        "vkGetPhysicalDeviceProperties" => vk_get_physical_device_properties as PFN_vkVoidFunction,
        "vkGetPhysicalDeviceFeatures" => vk_get_physical_device_features as PFN_vkVoidFunction,
        "vkGetPhysicalDeviceFeatures2" | "vkGetPhysicalDeviceFeatures2KHR" => {
            vk_get_physical_device_features2 as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceProperties2" | "vkGetPhysicalDeviceProperties2KHR" => {
            vk_get_physical_device_properties2 as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceMemoryProperties" => {
            vk_get_physical_device_memory_properties as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceMemoryProperties2" | "vkGetPhysicalDeviceMemoryProperties2KHR" => {
            vk_get_physical_device_memory_properties2 as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceQueueFamilyProperties" => {
            vk_get_physical_device_queue_family_properties as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceQueueFamilyProperties2"
        | "vkGetPhysicalDeviceQueueFamilyProperties2KHR" => {
            vk_get_physical_device_queue_family_properties2 as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceFormatProperties" => {
            vk_get_physical_device_format_properties as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceFormatProperties2" | "vkGetPhysicalDeviceFormatProperties2KHR" => {
            vk_get_physical_device_format_properties2 as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceImageFormatProperties" => {
            vk_get_physical_device_image_format_properties as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceImageFormatProperties2"
        | "vkGetPhysicalDeviceImageFormatProperties2KHR" => {
            vk_get_physical_device_image_format_properties2 as PFN_vkVoidFunction
        }
        "vkEnumerateDeviceExtensionProperties" => {
            vk_enumerate_device_extension_properties as PFN_vkVoidFunction
        }
        "vkEnumerateDeviceLayerProperties" => {
            vk_enumerate_device_layer_properties as PFN_vkVoidFunction
        }
        "vkCreateDevice" => vk_create_device as PFN_vkVoidFunction,
        "vkGetPhysicalDeviceSurfaceSupportKHR" => {
            vk_get_physical_device_surface_support_khr as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceSurfaceCapabilitiesKHR" => {
            vk_get_physical_device_surface_capabilities_khr as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceSurfaceFormatsKHR" => {
            vk_get_physical_device_surface_formats_khr as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceSurfacePresentModesKHR" => {
            vk_get_physical_device_surface_present_modes_khr as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceSurfaceCapabilities2KHR" => {
            vk_get_physical_device_surface_capabilities2_khr as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceCalibrateableTimeDomainsEXT" => {
            vk_get_physical_device_calibrateable_time_domains_ext as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceSparseImageFormatProperties" => {
            vk_get_physical_device_sparse_image_format_properties as PFN_vkVoidFunction
        }
        // Device thunks
        "vkDestroyDevice" => vk_destroy_device as PFN_vkVoidFunction,
        "vkGetDeviceQueue" => vk_get_device_queue as PFN_vkVoidFunction,
        "vkGetDeviceQueue2" => vk_get_device_queue2 as PFN_vkVoidFunction,
        "vkDeviceWaitIdle" => vk_device_wait_idle as PFN_vkVoidFunction,
        "vkQueueSubmit" => vk_queue_submit as PFN_vkVoidFunction,
        "vkQueueSubmit2" | "vkQueueSubmit2KHR" => vk_queue_submit2 as PFN_vkVoidFunction,
        "vkQueueWaitIdle" => vk_queue_wait_idle as PFN_vkVoidFunction,
        "vkQueuePresentKHR" => vk_queue_present_khr as PFN_vkVoidFunction,
        "vkAllocateMemory" => vk_allocate_memory as PFN_vkVoidFunction,
        "vkFreeMemory" => vk_free_memory as PFN_vkVoidFunction,
        "vkMapMemory" => vk_map_memory as PFN_vkVoidFunction,
        "vkUnmapMemory" => vk_unmap_memory as PFN_vkVoidFunction,
        "vkFlushMappedMemoryRanges" => vk_flush_mapped_memory_ranges as PFN_vkVoidFunction,
        "vkInvalidateMappedMemoryRanges" => {
            vk_invalidate_mapped_memory_ranges as PFN_vkVoidFunction
        }
        "vkBindBufferMemory" => vk_bind_buffer_memory as PFN_vkVoidFunction,
        "vkBindBufferMemory2" | "vkBindBufferMemory2KHR" => {
            vk_bind_buffer_memory2 as PFN_vkVoidFunction
        }
        "vkBindImageMemory" => vk_bind_image_memory as PFN_vkVoidFunction,
        "vkBindImageMemory2" | "vkBindImageMemory2KHR" => {
            vk_bind_image_memory2 as PFN_vkVoidFunction
        }
        "vkGetBufferMemoryRequirements" => vk_get_buffer_memory_requirements as PFN_vkVoidFunction,
        "vkGetBufferMemoryRequirements2" | "vkGetBufferMemoryRequirements2KHR" => {
            vk_get_buffer_memory_requirements2 as PFN_vkVoidFunction
        }
        "vkGetImageMemoryRequirements" => vk_get_image_memory_requirements as PFN_vkVoidFunction,
        "vkGetImageMemoryRequirements2" | "vkGetImageMemoryRequirements2KHR" => {
            vk_get_image_memory_requirements2 as PFN_vkVoidFunction
        }
        "vkGetDeviceBufferMemoryRequirements" | "vkGetDeviceBufferMemoryRequirementsKHR" => {
            vk_get_device_buffer_memory_requirements as PFN_vkVoidFunction
        }
        "vkGetDeviceImageMemoryRequirements" | "vkGetDeviceImageMemoryRequirementsKHR" => {
            vk_get_device_image_memory_requirements as PFN_vkVoidFunction
        }
        "vkGetDeviceImageSparseMemoryRequirements"
        | "vkGetDeviceImageSparseMemoryRequirementsKHR" => {
            vk_get_device_image_sparse_memory_requirements as PFN_vkVoidFunction
        }
        "vkGetImageSparseMemoryRequirements" => {
            vk_get_image_sparse_memory_requirements as PFN_vkVoidFunction
        }
        "vkGetImageSparseMemoryRequirements2" | "vkGetImageSparseMemoryRequirements2KHR" => {
            vk_get_image_sparse_memory_requirements2 as PFN_vkVoidFunction
        }
        "vkGetPipelineCacheData" => vk_get_pipeline_cache_data as PFN_vkVoidFunction,
        "vkMergePipelineCaches" => vk_merge_pipeline_caches as PFN_vkVoidFunction,
        "vkCreateBuffer" => vk_create_buffer as PFN_vkVoidFunction,
        "vkDestroyBuffer" => vk_destroy_buffer as PFN_vkVoidFunction,
        "vkCreateImage" => vk_create_image as PFN_vkVoidFunction,
        "vkDestroyImage" => vk_destroy_image as PFN_vkVoidFunction,
        "vkGetImageSubresourceLayout" => vk_get_image_subresource_layout as PFN_vkVoidFunction,
        "vkCreateImageView" => vk_create_image_view as PFN_vkVoidFunction,
        "vkDestroyImageView" => vk_destroy_image_view as PFN_vkVoidFunction,
        "vkCreateBufferView" => vk_create_buffer_view as PFN_vkVoidFunction,
        "vkDestroyBufferView" => vk_destroy_buffer_view as PFN_vkVoidFunction,
        "vkCreateShaderModule" => vk_create_shader_module as PFN_vkVoidFunction,
        "vkDestroyShaderModule" => vk_destroy_shader_module as PFN_vkVoidFunction,
        "vkCreatePipelineCache" => vk_create_pipeline_cache as PFN_vkVoidFunction,
        "vkDestroyPipelineCache" => vk_destroy_pipeline_cache as PFN_vkVoidFunction,
        "vkCreateGraphicsPipelines" => vk_create_graphics_pipelines as PFN_vkVoidFunction,
        "vkCreateComputePipelines" => vk_create_compute_pipelines as PFN_vkVoidFunction,
        "vkDestroyPipeline" => vk_destroy_pipeline as PFN_vkVoidFunction,
        "vkCreatePipelineLayout" => vk_create_pipeline_layout as PFN_vkVoidFunction,
        "vkDestroyPipelineLayout" => vk_destroy_pipeline_layout as PFN_vkVoidFunction,
        "vkCreateSampler" => vk_create_sampler as PFN_vkVoidFunction,
        "vkDestroySampler" => vk_destroy_sampler as PFN_vkVoidFunction,
        "vkCreateDescriptorSetLayout" => vk_create_descriptor_set_layout as PFN_vkVoidFunction,
        "vkDestroyDescriptorSetLayout" => vk_destroy_descriptor_set_layout as PFN_vkVoidFunction,
        "vkCreateDescriptorPool" => vk_create_descriptor_pool as PFN_vkVoidFunction,
        "vkDestroyDescriptorPool" => vk_destroy_descriptor_pool as PFN_vkVoidFunction,
        "vkResetDescriptorPool" => vk_reset_descriptor_pool as PFN_vkVoidFunction,
        "vkAllocateDescriptorSets" => vk_allocate_descriptor_sets as PFN_vkVoidFunction,
        "vkFreeDescriptorSets" => vk_free_descriptor_sets as PFN_vkVoidFunction,
        "vkUpdateDescriptorSets" => vk_update_descriptor_sets as PFN_vkVoidFunction,
        "vkCreateDescriptorUpdateTemplate" | "vkCreateDescriptorUpdateTemplateKHR" => {
            vk_create_descriptor_update_template as PFN_vkVoidFunction
        }
        "vkDestroyDescriptorUpdateTemplate" | "vkDestroyDescriptorUpdateTemplateKHR" => {
            vk_destroy_descriptor_update_template as PFN_vkVoidFunction
        }
        "vkUpdateDescriptorSetWithTemplate" | "vkUpdateDescriptorSetWithTemplateKHR" => {
            vk_update_descriptor_set_with_template as PFN_vkVoidFunction
        }
        "vkCreateRenderPass" => vk_create_render_pass as PFN_vkVoidFunction,
        "vkCreateRenderPass2" | "vkCreateRenderPass2KHR" => {
            vk_create_render_pass2 as PFN_vkVoidFunction
        }
        "vkDestroyRenderPass" => vk_destroy_render_pass as PFN_vkVoidFunction,
        "vkCreateFramebuffer" => vk_create_framebuffer as PFN_vkVoidFunction,
        "vkDestroyFramebuffer" => vk_destroy_framebuffer as PFN_vkVoidFunction,
        "vkCreateCommandPool" => vk_create_command_pool as PFN_vkVoidFunction,
        "vkDestroyCommandPool" => vk_destroy_command_pool as PFN_vkVoidFunction,
        "vkResetCommandPool" => vk_reset_command_pool as PFN_vkVoidFunction,
        "vkAllocateCommandBuffers" => vk_allocate_command_buffers as PFN_vkVoidFunction,
        "vkFreeCommandBuffers" => vk_free_command_buffers as PFN_vkVoidFunction,
        "vkCreateFence" => vk_create_fence as PFN_vkVoidFunction,
        "vkDestroyFence" => vk_destroy_fence as PFN_vkVoidFunction,
        "vkResetFences" => vk_reset_fences as PFN_vkVoidFunction,
        "vkGetFenceStatus" => vk_get_fence_status as PFN_vkVoidFunction,
        "vkWaitForFences" => vk_wait_for_fences as PFN_vkVoidFunction,
        "vkCreateSemaphore" => vk_create_semaphore as PFN_vkVoidFunction,
        "vkDestroySemaphore" => vk_destroy_semaphore as PFN_vkVoidFunction,
        "vkGetSemaphoreCounterValue" | "vkGetSemaphoreCounterValueKHR" => {
            vk_get_semaphore_counter_value as PFN_vkVoidFunction
        }
        "vkWaitSemaphores" | "vkWaitSemaphoresKHR" => vk_wait_semaphores as PFN_vkVoidFunction,
        "vkSignalSemaphore" | "vkSignalSemaphoreKHR" => vk_signal_semaphore as PFN_vkVoidFunction,
        "vkCreateEvent" => vk_create_event as PFN_vkVoidFunction,
        "vkDestroyEvent" => vk_destroy_event as PFN_vkVoidFunction,
        "vkGetEventStatus" => vk_get_event_status as PFN_vkVoidFunction,
        "vkSetEvent" => vk_set_event as PFN_vkVoidFunction,
        "vkResetEvent" => vk_reset_event as PFN_vkVoidFunction,
        "vkCreateQueryPool" => vk_create_query_pool as PFN_vkVoidFunction,
        "vkDestroyQueryPool" => vk_destroy_query_pool as PFN_vkVoidFunction,
        "vkGetQueryPoolResults" => vk_get_query_pool_results as PFN_vkVoidFunction,
        "vkResetQueryPool" | "vkResetQueryPoolEXT" => vk_reset_query_pool as PFN_vkVoidFunction,
        "vkCreateSwapchainKHR" => vk_create_swapchain_khr as PFN_vkVoidFunction,
        "vkDestroySwapchainKHR" => vk_destroy_swapchain_khr as PFN_vkVoidFunction,
        "vkGetSwapchainImagesKHR" => vk_get_swapchain_images_khr as PFN_vkVoidFunction,
        "vkAcquireNextImageKHR" => vk_acquire_next_image_khr as PFN_vkVoidFunction,
        "vkAcquireNextImage2KHR" => vk_acquire_next_image2_khr as PFN_vkVoidFunction,
        "vkGetDeviceGroupPresentCapabilitiesKHR" => {
            vk_get_device_group_present_capabilities_khr as PFN_vkVoidFunction
        }
        "vkGetDeviceGroupSurfacePresentModesKHR" => {
            vk_get_device_group_surface_present_modes_khr as PFN_vkVoidFunction
        }
        "vkGetDeviceGroupSurfacePresentModes2EXT" => {
            vk_get_device_group_surface_present_modes2_ext as PFN_vkVoidFunction
        }
        "vkGetDeviceMemoryCommitment" => vk_get_device_memory_commitment as PFN_vkVoidFunction,
        "vkGetDeviceMemoryOpaqueCaptureAddress" | "vkGetDeviceMemoryOpaqueCaptureAddressKHR" => {
            vk_get_device_memory_opaque_capture_address as PFN_vkVoidFunction
        }
        "vkGetBufferDeviceAddress"
        | "vkGetBufferDeviceAddressKHR"
        | "vkGetBufferDeviceAddressEXT" => vk_get_buffer_device_address as PFN_vkVoidFunction,
        "vkGetBufferOpaqueCaptureAddress" | "vkGetBufferOpaqueCaptureAddressKHR" => {
            vk_get_buffer_opaque_capture_address as PFN_vkVoidFunction
        }
        "vkGetRenderAreaGranularity" => vk_get_render_area_granularity as PFN_vkVoidFunction,
        "vkGetRenderingAreaGranularityKHR" => {
            vk_get_rendering_area_granularity_khr as PFN_vkVoidFunction
        }
        "vkGetDeviceImageSubresourceLayoutKHR" => {
            vk_get_device_image_subresource_layout_khr as PFN_vkVoidFunction
        }
        "vkGetImageSubresourceLayout2KHR" => {
            vk_get_image_subresource_layout2_khr as PFN_vkVoidFunction
        }
        "vkGetCalibratedTimestampsEXT" => vk_get_calibrated_timestamps_ext as PFN_vkVoidFunction,
        "vkCreatePrivateDataSlot" | "vkCreatePrivateDataSlotEXT" => {
            vk_create_private_data_slot as PFN_vkVoidFunction
        }
        "vkDestroyPrivateDataSlot" | "vkDestroyPrivateDataSlotEXT" => {
            vk_destroy_private_data_slot as PFN_vkVoidFunction
        }
        "vkSetPrivateData" | "vkSetPrivateDataEXT" => vk_set_private_data as PFN_vkVoidFunction,
        "vkGetPrivateData" | "vkGetPrivateDataEXT" => vk_get_private_data as PFN_vkVoidFunction,
        "vkSetHdrMetadataEXT" => vk_set_hdr_metadata_ext as PFN_vkVoidFunction,
        "vkWaitForPresentKHR" => vk_wait_for_present_khr as PFN_vkVoidFunction,
        "vkGetMemoryWin32HandleKHR" => vk_get_memory_win32_handle_khr as PFN_vkVoidFunction,
        "vkGetMemoryWin32HandlePropertiesKHR" => {
            vk_get_memory_win32_handle_properties_khr as PFN_vkVoidFunction
        }
        "vkGetSemaphoreWin32HandleKHR" => vk_get_semaphore_win32_handle_khr as PFN_vkVoidFunction,
        "vkImportSemaphoreWin32HandleKHR" => {
            vk_import_semaphore_win32_handle_khr as PFN_vkVoidFunction
        }
        "wine_vkAcquireKeyedMutex" => wine_vkAcquireKeyedMutex as PFN_vkVoidFunction,
        "wine_vkReleaseKeyedMutex" => wine_vkReleaseKeyedMutex as PFN_vkVoidFunction,
        "vkAcquireFullScreenExclusiveModeEXT" => {
            vk_acquire_full_screen_exclusive_mode_ext as PFN_vkVoidFunction
        }
        "vkReleaseFullScreenExclusiveModeEXT" => {
            vk_release_full_screen_exclusive_mode_ext as PFN_vkVoidFunction
        }
        // Command buffer thunks
        "vkBeginCommandBuffer" => vk_begin_command_buffer as PFN_vkVoidFunction,
        "vkEndCommandBuffer" => vk_end_command_buffer as PFN_vkVoidFunction,
        "vkResetCommandBuffer" => vk_reset_command_buffer as PFN_vkVoidFunction,
        "vkCmdBindPipeline" => vk_cmd_bind_pipeline as PFN_vkVoidFunction,
        "vkCmdSetViewport" => vk_cmd_set_viewport as PFN_vkVoidFunction,
        "vkCmdSetScissor" => vk_cmd_set_scissor as PFN_vkVoidFunction,
        "vkCmdSetLineWidth" => vk_cmd_set_line_width as PFN_vkVoidFunction,
        "vkCmdSetDepthBias" => vk_cmd_set_depth_bias as PFN_vkVoidFunction,
        "vkCmdSetBlendConstants" => vk_cmd_set_blend_constants as PFN_vkVoidFunction,
        "vkCmdSetDepthBounds" => vk_cmd_set_depth_bounds as PFN_vkVoidFunction,
        "vkCmdSetStencilCompareMask" => vk_cmd_set_stencil_compare_mask as PFN_vkVoidFunction,
        "vkCmdSetStencilWriteMask" => vk_cmd_set_stencil_write_mask as PFN_vkVoidFunction,
        "vkCmdSetStencilReference" => vk_cmd_set_stencil_reference as PFN_vkVoidFunction,
        "vkCmdSetCullMode" | "vkCmdSetCullModeEXT" => vk_cmd_set_cull_mode as PFN_vkVoidFunction,
        "vkCmdSetFrontFace" | "vkCmdSetFrontFaceEXT" => vk_cmd_set_front_face as PFN_vkVoidFunction,
        "vkCmdSetPrimitiveTopology" | "vkCmdSetPrimitiveTopologyEXT" => {
            vk_cmd_set_primitive_topology as PFN_vkVoidFunction
        }
        "vkCmdSetViewportWithCount" | "vkCmdSetViewportWithCountEXT" => {
            vk_cmd_set_viewport_with_count as PFN_vkVoidFunction
        }
        "vkCmdSetScissorWithCount" | "vkCmdSetScissorWithCountEXT" => {
            vk_cmd_set_scissor_with_count as PFN_vkVoidFunction
        }
        "vkCmdSetDepthTestEnable" | "vkCmdSetDepthTestEnableEXT" => {
            vk_cmd_set_depth_test_enable as PFN_vkVoidFunction
        }
        "vkCmdSetDepthWriteEnable" | "vkCmdSetDepthWriteEnableEXT" => {
            vk_cmd_set_depth_write_enable as PFN_vkVoidFunction
        }
        "vkCmdSetDepthCompareOp" | "vkCmdSetDepthCompareOpEXT" => {
            vk_cmd_set_depth_compare_op as PFN_vkVoidFunction
        }
        "vkCmdSetDepthBoundsTestEnable" | "vkCmdSetDepthBoundsTestEnableEXT" => {
            vk_cmd_set_depth_bounds_test_enable as PFN_vkVoidFunction
        }
        "vkCmdSetStencilTestEnable" | "vkCmdSetStencilTestEnableEXT" => {
            vk_cmd_set_stencil_test_enable as PFN_vkVoidFunction
        }
        "vkCmdSetStencilOp" | "vkCmdSetStencilOpEXT" => vk_cmd_set_stencil_op as PFN_vkVoidFunction,
        "vkCmdSetRasterizerDiscardEnable" | "vkCmdSetRasterizerDiscardEnableEXT" => {
            vk_cmd_set_rasterizer_discard_enable as PFN_vkVoidFunction
        }
        "vkCmdSetDepthBiasEnable" | "vkCmdSetDepthBiasEnableEXT" => {
            vk_cmd_set_depth_bias_enable as PFN_vkVoidFunction
        }
        "vkCmdSetPrimitiveRestartEnable" | "vkCmdSetPrimitiveRestartEnableEXT" => {
            vk_cmd_set_primitive_restart_enable as PFN_vkVoidFunction
        }
        "vkCmdBindDescriptorSets" => vk_cmd_bind_descriptor_sets as PFN_vkVoidFunction,
        "vkCmdBindIndexBuffer" => vk_cmd_bind_index_buffer as PFN_vkVoidFunction,
        "vkCmdBindIndexBuffer2KHR" => vk_cmd_bind_index_buffer2_khr as PFN_vkVoidFunction,
        "vkCmdBindVertexBuffers" => vk_cmd_bind_vertex_buffers as PFN_vkVoidFunction,
        "vkCmdBindVertexBuffers2" | "vkCmdBindVertexBuffers2EXT" => {
            vk_cmd_bind_vertex_buffers2 as PFN_vkVoidFunction
        }
        "vkCmdDraw" => vk_cmd_draw as PFN_vkVoidFunction,
        "vkCmdDrawIndexed" => vk_cmd_draw_indexed as PFN_vkVoidFunction,
        "vkCmdDrawIndirect" => vk_cmd_draw_indirect as PFN_vkVoidFunction,
        "vkCmdDrawIndirectCount" | "vkCmdDrawIndirectCountKHR" => {
            vk_cmd_draw_indirect_count as PFN_vkVoidFunction
        }
        "vkCmdDrawIndexedIndirect" => vk_cmd_draw_indexed_indirect as PFN_vkVoidFunction,
        "vkCmdDrawIndexedIndirectCount" | "vkCmdDrawIndexedIndirectCountKHR" => {
            vk_cmd_draw_indexed_indirect_count as PFN_vkVoidFunction
        }
        "vkCmdDispatch" => vk_cmd_dispatch as PFN_vkVoidFunction,
        "vkCmdDispatchIndirect" => vk_cmd_dispatch_indirect as PFN_vkVoidFunction,
        "vkCmdCopyBuffer" => vk_cmd_copy_buffer as PFN_vkVoidFunction,
        "vkCmdCopyBuffer2" | "vkCmdCopyBuffer2KHR" => vk_cmd_copy_buffer2 as PFN_vkVoidFunction,
        "vkCmdCopyImage" => vk_cmd_copy_image as PFN_vkVoidFunction,
        "vkCmdCopyImage2" | "vkCmdCopyImage2KHR" => vk_cmd_copy_image2 as PFN_vkVoidFunction,
        "vkCmdBlitImage" => vk_cmd_blit_image as PFN_vkVoidFunction,
        "vkCmdBlitImage2" | "vkCmdBlitImage2KHR" => vk_cmd_blit_image2 as PFN_vkVoidFunction,
        "vkCmdCopyBufferToImage" => vk_cmd_copy_buffer_to_image as PFN_vkVoidFunction,
        "vkCmdCopyBufferToImage2" | "vkCmdCopyBufferToImage2KHR" => {
            vk_cmd_copy_buffer_to_image2 as PFN_vkVoidFunction
        }
        "vkCmdCopyImageToBuffer" => vk_cmd_copy_image_to_buffer as PFN_vkVoidFunction,
        "vkCmdCopyImageToBuffer2" | "vkCmdCopyImageToBuffer2KHR" => {
            vk_cmd_copy_image_to_buffer2 as PFN_vkVoidFunction
        }
        "vkCmdUpdateBuffer" => vk_cmd_update_buffer as PFN_vkVoidFunction,
        "vkCmdFillBuffer" => vk_cmd_fill_buffer as PFN_vkVoidFunction,
        "vkCmdClearColorImage" => vk_cmd_clear_color_image as PFN_vkVoidFunction,
        "vkCmdClearDepthStencilImage" => vk_cmd_clear_depth_stencil_image as PFN_vkVoidFunction,
        "vkCmdClearAttachments" => vk_cmd_clear_attachments as PFN_vkVoidFunction,
        "vkCmdResolveImage" => vk_cmd_resolve_image as PFN_vkVoidFunction,
        "vkCmdResolveImage2" | "vkCmdResolveImage2KHR" => {
            vk_cmd_resolve_image2 as PFN_vkVoidFunction
        }
        "vkCmdSetEvent" => vk_cmd_set_event as PFN_vkVoidFunction,
        "vkCmdSetEvent2" | "vkCmdSetEvent2KHR" => vk_cmd_set_event2 as PFN_vkVoidFunction,
        "vkCmdResetEvent" => vk_cmd_reset_event as PFN_vkVoidFunction,
        "vkCmdResetEvent2" => vk_cmd_reset_event2 as PFN_vkVoidFunction,
        "vkCmdWaitEvents" => vk_cmd_wait_events as PFN_vkVoidFunction,
        "vkCmdWaitEvents2" | "vkCmdWaitEvents2KHR" => vk_cmd_wait_events2 as PFN_vkVoidFunction,
        "vkCmdPipelineBarrier" => vk_cmd_pipeline_barrier as PFN_vkVoidFunction,
        "vkCmdPipelineBarrier2" | "vkCmdPipelineBarrier2KHR" => {
            vk_cmd_pipeline_barrier2 as PFN_vkVoidFunction
        }
        "vkCmdBeginQuery" => vk_cmd_begin_query as PFN_vkVoidFunction,
        "vkCmdEndQuery" => vk_cmd_end_query as PFN_vkVoidFunction,
        "vkCmdResetQueryPool" => vk_cmd_reset_query_pool as PFN_vkVoidFunction,
        "vkCmdWriteTimestamp" => vk_cmd_write_timestamp as PFN_vkVoidFunction,
        "vkCmdWriteTimestamp2" | "vkCmdWriteTimestamp2KHR" => {
            vk_cmd_write_timestamp2 as PFN_vkVoidFunction
        }
        "vkCmdCopyQueryPoolResults" => vk_cmd_copy_query_pool_results as PFN_vkVoidFunction,
        "vkCmdPushConstants" => vk_cmd_push_constants as PFN_vkVoidFunction,
        "vkCmdBeginRenderPass" => vk_cmd_begin_render_pass as PFN_vkVoidFunction,
        "vkCmdBeginRenderPass2" | "vkCmdBeginRenderPass2KHR" => {
            vk_cmd_begin_render_pass2 as PFN_vkVoidFunction
        }
        "vkCmdNextSubpass" => vk_cmd_next_subpass as PFN_vkVoidFunction,
        "vkCmdNextSubpass2" | "vkCmdNextSubpass2KHR" => vk_cmd_next_subpass2 as PFN_vkVoidFunction,
        "vkCmdEndRenderPass" => vk_cmd_end_render_pass as PFN_vkVoidFunction,
        "vkCmdEndRenderPass2" | "vkCmdEndRenderPass2KHR" => {
            vk_cmd_end_render_pass2 as PFN_vkVoidFunction
        }
        "vkCmdBeginRendering" | "vkCmdBeginRenderingKHR" => {
            vk_cmd_begin_rendering as PFN_vkVoidFunction
        }
        "vkCmdEndRendering" | "vkCmdEndRenderingKHR" => vk_cmd_end_rendering as PFN_vkVoidFunction,
        "vkCmdExecuteCommands" => vk_cmd_execute_commands as PFN_vkVoidFunction,
        "vkCmdBindDescriptorSets2" | "vkCmdBindDescriptorSets2KHR" => {
            vk_cmd_bind_descriptor_sets2 as PFN_vkVoidFunction
        }
        "vkCmdPushConstants2" | "vkCmdPushConstants2KHR" => {
            vk_cmd_push_constants2 as PFN_vkVoidFunction
        }
        "vkCmdPushDescriptorSetKHR" => vk_cmd_push_descriptor_set_khr as PFN_vkVoidFunction,
        "vkCmdPushDescriptorSetWithTemplateKHR" => {
            vk_cmd_push_descriptor_set_with_template_khr as PFN_vkVoidFunction
        }
        "vkCmdDebugMarkerBeginEXT" => vk_cmd_debug_marker_begin_ext as PFN_vkVoidFunction,
        "vkCmdDebugMarkerEndEXT" => vk_cmd_debug_marker_end_ext as PFN_vkVoidFunction,
        "vkCmdDebugMarkerInsertEXT" => vk_cmd_debug_marker_insert_ext as PFN_vkVoidFunction,
        // Physical-device external-object property queries — return no-op thunks that
        // zero-fill the output struct, signalling "no external support" (valid behaviour).
        "vkGetPhysicalDeviceExternalSemaphoreProperties"
        | "vkGetPhysicalDeviceExternalSemaphorePropertiesKHR" => {
            vk_get_physical_device_external_semaphore_properties as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceExternalFenceProperties"
        | "vkGetPhysicalDeviceExternalFencePropertiesKHR" => {
            vk_get_physical_device_external_fence_properties as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceExternalBufferProperties"
        | "vkGetPhysicalDeviceExternalBufferPropertiesKHR" => {
            vk_get_physical_device_external_buffer_properties as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceSparseImageFormatProperties2"
        | "vkGetPhysicalDeviceSparseImageFormatProperties2KHR" => {
            vk_get_physical_device_sparse_image_format_properties2 as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceSurfaceFormats2KHR" => {
            vk_get_physical_device_surface_formats2_khr as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceWin32PresentationSupportKHR" => {
            vk_get_physical_device_win32_presentation_support_khr as PFN_vkVoidFunction
        }
        "vkGetPhysicalDeviceSurfacePresentModes2EXT" => {
            vk_get_physical_device_surface_present_modes2_ext as PFN_vkVoidFunction
        }
        "vkReleaseSwapchainImagesEXT" => vk_release_swapchain_images_ext as PFN_vkVoidFunction,
        // ── EXT pass-through thunks (converted from named-abort stubs) ──────
        "vkCmdSetDepthBias2EXT" => vk_cmd_set_depth_bias2_ext as PFN_vkVoidFunction,
        "vkQueueBindSparse" => vk_queue_bind_sparse as PFN_vkVoidFunction,
        "vkGetShaderModuleCreateInfoIdentifierEXT" => {
            vk_get_shader_module_create_info_identifier_ext as PFN_vkVoidFunction
        }
        "vkGetShaderModuleIdentifierEXT" => {
            vk_get_shader_module_identifier_ext as PFN_vkVoidFunction
        }
        "vkCmdBindTransformFeedbackBuffersEXT" => {
            vk_cmd_bind_transform_feedback_buffers_ext as PFN_vkVoidFunction
        }
        "vkCmdBeginTransformFeedbackEXT" => {
            vk_cmd_begin_transform_feedback_ext as PFN_vkVoidFunction
        }
        "vkCmdEndTransformFeedbackEXT" => vk_cmd_end_transform_feedback_ext as PFN_vkVoidFunction,
        "vkCmdDrawIndirectByteCountEXT" => {
            vk_cmd_draw_indirect_byte_count_ext as PFN_vkVoidFunction
        }
        "vkCmdBeginQueryIndexedEXT" => vk_cmd_begin_query_indexed_ext as PFN_vkVoidFunction,
        "vkCmdEndQueryIndexedEXT" => vk_cmd_end_query_indexed_ext as PFN_vkVoidFunction,
        "vkCmdBeginConditionalRenderingEXT" => {
            vk_cmd_begin_conditional_rendering_ext as PFN_vkVoidFunction
        }
        "vkCmdEndConditionalRenderingEXT" => {
            vk_cmd_end_conditional_rendering_ext as PFN_vkVoidFunction
        }
        "vkCmdSetTessellationDomainOriginEXT" => {
            vk_cmd_set_tessellation_domain_origin_ext as PFN_vkVoidFunction
        }
        "vkCmdSetDepthClampEnableEXT" => vk_cmd_set_depth_clamp_enable_ext as PFN_vkVoidFunction,
        "vkCmdSetPolygonModeEXT" => vk_cmd_set_polygon_mode_ext as PFN_vkVoidFunction,
        "vkCmdSetRasterizationSamplesEXT" => {
            vk_cmd_set_rasterization_samples_ext as PFN_vkVoidFunction
        }
        "vkCmdSetSampleMaskEXT" => vk_cmd_set_sample_mask_ext as PFN_vkVoidFunction,
        "vkCmdSetAlphaToCoverageEnableEXT" => {
            vk_cmd_set_alpha_to_coverage_enable_ext as PFN_vkVoidFunction
        }
        "vkCmdSetAlphaToOneEnableEXT" => vk_cmd_set_alpha_to_one_enable_ext as PFN_vkVoidFunction,
        "vkCmdSetLogicOpEnableEXT" => vk_cmd_set_logic_op_enable_ext as PFN_vkVoidFunction,
        "vkCmdSetColorBlendEnableEXT" => vk_cmd_set_color_blend_enable_ext as PFN_vkVoidFunction,
        "vkCmdSetColorBlendEquationEXT" => {
            vk_cmd_set_color_blend_equation_ext as PFN_vkVoidFunction
        }
        "vkCmdSetColorWriteMaskEXT" => vk_cmd_set_color_write_mask_ext as PFN_vkVoidFunction,
        "vkCmdSetRasterizationStreamEXT" => {
            vk_cmd_set_rasterization_stream_ext as PFN_vkVoidFunction
        }
        "vkCmdSetConservativeRasterizationModeEXT" => {
            vk_cmd_set_conservative_rasterization_mode_ext as PFN_vkVoidFunction
        }
        "vkCmdSetExtraPrimitiveOverestimationSizeEXT" => {
            vk_cmd_set_extra_primitive_overestimation_size_ext as PFN_vkVoidFunction
        }
        "vkCmdSetDepthClipEnableEXT" => vk_cmd_set_depth_clip_enable_ext as PFN_vkVoidFunction,
        "vkCmdSetLineRasterizationModeEXT" => {
            vk_cmd_set_line_rasterization_mode_ext as PFN_vkVoidFunction
        }
        "vkCmdBeginDebugUtilsLabelEXT" => vk_cmd_begin_debug_utils_label_ext as PFN_vkVoidFunction,
        "vkCmdEndDebugUtilsLabelEXT" => vk_cmd_end_debug_utils_label_ext as PFN_vkVoidFunction,
        "vkCmdInsertDebugUtilsLabelEXT" => {
            vk_cmd_insert_debug_utils_label_ext as PFN_vkVoidFunction
        }
        "vkQueueBeginDebugUtilsLabelEXT" => {
            vk_queue_begin_debug_utils_label_ext as PFN_vkVoidFunction
        }
        "vkQueueEndDebugUtilsLabelEXT" => vk_queue_end_debug_utils_label_ext as PFN_vkVoidFunction,
        "vkQueueInsertDebugUtilsLabelEXT" => {
            vk_queue_insert_debug_utils_label_ext as PFN_vkVoidFunction
        }
        "vkSetDebugUtilsObjectNameEXT" => vk_set_debug_utils_object_name_ext as PFN_vkVoidFunction,
        "vkSetDebugUtilsObjectTagEXT" => vk_set_debug_utils_object_tag_ext as PFN_vkVoidFunction,
        // Safety fence: for any Vulkan function not in our dispatch table, return NULL.
        // Returning the raw SysV host-library pointer would cause an ABI mismatch crash
        // when DXVK (Win64 caller) calls it — Win64 passes args in RCX/RDX/R8/R9
        // but SysV expects them in RDI/RSI/RDX/RCX.  NULL signals "not available" and
        // DXVK's feature-detection paths handle NULL gracefully.
        _ => std::ptr::null(),
    };
    if result.is_null() {
        eprintln!("weave-vulkan: vk_get_instance_proc_addr({name:?}) -> NULL");
    } else {
        eprintln!(
            "weave-vulkan: vk_get_instance_proc_addr({name:?}) -> 0x{:x}",
            result as usize
        );
    }
    result
}

/// vkCreateInstance — swap VK_KHR_win32_surface → VK_KHR_xcb_surface.
pub unsafe extern "win64" fn vk_create_instance(
    p_create_info: *const VkInstanceCreateInfo,
    p_allocator: *const c_void,
    p_instance: *mut VkInstance,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_create_instance ENTER p_create_info={:p}",
        p_create_info
    );
    let vk = match vulkan() {
        Some(v) => v,
        None => return VK_ERROR_FEATURE_NOT_PRESENT,
    };

    if p_create_info.is_null() {
        let r = unsafe { (vk.create_instance)(p_create_info, p_allocator, p_instance) };
        eprintln!(
            "weave-vulkan: vk_create_instance RETURN (null ci) result={}",
            r
        );
        return r;
    }

    let info = unsafe { &*p_create_info };
    eprintln!(
        "weave-vulkan: vk_create_instance p_next={:p} ext_count={}",
        info.p_next, info.enabled_extension_count
    );
    let ext_count = info.enabled_extension_count as usize;

    let new_exts: Vec<*const c_char> =
        if ext_count > 0 && !info.pp_enabled_extension_names.is_null() {
            let slice =
                unsafe { std::slice::from_raw_parts(info.pp_enabled_extension_names, ext_count) };
            let mut v: Vec<*const c_char> = Vec::with_capacity(ext_count + 1);
            let mut has_xcb = false;
            for &ext_ptr in slice {
                if ext_ptr.is_null() {
                    continue;
                }
                let ext_name = unsafe { CStr::from_ptr(ext_ptr) }.to_bytes_with_nul();
                if ext_name == EXT_WIN32_SURFACE {
                    v.push(EXT_XCB_SURFACE.as_ptr() as *const c_char);
                    has_xcb = true;
                } else {
                    if ext_name == EXT_XCB_SURFACE {
                        has_xcb = true;
                    }
                    v.push(ext_ptr);
                }
            }
            if !has_xcb {
                v.push(EXT_XCB_SURFACE.as_ptr() as *const c_char);
            }
            v
        } else {
            vec![EXT_XCB_SURFACE.as_ptr() as *const c_char]
        };

    // Strip VkDebugUtilsMessengerCreateInfoEXT nodes from pNext.
    // These contain Win64 pfnUserCallback pointers; lavapipe calls them with
    // SysV ABI → register corruption → SIGSEGV. NULL out the entire pNext chain
    // since we don't need debug callbacks for lavapipe device init on CI.
    let clean_p_next: *const c_void = std::ptr::null();

    let patched = VkInstanceCreateInfo {
        s_type: info.s_type,
        p_next: clean_p_next,
        flags: info.flags,
        p_application_info: info.p_application_info,
        enabled_layer_count: info.enabled_layer_count,
        pp_enabled_layer_names: info.pp_enabled_layer_names,
        enabled_extension_count: new_exts.len() as u32,
        pp_enabled_extension_names: new_exts.as_ptr(),
    };

    eprintln!("weave-vulkan: vk_create_instance calling real vkCreateInstance");
    let result = unsafe { (vk.create_instance)(&patched, p_allocator, p_instance) };
    eprintln!(
        "weave-vulkan: vk_create_instance real vkCreateInstance returned {}",
        result
    );
    if result == VK_SUCCESS && !p_instance.is_null() {
        INSTANCE.store(unsafe { *p_instance } as usize, Ordering::Release);
    }
    eprintln!("weave-vulkan: vk_create_instance RETURN result={}", result);
    result
}

/// vkGetDeviceProcAddr — returns our win64 thunk for the named function.
pub unsafe extern "win64" fn vk_get_device_proc_addr(
    device: VkDevice,
    p_name: *const c_char,
) -> PFN_vkVoidFunction {
    // Re-use the instance proc addr dispatch — our thunks work for both.
    vk_get_instance_proc_addr(device as VkInstance, p_name)
}

/// vkEnumerateInstanceExtensionProperties — passthrough.
pub unsafe extern "win64" fn vk_enumerate_instance_extension_properties(
    p_layer_name: *const c_char,
    p_property_count: *mut u32,
    p_properties: *mut c_void,
) -> VkResult {
    let vk = match vulkan() {
        Some(v) => v,
        None => return VK_ERROR_FEATURE_NOT_PRESENT,
    };
    unsafe {
        (vk.enumerate_instance_extension_properties)(p_layer_name, p_property_count, p_properties)
    }
}

/// vkEnumerateInstanceLayerProperties — passthrough.
pub unsafe extern "win64" fn vk_enumerate_instance_layer_properties(
    p_property_count: *mut u32,
    p_properties: *mut c_void,
) -> VkResult {
    let vk = match vulkan() {
        Some(v) => v,
        None => return VK_ERROR_FEATURE_NOT_PRESENT,
    };
    unsafe { (vk.enumerate_instance_layer_properties)(p_property_count, p_properties) }
}

/// vkEnumerateInstanceVersion — passthrough (Vulkan 1.1+).
pub unsafe extern "win64" fn vk_enumerate_instance_version(p_api_version: *mut u32) -> VkResult {
    let vk = match vulkan() {
        Some(v) => v,
        None => return VK_ERROR_FEATURE_NOT_PRESENT,
    };
    match vk.enumerate_instance_version {
        Some(f) => unsafe { f(p_api_version) },
        None => {
            if !p_api_version.is_null() {
                unsafe { *p_api_version = 1 << 22 };
            }
            VK_SUCCESS
        }
    }
}

/// vkCreateWin32SurfaceKHR → vkCreateXcbSurfaceKHR.
pub unsafe extern "win64" fn vk_create_win32_surface_khr(
    instance: VkInstance,
    p_create_info: *const VkWin32SurfaceCreateInfoKHR,
    p_allocator: *const c_void,
    p_surface: *mut VkSurfaceKHR,
) -> VkResult {
    eprintln!(
        "weave-vulkan: vk_create_win32_surface_khr ENTER instance={:p} p_create_info={:p} p_surface={:p}",
        instance, p_create_info, p_surface
    );
    if p_create_info.is_null() || p_surface.is_null() {
        eprintln!(
            "weave-vulkan: vk_create_win32_surface_khr: null in/out, returning FEATURE_NOT_PRESENT"
        );
        return VK_ERROR_FEATURE_NOT_PRESENT;
    }
    let info = unsafe { &*p_create_info };
    eprintln!(
        "weave-vulkan: vk_create_win32_surface_khr: hwnd=0x{:x} hinstance={:p}",
        info.hwnd, info.hinstance
    );

    let xcb_win = weave_user32::window::xcb_id(info.hwnd);
    eprintln!("weave-vulkan: vk_create_win32_surface_khr: xcb_id={xcb_win}");
    if xcb_win != 0 {
        D3D9_SURFACE_XCB.store(xcb_win, Ordering::Relaxed);
    }
    if xcb_win == 0 {
        eprintln!("weave-vulkan: vk_create_win32_surface_khr: hwnd not registered, returning FEATURE_NOT_PRESENT");
        return VK_ERROR_FEATURE_NOT_PRESENT;
    }

    let conn = match xcb_connection() {
        Some(c) => c,
        None => {
            eprintln!("weave-vulkan: vk_create_win32_surface_khr: xcb_connection() = None, returning FEATURE_NOT_PRESENT");
            return VK_ERROR_FEATURE_NOT_PRESENT;
        }
    };
    eprintln!("weave-vulkan: vk_create_win32_surface_khr: xcb_connection={conn:p}");

    let fn_ptr = real_fn(instance, "vkCreateXcbSurfaceKHR");
    if fn_ptr.is_null() {
        eprintln!("weave-vulkan: vk_create_win32_surface_khr: real vkCreateXcbSurfaceKHR is NULL, returning EXT_NOT_PRESENT");
        return VK_ERROR_EXTENSION_NOT_PRESENT;
    }
    eprintln!("weave-vulkan: vk_create_win32_surface_khr: real fn_ptr={fn_ptr:p}");
    // SAFETY: `fn_ptr` is the `PFN_vkVoidFunction` returned by
    // `vkGetInstanceProcAddr(instance, "vkCreateXcbSurfaceKHR")`.  The Vulkan
    // specification (VK_KHR_xcb_surface) defines `vkCreateXcbSurfaceKHR` to have
    // exactly the signature `VkResult(VkInstance, const VkXcbSurfaceCreateInfoKHR*,
    // const VkAllocationCallbacks*, VkSurfaceKHR*)`, matching the `extern "C"` fn
    // pointer declared here.  The null-pointer guard above ensures `fn_ptr` is a
    // valid code address before the cast.
    let create_xcb: unsafe extern "C" fn(
        VkInstance,
        *const VkXcbSurfaceCreateInfoKHR,
        *const c_void,
        *mut VkSurfaceKHR,
    ) -> VkResult = unsafe { std::mem::transmute(fn_ptr) };

    let xcb_info = VkXcbSurfaceCreateInfoKHR {
        s_type: VK_STRUCTURE_TYPE_XCB_SURFACE_CREATE_INFO_KHR,
        p_next: std::ptr::null(),
        flags: 0,
        connection: conn,
        window: xcb_win,
    };

    eprintln!("weave-vulkan: vk_create_win32_surface_khr: calling real vkCreateXcbSurfaceKHR");
    let r = unsafe { create_xcb(instance, &xcb_info, p_allocator, p_surface) };
    eprintln!(
        "weave-vulkan: vk_create_win32_surface_khr: real returned {r}, surface=0x{:x}",
        unsafe { *p_surface }
    );
    r
}

/// vkDestroySurfaceKHR — passthrough.
pub unsafe extern "win64" fn vk_destroy_surface_khr(
    instance: VkInstance,
    surface: VkSurfaceKHR,
    p_allocator: *const c_void,
) {
    let fn_ptr = real_fn(instance, "vkDestroySurfaceKHR");
    if fn_ptr.is_null() {
        return;
    }
    // SAFETY: `fn_ptr` is the `PFN_vkVoidFunction` returned by
    // `vkGetInstanceProcAddr(instance, "vkDestroySurfaceKHR")`.  The Vulkan
    // specification (VK_KHR_surface) defines `vkDestroySurfaceKHR` to have the
    // signature `void(VkInstance, VkSurfaceKHR, const VkAllocationCallbacks*)`,
    // matching the `extern "C" fn(VkInstance, VkSurfaceKHR, *const c_void)` type
    // declared here.  The null-pointer guard above ensures `fn_ptr` is a valid
    // code address before the cast.
    let destroy: unsafe extern "C" fn(VkInstance, VkSurfaceKHR, *const c_void) =
        unsafe { std::mem::transmute(fn_ptr) };
    unsafe { destroy(instance, surface, p_allocator) };
}

// ── External-object property stubs ───────────────────────────────────────────
//
// These three functions are queried by DXVK during device initialisation to
// discover external-handle support.  On Weave there is no cross-process sharing
// infrastructure, so the answer is always "no external handles supported".
// Each stub writes zeros into the output struct (compatible_handle_types = 0,
// export_from_imported_handle_types = 0, external_semaphore_features = 0, etc.)
// which is a valid "not supported" response per the Vulkan spec.
//
// Wine ref: dlls/winevulkan/vulkan.c — the Wine Vulkan wrapper forwards these
// to the host loader unchanged; the host returns driver-specific capabilities.
// Weave returns "none" unconditionally because we have no OS-level sharing.

/// vkGetPhysicalDeviceExternalSemaphoreProperties — reports no external support.
///
/// Zeroes the VkExternalSemaphoreProperties output, signalling that no external
/// semaphore handle types are compatible with this physical device in Weave.
// Wine ref: dlls/winevulkan/vulkan.c — forwarded to host vkGetPhysicalDeviceExternalSemaphoreProperties;
// Weave has no shared-semaphore infrastructure so we always report zero support.
pub unsafe extern "win64" fn vk_get_physical_device_external_semaphore_properties(
    _physical_device: VkPhysicalDevice,
    _p_external_semaphore_info: *const c_void,
    p_external_semaphore_properties: *mut c_void,
) {
    // VkExternalSemaphoreProperties: { sType(u32), _pad(4), pNext(*void), flags×3(u32) }
    // Header = 4 (sType) + 4 (align padding) + 8 (pNext) = 16 bytes; flags start at offset 16.
    if !p_external_semaphore_properties.is_null() {
        let flags_ptr = unsafe { (p_external_semaphore_properties as *mut u8).add(16) as *mut u32 };
        unsafe { flags_ptr.write(0) }; // exportFromImportedHandleTypes
        unsafe { flags_ptr.add(1).write(0) }; // compatibleHandleTypes
        unsafe { flags_ptr.add(2).write(0) }; // externalSemaphoreFeatures
    }
}

/// vkGetPhysicalDeviceExternalFenceProperties — reports no external support.
///
/// Zeroes the VkExternalFenceProperties output, signalling that no external
/// fence handle types are compatible with this physical device in Weave.
// Wine ref: dlls/winevulkan/vulkan.c — forwarded to host vkGetPhysicalDeviceExternalFenceProperties;
// Weave has no shared-fence infrastructure so we always report zero support.
pub unsafe extern "win64" fn vk_get_physical_device_external_fence_properties(
    _physical_device: VkPhysicalDevice,
    _p_external_fence_info: *const c_void,
    p_external_fence_properties: *mut c_void,
) {
    // VkExternalFenceProperties: { sType(u32), _pad(4), pNext(*void), flags×3(u32) }
    // Flags start at offset 16 (same header layout as all Vk*Properties structs).
    if !p_external_fence_properties.is_null() {
        let flags_ptr = unsafe { (p_external_fence_properties as *mut u8).add(16) as *mut u32 };
        unsafe { flags_ptr.write(0) }; // exportFromImportedHandleTypes
        unsafe { flags_ptr.add(1).write(0) }; // compatibleHandleTypes
        unsafe { flags_ptr.add(2).write(0) }; // externalFenceFeatures
    }
}

/// vkGetPhysicalDeviceExternalBufferProperties — reports no external support.
///
/// Zeroes the VkExternalBufferProperties output, signalling that no external
/// buffer handle types are compatible with this physical device in Weave.
// Wine ref: dlls/winevulkan/vulkan.c — forwarded to host vkGetPhysicalDeviceExternalBufferProperties;
// Weave has no external-memory infrastructure so we always report zero support.
pub unsafe extern "win64" fn vk_get_physical_device_external_buffer_properties(
    _physical_device: VkPhysicalDevice,
    _p_external_buffer_info: *const c_void,
    p_external_buffer_properties: *mut c_void,
) {
    // VkExternalBufferProperties: { sType(u32), _pad(4), pNext(*void),
    //   VkExternalMemoryProperties{ externalMemoryFeatures, exportFromImportedHandleTypes,
    //   compatibleHandleTypes }(u32×3) } — flags start at offset 16.
    if !p_external_buffer_properties.is_null() {
        let flags_ptr = unsafe { (p_external_buffer_properties as *mut u8).add(16) as *mut u32 };
        unsafe { flags_ptr.write(0) }; // externalMemoryFeatures
        unsafe { flags_ptr.add(1).write(0) }; // exportFromImportedHandleTypes
        unsafe { flags_ptr.add(2).write(0) }; // compatibleHandleTypes
    }
}

// ── Wine-specific keyed-mutex helpers ────────────────────────────────────────
//
// DXVK's Wine path looks up these helpers on winevulkan. They are only needed
// for Win32 shared-resource synchronization via keyed mutexes. Weave does not
// implement that cross-process sharing model, so the functions exist only to
// report "not supported" without crashing the loader path.

pub unsafe extern "win64" fn wine_vkAcquireKeyedMutex(
    _device: VkDevice,
    _memory: VkDeviceMemory,
    _key: u64,
    _timeout_ms: u32,
) -> VkResult {
    VK_ERROR_FEATURE_NOT_PRESENT
}

pub unsafe extern "win64" fn wine_vkReleaseKeyedMutex(
    _device: VkDevice,
    _memory: VkDeviceMemory,
    _key: u64,
) -> VkResult {
    VK_ERROR_FEATURE_NOT_PRESENT
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Resolve a `vulkan-1.dll` or `winevulkan.dll` import to a Weave stub address.
///
/// `winevulkan.dll` is treated as an alias for `vulkan-1.dll`: DXVK loaded via the
/// Wine code path (triggered by our `__wine_dbg_output` presence marker in ntdll)
/// will call LoadLibraryA("winevulkan.dll") and then GetProcAddress on that handle.
/// Both DLL names map to the same win64 thunk set so the call chain is identical.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("vulkan-1.dll") && !dll.eq_ignore_ascii_case("winevulkan.dll") {
        return None;
    }
    match func {
        "vkGetInstanceProcAddr" => Some(
            vk_get_instance_proc_addr as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "vkCreateInstance" => {
            Some(vk_create_instance as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "vkEnumerateInstanceExtensionProperties" => Some(
            vk_enumerate_instance_extension_properties as unsafe extern "win64" fn(_, _, _) -> _
                as *const () as usize,
        ),
        "vkEnumerateInstanceLayerProperties" => Some(
            vk_enumerate_instance_layer_properties as unsafe extern "win64" fn(_, _) -> _
                as *const () as usize,
        ),
        "vkEnumerateInstanceVersion" => Some(
            vk_enumerate_instance_version as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "vkCreateWin32SurfaceKHR" => Some(
            vk_create_win32_surface_khr as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "vkDestroySurfaceKHR" => {
            Some(vk_destroy_surface_khr as unsafe extern "win64" fn(_, _, _) as *const () as usize)
        }
        _ => None,
    }
}
