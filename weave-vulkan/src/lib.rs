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
use std::sync::OnceLock;

// ── Vulkan type aliases ───────────────────────────────────────────────────────

#[allow(non_camel_case_types)]
type PFN_vkVoidFunction = *const c_void;

type VkResult = i32;
type VkInstance = *mut c_void;
type VkSurfaceKHR = u64;

const VK_SUCCESS: VkResult = 0;
const VK_ERROR_FEATURE_NOT_PRESENT: VkResult = -8;
const VK_ERROR_EXTENSION_NOT_PRESENT: VkResult = -7;

const VK_STRUCTURE_TYPE_XCB_SURFACE_CREATE_INFO_KHR: u32 = 1_000_005_000;

const EXT_WIN32_SURFACE: &[u8] = b"VK_KHR_win32_surface\0";
const EXT_XCB_SURFACE: &[u8] = b"VK_KHR_xcb_surface\0";

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
            unsafe { std::mem::transmute(ptr) }
        }};
        (opt $name:literal) => {{
            let ptr = unsafe { libc::dlsym(lib, concat!($name, "\0").as_ptr() as _) };
            if ptr.is_null() {
                None
            } else {
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

// ── Exported Vulkan stubs (extern "win64") ────────────────────────────────────

/// vkGetInstanceProcAddr — primary Vulkan function loader.
///
/// Returns our wrapper for intercepted functions; delegates to the real Linux
/// Vulkan loader for everything else.
pub unsafe extern "win64" fn vk_get_instance_proc_addr(
    instance: VkInstance,
    p_name: *const c_char,
) -> PFN_vkVoidFunction {
    if p_name.is_null() {
        return std::ptr::null();
    }
    let name = match unsafe { CStr::from_ptr(p_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };

    match name {
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
        // For all other functions: return the real Linux function pointer.
        // NOTE: The returned pointer uses SysV ABI. A Windows PE caller will invoke
        // it with Windows x64 ABI — this is a known Phase 3 limitation. A full
        // per-function thunk table is needed for complete compatibility.
        _ => real_fn(instance, name),
    }
}

/// vkCreateInstance — swap VK_KHR_win32_surface → VK_KHR_xcb_surface.
pub unsafe extern "win64" fn vk_create_instance(
    p_create_info: *const VkInstanceCreateInfo,
    p_allocator: *const c_void,
    p_instance: *mut VkInstance,
) -> VkResult {
    let vk = match vulkan() {
        Some(v) => v,
        None => return VK_ERROR_FEATURE_NOT_PRESENT,
    };

    if p_create_info.is_null() {
        return unsafe { (vk.create_instance)(p_create_info, p_allocator, p_instance) };
    }

    let info = unsafe { &*p_create_info };
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

    let patched = VkInstanceCreateInfo {
        s_type: info.s_type,
        p_next: info.p_next,
        flags: info.flags,
        p_application_info: info.p_application_info,
        enabled_layer_count: info.enabled_layer_count,
        pp_enabled_layer_names: info.pp_enabled_layer_names,
        enabled_extension_count: new_exts.len() as u32,
        pp_enabled_extension_names: new_exts.as_ptr(),
    };

    unsafe { (vk.create_instance)(&patched, p_allocator, p_instance) }
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
    if p_create_info.is_null() || p_surface.is_null() {
        return VK_ERROR_FEATURE_NOT_PRESENT;
    }
    let info = unsafe { &*p_create_info };

    let xcb_win = weave_user32::window::xcb_id(info.hwnd);
    if xcb_win == 0 {
        return VK_ERROR_FEATURE_NOT_PRESENT;
    }

    let conn = match xcb_connection() {
        Some(c) => c,
        None => return VK_ERROR_FEATURE_NOT_PRESENT,
    };

    let fn_ptr = real_fn(instance, "vkCreateXcbSurfaceKHR");
    if fn_ptr.is_null() {
        return VK_ERROR_EXTENSION_NOT_PRESENT;
    }
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

    unsafe { create_xcb(instance, &xcb_info, p_allocator, p_surface) }
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
    let destroy: unsafe extern "C" fn(VkInstance, VkSurfaceKHR, *const c_void) =
        unsafe { std::mem::transmute(fn_ptr) };
    unsafe { destroy(instance, surface, p_allocator) };
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Resolve a `vulkan-1.dll` import to a Weave stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("vulkan-1.dll") {
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
