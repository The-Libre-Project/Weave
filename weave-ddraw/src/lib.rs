//! ddraw.dll stubs for Weave.
//!
//! Covers DirectDrawCreate, DirectDrawCreateEx, DirectDrawEnumerateA/W/ExA/ExW,
//! and minimal IDirectDraw4 + IDirectDrawSurface4 COM vtables.
//! All methods are stubs returning DD_OK (0) or safe values.
//!
//! Wine ref: include/ddraw.h — IDirectDraw4 vtable order (28 entries),
//!   IDirectDrawSurface4 vtable order (45 entries).
//! Wine ref: dlls/ddraw/main.c::DirectDrawCreate — signature and initialization order.

#![allow(non_snake_case)]

// ── Constants ────────────────────────────────────────────────────────────────

const DD_OK: u32 = 0;
// Wine ref: include/ddraw.h — E_NOINTERFACE = 0x80004002
const E_NOINTERFACE: u32 = 0x80004002u32;
// Wine ref: include/ddraw.h — E_FAIL = 0x80004005
const E_FAIL: u32 = 0x80004005u32;
// S_FALSE — COM "already done, not an error"
const S_FALSE: u32 = 1;

// ── IDirectDrawSurface4 vtable ───────────────────────────────────────────────
// Wine ref: include/ddraw.h lines 2358-2415 — IDirectDrawSurface4 method order:
// [0]  QueryInterface
// [1]  AddRef
// [2]  Release
// [3]  AddAttachedSurface
// [4]  AddOverlayDirtyRect
// [5]  Blt
// [6]  BltBatch
// [7]  BltFast
// [8]  DeleteAttachedSurface
// [9]  EnumAttachedSurfaces
// [10] EnumOverlayZOrders
// [11] Flip
// [12] GetAttachedSurface
// [13] GetBltStatus
// [14] GetCaps
// [15] GetClipper
// [16] GetColorKey
// [17] GetDC
// [18] GetFlipStatus
// [19] GetOverlayPosition
// [20] GetPalette
// [21] GetPixelFormat
// [22] GetSurfaceDesc
// [23] Initialize
// [24] IsLost
// [25] Lock
// [26] ReleaseDC
// [27] Restore
// [28] SetClipper
// [29] SetColorKey
// [30] SetOverlayPosition
// [31] SetPalette
// [32] Unlock
// [33] UpdateOverlay
// [34] UpdateOverlayDisplay
// [35] UpdateOverlayZOrder
// [36] GetDDInterface
// [37] PageLock
// [38] PageUnlock
// [39] SetSurfaceDesc
// [40] SetPrivateData
// [41] GetPrivateData
// [42] FreePrivateData
// [43] GetUniquenessValue
// [44] ChangeUniquenessValue

#[repr(C)]
pub struct IDirectDrawSurface4Vtbl {
    pub QueryInterface: unsafe extern "win64" fn(*mut u8, *const u8, *mut *mut u8) -> u32,
    pub AddRef: unsafe extern "win64" fn(*mut u8) -> u32,
    pub Release: unsafe extern "win64" fn(*mut u8) -> u32,
    pub AddAttachedSurface: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub AddOverlayDirtyRect: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub Blt: unsafe extern "win64" fn(*mut u8, *mut u8, *mut u8, *mut u8, u32, *mut u8) -> u32,
    pub BltBatch: unsafe extern "win64" fn(*mut u8, *mut u8, u32, u32) -> u32,
    pub BltFast: unsafe extern "win64" fn(*mut u8, u32, u32, *mut u8, *mut u8, u32) -> u32,
    pub DeleteAttachedSurface: unsafe extern "win64" fn(*mut u8, u32, *mut u8) -> u32,
    pub EnumAttachedSurfaces: unsafe extern "win64" fn(*mut u8, *mut u8, *mut u8) -> u32,
    pub EnumOverlayZOrders: unsafe extern "win64" fn(*mut u8, u32, *mut u8, *mut u8) -> u32,
    pub Flip: unsafe extern "win64" fn(*mut u8, *mut u8, u32) -> u32,
    pub GetAttachedSurface: unsafe extern "win64" fn(*mut u8, *mut u8, *mut *mut u8) -> u32,
    pub GetBltStatus: unsafe extern "win64" fn(*mut u8, u32) -> u32,
    pub GetCaps: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub GetClipper: unsafe extern "win64" fn(*mut u8, *mut *mut u8) -> u32,
    pub GetColorKey: unsafe extern "win64" fn(*mut u8, u32, *mut u8) -> u32,
    pub GetDC: unsafe extern "win64" fn(*mut u8, *mut usize) -> u32,
    pub GetFlipStatus: unsafe extern "win64" fn(*mut u8, u32) -> u32,
    pub GetOverlayPosition: unsafe extern "win64" fn(*mut u8, *mut i32, *mut i32) -> u32,
    pub GetPalette: unsafe extern "win64" fn(*mut u8, *mut *mut u8) -> u32,
    pub GetPixelFormat: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub GetSurfaceDesc: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub Initialize: unsafe extern "win64" fn(*mut u8, *mut u8, *mut u8) -> u32,
    pub IsLost: unsafe extern "win64" fn(*mut u8) -> u32,
    pub Lock: unsafe extern "win64" fn(*mut u8, *mut u8, *mut u8, u32, usize) -> u32,
    pub ReleaseDC: unsafe extern "win64" fn(*mut u8, usize) -> u32,
    pub Restore: unsafe extern "win64" fn(*mut u8) -> u32,
    pub SetClipper: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub SetColorKey: unsafe extern "win64" fn(*mut u8, u32, *mut u8) -> u32,
    pub SetOverlayPosition: unsafe extern "win64" fn(*mut u8, i32, i32) -> u32,
    pub SetPalette: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub Unlock: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub UpdateOverlay:
        unsafe extern "win64" fn(*mut u8, *mut u8, *mut u8, *mut u8, u32, *mut u8) -> u32,
    pub UpdateOverlayDisplay: unsafe extern "win64" fn(*mut u8, u32) -> u32,
    pub UpdateOverlayZOrder: unsafe extern "win64" fn(*mut u8, u32, *mut u8) -> u32,
    pub GetDDInterface: unsafe extern "win64" fn(*mut u8, *mut *mut u8) -> u32,
    pub PageLock: unsafe extern "win64" fn(*mut u8, u32) -> u32,
    pub PageUnlock: unsafe extern "win64" fn(*mut u8, u32) -> u32,
    pub SetSurfaceDesc: unsafe extern "win64" fn(*mut u8, *mut u8, u32) -> u32,
    pub SetPrivateData: unsafe extern "win64" fn(*mut u8, *const u8, *mut u8, u32, u32) -> u32,
    pub GetPrivateData: unsafe extern "win64" fn(*mut u8, *const u8, *mut u8, *mut u32) -> u32,
    pub FreePrivateData: unsafe extern "win64" fn(*mut u8, *const u8) -> u32,
    pub GetUniquenessValue: unsafe extern "win64" fn(*mut u8, *mut u32) -> u32,
    pub ChangeUniquenessValue: unsafe extern "win64" fn(*mut u8) -> u32,
}

// ── DDSURFACEDESC2 on-wire layout ────────────────────────────────────────────
//
// Wine ref: include/ddraw.h:1036-1072 — DDSURFACEDESC2 struct.
//   DWORD    dwSize           /* 0 */
//   DWORD    dwFlags          /* 4 */
//   DWORD    dwHeight         /* 8 */
//   DWORD    dwWidth          /* C */
//   union { LONG lPitch; DWORD dwLinearSize; }  /* 10 */
//   union { DWORD dwBackBufferCount; DWORD dwDepth; } /* 14 */
//   union { DWORD dwMipMapCount; DWORD dwRefreshRate; DWORD dwSrcVBHandle; } /* 18 */
//   DWORD    dwAlphaBitDepth  /* 1C */
//   DWORD    dwReserved       /* 20 */
//   LPVOID   lpSurface        /* 24 on x86 / naturally aligned on x86-64 → 28 */
//   ...
//
// The Wine header comments annotate 32-bit x86 offsets. On x86-64 (our guest
// ABI — `extern "win64"`), LPVOID is 8 bytes and natural alignment pushes
// lpSurface to offset 0x28 with 4 bytes of padding after dwReserved. Rather
// than hardcode offsets, we declare `#[repr(C)]` structs with identical field
// types so rustc computes the same layout the guest's MSVC/MinGW compiler did.
// This matches whatever the guest PE passes us bit-for-bit.
//
// Wine ref: dlls/ddraw/surface.c:1136 (surface_lock) — "Windows does not set
// DDSD_LPSURFACE on locked surfaces" but explicitly writes
// `surface_desc->lpSurface = map_desc.data;`. We also write the lpSurface and
// set DDSD_LPSURFACE | DDSD_PITCH so downstream Blt (dispatch 3) can read the
// buffer pointer deterministically without walking the surface object.

/// DDSD_HEIGHT — Wine ref: include/ddraw.h:968
const DDSD_HEIGHT: u32 = 0x0000_0002;
/// DDSD_WIDTH — Wine ref: include/ddraw.h:969
const DDSD_WIDTH: u32 = 0x0000_0004;
/// DDSD_PITCH — Wine ref: include/ddraw.h:970
const DDSD_PITCH: u32 = 0x0000_0008;
/// DDSD_LPSURFACE — Wine ref: include/ddraw.h:974
const DDSD_LPSURFACE: u32 = 0x0000_0800;
/// DDSD_PIXELFORMAT — Wine ref: include/ddraw.h:975
const DDSD_PIXELFORMAT: u32 = 0x0000_1000;

/// On-wire DDSURFACEDESC2 — natural layout for the guest's `extern "win64"` ABI.
///
/// Field order/types mirror Wine's include/ddraw.h:1036 exactly so `#[repr(C)]`
/// produces the same byte layout as MinGW/MSVC compiles for the guest PE.
#[repr(C)]
pub struct Ddsd2 {
    pub dw_size: u32,              // offset 0x00
    pub dw_flags: u32,             // offset 0x04
    pub dw_height: u32,            // offset 0x08
    pub dw_width: u32,             // offset 0x0C
    pub l_pitch: i32,              // offset 0x10 (union lPitch / dwLinearSize)
    pub dw_back_buffer_count: u32, // offset 0x14 (union)
    pub dw_mip_map_count: u32,     // offset 0x18 (union)
    pub dw_alpha_bit_depth: u32,   // offset 0x1C
    pub dw_reserved: u32,          // offset 0x20
    pub lp_surface: *mut u8,       // offset 0x28 on x64 (0x24 on x86)
    pub ddck_ck_dest_overlay: [u32; 2],
    pub ddck_ck_dest_blt: [u32; 2],
    pub ddck_ck_src_overlay: [u32; 2],
    pub ddck_ck_src_blt: [u32; 2],
    pub ddpf_pixel_format: [u32; 8], // DDPIXELFORMAT, 32 bytes on Wine
    pub dds_caps: [u32; 4],          // DDSCAPS2, 16 bytes
    pub dw_texture_stage: u32,
}

#[repr(C)]
pub struct FakeSurface4 {
    /// Vtable pointer MUST be the first field. Guest reads *this as the vtable ptr.
    pub vtbl: *const IDirectDrawSurface4Vtbl,
    pub refcount: core::sync::atomic::AtomicU32,
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub pitch: u32,
    /// Leaked Box<[u8]> — freed on refcount→0 via Box::from_raw reconstitution.
    pub pixels: *mut u8,
    pub pixels_len: usize,
    /// Raw non-owning pointer to the parent IDirectDraw4 instance.
    /// Dispatch 2: do NOT AddRef — dispatch 3 may revisit if Blt needs it.
    pub parent_ddraw: *mut u8,
}

// SAFETY: vtable pointer is never mutated; refcount is atomic; pixel buffer is
// exclusively owned by this surface instance (Lock/Unlock is not concurrent in
// DirectDraw's contract — the guest is expected to serialize).
unsafe impl Sync for FakeSurface4 {}
unsafe impl Send for FakeSurface4 {}

impl FakeSurface4 {
    /// Default primary surface geometry for dispatch 2.
    const DEFAULT_WIDTH: u32 = 640;
    const DEFAULT_HEIGHT: u32 = 480;
    const DEFAULT_BPP: u32 = 32;

    fn new_boxed(width: u32, height: u32, bpp: u32, parent_ddraw: *mut u8) -> *mut FakeSurface4 {
        use core::sync::atomic::AtomicU32;
        let pitch = width.saturating_mul(bpp / 8);
        let len = (pitch as usize).saturating_mul(height as usize);
        // Zero-filled BGRA backing buffer. Leak as raw pointer; paired with
        // Box::from_raw in surf_Release.
        let pixel_vec: Vec<u8> = vec![0u8; len];
        let pixel_box: Box<[u8]> = pixel_vec.into_boxed_slice();
        let pixels_ptr = Box::into_raw(pixel_box) as *mut u8;
        let boxed = Box::new(FakeSurface4 {
            vtbl: &SURFACE4_VTBL,
            refcount: AtomicU32::new(1),
            width,
            height,
            bpp,
            pitch,
            pixels: pixels_ptr,
            pixels_len: len,
            parent_ddraw,
        });
        Box::into_raw(boxed)
    }
}

// ── IDirectDrawSurface4 stub implementations ─────────────────────────────────

unsafe extern "win64" fn surf_QueryInterface(
    _this: *mut u8,
    _riid: *const u8,
    _ppv: *mut *mut u8,
) -> u32 {
    E_NOINTERFACE
}
unsafe extern "win64" fn surf_AddRef(this: *mut u8) -> u32 {
    // Wine ref: dlls/ddraw/surface.c::ddraw_surface4_AddRef — InterlockedIncrement.
    if this.is_null() {
        return 0;
    }
    let obj = unsafe { &*(this as *const FakeSurface4) };
    obj.refcount
        .fetch_add(1, core::sync::atomic::Ordering::AcqRel)
        + 1
}
unsafe extern "win64" fn surf_Release(this: *mut u8) -> u32 {
    // Wine ref: dlls/ddraw/surface.c::ddraw_surface_release_iface — at ref=0,
    // ddraw_surface_cleanup (line 577) frees the surface struct AND the backing
    // pixel buffer. We mirror that: Box::from_raw for the surface + reconstitute
    // the pixel slice so its allocation is returned to the heap.
    if this.is_null() {
        return 0;
    }
    let obj = unsafe { &*(this as *const FakeSurface4) };
    let prev = obj
        .refcount
        .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    let new_count = prev.saturating_sub(1);
    if new_count == 0 {
        // Reconstitute and drop the pixel buffer first, then the surface Box.
        // KNOWN-BUG-CLASSES: "State maps must deregister on close" — every Box
        // allocated in dd_CreateSurface must be freed here.
        unsafe {
            let pixels_ptr = obj.pixels;
            let pixels_len = obj.pixels_len;
            if !pixels_ptr.is_null() && pixels_len > 0 {
                let slice = core::slice::from_raw_parts_mut(pixels_ptr, pixels_len);
                drop(Box::from_raw(slice as *mut [u8]));
            }
            drop(Box::from_raw(this as *mut FakeSurface4));
        }
    }
    new_count
}
unsafe extern "win64" fn surf_stub0(_this: *mut u8, _a: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_Blt(
    _this: *mut u8,
    _a: *mut u8,
    _b: *mut u8,
    _c: *mut u8,
    _d: u32,
    _e: *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_BltBatch(_this: *mut u8, _a: *mut u8, _b: u32, _c: u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_BltFast(
    _this: *mut u8,
    _x: u32,
    _y: u32,
    _src: *mut u8,
    _rect: *mut u8,
    _flags: u32,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_DeleteAttachedSurface(_this: *mut u8, _f: u32, _a: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_EnumAttachedSurfaces(
    _this: *mut u8,
    _ctx: *mut u8,
    _cb: *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_EnumOverlayZOrders(
    _this: *mut u8,
    _f: u32,
    _ctx: *mut u8,
    _cb: *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_Flip(_this: *mut u8, _dst: *mut u8, _flags: u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetAttachedSurface(
    _this: *mut u8,
    _caps: *mut u8,
    _ppv: *mut *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetBltStatus(_this: *mut u8, _f: u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetCaps(_this: *mut u8, _caps: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetClipper(_this: *mut u8, _ppv: *mut *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetColorKey(_this: *mut u8, _f: u32, _ck: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetDC(_this: *mut u8, _phdc: *mut usize) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetFlipStatus(_this: *mut u8, _f: u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetOverlayPosition(
    _this: *mut u8,
    _x: *mut i32,
    _y: *mut i32,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetPalette(_this: *mut u8, _ppv: *mut *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetPixelFormat(_this: *mut u8, _fmt: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetSurfaceDesc(this: *mut u8, desc: *mut u8) -> u32 {
    // Wine ref: dlls/ddraw/surface.c::ddraw_surface4_GetSurfaceDesc — copies the
    // cached surface_desc (width/height/pitch/pixel format/caps) into the caller's
    // buffer via DD_STRUCT_COPY_BYSIZE. We fill the subset relevant to dispatch 2
    // consumers: geometry + pitch + lpSurface.
    if this.is_null() || desc.is_null() {
        return E_FAIL;
    }
    let obj = unsafe { &*(this as *const FakeSurface4) };
    let d = unsafe { &mut *(desc as *mut Ddsd2) };
    // Respect caller-provided dwSize; only overwrite when zero (uninitialized).
    if d.dw_size == 0 {
        d.dw_size = core::mem::size_of::<Ddsd2>() as u32;
    }
    d.dw_flags |= DDSD_WIDTH | DDSD_HEIGHT | DDSD_PITCH | DDSD_LPSURFACE | DDSD_PIXELFORMAT;
    d.dw_width = obj.width;
    d.dw_height = obj.height;
    d.l_pitch = obj.pitch as i32;
    d.lp_surface = obj.pixels;
    DD_OK
}
unsafe extern "win64" fn surf_Initialize(_this: *mut u8, _dd: *mut u8, _desc: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_IsLost(_this: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_Lock(
    this: *mut u8,
    _rect: *mut u8,
    desc: *mut u8,
    _flags: u32,
    _event: usize,
) -> u32 {
    // Wine ref: dlls/ddraw/surface.c::surface_lock (line 1064-1146) — after the
    // wined3d map succeeds, Wine writes into the caller's DDSURFACEDESC2:
    //   DD_STRUCT_COPY_BYSIZE_(surface_desc, &surface->surface_desc, ...);
    //   surface_desc->lpSurface = map_desc.data;
    //
    // Wine comment at line 1134: "Windows does not set DDSD_LPSURFACE on locked
    // surfaces." We still set DDSD_LPSURFACE | DDSD_PITCH to give the guest a
    // deterministic signal that our stub populated those fields — the guest
    // check flags-before-read pattern will still find the buffer pointer.
    //
    // Offsets written (Wine include/ddraw.h:1036-1045):
    //   dwSize   @ 0x00 — preserved unless guest passed zero
    //   dwFlags  @ 0x04 — OR in DDSD_LPSURFACE | DDSD_PITCH | DDSD_WIDTH | ...
    //   dwHeight @ 0x08 / dwWidth @ 0x0C
    //   lPitch   @ 0x10 (union member)
    //   lpSurface@ 0x28 on x86-64 (natural alignment of LPVOID); Rust repr(C)
    //            matches the guest's MSVC/MinGW x64 layout byte-for-byte.
    if this.is_null() || desc.is_null() {
        return E_FAIL;
    }
    let obj = unsafe { &*(this as *const FakeSurface4) };
    let d = unsafe { &mut *(desc as *mut Ddsd2) };
    if d.dw_size == 0 {
        d.dw_size = core::mem::size_of::<Ddsd2>() as u32;
    }
    d.dw_flags |= DDSD_LPSURFACE | DDSD_PITCH | DDSD_WIDTH | DDSD_HEIGHT;
    d.dw_width = obj.width;
    d.dw_height = obj.height;
    d.l_pitch = obj.pitch as i32;
    d.lp_surface = obj.pixels;
    DD_OK
}
unsafe extern "win64" fn surf_ReleaseDC(_this: *mut u8, _hdc: usize) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_Restore(_this: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_SetClipper(_this: *mut u8, _clip: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_SetColorKey(_this: *mut u8, _f: u32, _ck: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_SetOverlayPosition(_this: *mut u8, _x: i32, _y: i32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_SetPalette(_this: *mut u8, _pal: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_Unlock(_this: *mut u8, _rect: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_UpdateOverlay(
    _this: *mut u8,
    _sr: *mut u8,
    _dst: *mut u8,
    _dr: *mut u8,
    _f: u32,
    _fx: *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_UpdateOverlayDisplay(_this: *mut u8, _f: u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_UpdateOverlayZOrder(_this: *mut u8, _f: u32, _ref_: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetDDInterface(_this: *mut u8, _ppv: *mut *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_PageLock(_this: *mut u8, _f: u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_PageUnlock(_this: *mut u8, _f: u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_SetSurfaceDesc(_this: *mut u8, _desc: *mut u8, _f: u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_SetPrivateData(
    _this: *mut u8,
    _tag: *const u8,
    _data: *mut u8,
    _size: u32,
    _f: u32,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetPrivateData(
    _this: *mut u8,
    _tag: *const u8,
    _data: *mut u8,
    _size: *mut u32,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_FreePrivateData(_this: *mut u8, _tag: *const u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_GetUniquenessValue(_this: *mut u8, _val: *mut u32) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_ChangeUniquenessValue(_this: *mut u8) -> u32 {
    DD_OK
}

static SURFACE4_VTBL: IDirectDrawSurface4Vtbl = IDirectDrawSurface4Vtbl {
    QueryInterface: surf_QueryInterface,
    AddRef: surf_AddRef,
    Release: surf_Release,
    AddAttachedSurface: surf_stub0,
    AddOverlayDirtyRect: surf_stub0,
    Blt: surf_Blt,
    BltBatch: surf_BltBatch,
    BltFast: surf_BltFast,
    DeleteAttachedSurface: surf_DeleteAttachedSurface,
    EnumAttachedSurfaces: surf_EnumAttachedSurfaces,
    EnumOverlayZOrders: surf_EnumOverlayZOrders,
    Flip: surf_Flip,
    GetAttachedSurface: surf_GetAttachedSurface,
    GetBltStatus: surf_GetBltStatus,
    GetCaps: surf_GetCaps,
    GetClipper: surf_GetClipper,
    GetColorKey: surf_GetColorKey,
    GetDC: surf_GetDC,
    GetFlipStatus: surf_GetFlipStatus,
    GetOverlayPosition: surf_GetOverlayPosition,
    GetPalette: surf_GetPalette,
    GetPixelFormat: surf_GetPixelFormat,
    GetSurfaceDesc: surf_GetSurfaceDesc,
    Initialize: surf_Initialize,
    IsLost: surf_IsLost,
    Lock: surf_Lock,
    ReleaseDC: surf_ReleaseDC,
    Restore: surf_Restore,
    SetClipper: surf_SetClipper,
    SetColorKey: surf_SetColorKey,
    SetOverlayPosition: surf_SetOverlayPosition,
    SetPalette: surf_SetPalette,
    Unlock: surf_Unlock,
    UpdateOverlay: surf_UpdateOverlay,
    UpdateOverlayDisplay: surf_UpdateOverlayDisplay,
    UpdateOverlayZOrder: surf_UpdateOverlayZOrder,
    GetDDInterface: surf_GetDDInterface,
    PageLock: surf_PageLock,
    PageUnlock: surf_PageUnlock,
    SetSurfaceDesc: surf_SetSurfaceDesc,
    SetPrivateData: surf_SetPrivateData,
    GetPrivateData: surf_GetPrivateData,
    FreePrivateData: surf_FreePrivateData,
    GetUniquenessValue: surf_GetUniquenessValue,
    ChangeUniquenessValue: surf_ChangeUniquenessValue,
};

// ── IDirectDraw4 vtable ──────────────────────────────────────────────────────
// Wine ref: include/ddraw.h lines 1681-1724 — IDirectDraw4 method order (28 entries):
// [0]  QueryInterface
// [1]  AddRef
// [2]  Release
// [3]  Compact
// [4]  CreateClipper
// [5]  CreatePalette
// [6]  CreateSurface
// [7]  DuplicateSurface
// [8]  EnumDisplayModes
// [9]  EnumSurfaces
// [10] FlipToGDISurface
// [11] GetCaps
// [12] GetDisplayMode
// [13] GetFourCCCodes
// [14] GetGDISurface
// [15] GetMonitorFrequency
// [16] GetScanLine
// [17] GetVerticalBlankStatus
// [18] Initialize
// [19] RestoreDisplayMode
// [20] SetCooperativeLevel
// [21] SetDisplayMode
// [22] WaitForVerticalBlank
// [23] GetAvailableVidMem  (added in v2)
// [24] GetSurfaceFromDC    (added in v4)
// [25] RestoreAllSurfaces  (added in v4)
// [26] TestCooperativeLevel (added in v4)
// [27] GetDeviceIdentifier (added in v4)
//
// Note: IDirectDraw5 does not exist in Wine's ddraw.h; the progression is
// IDirectDraw → IDirectDraw2 → IDirectDraw3 → IDirectDraw4 → IDirectDraw7.
// We implement IDirectDraw4 as the "IDirectDraw5" stub requested by the task.

#[repr(C)]
pub struct IDirectDraw4Vtbl {
    pub QueryInterface: unsafe extern "win64" fn(*mut u8, *const u8, *mut *mut u8) -> u32,
    pub AddRef: unsafe extern "win64" fn(*mut u8) -> u32,
    pub Release: unsafe extern "win64" fn(*mut u8) -> u32,
    pub Compact: unsafe extern "win64" fn(*mut u8) -> u32,
    pub CreateClipper: unsafe extern "win64" fn(*mut u8, u32, *mut *mut u8, *mut u8) -> u32,
    pub CreatePalette:
        unsafe extern "win64" fn(*mut u8, u32, *mut u8, *mut *mut u8, *mut u8) -> u32,
    pub CreateSurface: unsafe extern "win64" fn(*mut u8, *mut u8, *mut *mut u8, *mut u8) -> u32,
    pub DuplicateSurface: unsafe extern "win64" fn(*mut u8, *mut u8, *mut *mut u8) -> u32,
    pub EnumDisplayModes: unsafe extern "win64" fn(*mut u8, u32, *mut u8, *mut u8, *mut u8) -> u32,
    pub EnumSurfaces: unsafe extern "win64" fn(*mut u8, u32, *mut u8, *mut u8, *mut u8) -> u32,
    pub FlipToGDISurface: unsafe extern "win64" fn(*mut u8) -> u32,
    pub GetCaps: unsafe extern "win64" fn(*mut u8, *mut u8, *mut u8) -> u32,
    pub GetDisplayMode: unsafe extern "win64" fn(*mut u8, *mut u8) -> u32,
    pub GetFourCCCodes: unsafe extern "win64" fn(*mut u8, *mut u32, *mut u32) -> u32,
    pub GetGDISurface: unsafe extern "win64" fn(*mut u8, *mut *mut u8) -> u32,
    pub GetMonitorFrequency: unsafe extern "win64" fn(*mut u8, *mut u32) -> u32,
    pub GetScanLine: unsafe extern "win64" fn(*mut u8, *mut u32) -> u32,
    pub GetVerticalBlankStatus: unsafe extern "win64" fn(*mut u8, *mut u32) -> u32,
    pub Initialize: unsafe extern "win64" fn(*mut u8, *const u8) -> u32,
    pub RestoreDisplayMode: unsafe extern "win64" fn(*mut u8) -> u32,
    pub SetCooperativeLevel: unsafe extern "win64" fn(*mut u8, usize, u32) -> u32,
    pub SetDisplayMode: unsafe extern "win64" fn(*mut u8, u32, u32, u32, u32, u32) -> u32,
    pub WaitForVerticalBlank: unsafe extern "win64" fn(*mut u8, u32, usize) -> u32,
    pub GetAvailableVidMem: unsafe extern "win64" fn(*mut u8, *mut u8, *mut u32, *mut u32) -> u32,
    pub GetSurfaceFromDC: unsafe extern "win64" fn(*mut u8, usize, *mut *mut u8) -> u32,
    pub RestoreAllSurfaces: unsafe extern "win64" fn(*mut u8) -> u32,
    pub TestCooperativeLevel: unsafe extern "win64" fn(*mut u8) -> u32,
    pub GetDeviceIdentifier: unsafe extern "win64" fn(*mut u8, *mut u8, u32) -> u32,
}

// Per-instance IDirectDraw4 object.
//
// Wine ref: dlls/ddraw/ddraw.c::ddraw4_SetCooperativeLevel — stores HWND + DWORD flags on
// the ddraw struct. DirectDrawCreate allocates a fresh instance per call (see DDRAW_Create
// in dlls/ddraw/main.c). Release at refcount zero frees the instance.
//
// COM ABI requirement: vtbl MUST be the first field (guest reads *this as the vtable pointer).
//
// Wine ref (DDSCL flags): dlls/ddraw/ddraw.c:419 — DDSCL_NORMAL used as default coop level.
// DDSCL_EXCLUSIVE / DDSCL_FULLSCREEN / DDSCL_NORMAL are the main flags stored.
#[repr(C)]
pub struct FakeDirectDraw4 {
    pub vtbl: *const IDirectDraw4Vtbl,
    pub refcount: core::sync::atomic::AtomicU32,
    pub hwnd: core::sync::atomic::AtomicUsize,
    pub coop_flags: core::sync::atomic::AtomicU32,
}

// SAFETY: vtable pointer is never mutated; all mutable state is atomic.
unsafe impl Sync for FakeDirectDraw4 {}
unsafe impl Send for FakeDirectDraw4 {}

impl FakeDirectDraw4 {
    fn new_boxed() -> *mut FakeDirectDraw4 {
        use core::sync::atomic::{AtomicU32, AtomicUsize};
        let boxed = Box::new(FakeDirectDraw4 {
            vtbl: &DD4_VTBL,
            refcount: AtomicU32::new(1),
            hwnd: AtomicUsize::new(0),
            coop_flags: AtomicU32::new(0),
        });
        Box::into_raw(boxed)
    }
}

// ── IDirectDraw4 stub implementations ───────────────────────────────────────

unsafe extern "win64" fn dd_QueryInterface(
    _this: *mut u8,
    _riid: *const u8,
    _ppv: *mut *mut u8,
) -> u32 {
    E_NOINTERFACE
}
unsafe extern "win64" fn dd_AddRef(this: *mut u8) -> u32 {
    // Wine ref: dlls/ddraw/ddraw.c::ddraw7_AddRef — InterlockedIncrement on ref,
    // returns new count.
    if this.is_null() {
        return 0;
    }
    let obj = unsafe { &*(this as *const FakeDirectDraw4) };
    obj.refcount
        .fetch_add(1, core::sync::atomic::Ordering::AcqRel)
        + 1
}
unsafe extern "win64" fn dd_Release(this: *mut u8) -> u32 {
    // Wine ref: dlls/ddraw/ddraw.c::ddraw7_Release — InterlockedDecrement; at zero,
    // free the instance (ddraw_destroy cleanup). We Box::from_raw to drop.
    if this.is_null() {
        return 0;
    }
    let obj = unsafe { &*(this as *const FakeDirectDraw4) };
    let prev = obj
        .refcount
        .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    let new_count = prev.saturating_sub(1);
    if new_count == 0 {
        // Last reference — free the Box allocation.
        // KNOWN-BUG-CLASSES: "State maps must deregister on close" — every Box allocated
        // in DirectDrawCreate must be freed here when refcount hits zero.
        unsafe {
            drop(Box::from_raw(this as *mut FakeDirectDraw4));
        }
    }
    new_count
}
unsafe extern "win64" fn dd_Compact(_this: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_CreateClipper(
    _this: *mut u8,
    _f: u32,
    _ppv: *mut *mut u8,
    _outer: *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_CreatePalette(
    _this: *mut u8,
    _f: u32,
    _ct: *mut u8,
    _ppv: *mut *mut u8,
    _outer: *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_CreateSurface(
    this: *mut u8,
    desc: *mut u8,
    ppv: *mut *mut u8,
    _outer: *mut u8,
) -> u32 {
    // Wine ref: dlls/ddraw/ddraw.c::ddraw4_CreateSurface — reads DDSURFACEDESC2
    // from the guest (width/height/pixel format govern the allocation), invokes
    // ddraw_surface_create, and writes the new surface pointer back through ppv.
    //
    // Dispatch 2 policy:
    //   - Default to 640x480x32bpp BGRA when caller didn't supply DDSD_WIDTH/HEIGHT.
    //   - Honor guest-provided width/height when DDSD_WIDTH | DDSD_HEIGHT are set.
    //   - bpp is fixed at 32 for now (DDSD_PIXELFORMAT parsing deferred to dispatch 3).
    if ppv.is_null() {
        return E_FAIL;
    }
    let (mut w, mut h, bpp) = (
        FakeSurface4::DEFAULT_WIDTH,
        FakeSurface4::DEFAULT_HEIGHT,
        FakeSurface4::DEFAULT_BPP,
    );
    if !desc.is_null() {
        let d = unsafe { &*(desc as *const Ddsd2) };
        // Guard against malformed desc (dwSize too small).
        let min_size = core::mem::offset_of!(Ddsd2, lp_surface) as u32;
        if d.dw_size >= min_size {
            if d.dw_flags & DDSD_WIDTH != 0 && d.dw_width > 0 {
                w = d.dw_width;
            }
            if d.dw_flags & DDSD_HEIGHT != 0 && d.dw_height > 0 {
                h = d.dw_height;
            }
            let _ = d.dw_flags & DDSD_PIXELFORMAT; // acknowledged; parsed in dispatch 3
        }
    }
    let ptr = FakeSurface4::new_boxed(w, h, bpp, this);
    unsafe {
        *ppv = ptr as *mut u8;
    }
    DD_OK
}
unsafe extern "win64" fn dd_DuplicateSurface(
    _this: *mut u8,
    _src: *mut u8,
    _ppv: *mut *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_EnumDisplayModes(
    _this: *mut u8,
    _f: u32,
    _desc: *mut u8,
    _ctx: *mut u8,
    _cb: *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_EnumSurfaces(
    _this: *mut u8,
    _f: u32,
    _desc: *mut u8,
    _ctx: *mut u8,
    _cb: *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_FlipToGDISurface(_this: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_GetCaps(_this: *mut u8, _drv: *mut u8, _hel: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_GetDisplayMode(_this: *mut u8, _desc: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_GetFourCCCodes(
    _this: *mut u8,
    _num: *mut u32,
    _codes: *mut u32,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_GetGDISurface(_this: *mut u8, _ppv: *mut *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_GetMonitorFrequency(_this: *mut u8, _freq: *mut u32) -> u32 {
    if !_freq.is_null() {
        unsafe {
            *_freq = 60;
        }
    }
    DD_OK
}
unsafe extern "win64" fn dd_GetScanLine(_this: *mut u8, _scan: *mut u32) -> u32 {
    if !_scan.is_null() {
        unsafe {
            *_scan = 0;
        }
    }
    DD_OK
}
unsafe extern "win64" fn dd_GetVerticalBlankStatus(_this: *mut u8, _vb: *mut u32) -> u32 {
    if !_vb.is_null() {
        unsafe {
            *_vb = 0;
        }
    }
    DD_OK
}
unsafe extern "win64" fn dd_Initialize(_this: *mut u8, _guid: *const u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_RestoreDisplayMode(_this: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_SetCooperativeLevel(this: *mut u8, hwnd: usize, flags: u32) -> u32 {
    // Wine ref: dlls/ddraw/ddraw.c::ddraw4_SetCooperativeLevel (line 1034) — signature
    // (IDirectDraw4 *iface, HWND window, DWORD flags). Wine stores the window handle on
    // the ddraw instance and records coop flags (DDSCL_NORMAL / DDSCL_EXCLUSIVE /
    // DDSCL_FULLSCREEN). We mirror that state-store so later dispatches can honor it.
    if this.is_null() {
        return E_FAIL;
    }
    let obj = unsafe { &*(this as *const FakeDirectDraw4) };
    obj.hwnd.store(hwnd, core::sync::atomic::Ordering::Release);
    obj.coop_flags
        .store(flags, core::sync::atomic::Ordering::Release);
    DD_OK
}
unsafe extern "win64" fn dd_SetDisplayMode(
    _this: *mut u8,
    _w: u32,
    _h: u32,
    _bpp: u32,
    _refresh: u32,
    _flags: u32,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_WaitForVerticalBlank(
    _this: *mut u8,
    _flags: u32,
    _event: usize,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_GetAvailableVidMem(
    _this: *mut u8,
    _caps: *mut u8,
    _total: *mut u32,
    _free: *mut u32,
) -> u32 {
    // Wine ref: include/ddraw.h GetAvailableVidMem — DDSCAPS2 filter, total/free out
    const VID_MEM: u32 = 256 * 1024 * 1024;
    if !_total.is_null() {
        unsafe {
            *_total = VID_MEM;
        }
    }
    if !_free.is_null() {
        unsafe {
            *_free = VID_MEM;
        }
    }
    DD_OK
}
unsafe extern "win64" fn dd_GetSurfaceFromDC(
    _this: *mut u8,
    _dc: usize,
    _ppv: *mut *mut u8,
) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_RestoreAllSurfaces(_this: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_TestCooperativeLevel(_this: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn dd_GetDeviceIdentifier(
    _this: *mut u8,
    _ident: *mut u8,
    _flags: u32,
) -> u32 {
    DD_OK
}

static DD4_VTBL: IDirectDraw4Vtbl = IDirectDraw4Vtbl {
    QueryInterface: dd_QueryInterface,
    AddRef: dd_AddRef,
    Release: dd_Release,
    Compact: dd_Compact,
    CreateClipper: dd_CreateClipper,
    CreatePalette: dd_CreatePalette,
    CreateSurface: dd_CreateSurface,
    DuplicateSurface: dd_DuplicateSurface,
    EnumDisplayModes: dd_EnumDisplayModes,
    EnumSurfaces: dd_EnumSurfaces,
    FlipToGDISurface: dd_FlipToGDISurface,
    GetCaps: dd_GetCaps,
    GetDisplayMode: dd_GetDisplayMode,
    GetFourCCCodes: dd_GetFourCCCodes,
    GetGDISurface: dd_GetGDISurface,
    GetMonitorFrequency: dd_GetMonitorFrequency,
    GetScanLine: dd_GetScanLine,
    GetVerticalBlankStatus: dd_GetVerticalBlankStatus,
    Initialize: dd_Initialize,
    RestoreDisplayMode: dd_RestoreDisplayMode,
    SetCooperativeLevel: dd_SetCooperativeLevel,
    SetDisplayMode: dd_SetDisplayMode,
    WaitForVerticalBlank: dd_WaitForVerticalBlank,
    GetAvailableVidMem: dd_GetAvailableVidMem,
    GetSurfaceFromDC: dd_GetSurfaceFromDC,
    RestoreAllSurfaces: dd_RestoreAllSurfaces,
    TestCooperativeLevel: dd_TestCooperativeLevel,
    GetDeviceIdentifier: dd_GetDeviceIdentifier,
};

// ── Exported API functions ───────────────────────────────────────────────────
// Wine ref: dlls/ddraw/main.c::DirectDrawCreate — takes GUID*, IDirectDraw**, IUnknown*.
// Wine's DirectDrawCreate allocates a fresh struct ddraw per call via DDRAW_Create; we
// mirror that per-instance pattern with Box::into_raw. Release drops the Box when the
// refcount reaches zero (see dd_Release).

/// # Safety
/// Called from Windows PE IAT — raw pointers from guest process.
#[no_mangle]
pub unsafe extern "win64" fn DirectDrawCreate(
    _lpGUID: *const u8,
    lplpDD: *mut *mut u8,
    _pUnkOuter: *mut u8,
) -> u32 {
    eprintln!("[weave-ddraw] DirectDrawCreate called");
    if !lplpDD.is_null() {
        let ptr = FakeDirectDraw4::new_boxed();
        *lplpDD = ptr as *mut u8;
    }
    DD_OK
}

/// # Safety
/// Called from Windows PE IAT — raw pointers from guest process.
#[no_mangle]
pub unsafe extern "win64" fn DirectDrawCreateEx(
    _lpGUID: *const u8,
    lplpDD: *mut *mut u8,
    _iid: *const u8,
    _pUnkOuter: *mut u8,
) -> u32 {
    eprintln!("[weave-ddraw] DirectDrawCreateEx called");
    if !lplpDD.is_null() {
        let ptr = FakeDirectDraw4::new_boxed();
        *lplpDD = ptr as *mut u8;
    }
    DD_OK
}

/// # Safety
/// Called from Windows PE IAT — raw pointers from guest process.
#[no_mangle]
pub unsafe extern "win64" fn DirectDrawEnumerateA(
    _lpCallback: *const u8,
    _lpContext: *mut u8,
) -> u32 {
    eprintln!("[weave-ddraw] DirectDrawEnumerateA called (no devices to enumerate)");
    DD_OK
}

/// # Safety
/// Called from Windows PE IAT — raw pointers from guest process.
#[no_mangle]
pub unsafe extern "win64" fn DirectDrawEnumerateW(
    _lpCallback: *const u8,
    _lpContext: *mut u8,
) -> u32 {
    eprintln!("[weave-ddraw] DirectDrawEnumerateW called (no devices to enumerate)");
    DD_OK
}

/// # Safety
/// Called from Windows PE IAT — raw pointers from guest process.
#[no_mangle]
pub unsafe extern "win64" fn DirectDrawEnumerateExA(
    _lpCallback: *const u8,
    _lpContext: *mut u8,
    _dwFlags: u32,
) -> u32 {
    eprintln!("[weave-ddraw] DirectDrawEnumerateExA called");
    DD_OK
}

/// # Safety
/// Called from Windows PE IAT — raw pointers from guest process.
#[no_mangle]
pub unsafe extern "win64" fn DirectDrawEnumerateExW(
    _lpCallback: *const u8,
    _lpContext: *mut u8,
    _dwFlags: u32,
) -> u32 {
    eprintln!("[weave-ddraw] DirectDrawEnumerateExW called");
    DD_OK
}

// ── COM helpers ──────────────────────────────────────────────────────────────

/// # Safety
/// Called from Windows PE IAT.
#[no_mangle]
pub unsafe extern "win64" fn DllCanUnloadNow() -> u32 {
    S_FALSE
}

/// # Safety
/// Called from Windows PE IAT — raw pointers from guest process.
#[no_mangle]
pub unsafe extern "win64" fn DllGetClassObject(
    _rclsid: *const u8,
    _riid: *const u8,
    _ppv: *mut *mut u8,
) -> u32 {
    E_FAIL
}

// ── IAT resolver ─────────────────────────────────────────────────────────────

pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("ddraw.dll") {
        return None;
    }
    let ptr: usize = match func {
        "DirectDrawCreate" => DirectDrawCreate as *const () as usize,
        "DirectDrawCreateEx" => DirectDrawCreateEx as *const () as usize,
        "DirectDrawEnumerateA" => DirectDrawEnumerateA as *const () as usize,
        "DirectDrawEnumerateW" => DirectDrawEnumerateW as *const () as usize,
        "DirectDrawEnumerateExA" => DirectDrawEnumerateExA as *const () as usize,
        "DirectDrawEnumerateExW" => DirectDrawEnumerateExW as *const () as usize,
        "DllCanUnloadNow" => DllCanUnloadNow as *const () as usize,
        "DllGetClassObject" => DllGetClassObject as *const () as usize,
        _ => return None,
    };
    Some(ptr)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    /// DDSCL_NORMAL from Wine's include/ddraw.h — used as a sentinel coop flag.
    const DDSCL_NORMAL_SENTINEL: u32 = 0x00000008;
    /// Arbitrary fake HWND — not a real window handle; used only to verify storage.
    const TEST_HWND: usize = 0xDEAD_BEEF;

    /// Full lifecycle: Create → SetCooperativeLevel → verify stored → Release → freed.
    ///
    /// Sanity-check for the per-instance state plumbing:
    /// 1. DirectDrawCreate returns a non-null pointer
    /// 2. Vtable SetCooperativeLevel stores hwnd + flags on the instance
    /// 3. Release decrements refcount and frees at zero (Box::from_raw drop)
    #[test]
    fn ddraw_instance_lifecycle() {
        let mut out: *mut u8 = core::ptr::null_mut();
        let hr = unsafe {
            DirectDrawCreate(
                core::ptr::null(),
                &mut out as *mut *mut u8,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(hr, DD_OK);
        assert!(!out.is_null(), "DirectDrawCreate returned null instance");

        // Inspect initial state: refcount = 1, hwnd = 0, coop_flags = 0.
        let obj = unsafe { &*(out as *const FakeDirectDraw4) };
        assert_eq!(obj.refcount.load(Ordering::Acquire), 1);
        assert_eq!(obj.hwnd.load(Ordering::Acquire), 0);
        assert_eq!(obj.coop_flags.load(Ordering::Acquire), 0);

        // Call SetCooperativeLevel via the vtable (not via direct function pointer),
        // to exercise the same path the guest takes.
        let vtbl = unsafe { &*obj.vtbl };
        let hr = unsafe { (vtbl.SetCooperativeLevel)(out, TEST_HWND, DDSCL_NORMAL_SENTINEL) };
        assert_eq!(hr, DD_OK);

        // Re-read state: verify hwnd + flags were stored on this specific instance.
        assert_eq!(obj.hwnd.load(Ordering::Acquire), TEST_HWND);
        assert_eq!(
            obj.coop_flags.load(Ordering::Acquire),
            DDSCL_NORMAL_SENTINEL
        );

        // Release drops refcount to zero and frees the Box.
        let remaining = unsafe { (vtbl.Release)(out) };
        assert_eq!(remaining, 0, "Release at refcount=1 must yield 0");
        // NOTE: `out` is dangling here — do not dereference.
    }

    /// AddRef then Release twice — first Release keeps the object alive, second frees.
    #[test]
    fn ddraw_refcount_addref_release() {
        let mut out: *mut u8 = core::ptr::null_mut();
        unsafe {
            DirectDrawCreate(
                core::ptr::null(),
                &mut out as *mut *mut u8,
                core::ptr::null_mut(),
            );
        }
        assert!(!out.is_null());

        let vtbl = unsafe { &*(*(out as *const FakeDirectDraw4)).vtbl };

        // AddRef: 1 → 2
        let two = unsafe { (vtbl.AddRef)(out) };
        assert_eq!(two, 2);

        // Release: 2 → 1 (not freed)
        let one = unsafe { (vtbl.Release)(out) };
        assert_eq!(one, 1);

        // State should still be intact — instance is still alive.
        let obj = unsafe { &*(out as *const FakeDirectDraw4) };
        assert_eq!(obj.refcount.load(Ordering::Acquire), 1);

        // Release: 1 → 0 (freed)
        let zero = unsafe { (vtbl.Release)(out) };
        assert_eq!(zero, 0);
    }

    /// Two DirectDrawCreate calls must return distinct pointers.
    #[test]
    fn ddraw_instances_are_distinct() {
        let mut a: *mut u8 = core::ptr::null_mut();
        let mut b: *mut u8 = core::ptr::null_mut();
        unsafe {
            DirectDrawCreate(
                core::ptr::null(),
                &mut a as *mut *mut u8,
                core::ptr::null_mut(),
            );
            DirectDrawCreate(
                core::ptr::null(),
                &mut b as *mut *mut u8,
                core::ptr::null_mut(),
            );
        }
        assert!(!a.is_null() && !b.is_null());
        assert_ne!(a, b, "Per-instance allocation must yield distinct pointers");

        // Store different state on each, confirm isolation.
        let obj_a = unsafe { &*(a as *const FakeDirectDraw4) };
        let obj_b = unsafe { &*(b as *const FakeDirectDraw4) };
        obj_a.hwnd.store(0x1111, Ordering::Release);
        obj_b.hwnd.store(0x2222, Ordering::Release);
        assert_eq!(obj_a.hwnd.load(Ordering::Acquire), 0x1111);
        assert_eq!(obj_b.hwnd.load(Ordering::Acquire), 0x2222);

        // Free both.
        let vtbl_a = unsafe { &*obj_a.vtbl };
        let vtbl_b = unsafe { &*obj_b.vtbl };
        assert_eq!(unsafe { (vtbl_a.Release)(a) }, 0);
        assert_eq!(unsafe { (vtbl_b.Release)(b) }, 0);
    }

    // ── IDirectDrawSurface4 dispatch 2 tests ─────────────────────────────────

    /// Helper: create a ddraw instance + a default primary surface.
    /// Returns (ddraw_ptr, surface_ptr). Caller must Release both.
    unsafe fn make_ddraw_and_surface() -> (*mut u8, *mut u8) {
        let mut dd: *mut u8 = core::ptr::null_mut();
        unsafe {
            DirectDrawCreate(
                core::ptr::null(),
                &mut dd as *mut *mut u8,
                core::ptr::null_mut(),
            );
        }
        assert!(!dd.is_null());
        let dd_vtbl = unsafe { &*(*(dd as *const FakeDirectDraw4)).vtbl };
        let mut surf: *mut u8 = core::ptr::null_mut();
        let hr = unsafe {
            (dd_vtbl.CreateSurface)(
                dd,
                core::ptr::null_mut(), // no desc → defaults (640x480x32bpp)
                &mut surf as *mut *mut u8,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(hr, DD_OK);
        assert!(!surf.is_null());
        (dd, surf)
    }

    /// CreateSurface must return non-null and distinct pointers across calls.
    #[test]
    fn surface_instances_are_distinct() {
        let (dd, s1) = unsafe { make_ddraw_and_surface() };
        let dd_vtbl = unsafe { &*(*(dd as *const FakeDirectDraw4)).vtbl };
        let mut s2: *mut u8 = core::ptr::null_mut();
        let hr = unsafe {
            (dd_vtbl.CreateSurface)(
                dd,
                core::ptr::null_mut(),
                &mut s2 as *mut *mut u8,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(hr, DD_OK);
        assert!(!s2.is_null());
        assert_ne!(s1, s2, "CreateSurface must return distinct allocations");

        // Each surface must have its own distinct backing buffer too.
        let o1 = unsafe { &*(s1 as *const FakeSurface4) };
        let o2 = unsafe { &*(s2 as *const FakeSurface4) };
        assert_ne!(o1.pixels, o2.pixels);

        let s_vtbl = unsafe { &*o1.vtbl };
        assert_eq!(unsafe { (s_vtbl.Release)(s1) }, 0);
        assert_eq!(unsafe { (s_vtbl.Release)(s2) }, 0);
        let dd_vtbl = unsafe { &*(*(dd as *const FakeDirectDraw4)).vtbl };
        assert_eq!(unsafe { (dd_vtbl.Release)(dd) }, 0);
    }

    /// Lock returns DD_OK and writes non-null lpSurface + non-zero lPitch.
    #[test]
    fn surface_lock_writes_lp_surface_and_pitch() {
        let (dd, surf) = unsafe { make_ddraw_and_surface() };
        let s_vtbl = unsafe { &*(*(surf as *const FakeSurface4)).vtbl };

        // Zero-initialized DDSURFACEDESC2 (as the guest would do after memset).
        let mut desc: Ddsd2 = unsafe { core::mem::zeroed() };
        desc.dw_size = core::mem::size_of::<Ddsd2>() as u32;

        let hr = unsafe {
            (s_vtbl.Lock)(
                surf,
                core::ptr::null_mut(),
                &mut desc as *mut Ddsd2 as *mut u8,
                0,
                0,
            )
        };
        assert_eq!(hr, DD_OK);
        assert!(
            !desc.lp_surface.is_null(),
            "Lock must publish a pixel pointer"
        );
        assert!(desc.l_pitch > 0, "Lock must publish a positive row pitch");
        assert_ne!(desc.dw_flags & DDSD_LPSURFACE, 0);
        assert_ne!(desc.dw_flags & DDSD_PITCH, 0);
        assert_eq!(desc.dw_width, 640);
        assert_eq!(desc.dw_height, 480);
        // 640 * 4 bytes/px = 2560
        assert_eq!(desc.l_pitch, 640 * 4);

        let dd_vtbl = unsafe { &*(*(dd as *const FakeDirectDraw4)).vtbl };
        assert_eq!(unsafe { (s_vtbl.Release)(surf) }, 0);
        assert_eq!(unsafe { (dd_vtbl.Release)(dd) }, 0);
    }

    /// Guest writes to lpSurface then reads it back via a second Lock — data
    /// must persist across Unlock/Lock (buffer is owned by the surface).
    #[test]
    fn surface_lock_pixel_write_read_roundtrip() {
        let (dd, surf) = unsafe { make_ddraw_and_surface() };
        let s_vtbl = unsafe { &*(*(surf as *const FakeSurface4)).vtbl };

        // First Lock — obtain pointer, write a known 4-byte pattern at pixel 0.
        let mut desc1: Ddsd2 = unsafe { core::mem::zeroed() };
        desc1.dw_size = core::mem::size_of::<Ddsd2>() as u32;
        let hr = unsafe {
            (s_vtbl.Lock)(
                surf,
                core::ptr::null_mut(),
                &mut desc1 as *mut Ddsd2 as *mut u8,
                0,
                0,
            )
        };
        assert_eq!(hr, DD_OK);
        unsafe {
            let p = desc1.lp_surface;
            *p.add(0) = 0xFF;
            *p.add(1) = 0x00;
            *p.add(2) = 0x00;
            *p.add(3) = 0xFF;
        }
        // Unlock is a no-op for dispatch 2 but must return DD_OK.
        let hr = unsafe { (s_vtbl.Unlock)(surf, core::ptr::null_mut()) };
        assert_eq!(hr, DD_OK);

        // Second Lock — read back through the (again-published) pointer.
        let mut desc2: Ddsd2 = unsafe { core::mem::zeroed() };
        desc2.dw_size = core::mem::size_of::<Ddsd2>() as u32;
        let hr = unsafe {
            (s_vtbl.Lock)(
                surf,
                core::ptr::null_mut(),
                &mut desc2 as *mut Ddsd2 as *mut u8,
                0,
                0,
            )
        };
        assert_eq!(hr, DD_OK);
        assert_eq!(
            desc2.lp_surface, desc1.lp_surface,
            "Same surface ⇒ same pointer"
        );
        unsafe {
            let p = desc2.lp_surface;
            assert_eq!(*p.add(0), 0xFF);
            assert_eq!(*p.add(1), 0x00);
            assert_eq!(*p.add(2), 0x00);
            assert_eq!(*p.add(3), 0xFF);
        }

        let dd_vtbl = unsafe { &*(*(dd as *const FakeDirectDraw4)).vtbl };
        assert_eq!(unsafe { (s_vtbl.Release)(surf) }, 0);
        assert_eq!(unsafe { (dd_vtbl.Release)(dd) }, 0);
    }

    /// AddRef + two Release calls on a surface — first keeps alive, second frees.
    /// Independent instance must Release cleanly afterward (no cross-talk).
    #[test]
    fn surface_refcount_addref_release() {
        let (dd, surf) = unsafe { make_ddraw_and_surface() };
        let s_vtbl = unsafe { &*(*(surf as *const FakeSurface4)).vtbl };

        let two = unsafe { (s_vtbl.AddRef)(surf) };
        assert_eq!(two, 2);
        let one = unsafe { (s_vtbl.Release)(surf) };
        assert_eq!(one, 1);
        let obj = unsafe { &*(surf as *const FakeSurface4) };
        assert_eq!(obj.refcount.load(Ordering::Acquire), 1);
        let zero = unsafe { (s_vtbl.Release)(surf) };
        assert_eq!(zero, 0);

        // Verify an independent new surface still Releases cleanly after
        // the prior one was freed — no double-free contamination.
        let dd_vtbl = unsafe { &*(*(dd as *const FakeDirectDraw4)).vtbl };
        let mut s2: *mut u8 = core::ptr::null_mut();
        let _ = unsafe {
            (dd_vtbl.CreateSurface)(
                dd,
                core::ptr::null_mut(),
                &mut s2 as *mut *mut u8,
                core::ptr::null_mut(),
            )
        };
        assert!(!s2.is_null());
        let s2_vtbl = unsafe { &*(*(s2 as *const FakeSurface4)).vtbl };
        assert_eq!(unsafe { (s2_vtbl.Release)(s2) }, 0);
        assert_eq!(unsafe { (dd_vtbl.Release)(dd) }, 0);
    }

    /// GetSurfaceDesc fills out geometry + pitch + lpSurface.
    #[test]
    fn surface_get_surface_desc_fills_geometry() {
        let (dd, surf) = unsafe { make_ddraw_and_surface() };
        let s_vtbl = unsafe { &*(*(surf as *const FakeSurface4)).vtbl };

        let mut desc: Ddsd2 = unsafe { core::mem::zeroed() };
        desc.dw_size = core::mem::size_of::<Ddsd2>() as u32;
        let hr = unsafe { (s_vtbl.GetSurfaceDesc)(surf, &mut desc as *mut Ddsd2 as *mut u8) };
        assert_eq!(hr, DD_OK);
        assert_eq!(desc.dw_width, 640);
        assert_eq!(desc.dw_height, 480);
        assert_eq!(desc.l_pitch, 640 * 4);
        assert!(!desc.lp_surface.is_null());

        let dd_vtbl = unsafe { &*(*(dd as *const FakeDirectDraw4)).vtbl };
        assert_eq!(unsafe { (s_vtbl.Release)(surf) }, 0);
        assert_eq!(unsafe { (dd_vtbl.Release)(dd) }, 0);
    }

    /// DDSURFACEDESC2 field offsets must match Wine's include/ddraw.h:1036
    /// for the 32-bit fields (all up to lpSurface). lpSurface itself shifts on
    /// x86-64 due to 8-byte pointer alignment; this test documents both cases.
    #[test]
    fn ddsd2_field_offsets_match_wine_header() {
        use core::mem::offset_of;
        assert_eq!(offset_of!(Ddsd2, dw_size), 0x00);
        assert_eq!(offset_of!(Ddsd2, dw_flags), 0x04);
        assert_eq!(offset_of!(Ddsd2, dw_height), 0x08);
        assert_eq!(offset_of!(Ddsd2, dw_width), 0x0C);
        assert_eq!(offset_of!(Ddsd2, l_pitch), 0x10);
        assert_eq!(offset_of!(Ddsd2, dw_back_buffer_count), 0x14);
        assert_eq!(offset_of!(Ddsd2, dw_mip_map_count), 0x18);
        assert_eq!(offset_of!(Ddsd2, dw_alpha_bit_depth), 0x1C);
        assert_eq!(offset_of!(Ddsd2, dw_reserved), 0x20);
        // lpSurface: Wine comment says 0x24 (x86); on x86-64 natural alignment
        // of an 8-byte pointer after a 4-byte field forces offset 0x28.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(offset_of!(Ddsd2, lp_surface), 0x28);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(offset_of!(Ddsd2, lp_surface), 0x24);
    }
}
