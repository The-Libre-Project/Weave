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

#[repr(C)]
pub struct FakeSurface4 {
    pub vtbl: *const IDirectDrawSurface4Vtbl,
}

// SAFETY: vtable pointer is never mutated; safe to share across threads as a static.
unsafe impl Sync for FakeSurface4 {}

// ── IDirectDrawSurface4 stub implementations ─────────────────────────────────

unsafe extern "win64" fn surf_QueryInterface(
    _this: *mut u8,
    _riid: *const u8,
    _ppv: *mut *mut u8,
) -> u32 {
    E_NOINTERFACE
}
unsafe extern "win64" fn surf_AddRef(_this: *mut u8) -> u32 {
    1
}
unsafe extern "win64" fn surf_Release(_this: *mut u8) -> u32 {
    1
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
unsafe extern "win64" fn surf_GetSurfaceDesc(_this: *mut u8, _desc: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_Initialize(_this: *mut u8, _dd: *mut u8, _desc: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_IsLost(_this: *mut u8) -> u32 {
    DD_OK
}
unsafe extern "win64" fn surf_Lock(
    _this: *mut u8,
    _rect: *mut u8,
    _desc: *mut u8,
    _flags: u32,
    _event: usize,
) -> u32 {
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

static FAKE_SURFACE4: FakeSurface4 = FakeSurface4 {
    vtbl: &SURFACE4_VTBL,
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

#[repr(C)]
pub struct FakeDirectDraw4 {
    pub vtbl: *const IDirectDraw4Vtbl,
}

// SAFETY: vtable pointer is never mutated; safe to share across threads as a static.
unsafe impl Sync for FakeDirectDraw4 {}

// ── IDirectDraw4 stub implementations ───────────────────────────────────────

unsafe extern "win64" fn dd_QueryInterface(
    _this: *mut u8,
    _riid: *const u8,
    _ppv: *mut *mut u8,
) -> u32 {
    E_NOINTERFACE
}
unsafe extern "win64" fn dd_AddRef(_this: *mut u8) -> u32 {
    1
}
unsafe extern "win64" fn dd_Release(_this: *mut u8) -> u32 {
    1
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
    _this: *mut u8,
    _desc: *mut u8,
    _ppv: *mut *mut u8,
    _outer: *mut u8,
) -> u32 {
    // Return a pointer to our fake surface stub
    if !_ppv.is_null() {
        unsafe {
            *_ppv = &FAKE_SURFACE4 as *const FakeSurface4 as *mut u8;
        }
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
unsafe extern "win64" fn dd_SetCooperativeLevel(_this: *mut u8, _hwnd: usize, _flags: u32) -> u32 {
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

static FAKE_DDRAW4: FakeDirectDraw4 = FakeDirectDraw4 { vtbl: &DD4_VTBL };

// ── Exported API functions ───────────────────────────────────────────────────
// Wine ref: dlls/ddraw/main.c::DirectDrawCreate — takes GUID*, IDirectDraw**, IUnknown*

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
        *lplpDD = &FAKE_DDRAW4 as *const FakeDirectDraw4 as *mut u8;
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
        *lplpDD = &FAKE_DDRAW4 as *const FakeDirectDraw4 as *mut u8;
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
