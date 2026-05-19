//! gdiplus.dll stubs for Weave.
//!
//! GDI+ is Windows' 2D graphics library: anti-aliased drawing, image codecs
//! (JPEG, PNG, BMP, GIF, TIFF, …), alpha-compositing, path rendering, and
//! font layout. It is needed by IrfanView, Paint.NET, and any application that
//! calls `GdiplusStartup`.
//!
//! # Implementation status
//!
//! All exports are stubs. The startup/shutdown pair succeeds (returns Ok=0) so
//! that apps can initialise GDI+ and proceed to the message loop. Image-loading
//! and drawing functions return `NotImplemented` (6) so that apps which check
//! the status code fall back gracefully rather than crashing.
//!
//! Codec enumeration (`GdipGetImageEncoders/Decoders`) reports zero codecs; apps
//! that rely on this to list file formats will see an empty list. This is
//! correct headless behaviour — no display, no codecs.
//!
//! # Wine ref
//! dlls/gdiplus/*.c — GDI+ flat API naming convention, GpStatus codes,
//! GdiplusStartupInput/Output layout, codec enumeration semantics.

#![allow(non_snake_case)]

extern crate libc;

// ── GpStatus values ───────────────────────────────────────────────────────────
//
// Wine ref: include/gdiplus/gdiplustypes.h — GpStatus enum; values confirmed
// by reading dlls/gdiplus/gdiplus.c and dlls/gdiplus/image.c.
const GP_OK: i32 = 0;
const GP_GENERIC_ERROR: i32 = 1;
const GP_INVALID_PARAMETER: i32 = 2;
const GP_OUT_OF_MEMORY: i32 = 3;
const GP_NOT_IMPLEMENTED: i32 = 6;

// ── Startup / Shutdown ────────────────────────────────────────────────────────

// Wine ref: dlls/gdiplus/gdiplus.c — NotificationHook/Unhook stubs for
// callers that set SuppressBackgroundThread=TRUE and then call these themselves.
pub extern "win64" fn gdip_notification_hook(_token: *mut usize) -> i32 {
    GP_OK
}
pub extern "win64" fn gdip_notification_unhook(_token: usize) {}

/// GdiplusStartup — initialise the GDI+ subsystem for this process.
///
/// Wine ref: dlls/gdiplus/gdiplus.c:83 — returns InvalidParameter if `token`
/// OR `input` is NULL (both checked). Validates GdiplusVersion: must be 1 or 2
/// (returns UnsupportedGdiplusVersion=18 otherwise). When
/// `input->SuppressBackgroundThread` is set, `output` must be non-null
/// (InvalidParameter if not) and Wine fills `output->NotificationHook/Unhook`.
/// Token value Wine uses is `0xdeadbeef` — opaque cookie passed to Shutdown.
/// We use the same value.
///
/// # Safety
/// `token` must be a writable `ULONG_PTR *` (8 bytes on x64).
/// `input` must be a valid `GdiplusStartupInput *` (not NULL — we check).
/// `output` is optional unless SuppressBackgroundThread is set.
#[no_mangle]
pub unsafe extern "win64" fn GdiplusStartup(
    token: *mut usize,
    input: *const u8,
    output: *mut u8,
) -> i32 {
    eprintln!("weave/gdiplus: GdiplusStartup");
    // Wine ref: dlls/gdiplus/gdiplus.c:87 — both token and input are required.
    if token.is_null() || input.is_null() {
        return GP_INVALID_PARAMETER;
    }
    // GdiplusStartupInput x64 layout (MSVC, no pack):
    //   +0  GdiplusVersion: u32
    //   +4  (padding)
    //   +8  DebugEventCallback: *fn (ignored)
    //   +16 SuppressBackgroundThread: BOOL (u32)
    //   +20 SuppressExternalCodecs: BOOL (u32)
    // Wine ref: dlls/gdiplus/gdiplus.c:94 — version must be 1 or 2.
    let version = unsafe { *(input as *const u32) };
    if !(1..=2).contains(&version) {
        return 18; // UnsupportedGdiplusVersion
    }
    // Wine ref: dlls/gdiplus/gdiplus.c:104 — when SuppressBackgroundThread is
    // set, output must be non-null and receives NotificationHook/Unhook pointers.
    let suppress_bg = unsafe { *(input.add(16) as *const u32) };
    if suppress_bg != 0 {
        if output.is_null() {
            return GP_INVALID_PARAMETER;
        }
        // GdiplusStartupOutput layout: +0 NotificationHook ptr, +8 NotificationUnhook ptr
        unsafe {
            *(output as *mut usize) = gdip_notification_hook as *const () as usize;
            *(output.add(8) as *mut usize) = gdip_notification_unhook as *const () as usize;
        }
    }
    // Wine ref: dlls/gdiplus/gdiplus.c:104 — token set to 0xdeadbeef.
    unsafe { *token = 0xdeadbeef };
    GP_OK
}

/// GdiplusShutdown — shut down the GDI+ subsystem for this token.
///
/// Wine ref: dlls/gdiplus/gdiplus.c:127 — exported as `GdiplusShutdown_wrapper`
/// with a ULONG return type (not void). The wrapper always returns 0. The
/// "bricksntiles" game relies on the return value being 0, per the Wine comment.
/// We match this: `-> u32`, returns 0.
///
/// # Safety
/// `token` is the opaque cookie from GdiplusStartup (0xdeadbeef). Ignored here.
#[no_mangle]
pub unsafe extern "win64" fn GdiplusShutdown(_token: usize) -> u32 {
    eprintln!("weave/gdiplus: GdiplusShutdown");
    0
}

// ── Memory allocation ─────────────────────────────────────────────────────────

/// GdipAlloc — allocate zeroed memory for GDI+ internal use.
///
/// Wine ref: dlls/gdiplus/gdiplus.c — thin wrapper around `heap_alloc_zero`
/// (calloc). Used by callers that retrieve it via `GetProcAddress` as a custom
/// allocator.
///
/// # Safety
/// Caller is responsible for freeing the returned pointer with `GdipFree`.
#[no_mangle]
pub unsafe extern "win64" fn GdipAlloc(size: usize) -> *mut u8 {
    unsafe { libc::calloc(1, size) as *mut u8 }
}

/// GdipFree — free memory allocated by `GdipAlloc`.
///
/// Wine ref: dlls/gdiplus/gdiplus.c — thin wrapper around `heap_free`.
///
/// # Safety
/// `ptr` must have been returned by `GdipAlloc` and must not be freed twice.
#[no_mangle]
pub unsafe extern "win64" fn GdipFree(ptr: *mut u8) {
    unsafe { libc::free(ptr as *mut libc::c_void) }
}

// ── Codec enumeration ─────────────────────────────────────────────────────────

/// GdipGetImageEncodersSize — query how many image encoders are available.
///
/// Wine ref: dlls/gdiplus/image.c:5303 — returns InvalidParameter if either
/// pointer is NULL. Counts codecs whose `Flags & ImageCodecFlagsEncoder` is set
/// and returns (count, count * sizeof(ImageCodecInfo)). We have no codec backend
/// so both outputs are 0, returning Ok.
///
/// # Safety
/// `count` and `size` must be writable u32 pointers.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageEncodersSize(count: *mut u32, size: *mut u32) -> i32 {
    if count.is_null() || size.is_null() {
        return GP_INVALID_PARAMETER;
    }
    unsafe {
        *count = 0;
        *size = 0;
    }
    GP_OK
}

/// GdipGetImageEncoders — fill a caller-supplied buffer with encoder info.
///
/// Wine ref: dlls/gdiplus/image.c:5327 — returns GenericError(1) if `encoders`
/// is NULL OR if `size != numEncoders * sizeof(ImageCodecInfo)`. Since we
/// report numEncoders=0 and size=0, a caller that passes count=0, size=0 with
/// a non-null buffer will get Ok; a null buffer gets GenericError. We match this.
///
/// # Safety
/// `encoders` must be a writable buffer of at least `size` bytes, or NULL
/// (in which case GenericError is returned when numEncoders > 0).
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageEncoders(
    num_encoders: u32,
    size: u32,
    encoders: *mut u8,
) -> i32 {
    // Wine ref: dlls/gdiplus/image.c:5336 — GenericError if buffer NULL or
    // size doesn't match count * sizeof(ImageCodecInfo) (size=88 on x64).
    if encoders.is_null() || size != num_encoders * 88 {
        return GP_GENERIC_ERROR;
    }
    GP_OK
}

/// GdipGetImageDecodersSize — query how many image decoders are available.
///
/// Wine ref: dlls/gdiplus/image.c:5252 — identical logic to EncodersSize but
/// filters on `ImageCodecFlagsDecoder`. NULL pointers → InvalidParameter.
///
/// # Safety
/// `count` and `size` must be writable u32 pointers.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageDecodersSize(count: *mut u32, size: *mut u32) -> i32 {
    if count.is_null() || size.is_null() {
        return GP_INVALID_PARAMETER;
    }
    unsafe {
        *count = 0;
        *size = 0;
    }
    GP_OK
}

/// GdipGetImageDecoders — fill a caller-supplied buffer with decoder info.
///
/// Wine ref: dlls/gdiplus/image.c:5276 — GenericError if `decoders` is NULL or
/// `size != numDecoders * sizeof(ImageCodecInfo)`. Same logic as GdipGetImageEncoders.
///
/// # Safety
/// `decoders` must be a writable buffer of at least `size` bytes, or NULL.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageDecoders(
    num_decoders: u32,
    size: u32,
    decoders: *mut u8,
) -> i32 {
    if decoders.is_null() || size != num_decoders * 88 {
        return GP_GENERIC_ERROR;
    }
    GP_OK
}

// ── Image loading / saving ────────────────────────────────────────────────────

/// GdipLoadImageFromFile — load an image from a wide-character file path.
///
/// Wine ref: dlls/gdiplus/image.c:2937 — returns InvalidParameter if
/// `filename` or `image` is NULL. Sets `*image = NULL` before opening the
/// stream. Opens the file via GdipCreateStreamOnFile then delegates to
/// GdipLoadImageFromStream (which sniffs the magic bytes to pick the codec).
/// We return InvalidParameter on NULL args and set *image=NULL, then return
/// NotImplemented since we have no codec backend.
///
/// # Safety
/// `filename` must be a valid null-terminated UTF-16 string or NULL.
/// `image` must be a writable pointer-sized slot or NULL.
#[no_mangle]
pub unsafe extern "win64" fn GdipLoadImageFromFile(filename: *const u16, image: *mut usize) -> i32 {
    if filename.is_null() || image.is_null() {
        return GP_INVALID_PARAMETER;
    }
    unsafe { *image = 0 };
    GP_NOT_IMPLEMENTED
}

/// GdipLoadImageFromStream — load an image from a COM IStream.
///
/// # Safety
/// `stream` is a COM IStream pointer. `image` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipLoadImageFromStream(_stream: *mut u8, image: *mut usize) -> i32 {
    if !image.is_null() {
        unsafe { *image = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipLoadImageFromFileICM — GdipLoadImageFromFile with ICM colour management.
///
/// # Safety
/// Same as GdipLoadImageFromFile.
#[no_mangle]
pub unsafe extern "win64" fn GdipLoadImageFromFileICM(
    filename: *const u16,
    image: *mut usize,
) -> i32 {
    unsafe { GdipLoadImageFromFile(filename, image) }
}

/// GdipLoadImageFromStreamICM — GdipLoadImageFromStream with ICM.
///
/// # Safety
/// Same as GdipLoadImageFromStream.
#[no_mangle]
pub unsafe extern "win64" fn GdipLoadImageFromStreamICM(stream: *mut u8, image: *mut usize) -> i32 {
    unsafe { GdipLoadImageFromStream(stream, image) }
}

/// GdipSaveImageToFile — encode an image to a file path.
///
/// # Safety
/// All pointer arguments may be non-null; we ignore them.
#[no_mangle]
pub unsafe extern "win64" fn GdipSaveImageToFile(
    _image: usize,
    _filename: *const u16,
    _clsid_encoder: *const u8,
    _encoder_params: *const u8,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSaveImageToStream — encode an image to a COM IStream.
///
/// # Safety
/// All pointer arguments may be non-null; we ignore them.
#[no_mangle]
pub unsafe extern "win64" fn GdipSaveImageToStream(
    _image: usize,
    _stream: *mut u8,
    _clsid_encoder: *const u8,
    _encoder_params: *const u8,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDisposeImage — free a GpImage (or GpBitmap) object.
///
/// Wine ref: dlls/gdiplus/image.c:2104 — calls `free_image_data` then `free(image)`.
/// Returns InvalidParameter if `image` is NULL (checked via free_image_data which
/// calls GdipGetImageType which checks for NULL). We match the NULL → InvalidParameter
/// behaviour. Since we never allocate a real GpImage, non-null pointers are no-ops.
#[no_mangle]
pub extern "win64" fn GdipDisposeImage(image: usize) -> i32 {
    if image == 0 {
        return GP_INVALID_PARAMETER;
    }
    GP_OK
}

/// GdipCloneImage — clone a GpImage.
///
/// # Safety
/// `clone_image` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCloneImage(_image: usize, clone_image: *mut usize) -> i32 {
    if !clone_image.is_null() {
        unsafe { *clone_image = 0 };
    }
    GP_NOT_IMPLEMENTED
}

// ── Bitmap creation ───────────────────────────────────────────────────────────

/// GdipCreateBitmapFromFile — create a GpBitmap from a file path.
///
/// Wine ref: dlls/gdiplus/image.c:1442 — returns InvalidParameter if `filename`
/// or `bitmap` is NULL. Sets `*bitmap = NULL` then opens via
/// GdipCreateStreamOnFile → GdipCreateBitmapFromStream. Same NULL contract as
/// GdipLoadImageFromFile.
///
/// # Safety
/// `filename` is a null-terminated UTF-16 path or NULL.
/// `bitmap` is a writable pointer slot or NULL.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateBitmapFromFile(
    filename: *const u16,
    bitmap: *mut usize,
) -> i32 {
    if filename.is_null() || bitmap.is_null() {
        return GP_INVALID_PARAMETER;
    }
    unsafe { *bitmap = 0 };
    GP_NOT_IMPLEMENTED
}

/// GdipCreateBitmapFromStream — create a GpBitmap from a COM IStream.
///
/// # Safety
/// `stream` is a COM IStream pointer. `bitmap` is a writable slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateBitmapFromStream(
    _stream: *mut u8,
    bitmap: *mut usize,
) -> i32 {
    if !bitmap.is_null() {
        unsafe { *bitmap = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateBitmapFromHBITMAP — wrap a GDI HBITMAP in a GpBitmap.
///
/// Wine ref: dlls/gdiplus/image.c:5412 — both `hbm` and `bitmap` NULL → InvalidParameter;
/// calls GetObjectA(hbm) to read the BITMAP struct — if that fails (wrong handle type) →
/// InvalidParameter; derives PixelFormat from bmBitsPixel: 1/4/8/16/24/32/48 bpp supported,
/// anything else → InvalidParameter (not NotImplemented). Then creates via
/// GdipCreateBitmapFromScan0 and copies pixels via GetDIBits with a negative biHeight to
/// ensure top-down row order.
///
/// # Safety
/// `hbm` is a GDI bitmap handle. `bitmap` is a writable slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateBitmapFromHBITMAP(
    _hbm: usize,
    _hpal: usize,
    bitmap: *mut usize,
) -> i32 {
    if !bitmap.is_null() {
        unsafe { *bitmap = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateBitmapFromHICON — create a GpBitmap from a GDI HICON.
///
/// # Safety
/// `hicon` is a GDI icon handle. `bitmap` is a writable slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateBitmapFromHICON(_hicon: usize, bitmap: *mut usize) -> i32 {
    if !bitmap.is_null() {
        unsafe { *bitmap = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateBitmapFromScan0 — create a GpBitmap backed by caller-supplied scan0.
///
/// # Safety
/// `scan0` may be NULL (GDI+ allocates). `bitmap` is a writable slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateBitmapFromScan0(
    _width: i32,
    _height: i32,
    _stride: i32,
    _pixel_format: i32,
    _scan0: *mut u8,
    bitmap: *mut usize,
) -> i32 {
    if !bitmap.is_null() {
        unsafe { *bitmap = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateHBITMAPFromBitmap — extract a GDI HBITMAP from a GpBitmap.
///
/// # Safety
/// `hbm_return` must be a writable HBITMAP slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateHBITMAPFromBitmap(
    _bitmap: usize,
    hbm_return: *mut usize,
    _background: u32,
) -> i32 {
    if !hbm_return.is_null() {
        unsafe { *hbm_return = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateHICONFromBitmap — extract a GDI HICON from a GpBitmap.
///
/// # Safety
/// `hicon_return` must be a writable HICON slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateHICONFromBitmap(
    _bitmap: usize,
    hicon_return: *mut usize,
) -> i32 {
    if !hicon_return.is_null() {
        unsafe { *hicon_return = 0 };
    }
    GP_NOT_IMPLEMENTED
}

// ── Image properties ──────────────────────────────────────────────────────────

/// GdipGetImageWidth — get image width in pixels.
///
/// # Safety
/// `width` must be a writable u32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageWidth(_image: usize, width: *mut u32) -> i32 {
    if !width.is_null() {
        unsafe { *width = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetImageHeight — get image height in pixels.
///
/// # Safety
/// `height` must be a writable u32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageHeight(_image: usize, height: *mut u32) -> i32 {
    if !height.is_null() {
        unsafe { *height = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetImageType — get image type (Bitmap=1, Metafile=2).
///
/// # Safety
/// `type_` must be a writable i32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageType(_image: usize, type_: *mut i32) -> i32 {
    if !type_.is_null() {
        unsafe { *type_ = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetImagePixelFormat — get the pixel format of an image.
///
/// # Safety
/// `format` must be a writable i32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImagePixelFormat(_image: usize, format: *mut i32) -> i32 {
    if !format.is_null() {
        unsafe { *format = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetImageDimension — get image size as floating-point (width, height).
///
/// # Safety
/// `width` and `height` must be writable f32 pointers.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageDimension(
    _image: usize,
    width: *mut f32,
    height: *mut f32,
) -> i32 {
    if !width.is_null() {
        unsafe { *width = 0.0 };
    }
    if !height.is_null() {
        unsafe { *height = 0.0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetImageBounds — get the bounding rectangle in the given unit.
///
/// # Safety
/// `src_rect` must point to a writable GpRectF (4 x f32 = 16 bytes).
/// `src_unit` must be a writable i32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageBounds(
    _image: usize,
    src_rect: *mut f32,
    src_unit: *mut i32,
) -> i32 {
    if !src_rect.is_null() {
        unsafe {
            *src_rect = 0.0;
            *src_rect.add(1) = 0.0;
            *src_rect.add(2) = 0.0;
            *src_rect.add(3) = 0.0;
        }
    }
    if !src_unit.is_null() {
        unsafe { *src_unit = 2 }; // UnitPixel
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetImageHorizontalResolution — get horizontal DPI.
///
/// # Safety
/// `resolution` must be a writable f32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageHorizontalResolution(
    _image: usize,
    resolution: *mut f32,
) -> i32 {
    if !resolution.is_null() {
        unsafe { *resolution = 96.0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetImageVerticalResolution — get vertical DPI.
///
/// # Safety
/// `resolution` must be a writable f32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageVerticalResolution(
    _image: usize,
    resolution: *mut f32,
) -> i32 {
    if !resolution.is_null() {
        unsafe { *resolution = 96.0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetImageFlags — get image flags (immutable, cached, etc.).
///
/// # Safety
/// `flags` must be a writable u32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetImageFlags(_image: usize, flags: *mut u32) -> i32 {
    if !flags.is_null() {
        unsafe { *flags = 0 };
    }
    GP_NOT_IMPLEMENTED
}

// ── Frame / animation support ─────────────────────────────────────────────────

/// GdipImageGetFrameCount — count frames in the given dimension (e.g. animation).
///
/// # Safety
/// `dimension_id` is a GUID pointer. `count` is a writable u32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipImageGetFrameCount(
    _image: usize,
    _dimension_id: *const u8,
    count: *mut u32,
) -> i32 {
    if !count.is_null() {
        unsafe { *count = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipImageSelectActiveFrame — select which animation frame is displayed.
///
/// # Safety
/// `dimension_id` is a GUID pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipImageSelectActiveFrame(
    _image: usize,
    _dimension_id: *const u8,
    _frame_index: u32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipImageGetFrameDimensionsCount — number of frame dimension lists.
///
/// # Safety
/// `count` must be a writable u32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipImageGetFrameDimensionsCount(
    _image: usize,
    count: *mut u32,
) -> i32 {
    if !count.is_null() {
        unsafe { *count = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipImageGetFrameDimensionsList — list frame dimension GUIDs.
///
/// # Safety
/// `dimension_ids` is a caller-supplied buffer of `count` GUIDs.
#[no_mangle]
pub unsafe extern "win64" fn GdipImageGetFrameDimensionsList(
    _image: usize,
    _dimension_ids: *mut u8,
    _count: u32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

// ── Property (EXIF / metadata) ────────────────────────────────────────────────

/// GdipGetPropertyCount — count the property items stored in the image.
///
/// Wine ref: dlls/gdiplus/image.c:2365 — returns InvalidParameter if `image`
/// is NULL or `num` is NULL. For a bitmap with no metadata reader and no cached
/// prop_item, sets *num=0 and returns Ok. We return InvalidParameter on NULL
/// args (matching Wine), then Ok with count=0 for any non-null image pointer
/// (since we have no real image data).
///
/// # Safety
/// `num_of_property` must be a writable u32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetPropertyCount(image: usize, num_of_property: *mut u32) -> i32 {
    if image == 0 || num_of_property.is_null() {
        return GP_INVALID_PARAMETER;
    }
    unsafe { *num_of_property = 0 };
    GP_OK
}

/// GdipGetPropertyIdList — list the property tag IDs stored in the image.
///
/// # Safety
/// `list` is a caller-supplied buffer of `num_of_property` u32 slots.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetPropertyIdList(
    _image: usize,
    _num_of_property: u32,
    _list: *mut u32,
) -> i32 {
    GP_OK
}

/// GdipGetPropertyItemSize — get the byte size of one property item.
///
/// # Safety
/// `size` must be a writable u32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetPropertyItemSize(
    _image: usize,
    _prop_id: u32,
    size: *mut u32,
) -> i32 {
    if !size.is_null() {
        unsafe { *size = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetPropertyItem — retrieve one property item from the image.
///
/// # Safety
/// `buffer` is a caller-supplied buffer of `prop_size` bytes.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetPropertyItem(
    _image: usize,
    _prop_id: u32,
    _prop_size: u32,
    _buffer: *mut u8,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipGetAllPropertyItems — retrieve all property items from the image.
///
/// # Safety
/// `all_items` is a caller-supplied buffer of `total_buffer_size` bytes.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetAllPropertyItems(
    _image: usize,
    _total_buffer_size: u32,
    _num_properties: u32,
    _all_items: *mut u8,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

// ── Graphics context ──────────────────────────────────────────────────────────

/// GdipCreateFromHDC — create a GpGraphics that draws on an HDC.
///
/// Wine ref: dlls/gdiplus/graphics.c:2470 — GdipCreateFromHDC delegates
/// immediately to GdipCreateFromHDC2(hdc, NULL, graphics). The HDC is stored
/// in `graphics->hdc`; hwnd is obtained via WindowFromDC. NULL hdc → OutOfMemory
/// (not InvalidParameter). NULL graphics → InvalidParameter.
///
/// # Safety
/// `hdc` is a Windows HDC (opaque handle). `graphics` is a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateFromHDC(hdc: usize, graphics: *mut usize) -> i32 {
    // Wine ref: dlls/gdiplus/graphics.c:2494 — hdc==NULL → OutOfMemory.
    if hdc == 0 {
        return GP_OUT_OF_MEMORY;
    }
    if graphics.is_null() {
        return GP_INVALID_PARAMETER;
    }
    unsafe { *graphics = 0 };
    GP_NOT_IMPLEMENTED
}

/// GdipCreateFromHDC2 — create a GpGraphics on an HDC with a device handle.
///
/// Wine ref: dlls/gdiplus/graphics.c:2493 — hdc==NULL → OutOfMemory;
/// graphics==NULL → InvalidParameter. hDevice is accepted but ignored (FIXME
/// in Wine). Allocates GpGraphics with calloc and stores hdc, hwnd, smoothing,
/// interpolation defaults.
///
/// # Safety
/// Same as GdipCreateFromHDC.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateFromHDC2(
    hdc: usize,
    _h_device: usize,
    graphics: *mut usize,
) -> i32 {
    if hdc == 0 {
        return GP_OUT_OF_MEMORY;
    }
    if graphics.is_null() {
        return GP_INVALID_PARAMETER;
    }
    unsafe { *graphics = 0 };
    GP_NOT_IMPLEMENTED
}

/// GdipCreateFromHWND — create a GpGraphics for a window handle.
///
/// Wine ref: dlls/gdiplus/graphics.c:2604 — calls GetDC(hwnd) then
/// GdipCreateFromHDC2; sets graphics->owndc = TRUE so DeleteGraphics releases
/// the DC via ReleaseDC rather than DeleteDC.
///
/// # Safety
/// `hwnd` is a Windows HWND. `graphics` is a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateFromHWND(_hwnd: usize, graphics: *mut usize) -> i32 {
    if graphics.is_null() {
        return GP_INVALID_PARAMETER;
    }
    unsafe { *graphics = 0 };
    GP_NOT_IMPLEMENTED
}

/// GdipDeleteGraphics — release a GpGraphics object.
///
/// Wine ref: dlls/gdiplus/graphics.c:2652 — returns InvalidParameter if
/// `graphics` is NULL; returns ObjectBusy(4) if `graphics->busy` is set
/// (double-free guard). We match the NULL check; non-null is a no-op.
#[no_mangle]
pub extern "win64" fn GdipDeleteGraphics(graphics: usize) -> i32 {
    if graphics == 0 {
        return GP_INVALID_PARAMETER;
    }
    GP_OK
}

/// GdipGetDC — get the underlying HDC from a GpGraphics.
///
/// Wine ref: dlls/gdiplus/graphics.c — GdipGetDC flushes and returns the HDC.
///
/// # Safety
/// `hdc` must be a writable pointer-sized slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetDC(_graphics: usize, hdc: *mut usize) -> i32 {
    if !hdc.is_null() {
        unsafe { *hdc = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipReleaseDC — return the HDC to the GpGraphics.
#[no_mangle]
pub extern "win64" fn GdipReleaseDC(_graphics: usize, _hdc: usize) -> i32 {
    GP_NOT_IMPLEMENTED
}

// ── Graphics state ────────────────────────────────────────────────────────────

/// GdipSetInterpolationMode — set resampling algorithm (nearest, bilinear, bicubic…).
#[no_mangle]
pub extern "win64" fn GdipSetInterpolationMode(_graphics: usize, _mode: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipGetInterpolationMode — query the current resampling algorithm.
///
/// # Safety
/// `mode` must be a writable i32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetInterpolationMode(_graphics: usize, mode: *mut i32) -> i32 {
    if !mode.is_null() {
        unsafe { *mode = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipSetSmoothingMode — set anti-aliasing mode.
#[no_mangle]
pub extern "win64" fn GdipSetSmoothingMode(_graphics: usize, _mode: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipGetSmoothingMode — query anti-aliasing mode.
///
/// # Safety
/// `mode` must be a writable i32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetSmoothingMode(_graphics: usize, mode: *mut i32) -> i32 {
    if !mode.is_null() {
        unsafe { *mode = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipSetPixelOffsetMode — set pixel-offset mode (None, Half, HighQuality…).
#[no_mangle]
pub extern "win64" fn GdipSetPixelOffsetMode(_graphics: usize, _mode: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetCompositingMode — set compositing mode (SourceOver, SourceCopy).
#[no_mangle]
pub extern "win64" fn GdipSetCompositingMode(_graphics: usize, _mode: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetCompositingQuality — set compositing quality.
#[no_mangle]
pub extern "win64" fn GdipSetCompositingQuality(_graphics: usize, _quality: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetTextRenderingHint — set text anti-aliasing mode.
#[no_mangle]
pub extern "win64" fn GdipSetTextRenderingHint(_graphics: usize, _mode: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetPageUnit — set the unit of measure for a graphics context.
#[no_mangle]
pub extern "win64" fn GdipSetPageUnit(_graphics: usize, _unit: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetPageScale — set a scaling factor on top of the unit.
#[no_mangle]
pub extern "win64" fn GdipSetPageScale(_graphics: usize, _scale: f32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipGetPageUnit — query the current unit.
///
/// # Safety
/// `unit` must be a writable i32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetPageUnit(_graphics: usize, unit: *mut i32) -> i32 {
    if !unit.is_null() {
        unsafe { *unit = 2 }; // UnitPixel
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetDpiX — query horizontal DPI of the graphics context.
///
/// # Safety
/// `dpi` must be a writable f32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetDpiX(_graphics: usize, dpi: *mut f32) -> i32 {
    if !dpi.is_null() {
        unsafe { *dpi = 96.0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetDpiY — query vertical DPI of the graphics context.
///
/// # Safety
/// `dpi` must be a writable f32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetDpiY(_graphics: usize, dpi: *mut f32) -> i32 {
    if !dpi.is_null() {
        unsafe { *dpi = 96.0 };
    }
    GP_NOT_IMPLEMENTED
}

// ── Clipping ──────────────────────────────────────────────────────────────────

/// GdipSetClipRect — set a rectangular clip region (floating-point).
#[no_mangle]
pub extern "win64" fn GdipSetClipRect(
    _graphics: usize,
    _x: f32,
    _y: f32,
    _width: f32,
    _height: f32,
    _combine_mode: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetClipRectI — set a rectangular clip region (integer).
#[no_mangle]
pub extern "win64" fn GdipSetClipRectI(
    _graphics: usize,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
    _combine_mode: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipResetClip — reset the clip region to infinite (no clip).
#[no_mangle]
pub extern "win64" fn GdipResetClip(_graphics: usize) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSaveGraphics — push graphics state onto a stack.
///
/// # Safety
/// `state` must be a writable u32 pointer (GraphicsState cookie).
#[no_mangle]
pub unsafe extern "win64" fn GdipSaveGraphics(_graphics: usize, state: *mut u32) -> i32 {
    if !state.is_null() {
        unsafe { *state = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipRestoreGraphics — pop graphics state from the stack.
#[no_mangle]
pub extern "win64" fn GdipRestoreGraphics(_graphics: usize, _state: u32) -> i32 {
    GP_NOT_IMPLEMENTED
}

// ── Drawing ───────────────────────────────────────────────────────────────────

/// GdipGraphicsClear — fill the entire drawing surface with one colour.
#[no_mangle]
pub extern "win64" fn GdipGraphicsClear(_graphics: usize, _color: u32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImage — draw an image at a floating-point (x, y).
#[no_mangle]
pub extern "win64" fn GdipDrawImage(_graphics: usize, _image: usize, _x: f32, _y: f32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImageI — draw an image at an integer (x, y).
#[no_mangle]
pub extern "win64" fn GdipDrawImageI(_graphics: usize, _image: usize, _x: i32, _y: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImageRect — draw an image scaled into a destination rectangle (f32).
#[no_mangle]
pub extern "win64" fn GdipDrawImageRect(
    _graphics: usize,
    _image: usize,
    _x: f32,
    _y: f32,
    _width: f32,
    _height: f32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImageRectI — draw an image scaled into a destination rectangle (int).
#[no_mangle]
pub extern "win64" fn GdipDrawImageRectI(
    _graphics: usize,
    _image: usize,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImageRectRect — draw a source rect of an image into a destination rect (f32).
///
/// Wine ref: dlls/gdiplus/graphics.c:3591 — converts the four dst corner params
/// into three GpPointF corner points and delegates to GdipDrawImagePointsRect.
/// The src rect + srcUnit define the source region; imageattr, callback, and
/// callbackData are optional and may be NULL. No NULL checks on graphics or
/// image before the points conversion — a NULL image will crash in
/// GdipDrawImagePointsRect. We return NotImplemented; callers that handle it
/// fall back to GDI blitting.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "win64" fn GdipDrawImageRectRect(
    _graphics: usize,
    _image: usize,
    _dst_x: f32,
    _dst_y: f32,
    _dst_width: f32,
    _dst_height: f32,
    _src_x: f32,
    _src_y: f32,
    _src_width: f32,
    _src_height: f32,
    _src_unit: i32,
    _image_attributes: usize,
    _callback: usize,
    _callback_data: usize,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImageRectRectI — draw a source rect into a destination rect (int).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "win64" fn GdipDrawImageRectRectI(
    _graphics: usize,
    _image: usize,
    _dst_x: i32,
    _dst_y: i32,
    _dst_width: i32,
    _dst_height: i32,
    _src_x: i32,
    _src_y: i32,
    _src_width: i32,
    _src_height: i32,
    _src_unit: i32,
    _image_attributes: usize,
    _callback: usize,
    _callback_data: usize,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImagePoints — draw an image mapped to three parallelogram corners.
///
/// # Safety
/// `dst_points` must point to 3 GpPointF structs (3 × 2 × f32 = 24 bytes).
#[no_mangle]
pub unsafe extern "win64" fn GdipDrawImagePoints(
    _graphics: usize,
    _image: usize,
    _dst_points: *const f32,
    _count: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImagePointsI — draw an image mapped to three parallelogram corners (int).
///
/// # Safety
/// `dst_points` must point to 3 GpPoint structs.
#[no_mangle]
pub unsafe extern "win64" fn GdipDrawImagePointsI(
    _graphics: usize,
    _image: usize,
    _dst_points: *const i32,
    _count: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawImagePointsRect — draw an image mapped to three points from a source rect.
///
/// # Safety
/// `points` must point to 3 GpPointF structs. All other pointer args may be null.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn GdipDrawImagePointsRect(
    _graphics: usize,
    _image: usize,
    _points: *const f32,
    _count: i32,
    _src_x: f32,
    _src_y: f32,
    _src_width: f32,
    _src_height: f32,
    _src_unit: i32,
    _image_attr: usize,
    _callback: usize,
    _callback_data: usize,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipFillRectangle — fill a rectangle with a brush (f32).
#[no_mangle]
pub extern "win64" fn GdipFillRectangle(
    _graphics: usize,
    _brush: usize,
    _x: f32,
    _y: f32,
    _width: f32,
    _height: f32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipFillRectangleI — fill a rectangle with a brush (int).
#[no_mangle]
pub extern "win64" fn GdipFillRectangleI(
    _graphics: usize,
    _brush: usize,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipFillEllipse — fill an ellipse with a brush (f32).
#[no_mangle]
pub extern "win64" fn GdipFillEllipse(
    _graphics: usize,
    _brush: usize,
    _x: f32,
    _y: f32,
    _width: f32,
    _height: f32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawRectangle — stroke a rectangle outline with a pen (f32).
#[no_mangle]
pub extern "win64" fn GdipDrawRectangle(
    _graphics: usize,
    _pen: usize,
    _x: f32,
    _y: f32,
    _width: f32,
    _height: f32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawRectangleI — stroke a rectangle outline with a pen (int).
#[no_mangle]
pub extern "win64" fn GdipDrawRectangleI(
    _graphics: usize,
    _pen: usize,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawLine — draw a line (f32).
#[no_mangle]
pub extern "win64" fn GdipDrawLine(
    _graphics: usize,
    _pen: usize,
    _x1: f32,
    _y1: f32,
    _x2: f32,
    _y2: f32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawLineI — draw a line (int).
#[no_mangle]
pub extern "win64" fn GdipDrawLineI(
    _graphics: usize,
    _pen: usize,
    _x1: i32,
    _y1: i32,
    _x2: i32,
    _y2: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipDrawString — draw a UTF-16 string using a GpFont and GpBrush.
///
/// Wine ref: dlls/gdiplus/graphics.c:6136 — all five of graphics/string/font/brush/rect
/// being NULL → InvalidParameter (each checked individually); graphics->busy → ObjectBusy.
/// Adds a horizontal margin of font->emSize/6.0 on each side unless the format is
/// generic_typographic (in which case margin_x=0.0). When line_align != Near, calls
/// GdipMeasureString internally to compute the vertical offsety for Center/Far alignment.
/// Width/height capped at 1<<23 to avoid integer overflow in the layout engine.
///
/// # Safety
/// `string` is a UTF-16 string of `length` chars (or -1 for null-terminated).
/// `layout_rect` is a GpRectF pointer (4 f32s).
#[no_mangle]
pub unsafe extern "win64" fn GdipDrawString(
    _graphics: usize,
    _string: *const u16,
    _length: i32,
    _font: usize,
    _layout_rect: *const f32,
    _string_format: usize,
    _brush: usize,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipMeasureString — measure the bounding box of a string.
///
/// # Safety
/// `layout_rect` and `bounding_box` are GpRectF pointers (4 f32s each).
/// `codepointsFitted` and `linesFilled` are optional writable int pointers.
#[no_mangle]
pub unsafe extern "win64" fn GdipMeasureString(
    _graphics: usize,
    _string: *const u16,
    _length: i32,
    _font: usize,
    _layout_rect: *const f32,
    _string_format: usize,
    bounding_box: *mut f32,
    _codepoints_fitted: *mut i32,
    _lines_filled: *mut i32,
) -> i32 {
    if !bounding_box.is_null() {
        unsafe {
            *bounding_box = 0.0;
            *bounding_box.add(1) = 0.0;
            *bounding_box.add(2) = 0.0;
            *bounding_box.add(3) = 0.0;
        }
    }
    GP_NOT_IMPLEMENTED
}

// ── Brushes ───────────────────────────────────────────────────────────────────

/// GdipCreateSolidFill — create a solid-colour brush.
///
/// Wine ref: dlls/gdiplus/brush.c:754 — only `sf==NULL` is checked (InvalidParameter);
/// the ARGB `color` value is accepted without validation (any 32-bit value is stored).
/// Allocates with calloc; sets `brush.bt = BrushTypeSolidColor` and stores the ARGB.
/// Returns Ok, not NotImplemented, on success — the object is immediately usable.
///
/// # Safety
/// `brush` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateSolidFill(_color: u32, brush: *mut usize) -> i32 {
    if !brush.is_null() {
        unsafe { *brush = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipDeleteBrush — free any GpBrush subtype.
#[no_mangle]
pub extern "win64" fn GdipDeleteBrush(_brush: usize) -> i32 {
    GP_OK
}

/// GdipGetBrushType — query the brush type (SolidColor, HatchFill, …).
///
/// # Safety
/// `type_` must be a writable i32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetBrushType(_brush: usize, type_: *mut i32) -> i32 {
    if !type_.is_null() {
        unsafe { *type_ = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateLineBrush — create a linear gradient brush.
///
/// # Safety
/// `point1` and `point2` are GpPointF pointers (2 f32s each). `line_gradient`
/// is a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateLineBrush(
    _point1: *const f32,
    _point2: *const f32,
    _color1: u32,
    _color2: u32,
    _wrap_mode: i32,
    line_gradient: *mut usize,
) -> i32 {
    if !line_gradient.is_null() {
        unsafe { *line_gradient = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateTexture — create a texture (pattern) brush from an image.
///
/// # Safety
/// `texture` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateTexture(
    _image: usize,
    _wrap_mode: i32,
    texture: *mut usize,
) -> i32 {
    if !texture.is_null() {
        unsafe { *texture = 0 };
    }
    GP_NOT_IMPLEMENTED
}

// ── Pens ──────────────────────────────────────────────────────────────────────

/// GdipCreatePen1 — create a pen from a colour and width.
///
/// Wine ref: dlls/gdiplus/pen.c:146 — GdipCreatePen1 is a thin wrapper: it calls
/// GdipCreateSolidFill → GdipCreatePen2 → GdipDeleteBrush; the NULL pen check is in
/// GdipCreatePen2, not here. GdipCreatePen2 initialises defaults: miterlimit=10.0,
/// join=LineJoinMiter, endcap=LineCapFlat, dash=DashStyleSolid. Only UnitWorld and
/// UnitPixel are supported; other units return NotImplemented (not InvalidParameter).
///
/// # Safety
/// `pen` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreatePen1(
    _color: u32,
    _width: f32,
    _unit: i32,
    pen: *mut usize,
) -> i32 {
    if !pen.is_null() {
        unsafe { *pen = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreatePen2 — create a pen from a brush and width.
///
/// # Safety
/// `pen` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreatePen2(
    _brush: usize,
    _width: f32,
    _unit: i32,
    pen: *mut usize,
) -> i32 {
    if !pen.is_null() {
        unsafe { *pen = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipDeletePen — free a GpPen.
#[no_mangle]
pub extern "win64" fn GdipDeletePen(_pen: usize) -> i32 {
    GP_OK
}

// ── Fonts ─────────────────────────────────────────────────────────────────────

/// GdipCreateFontFamilyFromName — look up a font family by name.
///
/// Wine ref: dlls/gdiplus/font.c:701 — `name==NULL || family==NULL` → InvalidParameter;
/// when `collection==NULL`, Wine calls GdipNewInstalledFontCollection() to get the system
/// collection. Uses EnumFontFamiliesW + is_font_installed_proc to confirm existence, then
/// does a case-insensitive wcsicmp search in collection->FontFamilies. Returns
/// FontFamilyNotFound (status 14) — not InvalidParameter — when the name doesn't match
/// any installed font.
///
/// # Safety
/// `name` is a null-terminated UTF-16 font name. `font_collection` may be NULL.
/// `font_family` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateFontFamilyFromName(
    _name: *const u16,
    _font_collection: usize,
    font_family: *mut usize,
) -> i32 {
    if !font_family.is_null() {
        unsafe { *font_family = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipDeleteFontFamily — free a GpFontFamily.
#[no_mangle]
pub extern "win64" fn GdipDeleteFontFamily(_font_family: usize) -> i32 {
    GP_OK
}

/// GdipCreateFont — create a GpFont from a family, size, style, and unit.
///
/// # Safety
/// `font` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateFont(
    _font_family: usize,
    _em_size: f32,
    _style: i32,
    _unit: i32,
    font: *mut usize,
) -> i32 {
    if !font.is_null() {
        unsafe { *font = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateFontFromDC — create a GpFont matching an HDC's currently selected font.
///
/// # Safety
/// `font` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateFontFromDC(_hdc: usize, font: *mut usize) -> i32 {
    if !font.is_null() {
        unsafe { *font = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipCreateFontFromLogfontW — create a GpFont from a LOGFONTW struct.
///
/// # Safety
/// `logfont` must point to a valid LOGFONTW (92 bytes). `font` is a writable slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateFontFromLogfontW(
    _hdc: usize,
    _logfont: *const u8,
    font: *mut usize,
) -> i32 {
    if !font.is_null() {
        unsafe { *font = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipDeleteFont — free a GpFont.
#[no_mangle]
pub extern "win64" fn GdipDeleteFont(_font: usize) -> i32 {
    GP_OK
}

/// GdipGetFontHeight — get the line spacing height of a font in the given unit.
///
/// # Safety
/// `height` must be a writable f32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetFontHeight(
    _font: usize,
    _graphics: usize,
    height: *mut f32,
) -> i32 {
    if !height.is_null() {
        unsafe { *height = 0.0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipGetFontSize — get the em size of a font.
///
/// # Safety
/// `size` must be a writable f32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipGetFontSize(_font: usize, size: *mut f32) -> i32 {
    if !size.is_null() {
        unsafe { *size = 0.0 };
    }
    GP_NOT_IMPLEMENTED
}

// ── String format ─────────────────────────────────────────────────────────────

/// GdipCreateStringFormat — create a GpStringFormat with given attributes.
///
/// Wine ref: dlls/gdiplus/stringformat.c
///
/// # Safety
/// `format` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateStringFormat(
    _format_attributes: i32,
    _language: u16,
    format: *mut usize,
) -> i32 {
    if !format.is_null() {
        unsafe { *format = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipDeleteStringFormat — free a GpStringFormat.
#[no_mangle]
pub extern "win64" fn GdipDeleteStringFormat(_format: usize) -> i32 {
    GP_OK
}

/// GdipStringFormatGetGenericDefault — get the default (generic) string format.
///
/// # Safety
/// `format` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipStringFormatGetGenericDefault(format: *mut usize) -> i32 {
    if !format.is_null() {
        unsafe { *format = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipStringFormatGetGenericTypographic — get the typographic string format.
///
/// # Safety
/// `format` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipStringFormatGetGenericTypographic(format: *mut usize) -> i32 {
    if !format.is_null() {
        unsafe { *format = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipSetStringFormatAlign — set the horizontal alignment of a string format.
#[no_mangle]
pub extern "win64" fn GdipSetStringFormatAlign(_format: usize, _align: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetStringFormatLineAlign — set the vertical alignment.
#[no_mangle]
pub extern "win64" fn GdipSetStringFormatLineAlign(_format: usize, _align: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetStringFormatTrimming — set the string trimming mode.
#[no_mangle]
pub extern "win64" fn GdipSetStringFormatTrimming(_format: usize, _trimming: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetStringFormatFlags — set string format flags.
#[no_mangle]
pub extern "win64" fn GdipSetStringFormatFlags(_format: usize, _flags: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

// ── Image attributes ──────────────────────────────────────────────────────────

/// GdipCreateImageAttributes — allocate a GpImageAttributes (colour/gamma tweaks).
///
/// # Safety
/// `image_attr` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateImageAttributes(image_attr: *mut usize) -> i32 {
    if !image_attr.is_null() {
        unsafe { *image_attr = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipDisposeImageAttributes — free a GpImageAttributes.
#[no_mangle]
pub extern "win64" fn GdipDisposeImageAttributes(_image_attr: usize) -> i32 {
    GP_OK
}

/// GdipSetImageAttributesColorKey — set a colour-key (transparency) range.
#[no_mangle]
pub extern "win64" fn GdipSetImageAttributesColorKey(
    _image_attr: usize,
    _type_: i32,
    _enable: i32,
    _color_low: u32,
    _color_high: u32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetImageAttributesColorMatrix — set a 5×5 colour-transformation matrix.
///
/// # Safety
/// `color_matrix` and `gray_matrix` point to 5×5 f32 arrays (100 bytes each).
#[no_mangle]
pub unsafe extern "win64" fn GdipSetImageAttributesColorMatrix(
    _image_attr: usize,
    _type_: i32,
    _enable_flag: i32,
    _color_matrix: *const f32,
    _gray_matrix: *const f32,
    _flags: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetImageAttributesGamma — apply a gamma-correction value.
#[no_mangle]
pub extern "win64" fn GdipSetImageAttributesGamma(
    _image_attr: usize,
    _type_: i32,
    _enable_flag: i32,
    _gamma: f32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipSetImageAttributesWrapMode — set the tiling/wrap mode.
#[no_mangle]
pub extern "win64" fn GdipSetImageAttributesWrapMode(
    _image_attr: usize,
    _wrap: i32,
    _color: u32,
    _clamp: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

// ── Bitmap pixel access ───────────────────────────────────────────────────────

/// GdipBitmapGetPixel — read a single pixel from a bitmap.
///
/// # Safety
/// `color` must be a writable u32 pointer.
#[no_mangle]
pub unsafe extern "win64" fn GdipBitmapGetPixel(
    _bitmap: usize,
    _x: i32,
    _y: i32,
    color: *mut u32,
) -> i32 {
    if !color.is_null() {
        unsafe { *color = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipBitmapSetPixel — write a single pixel to a bitmap.
#[no_mangle]
pub extern "win64" fn GdipBitmapSetPixel(_bitmap: usize, _x: i32, _y: i32, _color: u32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipBitmapLockBits — lock a rectangle of pixel data for direct access.
///
/// Wine ref: dlls/gdiplus/image.c:1112 — returns InvalidParameter if
/// `lockeddata` or `bitmap` is NULL. Returns ObjectBusy(4) if the image is
/// already locked (`image_lock` fails or `bitmap->lockmode` is set →
/// WrongState=8). When the bitmap's internal buffer format matches the
/// requested format, fills lockeddata: Width, Height, PixelFormat, Reserved
/// (= flags), Stride, Scan0 (pointer into bitmap->bits). On format mismatch it
/// allocates a temporary conversion buffer. BitmapData struct is 32 bytes on
/// x64: [Width:u32, Height:u32, Stride:i32, PixelFormat:i32, Scan0:ptr, Reserved:ptr].
/// We zero the struct and return NotImplemented (no real bitmap to lock).
///
/// # Safety
/// `rect` is a GpRect pointer (4 × i32 = 16 bytes) or NULL for the whole image.
/// `locked_bitmap_data` must point to a writable BitmapData struct (32 bytes).
#[no_mangle]
pub unsafe extern "win64" fn GdipBitmapLockBits(
    bitmap: usize,
    _rect: *const i32,
    _flags: u32,
    _format: i32,
    locked_bitmap_data: *mut u8,
) -> i32 {
    // Wine ref: dlls/gdiplus/image.c:1123 — InvalidParameter if lockeddata or bitmap NULL.
    if bitmap == 0 || locked_bitmap_data.is_null() {
        return GP_INVALID_PARAMETER;
    }
    // Zero out the BitmapData struct so callers do not read garbage.
    unsafe { std::ptr::write_bytes(locked_bitmap_data, 0, 32) };
    GP_NOT_IMPLEMENTED
}

/// GdipBitmapUnlockBits — release locked pixel data.
///
/// # Safety
/// `locked_bitmap_data` must be the same BitmapData passed to GdipBitmapLockBits.
#[no_mangle]
pub unsafe extern "win64" fn GdipBitmapUnlockBits(
    _bitmap: usize,
    _locked_bitmap_data: *mut u8,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

// ── Paths ─────────────────────────────────────────────────────────────────────

/// GdipCreatePath — create a GpPath with a given fill mode.
///
/// # Safety
/// `path` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreatePath(_fill_mode: i32, path: *mut usize) -> i32 {
    if !path.is_null() {
        unsafe { *path = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipDeletePath — free a GpPath.
#[no_mangle]
pub extern "win64" fn GdipDeletePath(_path: usize) -> i32 {
    GP_OK
}

/// GdipDrawPath — stroke a GpPath.
#[no_mangle]
pub extern "win64" fn GdipDrawPath(_graphics: usize, _pen: usize, _path: usize) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipFillPath — fill a GpPath.
#[no_mangle]
pub extern "win64" fn GdipFillPath(_graphics: usize, _brush: usize, _path: usize) -> i32 {
    GP_NOT_IMPLEMENTED
}

// ── Transforms ────────────────────────────────────────────────────────────────

/// GdipSetWorldTransform — replace the graphics world transform.
///
/// # Safety
/// `matrix` is a GpMatrix pointer (6 f32s = 24 bytes).
#[no_mangle]
pub unsafe extern "win64" fn GdipSetWorldTransform(_graphics: usize, _matrix: *const f32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipResetWorldTransform — reset to the identity transform.
#[no_mangle]
pub extern "win64" fn GdipResetWorldTransform(_graphics: usize) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipTranslateWorldTransform — prepend/append a translation.
#[no_mangle]
pub extern "win64" fn GdipTranslateWorldTransform(
    _graphics: usize,
    _dx: f32,
    _dy: f32,
    _order: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipScaleWorldTransform — prepend/append a scaling transform.
#[no_mangle]
pub extern "win64" fn GdipScaleWorldTransform(
    _graphics: usize,
    _sx: f32,
    _sy: f32,
    _order: i32,
) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipRotateWorldTransform — prepend/append a rotation.
#[no_mangle]
pub extern "win64" fn GdipRotateWorldTransform(_graphics: usize, _angle: f32, _order: i32) -> i32 {
    GP_NOT_IMPLEMENTED
}

/// GdipCreateMatrix — create a new identity GpMatrix.
///
/// # Safety
/// `matrix` must be a writable pointer slot.
#[no_mangle]
pub unsafe extern "win64" fn GdipCreateMatrix(matrix: *mut usize) -> i32 {
    if !matrix.is_null() {
        unsafe { *matrix = 0 };
    }
    GP_NOT_IMPLEMENTED
}

/// GdipDeleteMatrix — free a GpMatrix.
#[no_mangle]
pub extern "win64" fn GdipDeleteMatrix(_matrix: usize) -> i32 {
    GP_OK
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/// Resolve a gdiplus.dll import to a function pointer.
///
/// Called by weave-cli's top-level resolve chain during IAT patching.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("gdiplus.dll") {
        return None;
    }
    Some(match func {
        // Startup
        "GdiplusStartup" => GdiplusStartup as *const () as usize,
        "GdiplusShutdown" => GdiplusShutdown as *const () as usize,
        // Memory
        "GdipAlloc" => GdipAlloc as *const () as usize,
        "GdipFree" => GdipFree as *const () as usize,
        // Codec enumeration
        "GdipGetImageEncodersSize" => GdipGetImageEncodersSize as *const () as usize,
        "GdipGetImageEncoders" => GdipGetImageEncoders as *const () as usize,
        "GdipGetImageDecodersSize" => GdipGetImageDecodersSize as *const () as usize,
        "GdipGetImageDecoders" => GdipGetImageDecoders as *const () as usize,
        // Image load/save
        "GdipLoadImageFromFile" => GdipLoadImageFromFile as *const () as usize,
        "GdipLoadImageFromStream" => GdipLoadImageFromStream as *const () as usize,
        "GdipLoadImageFromFileICM" => GdipLoadImageFromFileICM as *const () as usize,
        "GdipLoadImageFromStreamICM" => GdipLoadImageFromStreamICM as *const () as usize,
        "GdipSaveImageToFile" => GdipSaveImageToFile as *const () as usize,
        "GdipSaveImageToStream" => GdipSaveImageToStream as *const () as usize,
        "GdipDisposeImage" => GdipDisposeImage as *const () as usize,
        "GdipCloneImage" => GdipCloneImage as *const () as usize,
        // Bitmap creation
        "GdipCreateBitmapFromFile" => GdipCreateBitmapFromFile as *const () as usize,
        "GdipCreateBitmapFromStream" => GdipCreateBitmapFromStream as *const () as usize,
        "GdipCreateBitmapFromHBITMAP" => GdipCreateBitmapFromHBITMAP as *const () as usize,
        "GdipCreateBitmapFromHICON" => GdipCreateBitmapFromHICON as *const () as usize,
        "GdipCreateBitmapFromScan0" => GdipCreateBitmapFromScan0 as *const () as usize,
        "GdipCreateHBITMAPFromBitmap" => GdipCreateHBITMAPFromBitmap as *const () as usize,
        "GdipCreateHICONFromBitmap" => GdipCreateHICONFromBitmap as *const () as usize,
        // Image properties
        "GdipGetImageWidth" => GdipGetImageWidth as *const () as usize,
        "GdipGetImageHeight" => GdipGetImageHeight as *const () as usize,
        "GdipGetImageType" => GdipGetImageType as *const () as usize,
        "GdipGetImagePixelFormat" => GdipGetImagePixelFormat as *const () as usize,
        "GdipGetImageDimension" => GdipGetImageDimension as *const () as usize,
        "GdipGetImageBounds" => GdipGetImageBounds as *const () as usize,
        "GdipGetImageHorizontalResolution" => {
            GdipGetImageHorizontalResolution as *const () as usize
        }
        "GdipGetImageVerticalResolution" => GdipGetImageVerticalResolution as *const () as usize,
        "GdipGetImageFlags" => GdipGetImageFlags as *const () as usize,
        // Frame/animation
        "GdipImageGetFrameCount" => GdipImageGetFrameCount as *const () as usize,
        "GdipImageSelectActiveFrame" => GdipImageSelectActiveFrame as *const () as usize,
        "GdipImageGetFrameDimensionsCount" => {
            GdipImageGetFrameDimensionsCount as *const () as usize
        }
        "GdipImageGetFrameDimensionsList" => GdipImageGetFrameDimensionsList as *const () as usize,
        // Property/metadata
        "GdipGetPropertyCount" => GdipGetPropertyCount as *const () as usize,
        "GdipGetPropertyIdList" => GdipGetPropertyIdList as *const () as usize,
        "GdipGetPropertyItemSize" => GdipGetPropertyItemSize as *const () as usize,
        "GdipGetPropertyItem" => GdipGetPropertyItem as *const () as usize,
        "GdipGetAllPropertyItems" => GdipGetAllPropertyItems as *const () as usize,
        // Graphics context
        "GdipCreateFromHDC" => GdipCreateFromHDC as *const () as usize,
        "GdipCreateFromHDC2" => GdipCreateFromHDC2 as *const () as usize,
        "GdipCreateFromHWND" => GdipCreateFromHWND as *const () as usize,
        "GdipDeleteGraphics" => GdipDeleteGraphics as *const () as usize,
        "GdipGetDC" => GdipGetDC as *const () as usize,
        "GdipReleaseDC" => GdipReleaseDC as *const () as usize,
        // Graphics state
        "GdipSetInterpolationMode" => GdipSetInterpolationMode as *const () as usize,
        "GdipGetInterpolationMode" => GdipGetInterpolationMode as *const () as usize,
        "GdipSetSmoothingMode" => GdipSetSmoothingMode as *const () as usize,
        "GdipGetSmoothingMode" => GdipGetSmoothingMode as *const () as usize,
        "GdipSetPixelOffsetMode" => GdipSetPixelOffsetMode as *const () as usize,
        "GdipSetCompositingMode" => GdipSetCompositingMode as *const () as usize,
        "GdipSetCompositingQuality" => GdipSetCompositingQuality as *const () as usize,
        "GdipSetTextRenderingHint" => GdipSetTextRenderingHint as *const () as usize,
        "GdipSetPageUnit" => GdipSetPageUnit as *const () as usize,
        "GdipSetPageScale" => GdipSetPageScale as *const () as usize,
        "GdipGetPageUnit" => GdipGetPageUnit as *const () as usize,
        "GdipGetDpiX" => GdipGetDpiX as *const () as usize,
        "GdipGetDpiY" => GdipGetDpiY as *const () as usize,
        // Clipping
        "GdipSetClipRect" => GdipSetClipRect as *const () as usize,
        "GdipSetClipRectI" => GdipSetClipRectI as *const () as usize,
        "GdipResetClip" => GdipResetClip as *const () as usize,
        "GdipSaveGraphics" => GdipSaveGraphics as *const () as usize,
        "GdipRestoreGraphics" => GdipRestoreGraphics as *const () as usize,
        // Drawing
        "GdipGraphicsClear" => GdipGraphicsClear as *const () as usize,
        "GdipDrawImage" => GdipDrawImage as *const () as usize,
        "GdipDrawImageI" => GdipDrawImageI as *const () as usize,
        "GdipDrawImageRect" => GdipDrawImageRect as *const () as usize,
        "GdipDrawImageRectI" => GdipDrawImageRectI as *const () as usize,
        "GdipDrawImageRectRect" => GdipDrawImageRectRect as *const () as usize,
        "GdipDrawImageRectRectI" => GdipDrawImageRectRectI as *const () as usize,
        "GdipDrawImagePoints" => GdipDrawImagePoints as *const () as usize,
        "GdipDrawImagePointsI" => GdipDrawImagePointsI as *const () as usize,
        "GdipDrawImagePointsRect" => GdipDrawImagePointsRect as *const () as usize,
        "GdipFillRectangle" => GdipFillRectangle as *const () as usize,
        "GdipFillRectangleI" => GdipFillRectangleI as *const () as usize,
        "GdipFillEllipse" => GdipFillEllipse as *const () as usize,
        "GdipDrawRectangle" => GdipDrawRectangle as *const () as usize,
        "GdipDrawRectangleI" => GdipDrawRectangleI as *const () as usize,
        "GdipDrawLine" => GdipDrawLine as *const () as usize,
        "GdipDrawLineI" => GdipDrawLineI as *const () as usize,
        "GdipDrawString" => GdipDrawString as *const () as usize,
        "GdipMeasureString" => GdipMeasureString as *const () as usize,
        // Brushes
        "GdipCreateSolidFill" => GdipCreateSolidFill as *const () as usize,
        "GdipDeleteBrush" => GdipDeleteBrush as *const () as usize,
        "GdipGetBrushType" => GdipGetBrushType as *const () as usize,
        "GdipCreateLineBrush" => GdipCreateLineBrush as *const () as usize,
        "GdipCreateTexture" => GdipCreateTexture as *const () as usize,
        // Pens
        "GdipCreatePen1" => GdipCreatePen1 as *const () as usize,
        "GdipCreatePen2" => GdipCreatePen2 as *const () as usize,
        "GdipDeletePen" => GdipDeletePen as *const () as usize,
        // Fonts
        "GdipCreateFontFamilyFromName" => GdipCreateFontFamilyFromName as *const () as usize,
        "GdipDeleteFontFamily" => GdipDeleteFontFamily as *const () as usize,
        "GdipCreateFont" => GdipCreateFont as *const () as usize,
        "GdipCreateFontFromDC" => GdipCreateFontFromDC as *const () as usize,
        "GdipCreateFontFromLogfontW" => GdipCreateFontFromLogfontW as *const () as usize,
        "GdipDeleteFont" => GdipDeleteFont as *const () as usize,
        "GdipGetFontHeight" => GdipGetFontHeight as *const () as usize,
        "GdipGetFontSize" => GdipGetFontSize as *const () as usize,
        // String format
        "GdipCreateStringFormat" => GdipCreateStringFormat as *const () as usize,
        "GdipDeleteStringFormat" => GdipDeleteStringFormat as *const () as usize,
        "GdipStringFormatGetGenericDefault" => {
            GdipStringFormatGetGenericDefault as *const () as usize
        }
        "GdipStringFormatGetGenericTypographic" => {
            GdipStringFormatGetGenericTypographic as *const () as usize
        }
        "GdipSetStringFormatAlign" => GdipSetStringFormatAlign as *const () as usize,
        "GdipSetStringFormatLineAlign" => GdipSetStringFormatLineAlign as *const () as usize,
        "GdipSetStringFormatTrimming" => GdipSetStringFormatTrimming as *const () as usize,
        "GdipSetStringFormatFlags" => GdipSetStringFormatFlags as *const () as usize,
        // Image attributes
        "GdipCreateImageAttributes" => GdipCreateImageAttributes as *const () as usize,
        "GdipDisposeImageAttributes" => GdipDisposeImageAttributes as *const () as usize,
        "GdipSetImageAttributesColorKey" => GdipSetImageAttributesColorKey as *const () as usize,
        "GdipSetImageAttributesColorMatrix" => {
            GdipSetImageAttributesColorMatrix as *const () as usize
        }
        "GdipSetImageAttributesGamma" => GdipSetImageAttributesGamma as *const () as usize,
        "GdipSetImageAttributesWrapMode" => GdipSetImageAttributesWrapMode as *const () as usize,
        // Bitmap pixel access
        "GdipBitmapGetPixel" => GdipBitmapGetPixel as *const () as usize,
        "GdipBitmapSetPixel" => GdipBitmapSetPixel as *const () as usize,
        "GdipBitmapLockBits" => GdipBitmapLockBits as *const () as usize,
        "GdipBitmapUnlockBits" => GdipBitmapUnlockBits as *const () as usize,
        // Paths
        "GdipCreatePath" => GdipCreatePath as *const () as usize,
        "GdipDeletePath" => GdipDeletePath as *const () as usize,
        "GdipDrawPath" => GdipDrawPath as *const () as usize,
        "GdipFillPath" => GdipFillPath as *const () as usize,
        // Transforms
        "GdipSetWorldTransform" => GdipSetWorldTransform as *const () as usize,
        "GdipResetWorldTransform" => GdipResetWorldTransform as *const () as usize,
        "GdipTranslateWorldTransform" => GdipTranslateWorldTransform as *const () as usize,
        "GdipScaleWorldTransform" => GdipScaleWorldTransform as *const () as usize,
        "GdipRotateWorldTransform" => GdipRotateWorldTransform as *const () as usize,
        "GdipCreateMatrix" => GdipCreateMatrix as *const () as usize,
        "GdipDeleteMatrix" => GdipDeleteMatrix as *const () as usize,
        _ => return None,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_functions() {
        let funcs = [
            "GdiplusStartup",
            "GdiplusShutdown",
            "GdipGetImageEncodersSize",
            "GdipGetImageEncoders",
            "GdipGetImageDecodersSize",
            "GdipGetImageDecoders",
            "GdipLoadImageFromFile",
            "GdipDisposeImage",
            "GdipCreateBitmapFromFile",
            "GdipCreateBitmapFromHBITMAP",
            "GdipCreateHBITMAPFromBitmap",
            "GdipGetImageWidth",
            "GdipGetImageHeight",
            "GdipGetImageType",
            "GdipCreateFromHDC",
            "GdipDeleteGraphics",
            "GdipDrawImageRectRect",
            "GdipSetInterpolationMode",
            "GdipSetSmoothingMode",
            "GdipCreateSolidFill",
            "GdipDeleteBrush",
            "GdipCreatePen1",
            "GdipDeletePen",
            "GdipCreateFontFamilyFromName",
            "GdipCreateFont",
            "GdipDeleteFont",
            "GdipDrawString",
            "GdipCreateStringFormat",
            "GdipDeleteStringFormat",
            "GdipCreateImageAttributes",
            "GdipDisposeImageAttributes",
            "GdipBitmapLockBits",
            "GdipBitmapUnlockBits",
        ];
        for f in &funcs {
            assert!(resolve("gdiplus.dll", f).is_some(), "missing: {f}");
        }
    }

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "GdiplusStartup").is_none());
    }

    #[test]
    fn resolve_case_insensitive() {
        assert!(resolve("GDIPLUS.DLL", "GdiplusStartup").is_some());
        assert!(resolve("GdiPlus.Dll", "GdiplusShutdown").is_some());
    }

    #[test]
    fn startup_null_token_is_invalid_parameter() {
        // Wine ref: dlls/gdiplus/gdiplus.c:87 — token NULL → InvalidParameter
        // Build a minimal valid GdiplusStartupInput (version=1, rest zeroed).
        let input = [1u32, 0, 0, 0];
        let status = unsafe {
            GdiplusStartup(
                std::ptr::null_mut(),
                input.as_ptr() as *const u8,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            status, GP_INVALID_PARAMETER,
            "NULL token must return InvalidParameter"
        );
    }

    #[test]
    fn startup_null_input_is_invalid_parameter() {
        // Wine ref: dlls/gdiplus/gdiplus.c:87 — input NULL → InvalidParameter
        let mut token: usize = 0;
        let status = unsafe { GdiplusStartup(&mut token, std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(
            status, GP_INVALID_PARAMETER,
            "NULL input must return InvalidParameter"
        );
    }

    #[test]
    fn startup_sets_deadbeef_token() {
        // Wine ref: dlls/gdiplus/gdiplus.c:104 — token is set to 0xdeadbeef
        let mut token: usize = 0;
        let input = [1u32, 0, 0, 0]; // GdiplusStartupInput { Version=1, ... }
        let status = unsafe {
            GdiplusStartup(
                &mut token,
                input.as_ptr() as *const u8,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, GP_OK, "valid GdiplusStartup must return Ok");
        assert_eq!(
            token, 0xdeadbeef,
            "token must be set to 0xdeadbeef (Wine behaviour)"
        );
    }

    #[test]
    fn startup_bad_version_returns_unsupported() {
        // Wine ref: dlls/gdiplus/gdiplus.c:94 — version 0 or >2 → UnsupportedGdiplusVersion=18
        let mut token: usize = 0;
        let input_v0 = [0u32, 0, 0, 0];
        let s = unsafe {
            GdiplusStartup(
                &mut token,
                input_v0.as_ptr() as *const u8,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(s, 18, "version=0 must return UnsupportedGdiplusVersion");
        let input_v3 = [3u32, 0, 0, 0];
        let s = unsafe {
            GdiplusStartup(
                &mut token,
                input_v3.as_ptr() as *const u8,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(s, 18, "version=3 must return UnsupportedGdiplusVersion");
    }

    #[test]
    fn encoder_size_returns_zero() {
        let mut count = 99u32;
        let mut size = 99u32;
        let status = unsafe { GdipGetImageEncodersSize(&mut count, &mut size) };
        assert_eq!(status, 0);
        assert_eq!(count, 0);
        assert_eq!(size, 0);
    }

    #[test]
    fn decoder_size_returns_zero() {
        let mut count = 99u32;
        let mut size = 99u32;
        let status = unsafe { GdipGetImageDecodersSize(&mut count, &mut size) };
        assert_eq!(status, 0);
        assert_eq!(count, 0);
        assert_eq!(size, 0);
    }

    #[test]
    fn property_count_null_image_is_invalid_parameter() {
        // Wine ref: dlls/gdiplus/image.c:2365 — image NULL → InvalidParameter
        let mut count = 5u32;
        let status = unsafe { GdipGetPropertyCount(0, &mut count) };
        assert_eq!(status, GP_INVALID_PARAMETER);
    }

    #[test]
    fn property_count_valid_returns_zero_ok() {
        // Wine ref: dlls/gdiplus/image.c:2365 — no metadata → *num=0, Ok
        let mut count = 5u32;
        let status = unsafe { GdipGetPropertyCount(1, &mut count) }; // fake non-null image
        assert_eq!(status, GP_OK);
        assert_eq!(count, 0);
    }

    #[test]
    fn dispose_image_null_is_invalid_parameter() {
        // Wine ref: dlls/gdiplus/image.c:2104 — NULL image → InvalidParameter
        assert_eq!(GdipDisposeImage(0), GP_INVALID_PARAMETER);
    }

    #[test]
    fn delete_graphics_null_is_invalid_parameter() {
        // Wine ref: dlls/gdiplus/graphics.c:2652 — NULL graphics → InvalidParameter
        assert_eq!(GdipDeleteGraphics(0), GP_INVALID_PARAMETER);
    }

    #[test]
    fn delete_functions_are_ok() {
        assert_eq!(GdipDisposeImage(1), 0); // non-null → Ok
        assert_eq!(GdipDeleteGraphics(1), 0); // non-null → Ok
        assert_eq!(GdipDeleteBrush(0), 0);
        assert_eq!(GdipDeletePen(0), 0);
        assert_eq!(GdipDeleteFont(0), 0);
        assert_eq!(GdipDeleteFontFamily(0), 0);
        assert_eq!(GdipDeleteStringFormat(0), 0);
        assert_eq!(GdipDisposeImageAttributes(0), 0);
        assert_eq!(GdipDeletePath(0), 0);
        assert_eq!(GdipDeleteMatrix(0), 0);
        // GdiplusShutdown returns 0 (ULONG), Wine ref: gdiplus.c:127
        assert_eq!(unsafe { GdiplusShutdown(0xdeadbeef) }, 0);
    }
}
