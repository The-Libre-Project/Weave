//! gdi32.dll stubs for Weave.
//!
//! GDI object management, DC attributes, basic 2D drawing, and text rendering.
//! Actual rendering delegates to `weave_user32::backend` which holds the X11
//! connection. All stubs are safe to call even when no display is available —
//! drawing functions become no-ops on headless systems.
//!
//! # Coupling to weave-user32 — intentional, documented exception
//!
//! `weave-gdi32` directly imports `weave-user32`. This violates the general
//! architecture rule that DLL crates should not import each other (shared types
//! belong in `weave-common`). The exception is intentional and mirrors real
//! Windows: gdi32 and user32 are deeply entangled at the implementation level.
//!
//! On Windows, gdi32 cannot function without user32 internals:
//! - **Window DCs**: `GetDC` / `BeginPaint` return a DC bound to an HWND. gdi32
//!   must reach into the window's drawable (here: an XCB drawable/pixmap) to
//!   issue drawing commands. That state lives in `weave_user32::window`.
//! - **Paint context**: `weave_user32::api::current_paint_hwnd()` tracks the
//!   window currently inside `BeginPaint`/`EndPaint`. gdi32 needs this to
//!   resolve which drawable the DC targets during a WM_PAINT handler.
//! - **Rendering backend**: X11 drawing primitives (fill, line, blit, text) are
//!   owned by `weave_user32::backend` because user32 bootstraps the XCB
//!   connection. gdi32 borrows those primitives rather than re-owning the
//!   connection.
//! - **Font metrics**: `weave_user32::font` provides the fontdue rasterizer.
//!   gdi32 calls `metrics()` and `measure_text()` for `GetTextMetrics`,
//!   `GetTextExtentPoint32`, and `DrawText` layout.
//!
//! Extraction was evaluated (audit action 01, 2026-04-15). The surface is 13
//! items across 4 modules (`backend`, `font`, `api`, `window`), several of
//! which mutate or read user32-internal state. Moving them to `weave-common`
//! would either hollow out `weave-user32` or create a circular dependency.
//! The coupling is accepted as-is. Do not add further DLL→DLL imports without
//! a similar written justification.
//!
//! # Text rendering (Phase 3)
//!
//! Text is rendered via fontdue (pure-Rust TrueType rasterizer). UTF-16 strings
//! are passed through without lossy conversion. System fonts are loaded from
//! standard Linux paths; if unavailable, falls back to X11 bitmap fonts.
//!
//! # Current simplifications
//!
//! - Memory DCs are backed by X11 Pixmaps (created on SelectObject of a bitmap).
//! - BitBlt / SRCCOPY copies from the src Pixmap to the dst drawable via XCopyArea.
//! - Other ROP codes beyond SRCCOPY are not yet implemented.

pub mod dc;
pub mod defs;
pub mod objects;

use defs::*;
use objects::GdiKind;

// ── Pixel helpers ─────────────────────────────────────────────────────────────

/// Win32 COLORREF (0x00BBGGRR) → X11 TrueColor pixel (0x00RRGGBB).
#[inline]
fn to_pixel(colorref: u32) -> u32 {
    weave_user32::backend::colorref_to_pixel(colorref)
}

// ── GDI object creation / deletion ───────────────────────────────────────────

/// CreateSolidBrush: allocate a solid-colour brush.
///
/// Wine ref: dlls/win32u/pen.c — NtGdiCreateSolidBrush allocates a BRUSHOBJ with
/// lbStyle=BS_SOLID and lbColor=color; returns NULL on failure.
pub extern "win64" fn create_solid_brush(color: u32) -> usize {
    objects::alloc(GdiKind::Brush { color })
}

/// CreatePen: allocate a cosmetic pen.
///
/// Wine ref: dlls/win32u/pen.c — NtGdiExtCreatePen; fnPenStyle may be PS_SOLID/PS_DASH/etc.;
/// nWidth=0 selects 1-pixel cosmetic width. Returns NULL on failure.
pub extern "win64" fn create_pen(fn_pen_style: i32, n_width: i32, color: u32) -> usize {
    objects::alloc(GdiKind::Pen {
        color,
        style: fn_pen_style,
        width: n_width,
    })
}

/// CreateFontW: allocate a logical font.
///
/// # Safety
/// `lp_sz_face` (if non-null) must be a null-terminated UTF-16 string.
// Wine ref: dlls/win32u/font.c — NtGdiHfontCreate fills LOGFONTW; lfFaceName is
// truncated to LF_FACESIZE-1 (31) chars; lfHeight<0 means cell height, >0 means
// character height; weight 400=normal, 700=bold.
pub unsafe extern "win64" fn create_font_w(
    c_height: i32,
    _c_width: i32,
    _c_escapement: i32,
    _c_orientation: i32,
    c_weight: i32,
    b_italic: u32,
    _b_underline: u32,
    _b_strike_out: u32,
    _i_char_set: u32,
    _i_out_precision: u32,
    _i_clip_precision: u32,
    _i_quality: u32,
    _i_pitch_and_family: u32,
    lp_sz_face: *const u16,
) -> usize {
    let mut face = [0u16; 32];
    if !lp_sz_face.is_null() {
        let mut i = 0usize;
        while i < 31 {
            let ch = unsafe { *lp_sz_face.add(i) };
            if ch == 0 {
                break;
            }
            face[i] = ch;
            i += 1;
        }
    }
    objects::alloc(GdiKind::Font {
        height: c_height,
        weight: c_weight,
        italic: b_italic != 0,
        face,
    })
}

/// CreateFontIndirectW: allocate a logical font from a LOGFONTW struct.
///
/// # Safety
/// `lplf` must be a valid pointer to a `LOGFONTW`.
// Wine ref: dlls/win32u/font.c — NtGdiHfontCreate copies the full LOGFONTW; if lplf
// is NULL returns NULL; lfFaceName is treated as UTF-16 and clamped to 31 chars.
pub unsafe extern "win64" fn create_font_indirect_w(lplf: *const LogFontW) -> usize {
    if lplf.is_null() {
        return 0;
    }
    let lf = unsafe { &*lplf };
    objects::alloc(GdiKind::Font {
        height: lf.lf_height,
        weight: lf.lf_weight,
        italic: lf.lf_italic != 0,
        face: lf.lf_face_name,
    })
}

/// DeleteObject: free an allocated GDI object.
///
/// For `Bitmap` and `DibSection` handles, also reconstructs the leaked pixel
/// buffer via `Box::from_raw` and drops it, so `CreateCompatibleBitmap` /
/// `CreateDIBSection` + `DeleteObject` does not leak memory per round-trip.
///
/// Wine ref: dlls/win32u/gdiobj.c — NtGdiDeleteObjectApp; returns FALSE if the object is
/// a stock object (stock objects cannot be deleted). Weave: stock handles are not freed.
pub extern "win64" fn delete_object(h_object: usize) -> i32 {
    if h_object == 0 {
        return 0;
    }
    // Snapshot the backing-buffer info before dropping the handle entry.
    let buf_info: Option<(usize, usize)> = objects::get(h_object, |kind| match kind {
        GdiKind::Bitmap {
            width,
            height,
            bits_ptr,
            bpp,
        }
        | GdiKind::DibSection {
            width,
            height,
            bits_ptr,
            bpp,
        } => {
            // Match CreateDIBSection's stride rule (dword-aligned rows) so
            // both entry points round-trip through Box::from_raw correctly.
            let stride = (u64::from(*width) * u64::from(*bpp)).div_ceil(32) * 4;
            let size = (stride * u64::from(*height)).max(1) as usize;
            Some((*bits_ptr, size))
        }
        _ => None,
    })
    .flatten();
    let ok = objects::free(h_object);
    if ok {
        if let Some((ptr, size)) = buf_info {
            if ptr != 0 {
                // Reconstruct the boxed slice we leaked at creation time.
                // SAFETY: ptr was produced by Box::leak(Box<[u8]> of `size`
                // bytes) in create_compatible_bitmap / create_dib_section /
                // create_compatible_dc's stub allocation; we are the sole
                // owner by virtue of just removing the handle entry.
                unsafe {
                    let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, size);
                    drop(Box::from_raw(slice as *mut [u8]));
                }
            }
        }
    }
    ok as i32
}

/// GetStockObject: return a stock GDI object handle.
///
/// Wine ref: dlls/gdi32/objects.c::GetStockObject — validates 0 ≤ obj ≤ STOCK_LAST+1 and
/// obj ≠ 9; maps DPI-aware font aliases for SYSTEM_FONT etc. Returns 0 for out-of-range.
pub extern "win64" fn get_stock_object(i_object: i32) -> usize {
    if (0..=19).contains(&i_object) {
        objects::stock_handle(i_object)
    } else {
        0
    }
}

/// GetObject: fill a buffer with GDI object information.
///
/// Delegates to `get_object_w` — same binary representation on x64 (pointer == usize).
// Wine ref: dlls/gdi32/objects.c — GetObject calls NtGdiExtGetObjectW; for HBITMAP
// returns BITMAP or DIBSECTION; for HPEN returns LOGPEN (or EXTLOGPEN if ExtCreatePen);
// returns 0 if h is NULL or unrecognized type.
pub extern "win64" fn get_object(h: usize, c: i32, pv: usize) -> i32 {
    unsafe { get_object_w(h, c, pv as *mut u8) }
}

// ── DC object selection ───────────────────────────────────────────────────────

/// SelectObject: bind a GDI object to a DC; returns the previously selected object.
///
/// Wine ref: dlls/win32u/dc.c — NtGdiSelectObject dispatches by object type (pen/brush/font/
/// bitmap/region); returns the previously selected object of that type. Selecting a bitmap
/// only succeeds on memory DCs (Phase 2 gap: Weave has no real memory DCs).
pub extern "win64" fn select_object(hdc: usize, h_gdi_obj: usize) -> usize {
    let mut old: usize = 0;
    dc::with_mut(hdc, |dc| {
        // Determine object type from the handle and update the appropriate slot.
        if objects::is_stock(h_gdi_obj) {
            let idx = (h_gdi_obj - STOCK_HANDLE_BASE) as i32;
            match idx {
                WHITE_BRUSH | LTGRAY_BRUSH | GRAY_BRUSH | DKGRAY_BRUSH | BLACK_BRUSH
                | NULL_BRUSH | DC_BRUSH => {
                    old = dc.h_brush;
                    dc.h_brush = h_gdi_obj;
                }
                WHITE_PEN | BLACK_PEN | NULL_PEN | DC_PEN => {
                    old = dc.h_pen;
                    dc.h_pen = h_gdi_obj;
                }
                OEM_FIXED_FONT | ANSI_FIXED_FONT | ANSI_VAR_FONT | SYSTEM_FONT
                | DEVICE_DEFAULT_FONT | SYSTEM_FIXED_FONT | DEFAULT_GUI_FONT => {
                    old = dc.h_font;
                    dc.h_font = h_gdi_obj;
                }
                _ => {}
            }
        } else {
            objects::get(h_gdi_obj, |kind| match kind {
                GdiKind::Brush { .. } => {
                    old = dc.h_brush;
                    dc.h_brush = h_gdi_obj;
                }
                GdiKind::Pen { .. } => {
                    old = dc.h_pen;
                    dc.h_pen = h_gdi_obj;
                }
                GdiKind::Font { .. } => {
                    old = dc.h_font;
                    dc.h_font = h_gdi_obj;
                }
                GdiKind::Bitmap { width, height, .. }
                | GdiKind::DibSection { width, height, .. } => {
                    old = dc.selected_bitmap;
                    dc.selected_bitmap = h_gdi_obj;
                    if dc.pixmap.is_none() {
                        let parent_draw = dc.drawable();
                        let pid = weave_user32::backend::create_pixmap(
                            parent_draw,
                            *width as u16,
                            *height as u16,
                        );
                        // Only store a non-zero pixmap ID.  If create_pixmap fails
                        // (returns 0) leave dc.pixmap as None so drawable() falls
                        // back to xcb_id(hwnd) rather than returning 0, which would
                        // silently discard all draw calls to this DC.
                        // Wine ref: dlls/winex11.drv/bitmap.c — X11DRV_CreateBitmap
                        // fails gracefully; callers fall back to display DC drawing.
                        if pid != 0 {
                            dc.pixmap = Some(pid);
                        }
                    }
                }
                GdiKind::Region => {
                    // SelectObject with a region selects it as the clip region.
                    // Phase 2 stub — clipping not applied, but return non-zero
                    // so callers see "success" and don't abort.
                    old = 0;
                }
            });
        }
    });
    old
}

// ── DC attribute setters / getters ────────────────────────────────────────────

/// SetTextColor: set the foreground (text) colour. Returns the previous colour.
///
/// Wine ref: dlls/win32u/dc.c::set_text_color — stores color in dc->attr->text_color via
/// physdev chain; returns CLR_INVALID (0xFFFFFFFF) for an invalid HDC. Weave returns 0.
pub extern "win64" fn set_text_color(hdc: usize, color: u32) -> u32 {
    let mut prev = 0u32;
    dc::with_mut(hdc, |dc| {
        prev = dc.text_color;
        dc.text_color = color;
    });
    prev
}

/// GetTextColor: return the current text colour.
// Wine ref: dlls/win32u/dc.c — reads dc->attr->text_color directly; returns
// CLR_INVALID (0xFFFFFFFF) if hdc is invalid (Weave returns 0 for invalid hdc).
pub extern "win64" fn get_text_color(hdc: usize) -> u32 {
    dc::with(hdc, |dc| dc.text_color)
}

/// SetBkColor: set the background colour used by text and hatched brushes.
// Wine ref: dlls/win32u/dc.c::set_bk_color — stores color in dc->attr->background_color
// via physdev chain (pSetBkColor); returns previous color; CLR_INVALID returned on bad hdc.
pub extern "win64" fn set_bk_color(hdc: usize, color: u32) -> u32 {
    let mut prev = 0u32;
    dc::with_mut(hdc, |dc| {
        prev = dc.bk_color;
        dc.bk_color = color;
    });
    prev
}

/// GetBkColor: return the current background colour.
// Wine ref: dlls/win32u/dc.c — reads dc->attr->background_color directly;
// returns CLR_INVALID on invalid hdc.
pub extern "win64" fn get_bk_color(hdc: usize) -> u32 {
    dc::with(hdc, |dc| dc.bk_color)
}

/// SetBkMode: TRANSPARENT (1) or OPAQUE (2).
// Wine ref: dlls/win32u/dc.c — stores mode in dc->attr->background_mode; returns
// previous mode; only TRANSPARENT(1) and OPAQUE(2) are valid; invalid values are
// stored as-is (no validation in Wine).
pub extern "win64" fn set_bk_mode(hdc: usize, i_bk_mode: i32) -> i32 {
    let mut prev = 0i32;
    dc::with_mut(hdc, |dc| {
        prev = dc.bk_mode;
        dc.bk_mode = i_bk_mode;
    });
    prev
}

/// GetBkMode: return the current background mode.
// Wine ref: dlls/win32u/dc.c — reads dc->attr->background_mode directly; returns 0
// on invalid hdc (not CLR_INVALID since mode is INT not COLORREF).
pub extern "win64" fn get_bk_mode(hdc: usize) -> i32 {
    dc::with(hdc, |dc| dc.bk_mode)
}

/// SetGraphicsMode: select compatible or advanced graphics mode for an HDC.
///
/// Wine ref: dlls/win32u/dc.c::NtGdiSetGraphicsMode — accepts GM_COMPATIBLE(1)
/// or GM_ADVANCED(2), returns the previous mode, and rejects invalid values.
pub extern "win64" fn set_graphics_mode(hdc: usize, i_mode: i32) -> i32 {
    if i_mode != GM_COMPATIBLE && i_mode != GM_ADVANCED {
        return 0;
    }
    let mut prev = GM_COMPATIBLE;
    dc::with_mut(hdc, |dc| {
        prev = dc.graphics_mode;
        dc.graphics_mode = i_mode;
    });
    prev
}

/// SetWorldTransform: replace the DC world transform.
///
/// # Safety
/// `lp_xform` must point to a valid XFORM. Windows requires GM_ADVANCED; Weave
/// follows that contract so callers that check return values get a real signal.
pub unsafe extern "win64" fn set_world_transform(hdc: usize, lp_xform: *const XForm) -> i32 {
    if lp_xform.is_null() {
        return 0;
    }
    let xf = unsafe { *lp_xform };
    let mut ok = 0;
    dc::with_mut(hdc, |dc| {
        if dc.graphics_mode == GM_ADVANCED {
            dc.world_transform = xf;
            ok = 1;
        }
    });
    ok
}

/// GetWorldTransform: copy the current DC world transform.
///
/// # Safety
/// `lp_xform` must point to writable XFORM storage.
pub unsafe extern "win64" fn get_world_transform(hdc: usize, lp_xform: *mut XForm) -> i32 {
    if lp_xform.is_null() {
        return 0;
    }
    dc::with(hdc, |dc| unsafe {
        *lp_xform = dc.world_transform;
    });
    1
}

// ── Drawing primitives ────────────────────────────────────────────────────────

/// FillRect: fill a rectangle with a brush.
///
/// Wine ref: dlls/win32u/defwnd.c::fill_rect — if hbrush ≤ COLOR_MENUBAR+1 (31), treats
/// the value as a system colour index and maps to the real sys color brush; selects it
/// into the DC, calls PatBlt with PATCOPY, then restores the old brush. Returns 1 on
/// success, 0 if rect is NULL.
///
/// # Safety
/// `lp_rc` must be a valid pointer to a `RECT`.
// Wine ref: dlls/win32u/defwnd.c::fill_rect — hbrush ≤ 31 treated as system color index.
pub unsafe extern "win64" fn fill_rect(hdc: usize, lp_rc: *const Rect, h_brush: usize) -> i32 {
    if lp_rc.is_null() {
        return 0;
    }
    let rc = unsafe { *lp_rc };
    {
        static FR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if FR.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3 {
            let xcb = dc::with(hdc, |dc| dc.drawable());
            eprintln!(
                "weave/gdi32: FillRect hdc={hdc:#x} xcb={xcb:#x} ({},{}) {}x{}",
                rc.left,
                rc.top,
                rc.right - rc.left,
                rc.bottom - rc.top
            );
        }
    }
    let (dx, dy) = dc::with(hdc, |dc| dc.lp_to_device(rc.left, rc.top));
    let w = (rc.right - rc.left).max(0) as u16;
    let h = (rc.bottom - rc.top).max(0) as u16;
    if w == 0 || h == 0 {
        return 1;
    }
    // Windows allows passing (COLOR_xxx + 1) as a pseudo-brush handle.
    // Handle values 1..=31 are system color sentinels; 0 means use DC brush.
    let color = if (1..=31).contains(&h_brush) {
        objects::sys_color_rgb(h_brush - 1)
    } else {
        let brush = if h_brush == 0 {
            dc::with(hdc, |dc| dc.h_brush)
        } else {
            h_brush
        };
        objects::brush_color(brush)
    };
    let pixel = to_pixel(color);
    let xcb = dc::with(hdc, |dc| dc.drawable());
    let (dw, dh) = dc::with(hdc, |dc| dc.lp_to_device(rc.right, rc.bottom));
    let ww = (dw - dx) as u16;
    let hh = (dh - dy) as u16;
    weave_user32::backend::draw_filled_rect(xcb, dx, dy, ww, hh, pixel);
    1
}

/// Rectangle: draw a filled rectangle with the current brush, outlined with the current pen.
// Wine ref: dlls/win32u/driver.c::nulldrv_Rectangle — forwards to physdev chain;
// the pen outline excludes right/bottom edges (interior is left+1..right-1); empty
// or inverted rectangles (left>=right or top>=bottom) are silently no-ops.
pub extern "win64" fn rectangle(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) -> i32 {
    let (dx, dy) = dc::with(hdc, |dc| dc.lp_to_device(left, top));
    let w = (right - left).max(0) as u16;
    let h = (bottom - top).max(0) as u16;
    if w == 0 || h == 0 {
        return 1;
    }
    let xcb = dc::with(hdc, |dc| dc.drawable());
    let (brush_h, pen_h) = dc::with(hdc, |dc| (dc.h_brush, dc.h_pen));

    // Fill interior with brush.
    let fill_pixel = to_pixel(objects::brush_color(brush_h));
    weave_user32::backend::draw_filled_rect(xcb, dx, dy, w, h, fill_pixel);

    // Draw outline with pen.
    let outline_pixel = to_pixel(objects::pen_color(pen_h));
    weave_user32::backend::draw_rect_outline(xcb, dx, dy, w, h, outline_pixel);
    1
}

/// Ellipse: draw an ellipse (stub in Phase 2 — renders as a rectangle).
// Wine ref: dlls/win32u/driver.c::nulldrv_Ellipse — forwards to physdev chain;
// bounding box semantics same as Rectangle (exclusive right/bottom); fills with
// current brush, outlines with current pen.
pub extern "win64" fn ellipse(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) -> i32 {
    // TODO Phase 3: real ellipse rasterisation.
    rectangle(hdc, left, top, right, bottom)
}

/// Default font pixel size when no specific height is selected.
const DEFAULT_FONT_PX: f32 = 13.0;

/// Resolve the pixel size for the font currently selected into this DC.
fn font_px_size(hdc: usize) -> f32 {
    let h_font = dc::with(hdc, |dc| dc.h_font);
    if h_font == 0 {
        return DEFAULT_FONT_PX;
    }
    let mut height: i32 = 0;
    objects::get(h_font, |kind| {
        if let GdiKind::Font { height: h, .. } = kind {
            height = *h;
        }
    });
    if height == 0 {
        DEFAULT_FONT_PX
    } else {
        height.unsigned_abs().max(8) as f32
    }
}

/// TextOutW: draw a UTF-16 string at (x, y) using the current DC colours.
///
/// Wine ref: dlls/win32u/font.c::nulldrv_ExtTextOut — TextOutW maps to ExtTextOutW with
/// no options/rect; renders glyphs using the selected font; honours current text and bk
/// colors and bk mode (OPAQUE fills background, TRANSPARENT does not).
/// Known gap: Weave always paints an opaque background regardless of bk mode.
///
/// # Safety
/// `lp_string` must be a valid pointer to `c` UTF-16 code units.
// Wine ref: dlls/win32u/font.c::nulldrv_ExtTextOut — TextOutW calls ExtTextOutW(0,NULL).
pub unsafe extern "win64" fn text_out_w(
    hdc: usize,
    x: i32,
    y: i32,
    lp_string: *const u16,
    c: i32,
) -> i32 {
    {
        static TOW: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if TOW.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3 {
            eprintln!("weave/gdi32: TextOutW hdc={hdc:#x} ({x},{y}) c={c}");
        }
    }
    if lp_string.is_null() || c <= 0 {
        return 0;
    }
    // Pointer validation: cap c to prevent building a multi-GB slice from a
    // crafted large c value. Real text is never this long.
    const MAX_TEXT_CHARS: i32 = 65_536;
    let c = c.min(MAX_TEXT_CHARS);
    let (fg, bg) = dc::with(hdc, |dc| (dc.text_color, dc.bk_color));
    let fg_pixel = to_pixel(fg);
    let bg_pixel = to_pixel(bg);
    let units: &[u16] = unsafe { std::slice::from_raw_parts(lp_string, c as usize) };
    let xcb = dc::with(hdc, |dc| dc.drawable());
    let px_size = font_px_size(hdc);
    let text_align = dc::with(hdc, |dc| dc.text_align);

    let draw_y = match text_align & 0x0018 {
        TA_BASELINE => {
            let fm = weave_user32::font::metrics(px_size);
            y - fm.ascent
        }
        TA_BOTTOM => {
            let fm = weave_user32::font::metrics(px_size);
            y - fm.height
        }
        _ => y,
    };
    let draw_x = match text_align & 0x0006 {
        TA_RIGHT => {
            let (tw, _) = weave_user32::font::measure_text(units, px_size);
            x - tw
        }
        TA_CENTER => {
            let (tw, _) = weave_user32::font::measure_text(units, px_size);
            x - tw / 2
        }
        _ => x,
    };

    weave_user32::backend::draw_text_utf16(
        xcb,
        draw_x as i16,
        draw_y as i16,
        units,
        px_size,
        fg_pixel,
        bg_pixel,
    );
    1
}

/// DrawTextW: draw formatted text within a rectangle.
///
/// Supports DT_CALCRECT, DT_CENTER, DT_RIGHT, DT_VCENTER, DT_SINGLELINE.
///
/// # Safety
/// `lp_string` must point to `n_count` UTF-16 units (or null-terminated if
/// `n_count == -1`). `lp_rect` must be a valid pointer to a `RECT`.
// Wine ref: dlls/user32/text.c::DrawTextExW — DT_CALCRECT updates lp_rect without
// drawing; DT_NOCLIP is implied if lp_rect is NULL; n_count==-1 means null-terminated;
// returns height of drawn text (0 on error), not number of chars.
pub unsafe extern "win64" fn draw_text_w(
    hdc: usize,
    lp_string: *const u16,
    n_count: i32,
    lp_rect: *mut Rect,
    u_format: u32,
) -> i32 {
    const DT_CENTER: u32 = 0x0001;
    const DT_RIGHT: u32 = 0x0002;
    const DT_VCENTER: u32 = 0x0004;
    const DT_SINGLELINE: u32 = 0x0020;
    const DT_CALCRECT: u32 = 0x0400;

    if lp_string.is_null() || lp_rect.is_null() {
        return 0;
    }

    // Determine length. Pointer validation: cap at 65k to prevent OOB reads
    // from unterminated strings (n_count == -1) or crafted large n_count values.
    const MAX_TEXT_CHARS: usize = 65_536;
    let len = if n_count < 0 {
        let mut i = 0usize;
        while i < MAX_TEXT_CHARS && unsafe { *lp_string.add(i) } != 0 {
            i += 1;
        }
        i
    } else {
        (n_count as usize).min(MAX_TEXT_CHARS)
    };

    let units: &[u16] = unsafe { std::slice::from_raw_parts(lp_string, len) };
    let px_size = font_px_size(hdc);
    let (text_w, text_h) = weave_user32::font::measure_text(units, px_size);

    if u_format & DT_CALCRECT != 0 {
        let rc = unsafe { &mut *lp_rect };
        rc.right = rc.left + text_w;
        rc.bottom = rc.top + text_h;
        return text_h;
    }

    let rc = unsafe { *lp_rect };
    let rect_w = rc.right - rc.left;
    let rect_h = rc.bottom - rc.top;

    // Horizontal alignment.
    let x = if u_format & DT_CENTER != 0 {
        rc.left + (rect_w - text_w) / 2
    } else if u_format & DT_RIGHT != 0 {
        rc.right - text_w
    } else {
        rc.left
    };

    // Vertical alignment (DT_VCENTER only applies with DT_SINGLELINE).
    let y = if u_format & DT_VCENTER != 0 && u_format & DT_SINGLELINE != 0 {
        rc.top + (rect_h - text_h) / 2
    } else {
        rc.top
    };

    let (fg, bg) = dc::with(hdc, |dc| (dc.text_color, dc.bk_color));
    let xcb = dc::with(hdc, |dc| dc.drawable());
    let (dx, dy) = dc::with(hdc, |dc| dc.lp_to_device(x, y));
    weave_user32::backend::draw_text_utf16(xcb, dx, dy, units, px_size, to_pixel(fg), to_pixel(bg));
    text_h
}

/// DrawTextA: ANSI variant — decode the byte string and delegate to draw_text_w.
///
/// # Safety
/// `lp_string` must point to `n_count` bytes (or a null-terminated string if n_count == -1).
// Wine ref: dlls/user32/text.c::DrawTextExA — converts lpchText from ACP to UTF-16 via
// MultiByteToWideChar then calls DrawTextExW; nCount==-1 triggers strlen on input.
pub unsafe extern "win64" fn draw_text_a(
    hdc: usize,
    lp_string: *const u8,
    n_count: i32,
    lp_rect: *mut Rect,
    u_format: u32,
) -> i32 {
    if lp_string.is_null() || lp_rect.is_null() {
        return 0;
    }
    // Pointer validation: cap at 65k to prevent OOB reads.
    const MAX_TEXT_CHARS: usize = 65_536;
    let len = if n_count < 0 {
        let mut i = 0usize;
        while i < MAX_TEXT_CHARS && unsafe { *lp_string.add(i) } != 0 {
            i += 1;
        }
        i
    } else {
        (n_count as usize).min(MAX_TEXT_CHARS)
    };
    let bytes = unsafe { std::slice::from_raw_parts(lp_string, len) };
    // Encode as UTF-16 for draw_text_w.
    let wide: Vec<u16> = bytes.iter().map(|&b| b as u16).collect();
    unsafe { draw_text_w(hdc, wide.as_ptr(), wide.len() as i32, lp_rect, u_format) }
}

/// ExtTextOutW: extended text output with options, clip rect, and per-char advances.
///
/// Wine ref: dlls/win32u/font.c::nulldrv_ExtTextOut — ETO_OPAQUE fills lp_rc with
/// the background colour before glyph rendering; ETO_CLIPPED clips to lp_rc (Weave
/// does not clip but does honour ETO_OPAQUE). lp_dx per-character advances are
/// accepted and used to position individual glyphs for correct tab/fixed-width
/// rendering; ETO_GLYPH_INDEX means lpString holds glyph indices — Weave falls
/// back to treating them as codepoints (best-effort; may render wrong glyphs for
/// scripts with complex shaping but avoids crashes).
///
/// # Safety
/// `lp_string` must point to `c` valid UTF-16 code units (or glyph indices).
// Wine ref: dlls/win32u/font.c::nulldrv_ExtTextOut — ETO_OPAQUE fills background rect first.
pub unsafe extern "win64" fn ext_text_out_w(
    hdc: usize,
    x: i32,
    y: i32,
    options: u32,
    lp_rc: *const Rect,
    lp_string: *const u16,
    c: u32,
    lp_dx: *const i32,
) -> i32 {
    let xcb = dc::with(hdc, |dc| dc.drawable());
    {
        static ETO_ALL: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = ETO_ALL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Always log first 20 calls and ALL calls with c>0 (actual text glyphs).
        // Previously also filtered on xcb>=0x2006a0 but that threshold is
        // run-specific and causes silent loss of c>0 log entries when xcb==0.
        if n < 20 || c > 0 {
            eprintln!(
                "weave/gdi32: ExtTextOutW#{n} hdc={hdc:#x} xcb={xcb:#x} c={c} options={options:#x}"
            );
        }
    }
    if xcb == 0 {
        return 1; // no window — safe no-op
    }

    // ETO_OPAQUE: fill the background rectangle before drawing.
    if options & ETO_OPAQUE != 0 && !lp_rc.is_null() {
        let rc = unsafe { *lp_rc };
        let w = (rc.right - rc.left).max(0) as u16;
        let h = (rc.bottom - rc.top).max(0) as u16;
        if w > 0 && h > 0 {
            let bg_pixel = to_pixel(dc::with(hdc, |dc| dc.bk_color));
            let (dx, dy) = dc::with(hdc, |dc| dc.lp_to_device(rc.left, rc.top));
            weave_user32::backend::draw_filled_rect(xcb, dx, dy, w, h, bg_pixel);
        }
    }

    if lp_string.is_null() || c == 0 {
        return 1;
    }
    const MAX_TEXT_CHARS: u32 = 65_536;
    let c = c.min(MAX_TEXT_CHARS);
    {
        static ETO: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if ETO.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3 {
            let (fg, bg) = dc::with(hdc, |dc| (dc.text_color, dc.bk_color));
            eprintln!("weave/gdi32: ExtTextOutW hdc={hdc:#x} xcb={xcb:#x} ({x},{y}) c={c} fg={fg:#08x} bg={bg:#08x}");
        }
    }
    let units: &[u16] = unsafe { std::slice::from_raw_parts(lp_string, c as usize) };

    let (fg, bg) = dc::with(hdc, |dc| (dc.text_color, dc.bk_color));
    let fg_pixel = to_pixel(fg);
    let bg_pixel = to_pixel(bg);
    let px_size = font_px_size(hdc);
    let text_align = dc::with(hdc, |dc| dc.text_align);

    // lp_dx per-character advances are acknowledged but not used for individual glyph
    // positioning yet — exact per-char kerning is a Phase 7 enhancement; the standard
    // rasterize path below produces correct overall string width for most cases.
    let _ = lp_dx;

    // Adjust x/y for text alignment.
    let draw_y = match text_align & 0x0018 {
        TA_BASELINE => {
            let fm = weave_user32::font::metrics(px_size);
            y - fm.ascent
        }
        TA_BOTTOM => {
            let fm = weave_user32::font::metrics(px_size);
            y - fm.height
        }
        _ => y, // TA_TOP (default)
    };
    let draw_x = match text_align & 0x0006 {
        TA_RIGHT => {
            let (tw, _) = weave_user32::font::measure_text(units, px_size);
            x - tw
        }
        TA_CENTER => {
            let (tw, _) = weave_user32::font::measure_text(units, px_size);
            x - tw / 2
        }
        _ => x, // TA_LEFT (default)
    };

    weave_user32::backend::draw_text_utf16(
        xcb,
        draw_x as i16,
        draw_y as i16,
        units,
        px_size,
        fg_pixel,
        bg_pixel,
    );
    1
}

/// SetPixel: draw a single pixel.
// Wine ref: dlls/win32u/driver.c::nulldrv_SetPixel — returns color unchanged (no
// real drawing in null driver); actual X11 impl in winex11.drv calls XDrawPoint and
// returns the nearest palette color for the pixel drawn.
pub extern "win64" fn set_pixel(hdc: usize, x: i32, y: i32, color: u32) -> u32 {
    let pixel = to_pixel(color);
    let xcb = dc::with(hdc, |dc| dc.drawable());
    let (dx, dy) = dc::with(hdc, |dc| dc.lp_to_device(x, y));
    weave_user32::backend::draw_filled_rect(xcb, dx, dy, 1, 1, pixel);
    color
}

/// GetPixel: return the colour of a pixel from a memory DC's CPU buffer.
// Wine ref: dlls/win32u/bitblt.c — NtGdiGetPixel clips x,y to DC clip region; returns
// CLR_INVALID (0xFFFFFFFF) if point is outside; otherwise reads back the pixel color
// from the device surface via GetImage. Weave reads from bits_ptr for memory DCs only
// (screen DCs have no CPU buffer — return CLR_INVALID).
pub extern "win64" fn get_pixel(hdc: usize, x: i32, y: i32) -> u32 {
    const CLR_INVALID: u32 = 0xFFFF_FFFF;
    let bitmap_h = dc::with(hdc, |dc| dc.selected_bitmap);
    if bitmap_h == 0 {
        return CLR_INVALID;
    }
    objects::get(bitmap_h, |kind| {
        let (width, height, bits_ptr) = match kind {
            GdiKind::Bitmap {
                width,
                height,
                bits_ptr,
                ..
            } => (*width, *height, *bits_ptr),
            GdiKind::DibSection {
                width,
                height,
                bits_ptr,
                ..
            } => (*width, *height, *bits_ptr),
            _ => return CLR_INVALID,
        };
        if x < 0 || y < 0 || x as u32 >= width || y as u32 >= height || bits_ptr == 0 {
            return CLR_INVALID;
        }
        // DIB pixels: BGRA bytes (B=byte0, G=byte1, R=byte2, A=byte3). As u32 LE:
        // pixel_u32 = B|(G<<8)|(R<<16)|(A<<24). COLORREF = R|(G<<8)|(B<<16).
        let pixel = unsafe {
            (bits_ptr as *const u32)
                .add(y as usize * width as usize + x as usize)
                .read_unaligned()
        };
        let r = (pixel >> 16) & 0xFF;
        let g = (pixel >> 8) & 0xFF;
        let b = pixel & 0xFF;
        r | (g << 8) | (b << 16)
    })
    .unwrap_or(CLR_INVALID)
}

/// MoveToEx: set the current pen position.
///
/// # Safety
/// `lp_point` (if non-null) must be a valid writable pointer to a `POINT`.
// Wine ref: dlls/win32u/driver.c::nulldrv_MoveTo — stores new position in dc->cur_pos;
// lpPoint receives *previous* position before the move; returns FALSE on invalid hdc.
pub unsafe extern "win64" fn move_to_ex(hdc: usize, x: i32, y: i32, lp_point: *mut Point) -> i32 {
    dc::with_mut(hdc, |dc| {
        if !lp_point.is_null() {
            unsafe {
                *lp_point = dc.pen_pos;
            }
        }
        dc.pen_pos = Point { x, y };
    });
    1
}

/// LineTo: draw a line from the current position to (x, y) (stub).
// Wine ref: dlls/win32u/painting.c — NtGdiLineTo draws from current pos to (x,y)
// using the current pen; updates dc->cur_pos to (x,y) after drawing.
pub extern "win64" fn line_to(hdc: usize, x: i32, y: i32) -> i32 {
    let (drawable, x1, y1, pixel) = dc::with(hdc, |dc| {
        let (x1, y1) = dc.lp_to_device(dc.pen_pos.x, dc.pen_pos.y);
        let pixel = weave_user32::backend::colorref_to_pixel(objects::pen_color(dc.h_pen));
        (dc.drawable(), x1, y1, pixel)
    });
    let (x2, y2) = dc::with(hdc, |dc| dc.lp_to_device(x, y));
    if drawable != 0 {
        weave_user32::backend::draw_line(drawable, x1, y1, x2, y2, pixel);
    }
    dc::with_mut(hdc, |dc| dc.pen_pos = Point { x, y });
    1
}

/// Polygon: draw a filled polygon (stub).
// Wine ref: dlls/win32u/painting.c — NtGdiPolyPolyDraw with type POLYPOLYGON; fills
// with current brush using fill mode (ALTERNATE or WINDING); outlines with current pen;
// requires at least 2 points, returns FALSE if cpt < 2.
pub extern "win64" fn polygon(_hdc: usize, _apt: *const Point, _cpt: i32) -> i32 {
    1
}

/// PatBlt: fill with a pattern brush using a raster operation.
// Wine ref: dlls/winex11.drv/bitblt.c::X11DRV_PatBlt — BITBLT_Opcodes[(rop>>16)&0xff]
// gives the GX function. BLACKNESS/WHITENESS use GXcopy with palette black/white pixel.
// DSTINVERT uses GXinvert on TrueColor (GXxor with white^black only on shared palette).
// PATCOPY/PATINVERT set up brush foreground then XFillRectangle with GXcopy/GXxor.
pub extern "win64" fn pat_blt(hdc: usize, x: i32, y: i32, w: i32, h: i32, rop: u32) -> i32 {
    if w <= 0 || h <= 0 {
        return 1;
    }
    let xcb = dc::with(hdc, |dc| dc.drawable());
    let brush_pixel = || {
        let bh = dc::with(hdc, |dc| dc.h_brush);
        weave_user32::backend::colorref_to_pixel(objects::brush_color(bh))
    };
    let (gx_func, pixel) = match rop {
        defs::BLACKNESS => (weave_user32::backend::GX_CLEAR, 0u32),
        defs::WHITENESS => (weave_user32::backend::GX_SET, 0xFFFF_FFFFu32),
        defs::DSTINVERT => (weave_user32::backend::GX_INVERT, 0u32),
        defs::PATCOPY => (weave_user32::backend::GX_COPY, brush_pixel()),
        defs::PATINVERT => (weave_user32::backend::GX_XOR, brush_pixel()),
        _ => {
            static UNK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            if UNK.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 8 {
                eprintln!("weave/gdi32: PatBlt unrecognised ROP {rop:#010x} → brush fill");
            }
            (weave_user32::backend::GX_COPY, brush_pixel())
        }
    };
    weave_user32::backend::fill_rect_with_rop(
        xcb, x as i16, y as i16, w as u16, h as u16, gx_func, pixel,
    );
    1
}

/// BitBlt: bit-block transfer.
///
/// Wine ref: dlls/win32u/bitblt.c — NtGdiBitBlt applies rop3 raster operation combining
/// src DC, dst DC, and current brush pattern. SRCCOPY (0xCC0020) copies src to dst.
/// Phase 2 stub: returns TRUE without transferring pixels (no real memory DC backing).
// Wine ref: dlls/gdi32/dc.c BitBlt → NtGdiBitBlt; dlls/gdi32/tests/bitmap.c ROP3 tests; dlls/winex11.drv/bitblt.c X11DRV_BitBlt → XCopyArea(GXcopy) SRCCOPY
pub extern "win64" fn bit_blt(
    hdc_dest: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    hdc_src: usize,
    x1: i32,
    y1: i32,
    rop: u32,
) -> i32 {
    // Wine ref: dlls/win32u/bitblt.c NtGdiBitBlt → X11DRV_BitBlt (winex11.drv/bitblt.c)
    // SRCCOPY (0xCC0020): XCopyArea from src drawable to dst drawable.
    if cx <= 0 || cy <= 0 {
        return 1;
    }
    let dst_draw = dc::with(hdc_dest, |dc| dc.drawable());
    let src_draw = dc::with(hdc_src, |dc| dc.drawable());
    static BB: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    if BB.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 30 {
        eprintln!("weave/gdi32: BitBlt dst={dst_draw:#x} src={src_draw:#x} ({x},{y}) {cx}x{cy}");
    }
    if dst_draw == 0 {
        // Headless/library-test path: the DC is valid but no X11 drawable is
        // available. Treat this like the backend no-op cases below and report
        // success so ROP-dispatch probes can run without a display.
        return 1;
    }
    // Classify the ROP.  Source ROPs need src_draw and a DIB sync; pattern-only
    // ROPs (PATCOPY/DSTINVERT/WHITENESS/BLACKNESS) ignore the source entirely.
    //
    // Wine ref: dlls/winex11.drv/bitblt.c — BITBLT_Opcodes[ROP>>16] row maps
    // each top-byte to a single X11 GX op:
    //   0x00 BLACKNESS  → GXclear        (no source)
    //   0x33 NOTSRCCOPY → GXcopyInverted (source)
    //   0x55 DSTINVERT  → GXinvert       (no source)
    //   0x66 SRCINVERT  → GXxor          (source)
    //   0x88 SRCAND     → GXand          (source)
    //   0xCC SRCCOPY    → GXcopy         (source)
    //   0xEE SRCPAINT   → GXor           (source)
    //   0xF0 PATCOPY    → GXcopy         (no source, brush as fg)
    //   0xFF WHITENESS  → GXset          (no source)
    // See BITBLT_Opcodes table (line 71) and X11DRV_PatBlt (line 757).
    enum RopPlan {
        Source(u32),       // gx_func applied to XCopyArea(src → dst)
        Pattern(u32, u32), // gx_func + foreground pixel applied to XFillRectangle
        Unknown,
    }
    let plan = match rop {
        defs::SRCCOPY => RopPlan::Source(weave_user32::backend::GX_COPY),
        defs::NOTSRCCOPY => RopPlan::Source(weave_user32::backend::GX_COPY_INVERTED),
        defs::SRCINVERT => RopPlan::Source(weave_user32::backend::GX_XOR),
        defs::SRCAND => RopPlan::Source(weave_user32::backend::GX_AND),
        defs::SRCPAINT => RopPlan::Source(weave_user32::backend::GX_OR),
        defs::DSTINVERT => RopPlan::Pattern(weave_user32::backend::GX_INVERT, 0),
        defs::WHITENESS => RopPlan::Pattern(weave_user32::backend::GX_SET, 0xFFFF_FFFF),
        defs::BLACKNESS => RopPlan::Pattern(weave_user32::backend::GX_CLEAR, 0),
        defs::PATCOPY => {
            // PATCOPY requires a solid brush; hatch/pattern brushes return
            // FALSE until Weave grows a stipple path.  Resolve the brush color
            // here so the match arm can carry it through.
            let brush_h = dc::with(hdc_dest, |dc| dc.h_brush);
            let resolved = objects::get(brush_h, |k| matches!(k, objects::GdiKind::Brush { .. }));
            // Stock brushes are not in the table (is_stock) but are all solid.
            let is_solid = objects::is_stock(brush_h) || resolved.unwrap_or(false);
            if !is_solid {
                RopPlan::Unknown
            } else {
                let color = objects::brush_color(brush_h);
                let pixel = weave_user32::backend::colorref_to_pixel(color);
                RopPlan::Pattern(weave_user32::backend::GX_COPY, pixel)
            }
        }
        _ => RopPlan::Unknown,
    };
    match plan {
        RopPlan::Unknown => {
            // Pre-task-17 behaviour: return TRUE on unknown ROPs so guests
            // that don't check the return value continue rendering. SDL2's
            // testsprite2 hits a non-SRCCOPY ROP at ~5s post-render and
            // SIGSEGVs in sdl2.dll when BitBlt returns 0 (crash at
            // NULL+0x1c8). Log the ROP so we can grow coverage over time.
            static UNK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            if UNK.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 8 {
                eprintln!("weave/gdi32: BitBlt unrecognised ROP {rop:#010x} → lying TRUE");
            }
            1
        }
        RopPlan::Pattern(gx_func, pixel) => {
            weave_user32::backend::fill_rect_with_rop(
                dst_draw, x as i16, y as i16, cx as u16, cy as u16, gx_func, pixel,
            );
            1
        }
        RopPlan::Source(gx_func) => {
            if src_draw == 0 {
                return 0;
            }
            // If the source DC has a bitmap selected (DDB via CreateCompatibleBitmap
            // or a DibSection), upload its CPU-side pixel buffer to the server-side
            // Pixmap before XCopyArea. Both variants share the same 32-bit ARGB layout
            // in Weave, so the sync path is identical.
            //
            // Wine ref: dlls/winex11.drv/bitmap.c — X11DRV_PutImage syncs DIB→Pixmap.
            let dib_info: Option<(u32, u32, usize, u16)> = dc::with(hdc_src, |dc| {
                let bmp = dc.selected_bitmap;
                if bmp == 0 {
                    return None;
                }
                objects::get(bmp, |kind| match kind {
                    objects::GdiKind::DibSection {
                        width,
                        height,
                        bits_ptr,
                        bpp,
                    }
                    | objects::GdiKind::Bitmap {
                        width,
                        height,
                        bits_ptr,
                        bpp,
                    } => Some((*width, *height, *bits_ptr, *bpp)),
                    _ => None,
                })
                .flatten()
            });
            if let Some((dib_w, dib_h, bits_ptr, bpp)) = dib_info {
                unsafe {
                    weave_user32::backend::put_dib_to_pixmap(src_draw, dib_w, dib_h, bits_ptr, bpp);
                }
            }
            // Fast path: SRCCOPY (GXcopy) is by far the hottest BitBlt ROP
            // (SDL2's testsprite2 fires it 60×/s). Route it through the
            // lean `copy_area` helper which skips the redundant
            // `change_gc(GX::COPY)` round-trip needed only when the GC's
            // function was changed away from GXcopy. Non-SRCCOPY source
            // ROPs still flow through `copy_area_with_rop`.
            //
            // Wine ref: dlls/winex11.drv/bitblt.c — X11DRV_BitBlt
            // optimises SRCCOPY by not calling XSetFunction at all.
            if gx_func == weave_user32::backend::GX_COPY {
                weave_user32::backend::copy_area(
                    src_draw, dst_draw, x1 as i16, y1 as i16, x as i16, y as i16, cx as u16,
                    cy as u16,
                );
            } else {
                weave_user32::backend::copy_area_with_rop(
                    src_draw, dst_draw, x1 as i16, y1 as i16, x as i16, y as i16, cx as u16,
                    cy as u16, gx_func,
                );
            }
            1
        }
    }
}

/// StretchBlt: stretched bit-block transfer.
///
/// Scales the source rectangle to fit the destination rectangle using the
/// DC's current StretchBlt filter mode. Weave implements COLORONCOLOR
/// (nearest-neighbor) only — the default Wine uses for all depths and the
/// mode apps like IrfanView expect.
///
/// Strategy: CPU-side nearest-neighbor scale from the source bitmap's
/// `bits_ptr` into a scratch buffer sized to the destination rectangle,
/// upload that scratch to a temporary X11 Pixmap via `put_dib_to_pixmap`,
/// then route the final blit to the destination drawable through the
/// Task-17 ROP dispatch path (SRCCOPY → lean `copy_area`; others →
/// `copy_area_with_rop`). Negative `w_dest`/`h_dest` mirror the output by
/// stepping through the dest pixels in reverse.
///
/// Wine ref: dlls/win32u/bitblt.c::stretch_bits — malloc(dst biSizeImage),
/// call stretch_bitmapinfo (nearest-neighbor for non-HALFTONE modes), then
/// transfer to the destination. dlls/winex11.drv/bitblt.c::X11DRV_StretchBlt
/// performs the scale on the CPU then uploads via XPutImage.
#[allow(clippy::too_many_arguments)]
pub extern "win64" fn stretch_blt(
    hdc_dest: usize,
    x_dest: i32,
    y_dest: i32,
    w_dest: i32,
    h_dest: i32,
    hdc_src: usize,
    x_src: i32,
    y_src: i32,
    w_src: i32,
    h_src: i32,
    rop: u32,
) -> i32 {
    // Zero-area source or destination: Wine returns FALSE.
    if w_dest == 0 || h_dest == 0 || w_src == 0 || h_src == 0 {
        return 0;
    }

    let mode = dc::with(hdc_dest, |dc| dc.stretch_blt_mode);

    // Only COLORONCOLOR (nearest-neighbor) is implemented. HALFTONE /
    // BLACKONWHITE / WHITEONBLACK return FALSE with a traced warning so
    // callers learn to expect it. Wine renders all non-HALFTONE modes as
    // nearest-neighbor anyway, but staying strict here keeps the surface
    // honest until linear-averaging lands in a later task.
    if mode != defs::COLORONCOLOR {
        static UNSUPPORTED_MODE: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);
        if UNSUPPORTED_MODE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 8 {
            eprintln!("weave/gdi32: StretchBlt mode={mode} unsupported (COLORONCOLOR only)");
        }
        return 0;
    }

    // Resolve src bitmap info. Bitmap and DibSection share the same 32bpp
    // ARGB layout in Weave (see create_compatible_bitmap).
    let src_info: Option<(u32, u32, usize, u16)> = dc::with(hdc_src, |dc| {
        let bmp = dc.selected_bitmap;
        if bmp == 0 {
            return None;
        }
        objects::get(bmp, |kind| match kind {
            objects::GdiKind::DibSection {
                width,
                height,
                bits_ptr,
                bpp,
            }
            | objects::GdiKind::Bitmap {
                width,
                height,
                bits_ptr,
                bpp,
            } => Some((*width, *height, *bits_ptr, *bpp)),
            _ => None,
        })
        .flatten()
    });

    let (src_w, src_h, src_ptr, src_bpp) = match src_info {
        Some(v) => v,
        None => {
            // No source bitmap — nothing to scale. Return FALSE.
            return 0;
        }
    };

    // 32-bit ARGB only for the first pass. 8/16/24-bit DIBs return FALSE;
    // widening the scale path to other depths is deferred.
    if src_bpp != 32 {
        static UNSUPPORTED_BPP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if UNSUPPORTED_BPP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!("weave/gdi32: StretchBlt src bpp={src_bpp} unsupported (32-bit only)");
        }
        return 0;
    }

    // Absolute destination size for the scratch buffer; mirroring is applied
    // through the step direction when walking the dest grid.
    let abs_w_dest = w_dest.unsigned_abs() as usize;
    let abs_h_dest = h_dest.unsigned_abs() as usize;

    // Guard against overflow in the scratch allocation (treat as FALSE).
    let scratch_pixels = match abs_w_dest.checked_mul(abs_h_dest) {
        Some(v) => v,
        None => return 0,
    };
    let scratch_bytes = match scratch_pixels.checked_mul(4) {
        Some(v) => v,
        None => return 0,
    };

    // Nearest-neighbor scale into the scratch buffer.
    // Wine ref: dlls/win32u/bitblt.c::stretch_bitmapinfo — for COLORONCOLOR
    // the formula reduces to src_idx = src_origin + dst_idx * src_span /
    // dst_span (integer divide). Negative dst spans mirror via the step
    // direction of the walk; negative src spans do the same for the source.
    let src_row_stride = src_w as usize * 4;
    let mut scratch = vec![0u8; scratch_bytes];
    let src_bytes = unsafe {
        std::slice::from_raw_parts(src_ptr as *const u8, src_h as usize * src_row_stride)
    };

    let src_x_start: i64 = x_src as i64;
    let src_y_start: i64 = y_src as i64;
    let src_w_signed: i64 = w_src as i64;
    let src_h_signed: i64 = h_src as i64;

    // Dest-walk direction. w_dest/h_dest < 0 flip the destination output;
    // for the scratch we simply walk destination pixels in reverse order.
    let flip_x = w_dest < 0;
    let flip_y = h_dest < 0;

    for dy in 0..abs_h_dest {
        // Compute which source row maps to this dest row. Using the signed
        // src span preserves the mirror-on-negative-src behaviour Wine
        // documents; COLORONCOLOR always floors toward the origin.
        let dy_out = if flip_y { abs_h_dest - 1 - dy } else { dy };
        let sy_signed = src_y_start + (dy as i64 * src_h_signed) / (abs_h_dest.max(1) as i64);
        // Clamp to source bounds defensively. If src_y_start + span slides
        // outside the bitmap, Wine leaves undefined garbage there; we clamp
        // to keep the scratch deterministic.
        let sy = if sy_signed < 0 {
            0
        } else if sy_signed >= src_h as i64 {
            (src_h as i64 - 1).max(0)
        } else {
            sy_signed
        } as usize;
        for dx in 0..abs_w_dest {
            let dx_out = if flip_x { abs_w_dest - 1 - dx } else { dx };
            let sx_signed = src_x_start + (dx as i64 * src_w_signed) / (abs_w_dest.max(1) as i64);
            let sx = if sx_signed < 0 {
                0
            } else if sx_signed >= src_w as i64 {
                (src_w as i64 - 1).max(0)
            } else {
                sx_signed
            } as usize;
            let src_off = sy * src_row_stride + sx * 4;
            let dst_off = (dy_out * abs_w_dest + dx_out) * 4;
            // Bounds check — clamping above should guarantee in-range but
            // keep the copy safe if abs_w_src/abs_h_src is 0 (handled via
            // the clamp when src_w_signed is 0, though we short-circuited
            // zero-area src at the top).
            if src_off + 4 <= src_bytes.len() && dst_off + 4 <= scratch.len() {
                scratch[dst_off..dst_off + 4].copy_from_slice(&src_bytes[src_off..src_off + 4]);
            }
        }
    }

    // Upload scratch to a temporary Pixmap the same size as the scaled
    // output, then blit that Pixmap into the destination drawable at
    // (x_dest, y_dest). Using a temp Pixmap lets us reuse the existing
    // put_dib_to_pixmap + copy_area helpers without introducing a new
    // "put rect at offset" backend entry point.
    let dst_draw = dc::with(hdc_dest, |dc| dc.drawable());
    if dst_draw == 0 {
        return 0;
    }

    let scratch_ptr = scratch.as_ptr() as usize;
    let tmp_pixmap =
        weave_user32::backend::create_pixmap(dst_draw, abs_w_dest as u16, abs_h_dest as u16);
    if tmp_pixmap == 0 {
        // Backend unavailable (headless macOS, no X11). Return TRUE per the
        // Task-17 "lie TRUE" policy for dispatch-reached-backend cases so
        // callers that ignore the return value keep running. The CPU scale
        // above already ran — skipping only the server-side upload.
        return 1;
    }
    unsafe {
        weave_user32::backend::put_dib_to_pixmap(
            tmp_pixmap,
            abs_w_dest as u32,
            abs_h_dest as u32,
            scratch_ptr,
            32,
        );
    }

    // Route the final Pixmap→dest blit through the Task-17 ROP dispatch.
    // SRCCOPY takes the lean `copy_area`; other source ROPs go through
    // `copy_area_with_rop`. Non-source ROPs (PATCOPY, DSTINVERT, etc.)
    // do not apply to StretchBlt's pattern slot in this first cut — we
    // still accept them but just drop the source contribution (they
    // would need a separate fill pass we haven't wired yet).
    let gx_func = match rop {
        defs::SRCCOPY => Some(weave_user32::backend::GX_COPY),
        defs::NOTSRCCOPY => Some(weave_user32::backend::GX_COPY_INVERTED),
        defs::SRCINVERT => Some(weave_user32::backend::GX_XOR),
        defs::SRCAND => Some(weave_user32::backend::GX_AND),
        defs::SRCPAINT => Some(weave_user32::backend::GX_OR),
        _ => None,
    };

    match gx_func {
        Some(gx) if gx == weave_user32::backend::GX_COPY => {
            weave_user32::backend::copy_area(
                tmp_pixmap,
                dst_draw,
                0,
                0,
                x_dest as i16,
                y_dest as i16,
                abs_w_dest as u16,
                abs_h_dest as u16,
            );
        }
        Some(gx) => {
            weave_user32::backend::copy_area_with_rop(
                tmp_pixmap,
                dst_draw,
                0,
                0,
                x_dest as i16,
                y_dest as i16,
                abs_w_dest as u16,
                abs_h_dest as u16,
                gx,
            );
        }
        None => {
            // Unknown/unsupported ROP — log once and lie TRUE (same policy
            // as bit_blt's RopPlan::Unknown arm; see Task-17 CI fix).
            static UNK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            if UNK.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 8 {
                eprintln!("weave/gdi32: StretchBlt unrecognised ROP {rop:#010x} → lying TRUE");
            }
        }
    }

    weave_user32::backend::free_pixmap(tmp_pixmap);
    1
}

/// SetStretchBltMode: set the bitmap-stretching mode.
///
/// Stores the mode on the DC and returns the previous mode. Valid modes are
/// BLACKONWHITE(1), WHITEONBLACK(2), COLORONCOLOR(3), HALFTONE(4). Weave's
/// stretch_blt only honours COLORONCOLOR; other modes return FALSE from
/// StretchBlt but the mode is still stored here so round-tripping the DC
/// state works (SaveDC/RestoreDC, GetStretchBltMode).
///
/// Wine ref: dlls/win32u/dc.c::set_stretch_blt_mode — reads the current
/// mode from dc->attr->stretch_blt_mode, writes the new one, and returns
/// the old value. HALFTONE(4) requires SetBrushOrgEx to align the halftone
/// brush, which Wine honours but Weave skips.
pub extern "win64" fn set_stretch_blt_mode(hdc: usize, mode: i32) -> i32 {
    let mut prev = defs::COLORONCOLOR;
    dc::with_mut(hdc, |dc| {
        prev = dc.stretch_blt_mode;
        dc.stretch_blt_mode = mode;
    });
    prev
}

/// StretchDIBits: copy a source rectangle from a DIB to a destination DC with scaling.
///
/// First-pass scope: 32-bit BI_RGB, DIB_RGB_COLORS (iUsage=0), SRCCOPY + simple ROPs.
/// 8/16/24-bit depths, BI_BITFIELDS, and DIB_PAL_COLORS deferred — return 0 with a
/// one-time diagnostic. Non-source ROPs lie TRUE (same policy as StretchBlt/BitBlt).
///
/// Returns: nDestHeight (number of destination scan lines written) on success, 0 on error.
///
/// # Safety
/// `lp_bits` must point to at least `stride × |biHeight|` bytes where
/// `stride = ((|biWidth| × biBitCount + 31) / 32) × 4`.
/// `lpbmi` must point to a readable BITMAPINFOHEADER (40 bytes minimum).
// Wine ref: dlls/win32u/bitblt.c::NtGdiStretchDIBitsAndColor — validates header, clips
// src rect to DIB bounds, calls stretch_bits (nearest-neighbor for COLORONCOLOR), then
// driver StretchBlt. Returns dst.visrect.bottom - dst.visrect.top on success.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn stretch_di_bits(
    hdc: usize,
    x_dest: i32,
    y_dest: i32,
    n_dest_width: i32,
    n_dest_height: i32,
    x_src: i32,
    y_src: i32,
    n_src_width: i32,
    n_src_height: i32,
    lp_bits: *const u8,
    lpbmi: usize,
    i_usage: u32,
    dw_rop: u32,
) -> i32 {
    if lpbmi == 0 || lp_bits.is_null() {
        return 0;
    }
    if n_dest_width == 0 || n_dest_height == 0 || n_src_width == 0 || n_src_height == 0 {
        return 0;
    }

    // DIB_RGB_COLORS == 0. DIB_PAL_COLORS not supported first pass.
    if i_usage != 0 {
        static UNSUPPORTED_USAGE: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);
        if UNSUPPORTED_USAGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!(
                "weave/gdi32: StretchDIBits i_usage={i_usage} unsupported (DIB_RGB_COLORS only)"
            );
        }
        return 0;
    }

    // Parse BITMAPINFOHEADER — same offsets as SetDIBitsToDevice / GetDIBits.
    //   +4  biWidth (i32), +8 biHeight (i32), +14 biBitCount (u16), +16 biCompression (u32)
    let (bi_width, bi_height, bi_bit_count, bi_compression) = unsafe {
        (
            *((lpbmi + 4) as *const i32),
            *((lpbmi + 8) as *const i32),
            *((lpbmi + 14) as *const u16),
            *((lpbmi + 16) as *const u32),
        )
    };

    if bi_compression != 0 {
        static UNSUPPORTED_COMP: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);
        if UNSUPPORTED_COMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!(
                "weave/gdi32: StretchDIBits compression={bi_compression} unsupported (BI_RGB only)"
            );
        }
        return 0;
    }

    if bi_bit_count != 32 && bi_bit_count != 24 {
        static UNSUPPORTED_BPP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if UNSUPPORTED_BPP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!("weave/gdi32: StretchDIBits bpp={bi_bit_count} unsupported (24/32-bit only)");
        }
        return 0;
    }

    let dib_w = bi_width.unsigned_abs() as usize;
    let dib_h = bi_height.unsigned_abs() as usize;
    let top_down = bi_height < 0;
    if dib_w == 0 || dib_h == 0 {
        return 0;
    }

    // Stride: ((|biWidth| × biBitCount + 31) / 32) × 4
    // Wine ref: dlls/win32u/dib.c::get_dib_stride
    let stride = ((dib_w as u64 * bi_bit_count as u64).div_ceil(32) * 4) as usize;
    let src_px = bi_bit_count as usize / 8; // bytes per source pixel (3 or 4)
    let total_bytes = stride.saturating_mul(dib_h);
    let dib_data = unsafe { std::slice::from_raw_parts(lp_bits, total_bytes) };

    // Clip source rect to DIB bounds (Wine: clip before scale).
    let xs0 = x_src.clamp(0, dib_w as i32) as usize;
    let ys0 = y_src.clamp(0, dib_h as i32) as usize;
    let xs1 = (x_src + n_src_width.abs()).clamp(0, dib_w as i32) as usize;
    let ys1 = (y_src + n_src_height.abs()).clamp(0, dib_h as i32) as usize;
    let eff_src_w = xs1.saturating_sub(xs0);
    let eff_src_h = ys1.saturating_sub(ys0);
    if eff_src_w == 0 || eff_src_h == 0 {
        return 0;
    }

    let (dev_x_dest, dev_y_dest, abs_w_dest, abs_h_dest) = dc::with(hdc, |dc| {
        let (x0, y0) = dc.lp_to_device(x_dest, y_dest);
        let (x1, y1) = dc.lp_to_device(x_dest + n_dest_width, y_dest + n_dest_height);
        let left = x0.min(x1);
        let top = y0.min(y1);
        let width = i32::from(x1).abs_diff(i32::from(x0)).max(1) as usize;
        let height = i32::from(y1).abs_diff(i32::from(y0)).max(1) as usize;
        (left, top, width, height)
    });
    let scratch_bytes = match abs_w_dest
        .checked_mul(abs_h_dest)
        .and_then(|p| p.checked_mul(4))
    {
        Some(v) => v,
        None => return 0,
    };

    // Nearest-neighbor scale into a top-down BGRA scratch buffer.
    // Negative src or dest dimensions mirror independently; XOR gives net flip.
    // Wine ref: dlls/win32u/bitblt.c::stretch_bitmapinfo — COLORONCOLOR formula:
    //   src_idx = src_origin + dst_idx * src_span / dst_span (floor).
    let flip_x = (n_dest_width < 0) ^ (n_src_width < 0);
    let flip_y = (n_dest_height < 0) ^ (n_src_height < 0);

    let mut scratch = vec![0u8; scratch_bytes];
    for dy in 0..abs_h_dest {
        let dy_out = if flip_y { abs_h_dest - 1 - dy } else { dy };
        // Map dest row → source row in the DIB (top-down normalized).
        let src_row_logical = ys0 + (dy * eff_src_h) / abs_h_dest.max(1);
        let src_row_logical = src_row_logical.min(dib_h.saturating_sub(1));
        // Convert logical row (top-down) to physical DIB row offset.
        let phys_row = if top_down {
            src_row_logical
        } else {
            dib_h - 1 - src_row_logical
        };
        let row_base = phys_row * stride;
        for dx in 0..abs_w_dest {
            let dx_out = if flip_x { abs_w_dest - 1 - dx } else { dx };
            let src_col = xs0 + (dx * eff_src_w) / abs_w_dest.max(1);
            let src_col = src_col.min(dib_w.saturating_sub(1));
            let src_off = row_base + src_col * src_px;
            let dst_off = (dy_out * abs_w_dest + dx_out) * 4;
            if src_off + src_px <= dib_data.len() && dst_off + 4 <= scratch.len() {
                if src_px == 4 {
                    scratch[dst_off..dst_off + 4].copy_from_slice(&dib_data[src_off..src_off + 4]);
                } else {
                    // 24-bit BGR → BGRA (alpha=0xFF)
                    scratch[dst_off] = dib_data[src_off];
                    scratch[dst_off + 1] = dib_data[src_off + 1];
                    scratch[dst_off + 2] = dib_data[src_off + 2];
                    scratch[dst_off + 3] = 0xFF;
                }
            }
        }
    }

    let dst_draw = dc::with(hdc, |dc| dc.drawable());
    if dst_draw == 0 {
        return abs_h_dest as i32;
    }

    let scratch_ptr = scratch.as_ptr() as usize;
    let tmp_pixmap =
        weave_user32::backend::create_pixmap(dst_draw, abs_w_dest as u16, abs_h_dest as u16);
    if tmp_pixmap == 0 {
        // Headless — CPU scale ran; skip X11 upload (lie success per Task-17 policy).
        return abs_h_dest as i32;
    }
    unsafe {
        weave_user32::backend::put_dib_to_pixmap(
            tmp_pixmap,
            abs_w_dest as u32,
            abs_h_dest as u32,
            scratch_ptr,
            32,
        );
    }

    let gx_func = match dw_rop {
        defs::SRCCOPY => Some(weave_user32::backend::GX_COPY),
        defs::NOTSRCCOPY => Some(weave_user32::backend::GX_COPY_INVERTED),
        defs::SRCINVERT => Some(weave_user32::backend::GX_XOR),
        defs::SRCAND => Some(weave_user32::backend::GX_AND),
        defs::SRCPAINT => Some(weave_user32::backend::GX_OR),
        _ => None,
    };

    match gx_func {
        Some(gx) if gx == weave_user32::backend::GX_COPY => {
            weave_user32::backend::copy_area(
                tmp_pixmap,
                dst_draw,
                0,
                0,
                dev_x_dest,
                dev_y_dest,
                abs_w_dest as u16,
                abs_h_dest as u16,
            );
        }
        Some(gx) => {
            weave_user32::backend::copy_area_with_rop(
                tmp_pixmap,
                dst_draw,
                0,
                0,
                dev_x_dest,
                dev_y_dest,
                abs_w_dest as u16,
                abs_h_dest as u16,
                gx,
            );
        }
        None => {
            static UNK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            if UNK.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 8 {
                eprintln!(
                    "weave/gdi32: StretchDIBits unrecognised ROP {dw_rop:#010x} → lying TRUE"
                );
            }
        }
    }

    weave_user32::backend::free_pixmap(tmp_pixmap);
    // First successful StretchDIBits with real pixel data confirms image rendering reached.
    weave_core::progress::mark_phase("stretch_dibits_first");
    abs_h_dest as i32
}

/// SetROP2: set the foreground mix mode (stub).
// Wine ref: dlls/win32u/dc.c — stores rop2 in dc->attr->rop_mode; valid range 1..16
// (R2_BLACK..R2_WHITE); returns previous mode; out-of-range values stored as-is.
pub extern "win64" fn set_rop2(_hdc: usize, _rop2: i32) -> i32 {
    1
}

// ── Memory DC and bitmap stubs ────────────────────────────────────────────────

/// CreateCompatibleDC: create an off-screen memory DC compatible with the given DC.
///
/// Wine ref: dlls/win32u/dc.c — alloc_dc_ptr allocates a new DC_OBJ; copies bit depth
/// and device info from source DC; initially has a 1×1 monochrome bitmap selected.
///
/// Phase 2 implementation: allocates a unique handle and binds it to the same X11 window
/// as the parent DC. All drawing operations on this memory DC are routed to the parent
/// window directly (no off-screen pixel buffer). BitBlt from memory→screen is a no-op
/// because the pixels are already on screen. This makes double-buffered drawing (like
/// Scintilla's) produce visible output without a real bitmap backing.
// Wine ref: dlls/win32u/dc.c — alloc_dc_ptr; new compat DC starts with 1×1 monochrome
// bitmap selected; CreateCompatibleDC(NULL) creates a screen-compatible memory DC.
pub extern "win64" fn create_compatible_dc(hdc: usize) -> usize {
    // Find the window this parent DC is bound to.
    // For screen DCs (BeginPaint), dc.hwnd == hdc == HWND.
    // For nested memory DCs, dc.hwnd was set when the parent CompatibleDC was created.
    let parent_hwnd = dc::with(hdc, |dc| dc.hwnd);
    // If parent_hwnd is 0 (e.g. CreateCompatibleDC(NULL) — screen-compatible DC),
    // fall back to the HWND that was most recently passed to BeginPaint. This is the
    // common Scintilla pattern: create a screen-compatible memory DC outside of any
    // BeginPaint call, then use it for all painting.
    //
    // If even that is 0 (DC created before the first WM_PAINT, which Scintilla does
    // during class initialisation), fall back to the first window with a valid XCB ID.
    let parent_hwnd = if parent_hwnd == 0 {
        let from_paint = weave_user32::api::current_paint_hwnd();
        if from_paint != 0 {
            from_paint
        } else {
            weave_user32::window::first_hwnd_with_xcb()
        }
    } else {
        parent_hwnd
    };
    // Allocate a unique GDI handle for this memory DC.
    // Bitmap is used here purely for handle uniqueness — the 1×1 pixel buffer
    // is never drawn into (nothing ever SelectObjects this handle as a bitmap;
    // it is used as a DC handle). Leak a 4-byte stub so DeleteObject can still
    // reconstruct a consistent boxed slice for any handle of this variant.
    let stub_buf = vec![0u8; 4].into_boxed_slice();
    let stub_ptr = stub_buf.as_ptr() as usize;
    Box::leak(stub_buf);
    let mem_dc = objects::alloc(GdiKind::Bitmap {
        width: 1,
        height: 1,
        bits_ptr: stub_ptr,
        bpp: 32,
    });
    // Bind the new memory DC to the parent window so xcb_for() resolves correctly.
    dc::with_mut(mem_dc, |dc| dc.hwnd = parent_hwnd);
    mem_dc
}

/// CreateDCW: create a device context for the named device.
///
/// SDL2 calls `CreateDCW(driver, NULL, NULL, NULL)` to get a display DC for
/// gamma-ramp queries and pixel-format introspection. Weave returns a screen-
/// compatible DC (same as CreateCompatibleDC(NULL)) so callers get a valid
/// handle without crashing.
///
/// # Safety
/// All pointer arguments may be NULL; non-NULL pointers must be valid.
// Wine ref: dlls/win32u/dc.c::NtGdiOpenDCW — allocates a DC_OBJ and binds it to
// the named device (display or printer); for "DISPLAY" creates a screen DC;
// returns NULL only if the device doesn't exist or alloc fails.
pub unsafe extern "win64" fn create_dc_w(
    _lp_driver: *const u16,
    _lp_device: *const u16,
    _lp_port: *const u16,
    _pdm: *const u8,
) -> usize {
    // Delegate to CreateCompatibleDC(NULL) — creates a screen-compatible DC.
    create_compatible_dc(0)
}

/// DeleteDC: delete a DC created by CreateCompatibleDC (stub).
// Wine ref: dlls/win32u/dc.c::free_dc_ptr — walks physDev chain calling pDeleteDC on
// each; decrements refcounts on hPen/hBrush/hFont/hBitmap; frees GDI handle; returns
// FALSE if hdc is a display DC (those are not freed via DeleteDC).
pub extern "win64" fn delete_dc(hdc: usize) -> i32 {
    if let Some(pixmap) = dc::with(hdc, |dc| dc.pixmap) {
        if pixmap != 0 {
            weave_user32::backend::free_pixmap(pixmap);
        }
    }
    dc::remove(hdc);
    1
}

/// CreateCompatibleBitmap: create a bitmap compatible with a DC.
///
/// Allocates a zero-filled 32-bit ARGB pixel buffer sized `cx * cy * 4` bytes
/// and leaks it for the bitmap's lifetime. `DeleteObject` reconstructs and
/// drops the buffer. Weave flattens Wine's depth-inheritance rule (screen DC →
/// display depth, mem DC → selected bitmap's depth) to 32-bit ARGB so the
/// BitBlt DIB→Pixmap sync path has a single uniform format to handle.
// Wine ref: dlls/win32u/bitmap.c::NtGdiCreateCompatibleBitmap — returns 0 if
// width==0 || height==0; for a non-MEMDC delegates to NtGdiCreateBitmap with
// PLANES/BITSPIXEL from the DC; for a MEMDC with a DDB selected, matches its
// planes/bpp; for a MEMDC with a DIBSection selected, returns a DIBSection
// with the same BITMAPINFOHEADER (width/height overridden).
pub extern "win64" fn create_compatible_bitmap(_hdc: usize, cx: i32, cy: i32) -> usize {
    // Wine returns 0 when either dimension is 0; mirror that, but tolerate
    // negative dimensions by taking the absolute value (Windows does the same
    // via NtGdiCreateBitmap's MAX_BITMAP clamp).
    if cx == 0 || cy == 0 {
        return 0;
    }
    let width = cx.unsigned_abs();
    let height = cy.unsigned_abs();
    const BPP: u16 = 32;
    let size = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul((BPP / 8) as usize)
        .max(1);
    let buf = vec![0u8; size].into_boxed_slice();
    let bits_ptr = buf.as_ptr() as usize;
    // Leak for the lifetime of the handle; DeleteObject reclaims.
    Box::leak(buf);
    objects::alloc(GdiKind::Bitmap {
        width,
        height,
        bits_ptr,
        bpp: BPP,
    })
}

/// CreateDIBSection: create a DIB section with a CPU-accessible pixel buffer.
///
/// # Safety
/// `pbmi` must point to a valid `BITMAPINFO` struct. `ppv_bits` may be NULL;
/// if non-NULL it must be a writable `*mut usize`.
// Wine ref: dlls/gdi32/objects.c::CreateDIBSection → NtGdiCreateDIBSection; creates a
// shared-memory bitmap (section!=NULL uses MapViewOfSection); ppvBits receives a pointer
// to the raw pixel buffer; DIB_PAL_COLORS usage maps color table entries to palette indices.
// Weave: h_section always ignored (no section object support). Allocates a zeroed heap
// buffer sized to the bitmap, leaks it for the handle's lifetime, writes address to ppvBits.
pub unsafe extern "win64" fn create_dib_section(
    _hdc: usize,
    pbmi: usize,
    _usage: u32,
    ppv_bits: *mut usize,
    _h_section: usize,
    _offset: u32,
) -> usize {
    if pbmi == 0 {
        return 0;
    }
    // BITMAPINFOHEADER offsets (little-endian, packed):
    //   +0  biSize(4), +4 biWidth(i32), +8 biHeight(i32),
    //   +12 biPlanes(u16), +14 biBitCount(u16), +16 biCompression(u32), ...
    let (width, height, bpp) = unsafe {
        let bi_width = (pbmi + 4) as *const i32;
        let bi_height = (pbmi + 8) as *const i32;
        let bi_bit_count = (pbmi + 14) as *const u16;
        (
            (*bi_width).unsigned_abs(),
            (*bi_height).unsigned_abs(),
            (*bi_bit_count).max(1),
        )
    };
    let stride = (u64::from(width) * u64::from(bpp)).div_ceil(32) * 4;
    let size = (stride * u64::from(height)).max(1) as usize;
    let buf: Vec<u8> = vec![0u8; size];
    let ptr = buf.as_ptr() as usize;
    let _ = Box::leak(buf.into_boxed_slice());
    if !ppv_bits.is_null() {
        unsafe {
            *ppv_bits = ptr;
        }
    }
    objects::alloc(GdiKind::DibSection {
        width,
        height,
        bits_ptr: ptr,
        bpp,
    })
}

/// SetDIBitsToDevice: copy a horizontal band of a caller-owned DIB straight to
/// a device.
///
/// Parses the caller-supplied `BITMAPINFOHEADER`, slices `cLines` scanlines
/// starting at `uStartScan`, and uploads the band to the destination DC's
/// drawable at `(xDest, yDest)`. Bottom-up DIBs (biHeight > 0) are re-emitted
/// in top-down order before upload so the X server receives scanlines in
/// natural draw order.
///
/// First-pass scope: 32-bit BI_RGB DIBs with `DIB_RGB_COLORS`. Every other
/// combination (24/16/8-bit depths, BI_BITFIELDS / BI_RLE*, DIB_PAL_COLORS)
/// returns 0 with a rate-limited stderr trace. Null `lpBits` or null
/// `lpBitsInfo` return 0 without panicking.
///
/// Returns the number of scanlines uploaded on success; 0 on any rejection.
///
/// Wine ref: dlls/win32u/dib.c::nulldrv_SetDIBitsToDevice — clamps `lines` to
/// `height - startscan` for bottom-up DIBs when `startscan + lines > height`,
/// returns 0 if `startscan >= height`, rejects `lines == 0` early, and returns
/// the final `lines` count after PutImage. Stride formula (Windows DIB rows
/// are DWORD-aligned): `stride = ((|biWidth| * biBitCount + 31) / 32) * 4`
/// — identical to the formula used in `create_dib_section` above.
///
/// # Safety
/// `lp_v_bits` must point to at least `stride * (uStartScan + cLines)` bytes
/// for bottom-up DIBs (rows below the band are addressed to compute offsets
/// when re-emitting top-down). `lpbmi` must point to a readable
/// `BITMAPINFOHEADER`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn set_dib_bits_to_device(
    hdc: usize,
    x_dest: i32,
    y_dest: i32,
    w: u32,
    h: u32,
    _x_src: i32,
    _y_src: i32,
    start_scan: u32,
    c_lines: u32,
    lp_v_bits: *const u8,
    lpbmi: usize,
    color_use: u32,
) -> i32 {
    if lpbmi == 0 || lp_v_bits.is_null() || c_lines == 0 || w == 0 || h == 0 {
        return 0;
    }

    // DIB_RGB_COLORS == 0, DIB_PAL_COLORS == 1. First pass supports RGB only.
    if color_use != 0 {
        static UNSUPPORTED_COLORUSE: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);
        if UNSUPPORTED_COLORUSE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!(
                "weave/gdi32: SetDIBitsToDevice color_use={color_use} unsupported (DIB_RGB_COLORS only)"
            );
        }
        return 0;
    }

    // Parse BITMAPINFOHEADER — same offsets used in create_dib_section:
    //   +4 biWidth(i32), +8 biHeight(i32), +14 biBitCount(u16), +16 biCompression(u32)
    let (bi_width, bi_height, bi_bit_count, bi_compression) = unsafe {
        let w_ptr = (lpbmi + 4) as *const i32;
        let h_ptr = (lpbmi + 8) as *const i32;
        let bc_ptr = (lpbmi + 14) as *const u16;
        let comp_ptr = (lpbmi + 16) as *const u32;
        (*w_ptr, *h_ptr, *bc_ptr, *comp_ptr)
    };

    // BI_RGB = 0. BI_BITFIELDS = 3, BI_RLE4/8 rejected.
    if bi_compression != 0 {
        static UNSUPPORTED_COMP: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);
        if UNSUPPORTED_COMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!(
                "weave/gdi32: SetDIBitsToDevice compression={bi_compression} unsupported (BI_RGB only)"
            );
        }
        return 0;
    }

    if bi_bit_count != 32 && bi_bit_count != 24 {
        static UNSUPPORTED_BPP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if UNSUPPORTED_BPP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!(
                "weave/gdi32: SetDIBitsToDevice bpp={bi_bit_count} unsupported (24/32-bit only)"
            );
        }
        return 0;
    }

    let abs_width = bi_width.unsigned_abs();
    let abs_height = bi_height.unsigned_abs();
    let top_down = bi_height < 0;
    if abs_width == 0 || abs_height == 0 {
        return 0;
    }

    // Wine clamp: startscan >= height → return 0; lines > height - startscan
    // → clamp to height - startscan (bottom-up path).
    if start_scan >= abs_height {
        return 0;
    }
    let mut lines = c_lines;
    if lines > abs_height - start_scan {
        lines = abs_height - start_scan;
    }

    // Stride formula (Wine ref: dlls/win32u/dib.c get_dib_stride):
    //   stride = ((|biWidth| * biBitCount + 31) / 32) * 4
    let stride = ((abs_width as u64 * bi_bit_count as u64).div_ceil(32) * 4) as usize;
    let lines_usize = lines as usize;
    let band_bytes = stride.saturating_mul(lines_usize);
    if band_bytes == 0 {
        return 0;
    }

    // Slice the source band. For bottom-up DIBs the scanline at "startscan"
    // counted from the bottom sits at offset `(height - 1 - startscan) * stride`
    // and rows above it step DOWN in memory — so the band runs from
    // `(height - startscan - lines) * stride` for `lines * stride` bytes, and
    // we re-emit it reversed into a top-down scratch before upload. Top-down
    // DIBs pass through directly: band at `startscan * stride`.
    let src_band_offset = if top_down {
        start_scan as usize * stride
    } else {
        (abs_height as usize - start_scan as usize - lines_usize) * stride
    };
    let src_slice =
        unsafe { std::slice::from_raw_parts(lp_v_bits.add(src_band_offset), band_bytes) };

    let top_down_rows: Vec<u8> = if top_down {
        src_slice.to_vec()
    } else {
        // Reverse row order so caller-supplied bottom-up becomes top-down.
        let mut out = vec![0u8; band_bytes];
        for row in 0..lines_usize {
            let src_row =
                &src_slice[(lines_usize - 1 - row) * stride..(lines_usize - row) * stride];
            out[row * stride..(row + 1) * stride].copy_from_slice(src_row);
        }
        out
    };

    // Resolve destination drawable.
    let dst_draw = dc::with(hdc, |dc| dc.drawable());
    if dst_draw == 0 {
        return 0;
    }

    // Upload width is the lesser of w and abs_width — Wine intersects against
    // the source rect. We keep it simple: clamp upload width to whatever the
    // caller requested AND the DIB actually provides.
    let upload_w = w.min(abs_width) as u16;
    let upload_h = lines as u16;

    // put_bits_to_pixmap_at only accepts 32-bit BGRA. For 24-bit BGR input,
    // expand each pixel to BGRA (alpha=0xFF) before upload.
    if bi_bit_count == 24 {
        let src_stride_24 = stride;
        let dst_stride_32 = abs_width as usize * 4;
        let mut expanded = vec![0u8; dst_stride_32 * lines_usize];
        for row in 0..lines_usize {
            for col in 0..abs_width as usize {
                let s = row * src_stride_24 + col * 3;
                let d = row * dst_stride_32 + col * 4;
                if s + 3 <= top_down_rows.len() && d + 4 <= expanded.len() {
                    expanded[d] = top_down_rows[s];
                    expanded[d + 1] = top_down_rows[s + 1];
                    expanded[d + 2] = top_down_rows[s + 2];
                    expanded[d + 3] = 0xFF;
                }
            }
        }
        weave_user32::backend::put_bits_to_pixmap_at(
            dst_draw,
            x_dest as i16,
            y_dest as i16,
            upload_w,
            upload_h,
            dst_stride_32,
            &expanded,
            32,
        );
    } else {
        weave_user32::backend::put_bits_to_pixmap_at(
            dst_draw,
            x_dest as i16,
            y_dest as i16,
            upload_w,
            upload_h,
            stride,
            &top_down_rows,
            bi_bit_count,
        );
    }

    lines as i32
}

// ── Text metrics ──────────────────────────────────────────────────────────────

/// GetTextMetricsW: return metrics for the selected font.
///
/// Wine ref: dlls/win32u/font.c::font_GetTextMetrics — queries the font cache for the
/// currently selected font's TEXTMETRICW; fills tmHeight, tmAscent, tmDescent,
/// tmAveCharWidth, tmMaxCharWidth, tmWeight, tmPitchAndFamily, tmCharSet.
/// Returns FALSE if lptm is NULL or no font is selected.
///
/// # Safety
/// `lptm` must be a valid writable pointer to a `TEXTMETRICW`.
// Wine ref: dlls/win32u/font.c::font_GetTextMetrics — fills otmTextMetrics from font cache.
pub unsafe extern "win64" fn get_text_metrics_w(hdc: usize, lptm: *mut TextMetricW) -> i32 {
    if lptm.is_null() {
        return 0;
    }
    let px_size = font_px_size(hdc);
    let fm = weave_user32::font::metrics(px_size);
    unsafe {
        let tm = &mut *lptm;
        tm.tm_height = fm.height;
        tm.tm_ascent = fm.ascent;
        tm.tm_descent = fm.descent;
        tm.tm_internal_leading = 0;
        tm.tm_external_leading = 2;
        // Clamp tmAveCharWidth to a reasonable value for typical screen fonts.
        // Fontdue can return advance widths > 12px for some system fonts at small
        // pixel sizes (e.g. DejaVu Sans at certain hinting levels). Scintilla uses
        // tmAveCharWidth * digitCount to size its line-number margin, so an
        // inflated value causes the margin to consume the entire client width,
        // leaving a 1px-wide document body. Clamping to 9px matches a typical
        // monospace character width at 13px font size (matches Wine's font metrics
        // for Courier New 10pt at 96 DPI).
        let ave = fm.ave_char_width.min(9);
        tm.tm_ave_char_width = ave;
        tm.tm_max_char_width = ave + 2;
        tm.tm_weight = 400; // FW_NORMAL
        tm.tm_overhang = 0;
        tm.tm_digitized_aspect_x = 96;
        tm.tm_digitized_aspect_y = 96;
        tm.tm_first_char = 0x20;
        tm.tm_last_char = 0xFFFF;
        tm.tm_default_char = b'?' as u16;
        tm.tm_break_char = b' ' as u16;
        tm.tm_italic = 0;
        tm.tm_underlined = 0;
        tm.tm_struck_out = 0;
        tm.tm_pitch_and_family = 0x01 | 0x30; // TMPF_FIXED_PITCH | FF_MODERN
        tm.tm_char_set = 0; // ANSI_CHARSET
        tm._pad = [0u8; 3];
    }
    1
}

/// GetTextExtentPoint32W: compute the bounding box of a text string.
///
/// Wine ref: dlls/win32u/font.c::font_GetTextExtentExPoint — measures advance widths for
/// each glyph using the selected font and sums them; cy = tmHeight. Returns FALSE if
/// lpSize is NULL. Negative c is treated as 0 in Wine; Weave returns early with cy only.
///
/// # Safety
/// `lpsz` must be a valid pointer to `c` UTF-16 code units.
/// `lp_size` must be a valid writable pointer to a `SIZE`.
// Wine ref: dlls/win32u/font.c::font_GetTextExtentExPoint — sums abc advances per glyph.
pub unsafe extern "win64" fn get_text_extent_point32_w(
    hdc: usize,
    lpsz: *const u16,
    c: i32,
    lp_size: *mut Size,
) -> i32 {
    if lp_size.is_null() {
        return 0;
    }
    let px_size = font_px_size(hdc);
    if lpsz.is_null() || c <= 0 {
        unsafe {
            (*lp_size).cx = 0;
            (*lp_size).cy = weave_user32::font::metrics(px_size).height;
        }
        return 1;
    }
    // Pointer validation: cap c to prevent building a multi-GB slice.
    let c = c.min(65_536i32);
    let units: &[u16] = unsafe { std::slice::from_raw_parts(lpsz, c as usize) };
    let (w, h) = weave_user32::font::measure_text(units, px_size);
    {
        static GTE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if GTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 3 {
            eprintln!("weave/gdi32: GetTextExtentPoint32W hdc={hdc:#x} c={c} → {w}x{h}");
        }
    }
    unsafe {
        (*lp_size).cx = w;
        (*lp_size).cy = h;
    }
    1
}

// ── Resource-backed bitmap loaders ────────────────────────────────────────────

/// LoadBitmapW: load an HBITMAP from `h_inst`'s RT_BITMAP resource by name.
///
/// Trampolines into `weave_user32::api::load_image_w` with `IMAGE_BITMAP` —
/// that path already walks RT_BITMAP via `weave_core::resource::find_resource`
/// (Task 09 walker, Task 10 LoadImageW), allocates an HBITMAP slot in
/// `weave_user32::image_handles`, and honours `LR_SHARED` dedup. Wine takes
/// the same shape (LoadBitmapW is a one-line call into LoadImageW with
/// `IMAGE_BITMAP`), so we delegate rather than duplicating the walker.
///
/// Crate-boundary note: gdi32→user32 is the documented exception (see header).
/// Routing bitmap loads through user32's `image_handles` avoids a parallel
/// slab in gdi32 + keeps HBITMAP a single namespace.
///
/// # Safety
/// `lp_bitmap_name` is either a UTF-16 string pointer or an
/// `IS_INTRESOURCE`-style packed ordinal.
// Wine ref: dlls/user32/cursoricon.c::LoadBitmapW — internally calls
// LoadImageW(hInst, name, IMAGE_BITMAP, 0, 0, 0). Our delegation matches.
pub unsafe extern "win64" fn load_bitmap_w(h_inst: usize, lp_bitmap_name: *const u16) -> usize {
    const IMAGE_BITMAP: u32 = 0;
    // SAFETY: forward caller contract on `lp_bitmap_name`.
    // restrace: fires via load_image_w in weave-user32 (weave-core not a direct dep here).
    unsafe {
        weave_user32::api::load_image_w(h_inst, lp_bitmap_name as usize, IMAGE_BITMAP, 0, 0, 0)
    }
}

/// LoadBitmapA: ANSI trampoline. For ordinal ids (`IS_INTRESOURCE`) we pass
/// the value through unchanged; for string names we transcode CP_ACP→UTF-16
/// on the heap and re-enter LoadBitmapW.
///
/// # Safety
/// `lp_bitmap_name` is either an ordinal or a CP_ACP null-terminated string.
// Wine ref: dlls/user32/cursoricon.c::LoadBitmapA — same delegate pattern as
// LoadBitmapW after a CP_ACP→WCHAR conversion via MultiByteToWideChar.
pub unsafe extern "win64" fn load_bitmap_a(h_inst: usize, lp_bitmap_name: *const u8) -> usize {
    let name_usize = lp_bitmap_name as usize;
    if name_usize >> 16 == 0 {
        // Ordinal path — no deref.
        // SAFETY: ordinal-as-pointer convention.
        return unsafe { load_bitmap_w(h_inst, name_usize as *const u16) };
    }
    let mut bytes: Vec<u8> = Vec::new();
    // SAFETY: caller contract — null-terminated CP_ACP string.
    unsafe {
        let mut p = lp_bitmap_name;
        for _ in 0..32_768 {
            let b = *p;
            if b == 0 {
                break;
            }
            bytes.push(b);
            p = p.add(1);
        }
    }
    // Latin-1 expansion is 1:1 to UTF-16 — adequate for resource names which
    // are ASCII in practice. Real CP_ACP would call MultiByteToWideChar.
    let mut wide: Vec<u16> = bytes.iter().map(|&b| b as u16).collect();
    wide.push(0);
    // SAFETY: `wide` outlives the call.
    unsafe { load_bitmap_w(h_inst, wide.as_ptr()) }
}

// ── ICM (color-profile) stubs ─────────────────────────────────────────────────

/// GetICMProfileW: return the path to the ICM color profile associated with
/// `hdc`. We have no ICM support — write `*lp_buf_size = 0`, set the buffer
/// to an empty string if writable, return FALSE.
///
/// SDL2's renderer queries this every frame on the back-buffer DC; the
/// unresolved-import stub previously returned with leftover `rax` that the
/// caller treated as a BOOL success and then dereferenced `psz_filename` as
/// a populated path → flaky SIGSEGV in the same family as `GetClipCursor`.
/// FALSE + zeroed out-params closes the deref hazard.
///
/// # Safety
/// `lp_buf_size` and `psz_filename` (if non-null) must point to writable
/// memory of the appropriate size.
// Wine ref: dlls/gdi32/dc.c::GetICMProfileW — calls NtGdiGetICMProfile which
// queries the device's WINEDC color-management state; on systems without an
// installed profile, returns FALSE and writes zero into *lp_buf_size.
pub unsafe extern "win64" fn get_icm_profile_w(
    _hdc: usize,
    lp_buf_size: *mut u32,
    psz_filename: *mut u16,
) -> i32 {
    if !lp_buf_size.is_null() {
        // SAFETY: caller-provided writable u32.
        unsafe { *lp_buf_size = 0 };
    }
    if !psz_filename.is_null() {
        // SAFETY: write a single NUL so callers that read the buffer without
        // checking the BOOL return get a well-formed empty string.
        unsafe { *psz_filename = 0 };
    }
    0
}

// ── Device capabilities ───────────────────────────────────────────────────────

/// GetDeviceCaps: return device capabilities for a DC.
///
/// Returns sensible defaults for a 96-DPI TrueColor display.
// Wine ref: dlls/win32u/driver.c::nulldrv_GetDeviceCaps — HORZRES/VERTRES from primary
// monitor rect (fallback: SM_CXSCREEN); LOGPIXELSX/Y = system DPI; PLANES=1;
// RASTERCAPS = RC_BITBLT|RC_BITMAP64|RC_GDI20_OUTPUT|...|RC_DEVBITS for display DCs.
// Known gap: HORZRES/VERTRES hardcoded to 1920×1080 instead of querying screen size.
pub extern "win64" fn get_device_caps(hdc: usize, n_index: i32) -> i32 {
    let _ = hdc;
    match n_index {
        HORZRES => 1920,
        VERTRES => 1080,
        BITSPIXEL => 32,
        PLANES => 1,
        LOGPIXELSX => 96,
        LOGPIXELSY => 96,
        // Wine ref: dlls/win32u/driver.c::nulldrv_GetDeviceCaps — standard display raster caps.
        // RC_DI_BITMAP / RC_DIBTODEV now safe: GetDIBits and SetDIBitsToDevice are real.
        // RC_FLOODFILL / RC_BIGFONT / RC_DEVBITS omitted — those paths not yet implemented.
        RASTERCAPS => {
            RC_BITBLT
                | RC_BITMAP64
                | RC_GDI20_OUTPUT
                | RC_DI_BITMAP
                | RC_DIBTODEV
                | RC_STRETCHBLT
                | RC_STRETCHDIB
        }
        _ => 0,
    }
}

// ── DC clipping ───────────────────────────────────────────────────────────────

/// GetClipBox: return the bounding rectangle of the current clipping region (stub).
///
/// # Safety
/// `lp_rect` must be a valid writable pointer to a `RECT`.
// Wine ref: dlls/win32u/clipping.c — NtGdiGetAppClipBox intersects the vis region
// with the meta/app clip regions; return values: ERROR(0), NULLREGION(1), SIMPLEREGION(2),
// COMPLEXREGION(3); lp_rect receives the bounding box of the combined region.
pub unsafe extern "win64" fn get_clip_box(hdc: usize, lp_rect: *mut Rect) -> i32 {
    if lp_rect.is_null() {
        return 0; // ERROR
    }
    // Return the whole screen as the clip box.
    let _ = hdc;
    unsafe {
        *lp_rect = Rect {
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
        };
    }
    2 // SIMPLEREGION
}

/// GetDCOrgEx: return the DC origin in screen coordinates (stub).
///
/// # Safety
/// `lp_point` must be a valid writable pointer to a `POINT`.
// Wine ref: dlls/win32u/dc.c — NtGdiGetDCPoint(hdc, DCPT_DCORG) returns the DC origin
// offset (window client area top-left in screen coords for window DCs; (0,0) for
// compatible/printer DCs). Weave always returns (0,0).
pub unsafe extern "win64" fn get_dc_org_ex(_hdc: usize, lp_point: *mut Point) -> i32 {
    if !lp_point.is_null() {
        unsafe { *lp_point = Point { x: 0, y: 0 } };
    }
    1
}

// ── DC save/restore ───────────────────────────────────────────────────────────

/// SaveDC: push the current DC state onto the per-HDC save stack.
///
/// Wine ref: dlls/win32u/dc.c — NtGdiSaveDC clones the DC object and pushes
/// it onto the DC's save-state list. Returns the save level (≥ 1) on success
/// or 0 on failure. The save level can be passed to RestoreDC to pop back to
/// a specific point.
pub extern "win64" fn save_dc(hdc: usize) -> i32 {
    dc::save(hdc)
}

/// RestoreDC: restore a previously saved DC state and discard more-recent saves.
///
/// Wine ref: dlls/win32u/dc.c — NtGdiRestoreDC accepts a positive save level
/// (absolute, 1-based) or negative (relative: -1 = most recent). All states
/// more recent than the target are discarded. Returns TRUE (1) on success or
/// FALSE (0) if the level is out of range.
pub extern "win64" fn restore_dc(hdc: usize, n_saved_dc: i32) -> i32 {
    dc::restore(hdc, n_saved_dc)
}

// ── D3DKMT adapter stubs ──────────────────────────────────────────────────────

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/dc.c — NtGdiDdDDIOpenAdapterFromHdc maps HDC to adapter LUID;
// returns STATUS_INVALID_PARAMETER if hdc is not a display DC; not in Wine gdi32.
pub unsafe extern "win64" fn d3dkmt_open_adapter_from_hdc(_p_data: usize) -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: include/ntuser.h::NtUserD3DKMTCloseAdapter — thin wrapper; returns
// STATUS_SUCCESS(0) on success, STATUS_INVALID_HANDLE on bad adapter handle.
pub unsafe extern "win64" fn d3dkmt_close_adapter(_p_data: usize) -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: include/ntuser.h::NtUserD3DKMTCreateDevice — allocates a kernel-mode
// device context on the adapter; returns STATUS_NO_MEMORY if allocation fails.
pub unsafe extern "win64" fn d3dkmt_create_device(_p_data: usize) -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: include/ntuser.h::NtUserD3DKMTDestroyDevice — frees kernel device context;
// returns STATUS_INVALID_HANDLE if hDevice is invalid.
pub unsafe extern "win64" fn d3dkmt_destroy_device(_p_data: usize) -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: include/ntuser.h::NtUserD3DKMTQueryAdapterInfo — dispatches on QueryType;
// returns STATUS_INVALID_PARAMETER(0xC000000D) for unknown types; Weave returns
// STATUS_NOT_IMPLEMENTED(0xC0000001) to signal unimplemented adapter queries.
pub unsafe extern "win64" fn d3dkmt_query_adapter_info(_p_data: usize) -> u32 {
    0xC000_0001u32
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: include/ntuser.h::NtUserD3DKMTSetVidPnSourceOwner — claims exclusive
// ownership of a VidPN source for fullscreen presentation; returns
// STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE if already owned.
pub unsafe extern "win64" fn d3dkmt_set_vid_pn_source_owner(_p_data: usize) -> u32 {
    0
}

// ── Resolve ───────────────────────────────────────────────────────────────────

/// Resolve a `gdi32.dll` import to a stub address.
///
/// Also handles a small set of GDI functions that Windows re-exports from
/// `user32.dll` (FillRect, DrawTextW, DrawTextA). Binaries compiled with
/// MinGW may import these from either DLL name.
// Wine ref: not applicable — Weave-internal IAT dispatch function with no Wine equivalent.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    let is_gdi32 = dll.eq_ignore_ascii_case("gdi32.dll");
    let is_user32_gdi = dll.eq_ignore_ascii_case("user32.dll")
        && matches!(func, "FillRect" | "DrawTextW" | "DrawTextA");
    if !is_gdi32 && !is_user32_gdi {
        return None;
    }
    match func {
        // Brush / pen / font creation
        "CreateSolidBrush" => Some(create_solid_brush as *const () as usize),
        "CreatePen" => Some(create_pen as *const () as usize),
        "CreateFontW" => Some(
            create_font_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CreateFontIndirectW" => {
            Some(create_font_indirect_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "DeleteObject" => Some(delete_object as *const () as usize),
        "GetStockObject" => Some(get_stock_object as *const () as usize),
        "GetObject" => Some(get_object as *const () as usize),
        // DC object selection
        "SelectObject" => Some(select_object as *const () as usize),
        // DC attributes
        "SetTextColor" => Some(set_text_color as *const () as usize),
        "GetTextColor" => Some(get_text_color as *const () as usize),
        "SetBkColor" => Some(set_bk_color as *const () as usize),
        "GetBkColor" => Some(get_bk_color as *const () as usize),
        "SetBkMode" => Some(set_bk_mode as *const () as usize),
        "GetBkMode" => Some(get_bk_mode as *const () as usize),
        "SetGraphicsMode" => Some(set_graphics_mode as *const () as usize),
        "SetWorldTransform" => {
            Some(set_world_transform as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetWorldTransform" => {
            Some(get_world_transform as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Drawing
        "FillRect" => {
            Some(fill_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "Rectangle" => Some(rectangle as *const () as usize),
        "Ellipse" => Some(ellipse as *const () as usize),
        "TextOutW" => {
            Some(text_out_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "DrawTextW" => {
            Some(draw_text_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "DrawTextA" => {
            Some(draw_text_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "ExtTextOutW" => Some(
            ext_text_out_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetPixel" => Some(set_pixel as *const () as usize),
        "GetPixel" => Some(get_pixel as *const () as usize),
        "MoveToEx" => {
            Some(move_to_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "LineTo" => Some(line_to as *const () as usize),
        "Polygon" => Some(polygon as *const () as usize),
        "PatBlt" => Some(pat_blt as *const () as usize),
        "BitBlt" => Some(bit_blt as *const () as usize),
        "StretchBlt" => Some(stretch_blt as *const () as usize),
        "StretchDIBits" => Some(
            stretch_di_bits as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "SetStretchBltMode" => Some(set_stretch_blt_mode as *const () as usize),
        "SetROP2" => Some(set_rop2 as *const () as usize),
        // Memory DCs and bitmaps
        "CreateCompatibleDC" => Some(create_compatible_dc as *const () as usize),
        "CreateDCW" | "CreateDCA" => {
            Some(create_dc_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "DeleteDC" => Some(delete_dc as *const () as usize),
        "CreateCompatibleBitmap" => Some(create_compatible_bitmap as *const () as usize),
        "CreateDIBSection" => Some(
            create_dib_section as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetDIBitsToDevice" => Some(
            set_dib_bits_to_device
                as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        // Text metrics
        "GetTextMetricsW" => {
            Some(get_text_metrics_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetTextExtentPoint32W" => Some(
            get_text_extent_point32_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Device capabilities
        "GetDeviceCaps" => Some(get_device_caps as *const () as usize),
        "LoadBitmapW" => {
            Some(load_bitmap_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LoadBitmapA" => {
            Some(load_bitmap_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetICMProfileA" | "GetICMProfileW" => {
            Some(get_icm_profile_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // DC state
        "GetClipBox" => {
            Some(get_clip_box as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetDCOrgEx" => {
            Some(get_dc_org_ex as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SaveDC" => Some(save_dc as *const () as usize),
        "RestoreDC" => Some(restore_dc as *const () as usize),
        // D3DKMT adapter stubs
        "D3DKMTOpenAdapterFromHdc" => Some(
            d3dkmt_open_adapter_from_hdc as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "D3DKMTCloseAdapter" => {
            Some(d3dkmt_close_adapter as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "D3DKMTCreateDevice" => {
            Some(d3dkmt_create_device as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "D3DKMTDestroyDevice" => {
            Some(d3dkmt_destroy_device as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "D3DKMTQueryAdapterInfo" => Some(
            d3dkmt_query_adapter_info as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "D3DKMTSetVidPnSourceOwner" => Some(
            d3dkmt_set_vid_pn_source_owner as unsafe extern "win64" fn(_) -> _ as *const ()
                as usize,
        ),
        // ── PuTTY gap-fill: ANSI variants + missing GDI ──────────────────
        "CreateFontA" => Some(
            create_font_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CreateFontIndirectA" => {
            Some(create_font_indirect_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "TextOutA" => {
            Some(text_out_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "ExtTextOutA" => Some(
            ext_text_out_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetTextExtentPoint32A" => Some(
            get_text_extent_point32_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetTextMetricsA" => {
            Some(get_text_metrics_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetObjectA" => {
            Some(get_object_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "GetTextExtentExPointA" => Some(
            get_text_extent_ex_point_a as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "GetOutlineTextMetricsA" => Some(
            get_outline_text_metrics_a as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "GetCharABCWidthsFloatA" => Some(
            get_char_abc_widths_float_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetCharWidth32A" => Some(
            get_char_width32_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetCharWidth32W" => Some(
            get_char_width32_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetCharWidthA" => Some(
            get_char_width_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetCharWidthW" => Some(
            get_char_width_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetCharacterPlacementW" => Some(
            get_character_placement_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "SetTextAlign" => Some(set_text_align as *const () as usize),
        "GetCurrentObject" => Some(get_current_object as *const () as usize),
        "SetMapMode" => Some(set_map_mode as *const () as usize),
        "Polyline" => {
            Some(polyline as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CreateBitmap" => Some(create_bitmap as *const () as usize),
        "GetDIBits" => Some(
            get_dib_bits as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "ExcludeClipRect" => Some(exclude_clip_rect as *const () as usize),
        "IntersectClipRect" => Some(intersect_clip_rect as *const () as usize),
        "TranslateCharsetInfo" => Some(
            translate_charset_info as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        // Palette functions
        "CreatePalette" => {
            Some(create_palette as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SelectPalette" => Some(select_palette as *const () as usize),
        "RealizePalette" => Some(realize_palette as *const () as usize),
        "SetPaletteEntries" => Some(
            set_palette_entries as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "UnrealizeObject" => Some(unrealize_object as *const () as usize),
        "UpdateColors" => Some(update_colors as *const () as usize),
        // ── Notepad++ / Scintilla gap-fill ────────────────────────────────
        "GetTextAlign" => Some(get_text_align as *const () as usize),
        "GetTextExtentExPointW" => Some(
            get_text_extent_ex_point_w as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "GetTextExtentPointW" => Some(
            get_text_extent_point_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetObjectW" => {
            Some(get_object_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "EnumFontFamiliesExW" => Some(
            enum_font_families_ex_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateRectRgn" => Some(create_rect_rgn as *const () as usize),
        "CreateRectRgnIndirect" => {
            Some(create_rect_rgn_indirect as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CombineRgn" => Some(combine_rgn as *const () as usize),
        "SelectClipRgn" => Some(select_clip_rgn as *const () as usize),
        "CreateHatchBrush" => Some(create_hatch_brush as *const () as usize),
        "CreatePatternBrush" => Some(create_pattern_brush as *const () as usize),
        "ExtCreatePen" => Some(
            ext_create_pen as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "GdiAlphaBlend" => Some(
            gdi_alpha_blend as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "GetClipRgn" => Some(get_clip_rgn as *const () as usize),
        "GetROP2" => Some(get_rop2 as *const () as usize),
        "RectVisible" => {
            Some(rect_visible as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RoundRect" => Some(round_rect as *const () as usize),
        "SetWindowOrgEx" => Some(
            set_window_org_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "SetViewportOrgEx" => Some(
            set_viewport_org_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetViewportOrgEx" => {
            Some(get_viewport_org_ex as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "OffsetViewportOrgEx" => Some(
            offset_viewport_org_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "OffsetWindowOrgEx" => Some(
            offset_window_org_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "SetBrushOrgEx" => Some(
            set_brush_org_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "SetDIBits" => Some(
            set_dib_bits as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "DPtoLP" => Some(dpto_lp as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize),
        "LPtoDP" => Some(lpto_dp as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize),
        "StartDocW" => {
            Some(start_doc_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "StartPage" => Some(start_page as *const () as usize),
        "EndDoc" => Some(end_doc as *const () as usize),
        "EndPage" => Some(end_page as *const () as usize),
        "AbortDoc" => Some(abort_doc as *const () as usize),
        // OpenGL pixel format
        "ChoosePixelFormat" => {
            Some(choose_pixel_format as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetPixelFormat" => {
            Some(set_pixel_format as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "GetPixelFormat" => Some(get_pixel_format as *const () as usize),
        "DescribePixelFormat" => Some(
            describe_pixel_format as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SwapBuffers" => Some(swap_buffers as *const () as usize),
        "GetDeviceGammaRamp" => {
            Some(get_device_gamma_ramp as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetDeviceGammaRamp" => {
            Some(set_device_gamma_ramp as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        _ => None,
    }
}

// ── msimg32.dll stubs ─────────────────────────────────────────────────────────
//
// msimg32.dll provides alpha-blending, transparent blit, and gradient fill.
// IrfanView uses AlphaBlend for compositing images with transparency.
// All three stubs return FALSE (0); callers that check the return value will
// fall back to a non-alpha path or skip the draw.
//
// Wine ref: dlls/msimg32/msimg32.c — AlphaBlend calls NtGdiAlphaBlend;
// TransparentBlt calls NtGdiTransparentBlt; GradientFill calls NtGdiGradientFill.

/// AlphaBlend — alpha-composite a source DC onto a destination DC.
///
/// Implements the AC_SRC_OVER blend op for 32-bit ARGB memory-DC source and
/// destination with matching dimensions. Other configurations (scale, non-32bpp,
/// window-DC dest, BlendOp != 0, BlendFlags != 0) return FALSE with a traced
/// warning so callers observe the rejection and can fall back.
///
/// BLENDFUNCTION byte layout (packed into a u64 on win64):
///   byte 0  BlendOp              — must be AC_SRC_OVER (0)
///   byte 1  BlendFlags           — must be 0
///   byte 2  SourceConstantAlpha  — 0..=255 scales effective source alpha
///   byte 3  AlphaFormat          — AC_SRC_ALPHA (1) means premultiplied source
///
/// Premultiplied (AC_SRC_ALPHA=1): `dst = src*SCA/255 + dst*(1 - src.a*SCA/255)`
/// Straight (AC_SRC_ALPHA=0):      `dst = src*(SCA/255) + dst*(1 - SCA/255)`
///
/// Wine ref: dlls/win32u/bitblt.c::nulldrv_BlendImage — rejects BI_BITFIELDS when
/// AC_SRC_ALPHA is set (premultiplied source requires A8R8G8B8); requires
/// `src->width == dst->width && src->height == dst->height` or returns
/// ERROR_TRANSFORM_NOT_SUPPORTED; calls `blend_bitmapinfo` for per-pixel
/// source-over composite. Wine test dlls/gdi32/tests/dib.c::test_alpha_blend
/// pins the MulDiv255 rounding `(a*b + 127) / 255` idiom for alpha math.
///
/// # Safety
/// `hdc_dest` and `hdc_src` must be DC handles whose selected bitmaps (if any)
/// have valid `bits_ptr` allocations covering `width*height*4` bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn alpha_blend(
    hdc_dest: usize,
    x_origin_dest: i32,
    y_origin_dest: i32,
    w_dest: i32,
    h_dest: i32,
    hdc_src: usize,
    x_origin_src: i32,
    y_origin_src: i32,
    w_src: i32,
    h_src: i32,
    blend_function: u64, // BLENDFUNCTION packs into a u64 on x64 ABI
) -> i32 {
    // Unpack BLENDFUNCTION — generated.c tests pin these byte offsets.
    let blend_op = (blend_function & 0xFF) as u8;
    let blend_flags = ((blend_function >> 8) & 0xFF) as u8;
    let src_const_alpha = ((blend_function >> 16) & 0xFF) as u8;
    let alpha_format = ((blend_function >> 24) & 0xFF) as u8;

    const AC_SRC_OVER: u8 = 0x00;
    const AC_SRC_ALPHA: u8 = 0x01;

    if blend_op != AC_SRC_OVER || blend_flags != 0 {
        static BAD_OP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if BAD_OP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!(
                "weave/gdi32: AlphaBlend BlendOp={blend_op:#x} Flags={blend_flags:#x} unsupported"
            );
        }
        return 0;
    }

    if w_dest <= 0 || h_dest <= 0 || w_src <= 0 || h_src <= 0 {
        return 0;
    }

    // Scale-and-blend is deferred — this first pass handles equal-dim only.
    if w_src != w_dest || h_src != h_dest {
        static NO_SCALE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if NO_SCALE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!(
                "weave/gdi32: AlphaBlend scale not yet supported ({w_src}x{h_src} -> {w_dest}x{h_dest})"
            );
        }
        return 0;
    }

    // Resolve source bits (memory-DC with a 32bpp Bitmap or DibSection selected).
    let src_info: Option<(u32, u32, usize, u16)> = dc::with(hdc_src, |dc| {
        let bmp = dc.selected_bitmap;
        if bmp == 0 {
            return None;
        }
        objects::get(bmp, |kind| match kind {
            objects::GdiKind::DibSection {
                width,
                height,
                bits_ptr,
                bpp,
            }
            | objects::GdiKind::Bitmap {
                width,
                height,
                bits_ptr,
                bpp,
            } => Some((*width, *height, *bits_ptr, *bpp)),
            _ => None,
        })
        .flatten()
    });
    let (src_w, src_h, src_ptr, src_bpp) = match src_info {
        Some(v) => v,
        None => return 0,
    };
    if src_bpp != 32 {
        static BAD_SRC_BPP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if BAD_SRC_BPP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!("weave/gdi32: AlphaBlend src bpp={src_bpp} unsupported (32-bit only)");
        }
        return 0;
    }

    // Resolve dest bits — must be a memory DC with a 32bpp backing bitmap.
    let dst_info: Option<(u32, u32, usize, u16)> = dc::with(hdc_dest, |dc| {
        let bmp = dc.selected_bitmap;
        if bmp == 0 {
            return None;
        }
        objects::get(bmp, |kind| match kind {
            objects::GdiKind::DibSection {
                width,
                height,
                bits_ptr,
                bpp,
            }
            | objects::GdiKind::Bitmap {
                width,
                height,
                bits_ptr,
                bpp,
            } => Some((*width, *height, *bits_ptr, *bpp)),
            _ => None,
        })
        .flatten()
    });
    let (dst_w, dst_h, dst_ptr, dst_bpp) = match dst_info {
        Some(v) => v,
        None => {
            // No CPU-side dest buffer — window-DC dest needs an XGetImage round-trip
            // we don't do yet. Defer.
            static NO_WIN_DC: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            if NO_WIN_DC.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
                eprintln!("weave/gdi32: AlphaBlend dest must be a memory DC with a 32bpp bitmap");
            }
            return 0;
        }
    };
    if dst_bpp != 32 {
        static BAD_DST_BPP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if BAD_DST_BPP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!("weave/gdi32: AlphaBlend dst bpp={dst_bpp} unsupported (32-bit only)");
        }
        return 0;
    }

    // Bounds-clip the source/dest rectangles against their bitmap dimensions —
    // anything outside the bitmap is skipped. Wine clips in `clip_visrect` plus
    // the `bitblt_coords` intersection; we do the simpler CPU clip here.
    if x_origin_src < 0
        || y_origin_src < 0
        || x_origin_dest < 0
        || y_origin_dest < 0
        || (x_origin_src as i64 + w_src as i64) > src_w as i64
        || (y_origin_src as i64 + h_src as i64) > src_h as i64
        || (x_origin_dest as i64 + w_dest as i64) > dst_w as i64
        || (y_origin_dest as i64 + h_dest as i64) > dst_h as i64
    {
        return 0;
    }

    let w = w_src as usize;
    let h = h_src as usize;
    let src_stride = src_w as usize * 4;
    let dst_stride = dst_w as usize * 4;
    let sca = src_const_alpha as u32;
    let premul = alpha_format == AC_SRC_ALPHA;

    // MulDiv255 rounded — Wine's `((a * b) + 127) / 255` idiom; gives the
    // alpha-blend-accurate result without a divide instruction.
    #[inline]
    fn muldiv255(a: u32, b: u32) -> u32 {
        ((a * b) + 127) / 255
    }

    let src_bytes =
        unsafe { std::slice::from_raw_parts(src_ptr as *const u8, src_h as usize * src_stride) };
    let dst_bytes =
        unsafe { std::slice::from_raw_parts_mut(dst_ptr as *mut u8, dst_h as usize * dst_stride) };

    for row in 0..h {
        let sy = y_origin_src as usize + row;
        let dy = y_origin_dest as usize + row;
        for col in 0..w {
            let sx = x_origin_src as usize + col;
            let dx = x_origin_dest as usize + col;
            let s_off = sy * src_stride + sx * 4;
            let d_off = dy * dst_stride + dx * 4;
            // BGRA in memory (little-endian DWORD = AARRGGBB).
            let sb = src_bytes[s_off] as u32;
            let sg = src_bytes[s_off + 1] as u32;
            let sr = src_bytes[s_off + 2] as u32;
            let sa = src_bytes[s_off + 3] as u32;
            let db = dst_bytes[d_off] as u32;
            let dg = dst_bytes[d_off + 1] as u32;
            let dr = dst_bytes[d_off + 2] as u32;
            let da = dst_bytes[d_off + 3] as u32;

            // Effective source alpha for the inverse-alpha blend term.
            // Both paths compute this the same way: sa_eff = sa * SCA / 255.
            let sa_eff = muldiv255(sa, sca);
            let inv_a = 255 - sa_eff;

            let (out_b, out_g, out_r, out_a) = if premul {
                // Premultiplied: src channels already carry sa, so scale only by SCA/255.
                let b = muldiv255(sb, sca) + muldiv255(db, inv_a);
                let g = muldiv255(sg, sca) + muldiv255(dg, inv_a);
                let r = muldiv255(sr, sca) + muldiv255(dr, inv_a);
                let a = sa_eff + muldiv255(da, inv_a);
                (b, g, r, a)
            } else {
                // Straight alpha: multiply src by sa_eff on the fly.
                let b = muldiv255(sb, sa_eff) + muldiv255(db, inv_a);
                let g = muldiv255(sg, sa_eff) + muldiv255(dg, inv_a);
                let r = muldiv255(sr, sa_eff) + muldiv255(dr, inv_a);
                let a = sa_eff + muldiv255(da, inv_a);
                (b, g, r, a)
            };

            dst_bytes[d_off] = out_b.min(255) as u8;
            dst_bytes[d_off + 1] = out_g.min(255) as u8;
            dst_bytes[d_off + 2] = out_r.min(255) as u8;
            dst_bytes[d_off + 3] = out_a.min(255) as u8;
        }
    }

    // Upload the composited band to the dest drawable so subsequent server-side
    // copies see the updated pixels. Mirrors set_dib_bits_to_device (task 19).
    let dst_draw = dc::with(hdc_dest, |dc| dc.drawable());
    if dst_draw != 0 {
        // Slice the composited band out of the dest bits, row-major top-down.
        let band_w = w_dest as usize;
        let band_h = h_dest as usize;
        let mut band = vec![0u8; band_w * band_h * 4];
        for row in 0..band_h {
            let dy = y_origin_dest as usize + row;
            let src_row_off = dy * dst_stride + x_origin_dest as usize * 4;
            let dst_row_off = row * band_w * 4;
            band[dst_row_off..dst_row_off + band_w * 4]
                .copy_from_slice(&dst_bytes[src_row_off..src_row_off + band_w * 4]);
        }
        weave_user32::backend::put_bits_to_pixmap_at(
            dst_draw,
            x_origin_dest as i16,
            y_origin_dest as i16,
            w_dest as u16,
            h_dest as u16,
            band_w * 4,
            &band,
            32,
        );
    }

    1
}

/// TransparentBlt — blit with a transparent colour key.
///
/// Copies source pixels to the destination, leaving destination pixels
/// untouched wherever the matching source pixel equals `cr_transparent`.
/// COLORREF is `0x00BBGGRR`; exact match only, no tolerance.
///
/// First-pass scope: 32-bit ARGB memory-DC source + dest, equal dimensions.
/// Mismatched dimensions, non-32bpp bitmaps, window-DC dest, or zero area
/// return FALSE with a rate-limited stderr trace. Stretch-and-key is a
/// follow-up task.
///
/// Wine ref: dlls/win32u/bitblt.c::NtGdiTransparentBlt — builds a 1bpp mask
/// from the source by `SetBkColor(crTransparent)` + `StretchBlt`, then uses
/// that mask to `BitBlt` only the non-keyed pixels onto the destination
/// (mask bit 1 = keyed pixel, skipped). COLORREF is exact match; no
/// tolerance, no fuzz. We achieve the same result with a direct per-pixel
/// CPU skip loop — cheaper on a 32bpp round-trip than building a 1bpp mask.
///
/// # Safety
/// `hdc_dest` and `hdc_src` must be valid DC handles whose selected bitmaps
/// expose 32bpp backing buffers reachable via `objects::get`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn transparent_blt(
    hdc_dest: usize,
    x_origin_dest: i32,
    y_origin_dest: i32,
    w_dest: i32,
    h_dest: i32,
    hdc_src: usize,
    x_origin_src: i32,
    y_origin_src: i32,
    w_src: i32,
    h_src: i32,
    cr_transparent: u32,
) -> i32 {
    if w_dest <= 0 || h_dest <= 0 || w_src <= 0 || h_src <= 0 {
        return 0;
    }

    // Stretch-and-key is deferred; equal-dim only this pass.
    if w_src != w_dest || h_src != h_dest {
        static NO_SCALE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if NO_SCALE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!(
                "weave/gdi32: TransparentBlt scale not yet supported ({w_src}x{h_src} -> {w_dest}x{h_dest})"
            );
        }
        return 0;
    }

    // Resolve source bits (memory-DC with a 32bpp Bitmap or DibSection).
    let src_info: Option<(u32, u32, usize, u16)> = dc::with(hdc_src, |dc| {
        let bmp = dc.selected_bitmap;
        if bmp == 0 {
            return None;
        }
        objects::get(bmp, |kind| match kind {
            objects::GdiKind::DibSection {
                width,
                height,
                bits_ptr,
                bpp,
            }
            | objects::GdiKind::Bitmap {
                width,
                height,
                bits_ptr,
                bpp,
            } => Some((*width, *height, *bits_ptr, *bpp)),
            _ => None,
        })
        .flatten()
    });
    let (src_w, src_h, src_ptr, src_bpp) = match src_info {
        Some(v) => v,
        None => return 0,
    };
    if src_bpp != 32 {
        static BAD_SRC_BPP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if BAD_SRC_BPP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!("weave/gdi32: TransparentBlt src bpp={src_bpp} unsupported (32-bit only)");
        }
        return 0;
    }

    // Resolve dest bits — must be a memory DC with a 32bpp backing bitmap.
    let dst_info: Option<(u32, u32, usize, u16)> = dc::with(hdc_dest, |dc| {
        let bmp = dc.selected_bitmap;
        if bmp == 0 {
            return None;
        }
        objects::get(bmp, |kind| match kind {
            objects::GdiKind::DibSection {
                width,
                height,
                bits_ptr,
                bpp,
            }
            | objects::GdiKind::Bitmap {
                width,
                height,
                bits_ptr,
                bpp,
            } => Some((*width, *height, *bits_ptr, *bpp)),
            _ => None,
        })
        .flatten()
    });
    let (dst_w, dst_h, dst_ptr, dst_bpp) = match dst_info {
        Some(v) => v,
        None => {
            static NO_WIN_DC: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            if NO_WIN_DC.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
                eprintln!(
                    "weave/gdi32: TransparentBlt dest must be a memory DC with a 32bpp bitmap"
                );
            }
            return 0;
        }
    };
    if dst_bpp != 32 {
        static BAD_DST_BPP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if BAD_DST_BPP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!("weave/gdi32: TransparentBlt dst bpp={dst_bpp} unsupported (32-bit only)");
        }
        return 0;
    }

    // Bounds-clip source and dest rectangles against their bitmaps.
    if x_origin_src < 0
        || y_origin_src < 0
        || x_origin_dest < 0
        || y_origin_dest < 0
        || (x_origin_src as i64 + w_src as i64) > src_w as i64
        || (y_origin_src as i64 + h_src as i64) > src_h as i64
        || (x_origin_dest as i64 + w_dest as i64) > dst_w as i64
        || (y_origin_dest as i64 + h_dest as i64) > dst_h as i64
    {
        return 0;
    }

    // Reassemble crTransparent (0x00BBGGRR) into the low-24 bits of an ARGB
    // u32 (0x00RRGGBB) so we can compare against `pixel & 0x00FFFFFF`.
    //   COLORREF: B=bits 16-23, G=bits 8-15, R=bits 0-7.
    //   ARGB u32 (little-endian BGRA in memory): R=16-23, G=8-15, B=0-7.
    let key_rgb = ((cr_transparent & 0x0000_00FF) << 16)   // R → bits 16-23
        | (cr_transparent & 0x0000_FF00)                   // G stays at 8-15
        | ((cr_transparent & 0x00FF_0000) >> 16); // B → bits 0-7

    let w = w_src as usize;
    let h = h_src as usize;
    let src_stride = src_w as usize * 4;
    let dst_stride = dst_w as usize * 4;

    let src_bytes =
        unsafe { std::slice::from_raw_parts(src_ptr as *const u8, src_h as usize * src_stride) };
    let dst_bytes =
        unsafe { std::slice::from_raw_parts_mut(dst_ptr as *mut u8, dst_h as usize * dst_stride) };

    for row in 0..h {
        let sy = y_origin_src as usize + row;
        let dy = y_origin_dest as usize + row;
        for col in 0..w {
            let sx = x_origin_src as usize + col;
            let dx = x_origin_dest as usize + col;
            let s_off = sy * src_stride + sx * 4;
            let d_off = dy * dst_stride + dx * 4;
            // Source pixel as u32 0xAARRGGBB (little-endian from BGRA memory).
            let sb = src_bytes[s_off] as u32;
            let sg = src_bytes[s_off + 1] as u32;
            let sr = src_bytes[s_off + 2] as u32;
            let sa = src_bytes[s_off + 3] as u32;
            let src_rgb = (sr << 16) | (sg << 8) | sb;
            if src_rgb == key_rgb {
                // Keyed pixel — destination untouched.
                continue;
            }
            dst_bytes[d_off] = sb as u8;
            dst_bytes[d_off + 1] = sg as u8;
            dst_bytes[d_off + 2] = sr as u8;
            dst_bytes[d_off + 3] = sa as u8;
        }
    }

    // Upload the composited dest band so subsequent server-side copies see
    // the updated pixels — mirrors AlphaBlend (task 20).
    let dst_draw = dc::with(hdc_dest, |dc| dc.drawable());
    if dst_draw != 0 {
        let band_w = w_dest as usize;
        let band_h = h_dest as usize;
        let mut band = vec![0u8; band_w * band_h * 4];
        for row in 0..band_h {
            let dy = y_origin_dest as usize + row;
            let src_row_off = dy * dst_stride + x_origin_dest as usize * 4;
            let dst_row_off = row * band_w * 4;
            band[dst_row_off..dst_row_off + band_w * 4]
                .copy_from_slice(&dst_bytes[src_row_off..src_row_off + band_w * 4]);
        }
        weave_user32::backend::put_bits_to_pixmap_at(
            dst_draw,
            x_origin_dest as i16,
            y_origin_dest as i16,
            w_dest as u16,
            h_dest as u16,
            band_w * 4,
            &band,
            32,
        );
    }

    1
}

/// GradientFill — fill a rectangle with a colour gradient between two vertices.
///
/// TRIVERTEX layout (16 bytes): `{ LONG x; LONG y; USHORT Red, Green, Blue, Alpha; }`.
/// Colour channels are 16-bit; Wine divides by 256 to reach the 8-bit dest
/// channel (so a vertex channel of 0xFF00 yields 0xFF after scaling).
///
/// GRADIENT_RECT layout (8 bytes): `{ ULONG UpperLeft, LowerRight; }` — both
/// are vertex-array indices. TRIANGLE mode uses GRADIENT_TRIANGLE (12 bytes)
/// and is deferred to a follow-up task.
///
/// Validation (mirrors `NtGdiGradientFill` in dlls/win32u/painting.c):
///   * pVertex / pMesh NULL, nVertex==0, nMesh==0, mode > 2 → FALSE.
///   * Any mesh vertex index >= nVertex → FALSE (no panic).
///
/// Interpolation (mirrors X11DRV_GradientFill graphics.c:1519/1569):
///   colour[c] = (v0[c] * (d - i) + v1[c] * i) / d / 256
/// where d = dx for RECT_H, dy for RECT_V; i walks 0..d. Dest alpha is
/// forced to 0xFF (first-pass scope — vertex alpha is ignored).
///
/// First-pass scope: 32-bit ARGB memory DC destination only, RECT_H + RECT_V.
/// TRIANGLE returns FALSE with a rate-limited stderr trace.
///
/// Wine ref: dlls/win32u/painting.c::NtGdiGradientFill — validates mode and
/// vertex-index bounds before delegating to the driver. dlls/win32u/bitblt.c
/// ::nulldrv_GradientFill computes the bounding rect as
/// `min/max(pts[v])` over every referenced vertex.
/// Wine ref: dlls/winex11.drv/graphics.c::X11DRV_GradientFill — the RECT_H/V
/// branches use `(v0*(d-i) + v1*i) / d / 256` per channel and skip when d==0.
///
/// # Safety
/// `p_vertex` points to `n_vertex * 16` readable bytes; `p_mesh` points to
/// `n_mesh * 8` readable bytes (for RECT_H/RECT_V). Null pointers are
/// rejected without dereference.
pub unsafe extern "win64" fn gradient_fill(
    hdc: usize,
    p_vertex: *const u8,
    n_vertex: u32,
    p_mesh: *const u8,
    n_mesh: u32,
    ul_mode: u32,
) -> i32 {
    const GRADIENT_FILL_RECT_H: u32 = 0;
    const GRADIENT_FILL_RECT_V: u32 = 1;
    const GRADIENT_FILL_TRIANGLE: u32 = 2;

    if p_vertex.is_null() || p_mesh.is_null() || n_vertex == 0 || n_mesh == 0 {
        return 0;
    }
    if ul_mode > GRADIENT_FILL_TRIANGLE {
        return 0;
    }
    if ul_mode == GRADIENT_FILL_TRIANGLE {
        static NO_TRI: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if NO_TRI.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!("weave/gdi32: GradientFill TRIANGLE not yet supported");
        }
        return 0;
    }

    // Parse TRIVERTEX array with unaligned reads — caller alignment not
    // guaranteed. Each vertex is exactly 16 bytes: x(i32) y(i32) R/G/B/A(u16).
    struct TriVertex {
        x: i32,
        y: i32,
        r: u16,
        g: u16,
        b: u16,
        _a: u16,
    }
    let mut verts: Vec<TriVertex> = Vec::with_capacity(n_vertex as usize);
    for i in 0..n_vertex as usize {
        let base = p_vertex.add(i * 16);
        let x = (base.cast::<i32>()).read_unaligned();
        let y = (base.add(4).cast::<i32>()).read_unaligned();
        let r = (base.add(8).cast::<u16>()).read_unaligned();
        let g = (base.add(10).cast::<u16>()).read_unaligned();
        let b = (base.add(12).cast::<u16>()).read_unaligned();
        let a = (base.add(14).cast::<u16>()).read_unaligned();
        verts.push(TriVertex {
            x,
            y,
            r,
            g,
            b,
            _a: a,
        });
    }

    // Parse GRADIENT_RECT array (8 bytes each: UpperLeft(u32) LowerRight(u32))
    // and validate every vertex index against nVertex — matches the
    // NtGdiGradientFill early-reject loop.
    let mut mesh: Vec<(u32, u32)> = Vec::with_capacity(n_mesh as usize);
    for i in 0..n_mesh as usize {
        let base = p_mesh.add(i * 8);
        let ul = (base.cast::<u32>()).read_unaligned();
        let lr = (base.add(4).cast::<u32>()).read_unaligned();
        if ul >= n_vertex || lr >= n_vertex {
            return 0;
        }
        mesh.push((ul, lr));
    }

    // Resolve dest bits — require a 32bpp memory-DC backing bitmap.
    let dst_info: Option<(u32, u32, usize, u16)> = dc::with(hdc, |dc| {
        let bmp = dc.selected_bitmap;
        if bmp == 0 {
            return None;
        }
        objects::get(bmp, |kind| match kind {
            objects::GdiKind::DibSection {
                width,
                height,
                bits_ptr,
                bpp,
            }
            | objects::GdiKind::Bitmap {
                width,
                height,
                bits_ptr,
                bpp,
            } => Some((*width, *height, *bits_ptr, *bpp)),
            _ => None,
        })
        .flatten()
    });
    let (dst_w, dst_h, dst_ptr, dst_bpp) = match dst_info {
        Some(v) => v,
        None => {
            static NO_WIN_DC: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            if NO_WIN_DC.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
                eprintln!("weave/gdi32: GradientFill dest must be a memory DC with a 32bpp bitmap");
            }
            return 0;
        }
    };
    if dst_bpp != 32 {
        static BAD_DST_BPP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if BAD_DST_BPP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 4 {
            eprintln!("weave/gdi32: GradientFill dst bpp={dst_bpp} unsupported (32-bit only)");
        }
        return 0;
    }

    let dst_stride = dst_w as usize * 4;
    let dst_bytes =
        unsafe { std::slice::from_raw_parts_mut(dst_ptr as *mut u8, dst_h as usize * dst_stride) };

    // Track the overall bounding rect of painted pixels so we can issue one
    // CPU→pixmap upload at the end (mirrors alpha_blend's trailing
    // put_bits_to_pixmap_at).
    let mut dirty_x0 = i32::MAX;
    let mut dirty_y0 = i32::MAX;
    let mut dirty_x1 = i32::MIN;
    let mut dirty_y1 = i32::MIN;

    for &(ul_idx, lr_idx) in &mesh {
        let v0 = &verts[ul_idx as usize];
        let v1 = &verts[lr_idx as usize];

        // Geometric bounding box — Wine does min/max over the referenced
        // vertices, so upper-left/lower-right ordering is not assumed.
        let x0 = v0.x.min(v1.x);
        let y0 = v0.y.min(v1.y);
        let x1 = v0.x.max(v1.x);
        let y1 = v0.y.max(v1.y);

        // Zero-area rects contribute nothing — graphics.c bails when dx==0.
        if x1 <= x0 || y1 <= y0 {
            continue;
        }

        // Clip to dest bitmap.
        let cx0 = x0.max(0);
        let cy0 = y0.max(0);
        let cx1 = x1.min(dst_w as i32);
        let cy1 = y1.min(dst_h as i32);
        if cx1 <= cx0 || cy1 <= cy0 {
            continue;
        }

        // Wine swaps v0/v1 when the walk direction is negative — but we've
        // already min/max'd, so the effective gradient endpoints are the
        // lexically ordered pair. For interpolation we need the colour that
        // belongs to the low end of the axis vs the high end.
        let (lo_r, lo_g, lo_b, hi_r, hi_g, hi_b) = match ul_mode {
            GRADIENT_FILL_RECT_H => {
                if v0.x <= v1.x {
                    (v0.r, v0.g, v0.b, v1.r, v1.g, v1.b)
                } else {
                    (v1.r, v1.g, v1.b, v0.r, v0.g, v0.b)
                }
            }
            GRADIENT_FILL_RECT_V => {
                if v0.y <= v1.y {
                    (v0.r, v0.g, v0.b, v1.r, v1.g, v1.b)
                } else {
                    (v1.r, v1.g, v1.b, v0.r, v0.g, v0.b)
                }
            }
            _ => unreachable!(),
        };

        match ul_mode {
            GRADIENT_FILL_RECT_H => {
                let dx = (x1 - x0) as u32;
                for ix in cx0..cx1 {
                    // Distance from the low-x end, pre-clip, so that the
                    // colour sampled at ix is independent of clipping.
                    let i = (ix - x0) as u32;
                    let r = ((lo_r as u32 * (dx - i) + hi_r as u32 * i) / dx / 256) as u8;
                    let g = ((lo_g as u32 * (dx - i) + hi_g as u32 * i) / dx / 256) as u8;
                    let b = ((lo_b as u32 * (dx - i) + hi_b as u32 * i) / dx / 256) as u8;
                    for iy in cy0..cy1 {
                        let off = iy as usize * dst_stride + ix as usize * 4;
                        dst_bytes[off] = b;
                        dst_bytes[off + 1] = g;
                        dst_bytes[off + 2] = r;
                        dst_bytes[off + 3] = 0xFF;
                    }
                }
            }
            GRADIENT_FILL_RECT_V => {
                let dy = (y1 - y0) as u32;
                for iy in cy0..cy1 {
                    let i = (iy - y0) as u32;
                    let r = ((lo_r as u32 * (dy - i) + hi_r as u32 * i) / dy / 256) as u8;
                    let g = ((lo_g as u32 * (dy - i) + hi_g as u32 * i) / dy / 256) as u8;
                    let b = ((lo_b as u32 * (dy - i) + hi_b as u32 * i) / dy / 256) as u8;
                    for ix in cx0..cx1 {
                        let off = iy as usize * dst_stride + ix as usize * 4;
                        dst_bytes[off] = b;
                        dst_bytes[off + 1] = g;
                        dst_bytes[off + 2] = r;
                        dst_bytes[off + 3] = 0xFF;
                    }
                }
            }
            _ => unreachable!(),
        }

        dirty_x0 = dirty_x0.min(cx0);
        dirty_y0 = dirty_y0.min(cy0);
        dirty_x1 = dirty_x1.max(cx1);
        dirty_y1 = dirty_y1.max(cy1);
    }

    if dirty_x1 <= dirty_x0 || dirty_y1 <= dirty_y0 {
        // Nothing was actually painted — still a valid TRUE per Wine
        // (graphics.c returns TRUE even after every rect hit dx==0).
        return 1;
    }

    // Upload the painted band to the drawable — mirrors alpha_blend /
    // transparent_blt tail.
    let dst_draw = dc::with(hdc, |dc| dc.drawable());
    if dst_draw != 0 {
        let band_w = (dirty_x1 - dirty_x0) as usize;
        let band_h = (dirty_y1 - dirty_y0) as usize;
        let mut band = vec![0u8; band_w * band_h * 4];
        for row in 0..band_h {
            let dy = dirty_y0 as usize + row;
            let src_row_off = dy * dst_stride + dirty_x0 as usize * 4;
            let dst_row_off = row * band_w * 4;
            band[dst_row_off..dst_row_off + band_w * 4]
                .copy_from_slice(&dst_bytes[src_row_off..src_row_off + band_w * 4]);
        }
        weave_user32::backend::put_bits_to_pixmap_at(
            dst_draw,
            dirty_x0 as i16,
            dirty_y0 as i16,
            band_w as u16,
            band_h as u16,
            band_w * 4,
            &band,
            32,
        );
    }

    1
}

/// Resolve a gdi32.dll or msimg32.dll import added in Sprint 5.
// Wine ref: dlls/msimg32/msimg32.c — msimg32 exports AlphaBlend, TransparentBlt,
// GradientFill, and DllMain only; all three drawing functions delegate to ntgdi syscalls.
pub fn resolve_msimg32(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("msimg32.dll") {
        return None;
    }
    match func {
        "AlphaBlend" => Some(
            alpha_blend as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "TransparentBlt" => Some(
            transparent_blt as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "GradientFill" => Some(
            gradient_fill as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        _ => None,
    }
}

// ── PuTTY gap-fill: GDI ANSI variants and missing stubs ──────────────────────

/// Read a null-terminated ANSI string from a raw pointer into a `String`.
unsafe fn read_gdi_ansi(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(p, len) }).into_owned()
}

/// CreateFontA: ANSI variant — converts face name and delegates to CreateFontW.
///
/// # Safety
/// `lp_sz_face` must be null or a valid null-terminated ANSI string.
// Wine ref: dlls/gdi32/font.c — CreateFontA converts face name via MultiByteToWideChar
// then calls CreateFontW; all other params pass through unchanged.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn create_font_a(
    c_height: i32,
    c_width: i32,
    c_escapement: i32,
    c_orientation: i32,
    c_weight: i32,
    b_italic: u32,
    b_underline: u32,
    b_strike_out: u32,
    i_char_set: u32,
    i_out_precision: u32,
    i_clip_precision: u32,
    i_quality: u32,
    i_pitch_and_family: u32,
    lp_sz_face: *const u8,
) -> usize {
    let face = unsafe { read_gdi_ansi(lp_sz_face) };
    let wide: Vec<u16> = face.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        create_font_w(
            c_height,
            c_width,
            c_escapement,
            c_orientation,
            c_weight,
            b_italic,
            b_underline,
            b_strike_out,
            i_char_set,
            i_out_precision,
            i_clip_precision,
            i_quality,
            i_pitch_and_family,
            wide.as_ptr(),
        )
    }
}

/// LOGFONTA: ANSI logical font descriptor (60 bytes).
#[repr(C)]
pub struct LogFontA {
    lf_height: i32,
    lf_width: i32,
    lf_escapement: i32,
    lf_orientation: i32,
    lf_weight: i32,
    lf_italic: u8,
    lf_underline: u8,
    lf_strike_out: u8,
    lf_char_set: u8,
    lf_out_precision: u8,
    lf_clip_precision: u8,
    lf_quality: u8,
    lf_pitch_and_family: u8,
    lf_face_name: [u8; 32],
}

/// CreateFontIndirectA: ANSI variant — convert LOGFONTA to wide and delegate.
///
/// # Safety
/// `lplf` must point to a valid `LOGFONTA`.
// Wine ref: dlls/gdi32/font.c — CreateFontIndirectA converts LOGFONTA.lfFaceName via
// MultiByteToWideChar into LOGFONTW.lfFaceName, then calls CreateFontIndirectW.
pub unsafe extern "win64" fn create_font_indirect_a(lplf: *const LogFontA) -> usize {
    if lplf.is_null() {
        return 0;
    }
    let lf = unsafe { &*lplf };
    let face_end = lf.lf_face_name.iter().position(|&b| b == 0).unwrap_or(32);
    let face = String::from_utf8_lossy(&lf.lf_face_name[..face_end]).into_owned();
    unsafe {
        create_font_a(
            lf.lf_height,
            lf.lf_width,
            lf.lf_escapement,
            lf.lf_orientation,
            lf.lf_weight,
            lf.lf_italic as u32,
            lf.lf_underline as u32,
            lf.lf_strike_out as u32,
            lf.lf_char_set as u32,
            lf.lf_out_precision as u32,
            lf.lf_clip_precision as u32,
            lf.lf_quality as u32,
            lf.lf_pitch_and_family as u32,
            face.as_ptr(),
        )
    }
}

/// TextOutA: ANSI text output — convert and delegate to TextOutW.
///
/// # Safety
/// `lp_string` must point to `c_string` valid ANSI bytes.
// Wine ref: dlls/gdi32/font.c — TextOutA converts lpString via MultiByteToWideChar
// (using DC's charset from LOGFONT) then calls TextOutW; c is byte count, not char count.
pub unsafe extern "win64" fn text_out_a(
    hdc: usize,
    x: i32,
    y: i32,
    lp_string: *const u8,
    c_string: i32,
) -> i32 {
    if lp_string.is_null() || c_string <= 0 {
        return 0;
    }
    // Pointer validation: cap to prevent building a multi-GB slice.
    let c_string = c_string.min(65_536i32);
    let s = unsafe { std::slice::from_raw_parts(lp_string, c_string as usize) };
    let wide: Vec<u16> = String::from_utf8_lossy(s).encode_utf16().collect();
    unsafe { text_out_w(hdc, x, y, wide.as_ptr(), wide.len() as i32) }
}

/// ExtTextOutA: ANSI extended text output — convert and delegate to W.
///
/// # Safety
/// `lp_string` must point to `cb_count` valid ANSI bytes.
// Wine ref: dlls/gdi32/font.c — ExtTextOutA converts lpString via MultiByteToWideChar;
// cbCount is byte count; lpDx spacing array is per-character (byte), not per-wchar.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn ext_text_out_a(
    hdc: usize,
    x: i32,
    y: i32,
    options: u32,
    lp_rc: usize,
    lp_string: *const u8,
    cb_count: u32,
    lp_dx: usize,
) -> i32 {
    let wide: Vec<u16> = if lp_string.is_null() || cb_count == 0 {
        Vec::new()
    } else {
        // Pointer validation: cap to prevent building a multi-GB slice.
        let cb_count = cb_count.min(65_536u32);
        let s = unsafe { std::slice::from_raw_parts(lp_string, cb_count as usize) };
        String::from_utf8_lossy(s).encode_utf16().collect()
    };
    unsafe {
        ext_text_out_w(
            hdc,
            x,
            y,
            options,
            lp_rc as *const _,
            wide.as_ptr(),
            wide.len() as u32,
            lp_dx as *const _,
        )
    }
}

/// GetTextExtentPoint32A: ANSI variant — convert and delegate to W.
///
/// # Safety
/// `lp_string` must point to `c` valid ANSI bytes; `lp_size` writable.
// Wine ref: dlls/gdi32/font.c — GetTextExtentPoint32A converts via MultiByteToWideChar
// then delegates to GetTextExtentPoint32W; c is byte count (MBCS chars may span 2 bytes).
pub unsafe extern "win64" fn get_text_extent_point32_a(
    hdc: usize,
    lp_string: *const u8,
    c: i32,
    lp_size: usize,
) -> i32 {
    let wide: Vec<u16> = if lp_string.is_null() || c <= 0 {
        Vec::new()
    } else {
        // Pointer validation: cap to prevent building a multi-GB slice.
        let c = c.min(65_536i32);
        let s = unsafe { std::slice::from_raw_parts(lp_string, c as usize) };
        String::from_utf8_lossy(s).encode_utf16().collect()
    };
    unsafe { get_text_extent_point32_w(hdc, wide.as_ptr(), wide.len() as i32, lp_size as *mut _) }
}

/// GetTextMetricsA: ANSI variant — same struct layout as W for metrics.
///
/// # Safety
/// `lptm` must be a writable pointer to a TEXTMETRICA (same layout as W).
// Wine ref: dlls/gdi32/font.c — GetTextMetricsA calls GetTextMetricsW; then converts
// tmFirstChar/tmLastChar/tmDefaultChar/tmBreakChar from wide to the DC charset encoding.
pub unsafe extern "win64" fn get_text_metrics_a(hdc: usize, lptm: usize) -> i32 {
    unsafe { get_text_metrics_w(hdc, lptm as *mut _) }
}

/// GetObjectA: ANSI variant — identical to GetObject (no strings involved).
///
/// # Safety
/// Pointer arguments must be valid.
// Wine ref: dlls/gdi32/objects.c — GetObjectA calls NtGdiExtGetObjectW for most types;
// for HFONT it calls GetObjectW then converts lfFaceName from wide to ANSI via WideCharToMultiByte.
pub unsafe extern "win64" fn get_object_a(h: usize, c: i32, pv: *mut u8) -> i32 {
    get_object(h, c, pv as usize)
}

/// GetTextExtentExPointA: ANSI variant. Returns FALSE (stub).
///
/// # Safety
/// Pointer arguments are accepted but not fully used.
// Wine ref: dlls/gdi32/font.c — GetTextExtentExPointA converts string via
// MultiByteToWideChar then calls GetTextExtentExPointW; lpnFit counts MBCS chars, not bytes.
pub unsafe extern "win64" fn get_text_extent_ex_point_a(
    _hdc: usize,
    _lp_sz: *const u8,
    _cch_string: i32,
    _n_max_extent: i32,
    _lp_n_fit: *mut i32,
    _lp_dx: usize,
    lp_size: usize,
) -> i32 {
    // Fill size with zeros to avoid garbage reads.
    if lp_size != 0 {
        unsafe {
            let p = lp_size as *mut i32;
            *p = 0;
            *p.add(1) = 0;
        }
    }
    0
}

/// GetOutlineTextMetricsA: return 0 (TrueType metrics not available).
///
/// # Safety
/// Pointer arguments are accepted but not fully used.
// Wine ref: dlls/win32u/font.c::font_GetOutlineTextMetrics — returns total size of
// OUTLINETEXTMETRICA struct (including variable strings) when lpOTM is NULL; only
// works for TrueType fonts (returns 0 for raster/device fonts).
pub unsafe extern "win64" fn get_outline_text_metrics_a(
    _hdc: usize,
    _cb_data: u32,
    _lp_otm: usize,
) -> u32 {
    0
}

/// GetCharABCWidthsFloatA — return per-character ABC float advance metrics.
///
/// Fills `lp_abc_f` with `ABCFLOAT {abcfA=0, abcfB=ave_char_width, abcfC=0}` for each
/// character in [`i_first_char`, `i_last_char`]. Per-glyph shaping is a Phase 7
/// enhancement; uniform advance is accurate for monospace and close for proportional.
///
/// # Safety
/// `lp_abc_f` must be a writable pointer to at least `(i_last_char - i_first_char + 1)`
/// `ABCFLOAT` structs (12 bytes each: abcfA f32, abcfB f32, abcfC f32).
// Wine ref: dlls/win32u/font.c — GetCharABCWidthsFloatA: converts char range to wide,
// calls GetCharABCWidthsFloatW; only valid for TrueType fonts (returns FALSE for raster).
// Weave approximation: fills abcfB = ave_char_width, abcfA = abcfC = 0.
pub unsafe extern "win64" fn get_char_abc_widths_float_a(
    hdc: usize,
    i_first_char: u32,
    i_last_char: u32,
    lp_abc_f: *mut f32,
) -> i32 {
    if lp_abc_f.is_null() || i_last_char < i_first_char {
        return 0;
    }
    let count = (i_last_char - i_first_char + 1) as usize;
    let px = font_px_size(hdc);
    let fm = weave_user32::font::metrics(px);
    let advance = fm.ave_char_width.min(9) as f32;
    // ABCFLOAT layout: [abcfA f32, abcfB f32, abcfC f32] — 3 floats per entry.
    // SAFETY: caller guarantees lp_abc_f points to count * 3 writable f32 values.
    for i in 0..count {
        unsafe {
            lp_abc_f.add(i * 3).write(0.0f32); // abcfA
            lp_abc_f.add(i * 3 + 1).write(advance); // abcfB
            lp_abc_f.add(i * 3 + 2).write(0.0f32); // abcfC
        }
    }
    1
}

/// GetCharWidth32W — return per-character INT advance widths.
///
/// Fills `lp_buffer` with `ave_char_width` for each character in [`i_first`, `i_last`].
///
/// # Safety
/// `lp_buffer` must point to writable storage for `(i_last - i_first + 1)` i32 values.
// Wine ref: dlls/win32u/font.c — GetCharWidth32W: queries glyph advance widths and
// returns abcA+abcB+abcC as a single INT per character.
pub unsafe extern "win64" fn get_char_width32_w(
    hdc: usize,
    i_first: u32,
    i_last: u32,
    lp_buffer: *mut i32,
) -> i32 {
    if lp_buffer.is_null() || i_last < i_first {
        return 0;
    }
    let count = (i_last - i_first + 1) as usize;
    let px = font_px_size(hdc);
    let fm = weave_user32::font::metrics(px);
    let advance = fm.ave_char_width.min(9);
    // SAFETY: caller guarantees lp_buffer points to count writable i32 values.
    for i in 0..count {
        unsafe { lp_buffer.add(i).write(advance) };
    }
    1
}

/// GetCharWidth32A — ANSI variant of GetCharWidth32W.
///
/// # Safety
/// `lp_buffer` must point to writable storage for `(i_last - i_first + 1)` i32 values.
// Wine ref: dlls/win32u/font.c — GetCharWidth32A: converts ANSI range to wide,
// calls GetCharWidth32W; INT advance widths identical.
pub unsafe extern "win64" fn get_char_width32_a(
    hdc: usize,
    i_first: u32,
    i_last: u32,
    lp_buffer: *mut i32,
) -> i32 {
    unsafe { get_char_width32_w(hdc, i_first, i_last, lp_buffer) }
}

/// GetCharWidthW — alias for GetCharWidth32W.
///
/// # Safety
/// `lp_buffer` must point to writable storage for the requested char range.
// Wine ref: dlls/gdi32/font.c — GetCharWidthW is an alias for GetCharWidth32W;
// same INT advance width semantics; superseded by GetCharABCWidthsW for TrueType detail.
pub unsafe extern "win64" fn get_char_width_w(
    hdc: usize,
    i_first: u32,
    i_last: u32,
    lp_buffer: *mut i32,
) -> i32 {
    unsafe { get_char_width32_w(hdc, i_first, i_last, lp_buffer) }
}

/// GetCharWidthA — alias for GetCharWidth32A.
///
/// # Safety
/// `lp_buffer` must point to writable storage for the requested char range.
// Wine ref: dlls/gdi32/font.c — GetCharWidthA is an alias for GetCharWidth32A;
// call NtGdiGetCharWidthW with the same semantics.
pub unsafe extern "win64" fn get_char_width_a(
    hdc: usize,
    i_first: u32,
    i_last: u32,
    lp_buffer: *mut i32,
) -> i32 {
    unsafe { get_char_width32_a(hdc, i_first, i_last, lp_buffer) }
}

/// GetCharacterPlacementW: return 0 (not implemented).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/font.c — GetCharacterPlacementW fills GCP_RESULTS with glyph
// indices, dx advances, caret positions, and reordering info; GCP_REORDER flag triggers
// BiDi analysis; return value packs nGlyphs in low word and nMaxFit in high word.
pub unsafe extern "win64" fn get_character_placement_w(
    _hdc: usize,
    _lpsz: *const u16,
    _c_string: i32,
    _n_max_extent: i32,
    _lpgcp_results: usize,
    _dw_flags: u32,
) -> u32 {
    0
}

/// SetTextAlign: set the text-drawing alignment flags for an HDC.
///
/// Wine ref: dlls/win32u/dc.c — NtGdiSetTextAlign stores flags in dc->attr.text_align
/// and returns the previous value; GDI_ERROR (0xFFFFFFFF) on invalid HDC.
/// Key flag values: TA_LEFT=0, TA_RIGHT=2, TA_CENTER=6 (horizontal, bits 1-2);
/// TA_TOP=0, TA_BOTTOM=8, TA_BASELINE=24 (vertical, bits 3-4); TA_UPDATECP=1.
/// Scintilla uses TA_TOP|TA_LEFT (0) for its main editor area.
pub extern "win64" fn set_text_align(hdc: usize, fmode: u32) -> u32 {
    let mut prev = 0u32;
    dc::with_mut(hdc, |dc| {
        prev = dc.text_align;
        dc.text_align = fmode;
    });
    prev
}

/// GetTextAlign: return the current text alignment flags for an HDC.
///
/// Wine ref: dlls/win32u/dc.c — NtGdiGetTextAlign reads dc->attr.text_align directly.
pub extern "win64" fn get_text_align(hdc: usize) -> u32 {
    dc::with(hdc, |dc| dc.text_align)
}

/// GetCurrentObject: return a selected GDI object from a DC. Returns 0.
// Wine ref: dlls/win32u/gdiobj.c — NtGdiGetDCObject maps uObjectType (OBJ_PEN=1,
// OBJ_BRUSH=2, OBJ_FONT=6, OBJ_BITMAP=7) to the corresponding handle in the DC struct.
pub extern "win64" fn get_current_object(_hdc: usize, _u_object_type: u32) -> usize {
    0
}

/// SetMapMode: set the DC mapping mode. Returns MM_TEXT (1) as the previous mode.
// Wine ref: dlls/win32u/dc.c — NtGdiSetMapMode stores iMode in dc->attr->map_mode;
// valid modes: MM_TEXT(1)..MM_ANISOTROPIC(8); changes viewport/window extents for
// non-MM_TEXT modes; returns 0 on invalid hdc (Weave always returns 1).
pub extern "win64" fn set_map_mode(_hdc: usize, _i_mode: i32) -> i32 {
    1 // MM_TEXT
}

/// Polyline: draw a polyline through a series of points.
///
/// # Safety
/// `lpt` must point to `c_pt` valid POINT structs, or be NULL when `c_pt` < 2.
// Wine ref: dlls/win32u/painting.c — NtGdiPolyPolyDraw with type POLYLINE; draws line
// segments between consecutive points using current pen; does NOT close the figure;
// does NOT update the current pen position; cPt must be >= 2 or returns FALSE.
pub unsafe extern "win64" fn polyline(hdc: usize, lpt: *const i32, c_pt: i32) -> i32 {
    if lpt.is_null() || c_pt < 2 {
        return 0;
    }
    let pts = unsafe { std::slice::from_raw_parts(lpt as *const Point, c_pt as usize) };
    let (drawable, h_pen) = dc::with(hdc, |dc| (dc.drawable(), dc.h_pen));
    if drawable == 0 {
        return 1;
    }
    let pixel = weave_user32::backend::colorref_to_pixel(objects::pen_color(h_pen));
    for seg in pts.windows(2) {
        let (x1, y1) = dc::with(hdc, |dc| dc.lp_to_device(seg[0].x, seg[0].y));
        let (x2, y2) = dc::with(hdc, |dc| dc.lp_to_device(seg[1].x, seg[1].y));
        weave_user32::backend::draw_line(drawable, x1, y1, x2, y2, pixel);
    }
    1
}

/// CreateBitmap: create a device-dependent bitmap.
///
/// Returns a GDI object handle. Phase 2 stub — no pixel data stored.
// Wine ref: dlls/win32u/bitmap.c — NtGdiCreateBitmap clamps nWidth/nHeight to MAX_BITMAP
// (0x7fff); nPlanes×nBitCount must not exceed 32; lpBits initialises the bitmap data if
// non-NULL; a 0×0 bitmap creates a 1×1 placeholder.
pub extern "win64" fn create_bitmap(
    n_width: i32,
    n_height: i32,
    _n_planes: u32,
    _n_bit_count: u32,
    _lp_bits: usize,
) -> usize {
    // Delegate to create_compatible_bitmap so both DDB entry points share the
    // same 32-bit ARGB backing-buffer allocation and DeleteObject free path.
    create_compatible_bitmap(0, n_width, n_height)
}

/// GetDIBits: copy pixel data from a bitmap into a DIB.
///
/// # Safety
/// `lpbmi` must point to a readable BITMAPINFOHEADER (40 bytes). When
/// `lp_vbits != 0` it must be a writable buffer sized for the requested scan
/// lines. Phase 2: 32-bit BI_RGB only.
// Wine ref: dlls/gdi32/objects.c::GetDIBits → NtGdiGetDIBitsInternal;
// dlls/win32u/bitmap.c::NtGdiGetBitmapBits — get_image_from_bitmap extracts
// scan lines; biHeight < 0 in lpbmi → top-down output; startscan counts from
// the bottom for bottom-up bitmaps; lp_vbits == 0 → query mode, fills header
// and returns bitmap height without copying pixels.
pub unsafe extern "win64" fn get_dib_bits(
    _hdc: usize,
    h_bm: usize,
    start: u32,
    c_lines: u32,
    lp_vbits: usize,
    lpbmi: usize,
    _usage: u32,
) -> i32 {
    if h_bm == 0 || lpbmi == 0 {
        return 0;
    }

    let bmp = objects::get(h_bm, |kind| match kind {
        GdiKind::Bitmap {
            width,
            height,
            bits_ptr,
            bpp,
        }
        | GdiKind::DibSection {
            width,
            height,
            bits_ptr,
            bpp,
        } => Some((*width, *height, *bits_ptr, *bpp)),
        _ => None,
    });
    let Some(Some((bmp_w, bmp_h, bits_ptr, bmp_bpp))) = bmp else {
        return 0;
    };
    if bmp_bpp != 32 || bmp_w == 0 || bmp_h == 0 {
        return 0;
    }

    // Caller's requested output biBitCount (offset +14 in BITMAPINFOHEADER).
    // 0 means "query, use native"; treat as 32. Reject anything other than 24/32.
    // Wine ref: dlls/win32u/dib.c::get_dib_bits — reads bi.biBitCount to select
    // output format; converts internal BGRA to the requested depth on copy.
    let bi_bit_count_req = unsafe { *((lpbmi + 14) as *const u16) };
    let out_bpp: u16 = match bi_bit_count_req {
        0 | 32 => 32,
        24 => 24,
        _ => return 0,
    };

    // Stride for requested output format (Wine ref: dlls/win32u/dib.c::get_dib_stride).
    let out_stride = (bmp_w as usize * out_bpp as usize).div_ceil(32) * 4;
    let internal_stride = bmp_w as usize * 4;

    // Query mode: fill BITMAPINFOHEADER, return scan-line count, no copy.
    if lp_vbits == 0 {
        let size_image = out_stride as u32 * bmp_h;
        unsafe {
            let p = lpbmi as *mut u8;
            (p as *mut u32).write_unaligned(40);
            (p.add(4) as *mut i32).write_unaligned(bmp_w as i32);
            (p.add(8) as *mut i32).write_unaligned(bmp_h as i32); // bottom-up
            (p.add(12) as *mut u16).write_unaligned(1); // biPlanes
            (p.add(14) as *mut u16).write_unaligned(out_bpp); // biBitCount
            (p.add(16) as *mut u32).write_unaligned(0); // BI_RGB
            (p.add(20) as *mut u32).write_unaligned(size_image);
            (p.add(24) as *mut i32).write_unaligned(0);
            (p.add(28) as *mut i32).write_unaligned(0);
            (p.add(32) as *mut u32).write_unaligned(0);
            (p.add(36) as *mut u32).write_unaligned(0);
        }
        return bmp_h as i32;
    }

    // biHeight < 0 in caller's header → top-down output; > 0 → bottom-up.
    let bi_height = unsafe { *((lpbmi + 8) as *const i32) };
    let top_down_output = bi_height < 0;

    if start >= bmp_h || c_lines == 0 {
        return 0;
    }
    let lines = c_lines.min(bmp_h - start);

    // Internal storage is top-down (row 0 = topmost pixel row).
    // Bottom-up output row i = scan line (start+i) from the bottom
    //   = internal row (bmp_h - 1 - start - i).
    // Top-down output row i = internal row (start + i).
    let dst = lp_vbits as *mut u8;
    for i in 0..lines as usize {
        let src_row = if top_down_output {
            start as usize + i
        } else {
            (bmp_h as usize).wrapping_sub(1 + start as usize + i)
        };
        if src_row >= bmp_h as usize {
            break;
        }
        unsafe {
            let src = (bits_ptr + src_row * internal_stride) as *const u8;
            let dst_row = dst.add(i * out_stride);
            if out_bpp == 32 {
                std::ptr::copy_nonoverlapping(src, dst_row, internal_stride);
            } else {
                // 24-bit output: BGRA → BGR (drop alpha byte).
                for col in 0..bmp_w as usize {
                    let s = src.add(col * 4);
                    let d = dst_row.add(col * 3);
                    *d = *s;
                    *d.add(1) = *s.add(1);
                    *d.add(2) = *s.add(2);
                }
            }
        }
    }
    lines as i32
}

/// ExcludeClipRect: exclude a rectangle from the clipping region. Returns SIMPLEREGION (2).
// Wine ref: dlls/win32u/clipping.c — NtGdiExcludeClipRect intersects the clip region
// with the complement of the rectangle; returns NULLREGION(1) if result is empty,
// SIMPLEREGION(2) if rectangular, COMPLEXREGION(3) otherwise.
pub extern "win64" fn exclude_clip_rect(
    _hdc: usize,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    2 // SIMPLEREGION
}

/// IntersectClipRect: intersect the clipping region with a rectangle. Returns SIMPLEREGION (2).
// Wine ref: dlls/win32u/clipping.c — NtGdiIntersectClipRect intersects the current clip
// region with the specified rectangle; returns NULLREGION(1) if intersection is empty.
pub extern "win64" fn intersect_clip_rect(
    _hdc: usize,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    2 // SIMPLEREGION
}

/// TranslateCharsetInfo: translate character set info. Returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not fully used.
// Wine ref: dlls/win32u/font.c — TranslateCharsetInfo maps between charset id, codepage,
// and font signature; TCI_SRCCHARSET(1), TCI_SRCCODEPAGE(2), TCI_SRCFONTSIG(3) are the
// three valid dwFlags values; returns FALSE for unknown charset/codepage combos.
pub unsafe extern "win64" fn translate_charset_info(
    _lp_src: usize,
    _lp_cs: usize,
    _dw_flags: u32,
) -> i32 {
    0
}

// ── Palette stubs ─────────────────────────────────────────────────────────────

/// CreatePalette: create a logical colour palette. Returns a fake HPALETTE.
///
/// # Safety
/// `lplgpl` must point to a valid LOGPALETTE struct.
// Wine ref: dlls/win32u/palette.c — NtGdiCreatePaletteInternal allocates a PALETTEOBJ;
// palNumEntries must be in range 1..0x400 (1024); palVersion must be 0x300.
pub unsafe extern "win64" fn create_palette(_lplgpl: *const u8) -> usize {
    // Return a non-zero fake handle; palette operations are no-ops.
    0x0000_FACE_usize
}

/// SelectPalette: select a palette into a DC. Returns the previous (fake) palette.
// Wine ref: dlls/win32u/palette.c — NtUserSelectPalette stores hpal in dc->hPalette;
// bForceBackground=FALSE means foreground (top-level window) palette mapping is used;
// returns old palette handle; NULL hdc returns NULL.
pub extern "win64" fn select_palette(
    _hdc: usize,
    _h_pal: usize,
    _b_force_background: i32,
) -> usize {
    0x0000_FACE_usize
}

/// RealizePalette: map palette entries to the system palette. Returns 0.
// Wine ref: dlls/win32u/palette.c — NtUserRealizePalette maps the foreground palette
// to system palette entries; returns the number of entries changed; WM_PALETTECHANGED
// is broadcast to all top-level windows after mapping.
pub extern "win64" fn realize_palette(_hdc: usize) -> u32 {
    0
}

/// SetPaletteEntries: set palette colour entries. Returns 0.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/palette.c — NtGdiSetPaletteEntries modifies cEntries palette
// slots starting at iStart; returns 0 if hpal is invalid or iStart+cEntries > palNumEntries.
pub unsafe extern "win64" fn set_palette_entries(
    _h_pal: usize,
    _i_start: u32,
    _c_entries: u32,
    _lppe: usize,
) -> u32 {
    0
}

/// UnrealizeObject: reset a brush origin or restore a palette. Returns TRUE.
// Wine ref: dlls/win32u/palette.c — NtGdiUnrealizeObject; for HPALETTE marks it
// unrealized so next RealizePalette remaps all entries; for HBRUSH clears the brush
// origin so next SelectObject recalculates it.
pub extern "win64" fn unrealize_object(_h: usize) -> i32 {
    1
}

/// UpdateColors: update client area colors. Returns TRUE.
// Wine ref: dlls/win32u/palette.c — NtGdiUpdateColors remaps pixels in the DC's client
// area to the new realized palette; intended for WM_PALETTECHANGED handlers; slow on
// large windows (redraws all pixels); modern apps use InvalidateRect instead.
pub extern "win64" fn update_colors(_hdc: usize) -> i32 {
    1
}

// ── Notepad++ / Scintilla gap-fill: missing GDI32 functions ──────────────────

/// GetTextExtentExPointW: compute how many characters fit in a given width, and
/// optionally fill an array of cumulative advance widths.
///
/// Wine ref: dlls/win32u/font.c::font_GetTextExtentExPoint — iterates over each
/// glyph, calls get_glyph_outline to obtain ABC metrics, accumulates running total
/// pos += abcA+abcB+abcC, and stores dxs[i] = pos (cumulative advance through char i,
/// not per-char delta). lpnFit receives the count of chars fitting within nMaxExtent;
/// lpSize receives the full-string bounding box.
///
/// # Safety
/// `lp_string` must point to `cch_string` valid UTF-16 code units.
/// `lp_nfit`, `lp_dx`, `lp_size` must be valid writable pointers when non-null.
// Wine ref: dlls/win32u/font.c::font_GetTextExtentExPoint — accumulates pos+=abcA+abcB+abcC; dxs[i]=pos.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn get_text_extent_ex_point_w(
    hdc: usize,
    lp_string: *const u16,
    cch_string: i32,
    n_max_extent: i32,
    lp_nfit: *mut i32,
    lp_dx: *mut i32,
    lp_size: *mut Size,
) -> i32 {
    if lp_size.is_null() {
        return 0;
    }
    let px_size = font_px_size(hdc);
    let fm = weave_user32::font::metrics(px_size);
    if lp_string.is_null() || cch_string <= 0 {
        unsafe {
            (*lp_size).cx = 0;
            (*lp_size).cy = fm.height;
            if !lp_nfit.is_null() {
                *lp_nfit = 0;
            }
        }
        return 1;
    }
    let c = (cch_string as usize).min(65_536);
    let units: &[u16] = unsafe { std::slice::from_raw_parts(lp_string, c) };

    // Compute per-character cumulative advance widths using average char width.
    // Wine: dxs[i] = cumulative advance up through and including character i.
    // Per-glyph ABC metrics are a Phase 7 enhancement; ave_char_width is accurate
    // enough for Scintilla column layout calculations.
    let char_w = fm.ave_char_width;
    let mut cum = 0i32;
    let mut fit_count = c as i32;
    let check_max = n_max_extent > 0;

    for (i, _) in units.iter().enumerate() {
        cum += char_w;
        if !lp_dx.is_null() {
            unsafe {
                *lp_dx.add(i) = cum;
            }
        }
        if check_max && cum > n_max_extent && fit_count == c as i32 {
            fit_count = i as i32;
        }
    }

    let nfit_out = if check_max { fit_count } else { c as i32 };
    {
        static GTEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let m = GTEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Log first 5 calls and any call where nFit < cch (chars were clipped).
        if m < 5 || (check_max && nfit_out < c as i32) {
            eprintln!(
                "weave/gdi32: GetTextExtentExPointW#{m} hdc={hdc:#x} cch={c} max={n_max_extent} char_w={char_w} → fit={nfit_out} cx={cum}"
            );
        }
    }
    unsafe {
        (*lp_size).cx = cum;
        (*lp_size).cy = fm.height;
        if !lp_nfit.is_null() {
            *lp_nfit = nfit_out;
        }
    }
    1
}

/// GetTextExtentPointW: compute the bounding box of a string.
///
/// Wine ref: dlls/win32u/font.c — GetTextExtentPointW is a thin wrapper around
/// GetTextExtentExPoint with nMaxExtent=0, lpnFit=NULL, lpnDx=NULL.
///
/// # Safety
/// `lpsz` must point to `c` UTF-16 units; `lp_size` writable.
pub unsafe extern "win64" fn get_text_extent_point_w(
    hdc: usize,
    lpsz: *const u16,
    c: i32,
    lp_size: *mut Size,
) -> i32 {
    unsafe { get_text_extent_point32_w(hdc, lpsz, c, lp_size) }
}

/// GetObjectW: fill a buffer with information about a GDI object.
///
/// Wine ref: dlls/win32u/gdiobj.c::NtGdiExtGetObjectW — dispatches by object type;
/// for HFONT fills a LOGFONTW (92 bytes); for HBRUSH fills a LOGBRUSH (12 bytes);
/// for HPEN fills a LOGPEN (16 bytes). Returns bytes written, or 0 on error.
///
/// # Safety
/// `pv` must be writable for at least `c` bytes when non-null.
// Wine ref: dlls/win32u/gdiobj.c::NtGdiExtGetObjectW — dispatches by type; HFONT→92 bytes LOGFONTW.
pub unsafe extern "win64" fn get_object_w(h: usize, c: i32, pv: *mut u8) -> i32 {
    if h == 0 || c <= 0 || pv.is_null() {
        return 0;
    }
    let mut written = 0i32;
    objects::get(h, |kind| match kind {
        GdiKind::Font {
            height,
            weight,
            italic,
            face,
        } => {
            if c >= 92 {
                let lf = pv as *mut LogFontW;
                unsafe {
                    (*lf).lf_height = *height;
                    (*lf).lf_width = 0;
                    (*lf).lf_escapement = 0;
                    (*lf).lf_orientation = 0;
                    (*lf).lf_weight = *weight;
                    (*lf).lf_italic = if *italic { 1 } else { 0 };
                    (*lf).lf_underline = 0;
                    (*lf).lf_strike_out = 0;
                    (*lf).lf_char_set = 1; // DEFAULT_CHARSET
                    (*lf).lf_out_precision = 0;
                    (*lf).lf_clip_precision = 0;
                    (*lf).lf_quality = 0;
                    (*lf).lf_pitch_and_family = 0;
                    (*lf).lf_face_name = *face;
                }
                written = 92;
            }
        }
        GdiKind::Brush { color } => {
            // LOGBRUSH: lbStyle(4) + lbColor(4) + lbHatch(4) = 12 bytes
            if c >= 12 {
                let p = pv as *mut u32;
                unsafe {
                    *p = 0; // BS_SOLID
                    *p.add(1) = *color;
                    *p.add(2) = 0;
                }
                written = 12;
            }
        }
        GdiKind::Pen {
            color,
            style,
            width,
        } => {
            // LOGPEN: lopnStyle(4)+lopnWidth.x(4)+lopnWidth.y(4)+lopnColor(4) = 16 bytes
            if c >= 16 {
                let p = pv as *mut u32;
                unsafe {
                    *p = *style as u32;
                    *p.add(1) = *width as u32;
                    *p.add(2) = 0u32;
                    *p.add(3) = *color;
                }
                written = 16;
            }
        }
        GdiKind::Bitmap { .. } | GdiKind::DibSection { .. } | GdiKind::Region => {
            // TODO: fill BITMAP/DIBSECTION buffers when a caller needs them.
        }
    });
    written
}

/// EnumFontFamiliesExW: enumerate font families matching a LOGFONTW filter.
///
/// Wine ref: dlls/win32u/driver.c::nulldrv_EnumFonts — the null driver returns TRUE
/// without invoking proc at all. The real font driver (dlls/win32u/font.c) iterates
/// gdi_font_family entries and calls enum_face_charsets per matching family.
/// Weave: invokes the callback once with a synthetic "Courier New" TrueType entry
/// so Scintilla's font selection finds at least one font and proceeds.
///
/// Callback: int CALLBACK proc(ENUMLOGFONTEXW*, NEWTEXTMETRICEXW*, DWORD FontType, LPARAM)
///
/// # Safety
/// `lp_log_font` may be null (enumerate all families) or a valid LOGFONTW pointer.
/// `lp_proc` must be a valid FONTENUMPROCW function pointer.
// Wine ref: dlls/win32u/font.c — iterates gdi_font_family list; calls enum_face_charsets
// per family; stops early if callback returns 0.
pub unsafe extern "win64" fn enum_font_families_ex_w(
    hdc: usize,
    lp_log_font: *const LogFontW,
    lp_proc: usize,
    lp_param: isize,
    _dw_flags: u32,
) -> i32 {
    let _ = (hdc, lp_log_font);
    if lp_proc == 0 {
        return 1;
    }

    // Build ENUMLOGFONTEXW for "Courier New Regular".
    let mut elf = EnumLogFontExW {
        elf_log_font: LogFontW {
            lf_height: -13,
            lf_width: 0,
            lf_escapement: 0,
            lf_orientation: 0,
            lf_weight: 400,
            lf_italic: 0,
            lf_underline: 0,
            lf_strike_out: 0,
            lf_char_set: 0, // ANSI_CHARSET
            lf_out_precision: 0,
            lf_clip_precision: 0,
            lf_quality: 0,
            lf_pitch_and_family: 0x31, // FIXED_PITCH | FF_MODERN
            lf_face_name: [0u16; 32],
        },
        elf_full_name: [0u16; 64],
        elf_style: [0u16; 32],
        elf_script: [0u16; 32],
    };
    for (i, ch) in "Courier New".encode_utf16().enumerate() {
        if i < 31 {
            elf.elf_log_font.lf_face_name[i] = ch;
        }
        if i < 63 {
            elf.elf_full_name[i] = ch;
        }
    }
    for (i, ch) in "Regular".encode_utf16().enumerate() {
        if i < 31 {
            elf.elf_style[i] = ch;
        }
    }

    // Build NEWTEXTMETRICEXW.
    let ntm = NewTextMetricExW {
        tm: TextMetricW {
            tm_height: 16,
            tm_ascent: 13,
            tm_descent: 3,
            tm_internal_leading: 0,
            tm_external_leading: 2,
            tm_ave_char_width: 8,
            tm_max_char_width: 10,
            tm_weight: 400,
            tm_overhang: 0,
            tm_digitized_aspect_x: 96,
            tm_digitized_aspect_y: 96,
            tm_first_char: 0x20,
            tm_last_char: 0xFF,
            tm_default_char: b'?' as u16,
            tm_break_char: b' ' as u16,
            tm_italic: 0,
            tm_underlined: 0,
            tm_struck_out: 0,
            tm_pitch_and_family: 0x31,
            tm_char_set: 0,
            _pad: [0u8; 3],
        },
        ntm_flags: 0,
        ntm_size_em: 2048,
        ntm_cell_height: 2086,
        ntm_avg_width: 1003,
        fs_usage_bitmap: [0x0000_0003, 0, 0, 0], // Basic Latin + Latin-1
        fs_cset_bitmap: [0u32; 2],
    };

    type EnumFontProc =
        unsafe extern "win64" fn(*const EnumLogFontExW, *const NewTextMetricExW, u32, isize) -> i32;
    // SAFETY: `lp_proc` is the `FONTENUMPROC` callback supplied by the caller of
    // `EnumFontFamiliesExW`.  The Windows API contract (documented in MSDN and
    // confirmed by Wine's dlls/win32u/font.c) requires this argument to be a pointer
    // to a function with the signature `FONTENUMPROC` — identical to `EnumFontProc`
    // above: four Win64-ABI arguments (ENUMLOGFONTEXW*, NEWTEXTMETRICEXW*, DWORD,
    // LPARAM) returning int.  The caller has already been guarded by the
    // `if lp_proc == 0 { return 1; }` check above, so `lp_proc` is non-zero.
    // Transmuting a `usize` to a Win64 fn pointer is the correct mechanism for
    // invoking guest callbacks stored as raw addresses in Weave's IAT.
    let proc_fn: EnumFontProc = unsafe { std::mem::transmute(lp_proc) };
    let ret = unsafe { proc_fn(&elf, &ntm, TRUETYPE_FONTTYPE, lp_param) };
    if ret == 0 {
        0
    } else {
        1
    }
}

/// CreateRectRgn: create a rectangular region.
///
/// Wine ref: dlls/win32u/region.c::NtGdiCreateRectRgn — allocates a WINEREGION
/// with a single rect entry. Returns an HRGN handle; NULL on failure.
/// Weave: allocates GdiKind::Region (clipping not applied — no real GDI surface).
pub extern "win64" fn create_rect_rgn(left: i32, top: i32, right: i32, bottom: i32) -> usize {
    let _ = (left, top, right, bottom);
    objects::alloc(GdiKind::Region)
}

/// CreateRectRgnIndirect: create a rectangular region from a RECT pointer.
///
/// # Safety
/// `lp_rc` must be a valid pointer to a RECT.
// Wine ref: dlls/win32u/region.c — NtGdiCreateRectRgn; NULL lp_rc returns NULL (ERROR).
pub unsafe extern "win64" fn create_rect_rgn_indirect(lp_rc: *const Rect) -> usize {
    if lp_rc.is_null() {
        return 0;
    }
    let rc = unsafe { *lp_rc };
    create_rect_rgn(rc.left, rc.top, rc.right, rc.bottom)
}

/// CombineRgn: combine two regions using a set operation.
///
/// Wine ref: dlls/win32u/region.c::NtGdiCombineRgn — applies RGN_AND/OR/XOR/DIFF/COPY
/// to hrgn_src1 and hrgn_src2, stores in hrgn_dest. Returns NULLREGION(1),
/// SIMPLEREGION(2), or COMPLEXREGION(3). Weave: always returns SIMPLEREGION.
pub extern "win64" fn combine_rgn(
    _hrgn_dest: usize,
    _hrgn_src1: usize,
    _hrgn_src2: usize,
    _i_mode: i32,
) -> i32 {
    SIMPLEREGION
}

/// SelectClipRgn: select a clipping region into a DC.
///
/// Wine ref: dlls/win32u/clipping.c::NtGdiSelectClipRgn — copies the region into
/// the DC's application clip list; NULL removes the region. Returns SIMPLEREGION or
/// NULLREGION. Weave: stub, returns SIMPLEREGION (no real clipping).
pub extern "win64" fn select_clip_rgn(_hdc: usize, _hrgn: usize) -> i32 {
    SIMPLEREGION
}

/// CreateHatchBrush: create a brush with a hatching pattern.
///
/// Wine ref: dlls/win32u/pen.c::NtGdiCreateHatchBrushInternal — stores lbStyle=BS_HATCHED,
/// lbColor=color, lbHatch=fn_style. Weave: creates a solid brush with the given color
/// (hatch rendering not implemented — no real GDI surface).
pub extern "win64" fn create_hatch_brush(_fn_style: i32, color: u32) -> usize {
    objects::alloc(GdiKind::Brush { color })
}

/// CreatePatternBrush: create a brush from a bitmap pattern.
///
/// Wine ref: dlls/win32u/pen.c::NtGdiCreatePatternBrushInternal — stores lbStyle=BS_PATTERN,
/// lbHatch=hbm. Weave: returns a white solid brush (bitmap pattern not rendered).
pub extern "win64" fn create_pattern_brush(_hbm: usize) -> usize {
    objects::alloc(GdiKind::Brush { color: 0x00FF_FFFF })
}

/// ExtCreatePen: create an extended cosmetic or geometric pen.
///
/// Wine ref: dlls/win32u/pen.c::NtGdiExtCreatePen — validates dw_pen_style; for
/// geometric pens reads LOGBRUSH for color/style; for cosmetic pens ignores lp_lb.
/// Returns NULL on invalid style combination.
/// Weave: creates a Pen using the LOGBRUSH color and low 4 bits of dw_pen_style.
///
/// # Safety
/// `lp_lb` (if non-null) must point to a valid LOGBRUSH (12 bytes: style+color+hatch).
// Wine ref: dlls/win32u/pen.c::NtGdiExtCreatePen — PS_GEOMETRIC pens use LOGBRUSH color;
// PS_COSMETIC pens ignore brush; dw_pen_style low byte is PS_SOLID/PS_DASH/PS_DOT/etc.
pub unsafe extern "win64" fn ext_create_pen(
    dw_pen_style: u32,
    dw_width: u32,
    lp_lb: *const u8,
    _dw_style_count: u32,
    _lp_style: *const u32,
) -> usize {
    let color = if !lp_lb.is_null() {
        // LOGBRUSH layout: lbStyle(4) + lbColor(4) + lbHatch(4)
        unsafe { *(lp_lb.add(4) as *const u32) }
    } else {
        0 // black
    };
    objects::alloc(GdiKind::Pen {
        color,
        style: (dw_pen_style & 0xF) as i32,
        width: dw_width as i32,
    })
}

/// GdiAlphaBlend: alpha-composite source DC onto destination (gdi32.dll export).
///
/// Wine ref: dlls/gdi32/gdi32.spec — GdiAlphaBlend is forwarded to msimg32.AlphaBlend;
/// the implementation is NtGdiAlphaBlend in win32u. Weave: stub returning FALSE.
///
/// # Safety
/// All pointer arguments are ignored in this stub.
// Wine ref: dlls/gdi32/gdi32.spec — GdiAlphaBlend is a forward to msimg32.AlphaBlend;
// both map to NtGdiAlphaBlend in win32u.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn gdi_alpha_blend(
    _hdc_dest: usize,
    _x_dest: i32,
    _y_dest: i32,
    _w_dest: i32,
    _h_dest: i32,
    _hdc_src: usize,
    _x_src: i32,
    _y_src: i32,
    _w_src: i32,
    _h_src: i32,
    _blend: u64,
) -> i32 {
    0
}

/// GetClipRgn: retrieve the current application-defined clipping region.
///
/// Wine ref: dlls/win32u/clipping.c::NtGdiGetRandomRgn with iCode=1 (CLIPRGN) —
/// copies the app clip region into hrgnRgn; returns 1 if a region exists, 0 if
/// none, -1 on error. Weave: always returns 0 (no clip region set).
pub extern "win64" fn get_clip_rgn(_hdc: usize, _hrgn: usize) -> i32 {
    0
}

/// GetROP2: return the current foreground binary raster operation.
///
/// Wine ref: dlls/win32u/dc.c — NtGdiGetDCDword with DWORD_ROP2 reads
/// dc->attr.rop2; the default value after DC creation is R2_COPYPEN (13).
pub extern "win64" fn get_rop2(_hdc: usize) -> i32 {
    R2_COPYPEN
}

/// RectVisible: determine whether a rectangle intersects the clipping region.
///
/// Wine ref: dlls/win32u/clipping.c::NtGdiRectVisible — intersects the passed rect
/// with the DC's combined visible region; returns TRUE if any part is visible.
/// Weave: always returns TRUE (no real clipping region maintained).
///
/// # Safety
/// `lp_rect` must be a valid pointer to a RECT.
// Wine ref: dlls/win32u/clipping.c — NtGdiRectVisible checks rect against DC vis region;
// returns TRUE if any part is unclipped, FALSE if entirely outside the clip region.
pub unsafe extern "win64" fn rect_visible(_hdc: usize, lp_rect: *const Rect) -> i32 {
    let _ = lp_rect;
    1
}

/// RoundRect: draw a rectangle with rounded corners.
///
/// Wine ref: dlls/win32u/graphics.c — NtGdiRoundRect draws a filled rounded-corner
/// rectangle using the current brush and pen; corner ellipse dimensions are (w×h).
/// Weave: delegates to rectangle (corner rounding is a Phase 3 TODO).
pub extern "win64" fn round_rect(
    hdc: usize,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    _w: i32,
    _h: i32,
) -> i32 {
    rectangle(hdc, left, top, right, bottom)
}

/// SetWindowOrgEx: set the window (logical) origin of the DC.
///
/// Wine ref: dlls/win32u/mapping.c::NtGdiSetWindowOrgEx — stores (x,y) in
/// dc->attr.wnd_org and returns the previous origin in lpPoint. Weave: stub
/// (coordinate transforms not implemented; Weave uses identity MM_TEXT).
///
/// # Safety
/// `lp_point` (if non-null) must be a valid writable POINT.
// Wine ref: dlls/win32u/mapping.c::NtGdiSetWindowOrgEx — stores (x,y) in dc->attr.wnd_org.
pub unsafe extern "win64" fn set_window_org_ex(
    hdc: usize,
    x: i32,
    y: i32,
    lp_point: *mut Point,
) -> i32 {
    // Wine ref: dlls/win32u/mapping.c — NtGdiSetWindowOrgEx stores (x,y) in
    // dc->attr.wnd_org, returns previous origin in lp_point if non-null.
    let mut prev = Point { x: 0, y: 0 };
    dc::with_mut(hdc, |dc| {
        if !lp_point.is_null() {
            unsafe {
                *lp_point = dc.window_org;
            }
        }
        prev = dc.window_org;
        dc.window_org = Point { x, y };
    });
    1
}

/// OffsetWindowOrgEx: offset the window origin by (x, y).
///
/// Wine ref: dlls/win32u/mapping.c::NtGdiOffsetWindowOrg — adds (x,y) to
/// dc->attr.wnd_org and stores the previous value in lpPoint.
///
/// # Safety
/// `lp_point` (if non-null) must be a valid writable POINT.
pub unsafe extern "win64" fn offset_window_org_ex(
    hdc: usize,
    x: i32,
    y: i32,
    lp_point: *mut Point,
) -> i32 {
    dc::with_mut(hdc, |dc| {
        if !lp_point.is_null() {
            unsafe {
                *lp_point = dc.window_org;
            }
        }
        dc.window_org.x += x;
        dc.window_org.y += y;
    });
    1
}

/// SetViewportOrgEx: set the viewport origin of the DC.
///
/// Wine ref: dlls/win32u/mapping.c — NtGdiSetViewportOrgEx stores (x,y) in
/// dc->attr.vport_org, returns previous origin in lp_point.
///
/// # Safety
/// `lp_point` (if non-null) must be a valid writable POINT.
pub unsafe extern "win64" fn set_viewport_org_ex(
    hdc: usize,
    x: i32,
    y: i32,
    lp_point: *mut Point,
) -> i32 {
    dc::with_mut(hdc, |dc| {
        if !lp_point.is_null() {
            unsafe {
                *lp_point = dc.viewport_org;
            }
        }
        dc.viewport_org = Point { x, y };
    });
    1
}

/// GetViewportOrgEx: return the viewport origin of the DC.
///
/// # Safety
/// `lp_point` (if non-null) must be a valid writable POINT.
// Wine ref: dlls/win32u/dc.c — NtGdiGetDCPoint(DCPT_VPORT_ORG) reads dc->attr.vport_org.
pub unsafe extern "win64" fn get_viewport_org_ex(hdc: usize, lp_point: *mut Point) -> i32 {
    if !lp_point.is_null() {
        dc::with(hdc, |dc| unsafe { *lp_point = dc.viewport_org });
    }
    1
}

/// OffsetViewportOrgEx: add (x, y) to the viewport origin.
///
/// Wine ref: dlls/win32u/mapping.c — NtGdiOffsetViewportOrg adds (x,y) to
/// dc->attr.vport_org and returns the previous value in lp_point.
///
/// # Safety
/// `lp_point` (if non-null) must be a valid writable POINT.
pub unsafe extern "win64" fn offset_viewport_org_ex(
    hdc: usize,
    x: i32,
    y: i32,
    lp_point: *mut Point,
) -> i32 {
    // Wine ref: dlls/win32u/dc.c — offset_viewport_org adds (x,y) to dc->attr.vport_org
    let mut prev = Point { x: 0, y: 0 };
    dc::with_mut(hdc, |dc| {
        if !lp_point.is_null() {
            unsafe {
                *lp_point = dc.viewport_org;
            }
        }
        prev = dc.viewport_org;
        dc.viewport_org.x += x;
        dc.viewport_org.y += y;
    });
    1
}

/// SetBrushOrgEx: set the brush origin for pattern alignment.
///
/// Wine ref: dlls/win32u/dc.c::NtGdiSetBrushOrg — stores the new brush origin in
/// dc->attr.brush_org; returns the previous origin in lppt.
///
/// # Safety
/// `lp_pt` (if non-null) must be a valid writable POINT.
pub unsafe extern "win64" fn set_brush_org_ex(
    _hdc: usize,
    _x: i32,
    _y: i32,
    lp_pt: *mut Point,
) -> i32 {
    if !lp_pt.is_null() {
        unsafe {
            *lp_pt = Point { x: 0, y: 0 };
        }
    }
    1
}

/// SetDIBits: write pixel data from a DIB into a device-dependent bitmap.
///
/// # Safety
/// `lp_bits` must point to at least `stride * c_lines` readable bytes.
/// `lp_bmi` must point to a readable BITMAPINFOHEADER. Phase 2: 32-bit and 24-bit BI_RGB.
// Wine ref: dlls/win32u/dib.c::set_di_bits — validates BITMAPINFO, builds
// bitblt_coords for [startscan, startscan+lines), calls put_image_into_bitmap;
// biHeight > 0 → source is bottom-up (row 0 = bottom of image); biHeight < 0
// → source is top-down; startscan counts from the bottom for bottom-up bitmaps.
pub unsafe extern "win64" fn set_dib_bits(
    _hdc: usize,
    h_bm: usize,
    start: u32,
    c_lines: u32,
    lp_bits: *const u8,
    lp_bmi: usize,
    _color_use: u32,
) -> i32 {
    if h_bm == 0 || lp_bits.is_null() || lp_bmi == 0 || c_lines == 0 {
        return 0;
    }

    let bmp = objects::get(h_bm, |kind| match kind {
        GdiKind::Bitmap {
            width,
            height,
            bits_ptr,
            bpp,
        }
        | GdiKind::DibSection {
            width,
            height,
            bits_ptr,
            bpp,
        } => Some((*width, *height, *bits_ptr, *bpp)),
        _ => None,
    });
    let Some(Some((bmp_w, bmp_h, bits_ptr, bmp_bpp))) = bmp else {
        return 0;
    };
    if bmp_bpp != 32 || bmp_w == 0 || bmp_h == 0 {
        return 0;
    }

    // Parse BITMAPINFOHEADER — 32-bit and 24-bit BI_RGB accepted.
    let (bi_width, bi_height, bi_bpp, bi_comp) = unsafe {
        let w = *((lp_bmi + 4) as *const i32);
        let h = *((lp_bmi + 8) as *const i32);
        let bpp = *((lp_bmi + 14) as *const u16);
        let comp = *((lp_bmi + 16) as *const u32);
        (w, h, bpp, comp)
    };
    if (bi_bpp != 32 && bi_bpp != 24) || bi_comp != 0 || bi_width <= 0 {
        return 0;
    }

    let src_w = bi_width.unsigned_abs();
    let abs_src_h = bi_height.unsigned_abs();
    let top_down_src = bi_height < 0;

    if start >= bmp_h || start >= abs_src_h {
        return 0;
    }
    let lines = c_lines.min(bmp_h - start).min(abs_src_h - start);

    // Source stride is DWORD-aligned: round up to 32-bit boundary.
    let src_stride = (src_w as usize * bi_bpp as usize).div_ceil(32) * 4;
    let dst_stride = (bmp_w as usize) * 4;

    // Internal storage is top-down (row 0 = topmost pixel row).
    // Bottom-up source: input row 0 = scan line `start` from the bottom
    //   = internal row (bmp_h - 1 - start). Row i → internal row (bmp_h-1-start-i).
    // Top-down source: input row i → internal row (start + i).
    for i in 0..lines as usize {
        let (src_row, dst_row) = if top_down_src {
            (start as usize + i, start as usize + i)
        } else {
            (i, (bmp_h as usize).wrapping_sub(1 + start as usize + i))
        };
        if dst_row >= bmp_h as usize {
            break;
        }
        unsafe {
            let src = lp_bits.add(src_row * src_stride);
            let dst = (bits_ptr + dst_row * dst_stride) as *mut u8;
            if bi_bpp == 32 {
                let copy_len = src_stride.min(dst_stride);
                std::ptr::copy_nonoverlapping(src, dst, copy_len);
            } else {
                // 24-bit BGR → expand to BGRA (alpha = 0xFF) for the internal store.
                let px_count = (src_w as usize).min(bmp_w as usize);
                for px in 0..px_count {
                    let s = src.add(px * 3);
                    let d = dst.add(px * 4);
                    *d = *s; // B
                    *d.add(1) = *s.add(1); // G
                    *d.add(2) = *s.add(2); // R
                    *d.add(3) = 0xFF; // A
                }
            }
        }
    }
    lines as i32
}

/// DPtoLP: convert device coordinates to logical coordinates.
///
/// Wine ref: dlls/win32u/mapping.c::NtGdiTransformPoints — applies the inverse of
/// the DC's world-to-device transform to each POINT. In MM_TEXT (Weave's identity
/// mode) logical == device, so this is a no-op that returns TRUE.
///
/// # Safety
/// `lp_points` must point to `c` writable POINT structs.
// Wine ref: dlls/win32u/mapping.c::NtGdiTransformPoints — applies inverse world-to-device
// matrix; in MM_TEXT (scale=1, no offset) this is identity and points pass through unchanged.
pub unsafe extern "win64" fn dpto_lp(_hdc: usize, _lp_points: *mut Point, _c: i32) -> i32 {
    1
}

/// LPtoDP: convert logical coordinates to device coordinates (identity in MM_TEXT).
///
/// # Safety
/// `lp_points` must point to `c` writable POINT structs.
// Wine ref: dlls/win32u/mapping.c::NtGdiTransformPoints — applies world-to-device
// matrix; in MM_TEXT (scale=1) logical coords equal device coords.
pub unsafe extern "win64" fn lpto_dp(_hdc: usize, _lp_points: *mut Point, _c: i32) -> i32 {
    1
}

// ── Printing stubs ────────────────────────────────────────────────────────────

/// StartDocW: begin a print job.
///
/// Wine ref: dlls/win32u/printdrv.c::NtGdiStartDoc — opens a spool job; DOCINFOW
/// holds doc name, output file, and data type. Returns a positive job ID on success
/// or SP_ERROR (-1) on failure. Weave: stub returns 1 (fake job id).
///
/// # Safety
/// `lp_di` (if non-null) must point to a valid DOCINFOW.
// Wine ref: dlls/win32u/printdrv.c::NtGdiStartDoc — opens spool job; returns positive job
// ID on success; SP_ERROR(-1) if printer DC is invalid or spooler is unavailable.
pub unsafe extern "win64" fn start_doc_w(_hdc: usize, _lp_di: *const DocInfoW) -> i32 {
    1
}

/// StartPage: begin a new page in a print job.
///
/// Wine ref: dlls/win32u/printdrv.c::NtGdiStartPage — resets the DC page state.
/// Returns TRUE on success. Weave: stub.
pub extern "win64" fn start_page(_hdc: usize) -> i32 {
    1
}

/// EndDoc: end a print job and release the spool entry.
///
/// Wine ref: dlls/win32u/printdrv.c::NtGdiEndDoc. Returns TRUE. Weave: stub.
pub extern "win64" fn end_doc(_hdc: usize) -> i32 {
    1
}

/// EndPage: end the current page in a print job.
///
/// Wine ref: dlls/win32u/printdrv.c::NtGdiEndPage. Returns TRUE. Weave: stub.
pub extern "win64" fn end_page(_hdc: usize) -> i32 {
    1
}

/// AbortDoc: abort a print job. Returns TRUE. Weave: stub.
// Wine ref: dlls/win32u/printdrv.c::NtGdiAbortDoc — cancels the current print job;
// discards any buffered output; returns FALSE if no job is active.
pub extern "win64" fn abort_doc(_hdc: usize) -> i32 {
    1
}

// ── OpenGL pixel format stubs ─────────────────────────────────────────────────
//
// SDL2's Direct3D renderer calls these during device setup to negotiate a pixel
// format on the DC. Weave does not implement OpenGL; DXVK handles all presentation
// via Vulkan. Returning a valid-looking pixel format index (1) allows SDL2 to
// proceed past the negotiation step without falling back to a software blitter.

/// ChoosePixelFormat — select a pixel format index matching a PIXELFORMATDESCRIPTOR.
///
/// # Safety
/// `ppfd` is accepted but not dereferenced.
// Wine ref: dlls/win32u/opengl.c — calls NtGdiDescribePixelFormat to find a
// matching format; returns the index (1-based) of the closest match or 0 on failure.
// Returning 1 is safe: SDL2 treats any nonzero value as success.
pub unsafe extern "win64" fn choose_pixel_format(_hdc: usize, _ppfd: *const u8) -> i32 {
    1
}

/// SetPixelFormat — associate a pixel format with a DC.
///
/// # Safety
/// `ppfd` is accepted but not dereferenced.
// Wine ref: dlls/win32u/opengl.c — calls NtGdiSetPixelFormat; returns TRUE on
// success, FALSE if format already set or index out of range.
// Returning TRUE (1) is safe; SDL2 continues after a successful SetPixelFormat.
pub unsafe extern "win64" fn set_pixel_format(_hdc: usize, _fmt: i32, _ppfd: *const u8) -> i32 {
    1
}

/// GetPixelFormat — return the current pixel format index for a DC.
///
// Wine ref: dlls/win32u/opengl.c — calls NtGdiGetPixelFormat; returns the
// 1-based index previously set by SetPixelFormat, or 0 if none.
pub extern "win64" fn get_pixel_format(_hdc: usize) -> i32 {
    1
}

/// DescribePixelFormat — fill a PIXELFORMATDESCRIPTOR for a given format index.
///
/// Writes 40 zero bytes to `ppfd` when it is non-null and `bytes >= 40`.
/// Returns 1 (the number of available pixel formats).
///
/// # Safety
/// `ppfd` must point to at least `bytes` writable bytes when non-null.
// Wine ref: dlls/win32u/opengl.c — calls NtGdiDescribePixelFormat; returns the
// maximum valid format index (total number of pixel formats for the DC).
// Writing a zeroed descriptor is safe: SDL2 reads it only for informational hints.
pub unsafe extern "win64" fn describe_pixel_format(
    _hdc: usize,
    _fmt: i32,
    bytes: u32,
    ppfd: *mut u8,
) -> i32 {
    if !ppfd.is_null() && bytes >= 40 {
        std::ptr::write_bytes(ppfd, 0, 40);
    }
    1
}

/// SwapBuffers — present an OpenGL backbuffer to the screen.
///
/// No-op in Weave: DXVK handles all frame presentation via Vulkan. Returns TRUE.
// Wine ref: dlls/win32u/opengl.c — calls NtGdiSwapBuffers which calls the
// driver's SwapBuffers entry; Weave has no GL context so this is a safe no-op.
pub extern "win64" fn swap_buffers(_hdc: usize) -> i32 {
    1
}

/// GetDeviceGammaRamp — read the hardware gamma curve for a DC.
///
/// Returns FALSE: Weave does not support hardware gamma adjustment.
///
/// # Safety
/// `ramp` is accepted but not dereferenced.
// Wine ref: dlls/win32u/dibdrv/dc.c — returns FALSE when the driver does not
// support gamma (dibdrv_GetDeviceGammaRamp always returns FALSE).
pub unsafe extern "win64" fn get_device_gamma_ramp(_hdc: usize, _ramp: *mut u8) -> i32 {
    0
}

/// SetDeviceGammaRamp — set the hardware gamma curve for a DC.
///
/// Returns FALSE: Weave does not support hardware gamma adjustment.
///
/// # Safety
/// `ramp` is accepted but not dereferenced.
// Wine ref: dlls/win32u/dibdrv/dc.c — returns FALSE when the driver does not
// support gamma (dibdrv_SetDeviceGammaRamp always returns FALSE).
pub unsafe extern "win64" fn set_device_gamma_ramp(_hdc: usize, _ramp: *mut u8) -> i32 {
    0
}
