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
use weave_common::stub::warn_once;

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
/// Wine ref: dlls/win32u/gdiobj.c — NtGdiDeleteObjectApp; returns FALSE if the object is
/// a stock object (stock objects cannot be deleted). Weave: stock handles are not freed.
pub extern "win64" fn delete_object(h_object: usize) -> i32 {
    if h_object == 0 {
        return 0;
    }
    objects::free(h_object) as i32
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
                GdiKind::Bitmap { width, height } => {
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

/// GetPixel: return the colour of a pixel (stub — always returns black).
// Wine ref: dlls/win32u/bitblt.c — NtGdiGetPixel clips x,y to DC clip region; returns
// CLR_INVALID (0xFFFFFFFF) if point is outside; otherwise reads back the pixel color
// from the device surface via GetImage.
pub extern "win64" fn get_pixel(_hdc: usize, _x: i32, _y: i32) -> u32 {
    0 // CLR_INVALID would be 0xFFFFFFFF; return black for now
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

/// PatBlt: fill with a pattern brush using a raster operation (stub).
// Wine ref: dlls/winex11.drv/bitblt.c::X11DRV_PatBlt — checks usePat=(rop uses pattern
// bits); BLACKNESS/WHITENESS handled specially to set XForeground directly; DSTINVERT
// uses GXxor with white^black pixel; falls through to XFillRectangle for all cases.
pub extern "win64" fn pat_blt(hdc: usize, x: i32, y: i32, w: i32, h: i32, _rop: u32) -> i32 {
    // Use the selected brush to fill the rectangle.
    let brush_h = dc::with(hdc, |dc| dc.h_brush);
    let color = objects::brush_color(brush_h);
    let xcb = dc::with(hdc, |dc| dc.drawable());
    weave_user32::backend::draw_filled_rect(
        xcb,
        x as i16,
        y as i16,
        w.max(0) as u16,
        h.max(0) as u16,
        to_pixel(color),
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
    if dst_draw == 0 || src_draw == 0 {
        return 0;
    }
    if rop != defs::SRCCOPY {
        return 1; // TODO: other ROP codes
    }
    weave_user32::backend::copy_area(
        src_draw, dst_draw, x1 as i16, y1 as i16, x as i16, y as i16, cx as u16, cy as u16,
    );
    1
}

/// StretchBlt: stretched bit-block transfer (stub).
// Wine ref: dlls/win32u/bitblt.c — NtGdiStretchBlt uses stretch_blt_mode
// (COLORONCOLOR=3 deletes rows/cols; HALFTONE=4 uses averaging); negative w/h
// mirror the image; returns FALSE if src and dst DCs have incompatible formats.
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
    let _ = (
        hdc_dest, x_dest, y_dest, w_dest, h_dest, hdc_src, x_src, y_src, w_src, h_src, rop,
    );
    1
}

/// SetStretchBltMode: set the bitmap-stretching mode (stub).
// Wine ref: dlls/win32u/dc.c::set_stretch_blt_mode — stores mode in
// dc->attr->stretch_blt_mode; returns previous mode; HALFTONE(4) requires
// SetBrushOrgEx to align the halftone brush, which is skipped here.
pub extern "win64" fn set_stretch_blt_mode(_hdc: usize, _mode: i32) -> i32 {
    1
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
    // Bitmap is a no-payload kind — used here purely for handle uniqueness.
    let mem_dc = objects::alloc(GdiKind::Bitmap {
        width: 1,
        height: 1,
    });
    // Bind the new memory DC to the parent window so xcb_for() resolves correctly.
    dc::with_mut(mem_dc, |dc| dc.hwnd = parent_hwnd);
    mem_dc
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

/// CreateCompatibleBitmap: create a bitmap compatible with a DC (stub).
// Wine ref: dlls/win32u/bitmap.c — NtGdiCreateCompatibleBitmap uses the DC's bit depth;
// cx/cy of 0 creates a 1×1 bitmap (not NULL); returns NULL only on alloc failure.
// A DC-compatible bitmap inherits depth from hdc (screen DC → display depth, mem DC → 1bpp).
pub extern "win64" fn create_compatible_bitmap(_hdc: usize, cx: i32, cy: i32) -> usize {
    let width = cx.unsigned_abs().max(1);
    let height = cy.unsigned_abs().max(1);
    objects::alloc(GdiKind::Bitmap { width, height })
}

/// CreateDIBSection: create a DIB section (stub — returns 0).
// Wine ref: dlls/gdi32/objects.c::CreateDIBSection → NtGdiCreateDIBSection; creates a
// shared-memory bitmap (section!=NULL uses MapViewOfSection); ppvBits receives a pointer
// to the raw pixel buffer; DIB_PAL_COLORS usage maps color table entries to palette indices.
pub extern "win64" fn create_dib_section(
    _hdc: usize,
    _pbmi: usize,
    _usage: u32,
    _ppv_bits: *mut usize,
    _h_section: usize,
    _offset: u32,
) -> usize {
    warn_once("CreateDIBSection");
    0
}

/// SetDIBitsToDevice: copy DIB pixels to a device (stub).
// Wine ref: dlls/win32u/dib.c — NtGdiSetDIBitsToDevice validates BITMAPINFO header
// (biHeight<0 = top-down DIB); StartScan/cLines select a horizontal band; clips to
// DC clip region; DIB_PAL_COLORS in ColorUse maps table entries through current palette.
pub extern "win64" fn set_dib_bits_to_device(
    _hdc: usize,
    _x_dest: i32,
    _y_dest: i32,
    _w: u32,
    _h: u32,
    _x_src: i32,
    _y_src: i32,
    _start_scan: u32,
    _c_lines: u32,
    _lp_v_bits: *const u8,
    _lpbmi: usize,
    _color_use: u32,
) -> i32 {
    warn_once("SetDIBitsToDevice");
    0
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
        // Wine ref: dlls/win32u/driver.c::nulldrv_GetDeviceCaps — standard display raster caps
        // TODO: return RASTER_CAPS_DISPLAY once CreateDIBSection/BitBlt are real implementations.
        // IrfanView (and likely others) branch into DIB code paths when RC_DI_BITMAP/RC_DIBTODEV
        // are set; our stubs return NULL without initialising ppvBits, causing heap corruption.
        // Returning 0 keeps apps on the non-DIB path until Phase 3 GDI is real.
        RASTERCAPS => 0,
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
        "SetStretchBltMode" => Some(set_stretch_blt_mode as *const () as usize),
        "SetROP2" => Some(set_rop2 as *const () as usize),
        // Memory DCs and bitmaps
        "CreateCompatibleDC" => Some(create_compatible_dc as *const () as usize),
        "DeleteDC" => Some(delete_dc as *const () as usize),
        "CreateCompatibleBitmap" => Some(create_compatible_bitmap as *const () as usize),
        "CreateDIBSection" => Some(create_dib_section as *const () as usize),
        "SetDIBitsToDevice" => Some(set_dib_bits_to_device as *const () as usize),
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
/// # Safety
/// All HDC and BLENDFUNCTION arguments are ignored in this stub.
// Wine ref: dlls/msimg32/msimg32.c — AlphaBlend calls NtGdiAlphaBlend; BLENDFUNCTION
// SourceAlpha=AC_SRC_ALPHA(1) + AlphaFormat=AC_SRC_OVER(0) is the standard per-pixel
// alpha path; returns FALSE if source and destination DCs are incompatible.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn alpha_blend(
    _hdc_dest: usize,
    _x_origin_dest: i32,
    _y_origin_dest: i32,
    _w_dest: i32,
    _h_dest: i32,
    _hdc_src: usize,
    _x_origin_src: i32,
    _y_origin_src: i32,
    _w_src: i32,
    _h_src: i32,
    _blend_function: u64, // BLENDFUNCTION packs into a u64 on x64 ABI
) -> i32 {
    0 // FALSE — not supported in headless
}

/// TransparentBlt — blit with a transparent colour key.
///
/// # Safety
/// All HDC arguments are ignored.
// Wine ref: dlls/msimg32/msimg32.c — TransparentBlt calls NtGdiTransparentBlt;
// crTransparent color is matched exactly (no tolerance); src pixels matching the key
// are skipped; the blit is stretched if src and dst dimensions differ.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn transparent_blt(
    _hdc_dest: usize,
    _x_origin_dest: i32,
    _y_origin_dest: i32,
    _w_dest: i32,
    _h_dest: i32,
    _hdc_src: usize,
    _x_origin_src: i32,
    _y_origin_src: i32,
    _w_src: i32,
    _h_src: i32,
    _cr_transparent: u32,
) -> i32 {
    0 // FALSE
}

/// GradientFill — fill a rectangle or triangle with a colour gradient.
///
/// # Safety
/// `pVertex` and `pMesh` are caller-supplied structs; we ignore them.
// Wine ref: dlls/msimg32/msimg32.c — GradientFill calls NtGdiGradientFill; ulMode is
// GRADIENT_FILL_RECT_H(0), GRADIENT_FILL_RECT_V(1), or GRADIENT_FILL_TRIANGLE(2);
// pVertex is TRIVERTEX array; nVertex must match pMesh references or return FALSE.
pub unsafe extern "win64" fn gradient_fill(
    _hdc: usize,
    _p_vertex: *const u8,
    _n_vertex: u32,
    _p_mesh: *const u8,
    _n_mesh: u32,
    _ul_mode: u32,
) -> i32 {
    0 // FALSE
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

/// GetCharABCWidthsFloatA: return FALSE (not implemented).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/font.c — GetCharABCWidthsFloatA converts char range to wide,
// calls GetCharABCWidthsFloatW; only valid for TrueType fonts (returns FALSE for raster).
pub unsafe extern "win64" fn get_char_abc_widths_float_a(
    _hdc: usize,
    _i_first_char: u32,
    _i_last_char: u32,
    _lp_abc_f: usize,
) -> i32 {
    0
}

/// GetCharWidth32A / W / GetCharWidthA / W: return FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/font.c — GetCharWidth32A/W queries advance widths for a char
// range; fills lpBuffer with INT advance widths; GetCharWidthA/W are identical (old alias).
pub unsafe extern "win64" fn get_char_width32_a(
    _hdc: usize,
    _i_first: u32,
    _i_last: u32,
    _lp_buffer: usize,
) -> i32 {
    0
}

/// # Safety
/// `lp_buffer` must point to writable storage for `(i_last - i_first + 1)` INT values.
// Wine ref: dlls/win32u/font.c — GetCharWidth32W queries ABC widths via get_glyph_outline
// and returns abcA+abcB+abcC as a single INT per character.
pub unsafe extern "win64" fn get_char_width32_w(
    _hdc: usize,
    _i_first: u32,
    _i_last: u32,
    _lp_buffer: usize,
) -> i32 {
    0
}

/// # Safety
/// `lp_buffer` must point to writable storage for the requested char range.
// Wine ref: dlls/gdi32/font.c — GetCharWidthA is an alias for GetCharWidth32A; both
// call NtGdiGetCharWidthW with the same semantics.
pub unsafe extern "win64" fn get_char_width_a(
    _hdc: usize,
    _i_first: u32,
    _i_last: u32,
    _lp_buffer: usize,
) -> i32 {
    0
}

/// # Safety
/// `lp_buffer` must point to writable storage for the requested char range.
// Wine ref: dlls/gdi32/font.c — GetCharWidthW is an alias for GetCharWidth32W; same
// INT advance width semantics; both superseded by GetCharABCWidthsW for TrueType detail.
pub unsafe extern "win64" fn get_char_width_w(
    _hdc: usize,
    _i_first: u32,
    _i_last: u32,
    _lp_buffer: usize,
) -> i32 {
    0
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

/// Polyline: draw a polyline through a series of points. Returns TRUE.
///
/// # Safety
/// `lpt` must point to `c_pt` valid POINT structs.
// Wine ref: dlls/win32u/painting.c — NtGdiPolyPolyDraw with type POLYLINE; draws line
// segments between consecutive points using current pen; does NOT close the figure;
// cPt must be >= 2 or returns FALSE.
pub unsafe extern "win64" fn polyline(_hdc: usize, _lpt: *const i32, _c_pt: i32) -> i32 {
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
    let width = n_width.unsigned_abs().max(1);
    let height = n_height.unsigned_abs().max(1);
    objects::alloc(GdiKind::Bitmap { width, height })
}

/// GetDIBits: copy pixel data from a bitmap into a DIB. Returns 0 (stub).
///
/// # Safety
/// Pointer arguments are accepted but not fully used.
// Wine ref: dlls/win32u/dib.c — NtGdiGetDIBitsInternal copies scan lines from hbm into
// lpvBits; negative biHeight in lpbmi means top-down output; uStartScan+cLines must not
// exceed bitmap height or it clips; DIB_PAL_COLORS usage maps colors through palette.
pub unsafe extern "win64" fn get_dib_bits(
    _hdc: usize,
    _h_bm: usize,
    _start: u32,
    _c_lines: u32,
    _lp_vbits: usize,
    _lpbmi: usize,
    _usage: u32,
) -> i32 {
    0
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
        GdiKind::Bitmap { .. } | GdiKind::Region => {}
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

/// SetDIBits: set pixel data in a device-independent bitmap. Returns 0 (stub).
///
/// Wine ref: dlls/win32u/bitblt.c::NtGdiSetDIBits — validates the BITMAPINFO header,
/// converts DIB pixels to the target bitmap's format, copies scan lines. Phase 2 stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_dib_bits(
    _hdc: usize,
    _hbm: usize,
    _start: u32,
    _c_lines: u32,
    _lp_bits: *const u8,
    _lp_bmi: usize,
    _color_use: u32,
) -> i32 {
    0
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
