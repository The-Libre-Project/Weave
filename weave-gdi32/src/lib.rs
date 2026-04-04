//! gdi32.dll stubs for Weave.
//!
//! GDI object management, DC attributes, basic 2D drawing, and text rendering.
//! Actual rendering delegates to `weave_user32::backend` which holds the X11
//! connection. All stubs are safe to call even when no display is available —
//! drawing functions become no-ops on headless systems.
//!
//! # Text rendering (Phase 3)
//!
//! Text is rendered via fontdue (pure-Rust TrueType rasterizer). UTF-16 strings
//! are passed through without lossy conversion. System fonts are loaded from
//! standard Linux paths; if unavailable, falls back to X11 bitmap fonts.
//!
//! # Current simplifications
//!
//! - HDC == HWND (every DC is tied to its window; no memory DCs backed by
//!   real pixel buffers).
//! - Bitmaps, DIBs, and blitting are stubbed (return success codes, no pixels
//!   are transferred).

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

/// Resolve an HDC to the XCB window ID needed for drawing.
#[inline]
fn xcb_for(hdc: usize) -> u32 {
    weave_user32::window::xcb_id(hdc)
}

// ── GDI object creation / deletion ───────────────────────────────────────────

/// CreateSolidBrush: allocate a solid-colour brush.
pub extern "win64" fn create_solid_brush(color: u32) -> usize {
    objects::alloc(GdiKind::Brush { color })
}

/// CreatePen: allocate a cosmetic pen.
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
pub extern "win64" fn delete_object(h_object: usize) -> i32 {
    if h_object == 0 {
        return 0;
    }
    objects::free(h_object) as i32
}

/// GetStockObject: return a stock GDI object handle.
pub extern "win64" fn get_stock_object(i_object: i32) -> usize {
    if (0..=19).contains(&i_object) {
        objects::stock_handle(i_object)
    } else {
        0
    }
}

/// GetObject: fill a buffer with GDI object information (stub).
pub extern "win64" fn get_object(_h: usize, _c: i32, _pv: usize) -> i32 {
    0
}

// ── DC object selection ───────────────────────────────────────────────────────

/// SelectObject: bind a GDI object to a DC; returns the previously selected object.
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
                GdiKind::Bitmap => {
                    // In a real GDI, selecting a bitmap into a compatible DC
                    // changes the DC's drawing surface. Phase 2: stub.
                    old = 0;
                }
            });
        }
    });
    old
}

// ── DC attribute setters / getters ────────────────────────────────────────────

/// SetTextColor: set the foreground (text) colour. Returns the previous colour.
pub extern "win64" fn set_text_color(hdc: usize, color: u32) -> u32 {
    let mut prev = 0u32;
    dc::with_mut(hdc, |dc| {
        prev = dc.text_color;
        dc.text_color = color;
    });
    prev
}

/// GetTextColor: return the current text colour.
pub extern "win64" fn get_text_color(hdc: usize) -> u32 {
    dc::with(hdc, |dc| dc.text_color)
}

/// SetBkColor: set the background colour used by text and hatched brushes.
pub extern "win64" fn set_bk_color(hdc: usize, color: u32) -> u32 {
    let mut prev = 0u32;
    dc::with_mut(hdc, |dc| {
        prev = dc.bk_color;
        dc.bk_color = color;
    });
    prev
}

/// GetBkColor: return the current background colour.
pub extern "win64" fn get_bk_color(hdc: usize) -> u32 {
    dc::with(hdc, |dc| dc.bk_color)
}

/// SetBkMode: TRANSPARENT (1) or OPAQUE (2).
pub extern "win64" fn set_bk_mode(hdc: usize, i_bk_mode: i32) -> i32 {
    let mut prev = 0i32;
    dc::with_mut(hdc, |dc| {
        prev = dc.bk_mode;
        dc.bk_mode = i_bk_mode;
    });
    prev
}

/// GetBkMode: return the current background mode.
pub extern "win64" fn get_bk_mode(hdc: usize) -> i32 {
    dc::with(hdc, |dc| dc.bk_mode)
}

// ── Drawing primitives ────────────────────────────────────────────────────────

/// FillRect: fill a rectangle with a brush.
///
/// # Safety
/// `lp_rc` must be a valid pointer to a `RECT`.
pub unsafe extern "win64" fn fill_rect(hdc: usize, lp_rc: *const Rect, h_brush: usize) -> i32 {
    if lp_rc.is_null() {
        return 0;
    }
    let rc = unsafe { *lp_rc };
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
    let xcb = xcb_for(hdc);
    weave_user32::backend::draw_filled_rect(xcb, rc.left as i16, rc.top as i16, w, h, pixel);
    1
}

/// Rectangle: draw a filled rectangle with the current brush, outlined with the current pen.
pub extern "win64" fn rectangle(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) -> i32 {
    let w = (right - left).max(0) as u16;
    let h = (bottom - top).max(0) as u16;
    if w == 0 || h == 0 {
        return 1;
    }
    let xcb = xcb_for(hdc);
    let (brush_h, pen_h) = dc::with(hdc, |dc| (dc.h_brush, dc.h_pen));

    // Fill interior with brush.
    let fill_pixel = to_pixel(objects::brush_color(brush_h));
    weave_user32::backend::draw_filled_rect(xcb, left as i16, top as i16, w, h, fill_pixel);

    // Draw outline with pen.
    let outline_pixel = to_pixel(objects::pen_color(pen_h));
    weave_user32::backend::draw_rect_outline(xcb, left as i16, top as i16, w, h, outline_pixel);
    1
}

/// Ellipse: draw an ellipse (stub in Phase 2 — renders as a rectangle).
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
/// # Safety
/// `lp_string` must be a valid pointer to `c` UTF-16 code units.
pub unsafe extern "win64" fn text_out_w(
    hdc: usize,
    x: i32,
    y: i32,
    lp_string: *const u16,
    c: i32,
) -> i32 {
    if lp_string.is_null() || c <= 0 {
        return 0;
    }
    let (fg, bg) = dc::with(hdc, |dc| (dc.text_color, dc.bk_color));
    let fg_pixel = to_pixel(fg);
    let bg_pixel = to_pixel(bg);
    let units: &[u16] = unsafe { std::slice::from_raw_parts(lp_string, c as usize) };
    let xcb = xcb_for(hdc);
    let px_size = font_px_size(hdc);
    weave_user32::backend::draw_text_utf16(
        xcb, x as i16, y as i16, units, px_size, fg_pixel, bg_pixel,
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

    // Determine length.
    let len = if n_count < 0 {
        let mut i = 0usize;
        while unsafe { *lp_string.add(i) } != 0 {
            i += 1;
        }
        i
    } else {
        n_count as usize
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
    let xcb = xcb_for(hdc);
    weave_user32::backend::draw_text_utf16(
        xcb,
        x as i16,
        y as i16,
        units,
        px_size,
        to_pixel(fg),
        to_pixel(bg),
    );
    text_h
}

/// DrawTextA: ANSI variant — decode the byte string and delegate to draw_text_w.
///
/// # Safety
/// `lp_string` must point to `n_count` bytes (or a null-terminated string if n_count == -1).
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
    let len = if n_count < 0 {
        let mut i = 0usize;
        while unsafe { *lp_string.add(i) } != 0 {
            i += 1;
        }
        i
    } else {
        n_count as usize
    };
    let bytes = unsafe { std::slice::from_raw_parts(lp_string, len) };
    // Encode as UTF-16 for draw_text_w.
    let wide: Vec<u16> = bytes.iter().map(|&b| b as u16).collect();
    unsafe { draw_text_w(hdc, wide.as_ptr(), wide.len() as i32, lp_rect, u_format) }
}

/// ExtTextOutW: extended text drawing (Phase 2: delegates to text_out_w).
///
/// # Safety
/// `lp_string` must point to `c` valid UTF-16 code units.
pub unsafe extern "win64" fn ext_text_out_w(
    hdc: usize,
    x: i32,
    y: i32,
    _options: u32,
    _lp_rc: *const Rect,
    lp_string: *const u16,
    c: u32,
    _lp_dx: *const i32,
) -> i32 {
    unsafe { text_out_w(hdc, x, y, lp_string, c as i32) }
}

/// SetPixel: draw a single pixel.
pub extern "win64" fn set_pixel(hdc: usize, x: i32, y: i32, color: u32) -> u32 {
    let pixel = to_pixel(color);
    let xcb = xcb_for(hdc);
    weave_user32::backend::draw_filled_rect(xcb, x as i16, y as i16, 1, 1, pixel);
    color
}

/// GetPixel: return the colour of a pixel (stub — always returns black).
pub extern "win64" fn get_pixel(_hdc: usize, _x: i32, _y: i32) -> u32 {
    0 // CLR_INVALID would be 0xFFFFFFFF; return black for now
}

/// MoveToEx: set the current pen position.
///
/// # Safety
/// `lp_point` (if non-null) must be a valid writable pointer to a `POINT`.
pub unsafe extern "win64" fn move_to_ex(hdc: usize, x: i32, y: i32, lp_point: *mut Point) -> i32 {
    // Phase 2: no pen position in DC state — stub.
    if !lp_point.is_null() {
        unsafe { *lp_point = Point { x, y } };
    }
    let _ = hdc;
    1
}

/// LineTo: draw a line from the current position to (x, y) (stub).
pub extern "win64" fn line_to(_hdc: usize, _x: i32, _y: i32) -> i32 {
    // TODO Phase 3: real line drawing.
    1
}

/// Polygon: draw a filled polygon (stub).
pub extern "win64" fn polygon(_hdc: usize, _apt: *const Point, _cpt: i32) -> i32 {
    1
}

/// PatBlt: fill with a pattern brush using a raster operation (stub).
pub extern "win64" fn pat_blt(hdc: usize, x: i32, y: i32, w: i32, h: i32, _rop: u32) -> i32 {
    // Use the selected brush to fill the rectangle.
    let brush_h = dc::with(hdc, |dc| dc.h_brush);
    let color = objects::brush_color(brush_h);
    let xcb = xcb_for(hdc);
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

/// BitBlt: bit-block transfer (stub — returns TRUE, no pixels transferred).
pub extern "win64" fn bit_blt(
    _hdc_dest: usize,
    _x: i32,
    _y: i32,
    _cx: i32,
    _cy: i32,
    _hdc_src: usize,
    _x1: i32,
    _y1: i32,
    _rop: u32,
) -> i32 {
    1
}

/// StretchBlt: stretched bit-block transfer (stub).
pub extern "win64" fn stretch_blt(
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
    _rop: u32,
) -> i32 {
    1
}

/// SetStretchBltMode: set the bitmap-stretching mode (stub).
pub extern "win64" fn set_stretch_blt_mode(_hdc: usize, _mode: i32) -> i32 {
    1
}

/// SetROP2: set the foreground mix mode (stub).
pub extern "win64" fn set_rop2(_hdc: usize, _rop2: i32) -> i32 {
    1
}

// ── Memory DC and bitmap stubs ────────────────────────────────────────────────

/// CreateCompatibleDC: create an off-screen DC (stub — returns the source HDC).
pub extern "win64" fn create_compatible_dc(hdc: usize) -> usize {
    // Phase 2: return a fake HDC. No pixel buffer is allocated.
    // The value 0x00FF_FF00 is chosen to be visually distinct from valid HWNDs.
    let _ = hdc;
    0x00FF_FF00
}

/// DeleteDC: delete a DC created by CreateCompatibleDC (stub).
pub extern "win64" fn delete_dc(hdc: usize) -> i32 {
    dc::remove(hdc);
    1
}

/// CreateCompatibleBitmap: create a bitmap compatible with a DC (stub).
pub extern "win64" fn create_compatible_bitmap(hdc: usize, cx: i32, cy: i32) -> usize {
    let _ = (hdc, cx, cy);
    objects::alloc(GdiKind::Bitmap)
}

/// CreateDIBSection: create a DIB section (stub — returns 0).
pub extern "win64" fn create_dib_section(
    _hdc: usize,
    _pbmi: usize,
    _usage: u32,
    _ppv_bits: *mut usize,
    _h_section: usize,
    _offset: u32,
) -> usize {
    0
}

/// SetDIBitsToDevice: copy DIB pixels to a device (stub).
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
    0
}

// ── Text metrics ──────────────────────────────────────────────────────────────

/// GetTextMetricsW: return metrics for the selected font.
///
/// # Safety
/// `lptm` must be a valid writable pointer to a `TEXTMETRICW`.
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
        tm.tm_ave_char_width = fm.ave_char_width;
        tm.tm_max_char_width = fm.ave_char_width + 2;
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
/// # Safety
/// `lpsz` must be a valid pointer to `c` UTF-16 code units.
/// `lp_size` must be a valid writable pointer to a `SIZE`.
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
    let units: &[u16] = unsafe { std::slice::from_raw_parts(lpsz, c as usize) };
    let (w, h) = weave_user32::font::measure_text(units, px_size);
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
pub extern "win64" fn get_device_caps(hdc: usize, n_index: i32) -> i32 {
    let _ = hdc;
    match n_index {
        HORZRES => 1920,
        VERTRES => 1080,
        BITSPIXEL => 32,
        PLANES => 1,
        LOGPIXELSX => 96,
        LOGPIXELSY => 96,
        RASTERCAPS => 0, // no raster capabilities special bits
        _ => 0,
    }
}

// ── DC clipping ───────────────────────────────────────────────────────────────

/// GetClipBox: return the bounding rectangle of the current clipping region (stub).
///
/// # Safety
/// `lp_rect` must be a valid writable pointer to a `RECT`.
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
pub unsafe extern "win64" fn get_dc_org_ex(_hdc: usize, lp_point: *mut Point) -> i32 {
    if !lp_point.is_null() {
        unsafe { *lp_point = Point { x: 0, y: 0 } };
    }
    1
}

// ── DC save/restore ───────────────────────────────────────────────────────────

/// SaveDC: save the current DC state onto an internal stack (stub).
pub extern "win64" fn save_dc(_hdc: usize) -> i32 {
    1 // returns save-state ID; Phase 2: always 1
}

/// RestoreDC: restore a previously saved DC state (stub).
pub extern "win64" fn restore_dc(_hdc: usize, _n_saved_dc: i32) -> i32 {
    1
}

// ── D3DKMT adapter stubs ──────────────────────────────────────────────────────

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn d3dkmt_open_adapter_from_hdc(_p_data: usize) -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn d3dkmt_close_adapter(_p_data: usize) -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn d3dkmt_create_device(_p_data: usize) -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn d3dkmt_destroy_device(_p_data: usize) -> u32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn d3dkmt_query_adapter_info(_p_data: usize) -> u32 {
    0xC000_0001u32
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn d3dkmt_set_vid_pn_source_owner(_p_data: usize) -> u32 {
    0
}

// ── Resolve ───────────────────────────────────────────────────────────────────

/// Resolve a `gdi32.dll` import to a stub address.
///
/// Also handles a small set of GDI functions that Windows re-exports from
/// `user32.dll` (FillRect, DrawTextW, DrawTextA). Binaries compiled with
/// MinGW may import these from either DLL name.
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
            create_font_a
                as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CreateFontIndirectA" => Some(
            create_font_indirect_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "TextOutA" => Some(
            text_out_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "ExtTextOutA" => Some(
            ext_text_out_a
                as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "GetTextExtentPoint32A" => Some(
            get_text_extent_point32_a
                as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "GetTextMetricsA" => Some(
            get_text_metrics_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetObjectA" => Some(
            get_object_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetTextExtentExPointA" => Some(
            get_text_extent_ex_point_a
                as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "GetOutlineTextMetricsA" => Some(
            get_outline_text_metrics_a
                as unsafe extern "win64" fn(_, _, _) -> _
                as *const () as usize,
        ),
        "GetCharABCWidthsFloatA" => Some(
            get_char_abc_widths_float_a
                as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
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
            get_character_placement_w
                as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "SetTextAlign" => Some(set_text_align as *const () as usize),
        "GetCurrentObject" => Some(get_current_object as *const () as usize),
        "SetMapMode" => Some(set_map_mode as *const () as usize),
        "Polyline" => Some(
            polyline as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CreateBitmap" => Some(create_bitmap as *const () as usize),
        "GetDIBits" => Some(
            get_dib_bits
                as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "ExcludeClipRect" => Some(exclude_clip_rect as *const () as usize),
        "IntersectClipRect" => Some(intersect_clip_rect as *const () as usize),
        "TranslateCharsetInfo" => Some(
            translate_charset_info
                as unsafe extern "win64" fn(_, _, _) -> _
                as *const () as usize,
        ),
        // Palette functions
        "CreatePalette" => Some(
            create_palette as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SelectPalette" => Some(select_palette as *const () as usize),
        "RealizePalette" => Some(realize_palette as *const () as usize),
        "SetPaletteEntries" => Some(
            set_palette_entries as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "UnrealizeObject" => Some(unrealize_object as *const () as usize),
        "UpdateColors" => Some(update_colors as *const () as usize),
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
            c_height, c_width, c_escapement, c_orientation, c_weight,
            b_italic, b_underline, b_strike_out, i_char_set,
            i_out_precision, i_clip_precision, i_quality, i_pitch_and_family,
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
pub unsafe extern "win64" fn create_font_indirect_a(lplf: *const LogFontA) -> usize {
    if lplf.is_null() {
        return 0;
    }
    let lf = unsafe { &*lplf };
    let face_end = lf.lf_face_name.iter().position(|&b| b == 0).unwrap_or(32);
    let face = String::from_utf8_lossy(&lf.lf_face_name[..face_end]).into_owned();
    unsafe {
        create_font_a(
            lf.lf_height, lf.lf_width, lf.lf_escapement, lf.lf_orientation,
            lf.lf_weight, lf.lf_italic as u32, lf.lf_underline as u32,
            lf.lf_strike_out as u32, lf.lf_char_set as u32,
            lf.lf_out_precision as u32, lf.lf_clip_precision as u32,
            lf.lf_quality as u32, lf.lf_pitch_and_family as u32,
            face.as_ptr(),
        )
    }
}

/// TextOutA: ANSI text output — convert and delegate to TextOutW.
///
/// # Safety
/// `lp_string` must point to `c_string` valid ANSI bytes.
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
    let s = unsafe { std::slice::from_raw_parts(lp_string, c_string as usize) };
    let wide: Vec<u16> = String::from_utf8_lossy(s).encode_utf16().collect();
    unsafe { text_out_w(hdc, x, y, wide.as_ptr(), wide.len() as i32) }
}

/// ExtTextOutA: ANSI extended text output — convert and delegate to W.
///
/// # Safety
/// `lp_string` must point to `cb_count` valid ANSI bytes.
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
        let s = unsafe { std::slice::from_raw_parts(lp_string, cb_count as usize) };
        String::from_utf8_lossy(s).encode_utf16().collect()
    };
    unsafe {
        ext_text_out_w(
            hdc, x, y, options, lp_rc as *const _,
            wide.as_ptr(), wide.len() as u32, lp_dx as *const _,
        )
    }
}

/// GetTextExtentPoint32A: ANSI variant — convert and delegate to W.
///
/// # Safety
/// `lp_string` must point to `c` valid ANSI bytes; `lp_size` writable.
pub unsafe extern "win64" fn get_text_extent_point32_a(
    hdc: usize,
    lp_string: *const u8,
    c: i32,
    lp_size: usize,
) -> i32 {
    let wide: Vec<u16> = if lp_string.is_null() || c <= 0 {
        Vec::new()
    } else {
        let s = unsafe { std::slice::from_raw_parts(lp_string, c as usize) };
        String::from_utf8_lossy(s).encode_utf16().collect()
    };
    unsafe { get_text_extent_point32_w(hdc, wide.as_ptr(), wide.len() as i32, lp_size as *mut _) }
}

/// GetTextMetricsA: ANSI variant — same struct layout as W for metrics.
///
/// # Safety
/// `lptm` must be a writable pointer to a TEXTMETRICA (same layout as W).
pub unsafe extern "win64" fn get_text_metrics_a(hdc: usize, lptm: usize) -> i32 {
    unsafe { get_text_metrics_w(hdc, lptm as *mut _) }
}

/// GetObjectA: ANSI variant — identical to GetObject (no strings involved).
///
/// # Safety
/// Pointer arguments must be valid.
pub unsafe extern "win64" fn get_object_a(h: usize, c: i32, pv: *mut u8) -> i32 {
    get_object(h, c, pv as usize)
}

/// GetTextExtentExPointA: ANSI variant. Returns FALSE (stub).
///
/// # Safety
/// Pointer arguments are accepted but not fully used.
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
pub unsafe extern "win64" fn get_char_width32_a(
    _hdc: usize, _i_first: u32, _i_last: u32, _lp_buffer: usize,
) -> i32 { 0 }

/// # Safety
/// `lp_buffer` must point to writable storage for `(i_last - i_first + 1)` INT values.
pub unsafe extern "win64" fn get_char_width32_w(
    _hdc: usize, _i_first: u32, _i_last: u32, _lp_buffer: usize,
) -> i32 { 0 }

/// # Safety
/// `lp_buffer` must point to writable storage for the requested char range.
pub unsafe extern "win64" fn get_char_width_a(
    _hdc: usize, _i_first: u32, _i_last: u32, _lp_buffer: usize,
) -> i32 { 0 }

/// # Safety
/// `lp_buffer` must point to writable storage for the requested char range.
pub unsafe extern "win64" fn get_char_width_w(
    _hdc: usize, _i_first: u32, _i_last: u32, _lp_buffer: usize,
) -> i32 { 0 }

/// GetCharacterPlacementW: return 0 (not implemented).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_character_placement_w(
    _hdc: usize,
    _lpsz: *const u16,
    _c_string: i32,
    _n_max_extent: i32,
    _lpgcp_results: usize,
    _dw_flags: u32,
) -> u32 { 0 }

/// SetTextAlign: set DC text alignment. Returns TA_LEFT (previous value).
pub extern "win64" fn set_text_align(_hdc: usize, _fmode: u32) -> u32 {
    0 // TA_LEFT | TA_TOP | TA_NOUPDATECP
}

/// GetCurrentObject: return a selected GDI object from a DC. Returns 0.
pub extern "win64" fn get_current_object(_hdc: usize, _u_object_type: u32) -> usize {
    0
}

/// SetMapMode: set the DC mapping mode. Returns MM_TEXT (1) as the previous mode.
pub extern "win64" fn set_map_mode(_hdc: usize, _i_mode: i32) -> i32 {
    1 // MM_TEXT
}

/// Polyline: draw a polyline through a series of points. Returns TRUE.
///
/// # Safety
/// `lpt` must point to `c_pt` valid POINT structs.
pub unsafe extern "win64" fn polyline(_hdc: usize, _lpt: *const i32, _c_pt: i32) -> i32 {
    1
}

/// CreateBitmap: create a device-dependent bitmap.
///
/// Returns a GDI object handle. Phase 2 stub — no pixel data stored.
pub extern "win64" fn create_bitmap(
    _n_width: i32,
    _n_height: i32,
    _n_planes: u32,
    _n_bit_count: u32,
    _lp_bits: usize,
) -> usize {
    objects::alloc(GdiKind::Bitmap)
}

/// GetDIBits: copy pixel data from a bitmap into a DIB. Returns 0 (stub).
///
/// # Safety
/// Pointer arguments are accepted but not fully used.
pub unsafe extern "win64" fn get_dib_bits(
    _hdc: usize,
    _h_bm: usize,
    _start: u32,
    _c_lines: u32,
    _lp_vbits: usize,
    _lpbmi: usize,
    _usage: u32,
) -> i32 { 0 }

/// ExcludeClipRect: exclude a rectangle from the clipping region. Returns SIMPLEREGION (2).
pub extern "win64" fn exclude_clip_rect(_hdc: usize, _left: i32, _top: i32, _right: i32, _bottom: i32) -> i32 {
    2 // SIMPLEREGION
}

/// IntersectClipRect: intersect the clipping region with a rectangle. Returns SIMPLEREGION (2).
pub extern "win64" fn intersect_clip_rect(_hdc: usize, _left: i32, _top: i32, _right: i32, _bottom: i32) -> i32 {
    2 // SIMPLEREGION
}

/// TranslateCharsetInfo: translate character set info. Returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not fully used.
pub unsafe extern "win64" fn translate_charset_info(
    _lp_src: usize,
    _lp_cs: usize,
    _dw_flags: u32,
) -> i32 { 0 }

// ── Palette stubs ─────────────────────────────────────────────────────────────

/// CreatePalette: create a logical colour palette. Returns a fake HPALETTE.
///
/// # Safety
/// `lplgpl` must point to a valid LOGPALETTE struct.
pub unsafe extern "win64" fn create_palette(_lplgpl: *const u8) -> usize {
    // Return a non-zero fake handle; palette operations are no-ops.
    0x0000_FACE_usize
}

/// SelectPalette: select a palette into a DC. Returns the previous (fake) palette.
pub extern "win64" fn select_palette(_hdc: usize, _h_pal: usize, _b_force_background: i32) -> usize {
    0x0000_FACE_usize
}

/// RealizePalette: map palette entries to the system palette. Returns 0.
pub extern "win64" fn realize_palette(_hdc: usize) -> u32 {
    0
}

/// SetPaletteEntries: set palette colour entries. Returns 0.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_palette_entries(
    _h_pal: usize,
    _i_start: u32,
    _c_entries: u32,
    _lppe: usize,
) -> u32 { 0 }

/// UnrealizeObject: reset a brush origin or restore a palette. Returns TRUE.
pub extern "win64" fn unrealize_object(_h: usize) -> i32 { 1 }

/// UpdateColors: update client area colors. Returns TRUE.
pub extern "win64" fn update_colors(_hdc: usize) -> i32 { 1 }
