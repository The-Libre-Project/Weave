//! GDI constants, types and Win32 struct layouts.

// ── Stock object indices (passed to GetStockObject) ──────────────────────────
pub const WHITE_BRUSH: i32 = 0;
pub const LTGRAY_BRUSH: i32 = 1;
pub const GRAY_BRUSH: i32 = 2;
pub const DKGRAY_BRUSH: i32 = 3;
pub const BLACK_BRUSH: i32 = 4;
pub const NULL_BRUSH: i32 = 5;
pub const HOLLOW_BRUSH: i32 = NULL_BRUSH;
pub const WHITE_PEN: i32 = 6;
pub const BLACK_PEN: i32 = 7;
pub const NULL_PEN: i32 = 8;
pub const OEM_FIXED_FONT: i32 = 10;
pub const ANSI_FIXED_FONT: i32 = 11;
pub const ANSI_VAR_FONT: i32 = 12;
pub const SYSTEM_FONT: i32 = 13;
pub const DEVICE_DEFAULT_FONT: i32 = 14;
pub const DEFAULT_PALETTE: i32 = 15;
pub const SYSTEM_FIXED_FONT: i32 = 16;
pub const DEFAULT_GUI_FONT: i32 = 17;
pub const DC_BRUSH: i32 = 18;
pub const DC_PEN: i32 = 19;

// ── Background modes ──────────────────────────────────────────────────────────
pub const TRANSPARENT: i32 = 1;
pub const OPAQUE: i32 = 2;

// ── Pen styles ────────────────────────────────────────────────────────────────
pub const PS_SOLID: i32 = 0;
pub const PS_DASH: i32 = 1;
pub const PS_DOT: i32 = 2;
pub const PS_NULL: i32 = 5;

// ── GetDeviceCaps indices ─────────────────────────────────────────────────────
pub const HORZRES: i32 = 8;
pub const VERTRES: i32 = 10;
pub const BITSPIXEL: i32 = 12;
pub const PLANES: i32 = 14;
pub const LOGPIXELSX: i32 = 88;
pub const LOGPIXELSY: i32 = 90;
pub const RASTERCAPS: i32 = 38;
pub const RC_PALETTE: i32 = 0x0100;
// Wine ref: dlls/win32u/driver.c::nulldrv_GetDeviceCaps — standard raster capabilities
// for a display DC: RC_BITBLT | RC_BITMAP64 | RC_GDI20_OUTPUT | RC_DI_BITMAP |
// RC_DIBTODEV | RC_BIGFONT | RC_STRETCHBLT | RC_FLOODFILL | RC_STRETCHDIB | RC_DEVBITS
pub const RC_BITBLT: i32 = 0x0001;
pub const RC_BITMAP64: i32 = 0x0002;
pub const RC_GDI20_OUTPUT: i32 = 0x0010;
pub const RC_DI_BITMAP: i32 = 0x0080;
pub const RC_DIBTODEV: i32 = 0x0200;
pub const RC_BIGFONT: i32 = 0x0400;
pub const RC_STRETCHBLT: i32 = 0x0800;
pub const RC_FLOODFILL: i32 = 0x1000;
pub const RC_STRETCHDIB: i32 = 0x2000;
pub const RC_DEVBITS: i32 = 0x8000;
pub const RASTER_CAPS_DISPLAY: i32 = RC_BITBLT | RC_BITMAP64 | RC_GDI20_OUTPUT |
    RC_DI_BITMAP | RC_DIBTODEV | RC_BIGFONT | RC_STRETCHBLT |
    RC_FLOODFILL | RC_STRETCHDIB | RC_DEVBITS;

// ── GDI handle offsets ────────────────────────────────────────────────────────
/// Allocated GDI object handles start at this offset.
pub const GDI_HANDLE_OFFSET: usize = 0x0020_0000;
/// Stock object handles are in this range.
pub const STOCK_HANDLE_BASE: usize = 0x0030_0000;

// ── Win32 Rect ────────────────────────────────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

// ── POINT ─────────────────────────────────────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

// ── SIZE ──────────────────────────────────────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Size {
    pub cx: i32,
    pub cy: i32,
}

// ── LOGFONTW (92 bytes on Win64) ──────────────────────────────────────────────
#[repr(C)]
pub struct LogFontW {
    pub lf_height: i32,
    pub lf_width: i32,
    pub lf_escapement: i32,
    pub lf_orientation: i32,
    pub lf_weight: i32,
    pub lf_italic: u8,
    pub lf_underline: u8,
    pub lf_strike_out: u8,
    pub lf_char_set: u8,
    pub lf_out_precision: u8,
    pub lf_clip_precision: u8,
    pub lf_quality: u8,
    pub lf_pitch_and_family: u8,
    pub lf_face_name: [u16; 32],
}

// ── TEXTMETRICW (60 bytes on Win64) ──────────────────────────────────────────
#[repr(C)]
pub struct TextMetricW {
    pub tm_height: i32,
    pub tm_ascent: i32,
    pub tm_descent: i32,
    pub tm_internal_leading: i32,
    pub tm_external_leading: i32,
    pub tm_ave_char_width: i32,
    pub tm_max_char_width: i32,
    pub tm_weight: i32,
    pub tm_overhang: i32,
    pub tm_digitized_aspect_x: i32,
    pub tm_digitized_aspect_y: i32,
    pub tm_first_char: u16,
    pub tm_last_char: u16,
    pub tm_default_char: u16,
    pub tm_break_char: u16,
    pub tm_italic: u8,
    pub tm_underlined: u8,
    pub tm_struck_out: u8,
    pub tm_pitch_and_family: u8,
    pub tm_char_set: u8,
    pub _pad: [u8; 3],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn logfontw_size() {
        // 5×i32 + 8×u8 + padding + 32×u16 = 20 + 8 + 64 = 92 bytes
        assert_eq!(size_of::<LogFontW>(), 92);
    }

    #[test]
    fn textmetricw_size() {
        assert_eq!(size_of::<TextMetricW>(), 60);
    }
}
