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

// ── Text alignment flags (SetTextAlign / GetTextAlign) ────────────────────────
// Wine ref: dlls/win32u/dc.c — NtGdiSetTextAlign stores these in dc->attr.text_align.
// Horizontal: TA_LEFT=0 (default), TA_RIGHT=2, TA_CENTER=6.
// Vertical: TA_TOP=0 (default), TA_BOTTOM=8, TA_BASELINE=24.
// TA_UPDATECP=1: advance current position after each draw call.
pub const TA_NOUPDATECP: u32 = 0x0000;
pub const TA_UPDATECP: u32 = 0x0001;
pub const TA_LEFT: u32 = 0x0000;
pub const TA_RIGHT: u32 = 0x0002;
pub const TA_CENTER: u32 = 0x0006;
pub const TA_TOP: u32 = 0x0000;
pub const TA_BOTTOM: u32 = 0x0008;
pub const TA_BASELINE: u32 = 0x0018;
pub const GDI_ERROR: u32 = 0xFFFF_FFFF;

// ── ExtTextOut option flags ───────────────────────────────────────────────────
// Wine ref: dlls/win32u/font.c::nulldrv_ExtTextOut — ETO_OPAQUE fills the
// background rect with the current background colour before rendering glyphs;
// ETO_CLIPPED clips output to the provided rect; ETO_GLYPH_INDEX means lpString
// holds glyph indices rather than Unicode codepoints.
pub const ETO_OPAQUE: u32 = 0x0002;
pub const ETO_CLIPPED: u32 = 0x0004;
pub const ETO_GLYPH_INDEX: u32 = 0x0010;

// ── Region combine modes ──────────────────────────────────────────────────────
pub const RGN_AND: i32 = 1;
pub const RGN_OR: i32 = 2;
pub const RGN_XOR: i32 = 3;
pub const RGN_DIFF: i32 = 4;
pub const RGN_COPY: i32 = 5;

// ── Region return values ──────────────────────────────────────────────────────
pub const NULLREGION: i32 = 1;
pub const SIMPLEREGION: i32 = 2;
pub const COMPLEXREGION: i32 = 3;

// ── Font type flags for EnumFontFamiliesEx callback ──────────────────────────
pub const TRUETYPE_FONTTYPE: u32 = 0x0004;

// ── StretchBlt filter modes (SetStretchBltMode) ───────────────────────────────
// Wine ref: dlls/win32u/dc.c::set_stretch_blt_mode — stored in dc->attr->stretch_blt_mode.
// BLACKONWHITE/STRETCH_ANDSCANS (1): AND pixels when shrinking (preserves black).
// WHITEONBLACK/STRETCH_ORSCANS (2): OR pixels when shrinking (preserves white).
// COLORONCOLOR/STRETCH_DELETESCANS (3): delete rows/cols — nearest-neighbor, the
// default used by Wine for all depths.
// HALFTONE (4): linear-averaging filter; requires SetBrushOrgEx for brush alignment.
pub const BLACKONWHITE: i32 = 1;
pub const WHITEONBLACK: i32 = 2;
pub const COLORONCOLOR: i32 = 3;
pub const HALFTONE: i32 = 4;
pub const STRETCH_ANDSCANS: i32 = BLACKONWHITE;
pub const STRETCH_ORSCANS: i32 = WHITEONBLACK;
pub const STRETCH_DELETESCANS: i32 = COLORONCOLOR;
pub const STRETCH_HALFTONE: i32 = HALFTONE;

// ── R2 mix mode (ROP2) ────────────────────────────────────────────────────────
pub const R2_COPYPEN: i32 = 13;

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
// ── Ternary raster-op codes (BitBlt / PatBlt ROP3) ───────────────────────────
// Wine ref: dlls/winex11.drv/bitblt.c — BITBLT_Opcodes table rows 0x00/0x33/0x55/
// 0x66/0x88/0xcc/0xee/0xf0/0xff map each of the high byte of the ROP3 code to a
// single X11 GC `function` op (GXclear / GXcopyInverted / GXinvert / GXxor /
// GXand / GXcopy / GXor / GXcopy / GXset respectively). See also X11DRV_PatBlt.
pub const SRCCOPY: u32 = 0x00CC_0020; // dest = src
pub const SRCPAINT: u32 = 0x00EE_0086; // dest |= src
pub const SRCAND: u32 = 0x0088_00C6; // dest &= src
pub const SRCINVERT: u32 = 0x0066_0046; // dest ^= src
pub const NOTSRCCOPY: u32 = 0x0033_0008; // dest = ~src
pub const DSTINVERT: u32 = 0x0055_0009; // dest = ~dest
pub const PATCOPY: u32 = 0x00F0_0021; // dest = pattern
pub const PATINVERT: u32 = 0x005A_0049; // dest ^= pattern
pub const BLACKNESS: u32 = 0x0000_0042; // dest = black
pub const WHITENESS: u32 = 0x00FF_0062; // dest = white
pub const RASTER_CAPS_DISPLAY: i32 = RC_BITBLT
    | RC_BITMAP64
    | RC_GDI20_OUTPUT
    | RC_DI_BITMAP
    | RC_DIBTODEV
    | RC_BIGFONT
    | RC_STRETCHBLT
    | RC_FLOODFILL
    | RC_STRETCHDIB
    | RC_DEVBITS;

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

// ── ENUMLOGFONTEXW (348 bytes) ────────────────────────────────────────────────
// Wine ref: dlls/win32u/font.c — EnumFontFamiliesExW callback receives this as
// first arg; elf_log_font is the logical font, elf_full_name is the full face
// name, elf_style is the style string ("Regular", "Bold Italic", etc.).
#[repr(C)]
pub struct EnumLogFontExW {
    pub elf_log_font: LogFontW,   // 92 bytes — the basic LOGFONTW
    pub elf_full_name: [u16; 64], // 128 bytes — full face name
    pub elf_style: [u16; 32],     // 64 bytes — style string
    pub elf_script: [u16; 32],    // 64 bytes — script name
}

// ── NEWTEXTMETRICEXW (100 bytes) ─────────────────────────────────────────────
// Extends TEXTMETRICW with ntmFlags, ntmSizeEM, ntmCellHeight, ntmAvgWidth,
// and FONTSIGNATURE. Wine ref: dlls/win32u/font.c — callbacks receive this
// as second arg. Most callers only inspect the TEXTMETRICW portion.
#[repr(C)]
pub struct NewTextMetricExW {
    pub tm: TextMetricW,           // 60 bytes — base TEXTMETRICW
    pub ntm_flags: u32,            // NTM_* font flags
    pub ntm_size_em: u32,          // design em square size
    pub ntm_cell_height: u32,      // cell height in design units
    pub ntm_avg_width: u32,        // avg char width in design units
    pub fs_usage_bitmap: [u32; 4], // FONTSIGNATURE.fsUsb — Unicode subranges
    pub fs_cset_bitmap: [u32; 2],  // FONTSIGNATURE.fsCsb — codepage ranges
}

// ── DOCINFOW (printing) ───────────────────────────────────────────────────────
#[repr(C)]
pub struct DocInfoW {
    pub cb_size: i32,
    pub lp_sz_doc_name: *const u16,
    pub lp_sz_output: *const u16,
    pub lp_sz_datatype: *const u16,
    pub f_type: u32,
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
