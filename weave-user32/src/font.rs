//! Font loading and text rasterization for Weave.
//!
//! Uses `fontdue` (pure Rust) for TrueType/OpenType font parsing and glyph
//! rasterization. Fonts are loaded from standard Linux system paths at runtime.
//! If no system font is found, text rendering gracefully degrades (no-op).
//!
//! Supports loading a specific font by file path (used by the GDI font-object
//! pipeline). Font file bytes are cached in a global map so repeated renders
//! with the same font path avoid re-reading from disk.
//!
//! This replaces the Phase 2 approach of X11 core bitmap fonts + Latin-1 only.

#[cfg(target_os = "linux")]
mod inner {
    use fontdue::{Font, FontSettings};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// Cached system font, loaded once on first use.
    static SYSTEM_FONT: OnceLock<Option<Font>> = OnceLock::new();

    /// Cache of font file bytes keyed by absolute path, so we never re-read
    /// the same TrueType file from disk.
    static FONT_BYTES_CACHE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

    /// Standard Linux paths to search for a TrueType font with broad Unicode coverage.
    const FONT_SEARCH_PATHS: &[&str] = &[
        // Debian/Ubuntu
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
        // Fedora / RHEL
        "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf",
        "/usr/share/fonts/liberation-sans/LiberationSans-Regular.ttf",
        "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/gnu-free/FreeSans.ttf",
        // Arch
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        // openSUSE
        "/usr/share/fonts/truetype/DejaVuSans.ttf",
        // Generic fallbacks — any .ttf in common directories
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ];

    fn load_system_font() -> Option<Font> {
        for path in FONT_SEARCH_PATHS {
            if let Ok(data) = std::fs::read(path) {
                if let Ok(font) = Font::from_bytes(data, FontSettings::default()) {
                    return Some(font);
                }
            }
        }
        None
    }

    /// Get the cached system font (loaded lazily on first call).
    pub fn system_font() -> Option<&'static Font> {
        SYSTEM_FONT.get_or_init(load_system_font).as_ref()
    }

    /// Return cached font file bytes for *path*, reading from disk on first
    /// access. This avoids re-parsing the TrueType tables on every render call.
    fn font_bytes(path: &str) -> Option<Vec<u8>> {
        let cache = FONT_BYTES_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut cache = cache.lock().ok()?;
        if let Some(bytes) = cache.get(path) {
            return Some(bytes.clone());
        }
        let bytes = std::fs::read(path).ok()?;
        cache.insert(path.to_string(), bytes.clone());
        Some(bytes)
    }

    /// Load a `Font` from its file path (reads via `font_bytes` cache).
    pub fn font_from_path(path: &str) -> Option<Font> {
        let bytes = font_bytes(path)?;
        Font::from_bytes(bytes, FontSettings::default()).ok()
    }

    /// Font metrics at a given pixel size.
    pub struct FontMetrics {
        pub ascent: i32,
        pub descent: i32,
        pub height: i32,
        pub ave_char_width: i32,
    }

    fn metrics_for_font(font: &Font, px_size: f32) -> FontMetrics {
        let m = font
            .horizontal_line_metrics(px_size)
            .unwrap_or(fontdue::LineMetrics {
                ascent: px_size * 0.8,
                descent: px_size * -0.2,
                line_gap: px_size * 0.1,
                new_line_size: px_size * 1.2,
            });
        let ascent = m.ascent.round() as i32;
        let descent = m.descent.abs().round() as i32;
        let height = ascent + descent;
        let ave_w = font.metrics('x', px_size).advance_width.round() as i32;
        FontMetrics {
            ascent,
            descent,
            height,
            ave_char_width: ave_w.max(1),
        }
    }

    /// Return font metrics for the given pixel size, optionally from a specific
    /// font file path.
    pub fn metrics(px_size: f32) -> FontMetrics {
        metrics_with_path(px_size, None)
    }

    /// Like `metrics` but uses a specific font file path when provided.
    pub fn metrics_with_path(px_size: f32, font_path: Option<&str>) -> FontMetrics {
        if let Some(path) = font_path {
            if let Some(font) = font_from_path(path) {
                return metrics_for_font(&font, px_size);
            }
        }
        match system_font() {
            Some(font) => metrics_for_font(font, px_size),
            None => FontMetrics {
                ascent: 11,
                descent: 2,
                height: 13,
                ave_char_width: 7,
            },
        }
    }

    fn measure_text_for_font(font: &Font, text: &[u16], px_size: f32) -> (i32, i32) {
        let mut width: f32 = 0.0;
        for ch in char::decode_utf16(text.iter().copied()) {
            let ch = ch.unwrap_or('\u{FFFD}');
            let m = font.metrics(ch, px_size);
            width += m.advance_width;
        }
        let fm = metrics_for_font(font, px_size);
        (width.round() as i32, fm.height)
    }

    /// Measure the pixel width and height of a UTF-16 string at a given size,
    /// optionally using a specific font file path.
    pub fn measure_text(text: &[u16], px_size: f32) -> (i32, i32) {
        measure_text_with_path(text, px_size, None)
    }

    /// Like `measure_text` but uses a specific font file path when provided.
    pub fn measure_text_with_path(
        text: &[u16],
        px_size: f32,
        font_path: Option<&str>,
    ) -> (i32, i32) {
        if let Some(path) = font_path {
            if let Some(font) = font_from_path(path) {
                return measure_text_for_font(&font, text, px_size);
            }
        }
        match system_font() {
            Some(f) => measure_text_for_font(f, text, px_size),
            None => (text.len() as i32 * 7, 13),
        }
    }

    fn rasterize_text_inner(
        font: &Font,
        text: &[u16],
        px_size: f32,
        fg: u32,
        bg: u32,
    ) -> Option<(Vec<u8>, u32, u32)> {
        if text.is_empty() {
            return None;
        }

        let fm = metrics_for_font(font, px_size);
        let (total_width, total_height) = measure_text_for_font(font, text, px_size);
        if total_width <= 0 || total_height <= 0 {
            return None;
        }

        let w = total_width as u32;
        let h = total_height as u32;

        let fg_r = ((fg >> 16) & 0xFF) as f32;
        let fg_g = ((fg >> 8) & 0xFF) as f32;
        let fg_b = (fg & 0xFF) as f32;
        let bg_r = ((bg >> 16) & 0xFF) as f32;
        let bg_g = ((bg >> 8) & 0xFF) as f32;
        let bg_b = (bg & 0xFF) as f32;

        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for chunk in pixels.chunks_exact_mut(4) {
            chunk[0] = bg_b as u8;
            chunk[1] = bg_g as u8;
            chunk[2] = bg_r as u8;
            chunk[3] = 0xFF;
        }

        let mut cursor_x: f32 = 0.0;

        for ch in char::decode_utf16(text.iter().copied()) {
            let ch = ch.unwrap_or('\u{FFFD}');
            let (glyph_metrics, bitmap) = font.rasterize(ch, px_size);

            if glyph_metrics.width == 0 || glyph_metrics.height == 0 {
                cursor_x += glyph_metrics.advance_width;
                continue;
            }

            let gx = cursor_x.round() as i32 + glyph_metrics.xmin;
            let gy = fm.ascent - glyph_metrics.height as i32 - glyph_metrics.ymin;

            for row in 0..glyph_metrics.height {
                for col in 0..glyph_metrics.width {
                    let px = gx + col as i32;
                    let py = gy + row as i32;
                    if px < 0 || py < 0 || px >= w as i32 || py >= h as i32 {
                        continue;
                    }
                    let alpha = bitmap[row * glyph_metrics.width + col] as f32 / 255.0;
                    if alpha < 0.01 {
                        continue;
                    }
                    let idx = ((py as u32 * w + px as u32) * 4) as usize;
                    let r = (fg_r * alpha + bg_r * (1.0 - alpha)).round() as u8;
                    let g = (fg_g * alpha + bg_g * (1.0 - alpha)).round() as u8;
                    let b = (fg_b * alpha + bg_b * (1.0 - alpha)).round() as u8;
                    pixels[idx] = b;
                    pixels[idx + 1] = g;
                    pixels[idx + 2] = r;
                    pixels[idx + 3] = 0xFF;
                }
            }

            cursor_x += glyph_metrics.advance_width;
        }

        Some((pixels, w, h))
    }

    /// Rasterize a UTF-16 string into an XRGB pixel buffer, optionally using a
    /// specific font file path.
    ///
    /// Returns `(pixels, width, height)` where `pixels` is a `Vec<u8>` with
    /// 4 bytes per pixel (BGRX / little-endian 0xXXRRGGBB stored as B, G, R, X).
    /// `fg` and `bg` are X11 TrueColor pixel values (0x00RRGGBB).
    ///
    /// Returns `None` if no font is available or text is empty.
    pub fn rasterize_text(
        text: &[u16],
        px_size: f32,
        fg: u32,
        bg: u32,
        font_path: Option<&str>,
    ) -> Option<(Vec<u8>, u32, u32)> {
        if let Some(path) = font_path {
            if let Some(font) = font_from_path(path) {
                return rasterize_text_inner(&font, text, px_size, fg, bg);
            }
        }
        let font = system_font()?;
        rasterize_text_inner(font, text, px_size, fg, bg)
    }
}

// ── Public API (cross-platform) ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use inner::*;

#[cfg(not(target_os = "linux"))]
pub struct FontMetrics {
    pub ascent: i32,
    pub descent: i32,
    pub height: i32,
    pub ave_char_width: i32,
}

#[cfg(not(target_os = "linux"))]
pub fn metrics(_px_size: f32) -> FontMetrics {
    FontMetrics {
        ascent: 11,
        descent: 2,
        height: 13,
        ave_char_width: 7,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn metrics_with_path(_px_size: f32, _font_path: Option<&str>) -> FontMetrics {
    FontMetrics {
        ascent: 11,
        descent: 2,
        height: 13,
        ave_char_width: 7,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn measure_text(text: &[u16], _px_size: f32) -> (i32, i32) {
    (text.len() as i32 * 7, 13)
}

#[cfg(not(target_os = "linux"))]
pub fn measure_text_with_path(
    text: &[u16],
    _px_size: f32,
    _font_path: Option<&str>,
) -> (i32, i32) {
    (text.len() as i32 * 7, 13)
}

#[cfg(not(target_os = "linux"))]
pub fn rasterize_text(
    _text: &[u16],
    _px_size: f32,
    _fg: u32,
    _bg: u32,
    _font_path: Option<&str>,
) -> Option<(Vec<u8>, u32, u32)> {
    None
}
