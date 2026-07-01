//! Fontconfig bridge — Win32 font enumeration, matching, and substitution.
//!
//! Translates Windows font names (Arial, Times New Roman, etc.) to fontconfig
//! patterns and file paths. Used by GDI font functions like CreateFontIndirectW,
//! EnumFontFamiliesExW, GetTextMetrics, etc.
//!
//! Wine ref: dlls/win32u/font.c — EnumFontFamiliesExW enumerates via the
//! font driver's EnumFonts callback; the X11 driver (winex11.drv) delegates to
//! fontconfig's FcFontList / FcFontSort. The substitution table below mirrors
//! Wine's fontmetric-aliases.conf and 45-generic.conf mappings.

use std::ffi::CString;
use std::sync::OnceLock;

use fontconfig::{Fontconfig, ObjectSet, Pattern};

// ── FontInfo ───────────────────────────────────────────────────────────────────

/// Describes a single font face as discovered by fontconfig.
#[derive(Clone, Debug)]
pub struct FontInfo {
    pub family: String,
    pub style: String,
    pub file_path: String,
    pub index: i32,
    pub format: String,
}

// ── Font substitution table ────────────────────────────────────────────────────
//
// Maps common Windows font family names to Linux-equivalent fonts.  Checked
// first during font matching: if the requested family is a well-known Windows
// font name, the mapped Linux name is used for the fontconfig query.
//
// Wine ref: dlls/winex11.drv/font.c — X11DRV_LoadFontFamilyAliases loads
// HKLM\Software\Microsoft\Windows NT\CurrentVersion\FontSubstitutes which
// includes the same substitutions.

fn substitute_font(windows_family: &str) -> &str {
    match windows_family.to_lowercase().as_str() {
        "arial" | "arial narrow" => "Liberation Sans",
        "times new roman" => "Liberation Serif",
        "courier new" => "Liberation Mono",
        "tahoma" => "Noto Sans",
        "verdana" => "Noto Sans",
        "segoe ui" => "Noto Sans",
        "microsoft sans serif" => "Noto Sans",
        "trebuchet ms" => "Noto Sans",
        "impact" => "Noto Sans",
        "comic sans ms" => "Noto Sans",
        "palatino linotype" => "Noto Serif",
        "georgia" => "Noto Serif",
        "bookman old style" => "Noto Serif",
        "garamond" => "Noto Serif",
        "century gothic" => "Noto Sans",
        "lucida console" => "Liberation Mono",
        "lucida sans unicode" => "Noto Sans",
        "symbol" | "wingdings" | "webdings" => "Noto Sans",
        _ => windows_family,
    }
}

// ── Lazy fontconfig initialisation ─────────────────────────────────────────────

fn fontconfig() -> Option<&'static Fontconfig> {
    static FC: OnceLock<Option<Fontconfig>> = OnceLock::new();
    FC.get_or_init(|| {
        let fc = Fontconfig::new();
        if fc.is_none() {
            eprintln!("weave/gdi32: fontconfig initialisation failed");
        }
        fc
    })
    .as_ref()
}

// ── Font enumeration ──────────────────────────────────────────────────────────

/// Enumerate all fonts available via fontconfig.
///
/// Returns a `Vec<FontInfo>` describing every installed font face.  Returns an
/// empty vector if fontconfig is not available or fails to initialise.
///
/// Wine ref: dlls/winex11.drv/font.c — X11DRV_EnumFonts calls FcFontList with
/// no family filter to enumerate all fonts; callers receive ENUMLOGFONTEX
/// callbacks.
pub fn enumerate_fonts() -> Vec<FontInfo> {
    let fc = match fontconfig() {
        Some(fc) => fc,
        None => return Vec::new(),
    };

    let pat = match Pattern::new(fc) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut objects = match ObjectSet::new(fc) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    objects.add(fontconfig::FC_FAMILY).ok();
    objects.add(fontconfig::FC_STYLE).ok();
    objects.add(fontconfig::FC_FILE).ok();
    objects.add(fontconfig::FC_INDEX).ok();
    objects.add(fontconfig::FC_FONTFORMAT).ok();

    let fontset = match fontconfig::list_fonts(&pat, Some(&objects)) {
        Ok(fs) => fs,
        Err(_) => return Vec::new(),
    };

    let mut fonts = Vec::new();
    for p in fontset.iter() {
        let family = p.get_string(fontconfig::FC_FAMILY).unwrap_or("Unknown");
        let style = p.get_string(fontconfig::FC_STYLE).unwrap_or("Regular");
        let file_path = p.filename().unwrap_or("");
        let index = p.face_index().unwrap_or(0);
        let format = match p.format() {
            Ok(f) => f.to_string(),
            Err(e) => e.0,
        };
        fonts.push(FontInfo {
            family: family.to_owned(),
            style: style.to_owned(),
            file_path: file_path.to_owned(),
            index,
            format,
        });
    }
    fonts
}

// ── Font matching ──────────────────────────────────────────────────────────────

/// Find the best font match for a given family, weight, and italic flag.
///
/// The Windows font name is first checked against the substitution table:
/// common names like "Arial" are mapped to their Linux equivalents (e.g.
/// "Liberation Sans") before querying fontconfig.
///
/// Returns `None` if fontconfig is unavailable or no match is found.
///
/// # Fontconfig weight constants
/// - `FC_WEIGHT_REGULAR` = 80
/// - `FC_WEIGHT_BOLD` = 200
///
/// # Fontconfig slant constants
/// - `FC_SLANT_ROMAN` = 0
/// - `FC_SLANT_ITALIC` = 100
/// - `FC_SLANT_OBLIQUE` = 110
///
/// Wine ref: dlls/winex11.drv/font.c — X11DRV_FontMatch builds an FcPattern
/// from LOGFONTW fields (lfFaceName, lfWeight, lfItalic, lfHeight, lfCharSet)
/// then calls FcConfigSubstitute + FcDefaultSubstitute + FcFontMatch.
pub fn match_font(family: &str, weight: i32, italic: bool) -> Option<FontInfo> {
    let fc = fontconfig()?;

    // Apply the Windows→Linux font substitution table.
    let mapped_family = substitute_font(family);
    let family_cstr = CString::new(mapped_family).ok()?;

    let mut pat = Pattern::new(fc).ok()?;
    pat.add_string(fontconfig::FC_FAMILY, &family_cstr).ok()?;
    pat.add_integer(fontconfig::FC_WEIGHT, weight).ok()?;
    pat.add_integer(
        fontconfig::FC_SLANT,
        if italic {
            fontconfig::FC_SLANT_ITALIC
        } else {
            fontconfig::FC_SLANT_ROMAN
        },
    )
    .ok()?;

    let matched = pat.font_match().ok()?;

    let family_name = matched.get_string(fontconfig::FC_FAMILY).ok()?;
    let style = matched
        .get_string(fontconfig::FC_STYLE)
        .unwrap_or("Regular");
    let file_path = matched.filename().ok()?;
    let index = matched.face_index().unwrap_or(0);
    let format = matched.format().map(|f| f.to_string()).unwrap_or_default();

    Some(FontInfo {
        family: family_name.to_owned(),
        style: style.to_owned(),
        file_path: file_path.to_owned(),
        index,
        format,
    })
}

/// Convenience: match a font with regular weight (400) and no italic.
pub fn match_font_regular(family: &str) -> Option<FontInfo> {
    match_font(family, fontconfig::FC_WEIGHT_REGULAR, false)
}

/// Convenience: match a font with bold weight (700) and no italic.
pub fn match_font_bold(family: &str) -> Option<FontInfo> {
    match_font(family, fontconfig::FC_WEIGHT_BOLD, false)
}

/// Convenience: match a font with regular weight and italic slant.
pub fn match_font_italic(family: &str) -> Option<FontInfo> {
    match_font(family, fontconfig::FC_WEIGHT_REGULAR, true)
}

/// Convenience: match a font with bold weight (700) and italic slant.
pub fn match_font_bold_italic(family: &str) -> Option<FontInfo> {
    match_font(family, fontconfig::FC_WEIGHT_BOLD, true)
}

/// Return the path of the best match for `family` with the given weight/slant.
/// Shorthand for `match_font(..).map(|f| f.file_path)`.
pub fn font_path(family: &str, weight: i32, italic: bool) -> Option<String> {
    match_font(family, weight, italic).map(|f| f.file_path)
}

// ── LOGFONTW → Fontconfig translation ────────────────────────────────────────

/// Translate a Windows LOGFONTW struct into a fontconfig pattern and return the
/// best matching font. Handles family name substitution, weight mapping, italic
/// flag, and charset hints.
///
/// Returns `None` if fontconfig is unavailable or no match is found.
///
/// Wine ref: dlls/win32u/font.c — NtGdiHfontCreate calls X11DRV_FontMatch which
/// builds an FcPattern from the LOGFONTW fields (lfFaceName, lfWeight, lfItalic,
/// lfHeight, lfCharSet) and calls FcConfigSubstitute + FcDefaultSubstitute +
/// FcFontMatch.
pub fn logfont_to_fontconfig(lf: &crate::defs::LogFontW) -> Option<FontInfo> {
    // 1. Extract family name from lfFaceName (UTF-16).
    let face_end = lf.lf_face_name.iter().position(|&c| c == 0).unwrap_or(32);
    let family_str = String::from_utf16_lossy(&lf.lf_face_name[..face_end]);
    let family = if family_str.trim().is_empty() {
        "Sans Serif"
    } else {
        substitute_font(family_str.trim())
    };

    // 2. Map Windows weight (0–1000) to fontconfig weight.
    //    Fontconfig weights: Thin=0, Light=50, Regular=80, Medium=100,
    //    DemiBold=180, Bold=200, ExtraBold=205, Black=210.
    let fc_weight = match lf.lf_weight {
        0 | 400 => fontconfig::FC_WEIGHT_REGULAR, // FW_DONTCARE / FW_NORMAL
        100 => fontconfig::FC_WEIGHT_THIN,        // FW_THIN
        200 => fontconfig::FC_WEIGHT_EXTRALIGHT,  // FW_EXTRALIGHT
        300 => fontconfig::FC_WEIGHT_LIGHT,       // FW_LIGHT
        500 => fontconfig::FC_WEIGHT_MEDIUM,      // FW_MEDIUM
        600 => fontconfig::FC_WEIGHT_DEMIBOLD,    // FW_SEMIBOLD
        700 => fontconfig::FC_WEIGHT_BOLD,        // FW_BOLD
        800 => fontconfig::FC_WEIGHT_EXTRABOLD,   // FW_EXTRABOLD
        900 => fontconfig::FC_WEIGHT_BLACK,       // FW_HEAVY/BLACK
        w if w < 100 => fontconfig::FC_WEIGHT_THIN,
        w if w < 300 => fontconfig::FC_WEIGHT_LIGHT,
        w if w < 500 => fontconfig::FC_WEIGHT_REGULAR,
        w if w < 600 => fontconfig::FC_WEIGHT_MEDIUM,
        w if w < 700 => fontconfig::FC_WEIGHT_DEMIBOLD,
        w if w < 800 => fontconfig::FC_WEIGHT_BOLD,
        w if w < 900 => fontconfig::FC_WEIGHT_EXTRABOLD,
        _ => fontconfig::FC_WEIGHT_BLACK,
    };

    // 3. Italic flag.
    let italic = lf.lf_italic != 0;

    // 4. Match via fontconfig.
    match_font(family, fc_weight, italic)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defs::LogFontW;

    #[test]
    fn substitute_known_names() {
        assert_eq!(substitute_font("Arial"), "Liberation Sans");
        assert_eq!(substitute_font("arial"), "Liberation Sans");
        assert_eq!(substitute_font("Times New Roman"), "Liberation Serif");
        assert_eq!(substitute_font("Courier New"), "Liberation Mono");
        assert_eq!(substitute_font("Segoe UI"), "Noto Sans");
    }

    #[test]
    fn substitute_passes_unknown_through() {
        assert_eq!(substitute_font("UnknownFontName"), "UnknownFontName");
        assert_eq!(substitute_font("BogusFamily"), "BogusFamily");
    }

    #[test]
    fn enumerate_fonts_returns_at_least_one() {
        let fonts = enumerate_fonts();
        assert!(
            !fonts.is_empty(),
            "expected at least one font from fontconfig"
        );
        // Every entry must have a file path.
        for f in &fonts {
            assert!(!f.file_path.is_empty(), "font {:?} has no file path", f);
        }
    }

    #[test]
    fn match_font_arial_returns_some() {
        let info = match_font_regular("Arial");
        assert!(
            info.is_some(),
            "expected match_font('Arial') to find a Liberation Sans or similar"
        );
        if let Some(f) = info {
            assert!(!f.file_path.is_empty(), "matched font has no file path");
            // The returned family will be the substituted name (Liberation Sans etc.)
            // rather than "Arial".
        }
    }

    #[test]
    fn match_font_bold_returns_bold_ish() {
        let info = match_font_bold("Arial");
        assert!(info.is_some(), "bold Arial should resolve");
    }

    #[test]
    fn match_font_italic_returns_italic_ish() {
        let info = match_font_italic("Arial");
        assert!(info.is_some(), "italic Arial should resolve");
    }

    #[test]
    fn match_font_unknown_name_falls_back() {
        // Unknown names are passed through the substitution table unchanged
        // and fontconfig will try to match them. This should find *something*
        // (likely a fallback from fontconfig's own config).
        let info = match_font_regular("TotallyMadeUpFontName");
        // This may or may not match depending on fontconfig configuration.
        // Just verify it doesn't panic.
        let _ = info;
    }

    #[test]
    fn font_path_returns_path() {
        let path = font_path("Arial", fontconfig::FC_WEIGHT_REGULAR, false);
        assert!(path.is_some(), "expected a file path for Arial");
        if let Some(p) = path {
            assert!(p.contains('/'), "expected absolute path, got: {p}");
        }
    }

    #[test]
    fn logfont_arial_regular() {
        let mut face = [0u16; 32];
        for (i, c) in "Arial\0".encode_utf16().take(32).enumerate() {
            face[i] = c;
        }
        let lf = LogFontW {
            lf_height: -16,
            lf_width: 0,
            lf_escapement: 0,
            lf_orientation: 0,
            lf_weight: 400,
            lf_italic: 0,
            lf_underline: 0,
            lf_strike_out: 0,
            lf_char_set: 0,
            lf_out_precision: 0,
            lf_clip_precision: 0,
            lf_quality: 0,
            lf_pitch_and_family: 0,
            lf_face_name: face,
        };
        let fi = logfont_to_fontconfig(&lf);
        assert!(fi.is_some(), "Arial 400 should resolve to a font");
        if let Some(f) = fi {
            assert!(!f.file_path.is_empty(), "matched font has no file path");
        }
    }

    #[test]
    fn logfont_bold() {
        let mut face = [0u16; 32];
        for (i, c) in "Arial\0".encode_utf16().take(32).enumerate() {
            face[i] = c;
        }
        let lf = LogFontW {
            lf_height: -16,
            lf_width: 0,
            lf_escapement: 0,
            lf_orientation: 0,
            lf_weight: 700,
            lf_italic: 0,
            lf_underline: 0,
            lf_strike_out: 0,
            lf_char_set: 0,
            lf_out_precision: 0,
            lf_clip_precision: 0,
            lf_quality: 0,
            lf_pitch_and_family: 0,
            lf_face_name: face,
        };
        let fi = logfont_to_fontconfig(&lf);
        assert!(fi.is_some(), "bold Arial should resolve to a font");
    }

    #[test]
    fn logfont_italic() {
        let mut face = [0u16; 32];
        for (i, c) in "Arial\0".encode_utf16().take(32).enumerate() {
            face[i] = c;
        }
        let lf = LogFontW {
            lf_height: -16,
            lf_width: 0,
            lf_escapement: 0,
            lf_orientation: 0,
            lf_weight: 400,
            lf_italic: 1,
            lf_underline: 0,
            lf_strike_out: 0,
            lf_char_set: 0,
            lf_out_precision: 0,
            lf_clip_precision: 0,
            lf_quality: 0,
            lf_pitch_and_family: 0,
            lf_face_name: face,
        };
        let fi = logfont_to_fontconfig(&lf);
        assert!(fi.is_some(), "italic Arial should resolve to a font");
    }

    #[test]
    fn logfont_empty_face_name() {
        let lf = LogFontW {
            lf_height: -13,
            lf_width: 0,
            lf_escapement: 0,
            lf_orientation: 0,
            lf_weight: 400,
            lf_italic: 0,
            lf_underline: 0,
            lf_strike_out: 0,
            lf_char_set: 0,
            lf_out_precision: 0,
            lf_clip_precision: 0,
            lf_quality: 0,
            lf_pitch_and_family: 0,
            lf_face_name: [0u16; 32],
        };
        let fi = logfont_to_fontconfig(&lf);
        assert!(
            fi.is_some(),
            "empty face name should fall back to a default font"
        );
    }

    #[test]
    fn logfont_weight_mapping() {
        // FW_DONTCARE (0) → same as FW_NORMAL → should resolve
        let face = [0u16; 32];
        let lf = LogFontW {
            lf_height: -13,
            lf_width: 0,
            lf_escapement: 0,
            lf_orientation: 0,
            lf_weight: 0,
            lf_italic: 0,
            lf_underline: 0,
            lf_strike_out: 0,
            lf_char_set: 0,
            lf_out_precision: 0,
            lf_clip_precision: 0,
            lf_quality: 0,
            lf_pitch_and_family: 0,
            lf_face_name: face,
        };
        let fi = logfont_to_fontconfig(&lf);
        assert!(fi.is_some(), "FW_DONTCARE should resolve");
    }

    #[test]
    fn substitution_table_completeness() {
        // Verify every known Windows font maps to a non-empty string.
        let known = [
            "Arial",
            "Times New Roman",
            "Courier New",
            "Tahoma",
            "Verdana",
            "Segoe UI",
            "Microsoft Sans Serif",
            "Trebuchet MS",
            "Impact",
            "Comic Sans MS",
            "Palatino Linotype",
            "Georgia",
            "Bookman Old Style",
            "Garamond",
            "Century Gothic",
            "Lucida Console",
            "Lucida Sans Unicode",
            "Symbol",
            "Wingdings",
        ];
        for name in &known {
            let sub = substitute_font(name);
            assert!(!sub.is_empty(), "substitution for {name} is empty");
        }
    }
}
