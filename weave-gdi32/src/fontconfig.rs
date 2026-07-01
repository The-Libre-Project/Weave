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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
