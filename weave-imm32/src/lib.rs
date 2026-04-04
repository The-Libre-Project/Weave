//! imm32.dll stubs for Weave — Input Method Manager.
//!
//! IMM provides access to input method editors (CJK text input). On Linux,
//! these are no-ops: we have no IME pipeline. Apps call these during init
//! and on keyboard events; returning null/failure values is safe.

#![allow(non_snake_case)]

/// ImmGetContext — retrieve the input context for a window.
///
/// Returns NULL (no IME context). Apps handle this gracefully.
///
/// # Safety
/// `hwnd` is ignored.
pub unsafe extern "win64" fn imm_get_context(_hwnd: usize) -> usize {
    0 // NULL HIMC
}

/// ImmReleaseContext — release an input context.
///
/// Returns TRUE (success no-op).
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_release_context(_hwnd: usize, _himc: usize) -> i32 {
    1 // TRUE
}

/// ImmGetCompositionStringW — get composition string data.
///
/// Returns 0 (empty string / no composition in progress).
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_get_composition_string_w(
    _himc: usize,
    _dw_index: u32,
    _lp_buf: *mut u8,
    _dw_buf_len: u32,
) -> i32 {
    0
}

/// ImmSetCompositionFontA — set the composition window font.
///
/// Returns TRUE (no-op).
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_set_composition_font_a(_himc: usize, _lp_lf: *const u8) -> i32 {
    1 // TRUE
}

/// ImmSetCompositionWindow — set the composition window position.
///
/// Returns TRUE (no-op).
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_set_composition_window(
    _himc: usize,
    _lp_comp_form: *const u8,
) -> i32 {
    1 // TRUE
}

/// Resolve an imm32.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("imm32.dll") {
        return None;
    }
    match func {
        "ImmGetContext" => Some(imm_get_context as *const () as usize),
        "ImmReleaseContext" => Some(imm_release_context as *const () as usize),
        "ImmGetCompositionStringW" => Some(imm_get_composition_string_w as *const () as usize),
        "ImmSetCompositionFontA" => Some(imm_set_composition_font_a as *const () as usize),
        "ImmSetCompositionWindow" => Some(imm_set_composition_window as *const () as usize),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_all_exports() {
        let funcs = [
            "ImmGetContext",
            "ImmReleaseContext",
            "ImmGetCompositionStringW",
            "ImmSetCompositionFontA",
            "ImmSetCompositionWindow",
        ];
        for f in &funcs {
            assert!(resolve("imm32.dll", f).is_some(), "missing: {f}");
        }
    }

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "ImmGetContext").is_none());
    }

    #[test]
    fn resolve_case_insensitive() {
        assert!(resolve("IMM32.DLL", "ImmGetContext").is_some());
    }
}
