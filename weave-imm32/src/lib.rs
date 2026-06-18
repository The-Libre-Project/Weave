//! imm32.dll stubs for Weave — Input Method Manager.
//!
//! IMM provides access to input method editors (CJK text input). On Linux,
//! these are no-ops: we have no IME pipeline. Apps call these during init
//! and on keyboard events; returning null/failure values is safe.

#![allow(non_snake_case, clippy::missing_safety_doc)]

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

/// ImmAssociateContext — associate/disassociate an IME context with a window.
///
/// SDL2 calls this at window creation with himc=NULL to detach IME.
/// Returns NULL (previous context, no IME active).
///
/// Wine ref: dlls/imm32/imm.c — stores HIMC in window property; returns previous HIMC.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_associate_context(_hwnd: usize, _himc: usize) -> usize {
    0 // NULL — no previous IME context
}

/// ImmGetCandidateListW — get the candidate list for an input context.
///
/// Returns 0 (no candidates; no IME active).
///
/// Wine ref: dlls/imm32/imm.c — returns required buffer size or 0 if no candidates.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_get_candidate_list_w(
    _himc: usize,
    _index: u32,
    _dest: *mut u8,
    _bytes: u32,
) -> u32 {
    0
}

/// ImmGetIMEFileNameA — get the filename of the current IME.
///
/// SDL2 calls this to detect IME presence. Returns 0 (no chars written, no IME).
///
/// Wine ref: dlls/imm32/imm.c — fills buf with IME filename; returns chars written.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_get_ime_file_name_a(
    _hkl: usize,
    _buf: *mut u8,
    _count: u32,
) -> u32 {
    0
}

/// ImmNotifyIME — notify the IME of an event.
///
/// Returns TRUE (success no-op).
///
/// Wine ref: dlls/imm32/imm.c::ImmNotifyIME — dispatches IME notification action.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_notify_ime(
    _himc: usize,
    _action: u32,
    _index: u32,
    _value: u32,
) -> i32 {
    1 // TRUE
}

/// ImmSetCompositionStringW — set the composition string.
///
/// Returns TRUE (success no-op).
///
/// Wine ref: dlls/imm32/imm.c — sets composition/reading string data in HIMC.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_set_composition_string_w(
    _himc: usize,
    _index: u32,
    _comp: *const u8,
    _comp_len: u32,
    _read: *const u8,
    _read_len: u32,
) -> i32 {
    1 // TRUE
}

/// ImmLockIMC — lock an input method context.
///
/// SDL2 loads imm32.dll dynamically then GetProcAddress for this.
/// Returns NULL (no IME active).
///
/// Wine ref: dlls/imm32/imm.c — increments HIMC lock count; returns INPUTCONTEXT*.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_lock_imc(_himc: usize) -> usize {
    0 // NULL
}

/// ImmUnlockIMC — unlock an input method context.
///
/// Returns TRUE (success no-op).
///
/// Wine ref: dlls/imm32/imm.c — decrements HIMC lock count.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_unlock_imc(_himc: usize) -> i32 {
    1 // TRUE
}

/// ImmLockIMCC — lock an IME component container.
///
/// Returns NULL (no IME active).
///
/// Wine ref: dlls/imm32/imm.c — locks HIMCC component; returns pointer to data.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_lock_imcc(_himcc: usize) -> usize {
    0 // NULL
}

/// ImmUnlockIMCC — unlock an IME component container.
///
/// Returns TRUE (success no-op).
///
/// Wine ref: dlls/imm32/imm.c — unlocks HIMCC component.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_unlock_imcc(_himcc: usize) -> i32 {
    1 // TRUE
}

// Wine ref: dlls/imm32/imm.c — ImmSetCandidateWindow sets candidate window
// position/style; no-op under Weave (no IME pipeline).
/// ImmSetCandidateWindow — set the candidate window info (stub). Returns TRUE.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_set_candidate_window(
    _himc: usize,
    _lp_candidate: *const u8,
) -> i32 {
    1 // TRUE
}

// Wine ref: dlls/imm32/imm.c — ImmEscapeW dispatches IME escape codes;
// no-op under Weave (no IME pipeline).
/// ImmEscapeW — send an escape code to an IME (stub). Returns 0.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_escape_w(_hkl: usize, _himc: usize, _index: u32) -> usize {
    0
}

// Wine ref: dlls/imm32/imm.c — ImmSetCompositionFontW sets the font for
// the composition window; stub returns TRUE.
/// ImmSetCompositionFontW — set the composition window font (stub). Returns TRUE.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn imm_set_composition_font_w(_himc: usize, _lp_lf: *const u8) -> i32 {
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
        "ImmAssociateContext" => {
            Some(imm_associate_context as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "ImmGetCandidateListW" => Some(
            imm_get_candidate_list_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "ImmGetIMEFileNameA" => Some(
            imm_get_ime_file_name_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "ImmNotifyIME" => {
            Some(imm_notify_ime as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "ImmSetCompositionStringW" => Some(
            imm_set_composition_string_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "ImmLockIMC" => {
            Some(imm_lock_imc as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ImmUnlockIMC" => {
            Some(imm_unlock_imc as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ImmLockIMCC" => {
            Some(imm_lock_imcc as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ImmUnlockIMCC" => {
            Some(imm_unlock_imcc as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // NPP startup imports
        "ImmSetCandidateWindow" => Some(
            imm_set_candidate_window as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "ImmEscapeW" => {
            Some(imm_escape_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "ImmSetCompositionFontW" => Some(
            imm_set_composition_font_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
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
            "ImmAssociateContext",
            "ImmGetCandidateListW",
            "ImmGetIMEFileNameA",
            "ImmNotifyIME",
            "ImmSetCompositionStringW",
            "ImmLockIMC",
            "ImmUnlockIMC",
            "ImmLockIMCC",
            "ImmUnlockIMCC",
            "ImmSetCandidateWindow",
            "ImmEscapeW",
            "ImmSetCompositionFontW",
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
