//! user32.dll stubs for Weave.
//!
//! Phase 2 scope: window creation, message loop, basic input, paint stubs.
//! Graphics (GDI) are in weave-gdi32 (Phase 2 Step 4).
//!
//! # Architecture
//!
//! - `defs`    — Win32 struct layouts and constants
//! - `class`   — window class registry (`RegisterClassW` → here)
//! - `window`  — HWND table (one entry per created window)
//! - `queue`   — global message queue (VecDeque<MsgEntry>)
//! - `backend` — X11 connection + event translation (Linux-only via x11rb)
//! - `api`     — Win32 API function implementations

pub mod api;
pub mod backend;
pub mod class;
pub mod clipboard;
pub mod defs;
pub mod font;
pub mod image_handles;
pub mod menu;
pub mod queue;
pub mod window;

// ── uxtheme.dll stubs ─────────────────────────────────────────────────────────
//
// UxTheme provides visual style (themed) drawing. In headless Docker there is
// no theme engine, so all functions return "no theme" or success-no-op.
// IrfanView calls IsThemeActive, OpenThemeData, DrawThemeBackground, and a
// handful of others to decide whether to use themed controls.
//
// Wine ref: dlls/uxtheme/uxtheme.c — IsThemeActive checks a global flag;
// OpenThemeData returns NULL when themes are inactive.

/// IsThemeActive — returns TRUE if visual styles are active system-wide.
///
/// Headless: always FALSE — no display, no theme engine.
// Wine ref: dlls/uxtheme/system.c:539 — reads module-global `bThemeActive` and
// unconditionally calls SetLastError(ERROR_SUCCESS) before returning, even on TRUE.
pub extern "win64" fn is_theme_active() -> i32 {
    0 // FALSE
}

/// IsAppThemed — returns TRUE if the calling process has themes enabled.
///
/// Headless: always FALSE.
// Wine ref: dlls/uxtheme/system.c:531 — pure alias for IsThemeActive(); no
// separate per-process theming state exists in Wine's implementation.
pub extern "win64" fn is_app_themed() -> i32 {
    0 // FALSE
}

/// OpenThemeData — open a theme handle for a window and class list.
///
/// Returns NULL — no theme available.
///
/// # Safety
/// `hwnd` and `psz_class_list` are ignored.
// Wine ref: dlls/uxtheme/system.c:678 — one-liner alias: `return OpenThemeDataEx(hwnd, classlist, 0)`.
pub unsafe extern "win64" fn open_theme_data(_hwnd: usize, _psz_class_list: *const u16) -> usize {
    0 // NULL
}

/// OpenThemeDataEx — extended OpenThemeData with flags.
///
/// # Safety
/// Arguments are ignored; returns NULL.
// Wine ref: dlls/uxtheme/system.c:656 — on failure sets SetLastError(E_PROP_ID_UNSUPPORTED)
// (an HRESULT, not a standard Win32 error) and calls SetPropW(hwnd, atWindowTheme, NULL)
// even when returning NULL, clearing any previously cached theme handle.
pub unsafe extern "win64" fn open_theme_data_ex(
    _hwnd: usize,
    _psz_class_list: *const u16,
    _dw_flags: u32,
) -> usize {
    0 // NULL
}

/// CloseThemeData — release a theme handle.
///
/// Wine ref: dlls/uxtheme/uxtheme.c — frees the theme object. No-op here.
pub extern "win64" fn close_theme_data(_h_theme: usize) -> i32 {
    0 // S_OK
}

/// DrawThemeBackground — render a themed part/state background.
///
/// No-op stub; returns S_OK so apps do not abort the paint cycle.
///
/// # Safety
/// `hdc`, `p_rect`, and `p_clip_rect` are ignored.
// Wine ref: dlls/uxtheme/draw.c:148 — thin wrapper that synthesizes DTBGOPTS with
// DTBG_CLIPRECT when pClipRect != NULL, then calls DrawThemeBackgroundEx. No drawing itself.
pub unsafe extern "win64" fn draw_theme_background(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _p_rect: *const i32,
    _p_clip_rect: *const i32,
) -> i32 {
    0 // S_OK
}

/// DrawThemeBackgroundEx — extended DrawThemeBackground with options.
///
/// # Safety
/// Arguments are ignored; returns S_OK.
// Wine ref: dlls/uxtheme/draw.c:1084 — reads TMT_BGTYPE first; if BT_NONE returns S_OK
// immediately without touching the DC. For BT_IMAGEFILE/BT_BORDERFILL calls UXTHEME_DrawGlyph
// as a second pass after the background fill.
pub unsafe extern "win64" fn draw_theme_background_ex(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _p_rect: *const i32,
    _p_options: *const u8,
) -> i32 {
    0 // S_OK
}

/// DrawThemeText — render themed text.
///
/// No-op; returns S_OK.
///
/// # Safety
/// `psz_text` and `p_rect` are ignored.
// Wine ref: dlls/uxtheme/draw.c:1753 — checks flags2 only for DTT_GRAYED; if set, forces
// DTT_TEXTCOLOR with GetSysColor(COLOR_GRAYTEXT), ignores all other flags2 bits, then
// delegates entirely to DrawThemeTextEx.
pub unsafe extern "win64" fn draw_theme_text(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _psz_text: *const u16,
    _i_char_count: i32,
    _dw_text_flags: u32,
    _dw_text_flags2: u32,
    _p_rect: *const i32,
) -> i32 {
    0 // S_OK
}

/// DrawThemeEdge — render a themed edge.
///
/// # Safety
/// `p_dest_rect` and `p_content_rect` are optional rect pointers.
// Wine ref: dlls/uxtheme/draw.c:1672 — dispatches to draw_diag_edge() vs draw_rect_edge()
// based on BF_DIAGONAL in uFlags; diagonal path is ~50% larger (distinct algorithm).
pub unsafe extern "win64" fn draw_theme_edge(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _p_dest_rect: *const i32,
    _u_edge: u32,
    _grf_flags: u32,
    _p_content_rect: *mut i32,
) -> i32 {
    0 // S_OK
}

/// DrawThemeIcon — render an icon via the theme engine.
///
/// # Safety
/// Arguments are ignored; returns S_OK.
// Wine ref: dlls/uxtheme/draw.c:1694 — reads TMT_ICONEFFECT to select ILS_* draw state;
// for ICE_PULSE reads TMT_SATURATION into params.Frame (not alpha); default alpha=128
// is only used for ICE_ALPHA path.
pub unsafe extern "win64" fn draw_theme_icon(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _p_rect: *const i32,
    _himl: usize,
    _i_image_index: i32,
) -> i32 {
    0 // S_OK
}

/// GetThemePartSize — query the size of a themed part.
///
/// Returns E_NOTIMPL so the caller uses its own sizing logic.
///
/// # Safety
/// `p_sz` is written only on success; we don't write it.
// Wine ref: dlls/uxtheme/draw.c:2126 — if TMT_BGTYPE resolves to BT_NONE, returns S_OK
// with psz={1,1} (1×1 sentinel, not zero). Callers must handle this case.
pub unsafe extern "win64" fn get_theme_part_size(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _p_rect: *const i32,
    _e_size: i32,
    _p_sz: *mut i32,
) -> i32 {
    0x80004001u32 as i32 // E_NOTIMPL
}

/// GetThemeMetric — query a themed integer metric (e.g. border width).
///
/// Returns E_NOTIMPL.
///
/// # Safety
/// `pi_val` is not written.
// Wine ref: dlls/uxtheme/property.c:238 — TMT_POSITION returns only X coord,
// TMT_MARGINS returns only cxLeftWidth, TMT_INTLIST returns only first element —
// all silently truncated to a single int.
pub unsafe extern "win64" fn get_theme_metric(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _i_prop_id: i32,
    _pi_val: *mut i32,
) -> i32 {
    0x80004001u32 as i32 // E_NOTIMPL
}

/// GetThemeColor — query a themed colour value.
///
/// Returns E_NOTIMPL.
///
/// # Safety
/// `p_color` is not written.
// Wine ref: dlls/uxtheme/property.c:57 — on any lookup failure returns E_PROP_ID_UNSUPPORTED
// (not E_INVALIDARG). Passing a non-color iPropId always fails with E_PROP_ID_UNSUPPORTED
// regardless of whether the property exists under a different type.
pub unsafe extern "win64" fn get_theme_color(
    _h_theme: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _i_prop_id: i32,
    _p_color: *mut u32,
) -> i32 {
    0x80004001u32 as i32 // E_NOTIMPL
}

/// GetThemeFont — query a themed LOGFONTW.
///
/// Returns E_NOTIMPL.
///
/// # Safety
/// `p_font` is not written.
// Wine ref: dlls/uxtheme/property.c:117 — hdc is passed to MSSTYLES_GetPropertyFont
// but only used for device-unit size conversion; not validated. Lookup uses TMT_FONT
// primitive type filter via MSSTYLES_FindProperty.
pub unsafe extern "win64" fn get_theme_font(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _i_prop_id: i32,
    _p_font: *mut u8,
) -> i32 {
    0x80004001u32 as i32 // E_NOTIMPL
}

/// GetThemeSysColor — query a system colour via the theme engine.
///
/// Falls back to 0 (black) since no theme is active.
// Wine ref: dlls/uxtheme/metric.c:71 — if hTheme is NULL or metric not found, falls
// through to GetSysColor(iColorID) passing the ID directly as a COLOR_* index.
// Also calls SetLastError(0) on entry (explicit zero, same as ERROR_SUCCESS).
pub extern "win64" fn get_theme_sys_color(_h_theme: usize, _i_color_id: i32) -> u32 {
    0
}

/// GetThemeSysColorBrush — get a system-colour brush via the theme engine.
///
/// Returns NULL — caller must fall back to GetSysColorBrush.
// Wine ref: dlls/uxtheme/metric.c:94 — always calls CreateSolidBrush(GetThemeSysColor(...));
// allocates a new GDI brush on every call, never cached. Caller must DeleteObject.
pub extern "win64" fn get_theme_sys_color_brush(_h_theme: usize, _i_color_id: i32) -> usize {
    0 // NULL
}

/// GetThemeSysFont — query a system font via the theme engine.
///
/// Returns E_NOTIMPL.
///
/// # Safety
/// `p_lf` is not written.
// Wine ref: dlls/uxtheme/metric.c:103 — falls back to SPI_GETICONTITLELOGFONT only for
// TMT_ICONTITLEFONT; all others use SPI_GETNONCLIENTMETRICS with a switch on ID for
// lfCaptionFont/lfSmCaptionFont/lfMenuFont/lfStatusFont/lfMessageFont. Unknown IDs hit
// FIXME and return without writing *plf.
pub unsafe extern "win64" fn get_theme_sys_font(
    _h_theme: usize,
    _i_font_id: i32,
    _p_lf: *mut u8,
) -> i32 {
    0x80004001u32 as i32 // E_NOTIMPL
}

/// IsThemePartDefined — check whether a part/state is defined in the theme.
///
/// Returns FALSE — no theme, no parts.
// Wine ref: dlls/uxtheme/system.c:800 — checks !iStateId first; if iStateId != 0,
// returns FALSE without calling MSSTYLES_FindPart at all. Only part-level (state 0) queries
// are supported.
pub extern "win64" fn is_theme_part_defined(
    _h_theme: usize,
    _i_part_id: i32,
    _i_state_id: i32,
) -> i32 {
    0 // FALSE
}

/// IsThemeBackgroundPartiallyTransparent — check if a part uses alpha.
///
/// Returns FALSE — safe default that avoids transparency compositing.
// Wine ref: dlls/uxtheme/draw.c:2232 — returns FALSE immediately if TMT_BGTYPE != BT_IMAGEFILE;
// border-fill backgrounds are never partially transparent. Returns FALSE (not error) if
// hTheme == NULL.
pub extern "win64" fn is_theme_background_partially_transparent(
    _h_theme: usize,
    _i_part_id: i32,
    _i_state_id: i32,
) -> i32 {
    0 // FALSE
}

/// SetWindowTheme — override the visual style class for a window.
///
/// No-op stub; returns S_OK.
///
/// # Safety
/// `h_wnd`, `psz_sub_app_name`, `psz_sub_id_list` are ignored.
// Wine ref: dlls/uxtheme/system.c:712 — stores pszSubAppName/pszSubIdList as window
// properties via SetPropW, then sends WM_THEMECHANGED to force immediate re-open of any
// cached theme handle (not lazily deferred).
pub unsafe extern "win64" fn set_window_theme(
    _h_wnd: usize,
    _psz_sub_app_name: *const u16,
    _psz_sub_id_list: *const u16,
) -> i32 {
    0 // S_OK
}

/// EnableThemeDialogTexture — enable/disable themed dialog texture.
///
/// No-op; returns S_OK.
// Wine ref: dlls/uxtheme/draw.c:55 — masks new_flag with ETDT_VALIDBITS; if ETDT_DISABLE
// is set, clears all other bits and sets old_flag=0. Returns S_OK without touching the
// window property if the masked new_flag == 0.
pub extern "win64" fn enable_theme_dialog_texture(_h_wnd: usize, _dw_flags: u32) -> i32 {
    0 // S_OK
}

/// GetThemeAppProperties — query global theme property flags.
///
/// Returns 0 — no theme flags.
// Wine ref: dlls/uxtheme/system.c:758 — direct read of module-global dwThemeAppProperties
// DWORD; no handle, no validation, no error path.
pub extern "win64" fn get_theme_app_properties() -> u32 {
    0
}

/// SetThemeAppProperties — set global theme property flags.
// Wine ref: dlls/uxtheme/system.c:766 — writes directly to dwThemeAppProperties with no
// flag validation, no notification to other windows, no return value.
pub extern "win64" fn set_theme_app_properties(_dw_flags: u32) {}

/// BufferedPaintInit — initialise the buffered-paint API.
// Wine ref: dlls/uxtheme/buffer.c:60 — complete stub (FIXME + return S_OK); BeginBufferedPaint
// works regardless of whether Init was called, so the no-op is behaviorally correct.
pub extern "win64" fn buffered_paint_init() -> i32 {
    0 // S_OK
}

/// BufferedPaintUnInit — shut down the buffered-paint API.
// Wine ref: dlls/uxtheme/buffer.c:68 — identical stub to BufferedPaintInit; no cleanup performed.
pub extern "win64" fn buffered_paint_un_init() -> i32 {
    0 // S_OK
}

/// EndBufferedAnimation — end a buffered animation (commit final frame).
///
/// Wine ref: dlls/uxtheme/animation.c — EndBufferedAnimation calls EndPaint on
/// the window; Weave no-ops since we have no animation infrastructure.
pub extern "win64" fn end_buffered_animation(_h_bp_animation: usize, _f_update_target: i32) -> i32 {
    0 // S_OK
}

/// GetThemeTransitionDuration — query animation duration for a theme transition.
///
/// Wine ref: dlls/uxtheme/uxtheme.c — returns E_FAIL (theme not active).
/// Weave: returns 0 duration (no transition).
///
/// # Safety
/// Pointer arguments must be valid for the duration of the call; null where noted is permitted.
pub unsafe extern "win64" fn get_theme_transition_duration(
    _h_theme: usize,
    _i_part_id: i32,
    _i_state_id_from: i32,
    _i_state_id_to: i32,
    _prop_id: i32,
    pdw_duration: *mut u32,
) -> i32 {
    if !pdw_duration.is_null() {
        unsafe { *pdw_duration = 0 };
    }
    0 // S_OK
}

/// DrawThemeParentBackground — redraw the parent window background.
///
/// Wine ref: dlls/uxtheme/uxtheme.c — SendMessage(parent, WM_ERASEBKGND/WM_PRINTCLIENT).
/// Weave: no-op (S_OK); background is handled by BeginPaint/EndPaint in our backend.
pub extern "win64" fn draw_theme_parent_background(_hwnd: usize, _hdc: usize, _prc: usize) -> i32 {
    0 // S_OK
}

/// GetThemeBackgroundContentRect — compute inner content rect of a themed part.
///
/// Wine ref: dlls/uxtheme/uxtheme.c — subtracts margins from the bounding rect.
/// Weave: returns the bounding rect unchanged (no margins).
///
/// # Safety
/// Pointer arguments must be valid for the duration of the call; null where noted is permitted.
pub unsafe extern "win64" fn get_theme_background_content_rect(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    p_bounding_rect: *const [i32; 4],
    p_content_rect: *mut [i32; 4],
) -> i32 {
    if !p_bounding_rect.is_null() && !p_content_rect.is_null() {
        unsafe { *p_content_rect = *p_bounding_rect };
    }
    0 // S_OK
}

/// DrawThemeTextEx — draw themed text with additional options.
///
/// Wine ref: dlls/uxtheme/uxtheme.c — draws text using GDI with theme font/color.
/// Weave: no-op (S_OK); text is drawn directly by GDI functions we implement.
pub extern "win64" fn draw_theme_text_ex(
    _h_theme: usize,
    _hdc: usize,
    _i_part_id: i32,
    _i_state_id: i32,
    _psz_text: usize,
    _cch_text: i32,
    _dw_text_flags: u32,
    _p_rect: usize,
    _p_options: usize,
) -> i32 {
    0 // S_OK
}

/// BufferedPaintStopAllAnimations — stop buffered animations for a window.
///
/// Wine ref: dlls/uxtheme/animation.c — iterates the animation list.
/// Weave: no-op (S_OK), no animation list exists.
pub extern "win64" fn buffered_paint_stop_all_animations(_hwnd: usize) -> i32 {
    0 // S_OK
}

/// BeginBufferedAnimation — start a buffered animation.
///
/// Wine ref: dlls/uxtheme/animation.c — allocates an animation context.
/// Weave: returns NULL (no animation support); callers must handle NULL gracefully.
pub extern "win64" fn begin_buffered_animation(
    _hwnd: usize,
    _hdc_target: usize,
    _prc_target: usize,
    _dw_format: u32,
    _p_paint_params: usize,
    _p_animation_params: usize,
    _phdc_from: usize,
    _phdc_to: usize,
) -> usize {
    0 // NULL — no animation handle
}

/// BufferedPaintRenderAnimation — render the current frame of a buffered animation.
///
/// Wine ref: dlls/uxtheme/animation.c — blends from/to frames.
/// Weave: returns FALSE (no animation running).
pub extern "win64" fn buffered_paint_render_animation(_hwnd: usize, _hdc_target: usize) -> i32 {
    0 // FALSE — no animation to render
}

/// Resolve a uxtheme.dll import to a stub address.
///
/// Called by weave-cli's resolve chain.
pub fn resolve_uxtheme(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("uxtheme.dll") {
        return None;
    }
    Some(match func {
        "IsThemeActive" => is_theme_active as *const () as usize,
        "IsAppThemed" => is_app_themed as *const () as usize,
        "OpenThemeData" => open_theme_data as *const () as usize,
        "OpenThemeDataEx" => open_theme_data_ex as *const () as usize,
        "CloseThemeData" => close_theme_data as *const () as usize,
        "DrawThemeBackground" => draw_theme_background as *const () as usize,
        "DrawThemeBackgroundEx" => draw_theme_background_ex as *const () as usize,
        "DrawThemeText" => draw_theme_text as *const () as usize,
        "DrawThemeEdge" => draw_theme_edge as *const () as usize,
        "DrawThemeIcon" => draw_theme_icon as *const () as usize,
        "GetThemePartSize" => get_theme_part_size as *const () as usize,
        "GetThemeMetric" => get_theme_metric as *const () as usize,
        "GetThemeColor" => get_theme_color as *const () as usize,
        "GetThemeFont" => get_theme_font as *const () as usize,
        "GetThemeSysColor" => get_theme_sys_color as *const () as usize,
        "GetThemeSysColorBrush" => get_theme_sys_color_brush as *const () as usize,
        "GetThemeSysFont" => get_theme_sys_font as *const () as usize,
        "IsThemePartDefined" => is_theme_part_defined as *const () as usize,
        "IsThemeBackgroundPartiallyTransparent" => {
            is_theme_background_partially_transparent as *const () as usize
        }
        "SetWindowTheme" => set_window_theme as *const () as usize,
        "EnableThemeDialogTexture" => enable_theme_dialog_texture as *const () as usize,
        "GetThemeAppProperties" => get_theme_app_properties as *const () as usize,
        "SetThemeAppProperties" => set_theme_app_properties as *const () as usize,
        "BufferedPaintInit" => buffered_paint_init as *const () as usize,
        "BufferedPaintUnInit" => buffered_paint_un_init as *const () as usize,
        "EndBufferedAnimation" => end_buffered_animation as *const () as usize,
        "GetThemeTransitionDuration" => get_theme_transition_duration as *const () as usize,
        "DrawThemeParentBackground" => draw_theme_parent_background as *const () as usize,
        "GetThemeBackgroundContentRect" => get_theme_background_content_rect as *const () as usize,
        "DrawThemeTextEx" => draw_theme_text_ex as *const () as usize,
        "BufferedPaintStopAllAnimations" => {
            buffered_paint_stop_all_animations as *const () as usize
        }
        "BeginBufferedAnimation" => begin_buffered_animation as *const () as usize,
        "BufferedPaintRenderAnimation" => buffered_paint_render_animation as *const () as usize,
        _ => return None,
    })
}

// ── dwmapi.dll stubs ──────────────────────────────────────────────────────────
//
// Desktop Window Manager API. NPP uses DwmSetWindowAttribute to enable rounded
// corners / Mica blur on Windows 11, and DwmGetColorizationColor for the accent
// colour. Both are cosmetic; returning safe defaults is correct for headless use.
//
// Wine ref: dlls/dwmapi/dwmapi_main.c — both functions are FIXME stubs returning
// S_OK / a hardcoded colour. Weave does the same.

/// DwmSetWindowAttribute — set a DWM attribute on a window.
///
/// Wine ref: dlls/dwmapi/dwmapi_main.c — FIXME stub, returns S_OK.
///
/// # Safety
/// `pv_attribute` is ignored.
pub unsafe extern "win64" fn dwm_set_window_attribute(
    _hwnd: usize,
    _dw_attribute: u32,
    _pv_attribute: *const u8,
    _cb_attribute: u32,
) -> i32 {
    0 // S_OK
}

/// DwmGetColorizationColor — query the current DWM accent colour.
///
/// Wine ref: dlls/dwmapi/dwmapi_main.c — FIXME stub returning a hardcoded
/// blue/purple colour with opaque blend disabled.
///
/// # Safety
/// Output pointers may be NULL.
pub unsafe extern "win64" fn dwm_get_colorization_color(
    pcr_colorization: *mut u32,
    pf_opaque_blend: *mut i32,
) -> i32 {
    if !pcr_colorization.is_null() {
        unsafe { *pcr_colorization = 0x640050EF }; // ABGR blue-purple accent
    }
    if !pf_opaque_blend.is_null() {
        unsafe { *pf_opaque_blend = 0 }; // FALSE — not opaque
    }
    0 // S_OK
}

/// Resolve a dwmapi.dll import to a stub address.
pub fn resolve_dwmapi(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("dwmapi.dll") {
        return None;
    }
    Some(match func {
        "DwmSetWindowAttribute" => dwm_set_window_attribute as *const () as usize,
        "DwmGetColorizationColor" => dwm_get_colorization_color as *const () as usize,
        _ => return None,
    })
}

// ─────────────────────────────────────────────────────────────────────────────

/// Resolve a user32.dll import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    // Also handle uxtheme.dll — UI theming, closely related to user32.
    if let Some(addr) = resolve_uxtheme(dll, func) {
        return Some(addr);
    }
    // dwmapi.dll — Desktop Window Manager, closely related to user32 windowing.
    if let Some(addr) = resolve_dwmapi(dll, func) {
        return Some(addr);
    }

    if !dll.eq_ignore_ascii_case("user32.dll") {
        return None;
    }
    use api::*;
    match func {
        // Window class registration
        "RegisterClassW" => {
            Some(register_class_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RegisterClassExW" => {
            Some(register_class_ex_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Window lifecycle
        "CreateWindowExW" => Some(
            create_window_ex_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "ShowWindow" => Some(show_window as *const () as usize),
        "UpdateWindow" => Some(update_window as *const () as usize),
        "DestroyWindow" => Some(destroy_window as *const () as usize),
        // Message loop
        "GetMessageW" => {
            Some(get_message_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "PeekMessageW" => Some(
            peek_message_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "TranslateMessage" => {
            Some(translate_message as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "DispatchMessageW" => {
            Some(dispatch_message_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "PostQuitMessage" => Some(post_quit_message as *const () as usize),
        "PostMessageW" => Some(post_message_w as *const () as usize),
        "SendMessageW" => Some(send_message_w as *const () as usize),
        "SendMessageTimeoutW" => Some(
            send_message_timeout_w as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        // Default window procedure
        "DefWindowProcW" => Some(def_window_proc_w as *const () as usize),
        // Geometry
        "GetClientRect" => {
            Some(get_client_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetWindowRect" => {
            Some(get_window_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "InvalidateRect" => {
            Some(invalidate_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "ValidateRect" => {
            Some(validate_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CopyImage" => {
            Some(copy_image as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "GetUpdateRect" => {
            Some(get_update_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "MoveWindow" => Some(move_window as *const () as usize),
        "AdjustWindowRect" => {
            Some(adjust_window_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "AdjustWindowRectEx" => Some(
            adjust_window_rect_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Window title
        "SetWindowTextW" => {
            Some(set_window_text_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetWindowTextA" => {
            Some(set_window_text_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetWindowTextW" => {
            Some(get_window_text_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // Focus
        "SetFocus" => Some(set_focus as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "SetKeyboardState" => {
            Some(set_keyboard_state as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // System metrics
        "GetSystemMetrics" => Some(get_system_metrics as *const () as usize),
        "GetSystemMetricsForDpi" => {
            Some(get_system_metrics_for_dpi as extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Cursor / icon
        "LoadCursorW" => {
            Some(load_cursor_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LoadCursorA" => {
            Some(load_cursor_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LoadIconW" => {
            Some(load_icon_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LoadImageW" => Some(
            load_image_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "SetCursor" => Some(set_cursor as *const () as usize),
        "ShowCursor" => Some(show_cursor as *const () as usize),
        // Window property store
        "SetPropA" | "SetPropW" => {
            Some(set_prop_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "GetPropA" | "GetPropW" => {
            Some(get_prop_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RemovePropA" | "RemovePropW" => {
            Some(remove_prop_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Message box
        "MessageBoxW" => {
            Some(message_box_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        // DC (user32 owns GetDC/ReleaseDC, not gdi32)
        "GetDC" => Some(get_dc as *const () as usize),
        "ReleaseDC" => Some(release_dc as *const () as usize),
        // Paint
        "BeginPaint" => {
            Some(begin_paint as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "EndPaint" => Some(end_paint as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        // Foreground / desktop
        "GetForegroundWindow" => Some(get_foreground_window as *const () as usize),
        "SetForegroundWindow" => Some(set_foreground_window as *const () as usize),
        "GetDesktopWindow" => Some(get_desktop_window as *const () as usize),
        // Clipboard
        "OpenClipboard" => Some(clipboard::open_clipboard as *const () as usize),
        "CloseClipboard" => Some(clipboard::close_clipboard as *const () as usize),
        "EmptyClipboard" => Some(clipboard::empty_clipboard as *const () as usize),
        "SetClipboardData" => Some(clipboard::set_clipboard_data as *const () as usize),
        "GetClipboardData" => Some(clipboard::get_clipboard_data as *const () as usize),
        "IsClipboardFormatAvailable" => {
            Some(clipboard::is_clipboard_format_available as *const () as usize)
        }
        "CountClipboardFormats" => Some(clipboard::count_clipboard_formats as *const () as usize),
        "GetClipboardOwner" => Some(clipboard::get_clipboard_owner as *const () as usize),
        // Menus
        "CreateMenu" => Some(menu::create_menu as *const () as usize),
        "CreatePopupMenu" => Some(menu::create_popup_menu as *const () as usize),
        "AppendMenuW" => Some(
            menu::append_menu_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "InsertMenuItemW" => Some(
            menu::insert_menu_item_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetMenu" => Some(menu::set_menu as *const () as usize),
        "GetMenu" => Some(menu::get_menu as *const () as usize),
        "DestroyMenu" => Some(menu::destroy_menu as *const () as usize),
        "TrackPopupMenu" => Some(menu::track_popup_menu as *const () as usize),
        "TrackPopupMenuEx" => Some(menu::track_popup_menu_ex as *const () as usize),
        "GetMenuItemCount" => Some(menu::get_menu_item_count as *const () as usize),
        "CheckMenuItem" => Some(menu::check_menu_item as *const () as usize),
        "EnableMenuItem" => Some(menu::enable_menu_item as *const () as usize),
        "GetMenuStringW" => Some(
            menu::get_menu_string_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetMenuItemBitmaps" => Some(menu::set_menu_item_bitmaps as *const () as usize),
        "GetMenuState" => Some(menu::get_menu_state as *const () as usize),
        "ModifyMenuW" => Some(
            menu::modify_menu_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetMenuItemID" => Some(menu::get_menu_item_id as *const () as usize),
        "GetSubMenu" => Some(menu::get_sub_menu as *const () as usize),
        // Display and mode enumeration
        "EnumDisplayDevicesW" => Some(
            enum_display_devices_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "EnumDisplaySettingsW" => Some(
            enum_display_settings_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "EnumDisplaySettingsExW" => Some(
            enum_display_settings_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "ChangeDisplaySettingsW" => Some(
            change_display_settings_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "ChangeDisplaySettingsExW" => Some(
            change_display_settings_ex_w as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        // Monitor handle functions
        "MonitorFromWindow" => Some(monitor_from_window as *const () as usize),
        "MonitorFromPoint" => Some(monitor_from_point as *const () as usize),
        "MonitorFromRect" => {
            Some(monitor_from_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetMonitorInfoW" => {
            Some(get_monitor_info_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "EnumDisplayMonitors" => Some(
            enum_display_monitors as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Window long + SetWindowPos
        "GetWindowLongW" => Some(get_window_long_w as *const () as usize),
        "GetWindowLongPtrW" => Some(get_window_long_ptr_w as *const () as usize),
        "SetWindowLongW" => Some(set_window_long_w as *const () as usize),
        "SetWindowLongPtrW" => Some(set_window_long_ptr_w as *const () as usize),
        "SetWindowPos" => Some(set_window_pos as *const () as usize),
        "BeginDeferWindowPos" => Some(begin_defer_window_pos as *const () as usize),
        "DeferWindowPos" => Some(defer_window_pos as *const () as usize),
        "EndDeferWindowPos" => Some(end_defer_window_pos as *const () as usize),
        // Window queries
        "FindWindowW" => {
            Some(find_window_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindWindowA" => {
            Some(find_window_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "IsWindow" => Some(is_window as *const () as usize),
        "IsWindowVisible" => Some(is_window_visible as *const () as usize),
        "GetWindowThreadProcessId" => Some(
            get_window_thread_process_id as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "ScreenToClient" => {
            Some(screen_to_client as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "ClientToScreen" => {
            Some(client_to_screen as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Cursor + misc window ops
        "GetCursorPos" => {
            Some(get_cursor_pos as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetCursorPos" => Some(set_cursor_pos as *const () as usize),
        "GetClipCursor" => {
            Some(get_clip_cursor as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ClipCursor" => Some(clip_cursor as *const () as usize),
        "EnableWindow" => Some(enable_window as *const () as usize),
        "IsWindowEnabled" => Some(is_window_enabled as *const () as usize),
        "GetParent" => Some(get_parent as *const () as usize),
        "SetParent" => Some(set_parent as *const () as usize),
        "BringWindowToTop" => Some(bring_window_to_top as *const () as usize),
        "WindowFromPoint" => Some(window_from_point as *const () as usize),
        // DPI awareness stubs
        "SetProcessDPIAware" => Some(set_process_dpi_aware as *const () as usize),
        "GetDpiForWindow" => Some(get_dpi_for_window as *const () as usize),
        "GetDpiForSystem" => Some(get_dpi_for_system as *const () as usize),
        "AdjustWindowRectExForDpi" => Some(
            adjust_window_rect_ex_for_dpi as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        "SetProcessDpiAwarenessContext" => {
            Some(set_process_dpi_awareness_context as *const () as usize)
        }
        "GetDpiAwarenessContextForProcess" => {
            Some(get_dpi_awareness_context_for_process as *const () as usize)
        }
        "AreDpiAwarenessContextsEqual" => {
            Some(are_dpi_awareness_contexts_equal as *const () as usize)
        }
        // Input state stubs
        "GetKeyState" => Some(get_key_state as *const () as usize),
        "GetAsyncKeyState" => Some(get_async_key_state as *const () as usize),
        "MapVirtualKeyW" => Some(map_virtual_key_w as *const () as usize),
        "MapVirtualKeyExW" => Some(map_virtual_key_ex_w as *const () as usize),
        "GetKeyboardLayout" => Some(get_keyboard_layout as *const () as usize),
        "GetKeyboardLayoutList" => Some(
            get_keyboard_layout_list as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "VkKeyScanW" => Some(vk_key_scan_w as *const () as usize),
        "GetKeyboardState" => {
            Some(get_keyboard_state as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ToUnicodeEx" => Some(
            to_unicode_ex as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // ── ANSI window class wrappers ───────────────────────────��────────
        "RegisterClassA" => {
            Some(register_class_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RegisterClassExA" => {
            Some(register_class_ex_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // ── ANSI window creation ──────────────────────────────────────────
        "CreateWindowExA" => Some(
            create_window_ex_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        // ── ANSI message loop ─────────────────────────────────────────────
        "GetMessageA" => {
            Some(get_message_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "PeekMessageA" => Some(
            peek_message_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "DispatchMessageA" => {
            Some(dispatch_message_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "PostMessageA" => Some(post_message_a as *const () as usize),
        "SendMessageA" => Some(send_message_a as *const () as usize),
        "DefWindowProcA" => Some(def_window_proc_a as *const () as usize),
        // ── ANSI window text / class ──────────────────────────────────────
        "GetWindowTextA" => {
            Some(get_window_text_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "GetWindowTextLengthA" => Some(get_window_text_length_a as *const () as usize),
        "GetWindowLongPtrA" => Some(get_window_long_ptr_a as *const () as usize),
        "SetWindowLongPtrA" => Some(set_window_long_ptr_a as *const () as usize),
        "SetClassLongPtrA" => Some(
            set_class_long_ptr_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        // ── ANSI resource loading ─────────────────────────────────────────
        "LoadIconA" => {
            Some(load_icon_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "LoadImageA" => Some(
            load_image_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "DestroyIcon" => Some(destroy_icon as *const () as usize),
        // ── ANSI message box ──────────────────────────────────────────────
        "MessageBoxA" => {
            Some(message_box_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "MessageBoxIndirectW" => {
            Some(message_box_indirect_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // ── ANSI menu helpers ─────────────────────────────────────────────
        "AppendMenuA" => {
            Some(append_menu_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "InsertMenuA" => Some(
            insert_menu_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetSystemMenu" => Some(get_system_menu as *const () as usize),
        "DeleteMenu" => Some(delete_menu as *const () as usize),
        // ── Dialog stubs ──────────────────────────────────────────────────
        "DefDlgProcA" => Some(def_dlg_proc_a as *const () as usize),
        "DialogBoxParamA" => Some(
            dialog_box_param_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateDialogParamA" => Some(
            create_dialog_param_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateDialogParamW" => Some(
            create_dialog_param_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateDialogIndirectParamW" => Some(
            create_dialog_indirect_param_w as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        "EndDialog" => Some(end_dialog as *const () as usize),
        "GetDlgCtrlID" => Some(get_dlg_ctrl_id as *const () as usize),
        "GetDlgItem" => Some(get_dlg_item as *const () as usize),
        "GetDlgItemTextA" => Some(
            get_dlg_item_text_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetDlgItemTextW" => Some(
            get_dlg_item_text_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "SetDlgItemTextA" => Some(
            set_dlg_item_text_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "SetDlgItemTextW" => Some(
            set_dlg_item_text_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "SendDlgItemMessageA" => Some(send_dlg_item_message_a as *const () as usize),
        "CheckDlgButton" => Some(check_dlg_button as *const () as usize),
        "IsDlgButtonChecked" => Some(is_dlg_button_checked as *const () as usize),
        "CheckRadioButton" => Some(check_radio_button as *const () as usize),
        "IsDialogMessageA" => {
            Some(is_dialog_message_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "MapDialogRect" => {
            Some(map_dialog_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // ── Window state ──────────────────────────────────────────────────
        "IsIconic" => Some(is_iconic as *const () as usize),
        "IsZoomed" => Some(is_zoomed as *const () as usize),
        "FlashWindow" => Some(flash_window as *const () as usize),
        "GetWindowPlacement" => {
            Some(get_window_placement as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetWindowPlacement" => {
            Some(set_window_placement as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // ── Timers ────────────────────────────────────────────────────────
        "SetTimer" => {
            Some(set_timer as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "KillTimer" => Some(kill_timer as *const () as usize),
        // ── Message helpers ───────────────────────────────────────────────
        "GetMessageTime" => Some(get_message_time as *const () as usize),
        "GetMessagePos" => Some(get_message_pos as *const () as usize),
        "GetQueueStatus" => Some(get_queue_status as *const () as usize),
        "MsgWaitForMultipleObjects" => Some(
            msg_wait_for_multiple_objects as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        // ── Mouse capture ─────────────────────────────────────────────────
        "GetCapture" => Some(get_capture as *const () as usize),
        "SetCapture" => Some(set_capture as *const () as usize),
        "ReleaseCapture" => Some(release_capture as *const () as usize),
        "SetActiveWindow" => Some(set_active_window as *const () as usize),
        // ── System colors ─────────────────────────────────────────────────
        "GetSysColor" => Some(get_sys_color as *const () as usize),
        "GetSysColorBrush" => Some(get_sys_color_brush as *const () as usize),
        // ── Scrollbar ───────────────────────────────���────────────────────
        "GetScrollInfo" => {
            Some(get_scroll_info as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "SetScrollInfo" => {
            Some(set_scroll_info as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        // ── Caret ────────────────────────────────────────────────────────
        "CreateCaret" => Some(create_caret as *const () as usize),
        "DestroyCaret" => Some(destroy_caret as *const () as usize),
        "ShowCaret" => Some(show_caret as *const () as usize),
        "HideCaret" => Some(hide_caret as *const () as usize),
        "SetCaretPos" => Some(set_caret_pos as *const () as usize),
        "GetCaretPos" => {
            Some(get_caret_pos as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetCaretBlinkTime" => Some(get_caret_blink_time as *const () as usize),
        // ── Misc ──────────────────────────────────────────────────────────
        "MessageBeep" => Some(message_beep as *const () as usize),
        "GetDoubleClickTime" => Some(get_double_click_time as *const () as usize),
        "OffsetRect" => {
            Some(offset_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "DrawEdge" => {
            Some(draw_edge as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "DrawIconEx" => Some(
            draw_icon_ex as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RegisterClipboardFormatA" => Some(
            register_clipboard_format_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "RegisterWindowMessageA" => Some(
            register_window_message_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "RegisterWindowMessageW" => Some(
            register_window_message_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SystemParametersInfoA" => Some(
            system_parameters_info_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "ToAsciiEx" => Some(
            to_ascii_ex as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "CharUpperW" => {
            Some(api::char_upper_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CharPrevExA" => Some(
            api::char_prev_ex_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetMenuItemInfoW" => Some(
            api::get_menu_item_info_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetMenuItemInfoW" => Some(
            api::set_menu_item_info_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "LoadStringW" => Some(
            api::load_string_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "LoadStringA" => Some(
            api::load_string_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "RegisterClipboardFormatW" => Some(
            api::register_clipboard_format_w as unsafe extern "win64" fn(_) -> _ as *const ()
                as usize,
        ),
        "GetWindowTextLengthW" => Some(
            api::get_window_text_length_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SystemParametersInfoW" => Some(
            api::system_parameters_info_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetMonitorInfoA" => Some(
            api::get_monitor_info_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetDialogBaseUnits" => Some(api::get_dialog_base_units as *const () as usize),
        "ChildWindowFromPointEx" => Some(
            api::child_window_from_point_ex as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "LoadMenuW" => {
            Some(api::load_menu_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "DrawMenuBar" => {
            Some(api::draw_menu_bar as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CheckMenuRadioItem" => Some(
            api::check_menu_radio_item as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RemoveMenu" => {
            Some(api::remove_menu as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "SendDlgItemMessageW" => Some(
            api::send_dlg_item_message_w as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        "LoadAcceleratorsW" => Some(
            api::load_accelerators_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "TranslateAcceleratorW" => Some(
            api::translate_accelerator_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "GetFocus" => Some(api::get_focus as *const () as usize),
        "LoadBitmapW" => {
            Some(api::load_bitmap_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetClassInfoW" => Some(
            api::get_class_info_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CallWindowProcW" => Some(
            api::call_window_proc_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "DialogBoxParamW" => Some(
            api::dialog_box_param_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "DialogBoxIndirectParamW" => Some(
            api::dialog_box_indirect_param_w as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        // Accessibility / event hooks
        "NotifyWinEvent" => Some(api::notify_win_event as *const () as usize),
        "FlashWindowEx" => {
            Some(api::flash_window_ex as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "LockWindowUpdate" => Some(api::lock_window_update as *const () as usize),
        "GetMenuBarInfo" => Some(
            api::get_menu_bar_info as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetIconInfo" => {
            Some(api::get_icon_info as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CreateIconIndirect" => Some(
            api::create_icon_indirect as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "IsChild" => Some(api::is_child as *const () as usize),
        // ── Window hierarchy / rect utilities / char ops ──────────────────
        "GetWindow" => Some(api::get_window as *const () as usize),
        "IsRectEmpty" => {
            Some(api::is_rect_empty as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CopyRect" => {
            Some(api::copy_rect as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "InflateRect" => {
            Some(api::inflate_rect as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CharNextW" => {
            Some(api::char_next_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CharLowerBuffW" => Some(
            api::char_lower_buff_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        _ => None,
    }
}
