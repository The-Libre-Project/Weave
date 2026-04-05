//! comctl32.dll stubs for Weave — Common Controls library.
//!
//! Provides load-time import resolution for applications that link against
//! comctl32.dll. Functions are stubs that return plausible values without
//! implementing real window classes or message loops.
//!
//! For Phase 6: PuTTY and 7-Zip need these imports resolved at load time.
//! Real common control behaviour (SysTreeView32, SysListView32 window procs)
//! is deferred to a later phase.

#![allow(non_snake_case)]

// ── Initialisation ────────────────────────────────────────────────────────────

/// InitCommonControls — register common control window classes.
///
/// On Windows this registers classes like SysListView32, SysTreeView32, etc.
/// As a stub we do nothing — class creation will fail gracefully when the app
/// tries to CreateWindow a control class.
pub extern "win64" fn init_common_controls() {}

/// InitCommonControlsEx — register a specific set of common control classes.
///
/// # Safety
/// `p_icc` may be null (some callers pass null). Ignored.
pub unsafe extern "win64" fn init_common_controls_ex(_p_icc: *const u8) -> i32 {
    1 // TRUE — pretend all requested classes were registered
}

// ── ImageList ─────────────────────────────────────────────────────────────────

/// ImageList_Create — create a new image list.
///
/// Returns a fake non-zero handle. Apps check for NULL to detect failure.
///
/// # Safety
/// No pointer arguments.
pub unsafe extern "win64" fn image_list_create(
    _cx: i32,
    _cy: i32,
    _flags: u32,
    _c_initial: i32,
    _c_grow: i32,
) -> usize {
    1 // fake HIMAGELIST handle
}

/// ImageList_Destroy — destroy an image list.
///
/// # Safety
/// `himl` is a fake handle from `image_list_create`. No real memory to free.
pub unsafe extern "win64" fn image_list_destroy(_himl: usize) -> i32 {
    1 // TRUE
}

/// ImageList_Add — add a bitmap to an image list. Returns image index.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_add(
    _himl: usize,
    _hbm_image: usize,
    _hbm_mask: usize,
) -> i32 {
    0 // index 0
}

/// ImageList_AddIcon — add an icon to an image list. Returns image index.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_add_icon(_himl: usize, _hicon: usize) -> i32 {
    0 // index 0
}

/// ImageList_AddMasked — add a bitmap using a mask colour. Returns image index.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_add_masked(
    _himl: usize,
    _hbm_image: usize,
    _cr_mask: u32,
) -> i32 {
    0
}

/// ImageList_ReplaceIcon — replace or add an icon in an image list.
///
/// Returns the image index (0).
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_replace_icon(_himl: usize, _i: i32, _hicon: usize) -> i32 {
    0
}

/// ImageList_GetImageCount — return the number of images in a list.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_get_image_count(_himl: usize) -> i32 {
    0
}

/// ImageList_SetImageCount — resize an image list.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_set_image_count(_himl: usize, _u_new_count: u32) -> i32 {
    1 // TRUE
}

/// ImageList_Draw — draw an image from a list onto a DC.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_draw(
    _himl: usize,
    _i: i32,
    _hdc_dst: usize,
    _x: i32,
    _y: i32,
    _f_style: u32,
) -> i32 {
    0 // FALSE — nothing drawn
}

/// ImageList_DrawEx — draw an image with extended options.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_draw_ex(
    _himl: usize,
    _i: i32,
    _hdc_dst: usize,
    _x: i32,
    _y: i32,
    _dx: i32,
    _dy: i32,
    _rgb_bk: u32,
    _rgb_fg: u32,
    _f_style: u32,
) -> i32 {
    0
}

/// ImageList_LoadImageW — load an image list from a resource (Wide).
///
/// Returns a fake non-zero handle.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_load_image_w(
    _hi: usize,
    _lp_bmp: *const u16,
    _cx: i32,
    _c_grow: i32,
    _cr_mask: u32,
    _u_type: u32,
    _u_flags: u32,
) -> usize {
    1 // fake HIMAGELIST
}

/// ImageList_LoadImageA — load an image list from a resource (ANSI).
///
/// Returns a fake non-zero handle.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn image_list_load_image_a(
    _hi: usize,
    _lp_bmp: *const u8,
    _cx: i32,
    _c_grow: i32,
    _cr_mask: u32,
    _u_type: u32,
    _u_flags: u32,
) -> usize {
    1 // fake HIMAGELIST
}

// ── Status bar ────────────────────────────────────────────────────────────────

/// CreateStatusWindowW — create a status bar window (Wide).
///
/// Returns NULL HWND. Apps degrade gracefully when no status bar is present.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn create_status_window_w(
    _style: i32,
    _lp_sz_text: *const u16,
    _hwnd_parent: usize,
    _wid: u32,
) -> usize {
    0 // NULL HWND
}

/// CreateStatusWindowA — create a status bar window (ANSI).
///
/// Returns NULL HWND.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn create_status_window_a(
    _style: i32,
    _lp_sz_text: *const u8,
    _hwnd_parent: usize,
    _wid: u32,
) -> usize {
    0 // NULL HWND
}

/// DrawStatusTextW — draw status bar text into a DC (Wide). No-op.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn draw_status_text_w(
    _hdc: usize,
    _lp_rc: *mut u8,
    _sz_text: *const u16,
    _u_flags: u32,
) {
}

/// DrawStatusTextA — draw status bar text into a DC (ANSI). No-op.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn draw_status_text_a(
    _hdc: usize,
    _lp_rc: *mut u8,
    _sz_text: *const u8,
    _u_flags: u32,
) {
}

// ── Toolbar ───────────────────────────────────────────────────────────────────

/// CreateToolbarEx — create a toolbar window.
///
/// Returns NULL HWND. Apps degrade gracefully.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn create_toolbar_ex(
    _hwnd: usize,
    _ws: u32,
    _wid: u32,
    _n_bitmaps: i32,
    _h_bm_inst: usize,
    _w_bm_id: usize,
    _lp_buttons: *const u8,
    _i_num_buttons: i32,
    _dx_button: i32,
    _dy_button: i32,
    _dx_bitmap: i32,
    _dy_bitmap: i32,
    _u_struct_size: u32,
) -> usize {
    0 // NULL HWND
}

/// CreateMappedBitmap — create a bitmap, mapping colours from a table.
///
/// Returns NULL HBITMAP.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn create_mapped_bitmap(
    _h_instance: usize,
    _id_bitmap: isize,
    _w_flags: u32,
    _lp_color_map: *const u8,
    _i_num_maps: i32,
) -> usize {
    0 // NULL HBITMAP
}

// ── Mouse tracking ────────────────────────────────────────────────────────────

/// _TrackMouseEvent — request WM_MOUSELEAVE / WM_MOUSEHOVER messages.
///
/// Returns TRUE (success). Since we don't have a real message loop,
/// the events won't actually fire, but callers treat this as optional.
///
/// # Safety
/// `lp_event_track` is ignored.
pub unsafe extern "win64" fn track_mouse_event(_lp_event_track: *mut u8) -> i32 {
    1 // TRUE
}

// ── Property sheets ───────────────────────────────────────────────────────────

/// PropertySheetW — display a property sheet dialog (Wide).
///
/// Returns -1 (error). Apps should handle gracefully.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn property_sheet_w(_lp_psh: *const u8) -> isize {
    -1
}

/// PropertySheetA — display a property sheet dialog (ANSI).
///
/// Returns -1 (error).
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn property_sheet_a(_lp_psh: *const u8) -> isize {
    -1
}

// ── Flat scrollbars ───────────────────────────────────────────────────────────

/// InitializeFlatSB — initialise flat scroll bars for a window.
///
/// Returns TRUE.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn initialize_flat_sb(_hwnd: usize) -> i32 {
    1 // TRUE
}

/// UninitializeFlatSB — remove flat scroll bars from a window.
///
/// # Safety
/// Arguments are ignored.
pub unsafe extern "win64" fn uninitialize_flat_sb(_hwnd: usize) -> i32 {
    1 // S_OK (0 is also acceptable; apps rarely check this)
}

/// ImageList_GetIcon — create an icon from an image list entry.
///
/// Returns NULL HICON — stub.
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_get_icon(_himl: usize, _i: i32, _flags: u32) -> usize {
    0 // NULL HICON
}

// ── DLL Resolver ─────────────────────────────────────────────────────────────

/// Resolve a comctl32.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("comctl32.dll") {
        return None;
    }

    match func {
        "InitCommonControls" => Some(init_common_controls as *const () as usize),
        "InitCommonControlsEx" => Some(init_common_controls_ex as *const () as usize),
        "ImageList_Create" => Some(image_list_create as *const () as usize),
        "ImageList_Destroy" => Some(image_list_destroy as *const () as usize),
        "ImageList_Add" => Some(image_list_add as *const () as usize),
        "ImageList_AddIcon" => Some(image_list_add_icon as *const () as usize),
        "ImageList_AddMasked" => Some(image_list_add_masked as *const () as usize),
        "ImageList_ReplaceIcon" => Some(image_list_replace_icon as *const () as usize),
        "ImageList_GetImageCount" => Some(image_list_get_image_count as *const () as usize),
        "ImageList_SetImageCount" => Some(image_list_set_image_count as *const () as usize),
        "ImageList_Draw" => Some(image_list_draw as *const () as usize),
        "ImageList_DrawEx" => Some(image_list_draw_ex as *const () as usize),
        "ImageList_LoadImageW" => Some(image_list_load_image_w as *const () as usize),
        "ImageList_LoadImageA" => Some(image_list_load_image_a as *const () as usize),
        "CreateStatusWindowW" => Some(create_status_window_w as *const () as usize),
        "CreateStatusWindowA" => Some(create_status_window_a as *const () as usize),
        "DrawStatusTextW" => Some(draw_status_text_w as *const () as usize),
        "DrawStatusTextA" => Some(draw_status_text_a as *const () as usize),
        "CreateToolbarEx" => Some(create_toolbar_ex as *const () as usize),
        "CreateMappedBitmap" => Some(create_mapped_bitmap as *const () as usize),
        "_TrackMouseEvent" => Some(track_mouse_event as *const () as usize),
        "PropertySheetW" => Some(property_sheet_w as *const () as usize),
        "PropertySheetA" => Some(property_sheet_a as *const () as usize),
        "InitializeFlatSB" => Some(initialize_flat_sb as *const () as usize),
        "UninitializeFlatSB" => Some(uninitialize_flat_sb as *const () as usize),
        "ImageList_GetIcon" | "#17" => Some(
            image_list_get_icon as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "InitCommonControls").is_none());
    }

    #[test]
    fn resolve_unknown_function() {
        assert!(resolve("comctl32.dll", "__nonexistent__").is_none());
    }

    #[test]
    fn resolve_all_exports() {
        let funcs = [
            "InitCommonControls",
            "InitCommonControlsEx",
            "ImageList_Create",
            "ImageList_Destroy",
            "ImageList_Add",
            "ImageList_AddIcon",
            "ImageList_AddMasked",
            "ImageList_ReplaceIcon",
            "ImageList_GetImageCount",
            "ImageList_SetImageCount",
            "ImageList_Draw",
            "ImageList_DrawEx",
            "ImageList_LoadImageW",
            "ImageList_LoadImageA",
            "CreateStatusWindowW",
            "CreateStatusWindowA",
            "DrawStatusTextW",
            "DrawStatusTextA",
            "CreateToolbarEx",
            "CreateMappedBitmap",
            "_TrackMouseEvent",
            "PropertySheetW",
            "PropertySheetA",
            "InitializeFlatSB",
            "UninitializeFlatSB",
            "ImageList_GetIcon",
        ];
        for f in &funcs {
            assert!(resolve("comctl32.dll", f).is_some(), "missing: {f}");
        }
    }

    #[test]
    fn resolve_case_insensitive_dll_name() {
        assert!(resolve("ComCtl32.DLL", "InitCommonControls").is_some());
        assert!(resolve("COMCTL32.DLL", "ImageList_Create").is_some());
    }
}
