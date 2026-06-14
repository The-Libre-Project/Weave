//! comctl32.dll stubs for Weave — Common Controls library.
//!
//! Provides load-time import resolution for applications that link against
//! comctl32.dll. Functions are stubs that return plausible values without
//! implementing real window classes or message loops.
//!
//! For Phase 6: PuTTY and 7-Zip need these imports resolved at load time.
//! Real common control behaviour (SysTreeView32, SysListView32 window procs)
//! is deferred to a later phase.
//!
//! # Crate boundary note
//!
//! `weave-comctl32` directly imports `weave-user32`. This violates the general
//! architecture rule that DLL crates should not import each other (shared types
//! belong in `weave-common`). The exception is intentional and mirrors real
//! Windows: comctl32 common-control classes (ImageList, TreeView, ListView,
//! StatusBar) are real Win32 window classes whose creation flows through
//! `CreateWindowExW`. Because window class registration and HWND lifetime are
//! owned by user32, comctl32 must call directly into user32's API surface to
//! create those windows — it cannot go through weave-common, which has no
//! Win32 window-management types.
//!
//! Extraction was considered: moving `CreateWindowExW` to `weave-common` would
//! hollow user32 (all window state lives there) or create a circular dependency
//! (common needing user32 internals). The coupling is accepted as-is. Do not
//! add further DLL→DLL imports without a similar written justification.

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
/// Wine ref: comctl32/status.c — CreateStatusWindowW is a thin wrapper around
/// CreateWindowExW(0, STATUSCLASSNAME, lpszText, style, ...) where STATUSCLASSNAME
/// is "msctls_statusbar32". SciTE checks `if (!statusBar_) return false` after
/// this call, so returning NULL causes an immediate clean exit before GetMessageW.
///
/// # Safety
/// lp_sz_text, if non-null, must be a valid null-terminated UTF-16 string.
/// hwnd_parent must be a valid HWND or 0.
pub unsafe extern "win64" fn create_status_window_w(
    style: i32,
    lp_sz_text: *const u16,
    hwnd_parent: usize,
    wid: u32,
) -> usize {
    // "msctls_statusbar32\0" as a wide string literal for the class name.
    let class_name: Vec<u16> = "msctls_statusbar32\0".encode_utf16().collect();
    let empty_title = [0u16; 1];
    let title_ptr = if lp_sz_text.is_null() {
        empty_title.as_ptr()
    } else {
        lp_sz_text
    };
    // WS_CHILD (0x4000_0000) must be set so user32 treats it as a child window.
    let adjusted_style = (style as u32) | 0x4000_0000u32;
    weave_user32::api::create_window_ex_w(
        0,                    // dwExStyle
        class_name.as_ptr(),  // "msctls_statusbar32"
        title_ptr,            // lpWindowName
        adjusted_style,       // dwStyle | WS_CHILD
        0,                    // x
        0,                    // y
        0,                    // nWidth (sized by parent on WM_SIZE)
        20,                   // nHeight (typical status bar height)
        hwnd_parent,          // hWndParent
        wid as usize,         // hMenu (child window ID)
        0,                    // hInstance
        std::ptr::null_mut(), // lpParam
    )
}

/// CreateStatusWindowA — create a status bar window (ANSI).
///
/// Forwards to the wide variant; the initial text is not significant for
/// Gate 5 (SciTE sets parts/text via SB_* messages after creation).
///
/// # Safety
/// hwnd_parent must be a valid HWND or 0.
pub unsafe extern "win64" fn create_status_window_a(
    style: i32,
    _lp_sz_text: *const u8,
    hwnd_parent: usize,
    wid: u32,
) -> usize {
    create_status_window_w(style, std::ptr::null(), hwnd_parent, wid)
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

// Wine ref: dlls/comctl32/propsheet.c — CreatePropertySheetPageW allocates a copy of the
// PROPSHEETPAGEW struct via Alloc(); returns an opaque HPROPSHEETPAGE handle (pointer to
// the allocated struct), or NULL on allocation failure. The returned handle is passed to
// PropertySheetW or AddPropertySheetPage. Since Weave has no property-sheet dialog loop,
// returning NULL is the safe failure sentinel — callers that check for NULL skip the page.
/// CreatePropertySheetPageW — create a property sheet page handle (Wide).
///
/// Returns NULL (stub — no property sheet dialog subsystem in Weave).
/// Callers must check for NULL before passing the handle to PropertySheetW.
///
/// # Safety
/// `lp_psp` is ignored.
// TODO(shim): Phase A — no dialog subsystem; always returns NULL.
pub unsafe extern "win64" fn create_property_sheet_page_w(_lp_psp: *const u8) -> usize {
    0 // NULL HPROPSHEETPAGE
}

/// CreatePropertySheetPageA — create a property sheet page handle (ANSI).
///
/// Returns NULL — stub, mirrors CreatePropertySheetPageW.
///
/// # Safety
/// `lp_psp` is ignored.
// TODO(shim): Phase A — no dialog subsystem; always returns NULL.
pub unsafe extern "win64" fn create_property_sheet_page_a(_lp_psp: *const u8) -> usize {
    0 // NULL HPROPSHEETPAGE
}

/// DestroyPropertySheetPage — destroy a property sheet page handle.
///
/// Returns TRUE — stub; nothing to free since CreatePropertySheetPage* always returns NULL.
///
/// # Safety
/// `hpsp` is ignored.
// TODO(shim): Phase A — no handle table; returns TRUE (no-op destroy).
pub unsafe extern "win64" fn destroy_property_sheet_page(_hpsp: usize) -> i32 {
    1 // TRUE
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

/// ImageList_BeginDrag — begin dragging an image. Returns TRUE (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_begin_drag(
    _himl_track: usize,
    _i_track: i32,
    _dx_hotspot: i32,
    _dy_hotspot: i32,
) -> i32 {
    1 // TRUE
}

/// ImageList_EndDrag — end a drag operation (stub, no-op).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_end_drag() {}

/// ImageList_DragEnter — lock window updates and display drag image (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_drag_enter(_hwnd_lock: usize, _x: i32, _y: i32) -> i32 {
    1 // TRUE
}

/// ImageList_DragLeave — unlocks window updates (stub, no-op).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_drag_leave(_hwnd_lock: usize) -> i32 {
    1 // TRUE
}

/// ImageList_DragMove — moves the image being dragged (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_drag_move(_x: i32, _y: i32) -> i32 {
    1 // TRUE
}

/// ImageList_DragShowNolock — shows or hides drag image without locking window (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_drag_show_nolock(_f_show: i32) -> i32 {
    1 // TRUE
}

/// ImageList_Remove — removes an image from an image list. Returns TRUE (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_remove(_himl: usize, _i: i32) -> i32 {
    1 // TRUE
}

/// ImageList_SetIconSize — sets the icon dimensions for an image list. Returns TRUE (stub).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn image_list_set_icon_size(_himl: usize, _cx: i32, _cy: i32) -> i32 {
    1 // TRUE
}

/// ImageList_GetIconSize — gets the icon dimensions for an image list (stub).
///
/// Returns FALSE — no real image list backing. Apps should tolerate this.
///
/// # Safety
/// `pcx`/`pcy` are ignored; we do not write through them.
pub unsafe extern "win64" fn image_list_get_icon_size(
    _himl: usize,
    _pcx: *mut i32,
    _pcy: *mut i32,
) -> i32 {
    0 // FALSE — stub
}

// ── TaskDialog ─────────────────────────────────────────────────────────────────

/// TaskDialogIndirect: create and show a task dialog (stub).
///
/// Stubbed to S_OK so callers proceed as if the dialog was dismissed.
/// The #345 ordinal is how SumatraPDF imports TaskDialogIndirect.
///
/// # Safety
/// All pointer arguments are ignored.
// Wine ref: dlls/comctl32/taskdialog.c — TaskDialogIndirect creates a modal
// task dialog with custom buttons, icon, and content.
pub unsafe extern "win64" fn task_dialog_indirect(
    _p_task_config: *const u8,
    _pn_button: *mut i32,
    _pn_radio: *mut i32,
    _pf_verification: *mut i32,
) -> i32 {
    0 // S_OK
}

/// TaskDialog: simplified task dialog with a fixed button set (stub).
///
/// # Safety
/// All pointer arguments are ignored.
// Wine ref: dlls/comctl32/taskdialog.c — wraps TaskDialogIndirect.
pub unsafe extern "win64" fn task_dialog(
    _hwnd_parent: usize,
    _h_instance: usize,
    _window_title: *const u16,
    _main_instruction: *const u16,
    _buttons: u32,
    _icon: *const u16,
    _pn_button: *mut i32,
) -> i32 {
    0 // S_OK
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
        "ImageList_BeginDrag" => Some(image_list_begin_drag as *const () as usize),
        "ImageList_EndDrag" => Some(image_list_end_drag as *const () as usize),
        "ImageList_DragEnter" => Some(image_list_drag_enter as *const () as usize),
        "ImageList_DragLeave" => Some(image_list_drag_leave as *const () as usize),
        "ImageList_DragMove" => Some(image_list_drag_move as *const () as usize),
        "ImageList_DragShowNolock" => Some(image_list_drag_show_nolock as *const () as usize),
        "ImageList_Remove" => Some(image_list_remove as *const () as usize),
        "ImageList_SetIconSize" => Some(image_list_set_icon_size as *const () as usize),
        "ImageList_GetIconSize" => Some(image_list_get_icon_size as *const () as usize),
        // Ordinals seen in Notepad++ imports — map to their named equivalents.
        // #381 = ImageList_BeginDrag, #410/#411/#412/#413 = drag show/move/enter/leave variants.
        "#381" => Some(image_list_begin_drag as *const () as usize),
        "#410" => Some(image_list_drag_enter as *const () as usize),
        "#411" => Some(image_list_drag_leave as *const () as usize),
        "#412" => Some(image_list_drag_move as *const () as usize),
        "#413" => Some(image_list_drag_show_nolock as *const () as usize),
        // Property sheet page creation — SumatraPDF and printer dialogs use these.
        "CreatePropertySheetPageW" => Some(create_property_sheet_page_w as *const () as usize),
        "CreatePropertySheetPageA" => Some(create_property_sheet_page_a as *const () as usize),
        "DestroyPropertySheetPage" => Some(destroy_property_sheet_page as *const () as usize),
        "#345" => Some(task_dialog_indirect as *const () as usize),
        "TaskDialogIndirect" => Some(task_dialog_indirect as *const () as usize),
        "TaskDialog" => Some(task_dialog as *const () as usize),
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
            "ImageList_BeginDrag",
            "ImageList_EndDrag",
            "ImageList_DragEnter",
            "ImageList_DragLeave",
            "ImageList_DragMove",
            "ImageList_DragShowNolock",
            "ImageList_Remove",
            "ImageList_SetIconSize",
            "ImageList_GetIconSize",
            "#381",
            "#410",
            "#411",
            "#412",
            "#413",
            "CreatePropertySheetPageW",
            "CreatePropertySheetPageA",
            "DestroyPropertySheetPage",
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

// ── uxtheme.dll stubs ─────────────────────────────────────────────────────────
//
// Wine ref: dlls/uxtheme/uxtheme.c — theme API functions.
// All stubs return safe sentinel values (NULL handle, S_OK, FALSE).

const S_OK: i32 = 0;

/// Resolve a uxtheme.dll import to a stub address.
pub fn resolve_uxtheme(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("uxtheme.dll") {
        return None;
    }
    match func {
        "OpenThemeData" => Some(open_theme_data as *const () as usize),
        "CloseThemeData" => Some(close_theme_data as *const () as usize),
        "DrawThemeBackground" => Some(draw_theme_background as *const () as usize),
        "DrawThemeText" => Some(draw_theme_text as *const () as usize),
        "SetWindowTheme" => Some(set_window_theme as *const () as usize),
        "IsThemeActive" => Some(is_theme_active as *const () as usize),
        "IsAppThemed" => Some(is_app_themed as *const () as usize),
        "GetWindowTheme" => Some(get_window_theme as *const () as usize),
        "EnableThemeDialogTexture" => Some(enable_theme_dialog_texture as *const () as usize),
        "EnableTheming" => Some(enable_theming as *const () as usize),
        _ => None,
    }
}

// Wine ref: dlls/uxtheme/theme.c — OpenThemeData returns HTHEME handle or NULL.
extern "win64" fn open_theme_data(_hwnd: usize, _class: *const u16) -> usize {
    0 // NULL — no theme available
}

// Wine ref: dlls/uxtheme/theme.c — CloseThemeData frees theme handle resources.
extern "win64" fn close_theme_data(_h_theme: usize) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — DrawThemeBackground draws themed background.
extern "win64" fn draw_theme_background(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _rect: *const u8,
    _clip: *const u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — DrawThemeText draws themed text.
extern "win64" fn draw_theme_text(
    _h_theme: usize,
    _hdc: usize,
    _part: i32,
    _state: i32,
    _str: *const u16,
    _len: i32,
    _flags: u32,
    _flags2: u32,
    _rect: *const u8,
) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — SetWindowTheme sets/clears theme per window.
extern "win64" fn set_window_theme(_hwnd: usize, _app: *const u16, _sub: *const u16) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — IsThemeActive returns TRUE if themes active.
extern "win64" fn is_theme_active() -> i32 {
    0 // FALSE — no themes active
}

// Wine ref: dlls/uxtheme/theme.c — IsAppThemed returns TRUE if app is themed.
extern "win64" fn is_app_themed() -> i32 {
    0 // FALSE — not themed
}

// Wine ref: dlls/uxtheme/theme.c — GetWindowTheme returns theme handle for window.
extern "win64" fn get_window_theme(_hwnd: usize) -> usize {
    0 // NULL — no theme assigned
}

// Wine ref: dlls/uxtheme/theme.c — EnableThemeDialogTexture enables background texture.
extern "win64" fn enable_theme_dialog_texture(_hwnd: usize, _flags: u32) -> i32 {
    S_OK
}

// Wine ref: dlls/uxtheme/theme.c — EnableTheming enables/disables visual styles.
extern "win64" fn enable_theming(_enable: i32) -> i32 {
    S_OK
}
