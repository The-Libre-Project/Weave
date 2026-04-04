//! Win32 user32 API function implementations.
//!
//! All functions use `extern "win64"` (Windows x86-64 calling convention).
//! Functions that need X11 delegate to `backend::*`; when X11 is unavailable
//! (no display, or non-Linux) they return safe error values.

#![allow(non_snake_case)]

use crate::backend;
use crate::class::{self, ClassEntry};
use crate::defs::*;
use crate::queue::{self, MsgEntry};
use crate::window::{self, WindowEntry};
use libc;

// ── RegisterClassW / RegisterClassExW ─────────────────────────────────────────

/// RegisterClassW: register a window class.
///
/// Returns a non-zero ATOM identifying the class, or 0 on failure.
///
/// # Safety
/// `lp_wnd_class` must point to a valid `WNDCLASSW` struct.
pub unsafe extern "win64" fn register_class_w(lp_wnd_class: *const WndClassW) -> u16 {
    if lp_wnd_class.is_null() {
        return 0;
    }
    let wc = unsafe { &*lp_wnd_class };
    let name = unsafe { decode_wide(wc.lpsz_class_name) };
    if name.is_empty() {
        return 0;
    }
    class::register(
        &name,
        ClassEntry {
            wnd_proc: wc.lpfn_wnd_proc,
            style: wc.style,
            h_cursor: wc.h_cursor,
            hbr_background: wc.hbr_background,
        },
    );
    // Return a non-zero ATOM — use a hash of the name for uniqueness.
    name_to_atom(&name)
}

/// RegisterClassExW: extended version with cbSize + hIconSm fields.
///
/// # Safety
/// `lp_wnd_class_ex` must point to a valid `WNDCLASSEXW` struct.
pub unsafe extern "win64" fn register_class_ex_w(lp_wnd_class_ex: *const WndClassExW) -> u16 {
    if lp_wnd_class_ex.is_null() {
        return 0;
    }
    let wc = unsafe { &*lp_wnd_class_ex };
    let name = unsafe { decode_wide(wc.lpsz_class_name) };
    if name.is_empty() {
        return 0;
    }
    class::register(
        &name,
        ClassEntry {
            wnd_proc: wc.lpfn_wnd_proc,
            style: wc.style,
            h_cursor: wc.h_cursor,
            hbr_background: wc.hbr_background,
        },
    );
    name_to_atom(&name)
}

/// Convert a class name to a stable 16-bit ATOM. Uses a simple djb2 hash.
fn name_to_atom(name: &str) -> u16 {
    let mut hash: u32 = 5381;
    for b in name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    let atom = (hash & 0xFFFF) as u16;
    if atom == 0 {
        1
    } else {
        atom
    }
}

// ── CreateWindowExW ───────────────────────────────────────────────────────────

/// CreateWindowExW: create a new window.
///
/// # Safety
/// `lp_class_name` and `lp_window_name` (if non-null) must be valid
/// null-terminated UTF-16 strings.
pub unsafe extern "win64" fn create_window_ex_w(
    dw_ex_style: u32,
    lp_class_name: *const u16,
    lp_window_name: *const u16,
    dw_style: u32,
    x: i32,
    y: i32,
    n_width: i32,
    n_height: i32,
    h_wnd_parent: usize,
    h_menu_param: usize,
    h_instance: usize,
    lp_param: *mut u8,
) -> usize {
    let class_name = unsafe { decode_wide(lp_class_name) };
    let title = unsafe { decode_wide(lp_window_name) };

    // Look up the class.
    let cls = match class::find(&class_name) {
        Some(c) => c,
        None => {
            eprintln!("weave/user32: CreateWindowExW: unknown class '{class_name}'");
            return 0;
        }
    };

    // Default size if CW_USEDEFAULT (0x80000000 as i32).
    let width = if n_width == i32::MIN {
        640
    } else {
        n_width.max(1)
    } as u32;
    let height = if n_height == i32::MIN {
        480
    } else {
        n_height.max(1)
    } as u32;
    let pos_x = if x == i32::MIN { 100 } else { x };
    let pos_y = if y == i32::MIN { 100 } else { y };

    let visible = (dw_style & WS_VISIBLE) != 0;

    // Create the X11 window (no-op on non-Linux).
    let xcb_id = backend::create_window(&title, pos_x, pos_y, width, height, visible);

    let hwnd = window::create(WindowEntry {
        class_name: class_name.clone(),
        wnd_proc: cls.wnd_proc,
        title: title.clone(),
        style: dw_style,
        x: pos_x,
        y: pos_y,
        width,
        height,
        visible,
        xcb_id,
        h_menu: h_menu_param,
    });

    // Build CREATESTRUCTW on the stack and call WNDPROC with WM_NCCREATE then WM_CREATE.
    // Title and class name as wide strings for the struct — we need them alive during the call.
    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let class_wide: Vec<u16> = class_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let cs = CreateStructW {
        lp_create_params: lp_param,
        h_instance,
        h_menu: h_menu_param,
        hwnd_parent: h_wnd_parent,
        cy: height as i32,
        cx: width as i32,
        y: pos_y,
        x: pos_x,
        style: dw_style as i32,
        _pad: 0,
        lp_sz_name: title_wide.as_ptr(),
        lp_sz_class: class_wide.as_ptr(),
        dw_ex_style,
        _pad2: 0,
    };

    call_wnd_proc(cls.wnd_proc, hwnd, WM_NCCREATE, 0, &cs as *const _ as isize);
    call_wnd_proc(cls.wnd_proc, hwnd, WM_CREATE, 0, &cs as *const _ as isize);

    hwnd
}

// ── ShowWindow ────────────────────────────────────────────────────────────────

/// ShowWindow: show, hide, or change the state of a window.
///
/// Returns the previous visibility state as a BOOL.
pub extern "win64" fn show_window(hwnd: usize, n_cmd_show: i32) -> i32 {
    let was_visible = window::with(hwnd, |e| e.visible).unwrap_or(false);

    let show = !matches!(n_cmd_show, SW_HIDE);

    let xcb = window::xcb_id(hwnd);
    window::with_mut(hwnd, |e| e.visible = show);
    backend::show_window(xcb, show);

    was_visible as i32
}

/// UpdateWindow: send WM_PAINT directly if the update region is non-empty.
/// Phase 2: always posts WM_PAINT to the message queue.
pub extern "win64" fn update_window(hwnd: usize) -> i32 {
    if window::with(hwnd, |_| ()).is_some() {
        queue::post(MsgEntry {
            hwnd,
            message: WM_PAINT,
            w_param: 0,
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
        });
        1 // TRUE
    } else {
        0 // FALSE — invalid HWND
    }
}

// ── DestroyWindow ─────────────────────────────────────────────────────────────

/// DestroyWindow: destroy a window and post WM_DESTROY.
pub extern "win64" fn destroy_window(hwnd: usize) -> i32 {
    let xcb = window::xcb_id(hwnd);

    // Call WM_DESTROY via the window's WNDPROC before removing it.
    if let Some(proc_addr) = window::with(hwnd, |e| e.wnd_proc) {
        call_wnd_proc(proc_addr, hwnd, WM_NCDESTROY, 0, 0);
        call_wnd_proc(proc_addr, hwnd, WM_DESTROY, 0, 0);
    }

    backend::destroy_window(xcb);
    window::remove(hwnd);
    1 // TRUE
}

// ── Message loop ──────────────────────────────────────────────────────────────

/// GetMessageW: retrieve a message from the queue, blocking until one arrives.
///
/// Returns:
/// - `> 0` — a message was retrieved (not WM_QUIT)
/// - `0`   — WM_QUIT was retrieved
/// - `-1`  — error (invalid hwnd filter, or connection lost)
///
/// # Safety
/// `lp_msg` must be a valid writable pointer to a `MSG`-sized buffer (48 bytes).
pub unsafe extern "win64" fn get_message_w(
    lp_msg: *mut Msg,
    _h_wnd: usize,        // window filter — 0 = all windows (ignored in Phase 2)
    _msg_filter_min: u32, // message range filter (ignored)
    _msg_filter_max: u32,
) -> i32 {
    if lp_msg.is_null() {
        return -1;
    }

    // Wait for a message: keep pumping X11 events until the queue has one.
    loop {
        if let Some(entry) = queue::pop() {
            fill_msg(lp_msg, &entry);
            return if entry.message == WM_QUIT { 0 } else { 1 };
        }
        // Block on the X11 connection for the next event.
        if !backend::wait_event() {
            // Connection lost or no display — return WM_QUIT.
            let quit = MsgEntry {
                hwnd: 0,
                message: WM_QUIT,
                w_param: 0,
                l_param: 0,
                time: 0,
                pt_x: 0,
                pt_y: 0,
            };
            fill_msg(lp_msg, &quit);
            return 0;
        }
    }
}

/// PeekMessageW: check for messages without blocking.
///
/// # Safety
/// `lp_msg` must be a valid writable pointer to a `MSG`-sized buffer.
pub unsafe extern "win64" fn peek_message_w(
    lp_msg: *mut Msg,
    _h_wnd: usize,
    _msg_filter_min: u32,
    _msg_filter_max: u32,
    w_remove_msg: u32, // PM_NOREMOVE (0) or PM_REMOVE (1)
) -> i32 {
    if lp_msg.is_null() {
        return 0;
    }
    // Drain any pending X11 events first.
    while backend::poll_event() {}

    let entry = if w_remove_msg == 0 {
        queue::peek()
    } else {
        queue::pop()
    };

    match entry {
        Some(ref e) => {
            fill_msg(lp_msg, e);
            1 // TRUE — message available
        }
        None => 0, // FALSE — no message
    }
}

/// Map an X11 keycode to a Unicode code point (unshifted, standard PC layout).
///
/// X11 keycodes are hardware-specific but follow a well-known layout on
/// standard PC keyboards. This table covers the ASCII printable range.
/// Returns `None` for keycodes with no printable character (function keys,
/// modifiers, cursor keys, etc.).
fn keycode_to_char(keycode: usize, _shift: bool) -> Option<char> {
    // Standard PC keyboard keycode mapping (unshifted).
    // Keycodes 8–255; printable ASCII starts around 10.
    // Source: X11 keyboard specification for evdev/standard PC layout.
    let ch: u8 = match keycode {
        // Row 0 — number row
        10 => b'1',
        11 => b'2',
        12 => b'3',
        13 => b'4',
        14 => b'5',
        15 => b'6',
        16 => b'7',
        17 => b'8',
        18 => b'9',
        19 => b'0',
        20 => b'-',
        21 => b'=',
        // Row 1 — QWERTY
        24 => b'q',
        25 => b'w',
        26 => b'e',
        27 => b'r',
        28 => b't',
        29 => b'y',
        30 => b'u',
        31 => b'i',
        32 => b'o',
        33 => b'p',
        34 => b'[',
        35 => b']',
        // Row 2 — ASDF
        38 => b'a',
        39 => b's',
        40 => b'd',
        41 => b'f',
        42 => b'g',
        43 => b'h',
        44 => b'j',
        45 => b'k',
        46 => b'l',
        47 => b';',
        48 => b'\'',
        // Row 3 — ZXCV
        52 => b'z',
        53 => b'x',
        54 => b'c',
        55 => b'v',
        56 => b'b',
        57 => b'n',
        58 => b'm',
        59 => b',',
        60 => b'.',
        61 => b'/',
        // Special
        65 => b' ',  // Space
        36 => b'\r', // Return / Enter
        22 => 8,     // Backspace
        23 => b'\t', // Tab
        _ => return None,
    };
    Some(ch as char)
}

/// TranslateMessage: translate WM_KEYDOWN messages to WM_CHAR.
///
/// For each WM_KEYDOWN with a printable character, posts a corresponding
/// WM_CHAR to the message queue. Returns TRUE if the message was translated.
///
/// # Safety
/// `lp_msg` must point to a valid `MSG`.
pub unsafe extern "win64" fn translate_message(lp_msg: *const Msg) -> i32 {
    if lp_msg.is_null() {
        return 0;
    }
    let msg = unsafe { &*lp_msg };
    if msg.message != WM_KEYDOWN {
        return (msg.message == WM_KEYUP || msg.message == WM_CHAR) as i32;
    }
    // msg.w_param holds the X11 keycode (set by backend::translate_event).
    if let Some(ch) = keycode_to_char(msg.w_param, false) {
        queue::post(MsgEntry {
            hwnd: msg.hwnd,
            message: WM_CHAR,
            w_param: ch as usize,
            l_param: msg.l_param,
            time: msg.time,
            pt_x: 0,
            pt_y: 0,
        });
        return 1;
    }
    1 // WM_KEYDOWN always returns TRUE even if no WM_CHAR was generated
}

/// DispatchMessageW: call the window procedure for the message in `lp_msg`.
///
/// Returns the value returned by the window procedure.
///
/// # Safety
/// `lp_msg` must point to a valid `MSG`.
pub unsafe extern "win64" fn dispatch_message_w(lp_msg: *const Msg) -> isize {
    if lp_msg.is_null() {
        return 0;
    }
    let m = unsafe { &*lp_msg };

    // WM_QUIT is never dispatched to a WNDPROC.
    if m.message == WM_QUIT {
        return 0;
    }

    let proc_addr = match window::with(m.hwnd, |e| e.wnd_proc) {
        Some(p) => p,
        None => return 0,
    };

    call_wnd_proc(proc_addr, m.hwnd, m.message, m.w_param, m.l_param)
}

// ── PostQuitMessage ───────────────────────────────────────────────────────────

/// PostQuitMessage: post a WM_QUIT message to the calling thread's message queue.
///
/// `n_exit_code` becomes the wParam of the WM_QUIT message.
pub extern "win64" fn post_quit_message(n_exit_code: i32) {
    queue::post(MsgEntry {
        hwnd: 0,
        message: WM_QUIT,
        w_param: n_exit_code as usize,
        l_param: 0,
        time: 0,
        pt_x: 0,
        pt_y: 0,
    });
}

/// PostMessageW: post a message to a window's message queue without blocking.
///
/// Returns TRUE on success.
pub extern "win64" fn post_message_w(hwnd: usize, msg: u32, w_param: usize, l_param: isize) -> i32 {
    queue::post(MsgEntry {
        hwnd,
        message: msg,
        w_param,
        l_param,
        time: 0,
        pt_x: 0,
        pt_y: 0,
    });
    1
}

/// SendMessageW: send a message directly to the WNDPROC, bypassing the queue.
///
/// Blocks until the WNDPROC returns.
pub extern "win64" fn send_message_w(
    hwnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    let proc_addr = match window::with(hwnd, |e| e.wnd_proc) {
        Some(p) => p,
        None => return 0,
    };
    call_wnd_proc(proc_addr, hwnd, msg, w_param, l_param)
}

// ── DefWindowProcW ────────────────────────────────────────────────────────────

/// DefWindowProcW: default message handling for messages the application
/// does not process.
///
/// Key behaviours:
///   WM_CLOSE   → calls DestroyWindow
///   WM_DESTROY → calls PostQuitMessage(0)
///   WM_PAINT   → validates the window (returns 0 without drawing)
///   All others → return 0
pub extern "win64" fn def_window_proc_w(
    hwnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    match msg {
        WM_CLOSE => {
            destroy_window(hwnd);
            0
        }
        WM_DESTROY => {
            post_quit_message(0);
            0
        }
        WM_PAINT => {
            // Validate the update region without drawing.
            // In Phase 2, no GDI; apps that handle WM_PAINT call BeginPaint/EndPaint.
            0
        }
        WM_NCCREATE => 1,  // non-zero = proceed with window creation
        WM_NCHITTEST => 1, // HTCLIENT (1) — all hits are in client area
        _ => {
            let _ = (hwnd, w_param, l_param); // suppress unused warnings
            0
        }
    }
}

// ── Geometry ──────────────────────────────────────────────────────────────────

/// GetClientRect: return the client area of a window (x=0, y=0, w, h).
///
/// # Safety
/// `lp_rect` must be a valid writable pointer to a `RECT`.
pub unsafe extern "win64" fn get_client_rect(hwnd: usize, lp_rect: *mut Rect) -> i32 {
    if lp_rect.is_null() {
        return 0;
    }
    let (w, h) = window::with(hwnd, |e| (e.width, e.height)).unwrap_or((0, 0));
    unsafe {
        (*lp_rect).left = 0;
        (*lp_rect).top = 0;
        (*lp_rect).right = w as i32;
        (*lp_rect).bottom = h as i32;
    }
    1
}

/// GetWindowRect: return the window position and size in screen coordinates.
///
/// # Safety
/// `lp_rect` must be a valid writable pointer to a `RECT`.
pub unsafe extern "win64" fn get_window_rect(hwnd: usize, lp_rect: *mut Rect) -> i32 {
    if lp_rect.is_null() {
        return 0;
    }
    let (x, y, w, h) =
        window::with(hwnd, |e| (e.x, e.y, e.width, e.height)).unwrap_or((0, 0, 0, 0));
    unsafe {
        (*lp_rect).left = x;
        (*lp_rect).top = y;
        (*lp_rect).right = x + w as i32;
        (*lp_rect).bottom = y + h as i32;
    }
    1
}

/// InvalidateRect: mark a region of a window as needing repaint.
///
/// Phase 2: posts WM_PAINT to the message queue.
///
/// # Safety
/// `lp_rect` may be null (means invalidate entire client area).
pub unsafe extern "win64" fn invalidate_rect(
    hwnd: usize,
    _lp_rect: *const Rect,
    _b_erase: i32,
) -> i32 {
    if window::with(hwnd, |_| ()).is_some() {
        queue::post(MsgEntry {
            hwnd,
            message: WM_PAINT,
            w_param: 0,
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
        });
        1
    } else {
        0
    }
}

// ── Window title ──────────────────────────────────────────────────────────────

/// SetWindowTextW: update the title bar text of a window.
///
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn set_window_text_w(hwnd: usize, lp_string: *const u16) -> i32 {
    let title = unsafe { decode_wide(lp_string) };
    let xcb = window::xcb_id(hwnd);
    window::with_mut(hwnd, |e| e.title = title.clone());
    backend::set_title(xcb, &title);
    1
}

/// GetWindowTextW: retrieve the title bar text.
///
/// Returns the number of characters copied (excluding the null terminator).
///
/// # Safety
/// `lp_string` must be valid for `n_max_count` UTF-16 code units.
pub unsafe extern "win64" fn get_window_text_w(
    hwnd: usize,
    lp_string: *mut u16,
    n_max_count: i32,
) -> i32 {
    if lp_string.is_null() || n_max_count <= 0 {
        return 0;
    }
    let title = window::with(hwnd, |e| e.title.clone()).unwrap_or_default();
    let wide: Vec<u16> = title.encode_utf16().collect();
    let copy_len = wide.len().min((n_max_count - 1) as usize);
    for (i, &c) in wide[..copy_len].iter().enumerate() {
        unsafe { *lp_string.add(i) = c };
    }
    unsafe { *lp_string.add(copy_len) = 0 };
    copy_len as i32
}

// ── Paint ─────────────────────────────────────────────────────────────────────

/// BeginPaint: prepare a window for painting; fill the PAINTSTRUCT.
///
/// Phase 2: returns a fake HDC (the HWND value itself). Real GDI integration
/// comes in Step 4 (weave-gdi32).
///
/// # Safety
/// `lp_paint` must point to a valid `PAINTSTRUCT`.
pub unsafe extern "win64" fn begin_paint(hwnd: usize, lp_paint: *mut PaintStruct) -> usize {
    if !lp_paint.is_null() {
        unsafe {
            let ps = &mut *lp_paint;
            ps.hdc = hwnd; // fake HDC for now
            ps.f_erase = 1;
            ps._pad = 0;
            let (w, h) = window::with(hwnd, |e| (e.width, e.height)).unwrap_or((640, 480));
            ps.rc_paint = Rect {
                left: 0,
                top: 0,
                right: w as i32,
                bottom: h as i32,
            };
            ps.f_restore = 0;
            ps.f_inc_update = 0;
            ps.rgb_reserved = [0u8; 32];
        }
    }
    hwnd // fake HDC
}

/// EndPaint: mark the end of painting for a window.
///
/// Phase 2: validates the update region (clears the WM_PAINT pending flag).
/// Returns TRUE always.
///
/// # Safety
/// `lp_paint` must point to the `PAINTSTRUCT` filled by `BeginPaint`.
pub unsafe extern "win64" fn end_paint(_hwnd: usize, _lp_paint: *const PaintStruct) -> i32 {
    1 // TRUE
}

// ── System metrics ────────────────────────────────────────────────────────────

/// GetSystemMetrics: return various system dimension/capability values.
///
/// Returns reasonable values for a typical Linux desktop.
pub extern "win64" fn get_system_metrics(n_index: i32) -> i32 {
    let (sw, sh) = backend::screen_size();
    match n_index {
        SM_CXSCREEN => sw as i32,
        SM_CYSCREEN => sh as i32,
        SM_CXFULLSCREEN => sw as i32,
        SM_CYFULLSCREEN => sh as i32 - 40, // subtract taskbar
        SM_CXICON => 32,
        SM_CYICON => 32,
        SM_CXCURSOR => 32,
        SM_CYCURSOR => 32,
        SM_CYCAPTION => 23,
        SM_CXFRAME => 4,
        SM_CYFRAME => 4,
        _ => 0,
    }
}

// ── Cursor / Icon stubs ───────────────────────────────────────────────────────

/// LoadCursorW: load a cursor resource.
///
/// Returns a non-zero fake HCURSOR. Real cursor loading requires Phase 3.
///
/// # Safety
/// `lp_cursor_name` (if non-null) must be a valid UTF-16 string or an integer
/// resource identifier (IDC_* constant passed via MAKEINTRESOURCEW).
pub unsafe extern "win64" fn load_cursor_w(_h_instance: usize, _lp_cursor_name: usize) -> usize {
    1 // non-zero fake HCURSOR
}

/// LoadIconW: load an icon resource.
///
/// Returns a non-zero fake HICON.
///
/// # Safety
/// `lp_icon_name` (if non-null) must be a valid UTF-16 string or integer resource.
pub unsafe extern "win64" fn load_icon_w(_h_instance: usize, _lp_icon_name: usize) -> usize {
    1 // non-zero fake HICON
}

/// LoadImageW: load an image (icon, cursor, or bitmap) from a resource.
///
/// Phase 2 stub: returns a fake non-zero handle for all image types.
///
/// # Safety
/// `_name` may be a pointer or an integer resource ID; callers must ensure it
/// is valid for the given `_ty`. This stub ignores it entirely.
pub unsafe extern "win64" fn load_image_w(
    _h_inst: usize,
    _name: usize,
    _ty: u32,
    _cx: i32,
    _cy: i32,
    _fu_load: u32,
) -> usize {
    1
}

// ── MessageBoxW ───────────────────────────────────────────────────────────────

/// MessageBoxW: display a modal message box.
///
/// Phase 2: prints the message to stderr and returns IDOK (1). Real dialog
/// support requires weave-comdlg32 in Phase 5.
///
/// # Safety
/// `lp_text` and `lp_caption` (if non-null) must be valid UTF-16 strings.
pub unsafe extern "win64" fn message_box_w(
    _hwnd: usize,
    lp_text: *const u16,
    lp_caption: *const u16,
    _u_type: u32,
) -> i32 {
    let text = unsafe { decode_wide(lp_text) };
    let caption = unsafe { decode_wide(lp_caption) };
    eprintln!("weave/MessageBoxW: [{caption}] {text}");
    IDOK
}

// ── GetDC / ReleaseDC (user32-resident, not gdi32) ────────────────────────────

/// GetDC: return a device context for a window.
///
/// Phase 2: returns a fake HDC (the HWND value itself).
/// Real GDI integration comes in Step 4.
pub extern "win64" fn get_dc(hwnd: usize) -> usize {
    hwnd // fake HDC
}

/// ReleaseDC: release a device context.
///
/// Phase 2: no-op. Returns 1 (success).
pub extern "win64" fn release_dc(_hwnd: usize, _hdc: usize) -> i32 {
    1
}

// ── SetWindowPos / MoveWindow ─────────────────────────────────────────────────

/// MoveWindow: change the position and size of a window.
pub extern "win64" fn move_window(
    hwnd: usize,
    x: i32,
    y: i32,
    n_width: i32,
    n_height: i32,
    b_repaint: i32,
) -> i32 {
    window::with_mut(hwnd, |e| {
        e.x = x;
        e.y = y;
        e.width = n_width.max(0) as u32;
        e.height = n_height.max(0) as u32;
    });
    if b_repaint != 0 {
        queue::post(MsgEntry {
            hwnd,
            message: WM_PAINT,
            w_param: 0,
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
        });
    }
    1
}

// ── GetForegroundWindow / SetForegroundWindow ─────────────────────────────────

/// GetForegroundWindow: return the foreground window's HWND.
///
/// Phase 2: returns the first registered HWND, or 0 if none.
pub extern "win64" fn get_foreground_window() -> usize {
    window::all_hwnds().into_iter().next().unwrap_or(0)
}

/// SetForegroundWindow: attempt to bring a window to the foreground.
///
/// Phase 2: no-op (always succeeds).
pub extern "win64" fn set_foreground_window(_hwnd: usize) -> i32 {
    1
}

/// GetDesktopWindow: return the handle to the desktop window.
///
/// Phase 2: returns 0 (no desktop window object).
pub extern "win64" fn get_desktop_window() -> usize {
    0
}

// ── AdjustWindowRect ──────────────────────────────────────────────────────────

/// AdjustWindowRect: compute window size from desired client area size.
///
/// Phase 2: returns the rect unchanged (no frame adjustments without a real WM).
///
/// # Safety
/// `lp_rect` must point to a valid `RECT`.
pub unsafe extern "win64" fn adjust_window_rect(
    lp_rect: *mut Rect,
    _dw_style: u32,
    _b_menu: i32,
) -> i32 {
    if lp_rect.is_null() {
        0
    } else {
        1
    }
}

/// AdjustWindowRectEx: extended version with ex style parameter.
///
/// # Safety
/// `lp_rect` must point to a valid `RECT`.
pub unsafe extern "win64" fn adjust_window_rect_ex(
    lp_rect: *mut Rect,
    _dw_style: u32,
    _b_menu: i32,
    _dw_ex_style: u32,
) -> i32 {
    if lp_rect.is_null() {
        0
    } else {
        1
    }
}

/// SetCursor: set the cursor shape.
///
/// Phase 2: no-op; returns the previous cursor (fake handle = 1).
pub extern "win64" fn set_cursor(_h_cursor: usize) -> usize {
    1
}

/// ShowCursor: show or hide the cursor (ref-counted).
///
/// Phase 2: returns 0 (display counter unchanged).
pub extern "win64" fn show_cursor(_b_show: i32) -> i32 {
    0
}

// ── Display and mode enumeration stubs ────────────────────────────────────────

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn enum_display_devices_w(
    _lp_device: *const u16,
    _i_dev_num: u32,
    _lp_display_device: usize,
    _dw_flags: u32,
) -> i32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn enum_display_settings_w(
    _lp_sz_device_name: *const u16,
    _i_mode_num: u32,
    _lp_dev_mode: usize,
) -> i32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn enum_display_settings_ex_w(
    _lp_sz_device_name: *const u16,
    _i_mode_num: u32,
    _lp_dev_mode: usize,
    _dw_flags: u32,
) -> i32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn change_display_settings_w(_lp_dev_mode: usize, _dw_flags: u32) -> i32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn change_display_settings_ex_w(
    _lp_sz_device_name: *const u16,
    _lp_dev_mode: usize,
    _hwnd: usize,
    _dw_flags: u32,
    _lp_param: usize,
) -> i32 {
    0
}

// ── Monitor handle functions ─────────────────────────────────────────────────

pub extern "win64" fn monitor_from_window(_hwnd: usize, _dw_flags: u32) -> usize {
    1usize
}

pub extern "win64" fn monitor_from_point(_pt_x: i32, _pt_y: i32, _dw_flags: u32) -> usize {
    1usize
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn monitor_from_rect(_lp_rc: *const Rect, _dw_flags: u32) -> usize {
    1usize
}

/// # Safety
/// `lp_mi` must point to a valid `MonitorInfo` struct.
pub unsafe extern "win64" fn get_monitor_info_w(_h_monitor: usize, lp_mi: *mut MonitorInfo) -> i32 {
    if lp_mi.is_null() {
        return 0;
    }
    unsafe {
        (*lp_mi).rc_monitor = Rect {
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
        };
        (*lp_mi).rc_work = Rect {
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
        };
        (*lp_mi).dw_flags = 1;
    }
    1
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn enum_display_monitors(
    _hdc: usize,
    _lprc_clip: usize,
    _lpfn_enum: usize,
    _dw_data: isize,
) -> i32 {
    1
}

// ── Window long + SetWindowPos ───────────────────────────────────────────────

const GWL_WNDPROC: i32 = -4;
const GWL_STYLE: i32 = -16;
#[allow(dead_code)]
const GWL_EXSTYLE: i32 = -20;

pub extern "win64" fn get_window_long_w(hwnd: usize, n_index: i32) -> i32 {
    window::with(hwnd, |w| match n_index {
        GWL_STYLE => w.style as i32,
        GWL_WNDPROC => w.wnd_proc as i32,
        _ => 0,
    })
    .unwrap_or(0)
}

pub extern "win64" fn get_window_long_ptr_w(hwnd: usize, n_index: i32) -> isize {
    window::with(hwnd, |w| match n_index {
        GWL_STYLE => w.style as isize,
        GWL_WNDPROC => w.wnd_proc as isize,
        _ => 0,
    })
    .unwrap_or(0)
}

pub extern "win64" fn set_window_long_w(hwnd: usize, n_index: i32, dw_new_long: i32) -> i32 {
    match n_index {
        GWL_STYLE => window::with_mut(hwnd, |w| {
            let old = w.style as i32;
            w.style = dw_new_long as u32;
            old
        })
        .unwrap_or(0),
        _ => 0,
    }
}

pub extern "win64" fn set_window_long_ptr_w(
    hwnd: usize,
    n_index: i32,
    dw_new_long: isize,
) -> isize {
    match n_index {
        GWL_STYLE => window::with_mut(hwnd, |w| {
            let old = w.style as isize;
            w.style = dw_new_long as u32;
            old
        })
        .unwrap_or(0),
        GWL_WNDPROC => window::with_mut(hwnd, |w| {
            let old = w.wnd_proc as isize;
            w.wnd_proc = dw_new_long as usize;
            old
        })
        .unwrap_or(0),
        _ => 0,
    }
}

const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;

/// SetWindowPos: change window size, position, and Z order.
///
/// Updates the window table entry. Returns TRUE.
pub extern "win64" fn set_window_pos(
    hwnd: usize,
    _hwnd_insert_after: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    u_flags: u32,
) -> i32 {
    window::with_mut(hwnd, |w| {
        if u_flags & SWP_NOMOVE == 0 {
            w.x = x;
            w.y = y;
        }
        if u_flags & SWP_NOSIZE == 0 {
            w.width = cx as u32;
            w.height = cy as u32;
        }
    });
    1 // TRUE
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn find_window_w(
    _lp_class_name: *const u16,
    _lp_window_name: *const u16,
) -> usize {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn find_window_a(
    _lp_class_name: *const u8,
    _lp_window_name: *const u8,
) -> usize {
    0
}

pub extern "win64" fn is_window(hwnd: usize) -> i32 {
    if window::with(hwnd, |_| ()).is_some() {
        1
    } else {
        0
    }
}

pub extern "win64" fn is_window_visible(hwnd: usize) -> i32 {
    window::with(hwnd, |w| w.visible as i32).unwrap_or(0)
}

/// # Safety
/// `lpdw_process_id` may be null.
pub unsafe extern "win64" fn get_window_thread_process_id(
    _hwnd: usize,
    lpdw_process_id: *mut u32,
) -> u32 {
    unsafe {
        if !lpdw_process_id.is_null() {
            *lpdw_process_id = libc::getpid() as u32;
        }
    }
    1 // fake thread ID
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn screen_to_client(_hwnd: usize, _lp_point: usize) -> i32 {
    1
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn client_to_screen(_hwnd: usize, _lp_point: usize) -> i32 {
    1
}

// ── Cursor + misc window ops ─────────────────────────────────────────────────

/// # Safety
/// `lp_point` must point to a valid `Point` struct.
pub unsafe extern "win64" fn get_cursor_pos(lp_point: *mut Point) -> i32 {
    if lp_point.is_null() {
        return 0;
    }
    unsafe {
        (*lp_point).x = 0;
        (*lp_point).y = 0;
    }
    1
}

pub extern "win64" fn set_cursor_pos(_x: i32, _y: i32) -> i32 {
    1
}

pub extern "win64" fn enable_window(_hwnd: usize, _b_enable: i32) -> i32 {
    0
}

pub extern "win64" fn is_window_enabled(_hwnd: usize) -> i32 {
    1
}

pub extern "win64" fn get_parent(_hwnd: usize) -> usize {
    0
}

pub extern "win64" fn set_parent(_hwnd_child: usize, _hwnd_new_parent: usize) -> usize {
    0
}

pub extern "win64" fn bring_window_to_top(_hwnd: usize) -> i32 {
    1
}

pub extern "win64" fn window_from_point(_pt_x: i32, _pt_y: i32) -> usize {
    0
}

// ── DPI awareness stubs ───────────────────────────────────────────────────────

/// SetProcessDPIAware: mark the process as DPI-aware.
pub extern "win64" fn set_process_dpi_aware() -> i32 {
    1
}

/// GetDpiForWindow: return the DPI for a window.
pub extern "win64" fn get_dpi_for_window(_hwnd: usize) -> u32 {
    96
}

/// GetDpiForSystem: return the system DPI.
pub extern "win64" fn get_dpi_for_system() -> u32 {
    96
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn adjust_window_rect_ex_for_dpi(
    _lp_rect: usize,
    _dw_style: u32,
    _b_menu: i32,
    _dw_ex_style: u32,
    _dpi: u32,
) -> i32 {
    1
}

/// SetProcessDpiAwarenessContext: set the DPI awareness context.
pub extern "win64" fn set_process_dpi_awareness_context(_value: isize) -> i32 {
    1
}

/// GetDpiAwarenessContextForProcess: get the DPI awareness context for a process.
pub extern "win64" fn get_dpi_awareness_context_for_process(_h_process: usize) -> isize {
    -4isize
}

/// AreDpiAwarenessContextsEqual: compare two DPI awareness contexts.
pub extern "win64" fn are_dpi_awareness_contexts_equal(
    dpi_context_a: isize,
    dpi_context_b: isize,
) -> i32 {
    (dpi_context_a == dpi_context_b) as i32
}

// ── Input state stubs ─────────────────────────────────────────────────────────

/// GetKeyState: return the state of a virtual key.
pub extern "win64" fn get_key_state(_n_virt_key: i32) -> i16 {
    0
}

/// GetAsyncKeyState: return the state of a virtual key (async).
pub extern "win64" fn get_async_key_state(_v_key: i32) -> i16 {
    0
}

/// MapVirtualKeyW: map a virtual key code to a scan code or character.
pub extern "win64" fn map_virtual_key_w(_u_code: u32, _u_map_type: u32) -> u32 {
    0
}

/// MapVirtualKeyExW: map a virtual key code to a scan code or character (extended).
pub extern "win64" fn map_virtual_key_ex_w(_u_code: u32, _u_map_type: u32, _dwhkl: usize) -> u32 {
    0
}

/// GetKeyboardLayout: return the keyboard layout for the current thread.
pub extern "win64" fn get_keyboard_layout(_id_thread: u32) -> usize {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_keyboard_layout_list(_n_buff: i32, _lp_list: usize) -> i32 {
    0
}

/// VkKeyScanW: translate a character to a virtual key code.
pub extern "win64" fn vk_key_scan_w(_ch: u16) -> i16 {
    -1i16
}

/// # Safety
/// `lp_key_state` must be a valid pointer to 256 bytes if non-null.
pub unsafe extern "win64" fn get_keyboard_state(lp_key_state: *mut u8) -> i32 {
    if !lp_key_state.is_null() {
        unsafe { std::ptr::write_bytes(lp_key_state, 0, 256) };
    }
    1
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn to_unicode_ex(
    _w_virt_key: u32,
    _w_scan_code: u32,
    _lp_key_state: usize,
    _pwsz_buff: usize,
    _cch_buff: i32,
    _w_flags: u32,
    _dwhkl: usize,
) -> i32 {
    0
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Call a window procedure (stored as `usize`) with `extern "win64"` ABI.
fn call_wnd_proc(proc_addr: usize, hwnd: usize, msg: u32, w_param: usize, l_param: isize) -> isize {
    if proc_addr == 0 {
        return 0;
    }
    // Safety: proc_addr was registered by the PE as a valid WNDPROC with the
    // Windows x64 calling convention. Transmuting a usize to a fn pointer is
    // how Weave calls all guest callbacks.
    let f: unsafe extern "win64" fn(usize, u32, usize, isize) -> isize =
        unsafe { std::mem::transmute(proc_addr) };
    unsafe { f(hwnd, msg, w_param, l_param) }
}

/// Write a `MsgEntry` into the caller-provided `MSG` buffer.
///
/// # Safety
/// `lp_msg` must be a valid writable pointer.
unsafe fn fill_msg(lp_msg: *mut Msg, entry: &MsgEntry) {
    unsafe {
        let m = &mut *lp_msg;
        m.hwnd = entry.hwnd;
        m.message = entry.message;
        m._pad0 = 0;
        m.w_param = entry.w_param;
        m.l_param = entry.l_param;
        m.time = entry.time;
        m.pt_x = entry.pt_x;
        m.pt_y = entry.pt_y;
        m._pad1 = 0;
    }
}
