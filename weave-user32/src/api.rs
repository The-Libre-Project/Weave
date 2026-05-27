//! Win32 user32 API function implementations.
//!
//! All functions use `extern "win64"` (Windows x86-64 calling convention).
//! Functions that need X11 delegate to `backend::*`; when X11 is unavailable
//! (no display, or non-Linux) they return safe error values.

#![allow(non_snake_case)]

use crate::backend;
use crate::class::{self, ClassEntry};
use crate::defs::*;
use crate::input;
use crate::menu;
use crate::queue::{self, MsgEntry};
use crate::window::{self, WindowEntry};
use libc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use weave_common::set_last_error;
use weave_core::progress::mark_phase;
use weave_core::restrace;

// ── Progress phase guards (fire exactly once) ────────────────────────────────

static PHASE_REGISTER_CLASS: AtomicBool = AtomicBool::new(false);
static PHASE_CREATE_WINDOW: AtomicBool = AtomicBool::new(false);
static PHASE_GET_MESSAGE: AtomicBool = AtomicBool::new(false);
static PHASE_WM_PAINT_DISPATCHED: AtomicBool = AtomicBool::new(false);
static PHASE_SCI_GETLENGTH: AtomicBool = AtomicBool::new(false);
// Fires once on first ShowWindow(SW_HIDE) — marks the boundary between startup/render
// and teardown. Used to order unresolved-stub firings relative to shutdown start.
static PHASE_SW_HIDE_FIRST: AtomicBool = AtomicBool::new(false);
/// Monotonically increasing sequence number for SendMessageW enter/exit pairing.
static SEND_MSG_SEQ: AtomicU32 = AtomicU32::new(0);

// ── Scroll bar per-(hwnd,bar) state ──────────────────────────────────────────

/// Per-window per-bar scroll state.
#[derive(Clone, Default)]
struct ScrollState {
    n_min: i32,
    n_max: i32,
    n_page: u32,
    n_pos: i32,
}

static SCROLL_STATE: OnceLock<Mutex<HashMap<(usize, i32), ScrollState>>> = OnceLock::new();

fn scroll_state() -> &'static Mutex<HashMap<(usize, i32), ScrollState>> {
    SCROLL_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Per-window extra data (GWL_EXSTYLE / GWLP_USERDATA / cbWndExtra) ────────
//
// Stored outside WindowEntry so that adding these fields doesn't change the
// struct's heap-allocation size (which affects glibc tcache bucketing and can
// expose latent heap bugs in certain apps).

struct WindowExtra {
    ex_style: u32,
    user_data: isize,
    /// cbWndExtra bytes allocated at window creation (accessed via GetWindowLongPtr index >= 0).
    extra_bytes: Vec<u8>,
}

static WINDOW_EXTRA: OnceLock<Mutex<HashMap<usize, WindowExtra>>> = OnceLock::new();

fn window_extra() -> &'static Mutex<HashMap<usize, WindowExtra>> {
    WINDOW_EXTRA.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_extra<R, F: FnOnce(&WindowExtra) -> R>(hwnd: usize, f: F, default: R) -> R {
    window_extra()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&hwnd)
        .map(f)
        .unwrap_or(default)
}

fn set_extra<F: FnOnce(&mut WindowExtra)>(hwnd: usize, f: F) {
    let mut map = window_extra().lock().unwrap_or_else(|p| p.into_inner());
    let entry = map.entry(hwnd).or_insert(WindowExtra {
        ex_style: 0,
        user_data: 0,
        extra_bytes: Vec::new(),
    });
    f(entry);
}

/// Seed per-window extra storage for HWNDs created outside CreateWindowExW (e.g. dialogs).
pub(crate) fn init_window_extra(hwnd: usize, ex_style: u32, cb_wnd_extra: u32) {
    if hwnd == 0 {
        return;
    }
    set_extra(hwnd, |e| {
        e.ex_style = ex_style;
        e.extra_bytes = vec![0u8; cb_wnd_extra as usize];
    });
}

/// Fire the create-window phase marker once (dialogs bypass CreateWindowExW).
pub(crate) fn mark_create_window_phase() {
    if !PHASE_CREATE_WINDOW.swap(true, Ordering::Relaxed) {
        mark_phase("create_window_first");
    }
}

// ── Caret position ───────────────────────────────────────────────────────────

static CARET_X: AtomicI32 = AtomicI32::new(0);
static CARET_Y: AtomicI32 = AtomicI32::new(0);

// ── Timer ID allocator ───────────────────────────────────────────────────────

static NEXT_TIMER_ID: AtomicU32 = AtomicU32::new(1);

static TIMER_TABLE: OnceLock<Mutex<HashMap<(usize, usize), usize>>> = OnceLock::new();

fn timer_table() -> &'static Mutex<HashMap<(usize, usize), usize>> {
    TIMER_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Last message time and position ───────────────────────────────────────────

static LAST_MSG_TIME: AtomicU32 = AtomicU32::new(0);
static LAST_MSG_POS_X: AtomicI32 = AtomicI32::new(0);
static LAST_MSG_POS_Y: AtomicI32 = AtomicI32::new(0);

/// HWND currently holding keyboard focus (0 = none).
static FOCUSED_HWND: AtomicUsize = AtomicUsize::new(0);

/// The HWND most recently passed to BeginPaint. Used by gdi32's CreateCompatibleDC(NULL)
/// as a fallback when no explicit DC is provided.
static CURRENT_PAINT_HWND: AtomicUsize = AtomicUsize::new(0);

/// Return the HWND that was most recently passed to BeginPaint.
/// Used by weave-gdi32 to resolve CreateCompatibleDC(NULL).
pub fn current_paint_hwnd() -> usize {
    CURRENT_PAINT_HWND.load(Ordering::Relaxed)
}

// ── TrackMouseEvent leave-tracking table ─────────────────────────────────────
// Per-hwnd set of windows that have an active TME_LEAVE subscription.
// When the XCB LeaveNotify fires for a window in this set, WM_MOUSELEAVE is
// posted and the entry is removed (one-shot per Wine contract).

use std::collections::HashSet;

static TME_LEAVE_TABLE: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

fn tme_leave_table() -> &'static Mutex<HashSet<usize>> {
    TME_LEAVE_TABLE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Per-hwnd validated set. When an hwnd is present, its update region has been
/// cleared via ValidateRect and GetUpdateRect should return FALSE.
static VALIDATED_HWNDS: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

fn validated_hwnds() -> &'static Mutex<HashSet<usize>> {
    VALIDATED_HWNDS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Register TME_LEAVE for `hwnd`. Called by `track_mouse_event`.
pub fn register_tme_leave(hwnd: usize) {
    if let Ok(mut t) = tme_leave_table().lock() {
        t.insert(hwnd);
    }
}

/// Cancel TME_LEAVE for `hwnd`. Called by `track_mouse_event` with TME_CANCEL.
pub fn cancel_tme_leave(hwnd: usize) {
    if let Ok(mut t) = tme_leave_table().lock() {
        t.remove(&hwnd);
    }
}

/// Check and atomically remove TME_LEAVE for `hwnd`. Returns true if it was registered.
/// Called from the backend XCB LeaveNotify handler.
pub fn take_tme_leave(hwnd: usize) -> bool {
    if let Ok(mut t) = tme_leave_table().lock() {
        t.remove(&hwnd)
    } else {
        false
    }
}

// ── RegisterClassW / RegisterClassExW ─────────────────────────────────────────

/// RegisterClassW: register a window class.
///
/// Returns a non-zero ATOM identifying the class, or 0 on failure.
///
/// # Safety
/// `lp_wnd_class` must point to a valid `WNDCLASSW` struct.
// Wine ref: dlls/user32/class.c — RegisterClassW calls NtUserRegisterClassExWOW; ATOM is
// allocated by the server; duplicate registration returns the existing atom, not an error.
pub unsafe extern "win64" fn register_class_w(lp_wnd_class: *const WndClassW) -> u16 {
    if !PHASE_REGISTER_CLASS.swap(true, Ordering::Relaxed) {
        mark_phase("register_class_first");
    }
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
            cb_wnd_extra: wc.cb_wnd_extra.max(0) as u32,
            h_icon: 0,
            h_icon_sm: 0,
        },
    );
    // Return a non-zero ATOM — use a hash of the name for uniqueness.
    name_to_atom(&name)
}

/// RegisterClassExW: extended version with cbSize + hIconSm fields.
///
/// # Safety
/// `lp_wnd_class_ex` must point to a valid `WNDCLASSEXW` struct.
// Wine ref: dlls/user32/class.c — RegisterClassExW validates cbSize == sizeof(WNDCLASSEXW)
// before passing to NtUserRegisterClassExWOW; hIconSm stored separately from hIcon.
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
            cb_wnd_extra: wc.cb_wnd_extra.max(0) as u32,
            h_icon: 0,
            h_icon_sm: 0,
        },
    );
    let atom = name_to_atom(&name);
    eprintln!("weave/user32: RegisterClassExW({name:?}) → atom 0x{atom:04x}");
    atom
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
/// Wine ref: dlls/user32/win.c::CreateWindowExW — fills a CREATESTRUCTW and delegates to
/// wow_handlers.create_window; dwExStyle is stored in cs.dwExStyle and must be preserved
/// in the window object for GetWindowLong(GWL_EXSTYLE) to return the correct value.
/// Sends WM_NCCREATE then WM_CREATE with a pointer to CREATESTRUCTW as lParam.
///
/// # Safety
/// `lp_class_name` and `lp_window_name` (if non-null) must be valid
/// null-terminated UTF-16 strings.
// Wine ref: dlls/user32/win.c::CreateWindowExW — fills CREATESTRUCTW, sends WM_NCCREATE
// then WM_CREATE; dwExStyle stored in window object for GWL_EXSTYLE; returns NULL on WM_CREATE failure.
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
    if !PHASE_CREATE_WINDOW.swap(true, Ordering::Relaxed) {
        mark_phase("create_window_first");
    }
    let class_name = unsafe { decode_wide(lp_class_name) };
    let title = unsafe { decode_wide(lp_window_name) };

    // Look up the class.
    let cls = match class::find(&class_name) {
        Some(c) => c,
        None => {
            eprintln!("weave/user32: CreateWindowExW: unknown class '{class_name}' → 0");
            return 0;
        }
    };

    // Default size for CW_USEDEFAULT (0x80000000 as i32) and for top-level windows
    // created with zero size (e.g. NPP reads window size from config; when config is
    // absent it passes 0×0, intending the OS to supply a default).
    // Wine ref: dlls/win32u/window.c::NtUserCreateWindowEx — CW_USEDEFAULT is only
    // valid for top-level windows; for child windows a 0-size is left at 0.
    let is_toplevel = (dw_style & WS_CHILD) == 0;
    let width = if n_width == i32::MIN || (is_toplevel && n_width <= 0) {
        800
    } else {
        n_width.max(1)
    } as u32;
    let height = if n_height == i32::MIN || (is_toplevel && n_height <= 0) {
        600
    } else {
        n_height.max(1)
    } as u32;
    let pos_x = if x == i32::MIN { 100 } else { x };
    let pos_y = if y == i32::MIN { 100 } else { y };

    // Wine ref: dlls/win32u/window.c — child window positions are parent-relative;
    // top-level window positions are screen coordinates. Translate to screen coords
    // so the Win32 window table stores correct absolute positions for future lookups.
    let (abs_x, abs_y) = if (dw_style & WS_CHILD) != 0 && h_wnd_parent != 0 {
        let parent_pos = window::with(h_wnd_parent, |e| (e.x, e.y)).unwrap_or((0, 0));
        (pos_x + parent_pos.0, pos_y + parent_pos.1)
    } else {
        (pos_x, pos_y)
    };

    let visible = (dw_style & WS_VISIBLE) != 0;

    // For child windows, create the X11 window as a child of the Win32 parent's X11
    // window. X11 child windows use parent-relative coordinates and are z-ordered on
    // top of (and clipped by) their X11 parent — which is the correct Win32 behavior.
    // Top-level windows are created as children of the root window (screen coords).
    let (x11_x, x11_y, parent_xcb_id) = if (dw_style & WS_CHILD) != 0 && h_wnd_parent != 0 {
        let px = window::xcb_id(h_wnd_parent);
        if px != 0 {
            (pos_x, pos_y, px) // relative coords, proper X11 parent
        } else {
            (abs_x, abs_y, 0u32) // no X11 parent yet; fall back to root
        }
    } else {
        (pos_x, pos_y, 0u32) // top-level: screen coords, root parent
    };

    // Create the X11 window (no-op on non-Linux).
    let xcb_id =
        backend::create_window(&title, x11_x, x11_y, width, height, visible, parent_xcb_id);

    eprintln!("weave/user32: CreateWindow class={class_name:?} title={title:?} pos=({abs_x},{abs_y}) size={width}x{height} visible={visible} style={dw_style:#010x} xcb={xcb_id:#x} parent_xcb={parent_xcb_id:#x}");

    let hwnd = window::create(WindowEntry {
        class_name: class_name.clone(),
        wnd_proc: cls.wnd_proc,
        title: title.clone(),
        style: dw_style,
        x: abs_x,
        y: abs_y,
        width,
        height,
        visible,
        xcb_id,
        h_menu: h_menu_param,
        hwnd_parent: h_wnd_parent,
        tid: unsafe { libc::syscall(libc::SYS_gettid) as u32 },
    });
    set_extra(hwnd, |e| {
        e.ex_style = dw_ex_style;
        e.extra_bytes = vec![0u8; cls.cb_wnd_extra as usize];
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
    let wm_create_ret = call_wnd_proc(cls.wnd_proc, hwnd, WM_CREATE, 0, &cs as *const _ as isize);
    eprintln!("weave/user32: WM_CREATE class={class_name:?} hwnd={hwnd:#x} → {wm_create_ret}");

    // Probe Scintilla document state immediately after WM_CREATE, before NPP has a
    // chance to call SCI_SETDOCPOINTER.  This tells us whether pdoc is NULL from the
    // start (constructor/init failure) or whether something clears it later.
    // SCI_GETDOCPOINTER = 2268, SCI_GETDIRECTPOINTER = 2185.
    if class_name.eq_ignore_ascii_case("Scintilla") {
        let sci_ptr = send_message_w(hwnd, 2185, 0, 0); // SCI_GETDIRECTPOINTER → this*
        let doc_ptr = send_message_w(hwnd, 2268, 0, 0); // SCI_GETDOCPOINTER → pdoc
        eprintln!("weave/user32: Scintilla post-WM_CREATE hwnd={hwnd:#x} sci*={sci_ptr:#x} pdoc={doc_ptr:#x}");
    }

    hwnd
}

// ── ShowWindow ────────────────────────────────────────────────────────────────

/// ShowWindow: show, hide, or change the state of a window.
///
/// Returns the previous visibility state as a BOOL.
// Wine ref: dlls/win32u/window.c::show_window — returns was_visible; sends WM_SHOWWINDOW
// before changing visibility; handles SW_HIDE, SW_MINIMIZE, SW_MAXIMIZE, SW_RESTORE, etc.
// TODO Wine ref gap: WM_SHOWWINDOW not sent before show/hide (Phase 4); SW_MINIMIZE/MAXIMIZE
// not handled (treated as show).
pub extern "win64" fn show_window(hwnd: usize, n_cmd_show: i32) -> i32 {
    let was_visible = window::with(hwnd, |e| e.visible).unwrap_or(false);

    let show = !matches!(n_cmd_show, SW_HIDE);

    // Ordering marker: first SW_HIDE is the boundary between render loop and teardown.
    // Any unresolved-stub firings after this line are teardown-only.
    if !show && !PHASE_SW_HIDE_FIRST.swap(true, Ordering::Relaxed) {
        eprintln!("weave/user32: ShowWindow SW_HIDE first-fire — teardown sequence begins (hwnd={hwnd:#x})");
    }

    let xcb = window::xcb_id(hwnd);
    eprintln!("weave/user32: ShowWindow hwnd={hwnd:#x} cmd={n_cmd_show} show={show} xcb={xcb:#x}");
    window::with_mut(hwnd, |e| e.visible = show);
    backend::show_window(xcb, show);

    // Win32 invalid-region model: when a window first becomes visible the OS marks
    // its entire client area dirty, causing WM_PAINT to be synthesised by the next
    // GetMessage call.  We replicate this by posting WM_PAINT immediately so that
    // the message loop doesn't have to wait for an X11 Expose event.
    if show && !was_visible && hwnd != 0 {
        eprintln!("weave/user32: ShowWindow → posting WM_PAINT to hwnd={hwnd:#x}");
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

    was_visible as i32
}

/// UpdateWindow: send WM_PAINT directly if the update region is non-empty.
/// Phase 2: always posts WM_PAINT to the message queue.
// Wine ref: dlls/win32u/painting.c — NtUserRedrawWindow with RDW_UPDATENOW; sends WM_PAINT
// only if the window has a non-empty update region; returns TRUE even if nothing was painted.
pub extern "win64" fn update_window(hwnd: usize) -> i32 {
    eprintln!("weave/user32: UpdateWindow hwnd={hwnd:#x}");
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

// Wine ref: dlls/win32u/window.c::user_destroy_window — sends WM_DESTROY first via
// send_destroy_message, then WM_NCDESTROY inside destroy_window. WM_NCDESTROY is always
// the last message a window receives; WM_DESTROY precedes it.
pub extern "win64" fn destroy_window(hwnd: usize) -> i32 {
    let xcb = window::xcb_id(hwnd);
    eprintln!("weave/user32: DestroyWindow hwnd={hwnd:#x} xcb={xcb:#x}");

    // WM_DESTROY first, then WM_NCDESTROY (Wine order: send_destroy_message → destroy_window).
    if let Some(proc_addr) = window::with(hwnd, |e| e.wnd_proc) {
        call_wnd_proc(proc_addr, hwnd, WM_DESTROY, 0, 0);
        call_wnd_proc(proc_addr, hwnd, WM_NCDESTROY, 0, 0);
    }

    backend::destroy_window(xcb);
    window::remove(hwnd);
    window_extra()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&hwnd);
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
/// Wine ref: dlls/win32u/message.c — GetMessageW calls NtUserGetMessage which blocks on the
/// server queue; WM_QUIT returns 0; null lp_msg → returns -1. hwnd/filter params narrow which
/// messages are returned; Weave ignores filters (Phase 4 gap).
///
/// # Safety
/// `lp_msg` must be a valid writable pointer to a `MSG`-sized buffer (48 bytes).
// Wine ref: dlls/win32u/message.c — NtUserGetMessage blocks on server queue; WM_QUIT → 0;
// hwnd/filter narrow which messages dequeue; dispatches SendMessage calls while waiting.
pub unsafe extern "win64" fn get_message_w(
    lp_msg: *mut Msg,
    _h_wnd: usize,        // window filter — 0 = all windows (ignored in Phase 2)
    _msg_filter_min: u32, // message range filter (ignored)
    _msg_filter_max: u32,
) -> i32 {
    if !PHASE_GET_MESSAGE.swap(true, Ordering::Relaxed) {
        mark_phase("get_message_first");
    }
    if lp_msg.is_null() {
        return -1;
    }

    // Apply any pending deferred doc transfer after NPP is fully initialized.
    // The transfer crashes if applied too early (NPP not ready for SCN_DOCUMENTCHANGE at
    // RVA 0x2521b3). Wait until PHASE_WM_PAINT has fired (first WM_PAINT = NPP fully up).
    {
        let pending_sci = PENDING_DOC_SCI.load(std::sync::atomic::Ordering::Relaxed);
        let text_buf = PENDING_TEXT_BUF.load(std::sync::atomic::Ordering::Relaxed);
        if pending_sci != 0
            && text_buf != 0
            && PHASE_WM_PAINT_DISPATCHED.load(std::sync::atomic::Ordering::Relaxed)
        {
            // Clear all pending state before calling to prevent re-triggering.
            PENDING_DOC_SCI.store(0, std::sync::atomic::Ordering::Relaxed);
            PENDING_DOC_PTR.store(0, std::sync::atomic::Ordering::Relaxed);
            PENDING_TEXT_BUF.store(0, std::sync::atomic::Ordering::Relaxed);
            let real_fn = SCI_REAL_DIRECT_FN.load(std::sync::atomic::Ordering::Relaxed);
            if real_fn != 0 {
                type DirectFn =
                    unsafe extern "win64" fn(usize, u32, usize, isize, *mut u8) -> isize;
                let f: DirectFn = unsafe { std::mem::transmute(real_fn) };
                // Use SCI_APPENDTEXT (2282) — confirmed working in this Scintilla build.
                // SCI_SETTEXT (2009) returned len=0 (wrong msg# or notification resets it).
                // SCI_APPENDTEXT fires SCN_MODIFIED (safe from message-loop context).
                // First clear any content, then append the file bytes.
                unsafe {
                    f(
                        pending_sci,
                        2004, /*SCI_CLEARALL*/
                        0,
                        0,
                        std::ptr::null_mut(),
                    )
                };
                // text_buf is null-terminated; pass wparam=length (not including null).
                let text_len = unsafe {
                    std::ffi::CStr::from_ptr(text_buf as *const i8)
                        .to_bytes()
                        .len()
                };
                unsafe {
                    f(
                        pending_sci,
                        2282, /*SCI_APPENDTEXT*/
                        text_len,
                        text_buf as isize,
                        std::ptr::null_mut(),
                    )
                };
                // Free the buffer we allocated in sci_direct_fn_proxy.
                let _ = unsafe { Box::from_raw(text_buf as *mut u8) };
                let main_len = unsafe { f(pending_sci, 2006, 0, 0, std::ptr::null_mut()) };
                eprintln!(
                    "weave/GetMessageW: applied SCI_SETTEXT to main \
                     sci={pending_sci:#x} main_SCI_GETLENGTH={main_len}"
                );
            }
        }
    }

    // Wait for a message: keep pumping X11 events until the queue has one.
    static GM_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static GM_ENTRY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let entry_n = GM_ENTRY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if entry_n < 5 {
        eprintln!("weave/GetMessageW: entry #{entry_n}");
    }
    loop {
        if let Some(entry) = queue::pop() {
            let n = GM_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n < 30 {
                eprintln!(
                    "weave/GetMessageW#{n}: hwnd={:#x} msg={}",
                    entry.hwnd, entry.message
                );
            }
            fill_msg(lp_msg, &entry);
            if entry.message == WM_QUIT {
                eprintln!(
                    "weave/user32: GetMessageW → WM_QUIT (exit_code={}) — shutdown begins",
                    entry.w_param
                );
                return 0;
            }
            return 1;
        }
        // Block on the X11 connection for the next event.
        if !backend::wait_event() {
            // Connection lost or no display — return WM_QUIT.
            eprintln!("weave/user32: GetMessageW → WM_QUIT (no display) — shutdown begins");
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
/// Wine ref: dlls/win32u/message.c — PeekMessageW calls NtUserPeekMessage; PM_NOREMOVE (0)
/// peeks without removing; PM_REMOVE (1) pops; returns non-zero if a message is available.
/// Returns 0 (no message) without blocking, unlike GetMessage.
///
/// # Safety
/// `lp_msg` must be a valid writable pointer to a `MSG`-sized buffer.
// Wine ref: dlls/win32u/message.c — NtUserPeekMessage; PM_NOREMOVE leaves msg in queue;
// PM_REMOVE pops; PM_NOYIELD suppresses fiber yield; returns 0 immediately if no msg.
pub unsafe extern "win64" fn peek_message_w(
    lp_msg: *mut Msg,
    _h_wnd: usize,
    _msg_filter_min: u32,
    _msg_filter_max: u32,
    w_remove_msg: u32, // PM_NOREMOVE (0) or PM_REMOVE (1)
) -> i32 {
    // Shared phase flag with GetMessageW — fires once on whichever is called first.
    if !PHASE_GET_MESSAGE.swap(true, Ordering::Relaxed) {
        mark_phase("get_message_first");
    }
    static PEEK_ENTRY: AtomicU32 = AtomicU32::new(0);
    let pn = PEEK_ENTRY.fetch_add(1, Ordering::Relaxed);
    if pn < 5 {
        eprintln!("weave/PeekMessageW: entry #{pn}");
    }
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
            static PEEK_MSG_COUNT: AtomicU32 = AtomicU32::new(0);
            let mn = PEEK_MSG_COUNT.fetch_add(1, Ordering::Relaxed);
            if mn < 30 {
                eprintln!(
                    "weave/PeekMessageW#{mn}: hwnd={:#x} msg={}",
                    e.hwnd, e.message
                );
            }
            fill_msg(lp_msg, e);
            1 // TRUE — message available
        }
        None => 0, // FALSE — no message
    }
}

/// Map an X11 keycode to a Unicode code point (unshifted, standard PC layout).
///
/// X11 keycodes are hardware-specific but follow a well-known layout on
/// Convert a Win32 VK virtual key code to a Unicode character for WM_CHAR.
///
/// Wine ref: dlls/winex11.drv/keyboard.c::X11DRV_ToUnicodeEx — applies the active
/// keyboard layout to translate a VK + scan code pair to a Unicode string; for
/// simple layouts this reduces to a table lookup. Weave: static US-QWERTY mapping.
///
/// `shift` is extracted from the X11 modifier state stored in `msg.l_param >> 16`.
/// ShiftMask = bit 0 of the X11 state word.
fn vk_to_char(vk: usize, shift: bool) -> Option<char> {
    // Letters: VK_A(0x41)..VK_Z(0x5A) → lowercase or uppercase
    if (0x41..=0x5A).contains(&vk) {
        let base = vk as u8; // uppercase ASCII
        return Some(if shift {
            base as char
        } else {
            (base + 0x20) as char
        });
    }
    // Digits and OEM punctuation
    let ch = match vk {
        // Digits — shift gives US shift-symbol
        0x30 => {
            if shift {
                ')'
            } else {
                '0'
            }
        }
        0x31 => {
            if shift {
                '!'
            } else {
                '1'
            }
        }
        0x32 => {
            if shift {
                '@'
            } else {
                '2'
            }
        }
        0x33 => {
            if shift {
                '#'
            } else {
                '3'
            }
        }
        0x34 => {
            if shift {
                '$'
            } else {
                '4'
            }
        }
        0x35 => {
            if shift {
                '%'
            } else {
                '5'
            }
        }
        0x36 => {
            if shift {
                '^'
            } else {
                '6'
            }
        }
        0x37 => {
            if shift {
                '&'
            } else {
                '7'
            }
        }
        0x38 => {
            if shift {
                '*'
            } else {
                '8'
            }
        }
        0x39 => {
            if shift {
                '('
            } else {
                '9'
            }
        }
        // OEM keys (US layout)
        0xBA => {
            if shift {
                ':'
            } else {
                ';'
            }
        } // VK_OEM_1
        0xBB => {
            if shift {
                '+'
            } else {
                '='
            }
        } // VK_OEM_PLUS
        0xBC => {
            if shift {
                '<'
            } else {
                ','
            }
        } // VK_OEM_COMMA
        0xBD => {
            if shift {
                '_'
            } else {
                '-'
            }
        } // VK_OEM_MINUS
        0xBE => {
            if shift {
                '>'
            } else {
                '.'
            }
        } // VK_OEM_PERIOD
        0xBF => {
            if shift {
                '?'
            } else {
                '/'
            }
        } // VK_OEM_2
        0xC0 => {
            if shift {
                '~'
            } else {
                '`'
            }
        } // VK_OEM_3
        0xDB => {
            if shift {
                '{'
            } else {
                '['
            }
        } // VK_OEM_4
        0xDC => {
            if shift {
                '|'
            } else {
                '\\'
            }
        } // VK_OEM_5
        0xDD => {
            if shift {
                '}'
            } else {
                ']'
            }
        } // VK_OEM_6
        0xDE => {
            if shift {
                '"'
            } else {
                '\''
            }
        } // VK_OEM_7
        // Control characters
        0x08 => '\x08', // VK_BACK
        0x09 => '\t',   // VK_TAB
        0x0D => '\r',   // VK_RETURN
        0x20 => ' ',    // VK_SPACE
        // Numpad digits
        0x60 => '0',
        0x61 => '1',
        0x62 => '2',
        0x63 => '3',
        0x64 => '4',
        0x65 => '5',
        0x66 => '6',
        0x67 => '7',
        0x68 => '8',
        0x69 => '9',
        0x6A => '*',      // VK_MULTIPLY
        0x6B => '+',      // VK_ADD
        0x6D => '-',      // VK_SUBTRACT
        0x6E => '.',      // VK_DECIMAL
        0x6F => '/',      // VK_DIVIDE
        _ => return None, // non-printable: function keys, modifiers, arrows, etc.
    };
    Some(ch)
}

/// TranslateMessage: translate WM_KEYDOWN messages to WM_CHAR.
///
/// For each WM_KEYDOWN with a printable character, posts a corresponding
/// WM_CHAR to the message queue. Returns TRUE if the message was translated.
///
/// # Safety
/// `lp_msg` must point to a valid `MSG`.
// Wine ref: dlls/user32/message.c::TranslateMessage — calls NtUserTranslateMessage which
// uses the thread keyboard layout to convert WM_KEYDOWN to WM_CHAR/WM_DEADCHAR; returns
// TRUE for WM_KEYDOWN/WM_KEYUP/WM_SYSKEYDOWN/WM_SYSKEYUP regardless of translation result.
pub unsafe extern "win64" fn translate_message(lp_msg: *const Msg) -> i32 {
    if lp_msg.is_null() {
        return 0;
    }
    let msg = unsafe { &*lp_msg };
    if msg.message != WM_KEYDOWN {
        return (msg.message == WM_KEYUP || msg.message == WM_CHAR) as i32;
    }
    // msg.w_param holds the Win32 VK code (set by backend::x11_keycode_to_vk).
    // X11 modifier state is stored in msg.l_param bits 16–31; ShiftMask = bit 16.
    let shift = ((msg.l_param >> 16) & 0x0001) != 0;
    if let Some(ch) = vk_to_char(msg.w_param, shift) {
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
// Wine ref: dlls/user32/message.c::dispatch_message — calls NtUserMessageCall to get dispatch
// params then dispatch_win_proc_params; WM_QUIT is never dispatched to a WNDPROC.
pub unsafe extern "win64" fn dispatch_message_w(lp_msg: *const Msg) -> isize {
    if lp_msg.is_null() {
        return 0;
    }
    let m = unsafe { &*lp_msg };

    // WM_QUIT is never dispatched to a WNDPROC.
    if m.message == WM_QUIT {
        return 0;
    }

    // Fire phase marker before the HWND table lookup.  Previously the marker
    // was placed after the lookup, so any WM_PAINT dispatched for an HWND that
    // had already been removed from the table (e.g. a child window destroyed
    // between queue-post and dispatch) caused an early return that silently
    // swallowed the marker.  Moving it here ensures we record the first
    // WM_PAINT that reaches DispatchMessageW regardless of HWND validity.
    if m.message == WM_PAINT && !PHASE_WM_PAINT_DISPATCHED.swap(true, Ordering::Relaxed) {
        mark_phase("wm_paint_dispatched_first");
    }

    let proc_addr = match window::with(m.hwnd, |e| e.wnd_proc) {
        Some(p) => p,
        None => {
            if m.message == WM_PAINT {
                eprintln!(
                    "weave/DispatchMessageW: WM_PAINT hwnd={:#x} not in window table — skipped",
                    m.hwnd
                );
            }
            return 0;
        }
    };

    call_wnd_proc(proc_addr, m.hwnd, m.message, m.w_param, m.l_param)
}

// ── PostQuitMessage ───────────────────────────────────────────────────────────

/// PostQuitMessage: post a WM_QUIT message to the calling thread's message queue.
///
/// Wine ref: dlls/win32u/message.c:3986 — sends post_quit_message server request with
/// exit_code as wParam; WM_QUIT is thread-local and not associated with any window (hwnd=0).
///
/// `n_exit_code` becomes the wParam of the WM_QUIT message.
pub extern "win64" fn post_quit_message(n_exit_code: i32) {
    eprintln!("weave/user32: PostQuitMessage({n_exit_code})");
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
/// Wine ref: server/queue.c::post_message — appends message to queue; returns TRUE if the
/// window exists. HWND_BROADCAST (0xFFFF) posts to all top-level windows (not implemented).
///
/// Returns TRUE on success.
pub extern "win64" fn post_message_w(hwnd: usize, msg: u32, w_param: usize, l_param: isize) -> i32 {
    // Log WM_USER+ messages (>= 0x0400 = 1024) — these are app-defined messages, often
    // used by NPP to schedule operations like file loading.
    if msg >= 0x0400 {
        eprintln!(
            "weave/user32: PostMessageW hwnd={hwnd:#x} msg={msg} wp={w_param:#x} lp={l_param:#x}"
        );
    }
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
/// Wine ref: dlls/win32u/message.c::send_window_message — sets up send_message_info with
/// MSG_UNICODE type and calls process_message; blocks until WNDPROC returns. For cross-thread
/// sends, Wine uses a server round-trip; Weave calls the WNDPROC directly (single-threaded).
///
/// Blocks until the WNDPROC returns.
pub extern "win64" fn send_message_w(
    hwnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    if msg == 2006 && !PHASE_SCI_GETLENGTH.swap(true, Ordering::Relaxed) {
        mark_phase("sci_getlength_probed");
    }
    let proc_addr = match window::with(hwnd, |e| e.wnd_proc) {
        Some(p) => p,
        None => {
            if (2000..=3000).contains(&msg) {
                eprintln!("weave/user32: SendMessageW hwnd={hwnd:#x} msg={msg} → 0 (no wndproc)");
            }
            return 0;
        }
    };
    // SCI_GETDOCPOINTER (2268=0x08DC): Scintilla's WndProc in this NPP 8.9.3 build reads a
    // different field. Binary analysis confirmed pdoc is at sci+0x128. Read it directly.
    if msg == 2268 {
        let sci = get_extra(
            hwnd,
            |e| {
                if e.extra_bytes.len() >= 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&e.extra_bytes[0..8]);
                    usize::from_ne_bytes(buf)
                } else {
                    0
                }
            },
            0_usize,
        );
        if sci >= 0x0000_1000_0000_0000 {
            let pdoc = unsafe { *(sci as *const usize).add(37) }; // sci+0x128
            eprintln!(
                "weave/user32: SendMessageW SCI_GETDOCPOINTER hwnd={hwnd:#x} sci={sci:#x} → pdoc={pdoc:#x}"
            );
            return pdoc as isize;
        }
    }

    let seq = SEND_MSG_SEQ.fetch_add(1, Ordering::Relaxed);
    let cur_tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    let (owner_tid, class_name) =
        window::with(hwnd, |e| (e.tid, e.class_name.clone())).unwrap_or((0, String::new()));
    let cross_thread = owner_tid != 0 && cur_tid != owner_tid;
    eprintln!(
        "weave/user32: SendMessageW enter seq={seq} tid={cur_tid} hwnd={hwnd:#x} owner_tid={owner_tid} cross_thread={cross_thread} class={class_name:?} msg={msg:#06x} wp={w_param:#x} lp={l_param:#x} wndproc={proc_addr:#x}"
    );
    let ret = call_wnd_proc(proc_addr, hwnd, msg, w_param, l_param);
    // Intercept SCI_GETDIRECTSTATUSFUNCTION (2184): return our proxy instead of the real fn ptr.
    // SCI_GETDIRECTSTATUSFUNCTION returns a 5-param fn: (sci, msg, wp, lp, *status) -> iptr.
    // The proxy logs all SCI calls and fixes SCI_GETDOCPOINTER to read pdoc from sci+0x128.
    if msg == 2184 && ret != 0 {
        // Store the real SciFnDirectStatus address, return our 5-param proxy instead.
        SCI_REAL_DIRECT_FN.store(ret as usize, std::sync::atomic::Ordering::Relaxed);
        SCI_DIRECT_FN.store(
            sci_direct_fn_proxy as *const () as usize,
            std::sync::atomic::Ordering::Relaxed,
        );
        let proxy_addr = sci_direct_fn_proxy as *const () as usize as isize;
        eprintln!(
            "weave/user32: SendMessageW hwnd={hwnd:#x} msg={msg:#06x}(SCI_GETDIRECTSTATUSFUNCTION) real_fn={ret:#x} proxy={proxy_addr:#x}"
        );
        return proxy_addr;
    }
    if msg == 2185 && ret != 0 {
        SCI_DIRECT_PTR.store(ret as usize, std::sync::atomic::Ordering::Relaxed);
    }
    eprintln!(
        "weave/user32: SendMessageW exit seq={seq} tid={cur_tid} hwnd={hwnd:#x} msg={msg:#06x} → {ret:#x}"
    );
    ret
}

/// Stored Scintilla direct function pointer (proxy address, not the real one).
static SCI_DIRECT_FN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Real Scintilla_DirectFunction address (from the PE binary).
static SCI_REAL_DIRECT_FN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Stored Scintilla direct pointer / sci* (SCI_GETDIRECTPOINTER result).
static SCI_DIRECT_PTR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Tracks the sci pointer that received SCI_SETDOCPOINTER(NULL) = the main editor sci.
/// Required for the forced doc transfer in sci_direct_fn_proxy.
static MAIN_EDITOR_SCI: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Deferred SCI_SETTEXT: target sci and text buffer to apply from get_message_w after WM_PAINT.
/// Calling any SCI message re-entrantly from inside the proxy causes NPP notification crashes.
/// Instead, we copy scratch's text here and apply it from the message-loop context.
static PENDING_DOC_SCI: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PENDING_DOC_PTR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Heap-allocated copy of file content to apply via SCI_SETTEXT from get_message_w.
/// Raw pointer to a null-terminated Vec<u8> owned by Weave. Set once, freed after use.
static PENDING_TEXT_BUF: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Proxy for SciFnDirectStatus — logs all SCI messages and intercepts SCI_GETDOCPOINTER.
/// NPP calls this instead of SciFnDirectStatus after we intercept SCI_GETDIRECTSTATUSFUNCTION.
/// Matches the 5-param SciFnDirectStatus signature: (sci, msg, wp, lp, *status) -> iptr.
///
/// # Safety
/// `p_status` is passed through to the real Scintilla function; caller must ensure it
/// is null or points to a valid bool-sized location (as guaranteed by NPP's Scintilla bindings).
pub unsafe extern "win64" fn sci_direct_fn_proxy(
    sci: usize,
    msg: u32,
    wparam: usize,
    lparam: isize,
    p_status: *mut u8,
) -> isize {
    let real_fn = SCI_REAL_DIRECT_FN.load(std::sync::atomic::Ordering::Relaxed);
    // SciFnDirectStatus: (usize, u32, usize, isize, *mut u8) -> isize
    let f: unsafe extern "win64" fn(usize, u32, usize, isize, *mut u8) -> isize =
        unsafe { std::mem::transmute(real_fn) };

    let msg_name = match msg {
        2001 => "SCI_ADDTEXT",
        2003 => "SCI_INSERTTEXT",
        2004 => "SCI_CLEARALL",
        2006 => "SCI_GETLENGTH",
        2009 => "SCI_SETTEXT",
        2037 => "SCI_SETDOCPOINTER",
        2046 => "SCI_SETREADONLY",
        2182 => "SCI_GETDIRECTFUNCTION",
        2183 => "SCI_GETDIRECTPOINTER",
        2184 => "SCI_GETDIRECTSTATUSFUNCTION",
        2268 => "SCI_GETDOCPOINTER",
        2276 => "SCI_CREATEDOCUMENT",
        2282 => "SCI_APPENDTEXT",
        2007 => "SCI_GETCHARACTERPOINTER",
        _ => "",
    };
    if !msg_name.is_empty() || (2000..=3000).contains(&msg) {
        eprintln!(
            "weave/sci_proxy: msg={msg}({}) sci={sci:#x} wp={wparam:#x} lp={lparam:#x} real_fn={real_fn:#x}",
            if msg_name.is_empty() { "?" } else { msg_name }
        );
    }

    // Track main editor sci (first sci to receive SCI_SETDOCPOINTER=NULL, msg=2269, lp=0).
    // Required for the forced doc transfer below.
    if msg == 2269 && lparam == 0 && MAIN_EDITOR_SCI.load(std::sync::atomic::Ordering::Relaxed) == 0
    {
        MAIN_EDITOR_SCI.store(sci, std::sync::atomic::Ordering::Relaxed);
    }

    // SCI_GETDOCPOINTER (2268): Scintilla's WndProc in this NPP 8.9.3 build reads a different
    // field than pdoc. Binary analysis confirmed pdoc is at sci+0x128 (offset 37 * 8).
    // RVAs 0x2626bb and 0x2634f1 both dereference [sci+0x128] for the document pointer.
    if msg == 2268 && sci >= 0x0000_1000_0000_0000 {
        let pdoc = unsafe { *(sci as *const usize).add(37) }; // sci+0x128
        return pdoc as isize;
    }

    // msg=2358 = SCI_SETDOCPOINTER in NPP 8.9.3's Scintilla (writes to sci+0x128).
    // NPP calls this on scratch to set up document sharing, but never calls it on the main
    // editor to transfer the loaded document. We intercept here: when scratch is about to be
    // reset to a new empty doc (lparam = new_empty_doc) and scratch currently has content,
    // first transfer scratch's current doc (with file bytes) to the main editor, then let
    // scratch reset normally.
    if msg == 2358 {
        let main_sci = MAIN_EDITOR_SCI.load(std::sync::atomic::Ordering::Relaxed);
        if main_sci != 0 && sci != main_sci && sci >= 0x0000_1000_0000_0000 {
            // Read scratch's CURRENT pdoc (before this msg=2358 replaces it).
            let scratch_pdoc = unsafe { *(sci as *const usize).add(37) }; // sci+0x128
            let scratch_len_dbg = if scratch_pdoc != 0 {
                unsafe { f(sci, 2006, 0, 0, std::ptr::null_mut()) }
            } else {
                -99
            };
            let main_len_dbg = unsafe { f(main_sci, 2006, 0, 0, std::ptr::null_mut()) };
            eprintln!("weave/sci_proxy: msg=2358 debug: scratch_pdoc={scratch_pdoc:#x} scratch_len={scratch_len_dbg} main_len={main_len_dbg}");
            if scratch_pdoc != 0 {
                // Check if scratch has content worth transferring.
                let scratch_len = scratch_len_dbg;
                // Check if main is currently empty (avoid overwriting user edits).
                let main_len = main_len_dbg;
                if scratch_len > 0 && main_len == 0 {
                    // Use the text pointer saved from SCI_APPENDTEXT (PENDING_DOC_PTR).
                    // SCI_GETCHARACTERPOINTER returns 0 in this build (wrong msg number).
                    let saved_text_ptr = PENDING_DOC_PTR.load(std::sync::atomic::Ordering::Relaxed);
                    if saved_text_ptr != 0 {
                        let text_slice = unsafe {
                            std::slice::from_raw_parts(
                                saved_text_ptr as *const u8,
                                scratch_len as usize,
                            )
                        };
                        let mut buf = text_slice.to_vec();
                        buf.push(0); // null-terminate for SCI_SETTEXT
                        let buf_ptr = Box::into_raw(buf.into_boxed_slice()) as *mut u8 as usize;
                        PENDING_TEXT_BUF.store(buf_ptr, std::sync::atomic::Ordering::Relaxed);
                        PENDING_DOC_SCI.store(main_sci, std::sync::atomic::Ordering::Relaxed);
                        PENDING_DOC_PTR.store(0, std::sync::atomic::Ordering::Relaxed);
                        eprintln!(
                            "weave/sci_proxy: text captured for deferred SCI_SETTEXT: \
                             scratch={sci:#x} len={scratch_len} → main={main_sci:#x}"
                        );
                    }
                }
            }
        }
    }

    let ret = unsafe { f(sci, msg, wparam, lparam, p_status) };

    if !msg_name.is_empty() || (2000..=3000).contains(&msg) {
        // SCI_SETREADONLY (2046): log ret and wParam only — do NOT dereference p_status.
        // p_status is not a valid output pointer for SCI_SETREADONLY; dereferencing it
        // caused a SIGSEGV on the VM when p_status was non-null but unmapped.
        if msg == 2046 {
            eprintln!(
                "weave/sci_proxy:   → ret={ret:#x} readonly_set={} (SCI_SETREADONLY)",
                wparam != 0,
            );
        } else {
            eprintln!("weave/sci_proxy:   → {ret:#x}");
        }
    }

    // Save lparam from SCI_APPENDTEXT for the msg=2358 handler's text copy.
    if msg == 2282 /*SCI_APPENDTEXT*/ && lparam != 0 && wparam > 0 {
        PENDING_DOC_PTR.store(lparam as usize, std::sync::atomic::Ordering::Relaxed);
    }

    ret
}

/// SendMessageTimeoutW: send a message to a window with a timeout.
///
// Wine ref: dlls/user32/message.c::SendMessageTimeoutW — calls NtUserMessageCall with
// NtUserSendMessageTimeout; stores message result in *res_ptr; returns params.result
// (non-zero = success, 0 = timeout or error). For single-process in-process WndProc
// calls the timeout never fires — dispatch is synchronous. Weave calls send_message_w
// directly and always succeeds.
///
/// # Safety
/// `lpdw_result` may be null; if non-null must be a valid writable `usize`-sized location.
pub unsafe extern "win64" fn send_message_timeout_w(
    h_wnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
    _fu_flags: u32,
    _u_timeout: u32,
    lpdw_result: *mut usize,
) -> isize {
    let result = send_message_w(h_wnd, msg, w_param, l_param);
    if !lpdw_result.is_null() {
        *lpdw_result = result as usize;
    }
    1 // non-zero = success (no timeout)
}

// ── DefWindowProcW ────────────────────────────────────────────────────────────

/// DefWindowProcW: default message handling for messages the application does not process.
///
/// Wine ref: dlls/win32u/defwnd.c — WM_CLOSE calls NtUserDestroyWindow; WM_DESTROY does NOT
/// post WM_QUIT unless this is the last top-level window (Weave simplifies: always posts quit).
/// WM_NCCREATE returns TRUE to allow window creation to proceed. WM_NCHITTEST returns HTCLIENT.
/// WM_PAINT: calls BeginPaint/EndPaint to validate the update region.
/// WM_SIZE: Wine ref: dlls/win32u/defwnd.c — DefWindowProc does not handle WM_SIZE; it is sent
///   by the window manager to the app WNDPROC after a resize. We return 0 (no-op).
/// WM_SETTEXT: stores text as window title (Wine: defwnd.c::DefWndSetText — calls
///   NtUserDefSetText which updates the window text in the window object).
/// WM_GETTEXT: copies window title into buffer (Wine: defwnd.c — NtUserInternalGetWindowText).
/// WM_GETTEXTLENGTH: returns title length in UTF-16 code units.
/// TODO Wine ref gap: WM_DESTROY should only PostQuitMessage for last top-level window.
// Wine ref: dlls/win32u/defwnd.c::DefWindowProcW — dispatches ~30 default message handlers;
// WM_NCCREATE sets WS_EX_CLIENTEDGE; WM_SETTEXT calls NtUserDefSetText; WM_CLOSE calls DestroyWindow.
pub extern "win64" fn def_window_proc_w(
    hwnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    match msg {
        WM_CLOSE => {
            eprintln!("weave/user32: DefWindowProcW WM_CLOSE hwnd={hwnd:#x} → DestroyWindow");
            destroy_window(hwnd);
            0
        }
        WM_DESTROY => {
            // Wine ref: dlls/win32u/defwnd.c — DefWindowProcW does NOT call
            // PostQuitMessage for WM_DESTROY; that is the application's responsibility
            // (typically done in WM_DESTROY of the main window). Posting WM_QUIT here
            // breaks SDL2 which creates/destroys multiple test windows during renderer
            // selection and expects WM_DESTROY to be silent in DefWindowProc.
            eprintln!("weave/user32: DefWindowProcW WM_DESTROY hwnd={hwnd:#x} (no-op — app must PostQuitMessage)");
            0
        }
        WM_PAINT => {
            // Validate the update region without drawing.
            0
        }
        // Wine ref: dlls/win32u/defwnd.c — WM_SIZE is dispatched by the window manager to the
        // app WNDPROC; DefWindowProc itself takes no action and returns 0.
        WM_SIZE => 0,
        WM_NCCREATE => 1,  // non-zero = proceed with window creation
        WM_NCHITTEST => 1, // HTCLIENT (1) — all hits are in client area
        WM_SETTEXT => {
            // Wine ref: dlls/win32u/defwnd.c — DefWndSetText stores text in window object
            // title field; SetWindowTextW internally sends this message.
            let text = unsafe { decode_wide(l_param as *const u16) };
            let xcb = window::xcb_id(hwnd);
            window::with_mut(hwnd, |e| e.title = text.clone());
            backend::set_title(xcb, &text);
            1 // TRUE
        }
        WM_GETTEXT => {
            // Wine ref: dlls/win32u/defwnd.c — NtUserInternalGetWindowText; wParam=max count,
            // lParam=LPWSTR buffer. Returns number of chars copied (excl. null terminator).
            let max_count = w_param;
            if max_count == 0 || l_param == 0 {
                return 0;
            }
            let title = window::with(hwnd, |e| e.title.clone()).unwrap_or_default();
            let wide: Vec<u16> = title.encode_utf16().collect();
            let dst = l_param as *mut u16;
            let copy_len = wide.len().min(max_count.saturating_sub(1));
            unsafe {
                for (i, &cu) in wide[..copy_len].iter().enumerate() {
                    *dst.add(i) = cu;
                }
                *dst.add(copy_len) = 0;
            }
            copy_len as isize
        }
        WM_GETTEXTLENGTH => {
            // Wine ref: dlls/win32u/defwnd.c — returns lstrlenW of window title.
            window::with(hwnd, |e| e.title.encode_utf16().count()).unwrap_or(0) as isize
        }
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
// Wine ref: dlls/win32u/window.c::get_client_rect — calls get_client_rect_rel with
// COORDS_CLIENT; origin is always (0,0) in client coords; right/bottom = client size.
pub unsafe extern "win64" fn get_client_rect(hwnd: usize, lp_rect: *mut Rect) -> i32 {
    eprintln!("weave/user32: GetClientRect hwnd={hwnd:#x}");
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
// Wine ref: dlls/win32u/window.c::get_window_rect — calls get_window_rect_rel with
// COORDS_SCREEN; includes non-client area (frame + caption); returns screen coordinates.
pub unsafe extern "win64" fn get_window_rect(hwnd: usize, lp_rect: *mut Rect) -> i32 {
    eprintln!("weave/user32: GetWindowRect hwnd={hwnd:#x}");
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

/// GetUpdateRect: return the bounding rect of the current update region.
///
/// Wine ref: dlls/win32u/painting.c::NtUserGetUpdateRect — returns the smallest
/// bounding rect of the window's update region; fills *lprect and returns TRUE if
/// the region is non-empty, FALSE if it is empty.
///
/// Weave has no per-pixel update region tracking (Phase 2 gap). We always report
/// the full client rect as dirty so Scintilla/other WM_PAINT handlers paint the
/// full window rather than skipping on an empty region.
///
/// # Safety
/// `lp_rect` must point to a `RECT`-sized buffer or be null.
// Wine ref: dlls/win32u/painting.c::NtUserGetUpdateRect — returns bounding rect of update
// region; TRUE if region non-empty; bErase TRUE triggers WM_ERASEBKGND before returning.
pub unsafe extern "win64" fn get_update_rect(
    hwnd: usize,
    lp_rect: *mut Rect,
    _b_erase: i32,
) -> i32 {
    // If ValidateRect was called for this hwnd and no new InvalidateRect has
    // arrived since, report an empty update region (return FALSE).
    if validated_hwnds().lock().unwrap().contains(&hwnd) {
        if !lp_rect.is_null() {
            unsafe {
                (*lp_rect).left = 0;
                (*lp_rect).top = 0;
                (*lp_rect).right = 0;
                (*lp_rect).bottom = 0;
            }
        }
        return 0;
    }
    let (w, h) = window::with(hwnd, |e| (e.width, e.height)).unwrap_or((0, 0));
    if !lp_rect.is_null() {
        unsafe {
            (*lp_rect).left = 0;
            (*lp_rect).top = 0;
            (*lp_rect).right = w as i32;
            (*lp_rect).bottom = h as i32;
        }
    }
    if w == 0 || h == 0 {
        0
    } else {
        1
    }
}

/// InvalidateRect: mark a region of a window as needing repaint.
///
/// Phase 2: posts WM_PAINT to the message queue.
///
/// # Safety
/// `lp_rect` may be null (means invalidate entire client area).
// Wine ref: dlls/win32u/painting.c::NtUserInvalidateRect — adds rect (or entire client area
// if NULL) to the window's update region; posts WM_PAINT if region transitions from empty.
pub unsafe extern "win64" fn invalidate_rect(
    hwnd: usize,
    _lp_rect: *const Rect,
    _b_erase: i32,
) -> i32 {
    if window::with(hwnd, |_| ()).is_some() {
        // Coalesce: only post WM_PAINT if one is not already queued for this hwnd.
        // In Windows, multiple InvalidateRect calls before the next GetMessage are
        // merged into a single WM_PAINT. Posting duplicates floods the queue and
        // can cause Scintilla to paint before document state is settled.
        // Wine ref: dlls/win32u/painting.c::NtUserInvalidateRect — adds to update
        // region; WM_PAINT is generated lazily on next GetMessage, not posted directly.
        let already_queued = queue::has_paint_for(hwnd);
        {
            static INV: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = INV.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n < 30 {
                eprintln!(
                    "weave/user32: InvalidateRect hwnd={hwnd:#x} already_queued={already_queued}"
                );
            }
        }
        // A new invalidation means the window is dirty again — remove from the
        // validated set so that GetUpdateRect returns non-empty.
        validated_hwnds().lock().unwrap().remove(&hwnd);
        if !already_queued {
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
    } else {
        eprintln!("weave/user32: InvalidateRect hwnd={hwnd:#x} — window not found");
        0
    }
}

/// ValidateRect: remove a rectangle (or the whole window if NULL) from a
/// window's update region. With no client-side region tracking today, this is
/// a logical no-op — InvalidateRect posts WM_PAINT directly and BeginPaint
/// clears the dirty state. Returning TRUE matches the Win32 success contract
/// so callers don't take a failure branch.
///
/// # Safety
/// `_lp_rect` (if non-null) must point to a valid `Rect`.
// Wine ref: dlls/win32u/painting.c::NtUserValidateRect — subtracts the rect
// from the update region (or clears it if rect == NULL); cancels any pending
// WM_PAINT for the validated area. Real region tracking is M6+ work; for now
// a TRUE return prevents the caller-derefs-uninit-rax crash class.
pub unsafe extern "win64" fn validate_rect(hwnd: usize, _lp_rect: *const Rect) -> i32 {
    // Mark the hwnd as validated so GetUpdateRect returns FALSE until the next
    // InvalidateRect call arrives.
    // Wine ref: dlls/win32u/painting.c::NtUserValidateRect — subtracts rect from
    // update region (or clears entirely when rect==NULL); cancels pending WM_PAINT
    // for the validated area. We clear the whole pending-paint flag for now (no
    // per-rect region math) which is correct for the NULL case and good-enough for
    // the rect case (95 % of callers pass NULL to ack the paint).
    validated_hwnds().lock().unwrap().insert(hwnd);
    1
}

/// CopyImage: duplicate an HICON / HCURSOR / HBITMAP. Returns a new handle
/// referencing the same underlying resource bytes (which live for the
/// originating module's lifetime — same invariant `LoadImageW` relies on).
///
/// Honoured flags:
/// * `LR_COPYRETURNORG` (0x0004) — return the source handle unchanged. Wine
///   does this when no transformation is requested.
/// * `LR_COPYDELETEORG` (0x0008) — would delete the source after copy. We
///   ignore (no destruction path on shared handles); worst case a guest leaks
///   one slot, never a crash.
///
/// `cx`/`cy` size hints are ignored; we don't rescale yet.
///
/// # Safety
/// `h_image` should be a handle previously returned by `LoadImageW` /
/// `LoadIconW` / `LoadCursorW` / `LoadBitmapW`. Unknown handles are returned
/// as-is rather than producing NULL — callers that ignored the load return
/// then re-fed garbage are no worse off than before.
// Wine ref: dlls/user32/cursoricon.c::CopyImage — for HICON/HCURSOR delegates
// to CopyIcon (NtUserCopyImage path); for HBITMAP creates a new DIB with the
// same bits via CreateDIBSection. Our shallow-clone matches the behavioral
// shape callers rely on (distinct handle, same pixels) without needing a
// pixel-buffer copy that would never be observed differently in Weave.
pub unsafe extern "win64" fn copy_image(
    h_image: usize,
    _u_type: u32,
    _cx: i32,
    _cy: i32,
    fu_flags: u32,
) -> usize {
    use crate::image_handles as ih;
    const LR_COPYRETURNORG: u32 = 0x0004;
    if fu_flags & LR_COPYRETURNORG != 0 {
        return h_image;
    }
    let entry = match ih::get(h_image) {
        Some(e) => e,
        None => return h_image, // unknown — pass-through is safer than NULL
    };
    let mut dup = entry.clone();
    dup.shared = false; // copies are never LR_SHARED per Win32 contract
    ih::insert(dup, None)
}

// ── Window title ──────────────────────────────────────────────────────────────

/// SetWindowTextW: update the title bar text of a window.
///
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-16 string.
// Wine ref: server/window.c::set_window_text handler — stores text in server-side window
// object; also calls X11DRV_SetWindowText (dlls/winex11.drv/window.c:2562) to update title.
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
// Wine ref: server/window.c::get_window_text handler — reads text stored in server window
// object; NtUserInternalGetWindowText returns char count excluding null terminator.
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
// Wine ref: dlls/win32u/painting.c::NtUserBeginPaint — validates the update region by clearing
// the WM_PAINT pending flag; returns an HDC clipped to the update region; sets fErase if the
// background was erased. Weave returns hwnd as a fake HDC (Phase 2 gap: no real DC or region).
pub unsafe extern "win64" fn begin_paint(hwnd: usize, lp_paint: *mut PaintStruct) -> usize {
    CURRENT_PAINT_HWND.store(hwnd, Ordering::Relaxed);
    // Query SCI_GETLENGTH (2006) for Scintilla windows to check document state at paint time.
    // Use a Scintilla-only counter so non-Scintilla BeginPaint calls don't consume slots.
    // Each Scintilla HWND gets its own probe via SCI_GETDIRECTPOINTER to avoid
    // the stale SCI_DIRECT_PTR bug (which always pointed to the secondary Scintilla).
    {
        let is_sci = window::with(hwnd, |e| e.class_name == "Scintilla").unwrap_or(false);
        if is_sci {
            static BP_SCI: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = BP_SCI.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Log every Scintilla paint for the first 40 (covers startup + first repaint after
            // text load), then every 10th to avoid drowning the log during long sessions.
            if n < 40 || n.is_multiple_of(10) {
                let doc_len = send_message_w(hwnd, 2006, 0, 0); // SCI_GETLENGTH via WndProc
                let xcb = window::xcb_id(hwnd);
                // Capture wnd_proc to detect NPP subclassing — if NPP replaced Scintilla's
                // WndProc the stored proc won't handle SCI_GETDIRECTPOINTER, and both
                // doc_len and direct_len will be 0 via the SendMessage path.
                let wnd_proc = window::with(hwnd, |e| e.wnd_proc).unwrap_or(0);
                // Also read extra[0] directly (bypassing the WndProc) to show the real sci*.
                let extra0 = get_extra(
                    hwnd,
                    |e| {
                        if e.extra_bytes.len() >= 8 {
                            let mut buf = [0u8; 8];
                            buf.copy_from_slice(&e.extra_bytes[0..8]);
                            isize::from_ne_bytes(buf)
                        } else {
                            -3 // extra_bytes too small
                        }
                    },
                    -4,
                ); // hwnd not in extra map
                   // Call SCI_GETDIRECTPOINTER on THIS window to get the per-window sci* pointer,
                   // then call SCI_GETLENGTH directly to cross-check the WndProc result.
                   // This avoids the stale SCI_DIRECT_PTR bug where the global ptr pointed to
                   // the secondary (always-empty) Scintilla.
                let direct_fn = SCI_REAL_DIRECT_FN.load(std::sync::atomic::Ordering::Relaxed);
                // SCI_REAL_DIRECT_FN holds SciFnDirectStatus (5-param: sci,msg,wp,lp,*status).
                // Pass a null status pointer — we only care about the return value here.
                let direct_len = if direct_fn != 0 {
                    let this_sci_ptr = send_message_w(hwnd, 2185, 0, 0); // SCI_GETDIRECTPOINTER
                    if this_sci_ptr != 0 {
                        type DirectFn =
                            unsafe extern "win64" fn(usize, u32, usize, isize, *mut u8) -> isize;
                        let f: DirectFn = unsafe { std::mem::transmute(direct_fn) };
                        unsafe { f(this_sci_ptr as usize, 2006, 0, 0, std::ptr::null_mut()) }
                    } else {
                        -2 // SCI_GETDIRECTPOINTER returned 0
                    }
                } else {
                    -1 // no real direct fn captured yet
                };
                // If extra[0] is non-zero but SCI_GETDIRECTPOINTER returns 0, the WndProc was
                // subclassed and the new proc doesn't forward SCI queries to Scintilla.
                // In that case, use extra[0] directly as the sci* for the direct_len probe.
                let (direct_len_via_extra, doc_ptr_via_extra) = if direct_fn != 0 && extra0 > 0 {
                    type DirectFn =
                        unsafe extern "win64" fn(usize, u32, usize, isize, *mut u8) -> isize;
                    let f: DirectFn = unsafe { std::mem::transmute(direct_fn) };
                    let len = unsafe { f(extra0 as usize, 2006, 0, 0, std::ptr::null_mut()) };
                    let doc_ptr = unsafe { f(extra0 as usize, 2268, 0, 0, std::ptr::null_mut()) };
                    eprintln!(
                        "weave/user32: BeginPaint direct_len_via_extra query \
                         sci={extra0:#x} SCI_GETLENGTH → ret={len:#x} ({len}) \
                         SCI_GETDOCPOINTER → doc_ptr={doc_ptr:#x}"
                    );
                    (len, doc_ptr)
                } else {
                    (-1, -1)
                };
                eprintln!(
                    "weave/user32: BeginPaint Scintilla hwnd={hwnd:#x} xcb={xcb:#x} sci_paint#{n} \
                     wnd_proc={wnd_proc:#x} extra0={extra0:#x} \
                     SCI_GETLENGTH={doc_len} direct_len={direct_len} \
                     direct_len_via_extra={direct_len_via_extra} \
                     doc_ptr={doc_ptr_via_extra:#x}"
                );
            }
        }
    }
    if !lp_paint.is_null() {
        unsafe {
            let ps = &mut *lp_paint;
            ps.hdc = hwnd; // fake HDC for now
            ps.f_erase = 1;
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
// Wine ref: dlls/win32u/painting.c::NtUserEndPaint — releases the HDC obtained in BeginPaint,
// calls validate_window to clear the update region; always returns TRUE.
pub unsafe extern "win64" fn end_paint(hwnd: usize, _lp_paint: *const PaintStruct) -> i32 {
    // Wine ref: dlls/win32u/painting.c::NtUserEndPaint — releases HDC from BeginPaint,
    // calls validate_window (ValidateRect(hwnd, NULL)) to clear the update region.
    // Weave: clear CURRENT_PAINT_HWND so gdi32::create_compatible_dc does not route
    // subsequent GDI calls to a stale paint target after the paint cycle ends.
    // ps.hdc == hwnd (fake HDC) — no real DC resource to release.
    let _ = hwnd;
    CURRENT_PAINT_HWND.store(0, Ordering::Relaxed);
    1 // TRUE — Wine always returns TRUE
}

// ── System metrics ────────────────────────────────────────────────────────────

/// GetSystemMetrics: return various system dimension/capability values.
///
/// Wine ref: dlls/win32u/sysparams.c::get_system_metrics — SM_CXSCREEN/SM_CYSCREEN from
/// primary monitor rect; SM_CXBORDER/SM_CYBORDER always 1 ("regardless of BorderWidth in
/// registry"); SM_CXEDGE/SM_CYEDGE = SM_CXBORDER+1 = 2; SM_CXFRAME/SM_CYFRAME =
/// SM_CXDLGFRAME(3) + max(border,1) = 4; SM_CXICON/SM_CYICON = map_to_dpi(32,...).
/// Scrollbar dims from entry_SCROLLWIDTH/SCROLLHEIGHT (max(val,8)); Wine default 17.
/// Small icons map_to_dpi(16,96) & ~1 = 16. Min window: CYMIN = CYCAPTION+2×CYFRAME.
pub extern "win64" fn get_system_metrics(n_index: i32) -> i32 {
    let (sw, sh) = backend::screen_size();
    match n_index {
        // ── screen / virtual screen ───────────────────────────────────────────
        SM_CXSCREEN => sw as i32,
        SM_CYSCREEN => sh as i32,
        SM_CXFULLSCREEN => sw as i32,
        SM_CYFULLSCREEN => sh as i32 - 40,
        SM_XVIRTUALSCREEN => 0,
        SM_YVIRTUALSCREEN => 0,
        SM_CXVIRTUALSCREEN => sw as i32,
        SM_CYVIRTUALSCREEN => sh as i32,
        // SM_CMONITORS: 1 only when a real display is available — IrfanView triggers
        // display hardware init on 1, corrupting the heap in headless Docker.
        80 => i32::from(backend::is_available()),
        SM_SAMEDISPLAYFORMAT => 1,

        // ── window border / frame ─────────────────────────────────────────────
        SM_CXBORDER | SM_CYBORDER => 1, // Wine: always 1 regardless of registry
        SM_CXEDGE | SM_CYEDGE => 2,     // SM_CXBORDER + 1
        SM_CXDLGFRAME | SM_CYDLGFRAME => 3,
        SM_CXFRAME | SM_CYFRAME => 4, // SM_CXDLGFRAME + max(border,1)
        SM_CXFOCUSBORDER | SM_CYFOCUSBORDER => 1,

        // ── caption / menu bars ───────────────────────────────────────────────
        SM_CYCAPTION => 23,   // iCaptionHeight(22) + 1
        SM_CYMENU => 20,      // iMenuHeight(19) + 1
        SM_CYSMCAPTION => 16, // iSmCaptionHeight(15) + 1

        // ── scrollbar dimensions ──────────────────────────────────────────────
        // Wine: max(entry_SCROLLWIDTH, 8); SCROLLWIDTH/HEIGHT default 17.
        SM_CXVSCROLL | SM_CYHSCROLL | SM_CYVSCROLL | SM_CXHSCROLL | SM_CYVTHUMB | SM_CXHTHUMB => 17,

        // ── icons / cursors ───────────────────────────────────────────────────
        SM_CXICON | SM_CYICON => 32, // map_to_dpi(32, 96dpi)
        SM_CXCURSOR | SM_CYCURSOR => 32,
        SM_CXSMICON | SM_CYSMICON => 16, // map_to_dpi(16, 96dpi) & ~1

        // ── caption / menu buttons ────────────────────────────────────────────
        SM_CXSIZE | SM_CYSIZE => 19,     // iCaptionWidth/Height from NCM
        SM_CXSMSIZE | SM_CYSMSIZE => 15, // iSmCaptionWidth/Height from NCM
        SM_CXMENUSIZE | SM_CYMENUSIZE => 19, // iMenuWidth/Height from NCM

        // ── minimum / maximized window sizes ─────────────────────────────────
        SM_CXMIN => 132, // typical: 3×cxCaption + cyCaption + 4×textW + 2×frame + 4
        SM_CYMIN => 31,  // SM_CYCAPTION(23) + 2×SM_CYFRAME(4) = 31
        SM_CXMINTRACK => 132,
        SM_CYMINTRACK => 31,
        SM_CXMINIMIZED => 160,           // mm.iWidth(154) + 6
        SM_CYMINIMIZED => 25,            // iCaptionHeight(19) + 6
        SM_CXMAXTRACK => sw as i32 + 12, // virtualW + 4 + 2×frame(4)
        SM_CYMAXTRACK => sh as i32 + 12,
        SM_CXMAXIMIZED => sw as i32 + 8,  // screen + 2×frame(4)
        SM_CYMAXIMIZED => sh as i32 + 46, // screen + 2×caption(23)

        // ── icon spacing ──────────────────────────────────────────────────────
        SM_CXICONSPACING | SM_CYICONSPACING => 75, // Wine default from ICONMETRICS

        // ── mouse / input ─────────────────────────────────────────────────────
        SM_MOUSEPRESENT => 1,
        SM_MOUSEWHEELPRESENT => 1,
        SM_CMOUSEBUTTONS => 3,
        SM_CXDOUBLECLK | SM_CYDOUBLECLK => 4, // entry_DOUBLECLKWIDTH/HEIGHT default 4
        SM_CXDRAG | SM_CYDRAG => 4,           // entry_DRAGWIDTH/HEIGHT default 4

        // ── menu check mark ───────────────────────────────────────────────────
        // Wine: ((tmHeight + tmExternalLeading + 1) / 2) * 2 - 1, or 13 when
        // tmHeight ≤ 0. At 96dpi with Segoe UI 11pt, 13 is the typical result.
        SM_CXMENUCHECK | SM_CYMENUCHECK => 13,

        // ── misc capability flags ─────────────────────────────────────────────
        SM_NETWORK => 3, // network present (Wine: FIXME, returns 3)

        // everything else defined to 0 by Wine (debug, swap, reserved, tablet, etc.)
        _ => {
            eprintln!("weave/user32: GetSystemMetrics({n_index}) → 0 (unhandled)");
            0
        }
    }
}

/// GetSystemMetricsForDpi: DPI-aware variant of GetSystemMetrics.
///
/// Wine ref: dlls/win32u/sysparams.c — same as GetSystemMetrics but scales
/// SM_CX*/SM_CY* values by (dpi / 96). Weave doesn't implement per-monitor
/// DPI scaling, so we ignore dpi and delegate to GetSystemMetrics.
pub extern "win64" fn get_system_metrics_for_dpi(n_index: i32, _dpi: u32) -> i32 {
    get_system_metrics(n_index)
}

// ── Cursor / Icon stubs ───────────────────────────────────────────────────────

// ── Image / icon / cursor loading ─────────────────────────────────────────────
//
// Task 10 — real RT_GROUP_ICON / RT_ICON / RT_GROUP_CURSOR / RT_CURSOR /
// RT_BITMAP lookup via `weave_core::resource::find_resource` +
// `weave_core::module_handles::base_of`. Handle table lives in
// `crate::image_handles`.
//
// Per repo CLAUDE.md "No DLL→DLL imports": we call into `weave-core`
// directly, NEVER into `weave-kernel32`. `weave-core` is a core crate, not
// a DLL crate, so that import is inside the allowed envelope.

// IMAGE_* types (winuser.h)
const IMAGE_BITMAP: u32 = 0;
const IMAGE_ICON: u32 = 1;
const IMAGE_CURSOR: u32 = 2;

// LR_* flags (subset used here).
const LR_DEFAULTSIZE: u32 = 0x0040;
const LR_SHARED: u32 = 0x8000;

// RT_* resource type ordinals (winuser.h).
const RT_CURSOR: u16 = 1;
const RT_BITMAP: u16 = 2;
const RT_ICON: u16 = 3;
const RT_GROUP_CURSOR: u16 = 12;
const RT_GROUP_ICON: u16 = 14;

// System metrics used as LR_DEFAULTSIZE defaults (winuser.h SM_*).
const DEFAULT_ICON_CX: i32 = 32;
const DEFAULT_ICON_CY: i32 = 32;
const DEFAULT_CURSOR_CX: i32 = 32;
const DEFAULT_CURSOR_CY: i32 = 32;

/// Translate a caller-supplied `name_ptr` into a `weave_core::resource::ResourceId`.
///
/// Wine macro (quoted): `IS_INTRESOURCE(x)` ≡ `(((ULONG_PTR)(x)) >> 16) == 0`.
/// Our `weave_core::resource` module encodes the same gate by exposing a
/// `ResourceId` enum; we never dereference `name_ptr` unless the high 48
/// bits are non-zero.
///
/// # Safety
/// If the high 48 bits of `name_ptr` are non-zero, the caller guarantees
/// `name_ptr` is a valid null-terminated UTF-16 string.
unsafe fn name_ptr_to_resource_id(name_ptr: usize) -> weave_core::resource::ResourceId {
    if name_ptr >> 16 == 0 {
        return weave_core::resource::ResourceId::Id(name_ptr as u16);
    }
    // SAFETY: caller contract above.
    let mut v: Vec<u16> = Vec::new();
    unsafe {
        let mut p = name_ptr as *const u16;
        for _ in 0..32_768 {
            let ch = *p;
            if ch == 0 {
                break;
            }
            v.push(ch);
            p = p.add(1);
        }
    }
    weave_core::resource::ResourceId::Name(v)
}

/// Resolve an image resource *blob* inside the loaded PE whose base is
/// `image_base`. Returns `(data_ptr, size)` of the raw resource payload.
fn locate_resource_bytes(
    image_base: usize,
    type_id: u16,
    name: weave_core::resource::ResourceId,
) -> Option<(usize, u32)> {
    let loc = weave_core::resource::find_resource(
        image_base,
        weave_core::resource::ResourceId::Id(type_id),
        name,
        0,
    )?;
    let data_ptr = image_base.checked_add(loc.data_rva as usize)?;
    Some((data_ptr, loc.size))
}

/// Walk a GRPICONDIR / GRPCURSORDIR blob and return `(nId, width, height,
/// bit_count)` of the entry best matching `(want_cx, want_cy)`. We implement
/// Wine's `CURSORICON_FindBestIconRes` / `FindBestCursorRes` simplification:
/// pick the entry whose `max(width,height)` is closest to the requested
/// size (ties broken by highest bit-depth).
///
/// GRPICONDIR layout:
///   u16 reserved, u16 type, u16 count
///   then `count` GRPICONDIRENTRY records (14 bytes each for icons):
///     u8 width, u8 height, u8 colorCount, u8 reserved,
///     u16 planes, u16 bitCount, u32 bytesInRes, u16 nId
/// GRPCURSORDIRENTRY differs: width/height are u16 (actual pixels * 1),
/// planes field repurposed as hotspot, bitCount as bitCount, then u32 size,
/// u16 nId. We only read `nId`/`width`/`height`/`bitCount` — same offsets
/// work well enough for resolution purposes as a first-pass picker.
fn pick_group_entry(blob: &[u8], want_cx: i32, want_cy: i32) -> Option<(u16, u16, u16, u16)> {
    if blob.len() < 6 {
        return None;
    }
    let count = u16::from_le_bytes(blob[4..6].try_into().ok()?) as usize;
    if count == 0 {
        return None;
    }
    let mut best: Option<(i64, i64, u16, u16, u16, u16)> = None;
    for i in 0..count {
        let base = 6 + i * 14;
        if base + 14 > blob.len() {
            break;
        }
        let w_raw = blob[base];
        let h_raw = blob[base + 1];
        // Wine uses 0 in the GRPICONDIRENTRY width/height byte to mean 256.
        let width: u16 = if w_raw == 0 { 256 } else { w_raw as u16 };
        let height: u16 = if h_raw == 0 { 256 } else { h_raw as u16 };
        let bit_count = u16::from_le_bytes(blob[base + 6..base + 8].try_into().ok()?);
        let n_id = u16::from_le_bytes(blob[base + 12..base + 14].try_into().ok()?);
        let dim = width.max(height) as i64;
        let want = want_cx.max(want_cy).max(1) as i64;
        let dist = (dim - want).abs();
        let key = (dist, -(bit_count as i64));
        match &best {
            None => best = Some((key.0, key.1, n_id, width, height, bit_count)),
            Some((bd, bb, _, _, _, _)) => {
                if (key.0, key.1) < (*bd, *bb) {
                    best = Some((key.0, key.1, n_id, width, height, bit_count));
                }
            }
        }
    }
    best.map(|(_, _, n_id, w, h, bc)| (n_id, w, h, bc))
}

/// Core dispatcher for `LoadImageW`.
///
/// Wine ref: `dlls/user32/cursoricon.c::CURSORICON_Load` — `FindResourceW` on
/// RT_GROUP_* to get the directory, pick best entry, second `FindResourceW`
/// on RT_ICON/RT_CURSOR by the `wResId` from the group entry. For
/// `IMAGE_BITMAP`, Wine calls `BITMAP_LoadImageW` which skips the group
/// indirection and resolves RT_BITMAP directly.
///
/// # Safety
/// If `name_ptr` is a string pointer (non-INTRESOURCE), it must be a valid
/// null-terminated UTF-16 string.
unsafe fn load_image_impl(
    h_inst: usize,
    name_ptr: usize,
    ty: u32,
    cx: i32,
    cy: i32,
    fu_load: u32,
) -> usize {
    use crate::image_handles::{self as ih, ImageEntry, ImageKind};

    let shared = (fu_load & LR_SHARED) != 0;
    let default_size = (fu_load & LR_DEFAULTSIZE) != 0;

    // Dedup key BEFORE any string consumption so both string and ordinal
    // paths produce a stable 64-bit fingerprint.
    // SAFETY: forward the caller's guarantee.
    let name_key = unsafe { ih::name_key_from_ptr(name_ptr) };
    let kind = match ty {
        IMAGE_ICON => ImageKind::Icon,
        IMAGE_CURSOR => ImageKind::Cursor,
        IMAGE_BITMAP => ImageKind::Bitmap,
        _ => {
            eprintln!("weave/user32: LoadImageW: unsupported image type {ty}");
            return 0;
        }
    };

    if shared {
        if let Some(existing) = ih::get_shared(h_inst, name_key, kind) {
            return existing;
        }
    }

    // hInst == NULL: OEM load. Deferred to Task 10b per brief — return a
    // stable non-zero handle keyed by (0, name_key, kind) so guest apps
    // that depend on hCursor != NULL don't crash. Backing pixels are NOT
    // fabricated; `GetIconInfo` / `DrawIcon` on these handles will see
    // data_ptr == 0 and bail gracefully.
    if h_inst == 0 {
        let entry = ImageEntry {
            kind,
            data_ptr: 0,
            data_size: 0,
            width: cx,
            height: cy,
            bpp: 0,
            shared: true, // OEM is always dedup'd so apps get stable IDC_ARROW etc.
        };
        return ih::insert(entry, Some((0, name_key)));
    }

    let image_base = match weave_core::module_handles::base_of(h_inst) {
        Some(b) => b,
        None => {
            eprintln!(
                "weave/user32: LoadImageW: no registered base for hInst={h_inst:#x} — falling back to 0"
            );
            return 0;
        }
    };

    // SAFETY: forward the caller's guarantee on `name_ptr`.
    let name_id = unsafe { name_ptr_to_resource_id(name_ptr) };

    match ty {
        IMAGE_ICON | IMAGE_CURSOR => {
            let (group_type, leaf_type, is_cursor) = if ty == IMAGE_ICON {
                (RT_GROUP_ICON, RT_ICON, false)
            } else {
                (RT_GROUP_CURSOR, RT_CURSOR, true)
            };
            let (want_cx, want_cy) = if default_size || (cx == 0 && cy == 0) {
                if is_cursor {
                    (DEFAULT_CURSOR_CX, DEFAULT_CURSOR_CY)
                } else {
                    (DEFAULT_ICON_CX, DEFAULT_ICON_CY)
                }
            } else {
                (cx, cy)
            };

            let (grp_ptr, grp_size) = match locate_resource_bytes(image_base, group_type, name_id) {
                Some(v) => v,
                None => return 0,
            };
            // SAFETY: grp_ptr came from find_resource — it lies within the
            // mapped image, and grp_size is the exact resource size.
            let blob =
                unsafe { std::slice::from_raw_parts(grp_ptr as *const u8, grp_size as usize) };
            let (n_id, width, height, bit_count) = match pick_group_entry(blob, want_cx, want_cy) {
                Some(t) => t,
                None => return 0,
            };

            let (data_ptr, data_size) = match locate_resource_bytes(
                image_base,
                leaf_type,
                weave_core::resource::ResourceId::Id(n_id),
            ) {
                Some(v) => v,
                None => return 0,
            };

            let entry = ImageEntry {
                kind,
                data_ptr,
                data_size,
                width: width as i32,
                height: height as i32,
                bpp: bit_count,
                shared,
            };
            let share_key = if shared {
                Some((h_inst, name_key))
            } else {
                None
            };
            ih::insert(entry, share_key)
        }
        IMAGE_BITMAP => {
            let (data_ptr, data_size) = match locate_resource_bytes(image_base, RT_BITMAP, name_id)
            {
                Some(v) => v,
                None => return 0,
            };
            // BITMAPINFOHEADER starts at data_ptr; first 4 bytes = biSize,
            // next 4 = biWidth, next 4 = biHeight, next 2 = biPlanes, next
            // 2 = biBitCount. Read width/height/bpp for bookkeeping.
            // SAFETY: data_ptr/data_size delimit a valid resource.
            let (w, h, bpp) = unsafe {
                if data_size < 16 {
                    (0i32, 0i32, 0u16)
                } else {
                    let p = data_ptr as *const u8;
                    let read_i32 = |off: usize| -> i32 {
                        let mut b = [0u8; 4];
                        for (i, bb) in b.iter_mut().enumerate() {
                            *bb = *p.add(off + i);
                        }
                        i32::from_le_bytes(b)
                    };
                    let read_u16 = |off: usize| -> u16 {
                        let b0 = *p.add(off);
                        let b1 = *p.add(off + 1);
                        u16::from_le_bytes([b0, b1])
                    };
                    (read_i32(4), read_i32(8), read_u16(14))
                }
            };
            let entry = ImageEntry {
                kind,
                data_ptr,
                data_size,
                width: w,
                height: h,
                bpp,
                shared,
            };
            let share_key = if shared {
                Some((h_inst, name_key))
            } else {
                None
            };
            ih::insert(entry, share_key)
        }
        _ => 0,
    }
}

/// LoadCursorW: load a cursor resource.
///
/// Thin wrapper over `load_image_w(IMAGE_CURSOR, LR_DEFAULTSIZE | LR_SHARED)`
/// — matches Wine's one-liner in `dlls/user32/cursoricon.c`.
///
/// # Safety
/// `lp_cursor_name` (if non-null) must be a valid UTF-16 string or an integer
/// resource identifier (IDC_* constant passed via MAKEINTRESOURCEW).
// Wine ref: dlls/user32/cursoricon.c::CURSORICON_Load — LoadCursorW delegates
// to LoadImageW(IMAGE_CURSOR, 0, 0, LR_DEFAULTSIZE | LR_SHARED); FindResourceW
// runs against RT_GROUP_CURSOR then the leaf RT_CURSOR by wResId.
pub unsafe extern "win64" fn load_cursor_w(h_instance: usize, lp_cursor_name: usize) -> usize {
    // SAFETY: forward caller contract on lp_cursor_name.
    let result = unsafe {
        load_image_impl(
            h_instance,
            lp_cursor_name,
            IMAGE_CURSOR,
            0,
            0,
            LR_DEFAULTSIZE | LR_SHARED,
        )
    };
    restrace!(
        "load_cursor_w hInst={h_instance:#x} name={lp_cursor_name:#x} → {}",
        if result != 0 {
            format!("hCursor={result:#x}")
        } else {
            "zero".to_string()
        }
    );
    result
}

/// LoadIconW: load an icon resource.
///
/// # Safety
/// `lp_icon_name` (if non-null) must be a valid UTF-16 string or integer resource.
// Wine ref: dlls/user32/cursoricon.c::CURSORICON_Load — LoadIconW delegates to
// LoadImageW(IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED); RT_GROUP_ICON →
// best-match entry by SM_CXICON → RT_ICON lookup by wResId.
pub unsafe extern "win64" fn load_icon_w(h_instance: usize, lp_icon_name: usize) -> usize {
    // SAFETY: forward caller contract.
    let result = unsafe {
        load_image_impl(
            h_instance,
            lp_icon_name,
            IMAGE_ICON,
            0,
            0,
            LR_DEFAULTSIZE | LR_SHARED,
        )
    };
    restrace!(
        "load_icon_w hInst={h_instance:#x} name={lp_icon_name:#x} → {}",
        if result != 0 {
            format!("hIcon={result:#x}")
        } else {
            "zero".to_string()
        }
    );
    result
}

/// LoadImageW: load an image (icon, cursor, or bitmap) from a resource.
///
/// Dispatches on `ty`:
///   * `IMAGE_ICON` / `IMAGE_CURSOR` → RT_GROUP_* lookup, pick best by size,
///     then RT_ICON/RT_CURSOR lookup for the chosen entry's `wResId`.
///   * `IMAGE_BITMAP` → RT_BITMAP direct lookup.
///
/// `hInst == NULL` (OEM loads) returns a stable dedup'd handle with no
/// backing pixels — real OEM cursor/icon pixels are Task 10b.
///
/// # Safety
/// `name` may be a pointer or integer resource ID. If the high 48 bits are
/// non-zero, the caller guarantees `name` is a valid null-terminated UTF-16
/// string (`IS_INTRESOURCE` gate).
// Wine ref: dlls/user32/cursoricon.c::CURSORICON_Load (icon/cursor) and
// dlls/user32/cursoricon.c::BITMAP_Load (bitmap); IS_INTRESOURCE gate at
// include/winuser.h: ((((ULONG_PTR)(x)) >> 16) == 0).
pub unsafe extern "win64" fn load_image_w(
    h_inst: usize,
    name: usize,
    ty: u32,
    cx: i32,
    cy: i32,
    fu_load: u32,
) -> usize {
    // SAFETY: forward caller contract.
    let result = unsafe { load_image_impl(h_inst, name, ty, cx, cy, fu_load) };
    restrace!(
        "load_image_w hInst={h_inst:#x} name={name:#x} ty={ty} cx={cx} cy={cy} fuLoad={fu_load:#x} → {}",
        if result != 0 {
            format!("handle={result:#x}")
        } else {
            "zero".to_string()
        }
    );
    result
}

// ── MessageBoxW ───────────────────────────────────────────────────────────────

/// MessageBoxW: display a modal message box.
///
/// Phase 2: prints the message to stderr and returns IDOK (1). Real dialog
/// support requires weave-comdlg32 in Phase 5.
///
/// # Safety
/// `lp_text` and `lp_caption` (if non-null) must be valid UTF-16 strings.
// Wine ref: dlls/user32/dialog.c::DIALOG_DoDialogBox — MessageBoxW creates a dialog via
// DialogBoxIndirectParamAW; runs its own modal message loop; returns button ID (IDOK=1 etc).
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

/// Sentinel HDC returned by GetDC(NULL) — represents the screen/desktop DC.
///
/// Wine ref: dlls/win32u/dc.c — NtUserGetDC(NULL) returns a whole-screen DC tied
/// to the root window; it is always non-NULL. Returning hwnd directly (0) for
/// GetDC(NULL) causes callers that check hdc != NULL to spin-loop retrying forever,
/// because they interpret NULL as "no display available." Using this sentinel keeps
/// the HDC non-zero so validity checks pass; GetDeviceCaps / GetTextMetrics work on
/// any non-NULL HDC in Weave (they ignore the drawable and return fixed values).
/// Actual drawing on the screen DC resolves xcb_id → 0 → silent no-op, which is
/// correct because nothing should be drawing directly to the root window.
pub const SCREEN_HDC: usize = 0x0000_00DC;

/// GetDC: return a device context for a window.
///
/// Wine ref: dlls/win32u/dc.c — NtUserGetDC(hwnd=NULL) returns a whole-screen DC
/// (never NULL); NtUserGetDC(hwnd) returns a DC clipped to that window's client area.
/// Weave: returns SCREEN_HDC for hwnd=0 so callers don't spin-loop on a NULL check,
/// and hwnd itself for non-null windows (matches the BeginPaint fake-HDC contract).
pub extern "win64" fn get_dc(hwnd: usize) -> usize {
    if hwnd == 0 {
        SCREEN_HDC
    } else {
        hwnd
    }
}

/// ReleaseDC: release a device context.
///
/// Phase 2: no-op. Returns 1 (success).
// Wine ref: dlls/win32u/dce.c::release_dc — decrements DC ref count; for class/window DCs
// clears busy flag; for private DCs (GetDC) actually frees the DCE; returns 1 if released.
pub extern "win64" fn release_dc(_hwnd: usize, _hdc: usize) -> i32 {
    1
}

/// WindowFromDC: return the HWND associated with a DC.
///
/// Wine ref: dlls/win32u/dce.c — maps a cached/window DC back to the owning
/// window. Weave's HDC contract is intentionally simple: BeginPaint/GetDC return
/// the HWND itself for window DCs, and SCREEN_HDC for GetDC(NULL).
pub extern "win64" fn window_from_dc(hdc: usize) -> usize {
    if hdc == 0 || hdc == SCREEN_HDC {
        return 0;
    }
    if window::with(hdc, |_| ()).is_some() {
        return hdc;
    }
    let paint_hwnd = current_paint_hwnd();
    if paint_hwnd != 0 {
        return paint_hwnd;
    }
    window::first_hwnd_with_xcb()
}

// ── SetWindowPos / MoveWindow ─────────────────────────────────────────────────

/// MoveWindow: change the position and size of a window.
// Wine ref: dlls/win32u/window.c::set_window_pos — MoveWindow calls NtUserSetWindowPos with
// SWP_NOZORDER|SWP_NOACTIVATE; sends WM_SIZE synchronously before WM_PAINT fires.
pub extern "win64" fn move_window(
    hwnd: usize,
    x: i32,
    y: i32,
    n_width: i32,
    n_height: i32,
    b_repaint: i32,
) -> i32 {
    let w = n_width.max(0) as u32;
    let h = n_height.max(0) as u32;
    eprintln!("weave/user32: MoveWindow hwnd={hwnd:#x} ({x},{y}) {w}x{h}");
    let xcb_id = window::with_mut(hwnd, |e| {
        e.x = x;
        e.y = y;
        e.width = w;
        e.height = h;
        e.xcb_id
    })
    .unwrap_or(0);
    if xcb_id != 0 {
        backend::configure_window(xcb_id, x, y, w, h);
    }
    // Wine ref: dlls/win32u/winpos.c — NtUserSetWindowPos sends WM_SIZE synchronously
    // (via SendMessageTimeout) before the resize completes so that the application's
    // window proc has updated internal state by the time WM_PAINT fires.
    // We post WM_SIZE before WM_PAINT so Scintilla/NPP update their layout state
    // (line count, content area width) before painting the invalidated region.
    let l_param = (w as isize) | ((h as isize) << 16);
    queue::post(MsgEntry {
        hwnd,
        message: WM_SIZE,
        w_param: 0, // SIZE_RESTORED
        l_param,
        time: 0,
        pt_x: 0,
        pt_y: 0,
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
// Wine ref: dlls/win32u/main.c — NtUserGetForegroundWindow returns thread's active window
// from the server; can return NULL if no window has focus (e.g. another process is active).
pub extern "win64" fn get_foreground_window() -> usize {
    window::all_hwnds().into_iter().next().unwrap_or(0)
}

/// SetForegroundWindow: attempt to bring a window to the foreground.
///
/// Phase 2: no-op (always succeeds).
// Wine ref: dlls/win32u/input.c::set_foreground_window — sends set_foreground_window server
// request; allowed_fg_apps list controls whether caller is permitted to steal focus.
pub extern "win64" fn set_foreground_window(_hwnd: usize) -> i32 {
    1
}

/// GetDesktopWindow: return the handle to the desktop window.
///
/// Phase 2: returns 0 (no desktop window object).
// Wine ref: dlls/win32u/winstation.c::get_desktop_window — queries server for the desktop
// HWND; creates the desktop window on first call; handle is process-global.
pub extern "win64" fn get_desktop_window() -> usize {
    0
}

// ── AdjustWindowRect ──────────────────────────────────────────────────────────

// Wine ref: dlls/win32u/defwnd.c:254 — outer-frame adjust comes from style bits;
// WS_THICKFRAME adds iBorderWidth(1)+iPaddedBorderWidth(4)=5; WS_CAPTION top-inflates
// by SM_CYCAPTION(23); WS_EX_CLIENTEDGE inflates all sides by SM_CXEDGE/SM_CYEDGE(2).
unsafe fn adjust_window_rect_impl(rect: *mut Rect, style: u32, menu: i32, ex_style: u32) -> i32 {
    if rect.is_null() {
        return 0;
    }
    let r = unsafe { &mut *rect };

    // Outer frame: how many border pixels to add on each side.
    let mut adj: i32 = 0;
    if (ex_style & (WS_EX_STATICEDGE | WS_EX_DLGMODALFRAME)) == WS_EX_STATICEDGE {
        adj = 1;
    } else if ex_style & WS_EX_DLGMODALFRAME != 0 || style & (WS_THICKFRAME | WS_DLGFRAME) != 0 {
        adj = 2;
    }
    if style & WS_THICKFRAME != 0 {
        adj += 5; // iBorderWidth(1) + iPaddedBorderWidth(4)
    }
    if style & (WS_BORDER | WS_DLGFRAME) != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 {
        adj += 1;
    }
    r.left -= adj;
    r.top -= adj;
    r.right += adj;
    r.bottom += adj;

    // Caption bar.
    if style & WS_CAPTION == WS_CAPTION {
        if ex_style & WS_EX_TOOLWINDOW != 0 {
            r.top -= 16; // iSmCaptionHeight(15) + 1
        } else {
            r.top -= 23; // SM_CYCAPTION = iCaptionHeight(22) + 1
        }
    }
    // Menu bar.
    if menu != 0 {
        r.top -= 16; // iMenuHeight(15) + 1
    }
    // Client edge (WS_EX_CLIENTEDGE).
    if ex_style & WS_EX_CLIENTEDGE != 0 {
        r.left -= 2; // SM_CXEDGE
        r.top -= 2; // SM_CYEDGE
        r.right += 2;
        r.bottom += 2;
    }

    1 // TRUE
}

/// # Safety
/// `lp_rect` must point to a valid `RECT`.
// Wine ref: dlls/win32u/defwnd.c::adjust_window_rect — delegates to AdjustWindowRectEx
// with dwExStyle=0; no ex-style adjustments (no client edge, no static edge).
pub unsafe extern "win64" fn adjust_window_rect(
    lp_rect: *mut Rect,
    dw_style: u32,
    b_menu: i32,
) -> i32 {
    unsafe { adjust_window_rect_impl(lp_rect, dw_style, b_menu, 0) }
}

/// # Safety
/// `lp_rect` must point to a valid `RECT`.
// Wine ref: dlls/win32u/defwnd.c::adjust_window_rect — full version with ex_style;
// handles WS_EX_CLIENTEDGE (inflates by SM_CXEDGE/SM_CYEDGE) and WS_EX_STATICEDGE.
pub unsafe extern "win64" fn adjust_window_rect_ex(
    lp_rect: *mut Rect,
    dw_style: u32,
    b_menu: i32,
    dw_ex_style: u32,
) -> i32 {
    unsafe { adjust_window_rect_impl(lp_rect, dw_style, b_menu, dw_ex_style) }
}

/// SetCursor: set the cursor shape.
///
/// Phase 2: no-op; returns the previous cursor (fake handle = 1).
// Wine ref: dlls/win32u/input.c — NtUserSetCursor updates thread cursor and sends
// WM_SETCURSOR to the window under the cursor; returns previous HCURSOR.
pub extern "win64" fn set_cursor(_h_cursor: usize) -> usize {
    1
}

/// ShowCursor: show or hide the cursor (ref-counted).
///
/// Phase 2: returns 0 (display counter unchanged).
// Wine ref: dlls/win32u/input.c — NtUserShowCursor increments/decrements a per-thread
// display counter; cursor visible when counter >= 0; returns new counter value.
pub extern "win64" fn show_cursor(_b_show: i32) -> i32 {
    0
}

// ── Window property store (SetPropW / GetPropW / RemovePropW) ─────────────────

/// Global window property table: (hwnd, prop_name) → handle value.
///
/// Wine ref: dlls/win32u/property.c — properties are stored per-window in a
/// linked list of PROPERTY structs (name atom + handle value); Get/Set/Remove
/// operate on that list. Weave uses a flat HashMap for simplicity.
fn prop_table() -> &'static std::sync::Mutex<std::collections::HashMap<(usize, String), usize>> {
    static T: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(usize, String), usize>>,
    > = std::sync::OnceLock::new();
    T.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// SetPropW: add or replace a named property on a window.
///
/// Returns TRUE (1) on success, FALSE (0) on failure.
///
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-16 string or NULL.
// Wine ref: dlls/win32u/property.c::NtUserSetProp — looks up/creates a PROPERTY
// entry by atom (intern string via GlobalAddAtom); stores handle; returns TRUE on success.
pub unsafe extern "win64" fn set_prop_w(hwnd: usize, lp_string: *const u16, h_data: usize) -> i32 {
    if hwnd == 0 || lp_string.is_null() {
        return 0;
    }
    // MAKEINTATOM guard: values ≤ 0xFFFF are atoms, not string pointers.
    if lp_string as usize <= 0xFFFF {
        let key = format!("#{}", lp_string as usize);
        if let Ok(mut t) = prop_table().lock() {
            t.insert((hwnd, key), h_data);
            return 1;
        }
        return 0;
    }
    let name = unsafe { decode_wide(lp_string) };
    if let Ok(mut t) = prop_table().lock() {
        t.insert((hwnd, name), h_data);
        1 // TRUE
    } else {
        0
    }
}

/// GetPropW: retrieve a named property from a window.
///
/// Returns the stored handle, or NULL if not found.
///
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-16 string or NULL.
// Wine ref: dlls/win32u/property.c::NtUserGetProp — looks up PROPERTY by atom;
// returns handle or NULL if atom not found on window.
pub unsafe extern "win64" fn get_prop_w(hwnd: usize, lp_string: *const u16) -> usize {
    if hwnd == 0 || lp_string.is_null() {
        return 0;
    }
    let name = unsafe { decode_wide(lp_string) };
    prop_table()
        .lock()
        .ok()
        .and_then(|t| t.get(&(hwnd, name)).copied())
        .unwrap_or(0)
}

/// RemovePropW: remove a named property from a window.
///
/// Returns the previously stored handle, or NULL if not found.
///
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-16 string or NULL.
// Wine ref: dlls/win32u/property.c::NtUserRemoveProp — removes PROPERTY entry
// by atom; returns old handle so caller can free it if needed.
pub unsafe extern "win64" fn remove_prop_w(hwnd: usize, lp_string: *const u16) -> usize {
    if hwnd == 0 || lp_string.is_null() {
        return 0;
    }
    let name = unsafe { decode_wide(lp_string) };
    prop_table()
        .lock()
        .ok()
        .and_then(|mut t| t.remove(&(hwnd, name)))
        .unwrap_or(0)
}

// ── Display and mode enumeration stubs ────────────────────────────────────────

/// # Safety
/// `lp_display_device` must point to a caller-allocated DISPLAY_DEVICEW (cb must be set).
// Wine ref: dlls/win32u/sysparams.c — EnumDisplayDevicesW iterates source list; returns
// FALSE when iDevNum >= adapter count; fills DISPLAY_DEVICEW with DeviceName/DeviceString.
pub unsafe extern "win64" fn enum_display_devices_w(
    _lp_device: *const u16,
    i_dev_num: u32,
    lp_display_device: usize,
    _dw_flags: u32,
) -> i32 {
    // Weave presents exactly one display adapter (and one monitor per adapter).
    if i_dev_num > 0 || lp_display_device == 0 {
        return 0; // FALSE — no more devices
    }

    // DISPLAY_DEVICEW layout:
    //   offset   0: cb         (u32)         — 4 bytes
    //   offset   4: DeviceName (u16 × 32)    — 64 bytes
    //   offset  68: DeviceString (u16 × 128) — 256 bytes
    //   offset 324: StateFlags  (u32)         — 4 bytes
    //   offset 328: DeviceID    (u16 × 128)   — 256 bytes
    //   offset 584: DeviceKey   (u16 × 128)   — 256 bytes
    let base = lp_display_device as *mut u8;

    // DeviceName: "\\.\DISPLAY1"
    let name_chars: Vec<u16> = [
        '\\', '\\', '.', '\\', 'D', 'I', 'S', 'P', 'L', 'A', 'Y', '1', '\0',
    ]
    .iter()
    .map(|&c| c as u16)
    .collect();
    let name_ptr = base.add(4) as *mut u16;
    for (i, &c) in name_chars.iter().enumerate().take(32) {
        name_ptr.add(i).write(c);
    }

    // DeviceString: "Generic Display"
    let ds_chars: Vec<u16> = "Generic Display\0".encode_utf16().collect();
    let ds_ptr = base.add(68) as *mut u16;
    for (i, &c) in ds_chars.iter().enumerate().take(128) {
        ds_ptr.add(i).write(c);
    }

    // StateFlags: DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE
    (base.add(324) as *mut u32).write(0x0000_0001 | 0x0000_0004);

    1 // TRUE
}

/// Write the current display mode into a caller-supplied DEVMODEW.
///
/// # Safety
/// `lp_dev_mode` must point to a DEVMODEW large enough to hold the fields written.
// Wine ref: dlls/win32u/sysparams.c::source_enum_display_settings — iModeNum=ENUM_CURRENT_SETTINGS
// (-1) returns current mode; ENUM_REGISTRY_SETTINGS (-2) returns saved mode; else enumerates.
pub unsafe extern "win64" fn enum_display_settings_w(
    _lp_sz_device_name: *const u16,
    i_mode_num: u32,
    lp_dev_mode: usize,
) -> i32 {
    fill_devmode(i_mode_num, lp_dev_mode)
}

/// # Safety
/// `lp_dev_mode` must point to a DEVMODEW large enough to hold the fields written.
// Wine ref: dlls/win32u/sysparams.c — EnumDisplaySettingsExW adds EDS_RAWMODE/EDS_ROTATEDMODE
// flags; otherwise identical to EnumDisplaySettingsW.
pub unsafe extern "win64" fn enum_display_settings_ex_w(
    _lp_sz_device_name: *const u16,
    i_mode_num: u32,
    lp_dev_mode: usize,
    _dw_flags: u32,
) -> i32 {
    fill_devmode(i_mode_num, lp_dev_mode)
}

/// Populate a DEVMODEW with the Weave virtual display's current mode.
///
/// ENUM_CURRENT_SETTINGS (0xFFFF_FFFF) and ENUM_REGISTRY_SETTINGS (0xFFFF_FFFE) both
/// return the single mode Weave advertises. iModeNum == 0 also returns that mode (the
/// only enumerable index). All other indices return FALSE so SDL2 stops enumerating.
///
/// DEVMODEW key offsets (all little-endian, Windows x64 ABI):
///   68: dmSize (u16) — sizeof(DEVMODEW) = 220
///   72: dmFields (u32)
///  168: dmBitsPerPel (u32)
///  172: dmPelsWidth (u32)
///  176: dmPelsHeight (u32)
///  184: dmDisplayFrequency (u32)
unsafe fn fill_devmode(i_mode_num: u32, lp_dev_mode: usize) -> i32 {
    // Accept ENUM_CURRENT_SETTINGS, ENUM_REGISTRY_SETTINGS, and index 0.
    // Reject any other index so callers stop enumerating.
    const ENUM_CURRENT_SETTINGS: u32 = 0xFFFF_FFFF;
    const ENUM_REGISTRY_SETTINGS: u32 = 0xFFFF_FFFE;
    if i_mode_num > 0 && i_mode_num != ENUM_CURRENT_SETTINGS && i_mode_num != ENUM_REGISTRY_SETTINGS
    {
        return 0;
    }
    if lp_dev_mode == 0 {
        return 0;
    }

    let (sw, sh) = backend::screen_size();
    let base = lp_dev_mode as *mut u8;

    // dmSize — caller must have set this; we overwrite to ensure correctness
    (base.add(68) as *mut u16).write(220);

    // dmFields: DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY
    (base.add(72) as *mut u32).write(0x0040_0000 | 0x0008_0000 | 0x0010_0000 | 0x0004_0000);

    // dmBitsPerPel, dmPelsWidth, dmPelsHeight, dmDisplayFrequency
    (base.add(168) as *mut u32).write(32);
    (base.add(172) as *mut u32).write(sw as u32);
    (base.add(176) as *mut u32).write(sh as u32);
    (base.add(184) as *mut u32).write(60);

    1 // TRUE
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/driver.c::nulldrv_ChangeDisplaySettings — returns DISP_CHANGE_FAILED
// when no driver; the real path calls into the GPU driver via NtUserChangeDisplaySettings.
pub unsafe extern "win64" fn change_display_settings_w(_lp_dev_mode: usize, _dw_flags: u32) -> i32 {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/driver.c::loaderdrv_ChangeDisplaySettings — ChangeDisplaySettingsExW
// adds target device name and HWND parameters; same DISP_CHANGE_* return codes.
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

// Wine ref: dlls/win32u/sysparams.c::monitor_from_window — uses window rect (or placement
// rcNormalPosition if iconic) to find intersecting monitor; falls back to primary if no match.
// Return 0 (no monitor) when X11 is unavailable so headless apps see no display.
pub extern "win64" fn monitor_from_window(_hwnd: usize, _dw_flags: u32) -> usize {
    if !backend::is_available() {
        return 0;
    }
    1usize
}

// Wine ref: dlls/win32u/sysparams.c — MonitorFromPoint wraps monitor_from_rect with a
// 1×1 rect at the point; returns primary monitor handle on MONITOR_DEFAULTTOPRIMARY.
pub extern "win64" fn monitor_from_point(_pt_x: i32, _pt_y: i32, _dw_flags: u32) -> usize {
    if !backend::is_available() {
        return 0;
    }
    1usize
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/sysparams.c::monitor_info_from_rect — finds monitor with largest
// intersection area; if no intersection uses MONITOR_DEFAULTTO* flag to pick fallback.
pub unsafe extern "win64" fn monitor_from_rect(_lp_rc: *const Rect, _dw_flags: u32) -> usize {
    if !backend::is_available() {
        return 0;
    }
    1usize
}

/// # Safety
/// `lp_mi` must point to a MONITORINFO or MONITORINFOEXW with `cbSize` pre-filled.
// Wine ref: dlls/win32u/sysparams.c::monitor_info_from_window — fills rcMonitor (full screen
// rect) and rcWork (work area minus taskbar); dwFlags=MONITORINFOF_PRIMARY for primary.
pub unsafe extern "win64" fn get_monitor_info_w(_h_monitor: usize, lp_mi: *mut MonitorInfo) -> i32 {
    if lp_mi.is_null() {
        return 0;
    }
    let (sw, sh) = crate::backend::screen_size();
    // Write using real Windows MONITORINFO layout (NOT the Weave MonitorInfo struct,
    // which has an erroneous _pad field that shifts offsets by 4 bytes):
    //   offset  0: cbSize (u32)  — caller pre-fills; do not touch
    //   offset  4: rcMonitor (RECT = 4×i32 = 16 bytes)
    //   offset 20: rcWork    (RECT)
    //   offset 36: dwFlags   (u32) — MONITORINFOF_PRIMARY = 1
    //   offset 40: szDevice  (u16×32, only in MONITORINFOEXW, cbSize ≥ 104)
    let base = lp_mi as *mut u8;
    let cb_size = (base as *const u32).read_unaligned();

    // rcMonitor
    (base.add(4) as *mut i32).write(0);
    (base.add(8) as *mut i32).write(0);
    (base.add(12) as *mut i32).write(sw as i32);
    (base.add(16) as *mut i32).write(sh as i32);
    // rcWork (same — no taskbar in Weave)
    (base.add(20) as *mut i32).write(0);
    (base.add(24) as *mut i32).write(0);
    (base.add(28) as *mut i32).write(sw as i32);
    (base.add(32) as *mut i32).write(sh as i32);
    // dwFlags: MONITORINFOF_PRIMARY
    (base.add(36) as *mut u32).write(1);
    // szDevice in MONITORINFOEXW — SDL2 passes cbSize=104; fill "\\.\DISPLAY1"
    if cb_size >= 104 {
        let name: [u16; 13] = [
            '\\' as u16,
            '\\' as u16,
            '.' as u16,
            '\\' as u16,
            'D' as u16,
            'I' as u16,
            'S' as u16,
            'P' as u16,
            'L' as u16,
            'A' as u16,
            'Y' as u16,
            '1' as u16,
            0,
        ];
        let sz_ptr = base.add(40) as *mut u16;
        for (i, &c) in name.iter().enumerate() {
            sz_ptr.add(i).write(c);
        }
    }
    1
}

/// # Safety
/// `lpfn_enum` must be a valid MONITORENUMPROC callback (or zero/null to skip).
// Wine ref: dlls/win32u/sysparams.c — EnumDisplayMonitors iterates monitor list; calls
// lpfnEnum for each monitor whose rect intersects hdc clip rect (or all if hdc=NULL).
pub unsafe extern "win64" fn enum_display_monitors(
    _hdc: usize,
    _lprc_clip: usize,
    lpfn_enum: usize,
    dw_data: isize,
) -> i32 {
    if lpfn_enum == 0 {
        return 1;
    }
    // Only enumerate monitors when a real display is available.  Without a
    // display (e.g. headless IrfanView test, env_remove("DISPLAY")), there are
    // no monitors to report and the callback must not be called — calling it
    // with a fake HMONITOR causes apps that probe display hardware in their
    // callback (IrfanView) to corrupt the heap when the hardware isn't there.
    if !backend::is_available() {
        return 1;
    }
    let (sw, sh) = backend::screen_size();
    // RECT: left, top, right, bottom
    let rect: [i32; 4] = [0, 0, sw as i32, sh as i32];
    // MONITORENUMPROC: BOOL CALLBACK(HMONITOR, HDC, LPRECT, LPARAM)
    let callback: unsafe extern "win64" fn(usize, usize, *const i32, isize) -> i32 =
        std::mem::transmute(lpfn_enum);
    callback(1, 0, rect.as_ptr(), dw_data);
    1
}

// ── Window long + SetWindowPos ───────────────────────────────────────────────

const GWL_WNDPROC: i32 = -4;
const GWL_STYLE: i32 = -16;
const GWL_EXSTYLE: i32 = -20;
const GWLP_USERDATA: i32 = -21;

// Wine ref: dlls/win32u/window.c — get_window_long_size dispatches on offset; GWL_EXSTYLE
// returns the extended style stored at creation; GWLP_USERDATA returns per-window app data.
pub extern "win64" fn get_window_long_w(hwnd: usize, n_index: i32) -> i32 {
    match n_index {
        GWL_EXSTYLE => get_extra(hwnd, |e| e.ex_style as i32, 0),
        GWLP_USERDATA => get_extra(hwnd, |e| e.user_data as i32, 0),
        _ => window::with(hwnd, |w| match n_index {
            GWL_STYLE => w.style as i32,
            GWL_WNDPROC => w.wnd_proc as i32,
            _ => 0,
        })
        .unwrap_or(0),
    }
}

// Wine ref: dlls/win32u/window.c — GetWindowLongPtrW is a 64-bit version of GetWindowLongW;
// GWLP_USERDATA returns the full pointer-width value; non-negative indices are byte offsets
// into the per-window extra bytes (cbWndExtra) allocated at window creation.
pub extern "win64" fn get_window_long_ptr_w(hwnd: usize, n_index: i32) -> isize {
    match n_index {
        GWL_EXSTYLE => get_extra(hwnd, |e| e.ex_style as isize, 0),
        GWLP_USERDATA => get_extra(hwnd, |e| e.user_data, 0),
        _ if n_index >= 0 => {
            // Extra bytes: n_index is a byte offset; reads a pointer-sized (8-byte) value.
            let offset = n_index as usize;
            let val = get_extra(
                hwnd,
                |e| {
                    if offset + 8 <= e.extra_bytes.len() {
                        let mut buf = [0u8; 8];
                        buf.copy_from_slice(&e.extra_bytes[offset..offset + 8]);
                        isize::from_ne_bytes(buf)
                    } else {
                        0
                    }
                },
                0,
            );
            {
                static GWLP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                let is_sci = window::with(hwnd, |e| e.class_name == "Scintilla").unwrap_or(false);
                if is_sci
                    && offset == 0
                    && GWLP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 8
                {
                    eprintln!("weave/user32: GetWindowLongPtr hwnd={hwnd:#x} offset=0 → {val:#x}");
                }
            }
            val
        }
        _ => window::with(hwnd, |w| match n_index {
            GWL_STYLE => w.style as isize,
            GWL_WNDPROC => w.wnd_proc as isize,
            _ => 0,
        })
        .unwrap_or(0),
    }
}

// Wine ref: dlls/win32u/window.c — SetWindowLongW returns the previous value; triggers
// WM_STYLECHANGING/WM_STYLECHANGED for GWL_STYLE (not implemented here — Phase 4 gap).
pub extern "win64" fn set_window_long_w(hwnd: usize, n_index: i32, dw_new_long: i32) -> i32 {
    match n_index {
        GWL_EXSTYLE => {
            let old = get_extra(hwnd, |e| e.ex_style as i32, 0);
            set_extra(hwnd, |e| e.ex_style = dw_new_long as u32);
            old
        }
        GWLP_USERDATA => {
            let old = get_extra(hwnd, |e| e.user_data as i32, 0);
            set_extra(hwnd, |e| e.user_data = dw_new_long as isize);
            old
        }
        GWL_STYLE => window::with_mut(hwnd, |w| {
            let old = w.style as i32;
            w.style = dw_new_long as u32;
            old
        })
        .unwrap_or(0),
        _ => 0,
    }
}

// Wine ref: dlls/win32u/window.c — SetWindowLongPtrW is the 64-bit version; GWLP_WNDPROC
// changes the window procedure and returns the old one.
pub extern "win64" fn set_window_long_ptr_w(
    hwnd: usize,
    n_index: i32,
    dw_new_long: isize,
) -> isize {
    match n_index {
        GWL_EXSTYLE => {
            let old = get_extra(hwnd, |e| e.ex_style as isize, 0);
            set_extra(hwnd, |e| e.ex_style = dw_new_long as u32);
            old
        }
        GWLP_USERDATA => {
            let old = get_extra(hwnd, |e| e.user_data, 0);
            set_extra(hwnd, |e| e.user_data = dw_new_long);
            old
        }
        GWL_STYLE => window::with_mut(hwnd, |w| {
            let old = w.style as isize;
            w.style = dw_new_long as u32;
            old
        })
        .unwrap_or(0),
        GWL_WNDPROC => {
            let result = window::with_mut(hwnd, |w| {
                let old = w.wnd_proc as isize;
                w.wnd_proc = dw_new_long as usize;
                old
            })
            .unwrap_or(0);
            // Log wndproc changes for Scintilla hwnds — NPP subclasses them; we need to
            // know when the WndProc changes and what it changes to, so that BeginPaint
            // SCI probes know which proc is actually handling SCI_GETDIRECTPOINTER.
            let is_sci = window::with(hwnd, |e| e.class_name == "Scintilla").unwrap_or(false);
            if is_sci {
                eprintln!(
                    "weave/user32: SetWindowLongPtr GWL_WNDPROC hwnd={hwnd:#x} \
                     old={result:#x} new={dw_new_long:#x}"
                );
            }
            result
        }
        _ if n_index >= 0 => {
            // Extra bytes: n_index is a byte offset; writes a pointer-sized (8-byte) value.
            let offset = n_index as usize;
            let mut map = window_extra().lock().unwrap_or_else(|p| p.into_inner());
            if let Some(e) = map.get_mut(&hwnd) {
                if offset + 8 <= e.extra_bytes.len() {
                    let old =
                        isize::from_ne_bytes(e.extra_bytes[offset..offset + 8].try_into().unwrap());
                    e.extra_bytes[offset..offset + 8].copy_from_slice(&dw_new_long.to_ne_bytes());
                    // Log this* storage for Scintilla hwnds at offset 0 (the sci* slot).
                    // This confirms whether Scintilla_WM_NCCREATE ran and stored a valid ptr.
                    let is_sci =
                        window::with(hwnd, |e| e.class_name == "Scintilla").unwrap_or(false);
                    if is_sci && offset == 0 {
                        eprintln!(
                            "weave/user32: SetWindowLongPtr extra[0] hwnd={hwnd:#x} \
                             old={old:#x} new={dw_new_long:#x}"
                        );
                    }
                    old
                } else {
                    eprintln!("weave/user32: SetWindowLongPtr FAIL hwnd={hwnd:#x} offset={offset} extra_bytes.len()={} — too small to store ptr", e.extra_bytes.len());
                    0
                }
            } else {
                eprintln!("weave/user32: SetWindowLongPtr FAIL hwnd={hwnd:#x} offset={offset} — hwnd not in extra map");
                0
            }
        }
        _ => 0,
    }
}

const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;

/// SetWindowPos: change window size, position, and Z order.
///
/// Wine ref: dlls/winex11.drv/window.c — X11DRV_SetWindowPos drives the geometry
/// update; SWP_NOMOVE/SWP_NOSIZE gates which fields change; SWP_SHOWWINDOW /
/// SWP_HIDEWINDOW map to map_window / unmap_window. Z-order (HWND_TOP, etc.) not
/// yet implemented — Weave has no compositor.
pub extern "win64" fn set_window_pos(
    hwnd: usize,
    _hwnd_insert_after: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    u_flags: u32,
) -> i32 {
    const SWP_SHOWWINDOW: u32 = 0x0040;
    const SWP_HIDEWINDOW: u32 = 0x0080;

    eprintln!(
        "weave/user32: SetWindowPos hwnd={hwnd:#x} ({x},{y}) {cx}x{cy} flags={u_flags:#010x}"
    );
    let result = window::with_mut(hwnd, |w| {
        if u_flags & SWP_NOMOVE == 0 {
            w.x = x;
            w.y = y;
        }
        if u_flags & SWP_NOSIZE == 0 {
            w.width = cx as u32;
            w.height = cy as u32;
        }
        if u_flags & SWP_SHOWWINDOW != 0 {
            w.visible = true;
        }
        if u_flags & SWP_HIDEWINDOW != 0 {
            w.visible = false;
        }
        (w.xcb_id, w.x, w.y, w.width, w.height, w.visible)
    });

    if let Some((xcb_id, wx, wy, ww, wh, vis)) = result {
        if xcb_id != 0 {
            backend::configure_window(xcb_id, wx, wy, ww, wh);
            if u_flags & SWP_SHOWWINDOW != 0 {
                backend::show_window(xcb_id, true);
            } else if u_flags & SWP_HIDEWINDOW != 0 {
                backend::show_window(xcb_id, false);
            } else if vis {
                // Ensure the window is mapped if it was already visible.
                backend::show_window(xcb_id, true);
            }
        }
        // Post WM_SIZE so app can update layout state before WM_PAINT.
        // Only post when size actually changes (SWP_NOSIZE not set).
        if u_flags & SWP_NOSIZE == 0 {
            let l_param = (ww as isize) | ((wh as isize) << 16);
            queue::post(MsgEntry {
                hwnd,
                message: WM_SIZE,
                w_param: 0, // SIZE_RESTORED
                l_param,
                time: 0,
                pt_x: 0,
                pt_y: 0,
            });
        }
    }
    1 // TRUE
}

/// BeginDeferWindowPos: begin a batch window-position update.
///
/// Wine ref: dlls/win32u/winpos.c — BeginDeferWindowPos allocates a HDWP
/// (pointer to SMWP struct) with pre-allocated space for n_num_windows entries.
/// Returns NULL on failure.
///
/// Weave implementation: returns a non-null sentinel handle (0x1). We execute
/// each DeferWindowPos call immediately rather than batching (deferred
/// atomicity is a correctness nicety, not required for correctness of layout).
// Wine ref: dlls/win32u/winpos.c — BeginDeferWindowPos allocates SMWP struct with
// n_num_windows pre-allocated entries; returns NULL on allocation failure.
pub extern "win64" fn begin_defer_window_pos(_n_num_windows: i32) -> usize {
    0x1 // non-null sentinel HDWP
}

/// DeferWindowPos: queue a SetWindowPos call for EndDeferWindowPos.
///
/// Wine ref: dlls/win32u/winpos.c — DeferWindowPos appends to the SMWP list;
/// may reallocate. On failure returns NULL (caller should abort).
///
/// Weave: executes immediately via set_window_pos; returns the same HDWP.
pub extern "win64" fn defer_window_pos(
    h_win_pos_info: usize,
    hwnd: usize,
    hwnd_insert_after: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    u_flags: u32,
) -> usize {
    if h_win_pos_info == 0 {
        return 0; // invalid HDWP
    }
    set_window_pos(hwnd, hwnd_insert_after, x, y, cx, cy, u_flags);
    h_win_pos_info
}

/// EndDeferWindowPos: execute all deferred SetWindowPos calls.
///
/// Wine ref: dlls/win32u/winpos.c — EndDeferWindowPos iterates the SMWP list,
/// calls NtUserSetWindowPos for each entry, then frees the HDWP. Returns TRUE.
///
/// Weave: all calls were already executed in DeferWindowPos; just return TRUE.
pub extern "win64" fn end_defer_window_pos(_h_win_pos_info: usize) -> i32 {
    1 // TRUE
}

/// # Safety
/// Pointer arguments, if non-null, must be valid null-terminated wide strings.
// Wine ref: dlls/win32u/window.c — FindWindowW calls NtUserFindWindowEx with hwndParent=0,
// hwndChildAfter=0; searches top-level windows matching class and/or title (both optional;
// NULL means "match any").
pub unsafe extern "win64" fn find_window_w(
    lp_class_name: *const u16,
    lp_window_name: *const u16,
) -> usize {
    let want_class = if lp_class_name.is_null() {
        None
    } else {
        Some(unsafe { decode_wide(lp_class_name) })
    };
    let want_title = if lp_window_name.is_null() {
        None
    } else {
        Some(unsafe { decode_wide(lp_window_name) })
    };
    window::find_with(|_, e| {
        e.style & WS_CHILD == 0
            && want_class.as_deref().is_none_or(|c| e.class_name == c)
            && want_title.as_deref().is_none_or(|t| e.title == t)
    })
}

/// # Safety
/// Pointer arguments, if non-null, must be valid null-terminated ANSI strings.
// Wine ref: dlls/user32/win.c — FindWindowA converts ANSI class/title to wide and calls
// FindWindowExW; same search semantics as FindWindowW.
pub unsafe extern "win64" fn find_window_a(
    lp_class_name: *const u8,
    lp_window_name: *const u8,
) -> usize {
    let want_class = if lp_class_name.is_null() {
        None
    } else {
        Some(unsafe { decode_ansi(lp_class_name) })
    };
    let want_title = if lp_window_name.is_null() {
        None
    } else {
        Some(unsafe { decode_ansi(lp_window_name) })
    };
    window::find_with(|_, e| {
        e.style & WS_CHILD == 0
            && want_class.as_deref().is_none_or(|c| e.class_name == c)
            && want_title.as_deref().is_none_or(|t| e.title == t)
    })
}

// Wine ref: include/ntuser.h::NtUserIsWindow — calls NtUserGetWindowLongW(hwnd, GWL_STYLE);
// returns FALSE for destroyed or invalid handles (server validates via get_user_entry).
pub extern "win64" fn is_window(hwnd: usize) -> i32 {
    if window::with(hwnd, |_| ()).is_some() {
        1
    } else {
        0
    }
}

// Wine ref: dlls/win32u/window.c::is_window_visible — walks parent chain checking WS_VISIBLE
// on each ancestor; returns FALSE if any ancestor is hidden; top message window always hidden.
pub extern "win64" fn is_window_visible(hwnd: usize) -> i32 {
    window::with(hwnd, |w| w.visible as i32).unwrap_or(0)
}

/// # Safety
/// `lpdw_process_id` may be null.
// Wine ref: dlls/win32u/window.c::get_window_thread — returns entry.tid and optionally
// entry.pid; sets ERROR_INVALID_WINDOW_HANDLE and returns 0 for invalid HWND.
pub unsafe extern "win64" fn get_window_thread_process_id(
    hwnd: usize,
    lpdw_process_id: *mut u32,
) -> u32 {
    let tid = window::with(hwnd, |w| w.tid).unwrap_or(0);
    if !lpdw_process_id.is_null() {
        unsafe { *lpdw_process_id = libc::getpid() as u32 };
    }
    tid
}

/// ScreenToClient: convert screen coordinates to client coordinates.
///
/// Wine ref: server/window.c — screen_to_client walks the window parent chain,
/// subtracting each window's client_rect offset from the point until reaching
/// the desktop window. Weave stores window position (x, y) in the window table,
/// where (x, y) is the top-left corner of the window in screen space. The
/// client area starts at (x, y) so we subtract that offset.
///
/// # Safety
/// `lp_point` must point to a valid `Point` (8 bytes) or NULL.
// Wine ref: server/window.c — walks parent chain subtracting client_rect offsets;
// result is point in client coords of hwnd; returns FALSE if hwnd is invalid.
pub unsafe extern "win64" fn screen_to_client(hwnd: usize, lp_point: *mut Point) -> i32 {
    if lp_point.is_null() {
        return 0;
    }
    let (wx, wy) = window::with(hwnd, |w| (w.x, w.y)).unwrap_or((0, 0));
    unsafe {
        (*lp_point).x -= wx;
        (*lp_point).y -= wy;
    }
    1
}

/// ClientToScreen: convert client coordinates to screen coordinates.
///
/// Wine ref: server/window.c — client_to_screen walks the parent chain and
/// adds each window's client_rect.left/top offset. Weave adds the stored
/// window position (x, y).
///
/// # Safety
/// `lp_point` must point to a valid `Point` (8 bytes) or NULL.
// Wine ref: server/window.c — client_to_screen adds each window's client_rect offset up
// the parent chain; inverse of ScreenToClient; returns FALSE if hwnd is invalid.
pub unsafe extern "win64" fn client_to_screen(hwnd: usize, lp_point: *mut Point) -> i32 {
    if lp_point.is_null() {
        return 0;
    }
    let (wx, wy) = window::with(hwnd, |w| (w.x, w.y)).unwrap_or((0, 0));
    unsafe {
        (*lp_point).x += wx;
        (*lp_point).y += wy;
    }
    1
}

// ── Cursor + misc window ops ─────────────────────────────────────────────────

/// # Safety
/// `lp_point` must point to a valid `Point` struct.
// Wine ref: dlls/win32u/driver.c::nulldrv_GetCursorPos — driver entry point; winex11.drv
// queries XQueryPointer; returns screen-space cursor position in POINT.
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

// Wine ref: dlls/win32u/driver.c::loaderdrv_SetCursorPos — delegates to GPU driver;
// winex11.drv calls XWarpPointer to move cursor; returns TRUE on success.
pub extern "win64" fn set_cursor_pos(_x: i32, _y: i32) -> i32 {
    1
}

/// # Safety
/// `lp_rect` must point to a writable `Rect`.
// Wine ref: dlls/win32u/cursoricon.c::NtUserGetClipCursor — returns the active
// clip rectangle (the screen region the cursor is confined to). When no clip is
// set, returns the full virtual-screen bounds. We have no clipping mechanism
// today; return a generous virtual-screen rectangle and TRUE so callers like
// SDL2 (which derefs the rect to compute window-relative coordinates) don't
// segfault. Replacing the previous unresolved-stub behaviour where rax leftover
// was treated as a RECT pointer.
pub unsafe extern "win64" fn get_clip_cursor(lp_rect: *mut crate::defs::Rect) -> i32 {
    if lp_rect.is_null() {
        return 0;
    }
    unsafe {
        (*lp_rect).left = 0;
        (*lp_rect).top = 0;
        (*lp_rect).right = 65535;
        (*lp_rect).bottom = 65535;
    }
    1
}

// Wine ref: dlls/win32u/cursoricon.c::NtUserClipCursor — confines cursor to a
// rectangle (or releases when NULL). No-op stub; return TRUE.
pub extern "win64" fn clip_cursor(_lp_rect: *const crate::defs::Rect) -> i32 {
    1
}

// Wine ref: dlls/win32u/window.c — NtUserEnableWindow sets/clears WS_DISABLED style;
// sends WM_ENABLE(wParam=TRUE/FALSE) before changing state; returns previous disabled state
// (TRUE=1 if the window was previously disabled).
pub extern "win64" fn enable_window(hwnd: usize, b_enable: i32) -> i32 {
    let was_disabled = window::with(hwnd, |w| (w.style & WS_DISABLED) != 0).unwrap_or(false);
    let became_enabled = b_enable != 0 && was_disabled;
    let became_disabled = b_enable == 0 && !was_disabled;
    if became_enabled || became_disabled {
        window::with_mut(hwnd, |w| {
            if b_enable != 0 {
                w.style &= !WS_DISABLED;
            } else {
                w.style |= WS_DISABLED;
            }
        });
        if let Some(proc_addr) = window::with(hwnd, |w| w.wnd_proc) {
            call_wnd_proc(proc_addr, hwnd, WM_ENABLE, b_enable as usize, 0);
        }
    }
    i32::from(was_disabled)
}

// Wine ref: dlls/win32u/window.c — IsWindowEnabled checks !(style & WS_DISABLED);
// also returns FALSE if any ancestor in the chain has WS_DISABLED set.
// Weave: checks the window itself; ancestor check deferred (no multi-level disabled chains in practice).
pub extern "win64" fn is_window_enabled(hwnd: usize) -> i32 {
    window::with(hwnd, |w| i32::from(w.style & WS_DISABLED == 0)).unwrap_or(0)
}

// Wine ref: dlls/win32u/window.c — NtUserGetParent returns owner for top-level windows
// with WS_POPUP, or parent for child windows (WS_CHILD); NULL for top-level non-popup.
// Wine ref: dlls/win32u/window.c::get_parent — WS_POPUP returns owner, WS_CHILD
// returns parent; both map to hwnd_parent in Weave's model. Returns 0 for top-level.
pub extern "win64" fn get_parent(hwnd: usize) -> usize {
    window::with(hwnd, |w| {
        if w.style & (WS_POPUP | WS_CHILD) != 0 {
            w.hwnd_parent
        } else {
            0
        }
    })
    .unwrap_or(0)
}

// Wine ref: dlls/win32u/window.c — NtUserSetParent re-parents a window; returns old parent.
pub extern "win64" fn set_parent(hwnd_child: usize, hwnd_new_parent: usize) -> usize {
    window::with_mut(hwnd_child, |w| {
        let old = w.hwnd_parent;
        w.hwnd_parent = hwnd_new_parent;
        old
    })
    .unwrap_or(0)
}

// Wine ref: dlls/win32u/window.c — BringWindowToTop calls NtUserSetWindowPos with
// HWND_TOP and SWP_NOMOVE|SWP_NOSIZE; brings window to top of Z order.
pub extern "win64" fn bring_window_to_top(_hwnd: usize) -> i32 {
    1
}

// Wine ref: dlls/win32u/window.c — WindowFromPoint calls NtUserWindowFromPoint which
// hit-tests all windows at the point; returns child before parent (WS_CHILD first).
// Wine ref: dlls/win32u/window.c::window_from_point — walks Z-ordered child list;
// returns deepest child containing the point, then top-level if no child matches.
// Weave: two-pass — WS_CHILD windows first, then non-child visible windows.
pub extern "win64" fn window_from_point(pt_x: i32, pt_y: i32) -> usize {
    let hwnds = window::all_hwnds();
    let hit = |style: u32, visible: bool, x: i32, y: i32, w: u32, h: u32| -> bool {
        visible
            && pt_x >= x
            && pt_x < x + w as i32
            && pt_y >= y
            && pt_y < y + h as i32
            && style & WS_DISABLED == 0
    };
    // Pass 1: visible child windows (higher Z-order than parents in Weave's flat model)
    for &hwnd in &hwnds {
        if let Some(true) = window::with(hwnd, |e| {
            e.style & WS_CHILD != 0 && hit(e.style, e.visible, e.x, e.y, e.width, e.height)
        }) {
            return hwnd;
        }
    }
    // Pass 2: visible top-level windows
    for &hwnd in &hwnds {
        if let Some(true) = window::with(hwnd, |e| {
            e.style & WS_CHILD == 0 && hit(e.style, e.visible, e.x, e.y, e.width, e.height)
        }) {
            return hwnd;
        }
    }
    0
}

// ── DPI awareness stubs ───────────────────────────────────────────────────────

/// SetProcessDPIAware: mark the process as DPI-aware.
// Wine ref: dlls/win32u/sysparams.c — sets thread DPI awareness context to
// DPI_AWARENESS_CONTEXT_SYSTEM_AWARE; older API, superseded by SetProcessDpiAwarenessContext.
pub extern "win64" fn set_process_dpi_aware() -> i32 {
    1
}

/// GetDpiForWindow: return the DPI for a window.
///
/// Returns the detected system DPI. Per-window DPI (multi-monitor setups) is
/// not yet implemented — all windows report the primary monitor's DPI.
// Wine ref: dlls/win32u/window.c::get_dpi_for_window — if window is monitor-aware returns
// monitor DPI via get_win_monitor_dpi; otherwise returns context DPI from awareness context.
pub extern "win64" fn get_dpi_for_window(_hwnd: usize) -> u32 {
    crate::backend::system_dpi()
}

/// GetDpiForSystem: return the system DPI.
// Wine ref: dlls/win32u/sysparams.c::get_system_dpi — returns USER_DEFAULT_SCREEN_DPI (96)
// for DPI_AWARENESS_UNAWARE threads; returns actual system_dpi for aware threads.
pub extern "win64" fn get_dpi_for_system() -> u32 {
    crate::backend::system_dpi()
}

/// # Safety
/// `lp_rect` must point to a valid `RECT`.
// Wine ref: dlls/win32u/defwnd.c::adjust_window_rect — DPI-aware version; Weave ignores
// dpi (no per-monitor scaling) and delegates to the shared impl.
pub unsafe extern "win64" fn adjust_window_rect_ex_for_dpi(
    lp_rect: *mut Rect,
    dw_style: u32,
    b_menu: i32,
    dw_ex_style: u32,
    _dpi: u32,
) -> i32 {
    unsafe { adjust_window_rect_impl(lp_rect, dw_style, b_menu, dw_ex_style) }
}

/// SetProcessDpiAwarenessContext: set the DPI awareness context.
// Wine ref: dlls/win32u/sysparams.c — stores value in thread-local DPI awareness context;
// valid values: DPI_AWARENESS_CONTEXT_UNAWARE (-1) through PER_MONITOR_AWARE_V2 (-4).
pub extern "win64" fn set_process_dpi_awareness_context(_value: isize) -> i32 {
    1
}

/// GetDpiAwarenessContextForProcess: get the DPI awareness context for a process.
// Wine ref: dlls/win32u/sysparams.c — returns process-level DPI awareness context as
// a DPI_AWARENESS_CONTEXT handle (encoded isize); -4 = PER_MONITOR_AWARE_V2.
pub extern "win64" fn get_dpi_awareness_context_for_process(_h_process: usize) -> isize {
    -4isize
}

/// AreDpiAwarenessContextsEqual: compare two DPI awareness contexts.
// Wine ref: dlls/win32u/sysparams.c — extracts DPI_AWARENESS from both context handles
// via NTUSER_DPI_CONTEXT_GET_AWARENESS macro and compares them.
pub extern "win64" fn are_dpi_awareness_contexts_equal(
    dpi_context_a: isize,
    dpi_context_b: isize,
) -> i32 {
    (dpi_context_a == dpi_context_b) as i32
}

// ── SHCORE stubs (DPI functions exported by shcore.dll on Win8+) ─────────────

/// GetDpiForMonitor: return the DPI of a specific monitor.
// Wine ref: dlls/shcore/main.c::GetDpiForMonitor — queries monitor DPI from registry
// or defaults to USER_DEFAULT_SCREEN_DPI (96). SDL2 calls this optionally via dynamic
// GetProcAddress; if the function is absent SDL2 falls back to 96 DPI. We always return
// 96 and S_OK so SDL2 treats the monitor as system-DPI-aware without dynamic lookup.
/// # Safety
/// dpi_x and dpi_y must be valid pointers to u32, or null.
pub unsafe extern "win64" fn get_dpi_for_monitor(
    _h_monitor: usize,
    _dpi_type: u32,
    dpi_x: *mut u32,
    dpi_y: *mut u32,
) -> i32 {
    if !dpi_x.is_null() {
        unsafe { *dpi_x = 96 };
    }
    if !dpi_y.is_null() {
        unsafe { *dpi_y = 96 };
    }
    0 // S_OK
}

/// SetProcessDpiAwareness: set DPI awareness for the calling process.
// Wine ref: dlls/shcore/main.c::SetProcessDpiAwareness — validates value (0-2),
// stores it, then calls SetProcessDpiAwarenessInternal. Weave has no per-monitor DPI
// tracking so we accept any value and return S_OK.
pub extern "win64" fn set_process_dpi_awareness(_value: u32) -> i32 {
    0 // S_OK
}

/// GetProcessDpiAwareness: query the DPI awareness of a process.
// Wine ref: dlls/shcore/main.c::GetProcessDpiAwareness — retrieves stored value;
// defaults to PROCESS_DPI_UNAWARE (0) if never set. SDL2 calls this to decide whether
// to scale mouse coordinates. We report PROCESS_SYSTEM_DPI_AWARE (1).
/// # Safety
/// value must be a valid pointer to u32, or null.
pub unsafe extern "win64" fn get_process_dpi_awareness(_h_process: usize, value: *mut u32) -> i32 {
    if !value.is_null() {
        unsafe { *value = 1 }; // PROCESS_SYSTEM_DPI_AWARE
    }
    0 // S_OK
}

// ── Input state stubs ─────────────────────────────────────────────────────────

/// GetKeyState: return the state of a virtual key.
//
// Wine ref: dlls/win32u/input.c SERVER_START_REQ(get_key_state) — bit-packing formula:
//   if (reply->state & 0x80) ret |= 0x8000;  // bit 7 of state byte → bit 15 of SHORT
//   if (reply->state & 0x40) ret |= 0x0001;  // bit 6 (pressed-since-last-call) → bit 0
// Weave uses bit 0 of the VK byte (toggle) directly rather than the transient bit 6.
// Out-of-bounds nVirtKey (> 255 or < 0) returns 0 per Windows behaviour.
pub extern "win64" fn get_key_state(n_virt_key: i32) -> i16 {
    if !(0..=255).contains(&n_virt_key) {
        return 0;
    }
    let state = input::vk_state(n_virt_key as u8);
    // Bit 7 (0x80) → bit 15 (0x8000) of the returned SHORT; bit 0 (toggle) stays at bit 0.
    let high = ((state & 0x80) as i16) << 8;
    let low = (state & 0x01) as i16;
    high | low
}

/// GetAsyncKeyState: return the state of a virtual key (async).
//
// Wine ref: dlls/win32u/input.c SERVER_START_REQ(get_key_state) with async=1 — same
// bit-packing: bit 7 of state byte → bit 15 of SHORT (key currently down).
// Bit 0 (pressed-since-last-call) is always 0 in Weave — we do not track the transient flag.
pub extern "win64" fn get_async_key_state(v_key: i32) -> i16 {
    if !(0..=255).contains(&v_key) {
        return 0;
    }
    let state = input::vk_state(v_key as u8);
    // Only high bit: bit 7 → bit 15; bit 0 always 0 (no pressed-since-last-call tracking).
    ((state & 0x80) as i16) << 8
}

/// MapVirtualKeyW: map a virtual key code to a scan code or character.
//
// Wine ref: dlls/win32u/driver.c::nulldrv_MapVirtualKeyEx — dispatches to keyboard driver;
// MAPVK_VK_TO_VSC (0): VK → scan code; MAPVK_VSC_TO_VK (1): scan → generic VK;
// MAPVK_VK_TO_CHAR (2): VK → unshifted char; MAPVK_VSC_TO_VK_EX (3): scan → VK
// (Wine returns L/R-distinct VKs for 3, but we collapse to generic — same table as 1).
pub extern "win64" fn map_virtual_key_w(u_code: u32, u_map_type: u32) -> u32 {
    // Delegate to the Ex variant with HKL=0 (current layout).
    map_virtual_key_ex_w(u_code, u_map_type, 0)
}

/// MapVirtualKeyExW: map a virtual key code to a scan code or character (extended).
//
// Wine ref: dlls/win32u/driver.c::loaderdrv_MapVirtualKeyEx — layout-aware version of
// MapVirtualKeyW; uses the HKL to pick the keyboard driver for the given layout.
// Weave bakes in US QWERTY only (HKL ignored).
pub extern "win64" fn map_virtual_key_ex_w(u_code: u32, u_map_type: u32, _dwhkl: usize) -> u32 {
    // MAPVK_VK_TO_VSC = 0, MAPVK_VSC_TO_VK = 1, MAPVK_VK_TO_CHAR = 2,
    // MAPVK_VSC_TO_VK_EX = 3 (extended — same result as 1 for Weave).
    match u_map_type {
        0 => {
            // VK → scan code.
            let vk = u_code as u8;
            input::vk_to_vsc(vk) as u32
        }
        1 | 3 => {
            // scan code → VK (generic; L/R pairs collapsed for mode 1).
            let vsc = u_code as u8;
            input::vsc_to_vk(vsc) as u32
        }
        2 => {
            // VK → unshifted character (uppercase for letters).
            let vk = u_code as u8;
            input::vk_to_char(vk) as u32
        }
        _ => 0,
    }
}

/// GetKeyboardLayout: return the keyboard layout for the current thread.
// Wine ref: dlls/win32u/input.c — NtUserGetKeyboardLayout returns HKL for the given thread
// (or calling thread if idThread=0); HKL encodes locale and device in a single handle.
pub extern "win64" fn get_keyboard_layout(_id_thread: u32) -> usize {
    0
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/input.c — GetKeyboardLayoutList fills lpList with HKL handles for
// all loaded layouts; returns count; if nBuff=0 returns count without filling buffer.
pub unsafe extern "win64" fn get_keyboard_layout_list(_n_buff: i32, _lp_list: usize) -> i32 {
    0
}

/// VkKeyScanW: translate a character to a virtual key code.
//
// Wine ref: dlls/win32u/driver.c::nulldrv_VkKeyScanEx — VkKeyScanW calls VkKeyScanExW with
// current HKL; high byte = modifier state (0=none, 1=SHIFT, 2=CTRL); returns -1 (0xFFFF) if
// no mapping exists. Weave bakes in ASCII US QWERTY; non-ASCII or unmapped chars → -1.
pub extern "win64" fn vk_key_scan_w(ch: u16) -> i16 {
    match input::char_to_vk(ch) {
        Some((vk, mods)) => {
            // Pack: low byte = VK code, high byte = modifier flags.
            (((mods as u16) << 8) | (vk as u16)) as i16
        }
        None => -1i16,
    }
}

/// # Safety
/// `lp_key_state` must be a valid pointer to 256 bytes if non-null.
//
// Wine ref: dlls/win32u/input.c::get_async_keyboard_state — copies the 256-byte desktop
// shared-memory keystate array into the caller's buffer via memcpy; returns TRUE on success,
// FALSE (and zeroes the buffer) on server error. Weave reads from the process-global VK_STATE
// table (input::snapshot) — equivalent for our single-process model.
pub unsafe extern "win64" fn get_keyboard_state(lp_key_state: *mut u8) -> i32 {
    if lp_key_state.is_null() {
        return 0; // FALSE — null buffer
    }
    let snap = input::snapshot();
    // SAFETY: caller guarantees `lp_key_state` points to at least 256 bytes.
    unsafe { std::ptr::copy_nonoverlapping(snap.as_ptr(), lp_key_state, 256) };
    1 // TRUE
}

/// # Safety
/// `lp_key_state` must be a valid pointer to a 256-byte key state array when
/// non-zero. `pwsz_buff` must point to a buffer of at least `cch_buff` UTF-16
/// code units when non-zero and `cch_buff > 0`.
// Wine ref: dlls/win32u/input.c — ToUnicodeEx translates VK+scan+keystate to Unicode via
// keyboard driver; returns char count (1+), 0 (no translation), or -1 (dead key).
// Shift state: keystate[VK_SHIFT=0x10] bit 0x80 set → uppercase/shifted character.
// dwhkl (keyboard layout handle) is ignored — US QWERTY is the only supported layout.
pub unsafe extern "win64" fn to_unicode_ex(
    w_virt_key: u32,
    _w_scan_code: u32,
    lp_key_state: usize,
    pwsz_buff: usize,
    cch_buff: i32,
    _w_flags: u32,
    _dwhkl: usize,
) -> i32 {
    // Guard: null output buffer or zero capacity → no translation.
    if pwsz_buff == 0 || cch_buff <= 0 {
        return 0;
    }

    // Extract shift state from keystate[VK_SHIFT = 0x10].
    // If lp_key_state is null we treat shift as not held.
    let shift = if lp_key_state != 0 {
        let byte = unsafe { *(lp_key_state as *const u8).add(0x10) };
        byte & 0x80 != 0
    } else {
        false
    };

    match crate::input::vk_to_char_shifted(w_virt_key as u8, shift) {
        Some(ch) => {
            unsafe { *(pwsz_buff as *mut u16) = ch };
            1
        }
        None => 0,
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Call a window procedure (stored as `usize`) with `extern "win64"` ABI.
fn call_wnd_proc(proc_addr: usize, hwnd: usize, msg: u32, w_param: usize, l_param: isize) -> isize {
    if proc_addr == 0 {
        return 0;
    }
    // SAFETY: `proc_addr` is a window-procedure address registered by the PE guest
    // via `RegisterClassExW` or `CreateWindowExW`, both of which store the raw
    // `WNDPROC` value the guest supplied.  The Win32 API contract requires a WNDPROC
    // to have the signature `LRESULT CALLBACK(HWND, UINT, WPARAM, LPARAM)`, which
    // maps to `extern "win64" fn(usize, u32, usize, isize) -> isize` on x86-64
    // Windows.  The non-zero guard at the top of this function ensures `proc_addr`
    // is not null.  Transmuting a non-null `usize` VA to a Win64 fn pointer is the
    // standard Weave pattern for invoking all guest callbacks stored in the IAT or
    // class/window registries.
    let f: unsafe extern "win64" fn(usize, u32, usize, isize) -> isize =
        unsafe { std::mem::transmute(proc_addr) };
    unsafe { f(hwnd, msg, w_param, l_param) }
}

/// Write a `MsgEntry` into the caller-provided `MSG` buffer.
///
/// # Safety
/// `lp_msg` must be a valid writable pointer.
unsafe fn fill_msg(lp_msg: *mut Msg, entry: &MsgEntry) {
    // Record last message time and position for GetMessageTime/GetMessagePos.
    LAST_MSG_TIME.store(entry.time, Ordering::Relaxed);
    LAST_MSG_POS_X.store(entry.pt_x, Ordering::Relaxed);
    LAST_MSG_POS_Y.store(entry.pt_y, Ordering::Relaxed);
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

// ── ANSI window class wrappers ────────────────────────────────────────────────

/// RegisterClassA: ANSI variant — converts class name to wide and calls through.
///
/// # Safety
/// `lp_wnd_class` must point to a valid `WNDCLASSA` struct.
// Wine ref: dlls/user32/class.c — RegisterClassA converts lpszClassName/lpszMenuName to
// UNICODE_STRING then calls NtUserRegisterClassExWOW with IS_ANSI flag set.
pub unsafe extern "win64" fn register_class_a(lp_wnd_class: *const WndClassA) -> u16 {
    if lp_wnd_class.is_null() {
        return 0;
    }
    let wc = unsafe { &*lp_wnd_class };
    let name = unsafe { decode_ansi(wc.lpsz_class_name) };
    if name.is_empty() {
        return 0;
    }
    class::register(
        &name,
        class::ClassEntry {
            wnd_proc: wc.lpfn_wnd_proc,
            style: wc.style,
            h_cursor: wc.h_cursor,
            hbr_background: wc.hbr_background,
            cb_wnd_extra: wc.cb_wnd_extra.max(0) as u32,
            h_icon: 0,
            h_icon_sm: 0,
        },
    );
    name_to_atom(&name)
}

/// RegisterClassExA: ANSI extended variant.
///
/// # Safety
/// `lp_wnd_class_ex` must point to a valid `WNDCLASSEXA` struct.
// Wine ref: dlls/user32/class.c — RegisterClassExA uses init_class_name_ansi to convert
// lpszClassName; validates cbSize == sizeof(WNDCLASSEXA); delegates to NtUserRegisterClassExWOW.
pub unsafe extern "win64" fn register_class_ex_a(lp_wnd_class_ex: *const WndClassExA) -> u16 {
    if lp_wnd_class_ex.is_null() {
        return 0;
    }
    let wc = unsafe { &*lp_wnd_class_ex };
    let name = unsafe { decode_ansi(wc.lpsz_class_name) };
    if name.is_empty() {
        return 0;
    }
    class::register(
        &name,
        class::ClassEntry {
            wnd_proc: wc.lpfn_wnd_proc,
            style: wc.style,
            h_cursor: wc.h_cursor,
            hbr_background: wc.hbr_background,
            cb_wnd_extra: wc.cb_wnd_extra.max(0) as u32,
            h_icon: 0,
            h_icon_sm: 0,
        },
    );
    name_to_atom(&name)
}

// ── ANSI window creation ──────────────────────────────────────────────────────

/// CreateWindowExA: ANSI variant — converts string args and calls through.
///
/// # Safety
/// String pointer arguments must be null or valid null-terminated ANSI strings.
// Wine ref: dlls/user32/win.c::CreateWindowExA — converts class/title to wide via
// RtlCreateUnicodeStringFromAsciiz then delegates to WIN_CreateWindowEx with unicode=FALSE.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn create_window_ex_a(
    dw_ex_style: u32,
    lp_class_name: *const u8,
    lp_window_name: *const u8,
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
    let class_name = unsafe { decode_ansi(lp_class_name) };
    let title = unsafe { decode_ansi(lp_window_name) };

    let cls = match class::find(&class_name) {
        Some(c) => c,
        None => {
            eprintln!("weave/user32: CreateWindowExA: unknown class '{class_name}'");
            return 0;
        }
    };

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

    let (abs_x, abs_y) = if (dw_style & WS_CHILD) != 0 && h_wnd_parent != 0 {
        let parent_pos = window::with(h_wnd_parent, |e| (e.x, e.y)).unwrap_or((0, 0));
        (pos_x + parent_pos.0, pos_y + parent_pos.1)
    } else {
        (pos_x, pos_y)
    };

    let (x11_x, x11_y, parent_xcb_id) = if (dw_style & WS_CHILD) != 0 && h_wnd_parent != 0 {
        let px = window::xcb_id(h_wnd_parent);
        if px != 0 {
            (pos_x, pos_y, px)
        } else {
            (abs_x, abs_y, 0u32)
        }
    } else {
        (pos_x, pos_y, 0u32)
    };

    let xcb_id =
        backend::create_window(&title, x11_x, x11_y, width, height, visible, parent_xcb_id);

    eprintln!("weave/user32: CreateWindowA class={class_name:?} title={title:?} pos=({abs_x},{abs_y}) size={width}x{height} visible={visible} style={dw_style:#010x} xcb={xcb_id:#x} parent_xcb={parent_xcb_id:#x}");

    let hwnd = window::create(window::WindowEntry {
        class_name: class_name.clone(),
        wnd_proc: cls.wnd_proc,
        title: title.clone(),
        style: dw_style,
        x: abs_x,
        y: abs_y,
        width,
        height,
        visible,
        xcb_id,
        h_menu: h_menu_param,
        hwnd_parent: h_wnd_parent,
        tid: unsafe { libc::syscall(libc::SYS_gettid) as u32 },
    });
    set_extra(hwnd, |e| {
        e.ex_style = dw_ex_style;
        e.extra_bytes = vec![0u8; cls.cb_wnd_extra as usize];
    });

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

// ── ANSI message loop ─────────────────────────────────────────────────────────

/// GetMessageA: ANSI variant — identical to W (MSG has no string fields).
///
/// # Safety
/// `lp_msg` must be a valid writable `MSG` pointer.
// Wine ref: dlls/user32/message.c::GetMessageA — calls NtUserGetMessage; MSG struct is
// identical for A/W (no embedded strings); ANSI/W difference only matters for WM_CHAR.
pub unsafe extern "win64" fn get_message_a(
    lp_msg: *mut Msg,
    h_wnd: usize,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
) -> i32 {
    unsafe { get_message_w(lp_msg, h_wnd, w_msg_filter_min, w_msg_filter_max) }
}

/// PeekMessageA: ANSI variant — identical to W.
///
/// # Safety
/// `lp_msg` must be a valid writable `MSG` pointer.
// Wine ref: dlls/user32/message.c::PeekMessageA — calls NtUserPeekMessage; translates
// WM_CHAR wParam from Unicode to ANSI via WM_CHAR_MAPPING table if needed.
pub unsafe extern "win64" fn peek_message_a(
    lp_msg: *mut Msg,
    h_wnd: usize,
    w_msg_filter_min: u32,
    w_msg_filter_max: u32,
    w_remove_msg: u32,
) -> i32 {
    unsafe {
        peek_message_w(
            lp_msg,
            h_wnd,
            w_msg_filter_min,
            w_msg_filter_max,
            w_remove_msg,
        )
    }
}

/// DispatchMessageA: ANSI variant — identical to W.
///
/// # Safety
/// `lp_msg` must be a valid `MSG` pointer.
// Wine ref: dlls/user32/message.c::dispatch_message — calls WINPROC_CallProcAtoW for ANSI
// window procs; WM_CHAR wParam is converted from ANSI to Unicode before dispatch.
pub unsafe extern "win64" fn dispatch_message_a(lp_msg: *const Msg) -> isize {
    unsafe { dispatch_message_w(lp_msg) }
}

/// PostMessageA: ANSI variant.
// Wine ref: dlls/win32u/message.c — PostMessageA calls NtUserPostMessage; for string
// messages (WM_SETTEXT etc.) duplicates the string buffer for async delivery.
pub extern "win64" fn post_message_a(
    h_wnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> i32 {
    post_message_w(h_wnd, msg, w_param, l_param)
}

/// SendMessageA: ANSI variant.
// Wine ref: dlls/win32u/message.c — SendMessageA sets up send_message_info with MSG_ANSI
// type; WINPROC thunk converts string params A→W before calling Unicode WNDPROC.
pub extern "win64" fn send_message_a(
    h_wnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    send_message_w(h_wnd, msg, w_param, l_param)
}

/// DefWindowProcA: ANSI variant — forwards to W implementation.
// Wine ref: dlls/win32u/defwnd.c — DefWindowProcA is identical to DefWindowProcW; all
// internal processing is Unicode; ANSI callers go through the same DefWndProc handler.
pub extern "win64" fn def_window_proc_a(
    h_wnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    def_window_proc_w(h_wnd, msg, w_param, l_param)
}

// ── ANSI window text / class ──────────────────────────────────────────────────

/// GetWindowTextA: copy window title as ANSI into buffer.
///
/// # Safety
/// `lp_string` must be a writable buffer of at least `n_max_count` bytes.
// Wine ref: server/window.c::get_window_text — GetWindowTextA retrieves Unicode text then
// converts to ANSI via WideCharToMultiByte; result may be shorter than Unicode length.
pub unsafe extern "win64" fn get_window_text_a(
    h_wnd: usize,
    lp_string: *mut u8,
    n_max_count: i32,
) -> i32 {
    if lp_string.is_null() || n_max_count <= 0 {
        return 0;
    }
    let title = window::with(h_wnd, |w| w.title.clone()).unwrap_or_default();
    let bytes = title.as_bytes();
    let copy = bytes.len().min((n_max_count - 1) as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_string, copy);
        *lp_string.add(copy) = 0;
    }
    copy as i32
}

/// GetWindowTextLengthA: return character count of window title (ANSI).
// Wine ref: dlls/win32u/window.c — GetWindowTextLengthA calls NtUserGetWindowTextLength
// which returns UTF-16 length; ANSI length may differ for non-ASCII window titles.
pub extern "win64" fn get_window_text_length_a(h_wnd: usize) -> i32 {
    window::with(h_wnd, |w| w.title.len() as i32).unwrap_or(0)
}

/// GetWindowLongPtrA: ANSI variant — identical to W.
// Wine ref: dlls/win32u/window.c — GetWindowLongPtrA dispatches to get_window_long_size;
// for GWLP_WNDPROC returns ANSI thunk address (not the raw WNDPROC) for ANSI windows.
pub extern "win64" fn get_window_long_ptr_a(hwnd: usize, n_index: i32) -> isize {
    get_window_long_ptr_w(hwnd, n_index)
}

/// SetWindowLongPtrA: ANSI variant — identical to W.
// Wine ref: dlls/win32u/window.c — SetWindowLongPtrA for GWLP_WNDPROC stores ANSI thunk;
// returns old value; triggers WM_STYLECHANGING/WM_STYLECHANGED for GWL_STYLE.
pub extern "win64" fn set_window_long_ptr_a(
    hwnd: usize,
    n_index: i32,
    dw_new_long: isize,
) -> isize {
    set_window_long_ptr_w(hwnd, n_index, dw_new_long)
}

/// SetClassLongPtrW: modify a class attribute for the class associated with hwnd.
///
/// # Safety
/// hwnd must be a valid HWND created by this process.
// Wine ref: dlls/win32u/class.c::set_class_long_size — returns old value; GCLP_WNDPROC
// replaces class wndproc for all future windows; GCLP_HCURSOR/HBRBACKGROUND/HICON set
// their respective class fields. A/W are identical for integer nIndex values.
pub unsafe extern "win64" fn set_class_long_ptr_w(
    hwnd: usize,
    n_index: i32,
    dw_new_long: isize,
) -> isize {
    let class_name = match window::with(hwnd, |e| e.class_name.clone()) {
        Some(n) => n,
        None => return 0,
    };
    class::set_long(&class_name, n_index, dw_new_long as usize) as isize
}

/// SetClassLongPtrA: ANSI variant — delegates to W.
///
/// # Safety
/// hwnd must be a valid HWND created by this process.
// Wine ref: dlls/win32u/class.c — A and W are identical for integer nIndex values.
pub unsafe extern "win64" fn set_class_long_ptr_a(
    hwnd: usize,
    n_index: i32,
    dw_new_long: isize,
) -> isize {
    unsafe { set_class_long_ptr_w(hwnd, n_index, dw_new_long) }
}

/// GetClassLongPtrW: read a class attribute.
// Wine ref: dlls/win32u/class.c::get_class_long_size — reads per-class data by nIndex;
// returns 0 for unknown nIndex.
pub extern "win64" fn get_class_long_ptr_w(hwnd: usize, n_index: i32) -> usize {
    let class_name = match window::with(hwnd, |e| e.class_name.clone()) {
        Some(n) => n,
        None => return 0,
    };
    class::get_long(&class_name, n_index)
}

/// GetClassLongPtrA: ANSI variant — delegates to W.
// Wine ref: dlls/win32u/class.c — A and W are identical for integer nIndex values.
pub extern "win64" fn get_class_long_ptr_a(hwnd: usize, n_index: i32) -> usize {
    get_class_long_ptr_w(hwnd, n_index)
}

/// GetClassNameW: retrieve the registered class name for the window identified by hwnd.
///
/// Copies the class name string (stored in WindowEntry::class_name) into the caller-supplied
/// UTF-16 buffer. Returns the number of UTF-16 code units copied (excluding the null
/// terminator), or 0 on failure (invalid hwnd, null buffer, or zero capacity).
///
/// # Safety
/// `lp_class_name` must point to a writable buffer of at least `n_max_count` UTF-16 code
/// units. `n_max_count` must be positive.
// Wine ref: dlls/win32u/class.c::NtUserGetClassName — copies class->name into caller buffer
// with WideCharToMultiByte conversion for A variant; W variant copies UTF-16 directly;
// returns char count excluding NUL, 0 on failure (invalid hwnd or zero-length buffer).
pub unsafe extern "win64" fn get_class_name_w(
    hwnd: usize,
    lp_class_name: *mut u16,
    n_max_count: i32,
) -> i32 {
    if lp_class_name.is_null() || n_max_count <= 0 {
        return 0;
    }
    let class_name = match window::with(hwnd, |e| e.class_name.clone()) {
        Some(n) => n,
        None => return 0,
    };
    let wide: Vec<u16> = class_name.encode_utf16().collect();
    // Copy up to n_max_count-1 code units so there is always room for the NUL terminator.
    let copy_len = wide.len().min((n_max_count as usize).saturating_sub(1));
    // SAFETY: caller guarantees buffer is valid for n_max_count u16 units.
    unsafe {
        for (i, &cu) in wide[..copy_len].iter().enumerate() {
            *lp_class_name.add(i) = cu;
        }
        *lp_class_name.add(copy_len) = 0;
    }
    copy_len as i32
}

/// GetClassNameA: ANSI variant — decodes the stored UTF-16 class name to ANSI bytes.
///
/// # Safety
/// `lp_class_name` must point to a writable buffer of at least `n_max_count` bytes.
// Wine ref: dlls/win32u/class.c::NtUserGetClassName — A path converts UTF-16 class name
// to multibyte via WideCharToMultiByte; Weave uses a direct ASCII downcast (class names
// are always ASCII in practice) with the same length-excluding-NUL return convention.
pub unsafe extern "win64" fn get_class_name_a(
    hwnd: usize,
    lp_class_name: *mut u8,
    n_max_count: i32,
) -> i32 {
    if lp_class_name.is_null() || n_max_count <= 0 {
        return 0;
    }
    let class_name = match window::with(hwnd, |e| e.class_name.clone()) {
        Some(n) => n,
        None => return 0,
    };
    // Class names are always ASCII; safe to cast each UTF-16 code unit to u8.
    let bytes: Vec<u8> = class_name
        .encode_utf16()
        .map(|cu| if cu < 0x80 { cu as u8 } else { b'?' })
        .collect();
    let copy_len = bytes.len().min((n_max_count as usize).saturating_sub(1));
    // SAFETY: caller guarantees buffer is valid for n_max_count bytes.
    unsafe {
        for (i, &b) in bytes[..copy_len].iter().enumerate() {
            *lp_class_name.add(i) = b;
        }
        *lp_class_name.add(copy_len) = 0;
    }
    copy_len as i32
}

/// EnumChildWindows: invoke lpEnumFunc for each direct child of hwndParent.
///
/// # Safety
/// `lp_enum_func` must be a valid guest WNDENUMPROC callable with win64 ABI.
// Wine ref: dlls/user32/win.c::enum_windows — children=TRUE path; returns FALSE (0) on
// empty list; stops enumeration when callback returns FALSE (0); callback signature is
// BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam).
pub unsafe extern "win64" fn enum_child_windows(
    hwnd_parent: usize,
    lp_enum_func: usize,
    l_param: isize,
) -> i32 {
    if lp_enum_func == 0 {
        return 0;
    }
    let children: Vec<usize> = window::all_hwnds()
        .into_iter()
        .filter(|&h| window::with(h, |e| e.hwnd_parent == hwnd_parent).unwrap_or(false))
        .collect();
    if children.is_empty() {
        return 0;
    }
    let callback: unsafe extern "win64" fn(usize, isize) -> i32 = std::mem::transmute(lp_enum_func);
    for child in children {
        let ret = unsafe { callback(child, l_param) };
        if ret == 0 {
            return 0;
        }
    }
    1
}

// ── ANSI resource loading ─────────────────────────────────────────────────────

/// Convert an ANSI resource-identifier pointer into a 64-bit value suitable
/// for passing through the W-family trampoline. Ordinals (IS_INTRESOURCE)
/// pass through unchanged; string pointers are widened in-place to a fresh
/// UTF-16 `Vec` whose pointer is returned (caller must keep the `Vec`
/// alive for the duration of the W-side call).
///
/// # Safety
/// If the caller intends the string path, `ptr` must be a valid NUL-terminated
/// ANSI string.
unsafe fn widen_ansi_name(ptr: *const u8) -> (usize, Option<Vec<u16>>) {
    let raw = ptr as usize;
    if raw >> 16 == 0 {
        return (raw, None);
    }
    // SAFETY: caller contract above.
    let mut bytes: Vec<u8> = Vec::new();
    unsafe {
        let mut p = ptr;
        for _ in 0..32_768 {
            let b = *p;
            if b == 0 {
                break;
            }
            bytes.push(b);
            p = p.add(1);
        }
    }
    let mut wide: Vec<u16> = bytes.iter().map(|&b| b as u16).collect();
    wide.push(0);
    let addr = wide.as_ptr() as usize;
    (addr, Some(wide))
}

/// LoadIconA: ANSI trampoline into `load_icon_w`.
///
/// # Safety
/// `lp_icon_name` (if non-null and non-INTRESOURCE) must be a valid
/// null-terminated ANSI string.
// Wine ref: dlls/user32/cursoricon.c — LoadIconA converts lpIconName to wide
// via MultiByteToWideChar and calls LoadIconW; the MAKEINTRESOURCE fast path
// never touches the pointer.
pub unsafe extern "win64" fn load_icon_a(h_instance: usize, lp_icon_name: *const u8) -> usize {
    // SAFETY: forward caller contract.
    let (raw, _keepalive) = unsafe { widen_ansi_name(lp_icon_name) };
    // SAFETY: raw is either an ordinal (IS_INTRESOURCE) or points at the
    // kept-alive UTF-16 buffer held in `_keepalive`.
    unsafe { load_icon_w(h_instance, raw) }
}

/// LoadCursorA: ANSI trampoline into `load_cursor_w`.
///
/// # Safety
/// `lp_cursor_name` (if non-null and non-INTRESOURCE) must be a valid
/// null-terminated ANSI string.
// Wine ref: dlls/user32/cursoricon.c — LoadCursorA widens name and calls
// LoadCursorW; ordinal path skips widening.
pub unsafe extern "win64" fn load_cursor_a(h_instance: usize, lp_cursor_name: *const u8) -> usize {
    // SAFETY: forward caller contract.
    let (raw, _keepalive) = unsafe { widen_ansi_name(lp_cursor_name) };
    // SAFETY: same contract as load_icon_a.
    unsafe { load_cursor_w(h_instance, raw) }
}

/// LoadImageA: ANSI trampoline into `load_image_w`.
///
/// # Safety
/// `name` (if non-null and non-INTRESOURCE) must be a valid null-terminated
/// ANSI string.
// Wine ref: dlls/user32/cursoricon.c — LoadImageA converts name to wide then
// calls NtUserLoadImage/LoadImageW; LR_LOADFROMFILE flag is honored before
// the widen step but that path is out of scope for Task 10.
pub unsafe extern "win64" fn load_image_a(
    h_inst: usize,
    name: *const u8,
    ty: u32,
    cx: i32,
    cy: i32,
    fu_load: u32,
) -> usize {
    // SAFETY: forward caller contract.
    let (raw, _keepalive) = unsafe { widen_ansi_name(name) };
    // SAFETY: raw validity held by `_keepalive` when non-INTRESOURCE.
    unsafe { load_image_w(h_inst, raw, ty, cx, cy, fu_load) }
}

/// DestroyIcon: free an HICON. Stub — always succeeds.
// Wine ref: dlls/win32u/cursoricon.c — NtUserDestroyCursor decrements refcount on the
// CURSORICONCACHE entry; frees backing bitmaps when count reaches zero.
pub extern "win64" fn destroy_icon(_h_icon: usize) -> i32 {
    1
}

// ── ANSI message box ──────────────────────────────────────────────────────────

/// MessageBoxA: ANSI variant — returns IDOK.
///
/// # Safety
/// String pointer arguments must be null or valid null-terminated ANSI strings.
// Wine ref: dlls/user32/dialog.c — MessageBoxA converts text/caption to wide via
// MultiByteToWideChar then calls MessageBoxW; same IDOK/IDCANCEL/etc return values.
pub unsafe extern "win64" fn message_box_a(
    h_wnd: usize,
    lp_text: *const u8,
    lp_caption: *const u8,
    u_type: u32,
) -> i32 {
    let text = unsafe { decode_ansi(lp_text) };
    let caption = unsafe { decode_ansi(lp_caption) };
    eprintln!("weave/user32: MessageBoxA(hwnd={h_wnd:#x}, caption={caption:?}, text={text:?}, type={u_type:#x})");
    1 // IDOK
}

/// MessageBoxIndirectW: extended message box. Returns IDOK.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/user32/dialog.c — MessageBoxIndirectW reads MSGBOXPARAMSW to get hook
// proc, icon, and help context; runs dialog via DIALOG_DoDialogBox.
pub unsafe extern "win64" fn message_box_indirect_w(_lp_msgboxparams: usize) -> i32 {
    1 // IDOK
}

// ── ANSI menu helpers ─────────────────────────────────────────────────────────

/// AppendMenuA: ANSI variant — converts text and calls through.
///
/// # Safety
/// `lp_new_item` may be a string, bitmap, or other resource pointer.
// Wine ref: dlls/win32u/menu.c — AppendMenuA converts string via RtlCreateUnicodeStringFromAsciiz
// then calls NtUserThunkedMenuItemInfo; MF_SEPARATOR/MF_POPUP/MF_BITMAP change lpNewItem type.
pub unsafe extern "win64" fn append_menu_a(
    h_menu: usize,
    u_flags: u32,
    u_id_new_item: usize,
    lp_new_item: *const u8,
) -> i32 {
    const MF_POPUP: u32 = 0x0010;
    const MF_SEPARATOR: u32 = 0x0800;
    const MF_BITMAP: u32 = 0x0004;
    let is_string = (u_flags & (MF_SEPARATOR | MF_POPUP | MF_BITMAP)) == 0;
    let text = if is_string && !lp_new_item.is_null() {
        unsafe { decode_ansi(lp_new_item) }
    } else {
        String::new()
    };
    menu::append_menu_raw(h_menu, u_flags, u_id_new_item, text);
    1
}

/// InsertMenuA: ANSI variant of InsertMenu.
///
/// # Safety
/// `lp_new_item` may be a string pointer.
// Wine ref: dlls/win32u/menu.c — InsertMenuA calls NtUserThunkedMenuItemInfo with
// uPosition as insertion point; MF_BYCOMMAND or MF_BYPOSITION controls lookup mode.
pub unsafe extern "win64" fn insert_menu_a(
    h_menu: usize,
    u_position: u32,
    u_flags: u32,
    u_id_new_item: usize,
    lp_new_item: *const u8,
) -> i32 {
    // Simplified: forward to AppendMenuA — position ignored for now.
    let _ = u_position;
    unsafe { append_menu_a(h_menu, u_flags, u_id_new_item, lp_new_item) }
}

/// GetSystemMenu: return the system (window) menu handle.
///
/// For Weave we allocate a real menu entry so callers can append to it safely.
// Wine ref: dlls/win32u/menu.c::get_win_sys_menu — returns window's system menu HMENU;
// bRevert=TRUE resets to default; system menu is separate from the window menu bar.
pub extern "win64" fn get_system_menu(h_wnd: usize, b_revert: i32) -> usize {
    if b_revert != 0 {
        // Revert to default — we don't track the original, just return current.
        return window::with(h_wnd, |w| w.h_menu).unwrap_or(0);
    }
    window::with(h_wnd, |w| if w.h_menu != 0 { w.h_menu } else { 0 })
        .unwrap_or_else(|| menu::create_menu())
}

/// DeleteMenu: remove an item from a menu.
// Wine ref: dlls/win32u/menu.c — NtUserDeleteMenu removes item by position or command ID;
// MF_POPUP submenus are NOT destroyed (caller must DestroyMenu them separately).
pub extern "win64" fn delete_menu(h_menu: usize, u_position: u32, u_flags: u32) -> i32 {
    menu::delete_item(h_menu, u_position, u_flags);
    1
}

// ── Dialog stubs ──────────────────────────────────────────────────────────────

/// DefDlgProcA: default dialog procedure (ANSI). Forwards to DefWindowProcW.
// Wine ref: dlls/user32/dialog.c — DefDlgProcA/W handles WM_INITDIALOG, WM_NEXTDLGCTL,
// WM_GETFONT, WM_SETFONT; tab key navigation between dialog controls via IsDialogMessage.
pub extern "win64" fn def_dlg_proc_a(
    h_dlg: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    def_window_proc_w(h_dlg, msg, w_param, l_param)
}

/// DialogBoxParamA: create and show a modal dialog box.
///
/// Returns IDCANCEL — Weave does not implement dialog templates.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/user32/dialog.c — DialogBoxParamA loads template from resources, creates
// window, calls WM_INITDIALOG with dwInitParam, runs modal loop until EndDialog.
pub unsafe extern "win64" fn dialog_box_param_a(
    _h_instance: usize,
    _lp_template_name: *const u8,
    _hwnd_parent: usize,
    _lp_dialog_func: usize,
    _dw_init_param: isize,
) -> i32 {
    eprintln!("weave/user32: DialogBoxParamA → IDCANCEL (dialog templates not implemented)");
    2 // IDCANCEL
}

/// CreateDialogParamW: create a modeless dialog box.
///
/// Wine ref: dlls/user32/dialog.c::CreateDialogParamW — loads dialog template from PE
/// resources, creates dialog window, calls WM_INITDIALOG with dw_init_param as lParam.
/// Weave cannot parse PE dialog templates, so we create a minimal invisible window with
/// the given DLGPROC and call WM_INITDIALOG, satisfying the non-NULL return requirement.
///
/// # Safety
/// `lp_dialog_func` must be a valid `DLGPROC` if non-zero.
// Wine ref: dlls/user32/dialog.c::CreateDialogParamW — loads DLGTEMPLATE from PE resources,
// creates modeless dialog window, sends WM_INITDIALOG with lParam; returns HWND (not modal).
pub unsafe extern "win64" fn create_dialog_param_w(
    _h_instance: usize,
    _lp_template_name: *const u16,
    hwnd_parent: usize,
    lp_dialog_func: usize,
    dw_init_param: isize,
) -> usize {
    if lp_dialog_func == 0 {
        return 0;
    }
    // Create a minimal invisible window in the window table with the DLGPROC as wnd_proc.
    // No X11 window is created (xcb_id=0) — dialog is purely logical.
    let hwnd = window::create(window::WindowEntry {
        class_name: "#32770".to_string(),
        wnd_proc: lp_dialog_func,
        title: String::new(),
        style: 0x4000_0000, // WS_CLIPSIBLINGS
        x: 0,
        y: 0,
        width: 1,
        height: 1,
        visible: false,
        xcb_id: 0,
        h_menu: 0,
        hwnd_parent,
        tid: unsafe { libc::syscall(libc::SYS_gettid) as u32 },
    });
    // Call WM_INITDIALOG (0x0110) with hwnd_parent as wParam, dw_init_param as lParam.
    // Wine ref: dlls/user32/dialog.c — WM_INITDIALOG return value is ignored for
    // CreateDialogParam (only used by DialogBox modal variant).
    let fn_ptr: unsafe extern "win64" fn(usize, u32, usize, isize) -> i32 =
        unsafe { std::mem::transmute(lp_dialog_func) };
    let _ = unsafe { fn_ptr(hwnd, 0x0110, hwnd_parent, dw_init_param) };
    eprintln!("weave/user32: CreateDialogParamW → hwnd={hwnd:#x}");
    hwnd
}

/// CreateDialogParamA: create a modeless dialog box.
///
/// Wine ref: dlls/user32/dialog.c::CreateDialogParamA — converts template name to wide
/// and delegates to CreateDialogParamW. Weave: same minimal stub as the W variant.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_dialog_param_a(
    _h_instance: usize,
    _lp_template_name: *const u8,
    _hwnd_parent: usize,
    _lp_dialog_func: usize,
    _dw_init_param: isize,
) -> usize {
    0
}

/// CreateDialogIndirectParamW: create a modeless dialog box from a DLGTEMPLATE pointer.
///
/// Wine ref: dlls/user32/dialog.c::DIALOG_CreateIndirect — takes raw DLGTEMPLATE pointer
/// (not a resource name); first check is `if (!dlgTemplate) return 0;`; modal_owner=NULL
/// for CreateDialogIndirect (modeless); passes through DIALOG_CreateIndirect then returns
/// HWND. Weave: null-checks template, then mirrors create_dialog_param_w stub body.
///
/// # Safety
/// `lp_template` must be a valid DLGTEMPLATE pointer if non-null.
/// `lp_dialog_func` must be a valid `DLGPROC` if non-zero.
// Wine ref: dlls/user32/dialog.c::DIALOG_CreateIndirect — null template → return 0;
// modal_owner=NULL distinguishes CreateDialogIndirect (modeless) from DialogBoxIndirect (modal).
pub unsafe extern "win64" fn create_dialog_indirect_param_w(
    _h_instance: usize,
    lp_template: *const u8,
    hwnd_parent: usize,
    lp_dialog_func: usize,
    dw_init_param: isize,
) -> usize {
    if lp_template.is_null() {
        return 0;
    }
    if lp_dialog_func == 0 {
        return 0;
    }
    // Create a minimal invisible window in the window table with the DLGPROC as wnd_proc.
    // No X11 window is created (xcb_id=0) — dialog is purely logical.
    let hwnd = window::create(window::WindowEntry {
        class_name: "#32770".to_string(),
        wnd_proc: lp_dialog_func,
        title: String::new(),
        style: 0x4000_0000, // WS_CLIPSIBLINGS
        x: 0,
        y: 0,
        width: 1,
        height: 1,
        visible: false,
        xcb_id: 0,
        h_menu: 0,
        hwnd_parent,
        tid: unsafe { libc::syscall(libc::SYS_gettid) as u32 },
    });
    // Call WM_INITDIALOG (0x0110) with hwnd_parent as wParam, dw_init_param as lParam.
    let fn_ptr: unsafe extern "win64" fn(usize, u32, usize, isize) -> i32 =
        unsafe { std::mem::transmute(lp_dialog_func) };
    let _ = unsafe { fn_ptr(hwnd, 0x0110, hwnd_parent, dw_init_param) };
    eprintln!("weave/user32: CreateDialogIndirectParamW → hwnd={hwnd:#x}");
    hwnd
}

/// DialogBoxIndirectParamW: display a modal dialog box from a DLGTEMPLATE pointer (Wide).
///
/// # Safety
/// `lp_template` must point at a valid DLGTEMPLATE when non-null.
// Wine ref: dlls/user32/dialog.c::DialogBoxIndirectParamW — DIALOG_CreateIndirect then
// DIALOG_DoDialogBox; returns EndDialog nResult or -1 on error.
pub unsafe extern "win64" fn dialog_box_indirect_param_w(
    h_instance: usize,
    lp_template: *const u8,
    hwnd_parent: usize,
    lp_dialog_func: usize,
    dw_init_param: isize,
) -> isize {
    if lp_template.is_null() || lp_dialog_func == 0 {
        return -1;
    }
    let Some(hwnd) = crate::dialog::create_from_template_bytes(
        lp_template,
        4096,
        hwnd_parent,
        lp_dialog_func,
        dw_init_param,
        h_instance,
    ) else {
        return -1;
    };
    unsafe { run_modal_dialog_loop(hwnd) }
}

/// EndDialog: close a dialog box.
// Wine ref: dlls/user32/dialog.c — EndDialog sets dialog's nResult field and posts
// WM_NULL to unblock the modal message loop in DialogBox; DestroyWindow called after loop.
pub extern "win64" fn end_dialog(h_dlg: usize, n_result: isize) -> i32 {
    if crate::dialog::signal_end_dialog(h_dlg, n_result) {
        1
    } else {
        0
    }
}

/// GetDlgItem: find a control in a dialog by ID. Returns 0 (not found).
// Wine ref: dlls/win32u/dialog.c — NtUserGetDlgItem searches child windows for matching
// nIDDlgItem (from GWLP_ID); returns first match or NULL if not found.
// Wine ref: dlls/win32u/dialog.c — iterates child windows; ctrl ID is stored in
// wIDmenu (Weave: h_menu) for WS_CHILD windows created via CreateWindow(hMenu=id).
pub extern "win64" fn get_dlg_item(h_dlg: usize, n_id_dlg_item: i32) -> usize {
    let ctrl_id = n_id_dlg_item as usize;
    window::find_with(|_, w| {
        w.hwnd_parent == h_dlg && w.style & WS_CHILD != 0 && w.h_menu == ctrl_id
    })
}

/// GetDlgCtrlID: return the child-window identifier for `hwnd`.
///
/// For child windows (WS_CHILD set), the ID is the integer passed as the
/// `hMenu` parameter when the window was created.  Returns 0 if the window
/// has no identifier or is not found.
///
/// Wine ref: dlls/win32u/window.c::NtUserGetDlgCtrlID — reads WND.wIDmenu;
/// same field used for both menu handle and child ID.
pub extern "win64" fn get_dlg_ctrl_id(hwnd: usize) -> i32 {
    const WS_CHILD: u32 = 0x4000_0000;
    window::with(hwnd, |e| {
        if e.style & WS_CHILD != 0 {
            e.h_menu as i32
        } else {
            0
        }
    })
    .unwrap_or(0)
}

/// GetDlgItemTextA: copy a dialog control's text. Returns 0 chars.
///
/// # Safety
/// `lp_string` must be writable if non-null.
// Wine ref: dlls/user32/dialog.c — GetDlgItemTextA calls GetDlgItem then GetWindowTextA;
// returns 0 and null-terminates buffer if control not found.
pub unsafe extern "win64" fn get_dlg_item_text_a(
    _h_dlg: usize,
    _n_id_dlg_item: i32,
    lp_string: *mut u8,
    n_max_count: i32,
) -> u32 {
    if !lp_string.is_null() && n_max_count > 0 {
        unsafe { *lp_string = 0 };
    }
    0
}

/// GetDlgItemTextW: copy a dialog control's text (wide). Returns 0 chars.
///
/// # Safety
/// `lp_string` must be writable if non-null.
// Wine ref: dlls/user32/dialog.c — GetDlgItemTextW calls GetDlgItem then GetWindowTextW;
// identical to A variant except buffer is UTF-16.
pub unsafe extern "win64" fn get_dlg_item_text_w(
    _h_dlg: usize,
    _n_id_dlg_item: i32,
    lp_string: *mut u16,
    n_max_count: i32,
) -> u32 {
    if !lp_string.is_null() && n_max_count > 0 {
        unsafe { *lp_string = 0 };
    }
    0
}

/// SetDlgItemTextA: set a dialog control's text. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/user32/dialog.c — SetDlgItemTextA calls GetDlgItem then SetWindowTextA;
// returns TRUE if control found, FALSE otherwise.
pub unsafe extern "win64" fn set_dlg_item_text_a(
    _h_dlg: usize,
    _n_id_dlg_item: i32,
    _lp_string: *const u8,
) -> i32 {
    1
}

/// SetDlgItemTextW: set a dialog control's text (wide). Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/user32/dialog.c — SetDlgItemTextW calls GetDlgItem then SetWindowTextW;
// sends WM_SETTEXT directly to control HWND.
pub unsafe extern "win64" fn set_dlg_item_text_w(
    _h_dlg: usize,
    _n_id_dlg_item: i32,
    _lp_string: *const u16,
) -> i32 {
    1
}

/// SendDlgItemMessageA: send a message to a dialog control. Returns 0.
// Wine ref: dlls/user32/dialog.c — SendDlgItemMessageA calls GetDlgItem then SendMessageA;
// returns 0 if control not found; otherwise returns WNDPROC return value.
pub extern "win64" fn send_dlg_item_message_a(
    _h_dlg: usize,
    _n_id_dlg_item: i32,
    _msg: u32,
    _w_param: usize,
    _l_param: isize,
) -> isize {
    0
}

/// CheckDlgButton: set the checked state of a button control. Returns TRUE.
// Wine ref: dlls/user32/dialog.c — CheckDlgButton calls GetDlgItem then sends BM_SETCHECK;
// uCheck: BST_UNCHECKED(0), BST_CHECKED(1), BST_INDETERMINATE(2).
pub extern "win64" fn check_dlg_button(_h_dlg: usize, _n_id_button: i32, _u_check: u32) -> i32 {
    1
}

/// IsDlgButtonChecked: query the checked state of a button. Returns 0.
// Wine ref: dlls/user32/dialog.c — IsDlgButtonChecked calls GetDlgItem then sends
// BM_GETCHECK; returns BST_UNCHECKED(0), BST_CHECKED(1), or BST_INDETERMINATE(2).
pub extern "win64" fn is_dlg_button_checked(_h_dlg: usize, _n_id_button: i32) -> u32 {
    0 // BST_UNCHECKED
}

/// CheckRadioButton: check one button in a group, uncheck the rest. Returns TRUE.
// Wine ref: dlls/user32/dialog.c — iterates controls from nIDFirstButton to nIDLastButton,
// sends BM_SETCHECK(BST_CHECKED) to nIDCheckButton, BM_SETCHECK(0) to all others.
pub extern "win64" fn check_radio_button(
    _h_dlg: usize,
    _n_id_first_button: i32,
    _n_id_last_button: i32,
    _n_id_check_button: i32,
) -> i32 {
    1
}

/// IsDialogMessageA: determine whether a message is for a dialog. Returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/user32/dialog.c — IsDialogMessage handles WM_KEYDOWN Tab/Escape/Return
// for dialog navigation; translates and dispatches if consumed; returns TRUE if eaten.
pub unsafe extern "win64" fn is_dialog_message_a(_h_dlg: usize, _lp_msg: *const Msg) -> i32 {
    0
}

/// MapDialogRect: map dialog box units to pixels. Returns TRUE (rect unchanged).
///
/// # Safety
/// `lp_rect` must point to a valid `Rect` if non-null.
// Wine ref: dlls/user32/dialog.c — MapDialogRect uses dialog base units (GetDialogBaseUnits)
// to scale: x = (dlgx * baseX) / 4, y = (dlgy * baseY) / 8.
pub unsafe extern "win64" fn map_dialog_rect(_h_dlg: usize, _lp_rect: *mut Rect) -> i32 {
    1
}

// ── Window state ──────────────────────────────────────────────────────────────

/// IsIconic: return TRUE if the window is minimised. Always returns FALSE.
// Wine ref: dlls/win32u/window.c — IsIconic checks WS_MINIMIZE style via
// get_window_long(hwnd, GWL_STYLE); does NOT check WS_ICONIC (same bit, legacy alias).
pub extern "win64" fn is_iconic(_h_wnd: usize) -> i32 {
    0
}

/// IsZoomed: return TRUE if the window is maximised. Always returns FALSE.
// Wine ref: dlls/win32u/window.c — IsZoomed checks WS_MAXIMIZE style bit; maximised
// windows have WS_MAXIMIZE set by ShowWindow(SW_MAXIMIZE) or WM_SIZE/SIZE_MAXIMIZED.
pub extern "win64" fn is_zoomed(_h_wnd: usize) -> i32 {
    0
}

/// FlashWindow: flash a window in the taskbar. Returns FALSE.
// Wine ref: dlls/user32/message.c — FlashWindow calls FlashWindowEx with FLASHW_CAPTION|
// FLASHW_TRAY for bInvert=TRUE; returns previous active state of caption.
pub extern "win64" fn flash_window(_h_wnd: usize, _b_invert: i32) -> i32 {
    0
}

/// GetWindowPlacement: retrieve window size and position.
///
/// # Safety
/// `lp_wndpl` must point to a valid `WindowPlacement` with `length` set.
// Wine ref: dlls/win32u/window.c::set_window_placement — GetWindowPlacement fills
// WINDOWPLACEMENT: showCmd=SW_SHOW for normal, ptMinPosition/ptMaxPosition from window state.
pub unsafe extern "win64" fn get_window_placement(
    h_wnd: usize,
    lp_wndpl: *mut WindowPlacement,
) -> i32 {
    if lp_wndpl.is_null() {
        return 0;
    }
    let (x, y, w, h) = window::with(h_wnd, |win| (win.x, win.y, win.width, win.height))
        .unwrap_or((0, 0, 800, 600));
    unsafe {
        (*lp_wndpl).flags = 0;
        (*lp_wndpl).show_cmd = SW_SHOW as u32;
        (*lp_wndpl).pt_min_position = Point { x: -1, y: -1 };
        (*lp_wndpl).pt_max_position = Point { x: -1, y: -1 };
        (*lp_wndpl).rc_normal_position = Rect {
            left: x,
            top: y,
            right: x + w as i32,
            bottom: y + h as i32,
        };
    }
    1
}

/// SetWindowPlacement: set window size and position. Returns TRUE.
///
/// # Safety
/// `lp_wndpl` must point to a valid `WindowPlacement` struct.
// Wine ref: dlls/win32u/window.c::set_window_placement — applies rcNormalPosition via
// NtUserSetWindowPos; handles SW_SHOWMINIMIZED/SW_SHOWMAXIMIZED in showCmd field.
pub unsafe extern "win64" fn set_window_placement(
    h_wnd: usize,
    lp_wndpl: *const WindowPlacement,
) -> i32 {
    if lp_wndpl.is_null() {
        return 0;
    }
    let rc = unsafe { &(*lp_wndpl).rc_normal_position };
    let w = (rc.right - rc.left) as u32;
    let h = (rc.bottom - rc.top) as u32;
    let xcb_id = window::with_mut(h_wnd, |win| {
        win.x = rc.left;
        win.y = rc.top;
        win.width = w;
        win.height = h;
        win.xcb_id
    })
    .unwrap_or(0);
    if xcb_id != 0 {
        backend::configure_window(xcb_id, rc.left, rc.top, w, h);
    }
    1
}

// ── Timer management ─────────────────────────────────────────────────────────

/// SetTimer: create or replace a window timer, returning its ID.
///
/// Wine ref: dlls/win32u/message.c — SetTimer calls NtUserSetTimer which
/// sends a set_win_timer request to the server. If n_id_event is 0 the
/// server allocates a new ID (> 0x7FFF per Wine convention); if non-zero
/// the existing timer for that (hwnd, id) is replaced. Weave tracks timer
/// IDs in a HashMap but does not fire WM_TIMER messages (no real event
/// loop timer support yet — Phase 5 gap). Returns 0 on failure.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/message.c — NtUserSetTimer sends set_win_timer to wineserver;
// id=0 allocates new ID > 0x7FFF; uElapse clamped to [USER_TIMER_MINIMUM, USER_TIMER_MAXIMUM].
pub unsafe extern "win64" fn set_timer(
    h_wnd: usize,
    n_id_event: usize,
    _u_elapse: u32,
    _lp_timer_func: usize,
) -> usize {
    let id = if n_id_event == 0 {
        // System-allocated timer ID — use counter above 0x7FFF to match Wine.
        NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed) as usize + 0x8000
    } else {
        n_id_event
    };
    timer_table()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert((h_wnd, id), id);
    eprintln!("weave/user32: SetTimer hwnd={h_wnd:#x} id={id:#x} elapse={_u_elapse}ms → WM_TIMER NOT FIRED (Phase 5 gap)");
    id
}

/// KillTimer: destroy a timer and free its ID. Returns TRUE if found, FALSE if not.
///
/// Wine ref: dlls/win32u/message.c — KillTimer sends a kill_win_timer request
/// to the server; returns FALSE (sets ERROR_INVALID_PARAMETER) if the timer
/// does not exist for the given (hwnd, id) pair.
pub extern "win64" fn kill_timer(h_wnd: usize, u_id_event: usize) -> i32 {
    let removed = timer_table()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&(h_wnd, u_id_event));
    if removed.is_some() {
        1
    } else {
        0
    }
}

// ── Message helpers ───────────────────────────────────────────────────────────

/// GetMessageTime: return the time field of the last retrieved message (ms).
///
/// Wine ref: dlls/user32/message.c — GetMessageTime calls NtUserGetMessageTime
/// which reads the time field of the last message retrieved by the thread's
/// GetMessage/PeekMessage call. Weave records this in LAST_MSG_TIME whenever
/// fill_msg() copies a message to the caller.
pub extern "win64" fn get_message_time() -> i32 {
    LAST_MSG_TIME.load(Ordering::Relaxed) as i32
}

/// GetMessagePos: return the cursor position when the last message was posted.
///
/// Wine ref: dlls/win32u/message.c — GetMessagePos returns a DWORD packing
/// the (x, y) cursor position from the last MSG retrieved by GetMessage/
/// PeekMessage. Returns MAKELONG(x, y) — low word is X, high word is Y.
pub extern "win64" fn get_message_pos() -> u32 {
    let x = LAST_MSG_POS_X.load(Ordering::Relaxed) as u16 as u32;
    let y = LAST_MSG_POS_Y.load(Ordering::Relaxed) as u16 as u32;
    x | (y << 16)
}

/// GetQueueStatus: return the types of messages currently in the queue.
///
/// Wine ref: dlls/win32u/message.c — GetQueueStatus calls NtUserGetQueueStatus
/// which returns a bitmask of QS_* flags. Weave returns QS_POSTMESSAGE (0x0008)
/// when the queue is non-empty, 0 otherwise.
pub extern "win64" fn get_queue_status(_flags: u32) -> u32 {
    if queue::has_message() {
        0x0008
    } else {
        0
    } // QS_POSTMESSAGE
}

/// MsgWaitForMultipleObjects: wait for objects or a message.
///
/// Contract (Wine ref: dlls/user32/message.c — calls NtUserMsgWaitForMultipleObjectsEx;
/// which delegates to `wait_message` in dlls/win32u/message.c):
/// - Returns `WAIT_OBJECT_0 + i` when `lp_handles[i]` became signalled
/// - Returns `WAIT_OBJECT_0 + n_count` when a queued message matches `dw_wake_mask`
/// - Returns `WAIT_TIMEOUT` (0x102) on timeout
/// - Returns `WAIT_FAILED` (0xFFFFFFFF) on error
///
/// Previously stubbed to return WAIT_TIMEOUT immediately. That broke gnulib's
/// Windows `select(2)` emulator (used by wget's `fd_read` path): gnulib registers
/// an hEvent via WSAEventSelect then calls `MsgWaitForMultipleObjects(1, &hEvent,
/// FALSE, timeout, QS_ALLINPUT)` to wait for socket readiness. When this returned
/// WAIT_TIMEOUT instantly, gnulib's follow-up `select()` poll saw no ready fds
/// and wget's caller set `errno = ETIMEDOUT` (MinGW errno 138) — "Read error
/// (Unknown error 138) in headers".
///
/// Implementation mirrors weave-kernel32::wait_for_multiple_objects. For socket-
/// event handles registered by WSAEventSelect we poll the underlying socket fd
/// directly (its eventfd is never written); for plain eventfd handles we poll
/// the eventfd; we also watch the message-queue wake pipe so posted messages
/// unblock the wait.
///
/// # Safety
/// `lp_handles` must point to `n_count` HANDLE values, or be null.
// Wine ref: dlls/kernelbase/sync.c:434 — WaitForMultipleObjectsEx contract;
// dlls/win32u/message.c:wait_message — MsgWait variant adds the server queue at
// handle_count, returning WAIT_OBJECT_0+count when a message wakes the wait.
pub unsafe extern "win64" fn msg_wait_for_multiple_objects(
    n_count: u32,
    lp_handles: *const usize,
    _b_wait_all: i32,
    dw_milliseconds: u32,
    _dw_wake_mask: u32,
) -> u32 {
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x00000102;
    const WAIT_FAILED: u32 = 0xFFFF_FFFF;
    const INFINITE: u32 = 0xFFFF_FFFF;

    let trace = weave_core::ws2_trace::enabled();
    eprintln!("weave/MsgWait: entry n={n_count} ms={dw_milliseconds} mask={_dw_wake_mask:#x}");
    if trace {
        eprintln!("weave/MsgWait: n={n_count} ms={dw_milliseconds} mask={_dw_wake_mask:#x}");
    }
    // n_count == 0 is valid: "wait for message only, no object handles."
    // The poll loop below will add the wake-pipe and block until a message
    // arrives — correct per MSDN. Only guard against null dereference when
    // the caller actually supplies handles.
    if lp_handles.is_null() && n_count > 0 {
        return WAIT_FAILED;
    }
    if trace {
        for _i in 0..n_count as usize {
            let _h = *lp_handles.add(_i);
            eprintln!("weave/MsgWait:   handle[{_i}]={_h:#x}");
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Collect pollfds for each handle. Track the mapping back to handle index.
        let mut pollfds: Vec<libc::pollfd> = Vec::with_capacity(n_count as usize + 1);
        let mut pfd_to_handle_idx: Vec<usize> = Vec::with_capacity(n_count as usize);

        for i in 0..n_count as usize {
            let handle = *lp_handles.add(i);

            // Guard: NULL (0) or INVALID_HANDLE_VALUE are never valid objects.
            // Skip them so they cannot be passed to get_event_fd, fstat, or poll.
            if handle == 0 || handle == usize::MAX {
                continue;
            }

            // Event handle backed by eventfd.  WSAEventSelect-registered event
            // handles have a reverse map to the socket fd — poll the socket
            // directly since the eventfd is never written for socket events.
            if let Some(efd) = weave_core::handles::get_event_fd(handle) {
                if let Some(sock_fd) =
                    weave_common::socket_event::get_socket_for_event(handle as u64)
                {
                    // Edge-triggered FD_WRITE: only include POLLOUT when armed.
                    // Otherwise an idle connected socket is always writable and
                    // MsgWait would wake instantly every call.
                    // Wine ref: dlls/ws2_32/socket.c — sock_get_events respects hmask.
                    let mut sock_events = libc::POLLIN | libc::POLLHUP | libc::POLLRDHUP;
                    if weave_common::socket_event::is_socket_write_armed(sock_fd) {
                        sock_events |= libc::POLLOUT;
                    }
                    pollfds.push(libc::pollfd {
                        fd: sock_fd,
                        events: sock_events,
                        revents: 0,
                    });
                    pfd_to_handle_idx.push(i);
                    continue;
                }
                // Plain event handle — poll its eventfd for readability.
                pollfds.push(libc::pollfd {
                    fd: efd,
                    events: libc::POLLIN,
                    revents: 0,
                });
                pfd_to_handle_idx.push(i);
                continue;
            }

            // Thread-completion handle — cannot be multiplexed via poll (it is
            // a condvar, not an fd). gnulib select only supplies hEvent handles
            // here, so for now we simply omit thread handles from the poll set
            // and let the timeout or another handle wake the wait. If a caller
            // ever passes only a thread handle, `pollfds` will still contain
            // the message wake pipe as a safety net.
            if weave_core::handles::get_thread_completion(handle).is_some() {
                continue;
            }

            // Socket-as-handle path — MinGW's gnulib select wrapper obtains a
            // HANDLE for a socket fd via `_get_osfhandle(fd)`, which in our
            // impl is the identity mapping (socket fd IS the handle). wget's
            // I/O wait loop passes [hEvent, socket_handle] to MsgWait; we must
            // poll the socket fd so POLLIN / POLLOUT wakes the wait.
            //
            // Wine ref: dlls/ws2_32/socket.c — socket handles on Windows are
            // signalable objects. Our equivalent on Linux: fstat the fd and if
            // it's a socket, include POLLIN|POLLOUT|POLLHUP in the pollfd.
            //
            // The handle value fits in a socket fd range (small positive int)
            // — do a cheap fstat probe. If it is a socket, poll it.
            let fd = handle as i32;
            if fd > 0 && fd < 4096 {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::fstat(fd, &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK {
                    let mut sock_events = libc::POLLIN | libc::POLLHUP | libc::POLLRDHUP;
                    if weave_common::socket_event::is_socket_write_armed(fd) {
                        sock_events |= libc::POLLOUT;
                    } else {
                        // Without an explicit WSAEventSelect FD_WRITE arm,
                        // still include POLLOUT because a blocking socket
                        // passed directly as a HANDLE has no Windows-side
                        // arming — the caller expects "connected + writable"
                        // to wake the wait the first time and after recv().
                        sock_events |= libc::POLLOUT;
                    }
                    pollfds.push(libc::pollfd {
                        fd,
                        events: sock_events,
                        revents: 0,
                    });
                    pfd_to_handle_idx.push(i);
                    continue;
                }
            }
        }

        // Always include the message-queue wake pipe so a posted message can
        // unblock the wait. Wine equivalent: the server queue is handles[count].
        crate::queue::init_wake_pipe();
        let msg_wake_fd = crate::queue::wake_fd_read();
        pollfds.push(libc::pollfd {
            fd: msg_wake_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        let msg_pfd_index = pollfds.len() - 1;

        let timeout_ms: i32 = if dw_milliseconds == INFINITE {
            -1
        } else {
            dw_milliseconds.min(i32::MAX as u32) as i32
        };

        eprintln!(
            "weave/MsgWait: polling nfds={} timeout_ms={timeout_ms}",
            pollfds.len()
        );
        let ret = libc::poll(
            pollfds.as_mut_ptr(),
            pollfds.len() as libc::nfds_t,
            timeout_ms,
        );
        eprintln!("weave/MsgWait: poll returned ret={ret}");

        if trace {
            eprintln!("weave/MsgWait: poll returned {} ret={}", pollfds.len(), ret);
        }
        if ret < 0 {
            return WAIT_FAILED;
        }
        if ret == 0 {
            return WAIT_TIMEOUT;
        }

        // Check the message wake pipe last, per Wine semantics (handles first).
        for (pi, pfd) in pollfds.iter().enumerate() {
            if pi == msg_pfd_index {
                continue;
            }
            let ready = (pfd.revents
                & (libc::POLLIN | libc::POLLOUT | libc::POLLHUP | libc::POLLRDHUP))
                != 0;
            if ready {
                let hi = pfd_to_handle_idx[pi];
                if trace {
                    eprintln!(
                        "weave/MsgWait: ready pi={pi} hi={hi} revents={:#x} → ret={}",
                        pfd.revents,
                        WAIT_OBJECT_0 + hi as u32
                    );
                }
                return WAIT_OBJECT_0 + hi as u32;
            }
        }
        if (pollfds[msg_pfd_index].revents & libc::POLLIN) != 0 {
            // Drain one byte from the wake pipe so subsequent waits block again
            // until the next post. Ignore errors — the pipe is non-blocking.
            let mut scratch = [0u8; 64];
            let _ = libc::read(
                msg_wake_fd,
                scratch.as_mut_ptr() as *mut libc::c_void,
                scratch.len(),
            );
            return WAIT_OBJECT_0 + n_count;
        }

        WAIT_TIMEOUT
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (n_count, lp_handles, dw_milliseconds);
        WAIT_TIMEOUT
    }
}

// ── Mouse capture ─────────────────────────────────────────────────────────────

/// GetCapture: return the window that has mouse capture. Returns 0.
// Wine ref: dlls/win32u/input.c — NtUserGetCapture returns the per-thread capture window;
// capture is thread-local; returns NULL if no window has capture in this thread.
pub extern "win64" fn get_capture() -> usize {
    0
}

/// SetCapture: capture mouse input for a window. Returns 0 (previous capture).
// Wine ref: dlls/win32u/input.c — NtUserSetCapture sets per-thread capture window;
// sends WM_CAPTURECHANGED to the old capture window; returns previous capture HWND.
pub extern "win64" fn set_capture(_h_wnd: usize) -> usize {
    0
}

/// ReleaseCapture: release mouse capture. Returns TRUE.
// Wine ref: dlls/win32u/main.c — NtUserReleaseCapture clears per-thread capture;
// sends WM_CAPTURECHANGED(NULL) to the previously capturing window.
pub extern "win64" fn release_capture() -> i32 {
    1
}

/// SetActiveWindow: activate a window. Returns 0 (previous).
// Wine ref: dlls/win32u/input.c::set_focus_window — SetActiveWindow calls set_focus_window
// via server request; sends WM_ACTIVATE(WA_ACTIVE) and WM_SETFOCUS to new window.
pub extern "win64" fn set_active_window(_h_wnd: usize) -> usize {
    0
}

// ── System colors ─────────────────────────────────────────────────────────────

/// GetSysColor: return a system color. Returns black (0x000000) for all.
// Wine ref: dlls/win32u/sysparams.c::get_sys_color — returns COLORREF from syscolor array
// indexed by nIndex; array populated from registry (Control Panel colors) at startup.
pub extern "win64" fn get_sys_color(_n_index: i32) -> u32 {
    // Hardcode some common ones for better appearance.
    match _n_index {
        5 => 0x00FFFFFF,  // COLOR_WINDOW = white
        8 => 0x00000000,  // COLOR_WINDOWTEXT = black
        15 => 0x00F0F0F0, // COLOR_BTNFACE = light gray
        _ => 0x00D4D0C8,  // default = classic Windows gray
    }
}

/// GetSysColorBrush: return a brush for a system color.
///
/// Returns a non-zero fake HBRUSH value. GDI functions that receive this
/// handle will silently accept it (SelectObject/DeleteObject treat unknown
/// handles as no-ops in Weave's stub implementation).
// Wine ref: dlls/win32u/sysparams.c::get_sys_color_brush — returns a cached HBRUSH from
// the syscolbrush array; brushes are created once and reused (do not delete them).
pub extern "win64" fn get_sys_color_brush(n_index: i32) -> usize {
    // Use the color index + 1 as the fake handle (non-zero, stable, cheap).
    (n_index as usize).wrapping_add(1)
}

// ── Scrollbar state ───────────────────────────────────────────────────────────

/// GetScrollInfo: retrieve per-HWND per-bar scroll parameters.
///
/// Wine ref: dlls/win32u/scroll.c — get_scroll_info reads from a per-window
/// scroll_info struct keyed by (hwnd, bar). SIF_PAGE/SIF_POS/SIF_RANGE/
/// SIF_TRACKPOS control which fields are filled. Returns FALSE if no stored
/// state exists for (hwnd, bar) — callers must initialise via SetScrollInfo.
///
/// # Safety
/// `lp_si` must point to a valid `ScrollInfo` with `cb_size` and `f_mask` set.
// Wine ref: dlls/win32u/scroll.c — reads per-window scroll_info keyed by (hwnd, bar);
// SIF_PAGE/POS/RANGE/TRACKPOS select which fields are filled; FALSE if no state stored.
pub unsafe extern "win64" fn get_scroll_info(
    hwnd: usize,
    n_bar: i32,
    lp_si: *mut ScrollInfo,
) -> i32 {
    if lp_si.is_null() {
        return 0;
    }
    let mask = unsafe { (*lp_si).f_mask };
    const SIF_RANGE: u32 = 0x0001;
    const SIF_PAGE: u32 = 0x0002;
    const SIF_POS: u32 = 0x0004;
    const SIF_TRACKPOS: u32 = 0x0010;
    let state = scroll_state()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&(hwnd, n_bar))
        .cloned()
        .unwrap_or_default();
    unsafe {
        if mask & SIF_RANGE != 0 {
            (*lp_si).n_min = state.n_min;
            (*lp_si).n_max = state.n_max;
        }
        if mask & SIF_PAGE != 0 {
            (*lp_si).n_page = state.n_page;
        }
        if mask & SIF_POS != 0 {
            (*lp_si).n_pos = state.n_pos;
        }
        if mask & SIF_TRACKPOS != 0 {
            (*lp_si).n_track_pos = state.n_pos; // track pos = current pos (headless)
        }
    }
    1 // TRUE
}

/// SetScrollInfo: store per-HWND per-bar scroll parameters, return new position.
///
/// Wine ref: dlls/win32u/scroll.c — set_scroll_info validates the struct,
/// clamps page to (0, max-min+1), clamps pos to [min, max-max(page-1,0)],
/// and returns the resulting position. Redraw is a no-op in headless mode.
/// Returns the new clamped scroll position.
///
/// # Safety
/// `lp_si` must point to a valid `ScrollInfo` with `cb_size` and `f_mask` set.
// Wine ref: dlls/win32u/scroll.c — clamps page to (0, max-min+1), pos to [min, max-max(page-1,0)];
// sends WM_HSCROLL/WM_VSCROLL if redraw; returns new clamped nPos.
pub unsafe extern "win64" fn set_scroll_info(
    hwnd: usize,
    n_bar: i32,
    lp_si: *const ScrollInfo,
    _b_redraw: i32,
) -> i32 {
    if lp_si.is_null() {
        return 0;
    }
    const SIF_RANGE: u32 = 0x0001;
    const SIF_PAGE: u32 = 0x0002;
    const SIF_POS: u32 = 0x0004;
    let si = unsafe { &*lp_si };
    let mut table = scroll_state().lock().unwrap_or_else(|p| p.into_inner());
    let state = table.entry((hwnd, n_bar)).or_default();
    if si.f_mask & SIF_RANGE != 0 {
        if si.n_min > si.n_max {
            state.n_min = 0;
            state.n_max = 0;
        } else {
            state.n_min = si.n_min;
            state.n_max = si.n_max;
        }
    }
    if si.f_mask & SIF_PAGE != 0 {
        state.n_page = si.n_page;
    }
    if si.f_mask & SIF_POS != 0 {
        state.n_pos = si.n_pos;
    }
    // Clamp page to [0, max-min+1].
    let range = (state.n_max - state.n_min + 1).max(0) as u32;
    if state.n_page > range {
        state.n_page = range;
    }
    // Clamp pos to [min, max - max(page-1, 0)].
    let page_adj = (state.n_page as i32 - 1).max(0);
    let pos_max = state.n_max - page_adj;
    if state.n_pos < state.n_min {
        state.n_pos = state.n_min;
    } else if state.n_pos > pos_max {
        state.n_pos = pos_max;
    }
    state.n_pos // return new clamped position
}

// ── Caret stubs ───────────────────────────────────────────────────────────────

/// CreateCaret: create a caret shape for a window. Returns TRUE.
// Wine ref: dlls/win32u/input.c — NtUserCreateCaret stores caret dimensions in per-thread
// caret info; hBitmap=NULL=solid, hBitmap=1=gray; destroys previous caret first.
pub extern "win64" fn create_caret(_hwnd: usize, _h_bitmap: usize, _w: i32, _h: i32) -> i32 {
    1
}

/// DestroyCaret: destroy the current caret. Returns TRUE.
// Wine ref: dlls/win32u/main.c — NtUserDestroyCaret clears per-thread caret state;
// hides the caret if visible; only the thread that owns the caret can destroy it.
pub extern "win64" fn destroy_caret() -> i32 {
    1
}

/// ShowCaret: make the caret visible. Returns TRUE.
// Wine ref: dlls/win32u/input.c — NtUserShowCaret decrements the per-thread caret
// hide count; caret becomes visible when hide count reaches 0.
pub extern "win64" fn show_caret(_hwnd: usize) -> i32 {
    1
}

/// HideCaret: hide the caret. Returns TRUE.
// Wine ref: dlls/win32u/input.c — NtUserHideCaret increments the per-thread caret
// hide count; caret is hidden when count > 0; paired with ShowCaret.
pub extern "win64" fn hide_caret(_hwnd: usize) -> i32 {
    1
}

/// SetCaretPos: move the caret to (x, y) relative to the owning window.
///
/// Wine ref: dlls/win32u/caret.c — SetCaretPos stores the new position in the
/// thread-local caret info and posts a WM_SETCARET message. Weave stores a
/// single global caret position (single-threaded). Returns TRUE.
pub extern "win64" fn set_caret_pos(x: i32, y: i32) -> i32 {
    CARET_X.store(x, Ordering::Relaxed);
    CARET_Y.store(y, Ordering::Relaxed);
    1
}

/// GetCaretPos: retrieve the caret position into a POINT.
///
/// Wine ref: dlls/win32u/caret.c — GetCaretPos copies the stored caret
/// coordinates into the provided POINT. Returns TRUE if the POINT is non-null.
///
/// # Safety
/// `lp_point` must point to a valid `Point` struct or NULL.
pub unsafe extern "win64" fn get_caret_pos(lp_point: *mut Point) -> i32 {
    if lp_point.is_null() {
        return 0;
    }
    unsafe {
        (*lp_point).x = CARET_X.load(Ordering::Relaxed);
        (*lp_point).y = CARET_Y.load(Ordering::Relaxed);
    }
    1
}

/// GetCaretBlinkTime: return the caret blink interval in milliseconds.
// Wine ref: dlls/win32u/main.c — NtUserGetCaretBlinkTime reads from per-thread caret info;
// default 500ms; can be changed by SystemParametersInfo(SPI_SETCARETWIDTH) or registry.
pub extern "win64" fn get_caret_blink_time() -> u32 {
    500
}

// ── Misc stubs ────────────────────────────────────────────────────────────────

/// MessageBeep: produce a sound. Returns TRUE (no audio yet).
// Wine ref: dlls/user32/message.c — MessageBeep plays a system sound via PlaySound;
// uType maps MB_OK/MB_ICONERROR etc. to SND_ALIAS entries; returns TRUE always.
pub extern "win64" fn message_beep(_u_type: u32) -> i32 {
    1
}

/// GetDoubleClickTime: return the double-click interval in milliseconds.
// Wine ref: dlls/win32u/sysparams.c — NtUserGetDoubleClickTime reads SPI_GETDOUBLECLICKTIME
// from system parameters; default 500ms; configurable via SystemParametersInfo.
pub extern "win64" fn get_double_click_time() -> u32 {
    500
}

/// OffsetRect: offset a rectangle by x, y. Returns TRUE.
///
/// # Safety
/// `lp_rc` must point to a valid `Rect`.
// Wine ref: dlls/win32u/defwnd.c — OffsetRect adds dx to left/right and dy to top/bottom;
// returns FALSE if lprc is NULL; works on empty rects without validation.
pub unsafe extern "win64" fn offset_rect(lp_rc: *mut Rect, dx: i32, dy: i32) -> i32 {
    if lp_rc.is_null() {
        return 0;
    }
    unsafe {
        (*lp_rc).left += dx;
        (*lp_rc).right += dx;
        (*lp_rc).top += dy;
        (*lp_rc).bottom += dy;
    }
    1
}

/// DrawEdge: draw a 3D border around a rectangle. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/defwnd.c — DrawEdge renders BDR_RAISED/BDR_SUNKEN/EDGE_BUMP etc.
// using system colors; BF_ADJUST shrinks qrc by border width after drawing.
pub unsafe extern "win64" fn draw_edge(
    _hdc: usize,
    _qrc: *mut Rect,
    _edge: u32,
    _grfflags: u32,
) -> i32 {
    1
}

/// DrawIconEx: draw an icon or cursor. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/cursoricon.c — DrawIconEx renders icon mask + color bitmaps onto
// hdc; DI_IMAGE|DI_MASK|DI_NORMAL control which planes are drawn; animates if iStepIfAniCur>0.
pub unsafe extern "win64" fn draw_icon_ex(
    _hdc: usize,
    _x_left: i32,
    _y_top: i32,
    _h_icon: usize,
    _cx_width: i32,
    _cy_height: i32,
    _i_step_if_ani_cur: u32,
    _h_br_flicker_free_draw: usize,
    _di_flags: u32,
) -> i32 {
    1
}

/// # Safety
/// `lp_sz_format` must be a valid null-terminated ANSI string.
// Wine ref: dlls/win32u/clipboard.c — NtUserRegisterClipboardFormat allocates IDs in
// 0xC000–0xFFFF range; same name → same ID (idempotent); case-insensitive comparison.
pub unsafe extern "win64" fn register_clipboard_format_a(lp_sz_format: *const u8) -> u32 {
    let name = unsafe { decode_ansi(lp_sz_format) };
    crate::clipboard::register_format(&name)
}

/// # Safety
/// `lp_string` must be a valid null-terminated ANSI string.
// Wine ref: dlls/win32u/message.c — RegisterWindowMessageA converts to wide then calls
// NtUserRegisterClipboardFormat; WM IDs share the same 0xC000–0xFFFF range as clipboard formats.
pub unsafe extern "win64" fn register_window_message_a(lp_string: *const u8) -> u32 {
    unsafe { register_clipboard_format_a(lp_string) }
}

/// # Safety
/// `lp_string` must be a valid null-terminated UTF-16 string.
// Wine ref: dlls/user32/message.c — RegisterWindowMessageW calls NtUserRegisterClipboardFormat;
// WM IDs share the 0xC000–0xFFFF atom range with clipboard formats; same name → same ID.
pub unsafe extern "win64" fn register_window_message_w(lp_string: *const u16) -> u32 {
    if lp_string.is_null() {
        return 0;
    }
    let name = unsafe { decode_wide(lp_string) };
    crate::clipboard::register_format(&name)
}

/// SystemParametersInfoA: delegates to W for all bool/uint/struct actions.
///
/// # Safety
/// pv_param must be a valid writable pointer for GET actions.
// Wine ref: dlls/win32u/sysparams.c — SystemParametersInfoA converts string params to
// wide then calls SystemParametersInfoW; for bool/uint/struct actions the pointer passes
// through unchanged.
pub unsafe extern "win64" fn system_parameters_info_a(
    u_action: u32,
    u_param: u32,
    pv_param: usize,
    f_win_ini: u32,
) -> i32 {
    system_parameters_info_w(u_action, u_param, pv_param as *mut u8, f_win_ini)
}

/// ToAsciiEx: translate a virtual key to a character. Returns 0.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/input.c — ToAsciiEx calls ToUnicodeEx then WideCharToMultiByte;
// returns -1 for dead key, 0 for no char, 1-2 for chars produced.
pub unsafe extern "win64" fn to_ascii_ex(
    _u_virt_key: u32,
    _u_scan_code: u32,
    _lp_key_state: *const u8,
    _lp_char: *mut u16,
    _u_flags: u32,
    _dwhkl: usize,
) -> i32 {
    0
}

/// SetFocus: set keyboard focus to a window. Returns the previous focus window.
///
// Wine ref: dlls/win32u/input.c::set_focus_window — sends WM_KILLFOCUS to old focus window,
// then WM_SETFOCUS to new one; returns old focus HWND (NULL if none had focus).
/// # Safety
/// No pointer dereferences; `hwnd` is an opaque handle value.
pub unsafe extern "win64" fn set_focus(hwnd: usize) -> usize {
    let old = FOCUSED_HWND.swap(hwnd, Ordering::SeqCst);
    if old != 0 && old != hwnd {
        if let Some(proc_addr) = window::with(old, |w| w.wnd_proc) {
            call_wnd_proc(proc_addr, old, 0x0008, hwnd, 0); // WM_KILLFOCUS, wParam=new focus
        }
    }
    if hwnd != 0 && hwnd != old {
        if let Some(proc_addr) = window::with(hwnd, |w| w.wnd_proc) {
            call_wnd_proc(proc_addr, hwnd, 0x0007, old, 0); // WM_SETFOCUS, wParam=old focus
        }
    }
    old
}

/// SetKeyboardState: set the keyboard state for the calling thread. Returns TRUE.
///
/// # Safety
/// `lp_key_state` is accepted but not dereferenced.
// Wine ref: dlls/win32u/input.c — NtUserSetKeyboardState copies 256-byte array into the
// per-thread key state table; used by IME and accessibility tools to inject key state.
pub unsafe extern "win64" fn set_keyboard_state(_lp_key_state: *const u8) -> i32 {
    1 // TRUE
}

/// SetWindowTextA: update the title bar text of a window (ANSI).
///
/// Decodes the ANSI string and delegates to `set_window_text_w`.
///
/// # Safety
/// `lp_string` must be a valid null-terminated ANSI string or null.
// Wine ref: dlls/user32/win.c — SetWindowTextA converts to wide via MultiByteToWideChar
// then calls NtUserDefSetText; sends WM_SETTEXT to the window; returns FALSE if hwnd invalid.
pub unsafe extern "win64" fn set_window_text_a(hwnd: usize, lp_string: *const u8) -> i32 {
    if lp_string.is_null() {
        return 0;
    }
    let mut len = 0usize;
    // Pointer validation: cap walk to prevent OOB read from unterminated string.
    while len < crate::defs::MAX_GUEST_STR_LEN && unsafe { *lp_string.add(len) } != 0 {
        len += 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(lp_string, len) };
    let s = String::from_utf8_lossy(bytes);
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { set_window_text_w(hwnd, wide.as_ptr()) }
}

/// CharUpperW — convert a wide string or character to uppercase in-place.
///
/// If the high word of `lpsz` is 0, treats it as a character value and returns
/// the uppercased character. Otherwise treats it as a pointer to a null-terminated
/// UTF-16 string and uppercases in place, returning the same pointer.
///
/// # Safety
/// If `lpsz` has a non-zero high word, it must be a valid null-terminated UTF-16
/// string.
// Wine ref: dlls/win32u/defwnd.c — CharUpperW checks HIWORD(lpsz)==0 for single-char mode;
// string mode calls RtlUpcaseUnicodeChar per code unit; locale-insensitive.
pub unsafe extern "win64" fn char_upper_w(lpsz: *mut u16) -> *mut u16 {
    if (lpsz as usize) < 0x10000 {
        let c = lpsz as u16;
        let up = char::from_u32(c as u32)
            .map(|ch| ch.to_uppercase().next().unwrap_or(ch) as u16)
            .unwrap_or(c);
        return up as usize as *mut u16;
    }
    let mut p = lpsz;
    let mut walked = 0usize;
    // Pointer validation: cap walk to prevent OOB on unterminated strings.
    while walked < crate::defs::MAX_GUEST_STR_LEN && unsafe { *p } != 0 {
        let c = unsafe { *p };
        let up = char::from_u32(c as u32)
            .map(|ch| ch.to_uppercase().next().unwrap_or(ch) as u16)
            .unwrap_or(c);
        unsafe { *p = up };
        p = unsafe { p.add(1) };
        walked += 1;
    }
    lpsz
}

/// GetMenuItemInfoW — retrieve information about a menu item (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// `lpmii` is accepted but not dereferenced.
// Wine ref: dlls/win32u/menu.c::get_menu_item_info — validates cbSize via
// MENU_NormalizeMenuItemInfoStruct; copies string via get_menu_item_text if MIIM_STRING set;
// MIIM_TYPE is legacy alias — normalized to MIIM_FTYPE+MIIM_STRING before dispatch.
pub unsafe extern "win64" fn get_menu_item_info_w(
    _h_menu: usize,
    _u_item: u32,
    _f_by_position: i32,
    _lpmii: *mut u8,
) -> i32 {
    0 // FALSE
}

/// SetMenuItemInfoW — set information about a menu item (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// `lpmii` is accepted but not dereferenced.
// Wine ref: dlls/win32u/menu.c::set_menu_item_info — normalizes struct via
// MENU_NormalizeMenuItemInfoStruct; MIIM_BITMAP/MIIM_FTYPE/MIIM_STRING handled separately;
// string ownership: copies dwTypeData if MIIM_STRING, frees previous string.
pub unsafe extern "win64" fn set_menu_item_info_w(
    _h_menu: usize,
    _u_item: u32,
    _f_by_position: i32,
    _lpmii: *const u8,
) -> i32 {
    0 // FALSE
}

/// LoadStringW — load a string from a module's RT_STRING resource table (Wide).
///
/// RT_STRING storage: bundles of 16 strings each, indexed by `(id >> 4) + 1`
/// as the resource ordinal. Within a bundle, the string at index `id & 0x0F`
/// is the target. Each string is length-prefixed UTF-16 (`u16 len; WCHAR[len]`)
/// with NO null terminator in the resource itself.
///
/// Normal case (`n_buffer_max > 0`): copy up to `n_buffer_max - 1` UTF-16
/// code units into `lp_buffer`, null-terminate, return count copied.
///
/// Special case (`n_buffer_max == 0`): write a pointer to the in-PE string
/// data into `*(LPWSTR*)lp_buffer` and return the character count. No null
/// terminator is written — caller uses the returned length.
///
/// `h_instance == NULL` or ID-not-found → return 0, write empty if buffer.
///
/// # Safety
/// `lp_buffer` must be null, writable for `n_buffer_max` UTF-16 units (normal
/// case), or writable for one `LPWSTR` (when `n_buffer_max == 0`).
// Wine ref: dlls/user32/resource.c::LoadStringW (lines 149-193) — verified via
// jcodemunch get_symbol_source on local/wine-reference-182107cc:
//   hrsrc = FindResourceW(instance, MAKEINTRESOURCEW((LOWORD(id)>>4)+1), RT_STRING);
//   p = LockResource(hmem); string_num = resource_id & 0x000f;
//   for (i = 0; i < string_num; i++) p += *p + 1;
//   if (buflen == 0) { *((LPWSTR*)buffer) = p + 1; return *p; }
//   i = min(buflen - 1, *p); memcpy(buffer, p + 1, i*sizeof(WCHAR)); buffer[i] = 0;
pub unsafe extern "win64" fn load_string_w(
    h_instance: usize,
    u_id: u32,
    lp_buffer: *mut u16,
    n_buffer_max: i32,
) -> i32 {
    restrace!("load_string_w hInst={h_instance:#x} id={u_id} cchMax={n_buffer_max}");
    if lp_buffer.is_null() {
        return 0;
    }

    // Pre-clear for failure paths (normal case only — cchMax==0 treats
    // lp_buffer as LPWSTR* and we must not scribble over its destination).
    let write_empty_on_fail = || {
        if n_buffer_max > 0 {
            unsafe { *lp_buffer = 0 };
        }
    };

    // hInst==NULL: Wine resolves to user32 module for system strings. Out of
    // scope for first pass (per task-11 brief) — treat as not found.
    if h_instance == 0 {
        write_empty_on_fail();
        return 0;
    }

    // Locate bundle. Wine: LOWORD(id) >> 4 + 1.
    let low_id = (u_id & 0xFFFF) as u16;
    let bundle_ord = (low_id >> 4).wrapping_add(1);
    let string_index = (low_id & 0x0F) as usize;

    let image_base = match weave_core::module_handles::base_of(h_instance) {
        Some(b) => b,
        None => {
            write_empty_on_fail();
            return 0;
        }
    };

    const RT_STRING: u16 = 6;
    let loc = match weave_core::resource::find_resource(
        image_base,
        weave_core::resource::ResourceId::Id(RT_STRING),
        weave_core::resource::ResourceId::Id(bundle_ord),
        0,
    ) {
        Some(l) => l,
        None => {
            write_empty_on_fail();
            return 0;
        }
    };

    // Walk to the target entry. Each entry = u16 length + length WCHARs.
    // We must bounds-check against `loc.size` — the bundle may legitimately
    // contain fewer than 16 populated entries (trailing empties are a u16
    // zero each, but malformed resources could truncate).
    let bundle_ptr = match image_base.checked_add(loc.data_rva as usize) {
        Some(p) => p as *const u16,
        None => {
            write_empty_on_fail();
            return 0;
        }
    };
    let bundle_u16_count = (loc.size as usize) / 2;

    // Walk `string_index` length-prefixed entries, then read the target's
    // length prefix. All reads bounds-checked against bundle_u16_count.
    let mut cursor: usize = 0;
    for _ in 0..string_index {
        if cursor >= bundle_u16_count {
            write_empty_on_fail();
            return 0;
        }
        // SAFETY: bundle_ptr points into a mapped PE image; cursor < count.
        let len = unsafe { *bundle_ptr.add(cursor) } as usize;
        cursor = match cursor.checked_add(1).and_then(|c| c.checked_add(len)) {
            Some(c) => c,
            None => {
                write_empty_on_fail();
                return 0;
            }
        };
    }
    if cursor >= bundle_u16_count {
        write_empty_on_fail();
        return 0;
    }
    // SAFETY: cursor < count.
    let target_len = unsafe { *bundle_ptr.add(cursor) } as usize;
    if cursor + 1 + target_len > bundle_u16_count {
        write_empty_on_fail();
        return 0;
    }
    // SAFETY: chars in [cursor+1, cursor+1+target_len) are in-bounds.
    let chars_ptr = unsafe { bundle_ptr.add(cursor + 1) };

    // Empty string slot: Wine still returns 0 and null-terminates buffer.
    if target_len == 0 {
        if n_buffer_max == 0 {
            // Pointer-return mode: hand back the (empty) source pointer.
            // SAFETY: caller asserts lp_buffer is LPWSTR*.
            unsafe { *(lp_buffer as *mut *const u16) = chars_ptr };
            return 0;
        }
        write_empty_on_fail();
        return 0;
    }

    if n_buffer_max == 0 {
        // Special case: return pointer into the PE image. Caller treats
        // lp_buffer as LPWSTR* and uses returned length (no null terminator
        // in the source data).
        // SAFETY: caller asserts lp_buffer is LPWSTR*; chars_ptr is in-bounds.
        unsafe { *(lp_buffer as *mut *const u16) = chars_ptr };
        return target_len as i32;
    }
    if n_buffer_max < 0 {
        // Wine's `min(buflen - 1, *p)` with a negative buflen would underflow;
        // treat as empty failure.
        return 0;
    }

    // Normal copy: min(buflen - 1, len) chars, then null-terminate.
    let to_copy = core::cmp::min((n_buffer_max - 1) as usize, target_len);
    // SAFETY: lp_buffer is writable for n_buffer_max WCHARs; chars_ptr is
    // readable for target_len WCHARs; to_copy <= both.
    unsafe {
        core::ptr::copy_nonoverlapping(chars_ptr, lp_buffer, to_copy);
        *lp_buffer.add(to_copy) = 0;
    }
    let result = to_copy as i32;
    restrace!("load_string_w hInst={h_instance:#x} id={u_id} → bytes_copied={result}");
    result
}

/// LoadStringA — ANSI trampoline around `LoadStringW`.
///
/// Loads the string via `LoadStringW` into a temporary UTF-16 buffer (sized
/// to match `n_buffer_max`, capped at a reasonable max), then converts to
/// ANSI (CP_ACP ≈ CP1252 in Weave's current WideCharToMultiByte impl) into
/// the caller's CHAR buffer. Null-terminates.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_max` bytes.
// Wine ref: dlls/user32/resource.c::LoadStringA (lines 198-224) — verified via
// jcodemunch get_symbol_source on local/wine-reference-182107cc:
//   if (!buflen) return -1;
//   hrsrc = FindResourceW(instance, MAKEINTRESOURCEW((LOWORD(id)>>4)+1), RT_STRING);
//   p = LockResource(hmem); id = resource_id & 0x000f;
//   while (id--) p += *p + 1;
//   RtlUnicodeToMultiByteN(buffer, buflen - 1, &retval, p + 1, *p * sizeof(WCHAR));
//   buffer[retval] = 0;
// Weave implementation: LoadStringW into a temp WCHAR buffer, then
// convert to the caller's CHAR buffer via a simple CP_ACP (1252) conversion
// (lossy ASCII fallback is acceptable — matches existing CP_ACP behavior
// elsewhere in weave-user32, and ASCII is the common resource content).
pub unsafe extern "win64" fn load_string_a(
    h_instance: usize,
    u_id: u32,
    lp_buffer: *mut u8,
    n_buffer_max: i32,
) -> i32 {
    // Wine: `if (!buflen) return -1;` — LoadStringA has no pointer-return mode.
    if n_buffer_max == 0 {
        return -1;
    }
    if lp_buffer.is_null() || n_buffer_max < 0 {
        return 0;
    }

    // Allocate a wide temp buffer the same length as the caller's buffer.
    // LoadStringW copies min(buflen-1, len) WCHARs; we size the temp to
    // n_buffer_max so each ANSI byte has a corresponding WCHAR slot.
    let wide_cap = n_buffer_max as usize;
    let mut wide: Vec<u16> = vec![0u16; wide_cap];
    // SAFETY: wide.as_mut_ptr() is valid for wide_cap WCHARs.
    let copied = unsafe { load_string_w(h_instance, u_id, wide.as_mut_ptr(), n_buffer_max) };
    if copied <= 0 {
        // Null-terminate the ANSI buffer on failure.
        // SAFETY: n_buffer_max > 0 checked above.
        unsafe { *lp_buffer = 0 };
        return 0;
    }

    // Narrow to CP_ACP (1252). Characters > 0xFF are replaced with '?'.
    let copied_usize = copied as usize;
    // SAFETY: lp_buffer is writable for n_buffer_max bytes; copied < n_buffer_max.
    unsafe {
        for (i, w) in wide.iter().take(copied_usize).enumerate() {
            let b = if *w <= 0xFF { *w as u8 } else { b'?' };
            *lp_buffer.add(i) = b;
        }
        *lp_buffer.add(copied_usize) = 0;
    }
    copied
}

/// # Safety
/// `lpsz`, if non-null, must be a valid null-terminated UTF-16 string.
// Wine ref: dlls/win32u/clipboard.c — NtUserRegisterClipboardFormat allocates IDs in
// 0xC000–0xFFFF range; same name → same ID (idempotent); name comparison is case-insensitive.
pub unsafe extern "win64" fn register_clipboard_format_w(lpsz: *const u16) -> u32 {
    if lpsz.is_null() {
        return 0;
    }
    let name = unsafe { decode_wide(lpsz) };
    crate::clipboard::register_format(&name)
}

/// GetWindowTextLengthW — return the length of a window's title bar text.
///
/// Returns 0 — stub.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: include/ntuser.h::NtUserGetWindowTextLength — calls NtUserGetWindowText with
// NULL buffer; WM_GETTEXTLENGTH is sent to the window; result may differ from actual
// text length due to ANSI/Unicode conversion expansion.
pub unsafe extern "win64" fn get_window_text_length_w(hwnd: usize) -> i32 {
    window::with(hwnd, |w| w.title.encode_utf16().count() as i32).unwrap_or(0)
}

/// SystemParametersInfoW — query or set system-wide parameters (Wide).
///
/// # Safety
/// pv_param is written for GET actions; caller must provide a valid buffer.
// Wine ref: dlls/win32u/sysparams.c::NtUserSystemParametersInfo —
// GET actions read from the system-parameter entry table; SET actions update registry.
// Weave covers the most-called GET subset; SET actions return TRUE (accepted, not persisted).
// SPI_GETICONTITLELOGFONT: calls get_font_entry(&entry_ICONTITLELOGFONT,...) which
// falls back to DEFAULT_GUI_FONT with lfCharSet=DEFAULT_CHARSET, lfHeight mapped from
// system DPI (typically -11 at 96dpi), lfWeight from entry default (FW_NORMAL=400),
// copies full LOGFONTW into ptr_param, returns TRUE. SciTE calls this with
// uiParam=sizeof(LOGFONTW)=92 and exits immediately on FALSE return (RVA 0x777ab).
pub unsafe extern "win64" fn system_parameters_info_w(
    u_action: u32,
    _u_param: u32,
    pv_param: *mut u8,
    _f_win_ini: u32,
) -> i32 {
    // Helper: write u32 to pv_param, guard null.
    macro_rules! write_u32 {
        ($val:expr) => {{
            if pv_param.is_null() {
                return 0;
            }
            *(pv_param as *mut u32) = $val;
            1
        }};
    }

    // Helper: write LOGFONTW (92 bytes) at `base` with Segoe UI / FW_NORMAL / -11pt.
    // Wine ref: dlls/win32u/sysparams.c — default logfont fields for all five NCM fonts.
    macro_rules! write_logfont {
        ($base:expr) => {{
            let lf: *mut u8 = $base;
            std::ptr::write_bytes(lf, 0, 92);
            *(lf as *mut i32) = -11; // lfHeight: 11pt at 96dpi
            *(lf.add(0x10) as *mut i32) = 400; // lfWeight: FW_NORMAL
            *lf.add(0x17) = 1; // lfCharSet: DEFAULT_CHARSET
            let face: &[u16] = &[0x53, 0x65, 0x67, 0x6f, 0x65, 0x20, 0x55, 0x49, 0]; // "Segoe UI\0"
            std::ptr::copy_nonoverlapping(face.as_ptr(), lf.add(0x1c) as *mut u16, face.len());
        }};
    }

    match u_action {
        // ── simple bool/uint GET actions ─────────────────────────────────────

        // SPI_GETBORDER (5) — border width; Wine default 1
        0x05 => write_u32!(1),

        // SPI_GETSCREENSAVEACTIVE (16) — no screen saver in Weave
        0x10 => write_u32!(0),

        // SPI_GETICONTITLELOGFONT (31) — icon-title LOGFONTW
        // LOGFONTW layout (92 bytes): lfHeight(i32)+lfWidth(i32)+…+lfFaceName[32](u16×32)
        0x1f => {
            if pv_param.is_null() {
                return 0;
            }
            write_logfont!(pv_param);
            1
        }

        // SPI_GETDRAGFULLWINDOWS (38) — drag full windows: TRUE per Wine default
        0x26 => write_u32!(1),

        // SPI_GETNONCLIENTMETRICS (41) — NONCLIENTMETRICSW; Vista+ cbSize = 340
        // Wine ref: dlls/win32u/sysparams.c — fills 5 LOGFONTWs from registry entries;
        // sets iPaddedBorderWidth only when cbSize == 340; returns FALSE on null ptr.
        0x29 => {
            if pv_param.is_null() {
                return 0;
            }
            let cb_size = *(pv_param as *const u32);
            if cb_size == 0 {
                return 0;
            }
            std::ptr::write_bytes(pv_param, 0, cb_size as usize);
            *(pv_param as *mut u32) = cb_size;
            let p32 = pv_param as *mut i32;
            *p32.add(1) = 1; // iBorderWidth  (+0x04)
            *p32.add(2) = 17; // iScrollWidth  (+0x08)
            *p32.add(3) = 17; // iScrollHeight (+0x0c)
            *p32.add(4) = 19; // iCaptionWidth (+0x10)
            *p32.add(5) = 19; // iCaptionHeight(+0x14)
            write_logfont!(pv_param.add(0x18)); // lfCaptionFont
            *p32.add(0x74 / 4) = 15; // iSmCaptionWidth  (+0x74)
            *p32.add(0x78 / 4) = 15; // iSmCaptionHeight (+0x78)
            write_logfont!(pv_param.add(0x7c)); // lfSmCaptionFont
            *p32.add(0xd8 / 4) = 19; // iMenuWidth  (+0xd8)
            *p32.add(0xdc / 4) = 19; // iMenuHeight (+0xdc)
            write_logfont!(pv_param.add(0xe0)); // lfMenuFont
            write_logfont!(pv_param.add(0x13c)); // lfStatusFont
            write_logfont!(pv_param.add(0x198)); // lfMessageFont
            // iPaddedBorderWidth (+0x1f4) — already zeroed by write_bytes above
            1
        }

        // SPI_GETWORKAREA (48) — usable desktop RECT
        // Wine ref: dlls/win32u/sysparams.c — fills RECT from primary monitor's rcWork.
        0x30 => {
            if pv_param.is_null() {
                return 0;
            }
            let r = pv_param as *mut i32;
            *r.add(0) = 0;
            *r.add(1) = 0;
            *r.add(2) = 1024;
            *r.add(3) = 768;
            1
        }

        // SPI_GETFONTSMOOTHING (74) — font smoothing enabled; TRUE per Wine/Win10 default
        0x4a => write_u32!(1),

        // SPI_GETWHEELSCROLLLINES (104) — lines per wheel notch; 3 = Windows default
        0x68 => write_u32!(3),

        // SPI_GETMENUSHOWDELAY (106) — ms before submenu opens; 400 = Windows default
        0x6a => write_u32!(400),

        // SPI_GETSCREENSAVERRUNNING (114) — no screen saver running in Weave
        0x72 => write_u32!(0),

        // SPI_GETHOTTRACKING (0x1002) — TRUE: highlight controls on mouse-over
        0x1002 => write_u32!(1),

        // SPI_GETGRADIENTCAPTIONS (0x1008) — TRUE: gradient title bars
        0x1008 => write_u32!(1),

        // SPI_GETKEYBOARDCUES (0x100a) — TRUE: always show keyboard underlines
        0x100a => write_u32!(1),

        // SPI_GETMOUSECLICKLOCK (0x101e) — FALSE: no click-lock
        0x101e => write_u32!(0),

        // SPI_GETFLATMENU (0x1022) — TRUE: flat menus (Vista+ default)
        0x1022 => write_u32!(1),

        // SPI_GETFONTSMOOTHINGTYPE (0x200a) — 2 = FE_FONTSMOOTHINGCLEARTYPE
        0x200a => write_u32!(2),

        // SPI_GETFONTSMOOTHINGCONTRAST (0x200c) — 1400 = Wine/Win default
        0x200c => write_u32!(1400),

        // ── SET actions accepted silently ────────────────────────────────────
        // Wine ref: dlls/win32u/sysparams.c — SET actions update registry + broadcast
        // WM_SETTINGCHANGE when SPIF_SENDCHANGE set. Weave accepts without persisting.
        0x06 | // SPI_SETBORDER
        0x11 | // SPI_SETSCREENSAVEACTIVE
        0x27 | // SPI_SETDRAGFULLWINDOWS
        0x4b | // SPI_SETFONTSMOOTHING
        0x69 | // SPI_SETMENUSHOWDELAY
        0x1003 | // SPI_SETHOTTRACKING
        0x1009 | // SPI_SETGRADIENTCAPTIONS
        0x100b | // SPI_SETKEYBOARDCUES
        0x1023 | // SPI_SETFLATMENU
        0x200b | // SPI_SETFONTSMOOTHINGTYPE
        0x200d => 1, // SPI_SETFONTSMOOTHINGCONTRAST

        _ => {
            eprintln!("weave/user32: SystemParametersInfoW({u_action:#x}) → FALSE (unhandled)");
            0
        }
    }
}

/// GetMonitorInfoA — fill a MONITORINFO or MONITORINFOEX structure (ANSI).
///
/// Returns FALSE — stub (no multi-monitor support).
///
/// # Safety
/// `lpmi` is accepted but not dereferenced.
// Wine ref: dlls/win32u/sysparams.c::get_monitor_info — fills rcMonitor/rcWork/dwFlags;
// MONITORINFOEX adds szDevice name; cbSize must be sizeof(MONITORINFO) or MONITORINFOEX
// else returns FALSE; primary monitor has MONITORINFOF_PRIMARY flag set.
pub unsafe extern "win64" fn get_monitor_info_a(_h_monitor: usize, _lpmi: *mut u8) -> i32 {
    0 // FALSE
}

/// GetDialogBaseUnits — return dialog base units. Returns a fixed value.
// Wine ref: dlls/win32u/sysparams.c::get_dialog_base_units — measures average char width/height
// of system font via get_char_dimensions on screen DC; scales by DPI; low word = horizontal
// base units (avg char width), high word = vertical base units (avg char height).
pub extern "win64" fn get_dialog_base_units() -> u32 {
    // Low word = horizontal base units (typically 6), high word = vertical (13).
    (13 << 16) | 6
}

/// ChildWindowFromPointEx — find child window containing a point.
///
/// Returns NULL — no child windows in stub.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/win32u/win32u_private.h::window_from_point — walks child list in Z-order;
// uFlags (CWP_SKIPINVISIBLE/SKIPDISABLED/SKIPTRANSPARENT) control which children are skipped;
// returns parent if no child contains the point.
pub unsafe extern "win64" fn child_window_from_point_ex(
    _hwnd_parent: usize,
    _point_x: i32,
    _point_y: i32,
    _u_flags: u32,
) -> usize {
    0 // NULL
}

/// LoadMenuW — locate an RT_MENU resource in `h_instance` and return a
/// synthetic, stable HMENU for `(h_instance, name)`.
///
/// # Safety
/// If `lp_menu_name` is not an ordinal (`IS_INTRESOURCE`), the caller
/// guarantees it points to a valid null-terminated UTF-16 string.
// Wine ref: dlls/user32/menu.c::LoadMenuW (lines 560–566) —
//   HRSRC hrsrc = FindResourceW( instance, name, (LPWSTR)RT_MENU );
//   if (!hrsrc) return 0;
//   return LoadMenuIndirectW( LoadResource( instance, hrsrc ));
// RT_MENU = MAKEINTRESOURCE(4) per include/winuser.h:816. Failure mode:
// missing resource → NULL; everything else goes through LoadMenuIndirectW
// which parses the MENU/MENUEX template. Weave stops at the resource
// lookup and hands out a synthetic HMENU via the menu_handles slab; we
// do NOT parse the template (out of scope for this brief).
pub unsafe extern "win64" fn load_menu_w(h_instance: usize, lp_menu_name: *const u16) -> usize {
    restrace!(
        "load_menu_w hInst={h_instance:#x} name={:#x}",
        lp_menu_name as usize
    );

    // Wine: hInst==NULL resolves to the user32 module for system menus.
    // Out of scope for the first pass — return NULL.
    if h_instance == 0 {
        return 0;
    }

    let image_base = match weave_core::module_handles::base_of(h_instance) {
        Some(b) => b,
        None => return 0,
    };

    // Classify the name via IS_INTRESOURCE and build a ResourceId.
    let name_ptr = lp_menu_name as usize;
    let name_id = if name_ptr >> 16 == 0 {
        weave_core::resource::ResourceId::Id(name_ptr as u16)
    } else {
        // SAFETY: caller contract — ptr is a valid NUL-terminated UTF-16
        // string when it's not an ordinal.
        let mut wchars: Vec<u16> = Vec::new();
        unsafe {
            let mut p = lp_menu_name;
            for _ in 0..32_768 {
                let ch = *p;
                if ch == 0 {
                    break;
                }
                wchars.push(ch);
                p = p.add(1);
            }
        }
        weave_core::resource::ResourceId::Name(wchars)
    };

    const RT_MENU: u16 = 4;
    if weave_core::resource::find_resource(
        image_base,
        weave_core::resource::ResourceId::Id(RT_MENU),
        name_id,
        0,
    )
    .is_none()
    {
        return 0;
    }

    // SAFETY: name_ptr has already been classified above; `name_key_from_wide_ptr`
    // applies the same IS_INTRESOURCE gate before dereferencing.
    let name_key = unsafe { crate::menu_handles::name_key_from_wide_ptr(name_ptr) };
    crate::menu_handles::register(h_instance, name_key)
}

/// LoadMenuA — ANSI form of LoadMenuW.
///
/// Per Wine, the name argument is interpreted via `IS_INTRESOURCE`: small
/// integers are ordinals (no string deref), everything else is an LPCSTR.
/// This stub converts string names to UTF-16 (CP_ACP, 1-byte pass-through
/// since resource names are ASCII in practice) and trampolines to
/// `load_menu_w`.
///
/// # Safety
/// If `lp_menu_name` is not an ordinal, caller guarantees it points to a
/// valid NUL-terminated byte string.
// Wine ref: dlls/user32/menu.c::LoadMenuA (lines 549–555) —
//   HRSRC hrsrc = FindResourceA( instance, name, (LPSTR)RT_MENU );
//   if (!hrsrc) return 0;
//   return LoadMenuIndirectA( LoadResource( instance, hrsrc ));
// IS_INTRESOURCE preserves ordinals across A/W; string names are widened
// by FindResourceA internally. Weave's W implementation handles both, so
// we widen the name here and delegate.
pub unsafe extern "win64" fn load_menu_a(h_instance: usize, lp_menu_name: *const u8) -> usize {
    let name_ptr = lp_menu_name as usize;
    if name_ptr >> 16 == 0 {
        // Ordinal path: reinterpret as u16 ordinal directly — no string deref.
        // SAFETY: w-form's IS_INTRESOURCE branch does not dereference.
        return unsafe { load_menu_w(h_instance, lp_menu_name as *const u16) };
    }
    // String path: widen ASCII/CP_ACP to UTF-16 and call through.
    // SAFETY: caller contract — lp_menu_name is a valid NUL-terminated byte string.
    let wide: Vec<u16> = unsafe {
        let mut out: Vec<u16> = Vec::new();
        let mut p = lp_menu_name;
        for _ in 0..32_768 {
            let b = *p;
            if b == 0 {
                break;
            }
            out.push(b as u16);
            p = p.add(1);
        }
        out.push(0);
        out
    };
    // SAFETY: `wide` is NUL-terminated and lives for the call.
    unsafe { load_menu_w(h_instance, wide.as_ptr()) }
}

/// SetMenu — attach or remove a menu from a top-level window.
///
/// Returns TRUE. Weave does not render Win32 menus natively; this is a no-op stub.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/win32u/menu.c::NtUserSetMenu — stores hMenu in window data,
// posts WM_NCPAINT for menu-bar repaint; top-level only.
pub unsafe extern "win64" fn set_menu(hwnd: usize, h_menu: usize) -> i32 {
    eprintln!("weave/user32: SetMenu hwnd={hwnd:#x} hmenu={h_menu:#x} → TRUE");
    1 // TRUE
}

/// GetMenu — retrieve the menu handle for a window.
///
/// Returns 0 (NULL). Weave doesn't track menus per-window.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/win32u/menu.c::NtUserGetMenu — reads menu field from WND struct.
pub unsafe extern "win64" fn get_menu(hwnd: usize) -> usize {
    eprintln!("weave/user32: GetMenu hwnd={hwnd:#x} → NULL");
    0
}

/// DrawMenuBar — redraw the menu bar. Returns TRUE.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/win32u/menu.c — sets the menu-bar-dirty flag and posts WM_NCPAINT;
// only effective for top-level windows with WS_CAPTION|WS_SYSMENU; child windows ignored.
pub unsafe extern "win64" fn draw_menu_bar(_hwnd: usize) -> i32 {
    1 // TRUE
}

/// CheckMenuRadioItem — set a radio-button check mark. Returns TRUE.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/win32u/menu.c::check_menu_radio_item — iterates first..last range;
// sets MFT_RADIOCHECK|MFS_CHECKED on idCheck item; clears MFS_CHECKED on others;
// Windows does NOT remove MFT_RADIOCHECK flag from unchecked items (by design).
pub unsafe extern "win64" fn check_menu_radio_item(
    _h_menu: usize,
    _id_first: u32,
    _id_last: u32,
    _id_check: u32,
    _u_flags: u32,
) -> i32 {
    1 // TRUE
}

/// RemoveMenu — delete a menu item. Returns TRUE.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/win32u/menu.c — finds item by MF_BYPOSITION or MF_BYCOMMAND; removes
// item from list but does NOT destroy a popup submenu handle (use DestroyMenu for that);
// contrast with DeleteMenu which does destroy the submenu.
pub unsafe extern "win64" fn remove_menu(_h_menu: usize, _u_position: u32, _u_flags: u32) -> i32 {
    1 // TRUE
}

/// GetSubMenu — return the handle of a pop-up submenu. Returns NULL.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/win32u/menu.c::get_sub_menu — finds item by MF_BYPOSITION; returns
// item->hSubMenu only if fType has MF_POPUP set; returns NULL if item is not a popup.
pub unsafe extern "win64" fn get_sub_menu(_h_menu: usize, _n_pos: i32) -> usize {
    0 // NULL
}

/// SendDlgItemMessageW — send a message to a dialog control (Wide).
///
/// Returns 0 — stub.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/user32/dialog.c — calls GetDlgItem(hDlg, nIDDlgItem) then SendMessageW;
// returns 0 if control not found (GetDlgItem returns NULL); no special message routing.
pub unsafe extern "win64" fn send_dlg_item_message_w(
    _h_dlg: usize,
    _n_id_dlg_item: i32,
    _msg: u32,
    _w_param: usize,
    _l_param: isize,
) -> isize {
    0
}

/// LoadAcceleratorsW — load an accelerator table resource (Wide).
///
/// Looks up RT_ACCELERATOR (ordinal 9) in the PE resource directory of the
/// module identified by `h_inst`. On success, registers a stable synthetic
/// HACCEL in the `accel_handles` slab keyed on `(h_inst, name_key)` and
/// returns it; duplicate calls with the same key return the same handle.
/// On any failure (NULL hInst, unknown module, missing resource) returns
/// NULL.
///
/// Weave stores the raw `{ptr, size}` of the resource blob — it does NOT
/// decode the `PE_ACCEL` entries. `TranslateAcceleratorW` is still a stub,
/// so the handle is never dereferenced in practice; its purpose is to let
/// guests distinguish present vs absent accelerator tables.
///
/// # Safety
/// If `lp_table_name` is not an ordinal (`IS_INTRESOURCE`), the caller
/// guarantees it points to a valid null-terminated UTF-16 string.
// Wine ref: dlls/user32/resource.c::LoadAcceleratorsW —
//   if (!(rsrc = FindResourceW( instance, name, (LPWSTR)RT_ACCELERATOR ))) return 0;
//   pe_table = LoadResource( instance, rsrc );
//   count = SizeofResource( instance, rsrc ) / sizeof(*pe_table);
//   if (!count) return 0;
//   ...
//   handle = NtUserCreateAcceleratorTable( table, count );
// RT_ACCELERATOR = MAKEINTRESOURCE(9) per include/winuser.h. Failure mode:
// missing resource → 0; empty table → 0. Wine then copies each 8-byte
// PE_ACCEL (fVirt, key, cmd, pad) into an ACCEL and hands the array to
// NtUserCreateAcceleratorTable, which owns the kernel object. Weave stops
// at the resource lookup and stores the raw blob — out of scope: parsing
// the ACCEL entries, TranslateAcceleratorW semantics, DestroyAcceleratorTable.
pub unsafe extern "win64" fn load_accelerators_w(
    h_inst: usize,
    lp_table_name: *const u16,
) -> usize {
    restrace!(
        "load_accelerators_w hInst={h_inst:#x} name={:#x}",
        lp_table_name as usize
    );

    // Wine: hInst==NULL would resolve to user32's module for system
    // accelerators. Out of scope — return NULL.
    if h_inst == 0 {
        return 0;
    }

    let image_base = match weave_core::module_handles::base_of(h_inst) {
        Some(b) => b,
        None => return 0,
    };

    // Classify the name via IS_INTRESOURCE and build a ResourceId.
    let name_ptr = lp_table_name as usize;
    let name_id = if name_ptr >> 16 == 0 {
        weave_core::resource::ResourceId::Id(name_ptr as u16)
    } else {
        // SAFETY: caller contract — ptr is a valid NUL-terminated UTF-16
        // string when it's not an ordinal.
        let mut wchars: Vec<u16> = Vec::new();
        unsafe {
            let mut p = lp_table_name;
            for _ in 0..32_768 {
                let ch = *p;
                if ch == 0 {
                    break;
                }
                wchars.push(ch);
                p = p.add(1);
            }
        }
        weave_core::resource::ResourceId::Name(wchars)
    };

    const RT_ACCELERATOR: u16 = 9;
    let entry_ptr = match weave_core::resource::find_resource_entry(
        image_base,
        weave_core::resource::ResourceId::Id(RT_ACCELERATOR),
        name_id,
        0,
    ) {
        Some(p) => p,
        None => return 0,
    };

    // Read the IMAGE_RESOURCE_DATA_ENTRY to get (blob_ptr, size).
    // SAFETY: find_resource_entry returned a pointer to a valid, bounds-
    // checked IMAGE_RESOURCE_DATA_ENTRY within the mapped image.
    let (blob_ptr, size) =
        match unsafe { weave_core::resource::resource_entry_ptr_and_size(image_base, entry_ptr) } {
            Some((p, s)) => (p as usize, s as u32),
            None => return 0,
        };

    // SAFETY: name_ptr has already been classified above; `name_key_from_wide_ptr`
    // applies the same IS_INTRESOURCE gate before dereferencing.
    let name_key = unsafe { crate::accel_handles::name_key_from_wide_ptr(name_ptr) };
    crate::accel_handles::register(
        h_inst,
        name_key,
        crate::accel_handles::AccelBlob {
            ptr: blob_ptr,
            size,
        },
    )
}

/// LoadAcceleratorsA — ANSI form of LoadAcceleratorsW.
///
/// Per Wine, the name argument is interpreted via `IS_INTRESOURCE`: small
/// integers are ordinals (no string deref), everything else is an LPCSTR.
/// This implementation converts string names to UTF-16 (CP_ACP, 1-byte
/// pass-through since resource names are ASCII in practice) and
/// trampolines to `load_accelerators_w`.
///
/// # Safety
/// If `lp_table_name` is not an ordinal, caller guarantees it points to a
/// valid NUL-terminated byte string.
// Wine ref: dlls/user32/resource.c::LoadAcceleratorsA —
//   if (IS_INTRESOURCE(lpTableName)) return LoadAcceleratorsW( instance, (LPCWSTR)lpTableName );
//   len = MultiByteToWideChar( CP_ACP, 0, lpTableName, -1, NULL, 0 );
//   ...
//   result = LoadAcceleratorsW(instance,uni);
// IS_INTRESOURCE preserves ordinals across A/W without any string deref;
// string names are widened via CP_ACP. Weave's W implementation handles
// both, so we widen the name here and delegate.
pub unsafe extern "win64" fn load_accelerators_a(h_inst: usize, lp_table_name: *const u8) -> usize {
    let name_ptr = lp_table_name as usize;
    if name_ptr >> 16 == 0 {
        // Ordinal path: reinterpret as u16 ordinal directly — no string deref.
        // SAFETY: w-form's IS_INTRESOURCE branch does not dereference.
        return unsafe { load_accelerators_w(h_inst, lp_table_name as *const u16) };
    }
    // String path: widen ASCII/CP_ACP to UTF-16 and call through.
    // SAFETY: caller contract — lp_table_name is a valid NUL-terminated byte string.
    let wide: Vec<u16> = unsafe {
        let mut out: Vec<u16> = Vec::new();
        let mut p = lp_table_name;
        for _ in 0..32_768 {
            let b = *p;
            if b == 0 {
                break;
            }
            out.push(b as u16);
            p = p.add(1);
        }
        out.push(0);
        out
    };
    // SAFETY: `wide` is NUL-terminated and lives for the call.
    unsafe { load_accelerators_w(h_inst, wide.as_ptr()) }
}

/// TranslateAcceleratorW — decode ACCEL table, match MSG, dispatch WM_COMMAND.
///
/// Walks every entry in the PE_ACCEL blob stored by `load_accelerators_w`.
/// Each blob entry is 8 bytes: `fVirt(u16), key(u16), cmd(u16), pad(u16)`.
/// Only the low byte of fVirt carries the flag bits (FVIRTKEY/FSHIFT/FCONTROL/FALT).
/// On a match, sends WM_COMMAND(wparam = 0x10000|cmd) to h_wnd via send_message_w.
/// Returns 1 on match, 0 on no match / null HACCEL / unknown HACCEL.
///
/// Deferred:
/// - WM_SYSCOMMAND path (system-menu accelerators) — always returns 0 for those.
/// - Grayed/disabled menu-item skip (Wine checks MF_DISABLED|MF_GRAYED; first pass always
///   dispatches WM_COMMAND regardless of menu state).
///
/// # Safety
/// `lp_msg` must point to a valid `Msg` struct, or be null.
// Wine ref: dlls/win32u/menu.c::translate_accelerator (line 1703) —
//   ACCEL struct layout from include/winuser.h: { BYTE fVirt; WORD key; WORD cmd; } (6 bytes
//   user-facing); PE resource blob (PE_ACCEL, dlls/user32/resource.c) is 8 bytes:
//   { WORD fVirt; WORD key; WORD cmd; WORD pad; }. Modifier flag constants: FVIRTKEY=0x01,
//   FSHIFT=0x04, FCONTROL=0x08, FALT=0x10. Triggers: WM_KEYDOWN/WM_SYSKEYDOWN for FVIRTKEY
//   path; WM_CHAR/WM_SYSCHAR for non-FVIRTKEY path. On match: send_message(hwnd, WM_COMMAND,
//   0x10000|cmd, 0) for regular menu items; WM_SYSCOMMAND for system menu (deferred here).
//   Return TRUE if matched, FALSE otherwise.
// Wine ref (modifier-mask block, line ~1710): mask = 0; if NtUserGetKeyState(VK_CONTROL) &
//   0x8000: mask |= FCONTROL; if NtUserGetKeyState(VK_MENU) & 0x8000: mask |= FALT; if
//   NtUserGetKeyState(VK_SHIFT) & 0x8000: mask |= FSHIFT; FVIRTKEY path then checks
//   mask == (fVirt & (FSHIFT|FCONTROL|FALT)); non-FVIRTKEY (WM_CHAR) path only checks
//   (mask & FALT) == (fVirt & FALT).
pub unsafe extern "win64" fn translate_accelerator_w(
    h_wnd: usize,
    h_acc_table: usize,
    lp_msg: *const Msg,
) -> i32 {
    // Null guard: hwnd=0 or haccel=0 → no-op.
    if h_wnd == 0 || h_acc_table == 0 || lp_msg.is_null() {
        return 0;
    }

    // Look up the raw resource blob for this HACCEL.
    let blob = match crate::accel_handles::lookup(h_acc_table) {
        Some((_, _, b)) => b,
        None => return 0,
    };

    if blob.ptr == 0 || blob.size == 0 {
        return 0;
    }

    // SAFETY: lp_msg is non-null per guard above; caller contract.
    let msg = unsafe { &*lp_msg };

    // Only process keyboard messages that can match accelerators.
    let is_key_msg = matches!(
        msg.message,
        WM_KEYDOWN | WM_SYSKEYDOWN | WM_CHAR | WM_SYSCHAR
    );
    if !is_key_msg {
        return 0;
    }

    // Accelerator modifier flag constants (Wine include/winuser.h).
    const FVIRTKEY: u8 = 0x01;
    const FSHIFT: u8 = 0x04;
    const FCONTROL: u8 = 0x08;
    const FALT: u8 = 0x10;
    // Flag in fVirt indicating this is the last entry in the table.
    const FNOINVERT: u8 = 0x02;
    // Undocumented sentinel: the last entry has 0x80 set in fVirt (Win32 PE resource format).
    const LAST_ENTRY: u8 = 0x80;

    // PE_ACCEL blob: each entry is 8 bytes { WORD fVirt, WORD key, WORD cmd, WORD pad }.
    const ENTRY_SIZE: u32 = 8;
    let count = blob.size / ENTRY_SIZE;
    if count == 0 {
        return 0;
    }

    let base = blob.ptr as *const u8;

    for i in 0..count {
        let offset = (i * ENTRY_SIZE) as usize;
        // SAFETY: blob.ptr+size was obtained from a valid mapped PE resource section.
        // We read each field with read_unaligned to handle potentially-unaligned blobs.
        let (f_virt_w, key, cmd): (u16, u16, u16) = unsafe {
            let p = base.add(offset);
            let fv = (p as *const u16).read_unaligned();
            let k = (p.add(2) as *const u16).read_unaligned();
            let c = (p.add(4) as *const u16).read_unaligned();
            (fv, k, c)
        };

        // Only the low byte carries the flags; high byte is padding in PE_ACCEL.
        let f_virt = f_virt_w as u8;

        // wparam holds the virtual-key code (FVIRTKEY path) or the character code.
        let wp = msg.w_param as u16;
        if wp != key {
            // Try next entry unless this was the last one.
            if f_virt & LAST_ENTRY != 0 {
                break;
            }
            continue;
        }

        // Build modifier mask from the live VK state table via GetKeyState.
        // Wine ref (modifier-mask block, menu.c line ~1710): queries NtUserGetKeyState for
        // VK_CONTROL (0x11), VK_MENU (0x12), VK_SHIFT (0x10); bit 15 set means key is down.
        let mut mask: u8 = 0;
        if (get_key_state(0x10 /* VK_SHIFT */) as u16) & 0x8000 != 0 {
            mask |= FSHIFT;
        }
        if (get_key_state(0x11 /* VK_CONTROL */) as u16) & 0x8000 != 0 {
            mask |= FCONTROL;
        }
        if (get_key_state(0x12 /* VK_MENU */) as u16) & 0x8000 != 0 {
            mask |= FALT;
        }

        let matched = if msg.message == WM_CHAR || msg.message == WM_SYSCHAR {
            // Character (non-FVIRTKEY) path: must NOT have FVIRTKEY set;
            // ALT state in fVirt must match ALT state in MSG.
            (f_virt & FVIRTKEY == 0) && ((mask & FALT) == (f_virt & FALT))
        } else {
            // Virtual-key (FVIRTKEY) path: must have FVIRTKEY set;
            // shift/ctrl/alt modifiers in fVirt must all match.
            (f_virt & FVIRTKEY != 0)
                && ((mask & (FSHIFT | FCONTROL | FALT)) == (f_virt & (FSHIFT | FCONTROL | FALT)))
        };

        if matched {
            // Deferred: WM_SYSCOMMAND path (system-menu accel detection requires
            // menu handle lookup — out of scope for first pass).
            // Always send WM_COMMAND for regular accelerators.
            send_message_w(h_wnd, WM_COMMAND, (0x10000_usize) | (cmd as usize), 0);
            return 1;
        }

        // If this was the last entry, stop.
        if f_virt & LAST_ENTRY != 0 {
            break;
        }
        // Also honour FNOINVERT as a sentinel in some resource compilers.
        let _ = FNOINVERT; // referenced for documentation, not used as break condition
    }

    0
}

/// GetFocus — return the HWND that currently has keyboard focus. Returns NULL.
// Wine ref: dlls/win32u/input.c::get_focus — queries GUITHREADINFO for calling thread;
// returns info.hwndFocus; returns NULL if thread has no focus window or no message queue.
// Wine ref: dlls/win32u/input.c — returns the focus HWND for the calling thread's queue.
pub extern "win64" fn get_focus() -> usize {
    FOCUSED_HWND.load(Ordering::SeqCst)
}

/// LoadBitmapW — load a bitmap resource (Wide). Returns NULL.
///
/// # Safety
/// `lp_bitmap_name` is accepted but not dereferenced.
// Wine ref: dlls/user32/cursoricon.c::BITMAP_Load — calls LoadImageW(LR_LOADFROMFILE or
// RT_BITMAP resource); OBM_* predefined IDs (< 32768) load from OEMRESOURCE;
// returns DDB HBITMAP; caller must DeleteObject.
pub unsafe extern "win64" fn load_bitmap_w(
    _h_instance: usize,
    _lp_bitmap_name: *const u16,
) -> usize {
    restrace!(
        "load_bitmap_w hInst={_h_instance:#x} name={:#x} → zero",
        _lp_bitmap_name as usize
    );
    0 // NULL HBITMAP
}

/// GetClassInfoW — retrieve information about a registered window class (Wide).
///
/// Looks up the class in Weave's class registry. Returns TRUE if found and fills
/// `lp_wnd_class`; returns FALSE if the class does not exist.
///
/// # Safety
/// `lp_class_name` must be a valid null-terminated UTF-16 string or an ATOM cast to pointer.
/// `lp_wnd_class` must point to a writable `WNDCLASSW` struct (72 bytes) or be null.
// Wine ref: dlls/user32/class.c — calls NtUserGetClassInfoEx; searches per-instance then
// global class list; fills WNDCLASSEXW; lpszMenuName returned as atom or pointer;
// returns FALSE + ERROR_CLASS_DOES_NOT_EXIST if not found.
pub unsafe extern "win64" fn get_class_info_w(
    _h_instance: usize,
    lp_class_name: *const u16,
    lp_wnd_class: *mut u8,
) -> i32 {
    // ATOM inputs (LOWORD < 0xC000, HIWORD == 0) are not yet supported — treat as not found.
    let name = if lp_class_name.is_null() || (lp_class_name as usize) < 0xC000 {
        eprintln!("weave/user32: GetClassInfoW(atom/null) → FALSE");
        return 0;
    } else {
        unsafe { decode_wide(lp_class_name) }
    };

    let entry = class::find(&name);
    eprintln!(
        "weave/user32: GetClassInfoW({:?}) → {}",
        name,
        if entry.is_some() { "TRUE" } else { "FALSE" }
    );
    let entry = match entry {
        Some(e) => e,
        None => return 0,
    };

    if !lp_wnd_class.is_null() {
        // Fill WNDCLASSW (72 bytes, Win64 layout — see defs.rs WndClassW):
        //   offset  0: style (u32)
        //   offset  4: _pad  (u32) — zero
        //   offset  8: lpfnWndProc (usize)
        //   offset 16: cbClsExtra (i32) — zero
        //   offset 20: cbWndExtra (i32)
        //   offset 24: hInstance (usize) — zero
        //   offset 32: hIcon (usize) — zero
        //   offset 40: hCursor (usize)
        //   offset 48: hbrBackground (usize)
        //   offset 56: lpszMenuName (*const u16) — null
        //   offset 64: lpszClassName (*const u16) — null (caller already knows)
        let p = lp_wnd_class;
        unsafe {
            *(p.add(0) as *mut u32) = entry.style;
            *(p.add(4) as *mut u32) = 0;
            *(p.add(8) as *mut usize) = entry.wnd_proc;
            *(p.add(16) as *mut i32) = 0;
            *(p.add(20) as *mut i32) = entry.cb_wnd_extra as i32;
            *(p.add(24) as *mut usize) = 0;
            *(p.add(32) as *mut usize) = 0;
            *(p.add(40) as *mut usize) = entry.h_cursor;
            *(p.add(48) as *mut usize) = entry.hbr_background;
            *(p.add(56) as *mut usize) = 0;
            *(p.add(64) as *mut usize) = 0;
        }
    }
    1 // TRUE
}

/// CallWindowProcW — pass a message to the specified window procedure (Wide).
///
/// Returns 0 — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/message.c::call_window_proc — checks if lpPrevWndFunc is an
// interprocess thunk (for ANSI↔Unicode conversion); dispatches directly if same-thread;
// used by subclassing chains to call the previous wndproc.
pub unsafe extern "win64" fn call_window_proc_w(
    lp_prev_wnd_func: usize,
    h_wnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    // Previously a stub returning 0 — broke NPP subclassing of Scintilla.
    // NPP calls CallWindowProcW(original_sci_proc, hwnd, SCI_GETDOCPOINTER, 0, 0) to
    // forward unhandled SCI messages to Scintilla's real WndProc.  Stub meant
    // SCI_GETDOCPOINTER always returned NULL, preventing document transfer.
    //
    // Implementation: call the previous WndProc directly using extern "win64"
    // (Windows x64 calling convention), same as call_wnd_proc.
    call_wnd_proc(lp_prev_wnd_func, h_wnd, msg, w_param, l_param)
}

/// Run the modal message loop for a dialog until EndDialog or WM_QUIT.
///
/// # Safety
/// `hwnd` must be a valid dialog HWND created by `crate::dialog`.
unsafe fn run_modal_dialog_loop(hwnd: usize) -> isize {
    crate::dialog::begin_modal(hwnd);
    let mut msg = Msg {
        hwnd: 0,
        message: 0,
        _pad0: 0,
        w_param: 0,
        l_param: 0,
        time: 0,
        pt_x: 0,
        pt_y: 0,
        _pad1: 0,
    };
    loop {
        if crate::dialog::modal_ended() {
            break;
        }
        let ret = unsafe { get_message_w(&mut msg, 0, 0, 0) };
        if ret < 0 {
            break;
        }
        if ret == 0 {
            break;
        }
        if crate::dialog::modal_ended() {
            break;
        }
        if !window::contains(msg.hwnd) && msg.message != WM_NULL {
            continue;
        }
        let _ = unsafe { translate_message(&msg) };
        let _ = unsafe { dispatch_message_w(&msg) };
    }
    let result = crate::dialog::take_modal_result(hwnd).unwrap_or(0);
    window::remove(hwnd);
    result
}

/// DialogBoxParamW — display a modal dialog box from a resource template (Wide).
///
/// Loads RT_DIALOG from the PE, creates the dialog frame and child controls from the
/// DLGTEMPLATE, runs WM_INITDIALOG, then enters a modal message loop until EndDialog.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid for the duration of the call.
// Wine ref: dlls/user32/dialog.c::DialogBoxParamW — FindResourceW(RT_DIALOG), LoadResource,
// DIALOG_CreateIndirect (modal=TRUE), DIALOG_DoDialogBox; returns EndDialog nResult or -1.
pub unsafe extern "win64" fn dialog_box_param_w(
    h_instance: usize,
    lp_template_name: *const u16,
    hwnd_parent: usize,
    lp_dialog_func: usize,
    dw_init_param: isize,
) -> isize {
    if lp_dialog_func == 0 {
        return -1;
    }
    let image_base = weave_core::module_handles::base_of(h_instance).unwrap_or_else(|| {
        if h_instance == 0 {
            weave_core::seh::pe_base()
        } else {
            0
        }
    });
    if image_base == 0 {
        return -1;
    }
    let template_id = lp_template_name as usize;
    eprintln!("weave/user32: DialogBoxParamW(template={template_id:#x}) — Phase B");
    let Some(hwnd) = crate::dialog::create_from_resource(
        image_base,
        lp_template_name,
        hwnd_parent,
        lp_dialog_func,
        dw_init_param,
        h_instance,
    ) else {
        return -1;
    };
    unsafe { run_modal_dialog_loop(hwnd) }
}

/// CharPrevExA — find the previous character in a string (ANSI, code page aware).
///
/// Returns `lpsz - 1` clamped to `lpszStart`. Stub ignores the code page.
///
/// # Safety
/// `lpsz_start` and `lpsz` must be valid pointers into the same buffer.
// Wine ref: dlls/user32/charwidth.c — walks backward from lpsz checking IsDBCSLeadByteEx
// to skip the high byte of a 2-byte DBCS sequence; returns lpszStart if already at start;
// code page affects which lead bytes are valid DBCS high bytes.
pub unsafe extern "win64" fn char_prev_ex_a(
    _code_page: u16,
    lpsz_start: *const u8,
    lpsz: *const u8,
    _b_flags: u32,
) -> *const u8 {
    if lpsz > lpsz_start {
        unsafe { lpsz.sub(1) }
    } else {
        lpsz_start
    }
}

// ── Accessibility / event hooks ───────────────────────────────────────────────

/// NotifyWinEvent — fire a WinEvent hook (accessibility notification).
///
/// Wine ref: dlls/user32/event.c — NtUserNotifyWinEvent dispatches to
/// installed WinEvent hooks via the hook thread. Weave: no-op. We have no
/// accessibility infrastructure; callers (Scintilla, NPP) ignore the return.
pub extern "win64" fn notify_win_event(_event: u32, _hwnd: usize, _id_object: i32, _id_child: i32) {
    // no-op
}

/// FlashWindowEx — flash the taskbar button and/or caption.
///
/// Wine ref: dlls/user32/message.c — updates the window caption highlight
/// state. Weave: no-op, returns FALSE (was not previously active).
///
/// # Safety
/// Pointer arguments must be valid for the duration of the call; null where noted is permitted.
pub unsafe extern "win64" fn flash_window_ex(_pfwi: *const u8) -> i32 {
    0 // FALSE — window was not previously in an active state
}

/// LockWindowUpdate — prevent drawing in the specified window.
///
/// Wine ref: dlls/user32/painting.c — LockWindowUpdate sets a global lock
/// on drawing for one window at a time; NULL unlocks. Weave: no-op stub
/// returning TRUE (always succeeds).
pub extern "win64" fn lock_window_update(_hwnd_lock: usize) -> i32 {
    1 // TRUE
}

/// GetMenuBarInfo — retrieve menu bar information.
///
/// Wine ref: dlls/user32/menu.c — fills MENUBARINFO with the menu rect and
/// HMENU. Weave: fills with zeros and returns FALSE (no menu bar info).
///
/// # Safety
/// `pmbi` must be a valid MENUBARINFO pointer.
pub unsafe extern "win64" fn get_menu_bar_info(
    _hwnd: usize,
    _id_object: i32,
    _id_item: i32,
    pmbi: *mut u8,
) -> i32 {
    // MENUBARINFO starts with cbSize (DWORD). If the pointer is valid and
    // cbSize matches, fill with zeros and return TRUE; otherwise FALSE.
    if pmbi.is_null() {
        return 0;
    }
    0 // FALSE — simplest safe stub
}

/// GetIconInfo — retrieve information about an icon or cursor.
///
/// GetIconInfo: fill an ICONINFO struct for the given icon/cursor handle.
///
/// # Safety
/// `piconinfo` must be a valid pointer to an ICONINFO-sized buffer, or NULL.
// Wine ref: dlls/user32/cursoricon.c + dlls/win32u/window.c::get_icon_info —
// calls NtUserGetIconInfo; fills ICONINFO: fIcon TRUE for icons, FALSE for cursors;
// hotspots 0,0 for icons; hbmMask = monochrome AND-mask copy; hbmColor = color copy
// (NULL for monochrome icons). Both bitmaps are caller-owned (must DeleteObject).
pub unsafe extern "win64" fn get_icon_info(hicon: usize, piconinfo: *mut u8) -> i32 {
    if hicon == 0 || piconinfo.is_null() {
        return 0; // FALSE
    }
    let ii = unsafe { &mut *(piconinfo as *mut IconInfo) };
    let entry = crate::image_handles::get(hicon);
    let is_cursor = entry
        .as_ref()
        .map(|e| matches!(e.kind, crate::image_handles::ImageKind::Cursor))
        .unwrap_or(false);
    ii.f_icon = if is_cursor { 0 } else { 1 };
    ii.x_hotspot = 0;
    ii.y_hotspot = 0;
    // Synthetic bitmap handles: unique per icon, non-zero so callers don't treat
    // NULL as a failure. Not in any GDI table; DeleteObject on them is a no-op.
    // Offset into a range (0x5F00_xxxx) that does not overlap real handle ranges:
    // image_handles (0x6FFF_xxxx), module_handles (0x7FFF_xxxx), semaphore (0x8FFF_xxxx).
    ii.hbm_mask = 0x5F00_0000 | (hicon & 0xFFFF);
    ii.hbm_color = 0x5F10_0000 | (hicon & 0xFFFF);
    1 // TRUE
}

/// CreateIconIndirect — create an icon from an ICONINFO structure.
///
/// Wine ref: dlls/user32/cursoricon.c — allocates a new CURSORICONCACHE entry.
/// Weave: returns a non-NULL handle so callers don't treat NULL as an error.
/// We reuse the ICONINFO pointer value as a fake handle.
///
/// # Safety
/// `piconinfo` is ignored.
// Wine ref: dlls/user32/cursoricon.c — CreateIconIndirect allocates CURSORICONCACHE entry;
// copies mask+color bitmaps from ICONINFO; hbmColor=NULL means single-plane monochrome cursor.
pub unsafe extern "win64" fn create_icon_indirect(piconinfo: *const u8) -> usize {
    piconinfo as usize | 1 // non-NULL fake handle
}

/// IsChild — test if a window is a descendant of another.
///
/// Wine ref: dlls/user32/win.c — IsChild walks the parent chain looking for
/// hWndParent. Weave: stub returning FALSE — parent relationships are not
/// tracked in the window table (Phase 2 gap). No callers crash on FALSE.
// Wine ref: dlls/win32u/window.c::is_child — child must have WS_CHILD; walks
// parent chain stopping when a non-WS_CHILD window is encountered.
pub extern "win64" fn is_child(hwnd_parent: usize, hwnd: usize) -> i32 {
    let mut current = hwnd;
    loop {
        match window::with(current, |w| (w.style & WS_CHILD != 0, w.hwnd_parent)) {
            Some((true, parent)) => {
                if parent == hwnd_parent {
                    return 1;
                }
                current = parent;
            }
            _ => return 0,
        }
    }
}

const GW_HWNDFIRST: u32 = 0;
const GW_HWNDLAST: u32 = 1;
const GW_HWNDNEXT: u32 = 2;
const GW_HWNDPREV: u32 = 3;
const GW_OWNER: u32 = 4;
const GW_CHILD: u32 = 5;
const GW_ENABLEDPOPUP: u32 = 6;

const ERROR_INVALID_HANDLE: u32 = 6;

fn get_window_owner(hwnd: usize) -> Option<usize> {
    if !window::contains(hwnd) {
        return None;
    }
    let style = window::with(hwnd, |w| w.style).unwrap_or(0);
    if (style & WS_POPUP) != 0 && (style & WS_CHILD) == 0 {
        return window::with(hwnd, |w| w.hwnd_parent);
    }
    if (style & WS_CHILD) == 0 {
        return Some(0);
    }
    let mut current = hwnd;
    loop {
        let parent = window::with(current, |w| w.hwnd_parent).unwrap_or(0);
        if parent == 0 {
            return Some(0);
        }
        let parent_is_child =
            window::with(parent, |p| (p.style & WS_CHILD) != 0).unwrap_or(false);
        if !parent_is_child {
            return Some(parent);
        }
        current = parent;
    }
}

fn get_window_root(hwnd: usize) -> usize {
    let mut current = hwnd;
    loop {
        let parent = window::with(current, |w| w.hwnd_parent).unwrap_or(0);
        if parent == 0 {
            return current;
        }
        let parent_is_child =
            window::with(parent, |p| (p.style & WS_CHILD) != 0).unwrap_or(false);
        if !parent_is_child {
            return current;
        }
        current = parent;
    }
}

/// GetWindow — retrieve a window with the specified relationship to the given window.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/win32u/window.c::get_window_relative — GW_CHILD returns first_child;
// GW_HWND* walk sibling list; GW_OWNER reads win->owner (invalid hwnd → ERROR_INVALID_HANDLE);
// GW_ENABLEDPOPUP scans owned visible popups when hwnd is the root ancestor.
pub extern "win64" fn get_window(hwnd: usize, u_cmd: u32) -> usize {
    if hwnd != 0 && !window::contains(hwnd) {
        if u_cmd == GW_OWNER {
            set_last_error(ERROR_INVALID_HANDLE);
        }
        return 0;
    }

    match u_cmd {
        GW_CHILD => window::children_of(hwnd).into_iter().next().unwrap_or(0),
        GW_HWNDFIRST => window::siblings_of(hwnd).into_iter().next().unwrap_or(0),
        GW_HWNDLAST => window::siblings_of(hwnd).into_iter().last().unwrap_or(0),
        GW_HWNDNEXT => {
            let siblings = window::siblings_of(hwnd);
            match siblings.iter().position(|&h| h == hwnd) {
                Some(i) if i + 1 < siblings.len() => siblings[i + 1],
                _ => 0,
            }
        }
        GW_HWNDPREV => {
            let siblings = window::siblings_of(hwnd);
            match siblings.iter().position(|&h| h == hwnd) {
                Some(i) if i > 0 => siblings[i - 1],
                _ => 0,
            }
        }
        GW_OWNER => get_window_owner(hwnd).unwrap_or(0),
        GW_ENABLEDPOPUP => {
            if get_window_root(hwnd) != hwnd {
                return 0;
            }
            window::find_with(|candidate, entry| {
                if candidate == hwnd {
                    return false;
                }
                if (entry.style & WS_POPUP) == 0 || !entry.visible {
                    return false;
                }
                get_window_owner(candidate).unwrap_or(0) == hwnd
            })
        }
        _ => 0,
    }
}

/// IsRectEmpty — test whether a rectangle has zero or negative area.
///
/// Returns TRUE if `lprc` is NULL, or if `left >= right` or `top >= bottom`.
///
/// # Safety
/// `lprc` must be NULL or a valid pointer to a `RECT`-sized region.
// Wine ref: dlls/user32/uitools.c — IsRectEmpty: NULL→TRUE (bug compat);
// returns (rect->left >= rect->right) || (rect->top >= rect->bottom).
pub unsafe extern "win64" fn is_rect_empty(lprc: *const Rect) -> i32 {
    if lprc.is_null() {
        return 1; // TRUE — bug-compat, matches Wine
    }
    let r = unsafe { &*lprc };
    if r.left >= r.right || r.top >= r.bottom {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// CopyRect — copy a RECT from `lprc_src` to `lprc_dst`.
///
/// Returns TRUE on success; FALSE if either pointer is NULL.
///
/// # Safety
/// Both pointers must be NULL or valid, aligned `RECT` pointers.
// Wine ref: dlls/user32/uitools.c — CopyRect: NULL dst or src → FALSE;
// *dest = *src (struct copy); returns TRUE.
pub unsafe extern "win64" fn copy_rect(lprc_dst: *mut Rect, lprc_src: *const Rect) -> i32 {
    if lprc_dst.is_null() || lprc_src.is_null() {
        return 0; // FALSE
    }
    unsafe { std::ptr::copy_nonoverlapping(lprc_src, lprc_dst, 1) };
    1 // TRUE
}

/// InflateRect — expand or shrink a RECT by the specified amounts.
///
/// Subtracts `dx`/`dy` from left/top and adds to right/bottom.
/// Returns FALSE if `lprc` is NULL.
///
/// # Safety
/// `lprc` must be NULL or a valid, aligned mutable `RECT` pointer.
// Wine ref: dlls/user32/uitools.c — InflateRect: NULL→FALSE;
// rect->left -= x; rect->top -= y; rect->right += x; rect->bottom += y; TRUE.
pub unsafe extern "win64" fn inflate_rect(lprc: *mut Rect, dx: i32, dy: i32) -> i32 {
    if lprc.is_null() {
        return 0; // FALSE
    }
    let r = unsafe { &mut *lprc };
    r.left -= dx;
    r.top -= dy;
    r.right += dx;
    r.bottom += dy;
    1 // TRUE
}

/// CharNextW — advance a pointer past the next wide character.
///
/// For BMP characters, advances by one code unit. Returns the same pointer
/// unchanged if already at the null terminator.
///
/// # Safety
/// `lpsz` must be a valid pointer into a null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/string.c — CharNextW: if (*x) x++; return (WCHAR *)x;
// Wide strings are one code unit per BMP character; no DBCS handling needed.
pub unsafe extern "win64" fn char_next_w(lpsz: *const u16) -> *const u16 {
    if lpsz.is_null() {
        return lpsz;
    }
    if unsafe { *lpsz } != 0 {
        unsafe { lpsz.add(1) }
    } else {
        lpsz
    }
}

/// CharLowerBuffW — convert `cch_length` wide characters in a buffer to lowercase in-place.
///
/// Returns `cch_length` on success, 0 if `lpsz` is NULL.
///
/// # Safety
/// `lpsz` must be a valid pointer to at least `cch_length` writable UTF-16 code units.
// Wine ref: dlls/kernelbase/string.c — CharLowerBuffW: NULL→0 (Wine source comment: "YES",
// intentional bug-compat); calls LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_LOWERCASE, str, len,
// str, len). Weave: applies char::to_lowercase() per BMP code unit (no ICU/locale mapping).
pub unsafe extern "win64" fn char_lower_buff_w(lpsz: *mut u16, cch_length: u32) -> u32 {
    if lpsz.is_null() {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(lpsz, cch_length as usize) };
    for cu in slice.iter_mut() {
        *cu = char::from_u32(*cu as u32)
            .map(|ch| ch.to_lowercase().next().unwrap_or(ch) as u16)
            .unwrap_or(*cu);
    }
    cch_length
}

// ── DXVK d3d9.dll gap stubs ───────────────────────────────────────────────────

/// CallWindowProcA — dispatch a message to a wndproc (ANSI variant).
///
/// Stub: returns 0. A real implementation would dispatch to the proc pointer,
/// handling possible interprocess thunks for ANSI↔Unicode conversion.
///
/// # Safety
/// All pointer arguments are accepted but not dereferenced by this stub.
pub unsafe extern "win64" fn call_window_proc_a(
    _proc: usize,
    _hwnd: usize,
    _msg: u32,
    _wparam: usize,
    _lparam: isize,
) -> isize {
    0
}

/// DestroyCursor — destroy a cursor object; return TRUE (no-op).
///
/// # Safety
/// `_cursor` is accepted but not dereferenced.
pub unsafe extern "win64" fn destroy_cursor(_cursor: usize) -> i32 {
    1 // TRUE
}

/// DisplayConfigGetDeviceInfo — return ERROR_NOT_SUPPORTED.
///
/// # Safety
/// `_p` is accepted but not dereferenced.
pub unsafe extern "win64" fn display_config_get_device_info(_p: *mut std::ffi::c_void) -> i32 {
    50 // ERROR_NOT_SUPPORTED
}

/// EnumDisplayDevicesA — ANSI variant; expose the same single adapter as W.
///
/// # Safety
/// `info` must point to a caller-allocated DISPLAY_DEVICEA (cb must be set).
pub unsafe extern "win64" fn enum_display_devices_a(
    _dev: *const u8,
    n: u32,
    info: *mut std::ffi::c_void,
    _flags: u32,
) -> i32 {
    // Weave presents exactly one display adapter (and one monitor per adapter).
    if n > 0 || info.is_null() {
        return 0; // FALSE — no more devices
    }

    // DISPLAY_DEVICEA layout:
    //   offset   0: cb           (u32)
    //   offset   4: DeviceName   (char × 32)
    //   offset  36: DeviceString (char × 128)
    //   offset 164: StateFlags   (u32)
    //   offset 168: DeviceID     (char × 128)
    //   offset 296: DeviceKey    (char × 128)
    let base = info as *mut u8;

    let name = b"\\\\.\\DISPLAY1\0";
    let name_ptr = unsafe { base.add(4) };
    for (i, &c) in name.iter().enumerate().take(32) {
        unsafe { name_ptr.add(i).write(c) };
    }

    let device_string = b"Generic Display\0";
    let device_string_ptr = unsafe { base.add(36) };
    for (i, &c) in device_string.iter().enumerate().take(128) {
        unsafe { device_string_ptr.add(i).write(c) };
    }

    // DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE
    unsafe { (base.add(164) as *mut u32).write(0x0000_0001 | 0x0000_0004) };

    1 // TRUE
}

/// GetDCEx — extended GetDC with clip region and flags.
///
/// Delegates to GetDC; clip region and DCX_* flags are ignored.
///
/// # Safety
/// All arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/dc.c — GetDCEx calls NtUserGetDCEx; DCX_CACHE/DCX_WINDOW/
// DCX_CLIPCHILDREN etc. control DC sourcing and clipping. Weave: single DC per
// window, no clip-region support — delegate to GetDC ignoring clip and flags.
pub unsafe extern "win64" fn get_dc_ex(hwnd: usize, _clip: usize, _flags: u32) -> usize {
    get_dc(hwnd)
}

/// GetDisplayConfigBufferSizes — return ERROR_NOT_SUPPORTED.
///
/// # Safety
/// `_num_paths` and `_num_modes` are accepted but not written.
pub unsafe extern "win64" fn get_display_config_buffer_sizes(
    _flags: u32,
    _num_paths: *mut u32,
    _num_modes: *mut u32,
) -> i32 {
    50 // ERROR_NOT_SUPPORTED
}

/// IsWindowUnicode — return TRUE (Weave windows are always Unicode).
///
/// # Safety
/// `_hwnd` is accepted but not dereferenced.
pub unsafe extern "win64" fn is_window_unicode(_hwnd: usize) -> i32 {
    1 // TRUE
}

/// QueryDisplayConfig — return ERROR_NOT_SUPPORTED.
///
/// # Safety
/// All pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn query_display_config(
    _flags: u32,
    _num_paths: *mut u32,
    _paths: *mut std::ffi::c_void,
    _num_modes: *mut u32,
    _modes: *mut std::ffi::c_void,
    _top: *mut std::ffi::c_void,
) -> i32 {
    50 // ERROR_NOT_SUPPORTED
}

/// SetRect — fill a RECT structure with [x1, y1, x2, y2]; return TRUE.
///
/// RECT layout: four consecutive i32 fields (left, top, right, bottom).
///
/// # Safety
/// `lp_rc`, if non-null, must point to writable storage for four i32 values (16 bytes).
pub unsafe extern "win64" fn set_rect(lp_rc: *mut i32, x1: i32, y1: i32, x2: i32, y2: i32) -> i32 {
    if !lp_rc.is_null() {
        // SAFETY: caller guarantees lp_rc points to 16 bytes of writable i32 storage.
        unsafe {
            *lp_rc = x1;
            *lp_rc.add(1) = y1;
            *lp_rc.add(2) = x2;
            *lp_rc.add(3) = y2;
        }
    }
    1 // TRUE
}

// ── SDL2 gap-fill: raw input, device notification, thread messages, misc ──────
//
// SDL2 imports these via its static IAT. Without them Weave patches every slot
// with unresolved_import_stub (→ 0), causing per-frame noise in CI logs and
// potential misbehaviour in SDL2's event pump and D3D9 render path.

/// PostThreadMessageW — post a message to the queue of a specific thread.
///
/// Returns TRUE (success). Weave has a single-threaded message model; posting
/// to any thread ID is treated as posting to the global queue.
///
/// # Safety
/// All arguments are value-passed; no pointers.
// Wine ref: dlls/win32u/message.c — NtUserPostThreadMessage validates the
// thread ID against the system thread list; if invalid, sets ERROR_INVALID_THREAD_ID
// and returns FALSE.  Weave: always TRUE — single-thread model.
pub extern "win64" fn post_thread_message_w(
    _id_thread: u32,
    _msg: u32,
    _w_param: usize,
    _l_param: isize,
) -> i32 {
    1 // TRUE
}

/// GetRawInputData — copy raw input data from an HRAWINPUT handle.
///
/// Returns 0 with *pcbSize set to 0 — no raw-input data in Weave's model.
/// SDL2 treats 0 bytes as "no data" and continues; the render loop is unaffected.
///
/// # Safety
/// `pcbSize` must be a valid pointer to a u32 if non-null.
// Wine ref: dlls/user32/rawinput.c — GetRawInputData validates cbSizeHeader, then
// copies RAWINPUTHEADER + device-specific data into pData; returns -1 (UINT_MAX)
// on invalid header size.  Weave: always 0 bytes (no raw input subsystem).
pub unsafe extern "win64" fn get_raw_input_data(
    _h_raw_input: usize,
    _ui_command: u32,
    _p_data: *mut u8,
    pcb_size: *mut u32,
    _cb_size_header: u32,
) -> u32 {
    if !pcb_size.is_null() {
        unsafe { *pcb_size = 0 };
    }
    0
}

/// RegisterRawInputDevices — register or unregister devices for raw input.
///
/// Returns TRUE — Weave has no raw input subsystem but SDL2 expects success
/// to proceed with its input initialisation path.
///
/// # Safety
/// `p_raw_input_devices` is not dereferenced.
// Wine ref: dlls/user32/rawinput.c — validates each RAWINPUTDEVICE's usUsagePage
// and usUsage; writes the registrations into a global table.  Weave: no-op TRUE.
pub unsafe extern "win64" fn register_raw_input_devices(
    _p_raw_input_devices: *const u8,
    _ui_num_devices: u32,
    _cb_size: u32,
) -> i32 {
    1 // TRUE
}

/// GetRawInputDeviceList — enumerate all attached raw input devices.
///
/// Writes 0 to *puiNumDevices and returns 0 — no raw input devices in Weave.
///
/// # Safety
/// `pui_num_devices` must be a valid pointer to a u32 if non-null.
// Wine ref: dlls/user32/rawinput.c — fills pRawInputDeviceList with RAWINPUTDEVICELIST
// entries (hDevice + dwType) and sets *puiNumDevices; NULL pRawInputDeviceList is
// legal and just returns the count without filling.
pub unsafe extern "win64" fn get_raw_input_device_list(
    _p_raw_input_device_list: *mut u8,
    pui_num_devices: *mut u32,
    _cb_size: u32,
) -> u32 {
    if !pui_num_devices.is_null() {
        unsafe { *pui_num_devices = 0 };
    }
    0
}

/// GetRawInputDeviceInfoA — retrieve information about a raw input device (ANSI).
///
/// Returns UINT_MAX (error) — no raw input devices in Weave.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/user32/rawinput.c — fills pcbSize with the required buffer
// size when pData is NULL; copies device info when pData is non-NULL.
// Returns -1 (UINT_MAX) on invalid hDevice.
pub unsafe extern "win64" fn get_raw_input_device_info_a(
    _h_device: usize,
    _ui_command: u32,
    _p_data: *mut u8,
    _pcb_size: *mut u32,
) -> u32 {
    u32::MAX // UINT_MAX — invalid device
}

/// RegisterDeviceNotificationW — register for device-change notifications.
///
/// Returns a fake non-NULL handle (1) so SDL2 considers registration successful.
/// SDL2 stores this handle and calls UnregisterDeviceNotification at shutdown.
///
/// # Safety
/// `p_notification_filter` is accepted but not dereferenced.
// Wine ref: dlls/user32/message.c — allocates a DEVICE_NOTIFICATION_DETAILS struct
// and returns its pointer as HDEVNOTIFY; NULL on failure.  Weave: fake handle 1.
pub unsafe extern "win64" fn register_device_notification_w(
    _h_recipient: usize,
    _p_notification_filter: *const u8,
    _flags: u32,
) -> usize {
    1 // HDEVNOTIFY — fake non-NULL handle
}

/// UnregisterDeviceNotification — cancel a device notification registration.
///
/// Returns TRUE. Weave's fake handle (1) is silently accepted.
// Wine ref: dlls/user32/message.c — frees the DEVICE_NOTIFICATION_DETAILS struct.
// Weave: no-op TRUE.
pub extern "win64" fn unregister_device_notification(_h_notify: usize) -> i32 {
    1 // TRUE
}

/// PtInRect — test whether a point lies within a rectangle.
///
/// Returns TRUE if pt.x is in [left, right) and pt.y is in [top, bottom).
/// RECT layout: left, top, right, bottom (four consecutive i32 values).
///
/// Win64 ABI: POINT (8 bytes, two i32 fields) is passed packed in a single
/// 64-bit register — x in bits 0-31, y in bits 32-63.
///
/// # Safety
/// `lp_rc` must point to a valid RECT (16 bytes, four i32 fields) if non-null.
// Wine ref: dlls/user32/misc.c — PtInRect checks left≤x<right && top≤y<bottom;
// an empty rect (left≥right or top≥bottom) always returns FALSE.
pub unsafe extern "win64" fn pt_in_rect(lp_rc: *const i32, pt_packed: u64) -> i32 {
    if lp_rc.is_null() {
        return 0;
    }
    let pt_x = (pt_packed & 0xFFFF_FFFF) as i32;
    let pt_y = (pt_packed >> 32) as i32;
    // SAFETY: caller guarantees lp_rc points to a valid RECT (16 bytes).
    let left = unsafe { *lp_rc };
    let top = unsafe { *lp_rc.add(1) };
    let right = unsafe { *lp_rc.add(2) };
    let bottom = unsafe { *lp_rc.add(3) };
    if pt_x >= left && pt_x < right && pt_y >= top && pt_y < bottom {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// TrackMouseEvent — post hover and leave messages for mouse tracking.
///
/// Returns TRUE — Weave generates no hover/leave events but SDL2 does not
/// depend on them for rendering correctness.
///
/// # Safety
/// `lp_event_track` is accepted but not dereferenced.
// Wine ref: dlls/user32/input.c — sets a timer to fire WM_MOUSEHOVER/WM_MOUSELEAVE
// when the mouse enters/leaves the client area; HOVER_DEFAULT maps to the system
// hover time (400ms by default).
// Wine ref: dlls/win32u/input.c::NtUserTrackMouseEvent — validates cbSize >= 24,
// hwndTrack must be valid; TME_LEAVE subscribes a one-shot WM_MOUSELEAVE;
// TME_CANCEL|TME_LEAVE unsubscribes; TME_QUERY fills the struct with active flags;
// TME_HOVER sets a timer (Weave: accepted but not fired — no timer infrastructure).
pub unsafe extern "win64" fn track_mouse_event(lp_event_track: *mut u8) -> i32 {
    if lp_event_track.is_null() {
        return 0; // FALSE
    }
    let tme = unsafe { &*(lp_event_track as *const TrackMouseEventStruct) };
    // Wine: cbSize must be >= sizeof(TRACKMOUSEEVENT) = 24 on x64.
    if (tme.cb_size as usize) < std::mem::size_of::<TrackMouseEventStruct>() {
        return 0; // FALSE — malformed struct
    }
    let hwnd = tme.hwnd_track;
    let flags = tme.dw_flags;

    if flags & TME_QUERY != 0 {
        // Fill dwFlags with currently active tracking flags for hwndTrack.
        let tme_mut = unsafe { &mut *(lp_event_track as *mut TrackMouseEventStruct) };
        let active = if tme_leave_table()
            .lock()
            .map(|t| t.contains(&hwnd))
            .unwrap_or(false)
        {
            TME_LEAVE
        } else {
            0
        };
        tme_mut.dw_flags = active;
        return 1; // TRUE
    }

    if flags & TME_CANCEL != 0 {
        if flags & TME_LEAVE != 0 {
            cancel_tme_leave(hwnd);
        }
        return 1; // TRUE
    }

    if flags & TME_LEAVE != 0 {
        register_tme_leave(hwnd);
    }
    // TME_HOVER: accepted but timer not fired — no timer infrastructure yet.
    1 // TRUE
}

/// GetMessageExtraInfo — return the extra-message-info value for the last message.
///
/// Returns 0 — no extra info in Weave's message model.
// Wine ref: dlls/user32/message.c — returns the thread-local extra_info field
// set by SetMessageExtraInfo; defaults to 0.  Weave: always 0.
pub extern "win64" fn get_message_extra_info() -> isize {
    0
}

/// GetClipboardSequenceNumber — return the clipboard update sequence counter.
///
/// Returns 0 — clipboard sequence is unsupported in Weave.
/// SDL2 uses this to detect clipboard changes; returning 0 means "no change".
// Wine ref: dlls/user32/clipboard.c — reads a process-local counter incremented
// on each clipboard operation.  Weave: always 0.
pub extern "win64" fn get_clipboard_sequence_number() -> u32 {
    0
}

/// SetLayeredWindowAttributes — set transparency attributes for a layered window.
///
/// Returns TRUE — layered windows are not composited in Weave but the call
/// must succeed so SDL2 can continue window initialisation.
///
/// # Safety
/// All arguments are value-passed; no pointers.
// Wine ref: dlls/user32/winpos.c — validates the WS_EX_LAYERED style, updates
// the window's alpha/colorkey, and invalidates the window.  Weave: no-op TRUE.
pub extern "win64" fn set_layered_window_attributes(
    _hwnd: usize,
    _cr_key: u32,
    _b_alpha: u8,
    _dw_flags: u32,
) -> i32 {
    1 // TRUE
}

/// SetWindowRgn — set the window's clipping region.
///
/// Returns non-zero (success). Weave ignores the region — the full window
/// rectangle is always the visible area.
///
/// # Safety
/// `h_rgn` is an opaque GDI handle; the window takes ownership (we don't free it).
// Wine ref: dlls/win32u/window.c — NtUserSetWindowRgn validates the window,
// copies the region, and invalidates; the HRGN ownership transfers on success.
// Weave: no-op, returns 1.
pub extern "win64" fn set_window_rgn(_hwnd: usize, _h_rgn: usize, _b_redraw: i32) -> i32 {
    1 // non-zero = success
}

/// ToUnicode — translate a virtual key to Unicode characters.
///
/// Returns 0 — no translation performed. SDL2 falls back to its own key
/// mapping when ToUnicode returns 0.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/win32u/keyboard.c — NtUserToUnicodeEx applies the keyboard
// layout to translate VK+scancode to UTF-16; returns char count, 0 for no
// translation, or -1 for a dead key.  Weave: always 0.
pub unsafe extern "win64" fn to_unicode(
    _w_virt_key: u32,
    _w_scan_code: u32,
    _lp_key_state: *const u8,
    _pw_sz_buff: *mut u16,
    _cch_buff: i32,
    _w_flags: u32,
) -> i32 {
    0 // no chars translated
}

/// UnregisterClassA — unregister a window class (ANSI name).
///
/// Returns TRUE. In Weave's single-process model unregistering a class is a
/// no-op; the class table is not modified.
///
/// # Safety
/// `lp_class_name` is accepted but not dereferenced.
// Wine ref: dlls/win32u/class.c — NtUserUnregisterClass removes the class from
// the global class list; fails (FALSE) if any windows of the class exist.
// Weave: always TRUE (class table retained for process lifetime).
pub unsafe extern "win64" fn unregister_class_a(
    _lp_class_name: *const u8,
    _h_instance: usize,
) -> i32 {
    1 // TRUE
}

/// UnregisterClassW — unregister a window class (wide name).
///
/// Returns TRUE. See UnregisterClassA.
///
/// # Safety
/// `lp_class_name` is accepted but not dereferenced.
// Wine ref: dlls/win32u/class.c — NtUserUnregisterClass.  Weave: always TRUE.
pub unsafe extern "win64" fn unregister_class_w(
    _lp_class_name: *const u16,
    _h_instance: usize,
) -> i32 {
    1 // TRUE
}

/// CreateIconFromResource — create an icon or cursor from raw resource bits.
///
/// Returns a fake non-NULL HICON (1). SDL2 uses this to set the window icon;
/// a stub value prevents crashes on subsequent DestroyIcon(hIcon).
///
/// # Safety
/// `presbits` is accepted but not dereferenced.
// Wine ref: dlls/win32u/cursoricon.c — creates a CURSORICON object from
// the DIB/ANI resource bytes; returns NULL on parse failure.
// Weave: fake handle — DestroyIcon(1) returns FALSE, which SDL2 ignores.
pub unsafe extern "win64" fn create_icon_from_resource(
    _presbits: *const u8,
    _dw_res_size: u32,
    _f_icon: i32,
    _dw_ver: u32,
) -> usize {
    1 // fake HICON — non-NULL so SDL2 does not retry
}

/// GetClassInfoExW — retrieve extended window class info (wide name).
///
/// Delegates to GetClassInfoW. SDL2 calls this on startup to check
/// whether its window class is already registered.
///
/// # Safety
/// Pointer arguments must satisfy the same preconditions as GetClassInfoW.
// Wine ref: dlls/win32u/class.c — NtUserGetClassInfoEx fills WNDCLASSEXW
// including cbSize, hIconSm, and lpszMenuName; GetClassInfoW fills the
// smaller WNDCLASSW (without hIconSm).  Weave reuses the W variant.
pub unsafe extern "win64" fn get_class_info_ex_w(
    h_instance: usize,
    lp_class_name: *const u16,
    lp_wnd_class_ex: *mut u8,
) -> i32 {
    // Delegate to the non-Ex variant — the extra WNDCLASSEXW fields (cbSize,
    // hIconSm) are left at whatever the caller zero-initialised them to.
    get_class_info_w(h_instance, lp_class_name, lp_wnd_class_ex)
}

// ── SumatraPDF E3-M4 additions ────────────────────────────────────────────────

/// GetWindowDC — retrieve DC for the entire window (including non-client area).
// Wine ref: dlls/win32u/dce.c — GetWindowDC calls GetDCEx(hwnd, NULL, DCX_WINDOW).
pub extern "win64" fn get_window_dc(hwnd: usize) -> usize {
    get_dc(hwnd)
}

/// DrawTextExW — draw formatted text in a rectangle.
///
/// # Safety
/// `lp_string`, `lp_rc`, and `lp_dtp` must be valid or null.
// Wine ref: dlls/user32/text.c — DrawTextExW measures and draws text into rect via ExtTextOut.
pub unsafe extern "win64" fn draw_text_ex_w(
    _hdc: usize,
    _lp_string: *const u16,
    _cch: i32,
    _lp_rc: *mut i32,
    _format: u32,
    _lp_dtp: *const u8,
) -> i32 {
    0 // stub: return zero height
}

/// ShowScrollBar — show or hide a scroll bar control.
// Wine ref: dlls/user32/scroll.c — calls NtUserShowScrollBar.
pub extern "win64" fn show_scroll_bar(_hwnd: usize, _bar: i32, _show: i32) -> i32 {
    1 // TRUE
}

/// CreateAcceleratorTableW — create an accelerator table from an array of ACCEL structs.
///
/// # Safety
/// `lp_accel` must be a valid array of `count` ACCEL structs, or null.
// Wine ref: dlls/win32u/ntuser.c — allocates kernel accelerator object, returns HACCEL.
pub unsafe extern "win64" fn create_accelerator_table_w(
    _lp_accel: *const u8,
    _count: i32,
) -> usize {
    crate::accel_handles::ACCEL_HANDLE_BASE // non-zero fake HACCEL
}

/// DestroyAcceleratorTable — destroy an accelerator table created by CreateAcceleratorTableW.
// Wine ref: dlls/win32u/ntuser.c — frees kernel accelerator object.
pub extern "win64" fn destroy_accelerator_table(_h_accel: usize) -> i32 {
    1 // TRUE
}

// ── SumatraPDF DDE single-instance stubs ─────────────────────────────────────

/// # Safety
/// `pid_inst` must be null or point to a valid `u32` write target.
// Wine ref: dlls/user32/dde/ddeclient.c — DdeInitialize sets up per-instance
// state in a global table keyed by pidInst; DMLERR_NO_ERROR (0) = success.
// SumatraPDF calls this to register as a DDE client after CoCreateInstance
// fails (no existing instance). We return success so it proceeds past init.
pub unsafe extern "win64" fn dde_initialize_w(
    pid_inst: *mut u32,
    _pfn_callback: usize,
    _af_cmd: u32,
    _ul_res: u32,
) -> u32 {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    eprintln!("weave/user32: DdeInitializeW tid={tid}");
    if !pid_inst.is_null() {
        unsafe { *pid_inst = 1 };
    }
    0 // DMLERR_NO_ERROR
}

/// # Safety
/// `lp_sz_class` and `lp_sz_window` must be null or valid null-terminated UTF-16 strings.
// Wine ref: dlls/user32/winpos.c FindWindowExW — iterates the window list
// checking class name and title. Returns NULL when no match. SumatraPDF calls
// this looking for an existing SumatraPDF DDE server window; NULL means "I am
// the only instance" and it should proceed to enter the message loop.
pub unsafe extern "win64" fn find_window_ex_w(
    _h_wnd_parent: usize,
    _h_wnd_child_after: usize,
    lp_sz_class: *const u16,
    lp_sz_window: *const u16,
) -> usize {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    let class_str = if lp_sz_class.is_null() {
        String::from("<null>")
    } else {
        let len = (0usize..)
            .find(|&i| unsafe { *lp_sz_class.add(i) } == 0)
            .unwrap_or(0);
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(lp_sz_class, len) })
            .to_string()
    };
    let window_str = if lp_sz_window.is_null() {
        String::from("<null>")
    } else {
        let len = (0usize..)
            .find(|&i| unsafe { *lp_sz_window.add(i) } == 0)
            .unwrap_or(0);
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(lp_sz_window, len) })
            .to_string()
    };
    eprintln!(
        "weave/user32: FindWindowExW tid={tid} class={class_str:?} window={window_str:?} → NULL"
    );
    0 // NULL — no matching window
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Serializes tests that read/write the global VK_STATE table so parallel
    // test threads cannot race on test_reset() / set_vk_down().
    static INPUT_TEST_LOCK: Mutex<()> = Mutex::new(());

    // ── WS5: SetCaretPos / GetCaretPos ────────────────────────────────────────

    #[test]
    fn set_and_get_caret_pos_roundtrip() {
        set_caret_pos(42, 99);
        let mut pt = Point { x: 0, y: 0 };
        let result = unsafe { get_caret_pos(&mut pt as *mut Point) };
        assert_eq!(result, 1);
        assert_eq!(pt.x, 42);
        assert_eq!(pt.y, 99);
    }

    #[test]
    fn get_caret_pos_null_returns_false() {
        let result = unsafe { get_caret_pos(std::ptr::null_mut()) };
        assert_eq!(result, 0);
    }

    // ── WS5: GetMessagePos ────────────────────────────────────────────────────

    #[test]
    fn get_message_pos_returns_u32() {
        // Just ensure it doesn't crash and returns a valid u32
        let _ = get_message_pos();
    }

    // ── WS5: GetMessageTime ───────────────────────────────────────────────────

    #[test]
    fn get_message_time_returns_i32() {
        let _ = get_message_time();
    }

    // ── WS5: SetScrollInfo / GetScrollInfo ────────────────────────────────────

    #[test]
    fn scroll_info_set_and_get_range_pos() {
        let hwnd = 0xBEEF_0001usize;
        let n_bar = 0i32; // SB_HORZ

        let si_set = ScrollInfo {
            cb_size: std::mem::size_of::<ScrollInfo>() as u32,
            f_mask: 0x0001 | 0x0004, // SIF_RANGE | SIF_POS
            n_min: 0,
            n_max: 100,
            n_page: 0,
            n_pos: 50,
            n_track_pos: 0,
        };
        let new_pos = unsafe { set_scroll_info(hwnd, n_bar, &si_set as *const ScrollInfo, 0) };
        assert_eq!(new_pos, 50);

        let mut si_get = ScrollInfo {
            cb_size: std::mem::size_of::<ScrollInfo>() as u32,
            f_mask: 0x0001 | 0x0004, // SIF_RANGE | SIF_POS
            n_min: 0,
            n_max: 0,
            n_page: 0,
            n_pos: 0,
            n_track_pos: 0,
        };
        let result = unsafe { get_scroll_info(hwnd, n_bar, &mut si_get as *mut ScrollInfo) };
        assert_eq!(result, 1);
        assert_eq!(si_get.n_min, 0);
        assert_eq!(si_get.n_max, 100);
        assert_eq!(si_get.n_pos, 50);
    }

    #[test]
    fn scroll_info_pos_clamped_to_max() {
        let hwnd = 0xBEEF_0002usize;
        let n_bar = 1i32; // SB_VERT

        let si = ScrollInfo {
            cb_size: std::mem::size_of::<ScrollInfo>() as u32,
            f_mask: 0x0001 | 0x0004, // SIF_RANGE | SIF_POS
            n_min: 0,
            n_max: 10,
            n_page: 0,
            n_pos: 999, // way above max
            n_track_pos: 0,
        };
        let new_pos = unsafe { set_scroll_info(hwnd, n_bar, &si as *const ScrollInfo, 0) };
        assert_eq!(new_pos, 10, "pos should be clamped to max");
    }

    // ── WS5: SetTimer / KillTimer ─────────────────────────────────────────────

    #[test]
    fn set_timer_with_explicit_id_returns_that_id() {
        let hwnd = 0usize;
        let id = unsafe { set_timer(hwnd, 42, 1000, 0) };
        assert_eq!(id, 42);
        assert_eq!(kill_timer(hwnd, id), 1);
    }

    #[test]
    fn set_timer_with_zero_id_allocates_system_id() {
        let hwnd = 0usize;
        let id = unsafe { set_timer(hwnd, 0, 500, 0) };
        assert!(id > 0x7FFF, "system-allocated IDs should be > 0x7FFF");
        assert_eq!(kill_timer(hwnd, id), 1);
    }

    #[test]
    fn kill_timer_nonexistent_returns_false() {
        assert_eq!(kill_timer(0, 0xDEAD_BEEF), 0);
    }

    // ── WS5: ScreenToClient / ClientToScreen ──────────────────────────────────

    #[test]
    fn screen_to_client_null_returns_zero() {
        let result = unsafe { screen_to_client(0, std::ptr::null_mut()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn client_to_screen_null_returns_zero() {
        let result = unsafe { client_to_screen(0, std::ptr::null_mut()) };
        assert_eq!(result, 0);
    }

    // ── WS5: GetQueueStatus ───────────────────────────────────────────────────

    #[test]
    fn get_queue_status_returns_u32() {
        let status = get_queue_status(0xFFFF);
        // Either 0 (empty) or QS_POSTMESSAGE (0x0008)
        assert!(status == 0 || status == 0x0008);
    }

    // ── Dialog Indirect stubs ─────────────────────────────────────────────────

    #[test]
    fn create_dialog_indirect_param_w_returns_hwnd_on_nonnull_template() {
        // Use a static byte array as a stand-in for a DLGTEMPLATE pointer.
        // We do not parse it — the stub only null-checks the pointer.
        static FAKE_TEMPLATE: [u8; 18] = [0u8; 18];
        // DLGPROC that does nothing and returns 0 — avoids the fn-ptr null-check.
        unsafe extern "win64" fn noop_dlgproc(
            _hwnd: usize,
            _msg: u32,
            _wparam: usize,
            _lparam: isize,
        ) -> i32 {
            0
        }
        let lp_template = FAKE_TEMPLATE.as_ptr();
        let lp_dialog_func = noop_dlgproc as usize;
        let hwnd = unsafe { create_dialog_indirect_param_w(0, lp_template, 0, lp_dialog_func, 0) };
        assert_ne!(
            hwnd, 0,
            "non-null template + non-null DLGPROC should return a valid hwnd"
        );
    }

    #[test]
    fn create_dialog_indirect_param_w_returns_null_on_null_template() {
        unsafe extern "win64" fn noop_dlgproc(
            _hwnd: usize,
            _msg: u32,
            _wparam: usize,
            _lparam: isize,
        ) -> i32 {
            0
        }
        let hwnd = unsafe {
            create_dialog_indirect_param_w(0, std::ptr::null(), 0, noop_dlgproc as usize, 0)
        };
        assert_eq!(hwnd, 0, "null template must return 0");
    }

    #[test]
    fn dialog_box_indirect_param_w_returns_minus_one() {
        static FAKE_TEMPLATE: [u8; 18] = [0u8; 18];
        let result = unsafe { dialog_box_indirect_param_w(0, FAKE_TEMPLATE.as_ptr(), 0, 0, 0) };
        assert_eq!(
            result, -1,
            "stub must return -1 (modal message loop deferred)"
        );
    }

    #[test]
    fn dialog_box_indirect_param_w_returns_same_on_null_template() {
        let result = unsafe { dialog_box_indirect_param_w(0, std::ptr::null(), 0, 0, 0) };
        assert_eq!(result, -1, "null template must also return -1");
    }

    // ── TranslateAcceleratorW ─────────────────────────────────────────────────
    //
    // Build a synthetic PE_ACCEL blob (8 bytes per entry) in memory, register
    // it as an AccelBlob, and verify return values.  We cannot verify
    // WM_COMMAND dispatch without a real WNDPROC registered; instead we check
    // return value semantics (match→1, no-match→0, null→0) which are the
    // observable contract per Wine dlls/win32u/menu.c::translate_accelerator.

    /// Build a minimal PE_ACCEL blob for testing.
    /// Each entry: { fVirt: u16, key: u16, cmd: u16, pad: u16 }.
    /// Caller must keep the returned Vec alive for the duration of the test.
    fn make_pe_accel_blob(entries: &[(u16, u16, u16)]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(entries.len() * 8);
        for (i, &(fv, key, cmd)) in entries.iter().enumerate() {
            // Mark last entry with 0x80 in high byte so the walker can detect end.
            let fv_out = if i + 1 == entries.len() {
                fv | 0x80
            } else {
                fv
            };
            blob.extend_from_slice(&fv_out.to_le_bytes());
            blob.extend_from_slice(&key.to_le_bytes());
            blob.extend_from_slice(&cmd.to_le_bytes());
            blob.extend_from_slice(&0u16.to_le_bytes()); // pad
        }
        blob
    }

    #[test]
    fn translate_accelerator_w_null_haccel_returns_zero() {
        let msg = Msg {
            hwnd: 1,
            message: WM_KEYDOWN,
            _pad0: 0,
            w_param: 0x43, // 'C'
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
            _pad1: 0,
        };
        let result = unsafe { translate_accelerator_w(1, 0, &msg as *const Msg) };
        assert_eq!(result, 0, "null HACCEL must return 0");
    }

    #[test]
    fn translate_accelerator_w_unknown_haccel_returns_zero() {
        let msg = Msg {
            hwnd: 1,
            message: WM_KEYDOWN,
            _pad0: 0,
            w_param: 0x43,
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
            _pad1: 0,
        };
        // 0xDEAD_C0DE is not a registered handle.
        let result = unsafe { translate_accelerator_w(1, 0xDEAD_C0DE, &msg as *const Msg) };
        assert_eq!(result, 0, "unknown HACCEL must return 0");
    }

    #[test]
    fn translate_accelerator_w_non_key_message_returns_zero() {
        // Register a real HACCEL with a matching entry.
        let blob_data =
            make_pe_accel_blob(&[(0x01 /* FVIRTKEY */, 0x43 /* VK 'C' */, 100)]);
        let haccel = crate::accel_handles::register(
            0xABCD_0001,
            0xFFFF_0001,
            crate::accel_handles::AccelBlob {
                ptr: blob_data.as_ptr() as usize,
                size: blob_data.len() as u32,
            },
        );
        let msg = Msg {
            hwnd: 1,
            message: 0x0200, // WM_MOUSEMOVE — not a key message
            _pad0: 0,
            w_param: 0x43,
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
            _pad1: 0,
        };
        let result = unsafe { translate_accelerator_w(1, haccel, &msg as *const Msg) };
        assert_eq!(result, 0, "non-key message must return 0");
    }

    #[test]
    fn translate_accelerator_w_no_match_returns_zero() {
        // Table has VK 'C' (0x43) with FVIRTKEY; send VK 'X' (0x58) — no match.
        let blob_data = make_pe_accel_blob(&[(0x01 /* FVIRTKEY */, 0x43, 101)]);
        let haccel = crate::accel_handles::register(
            0xABCD_0002,
            0xFFFF_0002,
            crate::accel_handles::AccelBlob {
                ptr: blob_data.as_ptr() as usize,
                size: blob_data.len() as u32,
            },
        );
        let msg = Msg {
            hwnd: 1,
            message: WM_KEYDOWN,
            _pad0: 0,
            w_param: 0x58, // VK 'X' — not in table
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
            _pad1: 0,
        };
        let result = unsafe { translate_accelerator_w(1, haccel, &msg as *const Msg) };
        assert_eq!(result, 0, "non-matching VK must return 0");
    }

    #[test]
    fn translate_accelerator_w_vk_match_returns_one() {
        // Table entry: FVIRTKEY, no modifiers required, VK=0x43 ('C'), cmd=200.
        // Send WM_KEYDOWN w_param=0x43 with no modifiers — must match.
        let blob_data =
            make_pe_accel_blob(&[(0x01 /* FVIRTKEY only, no shift/ctrl/alt */, 0x43, 200)]);
        let haccel = crate::accel_handles::register(
            0xABCD_0003,
            0xFFFF_0003,
            crate::accel_handles::AccelBlob {
                ptr: blob_data.as_ptr() as usize,
                size: blob_data.len() as u32,
            },
        );
        // hwnd=0 would short-circuit; use any non-zero value.  send_message_w
        // will log "no wndproc" and return 0, which is fine for this test.
        let hwnd: usize = 0xDEAD_0001;
        let msg = Msg {
            hwnd,
            message: WM_KEYDOWN,
            _pad0: 0,
            w_param: 0x43,
            l_param: 0, // no ALT
            time: 0,
            pt_x: 0,
            pt_y: 0,
            _pad1: 0,
        };
        let result = unsafe { translate_accelerator_w(hwnd, haccel, &msg as *const Msg) };
        assert_eq!(result, 1, "matching FVIRTKEY entry must return 1");
    }

    #[test]
    fn translate_accelerator_w_two_entry_table_second_matches() {
        // Two entries: first VK=0x41 ('A'), second VK=0x42 ('B').
        // Send VK=0x42 — should hit second entry and return 1.
        let blob_data = make_pe_accel_blob(&[
            (0x01, 0x41, 300), // entry 0: VK 'A'
            (0x01, 0x42, 301), // entry 1: VK 'B' — last entry gets 0x80 added
        ]);
        let haccel = crate::accel_handles::register(
            0xABCD_0004,
            0xFFFF_0004,
            crate::accel_handles::AccelBlob {
                ptr: blob_data.as_ptr() as usize,
                size: blob_data.len() as u32,
            },
        );
        let hwnd: usize = 0xDEAD_0002;
        let msg = Msg {
            hwnd,
            message: WM_KEYDOWN,
            _pad0: 0,
            w_param: 0x42,
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
            _pad1: 0,
        };
        let result = unsafe { translate_accelerator_w(hwnd, haccel, &msg as *const Msg) };
        assert_eq!(
            result, 1,
            "second table entry must be reachable and return 1"
        );
    }

    // ── Task 24: GetKeyState / GetAsyncKeyState / GetKeyboardState ────────────

    #[test]
    fn get_key_state_reflects_input_table() {
        let _guard = INPUT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        input::test_reset();
        input::set_vk_down(b'A', true, None);
        let result = get_key_state(b'A' as i32);
        // Bit 15 must be set when key is down (result is negative as i16, or & 0x8000u16 != 0)
        assert!(
            (result as u16) & 0x8000 != 0,
            "get_key_state must reflect key-down: high bit set"
        );
        input::test_reset();
    }

    #[test]
    fn get_async_key_state_same_path() {
        let _guard = INPUT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        input::test_reset();
        input::set_vk_down(b'Z', true, None);
        let result = get_async_key_state(b'Z' as i32);
        assert!(
            (result as u16) & 0x8000 != 0,
            "get_async_key_state must reflect key-down: high bit set"
        );
        // Bit 0 must always be 0 (no pressed-since-last-call tracking in Weave)
        assert_eq!(result & 0x0001, 0, "get_async_key_state bit 0 must be 0");
        input::test_reset();
    }

    #[test]
    fn get_keyboard_state_copies_snapshot() {
        let _guard = INPUT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        input::test_reset();
        input::set_vk_down(0x41, true, None); // VK_A
        input::set_vk_down(0xA0, true, None); // VK_LSHIFT

        let mut buf = [0u8; 256];
        let result = unsafe { get_keyboard_state(buf.as_mut_ptr()) };
        assert_eq!(result, 1, "get_keyboard_state must return TRUE");
        assert_eq!(buf[0x41] & 0x80, 0x80, "VK_A must be marked down in buffer");
        assert_eq!(
            buf[0xA0] & 0x80,
            0x80,
            "VK_LSHIFT must be marked down in buffer"
        );
        assert_eq!(buf[0x42], 0, "VK_B must not be set in buffer");
        input::test_reset();
    }

    #[test]
    fn get_key_state_oob_returns_zero() {
        // Out-of-bounds nVirtKey must return 0 without panic
        assert_eq!(get_key_state(1000), 0, "nVirtKey=1000 must return 0");
        assert_eq!(get_key_state(-1), 0, "nVirtKey=-1 must return 0");
        assert_eq!(get_key_state(256), 0, "nVirtKey=256 must return 0");
    }
}

// ── UIAutomationCore.dll stubs ────────────────────────────────────────────────
//
// SumatraPDF delay-loads UIAutomationCore.DLL for accessibility support.
// When the delay-load thunk fires and Weave returns None, __delayLoadHelper2
// propagates a crash. These stubs cover the five symbols SumatraPDF imports
// so the thunks resolve cleanly without building a real UIA provider.
//
// Wine ref: dlls/uiautomationcore/uia_main.c, uia_event.c, uia_provider.c

/// UiaHostProviderFromHwnd — wraps an HWND as an IRawElementProviderSimple.
///
/// Wine ref: dlls/uiautomationcore/uia_main.c — allocates hwnd_host_provider
/// struct (IRawElementProviderSimple_iface + HWND); returns E_INVALIDARG for
/// NULL hwnd. Stub returns E_NOTIMPL — no UIA provider infrastructure.
// Wine ref: dlls/uiautomationcore/uia_main.c — UiaHostProviderFromHwnd wraps HWND as UIA provider; stub returns E_NOTIMPL
unsafe extern "win64" fn uia_host_provider_from_hwnd(
    _hwnd: usize,
    p_provider: *mut *mut (),
) -> i32 {
    if !p_provider.is_null() {
        unsafe { *p_provider = std::ptr::null_mut() };
    }
    0x80004001u32 as i32 // E_NOTIMPL
}

/// UiaGetReservedNotSupportedValue — returns a sentinel COM object meaning
/// "this UIA property is not supported".
///
/// Wine ref: dlls/uiautomationcore/uia_main.c — create_uia_object_wrapper
/// allocates a singleton IUnknown that QI rejects everything except IUnknown;
/// ppVal receives a non-NULL pointer. Stub writes NULL and returns S_OK;
/// callers check the pointer, not the HRESULT.
// Wine ref: dlls/uiautomationcore/uia_main.c — UiaGetReservedNotSupportedValue returns sentinel COM object; stub writes NULL, returns S_OK
unsafe extern "win64" fn uia_get_reserved_not_supported_value(pp_val: *mut *mut ()) -> i32 {
    if !pp_val.is_null() {
        unsafe { *pp_val = std::ptr::null_mut() };
    }
    0 // S_OK
}

/// UiaRaiseStructureChangedEvent — fires an accessibility structure-change
/// event (child added, removed, etc.) on an element provider.
///
/// Wine ref: dlls/uiautomationcore/uia_event.c — queues a
/// UiaStructureChangedEventArgs and dispatches it to registered event listeners;
/// no-op when no listeners are registered. Stub returns S_OK (no listeners).
// Wine ref: dlls/uiautomationcore/uia_event.c — UiaRaiseStructureChangedEvent fires accessibility event; stub no-op returns S_OK
unsafe extern "win64" fn uia_raise_structure_changed_event(
    _provider: *mut (),
    _structure_change_type: i32,
    _p_runtime_id: *const i32,
    _c_runtime_id_elm_count: i32,
) -> i32 {
    0 // S_OK
}

/// UiaRaiseAutomationEvent — fires a named automation event on an element.
///
/// Wine ref: dlls/uiautomationcore/uia_event.c — uia_raise_elprov_event builds
/// a UiaEventArgs, walks registered event advisers, and calls AdviseEventAdded;
/// no-op when no advisers. Stub returns S_OK (no advisers registered).
// Wine ref: dlls/uiautomationcore/uia_event.c — UiaRaiseAutomationEvent fires automation event; stub no-op returns S_OK
unsafe extern "win64" fn uia_raise_automation_event(_provider: *mut (), _id: i32) -> i32 {
    0 // S_OK
}

/// UiaReturnRawElementProvider — responds to WM_GETOBJECT by returning a UIA
/// element provider handle to the UIA client (LRESULT encoding).
///
/// Wine ref: dlls/uiautomationcore/uia_provider.c — builds a LRESULT via
/// UiaProviderCallback and encodes the provider handle for the client; returns
/// 0 when the provider is NULL (window not UIA-aware). Stub returns 0 so the
/// window appears non-UIA-aware, which is correct for Weave.
// Wine ref: dlls/uiautomationcore/uia_provider.c — UiaReturnRawElementProvider returns WM_GETOBJECT result; return 0 (not UIA-aware)
unsafe extern "win64" fn uia_return_raw_element_provider(
    _hwnd: usize,
    _w_param: usize,
    _l_param: isize,
    _el: *mut (),
) -> isize {
    0
}

/// Resolve a UIAutomationCore.dll import to a stub address.
///
/// Called by weave-cli's resolve chain. Uses eq_ignore_ascii_case because
/// delay-load helpers may pass mixed-case DLL names.
pub fn resolve_uiauto(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("uiautomationcore.dll") {
        return None;
    }
    match func {
        "UiaHostProviderFromHwnd" => Some(uia_host_provider_from_hwnd as *const () as usize),
        "UiaGetReservedNotSupportedValue" => {
            Some(uia_get_reserved_not_supported_value as *const () as usize)
        }
        "UiaRaiseStructureChangedEvent" => {
            Some(uia_raise_structure_changed_event as *const () as usize)
        }
        "UiaRaiseAutomationEvent" => Some(uia_raise_automation_event as *const () as usize),
        "UiaReturnRawElementProvider" => {
            Some(uia_return_raw_element_provider as *const () as usize)
        }
        _ => None,
    }
}
