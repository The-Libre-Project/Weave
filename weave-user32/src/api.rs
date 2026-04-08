//! Win32 user32 API function implementations.
//!
//! All functions use `extern "win64"` (Windows x86-64 calling convention).
//! Functions that need X11 delegate to `backend::*`; when X11 is unavailable
//! (no display, or non-Linux) they return safe error values.

#![allow(non_snake_case)]

use crate::backend;
use crate::class::{self, ClassEntry};
use crate::defs::*;
use crate::menu;
use crate::queue::{self, MsgEntry};
use crate::window::{self, WindowEntry};
use libc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use weave_common::stub::warn_once;

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
        .unwrap()
        .get(&hwnd)
        .map(f)
        .unwrap_or(default)
}

fn set_extra<F: FnOnce(&mut WindowExtra)>(hwnd: usize, f: F) {
    let mut map = window_extra().lock().unwrap();
    let entry = map.entry(hwnd).or_insert(WindowExtra {
        ex_style: 0,
        user_data: 0,
        extra_bytes: Vec::new(),
    });
    f(entry);
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

/// The HWND most recently passed to BeginPaint. Used by gdi32's CreateCompatibleDC(NULL)
/// as a fallback when no explicit DC is provided.
static CURRENT_PAINT_HWND: AtomicUsize = AtomicUsize::new(0);

/// Return the HWND that was most recently passed to BeginPaint.
/// Used by weave-gdi32 to resolve CreateCompatibleDC(NULL).
pub fn current_paint_hwnd() -> usize {
    CURRENT_PAINT_HWND.load(Ordering::Relaxed)
}

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
            cb_wnd_extra: wc.cb_wnd_extra.max(0) as u32,
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
            cb_wnd_extra: wc.cb_wnd_extra.max(0) as u32,
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
            eprintln!("weave/user32: CreateWindowExW: unknown class '{class_name}' → 0");
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
    call_wnd_proc(cls.wnd_proc, hwnd, WM_CREATE, 0, &cs as *const _ as isize);

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

    let xcb = window::xcb_id(hwnd);
    eprintln!("weave/user32: ShowWindow hwnd={hwnd:#x} cmd={n_cmd_show} show={show} xcb={xcb:#x}");
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

// Wine ref: dlls/win32u/window.c::user_destroy_window — sends WM_DESTROY first via
// send_destroy_message, then WM_NCDESTROY inside destroy_window. WM_NCDESTROY is always
// the last message a window receives; WM_DESTROY precedes it.
pub extern "win64" fn destroy_window(hwnd: usize) -> i32 {
    let xcb = window::xcb_id(hwnd);

    // WM_DESTROY first, then WM_NCDESTROY (Wine order: send_destroy_message → destroy_window).
    if let Some(proc_addr) = window::with(hwnd, |e| e.wnd_proc) {
        call_wnd_proc(proc_addr, hwnd, WM_DESTROY, 0, 0);
        call_wnd_proc(proc_addr, hwnd, WM_NCDESTROY, 0, 0);
    }

    backend::destroy_window(xcb);
    window::remove(hwnd);
    window_extra().lock().unwrap().remove(&hwnd);
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
            eprintln!("weave/user32: GetMessageW → WM_QUIT (no display)");
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

    let proc_addr = match window::with(m.hwnd, |e| e.wnd_proc) {
        Some(p) => p,
        None => return 0,
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
        eprintln!("weave/user32: PostMessageW hwnd={hwnd:#x} msg={msg} wp={w_param:#x} lp={l_param:#x}");
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
    let proc_addr = match window::with(hwnd, |e| e.wnd_proc) {
        Some(p) => p,
        None => return 0,
    };
    let ret = call_wnd_proc(proc_addr, hwnd, msg, w_param, l_param);
    // Log SCI range, WM_USER+ app messages, and WM_NOTIFY (Scintilla modification signal).
    const WM_NOTIFY: u32 = 0x004E;
    if (2000..=2200).contains(&msg) || (msg >= 0x0400 && msg < 2000) || msg == WM_NOTIFY {
        let xcb = window::xcb_id(hwnd);
        eprintln!("weave/user32: SendMessageW hwnd={hwnd:#x} xcb={xcb:#x} msg={msg} → {ret:#x}");
    }
    ret
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
pub unsafe extern "win64" fn get_update_rect(
    hwnd: usize,
    lp_rect: *mut Rect,
    _b_erase: i32,
) -> i32 {
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
// Wine ref: dlls/win32u/painting.c::NtUserBeginPaint — validates the update region by clearing
// the WM_PAINT pending flag; returns an HDC clipped to the update region; sets fErase if the
// background was erased. Weave returns hwnd as a fake HDC (Phase 2 gap: no real DC or region).
pub unsafe extern "win64" fn begin_paint(hwnd: usize, lp_paint: *mut PaintStruct) -> usize {
    CURRENT_PAINT_HWND.store(hwnd, Ordering::Relaxed);
    // Query SCI_GETLENGTH (2006) for Scintilla windows to check when document gets content.
    {
        static BP_SCI: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = BP_SCI.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let is_sci = window::with(hwnd, |e| e.class_name == "Scintilla").unwrap_or(false);
        if is_sci && (n < 20 || n % 5 == 0) {
            let doc_len = send_message_w(hwnd, 2006, 0, 0); // SCI_GETLENGTH
            let status = send_message_w(hwnd, 2173, 0, 0); // SCI_GETSTATUS (0=ok, non-zero=error)
            let xcb = window::xcb_id(hwnd);
            eprintln!("weave/user32: BeginPaint Scintilla hwnd={hwnd:#x} xcb={xcb:#x} paint#{n} SCI_GETLENGTH={doc_len} SCI_GETSTATUS={status}");
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
pub unsafe extern "win64" fn end_paint(_hwnd: usize, _lp_paint: *const PaintStruct) -> i32 {
    1 // TRUE
}

// ── System metrics ────────────────────────────────────────────────────────────

/// GetSystemMetrics: return various system dimension/capability values.
///
/// Wine ref: dlls/win32u/sysparams.c::get_system_metrics — SM_CXSCREEN/SM_CYSCREEN from
/// primary monitor rect; SM_CXBORDER/SM_CYBORDER always 1 ("regardless of BorderWidth in
/// registry"); SM_CXEDGE/SM_CYEDGE = SM_CXBORDER+1 = 2; SM_CXFRAME/SM_CYFRAME =
/// SM_CXDLGFRAME(3) + max(border,1) = 4; SM_CXICON/SM_CYICON = map_to_dpi(32,...).
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
        SM_CXBORDER => 1, // Wine: always 1 regardless of registry BorderWidth
        SM_CYBORDER => 1,
        SM_CXEDGE => 2, // Wine: SM_CXBORDER + 1
        SM_CYEDGE => 2,
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
    warn_once("LoadCursorW");
    1 // non-zero fake HCURSOR
}

/// LoadIconW: load an icon resource.
///
/// Returns a non-zero fake HICON.
///
/// # Safety
/// `lp_icon_name` (if non-null) must be a valid UTF-16 string or integer resource.
pub unsafe extern "win64" fn load_icon_w(_h_instance: usize, _lp_icon_name: usize) -> usize {
    warn_once("LoadIconW");
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
    warn_once("LoadImageW");
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
/// `lp_mi` must point to a valid `MonitorInfo` struct with `cb_size` set.
pub unsafe extern "win64" fn get_monitor_info_w(_h_monitor: usize, lp_mi: *mut MonitorInfo) -> i32 {
    if lp_mi.is_null() {
        return 0;
    }
    let (w, h) = crate::backend::screen_size();
    unsafe {
        (*lp_mi).rc_monitor = Rect {
            left: 0,
            top: 0,
            right: w as i32,
            bottom: h as i32,
        };
        (*lp_mi).rc_work = Rect {
            left: 0,
            top: 0,
            right: w as i32,
            bottom: h as i32,
        };
        (*lp_mi).dw_flags = 1; // MONITORINFOF_PRIMARY
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
                static GWLP: std::sync::atomic::AtomicU32 =
                    std::sync::atomic::AtomicU32::new(0);
                let is_sci = window::with(hwnd, |e| e.class_name == "Scintilla")
                    .unwrap_or(false);
                if is_sci && offset == 0
                    && GWLP.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 8
                {
                    eprintln!(
                        "weave/user32: GetWindowLongPtr hwnd={hwnd:#x} offset=0 → {val:#x}"
                    );
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
        GWL_WNDPROC => window::with_mut(hwnd, |w| {
            let old = w.wnd_proc as isize;
            w.wnd_proc = dw_new_long as usize;
            old
        })
        .unwrap_or(0),
        _ if n_index >= 0 => {
            // Extra bytes: n_index is a byte offset; writes a pointer-sized (8-byte) value.
            let offset = n_index as usize;
            let mut map = window_extra().lock().unwrap();
            if let Some(e) = map.get_mut(&hwnd) {
                if offset + 8 <= e.extra_bytes.len() {
                    let old =
                        isize::from_ne_bytes(e.extra_bytes[offset..offset + 8].try_into().unwrap());
                    e.extra_bytes[offset..offset + 8].copy_from_slice(&dw_new_long.to_ne_bytes());
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
///
/// Returns the detected system DPI. Per-window DPI (multi-monitor setups) is
/// not yet implemented — all windows report the primary monitor's DPI.
pub extern "win64" fn get_dpi_for_window(_hwnd: usize) -> u32 {
    crate::backend::system_dpi()
}

/// GetDpiForSystem: return the system DPI.
pub extern "win64" fn get_dpi_for_system() -> u32 {
    crate::backend::system_dpi()
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
        },
    );
    name_to_atom(&name)
}

/// RegisterClassExA: ANSI extended variant.
///
/// # Safety
/// `lp_wnd_class_ex` must point to a valid `WNDCLASSEXA` struct.
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
        },
    );
    name_to_atom(&name)
}

// ── ANSI window creation ──────────────────────────────────────────────────────

/// CreateWindowExA: ANSI variant — converts string args and calls through.
///
/// # Safety
/// String pointer arguments must be null or valid null-terminated ANSI strings.
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
pub unsafe extern "win64" fn dispatch_message_a(lp_msg: *const Msg) -> isize {
    unsafe { dispatch_message_w(lp_msg) }
}

/// PostMessageA: ANSI variant.
pub extern "win64" fn post_message_a(
    h_wnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> i32 {
    post_message_w(h_wnd, msg, w_param, l_param)
}

/// SendMessageA: ANSI variant.
pub extern "win64" fn send_message_a(
    h_wnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    send_message_w(h_wnd, msg, w_param, l_param)
}

/// DefWindowProcA: ANSI variant — forwards to W implementation.
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
pub extern "win64" fn get_window_text_length_a(h_wnd: usize) -> i32 {
    window::with(h_wnd, |w| w.title.len() as i32).unwrap_or(0)
}

/// GetWindowLongPtrA: ANSI variant — identical to W.
pub extern "win64" fn get_window_long_ptr_a(hwnd: usize, n_index: i32) -> isize {
    get_window_long_ptr_w(hwnd, n_index)
}

/// SetWindowLongPtrA: ANSI variant — identical to W.
pub extern "win64" fn set_window_long_ptr_a(
    hwnd: usize,
    n_index: i32,
    dw_new_long: isize,
) -> isize {
    set_window_long_ptr_w(hwnd, n_index, dw_new_long)
}

/// SetClassLongPtrA: change a class attribute. Stub — returns 0.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn set_class_long_ptr_a(
    _hwnd: usize,
    _n_index: i32,
    _dw_new_long: isize,
) -> isize {
    0
}

// ── ANSI resource loading ─────────────────────────────────────────────────────

/// LoadIconA: ANSI variant — delegates to W stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn load_icon_a(_h_instance: usize, _lp_icon_name: *const u8) -> usize {
    1usize // fake HICON
}

/// LoadImageA: ANSI variant — delegates to W stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn load_image_a(
    _h_inst: usize,
    _name: *const u8,
    _type: u32,
    _cx: i32,
    _cy: i32,
    _fu_load: u32,
) -> usize {
    1usize // fake handle
}

/// DestroyIcon: free an HICON. Stub — always succeeds.
pub extern "win64" fn destroy_icon(_h_icon: usize) -> i32 {
    1
}

// ── ANSI message box ──────────────────────────────────────────────────────────

/// MessageBoxA: ANSI variant — returns IDOK.
///
/// # Safety
/// String pointer arguments must be null or valid null-terminated ANSI strings.
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
pub unsafe extern "win64" fn message_box_indirect_w(_lp_msgboxparams: usize) -> i32 {
    1 // IDOK
}

// ── ANSI menu helpers ─────────────────────────────────────────────────────────

/// AppendMenuA: ANSI variant — converts text and calls through.
///
/// # Safety
/// `lp_new_item` may be a string, bitmap, or other resource pointer.
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
pub extern "win64" fn get_system_menu(h_wnd: usize, b_revert: i32) -> usize {
    if b_revert != 0 {
        // Revert to default — we don't track the original, just return current.
        return window::with(h_wnd, |w| w.h_menu).unwrap_or(0);
    }
    window::with(h_wnd, |w| if w.h_menu != 0 { w.h_menu } else { 0 })
        .unwrap_or_else(|| menu::create_menu())
}

/// DeleteMenu: remove an item from a menu.
pub extern "win64" fn delete_menu(h_menu: usize, u_position: u32, u_flags: u32) -> i32 {
    menu::delete_item(h_menu, u_position, u_flags);
    1
}

// ── Dialog stubs ──────────────────────────────────────────────────────────────

/// DefDlgProcA: default dialog procedure (ANSI). Forwards to DefWindowProcW.
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

/// CreateDialogParamA: create a modeless dialog box.
///
/// Returns NULL — Weave does not implement dialog templates.
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

/// EndDialog: close a dialog box.
pub extern "win64" fn end_dialog(_h_dlg: usize, _n_result: isize) -> i32 {
    1
}

/// GetDlgItem: find a control in a dialog by ID. Returns 0 (not found).
pub extern "win64" fn get_dlg_item(_h_dlg: usize, _n_id_dlg_item: i32) -> usize {
    0
}

/// GetDlgItemTextA: copy a dialog control's text. Returns 0 chars.
///
/// # Safety
/// `lp_string` must be writable if non-null.
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
pub unsafe extern "win64" fn set_dlg_item_text_w(
    _h_dlg: usize,
    _n_id_dlg_item: i32,
    _lp_string: *const u16,
) -> i32 {
    1
}

/// SendDlgItemMessageA: send a message to a dialog control. Returns 0.
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
pub extern "win64" fn check_dlg_button(_h_dlg: usize, _n_id_button: i32, _u_check: u32) -> i32 {
    1
}

/// IsDlgButtonChecked: query the checked state of a button. Returns 0.
pub extern "win64" fn is_dlg_button_checked(_h_dlg: usize, _n_id_button: i32) -> u32 {
    0 // BST_UNCHECKED
}

/// CheckRadioButton: check one button in a group, uncheck the rest. Returns TRUE.
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
pub unsafe extern "win64" fn is_dialog_message_a(_h_dlg: usize, _lp_msg: *const Msg) -> i32 {
    0
}

/// MapDialogRect: map dialog box units to pixels. Returns TRUE (rect unchanged).
///
/// # Safety
/// `lp_rect` must point to a valid `Rect` if non-null.
pub unsafe extern "win64" fn map_dialog_rect(_h_dlg: usize, _lp_rect: *mut Rect) -> i32 {
    1
}

// ── Window state ──────────────────────────────────────────────────────────────

/// IsIconic: return TRUE if the window is minimised. Always returns FALSE.
pub extern "win64" fn is_iconic(_h_wnd: usize) -> i32 {
    0
}

/// IsZoomed: return TRUE if the window is maximised. Always returns FALSE.
pub extern "win64" fn is_zoomed(_h_wnd: usize) -> i32 {
    0
}

/// FlashWindow: flash a window in the taskbar. Returns FALSE.
pub extern "win64" fn flash_window(_h_wnd: usize, _b_invert: i32) -> i32 {
    0
}

/// GetWindowPlacement: retrieve window size and position.
///
/// # Safety
/// `lp_wndpl` must point to a valid `WindowPlacement` with `length` set.
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
    timer_table().lock().unwrap().insert((h_wnd, id), id);
    eprintln!("weave/user32: SetTimer hwnd={h_wnd:#x} id={id:#x} elapse={_u_elapse}ms → WM_TIMER NOT FIRED (Phase 5 gap)");
    id
}

/// KillTimer: destroy a timer and free its ID. Returns TRUE if found, FALSE if not.
///
/// Wine ref: dlls/win32u/message.c — KillTimer sends a kill_win_timer request
/// to the server; returns FALSE (sets ERROR_INVALID_PARAMETER) if the timer
/// does not exist for the given (hwnd, id) pair.
pub extern "win64" fn kill_timer(h_wnd: usize, u_id_event: usize) -> i32 {
    let removed = timer_table().lock().unwrap().remove(&(h_wnd, u_id_event));
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

/// MsgWaitForMultipleObjects: wait for objects or a message. Returns WAIT_TIMEOUT.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn msg_wait_for_multiple_objects(
    _n_count: u32,
    _lp_handles: *const usize,
    _b_wait_all: i32,
    _dw_milliseconds: u32,
    _dw_wake_mask: u32,
) -> u32 {
    // Stub: always return WAIT_TIMEOUT immediately.
    // We do not dereference lp_handles — doing so with an untrusted n_count
    // from the guest could walk into unmapped memory.
    0x00000102u32 // WAIT_TIMEOUT
}

// ── Mouse capture ─────────────────────────────────────────────────────────────

/// GetCapture: return the window that has mouse capture. Returns 0.
pub extern "win64" fn get_capture() -> usize {
    0
}

/// SetCapture: capture mouse input for a window. Returns 0 (previous capture).
pub extern "win64" fn set_capture(_h_wnd: usize) -> usize {
    0
}

/// ReleaseCapture: release mouse capture. Returns TRUE.
pub extern "win64" fn release_capture() -> i32 {
    1
}

/// SetActiveWindow: activate a window. Returns 0 (previous).
pub extern "win64" fn set_active_window(_h_wnd: usize) -> usize {
    0
}

// ── System colors ─────────────────────────────────────────────────────────────

/// GetSysColor: return a system color. Returns black (0x000000) for all.
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
        .unwrap()
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
    let mut table = scroll_state().lock().unwrap();
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
pub extern "win64" fn create_caret(_hwnd: usize, _h_bitmap: usize, _w: i32, _h: i32) -> i32 {
    1
}

/// DestroyCaret: destroy the current caret. Returns TRUE.
pub extern "win64" fn destroy_caret() -> i32 {
    1
}

/// ShowCaret: make the caret visible. Returns TRUE.
pub extern "win64" fn show_caret(_hwnd: usize) -> i32 {
    1
}

/// HideCaret: hide the caret. Returns TRUE.
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
pub extern "win64" fn get_caret_blink_time() -> u32 {
    500
}

// ── Misc stubs ────────────────────────────────────────────────────────────────

/// MessageBeep: produce a sound. Returns TRUE (no audio yet).
pub extern "win64" fn message_beep(_u_type: u32) -> i32 {
    1
}

/// GetDoubleClickTime: return the double-click interval in milliseconds.
pub extern "win64" fn get_double_click_time() -> u32 {
    500
}

/// OffsetRect: offset a rectangle by x, y. Returns TRUE.
///
/// # Safety
/// `lp_rc` must point to a valid `Rect`.
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

/// RegisterClipboardFormatA: register a named clipboard format. Returns a fake ID.
///
/// # Safety
/// `lp_sz_format` must be a valid null-terminated ANSI string.
pub unsafe extern "win64" fn register_clipboard_format_a(lp_sz_format: *const u8) -> u32 {
    let name = unsafe { decode_ansi(lp_sz_format) };
    // Return a deterministic ID in the custom format range (0xC000–0xFFFF).
    let mut h: u32 = 0xC000;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    0xC000 | (h & 0x3FFF)
}

/// RegisterWindowMessageA: register a unique window message. Returns a fake ID.
///
/// # Safety
/// `lp_string` must be a valid null-terminated ANSI string.
pub unsafe extern "win64" fn register_window_message_a(lp_string: *const u8) -> u32 {
    unsafe { register_clipboard_format_a(lp_string) }
}

/// SystemParametersInfoA: stub — returns FALSE (operation not supported).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn system_parameters_info_a(
    _u_action: u32,
    _u_param: u32,
    _pv_param: usize,
    _f_win_ini: u32,
) -> i32 {
    0
}

/// ToAsciiEx: translate a virtual key to a character. Returns 0.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
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
/// Stub: returns the supplied HWND (pretend it already had focus).
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn set_focus(hwnd: usize) -> usize {
    hwnd
}

/// SetKeyboardState: set the keyboard state for the calling thread. Returns TRUE.
///
/// # Safety
/// `lp_key_state` is accepted but not dereferenced.
pub unsafe extern "win64" fn set_keyboard_state(_lp_key_state: *const u8) -> i32 {
    1 // TRUE
}

/// SetWindowTextA: update the title bar text of a window (ANSI).
///
/// Decodes the ANSI string and delegates to `set_window_text_w`.
///
/// # Safety
/// `lp_string` must be a valid null-terminated ANSI string or null.
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
pub unsafe extern "win64" fn set_menu_item_info_w(
    _h_menu: usize,
    _u_item: u32,
    _f_by_position: i32,
    _lpmii: *const u8,
) -> i32 {
    0 // FALSE
}

/// LoadStringW — load a string from the application's resource table (Wide).
///
/// Returns 0 (empty string) — stub, no resource loading.
///
/// # Safety
/// If `lp_buffer` is non-null and `n_buffer_max` > 0, writes an empty
/// null-terminated string.
pub unsafe extern "win64" fn load_string_w(
    _h_instance: usize,
    _u_id: u32,
    lp_buffer: *mut u16,
    n_buffer_max: i32,
) -> i32 {
    if !lp_buffer.is_null() && n_buffer_max > 0 {
        unsafe { *lp_buffer = 0 };
    }
    0
}

/// RegisterClipboardFormatW — register a new clipboard format (Wide).
///
/// Returns a fake non-zero format ID.
///
/// # Safety
/// `lpsz` is accepted but not dereferenced.
pub unsafe extern "win64" fn register_clipboard_format_w(_lpsz: *const u16) -> u32 {
    0xC000 // fake private clipboard format base
}

/// GetWindowTextLengthW — return the length of a window's title bar text.
///
/// Returns 0 — stub.
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn get_window_text_length_w(_hwnd: usize) -> i32 {
    0
}

/// SystemParametersInfoW — query or set system-wide parameters (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn system_parameters_info_w(
    _u_action: u32,
    _u_param: u32,
    _pv_param: *mut u8,
    _f_win_ini: u32,
) -> i32 {
    0 // FALSE
}

/// GetMonitorInfoA — fill a MONITORINFO or MONITORINFOEX structure (ANSI).
///
/// Returns FALSE — stub (no multi-monitor support).
///
/// # Safety
/// `lpmi` is accepted but not dereferenced.
pub unsafe extern "win64" fn get_monitor_info_a(_h_monitor: usize, _lpmi: *mut u8) -> i32 {
    0 // FALSE
}

/// GetDialogBaseUnits — return dialog base units. Returns a fixed value.
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
pub unsafe extern "win64" fn child_window_from_point_ex(
    _hwnd_parent: usize,
    _point_x: i32,
    _point_y: i32,
    _u_flags: u32,
) -> usize {
    0 // NULL
}

/// LoadMenuW — load a menu resource (Wide). Returns NULL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn load_menu_w(_h_instance: usize, _lp_menu_name: *const u16) -> usize {
    0 // NULL
}

/// DrawMenuBar — redraw the menu bar. Returns TRUE.
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn draw_menu_bar(_hwnd: usize) -> i32 {
    1 // TRUE
}

/// CheckMenuRadioItem — set a radio-button check mark. Returns TRUE.
///
/// # Safety
/// No pointer dereferences.
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
pub unsafe extern "win64" fn remove_menu(_h_menu: usize, _u_position: u32, _u_flags: u32) -> i32 {
    1 // TRUE
}

/// GetSubMenu — return the handle of a pop-up submenu. Returns NULL.
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn get_sub_menu(_h_menu: usize, _n_pos: i32) -> usize {
    0 // NULL
}

/// SendDlgItemMessageW — send a message to a dialog control (Wide).
///
/// Returns 0 — stub.
///
/// # Safety
/// No pointer dereferences.
pub unsafe extern "win64" fn send_dlg_item_message_w(
    _h_dlg: usize,
    _n_id_dlg_item: i32,
    _msg: u32,
    _w_param: usize,
    _l_param: isize,
) -> isize {
    0
}

/// LoadAcceleratorsW — load an accelerator table resource (Wide). Returns NULL.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn load_accelerators_w(
    _h_inst: usize,
    _lp_table_name: *const u16,
) -> usize {
    0 // NULL
}

/// TranslateAcceleratorW — translate accelerator keystrokes (Wide). Returns 0.
///
/// # Safety
/// `lp_msg` is accepted but not dereferenced.
pub unsafe extern "win64" fn translate_accelerator_w(
    _h_wnd: usize,
    _h_acc_table: usize,
    _lp_msg: *const u8,
) -> i32 {
    0
}

/// GetFocus — return the HWND that currently has keyboard focus. Returns NULL.
pub extern "win64" fn get_focus() -> usize {
    0 // NULL
}

/// LoadBitmapW — load a bitmap resource (Wide). Returns NULL.
///
/// # Safety
/// `lp_bitmap_name` is accepted but not dereferenced.
pub unsafe extern "win64" fn load_bitmap_w(
    _h_instance: usize,
    _lp_bitmap_name: *const u16,
) -> usize {
    0 // NULL HBITMAP
}

/// GetClassInfoW — retrieve information about a registered window class (Wide).
///
/// Returns FALSE — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn get_class_info_w(
    _h_instance: usize,
    _lp_class_name: *const u16,
    _lp_wnd_class: *mut u8,
) -> i32 {
    0 // FALSE
}

/// CallWindowProcW — pass a message to the specified window procedure (Wide).
///
/// Returns 0 — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn call_window_proc_w(
    _lp_prev_wnd_func: usize,
    _h_wnd: usize,
    _msg: u32,
    _w_param: usize,
    _l_param: isize,
) -> isize {
    0
}

/// DialogBoxParamW — display a modal dialog box from a resource template (Wide).
///
/// Returns -1 (error) — stub.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn dialog_box_param_w(
    _h_instance: usize,
    _lp_template_name: *const u16,
    _hwnd_parent: usize,
    _lp_dialog_func: usize,
    _dw_init_param: isize,
) -> isize {
    -1
}

/// CharPrevExA — find the previous character in a string (ANSI, code page aware).
///
/// Returns `lpsz - 1` clamped to `lpszStart`. Stub ignores the code page.
///
/// # Safety
/// `lpsz_start` and `lpsz` must be valid pointers into the same buffer.
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
}
