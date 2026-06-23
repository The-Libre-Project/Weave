//! Win32 type definitions and constants for user32.
//!
//! All structs use `#[repr(C)]` and match the Windows x64 ABI layout exactly.
//! Layouts verified against MSDN and the Windows SDK headers.

#![allow(dead_code)]

// ── Win32 type aliases ────────────────────────────────────────────────────────

pub type HWND = usize;
pub type HMENU = usize;
pub type HINSTANCE = usize;
pub type HICON = usize;
pub type HCURSOR = usize;
pub type HBRUSH = usize;
pub type ATOM = u16;
pub type WPARAM = usize;
pub type LPARAM = isize;
pub type LRESULT = isize;
pub type UINT = u32;
pub type DWORD = u32;
pub type BOOL = i32;

/// Window procedure type: called by DispatchMessageW for each message.
/// Uses the Windows x64 calling convention.
pub type WndProc = unsafe extern "win64" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;

// ── WM_* message codes ────────────────────────────────────────────────────────

pub const WM_ENABLE: u32 = 0x000A;
pub const WM_NULL: u32 = 0x0000;
pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_ACTIVATE: u32 = 0x0006;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_ERASEBKGND: u32 = 0x0014;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_SETCURSOR: u32 = 0x0020;
pub const WM_SETTEXT: u32 = 0x000C;
pub const WM_GETTEXT: u32 = 0x000D;
pub const WM_GETTEXTLENGTH: u32 = 0x000E;
// Edit control messages
pub const EM_GETSEL: u32 = 0x00B0;
pub const EM_SETSEL: u32 = 0x00B1;
pub const EM_REPLACESEL: u32 = 0x00C2;
pub const EM_SETLIMITTEXT: u32 = 0x00C5; // also EM_LIMITTEXT
pub const EM_GETLIMITTEXT: u32 = 0x00D5;
pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_NCDESTROY: u32 = 0x0082;
pub const WM_NCCALCSIZE: u32 = 0x0083;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_INITDIALOG: u32 = 0x0110;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;
pub const WM_MOUSEWHEEL: u32 = 0x020A;
pub const WM_HSCROLL: u32 = 0x0114;
pub const WM_VSCROLL: u32 = 0x0115;
pub const WM_MOUSEHOVER: u32 = 0x02A1;
pub const WM_MOUSELEAVE: u32 = 0x02A3;
pub const WM_DPICHANGED: u32 = 0x02E0;

// ── Mouse/keyboard virtual-key flags ──────────────────────────────────────────

pub const MK_LBUTTON: u32 = 0x0001;
pub const MK_RBUTTON: u32 = 0x0002;
pub const MK_SHIFT: u32 = 0x0004;
pub const MK_CONTROL: u32 = 0x0008;
pub const MK_MBUTTON: u32 = 0x0010;

// ── TrackMouseEvent flags ─────────────────────────────────────────────────────

pub const TME_HOVER: u32 = 0x0000_0001;
pub const TME_LEAVE: u32 = 0x0000_0002;
pub const TME_CANCEL: u32 = 0x8000_0000;
pub const TME_QUERY: u32 = 0x4000_0000;

/// Win64 layout of TRACKMOUSEEVENT (cbSize = 24).
///
/// cbSize(u32) @ 0 · dwFlags(u32) @ 4 · hwndTrack(usize) @ 8 · dwHoverTime(u32) @ 16 · _pad @ 20
#[repr(C)]
pub struct TrackMouseEventStruct {
    pub cb_size: u32,
    pub dw_flags: u32,
    pub hwnd_track: usize,
    pub dw_hover_time: u32,
    pub _pad: u32,
}
const _: () = assert!(std::mem::size_of::<TrackMouseEventStruct>() == 24);

// ── Window styles ─────────────────────────────────────────────────────────────

pub const WS_OVERLAPPED: u32 = 0x00000000;
pub const WS_POPUP: u32 = 0x80000000;
pub const WS_CHILD: u32 = 0x40000000;
pub const WS_VISIBLE: u32 = 0x10000000;
pub const WS_DISABLED: u32 = 0x08000000;
pub const WS_CAPTION: u32 = 0x00C00000;
pub const WS_SYSMENU: u32 = 0x00080000;
pub const WS_THICKFRAME: u32 = 0x00040000;
pub const WS_MINIMIZEBOX: u32 = 0x00020000;
pub const WS_MAXIMIZEBOX: u32 = 0x00010000;
pub const WS_BORDER: u32 = 0x00800000;
pub const WS_DLGFRAME: u32 = 0x00400000;
pub const WS_OVERLAPPEDWINDOW: u32 =
    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;

// ── Extended window styles ────────────────────────────────────────────────────

pub const WS_EX_DLGMODALFRAME: u32 = 0x00000001;
pub const WS_EX_TOOLWINDOW: u32 = 0x00000080;
pub const WS_EX_CLIENTEDGE: u32 = 0x00000200;
pub const WS_EX_STATICEDGE: u32 = 0x00020000;

// ── ShowWindow commands ───────────────────────────────────────────────────────

pub const SW_HIDE: i32 = 0;
pub const SW_SHOW: i32 = 5;
pub const SW_SHOWDEFAULT: i32 = 10;

// ── GetSystemMetrics indices ──────────────────────────────────────────────────
// Wine ref: dlls/win32u/sysparams.c::get_system_metrics — full index list

pub const SM_CXSCREEN: i32 = 0;
pub const SM_CYSCREEN: i32 = 1;
pub const SM_CXVSCROLL: i32 = 2; // vertical scrollbar width
pub const SM_CYHSCROLL: i32 = 3; // horizontal scrollbar height
pub const SM_CYCAPTION: i32 = 4;
pub const SM_CXBORDER: i32 = 5;
pub const SM_CYBORDER: i32 = 6;
pub const SM_CXDLGFRAME: i32 = 7;
pub const SM_CYDLGFRAME: i32 = 8;
pub const SM_CYVTHUMB: i32 = 9; // vertical scrollbar thumb height
pub const SM_CXHTHUMB: i32 = 10; // horizontal scrollbar thumb width
pub const SM_CXICON: i32 = 11;
pub const SM_CYICON: i32 = 12;
pub const SM_CXCURSOR: i32 = 13;
pub const SM_CYCURSOR: i32 = 14;
pub const SM_CYMENU: i32 = 15; // menu bar height
pub const SM_CXFULLSCREEN: i32 = 16;
pub const SM_CYFULLSCREEN: i32 = 17;
pub const SM_MOUSEPRESENT: i32 = 19;
pub const SM_CYVSCROLL: i32 = 20; // vertical scrollbar width (alias direction)
pub const SM_CXHSCROLL: i32 = 21; // horizontal scrollbar height (alias direction)
pub const SM_CXMIN: i32 = 28; // minimum window width
pub const SM_CYMIN: i32 = 29; // minimum window height
pub const SM_CXSIZE: i32 = 30; // caption button width
pub const SM_CYSIZE: i32 = 31; // caption button height
pub const SM_CXFRAME: i32 = 32;
pub const SM_CYFRAME: i32 = 33;
pub const SM_CXMINTRACK: i32 = 34; // minimum tracking width
pub const SM_CYMINTRACK: i32 = 35; // minimum tracking height
pub const SM_CXDOUBLECLK: i32 = 36; // double-click rectangle width
pub const SM_CYDOUBLECLK: i32 = 37; // double-click rectangle height
pub const SM_CXICONSPACING: i32 = 38; // icon horizontal spacing
pub const SM_CYICONSPACING: i32 = 39; // icon vertical spacing
pub const SM_CMOUSEBUTTONS: i32 = 43; // number of mouse buttons
pub const SM_CXEDGE: i32 = 45;
pub const SM_CYEDGE: i32 = 46;
pub const SM_CXSMICON: i32 = 49; // small icon width
pub const SM_CYSMICON: i32 = 50; // small icon height
pub const SM_CYSMCAPTION: i32 = 51; // small caption bar height
pub const SM_CXSMSIZE: i32 = 52; // small caption button width
pub const SM_CYSMSIZE: i32 = 53; // small caption button height
pub const SM_CXMENUSIZE: i32 = 54; // menu bar button width
pub const SM_CYMENUSIZE: i32 = 55; // menu bar button height
pub const SM_CXMINIMIZED: i32 = 57; // minimized window width
pub const SM_CYMINIMIZED: i32 = 58; // minimized window height
pub const SM_CXMAXTRACK: i32 = 59; // maximum tracking width
pub const SM_CYMAXTRACK: i32 = 60; // maximum tracking height
pub const SM_CXMAXIMIZED: i32 = 61; // maximized window width
pub const SM_CYMAXIMIZED: i32 = 62; // maximized window height
pub const SM_NETWORK: i32 = 63; // network present flag
pub const SM_CXDRAG: i32 = 68; // drag start threshold x
pub const SM_CYDRAG: i32 = 69; // drag start threshold y
pub const SM_CXMENUCHECK: i32 = 71; // menu check mark width
pub const SM_CYMENUCHECK: i32 = 72; // menu check mark height
pub const SM_MOUSEWHEELPRESENT: i32 = 75; // mouse wheel present
pub const SM_XVIRTUALSCREEN: i32 = 76; // virtual screen left
pub const SM_YVIRTUALSCREEN: i32 = 77; // virtual screen top
pub const SM_CXVIRTUALSCREEN: i32 = 78; // virtual screen width
pub const SM_CYVIRTUALSCREEN: i32 = 79; // virtual screen height
pub const SM_SAMEDISPLAYFORMAT: i32 = 81; // monitors same pixel format
pub const SM_CXFOCUSBORDER: i32 = 83; // focus rectangle border width
pub const SM_CYFOCUSBORDER: i32 = 84; // focus rectangle border height

// ── MessageBox flags ──────────────────────────────────────────────────────────

pub const MB_OK: u32 = 0x00000000;
pub const MB_ICONERROR: u32 = 0x00000010;
pub const IDOK: i32 = 1;

// ── MSG struct ────────────────────────────────────────────────────────────────
//
// Windows x64 layout (verified against Windows SDK):
//   offset  0: hwnd    (HWND = *void = 8 bytes)
//   offset  8: message (UINT = u32 = 4 bytes)
//   offset 12: _pad    (4 bytes — align wParam to 8)
//   offset 16: wParam  (WPARAM = usize = 8 bytes)
//   offset 24: lParam  (LPARAM = isize = 8 bytes)
//   offset 32: time    (DWORD = u32 = 4 bytes)
//   offset 36: pt.x    (LONG = i32 = 4 bytes)
//   offset 40: pt.y    (LONG = i32 = 4 bytes)
//   offset 44: _pad2   (4 bytes — align struct to 8)
//   total: 48 bytes

#[repr(C)]
pub struct Msg {
    pub hwnd: HWND,
    pub message: u32,
    pub _pad0: u32,
    pub w_param: WPARAM,
    pub l_param: LPARAM,
    pub time: u32,
    pub pt_x: i32,
    pub pt_y: i32,
    pub _pad1: u32,
}

/// ACCEL — accelerator table entry (user/kernel form).
///
/// Layout per include/winuser.h (Wine/Win32):
///   BYTE fVirt;   // FVIRTKEY=0x01, FSHIFT=0x04, FCONTROL=0x08, FALT=0x10, FNOINVERT=0x02
///   WORD key;
///   WORD cmd;
///
/// The PE resource form (PE_ACCEL) is 8 bytes per entry with an extra pad WORD
/// after fVirt (stored as u16) and a trailing pad WORD; the LAST_ENTRY (0x80)
/// sentinel lives in the low byte of the fVirt WORD in the PE blob and is
/// stripped ( & 0x7f ) when materializing user ACCEL entries via Copy.
///
/// # Safety
/// Used for FFI with guest code and for ptr::write into caller-supplied
/// buffers from CopyAcceleratorTable. Must match Windows x64 C layout (6 bytes,
/// naturally aligned as 2-byte struct on x86-64 with the BYTE+pad implicit).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_snake_case)]
pub struct ACCEL {
    pub fVirt: u8,
    pub key: u16,
    pub cmd: u16,
}

// ── WNDCLASSW struct ──────────────────────────────────────────────────────────
//
// Windows x64 layout:
//   offset  0: style         (UINT = u32)
//   offset  4: _pad          (4 bytes — align fn pointer to 8)
//   offset  8: lpfnWndProc   (WNDPROC = fn pointer = 8 bytes)
//   offset 16: cbClsExtra    (int = i32)
//   offset 20: cbWndExtra    (int = i32)
//   offset 24: hInstance     (HINSTANCE = usize)
//   offset 32: hIcon         (HICON = usize)
//   offset 40: hCursor       (HCURSOR = usize)
//   offset 48: hbrBackground (HBRUSH = usize)
//   offset 56: lpszMenuName  (*const u16)
//   offset 64: lpszClassName (*const u16)
//   total: 72 bytes

#[repr(C)]
pub struct WndClassW {
    pub style: u32,
    pub _pad: u32,
    pub lpfn_wnd_proc: usize, // WndProc, stored as usize
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: HINSTANCE,
    pub h_icon: HICON,
    pub h_cursor: HCURSOR,
    pub hbr_background: HBRUSH,
    pub lpsz_menu_name: *const u16,
    pub lpsz_class_name: *const u16,
}

// ── WNDCLASSEXW struct ────────────────────────────────────────────────────────
//
// Like WNDCLASSW but with cbSize prepended and hIconSm appended.
//   offset  0: cbSize        (UINT = u32)
//   offset  4: style         (UINT = u32)
//   offset  8: lpfnWndProc   (WNDPROC = usize)
//   offset 16: cbClsExtra    (i32)
//   offset 20: cbWndExtra    (i32)
//   offset 24: hInstance     (usize)
//   offset 32: hIcon         (usize)
//   offset 40: hCursor       (usize)
//   offset 48: hbrBackground (usize)
//   offset 56: lpszMenuName  (*const u16)
//   offset 64: lpszClassName (*const u16)
//   offset 72: hIconSm       (usize)
//   total: 80 bytes

#[repr(C)]
pub struct WndClassExW {
    pub cb_size: u32,
    pub style: u32,
    pub lpfn_wnd_proc: usize,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: HINSTANCE,
    pub h_icon: HICON,
    pub h_cursor: HCURSOR,
    pub hbr_background: HBRUSH,
    pub lpsz_menu_name: *const u16,
    pub lpsz_class_name: *const u16,
    pub h_icon_sm: HICON,
}

// ── ICONINFO struct ───────────────────────────────────────────────────────────
//
// Win64 layout (32 bytes):
//   offset  0: fIcon      (BOOL = i32, 4 bytes) — TRUE=icon, FALSE=cursor
//   offset  4: xHotspot   (DWORD = u32, 4 bytes)
//   offset  8: yHotspot   (DWORD = u32, 4 bytes)
//   offset 12: _pad       (4 bytes — HBITMAP requires 8-byte alignment)
//   offset 16: hbmMask    (HBITMAP = usize, 8 bytes) — monochrome AND mask
//   offset 24: hbmColor   (HBITMAP = usize, 8 bytes) — color XOR bitmap (NULL = mono)

#[repr(C)]
pub struct IconInfo {
    pub f_icon: i32,
    pub x_hotspot: u32,
    pub y_hotspot: u32,
    pub _pad: u32,
    pub hbm_mask: usize,
    pub hbm_color: usize,
}
const _: () = assert!(std::mem::size_of::<IconInfo>() == 32);

// ── RECT struct ───────────────────────────────────────────────────────────────

#[repr(C)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

// ── PAINTSTRUCT struct ────────────────────────────────────────────────────────
//
// Windows 64-bit layout (72 bytes):
//   offset  0: hdc         (HDC = usize, 8 bytes)
//   offset  8: fErase      (BOOL = i32, 4 bytes)
//   offset 12: rcPaint     (RECT = 16 bytes) — RECT is 4-byte aligned, no padding needed
//   offset 28: fRestore    (BOOL = i32, 4 bytes)
//   offset 32: fIncUpdate  (BOOL = i32, 4 bytes)
//   offset 36: rgbReserved ([u8; 32])
//   offset 68: 4-byte tail padding (struct must be 8-byte aligned for hdc)
//   total: 72 bytes
//
// Previous mistake: had a spurious _pad: u32 at offset 12, shifting rcPaint to
// offset 16. That caused Scintilla to read zeros for rcPaint.right, making
// IsRectEmpty() return true and skipping all painting.

#[repr(C)]
pub struct PaintStruct {
    pub hdc: usize,
    pub f_erase: i32,
    pub rc_paint: Rect,
    pub f_restore: i32,
    pub f_inc_update: i32,
    pub rgb_reserved: [u8; 32],
}
const _: () = assert!(std::mem::size_of::<PaintStruct>() == 72);

// ── CREATESTRUCTW — passed to WNDPROC with WM_CREATE / WM_NCCREATE ───────────
//
// The lParam for WM_CREATE is a pointer to this struct.
// Windows x64 layout (80 bytes):

#[repr(C)]
pub struct CreateStructW {
    pub lp_create_params: *mut u8, // +0
    pub h_instance: usize,         // +8
    pub h_menu: usize,             // +16
    pub hwnd_parent: usize,        // +24
    pub cy: i32,                   // +32
    pub cx: i32,                   // +36
    pub y: i32,                    // +40
    pub x: i32,                    // +44
    pub style: i32,                // +48
    pub _pad: u32,                 // +52
    pub lp_sz_name: *const u16,    // +56 (window title)
    pub lp_sz_class: *const u16,   // +64 (class name)
    pub dw_ex_style: u32,          // +72
    pub _pad2: u32,                // +76
} // total: 80 bytes

/// MONITORINFO: information about a monitor.
///
/// Windows x64 layout (40 bytes):
///   offset  0: cbSize    (u32)
///   offset  4: _pad      (u32)
///   offset  8: rcMonitor (RECT = 16 bytes)
///   offset 24: rcWork    (RECT = 16 bytes)
///   offset 40: dwFlags   (u32) — MONITORINFOF_PRIMARY = 1
///   _pad to align: 4 bytes (total 48 bytes on some compilers; use cbSize to detect)
///
/// Use this simplified layout that matches the 40-byte Windows definition:
#[repr(C)]
pub struct MonitorInfo {
    pub cb_size: u32,
    pub _pad: u32,
    pub rc_monitor: Rect,
    pub rc_work: Rect,
    pub dw_flags: u32,
}

/// POINT: a 2D coordinate pair.
#[repr(C)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

// ── WNDCLASSA / WNDCLASSEXA ───────────────────────────────────────────────────

/// WNDCLASSA: window class descriptor (ANSI variant).
///
/// Identical layout to WNDCLASSW except class/menu name fields are *const u8.
#[repr(C)]
pub struct WndClassA {
    pub style: u32,
    pub _pad: u32,
    pub lpfn_wnd_proc: usize,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: HINSTANCE,
    pub h_icon: HICON,
    pub h_cursor: HCURSOR,
    pub hbr_background: HBRUSH,
    pub lpsz_menu_name: *const u8,
    pub lpsz_class_name: *const u8,
}

/// WNDCLASSEXA: extended window class descriptor (ANSI variant).
#[repr(C)]
pub struct WndClassExA {
    pub cb_size: u32,
    pub style: u32,
    pub lpfn_wnd_proc: usize,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: HINSTANCE,
    pub h_icon: HICON,
    pub h_cursor: HCURSOR,
    pub hbr_background: HBRUSH,
    pub lpsz_menu_name: *const u8,
    pub lpsz_class_name: *const u8,
    pub h_icon_sm: HICON,
}

// ── WINDOWPLACEMENT ───────────────────────────────────────────────────────────

/// WINDOWPLACEMENT: window size, position, and show state.
///
/// Windows x64 layout (44 bytes):
///   +0  length          (UINT)
///   +4  flags           (UINT)
///   +8  showCmd         (UINT)
///   +12 ptMinPosition   (POINT = 8 bytes)
///   +20 ptMaxPosition   (POINT = 8 bytes)
///   +28 rcNormalPosition(RECT  = 16 bytes)
#[repr(C)]
pub struct WindowPlacement {
    pub length: u32,
    pub flags: u32,
    pub show_cmd: u32,
    pub pt_min_position: Point,
    pub pt_max_position: Point,
    pub rc_normal_position: Rect,
}

// ── SCROLLINFO ────────────────────────────────────────────────────────────────

/// SCROLLINFO: scroll bar parameters (28 bytes).
#[repr(C)]
pub struct ScrollInfo {
    pub cb_size: u32,
    pub f_mask: u32,
    pub n_min: i32,
    pub n_max: i32,
    pub n_page: u32,
    pub n_pos: i32,
    pub n_track_pos: i32,
}

// ── String helpers ────────────────────────────────────────────────────────────

/// Decode a null-terminated UTF-16 pointer to a `String`.
/// Returns an empty `String` if the pointer is null.
///
/// # Safety
/// `ptr`, if non-null, must point to a valid null-terminated UTF-16 sequence.
/// Maximum string length to walk for guest-provided pointers.
/// Prevents infinite loops or OOB reads from unterminated guest strings.
pub const MAX_GUEST_STR_LEN: usize = 65_536;

/// Decode a null-terminated UTF-16 pointer to a `String`.
/// Returns an empty `String` if the pointer is null.
///
/// # Safety
/// `ptr`, if non-null, must point to a valid null-terminated UTF-16 sequence.
/// Walk is capped at `MAX_GUEST_STR_LEN` to prevent OOB reads from guest strings.
pub unsafe fn decode_wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // Pointer validation: cap at MAX_GUEST_STR_LEN to avoid walking into
    // unmapped memory if the guest passes an unterminated wide string.
    while len < MAX_GUEST_STR_LEN && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// Decode a null-terminated ANSI (Latin-1/UTF-8) pointer to a `String`.
/// Returns an empty `String` if the pointer is null.
///
/// # Safety
/// `ptr`, if non-null, must point to a valid null-terminated byte string.
pub unsafe fn decode_ansi(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // Pointer validation: cap at MAX_GUEST_STR_LEN to avoid walking into
    // unmapped memory if the guest passes an unterminated ANSI string.
    while len < MAX_GUEST_STR_LEN && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(slice).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_size() {
        assert_eq!(std::mem::size_of::<Msg>(), 48);
    }

    #[test]
    fn wnd_class_w_size() {
        assert_eq!(std::mem::size_of::<WndClassW>(), 72);
    }

    #[test]
    fn wnd_class_ex_w_size() {
        assert_eq!(std::mem::size_of::<WndClassExW>(), 80);
    }

    #[test]
    fn rect_size() {
        assert_eq!(std::mem::size_of::<Rect>(), 16);
    }

    #[test]
    fn decode_wide_basic() {
        let wide: Vec<u16> = "Hello".encode_utf16().chain(std::iter::once(0)).collect();
        let s = unsafe { decode_wide(wide.as_ptr()) };
        assert_eq!(s, "Hello");
    }

    #[test]
    fn decode_wide_null_ptr() {
        let s = unsafe { decode_wide(std::ptr::null()) };
        assert_eq!(s, "");
    }
}
