//! X11 backend for weave-user32.
//!
//! All code here is `#[cfg(target_os = "linux")]`. On other platforms the
//! module exposes only the no-op stubs defined at the bottom of this file.
//!
//! # Design
//!
//! A single global `x11rb::rust_connection::RustConnection` is held for the
//! lifetime of the process. Windows are created on demand by `create_window`
//! and destroyed by `destroy_window`. The message loop in `api.rs` calls
//! `poll_event` / `wait_event` to translate X11 events into Win32 MSG entries.
//!
//! The connection is opened lazily on first use. If no DISPLAY is available
//! (e.g. running in a headless CI environment without Xvfb), all functions
//! return error codes and the process continues without a window.

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod inner {
    use std::sync::{Mutex, OnceLock};

    use crate::defs::*;
    use crate::queue::{self, MsgEntry};
    use crate::window;

    use x11rb::atom_manager;
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{
        AtomEnum, ConfigureNotifyEvent, ConnectionExt, CreateGCAux, CreateWindowAux, EventMask,
        Gcontext, PropMode, Window, WindowClass,
    };
    use x11rb::protocol::Event;
    use x11rb::rust_connection::RustConnection;
    use x11rb::wrapper::ConnectionExt as WrapperConnectionExt;

    // Intern the atoms we need at startup.
    atom_manager! {
        pub Atoms: AtomsCookie {
            WM_PROTOCOLS,
            WM_DELETE_WINDOW,
            _NET_WM_NAME,
            UTF8_STRING,
        }
    }

    pub struct X11State {
        pub conn: RustConnection,
        #[allow(dead_code)]
        pub screen_num: usize,
        pub atoms: Atoms,
        pub root: Window,
        pub white_pixel: u32,
        #[allow(dead_code)]
        pub black_pixel: u32,
        pub screen_width: u16,
        pub screen_height: u16,
    }

    static X11: OnceLock<Option<Mutex<X11State>>> = OnceLock::new();

    fn x11() -> Option<&'static Mutex<X11State>> {
        X11.get_or_init(|| {
            let (conn, screen_num) = RustConnection::connect(None).ok()?;
            let atoms = Atoms::new(&conn).ok()?.reply().ok()?;
            let screen = conn.setup().roots.get(screen_num)?.clone();
            Some(Mutex::new(X11State {
                atoms,
                root: screen.root,
                white_pixel: screen.white_pixel,
                black_pixel: screen.black_pixel,
                screen_width: screen.width_in_pixels,
                screen_height: screen.height_in_pixels,
                conn,
                screen_num,
            }))
        })
        .as_ref()
    }

    /// Return whether an X11 display is available.
    pub fn is_available() -> bool {
        x11().is_some()
    }

    /// Screen dimensions in pixels, or a sensible fallback.
    pub fn screen_size() -> (u16, u16) {
        x11()
            .map(|m| {
                let g = m.lock().unwrap();
                (g.screen_width, g.screen_height)
            })
            .unwrap_or((1920, 1080))
    }

    /// Create an X11 window and return its XCB window ID.
    /// Returns 0 on failure (no display, or XCB error).
    pub fn create_window(
        title: &str,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        visible: bool,
    ) -> u32 {
        let x11 = match x11() {
            Some(m) => m,
            None => return 0,
        };
        let g = x11.lock().unwrap();

        let wid = match g.conn.generate_id() {
            Ok(id) => id,
            Err(_) => return 0,
        };

        let event_mask = EventMask::EXPOSURE
            | EventMask::STRUCTURE_NOTIFY
            | EventMask::KEY_PRESS
            | EventMask::KEY_RELEASE
            | EventMask::BUTTON_PRESS
            | EventMask::BUTTON_RELEASE
            | EventMask::POINTER_MOTION;

        let aux = CreateWindowAux::new()
            .background_pixel(g.white_pixel)
            .event_mask(event_mask);

        if g.conn
            .create_window(
                x11rb::COPY_DEPTH_FROM_PARENT,
                wid,
                g.root,
                x as i16,
                y as i16,
                width.max(1) as u16,
                height.max(1) as u16,
                0,
                WindowClass::INPUT_OUTPUT,
                0,
                &aux,
            )
            .is_err()
        {
            return 0;
        }

        // Set window title via _NET_WM_NAME (UTF-8) and WM_NAME (Latin-1 fallback).
        let _ = g.conn.change_property8(
            PropMode::REPLACE,
            wid,
            g.atoms._NET_WM_NAME,
            g.atoms.UTF8_STRING,
            title.as_bytes(),
        );
        let _ = g.conn.change_property8(
            PropMode::REPLACE,
            wid,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            title.as_bytes(),
        );

        // Register WM_DELETE_WINDOW so we receive a ClientMessage when the
        // user closes the window instead of having it destroyed abruptly.
        let _ = g.conn.change_property32(
            PropMode::REPLACE,
            wid,
            g.atoms.WM_PROTOCOLS,
            AtomEnum::ATOM,
            &[g.atoms.WM_DELETE_WINDOW],
        );

        if visible {
            let _ = g.conn.map_window(wid);
        }

        let _ = g.conn.flush();
        wid
    }

    /// Show or hide an X11 window.
    pub fn show_window(xcb_id: u32, show: bool) {
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = x11.lock().unwrap();
        if show {
            let _ = g.conn.map_window(xcb_id);
        } else {
            let _ = g.conn.unmap_window(xcb_id);
        }
        let _ = g.conn.flush();
    }

    /// Destroy an X11 window.
    pub fn destroy_window(xcb_id: u32) {
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = x11.lock().unwrap();
        let _ = g.conn.destroy_window(xcb_id);
        let _ = g.conn.flush();
    }

    /// Update the title bar text of an X11 window.
    pub fn set_title(xcb_id: u32, title: &str) {
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = x11.lock().unwrap();
        let _ = g.conn.change_property8(
            PropMode::REPLACE,
            xcb_id,
            g.atoms._NET_WM_NAME,
            g.atoms.UTF8_STRING,
            title.as_bytes(),
        );
        let _ = g.conn.change_property8(
            PropMode::REPLACE,
            xcb_id,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            title.as_bytes(),
        );
        let _ = g.conn.flush();
    }

    static FONT_ID: OnceLock<Option<u32>> = OnceLock::new();

    fn get_or_open_font() -> Option<u32> {
        *FONT_ID.get_or_init(|| {
            let x11 = x11()?;
            let g = x11.lock().unwrap();
            let fid = g.conn.generate_id().ok()?;
            // Try common X11 bitmap font names in order.
            for name in [b"fixed" as &[u8], b"9x15", b"6x13"] {
                if g.conn.open_font(fid, name).is_ok() {
                    let _ = g.conn.flush();
                    return Some(fid);
                }
            }
            None
        })
    }

    /// Convert a Win32 COLORREF (0x00BBGGRR) to an X11 TrueColor pixel (0x00RRGGBB).
    pub fn colorref_to_pixel(colorref: u32) -> u32 {
        let r = colorref & 0xFF;
        let g = (colorref >> 8) & 0xFF;
        let b = (colorref >> 16) & 0xFF;
        (r << 16) | (g << 8) | b
    }

    /// Fill a solid rectangle on an X11 window.
    pub fn draw_filled_rect(xcb_id: u32, x: i16, y: i16, w: u16, h: u16, pixel: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = x11.lock().unwrap();
        let gc_id: Gcontext = match g.conn.generate_id() {
            Ok(id) => id,
            Err(_) => return,
        };
        let _ = g
            .conn
            .create_gc(gc_id, xcb_id, &CreateGCAux::new().foreground(pixel));
        let _ = g.conn.poly_fill_rectangle(
            xcb_id,
            gc_id,
            &[x11rb::protocol::xproto::Rectangle {
                x,
                y,
                width: w,
                height: h,
            }],
        );
        let _ = g.conn.free_gc(gc_id);
        let _ = g.conn.flush();
    }

    /// Draw a hollow rectangle outline on an X11 window.
    pub fn draw_rect_outline(xcb_id: u32, x: i16, y: i16, w: u16, h: u16, pixel: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = x11.lock().unwrap();
        let gc_id: Gcontext = match g.conn.generate_id() {
            Ok(id) => id,
            Err(_) => return,
        };
        let _ = g
            .conn
            .create_gc(gc_id, xcb_id, &CreateGCAux::new().foreground(pixel));
        let _ = g.conn.poly_rectangle(
            xcb_id,
            gc_id,
            &[x11rb::protocol::xproto::Rectangle {
                x,
                y,
                width: w,
                height: h,
            }],
        );
        let _ = g.conn.free_gc(gc_id);
        let _ = g.conn.flush();
    }

    /// Draw text using an X11 core bitmap font (Phase 2 legacy path).
    ///
    /// `text` must be ASCII/Latin-1 bytes (up to 255 per call). `fg_pixel` and
    /// `bg_pixel` are X11 TrueColor pixel values (0x00RRGGBB).
    pub fn draw_text(xcb_id: u32, x: i16, y: i16, text: &[u8], fg_pixel: u32, bg_pixel: u32) {
        if text.is_empty() {
            return;
        }
        let font_id = match get_or_open_font() {
            Some(f) => f,
            None => return,
        };
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = x11.lock().unwrap();
        let gc_id: Gcontext = match g.conn.generate_id() {
            Ok(id) => id,
            Err(_) => return,
        };
        let aux = CreateGCAux::new()
            .foreground(fg_pixel)
            .background(bg_pixel)
            .font(font_id);
        let _ = g.conn.create_gc(gc_id, xcb_id, &aux);
        // image_text8 y is the text baseline; add ~11px ascent for the "fixed" font.
        let baseline_y = y.saturating_add(11);
        // X11 image_text8 is limited to 255 bytes per call.
        let clamped = if text.len() > 255 { &text[..255] } else { text };
        let _ = g.conn.image_text8(xcb_id, gc_id, x, baseline_y, clamped);
        let _ = g.conn.free_gc(gc_id);
        let _ = g.conn.flush();
    }

    /// Draw UTF-16 text using fontdue rasterization + X11 PutImage.
    ///
    /// This is the Phase 3 text rendering path: proper Unicode support with
    /// anti-aliased TrueType rendering. Falls back to the legacy `draw_text`
    /// path if no system font is available.
    ///
    /// `fg_pixel` and `bg_pixel` are X11 TrueColor values (0x00RRGGBB).
    pub fn draw_text_utf16(
        xcb_id: u32,
        x: i16,
        y: i16,
        text: &[u16],
        px_size: f32,
        fg_pixel: u32,
        bg_pixel: u32,
    ) {
        use crate::font;
        use x11rb::protocol::xproto::ImageFormat;

        if text.is_empty() {
            return;
        }

        // Try fontdue rendering first.
        if let Some((pixels, w, h)) = font::rasterize_text(text, px_size, fg_pixel, bg_pixel) {
            let x11 = match x11() {
                Some(m) => m,
                None => return,
            };
            let g = x11.lock().unwrap();
            let gc_id: Gcontext = match g.conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = g.conn.create_gc(gc_id, xcb_id, &CreateGCAux::new());
            let _ = g.conn.put_image(
                ImageFormat::Z_PIXMAP,
                xcb_id,
                gc_id,
                w as u16,
                h as u16,
                x,
                y,
                0,  // left_pad
                24, // depth (TrueColor)
                &pixels,
            );
            let _ = g.conn.free_gc(gc_id);
            let _ = g.conn.flush();
        } else {
            // Fallback: convert to Latin-1 and use the legacy X11 bitmap path.
            let bytes: Vec<u8> = text
                .iter()
                .map(|&u| if u <= 0xFF { u as u8 } else { b'?' })
                .collect();
            draw_text(xcb_id, x, y, &bytes, fg_pixel, bg_pixel);
        }
    }

    /// Poll for one X11 event and translate it into Win32 messages.
    /// Returns `true` if an event was processed, `false` if none was pending.
    pub fn poll_event() -> bool {
        let x11 = match x11() {
            Some(m) => m,
            None => return false,
        };
        let event = {
            let g = x11.lock().unwrap();
            match g.conn.poll_for_event() {
                Ok(Some(ev)) => ev,
                _ => return false,
            }
        };
        translate_event(event, x11);
        true
    }

    /// Block until one X11 event arrives, translate it, and return.
    /// Returns `false` only on a connection error.
    pub fn wait_event() -> bool {
        let x11 = match x11() {
            Some(m) => m,
            None => return false,
        };
        let event = {
            let g = x11.lock().unwrap();
            match g.conn.wait_for_event() {
                Ok(ev) => ev,
                Err(_) => return false,
            }
        };
        translate_event(event, x11);
        true
    }

    /// Translate one X11 event into one or more Win32 queue messages.
    fn translate_event(event: Event, x11: &Mutex<X11State>) {
        let wm_delete_window = x11.lock().unwrap().atoms.WM_DELETE_WINDOW;

        match event {
            Event::ClientMessage(ev) => {
                // User clicked the window manager's close button.
                if ev.data.as_data32()[0] == wm_delete_window {
                    let hwnd = window::hwnd_for_xcb(ev.window);
                    if hwnd != 0 {
                        queue::post(MsgEntry {
                            hwnd,
                            message: WM_CLOSE,
                            w_param: 0,
                            l_param: 0,
                            time: 0,
                            pt_x: 0,
                            pt_y: 0,
                        });
                    }
                }
            }

            Event::Expose(ev) => {
                // Only post WM_PAINT for the last Expose in a sequence
                // (count == 0 means no more expose events follow).
                if ev.count == 0 {
                    let hwnd = window::hwnd_for_xcb(ev.window);
                    if hwnd != 0 {
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
                }
            }

            Event::ConfigureNotify(ConfigureNotifyEvent {
                window,
                width,
                height,
                ..
            }) => {
                let hwnd = window::hwnd_for_xcb(window);
                if hwnd != 0 {
                    // Update stored dimensions.
                    window::with_mut(hwnd, |e| {
                        e.width = width as u32;
                        e.height = height as u32;
                    });
                    // lParam: LOWORD = width, HIWORD = height (SIZE_RESTORED = 0)
                    let l_param = (width as isize) | ((height as isize) << 16);
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

            Event::KeyPress(ev) => {
                let hwnd = window::hwnd_for_xcb(ev.event);
                if hwnd != 0 {
                    queue::post(MsgEntry {
                        hwnd,
                        message: WM_KEYDOWN,
                        w_param: ev.detail as usize,
                        l_param: 0,
                        time: ev.time,
                        pt_x: ev.event_x as i32,
                        pt_y: ev.event_y as i32,
                    });
                }
            }

            Event::KeyRelease(ev) => {
                let hwnd = window::hwnd_for_xcb(ev.event);
                if hwnd != 0 {
                    queue::post(MsgEntry {
                        hwnd,
                        message: WM_KEYUP,
                        w_param: ev.detail as usize,
                        l_param: 0,
                        time: ev.time,
                        pt_x: ev.event_x as i32,
                        pt_y: ev.event_y as i32,
                    });
                }
            }

            Event::ButtonPress(ev) => {
                let hwnd = window::hwnd_for_xcb(ev.event);
                if hwnd != 0 {
                    let message = match ev.detail {
                        1 => WM_LBUTTONDOWN,
                        3 => WM_RBUTTONDOWN,
                        _ => return,
                    };
                    let l_param = (ev.event_x as isize) | ((ev.event_y as isize) << 16);
                    queue::post(MsgEntry {
                        hwnd,
                        message,
                        w_param: 0,
                        l_param,
                        time: ev.time,
                        pt_x: ev.event_x as i32,
                        pt_y: ev.event_y as i32,
                    });
                }
            }

            Event::ButtonRelease(ev) => {
                let hwnd = window::hwnd_for_xcb(ev.event);
                if hwnd != 0 {
                    let message = match ev.detail {
                        1 => WM_LBUTTONUP,
                        3 => WM_RBUTTONUP,
                        _ => return,
                    };
                    let l_param = (ev.event_x as isize) | ((ev.event_y as isize) << 16);
                    queue::post(MsgEntry {
                        hwnd,
                        message,
                        w_param: 0,
                        l_param,
                        time: ev.time,
                        pt_x: ev.event_x as i32,
                        pt_y: ev.event_y as i32,
                    });
                }
            }

            Event::MotionNotify(ev) => {
                let hwnd = window::hwnd_for_xcb(ev.event);
                if hwnd != 0 {
                    // wParam: MK_* modifier flags (Phase 2: always 0)
                    // lParam: LOWORD = x, HIWORD = y (client coordinates)
                    let l_param = (ev.event_x as isize) | ((ev.event_y as isize) << 16);
                    queue::post(MsgEntry {
                        hwnd,
                        message: WM_MOUSEMOVE,
                        w_param: 0,
                        l_param,
                        time: ev.time,
                        pt_x: ev.event_x as i32,
                        pt_y: ev.event_y as i32,
                    });
                }
            }

            _ => {} // Ignore all other events for now.
        }
    }
}

// ── Platform-specific re-exports ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use inner::{
    colorref_to_pixel, create_window, destroy_window, draw_filled_rect, draw_rect_outline,
    draw_text, draw_text_utf16, is_available, poll_event, screen_size, set_title, show_window,
    wait_event,
};

// ── No-op stubs for non-Linux platforms (macOS dev builds) ───────────────────

#[cfg(not(target_os = "linux"))]
pub fn is_available() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn screen_size() -> (u16, u16) {
    (1920, 1080)
}

#[cfg(not(target_os = "linux"))]
pub fn create_window(
    _title: &str,
    _x: i32,
    _y: i32,
    _width: u32,
    _height: u32,
    _visible: bool,
) -> u32 {
    0
}

#[cfg(not(target_os = "linux"))]
pub fn show_window(_xcb_id: u32, _show: bool) {}

#[cfg(not(target_os = "linux"))]
pub fn destroy_window(_xcb_id: u32) {}

#[cfg(not(target_os = "linux"))]
pub fn set_title(_xcb_id: u32, _title: &str) {}

#[cfg(not(target_os = "linux"))]
pub fn poll_event() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn wait_event() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn colorref_to_pixel(colorref: u32) -> u32 {
    colorref
}

#[cfg(not(target_os = "linux"))]
pub fn draw_filled_rect(_xcb_id: u32, _x: i16, _y: i16, _w: u16, _h: u16, _pixel: u32) {}

#[cfg(not(target_os = "linux"))]
pub fn draw_rect_outline(_xcb_id: u32, _x: i16, _y: i16, _w: u16, _h: u16, _pixel: u32) {}

#[cfg(not(target_os = "linux"))]
pub fn draw_text(_xcb_id: u32, _x: i16, _y: i16, _text: &[u8], _fg: u32, _bg: u32) {}

#[cfg(not(target_os = "linux"))]
pub fn draw_text_utf16(
    _xcb_id: u32,
    _x: i16,
    _y: i16,
    _text: &[u16],
    _px_size: f32,
    _fg: u32,
    _bg: u32,
) {
}
