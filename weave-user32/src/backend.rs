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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use crate::defs::*;
    use crate::queue::{self, MsgEntry};
    use crate::window;

    use x11rb::atom_manager;
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{
        AtomEnum, ConfigureNotifyEvent, ConfigureWindowAux, ConnectionExt, CreateGCAux,
        CreateWindowAux, EventMask, Gcontext, PropMode, Segment, Window, WindowClass,
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
        pub screen_width_mm: u16,
        #[allow(dead_code)]
        pub screen_height_mm: u16,
        /// Depth of the root window (typically 24 or 32). Used as PutImage depth.
        pub depth: u8,
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
                screen_width_mm: screen.width_in_millimeters,
                screen_height_mm: screen.height_in_millimeters,
                depth: screen.root_depth,
                conn,
                screen_num,
            }))
        })
        .as_ref()
    }

    fn lock_x11(m: &Mutex<X11State>) -> Option<MutexGuard<'_, X11State>> {
        m.lock()
            .map_err(|e| eprintln!("weave: user32: X11 mutex poisoned: {e}"))
            .ok()
    }

    /// Parse `Xft.dpi` from the X11 `RESOURCE_MANAGER` root window property.
    ///
    /// The `RESOURCE_MANAGER` property is a newline-separated list of X resource
    /// strings. Desktop environments (GNOME, KDE, etc.) set `Xft.dpi` here to
    /// communicate the intended DPI to all X clients, including under XWayland.
    fn read_xft_dpi(conn: &RustConnection, root: Window) -> Option<u32> {
        let reply = conn
            .get_property(
                false,
                root,
                AtomEnum::RESOURCE_MANAGER,
                AtomEnum::STRING,
                0,
                u32::MAX / 4,
            )
            .ok()?
            .reply()
            .ok()?;
        let data = std::str::from_utf8(&reply.value).ok()?;
        for line in data.lines() {
            if let Some(rest) = line.strip_prefix("Xft.dpi:") {
                let dpi: u32 = rest.trim().parse().ok()?;
                if (72..=576).contains(&dpi) {
                    return Some(dpi);
                }
            }
        }
        None
    }

    /// Calculate DPI from physical screen dimensions.
    ///
    /// Returns `None` if `mm` is zero or the result is outside the plausible
    /// range of 72–576 DPI.
    fn dpi_from_physical(px: u16, mm: u16) -> Option<u32> {
        if mm == 0 {
            return None;
        }
        let dpi = (f64::from(px) / f64::from(mm) * 25.4).round() as u32;
        if (72..=576).contains(&dpi) {
            Some(dpi)
        } else {
            None
        }
    }

    /// Detect the system DPI with the following priority:
    ///
    /// 1. `Xft.dpi` from the X11 `RESOURCE_MANAGER` root window property — this
    ///    is the authoritative value set by the desktop environment and works
    ///    correctly under both native X11 and XWayland.
    /// 2. Calculated from the physical screen width in millimetres as reported
    ///    by the X server (less reliable — monitors often report incorrect EDID).
    /// 3. 96 — the Windows "standard" DPI fallback.
    pub fn system_dpi() -> u32 {
        let Some(x11) = x11() else { return 96 };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return 96,
        };
        read_xft_dpi(&g.conn, g.root)
            .or_else(|| dpi_from_physical(g.screen_width, g.screen_width_mm))
            .unwrap_or(96)
    }

    /// Return whether an X11 display is available.
    pub fn is_available() -> bool {
        x11().is_some()
    }

    /// Screen dimensions in pixels, or a sensible fallback.
    pub fn screen_size() -> (u16, u16) {
        x11()
            .and_then(|m| {
                let g = lock_x11(m)?;
                Some((g.screen_width, g.screen_height))
            })
            .unwrap_or((1920, 1080))
    }

    /// Create an X11 window and return its XCB window ID.
    /// Returns 0 on failure (no display, or XCB error).
    /// Create an X11 window.
    ///
    /// `parent_xcb` — XCB window ID of the Win32 parent window, or 0 for top-level.
    /// Child windows are parented to their Win32 parent's X11 window (not root) so
    /// that they render on top of (and within) the parent. For top-level windows
    /// `parent_xcb` should be 0, which causes the root window to be used.
    pub fn create_window(
        title: &str,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        visible: bool,
        parent_xcb: u32,
    ) -> u32 {
        let x11 = match x11() {
            Some(m) => m,
            None => {
                eprintln!("weave/backend: create_window — x11() is None (no DISPLAY?)");
                return 0;
            }
        };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return 0,
        };

        let wid = match g.conn.generate_id() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("weave/backend: create_window — generate_id failed: {e}");
                return 0;
            }
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

        // Use the parent's X11 window if provided; fall back to root for top-level windows.
        let x11_parent = if parent_xcb != 0 { parent_xcb } else { g.root };

        if let Err(e) = g.conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            wid,
            x11_parent,
            x as i16,
            y as i16,
            width.max(1) as u16,
            height.max(1) as u16,
            0,
            WindowClass::INPUT_OUTPUT,
            0,
            &aux,
        ) {
            eprintln!("weave/backend: create_window — xcb create_window failed: {e}");
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
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
        if show {
            let _ = g.conn.map_window(xcb_id);
            // Win32 ShowWindow shows all visible children too.
            // map_subwindows recursively maps every unmapped descendant so that
            // child windows (Scintilla, toolbar, etc.) receive Expose events and
            // can repaint with correct content.
            let _ = g.conn.map_subwindows(xcb_id);
        } else {
            let _ = g.conn.unmap_window(xcb_id);
        }
        let _ = g.conn.flush();
    }

    /// Move and/or resize an X11 window via ConfigureWindow.
    ///
    /// Wine ref: dlls/winex11.drv/window.c — X11DRV_SetWindowPos calls
    /// XConfigureWindow with CWX/CWY for moves and CWWidth/CWHeight for resizes.
    /// Zero-size windows are clamped to 1×1 to avoid X11 BadValue errors.
    pub fn configure_window(xcb_id: u32, x: i32, y: i32, width: u32, height: u32) {
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
        let aux = ConfigureWindowAux::new()
            .x(x)
            .y(y)
            .width(width.max(1))
            .height(height.max(1));
        let _ = g.conn.configure_window(xcb_id, &aux);
        let _ = g.conn.flush();
    }

    /// Create an X11 Pixmap of the given dimensions.
    ///
    /// Wine ref: dlls/winex11.drv/bitblt.c — X11DRV_CreateBitmap allocates an
    /// X11 Pixmap via XCreatePixmap with the screen depth. Returns 0 on failure.
    pub fn create_pixmap(parent_drawable: u32, width: u16, height: u16) -> u32 {
        let x11 = match x11() {
            Some(m) => m,
            None => return 0,
        };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return 0,
        };
        let pid = match g.conn.generate_id() {
            Ok(id) => id,
            Err(_) => return 0,
        };
        let drawable = if parent_drawable != 0 {
            parent_drawable
        } else {
            g.root
        };
        if g.conn
            .create_pixmap(g.depth, pid, drawable, width.max(1), height.max(1))
            .is_err()
        {
            return 0;
        }
        let _ = g.conn.flush();
        pid
    }

    /// Draw a single-pixel line between two points using XDrawLine (poly_segment).
    ///
    /// Wine ref: dlls/winex11.drv/graphics.c — X11DRV_LineTo calls XDrawLine.
    pub fn draw_line(xcb_id: u32, x1: i16, y1: i16, x2: i16, y2: i16, pixel: u32) {
        if x1 == x2 && y1 == y2 {
            return;
        }
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
        let gc_id = match g.conn.generate_id() {
            Ok(id) => id,
            Err(_) => return,
        };
        let _ = g
            .conn
            .create_gc(gc_id, xcb_id, &CreateGCAux::new().foreground(pixel));
        let _ = g
            .conn
            .poly_segment(xcb_id, gc_id, &[Segment { x1, y1, x2, y2 }]);
        let _ = g.conn.free_gc(gc_id);
        let _ = g.conn.flush();
    }

    /// Copy a rectangle of pixels from one X11 drawable to another (XCopyArea).
    ///
    /// Wine ref: dlls/winex11.drv/bitblt.c — X11DRV_BitBlt issues XCopyArea for
    /// SRCCOPY. src and dst may be windows or pixmaps interchangeably.
    #[allow(clippy::too_many_arguments)]
    pub fn copy_area(
        src: u32,
        dst: u32,
        src_x: i16,
        src_y: i16,
        dst_x: i16,
        dst_y: i16,
        width: u16,
        height: u16,
    ) {
        if width == 0 || height == 0 {
            return;
        }
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
        let gc_id = match g.conn.generate_id() {
            Ok(id) => id,
            Err(_) => return,
        };
        let _ = g.conn.create_gc(gc_id, dst, &CreateGCAux::new());
        let _ = g
            .conn
            .copy_area(src, dst, gc_id, src_x, src_y, dst_x, dst_y, width, height);
        let _ = g.conn.free_gc(gc_id);
        let _ = g.conn.flush();
    }

    /// Destroy an X11 window.
    /// Free an X11 Pixmap.
    ///
    /// Wine ref: dlls/winex11.drv/bitblt.c — X11DRV_DeleteObject frees pixmaps allocated by CreateBitmap.
    pub fn free_pixmap(pid: u32) {
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
        let _ = g.conn.free_pixmap(pid);
        let _ = g.conn.flush();
    }

    pub fn destroy_window(xcb_id: u32) {
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
        let _ = g.conn.destroy_window(xcb_id);
        let _ = g.conn.flush();
    }

    /// Update the title bar text of an X11 window.
    pub fn set_title(xcb_id: u32, title: &str) {
        let x11 = match x11() {
            Some(m) => m,
            None => return,
        };
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
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
            let g = lock_x11(x11)?;
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
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
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
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
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
        let g = match lock_x11(x11) {
            Some(g) => g,
            None => return,
        };
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
            let g = match lock_x11(x11) {
                Some(g) => g,
                None => return,
            };
            let gc_id: Gcontext = match g.conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = g.conn.create_gc(gc_id, xcb_id, &CreateGCAux::new());
            // Wine ref: not applicable — X11 PutImage depth must match the drawable.
            // g.depth is stored from screen.root_depth at init; typically 24 on most
            // X11 servers, 32 on compositing desktops (XWayland, GNOME). Using the
            // wrong depth produces a BadMatch X11 error and silently drops the pixels.
            let _ = g.conn.put_image(
                ImageFormat::Z_PIXMAP,
                xcb_id,
                gc_id,
                w as u16,
                h as u16,
                x,
                y,
                0, // left_pad
                g.depth,
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

    /// Convert an X11 keycode (ev.detail, hardware scan code + 8) to a Win32 VK virtual key.
    ///
    /// Wine ref: dlls/winex11.drv/keyboard.c::EVENT_event_to_vkey — builds a per-process
    /// keyc2vkey[] table at runtime using XGetKeyboardMapping + keysym→VK tables.
    /// Weave: static table for the standard Linux evdev (pc105) US layout.
    /// X11 keycodes = Linux evdev keycode + 8 (the evdev offset).
    fn x11_keycode_to_vk(keycode: u8) -> u32 {
        match keycode {
            9 => 0x1B,  // VK_ESCAPE
            10 => 0x31, // VK_1
            11 => 0x32, // VK_2
            12 => 0x33, // VK_3
            13 => 0x34, // VK_4
            14 => 0x35, // VK_5
            15 => 0x36, // VK_6
            16 => 0x37, // VK_7
            17 => 0x38, // VK_8
            18 => 0x39, // VK_9
            19 => 0x30, // VK_0
            20 => 0xBD, // VK_OEM_MINUS  '-'
            21 => 0xBB, // VK_OEM_PLUS   '='
            22 => 0x08, // VK_BACK
            23 => 0x09, // VK_TAB
            // QWERTY row
            24 => 0x51, // VK_Q
            25 => 0x57, // VK_W
            26 => 0x45, // VK_E
            27 => 0x52, // VK_R
            28 => 0x54, // VK_T
            29 => 0x59, // VK_Y
            30 => 0x55, // VK_U
            31 => 0x49, // VK_I
            32 => 0x4F, // VK_O
            33 => 0x50, // VK_P
            34 => 0xDB, // VK_OEM_4  '['
            35 => 0xDD, // VK_OEM_6  ']'
            36 => 0x0D, // VK_RETURN
            37 => 0xA2, // VK_LCONTROL
            // ASDF row
            38 => 0x41, // VK_A
            39 => 0x53, // VK_S
            40 => 0x44, // VK_D
            41 => 0x46, // VK_F
            42 => 0x47, // VK_G
            43 => 0x48, // VK_H
            44 => 0x4A, // VK_J
            45 => 0x4B, // VK_K
            46 => 0x4C, // VK_L
            47 => 0xBA, // VK_OEM_1  ';'
            48 => 0xDE, // VK_OEM_7  '\''
            49 => 0xC0, // VK_OEM_3  '`'
            50 => 0xA0, // VK_LSHIFT
            51 => 0xDC, // VK_OEM_5  '\'
            // ZXCV row
            52 => 0x5A, // VK_Z
            53 => 0x58, // VK_X
            54 => 0x43, // VK_C
            55 => 0x56, // VK_V
            56 => 0x42, // VK_B
            57 => 0x4E, // VK_N
            58 => 0x4D, // VK_M
            59 => 0xBC, // VK_OEM_COMMA  ','
            60 => 0xBE, // VK_OEM_PERIOD '.'
            61 => 0xBF, // VK_OEM_2      '/'
            62 => 0xA1, // VK_RSHIFT
            63 => 0x6A, // VK_MULTIPLY (KP_*)
            64 => 0xA4, // VK_LMENU  (Alt_L)
            65 => 0x20, // VK_SPACE
            66 => 0x14, // VK_CAPITAL (CapsLock)
            // Function keys
            67 => 0x70, // VK_F1
            68 => 0x71, // VK_F2
            69 => 0x72, // VK_F3
            70 => 0x73, // VK_F4
            71 => 0x74, // VK_F5
            72 => 0x75, // VK_F6
            73 => 0x76, // VK_F7
            74 => 0x77, // VK_F8
            75 => 0x78, // VK_F9
            76 => 0x79, // VK_F10
            77 => 0x90, // VK_NUMLOCK
            78 => 0x91, // VK_SCROLL
            // Numpad
            79 => 0x67, // VK_NUMPAD7
            80 => 0x68, // VK_NUMPAD8
            81 => 0x69, // VK_NUMPAD9
            82 => 0x6D, // VK_SUBTRACT
            83 => 0x64, // VK_NUMPAD4
            84 => 0x65, // VK_NUMPAD5
            85 => 0x66, // VK_NUMPAD6
            86 => 0x6B, // VK_ADD
            87 => 0x61, // VK_NUMPAD1
            88 => 0x62, // VK_NUMPAD2
            89 => 0x63, // VK_NUMPAD3
            90 => 0x60, // VK_NUMPAD0
            91 => 0x6E, // VK_DECIMAL
            95 => 0x7A, // VK_F11
            96 => 0x7B, // VK_F12
            // Extended / nav cluster
            104 => 0x0D, // VK_RETURN  (KP_Enter)
            105 => 0xA3, // VK_RCONTROL
            106 => 0x6F, // VK_DIVIDE  (KP_/)
            107 => 0x2C, // VK_SNAPSHOT
            108 => 0xA5, // VK_RMENU   (Alt_R / AltGr)
            110 => 0x24, // VK_HOME
            111 => 0x26, // VK_UP
            112 => 0x21, // VK_PRIOR   (PageUp)
            113 => 0x25, // VK_LEFT
            114 => 0x27, // VK_RIGHT
            115 => 0x23, // VK_END
            116 => 0x28, // VK_DOWN
            117 => 0x22, // VK_NEXT    (PageDown)
            118 => 0x2D, // VK_INSERT
            119 => 0x2E, // VK_DELETE
            133 => 0x5B, // VK_LWIN   (Super_L)
            134 => 0x5C, // VK_RWIN   (Super_R)
            135 => 0x5D, // VK_APPS   (Menu)
            _ => 0,      // unknown — caller should fall back to raw keycode
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
            let g = match lock_x11(x11) {
                Some(g) => g,
                None => return false,
            };
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
            let g = match lock_x11(x11) {
                Some(g) => g,
                None => return false,
            };
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
        let wm_delete_window = match lock_x11(x11) {
            Some(g) => g.atoms.WM_DELETE_WINDOW,
            None => return,
        };

        // Diagnostic: log every X11 event type so we can see if events arrive.
        let event_tag = match &event {
            Event::Expose(ev) => format!("Expose(window={:#x}, count={})", ev.window, ev.count),
            Event::ClientMessage(_) => "ClientMessage".to_string(),
            Event::ConfigureNotify(_) => "ConfigureNotify".to_string(),
            Event::KeyPress(_) => "KeyPress".to_string(),
            Event::KeyRelease(_) => "KeyRelease".to_string(),
            Event::ButtonPress(_) => "ButtonPress".to_string(),
            Event::ButtonRelease(_) => "ButtonRelease".to_string(),
            Event::MotionNotify(_) => "MotionNotify".to_string(),
            _ => "Other".to_string(),
        };
        eprintln!("weave/x11: event {event_tag}");

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

                    // WS1 fix: On the first Expose (X server is now showing
                    // mapped windows), post WM_PAINT to ALL registered hwnds.
                    //
                    // Scintilla and other child windows paint during init
                    // (triggered by UpdateWindow/WM_PAINT from the queue) while
                    // their X11 windows are still unmapped — the X server
                    // silently discards those draws. After ShowWindow maps the
                    // top-level X11 window, most children receive Expose and
                    // repaint correctly, but windows that were already mapped
                    // via SetWindowPos before the parent was shown may not get
                    // Expose at all. This one-shot mass WM_PAINT guarantees
                    // they all repaint on their now-visible X11 surfaces.
                    static FIRST_EXPOSE_SEEN: AtomicBool = AtomicBool::new(false);
                    if !FIRST_EXPOSE_SEEN.swap(true, Ordering::SeqCst) {
                        // Force redraw of top-level window too
                        let top_hwnd = window::all_hwnds().first().copied().unwrap_or(0);
                        if top_hwnd != 0 {
                            queue::post(MsgEntry {
                                hwnd: top_hwnd,
                                message: WM_PAINT,
                                w_param: 0,
                                l_param: 0,
                                time: 0,
                                pt_x: 0,
                                pt_y: 0,
                            });
                        }
                        eprintln!("weave/x11: first Expose — posting WM_PAINT to all hwnds");
                        for h in window::all_hwnds() {
                            queue::post(MsgEntry {
                                hwnd: h,
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
                    let vk = x11_keycode_to_vk(ev.detail);
                    // Store X11 modifier state in l_param high word so TranslateMessage
                    // can extract the shift flag for WM_CHAR generation.
                    let l_param = ((u16::from(ev.state) as isize) << 16) | 1;
                    queue::post(MsgEntry {
                        hwnd,
                        message: WM_KEYDOWN,
                        w_param: vk as usize,
                        l_param,
                        time: ev.time,
                        pt_x: ev.event_x as i32,
                        pt_y: ev.event_y as i32,
                    });
                }
            }

            Event::KeyRelease(ev) => {
                let hwnd = window::hwnd_for_xcb(ev.event);
                if hwnd != 0 {
                    let vk = x11_keycode_to_vk(ev.detail);
                    let l_param = ((u16::from(ev.state) as isize) << 16) | (1 << 30) | (1 << 31);
                    queue::post(MsgEntry {
                        hwnd,
                        message: WM_KEYUP,
                        w_param: vk as usize,
                        l_param,
                        time: ev.time,
                        pt_x: ev.event_x as i32,
                        pt_y: ev.event_y as i32,
                    });
                }
            }

            Event::ButtonPress(ev) => {
                let hwnd = window::hwnd_for_xcb(ev.event);
                if hwnd != 0 {
                    let l_param = (ev.event_x as isize) | ((ev.event_y as isize) << 16);
                    match ev.detail {
                        1 | 3 => {
                            let message = if ev.detail == 1 {
                                WM_LBUTTONDOWN
                            } else {
                                WM_RBUTTONDOWN
                            };
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
                        // X11 button 4 = scroll up, button 5 = scroll down.
                        // Wine ref: dlls/winex11.drv/mouse.c — button_down_data[3]=WHEEL_DELTA(120),
                        //   button_down_data[4]=-WHEEL_DELTA(-120). WM_MOUSEWHEEL wParam HIWORD =
                        //   signed delta: +120 forward/up, -120 backward/down. LOWORD = modifier keys.
                        4 | 5 => {
                            let delta: i16 = if ev.detail == 4 { 120 } else { -120 };
                            let w_param = (delta as u16 as usize) << 16;
                            queue::post(MsgEntry {
                                hwnd,
                                message: WM_MOUSEWHEEL,
                                w_param,
                                l_param,
                                time: ev.time,
                                pt_x: ev.event_x as i32,
                                pt_y: ev.event_y as i32,
                            });
                        }
                        _ => {}
                    }
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
    colorref_to_pixel, configure_window, copy_area, create_pixmap, create_window, destroy_window,
    draw_filled_rect, draw_line, draw_rect_outline, draw_text, draw_text_utf16, free_pixmap,
    is_available, poll_event, screen_size, set_title, show_window, system_dpi, wait_event,
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
pub fn system_dpi() -> u32 {
    96
}

#[cfg(not(target_os = "linux"))]
pub fn create_window(
    _title: &str,
    _x: i32,
    _y: i32,
    _width: u32,
    _height: u32,
    _visible: bool,
    _parent_xcb: u32,
) -> u32 {
    0
}

#[cfg(not(target_os = "linux"))]
pub fn show_window(_xcb_id: u32, _show: bool) {}

#[cfg(not(target_os = "linux"))]
pub fn configure_window(_xcb_id: u32, _x: i32, _y: i32, _width: u32, _height: u32) {}

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
pub fn create_pixmap(_parent_drawable: u32, _width: u16, _height: u16) -> u32 {
    0
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn copy_area(
    _src: u32,
    _dst: u32,
    _src_x: i16,
    _src_y: i16,
    _dst_x: i16,
    _dst_y: i16,
    _width: u16,
    _height: u16,
) {
}

#[cfg(not(target_os = "linux"))]
pub fn draw_line(_xcb_id: u32, _x1: i16, _y1: i16, _x2: i16, _y2: i16, _pixel: u32) {}

#[cfg(not(target_os = "linux"))]
pub fn free_pixmap(_pid: u32) {}

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
