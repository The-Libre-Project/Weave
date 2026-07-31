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

// ── Global backend instance ────────────────────────────────────────────────────

/// Initialise the process-global backend. Must be called before any backend
/// functions. Returns `true` if a display is available, `false` otherwise.
#[cfg(target_os = "linux")]
pub fn init() -> bool {
    select_backend()
        .map(|b| {
            let _ = crate::backend_trait::BACKEND.set(b);
        })
        .is_some()
}

/// Select the window backend based on the display server environment.
///
/// Currently always returns `XcbBackend`. When a Wayland backend is added,
/// extend this function: detect `WAYLAND_DISPLAY` and construct
/// `WaylandBackend::new()` instead.
#[cfg(target_os = "linux")]
fn select_backend() -> Option<Box<dyn crate::backend_trait::WindowBackend + Send + Sync>> {
    let wayland = std::env::var("WAYLAND_DISPLAY")
        .ok()
        .filter(|v| !v.is_empty());
    let display = std::env::var("DISPLAY").ok().filter(|v| !v.is_empty());

    if wayland.is_some() {
        eprintln!(
            "weave/user32: WAYLAND_DISPLAY detected but no Wayland backend — falling back to xcb"
        );
    }

    eprintln!(
        "weave/user32: backend selected: xcb (Wayland not implemented, DISPLAY={})",
        display.as_deref().unwrap_or("(unset)"),
    );

    // TODO: when a WaylandBackend is implemented, add a match arm:
    //   if wayland.is_some() && display.is_none() => WaylandBackend::new()
    inner::XcbBackend::new()
        .map(|b| Box::new(b) as Box<dyn crate::backend_trait::WindowBackend + Send + Sync>)
}

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod inner {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, OnceLock};

    use crate::backend_trait::{
        BackendError, BackendResult, Drawable, PixmapHandle, WindowBackend, WindowHandle, BACKEND,
    };
    use crate::defs::*;
    use crate::queue::{self, MsgEntry};
    use crate::window;

    use x11rb::atom_manager;
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{
        AtomEnum, ChangeGCAux, ConfigureNotifyEvent, ConfigureWindowAux, ConnectionExt,
        CreateGCAux, CreateWindowAux, EventMask, Gcontext, ImageFormat, PropMode, Rectangle,
        Segment, Window, WindowClass, GX,
    };
    use x11rb::protocol::Event;
    use x11rb::rust_connection::RustConnection;
    use x11rb::wrapper::ConnectionExt as WrapperConnectionExt;

    // ── XcbBackend ──────────────────────────────────────────────────────────────

    atom_manager! {
        Atoms: AtomsCookie {
            WM_PROTOCOLS,
            WM_DELETE_WINDOW,
            _NET_WM_NAME,
            UTF8_STRING,
        }
    }

    pub struct XcbBackend {
        conn: Mutex<RustConnection>,
        #[allow(dead_code)]
        screen_num: usize,
        atoms: Atoms,
        root: Window,
        white_pixel: u32,
        #[allow(dead_code)]
        black_pixel: u32,
        screen_width: u16,
        screen_height: u16,
        screen_width_mm: u16,
        #[allow(dead_code)]
        screen_height_mm: u16,
        /// Depth of the root window (typically 24 or 32). Used as PutImage depth.
        depth: u8,
        font_id: OnceLock<Option<u32>>,
    }

    impl XcbBackend {
        pub fn new() -> Option<Self> {
            let (conn, screen_num) = RustConnection::connect(None).ok()?;
            let atoms = Atoms::new(&conn).ok()?.reply().ok()?;
            let screen = conn.setup().roots.get(screen_num)?.clone();
            Some(XcbBackend {
                conn: Mutex::new(conn),
                screen_num,
                atoms,
                root: screen.root,
                white_pixel: screen.white_pixel,
                black_pixel: screen.black_pixel,
                screen_width: screen.width_in_pixels,
                screen_height: screen.height_in_pixels,
                screen_width_mm: screen.width_in_millimeters,
                screen_height_mm: screen.height_in_millimeters,
                depth: screen.root_depth,
                font_id: OnceLock::new(),
            })
        }

        fn get_or_open_font(&self) -> Option<u32> {
            *self.font_id.get_or_init(|| {
                let conn = self.conn.lock().ok()?;
                let fid = conn.generate_id().ok()?;
                for name in [b"fixed" as &[u8], b"9x15", b"6x13"] {
                    if conn.open_font(fid, name).is_ok() {
                        let _ = conn.flush();
                        return Some(fid);
                    }
                }
                None
            })
        }
    }

    // ── WindowBackend trait implementation ──────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    impl WindowBackend for XcbBackend {
        fn is_available(&self) -> bool {
            true
        }

        fn screen_size(&self) -> (u16, u16) {
            (self.screen_width, self.screen_height)
        }

        fn system_dpi(&self) -> u32 {
            read_xft_dpi(&self.conn, self.root)
                .or_else(|| dpi_from_physical(self.screen_width, self.screen_width_mm))
                .unwrap_or(96)
        }

        fn enumerate_monitors(&self) -> Vec<crate::backend_trait::MonitorInfo> {
            use crate::backend_trait::MonitorInfo;
            vec![MonitorInfo {
                handle: 0,
                bounds: (0, 0, self.screen_width as i32, self.screen_height as i32),
                work_area: (0, 0, self.screen_width as i32, self.screen_height as i32),
                is_primary: true,
            }]
        }

        fn create_window(
            &self,
            title: &str,
            x: i32,
            y: i32,
            width: u32,
            height: u32,
            visible: bool,
            _parent: Option<WindowHandle>,
        ) -> BackendResult<WindowHandle> {
            let conn = self
                .conn
                .lock()
                .map_err(|e| BackendError::ConnectionError(format!("mutex poisoned: {e}")))?;

            let wid = conn
                .generate_id()
                .map_err(|e| BackendError::WindowError(format!("generate_id failed: {e}")))?;

            let event_mask = EventMask::EXPOSURE
                | EventMask::STRUCTURE_NOTIFY
                | EventMask::KEY_PRESS
                | EventMask::KEY_RELEASE
                | EventMask::BUTTON_PRESS
                | EventMask::BUTTON_RELEASE
                | EventMask::POINTER_MOTION
                | EventMask::ENTER_WINDOW
                | EventMask::LEAVE_WINDOW;

            let aux = CreateWindowAux::new()
                .background_pixel(self.white_pixel)
                .backing_store(x11rb::protocol::xproto::BackingStore::ALWAYS)
                .event_mask(event_mask);

            // Always create as children of root — XQuartz (macOS compositor) only
            // renders top-level X11 windows correctly. Win32 parent-child is
            // managed at the HWND level; all X11 windows are siblings.
            conn.create_window(
                x11rb::COPY_DEPTH_FROM_PARENT,
                wid,
                self.root,
                x as i16,
                y as i16,
                width.max(1) as u16,
                height.max(1) as u16,
                0,
                WindowClass::INPUT_OUTPUT,
                0,
                &aux,
            )
            .map_err(|e| BackendError::WindowError(format!("xcb create_window failed: {e}")))?;

            // Set window title via _NET_WM_NAME (UTF-8) and WM_NAME (Latin-1 fallback).
            let _ = conn.change_property8(
                PropMode::REPLACE,
                wid,
                self.atoms._NET_WM_NAME,
                self.atoms.UTF8_STRING,
                title.as_bytes(),
            );
            let _ = conn.change_property8(
                PropMode::REPLACE,
                wid,
                AtomEnum::WM_NAME,
                AtomEnum::STRING,
                title.as_bytes(),
            );

            // Register WM_DELETE_WINDOW.
            let _ = conn.change_property32(
                PropMode::REPLACE,
                wid,
                self.atoms.WM_PROTOCOLS,
                AtomEnum::ATOM,
                &[self.atoms.WM_DELETE_WINDOW],
            );

            if visible {
                let _ = conn.map_window(wid);
            }

            let _ = conn.flush();
            Ok(WindowHandle(wid))
        }

        fn destroy_window(&self, window: WindowHandle) {
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let _ = conn.destroy_window(window.0);
            let _ = conn.flush();
        }

        fn show_window(&self, window: WindowHandle, show: bool) {
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            if show {
                let _ = conn.map_window(window.0);
                let _ = conn.map_subwindows(window.0);
            } else {
                let _ = conn.unmap_window(window.0);
            }
            let _ = conn.flush();
        }

        fn configure_window(&self, window: WindowHandle, x: i32, y: i32, width: u32, height: u32) {
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let aux = ConfigureWindowAux::new()
                .x(x)
                .y(y)
                .width(width.max(1))
                .height(height.max(1));
            let _ = conn.configure_window(window.0, &aux);
            let _ = conn.flush();
        }

        fn set_title(&self, window: WindowHandle, title: &str) {
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let _ = conn.change_property8(
                PropMode::REPLACE,
                window.0,
                self.atoms._NET_WM_NAME,
                self.atoms.UTF8_STRING,
                title.as_bytes(),
            );
            let _ = conn.change_property8(
                PropMode::REPLACE,
                window.0,
                AtomEnum::WM_NAME,
                AtomEnum::STRING,
                title.as_bytes(),
            );
            let _ = conn.flush();
        }

        fn poll_event(&self) -> bool {
            let event = {
                let conn = match self.conn.lock() {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                conn.poll_for_event().ok().flatten()
            };
            match event {
                Some(ev) => {
                    self.translate_event(ev);
                    true
                }
                None => false,
            }
        }

        fn wait_event(&self) -> bool {
            use std::os::unix::io::AsRawFd;

            crate::queue::init_wake_pipe();
            let wake_fd = crate::queue::wake_fd_read();

            let x11_fd: i32 = match self.conn.lock() {
                Ok(c) => c.stream().as_raw_fd(),
                Err(_) => return false,
            };

            loop {
                let mut fds = [
                    libc::pollfd {
                        fd: x11_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: wake_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 50) };

                if ret < 0 {
                    continue;
                }

                if fds[1].revents & libc::POLLIN != 0 {
                    let mut buf = [0u8; 64];
                    unsafe { libc::read(wake_fd, buf.as_mut_ptr() as *mut _, 64) };
                    return true;
                }

                if fds[0].revents & libc::POLLIN != 0 {
                    let event = match self.conn.lock() {
                        Ok(c) => c.poll_for_event().ok().flatten(),
                        Err(_) => None,
                    };
                    if let Some(ev) = event {
                        self.translate_event(ev);
                        return true;
                    }
                    continue;
                }

                return true;
            }
        }

        fn create_pixmap(&self, width: u16, height: u16) -> BackendResult<PixmapHandle> {
            let conn = self
                .conn
                .lock()
                .map_err(|e| BackendError::PixmapError(format!("mutex poisoned: {e}")))?;
            let pid = conn
                .generate_id()
                .map_err(|_| BackendError::PixmapError("generate_id failed".into()))?;
            conn.create_pixmap(self.depth, pid, self.root, width.max(1), height.max(1))
                .map_err(|_| BackendError::PixmapError("create_pixmap failed".into()))?;
            let _ = conn.flush();
            Ok(PixmapHandle(pid))
        }

        fn free_pixmap(&self, pixmap: PixmapHandle) {
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let _ = conn.free_pixmap(pixmap.0);
            let _ = conn.flush();
        }

        fn draw_line(&self, dst: Drawable, x1: i16, y1: i16, x2: i16, y2: i16, pixel: u32) {
            if x1 == x2 && y1 == y2 {
                return;
            }
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let gc_id = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = conn.create_gc(gc_id, dst.0, &CreateGCAux::new().foreground(pixel));
            let _ = conn.poly_segment(dst.0, gc_id, &[Segment { x1, y1, x2, y2 }]);
            let _ = conn.free_gc(gc_id);
            let _ = conn.flush();
        }

        fn copy_area(
            &self,
            src: Drawable,
            dst: Drawable,
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
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let gc_id = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = conn.create_gc(gc_id, dst.0, &CreateGCAux::new());
            let _ = conn.copy_area(
                src.0, dst.0, gc_id, src_x, src_y, dst_x, dst_y, width, height,
            );
            let _ = conn.free_gc(gc_id);
            let _ = conn.sync();
        }

        fn copy_area_with_rop(
            &self,
            src: Drawable,
            dst: Drawable,
            src_x: i16,
            src_y: i16,
            dst_x: i16,
            dst_y: i16,
            width: u16,
            height: u16,
            gx_func: u32,
        ) {
            if width == 0 || height == 0 {
                return;
            }
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let gc_id = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = conn.create_gc(
                gc_id,
                dst.0,
                &CreateGCAux::new().function(GX::from(gx_func)),
            );
            let _ = conn.copy_area(
                src.0, dst.0, gc_id, src_x, src_y, dst_x, dst_y, width, height,
            );
            let _ = conn.change_gc(gc_id, &ChangeGCAux::new().function(GX::COPY));
            let _ = conn.free_gc(gc_id);
            let _ = conn.sync();
        }

        fn fill_rect_with_rop(
            &self,
            dst: Drawable,
            x: i16,
            y: i16,
            w: u16,
            h: u16,
            gx_func: u32,
            pixel: u32,
        ) {
            if w == 0 || h == 0 {
                return;
            }
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let gc_id: Gcontext = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = conn.create_gc(
                gc_id,
                dst.0,
                &CreateGCAux::new()
                    .function(GX::from(gx_func))
                    .foreground(pixel),
            );
            let _ = conn.poly_fill_rectangle(
                dst.0,
                gc_id,
                &[Rectangle {
                    x,
                    y,
                    width: w,
                    height: h,
                }],
            );
            let _ = conn.change_gc(gc_id, &ChangeGCAux::new().function(GX::COPY));
            let _ = conn.free_gc(gc_id);
            let _ = conn.flush();
        }

        fn draw_filled_rect(&self, dst: Drawable, x: i16, y: i16, w: u16, h: u16, pixel: u32) {
            if w == 0 || h == 0 {
                return;
            }
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let gc_id: Gcontext = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = conn.create_gc(gc_id, dst.0, &CreateGCAux::new().foreground(pixel));
            let _ = conn.poly_fill_rectangle(
                dst.0,
                gc_id,
                &[Rectangle {
                    x,
                    y,
                    width: w,
                    height: h,
                }],
            );
            let _ = conn.free_gc(gc_id);
            let _ = conn.flush();
        }

        fn draw_rect_outline(&self, dst: Drawable, x: i16, y: i16, w: u16, h: u16, pixel: u32) {
            if w == 0 || h == 0 {
                return;
            }
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let gc_id: Gcontext = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = conn.create_gc(gc_id, dst.0, &CreateGCAux::new().foreground(pixel));
            let _ = conn.poly_rectangle(
                dst.0,
                gc_id,
                &[Rectangle {
                    x,
                    y,
                    width: w,
                    height: h,
                }],
            );
            let _ = conn.free_gc(gc_id);
            let _ = conn.flush();
        }

        fn draw_text(
            &self,
            dst: Drawable,
            x: i16,
            y: i16,
            text: &[u8],
            fg_pixel: u32,
            bg_pixel: u32,
        ) {
            if text.is_empty() {
                return;
            }
            let font_id = match self.get_or_open_font() {
                Some(f) => f,
                None => return,
            };
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let gc_id: Gcontext = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let aux = CreateGCAux::new()
                .foreground(fg_pixel)
                .background(bg_pixel)
                .font(font_id);
            let _ = conn.create_gc(gc_id, dst.0, &aux);
            let baseline_y = y.saturating_add(11);
            let clamped = if text.len() > 255 { &text[..255] } else { text };
            let _ = conn.image_text8(dst.0, gc_id, x, baseline_y, clamped);
            let _ = conn.free_gc(gc_id);
            let _ = conn.flush();
        }

        fn draw_text_utf16(
            &self,
            dst: Drawable,
            x: i16,
            y: i16,
            text: &[u16],
            px_size: f32,
            fg_pixel: u32,
            bg_pixel: u32,
            font_path: Option<&str>,
        ) {
            use crate::font;
            use x11rb::protocol::xproto::ImageFormat;

            if text.is_empty() {
                return;
            }

            if let Some((pixels, w, h)) =
                font::rasterize_text(text, px_size, fg_pixel, bg_pixel, font_path)
            {
                let conn = match self.conn.lock() {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let gc_id: Gcontext = match conn.generate_id() {
                    Ok(id) => id,
                    Err(_) => return,
                };
                let _ = conn.create_gc(gc_id, dst.0, &CreateGCAux::new());
                let _ = conn.put_image(
                    ImageFormat::Z_PIXMAP,
                    dst.0,
                    gc_id,
                    w as u16,
                    h as u16,
                    x,
                    y,
                    0,
                    self.depth,
                    &pixels,
                );
                let _ = conn.free_gc(gc_id);
                let _ = conn.flush();
            } else {
                let bytes: Vec<u8> = text
                    .iter()
                    .map(|&u| if u <= 0xFF { u as u8 } else { b'?' })
                    .collect();
                self.draw_text(dst, x, y, &bytes, fg_pixel, bg_pixel);
            }
        }

        unsafe fn put_dib_to_pixmap(
            &self,
            pixmap: PixmapHandle,
            width: u32,
            height: u32,
            bits_ptr: usize,
            bpp: u16,
        ) {
            if pixmap.0 == 0 || width == 0 || height == 0 || bits_ptr == 0 {
                return;
            }
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };

            let stride = ((u64::from(width) * u64::from(bpp)).div_ceil(32) * 4) as usize;

            let pixels: Vec<u8> = match bpp {
                32 => {
                    let size = stride * height as usize;
                    unsafe { std::slice::from_raw_parts(bits_ptr as *const u8, size) }.to_vec()
                }
                24 => {
                    let src = unsafe {
                        std::slice::from_raw_parts(bits_ptr as *const u8, stride * height as usize)
                    };
                    let mut out = vec![0u8; (width * height * 4) as usize];
                    for row in 0..height as usize {
                        let row_src = &src[row * stride..row * stride + width as usize * 3];
                        for (col, chunk) in row_src.chunks_exact(3).enumerate() {
                            let base = (row * width as usize + col) * 4;
                            out[base] = chunk[0];
                            out[base + 1] = chunk[1];
                            out[base + 2] = chunk[2];
                            out[base + 3] = 0xFF;
                        }
                    }
                    out
                }
                _ => return,
            };

            let gc_id: Gcontext = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = conn.create_gc(gc_id, pixmap.0, &CreateGCAux::new());
            let _ = conn.put_image(
                ImageFormat::Z_PIXMAP,
                pixmap.0,
                gc_id,
                width as u16,
                height as u16,
                0,
                0,
                0,
                self.depth,
                &pixels,
            );
            let _ = conn.free_gc(gc_id);
            let _ = conn.flush();
        }

        fn put_bits_to_pixmap_at(
            &self,
            dst: Drawable,
            dst_x: i16,
            dst_y: i16,
            width: u16,
            height: u16,
            stride: usize,
            rows: &[u8],
            bpp: u16,
        ) {
            if dst.0 == 0 || width == 0 || height == 0 {
                return;
            }
            if bpp != 32 {
                return;
            }
            if rows.len() < stride * height as usize {
                return;
            }
            let conn = match self.conn.lock() {
                Ok(c) => c,
                Err(_) => return,
            };

            let row_bytes = width as usize * 4;
            let packed: Vec<u8> = if stride == row_bytes {
                rows[..stride * height as usize].to_vec()
            } else {
                let mut out = vec![0u8; row_bytes * height as usize];
                for row in 0..height as usize {
                    let src = &rows[row * stride..row * stride + row_bytes];
                    out[row * row_bytes..(row + 1) * row_bytes].copy_from_slice(src);
                }
                out
            };

            let gc_id: Gcontext = match conn.generate_id() {
                Ok(id) => id,
                Err(_) => return,
            };
            let _ = conn.create_gc(gc_id, dst.0, &CreateGCAux::new());
            let _ = conn.put_image(
                ImageFormat::Z_PIXMAP,
                dst.0,
                gc_id,
                width,
                height,
                dst_x,
                dst_y,
                0,
                self.depth,
                &packed,
            );
            let _ = conn.free_gc(gc_id);
            let _ = conn.flush();
        }

        fn colorref_to_pixel(&self, colorref: u32) -> u32 {
            let r = colorref & 0xFF;
            let g = (colorref >> 8) & 0xFF;
            let b = (colorref >> 16) & 0xFF;
            0xFF00_0000 | (r << 16) | (g << 8) | b
        }
    }

    // ── Helper: Xft.dpi from RESOURCE_MANAGER ─────────────────────────────────

    fn read_xft_dpi(conn: &Mutex<RustConnection>, root: Window) -> Option<u32> {
        let g = conn.lock().ok()?;
        let reply = g
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

    // ── Event translation helpers (pure) ───────────────────────────────────────

    const X11_MOD1_MASK: u16 = 0x0008;
    const VK_MENU: u32 = 0x12;

    fn win32_key_message(vk: u32, is_press: bool, x11_state: u16) -> u32 {
        let alt_context = (x11_state & X11_MOD1_MASK) != 0 || vk == VK_MENU;
        match (alt_context, is_press) {
            (true, true) => WM_SYSKEYDOWN,
            (true, false) => WM_SYSKEYUP,
            (false, true) => WM_KEYDOWN,
            (false, false) => WM_KEYUP,
        }
    }

    fn key_l_param(x11_state: u16, is_press: bool, is_sys: bool) -> isize {
        let mut low = if is_press { 1 } else { (1 << 30) | (1 << 31) };
        if is_sys {
            low |= 1 << 29;
        }
        ((x11_state as isize) << 16) | low
    }

    fn x11_keycode_to_vk(keycode: u8) -> u32 {
        match keycode {
            9 => 0x1B,
            10 => 0x31,
            11 => 0x32,
            12 => 0x33,
            13 => 0x34,
            14 => 0x35,
            15 => 0x36,
            16 => 0x37,
            17 => 0x38,
            18 => 0x39,
            19 => 0x30,
            20 => 0xBD,
            21 => 0xBB,
            22 => 0x08,
            23 => 0x09,
            24 => 0x51,
            25 => 0x57,
            26 => 0x45,
            27 => 0x52,
            28 => 0x54,
            29 => 0x59,
            30 => 0x55,
            31 => 0x49,
            32 => 0x4F,
            33 => 0x50,
            34 => 0xDB,
            35 => 0xDD,
            36 => 0x0D,
            37 => 0xA2,
            38 => 0x41,
            39 => 0x53,
            40 => 0x44,
            41 => 0x46,
            42 => 0x47,
            43 => 0x48,
            44 => 0x4A,
            45 => 0x4B,
            46 => 0x4C,
            47 => 0xBA,
            48 => 0xDE,
            49 => 0xC0,
            50 => 0xA0,
            51 => 0xDC,
            52 => 0x5A,
            53 => 0x58,
            54 => 0x43,
            55 => 0x56,
            56 => 0x42,
            57 => 0x4E,
            58 => 0x4D,
            59 => 0xBC,
            60 => 0xBE,
            61 => 0xBF,
            62 => 0xA1,
            63 => 0x6A,
            64 => 0xA4,
            65 => 0x20,
            66 => 0x14,
            67 => 0x70,
            68 => 0x71,
            69 => 0x72,
            70 => 0x73,
            71 => 0x74,
            72 => 0x75,
            73 => 0x76,
            74 => 0x77,
            75 => 0x78,
            76 => 0x79,
            77 => 0x90,
            78 => 0x91,
            79 => 0x67,
            80 => 0x68,
            81 => 0x69,
            82 => 0x6D,
            83 => 0x64,
            84 => 0x65,
            85 => 0x66,
            86 => 0x6B,
            87 => 0x61,
            88 => 0x62,
            89 => 0x63,
            90 => 0x60,
            91 => 0x6E,
            95 => 0x7A,
            96 => 0x7B,
            104 => 0x0D,
            105 => 0xA3,
            106 => 0x6F,
            107 => 0x2C,
            108 => 0xA5,
            110 => 0x24,
            111 => 0x26,
            112 => 0x21,
            113 => 0x25,
            114 => 0x27,
            115 => 0x23,
            116 => 0x28,
            117 => 0x22,
            118 => 0x2D,
            119 => 0x2E,
            133 => 0x5B,
            134 => 0x5C,
            135 => 0x5D,
            _ => 0,
        }
    }

    // ── Event translation (method on XcbBackend) ──────────────────────────────

    impl XcbBackend {
        fn translate_event(&self, event: Event) {
            let wm_protocols = self.atoms.WM_PROTOCOLS;
            let wm_delete_window = self.atoms.WM_DELETE_WINDOW;

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
                    let data32 = ev.data.as_data32();
                    let msg_type = ev.type_;
                    let data0 = data32[0];

                    let is_wm_protocols = msg_type == wm_protocols;
                    let is_delete_window = data0 == wm_delete_window;
                    let action = if is_wm_protocols && is_delete_window {
                        "WM_CLOSE"
                    } else if is_wm_protocols {
                        "ignored (WM_PROTOCOLS but data[0] != WM_DELETE_WINDOW)"
                    } else {
                        "ignored (message_type != WM_PROTOCOLS)"
                    };

                    eprintln!(
                        "weave/user32: X11 ClientMessage type={:#x}(WM_PROTOCOLS={}) \
                         data[0]={:#x}(WM_DELETE_WINDOW={}) → {action}",
                        msg_type, is_wm_protocols, data0, is_delete_window,
                    );

                    if is_wm_protocols && is_delete_window {
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

                Event::Expose(ev) if ev.count == 0 => {
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

                    static FIRST_EXPOSE_SEEN: AtomicBool = AtomicBool::new(false);
                    if !FIRST_EXPOSE_SEEN.swap(true, Ordering::SeqCst) {
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

                Event::ConfigureNotify(ConfigureNotifyEvent {
                    window,
                    width,
                    height,
                    ..
                }) => {
                    let hwnd = window::hwnd_for_xcb(window);
                    if hwnd != 0 {
                        window::with_mut(hwnd, |e| {
                            e.width = width as u32;
                            e.height = height as u32;
                        });
                        let l_param = (width as isize) | ((height as isize) << 16);
                        queue::post(MsgEntry {
                            hwnd,
                            message: WM_SIZE,
                            w_param: 0,
                            l_param,
                            time: 0,
                            pt_x: 0,
                            pt_y: 0,
                        });
                    }
                }

                Event::KeyPress(ev) => {
                    if let Some(vk8) = crate::input::keycode_to_vk(ev.detail) {
                        let toggle = if vk8 == 0x14 {
                            Some(crate::input::vk_state(vk8) & 0x01 == 0)
                        } else {
                            None
                        };
                        crate::input::set_vk_down(vk8, true, toggle);
                    }
                    let hwnd = window::hwnd_for_xcb(ev.event);
                    if hwnd != 0 {
                        let vk = x11_keycode_to_vk(ev.detail);
                        let x11_state = u16::from(ev.state);
                        let is_sys = (x11_state & X11_MOD1_MASK) != 0 || vk == VK_MENU;
                        let message = win32_key_message(vk, true, x11_state);
                        let l_param = key_l_param(x11_state, true, is_sys);
                        queue::post(MsgEntry {
                            hwnd,
                            message,
                            w_param: vk as usize,
                            l_param,
                            time: ev.time,
                            pt_x: ev.event_x as i32,
                            pt_y: ev.event_y as i32,
                        });
                    }
                }

                Event::KeyRelease(ev) => {
                    if let Some(vk8) = crate::input::keycode_to_vk(ev.detail) {
                        crate::input::set_vk_down(vk8, false, None);
                    }
                    let hwnd = window::hwnd_for_xcb(ev.event);
                    if hwnd != 0 {
                        let vk = x11_keycode_to_vk(ev.detail);
                        let x11_state = u16::from(ev.state);
                        let is_sys = (x11_state & X11_MOD1_MASK) != 0 || vk == VK_MENU;
                        let message = win32_key_message(vk, false, x11_state);
                        let l_param = key_l_param(x11_state, false, is_sys);
                        queue::post(MsgEntry {
                            hwnd,
                            message,
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

                Event::EnterNotify(ev) => {
                    let hwnd = window::hwnd_for_xcb(ev.event);
                    if hwnd != 0 {
                        crate::api::tme_hover_enter(
                            hwnd,
                            ev.time,
                            ev.event_x as i32,
                            ev.event_y as i32,
                        );
                    }
                }

                Event::MotionNotify(ev) => {
                    let hwnd = window::hwnd_for_xcb(ev.event);
                    if hwnd != 0 {
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
                        if crate::api::tme_hover_check(
                            hwnd,
                            ev.time,
                            ev.event_x as i32,
                            ev.event_y as i32,
                        ) {
                            queue::post(MsgEntry {
                                hwnd,
                                message: WM_MOUSEHOVER,
                                w_param: 0,
                                l_param,
                                time: ev.time,
                                pt_x: ev.event_x as i32,
                                pt_y: ev.event_y as i32,
                            });
                        }
                    }
                }

                Event::LeaveNotify(ev) => {
                    let hwnd = window::hwnd_for_xcb(ev.event);
                    if hwnd != 0 {
                        crate::api::cancel_tme_hover(hwnd);
                        if crate::api::take_tme_leave(hwnd) {
                            queue::post(MsgEntry {
                                hwnd,
                                message: WM_MOUSELEAVE,
                                w_param: 0,
                                l_param: 0,
                                time: ev.time,
                                pt_x: 0,
                                pt_y: 0,
                            });
                        }
                    }
                }

                _ => {}
            }
        }
    }

    // ── Module-level wrapper functions ─────────────────────────────────────────
    //
    // These delegate to the global BACKEND instance so that existing callers
    // (api.rs, dialog.rs, weave-gdi32) keep calling `backend::*()` unchanged.

    pub fn is_available() -> bool {
        BACKEND.get().is_some()
    }

    pub fn screen_size() -> (u16, u16) {
        match BACKEND.get() {
            Some(b) => b.screen_size(),
            None => (1920, 1080),
        }
    }

    pub fn system_dpi() -> u32 {
        match BACKEND.get() {
            Some(b) => b.system_dpi(),
            None => 96,
        }
    }

    pub fn enumerate_monitors() -> Vec<crate::backend_trait::MonitorInfo> {
        match BACKEND.get() {
            Some(b) => b.enumerate_monitors(),
            None => {
                // SDL2 and other apps query monitors during init (before any
                // window is created). Return a default display when the X11
                // backend has not been initialized yet.
                let (sw, sh) = screen_size();
                vec![crate::backend_trait::MonitorInfo {
                    handle: 0,
                    bounds: (0, 0, sw as i32, sh as i32),
                    work_area: (0, 0, sw as i32, sh as i32),
                    is_primary: true,
                }]
            }
        }
    }

    pub fn create_window(
        title: &str,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        visible: bool,
        parent_xcb: u32,
    ) -> u32 {
        let parent = if parent_xcb != 0 {
            Some(WindowHandle(parent_xcb))
        } else {
            None
        };
        match BACKEND.get() {
            Some(b) => match b.create_window(title, x, y, width, height, visible, parent) {
                Ok(h) => h.0,
                Err(e) => {
                    eprintln!("weave/backend: create_window failed: {e}");
                    0
                }
            },
            None => {
                eprintln!("weave/backend: create_window — backend not initialised (no DISPLAY?)");
                0
            }
        }
    }

    pub fn show_window(xcb_id: u32, show: bool) {
        if let Some(b) = BACKEND.get() {
            b.show_window(WindowHandle(xcb_id), show);
        }
    }

    pub fn configure_window(xcb_id: u32, x: i32, y: i32, width: u32, height: u32) {
        if let Some(b) = BACKEND.get() {
            b.configure_window(WindowHandle(xcb_id), x, y, width, height);
        }
    }

    pub fn create_pixmap(parent_drawable: u32, width: u16, height: u16) -> u32 {
        let _ = parent_drawable; // Not passed through trait — XcbBackend uses root.
        match BACKEND.get() {
            Some(b) => match b.create_pixmap(width, height) {
                Ok(p) => p.0,
                Err(_) => 0,
            },
            None => 0,
        }
    }

    pub fn free_pixmap(pid: u32) {
        if let Some(b) = BACKEND.get() {
            b.free_pixmap(PixmapHandle(pid));
        }
    }

    pub fn destroy_window(xcb_id: u32) {
        if let Some(b) = BACKEND.get() {
            b.destroy_window(WindowHandle(xcb_id));
        }
    }

    pub fn set_title(xcb_id: u32, title: &str) {
        if let Some(b) = BACKEND.get() {
            b.set_title(WindowHandle(xcb_id), title);
        }
    }

    pub fn colorref_to_pixel(colorref: u32) -> u32 {
        match BACKEND.get() {
            Some(b) => b.colorref_to_pixel(colorref),
            None => {
                let r = colorref & 0xFF;
                let g = (colorref >> 8) & 0xFF;
                let b_val = (colorref >> 16) & 0xFF;
                0xFF00_0000 | (r << 16) | (g << 8) | b_val
            }
        }
    }

    pub fn draw_line(xcb_id: u32, x1: i16, y1: i16, x2: i16, y2: i16, pixel: u32) {
        if let Some(b) = BACKEND.get() {
            b.draw_line(Drawable(xcb_id), x1, y1, x2, y2, pixel);
        }
    }

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
        if let Some(b) = BACKEND.get() {
            b.copy_area(
                Drawable(src),
                Drawable(dst),
                src_x,
                src_y,
                dst_x,
                dst_y,
                width,
                height,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn copy_area_with_rop(
        src: u32,
        dst: u32,
        src_x: i16,
        src_y: i16,
        dst_x: i16,
        dst_y: i16,
        width: u16,
        height: u16,
        gx_func: u32,
    ) {
        if let Some(b) = BACKEND.get() {
            b.copy_area_with_rop(
                Drawable(src),
                Drawable(dst),
                src_x,
                src_y,
                dst_x,
                dst_y,
                width,
                height,
                gx_func,
            );
        }
    }

    pub fn fill_rect_with_rop(
        xcb_id: u32,
        x: i16,
        y: i16,
        w: u16,
        h: u16,
        gx_func: u32,
        pixel: u32,
    ) {
        if let Some(b) = BACKEND.get() {
            b.fill_rect_with_rop(Drawable(xcb_id), x, y, w, h, gx_func, pixel);
        }
    }

    pub fn draw_filled_rect(xcb_id: u32, x: i16, y: i16, w: u16, h: u16, pixel: u32) {
        if let Some(b) = BACKEND.get() {
            b.draw_filled_rect(Drawable(xcb_id), x, y, w, h, pixel);
        }
    }

    pub fn draw_rect_outline(xcb_id: u32, x: i16, y: i16, w: u16, h: u16, pixel: u32) {
        if let Some(b) = BACKEND.get() {
            b.draw_rect_outline(Drawable(xcb_id), x, y, w, h, pixel);
        }
    }

    pub fn draw_text(xcb_id: u32, x: i16, y: i16, text: &[u8], fg_pixel: u32, bg_pixel: u32) {
        if let Some(b) = BACKEND.get() {
            b.draw_text(Drawable(xcb_id), x, y, text, fg_pixel, bg_pixel);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn draw_text_utf16(
        xcb_id: u32,
        x: i16,
        y: i16,
        text: &[u16],
        px_size: f32,
        fg_pixel: u32,
        bg_pixel: u32,
        font_path: Option<&str>,
    ) {
        if let Some(b) = BACKEND.get() {
            b.draw_text_utf16(
                Drawable(xcb_id),
                x,
                y,
                text,
                px_size,
                fg_pixel,
                bg_pixel,
                font_path,
            );
        }
    }

    pub unsafe fn put_dib_to_pixmap(
        pixmap: u32,
        width: u32,
        height: u32,
        bits_ptr: usize,
        bpp: u16,
    ) {
        if let Some(b) = BACKEND.get() {
            b.put_dib_to_pixmap(PixmapHandle(pixmap), width, height, bits_ptr, bpp);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put_bits_to_pixmap_at(
        drawable: u32,
        dst_x: i16,
        dst_y: i16,
        width: u16,
        height: u16,
        stride: usize,
        rows: &[u8],
        bpp: u16,
    ) {
        if let Some(b) = BACKEND.get() {
            b.put_bits_to_pixmap_at(
                Drawable(drawable),
                dst_x,
                dst_y,
                width,
                height,
                stride,
                rows,
                bpp,
            );
        }
    }

    pub fn poll_event() -> bool {
        match BACKEND.get() {
            Some(b) => b.poll_event(),
            None => false,
        }
    }

    pub fn wait_event() -> bool {
        match BACKEND.get() {
            Some(b) => b.wait_event(),
            None => false,
        }
    }
}

// ── Public GC function constants (mirror X11 `xcb/xproto.h` GX_* values) ─────
// Callers outside this crate (weave-gdi32) pass these to `copy_area_with_rop`
// and `fill_rect_with_rop` so we do not leak x11rb types across the crate
// boundary. Values match the X11 protocol constants exactly.
pub const GX_CLEAR: u32 = 0;
pub const GX_AND: u32 = 1;
pub const GX_COPY: u32 = 3;
pub const GX_XOR: u32 = 6;
pub const GX_OR: u32 = 7;
pub const GX_INVERT: u32 = 10;
pub const GX_COPY_INVERTED: u32 = 12;
pub const GX_SET: u32 = 15;

// ── Platform-specific re-exports ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use inner::{
    colorref_to_pixel, configure_window, copy_area, copy_area_with_rop, create_pixmap,
    create_window, destroy_window, draw_filled_rect, draw_line, draw_rect_outline, draw_text,
    draw_text_utf16, enumerate_monitors, fill_rect_with_rop, free_pixmap, is_available, poll_event,
    put_bits_to_pixmap_at, put_dib_to_pixmap, screen_size, set_title, show_window, system_dpi,
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
pub fn system_dpi() -> u32 {
    96
}

#[cfg(not(target_os = "linux"))]
pub fn enumerate_monitors() -> Vec<crate::backend_trait::MonitorInfo> {
    vec![]
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
#[allow(clippy::too_many_arguments)]
pub fn draw_text_utf16(
    _xcb_id: u32,
    _x: i16,
    _y: i16,
    _text: &[u16],
    _px_size: f32,
    _fg: u32,
    _bg: u32,
    _font_path: Option<&str>,
) {
}

#[cfg(not(target_os = "linux"))]
pub unsafe fn put_dib_to_pixmap(
    _pixmap: u32,
    _width: u32,
    _height: u32,
    _bits_ptr: usize,
    _bpp: u16,
) {
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn put_bits_to_pixmap_at(
    _drawable: u32,
    _dst_x: i16,
    _dst_y: i16,
    _width: u16,
    _height: u16,
    _stride: usize,
    _rows: &[u8],
    _bpp: u16,
) {
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn copy_area_with_rop(
    _src: u32,
    _dst: u32,
    _src_x: i16,
    _src_y: i16,
    _dst_x: i16,
    _dst_y: i16,
    _width: u16,
    _height: u16,
    _gx_func: u32,
) {
}

#[cfg(not(target_os = "linux"))]
pub fn fill_rect_with_rop(
    _xcb_id: u32,
    _x: i16,
    _y: i16,
    _w: u16,
    _h: u16,
    _gx_func: u32,
    _pixel: u32,
) {
}
