//! Abstract `WindowBackend` trait for the display/windowing system.
//!
//! # Design
//!
//! The entire window system (user32 windowing, GDI drawing) currently calls
//! into X11/xcb-specific module functions in [`crate::backend`]. This trait
//! captures every operation the backend performs at the abstraction level
//! Win32 needs — not at the level of xcb protocol calls.
//!
//! A future Wayland backend would implement this trait without touching any
//! of the user32/GDI business logic.
//!
//! # Handle types
//!
//! `WindowHandle`, `PixmapHandle`, and `Drawable` are newtype wrappers over
//! `u32`. On X11 they hold the X11 drawable ID directly. On Wayland they
//! would be indices into a surface table or raw `wl_surface*` pointers cast
//! to `u32` (via a handle table). The `u32` width keeps the trait compatible
//! with existing code paths that store `u32` in WindowEntry and DcState.

use std::fmt;

// ── Handle types ───────────────────────────────────────────────────────────────

/// Opaque handle to a native window (e.g. X11 Window ID, or Wayland surface
/// index).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WindowHandle(pub u32);

/// Opaque handle to a native off-screen pixmap / surface (e.g. X11 Pixmap).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PixmapHandle(pub u32);

/// Opaque handle to a drawable — something that can be used as a rendering
/// target. On X11 this is either a `Window` or a `Pixmap` (both are X11
/// drawables). On Wayland this could be a `wl_surface` or an off-screen buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Drawable(pub u32);

impl From<WindowHandle> for Drawable {
    fn from(w: WindowHandle) -> Self {
        Drawable(w.0)
    }
}

impl From<PixmapHandle> for Drawable {
    fn from(p: PixmapHandle) -> Self {
        Drawable(p.0)
    }
}

// ── Error type ─────────────────────────────────────────────────────────────────

/// Errors that can occur in window backend operations.
#[derive(Debug, Clone)]
pub enum BackendError {
    /// No display server is available (no DISPLAY, no Wayland socket, etc.).
    NotAvailable,
    /// Connection-level error (failed to open display, protocol error).
    ConnectionError(String),
    /// Window creation or manipulation error.
    WindowError(String),
    /// Pixmap or off-screen surface error.
    PixmapError(String),
    /// Drawing or rendering error.
    DrawError(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::NotAvailable => write!(f, "window backend not available"),
            BackendError::ConnectionError(e) => write!(f, "backend connection error: {e}"),
            BackendError::WindowError(e) => write!(f, "backend window error: {e}"),
            BackendError::PixmapError(e) => write!(f, "backend pixmap error: {e}"),
            BackendError::DrawError(e) => write!(f, "backend draw error: {e}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Convenience alias for `Result<T, BackendError>`.
pub type BackendResult<T> = Result<T, BackendError>;

// ── Trait ──────────────────────────────────────────────────────────────────────

/// Abstract window backend.
///
/// Every method takes `&self` — the backend owns its mutable state internally
/// (typically behind a `Mutex` or `RefCell`). This keeps the trait object-safe
/// and allows a single `Box<dyn WindowBackend>` to be shared across the
/// process.
///
/// # Object safety
///
/// This trait is designed to be object-safe: no generic methods, no
/// `Self: Sized` bounds, all methods take `&self`. It can be stored as
/// `Box<dyn WindowBackend>`.
#[allow(clippy::too_many_arguments)]
pub trait WindowBackend: Send + Sync {
    // ── Connection / global ──────────────────────────────────────────────────

    /// Returns `true` if a display server connection is available.
    fn is_available(&self) -> bool;

    /// Screen dimensions in pixels, or a sensible default (1920×1080) if
    /// no display is available.
    fn screen_size(&self) -> (u16, u16);

    /// System DPI value. Falls back to 96 when no display or no DPI info.
    fn system_dpi(&self) -> u32;

    // ── Window lifecycle ─────────────────────────────────────────────────────

    /// Create a native window.
    ///
    /// `parent` — optional native window handle of the Win32 parent window.
    /// `None` means top-level (parented to root/compositor).
    fn create_window(
        &self,
        title: &str,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        visible: bool,
        parent: Option<WindowHandle>,
    ) -> BackendResult<WindowHandle>;

    /// Destroy a native window.
    fn destroy_window(&self, window: WindowHandle);

    /// Show or hide a window.
    fn show_window(&self, window: WindowHandle, show: bool);

    /// Move and/or resize a window. Zero-size windows are clamped to 1×1.
    fn configure_window(&self, window: WindowHandle, x: i32, y: i32, width: u32, height: u32);

    /// Update the title bar / caption text.
    fn set_title(&self, window: WindowHandle, title: &str);

    // ── Event polling ────────────────────────────────────────────────────────

    /// Poll for one display event without blocking.
    ///
    /// Returns `true` if an event was processed and queued into the Win32
    /// message queue, `false` if none was pending.
    fn poll_event(&self) -> bool;

    /// Block until a display event arrives or the message-queue wake pipe
    /// fires.
    ///
    /// Returns `true` on any event/wake/timeout, `false` on unrecoverable
    /// connection error.
    fn wait_event(&self) -> bool;

    // ── Pixmap / off-screen surface ──────────────────────────────────────────

    /// Allocate an off-screen pixmap of the given dimensions.
    fn create_pixmap(&self, width: u16, height: u16) -> BackendResult<PixmapHandle>;

    /// Free an off-screen pixmap.
    fn free_pixmap(&self, pixmap: PixmapHandle);

    // ── Drawing (accept any Drawable) ────────────────────────────────────────

    /// Draw a single-pixel line.
    fn draw_line(&self, dst: Drawable, x1: i16, y1: i16, x2: i16, y2: i16, pixel: u32);

    /// Copy a rectangle of pixels from one drawable to another (SRCCOPY).
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
    );

    /// Copy a rectangle with an explicit raster operation (GX function).
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
    );

    /// Fill a rectangle using a raster operation other than GXcopy.
    fn fill_rect_with_rop(
        &self,
        dst: Drawable,
        x: i16,
        y: i16,
        w: u16,
        h: u16,
        gx_func: u32,
        pixel: u32,
    );

    /// Fill a solid rectangle.
    fn draw_filled_rect(&self, dst: Drawable, x: i16, y: i16, w: u16, h: u16, pixel: u32);

    /// Draw a hollow rectangle outline.
    fn draw_rect_outline(&self, dst: Drawable, x: i16, y: i16, w: u16, h: u16, pixel: u32);

    /// Draw Latin-1 text using a core bitmap font (legacy path).
    fn draw_text(&self, dst: Drawable, x: i16, y: i16, text: &[u8], fg_pixel: u32, bg_pixel: u32);

    /// Draw UTF-16 text with anti-aliased TrueType rendering.
    fn draw_text_utf16(
        &self,
        dst: Drawable,
        x: i16,
        y: i16,
        text: &[u16],
        px_size: f32,
        fg_pixel: u32,
        bg_pixel: u32,
    );

    /// Upload DIB pixel data from a heap buffer to a pixmap.
    ///
    /// # Safety
    /// `bits_ptr` must be a valid pointer to at least `stride × height` bytes.
    unsafe fn put_dib_to_pixmap(
        &self,
        pixmap: PixmapHandle,
        width: u32,
        height: u32,
        bits_ptr: usize,
        bpp: u16,
    );

    /// Upload a pixel buffer to a sub-rectangle of a drawable.
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
    );

    // ── Colour conversion ────────────────────────────────────────────────────

    /// Convert a Win32 COLORREF (0x00BBGGRR) to a native pixel value
    /// (0x00RRGGBB on X11).
    fn colorref_to_pixel(&self, colorref: u32) -> u32;
}

// ── XCB backend implementation (thin delegation to existing module) ───────────

/// X11/xcb backend.
///
/// Delegates every method to the existing module-level functions in
/// [`crate::backend`]. This is the production backend on Linux.
pub struct XcbBackend;

#[allow(clippy::too_many_arguments)]
impl WindowBackend for XcbBackend {
    fn is_available(&self) -> bool {
        crate::backend::is_available()
    }

    fn screen_size(&self) -> (u16, u16) {
        crate::backend::screen_size()
    }

    fn system_dpi(&self) -> u32 {
        crate::backend::system_dpi()
    }

    fn create_window(
        &self,
        title: &str,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        visible: bool,
        parent: Option<WindowHandle>,
    ) -> BackendResult<WindowHandle> {
        let parent_id = parent.map(|w| w.0).unwrap_or(0);
        let id = crate::backend::create_window(title, x, y, width, height, visible, parent_id);
        if id == 0 {
            Err(BackendError::NotAvailable)
        } else {
            Ok(WindowHandle(id))
        }
    }

    fn destroy_window(&self, window: WindowHandle) {
        crate::backend::destroy_window(window.0);
    }

    fn show_window(&self, window: WindowHandle, show: bool) {
        crate::backend::show_window(window.0, show);
    }

    fn configure_window(&self, window: WindowHandle, x: i32, y: i32, width: u32, height: u32) {
        crate::backend::configure_window(window.0, x, y, width, height);
    }

    fn set_title(&self, window: WindowHandle, title: &str) {
        crate::backend::set_title(window.0, title);
    }

    fn poll_event(&self) -> bool {
        crate::backend::poll_event()
    }

    fn wait_event(&self) -> bool {
        crate::backend::wait_event()
    }

    fn create_pixmap(&self, width: u16, height: u16) -> BackendResult<PixmapHandle> {
        let id = crate::backend::create_pixmap(0, width, height);
        if id == 0 {
            Err(BackendError::PixmapError("create_pixmap returned 0".into()))
        } else {
            Ok(PixmapHandle(id))
        }
    }

    fn free_pixmap(&self, pixmap: PixmapHandle) {
        crate::backend::free_pixmap(pixmap.0);
    }

    fn draw_line(&self, dst: Drawable, x1: i16, y1: i16, x2: i16, y2: i16, pixel: u32) {
        crate::backend::draw_line(dst.0, x1, y1, x2, y2, pixel);
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
        crate::backend::copy_area(src.0, dst.0, src_x, src_y, dst_x, dst_y, width, height);
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
        crate::backend::copy_area_with_rop(
            src.0, dst.0, src_x, src_y, dst_x, dst_y, width, height, gx_func,
        );
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
        crate::backend::fill_rect_with_rop(dst.0, x, y, w, h, gx_func, pixel);
    }

    fn draw_filled_rect(&self, dst: Drawable, x: i16, y: i16, w: u16, h: u16, pixel: u32) {
        crate::backend::draw_filled_rect(dst.0, x, y, w, h, pixel);
    }

    fn draw_rect_outline(&self, dst: Drawable, x: i16, y: i16, w: u16, h: u16, pixel: u32) {
        crate::backend::draw_rect_outline(dst.0, x, y, w, h, pixel);
    }

    fn draw_text(&self, dst: Drawable, x: i16, y: i16, text: &[u8], fg_pixel: u32, bg_pixel: u32) {
        crate::backend::draw_text(dst.0, x, y, text, fg_pixel, bg_pixel);
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
    ) {
        crate::backend::draw_text_utf16(dst.0, x, y, text, px_size, fg_pixel, bg_pixel);
    }

    unsafe fn put_dib_to_pixmap(
        &self,
        pixmap: PixmapHandle,
        width: u32,
        height: u32,
        bits_ptr: usize,
        bpp: u16,
    ) {
        crate::backend::put_dib_to_pixmap(pixmap.0, width, height, bits_ptr, bpp);
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
        crate::backend::put_bits_to_pixmap_at(dst.0, dst_x, dst_y, width, height, stride, rows, bpp);
    }

    fn colorref_to_pixel(&self, colorref: u32) -> u32 {
        crate::backend::colorref_to_pixel(colorref)
    }
}

/// Return the default backend for the current platform.
///
/// On Linux this returns `XcbBackend`. On other platforms (macOS dev builds)
/// the backend is not available and `is_available()` returns `false`.
pub fn default_backend() -> Box<dyn WindowBackend> {
    Box::new(XcbBackend)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the trait is object-safe by accepting a trait object reference.
    /// If the trait had a non-object-safe method, this would fail to compile.
    fn _assert_object_safe(_: &dyn WindowBackend) {}

    #[test]
    fn window_backend_is_object_safe() {
        _assert_object_safe(&XcbBackend);
    }

    #[test]
    fn handle_conversions() {
        let w = WindowHandle(42);
        let p = PixmapHandle(99);

        // WindowHandle and PixmapHandle convert into Drawable.
        let d1: Drawable = w.into();
        let d2: Drawable = p.into();
        assert_eq!(d1.0, 42);
        assert_eq!(d2.0, 99);
    }

    #[test]
    fn default_backend_returns_xcb_backend() {
        let backend = default_backend();
        // Just verify it's a valid trait object.
        let _ = backend.is_available();
    }

    #[test]
    fn backend_error_display() {
        let err = BackendError::NotAvailable;
        assert!(!err.to_string().is_empty());

        let err = BackendError::WindowError("test".into());
        assert_eq!(err.to_string(), "backend window error: test");
    }
}
