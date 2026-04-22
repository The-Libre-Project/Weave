//! Task 16 probe gate — `CreateCompatibleBitmap` now carries a real pixel
//! buffer. Validates:
//!
//!   * `CreateCompatibleBitmap` returns a non-zero HBITMAP whose
//!     `GdiKind::Bitmap` entry has a non-null `bits_ptr` and `bpp == 32`.
//!   * Writing a sentinel DWORD through `bits_ptr` round-trips — the buffer is
//!     CPU-writable and survives `SelectObject` into a memory DC.
//!   * `DeleteObject` returns success without panicking on the reconstructed
//!     boxed slice (Miri/ASAN would flag a bad free; here we just confirm the
//!     happy path).
//!   * Zero-dimension bitmaps return 0 (Wine's explicit NULL-path).
//!
//! This gate deliberately avoids touching `BitBlt`, which requires an X11
//! connection the CI sandbox may not have. The DIB-sync path in `bit_blt`
//! reads the same fields this test validates.

use weave_gdi32::objects::{self, GdiKind};
use weave_gdi32::{create_compatible_bitmap, create_compatible_dc, delete_object, select_object};

#[test]
fn compat_bitmap_has_backing_buffer() {
    let mem_dc = create_compatible_dc(0);
    assert!(mem_dc != 0, "CreateCompatibleDC returned 0");

    let hbm = create_compatible_bitmap(mem_dc, 10, 10);
    assert!(hbm != 0, "CreateCompatibleBitmap returned 0");

    let info: Option<(usize, u16, u32, u32)> = objects::get(hbm, |kind| match kind {
        GdiKind::Bitmap {
            width,
            height,
            bits_ptr,
            bpp,
        } => Some((*bits_ptr, *bpp, *width, *height)),
        _ => None,
    })
    .flatten();
    let (bits_ptr, bpp, w, h) = info.expect("Bitmap kind missing");
    assert_eq!(w, 10);
    assert_eq!(h, 10);
    assert_eq!(bpp, 32);
    assert!(bits_ptr != 0, "bits_ptr is null");

    // Write a sentinel at the first pixel and read it back through a fresh
    // `objects::get` — confirms the buffer is live heap memory, not stack.
    // SAFETY: bits_ptr came from Box::leak of a 10*10*4-byte slice; within
    // those 400 bytes, the first DWORD is writable for the object's lifetime.
    unsafe {
        let p = bits_ptr as *mut u32;
        p.write(0xDEAD_BEEF);
    }

    // Select the bitmap into the memory DC; the DC should track it and not
    // invalidate the buffer.
    let prev = select_object(mem_dc, hbm);
    let _ = prev; // may be 0 — no prior selection.

    let readback = objects::get(hbm, |kind| match kind {
        GdiKind::Bitmap { bits_ptr, .. } => *bits_ptr,
        _ => 0,
    })
    .unwrap_or(0);
    assert_eq!(readback, bits_ptr, "bits_ptr shifted after SelectObject");
    // SAFETY: same buffer as above.
    let sentinel = unsafe { (readback as *const u32).read() };
    assert_eq!(sentinel, 0xDEAD_BEEF, "sentinel did not round-trip");

    // DeleteObject must succeed and drop the boxed slice cleanly.
    assert_eq!(delete_object(hbm), 1, "DeleteObject returned failure");
    assert_eq!(delete_object(mem_dc), 1, "DeleteObject(mem_dc) failed");
}

#[test]
fn compat_bitmap_zero_dim_returns_null() {
    // Wine ref: dlls/win32u/bitmap.c::NtGdiCreateCompatibleBitmap —
    // `if (!width || !height) return 0;`
    let mem_dc = create_compatible_dc(0);
    assert_eq!(create_compatible_bitmap(mem_dc, 0, 10), 0);
    assert_eq!(create_compatible_bitmap(mem_dc, 10, 0), 0);
    assert_eq!(create_compatible_bitmap(mem_dc, 0, 0), 0);
    let _ = delete_object(mem_dc);
}
