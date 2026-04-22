//! Task 22 probe gate — `GradientFill` implements RECT_H and RECT_V
//! linear interpolation on a 32bpp memory-DC dest. TRIANGLE mode is
//! deferred and must return FALSE.
//!
//! Wine interpolation per X11DRV_GradientFill (graphics.c:1519):
//!   channel = (v0*(d-i) + v1*i) / d / 256
//! where d = dx (RECT_H) or dy (RECT_V), i walks 0..d. Colour channels are
//! 16-bit (0..=0xFF00), scaled by /256 to land in 0..=255. That means the
//! low endpoint is exactly v0 and the high endpoint is strictly less than
//! v1 — the last sample at i=d-1 gets `(v0 + v1*(d-1))/d/256`.
//!
//! Covered:
//!   * RECT_H 8x8: left column pure v0 (red), right column dominated by v1
//!     (blue channel > red channel), alpha forced to 0xFF.
//!   * RECT_V 8x8: same pattern along the y axis.
//!   * TRIANGLE mode → FALSE.
//!   * Out-of-bounds vertex index → FALSE, no panic.
//!   * Null pVertex / pMesh → FALSE, no panic.
//!   * Zero-area rect → FALSE or no change (no panic).

use weave_gdi32::{
    create_compatible_bitmap, create_compatible_dc, delete_object, gradient_fill, select_object,
};

/// Memory DC + 32bpp DDB of the given size. Returns (hdc, hbm, bits_ptr).
fn make_mem_dc(w: i32, h: i32) -> (usize, usize, *mut u8) {
    let hdc = create_compatible_dc(0);
    let hbm = create_compatible_bitmap(hdc, w, h);
    let _ = select_object(hdc, hbm);
    let bits_ptr = weave_gdi32::objects::get(hbm, |k| match k {
        weave_gdi32::objects::GdiKind::Bitmap { bits_ptr, .. }
        | weave_gdi32::objects::GdiKind::DibSection { bits_ptr, .. } => Some(*bits_ptr),
        _ => None,
    })
    .flatten()
    .unwrap() as *mut u8;
    (hdc, hbm, bits_ptr)
}

/// Pack a TRIVERTEX (16 bytes): x(i32) y(i32) R(u16) G(u16) B(u16) A(u16).
fn trivertex(x: i32, y: i32, r: u16, g: u16, b: u16, a: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&x.to_le_bytes());
    buf[4..8].copy_from_slice(&y.to_le_bytes());
    buf[8..10].copy_from_slice(&r.to_le_bytes());
    buf[10..12].copy_from_slice(&g.to_le_bytes());
    buf[12..14].copy_from_slice(&b.to_le_bytes());
    buf[14..16].copy_from_slice(&a.to_le_bytes());
    buf
}

/// Pack a GRADIENT_RECT (8 bytes): UpperLeft(u32) LowerRight(u32).
fn gradient_rect(ul: u32, lr: u32) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&ul.to_le_bytes());
    buf[4..8].copy_from_slice(&lr.to_le_bytes());
    buf
}

fn read_bgra(ptr: *const u8, idx: usize) -> (u8, u8, u8, u8) {
    unsafe {
        (
            *ptr.add(idx * 4),
            *ptr.add(idx * 4 + 1),
            *ptr.add(idx * 4 + 2),
            *ptr.add(idx * 4 + 3),
        )
    }
}

fn fill_black(ptr: *mut u8, w: i32, h: i32) {
    let n = (w * h) as usize;
    for i in 0..n {
        unsafe {
            *ptr.add(i * 4) = 0;
            *ptr.add(i * 4 + 1) = 0;
            *ptr.add(i * 4 + 2) = 0;
            *ptr.add(i * 4 + 3) = 0;
        }
    }
}

#[test]
fn rect_h_interpolates_red_to_blue() {
    let (hdc, hbm, bits) = make_mem_dc(8, 8);
    fill_black(bits, 8, 8);

    // v0 pure red at (0,0), v1 pure blue at (8,8). RECT_H references both.
    let mut verts = Vec::with_capacity(32);
    verts.extend_from_slice(&trivertex(0, 0, 0xFF00, 0x0000, 0x0000, 0xFF00));
    verts.extend_from_slice(&trivertex(8, 8, 0x0000, 0x0000, 0xFF00, 0xFF00));
    let mesh = gradient_rect(0, 1);

    let r = unsafe { gradient_fill(hdc, verts.as_ptr(), 2, mesh.as_ptr(), 1, 0) };
    assert_eq!(r, 1, "GradientFill RECT_H should return TRUE");

    // Left column (x=0): pure v0 (red).
    let (b, g, r_, a) = read_bgra(bits as *const u8, 0);
    assert_eq!(
        (b, g, r_, a),
        (0x00, 0x00, 0xFF, 0xFF),
        "left column must be pure red"
    );

    // Right column (x=7, dx=8, i=7): B channel dominates R channel.
    let (b, _g, r_, a) = read_bgra(bits as *const u8, 7);
    assert!(b > r_, "x=7: blue ({b}) must dominate red ({r_})");
    assert!(b > 0xC0, "x=7: blue ({b}) must be near saturated");
    assert_eq!(a, 0xFF, "alpha forced to 0xFF on fill");

    // Middle column (x=4): both R and B contribute (neither zero).
    let (b, _g, r_, _a) = read_bgra(bits as *const u8, 4);
    assert!(r_ > 0 && b > 0, "mid column must mix both endpoints");

    let _ = delete_object(hbm);
    let _ = delete_object(hdc);
}

#[test]
fn rect_v_interpolates_red_to_blue() {
    let (hdc, hbm, bits) = make_mem_dc(8, 8);
    fill_black(bits, 8, 8);

    let mut verts = Vec::with_capacity(32);
    verts.extend_from_slice(&trivertex(0, 0, 0xFF00, 0x0000, 0x0000, 0xFF00));
    verts.extend_from_slice(&trivertex(8, 8, 0x0000, 0x0000, 0xFF00, 0xFF00));
    let mesh = gradient_rect(0, 1);

    // Mode 1 = GRADIENT_FILL_RECT_V.
    let r = unsafe { gradient_fill(hdc, verts.as_ptr(), 2, mesh.as_ptr(), 1, 1) };
    assert_eq!(r, 1, "GradientFill RECT_V should return TRUE");

    // Top row (y=0): pure v0 (red). Index = y*w + x = 0.
    let (b, g, r_, a) = read_bgra(bits as *const u8, 0);
    assert_eq!(
        (b, g, r_, a),
        (0x00, 0x00, 0xFF, 0xFF),
        "top row must be pure red"
    );

    // Bottom row (y=7): blue dominates. Index = 7*8 = 56.
    let (b, _g, r_, a) = read_bgra(bits as *const u8, 56);
    assert!(b > r_, "y=7: blue ({b}) must dominate red ({r_})");
    assert!(b > 0xC0, "y=7: blue ({b}) must be near saturated");
    assert_eq!(a, 0xFF, "alpha forced to 0xFF on fill");

    let _ = delete_object(hbm);
    let _ = delete_object(hdc);
}

#[test]
fn triangle_mode_returns_false() {
    let (hdc, hbm, _bits) = make_mem_dc(8, 8);
    let mut verts = Vec::with_capacity(48);
    verts.extend_from_slice(&trivertex(0, 0, 0xFF00, 0, 0, 0xFF00));
    verts.extend_from_slice(&trivertex(8, 0, 0, 0xFF00, 0, 0xFF00));
    verts.extend_from_slice(&trivertex(4, 8, 0, 0, 0xFF00, 0xFF00));
    // GRADIENT_TRIANGLE is 12 bytes of three u32 indices.
    let mut mesh = Vec::with_capacity(12);
    mesh.extend_from_slice(&0u32.to_le_bytes());
    mesh.extend_from_slice(&1u32.to_le_bytes());
    mesh.extend_from_slice(&2u32.to_le_bytes());
    let r = unsafe { gradient_fill(hdc, verts.as_ptr(), 3, mesh.as_ptr(), 1, 2) };
    assert_eq!(r, 0, "TRIANGLE mode not yet supported → FALSE");
    let _ = delete_object(hbm);
    let _ = delete_object(hdc);
}

#[test]
fn out_of_bounds_vertex_index_returns_false() {
    let (hdc, hbm, _bits) = make_mem_dc(8, 8);
    let mut verts = Vec::with_capacity(32);
    verts.extend_from_slice(&trivertex(0, 0, 0xFF00, 0, 0, 0xFF00));
    verts.extend_from_slice(&trivertex(8, 8, 0, 0, 0xFF00, 0xFF00));
    // Index 5 is past nVertex=2.
    let mesh = gradient_rect(0, 5);
    let r = unsafe { gradient_fill(hdc, verts.as_ptr(), 2, mesh.as_ptr(), 1, 0) };
    assert_eq!(r, 0, "out-of-bounds vertex index must return FALSE");
    let _ = delete_object(hbm);
    let _ = delete_object(hdc);
}

#[test]
fn null_pointers_return_false() {
    let (hdc, hbm, _bits) = make_mem_dc(8, 8);
    let mesh = gradient_rect(0, 1);
    let r = unsafe { gradient_fill(hdc, std::ptr::null(), 2, mesh.as_ptr(), 1, 0) };
    assert_eq!(r, 0, "null pVertex → FALSE");

    let mut verts = Vec::with_capacity(32);
    verts.extend_from_slice(&trivertex(0, 0, 0xFF00, 0, 0, 0xFF00));
    verts.extend_from_slice(&trivertex(8, 8, 0, 0, 0xFF00, 0xFF00));
    let r = unsafe { gradient_fill(hdc, verts.as_ptr(), 2, std::ptr::null(), 1, 0) };
    assert_eq!(r, 0, "null pMesh → FALSE");

    // Zero counts also reject.
    let r = unsafe { gradient_fill(hdc, verts.as_ptr(), 0, mesh.as_ptr(), 1, 0) };
    assert_eq!(r, 0, "nVertex==0 → FALSE");
    let r = unsafe { gradient_fill(hdc, verts.as_ptr(), 2, mesh.as_ptr(), 0, 0) };
    assert_eq!(r, 0, "nMesh==0 → FALSE");

    let _ = delete_object(hbm);
    let _ = delete_object(hdc);
}

#[test]
fn zero_area_rect_does_not_panic() {
    let (hdc, hbm, bits) = make_mem_dc(8, 8);
    fill_black(bits, 8, 8);
    // Both vertices at the same point → dx=0, dy=0.
    let mut verts = Vec::with_capacity(32);
    verts.extend_from_slice(&trivertex(3, 3, 0xFF00, 0, 0, 0xFF00));
    verts.extend_from_slice(&trivertex(3, 3, 0, 0, 0xFF00, 0xFF00));
    let mesh = gradient_rect(0, 1);
    // Wine graphics.c silently skips dx==0 rects without returning FALSE —
    // the function still succeeds, just paints nothing. We treat that as
    // TRUE-with-no-op also, but the test only pins the no-panic contract:
    // dest must remain untouched.
    let _ = unsafe { gradient_fill(hdc, verts.as_ptr(), 2, mesh.as_ptr(), 1, 0) };
    // Every pixel still black.
    for i in 0..64 {
        let (b, g, r, a) = read_bgra(bits as *const u8, i);
        assert_eq!(
            (b, g, r, a),
            (0, 0, 0, 0),
            "zero-area rect must not paint pixel {i}"
        );
    }
    let _ = delete_object(hbm);
    let _ = delete_object(hdc);
}
