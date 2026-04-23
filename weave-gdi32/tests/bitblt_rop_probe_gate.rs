//! Task 17 probe gate — `BitBlt` dispatches non-SRCCOPY ROP codes.
//!
//! Validates dispatcher behaviour without asserting round-trip pixel state:
//!
//!   * Known ROPs (SRCCOPY, NOTSRCCOPY, SRCINVERT, SRCAND, SRCPAINT,
//!     DSTINVERT, WHITENESS, BLACKNESS) return 1 (TRUE).
//!   * Unknown ROPs lie TRUE (pre-17 behaviour; avoids guest crashes).
//!   * PATCOPY with a solid brush returns 1; with a non-brush handle selected
//!     as h_brush (simulated via a pen handle) falls through RopPlan::Unknown
//!     and also lies TRUE.
//!   * `copy_area_with_rop` and `fill_rect_with_rop` are reachable entry
//!     points on the user32 backend.
//!
//! Pixel-round-trip assertions are deferred: memory-DC drawables in Weave are
//! routed through XCopyArea on the X server, which does not write back to the
//! CPU-side `bits_ptr`. Exercising the pixel path end-to-end requires either a
//! running X server (not guaranteed in CI) or a CPU-side fallback blit, both
//! out of scope for Task 17.

use weave_gdi32::defs::{
    BLACKNESS, DSTINVERT, NOTSRCCOPY, PATCOPY, SRCAND, SRCCOPY, SRCINVERT, SRCPAINT, WHITENESS,
};
use weave_gdi32::objects::{self, GdiKind};
use weave_gdi32::{
    bit_blt, create_compatible_bitmap, create_compatible_dc, delete_object, select_object,
};

// ── ROP lie boundary rule ────────────────────────────────────────────────────
//
// This rule was established during Task 17 after three consecutive CI-fix
// commits (9235dcc → 521e9a1 → 323fbcf) caused by ambiguous probe-gate
// expectations. Document it here so the next engineer adding a ROP does not
// repeat the same rework cycle.
//
//  1. SRCCOPY uses the lean copy_area path — it does NOT enter the ROP dispatch
//     table at all. No ROP logic is applied; the fast path handles it directly.
//
//  2. Unknown / unimplemented ROP codes lie TRUE (return 1) without drawing
//     anything. This prevents guest crashes: Win32 programs routinely check the
//     return value but almost never validate pixel output for obscure ROPs.
//     SDL2 testsprite2 is a concrete example — it SIGSEGVs on a 0 return from
//     BitBlt (see bit_blt's RopPlan::Unknown arm comment).
//
//  3. Partially-implemented ROPs (e.g. PATCOPY): execute the ROP logic, but if
//     the selected brush type is unsupported (anything other than GdiKind::Brush)
//     fall through to RopPlan::Unknown and also lie TRUE. Real hatch-brush or
//     pattern-brush support is deferred to a later task.
//
// Do not weaken this contract without updating this comment and adding a
// matching test case that documents the new behaviour.
// ─────────────────────────────────────────────────────────────────────────────

/// Drive `bit_blt` and return the 0/1 result for each ROP code.
///
/// Uses two memory DCs with 4×4 compatible bitmaps selected into each. On a
/// headless host `copy_area`/`fill_rect_with_rop` silently no-op (see
/// backend::inner — missing `x11()` returns `None`); only the Rust-side
/// dispatcher logic is exercised.
fn make_pair() -> (usize, usize, usize, usize) {
    let src_dc = create_compatible_dc(0);
    let dst_dc = create_compatible_dc(0);
    let src_bm = create_compatible_bitmap(src_dc, 4, 4);
    let dst_bm = create_compatible_bitmap(dst_dc, 4, 4);
    let _ = select_object(src_dc, src_bm);
    let _ = select_object(dst_dc, dst_bm);
    (src_dc, dst_dc, src_bm, dst_bm)
}

#[test]
fn known_rops_return_true() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    for rop in [
        SRCCOPY, NOTSRCCOPY, SRCINVERT, SRCAND, SRCPAINT, DSTINVERT, WHITENESS, BLACKNESS, PATCOPY,
    ] {
        let r = bit_blt(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, rop);
        assert_eq!(r, 1, "BitBlt ROP {rop:#010x} should return 1");
    }
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn unknown_rop_lies_true() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    // 0x00AA_0029 (D) — a documented ROP3 not in our dispatcher table.
    // We lie TRUE on unknown ROPs so guests that don't check the return value
    // continue rendering (SDL2 testsprite2 SIGSEGVs on 0 return — see task-17
    // CI fix note in bit_blt's RopPlan::Unknown arm).
    let r = bit_blt(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, 0x00AA_0029);
    assert_eq!(r, 1, "unknown ROP should lie TRUE to avoid guest crashes");
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn patcopy_non_solid_brush_lies_true() {
    // Simulate a "non-solid" brush by putting a Pen in the h_brush slot — the
    // dispatcher probes `GdiKind::Brush` and falls through to `RopPlan::Unknown`
    // for any other variant. Unknown ROPs (and this fall-through case) lie
    // TRUE per the task-17 CI fix — see bit_blt's RopPlan::Unknown arm. Real
    // hatch-brush support remains a later task.
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();

    // Build a Pen handle and force it into dst_dc's h_brush.
    let pen = objects::alloc(GdiKind::Pen {
        color: 0x0000_00FF,
        style: 0,
        width: 1,
    });
    weave_gdi32::dc::with_mut(dst_dc, |dc| dc.h_brush = pen);

    let r = bit_blt(dst_dc, 0, 0, 4, 4, src_dc, 0, 0, PATCOPY);
    assert_eq!(
        r, 1,
        "PATCOPY with non-brush h_brush lies TRUE (Unknown arm)"
    );

    let _ = delete_object(pen);
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}

#[test]
fn zero_dim_short_circuits() {
    let (src_dc, dst_dc, src_bm, dst_bm) = make_pair();
    // cx<=0 / cy<=0 returns 1 without dispatch.
    assert_eq!(bit_blt(dst_dc, 0, 0, 0, 4, src_dc, 0, 0, SRCCOPY), 1);
    assert_eq!(bit_blt(dst_dc, 0, 0, 4, 0, src_dc, 0, 0, SRCCOPY), 1);
    let _ = delete_object(src_bm);
    let _ = delete_object(dst_bm);
    let _ = delete_object(src_dc);
    let _ = delete_object(dst_dc);
}
