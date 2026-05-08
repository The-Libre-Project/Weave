//! Probe gate for `GetIconInfo` — validates the ICONINFO fill contract.
//!
//! Verifies:
//!   1. NULL hicon or NULL piconinfo returns FALSE.
//!   2. Valid HICON returns TRUE with fIcon=1, non-null hbmMask/hbmColor.
//!   3. Cursor HICON sets fIcon=0.
//!   4. struct size is 32 bytes on x64 (Win64 layout invariant).

use std::mem::MaybeUninit;
use weave_user32::api::get_icon_info;
use weave_user32::defs::IconInfo;
use weave_user32::image_handles::{insert, ImageEntry, ImageKind};

fn make_icon(kind: ImageKind) -> usize {
    insert(
        ImageEntry {
            kind,
            data_ptr: 0x1000,
            data_size: 128,
            width: 32,
            height: 32,
            bpp: 32,
            shared: false,
        },
        None,
    )
}

#[test]
fn struct_size_is_32() {
    assert_eq!(
        std::mem::size_of::<IconInfo>(),
        32,
        "ICONINFO must be 32 bytes on x64"
    );
}

#[test]
fn null_hicon_returns_false() {
    let mut ii: MaybeUninit<IconInfo> = MaybeUninit::zeroed();
    let ret = unsafe { get_icon_info(0, ii.as_mut_ptr() as *mut u8) };
    assert_eq!(ret, 0, "NULL hicon must return FALSE");
}

#[test]
fn null_piconinfo_returns_false() {
    let hicon = make_icon(ImageKind::Icon);
    let ret = unsafe { get_icon_info(hicon, std::ptr::null_mut()) };
    assert_eq!(ret, 0, "NULL piconinfo must return FALSE");
}

#[test]
fn icon_handle_fills_iconinfo() {
    let hicon = make_icon(ImageKind::Icon);
    let mut ii: MaybeUninit<IconInfo> = MaybeUninit::zeroed();
    let ret = unsafe { get_icon_info(hicon, ii.as_mut_ptr() as *mut u8) };
    let ii = unsafe { ii.assume_init() };
    assert_eq!(ret, 1, "valid HICON must return TRUE");
    assert_eq!(ii.f_icon, 1, "icon kind must set fIcon=TRUE");
    assert_ne!(ii.hbm_mask, 0, "hbmMask must be non-zero");
    assert_ne!(ii.hbm_color, 0, "hbmColor must be non-zero");
    assert_ne!(
        ii.hbm_mask, ii.hbm_color,
        "hbmMask and hbmColor must be distinct"
    );
}

#[test]
fn cursor_handle_sets_f_icon_false() {
    let hcursor = make_icon(ImageKind::Cursor);
    let mut ii: MaybeUninit<IconInfo> = MaybeUninit::zeroed();
    let ret = unsafe { get_icon_info(hcursor, ii.as_mut_ptr() as *mut u8) };
    let ii = unsafe { ii.assume_init() };
    assert_eq!(ret, 1, "valid HCURSOR must return TRUE");
    assert_eq!(ii.f_icon, 0, "cursor kind must set fIcon=FALSE");
}

#[test]
fn unknown_handle_returns_true_with_icon_default() {
    // Non-null handle not in the table — unknown icon; should return TRUE with icon defaults.
    let fake_hicon: usize = 0xCAFE_BABE;
    let mut ii: MaybeUninit<IconInfo> = MaybeUninit::zeroed();
    let ret = unsafe { get_icon_info(fake_hicon, ii.as_mut_ptr() as *mut u8) };
    let ii = unsafe { ii.assume_init() };
    assert_eq!(ret, 1, "unknown non-null HICON must return TRUE");
    assert_eq!(ii.f_icon, 1, "unknown handle defaults to fIcon=TRUE");
    assert_ne!(ii.hbm_mask, 0, "hbmMask must be non-zero");
}
