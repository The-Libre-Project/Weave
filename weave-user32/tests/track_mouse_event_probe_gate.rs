//! Probe gate for `TrackMouseEvent` — validates TME_LEAVE subscription, TME_CANCEL,
//! and TME_QUERY against the tracking table, and struct size/alignment contract.
//!
//! Does NOT test WM_MOUSELEAVE injection (requires XCB LeaveNotify, i.e. a real
//! display). The gate pins the tracking-table contract that the backend relies on.

use std::mem::MaybeUninit;
use weave_user32::api::{cancel_tme_leave, register_tme_leave, take_tme_leave, track_mouse_event};
use weave_user32::defs::{TrackMouseEventStruct, TME_CANCEL, TME_LEAVE, TME_QUERY};

const FAKE_HWND: usize = 0xDEAD_BEEF;

fn make_tme(flags: u32, hwnd: usize) -> TrackMouseEventStruct {
    TrackMouseEventStruct {
        cb_size: std::mem::size_of::<TrackMouseEventStruct>() as u32,
        dw_flags: flags,
        hwnd_track: hwnd,
        dw_hover_time: 0,
        _pad: 0,
    }
}

#[test]
fn struct_size_is_24() {
    assert_eq!(
        std::mem::size_of::<TrackMouseEventStruct>(),
        24,
        "TRACKMOUSEEVENT must be 24 bytes on x64"
    );
}

#[test]
fn null_ptr_returns_false() {
    let ret = unsafe { track_mouse_event(std::ptr::null_mut()) };
    assert_eq!(ret, 0, "NULL lp_event_track must return FALSE");
}

#[test]
fn small_cbsize_returns_false() {
    let mut tme = make_tme(TME_LEAVE, FAKE_HWND);
    tme.cb_size = 4; // too small
    let ret = unsafe { track_mouse_event(&mut tme as *mut _ as *mut u8) };
    assert_eq!(ret, 0, "cbSize < 24 must return FALSE");
}

#[test]
fn tme_leave_registers_and_is_visible_via_take() {
    let mut tme = make_tme(TME_LEAVE, FAKE_HWND);
    let ret = unsafe { track_mouse_event(&mut tme as *mut _ as *mut u8) };
    assert_eq!(ret, 1, "TME_LEAVE must return TRUE");
    assert!(
        take_tme_leave(FAKE_HWND),
        "TME_LEAVE must register hwnd in tracking table"
    );
    // one-shot: second take returns false
    assert!(
        !take_tme_leave(FAKE_HWND),
        "take_tme_leave is one-shot — second call must return false"
    );
}

#[test]
fn tme_cancel_leave_removes_registration() {
    register_tme_leave(FAKE_HWND);
    let mut tme = make_tme(TME_CANCEL | TME_LEAVE, FAKE_HWND);
    let ret = unsafe { track_mouse_event(&mut tme as *mut _ as *mut u8) };
    assert_eq!(ret, 1, "TME_CANCEL must return TRUE");
    assert!(
        !take_tme_leave(FAKE_HWND),
        "TME_CANCEL|TME_LEAVE must remove hwnd from tracking table"
    );
}

#[test]
fn tme_query_returns_active_flags() {
    register_tme_leave(FAKE_HWND);
    let mut tme = make_tme(TME_QUERY, FAKE_HWND);
    let ret = unsafe { track_mouse_event(&mut tme as *mut _ as *mut u8) };
    assert_eq!(ret, 1, "TME_QUERY must return TRUE");
    assert_eq!(
        tme.dw_flags & TME_LEAVE,
        TME_LEAVE,
        "TME_QUERY must report TME_LEAVE as active when registered"
    );
    // cleanup
    cancel_tme_leave(FAKE_HWND);
}

#[test]
fn tme_query_no_registration_returns_zero_flags() {
    cancel_tme_leave(FAKE_HWND); // ensure clean state
    let mut tme = make_tme(TME_QUERY, FAKE_HWND);
    unsafe { track_mouse_event(&mut tme as *mut _ as *mut u8) };
    assert_eq!(
        tme.dw_flags & TME_LEAVE,
        0,
        "TME_QUERY must return 0 flags when not registered"
    );
}
