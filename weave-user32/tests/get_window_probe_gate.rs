//! Probe gate — `GetWindow` sibling/child/owner relationships against the window table.

use weave_common::{get_last_error, set_last_error};
use weave_user32::api::get_window;
use weave_user32::defs::{WS_CHILD, WS_POPUP};
use weave_user32::window::{self, WindowEntry};

const GW_HWNDFIRST: u32 = 0;
const GW_HWNDLAST: u32 = 1;
const GW_HWNDNEXT: u32 = 2;
const GW_HWNDPREV: u32 = 3;
const GW_OWNER: u32 = 4;
const GW_CHILD: u32 = 5;

fn make_window(parent: usize, style: u32) -> usize {
    window::create(WindowEntry {
        class_name: "GetWindowProbe".into(),
        wnd_proc: 0,
        title: String::new(),
        style,
        x: 0,
        y: 0,
        width: 100,
        height: 100,
        visible: true,
        xcb_id: 0,
        h_menu: 0,
        hwnd_parent: parent,
        tid: 1,
    })
}

#[test]
fn get_window_child_and_sibling_chain() {
    let parent = make_window(0, 0);
    let child_a = make_window(parent, WS_CHILD);
    let child_b = make_window(parent, WS_CHILD);

    assert_eq!(get_window(parent, GW_CHILD), child_a);
    assert_eq!(get_window(child_a, GW_HWNDNEXT), child_b);
    assert_eq!(get_window(child_b, GW_HWNDPREV), child_a);
    assert_eq!(get_window(child_a, GW_HWNDFIRST), child_a);
    assert_eq!(get_window(child_b, GW_HWNDLAST), child_b);
    assert_eq!(get_window(child_a, GW_OWNER), parent);
}

#[test]
fn get_window_owner_invalid_handle_sets_last_error() {
    set_last_error(0);
    assert_eq!(get_window(0xDEAD_BEEF, GW_OWNER), 0);
    assert_eq!(get_last_error(), 6); // ERROR_INVALID_HANDLE
}

#[test]
fn get_window_popup_owner_from_parent_field() {
    let owner = make_window(0, 0);
    let popup = make_window(owner, WS_POPUP);
    assert_eq!(get_window(popup, GW_OWNER), owner);
}
