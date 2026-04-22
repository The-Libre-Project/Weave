//! Probe gate — end-to-end validation that `TranslateAcceleratorW` consults
//! `GetKeyState` for Shift/Ctrl modifier matching (Task 26).
//!
//! Closes the Task 17 deferral: "modifier matching uses lParam ALT bit only;
//! Shift/Ctrl accelerators will not fire until keyboard state table lands."
//!
//! Cases validated:
//!   A — Ctrl+S accel with VK_CONTROL down → returns 1 (matched, WM_COMMAND sent)
//!   B — Ctrl+S accel without VK_CONTROL down → returns 0 (modifier mismatch)
//!   C — Ctrl+S accel with VK_CONTROL + VK_SHIFT down (FSHIFT not in fVirt) → returns 0
//!   D — Ctrl+S accel but MSG is WM_CHAR (not FVIRTKEY-compatible) → returns 0

use weave_user32::accel_handles::{register, AccelBlob};
use weave_user32::api::translate_accelerator_w;
use weave_user32::defs::{Msg, WM_CHAR, WM_KEYDOWN};
use weave_user32::input;

// VK constants
const VK_SHIFT: u8 = 0x10;
const VK_CONTROL: u8 = 0x11;
const VK_S: u16 = 0x53;

// Accelerator modifier flag constants (Wine include/winuser.h)
const FVIRTKEY: u16 = 0x01;
const FCONTROL: u16 = 0x08;

/// Build a PE_ACCEL blob with a single entry.
/// Format: { WORD fVirt, WORD key, WORD cmd, WORD pad } — 8 bytes per entry.
/// Last entry gets bit 7 (0x80) set in fVirt_low.
fn make_single_accel_blob(f_virt: u16, key: u16, cmd: u16) -> Vec<u8> {
    let mut blob = Vec::with_capacity(8);
    // Mark as last entry by ORing 0x80 into the low byte (high byte is padding in PE_ACCEL).
    let f_virt_last = f_virt | 0x80;
    blob.extend_from_slice(&f_virt_last.to_le_bytes());
    blob.extend_from_slice(&key.to_le_bytes());
    blob.extend_from_slice(&cmd.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes()); // pad
    blob
}

fn make_msg(message: u32, w_param: usize) -> Msg {
    Msg {
        hwnd: 0xDEAD_BEEF,
        message,
        _pad0: 0,
        w_param,
        l_param: 0,
        time: 0,
        pt_x: 0,
        pt_y: 0,
        _pad1: 0,
    }
}

/// Case A: VK_CONTROL is down, FVIRTKEY|FCONTROL accel for VK_S → must match (returns 1).
#[test]
fn case_a_ctrl_down_ctrl_s_accel_matches() {
    input::test_reset();

    // Register HACCEL: FVIRTKEY | FCONTROL, VK_S, cmd=0xC0DE
    let blob = make_single_accel_blob(FVIRTKEY | FCONTROL, VK_S, 0xC0DE);
    let haccel = register(
        0xCA5E_A001,
        0xFFFF_CA5E_A001,
        AccelBlob {
            ptr: blob.as_ptr() as usize,
            size: blob.len() as u32,
        },
    );

    // Press VK_CONTROL in the keyboard state table.
    input::set_vk_down(VK_CONTROL, true, None);

    let hwnd: usize = 0xDEAD_0A01;
    let msg = make_msg(WM_KEYDOWN, VK_S as usize);

    // SAFETY: msg is valid, haccel is registered.
    let result = unsafe { translate_accelerator_w(hwnd, haccel, &msg as *const Msg) };
    input::test_reset();

    assert_eq!(
        result, 1,
        "Case A: Ctrl+S with VK_CONTROL down must return 1 (accelerator matched)"
    );
}

/// Case B: VK_CONTROL is NOT down, FVIRTKEY|FCONTROL accel for VK_S → no match (returns 0).
#[test]
fn case_b_ctrl_not_down_ctrl_s_accel_no_match() {
    input::test_reset();

    let blob = make_single_accel_blob(FVIRTKEY | FCONTROL, VK_S, 0xC0DE);
    let haccel = register(
        0xCA5E_B001,
        0xFFFF_CA5E_B001,
        AccelBlob {
            ptr: blob.as_ptr() as usize,
            size: blob.len() as u32,
        },
    );

    // VK_CONTROL is NOT pressed — modifier mask will have no FCONTROL bit.
    let hwnd: usize = 0xDEAD_0B01;
    let msg = make_msg(WM_KEYDOWN, VK_S as usize);

    // SAFETY: msg is valid, haccel is registered.
    let result = unsafe { translate_accelerator_w(hwnd, haccel, &msg as *const Msg) };
    input::test_reset();

    assert_eq!(
        result, 0,
        "Case B: Ctrl+S with VK_CONTROL NOT down must return 0 (modifier mismatch)"
    );
}

/// Case C: VK_CONTROL + VK_SHIFT both down, accel only requires FCONTROL (no FSHIFT) → no match.
#[test]
fn case_c_extra_shift_prevents_match() {
    input::test_reset();

    // Accel: FVIRTKEY | FCONTROL only (no FSHIFT in fVirt).
    let blob = make_single_accel_blob(FVIRTKEY | FCONTROL, VK_S, 0xC0DE);
    let haccel = register(
        0xCA5E_C001,
        0xFFFF_CA5E_C001,
        AccelBlob {
            ptr: blob.as_ptr() as usize,
            size: blob.len() as u32,
        },
    );

    // Press BOTH Ctrl and Shift.
    input::set_vk_down(VK_CONTROL, true, None);
    input::set_vk_down(VK_SHIFT, true, None);

    let hwnd: usize = 0xDEAD_0C01;
    let msg = make_msg(WM_KEYDOWN, VK_S as usize);

    // SAFETY: msg is valid, haccel is registered.
    let result = unsafe { translate_accelerator_w(hwnd, haccel, &msg as *const Msg) };
    input::test_reset();

    assert_eq!(
        result, 0,
        "Case C: Ctrl+Shift+S when accel requires only Ctrl must return 0 (extra modifier)"
    );
}

/// Case D: VK_CONTROL is down but message is WM_CHAR — FVIRTKEY accel does not match WM_CHAR.
#[test]
fn case_d_wm_char_does_not_match_fvirtkey_accel() {
    input::test_reset();

    // Accel: FVIRTKEY | FCONTROL for VK_S.
    let blob = make_single_accel_blob(FVIRTKEY | FCONTROL, VK_S, 0xC0DE);
    let haccel = register(
        0xCA5E_D001,
        0xFFFF_CA5E_D001,
        AccelBlob {
            ptr: blob.as_ptr() as usize,
            size: blob.len() as u32,
        },
    );

    // Ctrl is down, but message is WM_CHAR — wrong message type for FVIRTKEY accel.
    input::set_vk_down(VK_CONTROL, true, None);

    let hwnd: usize = 0xDEAD_0D01;
    let msg = make_msg(WM_CHAR, VK_S as usize);

    // SAFETY: msg is valid, haccel is registered.
    let result = unsafe { translate_accelerator_w(hwnd, haccel, &msg as *const Msg) };
    input::test_reset();

    assert_eq!(
        result, 0,
        "Case D: WM_CHAR message must not match FVIRTKEY accelerator"
    );
}
