//! xinput1_3.dll, xinput1_4.dll, xinput9_1_0.dll stubs for Weave.
//!
//! Implements XInput (Xbox controller API) backed by Linux evdev/joystick.
//! Maps /dev/input/js0..js3 to XInput player slots 0-3.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::sync::Mutex;

// ── XInput Structures ─────────────────────────────────────────────────────

/// XINPUT_GAMEPAD
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XInputGamepad {
    pub w_buttons: u16,
    pub b_left_trigger: u8,
    pub b_right_trigger: u8,
    pub s_thumb_lx: i16,
    pub s_thumb_ly: i16,
    pub s_thumb_rx: i16,
    pub s_thumb_ry: i16,
}

/// XINPUT_STATE
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XInputState {
    pub dw_packet_number: u32,
    pub gamepad: XInputGamepad,
}

/// XINPUT_VIBRATION
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XInputVibration {
    pub w_left_motor_speed: u16,
    pub w_right_motor_speed: u16,
}

/// XINPUT_CAPABILITIES
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XInputCapabilities {
    pub type_: u8,
    pub sub_type: u8,
    pub flags: u16,
    pub gamepad: XInputGamepad,
    pub vibration: XInputVibration,
}

// Button bitmask constants (match Windows XInput header)
pub const XINPUT_GAMEPAD_DPAD_UP: u16        = 0x0001;
pub const XINPUT_GAMEPAD_DPAD_DOWN: u16      = 0x0002;
pub const XINPUT_GAMEPAD_DPAD_LEFT: u16      = 0x0004;
pub const XINPUT_GAMEPAD_DPAD_RIGHT: u16     = 0x0008;
pub const XINPUT_GAMEPAD_START: u16          = 0x0010;
pub const XINPUT_GAMEPAD_BACK: u16           = 0x0020;
pub const XINPUT_GAMEPAD_LEFT_THUMB: u16     = 0x0040;
pub const XINPUT_GAMEPAD_RIGHT_THUMB: u16    = 0x0080;
pub const XINPUT_GAMEPAD_LEFT_SHOULDER: u16  = 0x0100;
pub const XINPUT_GAMEPAD_RIGHT_SHOULDER: u16 = 0x0200;
pub const XINPUT_GAMEPAD_A: u16              = 0x1000;
pub const XINPUT_GAMEPAD_B: u16              = 0x2000;
pub const XINPUT_GAMEPAD_X: u16              = 0x4000;
pub const XINPUT_GAMEPAD_Y: u16              = 0x8000;

// Error codes (match Windows WinError.h)
pub const ERROR_SUCCESS: u32              = 0;
pub const ERROR_DEVICE_NOT_CONNECTED: u32 = 1167;

// ── Internal State ────────────────────────────────────────────────────────

/// Cached gamepad logical state for each slot (0-3).
static GAMEPAD_STATES: Mutex<Option<HashMap<u32, XInputState>>> = Mutex::new(None);

/// Monotonic packet counter — incremented on every state change.
static PACKET_COUNTER: Mutex<u32> = Mutex::new(0);

// ── Linux joystick backend ────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_backend {
    use super::*;
    use libc::{c_void, O_NONBLOCK, O_RDONLY};
    use std::ffi::CString;
    use std::os::unix::io::RawFd;

    // Linux joystick event structure (from <linux/joystick.h>)
    #[repr(C)]
    pub struct JsEvent {
        pub time: u32,   // event timestamp in milliseconds
        pub value: i16,  // axis value or button state
        pub type_: u8,   // event type
        pub number: u8,  // axis / button number
    }

    pub const JS_EVENT_BUTTON: u8 = 0x01;
    pub const JS_EVENT_AXIS: u8   = 0x02;
    pub const JS_EVENT_INIT: u8   = 0x80; // synthetic init event flag

    /// Open /dev/input/jsN in non-blocking mode; returns the fd or -1.
    pub fn open_joystick(slot: u32) -> Option<RawFd> {
        let path = format!("/dev/input/js{slot}");
        let c_path = CString::new(path).ok()?;
        let fd = unsafe { libc::open(c_path.as_ptr(), O_RDONLY | O_NONBLOCK) };
        if fd < 0 { None } else { Some(fd) }
    }

    /// Drain all pending js_events from fd and fold them into `gamepad`.
    pub fn read_joystick_state(fd: RawFd, gamepad: &mut XInputGamepad) {
        let event_size = std::mem::size_of::<JsEvent>();
        loop {
            let mut ev = JsEvent { time: 0, value: 0, type_: 0, number: 0 };
            let ret = unsafe {
                libc::read(fd, &mut ev as *mut JsEvent as *mut c_void, event_size)
            };
            if ret as usize != event_size {
                // No more events (EAGAIN) or error — stop draining.
                break;
            }
            match ev.type_ & !JS_EVENT_INIT {
                JS_EVENT_AXIS => apply_axis(gamepad, ev.number, ev.value),
                JS_EVENT_BUTTON => apply_button(gamepad, ev.number, ev.value),
                _ => {}
            }
        }
    }

    /// Map Linux joystick axis numbers to XInputGamepad fields.
    ///
    /// Standard USB gamepad axis layout (SDL/xpad convention):
    ///   0 → left stick X
    ///   1 → left stick Y   (negate: Linux +Y = down, Windows +Y = up)
    ///   2 → right stick X
    ///   3 → right stick Y  (negate)
    ///   4 → left trigger   (range -32767..32767 → 0..255)
    ///   5 → right trigger  (same)
    fn apply_axis(gp: &mut XInputGamepad, axis: u8, value: i16) {
        match axis {
            0 => gp.s_thumb_lx = value,
            1 => gp.s_thumb_ly = value.saturating_neg(),
            2 => gp.s_thumb_rx = value,
            3 => gp.s_thumb_ry = value.saturating_neg(),
            4 => gp.b_left_trigger  = axis_to_trigger(value),
            5 => gp.b_right_trigger = axis_to_trigger(value),
            _ => {}
        }
    }

    /// Convert trigger axis (-32767..32767) to Windows range (0..255).
    /// Resting position on most controllers is -32767 (not pressed).
    #[inline]
    fn axis_to_trigger(value: i16) -> u8 {
        // Map -32767..32767 → 0..255
        let shifted = (value as i32) + 32767; // 0..65534
        (shifted * 255 / 65534) as u8
    }

    /// Map Linux joystick button numbers to XInput bitmask constants.
    ///
    /// Standard xpad / Xbox controller button layout:
    ///   0  A
    ///   1  B
    ///   2  X
    ///   3  Y
    ///   4  Left Shoulder (LB)
    ///   5  Right Shoulder (RB)
    ///   6  Back / View
    ///   7  Start / Menu
    ///   8  Left Stick click (L3)
    ///   9  Right Stick click (R3)
    ///  10  D-Pad Up
    ///  11  D-Pad Down
    ///  12  D-Pad Left
    ///  13  D-Pad Right
    fn apply_button(gp: &mut XInputGamepad, button: u8, value: i16) {
        let bit: Option<u16> = match button {
            0  => Some(super::XINPUT_GAMEPAD_A),
            1  => Some(super::XINPUT_GAMEPAD_B),
            2  => Some(super::XINPUT_GAMEPAD_X),
            3  => Some(super::XINPUT_GAMEPAD_Y),
            4  => Some(super::XINPUT_GAMEPAD_LEFT_SHOULDER),
            5  => Some(super::XINPUT_GAMEPAD_RIGHT_SHOULDER),
            6  => Some(super::XINPUT_GAMEPAD_BACK),
            7  => Some(super::XINPUT_GAMEPAD_START),
            8  => Some(super::XINPUT_GAMEPAD_LEFT_THUMB),
            9  => Some(super::XINPUT_GAMEPAD_RIGHT_THUMB),
            10 => Some(super::XINPUT_GAMEPAD_DPAD_UP),
            11 => Some(super::XINPUT_GAMEPAD_DPAD_DOWN),
            12 => Some(super::XINPUT_GAMEPAD_DPAD_LEFT),
            13 => Some(super::XINPUT_GAMEPAD_DPAD_RIGHT),
            _  => None,
        };
        if let Some(mask) = bit {
            if value != 0 {
                gp.w_buttons |= mask;
            } else {
                gp.w_buttons &= !mask;
            }
        }
    }

    /// Open file descriptors for each joystick slot, keyed by slot index.
    static JOYSTICK_FDS: Mutex<Option<HashMap<u32, RawFd>>> = Mutex::new(None);

    /// Scan /dev/input/js0..js3, open each that exists, store the fds.
    pub fn init_joystick_fds() {
        let mut fds_opt = JOYSTICK_FDS.lock().unwrap();
        if fds_opt.is_none() {
            let mut map: HashMap<u32, RawFd> = HashMap::new();
            for slot in 0..4u32 {
                if let Some(fd) = open_joystick(slot) {
                    map.insert(slot, fd);
                }
            }
            *fds_opt = Some(map);
        }
    }

    /// Return the fd for `slot`, or None if no device is connected there.
    pub fn get_joystick_fd(slot: u32) -> Option<RawFd> {
        let fds_opt = JOYSTICK_FDS.lock().unwrap();
        fds_opt.as_ref().and_then(|m| m.get(&slot).copied())
    }

    /// True if the given slot has a joystick fd (i.e., a device is connected).
    pub fn slot_connected(slot: u32) -> bool {
        get_joystick_fd(slot).is_some()
    }
}

// ── Stub backend for non-Linux (macOS dev builds) ─────────────────────────

#[cfg(not(target_os = "linux"))]
mod linux_backend {
    use super::XInputGamepad;

    pub fn init_joystick_fds() {}
    pub fn get_joystick_fd(_slot: u32) -> Option<i32> { None }
    pub fn slot_connected(_slot: u32) -> bool { false }
    pub fn read_joystick_state(_fd: i32, _gamepad: &mut XInputGamepad) {}
}

// ── Shared init ───────────────────────────────────────────────────────────

fn init_gamepad_states() {
    // Ensure joystick fds are opened first (Linux: scans /dev/input/js*).
    linux_backend::init_joystick_fds();

    let mut states_opt = GAMEPAD_STATES.lock().unwrap();
    if states_opt.is_none() {
        let mut states = HashMap::new();
        for slot in 0..4u32 {
            states.insert(slot, XInputState {
                dw_packet_number: 0,
                gamepad: XInputGamepad {
                    w_buttons: 0,
                    b_left_trigger: 0,
                    b_right_trigger: 0,
                    s_thumb_lx: 0,
                    s_thumb_ly: 0,
                    s_thumb_rx: 0,
                    s_thumb_ry: 0,
                },
            });
        }
        *states_opt = Some(states);
    }
}

// ── XInput API Functions ──────────────────────────────────────────────────

/// XInputGetState — retrieves the current state of the specified controller.
///
/// On Linux, drains all pending joystick events from /dev/input/jsN into the
/// cached state before returning it.  Non-blocking — never stalls.
///
/// # Safety
/// `p_state` must be a valid non-null pointer to a writable `XInputState`.
pub unsafe extern "win64" fn x_input_get_state(
    dw_user_index: u32,
    p_state: *mut XInputState,
) -> u32 {
    if p_state.is_null() {
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    init_gamepad_states();

    // If no device exists for this slot, report disconnected immediately.
    if !linux_backend::slot_connected(dw_user_index) {
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    // Drain any new hardware events into the cached state.
    {
        let mut states_opt = GAMEPAD_STATES.lock().unwrap();
        if let Some(states) = states_opt.as_mut() {
            if let Some(state) = states.get_mut(&dw_user_index) {
                if let Some(fd) = linux_backend::get_joystick_fd(dw_user_index) {
                    let prev_buttons = state.gamepad.w_buttons;
                    let prev_lx = state.gamepad.s_thumb_lx;
                    linux_backend::read_joystick_state(fd, &mut state.gamepad);
                    // Bump packet number if anything changed.
                    if state.gamepad.w_buttons != prev_buttons
                        || state.gamepad.s_thumb_lx != prev_lx
                    {
                        let mut counter = PACKET_COUNTER.lock().unwrap();
                        *counter += 1;
                        state.dw_packet_number = *counter;
                    }
                }
            }
        }
    }

    // Copy state to caller.
    let states_opt = GAMEPAD_STATES.lock().unwrap();
    if let Some(states) = states_opt.as_ref() {
        if let Some(state) = states.get(&dw_user_index) {
            *p_state = *state;
            return ERROR_SUCCESS;
        }
    }
    ERROR_DEVICE_NOT_CONNECTED
}

/// XInputSetState — sends vibration data to the specified controller.
///
/// TODO: implement force-feedback via /dev/input/eventN using the Linux
/// FF_RUMBLE interface (EVIOCSFF / EV_FF).  Requires opening the evdev node
/// (not the js node) for the same physical device.  For now this is a no-op
/// that acknowledges the call correctly.
///
/// # Safety
/// `p_vibration` must be a valid non-null pointer to a readable `XInputVibration`.
pub unsafe extern "win64" fn x_input_set_state(
    dw_user_index: u32,
    p_vibration: *const XInputVibration,
) -> u32 {
    if p_vibration.is_null() {
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    init_gamepad_states();

    if !linux_backend::slot_connected(dw_user_index) {
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    // Acknowledge the call and bump the packet counter.
    let mut states_opt = GAMEPAD_STATES.lock().unwrap();
    if let Some(states) = states_opt.as_mut() {
        if let Some(state) = states.get_mut(&dw_user_index) {
            let mut counter = PACKET_COUNTER.lock().unwrap();
            *counter += 1;
            state.dw_packet_number = *counter;
            return ERROR_SUCCESS;
        }
    }
    ERROR_DEVICE_NOT_CONNECTED
}

/// XInputGetCapabilities — retrieves capabilities of the specified controller.
///
/// # Safety
/// `p_capabilities` must be a valid non-null pointer to a writable `XInputCapabilities`.
pub unsafe extern "win64" fn x_input_get_capabilities(
    dw_user_index: u32,
    _dw_flags: u32,
    p_capabilities: *mut XInputCapabilities,
) -> u32 {
    if p_capabilities.is_null() {
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    init_gamepad_states();

    if !linux_backend::slot_connected(dw_user_index) {
        return ERROR_DEVICE_NOT_CONNECTED;
    }

    *p_capabilities = XInputCapabilities {
        type_: 1,    // XINPUT_DEVTYPE_GAMEPAD
        sub_type: 1, // XINPUT_DEVSUBTYPE_GAMEPAD
        flags: 0,
        gamepad: XInputGamepad {
            w_buttons: 0xF3FF, // All buttons supported
            b_left_trigger: 255,
            b_right_trigger: 255,
            s_thumb_lx: -32768,
            s_thumb_ly: -32768,
            s_thumb_rx: -32768,
            s_thumb_ry: -32768,
        },
        vibration: XInputVibration {
            w_left_motor_speed: 65535,
            w_right_motor_speed: 65535,
        },
    };
    ERROR_SUCCESS
}

/// XInputEnable — enables or disables input processing.
///
/// A no-op in Weave; we always process input when a device is connected.
pub extern "win64" fn x_input_enable(_enable: i32) {}

// ── DLL Resolvers ─────────────────────────────────────────────────────────

/// Resolve an xinput DLL import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("xinput1_3.dll")
        && !dll.eq_ignore_ascii_case("xinput1_4.dll")
        && !dll.eq_ignore_ascii_case("xinput9_1_0.dll")
    {
        return None;
    }

    match func {
        "XInputGetState"        => Some(x_input_get_state as *const () as usize),
        "XInputSetState"        => Some(x_input_set_state as *const () as usize),
        "XInputGetCapabilities" => Some(x_input_get_capabilities as *const () as usize),
        "XInputEnable"          => Some(x_input_enable as *const () as usize),
        _                       => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_functions_returns_some() {
        for dll in &["xinput1_3.dll", "xinput1_4.dll", "xinput9_1_0.dll"] {
            assert!(resolve(dll, "XInputGetState").is_some(),        "missing XInputGetState in {dll}");
            assert!(resolve(dll, "XInputSetState").is_some(),        "missing XInputSetState in {dll}");
            assert!(resolve(dll, "XInputGetCapabilities").is_some(), "missing XInputGetCapabilities in {dll}");
        }
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("kernel32.dll", "XInputGetState").is_none());
    }

    #[test]
    fn resolve_unknown_function_returns_none() {
        assert!(resolve("xinput1_3.dll", "__weave_nonexistent__").is_none());
    }

    #[test]
    fn get_state_null_ptr_returns_not_connected() {
        let result = unsafe { x_input_get_state(0, std::ptr::null_mut()) };
        assert_eq!(result, ERROR_DEVICE_NOT_CONNECTED);
    }

    #[test]
    fn set_state_null_ptr_returns_not_connected() {
        let result = unsafe { x_input_set_state(0, std::ptr::null()) };
        assert_eq!(result, ERROR_DEVICE_NOT_CONNECTED);
    }

    #[test]
    fn get_capabilities_null_ptr_returns_not_connected() {
        let result = unsafe { x_input_get_capabilities(0, 0, std::ptr::null_mut()) };
        assert_eq!(result, ERROR_DEVICE_NOT_CONNECTED);
    }

    /// On macOS dev builds (no /dev/input/jsN), all slots report disconnected.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn no_device_on_non_linux() {
        let mut state = XInputState {
            dw_packet_number: 0,
            gamepad: XInputGamepad {
                w_buttons: 0,
                b_left_trigger: 0,
                b_right_trigger: 0,
                s_thumb_lx: 0,
                s_thumb_ly: 0,
                s_thumb_rx: 0,
                s_thumb_ry: 0,
            },
        };
        for slot in 0..4u32 {
            let result = unsafe { x_input_get_state(slot, &mut state) };
            assert_eq!(result, ERROR_DEVICE_NOT_CONNECTED, "slot {slot} should be disconnected on non-Linux");
        }
    }
}
