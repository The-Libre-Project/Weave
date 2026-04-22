//! Process-global keyboard state table.
//!
//! Tracks which Win32 virtual keys (VKs) are currently held down, fed by
//! XCB KeyPress/KeyRelease events translated in `backend.rs`. The same state
//! table serves both `GetKeyState` (synchronous snapshot) and
//! `GetAsyncKeyState` (live hardware state) — for Weave's single-process
//! single-thread model these are equivalent.
//!
//! # VK state byte layout
//!
//! Each byte in `VK_STATE[vk]` follows the Windows convention:
//! - Bit 7 (0x80): key is currently down.
//! - Bit 0 (0x01): toggle state (CAPSLOCK on/off; NUMLOCK/SCROLLLOCK TODO).
//!
//! # Thread safety
//!
//! `VK_STATE` is protected by a `Mutex`. Both `set_vk_down` and `vk_state`
//! acquire it briefly and release it — no long-held locks.

use std::sync::{Mutex, MutexGuard};

/// Process-global VK state array: 256 bytes, one per VK code.
///
/// Initialised to zero (all keys up, all toggles off).
static VK_STATE: Mutex<[u8; 256]> = Mutex::new([0u8; 256]);

fn lock() -> MutexGuard<'static, [u8; 256]> {
    VK_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Return the VK state byte for `vk`.
///
/// Bit 7 set → key is down. Bit 0 set → toggle is active (CAPSLOCK).
pub fn vk_state(vk: u8) -> u8 {
    lock()[vk as usize]
}

/// Update the down/up state for `vk`.
///
/// - `down = true` sets bit 7 (key pressed).
/// - `down = false` clears bit 7 (key released).
/// - `toggle = Some(v)` writes the toggle bit (bit 0) to `v`.
///   `toggle = None` leaves the toggle bit unchanged.
///
/// CAPSLOCK toggle: pass `toggle = Some(!current_toggle)` on KeyPress.
pub fn set_vk_down(vk: u8, down: bool, toggle: Option<bool>) {
    let mut state = lock();
    let byte = &mut state[vk as usize];
    if down {
        *byte |= 0x80;
    } else {
        *byte &= !0x80;
    }
    if let Some(t) = toggle {
        if t {
            *byte |= 0x01;
        } else {
            *byte &= !0x01;
        }
    }
}

/// Return an atomic snapshot of the entire VK state array.
///
/// The returned array is a copy — subsequent calls to `set_vk_down` do not
/// affect it. Used by `GetKeyboardState`.
pub fn snapshot() -> [u8; 256] {
    *lock()
}

/// Map an X11 keycode (`ev.detail` from XCB KeyPress/KeyRelease) to a
/// Windows virtual key code.
///
/// Uses a static 128-entry table covering keycodes 0x00..=0x7F (the full
/// evdev range minus the extended block above 0x7F). Returns `None` for
/// unmapped or out-of-range keycodes.
///
/// Wine ref: dlls/winex11.drv/keyboard.c — main_key_vkey_qwerty[] and
/// main_key_US layout; X11DRV_InitKeyboard builds keyc2vkey[] from these
/// tables at startup. X11 keycodes = Linux evdev keycode + 8 (the evdev
/// offset applied by the X server).
pub fn keycode_to_vk(xcb_keycode: u8) -> Option<u8> {
    // Only cover the low 128 keycodes (evdev layout + 8 offset).
    // Keycodes >= 128 are extended and not covered by this static table.
    if xcb_keycode >= 128 {
        return None;
    }
    KEYCODE_TO_VK[xcb_keycode as usize]
}

/// Static X11 keycode → Win32 VK table for the standard Linux evdev US layout.
///
/// Index = X11 keycode (ev.detail). Value = Some(VK) or None (unmapped).
/// X11 keycode = Linux evdev keycode + 8.
///
/// Wine ref: dlls/winex11.drv/keyboard.c main_key_vkey_qwerty[] and
/// main_key_US — the canonical US QWERTY layout VK assignments.
/// Extended nav/arrow cluster keycodes (104..=119, 133..=135) are >= 0x80
/// and handled by the backend's own x11_keycode_to_vk(); this table covers
/// 0x00..=0x7F only.
#[rustfmt::skip]
static KEYCODE_TO_VK: [Option<u8>; 128] = {
    // Initialise to None, then fill known mappings below.
    // Rust doesn't allow array literals with holes in const context, so we
    // use a helper const array.
    const N: Option<u8> = None;

    [
        //  0       1       2       3       4       5       6       7
        N,      N,      N,      N,      N,      N,      N,      N,      //   0..7
        //  8       9 (Esc) 10(1)   11(2)   12(3)   13(4)   14(5)   15(6)
        N,      Some(0x1B), Some(0x31), Some(0x32), Some(0x33), Some(0x34), Some(0x35), Some(0x36), //   8..15
        //  16(7)   17(8)   18(9)   19(0)   20(-)   21(=)   22(BS)  23(Tab)
        Some(0x37), Some(0x38), Some(0x39), Some(0x30), Some(0xBD), Some(0xBB), Some(0x08), Some(0x09), //  16..23
        //  24(Q)   25(W)   26(E)   27(R)   28(T)   29(Y)   30(U)   31(I)
        Some(0x51), Some(0x57), Some(0x45), Some(0x52), Some(0x54), Some(0x59), Some(0x55), Some(0x49), //  24..31
        //  32(O)   33(P)   34([)   35(])   36(Ret) 37(LCtl)38(A)   39(S)
        Some(0x4F), Some(0x50), Some(0xDB), Some(0xDD), Some(0x0D), Some(0xA2), Some(0x41), Some(0x53), //  32..39
        //  40(D)   41(F)   42(G)   43(H)   44(J)   45(K)   46(L)   47(;)
        Some(0x44), Some(0x46), Some(0x47), Some(0x48), Some(0x4A), Some(0x4B), Some(0x4C), Some(0xBA), //  40..47
        //  48(')   49(`)   50(LSh) 51(\)   52(Z)   53(X)   54(C)   55(V)
        Some(0xDE), Some(0xC0), Some(0xA0), Some(0xDC), Some(0x5A), Some(0x58), Some(0x43), Some(0x56), //  48..55
        //  56(B)   57(N)   58(M)   59(,)   60(.)   61(/)   62(RSh) 63(KP*)
        Some(0x42), Some(0x4E), Some(0x4D), Some(0xBC), Some(0xBE), Some(0xBF), Some(0xA1), Some(0x6A), //  56..63
        //  64(Alt) 65(Spc) 66(Cap) 67(F1)  68(F2)  69(F3)  70(F4)  71(F5)
        Some(0xA4), Some(0x20), Some(0x14), Some(0x70), Some(0x71), Some(0x72), Some(0x73), Some(0x74), //  64..71
        //  72(F6)  73(F7)  74(F8)  75(F9)  76(F10) 77(NLk) 78(Scr) 79(KP7)
        Some(0x75), Some(0x76), Some(0x77), Some(0x78), Some(0x79), Some(0x90), Some(0x91), Some(0x67), //  72..79
        //  80(KP8) 81(KP9) 82(KP-) 83(KP4) 84(KP5) 85(KP6) 86(KP+) 87(KP1)
        Some(0x68), Some(0x69), Some(0x6D), Some(0x64), Some(0x65), Some(0x66), Some(0x6B), Some(0x61), //  80..87
        //  88(KP2) 89(KP3) 90(KP0) 91(KP.) 92      93      94      95(F11)
        Some(0x62), Some(0x63), Some(0x60), Some(0x6E), N,      N,      N,      Some(0x7A), //  88..95
        //  96(F12) 97      98      99      100     101     102     103
        Some(0x7B), N,      N,      N,      N,      N,      N,      N,      //  96..103
        //  104     105     106     107     108     109     110     111
        N,      N,      N,      N,      N,      N,      N,      N,      // 104..111
        //  112     113     114     115     116     117     118     119
        N,      N,      N,      N,      N,      N,      N,      N,      // 112..119
        //  120     121     122     123     124     125     126     127
        N,      N,      N,      N,      N,      N,      N,      N,      // 120..127
    ]
};

/// Reset all VK state to zero. Used only in unit tests to ensure a clean slate.
#[cfg(test)]
pub fn test_reset() {
    let mut state = lock();
    *state = [0u8; 256];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: reset state before each test so tests do not bleed into each other.
    fn reset() {
        test_reset();
    }

    #[test]
    fn set_vk_down_marks_bit_7() {
        reset();
        set_vk_down(b'A', true, None);
        assert_eq!(
            vk_state(b'A') & 0x80,
            0x80,
            "bit 7 must be set when key is down"
        );
    }

    #[test]
    fn set_vk_down_clears_on_release() {
        reset();
        set_vk_down(b'A', true, None);
        set_vk_down(b'A', false, None);
        assert_eq!(
            vk_state(b'A') & 0x80,
            0,
            "bit 7 must be clear after release"
        );
    }

    #[test]
    fn toggle_bit_flips_on_subsequent_calls() {
        reset();
        // VK_CAPITAL = 0x14; press once → toggle on
        let vk_capital: u8 = 0x14;
        let current = vk_state(vk_capital) & 0x01 != 0;
        set_vk_down(vk_capital, true, Some(!current)); // first press
        let after_first = vk_state(vk_capital) & 0x01 != 0;
        assert_ne!(after_first, current, "toggle must flip on first press");

        // Press again → toggle flips back
        let current2 = vk_state(vk_capital) & 0x01 != 0;
        set_vk_down(vk_capital, true, Some(!current2)); // second press
        let after_second = vk_state(vk_capital) & 0x01 != 0;
        assert_eq!(
            after_second, current,
            "two toggles must return to start state"
        );
    }

    #[test]
    fn keycode_to_vk_maps_common_keys() {
        // Keycode 24 → Q (0x51)
        assert_eq!(keycode_to_vk(24), Some(0x51), "keycode 24 must map to VK_Q");
        // Keycode 36 → VK_RETURN (0x0D)
        assert_eq!(
            keycode_to_vk(36),
            Some(0x0D),
            "keycode 36 must map to VK_RETURN"
        );
        // Keycode 9 → VK_ESCAPE (0x1B)
        assert_eq!(
            keycode_to_vk(9),
            Some(0x1B),
            "keycode 9 must map to VK_ESCAPE"
        );
        // Keycode 66 → VK_CAPITAL (0x14)
        assert_eq!(
            keycode_to_vk(66),
            Some(0x14),
            "keycode 66 must map to VK_CAPITAL"
        );
        // Keycode 255 (>= 128) → None (out of table range)
        assert_eq!(
            keycode_to_vk(255),
            None,
            "out-of-range keycode must return None"
        );
        // Keycode 128 → None (first out-of-range)
        assert_eq!(keycode_to_vk(128), None, "keycode 128 must return None");
    }

    #[test]
    fn snapshot_copies_state() {
        reset();
        // Set a few keys.
        set_vk_down(0x41, true, None); // VK_A
        set_vk_down(0xA0, true, None); // VK_LSHIFT
        let snap = snapshot();

        // Mutate after snapshot.
        set_vk_down(0x41, false, None);
        set_vk_down(0x42, true, None); // VK_B

        // Snapshot must reflect state at capture time.
        assert_eq!(snap[0x41], 0x80, "snapshot must have VK_A down");
        assert_eq!(snap[0xA0], 0x80, "snapshot must have VK_LSHIFT down");
        assert_eq!(
            snap[0x42], 0x00,
            "snapshot must not see VK_B (set after snapshot)"
        );
    }
}
