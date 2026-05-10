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

// ─── VK ↔ Scan-code and VK → Char translation tables ──────────────────────
//
// PC/AT keyboard scan codes (set 1) for the US QWERTY layout.
//
// Wine ref: dlls/winex11.drv/keyboard.c::X11DRV_MapVirtualKeyEx —
//   MAPVK_VK_TO_VSC iterates keyc2vkey[] matching VK then reads keyc2scan[];
//   MAPVK_VSC_TO_VK does the reverse; MAPVK_VK_TO_CHAR calls XLookupString with
//   no modifiers and upcases the result (letters always return uppercase).
//   MAPVK_VSC_TO_VK collapses L/R pairs: VK_LSHIFT/VK_RSHIFT → VK_SHIFT, etc.
//
// Index = VK code. Value = scan code (0 = no mapping).
// Covers letters, digits, F1-F12, modifiers, editing keys, and common punctuation.
#[rustfmt::skip]
static VK_TO_VSC: [u8; 256] = {
    const Z: u8 = 0;
    let mut t = [Z; 256];

    // Letters A-Z (VK_A=0x41..VK_Z=0x5A) → scan codes
    // Scan codes from PC/AT set 1, US QWERTY row order.
    // Row 3 (home row):  A=0x1E S=0x1F D=0x20 F=0x21 G=0x22 H=0x23 J=0x24 K=0x25 L=0x26
    // Row 4 (bottom):    Z=0x2C X=0x2D C=0x2E V=0x2F B=0x30 N=0x31 M=0x32
    // Row 2 (top):       Q=0x10 W=0x11 E=0x12 R=0x13 T=0x14 Y=0x15 U=0x16 I=0x17 O=0x18 P=0x19
    t[0x41] = 0x1E; // A
    t[0x42] = 0x30; // B
    t[0x43] = 0x2E; // C
    t[0x44] = 0x20; // D
    t[0x45] = 0x12; // E
    t[0x46] = 0x21; // F
    t[0x47] = 0x22; // G
    t[0x48] = 0x23; // H
    t[0x49] = 0x17; // I
    t[0x4A] = 0x24; // J
    t[0x4B] = 0x25; // K
    t[0x4C] = 0x26; // L
    t[0x4D] = 0x32; // M
    t[0x4E] = 0x31; // N
    t[0x4F] = 0x18; // O
    t[0x50] = 0x19; // P
    t[0x51] = 0x10; // Q
    t[0x52] = 0x13; // R
    t[0x53] = 0x1F; // S
    t[0x54] = 0x14; // T
    t[0x55] = 0x16; // U
    t[0x56] = 0x2F; // V
    t[0x57] = 0x11; // W
    t[0x58] = 0x2D; // X
    t[0x59] = 0x15; // Y
    t[0x5A] = 0x2C; // Z

    // Digits 0-9 (VK_0=0x30..VK_9=0x39)
    t[0x30] = 0x0B; // 0
    t[0x31] = 0x02; // 1
    t[0x32] = 0x03; // 2
    t[0x33] = 0x04; // 3
    t[0x34] = 0x05; // 4
    t[0x35] = 0x06; // 5
    t[0x36] = 0x07; // 6
    t[0x37] = 0x08; // 7
    t[0x38] = 0x09; // 8
    t[0x39] = 0x0A; // 9

    // Function keys F1-F12
    t[0x70] = 0x3B; // F1
    t[0x71] = 0x3C; // F2
    t[0x72] = 0x3D; // F3
    t[0x73] = 0x3E; // F4
    t[0x74] = 0x3F; // F5
    t[0x75] = 0x40; // F6
    t[0x76] = 0x41; // F7
    t[0x77] = 0x42; // F8
    t[0x78] = 0x43; // F9
    t[0x79] = 0x44; // F10
    t[0x7A] = 0x57; // F11
    t[0x7B] = 0x58; // F12

    // Modifiers (generic — maps to left-hand scan codes)
    t[0x10] = 0x2A; // VK_SHIFT   → left shift
    t[0x11] = 0x1D; // VK_CONTROL → left ctrl
    t[0x12] = 0x38; // VK_MENU    → left alt
    t[0xA0] = 0x2A; // VK_LSHIFT
    t[0xA1] = 0x36; // VK_RSHIFT
    t[0xA2] = 0x1D; // VK_LCONTROL
    t[0xA4] = 0x38; // VK_LMENU

    // Common keys
    t[0x08] = 0x0E; // VK_BACK (Backspace)
    t[0x09] = 0x0F; // VK_TAB
    t[0x0D] = 0x1C; // VK_RETURN
    t[0x1B] = 0x01; // VK_ESCAPE
    t[0x20] = 0x39; // VK_SPACE
    t[0x14] = 0x3A; // VK_CAPITAL (CapsLock)
    t[0x90] = 0x45; // VK_NUMLOCK
    t[0x91] = 0x46; // VK_SCROLL

    // Punctuation / OEM keys
    t[0xBA] = 0x27; // VK_OEM_1 (;:)
    t[0xBB] = 0x0D; // VK_OEM_PLUS (=+)
    t[0xBC] = 0x33; // VK_OEM_COMMA (,<)
    t[0xBD] = 0x0C; // VK_OEM_MINUS (-_)
    t[0xBE] = 0x34; // VK_OEM_PERIOD (.>)
    t[0xBF] = 0x35; // VK_OEM_2 (/?)
    t[0xC0] = 0x29; // VK_OEM_3 (`~)
    t[0xDB] = 0x1A; // VK_OEM_4 ([{)
    t[0xDC] = 0x2B; // VK_OEM_5 (\|)
    t[0xDD] = 0x1B; // VK_OEM_6 (]})
    t[0xDE] = 0x28; // VK_OEM_7 ('")

    // Numpad
    t[0x60] = 0x52; // VK_NUMPAD0
    t[0x61] = 0x4F; // VK_NUMPAD1
    t[0x62] = 0x50; // VK_NUMPAD2
    t[0x63] = 0x51; // VK_NUMPAD3
    t[0x64] = 0x4B; // VK_NUMPAD4
    t[0x65] = 0x4C; // VK_NUMPAD5
    t[0x66] = 0x4D; // VK_NUMPAD6
    t[0x67] = 0x47; // VK_NUMPAD7
    t[0x68] = 0x48; // VK_NUMPAD8
    t[0x69] = 0x49; // VK_NUMPAD9
    t[0x6A] = 0x37; // VK_MULTIPLY
    t[0x6B] = 0x4E; // VK_ADD
    t[0x6D] = 0x4A; // VK_SUBTRACT
    t[0x6E] = 0x53; // VK_DECIMAL
    t[0x6C] = 0x35; // VK_DIVIDE (extended, but use base scan; 0xE035 extended omitted)

    t
};

/// VK → scan code. Returns 0 if no mapping.
pub fn vk_to_vsc(vk: u8) -> u8 {
    VK_TO_VSC[vk as usize]
}

// Scan code → VK table (PC/AT set 1, US QWERTY).
// Index = scan code (0x00..=0x58). Value = VK code (0 = unmapped).
// L/R modifier pairs are collapsed to their generic VK per MAPVK_VSC_TO_VK contract.
//
// Wine ref: dlls/winex11.drv/keyboard.c::X11DRV_MapVirtualKeyEx —
//   MAPVK_VSC_TO_VK collapses VK_LSHIFT/VK_RSHIFT → VK_SHIFT,
//   VK_LCONTROL/VK_RCONTROL → VK_CONTROL, VK_LMENU/VK_RMENU → VK_MENU.
#[rustfmt::skip]
static VSC_TO_VK: [u8; 128] = [
    //0x00  0x01(Esc) 0x02(1) 0x03(2) 0x04(3) 0x05(4) 0x06(5) 0x07(6)
    0x00, 0x1B,   0x31,   0x32,   0x33,   0x34,   0x35,   0x36,
    //0x08(7) 0x09(8) 0x0A(9) 0x0B(0) 0x0C(-) 0x0D(=) 0x0E(BS) 0x0F(Tab)
    0x37,   0x38,   0x39,   0x30,   0xBD,   0xBB,   0x08,   0x09,
    //0x10(Q) 0x11(W) 0x12(E) 0x13(R) 0x14(T) 0x15(Y) 0x16(U) 0x17(I)
    0x51,   0x57,   0x45,   0x52,   0x54,   0x59,   0x55,   0x49,
    //0x18(O) 0x19(P) 0x1A([) 0x1B(]) 0x1C(Ret) 0x1D(LCtl) 0x1E(A) 0x1F(S)
    0x4F,   0x50,   0xDB,   0xDD,   0x0D,   0x11,   0x41,   0x53,
    //0x20(D) 0x21(F) 0x22(G) 0x23(H) 0x24(J) 0x25(K) 0x26(L) 0x27(;)
    0x44,   0x46,   0x47,   0x48,   0x4A,   0x4B,   0x4C,   0xBA,
    //0x28(') 0x29(`) 0x2A(LSh) 0x2B(\) 0x2C(Z) 0x2D(X) 0x2E(C) 0x2F(V)
    0xDE,   0xC0,   0x10,   0xDC,   0x5A,   0x58,   0x43,   0x56,
    //0x30(B) 0x31(N) 0x32(M) 0x33(,) 0x34(.) 0x35(/) 0x36(RSh) 0x37(KP*)
    0x42,   0x4E,   0x4D,   0xBC,   0xBE,   0xBF,   0x10,   0x6A,
    //0x38(Alt) 0x39(Spc) 0x3A(Cap) 0x3B(F1) 0x3C(F2) 0x3D(F3) 0x3E(F4) 0x3F(F5)
    0x12,   0x20,   0x14,   0x70,   0x71,   0x72,   0x73,   0x74,
    //0x40(F6) 0x41(F7) 0x42(F8) 0x43(F9) 0x44(F10) 0x45(NLk) 0x46(Scr) 0x47(KP7)
    0x75,   0x76,   0x77,   0x78,   0x79,   0x90,   0x91,   0x67,
    //0x48(KP8) 0x49(KP9) 0x4A(KP-) 0x4B(KP4) 0x4C(KP5) 0x4D(KP6) 0x4E(KP+) 0x4F(KP1)
    0x68,   0x69,   0x6D,   0x64,   0x65,   0x66,   0x6B,   0x61,
    //0x50(KP2) 0x51(KP3) 0x52(KP0) 0x53(KP.) 0x54    0x55    0x56    0x57(F11)
    0x62,   0x63,   0x60,   0x6E,   0x00,   0x00,   0x00,   0x7A,
    //0x58(F12) 0x59..0x7F (unmapped)
    0x7B,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Scan code → VK, with L/R modifier pairs collapsed to generic VK.
/// Returns 0 if no mapping.
///
/// Wine ref: dlls/winex11.drv/keyboard.c::X11DRV_MapVirtualKeyEx —
///   MAPVK_VSC_TO_VK collapses VK_LSHIFT/VK_RSHIFT → VK_SHIFT (0x10),
///   VK_LCONTROL/VK_RCONTROL → VK_CONTROL (0x11), VK_LMENU/VK_RMENU → VK_MENU (0x12).
pub fn vsc_to_vk(vsc: u8) -> u8 {
    if vsc as usize >= VSC_TO_VK.len() {
        return 0;
    }
    VSC_TO_VK[vsc as usize]
}

// VK → unshifted character table for MAPVK_VK_TO_CHAR.
// Index = VK code. Value = ASCII char (0 = no char mapping).
//
// Wine ref: dlls/winex11.drv/keyboard.c::X11DRV_MapVirtualKeyEx MAPVK_VK_TO_CHAR —
//   calls XLookupString with state=0 (no modifiers), then upcases via RtlUpcaseUnicodeChar.
//   For letters this means the uppercase character; for digits the base digit character.
//   VK_RETURN → 0x0D (\r), VK_TAB → 0x09 (\t), VK_SPACE → 0x20 (' ').
#[rustfmt::skip]
static VK_TO_CHAR: [u8; 256] = {
    const Z: u8 = 0;
    let mut t = [Z; 256];

    // Letters A-Z: unshifted + upcased = 'A'..'Z' (0x41..0x5A)
    t[0x41] = b'A'; t[0x42] = b'B'; t[0x43] = b'C'; t[0x44] = b'D';
    t[0x45] = b'E'; t[0x46] = b'F'; t[0x47] = b'G'; t[0x48] = b'H';
    t[0x49] = b'I'; t[0x4A] = b'J'; t[0x4B] = b'K'; t[0x4C] = b'L';
    t[0x4D] = b'M'; t[0x4E] = b'N'; t[0x4F] = b'O'; t[0x50] = b'P';
    t[0x51] = b'Q'; t[0x52] = b'R'; t[0x53] = b'S'; t[0x54] = b'T';
    t[0x55] = b'U'; t[0x56] = b'V'; t[0x57] = b'W'; t[0x58] = b'X';
    t[0x59] = b'Y'; t[0x5A] = b'Z';

    // Digits 0-9
    t[0x30] = b'0'; t[0x31] = b'1'; t[0x32] = b'2'; t[0x33] = b'3';
    t[0x34] = b'4'; t[0x35] = b'5'; t[0x36] = b'6'; t[0x37] = b'7';
    t[0x38] = b'8'; t[0x39] = b'9';

    // Control characters
    t[0x08] = 0x08; // VK_BACK → BS
    t[0x09] = 0x09; // VK_TAB  → HT
    t[0x0D] = 0x0D; // VK_RETURN → CR
    t[0x1B] = 0x1B; // VK_ESCAPE → ESC
    t[0x20] = 0x20; // VK_SPACE

    // OEM punctuation (unshifted characters)
    t[0xBA] = b';'; // VK_OEM_1
    t[0xBB] = b'='; // VK_OEM_PLUS
    t[0xBC] = b','; // VK_OEM_COMMA
    t[0xBD] = b'-'; // VK_OEM_MINUS
    t[0xBE] = b'.'; // VK_OEM_PERIOD
    t[0xBF] = b'/'; // VK_OEM_2
    t[0xC0] = b'`'; // VK_OEM_3
    t[0xDB] = b'['; // VK_OEM_4
    t[0xDC] = b'\\'; // VK_OEM_5
    t[0xDD] = b']'; // VK_OEM_6
    t[0xDE] = b'\''; // VK_OEM_7

    t
};

/// VK → unshifted character. Returns 0 if no character mapping exists.
pub fn vk_to_char(vk: u8) -> u8 {
    VK_TO_CHAR[vk as usize]
}

// Char → (VK, modifier_flags) for VkKeyScanW.
// Index = ASCII byte value (0x00..=0x7F). Value = Some((vk, mods)) or None.
// modifier_flags: bit 0 = SHIFT, bit 1 = CTRL, bit 2 = ALT.
//
// Wine ref: dlls/winex11.drv/keyboard.c::X11DRV_VkKeyScanEx —
//   char → keysym → keycode → keyc2vkey; shift state determined by XkbKeycodeToKeysym
//   index (0=unshifted → +0x0000, 1=shift → +0x0100 i.e. high byte = modifier_flags).
//   For Weave: ASCII only, US QWERTY layout baked in.
static CHAR_TO_VK: [Option<(u8, u8)>; 128] = {
    const N: Option<(u8, u8)> = None;
    let mut t = [N; 128];

    // Lowercase letters → (VK, 0) — no shift required
    t[b'a' as usize] = Some((0x41, 0));
    t[b'b' as usize] = Some((0x42, 0));
    t[b'c' as usize] = Some((0x43, 0));
    t[b'd' as usize] = Some((0x44, 0));
    t[b'e' as usize] = Some((0x45, 0));
    t[b'f' as usize] = Some((0x46, 0));
    t[b'g' as usize] = Some((0x47, 0));
    t[b'h' as usize] = Some((0x48, 0));
    t[b'i' as usize] = Some((0x49, 0));
    t[b'j' as usize] = Some((0x4A, 0));
    t[b'k' as usize] = Some((0x4B, 0));
    t[b'l' as usize] = Some((0x4C, 0));
    t[b'm' as usize] = Some((0x4D, 0));
    t[b'n' as usize] = Some((0x4E, 0));
    t[b'o' as usize] = Some((0x4F, 0));
    t[b'p' as usize] = Some((0x50, 0));
    t[b'q' as usize] = Some((0x51, 0));
    t[b'r' as usize] = Some((0x52, 0));
    t[b's' as usize] = Some((0x53, 0));
    t[b't' as usize] = Some((0x54, 0));
    t[b'u' as usize] = Some((0x55, 0));
    t[b'v' as usize] = Some((0x56, 0));
    t[b'w' as usize] = Some((0x57, 0));
    t[b'x' as usize] = Some((0x58, 0));
    t[b'y' as usize] = Some((0x59, 0));
    t[b'z' as usize] = Some((0x5A, 0));

    // Uppercase letters → (VK, 1) — shift required
    t[b'A' as usize] = Some((0x41, 1));
    t[b'B' as usize] = Some((0x42, 1));
    t[b'C' as usize] = Some((0x43, 1));
    t[b'D' as usize] = Some((0x44, 1));
    t[b'E' as usize] = Some((0x45, 1));
    t[b'F' as usize] = Some((0x46, 1));
    t[b'G' as usize] = Some((0x47, 1));
    t[b'H' as usize] = Some((0x48, 1));
    t[b'I' as usize] = Some((0x49, 1));
    t[b'J' as usize] = Some((0x4A, 1));
    t[b'K' as usize] = Some((0x4B, 1));
    t[b'L' as usize] = Some((0x4C, 1));
    t[b'M' as usize] = Some((0x4D, 1));
    t[b'N' as usize] = Some((0x4E, 1));
    t[b'O' as usize] = Some((0x4F, 1));
    t[b'P' as usize] = Some((0x50, 1));
    t[b'Q' as usize] = Some((0x51, 1));
    t[b'R' as usize] = Some((0x52, 1));
    t[b'S' as usize] = Some((0x53, 1));
    t[b'T' as usize] = Some((0x54, 1));
    t[b'U' as usize] = Some((0x55, 1));
    t[b'V' as usize] = Some((0x56, 1));
    t[b'W' as usize] = Some((0x57, 1));
    t[b'X' as usize] = Some((0x58, 1));
    t[b'Y' as usize] = Some((0x59, 1));
    t[b'Z' as usize] = Some((0x5A, 1));

    // Digits (unshifted)
    t[b'0' as usize] = Some((0x30, 0));
    t[b'1' as usize] = Some((0x31, 0));
    t[b'2' as usize] = Some((0x32, 0));
    t[b'3' as usize] = Some((0x33, 0));
    t[b'4' as usize] = Some((0x34, 0));
    t[b'5' as usize] = Some((0x35, 0));
    t[b'6' as usize] = Some((0x36, 0));
    t[b'7' as usize] = Some((0x37, 0));
    t[b'8' as usize] = Some((0x38, 0));
    t[b'9' as usize] = Some((0x39, 0));

    // Shifted digit symbols
    t[b')' as usize] = Some((0x30, 1)); // shift+0
    t[b'!' as usize] = Some((0x31, 1)); // shift+1
    t[b'@' as usize] = Some((0x32, 1)); // shift+2
    t[b'#' as usize] = Some((0x33, 1)); // shift+3
    t[b'$' as usize] = Some((0x34, 1)); // shift+4
    t[b'%' as usize] = Some((0x35, 1)); // shift+5
    t[b'^' as usize] = Some((0x36, 1)); // shift+6
    t[b'&' as usize] = Some((0x37, 1)); // shift+7
    t[b'*' as usize] = Some((0x38, 1)); // shift+8
    t[b'(' as usize] = Some((0x39, 1)); // shift+9

    // Control characters
    t[0x08] = Some((0x08, 0)); // BS → VK_BACK
    t[0x09] = Some((0x09, 0)); // HT → VK_TAB
    t[0x0D] = Some((0x0D, 0)); // CR → VK_RETURN
    t[0x1B] = Some((0x1B, 0)); // ESC → VK_ESCAPE
    t[b' ' as usize] = Some((0x20, 0)); // VK_SPACE

    // OEM punctuation — unshifted
    t[b';' as usize] = Some((0xBA, 0)); // VK_OEM_1
    t[b'=' as usize] = Some((0xBB, 0)); // VK_OEM_PLUS
    t[b',' as usize] = Some((0xBC, 0)); // VK_OEM_COMMA
    t[b'-' as usize] = Some((0xBD, 0)); // VK_OEM_MINUS
    t[b'.' as usize] = Some((0xBE, 0)); // VK_OEM_PERIOD
    t[b'/' as usize] = Some((0xBF, 0)); // VK_OEM_2
    t[b'`' as usize] = Some((0xC0, 0)); // VK_OEM_3
    t[b'[' as usize] = Some((0xDB, 0)); // VK_OEM_4
    t[b'\\' as usize] = Some((0xDC, 0)); // VK_OEM_5
    t[b']' as usize] = Some((0xDD, 0)); // VK_OEM_6
    t[b'\'' as usize] = Some((0xDE, 0)); // VK_OEM_7

    // OEM punctuation — shifted
    t[b':' as usize] = Some((0xBA, 1)); // shift+;
    t[b'+' as usize] = Some((0xBB, 1)); // shift+=
    t[b'<' as usize] = Some((0xBC, 1)); // shift+,
    t[b'_' as usize] = Some((0xBD, 1)); // shift+-
    t[b'>' as usize] = Some((0xBE, 1)); // shift+.
    t[b'?' as usize] = Some((0xBF, 1)); // shift+/
    t[b'~' as usize] = Some((0xC0, 1)); // shift+`
    t[b'{' as usize] = Some((0xDB, 1)); // shift+[
    t[b'|' as usize] = Some((0xDC, 1)); // shift+\
    t[b'}' as usize] = Some((0xDD, 1)); // shift+]
    t[b'"' as usize] = Some((0xDE, 1)); // shift+'

    t
};

/// VK + shift state → UTF-16 character for ToUnicodeEx.
///
/// Returns the Unicode code point (as u16) for the given virtual key and shift
/// state on a US QWERTY layout. Returns `None` for keys with no printable
/// character mapping (function keys, modifiers, etc.).
///
/// Wine ref: dlls/win32u/input.c — ToUnicodeEx calls the keyboard driver's
///   ToUnicodeEx entry; for US QWERTY layout, letters yield lowercase/uppercase
///   based on shift (and CapsLock, which is out of scope here), digits yield
///   digit or symbol based on shift.
pub fn vk_to_char_shifted(vk: u8, shift: bool) -> Option<u16> {
    let ch: u8 = match (vk, shift) {
        // Letters A-Z: unshifted = lowercase, shifted = uppercase
        (0x41..=0x5A, false) => vk + 0x20, // 'A'(0x41)+0x20 = 'a'(0x61)
        (0x41..=0x5A, true)  => vk,         // already uppercase

        // Digits: unshifted = digit, shifted = symbol
        (0x30, false) => b'0', (0x30, true) => b')',
        (0x31, false) => b'1', (0x31, true) => b'!',
        (0x32, false) => b'2', (0x32, true) => b'@',
        (0x33, false) => b'3', (0x33, true) => b'#',
        (0x34, false) => b'4', (0x34, true) => b'$',
        (0x35, false) => b'5', (0x35, true) => b'%',
        (0x36, false) => b'6', (0x36, true) => b'^',
        (0x37, false) => b'7', (0x37, true) => b'&',
        (0x38, false) => b'8', (0x38, true) => b'*',
        (0x39, false) => b'9', (0x39, true) => b'(',

        // Space and Return (shift does not change them)
        (0x20, _) => b' ',
        (0x0D, _) => b'\r',

        // OEM keys: unshifted / shifted
        (0xBA, false) => b';',  (0xBA, true) => b':',
        (0xBB, false) => b'=',  (0xBB, true) => b'+',
        (0xBC, false) => b',',  (0xBC, true) => b'<',
        (0xBD, false) => b'-',  (0xBD, true) => b'_',
        (0xBE, false) => b'.',  (0xBE, true) => b'>',
        (0xBF, false) => b'/',  (0xBF, true) => b'?',
        (0xC0, false) => b'`',  (0xC0, true) => b'~',
        (0xDB, false) => b'[',  (0xDB, true) => b'{',
        (0xDC, false) => b'\\', (0xDC, true) => b'|',
        (0xDD, false) => b']',  (0xDD, true) => b'}',
        (0xDE, false) => b'\'', (0xDE, true) => b'"',

        _ => return None,
    };
    Some(ch as u16)
}

/// Char → (VK, modifier_flags) for VkKeyScanW.
///
/// `ch` must be an ASCII character (0x00..=0x7F). Returns None for non-ASCII or
/// characters with no US QWERTY mapping.
///
/// Wine ref: dlls/winex11.drv/keyboard.c::X11DRV_VkKeyScanEx —
///   modifier_flags high byte: 0=none, 1=SHIFT (0x0100 added to return), 2=CTRL (0x0200).
pub fn char_to_vk(ch: u16) -> Option<(u8, u8)> {
    if ch > 0x7F {
        return None;
    }
    CHAR_TO_VK[ch as usize]
}

/// Reset all VK state to zero. Used in unit tests and integration test probe gates
/// to ensure a clean keyboard state before each test case.
pub fn test_reset() {
    let mut state = lock();
    *state = [0u8; 256];
}

/// Process-global serializing lock for tests that read/write `VK_STATE`.
///
/// Cargo runs `#[test]` functions within a single test binary in parallel by
/// default. `test_reset()` only briefly locks `VK_STATE` to clear it — it does
/// NOT serialize a whole test case against another. Integration tests in
/// `weave-user32/tests/` that set VK bits, call into APIs that read VK state,
/// and then assert on the result must hold this lock for the full duration of
/// the case to prevent cross-test contamination.
///
/// Always `pub` (rather than `#[cfg(test)]`) because integration tests in
/// `tests/*.rs` are compiled as separate crates linking against the library
/// build of `weave-user32` — `cfg(test)` items in this lib.rs are NOT visible
/// to them. An idle `Mutex<()>` static has negligible cost in production.
pub static TEST_VK_LOCK: Mutex<()> = Mutex::new(());

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

    // ─── VK ↔ scan ↔ char table tests ────────────────────────────────────────

    #[test]
    fn vk_to_vsc_letter_round_trip() {
        // VK_A (0x41) → scan 0x1E → VK_A (generic) via vsc_to_vk.
        let sc = vk_to_vsc(0x41);
        assert_eq!(sc, 0x1E, "VK_A must map to scan 0x1E");
        let vk = vsc_to_vk(sc);
        assert_eq!(vk, 0x41, "scan 0x1E must round-trip to VK_A");
    }

    #[test]
    fn vk_to_vsc_digit_round_trip() {
        // VK_1 (0x31) → scan 0x02 → VK_1 (0x31).
        let sc = vk_to_vsc(0x31);
        assert_eq!(sc, 0x02, "VK_1 must map to scan 0x02");
        let vk = vsc_to_vk(sc);
        assert_eq!(vk, 0x31, "scan 0x02 must round-trip to VK_1");
    }

    #[test]
    fn vk_to_char_returns_uppercase_for_letters() {
        // Wine ref: MAPVK_VK_TO_CHAR always returns the upcase form for letter VKs.
        assert_eq!(vk_to_char(0x41), b'A', "VK_A must yield 'A'");
        assert_eq!(vk_to_char(0x5A), b'Z', "VK_Z must yield 'Z'");
        // Non-letter with no char mapping must return 0.
        assert_eq!(vk_to_char(0x10), 0, "VK_SHIFT has no char mapping");
    }

    #[test]
    fn vk_to_char_oem_unshifted() {
        // VK_OEM_1 (0xBA) = semicolon.
        assert_eq!(vk_to_char(0xBA), b';', "VK_OEM_1 must yield ';'");
        // VK_OEM_MINUS (0xBD) = hyphen.
        assert_eq!(vk_to_char(0xBD), b'-', "VK_OEM_MINUS must yield '-'");
    }

    #[test]
    fn char_to_vk_lowercase_no_shift() {
        // Lowercase 'a' → VK_A with no modifier.
        let (vk, mods) = char_to_vk(b'a' as u16).expect("'a' must have a VK mapping");
        assert_eq!(vk, 0x41, "'a' must map to VK_A");
        assert_eq!(mods, 0, "'a' must require no modifier");
    }

    #[test]
    fn char_to_vk_uppercase_needs_shift() {
        // Uppercase 'A' → VK_A with SHIFT modifier (bit 0).
        let (vk, mods) = char_to_vk(b'A' as u16).expect("'A' must have a VK mapping");
        assert_eq!(vk, 0x41, "'A' must map to VK_A");
        assert_eq!(mods, 1, "'A' must require SHIFT");
        // Non-ASCII returns None.
        assert!(char_to_vk(0x100).is_none(), "non-ASCII must return None");
    }
}
