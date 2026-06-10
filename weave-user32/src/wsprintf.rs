//! user32.dll wsprintfW / wvsprintfW — limited wide printf for legacy apps.
//!
//! IrfanView's Save As path calls `wsprintfW` before `LoadLibrary("COMDLG32.dll")`.
//! Wine-compatible subset: `%s` in `wsprintfW` is a **wide** string (not ANSI).

use crate::defs::{decode_ansi, decode_wide, MAX_GUEST_STR_LEN};

const WSPRINTF_MAX: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SpecType {
    WideChar,
    AnsiChar,
    WideStr,
    AnsiStr,
    Signed,
    Unsigned,
    Hex,
    Unknown,
}

#[derive(Clone, Copy)]
struct ParsedSpec {
    left_align: bool,
    prefix_hex: bool,
    zero_pad: bool,
    upper_hex: bool,
    width: u32,
    precision: u32,
    ty: SpecType,
}

// Wine ref: dlls/user32/wsprintf.c — WPRINTF_ParseFormatW: in wsprintfW, bare `%s`
// is WPR_WSTRING; `%h s` (short, not wide) is WPR_STRING; `%S` swaps with long/wide.
fn parse_format_spec(fmt: &[u16], start: usize) -> Option<(ParsedSpec, usize)> {
    if start >= fmt.len() || fmt[start] != '%' as u16 {
        return None;
    }
    let mut i = start + 1;
    if i >= fmt.len() {
        return None;
    }
    if fmt[i] == '%' as u16 {
        return None;
    }

    let mut spec = ParsedSpec {
        left_align: false,
        prefix_hex: false,
        zero_pad: false,
        upper_hex: false,
        width: 0,
        precision: 0,
        ty: SpecType::Unknown,
    };

    while i < fmt.len() {
        match fmt[i] as u8 as char {
            '-' => {
                spec.left_align = true;
                i += 1;
            }
            '#' => {
                spec.prefix_hex = true;
                i += 1;
            }
            '0' if spec.width == 0 && spec.precision == 0 => {
                spec.zero_pad = true;
                i += 1;
            }
            '0'..='9' => {
                let mut w = 0u32;
                while i < fmt.len() && (fmt[i] as u8 as char).is_ascii_digit() {
                    w = w * 10 + (fmt[i] as u8 - b'0') as u32;
                    i += 1;
                }
                spec.width = w;
            }
            '.' => {
                i += 1;
                let mut p = 0u32;
                while i < fmt.len() && (fmt[i] as u8 as char).is_ascii_digit() {
                    p = p * 10 + (fmt[i] as u8 - b'0') as u32;
                    i += 1;
                }
                spec.precision = p;
            }
            _ => break,
        }
    }

    let mut flags_short = false;
    let mut flags_long = false;
    let mut flags_wide = false;
    let mut _flags_i64 = false;

    while i < fmt.len() {
        match fmt[i] as u8 as char {
            'h' => {
                flags_short = true;
                i += 1;
            }
            'l' => {
                flags_long = true;
                i += 1;
            }
            'w' => {
                flags_wide = true;
                i += 1;
            }
            'I' if i + 2 < fmt.len() && fmt[i + 1] == '6' as u16 && fmt[i + 2] == '4' as u16 => {
                _flags_i64 = true;
                i += 3;
            }
            'I' => {
                i += 1;
            }
            _ => break,
        }
    }

    if i >= fmt.len() {
        return None;
    }

    let ch = fmt[i] as u8 as char;
    spec.ty = match ch {
        'c' => {
            if flags_short && !flags_wide {
                SpecType::AnsiChar
            } else {
                SpecType::WideChar
            }
        }
        'C' => {
            if flags_long || flags_wide {
                SpecType::WideChar
            } else {
                SpecType::AnsiChar
            }
        }
        'd' | 'i' => SpecType::Signed,
        's' => {
            if flags_short && !flags_wide {
                SpecType::AnsiStr
            } else {
                SpecType::WideStr
            }
        }
        'S' => {
            if flags_long || flags_wide {
                SpecType::WideStr
            } else {
                SpecType::AnsiStr
            }
        }
        'u' => SpecType::Unsigned,
        'p' => {
            spec.width = (std::mem::size_of::<usize>() * 2) as u32;
            spec.zero_pad = true;
            SpecType::Hex
        }
        'X' => {
            spec.upper_hex = true;
            SpecType::Hex
        }
        'x' => SpecType::Hex,
        _ => SpecType::Unknown,
    };

    let consumed = if spec.ty == SpecType::Unknown {
        i - start
    } else {
        i - start + 1
    };
    Some((spec, consumed))
}

fn va_arg_u64(ap: *const u8, slot: &mut usize) -> u64 {
    let v = unsafe { *ap.add(*slot).cast::<u64>() };
    *slot += 8;
    v
}

fn guest_ptr_readable(addr: usize) -> bool {
    if addr < 0x10000 {
        return false;
    }
    let pe_base = weave_core::seh::pe_base();
    let pe_size = weave_core::seh::pe_size();
    if pe_base != 0 && addr >= pe_base && addr < pe_base + pe_size {
        return true;
    }
    if addr >= 0x0000_7f00_0000_0000 {
        return true;
    }
    let top_byte = addr >> 40;
    top_byte == 0x55 || top_byte == 0x56 || top_byte == 0x5a
}

fn read_wide_at_guest(addr: usize) -> Option<u16> {
    if !guest_ptr_readable(addr) {
        return None;
    }
    Some(unsafe { (addr as *const u16).read_unaligned() })
}

fn wide_strlen_guest(addr: usize) -> usize {
    if !guest_ptr_readable(addr) {
        return 0;
    }
    let mut len = 0usize;
    while len < MAX_GUEST_STR_LEN {
        match read_wide_at_guest(addr + len * 2) {
            Some(0) => break,
            Some(_) => len += 1,
            None => return 0,
        }
    }
    len
}

fn push_wide(out: &mut usize, buf: *mut u16, maxlen: usize, ch: u16) -> bool {
    if *out + 1 >= maxlen {
        return false;
    }
    unsafe {
        *buf.add(*out) = ch;
    }
    *out += 1;
    true
}

fn push_wide_run(out: &mut usize, buf: *mut u16, maxlen: usize, src: &[u16]) -> bool {
    for &ch in src {
        if !push_wide(out, buf, maxlen, ch) {
            return false;
        }
    }
    true
}

fn push_pad(out: &mut usize, buf: *mut u16, maxlen: usize, count: u32, ch: u16) -> bool {
    for _ in 0..count {
        if !push_wide(out, buf, maxlen, ch) {
            return false;
        }
    }
    true
}

fn format_u64(mut value: u64, hex: bool, upper: bool) -> Vec<u16> {
    if value == 0 {
        return vec!['0' as u16];
    }
    let mut digits = Vec::new();
    while value > 0 {
        let d = (value % if hex { 16 } else { 10 }) as u8;
        let ch = if hex {
            if d < 10 {
                b'0' + d
            } else if upper {
                b'A' + (d - 10)
            } else {
                b'a' + (d - 10)
            }
        } else {
            b'0' + d
        };
        digits.push(ch as u16);
        value /= if hex { 16 } else { 10 };
    }
    digits.reverse();
    digits
}

fn emit_number(
    out: &mut usize,
    buf: *mut u16,
    maxlen: usize,
    spec: &ParsedSpec,
    negative: bool,
    value: u64,
    hex: bool,
) -> bool {
    let mut digits = format_u64(value, hex, spec.upper_hex);
    if negative {
        digits.insert(0, '-' as u16);
    }
    if spec.prefix_hex && hex {
        let prefix = if spec.upper_hex {
            ['0' as u16, 'X' as u16]
        } else {
            ['0' as u16, 'x' as u16]
        };
        if !push_wide_run(out, buf, maxlen, &prefix) {
            return false;
        }
    }
    let pad_ch = if spec.zero_pad && !spec.left_align {
        '0' as u16
    } else {
        ' ' as u16
    };
    let pad = spec.width.saturating_sub(digits.len() as u32);
    if !spec.left_align && !push_pad(out, buf, maxlen, pad, pad_ch) {
        return false;
    }
    if !push_wide_run(out, buf, maxlen, &digits) {
        return false;
    }
    if spec.left_align && !push_pad(out, buf, maxlen, pad, ' ' as u16) {
        return false;
    }
    true
}

// Wine ref: dlls/user32/wsprintf.c — wvsnprintfW(buf, maxlen, spec, args); maxlen=1024.
fn wvsprintf_w_inner(buffer: *mut u16, format: *const u16, ap: *const u8) -> i32 {
    if buffer.is_null() || format.is_null() || ap.is_null() {
        return -1;
    }

    let fmt = unsafe { decode_wide(format) };
    let fmt_u16: Vec<u16> = fmt.encode_utf16().collect();
    let mut out = 0usize;
    let maxlen = WSPRINTF_MAX;
    let mut va_slot = 0usize;
    let mut pos = 0usize;

    while pos < fmt_u16.len() && out + 1 < maxlen {
        if fmt_u16[pos] != '%' as u16 {
            if !push_wide(&mut out, buffer, maxlen, fmt_u16[pos]) {
                break;
            }
            pos += 1;
            continue;
        }
        if pos + 1 < fmt_u16.len() && fmt_u16[pos + 1] == '%' as u16 {
            if !push_wide(&mut out, buffer, maxlen, '%' as u16) {
                break;
            }
            pos += 2;
            continue;
        }

        let Some((spec, consumed)) = parse_format_spec(&fmt_u16, pos) else {
            if !push_wide(&mut out, buffer, maxlen, fmt_u16[pos]) {
                break;
            }
            pos += 1;
            continue;
        };

        if spec.ty == SpecType::Unknown {
            for j in 0..consumed {
                if pos + j >= fmt_u16.len()
                    || !push_wide(&mut out, buffer, maxlen, fmt_u16[pos + j])
                {
                    break;
                }
            }
            pos += consumed;
            continue;
        }

        match spec.ty {
            SpecType::WideChar => {
                let ch = va_arg_u64(ap, &mut va_slot) as u16;
                let _ = push_wide(&mut out, buffer, maxlen, ch);
            }
            SpecType::AnsiChar => {
                let ch = va_arg_u64(ap, &mut va_slot) as u8 as u16;
                let _ = push_wide(&mut out, buffer, maxlen, ch);
            }
            SpecType::WideStr => {
                let ptr_addr = va_arg_u64(ap, &mut va_slot) as usize;
                let mut len = wide_strlen_guest(ptr_addr);
                if spec.precision > 0 {
                    len = len.min(spec.precision as usize);
                }
                let pad = spec.width.saturating_sub(len as u32);
                if !spec.left_align {
                    let _ = push_pad(&mut out, buffer, maxlen, pad, ' ' as u16);
                }
                for i in 0..len {
                    let Some(ch) = read_wide_at_guest(ptr_addr + i * 2) else {
                        break;
                    };
                    if !push_wide(&mut out, buffer, maxlen, ch) {
                        break;
                    }
                }
                if spec.left_align {
                    let _ = push_pad(&mut out, buffer, maxlen, pad, ' ' as u16);
                }
            }
            SpecType::AnsiStr => {
                let ptr = va_arg_u64(ap, &mut va_slot) as usize as *const u8;
                let s = unsafe { decode_ansi(ptr) };
                let mut wide: Vec<u16> = s.encode_utf16().collect();
                if spec.precision > 0 {
                    wide.truncate(spec.precision as usize);
                }
                let pad = spec.width.saturating_sub(wide.len() as u32);
                if !spec.left_align {
                    let _ = push_pad(&mut out, buffer, maxlen, pad, ' ' as u16);
                }
                let _ = push_wide_run(&mut out, buffer, maxlen, &wide);
                if spec.left_align {
                    let _ = push_pad(&mut out, buffer, maxlen, pad, ' ' as u16);
                }
            }
            SpecType::Signed => {
                let raw = va_arg_u64(ap, &mut va_slot) as i64;
                let negative = raw < 0;
                let mag = if negative { (-raw) as u64 } else { raw as u64 };
                let _ = emit_number(&mut out, buffer, maxlen, &spec, negative, mag, false);
            }
            SpecType::Unsigned => {
                let raw = va_arg_u64(ap, &mut va_slot);
                let _ = emit_number(&mut out, buffer, maxlen, &spec, false, raw, false);
            }
            SpecType::Hex => {
                let raw = va_arg_u64(ap, &mut va_slot);
                let _ = emit_number(&mut out, buffer, maxlen, &spec, false, raw, true);
            }
            SpecType::Unknown => {}
        }

        pos += consumed;
    }

    unsafe {
        *buffer.add(out.min(maxlen - 1)) = 0;
    }

    if out + 1 >= maxlen {
        WSPRINTF_MAX as i32
    } else {
        out as i32
    }
}

/// wvsprintfW — write formatted wide text using an explicit va_list.
///
/// # Safety
/// `buffer` must be writable for at least 1024 `WCHAR`s. `format` must be a valid
/// null-terminated UTF-16 format string. `args` must be a valid Windows-x64 va_list.
// Wine ref: dlls/user32/wsprintf.c — wvsprintfW → wvsnprintfW( buffer, 1024, spec, args ).
pub unsafe extern "win64" fn wvsprintf_w(
    buffer: *mut u16,
    format: *const u16,
    args: *mut core::ffi::c_void,
) -> i32 {
    if args.is_null() {
        return -1;
    }
    wvsprintf_w_inner(buffer, format, args as *const u8)
}

/// wsprintfW — variadic wide sprintf (max 1024 WCHAR output).
///
/// # Safety
/// `buffer` and `format` must satisfy the same constraints as `wvsprintf_w`. Remaining
/// arguments must match `format` and are read via the Windows-x64 va_list spill layout.
// Wine ref: dlls/user32/wsprintf.c — wsprintfW va_start(valist, spec); wvsnprintfW(buf, 1024, spec, valist).
pub unsafe extern "win64" fn wsprintf_w(buffer: *mut u16, format: *const u16) -> i32 {
    if buffer.is_null() || format.is_null() {
        return 0;
    }

    let ap: *const u8;
    core::arch::asm!(
        "mov {ap}, rsp",
        "add {ap}, 24",
        ap = out(reg) ap,
    );

    let fmt_preview = unsafe { decode_wide(format) };
    eprintln!("weave/user32: wsprintfW enter fmt={fmt_preview:?}");
    let ret = wvsprintf_w_inner(buffer, format, ap);
    eprintln!("weave/user32: wsprintfW ret={ret}");
    if ret < 0 {
        0
    } else {
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ws_is_wide_string() {
        let fmt: Vec<u16> = "%s".encode_utf16().collect();
        let (spec, n) = parse_format_spec(&fmt, 0).unwrap();
        assert_eq!(spec.ty, SpecType::WideStr);
        assert_eq!(n, 2);
    }
}
