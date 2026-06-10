//! user32.dll wsprintfW / wvsprintfW — limited wide printf for legacy apps.
//!
//! IrfanView's Save As path calls `wsprintfW` before `LoadLibrary("COMDLG32.dll")`.
//! Full Wine `wvsnprintfW` is deferred; this delegates ASCII-ish wide formats to
//! `vsnprintf` via the Windows-x64 va_list spill layout (same bridge as weave-ucrt).

use crate::defs::decode_wide;
use libc::c_void;

const WSPRINTF_MAX: usize = 1024;

// Linux x86-64 va_list layout — see weave-ucrt `VaListTag` (Windows spill bridge).
#[repr(C)]
struct VaListTag {
    gp_offset: u32,
    fp_offset: u32,
    overflow_arg_area: *mut c_void,
    reg_save_area: *mut c_void,
}

extern "C" {
    fn vsnprintf(s: *mut u8, n: usize, format: *const u8, ap: *mut VaListTag) -> i32;
}

fn encode_utf8_into_wide(s: &str, buf: *mut u16, max_chars: usize) -> i32 {
    if buf.is_null() || max_chars == 0 {
        return 0;
    }
    let mut i = 0usize;
    for ch in s.chars() {
        if i + 1 >= max_chars {
            break;
        }
        let code = ch as u32;
        if code > 0xFFFF {
            continue;
        }
        unsafe {
            *buf.add(i) = code as u16;
        }
        i += 1;
    }
    unsafe {
        *buf.add(i) = 0;
    }
    i as i32
}

fn wide_format_to_utf8(format: *const u16) -> Option<Vec<u8>> {
    let wide = unsafe { decode_wide(format) };
    if wide.is_empty() && !format.is_null() {
        return Some(Vec::new());
    }
    let mut bytes = wide.into_bytes();
    bytes.push(0);
    Some(bytes)
}

// Wine ref: dlls/user32/wsprintf.c — wvsprintfW calls wvsnprintfW(buf, 1024, spec, args);
// overflow returns 1024; wsprintfW is a thin va_start wrapper around wvsnprintfW.
fn wvsprintf_w_inner(buffer: *mut u16, format: *const u16, args: *mut c_void) -> i32 {
    if buffer.is_null() || format.is_null() {
        return -1;
    }
    let Some(fmt_bytes) = wide_format_to_utf8(format) else {
        return -1;
    };
    let mut out = vec![0u8; WSPRINTF_MAX];
    let mut va_tag = VaListTag {
        gp_offset: 48,
        fp_offset: 176,
        overflow_arg_area: args,
        reg_save_area: std::ptr::null_mut(),
    };
    let n = unsafe {
        vsnprintf(
            out.as_mut_ptr(),
            WSPRINTF_MAX,
            fmt_bytes.as_ptr(),
            &mut va_tag,
        )
    };
    if n < 0 {
        return -1;
    }
    let utf8 = if n as usize >= WSPRINTF_MAX {
        String::from_utf8_lossy(&out[..WSPRINTF_MAX.saturating_sub(1)]).into_owned()
    } else {
        String::from_utf8_lossy(&out[..n as usize]).into_owned()
    };
    let written = encode_utf8_into_wide(&utf8, buffer, WSPRINTF_MAX);
    if written < 0 {
        return -1;
    }
    if n as usize >= WSPRINTF_MAX {
        WSPRINTF_MAX as i32
    } else {
        written
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
    args: *mut c_void,
) -> i32 {
    wvsprintf_w_inner(buffer, format, args)
}

/// wsprintfW — variadic wide sprintf (max 1024 WCHAR output).
///
/// # Safety
/// `buffer` and `format` must satisfy the same constraints as `wvsprintf_w`. Remaining
/// arguments must match `format` and are read via the Windows-x64 va_list spill layout.
// Wine ref: dlls/user32/wsprintf.c — wsprintfW va_start(valist, spec); wvsnprintfW(buf, 1024, spec, valist).
pub unsafe extern "win64" fn wsprintf_w(buffer: *mut u16, format: *const u16) -> i32 {
    let args =
        (std::ptr::addr_of!(format) as usize + std::mem::size_of::<*const u16>()) as *mut c_void;
    wvsprintf_w_inner(buffer, format, args)
}
