//! normaliz.dll stubs for Weave — Unicode normalization / IDN conversion.
//!
//! curl.exe imports IdnToAscii and IdnToUnicode for internationalized domain
//! name (IDNA) support. Pure ASCII hostnames are handled by copy-through.
//! Punycode encoding/decoding is not implemented.

#![allow(non_snake_case, clippy::missing_safety_doc)]

/// IdnToAscii — convert an IDN label to ASCII (Punycode).
///
/// Handles pure ASCII input (all chars < 0x80) by copy-through to the output
/// buffer as single bytes. For any input requiring actual Punycode encoding,
/// returns 0 (not implemented). Supports the length-query protocol: if the
/// output pointer is NULL and the output count is 0, returns the number of
/// bytes required for pure ASCII input.
///
/// Returns the number of bytes written on success (ASCII passthrough), 0 on
/// failure (input needs Punycode, invalid parameters, or buffer too small).
///
/// # Safety
/// `lpUnicodeCharStr` must be valid for `cchUnicodeChar` wide characters
/// or null. `lpASCIICharStr` must be valid for `cchASCIIChar` bytes or null.
// Wine ref: dlls/normaliz/normaliz.c — IdnToAscii delegates to
// IdnToAscii_UserDefault; the length-query pattern (NULL output + 0 count)
// returns the required buffer size in chars; returns 0 on any encoding error.
pub unsafe extern "win64" fn IdnToAscii(
    _dwFlags: u32,
    lpUnicodeCharStr: *const u16,
    cchUnicodeChar: i32,
    lpASCIICharStr: *mut u8,
    cchASCIIChar: i32,
) -> i32 {
    if lpUnicodeCharStr.is_null() || cchUnicodeChar <= 0 {
        return 0;
    }
    let len = cchUnicodeChar as usize;

    // Check if all chars are pure ASCII (< 0x80).
    for i in 0..len {
        if unsafe { *lpUnicodeCharStr.add(i) } >= 0x80 {
            return 0; // needs Punycode, not implemented
        }
    }

    // Length query — caller asks for required buffer size.
    if lpASCIICharStr.is_null() && cchASCIIChar == 0 {
        return len as i32;
    }

    // Buffer must be non-null and large enough.
    if lpASCIICharStr.is_null() || (cchASCIIChar as usize) < len {
        return 0;
    }

    // Copy each wide char as a single byte (chars are 0x00–0x7F).
    for i in 0..len {
        unsafe { *lpASCIICharStr.add(i) = *lpUnicodeCharStr.add(i) as u8 };
    }
    len as i32
}

/// IdnToUnicode — convert an ASCII (Punycode) IDN label to Unicode.
///
/// For pure ASCII input (all chars < 0x80), copies each narrow byte to a
/// wide character in the output buffer. For any input requiring actual
/// Punycode decoding, returns 0 (not implemented).
///
/// Returns the number of wide characters written on success, 0 on failure.
///
/// # Safety
/// `lpASCIICharStr` must be valid for `cchASCIIChar` bytes or null.
/// `lpUnicodeCharStr` must be valid for `cchUnicodeChar` wide characters
/// or null.
// Wine ref: dlls/normaliz/normaliz.c — IdnToUnicode is the inverse of
// IdnToAscii; same length-query and error-return contract.
pub unsafe extern "win64" fn IdnToUnicode(
    _dwFlags: u32,
    lpASCIICharStr: *const u8,
    cchASCIIChar: i32,
    lpUnicodeCharStr: *mut u16,
    cchUnicodeChar: i32,
) -> i32 {
    if lpASCIICharStr.is_null() || cchASCIIChar <= 0 {
        return 0;
    }
    let len = cchASCIIChar as usize;

    // Check if all input bytes are pure ASCII (< 0x80).
    for i in 0..len {
        if unsafe { *lpASCIICharStr.add(i) } >= 0x80 {
            return 0; // needs Punycode decoding, not implemented
        }
    }

    // Length query — caller asks for required buffer size.
    if lpUnicodeCharStr.is_null() && cchUnicodeChar == 0 {
        return len as i32;
    }

    // Buffer must be non-null and large enough.
    if lpUnicodeCharStr.is_null() || (cchUnicodeChar as usize) < len {
        return 0;
    }

    // Copy each input byte as a wide char (bytes are 0x00–0x7F).
    for i in 0..len {
        unsafe { *lpUnicodeCharStr.add(i) = *lpASCIICharStr.add(i) as u16 };
    }
    len as i32
}

/// Resolve a normaliz.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("normaliz.dll") {
        return None;
    }
    match func {
        "IdnToAscii" => {
            Some(IdnToAscii as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "IdnToUnicode" => {
            Some(IdnToUnicode as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "IdnToAscii").is_none());
    }

    #[test]
    fn resolve_unknown_function() {
        assert!(resolve("normaliz.dll", "__nonexistent__").is_none());
    }

    #[test]
    fn resolve_idn_to_ascii() {
        assert!(resolve("normaliz.dll", "IdnToAscii").is_some());
    }

    #[test]
    fn resolve_idn_to_unicode() {
        assert!(resolve("normaliz.dll", "IdnToUnicode").is_some());
    }

    #[test]
    fn idn_to_ascii_null_input() {
        assert_eq!(
            unsafe { IdnToAscii(0, std::ptr::null(), 5, std::ptr::null_mut(), 0) },
            0
        );
    }

    #[test]
    fn idn_to_ascii_zero_length() {
        let input = [0x61u16]; // "a"
        assert_eq!(
            unsafe { IdnToAscii(0, input.as_ptr(), 0, std::ptr::null_mut(), 0) },
            0
        );
    }

    #[test]
    fn idn_to_ascii_non_ascii_input() {
        // Non-ASCII char (U+00E9 = é) — needs Punycode, not implemented.
        let input = [0x00E9u16, 0];
        let mut out = [0u8; 16];
        assert_eq!(
            unsafe { IdnToAscii(0, input.as_ptr(), 1, out.as_mut_ptr(), 16) },
            0
        );
    }

    #[test]
    fn idn_to_ascii_ascii_passthrough() {
        let input: Vec<u16> = "hello".encode_utf16().collect();
        let mut out = [0u8; 16];
        let ret =
            unsafe { IdnToAscii(0, input.as_ptr(), input.len() as i32, out.as_mut_ptr(), 16) };
        assert_eq!(ret, 5);
        assert_eq!(&out[..5], b"hello");
    }

    #[test]
    fn idn_to_ascii_buffer_too_small() {
        let input: Vec<u16> = "hello".encode_utf16().collect();
        let mut out = [0u8; 3];
        // Buffer too small (3 < 5) → 0.
        assert_eq!(
            unsafe { IdnToAscii(0, input.as_ptr(), 5, out.as_mut_ptr(), 3) },
            0
        );
    }

    #[test]
    fn idn_to_ascii_null_output_no_query() {
        // NULL output with non-zero cchASCIIChar is not a length query → 0.
        let input: Vec<u16> = "abc".encode_utf16().collect();
        assert_eq!(
            unsafe { IdnToAscii(0, input.as_ptr(), 3, std::ptr::null_mut(), 1) },
            0
        );
    }

    #[test]
    fn idn_to_unicode_null_input() {
        assert_eq!(
            unsafe { IdnToUnicode(0, std::ptr::null(), 5, std::ptr::null_mut(), 0) },
            0
        );
    }

    #[test]
    fn idn_to_unicode_ascii_passthrough() {
        let input = b"hello";
        let mut out = [0u16; 16];
        let ret = unsafe { IdnToUnicode(0, input.as_ptr(), 5, out.as_mut_ptr(), 16) };
        assert_eq!(ret, 5);
        assert_eq!(&out[..5], &[0x68u16, 0x65, 0x6c, 0x6c, 0x6f]);
    }

    #[test]
    fn idn_to_unicode_length_query() {
        let input = b"abc";
        // Output NULL + cch=0 → length query, returns required count.
        let ret = unsafe { IdnToUnicode(0, input.as_ptr(), 3, std::ptr::null_mut(), 0) };
        assert_eq!(ret, 3);
    }

    #[test]
    fn idn_to_unicode_non_ascii_input() {
        let input = [0xC3u8, 0xA9]; // UTF-8 bytes for é
        let mut out = [0u16; 16];
        // Bytes >= 0x80 needs Punycode → 0.
        assert_eq!(
            unsafe { IdnToUnicode(0, input.as_ptr(), 2, out.as_mut_ptr(), 16) },
            0
        );
    }
}
