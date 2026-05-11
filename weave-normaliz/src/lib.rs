//! normaliz.dll stubs for Weave — Unicode normalization / IDN conversion.
//!
//! curl.exe imports IdnToAscii and IdnToUnicode for internationalized domain
//! name (IDNA) support. These stubs return 0 (failure). ASCII-only hostnames
//! work via the TLS library directly; IDNA is not supported.

#![allow(unused_variables, non_snake_case, clippy::missing_safety_doc)]

/// IdnToAscii — convert an IDN label to ASCII (Punycode).
///
/// Returns 0 to indicate failure (IDNA not supported).
pub unsafe extern "win64" fn IdnToAscii(
    _dwFlags: u32,
    _lpUnicodeCharStr: usize,
    _cchUnicodeChar: i32,
    _lpASCIICharStr: usize,
    _cchASCIIChar: i32,
) -> i32 {
    0
}

/// IdnToUnicode — convert an ASCII (Punycode) IDN label to Unicode.
///
/// Returns 0 to indicate failure (IDNA not supported).
pub unsafe extern "win64" fn IdnToUnicode(
    _dwFlags: u32,
    _lpASCIICharStr: usize,
    _cchASCIIChar: i32,
    _lpUnicodeCharStr: usize,
    _cchUnicodeChar: i32,
) -> i32 {
    0
}
