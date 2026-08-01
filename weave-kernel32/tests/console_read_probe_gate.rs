// Probe gate — ReadConsoleW → real line read from the console input fd.
//
// Only runs on Linux x86_64 where the win64 calling convention is supported.
//
// Test plan:
//   1. Validation: non-NULL pInputControl → FALSE + ERROR_INVALID_PARAMETER.
//   2. Validation: NULL lp_buffer → FALSE + ERROR_INVALID_PARAMETER.
//   3. Validation: NULL lp_number_of_chars_read → FALSE + ERROR_INVALID_PARAMETER.
//   4. Validation: nNumberOfCharsToRead > INT_MAX → FALSE + ERROR_NOT_ENOUGH_MEMORY.
//   5. Validation: invalid handle → FALSE + ERROR_INVALID_HANDLE, *count = 0.
//   6. Validation: output console handle (STDOUT) → FALSE + ERROR_INVALID_HANDLE.
//   7. Zero-length read on stdin → TRUE, *count = 0.
//   8. Read path: pipe injected with "hello\n" → TRUE, *count = 6,
//      buffer holds L"hello\n" (trailing newline preserved, Wine contract).
//   9. Read path: request shorter than the line → returns the first
//      nNumberOfCharsToRead characters; remainder stays readable.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use weave_core::handles;
use weave_kernel32::{
    close_handle, create_pipe, get_last_error, read_console_w, set_last_error, write_file,
};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

/// Create a pipe preloaded with `data` and return the read-end console handle.
/// The write end is closed so the reader sees EOF after the payload.
fn pipe_preloaded(data: &[u8]) -> usize {
    let mut read_handle: usize = 0;
    let mut write_handle: usize = 0;
    let ok = unsafe { create_pipe(&mut read_handle, &mut write_handle, 0, 0) };
    assert_eq!(
        ok,
        1,
        "CreatePipe must succeed, got {ok} last_error={}",
        get_last_error()
    );

    let mut written: u32 = 0;
    let wrote = unsafe {
        write_file(
            write_handle,
            data.as_ptr(),
            data.len() as u32,
            &mut written,
            0,
        )
    };
    assert_eq!(
        wrote,
        1,
        "WriteFile to pipe must succeed, got {wrote} last_error={}",
        get_last_error()
    );
    assert_eq!(written, data.len() as u32, "WriteFile must write all bytes");

    assert_eq!(close_handle(write_handle), 1, "close write end");
    read_handle
}

#[test]
fn read_console_w_rejects_non_null_pinput_control() {
    set_last_error(0);
    let mut buf = [0u16; 64];
    let mut count: u32 = 0xDEADBEEF;
    let ret =
        unsafe { read_console_w(handles::STDIN_HANDLE, buf.as_mut_ptr(), 64, &mut count, 0x1) };
    assert_eq!(
        ret, 0,
        "ReadConsoleW must fail with non-NULL pInputControl, got {ret}"
    );
    assert_eq!(get_last_error(), ERROR_INVALID_PARAMETER);
}

#[test]
fn read_console_w_rejects_null_buffer() {
    set_last_error(0);
    let mut count: u32 = 0;
    let ret = unsafe {
        read_console_w(
            handles::STDIN_HANDLE,
            std::ptr::null_mut(),
            64,
            &mut count,
            0,
        )
    };
    assert_eq!(ret, 0, "ReadConsoleW must fail with NULL buffer, got {ret}");
    assert_eq!(get_last_error(), ERROR_INVALID_PARAMETER);
}

#[test]
fn read_console_w_rejects_null_count() {
    set_last_error(0);
    let mut buf = [0u16; 64];
    let ret = unsafe {
        read_console_w(
            handles::STDIN_HANDLE,
            buf.as_mut_ptr(),
            64,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(ret, 0, "ReadConsoleW must fail with NULL count, got {ret}");
    assert_eq!(get_last_error(), ERROR_INVALID_PARAMETER);
}

#[test]
fn read_console_w_rejects_length_over_int_max() {
    set_last_error(0);
    let mut buf = [0u16; 4];
    let mut count: u32 = 0xDEADBEEF;
    let ret = unsafe {
        read_console_w(
            handles::STDIN_HANDLE,
            buf.as_mut_ptr(),
            0x8000_0000,
            &mut count,
            0,
        )
    };
    assert_eq!(
        ret, 0,
        "ReadConsoleW must reject length > INT_MAX, got {ret}"
    );
    assert_eq!(get_last_error(), ERROR_NOT_ENOUGH_MEMORY);
}

#[test]
fn read_console_w_invalid_handle() {
    set_last_error(0);
    let mut buf = [0u16; 64];
    let mut count: u32 = 0xDEADBEEF;
    let ret = unsafe { read_console_w(usize::MAX, buf.as_mut_ptr(), 64, &mut count, 0) };
    assert_eq!(
        ret, 0,
        "ReadConsoleW must fail on invalid handle, got {ret}"
    );
    assert_eq!(get_last_error(), ERROR_INVALID_HANDLE);
    assert_eq!(count, 0, "invalid handle must zero the count");
}

#[test]
fn read_console_w_rejects_output_console_handle() {
    set_last_error(0);
    let mut buf = [0u16; 64];
    let mut count: u32 = 0xDEADBEEF;
    let ret =
        unsafe { read_console_w(handles::STDOUT_HANDLE, buf.as_mut_ptr(), 64, &mut count, 0) };
    assert_eq!(ret, 0, "ReadConsoleW must fail on STDOUT, got {ret}");
    assert_eq!(get_last_error(), ERROR_INVALID_HANDLE);
}

#[test]
fn read_console_w_zero_length_read_succeeds() {
    set_last_error(0);
    let mut buf = [0u16; 4];
    let mut count: u32 = 0xDEADBEEF;
    let ret = unsafe { read_console_w(handles::STDIN_HANDLE, buf.as_mut_ptr(), 0, &mut count, 0) };
    assert_eq!(ret, 1, "zero-length read must return TRUE, got {ret}");
    assert_eq!(count, 0, "zero-length read must set count 0");
}

#[test]
fn read_console_w_reads_line_from_pipe() {
    let handle = pipe_preloaded(b"hello\n");
    let mut buf = [0u16; 64];
    let mut count: u32 = 0;
    let ret = unsafe { read_console_w(handle, buf.as_mut_ptr(), 64, &mut count, 0) };
    assert_eq!(
        ret,
        1,
        "ReadConsoleW must succeed, got {ret} last_error={}",
        get_last_error()
    );
    assert_eq!(count, 6, "expected 6 chars ('hello\\n'), got {count}");
    let expected: [u16; 6] = [
        b'h' as u16,
        b'e' as u16,
        b'l' as u16,
        b'l' as u16,
        b'o' as u16,
        b'\n' as u16,
    ];
    assert_eq!(
        &buf[..6],
        &expected,
        "buffer must hold L\"hello\\n\" (CR/LF preserved)"
    );
    close_handle(handle);
}

#[test]
fn read_console_w_short_read_returns_prefix() {
    let handle = pipe_preloaded(b"hello world\n");
    let mut buf = [0u16; 64];
    let mut count: u32 = 0;
    let ret = unsafe { read_console_w(handle, buf.as_mut_ptr(), 5, &mut count, 0) };
    assert_eq!(
        ret,
        1,
        "ReadConsoleW must succeed, got {ret} last_error={}",
        get_last_error()
    );
    assert_eq!(count, 5, "expected 5 chars ('hello'), got {count}");
    let expected: [u16; 5] = [
        b'h' as u16,
        b'e' as u16,
        b'l' as u16,
        b'l' as u16,
        b'o' as u16,
    ];
    assert_eq!(&buf[..5], &expected);
    close_handle(handle);
}

#[test]
fn read_console_w_decodes_utf8_to_utf16() {
    // 'café\n' — é is 0xC3 0xA9 in UTF-8 → U+00E9 in UTF-16.
    let handle = pipe_preloaded(b"caf\xc3\xa9\n");
    let mut buf = [0u16; 64];
    let mut count: u32 = 0;
    let ret = unsafe { read_console_w(handle, buf.as_mut_ptr(), 64, &mut count, 0) };
    assert_eq!(
        ret,
        1,
        "ReadConsoleW must succeed, got {ret} last_error={}",
        get_last_error()
    );
    assert_eq!(count, 5, "expected 5 chars ('café\\n'), got {count}");
    let expected: [u16; 5] = [b'c' as u16, b'a' as u16, b'f' as u16, 0x00E9, b'\n' as u16];
    assert_eq!(&buf[..5], &expected, "UTF-8 input must decode to UTF-16");
    close_handle(handle);
}
