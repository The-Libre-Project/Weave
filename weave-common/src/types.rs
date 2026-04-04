//! Windows type aliases used across Weave crates.
//!
//! These match the sizes and signedness of the Windows SDK definitions.
//! Using Rust aliases (rather than newtype wrappers) keeps stub signatures
//! simple while making intent clear.

#![allow(non_camel_case_types, dead_code)]

// ── Primitive aliases ─────────────────────────────────────────────────────────

pub type BOOL = i32;
pub type BYTE = u8;
pub type WORD = u16;
pub type DWORD = u32;
pub type LONG = i32;
pub type ULONG = u32;
pub type LONGLONG = i64;
pub type ULONGLONG = u64;
pub type LARGE_INTEGER = i64;
pub type ULARGE_INTEGER = u64;

/// Pointer-sized integer (isize equivalent in Windows SDK).
pub type LONG_PTR = isize;
/// Pointer-sized unsigned integer (usize equivalent in Windows SDK).
pub type ULONG_PTR = usize;
pub type DWORD_PTR = usize;
pub type SIZE_T = usize;

// ── Handle types ──────────────────────────────────────────────────────────────

/// Windows HANDLE — an opaque value. Weave uses small non-zero integers.
pub type HANDLE = usize;
pub type HMODULE = HANDLE;
pub type HINSTANCE = HANDLE;

/// Null handle value.
pub const INVALID_HANDLE_VALUE: HANDLE = usize::MAX; // (HANDLE)-1

// ── Standard handle constants (GetStdHandle argument) ────────────────────────

pub const STD_INPUT_HANDLE: DWORD = 0xFFFFFFF6_u32; // (DWORD)-10
pub const STD_OUTPUT_HANDLE: DWORD = 0xFFFFFFF5_u32; // (DWORD)-11
pub const STD_ERROR_HANDLE: DWORD = 0xFFFFFFF4_u32; // (DWORD)-12

// ── Boolean constants ─────────────────────────────────────────────────────────

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

// ── Memory protection flags (VirtualAlloc / VirtualProtect) ──────────────────

pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_WRITECOPY: DWORD = 0x08;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;

// ── NTSTATUS codes ────────────────────────────────────────────────────────────

pub type NTSTATUS = i32;
pub const STATUS_SUCCESS: NTSTATUS = 0x00000000;
pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC0000001_u32 as i32;
pub const STATUS_NOT_IMPLEMENTED: NTSTATUS = 0xC0000002_u32 as i32;
pub const STATUS_INVALID_HANDLE: NTSTATUS = 0xC0000008_u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000000D_u32 as i32;
pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022_u32 as i32;

// ── Win32 error codes (GetLastError / SetLastError) ───────────────────────────

pub const ERROR_SUCCESS: DWORD = 0;
pub const ERROR_INVALID_HANDLE: DWORD = 6;
pub const ERROR_NOT_SUPPORTED: DWORD = 50;
pub const ERROR_CALL_NOT_IMPLEMENTED: DWORD = 120;
