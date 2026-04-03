//! Error types for d3d12.dll operations.

use std::fmt;

/// DirectX 12 error codes (HRESULT values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum D3d12Error {
    Ok = 0,
    False = 1,
    InvalidArg = 0x80070057u32 as i32,
    OutOfMemory = 0x8007000Eu32 as i32,
    NotSupported = 0x80004002u32 as i32,
    Fail = 0x80004005u32 as i32,
}

impl fmt::Display for D3d12Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            D3d12Error::Ok => write!(f, "S_OK"),
            D3d12Error::False => write!(f, "S_FALSE"),
            D3d12Error::InvalidArg => write!(f, "E_INVALIDARG"),
            D3d12Error::OutOfMemory => write!(f, "E_OUTOFMEMORY"),
            D3d12Error::NotSupported => write!(f, "E_NOTIMPL"),
            D3d12Error::Fail => write!(f, "E_FAIL"),
        }
    }
}

impl std::error::Error for D3d12Error {}
