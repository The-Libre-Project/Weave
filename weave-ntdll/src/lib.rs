//! ntdll.dll and Universal CRT API-set stubs for Weave.

mod crt;
mod ntdll;

pub use weave_common::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

/// Resolve an ntdll or UCRT import to a stub address.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    match dll.to_ascii_lowercase().as_str() {
        "ntdll.dll" => ntdll::resolve(func),
        s if s.starts_with("api-ms-win-crt-") => crt::resolve(func),
        _ => None,
    }
}
