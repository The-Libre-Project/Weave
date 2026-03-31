//! Weave's top-level error type.

use std::fmt;

/// Errors that Weave can produce when loading or running a PE binary.
#[derive(Debug)]
pub enum WeaveError {
    /// The file could not be read from disk.
    Io(std::io::Error),
    /// PE parsing failed (malformed or unsupported binary format).
    Parse(String),
    /// A required Windows import could not be resolved to a stub.
    UnresolvedImport { dll: String, function: String },
    /// Memory mapping or allocation failed.
    Memory(String),
    /// TEB/PEB initialisation failed.
    TebSetup(String),
}

impl fmt::Display for WeaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WeaveError::Io(e) => write!(f, "I/O error: {e}"),
            WeaveError::Parse(msg) => write!(f, "PE parse error: {msg}"),
            WeaveError::UnresolvedImport { dll, function } => {
                write!(f, "unresolved import: {dll}!{function}")
            }
            WeaveError::Memory(msg) => write!(f, "memory error: {msg}"),
            WeaveError::TebSetup(msg) => write!(f, "TEB setup error: {msg}"),
        }
    }
}

impl std::error::Error for WeaveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WeaveError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for WeaveError {
    fn from(e: std::io::Error) -> Self {
        WeaveError::Io(e)
    }
}
