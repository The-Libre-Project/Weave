//! Shared types for Weave — Windows type aliases, handle constants, and errors.

pub mod error;
pub mod path;
pub mod types;

pub use error::WeaveError;
pub use types::*;
