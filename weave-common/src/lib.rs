//! Shared types for Weave — Windows type aliases, handle constants, and errors.

pub mod error;
pub mod last_error;
pub mod path;
pub mod stub;
pub mod types;

pub use error::WeaveError;
pub use last_error::{get_last_error, set_last_error};
pub use types::*;
