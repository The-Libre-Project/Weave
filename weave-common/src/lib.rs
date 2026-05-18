//! Shared types for Weave — Windows type aliases, handle constants, and errors.

pub mod com;
pub mod error;
pub mod filetime;
pub mod last_error;
pub mod path;
pub mod socket_event;
pub mod stub;
pub mod types;

pub use error::WeaveError;
pub use filetime::unix_to_filetime;
pub use last_error::{get_last_error, set_last_error};
pub use types::*;
