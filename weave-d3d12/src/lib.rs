//! D3D12 type definitions and error handling for Weave.
//!
//! This crate provides the DirectX 12 type surface used when integrating
//! VKD3D-Proton in Phase 3 (stretch goal) and Phase 4. It does not contain
//! any function implementations — those live in the PE DLLs loaded by
//! weave-core's DLL registry (same pattern as DXVK).

pub mod error;
pub mod types;

pub use error::D3d12Error;
pub use types::*;
