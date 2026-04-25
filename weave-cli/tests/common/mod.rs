//! Shared test-harness helpers.
//!
//! This module is included via `mod common;` from each integration test file
//! in `weave-cli/tests/`. Cargo only treats top-level `*.rs` files in `tests/`
//! as test binaries — `tests/common/` is a shared module, not a separate
//! binary, which is why it lives here and not in the main crate.

#![allow(dead_code)] // Each test binary uses a different subset of these helpers.

pub mod capability;
