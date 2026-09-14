//! Shared LocalVault core crate.
//!
//! Holds the platform-independent vault cryptography and format layer.
//! See docs/ARCHITECTURE.md for the target extraction boundary; the `crypto`
//! module is intentionally not public — only the narrow set of types its
//! public interfaces require flow out through `vault::format`.

mod crypto;
pub mod totp;
pub mod vault;
