//! This module defines the common data types and methods used by the Emily API.

/// Api errors.
pub mod error;

/// 6 block confirmations are considered as industry standard for considering that this block
/// will not be reorged. See https://en.bitcoin.it/wiki/Confirmation
pub const NO_REORG_DEPTH: u64 = 6;
