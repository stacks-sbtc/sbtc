#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

/// Types which are common to both v1 and v2
#[allow(clippy::op_ref)]
pub mod common;
/// Functions to perform various computations needed for v1 and v2
pub mod compute;
/// Errors which are returned from objects and functions
pub mod errors;
/// Network messages
pub mod net;
/// Schnorr utility types
#[allow(clippy::op_ref)]
pub mod schnorr;
/// State machines
#[allow(clippy::result_large_err)]
pub mod state_machine;
/// Functions for doing BIP-340 schnorr proofs and other taproot actions
pub mod taproot;
/// Traits which are used for v1 and v2
pub mod traits;
/// Utilities for hashing and encryption
pub mod util;
/// Version 1 of WSTS, which encapsulates a number of parties using vanilla FROST
#[allow(clippy::op_ref)]
pub mod v1;
/// Version 1 of WSTS, which encapsulates a number of parties using vanilla FROST
#[allow(clippy::op_ref)]
pub mod v2;
/// Shamir secret sharing, using in distributed key generation
pub mod vss;

pub use p256k1 as curve;
