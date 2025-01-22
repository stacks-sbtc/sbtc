use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::curve::{point::Error as PointError, scalar::Scalar};

#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Errors which can happen during distributed key generation
pub enum DkgError {
    #[error("missing public shares from {0:?}")]
    /// The public shares which were missing
    MissingPublicShares(Vec<u32>),
    #[error("missing private shares from {0:?}")]
    /// The private shares which were missing
    MissingPrivateShares(Vec<u32>),
    #[error("bad public shares {0:?}")]
    /// The public shares that failed to verify or were the wrong size
    BadPublicShares(Vec<u32>),
    #[error("not enough shares {0:?}")]
    /// Not enough shares to complete DKG
    NotEnoughShares(Vec<u32>),
    #[error("bad private shares {0:?}")]
    /// The private shares which failed to verify
    BadPrivateShares(Vec<u32>),
    #[error("point error {0:?}")]
    /// An error during point operations
    Point(PointError),
}

impl From<PointError> for DkgError {
    fn from(e: PointError) -> Self {
        DkgError::Point(e)
    }
}

#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Errors which can happen during signature aggregation
pub enum AggregatorError {
    #[error("bad poly commitment length (expected {0} got {1})")]
    /// The number of polynomial commitments was wrong (no longer used)
    BadPolyCommitmentLen(usize, usize),
    #[error("bad poly commitments {0:?}")]
    /// The polynomial commitments which failed verification or were the wrong size
    BadPolyCommitments(Vec<Scalar>),
    #[error("bad nonce length (expected {0} got {1}")]
    /// The nonce length was the wrong size
    BadNonceLen(usize, usize),
    #[error("bad party keys from {0:?}")]
    /// The party public keys which failed
    BadPartyKeys(Vec<u32>),
    #[error("bad party sigs from {0:?}")]
    /// The party signatures which failed to verify
    BadPartySigs(Vec<u32>),
    #[error("bad group sig")]
    /// The aggregate group signature failed to verify
    BadGroupSig,
}
