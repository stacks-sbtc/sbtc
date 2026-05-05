use aes_gcm::Error as AesGcmError;
use core::num::TryFromIntError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::curve::{point::Error as PointError, scalar::Scalar};

#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Errors which can happen during distributed key generation
pub enum DkgError {
    #[error("missing public shares from {0:?}")]
    /// The public shares which were missing
    MissingPublicShares(Vec<u32>),
    #[error("missing private shares for/from {0:?}")]
    /// The private shares which were missing
    MissingPrivateShares(Vec<(u32, u32)>),
    #[error("bad public shares {0:?}")]
    /// The public shares that failed to verify or were the wrong size
    BadPublicShares(Vec<u32>),
    #[error("bad private shares {0:?}")]
    /// The private shares which failed to verify
    BadPrivateShares(Vec<u32>),
    #[error("point error {0:?}")]
    /// An error during point operations
    Point(PointError),
    #[error("integer conversion error")]
    /// An error during integer conversion operations
    TryFromInt,
}

impl From<PointError> for DkgError {
    fn from(e: PointError) -> Self {
        DkgError::Point(e)
    }
}

impl From<TryFromIntError> for DkgError {
    fn from(_e: TryFromIntError) -> Self {
        Self::TryFromInt
    }
}

#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
/// Errors which can happen during signature aggregation
pub enum AggregatorError {
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
    #[error("integer conversion error")]
    /// An error during integer conversion operations
    TryFromInt,
}

impl From<TryFromIntError> for AggregatorError {
    fn from(_e: TryFromIntError) -> Self {
        Self::TryFromInt
    }
}

#[derive(Error, Debug, Clone, PartialEq)]
/// Errors which can happen during signature aggregation
pub enum EncryptionError {
    #[error("AES nonce was missing from the buffer")]
    /// AES nonce was missing from the buffer")]
    MissingNonce,
    #[error("AES data was missing from the buffer")]
    /// AES data was missing from the buffer")]
    MissingData,
    #[error("AES GCM error {0:?}")]
    /// Wrapped aes_gcm::Error, an opaque type
    AesGcm(AesGcmError),
}

impl From<AesGcmError> for EncryptionError {
    fn from(e: AesGcmError) -> Self {
        Self::AesGcm(e)
    }
}
