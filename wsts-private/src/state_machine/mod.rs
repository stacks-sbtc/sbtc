use std::collections::BTreeMap;

use hashbrown::{HashMap, HashSet};
use thiserror::Error;

use crate::{
    common::Signature,
    curve::{ecdsa, point::Point},
    errors::AggregatorError,
    net::DkgFailure,
    state_machine::coordinator::Error as CoordinatorError,
    taproot::SchnorrProof,
};

/// A generic state machine
pub trait StateMachine<S, E> {
    /// Attempt to move the state machine to a new state
    fn move_to(&mut self, state: S) -> Result<(), E>;
    /// Check if the state machine can move to a new state
    fn can_move_to(&self, state: &S) -> Result<(), E>;
}

/// DKG errors
#[derive(Error, Debug, Clone)]
pub enum DkgError {
    /// DKG public timeout
    #[error("DKG public timeout, waiting for {0:?}")]
    DkgPublicTimeout(Vec<u32>),
    /// DKG private timeout
    #[error("DKG private timeout, waiting for {0:?}")]
    DkgPrivateTimeout(Vec<u32>),
    /// DKG end timeout
    #[error("DKG end timeout, waiting for {0:?}")]
    DkgEndTimeout(Vec<u32>),
    /// DKG end failure
    #[error("DKG end failure")]
    DkgEndFailure(HashMap<u32, DkgFailure>),
}

/// Sign errors
#[derive(Error, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SignError {
    /// Nonce timeout
    #[error("Nonce timeout, valid responses from {0:?}, signers {1:?} are malicious")]
    NonceTimeout(Vec<u32>, Vec<u32>),
    /// Insufficient signers
    #[error("Insufficient signers, {0:?} are malicious")]
    InsufficientSigners(Vec<u32>),
    /// Signature aggregator error
    #[error("Signature aggregator error")]
    Aggregator(#[from] AggregatorError),
    /// Coordinator error
    #[error("Coordinator error")]
    Coordinator(#[from] CoordinatorError),
}

/// Result of a DKG or sign operation
#[derive(Debug, Clone)]
pub enum OperationResult {
    /// DKG succeeded with the wrapped public key
    Dkg(Point),
    /// Sign succeeded with the wrapped Signature
    Sign(Signature),
    /// Sign schnorr succeeded with the wrapped SchnorrProof
    SignSchnorr(SchnorrProof),
    /// Sign taproot succeeded with the wrapped SchnorrProof
    SignTaproot(SchnorrProof),
    /// DKG error
    DkgError(DkgError),
    /// Sign error
    SignError(SignError),
}

#[derive(Clone, Default, PartialEq, Eq)]
/// Map of signer_id and key_id to the relevant ecdsa public keys
pub struct PublicKeys {
    /// signer_id -> public key
    pub signers: HashMap<u32, ecdsa::PublicKey>,
    /// key_id -> public key
    pub key_ids: HashMap<u32, ecdsa::PublicKey>,
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
}

impl std::fmt::Debug for PublicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeys")
            .field("signers", &BTreeMap::from_iter(self.signers.iter()))
            .field("key_ids", &BTreeMap::from_iter(self.key_ids.iter()))
            .finish()
    }
}

/// State machine for a simple FROST coordinator
pub mod coordinator;

/// State machine for signers
pub mod signer;
