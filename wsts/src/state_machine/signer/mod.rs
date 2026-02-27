use core::num::TryFromIntError;
use hashbrown::{HashMap, HashSet};
use rand_core::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use tracing::{debug, info, trace, warn};

use crate::{
    common::{
        check_public_shares, validate_key_id, validate_signer_id, PolyCommitment, PublicNonce,
        TupleProof,
    },
    curve::{
        point::{Compressed, Point, G},
        scalar::Scalar,
    },
    errors::{DkgError, EncryptionError},
    net::{
        BadPrivateShare, DkgBegin, DkgEnd, DkgEndBegin, DkgFailure, DkgPrivateBegin,
        DkgPrivateShares, DkgPublicShares, DkgStatus, Message, NonceRequest, NonceResponse, Packet,
        Signable, SignatureShareRequest, SignatureShareResponse, SignatureType,
    },
    state_machine::{PublicKeys, StateMachine},
    traits::{Signer as SignerTrait, SignerState as SignerSavedState},
    util::{decrypt, encrypt, make_shared_secret},
};

#[derive(Debug, Clone, PartialEq)]
/// Signer states
pub enum State {
    /// The signer is idle
    Idle,
    /// The signer is distributing DKG public shares
    DkgPublicDistribute,
    /// The signer is gathering DKG public shares
    DkgPublicGather,
    /// The signer is distributing DKG private shares
    DkgPrivateDistribute,
    /// The signer is gathering DKG private shares
    DkgPrivateGather,
    /// The signer is distributing signature shares
    SignGather,
}

#[derive(thiserror::Error, Clone, Debug)]
/// Config errors for a signer
pub enum ConfigError {
    /// Insufficient keys for the number of signers
    #[error("Insufficient keys for the number of signers")]
    InsufficientKeys,
    /// The threshold was invalid
    #[error("InvalidThreshold")]
    InvalidThreshold,
    /// The signer ID was invalid
    #[error("Invalid signer ID {0}")]
    InvalidSignerId(u32),
    /// The key ID was invalid
    #[error("Invalid key ID {0}")]
    InvalidKeyId(u32),
}

#[derive(thiserror::Error, Clone, Debug)]
/// The error type for a signer
pub enum Error {
    /// Config error
    #[error("Config error {0}")]
    Config(#[from] ConfigError),
    /// The party ID was invalid
    #[error("InvalidPartyID")]
    InvalidPartyID,
    /// A DKG public share was invalid
    #[error("InvalidDkgPublicShares")]
    InvalidDkgPublicShares,
    /// A DKG private share was invalid
    #[error("InvalidDkgPrivateShares")]
    InvalidDkgPrivateShares(Vec<u32>),
    /// A nonce response was invalid
    #[error("InvalidNonceResponse")]
    InvalidNonceResponse,
    /// A signature share was invalid
    #[error("InvalidSignatureShare")]
    InvalidSignatureShare,
    /// A bad state change was made
    #[error("Bad State Change: {0}")]
    BadStateChange(String),
    /// An encryption error occurred
    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("integer conversion error")]
    /// An error during integer conversion operations
    TryFromInt,
}

impl From<TryFromIntError> for Error {
    fn from(_e: TryFromIntError) -> Self {
        Self::TryFromInt
    }
}

/// The saved state required to reconstruct a signer
#[derive(Clone, Debug)]
pub struct SavedState {
    /// current DKG round ID
    pub dkg_id: u64,
    /// current signing round ID
    pub sign_id: u64,
    /// current signing iteration ID
    pub sign_iter_id: u64,
    /// the threshold of the keys needed for a valid signature
    pub threshold: u32,
    /// the threshold of the keys needed for a valid DKG
    pub dkg_threshold: u32,
    /// the total number of signers
    pub total_signers: u32,
    /// the total number of keys
    pub total_keys: u32,
    /// the Signer object
    pub signer: SignerSavedState,
    /// the Signer ID
    pub signer_id: u32,
    /// the current state
    pub state: State,
    /// map of polynomial commitments for each party
    /// party_id => PolyCommitment
    pub commitments: HashMap<u32, PolyCommitment>,
    /// map of decrypted DKG private shares
    /// src_party_id => (dst_key_id => private_share)
    pub decrypted_shares: HashMap<u32, HashMap<u32, Scalar>>,
    /// shared secrets used to decrypt private shares
    /// src_party_id => (signer_id, dh shared key)
    pub decryption_keys: HashMap<u32, (u32, Point)>,
    /// invalid private shares
    /// signer_id => {shared_key, tuple_proof}
    pub invalid_private_shares: HashMap<u32, BadPrivateShare>,
    /// public nonces for this signing round
    pub public_nonces: Vec<PublicNonce>,
    /// the private key used to sign messages sent over the network
    pub network_private_key: Scalar,
    /// the public keys for all signers and coordinator
    pub public_keys: PublicKeys,
    /// the DKG public shares received in this round
    pub dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    /// the DKG private shares received in this round
    pub dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    /// the DKG private begin message received in this round
    pub dkg_private_begin_msg: Option<DkgPrivateBegin>,
    /// the DKG end begin message received in this round
    pub dkg_end_begin_msg: Option<DkgEndBegin>,
}

/// A state machine for a signing round
#[derive(Clone, Debug, PartialEq)]
pub struct Signer<SignerType: SignerTrait> {
    /// current DKG round ID
    pub dkg_id: u64,
    /// current signing round ID
    pub sign_id: u64,
    /// current signing iteration ID
    pub sign_iter_id: u64,
    /// the threshold of the keys needed for a valid signature
    pub threshold: u32,
    /// the threshold of the keys needed for a valid DKG
    pub dkg_threshold: u32,
    /// the total number of signers
    pub total_signers: u32,
    /// the total number of keys
    pub total_keys: u32,
    /// the Signer object
    pub signer: SignerType,
    /// the Signer ID
    pub signer_id: u32,
    /// the current state
    pub state: State,
    /// map of polynomial commitments for each party
    /// party_id => PolyCommitment
    pub commitments: HashMap<u32, PolyCommitment>,
    /// map of decrypted DKG private shares
    /// src_party_id => (dst_key_id => private_share)
    pub decrypted_shares: HashMap<u32, HashMap<u32, Scalar>>,
    /// shared secrets used to decrypt private shares
    /// src_party_id => (signer_id, dh shared key)
    pub decryption_keys: HashMap<u32, (u32, Point)>,
    /// invalid private shares
    /// signer_id => {shared_key, tuple_proof}
    pub invalid_private_shares: HashMap<u32, BadPrivateShare>,
    /// public nonces for this signing round
    pub public_nonces: Vec<PublicNonce>,
    /// the private key used to sign messages sent over the network
    pub network_private_key: Scalar,
    /// the public keys for all signers and coordinator
    pub public_keys: PublicKeys,
    /// the DKG public shares received in this round
    pub dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    /// the DKG private shares received in this round
    pub dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    /// the DKG private begin message received in this round
    pub dkg_private_begin_msg: Option<DkgPrivateBegin>,
    /// the DKG end begin message received in this round
    pub dkg_end_begin_msg: Option<DkgEndBegin>,
}

impl<SignerType: SignerTrait> Signer<SignerType> {
    /// create a Signer
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: RngCore + CryptoRng>(
        threshold: u32,
        dkg_threshold: u32,
        total_signers: u32,
        total_keys: u32,
        signer_id: u32,
        key_ids: Vec<u32>,
        network_private_key: Scalar,
        public_keys: PublicKeys,
        rng: &mut R,
    ) -> Result<Self, Error> {
        if total_signers > total_keys {
            return Err(Error::Config(ConfigError::InsufficientKeys));
        }

        if threshold == 0 || threshold > total_keys {
            return Err(Error::Config(ConfigError::InvalidThreshold));
        }

        if dkg_threshold == 0 || dkg_threshold < threshold {
            return Err(Error::Config(ConfigError::InvalidThreshold));
        }

        if !validate_signer_id(signer_id, total_signers) {
            return Err(Error::Config(ConfigError::InvalidSignerId(signer_id)));
        }

        for key_id in &key_ids {
            if !validate_key_id(*key_id, total_keys) {
                return Err(Error::Config(ConfigError::InvalidKeyId(*key_id)));
            }
        }

        public_keys.validate(total_signers, total_keys)?;

        let signer = SignerType::new(
            signer_id,
            &key_ids,
            total_signers,
            total_keys,
            threshold,
            rng,
        );
        debug!(
            "new Signer for signer_id {} with key_ids {:?}",
            signer_id, &key_ids
        );
        Ok(Self {
            dkg_id: 0,
            sign_id: 1,
            sign_iter_id: 1,
            threshold,
            dkg_threshold,
            total_signers,
            total_keys,
            signer,
            signer_id,
            state: State::Idle,
            commitments: Default::default(),
            decrypted_shares: Default::default(),
            decryption_keys: Default::default(),
            invalid_private_shares: Default::default(),
            public_nonces: vec![],
            network_private_key,
            public_keys,
            dkg_public_shares: Default::default(),
            dkg_private_shares: Default::default(),
            dkg_private_begin_msg: Default::default(),
            dkg_end_begin_msg: Default::default(),
        })
    }

    /// Load a coordinator from the previously saved `state`
    pub fn load(state: &SavedState) -> Self {
        Self {
            dkg_id: state.dkg_id,
            sign_id: state.sign_id,
            sign_iter_id: state.sign_iter_id,
            threshold: state.threshold,
            dkg_threshold: state.dkg_threshold,
            total_signers: state.total_signers,
            total_keys: state.total_keys,
            signer: SignerType::load(&state.signer),
            signer_id: state.signer_id,
            state: state.state.clone(),
            commitments: state.commitments.clone(),
            decrypted_shares: state.decrypted_shares.clone(),
            decryption_keys: state.decryption_keys.clone(),
            invalid_private_shares: state.invalid_private_shares.clone(),
            public_nonces: state.public_nonces.clone(),
            network_private_key: state.network_private_key,
            public_keys: state.public_keys.clone(),
            dkg_public_shares: state.dkg_public_shares.clone(),
            dkg_private_shares: state.dkg_private_shares.clone(),
            dkg_private_begin_msg: state.dkg_private_begin_msg.clone(),
            dkg_end_begin_msg: state.dkg_end_begin_msg.clone(),
        }
    }

    /// Save the state required to reconstruct the coordinator
    pub fn save(&self) -> SavedState {
        SavedState {
            dkg_id: self.dkg_id,
            sign_id: self.sign_id,
            sign_iter_id: self.sign_iter_id,
            threshold: self.threshold,
            dkg_threshold: self.dkg_threshold,
            total_signers: self.total_signers,
            total_keys: self.total_keys,
            signer: self.signer.save(),
            signer_id: self.signer_id,
            state: self.state.clone(),
            commitments: self.commitments.clone(),
            decrypted_shares: self.decrypted_shares.clone(),
            decryption_keys: self.decryption_keys.clone(),
            invalid_private_shares: self.invalid_private_shares.clone(),
            public_nonces: self.public_nonces.clone(),
            network_private_key: self.network_private_key,
            public_keys: self.public_keys.clone(),
            dkg_public_shares: self.dkg_public_shares.clone(),
            dkg_private_shares: self.dkg_private_shares.clone(),
            dkg_private_begin_msg: self.dkg_private_begin_msg.clone(),
            dkg_end_begin_msg: self.dkg_end_begin_msg.clone(),
        }
    }

    /// Reset internal state
    pub fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
        self.dkg_id = dkg_id;
        self.commitments.clear();
        self.decrypted_shares.clear();
        self.decryption_keys.clear();
        self.invalid_private_shares.clear();
        self.public_nonces.clear();
        self.signer.reset_polys(rng);
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_private_begin_msg = None;
        self.dkg_end_begin_msg = None;
        self.state = State::Idle;
    }

    /// Process the slice of packets
    pub fn process_inbound_messages<R: RngCore + CryptoRng>(
        &mut self,
        messages: &[Packet],
        rng: &mut R,
    ) -> Result<Vec<Packet>, Error> {
        let mut responses = vec![];
        for message in messages {
            let outbounds = self.process(&message.msg, rng)?;
            for out in outbounds {
                let msg = Packet {
                    sig: out
                        .sign(&self.network_private_key)
                        .expect("Failed to sign message"),
                    msg: out,
                };
                responses.push(msg);
            }
        }
        Ok(responses)
    }

    /// process the passed incoming message, and return any outgoing messages needed in response
    pub fn process<R: RngCore + CryptoRng>(
        &mut self,
        message: &Message,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let out_msgs = match message {
            Message::DkgBegin(dkg_begin) => self.dkg_begin(dkg_begin, rng),
            Message::DkgPrivateBegin(dkg_private_begin) => {
                self.dkg_private_begin(dkg_private_begin, rng)
            }
            Message::DkgEndBegin(dkg_end_begin) => self.dkg_end_begin(dkg_end_begin),
            Message::DkgPublicShares(dkg_public_shares) => self.dkg_public_share(dkg_public_shares),
            Message::DkgPrivateShares(dkg_private_shares) => {
                self.dkg_private_shares(dkg_private_shares, rng)
            }
            Message::SignatureShareRequest(sign_share_request) => {
                self.sign_share_request(sign_share_request, rng)
            }
            Message::NonceRequest(nonce_request) => self.nonce_request(nonce_request, rng),
            _ => Ok(vec![]), // TODO
        };

        match out_msgs {
            Ok(mut out) => {
                if self.can_dkg_end() {
                    let dkg_end_msgs = self.dkg_ended(rng)?;
                    out.push(dkg_end_msgs);
                    self.move_to(State::Idle)?;
                }
                Ok(out)
            }
            Err(e) => Err(e),
        }
    }

    /// DKG is done so compute secrets
    pub fn dkg_ended<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Message, Error> {
        if !self.can_dkg_end() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadState),
            }));
        }

        // only use the public shares from the DkgEndBegin signers
        let mut missing_public_shares = HashSet::new();
        let mut missing_private_shares = HashSet::new();
        let mut bad_public_shares = HashSet::new();
        let threshold: usize = self.threshold.try_into().unwrap();

        let Some(dkg_end_begin) = &self.dkg_end_begin_msg else {
            // no cached DkgEndBegin message
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadState),
            }));
        };

        // fist check to see if dkg_threshold has been met
        let signer_ids_set: HashSet<u32> = dkg_end_begin
            .signer_ids
            .iter()
            .filter(|&&id| id < self.total_signers)
            .copied()
            .collect::<HashSet<u32>>();
        let mut num_dkg_keys = 0u32;
        for id in &signer_ids_set {
            if let Some(key_ids) = self.public_keys.signer_key_ids.get(id) {
                let len: u32 = key_ids.len().try_into()?;
                num_dkg_keys = num_dkg_keys.saturating_add(len);
            }
        }

        if num_dkg_keys < self.dkg_threshold {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::Threshold),
            }));
        }

        for signer_id in &signer_ids_set {
            if let Some(shares) = self.dkg_public_shares.get(signer_id) {
                if shares.comms.is_empty() {
                    missing_public_shares.insert(*signer_id);
                } else {
                    for (party_id, comm) in shares.comms.iter() {
                        if !check_public_shares(comm, threshold) {
                            bad_public_shares.insert(*signer_id);
                        } else {
                            self.commitments.insert(*party_id, comm.clone());
                        }
                    }
                }
            } else {
                missing_public_shares.insert(*signer_id);
            }
            if let Some(shares) = self.dkg_private_shares.get(signer_id) {
                // signer_id sent shares, but make sure that it sent shares for every one of this signer's key_ids
                if shares.shares.is_empty() {
                    missing_private_shares.insert(*signer_id);
                } else {
                    for dst_key_id in self.signer.get_key_ids() {
                        for (_src_key_id, shares) in &shares.shares {
                            if shares.get(&dst_key_id).is_none() {
                                missing_private_shares.insert(*signer_id);
                            }
                        }
                    }
                }
            } else {
                missing_private_shares.insert(*signer_id);
            }
        }

        if !missing_public_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPublicShares(missing_public_shares)),
            }));
        }

        if !bad_public_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadPublicShares(bad_public_shares)),
            }));
        }

        if !missing_private_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPrivateShares(
                    missing_private_shares,
                )),
            }));
        }

        let dkg_end = if self.invalid_private_shares.is_empty() {
            match self
                .signer
                .compute_secrets(&self.decrypted_shares, &self.commitments)
            {
                Ok(()) => DkgEnd {
                    dkg_id: self.dkg_id,
                    signer_id: self.signer_id,
                    status: DkgStatus::Success,
                },
                Err(dkg_error_map) => {
                    // we've handled everything except BadPrivateShares and Point both of which should map to DkgFailure::BadPrivateShares
                    let mut bad_private_shares = HashMap::new();
                    for (_my_party_id, dkg_error) in dkg_error_map {
                        if let DkgError::BadPrivateShares(party_ids) = dkg_error {
                            for party_id in party_ids {
                                if let Some((party_signer_id, _shared_key)) =
                                    &self.decryption_keys.get(&party_id)
                                {
                                    bad_private_shares.insert(
                                        *party_signer_id,
                                        self.make_bad_private_share(*party_signer_id, rng),
                                    );
                                } else {
                                    warn!("DkgError::BadPrivateShares from party_id {} but no (signer_id, shared_secret) cached", party_id);
                                }
                            }
                        } else {
                            warn!("Got unexpected dkg_error {:?}", dkg_error);
                        }
                    }
                    DkgEnd {
                        dkg_id: self.dkg_id,
                        signer_id: self.signer_id,
                        status: DkgStatus::Failure(DkgFailure::BadPrivateShares(
                            bad_private_shares,
                        )),
                    }
                }
            }
        } else {
            DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadPrivateShares(
                    self.invalid_private_shares.clone(),
                )),
            }
        };

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            status = ?dkg_end.status,
            "sending DkgEnd"
        );

        let dkg_end = Message::DkgEnd(dkg_end);
        Ok(dkg_end)
    }

    /// do we have all DkgPublicShares?
    pub fn public_shares_done(&self) -> bool {
        debug!(
            "public_shares_done state {:?} commitments {}",
            self.state,
            self.commitments.len(),
        );
        self.state == State::DkgPublicGather
            && self.commitments.len() == usize::try_from(self.signer.get_num_parties()).unwrap()
    }

    /// do we have all DkgPublicShares and DkgPrivateShares?
    pub fn can_dkg_end(&self) -> bool {
        debug!(
            "can_dkg_end: state {:?} DkgPrivateBegin {} DkgEndBegin {}",
            self.state,
            self.dkg_private_begin_msg.is_some(),
            self.dkg_end_begin_msg.is_some(),
        );

        if self.state == State::DkgPrivateGather {
            if let Some(dkg_private_begin) = &self.dkg_private_begin_msg {
                // need public shares from active signers
                for signer_id in &dkg_private_begin.signer_ids {
                    if !self.dkg_public_shares.contains_key(signer_id) {
                        debug!(
                            "can_dkg_end: false, missing public shares from signer {}",
                            signer_id
                        );
                        return false;
                    }
                }

                if let Some(dkg_end_begin) = &self.dkg_end_begin_msg {
                    // need private shares from active signers
                    for signer_id in &dkg_end_begin.signer_ids {
                        if !self.dkg_private_shares.contains_key(signer_id) {
                            debug!(
                                "can_dkg_end: false, missing private shares from signer {}",
                                signer_id
                            );
                            return false;
                        }
                    }
                    debug!("can_dkg_end: true");

                    return true;
                }
            }
        } else {
            debug!("can_dkg_end: false, bad state {:?}", self.state);
            return false;
        }
        false
    }

    fn nonce_request<R: RngCore + CryptoRng>(
        &mut self,
        nonce_request: &NonceRequest,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let mut msgs = vec![];
        let signer_id = self.signer_id;
        let key_ids = self.signer.get_key_ids();
        let nonces = self.signer.gen_nonces(rng);

        let response = NonceResponse {
            dkg_id: nonce_request.dkg_id,
            sign_id: nonce_request.sign_id,
            sign_iter_id: nonce_request.sign_iter_id,
            signer_id,
            key_ids,
            nonces,
            message: nonce_request.message.clone(),
        };

        let response = Message::NonceResponse(response);

        info!(
            %signer_id,
            dkg_id = %nonce_request.dkg_id,
            sign_id = %nonce_request.sign_id,
            sign_iter_id = %nonce_request.sign_iter_id,
            "sending NonceResponse"
        );
        msgs.push(response);

        Ok(msgs)
    }

    fn sign_share_request<R: RngCore + CryptoRng>(
        &mut self,
        sign_request: &SignatureShareRequest,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let signer_id_set = sign_request
            .nonce_responses
            .iter()
            .map(|nr| nr.signer_id)
            .collect::<BTreeSet<u32>>();

        // The expected usage is that Signer IDs start at zero and
        // increment by one until self.total_signers - 1. So the checks
        // here should be sufficient for catching empty signer ID sets,
        // duplicate signer IDs, or unknown signer IDs.
        let is_invalid_request = sign_request.nonce_responses.len() != signer_id_set.len()
            || signer_id_set.is_empty()
            || signer_id_set.last() >= Some(&self.total_signers);

        if is_invalid_request {
            warn!("received an invalid SignatureShareRequest");
            return Err(Error::InvalidNonceResponse);
        }

        let nonces = sign_request
            .nonce_responses
            .iter()
            .flat_map(|nr| nr.nonces.clone())
            .collect::<Vec<PublicNonce>>();

        for nonce in &nonces {
            if !nonce.is_valid() {
                warn!(
                    signer_id = %self.signer_id,
                    "received an SignatureShareRequest with invalid nonce"
                );
                return Err(Error::InvalidNonceResponse);
            }
        }

        debug!(signer_id = %self.signer_id, "received a valid SignatureShareRequest");

        if signer_id_set.contains(&self.signer_id) {
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();

            let signer_ids = signer_id_set.into_iter().collect::<Vec<_>>();
            let msg = &sign_request.message;
            let signature_shares = match sign_request.signature_type {
                SignatureType::Taproot(merkle_root) => {
                    self.signer
                        .sign_taproot(msg, &signer_ids, &key_ids, &nonces, merkle_root)
                }
                SignatureType::Schnorr => {
                    self.signer
                        .sign_schnorr(msg, &signer_ids, &key_ids, &nonces)
                }
                SignatureType::Frost => self.signer.sign(msg, &signer_ids, &key_ids, &nonces),
            };

            self.signer.gen_nonces(rng);

            let response = SignatureShareResponse {
                dkg_id: sign_request.dkg_id,
                sign_id: sign_request.sign_id,
                sign_iter_id: sign_request.sign_iter_id,
                signer_id: self.signer_id,
                signature_shares,
            };
            info!(
                signer_id = %self.signer_id,
                dkg_id = %sign_request.dkg_id,
                sign_id = %sign_request.sign_id,
                sign_iter_id = %sign_request.sign_iter_id,
                "sending SignatureShareResponse"
            );

            Ok(vec![Message::SignatureShareResponse(response)])
        } else {
            debug!(signer_id = %self.signer_id, "signer not included in SignatureShareRequest");
            Ok(Vec::new())
        }
    }

    fn dkg_begin<R: RngCore + CryptoRng>(
        &mut self,
        dkg_begin: &DkgBegin,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        self.reset(dkg_begin.dkg_id, rng);
        self.move_to(State::DkgPublicDistribute)?;

        //let _party_state = self.signer.save();

        self.dkg_public_begin(rng)
    }

    fn dkg_public_begin<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let mut msgs = vec![];
        let comms = self.signer.get_poly_commitments(rng);

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            "sending DkgPublicShares"
        );

        let mut public_share = DkgPublicShares {
            dkg_id: self.dkg_id,
            signer_id: self.signer_id,
            comms: Vec::new(),
        };

        for poly in &comms {
            public_share
                .comms
                .push((poly.id.id.get_u32(), poly.clone()));
        }

        let public_share = Message::DkgPublicShares(public_share);
        msgs.push(public_share);

        self.move_to(State::DkgPublicGather)?;
        Ok(msgs)
    }

    fn dkg_private_begin<R: RngCore + CryptoRng>(
        &mut self,
        dkg_private_begin: &DkgPrivateBegin,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let mut msgs = vec![];
        let mut private_shares = DkgPrivateShares {
            dkg_id: self.dkg_id,
            signer_id: self.signer_id,
            shares: Vec::new(),
        };
        let mut active_key_ids = HashSet::new();
        for signer_id in &dkg_private_begin.signer_ids {
            if let Some(key_ids) = self.public_keys.signer_key_ids.get(signer_id) {
                for key_id in key_ids {
                    active_key_ids.insert(*key_id);
                }
            }
        }

        self.dkg_private_begin_msg = Some(dkg_private_begin.clone());
        self.move_to(State::DkgPrivateDistribute)?;

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            "sending DkgPrivateShares"
        );

        trace!(
            "Signer {} shares {:?}",
            self.signer_id,
            &self.signer.get_shares()
        );
        for (key_id, shares) in &self.signer.get_shares() {
            debug!(
                "Signer {} addding dkg private share for key_id {}",
                self.signer_id, key_id
            );
            // encrypt each share for the recipient
            let mut encrypted_shares = HashMap::new();

            for (dst_key_id, private_share) in shares {
                if active_key_ids.contains(dst_key_id) {
                    debug!("encrypting dkg private share for key_id {}", dst_key_id);
                    let compressed =
                        Compressed::from(self.public_keys.key_ids[dst_key_id].to_bytes());
                    // this should not fail as long as the public key above was valid
                    let dst_public_key = Point::try_from(&compressed).unwrap();
                    let shared_secret =
                        make_shared_secret(&self.network_private_key, &dst_public_key);
                    let encrypted_share = encrypt(&shared_secret, &private_share.to_bytes(), rng)?;

                    encrypted_shares.insert(*dst_key_id, encrypted_share);
                }
            }

            private_shares.shares.push((*key_id, encrypted_shares));
        }

        let private_shares = Message::DkgPrivateShares(private_shares);
        msgs.push(private_shares);

        self.move_to(State::DkgPrivateGather)?;
        Ok(msgs)
    }

    /// handle incoming DkgEndBegin
    pub fn dkg_end_begin(&mut self, dkg_end_begin: &DkgEndBegin) -> Result<Vec<Message>, Error> {
        let msgs = vec![];

        self.dkg_end_begin_msg = Some(dkg_end_begin.clone());

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            "received DkgEndBegin"
        );

        Ok(msgs)
    }

    /// handle incoming DkgPublicShares
    pub fn dkg_public_share(
        &mut self,
        dkg_public_shares: &DkgPublicShares,
    ) -> Result<Vec<Message>, Error> {
        debug!(
            "received DkgPublicShares from signer {} {}/{}",
            dkg_public_shares.signer_id,
            self.commitments.len(),
            self.signer.get_num_parties(),
        );

        let signer_id = dkg_public_shares.signer_id;

        // check that the signer_id exists in the config
        let Some(_signer_public_key) = self.public_keys.signers.get(&signer_id) else {
            warn!(%signer_id, "No public key configured");
            return Ok(vec![]);
        };

        for (party_id, _) in &dkg_public_shares.comms {
            if !SignerType::validate_party_id(
                signer_id,
                *party_id,
                &self.public_keys.signer_key_ids,
            ) {
                warn!(%signer_id, %party_id, "signer sent polynomial commitment for wrong party");
                return Ok(vec![]);
            }
        }

        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
        Ok(vec![])
    }

    /// handle incoming DkgPrivateShares
    pub fn dkg_private_shares<R: RngCore + CryptoRng>(
        &mut self,
        dkg_private_shares: &DkgPrivateShares,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        // go ahead and decrypt here, since we know the signer_id and hence the pubkey of the sender
        let src_signer_id = dkg_private_shares.signer_id;

        // check that the signer_id exists in the config
        let Some(_signer_public_key) = self.public_keys.signers.get(&src_signer_id) else {
            warn!(%src_signer_id, "No public key configured");
            return Ok(vec![]);
        };

        for (party_id, _shares) in &dkg_private_shares.shares {
            if !SignerType::validate_party_id(
                src_signer_id,
                *party_id,
                &self.public_keys.signer_key_ids,
            ) {
                warn!(
                    "Signer {} sent a polynomial commitment for party {}",
                    src_signer_id, party_id
                );
                return Ok(vec![]);
            }
        }

        self.dkg_private_shares
            .insert(src_signer_id, dkg_private_shares.clone());

        // make a HashSet of our key_ids so we can quickly query them
        let key_ids: HashSet<u32> = self.signer.get_key_ids().into_iter().collect();
        let compressed = Compressed::from(self.public_keys.signers[&src_signer_id].to_bytes());
        // this should not fail as long as the public key above was valid
        let public_key = Point::try_from(&compressed).unwrap();
        let shared_key = self.network_private_key * public_key;
        let shared_secret = make_shared_secret(&self.network_private_key, &public_key);

        for (src_id, shares) in &dkg_private_shares.shares {
            let mut decrypted_shares = HashMap::new();
            for (dst_key_id, bytes) in shares {
                if key_ids.contains(dst_key_id) {
                    match decrypt(&shared_secret, bytes) {
                        Ok(plain) => match Scalar::try_from(&plain[..]) {
                            Ok(s) => {
                                decrypted_shares.insert(*dst_key_id, s);
                            }
                            Err(e) => {
                                warn!("Failed to parse Scalar for dkg private share from src_id {} to dst_id {}: {:?}", src_id, dst_key_id, e);
                                self.invalid_private_shares.insert(
                                    src_signer_id,
                                    self.make_bad_private_share(src_signer_id, rng),
                                );
                            }
                        },
                        Err(e) => {
                            warn!("Failed to decrypt dkg private share from src_id {} to dst_id {}: {:?}", src_id, dst_key_id, e);
                            self.invalid_private_shares.insert(
                                src_signer_id,
                                self.make_bad_private_share(src_signer_id, rng),
                            );
                        }
                    }
                }
            }
            self.decrypted_shares.insert(*src_id, decrypted_shares);
            self.decryption_keys
                .insert(*src_id, (dkg_private_shares.signer_id, shared_key));
        }
        debug!(
            "received DkgPrivateShares from signer {} {}/{}",
            dkg_private_shares.signer_id,
            self.decrypted_shares.len(),
            self.signer.get_num_parties(),
        );
        Ok(vec![])
    }

    #[allow(non_snake_case)]
    fn make_bad_private_share<R: RngCore + CryptoRng>(
        &self,
        signer_id: u32,
        rng: &mut R,
    ) -> BadPrivateShare {
        let a = self.network_private_key;
        let A = a * G;
        let B = Point::try_from(&Compressed::from(
            self.public_keys.signers[&signer_id].to_bytes(),
        ))
        .unwrap();
        let K = a * B;
        let tuple_proof = TupleProof::new(&a, &A, &B, &K, rng);

        BadPrivateShare {
            shared_key: K,
            tuple_proof,
        }
    }
}

impl<SignerType: SignerTrait> StateMachine<State, Error> for Signer<SignerType> {
    fn move_to(&mut self, state: State) -> Result<(), Error> {
        self.can_move_to(&state)?;
        self.state = state;
        Ok(())
    }

    fn can_move_to(&self, state: &State) -> Result<(), Error> {
        let prev_state = &self.state;
        let accepted = match state {
            State::Idle => true,
            State::DkgPublicDistribute => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgPublicGather
                    || prev_state == &State::DkgPrivateDistribute
            }
            State::DkgPublicGather => prev_state == &State::DkgPublicDistribute,
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgPrivateGather => prev_state == &State::DkgPrivateDistribute,
            State::SignGather => prev_state == &State::Idle,
        };
        if accepted {
            debug!("state change from {:?} to {:?}", prev_state, state);
            Ok(())
        } else {
            Err(Error::BadStateChange(format!(
                "{:?} to {:?}",
                prev_state, state
            )))
        }
    }
}
#[cfg(test)]
/// Test module for signer functionality
pub mod test {
    use crate::{
        common::PolyCommitment,
        curve::{ecdsa, scalar::Scalar},
        net::{DkgBegin, DkgEndBegin, DkgPrivateBegin, DkgPublicShares, DkgStatus, Message},
        schnorr::ID,
        state_machine::{
            signer::{ConfigError, Error, Signer, State as SignerState},
            PublicKeys,
        },
        traits::Signer as SignerTrait,
        util::create_rng,
        v1, v2,
    };

    use hashbrown::HashSet;

    #[test]
    fn bad_config_v1() {
        bad_config::<v1::Signer>();
    }

    #[test]
    fn bad_config_v2() {
        bad_config::<v1::Signer>();
    }

    fn bad_config<SignerType: SignerTrait>() {
        let mut rng = create_rng();

        // more signers than keys
        assert!(matches!(
            Signer::<SignerType>::new(
                1,
                1,
                2,
                1,
                0,
                vec![1],
                Default::default(),
                Default::default(),
                &mut rng,
            ),
            Err(Error::Config(ConfigError::InsufficientKeys))
        ));

        // threshold == 0
        assert!(matches!(
            Signer::<SignerType>::new(
                0,
                1,
                4,
                4,
                0,
                vec![1],
                Default::default(),
                Default::default(),
                &mut rng,
            ),
            Err(Error::Config(ConfigError::InvalidThreshold))
        ));

        // dkg_threshold == 0
        assert!(matches!(
            Signer::<SignerType>::new(
                1,
                0,
                4,
                4,
                0,
                vec![1],
                Default::default(),
                Default::default(),
                &mut rng,
            ),
            Err(Error::Config(ConfigError::InvalidThreshold))
        ));

        // threshold > total_keys
        assert!(matches!(
            Signer::<SignerType>::new(
                5,
                5,
                4,
                4,
                0,
                vec![1],
                Default::default(),
                Default::default(),
                &mut rng,
            ),
            Err(Error::Config(ConfigError::InvalidThreshold))
        ));

        // dkg_threshold < threshold
        assert!(matches!(
            Signer::<SignerType>::new(
                2,
                1,
                4,
                4,
                0,
                vec![1],
                Default::default(),
                Default::default(),
                &mut rng,
            ),
            Err(Error::Config(ConfigError::InvalidThreshold))
        ));

        // signer_id >= num_signers
        assert!(matches!(
            Signer::<SignerType>::new(
                2,
                2,
                4,
                4,
                4,
                vec![1],
                Default::default(),
                Default::default(),
                &mut rng,
            ),
            Err(Error::Config(ConfigError::InvalidSignerId(4)))
        ));

        // key_id == 0
        assert!(matches!(
            Signer::<SignerType>::new(
                2,
                2,
                4,
                4,
                0,
                vec![0],
                Default::default(),
                Default::default(),
                &mut rng,
            ),
            Err(Error::Config(ConfigError::InvalidKeyId(0)))
        ));

        // key_id > num_keys
        assert!(matches!(
            Signer::<SignerType>::new(
                2,
                2,
                4,
                4,
                0,
                vec![5],
                Default::default(),
                Default::default(),
                &mut rng,
            ),
            Err(Error::Config(ConfigError::InvalidKeyId(5)))
        ));

        // public_keys: key_id == 0
    }

    #[test]
    fn dkg_public_share_v1() {
        dkg_public_share::<v1::Signer>();
    }

    #[test]
    fn dkg_public_share_v2() {
        dkg_public_share::<v2::Signer>();
    }

    fn dkg_public_share<SignerType: SignerTrait>() {
        let mut rng = create_rng();
        let private_key = Scalar::random(&mut rng);
        let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
        let mut public_keys: PublicKeys = Default::default();
        let mut key_ids = HashSet::new();

        public_keys.signers.insert(0, public_key.clone());
        public_keys.key_ids.insert(1, public_key.clone());

        key_ids.insert(1);
        public_keys.signer_key_ids.insert(0, key_ids);

        let mut signer =
            Signer::<SignerType>::new(1, 1, 1, 1, 0, vec![1], private_key, public_keys, &mut rng)
                .unwrap();
        let comms: Vec<(u32, PolyCommitment)> = signer
            .signer
            .get_poly_commitments(&mut rng)
            .iter()
            .map(|comm| (comm.id.id.get_u32(), comm.clone()))
            .collect();
        let public_share = DkgPublicShares {
            dkg_id: 0,
            signer_id: 0,
            comms,
        };
        signer.dkg_public_share(&public_share).unwrap();
        assert_eq!(1, signer.dkg_public_shares.len())
    }

    #[test]
    fn public_shares_done_v1() {
        public_shares_done::<v1::Signer>();
    }

    #[test]
    fn public_shares_done_v2() {
        public_shares_done::<v2::Signer>();
    }

    fn public_shares_done<SignerType: SignerTrait>() {
        let mut rng = create_rng();
        let mut signer = Signer::<SignerType>::new(
            1,
            1,
            1,
            1,
            0,
            vec![1],
            Default::default(),
            Default::default(),
            &mut rng,
        )
        .unwrap();
        // publich_shares_done starts out as false
        assert!(!signer.public_shares_done());

        // meet the conditions for all public keys received
        signer.state = SignerState::DkgPublicGather;
        signer.commitments.insert(
            1,
            PolyCommitment {
                id: ID::new(&Scalar::new(), &Scalar::new(), &mut rng),
                poly: vec![],
            },
        );

        // public_shares_done should be true
        assert!(signer.public_shares_done());
    }

    #[test]
    fn can_dkg_end_v1() {
        can_dkg_end::<v1::Signer>();
    }

    #[test]
    fn can_dkg_end_v2() {
        can_dkg_end::<v2::Signer>();
    }

    fn can_dkg_end<SignerType: SignerTrait>() {
        let mut rng = create_rng();
        let private_key = Scalar::random(&mut rng);
        let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
        let mut public_keys: PublicKeys = Default::default();
        let mut key_ids = HashSet::new();

        public_keys.signers.insert(0, public_key.clone());
        public_keys.key_ids.insert(1, public_key.clone());

        key_ids.insert(1);
        public_keys.signer_key_ids.insert(0, key_ids);

        let mut signer =
            Signer::<SignerType>::new(1, 1, 1, 1, 0, vec![1], private_key, public_keys, &mut rng)
                .unwrap();
        // can_dkg_end starts out as false
        assert!(!signer.can_dkg_end());

        // meet the conditions for DKG_END
        let dkg_begin = Message::DkgBegin(DkgBegin { dkg_id: 1 });
        let dkg_public_shares = signer
            .process(&dkg_begin, &mut rng)
            .expect("failed to process DkgBegin");
        let _ = signer
            .process(&dkg_public_shares[0], &mut rng)
            .expect("failed to process DkgPublicShares");
        let dkg_private_begin = Message::DkgPrivateBegin(DkgPrivateBegin {
            dkg_id: 1,
            signer_ids: vec![0],
            key_ids: vec![],
        });
        let dkg_private_shares = signer
            .process(&dkg_private_begin, &mut rng)
            .expect("failed to process DkgBegin");
        let _ = signer
            .process(&dkg_private_shares[0], &mut rng)
            .expect("failed to process DkgPrivateShares");
        let dkg_end_begin = DkgEndBegin {
            dkg_id: 1,
            signer_ids: vec![0],
            key_ids: vec![],
        };
        let _ = signer
            .dkg_end_begin(&dkg_end_begin)
            .expect("failed to process DkgPrivateShares");

        // can_dkg_end should be true
        assert!(signer.can_dkg_end());
    }

    #[test]
    fn dkg_ended_v1() {
        dkg_ended::<v1::Signer>();
    }

    #[test]
    fn dkg_ended_v2() {
        dkg_ended::<v2::Signer>();
    }
    //use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    fn dkg_ended<SignerType: SignerTrait>() {
        /*tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();*/
        let mut rng = create_rng();
        let mut signer = Signer::<SignerType>::new(
            1,
            1,
            1,
            1,
            0,
            vec![1],
            Default::default(),
            Default::default(),
            &mut rng,
        )
        .unwrap();

        if let Ok(Message::DkgEnd(dkg_end)) = signer.dkg_ended(&mut rng) {
            match dkg_end.status {
                DkgStatus::Failure(_) => {}
                _ => panic!("Expected DkgStatus::Failure"),
            }
        } else {
            panic!("Unexpected Error");
        }
    }
}
