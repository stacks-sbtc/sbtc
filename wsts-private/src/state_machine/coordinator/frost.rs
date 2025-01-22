use hashbrown::{HashMap, HashSet};
use std::collections::BTreeMap;
use tracing::{debug, info};

use crate::{
    common::{PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    curve::point::Point,
    net::{
        DkgBegin, DkgEndBegin, DkgPrivateBegin, DkgPrivateShares, DkgPublicShares, Message,
        NonceRequest, NonceResponse, Packet, Signable, SignatureShareRequest, SignatureType,
    },
    state_machine::{
        coordinator::{
            Config, Coordinator as CoordinatorTrait, Error, SavedState, SignRoundInfo, State,
        },
        OperationResult, SignError, StateMachine,
    },
    taproot::SchnorrProof,
    traits::Aggregator as AggregatorTrait,
};

/// The coordinator for the FROST algorithm
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator<Aggregator: AggregatorTrait> {
    /// common config fields
    config: Config,
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    current_sign_id: u64,
    /// current signing iteration ID
    current_sign_iter_id: u64,
    dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    party_polynomials: HashMap<u32, PolyCommitment>,
    public_nonces: BTreeMap<u32, NonceResponse>,
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    signature: Option<Signature>,
    schnorr_proof: Option<SchnorrProof>,
    /// which signers we're currently waiting on
    pub ids_to_await: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// Aggregator object
    aggregator: Aggregator,
}

impl<Aggregator: AggregatorTrait> Coordinator<Aggregator> {
    /// Process the message inside the passed packet
    pub fn process_message(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        loop {
            match self.state.clone() {
                State::Idle => {
                    // Did we receive a coordinator message?
                    if let Message::DkgBegin(dkg_begin) = &packet.msg {
                        if self.current_dkg_id >= dkg_begin.dkg_id {
                            // We have already processed this DKG round
                            return Ok((None, None));
                        }
                        // Set the current sign id to one before the current message to ensure
                        // that we start the next round at the correct id. (Do this rather
                        // then overwriting afterwards to ensure logging is accurate)
                        self.current_dkg_id = dkg_begin.dkg_id.wrapping_sub(1);
                        let packet = self.start_dkg_round()?;
                        return Ok((Some(packet), None));
                    } else if let Message::NonceRequest(nonce_request) = &packet.msg {
                        if self.current_sign_id >= nonce_request.sign_id {
                            // We have already processed this sign round
                            return Ok((None, None));
                        }
                        // Set the current sign id to one before the current message to ensure
                        // that we start the next round at the correct id. (Do this rather
                        // then overwriting afterwards to ensure logging is accurate)
                        self.current_sign_id = nonce_request.sign_id.wrapping_sub(1);
                        self.current_sign_iter_id = nonce_request.sign_iter_id;
                        let packet = self.start_signing_round(
                            nonce_request.message.as_slice(),
                            nonce_request.signature_type,
                        )?;
                        return Ok((Some(packet), None));
                    }
                    return Ok((None, None));
                }
                State::DkgPublicDistribute => {
                    let packet = self.start_public_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgPublicGather => {
                    self.gather_public_shares(packet)?;
                    if self.state == State::DkgPublicGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgPrivateDistribute => {
                    let packet = self.start_private_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgPrivateGather => {
                    self.gather_private_shares(packet)?;
                    if self.state == State::DkgPrivateGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgEndDistribute => {
                    let packet = self.start_dkg_end()?;
                    return Ok((Some(packet), None));
                }
                State::DkgEndGather => {
                    self.gather_dkg_end(packet)?;
                    if self.state == State::DkgEndGather {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        return Ok((
                            None,
                            Some(OperationResult::Dkg(
                                self.aggregate_public_key
                                    .ok_or(Error::MissingAggregatePublicKey)?,
                            )),
                        ));
                    }
                }
                State::NonceRequest(signature_type) => {
                    let packet = self.request_nonces(signature_type)?;
                    return Ok((Some(packet), None));
                }
                State::NonceGather(signature_type) => {
                    self.gather_nonces(packet, signature_type)?;
                    if self.state == State::NonceGather(signature_type) {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::SigShareRequest(signature_type) => {
                    let packet = self.request_sig_shares(signature_type)?;
                    return Ok((Some(packet), None));
                }
                State::SigShareGather(signature_type) => {
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
                    }
                    if self.state == State::SigShareGather(signature_type) {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        if let SignatureType::Taproot(_) = signature_type {
                            let schnorr_proof = self
                                .schnorr_proof
                                .as_ref()
                                .ok_or(Error::MissingSchnorrProof)?;
                            return Ok((
                                None,
                                Some(OperationResult::SignTaproot(SchnorrProof {
                                    r: schnorr_proof.r,
                                    s: schnorr_proof.s,
                                })),
                            ));
                        } else if let SignatureType::Schnorr = signature_type {
                            let schnorr_proof = self
                                .schnorr_proof
                                .as_ref()
                                .ok_or(Error::MissingSchnorrProof)?;
                            return Ok((
                                None,
                                Some(OperationResult::SignSchnorr(SchnorrProof {
                                    r: schnorr_proof.r,
                                    s: schnorr_proof.s,
                                })),
                            ));
                        } else {
                            let signature =
                                self.signature.as_ref().ok_or(Error::MissingSignature)?;
                            return Ok((
                                None,
                                Some(OperationResult::Sign(Signature {
                                    R: signature.R,
                                    z: signature.z,
                                })),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Ask signers to send DKG public shares
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            "DKG Round {}: Starting Public Share Distribution",
            self.current_dkg_id,
        );
        let dkg_begin = DkgBegin { dkg_id: self.current_dkg_id };

        let dkg_begin_packet = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgBegin"),
            msg: Message::DkgBegin(dkg_begin),
        };
        self.move_to(State::DkgPublicGather)?;
        Ok(dkg_begin_packet)
    }

    /// Ask signers to send DKG private shares
    pub fn start_private_shares(&mut self) -> Result<Packet, Error> {
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            "DKG Round {}: Starting Private Share Distribution",
            self.current_dkg_id
        );
        let dkg_begin = DkgPrivateBegin {
            dkg_id: self.current_dkg_id,
            key_ids: (1..self.config.num_keys + 1).collect(),
            signer_ids: (0..self.config.num_signers).collect(),
        };
        let dkg_private_begin_msg = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgPrivateBegin"),
            msg: Message::DkgPrivateBegin(dkg_begin),
        };
        self.move_to(State::DkgPrivateGather)?;
        Ok(dkg_private_begin_msg)
    }

    /// Ask signers to compute secrets and send DKG end
    pub fn start_dkg_end(&mut self) -> Result<Packet, Error> {
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            "DKG Round {}: Starting DKG End Distribution",
            self.current_dkg_id
        );
        let dkg_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            key_ids: (0..self.config.num_keys).collect(),
            signer_ids: (0..self.config.num_signers).collect(),
        };
        let dkg_end_begin_msg = Packet {
            sig: dkg_begin.sign(&self.config.message_private_key).expect(""),
            msg: Message::DkgEndBegin(dkg_begin),
        };
        self.move_to(State::DkgEndGather)?;
        Ok(dkg_end_begin_msg)
    }

    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            self.ids_to_await.remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }

            debug!(
                "DKG round {} DkgPublicShares from signer {}",
                dkg_public_shares.dkg_id, dkg_public_shares.signer_id
            );
        }

        if self.ids_to_await.is_empty() {
            self.move_to(State::DkgPrivateDistribute)?;
        }
        Ok(())
    }

    fn gather_private_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPrivateShares(dkg_private_shares) = &packet.msg {
            if dkg_private_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_private_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            self.ids_to_await.remove(&dkg_private_shares.signer_id);

            self.dkg_private_shares
                .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());
            info!(
                "DKG round {} DkgPrivateShares from signer {}",
                dkg_private_shares.dkg_id, dkg_private_shares.signer_id
            );
        }

        if self.ids_to_await.is_empty() {
            self.move_to(State::DkgEndDistribute)?;
        }
        Ok(())
    }

    fn gather_dkg_end(&mut self, packet: &Packet) -> Result<(), Error> {
        debug!(
            "DKG Round {}: waiting for Dkg End from signers {:?}",
            self.current_dkg_id, self.ids_to_await
        );
        if let Message::DkgEnd(dkg_end) = &packet.msg {
            if dkg_end.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(dkg_end.dkg_id, self.current_dkg_id));
            }
            self.ids_to_await.remove(&dkg_end.signer_id);
            debug!(
                "DKG_End round {} from signer {}. Waiting on {:?}",
                dkg_end.dkg_id, dkg_end.signer_id, self.ids_to_await
            );
        }

        if self.ids_to_await.is_empty() {
            // Calculate the aggregate public key
            let key = self
                .party_polynomials
                .iter()
                .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

            info!("Aggregate public key: {}", key);
            self.aggregate_public_key = Some(key);
            self.move_to(State::Idle)?;
        }
        Ok(())
    }

    fn request_nonces(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.public_nonces.clear();
        info!(
            "Sign Round {} Nonce round {} Requesting Nonces",
            self.current_sign_id, self.current_sign_iter_id,
        );
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            message: self.message.clone(),
            signature_type,
        };
        let nonce_request_msg = Packet {
            sig: nonce_request
                .sign(&self.config.message_private_key)
                .expect(""),
            msg: Message::NonceRequest(nonce_request),
        };
        self.ids_to_await = (0..self.config.num_signers).collect();
        self.move_to(State::NonceGather(signature_type))?;
        Ok(nonce_request_msg)
    }

    fn gather_nonces(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        if let Message::NonceResponse(nonce_response) = &packet.msg {
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
            }

            self.public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
            self.ids_to_await.remove(&nonce_response.signer_id);
            debug!(
                "Sign round {} nonce round {} NonceResponse from signer {}. Waiting on {:?}",
                nonce_response.sign_id,
                nonce_response.sign_iter_id,
                nonce_response.signer_id,
                self.ids_to_await
            );
        }
        if self.ids_to_await.is_empty() {
            let aggregate_nonce = self.compute_aggregate_nonce();
            info!("Aggregate nonce: {}", aggregate_nonce);

            self.move_to(State::SigShareRequest(signature_type))?;
        }
        Ok(())
    }

    fn request_sig_shares(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.signature_shares.clear();
        info!(
            "Sign Round {} Requesting Signature Shares",
            self.current_sign_id,
        );
        let nonce_responses = (0..self.config.num_signers)
            .map(|i| self.public_nonces[&i].clone())
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            signature_type,
        };
        let sig_share_request_msg = Packet {
            sig: sig_share_request
                .sign(&self.config.message_private_key)
                .expect(""),
            msg: Message::SignatureShareRequest(sig_share_request),
        };
        self.ids_to_await = (0..self.config.num_signers).collect();
        self.move_to(State::SigShareGather(signature_type))?;

        Ok(sig_share_request_msg)
    }

    fn gather_sig_shares(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        if let Message::SignatureShareResponse(sig_share_response) = &packet.msg {
            if sig_share_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    sig_share_response.dkg_id,
                    self.current_dkg_id,
                ));
            }
            if sig_share_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    sig_share_response.sign_id,
                    self.current_sign_id,
                ));
            }
            self.signature_shares.insert(
                sig_share_response.signer_id,
                sig_share_response.signature_shares.clone(),
            );
            self.ids_to_await.remove(&sig_share_response.signer_id);
            debug!(
                "Sign round {} SignatureShareResponse from signer {}. Waiting on {:?}",
                sig_share_response.sign_id, sig_share_response.signer_id, self.ids_to_await
            );
        }
        if self.ids_to_await.is_empty() {
            // Calculate the aggregate signature
            let nonce_responses = (0..self.config.num_signers)
                .map(|i| self.public_nonces[&i].clone())
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = &self
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();

            debug!(
                "aggregator.sign({:?}, {:?}, {:?})",
                self.message,
                nonces.len(),
                shares.len()
            );

            self.aggregator.init(&self.party_polynomials)?;

            if let SignatureType::Taproot(merkle_root) = signature_type {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    shares,
                    &key_ids,
                    merkle_root,
                )?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else if let SignatureType::Schnorr = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_schnorr(&self.message, &nonces, shares, &key_ids)?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, shares, &key_ids)?;
                debug!("Signature ({}, {})", signature.R, signature.z);
                self.signature = Some(signature);
            }

            self.move_to(State::Idle)?;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn compute_aggregate_nonce(&self) -> Point {
        // XXX this needs to be key_ids for v1 and signer_ids for v2
        let party_ids = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.key_ids.clone())
            .collect::<Vec<u32>>();
        let nonces = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.nonces.clone())
            .collect::<Vec<PublicNonce>>();
        let (_, R) = compute::intermediate(&self.message, &party_ids, &nonces);

        R
    }
}

impl<Aggregator: AggregatorTrait> StateMachine<State, Error> for Coordinator<Aggregator> {
    fn move_to(&mut self, state: State) -> Result<(), Error> {
        self.can_move_to(&state)?;
        self.state = state;
        Ok(())
    }

    fn can_move_to(&self, state: &State) -> Result<(), Error> {
        let prev_state = &self.state;
        let accepted = match state {
            State::Idle => true,
            State::DkgPublicDistribute => prev_state == &State::Idle,
            State::DkgPublicGather => {
                prev_state == &State::DkgPublicDistribute || prev_state == &State::DkgPublicGather
            }
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgPrivateGather => {
                prev_state == &State::DkgPrivateDistribute || prev_state == &State::DkgPrivateGather
            }
            State::DkgEndDistribute => prev_state == &State::DkgPrivateGather,
            State::DkgEndGather => prev_state == &State::DkgEndDistribute,
            State::NonceRequest(_) => {
                prev_state == &State::Idle || prev_state == &State::DkgEndGather
            }
            State::NonceGather(signature_type) => {
                prev_state == &State::NonceRequest(*signature_type)
                    || prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareRequest(signature_type) => {
                prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareGather(signature_type) => {
                prev_state == &State::SigShareRequest(*signature_type)
                    || prev_state == &State::SigShareGather(*signature_type)
            }
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

impl<Aggregator: AggregatorTrait> CoordinatorTrait for Coordinator<Aggregator> {
    /// Create a new coordinator
    fn new(config: Config) -> Self {
        Self {
            aggregator: Aggregator::new(config.num_keys, config.threshold),
            config,
            current_dkg_id: 0,
            current_sign_id: 0,
            current_sign_iter_id: 0,
            dkg_public_shares: Default::default(),
            dkg_private_shares: Default::default(),
            party_polynomials: Default::default(),
            public_nonces: Default::default(),
            signature_shares: Default::default(),
            aggregate_public_key: None,
            signature: None,
            schnorr_proof: None,
            message: Default::default(),
            ids_to_await: Default::default(),
            state: State::Idle,
        }
    }

    fn load(state: &SavedState) -> Self {
        Self {
            aggregator: Aggregator::new(state.config.num_keys, state.config.threshold),
            config: state.config.clone(),
            current_dkg_id: state.current_dkg_id,
            current_sign_id: state.current_sign_id,
            current_sign_iter_id: state.current_sign_iter_id,
            dkg_public_shares: state.dkg_public_shares.clone(),
            dkg_private_shares: state.dkg_private_shares.clone(),
            party_polynomials: state.party_polynomials.clone(),
            public_nonces: state.message_nonces[&Vec::new()].public_nonces.clone(),
            signature_shares: state.signature_shares.clone(),
            aggregate_public_key: state.aggregate_public_key,
            signature: state.signature.clone(),
            schnorr_proof: state.schnorr_proof.clone(),
            message: state.message.clone(),
            ids_to_await: state.dkg_wait_signer_ids.clone(),
            state: state.state.clone(),
        }
    }

    fn save(&self) -> SavedState {
        let round_info = SignRoundInfo {
            public_nonces: self.public_nonces.clone(),
            nonce_recv_key_ids: Default::default(),
            sign_recv_key_ids: Default::default(),
            sign_wait_signer_ids: Default::default(),
        };
        let mut message_nonces = BTreeMap::new();

        message_nonces.insert(Vec::new(), round_info);

        SavedState {
            config: self.config.clone(),
            current_dkg_id: self.current_dkg_id,
            current_sign_id: self.current_sign_id,
            current_sign_iter_id: self.current_sign_iter_id,
            dkg_public_shares: self.dkg_public_shares.clone(),
            dkg_private_shares: self.dkg_private_shares.clone(),
            dkg_end_messages: Default::default(),
            party_polynomials: self.party_polynomials.clone(),
            message_nonces,
            signature_shares: self.signature_shares.clone(),
            aggregate_public_key: self.aggregate_public_key,
            signature: self.signature.clone(),
            schnorr_proof: self.schnorr_proof.clone(),
            message: self.message.clone(),
            dkg_wait_signer_ids: self.ids_to_await.clone(),
            state: self.state.clone(),
            dkg_public_start: Default::default(),
            dkg_private_start: Default::default(),
            dkg_end_start: Default::default(),
            nonce_start: Default::default(),
            sign_start: Default::default(),
            malicious_signer_ids: Default::default(),
            malicious_dkg_signer_ids: Default::default(),
        }
    }

    /// Retrieve the config
    fn get_config(&self) -> Config {
        self.config.clone()
    }

    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        packets: &[Packet],
    ) -> Result<(Vec<Packet>, Vec<OperationResult>), Error> {
        let mut outbound_packets = vec![];
        let mut operation_results = vec![];
        for packet in packets {
            let (outbound_packet, operation_result) = self.process_message(packet)?;
            if let Some(outbound_packet) = outbound_packet {
                outbound_packets.push(outbound_packet);
            }
            if let Some(operation_result) = operation_result {
                operation_results.push(operation_result);
            }
        }
        Ok((outbound_packets, operation_results))
    }

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point> {
        self.aggregate_public_key
    }

    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>) {
        self.aggregate_public_key = aggregate_public_key;
    }

    /// Retrieve the current message bytes being signed
    fn get_message(&self) -> Vec<u8> {
        self.message.clone()
    }

    /// Retrive the current state
    fn get_state(&self) -> State {
        self.state.clone()
    }

    /// Start a DKG round
    fn start_dkg_round(&mut self) -> Result<Packet, Error> {
        self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        info!("Starting DKG round {}", self.current_dkg_id);
        self.move_to(State::DkgPublicDistribute)?;
        self.start_public_shares()
    }

    /// Start a signing round
    fn start_signing_round(
        &mut self,
        message: &[u8],
        signature_type: SignatureType,
    ) -> Result<Packet, Error> {
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
        self.message = message.to_vec();
        self.current_sign_id = self.current_sign_id.wrapping_add(1);
        info!("Starting signing round {}", self.current_sign_id);
        self.move_to(State::NonceRequest(signature_type))?;
        self.request_nonces(signature_type)
    }

    // Reset internal state
    fn reset(&mut self) {
        self.state = State::Idle;
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.public_nonces.clear();
        self.signature_shares.clear();
        self.ids_to_await = (0..self.config.num_signers).collect();
    }
}

#[cfg(test)]
mod test {
    use crate::{
        curve::scalar::Scalar,
        net::{DkgBegin, Message, NonceRequest, Packet, SignatureType},
        state_machine::coordinator::{
            frost::Coordinator as FrostCoordinator,
            test::{
                check_signature_shares, coordinator_state_machine, equal_after_save_load,
                new_coordinator, run_dkg_sign, start_dkg_round,
            },
            Config, Coordinator as CoordinatorTrait, State,
        },
        traits::Aggregator as AggregatorTrait,
        v1, v2,
    };
    use rand_core::OsRng;

    #[test]
    fn new_coordinator_v1() {
        new_coordinator::<FrostCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn new_coordinator_v2() {
        new_coordinator::<FrostCoordinator<v2::Aggregator>>();
    }

    #[test]
    fn equal_after_save_load_v1() {
        equal_after_save_load::<FrostCoordinator<v1::Aggregator>, v1::Signer>(2, 2);
    }

    #[test]
    fn equal_after_save_load_v2() {
        equal_after_save_load::<FrostCoordinator<v2::Aggregator>, v2::Signer>(2, 2);
    }

    #[test]
    fn coordinator_state_machine_v1() {
        coordinator_state_machine::<FrostCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn coordinator_state_machine_v2() {
        coordinator_state_machine::<FrostCoordinator<v2::Aggregator>>();
    }

    #[test]
    fn start_dkg_round_v1() {
        start_dkg_round::<FrostCoordinator<v1::Aggregator>>();
    }

    #[test]
    fn start_dkg_round_v2() {
        start_dkg_round::<FrostCoordinator<v2::Aggregator>>();
    }

    #[test]
    fn start_public_shares_v1() {
        start_public_shares::<v1::Aggregator>();
    }

    #[test]
    fn start_public_shares_v2() {
        start_public_shares::<v2::Aggregator>();
    }

    fn start_public_shares<Aggregator: AggregatorTrait>() {
        let mut rng = OsRng;
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FrostCoordinator::<Aggregator>::new(config);

        coordinator.state = State::DkgPublicDistribute; // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(matches!(result.msg, Message::DkgBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn start_private_shares_v1() {
        start_private_shares::<v1::Aggregator>();
    }

    #[test]
    fn start_private_shares_v2() {
        start_private_shares::<v2::Aggregator>();
    }

    fn start_private_shares<Aggregator: AggregatorTrait>() {
        let mut rng = OsRng;
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FrostCoordinator::<Aggregator>::new(config);

        coordinator.state = State::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(matches!(message.msg, Message::DkgPrivateBegin(_)));
        assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn run_dkg_sign_v1() {
        run_dkg_sign::<FrostCoordinator<v1::Aggregator>, v1::Signer>(5, 2);
    }

    #[test]
    fn run_dkg_sign_v2() {
        run_dkg_sign::<FrostCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    fn check_signature_shares_v1() {
        check_signature_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            1,
            SignatureType::Frost,
            vec![1],
        );
        check_signature_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            1,
            SignatureType::Schnorr,
            vec![1],
        );
        check_signature_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            1,
            SignatureType::Taproot(None),
            vec![1],
        );
        check_signature_shares::<FrostCoordinator<v1::Aggregator>, v1::Signer>(
            5,
            1,
            SignatureType::Taproot(Some([23u8; 32])),
            vec![1],
        );
    }

    #[test]
    fn check_signature_shares_v2() {
        check_signature_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Frost,
            vec![0],
        );
        check_signature_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Schnorr,
            vec![0],
        );
        check_signature_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Taproot(None),
            vec![0],
        );
        check_signature_shares::<FrostCoordinator<v2::Aggregator>, v2::Signer>(
            5,
            2,
            SignatureType::Taproot(Some([23u8; 32])),
            vec![0],
        );
    }

    #[test]
    fn process_inbound_messages_v2() {
        run_dkg_sign::<FrostCoordinator<v2::Aggregator>, v2::Signer>(5, 2);
    }

    #[test]
    fn old_round_ids_are_ignored_v1() {
        old_round_ids_are_ignored::<v1::Aggregator>();
    }

    #[test]
    fn old_round_ids_are_ignored_v2() {
        old_round_ids_are_ignored::<v2::Aggregator>();
    }

    fn old_round_ids_are_ignored<Aggregator: AggregatorTrait>() {
        let mut rng = OsRng;
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = FrostCoordinator::<Aggregator>::new(config);
        let id: u64 = 10;
        let old_id = id.saturating_sub(1);
        coordinator.current_dkg_id = id;
        coordinator.current_sign_id = id;
        // Attempt to start an old DKG round
        let (packets, results) = coordinator
            .process_inbound_messages(&[Packet {
                sig: vec![],
                msg: Message::DkgBegin(DkgBegin { dkg_id: old_id }),
            }])
            .unwrap();
        assert!(packets.is_empty());
        assert!(results.is_empty());
        assert_eq!(coordinator.state, State::Idle);
        assert_eq!(coordinator.current_dkg_id, id);

        // Attempt to start the same DKG round
        let (packets, results) = coordinator
            .process_inbound_messages(&[Packet {
                sig: vec![],
                msg: Message::DkgBegin(DkgBegin { dkg_id: id }),
            }])
            .unwrap();
        assert!(packets.is_empty());
        assert!(results.is_empty());
        assert_eq!(coordinator.state, State::Idle);
        assert_eq!(coordinator.current_dkg_id, id);

        // Attempt to start an old Sign round
        let (packets, results) = coordinator
            .process_inbound_messages(&[Packet {
                sig: vec![],
                msg: Message::NonceRequest(NonceRequest {
                    dkg_id: id,
                    sign_id: old_id,
                    message: vec![],
                    sign_iter_id: id,
                    signature_type: SignatureType::Frost,
                }),
            }])
            .unwrap();
        assert!(packets.is_empty());
        assert!(results.is_empty());
        assert_eq!(coordinator.state, State::Idle);
        assert_eq!(coordinator.current_sign_id, id);

        // Attempt to start the same Sign round
        let (packets, results) = coordinator
            .process_inbound_messages(&[Packet {
                sig: vec![],
                msg: Message::NonceRequest(NonceRequest {
                    dkg_id: id,
                    sign_id: id,
                    message: vec![],
                    sign_iter_id: id,
                    signature_type: SignatureType::Frost,
                }),
            }])
            .unwrap();
        assert!(packets.is_empty());
        assert!(results.is_empty());
        assert_eq!(coordinator.state, State::Idle);
        assert_eq!(coordinator.current_sign_id, id);
    }
}
