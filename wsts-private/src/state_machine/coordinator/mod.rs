use crate::{
    common::{PolyCommitment, Signature, SignatureShare},
    curve::{point::Point, scalar::Scalar},
    errors::AggregatorError,
    net::{DkgEnd, DkgPrivateShares, DkgPublicShares, NonceResponse, Packet, SignatureType},
    state_machine::{DkgFailure, OperationResult},
    taproot::SchnorrProof,
};
use core::{cmp::PartialEq, fmt::Debug};
use hashbrown::{HashMap, HashSet};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Clone, Default, Debug, PartialEq)]
/// Coordinator states
pub enum State {
    /// The coordinator is idle
    #[default]
    Idle,
    /// The coordinator is asking signers to send public shares
    DkgPublicDistribute,
    /// The coordinator is gathering public shares
    DkgPublicGather,
    /// The coordinator is asking signers to send private shares
    DkgPrivateDistribute,
    /// The coordinator is gathering private shares
    DkgPrivateGather,
    /// The coordinator is asking signers to compute shares and send end
    DkgEndDistribute,
    /// The coordinator is gathering DKG End messages
    DkgEndGather,
    /// The coordinator is requesting nonces
    NonceRequest(SignatureType),
    /// The coordinator is gathering nonces
    NonceGather(SignatureType),
    /// The coordinator is requesting signature shares
    SigShareRequest(SignatureType),
    /// The coordinator is gathering signature shares
    SigShareGather(SignatureType),
}

#[derive(thiserror::Error, Clone, Debug)]
#[allow(clippy::large_enum_variant)]
/// The error type for the coordinator
pub enum Error {
    /// A bad state change was made
    #[error("Bad State Change: {0}")]
    BadStateChange(String),
    /// A bad dkg_id in received message
    #[error("Bad dkg_id: got {0} expected {1}")]
    BadDkgId(u64, u64),
    /// A bad sign_id in received message
    #[error("Bad sign_id: got {0} expected {1}")]
    BadSignId(u64, u64),
    /// A bad sign_iter_id in received message
    #[error("Bad sign_iter_id: got {0} expected {1}")]
    BadSignIterId(u64, u64),
    /// A malicious signer sent the received message
    #[error("Malicious signer {0}")]
    MaliciousSigner(u32),
    /// SignatureAggregator error
    #[error("Aggregator: {0}")]
    Aggregator(AggregatorError),
    /// Schnorr proof failed to verify
    #[error("Schnorr Proof failed to verify")]
    SchnorrProofFailed,
    /// No aggregate public key set
    #[error("No aggregate public key set")]
    MissingAggregatePublicKey,
    /// No schnorr proof set
    #[error("No schnorr proof set")]
    MissingSchnorrProof,
    /// No signature set
    #[error("No signature set")]
    MissingSignature,
    /// Missing message response information for a signing round
    #[error("Missing message nonce information")]
    MissingMessageNonceInfo,
    /// DKG failure from signers
    #[error("DKG failure from signers")]
    DkgFailure(HashMap<u32, DkgFailure>),
    /// Aggregate key does not match supplied party polynomial
    #[error(
        "Aggregate key and computed key from party polynomials mismatch: got {0}, expected {1}"
    )]
    AggregateKeyPolynomialMismatch(Point, Point),
    /// Supplied party polynomial contained duplicate party IDs
    #[error("Supplied party polynomials contained a duplicate party ID")]
    DuplicatePartyId,
}

impl From<AggregatorError> for Error {
    fn from(err: AggregatorError) -> Self {
        Error::Aggregator(err)
    }
}

/// Config fields common to all Coordinators
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Config {
    /// total number of signers
    pub num_signers: u32,
    /// total number of keys
    pub num_keys: u32,
    /// threshold of keys needed to form a valid signature
    pub threshold: u32,
    /// threshold of keys needed to complete DKG (must be >= threshold)
    pub dkg_threshold: u32,
    /// private key used to sign network messages
    pub message_private_key: Scalar,
    /// timeout to gather DkgPublicShares messages
    pub dkg_public_timeout: Option<Duration>,
    /// timeout to gather DkgPrivateShares messages
    pub dkg_private_timeout: Option<Duration>,
    /// timeout to gather DkgEnd messages
    pub dkg_end_timeout: Option<Duration>,
    /// timeout to gather nonces
    pub nonce_timeout: Option<Duration>,
    /// timeout to gather signature shares
    pub sign_timeout: Option<Duration>,
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
    /// ECDSA public keys as Point objects indexed by signer_id
    pub signer_public_keys: HashMap<u32, Point>,
}

impl Config {
    /// Create a new config object with no timeouts
    pub fn new(
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        message_private_key: Scalar,
    ) -> Self {
        Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold: num_keys,
            message_private_key,
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            signer_key_ids: Default::default(),
            signer_public_keys: Default::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Create a new config object with the passed timeouts
    pub fn with_timeouts(
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        dkg_threshold: u32,
        message_private_key: Scalar,
        dkg_public_timeout: Option<Duration>,
        dkg_private_timeout: Option<Duration>,
        dkg_end_timeout: Option<Duration>,
        nonce_timeout: Option<Duration>,
        sign_timeout: Option<Duration>,
        signer_key_ids: HashMap<u32, HashSet<u32>>,
        signer_public_keys: HashMap<u32, Point>,
    ) -> Self {
        Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold,
            message_private_key,
            dkg_public_timeout,
            dkg_private_timeout,
            dkg_end_timeout,
            nonce_timeout,
            sign_timeout,
            signer_key_ids,
            signer_public_keys,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
/// The info for a sign round over specific message bytes
pub struct SignRoundInfo {
    /// the nonce response of a signer id
    pub public_nonces: BTreeMap<u32, NonceResponse>,
    /// which key_ids we've received nonces for this iteration
    pub nonce_recv_key_ids: HashSet<u32>,
    /// which key_ids we're received sig shares for this iteration
    pub sign_recv_key_ids: HashSet<u32>,
    /// which signer_ids we're expecting sig shares from this iteration
    pub sign_wait_signer_ids: HashSet<u32>,
}

/// The saved state required to reconstruct a coordinator
#[derive(Default, Clone, Debug, PartialEq)]
pub struct SavedState {
    /// common config fields
    pub config: Config,
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    pub current_sign_id: u64,
    /// current signing iteration ID
    pub current_sign_iter_id: u64,
    /// map of DkgPublicShares indexed by signer ID
    pub dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    /// map of DkgPrivateShares indexed by signer ID
    pub dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    /// map of DkgEnd indexed by signer ID
    pub dkg_end_messages: BTreeMap<u32, DkgEnd>,
    /// the current view of a successful DKG's participants' commitments
    pub party_polynomials: HashMap<u32, PolyCommitment>,
    /// map of SignatureShare indexed by signer ID
    pub signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    /// map of SignRoundInfo indexed by message bytes
    pub message_nonces: BTreeMap<Vec<u8>, SignRoundInfo>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    /// current Signature
    pub signature: Option<Signature>,
    /// current SchnorrProof
    pub schnorr_proof: Option<SchnorrProof>,
    /// which signers we're currently waiting on for DKG
    pub dkg_wait_signer_ids: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// start time for NonceRequest
    pub nonce_start: Option<Instant>,
    /// start time for DkgBegin
    pub dkg_public_start: Option<Instant>,
    /// start time for DkgPrivateBegin
    pub dkg_private_start: Option<Instant>,
    /// start time for DkgEndBegin
    pub dkg_end_start: Option<Instant>,
    /// start time for SignatureShareRequest
    pub sign_start: Option<Instant>,
    /// set of malicious signers during signing round
    pub malicious_signer_ids: HashSet<u32>,
    /// set of malicious signers during dkg round
    pub malicious_dkg_signer_ids: HashSet<u32>,
}

/// Coordinator trait for handling the coordination of DKG and sign messages
pub trait Coordinator: Clone + Debug + PartialEq {
    /// Create a new Coordinator
    fn new(config: Config) -> Self;

    /// Load a coordinator from the previously saved `state`
    fn load(state: &SavedState) -> Self;

    /// Save the state required to reconstruct the coordinator
    fn save(&self) -> SavedState;

    /// Retrieve the config
    fn get_config(&self) -> Config;

    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        packets: &[Packet],
    ) -> Result<(Vec<Packet>, Vec<OperationResult>), Error>;

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Option<Point>;

    /// Set the aggregate public key
    fn set_aggregate_public_key(&mut self, aggregate_public_key: Option<Point>);

    /// Retrieve the current message bytes being signed
    fn get_message(&self) -> Vec<u8>;

    /// Retrive the current state
    fn get_state(&self) -> State;

    /// Trigger a DKG round
    fn start_dkg_round(&mut self) -> Result<Packet, Error>;

    /// Trigger a signing round
    fn start_signing_round(
        &mut self,
        message: &[u8],
        signature_type: SignatureType,
    ) -> Result<Packet, Error>;

    /// Reset internal state
    fn reset(&mut self);
}

/// The coordinator for the FROST algorithm
pub mod frost;

/// The coordinator for the FIRE algorithm
pub mod fire;

#[allow(missing_docs)]
pub mod test {
    use hashbrown::{HashMap, HashSet};
    use rand_core::OsRng;
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use crate::{
        common::SignatureShare,
        compute,
        curve::{ecdsa, point::Point, scalar::Scalar},
        errors::AggregatorError,
        net::{Message, Packet, SignatureShareResponse, SignatureType},
        state_machine::{
            coordinator::{Config, Coordinator as CoordinatorTrait, Error, State},
            signer::Signer,
            OperationResult, PublicKeys, SignError, StateMachine,
        },
        traits::Signer as SignerTrait,
    };

    static mut LOG_INIT: AtomicBool = AtomicBool::new(false);

    pub fn new_coordinator<Coordinator: CoordinatorTrait>() {
        let mut rng = OsRng;
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let coordinator = Coordinator::new(config.clone());

        assert_eq!(coordinator.get_config().num_signers, config.num_signers);
        assert_eq!(coordinator.get_config().num_keys, config.num_keys);
        assert_eq!(coordinator.get_config().threshold, config.threshold);
        assert_eq!(
            coordinator.get_config().message_private_key,
            config.message_private_key
        );
        assert_eq!(coordinator.get_state(), State::Idle);
    }

    pub fn coordinator_state_machine<Coordinator: CoordinatorTrait + StateMachine<State, Error>>() {
        let mut rng = OsRng;
        let config = Config::new(3, 3, 3, Scalar::random(&mut rng));
        let mut coordinator = Coordinator::new(config);
        assert!(coordinator.can_move_to(&State::DkgPublicDistribute).is_ok());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPublicDistribute).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_ok());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPublicGather).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_ok());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_ok());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPrivateDistribute).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_ok());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPrivateGather).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPrivateGather).is_ok());
        assert!(coordinator.can_move_to(&State::DkgEndDistribute).is_ok());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgEndDistribute).unwrap();
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_ok());

        coordinator.move_to(State::DkgEndGather).unwrap();
        assert!(coordinator.can_move_to(&State::Idle).is_ok());
    }

    pub fn start_dkg_round<Coordinator: CoordinatorTrait>() {
        let mut rng = OsRng;
        let config = Config::new(10, 40, 28, Scalar::random(&mut rng));
        let mut coordinator = Coordinator::new(config);
        let result = coordinator.start_dkg_round();

        assert!(result.is_ok());
        if let Message::DkgBegin(dkg_begin) = result.unwrap().msg {
            assert_eq!(dkg_begin.dkg_id, 1);
        } else {
            panic!("Bad dkg_id");
        }
        assert_eq!(coordinator.get_state(), State::DkgPublicGather);
    }

    pub fn setup<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<Coordinator>, Vec<Signer<SignerType>>) {
        setup_with_timeouts::<Coordinator, SignerType>(
            num_signers,
            keys_per_signer,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[allow(static_mut_refs)]
    pub fn setup_with_timeouts<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
        dkg_public_timeout: Option<Duration>,
        dkg_private_timeout: Option<Duration>,
        dkg_end_timeout: Option<Duration>,
        nonce_timeout: Option<Duration>,
        sign_timeout: Option<Duration>,
    ) -> (Vec<Coordinator>, Vec<Signer<SignerType>>) {
        unsafe {
            if let Ok(false) =
                LOG_INIT.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            {
                tracing_subscriber::registry()
                    .with(fmt::layer())
                    .with(EnvFilter::from_default_env())
                    .init()
            }
        }

        let mut rng = OsRng;
        let num_keys = num_signers * keys_per_signer;
        let threshold = (num_keys * 7) / 10;
        let dkg_threshold = (num_keys * 9) / 10;
        let key_pairs = (0..num_signers)
            .map(|_| {
                let private_key = Scalar::random(&mut rng);
                let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
                (private_key, public_key)
            })
            .collect::<Vec<(Scalar, ecdsa::PublicKey)>>();
        let mut key_id: u32 = 1;
        let mut signer_ids_map = HashMap::new();
        let mut signer_key_ids = HashMap::new();
        let mut signer_key_ids_set = HashMap::new();
        let mut signer_public_keys = HashMap::new();
        let mut key_ids_map = HashMap::new();
        for (i, (private_key, public_key)) in key_pairs.iter().enumerate() {
            let mut key_ids = Vec::new();
            let mut key_ids_set = HashSet::new();
            for _ in 0..keys_per_signer {
                key_ids_map.insert(key_id, *public_key);
                key_ids.push(key_id);
                key_ids_set.insert(key_id);
                key_id += 1;
            }
            signer_ids_map.insert(i as u32, *public_key);
            signer_key_ids.insert(i as u32, key_ids);
            signer_key_ids_set.insert(i as u32, key_ids_set);
            signer_public_keys.insert(i as u32, Point::from(private_key));
        }
        let public_keys = PublicKeys {
            signers: signer_ids_map,
            key_ids: key_ids_map,
            signer_key_ids: signer_key_ids_set.clone(),
        };

        let signers = key_pairs
            .iter()
            .enumerate()
            .map(|(signer_id, (private_key, _public_key))| {
                Signer::<SignerType>::new(
                    threshold,
                    dkg_threshold,
                    num_signers,
                    num_keys,
                    signer_id as u32,
                    signer_key_ids[&(signer_id as u32)].clone(),
                    *private_key,
                    public_keys.clone(),
                )
                .unwrap()
            })
            .collect::<Vec<Signer<SignerType>>>();
        let coordinators = key_pairs
            .into_iter()
            .map(|(private_key, _public_key)| {
                let config = Config::with_timeouts(
                    num_signers,
                    num_keys,
                    threshold,
                    dkg_threshold,
                    private_key,
                    dkg_public_timeout,
                    dkg_private_timeout,
                    dkg_end_timeout,
                    nonce_timeout,
                    sign_timeout,
                    signer_key_ids_set.clone(),
                    signer_public_keys.clone(),
                );
                Coordinator::new(config)
            })
            .collect::<Vec<Coordinator>>();
        (coordinators, signers)
    }

    /// Helper function for feeding messages back from the processor into the signing rounds and coordinators
    pub fn feedback_messages<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        coordinators: &mut [Coordinator],
        signers: &mut [Signer<SignerType>],
        messages: &[Packet],
    ) -> (Vec<Packet>, Vec<OperationResult>) {
        feedback_mutated_messages(coordinators, signers, messages, |_signer, msgs| msgs)
    }
    /// Helper function for feeding mutated messages back from the processor into the signing rounds and coordinators
    pub fn feedback_mutated_messages<
        Coordinator: CoordinatorTrait,
        SignerType: SignerTrait,
        F: Fn(&Signer<SignerType>, Vec<Packet>) -> Vec<Packet>,
    >(
        coordinators: &mut [Coordinator],
        signers: &mut [Signer<SignerType>],
        messages: &[Packet],
        signer_mutator: F,
    ) -> (Vec<Packet>, Vec<OperationResult>) {
        let mut inbound_messages = vec![];
        let mut feedback_messages = vec![];
        for signer in signers.iter_mut() {
            let outbound_messages = signer.process_inbound_messages(messages).unwrap();
            let outbound_messages = signer_mutator(signer, outbound_messages);
            feedback_messages.extend_from_slice(outbound_messages.as_slice());
            inbound_messages.extend(outbound_messages);
        }
        for signer in signers.iter_mut() {
            let outbound_messages = signer.process_inbound_messages(&feedback_messages).unwrap();
            inbound_messages.extend(outbound_messages);
        }
        for coordinator in coordinators.iter_mut() {
            // Process all coordinator messages, but don't bother with propogating these results
            let _ = coordinator.process_inbound_messages(messages).unwrap();
        }
        let mut results = vec![];
        let mut messages = vec![];
        for (i, coordinator) in coordinators.iter_mut().enumerate() {
            let (outbound_messages, outbound_results) = coordinator
                .process_inbound_messages(&inbound_messages)
                .unwrap();
            // Only propogate a single coordinator's messages and results
            if i == 0 {
                messages.extend(outbound_messages);
                results.extend(outbound_results);
            }
        }
        (messages, results)
    }

    pub fn run_dkg<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<Coordinator>, Vec<Signer<SignerType>>) {
        let (mut coordinators, mut signers) =
            setup::<Coordinator, SignerType>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators.first_mut().unwrap().start_dkg_round().unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgPrivateBegin(_) => {}
            _ => {
                panic!("Expected DkgPrivateBegin message");
            }
        }

        // persist the state machines before continuing
        let new_coordinators = coordinators
            .iter()
            .map(|c| Coordinator::load(&c.save()))
            .collect::<Vec<Coordinator>>();

        assert_eq!(coordinators, new_coordinators);

        coordinators = new_coordinators;

        let new_signers = signers
            .iter()
            .map(|s| Signer::<SignerType>::load(&s.save()))
            .collect::<Vec<Signer<SignerType>>>();

        assert_eq!(signers, new_signers);

        signers = new_signers;

        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::DkgEndBegin(_) => {}
            _ => {
                panic!("Expected DkgEndBegin message");
            }
        }

        // persist the state machines before continuing
        let new_coordinators = coordinators
            .iter()
            .map(|c| Coordinator::load(&c.save()))
            .collect::<Vec<Coordinator>>();

        assert_eq!(coordinators, new_coordinators);

        coordinators = new_coordinators;

        let new_signers = signers
            .iter()
            .map(|s| Signer::<SignerType>::load(&s.save()))
            .collect::<Vec<Signer<SignerType>>>();

        assert_eq!(signers, new_signers);

        signers = new_signers;

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 1);
        match operation_results[0] {
            OperationResult::Dkg(point) => {
                assert_ne!(point, Point::default());
                for coordinator in coordinators.iter() {
                    assert_eq!(coordinator.get_aggregate_public_key(), Some(point));
                    assert_eq!(coordinator.get_state(), State::Idle);
                }
            }
            _ => panic!("Expected Dkg Operation result"),
        }

        // clear the polynomials before persisting
        for signer in &mut signers {
            signer.signer.clear_polys();
        }

        // persist the state machines before continuing
        let new_coordinators = coordinators
            .iter()
            .map(|c| Coordinator::load(&c.save()))
            .collect::<Vec<Coordinator>>();

        assert_eq!(coordinators, new_coordinators);

        coordinators = new_coordinators;

        let new_signers = signers
            .iter()
            .map(|s| Signer::<SignerType>::load(&s.save()))
            .collect::<Vec<Signer<SignerType>>>();

        assert_eq!(signers, new_signers);

        signers = new_signers;

        (coordinators, signers)
    }

    pub fn run_sign<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        coordinators: &mut [Coordinator],
        signers: &mut Vec<Signer<SignerType>>,
        msg: &[u8],
        signature_type: SignatureType,
    ) -> OperationResult {
        // Start a signing round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(coordinators, signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::SigShareGather(signature_type)
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        // persist the coordinators before continuing
        let _new_coordinators = coordinators
            .iter()
            .map(|c| Coordinator::load(&c.save()))
            .collect::<Vec<Coordinator>>();

        let new_signers = signers
            .iter()
            .map(|s| Signer::<SignerType>::load(&s.save()))
            .collect::<Vec<Signer<SignerType>>>();

        assert_eq!(signers, &new_signers);

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(coordinators, signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::Sign(sig) => {
                if let SignatureType::Frost = signature_type {
                    for coordinator in coordinators.iter() {
                        assert!(sig.verify(
                            &coordinator
                                .get_aggregate_public_key()
                                .expect("No aggregate public key set!"),
                            msg
                        ));
                        assert_eq!(coordinator.get_state(), State::Idle);
                    }
                } else {
                    panic!("Expected OperationResult::Sign");
                }
            }
            OperationResult::SignSchnorr(sig) => {
                if let SignatureType::Schnorr = signature_type {
                    for coordinator in coordinators.iter() {
                        assert!(sig.verify(
                            &coordinator
                                .get_aggregate_public_key()
                                .expect("No aggregate public key set!")
                                .x(),
                            msg
                        ));
                        assert_eq!(coordinator.get_state(), State::Idle);
                    }
                } else {
                    panic!("Expected OperationResult::SignSchnorr");
                }
            }
            OperationResult::SignTaproot(sig) => {
                if let SignatureType::Taproot(merkle_root) = signature_type {
                    for coordinator in coordinators.iter() {
                        let tweaked_public_key = compute::tweaked_public_key(
                            &coordinator
                                .get_aggregate_public_key()
                                .expect("No aggregate public key set!"),
                            merkle_root,
                        );

                        assert!(sig.verify(&tweaked_public_key.x(), msg));
                        assert_eq!(coordinator.get_state(), State::Idle);
                    }
                } else {
                    panic!("Expected OperationResult::SignTaproot");
                }
            }
            _ => panic!("Expected OperationResult"),
        }

        operation_results[0].clone()
    }

    pub fn run_dkg_sign<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) {
        let (mut coordinators, mut signers) =
            run_dkg::<Coordinator, SignerType>(num_signers, keys_per_signer);

        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();

        run_sign::<Coordinator, SignerType>(
            &mut coordinators,
            &mut signers,
            &msg,
            SignatureType::Frost,
        );
        run_sign::<Coordinator, SignerType>(
            &mut coordinators,
            &mut signers,
            &msg,
            SignatureType::Schnorr,
        );
        run_sign::<Coordinator, SignerType>(
            &mut coordinators,
            &mut signers,
            &msg,
            SignatureType::Taproot(None),
        );
        run_sign::<Coordinator, SignerType>(
            &mut coordinators,
            &mut signers,
            &msg,
            SignatureType::Taproot(Some([128u8; 32])),
        );
    }

    /// Run DKG then sign a message, but alter the signature shares for signer 0.  This should trigger the aggregator internal check_signature_shares function to run and determine which parties signatures were bad.
    /// Because of the differences between how parties are represented in v1 and v2, we need to pass in a vector of the expected bad parties.
    pub fn check_signature_shares<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
        signature_type: SignatureType,
        bad_parties: Vec<u32>,
    ) {
        let (mut coordinators, mut signers) =
            run_dkg::<Coordinator, SignerType>(num_signers, keys_per_signer);

        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        // Start a signing round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type)
            .unwrap();
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::SigShareGather(signature_type)
        );

        assert_eq!(outbound_messages.len(), 1);
        match &outbound_messages[0].msg {
            Message::SignatureShareRequest(_) => {}
            _ => {
                panic!("Expected SignatureShareRequest message");
            }
        }

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &outbound_messages,
            |signer, packets| {
                if signer.signer_id == 0 {
                    packets
                        .iter()
                        .map(|packet| {
                            if let Message::SignatureShareResponse(response) = &packet.msg {
                                // mutate one of the shares
                                let sshares: Vec<SignatureShare> = response
                                    .signature_shares
                                    .iter()
                                    .map(|share| SignatureShare {
                                        id: share.id,
                                        key_ids: share.key_ids.clone(),
                                        z_i: share.z_i + Scalar::from(1),
                                    })
                                    .collect();
                                Packet {
                                    msg: Message::SignatureShareResponse(SignatureShareResponse {
                                        dkg_id: response.dkg_id,
                                        sign_id: response.sign_id,
                                        sign_iter_id: response.sign_iter_id,
                                        signer_id: response.signer_id,
                                        signature_shares: sshares,
                                    }),
                                    sig: vec![],
                                }
                            } else {
                                packet.clone()
                            }
                        })
                        .collect()
                } else {
                    packets.clone()
                }
            },
        );
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        match &operation_results[0] {
            OperationResult::SignError(SignError::Coordinator(Error::Aggregator(AggregatorError::BadPartySigs(parties)))) => {
		if parties != &bad_parties {
		    panic!("Expected BadPartySigs from {:?}, got {:?}", &bad_parties, &operation_results[0]);
		}
	    }
            _ => panic!("Expected OperationResult::SignError(SignError::Coordinator(Error::Aggregator(AggregatorError::BadPartySigs(parties))))"),
        }
    }

    pub fn equal_after_save_load<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) {
        let (coordinators, signers) =
            setup::<Coordinator, SignerType>(num_signers, keys_per_signer);

        let loaded_coordinators = coordinators
            .iter()
            .map(|c| Coordinator::load(&c.save()))
            .collect::<Vec<Coordinator>>();

        assert_eq!(coordinators, loaded_coordinators);

        let loaded_signers = signers
            .iter()
            .map(|s| Signer::<SignerType>::load(&s.save()))
            .collect::<Vec<Signer<SignerType>>>();

        assert_eq!(signers, loaded_signers);
    }
}
