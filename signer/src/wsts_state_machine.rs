//! Utilities for constructing and loading WSTS state machines

use std::collections::BTreeMap;
use std::future::Future;

use crate::codec::CodecError;
use crate::codec::Decode as _;
use crate::codec::Encode as _;
use crate::error;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;
use crate::keys::SignerScriptPubKey as _;
use crate::proto;
use crate::storage;
use crate::storage::model;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinBlockHeight;
use crate::storage::model::BitcoinBlockRef;
use crate::storage::model::DkgSharesStatus;
use crate::storage::model::SigHash;

use hashbrown::HashMap;
use hashbrown::HashSet;
use prost::Message as _;
use rand::SeedableRng as _;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use sha2::Digest as _;
use sha2::Sha256;
use wsts::common::PolyCommitment;
use wsts::net::Message;
use wsts::net::Packet;
use wsts::net::SignatureType;
use wsts::state_machine::OperationResult;
use wsts::state_machine::StateMachine as _;
use wsts::state_machine::coordinator::Config;
use wsts::state_machine::coordinator::Coordinator as _;
use wsts::state_machine::coordinator::State as WstsState;
use wsts::state_machine::coordinator::fire;
use wsts::state_machine::coordinator::frost;
use wsts::traits::Signer as _;
use wsts::v2::Aggregator;

/// A database model for storing DKG public shares.
///
/// This is used to store the DKG public shares in the database.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct DkgSignerCommitments {
    /// List of (party_id, commitment)
    pub comms: Vec<(u32, PolyCommitment)>,
}

impl crate::codec::Decode for BTreeMap<u32, DkgSignerCommitments> {
    fn decode<R: std::io::Read>(mut reader: R) -> Result<Self, Error> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(CodecError::DecodeIOError)?;

        proto::DkgPolynomialCommitments::decode(&*buf)
            .map_err(CodecError::DecodeError)?
            .commitments
            .into_iter()
            .map(|(id, comms)| Ok((id, comms.try_into()?)))
            .collect::<Result<BTreeMap<u32, DkgSignerCommitments>, Error>>()
    }
}

/// An identifier for signer state machines.
///
/// Signer state machines are used for either DKG or signing rounds on
/// bitcoin. For DKG, the state machine is identified by the bitcoin block
/// hash bytes while for the signing rounds we identify the state machine
/// by the sighash bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateMachineId {
    /// Identifier for a DKG state machines
    Dkg(model::BitcoinBlockRef),
    /// Identifier for a Bitcoin signing state machines
    BitcoinSign(SigHash),
    /// Identifier for a rotate key verification signing round
    DkgVerification(PublicKeyXOnly, model::BitcoinBlockRef),
}

impl std::fmt::Display for StateMachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateMachineId::Dkg(block) => write!(
                f,
                "dkg(block_hash={}, block_height={})",
                block.block_hash, block.block_height
            ),
            StateMachineId::BitcoinSign(sighash) => write!(f, "bitcoin-sign({sighash})"),
            StateMachineId::DkgVerification(pubkey, block) => write!(
                f,
                "dkg-verification(key={pubkey}, block_hash={}, block_height={})",
                block.block_hash, block.block_height
            ),
        }
    }
}

impl From<&model::BitcoinBlockRef> for StateMachineId {
    fn from(value: &model::BitcoinBlockRef) -> Self {
        StateMachineId::Dkg(*value)
    }
}

impl From<SigHash> for StateMachineId {
    fn from(value: SigHash) -> Self {
        StateMachineId::BitcoinSign(value)
    }
}

/// Construct a signing round id from the given message and bitcoin chain tip.
///
/// The signing round id is a u64 that is used to identify the signing round.
/// It is constructed by hashing the message and bitcoin chain tip together.
/// The first 8 bytes of the hash are used as the u64.
pub fn construct_signing_round_id(message: &[u8], bitcoin_chain_tip: &BitcoinBlockHash) -> u64 {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(message)
        .chain_update(bitcoin_chain_tip.into_bytes())
        .finalize()
        .into();

    // Use the first 8 bytes of the digest to create a u64 index. Since
    // `digest` is 32 bytes and we explicitly take the first 8 bytes, this
    // is safe.
    #[allow(clippy::expect_used)]
    let u64_bytes: [u8; 8] = digest[..8]
        .try_into()
        .expect("BUG: failed to take first 8 bytes of digest");

    u64::from_le_bytes(u64_bytes)
}

/// A trait for converting a message into another type.
pub trait FromMessage {
    /// Convert the given message into the implementing type.
    fn from_message(message: &Message) -> Self
    where
        Self: Sized;
}

impl FromMessage for Packet {
    fn from_message(message: &Message) -> Self {
        Packet {
            msg: message.clone(),
            sig: Vec::new(),
        }
    }
}

/// Wrapper for a WSTS FIRE coordinator state machine.
#[derive(Debug, Clone, PartialEq)]
pub struct FireCoordinator(fire::Coordinator<Aggregator>);

impl std::ops::Deref for FireCoordinator {
    type Target = fire::Coordinator<Aggregator>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for FireCoordinator {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Wrapper for a WSTS FROST coordinator state machine.
#[derive(Debug, Clone, PartialEq)]
pub struct FrostCoordinator(frost::Coordinator<Aggregator>);

impl std::ops::Deref for FrostCoordinator {
    type Target = frost::Coordinator<Aggregator>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for FrostCoordinator {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<frost::Coordinator<Aggregator>> for FrostCoordinator {
    fn from(value: frost::Coordinator<Aggregator>) -> Self {
        Self(value)
    }
}

/// A trait for WSTS state machines.
pub trait WstsCoordinator
where
    Self: Sized,
{
    /// Creates a new coordinator state machine.
    ///
    /// # Notes
    ///
    /// For signing rounds, the `block_height` is the block height of the
    /// bitcoin chain tip when the DKG round associated with these shares
    /// started. For new rounds of DKG, the `block_height` is the block
    /// height of the bitcoin chain tip when the DKG round started.
    fn new<I>(
        signers: I,
        threshold: u16,
        message_private_key: PrivateKey,
        block_height: BitcoinBlockHeight,
    ) -> Self
    where
        I: IntoIterator<Item = PublicKey>;

    /// Gets the coordinator configuration.
    fn get_config(&self) -> Config;

    /// Creates a new coordinator state machine from the given configuration.
    fn from_config(config: Config) -> Self;

    /// Create a new coordinator state machine from the given aggregate
    /// key.
    ///
    /// # Notes
    ///
    /// The `WstsCoordinator` is a state machine that is responsible for
    /// DKG and for facilitating signing rounds. When created the
    /// `WstsCoordinator` state machine starts off in the `IDLE` state,
    /// where you can either start a signing round or start DKG. This
    /// function is for loading the state with the assumption that DKG has
    /// already been successfully completed.
    fn load<S>(
        storage: &S,
        aggregate_key: PublicKeyXOnly,
        signer_private_key: PrivateKey,
    ) -> impl Future<Output = Result<Self, error::Error>> + Send
    where
        S: storage::DbRead + Send + Sync;

    /// Process the given message.
    fn process_message(
        &mut self,
        message: &Message,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        let packet = Packet::from_message(message);
        self.process_packet(&packet)
    }

    /// Process the given packet.
    fn process_packet(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error>;

    /// Start a signing round with the given message and signature type.
    fn start_signing_round(
        &mut self,
        message: &[u8],
        bitcoin_chain_tip: &BitcoinBlockHash,
        signature_type: SignatureType,
    ) -> Result<Packet, Error>;
}

impl WstsCoordinator for FireCoordinator {
    fn new<I>(
        signers: I,
        threshold: u16,
        message_private_key: PrivateKey,
        block_height: BitcoinBlockHeight,
    ) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let signers: hashbrown::HashMap<u32, _> = signers
            .into_iter()
            .enumerate()
            .map(|(idx, key)| (idx as u32, key.into()))
            .collect();
        // The number of possible signers is capped at a number well below
        // u32::MAX, so this conversion should always work.
        let num_signers: u32 = signers
            .len()
            .try_into()
            .expect("the number of signers is greater than u32::MAX?");
        let key_ids = signers
            .clone()
            .into_iter()
            .map(|(id, key)| (id + 1, key))
            .collect();
        let signer_key_ids = (0..num_signers)
            .map(|signer_id| (signer_id, std::iter::once(signer_id + 1).collect()))
            .collect();
        let public_keys = wsts::state_machine::PublicKeys {
            signers,
            key_ids,
            signer_key_ids,
        };
        let config = wsts::state_machine::coordinator::Config {
            num_signers,
            num_keys: num_signers,
            threshold: threshold as u32,
            dkg_threshold: num_signers,
            message_private_key: message_private_key.into(),
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            public_keys,
            verify_packet_sigs: false,
        };

        let mut wsts_coordinator = fire::Coordinator::new(config);
        wsts_coordinator.current_dkg_id = *block_height;
        Self(wsts_coordinator)
    }

    fn get_config(&self) -> Config {
        self.0.get_config()
    }

    fn from_config(config: Config) -> Self {
        Self(fire::Coordinator::<Aggregator>::new(config))
    }

    async fn load<S>(
        storage: &S,
        aggregate_key: PublicKeyXOnly,
        signer_private_key: PrivateKey,
    ) -> Result<Self, error::Error>
    where
        S: storage::DbRead + Send + Sync,
    {
        let encrypted_shares = storage
            .get_encrypted_dkg_shares(aggregate_key)
            .await?
            .ok_or(Error::MissingDkgShares(aggregate_key))?;

        let public_dkg_shares: BTreeMap<u32, DkgSignerCommitments> =
            BTreeMap::decode(encrypted_shares.public_shares.as_slice())?;
        let party_polynomials = public_dkg_shares
            .iter()
            .flat_map(|(_, share)| share.comms.clone())
            .collect::<Vec<(u32, PolyCommitment)>>();

        let signer_public_keys = encrypted_shares.signer_set_public_keys();
        let threshold = encrypted_shares.signature_share_threshold;
        let block_height = encrypted_shares.started_at_bitcoin_block_height;
        let mut coordinator = Self::new(
            signer_public_keys,
            threshold,
            signer_private_key,
            block_height,
        );

        let aggregate_key = encrypted_shares.aggregate_key.into();
        coordinator
            .set_key_and_party_polynomials(aggregate_key, party_polynomials)
            .map_err(Error::wsts_coordinator)?;

        coordinator
            .move_to(WstsState::Idle)
            .map_err(Error::wsts_coordinator)?;

        Ok(coordinator)
    }

    fn process_packet(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        self.0
            .process_message(packet)
            .map_err(Error::wsts_coordinator)
    }

    fn start_signing_round(
        &mut self,
        message: &[u8],
        bitcoin_chain_tip: &BitcoinBlockHash,
        signature_type: SignatureType,
    ) -> Result<Packet, Error> {
        let sign_id = construct_signing_round_id(message, bitcoin_chain_tip);
        self.0
            .start_signing_round(message, signature_type, Some(sign_id))
            .map_err(Error::wsts_coordinator)
    }
}

impl WstsCoordinator for FrostCoordinator {
    fn new<I>(
        signers: I,
        threshold: u16,
        message_private_key: PrivateKey,
        block_height: BitcoinBlockHeight,
    ) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let signers: hashbrown::HashMap<u32, _> = signers
            .into_iter()
            .enumerate()
            .map(|(idx, key)| (idx as u32, key.into()))
            .collect();
        // The number of possible signers is capped at a number well below
        // u32::MAX, so this conversion should always work.
        let num_signers: u32 = signers
            .len()
            .try_into()
            .expect("the number of signers is greater than u32::MAX?");
        let key_ids = signers
            .clone()
            .into_iter()
            .map(|(id, key)| (id + 1, key))
            .collect();
        let signer_key_ids = (0..num_signers)
            .map(|signer_id| (signer_id, std::iter::once(signer_id + 1).collect()))
            .collect();
        let public_keys = wsts::state_machine::PublicKeys {
            signers,
            key_ids,
            signer_key_ids,
        };
        let config = wsts::state_machine::coordinator::Config {
            num_signers,
            num_keys: num_signers,
            threshold: threshold as u32,
            dkg_threshold: num_signers,
            message_private_key: message_private_key.into(),
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            public_keys,
            verify_packet_sigs: false,
        };

        let mut wsts_coordinator = frost::Coordinator::new(config);
        // TODO: Revisit when https://github.com/stacks-sbtc/wsts/pull/198
        // is merged and we updated the WSTS dependency with those changes.
        wsts_coordinator.current_dkg_id = *block_height;
        Self(wsts_coordinator)
    }

    fn get_config(&self) -> Config {
        self.0.get_config()
    }

    fn from_config(config: Config) -> Self {
        Self(frost::Coordinator::<Aggregator>::new(config))
    }

    async fn load<S>(
        storage: &S,
        aggregate_key: PublicKeyXOnly,
        signer_private_key: PrivateKey,
    ) -> Result<Self, error::Error>
    where
        S: storage::DbRead + Send + Sync,
    {
        let encrypted_shares = storage
            .get_encrypted_dkg_shares(aggregate_key)
            .await?
            .ok_or(Error::MissingDkgShares(aggregate_key))?;

        let public_dkg_shares: BTreeMap<u32, DkgSignerCommitments> =
            BTreeMap::decode(encrypted_shares.public_shares.as_slice())?;
        let party_polynomials = public_dkg_shares
            .iter()
            .flat_map(|(_, share)| share.comms.clone())
            .collect::<Vec<(u32, PolyCommitment)>>();

        let signer_public_keys = encrypted_shares.signer_set_public_keys();
        let threshold = encrypted_shares.signature_share_threshold;
        let block_height = encrypted_shares.started_at_bitcoin_block_height;
        let mut coordinator = Self::new(
            signer_public_keys,
            threshold,
            signer_private_key,
            block_height,
        );

        let aggregate_key = encrypted_shares.aggregate_key.into();
        coordinator
            .set_key_and_party_polynomials(aggregate_key, party_polynomials)
            .map_err(Error::wsts_coordinator)?;

        coordinator
            .move_to(WstsState::Idle)
            .map_err(Error::wsts_coordinator)?;

        Ok(coordinator)
    }

    fn process_packet(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        self.0
            .process_message(packet)
            .map_err(Error::wsts_coordinator)
    }

    fn start_signing_round(
        &mut self,
        message: &[u8],
        bitcoin_chain_tip: &BitcoinBlockHash,
        signature_type: SignatureType,
    ) -> Result<Packet, Error> {
        let sign_id = construct_signing_round_id(message, bitcoin_chain_tip);
        self.0
            .start_signing_round(message, signature_type, Some(sign_id))
            .map_err(Error::wsts_coordinator)
    }
}

/// Wrapper around a WSTS signer state machine
#[derive(Debug, Clone, PartialEq)]
pub struct SignerStateMachine {
    /// The inner WSTS state machine that this type wraps
    inner: wsts::state_machine::signer::Signer<wsts::v2::Party>,
    /// The bitcoin block hash and height at the time that this state
    /// machine was created. This is used to seed the random number
    /// generator used to create the secret polynomial during DKG.
    started_at: BitcoinBlockRef,
    /// The signer's private key. This is also used to seed the random
    /// number generated used to create the secret polynomial during DKG.
    private_key: PrivateKey,
}

type WstsSigner = wsts::state_machine::signer::Signer<wsts::v2::Party>;

impl SignerStateMachine {
    /// Create a new state machine
    ///
    /// # Notes
    ///
    /// When a new state machine is created, a new private polynomial is
    /// generated, however this polynomial is regenerated during DKG.
    pub fn new(
        signers: impl IntoIterator<Item = PublicKey>,
        threshold: u32,
        started_at: BitcoinBlockRef,
        private_key: PrivateKey,
    ) -> Result<Self, Error> {
        let signer_pub_key = PublicKey::from_private_key(&private_key);
        let signers: hashbrown::HashMap<u32, _> = signers
            .into_iter()
            .enumerate()
            .map(|(id, key)| (id as u32, p256k1::keys::PublicKey::from(&key)))
            .collect();

        let key_ids = signers
            .clone()
            .into_iter()
            .map(|(id, key)| (id + 1, key))
            .collect();

        let num_parties = signers
            .len()
            .try_into()
            .map_err(|_| error::Error::TypeConversion)?;
        let num_keys = num_parties;
        let dkg_threshold = num_parties;

        let p256k1_public_key = p256k1::keys::PublicKey::from(&signer_pub_key);
        let id: u32 = *signers
            .iter()
            .find(|(_, key)| *key == &p256k1_public_key)
            .ok_or_else(|| error::Error::MissingPublicKey)?
            .0;

        let signer_key_ids: HashMap<u32, HashSet<u32>> = signers
            .iter()
            .map(|(&signer_id, _)| {
                let mut keys = HashSet::new();
                keys.insert(signer_id + 1);
                (signer_id, keys)
            })
            .collect();
        let public_keys = wsts::state_machine::PublicKeys {
            signers,
            key_ids,
            signer_key_ids,
        };

        let key_ids = vec![id + 1];

        if threshold > num_keys {
            return Err(error::Error::InvalidConfiguration);
        };

        let mut inner = WstsSigner::new(
            threshold,
            dkg_threshold,
            num_parties,
            num_keys,
            id,
            key_ids,
            private_key.into(),
            public_keys,
            &mut OsRng,
        )
        .map_err(Error::Wsts)?;

        // sBTC has its own network packet layer with signatures and verification
        inner.verify_packet_sigs = false;

        Ok(Self { inner, started_at, private_key })
    }

    /// Create a random number generator seeded with the given bitcoin
    /// block reference and a private key.
    fn create_rng(started_at: &BitcoinBlockHash, private_key: PrivateKey) -> ChaCha20Rng {
        let seed_bytes: [u8; 32] = sha2::Sha256::new_with_prefix("DKG_RNG")
            .chain_update(started_at.into_bytes())
            .chain_update(private_key.to_bytes())
            .finalize()
            .into();

        ChaCha20Rng::from_seed(seed_bytes)
    }

    /// Process the passed incoming message, and return any outgoing
    /// messages.
    ///
    /// # Notes
    ///
    /// This function processes messages in such a way where the generated
    /// secrets for DKG are deterministic given the bitcoin block ref and
    /// private keys used to create this state machine. Here is how.
    ///
    /// The underlying WSTS state machine generates a new polynomial when
    /// it receives a DKG begin message using the given random number
    /// generator. This polynomial is the same one generated in the FROST
    /// scheme, which is used for creating secret shares. So this function
    /// intercepts `DkgBegin` messages and uses a random number generator
    /// that was seeded with a bitcoin block hash, the corresponding
    /// bitcoin block height, and the signer's private key. This ensures
    /// that secret shares are generated in a pseudo-random way.
    ///
    /// All other messages are processed with the OS random number
    /// generated.
    pub fn process(&mut self, message: &Message) -> Result<Vec<Message>, Error> {
        let packet = Packet::from_message(message);
        let response = match message {
            Message::DkgBegin(_) => {
                let mut rng = Self::create_rng(&self.started_at.block_hash, self.private_key);
                self.inner.process(&packet, &mut rng)
            }
            _ => self.inner.process(&packet, &mut OsRng),
        };

        response.map_err(Error::Wsts)
    }

    /// Return the public key for the given signer ID.
    pub fn get_signer_public_key(&self, signer_id: u32) -> Option<PublicKey> {
        self.inner
            .public_keys
            .signers
            .get(&signer_id)
            .map(PublicKey::from)
    }

    /// Return the DKG ID for the current DKG round.
    #[cfg(any(test, feature = "testing"))]
    pub fn dkg_id(&self) -> u64 {
        self.inner.dkg_id
    }

    /// Create a state machine from loaded DKG shares for the given
    /// aggregate key
    ///
    /// # Note
    ///
    /// Loaded state machines should only be used for signing rounds and
    /// not for DKG, since they will always create the same secret shares.
    /// TODO: Make it so that we have separate state machines for signing
    /// and DKG.
    pub async fn load<S>(
        storage: &S,
        aggregate_key: PublicKeyXOnly,
        signer_private_key: PrivateKey,
    ) -> Result<Self, Error>
    where
        S: storage::DbRead,
    {
        let encrypted_shares = storage
            .get_encrypted_dkg_shares(aggregate_key)
            .await?
            .ok_or_else(|| Error::MissingDkgShares(aggregate_key))?;

        let decrypted = wsts::util::decrypt(
            &signer_private_key.to_bytes(),
            &encrypted_shares.encrypted_private_shares,
        )
        .map_err(|error| Error::WstsDecrypt(error, aggregate_key))?;

        let saved_state = wsts::traits::SignerState::decode(decrypted.as_slice())?;

        // This may panic if the saved state doesn't contain exactly one party,
        // however, that should never be the case since wsts maintains this invariant
        // when we save the state.
        let signer = wsts::v2::Party::load(&saved_state);
        let signers = encrypted_shares.signer_set_public_keys();
        // This as _ cast is a widening of a u16 to a u32, which is always fine.
        let threshold = encrypted_shares.signature_share_threshold as u32;

        let created_at = BitcoinBlockRef {
            block_hash: encrypted_shares.started_at_bitcoin_block_hash,
            block_height: encrypted_shares.started_at_bitcoin_block_height,
        };

        let mut state_machine = Self::new(signers, threshold, created_at, signer_private_key)?;

        state_machine.inner.signer = signer;

        Ok(state_machine)
    }

    /// Get the encrypted DKG shares
    pub fn get_encrypted_dkg_shares(&self) -> Result<model::EncryptedDkgShares, Error> {
        let saved_state = self.inner.signer.save();
        let aggregate_key = PublicKey::try_from(&saved_state.group_key)?;

        // When creating a new Self, the `public_keys` field gets populated
        // using the `signers` input iterator. It represents the public
        // keys for all signers in the signing set for DKG, including the
        // coordinator.
        let mut signer_set_public_keys = self
            .inner
            .public_keys
            .signers
            .values()
            .map(PublicKey::from)
            .collect::<Vec<PublicKey>>();

        // We require the public keys to be stored sorted in db
        signer_set_public_keys.sort();

        let encoded = saved_state.encode_to_vec();
        let public_shares = self.inner.dkg_public_shares.clone().encode_to_vec();

        // After DKG, each of the signers will have "new public keys". The
        // call to `wsts::util::encrypt` can error if we are encrypting
        // more than 68719476752 bytes.
        let encrypted_private_shares = wsts::util::encrypt(
            &self.inner.network_private_key.to_bytes(),
            &encoded,
            &mut OsRng,
        )
        .map_err(|error| Error::WstsEncrypt(error, aggregate_key))?;

        let signature_share_threshold: u16 = self
            .inner
            .threshold
            .try_into()
            .map_err(|_| Error::TypeConversion)?;

        Ok(model::EncryptedDkgShares {
            aggregate_key,
            tweaked_aggregate_key: aggregate_key.signers_tweaked_pubkey()?,
            script_pubkey: aggregate_key.signers_script_pubkey().into(),
            encrypted_private_shares,
            public_shares,
            signer_set_public_keys,
            signature_share_threshold,
            dkg_shares_status: DkgSharesStatus::Unverified,
            started_at_bitcoin_block_hash: self.started_at.block_hash,
            started_at_bitcoin_block_height: self.started_at.block_height,
        })
    }
}

#[cfg(test)]
mod tests {
    use fake::Fake as _;
    use wsts::net::DkgPublicShares;

    use crate::testing::dummy::Unit;
    use crate::testing::get_rng;

    use super::*;

    /// Test that we can decode DKG public shares
    ///
    /// During normal operation the signers encode the full DKG public
    /// shares object as a protobuf. Public shares start out as a
    /// `BTreeMap<u32, DkgPublicShares>` and is serialized as a
    /// `proto::DkgPublicShares`. When decoding, we only decode the one
    /// field that we care about, the `comms` field in each
    /// `DkgPublicShares`. We do this to allow the WSTS types to evolve
    /// independently of what the signers store in their database. So long
    /// as the protobuf type that we stored, the `proto::DkgPublicShares`,
    /// is compatible with the `BTreeMap<u32, DkgPublicSharesDb>` type,
    /// then we are fine.
    #[test]
    fn test_dkg_public_shares_db_decoding() {
        let mut rng = get_rng();
        let shares: BTreeMap<u32, DkgPublicShares> = Unit.fake_with_rng(&mut rng);
        let encoded = shares.clone().encode_to_vec();
        let decoded_shares = BTreeMap::<u32, DkgSignerCommitments>::decode(&*encoded).unwrap();

        for (original, decoded) in shares.iter().zip(decoded_shares.iter()) {
            assert_eq!(original.0, decoded.0);
            assert_eq!(original.1.comms, decoded.1.comms);
        }
    }
}
