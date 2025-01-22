use std::fmt::Debug;

use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::{
    common::{MerkleRoot, PolyCommitment, PublicNonce, SignatureShare, TupleProof},
    curve::{ecdsa, point::Point, scalar::Scalar},
    state_machine::PublicKeys,
};

/// Trait to encapsulate sign/verify, users only need to impl hash
pub trait Signable {
    /// Hash this object in a consistent way so it can be signed/verified
    fn hash(&self, hasher: &mut Sha256);

    /// Sign a hash of this object using the passed private key
    fn sign(&self, private_key: &Scalar) -> Result<Vec<u8>, ecdsa::Error> {
        let mut hasher = Sha256::new();

        self.hash(&mut hasher);

        let hash = hasher.finalize();
        match ecdsa::Signature::new(hash.as_slice(), private_key) {
            Ok(sig) => Ok(sig.to_bytes().to_vec()),
            Err(e) => Err(e),
        }
    }

    /// Verify a hash of this object using the passed public key
    fn verify(&self, signature: &[u8], public_key: &ecdsa::PublicKey) -> bool {
        let mut hasher = Sha256::new();

        self.hash(&mut hasher);

        let hash = hasher.finalize();
        let sig = match ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        sig.verify(hash.as_slice(), public_key)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// A bad private share
pub struct BadPrivateShare {
    /// the DH shared key between these participants
    pub shared_key: Point,
    /// prooof that the shared key is a valid DH tuple as per chaum-pedersen
    pub tuple_proof: TupleProof,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Final DKG status after receiving public and private shares
pub enum DkgFailure {
    /// DKG threshold not met
    Threshold,
    /// Signer was in the wrong internal state to complete DKG
    BadState,
    /// DKG public shares were missing from these signer_ids
    MissingPublicShares(HashSet<u32>),
    /// DKG public shares were bad from these signer_ids
    BadPublicShares(HashSet<u32>),
    /// DKG private shares were missing from these signer_ids
    MissingPrivateShares(HashSet<u32>),
    /// DKG private shares were bad from these signer_ids
    BadPrivateShares(HashMap<u32, BadPrivateShare>),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Final DKG status after receiving public and private shares
pub enum DkgStatus {
    /// DKG completed successfully
    Success,
    /// DKG failed
    Failure(DkgFailure),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Encapsulation of all possible network message types
pub enum Message {
    /// Tell signers to begin DKG by sending DKG public shares
    DkgBegin(DkgBegin),
    /// Send DKG public shares
    DkgPublicShares(DkgPublicShares),
    /// Tell signers to send DKG private shares
    DkgPrivateBegin(DkgPrivateBegin),
    /// Send DKG private shares
    DkgPrivateShares(DkgPrivateShares),
    /// Tell signers to compute shares and send DKG end
    DkgEndBegin(DkgEndBegin),
    /// Tell coordinator that DKG is complete
    DkgEnd(DkgEnd),
    /// Tell signers to send signing nonces
    NonceRequest(NonceRequest),
    /// Tell coordinator signing nonces
    NonceResponse(NonceResponse),
    /// Tell signers to construct signature shares
    SignatureShareRequest(SignatureShareRequest),
    /// Tell coordinator signature shares
    SignatureShareResponse(SignatureShareResponse),
}

impl Signable for Message {
    fn hash(&self, hasher: &mut Sha256) {
        match self {
            Message::DkgBegin(msg) => msg.hash(hasher),
            Message::DkgPublicShares(msg) => msg.hash(hasher),
            Message::DkgPrivateBegin(msg) => msg.hash(hasher),
            Message::DkgPrivateShares(msg) => msg.hash(hasher),
            Message::DkgEndBegin(msg) => msg.hash(hasher),
            Message::DkgEnd(msg) => msg.hash(hasher),
            Message::NonceRequest(msg) => msg.hash(hasher),
            Message::NonceResponse(msg) => msg.hash(hasher),
            Message::SignatureShareRequest(msg) => msg.hash(hasher),
            Message::SignatureShareResponse(msg) => msg.hash(hasher),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG begin message from coordinator to signers
pub struct DkgBegin {
    /// DKG round ID
    pub dkg_id: u64,
}

impl Signable for DkgBegin {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_BEGIN".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG public shares message from signer to all signers and coordinator
pub struct DkgPublicShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (party_id, commitment)
    pub comms: Vec<(u32, PolyCommitment)>,
}

impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        for (party_id, comm) in &self.comms {
            hasher.update(party_id.to_be_bytes());
            for a in &comm.poly {
                hasher.update(a.compress().as_bytes());
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG private begin message from signer to all signers and coordinator
pub struct DkgPrivateBegin {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer IDs who responded in time for this DKG round
    pub signer_ids: Vec<u32>,
    /// Key IDs who responded in time for this DKG round
    pub key_ids: Vec<u32>,
}

impl Signable for DkgPrivateBegin {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PRIVATE_BEGIN".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        for key_id in &self.key_ids {
            hasher.update(key_id.to_be_bytes());
        }
        for signer_id in &self.signer_ids {
            hasher.update(signer_id.to_be_bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG private shares message from signer to all signers and coordinator
pub struct DkgPrivateShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (src_party_id, Map(dst_key_id, encrypted_share))
    pub shares: Vec<(u32, HashMap<u32, Vec<u8>>)>,
}

impl DkgPrivateShares {
    /// Verify that the shares are good
    pub fn verify() -> bool {
        true
    }
}

impl Signable for DkgPrivateShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PRIVATE_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        // make sure we hash consistently by sorting the keys
        for (src_id, share) in &self.shares {
            hasher.update(src_id.to_be_bytes());
            let mut dst_ids = share.keys().cloned().collect::<Vec<u32>>();
            dst_ids.sort();
            for dst_id in &dst_ids {
                hasher.update(dst_id.to_be_bytes());
                hasher.update(&share[dst_id]);
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG end begin message from signer to all signers and coordinator
pub struct DkgEndBegin {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer IDs who responded in time for this DKG round
    pub signer_ids: Vec<u32>,
    /// Key IDs who responded in time for this DKG round
    pub key_ids: Vec<u32>,
}

impl Signable for DkgEndBegin {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_END_BEGIN".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        for key_id in &self.key_ids {
            hasher.update(key_id.to_be_bytes());
        }
        for signer_id in &self.signer_ids {
            hasher.update(signer_id.to_be_bytes());
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG end message from signers to coordinator
pub struct DkgEnd {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// DKG status for this Signer after receiving public/private shares
    pub status: DkgStatus,
}

impl Signable for DkgEnd {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_END".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Nonce request message from coordinator to signers
pub struct NonceRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// The message to sign
    pub message: Vec<u8>,
    /// What type of signature to create
    pub signature_type: SignatureType,
}

impl Debug for NonceRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceRequest")
            .field("dkg_id", &self.dkg_id)
            .field("sign_id", &self.sign_id)
            .field("sign_iter_id", &self.sign_iter_id)
            .field("message", &hex::encode(&self.message))
            .field("signature_type", &self.signature_type)
            .finish()
    }
}

impl Signable for NonceRequest {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("NONCE_REQUEST".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_iter_id.to_be_bytes());
        hasher.update(self.message.as_slice());
        match self.signature_type {
            SignatureType::Frost => hasher.update("SIGNATURE_TYPE_FROST".as_bytes()),
            SignatureType::Schnorr => hasher.update("SIGNATURE_TYPE_SCHNORR".as_bytes()),
            SignatureType::Taproot(merkle_root) => {
                hasher.update("SIGNATURE_TYPE_TAPROOT".as_bytes());
                if let Some(merkle_root) = merkle_root {
                    hasher.update(merkle_root);
                }
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Nonce response message from signers to coordinator
pub struct NonceResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Key IDs
    pub key_ids: Vec<u32>,
    /// Public nonces
    pub nonces: Vec<PublicNonce>,
    /// Bytes being signed
    pub message: Vec<u8>,
}

impl Debug for NonceResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceResponse")
            .field("dkg_id", &self.dkg_id)
            .field("sign_id", &self.sign_id)
            .field("sign_iter_id", &self.sign_iter_id)
            .field("signer_id", &self.signer_id)
            .field("key_ids", &self.key_ids)
            .field(
                "nonces",
                &self
                    .nonces
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>(),
            )
            .field("message", &hex::encode(&self.message))
            .finish()
    }
}

impl Signable for NonceResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("NONCE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_iter_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for key_id in &self.key_ids {
            hasher.update(key_id.to_be_bytes());
        }

        for nonce in &self.nonces {
            hasher.update(nonce.D.compress().as_bytes());
            hasher.update(nonce.E.compress().as_bytes());
        }

        hasher.update(self.message.as_slice());
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
/// Signature type
pub enum SignatureType {
    /// FROST signature
    Frost,
    /// BIP-340 Schnorr proof
    Schnorr,
    /// BIP-341 Taproot style schnorr proof with a merkle root
    Taproot(Option<MerkleRoot>),
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Signature share request message from coordinator to signers
pub struct SignatureShareRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Nonces responses used for this signature
    pub nonce_responses: Vec<NonceResponse>,
    /// Bytes to sign
    pub message: Vec<u8>,
    /// What type of signature to create
    pub signature_type: SignatureType,
}

impl Debug for SignatureShareRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureShareRequest")
            .field("dkg_id", &self.dkg_id)
            .field("sign_id", &self.sign_id)
            .field("sign_iter_id", &self.sign_iter_id)
            .field("nonce_responses", &self.nonce_responses)
            .field("message", &hex::encode(&self.message))
            .field("signature_type", &self.signature_type)
            .finish()
    }
}

impl Signable for SignatureShareRequest {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_REQUEST".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());

        for nonce_response in &self.nonce_responses {
            nonce_response.hash(hasher);
        }

        hasher.update(self.message.as_slice());
        match self.signature_type {
            SignatureType::Frost => hasher.update("SIGNATURE_TYPE_FROST".as_bytes()),
            SignatureType::Schnorr => hasher.update("SIGNATURE_TYPE_SCHNORR".as_bytes()),
            SignatureType::Taproot(merkle_root) => {
                hasher.update("SIGNATURE_TYPE_TAPROOT".as_bytes());
                if let Some(merkle_root) = merkle_root {
                    hasher.update(merkle_root);
                }
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Signature share response message from signers to coordinator
pub struct SignatureShareResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Signature shares from this Signer
    pub signature_shares: Vec<SignatureShare>,
}

impl Signable for SignatureShareResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for signature_share in &self.signature_shares {
            hasher.update(signature_share.id.to_be_bytes());
            hasher.update(signature_share.z_i.to_bytes());
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
/// Network packets need to be signed so they can be verified
pub struct Packet {
    /// The message to sign
    pub msg: Message,
    /// The bytes of the signature
    pub sig: Vec<u8>,
}

impl Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packet")
            .field("msg", &self.msg)
            .field("sig", &hex::encode(&self.sig))
            .finish()
    }
}

impl Packet {
    /// This function verifies the packet's signature, returning true if the signature is valid,
    /// i.e. is appropriately signed by either the provided coordinator or one of the provided signer public keys
    pub fn verify(
        &self,
        signers_public_keys: &PublicKeys,
        coordinator_public_key: &ecdsa::PublicKey,
    ) -> bool {
        match &self.msg {
            Message::DkgBegin(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a DkgBegin message with an invalid signature.");
                    return false;
                }
            }
            Message::DkgPrivateBegin(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a DkgPrivateBegin message with an invalid signature.");
                    return false;
                }
            }
            Message::DkgEndBegin(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a DkgEndBegin message with an invalid signature.");
                    return false;
                }
            }
            Message::DkgEnd(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPublicEnd message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPublicEnd message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
            Message::DkgPublicShares(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPublicShares message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPublicShares message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
            Message::DkgPrivateShares(msg) => {
                // Private shares have key IDs from [0, N) to reference IDs from [1, N]
                // in Frost V4 to enable easy indexing hence ID + 1
                // TODO: Once Frost V5 is released, this off by one adjustment will no longer be required
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPrivateShares message with an invalid signature from signer_id {} key {}", msg.signer_id, &public_key);
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPrivateShares message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
            Message::NonceRequest(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a NonceRequest message with an invalid signature.");
                    return false;
                }
            }
            Message::NonceResponse(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a NonceResponse message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a NonceResponse message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
            Message::SignatureShareRequest(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a SignatureShareRequest message with an invalid signature.");
                    return false;
                }
            }
            Message::SignatureShareResponse(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!(
                            "Received a SignatureShareResponse message with an invalid signature."
                        );
                        return false;
                    }
                } else {
                    warn!(
                        "Received a SignatureShareResponse message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]

mod test {
    use crate::{schnorr::ID, state_machine::PublicKeys};
    use hashbrown::HashMap;
    use p256k1::{ecdsa, scalar::Scalar};
    use rand_core::OsRng;

    use super::*;

    /// Test config for verifying messages
    pub struct TestConfig {
        coordinator_private_key: Scalar,
        coordinator_public_key: ecdsa::PublicKey,
        signer_private_key: Scalar,
        public_keys: PublicKeys,
    }

    impl Default for TestConfig {
        fn default() -> Self {
            let mut rng = OsRng;
            let signer_private_key = Scalar::random(&mut rng);
            let signer_public_key = ecdsa::PublicKey::new(&signer_private_key).unwrap();
            let mut signer_ids_map = HashMap::new();
            let mut signer_key_ids = HashMap::new();
            let mut key_ids_map = HashMap::new();
            let mut key_ids_set = HashSet::new();
            signer_ids_map.insert(0, signer_public_key);
            key_ids_map.insert(1, signer_public_key);
            key_ids_set.insert(1);
            signer_key_ids.insert(0, key_ids_set);
            let public_keys = PublicKeys {
                signers: signer_ids_map,
                key_ids: key_ids_map,
                signer_key_ids,
            };
            let coordinator_private_key = Scalar::random(&mut rng);
            let coordinator_public_key = ecdsa::PublicKey::new(&coordinator_private_key).unwrap();
            Self {
                coordinator_private_key,
                coordinator_public_key,
                signer_private_key,
                public_keys,
            }
        }
    }
    #[test]
    fn dkg_begin_verify_msg() {
        let test_config = TestConfig::default();
        let dkg_begin = DkgBegin { dkg_id: 0 };
        let dkg_private_begin = DkgPrivateBegin {
            dkg_id: 0,
            key_ids: Default::default(),
            signer_ids: Default::default(),
        };
        let msg = Message::DkgBegin(dkg_begin.clone());
        let coordinator_packet_dkg_begin = Packet {
            sig: dkg_begin
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_dkg_begin = Packet {
            sig: dkg_begin
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };

        assert!(coordinator_packet_dkg_begin.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(!signer_packet_dkg_begin.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));

        let msg = Message::DkgPrivateBegin(dkg_private_begin.clone());
        let coordinator_packet_dkg_private_begin = Packet {
            sig: dkg_private_begin
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_dkg_private_begin = Packet {
            sig: dkg_private_begin
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };

        assert!(coordinator_packet_dkg_private_begin.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(!signer_packet_dkg_private_begin.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
    }

    #[test]
    fn dkg_public_shares_verify_msg() {
        let mut rng = OsRng;
        let test_config = TestConfig::default();
        let public_shares = DkgPublicShares {
            dkg_id: 0,
            signer_id: 0,
            comms: vec![(
                0,
                PolyCommitment {
                    id: ID::new(&Scalar::new(), &Scalar::new(), &mut rng),
                    poly: vec![],
                },
            )],
        };
        let msg = Message::DkgPublicShares(public_shares.clone());
        let coordinator_packet_dkg_public_shares = Packet {
            sig: public_shares
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_dkg_public_shares = Packet {
            sig: public_shares
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };

        assert!(!coordinator_packet_dkg_public_shares.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(signer_packet_dkg_public_shares.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
    }

    #[test]
    fn dkg_private_shares_verify_msg() {
        let test_config = TestConfig::default();
        let private_shares = DkgPrivateShares {
            dkg_id: 0,
            signer_id: 0,
            shares: vec![(0, HashMap::new())],
        };
        let msg = Message::DkgPrivateShares(private_shares.clone());
        let coordinator_packet_dkg_private_shares = Packet {
            sig: private_shares
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_dkg_private_shares = Packet {
            sig: private_shares
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };

        assert!(!coordinator_packet_dkg_private_shares.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(signer_packet_dkg_private_shares.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
    }

    #[test]
    fn dkg_end_verify_msg() {
        let test_config = TestConfig::default();
        let dkg_end = DkgEnd {
            dkg_id: 0,
            signer_id: 0,
            status: DkgStatus::Success,
        };
        let msg = Message::DkgEnd(dkg_end.clone());

        let coordinator_packet_dkg_end = Packet {
            sig: dkg_end
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_dkg_end = Packet {
            sig: dkg_end
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };
        assert!(!coordinator_packet_dkg_end.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(signer_packet_dkg_end.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
    }
    #[test]
    fn nonce_request_verify_msg() {
        let test_config = TestConfig::default();
        let nonce_request = NonceRequest {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            message: vec![],
            signature_type: SignatureType::Frost,
        };
        let msg = Message::NonceRequest(nonce_request.clone());
        let coordinator_packet_nonce_request = Packet {
            sig: nonce_request
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_nonce_request = Packet {
            sig: nonce_request
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };
        assert!(coordinator_packet_nonce_request.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(!signer_packet_nonce_request.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
    }
    #[test]
    fn nonce_response_verify_msg() {
        let test_config = TestConfig::default();

        let nonce_response = NonceResponse {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            signer_id: 0,
            key_ids: vec![],
            nonces: vec![],
            message: vec![],
        };
        let msg = Message::NonceResponse(nonce_response.clone());
        let coordinator_packet_nonce_response = Packet {
            sig: nonce_response
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_nonce_response = Packet {
            sig: nonce_response
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };
        assert!(!coordinator_packet_nonce_response.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(signer_packet_nonce_response.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
    }

    #[test]
    fn signature_share_request_verify_msg() {
        let test_config = TestConfig::default();
        let signature_share_request = SignatureShareRequest {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            nonce_responses: vec![],
            message: vec![],
            signature_type: SignatureType::Frost,
        };
        let msg = Message::SignatureShareRequest(signature_share_request.clone());
        let coordinator_packet_signature_share_request = Packet {
            sig: signature_share_request
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_signature_share_request = Packet {
            sig: signature_share_request
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };
        assert!(coordinator_packet_signature_share_request.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(!signer_packet_signature_share_request.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
    }

    #[test]
    fn signature_share_response_verify_msg() {
        let test_config = TestConfig::default();

        let signature_share_response = SignatureShareResponse {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            signer_id: 0,
            signature_shares: vec![],
        };
        let msg = Message::SignatureShareResponse(signature_share_response.clone());
        let coordinator_packet_signature_share_response = Packet {
            sig: signature_share_response
                .sign(&test_config.coordinator_private_key)
                .expect("Failed to sign"),
            msg: msg.clone(),
        };
        let signer_packet_signature_share_response = Packet {
            sig: signature_share_response
                .sign(&test_config.signer_private_key)
                .expect("Failed to sign"),
            msg,
        };
        assert!(!coordinator_packet_signature_share_response.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
        assert!(signer_packet_signature_share_response.verify(
            &test_config.public_keys,
            &test_config.coordinator_public_key
        ));
    }

    #[test]
    fn signature_share_response_wrapped_verify_msg() {
        let test_config = TestConfig::default();

        let signature_share_response = SignatureShareResponse {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            signer_id: 0,
            signature_shares: vec![],
        };
        let msg = Message::SignatureShareResponse(signature_share_response.clone());
        let sig = msg
            .sign(&test_config.coordinator_private_key)
            .expect("Failed to sign");
        assert!(msg.verify(&sig, &test_config.coordinator_public_key));
    }
}
