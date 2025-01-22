use hashbrown::HashMap;
use num_traits::{One, Zero};
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use tracing::warn;

use crate::{
    common::{Nonce, PolyCommitment, PublicNonce, Signature, SignatureShare},
    compute,
    curve::{
        point::{Point, G},
        scalar::Scalar,
    },
    errors::{AggregatorError, DkgError},
    schnorr::ID,
    taproot::SchnorrProof,
    traits,
    vss::VSS,
};

#[derive(Clone, Debug, Eq, PartialEq)]
/// A WSTS party, which encapsulates a single polynomial, nonce, and one private key per key ID
pub struct Party {
    /// The party ID
    pub party_id: u32,
    /// The key IDs for this party
    pub key_ids: Vec<u32>,
    /// The public keys for this party, indexed by ID
    num_keys: u32,
    num_parties: u32,
    threshold: u32,
    f: Option<Polynomial<Scalar>>,
    private_keys: HashMap<u32, Scalar>,
    group_key: Point,
    nonce: Nonce,
}

impl Party {
    /// Construct a random Party with the passed party ID, key IDs, and parameters
    pub fn new<RNG: RngCore + CryptoRng>(
        party_id: u32,
        key_ids: &[u32],
        num_parties: u32,
        num_keys: u32,
        threshold: u32,
        rng: &mut RNG,
    ) -> Self {
        Self {
            party_id,
            key_ids: key_ids.to_vec(),
            num_keys,
            num_parties,
            threshold,
            f: Some(VSS::random_poly(threshold - 1, rng)),
            private_keys: Default::default(),
            group_key: Point::zero(),
            nonce: Nonce::zero(),
        }
    }

    /// Generate and store a private nonce for a signing round
    pub fn gen_nonce<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> PublicNonce {
        self.nonce = Nonce::random(rng);

        PublicNonce::from(&self.nonce)
    }

    /// Get a public commitment to the private polynomial
    pub fn get_poly_commitment<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
    ) -> Option<PolyCommitment> {
        if let Some(poly) = &self.f {
            Some(PolyCommitment {
                id: ID::new(&self.id(), &poly.data()[0], rng),
                poly: (0..poly.data().len())
                    .map(|i| &poly.data()[i] * G)
                    .collect(),
            })
        } else {
            warn!("get_poly_commitment called with no polynomial");
            None
        }
    }

    /// Get the shares of this party's private polynomial for all keys
    pub fn get_shares(&self) -> HashMap<u32, Scalar> {
        let mut shares = HashMap::new();
        if let Some(poly) = &self.f {
            for i in 1..self.num_keys + 1 {
                shares.insert(i, poly.eval(compute::id(i)));
            }
        } else {
            warn!("get_poly_commitment called with no polynomial");
        }
        shares
    }

    /// Compute this party's share of the group secret key
    pub fn compute_secret(
        &mut self,
        shares: &HashMap<u32, HashMap<u32, Scalar>>,
        comms: &HashMap<u32, PolyCommitment>,
    ) -> Result<(), DkgError> {
        let mut missing_shares = Vec::new();
        for key_id in &self.key_ids {
            if shares.get(key_id).is_none() {
                missing_shares.push(*key_id);
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingPublicShares(missing_shares));
        }

        self.private_keys.clear();
        self.group_key = Point::zero();

        let threshold: usize = self.threshold.try_into().unwrap();
        let mut bad_ids = Vec::new();
        for (i, comm) in comms.iter() {
            if comm.poly.len() != threshold || !comm.verify() {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
        }
        if !bad_ids.is_empty() {
            return Err(DkgError::BadPublicShares(bad_ids));
        }

        let mut not_enough_shares = Vec::new();
        for key_id in &self.key_ids {
            if shares[key_id].len() != comms.len() {
                warn!(
                    "key_id {} has {} private shares not {}",
                    key_id,
                    shares[key_id].len(),
                    comms.len()
                );
                not_enough_shares.push(*key_id);
            }
        }
        if !not_enough_shares.is_empty() {
            return Err(DkgError::NotEnoughShares(not_enough_shares));
        }

        let mut bad_shares = Vec::new();
        for key_id in &self.key_ids {
            for (sender, s) in &shares[key_id] {
                let comm = &comms[sender];
                if s * G != compute::poly(&compute::id(*key_id), &comm.poly)? {
                    bad_shares.push(*sender);
                }
            }
        }
        if !bad_shares.is_empty() {
            return Err(DkgError::BadPrivateShares(bad_shares));
        }

        for key_id in &self.key_ids {
            self.private_keys.insert(*key_id, Scalar::zero());

            for (_sender, s) in &shares[key_id] {
                self.private_keys
                    .insert(*key_id, self.private_keys[key_id] + s);
            }
        }

        Ok(())
    }

    /// Compute a Scalar from this party's ID
    pub fn id(&self) -> Scalar {
        compute::id(self.party_id)
    }

    /// Sign `msg` with this party's shares of the group private key, using the set of `party_ids`, `key_ids` and corresponding `nonces`
    pub fn sign(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> SignatureShare {
        self.sign_with_tweak(msg, party_ids, key_ids, nonces, None)
    }

    /// Sign `msg` with this party's shares of the group private key, using the set of `party_ids`, `key_ids` and corresponding `nonces` with a tweaked public key. The posible values for tweak are
    /// None    - standard FROST signature
    /// Some(0) - BIP-340 schnorr signature using 32-byte private key adjustments
    /// Some(t) - BIP-340 schnorr signature with BIP-341 tweaked keys, using 32-byte private key adjustments
    #[allow(non_snake_case)]
    pub fn sign_with_tweak(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        tweak: Option<Scalar>,
    ) -> SignatureShare {
        // When using BIP-340 32-byte public keys, we have to invert the private key if the
        // public key is odd.  But if we're also using BIP-341 tweaked keys, we have to do
        // the same thing if the tweaked public key is odd.  In that case, only invert the
        // public key if exactly one of the internal or tweaked public keys is odd
        let mut cx_sign = Scalar::one();
        let tweaked_public_key = if let Some(t) = tweak {
            if t != Scalar::zero() {
                let key = compute::tweaked_public_key_from_tweak(&self.group_key, t);
                if key.has_even_y() ^ self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }

                key
            } else {
                if !self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }
                self.group_key
            }
        } else {
            self.group_key
        };
        let (_, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        if tweak.is_some() && !R.has_even_y() {
            r = -r;
        }

        let mut cx = Scalar::zero();
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }

        cx = cx_sign * cx;

        let z = r + cx;

        SignatureShare {
            id: self.party_id,
            z_i: z,
            key_ids: self.key_ids.clone(),
        }
    }
}

/// The group signature aggregator
#[derive(Clone, Debug, PartialEq)]
pub struct Aggregator {
    /// The total number of keys
    pub num_keys: u32,
    /// The threshold of signing keys needed to construct a valid signature
    pub threshold: u32,
    /// The aggregate group polynomial; poly[0] is the group public key
    pub poly: Vec<Point>,
}

impl Aggregator {
    /// Aggregate the party signatures using a tweak.  The posible values for tweak are
    /// None    - standard FROST signature
    /// Some(0) - BIP-340 schnorr signature using 32-byte private key adjustments
    /// Some(t) - BIP-340 schnorr signature with BIP-341 tweaked keys, using 32-byte private key adjustments
    #[allow(non_snake_case)]
    pub fn sign_with_tweak(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        _key_ids: &[u32],
        tweak: Option<Scalar>,
    ) -> Result<(Point, Signature), AggregatorError> {
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }

        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (_Rs, R) = compute::intermediate(msg, &party_ids, nonces);
        let mut z = Scalar::zero();
        let mut cx_sign = Scalar::one();
        let aggregate_public_key = self.poly[0];
        let tweaked_public_key = if let Some(t) = tweak {
            if t != Scalar::zero() {
                let key = compute::tweaked_public_key_from_tweak(&aggregate_public_key, t);
                if !key.has_even_y() {
                    cx_sign = -cx_sign;
                }
                key
            } else {
                aggregate_public_key
            }
        } else {
            aggregate_public_key
        };
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        // optimistically try to create the aggregate signature without checking for bad keys or sig shares
        for sig_share in sig_shares {
            z += sig_share.z_i;
        }

        // The signature shares have already incorporated the private key adjustments, so we just have to add the tweak.  But the tweak itself needs to be adjusted if the tweaked public key is odd
        if let Some(t) = tweak {
            z += cx_sign * c * t;
        }

        let sig = Signature { R, z };

        Ok((tweaked_public_key, sig))
    }

    /// Check the party signatures after a failed group signature. The posible values for tweak are
    /// None    - standard FROST signature
    /// Some(0) - BIP-340 schnorr signature using 32-byte private key adjustments
    /// Some(t) - BIP-340 schnorr signature with BIP-341 tweaked keys, using 32-byte private key adjustments
    #[allow(non_snake_case)]
    pub fn check_signature_shares(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
        tweak: Option<Scalar>,
    ) -> AggregatorError {
        if nonces.len() != sig_shares.len() {
            return AggregatorError::BadNonceLen(nonces.len(), sig_shares.len());
        }

        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (Rs, R) = compute::intermediate(msg, &party_ids, nonces);
        let mut bad_party_keys = Vec::new();
        let mut bad_party_sigs = Vec::new();
        let aggregate_public_key = self.poly[0];
        let tweaked_public_key = if let Some(t) = tweak {
            if t != Scalar::zero() {
                compute::tweaked_public_key_from_tweak(&aggregate_public_key, t)
            } else {
                aggregate_public_key
            }
        } else {
            aggregate_public_key
        };
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r_sign = Scalar::one();
        let mut cx_sign = Scalar::one();
        if let Some(t) = tweak {
            if !R.has_even_y() {
                r_sign = -Scalar::one();
            }
            if t != Scalar::zero() {
                if !tweaked_public_key.has_even_y() ^ !aggregate_public_key.has_even_y() {
                    cx_sign = -Scalar::one();
                }
            } else if !aggregate_public_key.has_even_y() {
                cx_sign = -Scalar::one();
            }
        }

        for i in 0..sig_shares.len() {
            let z_i = sig_shares[i].z_i;
            let mut cx = Point::zero();

            for key_id in &sig_shares[i].key_ids {
                let kid = compute::id(*key_id);
                let public_key = match compute::poly(&kid, &self.poly) {
                    Ok(p) => p,
                    Err(_) => {
                        bad_party_keys.push(sig_shares[i].id);
                        Point::zero()
                    }
                };

                cx += compute::lambda(*key_id, key_ids) * c * public_key;
            }

            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }
        }
        if !bad_party_keys.is_empty() {
            AggregatorError::BadPartyKeys(bad_party_keys)
        } else if !bad_party_sigs.is_empty() {
            AggregatorError::BadPartySigs(bad_party_sigs)
        } else {
            AggregatorError::BadGroupSig
        }
    }
}

impl traits::Aggregator for Aggregator {
    /// Construct an Aggregator with the passed parameters
    fn new(num_keys: u32, threshold: u32) -> Self {
        Self {
            num_keys,
            threshold,
            poly: Default::default(),
        }
    }

    /// Initialize the Aggregator polynomial
    fn init(&mut self, comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError> {
        let threshold: usize = self.threshold.try_into().unwrap();
        let mut bad_poly_commitments = Vec::new();
        for (_id, comm) in comms {
            if comm.poly.len() != threshold || !comm.verify() {
                bad_poly_commitments.push(comm.id.id);
            }
        }
        if !bad_poly_commitments.is_empty() {
            return Err(AggregatorError::BadPolyCommitments(bad_poly_commitments));
        }

        let mut poly = Vec::with_capacity(self.threshold.try_into().unwrap());

        for i in 0..poly.capacity() {
            poly.push(Point::zero());
            for (_, comm) in comms {
                poly[i] += &comm.poly[i];
            }
        }

        self.poly = poly;

        Ok(())
    }

    /// Check and aggregate the party signatures
    fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<Signature, AggregatorError> {
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, None)?;

        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
        }
    }

    /// Check and aggregate the party signatures
    fn sign_schnorr(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<SchnorrProof, AggregatorError> {
        let tweak = Scalar::from(0);
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, Some(tweak))?;
        let proof = SchnorrProof::new(&sig);

        if proof.verify(&key.x(), msg) {
            Ok(proof)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, Some(tweak)))
        }
    }

    /// Check and aggregate the party signatures
    fn sign_taproot(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
        merkle_root: Option<[u8; 32]>,
    ) -> Result<SchnorrProof, AggregatorError> {
        let tweak = compute::tweak(&self.poly[0], merkle_root);
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, Some(tweak))?;
        let proof = SchnorrProof::new(&sig);

        if proof.verify(&key.x(), msg) {
            Ok(proof)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, Some(tweak)))
        }
    }
}

/// Typedef so we can use the same tokens for v1 and v2
pub type Signer = Party;

impl traits::Signer for Party {
    fn new<RNG: RngCore + CryptoRng>(
        party_id: u32,
        key_ids: &[u32],
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        rng: &mut RNG,
    ) -> Self {
        Party::new(party_id, key_ids, num_signers, num_keys, threshold, rng)
    }

    fn load(state: &traits::SignerState) -> Self {
        // v2 signer contains single party
        assert_eq!(state.parties.len(), 1);

        let party_state = &state.parties[0].1;

        Self {
            party_id: state.id,
            key_ids: state.key_ids.clone(),
            num_keys: state.num_keys,
            num_parties: state.num_parties,
            threshold: state.threshold,
            f: party_state.polynomial.clone(),
            private_keys: party_state
                .private_keys
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            group_key: state.group_key,
            nonce: party_state.nonce.clone(),
        }
    }

    fn save(&self) -> traits::SignerState {
        let party_state = traits::PartyState {
            polynomial: self.f.clone(),
            private_keys: self.private_keys.iter().map(|(k, v)| (*k, *v)).collect(),
            nonce: self.nonce.clone(),
        };
        traits::SignerState {
            id: self.party_id,
            key_ids: self.key_ids.clone(),
            num_keys: self.num_keys,
            num_parties: self.num_parties,
            threshold: self.threshold,
            group_key: self.group_key,
            parties: vec![(self.party_id, party_state)],
        }
    }

    fn get_id(&self) -> u32 {
        self.party_id
    }

    fn get_key_ids(&self) -> Vec<u32> {
        self.key_ids.clone()
    }

    fn get_num_parties(&self) -> u32 {
        self.num_parties
    }

    fn get_poly_commitments<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> Vec<PolyCommitment> {
        if let Some(poly) = self.get_poly_commitment(rng) {
            vec![poly.clone()]
        } else {
            vec![]
        }
    }

    fn reset_polys<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) {
        self.f = Some(VSS::random_poly(self.threshold - 1, rng));
    }

    fn clear_polys(&mut self) {
        self.f = None;
    }

    fn get_shares(&self) -> HashMap<u32, HashMap<u32, Scalar>> {
        let mut shares = HashMap::new();

        shares.insert(self.party_id, self.get_shares());

        shares
    }

    fn compute_secrets(
        &mut self,
        private_shares: &HashMap<u32, HashMap<u32, Scalar>>,
        polys: &HashMap<u32, PolyCommitment>,
    ) -> Result<(), HashMap<u32, DkgError>> {
        // go through the shares, looking for this party's
        let mut key_shares = HashMap::new();
        for dest_key_id in self.get_key_ids() {
            let mut shares = HashMap::new();
            for (src_party_id, signer_shares) in private_shares.iter() {
                if let Some(signer_share) = signer_shares.get(&dest_key_id) {
                    shares.insert(*src_party_id, *signer_share);
                }
            }
            key_shares.insert(dest_key_id, shares);
        }

        match self.compute_secret(&key_shares, polys) {
            Ok(()) => Ok(()),
            Err(dkg_error) => {
                let mut dkg_errors = HashMap::new();
                dkg_errors.insert(self.party_id, dkg_error);
                Err(dkg_errors)
            }
        }
    }

    fn gen_nonces<RNG: RngCore + CryptoRng>(&mut self, rng: &mut RNG) -> Vec<PublicNonce> {
        vec![self.gen_nonce(rng)]
    }

    fn compute_intermediate(
        msg: &[u8],
        signer_ids: &[u32],
        _key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> (Vec<Point>, Point) {
        compute::intermediate(msg, signer_ids, nonces)
    }

    fn sign(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare> {
        vec![self.sign(msg, signer_ids, key_ids, nonces)]
    }

    fn sign_schnorr(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare> {
        vec![self.sign_with_tweak(msg, signer_ids, key_ids, nonces, Some(Scalar::from(0)))]
    }

    fn sign_taproot(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        merkle_root: Option<[u8; 32]>,
    ) -> Vec<SignatureShare> {
        let tweak = compute::tweak(&self.group_key, merkle_root);
        vec![self.sign_with_tweak(msg, signer_ids, key_ids, nonces, Some(tweak))]
    }
}

/// Helper functions for tests
pub mod test_helpers {
    use crate::common::{PolyCommitment, PublicNonce};
    use crate::errors::DkgError;
    use crate::traits::Signer;
    use crate::v2;
    use crate::v2::SignatureShare;

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, RngCore};

    /// Run a distributed key generation round
    pub fn dkg<RNG: RngCore + CryptoRng>(
        signers: &mut [v2::Party],
        rng: &mut RNG,
    ) -> Result<HashMap<u32, PolyCommitment>, HashMap<u32, DkgError>> {
        let mut polys: HashMap<u32, PolyCommitment> = Default::default();
        for signer in signers.iter() {
            if let Some(poly) = signer.get_poly_commitment(rng) {
                polys.insert(signer.get_id(), poly);
            }
        }

        // each party broadcasts their commitments
        let mut broadcast_shares = Vec::new();
        for party in signers.iter() {
            broadcast_shares.push((party.party_id, party.get_shares()));
        }

        // each party collects its shares from the broadcasts
        // maybe this should collect into a hashmap first?
        let mut secret_errors = HashMap::new();
        for party in signers.iter_mut() {
            let mut party_shares = HashMap::new();
            for key_id in party.key_ids.clone() {
                let mut key_shares = HashMap::new();

                for (id, shares) in &broadcast_shares {
                    if let Some(share) = shares.get(&key_id) {
                        key_shares.insert(*id, *share);
                    }
                }

                party_shares.insert(key_id, key_shares);
            }

            if let Err(secret_error) = party.compute_secret(&party_shares, &polys) {
                secret_errors.insert(party.party_id, secret_error);
            }
        }

        if secret_errors.is_empty() {
            Ok(polys)
        } else {
            Err(secret_errors)
        }
    }

    /// Run a signing round for the passed `msg`
    pub fn sign<RNG: RngCore + CryptoRng>(
        msg: &[u8],
        signers: &mut [v2::Party],
        rng: &mut RNG,
    ) -> (Vec<PublicNonce>, Vec<SignatureShare>, Vec<u32>) {
        let party_ids: Vec<u32> = signers.iter().map(|s| s.party_id).collect();
        let key_ids: Vec<u32> = signers.iter().flat_map(|s| s.key_ids.clone()).collect();
        let nonces: Vec<PublicNonce> = signers.iter_mut().map(|s| s.gen_nonce(rng)).collect();
        let shares = signers
            .iter()
            .map(|s| s.sign(msg, &party_ids, &key_ids, &nonces))
            .collect();

        (nonces, shares, key_ids)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        traits::{self, test_helpers::run_compute_secrets_not_enough_shares, Aggregator, Signer},
        v2,
    };

    use rand_core::OsRng;

    #[test]
    fn party_save_load() {
        let mut rng = OsRng;
        let key_ids = [1, 2, 3];
        let n: u32 = 10;
        let t: u32 = 7;

        let signer = v2::Party::new(0, &key_ids, 1, n, t, &mut rng);

        let state = signer.save();
        let loaded = v2::Party::load(&state);

        assert_eq!(signer, loaded);
    }

    #[test]
    fn clear_polys() {
        let mut rng = OsRng;
        let key_ids = [1, 2, 3];
        let n: u32 = 10;
        let t: u32 = 7;

        let mut signer = v2::Party::new(0, &key_ids, 1, n, t, &mut rng);

        assert_eq!(signer.get_poly_commitments(&mut rng).len(), 1);
        assert_eq!(signer.get_shares().len(), n as usize);

        signer.clear_polys();

        assert_eq!(signer.get_poly_commitments(&mut rng).len(), 0);
        assert_eq!(signer.get_shares().len(), 0);
    }

    #[test]
    fn aggregator_sign() {
        let mut rng = OsRng;
        let msg = "It was many and many a year ago".as_bytes();
        let n_k: u32 = 10;
        let t: u32 = 7;
        let party_key_ids: Vec<Vec<u32>> = [
            [1, 2, 3].to_vec(),
            [4, 5].to_vec(),
            [6, 7, 8].to_vec(),
            [9, 10].to_vec(),
        ]
        .to_vec();
        let n_p = party_key_ids.len().try_into().unwrap();
        let mut signers: Vec<v2::Party> = party_key_ids
            .iter()
            .enumerate()
            .map(|(pid, pkids)| {
                v2::Party::new(pid.try_into().unwrap(), pkids, n_p, n_k, t, &mut rng)
            })
            .collect();

        let comms = match traits::test_helpers::dkg(&mut signers, &mut rng) {
            Ok(comms) => comms,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        // signers [0,1,3] who have t keys
        {
            let mut signers = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
            let mut sig_agg = v2::Aggregator::new(n_k, t);

            sig_agg.init(&comms).expect("aggregator init failed");

            let (nonces, sig_shares, key_ids) = v2::test_helpers::sign(msg, &mut signers, &mut rng);
            if let Err(e) = sig_agg.sign(msg, &nonces, &sig_shares, &key_ids) {
                panic!("Aggregator sign failed: {:?}", e);
            }
        }
    }

    #[test]
    /// Run a distributed key generation round with not enough shares
    pub fn run_compute_secrets_missing_shares() {
        run_compute_secrets_not_enough_shares::<v2::Signer>()
    }

    #[test]
    /// Run DKG and aggregator init with a bad polynomial
    pub fn bad_polynomial_length() {
        let gt = |t| t + 1;
        let lt = |t| t - 1;
        traits::test_helpers::bad_polynomial_length::<v2::Signer, v2::Aggregator, _>(gt);
        traits::test_helpers::bad_polynomial_length::<v2::Signer, v2::Aggregator, _>(lt);
    }
}
