use core::{cmp::PartialEq, fmt::Debug};
use polynomial::Polynomial;

use crate::{
    common::Nonce,
    curve::{point::Point, scalar::Scalar},
};

#[derive(Clone, Debug, PartialEq)]
/// The saved state required to reconstruct a party
pub struct PartyState {
    /// The party's private polynomial
    pub polynomial: Option<Polynomial<Scalar>>,
    /// The key IDS and associate private keys for this party
    pub private_keys: Vec<(u32, Scalar)>,
    /// The nonce being used by this party
    pub nonce: Nonce,
}

#[derive(Clone, Debug, PartialEq)]
/// The saved state required to reconstruct a signer
pub struct SignerState {
    /// The signer ID
    pub id: u32,
    /// The key IDs this signer controls
    pub key_ids: Vec<u32>,
    /// The total number of keys
    pub num_keys: u32,
    /// The total number of parties
    pub num_parties: u32,
    /// The threshold for signing
    pub threshold: u32,
    /// The aggregate group public key
    pub group_key: Point,
    /// The party IDs and associated state for this signer
    pub parties: Vec<(u32, PartyState)>,
}

/// Helper functions for tests
#[cfg(test)]
pub mod test_helpers {
    use rand_core::{CryptoRng, RngCore};
    use std::collections::HashMap;

    use crate::{common::PolyCommitment, errors::DkgError, traits::Scalar, util::create_rng, v2};

    /// Run DKG on the passed signers
    pub fn dkg<RNG: RngCore + CryptoRng>(
        signers: &mut [v2::Party],
        rng: &mut RNG,
    ) -> Result<HashMap<u32, PolyCommitment>, HashMap<u32, DkgError>> {
        let public_shares: HashMap<u32, PolyCommitment> = signers
            .iter()
            .filter_map(|s| s.get_poly_commitment(rng))
            .map(|comm| (comm.id.id.get_u32(), comm))
            .collect();
        let mut private_shares = HashMap::new();

        for signer in signers.iter() {
            for (signer_id, signer_shares) in signer.get_shares_wrapped() {
                private_shares.insert(signer_id, signer_shares);
            }
        }

        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            if let Err(signer_secret_errors) =
                signer.compute_secrets(&private_shares, &public_shares)
            {
                secret_errors.extend(signer_secret_errors.into_iter());
            }
        }

        if secret_errors.is_empty() {
            Ok(public_shares)
        } else {
            Err(secret_errors)
        }
    }

    /// Remove the provided key ids from the list of private shares and execute compute secrets
    fn compute_secrets_missing_private_shares<RNG: RngCore + CryptoRng>(
        signers: &mut [v2::Party],
        rng: &mut RNG,
        missing_key_ids: &[u32],
    ) -> Result<HashMap<u32, PolyCommitment>, HashMap<u32, DkgError>> {
        assert!(
            !missing_key_ids.is_empty(),
            "Cannot run a missing shares test without specificying at least one missing key id"
        );
        let polys: HashMap<u32, PolyCommitment> = signers
            .iter()
            .filter_map(|s| s.get_poly_commitment(rng))
            .map(|comm| (comm.id.id.get_u32(), comm))
            .collect();
        let mut private_shares = HashMap::new();

        for signer in signers.iter() {
            for (signer_id, mut signer_shares) in signer.get_shares_wrapped() {
                for key_id in missing_key_ids {
                    if signer.get_key_ids().contains(key_id) {
                        signer_shares.remove(key_id);
                    }
                }
                private_shares.insert(signer_id, signer_shares);
            }
        }

        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            if let Err(signer_secret_errors) = signer.compute_secrets(&private_shares, &polys) {
                secret_errors.extend(signer_secret_errors.into_iter());
            }
        }

        if secret_errors.is_empty() {
            Ok(polys)
        } else {
            Err(secret_errors)
        }
    }

    #[allow(non_snake_case)]
    /// Run compute secrets test to trigger MissingPrivateShares code path
    pub fn run_compute_secrets_missing_private_shares() {
        let Nk: u32 = 10;
        let Np: u32 = 4;
        let T: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8], vec![9, 10]];
        let missing_key_ids = vec![1, 7];
        let mut rng = create_rng();
        let mut signers: Vec<v2::Party> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| v2::Party::new(id.try_into().unwrap(), ids, Nk, Np, T, &mut rng))
            .collect();

        match compute_secrets_missing_private_shares(&mut signers, &mut rng, &missing_key_ids) {
            Ok(polys) => panic!("Got a result with missing public shares: {polys:?}"),
            Err(secret_errors) => {
                for (_, error) in secret_errors {
                    assert!(matches!(error, DkgError::MissingPrivateShares(_)));
                }
            }
        }
    }

    /// Check that bad polynomial lengths are properly caught as errors during DKG
    pub fn bad_polynomial_length<F: Fn(u32) -> u32>(func: F) {
        let num_keys: u32 = 10;
        let num_signers: u32 = 4;
        let threshold: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7], vec![8, 9], vec![10]];
        let mut rng = create_rng();
        let mut signers: Vec<v2::Party> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| {
                if *ids == vec![10] {
                    v2::Party::new(
                        id.try_into().unwrap(),
                        ids,
                        num_signers,
                        num_keys,
                        func(threshold),
                        &mut rng,
                    )
                } else {
                    v2::Party::new(
                        id.try_into().unwrap(),
                        ids,
                        num_signers,
                        num_keys,
                        threshold,
                        &mut rng,
                    )
                }
            })
            .collect();

        if dkg(&mut signers, &mut rng).is_ok() {
            panic!("DKG should have failed")
        }
    }

    /// Check that bad polynomial commitments are properly caught as errors during DKG
    pub fn bad_polynomial_commitment() {
        let num_keys: u32 = 10;
        let num_signers: u32 = 4;
        let threshold: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7], vec![8, 9], vec![10]];
        let mut rng = create_rng();
        let mut signers: Vec<v2::Party> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| {
                v2::Party::new(
                    id.try_into().unwrap(),
                    ids,
                    num_signers,
                    num_keys,
                    threshold,
                    &mut rng,
                )
            })
            .collect();

        // The code that follows is essentially the same code that we have
        // in the `dkg` helper function above, except we've corrupted the
        // schnorr proof so that we can test verification would fail at
        // the end.
        let bad_party_id = 2u32;
        let public_shares: HashMap<u32, PolyCommitment> = signers
            .iter()
            .filter_map(|s| s.get_poly_commitment(&mut rng))
            .map(|comm| {
                let party_id = comm.id.id.get_u32();
                if party_id == bad_party_id {
                    // alter the schnorr proof so it will fail verification
                    let mut bad_comm = comm.clone();
                    bad_comm.id.kca += Scalar::from(1);
                    (party_id, bad_comm)
                } else {
                    (party_id, comm)
                }
            })
            .collect();
        let mut private_shares = HashMap::new();

        for signer in signers.iter() {
            for (signer_id, signer_shares) in signer.get_shares_wrapped() {
                private_shares.insert(signer_id, signer_shares);
            }
        }

        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            if let Err(signer_secret_errors) =
                signer.compute_secrets(&private_shares, &public_shares)
            {
                secret_errors.extend(signer_secret_errors.into_iter());
            }
        }

        assert!(!secret_errors.is_empty());
    }
}
