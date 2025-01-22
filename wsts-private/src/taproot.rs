use crate::{
    common::Signature,
    compute,
    curve::{
        field,
        point::{Point, G},
        scalar::Scalar,
    },
};

/// A SchnorrProof in BIP-340 format
#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    /// The schnorr public commitment (FROST Signature R)
    pub r: field::Element,
    /// The schnorr response (FROST Signature z)
    pub s: Scalar,
}

impl SchnorrProof {
    /// Construct a BIP-340 schnorr proof from a FROST signature
    pub fn new(sig: &Signature) -> Self {
        Self { r: sig.R.x(), s: sig.z }
    }

    /// Verify a BIP-340 schnorr proof
    #[allow(non_snake_case)]
    pub fn verify(&self, public_key: &field::Element, msg: &[u8]) -> bool {
        let Y = match Point::lift_x(public_key) {
            Ok(Y) => Y,
            Err(_) => return false,
        };
        let R = match Point::lift_x(&self.r) {
            Ok(R) => R,
            Err(_) => return false,
        };
        let c = compute::challenge(&Y, &R, msg);
        let Rp = self.s * G - c * Y;

        Rp.has_even_y() && Rp.x() == self.r
    }

    /// Serialize this proof into a 64-byte buffer
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        bytes[0..32].copy_from_slice(&self.r.to_bytes());
        bytes[32..64].copy_from_slice(&self.s.to_bytes());

        bytes
    }
}

impl From<[u8; 64]> for SchnorrProof {
    fn from(bytes: [u8; 64]) -> Self {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];

        r_bytes.copy_from_slice(&bytes[0..32]);
        s_bytes.copy_from_slice(&bytes[32..64]);

        Self {
            r: field::Element::from(r_bytes),
            s: Scalar::from(s_bytes),
        }
    }
}

/// Helper functions for tests
pub mod test_helpers {
    use crate::{
        common::{PolyCommitment, PublicNonce, SignatureShare},
        errors::DkgError,
        traits,
    };

    use hashbrown::HashMap;
    use rand_core::{CryptoRng, RngCore};

    /// Run a distributed key generation round
    #[allow(non_snake_case)]
    pub fn dkg<RNG: RngCore + CryptoRng, Signer: traits::Signer>(
        signers: &mut [Signer],
        rng: &mut RNG,
    ) -> Result<HashMap<u32, PolyCommitment>, HashMap<u32, DkgError>> {
        let polys: HashMap<u32, PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(rng))
            .map(|comm| (comm.id.id.get_u32(), comm))
            .collect();

        let mut private_shares = HashMap::new();
        for signer in signers.iter() {
            for (signer_id, signer_shares) in signer.get_shares() {
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
    fn sign_params<RNG: RngCore + CryptoRng, Signer: traits::Signer>(
        signers: &mut [Signer],
        rng: &mut RNG,
    ) -> (Vec<u32>, Vec<u32>, Vec<PublicNonce>) {
        let signer_ids: Vec<u32> = signers.iter().map(|s| s.get_id()).collect();
        let key_ids: Vec<u32> = signers.iter().flat_map(|s| s.get_key_ids()).collect();
        let nonces: Vec<PublicNonce> = signers.iter_mut().flat_map(|s| s.gen_nonces(rng)).collect();

        (signer_ids, key_ids, nonces)
    }

    /// Run a signing round for the passed `msg`
    #[allow(non_snake_case)]
    pub fn sign<RNG: RngCore + CryptoRng, Signer: traits::Signer>(
        msg: &[u8],
        signers: &mut [Signer],
        rng: &mut RNG,
        merkle_root: Option<[u8; 32]>,
    ) -> (Vec<PublicNonce>, Vec<SignatureShare>) {
        let (signer_ids, key_ids, nonces) = sign_params(signers, rng);
        let shares = signers
            .iter()
            .flat_map(|s| s.sign_taproot(msg, &signer_ids, &key_ids, &nonces, merkle_root))
            .collect();

        (nonces, shares)
    }
}

#[cfg(test)]
mod test {
    use super::{test_helpers, Point, Scalar, SchnorrProof, G};

    use crate::{compute, traits::Aggregator, traits::Signer, v1, v2};
    use rand_core::OsRng;

    #[test]
    #[allow(non_snake_case)]
    fn key_tweaks() {
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let R = r * G;
        let rp = if R.has_even_y() { r } else { -r };
        let mut d = Scalar::random(&mut rng);
        let mut P = d * G;
        let msg = "sign me";
        let c = compute::challenge(&P, &R, msg.as_bytes());

        println!("P.has_even_y {}", P.has_even_y());
        println!("R.has_even_y {}", R.has_even_y());

        let s = r - c * d;
        assert!(R == s * G + c * P);

        while P.has_even_y() {
            d = Scalar::random(&mut rng);
            P = d * G;
        }

        println!("P.has_even_y {}", P.has_even_y());
        let c = compute::challenge(&P, &R, msg.as_bytes());
        let s = r - c * d;
        assert!(R == s * G + c * P);

        assert!(!P.has_even_y());
        assert_eq!(d * G, P);

        let s = rp + c * (-d);
        assert!(Point::lift_x(&R.x()).unwrap() == s * G - c * Point::lift_x(&P.x()).unwrap());

        let proof = SchnorrProof { r: R.x(), s };
        {
            let Pp = Point::lift_x(&P.x()).unwrap();
            assert!(Pp == (-d) * G);
            let R = Point::lift_x(&proof.r).unwrap();
            let e = compute::challenge(&P, &R, msg.as_bytes());
            let Rp = proof.s * G - e * Pp;
            assert!(Rp.has_even_y());
            assert_eq!(Rp.x(), proof.r);
        }
        assert!(proof.verify(&P.x(), msg.as_bytes()));

        let Q = Point::lift_x(&P.x()).unwrap();
        let c = compute::challenge(&Q, &R, msg.as_bytes());
        println!("Q.has_even_y {}", Q.has_even_y());

        assert!(Q != P);
        assert!(d * G != Q);

        let e = -d;

        assert!(e * G == Q);

        let s = r + c * e;
        assert!(R == s * G - c * Q);

        let s = rp + c * e;
        let proof = SchnorrProof { r: R.x(), s };
        assert!(proof.verify(&Q.x(), msg.as_bytes()));

        {
            let P = Point::lift_x(&Q.x()).unwrap();
            let R = Point::lift_x(&proof.r).unwrap();
            let e = compute::challenge(&Q, &R, msg.as_bytes());
            //let e = c.clone();
            let Rp = proof.s * G - e * P;
            assert!(Rp.has_even_y());
            assert_eq!(Rp.x(), proof.r);
        }

        /*
        d = Scalar::random(&mut rng);
        P = d * G;
        e = Scalar::random(&mut rng);
        Q = e * G;
        */
        let S = compute::tweaked_public_key(&P, None);
        println!("S.has_even_y {}", S.has_even_y());
        let t = compute::tweak(&P, None);
        //let d = if !P.has_even_y() || !S.has_even_y() {
        //let d = if !S.has_even_y() {
        let d = if !P.has_even_y() { -d + t } else { d + t };
        assert!((d * G).x() == S.x());
        assert!((d * G) == S);

        let c = compute::challenge(&S, &R, msg.as_bytes());
        let s = r - c * d;
        assert!(R == s * G + c * S);

        let d = if !S.has_even_y() { -d } else { d };

        let s = rp + c * d;
        let proof = SchnorrProof { r: R.x(), s };
        {
            let P = Point::lift_x(&S.x()).unwrap();
            let R = Point::lift_x(&proof.r).unwrap();
            let e = compute::challenge(&S, &R, msg.as_bytes());
            //let e = c.clone();
            let Rp = proof.s * G - e * P;
            assert!(Rp.has_even_y());
            assert_eq!(Rp.x(), proof.r);
        }
        assert!(proof.verify(&S.x(), msg.as_bytes()));

        let T = compute::tweaked_public_key(&Q, None);
        println!("T.has_even_y {}", T.has_even_y());
        let t = compute::tweak(&Q, None);
        //let e = if !Q.has_even_y() || !T.has_even_y() {
        //let e = if !T.has_even_y() {
        let e = if !Q.has_even_y() { -e + t } else { e + t };
        assert!((e * G).x() == T.x());
        assert!((e * G) == T);

        let c = compute::challenge(&T, &R, msg.as_bytes());
        let s = r - c * e;
        assert!(R == s * G + c * T);

        let e = if !T.has_even_y() { -e } else { e };

        let s = rp + c * e;
        let schnorr_proof = SchnorrProof { r: R.x(), s };
        assert!(schnorr_proof.verify(&T.x(), msg.as_bytes()));
    }

    #[test]
    #[allow(non_snake_case)]
    fn taproot_sign_verify_v1_with_merkle_root() {
        let script = "OP_1".as_bytes();
        let merkle_root = compute::merkle_root(script);

        taproot_sign_verify_v1(Some(merkle_root));
    }

    #[test]
    #[allow(non_snake_case)]
    fn taproot_sign_verify_v1_no_merkle_root() {
        taproot_sign_verify_v1(None);
    }

    #[allow(non_snake_case)]
    fn taproot_sign_verify_v1(merkle_root: Option<[u8; 32]>) {
        let mut rng = OsRng;

        // First create and verify a frost signature
        let msg = "It was many and many a year ago".as_bytes();
        let N: u32 = 10;
        let T: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = [
            [1, 2, 3].to_vec(),
            [4, 5].to_vec(),
            [6, 7, 8].to_vec(),
            [9, 10].to_vec(),
        ]
        .to_vec();
        let mut signers: Vec<v1::Signer> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| v1::Signer::new(id.try_into().unwrap(), ids, N, T, &mut rng))
            .collect();

        let polys = match test_helpers::dkg(&mut signers, &mut rng) {
            Ok(polys) => polys,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        let mut S = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
        let mut sig_agg = v1::Aggregator::new(N, T);
        sig_agg.init(&polys).expect("aggregator init failed");
        let aggregate_public_key = sig_agg.poly[0];
        println!(
            "sign_verify:  agg_pubkey    {}",
            &hex::encode(sig_agg.poly[0].compress().as_bytes())
        );
        println!("sign_verify:  agg_pubkey.x  {}", &sig_agg.poly[0].x());
        let tweaked_public_key = compute::tweaked_public_key(&aggregate_public_key, merkle_root);
        println!(
            "sign_verify: tweaked_key    {}",
            &hex::encode(tweaked_public_key.compress().as_bytes())
        );
        println!("sign_verify: tweaked_key.x  {}", &tweaked_public_key.x());
        let (nonces, sig_shares) = test_helpers::sign(msg, &mut S, &mut rng, merkle_root);
        let proof = match sig_agg.sign_taproot(msg, &nonces, &sig_shares, &[], merkle_root) {
            Err(e) => panic!("Aggregator sign failed: {:?}", e),
            Ok(proof) => proof,
        };

        // now ser/de the proof
        let proof_bytes = proof.to_bytes();
        let proof_deser = SchnorrProof::from(proof_bytes);

        assert_eq!(proof, proof_deser);
        assert!(proof_deser.verify(&tweaked_public_key.x(), msg));
    }

    #[test]
    #[allow(non_snake_case)]
    fn taproot_sign_verify_v2_with_merkle_root() {
        let script = "OP_1".as_bytes();
        let merkle_root = compute::merkle_root(script);

        taproot_sign_verify_v2(Some(merkle_root));
    }

    #[test]
    #[allow(non_snake_case)]
    fn taproot_sign_verify_v2_no_merkle_root() {
        taproot_sign_verify_v2(None);
    }

    #[allow(non_snake_case)]
    fn taproot_sign_verify_v2(merkle_root: Option<[u8; 32]>) {
        let mut rng = OsRng;

        // First create and verify a frost signature
        let msg = "It was many and many a year ago".as_bytes();
        let Nk: u32 = 10;
        let Np: u32 = 4;
        let T: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = [
            [1, 2, 3].to_vec(),
            [4, 5].to_vec(),
            [6, 7, 8].to_vec(),
            [9, 10].to_vec(),
        ]
        .to_vec();
        let mut signers: Vec<v2::Signer> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| v2::Signer::new(id.try_into().unwrap(), ids, Np, Nk, T, &mut rng))
            .collect();

        let polys = match test_helpers::dkg(&mut signers, &mut rng) {
            Ok(polys) => polys,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        let mut S = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
        let key_ids = S.iter().flat_map(|s| s.get_key_ids()).collect::<Vec<u32>>();
        let mut sig_agg = v2::Aggregator::new(Nk, T);
        sig_agg.init(&polys).expect("aggregator init failed");
        let tweaked_public_key = compute::tweaked_public_key(&sig_agg.poly[0], merkle_root);
        let (nonces, sig_shares) = test_helpers::sign(msg, &mut S, &mut rng, merkle_root);
        let proof = match sig_agg.sign_taproot(msg, &nonces, &sig_shares, &key_ids, merkle_root) {
            Err(e) => panic!("Aggregator sign failed: {:?}", e),
            Ok(proof) => proof,
        };

        // now ser/de the proof
        let proof_bytes = proof.to_bytes();
        let proof_deser = SchnorrProof::from(proof_bytes);

        assert_eq!(proof, proof_deser);
        assert!(proof_deser.verify(&tweaked_public_key.x(), msg));
    }
}
