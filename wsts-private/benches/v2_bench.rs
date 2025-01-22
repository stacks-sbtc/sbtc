use wsts::common::test_helpers::gen_signer_ids;
use wsts::traits::Aggregator;
use wsts::v2;
use wsts::v2::test_helpers::{dkg, sign};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

const N: u32 = 20;
const T: u32 = 13;
const K: u32 = 4;

#[allow(non_snake_case)]
pub fn bench_dkg(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let party_key_ids = gen_signer_ids(N, K);
    let mut signers: Vec<v2::Party> = party_key_ids
        .iter()
        .enumerate()
        .map(|(pid, pkids)| {
            v2::Party::new(
                pid.try_into().unwrap(),
                pkids,
                party_key_ids.len().try_into().unwrap(),
                N,
                T,
                &mut rng,
            )
        })
        .collect();

    let s = format!("v2 dkg N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| b.iter(|| dkg(&mut signers, &mut rng)));
}

#[allow(non_snake_case)]
pub fn bench_party_sign(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let msg = "It was many and many a year ago".as_bytes();
    let party_key_ids = gen_signer_ids(N.try_into().unwrap(), K.try_into().unwrap());
    let mut signers: Vec<v2::Party> = party_key_ids
        .iter()
        .enumerate()
        .map(|(pid, pkids)| {
            v2::Party::new(
                pid.try_into().unwrap(),
                pkids,
                party_key_ids.len().try_into().unwrap(),
                N,
                T,
                &mut rng,
            )
        })
        .collect();

    let _A = match dkg(&mut signers, &mut rng) {
        Ok(A) => A,
        Err(secret_errors) => {
            panic!("Got secret errors from DKG: {:?}", secret_errors);
        }
    };

    let mut signers = signers[..(K * 3 / 4).try_into().unwrap()].to_vec();

    let s = format!("v2 party sign N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| b.iter(|| sign(&msg, &mut signers, &mut rng)));
}

#[allow(non_snake_case)]
pub fn bench_aggregator_sign(c: &mut Criterion) {
    let mut rng = OsRng::default();
    let msg = "It was many and many a year ago".as_bytes();
    let party_key_ids = gen_signer_ids(N, K);
    let mut signers: Vec<v2::Party> = party_key_ids
        .iter()
        .enumerate()
        .map(|(pid, pkids)| {
            v2::Party::new(
                pid.try_into().unwrap(),
                pkids,
                party_key_ids.len().try_into().unwrap(),
                N,
                T,
                &mut rng,
            )
        })
        .collect();

    let A = match dkg(&mut signers, &mut rng) {
        Ok(A) => A,
        Err(secret_errors) => {
            panic!("Got secret errors from DKG: {:?}", secret_errors);
        }
    };

    let mut signers = signers[..(K * 3 / 4).try_into().unwrap()].to_vec();
    let mut aggregator = v2::Aggregator::new(N, T);

    aggregator.init(&A).expect("aggregator init failed");

    let (nonces, sig_shares, key_ids) = sign(&msg, &mut signers, &mut rng);

    let s = format!("v2 group sign N={} T={} K={}", N, T, K);
    c.bench_function(&s, |b| {
        b.iter(|| aggregator.sign(&msg, &nonces, &sig_shares, &key_ids))
    });
}

criterion_group!(benches, bench_dkg, bench_party_sign, bench_aggregator_sign);
criterion_main!(benches);
