//! Module with testing utility functions.

#![allow(clippy::unwrap_in_result, clippy::unwrap_used, clippy::expect_used)]

pub mod api_clients;
pub mod block_observer;
pub mod blocks;
pub mod btc;
pub mod context;
pub mod dummy;
pub mod message;
pub mod network;
pub mod request_decider;
pub mod stacks;
pub mod storage;
pub mod transaction_coordinator;
pub mod transaction_signer;
pub mod wallet;
pub mod wsts;

use std::fmt::Debug;
use std::time::Duration;

use bitcoin::TapSighashType;
use bitcoin::Witness;
use bitcoin::key::TapTweak;
use secp256k1::SECP256K1;

use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::{OsRng, StdRng};

use crate::bitcoin::utxo::UnsignedTransaction;
use crate::config::Settings;

/// A type alias for `Arc<std::sync::RwLock<T>>`.
pub type StdArcRwLock<T> = std::sync::Arc<std::sync::RwLock<T>>;

/// The path for the configuration file that we should use during testing.
pub const DEFAULT_CONFIG_PATH: Option<&str> = Some("./src/config/default");

impl Settings {
    /// Create a new `Settings` instance from the default configuration file.
    /// This is useful for testing.
    pub fn new_from_default_config() -> Result<Self, config::ConfigError> {
        Self::new(DEFAULT_CONFIG_PATH)
    }
}

/// A custom error type for testing utilities. This is used to wrap errors
/// that occur in the testing utilities, allowing them to be easily handled
/// and reported instead of panicking directly from within the utility code,
/// which otherwise makes it more difficult to determine the exact call site of
/// the error.
#[derive(Debug, thiserror::Error)]
#[error("Test utility error: {0}")]
pub struct TestUtilityError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>);

impl TestUtilityError {
    /// Create a new `TestUtilityError` from an error that implements `std::error::Error`.
    /// Note that we provide this explicit impl because `From<dyn std::error::Error>` has
    /// a conflicting blanket implementation.
    pub fn from_err<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self(Box::new(err))
    }
}

impl From<String> for TestUtilityError {
    fn from(msg: String) -> Self {
        Self(msg.into())
    }
}

impl From<&str> for TestUtilityError {
    fn from(msg: &str) -> Self {
        Self(msg.to_string().into())
    }
}

impl From<crate::error::Error> for TestUtilityError {
    fn from(err: crate::error::Error) -> Self {
        Self(Box::new(err))
    }
}

/// A trait for mapping a `Result<T, E>` to a `Result<T, TestUtilityError>`.
pub trait MapTestUtilityError<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Maps the error type of a `Result<T, E>` to a `TestUtilityError`.
    fn map_to_test_utility_err(self) -> Result<T, TestUtilityError>;
}

impl<T, E> MapTestUtilityError<T, E> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn map_to_test_utility_err(self) -> Result<T, TestUtilityError> {
        self.map_err(TestUtilityError::from_err)
    }
}

/// Clears all signer-specific configuration environment variables. This is needed
/// for a number of tests which use the `Settings` struct due to the fact that
/// `cargo test` runs tests in threads, and environment variables are per-process.
///
/// If we switched to `cargo nextest` (which runs tests in separate processes),
/// this would no longer be needed.
pub fn clear_env() {
    for var in std::env::vars() {
        if var.0.starts_with("SIGNER_") {
            unsafe {
                std::env::remove_var(var.0);
            }
        }
    }
}

/// A wrapper for setting environment variables in tests
pub fn set_var<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(key: K, value: V) {
    unsafe {
        std::env::set_var(key, value);
    }
}
/// A helper function for correctly setting witness data
pub fn set_witness_data(unsigned: &mut UnsignedTransaction, keypair: secp256k1::Keypair) {
    let sighash_type = TapSighashType::All;
    let sighashes = unsigned.construct_digests().unwrap();

    let signer_msg = secp256k1::Message::from(sighashes.signers);
    let tweaked = keypair.tap_tweak(SECP256K1, None);
    let signature = SECP256K1.sign_schnorr(&signer_msg, &tweaked.to_inner());
    let signature = bitcoin::taproot::Signature { signature, sighash_type };
    let signer_witness = Witness::p2tr_key_spend(&signature);

    let deposit_witness = sighashes.deposits.into_iter().map(|(deposit, sighash)| {
        let deposit_msg = secp256k1::Message::from(sighash);
        let signature = SECP256K1.sign_schnorr(&deposit_msg, &keypair);
        let signature = bitcoin::taproot::Signature { signature, sighash_type };
        deposit.construct_witness_data(signature)
    });

    let witness_data: Vec<Witness> = std::iter::once(signer_witness)
        .chain(deposit_witness)
        .collect();

    unsigned
        .tx
        .input
        .iter_mut()
        .zip(witness_data)
        .for_each(|(tx_in, witness)| {
            tx_in.witness = witness;
        });
}

/// Testing helpers for [`Vec`].
pub trait IterTestExt<T>
where
    Self: IntoIterator<Item = T> + Sized,
{
    /// Asserts that the iterator contains exactly one element and returns it. Panics if
    /// the iterator is empty or contains more than one element.
    #[track_caller]
    fn single(self) -> T {
        let mut iter = self.into_iter();
        let item = iter
            .next()
            .expect("expected exactly one element, but got none");
        assert!(
            iter.next().is_none(),
            "expected exactly one element, but got more"
        );
        item
    }
}

impl<I, T> IterTestExt<T> for I where I: IntoIterator<Item = T> + Sized {}

/// Returns a seedable rng with random seed. Prints the seed to
/// stderr so that it can be used to reproduce the test
pub fn get_rng() -> StdRng {
    let seed = OsRng.next_u64();

    // Nextest prints stderr only for failing tests, so this message
    // will only appear if the test fails (by default).
    eprintln!("Test executed with seed: {seed}");
    StdRng::seed_from_u64(seed)
}

/// Generic trait for generating random values of type `T`.
pub trait GenerateRandom<T> {
    /// Generates a random value of type `T`.
    fn gen_one<R: RngCore>(rng: &mut R) -> T;

    /// Generates a vector of `n` random values of type `T`.
    fn gen_many<R: RngCore>(rng: &mut R, n: usize) -> Vec<T> {
        (0..n).map(|_| Self::gen_one(rng)).collect()
    }
}

/// Async sleep extensions.
pub trait SleepAsyncExt {
    /// Sleeps for the specified duration asynchronously.
    fn sleep(self) -> impl Future<Output = ()>;
}

impl SleepAsyncExt for std::time::Duration {
    async fn sleep(self) {
        tokio::time::sleep(self).await;
    }
}

/// Async timeout extensions.
pub trait TimeoutAsyncExt {
    /// Wraps a future with a timeout that expires after the specified duration.
    #[track_caller]
    fn with_timeout<F>(self, future: F) -> tokio::time::Timeout<F::IntoFuture>
    where
        F: IntoFuture;
}

impl TimeoutAsyncExt for std::time::Duration {
    fn with_timeout<F>(self, future: F) -> tokio::time::Timeout<F::IntoFuture>
    where
        F: IntoFuture,
    {
        tokio::time::timeout(self, future)
    }
}

/// Async extensions for `Future` types.
pub trait FutureExt: Future {
    /// Wraps the future with a timeout that expires after the specified duration.
    #[track_caller]
    fn with_timeout(self, duration: std::time::Duration) -> tokio::time::Timeout<Self>
    where
        Self: Sized,
    {
        tokio::time::timeout(duration, self)
    }
}

impl<F: Future> FutureExt for F {}

/// Add `join_all` functionality to iterators of futures.
pub trait FuturesIterExt: IntoIterator + Sized
where
    Self::Item: Future,
{
    /// Converts an iterator of futures into a single future that resolves
    /// when all futures in the iterator have completed.
    /// The output is a Vec of the outputs of the futures, in the original order.
    fn join_all(self) -> futures::future::JoinAll<Self::Item>;
}

impl<I> FuturesIterExt for I
where
    I: IntoIterator + Sized,
    I::Item: Future,
{
    fn join_all(self) -> futures::future::JoinAll<Self::Item> {
        futures::future::join_all(self)
    }
}

/// A utility struct for sleeping asynchronously.
pub struct Sleep;
impl Sleep {
    /// Sleeps for the specified number of seconds asynchronously.
    pub async fn for_secs(secs: u64) {
        Duration::from_secs(secs).sleep().await;
    }

    /// Sleeps for the specified number of milliseconds asynchronously.
    pub async fn for_millis(millis: u64) {
        Duration::from_millis(millis).sleep().await;
    }
}
