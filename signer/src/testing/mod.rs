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
use std::fmt::Display;
use std::ops::Deref;
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
#[error("{0}")]
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

/// Clears all signer-specific configuration environment variables. This is
/// needed for a number of tests which use the `Settings` struct due to the fact
/// that `cargo test` runs tests in threads, and environment variables are
/// per-process.
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
    /// Asserts that the iterator contains exactly one element and returns it.
    /// Panics if the iterator is empty or contains more than one element.
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

/// A wrapper type used by `join_all` to ensure that the results are processed.
#[must_use = "The collected results from `join_all` must be processed."]
pub struct JoinAllResults<T>(Vec<T>);
impl<T> Deref for JoinAllResults<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> IntoIterator for JoinAllResults<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Helper trait to adapt the output of `join_all` based on a future's output type.
pub trait JoinOutputAdapter: Sized {
    /// The type that `join_all().await` will ultimately produce.
    type AdaptedOutput;
    /// Adapts a Vec of raw future outputs into the desired final output.
    fn adapt_outputs(outputs: Vec<Self>) -> Self::AdaptedOutput;
}

/// For futures returning `()`, `join_all().await` will also return `()`, which
/// is not `#[must_use]`. A `Vec<()>` is adapted to `()`.
impl JoinOutputAdapter for () {
    type AdaptedOutput = ();
    fn adapt_outputs(_outputs: Vec<()>) -> Self::AdaptedOutput {}
}

/// For futures returning `Result<T, E>`, `join_all().await` returns
/// `JoinAllResults<Result<T, E>>`, which is `#[must_use]`.
impl<T, E> JoinOutputAdapter for Result<T, E> {
    type AdaptedOutput = JoinAllResults<Result<T, E>>;
    fn adapt_outputs(outputs: Vec<Result<T, E>>) -> Self::AdaptedOutput {
        JoinAllResults(outputs)
    }
}

/// Extension trait for iterators of futures.
pub trait FuturesIterExt: IntoIterator + Sized
where
    Self::Item: Future,
{
    /// Converts an iterator of futures into a single future that resolves when
    /// all futures in the iterator have completed. The output is a Vec of the
    /// outputs of the futures, in the original order.
    ///
    /// The `Output` type of the futures in the iterator must implement
    /// [`JoinOutputAdapter`]. This trait determines the final return type of
    /// `join_all().await`.
    ///
    /// # Examples
    ///
    /// ## Futures returning `()`
    ///
    /// If futures return `()`, `join_all().await` also returns `()`.
    ///
    /// ```
    /// # use signer::testing::FuturesIterExt as _;
    /// # use futures::future::FutureExt as _;
    /// # async fn run() {
    /// let fut1 = async { () };
    /// let fut2 = async { () };
    /// vec![fut1.boxed(), fut2.boxed()]
    ///     .into_iter()
    ///     .join_all()
    ///     .await; // No #[must_use] warning here as it's `()`
    /// # }
    /// ```
    ///
    /// ## Futures returning `Result<T, E>`
    ///
    /// If futures return `Result<T, E>`, `join_all().await` returns
    /// `JoinAllResults<Result<T, E>>`. This wrapper type is `#[must_use]`,
    /// so you'll get a warning if the result is not used.
    ///
    /// ```
    /// # // Note that we can't use `compile_fail` here because it doesn't seem that
    /// # // rustdoc respects `-D warnings`.
    /// # use signer::testing::{FuturesIterExt as _, TestUtilityError};
    /// # use futures::future::{Future, FutureExt as _};
    /// # use std::pin::Pin;
    /// # async fn run() {
    /// type Pbf<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;
    /// let fut1 = async { Ok(1) };
    /// let fut2 = async { Ok(2) };
    /// let futures: Vec<Pbf<i32, TestUtilityError>> = vec![fut1.boxed(), fut2.boxed()];
    /// futures.into_iter().join_all().await; // This line would cause a #[must_use] warning
    /// # }
    /// ```
    ///
    /// ## Compilation Failure for Unsupported Types
    ///
    /// The following will fail to compile because no integer types implement
    /// [`JoinOutputAdapter`].
    ///
    /// ```compile_fail
    /// # use signer::testing::FuturesIterExt as _;
    /// # use futures::future::FutureExt as _;
    /// # async fn run() {
    /// let fut1 = async { 1 };
    /// let fut2 = async { 2 };
    /// vec![fut1.boxed(), fut2.boxed()]
    /// .into_iter()
    /// .join_all()
    /// .await;
    /// # }
    /// ```
    #[track_caller]
    fn join_all(
        self,
    ) -> impl Future<Output = <<Self::Item as Future>::Output as JoinOutputAdapter>::AdaptedOutput>
    where
        <Self::Item as Future>::Output: JoinOutputAdapter;
}

/// Implement the `FuturesIterExt` trait for any iterator that produces futures.
impl<I> FuturesIterExt for I
where
    I: IntoIterator + Sized,
    I::Item: Future,
{
    async fn join_all(self) -> <<Self::Item as Future>::Output as JoinOutputAdapter>::AdaptedOutput
    where
        <Self::Item as Future>::Output: JoinOutputAdapter,
    {
        // Join on all of the futures, consuming `self` and returning a `Vec` of `Results`s
        let results = futures::future::join_all(self).await;

        // Use the adapter to convert Vec<Future::Output> to the final desired type
        <<Self::Item as Future>::Output as JoinOutputAdapter>::adapt_outputs(results)
    }
}

/// Extension trait for iterators of `Result<T, E>`.
pub trait ResultIterExt<T, E>
where
    Self: Sized + IntoIterator<Item = Result<T, E>>,
{
    /// Asserts that every `Result` in the iterator is `Ok`, returning a
    /// `Vec<T>` of the unwrapped values. Panics with the given message and list
    /// of errors if any `Result` is `Err`.
    #[track_caller]
    fn expect_all(self, msg: &str) -> Vec<T>
    where
        E: Display,
    {
        let mut oks = Vec::new();
        let mut errs = Vec::new();

        for item in self.into_iter() {
            match item {
                Ok(value) => oks.push(value),
                Err(err) => errs.push(err),
            }
        }

        if !errs.is_empty() {
            let error_messages = errs
                .iter()
                .enumerate()
                .map(|(i, error)| format!("#{}: {error}", i + 1))
                .collect::<Vec<_>>()
                .join("\n");

            panic!("{msg}:\n\n{error_messages}");
        }

        oks
    }
}

/// Implement the `ResultIterExt` trait for any iterator that produces `Result<T, E>`.
impl<T, E: Display, I: IntoIterator<Item = Result<T, E>>> ResultIterExt<T, E> for I {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::FutureExt;
    use std::boxed::Box;
    use std::pin::Pin;

    type Pbf<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;

    #[tokio::test]
    async fn test_join_all_with_units() {
        let fut1 = async {};
        let fut2 = async {};
        let futures_vec = vec![fut1.boxed(), fut2.boxed()];

        // This should compile without warning because the output is `()`, which
        // is *not* #[must_use].
        futures_vec.into_iter().join_all().await;
        println!("Joined unit futures");
    }

    /// Tests [`FuturesIterExt::join_all`] followed by
    /// [`ResultIterExt::expect_all`] when all futures return `Ok` results,
    /// which should not panic.
    #[tokio::test]
    async fn test_join_all_with_ok_results() {
        let fut1 = async { Ok::<i32, TestUtilityError>(1) };
        let fut2 = async { Ok::<i32, TestUtilityError>(2) };

        let results = vec![fut1.boxed(), fut2.boxed()]
            .into_iter()
            .join_all()
            .await;

        assert_eq!(results.expect_all("Should all be ok"), vec![1, 2]);

        // EXAMPLE: The following will raise a warning if the result is not used.
        // Uncomment to see the warning in action:
        //
        // let fut1 = async { Ok::<i32, TestUtilityError>(1) };
        // let fut2 = async { Ok::<i32, TestUtilityError>(2) };
        // vec![fut1.boxed(), fut2.boxed()]
        //     .into_iter()
        //     .join_all()
        //     .await;
    }

    /// Tests that [`ResultIterExt::expect_all`] panics if any result in the
    /// `join_all` output is an error.
    #[tokio::test]
    #[should_panic(expected = "Some failed:\n\n#1: Oh no!")]
    async fn test_join_all_with_mixed_results_and_expect_all() {
        let fut1: Pbf<i32, TestUtilityError> = Box::pin(async { Ok(1) });
        let fut2: Pbf<i32, TestUtilityError> =
            Box::pin(async { Err(TestUtilityError("Oh no!".into())) });
        let results = vec![fut1, fut2].into_iter().join_all().await;

        results.expect_all("Some failed");
    }

    /// Just an extra verification that everything works as expected with
    /// regular `async` functions.
    #[tokio::test]
    async fn test_join_all_concrete_results() {
        const RESULT1: &str = "hello";
        const RESULT2: &str = "world";

        // Create some concrete async fn's that return `Ok` results
        async fn fut_ok1() -> Result<String, TestUtilityError> {
            Ok(RESULT1.to_string())
        }
        async fn fut_ok2() -> Result<String, TestUtilityError> {
            Ok(RESULT2.to_string())
        }

        let results = vec![fut_ok1().boxed(), fut_ok2().boxed()]
            .into_iter()
            .join_all()
            .await;

        assert_eq!(
            results.expect_all("Concrete should be ok"),
            vec![RESULT1.to_string(), RESULT2.to_string()]
        );
    }
}
