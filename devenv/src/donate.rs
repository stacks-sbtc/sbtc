//! `wait-and-donate` subcommand.
//!
//! The signers need a "donation" UTXO sitting at the P2TR address derived
//! from their aggregate key before they can sweep any user deposits.
//!
//! This subcommand polls the Stacks node until the sBTC signers' aggregate
//! key is set, then builds, signs, and broadcasts the donation transaction
//! through the local depositor wallet on bitcoin-core.

use std::num::NonZeroU64;
use std::time::Duration;

use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::absolute;
use bitcoin::transaction::Version;
use bitcoincore_rpc::Client as BitcoinClient;
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc::json::ListUnspentQueryOptions;
use bitcoincore_rpc::json::ListUnspentResultEntry;
use clap::Args;
use secp256k1::PublicKey;
use secp256k1::SECP256K1;
use url::Url;

use crate::error::Error;
use crate::stacks::StacksClient;

/// Default Stacks principal that deployed the sbtc contracts in devenv.
const DEMO_DEPLOYER: &str = "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS";

/// Amount sent to the signers in the donation transaction.
const DONATION_AMOUNT: Amount = Amount::from_sat(10_000);

/// Flat fee in sats we burn when broadcasting the donation.
const DONATION_FEE: Amount = Amount::from_sat(300);

/// Default interval between Stacks node polls when waiting for the aggregate
/// key to appear.
const DEFAULT_POLL_INTERVAL_SECS: NonZeroU64 = NonZeroU64::new(10).unwrap();

/// Arguments for the `wait-and-donate` subcommand.
#[derive(Debug, Args)]
pub struct WaitAndDonateArgs {
    /// Stacks principal that deployed the sbtc contracts.
    ///
    /// We don't validate the format ourselves — the Stacks node rejects
    /// malformed principals with a 4xx, which propagates as
    /// [`Error::StacksRpc`].
    #[clap(long = "deployer", env = "DEPLOYER_ADDRESS", default_value = DEMO_DEPLOYER)]
    pub deployer: String,
    /// Interval between Stacks node polls, in seconds.
    #[clap(
        long = "poll-interval",
        env = "POLL_INTERVAL_SECS",
        default_value_t = DEFAULT_POLL_INTERVAL_SECS,
    )]
    pub poll_interval_secs: NonZeroU64,
    /// Base URL of the Stacks node to query.
    #[clap(long = "stacks-rpc-url", env = "STACKS_RPC_URL")]
    pub stacks_rpc_url: Url,
    /// Bitcoin RPC URL with embedded credentials and wallet path (for
    /// example, `http://devnet:devnet@bitcoin:18443/wallet/depositor`).
    ///
    /// The wallet path is mandatory because bitcoind routes wallet-scoped
    /// RPCs by URL path.
    #[clap(long = "bitcoin-rpc-url", env = "BITCOIN_RPC_URL")]
    pub bitcoin_rpc_url: Url,
}

/// Entry point for the subcommand.
///
/// Polls the Stacks node until the aggregate key is set, then builds and
/// broadcasts a donation transaction to the sbtc signers. The function
/// only returns successfully once a donation `txid` has been submitted.
pub async fn run(args: WaitAndDonateArgs) -> Result<(), Error> {
    let stacks = StacksClient::new(args.stacks_rpc_url)?;
    let bitcoin = build_bitcoin_client(&args.bitcoin_rpc_url)?;
    let poll_interval = Duration::from_secs(args.poll_interval_secs.get());

    let aggregate_key = wait_for_aggregate_key(&stacks, &args.deployer, poll_interval).await;
    tracing::info!(%aggregate_key, "aggregate key is set, broadcasting donation");

    let unsigned_tx = build_donation_tx(&bitcoin, &aggregate_key)?;
    let signed_tx = bitcoin.sign_raw_transaction_with_wallet(&unsigned_tx, None, None)?;
    let txid = bitcoin.send_raw_transaction(&signed_tx.hex)?;

    tracing::info!(%txid, "donation transaction broadcast");
    println!("{txid}");
    Ok(())
}

/// Poll the Stacks node for the aggregate pubkey, sleeping `poll_interval`
/// between attempts.
///
/// RPC errors are retried. The loop only exits when the data var holds a
/// real key. We never give up, we aren't quitters.
async fn wait_for_aggregate_key(
    stacks: &StacksClient,
    deployer: &str,
    poll_interval: Duration,
) -> PublicKey {
    loop {
        match stacks.get_current_aggregate_key(deployer).await {
            Ok(Some(key)) => return key,
            Ok(None) => tracing::debug!("aggregate key is unset, sleeping"),
            Err(error) => tracing::warn!(%error, "Stacks RPC error fetching aggregate key"),
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// Build the donation transaction.
///
/// We ask bitcoind for a single UTXO large enough to cover the donation
/// plus the flat fee, and spend it into two outputs: the donation to the
/// signers' P2TR address for the fixed [`DONATION_AMOUNT`] and the rest
/// back to the depositor wallet as change.
fn build_donation_tx(
    bitcoin: &BitcoinClient,
    aggregate_key: &PublicKey,
) -> Result<Transaction, Error> {
    let minimum = DONATION_AMOUNT + DONATION_FEE;
    let unspent = select_utxo(bitcoin, minimum)?;

    let (x_only, _) = aggregate_key.x_only_public_key();
    let signers_script_pubkey = ScriptBuf::new_p2tr(SECP256K1, x_only, None);

    Ok(Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: unspent.txid,
                vout: unspent.vout,
            },
            sequence: Sequence::ZERO,
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: DONATION_AMOUNT,
                script_pubkey: signers_script_pubkey,
            },
            TxOut {
                value: unspent.amount - minimum,
                script_pubkey: unspent.script_pub_key,
            },
        ],
    })
}

/// Pick a confirmed UTXO from the depositor wallet that covers at least
/// the given `minimum` amount.
fn select_utxo(bitcoin: &BitcoinClient, minimum: Amount) -> Result<ListUnspentResultEntry, Error> {
    let opts = ListUnspentQueryOptions {
        minimum_amount: Some(minimum),
        ..Default::default()
    };
    bitcoin
        .list_unspent(Some(1), None, None, None, Some(opts))?
        .into_iter()
        .next()
        .ok_or(Error::NoAvailableUtxos)
}

/// Build a [`BitcoinClient`] from a URL with embedded credentials.
fn build_bitcoin_client(url: &Url) -> Result<BitcoinClient, Error> {
    let username = url.username().to_string();
    let password = url.password().unwrap_or_default().to_string();

    let mut endpoint = url.clone();
    let _ = endpoint.set_username("");
    let _ = endpoint.set_password(None);

    BitcoinClient::new(
        endpoint.as_str(),
        bitcoincore_rpc::Auth::UserPass(username, password),
    )
    .map_err(Error::from)
}
