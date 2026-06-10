//! `wait-and-donate` subcommand.

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
use bitcoincore_rpc::json;
use clap::Args;
use secp256k1::PublicKey;
use secp256k1::SECP256K1;
use serde::Deserialize;
use url::Url;

use crate::error::Error;

/// Default Stacks principal that deployed the sbtc contracts in devenv.
const DEMO_DEPLOYER: &str = "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS";
/// Fixed fee used for the donation transaction, in sats.
const DONATION_FEE_SATS: u64 = 153;
/// Bitcoin RPC and HTTP request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default poll interval in seconds.
const DEFAULT_POLL_INTERVAL_SECS: NonZeroU64 = NonZeroU64::new(10).unwrap();
/// sBTC registry contract name.
const SBTC_REGISTRY: &str = "sbtc-registry";
/// Data var that holds the current signers' aggregate pubkey.
const AGGREGATE_PUBKEY_DATA_VAR: &str = "current-aggregate-pubkey";
/// Clarity binary type prefix for a buffer.
const CLARITY_TYPE_BUFFER: u8 = 0x02;

#[derive(Debug, Deserialize)]
struct DataVarResponse {
    data: String,
}

/// Arguments for the `wait-and-donate` subcommand.
#[derive(Debug, Args)]
pub struct WaitAndDonateArgs {
    /// Address that deployed the sbtc contracts.
    #[clap(long = "deployer", env = "DEPLOYER_ADDRESS", default_value = DEMO_DEPLOYER)]
    pub deployer: String,
    /// Donation amount in sats.
    #[clap(long, env = "DONATION_AMOUNT", default_value_t = 10_000)]
    pub amount: u64,
    /// Poll interval in seconds.
    #[clap(long = "poll-interval", env = "POLL_INTERVAL_SECS", default_value_t = DEFAULT_POLL_INTERVAL_SECS)]
    pub poll_interval_secs: NonZeroU64,
    /// Base URL of the Stacks node to query (e.g. `http://stacks-node:20443`).
    #[clap(long = "stacks-rpc-url", env = "STACKS_RPC_URL")]
    pub stacks_rpc_url: Url,
    /// Bitcoin RPC URL with embedded credentials and wallet path
    /// (e.g. `http://devnet:devnet@bitcoin:18443/wallet/depositor`).
    #[clap(long = "bitcoin-rpc-url", env = "BITCOIN_RPC_URL")]
    pub bitcoin_rpc_url: Url,
}

/// Entry point for the subcommand.
pub async fn run(args: WaitAndDonateArgs) -> Result<(), Error> {
    let http = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()?;
    let bitcoin = bitcoin_client(&args.bitcoin_rpc_url)?;

    let poll_interval = Duration::from_secs(args.poll_interval_secs.get());
    let aggregate_key =
        wait_for_aggregate_key(&http, &args.stacks_rpc_url, &args.deployer, poll_interval).await?;

    tracing::info!(%aggregate_key, "aggregate key is set, broadcasting donation");

    let unsigned_tx = build_donation_tx(&bitcoin, &aggregate_key, args.amount)?;
    let signed = bitcoin.sign_raw_transaction_with_wallet(&unsigned_tx, None, None)?;
    let txid = bitcoin.send_raw_transaction(&signed.hex)?;

    tracing::info!(%txid, "donation transaction broadcast");
    println!("{txid}");

    Ok(())
}

async fn wait_for_aggregate_key(
    http: &reqwest::Client,
    stacks_rpc_url: &Url,
    deployer: &str,
    poll_interval: Duration,
) -> Result<PublicKey, Error> {
    loop {
        match fetch_aggregate_key(http, stacks_rpc_url, deployer).await {
            Ok(Some(key)) => return Ok(key),
            Ok(None) => tracing::debug!("aggregate key is unset, sleeping"),
            Err(error) => tracing::warn!(%error, "Stacks RPC error fetching aggregate key"),
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// Fetch the `current-aggregate-pubkey` data var from the sbtc-registry
/// contract on the Stacks node. Returns `None` while the var is still its
/// initial all-zeros value.
async fn fetch_aggregate_key(
    http: &reqwest::Client,
    stacks_rpc_url: &Url,
    deployer: &str,
) -> Result<Option<PublicKey>, Error> {
    let path =
        format!("v2/data_var/{deployer}/{SBTC_REGISTRY}/{AGGREGATE_PUBKEY_DATA_VAR}?proof=0");
    let url = stacks_rpc_url.join(&path)?;

    let resp: DataVarResponse = http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    decode_aggregate_key(&resp.data)
}

/// Decode the Stacks node's hex-encoded Clarity buffer holding the aggregate
/// pubkey. The data var is initialised to a single `0x00` byte, which we map
/// to `None`; once the signers confirm a `rotate-keys-wrapper` call, it holds
/// the 33-byte compressed pubkey.
fn decode_aggregate_key(hex_data: &str) -> Result<Option<PublicKey>, Error> {
    let trimmed = hex_data.strip_prefix("0x").unwrap_or(hex_data);
    let bytes = hex::decode(trimmed)?;

    if bytes.first() != Some(&CLARITY_TYPE_BUFFER) || bytes.len() < 5 {
        return Err(Error::UnexpectedClarityValue);
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    let payload = bytes.get(5..5 + len).ok_or(Error::UnexpectedClarityValue)?;

    if payload == [0u8] {
        return Ok(None);
    }
    let key = PublicKey::from_slice(payload)?;
    Ok(Some(key))
}

fn build_donation_tx(
    bitcoin_client: &BitcoinClient,
    aggregate_key: &PublicKey,
    amount_sats: u64,
) -> Result<Transaction, Error> {
    let amount = Amount::from_sat(amount_sats);
    let fee = Amount::from_sat(DONATION_FEE_SATS);

    let opts = json::ListUnspentQueryOptions {
        minimum_amount: Some(amount + fee),
        ..Default::default()
    };
    let unspent = bitcoin_client
        .list_unspent(Some(1), None, None, None, Some(opts))?
        .into_iter()
        .next()
        .ok_or(Error::NoAvailableUtxos)?;

    let (x_only, _) = aggregate_key.x_only_public_key();

    Ok(Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: unspent.txid,
                vout: unspent.vout,
            },
            script_sig: Default::default(),
            sequence: Sequence::ZERO,
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                value: amount,
                script_pubkey: ScriptBuf::new_p2tr(SECP256K1, x_only, None),
            },
            TxOut {
                value: unspent.amount - amount - fee,
                script_pubkey: unspent.script_pub_key,
            },
        ],
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
    })
}

/// Build a [`BitcoinClient`] from a URL with embedded credentials. The path
/// segment (`/wallet/<name>`) is preserved — bitcoind's wallet RPC routes by
/// path.
fn bitcoin_client(url: &Url) -> Result<BitcoinClient, Error> {
    let username = url.username().to_string();
    let password = url.password().unwrap_or_default().to_string();

    let mut endpoint = url.clone();
    let _ = endpoint.set_username("");
    let _ = endpoint.set_password(None);

    let auth = bitcoincore_rpc::Auth::UserPass(username, password);

    BitcoinClient::new(endpoint.as_str(), auth).map_err(Error::from)
}
