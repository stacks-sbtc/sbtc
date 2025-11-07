//! Helper functions for the bitcoin module

use std::time::Duration;

use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::consensus::encode::serialize_hex;

use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc_json::GetChainTipsResultStatus;
use bitcoincore_rpc_json::GetChainTipsResultTip;
use emily_client::models::CreateDepositRequestBody;
use futures::StreamExt as _;
use sbtc::testing::regtest::BITCOIN_CORE_RPC_ENDPOINT;
use sbtc::testing::regtest::BITCOIN_CORE_RPC_PASSWORD;
use sbtc::testing::regtest::BITCOIN_CORE_RPC_USERNAME;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use crate::bitcoin::BitcoinBlockHashStreamProvider;
use crate::bitcoin::poller::BitcoinChainTipPoller;
use crate::bitcoin::rpc::BitcoinCoreClient;
use crate::bitcoin::utxo;

/// Return a transaction that is kinda like the signers' transaction,
/// but it does not service any requests, and it does not have any
/// signatures.
pub fn base_signer_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
            // This is the signers' previous UTXO
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            },
        ],
        output: vec![
            // This represents the signers' new UTXO.
            TxOut {
                value: Amount::ONE_BTC,
                script_pubkey: ScriptBuf::new(),
            },
            // This represents the OP_RETURN sBTC UTXO for a
            // transaction with no withdrawals.
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([0; 21]),
            },
        ],
    }
}

impl utxo::DepositRequest {
    /// Transform this deposit request into the body that Emily expects.
    pub fn as_emily_request(&self, tx: &Transaction) -> CreateDepositRequestBody {
        CreateDepositRequestBody {
            bitcoin_tx_output_index: self.outpoint.vout,
            bitcoin_txid: self.outpoint.txid.to_string(),
            deposit_script: self.deposit_script.to_hex_string(),
            reclaim_script: self.reclaim_script.to_hex_string(),
            transaction_hex: serialize_hex(tx),
        }
    }
}

/// Return the canonical (active) chain tip from `get_chain_tips`
pub fn get_canonical_chain_tip(rpc: &Client) -> GetChainTipsResultTip {
    rpc.get_chain_tips()
        .unwrap()
        .iter()
        .find(|t| t.status == GetChainTipsResultStatus::Active)
        .unwrap()
        .clone()
}

impl BitcoinCoreClient {
    /// Creates a new [`BitcoinCoreClient`] for the regtest network based on the
    /// defaults in the `sbtc` crate.
    pub fn new_regtest() -> Self {
        Self::new(
            BITCOIN_CORE_RPC_ENDPOINT,
            BITCOIN_CORE_RPC_USERNAME.to_string(),
            BITCOIN_CORE_RPC_PASSWORD.to_string(),
        )
        .expect("Failed to create BitcoinCoreClient for regtest")
    }
}

impl BitcoinChainTipPoller {
    /// Creates a new `BitcoinChainTipPoller` for the regtest network with a
    /// short polling interval and initialization timeout suitable for tests.
    pub async fn start_for_regtest() -> Self {
        BitcoinChainTipPoller::start_new(
            BitcoinCoreClient::new_regtest(),
            Duration::from_millis(100),
        )
        .await
    }
}

const DEFAULT_MANUAL_PROVIDER_CAPACITY: usize = 128;

/// A [`BlockHashStreamProvider`] that allows manual sending of block hashes.
///
/// This is useful for tests where you want to control the exact sequence and
/// timing of block hash notifications or you want to run a block observer
/// without a bitcoin node. It uses a broadcast channel internally, so multiple
/// streams can subscribe to the same sequence of manually sent items.
#[derive(Clone, Debug)]
pub struct MockBitcoinBlockHashStreamProvider {
    sender: broadcast::Sender<Result<BlockHash, BroadcastStreamRecvError>>,
}

impl MockBitcoinBlockHashStreamProvider {
    /// Creates a new `MockBitcoinBlockHashStreamProvider` with the specified buffer capacity
    /// for its internal broadcast channel.
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _receiver) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Sends a block hash result to all subscribers of this provider.
    #[track_caller]
    pub fn send(&self, item: Result<BlockHash, BroadcastStreamRecvError>) {
        self.sender
            .send(item)
            .expect("failed to send item to broadcast channel: no active receivers.");
    }
}

impl Default for MockBitcoinBlockHashStreamProvider {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MANUAL_PROVIDER_CAPACITY)
    }
}

impl BitcoinBlockHashStreamProvider for MockBitcoinBlockHashStreamProvider {
    type Error = BroadcastStreamRecvError;

    fn get_block_hash_stream(
        &self,
    ) -> impl futures::Stream<Item = Result<BlockHash, BroadcastStreamRecvError>>
    + Send
    + Sync
    + Unpin
    + 'static {
        let receiver = self.sender.subscribe();
        BroadcastStream::new(receiver).map(|result_from_broadcast| match result_from_broadcast {
            Ok(item) => item,
            Err(error) => Err(error),
        })
    }
}
