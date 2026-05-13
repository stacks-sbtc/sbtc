//! Contains functionality for interacting with the Bitcoin blockchain

use std::future::Future;

use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Txid;

use bitcoincore_rpc_json::GetMempoolEntryResult;
use bitcoincore_rpc_json::GetTxOutResult;
use rpc::BitcoinBlockHeader;
use rpc::BitcoinBlockInfo;
use rpc::BitcoinTxInfo;
#[cfg(any(test, feature = "testing"))]
use rpc::GetTxResponse;

use crate::bitcoin::rpc::OutPointSummary;
use crate::error::Error;

pub mod client;
pub mod packaging;
pub mod poller;
pub mod rpc;
pub mod utxo;
pub mod validation;

/// Result of a call to `get_transaction_fee`.
#[derive(Debug, Clone)]
pub struct GetTransactionFeeResult {
    /// The fee paid by the transaction.
    pub fee: u64,
    /// The fee rate of the transaction in satoshi per vbyte.
    pub fee_rate: f64,
    /// The virtual size of the transaction.
    pub vsize: u64,
}

/// Represents the ability to interact with the bitcoin blockchain
#[cfg_attr(any(test, feature = "testing"), mockall::automock())]
pub trait BitcoinInteract: Sync + Send {
    /// Get block
    fn get_block(
        &self,
        block_hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<BitcoinBlockInfo>, Error>> + Send;

    /// Get the header of the block identified by the given block hash.
    fn get_block_header(
        &self,
        block_hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<BitcoinBlockHeader>, Error>> + Send;

    /// get tx
    #[cfg(any(test, feature = "testing"))]
    fn get_tx(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<Option<GetTxResponse>, Error>> + Send;

    /// Get the confirmation summary of the UTXO identified by the given
    /// outpoint.
    ///
    /// # Notes
    ///
    /// This method only works for unspent outputs that have been confirmed
    /// in a block. If the output has been spent by a transaction that is
    /// confirmed in a block then Ok(None) is returned. If the output has
    /// been spent by a transaction that is in the mempool then Ok(Some(_))
    /// is returned.
    fn get_utxo_info(
        &self,
        outpoint: &OutPoint,
    ) -> impl Future<Output = Result<Option<OutPointSummary>, Error>> + Send;

    /// Get a transaction with additional information about it.
    fn get_tx_info(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<BitcoinTxInfo>, Error>> + Send;

    /// Estimate the fee rate (in sats/vbyte) targeting confirmation within
    /// `num_blocks` blocks.
    fn estimate_fee_rate(
        &self,
        num_blocks: u16,
    ) -> impl std::future::Future<Output = Result<f64, Error>> + Send;

    /// Broadcast transaction
    fn broadcast_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Find transactions in the mempool which spend the given output. `txid`
    /// must be a known confirmed transaction.
    ///
    /// This method returns an (unordered) list of transaction IDs which are in
    /// the mempool and spend the given (confirmed) output.
    ///
    /// If there are no transactions in the mempool which spend the given
    /// output, an empty list is returned.
    fn find_mempool_transactions_spending_output(
        &self,
        outpoint: &bitcoin::OutPoint,
    ) -> impl Future<Output = Result<Vec<Txid>, Error>> + Send;

    /// Finds all transactions in the mempool which are descendants of the given
    /// mempool transaction. `txid` must be a transaction in the mempool.
    ///
    /// This method returns an (unordered) list of transaction IDs which are
    /// both direct and indirect descendants of the given transaction, meaning
    /// that they either directly spend an output of the given transaction or
    /// spend an output of a transaction which is itself a descendant of the
    /// given transaction.
    ///
    /// If there are no descendants of the given transaction in the mempool, an
    /// empty list is returned.
    ///
    /// Use [`Self::find_mempool_transactions_spending_output`] to find
    /// transactions in the mempool which spend an output of a confirmed
    /// transaction if needed prior to calling this method.
    fn find_mempool_descendants(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<Vec<Txid>, Error>> + Send;

    /// Gets the output of the specified transaction, optionally including
    /// transactions from the mempool.
    fn get_transaction_output(
        &self,
        outpoint: &bitcoin::OutPoint,
        include_mempool: bool,
    ) -> impl Future<Output = Result<Option<GetTxOutResult>, Error>> + Send;

    /// Gets the associated fees for the given transaction. It is expected
    /// that the provided transaction is known to the Bitcoin core node, in
    /// the mempool, otherwise an error will be returned.
    fn get_transaction_fee(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<GetTransactionFeeResult, Error>> + Send;

    /// Attempts to get the mempool entry for the given transaction ID.
    fn get_mempool_entry(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<Option<GetMempoolEntryResult>, Error>> + Send;

    /// Gets information about the blockchain from the Bitcoin node.
    fn get_blockchain_info(
        &self,
    ) -> impl Future<Output = Result<bitcoincore_rpc_json::GetBlockchainInfoResult, Error>> + Send;

    /// Gets information about the network from the Bitcoin node.
    fn get_network_info(
        &self,
    ) -> impl Future<Output = Result<bitcoincore_rpc_json::GetNetworkInfoResult, Error>> + Send;

    /// Gets the best (canonical, chain tip from chain with most work) block hash from the Bitcoin node.
    fn get_best_block_hash(&self) -> impl Future<Output = Result<BlockHash, Error>> + Send;
}

/// A trait for providing a stream of block hashes to be used by the block observer.
///
/// Implementors of this trait are responsible for sourcing block hash notifications,
/// such as new chain tips from a Bitcoin Core node, and making them available as an
/// asynchronous stream. This abstraction allows different components, such as
/// block observers or test utilities, to consume block hash events without being
/// coupled to the specific mechanism of how those events are obtained.
pub trait BitcoinBlockHashStreamProvider: Send + Sync {
    /// The error type that this provider can return.
    type Error: std::error::Error;

    /// Subscribes to the block hash stream, returning a new stream that emits
    /// block hashes as they are received.
    ///
    /// The returned stream will yield `Result<BlockHash, Self::Error>`.
    ///
    /// Consumers of this stream are responsible for mapping the error
    /// to a broader application error type (like `crate::error::Error`) if needed.
    fn get_block_hash_stream(
        &self,
    ) -> impl futures::Stream<Item = Result<BlockHash, Self::Error>> + Send + Sync + Unpin + 'static;
}
