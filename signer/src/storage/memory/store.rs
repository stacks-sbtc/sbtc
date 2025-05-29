//! In-memory store implementation - useful for tests

use bitcoin::OutPoint;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::bitcoin::utxo::SignerUtxo;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;
use crate::keys::SignerScriptPubKey as _;
use crate::storage::Transactable;
use crate::storage::model;
use crate::storage::model::CompletedDepositEvent;
use crate::storage::model::WithdrawalAcceptEvent;
use crate::storage::model::WithdrawalRejectEvent;

use crate::storage::TransactionHandle;
use crate::storage::util::get_utxo;

use super::MemoryStoreError;

/// A store wrapped in an Arc<Mutex<...>> for interior mutability
pub type SharedStore = Arc<Mutex<Store>>;

type DepositRequestPk = (model::BitcoinTxId, u32);
type WithdrawalRequestPk = (u64, model::StacksBlockHash);

/// In-memory store
#[derive(Debug, Clone, Default)]
pub struct Store {
    /// Transactional version of the store, used in naive optimistic concurrency
    /// control for in-memory transaction emulation.
    pub version: usize,

    /// Bitcoin blocks
    pub bitcoin_blocks: HashMap<model::BitcoinBlockHash, model::BitcoinBlock>,

    /// Stacks blocks
    pub stacks_blocks: HashMap<model::StacksBlockHash, model::StacksBlock>,

    /// Deposit requests
    pub deposit_requests: HashMap<DepositRequestPk, model::DepositRequest>,

    /// A mapping between (request_ids, block_hash) and withdrawal-create events.
    /// Note that a single request_id may be associated with
    /// more than one withdrawal-create event because of reorgs.
    pub withdrawal_requests: HashMap<WithdrawalRequestPk, model::WithdrawalRequest>,

    /// Deposit request to signers
    pub deposit_request_to_signers: HashMap<DepositRequestPk, Vec<model::DepositSigner>>,

    /// Deposit signer to request
    pub signer_to_deposit_request: HashMap<PublicKey, Vec<DepositRequestPk>>,

    /// Withdraw signers
    pub withdrawal_request_to_signers: HashMap<WithdrawalRequestPk, Vec<model::WithdrawalSigner>>,

    /// Bitcoin blocks to transactions
    pub bitcoin_block_to_transactions:
        HashMap<model::BitcoinBlockHash, BTreeSet<model::BitcoinTxId>>,

    /// Bitcoin transactions to blocks
    pub bitcoin_transactions_to_blocks: HashMap<model::BitcoinTxId, Vec<model::BitcoinBlockHash>>,

    /// Stacks blocks to transactions
    pub stacks_block_to_transactions: HashMap<model::StacksBlockHash, Vec<model::StacksTxId>>,

    /// Stacks transactions to blocks
    pub stacks_transactions_to_blocks: HashMap<model::StacksTxId, Vec<model::StacksBlockHash>>,

    /// Stacks blocks to withdraw requests
    pub stacks_block_to_withdrawal_requests:
        HashMap<model::StacksBlockHash, Vec<WithdrawalRequestPk>>,

    /// Bitcoin anchor to stacks blocks
    pub bitcoin_anchor_to_stacks_blocks:
        HashMap<model::BitcoinBlockHash, Vec<model::StacksBlockHash>>,

    /// Encrypted DKG shares
    pub encrypted_dkg_shares: BTreeMap<PublicKeyXOnly, (OffsetDateTime, model::EncryptedDkgShares)>,

    /// Rotate keys transactions
    pub rotate_keys_transactions: HashMap<model::StacksBlockHash, Vec<model::KeyRotationEvent>>,

    /// A mapping between request_ids and withdrawal-accept events. Note
    /// that in prod we can have a single request_id be associated with
    /// more than one withdrawal-accept event because of reorgs.
    pub withdrawal_accept_events: HashMap<u64, WithdrawalAcceptEvent>,

    /// A mapping between request_ids and withdrawal-reject events. Note
    /// that in prod we can have a single request_id be associated with
    /// more than one withdrawal-reject event because of reorgs.
    pub withdrawal_reject_events: HashMap<u64, WithdrawalRejectEvent>,

    /// A mapping between request_ids and completed-deposit events. Note
    /// that in prod we can have a single outpoint be associated with
    /// more than one completed-deposit event because of reorgs.
    pub completed_deposit_events: HashMap<OutPoint, CompletedDepositEvent>,

    /// Bitcoin transaction outputs
    pub bitcoin_outputs: HashMap<model::BitcoinTxId, Vec<model::TxOutput>>,

    /// Bitcoin transaction inputs
    pub bitcoin_prevouts: HashMap<model::BitcoinTxId, Vec<model::TxPrevout>>,

    /// Bitcoin signhashes
    pub bitcoin_sighashes: HashMap<model::SigHash, model::BitcoinTxSigHash>,

    /// Bitcoin withdrawal outputs
    pub bitcoin_withdrawal_outputs:
        HashMap<(u64, model::StacksBlockHash), model::BitcoinWithdrawalOutput>,
}

impl Store {
    /// Create an empty store
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty store wrapped in an Arc<Mutex<...>>
    pub fn new_shared() -> SharedStore {
        Arc::new(Mutex::new(Self::new()))
    }

    /// Returns an iterator for the stacks blockchain, starting at the
    /// given chain tip.
    pub(super) fn stacks_blockchain<'a>(
        &'a self,
        chain_tip: &'a model::StacksBlock,
    ) -> impl Iterator<Item = &'a model::StacksBlock> {
        std::iter::successors(Some(chain_tip), |stacks_block| {
            self.stacks_blocks.get(&stacks_block.parent_hash)
        })
    }

    /// Create the bitcoin transaction from the stored Prevouts and outputs
    /// for the given transaction ID.
    pub(super) fn reconstruct_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Option<bitcoin::Transaction> {
        let outputs = self
            .bitcoin_outputs
            .get(txid)
            .cloned()
            .unwrap_or_else(Vec::new);
        let prevouts = self
            .bitcoin_prevouts
            .get(txid)
            .cloned()
            .unwrap_or_else(Vec::new);

        if outputs.is_empty() && prevouts.is_empty() {
            return None;
        }

        // This is most likely an sBTC sweep transaction, so we match the
        // version of locktime used in our actual sweep transactions.
        Some(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: prevouts
                .into_iter()
                .map(|prevout| bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: prevout.prevout_txid.into(),
                        vout: prevout.prevout_output_index,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ZERO,
                    witness: bitcoin::Witness::new(),
                })
                .collect(),
            output: outputs
                .into_iter()
                .map(|outpout| bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(outpout.amount),
                    script_pubkey: outpout.script_pubkey.into(),
                })
                .collect(),
        })
    }

    pub(super) async fn get_utxo_from_donation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        aggregate_key: &PublicKey,
        context_window: u16,
    ) -> Result<Option<SignerUtxo>, Error> {
        let script_pubkey = aggregate_key.signers_script_pubkey();
        let bitcoin_blocks = &self.bitcoin_blocks;
        let first = bitcoin_blocks.get(chain_tip);

        // Traverse the canonical chain backwards and find the first block containing relevant tx(s)
        let sbtc_txs = std::iter::successors(first, |block| bitcoin_blocks.get(&block.parent_hash))
            .take(context_window as usize)
            .filter_map(|block| {
                let txs = self.bitcoin_block_to_transactions.get(&block.block_hash)?;

                let mut sbtc_txs = txs
                    .iter()
                    .filter_map(|txid| {
                        let outputs = self.bitcoin_outputs.get(txid)?;

                        outputs
                            .iter()
                            .any(|output| output.output_type == model::TxOutputType::Donation)
                            .then_some(outputs.first()?.txid)
                            .and_then(|txid| self.reconstruct_transaction(&txid))
                    })
                    .filter(|tx| {
                        tx.output
                            .first()
                            .is_some_and(|out| out.script_pubkey == script_pubkey)
                    })
                    .peekable();

                if sbtc_txs.peek().is_some() {
                    Some(sbtc_txs.collect::<Vec<_>>())
                } else {
                    None
                }
            })
            .next();

        // `sbtc_txs` contains all the txs in the highest canonical block where the first
        // output is spendable by script_pubkey
        let Some(sbtc_txs) = sbtc_txs else {
            return Ok(None);
        };

        get_utxo(aggregate_key, sbtc_txs)
    }

    /// Get all deposit requests that are on the blockchain identified by
    /// the chain tip within the context window.
    pub fn get_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Vec<model::DepositRequest> {
        (0..context_window)
            // Find all tracked transaction IDs in the context window
            .scan(chain_tip, |block_hash, _| {
                let transaction_ids = self
                    .bitcoin_block_to_transactions
                    .get(*block_hash)
                    .cloned()
                    .unwrap_or_else(BTreeSet::new);

                let block = self.bitcoin_blocks.get(*block_hash)?;
                *block_hash = &block.parent_hash;

                Some(transaction_ids)
            })
            .flatten()
            // Return all deposit requests associated with any of these transaction IDs
            .flat_map(|txid| {
                self.deposit_requests
                    .values()
                    .filter(move |req| req.txid == txid)
                    .cloned()
            })
            .collect()
    }

    pub(super) fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Option<model::StacksBlock> {
        let bitcoin_chain_tip = self.bitcoin_blocks.get(bitcoin_chain_tip)?;

        std::iter::successors(Some(bitcoin_chain_tip), |block| {
            self.bitcoin_blocks.get(&block.parent_hash)
        })
        .filter_map(|block| self.bitcoin_anchor_to_stacks_blocks.get(&block.block_hash))
        .flatten()
        .filter_map(|stacks_block_hash| self.stacks_blocks.get(stacks_block_hash))
        .max_by_key(|block| (block.block_height, block.block_hash.to_bytes()))
        .cloned()
    }

    pub(super) fn get_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Vec<model::WithdrawalRequest> {
        let first_block = self.bitcoin_blocks.get(chain_tip);

        let context_window_end_block = std::iter::successors(first_block, |block| {
            Some(self.bitcoin_blocks.get(&block.parent_hash).unwrap_or(block))
        })
        .nth(context_window as usize);

        let Some(context_window_end_block) = context_window_end_block else {
            return Vec::new();
        };

        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip) else {
            return Vec::new();
        };

        std::iter::successors(Some(&stacks_chain_tip), |stacks_block| {
            self.stacks_blocks.get(&stacks_block.parent_hash)
        })
        .take_while(|stacks_block| {
            self.bitcoin_blocks
                .get(&stacks_block.bitcoin_anchor)
                .is_some_and(|anchor| anchor.block_height >= context_window_end_block.block_height)
        })
        .flat_map(|stacks_block| {
            self.stacks_block_to_withdrawal_requests
                .get(&stacks_block.block_hash)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|pk| {
                    self.withdrawal_requests
                        .get(&pk)
                        .expect("missing withdraw request")
                        .clone()
                })
        })
        .collect()
    }
}

impl Transactable for SharedStore {
    type Tx<'a> = InMemoryTransaction;

    async fn begin_transaction(&self) -> Result<Self::Tx<'_>, Error> {
        let store = self.lock().await;
        let store_clone = store.clone();
        Ok(InMemoryTransaction {
            version: store.version,
            store: Arc::new(Mutex::new(store_clone)),
            original_store_mutex: Arc::clone(self),
            completed: AtomicBool::new(false),
        })
    }
}

/// Represents an active in-memory transaction.
pub struct InMemoryTransaction {
    /// Records the version of the store at the time of transaction creation.
    pub version: usize,
    /// Holds a clone of the store's data for operations within this transaction.
    pub store: SharedStore,
    /// Reference to the original store's mutex to commit changes back.
    pub original_store_mutex: SharedStore,
    /// Tracks if commit/rollback has been called.
    pub completed: AtomicBool,
}

impl TransactionHandle for InMemoryTransaction {
    async fn commit(self) -> Result<(), Error> {
        // Lock the transaction's clone of the store and get a guard
        let store = self.store.lock().await;

        // Lock the original store and get a guard
        let mut original_store = self.original_store_mutex.lock().await;

        // Naive optimistic concurrency check
        if self.version != original_store.version {
            return Err(Error::InMemoryDatabase(
                MemoryStoreError::OptimisticConcurrency {
                    actual_version: original_store.version,
                    expected_version: self.version,
                },
            ));
        }

        // Commit the changes from the transactional store to the original store.
        // This copies all fields from transactional_store_content.
        *original_store = store.clone();

        // Explicitly set the original store's version to be one greater than the version
        // this transaction started with. This marks that the store has been updated.
        original_store.version = self.version + 1;

        // Mark the transaction as completed.
        self.completed
            .store(true, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    async fn rollback(self) -> Result<(), Error> {
        // Rollback is a no-op for in-memory transactions.
        // Just mark the transaction as completed.
        self.completed
            .store(true, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }
}

/// Log a warning if the transaction is dropped without being committed or
/// rolled back. We only do this for in-memory transactions to help highlight
/// potential misses in tests.
impl Drop for InMemoryTransaction {
    fn drop(&mut self) {
        if !*self.completed.get_mut() {
            tracing::warn!(
                "in-memory transaction dropped without explicit commit or rollback. Implicitly rolling back."
            );
        }
    }
}
