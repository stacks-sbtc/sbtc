use std::{collections::BTreeSet, sync::atomic::AtomicBool};

use clarity::types::chainstate::StacksBlockId;

use crate::{
    bitcoin::{
        utxo::SignerUtxo,
        validation::{DepositRequestReport, WithdrawalRequestReport},
    },
    error::Error,
    keys::{PublicKey, PublicKeyXOnly},
    storage::{
        DbRead, DbWrite, TransactionHandle,
        model::{
            self, BitcoinBlockHeight, CompletedDepositEvent, WithdrawalAcceptEvent,
            WithdrawalRejectEvent,
        },
    },
};

use super::SharedStore;

/// Represents an active in-memory transaction.
pub struct InMemoryTransaction {
    /// Records the version of the store at the time of transaction creation.
    pub version: usize,
    /// Holds a clone of the store's data for operations within this transaction.
    /// RefCell allows DbRead/DbWrite methods to take &self.
    pub transactional_store: SharedStore,
    /// Reference to the original store's mutex to commit changes back.
    pub original_store_mutex: SharedStore, // This is Arc<Mutex<Store>>
    /// To track if commit/rollback has been called.
    pub completed: AtomicBool,
}

impl TransactionHandle for InMemoryTransaction {
    async fn commit(self) -> Result<(), Error> {
        // Lock the transaction's clone of the store and get a guard
        let transactional_store = self.transactional_store.lock().await.clone();
        // Lock the original store and get a guard
        let mut original_store = self.original_store_mutex.lock().await;

        // Naive optimistic concurrency check
        if self.version != original_store.version {
            panic!(
                "Optimistic concurrency violation: attempted to commit in-memory \
                DB transaction where the store is at another version than the current transaction"
            );
        }

        // Commit the changes from the transactional store to the original store.
        *original_store = transactional_store.clone();

        // Mark the transaction as completed.
        self.completed
            .store(true, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    async fn rollback(self) -> Result<(), Error> {
        if self.completed.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("Transaction already completed");
        }

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

// ...existing code...
impl DbRead for InMemoryTransaction {
    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error> {
        self.transactional_store.get_bitcoin_block(block_hash).await
    }

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        self.transactional_store.get_stacks_block(block_hash).await
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Error> {
        self.transactional_store
            .get_bitcoin_canonical_chain_tip()
            .await
    }

    async fn get_bitcoin_canonical_chain_tip_ref(
        &self,
    ) -> Result<Option<model::BitcoinBlockRef>, Error> {
        self.transactional_store
            .get_bitcoin_canonical_chain_tip_ref()
            .await
    }

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        self.transactional_store
            .get_stacks_chain_tip(bitcoin_chain_tip)
            .await
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        self.transactional_store
            .get_pending_deposit_requests(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signatures_required: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        self.transactional_store
            .get_pending_accepted_deposit_requests(chain_tip, context_window, signatures_required)
            .await
    }

    async fn deposit_request_exists(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<bool, Error> {
        self.transactional_store
            .deposit_request_exists(txid, output_index)
            .await
    }

    async fn get_deposit_request_report(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<DepositRequestReport>, Error> {
        self.transactional_store
            .get_deposit_request_report(chain_tip, txid, output_index, signer_public_key)
            .await
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        self.transactional_store
            .get_deposit_signers(txid, output_index)
            .await
    }

    async fn get_deposit_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        self.transactional_store
            .get_deposit_signer_decisions(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn get_withdrawal_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        self.transactional_store
            .get_withdrawal_signer_decisions(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn can_sign_deposit_tx(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<bool>, Error> {
        self.transactional_store
            .can_sign_deposit_tx(txid, output_index, signer_public_key)
            .await
    }

    async fn get_withdrawal_signers(
        &self,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        self.transactional_store
            .get_withdrawal_signers(request_id, block_hash)
            .await
    }

    async fn get_pending_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        self.transactional_store
            .get_pending_withdrawal_requests(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn get_pending_accepted_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        min_bitcoin_height: BitcoinBlockHeight,
        signature_threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        self.transactional_store
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip,
                stacks_chain_tip,
                min_bitcoin_height,
                signature_threshold,
            )
            .await
    }

    async fn get_pending_rejected_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        context_window: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        self.transactional_store
            .get_pending_rejected_withdrawal_requests(chain_tip, context_window)
            .await
    }

    async fn get_withdrawal_request_report(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        id: &model::QualifiedRequestId,
        signer_public_key: &PublicKey,
    ) -> Result<Option<WithdrawalRequestReport>, Error> {
        self.transactional_store
            .get_withdrawal_request_report(
                bitcoin_chain_tip,
                stacks_chain_tip,
                id,
                signer_public_key,
            )
            .await
    }

    async fn compute_withdrawn_total(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<u64, Error> {
        self.transactional_store
            .compute_withdrawn_total(bitcoin_chain_tip, context_window)
            .await
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Error> {
        self.transactional_store
            .get_bitcoin_blocks_with_transaction(txid)
            .await
    }

    async fn stacks_block_exists(&self, block_id: StacksBlockId) -> Result<bool, Error> {
        self.transactional_store.stacks_block_exists(block_id).await
    }

    async fn get_encrypted_dkg_shares<X>(
        &self,
        aggregate_key: X,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        self.transactional_store
            .get_encrypted_dkg_shares(aggregate_key)
            .await
    }

    async fn get_latest_encrypted_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        self.transactional_store
            .get_latest_encrypted_dkg_shares()
            .await
    }

    async fn get_latest_verified_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        self.transactional_store
            .get_latest_verified_dkg_shares()
            .await
    }

    async fn get_encrypted_dkg_shares_count(&self) -> Result<u32, Error> {
        self.transactional_store
            .get_encrypted_dkg_shares_count()
            .await
    }

    async fn get_last_key_rotation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::KeyRotationEvent>, Error> {
        self.transactional_store
            .get_last_key_rotation(chain_tip)
            .await
    }

    async fn key_rotation_exists(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        signer_set: &BTreeSet<PublicKey>,
        aggregate_key: &PublicKey,
        signatures_required: u16,
    ) -> Result<bool, Error> {
        self.transactional_store
            .key_rotation_exists(chain_tip, signer_set, aggregate_key, signatures_required)
            .await
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error> {
        self.transactional_store.get_signers_script_pubkeys().await
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<SignerUtxo>, Error> {
        self.transactional_store.get_signer_utxo(chain_tip).await
    }

    async fn get_deposit_request_signer_votes(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        self.transactional_store
            .get_deposit_request_signer_votes(txid, output_index, aggregate_key)
            .await
    }

    async fn get_withdrawal_request_signer_votes(
        &self,
        id: &model::QualifiedRequestId,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        self.transactional_store
            .get_withdrawal_request_signer_votes(id, aggregate_key)
            .await
    }

    async fn is_known_bitcoin_block_hash(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        self.transactional_store
            .is_known_bitcoin_block_hash(block_hash)
            .await
    }

    async fn in_canonical_bitcoin_blockchain(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        block_ref: &model::BitcoinBlockRef,
    ) -> Result<bool, Error> {
        self.transactional_store
            .in_canonical_bitcoin_blockchain(chain_tip, block_ref)
            .await
    }

    async fn is_signer_script_pub_key(&self, script: &model::ScriptPubKey) -> Result<bool, Error> {
        self.transactional_store
            .is_signer_script_pub_key(script)
            .await
    }

    async fn is_withdrawal_inflight(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        self.transactional_store
            .is_withdrawal_inflight(id, bitcoin_chain_tip)
            .await
    }

    async fn is_withdrawal_active(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        min_confirmations: u64,
    ) -> Result<bool, Error> {
        self.transactional_store
            .is_withdrawal_active(id, bitcoin_chain_tip, min_confirmations)
            .await
    }

    async fn get_swept_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error> {
        self.transactional_store
            .get_swept_deposit_requests(chain_tip, context_window)
            .await
    }

    async fn get_swept_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptWithdrawalRequest>, Error> {
        self.transactional_store
            .get_swept_withdrawal_requests(chain_tip, context_window)
            .await
    }

    async fn get_deposit_request(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<model::DepositRequest>, Error> {
        self.transactional_store
            .get_deposit_request(txid, output_index)
            .await
    }

    async fn will_sign_bitcoin_tx_sighash(
        &self,
        sighash: &model::SigHash,
    ) -> Result<Option<(bool, PublicKeyXOnly)>, Error> {
        self.transactional_store
            .will_sign_bitcoin_tx_sighash(sighash)
            .await
    }
}

impl DbWrite for InMemoryTransaction {
    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Error> {
        self.transactional_store.write_bitcoin_block(block).await
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error> {
        self.transactional_store.write_stacks_block(block).await
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_deposit_request(deposit_request)
            .await
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_deposit_requests(deposit_requests)
            .await
    }

    async fn write_withdrawal_request(
        &self,
        request: &model::WithdrawalRequest,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_withdrawal_request(request)
            .await
    }

    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_deposit_signer_decision(decision)
            .await
    }

    async fn write_withdrawal_signer_decision(
        &self,
        decision: &model::WithdrawalSigner,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_withdrawal_signer_decision(decision)
            .await
    }

    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTxRef,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_bitcoin_transaction(bitcoin_transaction)
            .await
    }

    async fn write_bitcoin_transactions(&self, txs: Vec<model::BitcoinTxRef>) -> Result<(), Error> {
        self.transactional_store
            .write_bitcoin_transactions(txs)
            .await
    }

    async fn write_stacks_block_headers(
        &self,
        headers: Vec<model::StacksBlock>,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_stacks_block_headers(headers)
            .await
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_encrypted_dkg_shares(shares)
            .await
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::KeyRotationEvent,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_rotate_keys_transaction(key_rotation)
            .await
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_withdrawal_reject_event(event)
            .await
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_withdrawal_accept_event(event)
            .await
    }

    async fn write_completed_deposit_event(
        &self,
        event: &CompletedDepositEvent,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_completed_deposit_event(event)
            .await
    }

    async fn write_tx_output(&self, output: &model::TxOutput) -> Result<(), Error> {
        self.transactional_store.write_tx_output(output).await
    }

    async fn write_withdrawal_tx_output(
        &self,
        output: &model::WithdrawalTxOutput,
    ) -> Result<(), Error> {
        self.transactional_store
            .write_withdrawal_tx_output(output)
            .await
    }

    async fn write_tx_prevout(&self, prevout: &model::TxPrevout) -> Result<(), Error> {
        self.transactional_store.write_tx_prevout(prevout).await
    }

    async fn write_bitcoin_txs_sighashes(
        &self,
        sighashes: &[model::BitcoinTxSigHash],
    ) -> Result<(), Error> {
        self.transactional_store
            .write_bitcoin_txs_sighashes(sighashes)
            .await
    }

    async fn write_bitcoin_withdrawals_outputs(
        &self,
        withdrawals_outputs: &[model::BitcoinWithdrawalOutput],
    ) -> Result<(), Error> {
        self.transactional_store
            .write_bitcoin_withdrawals_outputs(withdrawals_outputs)
            .await
    }

    async fn revoke_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        self.transactional_store
            .revoke_dkg_shares(aggregate_key)
            .await
    }

    async fn verify_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        self.transactional_store
            .verify_dkg_shares(aggregate_key)
            .await
    }
}
