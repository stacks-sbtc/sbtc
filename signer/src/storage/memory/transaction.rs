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
    pub store: SharedStore,
    /// Reference to the original store's mutex to commit changes back.
    pub original_store_mutex: SharedStore, // This is Arc<Mutex<Store>>
    /// To track if commit/rollback has been called.
    pub completed: AtomicBool,
}

impl TransactionHandle for InMemoryTransaction {
    async fn commit(self) -> Result<(), Error> {
        if self.completed.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("Transaction already completed");
        }

        // Lock the transaction's clone of the store and get a guard
        let store = self.store.lock().await.clone();
        // Lock the original store and get a guard
        let mut original_store = self.original_store_mutex.lock().await;

        // Naive optimistic concurrency check
        if self.version != original_store.version {
            return Err(Error::OptimisticConcurrencyViolation {
                transaction_version: self.version,
                store_version: original_store.version,
            });
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
        self.store.get_bitcoin_block(block_hash).await
    }

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        self.store.get_stacks_block(block_hash).await
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Error> {
        self.store.get_bitcoin_canonical_chain_tip().await
    }

    async fn get_bitcoin_canonical_chain_tip_ref(
        &self,
    ) -> Result<Option<model::BitcoinBlockRef>, Error> {
        self.store.get_bitcoin_canonical_chain_tip_ref().await
    }

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        self.store.get_stacks_chain_tip(bitcoin_chain_tip).await
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        self.store
            .get_pending_deposit_requests(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signatures_required: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        self.store
            .get_pending_accepted_deposit_requests(chain_tip, context_window, signatures_required)
            .await
    }

    async fn deposit_request_exists(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<bool, Error> {
        self.store.deposit_request_exists(txid, output_index).await
    }

    async fn get_deposit_request_report(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<DepositRequestReport>, Error> {
        self.store
            .get_deposit_request_report(chain_tip, txid, output_index, signer_public_key)
            .await
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        self.store.get_deposit_signers(txid, output_index).await
    }

    async fn get_deposit_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        self.store
            .get_deposit_signer_decisions(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn get_withdrawal_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        self.store
            .get_withdrawal_signer_decisions(chain_tip, context_window, signer_public_key)
            .await
    }

    async fn can_sign_deposit_tx(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<bool>, Error> {
        self.store
            .can_sign_deposit_tx(txid, output_index, signer_public_key)
            .await
    }

    async fn get_withdrawal_signers(
        &self,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        self.store
            .get_withdrawal_signers(request_id, block_hash)
            .await
    }

    async fn get_pending_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        self.store
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
        self.store
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
        self.store
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
        self.store
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
        self.store
            .compute_withdrawn_total(bitcoin_chain_tip, context_window)
            .await
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Error> {
        self.store.get_bitcoin_blocks_with_transaction(txid).await
    }

    async fn stacks_block_exists(&self, block_id: StacksBlockId) -> Result<bool, Error> {
        self.store.stacks_block_exists(block_id).await
    }

    async fn get_encrypted_dkg_shares<X>(
        &self,
        aggregate_key: X,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        self.store.get_encrypted_dkg_shares(aggregate_key).await
    }

    async fn get_latest_encrypted_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        self.store.get_latest_encrypted_dkg_shares().await
    }

    async fn get_latest_verified_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        self.store.get_latest_verified_dkg_shares().await
    }

    async fn get_encrypted_dkg_shares_count(&self) -> Result<u32, Error> {
        self.store.get_encrypted_dkg_shares_count().await
    }

    async fn get_last_key_rotation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::KeyRotationEvent>, Error> {
        self.store.get_last_key_rotation(chain_tip).await
    }

    async fn key_rotation_exists(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        signer_set: &BTreeSet<PublicKey>,
        aggregate_key: &PublicKey,
        signatures_required: u16,
    ) -> Result<bool, Error> {
        self.store
            .key_rotation_exists(chain_tip, signer_set, aggregate_key, signatures_required)
            .await
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error> {
        self.store.get_signers_script_pubkeys().await
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<SignerUtxo>, Error> {
        self.store.get_signer_utxo(chain_tip).await
    }

    async fn get_deposit_request_signer_votes(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        self.store
            .get_deposit_request_signer_votes(txid, output_index, aggregate_key)
            .await
    }

    async fn get_withdrawal_request_signer_votes(
        &self,
        id: &model::QualifiedRequestId,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        self.store
            .get_withdrawal_request_signer_votes(id, aggregate_key)
            .await
    }

    async fn is_known_bitcoin_block_hash(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        self.store.is_known_bitcoin_block_hash(block_hash).await
    }

    async fn in_canonical_bitcoin_blockchain(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        block_ref: &model::BitcoinBlockRef,
    ) -> Result<bool, Error> {
        self.store
            .in_canonical_bitcoin_blockchain(chain_tip, block_ref)
            .await
    }

    async fn is_signer_script_pub_key(&self, script: &model::ScriptPubKey) -> Result<bool, Error> {
        self.store.is_signer_script_pub_key(script).await
    }

    async fn is_withdrawal_inflight(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        self.store
            .is_withdrawal_inflight(id, bitcoin_chain_tip)
            .await
    }

    async fn is_withdrawal_active(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        min_confirmations: u64,
    ) -> Result<bool, Error> {
        self.store
            .is_withdrawal_active(id, bitcoin_chain_tip, min_confirmations)
            .await
    }

    async fn get_swept_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error> {
        self.store
            .get_swept_deposit_requests(chain_tip, context_window)
            .await
    }

    async fn get_swept_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptWithdrawalRequest>, Error> {
        self.store
            .get_swept_withdrawal_requests(chain_tip, context_window)
            .await
    }

    async fn get_deposit_request(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<model::DepositRequest>, Error> {
        self.store.get_deposit_request(txid, output_index).await
    }

    async fn will_sign_bitcoin_tx_sighash(
        &self,
        sighash: &model::SigHash,
    ) -> Result<Option<(bool, PublicKeyXOnly)>, Error> {
        self.store.will_sign_bitcoin_tx_sighash(sighash).await
    }
}

impl DbWrite for InMemoryTransaction {
    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Error> {
        self.store.write_bitcoin_block(block).await
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error> {
        self.store.write_stacks_block(block).await
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error> {
        self.store.write_deposit_request(deposit_request).await
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error> {
        self.store.write_deposit_requests(deposit_requests).await
    }

    async fn write_withdrawal_request(
        &self,
        request: &model::WithdrawalRequest,
    ) -> Result<(), Error> {
        self.store.write_withdrawal_request(request).await
    }

    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Error> {
        self.store.write_deposit_signer_decision(decision).await
    }

    async fn write_withdrawal_signer_decision(
        &self,
        decision: &model::WithdrawalSigner,
    ) -> Result<(), Error> {
        self.store.write_withdrawal_signer_decision(decision).await
    }

    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTxRef,
    ) -> Result<(), Error> {
        self.store
            .write_bitcoin_transaction(bitcoin_transaction)
            .await
    }

    async fn write_bitcoin_transactions(&self, txs: Vec<model::BitcoinTxRef>) -> Result<(), Error> {
        self.store.write_bitcoin_transactions(txs).await
    }

    async fn write_stacks_block_headers(
        &self,
        headers: Vec<model::StacksBlock>,
    ) -> Result<(), Error> {
        self.store.write_stacks_block_headers(headers).await
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error> {
        self.store.write_encrypted_dkg_shares(shares).await
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::KeyRotationEvent,
    ) -> Result<(), Error> {
        self.store.write_rotate_keys_transaction(key_rotation).await
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Error> {
        self.store.write_withdrawal_reject_event(event).await
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Error> {
        self.store.write_withdrawal_accept_event(event).await
    }

    async fn write_completed_deposit_event(
        &self,
        event: &CompletedDepositEvent,
    ) -> Result<(), Error> {
        self.store.write_completed_deposit_event(event).await
    }

    async fn write_tx_output(&self, output: &model::TxOutput) -> Result<(), Error> {
        self.store.write_tx_output(output).await
    }

    async fn write_withdrawal_tx_output(
        &self,
        output: &model::WithdrawalTxOutput,
    ) -> Result<(), Error> {
        self.store.write_withdrawal_tx_output(output).await
    }

    async fn write_tx_prevout(&self, prevout: &model::TxPrevout) -> Result<(), Error> {
        self.store.write_tx_prevout(prevout).await
    }

    async fn write_bitcoin_txs_sighashes(
        &self,
        sighashes: &[model::BitcoinTxSigHash],
    ) -> Result<(), Error> {
        self.store.write_bitcoin_txs_sighashes(sighashes).await
    }

    async fn write_bitcoin_withdrawals_outputs(
        &self,
        withdrawals_outputs: &[model::BitcoinWithdrawalOutput],
    ) -> Result<(), Error> {
        self.store
            .write_bitcoin_withdrawals_outputs(withdrawals_outputs)
            .await
    }

    async fn revoke_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        self.store.revoke_dkg_shares(aggregate_key).await
    }

    async fn verify_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        self.store.verify_dkg_shares(aggregate_key).await
    }
}

// ...existing code...
#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::storage::memory::store::Store;
    use crate::storage::{DbRead, DbWrite, Transactable, TransactionHandle};
    use crate::testing::blocks::{BitcoinChain, StacksChain};

    use assert_matches::assert_matches;
    use test_log::test;

    #[tokio::test]
    async fn test_in_memory_transaction_commit() -> Result<(), Error> {
        let shared_store = Store::new_shared();

        let bitcoin_chain = BitcoinChain::default();
        let stacks_chain = StacksChain::new_anchored(&bitcoin_chain);
        let btc_1 = bitcoin_chain.first_block();
        let stx_a = stacks_chain.first_block();
        let stx_b = stx_a.new_child().anchored_to(btc_1);
        let btc_2 = btc_1.new_child();
        let stx_c = stx_b.new_child().anchored_to(&btc_2);

        // Start transaction
        let tx = shared_store.begin_transaction().await?;

        // Write data within transaction
        tx.write_bitcoin_block(btc_1).await?;
        tx.write_stacks_block(stx_a).await?;
        tx.write_stacks_block(&stx_b).await?;

        tx.write_bitcoin_block(&btc_2).await?;
        tx.write_stacks_block(&stx_c).await?;

        // Commit transaction
        tx.commit().await?;

        // Verify data in original store
        assert_eq!(
            shared_store.get_bitcoin_block(&btc_1.block_hash).await?,
            Some(btc_1.clone())
        );
        assert_eq!(
            shared_store.get_stacks_block(&stx_a.block_hash).await?,
            Some(stx_a.clone())
        );
        assert_eq!(
            shared_store.get_stacks_block(&stx_b.block_hash).await?,
            Some(stx_b.clone())
        );

        assert_eq!(
            shared_store.get_bitcoin_block(&btc_2.block_hash).await?,
            Some(btc_2.clone())
        );
        assert_eq!(
            shared_store.get_stacks_block(&stx_c.block_hash).await?,
            Some(stx_c.clone())
        );

        // Verify one-to-many relationships in bitcoin_anchor_to_stacks_blocks
        let store_guard = shared_store.lock().await;

        let anchored_blocks1 = store_guard
            .bitcoin_anchor_to_stacks_blocks
            .get(&btc_1.block_hash)
            .expect("BTC hash 1 should have anchored Stacks blocks");
        assert_eq!(
            anchored_blocks1.len(),
            2,
            "BTC block 1 should anchor 2 Stacks blocks"
        );
        assert!(anchored_blocks1.contains(&stx_a.block_hash));
        assert!(anchored_blocks1.contains(&stx_b.block_hash));

        let anchored_blocks2 = store_guard
            .bitcoin_anchor_to_stacks_blocks
            .get(&btc_2.block_hash)
            .expect("BTC hash 2 should have anchored Stacks blocks");
        assert_eq!(
            anchored_blocks2.len(),
            1,
            "BTC block 2 should anchor 1 Stacks block"
        );
        assert!(anchored_blocks2.contains(&stx_c.block_hash));

        Ok(())
    }

    #[tokio::test]
    async fn test_in_memory_transaction_rollback() -> Result<(), Error> {
        let shared_store = Store::new_shared();

        let bitcoin_chain = BitcoinChain::default();
        let stacks_chain = StacksChain::new_anchored(&bitcoin_chain);
        let btc_1 = bitcoin_chain.first_block();
        let stx_a = stacks_chain.first_block(); // Anchored to btc_1 by default in StacksChain

        // Start transaction
        let tx = shared_store.begin_transaction().await?;

        // Write data within transaction
        tx.write_bitcoin_block(btc_1).await?;
        tx.write_stacks_block(stx_a).await?;

        // Rollback transaction
        tx.rollback().await?;

        // Verify data is NOT in original store
        assert!(
            shared_store
                .get_bitcoin_block(&btc_1.block_hash)
                .await?
                .is_none()
        );
        assert!(
            shared_store
                .get_stacks_block(&stx_a.block_hash)
                .await?
                .is_none()
        );

        let store_guard = shared_store.lock().await;
        let anchored_stacks_blocks = store_guard
            .bitcoin_anchor_to_stacks_blocks
            .get(&btc_1.block_hash);
        assert!(
            anchored_stacks_blocks.is_none_or(|v| v.is_empty()),
            "Anchored blocks should be None or empty after rollback"
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn test_in_memory_transaction_implicit_rollback_on_drop() -> Result<(), Error> {
        let shared_store = Store::new_shared();

        let bitcoin_chain = BitcoinChain::default();
        let stacks_chain = StacksChain::new_anchored(&bitcoin_chain);
        let btc_1 = bitcoin_chain.first_block();
        let stx_a = stacks_chain.first_block(); // Anchored to btc_1

        // Scope for the transaction
        {
            let tx = shared_store.begin_transaction().await?;
            tx.write_bitcoin_block(btc_1).await?;
            tx.write_stacks_block(stx_a).await?;
            // tx is dropped here, Drop implementation should trigger implicit rollback
        }

        // Verify data is NOT in original store
        assert!(
            shared_store
                .get_bitcoin_block(&btc_1.block_hash)
                .await?
                .is_none()
        );
        assert!(
            shared_store
                .get_stacks_block(&stx_a.block_hash)
                .await?
                .is_none()
        );

        let store_guard = shared_store.lock().await;
        let anchored_stacks_blocks = store_guard
            .bitcoin_anchor_to_stacks_blocks
            .get(&btc_1.block_hash);
        assert!(
            anchored_stacks_blocks.is_none_or(|v| v.is_empty()),
            "Anchored blocks should be None or empty after implicit rollback"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_in_memory_transaction_optimistic_concurrency_violation() {
        let shared_store = Store::new_shared(); // Initial store.version is typically 0

        // Create some dummy block data
        let bitcoin_chain = BitcoinChain::default();
        let btc_block1 = bitcoin_chain.first_block();
        let btc_block2 = btc_block1.new_child();

        // Start transaction 1
        // tx1 captures the initial version of shared_store (e.g., 0)
        let tx1 = shared_store
            .begin_transaction()
            .await
            .expect("Failed to begin transaction 1");
        // Perform a write operation in tx1. This might increment the version of tx1's internal store copy.
        tx1.write_bitcoin_block(btc_block1)
            .await
            .expect("Failed to write bitcoin block in tx1");

        // Start transaction 2
        // tx2 also captures the initial version of shared_store (e.g., 0), as tx1 hasn't committed yet.
        let tx2 = shared_store
            .begin_transaction()
            .await
            .expect("Failed to begin transaction 2");
        // Perform a write operation in tx2.
        tx2.write_bitcoin_block(&btc_block2)
            .await
            .expect("Failed to write bitcoin block in tx2");

        // Commit transaction 2
        // This should succeed. If writes increment the transaction's internal store version,
        // and commit updates the original store's version to the transaction's store version,
        // then shared_store.version will now be updated (e.g., to 1).
        tx2.commit().await.expect("Failed to commit transaction 2");

        // Attempt to commit transaction 1
        // tx1.version is still the initial version (e.g., 0).
        // shared_store.version is now updated by tx2's commit (e.g., 1).
        // The versions will not match, and this commit attempt should error.
        assert_matches!(
            tx1.commit().await,
            Err(Error::OptimisticConcurrencyViolation { .. })
        );
    }
}
