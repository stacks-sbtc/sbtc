use tokio::sync::Mutex;

use crate::{
    error::Error,
    storage::{DbRead, DbWrite, TransactionHandle, model},
};

use super::read::PgRead;

/// Represents an active PostgreSQL transaction.
/// Implements DbRead and DbWrite to allow operations within the transaction.
pub struct PgTransaction<'a> {
    tx: Mutex<sqlx::PgTransaction<'a>>,
}

impl<'a> PgTransaction<'a> {
    pub(super) fn new(tx: sqlx::Transaction<'a, sqlx::Postgres>) -> Self {
        Self { tx: Mutex::new(tx) }
    }
}

impl TransactionHandle for PgTransaction<'_> {
    async fn commit(self) -> Result<(), crate::error::Error> {
        let tx = self.tx.into_inner();

        tx.commit()
            .await
            .map_err(crate::error::Error::SqlxCommitTransaction)?;

        Ok(())
    }

    async fn rollback(self) -> Result<(), crate::error::Error> {
        let tx = self.tx.into_inner();

        tx.rollback()
            .await
            .map_err(crate::error::Error::SqlxRollbackTransaction)?;

        Ok(())
    }
}

impl<'a> DbRead for PgTransaction<'a> {
    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_bitcoin_block(tx.as_mut(), block_hash).await
    }

    async fn get_stacks_block(
        &self,
        block_hash: &crate::storage::model::StacksBlockHash,
    ) -> Result<Option<crate::storage::model::StacksBlock>, crate::error::Error> {
        PgRead::get_stacks_block(self.tx.lock().await.as_mut(), block_hash).await
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<crate::storage::model::BitcoinBlockHash>, crate::error::Error> {
        todo!()
    }

    async fn get_bitcoin_canonical_chain_tip_ref(
        &self,
    ) -> Result<Option<crate::storage::model::BitcoinBlockRef>, crate::error::Error> {
        todo!()
    }

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &crate::storage::model::BitcoinBlockHash,
    ) -> Result<Option<crate::storage::model::StacksBlock>, crate::error::Error> {
        todo!()
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Vec<crate::storage::model::DepositRequest>, crate::error::Error> {
        todo!()
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        context_window: u16,
        signatures_required: u16,
    ) -> Result<Vec<crate::storage::model::DepositRequest>, crate::error::Error> {
        todo!()
    }

    async fn deposit_request_exists(
        &self,
        txid: &crate::storage::model::BitcoinTxId,
        output_index: u32,
    ) -> Result<bool, crate::error::Error> {
        todo!()
    }

    async fn get_deposit_request_report(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        txid: &crate::storage::model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Option<crate::bitcoin::validation::DepositRequestReport>, crate::error::Error> {
        todo!()
    }

    async fn get_deposit_signers(
        &self,
        txid: &crate::storage::model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<crate::storage::model::DepositSigner>, crate::error::Error> {
        todo!()
    }

    async fn get_deposit_signer_decisions(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Vec<crate::storage::model::DepositSigner>, crate::error::Error> {
        todo!()
    }

    async fn get_withdrawal_signer_decisions(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Vec<crate::storage::model::WithdrawalSigner>, crate::error::Error> {
        todo!()
    }

    async fn can_sign_deposit_tx(
        &self,
        txid: &crate::storage::model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Option<bool>, crate::error::Error> {
        todo!()
    }

    async fn get_withdrawal_signers(
        &self,
        request_id: u64,
        block_hash: &crate::storage::model::StacksBlockHash,
    ) -> Result<Vec<crate::storage::model::WithdrawalSigner>, crate::error::Error> {
        todo!()
    }

    async fn get_pending_withdrawal_requests(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Vec<crate::storage::model::WithdrawalRequest>, crate::error::Error> {
        todo!()
    }

    async fn get_pending_accepted_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &crate::storage::model::BitcoinBlockHash,
        stacks_chain_tip: &crate::storage::model::StacksBlockHash,
        min_bitcoin_height: crate::storage::model::BitcoinBlockHeight,
        signature_threshold: u16,
    ) -> Result<Vec<crate::storage::model::WithdrawalRequest>, crate::error::Error> {
        todo!()
    }

    async fn get_pending_rejected_withdrawal_requests(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockRef,
        context_window: u16,
    ) -> Result<Vec<crate::storage::model::WithdrawalRequest>, crate::error::Error> {
        todo!()
    }

    async fn get_withdrawal_request_report(
        &self,
        bitcoin_chain_tip: &crate::storage::model::BitcoinBlockHash,
        stacks_chain_tip: &crate::storage::model::StacksBlockHash,
        id: &crate::storage::model::QualifiedRequestId,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Option<crate::bitcoin::validation::WithdrawalRequestReport>, crate::error::Error>
    {
        todo!()
    }

    async fn compute_withdrawn_total(
        &self,
        bitcoin_chain_tip: &crate::storage::model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<u64, crate::error::Error> {
        todo!()
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &crate::storage::model::BitcoinTxId,
    ) -> Result<Vec<crate::storage::model::BitcoinBlockHash>, crate::error::Error> {
        todo!()
    }

    async fn stacks_block_exists(
        &self,
        block_id: clarity::types::chainstate::StacksBlockId,
    ) -> Result<bool, crate::error::Error> {
        todo!()
    }

    async fn get_encrypted_dkg_shares<X>(
        &self,
        aggregate_key: X,
    ) -> Result<Option<crate::storage::model::EncryptedDkgShares>, crate::error::Error>
    where
        X: Into<crate::keys::PublicKeyXOnly> + Send,
    {
        todo!()
    }

    async fn get_latest_encrypted_dkg_shares(
        &self,
    ) -> Result<Option<crate::storage::model::EncryptedDkgShares>, crate::error::Error> {
        todo!()
    }

    async fn get_latest_verified_dkg_shares(
        &self,
    ) -> Result<Option<crate::storage::model::EncryptedDkgShares>, crate::error::Error> {
        todo!()
    }

    async fn get_encrypted_dkg_shares_count(&self) -> Result<u32, crate::error::Error> {
        todo!()
    }

    async fn get_last_key_rotation(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
    ) -> Result<Option<crate::storage::model::KeyRotationEvent>, crate::error::Error> {
        todo!()
    }

    async fn key_rotation_exists(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        signer_set: &std::collections::BTreeSet<crate::keys::PublicKey>,
        aggregate_key: &crate::keys::PublicKey,
        signatures_required: u16,
    ) -> Result<bool, crate::error::Error> {
        todo!()
    }

    async fn get_signers_script_pubkeys(
        &self,
    ) -> Result<Vec<crate::storage::model::Bytes>, crate::error::Error> {
        todo!()
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
    ) -> Result<Option<crate::bitcoin::utxo::SignerUtxo>, crate::error::Error> {
        todo!()
    }

    async fn get_deposit_request_signer_votes(
        &self,
        txid: &crate::storage::model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &crate::keys::PublicKey,
    ) -> Result<crate::storage::model::SignerVotes, crate::error::Error> {
        todo!()
    }

    async fn get_withdrawal_request_signer_votes(
        &self,
        id: &crate::storage::model::QualifiedRequestId,
        aggregate_key: &crate::keys::PublicKey,
    ) -> Result<crate::storage::model::SignerVotes, crate::error::Error> {
        todo!()
    }

    async fn is_known_bitcoin_block_hash(
        &self,
        block_hash: &crate::storage::model::BitcoinBlockHash,
    ) -> Result<bool, crate::error::Error> {
        todo!()
    }

    async fn in_canonical_bitcoin_blockchain(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockRef,
        block_ref: &crate::storage::model::BitcoinBlockRef,
    ) -> Result<bool, crate::error::Error> {
        todo!()
    }

    async fn is_signer_script_pub_key(
        &self,
        script: &crate::storage::model::ScriptPubKey,
    ) -> Result<bool, crate::error::Error> {
        todo!()
    }

    async fn is_withdrawal_inflight(
        &self,
        id: &crate::storage::model::QualifiedRequestId,
        bitcoin_chain_tip: &crate::storage::model::BitcoinBlockHash,
    ) -> Result<bool, crate::error::Error> {
        todo!()
    }

    async fn is_withdrawal_active(
        &self,
        id: &crate::storage::model::QualifiedRequestId,
        bitcoin_chain_tip: &crate::storage::model::BitcoinBlockRef,
        min_confirmations: u64,
    ) -> Result<bool, crate::error::Error> {
        todo!()
    }

    async fn get_swept_deposit_requests(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<crate::storage::model::SweptDepositRequest>, crate::error::Error> {
        todo!()
    }

    async fn get_swept_withdrawal_requests(
        &self,
        chain_tip: &crate::storage::model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<crate::storage::model::SweptWithdrawalRequest>, crate::error::Error> {
        todo!()
    }

    async fn get_deposit_request(
        &self,
        txid: &crate::storage::model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<crate::storage::model::DepositRequest>, crate::error::Error> {
        todo!()
    }

    async fn will_sign_bitcoin_tx_sighash(
        &self,
        sighash: &crate::storage::model::SigHash,
    ) -> Result<Option<(bool, crate::keys::PublicKeyXOnly)>, crate::error::Error> {
        todo!()
    }
}

impl DbWrite for PgTransaction<'_> {
    async fn write_bitcoin_block(
        &self,
        block: &crate::storage::model::BitcoinBlock,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_stacks_block(
        &self,
        block: &crate::storage::model::StacksBlock,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &crate::storage::model::DepositRequest,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<crate::storage::model::DepositRequest>,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_withdrawal_request(
        &self,
        request: &crate::storage::model::WithdrawalRequest,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_deposit_signer_decision(
        &self,
        decision: &crate::storage::model::DepositSigner,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_withdrawal_signer_decision(
        &self,
        decision: &crate::storage::model::WithdrawalSigner,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &crate::storage::model::BitcoinTxRef,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_bitcoin_transactions(
        &self,
        txs: Vec<crate::storage::model::BitcoinTxRef>,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_stacks_block_headers(
        &self,
        headers: Vec<crate::storage::model::StacksBlock>,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &crate::storage::model::EncryptedDkgShares,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &crate::storage::model::KeyRotationEvent,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &crate::storage::model::WithdrawalRejectEvent,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &crate::storage::model::WithdrawalAcceptEvent,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_completed_deposit_event(
        &self,
        event: &crate::storage::model::CompletedDepositEvent,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_tx_output(
        &self,
        output: &crate::storage::model::TxOutput,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_withdrawal_tx_output(
        &self,
        output: &crate::storage::model::WithdrawalTxOutput,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_tx_prevout(
        &self,
        prevout: &crate::storage::model::TxPrevout,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_bitcoin_txs_sighashes(
        &self,
        sighashes: &[crate::storage::model::BitcoinTxSigHash],
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn write_bitcoin_withdrawals_outputs(
        &self,
        withdrawals_outputs: &[crate::storage::model::BitcoinWithdrawalOutput],
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn revoke_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, crate::error::Error>
    where
        X: Into<crate::keys::PublicKeyXOnly> + Send,
    {
        todo!()
    }

    async fn verify_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, crate::error::Error>
    where
        X: Into<crate::keys::PublicKeyXOnly> + Send,
    {
        todo!()
    }
}
