use libp2p::PeerId;

use crate::{
    error::Error,
    keys::{PublicKey, PublicKeyXOnly},
    storage::{
        DbWrite,
        model::{
            self, CompletedDepositEvent, DkgSharesStatus, WithdrawalAcceptEvent,
            WithdrawalRejectEvent,
        },
    },
};

use super::{SharedStore, store::InMemoryTransaction};

impl DbWrite for SharedStore {
    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store.bitcoin_blocks.insert(block.block_hash, block.clone());

        Ok(())
    }

    async fn write_bitcoin_transactions(&self, txs: Vec<model::BitcoinTxRef>) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        for bitcoin_transaction in txs {
            store
                .bitcoin_block_to_transactions
                .entry(bitcoin_transaction.block_hash)
                .or_default()
                .insert(bitcoin_transaction.txid);

            store
                .bitcoin_transactions_to_blocks
                .entry(bitcoin_transaction.txid)
                .or_default()
                .push(bitcoin_transaction.block_hash);
        }

        Ok(())
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store.stacks_blocks.insert(block.block_hash, block.clone());
        store
            .bitcoin_anchor_to_stacks_blocks
            .entry(block.bitcoin_anchor)
            .or_default()
            .push(block.block_hash);
        Ok(())
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store.deposit_requests.insert(
            (deposit_request.txid, deposit_request.output_index),
            deposit_request.clone(),
        );

        Ok(())
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        for req in deposit_requests.into_iter() {
            store
                .deposit_requests
                .insert((req.txid, req.output_index), req);
        }
        Ok(())
    }

    async fn write_withdrawal_request(
        &self,
        withdraw_request: &model::WithdrawalRequest,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        let pk = (withdraw_request.request_id, withdraw_request.block_hash);

        store
            .stacks_block_to_withdrawal_requests
            .entry(pk.1)
            .or_default()
            .push(pk);

        store
            .withdrawal_requests
            .insert(pk, withdraw_request.clone());

        Ok(())
    }

    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        let deposit_request_pk = (decision.txid, decision.output_index);

        store
            .deposit_request_to_signers
            .entry(deposit_request_pk)
            .or_default()
            .push(decision.clone());

        store
            .signer_to_deposit_request
            .entry(decision.signer_pub_key)
            .or_default()
            .push(deposit_request_pk);

        Ok(())
    }

    async fn write_withdrawal_signer_decision(
        &self,
        decision: &model::WithdrawalSigner,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store
            .withdrawal_request_to_signers
            .entry((decision.request_id, decision.block_hash))
            .or_default()
            .push(decision.clone());

        Ok(())
    }

    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTxRef,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store
            .bitcoin_block_to_transactions
            .entry(bitcoin_transaction.block_hash)
            .or_default()
            .insert(bitcoin_transaction.txid);

        store
            .bitcoin_transactions_to_blocks
            .entry(bitcoin_transaction.txid)
            .or_default()
            .push(bitcoin_transaction.block_hash);

        Ok(())
    }

    async fn write_stacks_block_headers(
        &self,
        blocks: Vec<model::StacksBlock>,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        blocks.iter().for_each(|block| {
            store.stacks_blocks.insert(block.block_hash, block.clone());
            store
                .bitcoin_anchor_to_stacks_blocks
                .entry(block.bitcoin_anchor)
                .or_default()
                .push(block.block_hash);
        });

        Ok(())
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store.encrypted_dkg_shares.insert(
            shares.aggregate_key.into(),
            (time::OffsetDateTime::now_utc(), shares.clone()),
        );

        Ok(())
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::KeyRotationEvent,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store
            .rotate_keys_transactions
            .entry(key_rotation.block_hash)
            .or_default()
            .push(key_rotation.clone());

        Ok(())
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store
            .withdrawal_accept_events
            .insert(event.request_id, event.clone());

        Ok(())
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store
            .withdrawal_reject_events
            .insert(event.request_id, event.clone());

        Ok(())
    }

    async fn write_completed_deposit_event(
        &self,
        event: &CompletedDepositEvent,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store
            .completed_deposit_events
            .insert(event.outpoint, event.clone());

        Ok(())
    }

    async fn write_tx_output(&self, output: &model::TxOutput) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store
            .bitcoin_outputs
            .entry(output.txid)
            .or_default()
            .push(output.clone());

        Ok(())
    }

    async fn write_withdrawal_tx_output(
        &self,
        _output: &model::WithdrawalTxOutput,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    async fn write_tx_prevout(&self, prevout: &model::TxPrevout) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        store
            .bitcoin_prevouts
            .entry(prevout.txid)
            .or_default()
            .push(prevout.clone());

        Ok(())
    }

    async fn write_bitcoin_withdrawals_outputs(
        &self,
        withdrawal_outputs: &[model::BitcoinWithdrawalOutput],
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        withdrawal_outputs.iter().for_each(|output| {
            store.bitcoin_withdrawal_outputs.insert(
                (output.request_id, output.stacks_block_hash),
                output.clone(),
            );
        });
        Ok(())
    }

    async fn write_bitcoin_txs_sighashes(
        &self,
        sighashes: &[model::BitcoinTxSigHash],
    ) -> Result<(), Error> {
        let mut store = self.lock().await;
        store.version += 1;

        sighashes.iter().for_each(|sighash| {
            store
                .bitcoin_sighashes
                .insert(sighash.sighash, sighash.clone());
        });
        Ok(())
    }

    async fn revoke_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        let mut store = self.lock().await;
        store.version += 1;

        if let Some((_, shares)) = store.encrypted_dkg_shares.get_mut(&aggregate_key.into())
            && shares.dkg_shares_status == DkgSharesStatus::Unverified
        {
            shares.dkg_shares_status = DkgSharesStatus::Failed;
            return Ok(true);
        }
        Ok(false)
    }

    async fn verify_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly> + Send,
    {
        let mut store = self.lock().await;
        store.version += 1;

        if let Some((_, shares)) = store.encrypted_dkg_shares.get_mut(&aggregate_key.into())
            && shares.dkg_shares_status == DkgSharesStatus::Unverified
        {
            shares.dkg_shares_status = DkgSharesStatus::Verified;
            return Ok(true);
        }
        Ok(false)
    }

    async fn update_peer_connection(
        &self,
        pub_key: &PublicKey,
        peer_id: &PeerId,
        address: libp2p::Multiaddr,
    ) -> Result<(), Error> {
        let mut store = self.lock().await;

        let now = time::OffsetDateTime::now_utc().into();
        match store.p2p_peers.entry((*peer_id, *pub_key)) {
            std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
                let peer = occupied_entry.get_mut();
                peer.address = address.into();
                peer.last_dialed_at = now;
            }
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(model::P2PPeer {
                    public_key: *pub_key,
                    peer_id: (*peer_id).into(),
                    address: address.into(),
                    last_dialed_at: now,
                });
            }
        }

        Ok(())
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

    async fn update_peer_connection(
        &self,
        pub_key: &PublicKey,
        peer_id: &PeerId,
        address: libp2p::Multiaddr,
    ) -> Result<(), Error> {
        self.store
            .update_peer_connection(pub_key, peer_id, address)
            .await
    }
}
