use super::{PgStore, PgTransaction};
use crate::{
    error::Error,
    keys::PublicKeyXOnly,
    storage::{
        DbWrite,
        model::{self, CompletedDepositEvent, WithdrawalAcceptEvent, WithdrawalRejectEvent},
    },
};
use bitcoin::hashes::Hash as _;

pub struct PgWrite;

impl PgWrite {
    async fn write_bitcoin_block<'e, E>(
        executor: &'e mut E,
        block: &model::BitcoinBlock,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO sbtc_signer.bitcoin_blocks
              ( block_hash
              , block_height
              , parent_hash
              )
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING",
        )
        .bind(block.block_hash)
        .bind(i64::try_from(block.block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(block.parent_hash)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_stacks_block<'e, E>(
        executor: &'e mut E,
        block: &model::StacksBlock,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO sbtc_signer.stacks_blocks
              ( block_hash
              , block_height
              , parent_hash
              , bitcoin_anchor
              )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING",
        )
        .bind(block.block_hash)
        .bind(i64::try_from(block.block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(block.parent_hash)
        .bind(block.bitcoin_anchor)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_deposit_request<'e, E>(
        executor: &'e mut E,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO sbtc_signer.deposit_requests
              ( txid
              , output_index
              , spend_script
              , reclaim_script
              , reclaim_script_hash
              , recipient
              , amount
              , max_fee
              , lock_time
              , signers_public_key
              , sender_script_pub_keys
              )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT DO NOTHING",
        )
        .bind(deposit_request.txid)
        .bind(i32::try_from(deposit_request.output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(&deposit_request.spend_script)
        .bind(&deposit_request.reclaim_script)
        .bind(&deposit_request.reclaim_script_hash)
        .bind(&deposit_request.recipient)
        .bind(i64::try_from(deposit_request.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(deposit_request.max_fee).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::from(deposit_request.lock_time))
        .bind(deposit_request.signers_public_key)
        .bind(&deposit_request.sender_script_pub_keys)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_deposit_requests<'e, E>(
        executor: &'e mut E,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        if deposit_requests.is_empty() {
            return Ok(());
        }

        let mut txid = Vec::with_capacity(deposit_requests.len());
        let mut output_index = Vec::with_capacity(deposit_requests.len());
        let mut spend_script = Vec::with_capacity(deposit_requests.len());
        let mut reclaim_script = Vec::with_capacity(deposit_requests.len());
        let mut reclaim_script_hash = Vec::with_capacity(deposit_requests.len());
        let mut recipient = Vec::with_capacity(deposit_requests.len());
        let mut amount = Vec::with_capacity(deposit_requests.len());
        let mut max_fee = Vec::with_capacity(deposit_requests.len());
        let mut lock_time = Vec::with_capacity(deposit_requests.len());
        let mut signers_public_key = Vec::with_capacity(deposit_requests.len());
        let mut sender_script_pubkeys = Vec::with_capacity(deposit_requests.len());

        for req in deposit_requests {
            let vout = i32::try_from(req.output_index).map_err(Error::ConversionDatabaseInt)?;
            txid.push(req.txid);
            output_index.push(vout);
            spend_script.push(req.spend_script);
            reclaim_script.push(req.reclaim_script);
            reclaim_script_hash.push(req.reclaim_script_hash);
            recipient.push(req.recipient);
            amount.push(i64::try_from(req.amount).map_err(Error::ConversionDatabaseInt)?);
            max_fee.push(i64::try_from(req.max_fee).map_err(Error::ConversionDatabaseInt)?);
            lock_time.push(i64::from(req.lock_time));
            signers_public_key.push(req.signers_public_key);
            // We need to join the addresses like this (and later split
            // them), because handling of multidimensional arrays in
            // postgres is tough. The naive approach of doing
            // UNNEST($1::VARCHAR[][]) doesn't work, since that completely
            // flattens the array.
            let addresses: Vec<String> = req
                .sender_script_pub_keys
                .iter()
                .map(|x| x.to_hex_string())
                .collect();
            sender_script_pubkeys.push(addresses.join(","));
        }

        sqlx::query(
            r#"
            WITH tx_ids           AS (SELECT ROW_NUMBER() OVER (), txid FROM UNNEST($1::BYTEA[]) AS txid)
            , output_index        AS (SELECT ROW_NUMBER() OVER (), output_index FROM UNNEST($2::INTEGER[]) AS output_index)
            , spend_script        AS (SELECT ROW_NUMBER() OVER (), spend_script FROM UNNEST($3::BYTEA[]) AS spend_script)
            , reclaim_script      AS (SELECT ROW_NUMBER() OVER (), reclaim_script FROM UNNEST($4::BYTEA[]) AS reclaim_script)
            , reclaim_script_hash AS (SELECT ROW_NUMBER() OVER (), reclaim_script_hash FROM UNNEST($5::BYTEA[]) AS reclaim_script_hash)
            , recipient           AS (SELECT ROW_NUMBER() OVER (), recipient FROM UNNEST($6::TEXT[]) AS recipient)
            , amount              AS (SELECT ROW_NUMBER() OVER (), amount FROM UNNEST($7::BIGINT[]) AS amount)
            , max_fee             AS (SELECT ROW_NUMBER() OVER (), max_fee FROM UNNEST($8::BIGINT[]) AS max_fee)
            , lock_time           AS (SELECT ROW_NUMBER() OVER (), lock_time FROM UNNEST($9::BIGINT[]) AS lock_time)
            , signer_pub_keys     AS (SELECT ROW_NUMBER() OVER (), signers_public_key FROM UNNEST($10::BYTEA[]) AS signers_public_key)
            , script_pub_keys     AS (SELECT ROW_NUMBER() OVER (), senders FROM UNNEST($11::VARCHAR[]) AS senders)
            INSERT INTO sbtc_signer.deposit_requests (
                  txid
                , output_index
                , spend_script
                , reclaim_script
                , reclaim_script_hash
                , recipient
                , amount
                , max_fee
                , lock_time
                , signers_public_key
                , sender_script_pub_keys)
            SELECT
                txid
              , output_index
              , spend_script
              , reclaim_script
              , reclaim_script_hash
              , recipient
              , amount
              , max_fee
              , lock_time
              , signers_public_key
              , ARRAY(SELECT decode(UNNEST(regexp_split_to_array(senders, ',')), 'hex'))
            FROM tx_ids
            JOIN output_index USING (row_number)
            JOIN spend_script USING (row_number)
            JOIN reclaim_script USING (row_number)
            JOIN reclaim_script_hash USING (row_number)
            JOIN recipient USING (row_number)
            JOIN amount USING (row_number)
            JOIN max_fee USING (row_number)
            JOIN lock_time USING (row_number)
            JOIN signer_pub_keys USING (row_number)
            JOIN script_pub_keys USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(txid)
        .bind(output_index)
        .bind(spend_script)
        .bind(reclaim_script)
        .bind(reclaim_script_hash)
        .bind(recipient)
        .bind(amount)
        .bind(max_fee)
        .bind(lock_time)
        .bind(signers_public_key)
        .bind(sender_script_pubkeys)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_request<'e, E>(
        executor: &'e mut E,
        request: &model::WithdrawalRequest,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO sbtc_signer.withdrawal_requests
              ( request_id
              , txid
              , block_hash
              , recipient
              , amount
              , max_fee
              , sender_address
              , bitcoin_block_height
              )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT DO NOTHING",
        )
        .bind(i64::try_from(request.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(request.txid)
        .bind(request.block_hash)
        .bind(&request.recipient)
        .bind(i64::try_from(request.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(request.max_fee).map_err(Error::ConversionDatabaseInt)?)
        .bind(&request.sender_address)
        .bind(i64::try_from(request.bitcoin_block_height).map_err(Error::ConversionDatabaseInt)?)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    #[tracing::instrument(skip(executor))]
    async fn write_deposit_signer_decision<'e, E>(
        executor: &'e mut E,
        decision: &model::DepositSigner,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO sbtc_signer.deposit_signers
              ( txid
              , output_index
              , signer_pub_key
              , can_accept
              , can_sign
              )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING",
        )
        .bind(decision.txid)
        .bind(i32::try_from(decision.output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(decision.signer_pub_key)
        .bind(decision.can_accept)
        .bind(decision.can_sign)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_signer_decision<'e, E>(
        executor: &'e mut E,
        decision: &model::WithdrawalSigner,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO sbtc_signer.withdrawal_signers
              ( request_id
              , txid
              , block_hash
              , signer_pub_key
              , is_accepted
              )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING",
        )
        .bind(i64::try_from(decision.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(decision.txid)
        .bind(decision.block_hash)
        .bind(decision.signer_pub_key)
        .bind(decision.is_accepted)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_bitcoin_transaction<'e, E>(
        executor: &'e mut E,
        tx_ref: &model::BitcoinTxRef,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO sbtc_signer.bitcoin_transactions (txid, block_hash)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING",
        )
        .bind(tx_ref.txid)
        .bind(tx_ref.block_hash)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_bitcoin_transactions<'e, E>(
        executor: &'e mut E,
        txs: Vec<model::BitcoinTxRef>,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        if txs.is_empty() {
            return Ok(());
        }

        let mut tx_ids = Vec::with_capacity(txs.len());
        let mut block_hashes = Vec::with_capacity(txs.len());

        for tx in txs {
            tx_ids.push(tx.txid);
            block_hashes.push(tx.block_hash)
        }

        sqlx::query(
            r#"
            WITH tx_ids AS (
                SELECT ROW_NUMBER() OVER (), txid
                FROM UNNEST($1::bytea[]) AS txid
            )
            , block_ids AS (
                SELECT ROW_NUMBER() OVER (), block_id
                FROM UNNEST($2::bytea[]) AS block_id
            )
            INSERT INTO sbtc_signer.bitcoin_transactions (txid, block_hash)
            SELECT
                txid
              , block_id
            FROM tx_ids
            JOIN block_ids USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(&tx_ids)
        .bind(&block_hashes)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_stacks_block_headers<'e, E>(
        executor: &'e mut E,
        blocks: Vec<model::StacksBlock>,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        if blocks.is_empty() {
            return Ok(());
        }

        let mut block_ids = Vec::with_capacity(blocks.len());
        let mut parent_block_ids = Vec::with_capacity(blocks.len());
        let mut chain_lengths = Vec::<i64>::with_capacity(blocks.len());
        let mut bitcoin_anchors = Vec::with_capacity(blocks.len());

        for block in blocks {
            block_ids.push(block.block_hash);
            parent_block_ids.push(block.parent_hash);
            let block_height =
                i64::try_from(block.block_height).map_err(Error::ConversionDatabaseInt)?;
            chain_lengths.push(block_height);
            bitcoin_anchors.push(block.bitcoin_anchor);
        }

        sqlx::query(
            r#"
            WITH block_ids AS (
                SELECT ROW_NUMBER() OVER (), block_id
                FROM UNNEST($1::bytea[]) AS block_id
            )
            , parent_block_ids AS (
                SELECT ROW_NUMBER() OVER (), parent_block_id
                FROM UNNEST($2::bytea[]) AS parent_block_id
            )
            , chain_lengths AS (
                SELECT ROW_NUMBER() OVER (), chain_length
                FROM UNNEST($3::bigint[]) AS chain_length
            )
            , bitcoin_anchors AS (
                SELECT ROW_NUMBER() OVER (), bitcoin_anchor
                FROM UNNEST($4::bytea[]) AS bitcoin_anchor
            )
            INSERT INTO sbtc_signer.stacks_blocks (block_hash, block_height, parent_hash, bitcoin_anchor)
            SELECT
                block_id
              , chain_length
              , parent_block_id
              , bitcoin_anchor
            FROM block_ids
            JOIN parent_block_ids USING (row_number)
            JOIN chain_lengths USING (row_number)
            JOIN bitcoin_anchors USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(&block_ids)
        .bind(&parent_block_ids)
        .bind(&chain_lengths)
        .bind(&bitcoin_anchors)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_encrypted_dkg_shares<'e, E>(
        executor: &'e mut E,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        let started_at_bitcoin_block_height = i64::try_from(shares.started_at_bitcoin_block_height)
            .map_err(Error::ConversionDatabaseInt)?;

        sqlx::query(
            r#"
            INSERT INTO sbtc_signer.dkg_shares (
                aggregate_key
              , tweaked_aggregate_key
              , encrypted_private_shares
              , public_shares
              , script_pubkey
              , signer_set_public_keys
              , signature_share_threshold
              , dkg_shares_status
              , started_at_bitcoin_block_hash
              , started_at_bitcoin_block_height
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(shares.aggregate_key)
        .bind(shares.tweaked_aggregate_key)
        .bind(&shares.encrypted_private_shares)
        .bind(&shares.public_shares)
        .bind(&shares.script_pubkey)
        .bind(&shares.signer_set_public_keys)
        .bind(i32::from(shares.signature_share_threshold))
        .bind(shares.dkg_shares_status)
        .bind(shares.started_at_bitcoin_block_hash)
        .bind(started_at_bitcoin_block_height)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_rotate_keys_transaction<'e, E>(
        executor: &'e mut E,
        key_rotation: &model::KeyRotationEvent,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO sbtc_signer.rotate_keys_transactions (
                  txid
                , block_hash
                , address
                , aggregate_key
                , signer_set
                , signatures_required)
            VALUES
                ($1, $2, $3, $4, $5, $6)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(key_rotation.txid)
        .bind(key_rotation.block_hash)
        .bind(&key_rotation.address)
        .bind(key_rotation.aggregate_key)
        .bind(&key_rotation.signer_set)
        .bind(i32::from(key_rotation.signatures_required))
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_completed_deposit_event<'e, E>(
        executor: &'e mut E,
        event: &CompletedDepositEvent,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "
        INSERT INTO sbtc_signer.completed_deposit_events (
            txid
          , block_hash
          , amount
          , bitcoin_txid
          , output_index
          , sweep_block_hash
          , sweep_block_height
          , sweep_txid
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(event.txid)
        .bind(event.block_id)
        .bind(i64::try_from(event.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.outpoint.txid.to_byte_array())
        .bind(i64::from(event.outpoint.vout))
        .bind(event.sweep_block_hash.to_byte_array())
        .bind(i64::try_from(event.sweep_block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.sweep_txid.to_byte_array())
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_accept_event<'e, E>(
        executor: &'e mut E,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "
        INSERT INTO sbtc_signer.withdrawal_accept_events (
            txid
          , block_hash
          , request_id
          , signer_bitmap
          , bitcoin_txid
          , output_index
          , fee
          , sweep_block_hash
          , sweep_block_height
          , sweep_txid
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(event.txid)
        .bind(event.block_id)
        .bind(i64::try_from(event.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.signer_bitmap.into_inner())
        .bind(event.outpoint.txid.to_byte_array())
        .bind(i64::from(event.outpoint.vout))
        .bind(i64::try_from(event.fee).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.sweep_block_hash.to_byte_array())
        .bind(i64::try_from(event.sweep_block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.sweep_txid.to_byte_array())
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_reject_event<'e, E>(
        executor: &'e mut E,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "
        INSERT INTO sbtc_signer.withdrawal_reject_events (
            txid
          , block_hash
          , request_id
          , signer_bitmap
        )
        VALUES ($1, $2, $3, $4)",
        )
        .bind(event.txid)
        .bind(event.block_id)
        .bind(i64::try_from(event.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.signer_bitmap.into_inner())
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_tx_output<'e, E>(
        executor: &'e mut E,
        output: &model::TxOutput,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO bitcoin_tx_outputs (
                txid
              , output_index
              , amount
              , script_pubkey
              , output_type
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING;
            "#,
        )
        .bind(output.txid)
        .bind(i32::try_from(output.output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(output.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(&output.script_pubkey)
        .bind(output.output_type)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_tx_output<'e, E>(
        executor: &'e mut E,
        output: &model::WithdrawalTxOutput,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO bitcoin_withdrawal_tx_outputs (
                txid
              , output_index
              , request_id
            )
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING;
            "#,
        )
        .bind(output.txid)
        .bind(i32::try_from(output.output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(output.request_id).map_err(Error::ConversionDatabaseInt)?)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_tx_prevout<'e, E>(
        executor: &'e mut E,
        prevout: &model::TxPrevout,
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO bitcoin_tx_inputs (
                txid
              , prevout_txid
              , prevout_output_index
              , amount
              , script_pubkey
              , prevout_type
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT DO NOTHING;
            "#,
        )
        .bind(prevout.txid)
        .bind(prevout.prevout_txid)
        .bind(i32::try_from(prevout.prevout_output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(prevout.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(&prevout.script_pubkey)
        .bind(prevout.prevout_type)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_bitcoin_txs_sighashes<'e, E>(
        executor: &'e mut E,
        sighashes: &[model::BitcoinTxSigHash],
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        if sighashes.is_empty() {
            return Ok(());
        }

        let mut txid = Vec::with_capacity(sighashes.len());
        let mut chain_tip = Vec::with_capacity(sighashes.len());
        let mut prevout_txid = Vec::with_capacity(sighashes.len());
        let mut prevout_output_index = Vec::with_capacity(sighashes.len());
        let mut sighash = Vec::with_capacity(sighashes.len());
        let mut prevout_type = Vec::with_capacity(sighashes.len());
        let mut validation_result = Vec::with_capacity(sighashes.len());
        let mut is_valid_tx = Vec::with_capacity(sighashes.len());
        let mut will_sign = Vec::with_capacity(sighashes.len());
        let mut aggregate_key = Vec::with_capacity(sighashes.len());

        for tx_sighash in sighashes {
            txid.push(tx_sighash.txid);
            chain_tip.push(tx_sighash.chain_tip);
            prevout_txid.push(tx_sighash.prevout_txid);
            prevout_output_index.push(
                i32::try_from(tx_sighash.prevout_output_index)
                    .map_err(Error::ConversionDatabaseInt)?,
            );
            sighash.push(tx_sighash.sighash);
            prevout_type.push(tx_sighash.prevout_type);
            validation_result.push(tx_sighash.validation_result);
            is_valid_tx.push(tx_sighash.is_valid_tx);
            will_sign.push(tx_sighash.will_sign);
            aggregate_key.push(tx_sighash.aggregate_key);
        }

        sqlx::query(
            r#"
            WITH tx_ids             AS (SELECT ROW_NUMBER() OVER (), txid FROM UNNEST($1::BYTEA[]) AS txid)
            , chain_tip             AS (SELECT ROW_NUMBER() OVER (), chain_tip FROM UNNEST($2::BYTEA[]) AS chain_tip)
            , prevout_txid          AS (SELECT ROW_NUMBER() OVER (), prevout_txid FROM UNNEST($3::BYTEA[]) AS prevout_txid)
            , prevout_output_index  AS (SELECT ROW_NUMBER() OVER (), prevout_output_index FROM UNNEST($4::INTEGER[]) AS prevout_output_index)
            , sighash               AS (SELECT ROW_NUMBER() OVER (), sighash FROM UNNEST($5::BYTEA[]) AS sighash)
            , prevout_type          AS (SELECT ROW_NUMBER() OVER (), prevout_type FROM UNNEST($6::sbtc_signer.prevout_type[]) AS prevout_type)
            , validation_result     AS (SELECT ROW_NUMBER() OVER (), validation_result FROM UNNEST($7::TEXT[]) AS validation_result)
            , is_valid_tx           AS (SELECT ROW_NUMBER() OVER (), is_valid_tx FROM UNNEST($8::BOOLEAN[]) AS is_valid_tx)
            , will_sign             AS (SELECT ROW_NUMBER() OVER (), will_sign FROM UNNEST($9::BOOLEAN[]) AS will_sign)
            , x_only_public_key     AS (SELECT ROW_NUMBER() OVER (), x_only_public_key FROM UNNEST($10::BYTEA[]) AS x_only_public_key)
            INSERT INTO sbtc_signer.bitcoin_tx_sighashes (
                  txid
                , chain_tip
                , prevout_txid
                , prevout_output_index
                , sighash
                , prevout_type
                , validation_result
                , is_valid_tx
                , will_sign
                , x_only_public_key
            )
            SELECT
                txid
              , chain_tip
              , prevout_txid
              , prevout_output_index
              , sighash
              , prevout_type
              , validation_result
              , is_valid_tx
              , will_sign
              , x_only_public_key
            FROM tx_ids
            JOIN chain_tip USING (row_number)
            JOIN prevout_txid USING (row_number)
            JOIN prevout_output_index USING (row_number)
            JOIN sighash USING (row_number)
            JOIN prevout_type USING (row_number)
            JOIN validation_result USING (row_number)
            JOIN is_valid_tx USING (row_number)
            JOIN will_sign USING (row_number)
            JOIN x_only_public_key USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(txid)
        .bind(chain_tip)
        .bind(prevout_txid)
        .bind(prevout_output_index)
        .bind(sighash)
        .bind(prevout_type)
        .bind(validation_result)
        .bind(is_valid_tx)
        .bind(will_sign)
        .bind(aggregate_key)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_bitcoin_withdrawals_outputs<'e, E>(
        executor: &'e mut E,
        withdrawal_outputs: &[model::BitcoinWithdrawalOutput],
    ) -> Result<(), Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        if withdrawal_outputs.is_empty() {
            return Ok(());
        }

        let mut bitcoin_txid = Vec::with_capacity(withdrawal_outputs.len());
        let mut bitcoin_chain_tip = Vec::with_capacity(withdrawal_outputs.len());
        let mut request_id = Vec::with_capacity(withdrawal_outputs.len());
        let mut output_index = Vec::with_capacity(withdrawal_outputs.len());
        let mut stacks_txid = Vec::with_capacity(withdrawal_outputs.len());
        let mut stacks_block_hash = Vec::with_capacity(withdrawal_outputs.len());
        let mut validation_result = Vec::with_capacity(withdrawal_outputs.len());
        let mut is_valid_tx = Vec::with_capacity(withdrawal_outputs.len());

        for withdrawal_output in withdrawal_outputs {
            bitcoin_txid.push(withdrawal_output.bitcoin_txid);
            bitcoin_chain_tip.push(withdrawal_output.bitcoin_chain_tip);
            output_index.push(
                i32::try_from(withdrawal_output.output_index)
                    .map_err(Error::ConversionDatabaseInt)?,
            );
            request_id.push(
                i64::try_from(withdrawal_output.request_id)
                    .map_err(Error::ConversionDatabaseInt)?,
            );
            stacks_txid.push(withdrawal_output.stacks_txid);
            stacks_block_hash.push(withdrawal_output.stacks_block_hash);
            validation_result.push(withdrawal_output.validation_result);
            is_valid_tx.push(withdrawal_output.is_valid_tx);
        }

        sqlx::query(
            r#"
            WITH bitcoin_tx_ids     AS (SELECT ROW_NUMBER() OVER (), bitcoin_txid FROM UNNEST($1::BYTEA[]) AS bitcoin_txid)
            , bitcoin_chain_tip     AS (SELECT ROW_NUMBER() OVER (), bitcoin_chain_tip FROM UNNEST($2::BYTEA[]) AS bitcoin_chain_tip)
            , output_index          AS (SELECT ROW_NUMBER() OVER (), output_index FROM UNNEST($3::INTEGER[]) AS output_index)
            , request_id            AS (SELECT ROW_NUMBER() OVER (), request_id FROM UNNEST($4::BIGINT[]) AS request_id)
            , stacks_txid           AS (SELECT ROW_NUMBER() OVER (), stacks_txid FROM UNNEST($5::BYTEA[]) AS stacks_txid)
            , stacks_block_hash     AS (SELECT ROW_NUMBER() OVER (), stacks_block_hash FROM UNNEST($6::BYTEA[]) AS stacks_block_hash)
            , validation_result     AS (SELECT ROW_NUMBER() OVER (), validation_result FROM UNNEST($7::TEXT[]) AS validation_result)
            , is_valid_tx           AS (SELECT ROW_NUMBER() OVER (), is_valid_tx FROM UNNEST($8::BOOLEAN[]) AS is_valid_tx)
            INSERT INTO sbtc_signer.bitcoin_withdrawals_outputs (
                  bitcoin_txid
                , bitcoin_chain_tip
                , output_index
                , request_id
                , stacks_txid
                , stacks_block_hash
                , validation_result
                , is_valid_tx)
            SELECT
                bitcoin_txid
              , bitcoin_chain_tip
              , output_index
              , request_id
              , stacks_txid
              , stacks_block_hash
              , validation_result
              , is_valid_tx
            FROM bitcoin_tx_ids
            JOIN bitcoin_chain_tip USING (row_number)
            JOIN output_index USING (row_number)
            JOIN request_id USING (row_number)
            JOIN stacks_txid USING (row_number)
            JOIN stacks_block_hash USING (row_number)
            JOIN validation_result USING (row_number)
            JOIN is_valid_tx USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(bitcoin_txid)
        .bind(bitcoin_chain_tip)
        .bind(output_index)
        .bind(request_id)
        .bind(stacks_txid)
        .bind(stacks_block_hash)
        .bind(validation_result)
        .bind(is_valid_tx)
        .execute(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn revoke_dkg_shares<'e, X, E>(
        executor: &'e mut E,
        aggregate_key: X,
    ) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly>,
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE sbtc_signer.dkg_shares
            SET dkg_shares_status = 'failed'
            WHERE substring(aggregate_key FROM 2) = $1
              AND dkg_shares_status = 'unverified'; -- only allow failing pending entries
            "#,
        )
        .bind(aggregate_key.into())
        .execute(executor)
        .await
        .map(|res| res.rows_affected() > 0)
        .map_err(Error::SqlxQuery)
    }

    async fn verify_dkg_shares<'e, X, E>(
        executor: &'e mut E,
        aggregate_key: X,
    ) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly>,
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE sbtc_signer.dkg_shares
            SET dkg_shares_status = 'verified'
            WHERE substring(aggregate_key FROM 2) = $1
              AND dkg_shares_status = 'unverified'; -- only allow verifying pending entries
            "#,
        )
        .bind(aggregate_key.into())
        .execute(executor)
        .await
        .map(|res| res.rows_affected() > 0)
        .map_err(Error::SqlxQuery)
    }
}

impl DbWrite for PgStore {
    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Error> {
        PgWrite::write_bitcoin_block(self.get_connection().await?.as_mut(), block).await
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error> {
        PgWrite::write_stacks_block(self.get_connection().await?.as_mut(), block).await
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error> {
        PgWrite::write_deposit_request(self.get_connection().await?.as_mut(), deposit_request).await
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error> {
        PgWrite::write_deposit_requests(self.get_connection().await?.as_mut(), deposit_requests)
            .await
    }

    async fn write_withdrawal_request(
        &self,
        request: &model::WithdrawalRequest,
    ) -> Result<(), Error> {
        PgWrite::write_withdrawal_request(self.get_connection().await?.as_mut(), request).await
    }

    #[tracing::instrument(skip(self))]
    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Error> {
        PgWrite::write_deposit_signer_decision(self.get_connection().await?.as_mut(), decision)
            .await
    }

    async fn write_withdrawal_signer_decision(
        &self,
        decision: &model::WithdrawalSigner,
    ) -> Result<(), Error> {
        PgWrite::write_withdrawal_signer_decision(self.get_connection().await?.as_mut(), decision)
            .await
    }

    async fn write_bitcoin_transaction(&self, tx_ref: &model::BitcoinTxRef) -> Result<(), Error> {
        PgWrite::write_bitcoin_transaction(self.get_connection().await?.as_mut(), tx_ref).await
    }

    async fn write_bitcoin_transactions(&self, txs: Vec<model::BitcoinTxRef>) -> Result<(), Error> {
        PgWrite::write_bitcoin_transactions(self.get_connection().await?.as_mut(), txs).await
    }

    async fn write_stacks_block_headers(
        &self,
        blocks: Vec<model::StacksBlock>,
    ) -> Result<(), Error> {
        PgWrite::write_stacks_block_headers(self.get_connection().await?.as_mut(), blocks).await
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error> {
        PgWrite::write_encrypted_dkg_shares(self.get_connection().await?.as_mut(), shares).await
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::KeyRotationEvent,
    ) -> Result<(), Error> {
        PgWrite::write_rotate_keys_transaction(self.get_connection().await?.as_mut(), key_rotation)
            .await
    }

    async fn write_completed_deposit_event(
        &self,
        event: &CompletedDepositEvent,
    ) -> Result<(), Error> {
        PgWrite::write_completed_deposit_event(self.get_connection().await?.as_mut(), event).await
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Error> {
        PgWrite::write_withdrawal_accept_event(self.get_connection().await?.as_mut(), event).await
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Error> {
        PgWrite::write_withdrawal_reject_event(self.get_connection().await?.as_mut(), event).await
    }

    async fn write_tx_output(&self, output: &model::TxOutput) -> Result<(), Error> {
        PgWrite::write_tx_output(self.get_connection().await?.as_mut(), output).await
    }

    async fn write_withdrawal_tx_output(
        &self,
        output: &model::WithdrawalTxOutput,
    ) -> Result<(), Error> {
        PgWrite::write_withdrawal_tx_output(self.get_connection().await?.as_mut(), output).await
    }

    async fn write_tx_prevout(&self, prevout: &model::TxPrevout) -> Result<(), Error> {
        PgWrite::write_tx_prevout(self.get_connection().await?.as_mut(), prevout).await
    }

    async fn write_bitcoin_txs_sighashes(
        &self,
        sighashes: &[model::BitcoinTxSigHash],
    ) -> Result<(), Error> {
        PgWrite::write_bitcoin_txs_sighashes(self.get_connection().await?.as_mut(), sighashes).await
    }

    async fn write_bitcoin_withdrawals_outputs(
        &self,
        withdrawal_outputs: &[model::BitcoinWithdrawalOutput],
    ) -> Result<(), Error> {
        PgWrite::write_bitcoin_withdrawals_outputs(
            self.get_connection().await?.as_mut(),
            withdrawal_outputs,
        )
        .await
    }

    async fn revoke_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly>,
    {
        PgWrite::revoke_dkg_shares(self.get_connection().await?.as_mut(), aggregate_key).await
    }

    async fn verify_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<PublicKeyXOnly>,
    {
        PgWrite::verify_dkg_shares(self.get_connection().await?.as_mut(), aggregate_key).await
    }
}

impl DbWrite for PgTransaction<'_> {
    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_bitcoin_block(tx.as_mut(), block).await
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_stacks_block(tx.as_mut(), block).await
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_deposit_request(tx.as_mut(), deposit_request).await
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_deposit_requests(tx.as_mut(), deposit_requests).await
    }

    async fn write_withdrawal_request(
        &self,
        request: &model::WithdrawalRequest,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_withdrawal_request(tx.as_mut(), request).await
    }

    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_deposit_signer_decision(tx.as_mut(), decision).await
    }

    async fn write_withdrawal_signer_decision(
        &self,
        decision: &model::WithdrawalSigner,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_withdrawal_signer_decision(tx.as_mut(), decision).await
    }

    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTxRef,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_bitcoin_transaction(tx.as_mut(), bitcoin_transaction).await
    }

    async fn write_bitcoin_transactions(&self, txs: Vec<model::BitcoinTxRef>) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_bitcoin_transactions(tx.as_mut(), txs).await
    }

    async fn write_stacks_block_headers(
        &self,
        headers: Vec<model::StacksBlock>,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_stacks_block_headers(tx.as_mut(), headers).await
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_encrypted_dkg_shares(tx.as_mut(), shares).await
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::KeyRotationEvent,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_rotate_keys_transaction(tx.as_mut(), key_rotation).await
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &model::WithdrawalRejectEvent,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_withdrawal_reject_event(tx.as_mut(), event).await
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &model::WithdrawalAcceptEvent,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_withdrawal_accept_event(tx.as_mut(), event).await
    }

    async fn write_completed_deposit_event(
        &self,
        event: &model::CompletedDepositEvent,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_completed_deposit_event(tx.as_mut(), event).await
    }

    async fn write_tx_output(&self, output: &model::TxOutput) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_tx_output(tx.as_mut(), output).await
    }

    async fn write_withdrawal_tx_output(
        &self,
        output: &model::WithdrawalTxOutput,
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_withdrawal_tx_output(tx.as_mut(), output).await
    }

    async fn write_tx_prevout(&self, prevout: &model::TxPrevout) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_tx_prevout(tx.as_mut(), prevout).await
    }

    async fn write_bitcoin_txs_sighashes(
        &self,
        sighashes: &[model::BitcoinTxSigHash],
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_bitcoin_txs_sighashes(tx.as_mut(), sighashes).await
    }

    async fn write_bitcoin_withdrawals_outputs(
        &self,
        withdrawals_outputs: &[model::BitcoinWithdrawalOutput],
    ) -> Result<(), Error> {
        let mut tx = self.tx.lock().await;
        PgWrite::write_bitcoin_withdrawals_outputs(tx.as_mut(), withdrawals_outputs).await
    }

    async fn revoke_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<crate::keys::PublicKeyXOnly>,
    {
        let mut tx = self.tx.lock().await;
        PgWrite::revoke_dkg_shares(tx.as_mut(), aggregate_key).await
    }

    async fn verify_dkg_shares<X>(&self, aggregate_key: X) -> Result<bool, Error>
    where
        X: Into<crate::keys::PublicKeyXOnly>,
    {
        let mut tx = self.tx.lock().await;
        PgWrite::verify_dkg_shares(tx.as_mut(), aggregate_key).await
    }
}
