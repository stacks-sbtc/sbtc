use crate::storage::Transactable;
use crate::storage::model::StacksBlockHeight;
use crate::{
    MAX_MEMPOOL_PACKAGE_TX_COUNT, MAX_REORG_BLOCK_COUNT,
    bitcoin::utxo::SignerUtxo,
    error::Error,
    keys::PublicKey,
    storage::{
        model::{self, BitcoinBlockHeight},
        postgres::PGSQL_MIGRATIONS,
    },
};
use sqlx::pool::PoolConnection;
use sqlx::{Executor, PgConnection};
use sqlx::{PgExecutor, postgres::PgPoolOptions};

use super::transaction::PgTransaction;
use super::{DepositStatusSummary, PgSignerUtxo, WithdrawalStatusSummary};

/// A wrapper around a [`sqlx::PgPool`] which implements
/// [`crate::storage::DbRead`] and [`crate::storage::DbWrite`].
#[derive(Debug, Clone)]
pub struct PgStore(sqlx::PgPool);

impl PgStore {
    /// Connect to the Postgres database at `url`.
    pub async fn connect(url: &str) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .after_connect(|conn, _meta| Box::pin(async move {
                conn.execute("SET application_name = 'sbtc-signer'; SET search_path = sbtc_signer,public;")
                    .await?;
                Ok(())
            }))
            .connect(url)
            .await
            .map_err(Error::SqlxConnect)?;

        Ok(Self(pool))
    }

    /// Apply the migrations to the database.
    pub async fn apply_migrations(&self) -> Result<(), Error> {
        // Related to https://github.com/stacks-network/sbtc/issues/411
        // TODO(537) - Revisit this prior to public launch
        //
        // Note 1: This could be generalized and moved up to the `storage` module, but
        // left that for a future exercise if we need to support other databases.
        //
        // Note 2: The `sqlx` "migration" feature results in dependency conflicts
        // with sqlite from the clarity crate.
        //
        // Note 3: The migration code paths have no explicit integration tests, but are
        // implicitly tested by all integration tests using `new_test_database()`.
        tracing::info!("Preparing to run database migrations");

        sqlx::raw_sql(
            r#"
                CREATE TABLE IF NOT EXISTS public.__sbtc_migrations (
                    key TEXT PRIMARY KEY
                );
            "#,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxMigrate)?;

        let mut trx = self
            .pool()
            .begin()
            .await
            .map_err(Error::SqlxBeginTransaction)?;

        // Collect all migration scripts and sort them by filename. It is important
        // that the migration scripts are named in a way that they are executed in
        // the correct order, i.e. the current naming of `0001__`, `0002__`, etc.
        let mut migrations = PGSQL_MIGRATIONS.files().collect::<Vec<_>>();
        migrations.sort_by_key(|file| file.path().file_name());
        for migration in migrations {
            let key = migration
                .path()
                .file_name()
                .expect("failed to get filename from migration script path")
                .to_string_lossy();

            // Just in-case we end up with a README.md or some other non-SQL file
            // in the migrations directory.
            if !key.ends_with(".sql") {
                tracing::debug!(migration = %key, "Skipping non-SQL migration file");
            }

            // Check if the migration has already been applied. If so, we should
            // be able to safely skip it.
            if self.check_migration_existence(&mut *trx, &key).await? {
                tracing::debug!(migration = %key, "Database migration already applied");
                continue;
            }

            // Attempt to apply the migration. If we encounter an error, we abort
            // the entire migration process.
            if let Some(script) = migration.contents_utf8() {
                tracing::info!(migration = %key, "Applying database migration");

                // Execute the migration.
                sqlx::raw_sql(script)
                    .execute(&mut *trx)
                    .await
                    .map_err(Error::SqlxMigrate)?;

                // Save the migration as applied.
                self.insert_migration(&key).await?;
            } else {
                // The trx should be rolled back on drop but let's be explicit.
                trx.rollback()
                    .await
                    .map_err(Error::SqlxRollbackTransaction)?;

                // We failed to read the migration script as valid UTF-8. This
                // shouldn't happen since it's our own migration scripts, but
                // just in case...
                return Err(Error::ReadSqlMigration(
                    migration.path().as_os_str().to_string_lossy(),
                ));
            }
        }

        trx.commit().await.map_err(Error::SqlxCommitTransaction)?;

        Ok(())
    }

    /// Check if a migration with the given `key` exists.
    async fn check_migration_existence(
        &self,
        executor: impl PgExecutor<'_>,
        key: &str,
    ) -> Result<bool, Error> {
        let result = sqlx::query_scalar::<_, i64>(
            // Note: db_name + key are PK so we can only get max 1 row.
            r#"
            SELECT COUNT(*) FROM public.__sbtc_migrations
                WHERE
                    key = $1
            ;
            "#,
        )
        .bind(key)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(result > 0)
    }

    /// Insert a migration with the given `key`.
    async fn insert_migration(&self, key: &str) -> Result<(), Error> {
        sqlx::query(
            r#"
            INSERT INTO public.__sbtc_migrations (key)
                VALUES ($1)
            "#,
        )
        .bind(key)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.0
    }

    /// Get a connection from the pool.
    pub async fn get_connection(&self) -> PoolConnection<sqlx::Postgres> {
        self.0
            .acquire()
            .await
            .expect("Failed to acquire connection") // TODO: FIX

        //.map_err(Error::SqlxAcquireConnection)
    }

    pub(super) async fn get_utxo<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        output_type: model::TxOutputType,
        min_block_height: BitcoinBlockHeight,
    ) -> Result<Option<SignerUtxo>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e, Database = sqlx::Postgres> + Send + 'e,
    {
        let pg_utxo = sqlx::query_as::<_, PgSignerUtxo>(
            r#"
            WITH bitcoin_blockchain AS (
                SELECT block_hash
                FROM bitcoin_blockchain_until($1, $2)
            ),
            confirmed_sweeps AS (
                SELECT
                    prevout_txid
                  , prevout_output_index
                FROM sbtc_signer.bitcoin_tx_inputs
                JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
                JOIN bitcoin_blockchain AS bb USING (block_hash)
                WHERE prevout_type = 'signers_input'
            )
            SELECT
                bo.txid
              , bo.output_index
              , bo.amount
              , ds.aggregate_key
            FROM sbtc_signer.bitcoin_tx_outputs AS bo
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            JOIN bitcoin_blockchain AS bb USING (block_hash)
            JOIN sbtc_signer.dkg_shares AS ds USING (script_pubkey)
            LEFT JOIN confirmed_sweeps AS cs
              ON cs.prevout_txid = bo.txid
              AND cs.prevout_output_index = bo.output_index
            WHERE cs.prevout_txid IS NULL
              AND bo.output_type = $3
            ORDER BY bo.amount DESC
            LIMIT 1;
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(min_block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(output_type)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(pg_utxo.map(SignerUtxo::from))
    }

    /// This function returns the bitcoin block height of the first
    /// confirmed sweep that happened on or after the given minimum block
    /// height.
    pub(super) async fn get_least_txo_height<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        min_block_height: BitcoinBlockHeight,
    ) -> Result<Option<BitcoinBlockHeight>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e, Database = sqlx::Postgres> + Send + 'e,
    {
        sqlx::query_scalar::<_, BitcoinBlockHeight>(
            r#"
            SELECT bb.block_height
            FROM sbtc_signer.bitcoin_tx_inputs AS bi
            JOIN sbtc_signer.bitcoin_tx_outputs AS bo
              ON bo.txid = bi.txid
            JOIN sbtc_signer.bitcoin_transactions AS bt
              ON bt.txid = bi.txid
            JOIN bitcoin_blockchain_until($1, $2) AS bb
              ON bb.block_hash = bt.block_hash
            WHERE bo.output_type = 'signers_output'
              AND bi.prevout_type = 'signers_input'
            ORDER BY bb.block_height ASC
            LIMIT 1;
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(min_block_height).map_err(Error::ConversionDatabaseInt)?)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Return the height of the earliest block in which a donation UTXO
    /// has been confirmed.
    ///
    /// # Notes
    ///
    /// This function does not check whether the donation output has been
    /// spent.
    async fn minimum_donation_txo_height<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<BitcoinBlockHeight>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e, Database = sqlx::Postgres> + Send + 'e,
    {
        sqlx::query_scalar::<_, BitcoinBlockHeight>(
            r#"
            SELECT bb.block_height
            FROM sbtc_signer.bitcoin_tx_outputs AS bo
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            JOIN sbtc_signer.bitcoin_blocks AS bb USING (block_hash)
            WHERE bo.output_type = 'donation'
            ORDER BY bb.block_height ASC
            LIMIT 1;
            "#,
        )
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Return a donation UTXO with minimum height.
    pub(super) async fn get_donation_utxo<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<SignerUtxo>, Error>
    where
        E: Unpin + Send + 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c, Database = sqlx::Postgres> + Send + 'c,
    {
        let Some(min_block_height) = Self::minimum_donation_txo_height(executor).await? else {
            return Ok(None);
        };
        let output_type = model::TxOutputType::Donation;
        Self::get_utxo(executor, chain_tip, output_type, min_block_height).await
    }
    /// Return a block height that is less than or equal to the block that
    /// confirms the signers' UTXO.
    ///
    /// # Notes
    ///
    /// * This function only returns `Ok(None)` if there have been no
    ///   confirmed sweep transactions.
    /// * As the signers sweep funds between BTC and sBTC, they leave a
    ///   chain of transactions, where each transaction spends the signers'
    ///   sole UTXO and creates a new one. This function "crawls" the chain
    ///   of transactions, starting at the most recently confirmed one,
    ///   until it goes back at least [`MAX_REORG_BLOCK_COUNT`] blocks
    ///   worth of transactions. A block with height greater than or equal
    ///   to the height returned here should contain the transaction with
    ///   the signers' UTXO, and won't if there is a reorg spanning more
    ///   than [`MAX_REORG_BLOCK_COUNT`] blocks.
    pub(super) async fn minimum_utxo_height<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<BitcoinBlockHeight>, Error>
    where
        E: Unpin + Send + 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c, Database = sqlx::Postgres> + Send + 'c,
    {
        #[derive(sqlx::FromRow)]
        struct PgCandidateUtxo {
            txid: model::BitcoinTxId,
            block_height: BitcoinBlockHeight,
        }

        // Get the block height of the unspent transaction that was most
        // recently confirmed. Note that we are not filtering by the
        // blockchain identified by a chain tip, we just want the UTXO with
        // maximum height, even if it has been reorged.
        let utxo_candidate = sqlx::query_as::<_, PgCandidateUtxo>(
            r#"
            WITH confirmed_sweeps AS (
                SELECT
                    prevout_txid
                  , prevout_output_index
                FROM sbtc_signer.bitcoin_tx_inputs
                JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
                WHERE prevout_type = 'signers_input'
            )
            SELECT
                bo.txid
              , bb.block_height
            FROM sbtc_signer.bitcoin_tx_outputs AS bo
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            JOIN sbtc_signer.bitcoin_blocks AS bb USING (block_hash)
            LEFT JOIN confirmed_sweeps AS cs
              ON cs.prevout_txid = bo.txid
              AND cs.prevout_output_index = bo.output_index
            WHERE cs.prevout_txid IS NULL
              AND bo.output_type = 'signers_output'
            ORDER BY bb.block_height DESC
            LIMIT 1;
            "#,
        )
        .fetch_optional(&mut *executor)
        .await
        .map_err(Error::SqlxQuery)?;

        // If such a UTXO candidate doesn't exist then we know that there is no
        // UTXO at all the given transaction output type.
        let Some(utxo_candidate) = utxo_candidate else {
            return Ok(None);
        };

        // Now we want the max block height[1] of all sweep transactions
        // that occurred more than MAX_REORG_BLOCK_COUNT blocks ago, because
        // this sweep transaction is considered fully confirmed.
        //
        // [1]: The sweep transaction that occurred more than
        //      MAX_REORG_BLOCK_COUNT blocks ago may have been confirmed
        //      more than once. If this is the case, we want the min height
        //      of all of them.

        // Given the utxo candidate above, this is our best guess of the
        // minimum UTXO height. It might be wrong, we'll find out shortly.
        let min_block_height_candidate = utxo_candidate
            .block_height
            .saturating_sub(MAX_REORG_BLOCK_COUNT);

        // We want to go back at least MAX_REORG_BLOCK_COUNT blocks worth
        // of transactions. The number here is the maximum number of
        // transactions that the signers could get confirmed in
        // MAX_REORG_BLOCK_COUNT bitcoin blocks, plus one. We add the one
        // because we want the transaction right after
        // MAX_REORG_BLOCK_COUNT worth of transactions.
        let max_transactions =
            i64::try_from(MAX_MEMPOOL_PACKAGE_TX_COUNT * MAX_REORG_BLOCK_COUNT + 1)
                .map_err(Error::ConversionDatabaseInt)?;

        // Find the block height of the sweep transaction that occurred at
        // or before block "best candidate block height" minus
        // MAX_REORG_BLOCK_COUNT.
        //
        // We do this because the block that confirmed the UTXO with max
        // height need not be the signers' UTXO; it does not need to be on
        // the best blockchain. But if we go back at least
        // `MAX_REORG_BLOCK_COUNT` bitcoin blocks then that UTXO is assumed
        // to still be confirmed.
        let prev_confirmed_height_candidate = sqlx::query_scalar::<_, BitcoinBlockHeight>(
            r#"
            WITH RECURSIVE signer_inputs AS (
                SELECT
                    bti.txid
                  , bti.prevout_txid
                  , MIN(bb.block_height) AS block_height
                FROM sbtc_signer.bitcoin_tx_inputs AS bti
                JOIN sbtc_signer.bitcoin_transactions USING (txid)
                JOIN sbtc_signer.bitcoin_blocks AS bb USING (block_hash)
                WHERE bti.prevout_type = 'signers_input'
                  AND bb.block_height <= $1
                GROUP BY bti.txid, bti.prevout_txid
            ),
            tx_chain AS (
                SELECT
                    si.txid
                  , si.prevout_txid
                  , si.block_height
                  , 1 AS tx_count
                FROM signer_inputs AS si
                WHERE si.txid = $3

                UNION ALL

                SELECT
                    si.txid
                  , si.prevout_txid
                  , si.block_height
                  , tc.tx_count + 1
                FROM signer_inputs AS si
                JOIN tx_chain AS tc
                  ON tc.prevout_txid = si.txid
                WHERE tc.tx_count < $2
            )
            SELECT block_height
            FROM tx_chain
            WHERE block_height <= $4
            ORDER BY block_height DESC
            LIMIT 1;
            "#,
        )
        .bind(utxo_candidate.block_height)
        .bind(max_transactions)
        .bind(utxo_candidate.txid)
        .bind(min_block_height_candidate)
        .fetch_optional(&mut *executor)
        .await
        .map_err(Error::SqlxQuery)?;

        // We need to go back at least MAX_REORG_BLOCK_COUNT blocks before
        // the confirmation height of our best candidate height. If there
        // were no sweeps at least MAX_REORG_BLOCK_COUNT blocks ago, then
        // we can use min_block_height_candidate.
        let min_block_height =
            prev_confirmed_height_candidate.unwrap_or(min_block_height_candidate);

        Ok(Some(min_block_height))
    }

    /// Return the least height for which the deposit request was confirmed
    /// on a bitcoin blockchain.
    ///
    /// Transactions can be confirmed on more than one blockchain and this
    /// function returns the least height out of all bitcoin blocks for
    /// which the deposit has been confirmed.
    ///
    /// None is returned if we do not have a record of the deposit request.
    async fn get_deposit_request_least_height(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<BitcoinBlockHeight>, Error> {
        // Before the deposit request is written a signer also stores the
        // bitcoin transaction and (after #731) the bitcoin block
        // confirming the deposit to the database. So this will return zero
        // rows only when we cannot find the deposit request.
        sqlx::query_scalar::<_, BitcoinBlockHeight>(
            r#"
            SELECT block_height
            FROM sbtc_signer.deposit_requests AS dr
            JOIN sbtc_signer.bitcoin_transactions USING (txid)
            JOIN sbtc_signer.bitcoin_blocks USING (block_hash)
            WHERE dr.txid = $1
              AND dr.output_index = $2
            ORDER BY block_height
            LIMIT 1
            "#,
        )
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Return the txid of the bitcoin transaction that swept in the
    /// deposit UTXO. The sweep transaction must be confirmed on the
    /// blockchain identified by the given chain tip.
    ///
    /// This query only looks back at transactions that are confirmed at or
    /// after the given `min_block_height`.
    pub(super) async fn get_deposit_sweep_txid(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        min_block_height: BitcoinBlockHeight,
    ) -> Result<Option<model::BitcoinTxId>, Error> {
        sqlx::query_scalar::<_, model::BitcoinTxId>(
            r#"
            SELECT bti.txid
            FROM sbtc_signer.bitcoin_tx_inputs AS bti
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            JOIN sbtc_signer.bitcoin_blockchain_until($1, $2) USING (block_hash)
            WHERE bti.prevout_txid = $3
              AND bti.prevout_output_index = $4
            LIMIT 1
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(min_block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Fetch a status summary of a deposit request.
    ///
    /// In this query we list out the blockchain identified by the chain
    /// tip as far back as necessary. We then check if this signer accepted
    /// the deposit request, and whether it was confirmed on the blockchain
    /// that we just listed out.
    ///
    /// `None` is returned if no deposit request is in the database (we
    /// always write the associated transaction to the database for each
    /// deposit so that cannot be the reason for why the query here returns
    /// `None`).
    pub(super) async fn get_deposit_request_status_summary(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<DepositStatusSummary>, Error> {
        // We first get the least height for when the deposit request was
        // confirmed. This height serves as the stopping criteria for the
        // recursive part of the subsequent query.
        let min_block_height_fut = self.get_deposit_request_least_height(txid, output_index);
        // None is only returned if we do not have a record of the deposit
        // request or the deposit transaction.
        let Some(min_block_height) = min_block_height_fut.await? else {
            return Ok(None);
        };
        sqlx::query_as::<_, DepositStatusSummary>(
            r#"
            SELECT
                ds.can_accept
              , ds.can_sign
              , dr.amount
              , dr.max_fee
              , dr.lock_time
              , dr.spend_script AS deposit_script
              , dr.reclaim_script
              , dr.signers_public_key
              , bc.block_height
              , bc.block_hash
            FROM sbtc_signer.deposit_requests AS dr
            JOIN sbtc_signer.bitcoin_transactions USING (txid)
            LEFT JOIN sbtc_signer.bitcoin_blockchain_until($1, $2) AS bc USING (block_hash)
            LEFT JOIN sbtc_signer.deposit_signers AS ds
              ON dr.txid = ds.txid
             AND dr.output_index = ds.output_index
             AND ds.signer_pub_key = $5
            WHERE dr.txid = $3
              AND dr.output_index = $4
            LIMIT 1
            "#,
        )
        .bind(chain_tip)
        .bind(min_block_height)
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(signer_public_key)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Check whether the given block hash is a part of the stacks
    /// blockchain identified by the given chain-tip.
    pub async fn in_canonical_stacks_blockchain<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::StacksBlockHash,
        block_hash: &model::StacksBlockHash,
        block_height: StacksBlockHeight,
    ) -> Result<bool, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e, Database = sqlx::Postgres> + Send + 'e,
    {
        sqlx::query_scalar::<_, bool>(
            r#"
            WITH RECURSIVE tx_block_chain AS (
                SELECT
                    block_hash
                  , block_height
                  , parent_hash
                FROM sbtc_signer.stacks_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.block_height
                  , parent.parent_hash
                FROM sbtc_signer.stacks_blocks AS parent
                JOIN tx_block_chain AS child
                  ON parent.block_hash = child.parent_hash
                WHERE child.block_height > $2
            )
            SELECT EXISTS (
                SELECT TRUE
                FROM tx_block_chain AS tbc
                WHERE tbc.block_hash = $3
            );
        "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(block_hash)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Fetch a status summary of a withdrawal request.
    ///
    /// In this query we fetch the raw withdrawal request and add some
    /// information about whether this signer accepted the request.
    ///
    /// `None` is returned if withdrawal request is not in the database or
    /// if the withdrawal request is not associated with a stacks block in
    /// the database.
    pub(super) async fn get_withdrawal_request_status_summary(
        &self,
        id: &model::QualifiedRequestId,
        signer_public_key: &PublicKey,
    ) -> Result<Option<WithdrawalStatusSummary>, Error> {
        sqlx::query_as::<_, WithdrawalStatusSummary>(
            r#"
            SELECT
                ws.is_accepted
              , wr.amount
              , wr.max_fee
              , wr.recipient
              , wr.bitcoin_block_height
              , wr.block_hash   AS stacks_block_hash
              , sb.block_height AS stacks_block_height
            FROM sbtc_signer.withdrawal_requests AS wr
            JOIN sbtc_signer.stacks_blocks AS sb
              ON sb.block_hash = wr.block_hash
            LEFT JOIN sbtc_signer.withdrawal_signers AS ws
              ON ws.request_id = wr.request_id
             AND ws.block_hash = wr.block_hash
             AND ws.signer_pub_key = $1
            WHERE wr.request_id = $2
              AND wr.block_hash = $3
            LIMIT 1
            "#,
        )
        .bind(signer_public_key)
        .bind(i64::try_from(id.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(id.block_hash)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Fetch the bitcoin transaction ID that swept the withdrawal along
    /// with the block hash that confirmed the transaction.
    ///
    /// `None` is returned if there is no transaction sweeping out the
    /// funds that has been confirmed on the blockchain identified by the
    /// given chain-tip.
    pub(super) async fn get_withdrawal_sweep_info(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        id: &model::QualifiedRequestId,
    ) -> Result<Option<model::BitcoinTxRef>, Error> {
        sqlx::query_as::<_, model::BitcoinTxRef>(
            r#"
            SELECT
                bwo.bitcoin_txid AS txid
              , bt.block_hash
            FROM sbtc_signer.withdrawal_requests AS wr
            JOIN sbtc_signer.bitcoin_withdrawals_outputs AS bwo
              ON bwo.request_id = wr.request_id
             AND bwo.stacks_block_hash = wr.block_hash
            JOIN sbtc_signer.bitcoin_transactions AS bt
              ON bt.txid = bwo.bitcoin_txid
            JOIN sbtc_signer.bitcoin_blockchain_until($1, wr.bitcoin_block_height) AS bbu
              ON bbu.block_hash = bt.block_hash
            WHERE wr.request_id = $2
              AND wr.block_hash = $3
            LIMIT 1
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(id.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(id.block_hash)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }
}

impl From<sqlx::PgPool> for PgStore {
    fn from(value: sqlx::PgPool) -> Self {
        Self(value)
    }
}

impl Transactable for PgStore {
    type Tx<'a> = PgTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> Result<Self::Tx<'a>, Error> {
        let tx = self
            .pool()
            .begin()
            .await
            .map_err(Error::SqlxBeginTransaction)?;
        Ok(PgTransaction::new(tx))
    }
}
