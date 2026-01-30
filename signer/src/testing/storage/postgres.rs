//! A module with helper query functions.

use crate::error::Error;
use crate::storage::model;
use crate::storage::postgres::PgStore;

impl PgStore {
    /// Get all deposit requests that have been confirmed within the
    /// context window.
    pub async fn get_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        sqlx::query_as::<_, model::DepositRequest>(
            r#"
            SELECT
                dr.txid
              , dr.output_index
              , dr.spend_script
              , dr.reclaim_script_hash
              , dr.recipient
              , dr.amount
              , dr.max_fee
              , dr.lock_time
              , dr.signers_public_key
              , dr.sender_script_pub_keys
            FROM sbtc_signer.bitcoin_blockchain_of($1, $2)
            JOIN sbtc_signer.bitcoin_transactions USING (block_hash)
            JOIN sbtc_signer.deposit_requests AS dr USING (txid)
            "#,
        )
        .bind(chain_tip)
        .bind(i32::from(context_window))
        .fetch_all(self.pool())
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Returns the value of the is_canonical column for the given block
    /// hash. If the given block hash is missing then an error is returned.
    pub async fn is_block_canonical(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<bool>, Error> {
        sqlx::query_scalar(
            "SELECT is_canonical FROM sbtc_signer.bitcoin_blocks WHERE block_hash = $1",
        )
        .bind(block_hash)
        .fetch_one(self.pool())
        .await
        .map_err(Error::SqlxQuery)
    }
}
