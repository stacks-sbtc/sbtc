//! Postgres storage implementation.

use bitcoin::OutPoint;
use tokio::sync::Mutex;

use crate::{
    bitcoin::utxo::SignerUtxo,
    keys::{PublicKey, PublicKeyXOnly},
};

use super::{
    TransactionHandle,
    model::{self, BitcoinBlockHeight, StacksBlockHeight},
};

mod read;
mod store;
mod write;

pub use store::PgStore;

/// All migration scripts from the `signer/migrations` directory.
static PGSQL_MIGRATIONS: include_dir::Dir =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/migrations");

/// A convenience struct for retrieving a deposit request report
#[derive(sqlx::FromRow)]
pub(super) struct DepositStatusSummary {
    /// The current signer may not have a record of their vote for
    /// the deposit. When that happens the `can_accept` and
    /// `can_sign` fields will be None.
    can_accept: Option<bool>,
    /// Whether this signer is a member of the signing set that generated
    /// the public key locking the deposit.
    can_sign: Option<bool>,
    /// The height of the block that confirmed the deposit request
    /// transaction.
    block_height: Option<BitcoinBlockHeight>,
    /// The block hash that confirmed the deposit request.
    block_hash: Option<model::BitcoinBlockHash>,
    /// The bitcoin consensus encoded locktime in the reclaim script.
    #[sqlx(try_from = "i64")]
    lock_time: u32,
    /// The amount associated with the deposit UTXO in sats.
    #[sqlx(try_from = "i64")]
    amount: u64,
    /// The maximum amount to spend for the bitcoin miner fee when sweeping
    /// in the funds.
    #[sqlx(try_from = "i64")]
    max_fee: u64,
    /// The deposit script used so that the signers' can spend funds.
    deposit_script: model::ScriptPubKey,
    /// The reclaim script for the deposit.
    reclaim_script: model::ScriptPubKey,
    /// The public key used in the deposit script.
    signers_public_key: PublicKeyXOnly,
}

/// A convenience struct for retrieving a withdrawal request report
#[derive(sqlx::FromRow)]
pub(super) struct WithdrawalStatusSummary {
    /// The current signer may not have a record of their vote for the
    /// withdrawal. When that happens the `is_accepted` field will be
    /// [`None`].
    is_accepted: Option<bool>,
    /// The height of the bitcoin chain tip during the execution of the
    /// contract call that generated the withdrawal request.
    bitcoin_block_height: BitcoinBlockHeight,
    /// The amount associated with the deposit UTXO in sats.
    #[sqlx(try_from = "i64")]
    amount: u64,
    /// The maximum amount to spend for the bitcoin miner fee when sweeping
    /// in the funds.
    #[sqlx(try_from = "i64")]
    max_fee: u64,
    /// The recipient scriptPubKey of the withdrawn funds.
    recipient: model::ScriptPubKey,
    /// Stacks block ID of the block that includes the transaction
    /// associated with this withdrawal request.
    stacks_block_hash: model::StacksBlockHash,
    /// Stacks block ID of the block that includes the transaction
    /// associated with this withdrawal request.
    stacks_block_height: StacksBlockHeight,
}

// A convenience struct for retrieving the signers' UTXO
#[derive(sqlx::FromRow)]
pub(super) struct PgSignerUtxo {
    txid: model::BitcoinTxId,
    #[sqlx(try_from = "i32")]
    output_index: u32,
    #[sqlx(try_from = "i64")]
    amount: u64,
    aggregate_key: PublicKey,
}

impl From<PgSignerUtxo> for SignerUtxo {
    fn from(pg_txo: PgSignerUtxo) -> Self {
        SignerUtxo {
            outpoint: OutPoint::new(pg_txo.txid.into(), pg_txo.output_index),
            amount: pg_txo.amount,
            public_key: pg_txo.aggregate_key.into(),
        }
    }
}

/// Represents an active PostgreSQL transaction.
/// Implements DbRead and DbWrite to allow operations within the transaction.
pub struct PgTransaction<'a> {
    /// The underlying transaction.
    pub tx: Mutex<sqlx::PgTransaction<'a>>,
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
