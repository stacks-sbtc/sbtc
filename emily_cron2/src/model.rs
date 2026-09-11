//! Bitcoin and Stacks API response types and reconciliation helpers.

use crate::error::Error;
use bitcoin::ScriptBuf;
use sbtc::deposits::ReclaimScriptInputs;
use serde::Deserialize;

/// Bitcoin transaction details returned by the mempool API.
#[derive(Clone, Deserialize)]
pub struct Transaction {
    /// Confirmation state of the transaction.
    pub status: TransactionStatus,
    /// Transaction inputs, in Bitcoin input order.
    #[serde(default)]
    pub vin: Vec<Input>,
}

/// Bitcoin confirmation state of a transaction.
#[derive(Clone, Deserialize)]
pub struct TransactionStatus {
    /// Whether the transaction is included in a Bitcoin block.
    pub confirmed: bool,
    /// Height of the confirming block, when known.
    pub block_height: Option<u64>,
}

impl Transaction {
    /// Return the block height only when the transaction is confirmed.
    pub fn confirmed_height(&self) -> Option<u64> {
        if self.status.confirmed {
            self.status.block_height
        } else {
            None
        }
    }
}

/// Bitcoin transaction input witness data.
#[derive(Clone, Deserialize)]
pub struct Input {
    /// Hex-encoded witness stack elements.
    #[serde(default)]
    pub witness: Vec<String>,
}

/// Electrs spending information for a deposit output.
#[derive(Deserialize)]
pub struct Outspend {
    /// Whether the output has been spent.
    pub spent: bool,
    /// Spending transaction ID, if the output is spent.
    pub txid: Option<String>,
    /// Index of the input spending the output.
    pub vin: Option<usize>,
}

/// Replacement history returned by the mempool API.
#[derive(Deserialize)]
pub struct Rbf {
    /// Root of the replacement tree, if a replacement is known.
    pub replacements: Option<Replacement>,
}

/// One transaction and its predecessors in a replacement tree.
#[derive(Deserialize)]
pub struct Replacement {
    /// Transaction represented by this tree node.
    pub tx: Option<ReplacementTransaction>,
    /// Earlier transactions replaced by this transaction.
    #[serde(default)]
    pub replaces: Vec<Replacement>,
}

/// Transaction identity within a replacement tree.
#[derive(Deserialize)]
pub struct ReplacementTransaction {
    /// Bitcoin transaction ID of the replacement tree node.
    pub txid: String,
}

impl Replacement {
    /// Collect transaction IDs from this replacement subtree.
    pub fn txids(&self, output: &mut Vec<String>) {
        if let Some(tx) = &self.tx {
            output.push(tx.txid.clone());
        }
        for replacement in &self.replaces {
            replacement.txids(output);
        }
    }
}

/// Parse and validate the reclaim script using the shared sBTC rules.
pub fn lock_time(script: &str) -> Result<u32, Error> {
    let script = ScriptBuf::from_hex(script)?;
    let reclaim = ReclaimScriptInputs::parse(&script)?;
    Ok(reclaim.lock_time())
}

/// Check whether the required delay and confirmation margin have elapsed.
pub fn expired(height: u64, lock_time: u32, confirmations: u64, tip: u64) -> bool {
    let Some(reclaim_height) = height.checked_add(u64::from(lock_time)) else {
        return false;
    };
    let Some(expiry_height) = reclaim_height.checked_add(confirmations) else {
        return false;
    };
    tip >= expiry_height
}

impl Input {
    /// Check for a whole reclaim-script witness element, ignoring hex case.
    pub fn contains_reclaim_script(&self, reclaim_script: &str) -> bool {
        for item in &self.witness {
            if item.eq_ignore_ascii_case(reclaim_script) {
                return true;
            }
        }
        false
    }
}

/// Stacks block timestamp used to determine a deposit's age.
#[derive(Deserialize)]
pub struct Block {
    /// Block timestamp in seconds since the Unix epoch.
    pub block_time: u64,
}
