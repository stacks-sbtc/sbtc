//! Bitcoin and Stacks API response types, plus small reconciliation helpers.

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
    /// Return the confirming block height, or `None` if still unconfirmed.
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

impl Input {
    /// True when a witness element equals the reclaim script hex (case-insensitive).
    ///
    /// Matches a whole stack item only; substring matches are ignored.
    pub fn contains_reclaim_script(&self, reclaim_script: &str) -> bool {
        self.witness
            .iter()
            .any(|item| item.eq_ignore_ascii_case(reclaim_script))
    }
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
    /// Append every transaction ID in this replacement subtree to `output`.
    pub fn txids(&self, output: &mut Vec<String>) {
        if let Some(tx) = &self.tx {
            output.push(tx.txid.clone());
        }
        for child in &self.replaces {
            child.txids(output);
        }
    }
}

/// Stacks block timestamp used to determine a deposit's age.
#[derive(Deserialize)]
pub struct Block {
    /// Block timestamp in seconds since the Unix epoch.
    pub block_time: u64,
}

/// True when `tip` has reached `height + lock_time + confirmations`.
///
/// Returns `false` if the height arithmetic would overflow.
pub fn is_past_expiry(height: u64, lock_time: u32, confirmations: u64, tip: u64) -> bool {
    let Some(reclaim_height) = height.checked_add(u64::from(lock_time)) else {
        return false;
    };
    let Some(expiry_height) = reclaim_height.checked_add(confirmations) else {
        return false;
    };
    tip >= expiry_height
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locktime_and_expiry_boundaries() {
        assert!(!is_past_expiry(100, 96, 6, 201));
        assert!(is_past_expiry(100, 96, 6, 202));
        assert!(!is_past_expiry(u64::MAX, 1, 6, u64::MAX));
    }
}
