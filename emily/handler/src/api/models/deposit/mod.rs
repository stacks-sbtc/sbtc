//! Request structures for deposit api calls.

use sbtc::deposits::DepositScriptVersion;
use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

use crate::api::models::common::{DepositStatus, Fulfillment};

/// The deposit script format version.
#[derive(
    Clone, Copy, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse,
)]
#[serde(rename_all = "lowercase")]
pub enum DepositVersion {
    /// Legacy aggregate-key deposits.
    #[default]
    V1,
    /// Independent-signature `multi_a` deposits.
    V2,
}

impl From<DepositScriptVersion> for DepositVersion {
    fn from(value: DepositScriptVersion) -> Self {
        match value {
            DepositScriptVersion::V1 => Self::V1,
            DepositScriptVersion::V2 => Self::V2,
        }
    }
}

/// Requests.
pub mod requests;
/// Responses.
pub mod responses;

/// Deposit.
#[derive(
    Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct Deposit {
    /// Deposit script format version. Defaults to v1 so that clients can
    /// read responses from an Emily that predates this field.
    #[serde(default)]
    pub version: DepositVersion,
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub bitcoin_tx_output_index: u32,
    /// Stacks address to received the deposited sBTC.
    pub recipient: String,
    /// Amount of BTC being deposited in satoshis.
    pub amount: u64,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: u64,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
    /// The status of the deposit.
    pub status: DepositStatus,
    /// The status message of the deposit.
    pub status_message: String,
    /// Deposit parameters
    pub parameters: DepositParameters,
    /// Raw reclaim script binary in hex.
    pub reclaim_script: String,
    /// Raw deposit script binary in hex.
    pub deposit_script: String,
    /// Details about the on chain artifacts that fulfilled the deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
    /// Transaction ID of the transaction that replaced this one via RBF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_by_tx: Option<String>,
}

/// Deposit parameters.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct DepositParameters {
    /// Maximum fee the signers are allowed to take from the deposit to facilitate
    /// the transaction.
    pub max_fee: u64,
    /// Bitcoin block height at which the reclaim script becomes executable.
    pub lock_time: u32,
}

/// Reduced version of the Deposit data.
#[derive(
    Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct DepositInfo {
    /// Deposit script format version. Defaults to v1 so that clients can
    /// read responses from an Emily that predates this field.
    #[serde(default)]
    pub version: DepositVersion,
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub bitcoin_tx_output_index: u32,
    /// Stacks address to received the deposited sBTC.
    pub recipient: String,
    /// Maximum fee the signers may spend while sweeping this deposit.
    /// Defaults to zero so that clients can read responses from an Emily
    /// that predates this field.
    #[serde(default)]
    pub max_fee: u64,
    /// Amount of BTC being deposited in satoshis.
    pub amount: u64,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: u64,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
    /// The status of the deposit.
    pub status: DepositStatus,
    /// Raw reclaim script binary in hex.
    pub reclaim_script: String,
    /// Raw deposit script binary in hex.
    pub deposit_script: String,
}

/// Create a DepositInfo, which has a subset of the data within a Deposit, from a Deposit.
impl From<Deposit> for DepositInfo {
    fn from(deposit: Deposit) -> Self {
        DepositInfo {
            version: deposit.version,
            bitcoin_txid: deposit.bitcoin_txid,
            bitcoin_tx_output_index: deposit.bitcoin_tx_output_index,
            recipient: deposit.recipient,
            max_fee: deposit.parameters.max_fee,
            amount: deposit.amount,
            last_update_height: deposit.last_update_height,
            last_update_block_hash: deposit.last_update_block_hash,
            status: deposit.status,
            reclaim_script: deposit.reclaim_script,
            deposit_script: deposit.deposit_script,
        }
    }
}
