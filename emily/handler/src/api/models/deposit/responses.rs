//! Response structures for deposit api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

use crate::api::models::deposit::{Deposit, DepositInfo};

/// Response to get deposits for transaction request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct GetDepositsForTransactionResponse {
    /// Next token for the search.
    pub next_token: Option<String>,
    /// Deposits.
    pub deposits: Vec<Deposit>,
}

/// Response to get deposits request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct GetDepositsResponse {
    /// Next token for the search.
    pub next_token: Option<String>,
    /// Deposit infos: deposits with a little less data.
    pub deposits: Vec<DepositInfo>,
}

/// Response to update deposits request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDepositsResponse {
    /// Deposit infos: deposits with a little less data.
    pub deposits: Vec<DepositWithStatus>,
}

/// Wrapper for deposit with status code. Used for multi-status responses.
/// TODO: utopia, which we use for generating OpenAPI spec does not support
/// [`Result`] in structs, however, logically exactly one of `deposit` or `error` should be
/// None, and exactly one of them should be Some. It would be nice to find a way to use
/// `Result` here.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct DepositWithStatus {
    /// The fully extracted and validated deposit request.
    pub deposit: Option<Deposit>,
    /// A string explaining the error that occurred during the deposit update.
    pub error: Option<String>,
    /// HTTP status code for the deposit processing result.
    pub status: u16,
}
