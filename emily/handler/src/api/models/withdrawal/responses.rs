//! Responses for withdrawal api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

use crate::api::models::withdrawal::{Withdrawal, WithdrawalInfo};

/// Response to get withdrawals request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct GetWithdrawalsResponse {
    /// Next token for the search.
    pub next_token: Option<String>,
    /// Withdrawal infos: withdrawals with a little less data.
    pub withdrawals: Vec<WithdrawalInfo>,
}

/// Response to update withdrawals request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWithdrawalsResponse {
    /// Updated withdrawals.
    pub withdrawals: Vec<WithdrawalWithStatus>,
}

/// Wrapper for withdrawal with status code. Used for multi-status responses.
/// TODO: utopia, which we use for generating OpenAPI spec does not support
/// [`Result`] in structs, however, logically exactly one of `withdrawal` or `error` should be
/// None, and exactly one of them should be Some. It would be nice to find a way to use
/// `Result` here.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalWithStatus {
    /// The fully extracted and validated withdrawal request.
    pub withdrawal: Option<Withdrawal>,
    /// String explaining error occured during updating the withdrawal.
    pub error: Option<String>,
    /// HTTP status code for the withdrawal processing result.
    pub status: u16,
}
