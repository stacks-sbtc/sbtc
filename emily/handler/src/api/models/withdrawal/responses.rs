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
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalWithStatus {
    /// The fully extracted and validated withdrawal.
    pub withdrawal: Withdrawal,
    /// HTTP status code, returned as part of multi-status responses.
    pub status: u16,
}
