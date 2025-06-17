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
    pub withdrawals: Vec<WithdrawalWithStatusSchemed>,
}

impl<T> From<T> for UpdateWithdrawalsResponse
where
    T: IntoIterator<Item = WithdrawalWithStatus>,
{
    fn from(value: T) -> Self {
        Self {
            withdrawals: value.into_iter().map(Into::into).collect(),
        }
    }
}

/// Wrapper for withdrawal with status code. Used for multi-status responses.
#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalWithStatus {
    /// The fully extracted and validated withdrawal.
    pub withdrawal: Result<Withdrawal, String>,
    /// HTTP status code, returned as part of multi-status responses.
    pub status: u16,
}

/// Workaround to make utopia generate openapi. Used only as last step before sending
/// UpdateWithdrawalsResponce
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalWithStatusSchemed {
    withdrawal: Option<Withdrawal>,
    error: Option<String>,
    status: u16,
}

impl From<WithdrawalWithStatus> for WithdrawalWithStatusSchemed {
    fn from(value: WithdrawalWithStatus) -> Self {
        Self {
            withdrawal: value.withdrawal.clone().ok(),
            error: value.withdrawal.err(),
            status: value.status,
        }
    }
}
