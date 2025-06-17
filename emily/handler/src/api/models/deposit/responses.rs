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
    pub deposits: Vec<DepositWithStatusSchemed>,
}

impl<T> From<T> for UpdateDepositsResponse
where
    T: IntoIterator<Item = DepositWithStatus>,
{
    fn from(value: T) -> Self {
        Self {
            deposits: value.into_iter().map(Into::into).collect()
        }
    }
}

/// Wrapper for deposit with status code. Used for multi-status responses.
#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositWithStatus {
    /// The fully extracted and validated deposit request, or
    /// an error message.
    pub deposit: Result<Deposit, String>,
    /// HTTP status code, returned as part of multi-status responses.
    pub status: u16,
}

/// Workaround to make utopia generate openapi. Used only as last step before sending
/// UpdateDepositsResponce
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct DepositWithStatusSchemed {
    deposit: Option<Deposit>,
    error: Option<String>,
    status: u16,
}


impl From<DepositWithStatus> for DepositWithStatusSchemed {
    fn from(value: DepositWithStatus) -> Self {
        Self {
            deposit: value.deposit.clone().ok(),
            error: value.deposit.err(),
            status: value.status,
        }
    }
}