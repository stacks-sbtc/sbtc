//! Requests for withdrawal api calls.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::models::chainstate::Chainstate;
use crate::api::models::common::{Fulfillment, WithdrawalStatus};
use crate::api::models::withdrawal::WithdrawalParameters;
use crate::common::error::{self, ValidationError};
use crate::database::entries::WithdrawalStatusEntry;
use crate::database::entries::withdrawal::{
    ValidatedUpdateWithdrawalRequest, ValidatedWithdrawalUpdate, WithdrawalEvent,
};

/// Query structure for the get withdrawals request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetWithdrawalsQuery {
    /// Operation status.
    pub status: WithdrawalStatus,
    /// Next token for the search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    /// Maximum number of results to show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u16>,
}

/// Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateWithdrawalRequestBody {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: u64,
    /// The stacks block hash in which this request id was initiated.
    pub stacks_block_hash: String,
    /// The stacks block hash in which this request id was initiated.
    pub stacks_block_height: u64,
    /// The recipient's Bitcoin hex-encoded scriptPubKey.
    pub recipient: String,
    /// The sender's Stacks principal.
    pub sender: String,
    /// Amount of BTC being withdrawn in satoshis.
    pub amount: u64,
    /// Withdrawal request parameters.
    pub parameters: WithdrawalParameters,
    /// The hex encoded txid of the stacks transaction that generated this event.
    pub txid: String,
}

/// A singular Withdrawal update that contains only the fields pertinent
/// to updating the status of a withdrawal. This includes the key related
/// data in addition to status history related data.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalUpdate {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: u64,
    /// The status of the withdrawal.
    pub status: WithdrawalStatus,
    /// The status message of the withdrawal.
    pub status_message: String,
    /// Details about the on chain artifacts that fulfilled the withdrawal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
}

impl WithdrawalUpdate {
    /// Try to convert the withdrawal update into a validated withdrawal update.
    ///
    /// # Errors
    ///
    /// - `ValidationError::WithdrawalMissingFulfillment`: If the withdrawal update is missing a fulfillment.
    pub fn try_into_validated_withdrawal_update(
        self,
        chainstate: Chainstate,
    ) -> Result<ValidatedWithdrawalUpdate, error::ValidationError> {
        // Make status entry.
        let status_entry: WithdrawalStatusEntry = match self.status {
            WithdrawalStatus::Confirmed => {
                let fulfillment =
                    self.fulfillment
                        .ok_or(ValidationError::WithdrawalMissingFulfillment(
                            self.request_id,
                        ))?;
                WithdrawalStatusEntry::Confirmed(fulfillment)
            }
            WithdrawalStatus::Accepted => WithdrawalStatusEntry::Accepted,
            WithdrawalStatus::Pending => WithdrawalStatusEntry::Pending,
            WithdrawalStatus::Failed => WithdrawalStatusEntry::Failed,
        };
        // Make the new event.
        let event = WithdrawalEvent {
            status: status_entry,
            message: self.status_message,
            stacks_block_height: chainstate.stacks_block_height,
            stacks_block_hash: chainstate.stacks_block_hash,
        };
        // Return the validated update.
        Ok(ValidatedWithdrawalUpdate {
            request_id: self.request_id,
            event,
        })
    }
}

/// Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWithdrawalsRequestBody {
    /// Withdrawal updates to execute.
    pub withdrawals: Vec<WithdrawalUpdate>,
}

impl UpdateWithdrawalsRequestBody {
    /// Try to convert the request body into a validated update request.
    ///
    /// # Errors
    ///
    /// - `ValidationError::WithdrawalsMissingFulfillment`: If any of the withdrawal updates are missing a fulfillment.
    pub fn into_validated_update_request(
        self,
        chainstate: Chainstate,
    ) -> ValidatedUpdateWithdrawalRequest {
        // Validate all the withdrawal updates.
        let mut withdrawals: Vec<(usize, Result<ValidatedWithdrawalUpdate, ValidationError>)> =
            vec![];

        for (index, update) in self.withdrawals.into_iter().enumerate() {
            match update
                .clone()
                .try_into_validated_withdrawal_update(chainstate.clone())
            {
                Ok(validated_update) => withdrawals.push((index, Ok(validated_update))),
                Err(ref error @ ValidationError::WithdrawalMissingFulfillment(request_id)) => {
                    tracing::warn!(
                        request_id,
                        "failed to update withdrawal: request missing fulfillment for completed request."
                    );
                    withdrawals.push((index, Err(error.clone())));
                }
                Err(error) => {
                    tracing::error!(
                        request_id = update.request_id,
                        %error,
                        "unexpected error while validating withdrawal update: this error should never happen during a withdrawal update validation.",
                    );
                    withdrawals.push((index, Err(error)));
                }
            }
        }

        // Sort updates by stacks_block_height to process them in chronological order.
        withdrawals.sort_by_key(|(_, update)| match update {
            Ok(validated_update) => validated_update.event.stacks_block_height,
            Err(_) => u64::MAX, // Place errors at the end
        });

        ValidatedUpdateWithdrawalRequest { withdrawals }
    }
}
