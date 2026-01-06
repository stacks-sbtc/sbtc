//! Handlers for limits endpoints.
use std::time::SystemTime;

use crate::{
    api::models::limits::{AccountLimits, Limits},
    common::error::Error,
    context::EmilyContext,
    database::{
        accessors,
        entries::limits::{GLOBAL_CAP_ACCOUNT, LimitEntry},
    },
};
use axum::Json;
use axum::extract::Extension;
use axum::extract::Path as UrlPath;
use axum::http::StatusCode;
use tracing::instrument;

/// Get the global limits.
#[utoipa::path(
    get,
    operation_id = "getLimits",
    path = "/limits",
    tag = "limits",
    responses(
        (status = 200, description = "Limits retrieved successfully", body = Limits),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
#[instrument(skip(context))]
pub async fn get_limits(
    Extension(context): Extension<EmilyContext>,
) -> Result<(StatusCode, Limits), Error> {
    let global_limits = accessors::get_limits(&context).await?;
    Ok((StatusCode::OK, global_limits))
}

/// Set limits handler.
/// Note, that `available_to_withdraw` is not settable, but is calculated based on the other fields.
/// Value of `available_to_withdraw` passed to this endpoint will be ignored.
#[utoipa::path(
    post,
    operation_id = "setLimits",
    path = "/limits",
    tag = "limits",
    request_body = Limits,
    responses(
        (status = 200, description = "Limits updated successfully", body = Limits),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn set_limits(
    Extension(context): Extension<EmilyContext>,
    Json(limits): Json<Limits>,
) -> Result<(StatusCode, Limits), Error> {
    // Validate the withdrawal limit configuration.
    limits.validate()?;
    // Set the global limits.
    accessors::set_limit_for_account(
        &context,
        &LimitEntry::from_account_limit(
            GLOBAL_CAP_ACCOUNT.to_string(),
            SystemTime::now(),
            &AccountLimits {
                peg_cap: limits.peg_cap,
                per_deposit_minimum: limits.per_deposit_minimum,
                per_deposit_cap: limits.per_deposit_cap,
                per_withdrawal_cap: limits.per_withdrawal_cap,
                rolling_withdrawal_blocks: limits.rolling_withdrawal_blocks,
                rolling_withdrawal_cap: limits.rolling_withdrawal_cap,
            },
        ),
    )
    .await?;
    // Get account cap entries.
    let account_cap_entries = limits
        .account_caps
        .into_iter()
        .map(|(account, account_limits)| {
            LimitEntry::from_account_limit(account, SystemTime::now(), &account_limits)
        })
        .collect::<Vec<LimitEntry>>();
    // Put each entry into the table.
    for entry in account_cap_entries {
        accessors::set_limit_for_account(&context, &entry).await?;
    }
    // Get the limits from the database confirming that the updates were done.
    let global_limits = accessors::get_limits(&context).await?;
    // Respond.
    Ok((StatusCode::CREATED, global_limits))
}

/// Get limits for account handler.
#[utoipa::path(
    get,
    operation_id = "getLimitsForAccount",
    path = "/limits/{account}",
    params(
        ("account" = String, Path, description = "The account for which to get the limits."),
    ),
    tag = "limits",
    responses(
        (status = 201, description = "Account limits retrieved successfully", body = AccountLimits),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
#[instrument(skip(context))]
pub async fn get_limits_for_account(
    Extension(context): Extension<EmilyContext>,
    UrlPath(account): UrlPath<String>,
) -> Result<(StatusCode, AccountLimits), Error> {
    // Get the entry.
    let account_limit: AccountLimits = accessors::get_limit_for_account(&context, &account)
        .await?
        .into();
    // Respond.
    Ok((StatusCode::OK, account_limit))
}

/// Set limits for account handler.
#[utoipa::path(
    post,
    operation_id = "setLimitsForAccount",
    path = "/limits/{account}",
    params(
        ("account" = String, Path, description = "The account for which to set the limits."),
    ),
    tag = "limits",
    request_body = AccountLimits,
    responses(
        (status = 201, description = "Set account limits successfully", body = AccountLimits),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn set_limits_for_account(
    Extension(context): Extension<EmilyContext>,
    UrlPath(account): UrlPath<String>,
    Json(account_limit): Json<AccountLimits>,
) -> Result<(StatusCode, AccountLimits), Error> {
    // Create the limit entry.
    let limit_entry = LimitEntry::from_account_limit(account, SystemTime::now(), &account_limit);
    // Put entry into the table.
    accessors::set_limit_for_account(&context, &limit_entry).await?;
    // Respond.
    Ok((StatusCode::OK, account_limit))
}
