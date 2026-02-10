//! Handlers for limits endpoints.

use crate::{
    api::models::limits::Limits,
    api::models::slowdown::{SlowdownKey, SlowdownReqwest},
    common::error::Error,
    context::EmilyContext,
    database::{
        accessors::{self, KeyVerificationResult},
        entries::slowdown::{SlowdownKeyEntry, SlowdownKeyEntryKey},
    },
};
use tracing::instrument;
use warp::http::StatusCode;
use warp::reply::{Reply, json, with_status};

/// Get the slowdown key details.
#[utoipa::path(
    get,
    operation_id = "getSlowdownKey",
    path = "/slowdown",
    tag = "slowdown",
    request_body = String,
    responses(
        (status = 200, description = "Slowdown key retrieved successfully", body = SlowdownKey),
        (status = 404, description = "Slowdown key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
#[instrument(skip(context))]
pub async fn get_slowdown_key(name: String, context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        name: String,
        context: EmilyContext,
    ) -> Result<impl warp::reply::Reply, Error> {
        let key = accessors::get_slowdown_key(&context, &name).await?;
        Ok(with_status(json(&key), StatusCode::OK))
    }
    // Handle and respond.
    handler(name, context)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Rolling window size for slow mode.
pub const SLOW_MODE_ROLLING_WINDOW: u64 = 18;
/// Rolling cap for slow mode.
pub const SLOW_MODE_ROLLING_CAP: u64 = 200_000_000; // 2 BTC.
/// Per withdrawal cap for slow mode.
pub const SLOW_MODE_PER_WITHDRAWAL_CAP: u64 = 150_000_000; // 1.5 BTC

/// Calculates slow mode limits. It keeps most limits as they are now,
/// while overwriting some of them.
pub async fn calculate_slow_mode_limits(context: &EmilyContext) -> Result<Limits, Error> {
    let mut limits = accessors::get_limits(context).await?;
    limits.rolling_withdrawal_blocks = Some(SLOW_MODE_ROLLING_WINDOW);
    limits.rolling_withdrawal_cap = Some(SLOW_MODE_ROLLING_CAP);
    limits.per_withdrawal_cap = Some(SLOW_MODE_PER_WITHDRAWAL_CAP);
    Ok(limits)
}

/// Try to turn on slow mode
#[utoipa::path(
    post,
    operation_id = "startSlowdown",
    path = "/start_slowdown",
    tag = "slowdown",
    request_body = SlowdownReqwest,
    responses(
        (status = 200, description = "Slowdown key retrieved successfully", body = Limits),
        (status = 404, description = "Slowdown key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
#[instrument(skip(context))]
pub async fn start_slowdown(
    request: SlowdownReqwest,
    context: EmilyContext,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        request: SlowdownReqwest,
        context: EmilyContext,
    ) -> Result<impl warp::reply::Reply, Error> {
        let verification_result =
            accessors::verify_slowdown_key(&context, &request.name, &request.secret).await?;

        match verification_result {
            KeyVerificationResult::Revoked => {
                tracing::warn!(
                    key_name = %request.name,
                    "Attempt to start slow mode with revoked key",
                );
                Err(Error::Forbidden)
            }
            KeyVerificationResult::FailedSecretVerification => {
                tracing::warn!(
                    key_name = %request.name,
                    "Attempt to start slow mode failed key verification",
                );
                Err(Error::Forbidden)
            }
            KeyVerificationResult::Eligible => {
                // It is not actually an error, but we want to take maximum attention if it happens.
                // TODO: we need an alarm on this error.
                tracing::error!(
                    key_name = %request.name,
                    "Successfull request to start slow mode. Starting slow mode.",
                );
                let new_limits = calculate_slow_mode_limits(&context).await?;
                tracing::info!(?new_limits, "Calculated limits to use in slow mode",);
                let res = crate::api::handlers::limits::set_limits(new_limits.clone(), context)
                    .await
                    .into_response();
                let is_success = res.status().is_success();
                if is_success {
                    tracing::info!("successfully started slow mode.");
                    return Ok(with_status(json(&new_limits), StatusCode::OK));
                }
                tracing::error!(?res, "Error setting slow mode limits");
                Err(Error::InternalServer)
            }
        }
    }
    // Handle and respond.
    handler(request, context)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Add slowdown key handler.
#[utoipa::path(
    post,
    operation_id = "addSlowdownKey",
    path = "/slowdown",
    tag = "slowdown",
    request_body = SlowdownKey,
    responses(
        (status = 200, description = "Slowdown key added successfully", body = SlowdownKey),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn add_slowdown_key(key: SlowdownKey, context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        key: SlowdownKey,
    ) -> Result<impl warp::reply::Reply, Error> {
        let entry = SlowdownKeyEntry {
            key: SlowdownKeyEntryKey {
                key_name: key.name.clone(),
                hash: key.hash.clone(),
            },
            is_active: true,
        };
        accessors::add_slowdown_key(&context, &entry).await?;
        Ok(with_status(json(&key), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, key)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}


/// Deactivate existing slowdown key
#[utoipa::path(
    patch,
    operation_id = "deactivateSlowdownKey",
    path = "/slowdown/deactivate/{name}",
    params(
        ("name" = String, Path, description = "The name of the key to deactivate"),
    ),
    tag = "slowdown",
    responses(
        (status = 201, description = "Slowdown key deactivated successfully", body = ()),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Slowdown key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn deactivate_slowdown_key(
    name: String,
    context: EmilyContext,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        name: String,
    ) -> Result<impl warp::reply::Reply, Error> {
        let _ = accessors::deactivate_slowdown_key(&context, name).await?;
        Ok(with_status(json(&()), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, name)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}


/// Activate existing (previously deactivated) slowdown key
#[utoipa::path(
    patch,
    operation_id = "activateSlowdownKey",
    path = "/slowdown/activate/{name}",
    params(
        ("name" = String, Path, description = "The name of the key to activate"),
    ),
    tag = "slowdown",
    responses(
        (status = 201, description = "Slowdown key activated successfully", body = ()),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Slowdown key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn activate_slowdown_key(
    name: String,
    context: EmilyContext,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        name: String,
    ) -> Result<impl warp::reply::Reply, Error> {
        let _ = accessors::activate_slowdown_key(&context, name).await?;
        Ok(with_status(json(&()), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, name)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}
