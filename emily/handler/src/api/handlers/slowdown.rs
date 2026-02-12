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
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn get_slowdown_key(hash: String, context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        hash: String,
        context: EmilyContext,
    ) -> Result<impl warp::reply::Reply, Error> {
        let key = accessors::get_slowdown_key(&context, &hash).await?;
        let key = SlowdownKey {
            name: key.name,
            hash: key.key.hash,
        };
        Ok(with_status(json(&key), StatusCode::OK))
    }
    // Handle and respond.
    handler(hash, context)
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
pub async fn calculate_slow_mode_limits(
    context: &EmilyContext,
    initiator: String,
) -> Result<Limits, Error> {
    let mut limits = accessors::get_limits(context).await?;
    limits.per_withdrawal_cap = Some(
        limits
            .per_withdrawal_cap
            .map_or(SLOW_MODE_PER_WITHDRAWAL_CAP, |curr| {
                curr.min(SLOW_MODE_PER_WITHDRAWAL_CAP)
            }),
    );
    limits.rolling_withdrawal_blocks = Some(
        limits
            .rolling_withdrawal_blocks
            .map_or(SLOW_MODE_ROLLING_WINDOW, |curr| {
                curr.max(SLOW_MODE_ROLLING_WINDOW)
            }),
    );
    limits.rolling_withdrawal_cap = Some(
        limits
            .rolling_withdrawal_cap
            .map_or(SLOW_MODE_ROLLING_CAP, |curr| {
                curr.min(SLOW_MODE_ROLLING_CAP)
            }),
    );
    limits.slow_mode_initiator = Some(initiator);
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
        (status = 200, description = "Slowdown started successfully", body = Limits),
        (status = 401, description = "Failed key verification", body = ErrorResponse),
        (status = 403, description = "Key is revoked", body = ErrorResponse),
        (status = 404, description = "Slowdown key not found", body = ErrorResponse),
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
            accessors::verify_slowdown_key(&context, &request.hash, &request.secret).await?;

        match verification_result {
            KeyVerificationResult::Revoked => {
                tracing::warn!(
                    key_hash = %request.hash,
                    "Attempt to start slow mode with revoked key",
                );
                Err(Error::Forbidden)
            }
            KeyVerificationResult::FailedSecretVerification => {
                tracing::warn!(
                    key_hash = %request.hash,
                    "Attempt to start slow mode failed key verification",
                );
                Err(Error::Unauthorized)
            }
            KeyVerificationResult::Eligible(initiator) => {
                // TODO: we need an alarm on this error.
                tracing::info!(
                    key_hash = %request.hash,
                    "Successfull request to start slow mode. Starting slow mode.",
                );
                let new_limits = calculate_slow_mode_limits(&context, initiator).await?;
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
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 409, description = "Key already exists", body = ErrorResponse),
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
                hash: key.hash.clone(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    // It's impossible for this to fail.
                    .expect("Error making timestamp during limit entry creation.")
                    .as_secs(),
            },
            name: key.name.clone(),
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
    path = "/slowdown/deactivate",
    tag = "slowdown",
    request_body = String,
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
    hash: String,
    context: EmilyContext,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        hash: String,
    ) -> Result<impl warp::reply::Reply, Error> {
        accessors::deactivate_slowdown_key(&context, hash).await?;
        Ok(with_status(json(&()), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, hash)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Activate existing (previously deactivated) slowdown key
#[utoipa::path(
    patch,
    operation_id = "activateSlowdownKey",
    path = "/slowdown/activate",
    tag = "slowdown",
    request_body = String,
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
pub async fn activate_slowdown_key(hash: String, context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        hash: String,
    ) -> Result<impl warp::reply::Reply, Error> {
        accessors::activate_slowdown_key(&context, hash).await?;
        Ok(with_status(json(&()), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, hash)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}
