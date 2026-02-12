//! Handlers for limits endpoints.

use crate::{
    api::models::limits::Limits,
    api::models::throttle::{ThrottleKey, ThrottleReqwest},
    common::error::Error,
    context::EmilyContext,
    database::{
        accessors::{self, KeyVerificationResult},
        entries::throttle::{ThrottleKeyEntry, ThrottleKeyEntryKey},
    },
};
use tracing::instrument;
use warp::http::StatusCode;
use warp::reply::{Reply, json, with_status};

/// Get the throttle key details.
#[utoipa::path(
    get,
    operation_id = "getThrottleKey",
    path = "/throttle",
    tag = "throttle",
    request_body = String,
    responses(
        (status = 200, description = "Throttle key retrieved successfully", body = ThrottleKey),
        (status = 404, description = "Throttle key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn get_throttle_key(hash: String, context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        hash: String,
        context: EmilyContext,
    ) -> Result<impl warp::reply::Reply, Error> {
        let key = accessors::get_throttle_key(&context, &hash).await?;
        let key = ThrottleKey {
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

/// Rolling window size for throttle mode.
pub const THROTTLE_MODE_ROLLING_WINDOW: u64 = 18;
/// Rolling cap for throttle mode.
pub const THROTTLE_MODE_ROLLING_CAP: u64 = 200_000_000; // 2 BTC.
/// Per withdrawal cap for throttle mode.
pub const THROTTLE_MODE_PER_WITHDRAWAL_CAP: u64 = 150_000_000; // 1.5 BTC

/// Calculates throttle mode limits. It keeps most limits as they are now,
/// while overwriting some of them.
pub async fn calculate_throttle_mode_limits(
    context: &EmilyContext,
    initiator: String,
) -> Result<Limits, Error> {
    let mut limits = accessors::get_limits(context).await?;
    limits.per_withdrawal_cap = Some(
        limits
            .per_withdrawal_cap
            .map_or(THROTTLE_MODE_PER_WITHDRAWAL_CAP, |curr| {
                curr.min(THROTTLE_MODE_PER_WITHDRAWAL_CAP)
            }),
    );
    limits.rolling_withdrawal_blocks = Some(
        limits
            .rolling_withdrawal_blocks
            .map_or(THROTTLE_MODE_ROLLING_WINDOW, |curr| {
                curr.max(THROTTLE_MODE_ROLLING_WINDOW)
            }),
    );
    limits.rolling_withdrawal_cap = Some(
        limits
            .rolling_withdrawal_cap
            .map_or(THROTTLE_MODE_ROLLING_CAP, |curr| {
                curr.min(THROTTLE_MODE_ROLLING_CAP)
            }),
    );
    limits.throttle_mode_initiator = Some(initiator);
    Ok(limits)
}

/// Try to turn on throttle mode
#[utoipa::path(
    post,
    operation_id = "startThrottle",
    path = "/start_throttle",
    tag = "throttle",
    request_body = ThrottleReqwest,
    responses(
        (status = 200, description = "Throttle started successfully", body = Limits),
        (status = 401, description = "Failed key verification", body = ErrorResponse),
        (status = 403, description = "Key is revoked", body = ErrorResponse),
        (status = 404, description = "Throttle key not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
#[instrument(skip(context))]
pub async fn start_throttle(
    request: ThrottleReqwest,
    context: EmilyContext,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        request: ThrottleReqwest,
        context: EmilyContext,
    ) -> Result<impl warp::reply::Reply, Error> {
        let verification_result =
            accessors::verify_throttle_key(&context, &request.hash, &request.secret).await?;

        match verification_result {
            KeyVerificationResult::Revoked => {
                tracing::warn!(
                    key_hash = %request.hash,
                    "Attempt to start throttle mode with revoked key",
                );
                Err(Error::Forbidden)
            }
            KeyVerificationResult::FailedSecretVerification => {
                tracing::warn!(
                    key_hash = %request.hash,
                    "Attempt to start throttle mode failed key verification",
                );
                Err(Error::Unauthorized)
            }
            KeyVerificationResult::Eligible(initiator) => {
                // TODO: we need an alarm on this error.
                tracing::info!(
                    key_hash = %request.hash,
                    "Successfull request to start throttle mode. Starting throttle mode.",
                );
                let new_limits = calculate_throttle_mode_limits(&context, initiator).await?;
                tracing::info!(?new_limits, "Calculated limits to use in throttle mode",);
                let res = crate::api::handlers::limits::set_limits(new_limits.clone(), context)
                    .await
                    .into_response();
                let is_success = res.status().is_success();
                if is_success {
                    tracing::info!("successfully started throttle mode.");
                    return Ok(with_status(json(&new_limits), StatusCode::OK));
                }
                tracing::error!(?res, "Error setting throttle mode limits");
                Err(Error::InternalServer)
            }
        }
    }
    // Handle and respond.
    handler(request, context)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Add throttle key handler.
#[utoipa::path(
    post,
    operation_id = "addThrottleKey",
    path = "/throttle",
    tag = "throttle",
    request_body = ThrottleKey,
    responses(
        (status = 200, description = "Throttle key added successfully", body = ThrottleKey),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 409, description = "Key already exists", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn add_throttle_key(key: ThrottleKey, context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        key: ThrottleKey,
    ) -> Result<impl warp::reply::Reply, Error> {
        let entry = ThrottleKeyEntry {
            key: ThrottleKeyEntryKey {
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
        accessors::add_throttle_key(&context, &entry).await?;
        Ok(with_status(json(&key), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, key)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Deactivate existing throttle key
#[utoipa::path(
    patch,
    operation_id = "deactivateThrottleKey",
    path = "/throttle/deactivate",
    tag = "throttle",
    request_body = String,
    responses(
        (status = 201, description = "Throttle key deactivated successfully", body = ()),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Throttle key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn deactivate_throttle_key(
    hash: String,
    context: EmilyContext,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        hash: String,
    ) -> Result<impl warp::reply::Reply, Error> {
        accessors::deactivate_throttle_key(&context, hash).await?;
        Ok(with_status(json(&()), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, hash)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Activate existing (previously deactivated) throttle key
#[utoipa::path(
    patch,
    operation_id = "activateThrottleKey",
    path = "/throttle/activate",
    tag = "throttle",
    request_body = String,
    responses(
        (status = 201, description = "Throttle key activated successfully", body = ()),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Throttle key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn activate_throttle_key(hash: String, context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        hash: String,
    ) -> Result<impl warp::reply::Reply, Error> {
        accessors::activate_throttle_key(&context, hash).await?;
        Ok(with_status(json(&()), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, hash)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}
