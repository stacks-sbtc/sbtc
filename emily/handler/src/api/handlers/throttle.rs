//! Handlers for limits endpoints.

use crate::{
    api::models::limits::Limits,
    api::models::throttle::{GetThrottleKeyResponse, ThrottleKey, ThrottleRequest},
    common::error::Error,
    context::EmilyContext,
    database::{
        accessors::{self, KeyVerificationResult},
        entries::throttle::{ThrottleKeyEntry, ThrottleKeyEntryKey},
    },
};
use argon2::{Argon2, password_hash::PasswordHasher as _};
use axum::Json;
use axum::extract::Extension;
use axum::http::StatusCode;
use tracing::instrument;

/// Get the throttle key details.
#[utoipa::path(
    get,
    operation_id = "getThrottleKey",
    path = "/throttle",
    tag = "throttle",
    request_body = String,
    responses(
        (status = 200, description = "Throttle key retrieved successfully", body = GetThrottleKeyResponse),
        (status = 404, description = "Throttle key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn get_throttle_key(
    Extension(context): Extension<EmilyContext>,
    Json(hash): Json<String>,
) -> Result<(StatusCode, GetThrottleKeyResponse), Error> {
    let key = accessors::get_throttle_key(&context, &hash).await?;
    let key = GetThrottleKeyResponse {
        name: key.name,
        hash: key.key.hash,
        is_active: key.is_active,
    };
    Ok((StatusCode::OK, key))
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
    request_body = ThrottleRequest,
    responses(
        (status = 200, description = "Throttle started successfully", body = Limits),
        (status = 403, description = "Key is revoked", body = ErrorResponse),
        (status = 404, description = "Throttle key not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
#[instrument(
    skip(request, context),
    fields(request.name = %request.name)
)]
pub async fn start_throttle(
    Extension(context): Extension<EmilyContext>,
    Json(request): Json<ThrottleRequest>,
) -> Result<(StatusCode, Limits), Error> {
    let verification_result =
        accessors::verify_throttle_key(&context, &request.name, &request.secret).await?;

    match verification_result {
        KeyVerificationResult::Revoked => {
            tracing::warn!(
                key_name = %request.name,
                "Attempt to start throttle mode with revoked key",
            );
            Err(Error::Forbidden)
        }
        KeyVerificationResult::Eligible(initiator) => {
            // TODO: we need an alarm on this error.
            tracing::info!(
                key_name = %request.name,
                "Successfull request to start throttle mode. Starting throttle mode.",
            );
            let new_limits = calculate_throttle_mode_limits(&context, initiator).await?;
            tracing::info!(?new_limits, "Calculated limits to use in throttle mode",);
            match crate::api::handlers::limits::set_limits(
                Extension(context),
                Json(new_limits.clone()),
            )
            .await
            {
                Ok((_, limits)) => {
                    tracing::info!("successfully started throttle mode.");
                    Ok((StatusCode::OK, limits))
                }
                Err(error) => {
                    tracing::error!(?error, "Error setting throttle mode limits");
                    Err(Error::InternalServer)
                }
            }
        }
    }
}

/// Add throttle key handler.
#[utoipa::path(
    post,
    operation_id = "addThrottleKey",
    path = "/throttle",
    tag = "throttle",
    request_body = ThrottleKey,
    responses(
        (status = 201, description = "Throttle key added successfully"),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 409, description = "Key already exists", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(
    skip(key, context),
    fields(key.name = %key.name)
)]
pub async fn add_throttle_key(
    Extension(context): Extension<EmilyContext>,
    Json(key): Json<ThrottleKey>,
) -> Result<StatusCode, Error> {
    let argon2 = Argon2::default();
    let salt = accessors::name_to_salt(&key.name)?;
    let hash = argon2
            .hash_password(key.secret.as_bytes(), &salt)
            .inspect_err(|error| {
                tracing::error!(
                    ?error,
                    name = %key.name,
                    "Error hashing the secret. Usually happens due to failed conversion of name into salt",
                );
            })
            .map_err(|_| Error::Deserialization("Error hashing the secret. Usually happens due to failed conversion of name into salt".to_string()))?
            .to_string();
    let entry = ThrottleKeyEntry {
        key: ThrottleKeyEntryKey {
            hash,
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
    // This StatusCode gets transformed into a response with an empty body.
    // <https://github.com/tokio-rs/axum/blob/axum-core-v0.5.0/axum-core/src/response/into_response.rs#L118-L130>
    Ok(StatusCode::CREATED)
}

/// Deactivate existing throttle key
#[utoipa::path(
    patch,
    operation_id = "deactivateThrottleKey",
    path = "/throttle/deactivate",
    tag = "throttle",
    request_body = String,
    responses(
        (status = 204, description = "Throttle key deactivated successfully"),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Throttle key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn deactivate_throttle_key(
    Extension(context): Extension<EmilyContext>,
    Json(hash): Json<String>,
) -> Result<StatusCode, Error> {
    accessors::deactivate_throttle_key(&context, hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Activate existing (previously deactivated) throttle key
#[utoipa::path(
    patch,
    operation_id = "activateThrottleKey",
    path = "/throttle/activate",
    tag = "throttle",
    request_body = String,
    responses(
        (status = 204, description = "Throttle key activated successfully"),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Throttle key not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn activate_throttle_key(
    Extension(context): Extension<EmilyContext>,
    Json(hash): Json<String>,
) -> Result<StatusCode, Error> {
    accessors::activate_throttle_key(&context, hash).await?;
    Ok(StatusCode::NO_CONTENT)
}
