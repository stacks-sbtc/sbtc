//! Handlers for Health endpoint endpoints.

use axum::extract::Extension;
use axum::http::StatusCode;

use crate::common::error::Error;
use crate::{api::models::health::responses::HealthData, context::EmilyContext};

/// Get health handler.
#[utoipa::path(
    get,
    operation_id = "checkHealth",
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Successfully retrieved health data.", body = HealthData),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
pub async fn get_health(
    Extension(context): Extension<EmilyContext>,
) -> Result<(StatusCode, HealthData), Error> {
    // Handle and respond.
    let health_data = HealthData {
        version: context.settings.version.clone(),
    };
    Ok((StatusCode::OK, health_data))
}
