use axum::Json;
use axum::response::IntoResponse;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Struct that represents the current status of the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HealthData {
    /// The version of the API.
    pub version: String,
}

impl IntoResponse for HealthData {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}
