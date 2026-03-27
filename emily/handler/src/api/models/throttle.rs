//! Request structures for throttle api calls.

use axum::Json;
use axum::response::IntoResponse;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Represents the throttle key
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct ThrottleKey {
    /// The name of the key.
    pub name: String,
    /// The secret of the secret associated with this key.
    pub secret: String,
}

impl IntoResponse for ThrottleKey {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

/// Represents the throttle reqwest
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct ThrottleRequest {
    /// The name of the key.
    pub name: String,
    /// The secret associated with this key.
    pub secret: String,
}

impl IntoResponse for ThrottleRequest {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}
/// Response to get_throttle_key endpoint, with information about the key
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct GetThrottleKeyResponse {
    /// The name of the key.
    pub name: String,
    /// The hash of the key.
    pub hash: String,
    /// If this key is eligible to start throttle mode.
    pub is_active: bool,
}

impl IntoResponse for GetThrottleKeyResponse {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}
