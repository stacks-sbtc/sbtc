//! Request structures for throttle api calls.

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

/// Represents the throttle reqwest
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct ThrottleRequest {
    /// The name of the key.
    pub name: String,
    /// The secret associated with this key.
    pub secret: String,
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
