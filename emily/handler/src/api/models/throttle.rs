//! Request structures for throttle api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Represents the throttle key
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct ThrottleKey {
    /// The name of the key.
    pub name: String,
    /// The hash of the secret associated with this key.
    pub hash: String,
}

/// Represents the throttle reqwest
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct ThrottleReqwest {
    /// The hash of the key.
    pub hash: String,
    /// The secret associated with this key.
    pub secret: String,
}
