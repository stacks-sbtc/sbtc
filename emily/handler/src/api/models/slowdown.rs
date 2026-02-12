//! Request structures for limits api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Represents the slowdown key
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct SlowdownKey {
    /// The name of the key.
    pub name: String,
    /// The hash of the secret associated with this key.
    pub hash: String,
}

/// Represents the slowdown reqwest
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct SlowdownReqwest {
    /// The name of the key.
    pub hash: String,
    /// The secret associated with this key.
    pub secret: String,
}
