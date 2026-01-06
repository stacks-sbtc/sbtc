//! Request structures for chainstate api calls.

use axum::Json;
use axum::response::IntoResponse;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Chainstate.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct Chainstate {
    /// Stacks block height.
    pub stacks_block_height: u64,
    /// Stacks block hash at the height.
    pub stacks_block_hash: String,
    /// Bitcoin block height
    pub bitcoin_block_height: Option<u64>,
}

impl IntoResponse for Chainstate {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}
