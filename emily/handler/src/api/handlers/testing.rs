//! Handlers for testing endpoint endpoints.

use axum::extract::Extension;
use axum::http::StatusCode;
use tracing::instrument;

use crate::common::error::Error;
use crate::context::EmilyContext;
use crate::database::accessors;

/// Wipe databases handler.
#[utoipa::path(
    post,
    operation_id = "wipeDatabases",
    path = "/testing/wipe",
    tag = "testing",
    responses(
        (status = 204, description = "Successfully wiped databases."),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn wipe_databases(
    Extension(context): Extension<EmilyContext>,
) -> Result<StatusCode, Error> {
    accessors::wipe_all_tables(&context).await?;
    Ok(StatusCode::NO_CONTENT)
}
