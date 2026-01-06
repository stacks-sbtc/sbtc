//! Handlers for chainstate endpoints.
use crate::{
    api::{
        handlers::internal::{ExecuteReorgRequest, execute_reorg_handler},
        models::chainstate::Chainstate,
    },
    common::{
        NO_REORG_DEPTH,
        error::{Error, Inconsistency},
    },
    context::EmilyContext,
    database::{accessors, entries::chainstate::ChainstateEntry},
};
use axum::Json;
use axum::extract::Extension;
use axum::extract::Path as UrlPath;
use axum::http::StatusCode;
use tracing::{debug, info, instrument, warn};

// TODO(TBD): Add conflict handling to the chainstate endpoint.

/// Get chain tip handler.
#[utoipa::path(
    get,
    operation_id = "getChainTip",
    path = "/chainstate",
    tag = "chainstate",
    responses(
        (status = 200, description = "Chain tip retrieved successfully", body = Chainstate),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn get_chain_tip(
    Extension(context): Extension<EmilyContext>,
) -> Result<(StatusCode, Chainstate), Error> {
    debug!("Attempting to get chain tip");
    // TODO(390): Handle multiple being in the tip list here.
    let api_state = accessors::get_api_state(&context).await?;
    let chaintip: Chainstate = api_state.chaintip().into();
    Ok((StatusCode::OK, chaintip))
}

/// Get chainstate handler.
#[utoipa::path(
    get,
    operation_id = "getChainstateAtHeight",
    path = "/chainstate/{height}",
    params(
        ("height" = u64, Path, description = "Height of the blockchain data to receive."),
    ),
    tag = "chainstate",
    responses(
        (status = 200, description = "Chainstate retrieved successfully", body = Chainstate),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn get_chainstate_at_height(
    Extension(context): Extension<EmilyContext>,
    UrlPath(height): UrlPath<u64>,
) -> Result<(StatusCode, Chainstate), Error> {
    debug!("Attempting to get chainstate at height: {height:?}");
    // Get chainstate at height.
    let chainstate: Chainstate = accessors::get_chainstate_entry_at_height(&context, &height)
        .await?
        .into();
    Ok((StatusCode::OK, chainstate))
}

/// Set chainstate handler.
#[utoipa::path(
    post,
    operation_id = "setChainstate",
    path = "/chainstate",
    tag = "chainstate",
    request_body = Chainstate,
    responses(
        (status = 201, description = "Chainstate updated successfully", body = Chainstate),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn set_chainstate(
    Extension(context): Extension<EmilyContext>,
    Json(chainstate): Json<Chainstate>,
) -> Result<(StatusCode, Chainstate), Error> {
    debug!("Attempting to set chainstate: {chainstate:?}");
    add_chainstate_entry_or_reorg(&context, &chainstate)
        .await
        .inspect_err(|error| warn!("Failed to set chainstate with error: {error}"))?;
    Ok((StatusCode::CREATED, chainstate))
}

/// Update chainstate handler.
#[utoipa::path(
    put,
    operation_id = "updateChainstate",
    path = "/chainstate",
    tag = "chainstate",
    request_body = Chainstate,
    responses(
        (status = 201, description = "Chainstate updated successfully", body = Chainstate),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn update_chainstate(
    Extension(context): Extension<EmilyContext>,
    Json(chainstate): Json<Chainstate>,
) -> Result<(StatusCode, Chainstate), Error> {
    debug!("Attempting to update chainstate: {chainstate:?}");
    add_chainstate_entry_or_reorg(&context, &chainstate).await?;
    Ok((StatusCode::CREATED, chainstate))
}

/// Adds the chainstate to the table, and reorganizes the API if there's a
/// conflict that suggests it needs a reorg in order for this entry to be
/// consistent.
///
/// TODO(TBD): Consider moving this logic into database accessor structures.
pub async fn add_chainstate_entry_or_reorg(
    context: &EmilyContext,
    chainstate: &Chainstate,
) -> Result<(), Error> {
    // We don't want to reorg when given an old chainstate, because it is
    // unlikely that an actual reorg has taken place. It's much more likely
    // that something else is going on instead, such as Emily being connected
    // to a stacks node that has not fully synced with the canonical
    // stacks blockchain.
    let new_bitcoin_tip_height = chainstate.bitcoin_block_height;
    let current_bitcoin_tip_height = accessors::get_api_state(context)
        .await?
        .chaintip()
        .bitcoin_height;

    if let (Some(current_bitcoin_tip_height), Some(new_bitcoin_tip_height)) =
        (current_bitcoin_tip_height, new_bitcoin_tip_height)
        && new_bitcoin_tip_height < current_bitcoin_tip_height.saturating_sub(NO_REORG_DEPTH)
    {
        tracing::warn!(
            %new_bitcoin_tip_height,
            %current_bitcoin_tip_height,
            "Will not add chainstate with bitcoin tip height that is too old from the current bitcoin tip height"
        );
        return Ok(());
    }

    // Get chainstate as entry.
    let entry: ChainstateEntry = chainstate.clone().into();
    debug!("Attempting to add chainstate: {entry:?}");
    match accessors::add_chainstate_entry_with_retry(context, &entry, 15).await {
        Err(Error::InconsistentState(Inconsistency::Chainstates(conflicting_chainstates))) => {
            info!("Inconsistent chainstate found; attempting reorg for {entry:?}");
            let execute_reorg_request = ExecuteReorgRequest {
                canonical_tip: chainstate.clone(),
                conflicting_chainstates,
            };

            // Execute the reorg.
            execute_reorg_handler(context, execute_reorg_request)
                .await
                .inspect_err(|error| warn!(%error, "Failed executing reorg"))?;
        }
        e @ Err(_) => return e,
        _ => {}
    };
    // Return.
    Ok(())
}

// TODO(393): Add handler unit tests.
