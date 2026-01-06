//! Route definitions for the Emily API.

use std::time::Duration;

use crate::context::EmilyContext;

use super::handlers;
use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::routing::put;
use tracing::Span;


use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use axum::routing::post;

use crate::api::handlers::chainstate2;
use crate::api::handlers::deposit2;
use crate::api::handlers::health2;
use crate::api::handlers::limits2;
use crate::api::handlers::new_block2;
#[cfg(feature = "testing")]
use crate::api::handlers::testing2;
use crate::api::handlers::withdrawal2;

/// Chainstate routes.
mod chainstate;
/// Deposit routes.
mod deposit;
/// Health routes.
mod health;
/// Limit routes.
mod limits;
/// NewBlock routes.
mod new_block;
/// Testing routes.
#[cfg(feature = "testing")]
mod testing;
/// Withdrawal routes.
mod withdrawal;

/// Maximum request body size for the event observer endpoint.
///
/// Stacks blocks have a limit of 2 MB, which is enforced at the p2p level, but
/// event observer events can be larger than that since they contain the
/// subscribed sbtc events. Luckily, the size of the sbtc events themselves are
/// bounded by the size of the transactions that create them, so a limit of 8 MB
/// will be fine since it is twice as high as required.
pub const EVENT_OBSERVER_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// This function logs the response from an Axum route.
pub fn axum_log_response(response: &Response<Body>, duration: Duration, _: &Span) {
    tracing::debug!(
        event = "response",
        status = response.status().as_u16(),
        body = ?response.body(),
        headers = ?response.headers(),
        duration_ms = duration.as_millis()
    );
}

/// This function sets up the Axum routes for handling all requests.
pub fn routes_axum() -> Router<EmilyContext> {
    let get_chainstate_at_height = get(chainstate2::get_chainstate_at_height);
    let get_deposits_for_transaction = get(deposit2::get_deposits_for_transaction);
    let get_withdrawals_for_recipient = get(withdrawal2::get_withdrawals_for_recipient);
    let get_withdrawals_for_sender = get(withdrawal2::get_withdrawals_for_sender);
    let new_block =
        post(new_block2::new_block).layer(DefaultBodyLimit::max(EVENT_OBSERVER_BODY_LIMIT));
    let put_withdrawals_sidecar = put(withdrawal2::update_withdrawals_sidecar);

    let mut router = Router::new();

    #[cfg(feature = "testing")]
    {
        router = router.route("/testing/wipe", post(testing2::wipe_databases));
    }

    router
        .route("/health", get(health2::get_health))
        .route("/chainstate", get(chainstate2::get_chain_tip))
        .route("/chainstate/{height}", get_chainstate_at_height)
        .route("/chainstate", post(chainstate2::set_chainstate))
        .route("/chainstate", put(chainstate2::update_chainstate))
        .route("/deposit", get(deposit2::get_deposits))
        .route("/deposit", post(deposit2::create_deposit))
        .route("/deposit", put(deposit2::update_deposits_signer))
        .route("/deposit_private", put(deposit2::update_deposits_sidecar))
        .route("/deposit/{txid}", get_deposits_for_transaction)
        .route("/deposit/{txid}/{index}", get(deposit2::get_deposit))
        .route("/withdrawal", get(withdrawal2::get_withdrawals))
        .route("/withdrawal", post(withdrawal2::create_withdrawal))
        .route("/withdrawal", put(withdrawal2::update_withdrawals_signer))
        .route("/withdrawal_private", put_withdrawals_sidecar)
        .route("/withdrawal/{id}", get(withdrawal2::get_withdrawal))
        .route("/withdrawal/recipient/{r}", get_withdrawals_for_recipient)
        .route("/withdrawal/sender/{s}", get_withdrawals_for_sender)
        .route("/limits", get(limits2::get_limits))
        .route("/limits", post(limits2::set_limits))
        .route("/limits/{account}", get(limits2::get_limits_for_account))
        .route("/limits/{account}", post(limits2::set_limits_for_account))
        .route("/new_block", new_block)
}


/// Inject the request context into the request.
pub async fn inject_request_context(
    State(mut context): State<EmilyContext>,
    mut req: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {

    #[cfg(feature = "testing")]
    {
        let headers = req.headers();
        let get_header = |key| {
            headers
                .get(key)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };

        if let Some(h) = get_header("x-context-deposit") {
            context.settings.deposit_table_name = h;
        }
        if let Some(h) = get_header("x-context-withdrawal") {
            context.settings.withdrawal_table_name = h;
        }
        if let Some(h) = get_header("x-context-chainstate") {
            context.settings.chainstate_table_name = h;
        }
        if let Some(h) = get_header("x-context-limit") {
            context.settings.limit_table_name = h;
        }
        if let Some(h) = get_header("x-context-version") {
            context.settings.version = h;
        }
    }

    req.extensions_mut().insert(context);

    next.run(req).await
}
