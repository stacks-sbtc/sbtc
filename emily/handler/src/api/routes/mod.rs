//! Route definitions for the Emily API.

#[cfg(feature = "testing")]
use std::convert::Infallible;
use std::time::Duration;

use crate::context::EmilyContext;

use super::handlers;
use axum::body::Body;
use axum::response::Response;
use axum::routing::put;
use tracing::Span;
use tracing::debug;
use warp::Filter;
#[cfg(feature = "testing")]
use warp::http::HeaderMap;

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

// Filter that will print the response to the logs if set to debug.
fn log_response<T>(reply: T) -> (impl warp::Reply,)
where
    T: warp::Reply,
{
    let as_response = reply.into_response();
    tracing::debug!(
        event = "response",
        status = as_response.status().as_u16(),
        body = ?as_response.body(),
        headers = ?as_response.headers(),
    );
    (as_response,)
}

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

/// This function sets up the Warp filters for handling all requests.
#[cfg(feature = "testing")]
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let context = with_context(context);

    // `.boxed()` erases the deeply nested filter type from multiple `.or()` calls,
    // making the return type manageable and preventing compilation errors and runtime stack overflows.
    health::routes(context.clone())
        .or(new_block::routes(context.clone()))
        .boxed()
        .or(chainstate::routes(context.clone()))
        .boxed()
        .or(deposit::routes(context.clone()))
        .boxed()
        .or(withdrawal::routes(context.clone()))
        .boxed()
        .or(limits::routes(context.clone()))
        .boxed()
        .or(testing::routes(context))
        .boxed()
        .or(verbose_not_found_route())
        .boxed()
        // Convert reply to tuple to that more routes can be added to the returned filter.
        .map(|reply| (reply,))
        .map(log_response)
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

    let mut router = Router::new()
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
        .route("/new_block", new_block);

    #[cfg(feature = "testing")]
    {
        router = router.route("/testing/wipe", post(testing2::wipe_databases));
    }

    router
}

/// This function sets the Warp filters for handling all requests.
#[cfg(not(feature = "testing"))]
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let context = warp::any().map(move || context.clone());

    health::routes(context.clone())
        .or(new_block::routes(context.clone()))
        .boxed()
        .or(chainstate::routes(context.clone()))
        .boxed()
        .or(deposit::routes(context.clone()))
        .boxed()
        .or(withdrawal::routes(context.clone()))
        .boxed()
        .or(limits::routes(context))
        .boxed()
        // Convert reply to tuple to that more routes can be added to the returned filter.
        .map(|reply| (reply,))
        .map(log_response)
}

/// This function sets up the routes expecting the AWS stage to be passed in as the very
/// first segment of the path. AWS does this by default, and it's not something we can
/// change.
pub fn routes_with_stage_prefix(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // Get the AWS Stage name and then ignore it, but print it in the logs if
    // we're in debug mode.
    warp::path::param::<String>()
        .and(routes(context))
        .map(|stage, reply| {
            debug!("AWS stage: {}", stage);
            (reply,)
        })
}

/// A verbose route that will return a 404 with the full path and peeked path.
///
/// This is useful if you called the API and it doesn't recognize the call that was made internally,
/// but APIGateway let it through.
#[cfg(feature = "testing")]
fn verbose_not_found_route()
-> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::get())
        .and(warp::path::full())
        .and(warp::path::peek())
        .map(|full_path, peek_path| {
            warp::reply::with_status(
                format!("Endpoint not found. Full: {full_path:?} | Peek: {peek_path:?}"),
                warp::http::StatusCode::NOT_FOUND,
            )
        })
}

/// A Filter to dynamically change the context when running tests
#[cfg(feature = "testing")]
fn with_context(
    context: EmilyContext,
) -> impl Filter<Extract = (EmilyContext,), Error = Infallible> + Clone {
    warp::header::headers_cloned().map(move |headers: HeaderMap| {
        let mut context = context.clone();

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

        context
    })
}
