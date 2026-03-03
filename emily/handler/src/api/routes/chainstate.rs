//! Route definitions for the chainstate endpoint.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Chainstate routes.
pub fn routes<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
{
    get_chainstate_at_height(context.clone())
        .or(set_chainstate(context.clone()))
        .boxed()
        .or(update_chainstate(context.clone()))
        .boxed()
        .or(get_chain_tip(context))
        .boxed()
}

/// Get chain tip endpoint.
fn get_chain_tip<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("chainstate")
        .and(warp::get())
        .and(context)
        .then(handlers::chainstate::get_chain_tip)
}

/// Get chainstate at height endpoint.
fn get_chainstate_at_height<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("chainstate" / u64)
        .and(warp::get())
        .and(context)
        .then(handlers::chainstate::get_chainstate_at_height)
}

/// Set chainstate endpoint.
fn set_chainstate<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("chainstate")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::chainstate::set_chainstate)
}

/// Update chainstate endpoint.
fn update_chainstate<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("chainstate")
        .and(warp::put())
        .and(warp::body::json())
        .and(context)
        .then(handlers::chainstate::update_chainstate)
}

// TODO(387): Add route unit tests.
