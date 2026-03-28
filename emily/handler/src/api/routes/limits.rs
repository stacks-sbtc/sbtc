//! Route definitions for the limits endpoint.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Limits routes.
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
    get_limits(context.clone())
        .or(set_limits(context.clone()))
        .boxed()
}

/// Get limits endpoint.
fn get_limits<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("limits")
        .and(warp::get())
        .and(context)
        .then(handlers::limits::get_limits)
}

/// Set limits endpoint.
fn set_limits<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("limits")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::limits::set_limits)
}
