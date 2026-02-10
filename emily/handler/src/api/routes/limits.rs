//! Route definitions for the limits endpoint.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Limits routes.
pub fn routes<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    get_limits(context.clone())
        .or(set_limits(context.clone()))
        .or(set_limits_for_account(context.clone()))
        .or(get_limits_for_account(context))
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

/// Endpoint to set the limits for a specific account.
fn set_limits_for_account<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("limits" / String)
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::limits::set_limits_for_account)
}

/// Endpoint to get the limits for a specific account.
fn get_limits_for_account<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("limits" / String)
        .and(warp::get())
        .and(context)
        .then(handlers::limits::get_limits_for_account)
}
