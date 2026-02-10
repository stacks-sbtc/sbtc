//! Route definitions for the slowdown endpoints.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Slowdown routes.
pub fn routes<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    add_slowdown_key(context.clone())
        .or(get_slowdown_key(context.clone()))
        .or(activate_slowdown_key(context.clone()))
        .or(deactivate_slowdown_key(context.clone()))
        .or(start_slowdown(context))
}

/// Get slowdown key endpoint.
fn get_slowdown_key<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("slowdown")
        .and(warp::get())
        .and(warp::body::json())
        .and(context)
        .then(handlers::slowdown::get_slowdown_key)
}

/// Add slowdown key endpoint.
fn add_slowdown_key<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("slowdown")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::slowdown::add_slowdown_key)
}

/// Endpoint to start slowdown.
fn start_slowdown<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("start_slowdown")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::slowdown::start_slowdown)
}

/// Endpoint to activate existing key.
fn activate_slowdown_key<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("slowdown" / "activate" / String)
        .and(warp::patch())
        .and(context)
        .then(handlers::slowdown::activate_slowdown_key)
}

/// Endpoint to deactivate existing key.
fn deactivate_slowdown_key<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("slowdown" / "deactivate" / String)
        .and(warp::patch())
        .and(context)
        .then(handlers::slowdown::deactivate_slowdown_key)
}
