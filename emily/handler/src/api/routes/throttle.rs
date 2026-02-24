//! Route definitions for the throttle endpoints.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Throttle routes.
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
    add_throttle_key(context.clone())
        .or(get_throttle_key(context.clone()))
        .boxed()
        .or(activate_throttle_key(context.clone()))
        .boxed()
        .or(deactivate_throttle_key(context.clone()))
        .boxed()
        .or(start_throttle(context.clone()))
        .boxed()
        .or(stop_throttle(context))
        .boxed()
}

/// Stop throttle endpoint.
fn stop_throttle<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("throttle" / "stop")
        .and(warp::post())
        .and(context)
        .then(handlers::throttle::stop_throttle)
}

/// Get throttle key endpoint.
fn get_throttle_key<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("throttle")
        .and(warp::get())
        .and(warp::body::json())
        .and(context)
        .then(handlers::throttle::get_throttle_key)
}

/// Add throttle key endpoint.
fn add_throttle_key<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("throttle")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::throttle::add_throttle_key)
}

/// Endpoint to start throttle.
fn start_throttle<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("start_throttle")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::throttle::start_throttle)
}

/// Endpoint to activate existing key.
fn activate_throttle_key<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("throttle" / "activate")
        .and(warp::patch())
        .and(warp::body::json())
        .and(context)
        .then(handlers::throttle::activate_throttle_key)
}

/// Endpoint to deactivate existing key.
fn deactivate_throttle_key<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("throttle" / "deactivate")
        .and(warp::patch())
        .and(warp::body::json())
        .and(context)
        .then(handlers::throttle::deactivate_throttle_key)
}
