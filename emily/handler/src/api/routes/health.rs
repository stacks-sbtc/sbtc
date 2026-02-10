//! Route definitions for the health endpoint.

use crate::context::EmilyContext;

use super::handlers;
use warp::Filter;

/// Health routes.
pub fn routes<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    get_health(context)
}

/// Get health endpoint.
fn get_health<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path("health")
        .and(warp::get())
        .and(context)
        .then(handlers::health::get_health)
}

// TODO(387): Add route unit tests.
