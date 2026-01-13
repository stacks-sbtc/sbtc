//! Route definitions for the new_block endpoint.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// New block routes.
pub fn routes<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    new_block(context)
}

/// New block endpoint.
fn new_block<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("new_block")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::new_block::new_block)
}
