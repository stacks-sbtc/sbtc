//! Route definitions for the testing endpoint.
use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Testing routes
pub fn routes<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    wipe_databases(context)
}

/// Wipe databases
fn wipe_databases<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    context
        .and(warp::path!("testing" / "wipe"))
        .and(warp::post())
        .then(handlers::testing::wipe_databases)
}
