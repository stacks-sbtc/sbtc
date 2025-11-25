//! Route definitions for the withdrawal endpoint.
use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Withdrawal routes.
pub fn routes<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    get_withdrawal(context.clone())
        .or(get_withdrawals(context.clone()))
        .or(get_withdrawals_for_recipient(context.clone()))
        .or(get_withdrawals_for_sender(context.clone()))
        .or(create_withdrawal(context.clone()))
        .or(update_withdrawals_sidecar(context.clone()))
        .or(update_withdrawals_signer(context))
}

/// Get withdrawal endpoint.
fn get_withdrawal<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("withdrawal" / u64)
        .and(warp::get())
        .and(context)
        .then(handlers::withdrawal::get_withdrawal)
}

/// Get withdrawals endpoint.
fn get_withdrawals<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path("withdrawal")
        .and(warp::get())
        .and(warp::query())
        .and(context)
        .then(handlers::withdrawal::get_withdrawals)
}

/// Get withdrawals for recipient endpoint.
fn get_withdrawals_for_recipient<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("withdrawal" / "recipient" / String)
        .and(warp::get())
        .and(warp::query())
        .and(context)
        .then(handlers::withdrawal::get_withdrawals_for_recipient)
}

/// Get withdrawals for sender endpoint.
fn get_withdrawals_for_sender<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("withdrawal" / "sender" / String)
        .and(warp::get())
        .and(warp::query())
        .and(context)
        .then(handlers::withdrawal::get_withdrawals_for_sender)
}

/// Create withdrawal endpoint.
fn create_withdrawal<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path("withdrawal")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::withdrawal::create_withdrawal)
}

/// Update withdrawals from signer endpoint.
fn update_withdrawals_signer<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path("withdrawal")
        .and(warp::put())
        .and(warp::body::json())
        .and(context)
        .then(handlers::withdrawal::update_withdrawals_signer)
}

/// Update withdrawals from sidecar endpoint.
fn update_withdrawals_sidecar<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path("withdrawal_private")
        .and(warp::put())
        .and(warp::body::json())
        .and(context)
        .then(handlers::withdrawal::update_withdrawals_sidecar)
}

// TODO(387): Add route unit tests.
