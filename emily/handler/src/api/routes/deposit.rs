//! Route definitions for the deposit endpoint.
use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Deposit routes.
pub fn routes<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    get_deposit(context.clone())
        .or(get_deposits_for_transaction(context.clone()))
        .or(get_deposits(context.clone()))
        .or(get_deposits_for_recipient(context.clone()))
        .or(get_deposits_for_reclaim_pubkeys(context.clone()))
        .or(create_deposit(context.clone()))
        .or(update_deposits_sidecar(context.clone()))
        .or(update_deposits_signer(context))
}

/// Get deposit endpoint.
fn get_deposit<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("deposit" / String / u32)
        .and(warp::get())
        .and(context)
        .then(handlers::deposit::get_deposit)
}

/// Get deposits for transaction endpoint.
fn get_deposits_for_transaction<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("deposit" / String)
        .and(warp::get())
        .and(warp::query())
        .and(context)
        .then(handlers::deposit::get_deposits_for_transaction)
}

/// Get deposits endpoint.
fn get_deposits<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("deposit")
        .and(warp::get())
        .and(warp::query())
        .and(context)
        .then(handlers::deposit::get_deposits)
}

/// Get deposits for recipient endpoint.
fn get_deposits_for_recipient<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("deposit" / "recipient" / String)
        .and(warp::get())
        .and(warp::query())
        .and(context)
        .then(handlers::deposit::get_deposits_for_recipient)
}

/// Get deposits for reclaim pubkey endpoint.
fn get_deposits_for_reclaim_pubkeys<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("deposit" / "reclaim-pubkeys" / String)
        .and(warp::get())
        .and(warp::query())
        .and(context)
        .then(handlers::deposit::get_deposits_for_reclaim_pubkeys)
}

/// Create deposit endpoint.
fn create_deposit<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("deposit")
        .and(warp::post())
        .and(warp::body::json())
        .and(context)
        .then(handlers::deposit::create_deposit)
}

/// Update deposits from signer endpoint.
fn update_deposits_signer<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("deposit")
        .and(warp::put())
        .and(warp::body::json())
        .and(context)
        .then(handlers::deposit::update_deposits_signer)
}

/// Update deposits from sidecar endpoint.
fn update_deposits_sidecar<F>(
    context: F,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
where
    F: Filter<Extract = (EmilyContext,), Error = std::convert::Infallible> + Clone + Send,
{
    warp::path!("deposit_private")
        .and(warp::put())
        .and(warp::body::json())
        .and(context)
        .then(handlers::deposit::update_deposits_sidecar)
}

// TODO(387): Add route unit tests.
