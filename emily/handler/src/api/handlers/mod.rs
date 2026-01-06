//! Handlers for the emily API

/// Chainstate handlers.
pub mod chainstate;
/// Deposit handlers.
pub mod deposit;
/// Health handlers.
pub mod health;
/// Internal handlers.
pub mod internal;
/// Limit handlers.
pub mod limits;
/// New block handlers.
pub mod new_block;
/// Testing handlers.
#[cfg(feature = "testing")]
pub mod testing;
/// Withdrawal handlers.
pub mod withdrawal;
