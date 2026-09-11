//! Errors returned by the deposit reconciliation service.

use private_emily_client::apis;
use private_emily_client::apis::deposit_api::{GetDepositsError, UpdateDepositsSidecarError};

/// Errors from upstream clients, script validation, and reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An HTTP request or response decoding failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The generated client failed to read Emily deposits.
    #[error("Emily deposit query failed: {0}")]
    EmilyGetDeposits(#[from] apis::Error<GetDepositsError>),

    /// The generated client failed to submit Emily updates.
    #[error("Emily deposit update failed: {0}")]
    EmilyUpdateDeposits(#[from] apis::Error<UpdateDepositsSidecarError>),

    /// The Emily API key could not be encoded as an HTTP header.
    #[error("invalid Emily API key header: {0}")]
    InvalidApiKey(#[from] reqwest::header::InvalidHeaderValue),

    /// An endpoint URL could not be parsed.
    #[error("invalid endpoint URL: {0}")]
    Url(#[from] url::ParseError),

    /// Proposed updates could not be serialized for logging.
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    /// A reclaim script contained invalid hexadecimal data.
    #[error("invalid script hex: {0}")]
    ScriptHex(#[from] bitcoin::hex::HexToBytesError),

    /// A reclaim script failed shared sBTC validation.
    #[error("sBTC validation failed: {0}")]
    Sbtc(#[from] sbtc::error::Error),

    /// Registering or receiving an operating-system signal failed.
    #[error("shutdown signal handling failed: {0}")]
    Signal(#[from] std::io::Error),

    /// The system clock was earlier than the Unix epoch.
    #[error("invalid system time: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    /// Emily returned a continuation token already seen in this query.
    #[error("Emily repeated a pagination token")]
    RepeatedPaginationToken,

    /// A spent output lacked its spending transaction ID or input index.
    #[error("spent output missing spending transaction or input index")]
    IncompleteOutspend,

    /// Electrs identified a spending transaction that the mempool API could not find.
    #[error("spending transaction {0} not found")]
    SpendingTransactionNotFound(String),

    /// The spending input index did not identify an input in the transaction.
    #[error("spending input index {index} is out of bounds for transaction {txid}")]
    SpendingInputOutOfBounds {
        /// Transaction reported to spend the deposit output.
        txid: String,
        /// Input index reported by Electrs.
        index: usize,
    },

    /// Some deposits were skipped because their reconciliation failed.
    #[error("one or more deposits could not be reconciled")]
    IncompleteReconciliation,

    /// Emily returned a different number of results than submitted updates.
    #[error("Emily returned {actual} update results; expected {expected}")]
    UnexpectedUpdateCount {
        /// Number of updates submitted to Emily.
        expected: usize,
        /// Number of per-deposit results returned by Emily.
        actual: usize,
    },

    /// Emily rejected at least one update in a batch.
    #[error("Emily rejected one or more deposit updates")]
    DepositUpdatesRejected,
}
