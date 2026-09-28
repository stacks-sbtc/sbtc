//! Errors from upstream APIs, script validation, and reconciliation outcomes.

use private_emily_client::apis;
use private_emily_client::apis::deposit_api::GetDepositsError;
use private_emily_client::apis::deposit_api::UpdateDepositsSidecarError;

/// Failures that stop or partially complete a reconciliation cycle.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An HTTP request or response decoding failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// Emily deposit listing failed (transport, HTTP error, or bad JSON).
    #[error("Emily deposit query failed: {0}")]
    EmilyGetDeposits(#[from] apis::Error<GetDepositsError>),

    /// Emily batch update failed before per-deposit results were available.
    #[error("Emily deposit update failed: {0}")]
    EmilyUpdateDeposits(#[from] apis::Error<UpdateDepositsSidecarError>),

    /// The Emily API key could not be encoded as an HTTP header.
    #[error("invalid Emily API key header: {0}")]
    InvalidApiKey(#[from] reqwest::header::InvalidHeaderValue),

    /// An endpoint URL could not be parsed.
    #[error("invalid endpoint URL: {0}")]
    Url(#[from] url::ParseError),

    /// Proposed updates could not be serialized for dry-run logging.
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    /// A reclaim script contained invalid hexadecimal data.
    #[error("invalid script hex: {0}")]
    ScriptHex(#[from] bitcoin::hex::HexToBytesError),

    /// A reclaim script failed shared sBTC validation rules.
    #[error("sBTC validation failed: {0}")]
    Sbtc(#[from] sbtc::error::Error),

    /// Registering or receiving an operating-system signal failed.
    #[error("shutdown signal handling failed: {0}")]
    Signal(#[from] std::io::Error),

    /// The system clock was earlier than the Unix epoch.
    #[error("invalid system time: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    /// Electrs marked an output spent but omitted the spender txid or vin.
    #[error("spent output missing spending transaction or input index")]
    IncompleteOutspend,

    /// Electrs named a spender that the mempool API could not find.
    #[error("spending transaction {0} not found")]
    SpendingTransactionNotFound(String),

    /// The reported spending vin was outside the transaction's input list.
    #[error("spending input index {index} is out of bounds for transaction {txid}")]
    SpendingInputOutOfBounds {
        /// Transaction reported to spend the deposit output.
        txid: String,
        /// Input index reported by Electrs.
        index: usize,
    },

    /// At least one deposit was skipped because its lookups failed.
    #[error("one or more deposits could not be reconciled")]
    IncompleteReconciliation,

    /// Emily returned a different number of per-deposit results than updates sent.
    #[error("Emily returned {actual} update results; expected {expected}")]
    UnexpectedUpdateCount {
        /// Number of updates submitted in the batch.
        expected: usize,
        /// Number of per-deposit results returned by Emily.
        actual: usize,
    },

    /// Emily rejected at least one update in a submitted batch.
    #[error("Emily rejected one or more deposit updates")]
    DepositUpdatesRejected,
}
