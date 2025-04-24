//! Top-level error type for the Blocklist client

use std::env;

use aws_sdk_dynamodb::{
    error::SdkError,
    operation::{
        batch_write_item::BatchWriteItemError, delete_item::DeleteItemError,
        get_item::GetItemError, put_item::PutItemError, query::QueryError, scan::ScanError,
        update_item::UpdateItemError,
    },
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use warp::{reject::Reject, reply::Reply};

use crate::{
    api::models::chainstate::Chainstate,
    database::entries::{
        chainstate::ChainstateEntry, deposit::DepositEntryKey, withdrawal::WithdrawalEntryKey,
    },
};

/// State inconsistency representations.
#[derive(Debug)]
pub enum Inconsistency {
    /// There is a chainstate inconsistency, and all the chainstates
    /// in the vector are the chainstates that are present in the API
    /// but are not known to be correct. All chainstates in the vector
    /// are considered equally canonical.
    Chainstates(Vec<Chainstate>),
    /// There is an inconsistency in the way an item is being updated.
    ItemUpdate(String),
}

/// Errors from the internal API logic.
#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    /// The withdrawal is confirmed but missing the fulfillment data.
    #[error("missing fulfillment for confirmed withdrawal request with id: {0}")]
    WithdrawalMissingFulfillment(u64),
    /// The withdrawals are confirmed but missing the fulfillment data.
    #[error("missing fulfillment for confirmed withdrawals requests with ids: {0:?}")]
    WithdrawalsMissingFulfillment(Vec<u64>),

    /// The deposit is confirmed but missing the fulfillment data.
    #[error("missing fulfillment for confirmed deposit request with txid: {0}, vout: {1}")]
    DepositMissingFulfillment(String, u32),
    /// The deposits are confirmed but missing the fulfillment data.
    #[error("missing fulfillment for confirmed deposit requests with txid:vout pairs: {0:?}")]
    DepositsMissingFulfillment(Vec<String>),

    /// One of rolling_withdrawal_blocks or rolling_withdrawal_cap is missing while the other is set.
    /// Fields must be provided together to configure withdrawal limits.
    #[error(
        "incomplete withdrawal limit configuration: rolling_withdrawal_blocks and rolling_withdrawal_cap must be provided together"
    )]
    IncompleteWithdrawalLimitConfig,
}

/// Errors from the internal API logic.
#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The request was unacceptable. This may refer to a missing or improperly formatted parameter
    /// or request body property, or non-valid JSON
    #[error("HTTP request failed with status code {0}: {1}")]
    HttpRequest(StatusCode, String),

    /// Network error
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// You do not have permission to access or perform the requested action
    #[error("Forbidden")]
    Forbidden,

    /// This may be because you either requested a nonexistent endpoint
    /// or referenced a user that does not exist
    #[error("Resource not found")]
    NotFound,

    /// Internal error
    #[error("Internal server error")]
    InternalServer,

    /// Debug error.
    #[error("Debug error: {0}")]
    Debug(String),

    /// Internal too many retries error.
    #[error("Too many internal retries")]
    TooManyInternalRetries,

    /// Inconsistent API state detected during request
    #[error("Inconsistent internal state: {0:?}")]
    InconsistentState(Inconsistency),

    /// API is reorganizing.
    #[error("the API is reorganizing around new chain tip {0:?}")]
    Reorganizing(Chainstate),

    /// An entry update version conflict in a resource update resulted
    /// in an update not being performed.
    #[error("there was a conflict when attempting to update the database")]
    VersionConflict,

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// This happens if the deposit entry that was stored in the database
    /// was invalid, or if the deposit entry that we are creating to store
    /// in the database is invalid.
    #[error("deposit entry failed validation; {0}; ID: {1}")]
    DepositEntry(&'static str, DepositEntryKey),

    /// This happens if the withdrawal entry that was stored in the database
    /// was invalid, or if the withdrawal entry that we are creating to store
    /// in the database is invalid.
    #[error("withdrawal entry failed validation; {0}; ID: {1}")]
    WithdrawalEntry(&'static str, WithdrawalEntryKey),

    /// This happens when we fail to build a request object when trying to
    /// interact with DynamoDB. For example, when deleting entries in the
    /// database in our tests, we build a request object and that operation
    /// may fail with this error.
    #[cfg(feature = "testing")]
    #[error("{0}")]
    DynamoDbBuild(#[from] aws_sdk_dynamodb::error::BuildError),

    /// This happens when we fail to decode a base64 encoded string into a
    /// vector of bytes.
    #[error("failed to base64 decode the string into bytes; {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// This is used when trying to get a required value from the
    /// environment and that operation fails.
    #[error("could not read the environment variable; {0}")]
    EnvVariable(#[from] env::VarError),

    /// This occurs when serializing or deserializing an object into or
    /// from JSON.
    #[error("{0}")]
    SerdeJson(#[from] serde_json::Error),

    /// This occurs when converting structs to and from DynamoDB objects.
    #[error("{0}")]
    SerdeDynamo(#[from] serde_dynamo::Error),

    /// This happens when attempting to parse an integer from a string that
    /// has been read from an environment variable.
    #[error("could not parse the string into an integer; {0}")]
    EnvParseInt(#[from] std::num::ParseIntError),

    /// This happens when attempting to read an item from DynamoDB.
    #[error("could not retrieve an item from DynamoDB; {0}")]
    AwsSdkDynamoDbGetItem(#[from] SdkError<GetItemError>),

    /// This happens when attempting to store an item in DynamoDB. Note
    /// that precondition checks that occur when putting an item into
    /// DynamoDB are transformed into the `VersionConflict` error variant.
    #[error("could not put the item into DynamoDB; {0}")]
    AwsSdkDynamoDbPutItem(#[source] PutItemError),

    /// This happens when attempting the "Query" operation in DynamoDB.
    #[error("could complete Query operation on DynamoDB; {0}")]
    AwsSdkDynamoDbQuery(#[from] SdkError<QueryError>),

    /// This happens when attempting to delete an item in the database.
    #[cfg(feature = "testing")]
    #[error("{0}")]
    AwsSdkDynamoDbDeleteItem(#[source] DeleteItemError),

    /// This happens when attempting the "Scan" operation in DynamoDB.
    #[error("could complete Scan operation on DynamoDB; {0}")]
    AwsSdkDynamoDbScan(#[from] SdkError<ScanError>),

    /// This happens during the BatchWrite operation on DynamoDB.
    #[cfg(feature = "testing")]
    #[error("{0}")]
    AwsSdkDynamoDbBatchWriteItem(#[from] SdkError<BatchWriteItemError>),

    /// This happens when attempting to update a stored item in DynamoDB.
    #[error("could not update the item in DynamoDB; {0}")]
    AwsSdkDynamoDbUpdateItem(#[source] UpdateItemError),
}

/// Error implementation.
impl Error {
    /// Provides the status code that corresponds to the error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::HttpRequest(code, _) => *code,
            Error::Network(_) => StatusCode::BAD_GATEWAY,
            Error::Forbidden => StatusCode::FORBIDDEN,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Debug(_) => StatusCode::IM_A_TEAPOT,
            Error::TooManyInternalRetries => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InconsistentState(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Reorganizing(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::VersionConflict => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Deserialization(_) => StatusCode::BAD_REQUEST,
            Error::DepositEntry(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::WithdrawalEntry(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::DynamoDbBuild(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Base64Decode(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::EnvVariable(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::SerdeJson(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::SerdeDynamo(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::EnvParseInt(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbGetItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbPutItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbQuery(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbDeleteItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbScan(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbBatchWriteItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbUpdateItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    /// Converts the error into a warp response.
    pub fn into_response(self) -> warp::reply::Response {
        warp::reply::with_status(
            warp::reply::json(&ErrorResponse { message: format!("{self:?}") }),
            self.status_code(),
        )
        .into_response()
    }
    /// Convert error into a presentable version of the error that can be
    /// provided to a client in production.
    ///
    /// TODO(131): Scrutinize the outputs of the error messages to ensure they're
    /// production ready.
    pub fn into_production_error(self) -> Error {
        match self {
            Error::Debug(_)
            | Error::Network(_)
            | Error::VersionConflict
            | Error::Reorganizing(_)
            | Error::Base64Decode(_)
            | Error::EnvVariable(_)
            | Error::SerdeJson(_)
            | Error::SerdeDynamo(_)
            | Error::EnvParseInt(_)
            | Error::DepositEntry(_, _)
            | Error::WithdrawalEntry(_, _)
            | Error::DynamoDbBuild(_)
            | Error::AwsSdkDynamoDbGetItem(_)
            | Error::AwsSdkDynamoDbPutItem(_)
            | Error::AwsSdkDynamoDbQuery(_)
            | Error::AwsSdkDynamoDbDeleteItem(_)
            | Error::AwsSdkDynamoDbScan(_)
            | Error::AwsSdkDynamoDbBatchWriteItem(_)
            | Error::AwsSdkDynamoDbUpdateItem(_)
            | Error::InternalServer => Error::InternalServer,
            err => err,
        }
    }
    /// Makes an inconsistency error from a vector of chainstate entries.
    pub fn from_inconsistent_chainstate_entries(entries: Vec<ChainstateEntry>) -> Self {
        Error::InconsistentState(Inconsistency::Chainstates(
            entries.into_iter().map(|entry| entry.into()).collect(),
        ))
    }
    /// Makes an inconsistency error from a single chainstate entry.
    pub fn from_inconsistent_chainstate_entry(entry: ChainstateEntry) -> Self {
        Error::InconsistentState(Inconsistency::Chainstates(vec![entry.into()]))
    }
}

/// TODO(391): Route errors to the appropriate Emily API error.
///
/// Implement from for API Errors.
impl From<ValidationError> for Error {
    fn from(err: ValidationError) -> Self {
        Error::HttpRequest(StatusCode::BAD_REQUEST, err.to_string())
    }
}

impl From<SdkError<PutItemError>> for Error {
    fn from(err: SdkError<PutItemError>) -> Self {
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            PutItemError::ConditionalCheckFailedException(_) => Error::VersionConflict,
            service_err => Error::AwsSdkDynamoDbPutItem(service_err),
        }
    }
}

impl From<SdkError<DeleteItemError>> for Error {
    fn from(err: SdkError<DeleteItemError>) -> Self {
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            DeleteItemError::ConditionalCheckFailedException(_) => Error::VersionConflict,
            service_err => Error::AwsSdkDynamoDbDeleteItem(service_err),
        }
    }
}

impl From<SdkError<UpdateItemError>> for Error {
    fn from(err: SdkError<UpdateItemError>) -> Self {
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            UpdateItemError::ConditionalCheckFailedException(_) => Error::VersionConflict,
            service_err => Error::AwsSdkDynamoDbUpdateItem(service_err),
        }
    }
}

/// Structure representing an error response
/// This is used to serialize error messages in HTTP responses
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub(crate) message: String,
}

/// Implement reject for error.
impl Reject for Error {}

/// Implement reply for internal error representation so that the error can be
/// provided directly from Warp as a reply.
impl Reply for Error {
    /// Convert self into a warp response.
    #[cfg(not(feature = "testing"))]
    fn into_response(self: Error) -> warp::reply::Response {
        self.into_production_error().into_response()
    }
    /// Convert self into a warp response.
    #[cfg(feature = "testing")]
    fn into_response(self) -> warp::reply::Response {
        self.into_response()
    }
}
