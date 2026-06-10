//! Error type for the `devenv-setup` binary.
//!
//! One flat enum across all subcommands. The variants are grouped below by
//! the subsystem they come from: bitcoin RPC, Stacks RPC, CDK template I/O,
//! and DynamoDB.

use aws_sdk_dynamodb::error::BuildError;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::create_table::CreateTableError;
use aws_sdk_dynamodb::operation::list_tables::ListTablesError;

/// Errors returned by the various subcommands.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A bitcoin-core RPC call failed.
    #[error("bitcoin RPC error: {0}")]
    BitcoinRpc(#[from] bitcoincore_rpc::Error),
    /// `listunspent` returned no UTXO large enough to cover the donation
    /// plus the flat fee. In devenv this generally means the miner script
    /// hasn't topped up the depositor wallet yet.
    #[error("no available UTXOs")]
    NoAvailableUtxos,
    /// HTTP-level failure issuing or reading a Stacks RPC request.
    #[error("Stacks RPC error: {0}")]
    StacksRpc(#[from] reqwest::Error),
    /// The Stacks RPC base URL didn't join with the data-var path.
    #[error("invalid Stacks RPC URL: {0}")]
    StacksUrl(#[from] url::ParseError),
    /// The `data` field returned by the Stacks node wasn't valid hex.
    #[error("invalid hex from Stacks node: {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// The decoded Clarity value didn't match the buffer shape we expect
    /// for `current-aggregate-pubkey`.
    #[error("unexpected Clarity value for current-aggregate-pubkey")]
    UnexpectedClarityValue,
    /// The decoded buffer payload wasn't a valid secp256k1 public key.
    #[error("invalid secp256k1 public key: {0}")]
    InvalidPublicKey(#[from] secp256k1::Error),
    /// Could not open the CDK template at the given path.
    #[error("failed to read CDK template {0}: {source}", path.display())]
    ReadTemplate {
        /// The path that failed to open.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The CDK template wasn't valid JSON.
    #[error("failed to parse CDK template JSON: {0}")]
    ParseTemplate(#[from] serde_json::Error),
    /// The template parsed as JSON but had an unexpected shape (missing
    /// fields, unsupported enum string, etc.).
    #[error("malformed CDK template: {0}")]
    MalformedTemplate(String),
    /// Could not write the readiness sentinel that the docker healthcheck
    /// watches.
    #[error("failed to write ready sentinel {0}: {source}", path.display())]
    WriteReadyFile {
        /// Path we tried to write.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `ListTables` failed (network or DynamoDB-side error).
    #[error("dynamodb list-tables failed: {0}")]
    DynamoList(#[from] Box<SdkError<ListTablesError>>),
    /// `CreateTable` failed for a specific table.
    #[error("dynamodb create-table failed for {table}: {source}")]
    DynamoCreate {
        /// The table we tried to create.
        table: String,
        /// The underlying SDK error.
        #[source]
        source: Box<SdkError<CreateTableError>>,
    },
    /// One of the AWS SDK builders rejected the data we passed in. This
    /// almost always means the CDK template has fields we haven't taught
    /// the mapper about.
    #[error("dynamodb build error: {0}")]
    DynamoBuild(#[from] BuildError),
}
