//! Error type for the `devenv-setup` binary.

use aws_sdk_dynamodb::error::BuildError;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::create_table::CreateTableError;
use aws_sdk_dynamodb::operation::list_tables::ListTablesError;

/// Errors returned by the various subcommands.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Bitcoin RPC failure.
    #[error("bitcoin RPC error: {0}")]
    BitcoinRpc(#[from] bitcoincore_rpc::Error),
    /// No bitcoin UTXOs available to fund the donation.
    #[error("no available UTXOs")]
    NoAvailableUtxos,
    /// Failed to issue or read a Stacks RPC request.
    #[error("Stacks RPC error: {0}")]
    StacksRpc(#[from] reqwest::Error),
    /// Failed to assemble the Stacks RPC URL.
    #[error("invalid Stacks RPC URL: {0}")]
    StacksUrl(#[from] url::ParseError),
    /// Hex-decoding the Clarity buffer payload failed.
    #[error("invalid hex from Stacks node: {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// The Clarity buffer payload returned by the Stacks node did not match
    /// what we expect for the `current-aggregate-pubkey` data var.
    #[error("unexpected Clarity value for current-aggregate-pubkey")]
    UnexpectedClarityValue,
    /// The decoded buffer was not a valid secp256k1 public key.
    #[error("invalid secp256k1 public key: {0}")]
    InvalidPublicKey(#[from] secp256k1::Error),
    /// Failure reading the input CDK template from disk.
    #[error("failed to read CDK template {path}: {source}")]
    ReadTemplate {
        /// Path that failed to open.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Failure decoding JSON.
    #[error("failed to parse CDK template JSON: {0}")]
    ParseTemplate(#[from] serde_json::Error),
    /// Failure writing the readiness sentinel file.
    #[error("failed to write ready sentinel {path}: {source}")]
    WriteReadyFile {
        /// Path we tried to write.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Unexpected shape in the CDK template (missing fields, wrong types).
    #[error("malformed CDK template: {0}")]
    MalformedTemplate(String),
    /// DynamoDB ListTables failed.
    #[error("dynamodb list-tables failed: {0}")]
    DynamoList(#[from] Box<SdkError<ListTablesError>>),
    /// DynamoDB CreateTable failed.
    #[error("dynamodb create-table failed for {table}: {source}")]
    DynamoCreate {
        /// Table we tried to create.
        table: String,
        /// Underlying SDK error.
        #[source]
        source: Box<SdkError<CreateTableError>>,
    },
    /// Failure assembling a DynamoDB request from the template (e.g. an
    /// AttributeDefinition or KeySchemaElement that the SDK builder rejected).
    #[error("dynamodb build error: {0}")]
    DynamoBuild(#[from] BuildError),
}
