//! `aws-setup` subcommand.
//!
//! In this module, we implement the `aws-setup` subcommand. It reads the
//! CloudFormation template that the Emily CDK app synthesises, picks out
//! the `AWS::DynamoDB::Table` resources, and creates any tables that don't
//! yet exist on DynamoDB.
//!
//! It then creates a sentinel file so that the container's docker
//! healthcheck can flip to "healthy" when the tables are ready.
//!
//! # Notes
//!
//! - We always set `BillingMode::PayPerRequest` when creating tables,
//!   ignoring whatever the template says. DynamoDB-local treats every
//!   billing mode the same.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::str::FromStr as _;

use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_dynamodb::config::BehaviorVersion;
use aws_sdk_dynamodb::config::Credentials;
use aws_sdk_dynamodb::config::Region;
use aws_sdk_dynamodb::types::AttributeDefinition;
use aws_sdk_dynamodb::types::BillingMode;
use aws_sdk_dynamodb::types::GlobalSecondaryIndex;
use aws_sdk_dynamodb::types::KeySchemaElement;
use aws_sdk_dynamodb::types::KeyType;
use aws_sdk_dynamodb::types::Projection;
use aws_sdk_dynamodb::types::ProjectionType;
use aws_sdk_dynamodb::types::ScalarAttributeType;
use clap::Args;
use serde::Deserialize;

use crate::error::Error;

/// The CloudFormation resource type we care about. Other resource types in
/// the template are ignored.
const DYNAMO_TABLE_TYPE: &str = "AWS::DynamoDB::Table";

/// Page size used when paginating `ListTables`. Five tables today.
const LIST_TABLES_PAGE: i32 = 100;

/// Default path to the synthesised CDK template inside the container.
/// Matches where the Dockerfile copies it to.
const DEFAULT_TEMPLATE_PATH: &str = "/code/cdk.out/EmilyStack.template.json";

/// Path to a sentinel file touched once every required dynamodb table
/// exists. The container healthcheck watches this so downstream services
/// can start as soon as the tables are ready.
pub const READY_FILE_PATH: &str = "/tmp/aws-setup-ready";

/// Arguments for the `aws-setup` subcommand.
#[derive(Debug, Args)]
pub struct AwsSetupArgs {
    /// Path to the synthesised CDK template that lists the tables to
    /// create.
    #[clap(
        long = "input-cdk-template-path",
        env = "INPUT_CDK_TEMPLATE_PATH",
        default_value = DEFAULT_TEMPLATE_PATH,
    )]
    pub input_cdk_template_path: PathBuf,
    /// URL of the DynamoDB endpoint to talk to. For the devenv this is the
    /// `emily-dynamodb` service from docker compose.
    #[clap(long = "dynamodb-endpoint", env = "DYNAMODB_ENDPOINT")]
    pub dynamodb_endpoint: String,
    /// AWS region passed to the SDK. Local DynamoDB ignores it but the SDK
    /// refuses to start without one.
    #[clap(long, env = "AWS_REGION", default_value = "us-west-2")]
    pub region: String,
    /// Access key for the DynamoDB endpoint. DynamoDB-local accepts
    /// anything non-empty.
    #[clap(long, env = "AWS_ACCESS_KEY_ID", default_value = "xxxxxxxx")]
    pub access_key_id: String,
    /// Secret key for the DynamoDB endpoint. DynamoDB-local accepts
    /// anything non-empty.
    #[clap(long, env = "AWS_SECRET_ACCESS_KEY", default_value = "xxxxxxxx")]
    pub secret_access_key: String,
}

/// Entry point for the subcommand.
///
/// Order of operations:
/// 1. parse the CDK template,
/// 2. ask DynamoDB which tables already exist,
/// 3. create the missing ones,
/// 4. write the readiness sentinel.
pub async fn run(args: AwsSetupArgs) -> Result<(), Error> {
    let client = build_dynamodb_client(&args).await;
    let existing = list_existing_tables(&client).await?;
    tracing::info!(?existing, "existing dynamodb tables");

    let tables = read_table_definitions(args.input_cdk_template_path)?;
    tracing::info!(count = tables.len(), "tables defined in template");

    for table in tables {
        if existing.contains(&table.table_name) {
            tracing::info!(table = %table.table_name, "table already exists, skipping");
            continue;
        }
        create_table(&client, &table).await?;
        tracing::info!(table = %table.table_name, "created table");
    }

    let path = PathBuf::from_str(READY_FILE_PATH).unwrap();
    File::create(&path).map_err(Error::WriteReadyFile)?;
    tracing::info!(path = %READY_FILE_PATH, "wrote aws-setup ready sentinel");
    Ok(())
}

// =============================================================================
//  CDK template parsing
// =============================================================================

/// Read the CDK template from disk and pull out the
/// `AWS::DynamoDB::Table` resources, deserialising their `Properties` into
/// [`TableProperties`].
fn read_table_definitions(path: PathBuf) -> Result<Vec<TableProperties>, Error> {
    let buf_reader = File::open(&path)
        .map(BufReader::new)
        .map_err(|source| Error::ReadTemplate { path, source })?;
    let template: Template = serde_json::from_reader(buf_reader).map_err(Error::ParseTemplate)?;

    template
        .resources
        .into_values()
        .filter(|resource| resource.ty == DYNAMO_TABLE_TYPE)
        .map(|resource| serde_json::from_value::<TableProperties>(resource.properties))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::ParseTemplate)
}

/// Top-level CDK template object. We only care about `Resources`; the rest
/// of the file is ignored.
#[derive(Debug, Deserialize)]
struct Template {
    #[serde(rename = "Resources")]
    resources: HashMap<String, Resource>,
}

/// A single resource entry in the CDK template's `Resources` map. We keep
/// the raw `Properties` as a [`serde_json::Value`] so we can deserialise it
/// into the right concrete struct once we've branched on `Type`.
#[derive(Debug, Deserialize)]
struct Resource {
    #[serde(rename = "Type")]
    ty: String,
    #[serde(rename = "Properties")]
    properties: serde_json::Value,
}

/// The subset of CloudFormation's `AWS::DynamoDB::Table` properties [1]
/// that the Emily template actually uses. Anything else is ignored.
///
/// [1]: <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html>
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TableProperties {
    table_name: String,
    attribute_definitions: Vec<RawAttributeDefinition>,
    key_schema: Vec<RawKeySchemaEntry>,
    #[serde(default)]
    global_secondary_indexes: Vec<RawGlobalSecondaryIndex>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawAttributeDefinition {
    attribute_name: String,
    attribute_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawKeySchemaEntry {
    attribute_name: String,
    key_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawGlobalSecondaryIndex {
    index_name: String,
    key_schema: Vec<RawKeySchemaEntry>,
    projection: RawProjection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawProjection {
    projection_type: String,
    #[serde(default)]
    non_key_attributes: Option<Vec<String>>,
}

/// Build the AWS SDK client pointed at the configured endpoint.
///
/// The credentials provider is hand-rolled rather than letting the SDK
/// pick one from the environment.
async fn build_dynamodb_client(args: &AwsSetupArgs) -> DynamoClient {
    let credentials = Credentials::new(
        &args.access_key_id,
        &args.secret_access_key,
        None,
        None,
        "devenv",
    );
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(args.region.clone()))
        .endpoint_url(&args.dynamodb_endpoint)
        .credentials_provider(credentials)
        .load()
        .await;
    DynamoClient::new(&config)
}

/// Enumerate every table that already exists on the DynamoDB endpoint,
/// paginating until done.
async fn list_existing_tables(client: &DynamoClient) -> Result<HashSet<String>, Error> {
    let mut tables = HashSet::new();
    let mut start_after: Option<String> = None;
    loop {
        let mut req = client.list_tables().limit(LIST_TABLES_PAGE);
        if let Some(start) = start_after.take() {
            req = req.exclusive_start_table_name(start);
        }
        let resp = req.send().await.map_err(Box::new)?;

        if let Some(names) = resp.table_names {
            tables.extend(names);
        }
        match resp.last_evaluated_table_name {
            Some(next) => start_after = Some(next),
            None => break,
        }
    }
    Ok(tables)
}

/// Translate the parsed CFN properties into an SDK `CreateTable` call and
/// fire it off.
async fn create_table(client: &DynamoClient, props: &TableProperties) -> Result<(), Error> {
    let mut req = client
        .create_table()
        .table_name(&props.table_name)
        .billing_mode(BillingMode::PayPerRequest);

    for attr in &props.attribute_definitions {
        req = req.attribute_definitions(build_attribute_definition(attr)?);
    }
    for key in &props.key_schema {
        req = req.key_schema(build_key_schema_element(key)?);
    }
    for gsi in &props.global_secondary_indexes {
        req = req.global_secondary_indexes(build_gsi(gsi)?);
    }

    req.send().await.map_err(|source| Error::DynamoCreate {
        table: props.table_name.clone(),
        source: Box::new(source),
    })?;
    Ok(())
}

/// Build an `AttributeDefinition` from the raw CFN entry.
fn build_attribute_definition(raw: &RawAttributeDefinition) -> Result<AttributeDefinition, Error> {
    AttributeDefinition::builder()
        .attribute_name(&raw.attribute_name)
        .attribute_type(parse_scalar_type(&raw.attribute_type)?)
        .build()
        .map_err(Error::from)
}

/// Build a `KeySchemaElement` from the raw CFN entry. Same helper is used
/// for the primary key and for GSI keys.
fn build_key_schema_element(raw: &RawKeySchemaEntry) -> Result<KeySchemaElement, Error> {
    KeySchemaElement::builder()
        .attribute_name(&raw.attribute_name)
        .key_type(parse_key_type(&raw.key_type)?)
        .build()
        .map_err(Error::from)
}

/// Build a `GlobalSecondaryIndex` from the raw CFN entry. Note that we
/// don't set `ProvisionedThroughput` here — we hardcode `PayPerRequest`
/// for the parent table, which makes per-index throughput irrelevant.
fn build_gsi(raw: &RawGlobalSecondaryIndex) -> Result<GlobalSecondaryIndex, Error> {
    let key_schema = raw
        .key_schema
        .iter()
        .map(build_key_schema_element)
        .collect::<Result<Vec<_>, _>>()?;

    let mut projection = Projection::builder()
        .projection_type(parse_projection_type(&raw.projection.projection_type)?);
    if let Some(non_key) = &raw.projection.non_key_attributes {
        for attr in non_key {
            projection = projection.non_key_attributes(attr);
        }
    }

    GlobalSecondaryIndex::builder()
        .index_name(&raw.index_name)
        .set_key_schema(Some(key_schema))
        .projection(projection.build())
        .build()
        .map_err(Error::from)
}

fn parse_scalar_type(raw: &str) -> Result<ScalarAttributeType, Error> {
    match raw {
        "S" => Ok(ScalarAttributeType::S),
        "N" => Ok(ScalarAttributeType::N),
        "B" => Ok(ScalarAttributeType::B),
        other => Err(Error::MalformedTemplate(format!(
            "unsupported AttributeType {other:?}"
        ))),
    }
}

fn parse_key_type(raw: &str) -> Result<KeyType, Error> {
    match raw {
        "HASH" => Ok(KeyType::Hash),
        "RANGE" => Ok(KeyType::Range),
        other => Err(Error::MalformedTemplate(format!(
            "unsupported KeyType {other:?}"
        ))),
    }
}

fn parse_projection_type(raw: &str) -> Result<ProjectionType, Error> {
    match raw {
        "ALL" => Ok(ProjectionType::All),
        "KEYS_ONLY" => Ok(ProjectionType::KeysOnly),
        "INCLUDE" => Ok(ProjectionType::Include),
        other => Err(Error::MalformedTemplate(format!(
            "unsupported ProjectionType {other:?}"
        ))),
    }
}
