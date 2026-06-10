//! `aws-setup` subcommand. Creates any missing DynamoDB tables described by
//! the Emily CDK CloudFormation template against a local DynamoDB instance.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;

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

/// The CloudFormation type discriminator we care about.
const DYNAMO_TABLE_TYPE: &str = "AWS::DynamoDB::Table";

/// Arguments for the `aws-setup` subcommand.
#[derive(Debug, Args)]
pub struct AwsSetupArgs {
    /// Path to the synthesised CDK template that lists the tables to create.
    #[clap(
        long = "input-cdk-template",
        env = "INPUT_CDK_TEMPLATE",
        default_value = "/code/cdk.out/EmilyStack.template.json"
    )]
    pub input_cdk_template: String,
    /// URL of the DynamoDB endpoint to talk to (e.g. dynamodb-local).
    #[clap(long = "dynamodb-endpoint", env = "DYNAMODB_ENDPOINT")]
    pub dynamodb_endpoint: String,
    /// AWS region passed to the SDK. Local DynamoDB ignores it but the SDK
    /// requires a value.
    #[clap(long, env = "AWS_REGION", default_value = "us-west-2")]
    pub region: String,
    /// Access key for the local DynamoDB instance.
    #[clap(long, env = "AWS_ACCESS_KEY_ID", default_value = "xxxxxxxx")]
    pub access_key_id: String,
    /// Secret key for the local DynamoDB instance.
    #[clap(long, env = "AWS_SECRET_ACCESS_KEY", default_value = "xxxxxxxx")]
    pub secret_access_key: String,
    /// Path to a sentinel file touched once every required table exists. The
    /// container healthcheck watches this file so that downstream services
    /// (e.g. `emily-server`) can start as soon as the tables are ready, even
    /// while the `wait-and-donate` phase is still polling.
    #[clap(
        long = "ready-file",
        env = "READY_FILE",
        default_value = "/tmp/aws-setup-ready"
    )]
    pub ready_file: std::path::PathBuf,
}

/// Entry point for the subcommand.
pub async fn run(args: AwsSetupArgs) -> Result<(), Error> {
    let template = read_template(&args.input_cdk_template)?;
    let tables = collect_table_resources(&template)?;
    tracing::info!(count = tables.len(), "tables defined in template");

    let client = dynamo_client(&args).await;
    let existing = list_existing_tables(&client).await?;
    tracing::info!(?existing, "existing dynamodb tables");

    for table in tables {
        if existing.contains(&table.table_name) {
            tracing::info!(table = %table.table_name, "table already exists, skipping");
            continue;
        }
        create_table(&client, &table).await?;
        tracing::info!(table = %table.table_name, "created table");
    }

    std::fs::File::create(&args.ready_file).map_err(|source| Error::WriteReadyFile {
        path: args.ready_file.display().to_string(),
        source,
    })?;
    tracing::info!(path = %args.ready_file.display(), "wrote aws-setup ready sentinel");

    Ok(())
}

/// Read and parse a CDK CloudFormation template from disk.
fn read_template(path: &str) -> Result<Template, Error> {
    let file = File::open(path)
        .map_err(|source| Error::ReadTemplate { path: path.to_string(), source })?;
    let template = serde_json::from_reader(BufReader::new(file))?;
    Ok(template)
}

/// Pull the `AWS::DynamoDB::Table` resources out of the template, parsed into
/// `TableProperties`.
fn collect_table_resources(template: &Template) -> Result<Vec<TableProperties>, Error> {
    template
        .resources
        .iter()
        .filter(|(_, res)| res.ty == DYNAMO_TABLE_TYPE)
        .map(|(_, res)| {
            serde_json::from_value::<TableProperties>(res.properties.clone()).map_err(Error::from)
        })
        .collect()
}

/// Build the AWS SDK client pointed at the configured (local) endpoint.
async fn dynamo_client(args: &AwsSetupArgs) -> DynamoClient {
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

/// Enumerate all existing tables on the DynamoDB endpoint, paginating until
/// done.
async fn list_existing_tables(client: &DynamoClient) -> Result<HashSet<String>, Error> {
    let mut tables = HashSet::new();
    let mut last: Option<String> = None;
    loop {
        let mut req = client.list_tables().limit(100);
        if let Some(start) = last.take() {
            req = req.exclusive_start_table_name(start);
        }
        let resp = req.send().await.map_err(Box::new)?;

        if let Some(names) = resp.table_names {
            tables.extend(names);
        }
        match resp.last_evaluated_table_name {
            Some(next) => last = Some(next),
            None => break,
        }
    }
    Ok(tables)
}

/// Create a single table from its parsed properties. We always set
/// `BillingMode::PayPerRequest` rather than reading it from the template —
/// this is a devenv-only helper and DynamoDB-local treats all billing modes
/// the same, so there is no reason to give the template a vote.
async fn create_table(client: &DynamoClient, props: &TableProperties) -> Result<(), Error> {
    let mut req = client
        .create_table()
        .table_name(&props.table_name)
        .billing_mode(BillingMode::PayPerRequest);

    for attr in &props.attribute_definitions {
        req = req.attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name(&attr.attribute_name)
                .attribute_type(parse_scalar_type(&attr.attribute_type)?)
                .build()?,
        );
    }

    for key in &props.key_schema {
        req = req.key_schema(build_key_schema_element(key)?);
    }

    for gsi in &props.global_secondary_indexes {
        req = req.global_secondary_indexes(build_gsi(gsi)?);
    }

    req.send().await.map_err(|err| Error::DynamoCreate {
        table: props.table_name.clone(),
        source: Box::new(err),
    })?;
    Ok(())
}

fn build_key_schema_element(raw: &KeySchemaEntry) -> Result<KeySchemaElement, Error> {
    KeySchemaElement::builder()
        .attribute_name(&raw.attribute_name)
        .key_type(parse_key_type(&raw.key_type)?)
        .build()
        .map_err(Error::from)
}

fn build_gsi(raw: &GsiRaw) -> Result<GlobalSecondaryIndex, Error> {
    let mut key_schema = Vec::with_capacity(raw.key_schema.len());
    for key in &raw.key_schema {
        key_schema.push(build_key_schema_element(key)?);
    }

    let mut projection_builder = Projection::builder()
        .projection_type(parse_projection_type(&raw.projection.projection_type)?);
    if let Some(non_key) = &raw.projection.non_key_attributes {
        for attr in non_key {
            projection_builder = projection_builder.non_key_attributes(attr);
        }
    }

    GlobalSecondaryIndex::builder()
        .index_name(&raw.index_name)
        .set_key_schema(Some(key_schema))
        .projection(projection_builder.build())
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

#[derive(Debug, Deserialize)]
struct Template {
    #[serde(rename = "Resources")]
    resources: HashMap<String, Resource>,
}

#[derive(Debug, Deserialize)]
struct Resource {
    #[serde(rename = "Type")]
    ty: String,
    #[serde(rename = "Properties")]
    properties: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TableProperties {
    table_name: String,
    attribute_definitions: Vec<AttributeDefinitionRaw>,
    key_schema: Vec<KeySchemaEntry>,
    #[serde(default)]
    global_secondary_indexes: Vec<GsiRaw>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AttributeDefinitionRaw {
    attribute_name: String,
    attribute_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeySchemaEntry {
    attribute_name: String,
    key_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GsiRaw {
    index_name: String,
    key_schema: Vec<KeySchemaEntry>,
    projection: ProjectionRaw,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProjectionRaw {
    projection_type: String,
    #[serde(default)]
    non_key_attributes: Option<Vec<String>>,
}
