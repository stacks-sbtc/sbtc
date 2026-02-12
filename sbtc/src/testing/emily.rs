//! Integration testing helper functions for Emily
//!

use std::collections::HashMap;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::{
    Client, Config,
    types::{
        AttributeDefinition, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType,
        Projection, ProjectionType, ScalarAttributeType,
    },
};
use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;
use bitcoin::hex::DisplayHex as _;
use futures::future::join_all;
use rand::{RngCore as _, rngs::OsRng};

const EMILY_CDK_TEMPLATE: &str =
    include_str!("../../../emily/cdk/cdk.out/EmilyStack.template.json");

/// Initialized tables for Emily
pub struct EmilyTables {
    /// DynamoDB client
    pub client: Client,
    /// Deposits table name
    pub deposit: String,
    /// Withdrawals table name
    pub withdrawal: String,
    /// Chainstates table name
    pub chainstate: String,
    /// Limits table name
    pub limit: String,
    /// Throttle table name
    pub throttle: String,
}

impl EmilyTables {
    /// Initialize a new set of tables
    pub async fn new() -> Self {
        let client = get_test_client();
        let prefix = format!("test-{}", random_hex());
        create_tables(&client, &prefix).await
    }

    /// Get the list of tables
    pub fn tables(&self) -> [&str; 5] {
        [
            &self.chainstate,
            &self.deposit,
            &self.limit,
            &self.withdrawal,
            &self.throttle,
        ]
    }

    /// Delete the tables
    pub async fn delete(&self) {
        for table in self.tables() {
            delete_table(&self.client, table).await;
        }
    }
}

fn random_hex() -> String {
    let mut bytes = [0; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.to_lower_hex_string()
}

async fn create_tables(client: &Client, table_prefix: &str) -> EmilyTables {
    let template: serde_json::Value =
        serde_json::from_str(EMILY_CDK_TEMPLATE).expect("failed to parse CDK template");

    let resources = template["Resources"]
        .as_object()
        .expect("missing resources in CDK template");

    let mut tables: HashMap<&str, String> = HashMap::new();
    let mut futs = Vec::new();
    for (resource_name, resource) in resources {
        let resource_type = resource["Type"].as_str().unwrap_or("");
        if resource_type != "AWS::DynamoDB::Table" {
            continue;
        }

        let table_name = format!(
            "{table_prefix}-{}",
            resource["Properties"]["TableName"].as_str().unwrap()
        );

        let create_table_fut = create_table(client, table_name.clone(), &resource["Properties"]);
        futs.push(create_table_fut);

        tables.insert(resource_name, table_name);
    }

    join_all(futs).await;

    let tables_to_find = vec!["Deposit", "Chainstate", "Withdrawal", "Limit", "Throttle"];
    let mut table_name_map: HashMap<&str, String> = HashMap::new();

    for (resource, name) in tables {
        for table_to_find in &tables_to_find {
            if resource.contains(table_to_find) {
                table_name_map.insert(table_to_find, name.clone());
            }
        }
    }

    let emily_tables = EmilyTables {
        client: client.clone(),
        deposit: table_name_map.remove("Deposit").unwrap().to_string(),
        withdrawal: table_name_map.remove("Withdrawal").unwrap().to_string(),
        chainstate: table_name_map.remove("Chainstate").unwrap().to_string(),
        limit: table_name_map.remove("Limit").unwrap().to_string(),
        throttle: table_name_map.remove("Throttle").unwrap().to_string(),
    };
    if !table_name_map.is_empty() {
        panic!("some Emily tables are unknown");
    }

    emily_tables
}

async fn create_table(client: &Client, table_name: String, props: &serde_json::Value) {
    let mut attributes = Vec::new();
    let attrs = props["AttributeDefinitions"].as_array().unwrap();

    for attr in attrs {
        let name = attr["AttributeName"].as_str().unwrap();
        let type_str = attr["AttributeType"].as_str().unwrap();

        let scalar_type = ScalarAttributeType::try_parse(type_str).expect("unknown attribute type");

        attributes.push(
            AttributeDefinition::builder()
                .attribute_name(name)
                .attribute_type(scalar_type)
                .build()
                .expect("failed to build attribute definition"),
        );
    }

    let keys = parse_key_schema(&props["KeySchema"]);

    let mut builder = client
        .create_table()
        .table_name(table_name)
        .set_attribute_definitions(Some(attributes))
        .set_key_schema(Some(keys))
        .billing_mode(BillingMode::PayPerRequest);

    if let Some(gsi_array) = props["GlobalSecondaryIndexes"].as_array() {
        let gsis = parse_gsis(gsi_array);
        builder = builder.set_global_secondary_indexes(Some(gsis));
    }

    builder.send().await.expect("failed to create table");
}

fn parse_key_schema(schema_json: &serde_json::Value) -> Vec<KeySchemaElement> {
    let mut keys = Vec::new();
    for key in schema_json.as_array().unwrap() {
        let name = key["AttributeName"].as_str().unwrap();
        let type_str = key["KeyType"].as_str().unwrap();

        let key_type = KeyType::try_parse(type_str).expect("unknown key type");

        keys.push(
            KeySchemaElement::builder()
                .attribute_name(name)
                .key_type(key_type)
                .build()
                .expect("failed to build key schema"),
        );
    }
    keys
}

fn parse_gsis(gsi_array: &[serde_json::Value]) -> Vec<GlobalSecondaryIndex> {
    let mut indexes = Vec::new();

    for gsi in gsi_array {
        let index_name = gsi["IndexName"].as_str().unwrap();
        let key_schema = parse_key_schema(&gsi["KeySchema"]);

        let proj_json = &gsi["Projection"];
        let proj_type_str = proj_json["ProjectionType"].as_str().unwrap();

        let mut proj_builder = Projection::builder();

        let proj_type = ProjectionType::try_parse(proj_type_str).expect("unknown projection type");
        proj_builder = proj_builder.projection_type(proj_type);

        if proj_type_str == "INCLUDE"
            && let Some(attrs) = proj_json["NonKeyAttributes"].as_array()
        {
            let attr_names: Vec<String> = attrs
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            proj_builder = proj_builder.set_non_key_attributes(Some(attr_names));
        }

        let gsi_builder = GlobalSecondaryIndex::builder()
            .index_name(index_name)
            .set_key_schema(Some(key_schema))
            .set_projection(Some(proj_builder.build()));

        indexes.push(gsi_builder.build().expect("failed to build gsi"));
    }

    indexes
}

async fn delete_table(client: &Client, table_name: &str) {
    client
        .delete_table()
        .table_name(table_name)
        .send()
        .await
        .expect("failed to delete table");
}

fn get_test_client() -> Client {
    let creds = aws_sdk_dynamodb::config::Credentials::new(
        "xxxxxxxxxxxx",
        "xxxxxxxxxxxx",
        None,
        None,
        "test",
    );

    // We don't need https in tests (and we avoid wasting time in loading certs)
    let tcp_connector = hyper_014::client::HttpConnector::new();
    let http_client = HyperClientBuilder::new().build(tcp_connector);

    let config = Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(creds)
        .region(Region::new("us-west-2"))
        .endpoint_url("http://127.0.0.1:8000")
        .http_client(http_client)
        .build();

    Client::from_conf(config)
}
