//! Test emily setup utility

use assert_matches::assert_matches;
use aws_sdk_dynamodb::types::TableStatus;
use sbtc::testing::emily::EmilyTables;

#[tokio::test]
async fn test_create_table() {
    let setup = EmilyTables::new().await;

    for table in setup.tables() {
        let result = setup.client.describe_table().table_name(table).send().await;
        assert_matches!(
            result.unwrap().table.unwrap().table_status.unwrap(),
            TableStatus::Active
        );
    }

    setup.delete().await;

    for table in setup.tables() {
        let result = setup.client.describe_table().table_name(table).send().await;
        assert!(result.is_err());
    }
}
