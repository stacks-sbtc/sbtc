use sbtc::testing::containers::{SERVICE_BITCOIN, SERVICE_BITCOIN_RPC_PORT, TestContainersBuilder};

#[tokio::test]
async fn test_up() {
    let mut stack = TestContainersBuilder::new().with_bitcoin().build();
    stack.up().await.unwrap();

    assert!(stack.get_service_host(SERVICE_BITCOIN).await.is_ok());
    assert!(
        stack
            .get_service_port(SERVICE_BITCOIN, SERVICE_BITCOIN_RPC_PORT)
            .await
            .is_ok()
    );
}
