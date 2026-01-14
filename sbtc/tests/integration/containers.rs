use sbtc::testing::containers::{
    SERVICE_BITCOIN, SERVICE_BITCOIN_RPC_PORT, SERVICE_STACKS, SERVICE_STACKS_RPC_PORT,
    TestContainersBuilder,
};

#[tokio::test]
async fn test_bitcoin_port() {
    let stack = TestContainersBuilder::start_bitcoin().await;

    assert!(stack.get_service_host(SERVICE_BITCOIN).await.is_ok());
    assert!(
        stack
            .get_service_port(SERVICE_BITCOIN, SERVICE_BITCOIN_RPC_PORT)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_stacks_port() {
    let stack = TestContainersBuilder::start_stacks().await;

    assert!(stack.get_service_host(SERVICE_STACKS).await.is_ok());
    assert!(
        stack
            .get_service_port(SERVICE_STACKS, SERVICE_STACKS_RPC_PORT)
            .await
            .is_ok()
    );
}
