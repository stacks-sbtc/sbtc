use testing_emily_client::apis::health_api;

use crate::common::clean_setup;

#[tokio::test]
async fn test_dynamic_context() {
    let mut configuration = clean_setup().await;

    let version = health_api::check_health(&configuration)
        .await
        .unwrap()
        .version;
    assert_eq!(version, "local-instance");

    // Inject a custom value to test emily dynamic context
    let mut headers = reqwest_codegen::header::HeaderMap::new();
    headers.insert(
        "x-context-version",
        reqwest_codegen::header::HeaderValue::from_static("custom-version"),
    );

    configuration.client = reqwest_codegen::ClientBuilder::new()
        .default_headers(headers)
        .build()
        .unwrap();

    let version = health_api::check_health(&configuration)
        .await
        .unwrap()
        .version;
    assert_eq!(version, "custom-version");
}
