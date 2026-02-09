use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

use test_case::test_case;

use testing_emily_client::apis;
use testing_emily_client::models;
use testing_emily_client::models::AccountLimits;
use testing_emily_client::models::Chainstate;
use testing_emily_client::models::Limits;
use testing_emily_client::models::SlowdownKey;
use testing_emily_client::models::SlowdownReqwest;
use testing_emily_client::models::{CreateWithdrawalRequestBody, WithdrawalParameters};

use crate::common::StandardError;
use crate::common::clean_test_setup;
use crate::common::{batch_set_chainstates, new_test_chainstate, new_test_setup};

#[tokio::test]
async fn base_flow() {
    let (configuration, tables) = new_test_setup().await;

    // Set some limits first
    let limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1000)),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(10_000)),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    let result = apis::limits_api::set_limits(&configuration, limits.clone()).await;
    assert!(result.is_ok());

    // Check that we can't activate slow mode if we didn't register our key.
    let slowdown_reqwest = SlowdownReqwest {
        name: "test_key".to_string(),
        secret: "very secret string".to_string(),
    };
    let response =
        apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone()).await;
    assert!(response.is_err());
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(new_limits, limits);

    // Now let's register our key.
    let mut hasher = Sha256::new();
    hasher.update(slowdown_reqwest.secret.as_bytes());
    let result = hasher.finalize();
    let hash_hex_string = hex::encode(result);
    let slowdown_key = SlowdownKey {
        name: slowdown_reqwest.name.clone(),
        hash: hash_hex_string,
    };
    let _ = apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key)
        .await
        .unwrap();

    // Now let's check that it is impossible to start slow mode with wrong secret.
    let bad_slowdown_reqwest = SlowdownReqwest {
        name: "test_key".to_string(),
        secret: "wrong secret string".to_string(),
    };
    let response =
        apis::slowdown_api::start_slowdown(&configuration, bad_slowdown_reqwest.clone()).await;
    assert!(response.is_err());
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(new_limits, limits);

    // Finally, let's check that it is possible to start a slow mode with correct key.
    let response =
        apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone()).await;
    assert!(response.is_ok());
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_ne!(new_limits, limits);

    clean_test_setup(tables).await;
}
