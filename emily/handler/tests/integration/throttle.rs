use argon2::{Argon2, password_hash::PasswordHasher as _};
use reqwest_012::StatusCode;
use std::collections::HashMap;
use test_case::test_case;

use testing_emily_client::apis;
use testing_emily_client::apis::Error;
use testing_emily_client::models::Chainstate;
use testing_emily_client::models::Limits;
use testing_emily_client::models::ThrottleKey;
use testing_emily_client::models::ThrottleRequest;

use emily_handler::database::accessors::name_to_salt;

use crate::common::clean_test_setup;
use crate::common::{batch_set_chainstates, new_test_chainstate, new_test_setup};

// This test ensures core functionality, ignoring details (aka which exact error type returned, etc)
#[tokio::test]
async fn base_flow() {
    let (configuration, tables) = new_test_setup().await;

    // Set some limits first
    let limits = Limits {
        available_to_withdraw: Some(Some(10_000_000_000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1_000_000_000)),
        rolling_withdrawal_blocks: Some(Some(1)),
        rolling_withdrawal_cap: Some(Some(10_000_000_000)),
        throttle_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    let _ = apis::limits_api::set_limits(&configuration, limits.clone())
        .await
        .unwrap();

    // Check that we can't activate throttle mode if we didn't register our key.
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let salt = name_to_salt(&throttle_key.name).unwrap();
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let _ = apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap_err();
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(new_limits, limits);

    // Now let's register our key.
    let _ = apis::throttle_api::add_throttle_key(&configuration, throttle_key.clone())
        .await
        .unwrap();

    // Now let's check that it is impossible to start throttle mode with wrong secret.
    let bad_throttle_reqwest = ThrottleRequest {
        name: throttle_reqwest.name.clone(),
        secret: "TW9yZSBkYaaaaciB5b3VyIHRlc3Qcc".to_string(),
    };
    let _ = apis::throttle_api::start_throttle(&configuration, bad_throttle_reqwest.clone())
        .await
        .unwrap_err();
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(new_limits, limits);

    // Now, let's check that it is possible to start a throttle mode with correct key.
    let _ = apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap();
    let new_limits_after_throttle = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits_after_throttle
            .per_withdrawal_cap
            .unwrap()
            .unwrap(),
        emily_handler::database::accessors::THROTTLE_MODE_PER_WITHDRAWAL_CAP
    );
    assert_eq!(
        new_limits_after_throttle
            .rolling_withdrawal_blocks
            .unwrap()
            .unwrap(),
        emily_handler::database::accessors::THROTTLE_MODE_ROLLING_WINDOW
    );
    assert_eq!(
        new_limits_after_throttle
            .rolling_withdrawal_cap
            .unwrap()
            .unwrap(),
        emily_handler::database::accessors::THROTTLE_MODE_ROLLING_CAP
    );
    assert_eq!(new_limits_after_throttle.peg_cap, limits.peg_cap,);
    assert_eq!(
        new_limits_after_throttle.per_deposit_minimum,
        limits.per_deposit_minimum,
    );
    assert_eq!(
        new_limits_after_throttle.per_deposit_cap,
        limits.per_deposit_cap
    );

    // Now lets restore limits back to normal
    let _ = apis::limits_api::set_limits(&configuration, limits.clone())
        .await
        .unwrap();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(limits, retrieved_limits);

    // Now lets deactivate key, and make sure that it is not allowed to start throttle mode anymore.
    let _ = apis::throttle_api::deactivate_throttle_key(&configuration, &hash)
        .await
        .unwrap();
    let _ = apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap_err();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(limits, retrieved_limits);

    // Now lets activate key back, and make sure that it is again eligible to start throttle mode.
    let _ = apis::throttle_api::activate_throttle_key(&configuration, &hash)
        .await
        .unwrap();
    let _ = apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        retrieved_limits.per_withdrawal_cap.unwrap().unwrap(),
        emily_handler::database::accessors::THROTTLE_MODE_PER_WITHDRAWAL_CAP
    );
    assert_eq!(
        retrieved_limits.rolling_withdrawal_blocks.unwrap().unwrap(),
        emily_handler::database::accessors::THROTTLE_MODE_ROLLING_WINDOW
    );
    assert_eq!(
        retrieved_limits.rolling_withdrawal_cap.unwrap().unwrap(),
        emily_handler::database::accessors::THROTTLE_MODE_ROLLING_CAP
    );

    clean_test_setup(tables).await;
}

// Slow mode should not overwrite limits which are tighter then throttle mode limits.
// Particularly, we want to ensure that on throttle mode activation:
// - per_withdrawal_cap can be decreased only
// - rolling_withdrawal_blocks can be increased only
// - rolling_withdrawal_cap can be decreased only
#[test_case(true,  false, false; "per withdrawal cap")]
#[test_case(false, true,  false; "window size")]
#[test_case(false, false, true;  "window cap")]
#[test_case(true,  true,  false; "per withdrawal and window size")]
#[test_case(true,  false, true;  "per withdrawal and window cap")]
#[test_case(false, true,  true;  "window size and cap")]
#[test_case(true,  true,  true;  "all stricter")]
#[test_case(false, false, false; "none stricter")]
#[tokio::test]
async fn throttle_does_not_overwrite_stronger_limits(
    is_per_withdrawal_stricter: bool,
    is_rolling_window_size_stricter: bool,
    is_rolling_window_cap_stricter: bool,
) {
    let (configuration, tables) = new_test_setup().await;

    // Set limits first
    let throttle_mode_per_withdrawal_cap =
        emily_handler::database::accessors::THROTTLE_MODE_PER_WITHDRAWAL_CAP;
    let throttle_mode_rolling_window =
        emily_handler::database::accessors::THROTTLE_MODE_ROLLING_WINDOW;
    let throttle_mode_rolling_cap = emily_handler::database::accessors::THROTTLE_MODE_ROLLING_CAP;

    let per_withdrawal_cap = if is_per_withdrawal_stricter {
        Some(Some(throttle_mode_per_withdrawal_cap - 1))
    } else {
        Some(Some(throttle_mode_per_withdrawal_cap + 1))
    };
    let rolling_withdrawal_blocks = if is_rolling_window_size_stricter {
        Some(Some(throttle_mode_rolling_window + 1))
    } else {
        Some(Some(throttle_mode_rolling_window - 1))
    };
    let rolling_withdrawal_cap = if is_rolling_window_cap_stricter {
        Some(Some(throttle_mode_rolling_cap - 1))
    } else {
        Some(Some(throttle_mode_rolling_cap + 1))
    };

    let limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap,
        rolling_withdrawal_blocks,
        rolling_withdrawal_cap,
        account_caps: HashMap::new(),
        throttle_mode_initiator: Some(None),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    let _ = apis::limits_api::set_limits(&configuration, limits.clone())
        .await
        .unwrap();

    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };

    // Now let's register our key.
    let _ = apis::throttle_api::add_throttle_key(&configuration, throttle_key.clone())
        .await
        .unwrap();

    // Now, let's trigger throttle mode.
    let _ = apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap();

    // Now check that only allowed fields was changed.
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();

    if is_per_withdrawal_stricter {
        assert_eq!(new_limits.per_withdrawal_cap, limits.per_withdrawal_cap);
    } else {
        assert_eq!(
            new_limits.per_withdrawal_cap.unwrap().unwrap(),
            throttle_mode_per_withdrawal_cap
        );
    }
    if is_rolling_window_cap_stricter {
        assert_eq!(
            new_limits.rolling_withdrawal_cap,
            limits.rolling_withdrawal_cap
        );
    } else {
        assert_eq!(
            new_limits.rolling_withdrawal_cap.unwrap().unwrap(),
            throttle_mode_rolling_cap
        );
    }
    if is_rolling_window_size_stricter {
        assert_eq!(
            new_limits.rolling_withdrawal_blocks,
            limits.rolling_withdrawal_blocks
        );
    } else {
        assert_eq!(
            new_limits.rolling_withdrawal_blocks.unwrap().unwrap(),
            throttle_mode_rolling_window
        );
    }

    clean_test_setup(tables).await;
}

// We should pin behaviour on adding a key while key with such hash already exists
// (bail or overwrite)
// Current behavior is to bail.
#[tokio::test]
async fn duplicate_key_hashes() {
    let (configuration, tables) = new_test_setup().await;

    // Register the first key
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };

    apis::throttle_api::add_throttle_key(&configuration, throttle_key.clone())
        .await
        .unwrap();

    // Attempt to register a second key with the same hash
    let err = apis::throttle_api::add_throttle_key(&configuration, throttle_key)
        .await
        .unwrap_err();

    // Verify that it bails (returns a 409 Conflict error)
    let Error::ResponseError(err) = err else {
        panic!("Wrong error type: {:?}", err)
    };
    assert_eq!(err.status, StatusCode::CONFLICT);

    clean_test_setup(tables).await;
}

// We should ensure that start_throttle returns proper error (no such key/wrong secret/deactivated)
#[tokio::test]
async fn start_throttle_returns_proper_error() {
    let (configuration, tables) = new_test_setup().await;

    // Set some limits first (needed for calculate_throttle_mode_limits to work)
    let limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1000)),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(10_000)),
        throttle_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    let _ = apis::limits_api::set_limits(&configuration, limits.clone())
        .await
        .unwrap();

    // Test case 1: Key not found
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };

    let err = apis::throttle_api::start_throttle(&configuration, throttle_reqwest)
        .await
        .unwrap_err();
    let Error::ResponseError(err) = err else {
        panic!("Wrong error type")
    };
    assert!(matches!(err.status, StatusCode::NOT_FOUND));

    // Register a key for further tests
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    apis::throttle_api::add_throttle_key(&configuration, throttle_key.clone())
        .await
        .unwrap();

    let salt = name_to_salt(&throttle_key.name).unwrap();
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string();

    // Test case 3: Key is revoked (deactivated)
    apis::throttle_api::deactivate_throttle_key(&configuration, &hash)
        .await
        .unwrap();

    let err = apis::throttle_api::start_throttle(&configuration, throttle_reqwest)
        .await
        .unwrap_err();
    let Error::ResponseError(err) = err else {
        panic!("Wrong error type")
    };
    assert!(matches!(err.status, StatusCode::FORBIDDEN));

    clean_test_setup(tables).await;
}

// We should check that if current limits have unlimited fields throttle mode overwrites them successfully.
#[tokio::test]
async fn throttle_mode_overwrites_unlimited_limits() {
    let (configuration, tables) = new_test_setup().await;

    // Set limits to unlimited (None)
    let limits = Limits {
        available_to_withdraw: Some(None),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(None),
        rolling_withdrawal_blocks: Some(None),
        rolling_withdrawal_cap: Some(None),
        throttle_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    let _ = apis::limits_api::set_limits(&configuration, limits.clone())
        .await
        .unwrap();

    // Now let's register our key.
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };

    let _ = apis::throttle_api::add_throttle_key(&configuration, throttle_key.clone())
        .await
        .unwrap();

    // Now, let's trigger throttle mode.
    let _ = apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap();

    // Now check that all relevant fields are set to throttle mode limits.
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();

    assert!(new_limits.per_withdrawal_cap.is_some());
    assert!(new_limits.rolling_withdrawal_blocks.is_some());
    assert!(new_limits.rolling_withdrawal_cap.is_some());

    clean_test_setup(tables).await;
}

#[tokio::test]
async fn throttle_mode_initiator_correctly_shown_at_limits() {
    let (configuration, tables) = new_test_setup().await;

    // Set some initial limits
    let initial_limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1000)),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(10_000)),
        throttle_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    apis::limits_api::set_limits(&configuration, initial_limits.clone())
        .await
        .unwrap();

    // Register a throttle key
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    apis::throttle_api::add_throttle_key(&configuration, throttle_key)
        .await
        .unwrap();

    // Trigger throttle mode
    apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap();

    // Verify that the throttle_mode_initiator field is set correctly
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits.throttle_mode_initiator,
        Some(Some(key_name.clone()))
    );

    // Now let's restore limits back to normal and check that throttle_mode_initiator is None
    let _ = apis::limits_api::set_limits(&configuration, initial_limits.clone())
        .await
        .unwrap();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(retrieved_limits.throttle_mode_initiator, Some(None));

    // Trigger throttle mode again to ensure the initiator is set again
    let _ = apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap();
    let new_limits_after_retrigger = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits_after_retrigger.throttle_mode_initiator,
        Some(Some(key_name))
    );

    clean_test_setup(tables).await;
}

#[tokio::test]
async fn stop_throttle_works() {
    let (configuration, tables) = new_test_setup().await;

    // Set some initial limits
    let initial_limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1_000_000_000)),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(10_000)),
        throttle_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    apis::limits_api::set_limits(&configuration, initial_limits.clone())
        .await
        .unwrap();

    // Register a throttle key
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    apis::throttle_api::add_throttle_key(&configuration, throttle_key)
        .await
        .unwrap();

    // Verify that before starting throttle limits equal to what we set.
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits.per_withdrawal_cap,
        initial_limits.per_withdrawal_cap
    );
    assert_eq!(new_limits.throttle_mode_initiator, Some(None));

    // Trigger throttle mode
    apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap();

    // Verify that the throttle_mode_initiator field is set correctly
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits.per_withdrawal_cap,
        Some(Some(
            emily_handler::database::accessors::THROTTLE_MODE_PER_WITHDRAWAL_CAP
        ))
    );
    assert_eq!(
        new_limits.throttle_mode_initiator,
        Some(Some(key_name.clone()))
    );

    // Now let's restore limits back to normal and check that throttle_mode_initiator is None
    let _ = apis::throttle_api::stop_throttle(&configuration)
        .await
        .unwrap();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        retrieved_limits.per_withdrawal_cap,
        initial_limits.per_withdrawal_cap
    );
    assert_eq!(retrieved_limits.throttle_mode_initiator, Some(None));

    clean_test_setup(tables).await;
}

#[tokio::test]
async fn available_to_withdraw_calculated_correctly_in_throttle_mode() {
    let (configuration, tables) = new_test_setup().await;

    // Set some initial limits
    let initial_limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1000)),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(10_000_000_000)),
        throttle_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    apis::limits_api::set_limits(&configuration, initial_limits.clone())
        .await
        .unwrap();

    // Verify available_to_withdraw in normal mode
    let retrieved_limits_normal = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        retrieved_limits_normal.available_to_withdraw,
        initial_limits.rolling_withdrawal_cap
    );

    // Register a throttle key
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    apis::throttle_api::add_throttle_key(&configuration, throttle_key)
        .await
        .unwrap();

    // Trigger throttle mode
    apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
        .await
        .unwrap();

    // Verify available_to_withdraw in throttle mode
    let retrieved_limits_throttle = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        retrieved_limits_throttle.available_to_withdraw,
        Some(Some(
            emily_handler::database::accessors::THROTTLE_MODE_ROLLING_CAP
        ))
    );

    // Now let's set initial limits with a stricter rolling_withdrawal_cap
    let stricter_initial_limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1000)),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(
            emily_handler::database::accessors::THROTTLE_MODE_ROLLING_CAP - 100,
        )),
        throttle_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    apis::limits_api::set_limits(&configuration, stricter_initial_limits.clone())
        .await
        .unwrap();

    // Verify available_to_withdraw in normal mode with stricter cap
    let retrieved_limits_stricter_normal =
        apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        retrieved_limits_stricter_normal.available_to_withdraw,
        stricter_initial_limits.rolling_withdrawal_cap
    );

    // Trigger throttle mode again
    apis::throttle_api::start_throttle(&configuration, throttle_reqwest)
        .await
        .unwrap();

    // Verify available_to_withdraw in throttle mode with stricter cap
    // It should still respect the stricter cap, as throttle mode only decreases rolling_withdrawal_cap
    let retrieved_limits_stricter_throttle =
        apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        retrieved_limits_stricter_throttle.available_to_withdraw,
        stricter_initial_limits.rolling_withdrawal_cap
    );

    clean_test_setup(tables).await;
}

#[tokio::test]
async fn multiple_stop_throttle_does_not_overwrite_initial_limits() {
    let (configuration, tables) = new_test_setup().await;

    // Set some initial limits
    let initial_limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1_000_000_000)),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(10_000)),
        throttle_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    apis::limits_api::set_limits(&configuration, initial_limits.clone())
        .await
        .unwrap();

    // Register a throttle key
    let key_name = "aaaaaaaaaaaaaaaa".to_string();
    let secret = "very secret string".to_string();
    let throttle_key = ThrottleKey {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    let throttle_reqwest = ThrottleRequest {
        name: key_name.clone(),
        secret: secret.clone(),
    };
    apis::throttle_api::add_throttle_key(&configuration, throttle_key)
        .await
        .unwrap();

    // Trigger throttle mode multiple times
    for _ in 0..3 {
        apis::throttle_api::start_throttle(&configuration, throttle_reqwest.clone())
            .await
            .unwrap();
    }

    // Verify that the throttle_mode_initiator field is set correctly
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits.per_withdrawal_cap,
        Some(Some(
            emily_handler::database::accessors::THROTTLE_MODE_PER_WITHDRAWAL_CAP
        ))
    );

    // Now let's restore limits back to normal and check that throttle_mode_initiator is None
    let _ = apis::throttle_api::stop_throttle(&configuration)
        .await
        .unwrap();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        retrieved_limits.per_withdrawal_cap,
        initial_limits.per_withdrawal_cap
    );

    clean_test_setup(tables).await;
}
