use argon2::{
    Argon2,
    password_hash::{PasswordHasher as _, SaltString, rand_core::OsRng},
};
use reqwest_012::StatusCode;
use std::collections::HashMap;
use test_case::test_case;

use testing_emily_client::apis;
use testing_emily_client::apis::Error;
use testing_emily_client::models::Chainstate;
use testing_emily_client::models::Limits;
use testing_emily_client::models::SlowdownKey;
use testing_emily_client::models::SlowdownReqwest;

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
        slow_mode_initiator: Some(None),
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

    // Check that we can't activate slow mode if we didn't register our key.
    let secret = "very secret string".to_string();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let name = "test_key".to_string();

    let slowdown_reqwest = SlowdownReqwest { hash: hash.clone(), secret };
    let slowdown_key = SlowdownKey { hash, name };

    let _ = apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone())
        .await
        .unwrap_err();
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(new_limits, limits);

    // Now let's register our key.
    let _ = apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key.clone())
        .await
        .unwrap();

    // Now let's check that it is impossible to start slow mode with wrong secret.
    let bad_slowdown_reqwest = SlowdownReqwest {
        hash: slowdown_reqwest.hash.clone(),
        secret: "wrong secret string".to_string(),
    };
    let _ = apis::slowdown_api::start_slowdown(&configuration, bad_slowdown_reqwest.clone())
        .await
        .unwrap_err();
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(new_limits, limits);

    // Now, let's check that it is possible to start a slow mode with correct key.
    let _ = apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone())
        .await
        .unwrap();
    let new_limits_after_slowdown = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits_after_slowdown
            .per_withdrawal_cap
            .unwrap()
            .unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_PER_WITHDRAWAL_CAP
    );
    assert_eq!(
        new_limits_after_slowdown
            .rolling_withdrawal_blocks
            .unwrap()
            .unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_ROLLING_WINDOW
    );
    assert_eq!(
        new_limits_after_slowdown
            .rolling_withdrawal_cap
            .unwrap()
            .unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_ROLLING_CAP
    );

    // Now lets restore limits back to normal
    let _ = apis::limits_api::set_limits(&configuration, limits.clone())
        .await
        .unwrap();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(limits, retrieved_limits);

    // Now lets deactivate key, and make sure that it is not allowed to start slow mode anymore.
    let _ = apis::slowdown_api::deactivate_slowdown_key(&configuration, &(slowdown_key.hash))
        .await
        .unwrap();
    let _ = apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone())
        .await
        .unwrap_err();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(limits, retrieved_limits);

    // Now lets activate key back, and make sure that it is again eligible to start slow mode.
    let _ = apis::slowdown_api::activate_slowdown_key(&configuration, &(slowdown_key.hash))
        .await
        .unwrap();
    let _ = apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone())
        .await
        .unwrap();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        retrieved_limits.per_withdrawal_cap.unwrap().unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_PER_WITHDRAWAL_CAP
    );
    assert_eq!(
        retrieved_limits.rolling_withdrawal_blocks.unwrap().unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_ROLLING_WINDOW
    );
    assert_eq!(
        retrieved_limits.rolling_withdrawal_cap.unwrap().unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_ROLLING_CAP
    );

    clean_test_setup(tables).await;
}

// Slow mode should not overwrite limits which are tighter then slow mode limits.
// Particularly, we want to ensure that on slow mode activation:
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
async fn slowdown_does_not_overwrite_stronger_limits(
    is_per_withdrawal_stricter: bool,
    is_rolling_window_size_stricter: bool,
    is_rolling_window_cap_stricter: bool,
) {
    let (configuration, tables) = new_test_setup().await;

    // Set limits first
    let slow_mode_per_withdrawal_cap =
        emily_handler::api::handlers::slowdown::SLOW_MODE_PER_WITHDRAWAL_CAP;
    let slow_mode_rolling_window = emily_handler::api::handlers::slowdown::SLOW_MODE_ROLLING_WINDOW;
    let slow_mode_rolling_cap = emily_handler::api::handlers::slowdown::SLOW_MODE_ROLLING_CAP;

    let per_withdrawal_cap = if is_per_withdrawal_stricter {
        Some(Some(slow_mode_per_withdrawal_cap - 1))
    } else {
        Some(Some(slow_mode_per_withdrawal_cap + 1))
    };
    let rolling_withdrawal_blocks = if is_rolling_window_size_stricter {
        Some(Some(slow_mode_rolling_window + 1))
    } else {
        Some(Some(slow_mode_rolling_window - 1))
    };
    let rolling_withdrawal_cap = if is_rolling_window_cap_stricter {
        Some(Some(slow_mode_rolling_cap - 1))
    } else {
        Some(Some(slow_mode_rolling_cap + 1))
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
        slow_mode_initiator: Some(None),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    let _ = apis::limits_api::set_limits(&configuration, limits.clone())
        .await
        .unwrap();

    let name = "test_key".to_string();
    let secret = "very secret string".to_string();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let slowdown_key = SlowdownKey { hash: hash.clone(), name };
    let slowdown_reqwest = SlowdownReqwest { hash, secret };

    // Now let's register our key.
    let _ = apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key.clone())
        .await
        .unwrap();

    // Now, let's trigger slow mode.
    let _ = apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone())
        .await
        .unwrap();

    // Now check that only allowed fields was changed.
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();

    if is_per_withdrawal_stricter {
        assert_eq!(new_limits.per_withdrawal_cap, limits.per_withdrawal_cap);
    } else {
        assert_eq!(
            new_limits.per_withdrawal_cap.unwrap().unwrap(),
            slow_mode_per_withdrawal_cap
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
            slow_mode_rolling_cap
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
            slow_mode_rolling_window
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

    let key_name = "test_key".to_string();
    let secret1 = "very secret string 1".to_string();

    // Register the first key
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(secret1.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let slowdown_key1 = SlowdownKey {
        name: key_name.clone(),
        hash: password_hash,
    };
    apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key1.clone())
        .await
        .unwrap();

    // Attempt to register a second key with the same hash
    let slowdown_key2 = SlowdownKey {
        name: "aoaoaao".to_string(),
        hash: slowdown_key1.hash,
    };
    let err = apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key2)
        .await
        .unwrap_err();

    // Verify that it bails (returns a 409 Conflict error)
    let Error::ResponseError(err) = err else {
        panic!("Wrong error type: {:?}", err)
    };
    assert_eq!(err.status, StatusCode::CONFLICT);

    clean_test_setup(tables).await;
}

// We should ensure that start_slowdown returns proper error (no such key/wrong secret/deactivated)
#[tokio::test]
async fn start_slowdown_returns_proper_error() {
    let (configuration, tables) = new_test_setup().await;

    // Set some limits first (needed for calculate_slow_mode_limits to work)
    let limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1000)),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(10_000)),
        slow_mode_initiator: Some(None),
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
    let unknown_secret = "misterious".to_string();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let unknown_hash = argon2
        .hash_password(unknown_secret.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let unknown_key_reqwest = SlowdownReqwest {
        hash: unknown_hash,
        secret: unknown_secret,
    };
    let err = apis::slowdown_api::start_slowdown(&configuration, unknown_key_reqwest)
        .await
        .unwrap_err();
    let Error::ResponseError(err) = err else {
        panic!("Wrong error type")
    };
    assert!(matches!(err.status, StatusCode::NOT_FOUND));

    // Register a key for further tests
    let name = "test_key".to_string();
    let secret = "very secret string".to_string();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let slowdown_key = SlowdownKey {
        name: name.clone(),
        hash: hash.clone(),
    };
    apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key)
        .await
        .unwrap();

    // Test case 2: Failed secret verification
    let wrong_secret_reqwest = SlowdownReqwest {
        hash: hash.clone(),
        secret: "wrong secret".to_string(),
    };
    let err = apis::slowdown_api::start_slowdown(&configuration, wrong_secret_reqwest)
        .await
        .unwrap_err();
    let Error::ResponseError(err) = err else {
        panic!("Wrong error type")
    };
    assert!(matches!(err.status, StatusCode::UNAUTHORIZED));

    // Test case 3: Key is revoked (deactivated)
    apis::slowdown_api::deactivate_slowdown_key(&configuration, &hash)
        .await
        .unwrap();
    let deactivated_key_reqwest = SlowdownReqwest {
        hash: hash.clone(),
        secret: secret.clone(),
    };
    let err = apis::slowdown_api::start_slowdown(&configuration, deactivated_key_reqwest)
        .await
        .unwrap_err();
    let Error::ResponseError(err) = err else {
        panic!("Wrong error type")
    };
    assert!(matches!(err.status, StatusCode::FORBIDDEN));

    clean_test_setup(tables).await;
}

// We should check that if current limits have unlimited fields slow mode overwrites them successfully.
#[tokio::test]
async fn slow_mode_overwrites_unlimited_limits() {
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
        slow_mode_initiator: Some(None),
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
    let name = "test_key".to_string();
    let secret = "very secret string".to_string();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let slowdown_key = SlowdownKey { name, hash: hash.clone() };
    let slowdown_reqwest = SlowdownReqwest { hash, secret };

    let _ = apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key.clone())
        .await
        .unwrap();

    // Now, let's trigger slow mode.
    let _ = apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone())
        .await
        .unwrap();

    // Now check that all relevant fields are set to slow mode limits.
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();

    assert!(new_limits.per_withdrawal_cap.is_some());
    assert!(new_limits.rolling_withdrawal_blocks.is_some());
    assert!(new_limits.rolling_withdrawal_cap.is_some());

    clean_test_setup(tables).await;
}

#[tokio::test]
async fn slow_mode_initiator_correctly_shown_at_limits() {
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
        slow_mode_initiator: Some(None),
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

    // Register a slowdown key
    let key_name = "test_key".to_string();
    let secret = "very secret string".to_string();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let slowdown_key = SlowdownKey {
        name: key_name.clone(),
        hash: hash.clone(),
    };
    let slowdown_reqwest = SlowdownReqwest { hash, secret: secret.clone() };
    apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key)
        .await
        .unwrap();

    // Trigger slow mode
    apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone())
        .await
        .unwrap();

    // Verify that the slow_mode_initiator field is set correctly
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(new_limits.slow_mode_initiator, Some(Some(key_name.clone())));

    // Now let's restore limits back to normal and check that slow_mode_initiator is None
    let _ = apis::limits_api::set_limits(&configuration, initial_limits.clone())
        .await
        .unwrap();
    let retrieved_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(retrieved_limits.slow_mode_initiator, Some(None));

    // Trigger slow mode again to ensure the initiator is set again
    let _ = apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest.clone())
        .await
        .unwrap();
    let new_limits_after_retrigger = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits_after_retrigger.slow_mode_initiator,
        Some(Some(key_name))
    );

    clean_test_setup(tables).await;
}

// We should check that Emily verifies during slowdown key addition
// that hash is a valid hash string, and returns proper error otherwise
#[tokio::test]
async fn slowdown_key_addition_verifies_hash_formatting() {
    let (configuration, tables) = new_test_setup().await;

    // Test case: Invalid hash format (random string)
    let key_name = "test_key_invalid_hash".to_string();
    let invalid_password_hash = "not_a_valid_hash_string".to_string();
    let invalid_slowdown_key = SlowdownKey {
        name: key_name.clone(),
        hash: invalid_password_hash,
    };
    let err = apis::slowdown_api::add_slowdown_key(&configuration, invalid_slowdown_key)
        .await
        .unwrap_err();
    let Error::ResponseError(err) = err else {
        panic!("Wrong error type: {:?}", err)
    };
    assert_eq!(
        err.status,
        StatusCode::BAD_REQUEST,
        "Invalid hash format should return BAD_REQUEST"
    ); // This is the expected behavior.

    clean_test_setup(tables).await;
}

#[tokio::test]
async fn slowdown_key_with_custom_argon2_parameters_works() {
    let (configuration, tables) = new_test_setup().await;

    // Set some limits first (needed for calculate_slow_mode_limits to work)
    let limits = Limits {
        available_to_withdraw: Some(Some(10000)),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(Some(1_000_000_000)),
        rolling_withdrawal_blocks: Some(Some(10)),
        rolling_withdrawal_cap: Some(Some(10_000_000_000)),
        slow_mode_initiator: Some(None),
        account_caps: HashMap::new(),
    };
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    let _ = apis::limits_api::set_limits(&configuration, limits.clone())
        .await
        .unwrap();

    let key_name = "custom_argon2_key".to_string();
    let secret = "my_super_secret_password".to_string();

    // Generate an Argon2 hash with custom parameters
    let salt = SaltString::generate(&mut OsRng);
    let argon2_custom = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(1024, 2, 4, None).unwrap(), // Custom parameters
    );
    let hash = argon2_custom
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let slowdown_key = SlowdownKey {
        name: key_name.clone(),
        hash: hash.clone(),
    };
    let slowdown_reqwest = SlowdownReqwest { hash, secret: secret.clone() };

    // Add the slowdown key with custom Argon2 hash
    apis::slowdown_api::add_slowdown_key(&configuration, slowdown_key)
        .await
        .unwrap();

    // Attempt to start slow mode with the registered key
    let result = apis::slowdown_api::start_slowdown(&configuration, slowdown_reqwest).await;

    assert!(
        result.is_ok(),
        "Failed to start slow mode with custom Argon2 parameters: {:?}",
        result.unwrap_err()
    );

    // Verify that limits indeed changed to slow mode limits
    let new_limits = apis::limits_api::get_limits(&configuration).await.unwrap();
    assert_eq!(
        new_limits.per_withdrawal_cap.unwrap().unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_PER_WITHDRAWAL_CAP
    );
    assert_eq!(
        new_limits.rolling_withdrawal_blocks.unwrap().unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_ROLLING_WINDOW
    );
    assert_eq!(
        new_limits.rolling_withdrawal_cap.unwrap().unwrap(),
        emily_handler::api::handlers::slowdown::SLOW_MODE_ROLLING_CAP
    );

    clean_test_setup(tables).await;
}
