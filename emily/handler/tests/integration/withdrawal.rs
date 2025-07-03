use std::cmp::Ordering;
use std::collections::HashMap;

use test_case::test_case;

use testing_emily_client::apis;
use testing_emily_client::apis::chainstate_api::set_chainstate;
use testing_emily_client::apis::configuration::Configuration;
use testing_emily_client::models::{
    Chainstate, CreateWithdrawalRequestBody, Fulfillment, UpdateWithdrawalsRequestBody, Withdrawal,
    WithdrawalInfo, WithdrawalParameters, WithdrawalStatus, WithdrawalUpdate,
};

use crate::common::clean_setup;

const RECIPIENT: &str = "TEST_RECIPIENT";
const SENDER: &str = "TEST_SENDER";
const BLOCK_HASH: &str = "TEST_BLOCK_HASH";
const BLOCK_HEIGHT: u64 = 0;
const INITIAL_WITHDRAWAL_STATUS_MESSAGE: &str = "Just received withdrawal";

/// An arbitrary fully ordered partial cmp comparator for WithdrawalInfos.
/// This is useful for sorting vectors of withdrawal infos so that vectors with
/// the same elements will be considered equal in a test assert.
fn arbitrary_withdrawal_info_partial_cmp(a: &WithdrawalInfo, b: &WithdrawalInfo) -> Ordering {
    let a_str: String = format!("{}-{}", a.stacks_block_hash, a.request_id);
    let b_str: String = format!("{}-{}", b.stacks_block_hash, b.request_id);
    b_str
        .partial_cmp(&a_str)
        .expect("Failed to compare two strings that should be comparable")
}

/// An arbitrary fully ordered partial cmp comparator for Withdrawals.
/// This is useful for sorting vectors of withdrawal so that vectors with
/// the same elements will be considered equal in a test assert.
fn arbitrary_withdrawal_partial_cmp(a: &Withdrawal, b: &Withdrawal) -> Ordering {
    let a_str: String = format!("{}-{}", a.stacks_block_hash, a.request_id);
    let b_str: String = format!("{}-{}", b.stacks_block_hash, b.request_id);
    b_str
        .partial_cmp(&a_str)
        .expect("Failed to compare two strings that should be comparable")
}

/// Makes a bunch of withdrawals.
async fn batch_create_withdrawals(
    configuration: &Configuration,
    create_requests: Vec<CreateWithdrawalRequestBody>,
) -> Vec<Withdrawal> {
    let mut created: Vec<Withdrawal> = Vec::with_capacity(create_requests.len());
    for request in create_requests {
        created.push(
            apis::withdrawal_api::create_withdrawal(configuration, request)
                .await
                .expect(
                    "Received an error after making a valid create withdrawal request api call.",
                ),
        );
    }
    created
}

#[tokio::test]
async fn create_and_get_withdrawal_happy_path() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };
    let request_id = 1;

    let request = CreateWithdrawalRequestBody {
        amount,
        parameters: Box::new(parameters.clone()),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id,
        stacks_block_hash: BLOCK_HASH.into(),
        stacks_block_height: BLOCK_HEIGHT,
        txid: "test_txid".to_string(),
    };

    let expected = Withdrawal {
        amount,
        fulfillment: None,
        last_update_block_hash: BLOCK_HASH.into(),
        last_update_height: BLOCK_HEIGHT,
        parameters: Box::new(parameters.clone()),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id,
        stacks_block_hash: BLOCK_HASH.into(),
        stacks_block_height: BLOCK_HEIGHT,
        status: WithdrawalStatus::Pending,
        status_message: INITIAL_WITHDRAWAL_STATUS_MESSAGE.into(),
        txid: "test_txid".to_string(),
    };

    // Act.
    // ----
    let created = apis::withdrawal_api::create_withdrawal(&configuration, request)
        .await
        .expect("Received an error after making a valid create withdrawal request api call.");

    let gotten = apis::withdrawal_api::get_withdrawal(&configuration, request_id)
        .await
        .expect("Received an error after making a valid get withdrawal request api call.");

    // Assert.
    // -------
    assert_eq!(expected, created);
    assert_eq!(expected, gotten);
}

#[tokio::test]
async fn get_withdrawals() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let withdrawal_request_ids = vec![1, 2, 3, 4, 5, 6];
    let mut create_requests: Vec<CreateWithdrawalRequestBody> = Vec::new();
    let mut expected_withdrawal_infos: Vec<WithdrawalInfo> = Vec::new();

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    for request_id in withdrawal_request_ids {
        let request = CreateWithdrawalRequestBody {
            amount,
            parameters: Box::new(parameters.clone()),
            recipient: RECIPIENT.into(),
            sender: SENDER.into(),
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
            txid: "test_txid".to_string(),
        };
        create_requests.push(request);

        let expected_withdrawal_info = WithdrawalInfo {
            amount,
            last_update_block_hash: BLOCK_HASH.into(),
            last_update_height: BLOCK_HEIGHT,
            recipient: RECIPIENT.into(),
            sender: SENDER.into(),
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
            status: WithdrawalStatus::Pending,
            txid: "test_txid".to_string(),
        };
        expected_withdrawal_infos.push(expected_withdrawal_info);
    }

    let chunksize = 2;
    // If the number of elements is an exact multiple of the chunk size the "final"
    // query will still have a next token, and the next query will now have a next
    // token and will return no additional data.
    let expected_chunks = expected_withdrawal_infos.len() / chunksize + 1;

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    let status = testing_emily_client::models::WithdrawalStatus::Pending;
    let mut next_token: Option<String> = None;
    let mut gotten_withdrawal_info_chunks: Vec<Vec<WithdrawalInfo>> = Vec::new();
    loop {
        let response = apis::withdrawal_api::get_withdrawals(
            &configuration,
            status,
            next_token.as_deref(),
            Some(chunksize as u32),
        )
        .await
        .expect("Received an error after making a valid get withdrawal api call.");
        gotten_withdrawal_info_chunks.push(response.withdrawals);
        // If there's no next token then break.
        next_token = match response.next_token.flatten() {
            Some(token) => Some(token),
            None => break,
        };
    }

    // Assert.
    // -------
    assert_eq!(expected_chunks, gotten_withdrawal_info_chunks.len());
    let max_chunk_size = gotten_withdrawal_info_chunks
        .iter()
        .map(|chunk| chunk.len())
        .max()
        .unwrap();
    assert!(chunksize >= max_chunk_size);

    let mut gotten_withdrawal_infos = gotten_withdrawal_info_chunks
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    expected_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
    gotten_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
    assert_eq!(expected_withdrawal_infos, gotten_withdrawal_infos);
}

#[tokio::test]
async fn get_withdrawals_by_recipient() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let recipients = vec!["recipient_1", "recipient_2", "recipient_3"];
    let withdrawals_per_recipient = 5;
    let mut create_requests: Vec<CreateWithdrawalRequestBody> = Vec::new();
    let mut expected_recipient_data: HashMap<String, Vec<WithdrawalInfo>> = HashMap::new();

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    let mut request_id = 1;
    for recipient in recipients {
        let mut expected_withdrawal_infos: Vec<WithdrawalInfo> = Vec::new();
        for _ in 1..=withdrawals_per_recipient {
            let request = CreateWithdrawalRequestBody {
                amount,
                parameters: Box::new(parameters.clone()),
                recipient: recipient.into(),
                sender: SENDER.into(),
                request_id,
                stacks_block_hash: BLOCK_HASH.into(),
                stacks_block_height: BLOCK_HEIGHT,
                txid: "test_txid".to_string(),
            };
            create_requests.push(request);

            let expected_withdrawal_info = WithdrawalInfo {
                amount,
                last_update_block_hash: BLOCK_HASH.into(),
                last_update_height: BLOCK_HEIGHT,
                recipient: recipient.into(),
                sender: SENDER.into(),
                request_id,
                stacks_block_hash: BLOCK_HASH.into(),
                stacks_block_height: BLOCK_HEIGHT,
                status: WithdrawalStatus::Pending,
                txid: "test_txid".to_string(),
            };
            request_id += 1;
            expected_withdrawal_infos.push(expected_withdrawal_info);
        }
        // Add the recipient data to the recipient data hashmap that stores what
        // we expect to see from the recipient.
        expected_recipient_data.insert(recipient.to_string(), expected_withdrawal_infos.clone());
    }

    let chunksize = 2;

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    let mut actual_recipient_data: HashMap<String, Vec<WithdrawalInfo>> = HashMap::new();
    for recipient in expected_recipient_data.keys() {
        let mut gotten_withdrawal_info_chunks: Vec<Vec<WithdrawalInfo>> = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let response = apis::withdrawal_api::get_withdrawals_for_recipient(
                &configuration,
                recipient,
                next_token.as_deref(),
                Some(chunksize as u32),
            )
            .await
            .expect("Received an error after making a valid get withdrawal api call.");
            gotten_withdrawal_info_chunks.push(response.withdrawals);
            // If there's no next token then break.
            next_token = match response.next_token.flatten() {
                Some(token) => Some(token),
                None => break,
            };
        }
        // Store the actual data received from the api.
        actual_recipient_data.insert(
            recipient.clone(),
            gotten_withdrawal_info_chunks
                .into_iter()
                .flatten()
                .collect(),
        );
    }

    // Assert.
    // -------
    for recipient in expected_recipient_data.keys() {
        let mut expected_withdrawal_infos = expected_recipient_data.get(recipient).unwrap().clone();
        expected_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
        let mut actual_withdrawal_infos = actual_recipient_data.get(recipient).unwrap().clone();
        actual_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
        // Assert that the expected and actual withdrawal infos are the same.
        assert_eq!(expected_withdrawal_infos, actual_withdrawal_infos);
    }
}

#[tokio::test]
async fn get_withdrawals_by_sender() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let senders = vec![
        "SN1Z0WW5SMN4J99A1G1725PAB8H24CWNA7Z8H7214.my-contract",
        "SN1Z0WW5SMN4J99A1G1725PAB8H24CWNA7Z8H7214",
    ];
    let withdrawals_per_sender = 5;
    let mut create_requests: Vec<CreateWithdrawalRequestBody> = Vec::new();
    let mut expected_sender_data: HashMap<String, Vec<WithdrawalInfo>> = HashMap::new();

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    let mut request_id = 1;
    for sender in senders {
        let mut expected_withdrawal_infos: Vec<WithdrawalInfo> = Vec::new();
        for _ in 1..=withdrawals_per_sender {
            let request = CreateWithdrawalRequestBody {
                amount,
                parameters: Box::new(parameters.clone()),
                recipient: RECIPIENT.into(),
                sender: sender.into(),
                request_id,
                stacks_block_hash: BLOCK_HASH.into(),
                stacks_block_height: BLOCK_HEIGHT,
                txid: "test_txid".to_string(),
            };
            create_requests.push(request);

            let expected_withdrawal_info = WithdrawalInfo {
                amount,
                last_update_block_hash: BLOCK_HASH.into(),
                last_update_height: BLOCK_HEIGHT,
                recipient: RECIPIENT.into(),
                sender: sender.into(),
                request_id,
                stacks_block_hash: BLOCK_HASH.into(),
                stacks_block_height: BLOCK_HEIGHT,
                status: WithdrawalStatus::Pending,
                txid: "test_txid".to_string(),
            };
            request_id += 1;
            expected_withdrawal_infos.push(expected_withdrawal_info);
        }
        // Add the sender data to the sender data hashmap that stores what
        // we expect to see from the sender.
        expected_sender_data.insert(sender.to_string(), expected_withdrawal_infos.clone());
    }

    let chunksize = 2;

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    let mut actual_sender_data: HashMap<String, Vec<WithdrawalInfo>> = HashMap::new();
    for sender in expected_sender_data.keys() {
        let mut gotten_withdrawal_info_chunks: Vec<Vec<WithdrawalInfo>> = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let response = apis::withdrawal_api::get_withdrawals_for_sender(
                &configuration,
                sender,
                next_token.as_deref(),
                Some(chunksize as u32),
            )
            .await
            .expect("Received an error after making a valid get withdrawal api call.");
            gotten_withdrawal_info_chunks.push(response.withdrawals);
            // If there's no next token then break.
            next_token = match response.next_token.flatten() {
                Some(token) => Some(token),
                None => break,
            };
        }
        // Store the actual data received from the api.
        actual_sender_data.insert(
            sender.clone(),
            gotten_withdrawal_info_chunks
                .into_iter()
                .flatten()
                .collect(),
        );
    }

    // Assert.
    // -------
    for recipient in expected_sender_data.keys() {
        let mut expected_withdrawal_infos = expected_sender_data.get(recipient).unwrap().clone();
        expected_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
        let mut actual_withdrawal_infos = actual_sender_data.get(recipient).unwrap().clone();
        actual_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
        // Assert that the expected and actual withdrawal infos are the same.
        assert_eq!(expected_withdrawal_infos, actual_withdrawal_infos);
    }
}

#[tokio::test]
async fn update_withdrawals() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let withdrawal_request_ids = vec![1, 2, 3, 4, 5, 7, 9, 111];

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    let update_status_message: &str = "test_status_message";
    let update_chainstate = Chainstate {
        stacks_block_hash: "update_block_hash".to_string(),
        stacks_block_height: 42,
        bitcoin_block_height: Some(Some(42)),
    };
    let update_status = WithdrawalStatus::Confirmed;

    let update_fulfillment: Fulfillment = Fulfillment {
        bitcoin_block_hash: "bitcoin_block_hash".to_string(),
        bitcoin_block_height: 23,
        bitcoin_tx_index: 45,
        bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
        btc_fee: 2314,
        stacks_txid: "test_fulfillment_stacks_txid".to_string(),
    };

    let mut create_requests: Vec<CreateWithdrawalRequestBody> =
        Vec::with_capacity(withdrawal_request_ids.len());
    let mut withdrawal_updates: Vec<WithdrawalUpdate> =
        Vec::with_capacity(withdrawal_request_ids.len());
    let mut expected_withdrawals: Vec<Withdrawal> =
        Vec::with_capacity(withdrawal_request_ids.len());
    for request_id in withdrawal_request_ids {
        let request = CreateWithdrawalRequestBody {
            amount,
            parameters: Box::new(parameters.clone()),
            recipient: RECIPIENT.into(),
            sender: SENDER.into(),
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
            txid: "test_txid".to_string(),
        };
        create_requests.push(request);

        let withdrawal_update = WithdrawalUpdate {
            request_id,
            fulfillment: Some(Some(Box::new(update_fulfillment.clone()))),
            status: update_status,
            status_message: update_status_message.into(),
        };
        withdrawal_updates.push(withdrawal_update);

        let expected = Withdrawal {
            amount,
            fulfillment: Some(Some(Box::new(update_fulfillment.clone()))),
            last_update_block_hash: update_chainstate.stacks_block_hash.clone(),
            last_update_height: update_chainstate.stacks_block_height,
            parameters: Box::new(parameters.clone()),
            recipient: RECIPIENT.into(),
            sender: SENDER.into(),
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
            status: update_status,
            status_message: update_status_message.into(),
            txid: "test_txid".to_string(),
        };
        expected_withdrawals.push(expected);
    }

    let update_request = UpdateWithdrawalsRequestBody {
        withdrawals: withdrawal_updates,
    };

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    // Not strictly necessary, but we do it to make sure that the updates
    // are connected with the current chainstate.
    set_chainstate(&configuration, update_chainstate.clone())
        .await
        .expect("Received an error after making a valid set chainstate api call.");

    let update_withdrawals_response =
        apis::withdrawal_api::update_withdrawals_sidecar(&configuration, update_request)
            .await
            .expect("Received an error after making a valid update withdrawals api call.");

    // Assert.
    // -------
    let mut updated_withdrawals = update_withdrawals_response
        .withdrawals
        .iter()
        .map(|withdrawal| *withdrawal.withdrawal.clone().unwrap().unwrap())
        .collect::<Vec<_>>();
    updated_withdrawals.sort_by(arbitrary_withdrawal_partial_cmp);
    expected_withdrawals.sort_by(arbitrary_withdrawal_partial_cmp);
    assert_eq!(expected_withdrawals, updated_withdrawals);
}

#[test_case(WithdrawalStatus::Pending, WithdrawalStatus::Pending, true; "pending_to_pending")]
#[test_case(WithdrawalStatus::Pending, WithdrawalStatus::Accepted, false; "pending_to_accepted")]
#[test_case(WithdrawalStatus::Pending, WithdrawalStatus::Confirmed, true; "pending_to_confirmed")]
#[test_case(WithdrawalStatus::Pending, WithdrawalStatus::Failed, true; "pending_to_failed")]
#[test_case(WithdrawalStatus::Accepted, WithdrawalStatus::Pending, true; "accepted_to_pending")]
#[test_case(WithdrawalStatus::Failed, WithdrawalStatus::Pending, true; "failed_to_pending")]
#[test_case(WithdrawalStatus::Confirmed, WithdrawalStatus::Pending, true; "confirmed_to_pending")]
#[test_case(WithdrawalStatus::Accepted, WithdrawalStatus::Accepted, false; "accepted_to_accepted")]
#[test_case(WithdrawalStatus::Failed, WithdrawalStatus::Accepted, true; "failed_to_accepted")]
#[test_case(WithdrawalStatus::Confirmed, WithdrawalStatus::Accepted, true; "confirmed_to_accepted")]
#[tokio::test]
async fn update_withdrawals_is_forbidden_for_signer(
    previous_status: WithdrawalStatus,
    new_status: WithdrawalStatus,
    is_forbidden: bool,
) {
    // the testing configuration has privileged access to all endpoints.
    let testing_configuration = clean_setup().await;

    // the user configuration access depends on the api_key.
    let user_configuration = testing_configuration.clone();
    // Arrange.
    // --------
    let request_id = 1;

    let chainstate = Chainstate {
        stacks_block_hash: "test_block_hash".to_string(),
        stacks_block_height: 1,
        bitcoin_block_height: Some(Some(1)),
    };

    set_chainstate(&testing_configuration, chainstate.clone())
        .await
        .expect("Received an error after making a valid set chainstate api call.");

    // Setup test withdrawal transaction.
    let request = CreateWithdrawalRequestBody {
        amount: 10000,
        parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id,
        stacks_block_hash: chainstate.stacks_block_hash.clone(),
        stacks_block_height: chainstate.stacks_block_height,
        txid: "test_txid".to_string(),
    };

    // Create the withdrawal with the privileged configuration.
    apis::withdrawal_api::create_withdrawal(&testing_configuration, request.clone())
        .await
        .expect("Received an error after making a valid create withdrawal request api call.");

    // Update the withdrawal status with the privileged configuration.
    if previous_status != WithdrawalStatus::Pending {
        let mut fulfillment: Option<Option<Box<Fulfillment>>> = None;

        if previous_status == WithdrawalStatus::Confirmed {
            fulfillment = Some(Some(Box::new(Fulfillment {
                bitcoin_block_hash: "bitcoin_block_hash".to_string(),
                bitcoin_block_height: 23,
                bitcoin_tx_index: 45,
                bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
                btc_fee: 2314,
                stacks_txid: "test_fulfillment_stacks_txid".to_string(),
            })));
        }

        apis::withdrawal_api::update_withdrawals_sidecar(
            &testing_configuration,
            UpdateWithdrawalsRequestBody {
                withdrawals: vec![WithdrawalUpdate {
                    request_id,
                    fulfillment,
                    status: previous_status,
                    status_message: "foo".into(),
                }],
            },
        )
        .await
        .expect("Received an error after making a valid update withdrawal api call.");
    }

    let mut fulfillment: Option<Option<Box<Fulfillment>>> = None;

    if new_status == WithdrawalStatus::Confirmed {
        fulfillment = Some(Some(Box::new(Fulfillment {
            bitcoin_block_hash: "bitcoin_block_hash".to_string(),
            bitcoin_block_height: 23,
            bitcoin_tx_index: 45,
            bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
            btc_fee: 2314,
            stacks_txid: "test_fulfillment_stacks_txid".to_string(),
        })));
    }

    let response = apis::withdrawal_api::update_withdrawals_signer(
        &user_configuration,
        UpdateWithdrawalsRequestBody {
            withdrawals: vec![WithdrawalUpdate {
                request_id,
                fulfillment,
                status: new_status,
                status_message: "foo".into(),
            }],
        },
    )
    .await;

    if is_forbidden {
        // Check response correctness.
        let response = response.expect("Batch update should return 200 OK");
        let withdrawals = response.withdrawals;
        assert_eq!(withdrawals.len(), 1);
        let withdrawal = withdrawals.first().unwrap();
        assert_eq!(withdrawal.status, 403);
        assert!(withdrawal.withdrawal.clone().unwrap().is_none());
        assert_eq!(withdrawal.error.clone().unwrap().unwrap(), "Forbidden");

        // Check withdrawal wasn't updated
        let response = apis::withdrawal_api::get_withdrawal(&user_configuration, request_id)
            .await
            .expect("Received an error after making a valid get withdrawal api call.");
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.status, previous_status);
    } else {
        assert!(response.is_ok());
        let response = response.unwrap();
        let withdrawal = response
            .withdrawals
            .first()
            .expect("No withdrawal in response")
            .withdrawal
            .clone()
            .unwrap()
            .unwrap();
        assert_eq!(withdrawal.request_id, request_id);
        assert_eq!(withdrawal.status, new_status);
    }
}

#[test_case(WithdrawalStatus::Pending, WithdrawalStatus::Accepted; "pending_to_accepted")]
#[test_case(WithdrawalStatus::Pending, WithdrawalStatus::Pending; "pending_to_pending")]
#[test_case(WithdrawalStatus::Pending, WithdrawalStatus::Confirmed; "pending_to_confirmed")]
#[test_case(WithdrawalStatus::Pending, WithdrawalStatus::Failed; "pending_to_failed")]
#[test_case(WithdrawalStatus::Confirmed, WithdrawalStatus::Pending; "confirmed_to_pending")]
#[tokio::test]
async fn update_withdrawals_is_not_forbidden_for_sidecar(
    previous_status: WithdrawalStatus,
    new_status: WithdrawalStatus,
) {
    // the testing configuration has privileged access to all endpoints.
    let testing_configuration = clean_setup().await;

    // the user configuration access depends on the api_key.
    let user_configuration = testing_configuration.clone();
    // Arrange.
    // --------
    let request_id = 1;

    let chainstate = Chainstate {
        stacks_block_hash: "test_block_hash".to_string(),
        stacks_block_height: 1,
        bitcoin_block_height: Some(Some(1)),
    };

    set_chainstate(&testing_configuration, chainstate.clone())
        .await
        .expect("Received an error after making a valid set chainstate api call.");

    // Setup test withdrawal transaction.
    let request = CreateWithdrawalRequestBody {
        amount: 10000,
        parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id,
        stacks_block_hash: chainstate.stacks_block_hash.clone(),
        stacks_block_height: chainstate.stacks_block_height,
        txid: "test_txid".to_string(),
    };

    // Create the withdrawal with the privileged configuration.
    apis::withdrawal_api::create_withdrawal(&testing_configuration, request.clone())
        .await
        .expect("Received an error after making a valid create withdrawal request api call.");

    // Update the withdrawal status with the privileged configuration.
    if previous_status != WithdrawalStatus::Pending {
        let mut fulfillment: Option<Option<Box<Fulfillment>>> = None;

        if previous_status == WithdrawalStatus::Confirmed {
            fulfillment = Some(Some(Box::new(Fulfillment {
                bitcoin_block_hash: "bitcoin_block_hash".to_string(),
                bitcoin_block_height: 23,
                bitcoin_tx_index: 45,
                bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
                btc_fee: 2314,
                stacks_txid: "test_fulfillment_stacks_txid".to_string(),
            })));
        }

        apis::withdrawal_api::update_withdrawals_sidecar(
            &testing_configuration,
            UpdateWithdrawalsRequestBody {
                withdrawals: vec![WithdrawalUpdate {
                    request_id,
                    fulfillment,
                    status: previous_status,
                    status_message: "foo".into(),
                }],
            },
        )
        .await
        .expect("Received an error after making a valid update withdrawal api call.");
    }

    let mut fulfillment: Option<Option<Box<Fulfillment>>> = None;

    if new_status == WithdrawalStatus::Confirmed {
        fulfillment = Some(Some(Box::new(Fulfillment {
            bitcoin_block_hash: "bitcoin_block_hash".to_string(),
            bitcoin_block_height: 23,
            bitcoin_tx_index: 45,
            bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
            btc_fee: 2314,
            stacks_txid: "test_fulfillment_stacks_txid".to_string(),
        })));
    }

    let response = apis::withdrawal_api::update_withdrawals_sidecar(
        &user_configuration,
        UpdateWithdrawalsRequestBody {
            withdrawals: vec![WithdrawalUpdate {
                request_id,
                fulfillment,
                status: new_status,
                status_message: "foo".into(),
            }],
        },
    )
    .await;

    assert!(response.is_ok());
    let response = response.unwrap();
    let withdrawal = response
        .withdrawals
        .first()
        .expect("No withdrawal in response")
        .withdrawal
        .clone()
        .unwrap()
        .unwrap();
    assert_eq!(withdrawal.request_id, request_id);
    assert_eq!(withdrawal.status, new_status);
}

#[tokio::test]
async fn emily_process_withdrawal_updates_when_some_of_them_already_accepted() {
    // the testing configuration has privileged access to all endpoints.
    let testing_configuration = clean_setup().await;

    // Create two withdrawals
    let chainstate = Chainstate {
        stacks_block_hash: "test_block_hash".to_string(),
        stacks_block_height: 1,
        bitcoin_block_height: Some(Some(1)),
    };

    set_chainstate(&testing_configuration, chainstate.clone())
        .await
        .expect("Received an error after making a valid set chainstate api call.");

    let create_withdrawal_body1 = CreateWithdrawalRequestBody {
        amount: 10000,
        parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id: 1,
        stacks_block_hash: chainstate.stacks_block_hash.clone(),
        stacks_block_height: chainstate.stacks_block_height,
        txid: "test_txid".to_string(),
    };

    let create_withdrawal_body2 = CreateWithdrawalRequestBody {
        amount: 10000,
        parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id: 2,
        stacks_block_hash: chainstate.stacks_block_hash.clone(),
        stacks_block_height: chainstate.stacks_block_height,
        txid: "test_txid2".to_string(),
    };

    // Sanity check that the two withdrawals are different.
    assert_ne!(
        create_withdrawal_body1.request_id, create_withdrawal_body2.request_id,
        "The two withdrawals should have different request ids."
    );
    assert_ne!(
        create_withdrawal_body1.txid, create_withdrawal_body2.txid,
        "The two withdrawals should have different transaction hex."
    );

    apis::withdrawal_api::create_withdrawal(
        &testing_configuration,
        create_withdrawal_body1.clone(),
    )
    .await
    .expect("Received an error after making a valid create withdrawal request api call.");
    apis::withdrawal_api::create_withdrawal(
        &testing_configuration,
        create_withdrawal_body2.clone(),
    )
    .await
    .expect("Received an error after making a valid create withdrawal request api call.");

    // Now we should have 2 pending withdrawals.
    let withdrawals = apis::withdrawal_api::get_withdrawals(
        &testing_configuration,
        WithdrawalStatus::Pending,
        None,
        None,
    )
    .await
    .expect("Received an error after making a valid get withdrawals api call.");
    assert_eq!(withdrawals.withdrawals.len(), 2);

    // Update first withdrawal to Accepted.
    let update_withdrawals_request_body = UpdateWithdrawalsRequestBody {
        withdrawals: vec![WithdrawalUpdate {
            request_id: create_withdrawal_body1.request_id,
            fulfillment: None,
            status: WithdrawalStatus::Accepted,
            status_message: "First update".into(),
        }],
    };
    let response = apis::withdrawal_api::update_withdrawals_signer(
        &testing_configuration,
        update_withdrawals_request_body,
    )
    .await
    .expect("Received an error after making a valid update withdrawal request api call.");

    assert!(
        response
            .withdrawals
            .iter()
            .all(|withdrawal| withdrawal.status == 200)
    );
    assert_eq!(response.withdrawals.len(), 1);

    // Now we should have 1 pending and 1 accepted withdrawal.
    let withdrawals = apis::withdrawal_api::get_withdrawals(
        &testing_configuration,
        WithdrawalStatus::Pending,
        None,
        None,
    )
    .await
    .expect("Received an error after making a valid get withdrawals api call.");
    assert_eq!(withdrawals.withdrawals.len(), 1);
    let withdrawals = apis::withdrawal_api::get_withdrawals(
        &testing_configuration,
        WithdrawalStatus::Accepted,
        None,
        None,
    )
    .await
    .expect("Received an error after making a valid get withdrawals api call.");
    assert_eq!(withdrawals.withdrawals.len(), 1);

    // Now we update both withdrawals to Accepted in a batch. This still should be a valid api call.
    let update_withdrawals_request_body = UpdateWithdrawalsRequestBody {
        withdrawals: vec![
            WithdrawalUpdate {
                request_id: create_withdrawal_body1.request_id,
                fulfillment: None,
                status: WithdrawalStatus::Accepted,
                status_message: "Second update".into(),
            },
            WithdrawalUpdate {
                request_id: create_withdrawal_body2.request_id,
                fulfillment: None,
                status: WithdrawalStatus::Accepted,
                status_message: "Second update".into(),
            },
        ],
    };
    let response = apis::withdrawal_api::update_withdrawals_signer(
        &testing_configuration,
        update_withdrawals_request_body,
    )
    .await
    .expect("Received an error after making a valid update withdrawal request api call.");

    assert!(
        response
            .withdrawals
            .iter()
            .all(|withdrawal| withdrawal.status == 200)
    );
    assert_eq!(response.withdrawals.len(), 2);

    // Now we should have 2 accepted withdrawals.
    let withdrawals = apis::withdrawal_api::get_withdrawals(
        &testing_configuration,
        WithdrawalStatus::Accepted,
        None,
        None,
    )
    .await
    .expect("Received an error after making a valid get withdrawals api call.");
    assert_eq!(withdrawals.withdrawals.len(), 2);
}

#[tokio::test]
async fn emily_process_withdrawal_updates_when_some_of_them_are_unknown() {
    // the testing configuration has privileged access to all endpoints.
    let testing_configuration = clean_setup().await;

    // Create two withdrawals
    let chainstate = Chainstate {
        stacks_block_hash: "test_block_hash".to_string(),
        stacks_block_height: 1,
        bitcoin_block_height: Some(Some(1)),
    };

    set_chainstate(&testing_configuration, chainstate.clone())
        .await
        .expect("Received an error after making a valid set chainstate api call.");

    let create_withdrawal_body1 = CreateWithdrawalRequestBody {
        amount: 10000,
        parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id: 1,
        stacks_block_hash: chainstate.stacks_block_hash.clone(),
        stacks_block_height: chainstate.stacks_block_height,
        txid: "test_txid".to_string(),
    };

    let create_withdrawal_body2 = CreateWithdrawalRequestBody {
        amount: 10000,
        parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id: 2,
        stacks_block_hash: chainstate.stacks_block_hash.clone(),
        stacks_block_height: chainstate.stacks_block_height,
        txid: "test_txid2".to_string(),
    };

    // Sanity check that the two withdrawals are different.
    assert_ne!(
        create_withdrawal_body1.request_id, create_withdrawal_body2.request_id,
        "The two withdrawals should have different request ids."
    );
    assert_ne!(
        create_withdrawal_body1.txid, create_withdrawal_body2.txid,
        "The two withdrawals should have different transaction hex."
    );

    apis::withdrawal_api::create_withdrawal(
        &testing_configuration,
        create_withdrawal_body1.clone(),
    )
    .await
    .expect("Received an error after making a valid create withdrawal request api call.");

    // Now we should have 1 pending withdrawal.
    let withdrawals = apis::withdrawal_api::get_withdrawals(
        &testing_configuration,
        WithdrawalStatus::Pending,
        None,
        None,
    )
    .await
    .expect("Received an error after making a valid get withdrawals api call.");
    assert_eq!(withdrawals.withdrawals.len(), 1);

    // Now we update both withdrawals to Accepted in a batch. This still should be a valid api call
    // and existing withdrawal should be updated.
    let update_withdrawals_request_body = UpdateWithdrawalsRequestBody {
        withdrawals: vec![
            WithdrawalUpdate {
                request_id: create_withdrawal_body1.request_id,
                fulfillment: None,
                status: WithdrawalStatus::Accepted,
                status_message: "Second update".into(),
            },
            WithdrawalUpdate {
                request_id: create_withdrawal_body2.request_id,
                fulfillment: None,
                status: WithdrawalStatus::Accepted,
                status_message: "Second update".into(),
            },
        ],
    };
    let update_response = apis::withdrawal_api::update_withdrawals_signer(
        &testing_configuration,
        update_withdrawals_request_body,
    )
    .await
    .expect("Received an error after making a valid update withdrawal request api call.");

    // Check that multistatus response is returned correctly.
    let [correct_update, wrong_update] = &update_response.withdrawals[..] else {
        panic!("Expected 2 items, got {:?}", update_response.withdrawals);
    };

    assert_eq!(
        correct_update
            .withdrawal
            .clone()
            .unwrap()
            .unwrap()
            .request_id,
        create_withdrawal_body1.request_id
    );
    assert_eq!(correct_update.status, 200);
    assert!(correct_update.error.clone().unwrap().is_none());

    assert!(wrong_update.withdrawal.clone().unwrap().is_none());
    assert_eq!(wrong_update.status, 404);
    assert_eq!(
        wrong_update.error.clone().unwrap().unwrap(),
        "Resource not found"
    );

    // Now we should have 1 accepted withdrawal.
    let withdrawals = apis::withdrawal_api::get_withdrawals(
        &testing_configuration,
        WithdrawalStatus::Accepted,
        None,
        None,
    )
    .await
    .expect("Received an error after making a valid get withdrawals api call.");
    assert_eq!(withdrawals.withdrawals.len(), 1);
}
