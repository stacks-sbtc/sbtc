use std::str::FromStr as _;
use std::time::Duration;

use blockstack_lib::chainstate::stacks::SinglesigHashMode;
use blockstack_lib::chainstate::stacks::SinglesigSpendingCondition;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TokenTransferMemo;
use blockstack_lib::chainstate::stacks::TransactionAnchorMode;
use blockstack_lib::chainstate::stacks::TransactionAuth;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPublicKeyEncoding;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use blockstack_lib::chainstate::stacks::TransactionVersion;
use clarity::consts::CHAIN_ID_TESTNET;
use clarity::types::chainstate::StacksAddress;
use clarity::util::secp256k1::MessageSignature;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::QualifiedContractIdentifier;
use signer::signature::RecoverableEcdsaSignature as _;
use signer::stacks::api::StacksClient;
use signer::stacks::contracts::AsTxPayload as _;
use signer::util::FutureExt as _;
use stacks_common::address::AddressHashMode;
use stacks_common::address::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;

// This is one of the generic accounts defined in the stacks miner config used
// for tests.
// Address: ST1YEHRRYJ4GF9CYBFFN0ZVCXX1APSBEEQ5KEDN7M
const FAUCET_PRIVATE_KEY: &str = "e26e611fc92fe535c5e2e58a6a446375bb5e3b471440af21bbe327384befb50a";

/// Timeout used when waiting for something to happen on Stacks
const STACKS_NODE_TIMEOUT: Duration = Duration::from_secs(10);
/// Polling used when waiting for something to happen on Stacks
const STACKS_NODE_POLLING: Duration = Duration::from_millis(200);

// Wait until the uSTX balance of an address satisfies a predicate, or panic on timeout
pub async fn wait_for_stx_balance<F>(
    stacks_client: &StacksClient,
    address: &StacksAddress,
    predicate: F,
) where
    F: Fn(u128) -> bool,
{
    let polling_fut = async {
        while !predicate(stacks_client.get_account(address).await.unwrap().balance) {
            tokio::time::sleep(STACKS_NODE_POLLING).await;
        }
    };
    polling_fut
        .with_timeout(STACKS_NODE_TIMEOUT)
        .await
        .expect("failed to wait for stx balance");
}

// Wait until the nonce of an address changes, or panic on timeout
pub async fn wait_for_new_nonce(
    stacks_client: &StacksClient,
    address: &StacksAddress,
    old_nonce: u64,
) {
    let polling_fut = async {
        while stacks_client.get_account(address).await.unwrap().nonce <= old_nonce {
            tokio::time::sleep(STACKS_NODE_POLLING).await;
        }
    };
    polling_fut
        .with_timeout(STACKS_NODE_TIMEOUT)
        .await
        .expect("failed to wait for new nonce");
}

pub fn principal_to_address(principal: &PrincipalData) -> StacksAddress {
    let principal = match principal {
        PrincipalData::Standard(addr) => addr.clone(),
        PrincipalData::Contract(QualifiedContractIdentifier { issuer, .. }) => issuer.clone(),
    };
    StacksAddress::from(principal)
}

pub async fn fund_stx(
    stacks_client: &StacksClient,
    recipient: &PrincipalData,
    ustx: u64,
) -> StacksTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), ustx, TokenTransferMemo([0u8; 34]));
    create_stacks_tx(stacks_client, payload, FAUCET_PRIVATE_KEY.to_owned()).await
}

async fn create_stacks_tx(
    stacks_client: &StacksClient,
    payload: TransactionPayload,
    sender_sk: String,
) -> StacksTransaction {
    let private_key = signer::keys::PrivateKey::from_str(&sender_sk).unwrap();
    let public_key = signer::keys::PublicKey::from_private_key(&private_key);

    let sender_addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![public_key.into()],
    )
    .expect("failed to construct the stacks address");

    let nonce = stacks_client
        .get_account(&sender_addr)
        .await
        .expect("cannot get account nonce")
        .nonce;

    let conditions = payload.post_conditions();

    let auth = SinglesigSpendingCondition {
        signer: sender_addr.bytes().clone(),
        nonce,
        tx_fee: 1000,
        hash_mode: SinglesigHashMode::P2PKH,
        key_encoding: TransactionPublicKeyEncoding::Compressed,
        signature: MessageSignature::empty(),
    };

    let mut tx = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(auth)),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: conditions.post_condition_mode,
        post_conditions: conditions.post_conditions,
        payload: payload.tx_payload(),
    };

    let signature = signer::signature::sign_stacks_tx(&tx, &private_key).as_stacks_sig();
    match tx.auth {
        TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(ref mut auth)) => {
            auth.set_signature(signature)
        }
        _ => panic!("unexpected tx auth"),
    }

    tx
}
