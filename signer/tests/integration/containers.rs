use std::collections::HashSet;
use std::str::FromStr as _;
use std::time::Duration;

use bitcoincore_rpc::RpcApi as _;
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
use more_asserts::assert_gt;
use sbtc::testing::containers::BitcoinContainer;
use sbtc::testing::containers::StacksContainer;
use sbtc::testing::containers::TestContainersBuilder;
use signer::bitcoin::poller::BitcoinChainTipPoller;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::signature::RecoverableEcdsaSignature as _;
use signer::stacks::api::StacksClient;
use signer::stacks::contracts::AsTxPayload as _;
use stacks_common::address::AddressHashMode;
use stacks_common::address::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;

pub trait BitcoinContainerExt {
    /// Get the Bitcoin client
    fn get_client(&self) -> BitcoinCoreClient;
    /// Start a chain tip poller for this container
    async fn start_chain_tip_poller(&self) -> BitcoinChainTipPoller;
}

impl BitcoinContainerExt for BitcoinContainer {
    fn get_client(&self) -> BitcoinCoreClient {
        self.url().try_into().expect("cannot create bitcoin client")
    }

    async fn start_chain_tip_poller(&self) -> BitcoinChainTipPoller {
        BitcoinChainTipPoller::start_new(self.get_client(), Duration::from_millis(100)).await
    }
}

pub trait StacksContainerExt {
    /// Get the Stacks client
    fn get_client(&self) -> StacksClient;
}

impl StacksContainerExt for StacksContainer {
    fn get_client(&self) -> StacksClient {
        StacksClient::new(self.url().clone()).expect("cannot create stacks client")
    }
}

#[tokio::test]
async fn test_bitcoin() {
    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;

    let rpc = bitcoin.rpc();
    let faucet = bitcoin.get_faucet();
    let client = bitcoin.get_client();

    let block = faucet.generate_block();

    assert!(rpc.get_block(&block).is_ok());
    assert_eq!(client.get_best_block_hash().unwrap(), block);
}

#[tokio::test]
async fn test_stacks() {
    let stack = TestContainersBuilder::start_stacks().await.keep_up();
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;

    let rpc = bitcoin.rpc();
    let faucet = bitcoin.get_faucet();
    let bitcoin_client = bitcoin.get_client();

    // magic sleep
    tokio::time::sleep(Duration::from_secs(5)).await;

    let block = faucet.generate_block();

    assert!(rpc.get_block(&block).is_ok());
    assert_eq!(bitcoin_client.get_best_block_hash().unwrap(), block);

    let stacks_client = stacks.get_client();

    let mut bitcoin_blocks = HashSet::new();
    let mut stacks_blocks = HashSet::new();

    for _ in 0..3 {
        let stacks_status = stacks_client
            .get_node_info()
            .await
            .expect("failed to get stacks node info");
        dbg!(&stacks_status);
        bitcoin_blocks.insert(*stacks_status.burn_block_height);
        stacks_blocks.insert(*stacks_status.stacks_tip_height);

        let recipient = PrincipalData::parse("SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS").unwrap();
        let payload = TransactionPayload::TokenTransfer(
            recipient,
            12 * 1_000_000,
            TokenTransferMemo([0u8; 34]),
        );

        let tx = create_stacks_tx(&stacks_client, payload, ALICE_PRIVATE_KEY.to_owned()).await;
        stacks_client
            .submit_tx(&tx)
            .await
            .expect("failed to send stacks transaction");
        tokio::time::sleep(Duration::from_secs(2)).await;

        faucet.generate_block();
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    dbg!(&bitcoin_blocks);
    dbg!(&stacks_blocks);

    assert_gt!(bitcoin_blocks.len(), 2);
    assert_gt!(stacks_blocks.len(), 1);

    stack.dont_keep_up();
}

const ALICE_PRIVATE_KEY: &str = "e26e611fc92fe535c5e2e58a6a446375bb5e3b471440af21bbe327384befb50a";
async fn create_stacks_tx(
    stacks_client: &StacksClient,
    payload: TransactionPayload,
    sender_sk: String,
) -> StacksTransaction {
    let private_key = signer::keys::PrivateKey::from_str(&sender_sk).unwrap();
    let public_key = signer::keys::PublicKey::from_private_key(&private_key);

    let (tx_version, chain_id, addr_version) = (
        TransactionVersion::Testnet,
        CHAIN_ID_TESTNET,
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    );

    let sender_addr = StacksAddress::from_public_keys(
        addr_version,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![public_key.into()],
    )
    .unwrap();
    let nonce = stacks_client.get_account(&sender_addr).await.unwrap().nonce;

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
        version: tx_version,
        chain_id,
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
