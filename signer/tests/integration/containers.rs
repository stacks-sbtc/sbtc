use std::time::Duration;

use bitcoincore_rpc::RpcApi as _;
use clarity::vm::types::PrincipalData;
use sbtc::testing::containers::BitcoinContainer;
use sbtc::testing::containers::StacksContainer;
use sbtc::testing::containers::TestContainersBuilder;
use signer::bitcoin::poller::BitcoinChainTipPoller;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::stacks::api::StacksClient;

use crate::stacks::fund_stx;
use crate::stacks::principal_to_address;
use crate::stacks::wait_for_stx_balance;

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
    let stack = TestContainersBuilder::start_stacks().await;
    let stacks = stack.stacks().await;

    let stacks_client = stacks.get_client();

    let recipient = PrincipalData::parse("SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS").unwrap();
    let recipient_address = &principal_to_address(&recipient);

    // First let's ensure zero balance
    let balance = stacks_client
        .get_account(&principal_to_address(&recipient))
        .await
        .expect("cannot get account info")
        .balance;
    assert_eq!(balance, 0);

    // Now let's try to send some STX
    let ustx = 1_000_000;
    let iters: usize = 3;

    for i in 0..iters {
        let tx = fund_stx(&stacks_client, &recipient, ustx).await;
        stacks_client
            .submit_tx(&tx)
            .await
            .expect("failed to send stacks transaction");

        wait_for_stx_balance(&stacks_client, recipient_address, |b| {
            b == (i + 1) as u128 * ustx as u128
        })
        .await;
    }
    // Let's check the final balance (again)
    let balance = stacks_client
        .get_account(&principal_to_address(&recipient))
        .await
        .expect("cannot get account info")
        .balance;
    assert_eq!(balance, iters as u128 * ustx as u128)
}
