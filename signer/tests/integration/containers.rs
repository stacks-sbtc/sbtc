use std::collections::HashSet;
use std::time::Duration;

use bitcoincore_rpc::RpcApi as _;
use clarity::vm::types::PrincipalData;
use more_asserts::assert_gt;
use sbtc::testing::containers::BitcoinContainer;
use sbtc::testing::containers::StacksContainer;
use sbtc::testing::containers::TestContainersBuilder;
use signer::bitcoin::poller::BitcoinChainTipPoller;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::stacks::api::StacksClient;

use crate::stacks::fund_stx;

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
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;

    let faucet = bitcoin.get_faucet();

    let stacks_client = stacks.get_client();

    let recipient = PrincipalData::parse("SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS").unwrap();
    let mut bitcoin_blocks = HashSet::new();
    let mut stacks_blocks = HashSet::new();

    for _ in 0..2 {
        let tx = fund_stx(&stacks_client, &recipient, 1_000_000).await;
        stacks_client
            .submit_tx(&tx)
            .await
            .expect("failed to send stacks transaction");
        tokio::time::sleep(Duration::from_secs(2)).await;

        faucet.generate_block();
        tokio::time::sleep(Duration::from_secs(2)).await;

        let stacks_status = stacks_client
            .get_node_info()
            .await
            .expect("failed to get stacks node info");

        bitcoin_blocks.insert(*stacks_status.burn_block_height);
        stacks_blocks.insert(*stacks_status.stacks_tip_height);
    }

    assert_gt!(bitcoin_blocks.len(), 1);
    assert_gt!(stacks_blocks.len(), 1);
}
