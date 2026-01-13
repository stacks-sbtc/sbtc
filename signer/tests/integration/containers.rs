use std::time::Duration;

use bitcoincore_rpc::RpcApi as _;
use sbtc::testing::containers::BitcoinContainer;
use sbtc::testing::containers::TestContainersBuilder;
use signer::bitcoin::poller::BitcoinChainTipPoller;
use signer::bitcoin::rpc::BitcoinCoreClient;

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
