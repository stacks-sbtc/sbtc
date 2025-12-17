use sbtc::testing::containers::BitcoinContainer;
use signer::bitcoin::rpc::BitcoinCoreClient;

pub trait BitcoinContainerExt {
    /// Get the Bitcoin client
    fn get_client(&self) -> BitcoinCoreClient;
}

impl BitcoinContainerExt for BitcoinContainer {
    fn get_client(&self) -> BitcoinCoreClient {
        self.url().try_into().expect("cannot create bitcoin client")
    }
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::RpcApi as _;
    use sbtc::testing::containers::TestContainersBuilder;

    use super::*;

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
}
