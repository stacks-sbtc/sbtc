//! Integration testing helper functions for compose stack
//!

use std::{mem::ManuallyDrop, time::Duration};

use bitcoin::{AddressType, Amount};
use bitcoincore_rpc::RpcApi as _;
use testcontainers::compose::DockerCompose;
use tokio::sync::OnceCell;
use url::Url;

use crate::{
    error::Error,
    testing::regtest::{
        BITCOIN_CORE_RPC_PASSWORD, BITCOIN_CORE_RPC_USERNAME, BITCOIN_CORE_WALLET_NAME,
        FAUCET_LABEL, FAUCET_SECRET_KEY, Faucet, MIN_BLOCKCHAIN_HEIGHT, get_or_create_wallet,
    },
};

const COMPOSE_BITCOIN: &str = "docker-compose.bitcoin.yml";
const COMPOSE_STACKS: &str = "docker-compose.stacks.yml";

/// Bitcoin service name in the compose stack
pub const SERVICE_BITCOIN: &str = "bitcoin";
/// Bitcoin service exposed port in the compose stack
pub const SERVICE_BITCOIN_RPC_PORT: u16 = 18443;

/// Bitcoin service name in the compose stack
pub const SERVICE_STACKS: &str = "stacks-node";
/// Bitcoin service exposed port in the compose stack
pub const SERVICE_STACKS_RPC_PORT: u16 = 20443;

fn compose_path(file_name: &str) -> String {
    // Evaluate `CARGO_MANIFEST_DIR` at runtime for nextest relocation
    format!(
        "{}/../docker/tests/{file_name}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    )
}

/// Builder for test containers
pub struct TestContainersBuilder {
    /// Compose files to use
    compose_files: Vec<String>,
}

impl TestContainersBuilder {
    /// Create a new `TestContainersBuilder`
    pub fn new() -> Self {
        Self { compose_files: vec![] }
    }
    /// Add compose file
    fn with_compose(mut self, filename: &str) -> Self {
        self.compose_files.push(filename.to_string());
        self
    }
    /// Build a new `TestContainers` with this config
    pub fn build(self) -> TestContainers {
        TestContainers::new(self)
    }
    /// Build a new `TestContainers` with this config and start it, panic if fails
    async fn start(self) -> TestContainers {
        let mut stack = self.build();
        stack.up().await.expect("failed to start the stack");
        stack
    }
    /// Add Bitcoin compose stack
    fn with_bitcoin(self) -> Self {
        self.with_compose(&compose_path(COMPOSE_BITCOIN))
    }
    /// Start the test stack with only Bitcoin, panic if fails
    pub async fn start_bitcoin() -> TestContainers {
        Self::new().with_bitcoin().start().await
    }
    /// Add Stacks compose stack
    fn with_stacks(self) -> Self {
        self.with_compose(&compose_path(COMPOSE_STACKS))
    }
    /// Start the test stack with Stacks and Bitcoin, panic if fails
    pub async fn start_stacks() -> TestContainers {
        Self::new().with_stacks().start().await
    }
}

impl Default for TestContainersBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A `TestContainers` manage an isolated docker stack for tests
pub struct TestContainers {
    /// The underlying compose stack
    compose: ManuallyDrop<DockerCompose>,
    /// By default the stack is downed on drop (triggered on test exit)
    down_on_drop: bool,
    /// The Bitcoin container, if present
    bitcoin: OnceCell<BitcoinContainer>,
    /// The Stacks container, if present
    stacks: OnceCell<StacksContainer>,
}
impl TestContainers {
    /// Create a new `TestContainers`
    pub fn new(config: TestContainersBuilder) -> Self {
        let compose = DockerCompose::with_local_client(&config.compose_files);
        Self {
            compose: ManuallyDrop::new(compose),
            down_on_drop: true,
            bitcoin: OnceCell::new(),
            stacks: OnceCell::new(),
        }
    }

    /// Up the required services
    pub async fn up(&mut self) -> Result<(), Error> {
        self.compose.up().await.map_err(Error::ComposeError)
    }

    /// Get the service exposed port given the internal port
    pub async fn get_service_port(&self, service: &str, internal_port: u16) -> Result<u16, Error> {
        let container = self.compose.service(service).ok_or_else(|| {
            Error::ComposeError(testcontainers::compose::ComposeError::ServiceNotFound(
                service.to_string(),
            ))
        })?;
        container
            .get_host_port_ipv4(internal_port)
            .await
            .map_err(Error::Testcontainers)
    }

    /// Get the service host
    pub async fn get_service_host(&self, service: &str) -> Result<url::Host, Error> {
        let container = self.compose.service(service).ok_or_else(|| {
            Error::ComposeError(testcontainers::compose::ComposeError::ServiceNotFound(
                service.to_string(),
            ))
        })?;
        container.get_host().await.map_err(Error::Testcontainers)
    }

    /// Get the Bitcoin RPC url
    async fn get_bitcoin_url(&self) -> Result<Url, Error> {
        let host = self.get_service_host(SERVICE_BITCOIN).await?;
        let port = self
            .get_service_port(SERVICE_BITCOIN, SERVICE_BITCOIN_RPC_PORT)
            .await?;
        format!("http://{BITCOIN_CORE_RPC_USERNAME}:{BITCOIN_CORE_RPC_PASSWORD}@{host}:{port}",)
            .parse()
            .map_err(Error::InvalidUrl)
    }

    /// Get the Stacks RPC url
    async fn get_stacks_url(&self) -> Result<Url, Error> {
        let host = self.get_service_host(SERVICE_STACKS).await?;
        let port = self
            .get_service_port(SERVICE_STACKS, SERVICE_STACKS_RPC_PORT)
            .await?;
        format!("http://{host}:{port}",)
            .parse()
            .map_err(Error::InvalidUrl)
    }

    /// Get the Bitcoin container
    pub async fn bitcoin(&self) -> &BitcoinContainer {
        self.bitcoin
            .get_or_init(|| BitcoinContainer::from_containers(self))
            .await
    }

    /// Get the Stacks container
    pub async fn stacks(&self) -> &StacksContainer {
        self.stacks
            .get_or_init(|| StacksContainer::from_containers(self))
            .await
    }

    /// Use to keep the stack up after the test finishes
    ///
    /// ## Examples:
    /// ```
    /// let stack = TestContainersBuilder::start_bitcoin().await.keep_up();
    /// ```
    #[allow(unused)]
    pub fn keep_up(mut self) -> Self {
        self.down_on_drop = false;
        self
    }

    /// Use to bring down the stack after the test finishes (default behaviour)
    /// Can be used when debugging: putting it at the end of a test that is
    /// using `keep_up` enables removing the stack if the tests passed, and
    /// keeping it up in case of errors.
    #[allow(unused)]
    pub fn dont_keep_up(mut self) -> Self {
        self.down_on_drop = true;
        self
    }
}

/// By default the compose stack is downed on "normal" test exit (success or
/// fail/panic), so the container cannot be inspected after the run.
/// To prevent it from being dropped we skip dropping `compose` if
/// `down_on_drop` is false.
impl Drop for TestContainers {
    fn drop(&mut self) {
        if self.down_on_drop {
            // SAFETY: we drop it only here; we are dropping `self` so we cannot
            // access `self.compose` anymore after dropping it.
            unsafe {
                ManuallyDrop::drop(&mut self.compose);
            }
        }
    }
}

/// A running Bitcoin container
pub struct BitcoinContainer {
    url: Url,
    rpc_client: bitcoincore_rpc::Client,
}

impl BitcoinContainer {
    /// Creates a `BitcoinContainer` from a compose stack running it
    pub async fn from_containers(containers: &TestContainers) -> Self {
        let auth = bitcoincore_rpc::Auth::UserPass(
            BITCOIN_CORE_RPC_USERNAME.to_string(),
            BITCOIN_CORE_RPC_PASSWORD.to_string(),
        );
        let url = containers
            .get_bitcoin_url()
            .await
            .expect("cannot get bitcoin url");

        let stacks_running = containers.get_stacks_url().await.is_ok();

        let rpc_client_url = if stacks_running {
            // If we are running the stacks compose we must specify the wallet
            // in the client url to avoid failing with:
            // RpcError { code: -19, message: "Wallet file not specified (must request wallet RPC through /wallet/<filename> uri-path)." }
            &format!("{}wallet/{BITCOIN_CORE_WALLET_NAME}", url.as_ref())
        } else {
            url.as_ref()
        };

        let rpc_client = bitcoincore_rpc::Client::new(rpc_client_url, auth)
            .expect("cannot create bitcoin rpc client");

        get_or_create_wallet(&rpc_client, BITCOIN_CORE_WALLET_NAME);
        let faucet = Faucet::new(FAUCET_SECRET_KEY, AddressType::P2wpkh, &rpc_client);
        faucet.track_address(FAUCET_LABEL);

        let amount = rpc_client
            .get_received_by_address(&faucet.address, None)
            .unwrap();
        if amount < Amount::from_int_btc(1) {
            if stacks_running {
                // If we are running the stacks compose we can't generate too
                // many blocks to avoid messing with the stacks node.
                // But we should never reach this, as we do fund the faucet in
                // the miner script.
                unreachable!();
            } else {
                faucet.generate_blocks(MIN_BLOCKCHAIN_HEIGHT);
            }
        }

        BitcoinContainer { url, rpc_client }
    }

    /// Get the Bitcoin RPC address
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Get the Bitcoin RPC client
    pub fn rpc(&self) -> &bitcoincore_rpc::Client {
        &self.rpc_client
    }

    /// Get the faucet
    pub fn get_faucet(&self) -> Faucet<'_> {
        Faucet::new(FAUCET_SECRET_KEY, AddressType::P2wpkh, &self.rpc_client)
    }
}

/// A running Stacks container
pub struct StacksContainer {
    url: Url,
}

impl StacksContainer {
    /// Creates a `StacksContainer` from a compose stack running it
    pub async fn from_containers(containers: &TestContainers) -> Self {
        let url = containers
            .get_stacks_url()
            .await
            .expect("cannot get stacks url");

        // We generate some bitcoin blocks to ensure there are no pending
        // transactions that may disrupt our STX faucet (as that account is also
        // used to progress the chain in the build script). We also sleep a bit
        // to ensure no flash blocks that may mess with the node awakening.
        containers.bitcoin().await.get_faucet().generate_block();
        tokio::time::sleep(Duration::from_secs(3)).await;
        containers.bitcoin().await.get_faucet().generate_block();

        StacksContainer { url }
    }

    /// Get the Bitcoin RPC address
    pub fn url(&self) -> &Url {
        &self.url
    }
}
