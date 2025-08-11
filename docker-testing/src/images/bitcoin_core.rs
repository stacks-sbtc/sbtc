use std::time::Duration;

use bitcoincore_rpc::bitcoin::Network;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use testcontainers::ContainerAsync;
use testcontainers::GenericImage;
use testcontainers::ImageExt;
use testcontainers::core::ContainerPort;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use url::Url;

use crate::error::Error;
use crate::logging;

use super::container_name;

pub struct Defaults;
impl Defaults {
    /// The default version of the bitcoin-core image used in tests.
    pub const BITCOIN_CORE_VERSION: &str = "28.2";
    /// The username for RPC calls in bitcoin-core
    pub const RPC_USERNAME: &str = "devnet";
    /// The password for RPC calls in bitcoin-core
    pub const RPC_PASSWORD: &str = "devnet";
    /// The port for RPC calls in bitcoin-core
    pub const RPC_PORT: u16 = 18443;
    /// The default startup timeout for the bitcoin-core container.
    pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
    /// The default network for the bitcoin-core container.
    pub const NETWORK: Network = Network::Regtest;
}

/// Configuration for a `BitcoinCore` container.
///
/// This struct is created using a [`BitcoinCoreBuilder`].
pub struct BitcoinCoreConfig {
    pub version: String,
    pub cmd: Vec<String>,
    pub startup_timeout: Duration,
    pub rpc_username: String,
    pub rpc_password: String,
    pub rpc_port: u16,
    pub network: Network,
}

/// A builder for creating a `BitcoinCoreConfig`.
#[derive(Default)]
pub struct BitcoinCoreBuilder {
    config: BitcoinCoreConfig,
}

impl Default for BitcoinCoreConfig {
    fn default() -> Self {
        Self {
            version: Defaults::BITCOIN_CORE_VERSION.to_string(),
            cmd: vec![
                "-chain=regtest".into(),
                "-server".into(),
                "-rpcbind=0.0.0.0".into(),
                format!("-rpcuser={}", Defaults::RPC_USERNAME),
                format!("-rpcpassword={}", Defaults::RPC_PASSWORD),
                "-rpcallowip=0.0.0.0/0".into(),
                "-rpcallowip=::/0".into(),
                "-txindex".into(),
                "-fallbackfee=0.00001".into(),
            ],
            startup_timeout: Defaults::STARTUP_TIMEOUT,
            rpc_username: Defaults::RPC_USERNAME.to_string(),
            rpc_password: Defaults::RPC_PASSWORD.to_string(),
            rpc_port: Defaults::RPC_PORT,
            network: Defaults::NETWORK,
        }
    }
}

impl BitcoinCoreBuilder {
    /// Sets the version of Bitcoin Core to use.
    /// 
    /// The specified version must match a tag in the
    /// [`bitcoin/bitcoin`](https://hub.docker.com/r/bitcoin/bitcoin/tags)
    /// Docker image repository, meaning that the image author must also have
    /// published a tag with the specified version upon new Bitcoin Core
    /// releases.
    pub fn using_version(mut self, version: impl Into<String>) -> Result<Self, Error> {
        let version = version.into();
        // Validate that the version string is in the expected format.
        let parts: Vec<_> = version.split('.').collect();
        if parts.len() != 2 || parts.iter().any(|&p| p.is_empty() || p.parse::<u32>().is_err()) {
            return Err(Error::InvalidVersionFormat(version));
        }

        self.config.version = version.into();
        Ok(self)
    }

    /// Adds a command-line argument to the bitcoind process.
    pub fn with_cmd_arg(mut self, arg: impl Into<String>) -> Self {
        self.config.cmd.push(arg.into());
        self
    }

    /// Sets the startup timeout for the container.
    pub fn with_startup_timeout(mut self, timeout: Duration) -> Self {
        self.config.startup_timeout = timeout;
        self
    }

    pub fn with_rpc_username(mut self, username: impl Into<String>) -> Self {
        self.config.rpc_username = username.into();
        self
    }

    pub fn with_rpc_password(mut self, password: impl Into<String>) -> Self {
        self.config.rpc_password = password.into();
        self
    }

    pub fn with_rpc_port(mut self, port: u16) -> Self {
        self.config.rpc_port = port;
        self
    }

    pub fn start(self) -> impl Future<Output = Result<BitcoinCore, Error>> {
        let config = self.config;
        async move {
            BitcoinCore::start(
                config,
                (),
            )
            .await
        }
    }

    pub fn start_with_state<S>(self, state: S) -> impl Future<Output = Result<BitcoinCore<S>, Error>> {
        let config = self.config;
        async move {
            BitcoinCore::start(
                config,
                state,
            )
            .await
        }
    }
}

pub struct BitcoinCore<S = ()> {
    container: ContainerAsync<GenericImage>,
    rpc_endpoint: Url,
    rpc_client: bitcoincore_rpc::Client,
    state: S,
}

impl BitcoinCore<()> {
    /// Returns a new builder for creating a `BitcoinCore` container.
    pub fn builder() -> BitcoinCoreBuilder {
        BitcoinCoreBuilder::default()
    }

    pub async fn start_with_defaults() -> Result<BitcoinCore<()>, Error> {
        Self::start(BitcoinCoreConfig::default(), ()).await
    }
}

impl<S> BitcoinCore<S> {
    async fn start(config: BitcoinCoreConfig, state: S) -> Result<BitcoinCore<S>, Error> {
        let wait_strategy = WaitFor::message_on_stdout("dnsseed thread exit");
        let cmd: Vec<String> = vec![
            "-chain=regtest".into(),
            "-server".into(),
            "-rpcbind=0.0.0.0".into(),
            format!("-rpcuser={}", config.rpc_username),
            format!("-rpcpassword={}", config.rpc_password),
            "-rpcallowip=0.0.0.0/0".into(),
            "-rpcallowip=::/0".into(),
            "-txindex".into(),
            "-zmqpubhashblock=tcp://*:28332".into(),
            "-zmqpubrawblock=tcp://*:28332".into(),
            "-fallbackfee=0.00001".into(),
        ];

        let bitcoind = GenericImage::new("bitcoin/bitcoin", &config.version)
            .with_wait_for(wait_strategy)
            .with_entrypoint(&format!("/opt/bitcoin-{version}/bin/bitcoind", version = &config.version))
            .with_cmd(cmd)
            .with_container_name(container_name("bitcoind"))
            .with_mapped_port(0, ContainerPort::Tcp(config.rpc_port))
            .with_log_consumer(logging::SimpleLogConsumer::new())
            .with_startup_timeout(Duration::from_secs(5))
            .start()
            .await?;

        let host = bitcoind.get_host().await?;
        let rpc_port = bitcoind.get_host_port_ipv4(Defaults::RPC_PORT).await?;
        let rpc_endpoint = Url::parse(&format!("http://{host}:{rpc_port}"))?;

        let host_str = host.to_string();
        let check_rpc = tokio::spawn(async move {
            super::wait_for_tcp_connectivity(&host_str, rpc_port, Duration::from_secs(5)).await;
        });

        tokio::try_join!(check_rpc).map_err(|_| Error::StartupConnectivityTimeout)?;

        // Create a client which is used for the `as_ref()` implementation,
        // returning a reference to the client.
        let auth = Auth::UserPass(Defaults::RPC_USERNAME.into(), Defaults::RPC_PASSWORD.into());
        let rpc_client = Client::new(rpc_endpoint.as_str(), auth).map_err(Error::BitcoinCoreRpc)?;

        Ok(Self {
            container: bitcoind,
            rpc_endpoint,
            rpc_client,
            state,
        })
    }

    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    pub fn rpc_endpoint(&self) -> &Url {
        &self.rpc_endpoint
    }

    #[allow(unused)]
    /// Create a new client for the bitcoin-core RPC interface.
    ///
    /// This is primarily for when the caller needs an owned instance of a
    /// [`Client`]. If you only need a client reference you may use
    /// [`as_ref()`](BitcoinCore::as_ref).
    pub fn rpc_client(&self) -> Result<bitcoincore_rpc::Client, Error> {
        let auth = Auth::UserPass(Defaults::RPC_USERNAME.into(), Defaults::RPC_PASSWORD.into());
        Client::new(self.rpc_endpoint.as_str(), auth).map_err(Error::BitcoinCoreRpc)
    }

    /// Stops the bitcoin core container and returns a result indicating success or failure.
    pub async fn stop(self) -> Result<(), Error> {
        self.container
            .stop_with_timeout(Some(0))
            .await
            .map_err(Error::TestContainers)
    }

    /// Returns a reference to the attached state of the BitcoinCore instance.
    pub fn state(&self) -> &S {
        &self.state
    }
}

impl<S> AsRef<Client> for BitcoinCore<S> {
    fn as_ref(&self) -> &Client {
        &self.rpc_client
    }
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::{RpcApi, bitcoin::Network};

    use super::*;

    #[ignore = "utility test for manually verifying that the bitcoind docker setup works"]
    #[tokio::test]
    async fn test_bitcoind() {
        let bitcoind = BitcoinCore::start_with_defaults()
            .await
            .expect("failed to start bitcoind");

        let client = bitcoind.rpc_client().expect("failed to create rpc client");
        let info = client.get_blockchain_info().expect("failed to query node");
        assert_eq!(info.chain, Network::Regtest);

        dbg!(info);
    }
}
