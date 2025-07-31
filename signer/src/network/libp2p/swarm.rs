use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use crate::context::Context;
use crate::keys::PrivateKey;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::upgrade::Version;
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::ConnectionCounters;
use libp2p::swarm::NetworkBehaviour;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport, autonat, connection_limits, gossipsub, identify, kad,
    mdns, noise, ping, quic, tcp, yamux,
};
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use tokio::sync::Mutex;

use super::errors::SignerSwarmError;
use super::{bootstrap, event_loop};

/// The maximum number of substreams _per connection_. This is used to limit
/// the number of concurrent substreams that can be opened on a single
/// connection. The general assumption at the time of writing is:
/// * GossipSub: 1 bidirectional stream per connection
/// * Kademlia: 1-3 streams during active lookups, each query can use its own stream
/// * AutoNAT: 2 streams (one for client, one for server operations)
/// * Identify: 1 stream for peer identification
/// * Ping: 1 stream for keepalive pings
const MAX_SUBSTREAMS_PER_CONNECTION: usize = 20;

/// The maximum time to wait for a connection negotiation to complete. This is
/// used to prevent potentially malicious peers from being able to hold a
/// connection in a pending state for all too long, preventing legitimate peers
/// from connecting. The timeout is set to 10 seconds, which should be sufficient
/// for most use cases. If a connection cannot be established within this time,
/// the connection will be closed and the dialing peer will be notified. This
/// timeout is applied to both inbound and outbound connections.
const NEGOTIATION_TIMEOUT_SECS: u64 = 10;

/// Define the behaviors of the [`SignerSwarm`] libp2p network.
#[derive(NetworkBehaviour)]
pub struct SignerBehavior {
    pub gossipsub: gossipsub::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    pub kademlia: Toggle<kad::Behaviour<MemoryStore>>,
    ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub autonat_client: Toggle<autonat::v2::client::Behaviour<StdRng>>,
    pub autonat_server: Toggle<autonat::v2::server::Behaviour<StdRng>>,
    pub bootstrap: bootstrap::Behavior,
    pub connection_limits: connection_limits::Behaviour,
}

pub struct SignerSwarmConfig {
    pub enable_mdns: bool,
    pub enable_kademlia: bool,
    pub enable_autonat: bool,
    pub initial_bootstrap_delay: Duration,
    pub seed_addresses: Vec<Multiaddr>,
    pub known_peers: Vec<(PeerId, Multiaddr)>,
    pub num_signers: u16,
}

impl SignerBehavior {
    pub fn new(keypair: Keypair, config: SignerSwarmConfig) -> Result<Self, SignerSwarmError> {
        let local_peer_id = keypair.public().to_peer_id();

        let mdns = if config.enable_mdns {
            Some(
                mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                    .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?,
            )
        } else {
            None
        }
        .into();

        let kademlia = match config.enable_kademlia {
            true => Some(Self::kademlia(local_peer_id)),
            false => None,
        }
        .into();

        let (autonat_client, autonat_server) = if config.enable_autonat {
            let client = autonat::v2::client::Behaviour::new(
                rand::rngs::StdRng::from_entropy(),
                autonat::v2::client::Config::default(),
            );
            let server = autonat::v2::server::Behaviour::new(rand::rngs::StdRng::from_entropy());
            (Some(client).into(), Some(server).into())
        } else {
            (None.into(), None.into())
        };

        let identify = identify::Behaviour::new(identify::Config::new(
            identify::PUSH_PROTOCOL_NAME.to_string(),
            keypair.public(),
        ));

        let bootstrap_config = bootstrap::Config::new(local_peer_id)
            .with_initial_delay(config.initial_bootstrap_delay)
            .add_seed_addresses(config.seed_addresses)
            .add_known_peers(config.known_peers);
        let bootstrap = bootstrap::Behavior::new(bootstrap_config);

        Ok(Self {
            gossipsub: Self::gossipsub(&keypair)?,
            mdns,
            kademlia,
            ping: Default::default(),
            identify,
            autonat_client,
            autonat_server,
            bootstrap,
            connection_limits: Self::connection_limits(config.num_signers),
        })
    }

    fn connection_limits(num_signers_in: u16) -> connection_limits::Behaviour {
        // The number of signers is the number of signers in the set, minus one
        // for the local signer. This is used to calculate the connection limits.
        // Note: We use `max(2)` here to ensure that we always have limits
        // that support at least two signers.
        let num_signers = num_signers_in.saturating_sub(1).max(2) as u32;

        // Allow `num_signers` * 3 connections to be established at once. This
        // allows room for one incoming/outgoing connection to each signer, plus
        // one additional connection per signer as a buffer for protocols such
        // as autonat.
        let max_established = num_signers.saturating_mul(3);

        // Allow `num_signers` * 2 _incoming_ connections to be established at
        // once. This allows room for one incoming connection from each signer,
        // plus one additional connection per signer as a buffer for protocols
        // such as autonat.
        let max_established_incoming = num_signers.saturating_mul(2);

        // Allow for one incoming, one outgoing and one additional connection per
        // peer.
        let max_established_per_peer = 3;

        // Allow for `num_signers` _incoming_ connections to be pending at once.
        // This is conservative, but realistic as we wouldn't expect each signer
        // to be attempting to open multiple connections to us simultaneously,
        // even during bootstrapping.
        let max_pending_incoming = num_signers;

        // Allow for `num_signers` _outgoing_ connections to be pending at once.
        // This is conservative, but realistic as we wouldn't expect to be dialing
        // more than `num_signers` signers at once, even during bootstrapping.
        let max_pending_outgoing = num_signers;

        let limits = connection_limits::ConnectionLimits::default()
            .with_max_established(Some(max_established))
            .with_max_established_incoming(Some(max_established_incoming))
            .with_max_established_per_peer(Some(max_established_per_peer))
            .with_max_pending_incoming(Some(max_pending_incoming))
            .with_max_pending_outgoing(Some(max_pending_outgoing));

        connection_limits::Behaviour::new(limits)
    }

    /// Create a new gossipsub behavior.
    fn gossipsub(keypair: &Keypair) -> Result<gossipsub::Behaviour, SignerSwarmError> {
        let message_id_fn = |message: &gossipsub::Message| {
            let mut hasher = DefaultHasher::new();
            message.data.hash(&mut hasher);
            gossipsub::MessageId::from(hasher.finish().to_string())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1)) // Default is 1 second
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?;

        gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(SignerSwarmError::LibP2PMessage)
    }

    /// Create a new kademlia behavior.
    fn kademlia(peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
        let config = kad::Config::new(kad::PROTOCOL_NAME)
            .disjoint_query_paths(true)
            .to_owned();

        let mut kademlia = kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), config);
        kademlia.set_mode(Some(kad::Mode::Server));
        kademlia
    }
}

/// Builder for the [`SignerSwarm`] libp2p network.
pub struct SignerSwarmBuilder<'a> {
    private_key: &'a PrivateKey,
    listen_on: Vec<Multiaddr>,
    seed_addrs: Vec<Multiaddr>,
    known_peers: Vec<(PeerId, Multiaddr)>,
    external_addresses: Vec<Multiaddr>,
    enable_mdns: bool,
    enable_kademlia: bool,
    enable_autonat: bool,
    enable_quic_transport: bool,
    enable_memory_transport: bool,
    initial_bootstrap_delay: Duration,
    num_signers: u16,
}

impl<'a> SignerSwarmBuilder<'a> {
    /// Create a new [`SignerSwarmBuilder`] with the given private key.
    pub fn new(private_key: &'a PrivateKey) -> Self {
        Self {
            private_key,
            listen_on: Vec::new(),
            seed_addrs: Vec::new(),
            known_peers: Vec::new(),
            external_addresses: Vec::new(),
            enable_mdns: false,
            enable_kademlia: true,
            enable_autonat: true,
            enable_quic_transport: false,
            enable_memory_transport: false,
            initial_bootstrap_delay: Duration::ZERO,
            num_signers: crate::MAX_KEYS,
        }
    }

    /// Sets whether or not this swarm should use mdns.
    pub fn enable_mdns(mut self, use_mdns: bool) -> Self {
        self.enable_mdns = use_mdns;
        self
    }

    /// Sets whether or not this swarm should use kademlia for peer
    /// discovery/DHT.
    pub fn enable_kademlia(mut self, use_kademlia: bool) -> Self {
        self.enable_kademlia = use_kademlia;
        self
    }

    /// Sets whether or not this swarm should use autonat for NAT detection and
    /// external address discovery.
    pub fn enable_autonat(mut self, use_autonat: bool) -> Self {
        self.enable_autonat = use_autonat;
        self
    }

    /// Sets whether or not this swarm should use the QUIC transport.
    pub fn enable_quic_transport(mut self, enable: bool) -> Self {
        self.enable_quic_transport = enable;
        self
    }

    /// Sets the number of signers in the signer set. This is used as a base
    /// value for connection limits calculations.
    pub fn with_num_signers(mut self, num_signers: u16) -> Self {
        self.num_signers = num_signers;
        self
    }

    /// Sets whether or not this swarm should use the memory transport.
    pub fn enable_memory_transport(mut self, enable: bool) -> Self {
        self.enable_memory_transport = enable;
        self
    }

    /// Add a listen endpoint to the builder.
    pub fn add_listen_endpoint(mut self, addr: Multiaddr) -> Self {
        if !self.listen_on.contains(&addr) {
            self.listen_on.push(addr);
        }
        self
    }

    /// Add multiple listen endpoints to the builder.
    pub fn add_listen_endpoints(mut self, addrs: &[Multiaddr]) -> Self {
        for addr in addrs {
            if !self.listen_on.contains(addr) {
                self.listen_on.push(addr.clone());
            }
        }
        self
    }

    /// Add a seed address to the builder.
    pub fn add_seed_addr(mut self, addr: Multiaddr) -> Self {
        if !self.seed_addrs.contains(&addr) {
            self.seed_addrs.push(addr);
        }
        self
    }

    /// Add multiple seed addresses to the builder.
    pub fn add_seed_addrs(mut self, addrs: &[Multiaddr]) -> Self {
        for addr in addrs {
            if !self.seed_addrs.contains(addr) {
                self.seed_addrs.push(addr.clone());
            }
        }
        self
    }

    /// Add known peers to the builder.
    pub fn add_known_peers(mut self, peers: &[(PeerId, Multiaddr)]) -> Self {
        for (peer_id, addr) in peers {
            if !self.known_peers.contains(&(*peer_id, addr.clone())) {
                self.known_peers.push((*peer_id, addr.clone()));
            }
        }
        self
    }

    /// Add an external address to the builder.
    pub fn add_external_address(mut self, addr: Multiaddr) -> Self {
        if !self.external_addresses.contains(&addr) {
            self.external_addresses.push(addr);
        }
        self
    }

    /// Add multiple external addresses to the builder.
    pub fn add_external_addresses(mut self, addrs: &[Multiaddr]) -> Self {
        for addr in addrs {
            if !self.external_addresses.contains(addr) {
                self.external_addresses.push(addr.clone());
            }
        }
        self
    }

    /// Set the initial bootstrap delay.
    pub fn with_initial_bootstrap_delay(mut self, delay: Duration) -> Self {
        self.initial_bootstrap_delay = delay;
        self
    }

    /// Build the [`SignerSwarm`], consuming the builder.
    pub fn build(self) -> Result<SignerSwarm, SignerSwarmError> {
        let keypair: Keypair = (*self.private_key).into();
        let behavior_config = SignerSwarmConfig {
            enable_mdns: self.enable_mdns,
            enable_kademlia: self.enable_kademlia,
            enable_autonat: self.enable_autonat,
            initial_bootstrap_delay: self.initial_bootstrap_delay,
            seed_addresses: self.seed_addrs,
            known_peers: self.known_peers,
            num_signers: self.num_signers,
        };
        let behavior = SignerBehavior::new(keypair.clone(), behavior_config)?;

        // Noise (encryption) configuration.
        let noise =
            noise::Config::new(&keypair).map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?;

        // Yamux (muxer) configuration.
        let mut yamux = yamux::Config::default();
        yamux.set_max_num_streams(MAX_SUBSTREAMS_PER_CONNECTION);

        // TCP transport configuration.
        let tcp_config = tcp::Config::default().nodelay(true);

        // General swarm options
        let swarm_config = libp2p::swarm::Config::with_tokio_executor();

        // Start building the transport with the TCP transport, which should always
        // be enabled.
        let mut transport = tcp::tokio::Transport::new(tcp_config)
            .upgrade(Version::V1)
            .authenticate(noise.clone())
            .multiplex(yamux.clone())
            // Apply timeouts to the setup and protocol upgrade process to
            // prevent potential malicious peers from keeping connections open.
            .inbound_timeout(Duration::from_secs(NEGOTIATION_TIMEOUT_SECS))
            .outbound_timeout(Duration::from_secs(NEGOTIATION_TIMEOUT_SECS))
            .boxed();

        // If QUIC transport is enabled, add it to the transport.
        if self.enable_quic_transport {
            let config = quic::Config::new(&keypair);
            let quic_transport = quic::tokio::Transport::new(config)
                .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
                .boxed();
            transport = transport
                .or_transport(quic_transport)
                .map(|either, _| either.into_inner())
                .boxed();
        }

        // If memory transport is enabled, add it to the transport.
        if self.enable_memory_transport {
            let memory_transport = libp2p::core::transport::MemoryTransport::default()
                .upgrade(Version::V1)
                .authenticate(noise.clone())
                .multiplex(yamux.clone())
                .boxed();
            transport = transport
                .or_transport(memory_transport)
                .map(|either, _| either.into_inner())
                .boxed();
        }

        // Add the DNS transport to the transport.
        transport = libp2p::dns::tokio::Transport::system(transport)
            .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?
            .boxed();

        // Create the swarm.
        let swarm = Swarm::new(
            transport,
            behavior,
            keypair.public().to_peer_id(),
            swarm_config,
        );

        Ok(SignerSwarm {
            keypair,
            swarm: Arc::new(Mutex::new(swarm)),
            listen_addrs: self.listen_on,
            external_addresses: self.external_addresses,
        })
    }
}

#[derive(Clone)]
pub struct SignerSwarm {
    keypair: Keypair,
    swarm: Arc<Mutex<Swarm<SignerBehavior>>>,
    listen_addrs: Vec<Multiaddr>,
    external_addresses: Vec<Multiaddr>,
}

impl SignerSwarm {
    /// Get the local peer ID of the signer.
    pub fn local_peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.keypair.public())
    }

    /// Get the current listen addresses of the swarm.
    pub async fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.swarm.lock().await.listeners().cloned().collect()
    }

    /// Dials the given address.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), SignerSwarmError> {
        self.swarm
            .lock()
            .await
            .dial(DialOpts::unknown_peer_id().address(addr).build())
            .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))
    }

    /// Start the [`SignerSwarm`] and run the event loop. This function will block until the
    /// swarm is stopped (either by receiving a shutdown signal or an unrecoverable error).
    pub async fn start(&mut self, ctx: &impl Context) -> Result<(), SignerSwarmError> {
        // Separate scope to ensure that the lock is released before the event loop is run.
        {
            let mut swarm = self.swarm.lock().await;
            tracing::info!(local_peer_id = %swarm.local_peer_id(), "starting signer swarm");

            // Start listening on the listen addresses.
            for addr in self.listen_addrs.iter() {
                swarm.listen_on(addr.clone()).map_err(|error| {
                    tracing::error!(address = %addr, %error, "failed to listen on address");
                    SignerSwarmError::LibP2P(Box::new(error))
                })?;
            }

            for addr in self.external_addresses.iter() {
                swarm.add_external_address(addr.clone());
            }
        }

        // Run the event loop, blocking until its completion.
        event_loop::run(ctx, Arc::clone(&self.swarm)).await;

        Ok(())
    }

    /// Get the current number of established connections maintained by the swarm.
    pub async fn connection_counters(&self) -> ConnectionCounters {
        self.swarm
            .lock()
            .await
            .network_info()
            .connection_counters()
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore as _;

    use crate::{
        keys::PublicKey,
        storage::DbRead as _,
        testing::{context::*, get_rng, network::MultiaddrExt as _},
    };

    use super::*;

    const MULTIADDR_NOT_SUPPORTED: &str = "Multiaddr is not supported";

    #[tokio::test]
    async fn test_signer_swarm_builder() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let keypair: Keypair = private_key.into();
        let builder = SignerSwarmBuilder::new(&private_key)
            .add_listen_endpoint(addr.clone())
            .add_seed_addr(addr.clone());
        let swarm = builder.build().unwrap();

        assert!(swarm.listen_addrs.contains(&addr));
        assert_eq!(
            swarm.swarm.lock().await.local_peer_id(),
            &PeerId::from_public_key(&keypair.public())
        );
    }

    #[tokio::test]
    async fn swarm_shuts_down_on_shutdown_signal() {
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let builder = SignerSwarmBuilder::new(&private_key);
        let mut swarm = builder.build().unwrap();

        let ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let term = ctx.get_termination_handle();

        let timeout = tokio::time::timeout(Duration::from_secs(10), async {
            let swarm_task = tokio::spawn(async move {
                swarm.start(&ctx).await.unwrap();
            });

            // A small pause to ensure that the swarm's event loop has started
            // and that it is awaiting the shutdown signal.
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Send a termination signal.
            term.signal_shutdown();

            // Wait for the swarm to shut down.
            swarm_task.await.unwrap();
        });

        match timeout.await {
            Ok(_) => (),
            Err(_) => panic!("Swarm did not shut down within the timeout"),
        }
    }

    #[tokio::test]
    async fn swarm_with_memory_transport() {
        let rng = &mut get_rng();
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let builder = SignerSwarmBuilder::new(&private_key);
        let mut swarm = builder
            .enable_memory_transport(true)
            .add_listen_endpoint(Multiaddr::random_memory(rng))
            .build()
            .unwrap();

        let ctx = TestContext::default_mocked();
        let term = ctx.get_termination_handle();

        let handle = tokio::spawn(async move { swarm.start(&ctx).await });

        tokio::time::sleep(Duration::from_millis(10)).await;
        term.signal_shutdown();

        handle
            .await
            .expect("Task failed")
            .expect("Swarm failed to start");
    }

    #[tokio::test]
    async fn swarm_with_memory_transport_disabled() {
        let rng = &mut get_rng();
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let builder = SignerSwarmBuilder::new(&private_key);
        let mut swarm = builder
            .enable_memory_transport(false)
            .add_listen_endpoint(Multiaddr::random_memory(rng))
            .build()
            .unwrap();

        let ctx = TestContext::default_mocked();
        let term = ctx.get_termination_handle();

        let handle = tokio::spawn(async move { swarm.start(&ctx).await });

        tokio::time::sleep(Duration::from_millis(10)).await;
        term.signal_shutdown();

        let result = handle.await.unwrap().unwrap_err();
        assert!(result.to_string().contains(MULTIADDR_NOT_SUPPORTED));
    }

    /// Note: This test will create an actual listening socket on the system on
    /// an OS-provided port.
    #[tokio::test]
    async fn swarm_with_tcp_transport() {
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let builder = SignerSwarmBuilder::new(&private_key);
        let mut swarm = builder
            .add_listen_endpoint("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .build()
            .unwrap();

        let ctx = TestContext::default_mocked();
        let term = ctx.get_termination_handle();

        let handle = tokio::spawn(async move { swarm.start(&ctx).await });

        tokio::time::sleep(Duration::from_millis(10)).await;
        term.signal_shutdown();

        handle
            .await
            .expect("Task failed")
            .expect("Swarm failed to start");
    }

    /// Note: This test will create an actual listening socket on the system on
    /// an OS-provided port.
    #[tokio::test]
    async fn swarm_with_quic_transport() {
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let builder = SignerSwarmBuilder::new(&private_key);
        let mut swarm = builder
            .enable_quic_transport(true)
            .add_listen_endpoint("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .build()
            .unwrap();

        let ctx = TestContext::default_mocked();
        let term = ctx.get_termination_handle();

        let handle = tokio::spawn(async move { swarm.start(&ctx).await });

        tokio::time::sleep(Duration::from_millis(10)).await;
        term.signal_shutdown();

        handle
            .await
            .expect("Task failed")
            .expect("Swarm failed to start");
    }

    #[tokio::test]
    async fn swarm_with_quic_transport_disabled() {
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let builder = SignerSwarmBuilder::new(&private_key);
        let mut swarm = builder
            .enable_quic_transport(false)
            .add_listen_endpoint("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .build()
            .unwrap();

        let ctx = TestContext::default_mocked();
        let term = ctx.get_termination_handle();

        let handle = tokio::spawn(async move { swarm.start(&ctx).await });

        tokio::time::sleep(Duration::from_millis(10)).await;
        term.signal_shutdown();

        let result = handle.await.unwrap().unwrap_err();
        assert!(result.to_string().contains(MULTIADDR_NOT_SUPPORTED));
    }

    #[test_log::test(tokio::test)]
    async fn libp2p_swarm_stores_peer_connections() {
        let mut rng = get_rng();
        let swarm1_addr = Multiaddr::memory(rng.next_u64());
        let swarm2_addr = Multiaddr::memory(rng.next_u64());

        // PeerId = 16Uiu2HAm46BSFWYYWzMjhTRDRwXHpDWpQ32iu93nzDwd1F4Tt256
        let key1 = PrivateKey::from_slice(
            hex::decode("ab0893ecf683dc188c3fb219dd6489dc304bb5babb8151a41245a70e60cb7258")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let key1_pub = PublicKey::from_private_key(&key1);

        // PeerId = 16Uiu2HAkuyB8ECXxACm8hzQj4vZ2iWrYMF3xcKNf1oJJ1NuQEMvQ
        let key2 = PrivateKey::from_slice(
            hex::decode("0dd4077c8bcec09c803f9ba23a0f5b56eba75769b2d1b96a33b579dbbe5055ce")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let key2_pub = PublicKey::from_private_key(&key2);

        // Create two contexts with different keys but in same signer set.
        let context1 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .with_private_key(key1)
            .build();
        let context2 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .with_private_key(key2)
            .build();

        // Add each key to the other's signer set so they can connect.
        context1.state().current_signer_set().add_signer(key2_pub);
        context2.state().current_signer_set().add_signer(key1_pub);

        let term1 = context1.get_termination_handle();
        let term2 = context2.get_termination_handle();

        let swarm1 = SignerSwarmBuilder::new(&key1)
            .enable_mdns(false)
            .enable_kademlia(false)
            .enable_autonat(false)
            .enable_memory_transport(true)
            .with_initial_bootstrap_delay(Duration::MAX) // We manually dial below
            .add_listen_endpoint(swarm1_addr.clone())
            .build()
            .expect("Failed to build swarm 1");

        let swarm2 = SignerSwarmBuilder::new(&key2)
            .enable_mdns(false)
            .enable_kademlia(false)
            .enable_autonat(false)
            .enable_memory_transport(true)
            .with_initial_bootstrap_delay(Duration::MAX) // We manually dial below
            .add_listen_endpoint(swarm2_addr.clone())
            .build()
            .expect("Failed to build swarm 2");

        // For timestamp assertion later
        let utc_now = time::OffsetDateTime::now_utc();

        // Start the two swarms.
        let mut swarm1_clone = swarm1.clone();
        let context1_clone = context1.clone();
        tokio::spawn(async move {
            swarm1_clone.start(&context1_clone).await.unwrap();
        });

        let mut swarm2_clone = swarm2.clone();
        let context2_clone = context2.clone();
        tokio::spawn(async move {
            swarm2_clone.start(&context2_clone).await.unwrap();
        });

        // Wait for the swarms to start.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        swarm1.dial(swarm2_addr.clone()).await.unwrap();
        swarm2.dial(swarm1_addr.clone()).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Get the peers stored in context 1 after connection
        let p2p_peers_1a = context1.get_storage().get_p2p_peers().await.unwrap();
        let p2p_peers_2a = context2.get_storage().get_p2p_peers().await.unwrap();

        // Verify that context 1 has the peer from context 2.
        assert_eq!(p2p_peers_1a.len(), 1);
        assert_eq!(*p2p_peers_1a[0].peer_id, key2_pub.into());
        assert_eq!(p2p_peers_1a[0].public_key, key2_pub);
        assert_eq!(*p2p_peers_1a[0].address, swarm2_addr.clone());
        assert!(*p2p_peers_1a[0].last_dialed_at - utc_now < time::Duration::seconds(5));

        // Verify that context 2 has the peer from context 1.
        assert_eq!(p2p_peers_2a.len(), 1);
        assert_eq!(*p2p_peers_2a[0].peer_id, key1_pub.into());
        assert_eq!(p2p_peers_2a[0].public_key, key1_pub);
        assert_eq!(*p2p_peers_2a[0].address, swarm1_addr.clone());
        assert!(*p2p_peers_2a[0].last_dialed_at - utc_now < time::Duration::seconds(5));

        // Trigger shutdown
        term1.signal_shutdown();
        term2.signal_shutdown();
    }

    #[test_log::test(tokio::test)]
    async fn libp2p_swarm_bootstraps_with_known_peers() {
        let rng = &mut get_rng();
        let swarm1_addr = Multiaddr::random_memory(rng);
        let swarm2_addr = Multiaddr::random_memory(rng);

        // PeerId = 16Uiu2HAm46BSFWYYWzMjhTRDRwXHpDWpQ32iu93nzDwd1F4Tt256
        let key1 = PrivateKey::from_slice(
            hex::decode("ab0893ecf683dc188c3fb219dd6489dc304bb5babb8151a41245a70e60cb7258")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let key1_pub = PublicKey::from_private_key(&key1);

        // PeerId = 16Uiu2HAkuyB8ECXxACm8hzQj4vZ2iWrYMF3xcKNf1oJJ1NuQEMvQ
        let key2 = PrivateKey::from_slice(
            hex::decode("0dd4077c8bcec09c803f9ba23a0f5b56eba75769b2d1b96a33b579dbbe5055ce")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let key2_pub = PublicKey::from_private_key(&key2);

        // Create two contexts with different keys but in same signer set.
        let context1 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .with_private_key(key1)
            .build();

        let context2 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .with_private_key(key2)
            .build();

        // Add each key to the other's signer set so they can connect.
        context1.state().current_signer_set().add_signer(key2_pub);
        context2.state().current_signer_set().add_signer(key1_pub);

        // Create the swarms. Swarm 1 will bootstrap to swarm 2 via known peers.
        let swarm1 = SignerSwarmBuilder::new(&key1)
            .enable_mdns(false)
            .enable_kademlia(false)
            .enable_autonat(false)
            .enable_memory_transport(true)
            .with_initial_bootstrap_delay(Duration::ZERO) // Connect immediately
            .add_known_peers(&[(key2_pub.into(), swarm2_addr.clone())])
            .add_listen_endpoint(swarm1_addr.clone())
            .build()
            .expect("Failed to build swarm 1");
        let swarm2 = SignerSwarmBuilder::new(&key2)
            .enable_mdns(false)
            .enable_kademlia(false)
            .enable_autonat(false)
            .enable_memory_transport(true)
            .with_initial_bootstrap_delay(Duration::MAX) // Let swarm1 bootstrap
            .add_listen_endpoint(swarm2_addr.clone())
            .build()
            .expect("Failed to build swarm 2");

        // For timestamp assertion later
        let utc_now = time::OffsetDateTime::now_utc();

        // Start the two swarms (swarm 2 first as swarm 1 will bootstrap to it).
        let mut swarm2_clone = swarm2.clone();
        let context2_clone = context2.clone();
        tokio::spawn(async move {
            swarm2_clone.start(&context2_clone).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; // Quick pause to ensure swarm2 is ready
        let mut swarm1_clone = swarm1.clone();
        let context1_clone = context1.clone();
        tokio::spawn(async move {
            swarm1_clone.start(&context1_clone).await.unwrap();
        });

        // Wait for the swarms to start.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Get the peers stored in context 1 after bootstrapping
        let p2p_peers_1a = context1.get_storage().get_p2p_peers().await.unwrap();

        // Verify that context 1 has the peer from signer 2. We only only validate
        // context 1's stored signers because signer 1 is the dialer (incoming connections
        // do not update stored known peers due to the risk of ephemeral ports/NAT).
        assert_eq!(p2p_peers_1a.len(), 1);
        assert_eq!(*p2p_peers_1a[0].peer_id, key2_pub.into());
        assert_eq!(p2p_peers_1a[0].public_key, key2_pub);
        assert_eq!(*p2p_peers_1a[0].address, swarm2_addr);
        assert!(*p2p_peers_1a[0].last_dialed_at - utc_now < time::Duration::seconds(5));

        // Verify that context 2 has no peers stored, as it was not the dialer
        let p2p_peers_2a = context2.get_storage().get_p2p_peers().await.unwrap();
        assert!(p2p_peers_2a.is_empty());
    }
}
