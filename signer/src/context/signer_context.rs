use std::sync::Arc;
use tokio::sync::OnceCell;
use tokio::sync::broadcast::Sender;

use crate::{
    SIGNER_CHANNEL_CAPACITY,
    bitcoin::{BitcoinInteract, rpc::BitcoinCoreClientParams},
    config::{EmilyClientConfig, Settings},
    emily_client::EmilyInteract,
    error::Error,
    stacks::api::{StacksChainId, StacksInteract},
    storage::{DbRead, DbWrite, Transactable},
};

use super::{Context, SignerSignal, SignerState, TerminationHandle};

/// Network identity reported by the connected nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeNetwork {
    /// The Stacks chain ID reported by `/v2/info` as `network_id`.
    pub stacks_chain_id: StacksChainId,
    /// The Bitcoin network reported by `getblockchaininfo`.
    pub bitcoin_network: bitcoin::Network,
}

impl NodeNetwork {
    /// Returns true if the connected Stacks node is on mainnet.
    pub fn is_stacks_mainnet(&self) -> bool {
        self.stacks_chain_id.is_mainnet()
    }
}

/// Signer context which is passed to different components within the
/// signer binary.
#[derive(Debug, Clone)]
pub struct SignerContext<S, BC, ST, EM> {
    config: Settings,
    /// The Bitcoin and Stacks networks identities.
    node_network: Arc<OnceCell<NodeNetwork>>,
    // Handle to the app signalling channel. This keeps the channel alive
    // for the duration of the program and is used both to send messages
    // and to hand out new receivers.
    signal_tx: Sender<SignerSignal>,
    /// The internal state of the signer.
    state: Arc<SignerState>,
    /// Handle to the app termination channel. This keeps the channel alive
    /// for the duration of the program and is used to provide new senders
    /// and receivers for a [`TerminationHandle`].
    term_tx: tokio::sync::watch::Sender<bool>,
    /// Handle to the signer storage.
    storage: S,
    /// Handle to a Bitcoin-RPC fallback-client.
    bitcoin_client: BC,
    // TODO: Additional clients to be added in future PRs. We may want
    // to break the clients out into a separate struct to keep the field
    // count down.
    /// Handle to a Stacks-RPC fallback-client.
    stacks_client: ST,
    /// Handle to a Emily-API fallback-client.
    emily_client: EM,
    // /// Handle to a Blocklist-API fallback-client.
    //blocklist_client: ApiFallbackClient<BL>,
}

impl<S, BC, ST, EM> SignerContext<S, BC, ST, EM>
where
    S: DbRead + DbWrite + Clone + Sync + Send + 'static,
    BC: TryFrom<Vec<BitcoinCoreClientParams>> + BitcoinInteract + Clone + 'static,
    ST: for<'a> TryFrom<&'a Settings> + StacksInteract + Clone + Sync + Send + 'static,
    EM: for<'a> TryFrom<&'a EmilyClientConfig> + EmilyInteract + Clone + Sync + Send + 'static,
    Error: From<<BC as TryFrom<Vec<BitcoinCoreClientParams>>>::Error>,
    Error: for<'a> From<<ST as TryFrom<&'a Settings>>::Error>,
    Error: for<'a> From<<EM as TryFrom<&'a EmilyClientConfig>>::Error>,
{
    /// Initializes a new [`SignerContext`], automatically creating clients
    /// based on the provided types.
    pub async fn init(config: Settings, db: S) -> Result<Self, Error> {
        let bitcoin_params = config
            .bitcoin
            .rpc_endpoints
            .iter()
            .map(|url| BitcoinCoreClientParams {
                url: url.clone(),
                timeout: config.bitcoin.timeout,
            })
            .collect();
        let bc = BC::try_from(bitcoin_params)?;
        let st = ST::try_from(&config)?;
        let em = EM::try_from(&config.emily)?;

        Ok(Self::new(config, db, bc, st, em, None))
    }
}

impl<S, BC, ST, EM> SignerContext<S, BC, ST, EM>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: BitcoinInteract + Clone,
    ST: StacksInteract + Clone + Sync + Send,
    EM: EmilyInteract + Clone + Sync + Send,
{
    /// Create a signer context.
    pub fn new(
        config: Settings,
        db: S,
        bitcoin_client: BC,
        stacks_client: ST,
        emily_client: EM,
        node_network: Option<NodeNetwork>,
    ) -> Self {
        // TODO: Decide on the channel capacity and how we should handle slow consumers.
        // NOTE: Ideally consumers which require processing time should pull the relevent
        // messages into a local VecDequeue and process them in their own time.
        let (signal_tx, _) = tokio::sync::broadcast::channel(SIGNER_CHANNEL_CAPACITY);
        let (term_tx, _) = tokio::sync::watch::channel(false);
        let state = SignerState::default();
        if let Some(height) = config.signer.sbtc_bitcoin_start_height {
            state.set_sbtc_bitcoin_start_height(height);
        }

        Self {
            config,
            node_network: Arc::new(OnceCell::new_with(node_network)),
            state: Arc::new(state),
            signal_tx,
            term_tx,
            storage: db,
            bitcoin_client,
            stacks_client,
            emily_client,
        }
    }
}

impl<S, BC, ST, EM> Context for SignerContext<S, BC, ST, EM>
where
    S: DbRead + DbWrite + Transactable + Clone + Sync + Send + 'static,
    BC: BitcoinInteract + Clone + 'static,
    ST: StacksInteract + Clone + Sync + Send + 'static,
    EM: EmilyInteract + Clone + Sync + Send + 'static,
{
    fn config(&self) -> &Settings {
        &self.config
    }

    async fn node_network(&self) -> Result<NodeNetwork, Error> {
        self.node_network
            .get_or_try_init(|| async {
                let (bitcoin_info, stacks_info) = tokio::try_join!(
                    self.bitcoin_client.get_blockchain_info(),
                    self.stacks_client.get_node_info()
                )?;
                let network = NodeNetwork {
                    stacks_chain_id: stacks_info.network_id,
                    bitcoin_network: bitcoin_info.chain,
                };
                self.config
                    .validate_network(&network)
                    .inspect_err(|error| {
                        // A configuration validation failure is fatal.
                        tracing::error!(%error, ?network, "node network validation failed; shutting down");
                        self.get_termination_handle().signal_shutdown();
                    })
                    .map_err(Error::SignerConfig)?;

                tracing::debug!(?network, "discovered node network identity");
                Ok(network)
            })
            .await
            .copied()
    }

    fn state(&self) -> &Arc<SignerState> {
        &self.state
    }

    fn get_signal_receiver(&self) -> tokio::sync::broadcast::Receiver<SignerSignal> {
        self.signal_tx.subscribe()
    }

    fn get_signal_sender(&self) -> tokio::sync::broadcast::Sender<SignerSignal> {
        self.signal_tx.clone()
    }

    /// Send a signal to the application signalling channel.
    fn signal(&self, signal: SignerSignal) -> Result<(), Error> {
        self.signal_tx
            .send(signal)
            .map_err(|_| {
                // This realistically shouldn't ever happen
                tracing::warn!("failed to send signal to the application, no receivers present.");
                // Send a shutdown signal, just in-case.
                self.get_termination_handle().signal_shutdown();
                Error::SignerShutdown
            })
            .map(|_| ())
    }

    fn get_termination_handle(&self) -> TerminationHandle {
        TerminationHandle::new(self.term_tx.clone(), self.term_tx.subscribe())
    }

    fn get_storage(&self) -> impl DbRead + Clone + Sync + Send + 'static {
        self.storage.clone()
    }

    fn get_storage_mut(
        &self,
    ) -> impl DbRead + DbWrite + Transactable + Clone + Sync + Send + 'static {
        self.storage.clone()
    }

    fn get_bitcoin_client(&self) -> impl BitcoinInteract + Clone + 'static {
        self.bitcoin_client.clone()
    }

    fn get_stacks_client(&self) -> impl StacksInteract + Clone + 'static {
        self.stacks_client.clone()
    }

    fn get_emily_client(&self) -> impl EmilyInteract + Clone + 'static {
        self.emily_client.clone()
    }
}

#[cfg(any(test, feature = "testing"))]
impl<Storage, Bitcoin, Stacks, Emily> SignerContext<Storage, Bitcoin, Stacks, Emily> {
    /// Get a mutable reference to the config.
    pub fn config_mut(&mut self) -> &mut Settings {
        &mut self.config
    }

    /// Resets the termination signal for this context.
    ///
    /// This sets the underlying termination state to `false`, allowing
    /// new `TerminationHandle` instances or existing ones (that haven't
    /// been dropped) to reflect a non-terminated state. This is primarily
    /// useful in testing scenarios where a context is reused after a
    /// simulated shutdown.
    pub fn reset_termination_signal(&self) {
        // Send `false` to the watch channel, indicating not terminated.
        // The result of `send` is ignored here. If all receivers were dropped,
        // there's no one to signal, but the internal state of the sender
        // will be updated to `false`.
        let _ = self.term_tx.send(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::sync::atomic::{AtomicU8, Ordering};

    use tokio::sync::Notify;

    use crate::{
        context::SignerEvent,
        stacks::api::GetNodeInfoResponse,
        storage::{memory::SharedStore, model::BitcoinBlockRef},
        testing::context::*,
    };

    type MockContext = TestContext<
        SharedStore,
        WrappedMockBitcoinInteract,
        WrappedMockStacksInteract,
        WrappedMockEmilyInteract,
    >;

    const EXPECTED_NETWORK: NodeNetwork = NodeNetwork {
        stacks_chain_id: StacksChainId::TESTNET,
        bitcoin_network: bitcoin::Network::Regtest,
    };

    fn node_info(chain_id: StacksChainId) -> GetNodeInfoResponse {
        let mut info: GetNodeInfoResponse = serde_json::from_str(include_str!(
            "../../tests/fixtures/stacksapi-get-node-info-test-data.json"
        ))
        .unwrap();
        info.network_id = chain_id;
        info
    }

    /// Start with an empty cache and return the supplied Stacks responses in order.
    /// Bitcoin always reports regtest. Each response allows one discovery attempt.
    async fn context_with_network_responses<const N: usize>(
        responses: [Result<GetNodeInfoResponse, Error>; N],
    ) -> MockContext {
        let mut context = TestContext::default_mocked();
        // TestContext normally seeds a known network, bypassing discovery.
        context.inner.node_network = Arc::new(tokio::sync::OnceCell::new());
        context
            .with_bitcoin_client(|client| {
                client.expect_get_blockchain_info().times(N).returning(|| {
                    Box::pin(async {
                        // Allow concurrent callers to reach the uninitialized cache.
                        tokio::task::yield_now().await;
                        Ok(serde_json::from_str(include_str!(
                            "../../tests/fixtures/bitcoind-getblockchaininfo-data.json"
                        ))
                        .unwrap())
                    })
                });
            })
            .await;
        context
            .with_stacks_client(|client| {
                for response in responses {
                    client
                        .expect_get_node_info()
                        .once()
                        .return_once(move || Box::pin(async move { response }));
                }
            })
            .await;
        context
    }

    #[tokio::test]
    async fn node_network_retries_after_rpc_error() {
        let context = context_with_network_responses([
            Err(Error::Dummy),
            Ok(node_info(StacksChainId::TESTNET)),
        ])
        .await;

        let termination = context.get_termination_handle();

        assert_matches!(context.node_network().await, Err(Error::Dummy));
        assert!(context.inner.node_network.get().is_none());
        assert!(!termination.shutdown_signalled());

        assert_eq!(context.node_network().await.unwrap(), EXPECTED_NETWORK);
        assert_eq!(context.node_network().await.unwrap(), EXPECTED_NETWORK);
        assert!(!termination.shutdown_signalled());
    }

    #[tokio::test]
    async fn node_network_validation_error_signals_shutdown() {
        // The test config uses a testnet deployer, so mainnet fails validation.
        let context = context_with_network_responses([Ok(node_info(StacksChainId::MAINNET))]).await;
        let other_component = context.clone();
        let mut termination = other_component.get_termination_handle();
        assert!(!termination.shutdown_signalled());

        // Handling the error must not prevent other components from shutting down.
        assert_matches!(context.node_network().await, Err(Error::SignerConfig(_)));
        assert!(context.inner.node_network.get().is_none());
        assert!(termination.shutdown_signalled());

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            termination.wait_for_shutdown(),
        )
        .await
        .expect("network validation failure must notify shutdown listeners");

        // Components still starting when validation failed must also stop.
        let mut late_subscriber = context.get_termination_handle();
        assert!(late_subscriber.shutdown_signalled());
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            late_subscriber.wait_for_shutdown(),
        )
        .await
        .expect("listeners created after shutdown must not wait for another signal");
    }

    /// This test shows that cloning a context and signalling on the original
    /// context will also signal on the cloned context. But it also demonstrates
    /// that there can be timing issues (particularly in tests) when signalling
    /// across threads/clones, and shows how to handle that.
    #[tokio::test]
    async fn context_clone_signalling_works() {
        // Create a context.
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        // Clone the context.
        let context_clone = context.clone();

        // Get the receiver from the cloned context.
        let mut cloned_receiver = context_clone.get_signal_receiver();

        // Create a counter to track how many signals are received and some
        // Notify channels so that we ensure we don't hit timing issues.
        let recv_count = Arc::new(AtomicU8::new(0));
        let task_started = Arc::new(Notify::new());
        let task_completed = Arc::new(Notify::new());

        // Spawn a task that will receive a signal (and clone values that will
        // be used in the `move` closure). We will receive on the cloned context.
        let task_started_clone = Arc::clone(&task_started);
        let task_completed_clone = Arc::clone(&task_completed);
        let recv_count_clone = Arc::clone(&recv_count);
        tokio::spawn(async move {
            task_started_clone.notify_one();
            let signal = cloned_receiver.recv().await.unwrap();

            assert_matches::assert_matches!(
                signal,
                SignerSignal::Event(SignerEvent::BitcoinBlockObserved(_))
            );

            recv_count_clone.fetch_add(1, Ordering::Relaxed);
            task_completed_clone.notify_one();
        });

        // This wait is needed to ensure that the `recv_task` is started and
        // the receiver subscribed before we send the signal. Otherwise, the
        // signal may be sent before the receiver is ready to receive it,
        // failing the test.
        task_started.notified().await;

        // Signal the original context.
        context
            .signal(SignerEvent::BitcoinBlockObserved(BitcoinBlockRef::genesis()).into())
            .unwrap();

        // This wait is needed to ensure that the below `abort()` doesn't
        // kill the task before it has a chance to update `recv_count`.
        task_completed.notified().await;

        // Ensure that the signal was received.
        assert_eq!(recv_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
