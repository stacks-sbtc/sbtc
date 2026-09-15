use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::Sender;

use crate::{
    SIGNER_CHANNEL_CAPACITY,
    bitcoin::{BitcoinInteract, rpc::BitcoinCoreClientParams},
    config::{EmilyClientConfig, Settings},
    emily_client::EmilyInteract,
    error::Error,
    stacks::api::StacksInteract,
    storage::{DbRead, DbWrite, Transactable},
};

use super::{Context, SignerSignal, SignerState, TerminationHandle};

/// Network identity reported by the connected nodes at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeNetwork {
    /// The Stacks chain ID reported by `/v2/info` as `network_id`.
    pub stacks_chain_id: u32,
    /// The Bitcoin network reported by `getblockchaininfo`.
    pub bitcoin_network: bitcoin::Network,
}

impl NodeNetwork {
    /// Returns true if the Stacks chain is mainnet.
    pub fn is_stacks_mainnet(&self) -> bool {
        self.stacks_chain_id == stacks_common::consts::CHAIN_ID_MAINNET
    }
}

/// Signer context which is passed to different components within the
/// signer binary.
#[derive(Debug, Clone)]
pub struct SignerContext<S, BC, ST, EM> {
    config: Settings,
    /// The network identity reported by the connected nodes at startup.
    node_network: NodeNetwork,
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

        // Call the underlying clients so fallback retries do not multiply the
        // startup retry budget or bypass the delay between attempts.
        let (bitcoin_info, stacks_info) = tokio::try_join!(
            retry_node_request("Bitcoin", || bc.get_blockchain_info()),
            retry_node_request("Stacks", || st.get_node_info()),
        )?;
        let network = NodeNetwork {
            stacks_chain_id: stacks_info.network_id,
            bitcoin_network: bitcoin_info.chain,
        };
        config
            .validate_network(&network)
            .map_err(Error::SignerConfig)?;
        tracing::info!(?network, "discovered node network identity");

        Ok(Self::new(config, db, bc, st, em, network))
    }
}

impl<S, BC, ST, EM> SignerContext<S, BC, ST, EM>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: BitcoinInteract + Clone,
    ST: StacksInteract + Clone + Sync + Send,
    EM: EmilyInteract + Clone + Sync + Send,
{
    /// Create a signer context with supplied clients and a known network identity.
    pub fn new(
        config: Settings,
        db: S,
        bitcoin_client: BC,
        stacks_client: ST,
        emily_client: EM,
        node_network: NodeNetwork,
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
            node_network,
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

    fn node_network(&self) -> NodeNetwork {
        self.node_network
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
    use std::sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    };

    use tokio::sync::Notify;

    use crate::storage::model::BitcoinBlockRef;
    use crate::{
        context::{Context as _, SignerEvent, SignerSignal},
        testing::context::*,
    };

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

/// Make an initial request and up to three retries, waiting three seconds
/// after each failed attempt. Exhaustion prevents the signer from starting.
async fn retry_node_request<T, F, Fut>(node: &str, mut request: F) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, Error>>,
{
    const MAX_RETRIES: u8 = 3;
    const RETRY_DELAY: Duration = Duration::from_secs(3);

    for attempt in 0..=MAX_RETRIES {
        match request().await {
            Ok(value) => return Ok(value),
            Err(error) if attempt == MAX_RETRIES => {
                tracing::error!(node, %error, "failed to discover node network identity");
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(node, %error, retry = attempt + 1, "retrying node network discovery in three seconds");
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
    unreachable!("the final attempt always returns")
}

#[cfg(test)]
mod network_discovery_tests {
    use super::*;

    use stacks_common::consts::CHAIN_ID_TESTNET;

    use crate::bitcoin::rpc::BitcoinCoreClient;
    use crate::emily_client::EmilyClient;
    use crate::stacks::api::StacksClient;
    use crate::util::ApiFallbackClient;

    #[test_case::test_case(false, false, false; "networks known on creation")]
    #[test_case::test_case(true, false, false; "bitcoin discovery fails")]
    #[test_case::test_case(false, true, false; "stacks discovery fails")]
    #[test_case::test_case(false, false, true; "network validation fails")]
    #[tokio::test]
    async fn init_discovers_and_validates_networks(
        bitcoin_fails: bool,
        stacks_fails: bool,
        invalid_deployer: bool,
    ) {
        let mut bitcoin_server = mockito::Server::new_async().await;
        let mut stacks_server = mockito::Server::new_async().await;
        let bitcoin_mock = bitcoin_server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(
                serde_json::json!({"method": "getblockchaininfo"}),
            ))
            .with_status(if bitcoin_fails { 500 } else { 200 })
            .with_header("content-type", "application/json")
            .with_body_from_request(move |request| {
                let request: serde_json::Value =
                    serde_json::from_slice(request.body().unwrap()).unwrap();
                if bitcoin_fails {
                    return serde_json::json!({"result": null, "error": {"code": -1, "message": "node unavailable"}, "id": request["id"]}).to_string().into_bytes();
                }
                let result: serde_json::Value = serde_json::from_str(include_str!(
                    "../../tests/fixtures/bitcoind-getblockchaininfo-data.json"
                ))
                .unwrap();
                serde_json::json!({"result": result, "error": null, "id": request["id"]})
                    .to_string()
                    .into_bytes()
            })
            .expect(if bitcoin_fails { 4 } else { 1 })
            .create_async()
            .await;
        // The Bitcoin RPC library also queries the node version while decoding
        // getblockchaininfo, to handle older softfork response formats.
        let version_mock = bitcoin_server.mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({"method": "getnetworkinfo"})))
            .with_status(200)
            .with_body_from_request(|request| {
                let request: serde_json::Value = serde_json::from_slice(request.body().unwrap()).unwrap();
                serde_json::json!({"result": {"version": 300000}, "error": null, "id": request["id"]}).to_string().into_bytes()
            })
            .expect(if bitcoin_fails { 0 } else { 1 })
            .create_async().await;
        let stacks_mock = stacks_server
            .mock("GET", "/v2/info")
            .with_status(if stacks_fails { 500 } else { 200 })
            .with_header("content-type", "application/json")
            .with_body(include_str!(
                "../../tests/fixtures/stacksapi-get-node-info-test-data.json"
            ))
            .expect(if stacks_fails { 4 } else { 1 })
            .create_async()
            .await;
        let mut config = Settings::new_from_default_config().unwrap();
        config.bitcoin.rpc_endpoints = vec![bitcoin_server.url().parse().unwrap()];
        config.stacks.endpoints = vec![stacks_server.url().parse().unwrap()];
        if invalid_deployer {
            config.signer.deployer =
                stacks_common::types::chainstate::StacksAddress::burn_address(true);
        }
        let result = SignerContext::<
            _,
            ApiFallbackClient<BitcoinCoreClient>,
            ApiFallbackClient<StacksClient>,
            ApiFallbackClient<EmilyClient>,
        >::init(config, crate::storage::memory::Store::new_shared())
        .await;
        if bitcoin_fails || stacks_fails {
            assert!(result.is_err());
        } else if invalid_deployer {
            assert!(matches!(result, Err(Error::SignerConfig(_))));
        } else {
            let context = result.unwrap();
            let expected = NodeNetwork {
                stacks_chain_id: CHAIN_ID_TESTNET,
                bitcoin_network: bitcoin::Network::Regtest,
            };
            assert_eq!(context.node_network(), expected);
            assert_eq!(context.clone().node_network(), expected);
        }
        bitcoin_mock.assert_async().await;
        version_mock.assert_async().await;
        stacks_mock.assert_async().await;
    }

    #[tokio::test]
    async fn node_discovery_stops_after_success() {
        let mut attempts = 0;
        let result = retry_node_request("test", || {
            attempts += 1;
            std::future::ready(Ok(42))
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn node_discovery_retries_with_delays_and_can_recover_on_last_attempt() {
        let mut attempts = Vec::new();
        let result = retry_node_request("test", || {
            attempts.push(tokio::time::Instant::now());
            std::future::ready(if attempts.len() == 4 {
                Ok(42)
            } else {
                Err(Error::SignerShutdown)
            })
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.len(), 4);
        for pair in attempts.windows(2) {
            assert!(pair[1].duration_since(pair[0]) >= Duration::from_secs(3));
        }
    }

    #[tokio::test]
    async fn node_discovery_returns_error_after_three_retries() {
        let mut attempts = 0;
        let result = retry_node_request("test", || {
            attempts += 1;
            std::future::ready(Err::<(), _>(Error::SignerShutdown))
        })
        .await;
        assert!(matches!(result, Err(Error::SignerShutdown)));
        assert_eq!(attempts, 4);
    }
}
