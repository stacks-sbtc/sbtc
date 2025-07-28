//! This module provides a poller for detecting new blocks on the Bitcoin
//! blockchain.
//!
//! The `BitcoinChainTipPoller` is the primary component, responsible for
//! periodically calling the `getbestblockhash` RPC method on a Bitcoin Core
//! node. When it detects a new block hash, it broadcasts it to all subscribers.
//!
//! This approach provides a resilient, event-driven stream of new block hashes
//! that other components, like the `BlockObserver`, can consume. The poller is
//! designed to be robust, handling transient RPC errors by logging and retrying,
//! ensuring continuous operation as long as the Bitcoin node is reachable.
//!
//! The poller is created using the `BitcoinChainTipPollerBuilder`, which
//! provides a fluent interface for configuration.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::BlockHash;
use futures::stream::Stream;
use futures::stream::StreamExt as _;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use crate::bitcoin::BitcoinBlockHashStreamProvider;
use crate::bitcoin::BitcoinInteract;
use crate::error::Error;
use crate::util::SleepAsyncExt as _;

/// The default interval at which the poller will check for a new chain tip.
const DEFAULT_POLLING_INTERVAL: Duration = Duration::from_secs(5);
/// The default capacity of the broadcast channel for sending new block hashes.
const DEFAULT_BROADCAST_CAPACITY: usize = 1000;
/// The default timeout for the poller's initial connection to the RPC endpoint.
const DEFAULT_INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(60);

/// Error type for subscribers of the `BitcoinChainTipPoller`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BitcoinChainTipPollerError {
    /// A subscriber to the ZMQ block hash broadcast lagged too far behind
    /// and missed messages. The inner u64 is the number of messages missed.
    #[error("subscriber lagged behind broadcast channel: {0} messages missed")]
    SubscriberLagged(u64),
}

/// A builder for creating and configuring a `BitcoinChainTipPoller`.
///
/// This provides a fluent interface for setting up a poller instance.
pub struct BitcoinChainTipPollerBuilder<Bitcoin>
where
    Bitcoin: BitcoinInteract + 'static,
{
    rpc: Bitcoin,
    polling_interval: Duration,
    init_timeout: Duration,
}

impl<Bitcoin> BitcoinChainTipPollerBuilder<Bitcoin>
where
    Bitcoin: BitcoinInteract + 'static,
{
    /// Creates a new builder for a `BitcoinChainTipPoller`.
    ///
    /// The `rpc` client is required. Polling interval and initialization
    /// timeout will use default values unless otherwise configured.
    pub fn new(rpc: Bitcoin) -> Self {
        Self {
            rpc,
            polling_interval: DEFAULT_POLLING_INTERVAL,
            init_timeout: DEFAULT_INITIALIZATION_TIMEOUT,
        }
    }

    /// Sets a custom polling interval for the poller.
    pub fn with_polling_interval(mut self, polling_interval: Duration) -> Self {
        self.polling_interval = polling_interval;
        self
    }

    /// Sets a custom timeout for the initial connection to the RPC.
    pub fn with_init_timeout(mut self, init_timeout: Duration) -> Self {
        self.init_timeout = init_timeout;
        self
    }

    /// Builds and starts the `BitcoinChainTipPoller`.
    ///
    /// This function consumes the builder and spawns the background polling task.
    /// It will not return until it has successfully fetched the initial best
    /// block hash from the RPC, or until the `init_timeout` is reached.
    pub async fn start(self) -> Result<BitcoinChainTipPoller, Error> {
        BitcoinChainTipPoller::start(self.rpc, self.polling_interval, self.init_timeout).await
    }
}

/// A poller that periodically checks for and broadcasts new Bitcoin chain tips.
///
/// This struct manages a background task that polls a Bitcoin Core node's RPC
/// to get the latest block hash. It provides a stream of these hashes that other
/// parts of the application can subscribe to.
#[derive(Clone)]
pub struct BitcoinChainTipPoller {
    /// The sender for the broadcast channel that distributes new block hashes.
    broadcast_tx: broadcast::Sender<BlockHash>,
    /// A handle to the background polling task, used for graceful shutdown.
    poller_task_handle: Arc<JoinHandle<()>>,
}

/// Runs the RPC polling loop in a background task.
///
/// This function polls the `getbestblockhash` RPC method at a regular interval,
/// detects new block hashes, and broadcasts them on the provided channel.
async fn run_rpc_poller<Bitcoin>(
    rpc: Bitcoin,
    broadcast_tx: broadcast::Sender<BlockHash>,
    polling_interval: Duration,
    initial_hash: BlockHash,
) where
    Bitcoin: BitcoinInteract,
{
    let mut last_seen_hash = initial_hash;

    loop {
        polling_interval.sleep().await;

        match rpc.get_best_block_hash().await {
            Ok(current_hash) => {
                if current_hash != last_seen_hash {
                    tracing::info!(new_hash = %current_hash, "detected new best block hash");
                    last_seen_hash = current_hash;
                    if broadcast_tx.send(current_hash).is_err() {
                        tracing::warn!("broadcasting new block hash failed; no subscribers?");
                    }
                }
            }
            Err(e) => {
                // On a transient error, log it and continue polling. Do not send the
                // error to consumers, as they cannot act on it.
                tracing::error!(error = %e, "failed to get best block hash during polling; will retry.");
            }
        }
    }
}

impl BitcoinChainTipPoller {
    /// Creates a new builder for a `BitcoinChainTipPoller`.
    ///
    /// This is the main entry point for creating a new poller instance.
    pub fn builder<Bitcoin>(rpc: Bitcoin) -> BitcoinChainTipPollerBuilder<Bitcoin>
    where
        Bitcoin: BitcoinInteract + 'static,
    {
        BitcoinChainTipPollerBuilder::new(rpc)
    }

    /// Creates and starts a new `BitcoinChainTipPoller` task.
    ///
    /// This private method is called by the builder. It attempts to fetch the
    /// initial block hash within a timeout and then spawns the long-running
    /// poller task.
    async fn start<Bitcoin>(
        rpc: Bitcoin,
        polling_interval: Duration,
        init_timeout: Duration,
    ) -> Result<Self, Error>
    where
        Bitcoin: BitcoinInteract + 'static,
    {
        let start_time = tokio::time::Instant::now();
        let mut last_error;

        // Try to fetch the initial hash, retrying until the timeout is reached.
        let initial_hash = loop {
            match rpc.get_best_block_hash().await {
                Ok(hash) => break hash,
                Err(e) => {
                    last_error = e;
                    if start_time.elapsed() >= init_timeout {
                        tracing::error!(error = %last_error, "timed out getting initial block hash");
                        return Err(Error::BitcoinChainTipPollerInitialization {
                            last_error: Box::new(last_error),
                            timeout: init_timeout,
                        });
                    }
                    tracing::warn!(error = %last_error, "failed to get initial block hash, retrying...");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };

        let (broadcast_tx, _rx) = broadcast::channel::<BlockHash>(DEFAULT_BROADCAST_CAPACITY);

        // Broadcast the initial hash.
        if broadcast_tx.send(initial_hash).is_err() {
            tracing::warn!("no subscribers at initial broadcast, continuing anyway");
        }

        // Spawn the RPC polling task.
        let poller_task_handle = tokio::spawn(run_rpc_poller(
            rpc,
            broadcast_tx.clone(),
            polling_interval,
            initial_hash,
        ));

        Ok(Self {
            broadcast_tx,
            poller_task_handle: Arc::new(poller_task_handle),
        })
    }

    /// Stops the background polling task.
    pub fn stop(&self) {
        self.poller_task_handle.abort();
    }
}

impl BitcoinBlockHashStreamProvider for BitcoinChainTipPoller {
    type Error = BitcoinChainTipPollerError;

    /// Subscribes to the poller, returning a new stream of block hashes.
    fn get_block_hash_stream(
        &self,
    ) -> impl Stream<Item = Result<BlockHash, BitcoinChainTipPollerError>> + Send + Sync + 'static
    {
        BroadcastStream::new(self.broadcast_tx.subscribe()).map(|item_from_broadcast| {
            // The stream from the broadcast channel is now either a valid block hash
            // or a Lagged error. We map these directly to our stream's item type.
            item_from_broadcast.map_err(|e| match e {
                BroadcastStreamRecvError::Lagged(count) => {
                    BitcoinChainTipPollerError::SubscriberLagged(count)
                }
            })
        })
    }
}
