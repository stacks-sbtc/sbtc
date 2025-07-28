//! This module provides functionality for receiving new blocks from
//! bitcoin-core's ZeroMQ interface[1]. From the bitcoin-core docs:
//!
//! > The ZeroMQ facility implements a notification interface through a set of
//! > specific notifiers. Currently, there are notifiers that publish blocks and
//! > transactions. This read-only facility requires only the connection of a
//! > corresponding ZeroMQ subscriber port in receiving software; it is not
//! > authenticated nor is there any two-way protocol involvement. Therefore,
//! > subscribers should validate the received data since it may be out of date,
//! > incomplete or even invalid.
//!
//! > ZeroMQ sockets are self-connecting and self-healing; that is, connections
//! > made between two endpoints will be automatically restored after an outage,
//! > and either end may be freely started or stopped in any order.
//!
//! > Because ZeroMQ is message oriented, subscribers receive transactions and
//! > blocks all-at-once and do not need to implement any sort of buffering or
//! > reassembly.
//!
//! [^1]: https://github.com/bitcoin/bitcoin/blob/870447fd585e5926b4ce4e83db31c59b1be45a50/doc/zmq.md
//!
//! ### Testing Notes
//!
//! - When testing this module within the signer (i.e. in `devenv`), it is
//!   important that bitcoind's state be preserved between stops/starts. For
//!   docker compose, this means that you should use the `stop` command and not
//!   the `down` command.

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

const DEFAULT_POLLING_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_BROADCAST_CAPACITY: usize = 1000;
const INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(60);

/// Error type for the Bitcoin ZMQ module, encapsulating errors related to
/// the ZMQ data source or subscriber issues.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BitcoinChainTipPollerError {
    /// A subscriber to the ZMQ block hash broadcast lagged too far behind
    /// and missed messages. The inner u64 is the number of messages missed.
    #[error("subscriber lagged behind broadcast channel: {0} messages missed")]
    SubscriberLagged(u64),
}

/// A builder for creating and configuring a `BitcoinChainTipPoller`.
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
            init_timeout: INITIALIZATION_TIMEOUT,
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
    /// This function will not return until it has successfully fetched the
    /// initial best block hash from the RPC, or until the `init_timeout`
    /// is reached.
    pub async fn start(self) -> Result<BitcoinChainTipPoller, Error> {
        BitcoinChainTipPoller::start(self.rpc, self.polling_interval, self.init_timeout).await
    }
}

/// The `BitcoinChainTipPoller` is responsible for managing the ZMQ polling task
/// and providing a stream of block hashes received from the Bitcoin Core ZMQ interface.
/// It connects to the specified ZMQ endpoint, listens for block hash messages, and
/// broadcasts them to subscribers. This implementation ensures reliable message delivery
/// and handles reconnection logic in case of connection issues.
#[derive(Clone)]
pub struct BitcoinChainTipPoller {
    // The broadcast channel now sends Result<BlockHash, BitcoinChainTipPollerError>
    broadcast_tx: broadcast::Sender<BlockHash>,
    // Keep the task handle to ensure the poller task isn't dropped prematurely
    // and potentially for graceful shutdown in the future.
    poller_task_handle: Arc<JoinHandle<()>>,
}

/// Runs the RPC polling loop.
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
    /// Creates a new `BitcoinChainTipPoller` using the provided Bitcoin client
    /// and polling interval.
    pub fn builder<Bitcoin>(rpc: Bitcoin) -> BitcoinChainTipPollerBuilder<Bitcoin>
    where
        Bitcoin: BitcoinInteract + 'static,
    {
        BitcoinChainTipPollerBuilder::new(rpc)
    }

    /// Creates a new `BitcoinChainTipPoller` using the provided Bitcoin client
    /// and polling interval, starts the task and returns itself. This is called
    /// by the builder.
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
