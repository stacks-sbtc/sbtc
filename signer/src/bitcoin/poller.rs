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
use crate::util::SleepAsyncExt as _;

/// The default capacity of the broadcast channel for sending new block hashes.
const DEFAULT_BROADCAST_CAPACITY: usize = 1000;

/// Error type for subscribers of the [`BitcoinChainTipPoller`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum BitcoinChainTipPollerError {
    /// A subscriber to the block hash broadcast lagged too far behind
    /// and missed messages. The inner u64 is the number of messages missed.
    #[error("subscriber lagged behind broadcast channel: {0} messages missed")]
    SubscriberLagged(u64),
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
) where
    Bitcoin: BitcoinInteract,
{
    let mut last_seen_hash = None;

    loop {
        match rpc.get_best_block_hash().await {
            Ok(current_hash) => {
                if Some(current_hash) != last_seen_hash {
                    tracing::trace!(new_hash = %current_hash, "detected new best block hash");
                    match broadcast_tx.send(current_hash) {
                        Ok(_) => last_seen_hash = Some(current_hash),
                        Err(broadcast::error::SendError(_)) => {
                            tracing::warn!("no active subscribers for block hash broadcast");
                        }
                    }
                }
            }
            Err(error) => {
                // On a transient error, log it and continue polling. Do not send the
                // error to consumers, as they cannot act on it.
                tracing::warn!(%error, "failed to get best block hash during polling; will retry.");
            }
        }

        polling_interval.sleep().await;
    }
}

impl BitcoinChainTipPoller {
    /// Creates and starts a new `BitcoinChainTipPoller` task.
    ///
    /// This private method is called by the builder. It polls the bitcoin node.
    pub async fn start_new<Bitcoin>(rpc: Bitcoin, polling_interval: Duration) -> Self
    where
        Bitcoin: BitcoinInteract + 'static,
    {
        let (broadcast_tx, _rx) = broadcast::channel::<BlockHash>(DEFAULT_BROADCAST_CAPACITY);

        // Spawn the RPC polling task.
        let poller_task_handle =
            tokio::spawn(run_rpc_poller(rpc, broadcast_tx.clone(), polling_interval));

        Self {
            broadcast_tx,
            poller_task_handle: Arc::new(poller_task_handle),
        }
    }

    /// Stops the background polling task.
    pub fn stop(self) {
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
