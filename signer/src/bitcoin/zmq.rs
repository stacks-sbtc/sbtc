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
use bitcoincore_zmq::Message;
use bitcoincore_zmq::SocketEvent;
use bitcoincore_zmq::SocketMessage;
use futures::TryStreamExt as _;
use futures::stream::Stream;
use futures::stream::StreamExt as _;
use tokio::sync::broadcast;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use crate::error::Error;
use crate::util::FutureExt as _;
use crate::util::SleepAsyncExt as _;

const DEFAULT_BROADCAST_CAPACITY: usize = 100;
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// The factor by which the reconnect delay increases after each failed attempt.
const RECONNECT_BACKOFF_FACTOR: f32 = 1.5;

/// Timeout for the initial ZMQ connection attempt in `new_from_endpoint`.
const INITIAL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// The number of seconds to wait before considering a ZMQ connection "stale",
/// triggering a reconnection attempt.
const ZMQ_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour

/// Error type for the Bitcoin ZMQ module, encapsulating errors related to
/// the ZMQ data source or subscriber issues.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BitcoinZmqError {
    /// An error originating from the upstream ZMQ data source or poller.
    /// The inner String contains a description of the original error.
    #[error("internal error: {0}")]
    Internal(String),

    /// An error related to the Bitcoin Core ZMQ interface.
    #[error("bitcoin Core ZMQ error: {0}")]
    BitcoinCoreZmq(String),

    /// A subscriber to the ZMQ block hash broadcast lagged too far behind
    /// and missed messages. The inner u64 is the number of messages missed.
    #[error("subscriber lagged behind ZMQ broadcast: {0} messages missed")]
    SubscriberLagged(u64),
}

/// Represents the control flow decision after processing a ZMQ message.
#[derive(Debug, Clone)]
enum ControlFlow {
    /// Continue processing messages from the current stream.
    Continue,
    /// The stream has ended or an error occurred; break to attempt reconnection.
    Reconnect,
    /// A fatal, unrecoverable error was met; shut down the task.
    Shutdown,
}

/// A trait for providing a stream of block hashes to be used by the block observer.
///
/// Implementors of this trait are responsible for sourcing block hash notifications,
/// typically from a Bitcoin Core ZMQ endpoint, and making them available as an
/// asynchronous stream. This abstraction allows different components, such as
/// block observers or test utilities, to consume block hash events without being
/// coupled to the specific mechanism of how those events are obtained.
pub trait BlockHashStreamProvider: Send + Sync {
    /// Subscribes to the block hash stream, returning a new stream that emits
    /// block hashes as they are received.
    ///
    /// The returned stream will yield `Result<BlockHash, BitcoinZmqError>`.
    ///
    /// Consumers of this stream are responsible for mapping `BitcoinZmqError`
    /// to a broader application error type (like `crate::error::Error`) if needed.
    fn get_block_hash_stream(
        &self,
    ) -> impl futures::Stream<Item = Result<BlockHash, BitcoinZmqError>> + Send + Sync + Unpin + 'static;
}

/// Encapsulates the state and logic for the ZMQ polling task.
struct Poller {
    endpoint: String,
    broadcast_tx: broadcast::Sender<Result<BlockHash, BitcoinZmqError>>,
    initial_conn_signal_tx: Option<oneshot::Sender<Result<(), BitcoinZmqError>>>,
}

impl Poller {
    /// The main entry point for the poller task. Contains the reconnection loop.
    async fn run(mut self) {
        let mut reconnect_attempt: u32 = 0;
        loop {
            // This function now returns a variant that explicitly tells us what to do next.
            match self.connect_and_process_stream().await {
                ControlFlow::Shutdown => {
                    tracing::info!("Poller shutting down.");
                    return;
                }
                ControlFlow::Reconnect => {
                    // A reconnect is needed. Apply backoff and try again.
                    let backoff_duration = calculate_backoff_duration(reconnect_attempt);
                    tracing::info!(
                        endpoint = %self.endpoint,
                        "waiting {backoff_duration:?} before next ZMQ connection attempt."
                    );
                    backoff_duration.sleep().await;
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                }
                ControlFlow::Continue => {
                    // This case should not be returned by connect_and_process_stream.
                    // We'll log a warning and treat it as a reconnect to be safe.
                    tracing::warn!(
                        "connect_and_process_stream returned Continue; treating as Reconnect."
                    );
                    reconnect_attempt = 0; // Reset backoff as this is unexpected.
                }
            }
        }
    }

    /// Attempts to connect to the ZMQ endpoint and, if successful, enters the
    /// message processing loop.
    ///
    /// Returns a `ControlFlow` variant indicating whether to shut down or reconnect.
    async fn connect_and_process_stream(&mut self) -> ControlFlow {
        let zmq_stream = match bitcoincore_zmq::subscribe_async_monitor(&[&self.endpoint]) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(
                    endpoint = %self.endpoint,
                    %error,
                    "failed to connect ZMQ; will retry..."
                );
                // If we fail to connect, we must signal the constructor if it's still waiting.
                if let Some(tx) = self.initial_conn_signal_tx.take() {
                    let err_msg = format!("initial ZMQ connection attempt failed: {error}");
                    let _ = tx.send(Err(BitcoinZmqError::Internal(err_msg)));
                }
                return ControlFlow::Reconnect;
            }
        };

        tracing::info!(endpoint = %self.endpoint, "ZMQ poller connected.");
        let mut poller_stream =
            zmq_stream.map_err(|e| BitcoinZmqError::BitcoinCoreZmq(e.to_string()).into());

        // Loop to process messages from the connected stream.
        loop {
            let message_result = poller_stream
                .next()
                .with_timeout(ZMQ_INACTIVITY_TIMEOUT)
                .await;

            let decision = match message_result {
                // A message was successfully received from the stream.
                Ok(Some(message)) => self.handle_message(message),
                // The stream ended gracefully.
                Ok(None) => {
                    tracing::info!(
                        endpoint = %self.endpoint,
                        "ZMQ stream ended; will attempt to reconnect."
                    );
                    ControlFlow::Reconnect
                }
                // The stream timed out waiting for a message.
                Err(_) => {
                    tracing::warn!(
                        endpoint = %self.endpoint,
                        timeout_secs = ZMQ_INACTIVITY_TIMEOUT.as_secs(),
                        "ZMQ stream inactive; attempting to reconnect."
                    );
                    ControlFlow::Reconnect
                }
            };

            // Act on the decision from handling the message or the stream event.
            match decision {
                ControlFlow::Continue => continue,
                // For any other decision, we exit this function and let the main
                // run loop handle it.
                other => return other,
            }
        }
    }

    /// Processes a single message or event and determines the next action.
    fn handle_message(&mut self, msg: Result<SocketMessage, Error>) -> ControlFlow {
        inspect_zmq_message(&msg);

        match msg {
            Ok(SocketMessage::Event(event)) => {
                tracing::trace!(?event, "received ZMQ event");
                // Only attempt to take and send the signal if the event is `Connected`.
                if let SocketEvent::Connected { .. } = event.event {
                    // Now that we know it's the right event, we can take the sender.
                    if let Some(tx) = self.initial_conn_signal_tx.take() {
                        // On first successful connection, signal the constructor.
                        if tx.send(Ok(())).is_err() {
                            tracing::warn!("failed to send initial ZMQ connection success signal.");
                        }
                    }
                }
            }
            Ok(SocketMessage::Message(Message::HashBlock(hash, _))) => {
                tracing::trace!(block_hash = %hash, "received ZMQ block hash");
                // If send fails, it means there are no subscribers. This is a normal
                // condition during startup. We can just log it at trace level and continue.
                if self.broadcast_tx.send(Ok(hash)).is_err() {
                    tracing::trace!("no subscribers, dropping ZMQ block hash message");
                }
            }
            Ok(_) => {} // Ignore other message types
            Err(Error::BitcoinCoreZmq(error)) => {
                tracing::warn!(endpoint = %self.endpoint, %error, "ZMQ stream error; reconnecting.");
                // If a stream error occurs before the initial connection is confirmed,
                // signal the failure to the constructor.
                if let Some(tx) = self.initial_conn_signal_tx.take() {
                    let _ = tx.send(Err(error));
                }
                return ControlFlow::Reconnect;
            }
            Err(error) => {
                // For any other unexpected error, we treat it as fatal.
                tracing::error!(endpoint = %self.endpoint, "unexpected poller error: {error}; shutting down.");
                let bcast_err = BitcoinZmqError::Internal(error.to_string());
                if let Some(tx) = self.initial_conn_signal_tx.take() {
                    let _ = tx.send(Err(bcast_err.clone()));
                }
                let _ = self.broadcast_tx.send(Err(bcast_err));
                return ControlFlow::Shutdown;
            }
        }
        ControlFlow::Continue
    }
}

/// The `BitcoinCoreMessageDispatcher` is responsible for managing the ZMQ polling task
/// and providing a stream of block hashes received from the Bitcoin Core ZMQ interface.
/// It connects to the specified ZMQ endpoint, listens for block hash messages, and
/// broadcasts them to subscribers. This implementation ensures reliable message delivery
/// and handles reconnection logic in case of connection issues.
#[derive(Clone)]
pub struct BitcoinCoreMessageDispatcher {
    // The broadcast channel now sends Result<BlockHash, BitcoinZmqError>
    broadcast_tx: broadcast::Sender<Result<BlockHash, BitcoinZmqError>>,
    // Keep the task handle to ensure the poller task isn't dropped prematurely
    // and potentially for graceful shutdown in the future.
    _poller_task_handle: Arc<JoinHandle<()>>,
}

/// Inspects a ZMQ message and logs its content based on the type of message.
fn inspect_zmq_message(msg: &Result<SocketMessage, Error>) {
    match msg {
        Ok(SocketMessage::Event(event)) => match event.event {
            SocketEvent::Connected { fd } => {
                tracing::info!(%fd, endpoint = %event.source_url, "connected to ZMQ endpoint");
            }
            SocketEvent::Disconnected { fd } => {
                tracing::warn!(%fd, endpoint = %event.source_url, "disconnected from ZMQ endpoint");
            }
            _ => {}
        },
        Ok(SocketMessage::Message(message)) => match message {
            Message::Block(block, height) => {
                tracing::trace!(block_hash = %block.block_hash(), %height, "received ZMQ block");
            }
            Message::HashBlock(hash, height) => {
                tracing::trace!(block_hash = %hash, %height, "received ZMQ block hash");
            }
            // Other message types like full blocks are ignored by this poller
            _ => {}
        },
        Err(error) => {
            // This logging is for errors from the ZmqMessagePoller stream itself.
            // Specific handling (reconnect or broadcast error) happens in the poller loop.
            tracing::debug!(%error, "ZMQ poller received an error from inner stream");
        }
    }
}

/// Calculates the backoff duration based on attempt number.
fn calculate_backoff_duration(attempt: u32) -> Duration {
    if attempt == 0 {
        INITIAL_RECONNECT_DELAY
    } else {
        // Calculate delay using f32 arithmetic
        let delay = (INITIAL_RECONNECT_DELAY.as_secs_f32())
            * RECONNECT_BACKOFF_FACTOR.powi((attempt - 1) as i32);

        // Clamp the result between the initial and maximum delay values.
        Duration::from_secs_f32(delay).clamp(INITIAL_RECONNECT_DELAY, MAX_RECONNECT_DELAY)
    }
}

impl BitcoinCoreMessageDispatcher {
    /// Creates a new `BitcoinCoreMessageStream` instance that connects to the
    /// specified ZMQ endpoint and starts polling for block hash messages.
    pub async fn new_from_endpoint(endpoint: &str) -> Result<Self, Error> {
        let (broadcast_tx, _rx) =
            broadcast::channel::<Result<BlockHash, BitcoinZmqError>>(DEFAULT_BROADCAST_CAPACITY);

        // Channel for the poller task to signal initial connection status.
        let (initial_conn_signal_tx, initial_conn_signal_rx) =
            oneshot::channel::<Result<(), BitcoinZmqError>>();

        let poller = Poller {
            endpoint: endpoint.to_string(),
            broadcast_tx: broadcast_tx.clone(),
            initial_conn_signal_tx: Some(initial_conn_signal_tx),
        };

        let poller_task_handle = tokio::spawn(poller.run());

        // Wait for the initial connection signal from the poller task.
        initial_conn_signal_rx
            .with_timeout(INITIAL_CONNECTION_TIMEOUT)
            .await
            .map_err(|_| {
                // Result 1: Timeout waiting for the signal.
                tracing::error!(
                    endpoint = %endpoint,
                    timeout_secs = INITIAL_CONNECTION_TIMEOUT.as_secs(),
                    "timeout waiting for initial ZMQ connection."
                );
                let err_msg = format!(
                    "timeout ({INITIAL_CONNECTION_TIMEOUT:?}) waiting for initial ZMQ connection."
                );
                Error::BitcoinCoreZmq(BitcoinZmqError::Internal(err_msg))
            })?
            .map_err(|_| {
                // Result 2: The poller task dropped the sender, likely by exiting prematurely.
                tracing::error!(endpoint = %endpoint, "ZMQ poller task exited prematurely.");
                Error::BitcoinCoreZmq(BitcoinZmqError::Internal(
                    "ZMQ poller task exited prematurely".to_string(),
                ))
            })?
            .map_err(|error| {
                // Result 3: The poller task sent an explicit error signal.
                tracing::error!(endpoint = %endpoint, %error, "initial ZMQ connection failed.");
                Error::BitcoinCoreZmq(error)
            })?;

        // If we reach here, all results were Ok, meaning the connection is successful.
        tracing::info!(%endpoint, "successfully established initial ZMQ connection.");
        Ok(Self {
            broadcast_tx,
            _poller_task_handle: Arc::new(poller_task_handle),
        })
    }
}

impl BlockHashStreamProvider for BitcoinCoreMessageDispatcher {
    fn get_block_hash_stream(
        &self,
    ) -> impl Stream<Item = Result<BlockHash, BitcoinZmqError>> + Send + Sync + 'static {
        BroadcastStream::new(self.broadcast_tx.subscribe()).map(|item_from_broadcast| {
            match item_from_broadcast {
                Ok(Ok(block_hash)) => Ok(block_hash),
                Ok(Err(bitcoin_zmq_error)) => Err(bitcoin_zmq_error),
                Err(BroadcastStreamRecvError::Lagged(count)) => {
                    Err(BitcoinZmqError::SubscriberLagged(count))
                }
            }
        })
    }
}
