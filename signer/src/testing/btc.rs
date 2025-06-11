//! Helper functions for the bitcoin module

use std::sync::Arc;

use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::consensus::encode::serialize_hex;

use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc_json::GetChainTipsResultStatus;
use bitcoincore_rpc_json::GetChainTipsResultTip;
use emily_client::models::CreateDepositRequestBody;
use futures::StreamExt as _;
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use crate::bitcoin::utxo;
use crate::bitcoin::zmq::BitcoinCoreMessageStream;
use crate::error::Error;
use crate::testing::MapTestUtilityError as _;
use crate::testing::TestUtilityError;

/// Type alias for a shared result of a block hash notification, used in the dispatcher.
pub type ArcBlockHashResult = Arc<Result<BlockHash, Error>>;

/// Return a transaction that is kinda like the signers' transaction,
/// but it does not service any requests, and it does not have any
/// signatures.
pub fn base_signer_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
            // This is the signers' previous UTXO
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            },
        ],
        output: vec![
            // This represents the signers' new UTXO.
            TxOut {
                value: Amount::ONE_BTC,
                script_pubkey: ScriptBuf::new(),
            },
            // This represents the OP_RETURN sBTC UTXO for a
            // transaction with no withdrawals.
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([0; 21]),
            },
        ],
    }
}

impl utxo::DepositRequest {
    /// Transform this deposit request into the body that Emily expects.
    pub fn as_emily_request(&self, tx: &Transaction) -> CreateDepositRequestBody {
        CreateDepositRequestBody {
            bitcoin_tx_output_index: self.outpoint.vout,
            bitcoin_txid: self.outpoint.txid.to_string(),
            deposit_script: self.deposit_script.to_hex_string(),
            reclaim_script: self.reclaim_script.to_hex_string(),
            transaction_hex: serialize_hex(tx),
        }
    }
}

/// Return the canonical (active) chain tip from `get_chain_tips`
#[track_caller]
pub fn get_canonical_chain_tip(rpc: &Client) -> GetChainTipsResultTip {
    rpc.get_chain_tips()
        .unwrap()
        .iter()
        .find(|t| t.status == GetChainTipsResultStatus::Active)
        .unwrap()
        .clone()
}

// TODO: This trait could/should be made a first-class citizen in prod code and
// be what is passed to a `BlockObserver`, with `BitcoinCoreMessageStream`
// implementing it; but this is a bigger refactor so this remains a test utility
// for now.
//
/// A trait for providing a stream of block hashes to be used by the block observer.
///
/// Implementors of this trait are responsible for sourcing block hash notifications,
/// typically from a Bitcoin Core ZMQ endpoint, and making them available as an
/// asynchronous stream. This abstraction allows different components, such as
/// block observers or test utilities, to consume block hash events without being
/// coupled to the specific mechanism of how those events are obtained.
pub trait BlockHashStreamProvider {
    /// Subscribes to the block hash stream, returning a new stream that emits
    /// block hashes as they are received from the Bitcoin Core ZMQ interface.
    ///
    /// The returned stream will yield `Result<BlockHash, Error>`, where
    /// [`BlockHash`] is the hash of the block and [`Error`] will always be
    /// mapped to [`Error::TestUtility`] if an error occurs in the stream. This
    /// is due to constraints of the [`BroadcastStream`] which requires `Clone`
    /// on the item type, and [`Error`] does not implement `Clone`.
    fn get_block_hash_stream(
        &self,
    ) -> impl futures::Stream<Item = Result<BlockHash, Error>> + Send + Sync + 'static;
}

/// Represents the internal state of the [`BlockHashStreamDispatcher`] when
/// operating in direct (auto-broadcasting) mode.
///
/// In this mode, block hashes received from the ZMQ poller are immediately
/// broadcast to all subscribers.
pub struct DirectMode {
    // NOTE: Options are used here to allow taking ownership during state
    // transitions (e.g., when stopping the task).
    /// Handle to the Tokio task that forwards block hashes from the internal
    /// MPSC channel to the public broadcast channel.
    direct_mode_task_handle: Option<JoinHandle<mpsc::Receiver<ArcBlockHashResult>>>,
    /// Sender part of a one-shot channel used to signal the direct mode task to stop.
    direct_mode_stop_signal: Option<oneshot::Sender<()>>,
}

/// Represents the internal state of the [`BlockHashStreamDispatcher`] when
/// operating in buffered (manual broadcast) mode.
///
/// In this mode, block hashes received from the ZMQ poller are stored in an
/// internal buffer (MPSC channel) and are only broadcast when explicitly
/// requested via methods like `broadcast_next`.
pub struct BufferedMode {
    // NOTE: Options are used here to allow taking ownership during state
    // transitions (e.g., when stopping the task).
    /// Receiver part of the MPSC channel that buffers block hashes from the ZMQ
    /// poller.
    internal_buffer_rx: Option<mpsc::Receiver<ArcBlockHashResult>>,
}

/// Holds shared resources that are initialized once and used by the dispatcher
/// across different modes and clones.
///
/// These resources typically include handles to background tasks or channels
/// that need to be kept alive for the dispatcher to function.
struct SharedDispatcherResources {
    /// A broadcast receiver that is kept to ensure the broadcast channel remains open
    /// as long as there's at least one dispatcher instance.
    _keep_alive_broadcast_rx: broadcast::Receiver<ArcBlockHashResult>,
    /// Handle to the Tokio task that polls Bitcoin Core's ZMQ endpoint for new block hashes.
    _zmq_poller_task: JoinHandle<()>,
}

/// Contains resources that are initialized once when the first [`BlockHashStreamDispatcher`]
/// instance is created. These are then used to construct [`SharedDispatcherResources`]
/// and mode-specific states.
struct InitialDispatcherResources {
    /// The sender part of the broadcast channel used to distribute block hashes to subscribers.
    broadcast_tx: broadcast::Sender<ArcBlockHashResult>,
    /// A receiver for the broadcast channel, kept alive by `SharedDispatcherResources`.
    keep_alive_rx: broadcast::Receiver<ArcBlockHashResult>,
    /// Handle to the ZMQ poller task.
    zmq_poller_task: JoinHandle<()>,
    /// The receiver part of the MPSC channel that gets block hashes from the ZMQ poller task.
    mpsc_rx_from_poller: mpsc::Receiver<ArcBlockHashResult>,
}

/// A dispatcher for a stream of block hashes received from a Bitcoin Core ZMQ endpoint.
///
/// This dispatcher manages a **single underlying ZMQ connection** and poller task,
/// making it efficient for scenarios where multiple components or simulated entities
/// (like sBTC signers in a test environment) need to react to the same stream of
/// Bitcoin block events. It is designed to be **cloneable and shareable across threads**,
/// allowing various parts of an application or test suite to subscribe to or control
/// the same block hash feed without redundant ZMQ connections.
///
/// This dispatcher can operate in two modes:
/// 1.  **Direct Mode ([`DirectMode`]):** Block hashes are automatically broadcast to all
///     subscribers as soon as they are received from the ZMQ poller.
/// 2.  **Buffered Mode ([`BufferedMode`]):** Block hashes are collected into an internal
///     buffer and are only broadcast when explicitly triggered by methods like
///     `broadcast_next`. This allows for controlled processing of Bitcoin block events,
///     particularly in scenarios where you want to skip certain blocks or only trigger
///     processing for specific conditions/blocks.
///
/// It implements [`BlockHashStreamProvider`] to allow components to subscribe to the
/// resulting stream of block hashes.
pub struct BlockHashStreamDispatcher<Mode> {
    /// The sender part of the broadcast channel used to distribute block hashes.
    broadcast_tx: broadcast::Sender<ArcBlockHashResult>,
    /// Shared, mode-agnostic resources like task handles and keep-alive channels.
    resources: Arc<SharedDispatcherResources>,
    /// State specific to the current operational mode (e.g., `DirectMode` or `BufferedMode`),
    /// protected by a `Mutex` to allow for safe interior mutability and mode transitions.
    state: Arc<Mutex<Mode>>,
}

impl<Mode> Clone for BlockHashStreamDispatcher<Mode> {
    /// Clones the `BlockHashStreamDispatcher`.
    ///
    /// The cloned dispatcher shares the underlying ZMQ connection, poller task,
    /// broadcast channel, and mode-specific state (via `Arc` and `Mutex`).
    /// This allows multiple parts of the system to control or subscribe to the same
    /// block hash stream.
    fn clone(&self) -> Self {
        Self {
            broadcast_tx: self.broadcast_tx.clone(),
            resources: Arc::clone(&self.resources),
            state: Arc::clone(&self.state),
        }
    }
}

// Common methods available for any mode
impl<Mode: Send + 'static> BlockHashStreamDispatcher<Mode> {
    /// Default capacity for the internal MPSC channel buffering ZMQ messages
    /// and the broadcast channel.
    const DEFAULT_BUFFER_CAPACITY: usize = 100;

    /// Initializes common components required by the dispatcher, regardless of its mode.
    ///
    /// This includes setting up:
    /// - The ZMQ connection to the Bitcoin Core endpoint.
    /// - The ZMQ poller task that reads block hashes and sends them to an internal MPSC channel.
    /// - The main broadcast channel for distributing block hashes to subscribers.
    /// - An MPSC channel that acts as an internal buffer between the ZMQ poller and
    ///   the mode-specific forwarding logic.
    ///
    /// ## Arguments
    /// * `endpoint`: The ZMQ endpoint string (e.g., "tcp://127.0.0.1:28332").
    /// * `buffer_capacity`: The capacity for the internal MPSC channel.
    ///
    /// ## Returns
    /// A `Result` containing [`InitialDispatcherResources`] on success, or a [`TestUtilityError`].
    async fn initialize_common_components(
        endpoint: &str,
        buffer_capacity: usize,
    ) -> Result<InitialDispatcherResources, TestUtilityError> {
        let (broadcast_tx, keep_alive_rx) = broadcast::channel(Self::DEFAULT_BUFFER_CAPACITY);
        let (internal_buffer_tx, mpsc_rx_from_poller) = mpsc::channel(buffer_capacity);

        let mut zmq_stream = BitcoinCoreMessageStream::new_from_endpoint(endpoint)
            .await
            .map_to_test_utility_err()?
            .to_block_hash_stream();

        let zmq_poller_task = tokio::spawn(async move {
            while let Some(block_hash_result) = zmq_stream.next().await {
                if internal_buffer_tx
                    .send(Arc::new(block_hash_result))
                    .await
                    .is_err()
                {
                    tracing::debug!(
                        "ZMQ Poller: Internal MPSC receiver dropped, shutting down poller task."
                    );
                    break;
                }
            }
            tracing::debug!("ZMQ Poller task finished.");
        });

        Ok(InitialDispatcherResources {
            broadcast_tx,
            keep_alive_rx,
            zmq_poller_task,
            mpsc_rx_from_poller,
        })
    }
}

impl BlockHashStreamDispatcher<BufferedMode> {
    /// Creates a new [`BlockHashStreamDispatcher`] initialized in [`BufferedMode`].
    ///
    /// In buffered mode, block hashes from the ZMQ stream are collected into an
    /// internal buffer and are only broadcast when methods like `broadcast_next`
    /// are called.
    ///
    /// ## Arguments
    /// * `endpoint`: The ZMQ endpoint string for Bitcoin Core.
    ///
    /// ## Returns
    /// A `Result` containing the new `BlockHashStreamDispatcher<BufferedMode>` or a [`TestUtilityError`].
    pub async fn new_buffered(endpoint: &str) -> Result<Self, TestUtilityError> {
        let initial_resources =
            Self::initialize_common_components(endpoint, Self::DEFAULT_BUFFER_CAPACITY).await?;

        let shared_resources = SharedDispatcherResources {
            _keep_alive_broadcast_rx: initial_resources.keep_alive_rx,
            _zmq_poller_task: initial_resources.zmq_poller_task,
        };
        let buffered_state = BufferedMode {
            internal_buffer_rx: Some(initial_resources.mpsc_rx_from_poller),
        };

        Ok(Self {
            broadcast_tx: initial_resources.broadcast_tx,
            resources: Arc::new(shared_resources),
            state: Arc::new(Mutex::new(buffered_state)),
        })
    }

    /// Transitions a [`BlockHashStreamDispatcher`] from [`DirectMode`] to [`BufferedMode`].
    ///
    /// This involves stopping the direct mode's auto-forwarding task and reclaiming
    /// the internal MPSC receiver to be used for buffering.
    ///
    /// ## Arguments
    /// * `direct_dispatcher`: The dispatcher currently in `DirectMode`.
    ///
    /// ## Returns
    /// A `Result` containing the dispatcher now in `BufferedMode`, or a [`TestUtilityError`].
    pub async fn from_direct(
        direct_dispatcher: BlockHashStreamDispatcher<DirectMode>,
    ) -> Result<Self, TestUtilityError> {
        let mut direct_mode_state = direct_dispatcher.state.lock().await;

        let stop_signal = direct_mode_state
            .direct_mode_stop_signal
            .take()
            .ok_or("BlockHashStreamDispatcher: DirectMode state is missing the stop signal.")?;

        tracing::debug!("Stopping direct mode task...");
        if stop_signal.send(()).is_err() {
            // This is not necessarily an error; the task might have already completed.
            tracing::warn!(
                "Failed to send stop signal to direct mode task, or task already stopped."
            );
        }

        let direct_mode_task_handle = direct_mode_state
            .direct_mode_task_handle
            .take()
            .ok_or("BlockHashStreamDispatcher: DirectMode state is missing the task handle.")?;

        drop(direct_mode_state); // Release lock before await

        let returned_receiver = direct_mode_task_handle.await.map_err(|join_error| {
            format!(
                "BlockHashStreamDispatcher: Direct mode task failed to join cleanly: {join_error}"
            )
        })?;

        let buffered_state = BufferedMode {
            internal_buffer_rx: Some(returned_receiver),
        };

        tracing::info!("Switched to buffered mode. Direct mode task stopped gracefully.");
        Ok(BlockHashStreamDispatcher {
            broadcast_tx: direct_dispatcher.broadcast_tx.clone(),
            resources: direct_dispatcher.resources.clone(),
            state: Arc::new(Mutex::new(buffered_state)),
        })
    }

    /// Consumes the current [`BufferedMode`] dispatcher and transitions it to [`DirectMode`].
    ///
    /// ## Arguments
    /// * `self`: The dispatcher in `BufferedMode`.
    /// * `flush_buffer`: If `true`, any items currently in the internal buffer will be
    ///   broadcast before switching to direct mode.
    ///
    /// ## Returns
    /// A `Result` containing the dispatcher now in `DirectMode`, or a [`TestUtilityError`].
    pub async fn into_direct_dispatcher(
        self,
        flush_buffer: bool,
    ) -> Result<BlockHashStreamDispatcher<DirectMode>, TestUtilityError> {
        BlockHashStreamDispatcher::from_buffered(self, flush_buffer).await
    }

    /// Retrieves the next block hash result from the internal buffer and broadcasts it.
    ///
    /// This method will wait if the buffer is empty until a new item arrives from the
    /// ZMQ poller or the poller's channel is closed.
    ///
    /// ## Returns
    /// * `Ok(Some(ArcBlockHashResult))`: If an item was successfully received and broadcast.
    /// * `Ok(None)`: If the internal ZMQ poller channel has been closed (no more items).
    /// * `Err(TestUtilityError)`: If broadcasting fails or the dispatcher is in an invalid state.
    pub async fn broadcast_next(&mut self) -> Result<Option<ArcBlockHashResult>, TestUtilityError> {
        let mut buffered_state = self.state.lock().await;
        let internal_rx_opt = buffered_state.internal_buffer_rx.as_mut();

        match internal_rx_opt {
            Some(rx) => {
                match rx.recv().await {
                    Some(item_arc) => {
                        drop(buffered_state); // Release lock before send
                        self.broadcast_tx.send(item_arc.clone()).map_err(|e| {
                            format!("BlockHashStreamDispatcher: Buffered mode: Failed to broadcast item: {:?}", e.0)
                        })?;
                        Ok(Some(item_arc))
                    }
                    None => Ok(None), // Channel closed
                }
            }
            None => {
                // This case should ideally not happen if the dispatcher is in a valid BufferedMode state.
                Err(
                    "BlockHashStreamDispatcher: BufferedMode state is missing the internal MPSC receiver.",
                )?
            }
        }
    }

    /// Retrieves the next block hash result from the buffer and broadcasts it only if
    /// the provided `filter` closure returns `true` for the block hash.
    ///
    /// The item is consumed from the buffer regardless of whether it's broadcast.
    ///
    /// ## Arguments
    /// * `filter`: A closure that takes a `&BlockHash` and returns `true` if it should be broadcast.
    ///
    /// ## Returns
    /// * `Ok(Some(ArcBlockHashResult))`: The item received from the buffer.
    /// * `Ok(None)`: If the internal ZMQ poller channel has been closed.
    /// * `Err(TestUtilityError)`: If broadcasting fails or the dispatcher is in an invalid state.
    pub async fn broadcast_next_if<F>(
        &mut self,
        filter: F,
    ) -> Result<Option<ArcBlockHashResult>, TestUtilityError>
    where
        F: FnOnce(&BlockHash) -> bool,
    {
        let mut buffered_state = self.state.lock().await;
        let internal_rx_opt = buffered_state.internal_buffer_rx.as_mut();

        let Some(rx) = internal_rx_opt else {
            return Err(
                "BlockHashStreamDispatcher: BufferedMode state is missing the internal MPSC receiver for broadcast_next_if.",
            )?;
        };

        match rx.recv().await {
            Some(item_arc) => {
                let mut should_broadcast = true;
                if let Ok(block_hash_value) = item_arc.as_ref() {
                    if !filter(block_hash_value) {
                        should_broadcast = false;
                    }
                }
                drop(buffered_state); // Release lock before potential send
                if should_broadcast {
                    self.broadcast_tx.send(item_arc.clone()).map_err(|e| {
                        format!(
                            "BlockHashStreamDispatcher: Buffered mode: Failed to broadcast filtered item: {:?}",
                            e.0
                        )
                    })?;
                }
                Ok(Some(item_arc))
            }
            None => Ok(None), // Channel closed
        }
    }
}

impl BlockHashStreamDispatcher<DirectMode> {
    /// Creates a new [`BlockHashStreamDispatcher`] initialized in [`DirectMode`].
    ///
    /// In direct mode, block hashes from the ZMQ stream are immediately and
    /// automatically broadcast to all subscribers.
    ///
    /// ## Arguments
    /// * `endpoint`: The ZMQ endpoint string for Bitcoin Core.
    ///
    /// ## Returns
    /// A `Result` containing the new `BlockHashStreamDispatcher<DirectMode>` or a [`TestUtilityError`].
    pub async fn new(endpoint: &str) -> Result<Self, TestUtilityError> {
        let initial_resources =
            Self::initialize_common_components(endpoint, Self::DEFAULT_BUFFER_CAPACITY).await?;

        let (stop_tx, stop_rx) = oneshot::channel();

        let direct_task_broadcast_tx = initial_resources.broadcast_tx.clone();
        let direct_mode_task_handle = tokio::spawn(Self::run_direct_mode_forwarder_loop(
            initial_resources.mpsc_rx_from_poller,
            direct_task_broadcast_tx,
            stop_rx,
        ));

        let shared_resources = SharedDispatcherResources {
            _keep_alive_broadcast_rx: initial_resources.keep_alive_rx,
            _zmq_poller_task: initial_resources.zmq_poller_task,
        };
        let direct_state = DirectMode {
            direct_mode_task_handle: Some(direct_mode_task_handle),
            direct_mode_stop_signal: Some(stop_tx),
        };

        Ok(Self {
            broadcast_tx: initial_resources.broadcast_tx,
            resources: Arc::new(shared_resources),
            state: Arc::new(Mutex::new(direct_state)),
        })
    }

    /// Transitions a [`BlockHashStreamDispatcher`] from [`BufferedMode`] to [`DirectMode`].
    ///
    /// This involves taking the MPSC receiver from the buffered mode, potentially
    /// flushing its contents, and then spawning the direct mode's auto-forwarding task
    /// with this receiver.
    ///
    /// ## Arguments
    /// * `buffered_dispatcher`: The dispatcher currently in `BufferedMode`.
    /// * `flush_buffer`: If `true`, any items currently in the MPSC receiver (buffer)
    ///   will be synchronously broadcast before starting the direct mode task and returning.
    ///
    /// ## Returns
    /// A `Result` containing the dispatcher now in [`DirectMode`], or a [`TestUtilityError`].
    pub async fn from_buffered(
        buffered_dispatcher: BlockHashStreamDispatcher<BufferedMode>,
        flush_buffer: bool,
    ) -> Result<Self, TestUtilityError> {
        let mut buffered_mode_state_guard = buffered_dispatcher.state.lock().await;
        let mut receiver_for_direct_task = buffered_mode_state_guard
            .internal_buffer_rx
            .take()
            .ok_or("BlockHashStreamDispatcher: BufferedMode state is missing the internal MPSC receiver during transition.")?;

        drop(buffered_mode_state_guard); // Release lock

        if flush_buffer {
            tracing::info!("Flushing internal buffer before enabling direct mode...");
            let b_tx_clone = buffered_dispatcher.broadcast_tx.clone();
            while let Ok(item_arc) = receiver_for_direct_task.try_recv() {
                if b_tx_clone.send(item_arc).is_err() {
                    tracing::warn!(
                        "Flush: Failed to broadcast item (channel closed or no subscribers)."
                    );
                }
            }
            tracing::info!("Buffer flush attempt complete.");
        }

        let (stop_tx, stop_rx) = oneshot::channel();
        let direct_task_broadcast_tx = buffered_dispatcher.broadcast_tx.clone();
        let direct_mode_task_handle = tokio::spawn(Self::run_direct_mode_forwarder_loop(
            receiver_for_direct_task,
            direct_task_broadcast_tx,
            stop_rx,
        ));

        let direct_state = DirectMode {
            direct_mode_task_handle: Some(direct_mode_task_handle),
            direct_mode_stop_signal: Some(stop_tx),
        };

        tracing::info!("Switched to direct (auto-broadcasting) mode.");
        Ok(BlockHashStreamDispatcher {
            broadcast_tx: buffered_dispatcher.broadcast_tx.clone(),
            resources: buffered_dispatcher.resources.clone(),
            state: Arc::new(Mutex::new(direct_state)),
        })
    }

    /// Runs the asynchronous loop for direct mode operation.
    ///
    /// This loop continuously receives block hash results from the internal MPSC channel
    /// (fed by the ZMQ poller) and broadcasts them. It can be stopped via a one-shot signal.
    ///
    /// ## Arguments
    /// * `receiver`: The MPSC receiver for incoming [`ArcBlockHashResult`] items.
    /// * `broadcast_sender`: The broadcast sender to distribute items to subscribers.
    /// * `stop_listener`: A one-shot receiver to signal the loop to terminate.
    ///
    /// ## Returns
    /// The [`mpsc::Receiver`] passed in, which might contain un-forwarded items if the
    /// loop was stopped prematurely or the ZMQ poller's channel closed. This allows
    /// the receiver to be potentially reused if transitioning back to buffered mode.
    async fn run_direct_mode_forwarder_loop(
        mut receiver: mpsc::Receiver<ArcBlockHashResult>,
        broadcast_sender: broadcast::Sender<ArcBlockHashResult>,
        mut stop_listener: oneshot::Receiver<()>,
    ) -> mpsc::Receiver<ArcBlockHashResult> {
        // Returns the receiver for potential reuse
        tracing::debug!("Direct mode auto-forwarding task started.");
        loop {
            tokio::select! {
                biased; // Prioritize stop signal
                _ = &mut stop_listener => {
                    tracing::debug!("Direct mode task: Stop signal received.");
                    break;
                }
                maybe_item = receiver.recv() => {
                    match maybe_item {
                        Some(item_arc) => {
                            if broadcast_sender.send(item_arc).is_err() {
                                // Log warning, but don't stop the loop for this.
                                tracing::warn!(
                                    "Direct mode task: Failed to broadcast item (no active subscribers or channel closed)."
                                );
                            }
                        }
                        None => {
                            // MPSC channel from ZMQ poller closed.
                            tracing::debug!("Direct mode task: Internal MPSC channel closed (ZMQ poller likely ended).");
                            break;
                        }
                    }
                }
            }
        }
        tracing::debug!("Direct mode auto-forwarding task finished, returning MPSC receiver.");
        receiver
    }

    /// Consumes the current [`DirectMode`] dispatcher and transitions it to [`BufferedMode`].
    ///
    /// This involves signaling the direct mode's auto-forwarding task to stop,
    /// waiting for it to terminate, and then using the MPSC receiver it returns
    /// (which may contain pending items) to initialize the `BufferedMode` state.
    ///
    /// ## Arguments
    /// * `self`: The dispatcher in `DirectMode`.
    ///
    /// ## Returns
    /// A `Result` containing the dispatcher now in `BufferedMode`, or a [`TestUtilityError`].
    pub async fn into_buffered_dispatcher(
        self,
    ) -> Result<BlockHashStreamDispatcher<BufferedMode>, TestUtilityError> {
        BlockHashStreamDispatcher::from_direct(self).await
    }
}

/// Creates and returns a stream that listens to a broadcast channel for block hashes.
///
/// This function subscribes to the provided `broadcast_sender` and wraps the
/// subscription in a [`BroadcastStream`]. It then maps the items received from this
/// stream to the `Result<BlockHash, Error>` type expected by consumers of
/// [`BlockHashStreamProvider`].
///
/// ## Arguments
/// * `broadcast_sender`: A reference to a `tokio::sync::broadcast::Sender` that
///   transmits [`ArcBlockHashResult`] items. `ArcBlockHashResult` is an
///   `Arc<Result<BlockHash, Error>>`, allowing shared ownership of block hash
///   results, which might themselves be errors originating from the ZMQ poller.
///
/// ## Returns
/// An implementation of [`futures::Stream`] that yields `Result<BlockHash, Error>` items.
/// - If an `Arc<Ok(BlockHash)>` is successfully received from the broadcast channel,
///   it's mapped to `Ok(BlockHash)`.
/// - If an `Arc<Err(Error_inner)>` is received, `Error_inner` is converted to a string
///   and wrapped in [`Error::TestUtility`].
/// - If the `BroadcastStream` lags (i.e., messages are missed because the receiver
///   is too slow), a [`BroadcastStreamRecvError::Lagged`] occurs. This is mapped to
///   `Error::TestUtility` with a descriptive message.
///
/// The returned stream is `Send + Sync + 'static`.
fn create_block_hash_subscriber_stream(
    broadcast_sender: &broadcast::Sender<ArcBlockHashResult>,
) -> impl futures::Stream<Item = Result<BlockHash, Error>> + Send + Sync + 'static {
    BroadcastStream::new(broadcast_sender.subscribe()).map(|item_result| {
        match item_result {
            Ok(arc_result_bh_error) => {
                // Successfully received an Arc<Result<BlockHash, Error>> from broadcast.
                // Now, dereference the Arc and handle the inner Result.
                match arc_result_bh_error.as_ref() {
                    Ok(hash) => Ok(*hash),
                    Err(err_inner) => {
                        // The ZMQ poller encountered an error, which was wrapped in Arc and broadcast.
                        // Map this inner error to Error::TestUtility as a String as it's not cloneable.
                        Err(Error::TestUtility(err_inner.to_string().into()))
                    }
                }
            }
            Err(BroadcastStreamRecvError::Lagged(count)) => Err(Error::TestUtility(
                format!("Broadcast stream is lagging by {count} items").into(),
            )),
        }
    })
}

impl<Mode: Send + 'static> BlockHashStreamProvider for BlockHashStreamDispatcher<Mode> {
    /// Gets a stream of block hashes from the dispatcher.
    ///
    /// Subscribers will receive `Arc<Result<BlockHash, Error>>` items that are broadcast
    /// by the dispatcher. The `Arc` allows sharing the result, and the `Result`
    /// encapsulates either a [`BlockHash`] or an [`Error`] from the ZMQ stream.
    /// Errors during broadcast (like lagging) are mapped to [`Error::TestUtility`].
    fn get_block_hash_stream(
        &self,
    ) -> impl futures::Stream<Item = Result<BlockHash, Error>> + Send + Sync + 'static {
        create_block_hash_subscriber_stream(&self.broadcast_tx)
    }
}

/// A null implementation of [`BlockHashStreamProvider`].
///
/// This provider returns an empty stream of block hashes. It is useful in test scenarios
/// where a [`BlockHashStreamProvider`] is required by a component (e.g., a block observer),
/// but no actual block observations are needed or intended for that specific test.
pub struct NullBlockHashStreamProvider;

impl BlockHashStreamProvider for NullBlockHashStreamProvider {
    fn get_block_hash_stream(
        &self,
    ) -> impl futures::Stream<Item = Result<BlockHash, Error>> + Send + Sync + 'static {
        tokio_stream::empty::<Result<BlockHash, Error>>()
    }
}
