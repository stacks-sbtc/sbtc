//! # Bitcoin pruner event loop
//!
//! This module contains the bitcoin pruner, which is the component of the sBTC signer
//! responsible for pruning old bitcoin blocks from bitcoin-core.
//!
//!

use futures::StreamExt;

use crate::bitcoin::BitcoinInteract;
use crate::context::BitcoinPrunerEvent;
use crate::context::Context;
use crate::context::SignerCommand;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::context::TxCoordinatorEvent;
use crate::error::Error;
use crate::stacks::api::StacksInteract;
use crate::storage::model::BitcoinBlockHeight;
use crate::storage::model::BitcoinBlockRef;

/// The bitcoin pruner event loop.
#[derive(Debug)]
pub struct BitcoinPrunerEventLoop<C> {
    /// The signer context.
    context: C,
}

/// The number of bitcoin blocks the signer wants bitcoin-core to keep when
/// running on mainnet.
///
/// We keep this many blocks because the signer will not sweep funds if
/// they have been locked for more than this many blocks, because they
/// will necessarily be spendable by the user.
const KEEP_BLOCKS_MAINNET: u64 = u16::MAX as u64;

/// The number of bitcoin blocks the signer wants bitcoin-core to keep when
/// running on any non-mainnet network (testnet3, testnet4, signet,
/// regtest, etc.). Non-mainnet deployments have short lock periods, so a
/// small history is sufficient.
const KEEP_BLOCKS_NON_MAINNET: u64 = 100;

/// The minimum number of additional blocks beyond the last pruned height
/// that must be eligible for pruning before we will trigger another prune
/// while bitcoin-core is still catching up to the chain tip. Pruning is
/// an expensive operation so while bitcoin-core is syncing we only do it
/// periodically. This interval is not used once bitcoin-core has finished
/// its initial block download.
const CATCHUP_PRUNE_INTERVAL: u64 = 25_000;

/// Returns the number of bitcoin blocks we want bitcoin-core to keep
/// available for the given network.
fn keep_blocks_for_network(network: bitcoin::Network) -> u64 {
    match network {
        bitcoin::Network::Bitcoin => KEEP_BLOCKS_MAINNET,
        _ => KEEP_BLOCKS_NON_MAINNET,
    }
}

/// The outcome of a single pruning attempt.
///
/// Every path through [`BitcoinPrunerEventLoop::prune_blocks`] yields one
/// of these variants; transport and RPC failures are reported as
/// [`Err`](Result::Err).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PruneOutcome {
    /// The signer is not configured to prune bitcoin-core.
    SignerPruningDisabled,
    /// bitcoin-core does not have pruning enabled.
    BitcoinPruningDisabled,
    /// bitcoin-core is using automatic pruning; the signer only drives
    /// manual pruning.
    BitcoinAutomaticPruningEnabled,
    /// bitcoin-core successfully pruned blocks up to the indicated
    /// height.
    Pruned(BitcoinBlockHeight),
    /// bitcoin-core's `pruneblockchain` RPC returned -1, meaning no
    /// pruning actually occurred this round.
    PruneRpcNoOp,
    /// This happens when bitcoin-core has pruning enabled but did not
    /// return a `pruneheight` in the response to the `getblockchaininfo`
    /// RPC. This shouldn't happen in practice, since bitcoin-core always
    /// sets pruneheight; for bitcoin-core v25, this is set in [1], while
    /// on later versions have it set on [2].
    /// [1]: https://github.com/bitcoin/bitcoin/blob/v25.0/src/rpc/blockchain.cpp#L1272
    /// [2]: https://github.com/bitcoin/bitcoin/blob/31.x/src/rpc/blockchain.cpp#L1428
    PruneHeightMissing,
    /// bitcoin-core has already pruned at or beyond the target height,
    /// so no further pruning was needed.
    AlreadyAtTarget {
        /// The target prune height.
        target_height: BitcoinBlockHeight,
        /// The first unpruned block height that bitcoin-core has.
        prune_height: BitcoinBlockHeight,
    },
    /// bitcoin-core is doing its initial block download and the gap
    /// between the last pruned height and the target prune height is
    /// below [`CATCHUP_PRUNE_INTERVAL`].
    CatchupIntervalNotReached {
        /// The target prune height.
        target_height: BitcoinBlockHeight,
        /// The first unpruned block height that bitcoin-core has.
        prune_height: BitcoinBlockHeight,
    },
    /// We could not reach the connected stacks node, so we declined to
    /// prune this round as a precaution.
    StacksNodeUnreachable,
    /// The connected stacks node has not yet processed up to the target
    /// prune height.
    StacksNodeBehindTarget {
        /// The target prune height.
        target_height: BitcoinBlockHeight,
        /// The first unpruned block height that bitcoin-core has.
        node_bitcoin_height: BitcoinBlockHeight,
    },
}

impl std::fmt::Display for PruneOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignerPruningDisabled => {
                write!(f, "signer is not configured to prune bitcoin-core")
            }
            Self::BitcoinPruningDisabled => {
                write!(f, "bitcoin-core does not have pruning enabled")
            }
            Self::BitcoinAutomaticPruningEnabled => write!(
                f,
                "bitcoin-core is using automatic pruning; manual pruning is required"
            ),
            Self::Pruned(height) => write!(f, "pruned blocks up to height {height}"),
            Self::PruneRpcNoOp => write!(
                f,
                "the pruneblockchain RPC returned -1; no pruning occurred"
            ),
            Self::PruneHeightMissing => write!(
                f,
                "bitcoin-core did not return a prune height; that's unexpected"
            ),
            Self::AlreadyAtTarget { .. } => write!(
                f,
                "bitcoin-core is already pruned at or beyond the target height"
            ),
            Self::CatchupIntervalNotReached { .. } => write!(
                f,
                "bitcoin-core is in initial block download; waiting for the catchup interval to elapse"
            ),
            Self::StacksNodeUnreachable => {
                write!(f, "could not reach the connected stacks node")
            }
            Self::StacksNodeBehindTarget { .. } => write!(
                f,
                "the connected stacks node has not processed up to the target prune height"
            ),
        }
    }
}

fn run_loop_message_filter(signal: &SignerSignal) -> bool {
    matches!(signal, SignerSignal::Command(SignerCommand::Shutdown))
}

impl<C: Context> BitcoinPrunerEventLoop<C> {
    /// Create a new bitcoin pruner event loop.
    pub fn new(context: C) -> Self {
        Self { context }
    }

    /// Run the bitcoin pruner event loop.
    #[tracing::instrument(skip_all, name = "bitcoin-pruner")]
    pub async fn run(self) -> Result<(), Error> {
        let start_message = BitcoinPrunerEvent::EventLoopStarted.into();
        if let Err(error) = self.context.signal(start_message) {
            tracing::error!(%error, "error signaling event loop start");
            return Err(error);
        };

        let mut signal_stream = self.context.as_signal_stream(run_loop_message_filter);

        while let Some(message) = signal_stream.next().await {
            match message {
                SignerSignal::Command(SignerCommand::Shutdown) => break,
                SignerSignal::Event(SignerEvent::TxCoordinator(
                    TxCoordinatorEvent::TenureCompleted(block_ref),
                )) => {
                    tracing::info!(
                        "bitcoin pruner received tenure completed signal; pruning blocks"
                    );
                    if let Err(error) = self.prune_blocks(block_ref).await {
                        tracing::error!(%error, "error pruning blocks; skipping this round");
                    }
                }
                _ => {}
            }
        }

        tracing::info!("bitcoin pruner event loop has been stopped");
        Ok(())
    }

    /// Prune blocks from bitcoin-core.
    ///
    /// On success, returns a [`PruneOutcome`] describing what happened
    /// (including cases where pruning was skipped). RPC and transport
    /// failures are returned as [`Err`](Result::Err).
    #[tracing::instrument(skip_all, fields(block_hash = %block_ref.block_hash))]
    async fn prune_blocks(&self, block_ref: BitcoinBlockRef) -> Result<PruneOutcome, Error> {
        let bitcoin_client = self.context.get_bitcoin_client();
        let blockchain_info = bitcoin_client.get_blockchain_info().await?;

        // This indicates whether the signer is configured to prune blocks
        // manually. If it is not configured, it defaults to not pruning
        // bitcoin-core.
        let signer_pruning_enabled = self.context.config().bitcoin.prune.unwrap_or(false);
        // This indicates that bitcoin-core has pruning enabled.
        let bitcoin_pruning_enabled = blockchain_info.pruned;
        // This indicates that bitcoin-core is configured to prune blocks
        // automatically, and should be set when pruning is enabled. We
        // will only prune blocks if it is configured for manual pruning.
        let automatic_pruning = blockchain_info.automatic_pruning.unwrap_or(true);

        if !signer_pruning_enabled {
            tracing::info!("signer is not configured to prune; so no pruning");
            return Ok(PruneOutcome::SignerPruningDisabled);
        }
        if !bitcoin_pruning_enabled {
            tracing::info!("bitcoin-core pruning is not enabled; so no pruning");
            return Ok(PruneOutcome::BitcoinPruningDisabled);
        }
        if automatic_pruning {
            tracing::info!("bitcoin-core is using automatic pruning; so no pruning");
            return Ok(PruneOutcome::BitcoinAutomaticPruningEnabled);
        }

        // On testnets, we prune much more aggressively to make sure that
        // it works correctly.
        let keep_blocks = keep_blocks_for_network(blockchain_info.chain);
        // We want bitcoin-core to be pruned up to this block height.
        let target_height: BitcoinBlockHeight = block_ref.block_height.saturating_sub(keep_blocks);

        // The prune height should be set when pruning is enabled.
        let Some(prune_height) = blockchain_info.prune_height.map(BitcoinBlockHeight::from) else {
            tracing::warn!("pruning is enabled, but the prune height is unset; that's unexpected");
            return Ok(PruneOutcome::PruneHeightMissing);
        };

        if prune_height >= target_height {
            tracing::info!(
                %prune_height,
                %target_height,
                "pruning is not needed; the node is already pruned up to the target height"
            );
            return Ok(PruneOutcome::AlreadyAtTarget { target_height, prune_height });
        };

        // While bitcoin-core is doing its initial block download we don't
        // want to prune on every new tenure since pruning is expensive.
        // Instead we wait until the gap between the last pruned height and
        // the next target prune height is at least
        // `CATCHUP_PRUNE_INTERVAL` blocks. Once bitcoin-core has finished
        // its initial block download we prune on every tenure.
        if blockchain_info.initial_block_download
            && *target_height.saturating_sub(prune_height) < CATCHUP_PRUNE_INTERVAL
        {
            tracing::info!(
                validated_blocks = %blockchain_info.blocks,
                %prune_height,
                %target_height,
                "initial block download is in progress; pruning only every {CATCHUP_PRUNE_INTERVAL} blocks",
            );
            return Ok(PruneOutcome::CatchupIntervalNotReached { target_height, prune_height });
        }

        // We must not prune past what the connected Stacks node has
        // processed, since the Stacks node is likely connected to our
        // bitcoin node. If the Stacks node hasn't processed up to
        // `target_height` we skip pruning until it catches up. We also
        // conservatively skip pruning entirely if we cannot reach the
        // stacks node.
        let stacks_client = self.context.get_stacks_client();
        let node_bitcoin_height = match stacks_client.get_node_info().await {
            Ok(info) => info.burn_block_height,
            Err(error) => {
                tracing::warn!(%error, "could not reach the stacks node; skipping pruning");
                return Ok(PruneOutcome::StacksNodeUnreachable);
            }
        };

        if node_bitcoin_height < target_height {
            tracing::info!(
                %node_bitcoin_height,
                %target_height,
                "stacks node has not processed up to the target prune height; skipping pruning"
            );
            return Ok(PruneOutcome::StacksNodeBehindTarget {
                target_height,
                node_bitcoin_height,
            });
        }

        match bitcoin_client.prune_blockchain(target_height).await? {
            Some(pruned_height) => {
                tracing::info!(%pruned_height, "pruned blocks");
                Ok(PruneOutcome::Pruned(pruned_height))
            }
            None => {
                tracing::info!("RPC to prune blockchain returned -1, no pruning occurred");
                Ok(PruneOutcome::PruneRpcNoOp)
            }
        }
    }
}

/// Check if the connected bitcoin core is configured to allow pruning in
/// a way that is acceptable to the signer.
pub async fn pruning_enabled<B>(client: B) -> Result<bool, Error>
where
    B: BitcoinInteract,
{
    let blockchain_info = client.get_blockchain_info().await?;
    // This indicates that bitcoin-core has pruning enabled.
    let bitcoin_pruning_enabled = blockchain_info.pruned;
    // This indicates that bitcoin-core is configured to prune blocks
    // automatically. We will only prune blocks if it is configured for
    // manual pruning. If it is not configured, we assume automatic
    // pruning.
    let automatic_pruning = blockchain_info.automatic_pruning.unwrap_or(true);
    Ok(bitcoin_pruning_enabled && !automatic_pruning)
}
