//! # Bitcoin pruner event loop
//!
//! This module contains the bitcoin pruner, which is the component of the sBTC signer
//! responsible for pruning old bitcoin blocks from bitcoin-core.
//!
//!

use futures::StreamExt;

use crate::PRUNE_BLOCK_COUNT;
use crate::bitcoin::BitcoinInteract;
use crate::context::BitcoinPrunerEvent;
use crate::context::Context;
use crate::context::SignerCommand;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::context::TxCoordinatorEvent;
use crate::error::Error;
use crate::storage::model::BitcoinBlockRef;

/// The bitcoin pruner event loop.
#[derive(Debug)]
pub struct BitcoinPrunerEventLoop<C> {
    /// The signer context.
    context: C,
}

/// The interval at which we will prune blocks when bitcoin core is doing
/// an initial block download.
const PRUNE_INTERVAL: u64 = 25000;

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
    #[tracing::instrument(skip_all, fields(block_hash = %block_ref.block_hash))]
    async fn prune_blocks(&self, block_ref: BitcoinBlockRef) -> Result<(), Error> {
        let bitcoin_client = self.context.get_bitcoin_client();
        let blockchain_info = bitcoin_client.get_blockchain_info().await?;

        // This indicates whether the signer is configured to prune blocks
        // manually. If it is not configured, it defaults to not pruning
        // bitcoin-core.
        let signer_pruning_enabled = self.context.config().bitcoin.prune.unwrap_or(false);
        // This indicates that bitcoin-core has pruning enabled.
        let bitcoin_pruning_enabled = blockchain_info.pruned;
        // This indicates that bitcoin-core is configured to prune blocks
        // automatically. We will only prune blocks if it is configured for
        // manual pruning. If it is not configured, we assume automatic
        // pruning.
        let automatic_pruning = blockchain_info.automatic_pruning.unwrap_or(true);
        if !signer_pruning_enabled || !bitcoin_pruning_enabled || automatic_pruning {
            tracing::info!("pruning is not enabled; skipping this round");
            return Ok(());
        }

        let keep_blocks = match blockchain_info.chain {
            bitcoin::Network::Bitcoin => PRUNE_BLOCK_COUNT,
            _ => 100,
        };

        let target_height = block_ref.block_height.saturating_sub(keep_blocks);

        let Some(prune_height) = blockchain_info.prune_height else {
            tracing::warn!(
                "pruning is enabled; but the prune height is not set, that's unexpected"
            );
            return Ok(());
        };

        if prune_height >= *target_height {
            tracing::info!(
                %prune_height,
                %target_height,
                "pruning is not needed; the node is already pruned up to the target height"
            );
            return Ok(());
        };

        if blockchain_info.initial_block_download
            && blockchain_info.blocks.saturating_sub(prune_height) < PRUNE_INTERVAL
        {
            tracing::info!(
                validated_blocks = %blockchain_info.blocks,
                "initial block download is in progress; pruning only every {PRUNE_INTERVAL} blocks",
            );
            return Ok(());
        }

        match bitcoin_client.prune_blockchain(target_height).await? {
            Some(pruned_height) => {
                tracing::info!(%pruned_height, "pruned blocks");
            }
            None => {
                tracing::info!("RPC to prune blockchain returned -1, no pruning occurred");
            }
        }

        Ok(())
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
