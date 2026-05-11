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
#[derive(Debug, PartialEq, Eq)]
pub enum PruneOutcome {
    /// bitcoin-core successfully pruned blocks up to the indicated
    /// height.
    Pruned(BitcoinBlockHeight),
    /// The signer is not configured to prune bitcoin-core.
    SignerPruningDisabled,
    /// bitcoin-core does not have pruning enabled.
    BitcoinPruningDisabled,
    /// bitcoin-core is using automatic pruning; the signer only drives
    /// manual pruning.
    BitcoinAutomaticPruningEnabled,
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
        /// Height of the most-work fully-validated chain from bitcoin-core.
        validated_blocks: u64,
    },
    /// The connected stacks node has not yet processed past the target
    /// prune height.
    StacksNodeBehind {
        /// The target prune height.
        target_height: BitcoinBlockHeight,
        /// The first unpruned block height that bitcoin-core has.
        node_bitcoin_height: BitcoinBlockHeight,
    },
}

impl PruneOutcome {
    /// Emit tracing output for this outcome (severity and fields depend on the variant).
    fn log(self) {
        match self {
            Self::SignerPruningDisabled => {
                tracing::debug!("signer is not configured to prune; so no pruning");
            }
            Self::BitcoinPruningDisabled => {
                tracing::info!("bitcoin-core pruning is not enabled; so no pruning");
            }
            Self::BitcoinAutomaticPruningEnabled => {
                tracing::info!("bitcoin-core is using automatic pruning; so no pruning");
            }
            Self::Pruned(height) => {
                tracing::info!(%height, "pruned blocks");
            }
            Self::PruneRpcNoOp => {
                tracing::info!("RPC to prune blockchain returned -1, no pruning occurred");
            }
            Self::PruneHeightMissing => {
                tracing::warn!(
                    "pruning is enabled, but the prune height is unset; that's unexpected"
                );
            }
            Self::AlreadyAtTarget { target_height, prune_height } => {
                tracing::info!(
                    %prune_height,
                    %target_height,
                    "pruning is not needed; the node is already pruned up to the target height"
                );
            }
            Self::CatchupIntervalNotReached {
                target_height,
                prune_height,
                validated_blocks,
            } => {
                tracing::info!(
                    %validated_blocks,
                    %prune_height,
                    %target_height,
                    "initial block download is in progress; pruning only every {CATCHUP_PRUNE_INTERVAL} blocks",
                );
            }
            Self::StacksNodeBehind {
                target_height,
                node_bitcoin_height,
            } => {
                tracing::info!(
                    %node_bitcoin_height,
                    %target_height,
                    "stacks node has not processed past the target prune height; skipping pruning"
                );
            }
        }
    }
}

/// Bundled inputs for [`PruneInputs::decide`]. Caller must
/// already have established signer pruning is enabled; do not build this
/// when the signer's `bitcoin.prune` config flag is false (exit early instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneInputs {
    /// Tenure block from the coordinator signal.
    pub block_ref: BitcoinBlockRef,
    /// `GetBlockchainInfoResult::pruned`.
    pub bitcoin_core_reports_pruned: bool,
    /// `GetBlockchainInfoResult::automatic_pruning`.
    pub automatic_pruning: Option<bool>,
    /// `GetBlockchainInfoResult::prune_height`.
    pub prune_height: Option<u64>,
    /// `GetBlockchainInfoResult::initial_block_download`.
    pub initial_block_download: bool,
    /// `GetBlockchainInfoResult::blocks`.
    pub validated_blocks: u64,
    /// `GetBlockchainInfoResult::chain`.
    pub chain_network: bitcoin::Network,
    /// `GetNodeInfoResponse::burn_block_height` from the Stacks node.
    pub stacks_burn_block_height: BitcoinBlockHeight,
}

/// Same branching order as [`BitcoinPrunerEventLoop::prune_blocks`]. No I/O.
///
/// - [`Ok`] is the height to pass to `pruneblockchain`.
/// - [`Err`] is a terminal outcome (no prune RPC this round).
///
/// When the signer is not configured to prune, callers should return
/// [`PruneOutcome::SignerPruningDisabled`] before building [`PruneInputs`];
/// this function does not represent that case.
impl PruneInputs {
    /// Decide whether to prune blocks based on the inputs.
    fn compute_target_height(&self) -> Result<BitcoinBlockHeight, PruneOutcome> {
        if !self.bitcoin_core_reports_pruned {
            return Err(PruneOutcome::BitcoinPruningDisabled);
        }
        if self.automatic_pruning.unwrap_or(true) {
            return Err(PruneOutcome::BitcoinAutomaticPruningEnabled);
        }

        let keep_blocks = keep_blocks_for_network(self.chain_network);
        let target_height = self.block_ref.block_height.saturating_sub(keep_blocks);

        let Some(prune_height) = self.prune_height.map(BitcoinBlockHeight::from) else {
            return Err(PruneOutcome::PruneHeightMissing);
        };

        if prune_height >= target_height {
            return Err(PruneOutcome::AlreadyAtTarget { target_height, prune_height });
        }

        if self.initial_block_download
            && *target_height.saturating_sub(prune_height) < CATCHUP_PRUNE_INTERVAL
        {
            return Err(PruneOutcome::CatchupIntervalNotReached {
                target_height,
                prune_height,
                validated_blocks: self.validated_blocks,
            });
        }

        if self.stacks_burn_block_height <= target_height {
            return Err(PruneOutcome::StacksNodeBehind {
                target_height,
                node_bitcoin_height: self.stacks_burn_block_height,
            });
        }

        Ok(target_height)
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
                    match self.prune_blocks(block_ref).await {
                        Ok(outcome) => outcome.log(),
                        Err(error) => {
                            tracing::error!(%error, "error pruning blocks; skipping this round");
                        }
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
    /// (including cases where pruning was skipped). The caller should
    /// invoke [`PruneOutcome::log`] if tracing output is desired. RPC and
    /// transport failures are returned as [`Err`](Result::Err).
    #[tracing::instrument(skip_all, fields(block_hash = %block_ref.block_hash))]
    async fn prune_blocks(&self, block_ref: BitcoinBlockRef) -> Result<PruneOutcome, Error> {
        if !self.context.config().bitcoin.prune {
            return Ok(PruneOutcome::SignerPruningDisabled);
        }

        let bitcoin_client = self.context.get_bitcoin_client();
        let blockchain_info = bitcoin_client.get_blockchain_info().await?;

        let stacks_client = self.context.get_stacks_client();

        let inputs = PruneInputs {
            block_ref,
            bitcoin_core_reports_pruned: blockchain_info.pruned,
            automatic_pruning: blockchain_info.automatic_pruning,
            prune_height: blockchain_info.prune_height,
            initial_block_download: blockchain_info.initial_block_download,
            validated_blocks: blockchain_info.blocks,
            chain_network: blockchain_info.chain,
            stacks_burn_block_height: stacks_client.get_node_info().await?.burn_block_height,
        };

        match inputs.compute_target_height() {
            Err(outcome) => Ok(outcome),
            Ok(target_height) => match bitcoin_client.prune_blockchain(target_height).await? {
                Some(pruned_height) => Ok(PruneOutcome::Pruned(pruned_height)),
                None => Ok(PruneOutcome::PruneRpcNoOp),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::hashes::Hash as _;
    use bitcoincore_rpc_json::GetBlockchainInfoResult;
    use bitcoincore_rpc_json::StringOrStringArray;
    use serde_json::json;
    use test_case::test_case;

    use crate::stacks::api::GetNodeInfoResponse;
    use crate::storage::model::BitcoinBlockHash;
    use crate::testing::context::*;

    use super::*;

    /// Per-test inputs for [`prune_blocks_outcome`]. Each field is
    /// optional: tests set the ones they care about and fall back to
    /// happy-path defaults (regtest, chain tip 1000, manual pruning
    /// enabled, prune height 500, IBD finished, stacks and prune RPCs not
    /// reached) via `..Default::default()`.
    ///
    /// Fields that are themselves `Option` in `GetBlockchainInfoResult`
    /// (`automatic_pruning`, `prune_height`) are wrapped in an outer
    /// `Option` so that tests can distinguish "leave at default" (`None`)
    /// from "set to `None`" (`Some(None)`).
    #[derive(Clone)]
    struct PruneScenario {
        chain: bitcoin::Network,
        blocks: u64,
        pruned: bool,
        automatic_pruning: Option<bool>,
        prune_height: Option<u64>,
        initial_block_download: bool,
        /// `burn_block_height` reported by the mocked stacks RPC. `None`
        /// means the test does not expect the stacks RPC to be reached
        /// (no expectation is registered).
        stacks_burn_height: u64,
        /// If set, registers a mock for `prune_blockchain`. The outer
        /// `Option` is whether we expect the prune_blockchain RPC to be
        /// invoked; the inner value response.
        prune_blockchain_result: Option<Option<u64>>,
    }

    impl Default for PruneScenario {
        fn default() -> Self {
            Self {
                chain: bitcoin::Network::Regtest,
                blocks: 1_000,
                pruned: true,
                automatic_pruning: None,
                prune_height: Some(0),
                initial_block_download: false,
                stacks_burn_height: 0,
                prune_blockchain_result: None,
            }
        }
    }

    /// Build a `GetNodeInfoResponse` whose `burn_block_height` matches
    /// the provided height. Other fields come from the fixture used
    /// elsewhere in the test suite.
    fn node_info_with_burn_height(burn_block_height: u64) -> GetNodeInfoResponse {
        let raw = include_str!("../tests/fixtures/stacksapi-get-node-info-test-data.json");
        let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
        value["burn_block_height"] = json!(burn_block_height);
        serde_json::from_value(value).unwrap()
    }

    fn block_ref_at(height: u64) -> BitcoinBlockRef {
        BitcoinBlockRef {
            block_hash: BitcoinBlockHash::from([0; 32]),
            block_height: height.into(),
        }
    }

    /// `SignerPruningDisabled` is the only outcome that returns before
    /// touching either RPC client, so it gets its own minimal test.
    #[tokio::test]
    async fn prune_blocks_returns_signer_pruning_disabled_when_config_disabled() {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| settings.bitcoin.prune = false)
            .build();

        let pruner = BitcoinPrunerEventLoop::new(context);
        let outcome = pruner.prune_blocks(block_ref_at(1_000)).await.unwrap();

        assert_eq!(outcome, PruneOutcome::SignerPruningDisabled);
    }

    // On non-mainnet `keep_blocks` is 100, so with a chain tip of 1000
    // the target prune height is 900 in every case below.
    #[test_case(
        PruneScenario { 
            pruned: false,
            ..Default::default()
        },
        PruneOutcome::BitcoinPruningDisabled
        ; "BitcoinPruningDisabled when bitcoin-core has pruning off"
    )]
    #[test_case(
        PruneScenario { automatic_pruning: Some(true), ..Default::default() },
        PruneOutcome::BitcoinAutomaticPruningEnabled
        ; "BitcoinAutomaticPruningEnabled when bitcoin-core auto-prunes"
    )]
    #[test_case(
        PruneScenario { 
            prune_height: None,
            automatic_pruning: Some(false),
            ..Default::default()
        },
        PruneOutcome::PruneHeightMissing
        ; "PruneHeightMissing when bitcoin-core does not return a prune height"
    )]
    #[test_case(
        PruneScenario { 
            prune_height: Some(950),
            automatic_pruning: Some(false),
            ..Default::default()
        },
        PruneOutcome::AlreadyAtTarget {
            target_height: BitcoinBlockHeight::from(900u64),
            prune_height: BitcoinBlockHeight::from(950u64),
        }
        ; "AlreadyAtTarget when prune height is past the target"
    )]
    #[test_case(
        PruneScenario {
            prune_height: Some(800),
            initial_block_download: true,
            automatic_pruning: Some(false),
            ..Default::default()
        },
        PruneOutcome::CatchupIntervalNotReached {
            target_height: BitcoinBlockHeight::from(900u64),
            prune_height: BitcoinBlockHeight::from(800u64),
            validated_blocks: 1_000,
        }
        ; "CatchupIntervalNotReached during IBD with a small gap"
    )]
    #[test_case(
        PruneScenario { 
            stacks_burn_height: 800,
            automatic_pruning: Some(false),
            ..Default::default() 
        },
        PruneOutcome::StacksNodeBehind {
            target_height: BitcoinBlockHeight::from(900u64),
            node_bitcoin_height: BitcoinBlockHeight::from(800u64),
        }
        ; "StacksNodeBehind when stacks node is behind the target"
    )]
    #[test_case(
        PruneScenario {
            stacks_burn_height: 2_000,
            automatic_pruning: Some(false),
            prune_blockchain_result: Some(Some(900)),
            ..Default::default()
        },
        PruneOutcome::Pruned(BitcoinBlockHeight::from(900u64))
        ; "Pruned when the prune RPC returns the target height"
    )]
    #[test_case(
        PruneScenario {
            stacks_burn_height: 2_000,
            automatic_pruning: Some(false),
            prune_blockchain_result: Some(None),
            ..Default::default()
        },
        PruneOutcome::PruneRpcNoOp
        ; "PruneRpcNoOp when the prune RPC returns -1"
    )]
    #[tokio::test]
    async fn prune_blocks_outcome(scenario: PruneScenario, expected: PruneOutcome) {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| settings.bitcoin.prune = true)
            .build();

        let blockchain_info = GetBlockchainInfoResult {
            chain: scenario.chain,
            blocks: scenario.blocks,
            headers: 5 * scenario.blocks,
            best_block_hash: bitcoin::BlockHash::all_zeros(),
            difficulty: 0.0,
            median_time: 0,
            verification_progress: 1.0,
            initial_block_download: scenario.initial_block_download,
            chain_work: Vec::new(),
            size_on_disk: 0,
            pruned: scenario.pruned,
            prune_height: scenario.prune_height,
            automatic_pruning: scenario.automatic_pruning,
            prune_target_size: None,
            softforks: HashMap::new(),
            warnings: StringOrStringArray::String(String::new()),
        };

        context
            .with_bitcoin_client(|client| {
                client
                    .expect_get_blockchain_info()
                    .once()
                    .returning(move || {
                        let info = blockchain_info.clone();
                        Box::pin(async move { Ok(info) })
                    });

                if let Some(result) = scenario.prune_blockchain_result {
                    client
                        .expect_prune_blockchain()
                        .once()
                        .withf(|h| *h == BitcoinBlockHeight::from(900u64))
                        .returning(move |_| {
                            Box::pin(async move { Ok(result.map(BitcoinBlockHeight::from)) })
                        });
                }
            })
            .await;

        context
            .with_stacks_client(|client| {
                client.expect_get_node_info().once().returning(move || {
                    Box::pin(
                        async move { Ok(node_info_with_burn_height(scenario.stacks_burn_height)) },
                    )
                });
            })
            .await;

        let pruner = BitcoinPrunerEventLoop::new(context);
        let outcome = pruner.prune_blocks(block_ref_at(1_000)).await.unwrap();

        assert_eq!(outcome, expected);
    }
}
