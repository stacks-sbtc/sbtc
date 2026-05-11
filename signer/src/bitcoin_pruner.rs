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
/// while bitcoin-core is still catching up to the chain tip. It
/// corresponds to 180 days worth of blocks. This interval is not used once
/// bitcoin-core has finished its initial block download.
const CATCHUP_PRUNE_INTERVAL: u64 = 6 * 24 * 180;

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
pub enum PruneResult {
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

impl PruneResult {
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

/// Snapshot of the state used to decide whether (and where) to prune
/// bitcoin-core on a given tenure. Caller must already have established
/// signer pruning is enabled; do not build this when the signer's
/// `bitcoin.prune` config flag is false (exit early instead).
///
/// The `pruned`, `automatic_pruning`, `prune_height`,
/// `initial_block_download`, `validated_blocks`, and `chain` fields are
/// sourced from bitcoin-core's `getblockchaininfo` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneSnapshot {
    /// Height of the bitcoin chain tip the tenure was anchored to.
    pub chain_tip_height: BitcoinBlockHeight,
    /// Whether bitcoin-core has pruning enabled.
    pub pruned: bool,
    /// Whether bitcoin-core is pruning automatically. Some(false)
    /// indicates manual pruning, and this is None when bitcoin-core did
    /// not return the field in a `getblockchaininfo` response, which
    /// indicates that pruning is disabled.
    pub automatic_pruning: Option<bool>,
    /// First non-pruned block height — in other words, the lowest height
    /// bitcoin-core still has on disk. This is None when bitcoin-core did
    /// not return the field in a `getblockchaininfo` response.
    pub prune_height: Option<u64>,
    /// Whether bitcoin-core is still in its initial block download.
    pub initial_block_download: bool,
    /// Height of the most-work fully-validated chain.
    pub validated_blocks: u64,
    /// The bitcoin network bitcoin-core is connected to.
    pub chain: bitcoin::Network,
    /// `GetNodeInfoResponse::burn_block_height` — the bitcoin block
    /// height the connected stacks node has processed up to.
    pub stacks_bitcoin_block_height: BitcoinBlockHeight,
}

impl PruneSnapshot {
    /// Validate the snapshot and, if pruning should proceed, return the
    /// height to pass to `pruneblockchain`.
    ///
    /// - [`Ok`] is the height to pass to `pruneblockchain`.
    /// - [`Err`] is a terminal outcome (no prune RPC this round).
    ///
    /// When the signer is not configured to prune, callers should return
    /// [`PruneResult::SignerPruningDisabled`] before building a
    /// [`PruneSnapshot`]; this function does not represent that case.
    fn target_height(&self) -> Result<BitcoinBlockHeight, PruneResult> {
        if !self.pruned {
            return Err(PruneResult::BitcoinPruningDisabled);
        }
        if self.automatic_pruning.unwrap_or(true) {
            return Err(PruneResult::BitcoinAutomaticPruningEnabled);
        }

        let keep_blocks = keep_blocks_for_network(self.chain);
        let target_height = self.chain_tip_height.saturating_sub(keep_blocks);

        let Some(prune_height) = self.prune_height.map(BitcoinBlockHeight::from) else {
            return Err(PruneResult::PruneHeightMissing);
        };

        if prune_height >= target_height {
            return Err(PruneResult::AlreadyAtTarget { target_height, prune_height });
        }

        if self.initial_block_download
            && *target_height.saturating_sub(prune_height) < CATCHUP_PRUNE_INTERVAL
        {
            return Err(PruneResult::CatchupIntervalNotReached {
                target_height,
                prune_height,
                validated_blocks: self.validated_blocks,
            });
        }

        if self.stacks_bitcoin_block_height <= target_height {
            return Err(PruneResult::StacksNodeBehind {
                target_height,
                node_bitcoin_height: self.stacks_bitcoin_block_height,
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
    #[tracing::instrument(skip_all, name = "bitcoin-pruner", fields(
        bitcoin_tip_hash = tracing::field::Empty,
        bitcoin_tip_height = tracing::field::Empty,
    ))]
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
                    let span = tracing::Span::current();
                    let tracing_chain_tip = tracing::field::display(block_ref.block_hash);
                    span.record("bitcoin_tip_hash", tracing_chain_tip);
                    span.record("bitcoin_tip_height", *block_ref.block_height);

                    tracing::info!(
                        "bitcoin pruner received tenure completed signal; pruning blocks"
                    );
                    match self.prune_blocks(block_ref.block_height).await {
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
    /// On success, returns a [`PruneResult`] describing what happened
    /// (including cases where pruning was skipped). The caller should
    /// invoke [`PruneResult::log`] if tracing output is desired. RPC and
    /// transport failures are returned as [`Err`](Result::Err).
    #[tracing::instrument(skip_all)]
    async fn prune_blocks(&self, block_height: BitcoinBlockHeight) -> Result<PruneResult, Error> {
        if !self.context.config().bitcoin.prune {
            return Ok(PruneResult::SignerPruningDisabled);
        }

        let bitcoin_client = self.context.get_bitcoin_client();
        let blockchain_info = bitcoin_client.get_blockchain_info().await?;

        let stacks_client = self.context.get_stacks_client();

        let snapshot = PruneSnapshot {
            chain_tip_height: block_height,
            pruned: blockchain_info.pruned,
            automatic_pruning: blockchain_info.automatic_pruning,
            prune_height: blockchain_info.prune_height,
            initial_block_download: blockchain_info.initial_block_download,
            validated_blocks: blockchain_info.blocks,
            chain: blockchain_info.chain,
            stacks_bitcoin_block_height: stacks_client.get_node_info().await?.burn_block_height,
        };

        match snapshot.target_height() {
            Err(outcome) => Ok(outcome),
            Ok(target_height) => match bitcoin_client.prune_blockchain(target_height).await? {
                Some(pruned_height) => Ok(PruneResult::Pruned(pruned_height)),
                None => Ok(PruneResult::PruneRpcNoOp),
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
    use crate::testing::context::*;

    use super::*;

    /// A happy-path `PruneSnapshot` used as the baseline for the
    /// `target_height` test cases: regtest (so `keep_blocks` is 100),
    /// chain tip at 1000 (so the target prune height is 900), manual
    /// pruning enabled, bitcoin-core already pruned up to 500, IBD
    /// finished, stacks node ahead of the target.
    const SNAPSHOT: PruneSnapshot = PruneSnapshot {
        chain_tip_height: BitcoinBlockHeight::new(1_000),
        pruned: true,
        automatic_pruning: Some(false),
        prune_height: Some(500),
        initial_block_download: false,
        validated_blocks: 1_000,
        chain: bitcoin::Network::Regtest,
        stacks_bitcoin_block_height: BitcoinBlockHeight::new(2_000),
    };

    /// Build a happy-path `GetBlockchainInfoResult` matching the defaults
    /// used by [`snapshot`].
    fn blockchain_info() -> GetBlockchainInfoResult {
        GetBlockchainInfoResult {
            chain: bitcoin::Network::Regtest,
            blocks: 1_000,
            headers: 1_000,
            best_block_hash: bitcoin::BlockHash::all_zeros(),
            difficulty: 0.0,
            median_time: 0,
            verification_progress: 1.0,
            initial_block_download: false,
            chain_work: Vec::new(),
            size_on_disk: 0,
            pruned: true,
            prune_height: Some(500),
            automatic_pruning: Some(false),
            prune_target_size: None,
            softforks: HashMap::new(),
            warnings: StringOrStringArray::String(String::new()),
        }
    }

    #[test_case(
        PruneSnapshot { pruned: false, ..SNAPSHOT },
        PruneResult::BitcoinPruningDisabled
        ; "BitcoinPruningDisabled when bitcoin-core has pruning off"
    )]
    #[test_case(
        PruneSnapshot { automatic_pruning: Some(true), ..SNAPSHOT },
        PruneResult::BitcoinAutomaticPruningEnabled
        ; "BitcoinAutomaticPruningEnabled when bitcoin-core auto-prunes"
    )]
    #[test_case(
        PruneSnapshot { prune_height: None, ..SNAPSHOT },
        PruneResult::PruneHeightMissing
        ; "PruneHeightMissing when bitcoin-core does not return a prune height"
    )]
    #[test_case(
        PruneSnapshot { prune_height: Some(950), ..SNAPSHOT },
        PruneResult::AlreadyAtTarget {
            target_height: BitcoinBlockHeight::new(900),
            prune_height: BitcoinBlockHeight::new(950),
        }
        ; "AlreadyAtTarget when prune height is past the target"
    )]
    #[test_case(
        PruneSnapshot {
            prune_height: Some(800),
            initial_block_download: true,
            ..SNAPSHOT
        },
        PruneResult::CatchupIntervalNotReached {
            target_height: BitcoinBlockHeight::new(900),
            prune_height: BitcoinBlockHeight::new(800),
            validated_blocks: 1_000,
        }
        ; "CatchupIntervalNotReached on regtest during IBD with a small gap"
    )]
    #[test_case(
        PruneSnapshot {
            chain: bitcoin::Network::Bitcoin,
            chain_tip_height: BitcoinBlockHeight::new(100_000),
            prune_height: Some(30_000),
            initial_block_download: true,
            stacks_bitcoin_block_height: BitcoinBlockHeight::new(200_000),
            ..SNAPSHOT
        },
        PruneResult::CatchupIntervalNotReached {
            target_height: BitcoinBlockHeight::new(100_000 - u16::MAX as u64),
            prune_height: BitcoinBlockHeight::new(30_000),
            validated_blocks: 1_000,
        }
        ; "CatchupIntervalNotReached on mainnet during IBD with a small gap"
    )]
    #[test_case(
        PruneSnapshot { stacks_bitcoin_block_height: BitcoinBlockHeight::new(800), ..SNAPSHOT },
        PruneResult::StacksNodeBehind {
            target_height: BitcoinBlockHeight::new(900),
            node_bitcoin_height: BitcoinBlockHeight::new(800),
        }
        ; "StacksNodeBehind on regtest when stacks node is behind the target"
    )]
    #[test_case(
        PruneSnapshot {
            chain: bitcoin::Network::Bitcoin,
            chain_tip_height: BitcoinBlockHeight::new(100_000),
            stacks_bitcoin_block_height: BitcoinBlockHeight::new(34_000),
            ..SNAPSHOT
        },
        PruneResult::StacksNodeBehind {
            target_height: BitcoinBlockHeight::new(100_000 - u16::MAX as u64),
            node_bitcoin_height: BitcoinBlockHeight::new(34_000),
        }
        ; "StacksNodeBehind on mainnet when stacks node is behind the target"
    )]
    fn target_height_outcome(snapshot: PruneSnapshot, expected: PruneResult) {
        assert_eq!(snapshot.target_height(), Err(expected));
    }

    // Non-mainnet networks all share `KEEP_BLOCKS_NON_MAINNET` (100);
    // mainnet uses `KEEP_BLOCKS_MAINNET` (u16::MAX = 65_535). The cases
    // below exercise both branches of `keep_blocks_for_network`.
    #[test_case(
        SNAPSHOT,
        BitcoinBlockHeight::new(900)
        ; "regtest: chain tip minus 100"
    )]
    #[test_case(
        PruneSnapshot { chain: bitcoin::Network::Testnet, ..SNAPSHOT },
        BitcoinBlockHeight::new(900)
        ; "testnet: chain tip minus 100"
    )]
    #[test_case(
        PruneSnapshot { chain: bitcoin::Network::Signet, ..SNAPSHOT },
        BitcoinBlockHeight::new(900)
        ; "signet: chain tip minus 100"
    )]
    #[test_case(
        PruneSnapshot {
            chain: bitcoin::Network::Bitcoin,
            chain_tip_height: BitcoinBlockHeight::new(100_000),
            stacks_bitcoin_block_height: BitcoinBlockHeight::new(99_998),
            ..SNAPSHOT
        },
        BitcoinBlockHeight::new(100_000 - u16::MAX as u64)
        ; "mainnet: chain tip minus u16::MAX"
    )]
    fn target_height_happy_path(snapshot: PruneSnapshot, expected: BitcoinBlockHeight) {
        assert_eq!(snapshot.target_height(), Ok(expected));
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

    #[tokio::test]
    async fn prune_blocks_returns_signer_pruning_disabled_when_config_disabled() {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| settings.bitcoin.prune = false)
            .build();

        let pruner = BitcoinPrunerEventLoop::new(context);
        let outcome = pruner
            .prune_blocks(BitcoinBlockHeight::new(1_000))
            .await
            .unwrap();

        assert_eq!(outcome, PruneResult::SignerPruningDisabled);
    }

    #[test_case(
        Some(BitcoinBlockHeight::from(900u64)),
        PruneResult::Pruned(BitcoinBlockHeight::from(900u64))
        ; "Pruned when the prune RPC returns the target height"
    )]
    #[test_case(
        None,
        PruneResult::PruneRpcNoOp
        ; "PruneRpcNoOp when the prune RPC returns -1"
    )]
    #[tokio::test]
    async fn prune_blocks_invokes_prune_rpc(
        prune_rpc_result: Option<BitcoinBlockHeight>,
        expected: PruneResult,
    ) {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| settings.bitcoin.prune = true)
            .build();

        context
            .with_bitcoin_client(|client| {
                client
                    .expect_get_blockchain_info()
                    .once()
                    .returning(|| Box::pin(async { Ok(blockchain_info()) }));
                client
                    .expect_prune_blockchain()
                    .once()
                    .withf(|h| *h == BitcoinBlockHeight::from(900u64))
                    .returning(move |_| Box::pin(async move { Ok(prune_rpc_result) }));
            })
            .await;

        context
            .with_stacks_client(|client| {
                client
                    .expect_get_node_info()
                    .once()
                    .returning(|| Box::pin(async { Ok(node_info_with_burn_height(2_000)) }));
            })
            .await;

        let pruner = BitcoinPrunerEventLoop::new(context);
        let outcome = pruner
            .prune_blocks(BitcoinBlockHeight::new(1_000))
            .await
            .unwrap();

        assert_eq!(outcome, expected);
    }
}
