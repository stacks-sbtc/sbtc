//! # Block observer
//!
//! This module contains the block observer implementation for the sBTC signer.
//! The block observer is responsible for populating the signer database with
//! information from the Bitcoin and Stacks blockchains, and notifying
//! the signer event loop whenever the state has been updated.
//!
//! The following information is extracted by the block observer:
//! - Bitcoin blocks
//! - Stacks blocks
//! - Deposit requests
//! - sBTC transactions
//! - Withdraw requests
//! - Deposit accept transactions
//! - Withdraw accept transactions
//! - Withdraw reject transactions
//! - Update signer set transactions
//! - Set aggregate key transactions

use std::future::Future;
use std::num::NonZeroUsize;
use std::time::Duration;
use std::time::Instant;

use crate::MAX_REORG_BLOCK_COUNT;
use crate::bitcoin::BitcoinBlockHashStreamProvider;
use crate::bitcoin::BitcoinInteract;
use crate::bitcoin::rpc::BitcoinBlockHeader;
use crate::bitcoin::rpc::BitcoinBlockInfo;
use crate::bitcoin::rpc::BitcoinTxInfo;
use crate::bitcoin::utxo::TxDeconstructor as _;
use crate::context::Context;
use crate::context::SbtcLimits;
use crate::context::SignerEvent;
use crate::emily_client::EmilyInteract as _;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey as _;
use crate::metrics::BITCOIN_BLOCKCHAIN;
use crate::metrics::Metrics;
use crate::stacks::api::SignerSetInfo;
use crate::stacks::api::StacksInteract as _;
use crate::stacks::contracts::SMART_CONTRACTS;
use crate::storage::DbRead;
use crate::storage::DbWrite;
use crate::storage::Transactable as _;
use crate::storage::TransactionHandle as _;
use crate::storage::model;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinBlockRef;
use crate::storage::model::EncryptedDkgShares;
use crate::storage::model::SignerKeySet;
use crate::storage::model::StacksBlockRef;
use crate::storage::model::TxPrevout;
use crate::storage::model::TxPrevoutType;
use crate::util::FutureExt as _;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use bitcoin::hashes::Hash as _;
use bitcoin::hashes::HashEngine as _;
use bitcoin::hashes::sha256;
use clarity::codec::StacksMessageCodec as _;
use futures::stream::StreamExt as _;
use lru::LruCache;
use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::DepositInfo;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

/// Max requests [`DepositIntake`] tracks, about 120 bytes each, so ~6 MB.
const DEPOSIT_INTAKE_CAPACITY: NonZeroUsize =
    NonZeroUsize::new(50_000).expect("the deposit intake capacity is non-zero");

/// Intakes to wait before re-validating an unconfirmed, stored, or twice-failed request. Handles missed confirmations and reorgs.
const DEPOSIT_REPROBE_INTERVAL: u64 = 6;

/// Block observer
#[derive(Debug)]
pub struct BlockObserver<Context, BlockSource> {
    /// Signer context
    pub context: Context,
    /// Provider of Bitcoin block hashes.
    pub bitcoin_block_source: BlockSource,
}

/// A full "deposit", containing the bitcoin transaction and a fully
/// extracted and verified `scriptPubKey` from one of the transaction's
/// UTXOs.
#[derive(Debug, Clone)]
pub struct Deposit {
    /// The transaction spent to the signers as a deposit for sBTC.
    pub tx_info: BitcoinTxInfo,
    /// The deposit information included in one of the output
    /// `scriptPubKey`s of the above transaction.
    pub info: DepositInfo,
    /// The block hash of the Bitcoin block that includes this transaction.
    pub block_hash: BlockHash,
}

impl DepositRequestValidator for CreateDepositRequest {
    async fn validate<C>(&self, client: &C, is_mainnet: bool) -> Result<Option<Deposit>, Error>
    where
        C: BitcoinInteract,
    {
        // Fetch the UTXO info for a confirmed outpoint
        let Some(response) = client.get_utxo_info(&self.outpoint).await? else {
            return Ok(None);
        };

        if response.is_coinbase {
            return Err(Error::BitcoinTxCoinbase(self.outpoint.txid));
        }

        // This is usually the block hash confirming the transaction
        // associated with the outpoint. However, it can be incorrect if
        // our bitcoin node detects a reorg in the middle of the above
        // function call and the reorg affects the outpoint in question.
        // The call below to get_tx_info will detect this and we will
        // either return Ok(None) or an error, which is fine, it will get
        // sorted out at the arrival of the next bitcoin block.
        let block_hash = response.block_hash;

        // The `get_tx_info` call here should not return None, we know that
        // it has been included in a block.
        let Some(tx_info) = client.get_tx_info(&self.outpoint.txid, &block_hash).await? else {
            return Ok(None);
        };

        // Check that the necessary data is present for the transaction
        // info struct.
        tx_info.validate()?;

        Ok(Some(Deposit {
            info: self.validate_tx(&tx_info.tx, is_mainnet)?,
            tx_info,
            block_hash,
        }))
    }
}

/// A trait to add validation functionality to the [`CreateDepositRequest`]
/// type.
pub trait DepositRequestValidator {
    /// Validate this deposit request from the transaction.
    ///
    /// Returns `Ok(None)` if the outpoint is not a confirmed unspent output.
    fn validate<C>(
        &self,
        client: &C,
        is_mainnet: bool,
    ) -> impl Future<Output = Result<Option<Deposit>, Error>>
    where
        C: BitcoinInteract;
}

/// The result of validating one deposit request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationOutcome {
    /// Validated and stored.
    Valid,
    /// Not a confirmed unspent output.
    Unconfirmed,
    /// Fails for these exact request contents.
    Invalid,
    /// Failed transiently.
    Errored,
}

impl ValidationOutcome {
    fn new(result: &Result<Option<Deposit>, Error>) -> Self {
        match result {
            Ok(Some(_)) => Self::Valid,
            Ok(None) => Self::Unconfirmed,
            // Deterministic for a given transaction and request.
            Err(Error::SbtcLib(_) | Error::BitcoinTxCoinbase(_)) => Self::Invalid,
            Err(_) => Self::Errored,
        }
    }
}

/// Result of the last request validation.
enum IntakeEntry {
    /// Newly processed, but deferred by the budget.
    Due,
    /// Unconfirmed at `probed_at`.
    Unconfirmed { probed_at: u64 },
    /// Stored at `probed_at`; stops re-validation after leaving the context window.
    Stored { probed_at: u64 },
    /// Transiently failed at `probed_at`; `repeated` if the previous check also failed.
    Errored { probed_at: u64, repeated: bool },
    /// Deterministically invalid for `request_digest`.
    Invalid { request_digest: [u8; 32] },
}

/// Selects Emily deposit requests to validate each block within a budget.
struct DepositIntake {
    /// Intake counter; block heights may repeat after reorgs.
    seq: u64,
    /// Txids of processed blocks and their intake sequence.
    new_blocks: VecDeque<(u64, Vec<Txid>)>,
    /// First never-tried request skipped by the last completed intake. Prevents evicted requests from overtaking never-tried ones.
    fresh_cursor: Option<OutPoint>,
    /// Last validation result per request.
    entries: LruCache<OutPoint, IntakeEntry>,
}

/// Requests selected for an intake, with log counts and the next cursor.
struct Selection<'a> {
    /// Requests to validate, in order, within budget.
    requests: Vec<&'a CreateDepositRequest>,
    /// Stored and confirmed requests in the context window.
    known: usize,
    /// Eligible requests from newly processed blocks.
    in_new_blocks: usize,
    /// Eligible requests deferred by the budget.
    deferred: usize,
    /// First never-tried request for the next intake.
    cursor: Option<OutPoint>,
}

impl DepositIntake {
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            seq: 0,
            new_blocks: VecDeque::new(),
            fresh_cursor: None,
            entries: LruCache::new(capacity),
        }
    }

    /// Keeps only the newest [`MAX_REORG_BLOCK_COUNT`] blocks.
    fn add_new_blocks<I>(&mut self, blocks: I)
    where
        I: IntoIterator<Item = Vec<Txid>>,
    {
        let seq = self.seq;
        self.new_blocks
            .extend(blocks.into_iter().map(|txids| (seq, txids)));
        let excess = self
            .new_blocks
            .len()
            .saturating_sub(MAX_REORG_BLOCK_COUNT as usize);
        self.new_blocks.drain(..excess);
    }

    /// The intake each recent transaction was last processed in.
    fn new_txids(&self) -> HashMap<Txid, u64> {
        let mut txids = HashMap::new();
        for (seq, block) in &self.new_blocks {
            for txid in block {
                txids.insert(*txid, *seq);
            }
        }
        txids
    }

    /// Selects up to `budget` requests: new/due block requests, first errors and due re-checks (up to `ceil(budget / 4)`); changed contents; never-tried requests from the cursor; remaining re-checks. `requests` must be oldest-first and deduplicated.
    fn select<'a>(
        &mut self,
        requests: &'a [CreateDepositRequest],
        known: &HashSet<OutPoint>,
        new_txids: &HashMap<Txid, u64>,
        budget: usize,
    ) -> Selection<'a> {
        let mut known_count = 0;
        let mut in_new_blocks = Vec::new();
        let mut rechecks = Vec::new();
        let mut changed = Vec::new();
        let mut fresh = Vec::new();

        for (index, request) in requests.iter().enumerate() {
            if known.contains(&request.outpoint) {
                known_count += 1;
                continue;
            }
            let entry = self.entries.peek(&request.outpoint);
            let probed_at = match entry {
                Some(
                    IntakeEntry::Unconfirmed { probed_at }
                    | IntakeEntry::Stored { probed_at }
                    | IntakeEntry::Errored { probed_at, .. },
                ) => Some(*probed_at),
                _ => None,
            };
            let in_new_block = new_txids
                .get(&request.outpoint.txid)
                .is_some_and(|seen| probed_at.is_none_or(|probed_at| *seen > probed_at));

            match entry {
                Some(IntakeEntry::Invalid { request_digest })
                    if *request_digest == deposit_request_digest(request) => {}
                _ if in_new_block => in_new_blocks.push(request),
                Some(IntakeEntry::Due) => in_new_blocks.push(request),
                // Retry first errors next intake, others after the interval.
                Some(IntakeEntry::Errored { probed_at, repeated: false }) => {
                    rechecks.push((false, *probed_at, request))
                }
                Some(
                    IntakeEntry::Unconfirmed { probed_at }
                    | IntakeEntry::Stored { probed_at }
                    | IntakeEntry::Errored { probed_at, repeated: true },
                ) => {
                    if self.seq.saturating_sub(*probed_at) >= DEPOSIT_REPROBE_INTERVAL {
                        rechecks.push((true, *probed_at, request));
                    }
                }
                Some(IntakeEntry::Invalid { .. }) => changed.push(request),
                None => fresh.push((index, request)),
            }
        }

        let cursor = self.fresh_cursor.and_then(|cursor| {
            requests
                .iter()
                .position(|request| request.outpoint == cursor)
        });
        if let Some(position) = cursor {
            let start = fresh.partition_point(|(index, _)| *index < position);
            fresh.rotate_left(start);
        }

        rechecks.sort_by_key(|(is_due, probed_at, _)| (*is_due, *probed_at));

        // Reserved so re-checks keep a share of the budget.
        let mut reserved = rechecks;
        let later = reserved.split_off(budget.div_ceil(4).min(reserved.len()));

        for request in in_new_blocks.iter().skip(budget) {
            self.entries.put(request.outpoint, IntakeEntry::Due);
        }

        let taken_before_fresh = in_new_blocks.len() + reserved.len() + changed.len();
        let fresh_taken = budget.saturating_sub(taken_before_fresh).min(fresh.len());
        let cursor = fresh.get(fresh_taken).map(|(_, request)| request.outpoint);

        let eligible = taken_before_fresh + fresh.len() + later.len();
        let in_new_blocks_count = in_new_blocks.len();
        let selected: Vec<_> = in_new_blocks
            .into_iter()
            .chain(reserved.into_iter().map(|(_, _, request)| request))
            .chain(changed)
            .chain(fresh.into_iter().map(|(_, request)| request))
            .chain(later.into_iter().map(|(_, _, request)| request))
            .take(budget)
            .collect();
        Selection {
            deferred: eligible.saturating_sub(selected.len()),
            requests: selected,
            known: known_count,
            in_new_blocks: in_new_blocks_count,
            cursor,
        }
    }

    /// Records outcomes, commits the selection cursor and processed blocks, and ends the intake.
    fn record<'a, I>(
        &mut self,
        outcomes: I,
        cursor: Option<OutPoint>,
        written_blocks: Vec<Vec<Txid>>,
    ) where
        I: IntoIterator<Item = (&'a CreateDepositRequest, ValidationOutcome)>,
    {
        for (request, outcome) in outcomes {
            let entry = match outcome {
                ValidationOutcome::Valid => IntakeEntry::Stored { probed_at: self.seq },
                ValidationOutcome::Unconfirmed => IntakeEntry::Unconfirmed { probed_at: self.seq },
                ValidationOutcome::Errored => IntakeEntry::Errored {
                    probed_at: self.seq,
                    repeated: matches!(
                        self.entries.peek(&request.outpoint),
                        Some(IntakeEntry::Errored { .. })
                    ),
                },
                ValidationOutcome::Invalid => IntakeEntry::Invalid {
                    request_digest: deposit_request_digest(request),
                },
            };
            self.entries.put(request.outpoint, entry);
        }
        self.fresh_cursor = cursor;
        self.seq = self.seq.saturating_add(1);
        // Written during this intake, so some of its checks predate them.
        self.add_new_blocks(written_blocks);
    }
}

/// Hashes the full request, including Emily's mutable v2 recipient and max fee.
fn deposit_request_digest(request: &CreateDepositRequest) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(request.outpoint.txid.as_byte_array());
    engine.input(&request.outpoint.vout.to_be_bytes());
    for script in [&request.deposit_script, &request.reclaim_script] {
        engine.input(&script.len().to_be_bytes());
        engine.input(script.as_bytes());
    }
    match &request.recipient {
        Some(recipient) => {
            engine.input(&[1]);
            engine.input(&recipient.serialize_to_vec());
        }
        None => engine.input(&[0]),
    }
    match request.max_fee {
        Some(max_fee) => {
            engine.input(&[1]);
            engine.input(&max_fee.to_be_bytes());
        }
        None => engine.input(&[0]),
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

impl<C, BlockSource> BlockObserver<C, BlockSource>
where
    C: Context,
    BlockSource: BitcoinBlockHashStreamProvider,
{
    /// Create a new [`BlockObserver`] with the given context and Bitcoin block
    /// provider.
    pub fn new(context: C, bitcoin_block_source: BlockSource) -> Self {
        Self { context, bitcoin_block_source }
    }

    /// Run the block observer
    #[tracing::instrument(skip_all, name = "block-observer", fields(bitcoin_tip_hash = tracing::field::Empty))]
    pub async fn run(self) -> Result<(), Error> {
        let span = tracing::Span::current();
        let term = self.context.get_termination_handle();
        let mut bitcoin_blocks = self.bitcoin_block_source.get_block_hash_stream();
        let mut intake = DepositIntake::new(DEPOSIT_INTAKE_CAPACITY);

        loop {
            if term.shutdown_signalled() {
                tracing::debug!("block observer has received a shutdown signal");
                break;
            }

            // Bitcoin blocks will generally arrive in ~10 minute intervals, so
            // we don't need to be so aggressive in our timeout here.
            let poll = bitcoin_blocks
                .next()
                .with_timeout(Duration::from_millis(100));

            match poll.await {
                Ok(Some(Ok(block_hash))) => {
                    span.record("bitcoin_tip_hash", tracing::field::display(block_hash));

                    tracing::info!("observed new bitcoin block from stream");
                    metrics::counter!(
                        Metrics::BlocksObservedTotal,
                        "blockchain" => BITCOIN_BLOCKCHAIN,
                    )
                    .increment(1);

                    match self.process_bitcoin_chain_tip(block_hash).await {
                        Ok(new_blocks) => intake.add_new_blocks(new_blocks),
                        Err(error) => tracing::error!(%error, "could not process bitcoin blocks"),
                    }

                    let Ok(chain_tip) = self.resolve_block_ref(block_hash).await else {
                        tracing::error!("could not get bitcoin block ref from the block hash");
                        continue;
                    };

                    if let Err(error) = self.check_pending_dkg_shares(&chain_tip).await {
                        tracing::error!(%error, "could not check pending dkg shares");
                        continue;
                    }

                    // This updates the signer state with the stacks chain tip.
                    if let Err(error) = self.process_stacks_blocks().await {
                        tracing::error!(%error, "could not process stacks blocks");
                        continue;
                    }

                    tracing::debug!("updating the signer state");
                    if let Err(error) = self.update_signer_state(chain_tip).await {
                        tracing::error!(%error, "could not update the signer state");
                        continue;
                    }

                    tracing::info!("loading latest deposit requests from Emily");
                    let deposits =
                        self.load_latest_deposit_requests(&chain_tip.block_hash, &mut intake);
                    if let Err(error) = deposits.await {
                        tracing::error!(%error, "could not load latest deposit requests from Emily");
                    }

                    self.context
                        .signal(SignerEvent::BitcoinBlockObserved(chain_tip).into())?;
                }
                Ok(Some(Err(error))) => {
                    tracing::error!(%error, "error decoding new bitcoin block hash from stream");
                    continue;
                }
                _ => continue,
            };
        }

        tracing::info!("block observer has stopped");

        Ok(())
    }
}

impl<C: Context, B> BlockObserver<C, B> {
    /// Fetches Emily deposit requests, validates the selection, and stores valid ones.
    #[tracing::instrument(skip_all)]
    async fn load_latest_deposit_requests(
        &self,
        chain_tip: &BitcoinBlockHash,
        intake: &mut DepositIntake,
    ) -> Result<(), Error> {
        let config = &self.context.config().signer;
        let fetch_start = Instant::now();
        let fetched = self.context.get_emily_client().get_deposits().await?;
        let fetch_elapsed = fetch_start.elapsed();
        let fetched_count = fetched.len();

        // Reversed: accepted before pending, each oldest first.
        let mut seen = HashSet::new();
        let requests: Vec<CreateDepositRequest> = fetched
            .into_iter()
            .rev()
            .filter(|request| seen.insert(request.outpoint))
            .collect();

        let known = self
            .context
            .get_storage()
            .get_confirmed_deposit_outpoints(chain_tip, config.context_window)
            .await?;

        let budget = usize::from(config.max_deposit_validations_per_block.get());
        let new_txids = intake.new_txids();
        let selection = intake.select(&requests, &known, &new_txids, budget);
        let selected: Vec<CreateDepositRequest> = selection.requests.into_iter().cloned().collect();

        let validate_start = Instant::now();
        let (outcomes, written_blocks) = self.validate_and_store(&selected).await?;
        let validate_elapsed = validate_start.elapsed();

        let count = |outcome| outcomes.iter().filter(|item| **item == outcome).count();
        let valid = count(ValidationOutcome::Valid);
        let unconfirmed = count(ValidationOutcome::Unconfirmed);
        let invalid = count(ValidationOutcome::Invalid);
        let errored = count(ValidationOutcome::Errored);
        intake.record(
            selected.iter().zip(outcomes),
            selection.cursor,
            written_blocks,
        );

        tracing::info!(
            fetched = fetched_count,
            known = selection.known,
            in_new_blocks = selection.in_new_blocks,
            validated = selected.len(),
            valid,
            unconfirmed,
            invalid,
            errored,
            deferred = selection.deferred,
            tracked = intake.entries.len(),
            fetch_ms = fetch_elapsed.as_millis(),
            validate_ms = validate_elapsed.as_millis(),
            "processed deposit requests from emily"
        );
        Ok(())
    }

    /// Validate the given deposit requests and store the ones that pass
    /// validation into the database.
    ///
    /// There are three types of errors that can happen during validation
    /// 1. The transaction fails primary validation. This means the deposit
    ///    script itself does not align with what we expect. If probably
    ///    does not follow our protocol.
    /// 2. The transaction passes step (1), but we don't recognize the
    ///    x-only public key in the deposit script.
    /// 3. We cannot find the associated transaction confirmed on a bitcoin
    ///    block, or when we encountered some unexpected error when
    ///    reaching out to bitcoin-core or our database.
    #[tracing::instrument(skip_all)]
    pub async fn load_requests(&self, requests: &[CreateDepositRequest]) -> Result<(), Error> {
        self.validate_and_store(requests).await.map(|_| ())
    }

    /// Like [`Self::load_requests`], also returns outcomes and written block txids.
    async fn validate_and_store(
        &self,
        requests: &[CreateDepositRequest],
    ) -> Result<(Vec<ValidationOutcome>, Vec<Vec<Txid>>), Error> {
        let mut outcomes = Vec::with_capacity(requests.len());
        let mut new_blocks = Vec::new();
        let mut deposit_requests = Vec::new();
        let mut deposit_request_txs = Vec::new();
        let bitcoin_client = self.context.get_bitcoin_client();
        let is_mainnet = self.context.config().signer.network.is_mainnet();

        for request in requests {
            let deposit = request
                .validate(&bitcoin_client, is_mainnet)
                .await
                .inspect_err(|error| tracing::warn!(%error, "could not validate deposit request"));

            // We log the error above, so we just need to extract the
            // deposit now.
            Metrics::increment_deposit_total(&deposit);
            outcomes.push(ValidationOutcome::new(&deposit));
            let Ok(Some(deposit)) = deposit else { continue };

            let blocks = self.process_bitcoin_blocks_until(deposit.block_hash);
            new_blocks.extend(blocks.await?);

            let tx = model::BitcoinTxRef {
                txid: deposit.tx_info.compute_txid().into(),
                block_hash: deposit.block_hash.into(),
            };

            deposit_requests.push(model::DepositRequest::from(deposit));
            deposit_request_txs.push(tx);
        }

        let db = self.context.get_storage_mut();
        db.write_bitcoin_transactions(deposit_request_txs).await?;
        db.write_deposit_requests(deposit_requests).await?;

        tracing::debug!("finished processing deposit requests");
        Ok((outcomes, new_blocks))
    }

    /// Set the sbtc start height, if it has not been set already.
    async fn set_sbtc_bitcoin_start_height(&self) -> Result<(), Error> {
        if self.context.state().is_sbtc_bitcoin_start_height_set() {
            return Ok(());
        }

        let nakamoto_start_height = self
            .context
            .get_stacks_client()
            .get_epoch_status()
            .await?
            .nakamoto_start_height();

        self.context
            .state()
            .set_sbtc_bitcoin_start_height(nakamoto_start_height);

        Ok(())
    }

    /// Find the parent blocks from the given block that are also missing
    /// from our database. The results are returned from blocks with the
    /// least height to the greatest height.
    ///
    /// # Notes
    ///
    /// This function does two things:
    /// 1. Set the `sbtc_bitcoin_start_height` if it has not been set already. If
    ///    it is not set, then we fetch the stacks nakamoto start height
    ///    from stacks-core and use that value.
    /// 2. Continually fetches block headers from bitcoin-core until it
    ///    encounters a known block header or if the height of the block is
    ///    less than or equal to the `sbtc_bitcoin_start_height`.
    ///
    /// If there are many unknown blocks then this function can take some
    /// time. Since each header is 80 bytes, we should be able to fetch
    /// headers for the entire bitcoin blockchain (~900k blocks at the time
    /// of writing) into memory.
    #[tracing::instrument(skip_all, fields(%block_hash))]
    pub async fn next_headers_to_process(
        &self,
        mut block_hash: BlockHash,
    ) -> Result<Vec<BitcoinBlockHeader>, Error> {
        self.set_sbtc_bitcoin_start_height().await?;

        let start_height = self.context.state().get_sbtc_bitcoin_start_height();
        let mut headers = std::collections::VecDeque::new();
        let db = self.context.get_storage();
        let bitcoin_client = self.context.get_bitcoin_client();

        while !db.is_known_bitcoin_block_hash(&block_hash.into()).await? {
            let Some(header) = bitcoin_client.get_block_header(&block_hash).await? else {
                tracing::error!(%block_hash, "bitcoin-core does not know about block header");
                return Err(Error::BitcoinCoreUnknownBlockHeader(block_hash));
            };

            // We don't even try to write blocks to the database if the
            // height is less than the start height.
            if header.height < start_height {
                break;
            }

            let at_start_height = header.height == start_height;
            block_hash = header.previous_block_hash;
            headers.push_front(header);

            // We can write the block at the start height to the database.
            if at_start_height {
                break;
            }
        }

        Ok(headers.into())
    }

    /// Process the bitcoin chain tip by fetching all unknown block headers
    /// from the given chain tip back until the nakamoto start height. Then
    /// mark all blocks reachable from the chain tip as canonical in the
    /// database.
    ///
    /// # Notes
    ///
    /// This function must only be called with the bitcoin chain tip since
    /// it updates all blocks that are reachable from the given block hash
    /// as canonical and may update blocks not reachable as non-canonical.
    ///
    /// Returns the txids from [`Self::process_bitcoin_blocks_until`].
    #[tracing::instrument(skip_all)]
    async fn process_bitcoin_chain_tip(
        &self,
        chain_tip: BlockHash,
    ) -> Result<Vec<Vec<Txid>>, Error> {
        let new_blocks = self.process_bitcoin_blocks_until(chain_tip).await?;

        let db = self.context.get_storage_mut();

        tracing::info!("updating canonical bitcoin blockchain to chain tip");
        let chain_tip: model::BitcoinBlockHash = chain_tip.into();

        // This is a safeguard to prevent us from updating the is_canonical
        // column of all blocks in the database if the given chain tip has
        // not been written to the database.
        if !db.is_known_bitcoin_block_hash(&chain_tip).await? {
            tracing::error!("chain tip not found in database, not setting is_canonical column");
            return Err(Error::UnknownBitcoinChainTip(chain_tip));
        }
        db.set_canonical_bitcoin_blockchain(&chain_tip).await?;
        Ok(new_blocks)
    }

    /// Process bitcoin blocks until we get caught up to the given
    /// `block_hash`.
    ///
    /// This function starts at the given block hash and:
    /// 1. Works backwards, fetching block headers until it fetches one
    ///    that is already in the database or reaches a block that is at or
    ///    below the `sbtc_bitcoin_start_height`.
    /// 2. Starts from the header associated with the block with the least
    ///    height and writes the blocks and sweep transactions into the
    ///    database.
    /// 3. Bails if an error is encountered when fetching block headers or
    ///    when processing blocks.
    ///
    /// This means that if we stop processing blocks midway though,
    /// subsequent calls to this function will properly pick up from where
    /// we left off and update the database.
    ///
    /// Returns the txids of the newest [`MAX_REORG_BLOCK_COUNT`] processed
    /// blocks, oldest first.
    async fn process_bitcoin_blocks_until(
        &self,
        block_hash: BlockHash,
    ) -> Result<Vec<Vec<Txid>>, Error> {
        let block_headers = self.next_headers_to_process(block_hash).await?;
        // Older blocks are a backfill, don't hash them.
        let skip = block_headers
            .len()
            .saturating_sub(MAX_REORG_BLOCK_COUNT as usize);
        let mut new_blocks = Vec::new();

        for (index, block_header) in block_headers.into_iter().enumerate() {
            let block = self.process_bitcoin_block(block_header).await?;
            if index >= skip {
                let txids = block.transactions.iter().map(BitcoinTxInfo::compute_txid);
                new_blocks.push(txids.collect());
            }
        }

        Ok(new_blocks)
    }

    /// Write the bitcoin block and any transactions that spend to any of
    /// the signers `scriptPubKey`s to the database, and return the block.
    #[tracing::instrument(skip_all, fields(block_hash = %block_header.hash))]
    async fn process_bitcoin_block(
        &self,
        block_header: BitcoinBlockHeader,
    ) -> Result<BitcoinBlockInfo, Error> {
        let block = self
            .context
            .get_bitcoin_client()
            .get_block(&block_header.hash)
            .await?
            .ok_or(Error::BitcoinCoreMissingBlock(block_header.hash))?;
        let db_block = model::BitcoinBlock::from(&block);

        let storage = self.context.get_storage_mut();

        // When a signer is not part of the bootstrap signing set but is
        // joining the set as a new signer, it will not have the signers
        // original scriptPubKey in its database, so it relies on the config
        // to inform them of what it is.
        let bootstrap_script_pubkey = self.context.config().signer.bootstrap_aggregate_key;

        // Begin a storage transaction.
        let storage_tx = storage.begin_transaction().await?;

        // Write the bitcoin block to the database (in the transaction).
        storage_tx.write_bitcoin_block(&db_block).await?;

        // Extract the sBTC-related transactions from the block and write them
        // to the database (within the transaction).
        extract_sbtc_transactions(
            &storage_tx,
            bootstrap_script_pubkey,
            block_header.hash,
            &block.transactions,
        )
        .await?;

        // Commit the storage transaction.
        storage_tx.commit().await?;

        tracing::debug!("finished processing bitcoin block");
        Ok(block)
    }

    /// Get a bitcoin block ref from a block hash.
    async fn resolve_block_ref(&self, chain_tip: BlockHash) -> Result<BitcoinBlockRef, Error> {
        self.context
            .get_storage()
            .get_bitcoin_block(&chain_tip.into())
            .await
            .inspect_err(|error| tracing::error!(%error, "could not get bitcoin chain tip"))?
            .map(model::BitcoinBlockRef::from)
            .ok_or_else(|| Error::UnknownBitcoinBlock(chain_tip))
            .inspect_err(|error| tracing::error!(%error, "could not get bitcoin chain tip"))
    }

    /// Process all recent stacks blocks.
    ///
    /// # Note
    ///
    /// This function updates the current stacks chain tip in the signer
    /// state.
    #[tracing::instrument(skip_all)]
    async fn process_stacks_blocks(&self) -> Result<(), Error> {
        tracing::info!("processing stacks block");
        let stacks_client = self.context.get_stacks_client();
        let db = self.context.get_storage_mut();
        let tenure_info = stacks_client.get_tenure_info().await?;

        let consensus_hash = tenure_info.consensus_hash;

        tracing::debug!("fetching unknown ancestral blocks from stacks-core");
        crate::stacks::api::update_db_with_unknown_ancestors(&stacks_client, &db, consensus_hash)
            .await?;

        tracing::debug!("finished processing stacks block");

        let stacks_chain_tip = StacksBlockRef {
            block_hash: tenure_info.tip_block_id,
            block_height: tenure_info.tip_height,
        };
        tracing::info!("updating the signer state with the current stacks chain tip");
        self.context.state().set_stacks_chain_tip(stacks_chain_tip);
        Ok(())
    }

    /// Update the sBTC peg limits from Emily
    async fn update_sbtc_limits(&self, chain_tip: BitcoinBlockHash) -> Result<(), Error> {
        let limits = self.context.get_emily_client().get_limits().await?;
        let sbtc_deployed = self.context.state().sbtc_contracts_deployed();

        let max_mintable = if limits.total_cap_exists() && sbtc_deployed {
            let sbtc_supply = self
                .context
                .get_stacks_client()
                .get_sbtc_total_supply(&self.context.config().signer.deployer)
                .await?;
            // The maximum amount of sBTC that can be minted is the total cap
            // minus the current supply.
            limits
                .total_cap()
                .checked_sub(sbtc_supply)
                .unwrap_or(Amount::ZERO)
        } else {
            Amount::MAX_MONEY
        };

        let rolling_limits = limits.rolling_withdrawal_limits();
        let withdrawn_total = self
            .context
            .get_storage()
            .compute_withdrawn_total(&chain_tip, rolling_limits.blocks)
            .await?;

        let limits = SbtcLimits::new(
            Some(limits.total_cap()),
            Some(limits.per_deposit_minimum()),
            Some(limits.per_deposit_cap()),
            Some(limits.per_withdrawal_cap()),
            Some(rolling_limits.blocks),
            Some(rolling_limits.cap),
            Some(withdrawn_total),
            Some(max_mintable),
        );
        let signer_state = self.context.state();
        if limits == signer_state.get_current_limits() {
            tracing::trace!(%limits, "sBTC limits have not changed");
        } else {
            tracing::debug!(%limits, "updated sBTC limits from Emily");
            signer_state.update_current_limits(limits);
        }
        Ok(())
    }

    /// Update the `SignerState` object with the current signer set,
    /// signatures required, and aggregate key data.
    ///
    /// # Notes
    ///
    /// The query used for fetching the cached information can take quite a
    /// lot of some time to complete on mainnet. So this function updates
    /// the signers state once so that the other event loops do not need to
    /// execute them. The cached information is the current signer set
    /// info. It gets this information from the last successful
    /// key-rotation contract call if it exists.
    async fn set_signer_set_info(&self) -> Result<(), Error> {
        let info = get_signer_set_info(&self.context).await?;

        let state = self.context.state();
        if let Some(info) = info {
            state.update_registry_signer_set_info(info);
        }

        Ok(())
    }

    /// Update the `SignerState` object with data that is unlikely to
    /// change until the arrival of the next bitcoin block.
    ///
    /// # Notes
    ///
    /// The function updates the following:
    /// * sBTC limits from Emily.
    /// * The current signer set.
    /// * The current aggregate key.
    /// * The current bitcoin chain tip.
    async fn update_signer_state(&self, chain_tip: BitcoinBlockRef) -> Result<(), Error> {
        tracing::info!("loading sbtc limits from Emily");
        self.update_sbtc_limits(chain_tip.block_hash).await?;

        tracing::info!("updating the signer state with the current signer set");
        self.set_signer_set_info().await?;

        tracing::info!("updating the signer state with the current bitcoin chain tip");
        self.context.state().set_bitcoin_chain_tip(chain_tip);
        Ok(())
    }

    /// Checks if the latest dkg share is pending and is no longer valid
    async fn check_pending_dkg_shares(&self, chain_tip: &BitcoinBlockRef) -> Result<(), Error> {
        let db = self.context.get_storage_mut();

        let last_dkg = db.get_latest_encrypted_dkg_shares().await?;

        if let Some(ref shares) = last_dkg {
            tracing::info!(
                aggregate_key = %shares.aggregate_key,
                status = ?shares.dkg_shares_status,
                "checking latest DKG shares"
            );
        }

        let Some(
            last_dkg @ EncryptedDkgShares {
                dkg_shares_status: model::DkgSharesStatus::Unverified,
                ..
            },
        ) = last_dkg
        else {
            return Ok(());
        };

        let verification_window = self.context.config().signer.dkg_verification_window;

        let max_verification_height = last_dkg
            .started_at_bitcoin_block_height
            .saturating_add(verification_window as u64);

        if max_verification_height < chain_tip.block_height {
            tracing::info!(
                aggregate_key = %last_dkg.aggregate_key,
                "latest DKG shares are unverified and the verification window expired, marking them as failed"
            );
            db.revoke_dkg_shares(last_dkg.aggregate_key).await?;
        }

        Ok(())
    }
}

/// Extract all BTC transactions from the block where one of the UTXOs
/// can be spent by the signers.
///
/// # Note
///
/// When using the postgres storage, we need to make sure that this
/// function is called after the `Self::write_bitcoin_block` function
/// because of the foreign key constraints.
pub async fn extract_sbtc_transactions<Storage>(
    db: &Storage,
    bootstrap_aggregate_key: Option<PublicKey>,
    block_hash: BlockHash,
    txs: &[BitcoinTxInfo],
) -> Result<(), Error>
where
    Storage: DbRead + DbWrite,
{
    // Convert the bootstrap script public key to a `ScriptBuf` if it is
    // provided. This is used to check if the transaction outputs are
    // spent to the bootstrap signers' addresses.
    let bootstrap_script_pubkey = bootstrap_aggregate_key.map(|key| key.signers_script_pubkey());

    // Define a closure to extract the sBTC transactions from the given
    // transactions and write them to the database.
    let extract_fut = || async {
        // We store all the scriptPubKeys associated with the signers'
        // aggregate public key.
        let signer_script_pubkeys: HashSet<ScriptBuf> = db
            .get_signers_script_pubkeys()
            .await?
            .into_iter()
            .map(ScriptBuf::from_bytes)
            .chain(bootstrap_script_pubkey.clone())
            .collect();

        // Look through all the UTXOs in the given transaction slice and
        // keep the transactions where a UTXO is locked with a
        // `scriptPubKey` controlled by the signers.
        let mut sbtc_txs = Vec::new();
        for tx_info in txs {
            let txid = tx_info.compute_txid();
            tracing::trace!(%txid, "attempting to extract sbtc transaction");
            if tx_info.tx.is_coinbase() {
                continue;
            }

            // Bail if bitcoin-core doesn't return all the data that we
            // care about for a non-coinbase transaction. This will happen
            // if bitcoin core hasn't computed the undo data for the block
            // with these transactions, of it there is a bug in bitcoin
            // core.
            tx_info.validate()?;

            // If any of the outputs are spent to one of the signers'
            // addresses, then we care about it
            let outputs_spent_to_signers = tx_info
                .tx
                .output
                .iter()
                .any(|tx_out| signer_script_pubkeys.contains(&tx_out.script_pubkey));

            // We might not know about the new scriptPubKey, but we are
            // supposed to know about all existing scriptPubKeys, so we
            // check the inputs as well.
            let inputs_spent_by_signers = tx_info
                .vin
                .iter()
                .filter_map(|vin| vin.prevout.as_ref())
                .any(|prevout| signer_script_pubkeys.contains(&prevout.script_pubkey.script));

            if !outputs_spent_to_signers && !inputs_spent_by_signers {
                continue;
            }

            sbtc_txs.push(model::BitcoinTxRef {
                txid: txid.into(),
                block_hash: block_hash.into(),
            });

            for prevout in tx_info.to_inputs(&signer_script_pubkeys) {
                db.write_tx_prevout(&prevout).await?;
                match prevout.prevout_type {
                    TxPrevoutType::Deposit => {
                        metrics::counter!(
                            Metrics::DepositsSweptTotal,
                            "blockchain" => BITCOIN_BLOCKCHAIN,
                        )
                        .increment(1);
                    }
                    TxPrevoutType::SignersInput => {
                        if let Some(key_set) = signer_key_set_from_signer_input(tx_info, &prevout) {
                            db.write_signer_key_set(&key_set).await?;
                        }
                    }
                }
            }

            let (tx_outputs, withdrawal_outputs) = tx_info.to_outputs(&signer_script_pubkeys)?;
            for output in tx_outputs {
                db.write_tx_output(&output).await?;
            }
            for output in withdrawal_outputs {
                db.write_withdrawal_tx_output(&output).await?;
            }
        }

        // Write these transactions into storage.
        db.write_bitcoin_transactions(sbtc_txs).await?;
        Ok(())
    };

    // The first time, we get all sweep transactions with inputs that
    // we know about. However, we could have locked the UTXO with a new
    // scriptPubKey, and we have no way of knowing that ahead of time.
    // The first pass over will populate the database with the new
    // scriptPubKeys.
    extract_fut().await?;

    // This will catch cases where the signers have locked up their
    // UTXO with a new scriptPubKey and there are a chain of
    // transactions in the block.
    extract_fut().await
}

/// Recover a v2 signer key set from a known signer input's witness.
///
/// The signers' input is always the first input in a signer-created sweep.
/// The reconstructed single-leaf scriptPubKey must match the classified
/// prevout before the key set is returned.
fn signer_key_set_from_signer_input(
    tx_info: &BitcoinTxInfo,
    prevout: &TxPrevout,
) -> Option<SignerKeySet> {
    if prevout.prevout_type != TxPrevoutType::SignersInput {
        return None;
    }
    let script = tx_info.tx.input.first()?.witness.tapscript()?;
    let key_set = sbtc::SignerKeySet::parse(script).ok()?;
    let script_pubkey = key_set.script_pubkey();
    (model::ScriptPubKey::from(script_pubkey) == prevout.script_pubkey).then_some(key_set.into())
}

/// Return the signing set that can make sBTC-related contract calls along
/// with the registry's current versioned key field.
///
/// Before v2 activation this field is the aggregate public key from DKG. A
/// v2 rotation stores an opaque Bitcoin block hash instead. If there are no
/// rotate-keys transactions on the canonical Stacks blockchain, this returns
/// `None`.
#[tracing::instrument(skip_all)]
pub async fn get_signer_set_info<C>(ctx: &C) -> Result<Option<SignerSetInfo>, Error>
where
    C: Context,
{
    let stacks = ctx.get_stacks_client();
    let address = &ctx.config().signer.deployer;
    // If the sBTC contracts have not been deployed, then we don't have any
    // signer set info in the registry.
    if !are_sbtc_contracts_deployed(ctx).await? {
        return Ok(None);
    }

    // This returns Ok(None) if API call returns a response with values
    // that are only set when we first deploy the sBTC contracts.
    stacks.get_current_signer_set_info(address).await
}

/// Check if all the sBTC smart contracts have been deployed.
async fn are_sbtc_contracts_deployed<C>(ctx: &C) -> Result<bool, Error>
where
    C: Context,
{
    // First check if we already know if the contracts have been deployed.
    // If we get false, then it could be that we are just starting the
    // application, so we'll need to check our node.
    if ctx.state().sbtc_contracts_deployed() {
        return Ok(true);
    }

    let stacks = ctx.get_stacks_client();
    let deployer = &ctx.config().signer.deployer;

    for contract in SMART_CONTRACTS {
        if !contract.is_deployed(&stacks, deployer).await? {
            return Ok(false);
        }
    }

    // If we get here, then all the smart contracts have been deployed.
    // Let's store that fact so that we don't need to query our Stacks node
    // again.
    ctx.state().set_sbtc_contracts_deployed();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::num::NonZeroU16;
    use std::sync::Arc;
    use std::sync::Mutex;

    use bitcoin::Amount;
    use bitcoin::BlockHash;
    use bitcoin::OutPoint;
    use bitcoin::Sequence;
    use bitcoin::Transaction;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::Witness;
    use bitcoin::absolute;
    use bitcoin::taproot::LeafVersion;
    use bitcoin::transaction;
    use fake::Dummy as _;
    use fake::Fake as _;
    use fake::Faker;
    use model::BitcoinTxId;
    use model::ScriptPubKey;

    use crate::bitcoin::rpc::GetTxResponse;
    use crate::bitcoin::rpc::OutPointSummary;
    use crate::context::SignerSignal;
    use crate::keys::PublicKey;
    use crate::storage;
    use crate::storage::memory::SharedStore;
    use crate::storage::model::BitcoinBlockHash;
    use crate::storage::model::DkgSharesStatus;
    use crate::testing::block_observer::TestHarness;
    use crate::testing::context::*;
    use crate::testing::get_rng;
    use clarity::vm::types::PrincipalData;
    use stacks_common::types::chainstate::StacksAddress;

    use super::*;

    #[test]
    fn recovers_v2_key_set_only_from_a_known_signer_input() {
        let mut rng = get_rng();
        let public_keys = (0..3)
            .map(|_| {
                secp256k1::SECP256K1
                    .generate_keypair(&mut rng)
                    .1
                    .x_only_public_key()
                    .0
            })
            .collect::<BTreeSet<_>>();
        let key_set = sbtc::SignerKeySet::new(public_keys, 2).unwrap();
        let signing_script = key_set.signing_script();
        let control_block = key_set
            .taproot()
            .control_block(&(signing_script.clone(), LeafVersion::TapScript))
            .unwrap();
        let witness = Witness::from_slice(&[signing_script.to_bytes(), control_block.serialize()]);
        let tx_info = BitcoinTxInfo {
            fee: None,
            tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness,
                }],
                output: Vec::new(),
            },
            vin: vec![crate::bitcoin::rpc::BitcoinTxVin {
                txid: Some(bitcoin::Txid::all_zeros()),
                vout: Some(u32::MAX),
                prevout: Some(crate::bitcoin::rpc::BitcoinTxVinPrevout {
                    value: Amount::from_sat(1_000),
                    script_pubkey: crate::bitcoin::rpc::OutputScriptPubKey {
                        script: key_set.script_pubkey(),
                    },
                }),
            }],
        };

        let signer_input = tx_info
            .to_inputs(&HashSet::from([key_set.script_pubkey()]))
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(
            signer_key_set_from_signer_input(&tx_info, &signer_input),
            Some(key_set.into())
        );

        let mut deposit_input = signer_input.clone();
        deposit_input.prevout_type = TxPrevoutType::Deposit;
        assert!(signer_key_set_from_signer_input(&tx_info, &deposit_input).is_none());

        let mut mismatched_input = signer_input;
        mismatched_input.script_pubkey = ScriptBuf::new().into();
        assert!(signer_key_set_from_signer_input(&tx_info, &mismatched_input).is_none());
    }

    #[test_log::test(tokio::test)]
    async fn should_be_able_to_extract_bitcoin_blocks_given_a_block_header_stream() {
        let mut rng = get_rng();
        let storage = storage::memory::Store::new_shared();
        let test_harness = TestHarness::generate(&mut rng, 20, 0..5);
        let min_height = test_harness.min_block_height();
        let ctx = TestContext::builder()
            .with_storage(storage.clone())
            .with_stacks_client(test_harness.clone())
            .with_emily_client(test_harness.clone())
            .with_bitcoin_client(test_harness.clone())
            .modify_settings(|settings| settings.signer.sbtc_bitcoin_start_height = min_height)
            .build();

        // There must be at least one signal receiver alive when the block observer
        // later tries to send a signal, hence this line.
        let _signal_rx = ctx.get_signal_receiver();

        let block_observer = BlockObserver {
            context: ctx.clone(),
            bitcoin_block_source: test_harness.clone(),
        };

        // Let's get the bitcoin chain tip so that we know when to stop
        // waiting for the block observers signal.
        let chain_tip: BitcoinBlockHash = test_harness
            .bitcoin_blocks()
            .iter()
            .max_by_key(|block| block.height)
            .unwrap()
            .block_hash
            .into();

        let handle = tokio::spawn(block_observer.run());
        // Because of how the test is setup, the first few observed bitcoin
        // blocks end with the block observer failing to signal because we
        // cannot get the stacks chain tip. This isn't a bug because the
        // response from get_tenure_headers is always anchored to the chain
        // tip, while the block stream send blocks in ascending order
        // making the stacks blocks appear to not be part of the canonical
        // chain, when in reality they are all just anchored to a block
        // that is ahead of the bitcoin block being processed.
        ctx.wait_for_signal(Duration::from_secs(3), |signal| {
            matches!(
                signal,
                SignerSignal::Event(SignerEvent::BitcoinBlockObserved(block_ref))
                    if block_ref.block_hash == chain_tip
            )
        })
        .await
        .expect("block observer failed to complete within timeout");

        for block in test_harness.bitcoin_blocks() {
            let persisted = storage
                .get_bitcoin_block(&block.block_hash.into())
                .await
                .expect("storage error")
                .expect("block wasn't persisted");

            assert_eq!(persisted.block_hash, block.block_hash.into())
        }

        handle.abort();
    }

    /// Test that `BlockObserver::load_latest_deposit_requests` takes
    /// deposits from emily, validates them and only keeps the ones that
    /// pass validation and have been confirmed.
    #[tokio::test]
    async fn validated_confirmed_deposits_get_added_to_state() {
        let mut rng = get_rng();
        let mut test_harness = TestHarness::generate(&mut rng, 20, 0..5);
        // We want the test harness to fetch a block from our
        // "bitcoin-core", which in this case is the test harness. So we
        // use a block hash that the test harness knows about.
        let block_hash = test_harness
            .bitcoin_blocks()
            .first()
            .map(|block| block.block_hash);

        let lock_time = 150;
        let max_fee = i64::MAX as u64;
        let amount = 500_000;

        // We're going to create two deposit requests, the first one valid
        // and the second one invalid. Emily will return both the valid and
        // invalid requests (even though it should've validated them) and
        // BitcoinClient will return the right transaction for both of
        // them.
        let tx_setup0 = sbtc::testing::deposits::tx_setup(lock_time, max_fee, &[amount]);
        let deposit_request0 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup0.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: tx_setup0.deposits.first().unwrap().deposit_script(),
            reclaim_script: tx_setup0.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };
        let req0 = deposit_request0.clone();
        // When we validate the deposit request, we fetch the transaction
        // from bitcoin-core's blockchain. The stubs out that response.
        let get_tx_resp0 = GetTxResponse {
            tx: tx_setup0.tx.clone(),
            block_hash,
            confirmations: None,
            block_time: None,
        };

        let tx_setup1 = sbtc::testing::deposits::tx_setup(300, 2000, &[amount]);
        // This one is an invalid deposit request because the deposit
        // script is wrong
        let deposit_request1 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup1.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: bitcoin::ScriptBuf::new(),
            reclaim_script: tx_setup1.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };
        // The transaction is also in the mempool, even though it is an
        // invalid deposit.
        let get_tx_resp1 = GetTxResponse {
            tx: tx_setup1.tx.clone(),
            block_hash: None,
            confirmations: None,
            block_time: None,
        };

        // This deposit transaction is a fine deposit, it just hasn't been
        // confirmed yet.
        let tx_setup2 = sbtc::testing::deposits::tx_setup(400, 3000, &[amount]);
        let get_tx_resp2 = GetTxResponse {
            tx: tx_setup2.tx.clone(),
            block_hash: None,
            confirmations: None,
            block_time: None,
        };

        let deposit_request2 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup2.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: tx_setup2.deposits.first().unwrap().deposit_script(),
            reclaim_script: tx_setup2.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };

        // This deposit transaction is a fine deposit, it just hasn't been
        // confirmed yet.
        let max_fee = u64::MAX;
        let tx_setup3 = sbtc::testing::deposits::tx_setup(400, max_fee, &[amount]);
        let get_tx_resp3 = GetTxResponse {
            tx: tx_setup3.tx.clone(),
            block_hash,
            confirmations: None,
            block_time: None,
        };

        let deposit_request3 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup3.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: tx_setup3.deposits.first().unwrap().deposit_script(),
            reclaim_script: tx_setup3.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };
        let req3 = deposit_request3.clone();

        // Let's add the "responses" to the field that feeds the
        // response to the `BitcoinClient::get_tx` call.
        test_harness.add_deposits(&[
            (get_tx_resp0.tx.compute_txid(), get_tx_resp0),
            (get_tx_resp1.tx.compute_txid(), get_tx_resp1),
            (get_tx_resp2.tx.compute_txid(), get_tx_resp2),
            (get_tx_resp3.tx.compute_txid(), get_tx_resp3),
        ]);

        // Add the deposit requests to the pending deposits which
        // would be returned by Emily.
        let requests = [
            deposit_request0,
            deposit_request1,
            deposit_request2,
            deposit_request3,
        ];
        test_harness.add_pending_deposits(&requests);
        let min_height = test_harness.min_block_height();

        // Now we finish setting up the block observer.
        let storage = storage::memory::Store::new_shared();
        let ctx = TestContext::builder()
            .with_storage(storage.clone())
            .with_stacks_client(test_harness.clone())
            .with_emily_client(test_harness.clone())
            .with_bitcoin_client(test_harness.clone())
            .modify_settings(|settings| settings.signer.sbtc_bitcoin_start_height = min_height)
            .build();

        let block_observer = BlockObserver {
            context: ctx,
            bitcoin_block_source: (),
        };

        {
            let db = storage.lock().await;
            assert_eq!(db.deposit_requests.len(), 0);
        }

        let chain_tip = BitcoinBlockHash::from(block_hash.unwrap());
        let mut intake = DepositIntake::new(DEPOSIT_INTAKE_CAPACITY);
        block_observer
            .load_latest_deposit_requests(&chain_tip, &mut intake)
            .await
            .unwrap();
        // Only the transactions from tx_setup0 and tx_setup3 were valid.
        // Note that, since we are not using a real block hash stored in
        // the database. Our DbRead function won't actually find it. And in
        // prod we won't actually store the deposit request transaction.
        let (deposit0, deposit3) = {
            let db = storage.lock().await;
            assert_eq!(db.deposit_requests.len(), 2);
            let mut values = db.deposit_requests.values().cloned().collect::<Vec<_>>();
            values.sort_by_key(|req| req.max_fee);
            values.reverse();
            (values.pop().unwrap(), values.pop().unwrap())
        };

        assert_eq!(deposit0.outpoint(), req0.outpoint);
        assert_eq!(deposit0.max_fee, i64::MAX as u64);
        assert_eq!(deposit3.outpoint(), req3.outpoint);
        assert_eq!(deposit3.max_fee, u64::MAX);
    }

    /// Test that `BlockObserver::extract_deposit_requests` after
    /// `BlockObserver::load_latest_deposit_requests` stores validated
    /// deposit requests into "storage".
    #[tokio::test]
    async fn extract_deposit_requests_stores_validated_deposits() {
        let mut rng = get_rng();
        let mut test_harness = TestHarness::generate(&mut rng, 20, 0..5);

        // We want the test harness to fetch a block from our
        // "bitcoin-core", which in this case is the test harness. So we
        // use a block hash that the test harness knows about.
        let block_hash = test_harness
            .bitcoin_blocks()
            .first()
            .map(|block| block.block_hash);
        let lock_time = 150;
        let max_fee = 32000;
        let amount = 500_000;

        // We're going to create two deposit requests, the first one valid
        // and the second one invalid. Emily will return both the valid and
        // invalid requests (even though it should've validated them) and
        // BitcoinClient will return the right transaction for both of
        // them.
        let tx_setup0 = sbtc::testing::deposits::tx_setup(lock_time, max_fee, &[amount]);
        let deposit_request0 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup0.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: tx_setup0.deposits.first().unwrap().deposit_script(),
            reclaim_script: tx_setup0.reclaims.first().unwrap().reclaim_script(),
            recipient: None,
            max_fee: None,
        };
        // When we validate the deposit request, we fetch the transaction
        // from bitcoin-core's blockchain. The stubs out that
        // response.
        let get_tx_resp0 = GetTxResponse {
            tx: tx_setup0.tx.clone(),
            block_hash,
            confirmations: None,
            block_time: None,
        };

        // Let's add the "responses" to the field that feeds the
        // response to the `BitcoinClient::get_tx` call.
        test_harness.add_deposit(get_tx_resp0.tx.compute_txid(), get_tx_resp0);
        // Add the deposit request to the pending deposits which
        // would be returned by Emily.
        test_harness.add_pending_deposit(deposit_request0);

        let min_height = test_harness.min_block_height();
        // Now we finish setting up the block observer.
        let storage = storage::memory::Store::new_shared();
        let ctx = TestContext::builder()
            .with_storage(storage.clone())
            .with_stacks_client(test_harness.clone())
            .with_emily_client(test_harness.clone())
            .with_bitcoin_client(test_harness.clone())
            .modify_settings(|settings| settings.signer.sbtc_bitcoin_start_height = min_height)
            .build();

        let block_observer = BlockObserver {
            context: ctx,
            bitcoin_block_source: (),
        };

        let chain_tip = BitcoinBlockHash::from(block_hash.unwrap());
        let mut intake = DepositIntake::new(DEPOSIT_INTAKE_CAPACITY);
        block_observer
            .load_latest_deposit_requests(&chain_tip, &mut intake)
            .await
            .unwrap();

        let storage = storage.lock().await;
        assert_eq!(storage.deposit_requests.len(), 1);
        let db_outpoint: (BitcoinTxId, u32) = (tx_setup0.tx.compute_txid().into(), 0);
        assert!(storage.deposit_requests.contains_key(&db_outpoint));

        assert!(
            storage
                .bitcoin_transactions_to_blocks
                .contains_key(&db_outpoint.0)
        );
    }

    /// Test that `BlockObserver::extract_sbtc_transactions` takes the
    /// stored signer `scriptPubKey`s and stores all transactions from a
    /// bitcoin block that match one of those `scriptPubkey`s.
    #[tokio::test]
    async fn sbtc_transactions_get_stored() {
        let mut rng = get_rng();
        let mut test_harness = TestHarness::generate(&mut rng, 20, 0..5);

        let block_hash = BlockHash::from_byte_array([1u8; 32]);
        // We're going to do the following:
        // 1. pretend that the below bytes represent the signers
        //    `scriptPubKey`. We store it in our datastore along with some
        //    "DKG shares".
        // 2. We then create two transactions, one spending to our
        //    scriptPubKey and another not spending to it.
        // 3. We try "extracting" a block with one transaction that does
        //    not spend to the signers. This one transaction should not be
        //    extracted (we should not see it in storage).
        // 4. We try "extracting" a block with two transactions where one
        //    of them spends to the signers. The one transaction should be
        //    stored in our storage.
        let signers_script_pubkey: ScriptPubKey = fake::Faker.fake_with_rng(&mut rng);

        // We start by storing our `scriptPubKey`.
        let storage = storage::memory::Store::new_shared();
        let aggregate_key = PublicKey::dummy_with_rng(&fake::Faker, &mut rng);
        let shares = model::EncryptedDkgShares {
            aggregate_key,
            tweaked_aggregate_key: aggregate_key.signers_tweaked_pubkey().unwrap(),
            script_pubkey: signers_script_pubkey.clone(),
            encrypted_private_shares: Vec::new(),
            public_shares: Vec::new(),
            signer_set_public_keys: vec![aggregate_key],
            signature_share_threshold: 1,
            dkg_shares_status: DkgSharesStatus::Unverified,
            started_at_bitcoin_block_hash: block_hash.into(),
            started_at_bitcoin_block_height: 1u64.into(),
        };
        storage.write_encrypted_dkg_shares(&shares).await.unwrap();

        // Now let's create two transactions, one spending to the signers
        // and another not spending to the signers. We use
        // sbtc::testing::deposits::tx_setup just to quickly create a
        // transaction; any one will do since we will be adding the UTXO
        // that spends to the signer afterward.
        let mut tx_setup0 = sbtc::testing::deposits::tx_setup(0, 0, &[100]);
        tx_setup0.tx.output.push(TxOut {
            value: Amount::ONE_BTC,
            script_pubkey: signers_script_pubkey.into(),
        });

        // This one does not spend to the signers :(
        let tx_setup1 = sbtc::testing::deposits::tx_setup(1, 10, &[2000]);
        let txid0 = tx_setup0.tx.compute_txid();
        let txid1 = tx_setup1.tx.compute_txid();

        let response0 = GetTxResponse {
            tx: tx_setup0.tx.clone(),
            block_hash: Some(block_hash),
            confirmations: None,
            block_time: None,
        };
        let response1 = GetTxResponse {
            tx: tx_setup1.tx.clone(),
            block_hash: Some(block_hash),
            confirmations: None,
            block_time: None,
        };
        test_harness.add_deposit(txid0, response0);
        test_harness.add_deposit(txid1, response1);

        // First we try extracting the transactions from a block that does
        // not contain any transactions spent to the signers
        let txs = [tx_setup1.tx.fake_with_rng(&mut rng)];
        extract_sbtc_transactions(&storage, None, block_hash, &txs)
            .await
            .unwrap();

        // We need to change the scope so that the mutex guard is dropped.
        {
            let store = storage.lock().await;
            // Under the hood, bitcoin transactions get stored in the
            // `bitcoin_block_to_transactions` field, so lets check there
            let stored_transactions = store.bitcoin_block_to_transactions.get(&block_hash.into());

            // Nothing should be stored so the map get call should return
            // None.
            assert!(stored_transactions.is_none());
        }

        // Now we try again, but we include the transaction that spends to
        // the signer. This one should turn out differently.
        let txs = [
            tx_setup0.tx.fake_with_rng(&mut rng),
            tx_setup1.tx.fake_with_rng(&mut rng),
        ];
        extract_sbtc_transactions(&storage, None, block_hash, &txs)
            .await
            .unwrap();

        let store = storage.lock().await;
        let stored_transactions = store.bitcoin_block_to_transactions.get(&block_hash.into());

        // Is our one transaction stored? This block hash should now have
        // only one transaction with the expected txid.
        let tx_ids = stored_transactions.unwrap();
        let expected_tx_id = tx_setup0.tx.compute_txid().into();
        assert_eq!(tx_ids.len(), 1);
        assert!(tx_ids.contains(&expected_tx_id));
    }

    /// Fake bitcoin-core for intake tests.
    #[derive(Default)]
    struct FakeBitcoinCore {
        /// Unspent deposit transactions and the blocks confirming them.
        confirmed: HashMap<Txid, (BitcoinTxInfo, BlockHash)>,
        /// Outpoints whose lookup fails.
        failing: HashSet<OutPoint>,
        /// Outpoints that are coinbase outputs.
        coinbase: HashSet<OutPoint>,
        /// Every outpoint looked up, in order.
        probes: Vec<OutPoint>,
        /// Blocks that are not in the database yet.
        blocks: HashMap<BlockHash, BitcoinBlockInfo>,
    }

    type MockedContext = TestContext<
        SharedStore,
        WrappedMockBitcoinInteract,
        WrappedMockStacksInteract,
        WrappedMockEmilyInteract,
    >;

    /// Runs intakes against mocked Emily and bitcoin-core on a stored chain.
    struct IntakeHarness {
        observer: BlockObserver<MockedContext, ()>,
        bitcoin: Arc<Mutex<FakeBitcoinCore>>,
        /// What Emily returns, newest first.
        emily: Arc<Mutex<Vec<CreateDepositRequest>>>,
        /// Whether Emily fails to return deposits.
        emily_fails: Arc<Mutex<bool>>,
        blocks: Vec<model::BitcoinBlock>,
        chain_tip: BitcoinBlockHash,
        intake: DepositIntake,
    }

    impl IntakeHarness {
        async fn new(budget: u16, capacity: usize) -> Self {
            Self::with_context_window(budget, capacity, 1000).await
        }

        async fn with_context_window(budget: u16, capacity: usize, context_window: u16) -> Self {
            let mut rng = get_rng();
            let ctx = TestContext::builder()
                .with_in_memory_storage()
                .with_mocked_clients()
                .modify_settings(|settings| {
                    settings.signer.sbtc_bitcoin_start_height = Some(0u64.into());
                    settings.signer.context_window = context_window;
                    settings.signer.max_deposit_validations_per_block =
                        NonZeroU16::new(budget).unwrap();
                })
                .build();

            let mut blocks: Vec<model::BitcoinBlock> = Vec::new();
            for height in 0..5u64 {
                let mut block: model::BitcoinBlock = Faker.fake_with_rng(&mut rng);
                block.block_height = height.into();
                if let Some(parent) = blocks.last() {
                    block.parent_hash = parent.block_hash;
                }
                ctx.get_storage_mut()
                    .write_bitcoin_block(&block)
                    .await
                    .unwrap();
                blocks.push(block);
            }

            let bitcoin = Arc::new(Mutex::new(FakeBitcoinCore::default()));
            let emily = Arc::new(Mutex::new(Vec::new()));

            let fake = bitcoin.clone();
            ctx.with_bitcoin_client(|client| {
                let fake_utxo = fake.clone();
                client.expect_get_utxo_info().returning(move |outpoint| {
                    let mut fake = fake_utxo.lock().unwrap();
                    fake.probes.push(*outpoint);
                    let response = if fake.failing.contains(outpoint) {
                        Err(Error::BitcoinTxMissingData(outpoint.txid))
                    } else {
                        let confirmed = fake.confirmed.get(&outpoint.txid);
                        Ok(confirmed.map(|(_, block_hash)| OutPointSummary {
                            block_hash: *block_hash,
                            is_coinbase: fake.coinbase.contains(outpoint),
                        }))
                    };
                    Box::pin(std::future::ready(response))
                });
                let fake_headers = fake.clone();
                client
                    .expect_get_block_header()
                    .returning(move |block_hash| {
                        let fake = fake_headers.lock().unwrap();
                        let header = fake.blocks.get(block_hash).map(|block| BitcoinBlockHeader {
                            hash: block.block_hash,
                            height: block.height,
                            time: block.time,
                            previous_block_hash: block.previous_block_hash,
                        });
                        Box::pin(std::future::ready(Ok(header)))
                    });
                let fake_blocks = fake.clone();
                client.expect_get_block().returning(move |block_hash| {
                    let block = fake_blocks.lock().unwrap().blocks.get(block_hash).cloned();
                    Box::pin(std::future::ready(Ok(block)))
                });
                client.expect_get_tx_info().returning(move |txid, _| {
                    let tx_info = fake.lock().unwrap().confirmed.get(txid).cloned();
                    Box::pin(std::future::ready(Ok(tx_info.map(|(tx_info, _)| tx_info))))
                });
            })
            .await;

            let emily_fails = Arc::new(Mutex::new(false));
            let listed = emily.clone();
            let fails = emily_fails.clone();
            ctx.with_emily_client(|client| {
                client.expect_get_deposits().returning(move || {
                    let response = if *fails.lock().unwrap() {
                        Err(Error::InvalidSignerState)
                    } else {
                        Ok(listed.lock().unwrap().clone())
                    };
                    Box::pin(std::future::ready(response))
                });
            })
            .await;

            let chain_tip = blocks.last().unwrap().block_hash;
            Self {
                observer: BlockObserver {
                    context: ctx,
                    bitcoin_block_source: (),
                },
                bitcoin,
                emily,
                emily_fails,
                blocks,
                chain_tip,
                intake: DepositIntake::new(NonZeroUsize::new(capacity).unwrap()),
            }
        }

        /// Have Emily list this request as the newest one.
        fn list(&self, request: &CreateDepositRequest) {
            self.emily.lock().unwrap().insert(0, request.clone());
        }

        /// Confirm the deposit transaction in the chain tip block.
        fn confirm(&self, deposit: &(CreateDepositRequest, BitcoinTxInfo)) {
            self.confirm_in(deposit, self.chain_tip);
        }

        fn confirm_in(
            &self,
            (request, tx_info): &(CreateDepositRequest, BitcoinTxInfo),
            block_hash: BitcoinBlockHash,
        ) {
            let mut fake = self.bitcoin.lock().unwrap();
            fake.confirmed
                .insert(request.outpoint.txid, (tx_info.clone(), block_hash.into()));
        }

        /// A block after the tip that bitcoin-core knows but isn't stored.
        fn add_next_block(&self, transactions: &[&BitcoinTxInfo]) -> BitcoinBlockHash {
            let tip = self.blocks.last().unwrap();
            let mut rng = get_rng();
            let mut block = BitcoinBlockInfo::random_with_height(tip.block_height + 1, &mut rng);
            block.previous_block_hash = tip.block_hash.into();
            block
                .transactions
                .extend(transactions.iter().map(|&tx_info| tx_info.clone()));
            let block_hash = block.block_hash;
            let mut fake = self.bitcoin.lock().unwrap();
            fake.blocks.insert(block_hash, block);
            block_hash.into()
        }

        /// Runs an intake, after a block with `new_txids` unless it's empty;
        /// returns the probes.
        async fn intake(&mut self, new_txids: &[Txid]) -> Vec<OutPoint> {
            self.try_intake(new_txids).await.unwrap()
        }

        async fn try_intake(&mut self, new_txids: &[Txid]) -> Result<Vec<OutPoint>, Error> {
            if !new_txids.is_empty() {
                self.intake.add_new_blocks([new_txids.to_vec()]);
            }
            let result = self
                .observer
                .load_latest_deposit_requests(&self.chain_tip, &mut self.intake)
                .await;
            let probes = std::mem::take(&mut self.bitcoin.lock().unwrap().probes);
            result.map(|()| probes)
        }

        async fn is_stored(&self, request: &CreateDepositRequest) -> bool {
            let txid = request.outpoint.txid.into();
            let storage = self.observer.context.get_storage();
            storage
                .deposit_request_exists(&txid, request.outpoint.vout)
                .await
                .unwrap()
        }
    }

    fn tx_info(tx: Transaction) -> BitcoinTxInfo {
        BitcoinTxInfo {
            fee: Some(Amount::from_sat(1_000)),
            tx,
            vin: Vec::new(),
        }
    }

    /// A v1 deposit request and the transaction it points to.
    fn v1_deposit() -> (CreateDepositRequest, BitcoinTxInfo) {
        let setup = sbtc::testing::deposits::tx_setup(150, 10_000, &[500_000]);
        let request = CreateDepositRequest {
            outpoint: OutPoint::new(setup.tx.compute_txid(), 0),
            deposit_script: setup.deposits[0].deposit_script(),
            reclaim_script: setup.reclaims[0].reclaim_script(),
            recipient: None,
            max_fee: None,
        };
        (request, tx_info(setup.tx))
    }

    /// A v2 deposit request and the transaction it points to.
    fn v2_deposit(max_fee: u64) -> (CreateDepositRequest, BitcoinTxInfo) {
        let mut rng = get_rng();
        let recipient = PrincipalData::from(StacksAddress::burn_address(false));
        let public_keys = (0..3)
            .map(|_| {
                let (_, public_key) = secp256k1::SECP256K1.generate_keypair(&mut rng);
                public_key.x_only_public_key().0
            })
            .collect::<BTreeSet<_>>();
        let deposit =
            sbtc::deposits::DepositScriptInputsV2::new(public_keys, 2, recipient.clone(), max_fee)
                .unwrap();
        let reclaim = sbtc::deposits::ReclaimScriptInputs::try_new(150, ScriptBuf::new()).unwrap();
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(500_000),
                script_pubkey: sbtc::deposits::to_v2_script_pubkey(
                    deposit.deposit_script(),
                    reclaim.reclaim_script(),
                ),
            }],
        };
        let request = CreateDepositRequest {
            outpoint: OutPoint::new(tx.compute_txid(), 0),
            deposit_script: deposit.deposit_script(),
            reclaim_script: reclaim.reclaim_script(),
            recipient: Some(recipient),
            max_fee: Some(max_fee),
        };
        (request, tx_info(tx))
    }

    /// At most `budget` validations per intake; stored deposits aren't redone.
    #[tokio::test]
    async fn deposit_intake_validates_at_most_the_budget_per_block() {
        let mut harness = IntakeHarness::new(3, 100).await;
        let deposits: Vec<_> = (0..10).map(|_| v1_deposit()).collect();
        for deposit in &deposits {
            harness.confirm(deposit);
            harness.list(&deposit.0);
        }

        // Past the re-probe interval, so only the known filter skips them.
        let mut probes = Vec::new();
        for _ in 0..DEPOSIT_REPROBE_INTERVAL + 4 {
            probes.push(harness.intake(&[]).await.len());
        }

        assert_eq!(probes, [3, 3, 3, 1, 0, 0, 0, 0, 0, 0]);
        for (request, _) in &deposits {
            assert!(harness.is_stored(request).await);
        }
    }

    /// Oldest first, each once before any twice; unconfirmed ones wait.
    #[tokio::test]
    async fn deposit_intake_tries_every_request_before_retrying_any() {
        let mut harness = IntakeHarness::new(2, 100).await;
        let unconfirmed: Vec<_> = (0..5).map(|_| v1_deposit().0).collect();
        for request in &unconfirmed {
            harness.list(request);
        }
        let deposit = v1_deposit();
        harness.confirm(&deposit);
        harness.list(&deposit.0);

        let outpoints = |requests: &[&CreateDepositRequest]| -> Vec<OutPoint> {
            requests.iter().map(|request| request.outpoint).collect()
        };
        let [u0, u1, u2, u3, u4] = [0, 1, 2, 3, 4].map(|index| &unconfirmed[index]);

        assert_eq!(harness.intake(&[]).await, outpoints(&[u0, u1]));
        assert_eq!(harness.intake(&[]).await, outpoints(&[u2, u3]));
        assert_eq!(harness.intake(&[]).await, outpoints(&[u4, &deposit.0]));
        assert!(harness.is_stored(&deposit.0).await);

        // u0 and u1 come due in intake `DEPOSIT_REPROBE_INTERVAL`.
        for _ in 3..DEPOSIT_REPROBE_INTERVAL {
            assert!(harness.intake(&[]).await.is_empty());
        }
        assert_eq!(harness.intake(&[]).await, outpoints(&[u0, u1]));
        assert_eq!(harness.intake(&[]).await, outpoints(&[u2, u3]));
    }

    /// A reorged-out deposit is validated again and linked to its new block.
    #[tokio::test]
    async fn deposit_intake_relinks_deposits_after_a_reorg() {
        let mut harness = IntakeHarness::new(10, 100).await;
        let deposit = v1_deposit();
        harness.confirm(&deposit);
        harness.list(&deposit.0);

        assert_eq!(harness.intake(&[]).await.len(), 1);
        assert!(harness.intake(&[]).await.is_empty());

        // A sibling tip that also confirms the deposit.
        let mut rng = get_rng();
        let parent = &harness.blocks[3];
        let mut fork: model::BitcoinBlock = Faker.fake_with_rng(&mut rng);
        fork.block_height = parent.block_height + 1;
        fork.parent_hash = parent.block_hash;
        let storage = harness.observer.context.get_storage_mut();
        storage.write_bitcoin_block(&fork).await.unwrap();
        harness.chain_tip = fork.block_hash;
        harness.confirm(&deposit);

        let new_txids = [deposit.0.outpoint.txid];
        assert_eq!(harness.intake(&new_txids).await, [deposit.0.outpoint]);

        let signer_public_key: PublicKey = Faker.fake_with_rng(&mut rng);
        let pending = storage
            .get_pending_deposit_requests(&fork.block_hash, 100, &signer_public_key)
            .await
            .unwrap();
        let outpoints: Vec<_> = pending
            .iter()
            .map(model::DepositRequest::outpoint)
            .collect();
        assert_eq!(outpoints, [deposit.0.outpoint]);
    }

    /// A failed request is skipped until Emily returns different contents.
    #[tokio::test]
    async fn deposit_intake_skips_failed_requests_until_their_contents_change() {
        let mut harness = IntakeHarness::new(1, 100).await;
        let deposit = v2_deposit(25_000);
        harness.confirm(&deposit);
        // An Emily without v2 fields doesn't return the max fee.
        let mut without_max_fee = deposit.0.clone();
        without_max_fee.max_fee = None;
        harness.list(&without_max_fee);
        for _ in 0..3 {
            harness.list(&v1_deposit().0);
        }

        assert_eq!(harness.intake(&[]).await, [deposit.0.outpoint]);
        let probes = harness.intake(&[]).await;
        assert!(!probes.contains(&deposit.0.outpoint));
        assert!(!harness.is_stored(&deposit.0).await);

        // With the max fee it goes ahead of the newer requests.
        *harness.emily.lock().unwrap().last_mut().unwrap() = deposit.0.clone();

        assert_eq!(harness.intake(&[]).await, [deposit.0.outpoint]);
        assert!(harness.is_stored(&deposit.0).await);
    }

    /// A transient error is retried on the next block, ahead of due
    /// re-checks, even if an earlier check found the request unconfirmed.
    #[tokio::test]
    async fn deposit_intake_retries_requests_after_transient_errors() {
        let mut harness = IntakeHarness::new(1, 100).await;
        // Enough that the oldest are due for a re-check by the retry.
        let older: Vec<_> = (0..DEPOSIT_REPROBE_INTERVAL - 1)
            .map(|_| v1_deposit().0)
            .collect();
        for request in &older {
            harness.list(request);
        }
        let deposit = v1_deposit();
        harness.list(&deposit.0);
        let outpoint = deposit.0.outpoint;

        // One per block; the deposit isn't confirmed yet.
        for request in older.iter().chain([&deposit.0]) {
            assert_eq!(harness.intake(&[]).await, [request.outpoint]);
        }

        // Its block arrives while bitcoin-core fails to look it up.
        harness.confirm(&deposit);
        harness.bitcoin.lock().unwrap().failing.insert(outpoint);
        assert_eq!(harness.intake(&[outpoint.txid]).await, [outpoint]);
        harness.bitcoin.lock().unwrap().failing.clear();

        assert_eq!(harness.intake(&[]).await, [outpoint]);
        assert!(harness.is_stored(&deposit.0).await);
        assert_eq!(harness.intake(&[]).await, [older[0].outpoint]);
    }

    /// A request that fails again waits the re-check interval, so it can't
    /// keep due re-checks out of the reserved share.
    #[tokio::test]
    async fn deposit_intake_backs_off_requests_that_keep_failing() {
        let budget = 4;
        let mut harness = IntakeHarness::new(budget, 100).await;
        let failing = v1_deposit();
        harness.confirm(&failing);
        harness.list(&failing.0);
        let failing = failing.0.outpoint;
        harness.bitcoin.lock().unwrap().failing.insert(failing);
        let deposit = v1_deposit();
        harness.list(&deposit.0);

        // Its block is new, so the backoff must also hold against the trigger.
        let probes = harness.intake(&[failing.txid]).await;
        assert_eq!(probes, [failing, deposit.0.outpoint]);
        // The deposit confirms in a block the intake doesn't hear about.
        harness.confirm(&deposit);

        // New requests keep the never-tried class full. They are valid, so
        // once stored they don't compete as re-checks.
        let mut failing_checks = Vec::new();
        for intake in 1..=DEPOSIT_REPROBE_INTERVAL + 2 {
            for _ in 0..budget {
                let new = v1_deposit();
                harness.confirm(&new);
                harness.list(&new.0);
            }
            let probes = harness.intake(&[]).await;
            assert_eq!(probes.len(), usize::from(budget));
            if probes.contains(&failing) {
                failing_checks.push(intake);
            }
        }

        // Retried on the next block, then once per interval.
        assert_eq!(failing_checks, [1, 1 + DEPOSIT_REPROBE_INTERVAL]);
        assert!(harness.is_stored(&deposit.0).await);
    }

    /// A spent output in a new block is checked once, not every block.
    #[tokio::test]
    async fn deposit_intake_checks_a_spent_output_in_a_new_block_once() {
        let mut harness = IntakeHarness::new(10, 100).await;
        let request = v1_deposit().0;
        harness.list(&request);

        // In the block, but bitcoin-core reports it spent.
        let new_txids = [request.outpoint.txid];
        assert_eq!(harness.intake(&new_txids).await, [request.outpoint]);
        assert!(harness.intake(&[]).await.is_empty());
    }

    /// A coinbase output is validated once, not retried.
    #[tokio::test]
    async fn deposit_intake_checks_coinbase_outputs_once() {
        let mut harness = IntakeHarness::new(10, 100).await;
        let deposit = v1_deposit();
        harness.confirm(&deposit);
        harness.list(&deposit.0);
        let outpoint = deposit.0.outpoint;
        harness.bitcoin.lock().unwrap().coinbase.insert(outpoint);

        assert_eq!(harness.intake(&[]).await, [outpoint]);
        for _ in 0..DEPOSIT_REPROBE_INTERVAL {
            assert!(harness.intake(&[]).await.is_empty());
        }
    }

    /// A deposit listed after its block was processed still goes first, as
    /// long as the block is among the newest processed.
    #[tokio::test]
    async fn deposit_intake_matches_deposits_listed_after_their_block() {
        let mut harness = IntakeHarness::new(1, 100).await;
        let unconfirmed: Vec<_> = (0..3).map(|_| v1_deposit().0).collect();
        for request in &unconfirmed {
            harness.list(request);
        }
        let deposit = v1_deposit();
        harness.confirm(&deposit);

        assert_eq!(harness.intake(&[]).await, [unconfirmed[0].outpoint]);
        // The block confirming the deposit is processed before Emily lists it.
        let new_txids = [deposit.0.outpoint.txid];
        assert_eq!(harness.intake(&new_txids).await, [unconfirmed[1].outpoint]);
        harness.list(&deposit.0);
        // More blocks are processed before the intake that sees the listing;
        // its block is still among the newest.
        let newer_blocks = (1..MAX_REORG_BLOCK_COUNT).map(|_| Vec::new());
        harness.intake.add_new_blocks(newer_blocks);

        assert_eq!(harness.intake(&[]).await, [deposit.0.outpoint]);
        assert!(harness.is_stored(&deposit.0).await);
    }

    /// A failed intake doesn't move the never-tried cursor, so the same
    /// batch is retried.
    #[tokio::test]
    async fn deposit_intake_retries_the_same_batch_after_a_failed_intake() {
        let mut harness = IntakeHarness::new(2, 100).await;
        let deposit = v1_deposit();
        let block_hash = harness.add_next_block(&[&deposit.1]);
        harness.confirm_in(&deposit, block_hash);
        let unconfirmed: Vec<_> = (0..3).map(|_| v1_deposit().0).collect();
        harness.list(&unconfirmed[0]);
        harness.list(&deposit.0);
        harness.list(&unconfirmed[1]);
        harness.list(&unconfirmed[2]);

        // Storing the deposit fails because its block can't be fetched.
        let hash = BlockHash::from(block_hash);
        let block = harness.bitcoin.lock().unwrap().blocks.remove(&hash);
        assert!(harness.try_intake(&[]).await.is_err());
        harness
            .bitcoin
            .lock()
            .unwrap()
            .blocks
            .insert(hash, block.unwrap());

        let batch = [unconfirmed[0].outpoint, deposit.0.outpoint];
        assert_eq!(harness.intake(&[]).await, batch);
        assert!(harness.is_stored(&deposit.0).await);
    }

    /// A request checked before its block was written in the same intake
    /// is checked again in the next one.
    #[tokio::test]
    async fn deposit_intake_rechecks_requests_checked_before_their_block_was_written() {
        let mut harness = IntakeHarness::new(2, 100).await;
        let late = v1_deposit();
        let deposit = v1_deposit();
        let block_hash = harness.add_next_block(&[&late.1, &deposit.1]);
        harness.confirm_in(&deposit, block_hash);
        harness.list(&late.0);
        harness.list(&deposit.0);

        // The block is mined after `late` is checked and before `deposit`.
        let both = [late.0.outpoint, deposit.0.outpoint];
        assert_eq!(harness.intake(&[]).await, both);
        harness.confirm_in(&late, block_hash);
        harness.chain_tip = block_hash;

        assert_eq!(harness.intake(&[]).await, [late.0.outpoint]);
        assert!(harness.is_stored(&late.0).await);
    }

    /// New-block deposits go first; those over budget go first next time,
    /// even once their block is no longer among the newest processed.
    #[tokio::test]
    async fn deposit_intake_validates_deposits_in_new_blocks_first() {
        let mut harness = IntakeHarness::new(1, 100).await;
        let unconfirmed: Vec<_> = (0..3).map(|_| v1_deposit().0).collect();
        for request in &unconfirmed {
            harness.list(request);
        }
        let deposits = [v1_deposit(), v1_deposit()];
        for (request, _) in &deposits {
            harness.list(request);
        }

        assert_eq!(harness.intake(&[]).await, [unconfirmed[0].outpoint]);

        for deposit in &deposits {
            harness.confirm(deposit);
        }
        let new_txids = deposits
            .each_ref()
            .map(|(request, _)| request.outpoint.txid);

        assert_eq!(harness.intake(&new_txids).await, [deposits[0].0.outpoint]);
        let newer_blocks = (0..MAX_REORG_BLOCK_COUNT).map(|_| Vec::new());
        harness.intake.add_new_blocks(newer_blocks);
        assert_eq!(harness.intake(&[]).await, [deposits[1].0.outpoint]);
        assert_eq!(harness.intake(&[]).await, [unconfirmed[1].outpoint]);
        for (request, _) in &deposits {
            assert!(harness.is_stored(request).await);
        }
    }

    /// Unconfirmed requests are re-checked after the interval despite a full
    /// budget.
    #[tokio::test]
    async fn deposit_intake_retries_unconfirmed_requests_after_an_interval() {
        let budget = 4;
        let mut harness = IntakeHarness::new(budget, 100).await;
        let deposit = v1_deposit();
        harness.list(&deposit.0);

        assert_eq!(harness.intake(&[]).await, [deposit.0.outpoint]);
        // The deposit confirms in a block the intake doesn't hear about.
        harness.confirm(&deposit);

        for intake in 1..=DEPOSIT_REPROBE_INTERVAL {
            for _ in 0..budget {
                harness.list(&v1_deposit().0);
            }
            let probes = harness.intake(&[]).await;
            assert_eq!(probes.len(), usize::from(budget));
            let is_due = intake == DEPOSIT_REPROBE_INTERVAL;
            assert_eq!(probes.contains(&deposit.0.outpoint), is_due);
        }
        assert!(harness.is_stored(&deposit.0).await);
    }

    /// A stored deposit outside the window is re-validated once per interval.
    #[tokio::test]
    async fn deposit_intake_rechecks_old_stored_deposits_slowly() {
        let mut harness = IntakeHarness::with_context_window(10, 100, 2).await;
        let deposit = v1_deposit();
        harness.confirm_in(&deposit, harness.blocks[0].block_hash);
        harness.list(&deposit.0);

        assert_eq!(harness.intake(&[]).await, [deposit.0.outpoint]);
        assert!(harness.is_stored(&deposit.0).await);

        for _ in 1..DEPOSIT_REPROBE_INTERVAL {
            assert!(harness.intake(&[]).await.is_empty());
        }
        assert_eq!(harness.intake(&[]).await, [deposit.0.outpoint]);
    }

    /// New-block priority survives a failed intake.
    #[tokio::test]
    async fn deposit_intake_keeps_new_block_priority_after_a_failed_intake() {
        let mut harness = IntakeHarness::new(1, 100).await;
        for _ in 0..3 {
            harness.list(&v1_deposit().0);
        }
        let deposit = v1_deposit();
        harness.confirm(&deposit);
        harness.list(&deposit.0);

        *harness.emily_fails.lock().unwrap() = true;
        let new_txids = [deposit.0.outpoint.txid];
        assert!(harness.try_intake(&new_txids).await.is_err());
        *harness.emily_fails.lock().unwrap() = false;

        assert_eq!(harness.intake(&[]).await, [deposit.0.outpoint]);
        assert!(harness.is_stored(&deposit.0).await);
    }

    /// Past cache capacity every request is still tried in turn, even when
    /// the request decider stores the cursor's request.
    #[tokio::test]
    async fn deposit_intake_reaches_every_request_beyond_its_capacity() {
        let mut harness = IntakeHarness::new(2, 3).await;
        let deposits: Vec<_> = (0..9).map(|_| v1_deposit()).collect();
        harness.confirm(&deposits[6]);
        let requests: Vec<_> = deposits.into_iter().map(|(request, _)| request).collect();
        for request in &requests {
            harness.list(request);
        }

        // Nine requests and two validations per block take five blocks.
        let mut probed = HashSet::new();
        for intake in 0..5 {
            probed.extend(harness.intake(&[]).await);
            if intake == 2 {
                let stored = [requests[6].clone()];
                harness.observer.load_requests(&stored).await.unwrap();
            }
        }

        let all: HashSet<_> = requests.iter().map(|request| request.outpoint).collect();
        assert_eq!(probed, all);
    }

    /// The budget doesn't apply to the request decider's `load_requests`.
    #[tokio::test]
    async fn load_requests_validates_every_request_given() {
        let harness = IntakeHarness::new(1, 100).await;
        let deposits: Vec<_> = (0..3).map(|_| v1_deposit()).collect();
        for deposit in &deposits {
            harness.confirm(deposit);
        }
        let requests: Vec<_> = deposits
            .iter()
            .map(|(request, _)| request.clone())
            .collect();

        harness.observer.load_requests(&requests).await.unwrap();

        for request in &requests {
            assert!(harness.is_stored(request).await);
        }
    }

    /// Only the newest processed blocks' txids are returned.
    #[tokio::test]
    async fn processing_a_chain_tip_returns_txids_in_the_newest_blocks() {
        let mut rng = get_rng();
        let test_harness = TestHarness::generate(&mut rng, 20, 0..1);
        let min_height = test_harness.min_block_height();
        let ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_stacks_client(test_harness.clone())
            .with_emily_client(test_harness.clone())
            .with_bitcoin_client(test_harness.clone())
            .modify_settings(|settings| settings.signer.sbtc_bitcoin_start_height = min_height)
            .build();
        let block_observer = BlockObserver {
            context: ctx,
            bitcoin_block_source: (),
        };

        let blocks = test_harness.bitcoin_blocks();
        let chain_tip = blocks.last().unwrap().block_hash;
        let new_blocks = block_observer
            .process_bitcoin_chain_tip(chain_tip)
            .await
            .unwrap();

        let newest = blocks.len() - MAX_REORG_BLOCK_COUNT as usize;
        let expected: Vec<Vec<Txid>> = blocks[newest..]
            .iter()
            .map(|block| {
                let txids = block.transactions.iter().map(BitcoinTxInfo::compute_txid);
                txids.collect()
            })
            .collect();
        assert_eq!(new_blocks, expected);

        let new_blocks = block_observer
            .process_bitcoin_chain_tip(chain_tip)
            .await
            .unwrap();
        assert!(new_blocks.is_empty());
    }
}
