//! One reconciliation cycle: fetch Emily deposits, decide updates, submit batches.

use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use private_emily_client::apis::configuration::ApiKey;
use private_emily_client::apis::configuration::Configuration;
use private_emily_client::apis::deposit_api;
use private_emily_client::models::DepositInfo;
use private_emily_client::models::DepositStatus;
use private_emily_client::models::DepositUpdate;
use private_emily_client::models::UpdateDepositsRequestBody;
use reqwest::Client;
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use tracing::info;
use tracing::warn;

use crate::config::Config;
use crate::error::Error;
use crate::model::Block;
use crate::model::Outspend;
use crate::model::Rbf;
use crate::model::Transaction;
use crate::model::is_past_expiry;
use crate::model::reclaim_lock_time;

/// Emily applies deposit updates sequentially under a short Lambda deadline.
/// Keep each write small so a large backlog cannot miss the deadline.
const DEPOSIT_UPDATE_BATCH_SIZE: usize = 5;

/// How long one Emily status query may spend following `nextToken` pages.
///
/// When the budget is exceeded we keep deposits already fetched and continue
/// the cycle, so a huge backlog cannot stall reconciliation forever.
const EMILY_PAGINATION_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP timeout applied to every request in this cycle.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Reconciles Emily deposit statuses against Bitcoin and Stacks chain data.
pub struct Processor {
    config: Config,
    /// Used for mempool, Electrs, and Hiro (no Emily API key).
    client: Client,
    /// Generated Emily client; carries the API key on every request.
    emily: Configuration,
}

/// Mutable caches shared across every deposit in a single `run` cycle.
struct CycleState {
    /// Mempool transactions found during this cycle, keyed by txid.
    transactions: HashMap<String, Transaction>,
    /// Stacks block timestamps by block hash (seconds since Unix epoch).
    block_times: HashMap<String, u64>,
    /// Outpoints already considered, so duplicate Emily rows are skipped.
    seen_outpoints: HashSet<(String, u32)>,
}

impl CycleState {
    fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            block_times: HashMap::new(),
            seen_outpoints: HashSet::new(),
        }
    }
}

impl Processor {
    /// Build HTTP clients for Bitcoin/Stacks lookups and authenticated Emily calls.
    pub fn new(config: Config) -> Result<Self, Error> {
        let client = Client::builder().timeout(REQUEST_TIMEOUT).build()?;

        // `get_deposits` does not attach `api_key` itself, so Emily reads need
        // the key as a default header on a dedicated client.
        let mut api_key = HeaderValue::from_str(&config.emily_api_key)?;
        api_key.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", api_key);
        let emily_client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .default_headers(headers)
            .build()?;

        let emily = Configuration {
            base_path: config
                .private_emily_endpoint
                .trim_end_matches('/')
                .to_owned(),
            client: emily_client,
            api_key: Some(ApiKey {
                prefix: None,
                key: config.emily_api_key.clone(),
            }),
            ..Configuration::default()
        };

        Ok(Self { config, client, emily })
    }

    // -----------------------------------------------------------------------
    // Cycle entry point
    // -----------------------------------------------------------------------

    /// Fetch deposits, decide status updates, then submit or dry-run log them.
    pub async fn run(&self) -> Result<(), Error> {
        let tip = self.fetch_bitcoin_tip_height().await?;
        let deposits = self.fetch_deposits(DepositStatus::Pending).await?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut state = CycleState::new();
        let mut updates = Vec::new();
        let mut incomplete = false;

        for deposit in deposits {
            let outpoint = (
                deposit.bitcoin_txid.clone(),
                deposit.bitcoin_tx_output_index,
            );
            if !state.seen_outpoints.insert(outpoint) {
                continue;
            }

            match self.reconcile(&deposit, tip, now, &mut state).await {
                Ok(Some(update)) => updates.push(update),
                Ok(None) => {}
                Err(error) => {
                    incomplete = true;
                    tracing::warn!(
                        txid = %deposit.bitcoin_txid,
                        vout = deposit.bitcoin_tx_output_index,
                        %error,
                        "Skipping deposit with incomplete data"
                    );
                }
            }
        }

        if self.config.dry_run {
            tracing::info!(updates = %serde_json::to_string(&updates)?, "Proposed deposit updates");
        } else if !updates.is_empty() {
            self.submit_updates(&updates).await?;
        }

        if incomplete {
            return Err(Error::IncompleteReconciliation);
        }

        info!(
            tip,
            updates = updates.len(),
            dry_run = self.config.dry_run,
            "Deposit reconciliation completed"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Emily deposit fetch
    // -----------------------------------------------------------------------

    /// Fetch pending deposits, following `nextToken` pages.
    ///
    /// Accepted deposits are left alone: signers are already sweeping them.
    /// Replaced losers that still need failing remain pending and are handled
    /// by RBF or stale-pending rules.
    ///
    /// Returns early with deposits collected so far if paging exceeds
    /// [`EMILY_PAGINATION_TIMEOUT`].
    async fn fetch_deposits(&self, status: DepositStatus) -> Result<Vec<DepositInfo>, Error> {
        let mut deposits = Vec::new();
        let mut next_token: Option<String> = None;
        let started = Instant::now();

        loop {
            let page =
                deposit_api::get_deposits(&self.emily, status, next_token.as_deref(), None).await?;
            deposits.extend(page.deposits);

            next_token = page.next_token.flatten().filter(|token| !token.is_empty());

            if next_token.is_none() {
                break;
            }

            // Budget is checked only when another page remains, so the first
            // page is always fetched.
            if started.elapsed() > EMILY_PAGINATION_TIMEOUT {
                tracing::warn!(
                    %status,
                    fetched = deposits.len(),
                    "Emily deposit pagination timed out; continuing with partial results"
                );
                break;
            }
        }

        Ok(deposits)
    }

    // -----------------------------------------------------------------------
    // Per-deposit decisions
    // -----------------------------------------------------------------------

    /// Decide at most one Emily status update for a single deposit.
    ///
    /// Confirmed deposits are checked for lock-time expiry / reclaim.
    /// Unconfirmed deposits are checked for a finalized RBF replacement, then
    /// (if still pending and missing from the mempool) for age.
    async fn reconcile(
        &self,
        deposit: &DepositInfo,
        tip: u64,
        now: u64,
        state: &mut CycleState,
    ) -> Result<Option<DepositUpdate>, Error> {
        let maybe_tx = self
            .cached_transaction(&deposit.bitcoin_txid, state)
            .await?;

        if let Some(height) = maybe_tx.and_then(Transaction::confirmed_height) {
            return self.expiry_or_reclaim_update(deposit, height, tip).await;
        }
        let missing_from_mempool = maybe_tx.is_none();

        // Replacements may not be registered in Emily, and the original may
        // already have left the mempool after being replaced.
        if let Some(update) = self.rbf_update(deposit, tip, state).await? {
            return Ok(Some(update));
        }

        if missing_from_mempool && deposit.status == DepositStatus::Pending {
            return self
                .stale_pending_update(deposit, now, &mut state.block_times)
                .await;
        }

        Ok(None)
    }

    /// Fail a confirmed deposit whose reclaim window has passed and whose UTXO
    /// is still unspent, or was spent via the reclaim path.
    ///
    /// Signer sweeps are left alone.
    async fn expiry_or_reclaim_update(
        &self,
        deposit: &DepositInfo,
        confirmed_height: u64,
        tip: u64,
    ) -> Result<Option<DepositUpdate>, Error> {
        let reclaim_delay = reclaim_lock_time(&deposit.reclaim_script)?;
        let deposit_expired = is_past_expiry(
            confirmed_height,
            reclaim_delay,
            self.config.min_block_confirmations,
            tip,
        );

        if !deposit_expired {
            return Ok(None);
        }

        let outspend: Outspend = self
            .get_json(
                &self.config.electrs_api_url,
                &format!(
                    "/tx/{}/outspend/{}",
                    deposit.bitcoin_txid, deposit.bitcoin_tx_output_index
                ),
            )
            .await?;

        if !outspend.spent {
            return Ok(Some(deposit_update(
                deposit,
                DepositStatus::Failed,
                format!("Locktime expired at height {tip} and UTXO unspent"),
                None,
            )));
        }

        let (Some(txid), Some(vin)) = (outspend.txid, outspend.vin) else {
            return Err(Error::IncompleteOutspend);
        };
        let Some(transaction) = self.fetch_transaction(&txid).await? else {
            return Err(Error::SpendingTransactionNotFound(txid));
        };
        let input = transaction
            .vin
            .get(vin)
            .ok_or_else(|| Error::SpendingInputOutOfBounds { txid: txid.clone(), index: vin })?;

        if input.contains_reclaim_script(&deposit.reclaim_script) {
            return Ok(Some(deposit_update(
                deposit,
                DepositStatus::Failed,
                format!("Depositor reclaim detected in tx {txid}"),
                None,
            )));
        }

        Ok(None)
    }

    /// Mark the deposit as RBF when a replacement has enough confirmations.
    async fn rbf_update(
        &self,
        deposit: &DepositInfo,
        tip: u64,
        state: &mut CycleState,
    ) -> Result<Option<DepositUpdate>, Error> {
        let rbf: Rbf = self
            .get_json(
                &self.config.mempool_api_url,
                &format!("/v1/tx/{}/rbf", deposit.bitcoin_txid),
            )
            .await?;

        let mut replacement_txids = Vec::new();
        if let Some(root) = rbf.replacements {
            root.txids(&mut replacement_txids);
        }

        for txid in replacement_txids {
            if txid == deposit.bitcoin_txid {
                continue;
            }

            let Some(transaction) = self.cached_transaction(&txid, state).await? else {
                continue;
            };
            let Some(height) = transaction.confirmed_height() else {
                continue;
            };

            // Same confirmation margin as expiry, with no reclaim lock-time.
            if is_past_expiry(height, 0, self.config.min_block_confirmations, tip) {
                return Ok(Some(deposit_update(
                    deposit,
                    DepositStatus::Rbf,
                    format!("Replaced by confirmed tx {txid}"),
                    Some(txid),
                )));
            }
        }

        Ok(None)
    }

    /// Fail a pending deposit that has been missing from the mempool too long.
    async fn stale_pending_update(
        &self,
        deposit: &DepositInfo,
        now: u64,
        block_times: &mut HashMap<String, u64>,
    ) -> Result<Option<DepositUpdate>, Error> {
        let hash = &deposit.last_update_block_hash;
        let last_update_time = match block_times.entry(hash.clone()) {
            std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let block: Block = self
                    .get_json(
                        &self.config.hiro_api_url,
                        &format!("/extended/v2/blocks/{hash}"),
                    )
                    .await?;
                *entry.insert(block.block_time)
            }
        };

        let pending_age = now.saturating_sub(last_update_time);
        if pending_age > self.config.max_unconfirmed_time {
            let message = format!(
                "Pending for too long ({} seconds)",
                self.config.max_unconfirmed_time
            );
            let update = deposit_update(deposit, DepositStatus::Failed, message, None);
            return Ok(Some(update));
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Emily updates
    // -----------------------------------------------------------------------

    /// Submit updates in small batches.
    ///
    /// Per-deposit rejections are logged and the next batch still runs.
    /// Transport or malformed-response errors stop the cycle immediately.
    async fn submit_updates(&self, updates: &[DepositUpdate]) -> Result<(), Error> {
        let mut rejected = false;

        for (batch_index, batch) in updates.chunks(DEPOSIT_UPDATE_BATCH_SIZE).enumerate() {
            let request = UpdateDepositsRequestBody::new(batch.to_vec());
            let response = deposit_api::update_deposits_sidecar(&self.emily, request)
                .await
                .map_err(|error| {
                    warn!(
                        batch_index,
                        updates = batch.len(),
                        %error,
                        "Emily update batch failed"
                    );
                    Error::EmilyUpdateDeposits(error)
                })?;

            if response.deposits.len() != batch.len() {
                return Err(Error::UnexpectedUpdateCount {
                    expected: batch.len(),
                    actual: response.deposits.len(),
                });
            }

            for (update, outcome) in batch.iter().zip(response.deposits) {
                // Generated schema: omitted `error` vs JSON `null` are distinct.
                let error = outcome.error.flatten();
                let succeeded = (200..300).contains(&outcome.status) && error.is_none();
                if !succeeded {
                    rejected = true;
                    warn!(
                        txid = %update.bitcoin_txid,
                        vout = update.bitcoin_tx_output_index,
                        status = outcome.status,
                        error = ?error,
                        "Emily rejected deposit update"
                    );
                }
            }
        }

        if rejected {
            return Err(Error::DepositUpdatesRejected);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // HTTP helpers
    // -----------------------------------------------------------------------

    async fn fetch_bitcoin_tip_height(&self) -> Result<u64, Error> {
        self.get_json(&self.config.mempool_api_url, "/v1/blocks/tip/height")
            .await
    }

    /// Fetch a mempool transaction, treating only HTTP 404 as "missing".
    async fn fetch_transaction(&self, txid: &str) -> Result<Option<Transaction>, Error> {
        let path = format!("{}/{txid}", self.mempool_tx_path_prefix()?);
        let response = self
            .client
            .get(join_url(&self.config.mempool_api_url, &path))
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.error_for_status()?.json().await?))
    }

    /// Return a cached transaction, or fetch and store it when found.
    ///
    /// `Ok(None)` means the mempool API returned HTTP 404. Missing txids are
    /// not cached, so a later call will ask the API again.
    async fn cached_transaction<'a>(
        &self,
        txid: &str,
        state: &'a mut CycleState,
    ) -> Result<Option<&'a Transaction>, Error> {
        if state.transactions.contains_key(txid) {
            return Ok(state.transactions.get(txid));
        }

        let Some(transaction) = self.fetch_transaction(txid).await? else {
            return Ok(None);
        };
        state.transactions.insert(txid.to_owned(), transaction);
        Ok(state.transactions.get(txid))
    }

    /// Hosted mempool.space uses `/tx/{txid}`; local backends use `/v1/tx/{txid}`.
    fn mempool_tx_path_prefix(&self) -> Result<&'static str, Error> {
        let host = reqwest::Url::parse(&self.config.mempool_api_url)?;
        let hostname = host.host_str().unwrap_or_default();
        let hosted = hostname == "mempool.space" || hostname.ends_with(".mempool.space");
        Ok(if hosted { "/tx" } else { "/v1/tx" })
    }

    async fn get_json<T>(&self, base: &str, path: &str) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        Ok(self
            .client
            .get(join_url(base, path))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

fn join_url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

/// Build an Emily deposit update from a known deposit row.
fn deposit_update(
    deposit: &DepositInfo,
    status: DepositStatus,
    message: String,
    replaced_by_tx: Option<String>,
) -> DepositUpdate {
    let mut update = DepositUpdate::new(
        deposit.bitcoin_tx_output_index,
        deposit.bitcoin_txid.clone(),
        status,
        message,
    );
    update.replaced_by_tx = replaced_by_tx.map(Some);
    update
}
