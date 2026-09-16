//! One reconciliation cycle: fetch Emily deposits, decide updates, submit batches.

use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bitcoin::ScriptBuf;
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
use sbtc::deposits::ReclaimScriptInputs;

use crate::config::Config;
use crate::error::Error;
use crate::model::Block;
use crate::model::Outspend;
use crate::model::Rbf;
use crate::model::Transaction;
use crate::model::is_past_expiry;

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
        let tip_height = self.fetch_bitcoin_tip_height().await?;
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

            match self.reconcile(&deposit, tip_height, now, &mut state).await {
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

        tracing::info!(
            tip_height,
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
        tip_height: u64,
        now: u64,
        state: &mut CycleState,
    ) -> Result<Option<DepositUpdate>, Error> {
        let maybe_tx = self
            .cached_transaction(&deposit.bitcoin_txid, state)
            .await?;

        if let Some(confirmed_height) = maybe_tx.and_then(Transaction::confirmed_height) {
            return self
                .expiry_or_reclaim_update(deposit, confirmed_height, tip_height)
                .await;
        }
        let missing_from_mempool = maybe_tx.is_none();

        // Replacements may not be registered in Emily, and the original may
        // already have left the mempool after being replaced.
        if let Some(update) = self.rbf_update(deposit, tip_height, state).await? {
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
        tip_height: u64,
    ) -> Result<Option<DepositUpdate>, Error> {
        let script = ScriptBuf::from_hex(&deposit.reclaim_script)?;
        let reclaim = ReclaimScriptInputs::parse(&script)?;
        let deposit_expired = is_past_expiry(
            confirmed_height,
            reclaim.lock_time(),
            self.config.min_block_confirmations,
            tip_height,
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
                format!("Locktime expired at height {tip_height} and UTXO unspent"),
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
        tip_height: u64,
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
            if is_past_expiry(height, 0, self.config.min_block_confirmations, tip_height) {
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
                    tracing::warn!(
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
                    tracing::warn!(
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
    /// `Ok(None)` means the the transaction is missing from the cache and
    /// the mempool API returned HTTP 404.
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

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use mockito::Matcher;
    use mockito::Server;
    use serde_json::Value;
    use serde_json::json;
    use test_case::test_case;

    use crate::config::Config;
    use crate::error::Error;

    use super::Processor;

    /// Valid 32-byte Bitcoin txids used in HTTP fixtures.
    const DEPOSIT_TXID: &str = "52193ceeee4110ca2cf415820914bc42305758907d5f9b43d00540649d7c6fc9";
    const SPENDER_TXID: &str = "afe18f246b9624b17b21f2ebf84594bb75b582209d55dfc0b6edb34bfb785c3a";
    const REPLACEMENT_TXID: &str =
        "75b02b9884ec41c05f2cfa6e20823328321518dd0b027e7b609b63d4d1ea7c78";

    fn mempool_tx_path(txid: &str) -> String {
        format!("/v1/tx/{txid}")
    }

    fn electrs_outspend_path(txid: &str, vout: u32) -> String {
        format!("/tx/{txid}/outspend/{vout}")
    }

    fn mempool_rbf_path(txid: &str) -> String {
        format!("/v1/tx/{txid}/rbf")
    }

    fn processor(server: &Server, dry_run: bool) -> Processor {
        let mut config = Config::parse_from(["emily-cron2"]);
        config.private_emily_endpoint = server.url();
        config.mempool_api_url = server.url();
        config.electrs_api_url = server.url();
        config.hiro_api_url = server.url();
        config.emily_api_key = "test-key".into();
        config.min_block_confirmations = 6;
        config.max_unconfirmed_time = 86400;
        config.dry_run = dry_run;
        Processor::new(config).unwrap()
    }

    fn deposit(status: &str) -> Value {
        json!({
            "bitcoinTxid": DEPOSIT_TXID,
            "bitcoinTxOutputIndex": 2,
            "status": status,
            "lastUpdateBlockHash": "block",
            "reclaimScript": "0160b27551",
            "amount": 1000,
            "depositScript": "",
            "lastUpdateHeight": 1,
            "recipient": "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS"
        })
    }

    async fn setup(server: &mut Server, status: &str, tip: u64) -> Vec<mockito::Mock> {
        vec![
            server
                .mock("GET", "/v1/blocks/tip/height")
                .match_header("x-api-key", Matcher::Missing)
                .with_body(tip.to_string())
                .create_async()
                .await,
            server
                .mock("GET", "/deposit")
                .with_header("content-type", "application/json")
                .match_query(Matcher::UrlEncoded("status".into(), "pending".into()))
                .match_header("x-api-key", "test-key")
                .with_body(
                    json!({
                        "deposits": if status == "pending" { vec![deposit(status)] } else { vec![] },
                        "nextToken": null
                    })
                    .to_string(),
                )
                .create_async()
                .await,
        ]
    }

    async fn update_mock(
        server: &mut Server,
        status: &str,
        message: &str,
        replacement: Option<&str>,
        count: usize,
    ) -> mockito::Mock {
        let mut update = json!({
            "bitcoinTxid": DEPOSIT_TXID, "bitcoinTxOutputIndex": 2,
            "status": status, "statusMessage": message
        });
        if let Some(txid) = replacement {
            update["replacedByTx"] = json!(txid);
        }
        server
            .mock("PUT", "/deposit_private")
            .with_header("content-type", "application/json")
            .match_header("x-api-key", "test-key")
            .match_body(Matcher::Json(json!({"deposits": [update]})))
            .with_body(r#"{"deposits":[{"status":200,"error":null}]}"#)
            .expect(count)
            .create_async()
            .await
    }

    #[test_case(false, ""; "expired_unspent")]
    #[test_case(true, "0160b27551"; "depositor_reclaim")]
    #[test_case(true, "signature"; "signer_sweep")]
    #[test_case(true, "aa0160b27551bb"; "reclaim_substring_ignored")]
    #[tokio::test]
    async fn expiry_unspent_reclaim_and_signer_sweep(spent: bool, witness: &str) {
        let expected = match (spent, witness) {
            (false, _) => Some("Locktime expired at height 202 and UTXO unspent".to_string()),
            (true, "0160b27551") => {
                Some(format!("Depositor reclaim detected in tx {SPENDER_TXID}"))
            }
            _ => None,
        };
        let deposit_tx_path = mempool_tx_path(DEPOSIT_TXID);
        let outspend_path = electrs_outspend_path(DEPOSIT_TXID, 2);
        let spender_tx_path = mempool_tx_path(SPENDER_TXID);

        let mut server = Server::new_async().await;
        let mocks = setup(&mut server, "pending", 202).await;
        let tx = server
            .mock("GET", deposit_tx_path.as_str())
            .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
            .create_async()
            .await;
        let outspend = server
            .mock("GET", outspend_path.as_str())
            .with_body(json!({"spent":spent,"txid":SPENDER_TXID,"vin":0}).to_string())
            .create_async()
            .await;
        let spending = server
            .mock("GET", spender_tx_path.as_str())
            .with_body(
                json!({"status":{"confirmed":true},"vin":[{"witness":[witness]}]}).to_string(),
            )
            .expect(usize::from(spent))
            .create_async()
            .await;
        let update = update_mock(
            &mut server,
            "failed",
            expected.as_deref().unwrap_or(""),
            None,
            usize::from(expected.is_some()),
        )
        .await;
        processor(&server, false).run().await.unwrap();
        for mock in mocks {
            mock.assert_async().await;
        }
        tx.assert_async().await;
        outspend.assert_async().await;
        spending.assert_async().await;
        update.assert_async().await;
    }

    #[test_case(105; "below_confirmation_threshold")]
    #[test_case(106; "meets_confirmation_threshold")]
    #[tokio::test]
    async fn rbf_fetches_replacement_outside_emily_and_waits_for_confirmations(tip: u64) {
        let deposit_tx_path = mempool_tx_path(DEPOSIT_TXID);
        let rbf_path = mempool_rbf_path(DEPOSIT_TXID);
        let replacement_tx_path = mempool_tx_path(REPLACEMENT_TXID);
        let rbf_message = format!("Replaced by confirmed tx {REPLACEMENT_TXID}");
        let expect_rbf = tip >= 106;
        let mut server = Server::new_async().await;
        let _mocks = setup(&mut server, "pending", tip).await;
        let deposit_tx = server
            .mock("GET", deposit_tx_path.as_str())
            .with_status(404)
            .create_async()
            .await;
        let rbf = server
            .mock("GET", rbf_path.as_str())
            .with_body(
                json!({
                    "replacements": {
                        "tx": {"txid": REPLACEMENT_TXID},
                        "replaces": [{"tx": {"txid": DEPOSIT_TXID}}]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;
        let replacement = server
            .mock("GET", replacement_tx_path.as_str())
            .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
            .create_async()
            .await;
        let block = server
            .mock("GET", "/extended/v2/blocks/block")
            .with_body(r#"{"block_time":18446744073709551615}"#)
            .expect(usize::from(!expect_rbf))
            .create_async()
            .await;
        let update = update_mock(
            &mut server,
            "rbf",
            &rbf_message,
            Some(REPLACEMENT_TXID),
            usize::from(expect_rbf),
        )
        .await;
        processor(&server, false).run().await.unwrap();
        deposit_tx.assert_async().await;
        rbf.assert_async().await;
        replacement.assert_async().await;
        block.assert_async().await;
        update.assert_async().await;
    }

    #[test_case(true, true, true; "missing_and_old")]
    #[test_case(true, false, false; "missing_but_recent")]
    #[test_case(false, true, false; "in_mempool_even_if_old")]
    #[tokio::test]
    async fn only_missing_old_pending_transactions_fail(missing: bool, old: bool, expected: bool) {
        let deposit_tx_path = mempool_tx_path(DEPOSIT_TXID);
        let rbf_path = mempool_rbf_path(DEPOSIT_TXID);
        let mut server = Server::new_async().await;
        let _mocks = setup(&mut server, "pending", 100).await;
        let tx = server
            .mock("GET", deposit_tx_path.as_str())
            .with_status(if missing { 404 } else { 200 })
            .with_body(r#"{"status":{"confirmed":false}}"#)
            .create_async()
            .await;
        let rbf = server
            .mock("GET", rbf_path.as_str())
            .with_body(r#"{"replacements":null}"#)
            .create_async()
            .await;
        let block = server
            .mock("GET", "/extended/v2/blocks/block")
            .with_body(json!({"block_time": if old {0} else {u64::MAX}}).to_string())
            .expect(usize::from(missing))
            .create_async()
            .await;
        let update = update_mock(
            &mut server,
            "failed",
            "Pending for too long (86400 seconds)",
            None,
            usize::from(expected),
        )
        .await;
        processor(&server, false).run().await.unwrap();
        tx.assert_async().await;
        rbf.assert_async().await;
        block.assert_async().await;
        update.assert_async().await;
    }

    #[test_case("tx"; "mempool_transaction")]
    #[test_case("outspend"; "electrs_outspend")]
    #[test_case("block"; "hiro_block")]
    #[tokio::test]
    async fn upstream_failures_never_become_deposit_failures(which: &str) {
        let deposit_tx_path = mempool_tx_path(DEPOSIT_TXID);
        let outspend_path = electrs_outspend_path(DEPOSIT_TXID, 2);
        let rbf_path = mempool_rbf_path(DEPOSIT_TXID);
        let block_path = "/extended/v2/blocks/block".to_string();
        let failing_path = match which {
            "outspend" => outspend_path,
            "block" => block_path,
            _ => deposit_tx_path.clone(),
        };

        let mut server = Server::new_async().await;
        let _mocks = setup(&mut server, "pending", 202).await;
        if which != "tx" {
            server
                .mock("GET", deposit_tx_path.as_str())
                .with_status(if which == "block" { 404 } else { 200 })
                .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
                .create_async()
                .await;
        }
        server
            .mock("GET", rbf_path.as_str())
            .with_body(r#"{"replacements":null}"#)
            .expect_at_most(1)
            .create_async()
            .await;
        let failure = server
            .mock("GET", failing_path.as_str())
            .with_status(503)
            .create_async()
            .await;
        let writes = server
            .mock("PUT", "/deposit_private")
            .with_header("content-type", "application/json")
            .expect(0)
            .create_async()
            .await;
        assert!(processor(&server, false).run().await.is_err());
        failure.assert_async().await;
        writes.assert_async().await;
    }

    #[test_case(true, 200; "dry_run_skips_writes")]
    #[test_case(false, 400; "rejected_update")]
    #[test_case(false, 503; "update_http_error")]
    #[tokio::test]
    async fn pagination_dry_run_and_batch_errors(dry_run: bool, update_status: usize) {
        let mut server = Server::new_async().await;
        server
            .mock("GET", "/v1/blocks/tip/height")
            .match_header("x-api-key", Matcher::Missing)
            .with_body("202")
            .create_async()
            .await;
        let first = server
            .mock("GET", "/deposit")
            .with_header("content-type", "application/json")
            .match_query(Matcher::UrlEncoded("status".into(), "pending".into()))
            .with_body(r#"{"deposits":[],"nextToken":"a+b/c="}"#)
            .create_async()
            .await;
        let second = server
            .mock("GET", "/deposit")
            .with_header("content-type", "application/json")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("status".into(), "pending".into()),
                Matcher::UrlEncoded("nextToken".into(), "a+b/c=".into()),
            ]))
            .with_body(json!({"deposits":[deposit("pending")]}).to_string())
            .create_async()
            .await;
        let deposit_tx_path = mempool_tx_path(DEPOSIT_TXID);
        let outspend_path = electrs_outspend_path(DEPOSIT_TXID, 2);
        server
            .mock("GET", deposit_tx_path.as_str())
            .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
            .create_async()
            .await;
        server
            .mock("GET", outspend_path.as_str())
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;
        let update = server
            .mock("PUT", "/deposit_private")
            .with_header("content-type", "application/json")
            .with_status(if update_status == 503 { 503 } else { 200 })
            .with_body(
                json!({"deposits":[{"status":update_status,"error":"rejected"}]}).to_string(),
            )
            .expect(usize::from(!dry_run))
            .create_async()
            .await;
        assert_eq!(processor(&server, dry_run).run().await.is_ok(), dry_run);
        first.assert_async().await;
        second.assert_async().await;
        update.assert_async().await;
    }

    #[test_case(200; "malformed_json")]
    #[test_case(503; "http_error")]
    #[tokio::test]
    async fn emily_read_errors_retain_generated_client_errors(status: usize) {
        use private_emily_client::apis;

        let mut server = Server::new_async().await;
        let tip = server
            .mock("GET", "/v1/blocks/tip/height")
            .match_header("x-api-key", Matcher::Missing)
            .with_body("202")
            .create_async()
            .await;
        let read = server
            .mock("GET", "/deposit")
            .match_query(Matcher::UrlEncoded("status".into(), "pending".into()))
            .match_header("x-api-key", "test-key")
            .with_header("content-type", "application/json")
            .with_status(status)
            .with_body("invalid JSON")
            .create_async()
            .await;
        let writes = server
            .mock("PUT", "/deposit_private")
            .expect(0)
            .create_async()
            .await;

        let error = processor(&server, false).run().await.unwrap_err();
        if status == 200 {
            assert!(matches!(
                error,
                Error::EmilyGetDeposits(apis::Error::Serde(_))
            ));
        } else {
            assert!(matches!(
                error,
                Error::EmilyGetDeposits(apis::Error::ResponseError(_))
            ));
        }
        tip.assert_async().await;
        read.assert_async().await;
        writes.assert_async().await;
    }

    /// Arrange expired outputs so a full cycle produces the requested update count.
    async fn setup_update_backlog(server: &mut Server, count: u32) -> Vec<mockito::Mock> {
        let deposits: Vec<Value> = (0..count)
            .map(|index| {
                let mut deposit = deposit("pending");
                deposit["bitcoinTxOutputIndex"] = json!(index);
                deposit
            })
            .collect();
        let tip = server
            .mock("GET", "/v1/blocks/tip/height")
            .with_body("202")
            .create_async()
            .await;
        let pending = server
            .mock("GET", "/deposit")
            .match_query(Matcher::UrlEncoded("status".into(), "pending".into()))
            .with_header("content-type", "application/json")
            .with_body(json!({"deposits": deposits}).to_string())
            .create_async()
            .await;
        let deposit_tx_path = mempool_tx_path(DEPOSIT_TXID);
        let transaction = server
            .mock("GET", deposit_tx_path.as_str())
            .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
            .create_async()
            .await;
        let outspends = server
            .mock(
                "GET",
                Matcher::Regex(format!("^/tx/{DEPOSIT_TXID}/outspend/\\d+$")),
            )
            .with_body(r#"{"spent":false}"#)
            .expect(count as usize)
            .create_async()
            .await;
        vec![tip, pending, transaction, outspends]
    }

    /// Match the complete set of updates in one request, including output ordering.
    async fn backlog_batch(
        server: &mut Server,
        outputs: std::ops::Range<u32>,
        response_status: usize,
        rejected_output: Option<u32>,
        expected_calls: usize,
    ) -> mockito::Mock {
        let updates: Vec<Value> = outputs
            .clone()
            .map(|index| {
                json!({
                    "bitcoinTxid": DEPOSIT_TXID,
                    "bitcoinTxOutputIndex": index,
                    "status": "failed",
                    "statusMessage": "Locktime expired at height 202 and UTXO unspent"
                })
            })
            .collect();
        let outcomes: Vec<Value> = outputs
            .map(|index| {
                if Some(index) == rejected_output {
                    json!({"status":400, "error":"rejected"})
                } else {
                    json!({"status":200, "error":null})
                }
            })
            .collect();
        server
            .mock("PUT", "/deposit_private")
            .match_header("x-api-key", "test-key")
            .match_body(Matcher::Json(json!({"deposits":updates})))
            .with_header("content-type", "application/json")
            .with_status(response_status)
            .with_body(json!({"deposits":outcomes}).to_string())
            .expect(expected_calls)
            .create_async()
            .await
    }

    #[tokio::test]
    async fn submits_backlog_in_bounded_batches() {
        let mut server = Server::new_async().await;
        let reads = setup_update_backlog(&mut server, 11).await;
        let first = backlog_batch(&mut server, 0..5, 200, None, 1).await;
        let second = backlog_batch(&mut server, 5..10, 200, None, 1).await;
        let last = backlog_batch(&mut server, 10..11, 200, None, 1).await;

        processor(&server, false).run().await.unwrap();

        for read in reads {
            read.assert_async().await;
        }
        first.assert_async().await;
        second.assert_async().await;
        last.assert_async().await;
    }

    #[tokio::test]
    async fn partial_rejection_does_not_stop_later_batches() {
        let mut server = Server::new_async().await;
        let reads = setup_update_backlog(&mut server, 6).await;
        // One rejection among successful updates must still fail the cycle.
        let first = backlog_batch(&mut server, 0..5, 200, Some(2), 1).await;
        let last = backlog_batch(&mut server, 5..6, 200, None, 1).await;

        let result = processor(&server, false).run().await;
        assert!(matches!(result, Err(Error::DepositUpdatesRejected)));

        for read in reads {
            read.assert_async().await;
        }
        first.assert_async().await;
        last.assert_async().await;
    }

    #[tokio::test]
    async fn http_failure_after_success_stops_without_retrying_batches() {
        let mut server = Server::new_async().await;
        let reads = setup_update_backlog(&mut server, 11).await;
        let first = backlog_batch(&mut server, 0..5, 200, None, 1).await;
        let second = backlog_batch(&mut server, 5..10, 503, None, 1).await;
        let last = backlog_batch(&mut server, 10..11, 200, None, 0).await;

        let result = processor(&server, false).run().await;
        assert!(matches!(
            result,
            Err(Error::EmilyUpdateDeposits(
                private_emily_client::apis::Error::ResponseError(_)
            ))
        ));

        for read in reads {
            read.assert_async().await;
        }
        first.assert_async().await;
        second.assert_async().await;
        last.assert_async().await;
    }
}
