//! Deposit reconciliation through Emily, mempool, Electrs, and Hiro APIs.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use private_emily_client::apis::configuration::{ApiKey, Configuration};
use private_emily_client::apis::deposit_api;
use private_emily_client::models::{
    DepositInfo, DepositStatus, DepositUpdate, UpdateDepositsRequestBody,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use tracing::{info, warn};

use crate::config::Config;
use crate::error::Error;
use crate::model::{Block, Outspend, Rbf, Transaction, expired, lock_time};

/// Reconciles Emily deposits using Bitcoin and Stacks API data.
pub struct Processor {
    /// Endpoints, credentials, and reconciliation thresholds.
    config: Config,
    /// Shared HTTP client with a timeout for every request.
    client: Client,
    /// Generated Emily client configuration with isolated authentication headers.
    emily: Configuration,
}

impl Processor {
    /// Create a processor with a reusable HTTP client.
    pub fn new(config: Config) -> Result<Self, Error> {
        let timeout = Duration::from_secs(30);
        let client = Client::builder().timeout(timeout).build()?;

        // The generated read endpoint does not attach the API key itself.
        // Keep default authentication headers on a separate Emily-only client.
        let mut api_key = HeaderValue::from_str(&config.emily_api_key)?;
        api_key.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", api_key);
        let emily_client = Client::builder()
            .timeout(timeout)
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

    /// Join a base URL and an API path.
    fn url(base: &str, path: &str) -> String {
        format!("{}{path}", base.trim_end_matches('/'))
    }

    async fn get<T>(&self, base: &str, path: &str) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        Ok(self
            .client
            .get(Self::url(base, path))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Fetch a Bitcoin transaction, treating only HTTP 404 as missing.
    async fn transaction(&self, txid: &str) -> Result<Option<Transaction>, Error> {
        let host = reqwest::Url::parse(&self.config.mempool_api_url)?;
        let hostname = host.host_str().unwrap_or_default();
        let hosted_mempool = hostname == "mempool.space" || hostname.ends_with(".mempool.space");
        let prefix = if hosted_mempool { "/tx" } else { "/v1/tx" };
        let response = self
            .client
            .get(Self::url(
                &self.config.mempool_api_url,
                &format!("{prefix}/{txid}"),
            ))
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(response.error_for_status()?.json().await?))
    }

    /// Fetch every Emily page for the requested deposit status.
    async fn deposits(&self, status: DepositStatus) -> Result<Vec<DepositInfo>, Error> {
        let mut deposits = Vec::new();
        let mut token = None;
        let mut seen = HashSet::new();
        loop {
            let page =
                deposit_api::get_deposits(&self.emily, status, token.as_deref(), None).await?;
            deposits.extend(page.deposits);
            token = page.next_token.flatten().filter(|t| !t.is_empty());
            match &token {
                None => break,
                Some(token) if !seen.insert(token.clone()) => {
                    return Err(Error::RepeatedPaginationToken);
                }
                _ => {}
            }
        }
        Ok(deposits)
    }

    /// Find a sufficiently confirmed replacement transaction.
    async fn replacement(
        &self,
        deposit: &DepositInfo,
        tip: u64,
        cache: &mut HashMap<String, Option<Transaction>>,
    ) -> Result<Option<DepositUpdate>, Error> {
        let rbf: Rbf = self
            .get(
                &self.config.mempool_api_url,
                &format!("/v1/tx/{}/rbf", deposit.bitcoin_txid),
            )
            .await?;
        let mut txids = Vec::new();
        if let Some(root) = rbf.replacements {
            root.txids(&mut txids);
        }
        for txid in txids {
            if txid == deposit.bitcoin_txid {
                continue;
            }
            if !cache.contains_key(&txid) {
                cache.insert(txid.clone(), self.transaction(&txid).await?);
            }
            let Some(transaction) = cache.get(&txid).and_then(Option::as_ref) else {
                continue;
            };
            let Some(height) = transaction.confirmed_height() else {
                continue;
            };
            let replacement_is_final = expired(height, 0, self.config.min_block_confirmations, tip);
            if replacement_is_final {
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

    /// Check whether an expired output is unspent or reclaimed.
    async fn expired_update(
        &self,
        deposit: &DepositInfo,
        height: u64,
        tip: u64,
    ) -> Result<Option<DepositUpdate>, Error> {
        let reclaim_delay = lock_time(&deposit.reclaim_script)?;
        let deposit_has_expired = expired(
            height,
            reclaim_delay,
            self.config.min_block_confirmations,
            tip,
        );
        if !deposit_has_expired {
            return Ok(None);
        }
        let outspend: Outspend = self
            .get(
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
        let Some(transaction) = self.transaction(&txid).await? else {
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

    /// Determine at most one status update for a deposit.
    async fn reconcile(
        &self,
        deposit: &DepositInfo,
        tip: u64,
        now: u64,
        transactions: &mut HashMap<String, Option<Transaction>>,
        blocks: &mut HashMap<String, u64>,
    ) -> Result<Option<DepositUpdate>, Error> {
        let txid = &deposit.bitcoin_txid;
        if !transactions.contains_key(txid) {
            transactions.insert(txid.clone(), self.transaction(txid).await?);
        }
        let transaction = transactions.get(txid).and_then(Option::as_ref);
        if let Some(height) = transaction.and_then(Transaction::confirmed_height) {
            return self.expired_update(deposit, height, tip).await;
        }
        let missing = transaction.is_none();
        // Replacements may no longer be pending/accepted deposits in Emily,
        // and the original transaction may already be absent from the mempool.
        if let Some(update) = self.replacement(deposit, tip, transactions).await? {
            return Ok(Some(update));
        }
        if missing && deposit.status == DepositStatus::Pending {
            return self.pending_update(deposit, now, blocks).await;
        }
        Ok(None)
    }

    /// Check the age of a pending deposit whose Bitcoin transaction is missing.
    async fn pending_update(
        &self,
        deposit: &DepositInfo,
        now: u64,
        blocks: &mut HashMap<String, u64>,
    ) -> Result<Option<DepositUpdate>, Error> {
        let hash = &deposit.last_update_block_hash;
        if !blocks.contains_key(hash) {
            let block: Block = self
                .get(
                    &self.config.hiro_api_url,
                    &format!("/extended/v2/blocks/{hash}"),
                )
                .await?;
            blocks.insert(hash.clone(), block.block_time);
        }
        let pending_age = now.saturating_sub(blocks[hash]);
        if pending_age > self.config.max_unconfirmed_time {
            return Ok(Some(deposit_update(
                deposit,
                DepositStatus::Failed,
                format!(
                    "Pending for too long ({} seconds)",
                    self.config.max_unconfirmed_time
                ),
                None,
            )));
        }
        Ok(None)
    }

    /// Fetch deposits, determine status changes, and submit or preview updates.
    pub async fn run(&self) -> Result<(), Error> {
        let tip: u64 = self
            .get(&self.config.mempool_api_url, "/v1/blocks/tip/height")
            .await?;
        let mut deposits = self.deposits(DepositStatus::Pending).await?;
        deposits.extend(self.deposits(DepositStatus::Accepted).await?);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut transactions = HashMap::new();
        let mut blocks = HashMap::new();
        let mut seen = HashSet::new();
        let mut updates = Vec::new();
        let mut failed = false;
        for deposit in deposits {
            let outpoint = (
                deposit.bitcoin_txid.clone(),
                deposit.bitcoin_tx_output_index,
            );
            if !seen.insert(outpoint) {
                continue;
            }
            let result = self
                .reconcile(&deposit, tip, now, &mut transactions, &mut blocks)
                .await;
            match result {
                Ok(Some(update)) => updates.push(update),
                Ok(None) => {}
                Err(error) => {
                    failed = true;
                    warn!(txid = %deposit.bitcoin_txid, vout = deposit.bitcoin_tx_output_index,
                        %error, "Skipping deposit with incomplete data");
                }
            }
        }
        info!(
            tip,
            updates = updates.len(),
            dry_run = self.config.dry_run,
            "Deposit reconciliation completed"
        );
        if self.config.dry_run {
            info!(updates = %serde_json::to_string(&updates)?, "Proposed deposit updates");
        } else if !updates.is_empty() {
            self.submit_updates(&updates).await?;
        }
        if failed {
            return Err(Error::IncompleteReconciliation);
        }
        Ok(())
    }

    /// Submit a batch and check each individual result, including partial failures.
    async fn submit_updates(&self, updates: &[DepositUpdate]) -> Result<(), Error> {
        let request = UpdateDepositsRequestBody::new(updates.to_vec());
        let response = deposit_api::update_deposits_sidecar(&self.emily, request).await?;
        if response.deposits.len() != updates.len() {
            return Err(Error::UnexpectedUpdateCount {
                expected: updates.len(),
                actual: response.deposits.len(),
            });
        }
        let mut failed = false;
        for outcome in response.deposits {
            // The generated schema distinguishes an omitted error from JSON null.
            let error = outcome.error.flatten();
            let succeeded = (200..300).contains(&outcome.status) && error.is_none();
            if !succeeded {
                failed = true;
                warn!(status = outcome.status, error = ?error, "Emily rejected deposit update");
            }
        }
        if failed {
            return Err(Error::DepositUpdatesRejected);
        }
        Ok(())
    }
}

/// Build an Emily update using the generated wire types.
fn deposit_update(
    deposit: &DepositInfo,
    status: DepositStatus,
    message: String,
    replacement: Option<String>,
) -> DepositUpdate {
    let mut update = DepositUpdate::new(
        deposit.bitcoin_tx_output_index,
        deposit.bitcoin_txid.clone(),
        status,
        message,
    );
    update.replaced_by_tx = replacement.map(Some);
    update
}
