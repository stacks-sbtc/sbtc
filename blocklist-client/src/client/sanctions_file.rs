//! File-based sanctions list. A background task periodically fetches a text
//! file (one address per line) and replaces an in-memory `HashSet`.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use reqwest::Client;
use tokio::fs::read_to_string;

use crate::common::error::Error;
use crate::common::{BlocklistStatus, RiskSeverity};
use crate::config::SanctionFileConfig;

/// Shared sanctions state. Tracks whether the list has been populated at least
/// once so callers can fail-closed before the first successful load.
#[derive(Clone, Default)]
pub struct SanctionsState {
    addresses: Arc<RwLock<HashSet<String>>>,
    loaded: Arc<AtomicBool>,
}

impl SanctionsState {
    /// Whether the sanctions list has been populated at least once.
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }

    /// Replace the in-memory addresses and mark the state as loaded.
    pub fn load(&self, addresses: HashSet<String>) {
        *self.addresses.write().expect("sanctions lock poisoned") = addresses;
        self.loaded.store(true, Ordering::Release);
    }

    /// Look up an address in the sanctions set.
    pub fn check_address(&self, address: &str) -> BlocklistStatus {
        let blocked = self
            .addresses
            .read()
            .expect("sanctions lock poisoned")
            .contains(address);

        if blocked {
            BlocklistStatus {
                is_blocklisted: true,
                severity: RiskSeverity::Severe,
                accept: false,
                reason: None,
            }
        } else {
            BlocklistStatus {
                is_blocklisted: false,
                severity: RiskSeverity::Low,
                accept: true,
                reason: None,
            }
        }
    }
}

fn parse(body: &str) -> HashSet<String> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect()
}

/// Read a sanctions text file from disk.
pub async fn load_local(path: &Path) -> Result<HashSet<String>, Error> {
    Ok(parse(&read_to_string(path).await?))
}

/// Poll the sanctions file and update the sanctions set.
pub async fn run_refresh_loop(
    client: Client,
    config: SanctionFileConfig,
    sanctions_state: SanctionsState,
) {
    loop {
        match fetch(&client, &config).await {
            Ok(set) => {
                let count = set.len();
                sanctions_state.load(set);
                tracing::info!(count, "refreshed sanctions list");
            }
            Err(err) => tracing::warn!(%err, "failed to refresh sanctions list"),
        }
        tokio::time::sleep(config.polling_interval).await;
    }
}

async fn fetch(client: &Client, config: &SanctionFileConfig) -> Result<HashSet<String>, Error> {
    let mut req = client.get(config.url.clone());
    if let Some(header) = &config.header {
        req = req.header(&header.key, &header.value);
    }

    let body = req.send().await?.error_for_status()?.text().await?;
    Ok(parse(&body))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use url::Url;

    use super::*;
    use assert_matches::assert_matches;
    use mockito::{Matcher, Server, ServerGuard};

    const SANCTION_LIST_TEXT: &str = include_str!("../../tests/fixtures/sanction_list.txt");

    /// Return the parsed content of `SANCTION_LIST_TEXT`
    fn sanction_list() -> HashSet<String> {
        vec![
            "123WBUDmSJv4GctdVEz6Qq6z8nXSKrJ4KX",
            "bc1qq7p0es3dv5hcynjjf40f2xjjr6qp5py47d2f6n847vduuq9gvnyq7y9ecd",
            "bc1qzqqdvukupr0qr5uckn2zjn40mkflnxu8fuuqdp",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    // Setup function for common client and configuration
    fn setup_client(server: &ServerGuard) -> (Client, SanctionFileConfig) {
        let client = Client::new();
        let url = Url::parse(&format!("{}/sanctions", server.url())).unwrap();
        let config = SanctionFileConfig {
            url,
            header: Some(crate::config::SanctionFileConfigHeader {
                key: "x-api-key".to_owned(),
                value: "my-api-key".to_owned(),
            }),
            polling_interval: Duration::from_secs(3600),
            local_path: None,
        };
        (client, config)
    }

    #[test]
    fn test_state_not_loaded_by_default() {
        let state = SanctionsState::default();
        assert!(!state.is_loaded());
    }

    #[test]
    fn test_state_load_marks_loaded() {
        let state = SanctionsState::default();
        state.load(sanction_list());
        assert!(state.is_loaded());
        assert_eq!(*state.addresses.read().unwrap(), sanction_list());
    }

    #[test]
    fn test_check_address() {
        let sanction_list = sanction_list();
        let state = SanctionsState::default();
        state.load(sanction_list.clone());

        for addr in sanction_list {
            assert_eq!(
                state.check_address(&addr),
                BlocklistStatus {
                    is_blocklisted: true,
                    severity: RiskSeverity::Severe,
                    accept: false,
                    reason: None
                }
            );
        }

        assert_eq!(
            state.check_address("not-an-address"),
            BlocklistStatus {
                is_blocklisted: false,
                severity: RiskSeverity::Low,
                accept: true,
                reason: None
            }
        );
    }

    #[test]
    fn test_parse() {
        assert_eq!(parse(SANCTION_LIST_TEXT), sanction_list());
    }

    #[tokio::test]
    async fn test_fetch() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/sanctions")
            .match_header("x-api-key", "my-api-key")
            .with_status(200)
            .with_body(SANCTION_LIST_TEXT)
            .create();

        let (client, config) = setup_client(&server);

        let result = fetch(&client, &config).await.unwrap();

        mock.assert();
        assert_eq!(result, sanction_list());
    }

    #[tokio::test]
    async fn test_fetch_fails_when_header_absent() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/sanctions")
            .match_header("x-api-key", "my-api-key")
            .with_status(200)
            .with_body(SANCTION_LIST_TEXT)
            .create();

        let (client, mut config) = setup_client(&server);

        // Sanity check with the expected header
        let result = fetch(&client, &config).await.unwrap();
        assert_eq!(result, sanction_list());

        // No header
        config.header = None;
        fetch(&client, &config).await.unwrap_err();

        mock.assert();
    }

    #[tokio::test]
    async fn test_fetch_no_header() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/sanctions")
            .match_header("x-api-key", Matcher::Missing)
            .with_status(200)
            .with_body(SANCTION_LIST_TEXT)
            .create();

        let (client, mut config) = setup_client(&server);

        // Sanity check with the unexpected header
        fetch(&client, &config).await.unwrap_err();

        config.header = None;

        let result = fetch(&client, &config).await.unwrap();
        assert_eq!(result, sanction_list());

        mock.assert();
    }

    #[tokio::test]
    async fn test_fetch_fail() {
        let server = Server::new_async().await;

        let (client, config) = setup_client(&server);

        let result = fetch(&client, &config).await.unwrap_err();

        assert_matches!(result, Error::Network(_));
    }

    #[tokio::test]
    async fn test_run_refresh_loop() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/sanctions")
            .with_status(500)
            .expect(1)
            .create();

        let _ok_mock = server
            .mock("GET", "/sanctions")
            .with_status(200)
            .with_body(SANCTION_LIST_TEXT)
            .create();

        let (client, mut config) = setup_client(&server);
        config.polling_interval = Duration::from_secs(1);

        let sanctions_state = SanctionsState::default();

        let refresh_state = sanctions_state.clone();
        tokio::spawn(async move {
            run_refresh_loop(client, config, refresh_state).await;
        });

        // Yield to task
        tokio::time::sleep(Duration::from_millis(10)).await;
        mock.assert();
        assert!(!sanctions_state.is_loaded());

        // Wait for another fetch
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(sanctions_state.is_loaded());
        assert_eq!(*sanctions_state.addresses.read().unwrap(), sanction_list());
    }
}
