//! File-based sanctions list. A background task periodically fetches a text
//! file (one address per line) and replaces an in-memory `HashSet`.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use reqwest::Client;
use tokio::fs::read_to_string;
use tokio::sync::RwLock;

use crate::common::error::Error;
use crate::common::{BlocklistStatus, RiskSeverity};
use crate::config::SanctionFileConfig;

/// Shared sanctions state.
#[derive(Clone, Default)]
pub struct SanctionsState {
    /// The set of blocked addresses, None until the first successful load.
    blocked_addresses: Arc<RwLock<Option<HashSet<String>>>>,
}

impl SanctionsState {
    /// Replace the blocked addresses set.
    pub async fn replace(&self, blocked_addresses: HashSet<String>) {
        *self.blocked_addresses.write().await = Some(blocked_addresses);
    }

    /// Look up an address in the sanctions set, return an error if the set was
    /// not loaded.
    pub async fn check_address(&self, address: &str) -> Result<BlocklistStatus, Error> {
        let blocked = self
            .blocked_addresses
            .read()
            .await
            .as_ref()
            .ok_or(Error::SanctionsListNotReady)?
            .contains(address);

        if blocked {
            Ok(BlocklistStatus {
                is_blocklisted: true,
                severity: RiskSeverity::Severe,
                accept: false,
                reason: None,
            })
        } else {
            Ok(BlocklistStatus {
                is_blocklisted: false,
                severity: RiskSeverity::Low,
                accept: true,
                reason: None,
            })
        }
    }
}

/// Parse a string containing an address list into the set of addresses.
/// The input string is expected to contain one address per line.
fn parse_address_list(body: &str) -> HashSet<String> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect()
}

/// Read a sanctions text file from disk.
pub async fn load_local(path: &Path) -> Result<HashSet<String>, Error> {
    Ok(parse_address_list(&read_to_string(path).await?))
}

/// Poll the sanctions file and update the sanctions set.
pub async fn run_refresh_loop(
    client: Client,
    config: SanctionFileConfig,
    sanctions_state: SanctionsState,
) {
    loop {
        match fetch_address_list(&client, &config).await {
            Ok(set) => {
                let count = set.len();
                sanctions_state.replace(set).await;
                tracing::info!(count, "refreshed sanctions list");
            }
            Err(error) => tracing::warn!(%error, "failed to refresh sanctions list"),
        }
        tokio::time::sleep(config.polling_interval).await;
    }
}

/// Fetch the address list from the URL specified in the config, then parse it
/// and return the set of addresses.
async fn fetch_address_list(
    client: &Client,
    config: &SanctionFileConfig,
) -> Result<HashSet<String>, Error> {
    let mut req = client.get(config.url.clone());
    if let Some(header) = &config.header {
        req = req.header(&header.key, &header.value);
    }

    let response = req.send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::HttpRequest(
            status,
            format!("upstream returned status {status} while fetching sanctions list"),
        ));
    }
    Ok(parse_address_list(&response.text().await?))
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

    #[tokio::test]
    async fn test_state_not_loaded_by_default() {
        let state = SanctionsState::default();
        assert_matches!(
            state.check_address("test").await,
            Err(Error::SanctionsListNotReady)
        );
    }

    #[tokio::test]
    async fn test_check_address() {
        let sanction_list = sanction_list();
        let state = SanctionsState::default();
        state.replace(sanction_list.clone()).await;

        for addr in sanction_list {
            assert_eq!(
                state.check_address(&addr).await.unwrap(),
                BlocklistStatus {
                    is_blocklisted: true,
                    severity: RiskSeverity::Severe,
                    accept: false,
                    reason: None
                }
            );
        }

        assert_eq!(
            state.check_address("not-an-address").await.unwrap(),
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
        assert_eq!(parse_address_list(SANCTION_LIST_TEXT), sanction_list());
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

        let result = fetch_address_list(&client, &config).await.unwrap();

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
        let result = fetch_address_list(&client, &config).await.unwrap();
        assert_eq!(result, sanction_list());

        // No header
        config.header = None;
        fetch_address_list(&client, &config).await.unwrap_err();

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
        fetch_address_list(&client, &config).await.unwrap_err();

        config.header = None;

        let result = fetch_address_list(&client, &config).await.unwrap();
        assert_eq!(result, sanction_list());

        mock.assert();
    }

    #[tokio::test]
    async fn test_fetch_http_error() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/sanctions")
            .with_status(404)
            .with_body("foo")
            .create();

        let (client, config) = setup_client(&server);

        let result = fetch_address_list(&client, &config).await.unwrap_err();

        mock.assert();
        assert_matches!(
            result,
            Error::HttpRequest(status, _) if status == reqwest::StatusCode::NOT_FOUND
        );
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
        assert_matches!(
            sanctions_state.check_address("test").await,
            Err(Error::SanctionsListNotReady)
        );

        // Wait for another fetch
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            *sanctions_state.blocked_addresses.read().await,
            Some(sanction_list())
        );
    }
}
