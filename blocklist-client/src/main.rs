use std::time::Duration;

use crate::client::sanctions_file::{self, SanctionsState};
use crate::config::SETTINGS;
use reqwest::Client;
use warp::Filter;

mod api;
mod client;
mod common;
mod config;

#[tokio::main]
async fn main() {
    blocklist_client::logging::setup_logging(false);

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    let sanctions_state = SanctionsState::default();

    if let Some(sanctions_config) = SETTINGS.sanctions.clone() {
        if let Some(path) = &sanctions_config.local_path {
            let local_sanctions = sanctions_file::load_local(path)
                .await
                .expect("failed to preload sanctions list from local file");

            tracing::info!(
                count = local_sanctions.len(),
                path = %path.display(),
                "preloaded sanctions list from local file"
            );
            sanctions_state.replace(local_sanctions).await;
        }

        let refresh_sanctions_state = sanctions_state.clone();
        let refresh_client = client.clone();
        tokio::spawn(async move {
            sanctions_file::run_refresh_loop(
                refresh_client,
                sanctions_config,
                refresh_sanctions_state,
            )
            .await;
        });
    }

    let routes = api::routes::routes(client, sanctions_state)
        .recover(api::handlers::handle_rejection)
        .with(warp::log("api"));

    let addr_str = format!("{}:{}", SETTINGS.server.host, SETTINGS.server.port);
    tracing::info!("Server will run on {}", addr_str);

    let addr: std::net::SocketAddr = addr_str.parse().expect("Failed to parse address");

    warp::serve(routes).run(addr).await;
}
