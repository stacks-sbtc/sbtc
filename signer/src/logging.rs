//! This module sets up logging for the application using `tracing_subscriber`
//! It provides functions to initialize logging in either JSON format or pretty format

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::api::build_info;
use crate::context::Context;

use std::time::Duration;

/// Sets up logging based on the provided format preference
///
/// # Arguments
///
/// - `pretty` - A boolean that determines if the logging format should be pretty or JSON
pub fn setup_logging(directives: &str, pretty: bool) {
    match pretty {
        true => setup_logging_pretty(directives),
        false => setup_logging_json(directives),
    }
}

fn setup_logging_json(directives: &str) {
    let main_layer = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_target(true)
        .with_current_span(false)
        .with_span_list(true)
        .with_line_number(true)
        .with_file(true)
        .with_timer(UtcTime::rfc_3339());

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directives)))
        .with(main_layer)
        .init()
}

fn setup_logging_pretty(directives: &str) {
    let main_layer = tracing_subscriber::fmt::layer().with_timer(UtcTime::rfc_3339());

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directives)))
        .with(main_layer)
        .init()
}

/// Logs to standard logging stream information about Bitcoin and Stacks
/// node versions, chaintips, dkg rounds, etc.
async fn log_blockchain_nodes_info<C: Context>(ctx: &C) {
    let info = build_info(ctx).await;
    let json = serde_json::to_string(&info).unwrap_or_else(|_| format!("{info:?}"));
    tracing::debug!(info = %json, "signer info");
}

/// Simple struct for time to time writing logs
/// about Stacks and Bitcoin nodes state, info about DKG,
/// signer config, etc.
pub struct SignerInfoLogger<C> {
    /// Signer context.
    context: C,
    /// Logging interval.
    interval: Duration,
}

impl<C> SignerInfoLogger<C>
where
    C: Context,
{
    /// Creates new SignerInfoLogger with given context and interval.
    pub fn new(context: C, interval: Duration) -> Self {
        Self { context, interval }
    }
    /// Runs SignerInfoLogger which will log info about stacks & bitcoin nodes,
    /// last dkg, signer config, etc, each [`interval`].
    pub async fn run(self) {
        let mut term = self.context.get_termination_handle();
        log_blockchain_nodes_info(&self.context).await;
        loop {
            tokio::select! {
                _ = term.wait_for_shutdown() => {
                    break;
                }
                _ = tokio::time::sleep(self.interval) => {
                    log_blockchain_nodes_info(&self.context).await;
                }
            }
        }
        tracing::info!("blockchain info logger has stopped");
    }
}
