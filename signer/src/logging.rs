//! This module sets up logging for the application using `tracing_subscriber`
//! It provides functions to initialize logging in either JSON format or pretty format

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::api::build_info;
use crate::context::Context;
use crate::error::Error;

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
    tracing::debug!(?info, "logging blockchain info",);
}

/// Simple struct for time to time writing logs
/// about Stacks and Bitcoin nodes state.
pub struct BlockchainInfoLogger<Context> {
    /// Signer context.
    context: Context,
    /// Logging period.
    timeout: Duration,
}

impl<C> BlockchainInfoLogger<C>
where
    C: Context,
{
    /// Creates new BlockchainInfoLogger with given context and timeout.
    pub fn new(context: C, timeout: Duration) -> Self {
        Self { context, timeout }
    }
    /// Runs BlockchainInfoLogger which will log info about blockchain nodes
    /// each timeout.
    pub async fn run(self) {
        let term = self.context.get_termination_handle();
        loop {
            if term.shutdown_signalled() {
                break;
            }
            tokio::time::sleep(self.timeout).await;
            log_blockchain_nodes_info(&self.context).await;
        }
        tracing::info!("blockchain info logger has stopped");
    }
}
