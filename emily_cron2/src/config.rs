//! Runtime configuration from CLI flags and environment variables.

use clap::Parser;

use crate::logging::LogOutputFormat;

/// Endpoints, reconciliation thresholds, and scheduling options.
#[derive(Parser)]
#[command(about = "Reconcile Emily deposit statuses against Bitcoin")]
pub struct Config {
    /// Log output format: human-readable text or structured JSON.
    #[arg(short = 'o', long, value_enum, default_value = "json")]
    pub output_format: LogOutputFormat,

    /// Base URL for reading and updating Emily deposits.
    #[arg(
        long,
        env = "PRIVATE_EMILY_ENDPOINT",
        default_value = "http://emily-server:3031"
    )]
    pub private_emily_endpoint: String,

    /// API key used to authenticate Emily requests.
    #[arg(
        long,
        env = "EMILY_API_KEY",
        default_value = "",
        hide_env_values = true
    )]
    pub emily_api_key: String,

    /// Base URL for Bitcoin transaction and replacement lookups.
    #[arg(
        long,
        env = "MEMPOOL_API_URL",
        default_value = "http://mempool-api:8999/api"
    )]
    pub mempool_api_url: String,

    /// Base URL for Bitcoin output spending information.
    #[arg(long, env = "ELECTRS_API_URL", default_value = "http://electrs:3002")]
    pub electrs_api_url: String,

    /// Base URL for Stacks block timestamps.
    #[arg(long, env = "HIRO_API_URL", default_value = "https://api.hiro.so")]
    pub hiro_api_url: String,

    /// Extra Bitcoin blocks required before expiry or RBF updates are applied.
    #[arg(long, env = "MIN_BLOCK_CONFIRMATIONS", default_value_t = 6)]
    pub min_block_confirmations: u64,

    /// Maximum age in seconds for a pending deposit missing from the mempool.
    #[arg(long, env = "MAX_UNCONFIRMED_TIME", default_value_t = 86400)]
    pub max_unconfirmed_time: u64,

    /// Run a single cycle and exit (for an external scheduler).
    #[arg(long)]
    pub once: bool,

    /// Log proposed updates without writing them to Emily.
    #[arg(long)]
    pub dry_run: bool,

    /// Delay in seconds after each completed cycle before the next begins.
    #[arg(long, env = "POLL_INTERVAL_SECONDS", default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..))]
    pub poll_interval_seconds: u64,
}
