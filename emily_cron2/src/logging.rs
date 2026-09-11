//! Logging setup for text and structured JSON output.

use std::io::IsTerminal as _;

use clap::ValueEnum;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Format used for service logs written to stdout.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LogOutputFormat {
    /// Structured JSON events for log collectors.
    Json,
    /// Human-readable text, with color when stdout is a terminal.
    Pretty,
}

/// Initialize logging, using `RUST_LOG` to override the default directives.
pub fn setup_logging(directives: &str, format: LogOutputFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directives));
    match format {
        LogOutputFormat::Json => setup_logging_json(filter),
        LogOutputFormat::Pretty => setup_logging_pretty(filter),
    }
}

/// Install the structured event format used by the signer.
fn setup_logging_json(filter: EnvFilter) {
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_target(true)
        .with_current_span(false)
        .with_span_list(true)
        .with_line_number(true)
        .with_file(true)
        .with_timer(UtcTime::rfc_3339());

    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
}

/// Install human-readable output with terminal-aware colors.
fn setup_logging_pretty(filter: EnvFilter) {
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(std::io::stdout().is_terminal())
        .with_timer(UtcTime::rfc_3339());

    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
}
