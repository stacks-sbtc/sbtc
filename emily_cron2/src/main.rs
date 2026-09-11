//! Standalone Rust service for reconciling Emily deposit statuses.

use std::time::Duration;

use cfg_if::cfg_if;
use clap::Parser as _;
use emily_cron2::config::Config;
use emily_cron2::error::Error;
use emily_cron2::logging;
use emily_cron2::processor::Processor;
use tokio::signal;
use tracing::error;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = Config::parse();
    logging::setup_logging("info", config.output_format);
    let once = config.once;
    let period = Duration::from_secs(config.poll_interval_seconds);
    let processor = Processor::new(config)?;
    if once {
        return processor.run().await;
    }

    // Poll the watcher first so signal registration errors stop the service
    // before it begins reconciling deposits.
    tokio::select! {
        biased;
        result = run_shutdown_signal_watcher() => result?,
        _ = run_reconciliation_loop(&processor, period) => {},
    }
    info!("Emily cron2 stopped");
    Ok(())
}

/// Run sequential reconciliation cycles with a delay after each completed cycle.
async fn run_reconciliation_loop(processor: &Processor, period: Duration) {
    loop {
        if let Err(error) = processor.run().await {
            error!(%error, "Deposit reconciliation failed; retrying next cycle");
        }
        tokio::time::sleep(period).await;
    }
}

/// Listen for SIGHUP, SIGTERM, and SIGINT on Unix, or Ctrl-C on other systems.
#[tracing::instrument(name = "shutdown-watcher")]
async fn run_shutdown_signal_watcher() -> Result<(), Error> {
    cfg_if! {
        if #[cfg(unix)] {
            let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
            let mut hangup = signal::unix::signal(signal::unix::SignalKind::hangup())?;
            let mut interrupt = signal::unix::signal(signal::unix::SignalKind::interrupt())?;

            tokio::select! {
                _ = terminate.recv() => {
                    info!(signal = "SIGTERM", "received termination signal");
                },
                _ = hangup.recv() => {
                    info!(signal = "SIGHUP", "received termination signal");
                },
                _ = interrupt.recv() => {
                    info!(signal = "SIGINT", "received termination signal");
                },
            }
        } else {
            signal::ctrl_c().await?;
            info!(signal = "Ctrl+C", "received termination signal");
        }
    }

    // There is one worker future here; returning lets main stop it directly.
    info!("shutting down the application");
    Ok(())
}
