//! Binary entry point: configure logging, run cycles, stop on signal.

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

    // Register signals before the first cycle so setup errors exit cleanly.
    tokio::select! {
        biased;
        result = wait_for_shutdown_signal() => result?,
        _ = run_reconciliation_loop(&processor, period) => {},
    }

    info!("Emily cron2 stopped");
    Ok(())
}

/// Run cycles forever, sleeping `period` after each completed attempt.
async fn run_reconciliation_loop(processor: &Processor, period: Duration) {
    loop {
        if let Err(error) = processor.run().await {
            error!(%error, "Deposit reconciliation failed; retrying next cycle");
        }
        tokio::time::sleep(period).await;
    }
}

/// Wait for SIGHUP / SIGTERM / SIGINT on Unix, or Ctrl-C elsewhere.
#[tracing::instrument(name = "shutdown-watcher")]
async fn wait_for_shutdown_signal() -> Result<(), Error> {
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

    info!("shutting down the application");
    Ok(())
}
