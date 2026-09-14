//! Oneshot setup helpers for the sBTC devenv.
//!
//! Bundles the small tasks needed to setup devenv locally. There are three
//! subcommands:
//!
//! - [`aws-setup`](crate::aws_setup): parse the Emily CDK CloudFormation
//!   template and create any missing DynamoDB tables on the local DynamoDB
//!   instance, then touch a readiness sentinel file.
//!
//! - [`wait-and-donate`](crate::donate): wait for the signers to confirm a
//!   `rotate-keys-wrapper` contract call, then broadcast a donation to the
//!   signers' address.
//!
//! - `run`: do both of the above. `aws-setup` and `wait-and-donate` are
//!   independent, so we run them in parallel, exiting with success only
//!   when both have finished.
//!

mod aws_setup;
mod donate;
mod error;
mod stacks;

use clap::Args;
use clap::Parser;
use clap::Subcommand;

use crate::error::Error;

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(name = "devenv-setup", about = "Oneshot devenv setup helpers")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Poll until the signers' aggregate key is set, then send a donation.
    WaitAndDonate(donate::WaitAndDonateArgs),
    /// Create any missing DynamoDB tables described by the Emily CDK template.
    AwsSetup(aws_setup::AwsSetupArgs),
    /// Run `aws-setup` and `wait-and-donate` in parallel; exit once both
    /// have completed. This is the entrypoint the container uses.
    Run(RunArgs),
}

/// Arguments accepted by the combined `run` subcommand.
///
/// Each phase's flag set is flattened in, so every CLI flag and
/// environment variable from `aws-setup` / `wait-and-donate` still works
/// verbatim. None of the flag names collide today; if they ever do, clap
/// will fail at startup.
#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    aws_setup: aws_setup::AwsSetupArgs,
    #[command(flatten)]
    wait_and_donate: donate::WaitAndDonateArgs,
}

/// Process entry point. Initialises tracing, parses the CLI, and
/// dispatches to the chosen subcommand.
#[tokio::main]
async fn main() -> Result<(), Error> {
    init_tracing();

    match Cli::parse().command {
        Command::WaitAndDonate(args) => donate::run(args).await?,
        Command::AwsSetup(args) => aws_setup::run(args).await?,
        Command::Run(args) => {
            // try_join! drops both futures and surfaces the first error if
            // either phase fails. On success the container exits 0.
            tokio::try_join!(
                aws_setup::run(args.aws_setup),
                donate::run(args.wait_and_donate),
            )?;
        }
    };
    tracing::info!("devenv-setup completed successfully");
    Ok(())
}

/// Configure the `tracing` subscriber with sensible defaults. Honour
/// `RUST_LOG` when set, otherwise default to `info`.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
