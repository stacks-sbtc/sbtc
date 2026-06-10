//! Oneshot setup helpers for the sBTC devenv.
//!
//! This binary bundles small one-and-done tasks that the local devenv needs:
//!
//! - `wait-and-donate`: wait for the signers to confirm a `rotate-keys-wrapper`
//!   contract call (i.e. `get-current-signers-aggregate-key` returns `Some`),
//!   then broadcast a donation to the signers' bitcoin address and exit.
//! - `aws-setup`: parse the Emily CDK CloudFormation template and create any
//!   missing DynamoDB tables on the local DynamoDB instance. Replaces the
//!   `docker/sbtc/emily-aws-setup/initialize.py` script.

mod aws_setup;
mod donate;
mod error;

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
    /// Run `aws-setup` then `wait-and-donate` in sequence. The container only
    /// exits once both have completed.
    Run(RunArgs),
}

/// Arguments accepted by the combined `run` subcommand. Each phase's flags are
/// flattened in so every flag and environment variable still works.
#[derive(Debug, clap::Args)]
struct RunArgs {
    #[command(flatten)]
    aws_setup: aws_setup::AwsSetupArgs,
    #[command(flatten)]
    wait_and_donate: donate::WaitAndDonateArgs,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::WaitAndDonate(args) => donate::run(args).await,
        Command::AwsSetup(args) => aws_setup::run(args).await,
        Command::Run(args) => {
            tokio::try_join!(
                aws_setup::run(args.aws_setup),
                donate::run(args.wait_and_donate),
            )?;
            Ok(())
        }
    }
}
