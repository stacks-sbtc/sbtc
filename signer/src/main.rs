use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::http::Request;
use axum::http::Response;
use cfg_if::cfg_if;
use clap::Parser;
use clap::ValueEnum;
use signer::api;
use signer::api::ApiState;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::bitcoin::zmq::BitcoinCoreMessageStream;
use signer::block_observer;
use signer::blocklist_client::BlocklistClient;
use signer::cli;
use signer::config::Settings;
use signer::context::Context;
use signer::context::SignerContext;
use signer::emily_client::EmilyClient;
use signer::error::Error;
use signer::network::P2PNetwork;
use signer::network::libp2p::SignerSwarmBuilder;
use signer::request_decider::RequestDeciderEventLoop;
use signer::stacks::api::StacksClient;
use signer::storage::postgres::PgStore;
use signer::transaction_coordinator;
use signer::transaction_signer;
use signer::util::ApiFallbackClient;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::Instrument;
use tracing::Span;

// This is how many seconds the P2P swarm will wait before attempting to
// bootstrap (i.e. connect to other peers). Three seconds is a sane default
// value, giving the swarm a few seconds to start up and bind listener(s)
// before proceeding.
const INITIAL_BOOTSTRAP_DELAY_SECS: u64 = 3;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogOutputFormat {
    Json,
    Pretty,
}

/// Command line arguments for the sBTC Signer node.
///
/// The signer node is responsible for participating in distributed key generation (DKG),
/// observing Bitcoin and Stacks events, deciding on sBTC operations (deposits/withdrawals),
/// and coordinating transaction signing with other signers.
#[derive(Debug, Parser)]
#[clap(name = "sBTC Signer", subcommand_required = false)]
struct SignerArgs {
    /// Optional path to the TOML configuration file.
    ///
    /// If not provided, configuration is expected to be provided entirely
    /// via environment variables (e.g., SBTC_SIGNER__DB_ENDPOINT).
    #[clap(short = 'c', long, required = false)]
    config: Option<PathBuf>,

    /// Optional command to execute instead of running the main signer process.
    /// If no command is specified, defaults to 'run'.
    #[clap(subcommand)]
    command: Option<SignerCommand>,
}

/// Specific commands the signer executable can perform.
#[derive(Debug, clap::Subcommand)]
pub enum SignerCommand {
    /// Run the main signer node process (default).
    ///
    /// This starts all core components: P2P network, API server, block observers,
    /// request decider, transaction coordinator, and transaction signer.
    #[clap(name = "run")]
    Run {
        /// Automatically apply pending database migrations on startup.
        #[clap(long)]
        migrate_db: bool,

        /// Set the format for log output.
        #[clap(short = 'o', long = "output-format", default_value = "pretty")]
        output_format: Option<LogOutputFormat>,
    },

    /// Backup critical signer state to a file.
    ///
    /// This command creates a backup of the signer's state, including
    /// _verified_ DKG shares, which can later be restored using the `restore` command.
    #[clap(name = "backup")]
    Backup {
        /// The path where the backup file will be created.
        #[clap(short, long, value_name = "FILE_PATH")]
        path: PathBuf,
    },

    /// Restore critical signer state from a backup file.
    ///
    /// By itself, this command will not restore a file signed by a private key
    /// other than the private key in your configuration file. To override this
    /// (if for example you have changed your private key), use the `--force` flag.
    ///
    /// This command will not overwrite existing state.
    #[clap(name = "restore")]
    Restore {
        /// The path to the backup file to restore from.
        #[clap(short, long, value_name = "FILE_PATH")]
        path: PathBuf,

        /// Force the restoration of a backup file signed by a different private key.
        #[clap(long, value_name = "FORCE")]
        force: bool,
    },
}

/// The main entry point for the sBTC Signer application.
///
/// Parses command-line arguments and dispatches to the appropriate handler:
/// - If the `run` command is specified (or no command is given, defaulting to `run`),
///   it delegates execution to `exec_main`.
/// - If the `backup` or `restore` command is specified, it loads configuration,
///   connects to the database, and calls the corresponding function in the
///   `cli::backups` module.
///
/// # Errors
/// Returns a `Box<dyn std::error::Error>` if:
/// - Command-line argument parsing fails.
/// - Configuration loading fails.
/// - Connecting to the database fails.
/// - The `exec_main`, `backup_signer`, or `restore_backup` functions return an error.
#[tokio::main]
#[tracing::instrument(name = "signer")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse the command line arguments.
    let args = SignerArgs::parse();

    // If the command is `Run` or wasn't specified (defaults to `Run`), simply
    // run the main function and return its result.
    if matches!(args.command, Some(SignerCommand::Run { .. }) | None) {
        return exec_main(args).await;
    }

    // Otherwise, move on to the other utility commands
    println!("=== sBTC Signer (rev. {}) ===", signer::GIT_COMMIT);

    // Load the configuration file and/or environment variables.
    // If the config file is not provided, we will use the default settings.
    let settings = match Settings::new(args.config) {
        Ok(settings) => {
            println!("Configuration file loaded successfully");
            settings
        }
        Err(error) => {
            eprintln!("Failed to load configuration file: {error}");
            return Err(Box::new(error));
        }
    };

    // Open a connection to the database.
    // NOTE: Right now the remaining commands need a db, but we may want to
    // move this later if we add new commands which don't.
    let db = PgStore::connect(settings.signer.db_endpoint.as_str())
        .await
        .map_err(|err| {
            eprintln!("Failed to connect to the database: {err}");
            err
        })?;

    // Execute the correct handler based on the command.
    match args.command {
        // == BACKUP ==
        Some(SignerCommand::Backup { path }) => {
            println!("Preparing to backup signer state to '{}'", path.display());
            cli::backups::backup_signer(&db, &settings.signer.private_key, path)
                .await
                .inspect_err(|error| eprintln!("Failed to backup signer state: {error}"))?;
            println!("Signer state backed up successfully");
        }

        // == RESTORE ==
        Some(SignerCommand::Restore { path, force }) => {
            println!(
                "Preparing to restore signer state from '{}'",
                path.display()
            );
            cli::backups::restore_backup(&db, &settings.signer.private_key, path, force)
                .await
                .inspect_err(|error| eprintln!("Failed to restore signer state: {error}"))?;
            println!("Signer state restored successfully");
        }

        // == UNKNOWN COMMAND==
        _ => {
            return Err("Unknown command".into());
        }
    }

    Ok(())
}

/// Executes the main logic for running the sBTC Signer node.
///
/// This function is called when the `run` command is specified (or when no command
/// is provided, as `run` is the default). It performs the following steps:
///
/// 1. Sets up logging based on the specified output format.
/// 2. Loads configuration from the specified file or environment variables.
/// 3. Sets up Prometheus metrics exporting.
/// 4. Connects to the PostgreSQL database.
/// 5. Applies pending database migrations if the `--migrate-db` flag is set.
/// 6. Initializes the core [`SignerContext`].
/// 7. Bootstraps the initial signer set (currently from configuration).
/// 8. Spawns and runs all core concurrent tasks using [`tokio::join!`]:
///    - API server ([`run_api`])
///    - Libp2p network swarm ([`run_libp2p_swarm`])
///    - Block observers ([`run_block_observer`])
///    - Request decider ([`run_request_decider`])
///    - Transaction coordinator ([`run_transaction_coordinator`])
///    - Transaction signer ([`run_transaction_signer`])
///    - Shutdown signal watcher ([`run_shutdown_signal_watcher`])
/// 9. Uses the [`run_checked`] helper to ensure that if any core task fails,
///    a shutdown signal is broadcast to allow other tasks to terminate gracefully.
///
/// # Arguments
/// * `args` - Parsed command-line arguments, expected to contain the `Run` variant details.
///
/// # Errors
/// Returns a `Box<dyn std::error::Error>` if any critical setup step (like loading
/// configuration, connecting to the database, or applying migrations) fails, or if
/// any of the core concurrent tasks return an error.
async fn exec_main(args: SignerArgs) -> Result<(), Box<dyn std::error::Error>> {
    let Some(SignerCommand::Run { migrate_db, output_format }) = args.command else {
        return Err("BUG: attempting to 'run' using invalid command".into());
    };

    // Configure the binary's stdout/err output based on the provided output format.
    let pretty = matches!(output_format, Some(LogOutputFormat::Pretty));
    signer::logging::setup_logging("info,signer=debug", pretty);

    tracing::info!(
        rust_version = signer::RUSTC_VERSION,
        revision = signer::GIT_COMMIT,
        arch = signer::TARGET_ARCH,
        env_abi = signer::TARGET_ENV_ABI,
        "starting the sBTC signer",
    );

    // Load the configuration file and/or environment variables.
    let settings = Settings::new(args.config).inspect_err(|error| {
        tracing::error!(%error, "failed to construct the configuration");
    })?;

    let signer_public_key = settings.signer.public_key();
    tracing::info!(%signer_public_key, "config loaded successfully");

    signer::metrics::setup_metrics(settings.signer.prometheus_exporter_endpoint);

    // Open a connection to the signer db.
    let db = PgStore::connect(settings.signer.db_endpoint.as_str())
        .await
        .inspect_err(|err| {
            tracing::error!(%err, "failed to connect to the database");
        })?;

    // Apply any pending migrations if automatic migrations are enabled.
    if migrate_db {
        db.apply_migrations().await.inspect_err(|err| {
            tracing::error!(%err, "failed to apply database migrations");
        })?;
    }

    // Initialize the signer context.
    let context = SignerContext::<
        _,
        ApiFallbackClient<BitcoinCoreClient>,
        ApiFallbackClient<StacksClient>,
        ApiFallbackClient<EmilyClient>,
    >::init(settings, db)
    .inspect_err(|err| {
        tracing::error!(%err, "failed to initialize the signer context");
    })?;

    // TODO: We should first check "another source of truth" for the current
    // signing set, and only assume we are bootstrapping if that source is
    // empty.
    let settings = context.config();
    for signer in settings.signer.bootstrap_signing_set() {
        context.state().current_signer_set().add_signer(signer);
    }

    // Run the application components concurrently. We're `join!`ing them
    // here so that every component can shut itself down gracefully when
    // the shutdown signal is received.
    //
    // Note that we must use `join` here instead of `select` as `select` would
    // immediately abort the remaining tasks on the first completion, which
    // deprives the other tasks of the opportunity to shut down gracefully. This
    // is the reason we also use the `run_checked` helper method, which will
    // intercept errors and send a shutdown signal to the other components if an error
    // does occur, otherwise the `join` will continue running indefinitely.
    let _ = tokio::join!(
        // Our global termination signal watcher. This does not run using `run_checked`
        // as it sends its own shutdown signal.
        run_shutdown_signal_watcher(context.clone()),
        // The rest of our services which run concurrently, and must all be
        // running for the signer to be operational.
        run_checked(run_api, &context),
        run_checked(run_libp2p_swarm, &context),
        run_checked(run_block_observer, &context),
        run_checked(run_request_decider, &context),
        run_checked(run_transaction_coordinator, &context),
        run_checked(run_transaction_signer, &context),
    );

    Ok(())
}

/// A helper method that wraps a future representing a core application task.
///
/// It executes the provided future `f`. If the future completes with an `Err`,
/// this function logs the error, signals the application to shut down via the
/// context's termination handle, and returns the original error. This ensures
/// that a failure in one core task triggers a graceful shutdown of others.
///
/// # Arguments
/// * `f` - An async function that takes a context `C` and returns a future `Fut`.
/// * `ctx` - The application context implementing `Context`.
///
/// # Errors
/// Returns the `Error` returned by the inner future `Fut` if it fails.
async fn run_checked<F, Fut, C>(f: F, ctx: &C) -> Result<(), Error>
where
    C: Context,
    F: FnOnce(C) -> Fut,
    Fut: std::future::Future<Output = Result<(), Error>>,
{
    if let Err(error) = f(ctx.clone()).await {
        tracing::error!(%error, "a fatal error occurred; shutting down the application");
        ctx.get_termination_handle().signal_shutdown();
        return Err(error);
    }

    Ok(())
}

/// Runs the shutdown-signal watcher task.
///
/// This task listens for operating system signals indicating termination requests
/// (SIGTERM, SIGHUP, SIGINT on Unix; Ctrl-C elsewhere). Upon receiving such a
/// signal, or if the application's internal shutdown handle is triggered, it
/// signals the rest of the application to shut down gracefully via the context's
/// termination handle.
///
/// # Arguments
/// * `ctx` - The application context implementing `Context`.
///
/// # Errors
/// Returns an `Error` if setting up the OS signal listeners fails.
#[tracing::instrument(skip(ctx), name = "shutdown-watcher")]
async fn run_shutdown_signal_watcher(ctx: impl Context) -> Result<(), Error> {
    let mut term = ctx.get_termination_handle();

    cfg_if! {
        // If we are on a Unix system, we can listen for more signals.
        if #[cfg(unix)] {
            let mut terminate = tokio::signal::unix::signal(signal::unix::SignalKind::terminate())?;
            let mut hangup = tokio::signal::unix::signal(signal::unix::SignalKind::hangup())?;
            let mut interrupt = tokio::signal::unix::signal(signal::unix::SignalKind::interrupt())?;

            tokio::select! {
                // If the shutdown signal is received, we'll shut down the signal watcher
                // by returning early; the rest of the components have already received
                // the shutdown signal.
                _ = term.wait_for_shutdown() => {
                    tracing::info!("termination signal received, signal watcher is shutting down");
                    return Ok(());
                },
                // SIGTERM (kill -15 "nice")
                _ = terminate.recv() => {
                    tracing::info!(signal = "SIGTERM", "received termination signal");
                },
                // SIGHUP (kill -1)
                _ = hangup.recv() => {
                    tracing::info!(signal = "SIGHUP", "received termination signal");
                },
                // Ctrl-C will be received as a SIGINT (kill -2)
                _ = interrupt.recv() => {
                    tracing::info!(signal = "SIGINT", "received termination signal");
                },
            }
        // Otherwise, we'll just listen for Ctrl-C, which is the most portable.
        } else {
            tokio::select! {
                // If the shutdown signal is received, we'll shut down the signal watcher
                // by returning early; the rest of the components have already received
                // the shutdown signal.
                Ok(_) = ctx.wait_for_shutdown() => {
                    tracing::info!("termination signal received, signal watcher is shutting down");
                    return Ok(());
                },
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!(signal = "Ctrl+C", "received termination signal");
                }
            }
        }
    }

    // Send the shutdown signal to the rest of the application.
    tracing::info!("sending shutdown signal to the application");
    term.signal_shutdown();

    Ok(())
}

/// Initializes and runs the libp2p network swarm.
///
/// Configures the swarm based on settings from the context, including listen
/// addresses, seed nodes, transport protocols (TCP, QUIC), and discovery mechanisms
/// (mDNS). It then starts the swarm's event loop, which handles peer connections,
/// message passing, and discovery, running until a shutdown signal is received
/// or an unrecoverable error occurs.
///
/// # Arguments
/// * `ctx` - The application context implementing `Context`.
///
/// # Errors
/// Returns an `Error` if building or starting the libp2p swarm fails.
#[tracing::instrument(skip_all, name = "p2p")]
async fn run_libp2p_swarm(ctx: impl Context) -> Result<(), Error> {
    tracing::info!("initializing the p2p network");

    tracing::debug!("building the libp2p swarm");
    let config = ctx.config();

    let enable_quic = config.signer.p2p.is_quic_used();

    // Limit the number of signers to the maximum number of signer pubkeys we
    // can support. Note that this value is used as a base value for swarm
    // connection limit calculations.
    let num_signers = ctx
        .state()
        .current_signer_set()
        .num_signers()
        .try_into()
        .unwrap_or(signer::MAX_KEYS);

    // Build the swarm.
    let mut swarm = SignerSwarmBuilder::new(&config.signer.private_key)
        .add_listen_endpoints(&ctx.config().signer.p2p.listen_on)
        .add_seed_addrs(&ctx.config().signer.p2p.seeds)
        .add_external_addresses(&ctx.config().signer.p2p.public_endpoints)
        .enable_mdns(config.signer.p2p.enable_mdns)
        .enable_quic_transport(enable_quic)
        .with_initial_bootstrap_delay(Duration::from_secs(INITIAL_BOOTSTRAP_DELAY_SECS))
        .with_num_signers(num_signers)
        .build()?;

    // Start the libp2p swarm. This will run until either the shutdown signal is
    // received, or an unrecoverable error has occurred.
    tracing::info!("starting the libp2p swarm");
    swarm
        .start(&ctx)
        .in_current_span()
        .await
        .map_err(Error::SignerSwarm)
}

/// Initializes and runs the signer's HTTP API server.
///
/// Sets up an Axum web server based on the configuration in the context. It binds
/// to the specified address, configures request tracing, and serves the API routes.
/// The server runs until a shutdown signal is received, at which point it performs
/// a graceful shutdown.
///
/// # Arguments
/// * `ctx` - The application context implementing `Context` and `'static`.
///
/// # Errors
/// Returns an `Error` if binding the TCP listener fails or if the server encounters
/// an unrecoverable error during operation.
#[tracing::instrument(skip_all, name = "api")]
async fn run_api(ctx: impl Context + 'static) -> Result<(), Error> {
    let socket_addr = ctx.config().signer.event_observer.bind;
    tracing::info!(%socket_addr, "initializing the signer API server");

    let state = ApiState { ctx: ctx.clone() };

    let request_id = Arc::new(AtomicU64::new(0));

    // Build the signer API application
    let app = api::get_router()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    tracing::info_span!("api-request",
                        uri = %request.uri(),
                        method = %request.method(),
                        id = tracing::field::Empty,
                    )
                })
                .on_request(move |_: &Request<_>, span: &Span| {
                    span.record("id", request_id.fetch_add(1, Ordering::SeqCst));
                    tracing::trace!("processing request");
                })
                .on_response(|_: &Response<_>, duration: Duration, _: &Span| {
                    tracing::trace!(duration_ms = duration.as_millis(), "request completed");
                }),
        )
        .with_state(state);

    // Bind to the configured address and port
    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .expect("failed to bind the signer API to configured address");

    // Get the termination signal handle.
    let mut term = ctx.get_termination_handle();

    // Run our app with hyper
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // Listen for an application shutdown signal. We need to loop here
            // because we may receive other signals (which we will ignore here).
            term.wait_for_shutdown().await;
            tracing::info!("stopping the signer API server");
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "error running the signer API server");
            ctx.get_termination_handle().signal_shutdown();
            error.into()
        })
}

/// Initializes and runs the block observer event loop.
///
/// Connects to the configured Bitcoin Core ZMQ endpoint to receive notifications
/// about new blocks. It processes these block events, potentially triggering
/// other actions within the signer based on observed Bitcoin transactions.
/// The loop runs until a shutdown signal is received or an error occurs.
///
/// # Arguments
/// * `ctx` - The application context implementing `Context`.
///
/// # Errors
/// Returns an `Error` if connecting to the ZMQ stream fails or if an error occurs
/// during event processing.
async fn run_block_observer(ctx: impl Context) -> Result<(), Error> {
    let config = ctx.config().clone();

    // TODO: Need to handle multiple endpoints, so some sort of
    // failover-stream-wrapper.
    let endpoint = config.bitcoin.block_hash_stream_endpoints[0].as_str();
    let stream = BitcoinCoreMessageStream::new_from_endpoint(endpoint)
        .await
        .unwrap();

    // TODO: We should have a new() method that builds from the context
    let block_observer = block_observer::BlockObserver {
        context: ctx,
        bitcoin_blocks: stream.to_block_hash_stream(),
    };

    block_observer.run().await
}

/// Initializes and runs the transaction signer event loop.
///
/// This task is responsible for participating in distributed signing ceremonies
/// coordinated by other signers. It listens for signing requests over the P2P
/// network and contributes signature shares when required. The loop runs until
/// a shutdown signal is received or an error occurs.
///
/// # Arguments
/// * `ctx` - The application context implementing `Context`.
///
/// # Errors
/// Returns an `Error` if initializing the signer fails or if an error occurs
/// during the event loop.
async fn run_transaction_signer(ctx: impl Context) -> Result<(), Error> {
    let network = P2PNetwork::new(&ctx);

    let signer = transaction_signer::TxSignerEventLoop::new(ctx, network, rand::thread_rng())?;

    signer.run().await
}

/// Initializes and runs the transaction coordinator event loop.
///
/// This task coordinates distributed key generation (DKG) and signing rounds.
/// It initiates signing requests based on decisions made by the request decider
/// and manages the communication and state transitions for these distributed
/// protocols over the P2P network. The loop runs until a shutdown signal is
/// received or an error occurs.
///
/// # Arguments
/// * `ctx` - The application context implementing `Context`.
///
/// # Errors
/// Returns an `Error` if an error occurs during the event loop.
async fn run_transaction_coordinator(ctx: impl Context) -> Result<(), Error> {
    let config = ctx.config().clone();
    let private_key = config.signer.private_key;
    let network = P2PNetwork::new(&ctx);

    let coord = transaction_coordinator::TxCoordinatorEventLoop {
        network,
        context: ctx,
        context_window: config.signer.context_window,
        private_key,
        signing_round_max_duration: config.signer.signer_round_max_duration,
        bitcoin_presign_request_max_duration: config.signer.bitcoin_presign_request_max_duration,
        threshold: config.signer.bootstrap_signatures_required,
        dkg_max_duration: config.signer.dkg_max_duration,
        is_epoch3: false,
    };

    coord.run().await
}

/// Initializes and runs the request decider event loop.
///
/// This task observes events (e.g., from block observers) and makes decisions
/// about whether to initiate sBTC operations like deposits or withdrawals.
/// It may consult external services (like a blocklist) and communicates decisions
/// to the transaction coordinator via the P2P network. The loop runs until a
/// shutdown signal is received or an error occurs.
///
/// # Arguments
/// * `ctx` - The application context implementing `Context`.
///
/// # Errors
/// Returns an `Error` if an error occurs during the event loop.
async fn run_request_decider(ctx: impl Context) -> Result<(), Error> {
    let config = ctx.config().clone();
    let network = P2PNetwork::new(&ctx);

    let decider = RequestDeciderEventLoop {
        network,
        context: ctx.clone(),
        context_window: config.signer.context_window,
        deposit_decisions_retry_window: config.signer.deposit_decisions_retry_window,
        withdrawal_decisions_retry_window: config.signer.withdrawal_decisions_retry_window,
        blocklist_checker: config.blocklist_client.as_ref().map(BlocklistClient::new),
        signer_private_key: config.signer.private_key,
    };

    decider.run().await
}
