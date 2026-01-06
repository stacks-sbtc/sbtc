//! Emily Warp Service Binary.

use axum::http::HeaderName;
use axum::http::Method;
use axum::http::Request;
use axum::http::header::CONTENT_TYPE;
use clap::Args;
use clap::Parser;
use emily_handler::context::EmilyContext;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use emily_handler::api;
use emily_handler::logging;

/// The arguments for the Emily server.
#[derive(Parser, Debug)]
#[command(
    name = "EmilyServer",
    version = "1.0",
    author = "Ashton Stephens <ashton@trustmachines.co>",
    about = "Local emily server binary"
)]
pub struct Cli {
    /// Server arguments.
    #[command(flatten)]
    pub server: ServerArgs,
    /// General arguments.
    #[command(flatten)]
    pub general: GeneralArgs,
}

/// General arguments.
#[derive(Args, Debug)]
pub struct GeneralArgs {
    /// Whether to use pretty log printing.
    #[arg(long, default_value = "false")]
    pub pretty_logs: bool,
    /// Log directives.
    #[arg(long, default_value = "info,emily_handler=debug,api=debug")]
    pub log_directives: String,
    /// DynamoDB endpoint.
    #[arg(long, default_value = "http://localhost:8000")]
    pub dynamodb_endpoint: String,
    /// Whether to skip finding the dynamodb tables on startup. If true, table
    /// names must be provided in each request via `x-context-*` headers.
    #[arg(long, default_value = "false")]
    pub skip_tables: bool,
}

/// Server related arguments.
#[derive(Args, Debug)]
pub struct ServerArgs {
    /// Host.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Port to run on.
    #[arg(long, default_value = "3031")]
    pub port: u64,
}

/// Main program.
#[tokio::main]
async fn main() {
    // Get command line arguments.
    let Cli {
        server: ServerArgs { host, port },
        general:
            GeneralArgs {
                pretty_logs,
                log_directives,
                dynamodb_endpoint,
                skip_tables,
            },
    } = Cli::parse();

    // Setup logging.
    logging::setup_logging(&log_directives, pretty_logs);

    // Setup context.
    // TODO(389 + 358): Handle config pickup in a way that will only fail for the relevant call.
    let context: EmilyContext = EmilyContext::local_instance(&dynamodb_endpoint, skip_tables)
        .await
        .unwrap();
    info!(lambdaContext = ?context);

    // Create CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, HeaderName::from_static("x-api-key")]);

    // Create address.
    let addr_str = format!("{host}:{port}");
    info!("Server will run locally on {}", addr_str);
    let addr: std::net::SocketAddr = addr_str.parse().expect("Failed to parse address");

    let app = api::routes::routes_axum()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    tracing::info_span!("api-request",
                        uri = %request.uri(),
                        method = %request.method(),
                        id = tracing::field::Empty,
                    )
                })
                .on_response(api::routes::axum_log_response),
        )
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(
            context.clone(),
            api::routes::inject_request_context,
        ))
        .with_state(context);

    // Bind to the configured address and port
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind the emily API to configured address");

    // Run our app with hyper
    axum::serve(listener, app).await.unwrap();
}
