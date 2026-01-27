//! Emily API entrypoint.

use emily_handler::context::EmilyContext;
use tracing::{info, info_span};

use emily_handler::api;
use emily_handler::logging;
use warp::Filter as _;

#[tokio::main]
async fn main() {
    // Setup logging.
    logging::setup_logging("info,emily_handler=debug", false);

    // Setup context.
    let context: EmilyContext = EmilyContext::from_env()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    info!(lambdaContext = ?context);

    // Create CORS configuration
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST", "OPTIONS"])
        .allow_headers(vec!["content-type", "x-api-key"])
        .build();

    // Setup service filters.
    let service_filter = api::routes::routes_with_stage_prefix(context)
        .recover(api::handlers::handle_rejection)
        .with(warp::trace(|info| {
            let request_id = info
                .request_headers()
                .get("x-amz-request-id")
                .and_then(|val| val.to_str().ok())
                .unwrap_or("unknown");
            info_span!("aws-request", request_id = %request_id)
        }))
        .with(warp::log("api"))
        .with(cors);

    // Create warp service.
    let warp_service = warp::service(service_filter);
    warp_lambda::run(warp_service)
        .await
        .expect("An error occurred");
}
