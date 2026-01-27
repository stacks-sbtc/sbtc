//! Emily API entrypoint.

use emily_handler::context::EmilyContext;
use tracing::{info, info_span};

use emily_handler::api;
use emily_handler::logging;
use warp::Filter as _;

#[tokio::main]
async fn main() {
    // Setup logging.
    // TODO(TBD): Make the logging configurable.
    logging::setup_logging("info,emily_handler=debug", false);

    // Setup context.
    // TODO(389 + 358): Handle config pickup in a way that will only fail for the relevant call.
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
        // INJECT REQUEST ID HERE
        .with(warp::trace(|info| {
            // We use the header because warp::trace::Info does not access Request Extensions
            let request_id = info.request_headers()
                .get("x-amz-request-id")
                .and_then(|val| val.to_str().ok())
                .unwrap_or("unknown");

            // Create the span. All logs inside the request will inherit this.
            // We use 'request_id' as the key as it is the standard convention.
            info_span!("aws-request", request_id = %request_id)
        }))
        .with(warp::log("api"))
        .with(cors);

    // Create warp service.
    // TODO(276): Remove warp_lambda in Emily API and use different library.
    let warp_service = warp::service(service_filter);
    warp_lambda::run(warp_service)
        .await
        .expect("An error occurred");
}
