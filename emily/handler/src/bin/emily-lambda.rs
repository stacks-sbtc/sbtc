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
            let headers = info.request_headers();
            // Iterate over every header and format it into a string
            let all_headers_dump = headers
                .iter()
                .map(|(k, v)| {
                    // Handle potential non-string values safely
                    let val = v.to_str().unwrap_or("<binary>");
                    format!("{}: {}", k, val)
                })
                .collect::<Vec<_>>()
                .join(" | "); // Separator for readability in logs

            // Create span. The 'all_headers' field will contain the full dump.
            info_span!("request", all_headers = %all_headers_dump)
        }))
        .with(warp::log("api"))
        .with(cors);

    // REMOVE ME

    // Create warp service.
    let warp_service = warp::service(service_filter);
    warp_lambda::run(warp_service)
        .await
        .expect("An error occurred");
}
