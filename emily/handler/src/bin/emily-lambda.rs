//! Emily API entrypoint.

use axum::Router;
use axum::http::HeaderName;
use axum::http::Method;
use axum::http::Request;
use axum::http::header::CONTENT_TYPE;
use emily_handler::context::EmilyContext;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use emily_handler::api;
use emily_handler::logging;

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
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, HeaderName::from_static("x-api-key")]);

    // Setup service filters.
    // let service_filter = api::routes::routes_with_stage_prefix(context)
    //     .recover(api::handlers::handle_rejection)
    //     .with(warp::log("api"))
    //     .with(cors);

    let router = api::routes::routes_axum()
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

    // We need to ignore the stage prefix that is passed in by AWS Lambda.
    let app = Router::new().nest("/{*ignored}", router);

    // Create warp service.
    lambda_http::run(app).await.expect("An error occurred");
}
