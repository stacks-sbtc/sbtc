//! Emily API entrypoint.

use axum::Router;
use axum::http::HeaderName;
use axum::http::Method;
use axum::http::Request;
use axum::http::header::CONTENT_TYPE;
use emily_handler::context::EmilyContext;
use lambda_http::Context as LambdaContext;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use emily_handler::api;
use emily_handler::logging;

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
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, HeaderName::from_static("x-api-key")]);

    // Setup service filters.
    let router = api::routes::routes_axum()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let request_id = request
                        .extensions()
                        .get::<LambdaContext>()
                        .map(|c| c.request_id.as_str())
                        .unwrap_or("unknown");
                    let trace_id = request
                        .headers()
                        .get("x-amzn-trace-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown");

                    tracing::info_span!("request",
                        request_id = %request_id,
                        trace_id = %trace_id,
                        uri = %request.uri(),
                        method = %request.method(),
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

    // Create axum-lambda service.
    lambda_http::run(app).await.expect("An error occurred");
}
