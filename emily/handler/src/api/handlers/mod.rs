//! Handlers for the emily API

use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::middleware::Next;
use axum::response::IntoResponse as _;
use axum::response::Response;

use crate::common::error::ErrorResponse;

/// Chainstate handlers.
pub mod chainstate;
/// Deposit handlers.
pub mod deposit;
/// Health handlers.
pub mod health;
/// Internal handlers.
pub mod internal;
/// Limit handlers.
pub mod limits;
/// New block handlers.
pub mod new_block;
/// Testing handlers.
#[cfg(feature = "testing")]
pub mod testing;
/// Throttle handlers.
pub mod throttle;
/// Withdrawal handlers.
pub mod withdrawal;

/// Fallback handler for unmatched routes.
///
/// This returns the canonical `ErrorResponse` JSON body so clients (and
/// our integration tests) can decode every error the same way.
pub(crate) async fn not_found_fallback(req: Request<Body>) -> Response {
    let body = ErrorResponse {
        message: format!("Not Found: {} {}", req.method(), req.uri()),
    };
    (StatusCode::NOT_FOUND, axum::Json(body)).into_response()
}

/// Fallback invoked when a route exists but the request method does not
/// match.
///
/// Emits an `ErrorResponse` JSON body.
pub(crate) async fn method_not_allowed_fallback(req: Request<Body>) -> Response {
    let body = ErrorResponse {
        message: format!("Method Not Allowed: {} {}", req.method(), req.uri()),
    };
    (StatusCode::METHOD_NOT_ALLOWED, axum::Json(body)).into_response()
}

/// Middleware that ensures every error response is a JSON `ErrorResponse`
/// response.
///
/// This is catches axum's built-in extractor rejections which axum
/// surfaces as `text/plain` and re-encodes them so clients always see the
/// same error shape.
pub async fn ensure_json_error_body(req: Request<Body>, next: Next) -> Response {
    let response = next.run(req).await;
    let status = response.status();

    // If the response is not an error, we can just return it as is.
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }

    let already_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("application/json"));

    // If the response is already JSON, we can just return it as is.
    if already_json {
        return response;
    }

    // So this isn't a JSON response, we need to re-encode it as JSON,
    // because that is the API.
    let (parts, body) = response.into_parts();
    let message = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).into_owned(),
        res @ Ok(_) | res @ Err(_) => {
            if let Err(error) = res {
                tracing::warn!(%error, "failed to buffer error response body for re-encoding");
            }
            parts
                .status
                .canonical_reason()
                .unwrap_or("Error")
                .to_string()
        }
    };

    (parts.status, axum::Json(ErrorResponse { message })).into_response()
}
