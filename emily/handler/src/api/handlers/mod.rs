//! Handlers for the emily API

use axum::body::Body;
use axum::http::HeaderValue;
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
/// This is the axum equivalent of the warp-era `handle_rejection` 404 branch:
/// it returns the canonical `ErrorResponse` JSON body so clients (and our
/// integration tests) can decode every error the same way.
pub(crate) async fn not_found_fallback(req: Request<Body>) -> Response {
    let body = ErrorResponse {
        message: format!("Not Found: {} {}", req.method(), req.uri()),
    };
    (StatusCode::NOT_FOUND, axum::Json(body)).into_response()
}

/// Fallback invoked when a route exists but the request method does not match.
///
/// Replaces the warp-era `handle_rejection` `MethodNotAllowed` branch and
/// emits an `ErrorResponse` JSON body.
pub(crate) async fn method_not_allowed_fallback(req: Request<Body>) -> Response {
    let body = ErrorResponse {
        message: format!("Method Not Allowed: {} {}", req.method(), req.uri()),
    };
    (StatusCode::METHOD_NOT_ALLOWED, axum::Json(body)).into_response()
}

/// Middleware that ensures every error response (4xx/5xx) carries a JSON
/// `ErrorResponse` body.
///
/// This is the axum equivalent of the warp-era `handle_rejection`
/// `BodyDeserializeError`/internal-error branches: it catches axum's
/// built-in extractor rejections (for example malformed JSON bodies which
/// axum surfaces as `text/plain`) and re-encodes them so clients always
/// see the same error shape.
pub async fn ensure_json_error_body(req: Request<Body>, next: Next) -> Response {
    let response = next.run(req).await;
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }
    let already_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));
    if already_json {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "failed to buffer error response body for re-encoding");
            return (
                parts.status,
                axum::Json(ErrorResponse {
                    message: format!(
                        "{} {}",
                        parts.status.as_u16(),
                        parts.status.canonical_reason().unwrap_or("Error")
                    ),
                }),
            )
                .into_response();
        }
    };
    let message = if bytes.is_empty() {
        parts
            .status
            .canonical_reason()
            .unwrap_or("Error")
            .to_string()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let body = ErrorResponse { message };
    let json_response = axum::Json(body).into_response();
    let (json_parts, json_body) = json_response.into_parts();
    parts.headers.insert(
        CONTENT_TYPE,
        json_parts
            .headers
            .get(CONTENT_TYPE)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("application/json")),
    );
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Response::from_parts(parts, json_body)
}
