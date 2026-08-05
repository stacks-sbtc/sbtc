//! PoC observer for Immunefi report 86722:
//! "302 KB Clarity contract expands past the 256 MiB signer webhook limit".
//!
//! On :8804 it mounts the production `get_router()` (real
//! `NEW_BLOCK_BODY_LIMIT`, real `new_block_handler`) and logs each
//! `/new_block` POST with the body size and the status the real router
//! produced. On :8811 it stands up a permissive observer (limit lifted to
//! 512 MiB) that actually parses the body the real router rejected and
//! counts its `events` and `transactions` arrays.
//!
//! Both ports are intended to be registered with the stacks node under the
//! same `sbtc-registry::print` filter the production signer uses, so :8811
//! shows exactly what the real signer would have been handed.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{StatusCode, header::CONTENT_LENGTH};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::post;
use serde_json::Value;
use signer::NEW_BLOCK_BODY_LIMIT;
use signer::api::{ApiState, get_router};
use signer::logging::setup_logging;
use signer::testing::context::TestContext;

const PEEK_LIMIT: usize = 512 * 1024 * 1024;

async fn log_mw(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let cl = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let resp = next.run(req).await;
    if path == "/new_block" {
        let mb = cl as f64 / 1024.0 / 1024.0;
        let verdict = if resp.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ">>> 413: non-2xx -> stacks node retries forever -> SIGNER FROZEN"
        } else {
            "2xx (within 256 MiB limit)"
        };
        if resp.status() == StatusCode::PAYLOAD_TOO_LARGE {
            tracing::warn!(
                port = 8804,
                body_mb = mb,
                status = resp.status().as_u16(),
                "REAL signer router POST /new_block: {verdict}"
            );
        } else {
            tracing::info!(
                port = 8804,
                body_mb = mb,
                status = resp.status().as_u16(),
                "REAL signer router POST /new_block: {verdict}"
            );
        }
    }
    resp
}

async fn peek_new_block(body: String) -> StatusCode {
    let mb = body.len() as f64 / 1024.0 / 1024.0;
    let (events, txs) = serde_json::from_str::<Value>(&body)
        .ok()
        .map(|v| {
            (
                v.get("events").and_then(Value::as_array).map_or(0, |a| a.len()),
                v.get("transactions")
                    .and_then(Value::as_array)
                    .map_or(0, |a| a.len()),
            )
        })
        .unwrap_or((0, 0));
    tracing::info!(
        port = 8811,
        body_mb = mb,
        events,
        transactions = txs,
        "peek (same registry-print filter) POST /new_block"
    );
    if body.len() > NEW_BLOCK_BODY_LIMIT / 2 {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let raw_path = format!("/tmp/poc_block_{ts}.raw.json");
        if let Err(err) = std::fs::write(&raw_path, &body) {
            tracing::warn!(%err, path = %raw_path, "failed to write raw body");
        } else {
            tracing::info!(port = 8811, raw = %raw_path, "wrote oversized block body to disk");
        }
    }
    StatusCode::OK
}

#[tokio::main]
async fn main() {
    // `TestContext::default_mocked()` reads the signer config from the
    // hard-coded relative path `./src/config/default`. Anchor the process
    // CWD to the signer crate root so `cargo run` works from anywhere.
    std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"))
        .expect("failed to set CWD to CARGO_MANIFEST_DIR");

    setup_logging("info,signer=info,poc_observer=info", true);

    let ctx = TestContext::default_mocked();
    let real = get_router(NEW_BLOCK_BODY_LIMIT)
        .with_state(ApiState { ctx })
        .layer(middleware::from_fn(log_mw));

    let peek = Router::new()
        .route(
            "/new_block",
            post(peek_new_block).layer(DefaultBodyLimit::max(PEEK_LIMIT)),
        )
        .fallback(|| async { StatusCode::OK });

    let mut handles = Vec::new();
    for (port, app) in [(8804u16, real), (8811u16, peek)] {
        handles.push(tokio::spawn(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            tracing::info!(%addr, port, "listening");
            axum::serve(listener, app).await.unwrap();
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}
