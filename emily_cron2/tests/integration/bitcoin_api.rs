//! Mempool/Electrs-shaped HTTP shim backed by Bitcoin Core.
//!
//! emily-cron2 still speaks those APIs. This adapter lets tests drive the
//! processor from Core so a later Core-only change can drop the shim.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use bitcoin::Txid;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi as _;
use sbtc::testing::regtest::BITCOIN_CORE_RPC_PASSWORD;
use sbtc::testing::regtest::BITCOIN_CORE_RPC_USERNAME;
use serde_json::json;
use tokio::net::TcpListener;

pub async fn serve(rpc_url: &str) -> String {
    let auth = Auth::UserPass(
        BITCOIN_CORE_RPC_USERNAME.to_string(),
        BITCOIN_CORE_RPC_PASSWORD.to_string(),
    );
    let rpc = Client::new(rpc_url, auth).unwrap();
    let app = Router::new()
        .route("/v1/blocks/tip/height", get(tip_height))
        .route("/v1/tx/{txid}", get(transaction))
        .route("/tx/{txid}/outspend/{vout}", get(outspend))
        .with_state(Arc::new(rpc));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn tip_height(State(rpc): State<Arc<Client>>) -> impl IntoResponse {
    Json(rpc.get_block_count().unwrap())
}

async fn transaction(
    State(rpc): State<Arc<Client>>,
    Path(txid): Path<String>,
) -> impl IntoResponse {
    let Ok(txid) = Txid::from_str(&txid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(info) = rpc.get_raw_transaction_info(&txid, None) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let (confirmed, block_height) = match info.blockhash {
        Some(blockhash) => {
            let height = rpc.get_block_header_info(&blockhash).unwrap().height;
            (true, Some(height as u64))
        }
        None => (false, None),
    };

    Json(json!({
        "status": { "confirmed": confirmed, "block_height": block_height },
        "vin": []
    }))
    .into_response()
}

async fn outspend(
    State(rpc): State<Arc<Client>>,
    Path((txid, vout)): Path<(String, u32)>,
) -> impl IntoResponse {
    let Ok(txid) = Txid::from_str(&txid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let spent = rpc.get_tx_out(&txid, vout, Some(true)).unwrap().is_none();
    Json(json!({ "spent": spent })).into_response()
}
