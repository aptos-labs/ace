// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! HTTP server that handles `POST /` requests for threshold-IBE partial key extraction.
//!
//! Request body:  hex-encoded BCS `RequestForDecryptionKey`
//! Response body: hex-encoded BCS `tibe.IdentityDecryptionKeyShare`

use std::collections::HashMap;
use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use tokio::sync::RwLock;
use vss_common::normalize_account_addr;

/// Shared state for the HTTP handler.
#[derive(Clone)]
pub struct AppState {
    pub keypair_shares: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    pub cur_nodes: Arc<RwLock<Vec<String>>>,
    pub my_addr: String,
    /// Aptos fullnode URL, used for on-chain proof verification.
    pub rpc_url: String,
}

/// Spawn the axum server on `port`.  Runs until the process exits.
pub async fn run(
    port: u16,
    keypair_shares: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    cur_nodes: Arc<RwLock<Vec<String>>>,
    my_addr: String,
    rpc_url: String,
) {
    let state = AppState { keypair_shares, cur_nodes, my_addr, rpc_url };
    let app = Router::new().route("/", post(handle_request)).with_state(state);
    let addr = format!("0.0.0.0:{}", port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("http-server: bind {} failed: {}", addr, e);
            return;
        }
    };
    println!("http-server: listening on {}", addr);
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("http-server: serve error: {}", e);
    }
}

/// POST handler: body = hex `RequestForDecryptionKey`, response = hex `IdentityDecryptionKeyShare`.
async fn handle_request(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<String, StatusCode> {
    let body_str = std::str::from_utf8(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let req_bytes = hex::decode(body_str.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;

    // 1. Parse keypairId (32 fixed bytes, AccountAddress).
    if req_bytes.len() < 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let keypair_id = normalize_account_addr(&format!("0x{}", hex::encode(&req_bytes[0..32])));

    // 2. Parse FullDecryptionDomain (contractId + domain = IBE identity).
    let fdd =
        crate::verify::parse_fdd(&req_bytes[32..]).map_err(|_| StatusCode::BAD_REQUEST)?;
    let fdd_bytes = &req_bytes[32..32 + fdd.byte_len];
    let proof_bytes = &req_bytes[32 + fdd.byte_len..];

    // 3. Verify the proof (signature, auth-key, on-chain permission).
    crate::verify::verify(&fdd, proof_bytes, &state.rpc_url)
        .await
        .map_err(|e| {
            eprintln!("http-server: proof verification failed: {:#}", e);
            StatusCode::FORBIDDEN
        })?;

    // 4. Look up the scalar share for this keypairId.
    let scalar_le32 = {
        let shares = state.keypair_shares.read().await;
        shares.get(&keypair_id).copied()
    }
    .ok_or(StatusCode::NOT_FOUND)?;

    // 5. Determine this node's eval point (1-based position in cur_nodes).
    let eval_point = {
        let nodes = state.cur_nodes.read().await;
        nodes
            .iter()
            .position(|n| n == &state.my_addr)
            .map(|i| (i + 1) as u64)
    }
    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // 6. Compute H_G2(fdd_bytes) ^ scalar and return BCS hex.
    crate::crypto::partial_extract_idk_share(fdd_bytes, &scalar_le32, eval_point)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
