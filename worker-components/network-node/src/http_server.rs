// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! HTTP server that handles `POST /` requests for threshold-IBE partial key extraction.
//!
//! Request body:  hex-encoded PKE ciphertext (encrypted to this node's registered key) whose
//!                plaintext is a BCS [`verify::RequestForDecryptionKey`].
//! Response body: hex-encoded PKE ciphertext (encrypted to the client's key) whose
//!                plaintext is a BCS `tibe.IdentityDecryptionKeyShare`.
//!
//! Adding a new request flow or chain is a one-arm change in `verify::RequestForDecryptionKey`
//! and a matching arm here — no manual byte-walking, no per-scheme size tables.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use tokio::sync::{RwLock, Semaphore};
use vss_common::normalize_account_addr;
use vss_common::crypto::pke_encrypt;
use vss_common::pke::{pke_decrypt_bytes, EncryptionKey};

use crate::verify::{self, BasicFlowRequest, CustomFlowRequest, RequestForDecryptionKey};
use crate::{wlog, ChainRpcConfig};

/// Shared state for the HTTP handler.
#[derive(Clone)]
pub struct AppState {
    pub keypair_shares: Arc<RwLock<HashMap<String, HashMap<u64, ([u8; 32], u8)>>>>,
    pub cur_nodes: Arc<RwLock<Vec<String>>>,
    pub my_addr: String,
    /// Per-chain RPC config, used for on-chain proof verification.
    pub chain_rpc: Arc<ChainRpcConfig>,
    /// This node's PKE decryption key bytes, used to decrypt incoming requests.
    pub pke_dk_bytes: Vec<u8>,
    /// Bounds the number of simultaneously in-flight requests.
    pub concurrency: Arc<Semaphore>,
}

/// Spawn the axum server on `port`.  Runs until the process exits.
pub async fn run(
    port: u16,
    keypair_shares: Arc<RwLock<HashMap<String, HashMap<u64, ([u8; 32], u8)>>>>,
    cur_nodes: Arc<RwLock<Vec<String>>>,
    my_addr: String,
    chain_rpc: Arc<ChainRpcConfig>,
    pke_dk_bytes: Vec<u8>,
    concurrency: Arc<Semaphore>,
) {
    let state = AppState { keypair_shares, cur_nodes, my_addr, chain_rpc, pke_dk_bytes, concurrency };
    let app = Router::new().route("/", post(handle_request)).with_state(state);
    let addr = format!("0.0.0.0:{}", port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            wlog!("http-server: bind {} failed: {}", addr, e);
            return;
        }
    };
    wlog!("http-server: listening on {}", addr);
    if let Err(e) = axum::serve(listener, app).await {
        wlog!("http-server: serve error: {}", e);
    }
}

async fn handle_request(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<String, StatusCode> {
    let _permit = Arc::clone(&state.concurrency)
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;

    let body_str = std::str::from_utf8(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let ct_bytes = hex::decode(body_str.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;

    let req_bytes = pke_decrypt_bytes(&state.pke_dk_bytes, &ct_bytes).map_err(|e| {
        wlog!("http-server: request decryption failed: {:#}", e);
        StatusCode::BAD_REQUEST
    })?;

    let request: RequestForDecryptionKey = bcs::from_bytes(&req_bytes).map_err(|e| {
        wlog!("http-server: BCS decode RequestForDecryptionKey failed: {:#}", e);
        StatusCode::BAD_REQUEST
    })?;

    match request {
        RequestForDecryptionKey::Basic(req) => handle_basic_flow(&state, req).await,
        RequestForDecryptionKey::Custom(req) => handle_custom_flow(&state, req).await,
    }
}

async fn handle_basic_flow(state: &AppState, req: BasicFlowRequest) -> Result<String, StatusCode> {
    verify::verify_basic(&req, &state.chain_rpc).await.map_err(|e| {
        wlog!("http-server: basic flow: proof verification failed: {:#}", e);
        StatusCode::FORBIDDEN
    })?;

    let identity = verify::identity_bytes(&req.keypair_id, &req.contract_id, &req.domain);
    let keypair_id = keypair_id_str(&req.keypair_id);
    extract_and_respond(state, &keypair_id, req.epoch, &identity, &req.ephemeral_enc_key).await
}

async fn handle_custom_flow(state: &AppState, req: CustomFlowRequest) -> Result<String, StatusCode> {
    verify::verify_custom(&req, &state.chain_rpc).await.map_err(|e| {
        wlog!("http-server: custom flow: proof verification failed: {:#}", e);
        StatusCode::FORBIDDEN
    })?;

    // Custom-flow identity uses `label` in place of `domain`; ContractId is unchanged.
    let identity = verify::identity_bytes(&req.keypair_id, &req.contract_id, &req.label);
    let keypair_id = keypair_id_str(&req.keypair_id);
    extract_and_respond(state, &keypair_id, req.epoch, &identity, &req.enc_pk).await
}

fn keypair_id_str(keypair_id: &[u8; 32]) -> String {
    normalize_account_addr(&format!("0x{}", hex::encode(keypair_id)))
}

/// Look up the scalar share, compute the IDK share, and encrypt it to `response_enc_key`.
async fn extract_and_respond(
    state: &AppState,
    keypair_id: &str,
    epoch: u64,
    identity: &[u8],
    response_enc_key: &EncryptionKey,
) -> Result<String, StatusCode> {
    let (scalar_le32, tibe_scheme) = {
        let shares = state.keypair_shares.read().await;
        shares.get(keypair_id).and_then(|by_epoch| by_epoch.get(&epoch)).copied()
    }
    .ok_or(StatusCode::NOT_FOUND)?;

    let eval_point = {
        let nodes = state.cur_nodes.read().await;
        nodes
            .iter()
            .position(|n| n == &state.my_addr)
            .map(|i| (i + 1) as u64)
    }
    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let share_hex = crate::crypto::partial_extract_idk_share(
        tibe_scheme, identity, &scalar_le32, eval_point,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let share_bytes = hex::decode(&share_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let resp_ct = pke_encrypt(response_enc_key, &share_bytes);
    Ok(hex::encode(bcs::to_bytes(&resp_ct).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?))
}
