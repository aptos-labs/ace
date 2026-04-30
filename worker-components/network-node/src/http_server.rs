// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! HTTP server that handles `POST /` requests for threshold-IBE partial key extraction.
//!
//! Request body:  hex-encoded PKE ciphertext (encrypted to this node's registered key) whose
//!                plaintext is a BCS `RequestForDecryptionKey`
//! Response body: hex-encoded PKE ciphertext (encrypted to the client's key) whose
//!                plaintext is a BCS `tibe.IdentityDecryptionKeyShare`
//!
//! `RequestForDecryptionKey` wire format:
//!   [scheme: u8]    0 = BasicFlow, 1 = CustomFlow
//!   ... rest depends on scheme (see handle_basic_flow / handle_custom_flow)

use std::collections::HashMap;
use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use tokio::sync::{RwLock, Semaphore};
use vss_common::normalize_account_addr;
use vss_common::pke::{pke_decrypt_bytes, EncryptionKey};

use crate::{wlog, ChainRpcConfig};

/// Serialized size of a `pke::EncryptionKey` for scheme 0 (ElGamal-OTP-Ristretto255):
/// [0x00 scheme][0x20 ULEB128(32)][32B enc_base][0x20 ULEB128(32)][32B public_point] = 67 bytes.
const ENC_KEY_SIZE: usize = 67;

/// Shared state for the HTTP handler.
#[derive(Clone)]
pub struct AppState {
    pub keypair_shares: Arc<RwLock<HashMap<String, HashMap<u64, [u8; 32]>>>>,
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
    keypair_shares: Arc<RwLock<HashMap<String, HashMap<u64, [u8; 32]>>>>,
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

/// POST handler: body = hex PKE-encrypted `RequestForDecryptionKey`.
/// Dispatches to `handle_basic_flow` or `handle_custom_flow` based on scheme byte.
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

    if req_bytes.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let scheme = req_bytes[0];
    let rest = &req_bytes[1..];

    match scheme {
        0 => handle_basic_flow(&state, rest).await,
        1 => handle_custom_flow(&state, rest).await,
        _ => {
            wlog!("http-server: unknown request scheme {}", scheme);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

/// Handle a BasicFlow request.
///
/// Layout of `req` (after the scheme byte):
///   keypairId[32] + epoch[8 LE] + FDD(contractId+domain)[BCS] + ephemeralEncKey[67] + ProofOfPermission
async fn handle_basic_flow(state: &AppState, req: &[u8]) -> Result<String, StatusCode> {
    if req.len() < 40 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let keypair_id_bytes: [u8; 32] = req[0..32].try_into().unwrap();
    let keypair_id = normalize_account_addr(&format!("0x{}", hex::encode(keypair_id_bytes)));
    let epoch = u64::from_le_bytes(req[32..40].try_into().unwrap());

    let fdd = crate::verify::parse_fdd(keypair_id_bytes, &req[40..])
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut fdd_bytes = Vec::with_capacity(32 + fdd.byte_len);
    fdd_bytes.extend_from_slice(&keypair_id_bytes);
    fdd_bytes.extend_from_slice(&req[40..40 + fdd.byte_len]);

    let ek_start = 40 + fdd.byte_len;
    if req.len() < ek_start + ENC_KEY_SIZE {
        return Err(StatusCode::BAD_REQUEST);
    }
    let ephemeral_ek = EncryptionKey::from_bytes(&req[ek_start..ek_start + ENC_KEY_SIZE])
        .map_err(|e| {
            wlog!("http-server: basic flow: ephemeral enc key parse failed: {:#}", e);
            StatusCode::BAD_REQUEST
        })?;
    let proof_bytes = &req[ek_start + ENC_KEY_SIZE..];

    crate::verify::verify(&fdd, epoch, &req[ek_start..ek_start + ENC_KEY_SIZE], proof_bytes, &state.chain_rpc)
        .await
        .map_err(|e| {
            wlog!("http-server: basic flow: proof verification failed: {:#}", e);
            StatusCode::FORBIDDEN
        })?;

    extract_and_respond(state, &keypair_id, epoch, &fdd_bytes, &ephemeral_ek).await
}

/// Handle a CustomFlow request.
///
/// Layout of `req` (after the scheme byte):
///   keypairId[32] + epoch[8 LE] + FDD(contractId+label)[BCS] + encPk[67] + CustomFlowProof
async fn handle_custom_flow(state: &AppState, req: &[u8]) -> Result<String, StatusCode> {
    if req.len() < 40 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let keypair_id_bytes: [u8; 32] = req[0..32].try_into().unwrap();
    let keypair_id = normalize_account_addr(&format!("0x{}", hex::encode(keypair_id_bytes)));
    let epoch = u64::from_le_bytes(req[32..40].try_into().unwrap());

    let fdd = crate::verify::parse_fdd(keypair_id_bytes, &req[40..])
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut fdd_bytes = Vec::with_capacity(32 + fdd.byte_len);
    fdd_bytes.extend_from_slice(&keypair_id_bytes);
    fdd_bytes.extend_from_slice(&req[40..40 + fdd.byte_len]);

    let enc_pk_start = 40 + fdd.byte_len;
    if req.len() < enc_pk_start + ENC_KEY_SIZE {
        return Err(StatusCode::BAD_REQUEST);
    }
    let caller_enc_key = EncryptionKey::from_bytes(&req[enc_pk_start..enc_pk_start + ENC_KEY_SIZE])
        .map_err(|e| {
            wlog!("http-server: custom flow: enc key parse failed: {:#}", e);
            StatusCode::BAD_REQUEST
        })?;
    let proof_bytes = &req[enc_pk_start + ENC_KEY_SIZE..];

    crate::verify::verify_custom(&fdd, epoch, &req[enc_pk_start..enc_pk_start + ENC_KEY_SIZE], proof_bytes, &state.chain_rpc)
        .await
        .map_err(|e| {
            wlog!("http-server: custom flow: proof verification failed: {:#}", e);
            StatusCode::FORBIDDEN
        })?;

    extract_and_respond(state, &keypair_id, epoch, &fdd_bytes, &caller_enc_key).await
}

/// Look up the scalar share, compute the IDK share, and encrypt it to `response_enc_key`.
async fn extract_and_respond(
    state: &AppState,
    keypair_id: &str,
    epoch: u64,
    fdd_bytes: &[u8],
    response_enc_key: &EncryptionKey,
) -> Result<String, StatusCode> {
    let scalar_le32 = {
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

    let share_hex = crate::crypto::partial_extract_idk_share(fdd_bytes, &scalar_le32, eval_point)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let share_bytes = hex::decode(&share_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let resp_ct = vss_common::crypto::pke_encrypt(response_enc_key, &share_bytes);
    Ok(hex::encode(resp_ct.to_bytes()))
}
