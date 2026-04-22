// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! HTTP server that handles `POST /` requests for threshold-IBE partial key extraction.
//!
//! Request body:  hex-encoded PKE ciphertext (encrypted to this node's registered key) whose
//!                plaintext is a BCS `RequestForDecryptionKey`
//! Response body: hex-encoded PKE ciphertext (encrypted to the client's ephemeral key) whose
//!                plaintext is a BCS `tibe.IdentityDecryptionKeyShare`

use std::collections::HashMap;
use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use tokio::sync::RwLock;
use vss_common::normalize_account_addr;
use vss_common::pke::{pke_decrypt_bytes, EncryptionKey};

/// Serialized size of a `pke::EncryptionKey` for scheme 0 (ElGamal-OTP-Ristretto255):
/// [0x00 scheme][0x20 ULEB128(32)][32B enc_base][0x20 ULEB128(32)][32B public_point] = 67 bytes.
const ENC_KEY_SIZE: usize = 67;

/// Shared state for the HTTP handler.
#[derive(Clone)]
pub struct AppState {
    pub keypair_shares: Arc<RwLock<HashMap<String, HashMap<u64, [u8; 32]>>>>,
    pub cur_nodes: Arc<RwLock<Vec<String>>>,
    pub my_addr: String,
    /// Aptos fullnode URL, used for on-chain proof verification.
    pub rpc_url: String,
    /// This node's PKE decryption key bytes, used to decrypt incoming requests.
    pub pke_dk_bytes: Vec<u8>,
}

/// Spawn the axum server on `port`.  Runs until the process exits.
pub async fn run(
    port: u16,
    keypair_shares: Arc<RwLock<HashMap<String, HashMap<u64, [u8; 32]>>>>,
    cur_nodes: Arc<RwLock<Vec<String>>>,
    my_addr: String,
    rpc_url: String,
    pke_dk_bytes: Vec<u8>,
) {
    let state = AppState { keypair_shares, cur_nodes, my_addr, rpc_url, pke_dk_bytes };
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

/// POST handler: body = hex PKE-encrypted `RequestForDecryptionKey`,
/// response = hex PKE-encrypted `tibe.IdentityDecryptionKeyShare`.
async fn handle_request(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<String, StatusCode> {
    let body_str = std::str::from_utf8(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let ct_bytes = hex::decode(body_str.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;

    // 1. Decrypt the outer PKE ciphertext to recover the plaintext RequestForDecryptionKey.
    let req_bytes = pke_decrypt_bytes(&state.pke_dk_bytes, &ct_bytes).map_err(|e| {
        eprintln!("http-server: request decryption failed: {:#}", e);
        StatusCode::BAD_REQUEST
    })?;

    // 2. Parse keypairId (32 fixed bytes, AccountAddress).
    if req_bytes.len() < 40 + ENC_KEY_SIZE {
        return Err(StatusCode::BAD_REQUEST);
    }
    let keypair_id = normalize_account_addr(&format!("0x{}", hex::encode(&req_bytes[0..32])));

    // 3. Parse epoch (u64 LE, 8 bytes).
    let epoch = u64::from_le_bytes(req_bytes[32..40].try_into().unwrap());

    // 4. Extract ephemeral enc key (last ENC_KEY_SIZE bytes).
    let ek_start = req_bytes.len() - ENC_KEY_SIZE;
    let ephemeral_ek = EncryptionKey::from_bytes(&req_bytes[ek_start..]).map_err(|e| {
        eprintln!("http-server: ephemeral enc key parse failed: {:#}", e);
        StatusCode::BAD_REQUEST
    })?;

    // 5. Parse FullDecryptionDomain (contractId + domain = IBE identity).
    let fdd =
        crate::verify::parse_fdd(&req_bytes[40..]).map_err(|_| StatusCode::BAD_REQUEST)?;
    let fdd_bytes = &req_bytes[40..40 + fdd.byte_len];
    // proof is between fdd and the ephemeral enc key
    let proof_bytes = &req_bytes[40 + fdd.byte_len..ek_start];

    // 6. Verify the proof (signature, auth-key, on-chain permission).
    crate::verify::verify(&fdd, proof_bytes, &state.rpc_url)
        .await
        .map_err(|e| {
            eprintln!("http-server: proof verification failed: {:#}", e);
            StatusCode::FORBIDDEN
        })?;

    // 7. Look up the scalar share for this keypairId at the requested epoch.
    let scalar_le32 = {
        let shares = state.keypair_shares.read().await;
        shares.get(&keypair_id).and_then(|by_epoch| by_epoch.get(&epoch)).copied()
    }
    .ok_or(StatusCode::NOT_FOUND)?;

    // 8. Determine this node's eval point (1-based position in cur_nodes).
    let eval_point = {
        let nodes = state.cur_nodes.read().await;
        nodes
            .iter()
            .position(|n| n == &state.my_addr)
            .map(|i| (i + 1) as u64)
    }
    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // 9. Compute H_G2(fdd_bytes) ^ scalar, then encrypt the share under the client's ephemeral key.
    let share_hex = crate::crypto::partial_extract_idk_share(fdd_bytes, &scalar_le32, eval_point)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let share_bytes = hex::decode(&share_hex).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let resp_ct = vss_common::crypto::pke_encrypt(&ephemeral_ek, &share_bytes);
    Ok(hex::encode(resp_ct.to_bytes()))
}
