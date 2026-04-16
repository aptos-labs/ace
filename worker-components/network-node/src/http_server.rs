// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! HTTP server that handles `POST /` requests for threshold-IBE partial key extraction.
//!
//! Request body:  hex-encoded BCS `RequestForDecryptionKey`
//! Response body: hex-encoded BCS `tibe.IdentityDecryptionKeyShare`

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use tokio::sync::RwLock;
use vss_common::normalize_account_addr;

/// Shared state for the HTTP handler.
#[derive(Clone)]
pub struct AppState {
    pub keypair_shares: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    pub cur_nodes: Arc<RwLock<Vec<String>>>,
    pub my_addr: String,
}

/// Spawn the axum server on `port`.  Runs until the process exits.
pub async fn run(
    port: u16,
    keypair_shares: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    cur_nodes: Arc<RwLock<Vec<String>>>,
    my_addr: String,
) {
    let state = AppState { keypair_shares, cur_nodes, my_addr };
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

    // 2. Parse contractId + domain to get FullDecryptionDomain bytes (= IBE identity).
    let fdd_len = parse_fdd_len(&req_bytes[32..]).map_err(|_| StatusCode::BAD_REQUEST)?;
    let fdd_bytes = &req_bytes[32..32 + fdd_len];

    // 3. Look up the scalar share for this keypairId.
    let scalar_le32 = {
        let shares = state.keypair_shares.read().await;
        shares.get(&keypair_id).copied()
    }
    .ok_or(StatusCode::NOT_FOUND)?;

    // 4. Determine this node's eval point (1-based position in cur_nodes).
    let eval_point = {
        let nodes = state.cur_nodes.read().await;
        nodes
            .iter()
            .position(|n| n == &state.my_addr)
            .map(|i| (i + 1) as u64)
    }
    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // 5. Compute H_G2(fdd_bytes) ^ scalar and return BCS hex.
    crate::crypto::partial_extract_idk_share(fdd_bytes, &scalar_le32, eval_point)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ── BCS parsing helpers ───────────────────────────────────────────────────────

/// Returns the byte length of the `FullDecryptionDomain` portion that immediately follows
/// the 32-byte `keypairId` in a `RequestForDecryptionKey` BCS blob.
///
/// Layout after keypairId:
///   1B outer ContractID scheme
///   If Aptos (scheme=0): 1B chainId + 32B moduleAddr + BCS-string moduleName + BCS-string functionName
///   If Solana (scheme=1): BCS-string chainName + BCS-string programId
///   BCS-bytes domain
fn parse_fdd_len(bytes: &[u8]) -> Result<usize> {
    let mut pos = 0usize;

    // Outer ContractID scheme byte.
    let scheme = *bytes.get(pos).ok_or_else(|| anyhow!("too short for scheme"))?;
    pos += 1;

    match scheme {
        0 => {
            // Aptos ContractID: chainId (1B) + moduleAddr (32B fixed) + 2 BCS strings.
            if bytes.len() < pos + 1 + 32 {
                return Err(anyhow!("too short for Aptos ContractID"));
            }
            pos += 1; // chainId
            pos += 32; // moduleAddr (fixed 32B AccountAddress)
            // moduleName
            let (len, hlen) = read_uleb128(bytes, pos)?;
            pos += hlen + len as usize;
            // functionName
            let (len, hlen) = read_uleb128(bytes, pos)?;
            pos += hlen + len as usize;
        }
        1 => {
            // Solana ContractID: knownChainName + programId (two BCS strings).
            let (len, hlen) = read_uleb128(bytes, pos)?;
            pos += hlen + len as usize;
            let (len, hlen) = read_uleb128(bytes, pos)?;
            pos += hlen + len as usize;
        }
        _ => return Err(anyhow!("unknown ContractID scheme {}", scheme)),
    }

    // Domain (BCS bytes = ULEB128 length + raw bytes).
    let (len, hlen) = read_uleb128(bytes, pos)?;
    pos += hlen + len as usize;

    Ok(pos)
}

/// Reads a ULEB128 value at `start` in `bytes`.
/// Returns `(value, bytes_consumed)`.
fn read_uleb128(bytes: &[u8], start: usize) -> Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut i = start;
    loop {
        let b = *bytes.get(i).ok_or_else(|| anyhow!("ULEB128 out of bounds at {}", i))?;
        i += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(anyhow!("ULEB128 overflow"));
        }
    }
    Ok((result, i - start))
}
