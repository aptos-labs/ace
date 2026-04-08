// Axum HTTP server

use anyhow::Result;
use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    aptos_rpc::AptosRpc,
    crypto,
    store::ShareStore,
    types::RequestForDecryptionKey,
    verify,
    vss::{self, DealMsg, ReshareMsg},
    DkgShareAccum, ReshareAccum,
};

#[derive(Clone)]
pub struct AppState {
    pub contract_addr: String,
    pub rpc: AptosRpc,
    pub my_address: [u8; 32],
    pub store: Arc<Mutex<ShareStore>>,
    pub accum: Arc<Mutex<DkgShareAccum>>,
    pub reshare_accum: Arc<Mutex<ReshareAccum>>,
}

pub async fn run(
    port: u16,
    contract_addr: String,
    rpc_url: String,
    my_address: [u8; 32],
    store: Arc<Mutex<ShareStore>>,
    accum: Arc<Mutex<DkgShareAccum>>,
    reshare_accum: Arc<Mutex<ReshareAccum>>,
) -> Result<()> {
    let state = AppState {
        contract_addr,
        rpc: AptosRpc::new(rpc_url),
        my_address,
        store,
        accum,
        reshare_accum,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(handle_root).post(handle_post))
        .route("/ibe_mpk", get(handle_ibe_mpk))
        .route("/health", get(handle_health))
        .route("/deal_share", post(handle_deal_share))
        .route("/reshare_share", post(handle_reshare_share))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("ACE Worker v2 (Rust) listening on port {}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_root() -> impl IntoResponse {
    (StatusCode::OK, "ACE Worker v2 (Rust) OK")
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let addr = format!("0x{}", hex::encode(state.my_address));
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    (
        StatusCode::OK,
        axum::Json(json!({ "status": "ok", "address": addr, "timestamp": ts })),
    )
}

async fn handle_ibe_mpk(State(state): State<AppState>) -> impl IntoResponse {
    let result = state.rpc.view(
        &format!("{}::ace_network::get_secret", state.contract_addr),
        &[],
        &[serde_json::json!(state.contract_addr), serde_json::json!("0")],
    ).await;

    match result {
        Ok(vals) => {
            if let Some(mpk_hex) = vals.get(0).and_then(|v| v.as_str()) {
                let clean = mpk_hex.trim_start_matches("0x").to_string();
                (StatusCode::OK, clean)
            } else {
                (StatusCode::SERVICE_UNAVAILABLE, "MPK not yet available".to_string())
            }
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "MPK not yet available".to_string()),
    }
}

/// Receive a VSS share from a dealer during the DKG dealing phase.
/// Verifies the share against the provided commitments and accumulates it.
async fn handle_deal_share(
    State(state): State<AppState>,
    Json(msg): Json<DealMsg>,
) -> impl IntoResponse {
    // Determine our index in the current committee.
    let my_index = {
        let my_addr = format!("0x{}", hex::encode(state.my_address)).to_lowercase();
        let epoch_result = state
            .rpc
            .view(
                &format!("{}::ace_network::get_current_epoch", state.contract_addr),
                &[],
                &[serde_json::json!(state.contract_addr)],
            )
            .await;
        match epoch_result {
            Ok(vals) => {
                let nodes: Vec<String> = vals
                    .get(1)
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                            .collect()
                    })
                    .unwrap_or_default();
                match nodes.iter().position(|n| n == &my_addr) {
                    Some(i) => (i + 1) as u64,
                    None => {
                        warn!("[deal_share] not in committee, ignoring share");
                        return (StatusCode::BAD_REQUEST, "not in committee");
                    }
                }
            }
            Err(e) => {
                error!("[deal_share] failed to get epoch: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "failed to get epoch");
            }
        }
    };

    let share_fr = match msg.parse_share() {
        Ok(s) => s,
        Err(e) => {
            warn!("[deal_share] invalid share: {}", e);
            return (StatusCode::BAD_REQUEST, "invalid share");
        }
    };

    let commitments = match msg.parse_commitments() {
        Ok(c) => c,
        Err(e) => {
            warn!("[deal_share] invalid commitments: {}", e);
            return (StatusCode::BAD_REQUEST, "invalid commitments");
        }
    };

    if !vss::verify_share(share_fr, my_index, &commitments) {
        warn!(
            "[deal_share] share verification failed from dealer {}",
            msg.dealer_index
        );
        return (StatusCode::BAD_REQUEST, "share verification failed");
    }

    // Accumulate the valid share.
    {
        let mut locked = state.accum.lock().await;
        let entry = locked
            .shares
            .entry(msg.dkg_id)
            .or_insert(ark_bls12_381::Fr::from(0u64));
        *entry += share_fr;
    }

    info!(
        "[deal_share] accepted share from dealer {} for dkg_id={}",
        msg.dealer_index, msg.dkg_id
    );
    (StatusCode::OK, "ok")
}

/// Receive a resharing sub-share from an old committee dealer during DKR.
/// Verifies g_i(my_new_index) against the provided Pedersen commitments and
/// accumulates it for later Lagrange combination.
async fn handle_reshare_share(
    State(state): State<AppState>,
    Json(msg): Json<ReshareMsg>,
) -> impl IntoResponse {
    // Determine my 1-based index in the NEW committee by fetching epoch change details.
    let new_committee_result = state
        .rpc
        .view(
            &format!("{}::ace_network::get_epoch_change_details", state.contract_addr),
            &[],
            &[
                serde_json::json!(state.contract_addr),
                serde_json::json!(msg.epoch_change_id.to_string()),
            ],
        )
        .await;

    let my_new_index = match new_committee_result {
        Ok(vals) => {
            let my_addr = format!("0x{}", hex::encode(state.my_address)).to_lowercase();
            let nodes: Vec<String> = vals
                .get(0)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                        .collect()
                })
                .unwrap_or_default();
            match nodes.iter().position(|n| n == &my_addr) {
                Some(i) => (i + 1) as u64,
                None => {
                    warn!("[reshare_share] not in new committee, ignoring");
                    return (StatusCode::BAD_REQUEST, "not in new committee");
                }
            }
        }
        Err(e) => {
            error!("[reshare_share] failed to get epoch change details: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "failed to get committee");
        }
    };

    let share_fr = match msg.parse_share() {
        Ok(s) => s,
        Err(e) => {
            warn!("[reshare_share] invalid share: {}", e);
            return (StatusCode::BAD_REQUEST, "invalid share");
        }
    };

    let commitments = match msg.parse_commitments() {
        Ok(c) => c,
        Err(e) => {
            warn!("[reshare_share] invalid commitments: {}", e);
            return (StatusCode::BAD_REQUEST, "invalid commitments");
        }
    };

    // Verify g_i(my_new_index) against Pedersen commitments.
    if !vss::verify_share(share_fr, my_new_index, &commitments) {
        warn!(
            "[reshare_share] share verification failed from old dealer {}",
            msg.dealer_old_index
        );
        return (StatusCode::BAD_REQUEST, "share verification failed");
    }

    // Accumulate (dealer_old_index, sub_share).
    {
        let mut locked = state.reshare_accum.lock().await;
        let entry = locked
            .sub_shares
            .entry((msg.epoch_change_id, msg.secret_id))
            .or_default();
        // Deduplicate: only one sub-share per dealer per secret.
        if !entry.iter().any(|(idx, _)| *idx == msg.dealer_old_index) {
            entry.push((msg.dealer_old_index, share_fr));
        }
    }

    info!(
        "[reshare_share] accepted sub-share from old dealer {} for (ec_id={}, secret_id={})",
        msg.dealer_old_index, msg.epoch_change_id, msg.secret_id
    );
    (StatusCode::OK, "ok")
}

async fn handle_post(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let session_id = &Uuid::new_v4().to_string()[..8];
    info!("[{}] BEGIN", session_id);

    // Parse request
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            warn!("[{}] DENIED: invalid UTF-8 body", session_id);
            return (StatusCode::BAD_REQUEST, "Could not parse request.".to_string());
        }
    };

    let request = match RequestForDecryptionKey::from_hex(&body_str) {
        Ok(r) => r,
        Err(e) => {
            warn!("[{}] DENIED: parse error: {}", session_id, e);
            return (StatusCode::BAD_REQUEST, "Could not parse request.".to_string());
        }
    };

    // Only Aptos scheme supported
    if request.contract_id_scheme != 0 || request.proof_scheme != 0 {
        warn!("[{}] DENIED: unsupported scheme", session_id);
        return (StatusCode::BAD_REQUEST, "Only Aptos scheme supported in v2".to_string());
    }

    let cid = &request.aptos_contract_id;

    // Verify permission
    let rpc_url_for_verify = state.rpc.base_url.clone();
    let verify_rpc = AptosRpc::new(rpc_url_for_verify);
    let verify_result = verify::verify_aptos_permission(
        &verify_rpc,
        cid.chain_id,
        &cid.module_addr,
        &cid.module_name,
        &cid.function_name,
        &request.domain,
        &request.aptos_proof,
    ).await;

    if let Err(e) = verify_result {
        warn!("[{}] DENIED: {}", session_id, e);
        return (StatusCode::BAD_REQUEST, "Permission denied".to_string());
    }

    // Get my index in the current committee
    let epoch_result = state.rpc.view(
        &format!("{}::ace_network::get_current_epoch", state.contract_addr),
        &[],
        &[serde_json::json!(state.contract_addr)],
    ).await;

    let (node_list, _threshold) = match epoch_result {
        Ok(vals) => {
            let nodes: Vec<String> = vals.get(1)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_lowercase())).collect())
                .unwrap_or_default();
            let threshold = vals.get(2)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            (nodes, threshold)
        }
        Err(e) => {
            error!("[{}] ERROR getting epoch: {}", session_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string());
        }
    };

    let my_addr_lower = format!("0x{}", hex::encode(state.my_address));
    let my_index = match node_list.iter().position(|n| n == &my_addr_lower) {
        Some(i) => (i + 1) as u8,
        None => {
            warn!("[{}] DENIED: worker not in committee", session_id);
            return (StatusCode::BAD_REQUEST, "Worker not in committee".to_string());
        }
    };

    // Load key share
    let secret_count_result = state.rpc.view(
        &format!("{}::ace_network::get_secret_count", state.contract_addr),
        &[],
        &[serde_json::json!(state.contract_addr)],
    ).await;
    let secret_count = match secret_count_result {
        Ok(vals) => vals.get(0)
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0),
        Err(e) => {
            error!("[{}] ERROR getting secret count: {}", session_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string());
        }
    };

    if secret_count == 0 {
        return (StatusCode::SERVICE_UNAVAILABLE, "No secrets available yet".to_string());
    }
    let secret_id = secret_count - 1;

    let scalar_share_le: [u8; 32] = {
        let locked = state.store.lock().await;
        match locked.get(secret_id) {
            Some(row) => {
                match hex::decode(&row.scalar_share_hex) {
                    Ok(b) if b.len() == 32 => b.try_into().unwrap(),
                    _ => {
                        error!("[{}] ERROR: invalid scalar share in store", session_id);
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string());
                    }
                }
            }
            None => {
                warn!("[{}] key share not yet derived for secret_id={}", session_id, secret_id);
                return (StatusCode::SERVICE_UNAVAILABLE, "Key share not yet derived".to_string());
            }
        }
    };

    // Compute FullDecryptionDomain.toBytes() = identity for IBE
    let identity = full_decryption_domain_to_bytes(&request);

    // Partial extract
    match crypto::partial_extract(&identity, &scalar_share_le, my_index) {
        Ok(hex_result) => {
            info!("[{}] APPROVED (workerIndex={})", session_id, my_index);
            (StatusCode::OK, hex_result)
        }
        Err(e) => {
            error!("[{}] ERROR in partial extract: {}", session_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        }
    }
}

/// Reconstruct FullDecryptionDomain.toBytes() = BCS(ContractID) || BCS(domain)
/// matching the TypeScript FullDecryptionDomain.serialize() method
fn full_decryption_domain_to_bytes(req: &RequestForDecryptionKey) -> Vec<u8> {
    let mut out = Vec::new();
    let cid = &req.aptos_contract_id;

    // ContractID scheme byte
    out.push(req.contract_id_scheme); // 0x00 for Aptos

    // AptosContractID:
    // u8 chainId
    out.push(cid.chain_id);
    // 32 bytes moduleAddr (fixed)
    out.extend_from_slice(&cid.module_addr);
    // ULEB128(len) + moduleName bytes
    encode_uleb128_to(cid.module_name.len() as u64, &mut out);
    out.extend_from_slice(cid.module_name.as_bytes());
    // ULEB128(len) + functionName bytes
    encode_uleb128_to(cid.function_name.len() as u64, &mut out);
    out.extend_from_slice(cid.function_name.as_bytes());

    // domain: ULEB128(len) + bytes
    encode_uleb128_to(req.domain.len() as u64, &mut out);
    out.extend_from_slice(&req.domain);

    out
}

fn encode_uleb128_to(mut val: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}
