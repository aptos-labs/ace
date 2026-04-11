// Signer HTTP server: DKG/DKR share endpoints + internal /partial_key
//
// Routes (cluster-internal / worker-to-worker; NOT exposed directly to end users):
//   POST /deal_share      — receive VSS share from peer dealer during DKG
//   POST /reshare_share   — receive sub-share from old committee during DKR
//   POST /partial_key     — compute s_i * H(id); called by the public server

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::{
    aptos_rpc::AptosRpc,
    crypto,
    store::ShareStore,
    vss::{self, DealMsg, ReshareMsg},
    DkgShareAccum, ReshareAccum,
};

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SignerState {
    pub contract_addr: String,
    pub rpc: AptosRpc,
    pub my_address: [u8; 32],
    pub store: Arc<Mutex<ShareStore>>,
    pub accum: Arc<Mutex<DkgShareAccum>>,
    pub reshare_accum: Arc<Mutex<ReshareAccum>>,
}

// ── /partial_key request type ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PartialKeyRequest {
    pub identity_hex: String,
    pub secret_id: u64,
}

// ── Server entrypoint ─────────────────────────────────────────────────────────

pub async fn run(port: u16, state: SignerState) -> Result<()> {
    let app = Router::new()
        .route("/deal_share", post(handle_deal_share))
        .route("/reshare_share", post(handle_reshare_share))
        .route("/partial_key", post(handle_partial_key))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Signer listening on port {}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

// ── /partial_key ──────────────────────────────────────────────────────────────

async fn handle_partial_key(
    State(state): State<SignerState>,
    Json(req): Json<PartialKeyRequest>,
) -> impl IntoResponse {
    let identity = match hex::decode(req.identity_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid identity_hex".to_string()),
    };

    let my_addr_lower = format!("0x{}", hex::encode(state.my_address));
    let node_list: Vec<String> = match state
        .rpc
        .view(
            &format!("{}::ace_network::get_current_epoch", state.contract_addr),
            &[],
            &[serde_json::json!(state.contract_addr)],
        )
        .await
    {
        Ok(vals) => vals
            .get(1)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default(),
        Err(e) => {
            error!("[partial_key] get_current_epoch failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string());
        }
    };

    let my_index = match node_list.iter().position(|n| n == &my_addr_lower) {
        Some(i) => (i + 1) as u8,
        None => {
            warn!("[partial_key] not in current committee");
            return (StatusCode::BAD_REQUEST, "not in committee".to_string());
        }
    };

    let scalar_share_le: [u8; 32] = {
        let locked = state.store.lock().await;
        match locked.get(req.secret_id) {
            Some(row) => match hex::decode(&row.scalar_share_hex) {
                Ok(b) if b.len() == 32 => b.try_into().unwrap(),
                _ => {
                    error!("[partial_key] invalid scalar in store");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string());
                }
            },
            None => {
                warn!("[partial_key] no share for secret_id={}", req.secret_id);
                return (StatusCode::SERVICE_UNAVAILABLE, "Key share not yet derived".to_string());
            }
        }
    };

    match crypto::partial_extract(&identity, &scalar_share_le, my_index) {
        Ok(hex_result) => {
            info!("[partial_key] ok secret_id={} index={}", req.secret_id, my_index);
            (StatusCode::OK, hex_result)
        }
        Err(e) => {
            error!("[partial_key] extract error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        }
    }
}

// ── /deal_share ───────────────────────────────────────────────────────────────

async fn handle_deal_share(
    State(state): State<SignerState>,
    Json(msg): Json<DealMsg>,
) -> impl IntoResponse {
    let my_addr = format!("0x{}", hex::encode(state.my_address)).to_lowercase();
    let my_index = match state
        .rpc
        .view(
            &format!("{}::ace_network::get_current_epoch", state.contract_addr),
            &[],
            &[serde_json::json!(state.contract_addr)],
        )
        .await
    {
        Ok(vals) => {
            let nodes: Vec<String> = vals
                .get(1)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_lowercase())).collect())
                .unwrap_or_default();
            match nodes.iter().position(|n| n == &my_addr) {
                Some(i) => (i + 1) as u64,
                None => {
                    warn!("[deal_share] not in committee");
                    return (StatusCode::BAD_REQUEST, "not in committee");
                }
            }
        }
        Err(e) => {
            error!("[deal_share] get epoch failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "failed to get epoch");
        }
    };

    let share_fr = match msg.parse_share() {
        Ok(s) => s,
        Err(e) => { warn!("[deal_share] invalid share: {}", e); return (StatusCode::BAD_REQUEST, "invalid share"); }
    };
    let commitments = match msg.parse_commitments() {
        Ok(c) => c,
        Err(e) => { warn!("[deal_share] invalid commitments: {}", e); return (StatusCode::BAD_REQUEST, "invalid commitments"); }
    };
    if !vss::verify_share(share_fr, my_index, &commitments) {
        warn!("[deal_share] verification failed from dealer {}", msg.dealer_index);
        return (StatusCode::BAD_REQUEST, "share verification failed");
    }

    {
        let mut locked = state.accum.lock().await;
        let entry = locked.shares.entry(msg.dkg_id).or_insert(ark_bls12_381::Fr::from(0u64));
        *entry += share_fr;
    }
    info!("[deal_share] accepted from dealer {} dkg_id={}", msg.dealer_index, msg.dkg_id);
    (StatusCode::OK, "ok")
}

// ── /reshare_share ────────────────────────────────────────────────────────────

async fn handle_reshare_share(
    State(state): State<SignerState>,
    Json(msg): Json<ReshareMsg>,
) -> impl IntoResponse {
    let my_addr = format!("0x{}", hex::encode(state.my_address)).to_lowercase();
    let my_new_index = match state
        .rpc
        .view(
            &format!("{}::ace_network::get_epoch_change_details", state.contract_addr),
            &[],
            &[
                serde_json::json!(state.contract_addr),
                serde_json::json!(msg.epoch_change_id.to_string()),
            ],
        )
        .await
    {
        Ok(vals) => {
            let nodes: Vec<String> = vals
                .get(0)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_lowercase())).collect())
                .unwrap_or_default();
            match nodes.iter().position(|n| n == &my_addr) {
                Some(i) => (i + 1) as u64,
                None => {
                    warn!("[reshare_share] not in new committee");
                    return (StatusCode::BAD_REQUEST, "not in new committee");
                }
            }
        }
        Err(e) => {
            error!("[reshare_share] get epoch change failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "failed to get committee");
        }
    };

    let share_fr = match msg.parse_share() {
        Ok(s) => s,
        Err(e) => { warn!("[reshare_share] invalid share: {}", e); return (StatusCode::BAD_REQUEST, "invalid share"); }
    };
    let commitments = match msg.parse_commitments() {
        Ok(c) => c,
        Err(e) => { warn!("[reshare_share] invalid commitments: {}", e); return (StatusCode::BAD_REQUEST, "invalid commitments"); }
    };
    if !vss::verify_share(share_fr, my_new_index, &commitments) {
        warn!("[reshare_share] verification failed from dealer {}", msg.dealer_old_index);
        return (StatusCode::BAD_REQUEST, "share verification failed");
    }

    {
        let mut locked = state.reshare_accum.lock().await;
        let entry = locked.sub_shares.entry((msg.epoch_change_id, msg.secret_id)).or_default();
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
