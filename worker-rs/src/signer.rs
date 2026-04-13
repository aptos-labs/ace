// Signer HTTP server: internal /partial_key for the public server.

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

use crate::{aptos_rpc::AptosRpc, crypto, store::ShareStore};

#[derive(Clone)]
pub struct SignerState {
    pub contract_addr: String,
    pub rpc: AptosRpc,
    pub my_address: [u8; 32],
    pub store: Arc<Mutex<ShareStore>>,
}

#[derive(Deserialize)]
pub struct PartialKeyRequest {
    pub identity_hex: String,
    pub secret_id: u64,
}

pub async fn run(port: u16, state: SignerState) -> Result<()> {
    let app = Router::new()
        .route("/partial_key", post(handle_partial_key))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Signer listening on port {}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

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
