// Public-facing HTTP server
//
// Routes exposed to end users:
//   GET  /health       — liveness probe
//   GET  /ibe_mpk      — fetch the committee MPK (informational)
//   POST /             — decrypt request: verify permission, then call signer /partial_key
//
// Routes proxied transparently to the signer (worker-to-worker DKG/DKR traffic
// arrives here because the public URL is what peers registered on-chain):
//   POST /deal_share
//   POST /reshare_share

use anyhow::Result;
use axum::{
    body::Bytes,
    extract::State,
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    aptos_rpc::AptosRpc,
    types::RequestForDecryptionKey,
    verify,
};

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PublicServerState {
    pub contract_addr: String,
    pub rpc: AptosRpc,
    /// Base URL of the signer process, e.g. "http://localhost:9100"
    pub signer_url: String,
    pub http_client: reqwest::Client,
}

// ── Server entrypoint ─────────────────────────────────────────────────────────

pub async fn run(port: u16, state: PublicServerState) -> Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(handle_root).post(handle_post))
        .route("/ibe_mpk", get(handle_ibe_mpk))
        .route("/health", get(handle_health))
        // Proxy DKG/DKR traffic to the signer (peers send here because this is
        // the registered public endpoint).
        .route("/deal_share", post(proxy_to_signer))
        .route("/reshare_share", post(proxy_to_signer))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Public server listening on port {}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Utility endpoints ─────────────────────────────────────────────────────────

async fn handle_root() -> impl IntoResponse {
    (StatusCode::OK, "ACE Worker OK")
}

async fn handle_health(State(state): State<PublicServerState>) -> impl IntoResponse {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    (StatusCode::OK, axum::Json(json!({ "status": "ok", "timestamp": ts,
        "signer": state.signer_url })))
}

async fn handle_ibe_mpk(State(state): State<PublicServerState>) -> impl IntoResponse {
    match state
        .rpc
        .view(
            &format!("{}::ace_network::get_secret", state.contract_addr),
            &[],
            &[json!(state.contract_addr), json!("0")],
        )
        .await
    {
        Ok(vals) => {
            if let Some(mpk_hex) = vals.get(0).and_then(|v| v.as_str()) {
                (StatusCode::OK, mpk_hex.trim_start_matches("0x").to_string())
            } else {
                (StatusCode::SERVICE_UNAVAILABLE, "MPK not yet available".to_string())
            }
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "MPK not yet available".to_string()),
    }
}

// ── Transparent proxy for DKG/DKR ────────────────────────────────────────────
//
// The path is preserved: /deal_share → signer /deal_share, etc.
// Axum doesn't expose the matched path in a plain handler, so we use a
// different approach: each proxied route calls this same helper and the signer
// URL suffix is derived from the request URI extension point. Instead we just
// have the caller pass the suffix explicitly — but here both routes call
// `proxy_to_signer` and we need to know which path to forward to.
//
// We solve this by extracting the original URI from the axum request parts.

async fn proxy_to_signer(
    State(state): State<PublicServerState>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let path = req.uri().path().to_string();
    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "failed to read body".to_string()),
    };

    let url = format!("{}{}", state.signer_url.trim_end_matches('/'), path);
    match state
        .http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body_bytes.to_vec())
        .send()
        .await
    {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = resp.text().await.unwrap_or_default();
            (status, body)
        }
        Err(e) => {
            error!("[proxy{}] signer unreachable: {}", path, e);
            (StatusCode::BAD_GATEWAY, "signer unreachable".to_string())
        }
    }
}

// ── /  (decrypt request) ──────────────────────────────────────────────────────

async fn handle_post(
    State(state): State<PublicServerState>,
    body: Bytes,
) -> impl IntoResponse {
    let session_id = &Uuid::new_v4().to_string()[..8];
    info!("[{}] BEGIN", session_id);

    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return (StatusCode::BAD_REQUEST, "Could not parse request.".to_string()),
    };

    let request = match RequestForDecryptionKey::from_hex(&body_str) {
        Ok(r) => r,
        Err(e) => {
            warn!("[{}] parse error: {}", session_id, e);
            return (StatusCode::BAD_REQUEST, "Could not parse request.".to_string());
        }
    };

    if request.contract_id_scheme != 0 || request.proof_scheme != 0 {
        warn!("[{}] unsupported scheme", session_id);
        return (StatusCode::BAD_REQUEST, "Only Aptos scheme supported".to_string());
    }

    let cid = &request.aptos_contract_id;

    // Verify permission — public server is responsible for this.
    if let Err(e) = verify::verify_aptos_permission(
        &state.rpc,
        cid.chain_id,
        &cid.module_addr,
        &cid.module_name,
        &cid.function_name,
        &request.domain,
        &request.aptos_proof,
    )
    .await
    {
        warn!("[{}] DENIED: {}", session_id, e);
        return (StatusCode::BAD_REQUEST, "Permission denied".to_string());
    }

    // Fetch the latest secret_id.
    let secret_id = match state
        .rpc
        .view(
            &format!("{}::ace_network::get_secret_count", state.contract_addr),
            &[],
            &[json!(state.contract_addr)],
        )
        .await
    {
        Ok(vals) => {
            let count = vals
                .get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            if count == 0 {
                return (StatusCode::SERVICE_UNAVAILABLE, "No secrets available yet".to_string());
            }
            count - 1
        }
        Err(e) => {
            error!("[{}] get_secret_count failed: {}", session_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string());
        }
    };

    // Compute the identity bytes (FullDecryptionDomain serialisation).
    let identity = full_decryption_domain_to_bytes(&request);

    // Delegate the actual signing to the signer.
    let signer_req = json!({
        "identity_hex": hex::encode(&identity),
        "secret_id": secret_id,
    });
    let url = format!("{}/partial_key", state.signer_url.trim_end_matches('/'));
    match state.http_client.post(&url).json(&signer_req).send().await {
        Ok(resp) if resp.status().is_success() => {
            let hex_result = resp.text().await.unwrap_or_default();
            info!("[{}] APPROVED", session_id);
            (StatusCode::OK, hex_result)
        }
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = resp.text().await.unwrap_or_default();
            warn!("[{}] signer returned {}: {}", session_id, status, body);
            (status, body)
        }
        Err(e) => {
            error!("[{}] signer call failed: {}", session_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        }
    }
}

// ── Identity serialisation (FullDecryptionDomain.serialize()) ─────────────────

fn full_decryption_domain_to_bytes(req: &RequestForDecryptionKey) -> Vec<u8> {
    let mut out = Vec::new();
    let cid = &req.aptos_contract_id;
    out.push(req.contract_id_scheme);
    out.push(cid.chain_id);
    out.extend_from_slice(&cid.module_addr);
    encode_uleb128_to(cid.module_name.len() as u64, &mut out);
    out.extend_from_slice(cid.module_name.as_bytes());
    encode_uleb128_to(cid.function_name.len() as u64, &mut out);
    out.extend_from_slice(cid.function_name.as_bytes());
    encode_uleb128_to(req.domain.len() as u64, &mut out);
    out.extend_from_slice(&req.domain);
    out
}

fn encode_uleb128_to(mut val: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 { out.push(byte); break; } else { out.push(byte | 0x80); }
    }
}
