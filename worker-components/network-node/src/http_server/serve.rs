// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::CorsLayer;

use super::request::handle_request;
use super::status::{DebugStatusResponse, PublicStatusResponse};
use super::state::{AppState, SecretsServerState};
use crate::secrets::SecretsSnapshotWire;
use crate::wlog;

/// Spawn the user-request server. Runs until the process exits.
pub async fn run_user_server(port: u16, state: AppState) {
    serve(port, user_router(state), "http-server (user)").await;
}

pub async fn run_user_admin_server(port: u16, state: AppState) {
    serve_loopback(port, user_admin_router(state), "http-server (user-admin)").await;
}

pub async fn run_secrets_server(port: u16, state: SecretsServerState) {
    serve(port, secrets_router(state), "http-server (secrets)").await;
}

pub async fn run_secrets_admin_server(port: u16, state: SecretsServerState) {
    serve_loopback(
        port,
        secrets_admin_router(state),
        "http-server (secrets-admin)",
    )
    .await;
}

fn user_router(state: AppState) -> Router {
    Router::new()
        .route("/", post(handle_request))
        .route("/healthz", get(handle_healthz))
        .route("/status", get(handle_user_status))
        .with_state(state)
        .layer(CorsLayer::permissive())
}

fn user_admin_router(state: AppState) -> Router {
    Router::new()
        .route("/debug/status", get(handle_user_debug_status))
        .with_state(state)
}

fn secrets_router(state: SecretsServerState) -> Router {
    Router::new()
        .route("/secrets", get(handle_get_secrets))
        .route("/healthz", get(handle_secrets_healthz))
        .route("/status", get(handle_secrets_status))
        .with_state(state)
}

fn secrets_admin_router(state: SecretsServerState) -> Router {
    Router::new()
        .route("/debug/status", get(handle_secrets_debug_status))
        .with_state(state)
}

async fn handle_healthz() -> StatusCode {
    StatusCode::OK
}

async fn handle_user_status(State(state): State<AppState>) -> Json<PublicStatusResponse> {
    Json(state.status.public_response())
}

async fn handle_user_debug_status(State(state): State<AppState>) -> Json<DebugStatusResponse> {
    Json(state.status.debug_response().await)
}

async fn handle_get_secrets(State(state): State<SecretsServerState>) -> Json<SecretsSnapshotWire> {
    Json(state.local.snapshot_wire().await)
}

async fn handle_secrets_healthz() -> StatusCode {
    StatusCode::OK
}

async fn handle_secrets_status(
    State(state): State<SecretsServerState>,
) -> Json<PublicStatusResponse> {
    Json(state.status.public_response())
}

async fn handle_secrets_debug_status(
    State(state): State<SecretsServerState>,
) -> Json<DebugStatusResponse> {
    Json(state.status.debug_response().await)
}

async fn serve(port: u16, app: Router, label: &str) {
    serve_addr(format!("0.0.0.0:{}", port), app, label).await
}

async fn serve_loopback(port: u16, app: Router, label: &str) {
    serve_addr(format!("127.0.0.1:{}", port), app, label).await
}

async fn serve_addr(addr: String, app: Router, label: &str) {
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            wlog!("{}: bind {} failed: {}", label, addr, e);
            return;
        }
    };
    wlog!("{}: listening on {}", label, addr);
    if let Err(e) = axum::serve(listener, app).await {
        wlog!("{}: serve error: {}", label, e);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use axum::{body::Body, http::Request};
    use tokio::sync::{RwLock, Semaphore};
    use tower::ServiceExt;
    use vss_common::AptosRpc;

    use super::super::status::{NodeStatus, PublicNodeConfig};
    use super::*;
    use crate::secrets::{LocalSecrets, SecretsProvider};
    use crate::ChainRpcConfig;

    fn rpc(label: &str) -> AptosRpc {
        AptosRpc::new(format!("https://{}.example/v1", label))
    }

    fn chain_rpc_config() -> ChainRpcConfig {
        ChainRpcConfig {
            aptos_mainnet: rpc("mainnet"),
            aptos_testnet: rpc("testnet"),
            aptos_localnet: rpc("localnet"),
            aptos_shelbynet: rpc("shelbynet"),
            aptos_shelby_private_beta: Some(rpc("shelby")),
            solana_mainnet_beta: "https://solana-mainnet.example".to_string(),
            solana_testnet: "https://solana-testnet.example".to_string(),
            solana_devnet: "https://solana-devnet.example".to_string(),
            solana_client: reqwest::Client::new(),
        }
    }

    fn local_secrets() -> LocalSecrets {
        LocalSecrets {
            shares: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn node_status() -> Arc<NodeStatus> {
        Arc::new(NodeStatus::new(PublicNodeConfig::new("handler"), Vec::new()))
    }

    fn app_state() -> AppState {
        AppState {
            provider: Arc::new(SecretsProvider::Local(local_secrets())),
            chain_rpc: Arc::new(chain_rpc_config()),
            concurrency: Arc::new(Semaphore::new(1)),
            pke_dk_bytes: Arc::new(Vec::new()),
            status: node_status(),
        }
    }

    fn secrets_state() -> SecretsServerState {
        SecretsServerState {
            local: local_secrets(),
            status: node_status(),
        }
    }

    async fn get_status(app: Router, path: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[tokio::test]
    async fn public_user_router_does_not_expose_debug_status() {
        assert_eq!(
            get_status(user_router(app_state()), "/debug/status").await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn public_secrets_router_does_not_expose_debug_status() {
        assert_eq!(
            get_status(secrets_router(secrets_state()), "/debug/status").await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn user_admin_router_exposes_debug_status() {
        assert_eq!(
            get_status(user_admin_router(app_state()), "/debug/status").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn secrets_admin_router_exposes_debug_status() {
        assert_eq!(
            get_status(secrets_admin_router(secrets_state()), "/debug/status").await,
            StatusCode::OK
        );
    }
}
