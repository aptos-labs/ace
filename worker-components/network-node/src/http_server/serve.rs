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
use super::status::StatusResponse;
use super::state::{AppState, SecretsServerState};
use crate::secrets::SecretsSnapshotWire;
use crate::wlog;

/// Spawn the user-request server. Runs until the process exits.
pub async fn run_user_server(port: u16, state: AppState) {
    let app = Router::new()
        .route("/", post(handle_request))
        .route("/healthz", get(handle_healthz))
        .route("/status", get(handle_user_status))
        .route("/debug/status", get(handle_user_status))
        .with_state(state)
        .layer(CorsLayer::permissive());
    serve(port, app, "http-server (user)").await;
}

pub async fn run_secrets_server(port: u16, state: SecretsServerState) {
    let app = Router::new()
        .route("/secrets", get(handle_get_secrets))
        .route("/healthz", get(handle_secrets_healthz))
        .route("/status", get(handle_secrets_status))
        .route("/debug/status", get(handle_secrets_status))
        .with_state(state);
    serve(port, app, "http-server (secrets)").await;
}

async fn handle_healthz() -> StatusCode {
    StatusCode::OK
}

async fn handle_user_status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(state.status.response().await)
}

async fn handle_get_secrets(State(state): State<SecretsServerState>) -> Json<SecretsSnapshotWire> {
    Json(state.local.snapshot_wire().await)
}

async fn handle_secrets_healthz() -> StatusCode {
    StatusCode::OK
}

async fn handle_secrets_status(State(state): State<SecretsServerState>) -> Json<StatusResponse> {
    Json(state.status.response().await)
}

async fn serve(port: u16, app: Router, label: &str) {
    let addr = format!("0.0.0.0:{}", port);
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
