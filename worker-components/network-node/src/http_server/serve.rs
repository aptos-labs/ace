// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use axum::{
    http::StatusCode,
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;

use super::request::handle_request;
use super::state::AppState;
use crate::wlog;

/// Spawn the user-request server. Runs until the process exits.
pub async fn run_user_server(port: u16, state: AppState) {
    let app = Router::new()
        .route("/", post(handle_request))
        .route("/healthz", get(handle_healthz))
        .with_state(state)
        .layer(CorsLayer::permissive());
    serve(port, app, "http-server (user)").await;
}

async fn handle_healthz() -> StatusCode {
    StatusCode::OK
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
