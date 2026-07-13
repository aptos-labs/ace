// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use axum::http::StatusCode;
use node_msg_gateway::{NodeHandlerError, WorkerRequestHandler};
use tokio::sync::Semaphore;
use vss_common::pke;

use crate::secrets::SecretsProvider;
use crate::ChainRpcConfig;

/// Shared state for the user-facing request handler.
#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<SecretsProvider>,
    pub chain_rpc: Arc<ChainRpcConfig>,
    pub concurrency: Arc<Semaphore>,
    pub pke_dk_bytes: Arc<Vec<u8>>,
}

#[async_trait::async_trait]
impl WorkerRequestHandler for AppState {
    async fn handle(
        &self,
        request: pke::Ciphertext,
    ) -> std::result::Result<pke::Ciphertext, NodeHandlerError> {
        super::request::handle_worker_ciphertext(self, request)
            .await
            .map_err(|status| worker_error(status))
    }
}

fn worker_error(status: StatusCode) -> NodeHandlerError {
    NodeHandlerError::new(
        status,
        format!("worker request rejected with HTTP {status}"),
    )
}
