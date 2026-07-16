// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::sync::Semaphore;

use super::status::NodeStatus;
use crate::secrets::{LocalSecrets, SecretsProvider};
use crate::ChainRpcConfig;

/// Shared state for the user-facing request handler.
#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<SecretsProvider>,
    pub chain_rpc: Arc<ChainRpcConfig>,
    pub concurrency: Arc<Semaphore>,
    pub pke_dk_bytes: Arc<Vec<u8>>,
    pub status: Arc<NodeStatus>,
}

#[derive(Clone)]
pub struct SecretsServerState {
    pub local: LocalSecrets,
    pub status: Arc<NodeStatus>,
}
