// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::{oneshot, Semaphore};

use super::concurrency::resolve_max_concurrent;
use super::ChainRpcConfig;
use crate::http_server;
use crate::secrets::{RemoteSecrets, SecretsProvider};
use crate::wlog;

pub(crate) async fn run_handler(
    maintainer_url: String,
    pke_dk: String,
    port: u16,
    chain_rpc: ChainRpcConfig,
    max_concurrent: Option<usize>,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    wlog!(
        "network-node: starting handler-only (maintainer_url={})",
        maintainer_url
    );
    let state = http_server::AppState {
        provider: Arc::new(SecretsProvider::Remote(Arc::new(RemoteSecrets::new(
            maintainer_url,
        )))),
        chain_rpc: Arc::new(chain_rpc),
        concurrency: Arc::new(Semaphore::new(resolve_max_concurrent(max_concurrent))),
        pke_dk_bytes: Arc::new(decode_hex_key(&pke_dk)?),
    };
    tokio::spawn(http_server::run_user_server(port, state));
    let _ = shutdown_rx.await;
    wlog!("network-node: handler shutdown signal received.");
    Ok(())
}

pub(crate) fn decode_hex_key(value: &str) -> Result<Vec<u8>> {
    let raw = value.trim().trim_start_matches("0x");
    hex::decode(raw).map_err(|e| anyhow!("pke_dk decode: {}", e))
}
