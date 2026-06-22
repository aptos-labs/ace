// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::sync::Semaphore;

use super::super::concurrency::resolve_max_concurrent;
use super::super::HandlerLocalConfig;
use super::state::MaintainerState;
use crate::http_server;
use crate::secrets::SecretsProvider;

pub(crate) fn spawn_optional_servers(
    maintainer: &MaintainerState,
    handler_local: Option<HandlerLocalConfig>,
    secrets_server_port: Option<u16>,
) {
    if let Some(h) = handler_local {
        spawn_user_server(maintainer, h);
    }
    if let Some(port) = secrets_server_port {
        let state = http_server::SecretsServerState {
            local: maintainer.local.clone(),
        };
        tokio::spawn(http_server::run_secrets_server(port, state));
    }
}

fn spawn_user_server(maintainer: &MaintainerState, h: HandlerLocalConfig) {
    let state = http_server::AppState {
        provider: Arc::new(SecretsProvider::Local(maintainer.local.clone())),
        chain_rpc: Arc::new(h.chain_rpc),
        concurrency: Arc::new(Semaphore::new(resolve_max_concurrent(h.max_concurrent))),
        pke_dk_bytes: maintainer.pke_dk_bytes.clone(),
    };
    tokio::spawn(http_server::run_user_server(h.port, state));
}
