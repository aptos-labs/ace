// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod chain_rpc;
mod concurrency;
mod config;
mod handler;
mod maintainer;
mod state_view;
mod tasks;

use anyhow::Result;
use tokio::sync::oneshot;

pub use chain_rpc::ChainRpcConfig;
pub use config::{HandlerLocalConfig, MaintainerConfig, Mode};

pub async fn run(mode: Mode, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    match mode {
        Mode::Monolith {
            maintainer,
            handler,
        } => maintainer::run_with_maintainer(maintainer, handler, None, shutdown_rx).await,
        Mode::Maintainer { maintainer, port } => {
            maintainer::run_with_maintainer(maintainer, None, Some(port), shutdown_rx).await
        }
        Mode::Handler {
            maintainer_url,
            pke_dk,
            port,
            chain_rpc,
            max_concurrent,
        } => {
            handler::run_handler(
                maintainer_url,
                pke_dk,
                port,
                chain_rpc,
                max_concurrent,
                shutdown_rx,
            )
            .await
        }
    }
}
