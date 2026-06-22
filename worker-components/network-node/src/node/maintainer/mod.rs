// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

#[path = "active-secret-sessions/mod.rs"]
mod active_secret_sessions;
mod cleanup;
mod epoch;
mod epoch_config;
mod reconcile;
mod reconcile_loop;
mod servers;
mod state;
mod state_init;
mod touch;

use anyhow::Result;
use tokio::sync::oneshot;

use super::{HandlerLocalConfig, MaintainerConfig};
use state::MaintainerState;

pub(crate) async fn run_with_maintainer(
    config: MaintainerConfig,
    handler_local: Option<HandlerLocalConfig>,
    secrets_server_port: Option<u16>,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let maintainer = MaintainerState::new(config)?;
    servers::spawn_optional_servers(&maintainer, handler_local, secrets_server_port);
    cleanup::spawn_cleanup(&maintainer);
    reconcile_loop::reconcile_loop(maintainer, shutdown_rx).await
}
