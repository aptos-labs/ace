// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use tokio::sync::oneshot;

use super::reconcile;
use super::state::MaintainerState;
use crate::node::tasks::{stop_tasks, TaskMap};
use crate::wlog;

pub(crate) async fn reconcile_loop(
    maintainer: MaintainerState,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let mut session_reconstructions = TaskMap::new();
    let mut epoch_cur_tasks = TaskMap::new();
    let mut epoch_nxt_tasks = TaskMap::new();
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                wlog!("network-node: shutdown signal received.");
                stop_tasks(&mut session_reconstructions);
                stop_tasks(&mut epoch_cur_tasks);
                stop_tasks(&mut epoch_nxt_tasks);
                return Ok(());
            }
            _ = interval.tick() => {}
        }
        if let Err(e) = reconcile::reconcile(
            &maintainer,
            &mut session_reconstructions,
            &mut epoch_cur_tasks,
            &mut epoch_nxt_tasks,
        )
        .await
        {
            wlog!("network-node: fetch state view error: {:#}", e);
        }
    }
}
