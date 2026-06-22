// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::state::MaintainerState;
use super::{active_secret_sessions, epoch, touch};
use crate::node::state_view::{addr_bytes_to_string, fetch_state_view_v0, BcsStateViewV0};
use crate::node::tasks::TaskMap;

pub(super) async fn reconcile(
    maintainer: &MaintainerState,
    session_reconstructions: &mut TaskMap,
    epoch_cur_tasks: &mut TaskMap,
    epoch_nxt_tasks: &mut TaskMap,
) -> Result<()> {
    let state_view = fetch_state_view_v0(&maintainer.rpc, &maintainer.ace).await?;
    let cur_node_idx = current_node_index(maintainer, &state_view);
    touch::maybe_submit_touch(maintainer, &state_view, cur_node_idx).await;
    epoch::sync_epoch_change_tasks(
        maintainer,
        &state_view,
        cur_node_idx.is_some(),
        epoch_cur_tasks,
        epoch_nxt_tasks,
    );
    active_secret_sessions::reconcile(
        maintainer,
        &state_view,
        cur_node_idx,
        session_reconstructions,
    )
    .await;
    Ok(())
}

fn current_node_index(maintainer: &MaintainerState, state: &BcsStateViewV0) -> Option<usize> {
    state
        .cur_nodes
        .iter()
        .position(|n| addr_bytes_to_string(n) == maintainer.account_addr)
}
