// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod current;
mod next;

use super::state::MaintainerState;
use crate::node::state_view::{addr_bytes_to_string, BcsEpochChangeView, BcsStateViewV0};
use crate::node::tasks::{stop_tasks, TaskMap};

pub(crate) fn sync_epoch_change_tasks(
    maintainer: &MaintainerState,
    state: &BcsStateViewV0,
    in_cur_nodes: bool,
    cur_tasks: &mut TaskMap,
    nxt_tasks: &mut TaskMap,
) {
    let Some(info) = state.epoch_change_info.as_ref() else {
        stop_tasks(cur_tasks);
        stop_tasks(nxt_tasks);
        return;
    };
    let session = addr_bytes_to_string(&info.session_addr);
    sync_cur_task(maintainer, &session, in_cur_nodes, cur_tasks);
    sync_nxt_task(maintainer, info, &session, nxt_tasks);
}

fn sync_cur_task(
    maintainer: &MaintainerState,
    session: &str,
    in_cur_nodes: bool,
    tasks: &mut TaskMap,
) {
    if !in_cur_nodes {
        stop_tasks(tasks);
    } else if !tasks.contains_key(session) {
        current::start_task(maintainer, session, tasks);
    }
}

fn sync_nxt_task(
    maintainer: &MaintainerState,
    info: &BcsEpochChangeView,
    session: &str,
    tasks: &mut TaskMap,
) {
    let in_nxt_nodes = info
        .nxt_nodes
        .iter()
        .any(|n| addr_bytes_to_string(n) == maintainer.account_addr);
    if !in_nxt_nodes {
        stop_tasks(tasks);
    } else if !tasks.contains_key(session) {
        next::start_task(maintainer, session, tasks);
    }
}
