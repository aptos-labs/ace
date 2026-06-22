// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod selection;
mod share;
mod spawn;
mod stale;
mod task;
mod task_run;

use super::state::MaintainerState;
use crate::node::state_view::BcsStateViewV0;
use crate::node::tasks::TaskMap;
use crate::wlog;

use selection::ActiveSecretSessions;

pub(super) async fn reconcile(
    maintainer: &MaintainerState,
    state: &BcsStateViewV0,
    cur_node_idx: Option<usize>,
    reconstructions: &mut TaskMap,
) {
    let active_sessions = selection::from_state_view(state, cur_node_idx.is_some());
    for (session_addr, (expected_usage, note)) in &active_sessions {
        if reconstructions.contains_key(session_addr) {
            continue;
        }
        let Some(eval_point) = eval_point(cur_node_idx, session_addr) else {
            continue;
        };
        spawn::start_reconstruction(
            maintainer,
            state,
            session_addr,
            *expected_usage,
            note,
            eval_point,
            reconstructions,
        );
    }
    stale::stop_reconstructions(reconstructions, &active_sessions);
}

fn eval_point(cur_node_idx: Option<usize>, session_addr: &str) -> Option<u64> {
    cur_node_idx.map(|i| (i + 1) as u64).or_else(|| {
        wlog!(
            "network-node: [active-secret-sessions] {} unexpected: in_cur_nodes but no eval_point",
            session_addr
        );
        None
    })
}
