// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::should_submit_rotating_touch;

use super::state::MaintainerState;
use crate::node::state_view::BcsStateViewV0;
use crate::wlog;

pub(crate) async fn maybe_submit_touch(
    maintainer: &MaintainerState,
    state: &BcsStateViewV0,
    cur_node_idx: Option<usize>,
) {
    if !should_touch(state, cur_node_idx) {
        return;
    }
    if let Err(e) = maintainer
        .rpc
        .submit_txn(
            &maintainer.sk,
            &maintainer.vk,
            &maintainer.account_addr,
            &format!("{}::network::touch", maintainer.ace),
            &[],
            &[],
        )
        .await
    {
        wlog!("network-node: network::touch error: {:#}", e);
    }
}

fn should_touch(state: &BcsStateViewV0, cur_node_idx: Option<usize>) -> bool {
    let needs_touch =
        state.epoch_change_info.is_some() || epoch_timed_out(state) || has_approved_proposal(state);
    needs_touch
        && cur_node_idx
            .map(|idx| should_submit_rotating_touch(idx, state.cur_nodes.len()))
            .unwrap_or(false)
}

fn epoch_timed_out(state: &BcsStateViewV0) -> bool {
    let now_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    now_micros
        >= state
            .epoch_start_time_micros
            .saturating_add(state.epoch_duration_micros)
}

fn has_approved_proposal(state: &BcsStateViewV0) -> bool {
    state
        .proposals
        .iter()
        .any(|p| p.as_ref().is_some_and(|pv| pv.voting_passed))
}
