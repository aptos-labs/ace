// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::proposal::BcsProposalView;

#[derive(serde::Deserialize)]
pub(crate) struct BcsEpochChangeView {
    #[allow(dead_code)]
    triggering_proposal_idx: Option<u64>,
    pub(crate) session_addr: [u8; 32],
    pub(crate) nxt_nodes: Vec<[u8; 32]>,
    #[allow(dead_code)]
    nxt_threshold: u64,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub(crate) struct BcsSecretInfo {
    pub(crate) current_session: [u8; 32],
    keypair_id: [u8; 32],
    scheme: u8,
    pub(crate) expected_usage: u64,
    pub(crate) note: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct BcsStateViewV0 {
    pub(crate) epoch: u64,
    pub(crate) epoch_start_time_micros: u64,
    pub(crate) epoch_duration_micros: u64,
    pub(crate) cur_nodes: Vec<[u8; 32]>,
    #[allow(dead_code)]
    cur_threshold: u64,
    pub(crate) secrets: Vec<BcsSecretInfo>,
    pub(crate) proposals: Vec<Option<BcsProposalView>>,
    pub(crate) epoch_change_info: Option<BcsEpochChangeView>,
}
