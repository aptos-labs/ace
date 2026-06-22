// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsSecretRequest {
    expected_usage: u64,
    note: String,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsProposedEpochConfig {
    nodes: Vec<[u8; 32]>,
    threshold: u64,
    epoch_duration_micros: u64,
    secrets_to_retain: Vec<[u8; 32]>,
    new_secrets: Vec<BcsSecretRequest>,
    description: String,
    target_epoch: u64,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub(crate) struct BcsProposalView {
    proposal: BcsProposedEpochConfig,
    voting_session: [u8; 32],
    votes: Vec<bool>,
    pub(crate) voting_passed: bool,
}
