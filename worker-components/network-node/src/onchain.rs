// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use vss_common::group::{BcsElement, BcsScalar};
use vss_common::session::BcsPcsPublicParams;
use vss_common::AptosRpc;

// ── BCS mirror of ace::network::StateViewV0 ─────────────────────────────────

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub(crate) struct BcsSecretRequest {
    pub(crate) expected_usage: u64,
    pub(crate) note: String,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub(crate) struct BcsProposedEpochConfig {
    pub(crate) nodes: Vec<[u8; 32]>,
    pub(crate) threshold: u64,
    pub(crate) epoch_duration_micros: u64,
    pub(crate) secrets_to_retain: Vec<[u8; 32]>,
    pub(crate) new_secrets: Vec<BcsSecretRequest>,
    pub(crate) description: String,
    pub(crate) target_epoch: u64,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub(crate) struct BcsProposalView {
    pub(crate) proposal: BcsProposedEpochConfig,
    pub(crate) voting_session: [u8; 32],
    pub(crate) votes: Vec<bool>,
    pub(crate) voting_passed: bool,
}

#[derive(serde::Deserialize)]
pub(crate) struct BcsEpochChangeView {
    #[allow(dead_code)]
    pub(crate) triggering_proposal_idx: Option<u64>,
    pub(crate) session_addr: [u8; 32],
    pub(crate) nxt_nodes: Vec<[u8; 32]>,
    #[allow(dead_code)]
    pub(crate) nxt_threshold: u64,
}

#[allow(dead_code)]
#[derive(Clone, serde::Deserialize)]
pub(crate) struct BcsSecretInfo {
    pub(crate) current_session: [u8; 32],
    pub(crate) keypair_id: [u8; 32],
    pub(crate) scheme: u8,
    pub(crate) expected_usage: u64,
    pub(crate) note: String,
}

#[allow(dead_code)]
#[derive(Clone, serde::Deserialize)]
pub(crate) struct BcsEpochSnapshot {
    pub(crate) nodes: Vec<[u8; 32]>,
    pub(crate) secrets: Vec<BcsSecretInfo>,
}

#[derive(serde::Deserialize)]
pub(crate) struct BcsStateViewV0 {
    pub(crate) epoch: u64,
    pub(crate) epoch_start_time_micros: u64,
    pub(crate) epoch_duration_micros: u64,
    pub(crate) cur_nodes: Vec<[u8; 32]>,
    #[allow(dead_code)]
    pub(crate) cur_threshold: u64,
    pub(crate) secrets: Vec<BcsSecretInfo>,
    pub(crate) previous_epoch_info: Option<BcsEpochSnapshot>,
    pub(crate) proposals: Vec<Option<BcsProposalView>>,
    pub(crate) epoch_change_info: Option<BcsEpochChangeView>,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub(crate) struct BcsDkgSession {
    pub(crate) caller: [u8; 32],
    pub(crate) workers: Vec<[u8; 32]>,
    pub(crate) threshold: u64,
    pub(crate) scheme: u8,
    pub(crate) pcs_context: BcsPcsPublicParams,
    pub(crate) expected_usage: u64,
    pub(crate) note: String,
    pub(crate) state: u8,
    pub(crate) vss_sessions: Vec<[u8; 32]>,
    pub(crate) done_flags: Vec<bool>,
    pub(crate) commitment_points: Vec<BcsElement>,
    pub(crate) public_keys: Vec<BcsElement>,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub(crate) struct BcsDkrSession {
    pub(crate) caller: [u8; 32],
    pub(crate) original_session: [u8; 32],
    pub(crate) previous_session: [u8; 32],
    pub(crate) expected_usage: u64,
    pub(crate) note: String,
    pub(crate) current_nodes: Vec<[u8; 32]>,
    pub(crate) current_threshold: u64,
    pub(crate) new_nodes: Vec<[u8; 32]>,
    pub(crate) new_threshold: u64,
    pub(crate) pcs_context: BcsPcsPublicParams,
    pub(crate) src_pcs_context: BcsPcsPublicParams,
    pub(crate) src_commitment_points: Vec<BcsElement>,
    pub(crate) src_public_keys: Vec<BcsElement>,
    pub(crate) state_code: u8,
    pub(crate) vss_sessions: Vec<[u8; 32]>,
    pub(crate) vss_contribution_flags: Vec<bool>,
    pub(crate) lagrange_coeffs_at_zero: Vec<BcsScalar>,
    pub(crate) commitment_points: Vec<BcsElement>,
    pub(crate) public_keys: Vec<BcsElement>,
}

pub(crate) fn addr_bytes_to_string(addr: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(addr))
}

pub(crate) fn addr_string_to_bytes(addr: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(addr.trim_start_matches("0x"))?;
    raw.try_into()
        .map_err(|b: Vec<u8>| anyhow!("address has length {} (want 32)", b.len()))
}

pub(crate) async fn fetch_state_view_v0(rpc: &AptosRpc, ace: &str) -> Result<BcsStateViewV0> {
    let result = rpc
        .call_view(&format!("{}::network::state_view_v0_bcs", ace), &[])
        .await?;
    let hex = result
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("expected string in state_view_v0_bcs result"))?;
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    bcs::from_bytes(&bytes).map_err(|e| anyhow!("bcs decode StateViewV0: {}", e))
}

pub(crate) async fn fetch_dkg_session_bcs(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
) -> Result<BcsDkgSession> {
    let result = rpc
        .call_view(
            &format!("{}::dkg::get_session_bcs", ace),
            &[serde_json::json!(session_addr)],
        )
        .await?;
    let hex = result
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("expected string in dkg::get_session_bcs result"))?;
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    bcs::from_bytes(&bytes).map_err(|e| anyhow!("bcs decode DKG Session: {}", e))
}

pub(crate) async fn fetch_dkr_session_bcs(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
) -> Result<BcsDkrSession> {
    let result = rpc
        .call_view(
            &format!("{}::dkr::get_session_bcs", ace),
            &[serde_json::json!(session_addr)],
        )
        .await?;
    let hex = result
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("expected string in dkr::get_session_bcs result"))?;
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    bcs::from_bytes(&bytes).map_err(|e| anyhow!("bcs decode DKR Session: {}", e))
}
