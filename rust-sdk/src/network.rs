// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/network/index.ts`: the on-chain `network::State` view and primitive/usage
//! constants. Layouts are plain BCS, so they are serde-derived (Option = 0/1 tag, Vec = uleb len).

use serde::{Deserialize, Serialize};

use crate::address::AccountAddress;
use crate::error::{AceError, Result};
use crate::impl_bcs_wire;

pub const PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC: u8 = 0;
pub const PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD: u8 = 1;
pub const PRIMITIVE_BLS12381_THRESHOLD_VRF: u8 = 2;
pub const PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM: u8 = 3;

pub const USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC: u64 = 1;
pub const USAGE_BFIBE_BLS12381_SHORTSIG_AEAD: u64 = 2;
pub const USAGE_BLS12381_THRESHOLD_VRF: u64 = 4;
pub const USAGE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM: u64 = 8;

pub fn usage_for_primitive(primitive: u8) -> Result<u64> {
    Ok(match primitive {
        PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC => USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
        PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD => USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
        PRIMITIVE_BLS12381_THRESHOLD_VRF => USAGE_BLS12381_THRESHOLD_VRF,
        PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM => USAGE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM,
        p => return Err(AceError::Other(format!("unsupported ACE primitive {p}"))),
    })
}

pub fn scheme_name(scheme: u8) -> String {
    match scheme {
        0 => "BLS12-381 G1 / BFIBE-shortpk-otp-hmac (legacy)".into(),
        1 => "BLS12-381 G2 / BFIBE-shortsig-aead (default)".into(),
        3 => "BLS12-381 G2 / BFIBE-shortsig-aead-stream (streaming + seekable)".into(),
        s => format!("unknown scheme {s}"),
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SecretInfo {
    pub current_session: AccountAddress,
    pub keypair_id: AccountAddress,
    pub scheme: u8,
    pub expected_usage: u64,
    pub note: String,
}

impl SecretInfo {
    pub fn scheme_name(&self) -> String {
        scheme_name(self.scheme)
    }
}
impl_bcs_wire!(SecretInfo);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SecretRequest {
    pub expected_usage: u64,
    pub note: String,
}
impl_bcs_wire!(SecretRequest);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProposedEpochConfig {
    pub nodes: Vec<AccountAddress>,
    pub threshold: u64,
    pub epoch_duration_micros: u64,
    pub secrets_to_retain: Vec<AccountAddress>,
    pub new_secrets: Vec<SecretRequest>,
    pub description: String,
    pub target_epoch: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProposalView {
    pub proposal: ProposedEpochConfig,
    pub voting_session: AccountAddress,
    pub votes: Vec<bool>,
    pub voting_passed: bool,
}

impl ProposalView {
    pub fn vote_count(&self) -> usize {
        self.votes.iter().filter(|v| **v).count()
    }
    pub fn has_voted(&self, node: &AccountAddress, cur_nodes: &[AccountAddress]) -> bool {
        cur_nodes
            .iter()
            .position(|n| n == node)
            .map(|i| self.votes.get(i) == Some(&true))
            .unwrap_or(false)
    }
}
impl_bcs_wire!(ProposalView);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EpochChangeView {
    pub triggering_proposal_idx: Option<u64>,
    pub session_addr: AccountAddress,
    pub nxt_nodes: Vec<AccountAddress>,
    pub nxt_threshold: u64,
}
impl_bcs_wire!(EpochChangeView);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct State {
    pub epoch: u64,
    pub epoch_start_time_micros: u64,
    pub epoch_duration_micros: u64,
    pub cur_nodes: Vec<AccountAddress>,
    pub cur_threshold: u64,
    pub secrets: Vec<SecretInfo>,
    pub proposals: Vec<Option<ProposalView>>,
    pub epoch_change_info: Option<EpochChangeView>,
}

impl State {
    pub fn is_epoch_changing(&self) -> bool {
        self.epoch_change_info.is_some()
    }
    pub fn active_proposals(&self) -> impl Iterator<Item = &ProposalView> {
        self.proposals.iter().flatten()
    }
    pub fn secret(&self, keypair_id: &AccountAddress) -> Option<&SecretInfo> {
        self.secrets.iter().find(|s| &s.keypair_id == keypair_id)
    }
}
impl_bcs_wire!(State);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Wire;

    #[test]
    fn state_roundtrip_and_layout() {
        let st = State {
            epoch: 7,
            epoch_start_time_micros: 1,
            epoch_duration_micros: 3_600_000_000,
            cur_nodes: vec![AccountAddress::ONE],
            cur_threshold: 1,
            secrets: vec![SecretInfo {
                current_session: AccountAddress::ONE,
                keypair_id: AccountAddress::ONE,
                scheme: 1,
                expected_usage: 2,
                note: "n".into(),
            }],
            proposals: vec![None],
            epoch_change_info: None,
        };
        let b = st.to_bytes();
        // u64 epoch(8) + 2*u64(16) + vec<addr>(1+32) + u64(8) + secrets(1 + 32+32+1+8+(1+1)) + proposals(1+1) + option(1)
        assert_eq!(b.len(), 8 + 16 + 33 + 8 + 1 + 75 + 2 + 1);
        assert_eq!(State::from_bytes(&b).unwrap(), st);
        assert!(State::from_bytes(&b[..b.len() - 1]).is_err());
        assert!(!st.is_epoch_changing());
        assert_eq!(
            st.secret(&AccountAddress::ONE).unwrap().scheme_name(),
            scheme_name(1)
        );
    }
}
