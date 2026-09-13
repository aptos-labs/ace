// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/network/index.ts`: the on-chain `network::State` view and primitive/usage
//! constants. Layouts are plain BCS, so they are serde-derived (Option = 0/1 tag, Vec = uleb len).

use serde::{Deserialize, Serialize};

use crate::address::AccountAddress;
use crate::error::{AceError, Result};
use crate::group::wire_via_serialize;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

fn read_vec<T>(
    d: &mut Deserializer<'_>,
    mut f: impl FnMut(&mut Deserializer<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let n = d.vec_len()?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(f(d)?);
    }
    Ok(v)
}
fn read_opt<T>(
    d: &mut Deserializer<'_>,
    what: &str,
    f: impl FnOnce(&mut Deserializer<'_>) -> Result<T>,
) -> Result<Option<T>> {
    match d.u8()? {
        0 => Ok(None),
        1 => Ok(Some(f(d)?)),
        t => Err(AceError::wire(format!(
            "{what} option tag must be 0 or 1, got {t}"
        ))),
    }
}
fn write_addrs(s: &mut Serializer, v: &[AccountAddress]) {
    s.uleb128(v.len() as u32);
    for a in v {
        a.serialize(s);
    }
}

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
    pub fn serialize(&self, s: &mut Serializer) {
        self.current_session.serialize(s);
        self.keypair_id.serialize(s);
        s.u8(self.scheme).u64(self.expected_usage).str(&self.note);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            current_session: AccountAddress::deserialize(d)?,
            keypair_id: AccountAddress::deserialize(d)?,
            scheme: d.u8()?,
            expected_usage: d.u64()?,
            note: d.str()?,
        })
    }
}
wire_via_serialize!(SecretInfo);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SecretRequest {
    pub expected_usage: u64,
    pub note: String,
}
impl SecretRequest {
    pub fn serialize(&self, s: &mut Serializer) {
        s.u64(self.expected_usage).str(&self.note);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            expected_usage: d.u64()?,
            note: d.str()?,
        })
    }
}
wire_via_serialize!(SecretRequest);

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
impl ProposalView {
    pub fn serialize(&self, s: &mut Serializer) {
        let p = &self.proposal;
        write_addrs(s, &p.nodes);
        s.u64(p.threshold).u64(p.epoch_duration_micros);
        write_addrs(s, &p.secrets_to_retain);
        s.uleb128(p.new_secrets.len() as u32);
        for r in &p.new_secrets {
            r.serialize(s);
        }
        s.str(&p.description).u64(p.target_epoch);
        self.voting_session.serialize(s);
        s.uleb128(self.votes.len() as u32);
        for v in &self.votes {
            s.bool(*v);
        }
        s.bool(self.voting_passed);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let proposal = ProposedEpochConfig {
            nodes: read_vec(d, AccountAddress::deserialize)?,
            threshold: d.u64()?,
            epoch_duration_micros: d.u64()?,
            secrets_to_retain: read_vec(d, AccountAddress::deserialize)?,
            new_secrets: read_vec(d, SecretRequest::deserialize)?,
            description: d.str()?,
            target_epoch: d.u64()?,
        };
        Ok(Self {
            proposal,
            voting_session: AccountAddress::deserialize(d)?,
            votes: read_vec(d, |d| d.bool())?,
            voting_passed: d.bool()?,
        })
    }
}
wire_via_serialize!(ProposalView);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EpochChangeView {
    pub triggering_proposal_idx: Option<u64>,
    pub session_addr: AccountAddress,
    pub nxt_nodes: Vec<AccountAddress>,
    pub nxt_threshold: u64,
}
impl EpochChangeView {
    pub fn serialize(&self, s: &mut Serializer) {
        match self.triggering_proposal_idx {
            None => {
                s.u8(0);
            }
            Some(i) => {
                s.u8(1).u64(i);
            }
        }
        self.session_addr.serialize(s);
        write_addrs(s, &self.nxt_nodes);
        s.u64(self.nxt_threshold);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            triggering_proposal_idx: read_opt(d, "triggeringProposalIdx", |d| d.u64())?,
            session_addr: AccountAddress::deserialize(d)?,
            nxt_nodes: read_vec(d, AccountAddress::deserialize)?,
            nxt_threshold: d.u64()?,
        })
    }
}
wire_via_serialize!(EpochChangeView);

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
impl State {
    pub fn serialize(&self, s: &mut Serializer) {
        s.u64(self.epoch)
            .u64(self.epoch_start_time_micros)
            .u64(self.epoch_duration_micros);
        write_addrs(s, &self.cur_nodes);
        s.u64(self.cur_threshold);
        s.uleb128(self.secrets.len() as u32);
        for x in &self.secrets {
            x.serialize(s);
        }
        s.uleb128(self.proposals.len() as u32);
        for p in &self.proposals {
            match p {
                None => {
                    s.u8(0);
                }
                Some(p) => {
                    s.u8(1);
                    p.serialize(s);
                }
            }
        }
        match &self.epoch_change_info {
            None => {
                s.u8(0);
            }
            Some(e) => {
                s.u8(1);
                e.serialize(s);
            }
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            epoch: d.u64()?,
            epoch_start_time_micros: d.u64()?,
            epoch_duration_micros: d.u64()?,
            cur_nodes: read_vec(d, AccountAddress::deserialize)?,
            cur_threshold: d.u64()?,
            secrets: read_vec(d, SecretInfo::deserialize)?,
            proposals: read_vec(d, |d| {
                read_opt(d, "proposals[i]", ProposalView::deserialize)
            })?,
            epoch_change_info: read_opt(d, "epoch_change_info", EpochChangeView::deserialize)?,
        })
    }
}
wire_via_serialize!(State);

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
        assert_eq!(
            bcs::to_bytes(&st).unwrap(),
            b,
            "serde derive and cursor layout agree"
        );
        assert!(State::from_bytes(&b[..b.len() - 1]).is_err());
        assert!(!st.is_epoch_changing());
        assert_eq!(
            st.secret(&AccountAddress::ONE).unwrap().scheme_name(),
            scheme_name(1)
        );
    }
}
