// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Parse `ace::vss::Session` from Aptos REST `data` JSON — mirrors `ts-sdk` `Session`.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

// Group-level BCS mirror types and scheme constants now live in `crate::group`.
// Re-exported here for back-compat with existing `vss_common::session::Bcs*` import paths.
pub use crate::group::{
    BcsElement, BcsPrivateScalar, BcsPublicPoint, BcsScalar, SCHEME_BLS12381G1, SCHEME_BLS12381G2,
};

pub const STATE_DEALER_DEAL: u8 = 0;
pub const STATE_RECIPIENT_ACK: u8 = 1;
pub const STATE_VERIFY_DEALER_OPENING: u8 = 2;
pub const STATE_SUCCESS: u8 = 3;
pub const STATE_FAILED: u8 = 4;

pub const ACK_WINDOW_MICROS: u64 = 5_000_000;

#[derive(Debug, Clone)]
pub struct Session {
    pub dealer: String,
    pub share_holders: Vec<String>,
    pub threshold: u64,
    /// `dealer_contribution_0` is empty if DC0 has not been submitted yet.
    /// Non-empty (sentinel `[1]`) once the dealer has called `on_dealer_contribution_0`.
    pub dealer_contribution_0: Vec<u8>,
    pub share_holder_acks: Vec<bool>,
    /// `dealer_contribution_1` is empty if DC1 has not been submitted yet.
    pub dealer_contribution_1: Vec<u8>,
    pub state_code: u8,
    pub deal_time_micros: u64,
}

impl Session {
    /// `data_json` is the inner `data` object from
    /// `GET /accounts/.../resource/...::vss::Session`.
    ///
    /// # Session struct layout (mirrors `ace::vss::Session` Move struct):
    /// - `dealer: address`
    /// - `share_holders: vector<address>`
    /// - `threshold: u64`
    /// - `public_base_element: group::Element` (we don't need the value — just skip it)
    /// - `state_code: u8`
    /// - `deal_time_micros: u64`
    /// - `dealer_contribution_0: Option<DealerContribution0>` (struct, not raw bytes)
    /// - `share_holder_acks: vector<bool>`
    /// - `dealer_contribution_1: Option<DealerContribution1>` (struct, not raw bytes)
    pub fn try_from_node_resource_api(data_json: &Value) -> Result<Self> {
        let u64_field = |field: &str| -> Result<u64> {
            let raw = data_json
                .get(field)
                .ok_or_else(|| anyhow!("missing field {:?}", field))?;
            if let Some(n) = raw.as_u64() {
                return Ok(n);
            } else if let Some(st) = raw.as_str() {
                return st.parse::<u64>().with_context(|| format!("parse u64 field {:?}", field));
            }
            raw.to_string().parse::<u64>().with_context(|| format!("parse u64 field {:?}", field))
        };

        let dealer = data_json
            .get("dealer")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing dealer"))?;
        let dealer = crate::normalize_account_addr(dealer);

        let holders_raw = data_json
            .get("share_holders")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("share_holders must be an array"))?;
        let share_holders: Result<Vec<String>> = holders_raw
            .iter()
            .map(|v| {
                v.as_str()
                    .map(crate::normalize_account_addr)
                    .ok_or_else(|| anyhow!("share_holders entry must be string address"))
            })
            .collect();
        let share_holders = share_holders?;

        let threshold = u64_field("threshold")?;

        // public_base_element: group::Element — present in Session.
        // We only check it exists; we don't need the actual value.
        if data_json.get("public_base_element").is_none() {
            return Err(anyhow!("missing public_base_element in VSS session"));
        }

        let state_code_raw = data_json
            .get("state_code")
            .ok_or_else(|| anyhow!("missing state_code"))?;
        let state_code: u8 = if let Some(n) = state_code_raw.as_u64() {
            n.try_into().map_err(|_| anyhow!("state_code out of range"))?
        } else if let Some(s) = state_code_raw.as_str() {
            s.parse::<u8>().with_context(|| "parse state_code")?
        } else {
            return Err(anyhow!("state_code has unexpected type"));
        };

        let deal_time_micros = u64_field("deal_time_micros")?;

        // dealer_contribution_0: Option<DealerContribution0>
        // In Move JSON, Option<T> is represented as {"vec": []} (None) or {"vec": [value]} (Some).
        // We only care whether it has been submitted (Some vs None).
        let dc0_submitted = option_field_is_set(data_json, "dealer_contribution_0");
        let dealer_contribution_0 = if dc0_submitted { vec![1u8] } else { vec![] };

        let acks_raw = data_json
            .get("share_holder_acks")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("share_holder_acks must be an array"))?;
        let share_holder_acks: Vec<bool> = acks_raw
            .iter()
            .map(|v| v.as_bool().unwrap_or(false))
            .collect();
        if share_holder_acks.len() != share_holders.len() {
            return Err(anyhow!(
                "share_holder_acks length {} != share_holders length {}",
                share_holder_acks.len(),
                share_holders.len()
            ));
        }

        // dealer_contribution_1: Option<DealerContribution1> — same logic as DC0.
        let dc1_submitted = option_field_is_set(data_json, "dealer_contribution_1");
        let dealer_contribution_1 = if dc1_submitted { vec![1u8] } else { vec![] };

        Ok(Session {
            dealer,
            share_holders,
            threshold,
            dealer_contribution_0,
            share_holder_acks,
            dealer_contribution_1,
            state_code,
            deal_time_micros,
        })
    }

    /// From full resource JSON `{ "type": "...", "data": { ... } }` or inner `data` only.
    pub fn try_from_resource_json(resource: &Value) -> Result<Self> {
        if let Some(data) = resource.get("data") {
            Self::try_from_node_resource_api(data)
        } else {
            Self::try_from_node_resource_api(resource)
        }
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        self.state_code == STATE_SUCCESS
    }

    /// Active states where the skeleton client should keep working.
    #[inline]
    pub fn is_in_progress(&self) -> bool {
        matches!(self.state_code, STATE_DEALER_DEAL | STATE_RECIPIENT_ACK | STATE_VERIFY_DEALER_OPENING)
    }
}

// ── BCS mirror types (for decoding get_session_bcs view output) ───────────────
//
// Group-level mirror types (`BcsElement`, `BcsScalar`, `BcsPublicPoint`,
// `BcsPrivateScalar`) live in `crate::group` and are re-exported above.

/// BCS mirror of `vss::PcsCommitment`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BcsPcsCommitment {
    pub points: Vec<BcsElement>,
}

/// BCS mirror of `sigma_dlog_eq::Proof`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BcsSigmaDlogEqProof {
    pub t0: BcsElement,
    pub t1: BcsElement,
    pub s: BcsScalar,
}

/// BCS mirror of `vss::ResharingDealerResponse`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BcsResharingDealerResponse {
    pub another_scaled_element: BcsElement,
    pub proof: BcsSigmaDlogEqProof,
}

/// BCS mirror of `vss::ResharingDealerChallenge`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BcsResharingDealerChallenge {
    pub expected_scaled_element: BcsElement,
    pub another_base_element: BcsElement,
}

/// BCS mirror of `vss::DealerContribution0`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BcsDealerContribution0 {
    pub pcs_commitment: BcsPcsCommitment,
    pub private_share_messages: Vec<crate::pke::BcsCiphertext>,
    pub dealer_state: Option<crate::pke::BcsCiphertext>,
    pub resharing_response: Option<BcsResharingDealerResponse>,
}

/// BCS mirror of `vss::DealerContribution1`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BcsDealerContribution1 {
    pub shares_to_reveal: Vec<Option<BcsScalar>>,
}

/// BCS mirror of `vss::Session` — used with `bcs::from_bytes` on `get_session_bcs` output.
#[derive(serde::Deserialize)]
pub struct BcsSession {
    pub dealer: [u8; 32],
    pub share_holders: Vec<[u8; 32]>,
    pub threshold: u64,
    pub base_point: BcsElement,
    pub resharing_challenge: Option<BcsResharingDealerChallenge>,
    pub state_code: u8,
    pub deal_time_micros: u64,
    pub dealer_contribution_0: Option<BcsDealerContribution0>,
    pub share_holder_acks: Vec<bool>,
    pub dealer_contribution_1: Option<BcsDealerContribution1>,
    pub share_pks: Vec<BcsElement>,
}

/// Check whether a Move `Option<T>` field (encoded as `{"vec": []}` or `{"vec": [value]}`)
/// represents `Some`. Returns `true` if the field has a non-empty `vec` array.
fn option_field_is_set(data_json: &Value, field: &str) -> bool {
    match data_json.get(field) {
        None | Some(Value::Null) => false,
        Some(v) => {
            // Option<T> in Aptos JSON: {"vec": []} or {"vec": [value]}
            if let Some(vec_arr) = v.get("vec").and_then(|a| a.as_array()) {
                !vec_arr.is_empty()
            } else {
                // Fallback: if the field is non-null and not the empty-vec pattern, treat as Some.
                !v.is_null()
            }
        }
    }
}
