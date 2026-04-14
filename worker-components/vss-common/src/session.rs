// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Parse `ace::vss::Session` from Aptos REST `data` JSON — mirrors `ts-sdk` `Session.fromNodeResourceApi`.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

pub const SCHEME_BLS12381G1: u8 = 0;
pub const SCHEME_BLS12381G2: u8 = 1;

pub const STATE_DEALER_DEAL: u8 = 0;
pub const STATE_RECIPIENT_ACK: u8 = 1;
pub const STATE_SUCCESS: u8 = 2;
pub const STATE_FAILED: u8 = 3;

pub const ACK_WINDOW_MICROS: u64 = 5_000_000;

#[derive(Debug, Clone)]
pub struct Session {
    pub dealer: String,
    pub share_holders: Vec<String>,
    pub threshold: u64,
    pub secret_scheme: u8,
    pub state_code: u8,
    pub deal_time_micros: u64,
    pub dealer_contribution_0: Vec<u8>,
    pub share_holder_acks: Vec<bool>,
    pub dealer_contribution_1: Vec<u8>,
}

impl Session {
    /// `data_json` is the inner `data` object from
    /// `GET /accounts/.../resource/...::vss::Session` (same shape as TS `fromNodeResourceApi`).
    pub fn try_from_node_resource_api(data_json: &Value) -> Result<Self> {
        let parse_hex_bytes = |field: &str| -> Result<Vec<u8>> {
            let raw = data_json
                .get(field)
                .ok_or_else(|| anyhow!("missing field {:?}", field))?;
            let s = raw
                .as_str()
                .ok_or_else(|| anyhow!("field {:?} must be a hex string", field))?;
            let mut hex = s.trim().to_string();
            if hex.starts_with("0x") || hex.starts_with("0X") {
                hex = hex[2..].to_string();
            }
            if hex.is_empty() {
                return Ok(Vec::new());
            }
            if hex.len() % 2 == 1 {
                hex = format!("0{}", hex);
            }
            hex::decode(&hex).with_context(|| format!("decode hex field {:?}", field))
        };

        let u64_field = |field: &str| -> Result<u64> {
            let raw = data_json
                .get(field)
                .ok_or_else(|| anyhow!("missing field {:?}", field))?;
            let s = if let Some(n) = raw.as_u64() {
                return Ok(n);
            } else if let Some(st) = raw.as_str() {
                st.to_string()
            } else {
                raw.to_string()
            };
            s.parse::<u64>()
                .with_context(|| format!("parse u64 field {:?}", field))
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

        let secret_scheme = data_json
            .get("secret_scheme")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("secret_scheme"))? as u8;
        if secret_scheme != SCHEME_BLS12381G1 && secret_scheme != SCHEME_BLS12381G2 {
            return Err(anyhow!("unsupported secret_scheme {}", secret_scheme));
        }

        let state_code_u64 = data_json
            .get("state_code")
            .and_then(|v| v.as_u64())
            .or_else(|| data_json.get("state_code").and_then(|v| v.as_str()?.parse().ok()))
            .ok_or_else(|| anyhow!("state_code"))?;
        let state_code: u8 = state_code_u64
            .try_into()
            .map_err(|_| anyhow!("state_code out of range"))?;

        let deal_time_micros = u64_field("deal_time_micros")?;

        let acks_raw = data_json
            .get("share_holder_acks")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("share_holder_acks must be an array"))?;
        let share_holder_acks: Vec<bool> = acks_raw.iter().map(|v| v.as_bool().unwrap_or(false)).collect();
        if share_holder_acks.len() != share_holders.len() {
            return Err(anyhow!(
                "share_holder_acks length {} != share_holders length {}",
                share_holder_acks.len(),
                share_holders.len()
            ));
        }

        Ok(Session {
            dealer,
            share_holders,
            threshold,
            secret_scheme,
            state_code,
            deal_time_micros,
            dealer_contribution_0: parse_hex_bytes("dealer_contribution_0")?,
            share_holder_acks,
            dealer_contribution_1: parse_hex_bytes("dealer_contribution_1")?,
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
        matches!(
            self.state_code,
            STATE_DEALER_DEAL | STATE_RECIPIENT_ACK
        )
    }
}
