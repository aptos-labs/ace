// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use vss_common::AptosRpc;

use super::BcsStateViewV0;

pub(crate) fn addr_bytes_to_string(addr: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(addr))
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
