// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Reconstruct a committee member's Shamir share from a completed DKG or DKR session.
//!
//! Both session types appear in `network::State.secrets`.

use anyhow::{anyhow, Result};
use crate::{normalize_account_addr, AptosRpc};

/// Reconstruct this node's Shamir scalar share from a completed DKG or DKR session.
///
/// Returns `(scalar_le32, keypair_id, group_scheme)` where:
/// - `scalar_le32`: 32-byte LE Fr scalar = this node's Shamir share of the secret
/// - `keypair_id`: original DKG session address (= `keypairId` used by SDK clients)
/// - `group_scheme`: byte from the underlying VSS session's `base_point` — 0 = BLS12-381 G1,
///   1 = BLS12-381 G2. Determines which application protocols can consume this share.
///
/// New VSS no longer publishes encrypted share messages on-chain. This legacy
/// helper does not have a VSS store handle, so active clients use the
/// store-aware reconstruction paths in `network-node` and `dkr-src` instead.
pub async fn reconstruct_share(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    my_addr: &str,
    _pke_dk_bytes: &[u8],
) -> Result<([u8; 32], String, u8)> {
    let session_addr = normalize_account_addr(session_addr);
    let my_addr = normalize_account_addr(my_addr);

    // Try DKR first; fall back to DKG.
    match rpc
        .get_resource_data(&session_addr, &format!("{}::dkr::Session", ace))
        .await
    {
        Ok(dkr_data) => reconstruct_from_dkr(&dkr_data, &my_addr).await,
        Err(_) => {
            let dkg_data = rpc
                .get_resource_data(&session_addr, &format!("{}::dkg::Session", ace))
                .await
                .map_err(|e| anyhow!("not DKR and not DKG at {}: {}", session_addr, e))?;
            reconstruct_from_dkg(rpc, ace, &session_addr, &dkg_data, &my_addr).await
        }
    }
}

/// DKG case: `keypair_id = session_addr`, share = simple sum of sub-shares from done VSS sessions.
async fn reconstruct_from_dkg(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    dkg_data: &serde_json::Value,
    my_addr: &str,
) -> Result<([u8; 32], String, u8)> {
    let my_addr_bytes = addr_to_bytes(my_addr)?;

    let vss_sessions: Vec<String> = parse_addr_array(&dkg_data["vss_sessions"])?;
    let done_flags: Vec<bool> = parse_bool_array(&dkg_data["done_flags"])?;

    if vss_sessions.len() != done_flags.len() {
        return Err(anyhow!(
            "DKG vss_sessions.len()={} != done_flags.len()={}",
            vss_sessions.len(),
            done_flags.len()
        ));
    }

    let mut my_idx: Option<usize> = None;

    for (k, vss_addr) in vss_sessions.iter().enumerate() {
        if !done_flags[k] {
            continue;
        }

        let bcs_session = rpc
            .get_session_bcs_decoded(ace, vss_addr)
            .await
            .map_err(|e| anyhow!("decode DKG VSS {}: {}", vss_addr, e))?;

        // Derive my_idx on the first done session.
        if my_idx.is_none() {
            my_idx = bcs_session
                .share_holders
                .iter()
                .position(|h| h == &my_addr_bytes);
            if my_idx.is_none() {
                return Err(anyhow!(
                    "my_addr {} not found in share_holders of VSS {}",
                    my_addr,
                    vss_addr
                ));
            }
        }
        let idx = my_idx.unwrap();

        return Err(anyhow!(
            "DKG share reconstruction now requires offchain VSS holder shares from local store; session={} holder_index={}",
            vss_addr,
            idx,
        ));
    }

    Err(anyhow!("no done VSS sessions in DKG {}", session_addr))
}

/// DKR case: `keypair_id = original_session`, share = Lagrange combination at x=0 using old eval points.
///
/// See `tests/e2e/test-dkr-protocol.ts:152-219` for the TypeScript reference implementation.
async fn reconstruct_from_dkr(
    dkr_data: &serde_json::Value,
    my_addr: &str,
) -> Result<([u8; 32], String, u8)> {
    let original_session = normalize_account_addr(
        dkr_data["original_session"]
            .as_str()
            .ok_or_else(|| anyhow!("missing original_session in DKR session"))?,
    );

    let new_nodes: Vec<String> = parse_addr_array(&dkr_data["new_nodes"])?;
    let my_idx = new_nodes.iter().position(|n| n == my_addr).ok_or_else(|| {
        anyhow!(
            "my_addr {} not found in DKR new_nodes {:?}",
            my_addr,
            new_nodes
        )
    })?;

    let vss_sessions: Vec<String> = parse_addr_array(&dkr_data["vss_sessions"])?;
    let vss_contribution_flags: Vec<bool> = parse_bool_array(&dkr_data["vss_contribution_flags"])?;

    if vss_sessions.len() != vss_contribution_flags.len() {
        return Err(anyhow!(
            "DKR vss_sessions.len()={} != vss_contribution_flags.len()={}",
            vss_sessions.len(),
            vss_contribution_flags.len()
        ));
    }

    // H = contributing old-committee indices where vss_contribution_flags[j] == true
    let contributing: Vec<usize> = vss_contribution_flags
        .iter()
        .enumerate()
        .filter_map(|(j, &flag)| if flag { Some(j) } else { None })
        .collect();

    if contributing.is_empty() {
        return Err(anyhow!("no contributing VSS sessions in DKR session"));
    }

    for &j in &contributing {
        let vss_addr = &vss_sessions[j];
        return Err(anyhow!(
            "DKR share reconstruction now requires offchain VSS holder shares from local store; session={} holder_index={}",
            vss_addr,
            my_idx,
        ));
    }
    Err(anyhow!(
        "DKR share reconstruction now requires offchain VSS holder shares from local store; original_session={}",
        original_session,
    ))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr_to_bytes(addr: &str) -> Result<[u8; 32]> {
    hex::decode(addr.trim_start_matches("0x"))
        .map_err(|e| anyhow!("addr hex decode '{}': {}", addr, e))?
        .try_into()
        .map_err(|_| anyhow!("addr '{}' must be 32 bytes", addr))
}

fn parse_addr_array(v: &serde_json::Value) -> Result<Vec<String>> {
    v.as_array()
        .ok_or_else(|| anyhow!("expected address array, got {:?}", v))?
        .iter()
        .map(|a| {
            a.as_str()
                .map(normalize_account_addr)
                .ok_or_else(|| anyhow!("expected string address"))
        })
        .collect()
}

fn parse_bool_array(v: &serde_json::Value) -> Result<Vec<bool>> {
    v.as_array()
        .ok_or_else(|| anyhow!("expected bool array, got {:?}", v))?
        .iter()
        .map(|b| {
            b.as_bool()
                .ok_or_else(|| anyhow!("expected bool, got {:?}", b))
        })
        .collect()
}
