// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Reconstruct a committee member's Shamir share from a completed DKG or DKR session.
//!
//! Both session types appear in `network::State.secrets`.

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::Field;

use crate::{
    crypto::{fr_from_le_bytes, fr_to_le_bytes},
    normalize_account_addr,
    pke::{pke_decrypt, Ciphertext},
    AptosRpc,
};

/// Reconstruct this node's Shamir scalar share from a completed DKG or DKR session.
///
/// Returns `(scalar_le32, keypair_id, group_scheme)` where:
/// - `scalar_le32`: 32-byte LE Fr scalar = this node's Shamir share of the secret
/// - `keypair_id`: original DKG session address (= `keypairId` used by SDK clients)
/// - `group_scheme`: byte from the underlying VSS session's `base_point` — 0 = BLS12-381 G1,
///   1 = BLS12-381 G2. Determines which t-IBE variant the worker should serve from this share.
///
/// **DKG session**: `scalar = Σ_{k: done_flags[k]} decrypt(vss[k].share_messages[my_idx])`
/// **DKR session**: `scalar = Σ_{j ∈ H} L_{j+1}^H(0) · decrypt(vss[j].share_messages[my_idx])`
pub async fn reconstruct_share(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    my_addr: &str,
    pke_dk_bytes: &[u8],
) -> Result<([u8; 32], String, u8)> {
    let session_addr = normalize_account_addr(session_addr);
    let my_addr = normalize_account_addr(my_addr);

    // Try DKR first; fall back to DKG.
    match rpc.get_resource_data(&session_addr, &format!("{}::dkr::Session", ace)).await {
        Ok(dkr_data) => {
            reconstruct_from_dkr(rpc, ace, &dkr_data, &my_addr, pke_dk_bytes).await
        }
        Err(_) => {
            let dkg_data = rpc
                .get_resource_data(&session_addr, &format!("{}::dkg::Session", ace))
                .await
                .map_err(|e| anyhow!("not DKR and not DKG at {}: {}", session_addr, e))?;
            reconstruct_from_dkg(rpc, ace, &session_addr, &dkg_data, &my_addr, pke_dk_bytes).await
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
    pke_dk_bytes: &[u8],
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
    let mut group_scheme: Option<u8> = None;
    let mut share_fr = Fr::from(0u64);

    for (k, vss_addr) in vss_sessions.iter().enumerate() {
        if !done_flags[k] {
            continue;
        }

        let bcs_session = rpc
            .get_session_bcs_decoded(ace, vss_addr)
            .await
            .map_err(|e| anyhow!("decode DKG VSS {}: {}", vss_addr, e))?;

        // Derive my_idx + group_scheme on the first done session.
        if my_idx.is_none() {
            my_idx = bcs_session.share_holders.iter().position(|h| h == &my_addr_bytes);
            if my_idx.is_none() {
                return Err(anyhow!(
                    "my_addr {} not found in share_holders of VSS {}",
                    my_addr,
                    vss_addr
                ));
            }
            group_scheme = Some(bcs_session.base_point.scheme());
        }
        let idx = my_idx.unwrap();

        let dc0 = bcs_session
            .dealer_contribution_0
            .ok_or_else(|| anyhow!("DKG VSS {} (done=true) has no DC0", vss_addr))?;

        let ct = dc0
            .private_share_messages
            .get(idx)
            .ok_or_else(|| anyhow!("DKG VSS {} missing message[{}]", vss_addr, idx))?;

        share_fr += decrypt_and_extract_fr(ct, pke_dk_bytes, vss_addr)?;
    }

    let group_scheme = group_scheme
        .ok_or_else(|| anyhow!("no done VSS sessions in DKG {}", session_addr))?;

    Ok((fr_to_le_bytes(share_fr), session_addr.to_string(), group_scheme))
}

/// DKR case: `keypair_id = original_session`, share = Lagrange combination at x=0 using old eval points.
///
/// See `tests/e2e/test-dkr-protocol.ts:152-219` for the TypeScript reference implementation.
async fn reconstruct_from_dkr(
    rpc: &AptosRpc,
    ace: &str,
    dkr_data: &serde_json::Value,
    my_addr: &str,
    pke_dk_bytes: &[u8],
) -> Result<([u8; 32], String, u8)> {
    let original_session = normalize_account_addr(
        dkr_data["original_session"]
            .as_str()
            .ok_or_else(|| anyhow!("missing original_session in DKR session"))?,
    );

    let new_nodes: Vec<String> = parse_addr_array(&dkr_data["new_nodes"])?;
    let my_idx = new_nodes
        .iter()
        .position(|n| n == my_addr)
        .ok_or_else(|| anyhow!("my_addr {} not found in DKR new_nodes {:?}", my_addr, new_nodes))?;

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

    // Old eval points: x_j = j+1 (1-based) for each j ∈ H.
    let old_evals: Vec<Fr> = contributing.iter().map(|&j| Fr::from((j + 1) as u64)).collect();

    // Decrypt sub-share z_{j, my_idx} for each j ∈ H.
    let mut sub_shares: Vec<Fr> = Vec::with_capacity(contributing.len());
    let mut group_scheme: Option<u8> = None;
    for &j in &contributing {
        let vss_addr = &vss_sessions[j];
        let bcs_session = rpc
            .get_session_bcs_decoded(ace, vss_addr)
            .await
            .map_err(|e| anyhow!("decode DKR VSS {}: {}", vss_addr, e))?;

        if group_scheme.is_none() {
            group_scheme = Some(bcs_session.base_point.scheme());
        }

        let dc0 = bcs_session
            .dealer_contribution_0
            .ok_or_else(|| anyhow!("DKR VSS {} (contribution=true) has no DC0", vss_addr))?;

        let ct = dc0
            .private_share_messages
            .get(my_idx)
            .ok_or_else(|| anyhow!("DKR VSS {} missing message[{}]", vss_addr, my_idx))?;

        sub_shares.push(decrypt_and_extract_fr(ct, pke_dk_bytes, vss_addr)?);
    }
    let group_scheme = group_scheme
        .ok_or_else(|| anyhow!("no contributing VSS sessions yielded a group scheme"))?;

    // Lagrange-combine at x=0 using old eval points {j+1 : j ∈ H}.
    //   combined_share = Σ_{i} L_{x_i}^H(0) · z_{j_i, my_idx}
    // where L_{x_i}^H(0) = Π_{k≠i} (0 - x_k) / (x_i - x_k)
    let combined_share = sub_shares
        .iter()
        .enumerate()
        .map(|(i, &z_j_m)| {
            let xi = old_evals[i];
            let mut lambda = Fr::from(1u64);
            for (k, &xk) in old_evals.iter().enumerate() {
                if k == i {
                    continue;
                }
                lambda *= (-xk) * (xi - xk).inverse().expect("eval points are distinct");
            }
            lambda * z_j_m
        })
        .fold(Fr::from(0u64), |acc, term| acc + term);

    Ok((fr_to_le_bytes(combined_share), original_session, group_scheme))
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
        .map(|b| b.as_bool().ok_or_else(|| anyhow!("expected bool, got {:?}", b)))
        .collect()
}

fn decrypt_and_extract_fr(
    ct: &Ciphertext,
    pke_dk_bytes: &[u8],
    context: &str,
) -> Result<Fr> {
    let plaintext = pke_decrypt(pke_dk_bytes, ct)
        .map_err(|e| anyhow!("VSS {} decrypt failed: {}", context, e))?;

    // Format: [group scheme][ULEB128(32)=0x20][32B Fr LE]. Scheme may be 0x00 (G1) or 0x01 (G2);
    // Fr is the same prime field for both, so the y-bytes are interchangeable.
    if plaintext.len() < 34
        || (plaintext[0] != crate::session::SCHEME_BLS12381G1
            && plaintext[0] != crate::session::SCHEME_BLS12381G2)
        || plaintext[1] != 0x20
    {
        return Err(anyhow!(
            "VSS {} invalid share format (len={}, prefix={:02x?})",
            context,
            plaintext.len(),
            &plaintext[..2.min(plaintext.len())]
        ));
    }
    let y_bytes: [u8; 32] = plaintext[2..34]
        .try_into()
        .map_err(|_| anyhow!("share bytes wrong length"))?;
    Ok(fr_from_le_bytes(y_bytes))
}
