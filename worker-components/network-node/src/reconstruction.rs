// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::{Field, Zero};
use vss_common::crypto::fr_to_le_bytes;
use vss_common::group::BcsElement;
use vss_common::session::BcsPcsPublicParams;
use vss_common::vss_types::{opening_eval_value_p_fr, opening_eval_value_r_fr};
use vss_common::{normalize_account_addr, AptosRpc};
use vss_store::{read_verified_holder_opening, VssStore};

use crate::onchain::{
    addr_bytes_to_string, addr_string_to_bytes, fetch_dkg_session_bcs, fetch_dkr_session_bcs,
    BcsDkgSession, BcsDkrSession,
};

pub(crate) struct ReconstructedShare {
    pub(crate) scalar_le32: [u8; 32],
    pub(crate) blinding_le32: [u8; 32],
    pub(crate) keypair_id: String,
    pub(crate) group_scheme: u8,
    pub(crate) pcs_context: BcsPcsPublicParams,
    pub(crate) share_commitment: BcsElement,
}

pub(crate) async fn reconstruct_share_from_store(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<ReconstructedShare> {
    let session_addr = normalize_account_addr(session_addr);
    let my_addr = normalize_account_addr(my_addr);

    match fetch_dkr_session_bcs(rpc, ace, &session_addr).await {
        Ok(dkr_session) => reconstruct_from_dkr_store(rpc, ace, &dkr_session, &my_addr, store).await,
        Err(dkr_err) => match fetch_dkg_session_bcs(rpc, ace, &session_addr).await {
            Ok(dkg_session) => {
                reconstruct_from_dkg_store(rpc, ace, &session_addr, &dkg_session, &my_addr, store)
                    .await
            }
            Err(dkg_err) => Err(anyhow!(
                "not DKR and not DKG at {}: DKR get_session_bcs failed: {}; DKG get_session_bcs failed: {}",
                session_addr,
                dkr_err,
                dkg_err
            )),
        },
    }
}

async fn reconstruct_from_dkg_store(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    dkg_session: &BcsDkgSession,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<ReconstructedShare> {
    let my_addr_bytes = addr_string_to_bytes(my_addr)?;
    let workers = &dkg_session.workers;
    let my_idx = workers
        .iter()
        .position(|n| n == &my_addr_bytes)
        .ok_or_else(|| anyhow!("my_addr {} not found in DKG workers", my_addr))?;

    let vss_sessions = dkg_session
        .vss_sessions
        .iter()
        .map(addr_bytes_to_string)
        .collect::<Vec<_>>();
    let done_flags = &dkg_session.done_flags;
    if vss_sessions.len() != done_flags.len() {
        return Err(anyhow!(
            "DKG vss_sessions.len()={} != done_flags.len()={}",
            vss_sessions.len(),
            done_flags.len()
        ));
    }

    let mut secret = Fr::zero();
    let mut blinding = Fr::zero();
    let mut group_scheme: Option<u8> = None;
    let mut num_contributions = 0usize;
    for (idx, vss_addr) in vss_sessions.iter().enumerate() {
        if !done_flags[idx] {
            continue;
        }
        let opening =
            read_verified_holder_opening(rpc, ace, store, vss_addr, my_idx as u64).await?;
        let expected_position = my_idx as u64 + 1;
        if opening.eval_position != expected_position {
            return Err(anyhow!(
                "holder opening position {} != expected {} for DKG {}",
                opening.eval_position,
                expected_position,
                session_addr
            ));
        }
        let scheme = opening.eval_value_p.scheme();
        if group_scheme
            .replace(scheme)
            .is_some_and(|existing| existing != scheme)
        {
            return Err(anyhow!("mixed VSS scalar schemes in DKG {}", session_addr));
        }
        secret += opening_eval_value_p_fr(&opening)?;
        blinding += opening_eval_value_r_fr(&opening)?;
        num_contributions += 1;
    }
    if num_contributions == 0 {
        return Err(anyhow!("no done VSS sessions in DKG {}", session_addr));
    }
    let scheme =
        group_scheme.ok_or_else(|| anyhow!("missing group scheme in DKG {}", session_addr))?;
    let share_commitment = dkg_session
        .commitment_points
        .get(my_idx + 1)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "DKG commitment_points missing share commitment at index {} for {}",
                my_idx + 1,
                session_addr
            )
        })?;
    if share_commitment.scheme() != scheme {
        return Err(anyhow!(
            "DKG share commitment scheme {} != reconstructed share scheme {} for {}",
            share_commitment.scheme(),
            scheme,
            session_addr
        ));
    }
    Ok(ReconstructedShare {
        scalar_le32: fr_to_le_bytes(secret),
        blinding_le32: fr_to_le_bytes(blinding),
        keypair_id: session_addr.to_string(),
        group_scheme: scheme,
        pcs_context: dkg_session.pcs_context.clone(),
        share_commitment,
    })
}

async fn reconstruct_from_dkr_store(
    rpc: &AptosRpc,
    ace: &str,
    dkr_session: &BcsDkrSession,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<ReconstructedShare> {
    let original_session = addr_bytes_to_string(&dkr_session.original_session);
    let my_addr_bytes = addr_string_to_bytes(my_addr)?;
    let new_nodes = &dkr_session.new_nodes;
    let my_idx = new_nodes
        .iter()
        .position(|n| n == &my_addr_bytes)
        .ok_or_else(|| anyhow!("my_addr {} not found in DKR new_nodes", my_addr))?;

    let vss_sessions = dkr_session
        .vss_sessions
        .iter()
        .map(addr_bytes_to_string)
        .collect::<Vec<_>>();
    let vss_contribution_flags = &dkr_session.vss_contribution_flags;
    if vss_sessions.len() != vss_contribution_flags.len() {
        return Err(anyhow!(
            "DKR vss_sessions.len()={} != vss_contribution_flags.len()={}",
            vss_sessions.len(),
            vss_contribution_flags.len()
        ));
    }

    let mut secret_points = Vec::new();
    let mut blinding_points = Vec::new();
    let mut group_scheme: Option<u8> = None;
    for (idx, vss_addr) in vss_sessions.iter().enumerate() {
        if !vss_contribution_flags[idx] {
            continue;
        }
        let opening =
            read_verified_holder_opening(rpc, ace, store, vss_addr, my_idx as u64).await?;
        let expected_position = my_idx as u64 + 1;
        if opening.eval_position != expected_position {
            return Err(anyhow!(
                "holder opening position {} != expected {} for DKR VSS {}",
                opening.eval_position,
                expected_position,
                vss_addr
            ));
        }
        let scheme = opening.eval_value_p.scheme();
        if group_scheme
            .replace(scheme)
            .is_some_and(|existing| existing != scheme)
        {
            return Err(anyhow!(
                "mixed VSS scalar schemes in DKR original_session={}",
                original_session
            ));
        }
        let old_eval_position = idx as u64 + 1;
        secret_points.push((old_eval_position, opening_eval_value_p_fr(&opening)?));
        blinding_points.push((old_eval_position, opening_eval_value_r_fr(&opening)?));
    }
    if secret_points.is_empty() {
        return Err(anyhow!(
            "no contributing VSS sessions in DKR {}",
            original_session
        ));
    }
    let scheme =
        group_scheme.ok_or_else(|| anyhow!("missing group scheme in DKR {}", original_session))?;
    let share_commitment = dkr_session
        .commitment_points
        .get(my_idx + 1)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "DKR commitment_points missing share commitment at index {} for original_session={}",
                my_idx + 1,
                original_session
            )
        })?;
    if share_commitment.scheme() != scheme {
        return Err(anyhow!(
            "DKR share commitment scheme {} != reconstructed share scheme {} for original_session={}",
            share_commitment.scheme(),
            scheme,
            original_session
        ));
    }
    Ok(ReconstructedShare {
        scalar_le32: fr_to_le_bytes(lagrange_at_zero(&secret_points)?),
        blinding_le32: fr_to_le_bytes(lagrange_at_zero(&blinding_points)?),
        keypair_id: original_session,
        group_scheme: scheme,
        pcs_context: dkr_session.pcs_context.clone(),
        share_commitment,
    })
}

fn lagrange_at_zero(points: &[(u64, Fr)]) -> Result<Fr> {
    if points.is_empty() {
        return Err(anyhow!("lagrange_at_zero: no points"));
    }
    let mut acc = Fr::zero();
    for (i, (x_i_raw, y_i)) in points.iter().enumerate() {
        let x_i = Fr::from(*x_i_raw);
        let mut numerator = Fr::from(1u64);
        let mut denominator = Fr::from(1u64);
        for (j, (x_j_raw, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j = Fr::from(*x_j_raw);
            numerator *= -x_j;
            denominator *= x_i - x_j;
        }
        let denominator_inv = denominator
            .inverse()
            .ok_or_else(|| anyhow!("duplicate interpolation point {}", x_i_raw))?;
        acc += *y_i * numerator * denominator_inv;
    }
    Ok(acc)
}
