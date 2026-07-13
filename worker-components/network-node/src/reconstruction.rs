// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use vss_common::group::{scalar_linear_combination, scalar_sum, BcsElement, BcsScalar};
use vss_common::session::BcsPcsPublicParams;
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

    let mut secret_scalars = Vec::<BcsScalar>::new();
    let mut blinding_scalars = Vec::<BcsScalar>::new();
    let mut group_scheme: Option<u8> = None;
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
        if opening.eval_value_r.scheme() != scheme {
            return Err(anyhow!(
                "VSS opening p/r scheme mismatch in DKG {}",
                session_addr
            ));
        }
        if group_scheme
            .replace(scheme)
            .is_some_and(|existing| existing != scheme)
        {
            return Err(anyhow!("mixed VSS scalar schemes in DKG {}", session_addr));
        }
        secret_scalars.push(opening.eval_value_p.clone());
        blinding_scalars.push(opening.eval_value_r.clone());
    }
    if secret_scalars.is_empty() {
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
    let secret = scalar_sum(&secret_scalars)?;
    let blinding = scalar_sum(&blinding_scalars)?;
    Ok(ReconstructedShare {
        scalar_le32: secret.to_le_bytes()?,
        blinding_le32: blinding.to_le_bytes()?,
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

    let num_contributions = vss_contribution_flags.iter().filter(|flag| **flag).count();
    if dkr_session.lagrange_coeffs_at_zero.len() != num_contributions {
        return Err(anyhow!(
            "DKR lagrange_coeffs_at_zero.len()={} != contributing VSS count={} for original_session={}",
            dkr_session.lagrange_coeffs_at_zero.len(),
            num_contributions,
            original_session
        ));
    }

    let mut secret_terms = Vec::<(BcsScalar, BcsScalar)>::new();
    let mut blinding_terms = Vec::<(BcsScalar, BcsScalar)>::new();
    let mut group_scheme: Option<u8> = None;
    let mut coeff_idx = 0usize;
    for (idx, vss_addr) in vss_sessions.iter().enumerate() {
        if !vss_contribution_flags[idx] {
            continue;
        }
        let coeff = dkr_session
            .lagrange_coeffs_at_zero
            .get(coeff_idx)
            .ok_or_else(|| anyhow!("missing DKR Lagrange coefficient {}", coeff_idx))?
            .clone();
        coeff_idx += 1;
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
        if opening.eval_value_r.scheme() != scheme {
            return Err(anyhow!(
                "VSS opening p/r scheme mismatch in DKR original_session={}",
                original_session
            ));
        }
        if group_scheme
            .replace(scheme)
            .is_some_and(|existing| existing != scheme)
        {
            return Err(anyhow!(
                "mixed VSS scalar schemes in DKR original_session={}",
                original_session
            ));
        }
        secret_terms.push((opening.eval_value_p.clone(), coeff.clone()));
        blinding_terms.push((opening.eval_value_r.clone(), coeff));
    }
    if secret_terms.is_empty() {
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
    let secret = scalar_linear_combination(&secret_terms)?;
    let blinding = scalar_linear_combination(&blinding_terms)?;
    Ok(ReconstructedShare {
        scalar_le32: secret.to_le_bytes()?,
        blinding_le32: blinding.to_le_bytes()?,
        keypair_id: original_session,
        group_scheme: scheme,
        pcs_context: dkr_session.pcs_context.clone(),
        share_commitment,
    })
}
