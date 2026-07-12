// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Off-chain prover for `ace::sigma_dlog_linear`.

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use rand::RngCore;
use sha2::{Digest, Sha512};

use crate::crypto::{fr_to_le_bytes, group_msm_compressed};
use crate::group::{BcsElement, BcsScalar};
use crate::session::BcsSigmaDlogLinearProof;

pub fn prove_vss(
    scheme: u8,
    chain_id: u8,
    ace_addr: &[u8; 32],
    session_addr: &[u8; 32],
    purpose: &[u8],
    eval_position: u64,
    b_vals: &[BcsElement],
    p_vals: &[BcsElement],
    witnesses: &[Fr],
) -> Result<BcsSigmaDlogLinearProof> {
    let num_secrets = witnesses.len();
    let num_constraints = p_vals.len();
    if num_secrets == 0 || num_constraints == 0 {
        return Err(anyhow!("sigma_dlog_linear: empty statement"));
    }
    if b_vals.len() != num_secrets * num_constraints {
        return Err(anyhow!(
            "sigma_dlog_linear: b_vals length {} != {} * {}",
            b_vals.len(),
            num_secrets,
            num_constraints
        ));
    }
    if !b_vals.iter().all(|b| b.scheme() == scheme) || !p_vals.iter().all(|p| p.scheme() == scheme)
    {
        return Err(anyhow!("sigma_dlog_linear: statement scheme mismatch"));
    }

    let mut transcript = vss_transcript(chain_id, ace_addr, session_addr, purpose, eval_position)?;
    append_statement(
        &mut transcript,
        b_vals,
        p_vals,
        num_secrets as u64,
        num_constraints as u64,
    )?;

    let r_vals: Vec<Fr> = (0..num_secrets).map(|_| random_fr()).collect();
    let mut t_vals = Vec::with_capacity(num_constraints);
    for row in 0..num_constraints {
        let row_bases = &b_vals[row * num_secrets..(row + 1) * num_secrets];
        let row_bytes = row_bases
            .iter()
            .map(|b| b.point_bytes().to_vec())
            .collect::<Vec<_>>();
        let t = group_msm_compressed(scheme, &row_bytes, &r_vals)?;
        let t = BcsElement::from_scheme_and_bytes(scheme, t)?;
        transcript.extend(bcs::to_bytes(&t).map_err(|e| anyhow!("bcs t_val: {}", e))?);
        t_vals.push(t);
    }

    let c = hash_to_fr(&transcript);
    let z_vals = witnesses
        .iter()
        .zip(r_vals.iter())
        .map(|(w, r)| {
            BcsScalar::from_scheme_and_bytes(scheme, fr_to_le_bytes(*r + c * *w).to_vec())
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(BcsSigmaDlogLinearProof { t_vals, z_vals })
}

fn random_fr() -> Fr {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Fr::from_le_bytes_mod_order(&bytes)
}

fn vss_transcript(
    chain_id: u8,
    ace_addr: &[u8; 32],
    session_addr: &[u8; 32],
    purpose: &[u8],
    eval_position: u64,
) -> Result<Vec<u8>> {
    let mut transcript = Vec::new();
    transcript.extend(bcs::to_bytes(&chain_id).map_err(|e| anyhow!("bcs chain_id: {}", e))?);
    transcript.extend(bcs::to_bytes(ace_addr).map_err(|e| anyhow!("bcs ace addr: {}", e))?);
    transcript.extend(b"vss");
    transcript.extend(purpose);
    transcript.extend(bcs::to_bytes(session_addr).map_err(|e| anyhow!("bcs session addr: {}", e))?);
    transcript
        .extend(bcs::to_bytes(&eval_position).map_err(|e| anyhow!("bcs eval_position: {}", e))?);
    Ok(transcript)
}

fn append_statement(
    transcript: &mut Vec<u8>,
    b_vals: &[BcsElement],
    p_vals: &[BcsElement],
    num_secrets: u64,
    num_constraints: u64,
) -> Result<()> {
    transcript.extend(bcs::to_bytes(&num_secrets).map_err(|e| anyhow!("bcs num_secrets: {}", e))?);
    transcript.extend(
        bcs::to_bytes(&num_constraints).map_err(|e| anyhow!("bcs num_constraints: {}", e))?,
    );
    for b in b_vals {
        transcript.extend(bcs::to_bytes(b).map_err(|e| anyhow!("bcs b_val: {}", e))?);
    }
    for p in p_vals {
        transcript.extend(bcs::to_bytes(p).map_err(|e| anyhow!("bcs p_val: {}", e))?);
    }
    Ok(())
}

fn hash_to_fr(transcript: &[u8]) -> Fr {
    let hash = Sha512::digest(transcript);
    Fr::from_be_bytes_mod_order(hash.as_slice())
}
