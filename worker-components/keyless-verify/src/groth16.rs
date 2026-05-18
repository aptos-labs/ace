// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Groth16 verifying key wire-type + ark-groth16 verification helper.

use crate::{errors::VerifyError, types::Groth16Proof};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};

/// BCS-compat with `0x1::keyless_account::Groth16VerificationKey` on chain:
/// each field is the raw compressed-point bytes (no length prefix) for the
/// matching group element.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Groth16VerificationKey {
    #[serde(with = "serde_bytes")]
    pub alpha_g1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub beta_g2: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub gamma_g2: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub delta_g2: Vec<u8>,
    pub gamma_abc_g1: Vec<Vec<u8>>,
}

impl Groth16VerificationKey {
    pub fn to_ark_prepared(&self) -> Result<PreparedVerifyingKey<Bn254>, VerifyError> {
        let alpha_g1 = deserialize_g1(&self.alpha_g1, "alpha_g1")?;
        let beta_g2 = deserialize_g2(&self.beta_g2, "beta_g2")?;
        let gamma_g2 = deserialize_g2(&self.gamma_g2, "gamma_g2")?;
        let delta_g2 = deserialize_g2(&self.delta_g2, "delta_g2")?;
        let gamma_abc_g1: Result<Vec<G1Affine>, _> = self
            .gamma_abc_g1
            .iter()
            .enumerate()
            .map(|(i, bytes)| deserialize_g1(bytes, &format!("gamma_abc_g1[{}]", i)))
            .collect();
        let vk = VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1: gamma_abc_g1?,
        };
        Ok(prepare_verifying_key(&vk))
    }
}

fn deserialize_g1(bytes: &[u8], label: &str) -> Result<G1Affine, VerifyError> {
    let p = G1Affine::deserialize_compressed(bytes).map_err(|e| {
        VerifyError::Groth16(format!("VK {}: G1 decompress: {}", label, e))
    })?;
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VerifyError::Groth16(format!(
            "VK {}: G1 point not in correct subgroup",
            label
        )));
    }
    Ok(p)
}

fn deserialize_g2(bytes: &[u8], label: &str) -> Result<G2Affine, VerifyError> {
    let p = G2Affine::deserialize_compressed(bytes).map_err(|e| {
        VerifyError::Groth16(format!("VK {}: G2 decompress: {}", label, e))
    })?;
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VerifyError::Groth16(format!(
            "VK {}: G2 point not in correct subgroup",
            label
        )));
    }
    Ok(p)
}

/// Verify a Groth16 proof under `pvk` against the single public input
/// `public_inputs_hash` (interpreted as an Fr via little-endian byte order,
/// matching `fr_to_bytes_le` in aptos-crypto).
pub fn verify_proof(
    proof: &Groth16Proof,
    public_inputs_hash: &[u8; 32],
    pvk: &PreparedVerifyingKey<Bn254>,
) -> Result<(), VerifyError> {
    let a = G1Affine::deserialize_compressed(&proof.a.0[..])
        .map_err(|e| VerifyError::Groth16(format!("proof.a decompress: {}", e)))?;
    let b = G2Affine::deserialize_compressed(&proof.b.0[..])
        .map_err(|e| VerifyError::Groth16(format!("proof.b decompress: {}", e)))?;
    let c = G1Affine::deserialize_compressed(&proof.c.0[..])
        .map_err(|e| VerifyError::Groth16(format!("proof.c decompress: {}", e)))?;
    let ark_proof = Proof { a, b, c };
    let pih = Fr::from_le_bytes_mod_order(public_inputs_hash);
    let ok = Groth16::<Bn254>::verify_proof(pvk, &ark_proof, &[pih])
        .map_err(|e| VerifyError::Groth16(format!("verify_proof: {}", e)))?;
    if !ok {
        return Err(VerifyError::Groth16("pairing check failed".into()));
    }
    Ok(())
}
