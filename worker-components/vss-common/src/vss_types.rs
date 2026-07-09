// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! VSS payload builders and Pedersen PCS share verification.
//!
//! Wire layouts mirror Move's `contracts/vss/sources/vss.move`.

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use serde::Serialize;

use crate::crypto::{fr_from_le_bytes, pedersen_commit_compressed};
use crate::pke::Ciphertext;
use crate::session::{
    BcsDealerContribution0, BcsDealerContribution1, BcsElement, BcsPcsCommitment, BcsPcsOpening,
    BcsPcsPublicParams, BcsScalar, BcsSigmaDlogLinearProof, SCHEME_BLS12381G1, SCHEME_BLS12381G2,
};

// ── DealerState ───────────────────────────────────────────────────────────────

/// Plaintext-only intermediate (gets PKE-encrypted into `dealer_state` before going on chain).
#[derive(Serialize)]
pub enum DealerState {
    Bls12381Fr {
        n: u64,
        coefs_poly_p: Vec<Vec<u8>>, // each entry is a 32-byte Fr scalar (LE)
    },
}

impl DealerState {
    pub fn bls12381_fr(n: u64, coefs_poly_p: Vec<[u8; 32]>) -> Self {
        DealerState::Bls12381Fr {
            n,
            coefs_poly_p: coefs_poly_p.into_iter().map(|c| c.to_vec()).collect(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("bcs serialization failed")
    }
}

// ── PrivateShareMessage plaintext ─────────────────────────────────────────────

/// Plaintext of a per-recipient PKE ciphertext: BCS-encoded PCS opening at
/// recipient position `eval_position`.
pub fn private_share_message_bytes(
    scheme: u8,
    eval_position: u64,
    y: &[u8; 32],
    r: &[u8; 32],
) -> Result<Vec<u8>> {
    let opening = opening_for_scheme(scheme, eval_position, y, r)?;
    Ok(bcs::to_bytes(&opening).expect("bcs serialization failed"))
}

pub fn opening_for_scheme(
    scheme: u8,
    eval_position: u64,
    y: &[u8; 32],
    r: &[u8; 32],
) -> Result<BcsPcsOpening> {
    Ok(BcsPcsOpening {
        eval_position,
        eval_value_p: BcsScalar::from_scheme_and_bytes(scheme, y.to_vec())?,
        eval_value_r: BcsScalar::from_scheme_and_bytes(scheme, r.to_vec())?,
    })
}

pub fn parse_private_share_opening(plaintext: &[u8]) -> Result<BcsPcsOpening> {
    bcs::from_bytes(plaintext).map_err(|e| anyhow!("PrivateShareMessage opening BCS decode: {}", e))
}

pub fn opening_eval_value_p_fr(opening: &BcsPcsOpening) -> Result<Fr> {
    scalar_to_fr(&opening.eval_value_p)
}

/// Verify a decrypted share holder message before ACKing:
/// `V_i == p(i) * G + r(i) * H`.
pub fn pedersen_verify_private_share(
    plaintext: &[u8],
    context: &BcsPcsPublicParams,
    commitment: &BcsPcsCommitment,
    expected_position: u64,
) -> Result<BcsPcsOpening> {
    let opening = parse_private_share_opening(plaintext)?;
    if opening.eval_position != expected_position {
        return Err(anyhow!(
            "opening position {} != expected {}",
            opening.eval_position,
            expected_position
        ));
    }
    let scheme = context.generator_g.scheme();
    if context.generator_h.scheme() != scheme
        || opening.eval_value_p.scheme() != scheme
        || opening.eval_value_r.scheme() != scheme
    {
        return Err(anyhow!("Pedersen opening scheme mismatch"));
    }
    let point = commitment
        .points
        .get(expected_position as usize)
        .ok_or_else(|| anyhow!("commitment missing position {}", expected_position))?;
    if point.scheme() != scheme {
        return Err(anyhow!("commitment point scheme mismatch"));
    }

    let expected = pedersen_commit_compressed(
        scheme,
        scalar_to_fr(&opening.eval_value_p)?,
        scalar_to_fr(&opening.eval_value_r)?,
        context.generator_g.point_bytes(),
        context.generator_h.point_bytes(),
    )?;
    if expected.as_slice() != point.point_bytes() {
        return Err(anyhow!("Pedersen opening verification failed"));
    }
    Ok(opening)
}

// ── DealerContribution0 payload ───────────────────────────────────────────────

pub fn dc0_bytes(
    scheme: u8,
    commitment_points: &[Vec<u8>],
    share_ciphertexts: &[Ciphertext],
    dealer_state_ct: Option<&Ciphertext>,
    consistency_proof: Option<BcsSigmaDlogLinearProof>,
) -> Result<Vec<u8>> {
    let dc0 = BcsDealerContribution0 {
        pcs_commitment: BcsPcsCommitment {
            points: commitment_points
                .iter()
                .map(|v| element_for_scheme(scheme, v))
                .collect::<Result<Vec<_>>>()?,
        },
        private_share_messages: share_ciphertexts.to_vec(),
        dealer_state: dealer_state_ct.cloned(),
        consistency_proof,
    };
    Ok(bcs::to_bytes(&dc0).expect("bcs serialization failed"))
}

// ── DealerContribution1 payload ───────────────────────────────────────────────

pub fn dc1_bytes(
    scheme: u8,
    shares_to_reveal: &[Option<BcsPcsOpening>],
    public_keys: &[Vec<u8>],
    public_key_proofs: &[Option<BcsSigmaDlogLinearProof>],
) -> Result<Vec<u8>> {
    if public_keys.len() != shares_to_reveal.len()
        || public_key_proofs.len() != shares_to_reveal.len()
    {
        return Err(anyhow!(
            "dc1 length mismatch: shares={} public_keys={} proofs={}",
            shares_to_reveal.len(),
            public_keys.len(),
            public_key_proofs.len()
        ));
    }
    let dc1 = BcsDealerContribution1 {
        shares_to_reveal: shares_to_reveal.to_vec(),
        public_keys: public_keys
            .iter()
            .map(|v| element_for_scheme(scheme, v))
            .collect::<Result<Vec<_>>>()?,
        public_key_proofs: public_key_proofs.to_vec(),
    };
    Ok(bcs::to_bytes(&dc1).expect("bcs serialization failed"))
}

fn element_for_scheme(scheme: u8, bytes: &[u8]) -> Result<BcsElement> {
    match scheme {
        SCHEME_BLS12381G1 => {
            if bytes.len() != 48 {
                return Err(anyhow!(
                    "BLS12-381 G1 point must be 48 bytes, got {}",
                    bytes.len()
                ));
            }
            BcsElement::from_scheme_and_bytes(scheme, bytes.to_vec())
        }
        SCHEME_BLS12381G2 => {
            if bytes.len() != 96 {
                return Err(anyhow!(
                    "BLS12-381 G2 point must be 96 bytes, got {}",
                    bytes.len()
                ));
            }
            BcsElement::from_scheme_and_bytes(scheme, bytes.to_vec())
        }
        s => Err(anyhow!("unsupported group scheme {}", s)),
    }
}

fn scalar_to_fr(s: &BcsScalar) -> Result<Fr> {
    let bytes: [u8; 32] = s
        .scalar_bytes()
        .try_into()
        .map_err(|_| anyhow!("scalar must be 32 bytes, got {}", s.scalar_bytes().len()))?;
    Ok(fr_from_le_bytes(bytes))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pke::{Ciphertext, ElGamalOtpRistretto255Ciphertext};

    fn fake_ciphertext() -> Ciphertext {
        Ciphertext::ElGamalOtpRistretto255(ElGamalOtpRistretto255Ciphertext {
            c0: vec![0u8; 32],
            c1: vec![0u8; 32],
            sym_ciph: vec![0xaau8; 4],
            mac: vec![0u8; 32],
        })
    }

    fn minimal_dc0_base_g1() -> (Vec<Vec<u8>>, Vec<Ciphertext>, Ciphertext) {
        (
            vec![vec![0u8; 48], vec![0u8; 48]],
            vec![],
            fake_ciphertext(),
        )
    }

    fn minimal_dc0_base_g2() -> (Vec<Vec<u8>>, Vec<Ciphertext>, Ciphertext) {
        (
            vec![vec![0u8; 96], vec![0u8; 96]],
            vec![],
            fake_ciphertext(),
        )
    }

    #[test]
    fn dc0_bytes_g1_consistency_none_appends_zero() {
        let (c, s, d) = minimal_dc0_base_g1();
        let out = dc0_bytes(SCHEME_BLS12381G1, &c, &s, Some(&d), None).unwrap();
        assert_eq!(*out.last().unwrap(), 0x00);
    }

    #[test]
    fn dc0_bytes_g2_consistency_none_appends_zero() {
        let (c, s, d) = minimal_dc0_base_g2();
        let out = dc0_bytes(SCHEME_BLS12381G2, &c, &s, Some(&d), None).unwrap();
        assert_eq!(*out.last().unwrap(), 0x00);
    }

    #[test]
    fn dc0_bytes_g1_wrong_size_rejected() {
        let bad = vec![vec![0u8; 47], vec![0u8; 47]];
        let (_, s, d) = minimal_dc0_base_g1();
        assert!(dc0_bytes(SCHEME_BLS12381G1, &bad, &s, Some(&d), None).is_err());
    }

    #[test]
    fn dc1_requires_aligned_vectors() {
        let opening = opening_for_scheme(SCHEME_BLS12381G1, 1, &[1u8; 32], &[2u8; 32]).unwrap();
        let shares = vec![None, Some(opening)];
        let public_keys = vec![vec![0u8; 48]];
        let proofs = vec![None, None];
        assert!(dc1_bytes(SCHEME_BLS12381G1, &shares, &public_keys, &proofs).is_err());
    }
}
