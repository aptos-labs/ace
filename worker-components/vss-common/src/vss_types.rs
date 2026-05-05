// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! VSS payload builders and Feldman verification.
//!
//! Wire layouts mirror Move's `contracts/vss/sources/vss.move`. The BCS-derived
//! mirror types live in `session.rs` (`BcsDealerContribution0`, `BcsScalar`, …);
//! this module just constructs them and serializes via `bcs::to_bytes`.

use anyhow::{anyhow, Result};
use serde::Serialize;

use crate::pke::{BcsCiphertext, Ciphertext};
use crate::session::{
    BcsDealerContribution0, BcsDealerContribution1, BcsElement, BcsPcsCommitment,
    BcsPublicPoint, BcsResharingDealerResponse, BcsScalar, BcsSigmaDlogEqProof,
    SCHEME_BLS12381G1, SCHEME_BLS12381G2,
};

// ── DealerState ───────────────────────────────────────────────────────────────

/// Plaintext-only intermediate (gets PKE-encrypted into `dealer_state` before going on chain).
/// Wire: BCS enum tag (= scheme) || u64 LE n || BCS Vec<Vec<u8>> coefs_poly_p
///
/// Note: only one variant exists today — the on-chain `dealer_state` BCS layout is
/// agnostic to whether the polynomial commits to G1 or G2 (coefficients live in Fr).
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

/// Plaintext of a per-recipient PKE ciphertext: BCS-encoded `BcsScalar`.
/// Wire: scheme byte || ULEB128(32) || 32B y
pub fn private_share_message_bytes(scheme: u8, y: &[u8; 32]) -> Result<Vec<u8>> {
    let scalar = BcsScalar::from_scheme_and_bytes(scheme, y.to_vec())?;
    Ok(bcs::to_bytes(&scalar).expect("bcs serialization failed"))
}

// ── DealerContribution0 payload ───────────────────────────────────────────────

/// Build the wire payload for `on_dealer_contribution_0`.
///
/// `scheme` is the group scheme byte read from the on-chain session's `public_base_element`.
/// `commitment_v_values[k]` are the compressed group element bytes (48 for G1, 96 for G2)
/// of `coefs[k] · base_point`.
pub fn dc0_bytes(
    scheme: u8,
    commitment_v_values: &[Vec<u8>],
    share_ciphertexts: &[Ciphertext],
    dealer_state_ct: &Ciphertext,
    resharing_response: Option<(&[u8], &[u8], &[u8], &[u8; 32])>,
) -> Result<Vec<u8>> {
    let dc0 = BcsDealerContribution0 {
        pcs_commitment: BcsPcsCommitment {
            points: commitment_v_values
                .iter()
                .map(|v| element_for_scheme(scheme, v))
                .collect::<Result<Vec<_>>>()?,
        },
        private_share_messages: share_ciphertexts.iter().map(BcsCiphertext::from).collect(),
        dealer_state: Some(BcsCiphertext::from(dealer_state_ct)),
        resharing_response: resharing_response
            .map(|(p1, t0, t1, s)| -> Result<_> {
                Ok(BcsResharingDealerResponse {
                    another_scaled_element: element_for_scheme(scheme, p1)?,
                    proof: BcsSigmaDlogEqProof {
                        t0: element_for_scheme(scheme, t0)?,
                        t1: element_for_scheme(scheme, t1)?,
                        s: BcsScalar::from_scheme_and_bytes(scheme, s.to_vec())?,
                    },
                })
            })
            .transpose()?,
    };
    Ok(bcs::to_bytes(&dc0).expect("bcs serialization failed"))
}

// ── DealerContribution1 payload ───────────────────────────────────────────────

/// Build the wire payload for `on_dealer_open`.
///
/// `shares_to_reveal[i]` = None if holder i acked, Some(y_bytes) otherwise.
pub fn dc1_bytes(scheme: u8, shares_to_reveal: &[Option<[u8; 32]>]) -> Result<Vec<u8>> {
    let shares_to_reveal: Vec<Option<BcsScalar>> = shares_to_reveal
        .iter()
        .map(|opt| -> Result<_> {
            opt.map(|y| BcsScalar::from_scheme_and_bytes(scheme, y.to_vec()))
                .transpose()
        })
        .collect::<Result<Vec<_>>>()?;
    let dc1 = BcsDealerContribution1 { shares_to_reveal };
    Ok(bcs::to_bytes(&dc1).expect("bcs serialization failed"))
}

fn element_for_scheme(scheme: u8, bytes: &[u8]) -> Result<BcsElement> {
    match scheme {
        SCHEME_BLS12381G1 => {
            if bytes.len() != 48 {
                return Err(anyhow!("BLS12-381 G1 point must be 48 bytes, got {}", bytes.len()));
            }
            Ok(BcsElement::Bls12381G1(BcsPublicPoint { point: bytes.to_vec() }))
        }
        SCHEME_BLS12381G2 => {
            if bytes.len() != 96 {
                return Err(anyhow!("BLS12-381 G2 point must be 96 bytes, got {}", bytes.len()));
            }
            Ok(BcsElement::Bls12381G2(BcsPublicPoint { point: bytes.to_vec() }))
        }
        s => Err(anyhow!("unsupported group scheme {}", s)),
    }
}

// ── Feldman VSS verification ──────────────────────────────────────────────────

/// Verify that `plaintext` (a `BcsScalar` wire encoding) satisfies the Feldman commitment
/// against the given group scheme.
///
/// `plaintext` format: `[scheme_byte][0x20 ULEB128(32)][32B Fr scalar y]`
/// `holder_x`: 1-based evaluation point (= holder 0-based index + 1)
///
/// Checks: `y * base_point == sum(k=0..t-1, x^k * commitment.points[k])`
pub fn feldman_verify(
    plaintext: &[u8],
    base_point: &BcsElement,
    commitment: &BcsPcsCommitment,
    holder_x: u64,
) -> Result<()> {
    if plaintext.len() < 34 {
        return Err(anyhow!("plaintext too short for SecretShare"));
    }
    let plaintext_scheme = plaintext[0];
    if plaintext_scheme != base_point.scheme() {
        return Err(anyhow!(
            "feldman_verify: scheme mismatch (plaintext={}, base_point={})",
            plaintext_scheme,
            base_point.scheme()
        ));
    }
    let y = &plaintext[2..34]; // skip [variant byte][ULEB128(32) length prefix]

    match base_point {
        BcsElement::Bls12381G1(_) => feldman_verify_g1(y, base_point, commitment, holder_x),
        BcsElement::Bls12381G2(_) => feldman_verify_g2(y, base_point, commitment, holder_x),
    }
}

fn feldman_verify_g1(
    y_bytes: &[u8],
    base_point: &BcsElement,
    commitment: &BcsPcsCommitment,
    holder_x: u64,
) -> Result<()> {
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::CurveGroup;
    use ark_ff::{PrimeField, Zero};
    use ark_serialize::CanonicalDeserialize;

    let y_fr = Fr::from_le_bytes_mod_order(y_bytes);
    let base_g1 = G1Affine::deserialize_compressed(base_point.point_bytes())
        .map_err(|e| anyhow!("base_point G1 deserialize: {}", e))?;
    let lhs: G1Affine = (base_g1 * y_fr).into_affine();

    let x = Fr::from(holder_x);
    let mut rhs = G1Projective::zero();
    let mut x_power = Fr::from(1u64);
    for elem in &commitment.points {
        let pt = G1Affine::deserialize_compressed(elem.point_bytes())
            .map_err(|e| anyhow!("commitment G1 point deserialize: {}", e))?;
        rhs += pt * x_power;
        x_power *= x;
    }
    if lhs != rhs.into_affine() {
        return Err(anyhow!("Feldman verification failed (G1): share does not match commitment"));
    }
    Ok(())
}

fn feldman_verify_g2(
    y_bytes: &[u8],
    base_point: &BcsElement,
    commitment: &BcsPcsCommitment,
    holder_x: u64,
) -> Result<()> {
    use ark_bls12_381::{Fr, G2Affine, G2Projective};
    use ark_ec::CurveGroup;
    use ark_ff::{PrimeField, Zero};
    use ark_serialize::CanonicalDeserialize;

    let y_fr = Fr::from_le_bytes_mod_order(y_bytes);
    let base_g2 = G2Affine::deserialize_compressed(base_point.point_bytes())
        .map_err(|e| anyhow!("base_point G2 deserialize: {}", e))?;
    let lhs: G2Affine = (base_g2 * y_fr).into_affine();

    let x = Fr::from(holder_x);
    let mut rhs = G2Projective::zero();
    let mut x_power = Fr::from(1u64);
    for elem in &commitment.points {
        let pt = G2Affine::deserialize_compressed(elem.point_bytes())
            .map_err(|e| anyhow!("commitment G2 point deserialize: {}", e))?;
        rhs += pt * x_power;
        x_power *= x;
    }
    if lhs != rhs.into_affine() {
        return Err(anyhow!("Feldman verification failed (G2): share does not match commitment"));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pke::Ciphertext;

    fn fake_ciphertext() -> Ciphertext {
        Ciphertext::ElGamalOtpRistretto255 {
            c0: [0u8; 32],
            c1: [0u8; 32],
            sym_ciph: vec![0xaau8; 4],
            mac: [0u8; 32],
        }
    }

    fn minimal_dc0_base_g1() -> (Vec<Vec<u8>>, Vec<Ciphertext>, Ciphertext) {
        (vec![vec![0u8; 48]], vec![], fake_ciphertext())
    }

    fn minimal_dc0_base_g2() -> (Vec<Vec<u8>>, Vec<Ciphertext>, Ciphertext) {
        (vec![vec![0u8; 96]], vec![], fake_ciphertext())
    }

    #[test]
    fn dc0_bytes_g1_resharing_none_appends_zero() {
        let (c, s, d) = minimal_dc0_base_g1();
        let out = dc0_bytes(SCHEME_BLS12381G1, &c, &s, &d, None).unwrap();
        assert_eq!(*out.last().unwrap(), 0x00);
    }

    #[test]
    fn dc0_bytes_g2_resharing_none_appends_zero() {
        let (c, s, d) = minimal_dc0_base_g2();
        let out = dc0_bytes(SCHEME_BLS12381G2, &c, &s, &d, None).unwrap();
        assert_eq!(*out.last().unwrap(), 0x00);
    }

    #[test]
    fn dc0_bytes_g1_wrong_size_rejected() {
        // 47-byte commitment (should be 48 for G1) is rejected.
        let bad = vec![vec![0u8; 47]];
        let (_, s, d) = minimal_dc0_base_g1();
        assert!(dc0_bytes(SCHEME_BLS12381G1, &bad, &s, &d, None).is_err());
    }

    #[test]
    fn dc0_bytes_g2_wrong_size_rejected() {
        // 48-byte commitment with G2 scheme is rejected.
        let bad = vec![vec![0u8; 48]];
        let (_, s, d) = minimal_dc0_base_g2();
        assert!(dc0_bytes(SCHEME_BLS12381G2, &bad, &s, &d, None).is_err());
    }

    #[test]
    fn dc0_bytes_g1_resharing_some_appends_correct_bytes() {
        let (c, s, d) = minimal_dc0_base_g1();
        let p1 = vec![0x11u8; 48];
        let t0 = vec![0x22u8; 48];
        let t1 = vec![0x33u8; 48];
        let s_fr = [0x44u8; 32];

        let out_none = dc0_bytes(SCHEME_BLS12381G1, &c, &s, &d, None).unwrap();
        let out_some = dc0_bytes(SCHEME_BLS12381G1, &c, &s, &d, Some((&p1, &t0, &t1, &s_fr))).unwrap();

        // 0x01 + 3×50 (3 G1 elements with 0x00 variant tag) + 34 (scalar) - 1 (replaces 0x00) = 184
        assert_eq!(out_some.len(), out_none.len() + 184);

        let tail = &out_some[out_none.len() - 1..];
        assert_eq!(tail[0], 0x01);
        assert_eq!(&tail[1..3], &[0x00, 0x30]);
        assert_eq!(&tail[3..51], p1.as_slice());
        assert_eq!(&tail[51..53], &[0x00, 0x30]);
        assert_eq!(&tail[53..101], t0.as_slice());
        assert_eq!(&tail[101..103], &[0x00, 0x30]);
        assert_eq!(&tail[103..151], t1.as_slice());
        assert_eq!(&tail[151..153], &[0x00, 0x20]);
        assert_eq!(&tail[153..185], &s_fr);
    }
}
