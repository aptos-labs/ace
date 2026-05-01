// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! VSS payload builders and Feldman verification.
//!
//! Wire layouts mirror Move's `contracts/vss/sources/vss.move`. The BCS-derived
//! mirror types live in `session.rs` (`BcsDealerContribution0`, `BcsScalar`, …);
//! this module just constructs them and serializes via `bcs::to_bytes`.

use serde::Serialize;

use crate::pke::{BcsCiphertext, Ciphertext};
use crate::session::{
    BcsDealerContribution0, BcsDealerContribution1, BcsElement, BcsPcsCommitment,
    BcsPrivateScalar, BcsPublicPoint, BcsResharingDealerResponse, BcsScalar,
    BcsSigmaDlogEqProof,
};

pub const SCHEME_BLS12381_G1: u8 = 0;

// ── DealerState ───────────────────────────────────────────────────────────────

/// Plaintext-only intermediate (gets PKE-encrypted into `dealer_state` before going on chain).
/// Wire: BCS enum tag (= scheme) || u64 LE n || BCS Vec<Vec<u8>> coefs_poly_p
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
/// Wire: 0x00 (variant tag = scheme) || ULEB128(32) || 32B y
pub fn private_share_message_bytes(y: &[u8; 32]) -> Vec<u8> {
    let scalar = BcsScalar::Bls12381G1(BcsPrivateScalar { scalar: y.to_vec() });
    bcs::to_bytes(&scalar).expect("bcs serialization failed")
}

// ── DealerContribution0 payload ───────────────────────────────────────────────

/// Build the wire payload for `on_dealer_contribution_0`.
pub fn dc0_bytes(
    commitment_v_values: &[[u8; 48]],
    share_ciphertexts: &[Ciphertext],
    dealer_state_ct: &Ciphertext,
    resharing_response: Option<(&[u8; 48], &[u8; 48], &[u8; 48], &[u8; 32])>,
) -> Vec<u8> {
    let dc0 = BcsDealerContribution0 {
        pcs_commitment: BcsPcsCommitment {
            points: commitment_v_values.iter().map(|v| g1_element(v)).collect(),
        },
        private_share_messages: share_ciphertexts.iter().map(BcsCiphertext::from).collect(),
        dealer_state: Some(BcsCiphertext::from(dealer_state_ct)),
        resharing_response: resharing_response.map(|(p1, t0, t1, s)| BcsResharingDealerResponse {
            another_scaled_element: g1_element(p1),
            proof: BcsSigmaDlogEqProof {
                t0: g1_element(t0),
                t1: g1_element(t1),
                s: BcsScalar::Bls12381G1(BcsPrivateScalar { scalar: s.to_vec() }),
            },
        }),
    };
    bcs::to_bytes(&dc0).expect("bcs serialization failed")
}

// ── DealerContribution1 payload ───────────────────────────────────────────────

/// Build the wire payload for `on_dealer_open`.
///
/// `shares_to_reveal[i]` = None if holder i acked, Some(y_bytes) otherwise.
pub fn dc1_bytes(shares_to_reveal: &[Option<[u8; 32]>]) -> Vec<u8> {
    let dc1 = BcsDealerContribution1 {
        shares_to_reveal: shares_to_reveal
            .iter()
            .map(|opt| opt.map(|y| BcsScalar::Bls12381G1(BcsPrivateScalar { scalar: y.to_vec() })))
            .collect(),
    };
    bcs::to_bytes(&dc1).expect("bcs serialization failed")
}

fn g1_element(point: &[u8; 48]) -> BcsElement {
    BcsElement::Bls12381G1(BcsPublicPoint { point: point.to_vec() })
}

// ── Feldman VSS verification ──────────────────────────────────────────────────

/// Verify that `plaintext` (a `BcsScalar` wire encoding) satisfies the Feldman commitment.
///
/// `plaintext` format: `[0x00 variant][0x20 ULEB128(32)][32B Fr scalar y]`
/// `holder_x`: 1-based evaluation point (= holder 0-based index + 1)
///
/// Checks: `y * base_point == sum(k=0..t-1, x^k * commitment.points[k])`
pub fn feldman_verify(
    plaintext: &[u8],
    base_point: &BcsElement,
    commitment: &BcsPcsCommitment,
    holder_x: u64,
) -> anyhow::Result<()> {
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::CurveGroup;
    use ark_ff::{PrimeField, Zero};
    use ark_serialize::CanonicalDeserialize;

    if plaintext.len() < 34 {
        return Err(anyhow::anyhow!("plaintext too short for SecretShare"));
    }
    let y = &plaintext[2..34]; // skip [variant byte][ULEB128(32) length prefix]
    let y_fr = Fr::from_le_bytes_mod_order(y);

    let base_bytes = match base_point {
        BcsElement::Bls12381G1(p) => p.point.as_slice(),
    };
    let base_g1 = G1Affine::deserialize_compressed(base_bytes)
        .map_err(|e| anyhow::anyhow!("base_point deserialize: {}", e))?;
    let lhs: G1Affine = (base_g1 * y_fr).into_affine();

    let x = Fr::from(holder_x);
    let mut rhs = G1Projective::zero();
    let mut x_power = Fr::from(1u64);
    for elem in &commitment.points {
        let pt_bytes = match elem {
            BcsElement::Bls12381G1(p) => p.point.as_slice(),
        };
        let pt = G1Affine::deserialize_compressed(pt_bytes)
            .map_err(|e| anyhow::anyhow!("commitment point deserialize: {}", e))?;
        rhs += pt * x_power;
        x_power *= x;
    }

    if lhs != rhs.into_affine() {
        return Err(anyhow::anyhow!("Feldman verification failed: share does not match commitment"));
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

    fn minimal_dc0_base() -> (Vec<[u8; 48]>, Vec<Ciphertext>, Ciphertext) {
        (vec![[0u8; 48]], vec![], fake_ciphertext())
    }

    /// dc0_bytes with no resharing response ends with 0x00.
    #[test]
    fn dc0_bytes_resharing_none_appends_zero() {
        let (c, s, d) = minimal_dc0_base();
        let out = dc0_bytes(&c, &s, &d, None);
        assert_eq!(*out.last().unwrap(), 0x00, "last byte should be 0x00 for None");
    }

    /// dc0_bytes with Some resharing response appends the correct BCS bytes.
    /// Layout after dealer_state: 0x01 || [0x00,0x30,48B] × 3 || [0x00,0x20,32B]
    /// = 1 + 50*3 + 34 = 185 bytes.
    #[test]
    fn dc0_bytes_resharing_some_appends_correct_bytes() {
        let (c, s, d) = minimal_dc0_base();
        let p1 = [0x11u8; 48];
        let t0 = [0x22u8; 48];
        let t1 = [0x33u8; 48];
        let s_fr = [0x44u8; 32];

        let out_none = dc0_bytes(&c, &s, &d, None);
        let out_some = dc0_bytes(&c, &s, &d, Some((&p1, &t0, &t1, &s_fr)));

        // The Some output should be exactly 184 bytes longer (0x01 + 3×50 + 34 - 1 for the None 0x00)
        assert_eq!(out_some.len(), out_none.len() + 184);

        let tail = &out_some[out_none.len() - 1..]; // from where 0x00 would be
        assert_eq!(tail[0], 0x01);
        // p1 element
        assert_eq!(&tail[1..3], &[0x00, 0x30]);
        assert_eq!(&tail[3..51], &p1);
        // t0 element
        assert_eq!(&tail[51..53], &[0x00, 0x30]);
        assert_eq!(&tail[53..101], &t0);
        // t1 element
        assert_eq!(&tail[101..103], &[0x00, 0x30]);
        assert_eq!(&tail[103..151], &t1);
        // s scalar
        assert_eq!(&tail[151..153], &[0x00, 0x20]);
        assert_eq!(&tail[153..185], &s_fr);
    }
}
