// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Sigma DLog-Eq proof generator (group-parametric).
//!
//! Proves knowledge of `secret` such that `secret*b0 == p0` AND `secret*b1 == p1`,
//! using the Fiat-Shamir transcript expected by the on-chain verifier in
//! `ace::vss::on_dealer_contribution_0`.
//!
//! The proof is generic over the underlying group: the caller passes a `scheme` byte
//! (0 = BLS12-381 G1, 1 = BLS12-381 G2) and the function dispatches to the right
//! ark types internally. Group element bytes in / out are length 48 for G1 and 96
//! for G2 (compressed).

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use rand::RngCore;
use sha2::{Digest, Sha512};

use crate::crypto::fr_to_le_bytes;
use crate::group::{SCHEME_BLS12381G1, SCHEME_BLS12381G2};

/// Sigma DLog-Eq proof: proves knowledge of `secret` s.t. `secret*b0 == p0` AND `secret*b1 == p1`.
/// Returns `(p1_bytes, t0_bytes, t1_bytes, s_proof_bytes)`. Group element bytes are 48 (G1) or
/// 96 (G2), depending on `scheme`.
pub fn prove(
    scheme: u8,
    chain_id: u8,
    ace_addr_bytes: &[u8; 32],
    b0_bytes: &[u8],
    p0_bytes: &[u8],
    b1_bytes: &[u8],
    secret: Fr,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32])> {
    let mut r_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut r_bytes);
    let r = Fr::from_le_bytes_mod_order(&r_bytes);

    let (p1_bytes, t0_bytes, t1_bytes) = match scheme {
        SCHEME_BLS12381G1 => proof_points_g1(b0_bytes, b1_bytes, secret, r)?,
        SCHEME_BLS12381G2 => proof_points_g2(b0_bytes, b1_bytes, secret, r)?,
        s => return Err(anyhow!("sigma_dlog_eq::prove: unsupported scheme {}", s)),
    };

    // Fiat-Shamir transcript = BCS(FiatShamirTag) || BCS(b0) || BCS(p0) || BCS(b1) || BCS(p1) || BCS(t0) || BCS(t1)
    // BCS(FiatShamirTag { chain_id: u8, module_addr: address, module_name: vector<u8> })
    //   = [chain_id][32B addr][ULEB128(3)=0x03][b'v'][b's'][b's']
    // BCS(group::Element::*(...)) = [scheme byte][ULEB128(point_len)][point bytes]
    let mut trx: Vec<u8> = Vec::new();
    trx.push(chain_id);
    trx.extend_from_slice(ace_addr_bytes);
    trx.extend_from_slice(&[0x03, b'v', b's', b's']);
    for pt in [b0_bytes, p0_bytes, b1_bytes, &p1_bytes, &t0_bytes, &t1_bytes] {
        trx.push(scheme);
        // ULEB128 of 48 = 0x30; of 96 = 0x60. Both fit in one byte.
        trx.push(pt.len() as u8);
        trx.extend_from_slice(pt);
    }

    let hash = Sha512::digest(&trx);
    let c = Fr::from_le_bytes_mod_order(&hash.iter().rev().cloned().collect::<Vec<_>>());
    let s_proof = r + c * secret;
    let s_bytes = fr_to_le_bytes(s_proof);

    Ok((p1_bytes, t0_bytes, t1_bytes, s_bytes))
}

fn proof_points_g1(
    b0_bytes: &[u8],
    b1_bytes: &[u8],
    secret: Fr,
    r: Fr,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use ark_bls12_381::G1Affine;
    use ark_ec::CurveGroup;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    let b0 = G1Affine::deserialize_compressed(b0_bytes)
        .map_err(|e| anyhow!("b0 G1 deserialize: {}", e))?;
    let b1 = G1Affine::deserialize_compressed(b1_bytes)
        .map_err(|e| anyhow!("b1 G1 deserialize: {}", e))?;
    let mut p1 = vec![0u8; 48];
    let mut t0 = vec![0u8; 48];
    let mut t1 = vec![0u8; 48];
    (b1 * secret).into_affine().serialize_compressed(&mut p1[..]).expect("G1 serialize");
    (b0 * r).into_affine().serialize_compressed(&mut t0[..]).expect("G1 serialize");
    (b1 * r).into_affine().serialize_compressed(&mut t1[..]).expect("G1 serialize");
    Ok((p1, t0, t1))
}

fn proof_points_g2(
    b0_bytes: &[u8],
    b1_bytes: &[u8],
    secret: Fr,
    r: Fr,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use ark_bls12_381::G2Affine;
    use ark_ec::CurveGroup;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    let b0 = G2Affine::deserialize_compressed(b0_bytes)
        .map_err(|e| anyhow!("b0 G2 deserialize: {}", e))?;
    let b1 = G2Affine::deserialize_compressed(b1_bytes)
        .map_err(|e| anyhow!("b1 G2 deserialize: {}", e))?;
    let mut p1 = vec![0u8; 96];
    let mut t0 = vec![0u8; 96];
    let mut t1 = vec![0u8; 96];
    (b1 * secret).into_affine().serialize_compressed(&mut p1[..]).expect("G2 serialize");
    (b0 * r).into_affine().serialize_compressed(&mut t0[..]).expect("G2 serialize");
    (b1 * r).into_affine().serialize_compressed(&mut t1[..]).expect("G2 serialize");
    Ok((p1, t0, t1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    /// Rebuilds the Fiat-Shamir challenge exactly as `prove` does.
    fn rebuild_fs_challenge(
        scheme: u8,
        chain_id: u8,
        ace_bytes: &[u8; 32],
        pts: [&[u8]; 6],
    ) -> Fr {
        let mut trx: Vec<u8> = Vec::new();
        trx.push(chain_id);
        trx.extend_from_slice(ace_bytes);
        trx.extend_from_slice(&[0x03, b'v', b's', b's']);
        for pt in pts {
            trx.push(scheme);
            trx.push(pt.len() as u8);
            trx.extend_from_slice(pt);
        }
        let hash = Sha512::digest(&trx);
        Fr::from_le_bytes_mod_order(&hash.iter().rev().cloned().collect::<Vec<_>>())
    }

    /// G1 self-consistency: s*b0 == t0 + c*p0 AND s*b1 == t1 + c*p1.
    #[test]
    fn prove_self_consistent_g1() {
        let chain_id = 4u8;
        let mut ace_bytes = [0u8; 32];
        ace_bytes[30] = 0xca;
        ace_bytes[31] = 0xfe;

        let secret = Fr::from_le_bytes_mod_order(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);

        let b0 = G1Affine::generator();
        let b1: G1Affine = (b0 * Fr::from(7u64)).into_affine();
        let p0: G1Affine = (b0 * secret).into_affine();

        let mut b0_bytes = vec![0u8; 48];
        let mut b1_bytes = vec![0u8; 48];
        let mut p0_bytes = vec![0u8; 48];
        b0.serialize_compressed(&mut b0_bytes[..]).unwrap();
        b1.serialize_compressed(&mut b1_bytes[..]).unwrap();
        p0.serialize_compressed(&mut p0_bytes[..]).unwrap();

        let (p1_bytes, t0_bytes, t1_bytes, s_bytes) = prove(
            SCHEME_BLS12381G1, chain_id, &ace_bytes, &b0_bytes, &p0_bytes, &b1_bytes, secret,
        )
        .unwrap();

        let p1 = G1Affine::deserialize_compressed(p1_bytes.as_slice()).unwrap();
        let t0 = G1Affine::deserialize_compressed(t0_bytes.as_slice()).unwrap();
        let t1 = G1Affine::deserialize_compressed(t1_bytes.as_slice()).unwrap();
        let s_fr = Fr::from_le_bytes_mod_order(&s_bytes);

        let c = rebuild_fs_challenge(
            SCHEME_BLS12381G1, chain_id, &ace_bytes,
            [&b0_bytes, &p0_bytes, &b1_bytes, &p1_bytes, &t0_bytes, &t1_bytes],
        );

        let lhs0: G1Affine = (b0 * s_fr).into_affine();
        let rhs0: G1Affine = (t0.into_group() + p0 * c).into_affine();
        assert_eq!(lhs0, rhs0, "s*b0 != t0 + c*p0");

        let lhs1: G1Affine = (b1 * s_fr).into_affine();
        let rhs1: G1Affine = (t1.into_group() + p1 * c).into_affine();
        assert_eq!(lhs1, rhs1, "s*b1 != t1 + c*p1");
    }

    /// G2 self-consistency: same proof structure with the dealer working in G2.
    #[test]
    fn prove_self_consistent_g2() {
        let chain_id = 4u8;
        let mut ace_bytes = [0u8; 32];
        ace_bytes[31] = 0x42;

        let secret = Fr::from_le_bytes_mod_order(&[0x55u8; 32]);
        let b0 = G2Affine::generator();
        let b1: G2Affine = (b0 * Fr::from(11u64)).into_affine();
        let p0: G2Affine = (b0 * secret).into_affine();

        let mut b0_bytes = vec![0u8; 96];
        let mut b1_bytes = vec![0u8; 96];
        let mut p0_bytes = vec![0u8; 96];
        b0.serialize_compressed(&mut b0_bytes[..]).unwrap();
        b1.serialize_compressed(&mut b1_bytes[..]).unwrap();
        p0.serialize_compressed(&mut p0_bytes[..]).unwrap();

        let (p1_bytes, t0_bytes, t1_bytes, s_bytes) = prove(
            SCHEME_BLS12381G2, chain_id, &ace_bytes, &b0_bytes, &p0_bytes, &b1_bytes, secret,
        )
        .unwrap();
        assert_eq!(p1_bytes.len(), 96);
        assert_eq!(t0_bytes.len(), 96);
        assert_eq!(t1_bytes.len(), 96);

        let p1 = G2Affine::deserialize_compressed(p1_bytes.as_slice()).unwrap();
        let t0 = G2Affine::deserialize_compressed(t0_bytes.as_slice()).unwrap();
        let t1 = G2Affine::deserialize_compressed(t1_bytes.as_slice()).unwrap();
        let s_fr = Fr::from_le_bytes_mod_order(&s_bytes);

        let c = rebuild_fs_challenge(
            SCHEME_BLS12381G2, chain_id, &ace_bytes,
            [&b0_bytes, &p0_bytes, &b1_bytes, &p1_bytes, &t0_bytes, &t1_bytes],
        );

        let lhs0: G2Affine = (b0 * s_fr).into_affine();
        let rhs0: G2Affine = (t0.into_group() + p0 * c).into_affine();
        assert_eq!(lhs0, rhs0, "s*b0 != t0 + c*p0 (G2)");

        let lhs1: G2Affine = (b1 * s_fr).into_affine();
        let rhs1: G2Affine = (t1.into_group() + p1 * c).into_affine();
        assert_eq!(lhs1, rhs1, "s*b1 != t1 + c*p1 (G2)");
    }

    /// Wrong secret → proof does NOT verify (G1).
    #[test]
    fn prove_wrong_secret_fails_g1() {
        let chain_id = 1u8;
        let ace_bytes = [0u8; 32];

        let secret = Fr::from_le_bytes_mod_order(&[1u8; 32]);
        let wrong_secret = Fr::from_le_bytes_mod_order(&[2u8; 32]);

        let b0 = G1Affine::generator();
        let b1: G1Affine = (b0 * Fr::from(3u64)).into_affine();
        let p0: G1Affine = (b0 * secret).into_affine();

        let mut b0_bytes = vec![0u8; 48];
        let mut b1_bytes = vec![0u8; 48];
        let mut p0_bytes = vec![0u8; 48];
        b0.serialize_compressed(&mut b0_bytes[..]).unwrap();
        b1.serialize_compressed(&mut b1_bytes[..]).unwrap();
        p0.serialize_compressed(&mut p0_bytes[..]).unwrap();

        let (p1_bytes, t0_bytes, t1_bytes, s_bytes) = prove(
            SCHEME_BLS12381G1, chain_id, &ace_bytes, &b0_bytes, &p0_bytes, &b1_bytes, wrong_secret,
        )
        .unwrap();

        let t0 = G1Affine::deserialize_compressed(t0_bytes.as_slice()).unwrap();
        let s_fr = Fr::from_le_bytes_mod_order(&s_bytes);
        let c = rebuild_fs_challenge(
            SCHEME_BLS12381G1, chain_id, &ace_bytes,
            [&b0_bytes, &p0_bytes, &b1_bytes, &p1_bytes, &t0_bytes, &t1_bytes],
        );

        let lhs0: G1Affine = (b0 * s_fr).into_affine();
        let rhs0: G1Affine = (t0.into_group() + p0 * c).into_affine();
        assert_ne!(lhs0, rhs0, "proof with wrong secret should not verify");
    }
}
