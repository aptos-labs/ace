// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! VSS cryptographic helpers.
//!
//! PKE lives in the `ace-pke` crate; selected helpers are re-exported here for
//! legacy call sites that still import `vss_common::crypto::pke_encrypt`.

use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use sha3::{Digest, Sha3_256};

pub use ace_pke::{hmac_sha3_256, kdf, pke_encrypt};

// ── BLS12-381 Fr helpers ──────────────────────────────────────────────────────

/// Serialize a BLS12-381 Fr element to 32-byte little-endian canonical form.
/// Matches TypeScript `numberToBytesLE(scalar, 32)`.
pub fn fr_to_le_bytes(f: Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    f.serialize_uncompressed(&mut bytes[..])
        .expect("Fr serialize failed");
    bytes
}

/// Derive a BLS12-381 Fr polynomial coefficient from a PKE decryption key and index.
///
/// Uses SHA3-256("vss-coef-v1/" || dk_bytes || LE64(idx)) reduced mod Fr.
/// Deterministic: same dk + idx always gives the same coefficient.
pub fn fr_from_dk_bytes(dk: &[u8], idx: usize) -> Fr {
    fr_from_dk_bytes_with_dst(b"vss-coef-v1/", dk, idx)
}

/// Domain-separated variant of `fr_from_dk_bytes`.
pub fn fr_from_dk_bytes_with_dst(dst: &[u8], dk: &[u8], idx: usize) -> Fr {
    let mut hasher = Sha3_256::new();
    hasher.update(dst);
    hasher.update(dk);
    hasher.update((idx as u64).to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    Fr::from_le_bytes_mod_order(&hash)
}

/// Deserialize a BLS12-381 Fr element from 32-byte little-endian bytes.
/// Reduces mod Fr order, matching `Fr::from_le_bytes_mod_order`.
pub fn fr_from_le_bytes(bytes: [u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Evaluate polynomial at `x` using Horner's method.
/// `coefs[0]` is the constant term (secret), `coefs[t-1]` is the highest-degree coefficient.
pub fn poly_eval(coefs: &[Fr], x: Fr) -> Fr {
    let mut result = Fr::from(0u64);
    for c in coefs.iter().rev() {
        result = result * x + c;
    }
    result
}

/// Compute the compressed 48-byte BLS12-381 G1 point `scalar * G1::generator`.
/// Matches TypeScript `bls12_381.G1.ProjectivePoint.BASE.multiply(scalar).toBytes()`.
pub fn g1_compressed(scalar: Fr) -> [u8; 48] {
    let pt: ark_bls12_381::G1Affine = (ark_bls12_381::G1Affine::generator() * scalar).into_affine();
    let mut bytes = [0u8; 48];
    pt.serialize_compressed(&mut bytes[..])
        .expect("G1 serialize failed");
    bytes
}

/// Compute the compressed 48-byte BLS12-381 G1 point `scalar * base_point`.
/// Use this instead of `g1_compressed` when the session's base point is not G1::generator.
pub fn g1_compressed_with_base(scalar: Fr, base_point_bytes: &[u8]) -> anyhow::Result<[u8; 48]> {
    use ark_serialize::CanonicalDeserialize;
    let base = ark_bls12_381::G1Affine::deserialize_compressed(base_point_bytes)
        .map_err(|e| anyhow::anyhow!("base_point deserialize: {}", e))?;
    let pt: ark_bls12_381::G1Affine = (base * scalar).into_affine();
    let mut bytes = [0u8; 48];
    pt.serialize_compressed(&mut bytes[..])
        .expect("G1 serialize failed");
    Ok(bytes)
}

/// Compute the compressed 96-byte BLS12-381 G2 point `scalar * base_point`.
pub fn g2_compressed_with_base(scalar: Fr, base_point_bytes: &[u8]) -> anyhow::Result<[u8; 96]> {
    use ark_serialize::CanonicalDeserialize;
    let base = ark_bls12_381::G2Affine::deserialize_compressed(base_point_bytes)
        .map_err(|e| anyhow::anyhow!("base_point G2 deserialize: {}", e))?;
    let pt: ark_bls12_381::G2Affine = (base * scalar).into_affine();
    let mut bytes = [0u8; 96];
    pt.serialize_compressed(&mut bytes[..])
        .expect("G2 serialize failed");
    Ok(bytes)
}

/// Group-aware variant: dispatches on scheme byte. Returns variable-length compressed bytes
/// (48 for G1, 96 for G2).
pub fn group_compressed_with_base(
    scheme: u8,
    scalar: Fr,
    base_point_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match scheme {
        crate::session::SCHEME_BLS12381G1 => {
            Ok(g1_compressed_with_base(scalar, base_point_bytes)?.to_vec())
        }
        crate::session::SCHEME_BLS12381G2 => {
            Ok(g2_compressed_with_base(scalar, base_point_bytes)?.to_vec())
        }
        s => Err(anyhow::anyhow!("unsupported group scheme {}", s)),
    }
}

pub fn group_identity_compressed(scheme: u8) -> anyhow::Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;

    match scheme {
        crate::session::SCHEME_BLS12381G1 => {
            let pt: ark_bls12_381::G1Affine = ark_bls12_381::G1Projective::zero().into_affine();
            let mut bytes = vec![0u8; 48];
            pt.serialize_compressed(&mut bytes[..])
                .expect("G1 serialize failed");
            Ok(bytes)
        }
        crate::session::SCHEME_BLS12381G2 => {
            let pt: ark_bls12_381::G2Affine = ark_bls12_381::G2Projective::zero().into_affine();
            let mut bytes = vec![0u8; 96];
            pt.serialize_compressed(&mut bytes[..])
                .expect("G2 serialize failed");
            Ok(bytes)
        }
        s => Err(anyhow::anyhow!("unsupported group scheme {}", s)),
    }
}

pub fn group_add_compressed(
    scheme: u8,
    lhs_bytes: &[u8],
    rhs_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    match scheme {
        crate::session::SCHEME_BLS12381G1 => {
            let lhs = ark_bls12_381::G1Affine::deserialize_compressed(lhs_bytes)
                .map_err(|e| anyhow::anyhow!("lhs G1 deserialize: {}", e))?;
            let rhs = ark_bls12_381::G1Affine::deserialize_compressed(rhs_bytes)
                .map_err(|e| anyhow::anyhow!("rhs G1 deserialize: {}", e))?;
            let sum: ark_bls12_381::G1Affine = (lhs + rhs).into_affine();
            let mut bytes = vec![0u8; 48];
            sum.serialize_compressed(&mut bytes[..])
                .expect("G1 serialize failed");
            Ok(bytes)
        }
        crate::session::SCHEME_BLS12381G2 => {
            let lhs = ark_bls12_381::G2Affine::deserialize_compressed(lhs_bytes)
                .map_err(|e| anyhow::anyhow!("lhs G2 deserialize: {}", e))?;
            let rhs = ark_bls12_381::G2Affine::deserialize_compressed(rhs_bytes)
                .map_err(|e| anyhow::anyhow!("rhs G2 deserialize: {}", e))?;
            let sum: ark_bls12_381::G2Affine = (lhs + rhs).into_affine();
            let mut bytes = vec![0u8; 96];
            sum.serialize_compressed(&mut bytes[..])
                .expect("G2 serialize failed");
            Ok(bytes)
        }
        s => Err(anyhow::anyhow!("unsupported group scheme {}", s)),
    }
}

pub fn group_msm_compressed(
    scheme: u8,
    point_bytes: &[Vec<u8>],
    scalars: &[Fr],
) -> anyhow::Result<Vec<u8>> {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    if point_bytes.len() != scalars.len() {
        return Err(anyhow::anyhow!(
            "group_msm_compressed: points length {} != scalars length {}",
            point_bytes.len(),
            scalars.len()
        ));
    }
    if point_bytes.is_empty() {
        return Err(anyhow::anyhow!("group_msm_compressed: empty input"));
    }

    match scheme {
        crate::session::SCHEME_BLS12381G1 => {
            let mut acc = ark_bls12_381::G1Projective::zero();
            for (pt_bytes, scalar) in point_bytes.iter().zip(scalars.iter()) {
                let pt = ark_bls12_381::G1Affine::deserialize_compressed(pt_bytes.as_slice())
                    .map_err(|e| anyhow::anyhow!("G1 deserialize: {}", e))?;
                acc += pt * *scalar;
            }
            let affine: ark_bls12_381::G1Affine = acc.into_affine();
            let mut bytes = vec![0u8; 48];
            affine
                .serialize_compressed(&mut bytes[..])
                .expect("G1 serialize failed");
            Ok(bytes)
        }
        crate::session::SCHEME_BLS12381G2 => {
            let mut acc = ark_bls12_381::G2Projective::zero();
            for (pt_bytes, scalar) in point_bytes.iter().zip(scalars.iter()) {
                let pt = ark_bls12_381::G2Affine::deserialize_compressed(pt_bytes.as_slice())
                    .map_err(|e| anyhow::anyhow!("G2 deserialize: {}", e))?;
                acc += pt * *scalar;
            }
            let affine: ark_bls12_381::G2Affine = acc.into_affine();
            let mut bytes = vec![0u8; 96];
            affine
                .serialize_compressed(&mut bytes[..])
                .expect("G2 serialize failed");
            Ok(bytes)
        }
        s => Err(anyhow::anyhow!("unsupported group scheme {}", s)),
    }
}

pub fn pedersen_commit_compressed(
    scheme: u8,
    p: Fr,
    r: Fr,
    generator_g_bytes: &[u8],
    generator_h_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let p_g = group_compressed_with_base(scheme, p, generator_g_bytes)?;
    let r_h = group_compressed_with_base(scheme, r, generator_h_bytes)?;
    group_add_compressed(scheme, &p_g, &r_h)
}
