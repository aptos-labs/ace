// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/group/bls12381fr.ts` (+ `lagrangeAtZero` from `vss/dealing.ts`).
//! Fr is the scalar field shared by G1 and G2.

pub use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::error::{AceError, Result};

/// 32-byte little-endian canonical encoding (`numberToBytesLE(s, 32)` in TS).
pub fn fr_to_le_bytes(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    f.serialize_compressed(&mut out[..]).expect("Fr serialize");
    out
}

/// Strict inverse of [`fr_to_le_bytes`]: rejects non-canonical values (`>= FR_MODULUS`).
pub fn fr_from_le_bytes(bytes: &[u8]) -> Result<Fr> {
    if bytes.len() != 32 {
        return Err(AceError::wire(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Fr::deserialize_compressed(bytes).map_err(|_| AceError::wire("value out of range"))
}

/// `frMod(bytesToNumberLE(bytes))`: reduce an arbitrary-length LE integer mod r.
pub fn fr_from_le_bytes_mod_order(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

pub fn fr_from_u64(v: u64) -> Fr {
    Fr::from(v)
}

/// Lagrange interpolation at x = 0 over Fr. Errors on empty input or duplicate x.
pub fn lagrange_at_zero(points: &[(Fr, Fr)]) -> Result<Fr> {
    if points.is_empty() {
        return Err(AceError::crypto("lagrangeAtZero: need at least one point"));
    }
    for i in 0..points.len() {
        for j in i + 1..points.len() {
            if points[i].0 == points[j].0 {
                return Err(AceError::crypto("lagrangeAtZero: duplicate x"));
            }
        }
    }
    let mut result = Fr::zero();
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut lambda = Fr::from(1u64);
        for (j, (xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            // lambda *= xj / (xj - xi)
            let denom = *xj - *xi;
            let inv = denom
                .inverse()
                .ok_or_else(|| AceError::crypto("lagrangeAtZero: zero denominator"))?;
            lambda *= *xj * inv;
        }
        result += *yi * lambda;
    }
    Ok(result)
}

/// Evaluate `coeffs[0] + coeffs[1] x + ...` at `x`.
pub fn eval_poly(coeffs: &[Fr], x: Fr) -> Fr {
    let mut y = Fr::zero();
    let mut x_pow = Fr::from(1u64);
    for c in coeffs {
        y += *c * x_pow;
        x_pow *= x;
    }
    y
}
