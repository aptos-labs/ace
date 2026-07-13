// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! BCS-mirror types for `ace::group::*` (the on-chain abstract group enums).
//!
//! Wire layouts mirror Move's `contracts/group/sources/group.move`. These types are used
//! by `bcs::from_bytes` / `bcs::to_bytes` to round-trip the on-chain `Scalar` and `Element`
//! values when fetching session state via the `get_session_bcs` view function.

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;

pub const SCHEME_BLS12381G1: u8 = 0;
pub const SCHEME_BLS12381G2: u8 = 1;

/// BCS mirror of `group_bls12381_{g1,g2}::PublicPoint`. Both variants wire-encode
/// as a single `Vec<u8>` (48 bytes for G1, 96 for G2); the scheme is carried by
/// the surrounding `BcsElement` enum tag.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BcsPublicPoint {
    pub point: Vec<u8>,
}

/// BCS mirror of `group::Element` enum (variant 0 = Bls12381G1, variant 1 = Bls12381G2).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum BcsElement {
    Bls12381G1(BcsPublicPoint),
    Bls12381G2(BcsPublicPoint),
}

impl BcsElement {
    /// Returns the underlying scheme byte (0 = G1, 1 = G2).
    pub fn scheme(&self) -> u8 {
        match self {
            BcsElement::Bls12381G1(_) => SCHEME_BLS12381G1,
            BcsElement::Bls12381G2(_) => SCHEME_BLS12381G2,
        }
    }

    /// Borrows the raw compressed point bytes (48 or 96, depending on scheme).
    pub fn point_bytes(&self) -> &[u8] {
        match self {
            BcsElement::Bls12381G1(p) => &p.point,
            BcsElement::Bls12381G2(p) => &p.point,
        }
    }

    pub fn from_scheme_and_bytes(scheme: u8, bytes: Vec<u8>) -> anyhow::Result<Self> {
        match scheme {
            SCHEME_BLS12381G1 => Ok(BcsElement::Bls12381G1(BcsPublicPoint { point: bytes })),
            SCHEME_BLS12381G2 => Ok(BcsElement::Bls12381G2(BcsPublicPoint { point: bytes })),
            s => Err(anyhow!("unsupported group scheme {}", s)),
        }
    }
}

/// BCS mirror of `group_bls12381_{g1,g2}::PrivateScalar`. Fr is shared between G1 and G2,
/// so both variants wire-encode the same 32-byte LE scalar.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BcsPrivateScalar {
    pub scalar: Vec<u8>, // 32-byte Fr scalar (LE)
}

/// BCS mirror of `group::Scalar` enum (variant 0 = Bls12381G1, variant 1 = Bls12381G2).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum BcsScalar {
    Bls12381G1(BcsPrivateScalar),
    Bls12381G2(BcsPrivateScalar),
}

impl BcsScalar {
    pub fn scheme(&self) -> u8 {
        match self {
            BcsScalar::Bls12381G1(_) => SCHEME_BLS12381G1,
            BcsScalar::Bls12381G2(_) => SCHEME_BLS12381G2,
        }
    }

    pub fn from_scheme_and_bytes(scheme: u8, bytes: Vec<u8>) -> anyhow::Result<Self> {
        match scheme {
            SCHEME_BLS12381G1 => Ok(BcsScalar::Bls12381G1(BcsPrivateScalar { scalar: bytes })),
            SCHEME_BLS12381G2 => Ok(BcsScalar::Bls12381G2(BcsPrivateScalar { scalar: bytes })),
            s => Err(anyhow!("unsupported group scheme {}", s)),
        }
    }

    pub fn scalar_bytes(&self) -> &[u8] {
        match self {
            BcsScalar::Bls12381G1(s) => &s.scalar,
            BcsScalar::Bls12381G2(s) => &s.scalar,
        }
    }

    pub fn to_le_bytes(&self) -> Result<[u8; 32]> {
        self.scalar_bytes()
            .try_into()
            .map_err(|_| anyhow!("scalar must be 32 bytes, got {}", self.scalar_bytes().len()))
    }
}

pub fn scalar_sum(scalars: &[BcsScalar]) -> Result<BcsScalar> {
    let first = scalars
        .first()
        .ok_or_else(|| anyhow!("scalar_sum: empty input"))?;
    let scheme = first.scheme();
    let mut acc = Fr::zero();
    for scalar in scalars {
        if scalar.scheme() != scheme {
            return Err(anyhow!(
                "scalar_sum: mixed schemes {} and {}",
                scheme,
                scalar.scheme()
            ));
        }
        acc += scalar_to_fr(scalar)?;
    }
    scalar_from_fr(scheme, acc)
}

pub fn scalar_linear_combination(terms: &[(BcsScalar, BcsScalar)]) -> Result<BcsScalar> {
    let first = terms
        .first()
        .ok_or_else(|| anyhow!("scalar_linear_combination: empty input"))?;
    let scheme = first.0.scheme();
    let mut acc = Fr::zero();
    for (value, coeff) in terms {
        if value.scheme() != scheme || coeff.scheme() != scheme {
            return Err(anyhow!(
                "scalar_linear_combination: mixed schemes value={} coeff={} expected={}",
                value.scheme(),
                coeff.scheme(),
                scheme
            ));
        }
        acc += scalar_to_fr(value)? * scalar_to_fr(coeff)?;
    }
    scalar_from_fr(scheme, acc)
}

pub fn scalar_lagrange_at_zero(points: &[(u64, BcsScalar)]) -> Result<BcsScalar> {
    let first = points
        .first()
        .ok_or_else(|| anyhow!("scalar_lagrange_at_zero: no points"))?;
    let scheme = first.1.scheme();
    let mut acc = Fr::zero();
    for (i, (x_i_raw, y_i)) in points.iter().enumerate() {
        if y_i.scheme() != scheme {
            return Err(anyhow!(
                "scalar_lagrange_at_zero: mixed schemes {} and {}",
                scheme,
                y_i.scheme()
            ));
        }
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
        acc += scalar_to_fr(y_i)? * numerator * denominator_inv;
    }
    scalar_from_fr(scheme, acc)
}

fn scalar_to_fr(scalar: &BcsScalar) -> Result<Fr> {
    Ok(Fr::from_le_bytes_mod_order(&scalar.to_le_bytes()?))
}

fn scalar_from_fr(scheme: u8, scalar: Fr) -> Result<BcsScalar> {
    match scheme {
        SCHEME_BLS12381G1 | SCHEME_BLS12381G2 => {
            BcsScalar::from_scheme_and_bytes(scheme, fr_to_le_bytes(scalar).to_vec())
        }
        s => Err(anyhow!("unsupported group scheme {}", s)),
    }
}

fn fr_to_le_bytes(scalar: Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    scalar
        .serialize_uncompressed(&mut bytes[..])
        .expect("Fr serialize failed");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(scheme: u8, value: u64) -> BcsScalar {
        scalar_from_fr(scheme, Fr::from(value)).unwrap()
    }

    #[test]
    fn scalar_sum_rejects_mixed_schemes() {
        let err =
            scalar_sum(&[scalar(SCHEME_BLS12381G1, 1), scalar(SCHEME_BLS12381G2, 2)]).unwrap_err();
        assert!(err.to_string().contains("mixed schemes"));
    }

    #[test]
    fn scalar_linear_combination_uses_scheme_tagged_scalars() {
        let terms = vec![
            (scalar(SCHEME_BLS12381G1, 10), scalar(SCHEME_BLS12381G1, 2)),
            (scalar(SCHEME_BLS12381G1, 20), scalar(SCHEME_BLS12381G1, 3)),
        ];
        assert_eq!(
            scalar_linear_combination(&terms)
                .unwrap()
                .to_le_bytes()
                .unwrap(),
            scalar(SCHEME_BLS12381G1, 80).to_le_bytes().unwrap()
        );
    }

    #[test]
    fn scalar_lagrange_at_zero_interpolates_constant_term() {
        let points = vec![
            (1, scalar(SCHEME_BLS12381G2, 10)),
            (2, scalar(SCHEME_BLS12381G2, 20)),
        ];
        assert_eq!(
            scalar_lagrange_at_zero(&points)
                .unwrap()
                .to_le_bytes()
                .unwrap(),
            scalar(SCHEME_BLS12381G2, 0).to_le_bytes().unwrap()
        );
    }
}
