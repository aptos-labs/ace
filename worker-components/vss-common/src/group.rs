// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! BCS-mirror types for `ace::group::*` (the on-chain abstract group enums).
//!
//! Wire layouts mirror Move's `contracts/group/sources/group.move`. These types are used
//! by `bcs::from_bytes` / `bcs::to_bytes` to round-trip the on-chain `Scalar` and `Element`
//! values when fetching session state via the `get_session_bcs` view function.

use anyhow::anyhow;

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
}
