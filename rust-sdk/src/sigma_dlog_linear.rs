// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/sigma-dlog-linear/index.ts` (proof wire type). The prover lives in the
//! worker components (`vss-common/src/sigma_dlog_linear.rs`) and is not part of the client SDK.

use crate::error::Result;
use crate::group::{wire_via_serialize, Element, Scalar};
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

/// BCS: `uleb(len) ++ Element* ++ uleb(len) ++ Scalar*`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof {
    pub t_vals: Vec<Element>,
    pub z_vals: Vec<Scalar>,
}

impl Proof {
    pub fn serialize(&self, s: &mut Serializer) {
        s.uleb128(self.t_vals.len() as u32);
        for t in &self.t_vals {
            t.serialize(s);
        }
        s.uleb128(self.z_vals.len() as u32);
        for z in &self.z_vals {
            z.serialize(s);
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let tn = d.vec_len()?;
        let mut t_vals = Vec::with_capacity(tn);
        for _ in 0..tn {
            t_vals.push(Element::deserialize(d)?);
        }
        let zn = d.vec_len()?;
        let mut z_vals = Vec::with_capacity(zn);
        for _ in 0..zn {
            z_vals.push(Scalar::deserialize(d)?);
        }
        Ok(Self { t_vals, z_vals })
    }
}
wire_via_serialize!(Proof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::bls12381g2;

    #[test]
    fn roundtrip() {
        let p = Proof {
            t_vals: vec![Element::Bls12381G2(bls12381g2::generator())],
            z_vals: vec![Scalar::Bls12381G2(bls12381g2::sample())],
        };
        assert_eq!(Proof::from_bytes(&p.to_bytes()).unwrap(), p);
    }
}
