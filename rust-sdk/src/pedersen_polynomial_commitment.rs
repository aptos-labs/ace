// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/pedersen-polynomial-commitment/index.ts` (wire types only, as in TS).

use crate::error::Result;
use crate::group::{bls12381g1, bls12381g2, wire_via_serialize, Element, Scalar};
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

/// BCS: `Element(g) ++ Element(h)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicParams {
    pub generator_g: Element,
    pub generator_h: Element,
}

impl PublicParams {
    pub fn serialize(&self, s: &mut Serializer) {
        self.generator_g.serialize(s);
        self.generator_h.serialize(s);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            generator_g: Element::deserialize(d)?,
            generator_h: Element::deserialize(d)?,
        })
    }
}
wire_via_serialize!(PublicParams);

/// BCS: `uleb(len) ++ Element*`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitment {
    pub points: Vec<Element>,
}

impl Commitment {
    pub fn from_bls12381g1(inner: &bls12381g1::PcsCommitment) -> Self {
        Self {
            points: inner
                .v_values
                .iter()
                .map(|p| Element::Bls12381G1(*p))
                .collect(),
        }
    }
    pub fn from_bls12381g2(inner: &bls12381g2::PcsCommitment) -> Self {
        Self {
            points: inner
                .v_values
                .iter()
                .map(|p| Element::Bls12381G2(*p))
                .collect(),
        }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.uleb128(self.points.len() as u32);
        for p in &self.points {
            p.serialize(s);
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let n = d.vec_len()?;
        let mut points = Vec::with_capacity(n);
        for _ in 0..n {
            points.push(Element::deserialize(d)?);
        }
        Ok(Self { points })
    }
}
wire_via_serialize!(Commitment);

/// BCS: `u64(eval_position) ++ Scalar(p) ++ Scalar(r)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Opening {
    pub eval_position: u64,
    pub eval_value_p: Scalar,
    pub eval_value_r: Scalar,
}

impl Opening {
    pub fn serialize(&self, s: &mut Serializer) {
        s.u64(self.eval_position);
        self.eval_value_p.serialize(s);
        self.eval_value_r.serialize(s);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            eval_position: d.u64()?,
            eval_value_p: Scalar::deserialize(d)?,
            eval_value_r: Scalar::deserialize(d)?,
        })
    }
}
wire_via_serialize!(Opening);

/// BCS: `uleb(len) ++ Scalar* ++ Element(accumulator) ++ u64(next_eval_position)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DegreeCheckState {
    pub z_poly: Vec<Scalar>,
    pub accumulator: Element,
    pub next_eval_position: u64,
}

impl DegreeCheckState {
    pub fn serialize(&self, s: &mut Serializer) {
        s.uleb128(self.z_poly.len() as u32);
        for z in &self.z_poly {
            z.serialize(s);
        }
        self.accumulator.serialize(s);
        s.u64(self.next_eval_position);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let n = d.vec_len()?;
        let mut z_poly = Vec::with_capacity(n);
        for _ in 0..n {
            z_poly.push(Scalar::deserialize(d)?);
        }
        Ok(Self {
            z_poly,
            accumulator: Element::deserialize(d)?,
            next_eval_position: d.u64()?,
        })
    }
}
wire_via_serialize!(DegreeCheckState);
