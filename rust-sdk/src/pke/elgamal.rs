// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/pke/elgamal.ts`: plain ElGamal over Ristretto255.

use super::group::{Element, Scalar};
use crate::error::Result;
use crate::wire::{Deserializer, Serializer};

/// BCS: `Element(c0) ++ Element(c1)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    pub c0: Element,
    pub c1: Element,
}

impl Ciphertext {
    pub fn new(c0: Element, c1: Element) -> Self {
        Self { c0, c1 }
    }

    pub fn decode(d: &mut Deserializer<'_>) -> Result<Self> {
        let c0 = Element::decode(d)?;
        let c1 = Element::decode(d)?;
        Ok(Self { c0, c1 })
    }

    pub fn encode(&self, s: &mut Serializer) {
        self.c0.encode(s);
        self.c1.encode(s);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut s = Serializer::new();
        self.encode(&mut s);
        s.into_bytes()
    }

    pub fn add(&self, other: &Ciphertext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.c0.add(&other.c0)?,
            self.c1.add(&other.c1)?,
        ))
    }

    pub fn scale(&self, scalar: &Scalar) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.c0.scale(scalar)?,
            self.c1.scale(scalar)?,
        ))
    }
}

/// BCS: `Element(enc_base) ++ Scalar(private_scalar)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecKey {
    pub enc_base: Element,
    pub private_scalar: Scalar,
}

impl DecKey {
    pub fn new(enc_base: Element, private_scalar: Scalar) -> Self {
        Self {
            enc_base,
            private_scalar,
        }
    }

    pub fn decode(d: &mut Deserializer<'_>) -> Result<Self> {
        let enc_base = Element::decode(d)?;
        let private_scalar = Scalar::decode(d)?;
        Ok(Self {
            enc_base,
            private_scalar,
        })
    }

    pub fn encode(&self, s: &mut Serializer) {
        self.enc_base.encode(s);
        self.private_scalar.encode(s);
    }
}

/// BCS: `Element(enc_base) ++ Element(public_point)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EncKey {
    pub enc_base: Element,
    pub public_point: Element,
}

impl EncKey {
    pub fn new(enc_base: Element, public_point: Element) -> Self {
        Self {
            enc_base,
            public_point,
        }
    }

    pub fn decode(d: &mut Deserializer<'_>) -> Result<Self> {
        let enc_base = Element::decode(d)?;
        let public_point = Element::decode(d)?;
        Ok(Self {
            enc_base,
            public_point,
        })
    }

    pub fn encode(&self, s: &mut Serializer) {
        self.enc_base.encode(s);
        self.public_point.encode(s);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut s = Serializer::new();
        self.encode(&mut s);
        s.into_bytes()
    }
}

/// `(enc_base * r, ptxt + public_point * r)`.
pub fn enc(ek: &EncKey, randomizer: &Scalar, ptxt: &Element) -> Result<Ciphertext> {
    Ok(Ciphertext::new(
        ek.enc_base.scale(randomizer)?,
        ptxt.add(&ek.public_point.scale(randomizer)?)?,
    ))
}

/// `c1 - c0 * sk`.
pub fn dec(dk: &DecKey, ciph: &Ciphertext) -> Result<Element> {
    let unblinder = ciph.c0.scale(&dk.private_scalar)?;
    ciph.c1.sub(&unblinder)
}

/// `sum_i ciphs[i] * scalars[i]` (component-wise).
pub fn multi_exp(ciphs: &[Ciphertext], scalars: &[Scalar]) -> Result<Ciphertext> {
    let mut acc = Ciphertext::new(Element::group_identity(), Element::group_identity());
    for (c, s) in ciphs.iter().zip(scalars.iter()) {
        acc = acc.add(&c.scale(s)?)?;
    }
    Ok(acc)
}
