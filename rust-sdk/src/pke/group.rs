// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/pke/group.ts`: Ristretto255 elements/scalars used by ElGamal.
//! Both types store their raw 32 bytes (like the TS) and are BCS-encoded as `bytes` (ULEB
//! length prefix + 32 bytes).

use crate::error::{AceError, Result};
use crate::group::wire_via_serialize;
use crate::utils::rand_bytes;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use curve25519_dalek::traits::Identity;

/// A Ristretto255 point stored in compressed form (32 bytes).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Element {
    pub bytes: Vec<u8>,
}

impl Element {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn dummy() -> Self {
        Self::new(vec![0u8; 32])
    }

    pub fn from_inner(inner: RistrettoPoint) -> Self {
        Self::new(inner.compress().to_bytes().to_vec())
    }

    pub fn group_identity() -> Self {
        Self::from_inner(RistrettoPoint::identity())
    }

    /// Hash-to-curve of 64 random bytes (same one-way map as noble's `hashToCurve`).
    pub fn rand() -> Self {
        let rb: [u8; 64] = rand_bytes(64).try_into().expect("64 bytes");
        Self::from_inner(RistrettoPoint::from_uniform_bytes(&rb))
    }

    pub fn decode(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self::new(d.bytes()?))
    }

    pub fn encode(&self, s: &mut Serializer) {
        s.bytes(&self.bytes);
    }

    pub fn serialize(&self, s: &mut Serializer) {
        self.encode(s)
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Self::decode(d)
    }

    pub fn as_inner(&self) -> Result<RistrettoPoint> {
        let arr: [u8; 32] = self
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| AceError::crypto("ristretto255 element must be 32 bytes"))?;
        CompressedRistretto(arr)
            .decompress()
            .ok_or_else(|| AceError::crypto("invalid ristretto255 element encoding"))
    }

    pub fn add(&self, other: &Element) -> Result<Element> {
        Ok(Self::from_inner(self.as_inner()? + other.as_inner()?))
    }

    pub fn sub(&self, other: &Element) -> Result<Element> {
        Ok(Self::from_inner(self.as_inner()? - other.as_inner()?))
    }

    pub fn scale(&self, scalar: &Scalar) -> Result<Element> {
        if scalar.is_zero() {
            return Ok(Self::group_identity());
        }
        Ok(Self::from_inner(self.as_inner()? * scalar.as_dalek()?))
    }
}
wire_via_serialize!(Element);

/// A scalar mod the Ristretto255 group order, stored as 32 little-endian bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Scalar {
    pub bytes: Vec<u8>,
}

impl Scalar {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    fn from_dalek(s: DalekScalar) -> Self {
        Self::new(s.to_bytes().to_vec())
    }

    fn as_dalek(&self) -> Result<DalekScalar> {
        let arr: [u8; 32] = self
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| AceError::crypto("ristretto255 scalar must be 32 bytes"))?;
        Ok(DalekScalar::from_bytes_mod_order(arr))
    }

    pub fn dummy() -> Self {
        Self::new(vec![0u8; 32])
    }

    pub fn from_u64(x: u64) -> Self {
        let mut b = vec![0u8; 32];
        b[..8].copy_from_slice(&x.to_le_bytes());
        Self::new(b)
    }

    /// Interpret arbitrary-length LE bytes as an integer and reduce mod q.
    pub fn from_le_bytes_mod_q(bytes: &[u8]) -> Self {
        // Horner-style reduction over 8-byte limbs (most significant first) so any input
        // length is supported, exactly like the TS bigint `% Q`.
        let base = {
            let mut b = [0u8; 32];
            b[8] = 1; // 2^64
            DalekScalar::from_bytes_mod_order(b)
        };
        let mut acc = DalekScalar::ZERO;
        // Limbs are aligned from the low end; process most-significant limb first.
        for chunk in bytes.chunks(8).rev() {
            let mut limb = [0u8; 8];
            limb[..chunk.len()].copy_from_slice(chunk);
            acc = acc * base + DalekScalar::from(u64::from_le_bytes(limb));
        }
        Self::from_dalek(acc)
    }

    /// 64 random bytes reduced mod q; zero is mapped to one.
    pub fn rand() -> Self {
        let rb: [u8; 64] = rand_bytes(64).try_into().expect("64 bytes");
        let mut v = DalekScalar::from_bytes_mod_order_wide(&rb);
        if v == DalekScalar::ZERO {
            v = DalekScalar::ONE;
        }
        Self::from_dalek(v)
    }

    pub fn decode(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self::new(d.bytes()?))
    }

    pub fn encode(&self, s: &mut Serializer) {
        s.bytes(&self.bytes);
    }

    pub fn serialize(&self, s: &mut Serializer) {
        self.encode(s)
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Self::decode(d)
    }

    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|b| *b == 0)
    }

    pub fn add(&self, other: &Scalar) -> Result<Scalar> {
        Ok(Self::from_dalek(self.as_dalek()? + other.as_dalek()?))
    }

    pub fn sub(&self, other: &Scalar) -> Result<Scalar> {
        Ok(Self::from_dalek(self.as_dalek()? - other.as_dalek()?))
    }

    pub fn mul(&self, other: &Scalar) -> Result<Scalar> {
        Ok(Self::from_dalek(self.as_dalek()? * other.as_dalek()?))
    }

    pub fn neg(&self) -> Result<Scalar> {
        Ok(Self::from_dalek(-self.as_dalek()?))
    }
}
wire_via_serialize!(Scalar);

/// Naive multi-scalar multiplication: `sum_i bases[i] * scalars[i]`.
pub fn msm(bases: &[Element], scalars: &[Scalar]) -> Result<Element> {
    let mut acc = Element::group_identity();
    for (b, s) in bases.iter().zip(scalars.iter()) {
        acc = acc.add(&b.scale(s)?)?;
    }
    Ok(acc)
}

/// Mirrors TS `scalarFrom512BitHash`: the *first 32 bytes* (LE) reduced mod q, zero mapped to one.
/// (TS slices `hash[0..32]` before reducing, so this is deliberately NOT a wide reduction.)
pub fn scalar_from_512bit_hash(hash: &[u8; 64]) -> Scalar {
    let first: [u8; 32] = hash[..32].try_into().unwrap();
    let mut v = DalekScalar::from_bytes_mod_order(first);
    if v == DalekScalar::ZERO {
        v = DalekScalar::ONE;
    }
    Scalar::from_dalek(v)
}
