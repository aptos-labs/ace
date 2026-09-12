// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/group/index.ts`: scheme-tagged scalars and elements over BLS12-381 G1/G2.

pub mod bls12381fr;
pub mod bls12381g1;
pub mod bls12381g2;
mod curve_macro;

use crate::error::{AceError, Result};
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

pub const SCHEME_BLS12381G1: u8 = 0;
pub const SCHEME_BLS12381G2: u8 = 1;

pub fn scheme_supported(scheme: u8) -> bool {
    scheme == SCHEME_BLS12381G1 || scheme == SCHEME_BLS12381G2
}

macro_rules! wire_via_serialize {
    ($t:ty) => {
        impl Wire for $t {
            fn to_bytes(&self) -> Vec<u8> {
                let mut s = Serializer::new();
                self.serialize(&mut s);
                s.into_bytes()
            }
            fn from_bytes(bytes: &[u8]) -> Result<Self> {
                from_bytes_exact(bytes, Self::deserialize)
            }
        }
    };
}
pub(crate) use wire_via_serialize;

/// BCS: `u8(scheme) ++ PrivateScalar`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scalar {
    Bls12381G1(bls12381g1::PrivateScalar),
    Bls12381G2(bls12381g2::PrivateScalar),
}

impl Scalar {
    pub fn scheme(&self) -> u8 {
        match self {
            Scalar::Bls12381G1(_) => SCHEME_BLS12381G1,
            Scalar::Bls12381G2(_) => SCHEME_BLS12381G2,
        }
    }
    pub fn as_bls12381g1(&self) -> Result<&bls12381g1::PrivateScalar> {
        match self {
            Scalar::Bls12381G1(s) => Ok(s),
            _ => Err(AceError::crypto("wrong scheme")),
        }
    }
    pub fn as_bls12381g2(&self) -> Result<&bls12381g2::PrivateScalar> {
        match self {
            Scalar::Bls12381G2(s) => Ok(s),
            _ => Err(AceError::crypto("wrong scheme")),
        }
    }
    /// The underlying Fr value (shared field for both schemes).
    pub fn fr(&self) -> bls12381fr::Fr {
        match self {
            Scalar::Bls12381G1(s) => s.scalar,
            Scalar::Bls12381G2(s) => s.scalar,
        }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme());
        match self {
            Scalar::Bls12381G1(x) => x.serialize(s),
            Scalar::Bls12381G2(x) => x.serialize(s),
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        match d.u8()? {
            SCHEME_BLS12381G1 => Ok(Scalar::Bls12381G1(bls12381g1::PrivateScalar::deserialize(
                d,
            )?)),
            SCHEME_BLS12381G2 => Ok(Scalar::Bls12381G2(bls12381g2::PrivateScalar::deserialize(
                d,
            )?)),
            s => Err(AceError::UnsupportedScheme(s)),
        }
    }
}
wire_via_serialize!(Scalar);

/// BCS: `u8(scheme) ++ PublicPoint`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Element {
    Bls12381G1(bls12381g1::PublicPoint),
    Bls12381G2(bls12381g2::PublicPoint),
}

impl Element {
    pub fn scheme(&self) -> u8 {
        match self {
            Element::Bls12381G1(_) => SCHEME_BLS12381G1,
            Element::Bls12381G2(_) => SCHEME_BLS12381G2,
        }
    }
    pub fn as_bls12381g1(&self) -> Result<&bls12381g1::PublicPoint> {
        match self {
            Element::Bls12381G1(p) => Ok(p),
            _ => Err(AceError::crypto("wrong scheme")),
        }
    }
    pub fn as_bls12381g2(&self) -> Result<&bls12381g2::PublicPoint> {
        match self {
            Element::Bls12381G2(p) => Ok(p),
            _ => Err(AceError::crypto("wrong scheme")),
        }
    }
    pub fn scale(&self, scalar: &Scalar) -> Result<Element> {
        match (self, scalar) {
            (Element::Bls12381G1(p), Scalar::Bls12381G1(s)) => Ok(Element::Bls12381G1(p.scale(s))),
            (Element::Bls12381G2(p), Scalar::Bls12381G2(s)) => Ok(Element::Bls12381G2(p.scale(s))),
            _ => Err(AceError::crypto(format!(
                "scale: scheme mismatch (element={}, scalar={})",
                self.scheme(),
                scalar.scheme()
            ))),
        }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme());
        match self {
            Element::Bls12381G1(x) => x.serialize(s),
            Element::Bls12381G2(x) => x.serialize(s),
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        match d.u8()? {
            SCHEME_BLS12381G1 => Ok(Element::Bls12381G1(bls12381g1::PublicPoint::deserialize(
                d,
            )?)),
            SCHEME_BLS12381G2 => Ok(Element::Bls12381G2(bls12381g2::PublicPoint::deserialize(
                d,
            )?)),
            s => Err(AceError::UnsupportedScheme(s)),
        }
    }
}
wire_via_serialize!(Element);

#[cfg(test)]
mod tests {
    use super::*;

    // Standard BLS12-381 generators in zcash compressed encoding (what noble/TS produce).
    const G1_GEN: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    const G2_GEN: &str = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

    #[test]
    fn generator_encoding_matches_ts() {
        assert_eq!(hex::encode(bls12381g1::generator().raw_bytes()), G1_GEN);
        assert_eq!(hex::encode(bls12381g2::generator().raw_bytes()), G2_GEN);
        // BCS wraps with a ULEB length prefix: 0x30 / 0x60.
        assert_eq!(bls12381g1::generator().to_hex(), format!("30{G1_GEN}"));
        assert_eq!(bls12381g2::generator().to_hex(), format!("60{G2_GEN}"));
        // tagged element: scheme byte first
        assert_eq!(
            Element::Bls12381G2(bls12381g2::generator()).to_hex(),
            format!("0160{G2_GEN}")
        );
    }

    #[test]
    fn point_roundtrip_and_scale() {
        let s = bls12381g1::sample();
        let p = bls12381g1::generator().scale(&s);
        let back = bls12381g1::PublicPoint::from_hex(&p.to_hex()).unwrap();
        assert_eq!(p, back);
        assert!(bls12381g1::PublicPoint::from_raw_bytes(&[0u8; 48]).is_err());
        let el = Element::Bls12381G1(p);
        assert_eq!(Element::from_bytes(&el.to_bytes()).unwrap(), el);
        assert!(el.scale(&Scalar::Bls12381G2(bls12381g2::sample())).is_err());
    }

    #[test]
    fn scalar_rejects_non_canonical() {
        // r itself, LE, is not canonical
        let r_le = "01000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73";
        let mut bytes = vec![0x20u8];
        bytes.extend(hex::decode(r_le).unwrap());
        assert!(bls12381g1::PrivateScalar::from_bytes(&bytes).is_err());
        let mut one = vec![0x20u8, 1u8];
        one.extend([0u8; 31]);
        assert_eq!(
            bls12381g1::PrivateScalar::from_bytes(&one).unwrap().scalar,
            bls12381fr::Fr::from(1u64)
        );
    }

    #[test]
    fn split_reconstruct() {
        let secret = bls12381g1::sample();
        let shares = bls12381g1::split(&bls12381fr::fr_to_le_bytes(&secret.scalar), 2, 3).unwrap();
        let idx = |i: usize| {
            (
                i as u64 + 1,
                bls12381g1::SecretShare::from_fr(bls12381fr::fr_from_le_bytes(&shares[i]).unwrap()),
            )
        };
        assert_eq!(bls12381g1::reconstruct(&[idx(0), idx(2)]).unwrap(), secret);
        assert_eq!(bls12381g1::reconstruct(&[idx(1), idx(2)]).unwrap(), secret);
        assert_ne!(bls12381g1::reconstruct(&[idx(1)]).unwrap(), secret);
        assert!(bls12381g1::reconstruct(&[idx(1), idx(1)]).is_err());
    }
}
