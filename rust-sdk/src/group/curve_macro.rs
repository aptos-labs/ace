// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Generates the per-group module body shared by `bls12381g1.rs` and `bls12381g2.rs`
//! (the TS files are identical modulo G1/G2).

macro_rules! define_bls12381_group {
    ($proj:ty, $affine:ty, $point_len:expr, $name:literal) => {
        use ark_ec::{CurveGroup, Group};
        use ark_ff::Zero;
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        use crate::error::{AceError, Result};
        use crate::group::bls12381fr::{
            eval_poly, fr_from_le_bytes, fr_from_le_bytes_mod_order, fr_to_le_bytes,
            lagrange_at_zero, Fr,
        };
        use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

        pub const POINT_BYTES: usize = $point_len;

        use crate::group::wire_via_serialize;

        /// Canonical Fr scalar. BCS layout: `bytes(32-byte LE)`.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct PrivateScalar {
            pub scalar: Fr,
        }

        impl PrivateScalar {
            pub fn from_fr(scalar: Fr) -> Self {
                Self { scalar }
            }
            pub fn serialize(&self, s: &mut Serializer) {
                s.bytes(&fr_to_le_bytes(&self.scalar));
            }
            pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
                let b = d.bytes()?;
                Ok(Self {
                    scalar: fr_from_le_bytes(&b)?,
                })
            }
        }
        wire_via_serialize!(PrivateScalar);

        pub fn generator() -> PublicPoint {
            PublicPoint {
                pt: <$proj>::generator(),
            }
        }

        /// Group element. BCS layout: `bytes(compressed point)` (zcash encoding, as noble).
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct PublicPoint {
            pub pt: $proj,
        }

        impl PublicPoint {
            pub fn from_raw_bytes(raw: &[u8]) -> Result<Self> {
                if raw.len() != POINT_BYTES {
                    return Err(AceError::wire(format!("expected {} bytes", POINT_BYTES)));
                }
                let affine = <$affine>::deserialize_compressed(raw)
                    .map_err(|_| AceError::crypto(concat!("invalid ", $name, " point")))?;
                Ok(Self { pt: affine.into() })
            }
            pub fn raw_bytes(&self) -> Vec<u8> {
                let mut out = Vec::with_capacity(POINT_BYTES);
                self.pt
                    .into_affine()
                    .serialize_compressed(&mut out)
                    .expect("point serialize");
                out
            }
            pub fn serialize(&self, s: &mut Serializer) {
                s.bytes(&self.raw_bytes());
            }
            pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
                Self::from_raw_bytes(&d.bytes()?)
            }
            pub fn scale(&self, scalar: &PrivateScalar) -> Self {
                Self {
                    pt: self.pt * scalar.scalar,
                }
            }
            pub fn add(&self, other: &Self) -> Self {
                Self {
                    pt: self.pt + other.pt,
                }
            }
            pub fn is_identity(&self) -> bool {
                self.pt.is_zero()
            }
        }
        wire_via_serialize!(PublicPoint);

        /// Share y = f(i) in Fr. BCS layout identical to [`PrivateScalar`].
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct SecretShare {
            pub y: Fr,
        }

        impl SecretShare {
            pub fn from_fr(y: Fr) -> Self {
                Self { y }
            }
            pub fn add(&self, other: &Self) -> Self {
                Self {
                    y: self.y + other.y,
                }
            }
            pub fn serialize(&self, s: &mut Serializer) {
                s.bytes(&fr_to_le_bytes(&self.y));
            }
            pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
                let b = d.bytes()?;
                Ok(Self {
                    y: fr_from_le_bytes(&b)?,
                })
            }
        }
        wire_via_serialize!(SecretShare);

        /// Feldman commitment `[g^{a_0}, ..., g^{a_{t-1}}]`. BCS: `uleb(len) ++ bytes(point)*`.
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub struct PcsCommitment {
            pub v_values: Vec<PublicPoint>,
        }

        impl PcsCommitment {
            pub fn serialize(&self, s: &mut Serializer) {
                s.uleb128(self.v_values.len() as u32);
                for p in &self.v_values {
                    p.serialize(s);
                }
            }
            pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
                let n = d.vec_len()?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(PublicPoint::deserialize(d)?);
                }
                Ok(Self { v_values: v })
            }
        }
        wire_via_serialize!(PcsCommitment);

        /// Dealer's polynomial. BCS: `u64(n) ++ uleb(len) ++ bytes(32-byte LE coef)*`.
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub struct DealerState {
            pub n: u64,
            pub coefs_poly_p: Vec<Fr>,
        }

        impl DealerState {
            pub fn serialize(&self, s: &mut Serializer) {
                s.u64(self.n);
                s.uleb128(self.coefs_poly_p.len() as u32);
                for c in &self.coefs_poly_p {
                    s.bytes(&fr_to_le_bytes(c));
                }
            }
            pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
                let n = d.u64()?;
                let len = d.vec_len()?;
                let mut coefs = Vec::with_capacity(len);
                for i in 0..len {
                    let b = d.bytes()?;
                    coefs.push(
                        fr_from_le_bytes(&b)
                            .map_err(|_| AceError::wire(format!("coefsPolyP[{i}]: bad scalar")))?,
                    );
                }
                Ok(Self {
                    n,
                    coefs_poly_p: coefs,
                })
            }
        }
        wire_via_serialize!(DealerState);

        /// Uniform scalar from 64 random bytes reduced mod r (as TS `sample()`).
        pub fn sample() -> PrivateScalar {
            let bytes = crate::utils::rand_bytes(64);
            PrivateScalar {
                scalar: fr_from_le_bytes_mod_order(&bytes),
            }
        }

        /// Lagrange-reconstruct the secret from `(index, share)` pairs (indices are 1-based x).
        pub fn reconstruct(indexed_shares: &[(u64, SecretShare)]) -> Result<PrivateScalar> {
            let pts: Vec<(Fr, Fr)> = indexed_shares
                .iter()
                .map(|(i, s)| (Fr::from(*i), s.y))
                .collect();
            Ok(PrivateScalar {
                scalar: lagrange_at_zero(&pts)?,
            })
        }

        /// Shamir-split `secret` (LE bytes, reduced mod r) into `total` 32-byte LE shares
        /// evaluated at x = 1..=total with a random degree-(threshold-1) polynomial.
        pub fn split(secret: &[u8], threshold: usize, total: usize) -> Result<Vec<[u8; 32]>> {
            if threshold < 1 || threshold > total {
                return Err(AceError::crypto("split: invalid threshold or total"));
            }
            let mut coeffs = vec![fr_from_le_bytes_mod_order(secret)];
            for _ in 1..threshold {
                coeffs.push(fr_from_le_bytes_mod_order(&crate::utils::rand_bytes(32)));
            }
            Ok((1..=total as u64)
                .map(|x| fr_to_le_bytes(&eval_poly(&coeffs, Fr::from(x))))
                .collect())
        }
    };
}

pub(crate) use define_bls12381_group;
