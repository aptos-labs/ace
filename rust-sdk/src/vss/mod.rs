// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/vss/index.ts`: scheme-tagged VSS types and the on-chain `Session` view.

pub mod dealing;

use crate::address::AccountAddress;
use crate::error::{AceError, Result};
use crate::group::{bls12381g1, bls12381g2, wire_via_serialize, Element, Scalar};
use crate::pedersen_polynomial_commitment::{
    Commitment as PcsCommitment, DegreeCheckState as PcsDegreeCheckState, Opening as PcsOpening,
    PublicParams as PcsPublicParams,
};
use crate::pke;
use crate::sigma_dlog_linear::Proof as SigmaDlogLinearProof;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

pub use crate::group::{SCHEME_BLS12381G1, SCHEME_BLS12381G2};
/// TS re-exports `group.Scalar` as `PrivateScalar` and `group.Element` as `PublicPoint`.
pub type PrivateScalar = Scalar;
pub type PublicPoint = Element;

pub fn sample(scheme: u8) -> Result<Scalar> {
    match scheme {
        SCHEME_BLS12381G1 => Ok(Scalar::Bls12381G1(bls12381g1::sample())),
        SCHEME_BLS12381G2 => Ok(Scalar::Bls12381G2(bls12381g2::sample())),
        s => Err(AceError::UnsupportedScheme(s)),
    }
}
pub fn sample_bls12381g1() -> Scalar {
    Scalar::Bls12381G1(bls12381g1::sample())
}
pub fn sample_bls12381g2() -> Scalar {
    Scalar::Bls12381G2(bls12381g2::sample())
}

/// BCS: `u8(scheme) ++ inner SecretShare`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecretShare {
    Bls12381G1(bls12381g1::SecretShare),
    Bls12381G2(bls12381g2::SecretShare),
}

impl SecretShare {
    pub fn scheme(&self) -> u8 {
        match self {
            SecretShare::Bls12381G1(_) => SCHEME_BLS12381G1,
            SecretShare::Bls12381G2(_) => SCHEME_BLS12381G2,
        }
    }
    pub fn add(&self, other: &SecretShare) -> Result<SecretShare> {
        match (self, other) {
            (SecretShare::Bls12381G1(a), SecretShare::Bls12381G1(b)) => {
                Ok(SecretShare::Bls12381G1(a.add(b)))
            }
            (SecretShare::Bls12381G2(a), SecretShare::Bls12381G2(b)) => {
                Ok(SecretShare::Bls12381G2(a.add(b)))
            }
            _ => Err(AceError::crypto("add: scheme mismatch")),
        }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme());
        match self {
            SecretShare::Bls12381G1(x) => x.serialize(s),
            SecretShare::Bls12381G2(x) => x.serialize(s),
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        match d.u8()? {
            SCHEME_BLS12381G1 => Ok(SecretShare::Bls12381G1(
                bls12381g1::SecretShare::deserialize(d)?,
            )),
            SCHEME_BLS12381G2 => Ok(SecretShare::Bls12381G2(
                bls12381g2::SecretShare::deserialize(d)?,
            )),
            s => Err(AceError::UnsupportedScheme(s)),
        }
    }
}
wire_via_serialize!(SecretShare);

/// Reconstruct a secret from `(index, share)` pairs (all shares must share a scheme).
pub fn reconstruct(indexed_shares: &[(u64, SecretShare)]) -> Result<Scalar> {
    let first = indexed_shares
        .first()
        .ok_or(AceError::InsufficientShares { need: 1, got: 0 })?;
    macro_rules! collect {
        ($variant:ident, $m:ident) => {{
            let v: Result<Vec<_>> = indexed_shares
                .iter()
                .map(|(i, s)| match s {
                    SecretShare::$variant(x) => Ok((*i, *x)),
                    _ => Err(AceError::crypto("reconstruct: scheme mismatch")),
                })
                .collect();
            Ok(Scalar::$variant($m::reconstruct(&v?)?))
        }};
    }
    match first.1 {
        SecretShare::Bls12381G1(_) => collect!(Bls12381G1, bls12381g1),
        SecretShare::Bls12381G2(_) => collect!(Bls12381G2, bls12381g2),
    }
}

/// BCS: `PcsOpening` (the share is `opening.eval_value_p`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateShareMessage {
    pub opening: PcsOpening,
}

impl PrivateShareMessage {
    pub fn share(&self) -> Scalar {
        self.opening.eval_value_p
    }
    pub fn serialize(&self, s: &mut Serializer) {
        self.opening.serialize(s);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            opening: PcsOpening::deserialize(d)?,
        })
    }
}
wire_via_serialize!(PrivateShareMessage);

/// BCS: `u8(scheme) ++ inner DealerState`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DealerState {
    Bls12381G1(bls12381g1::DealerState),
    Bls12381G2(bls12381g2::DealerState),
}

impl DealerState {
    pub fn scheme(&self) -> u8 {
        match self {
            DealerState::Bls12381G1(_) => SCHEME_BLS12381G1,
            DealerState::Bls12381G2(_) => SCHEME_BLS12381G2,
        }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme());
        match self {
            DealerState::Bls12381G1(x) => x.serialize(s),
            DealerState::Bls12381G2(x) => x.serialize(s),
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        match d.u8()? {
            SCHEME_BLS12381G1 => Ok(DealerState::Bls12381G1(
                bls12381g1::DealerState::deserialize(d)?,
            )),
            SCHEME_BLS12381G2 => Ok(DealerState::Bls12381G2(
                bls12381g2::DealerState::deserialize(d)?,
            )),
            s => Err(AceError::UnsupportedScheme(s)),
        }
    }
}
wire_via_serialize!(DealerState);

fn read_option<T>(
    d: &mut Deserializer<'_>,
    what: &str,
    f: impl FnOnce(&mut Deserializer<'_>) -> Result<T>,
) -> Result<Option<T>> {
    match d.u8()? {
        0 => Ok(None),
        1 => Ok(Some(f(d)?)),
        t => Err(AceError::wire(format!(
            "{what} option tag must be 0 or 1, got {t}"
        ))),
    }
}

fn write_option<T>(s: &mut Serializer, v: &Option<T>, f: impl FnOnce(&T, &mut Serializer)) {
    match v {
        None => {
            s.u8(0);
        }
        Some(x) => {
            s.u8(1);
            f(x, s);
        }
    }
}

fn read_vec<T>(
    d: &mut Deserializer<'_>,
    mut f: impl FnMut(&mut Deserializer<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let n = d.vec_len()?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(f(d)?);
    }
    Ok(v)
}

/// BCS: `PcsCommitment ++ vec<pke::Ciphertext> ++ option<pke::Ciphertext> ++ option<SigmaProof>`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DealerContribution0 {
    pub sharing_poly_commitment: PcsCommitment,
    pub private_share_messages: Vec<pke::Ciphertext>,
    pub dealer_state: Option<pke::Ciphertext>,
    pub consistency_proof: Option<SigmaDlogLinearProof>,
}

impl DealerContribution0 {
    pub fn serialize(&self, s: &mut Serializer) {
        self.sharing_poly_commitment.serialize(s);
        s.uleb128(self.private_share_messages.len() as u32);
        for c in &self.private_share_messages {
            c.serialize(s);
        }
        write_option(s, &self.dealer_state, |c, s| c.serialize(s));
        write_option(s, &self.consistency_proof, |p, s| p.serialize(s));
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            sharing_poly_commitment: PcsCommitment::deserialize(d)?,
            private_share_messages: read_vec(d, pke::Ciphertext::deserialize)?,
            dealer_state: read_option(d, "dealerState", pke::Ciphertext::deserialize)?,
            consistency_proof: read_option(
                d,
                "consistencyProof",
                SigmaDlogLinearProof::deserialize,
            )?,
        })
    }
}
wire_via_serialize!(DealerContribution0);

/// BCS: `vec<option<PcsOpening>> ++ vec<Element> ++ vec<option<SigmaProof>>`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DealerContribution1 {
    pub shares_to_reveal: Vec<Option<PcsOpening>>,
    pub public_keys: Vec<Element>,
    pub public_key_proofs: Vec<Option<SigmaDlogLinearProof>>,
}

impl DealerContribution1 {
    pub fn serialize(&self, s: &mut Serializer) {
        s.uleb128(self.shares_to_reveal.len() as u32);
        for o in &self.shares_to_reveal {
            write_option(s, o, |x, s| x.serialize(s));
        }
        s.uleb128(self.public_keys.len() as u32);
        for e in &self.public_keys {
            e.serialize(s);
        }
        s.uleb128(self.public_key_proofs.len() as u32);
        for p in &self.public_key_proofs {
            write_option(s, p, |x, s| x.serialize(s));
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            shares_to_reveal: read_vec(d, |d| {
                read_option(d, "sharesToReveal[i]", PcsOpening::deserialize)
            })?,
            public_keys: read_vec(d, Element::deserialize)?,
            public_key_proofs: read_vec(d, |d| {
                read_option(d, "publicKeyProofs[i]", SigmaDlogLinearProof::deserialize)
            })?,
        })
    }
}
wire_via_serialize!(DealerContribution1);

pub const STATE_SUCCESS: u8 = 3;

/// On-chain VSS session view. `public_keys[0]` is the result pk, the rest are share pks.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Session {
    pub dealer: AccountAddress,
    pub share_holders: Vec<AccountAddress>,
    pub threshold: u64,
    pub base_point: Element,
    pub previous_public_key: Option<Element>,
    pub pcs_context: PcsPublicParams,
    pub state_code: u8,
    pub deal_time_micros: u64,
    pub dealer_contribution0: Option<DealerContribution0>,
    pub dealer_commitment_check: PcsDegreeCheckState,
    pub share_holder_acks: Vec<bool>,
    pub dealer_contribution1: Option<DealerContribution1>,
    pub next_public_key_to_verify: u64,
    pub public_keys: Vec<Element>,
}

impl Session {
    pub fn is_completed(&self) -> bool {
        self.state_code == STATE_SUCCESS
    }
    pub fn result_pk(&self) -> Option<&Element> {
        self.public_keys.first()
    }
    pub fn share_pks(&self) -> &[Element] {
        self.public_keys.get(1..).unwrap_or(&[])
    }
}

impl Session {
    pub fn serialize(&self, s: &mut Serializer) {
        self.dealer.serialize(s);
        s.uleb128(self.share_holders.len() as u32);
        for a in &self.share_holders {
            a.serialize(s);
        }
        s.u64(self.threshold);
        self.base_point.serialize(s);
        write_option(s, &self.previous_public_key, |e, s| e.serialize(s));
        self.pcs_context.serialize(s);
        s.u8(self.state_code);
        s.u64(self.deal_time_micros);
        write_option(s, &self.dealer_contribution0, |c, s| c.serialize(s));
        self.dealer_commitment_check.serialize(s);
        s.uleb128(self.share_holder_acks.len() as u32);
        for b in &self.share_holder_acks {
            s.bool(*b);
        }
        write_option(s, &self.dealer_contribution1, |c, s| c.serialize(s));
        s.u64(self.next_public_key_to_verify);
        s.uleb128(self.public_keys.len() as u32);
        for e in &self.public_keys {
            e.serialize(s);
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            dealer: AccountAddress::deserialize(d)?,
            share_holders: read_vec(d, AccountAddress::deserialize)?,
            threshold: d.u64()?,
            base_point: Element::deserialize(d)?,
            previous_public_key: read_option(d, "previousPublicKey", Element::deserialize)?,
            pcs_context: PcsPublicParams::deserialize(d)?,
            state_code: d.u8()?,
            deal_time_micros: d.u64()?,
            dealer_contribution0: read_option(
                d,
                "dealerContribution0",
                DealerContribution0::deserialize,
            )?,
            dealer_commitment_check: PcsDegreeCheckState::deserialize(d)?,
            share_holder_acks: read_vec(d, |d| d.bool())?,
            dealer_contribution1: read_option(
                d,
                "dealerContribution1",
                DealerContribution1::deserialize,
            )?,
            next_public_key_to_verify: d.u64()?,
            public_keys: read_vec(d, Element::deserialize)?,
        })
    }
}
wire_via_serialize!(Session);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrip() {
        let g = Element::Bls12381G2(bls12381g2::generator());
        let sc = Scalar::Bls12381G2(bls12381g2::sample());
        let opening = PcsOpening {
            eval_position: 1,
            eval_value_p: sc,
            eval_value_r: sc,
        };
        let dk = pke::keygen(pke::DEFAULT_SCHEME).unwrap();
        let ct = pke::encrypt(&pke::derive_encryption_key(&dk), b"x").unwrap();
        let sess = Session {
            dealer: AccountAddress::ONE,
            share_holders: vec![AccountAddress::ONE, AccountAddress::ZERO],
            threshold: 2,
            base_point: g,
            previous_public_key: None,
            pcs_context: PcsPublicParams {
                generator_g: g,
                generator_h: g,
            },
            state_code: STATE_SUCCESS,
            deal_time_micros: 42,
            dealer_contribution0: Some(DealerContribution0 {
                sharing_poly_commitment: PcsCommitment { points: vec![g, g] },
                private_share_messages: vec![ct.clone(), ct],
                dealer_state: None,
                consistency_proof: Some(SigmaDlogLinearProof {
                    t_vals: vec![g],
                    z_vals: vec![sc],
                }),
            }),
            dealer_commitment_check: PcsDegreeCheckState {
                z_poly: vec![sc],
                accumulator: g,
                next_eval_position: 0,
            },
            share_holder_acks: vec![true, false],
            dealer_contribution1: Some(DealerContribution1 {
                shares_to_reveal: vec![None, Some(opening)],
                public_keys: vec![g],
                public_key_proofs: vec![None],
            }),
            next_public_key_to_verify: 3,
            public_keys: vec![g, g, g],
        };
        assert!(sess.is_completed());
        assert_eq!(sess.share_pks().len(), 2);
        let b = sess.to_bytes();
        assert_eq!(Session::from_bytes(&b).unwrap(), sess);
        assert!(Session::from_bytes(&b[..b.len() - 1]).is_err());
        let share = SecretShare::Bls12381G2(bls12381g2::SecretShare::from_fr(sc.fr()));
        assert_eq!(SecretShare::from_bytes(&share.to_bytes()).unwrap(), share);
    }
}
