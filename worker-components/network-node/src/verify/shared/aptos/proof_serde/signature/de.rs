// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::de::{Error as _, SeqAccess, Visitor};
use std::fmt;

use super::super::super::constants::*;
use super::super::super::{multi_ed25519, AptosSignatureMaterial};
use super::super::bytes::{array, next};

impl<'de> serde::Deserialize<'de> for AptosSignatureMaterial {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        d.deserialize_tuple(2, SignatureVisitor)
    }
}

struct SignatureVisitor;

impl<'de> Visitor<'de> for SignatureVisitor {
    type Value = AptosSignatureMaterial;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an Aptos signature material tuple")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        match next(&mut seq, "missing sig_scheme")? {
            SIG_SCHEME_ED25519_WIRE => Ok(AptosSignatureMaterial::Ed25519(array(
                &mut seq,
                "Ed25519 signature",
            )?)),
            SIG_SCHEME_ANY_WIRE => Ok(AptosSignatureMaterial::Any(next(
                &mut seq,
                "missing Any signature",
            )?)),
            SIG_SCHEME_MULTI_ED25519_WIRE => multi_ed25519(&mut seq),
            SIG_SCHEME_MULTI_KEY_WIRE => Ok(AptosSignatureMaterial::MultiKey(next(
                &mut seq,
                "missing MultiKey signature",
            )?)),
            SIG_SCHEME_KEYLESS_WIRE => Ok(AptosSignatureMaterial::Keyless(next(
                &mut seq,
                "missing Keyless signature",
            )?)),
            other => Err(A::Error::custom(format!("unsupported sig_scheme {other}"))),
        }
    }
}

fn multi_ed25519<'de, A: SeqAccess<'de>>(seq: &mut A) -> Result<AptosSignatureMaterial, A::Error> {
    let raw: serde_bytes::ByteBuf = next(seq, "missing MultiEd25519 signature")?;
    let sig = multi_ed25519::MultiEd25519SignatureInner::from_flat_bytes(raw.as_ref())
        .map_err(A::Error::custom)?;
    Ok(AptosSignatureMaterial::MultiEd25519(sig))
}
