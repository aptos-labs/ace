// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::de::{Error as _, SeqAccess, Visitor};
use std::fmt;

use super::super::super::constants::*;
use super::super::super::{multi_ed25519, AptosPublicKeyMaterial as Key};
use super::super::bytes::{array, next};

impl<'de> serde::Deserialize<'de> for Key {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        d.deserialize_tuple(2, PublicKeyVisitor)
    }
}

struct PublicKeyVisitor;

impl<'de> Visitor<'de> for PublicKeyVisitor {
    type Value = Key;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an Aptos public key")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        match next(&mut seq, "missing pk_scheme")? {
            PK_SCHEME_ED25519_WIRE => Ok(Key::Ed25519(array(&mut seq, "Ed25519 public_key")?)),
            PK_SCHEME_ANY_WIRE => Ok(Key::Any(next(&mut seq, "missing Any public_key")?)),
            PK_SCHEME_MULTI_ED25519_WIRE => multi_ed25519(&mut seq),
            PK_SCHEME_MULTI_KEY_WIRE => Ok(Key::MultiKey(next(
                &mut seq,
                "missing MultiKey public_key",
            )?)),
            PK_SCHEME_KEYLESS_WIRE => {
                Ok(Key::Keyless(next(&mut seq, "missing Keyless public_key")?))
            }
            PK_SCHEME_FEDERATED_KEYLESS_WIRE => Ok(Key::FederatedKeyless(next(
                &mut seq,
                "missing FederatedKeyless public_key",
            )?)),
            other => Err(A::Error::custom(format!("unsupported pk_scheme {other}"))),
        }
    }
}

fn multi_ed25519<'de, A: SeqAccess<'de>>(seq: &mut A) -> Result<Key, A::Error> {
    let raw: serde_bytes::ByteBuf = next(seq, "missing MultiEd25519 public_key")?;
    let key = multi_ed25519::MultiEd25519PublicKeyInner::from_flat_bytes(raw.as_ref())
        .map_err(A::Error::custom)?;
    Ok(Key::MultiEd25519(key))
}
