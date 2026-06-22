// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::ser::SerializeTuple;

use super::super::super::constants::*;
use super::super::super::AptosSignatureMaterial;
use super::super::bytes::serialize;

impl serde::Serialize for AptosSignatureMaterial {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut t = s.serialize_tuple(2)?;
        t.serialize_element(&self.scheme())?;
        match self {
            AptosSignatureMaterial::Ed25519(arr) => t.serialize_element(&Bytes(arr))?,
            AptosSignatureMaterial::Any(inner) => t.serialize_element(inner)?,
            AptosSignatureMaterial::MultiEd25519(inner) => {
                t.serialize_element(&Bytes(&inner.to_flat_bytes()))?
            }
            AptosSignatureMaterial::MultiKey(inner) => t.serialize_element(inner)?,
            AptosSignatureMaterial::Keyless(sig) => t.serialize_element(sig)?,
        }
        t.end()
    }
}

struct Bytes<'a>(&'a [u8]);

impl serde::Serialize for Bytes<'_> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize(self.0, s)
    }
}

impl AptosSignatureMaterial {
    fn scheme(&self) -> u8 {
        match self {
            AptosSignatureMaterial::Ed25519(_) => SIG_SCHEME_ED25519_WIRE,
            AptosSignatureMaterial::Any(_) => SIG_SCHEME_ANY_WIRE,
            AptosSignatureMaterial::MultiEd25519(_) => SIG_SCHEME_MULTI_ED25519_WIRE,
            AptosSignatureMaterial::MultiKey(_) => SIG_SCHEME_MULTI_KEY_WIRE,
            AptosSignatureMaterial::Keyless(_) => SIG_SCHEME_KEYLESS_WIRE,
        }
    }
}
