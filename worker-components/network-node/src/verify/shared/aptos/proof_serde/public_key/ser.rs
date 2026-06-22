// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::ser::SerializeTuple;

use super::super::super::constants::*;
use super::super::super::AptosPublicKeyMaterial;
use super::super::bytes::serialize;

impl serde::Serialize for AptosPublicKeyMaterial {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut t = s.serialize_tuple(2)?;
        t.serialize_element(&self.scheme())?;
        match self {
            AptosPublicKeyMaterial::Ed25519(arr) => t.serialize_element(&Bytes(arr))?,
            AptosPublicKeyMaterial::Any(inner) => t.serialize_element(inner)?,
            AptosPublicKeyMaterial::MultiEd25519(inner) => {
                t.serialize_element(&Bytes(&inner.to_flat_bytes()))?
            }
            AptosPublicKeyMaterial::MultiKey(inner) => t.serialize_element(inner)?,
            AptosPublicKeyMaterial::Keyless(pk) => t.serialize_element(pk)?,
            AptosPublicKeyMaterial::FederatedKeyless(fpk) => t.serialize_element(fpk)?,
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

impl AptosPublicKeyMaterial {
    fn scheme(&self) -> u8 {
        match self {
            AptosPublicKeyMaterial::Ed25519(_) => PK_SCHEME_ED25519_WIRE,
            AptosPublicKeyMaterial::Any(_) => PK_SCHEME_ANY_WIRE,
            AptosPublicKeyMaterial::MultiEd25519(_) => PK_SCHEME_MULTI_ED25519_WIRE,
            AptosPublicKeyMaterial::MultiKey(_) => PK_SCHEME_MULTI_KEY_WIRE,
            AptosPublicKeyMaterial::Keyless(_) => PK_SCHEME_KEYLESS_WIRE,
            AptosPublicKeyMaterial::FederatedKeyless(_) => PK_SCHEME_FEDERATED_KEYLESS_WIRE,
        }
    }
}
