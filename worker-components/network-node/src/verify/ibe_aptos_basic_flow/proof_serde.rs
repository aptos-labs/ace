// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::constants::*;
use super::{any, multi_ed25519, multi_key};
use super::{AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial};

// `serde_bytes::ByteBuf` is what BCS uses to round-trip a `Vec<u8>` field
// (length-prefixed). We use it as the on-wire representation for the Ed25519
// pk / sig arms; the bytes are validated to length below.
impl<'de> serde::Deserialize<'de> for AptosProofOfPermission {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error as _, SeqAccess, Visitor};
        use std::fmt;

        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = AptosProofOfPermission;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an AptosProofOfPermission tuple")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let user_addr: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing user_addr"))?;
                let pk_scheme: u8 = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing pk_scheme"))?;
                let public_key = match pk_scheme {
                    PK_SCHEME_ED25519_WIRE => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Ed25519 public_key"))?;
                        let arr: [u8; 32] = bytes.into_vec().try_into().map_err(|v: Vec<u8>| {
                            A::Error::custom(format!(
                                "Ed25519 public_key must be 32 bytes, got {}",
                                v.len()
                            ))
                        })?;
                        AptosPublicKeyMaterial::Ed25519(arr)
                    }
                    PK_SCHEME_ANY_WIRE => {
                        let inner: any::AnyPublicKeyInner = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Any public_key"))?;
                        AptosPublicKeyMaterial::Any(inner)
                    }
                    PK_SCHEME_MULTI_ED25519_WIRE => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing MultiEd25519 public_key"))?;
                        let inner = multi_ed25519::MultiEd25519PublicKeyInner::from_flat_bytes(
                            bytes.as_ref(),
                        )
                        .map_err(A::Error::custom)?;
                        AptosPublicKeyMaterial::MultiEd25519(inner)
                    }
                    PK_SCHEME_MULTI_KEY_WIRE => {
                        let inner: multi_key::MultiKeyInner = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing MultiKey public_key"))?;
                        AptosPublicKeyMaterial::MultiKey(inner)
                    }
                    PK_SCHEME_KEYLESS_WIRE => {
                        let pk: aptos_keyless_common::KeylessPublicKey = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Keyless public_key"))?;
                        AptosPublicKeyMaterial::Keyless(pk)
                    }
                    PK_SCHEME_FEDERATED_KEYLESS_WIRE => {
                        let fpk: aptos_keyless_common::FederatedKeylessPublicKey =
                            seq.next_element()?.ok_or_else(|| {
                                A::Error::custom("missing FederatedKeyless public_key")
                            })?;
                        AptosPublicKeyMaterial::FederatedKeyless(fpk)
                    }
                    other => {
                        return Err(A::Error::custom(format!("unsupported pk_scheme {}", other)))
                    }
                };
                let sig_scheme: u8 = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing sig_scheme"))?;
                let signature = match sig_scheme {
                    SIG_SCHEME_ED25519_WIRE => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Ed25519 signature"))?;
                        let arr: [u8; 64] = bytes.into_vec().try_into().map_err(|v: Vec<u8>| {
                            A::Error::custom(format!(
                                "Ed25519 signature must be 64 bytes, got {}",
                                v.len()
                            ))
                        })?;
                        AptosSignatureMaterial::Ed25519(arr)
                    }
                    SIG_SCHEME_ANY_WIRE => {
                        let inner: any::AnySignatureInner = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Any signature"))?;
                        AptosSignatureMaterial::Any(inner)
                    }
                    SIG_SCHEME_MULTI_ED25519_WIRE => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing MultiEd25519 signature"))?;
                        let inner = multi_ed25519::MultiEd25519SignatureInner::from_flat_bytes(
                            bytes.as_ref(),
                        )
                        .map_err(A::Error::custom)?;
                        AptosSignatureMaterial::MultiEd25519(inner)
                    }
                    SIG_SCHEME_MULTI_KEY_WIRE => {
                        let inner: multi_key::MultiKeySigInner = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing MultiKey signature"))?;
                        AptosSignatureMaterial::MultiKey(inner)
                    }
                    SIG_SCHEME_KEYLESS_WIRE => {
                        let sig: aptos_keyless_common::KeylessSignature = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Keyless signature"))?;
                        AptosSignatureMaterial::Keyless(sig)
                    }
                    other => {
                        return Err(A::Error::custom(format!(
                            "unsupported sig_scheme {}",
                            other
                        )))
                    }
                };
                let full_message: String = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing full_message"))?;
                Ok(AptosProofOfPermission {
                    user_addr,
                    pk_scheme,
                    public_key,
                    sig_scheme,
                    signature,
                    full_message,
                })
            }
        }

        // BCS treats a struct as an n-tuple in its serde model; deserialize_tuple
        // is what `#[derive(Deserialize)]` would lower to here.
        d.deserialize_tuple(6, V)
    }
}

impl serde::Serialize for AptosProofOfPermission {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(6)?;
        t.serialize_element(&self.user_addr)?;
        t.serialize_element(&self.pk_scheme)?;
        match &self.public_key {
            AptosPublicKeyMaterial::Ed25519(arr) => {
                t.serialize_element(serde_bytes::Bytes::new(arr))?
            }
            AptosPublicKeyMaterial::Any(inner) => t.serialize_element(inner)?,
            AptosPublicKeyMaterial::MultiEd25519(inner) => {
                t.serialize_element(serde_bytes::Bytes::new(&inner.to_flat_bytes()))?
            }
            AptosPublicKeyMaterial::MultiKey(inner) => t.serialize_element(inner)?,
            AptosPublicKeyMaterial::Keyless(pk) => t.serialize_element(pk)?,
            AptosPublicKeyMaterial::FederatedKeyless(fpk) => t.serialize_element(fpk)?,
        }
        t.serialize_element(&self.sig_scheme)?;
        match &self.signature {
            AptosSignatureMaterial::Ed25519(arr) => {
                t.serialize_element(serde_bytes::Bytes::new(arr))?
            }
            AptosSignatureMaterial::Any(inner) => t.serialize_element(inner)?,
            AptosSignatureMaterial::MultiEd25519(inner) => {
                t.serialize_element(serde_bytes::Bytes::new(&inner.to_flat_bytes()))?
            }
            AptosSignatureMaterial::MultiKey(inner) => t.serialize_element(inner)?,
            AptosSignatureMaterial::Keyless(sig) => t.serialize_element(sig)?,
        }
        t.serialize_element(&self.full_message)?;
        t.end()
    }
}
