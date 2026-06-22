// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::de::{Error as _, SeqAccess};
use serde::Serialize;

use super::super::constants::*;
use super::super::{multi_ed25519, AptosPublicKeyMaterial};
use super::bytes::{array, next, serialize};

pub(super) fn deserialize_for_scheme<'de, A>(
    seq: &mut A,
    scheme: u8,
) -> Result<AptosPublicKeyMaterial, A::Error>
where
    A: SeqAccess<'de>,
{
    Ok(match scheme {
        PK_SCHEME_ED25519_WIRE => {
            AptosPublicKeyMaterial::Ed25519(array(seq, "Ed25519 public_key")?)
        }
        PK_SCHEME_ANY_WIRE => AptosPublicKeyMaterial::Any(next(seq, "missing Any public_key")?),
        PK_SCHEME_MULTI_ED25519_WIRE => {
            let raw: serde_bytes::ByteBuf = next(seq, "missing MultiEd25519 public_key")?;
            AptosPublicKeyMaterial::MultiEd25519(
                multi_ed25519::MultiEd25519PublicKeyInner::from_flat_bytes(raw.as_ref())
                    .map_err(A::Error::custom)?,
            )
        }
        PK_SCHEME_MULTI_KEY_WIRE => {
            AptosPublicKeyMaterial::MultiKey(next(seq, "missing MultiKey public_key")?)
        }
        PK_SCHEME_KEYLESS_WIRE => {
            AptosPublicKeyMaterial::Keyless(next(seq, "missing Keyless public_key")?)
        }
        PK_SCHEME_FEDERATED_KEYLESS_WIRE => AptosPublicKeyMaterial::FederatedKeyless(next(
            seq,
            "missing FederatedKeyless public_key",
        )?),
        other => return Err(A::Error::custom(format!("unsupported pk_scheme {other}"))),
    })
}

pub(in crate::verify::shared::aptos) fn serialize_public_key<S>(
    key: &AptosPublicKeyMaterial,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match key {
        AptosPublicKeyMaterial::Ed25519(arr) => serialize(arr, s),
        AptosPublicKeyMaterial::Any(inner) => inner.serialize(s),
        AptosPublicKeyMaterial::MultiEd25519(inner) => serialize(&inner.to_flat_bytes(), s),
        AptosPublicKeyMaterial::MultiKey(inner) => inner.serialize(s),
        AptosPublicKeyMaterial::Keyless(pk) => pk.serialize(s),
        AptosPublicKeyMaterial::FederatedKeyless(fpk) => fpk.serialize(s),
    }
}
