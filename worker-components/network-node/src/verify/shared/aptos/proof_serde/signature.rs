// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::de::{Error as _, SeqAccess};
use serde::Serialize;

use super::super::constants::*;
use super::super::{multi_ed25519, AptosSignatureMaterial};
use super::bytes::{array, next, serialize};

pub(super) fn deserialize_for_scheme<'de, A>(
    seq: &mut A,
    scheme: u8,
) -> Result<AptosSignatureMaterial, A::Error>
where
    A: SeqAccess<'de>,
{
    Ok(match scheme {
        SIG_SCHEME_ED25519_WIRE => {
            AptosSignatureMaterial::Ed25519(array(seq, "Ed25519 signature")?)
        }
        SIG_SCHEME_ANY_WIRE => AptosSignatureMaterial::Any(next(seq, "missing Any signature")?),
        SIG_SCHEME_MULTI_ED25519_WIRE => {
            let raw: serde_bytes::ByteBuf = next(seq, "missing MultiEd25519 signature")?;
            AptosSignatureMaterial::MultiEd25519(
                multi_ed25519::MultiEd25519SignatureInner::from_flat_bytes(raw.as_ref())
                    .map_err(A::Error::custom)?,
            )
        }
        SIG_SCHEME_MULTI_KEY_WIRE => {
            AptosSignatureMaterial::MultiKey(next(seq, "missing MultiKey signature")?)
        }
        SIG_SCHEME_KEYLESS_WIRE => {
            AptosSignatureMaterial::Keyless(next(seq, "missing Keyless signature")?)
        }
        other => return Err(A::Error::custom(format!("unsupported sig_scheme {other}"))),
    })
}

pub(in crate::verify::shared::aptos) fn serialize_signature<S>(
    sig: &AptosSignatureMaterial,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match sig {
        AptosSignatureMaterial::Ed25519(arr) => serialize(arr, s),
        AptosSignatureMaterial::Any(inner) => inner.serialize(s),
        AptosSignatureMaterial::MultiEd25519(inner) => serialize(&inner.to_flat_bytes(), s),
        AptosSignatureMaterial::MultiKey(inner) => inner.serialize(s),
        AptosSignatureMaterial::Keyless(sig) => sig.serialize(s),
    }
}
