// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::de::Error as _;
use serde::Deserialize;

use super::super::multi_ed25519::{MultiEd25519PublicKeyInner, MultiEd25519SignatureInner};

pub(crate) mod public_key {
    use super::*;

    pub(crate) fn serialize<S>(
        value: &MultiEd25519PublicKeyInner,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        super::super::bytes::serialize(&value.to_flat_bytes(), serializer)
    }

    pub(crate) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<MultiEd25519PublicKeyInner, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = serde_bytes::ByteBuf::deserialize(deserializer)?;
        MultiEd25519PublicKeyInner::from_flat_bytes(raw.as_ref()).map_err(D::Error::custom)
    }
}

pub(crate) mod signature {
    use super::*;

    pub(crate) fn serialize<S>(
        value: &MultiEd25519SignatureInner,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        super::super::bytes::serialize(&value.to_flat_bytes(), serializer)
    }

    pub(crate) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<MultiEd25519SignatureInner, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = serde_bytes::ByteBuf::deserialize(deserializer)?;
        MultiEd25519SignatureInner::from_flat_bytes(raw.as_ref()).map_err(D::Error::custom)
    }
}
