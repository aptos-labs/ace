// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::de::Error as _;
use serde::Deserialize;

pub(crate) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize;
    serde_bytes::Bytes::new(bytes).serialize(serializer)
}

pub(crate) fn fixed<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
    bytes
        .into_vec()
        .try_into()
        .map_err(|v: Vec<u8>| D::Error::custom(format!("expected {} bytes, got {}", N, v.len())))
}

pub(crate) mod fixed_32 {
    pub(crate) fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        super::serialize(value, serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        super::fixed(deserializer)
    }
}

pub(crate) mod fixed_64 {
    pub(crate) fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        super::serialize(value, serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        super::fixed(deserializer)
    }
}
