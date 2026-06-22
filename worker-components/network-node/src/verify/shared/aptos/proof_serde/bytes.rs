// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::de::{Error as _, SeqAccess};

pub(super) fn next<'de, A, T>(seq: &mut A, missing: &'static str) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: serde::Deserialize<'de>,
{
    seq.next_element()?.ok_or_else(|| A::Error::custom(missing))
}

pub(super) fn array<'de, const N: usize, A>(
    seq: &mut A,
    label: &'static str,
) -> Result<[u8; N], A::Error>
where
    A: SeqAccess<'de>,
{
    let bytes = seq
        .next_element::<serde_bytes::ByteBuf>()?
        .ok_or_else(|| A::Error::custom(format!("missing {label}")))?;
    bytes.into_vec().try_into().map_err(|v: Vec<u8>| {
        A::Error::custom(format!("{} must be {} bytes, got {}", label, N, v.len()))
    })
}

pub(super) fn serialize<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize;
    serde_bytes::Bytes::new(bytes).serialize(s)
}
