// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod bytes;
mod public_key;
mod signature;

use serde::de::{SeqAccess, Visitor};
use std::fmt;

use super::AptosProofOfPermission;
use bytes::next;

pub(in crate::verify::shared::aptos) use public_key::serialize_public_key;
pub(in crate::verify::shared::aptos) use signature::serialize_signature;

impl<'de> serde::Deserialize<'de> for AptosProofOfPermission {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        d.deserialize_tuple(6, ProofVisitor)
    }
}

struct ProofVisitor;

impl<'de> Visitor<'de> for ProofVisitor {
    type Value = AptosProofOfPermission;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an AptosProofOfPermission tuple")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let user_addr = next(&mut seq, "missing user_addr")?;
        let pk_scheme = next(&mut seq, "missing pk_scheme")?;
        let public_key = public_key::deserialize_for_scheme(&mut seq, pk_scheme)?;
        let sig_scheme = next(&mut seq, "missing sig_scheme")?;
        let signature = signature::deserialize_for_scheme(&mut seq, sig_scheme)?;
        let full_message = next(&mut seq, "missing full_message")?;
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
