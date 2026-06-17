// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::super::super::{AptosPayloadBinding, AptosProofOfPermission};
use super::super::any::verify_signature_locally_or_defer_keyless;
use super::super::deferred::AnySignatureCheck;
use crate::verify::aptos::multi_key as aptos_multi_key;

pub(super) fn collect<'a, P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    mk: &'a aptos_multi_key::MultiKeyInner,
    ms: &'a aptos_multi_key::MultiKeySigInner,
) -> Result<Vec<AnySignatureCheck<'a>>> {
    let positions = aptos_multi_key::bitmap_iter_ones(&ms.bitmap).zip(ms.signatures.iter());
    let mut deferred = Vec::new();
    for (pos, sig) in positions {
        let pk = &mk.public_keys[pos];
        match verify_signature_locally_or_defer_keyless(payload, proof, pk, sig)? {
            AnySignatureCheck::VerifiedLocally => {}
            check => deferred.push(check),
        }
    }
    Ok(deferred)
}
