// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::aptos_account_any::verify_signature_locally_or_defer_keyless;
use super::aptos_account_deferred::AnySignatureCheck;
use super::aptos_multi_key;
use super::{AptosPayloadBinding, AptosProofOfPermission};

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
