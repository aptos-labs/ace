// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod account;
mod local;

use anyhow::{anyhow, Result};

use super::super::{any as aptos_any, AptosPayloadBinding, AptosProofOfPermission};
use super::deferred::AnySignatureCheck;

pub(super) use account::verify_account_proof;

pub(super) fn verify_signature_locally_or_defer_keyless<'a, P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    any_pk: &'a aptos_any::AnyPublicKeyInner,
    any_sig: &'a aptos_any::AnySignatureInner,
) -> Result<AnySignatureCheck<'a>> {
    match (any_pk, any_sig) {
        (aptos_any::AnyPublicKeyInner::Ed25519(pk), aptos_any::AnySignatureInner::Ed25519(sig)) => {
            local::verify_ed25519(payload, proof, pk, sig)
        }
        (
            aptos_any::AnyPublicKeyInner::Secp256k1Ecdsa(pk),
            aptos_any::AnySignatureInner::Secp256k1Ecdsa(sig),
        ) => local::verify_secp256k1(payload, proof, pk, sig),
        (aptos_any::AnyPublicKeyInner::Keyless(pk), aptos_any::AnySignatureInner::Keyless(sig)) => {
            Ok(AnySignatureCheck::DeferredKeyless { pk, sig })
        }
        (
            aptos_any::AnyPublicKeyInner::FederatedKeyless(fpk),
            aptos_any::AnySignatureInner::Keyless(sig),
        ) => Ok(AnySignatureCheck::DeferredFederatedKeyless { fpk, sig }),
        (
            aptos_any::AnyPublicKeyInner::Secp256r1Ecdsa(pk),
            aptos_any::AnySignatureInner::WebAuthn(assertion),
        ) => super::webauthn::verify_signature(payload, pk, assertion),
        (pk, sig) => Err(anyhow!(
            "verify_any_signature_only: invalid pk/sig pairing ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
    }
}
