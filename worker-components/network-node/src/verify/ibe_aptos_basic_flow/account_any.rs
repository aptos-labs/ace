// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::{
    account_any_local as local, account_deferred::AnySignatureCheck, account_webauthn as webauthn,
    any, AptosPayloadBinding, AptosProofOfPermission,
};

pub(super) use super::account_any_account::verify_account_proof;

pub(super) fn verify_signature_locally_or_defer_keyless<'a, P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    any_pk: &'a any::AnyPublicKeyInner,
    any_sig: &'a any::AnySignatureInner,
) -> Result<AnySignatureCheck<'a>> {
    match (any_pk, any_sig) {
        (any::AnyPublicKeyInner::Ed25519(pk), any::AnySignatureInner::Ed25519(sig)) => {
            local::verify_ed25519(payload, proof, pk, sig)
        }
        (
            any::AnyPublicKeyInner::Secp256k1Ecdsa(pk),
            any::AnySignatureInner::Secp256k1Ecdsa(sig),
        ) => local::verify_secp256k1(payload, proof, pk, sig),
        (any::AnyPublicKeyInner::Keyless(pk), any::AnySignatureInner::Keyless(sig)) => {
            Ok(AnySignatureCheck::DeferredKeyless { pk, sig })
        }
        (any::AnyPublicKeyInner::FederatedKeyless(fpk), any::AnySignatureInner::Keyless(sig)) => {
            Ok(AnySignatureCheck::DeferredFederatedKeyless { fpk, sig })
        }
        (
            any::AnyPublicKeyInner::Secp256r1Ecdsa(pk),
            any::AnySignatureInner::WebAuthn(assertion),
        ) => webauthn::verify_signature(payload, pk, assertion),
        (pk, sig) => Err(anyhow!(
            "verify_any_signature_only: invalid pk/sig pairing ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
    }
}
