// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod challenge;
mod prehash;

use anyhow::{anyhow, Result};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};

use super::super::any::{AssertionSignature, WebAuthnAssertion};
use super::super::AptosPayloadBinding;
use super::deferred::AnySignatureCheck;

pub(super) fn verify_signature<'a, P: AptosPayloadBinding>(
    payload: &P,
    pk_bytes: &'a [u8],
    assertion: &'a WebAuthnAssertion,
) -> Result<AnySignatureCheck<'a>> {
    let vk = P256VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| anyhow!("verify_webauthn_signature: invalid Secp256r1 pubkey: {}", e))?;
    let sig = parse_signature(assertion)?;
    challenge::validate(payload, assertion)?;
    prehash::verify(&vk, &sig, assertion)?;
    Ok(AnySignatureCheck::VerifiedLocally)
}

fn parse_signature(assertion: &WebAuthnAssertion) -> Result<P256Signature> {
    let AssertionSignature::Secp256r1Ecdsa(sig_bytes) = &assertion.signature;
    if sig_bytes.len() != 64 {
        return Err(anyhow!(
            "verify_webauthn_signature: sig must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let sig = P256Signature::from_slice(sig_bytes).map_err(|e| {
        anyhow!(
            "verify_webauthn_signature: invalid Secp256r1 signature: {}",
            e
        )
    })?;
    if sig.normalize_s().is_some() {
        return Err(anyhow!(
            "verify_webauthn_signature: Secp256r1 signature has high s (malleable)"
        ));
    }
    Ok(sig)
}
