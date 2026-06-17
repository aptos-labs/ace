// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use k256::ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey};

use super::super::super::deferred::AnySignatureCheck;
use super::super::super::single::verify_secp256k1_signature;
use super::fixed_bytes;
use crate::verify::aptos::{AptosPayloadBinding, AptosProofOfPermission};

pub(super) fn verify<'a, P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    pk_bytes: &'a [u8],
    sig_bytes: &'a [u8],
) -> Result<AnySignatureCheck<'a>> {
    let vk = K256VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| anyhow!("verify_any_signature_only: invalid Secp256k1 pubkey: {}", e))?;
    let sig = parse_signature(sig_bytes)?;
    verify_secp256k1_signature(payload, proof, &vk, &sig, "verify_any_signature_only")?;
    Ok(AnySignatureCheck::VerifiedLocally)
}

fn parse_signature(sig_bytes: &[u8]) -> Result<K256Signature> {
    let sig_arr = fixed_bytes::<64>(sig_bytes, "Secp256k1 sig")?;
    let sig = K256Signature::from_slice(&sig_arr).map_err(|e| {
        anyhow!(
            "verify_any_signature_only: invalid Secp256k1 signature: {}",
            e
        )
    })?;
    if sig.normalize_s().is_some() {
        return Err(anyhow!(
            "verify_any_signature_only: Secp256k1 signature has high s (malleable)"
        ));
    }
    Ok(sig)
}
