// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::{
    aptos_account_deferred::AnySignatureCheck, aptos_account_single::verify_ed25519_signature,
    AptosPayloadBinding, AptosProofOfPermission,
};

pub(super) fn verify_ed25519<'a, P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    pk_bytes: &'a [u8],
    sig_bytes: &'a [u8],
) -> Result<AnySignatureCheck<'a>> {
    let pk_arr = fixed_bytes::<32>(pk_bytes, "Ed25519 pk")?;
    let sig_arr = fixed_bytes::<64>(sig_bytes, "Ed25519 sig")?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| anyhow!("verify_any_signature_only: invalid Ed25519 pubkey: {}", e))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verify_ed25519_signature(payload, proof, &vk, &sig, "verify_any_signature_only")?;
    Ok(AnySignatureCheck::VerifiedLocally)
}

pub(super) fn verify_secp256k1<'a, P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    pk_bytes: &'a [u8],
    sig_bytes: &'a [u8],
) -> Result<AnySignatureCheck<'a>> {
    super::aptos_account_any_local_secp256k1::verify(payload, proof, pk_bytes, sig_bytes)
}

pub(super) fn fixed_bytes<const N: usize>(bytes: &[u8], label: &str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        anyhow!(
            "verify_any_signature_only: {} must be {} bytes, got {}",
            label,
            N,
            bytes.len()
        )
    })
}
