// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as K256Signature,
    VerifyingKey as K256VerifyingKey,
};
use sha3::{Digest, Sha3_256};

use super::aptos_hooks::check_auth_key_bytes;
use super::aptos_message::signed_message_bytes;
use super::{AptosPayloadBinding, AptosProofOfPermission};
use crate::ChainRpcConfig;

pub(super) async fn verify_ed25519_account_proof<P: AptosPayloadBinding>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    pk_bytes: &[u8; 32],
    sig_bytes: &[u8; 64],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes)
        .map_err(|e| anyhow!("verify_aptos_account_proof: invalid Ed25519 pubkey: {}", e))?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
    verify_ed25519_signature(payload, proof, &vk, &sig, "verify_aptos_account_proof")?;
    let computed = vss_common::compute_account_address(&vk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, computed.as_ref(), "ed25519", rpc).await
}

pub(super) fn verify_ed25519_signature<P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    vk: &ed25519_dalek::VerifyingKey,
    sig: &ed25519_dalek::Signature,
    context: &str,
) -> Result<()> {
    use ed25519_dalek::Verifier;

    let msg_bytes = signed_message_bytes(payload, proof, context)?;
    vk.verify(&msg_bytes, sig)
        .map_err(|e| anyhow!("{}: Ed25519 verification failed: {}", context, e))
}

pub(super) fn verify_secp256k1_signature<P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    vk: &K256VerifyingKey,
    sig: &K256Signature,
    context: &str,
) -> Result<()> {
    let msg_bytes = signed_message_bytes(payload, proof, context)?;
    let prehash: [u8; 32] = Sha3_256::digest(&msg_bytes).into();
    vk.verify_prehash(&prehash, sig)
        .map_err(|e| anyhow!("{}: Secp256k1 ECDSA verification failed: {}", context, e))
}
