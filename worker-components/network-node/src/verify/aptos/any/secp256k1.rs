// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `AnyPublicKey::Secp256k1Ecdsa` / `AnySignature::Secp256k1Ecdsa`
//! proof-of-permission path.
//!
//! Matches `aptos-crypto::secp256k1_ecdsa` verification semantics:
//!
//! - Public key: SEC1 — uncompressed 65 bytes (`0x04 || X || Y`) or compressed
//!   33 bytes. `libsecp256k1::PublicKey::parse_slice(..., None)` in aptos-core
//!   accepts both forms; `k256::ecdsa::VerifyingKey::from_sec1_bytes` does the
//!   same. The TS SDK normalises any compressed input to 65 bytes before
//!   serialising, so what arrives here is almost always uncompressed.
//! - Signature: 64-byte standard `r || s`, low-s normalised. High-s is rejected
//!   as malleable (matches aptos-core's `s.is_high() ⇒ Err` and the TS SDK's
//!   `{ lowS: true }` verify option).
//! - Message: pre-hashed with SHA3-256, then verified as a 32-byte digest
//!   (`bytes_to_message` in aptos-core; `sha3_256(...)` in the TS SDK).
//!
//! Auth-key derivation is the shared SingleKey one — `SHA3-256( BCS(
//! AnyPublicKey::Secp256k1Ecdsa(pk) ) || 0x02 )` — handled by
//! [`super::authentication_key`].

use anyhow::{anyhow, Result};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha3::{Digest, Sha3_256};

use super::super::super::BasicFlowRequest;
use super::super::{
    check_permission, is_valid_hex, pretty_message, AptosContractId, AptosProofOfPermission,
};
use super::{authentication_key, AnyPublicKeyInner};
use crate::ChainRpcConfig;

const SIG_LEN: usize = 64;

pub(super) async fn verify(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    any_pk: &AnyPublicKeyInner,
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    ephemeral_ek_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    if sig_bytes.len() != SIG_LEN {
        return Err(anyhow!(
            "verify_aptos_any_secp256k1: sig must be {} bytes, got {}",
            SIG_LEN,
            sig_bytes.len()
        ));
    }
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| anyhow!("verify_aptos_any_secp256k1: invalid pubkey: {}", e))?;
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|e| anyhow!("verify_aptos_any_secp256k1: invalid signature: {}", e))?;
    // `normalize_s` returns Some(normalized) when the original was high-s — we
    // reject that (matches `s.is_high() ⇒ Err` in aptos-core).
    if sig.normalize_s().is_some() {
        return Err(anyhow!(
            "verify_aptos_any_secp256k1: signature has high s (malleable); only low-s normalized signatures are accepted"
        ));
    }

    // Cheap synchronous check first — fail fast before hitting RPC.
    verify_sig(req, contract, proof, ephemeral_ek_bytes, &vk, &sig)?;

    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let (auth_result, perm_result) = tokio::join!(
        check_auth_key(proof, any_pk, rpc),
        check_permission(contract, &req.payload.domain, proof, rpc),
    );
    auth_result?;
    perm_result?;
    Ok(())
}

/// Mirrors [`super::ed25519::verify_sig`] but pre-hashes the message with
/// SHA3-256 before ECDSA verification (matching aptos-core's
/// `secp256k1_ecdsa::bytes_to_message`).
fn verify_sig(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    ephemeral_ek_bytes: &[u8],
    vk: &VerifyingKey,
    sig: &Signature,
) -> Result<()> {
    let pretty_msg = pretty_message(req, contract, ephemeral_ek_bytes);
    let pretty_msg_hex = hex::encode(pretty_msg.as_bytes());

    let full_msg = &proof.full_message;
    if !full_msg.contains(&pretty_msg) && !full_msg.contains(&pretty_msg_hex) {
        return Err(anyhow!(
            "verify_aptos_any_secp256k1: fullMessage does not contain expected decryption request content"
        ));
    }

    let msg_bytes: Vec<u8> = if is_valid_hex(full_msg) {
        let stripped = full_msg.strip_prefix("0x").unwrap_or(full_msg.as_str());
        hex::decode(stripped)
            .map_err(|e| anyhow!("verify_aptos_any_secp256k1: hex decode fullMessage: {}", e))?
    } else {
        full_msg.as_bytes().to_vec()
    };

    let prehash: [u8; 32] = Sha3_256::digest(&msg_bytes).into();
    vk.verify_prehash(&prehash, sig)
        .map_err(|e| anyhow!("verify_aptos_any_secp256k1: ECDSA verification failed: {}", e))?;
    Ok(())
}

/// Checks that the on-chain `authentication_key` for `userAddr` equals
/// `SHA3-256( BCS(AnyPublicKey::Secp256k1Ecdsa(pk)) || 0x02 )`. Same shape as
/// [`super::ed25519::check_auth_key`] — only the variant tag inside the BCS
/// preimage differs (`0x01` here vs `0x00` for `Ed25519`).
async fn check_auth_key(
    proof: &AptosProofOfPermission,
    any_pk: &AnyPublicKeyInner,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let computed = authentication_key(any_pk);

    let user_addr_str = format!("0x{}", hex::encode(proof.user_addr));
    let account = rpc
        .get_account(&user_addr_str)
        .await
        .map_err(|e| anyhow!("checkAuthKey: get_account {}: {}", user_addr_str, e))?;

    let onchain = hex::decode(account.authentication_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("checkAuthKey: parse onchain auth key: {}", e))?;

    if onchain.as_slice() != computed.as_ref() {
        return Err(anyhow!(
            "checkAuthKey: any/secp256k1 auth key mismatch for {}",
            user_addr_str
        ));
    }
    Ok(())
}
