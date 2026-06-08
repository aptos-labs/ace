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
//!
//! Layered as:
//!   - [`verify_signature_only`] — pure signature crypto over pre-parsed
//!     `&VerifyingKey` / `&Signature`. Binds `proof.full_message` to the
//!     request via [`super::super::super::DecryptionRequestPayload::to_pretty_message`].
//!     No on-chain calls.
//!   - [`verify`] — single-key wrapper: SEC1 + low-s parse, then
//!     `verify_signature_only` fast-fail, then `tokio::join!` over auth-key
//!     + dapp ACL.
//!
//! The MultiKey path calls [`verify_signature_only`] per signing position
//! and applies its own MultiKey-level auth-key + ACL checks once at the
//! wrapper level.

use anyhow::{anyhow, Result};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha3::{Digest, Sha3_256};

use super::super::super::BasicFlowRequest;
use super::super::{
    check_basic_ace_hook, is_valid_hex, AptosContractId, AptosPayloadBinding, AptosProofOfPermission,
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

    // Cheap signature check first — fail fast before hitting RPC.
    verify_signature_only(req, proof, &vk, &sig).await?;

    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let (auth_result, perm_result) = tokio::join!(
        check_auth_key(proof, any_pk, rpc),
        check_basic_ace_hook(contract, &req.payload.domain, proof, rpc),
    );
    auth_result?;
    perm_result?;
    Ok(())
}

/// Secp256k1 ECDSA signature check for one signing position. Rebuilds the
/// expected pretty message from the request payload, confirms
/// `proof.full_message` is bound to it (with AptosConnect-style hex
/// tolerance), then ECDSA-verifies `sig` under `vk` over the SHA3-256
/// digest of the (possibly hex-decoded) message bytes (matching aptos-core's
/// `secp256k1_ecdsa::bytes_to_message`).
///
/// Takes already-parsed `&VerifyingKey` / `&Signature` (with low-s already
/// checked) so the caller can hoist length-check + SEC1 decode + low-s
/// rejection out of the hot path. Both the single-key wrapper [`verify`]
/// and the upcoming MultiKey dispatcher parse at their own level and pass
/// parsed primitives in.
///
/// `async` for shape uniformity with the keyless/federated-keyless paths
/// (which fetch chain-side inputs); this variant does no RPC.
///
/// **Not** included: SingleKey auth-key check or dapp ACL check. The
/// single-key wrapper adds both around this; the MultiKey path applies
/// its own equivalents once across all positions.
pub(super) async fn verify_signature_only(
    req: &BasicFlowRequest,
    proof: &AptosProofOfPermission,
    vk: &VerifyingKey,
    sig: &Signature,
) -> Result<()> {
    let expected_hex = req.payload.to_signed_message_hex()?;
    let expected_hex_hex = hex::encode(expected_hex.as_bytes());

    let full_msg = &proof.full_message;
    if !full_msg.contains(&expected_hex) && !full_msg.contains(&expected_hex_hex) {
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
        .map_err(|e| anyhow!("verify_aptos_any_secp256k1: ECDSA verification failed: {}", e))
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
