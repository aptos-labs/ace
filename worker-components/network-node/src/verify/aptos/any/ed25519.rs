// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `AnyPublicKey::Ed25519` / `AnySignature::Ed25519` proof-of-permission path.
//!
//! Same signature primitive as the legacy [`super::super::ed25519`] path
//! (Ed25519 over the pretty-message bytes), but the auth-key derivation is
//! the modern SingleKey one — `SHA3-256( BCS(AnyPublicKey::Ed25519(pk)) ||
//! 0x02 )` — so this account address is **different** from a bare-Ed25519
//! account using the same private key.
//!
//! Layered as:
//!   - [`verify_signature_only`] — pure signature crypto: parses pk + sig,
//!     binds `proof.full_message` to the request via
//!     [`super::super::super::DecryptionRequestPayload::to_pretty_message`],
//!     then Ed25519-verifies. No on-chain calls.
//!   - [`verify`] — single-key wrapper: composes `verify_signature_only`
//!     with the SingleKey auth-key check and the dapp ACL check, run in
//!     parallel via `tokio::join!`.
//!
//! The MultiKey path (`pk_scheme = 3`) will call `verify_signature_only`
//! directly per signing position and apply its own MultiKey-level auth-key
//! + ACL checks once at the wrapper level.

use anyhow::{anyhow, Result};
use ed25519_dalek::Verifier;

use super::super::super::BasicFlowRequest;
use super::super::{check_permission, is_valid_hex, AptosContractId, AptosProofOfPermission};
use super::{authentication_key, AnyPublicKeyInner};
use crate::ChainRpcConfig;

pub(super) async fn verify(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    any_pk: &AnyPublicKeyInner,
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| {
        anyhow!("verify_aptos_any_ed25519: pk must be 32 bytes, got {}", pk_bytes.len())
    })?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        anyhow!("verify_aptos_any_ed25519: sig must be 64 bytes, got {}", sig_bytes.len())
    })?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| anyhow!("verify_aptos_any_ed25519: invalid Ed25519 pubkey: {}", e))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // Cheap signature check first — fail fast before hitting RPC. Awaiting an
    // all-synchronous async fn is essentially free; the `.await` here doesn't
    // yield to the runtime, it just unwraps the immediately-ready future.
    verify_signature_only(req, proof, &vk, &sig).await?;

    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let (auth_result, perm_result) = tokio::join!(
        check_auth_key(proof, any_pk, rpc),
        check_permission(contract, &req.payload.domain, proof, rpc),
    );
    auth_result?;
    perm_result?;
    Ok(())
}

/// Ed25519 signature check for one signing position. Rebuilds the expected
/// pretty message from the request payload, confirms `proof.full_message` is
/// bound to it (with the AptosConnect-style hex tolerance), then
/// Ed25519-verifies the supplied signature over the (possibly hex-decoded)
/// message bytes.
///
/// Takes already-parsed `&VerifyingKey` / `&Signature` so the caller can
/// hoist the length-check and Edwards-decode out of the hot path — both the
/// single-key wrapper [`verify`] and the upcoming MultiKey dispatcher parse
/// at their own level and pass parsed primitives in.
///
/// `async` for shape uniformity with the keyless/federated-keyless paths
/// (which fetch chain-side inputs); this variant does no RPC.
///
/// **Not** included: SingleKey auth-key check or dapp ACL check. The
/// single-key wrapper [`verify`] adds both around this; the MultiKey path
/// applies its own equivalents once across all positions.
pub(in crate::verify::aptos) async fn verify_signature_only(
    req: &BasicFlowRequest,
    proof: &AptosProofOfPermission,
    vk: &ed25519_dalek::VerifyingKey,
    sig: &ed25519_dalek::Signature,
) -> Result<()> {
    let pretty_msg = req.payload.to_pretty_message()?;
    let pretty_msg_hex = hex::encode(pretty_msg.as_bytes());
    let full_msg = &proof.full_message;
    if !full_msg.contains(&pretty_msg) && !full_msg.contains(&pretty_msg_hex) {
        return Err(anyhow!(
            "verify_aptos_any_ed25519: fullMessage does not contain expected decryption request content"
        ));
    }
    let msg_bytes: Vec<u8> = if is_valid_hex(full_msg) {
        let stripped = full_msg.strip_prefix("0x").unwrap_or(full_msg.as_str());
        hex::decode(stripped)
            .map_err(|e| anyhow!("verify_aptos_any_ed25519: hex decode fullMessage: {}", e))?
    } else {
        full_msg.as_bytes().to_vec()
    };

    vk.verify(&msg_bytes, sig)
        .map_err(|e| anyhow!("verify_aptos_any_ed25519: Ed25519 verification failed: {}", e))
}

/// Checks that the on-chain `authentication_key` for `userAddr` equals
/// `SHA3-256( BCS(AnyPublicKey::Ed25519(pk)) || 0x02 )`.
///
/// Note this is **different** from the legacy `pk_scheme=0` path: bare
/// `Ed25519PublicKey` derives `SHA3-256(pk || 0x00)`, while the SingleKey
/// wrapping above prepends the AnyPublicKey variant tag (`0x00`) and the
/// length prefix (`0x20`) and uses `Scheme::SingleKey = 0x02` instead.
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
            "checkAuthKey: any/ed25519 auth key mismatch for {}",
            user_addr_str
        ));
    }
    Ok(())
}
