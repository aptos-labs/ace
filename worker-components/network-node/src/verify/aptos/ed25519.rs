// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Legacy Ed25519 proof-of-permission path for an `AptosProofOfPermission`.
//!
//! Checks, in order:
//!   1. `fullMessage` contains the pretty-printed
//!      [`DecryptionRequestPayload`][1] (or its hex encoding — AptosConnect
//!      wallets embed `hex(UTF-8(pretty_msg))` rather than the raw string).
//!   2. The Ed25519 signature over `fullMessage` verifies under the
//!      supplied public key.
//!   3. The pubkey's auth-key (`SHA3-256(pubkey || 0x00)`,
//!      [`Scheme::Ed25519`][2] preimage) matches the on-chain
//!      `authentication_key` for `userAddr`.
//!   4. The permission view returns `true` (handled by the shared
//!      `super::check_basic_ace_hook`).
//!
//! [1]: https://github.com/aptos-labs/ace/blob/main/ts-sdk/src/_internal/common.ts
//! [2]: https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/transaction/authenticator.rs#L522-L526

use anyhow::{anyhow, Result};

use super::{check_basic_ace_hook, is_valid_hex, AptosContractId, AptosProofOfPermission};
use crate::ChainRpcConfig;
use super::super::BasicFlowRequest;

pub(super) async fn verify(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    pk_bytes: &[u8; 32],
    sig_bytes: &[u8; 64],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes)
        .map_err(|e| anyhow!("verify_aptos: invalid Ed25519 pubkey: {}", e))?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);

    // verifySig is cheap and synchronous — fail fast before hitting RPC.
    verify_sig(req, proof, &vk, &sig)?;

    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;

    // auth-key and permission checks are independent RPC calls; run them concurrently.
    let (auth_result, perm_result) = tokio::join!(
        check_auth_key(proof, &vk, rpc),
        check_basic_ace_hook(contract, &req.payload.domain, proof, rpc),
    );
    auth_result?;
    perm_result?;

    Ok(())
}

/// Checks that `fullMessage` contains the decryption request's pretty-printed
/// representation (or its hex encoding, to handle AptosConnect wallets which
/// sign the hex of the UTF-8 bytes rather than the raw string), then verifies
/// the Ed25519 signature over the (possibly hex-decoded) message bytes.
fn verify_sig(
    req: &BasicFlowRequest,
    proof: &AptosProofOfPermission,
    vk: &ed25519_dalek::VerifyingKey,
    sig: &ed25519_dalek::Signature,
) -> Result<()> {
    use ed25519_dalek::Verifier;

    let pretty_msg = req.payload.to_pretty_message()?;
    // AptosConnect embeds hex(UTF-8(pretty_msg)) rather than the raw string.
    let pretty_msg_hex = hex::encode(pretty_msg.as_bytes());

    let full_msg = &proof.full_message;
    if !full_msg.contains(&pretty_msg) && !full_msg.contains(&pretty_msg_hex) {
        return Err(anyhow!(
            "verifySig: fullMessage does not contain expected decryption request content"
        ));
    }

    // Replicate `convertSigningMessage`: if fullMessage is not valid hex, sign/verify
    // over its UTF-8 bytes; otherwise hex-decode and use those bytes.
    let msg_bytes: Vec<u8> = if is_valid_hex(full_msg) {
        let stripped = full_msg.strip_prefix("0x").unwrap_or(full_msg.as_str());
        hex::decode(stripped)
            .map_err(|e| anyhow!("verifySig: hex decode fullMessage: {}", e))?
    } else {
        full_msg.as_bytes().to_vec()
    };

    vk.verify(&msg_bytes, sig)
        .map_err(|e| anyhow!("verifySig: Ed25519 verification failed: {}", e))?;

    Ok(())
}

/// Verifies that the Ed25519 public key's authentication key
/// `SHA3-256(pubkey || 0x00)` (`Scheme::Ed25519 = 0` preimage) matches the
/// on-chain `authentication_key` for `userAddr`.
///
/// Reference: [`AuthenticationKey::ed25519`](https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/transaction/authenticator.rs#L1001-L1003).
async fn check_auth_key(
    proof: &AptosProofOfPermission,
    vk: &ed25519_dalek::VerifyingKey,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    // For legacy Ed25519 (scheme=0): auth_key = SHA3-256(pubkey_bytes || 0x00)
    // This is identical to `vss_common::compute_account_address`.
    let computed = vss_common::compute_account_address(vk);

    let user_addr_str = format!("0x{}", hex::encode(proof.user_addr));
    let account = rpc
        .get_account(&user_addr_str)
        .await
        .map_err(|e| anyhow!("checkAuthKey: get_account {}: {}", user_addr_str, e))?;

    let onchain = hex::decode(account.authentication_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("checkAuthKey: parse onchain auth key: {}", e))?;

    if onchain.as_slice() != computed.as_ref() {
        return Err(anyhow!("checkAuthKey: auth key mismatch for {}", user_addr_str));
    }

    Ok(())
}
