// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Federated-keyless proof-of-permission path for an `AptosProofOfPermission`.
//!
//! Identical to the regular [`super::keyless`] path except for:
//!   - The public key carries an extra `jwk_addr` (the dapp/issuer account
//!     where the federated JWK set is published).
//!   - JWK lookup tries `0x1::jwks::PatchedJWKs` first and only falls back to
//!     `jwk_addr::0x1::jwks::FederatedJWKs` on miss. This matches the VM —
//!     see [`keyless_validation::validate_authenticators`][permalink].
//!   - Auth-key derivation uses
//!     `AnyPublicKey::FederatedKeyless` (variant byte `0x04`) over the full
//!     `FederatedKeylessPublicKey` BCS body, not just the inner keyless PK.
//!
//! Everything else (Groth16 VK, `Configuration`, Poseidon hash, expiry checks,
//! training-wheels) is shared via [`super::keyless::fetch_groth16_vk`] /
//! [`super::keyless::fetch_configuration`] / [`super::keyless::fetch_system_rsa_jwk`]
//! and [`aptos_keyless_common::verify_signature`].
//!
//! [permalink]: https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/aptos-vm/src/keyless_validation.rs

use anyhow::{anyhow, Result};

use super::keyless::{fetch_configuration, fetch_groth16_vk, fetch_system_rsa_jwk};
use super::{
    check_basic_ace_hook, find_rsa_jwk_in_jwks_resource, is_valid_hex, AptosContractId,
    AptosProofOfPermission,
};
use super::super::BasicFlowRequest;
use crate::ChainRpcConfig;

pub(super) async fn verify(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    fpk: &aptos_keyless_common::FederatedKeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let (sig_res, auth_res, perm_res) = tokio::join!(
        verify_signature_only(req, contract, proof, fpk, sig, chain_rpc),
        check_auth_key(proof, fpk, rpc),
        check_basic_ace_hook(contract, &req.payload.domain, proof, rpc),
    );
    sig_res?;
    auth_res?;
    perm_res?;
    Ok(())
}

/// Federated-keyless signature verification only: pretty-message binding
/// + concurrent fetch of JWK (system PatchedJWKs first, federated
/// FederatedJWKs at `fpk.jwk_addr` on miss) + Groth16 VK + Configuration
/// + `aptos_keyless_common::verify_signature`.
///
/// Takes `contract` only to resolve chain-id → RPC client for fetches;
/// it is **not** used to drive any contract-level check (auth-key / ACL
/// are the caller's responsibility).
///
/// **Not** included: SingleKey auth-key check or dapp ACL check. The
/// single-key wrapper [`verify`] adds both around this; the MultiKey
/// path applies its own equivalents once across all positions.
pub(super) async fn verify_signature_only(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    fpk: &aptos_keyless_common::FederatedKeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    // 1. Same pretty-message + AptosConnect hex tolerance as the regular path.
    let pretty_msg = req.payload.to_pretty_message()?;
    let pretty_msg_hex = hex::encode(pretty_msg.as_bytes());
    let full_msg = &proof.full_message;
    if !full_msg.contains(&pretty_msg) && !full_msg.contains(&pretty_msg_hex) {
        return Err(anyhow!(
            "verify_aptos_federated_keyless: fullMessage does not contain expected decryption request content"
        ));
    }
    let msg_bytes: Vec<u8> = if is_valid_hex(full_msg) {
        let stripped = full_msg.strip_prefix("0x").unwrap_or(full_msg.as_str());
        hex::decode(stripped).map_err(|e| {
            anyhow!("verify_aptos_federated_keyless: hex decode fullMessage: {}", e)
        })?
    } else {
        full_msg.as_bytes().to_vec()
    };

    // 2. Fetch chain-side inputs in parallel. The single-key wrapper
    //    `verify` runs this concurrently with check_auth_key + check_basic_ace_hook,
    //    so net parallelism matches the pre-refactor 5-way fan-out (plus the
    //    sys+federated JWK pair already overlapped inside the fallback fn).
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let header: aptos_keyless_common::types::JwtHeader =
        serde_json::from_str(&sig.jwt_header_json).map_err(|e| {
            anyhow!("verify_aptos_federated_keyless: parse jwt_header_json: {}", e)
        })?;
    let (jwk_res, vk_res, cfg_res) = tokio::join!(
        fetch_jwk_with_federated_fallback(rpc, fpk, &header.kid),
        fetch_groth16_vk(rpc),
        fetch_configuration(rpc),
    );
    let jwk = jwk_res?;
    let vk = vk_res?;
    let cfg = cfg_res?;

    // 3. Wall-clock now. EPK expiry check inside verify_signature is `exp_date_secs > now`.
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("verify_aptos_federated_keyless: system clock: {}", e))?
        .as_secs();

    // The Groth16 + EPK signature checks run against the inner `KeylessPublicKey`;
    // the `jwk_addr` only influences JWK lookup and auth-key derivation.
    aptos_keyless_common::verify_signature(&fpk.pk, sig, &msg_bytes, &jwk, &vk, &cfg, now_unix_secs)
        .map_err(|e| anyhow!("verify_aptos_federated_keyless: {}", e))
}

/// Matches the on-chain VM behaviour: try `0x1::jwks::PatchedJWKs` first; on
/// miss, fall back to `0x1::jwks::FederatedJWKs` at `fpk.jwk_addr`.
pub(super) async fn fetch_jwk_with_federated_fallback(
    rpc: &vss_common::AptosRpc,
    fpk: &aptos_keyless_common::FederatedKeylessPublicKey,
    kid: &str,
) -> Result<aptos_keyless_common::RsaJwk> {
    // Issue both reads concurrently. Most of the time we only need the system
    // result, but for issuers the foundation doesn't manage (Auth0, Cognito,
    // etc.) the federated read is on the hot path — overlap the RTTs.
    let (sys_res, fed_res) = tokio::join!(
        fetch_system_rsa_jwk(rpc, &fpk.pk.iss_val, kid),
        fetch_federated_rsa_jwk(rpc, &fpk.jwk_addr, &fpk.pk.iss_val, kid),
    );
    if let Ok(jwk) = sys_res {
        return Ok(jwk);
    }
    fed_res.map_err(|e| {
        anyhow!(
            "fetch_jwk_with_federated_fallback: no JWK for iss={:?} kid={:?} (system miss + federated: {})",
            fpk.pk.iss_val, kid, e
        )
    })
}

/// Fetches the `RSA_JWK` for `(iss, kid)` from `0x1::jwks::FederatedJWKs`
/// published at the dapp-controlled `jwk_addr`.
async fn fetch_federated_rsa_jwk(
    rpc: &vss_common::AptosRpc,
    jwk_addr: &[u8; 32],
    iss: &str,
    kid: &str,
) -> Result<aptos_keyless_common::RsaJwk> {
    let addr = format!("0x{}", hex::encode(jwk_addr));
    let resource = rpc
        .get_account_resource(&addr, "0x1::jwks::FederatedJWKs")
        .await
        .map_err(|e| {
            anyhow!("fetch_federated_rsa_jwk: FederatedJWKs read at {}: {}", addr, e)
        })?;
    find_rsa_jwk_in_jwks_resource(&resource, iss, kid)?.ok_or_else(|| {
        anyhow!(
            "fetch_federated_rsa_jwk: no JWK at {} for iss={:?} kid={:?}",
            addr, iss, kid
        )
    })
}

/// Auth-key match for a federated-keyless account: the on-chain
/// `authentication_key` at `userAddr` must equal
/// `SHA3-256(0x04 || BCS(FederatedKeylessPublicKey) || 0x02)`.
async fn check_auth_key(
    proof: &AptosProofOfPermission,
    fpk: &aptos_keyless_common::FederatedKeylessPublicKey,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let computed = aptos_keyless_common::federated_keyless_account_authentication_key(fpk);

    let user_addr_str = format!("0x{}", hex::encode(proof.user_addr));
    let account = rpc
        .get_account(&user_addr_str)
        .await
        .map_err(|e| anyhow!("checkAuthKey: get_account {}: {}", user_addr_str, e))?;

    let onchain = hex::decode(account.authentication_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("checkAuthKey: parse onchain auth key: {}", e))?;

    if onchain.as_slice() != computed.as_ref() {
        return Err(anyhow!(
            "checkAuthKey: federated keyless auth key mismatch for {}",
            user_addr_str
        ));
    }

    Ok(())
}
