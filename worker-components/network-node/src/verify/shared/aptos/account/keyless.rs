// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::super::cache::{
    fetch_cached_configuration, fetch_cached_groth16_vk, fetch_cached_system_rsa_jwk,
};
use super::super::{
    hooks::check_auth_key_bytes, message::verified_signed_message_bytes, AptosPayloadBinding,
    AptosProofOfPermission,
};
use crate::ChainRpcConfig;

pub(super) async fn verify_account_proof<P: AptosPayloadBinding>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    pk: &aptos_keyless_common::KeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let msg_bytes = verified_signed_message_bytes(payload, proof, "verify_keyless_signature")?;
    let computed = aptos_keyless_common::keyless_account_authentication_key(pk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, computed.as_ref(), "keyless", rpc).await?;
    verify_signature_for_message(chain_id, pk, sig, &msg_bytes, chain_rpc).await
}

pub(super) async fn verify_signature_for_message(
    chain_id: u8,
    pk: &aptos_keyless_common::KeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    msg_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    let header: aptos_keyless_common::types::JwtHeader = serde_json::from_str(&sig.jwt_header_json)
        .map_err(|e| anyhow!("verify_keyless_signature: parse jwt_header_json: {}", e))?;
    let (jwk_res, vk_res, cfg_res) = tokio::join!(
        fetch_cached_system_rsa_jwk(chain_id, rpc, &pk.iss_val, &header.kid),
        fetch_cached_groth16_vk(chain_id, rpc),
        fetch_cached_configuration(chain_id, rpc),
    );
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("verify_keyless_signature: system clock: {}", e))?
        .as_secs();
    aptos_keyless_common::verify_signature(
        pk,
        sig,
        msg_bytes,
        &jwk_res?,
        &vk_res?,
        &cfg_res?,
        now_unix_secs,
    )
    .map_err(|e| anyhow!("verify_keyless_signature: {}", e))
}
