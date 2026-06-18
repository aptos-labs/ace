// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::aptos_account_deferred::verify_deferred_keyless_signature_for_message;
use super::aptos_hooks::check_auth_key_bytes;
use super::aptos_message::signed_message_bytes;
use super::aptos_multi_key;
use super::{AptosPayloadBinding, AptosProofOfPermission};
use crate::ChainRpcConfig;

pub(super) async fn verify_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    mk: &aptos_multi_key::MultiKeyInner,
    ms: &aptos_multi_key::MultiKeySigInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    aptos_multi_key::validate(mk, ms)?;
    let deferred_keyless_checks =
        super::aptos_account_multi_key_deferred::collect(payload, proof, mk, ms)?;
    let keyless_msg_bytes = if deferred_keyless_checks.is_empty() {
        None
    } else {
        Some(signed_message_bytes(
            payload,
            proof,
            "verify_multi_key_account_proof",
        )?)
    };

    let computed = aptos_multi_key::authentication_key(mk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, &computed, "multi_key", rpc).await?;

    if let Some(msg_bytes) = keyless_msg_bytes {
        let keyless_futs = deferred_keyless_checks.into_iter().map(|deferred| {
            verify_deferred_keyless_signature_for_message(chain_id, deferred, &msg_bytes, chain_rpc)
        });
        futures::future::try_join_all(keyless_futs).await?;
    }
    Ok(())
}
