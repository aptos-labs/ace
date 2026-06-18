// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::hooks::check_auth_key_bytes;
use super::message::signed_message_bytes;
use super::{
    account_any::verify_signature_locally_or_defer_keyless,
    account_deferred::{verify_deferred_keyless_signature_for_message, AnySignatureCheck},
    any, AptosPayloadBinding, AptosProofOfPermission,
};
use crate::ChainRpcConfig;

pub(in crate::verify) async fn verify_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    any_pk: &any::AnyPublicKeyInner,
    any_sig: &any::AnySignatureInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let signature_check =
        verify_signature_locally_or_defer_keyless(payload, proof, any_pk, any_sig)?;
    let computed = any::authentication_key(any_pk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    match signature_check {
        AnySignatureCheck::VerifiedLocally => {
            check_auth_key_bytes(proof, &computed, any_pk.tag_name(), rpc).await
        }
        deferred => verify_deferred(payload, chain_id, proof, any_pk, deferred, chain_rpc).await,
    }
}

async fn verify_deferred<P: AptosPayloadBinding>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    any_pk: &any::AnyPublicKeyInner,
    deferred: AnySignatureCheck<'_>,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let msg_bytes = signed_message_bytes(payload, proof, deferred.signed_message_context())?;
    let computed = any::authentication_key(any_pk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, &computed, any_pk.tag_name(), rpc).await?;
    verify_deferred_keyless_signature_for_message(chain_id, deferred, &msg_bytes, chain_rpc).await
}
