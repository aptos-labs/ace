// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::super::super::{
    any as aptos_any, hooks::check_auth_key_bytes, message::verified_signed_message_bytes,
    AptosPayloadBinding, AptosProofOfPermission,
};
use super::super::deferred::{verify_deferred_keyless_signature_for_message, AnySignatureCheck};
use super::verify_signature_locally_or_defer_keyless;
use crate::ChainRpcConfig;

pub(in crate::verify::shared::aptos::account) async fn verify_account_proof<
    P: AptosPayloadBinding + Sync,
>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    any_pk: &aptos_any::AnyPublicKeyInner,
    any_sig: &aptos_any::AnySignatureInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let signature_check =
        verify_signature_locally_or_defer_keyless(payload, proof, any_pk, any_sig)?;
    let computed = aptos_any::authentication_key(any_pk);
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
    any_pk: &aptos_any::AnyPublicKeyInner,
    deferred: AnySignatureCheck<'_>,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let msg_bytes =
        verified_signed_message_bytes(payload, proof, deferred.signed_message_context())?;
    let computed = aptos_any::authentication_key(any_pk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, &computed, any_pk.tag_name(), rpc).await?;
    verify_deferred_keyless_signature_for_message(chain_id, deferred, &msg_bytes, chain_rpc).await
}
