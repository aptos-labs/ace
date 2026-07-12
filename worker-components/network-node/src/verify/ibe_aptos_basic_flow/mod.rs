// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::shared::aptos::{
    check_ace_request_hook, extract_request_origin, verify_account_proof, AptosContractId,
    AptosProofOfPermission, APTOS_DECRYPTION_HOOK,
};
use super::BasicFlowRequest;
use crate::ChainRpcConfig;

pub(in crate::verify) async fn verify_aptos(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    verify_account_proof(&req.payload, contract.chain_id, proof, chain_rpc).await?;
    let origin = extract_request_origin(proof)?;
    check_ace_request_hook(
        contract,
        APTOS_DECRYPTION_HOOK,
        &req.payload.domain,
        &proof.user_addr,
        &origin,
        chain_rpc,
    )
    .await
}
