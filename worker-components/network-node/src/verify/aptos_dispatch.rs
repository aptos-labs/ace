// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::aptos_account::verify_aptos_account_proof;
use super::aptos_constants::{APTOS_DECRYPTION_HOOK, APTOS_VRF_HOOK};
use super::aptos_hooks::check_ace_request_hook;
use super::aptos_message::extract_request_origin;
use super::{AptosContractId, AptosProofOfPermission};
use super::{BasicFlowRequest, ContractId, ThresholdVrfRequest};
use crate::ChainRpcConfig;

pub(in crate::verify) async fn verify_aptos(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    verify_aptos_account_proof(&req.payload, contract.chain_id, proof, chain_rpc).await?;
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

pub(in crate::verify) async fn verify_threshold_vrf_aptos(
    req: &ThresholdVrfRequest,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let proof = &req.auth_proof;
    if proof.user_addr != req.payload.account_address {
        return Err(anyhow!(
            "verify_threshold_vrf_aptos: proof user_addr does not match payload account_address"
        ));
    }
    let contract = match &req.payload.contract_id {
        ContractId::Aptos(contract) => contract,
        ContractId::Solana(_) => {
            return Err(anyhow!(
                "verify_threshold_vrf_aptos: threshold VRF origin checks require an Aptos contract"
            ))
        }
    };
    verify_aptos_account_proof(&req.payload, contract.chain_id, proof, chain_rpc).await?;
    let origin = extract_request_origin(proof)?;
    check_ace_request_hook(
        contract,
        APTOS_VRF_HOOK,
        &req.payload.label,
        &req.payload.account_address,
        &origin,
        chain_rpc,
    )
    .await
}
