// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::ibe_solana_basic_flow::{
    simulate_txn, solana_program_id, validate_custom_txn, SolanaContractId, SolanaProofOfPermission,
};
use super::CustomFlowRequest;
use crate::ChainRpcConfig;

pub(in crate::verify) async fn verify(
    req: &CustomFlowRequest,
    contract: &SolanaContractId,
    proof: &SolanaProofOfPermission,
    enc_pk_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let expected_program_id = solana_program_id(contract)?;
    let is_versioned = proof.inner_scheme == 1;
    validate_custom_txn(
        &proof.txn_bytes,
        &expected_program_id,
        &req.keypair_id,
        req.epoch,
        enc_pk_bytes,
        &req.label,
        is_versioned,
    )?;

    let rpc_url = chain_rpc.solana_rpc_for_chain_name(&contract.known_chain_name)?;
    simulate_txn(&proof.txn_bytes, &rpc_url, &chain_rpc.solana_client).await
}
