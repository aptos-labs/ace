// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use serde_json::json;

use super::constants::APTOS_DECRYPTION_HOOK;
use super::{AptosContractId, AptosProofOfPermission};
use crate::ChainRpcConfig;

pub(super) async fn check_ace_request_hook(
    contract: &AptosContractId,
    hook_name: &str,
    label: &[u8],
    account: &[u8; 32],
    origin: &str,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let func = format!(
        "0x{}::{}::{}",
        hex::encode(contract.module_addr),
        contract.module_name,
        hook_name,
    );
    let label_hex = format!("0x{}", hex::encode(label));
    let account_hex = format!("0x{}", hex::encode(account));

    let result = rpc
        .call_view(
            &func,
            &[json!(label_hex), json!(account_hex), json!(origin)],
        )
        .await
        .map_err(|e| anyhow!("checkAceRequestHook: view call failed for {}: {}", func, e))?;

    let returned = result
        .first()
        .ok_or_else(|| anyhow!("checkAceRequestHook: empty view result"))?;
    if returned.as_bool() != Some(true) && returned.to_string() != "true" {
        return Err(anyhow!(
            "checkAceRequestHook: request denied by {} for origin {:?} account {} label {} (returned {:?})",
            func,
            origin,
            account_hex,
            label_hex,
            returned,
        ));
    }

    Ok(())
}

pub(super) async fn check_auth_key_bytes(
    proof: &AptosProofOfPermission,
    computed: &[u8],
    label: &str,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let user_addr_str = format!("0x{}", hex::encode(proof.user_addr));
    let account = rpc
        .get_account(&user_addr_str)
        .await
        .map_err(|e| anyhow!("checkAuthKey: get_account {}: {}", user_addr_str, e))?;
    let onchain = hex::decode(account.authentication_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("checkAuthKey: parse onchain auth key: {}", e))?;
    if onchain.as_slice() != computed {
        return Err(anyhow!(
            "checkAuthKey: {} auth key mismatch for {}",
            label,
            user_addr_str
        ));
    }
    Ok(())
}

#[allow(dead_code)]
/// Calls the on-chain view function
/// `{moduleAddr}::{moduleName}::on_ace_decryption_request(label, account, origin)`
/// and expects `true` to be returned.
pub(super) async fn check_basic_ace_hook(
    contract: &AptosContractId,
    domain: &[u8],
    proof: &AptosProofOfPermission,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let func = format!(
        "0x{}::{}::{}",
        hex::encode(contract.module_addr),
        contract.module_name,
        APTOS_DECRYPTION_HOOK,
    );
    let user_addr = format!("0x{}", hex::encode(proof.user_addr));
    let domain_hex = format!("0x{}", hex::encode(domain));

    let result = rpc
        .call_view(&func, &[json!(domain_hex), json!(user_addr), json!("")])
        .await
        .map_err(|e| anyhow!("checkBasicAceHook: view call failed for {}: {}", func, e))?;

    let returned = result
        .first()
        .ok_or_else(|| anyhow!("checkBasicAceHook: empty view result"))?;
    if returned.as_bool() != Some(true) && returned.to_string() != "true" {
        return Err(anyhow!(
            "checkBasicAceHook: access denied (returned {:?})",
            returned
        ));
    }

    Ok(())
}
