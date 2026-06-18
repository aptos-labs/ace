// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use serde_json::json;

use super::shared::aptos::{AptosContractId, APTOS_CUSTOM_DECRYPTION_HOOK};
use crate::ChainRpcConfig;

// ── Custom-flow verification ──────────────────────────────────────────────────

pub(in crate::verify) async fn verify(
    contract: &AptosContractId,
    label: &[u8],
    enc_pk_bytes: &[u8],
    payload: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let func = format!(
        "0x{}::{}::{}",
        hex::encode(contract.module_addr),
        contract.module_name,
        APTOS_CUSTOM_DECRYPTION_HOOK,
    );
    let label_hex = format!("0x{}", hex::encode(label));
    let enc_pk_hex = format!("0x{}", hex::encode(enc_pk_bytes));
    let payload_hex = format!("0x{}", hex::encode(payload));

    let result = rpc
        .call_view(
            &func,
            &[json!(label_hex), json!(enc_pk_hex), json!(payload_hex)],
        )
        .await
        .map_err(|e| anyhow!("check_aptos_acl: view call failed for {}: {}", func, e))?;

    let returned = result
        .first()
        .ok_or_else(|| anyhow!("check_aptos_acl: empty view result"))?;
    if returned.as_bool() != Some(true) && returned.to_string() != "true" {
        return Err(anyhow!(
            "check_aptos_acl: access denied (returned {:?})",
            returned
        ));
    }
    Ok(())
}
