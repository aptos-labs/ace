// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Shared Aptos keyless resource fetch helpers.

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::jwks::find_rsa_jwk_in_jwks_resource;

/// Fetches the `RSA_JWK` for `(iss, kid)` from the on-chain
/// `0x1::jwks::PatchedJWKs` resource.
///
/// Errors with "no JWK found" if the system list does not carry an entry for
/// `(iss, kid)`. The federated-keyless path catches that miss and retries
/// against `FederatedJWKs` at the dapp's `jwk_addr`.
pub(super) async fn fetch_system_rsa_jwk(
    rpc: &vss_common::AptosRpc,
    iss: &str,
    kid: &str,
) -> Result<aptos_keyless_common::RsaJwk> {
    // PatchedJWKs.jwks.entries[i] = { issuer: vec<u8>, version: u64, jwks: vec<JWK> }
    // JWK is a Move enum (`Any` wrapper). We just need to surface the RSA fields.
    let resource = rpc
        .get_account_resource(&format!("0x{:0>64}", "1"), "0x1::jwks::PatchedJWKs")
        .await
        .map_err(|e| anyhow!("fetch_system_rsa_jwk: PatchedJWKs read: {}", e))?;
    find_rsa_jwk_in_jwks_resource(&resource, iss, kid)?.ok_or_else(|| {
        anyhow!(
            "fetch_system_rsa_jwk: no JWK found for iss={:?} kid={:?}",
            iss,
            kid
        )
    })
}

/// Fetches `0x1::keyless_account::Groth16VerificationKey` and BCS-decodes it.
pub(super) async fn fetch_groth16_vk(
    rpc: &vss_common::AptosRpc,
) -> Result<aptos_keyless_common::Groth16VerificationKey> {
    let resource = rpc
        .get_account_resource(
            &format!("0x{:0>64}", "1"),
            "0x1::keyless_account::Groth16VerificationKey",
        )
        .await
        .map_err(|e| anyhow!("fetch_keyless_groth16_vk: resource read: {}", e))?;
    let alpha_g1 = vec_u8_from_hex_field(&resource, "alpha_g1")?;
    let beta_g2 = vec_u8_from_hex_field(&resource, "beta_g2")?;
    let gamma_g2 = vec_u8_from_hex_field(&resource, "gamma_g2")?;
    let delta_g2 = vec_u8_from_hex_field(&resource, "delta_g2")?;
    let gamma_abc_g1 = resource
        .get("gamma_abc_g1")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("fetch_keyless_groth16_vk: missing gamma_abc_g1 array"))?
        .iter()
        .map(|v| {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow!("gamma_abc_g1 entry not string"))?;
            hex::decode(s.trim_start_matches("0x")).map_err(|e| anyhow!("decode: {}", e))
        })
        .collect::<Result<Vec<Vec<u8>>>>()?;
    Ok(aptos_keyless_common::Groth16VerificationKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

/// Fetches `0x1::keyless_account::Configuration` and BCS-decodes it.
pub(super) async fn fetch_configuration(
    rpc: &vss_common::AptosRpc,
) -> Result<aptos_keyless_common::types::Configuration> {
    let resource = rpc
        .get_account_resource(
            &format!("0x{:0>64}", "1"),
            "0x1::keyless_account::Configuration",
        )
        .await
        .map_err(|e| anyhow!("fetch_keyless_configuration: resource read: {}", e))?;
    let override_aud_vals = resource
        .get("override_aud_vals")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("Configuration: missing override_aud_vals"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow!("non-string aud"))
        })
        .collect::<Result<Vec<String>>>()?;
    let max_signatures_per_txn = u_from_str(&resource, "max_signatures_per_txn")? as u16;
    let max_exp_horizon_secs = u_from_str(&resource, "max_exp_horizon_secs")?;
    let training_wheels_pubkey = match resource.pointer("/training_wheels_pubkey/vec") {
        Some(v) => v
            .as_array()
            .and_then(|arr| arr.first())
            .map(|s| {
                s.as_str()
                    .ok_or_else(|| anyhow!("training_wheels_pubkey not string"))
                    .and_then(|h| {
                        hex::decode(h.trim_start_matches("0x")).map_err(|e| anyhow!("{}", e))
                    })
            })
            .transpose()?,
        None => None,
    };
    let max_commited_epk_bytes = u_from_str(&resource, "max_commited_epk_bytes")? as u16;
    let max_iss_val_bytes = u_from_str(&resource, "max_iss_val_bytes")? as u16;
    let max_extra_field_bytes = u_from_str(&resource, "max_extra_field_bytes")? as u16;
    let max_jwt_header_b64_bytes = u_from_str(&resource, "max_jwt_header_b64_bytes")? as u32;
    Ok(aptos_keyless_common::types::Configuration {
        override_aud_vals,
        max_signatures_per_txn,
        max_exp_horizon_secs,
        training_wheels_pubkey,
        max_commited_epk_bytes,
        max_iss_val_bytes,
        max_extra_field_bytes,
        max_jwt_header_b64_bytes,
    })
}

fn vec_u8_from_hex_field(v: &Value, field: &str) -> Result<Vec<u8>> {
    let s = v
        .get(field)
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("missing {} field", field))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|e| anyhow!("decode {}: {}", field, e))
}

/// REST returns u64 resource fields as JSON strings (`"1000000000000"`) most
/// of the time, but smaller widths as native numbers. Accept either shape.
fn u_from_str(v: &Value, field: &str) -> Result<u64> {
    let f = v
        .get(field)
        .ok_or_else(|| anyhow!("Configuration: missing {}", field))?;
    if let Some(n) = f.as_u64() {
        return Ok(n);
    }
    let s = f
        .as_str()
        .ok_or_else(|| anyhow!("Configuration.{} not int/string", field))?;
    s.parse::<u64>()
        .map_err(|e| anyhow!("parse {} ({:?}): {}", field, s, e))
}
