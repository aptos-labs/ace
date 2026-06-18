// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

/// Walks the `{ jwks: { entries: [...] } }` body of a `PatchedJWKs` or
/// `FederatedJWKs` resource and returns the RSA JWK matching `(iss, kid)`, if
/// present. Both resource types share this internal shape (see
/// `0x1::jwks::PatchedJWKs` / `0x1::jwks::FederatedJWKs` in aptos-core), so the
/// inner walk is shared between the system and federated keyless paths.
///
/// Returns `Ok(None)` when the resource is well-formed but contains no matching
/// JWK (a "miss" that the federated path treats as a signal to try the fallback
/// account); returns `Err(_)` only for structural problems with the JSON.
pub(super) fn find_rsa_jwk_in_jwks_resource(
    resource: &serde_json::Value,
    iss: &str,
    kid: &str,
) -> Result<Option<aptos_keyless_common::RsaJwk>> {
    let entries = resource
        .pointer("/jwks/entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("find_rsa_jwk_in_jwks_resource: missing entries array"))?;

    // `issuer` is published as a hex-encoded `vector<u8>` over the REST API.
    let iss_hex = format!("0x{}", hex::encode(iss.as_bytes()));
    for entry in entries {
        let issuer = entry.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
        if issuer != iss_hex {
            continue;
        }
        let jwks = entry
            .pointer("/jwks")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("find_rsa_jwk_in_jwks_resource: entry missing jwks array"))?;
        for jwk in jwks {
            // Each JWK is `{ variant: { type_name, data } }` (Any). The RSA
            // variant's data BCS-decodes as { kid, kty, alg, e, n }.
            let type_name = jwk
                .pointer("/variant/type_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if type_name != "0x1::jwks::RSA_JWK" {
                continue;
            }
            let data_hex = jwk
                .pointer("/variant/data")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("find_rsa_jwk_in_jwks_resource: missing variant.data"))?;
            let data_bytes = hex::decode(data_hex.trim_start_matches("0x")).map_err(|e| {
                anyhow!("find_rsa_jwk_in_jwks_resource: decode variant.data: {}", e)
            })?;
            let rsa: aptos_keyless_common::RsaJwk = bcs::from_bytes(&data_bytes)
                .map_err(|e| anyhow!("find_rsa_jwk_in_jwks_resource: BCS decode RSA_JWK: {}", e))?;
            if rsa.kid == kid {
                return Ok(Some(rsa));
            }
        }
    }
    Ok(None)
}
