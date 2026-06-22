// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Shared Aptos federated-keyless JWK fetch helpers.

use anyhow::{anyhow, Result};

use super::jwks::find_rsa_jwk_in_jwks_resource;
use super::keyless::fetch_system_rsa_jwk;

/// Matches the on-chain VM behaviour: try `0x1::jwks::PatchedJWKs` first; on
/// miss, fall back to `0x1::jwks::FederatedJWKs` at `fpk.jwk_addr`.
pub(super) async fn fetch_jwk_with_federated_fallback(
    rpc: &vss_common::AptosRpc,
    fpk: &aptos_keyless_common::FederatedKeylessPublicKey,
    kid: &str,
) -> Result<aptos_keyless_common::RsaJwk> {
    // Issue both reads concurrently. Most of the time we only need the system
    // result, but for issuers the foundation doesn't manage (Auth0, Cognito,
    // etc.) the federated read is on the hot path — overlap the RTTs.
    let (sys_res, fed_res) = tokio::join!(
        fetch_system_rsa_jwk(rpc, &fpk.pk.iss_val, kid),
        fetch_federated_rsa_jwk(rpc, &fpk.jwk_addr, &fpk.pk.iss_val, kid),
    );
    if let Ok(jwk) = sys_res {
        return Ok(jwk);
    }
    fed_res.map_err(|e| {
        anyhow!(
            "fetch_jwk_with_federated_fallback: no JWK for iss={:?} kid={:?} (system miss + federated: {})",
            fpk.pk.iss_val, kid, e
        )
    })
}

/// Fetches the `RSA_JWK` for `(iss, kid)` from `0x1::jwks::FederatedJWKs`
/// published at the dapp-controlled `jwk_addr`.
async fn fetch_federated_rsa_jwk(
    rpc: &vss_common::AptosRpc,
    jwk_addr: &[u8; 32],
    iss: &str,
    kid: &str,
) -> Result<aptos_keyless_common::RsaJwk> {
    let addr = format!("0x{}", hex::encode(jwk_addr));
    let resource = rpc
        .get_account_resource(&addr, "0x1::jwks::FederatedJWKs")
        .await
        .map_err(|e| {
            anyhow!(
                "fetch_federated_rsa_jwk: FederatedJWKs read at {}: {}",
                addr,
                e
            )
        })?;
    find_rsa_jwk_in_jwks_resource(&resource, iss, kid)?.ok_or_else(|| {
        anyhow!(
            "fetch_federated_rsa_jwk: no JWK at {} for iss={:?} kid={:?}",
            addr,
            iss,
            kid
        )
    })
}
