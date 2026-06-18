// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use super::any::WebAuthnAssertion;
use super::AptosPayloadBinding;

pub(super) fn validate<P: AptosPayloadBinding>(
    payload: &P,
    assertion: &WebAuthnAssertion,
) -> Result<()> {
    let expected_challenge = payload.to_webauthn_challenge()?;
    let cdj: serde_json::Value = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|e| anyhow!("verify_webauthn_signature: parse client_data_json: {}", e))?;
    let challenge = cdj
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!("verify_webauthn_signature: clientDataJSON missing `challenge` string")
        })?;
    let actual_challenge = URL_SAFE_NO_PAD.decode(challenge).map_err(|e| {
        anyhow!(
            "verify_webauthn_signature: base64url-decode challenge: {}",
            e
        )
    })?;
    if actual_challenge != expected_challenge {
        return Err(anyhow!(
            "verify_webauthn_signature: clientDataJSON.challenge does not bind to this request payload"
        ));
    }
    Ok(())
}
