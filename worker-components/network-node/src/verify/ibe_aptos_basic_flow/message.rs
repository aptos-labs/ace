// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::{any, AptosPayloadBinding, AptosProofOfPermission, AptosSignatureMaterial};

pub(super) fn signed_message_bytes<P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    context: &str,
) -> Result<Vec<u8>> {
    let expected_hex = payload.to_signed_message_hex()?;
    // AptosConnect wallets sign `hex(UTF-8(fullMessage))` rather than the raw
    // string, so the BCS-hex marker may appear hex-of-hex'd inside `full_msg`.
    let expected_hex_hex = hex::encode(expected_hex.as_bytes());
    let full_msg = &proof.full_message;
    if !full_msg.contains(&expected_hex) && !full_msg.contains(&expected_hex_hex) {
        return Err(anyhow!(
            "{}: fullMessage does not contain expected request content",
            context
        ));
    }

    if is_valid_hex(full_msg) {
        let stripped = full_msg.strip_prefix("0x").unwrap_or(full_msg.as_str());
        hex::decode(stripped).map_err(|e| anyhow!("{}: hex decode fullMessage: {}", context, e))
    } else {
        Ok(full_msg.as_bytes().to_vec())
    }
}

fn extract_signed_wallet_application(proof: &AptosProofOfPermission) -> Result<String> {
    let full_message = signed_full_message_as_utf8(proof, "extract_signed_wallet_application")?;
    parse_aptos_wallet_application(&full_message)
}

fn signed_full_message_as_utf8(proof: &AptosProofOfPermission, context: &str) -> Result<String> {
    let full_msg = &proof.full_message;
    let bytes = if is_valid_hex(full_msg) {
        let stripped = full_msg.strip_prefix("0x").unwrap_or(full_msg.as_str());
        hex::decode(stripped).map_err(|e| anyhow!("{}: hex decode fullMessage: {}", context, e))?
    } else {
        full_msg.as_bytes().to_vec()
    };
    String::from_utf8(bytes).map_err(|e| anyhow!("{}: fullMessage is not UTF-8: {}", context, e))
}

fn parse_aptos_wallet_application(full_message: &str) -> Result<String> {
    let mut lines = full_message.split('\n');
    match lines.next() {
        Some("APTOS") => {}
        _ => {
            return Err(anyhow!(
                "extract_signed_wallet_application: fullMessage is not an Aptos wallet message"
            ))
        }
    }

    for line in lines {
        if line.starts_with("message:") {
            break;
        }
        if let Some(application) = line.strip_prefix("application: ") {
            if application.is_empty() {
                return Err(anyhow!(
                    "extract_signed_wallet_application: application is empty"
                ));
            }
            return Ok(application.to_string());
        }
    }

    Err(anyhow!(
        "extract_signed_wallet_application: fullMessage missing application"
    ))
}

pub(in crate::verify) fn extract_request_origin(proof: &AptosProofOfPermission) -> Result<String> {
    let mut origins = Vec::new();
    collect_webauthn_app_origins(&proof.signature, &mut origins)?;

    match extract_signed_wallet_application(proof) {
        Ok(application) => origins.push(application),
        Err(err) if origins.is_empty() => {
            return Err(anyhow!("extract_request_origin: {}", err));
        }
        Err(_) => {}
    }

    let origin = origins
        .first()
        .ok_or_else(|| anyhow!("extract_request_origin: no signed request origin"))?
        .clone();
    if origins.iter().any(|candidate| candidate != &origin) {
        return Err(anyhow!(
            "extract_request_origin: signed origins disagree ({:?})",
            origins
        ));
    }
    Ok(origin)
}

fn collect_webauthn_app_origins(
    sig: &AptosSignatureMaterial,
    origins: &mut Vec<String>,
) -> Result<()> {
    match sig {
        AptosSignatureMaterial::Any(any_sig) => collect_any_webauthn_app_origin(any_sig, origins),
        AptosSignatureMaterial::MultiKey(ms) => {
            for sig in &ms.signatures {
                collect_any_webauthn_app_origin(sig, origins)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn collect_any_webauthn_app_origin(
    sig: &any::AnySignatureInner,
    origins: &mut Vec<String>,
) -> Result<()> {
    if let any::AnySignatureInner::WebAuthn(assertion) = sig {
        origins.push(extract_webauthn_app_origin(assertion)?);
    }
    Ok(())
}

fn extract_webauthn_app_origin(assertion: &any::WebAuthnAssertion) -> Result<String> {
    let cdj: serde_json::Value = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|e| anyhow!("extract_webauthn_app_origin: parse client_data_json: {}", e))?;
    let typ = cdj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("extract_webauthn_app_origin: clientDataJSON missing `type`"))?;
    if typ != "webauthn.get" {
        return Err(anyhow!(
            "extract_webauthn_app_origin: expected type webauthn.get, got {:?}",
            typ
        ));
    }

    let cross_origin = cdj
        .get("crossOrigin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let origin_field = if cross_origin { "topOrigin" } else { "origin" };
    let origin = cdj
        .get(origin_field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!(
                "extract_webauthn_app_origin: clientDataJSON missing `{}` string",
                origin_field
            )
        })?;
    if origin.is_empty() {
        return Err(anyhow!(
            "extract_webauthn_app_origin: clientDataJSON `{}` is empty",
            origin_field
        ));
    }
    Ok(origin.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_aptos_wallet_application;

    #[test]
    fn parses_application_before_message_body() {
        let full_message = concat!(
            "APTOS\n",
            "address: 0xabc\n",
            "application: https://app.example\n",
            "chainId: 4\n",
            "message: ACE Threshold VRF Derive Request\n",
            "application: https://evil.example\n",
            "nonce: 123",
        );
        assert_eq!(
            parse_aptos_wallet_application(full_message).unwrap(),
            "https://app.example"
        );
    }

    #[test]
    fn rejects_application_only_inside_message_body() {
        let full_message = concat!(
            "APTOS\n",
            "address: 0xabc\n",
            "chainId: 4\n",
            "message: ACE Threshold VRF Derive Request\n",
            "application: https://evil.example\n",
            "nonce: 123",
        );
        assert!(parse_aptos_wallet_application(full_message).is_err());
    }
}

// ── Shared helpers (used by ed25519 + keyless) ──────────────────────────────

/// True if `s` is a valid hex string (optional `0x` prefix, all hex digits).
///
/// Matches the `Hex.isValid()` semantics in the Aptos TS SDK — we use it to
/// decide whether `proof.full_message` is a raw hex blob (the AptosConnect
/// wallet path) or a plain UTF-8 string.
pub(super) fn is_valid_hex(s: &str) -> bool {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    hex.chars().all(|c| c.is_ascii_hexdigit())
}
