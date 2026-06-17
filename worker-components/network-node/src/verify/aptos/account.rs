// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as K256Signature,
    VerifyingKey as K256VerifyingKey,
};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use super::cache::{
    fetch_cached_configuration, fetch_cached_federated_jwk_with_fallback, fetch_cached_groth16_vk,
    fetch_cached_system_rsa_jwk,
};
use super::hooks::check_auth_key_bytes;
use super::message::signed_message_bytes;
use super::{any, multi_ed25519, multi_key};
use super::{
    AptosPayloadBinding, AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};
use crate::ChainRpcConfig;

pub(super) async fn verify_aptos_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    match (&proof.public_key, &proof.signature) {
        (AptosPublicKeyMaterial::Ed25519(pk_bytes), AptosSignatureMaterial::Ed25519(sig_bytes)) => {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes).map_err(|e| {
                anyhow!("verify_aptos_account_proof: invalid Ed25519 pubkey: {}", e)
            })?;
            let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
            verify_ed25519_signature(payload, proof, &vk, &sig, "verify_aptos_account_proof")?;
            let computed = vss_common::compute_account_address(&vk);
            let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
            check_auth_key_bytes(proof, computed.as_ref(), "ed25519", rpc).await
        }
        (AptosPublicKeyMaterial::Any(any_pk), AptosSignatureMaterial::Any(any_sig)) => {
            verify_any_account_proof(payload, chain_id, proof, any_pk, any_sig, chain_rpc).await
        }
        (AptosPublicKeyMaterial::MultiEd25519(pk), AptosSignatureMaterial::MultiEd25519(sig)) => {
            verify_multi_ed25519_account_proof(payload, chain_id, proof, pk, sig, chain_rpc).await
        }
        (AptosPublicKeyMaterial::MultiKey(mk), AptosSignatureMaterial::MultiKey(ms)) => {
            verify_multi_key_account_proof(payload, chain_id, proof, mk, ms, chain_rpc).await
        }
        (AptosPublicKeyMaterial::Keyless(pk), AptosSignatureMaterial::Keyless(sig)) => {
            let msg_bytes = signed_message_bytes(payload, proof, "verify_keyless_signature")?;
            let computed = aptos_keyless_common::keyless_account_authentication_key(pk);
            let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
            check_auth_key_bytes(proof, computed.as_ref(), "keyless", rpc).await?;
            verify_keyless_signature_for_message(chain_id, pk, sig, &msg_bytes, chain_rpc).await
        }
        (AptosPublicKeyMaterial::FederatedKeyless(fpk), AptosSignatureMaterial::Keyless(sig)) => {
            let msg_bytes =
                signed_message_bytes(payload, proof, "verify_federated_keyless_signature")?;
            let computed = aptos_keyless_common::federated_keyless_account_authentication_key(fpk);
            let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
            check_auth_key_bytes(proof, computed.as_ref(), "federated_keyless", rpc).await?;
            verify_federated_keyless_signature_for_message(
                chain_id, fpk, sig, &msg_bytes, chain_rpc,
            )
            .await
        }
        (pk, sig) => Err(anyhow!(
            "verify_aptos_account_proof: pk/sig scheme mismatch ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
    }
}

async fn verify_any_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    any_pk: &any::AnyPublicKeyInner,
    any_sig: &any::AnySignatureInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let signature_check =
        verify_any_signature_locally_or_defer_keyless(payload, proof, any_pk, any_sig)?;
    let computed = any::authentication_key(any_pk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    match signature_check {
        AnySignatureCheck::VerifiedLocally => {
            check_auth_key_bytes(proof, &computed, any_pk.tag_name(), rpc).await
        }
        deferred => {
            let msg_bytes =
                signed_message_bytes(payload, proof, deferred.signed_message_context())?;
            check_auth_key_bytes(proof, &computed, any_pk.tag_name(), rpc).await?;
            verify_deferred_keyless_signature_for_message(chain_id, deferred, &msg_bytes, chain_rpc)
                .await
        }
    }
}

async fn verify_multi_ed25519_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    pk: &multi_ed25519::MultiEd25519PublicKeyInner,
    sig: &multi_ed25519::MultiEd25519SignatureInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    multi_ed25519::validate(pk, sig)?;

    let positions = multi_ed25519::bitmap_iter_ones(&sig.bitmap).zip(sig.signatures.iter());
    let position_futs: Vec<_> = positions
        .map(|(pos, sig_bytes)| {
            let pk_bytes = &pk.public_keys[pos];
            async move {
                let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes).map_err(|e| {
                    anyhow!(
                        "multi_ed25519 account proof: invalid Ed25519 pubkey at position {}: {}",
                        pos,
                        e
                    )
                })?;
                let ed_sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
                verify_ed25519_signature(
                    payload,
                    proof,
                    &vk,
                    &ed_sig,
                    "multi_ed25519 account proof",
                )
            }
        })
        .collect();
    futures::future::try_join_all(position_futs).await?;

    let computed = multi_ed25519::authentication_key(pk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, &computed, "multi_ed25519", rpc).await
}

async fn verify_multi_key_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    mk: &multi_key::MultiKeyInner,
    ms: &multi_key::MultiKeySigInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    multi_key::validate(mk, ms)?;

    let mut deferred_keyless_checks = Vec::new();
    let positions = multi_key::bitmap_iter_ones(&ms.bitmap).zip(ms.signatures.iter());
    for (pos, sig) in positions {
        let pk = &mk.public_keys[pos];
        match verify_any_signature_locally_or_defer_keyless(payload, proof, pk, sig)? {
            AnySignatureCheck::VerifiedLocally => {}
            deferred => deferred_keyless_checks.push(deferred),
        }
    }
    let keyless_msg_bytes = if deferred_keyless_checks.is_empty() {
        None
    } else {
        Some(signed_message_bytes(
            payload,
            proof,
            "verify_multi_key_account_proof",
        )?)
    };

    let computed = multi_key::authentication_key(mk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, &computed, "multi_key", rpc).await?;

    if let Some(msg_bytes) = keyless_msg_bytes {
        let keyless_futs = deferred_keyless_checks.into_iter().map(|deferred| {
            verify_deferred_keyless_signature_for_message(chain_id, deferred, &msg_bytes, chain_rpc)
        });
        futures::future::try_join_all(keyless_futs).await?;
    }
    Ok(())
}

#[derive(Copy, Clone)]
enum AnySignatureCheck<'a> {
    VerifiedLocally,
    DeferredKeyless {
        pk: &'a aptos_keyless_common::KeylessPublicKey,
        sig: &'a aptos_keyless_common::KeylessSignature,
    },
    DeferredFederatedKeyless {
        fpk: &'a aptos_keyless_common::FederatedKeylessPublicKey,
        sig: &'a aptos_keyless_common::KeylessSignature,
    },
}

impl AnySignatureCheck<'_> {
    fn signed_message_context(&self) -> &'static str {
        match self {
            AnySignatureCheck::VerifiedLocally => "verify_any_signature_only",
            AnySignatureCheck::DeferredKeyless { .. } => "verify_keyless_signature",
            AnySignatureCheck::DeferredFederatedKeyless { .. } => {
                "verify_federated_keyless_signature"
            }
        }
    }
}

fn verify_any_signature_locally_or_defer_keyless<'a, P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    any_pk: &'a any::AnyPublicKeyInner,
    any_sig: &'a any::AnySignatureInner,
) -> Result<AnySignatureCheck<'a>> {
    match (any_pk, any_sig) {
        (any::AnyPublicKeyInner::Ed25519(pk_bytes), any::AnySignatureInner::Ed25519(sig_bytes)) => {
            let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "verify_any_signature_only: Ed25519 pk must be 32 bytes, got {}",
                    pk_bytes.len()
                )
            })?;
            let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "verify_any_signature_only: Ed25519 sig must be 64 bytes, got {}",
                    sig_bytes.len()
                )
            })?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
                .map_err(|e| anyhow!("verify_any_signature_only: invalid Ed25519 pubkey: {}", e))?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
            verify_ed25519_signature(payload, proof, &vk, &sig, "verify_any_signature_only")?;
            Ok(AnySignatureCheck::VerifiedLocally)
        }
        (
            any::AnyPublicKeyInner::Secp256k1Ecdsa(pk_bytes),
            any::AnySignatureInner::Secp256k1Ecdsa(sig_bytes),
        ) => {
            if sig_bytes.len() != 64 {
                return Err(anyhow!(
                    "verify_any_signature_only: Secp256k1 sig must be 64 bytes, got {}",
                    sig_bytes.len()
                ));
            }
            let vk = K256VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|e| {
                anyhow!("verify_any_signature_only: invalid Secp256k1 pubkey: {}", e)
            })?;
            let sig = K256Signature::from_slice(sig_bytes).map_err(|e| {
                anyhow!(
                    "verify_any_signature_only: invalid Secp256k1 signature: {}",
                    e
                )
            })?;
            if sig.normalize_s().is_some() {
                return Err(anyhow!(
                    "verify_any_signature_only: Secp256k1 signature has high s (malleable)"
                ));
            }
            verify_secp256k1_signature(payload, proof, &vk, &sig, "verify_any_signature_only")?;
            Ok(AnySignatureCheck::VerifiedLocally)
        }
        (any::AnyPublicKeyInner::Keyless(pk), any::AnySignatureInner::Keyless(sig)) => {
            Ok(AnySignatureCheck::DeferredKeyless { pk, sig })
        }
        (any::AnyPublicKeyInner::FederatedKeyless(fpk), any::AnySignatureInner::Keyless(sig)) => {
            Ok(AnySignatureCheck::DeferredFederatedKeyless { fpk, sig })
        }
        (
            any::AnyPublicKeyInner::Secp256r1Ecdsa(pk_bytes),
            any::AnySignatureInner::WebAuthn(assertion),
        ) => {
            verify_webauthn_signature(payload, pk_bytes, assertion)?;
            Ok(AnySignatureCheck::VerifiedLocally)
        }
        (pk, sig) => Err(anyhow!(
            "verify_any_signature_only: invalid pk/sig pairing ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
    }
}

async fn verify_deferred_keyless_signature_for_message(
    chain_id: u8,
    deferred: AnySignatureCheck<'_>,
    msg_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    match deferred {
        AnySignatureCheck::DeferredKeyless { pk, sig } => {
            verify_keyless_signature_for_message(chain_id, pk, sig, msg_bytes, chain_rpc).await
        }
        AnySignatureCheck::DeferredFederatedKeyless { fpk, sig } => {
            verify_federated_keyless_signature_for_message(chain_id, fpk, sig, msg_bytes, chain_rpc)
                .await
        }
        AnySignatureCheck::VerifiedLocally => Ok(()),
    }
}

fn verify_ed25519_signature<P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    vk: &ed25519_dalek::VerifyingKey,
    sig: &ed25519_dalek::Signature,
    context: &str,
) -> Result<()> {
    use ed25519_dalek::Verifier;

    let msg_bytes = signed_message_bytes(payload, proof, context)?;
    vk.verify(&msg_bytes, sig)
        .map_err(|e| anyhow!("{}: Ed25519 verification failed: {}", context, e))
}

fn verify_secp256k1_signature<P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    vk: &K256VerifyingKey,
    sig: &K256Signature,
    context: &str,
) -> Result<()> {
    let msg_bytes = signed_message_bytes(payload, proof, context)?;
    let prehash: [u8; 32] = Sha3_256::digest(&msg_bytes).into();
    vk.verify_prehash(&prehash, sig)
        .map_err(|e| anyhow!("{}: Secp256k1 ECDSA verification failed: {}", context, e))
}

fn verify_webauthn_signature<P: AptosPayloadBinding>(
    payload: &P,
    pk_bytes: &[u8],
    assertion: &any::WebAuthnAssertion,
) -> Result<()> {
    let any::AssertionSignature::Secp256r1Ecdsa(sig_bytes) = &assertion.signature;
    if sig_bytes.len() != 64 {
        return Err(anyhow!(
            "verify_webauthn_signature: sig must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let vk = P256VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| anyhow!("verify_webauthn_signature: invalid Secp256r1 pubkey: {}", e))?;
    let sig = P256Signature::from_slice(sig_bytes).map_err(|e| {
        anyhow!(
            "verify_webauthn_signature: invalid Secp256r1 signature: {}",
            e
        )
    })?;
    if sig.normalize_s().is_some() {
        return Err(anyhow!(
            "verify_webauthn_signature: Secp256r1 signature has high s (malleable)"
        ));
    }

    let expected_challenge = payload.to_webauthn_challenge()?;
    let cdj: serde_json::Value = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|e| anyhow!("verify_webauthn_signature: parse client_data_json: {}", e))?;
    let challenge_str = cdj
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!("verify_webauthn_signature: clientDataJSON missing `challenge` string")
        })?;
    let actual_challenge = URL_SAFE_NO_PAD.decode(challenge_str).map_err(|e| {
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

    let cdj_hash = Sha256::digest(&assertion.client_data_json);
    let mut ecdsa_preimage =
        Vec::with_capacity(assertion.authenticator_data.len() + cdj_hash.len());
    ecdsa_preimage.extend_from_slice(&assertion.authenticator_data);
    ecdsa_preimage.extend_from_slice(&cdj_hash);
    let prehash: [u8; 32] = Sha256::digest(&ecdsa_preimage).into();
    vk.verify_prehash(&prehash, &sig).map_err(|e| {
        anyhow!(
            "verify_webauthn_signature: P-256 ECDSA verification failed: {}",
            e
        )
    })
}

async fn verify_keyless_signature_for_message(
    chain_id: u8,
    pk: &aptos_keyless_common::KeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    msg_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    let header: aptos_keyless_common::types::JwtHeader = serde_json::from_str(&sig.jwt_header_json)
        .map_err(|e| anyhow!("verify_keyless_signature: parse jwt_header_json: {}", e))?;
    let (jwk_res, vk_res, cfg_res) = tokio::join!(
        fetch_cached_system_rsa_jwk(chain_id, rpc, &pk.iss_val, &header.kid),
        fetch_cached_groth16_vk(chain_id, rpc),
        fetch_cached_configuration(chain_id, rpc),
    );
    let jwk = jwk_res?;
    let vk = vk_res?;
    let cfg = cfg_res?;
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("verify_keyless_signature: system clock: {}", e))?
        .as_secs();
    aptos_keyless_common::verify_signature(pk, sig, msg_bytes, &jwk, &vk, &cfg, now_unix_secs)
        .map_err(|e| anyhow!("verify_keyless_signature: {}", e))
}

async fn verify_federated_keyless_signature_for_message(
    chain_id: u8,
    fpk: &aptos_keyless_common::FederatedKeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    msg_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    let header: aptos_keyless_common::types::JwtHeader = serde_json::from_str(&sig.jwt_header_json)
        .map_err(|e| {
            anyhow!(
                "verify_federated_keyless_signature: parse jwt_header_json: {}",
                e
            )
        })?;
    let (jwk_res, vk_res, cfg_res) = tokio::join!(
        fetch_cached_federated_jwk_with_fallback(chain_id, rpc, fpk, &header.kid),
        fetch_cached_groth16_vk(chain_id, rpc),
        fetch_cached_configuration(chain_id, rpc),
    );
    let jwk = jwk_res?;
    let vk = vk_res?;
    let cfg = cfg_res?;
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("verify_federated_keyless_signature: system clock: {}", e))?
        .as_secs();
    aptos_keyless_common::verify_signature(&fpk.pk, sig, msg_bytes, &jwk, &vk, &cfg, now_unix_secs)
        .map_err(|e| anyhow!("verify_federated_keyless_signature: {}", e))
}
