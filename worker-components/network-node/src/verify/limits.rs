// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::shared::aptos::any::{AnyPublicKeyInner, AnySignatureInner, AssertionSignature};
use super::shared::aptos::{
    AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};
use super::{
    ContractId, CustomFlowProof, DecryptionRequestPayload, ProofOfPermission,
    ThresholdVrfRequestPayload, WorkerRequest,
};

pub(crate) const MAX_WORKER_REQUEST_PLAINTEXT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_WORKER_REQUEST_LABEL_BYTES: usize = 1024;
pub(crate) const MAX_WORKER_REQUEST_MODULE_NAME_BYTES: usize = 256;
pub(crate) const MAX_WORKER_REQUEST_CUSTOM_PAYLOAD_BYTES: usize = 16 * 1024;
pub(crate) const MAX_WORKER_REQUEST_FULL_MESSAGE_BYTES: usize = 16 * 1024;
pub(crate) const MAX_WORKER_REQUEST_WEBAUTHN_CLIENT_DATA_JSON_BYTES: usize = 16 * 1024;
pub(crate) const MAX_WORKER_REQUEST_WEBAUTHN_AUTHENTICATOR_DATA_BYTES: usize = 4 * 1024;
pub(crate) const MAX_WORKER_REQUEST_KEYLESS_ISS_BYTES: usize = 512;
pub(crate) const MAX_WORKER_REQUEST_KEYLESS_JWT_HEADER_BYTES: usize = 2 * 1024;

pub(super) fn validate_worker_request(request: &WorkerRequest) -> Result<()> {
    match request {
        WorkerRequest::DecryptionBasicFlow(req) => {
            validate_decryption_payload(&req.payload, "basic.payload")?;
            let ProofOfPermission::Aptos(proof) = &req.proof;
            validate_aptos_proof(proof, "basic.proof")
        }
        WorkerRequest::DecryptionCustomFlow(req) => {
            validate_contract_id(&req.contract_id, "custom.contract_id")?;
            check_len(
                "custom.label",
                req.label.len(),
                MAX_WORKER_REQUEST_LABEL_BYTES,
            )?;
            validate_custom_proof(&req.proof, "custom.proof")
        }
        WorkerRequest::ThresholdVrf(req) => {
            validate_vrf_payload(&req.payload, "vrf.payload")?;
            validate_aptos_proof(&req.auth_proof, "vrf.auth_proof")
        }
    }
}

fn validate_decryption_payload(payload: &DecryptionRequestPayload, context: &str) -> Result<()> {
    validate_contract_id(&payload.contract_id, &format!("{context}.contract_id"))?;
    check_len(
        &format!("{context}.domain"),
        payload.domain.len(),
        MAX_WORKER_REQUEST_LABEL_BYTES,
    )
}

fn validate_vrf_payload(payload: &ThresholdVrfRequestPayload, context: &str) -> Result<()> {
    validate_contract_id(&payload.contract_id, &format!("{context}.contract_id"))?;
    check_len(
        &format!("{context}.label"),
        payload.label.len(),
        MAX_WORKER_REQUEST_LABEL_BYTES,
    )
}

fn validate_contract_id(contract_id: &ContractId, context: &str) -> Result<()> {
    let ContractId::Aptos(contract) = contract_id;
    check_len(
        &format!("{context}.module_name"),
        contract.module_name.len(),
        MAX_WORKER_REQUEST_MODULE_NAME_BYTES,
    )
}

fn validate_custom_proof(proof: &CustomFlowProof, context: &str) -> Result<()> {
    let CustomFlowProof::Aptos(payload) = proof;
    check_len(
        &format!("{context}.aptos_payload"),
        payload.len(),
        MAX_WORKER_REQUEST_CUSTOM_PAYLOAD_BYTES,
    )
}

fn validate_aptos_proof(proof: &AptosProofOfPermission, context: &str) -> Result<()> {
    check_len(
        &format!("{context}.full_message"),
        proof.full_message.len(),
        MAX_WORKER_REQUEST_FULL_MESSAGE_BYTES,
    )?;
    validate_public_key_material(
        &proof.public_key_payload,
        &format!("{context}.public_key_payload"),
    )?;
    validate_signature_material(
        &proof.signature_payload,
        &format!("{context}.signature_payload"),
    )
}

fn validate_public_key_material(pk: &AptosPublicKeyMaterial, context: &str) -> Result<()> {
    match pk {
        AptosPublicKeyMaterial::Any(inner) => validate_any_public_key(inner, context),
        AptosPublicKeyMaterial::MultiKey(multi_key) => {
            for (i, inner) in multi_key.public_keys.iter().enumerate() {
                validate_any_public_key(inner, &format!("{context}.public_keys[{i}]"))?;
            }
            Ok(())
        }
        AptosPublicKeyMaterial::Keyless(pk) => validate_keyless_public_key(pk, context),
        AptosPublicKeyMaterial::FederatedKeyless(pk) => {
            validate_keyless_public_key(&pk.pk, &format!("{context}.pk"))
        }
        _ => Ok(()),
    }
}

fn validate_any_public_key(pk: &AnyPublicKeyInner, context: &str) -> Result<()> {
    match pk {
        AnyPublicKeyInner::Keyless(pk) => validate_keyless_public_key(pk, context),
        AnyPublicKeyInner::FederatedKeyless(pk) => {
            validate_keyless_public_key(&pk.pk, &format!("{context}.pk"))
        }
        _ => Ok(()),
    }
}

fn validate_keyless_public_key(
    pk: &aptos_keyless_common::KeylessPublicKey,
    context: &str,
) -> Result<()> {
    check_len(
        &format!("{context}.iss_val"),
        pk.iss_val.len(),
        MAX_WORKER_REQUEST_KEYLESS_ISS_BYTES,
    )
}

fn validate_signature_material(sig: &AptosSignatureMaterial, context: &str) -> Result<()> {
    match sig {
        AptosSignatureMaterial::Any(inner) => validate_any_signature(inner, context),
        AptosSignatureMaterial::MultiKey(multi_key) => {
            for (i, inner) in multi_key.signatures.iter().enumerate() {
                validate_any_signature(inner, &format!("{context}.signatures[{i}]"))?;
            }
            Ok(())
        }
        AptosSignatureMaterial::Keyless(sig) => validate_keyless_signature(sig, context),
        _ => Ok(()),
    }
}

fn validate_any_signature(sig: &AnySignatureInner, context: &str) -> Result<()> {
    match sig {
        AnySignatureInner::WebAuthn(assertion) => {
            let AssertionSignature::Secp256r1Ecdsa(signature) = &assertion.signature;
            check_len(
                &format!("{context}.webauthn.signature"),
                signature.len(),
                64,
            )?;
            check_len(
                &format!("{context}.webauthn.authenticator_data"),
                assertion.authenticator_data.len(),
                MAX_WORKER_REQUEST_WEBAUTHN_AUTHENTICATOR_DATA_BYTES,
            )?;
            check_len(
                &format!("{context}.webauthn.client_data_json"),
                assertion.client_data_json.len(),
                MAX_WORKER_REQUEST_WEBAUTHN_CLIENT_DATA_JSON_BYTES,
            )
        }
        AnySignatureInner::Keyless(sig) => validate_keyless_signature(sig, context),
        _ => Ok(()),
    }
}

fn validate_keyless_signature(
    sig: &aptos_keyless_common::KeylessSignature,
    context: &str,
) -> Result<()> {
    check_len(
        &format!("{context}.jwt_header_json"),
        sig.jwt_header_json.len(),
        MAX_WORKER_REQUEST_KEYLESS_JWT_HEADER_BYTES,
    )
}

fn check_len(field: &str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(anyhow!("{field} length {actual} exceeds max {max}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{
        DecryptionBasicFlowRequest, DecryptionCustomFlowRequest, ProofOfPermission,
        ThresholdVrfRequest, ThresholdVrfRequestPayload,
    };
    use vss_common::pke::EncryptionKey;
    use vss_common::pke_hpke_x25519_chacha20poly1305 as hpke;

    fn contract() -> ContractId {
        ContractId::Aptos(super::super::AptosContractId {
            chain_id: 4,
            module_addr: [0x42; 32],
            module_name: "acl".to_string(),
        })
    }

    fn enc_key() -> EncryptionKey {
        EncryptionKey::HpkeX25519ChaCha20Poly1305(hpke::EncryptionKey { pk: vec![7u8; 32] })
    }

    fn aptos_proof(full_message: String) -> ProofOfPermission {
        ProofOfPermission::Aptos(AptosProofOfPermission {
            user_addr: [0x11; 32],
            public_key_payload: AptosPublicKeyMaterial::Ed25519([0x22; 32]),
            signature_payload: AptosSignatureMaterial::Ed25519([0x33; 64]),
            full_message,
        })
    }

    fn decryption_payload(domain: Vec<u8>) -> DecryptionRequestPayload {
        DecryptionRequestPayload {
            keypair_id: [0x44; 32],
            epoch: 9,
            contract_id: contract(),
            domain,
            ephemeral_enc_key: enc_key(),
        }
    }

    #[test]
    fn rejects_oversized_basic_domain() {
        let request = WorkerRequest::DecryptionBasicFlow(DecryptionBasicFlowRequest {
            payload: decryption_payload(vec![0u8; MAX_WORKER_REQUEST_LABEL_BYTES + 1]),
            proof: aptos_proof("APTOS\nmessage: 0x00".to_string()),
            tibe_scheme: 1,
        });

        let err = request.validate_size_limits().unwrap_err().to_string();
        assert!(err.contains("basic.payload.domain length"));
    }

    #[test]
    fn rejects_oversized_custom_payload() {
        let request = WorkerRequest::DecryptionCustomFlow(DecryptionCustomFlowRequest {
            keypair_id: [0x44; 32],
            epoch: 9,
            contract_id: contract(),
            label: b"ok".to_vec(),
            enc_pk: enc_key(),
            proof: CustomFlowProof::Aptos(vec![0u8; MAX_WORKER_REQUEST_CUSTOM_PAYLOAD_BYTES + 1]),
            tibe_scheme: 1,
        });

        let err = request.validate_size_limits().unwrap_err().to_string();
        assert!(err.contains("custom.proof.aptos_payload length"));
    }

    #[test]
    fn rejects_oversized_vrf_full_message() {
        let request = WorkerRequest::ThresholdVrf(ThresholdVrfRequest {
            payload: ThresholdVrfRequestPayload {
                keypair_id: [0x44; 32],
                epoch: 9,
                contract_id: contract(),
                label: b"ok".to_vec(),
                account_address: [0x11; 32],
                response_enc_key: enc_key(),
            },
            auth_proof: AptosProofOfPermission {
                user_addr: [0x11; 32],
                public_key_payload: AptosPublicKeyMaterial::Ed25519([0x22; 32]),
                signature_payload: AptosSignatureMaterial::Ed25519([0x33; 64]),
                full_message: "x".repeat(MAX_WORKER_REQUEST_FULL_MESSAGE_BYTES + 1),
            },
        });

        let err = request.validate_size_limits().unwrap_err().to_string();
        assert!(err.contains("vrf.auth_proof.full_message length"));
    }
}
