// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Wire-format types for worker requests and Aptos application-layer request
//! verification.
//!
//! The on-the-wire request layout mirrors `ts-sdk/src/_internal/common.ts` and
//! is decoded in one shot via `bcs::from_bytes`. Aptos key/signature material
//! carries its own `pk_scheme` / `sig_scheme` wire tag, matching the TS SDK's
//! inline layout.
//!
mod ibe_aptos_basic_flow;
mod ibe_aptos_custom_flow;
mod limits;
mod shared;
mod vrf_aptos;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use vss_common::pke::EncryptionKey;

use crate::ChainRpcConfig;

pub use self::shared::aptos::{
    AptosContractId, AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};

pub(crate) use limits::MAX_WORKER_REQUEST_PLAINTEXT_BYTES;

#[derive(Serialize, Deserialize)]
pub enum WorkerRequest {
    DecryptionBasicFlow(DecryptionBasicFlowRequest),
    DecryptionCustomFlow(DecryptionCustomFlowRequest),
    ThresholdVrf(ThresholdVrfRequest),
}

impl WorkerRequest {
    pub(crate) fn validate_size_limits(&self) -> Result<()> {
        limits::validate_worker_request(self)
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptionRequestPayload {
    pub keypair_id: [u8; 32],
    pub epoch: u64,
    pub contract_id: ContractId,
    pub domain: Vec<u8>,
    pub ephemeral_enc_key: EncryptionKey,
}

#[derive(Serialize, Deserialize)]
pub struct BasicFlowRequest {
    pub payload: DecryptionRequestPayload,
    pub proof: ProofOfPermission,
}

#[derive(Serialize, Deserialize)]
pub struct CustomFlowRequest {
    pub keypair_id: [u8; 32],
    pub epoch: u64,
    pub contract_id: ContractId,
    pub label: Vec<u8>,
    pub enc_pk: EncryptionKey,
    pub proof: CustomFlowProof,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptionBasicFlowRequest {
    pub payload: DecryptionRequestPayload,
    pub proof: ProofOfPermission,
    pub tibe_scheme: u8,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptionCustomFlowRequest {
    pub keypair_id: [u8; 32],
    pub epoch: u64,
    pub contract_id: ContractId,
    pub label: Vec<u8>,
    pub enc_pk: EncryptionKey,
    pub proof: CustomFlowProof,
    pub tibe_scheme: u8,
}

#[derive(Serialize, Deserialize)]
pub struct ThresholdVrfRequestPayload {
    pub keypair_id: [u8; 32],
    pub epoch: u64,
    pub contract_id: ContractId,
    pub label: Vec<u8>,
    pub account_address: [u8; 32],
    pub response_enc_key: EncryptionKey,
}

pub type AptosAccountSignatureProof = AptosProofOfPermission;

#[derive(Serialize, Deserialize)]
pub struct ThresholdVrfRequest {
    pub payload: ThresholdVrfRequestPayload,
    pub auth_proof: AptosAccountSignatureProof,
}

#[derive(Serialize, Deserialize)]
pub enum ContractId {
    Aptos(AptosContractId),
}

#[derive(Serialize, Deserialize)]
pub enum ProofOfPermission {
    Aptos(AptosProofOfPermission),
}

#[derive(Serialize, Deserialize)]
pub enum CustomFlowProof {
    Aptos(Vec<u8>),
}

impl DecryptionRequestPayload {
    pub fn to_webauthn_challenge(&self) -> Result<[u8; 32]> {
        use sha3::{Digest, Sha3_256};
        let seed: [u8; 32] = Sha3_256::digest(b"ACE::DecryptionRequestPayload").into();
        let body = bcs::to_bytes(self).map_err(|e| {
            anyhow!(
                "DecryptionRequestPayload::to_webauthn_challenge: BCS encode: {}",
                e
            )
        })?;
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        hasher.update(body);
        Ok(hasher.finalize().into())
    }
}

impl ThresholdVrfRequestPayload {
    /// 32-byte WebAuthn challenge bytes for this payload:
    ///
    ///   `SHA3-256( SHA3-256(b"ACE::ThresholdVrfRequestPayload") || BCS(self) )`
    ///
    /// Mirrors the decryption payload's passkey binding, with a tVRF-specific
    /// domain separator so a WebAuthn assertion cannot cross flow types.
    pub fn to_webauthn_challenge(&self) -> Result<[u8; 32]> {
        use sha3::{Digest, Sha3_256};
        let seed: [u8; 32] = Sha3_256::digest(b"ACE::ThresholdVrfRequestPayload").into();
        let body = bcs::to_bytes(self).map_err(|e| {
            anyhow!(
                "ThresholdVrfRequestPayload::to_webauthn_challenge: BCS encode: {}",
                e
            )
        })?;
        let mut h = Sha3_256::new();
        h.update(seed);
        h.update(&body);
        Ok(h.finalize().into())
    }
}

/// IBE identity = raw keypair ID || BCS(contract ID) || BCS(domain).
pub fn identity_bytes(keypair_id: &[u8; 32], contract_id: &ContractId, domain: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(keypair_id);
    bytes.extend(bcs::to_bytes(contract_id).expect("ContractId BCS serialization"));
    bytes.extend(bcs::to_bytes(&domain.to_vec()).expect("domain BCS serialization"));
    bytes
}

pub async fn verify_basic(req: &BasicFlowRequest, chain_rpc: &ChainRpcConfig) -> Result<()> {
    let ContractId::Aptos(contract) = &req.payload.contract_id;
    let ProofOfPermission::Aptos(proof) = &req.proof;
    ibe_aptos_basic_flow::verify_aptos(req, contract, proof, chain_rpc).await
}

pub async fn verify_custom(req: &CustomFlowRequest, chain_rpc: &ChainRpcConfig) -> Result<()> {
    let ContractId::Aptos(contract) = &req.contract_id;
    let CustomFlowProof::Aptos(payload) = &req.proof;
    let enc_pk_bytes = bcs::to_bytes(&req.enc_pk)
        .map_err(|e| anyhow!("verify_custom: serialize enc_pk: {}", e))?;
    ibe_aptos_custom_flow::verify(contract, &req.label, &enc_pk_bytes, payload, chain_rpc).await
}

/// Verify a threshold-VRF derivation request: the account proof must sign the
/// tVRF transcript, the proof account must match the requested account address,
/// and the supplied public key must still be the on-chain auth key for that
/// account.
pub async fn verify_threshold_vrf(
    req: &ThresholdVrfRequest,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    vrf_aptos::verify(req, chain_rpc).await
}
