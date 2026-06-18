// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Wire-format types for `WorkerRequest` and proof-of-permission verification.
//!
//! The on-the-wire request layout mirrors `ts-sdk/src/_internal/common.ts` and is decoded
//! in one shot via `bcs::from_bytes` (`#[derive(Serialize, Deserialize)]` on every nested
//! type — except [`AptosProofOfPermission`], which has hand-rolled serde that
//! dispatches on `pk_scheme` / `sig_scheme`).  Adding a new variant — chain, proof
//! scheme, flow — is one new enum arm.
//!
//! Verification entry points:
//!   - [`verify_basic`] — checks an `AptosProofOfPermission` (Ed25519 or keyless: sig +
//!     auth-key + permission view) or `SolanaProofOfPermission` (txn structure + RPC
//!     simulation).
//!   - [`verify_custom`] — checks a custom-flow ACL view (Aptos) or Solana
//!     custom-instruction.
//!
//! Mirrors `verifyAndExtract` and its helpers in `ts-sdk/src/ace-ex/{aptos,solana}.ts`.
//!
//! Module layout:
//!   - `verify` (this file) — outer-envelope wire types + flow dispatch
//!   - `ibe_aptos_basic_flow`
//!   - `ibe_aptos_custom_flow`
//!   - `ibe_solana_basic_flow`
//!   - `ibe_solana_custom_flow`
//!   - `vrf_aptos`

mod ibe_aptos_basic_flow;
mod ibe_aptos_custom_flow;
mod ibe_solana_basic_flow;
mod ibe_solana_custom_flow;
mod vrf_aptos;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use vss_common::pke::EncryptionKey;

use crate::ChainRpcConfig;

pub use ibe_aptos_basic_flow::{
    AptosContractId, AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};
use ibe_solana_basic_flow::SolanaContractId;
pub use ibe_solana_basic_flow::SolanaProofOfPermission;

// ── Wire types ────────────────────────────────────────────────────────────────

/// Top-level request body. Outer enum tag picks the flow.
///
/// Decryption variants carry an explicit `tibe_scheme: u8` so the handler can serve
/// shares formatted for the client's actual t-IBE choice, rather than guessing
/// it from the share's group scheme via a hard-coded 1:1 mapping.
///
/// BCS discriminants:
///   0 = DecryptionBasicFlow
///   1 = DecryptionCustomFlow
///   2 = ThresholdVrf
#[derive(Serialize, Deserialize)]
pub enum WorkerRequest {
    DecryptionBasicFlow(DecryptionBasicFlowRequest),
    DecryptionCustomFlow(DecryptionCustomFlowRequest),
    ThresholdVrf(ThresholdVrfRequest),
}

/// The 5 fields the wallet signs over for a basic-flow request. Mirrors the
/// TS-side `DecryptionRequestPayload` class — same field order, BCS-identical
/// wire shape. The `proof` lives one level up in [`BasicFlowRequest`] /
/// [`DecryptionBasicFlowRequest`], not here, because the proof is *about* this
/// payload (it carries a signature over it).
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
    /// Client-asserted t-IBE scheme the share should be formatted for.
    /// The handler validates both the share's group and its on-chain usage mask.
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
    Solana(SolanaContractId),
}

#[derive(Serialize, Deserialize)]
pub enum ProofOfPermission {
    Aptos(AptosProofOfPermission),
    Solana(SolanaProofOfPermission),
}

#[derive(Serialize, Deserialize)]
pub enum CustomFlowProof {
    /// Aptos custom flow carries a free-form payload that the configured ACL view
    /// will interpret. The worker just relays it.
    Aptos(Vec<u8>),
    Solana(SolanaProofOfPermission),
}

impl ContractId {
    fn tag_name(&self) -> &'static str {
        match self {
            ContractId::Aptos(_) => "aptos",
            ContractId::Solana(_) => "solana",
        }
    }
}

impl ProofOfPermission {
    fn tag_name(&self) -> &'static str {
        match self {
            ProofOfPermission::Aptos(_) => "aptos",
            ProofOfPermission::Solana(_) => "solana",
        }
    }
}

impl CustomFlowProof {
    fn tag_name(&self) -> &'static str {
        match self {
            CustomFlowProof::Aptos(_) => "aptos",
            CustomFlowProof::Solana(_) => "solana",
        }
    }
}

impl DecryptionRequestPayload {
    /// 32-byte WebAuthn challenge bytes for this payload — mirrors the TS-side
    /// `DecryptionRequestPayload.toWebAuthnChallenge()`:
    ///
    ///   `SHA3-256( SHA3-256(b"ACE::DecryptionRequestPayload") || BCS(self) )`
    ///
    /// Used by the `AnyPublicKey<Secp256r1Ecdsa>+AnySignature<WebAuthn>`
    /// (passkeys) verifier to recompute what `clientDataJSON.challenge`
    /// should base64url-decode to. Pattern mirrors aptos-core's
    /// `CryptoHasher` derive — `SHA3-256(b"APTOS::" || TypeName)` seed,
    /// then `SHA3-256(seed || BCS(value))` for the final digest.
    pub fn to_webauthn_challenge(&self) -> Result<[u8; 32]> {
        use sha3::{Digest, Sha3_256};
        let seed: [u8; 32] = Sha3_256::digest(b"ACE::DecryptionRequestPayload").into();
        let body = bcs::to_bytes(self).map_err(|e| {
            anyhow!(
                "DecryptionRequestPayload::to_webauthn_challenge: BCS encode: {}",
                e
            )
        })?;
        let mut h = Sha3_256::new();
        h.update(seed);
        h.update(&body);
        Ok(h.finalize().into())
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

// ── Identity bytes ────────────────────────────────────────────────────────────

/// IBE identity = `keypair_id (32B raw) ++ BCS(contract_id) ++ BCS(domain)`. This is the
/// same identity TS computes when encrypting (`FullDecryptionDomain.toBytes()`).
pub fn identity_bytes(keypair_id: &[u8; 32], contract_id: &ContractId, domain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(keypair_id);
    out.extend(bcs::to_bytes(contract_id).expect("BCS"));
    out.extend(bcs::to_bytes(domain).expect("BCS"));
    out
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// Verify a basic-flow request: checks the proof-of-permission and binds it to the
/// keypair_id, epoch, contract_id, domain, and ephemeral encryption key in `req`.
///
/// The Aptos side binds via `"0x" || hex(BCS(payload))` appearing in the wallet's
/// `fullMessage` (see [`ibe_aptos_basic_flow::AptosPayloadBinding::to_signed_message_hex`]); only
/// the Solana path needs the pre-serialized bytes for its `build_full_request_bytes`
/// shape.
pub async fn verify_basic(req: &BasicFlowRequest, chain_rpc: &ChainRpcConfig) -> Result<()> {
    match (&req.payload.contract_id, &req.proof) {
        (ContractId::Aptos(contract), ProofOfPermission::Aptos(proof)) => {
            ibe_aptos_basic_flow::verify_aptos(req, contract, proof, chain_rpc).await
        }
        (ContractId::Solana(contract), ProofOfPermission::Solana(proof)) => {
            let ephemeral_ek_bytes = bcs::to_bytes(&req.payload.ephemeral_enc_key)
                .map_err(|e| anyhow!("verify_basic: serialize ephemeral_enc_key: {}", e))?;
            ibe_solana_basic_flow::verify(req, contract, proof, &ephemeral_ek_bytes, chain_rpc)
                .await
        }
        (contract, proof) => Err(anyhow!(
            "verify_basic: contract/proof scheme mismatch (contract={}, proof={})",
            contract.tag_name(),
            proof.tag_name()
        )),
    }
}

/// Verify a custom-flow request: dispatches to the chain-specific ACL check.
pub async fn verify_custom(req: &CustomFlowRequest, chain_rpc: &ChainRpcConfig) -> Result<()> {
    let enc_pk_bytes = bcs::to_bytes(&req.enc_pk)
        .map_err(|e| anyhow!("verify_custom: serialize enc_pk: {}", e))?;

    match (&req.contract_id, &req.proof) {
        (ContractId::Aptos(contract), CustomFlowProof::Aptos(payload)) => {
            ibe_aptos_custom_flow::verify(contract, &req.label, &enc_pk_bytes, payload, chain_rpc)
                .await
        }
        (ContractId::Solana(contract), CustomFlowProof::Solana(proof)) => {
            ibe_solana_custom_flow::verify(req, contract, proof, &enc_pk_bytes, chain_rpc).await
        }
        (contract, proof) => Err(anyhow!(
            "verify_custom: contract/proof scheme mismatch (contract={}, proof={})",
            contract.tag_name(),
            proof.tag_name()
        )),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use vss_common::pke::{ElGamalOtpRistretto255EncKey, EncryptionKey};

    /// Pin down the exact `"0x" || hex(BCS(payload))` form for a hand-built
    /// Aptos payload. The wallet signs an AIP-62 wrap whose `message:` value
    /// is this string; the worker reconstructs it from the request and looks
    /// for it as a substring of `fullMessage`. If the BCS layout drifts,
    /// signatures from all wallets stop verifying — so the expected hex is
    /// pinned literally.
    #[test]
    fn signed_message_hex_aptos_known_answer() {
        use super::ibe_aptos_basic_flow::AptosPayloadBinding;
        let payload = DecryptionRequestPayload {
            keypair_id: [0xab; 32],
            epoch: 42,
            contract_id: ContractId::Aptos(AptosContractId {
                chain_id: 4,
                module_addr: [0xcd; 32],
                module_name: "my_module".to_string(),
            }),
            domain: vec![0x01, 0x02, 0x03, 0x04],
            ephemeral_enc_key: EncryptionKey::ElGamalOtpRistretto255(
                ElGamalOtpRistretto255EncKey {
                    enc_base: vec![0x11; 32],
                    public_point: vec![0x22; 32],
                },
            ),
        };
        // BCS layout:
        //   keypair_id [32] = 32×0xab
        //   epoch (u64 LE)  = 0x2a 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        //   contract_id (tag=0 Aptos)
        //     chain_id (u8)    = 0x04
        //     module_addr [32] = 32×0xcd
        //     module_name      = ULEB(9) "my_module"
        //   domain (vec<u8>) = ULEB(4) 0x01 0x02 0x03 0x04
        //   ephemeral_enc_key (tag=0 ElGamalOtpRistretto255)
        //     enc_base     = ULEB(32) 32×0x11
        //     public_point = ULEB(32) 32×0x22
        let expected = concat!(
            "0x",
            "abababababababababababababababababababababababababababababababab",
            "2a00000000000000",
            "00",
            "04",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "096d795f6d6f64756c65",
            "0401020304",
            "00",
            "201111111111111111111111111111111111111111111111111111111111111111",
            "202222222222222222222222222222222222222222222222222222222222222222",
        );
        assert_eq!(payload.to_signed_message_hex().unwrap(), expected);
    }
}
