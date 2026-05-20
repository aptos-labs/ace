// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Wire-format types for `RequestForDecryptionKey` and proof-of-permission verification.
//!
//! The on-the-wire request layout mirrors `ts-sdk/src/_internal/common.ts` and is decoded
//! in one shot via `bcs::from_bytes` (`#[derive(Serialize, Deserialize)]` on every nested
//! type — except [`aptos::AptosProofOfPermission`], which has hand-rolled serde that
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
//!   - `verify` (this file)  — outer-envelope wire types + flow dispatch
//!   - `verify::aptos`        — Aptos-shared: proof-of-permission types, scheme dispatch,
//!                              permission-view + pretty-message helpers
//!   - `verify::aptos::ed25519` — legacy Ed25519 PoP path
//!   - `verify::aptos::keyless` — keyless ZK PoP path
//!   - `verify::solana`       — Solana txn parsing + RPC simulation

pub mod aptos;
pub mod solana;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use vss_common::pke::EncryptionKey;

use crate::ChainRpcConfig;

pub use aptos::{
    AptosContractId, AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};
pub use solana::SolanaProofOfPermission;
use solana::SolanaContractId;

// ── Wire types ────────────────────────────────────────────────────────────────

/// Top-level request body. Outer enum tag picks the flow and wire version.
///
/// V2 variants carry an explicit `tibe_scheme: u8` so the handler can serve
/// shares formatted for the client's actual t-IBE choice, rather than guessing
/// it from the share's group scheme via a hard-coded 1:1 mapping. V1 variants
/// stay for backwards compatibility with older clients; the handler falls
/// back to [`crate::crypto::tibe_scheme_for_group`] for those.
///
/// BCS discriminants:
///   0 = Basic    (V1; legacy, no tibe_scheme field)
///   1 = Custom   (V1; legacy)
///   2 = BasicV2  (carries tibe_scheme)
///   3 = CustomV2 (carries tibe_scheme)
#[derive(Serialize, Deserialize)]
pub enum RequestForDecryptionKey {
    Basic(BasicFlowRequest),
    Custom(CustomFlowRequest),
    BasicV2(BasicFlowRequestV2),
    CustomV2(CustomFlowRequestV2),
}

/// The 5 fields the wallet signs over for a basic-flow request. Mirrors the
/// TS-side `DecryptionRequestPayload` class — same field order, BCS-identical
/// wire shape. The `proof` lives one level up in [`BasicFlowRequest`] /
/// [`BasicFlowRequestV2`], not here, because the proof is *about* this
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

/// The 5 fields that bind a custom-flow request to its application context.
/// Parallel to [`DecryptionRequestPayload`] but for the custom-flow wire —
/// `label` and `enc_pk` replace `domain` and `ephemeral_enc_key` respectively
/// since custom-flow ciphertexts have a different application contract.
#[derive(Serialize, Deserialize)]
pub struct CustomFlowPayload {
    pub keypair_id: [u8; 32],
    pub epoch: u64,
    pub contract_id: ContractId,
    pub label: Vec<u8>,
    pub enc_pk: EncryptionKey,
}

#[derive(Serialize, Deserialize)]
pub struct CustomFlowRequest {
    pub payload: CustomFlowPayload,
    pub proof: CustomFlowProof,
}

#[derive(Serialize, Deserialize)]
pub struct BasicFlowRequestV2 {
    pub payload: DecryptionRequestPayload,
    pub proof: ProofOfPermission,
    /// Client-asserted t-IBE scheme the share should be formatted for.
    /// The handler validates `t_ibe_scheme_group(tibe_scheme) == share.group_scheme`.
    pub tibe_scheme: u8,
}

#[derive(Serialize, Deserialize)]
pub struct CustomFlowRequestV2 {
    pub payload: CustomFlowPayload,
    pub proof: CustomFlowProof,
    pub tibe_scheme: u8,
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
        let body = bcs::to_bytes(self)
            .map_err(|e| anyhow!("DecryptionRequestPayload::to_webauthn_challenge: BCS encode: {}", e))?;
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
pub async fn verify_basic(req: &BasicFlowRequest, chain_rpc: &ChainRpcConfig) -> Result<()> {
    let ephemeral_ek_bytes = bcs::to_bytes(&req.payload.ephemeral_enc_key)
        .map_err(|e| anyhow!("verify_basic: serialize ephemeral_enc_key: {}", e))?;

    match (&req.payload.contract_id, &req.proof) {
        (ContractId::Aptos(contract), ProofOfPermission::Aptos(proof)) => {
            aptos::verify_aptos(req, contract, proof, &ephemeral_ek_bytes, chain_rpc).await
        }
        (ContractId::Solana(contract), ProofOfPermission::Solana(proof)) => {
            solana::verify_solana(req, contract, proof, &ephemeral_ek_bytes, chain_rpc).await
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
    let enc_pk_bytes = bcs::to_bytes(&req.payload.enc_pk)
        .map_err(|e| anyhow!("verify_custom: serialize enc_pk: {}", e))?;

    match (&req.payload.contract_id, &req.proof) {
        (ContractId::Aptos(contract), CustomFlowProof::Aptos(payload)) => {
            aptos::verify_custom_aptos(contract, &req.payload.label, &enc_pk_bytes, payload, chain_rpc)
                .await
        }
        (ContractId::Solana(contract), CustomFlowProof::Solana(proof)) => {
            solana::verify_custom_solana(req, contract, proof, &enc_pk_bytes, chain_rpc).await
        }
        (contract, proof) => Err(anyhow!(
            "verify_custom: contract/proof scheme mismatch (contract={}, proof={})",
            contract.tag_name(),
            proof.tag_name()
        )),
    }
}
