// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Wire-format types for `WorkerRequest` and proof-of-permission verification.
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
use solana::SolanaContractId;
pub use solana::SolanaProofOfPermission;

// ── Wire types ────────────────────────────────────────────────────────────────

/// Top-level request body. Outer enum tag picks the flow.
///
/// Decryption variants carry an explicit `tibe_scheme: u8` so the handler can serve
/// shares formatted for the client's actual t-IBE choice, rather than guessing
/// it from the share's group scheme via a hard-coded 1:1 mapping.
///
/// BCS discriminants:
///   0 = BasicDecryption
///   1 = CustomDecryption
///   2 = ThresholdVrf
#[derive(Serialize, Deserialize)]
pub enum WorkerRequest {
    BasicDecryption(BasicDecryptionRequest),
    CustomDecryption(CustomDecryptionRequest),
    ThresholdVrf(ThresholdVrfRequest),
}

/// The 5 fields the wallet signs over for a basic-flow request. Mirrors the
/// TS-side `DecryptionRequestPayload` class — same field order, BCS-identical
/// wire shape. The `proof` lives one level up in [`BasicFlowRequest`] /
/// [`BasicDecryptionRequest`], not here, because the proof is *about* this
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
pub struct BasicDecryptionRequest {
    pub payload: DecryptionRequestPayload,
    pub proof: ProofOfPermission,
    /// Client-asserted t-IBE scheme the share should be formatted for.
    /// The handler validates `t_ibe_scheme_group(tibe_scheme) == share.group_scheme`.
    pub tibe_scheme: u8,
}

#[derive(Serialize, Deserialize)]
pub struct CustomDecryptionRequest {
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

    /// Canonical human-readable form the wallet signs for the Flavor-A proof
    /// path (Ed25519, Secp256k1, Keyless, FederatedKeyless). Mirrors the TS-side
    /// `DecryptionRequestPayload.toPrettyMessage(0)` in
    /// `ts-sdk/src/_internal/common.ts` byte-for-byte. Field order matches:
    ///
    /// ```text
    /// ACE Decryption Request
    /// keypairId: 0x<32 hex>
    /// epoch: <u64>
    /// contractId:
    ///   scheme: aptos
    ///   inner:
    ///       chainId: <u8>
    ///       moduleAddr: 0x<32 hex>
    ///       moduleName: <string>
    /// domain: 0x<hex>
    /// ephemeralEncKey: <hex of BCS(EncryptionKey), no 0x>
    /// ```
    ///
    /// The verifier's binding step requires the wallet's `fullMessage` to
    /// contain this string (or its hex form, for AptosConnect wallets that
    /// sign the hex of the UTF-8). Binding `ephemeralEncKey` is critical: it
    /// is the public key the IDK share is encrypted to in the response. If it
    /// were not part of the signed message, anyone holding a valid proof
    /// could replay it with a substituted `ephemeralEncKey` and have shares
    /// re-encrypted to themselves.
    ///
    /// Returns an error if `self.contract_id` is not an Aptos contract — only
    /// Flavor-A Aptos proofs use this pretty-message binding; Solana proofs
    /// carry a real transaction and do not use a signed pretty message.
    pub fn to_pretty_message(&self) -> Result<String> {
        let contract_lines = self.contract_id.to_pretty_message_lines(1)?;
        let ephemeral_ek_bytes = bcs::to_bytes(&self.ephemeral_enc_key).map_err(|e| {
            anyhow!(
                "DecryptionRequestPayload::to_pretty_message: serialize ephemeral_enc_key: {}",
                e
            )
        })?;
        Ok(format!(
            "ACE Decryption Request\nkeypairId: 0x{}\nepoch: {}\ncontractId:{}\ndomain: 0x{}\nephemeralEncKey: {}",
            hex::encode(self.keypair_id),
            self.epoch,
            contract_lines,
            hex::encode(&self.domain),
            hex::encode(&ephemeral_ek_bytes),
        ))
    }
}

const THRESHOLD_VRF_PURPOSE: &str = "ace.threshold-vrf.derive.v1";

impl ThresholdVrfRequestPayload {
    /// Canonical human-readable form the owner signs for tVRF derivation.
    /// The TS-SDK will need to mirror this byte-for-byte when its tVRF origin
    /// binding is updated.
    pub fn to_pretty_message(&self) -> Result<String> {
        let response_ek_bytes = bcs::to_bytes(&self.response_enc_key).map_err(|e| {
            anyhow!(
                "ThresholdVrfRequestPayload::to_pretty_message: serialize response_enc_key: {}",
                e
            )
        })?;
        Ok(format!(
            "ACE Threshold VRF Derive Request\npurpose: {}\nkeypairId: 0x{}\nepoch: {}\ncontractId:{}\nlabel: 0x{}\naccountAddress: 0x{}\nresponseEncKey: {}",
            THRESHOLD_VRF_PURPOSE,
            hex::encode(self.keypair_id),
            self.epoch,
            self.contract_id.to_pretty_message_lines(1)?,
            hex::encode(&self.label),
            hex::encode(self.account_address),
            hex::encode(response_ek_bytes),
        ))
    }

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

impl ContractId {
    /// Mirrors TS-SDK `ContractID.toPrettyMessage(indent)` in
    /// `ts-sdk/src/_internal/common.ts:108-113`. Returns the inner block
    /// (`\n{pad}scheme: <name>\n{pad}inner:<inner_lines>`) with `pad =
    /// "  " * indent`. The inner-variant lines are produced at `indent + 2`,
    /// matching the TS step. Errors for variants without a pretty-message
    /// path (Solana's proof is a real txn, not a signed canonical string).
    pub(crate) fn to_pretty_message_lines(&self, indent: usize) -> Result<String> {
        let pad = "  ".repeat(indent);
        match self {
            ContractId::Aptos(c) => Ok(format!(
                "\n{pad}scheme: aptos\n{pad}inner:{}",
                c.to_pretty_message_lines(indent + 2),
            )),
            ContractId::Solana(_) => Err(anyhow!(
                "ContractId::to_pretty_message_lines: Solana proofs are not bound via a signed pretty message"
            )),
        }
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
/// The Aptos side derives the ephemeral-key hex from `req.payload.ephemeral_enc_key`
/// itself (via [`DecryptionRequestPayload::to_pretty_message`]); only the Solana
/// path needs the pre-serialized bytes for its `build_full_request_bytes` shape.
pub async fn verify_basic(req: &BasicFlowRequest, chain_rpc: &ChainRpcConfig) -> Result<()> {
    match (&req.payload.contract_id, &req.proof) {
        (ContractId::Aptos(contract), ProofOfPermission::Aptos(proof)) => {
            aptos::verify_aptos(req, contract, proof, chain_rpc).await
        }
        (ContractId::Solana(contract), ProofOfPermission::Solana(proof)) => {
            let ephemeral_ek_bytes = bcs::to_bytes(&req.payload.ephemeral_enc_key)
                .map_err(|e| anyhow!("verify_basic: serialize ephemeral_enc_key: {}", e))?;
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
    let enc_pk_bytes = bcs::to_bytes(&req.enc_pk)
        .map_err(|e| anyhow!("verify_custom: serialize enc_pk: {}", e))?;

    match (&req.contract_id, &req.proof) {
        (ContractId::Aptos(contract), CustomFlowProof::Aptos(payload)) => {
            aptos::verify_custom_aptos(contract, &req.label, &enc_pk_bytes, payload, chain_rpc)
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

/// Verify a threshold-VRF derivation request: the account proof must sign the
/// tVRF transcript, the proof account must match the requested account address,
/// and the supplied public key must still be the on-chain auth key for that
/// account.
pub async fn verify_threshold_vrf(
    req: &ThresholdVrfRequest,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    aptos::verify_threshold_vrf_aptos(req, chain_rpc).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana::SolanaContractId;
    use vss_common::pke::{ElGamalOtpRistretto255EncKey, EncryptionKey};

    /// Pin down the exact pretty-message output for a hand-built Aptos payload.
    /// Mirrors `ts-sdk/src/_internal/common.ts:341-344`'s `toPrettyMessage(0)`
    /// byte-for-byte (verified by hand against the template). If this string
    /// ever drifts, every wallet that has been signing the old shape will
    /// stop passing the `contains()` binding check in the verifier — so this
    /// test deliberately hard-codes the expected bytes rather than
    /// recomputing them with `format!`.
    #[test]
    fn to_pretty_message_aptos_known_answer() {
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
        // BCS(EncryptionKey::ElGamalOtpRistretto255) = variant tag 0x00
        //   || ULEB128(32)=0x20 || 32×0x11 || ULEB128(32)=0x20 || 32×0x22.
        let expected = concat!(
            "ACE Decryption Request\n",
            "keypairId: 0xabababababababababababababababababababababababababababababababab\n",
            "epoch: 42\n",
            "contractId:\n",
            "  scheme: aptos\n",
            "  inner:\n",
            "      chainId: 4\n",
            "      moduleAddr: 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\n",
            "      moduleName: my_module\n",
            "domain: 0x01020304\n",
            "ephemeralEncKey: 00201111111111111111111111111111111111111111111111111111111111111111202222222222222222222222222222222222222222222222222222222222222222",
        );
        assert_eq!(payload.to_pretty_message().unwrap(), expected);
    }

    /// Solana payloads don't have a signed pretty-message path (the proof is
    /// a real Solana transaction). Calling the method must surface a clear
    /// error rather than producing a nonsense string.
    #[test]
    fn to_pretty_message_solana_errors() {
        let payload = DecryptionRequestPayload {
            keypair_id: [0; 32],
            epoch: 0,
            contract_id: ContractId::Solana(SolanaContractId {
                known_chain_name: "devnet".to_string(),
                program_id: vec![0; 32],
            }),
            domain: vec![],
            ephemeral_enc_key: EncryptionKey::ElGamalOtpRistretto255(
                ElGamalOtpRistretto255EncKey {
                    enc_base: vec![0; 32],
                    public_point: vec![0; 32],
                },
            ),
        };
        let err = payload.to_pretty_message().unwrap_err().to_string();
        assert!(
            err.contains("Solana"),
            "expected Solana-rejection error, got: {}",
            err
        );
    }
}
