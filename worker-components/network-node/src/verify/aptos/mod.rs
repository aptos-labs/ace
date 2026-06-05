// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Aptos-side proof-of-permission verification.
//!
//! Owns the wire types and helpers shared between the scheme paths:
//!   - [`ed25519`] — legacy Ed25519 sig over the pretty message
//!   - [`keyless`] — ZK keyless signature
//!   - [`federated_keyless`] — ZK keyless signature with dapp-managed JWKs
//!   - [`any`] — modern `AnyPublicKey` / `AnySignature` (SingleKey scheme)
//!   - [`multi_ed25519`] — legacy K-of-N `MultiEd25519` (raw Ed25519 only)
//!   - [`multi_key`] — K-of-N `MultiKey` / `MultiKeyAuthenticator`
//!
//! The dispatcher [`verify_aptos`] matches on the typed [`AptosPublicKeyMaterial`] /
//! [`AptosSignatureMaterial`] enum payload (decoded by [`AptosProofOfPermission`]'s
//! custom serde from `pk_scheme` / `sig_scheme`) and delegates to the appropriate
//! sub-module.

pub mod any;
pub mod ed25519;
pub mod federated_keyless;
pub mod keyless;
pub mod multi_ed25519;
pub mod multi_key;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as K256Signature,
    VerifyingKey as K256VerifyingKey,
};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use crate::ChainRpcConfig;
use super::{
    BasicFlowRequest, DecryptionRequestPayload, ThresholdVrfRequest, ThresholdVrfRequestPayload,
    ThresholdVrfAuthorization,
};

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct AptosContractId {
    pub chain_id: u8,
    pub module_addr: [u8; 32],
    pub module_name: String,
    pub function_name: String,
}

impl AptosContractId {
    /// Mirrors TS-SDK `AptosContractID.toPrettyMessage(indent)` in
    /// `ts-sdk/src/_internal/aptos.ts:90-93`. Returns the 4 inner contract
    /// lines (`chainId`, `moduleAddr`, `moduleName`, `functionName`), each
    /// prefixed with a leading `\n` + `"  " * indent`. Used by
    /// [`super::ContractId::to_pretty_message_lines`] for the inner section.
    pub(crate) fn to_pretty_message_lines(&self, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        format!(
            "\n{pad}chainId: {}\n{pad}moduleAddr: 0x{}\n{pad}moduleName: {}\n{pad}functionName: {}",
            self.chain_id,
            hex::encode(self.module_addr),
            self.module_name,
            self.function_name,
        )
    }
}

/// Proof of permission for a basic-flow Aptos request.
///
/// `pk_scheme` / `sig_scheme` already disambiguate which inner type lives in
/// `public_key` / `signature` on the wire; we use those tags to deserialize
/// directly into a typed enum, no `Vec<u8>` framing. The custom serde impls
/// below match the inline encoding the TS SDK writes — see
/// `ts-sdk/src/_internal/aptos.ts`.
pub struct AptosProofOfPermission {
    pub user_addr: [u8; 32],
    pub pk_scheme: u8,
    pub public_key: AptosPublicKeyMaterial,
    pub sig_scheme: u8,
    pub signature: AptosSignatureMaterial,
    pub full_message: String,
}

/// Inner public-key payload for [`AptosProofOfPermission`].
#[derive(Clone, Debug)]
pub enum AptosPublicKeyMaterial {
    /// pk_scheme=0. BCS wire is `Vec<u8>(32 bytes)` — the natural BCS of
    /// `aptos_crypto::Ed25519PublicKey` (whose serde derive emits
    /// `serialize_bytes(&self.0)`).
    Ed25519([u8; 32]),
    /// pk_scheme=1. BCS wire is `ULEB128(any_variant) || BCS(inner)`. See
    /// [`any::AnyPublicKeyInner`] for the inner variant layout; the same
    /// account model also covers Secp256k1Ecdsa, Secp256r1Ecdsa, Keyless,
    /// and FederatedKeyless under a single SingleKey auth-key derivation.
    Any(any::AnyPublicKeyInner),
    /// pk_scheme=2. BCS wire is `serialize_bytes(pk_1 || ... || pk_N || threshold)`
    /// — the flat-concat layout from aptos-core's
    /// `MultiEd25519PublicKey::to_bytes`. Legacy K-of-N over raw Ed25519
    /// keys; auth-key derivation uses `Scheme::MultiEd25519 = 0x01`.
    MultiEd25519(multi_ed25519::MultiEd25519PublicKeyInner),
    /// pk_scheme=3. BCS wire is the inline `MultiKey` struct
    /// (`{ public_keys: Vec<AnyPublicKey>, signatures_required: u8 }`).
    /// K-of-N over the AnyPublicKey variants; auth-key derivation uses
    /// `Scheme::MultiKey = 0x03` (vs. `0x02` for SingleKey).
    MultiKey(multi_key::MultiKeyInner),
    /// pk_scheme=4. BCS wire is the inline `KeylessPublicKey` struct
    /// (`{ iss_val: String, idc: Vec<u8> }`).
    Keyless(aptos_keyless_common::KeylessPublicKey),
    /// pk_scheme=5. BCS wire is the inline `FederatedKeylessPublicKey` struct
    /// (`{ jwk_addr: [u8;32], pk: KeylessPublicKey }`). The signature carried
    /// alongside is still a `KeylessSignature` (sig_scheme=4).
    FederatedKeyless(aptos_keyless_common::FederatedKeylessPublicKey),
}

/// Inner signature payload for [`AptosProofOfPermission`].
#[derive(Clone, Debug)]
pub enum AptosSignatureMaterial {
    /// sig_scheme=0. BCS wire is `Vec<u8>(64 bytes)`.
    Ed25519([u8; 64]),
    /// sig_scheme=1. BCS wire is `ULEB128(any_variant) || BCS(inner)`. See
    /// [`any::AnySignatureInner`] — pairs with pk_scheme=1 / `AnyPublicKey`.
    Any(any::AnySignatureInner),
    /// sig_scheme=2. BCS wire is `serialize_bytes(sig_1 || ... || sig_K || bitmap[4])`
    /// — the flat-concat layout from aptos-core's
    /// `MultiEd25519Signature::to_bytes`. Pairs with pk_scheme=2 /
    /// `MultiEd25519`.
    MultiEd25519(multi_ed25519::MultiEd25519SignatureInner),
    /// sig_scheme=3. BCS wire is the inline `MultiKeyAuthenticator`
    /// signature struct (`{ signatures: Vec<AnySignature>, bitmap: Vec<u8> }`)
    /// — pairs with pk_scheme=3 / `MultiKey`. Bitmap is MSB-first per byte;
    /// position bits select which N of M positions signed.
    MultiKey(multi_key::MultiKeySigInner),
    /// sig_scheme=4. BCS wire is the inline `KeylessSignature` struct.
    Keyless(aptos_keyless_common::KeylessSignature),
}

impl AptosPublicKeyMaterial {
    fn tag_name(&self) -> &'static str {
        match self {
            AptosPublicKeyMaterial::Ed25519(_) => "ed25519",
            AptosPublicKeyMaterial::Any(_) => "any",
            AptosPublicKeyMaterial::MultiEd25519(_) => "multi_ed25519",
            AptosPublicKeyMaterial::MultiKey(_) => "multi_key",
            AptosPublicKeyMaterial::Keyless(_) => "keyless",
            AptosPublicKeyMaterial::FederatedKeyless(_) => "federated_keyless",
        }
    }
}

impl AptosSignatureMaterial {
    fn tag_name(&self) -> &'static str {
        match self {
            AptosSignatureMaterial::Ed25519(_) => "ed25519",
            AptosSignatureMaterial::Any(_) => "any",
            AptosSignatureMaterial::MultiEd25519(_) => "multi_ed25519",
            AptosSignatureMaterial::MultiKey(_) => "multi_key",
            AptosSignatureMaterial::Keyless(_) => "keyless",
        }
    }
}

// pk_scheme / sig_scheme constants — keep in lockstep with `_internal/aptos.ts`.
const PK_SCHEME_ED25519_WIRE: u8 = 0;
const PK_SCHEME_ANY_WIRE: u8 = 1;
const PK_SCHEME_MULTI_ED25519_WIRE: u8 = 2;
const PK_SCHEME_MULTI_KEY_WIRE: u8 = 3;
const PK_SCHEME_KEYLESS_WIRE: u8 = 4;
const PK_SCHEME_FEDERATED_KEYLESS_WIRE: u8 = 5;
const SIG_SCHEME_ED25519_WIRE: u8 = 0;
const SIG_SCHEME_ANY_WIRE: u8 = 1;
const SIG_SCHEME_MULTI_ED25519_WIRE: u8 = 2;
const SIG_SCHEME_MULTI_KEY_WIRE: u8 = 3;
const SIG_SCHEME_KEYLESS_WIRE: u8 = 4;

// `serde_bytes::ByteBuf` is what BCS uses to round-trip a `Vec<u8>` field
// (length-prefixed). We use it as the on-wire representation for the Ed25519
// pk / sig arms; the bytes are validated to length below.
impl<'de> serde::Deserialize<'de> for AptosProofOfPermission {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error as _, SeqAccess, Visitor};
        use std::fmt;

        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = AptosProofOfPermission;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an AptosProofOfPermission tuple")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let user_addr: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing user_addr"))?;
                let pk_scheme: u8 = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing pk_scheme"))?;
                let public_key = match pk_scheme {
                    PK_SCHEME_ED25519_WIRE => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Ed25519 public_key"))?;
                        let arr: [u8; 32] = bytes.into_vec().try_into().map_err(|v: Vec<u8>| {
                            A::Error::custom(format!(
                                "Ed25519 public_key must be 32 bytes, got {}",
                                v.len()
                            ))
                        })?;
                        AptosPublicKeyMaterial::Ed25519(arr)
                    }
                    PK_SCHEME_ANY_WIRE => {
                        let inner: any::AnyPublicKeyInner = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Any public_key"))?;
                        AptosPublicKeyMaterial::Any(inner)
                    }
                    PK_SCHEME_MULTI_ED25519_WIRE => {
                        let bytes: serde_bytes::ByteBuf = seq.next_element()?.ok_or_else(|| {
                            A::Error::custom("missing MultiEd25519 public_key")
                        })?;
                        let inner = multi_ed25519::MultiEd25519PublicKeyInner::from_flat_bytes(
                            bytes.as_ref(),
                        )
                        .map_err(A::Error::custom)?;
                        AptosPublicKeyMaterial::MultiEd25519(inner)
                    }
                    PK_SCHEME_MULTI_KEY_WIRE => {
                        let inner: multi_key::MultiKeyInner = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing MultiKey public_key"))?;
                        AptosPublicKeyMaterial::MultiKey(inner)
                    }
                    PK_SCHEME_KEYLESS_WIRE => {
                        let pk: aptos_keyless_common::KeylessPublicKey = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Keyless public_key"))?;
                        AptosPublicKeyMaterial::Keyless(pk)
                    }
                    PK_SCHEME_FEDERATED_KEYLESS_WIRE => {
                        let fpk: aptos_keyless_common::FederatedKeylessPublicKey = seq
                            .next_element()?
                            .ok_or_else(|| {
                                A::Error::custom("missing FederatedKeyless public_key")
                            })?;
                        AptosPublicKeyMaterial::FederatedKeyless(fpk)
                    }
                    other => {
                        return Err(A::Error::custom(format!(
                            "unsupported pk_scheme {}",
                            other
                        )))
                    }
                };
                let sig_scheme: u8 = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing sig_scheme"))?;
                let signature = match sig_scheme {
                    SIG_SCHEME_ED25519_WIRE => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Ed25519 signature"))?;
                        let arr: [u8; 64] = bytes.into_vec().try_into().map_err(|v: Vec<u8>| {
                            A::Error::custom(format!(
                                "Ed25519 signature must be 64 bytes, got {}",
                                v.len()
                            ))
                        })?;
                        AptosSignatureMaterial::Ed25519(arr)
                    }
                    SIG_SCHEME_ANY_WIRE => {
                        let inner: any::AnySignatureInner = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Any signature"))?;
                        AptosSignatureMaterial::Any(inner)
                    }
                    SIG_SCHEME_MULTI_ED25519_WIRE => {
                        let bytes: serde_bytes::ByteBuf = seq.next_element()?.ok_or_else(|| {
                            A::Error::custom("missing MultiEd25519 signature")
                        })?;
                        let inner = multi_ed25519::MultiEd25519SignatureInner::from_flat_bytes(
                            bytes.as_ref(),
                        )
                        .map_err(A::Error::custom)?;
                        AptosSignatureMaterial::MultiEd25519(inner)
                    }
                    SIG_SCHEME_MULTI_KEY_WIRE => {
                        let inner: multi_key::MultiKeySigInner = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing MultiKey signature"))?;
                        AptosSignatureMaterial::MultiKey(inner)
                    }
                    SIG_SCHEME_KEYLESS_WIRE => {
                        let sig: aptos_keyless_common::KeylessSignature = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Keyless signature"))?;
                        AptosSignatureMaterial::Keyless(sig)
                    }
                    other => {
                        return Err(A::Error::custom(format!(
                            "unsupported sig_scheme {}",
                            other
                        )))
                    }
                };
                let full_message: String = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing full_message"))?;
                Ok(AptosProofOfPermission {
                    user_addr,
                    pk_scheme,
                    public_key,
                    sig_scheme,
                    signature,
                    full_message,
                })
            }
        }

        // BCS treats a struct as an n-tuple in its serde model; deserialize_tuple
        // is what `#[derive(Deserialize)]` would lower to here.
        d.deserialize_tuple(6, V)
    }
}

impl serde::Serialize for AptosProofOfPermission {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(6)?;
        t.serialize_element(&self.user_addr)?;
        t.serialize_element(&self.pk_scheme)?;
        match &self.public_key {
            AptosPublicKeyMaterial::Ed25519(arr) => {
                t.serialize_element(serde_bytes::Bytes::new(arr))?
            }
            AptosPublicKeyMaterial::Any(inner) => t.serialize_element(inner)?,
            AptosPublicKeyMaterial::MultiEd25519(inner) => {
                t.serialize_element(serde_bytes::Bytes::new(&inner.to_flat_bytes()))?
            }
            AptosPublicKeyMaterial::MultiKey(inner) => t.serialize_element(inner)?,
            AptosPublicKeyMaterial::Keyless(pk) => t.serialize_element(pk)?,
            AptosPublicKeyMaterial::FederatedKeyless(fpk) => t.serialize_element(fpk)?,
        }
        t.serialize_element(&self.sig_scheme)?;
        match &self.signature {
            AptosSignatureMaterial::Ed25519(arr) => {
                t.serialize_element(serde_bytes::Bytes::new(arr))?
            }
            AptosSignatureMaterial::Any(inner) => t.serialize_element(inner)?,
            AptosSignatureMaterial::MultiEd25519(inner) => {
                t.serialize_element(serde_bytes::Bytes::new(&inner.to_flat_bytes()))?
            }
            AptosSignatureMaterial::MultiKey(inner) => t.serialize_element(inner)?,
            AptosSignatureMaterial::Keyless(sig) => t.serialize_element(sig)?,
        }
        t.serialize_element(&self.full_message)?;
        t.end()
    }
}

// ── Verification dispatch ────────────────────────────────────────────────────

pub(super) async fn verify_aptos(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    match (&proof.public_key, &proof.signature) {
        (AptosPublicKeyMaterial::Ed25519(pk_bytes), AptosSignatureMaterial::Ed25519(sig_bytes)) => {
            ed25519::verify(req, contract, proof, pk_bytes, sig_bytes, chain_rpc).await
        }
        (AptosPublicKeyMaterial::Any(any_pk), AptosSignatureMaterial::Any(any_sig)) => {
            any::verify(req, contract, proof, any_pk, any_sig, chain_rpc).await
        }
        (
            AptosPublicKeyMaterial::MultiEd25519(pk),
            AptosSignatureMaterial::MultiEd25519(sig),
        ) => multi_ed25519::verify(req, contract, proof, pk, sig, chain_rpc).await,
        (AptosPublicKeyMaterial::MultiKey(mk), AptosSignatureMaterial::MultiKey(ms)) => {
            multi_key::verify(req, contract, proof, mk, ms, chain_rpc).await
        }
        (AptosPublicKeyMaterial::Keyless(pk), AptosSignatureMaterial::Keyless(sig)) => {
            keyless::verify(req, contract, proof, pk, sig, chain_rpc).await
        }
        (
            AptosPublicKeyMaterial::FederatedKeyless(fpk),
            AptosSignatureMaterial::Keyless(sig),
        ) => federated_keyless::verify(req, contract, proof, fpk, sig, chain_rpc).await,
        (pk, sig) => Err(anyhow!(
            "verify_aptos: pk/sig scheme mismatch ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
    }
}

pub(super) async fn verify_threshold_vrf_aptos(
    req: &ThresholdVrfRequest,
    chain_rpc: &ChainRpcConfig,
) -> Result<ThresholdVrfAuthorization> {
    let proof = &req.auth_proof;
    if proof.user_addr != req.payload.account_address {
        return Err(anyhow!(
            "verify_threshold_vrf_aptos: proof user_addr does not match payload account_address"
        ));
    }
    verify_aptos_account_proof(&req.payload, req.payload.chain_id, proof, chain_rpc).await?;
    let application = extract_signed_wallet_application(proof)?;
    Ok(ThresholdVrfAuthorization { application })
}

pub(super) trait AptosPayloadBinding {
    fn to_pretty_message(&self) -> Result<String>;
    fn to_webauthn_challenge(&self) -> Result<[u8; 32]>;
}

impl AptosPayloadBinding for DecryptionRequestPayload {
    fn to_pretty_message(&self) -> Result<String> {
        DecryptionRequestPayload::to_pretty_message(self)
    }

    fn to_webauthn_challenge(&self) -> Result<[u8; 32]> {
        DecryptionRequestPayload::to_webauthn_challenge(self)
    }
}

impl AptosPayloadBinding for ThresholdVrfRequestPayload {
    fn to_pretty_message(&self) -> Result<String> {
        ThresholdVrfRequestPayload::to_pretty_message(self)
    }

    fn to_webauthn_challenge(&self) -> Result<[u8; 32]> {
        ThresholdVrfRequestPayload::to_webauthn_challenge(self)
    }
}

async fn verify_aptos_account_proof<P: AptosPayloadBinding + Sync>(
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
            verify_keyless_signature(payload, chain_id, proof, pk, sig, chain_rpc).await?;
            let computed = aptos_keyless_common::keyless_account_authentication_key(pk);
            let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
            check_auth_key_bytes(proof, computed.as_ref(), "keyless", rpc).await
        }
        (AptosPublicKeyMaterial::FederatedKeyless(fpk), AptosSignatureMaterial::Keyless(sig)) => {
            verify_federated_keyless_signature(payload, chain_id, proof, fpk, sig, chain_rpc)
                .await?;
            let computed = aptos_keyless_common::federated_keyless_account_authentication_key(fpk);
            let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
            check_auth_key_bytes(proof, computed.as_ref(), "federated_keyless", rpc).await
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
    verify_any_signature_only(payload, chain_id, proof, any_pk, any_sig, chain_rpc).await?;
    let computed = any::authentication_key(any_pk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, &computed, any_pk.tag_name(), rpc).await
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

    let positions = multi_key::bitmap_iter_ones(&ms.bitmap).zip(ms.signatures.iter());
    let position_futs: Vec<_> =
        positions
            .map(|(pos, sig)| {
                let pk = &mk.public_keys[pos];
                async move {
                    verify_any_signature_only(payload, chain_id, proof, pk, sig, chain_rpc).await
                }
            })
            .collect();
    futures::future::try_join_all(position_futs).await?;

    let computed = multi_key::authentication_key(mk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, &computed, "multi_key", rpc).await
}

async fn verify_any_signature_only<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    any_pk: &any::AnyPublicKeyInner,
    any_sig: &any::AnySignatureInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
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
            verify_ed25519_signature(payload, proof, &vk, &sig, "verify_any_signature_only")
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
            verify_secp256k1_signature(payload, proof, &vk, &sig, "verify_any_signature_only")
        }
        (any::AnyPublicKeyInner::Keyless(pk), any::AnySignatureInner::Keyless(sig)) => {
            verify_keyless_signature(payload, chain_id, proof, pk, sig, chain_rpc).await
        }
        (any::AnyPublicKeyInner::FederatedKeyless(fpk), any::AnySignatureInner::Keyless(sig)) => {
            verify_federated_keyless_signature(payload, chain_id, proof, fpk, sig, chain_rpc).await
        }
        (
            any::AnyPublicKeyInner::Secp256r1Ecdsa(pk_bytes),
            any::AnySignatureInner::WebAuthn(assertion),
        ) => verify_webauthn_signature(payload, pk_bytes, assertion),
        (pk, sig) => Err(anyhow!(
            "verify_any_signature_only: invalid pk/sig pairing ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
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

async fn verify_keyless_signature<P: AptosPayloadBinding>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    pk: &aptos_keyless_common::KeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let msg_bytes = signed_message_bytes(payload, proof, "verify_keyless_signature")?;
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    let header: aptos_keyless_common::types::JwtHeader = serde_json::from_str(&sig.jwt_header_json)
        .map_err(|e| anyhow!("verify_keyless_signature: parse jwt_header_json: {}", e))?;
    let (jwk_res, vk_res, cfg_res) = tokio::join!(
        keyless::fetch_system_rsa_jwk(rpc, &pk.iss_val, &header.kid),
        keyless::fetch_groth16_vk(rpc),
        keyless::fetch_configuration(rpc),
    );
    let jwk = jwk_res?;
    let vk = vk_res?;
    let cfg = cfg_res?;
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("verify_keyless_signature: system clock: {}", e))?
        .as_secs();
    aptos_keyless_common::verify_signature(pk, sig, &msg_bytes, &jwk, &vk, &cfg, now_unix_secs)
        .map_err(|e| anyhow!("verify_keyless_signature: {}", e))
}

async fn verify_federated_keyless_signature<P: AptosPayloadBinding>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    fpk: &aptos_keyless_common::FederatedKeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let msg_bytes = signed_message_bytes(payload, proof, "verify_federated_keyless_signature")?;
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    let header: aptos_keyless_common::types::JwtHeader = serde_json::from_str(&sig.jwt_header_json)
        .map_err(|e| {
            anyhow!(
                "verify_federated_keyless_signature: parse jwt_header_json: {}",
                e
            )
        })?;
    let (jwk_res, vk_res, cfg_res) = tokio::join!(
        federated_keyless::fetch_jwk_with_federated_fallback(rpc, fpk, &header.kid),
        keyless::fetch_groth16_vk(rpc),
        keyless::fetch_configuration(rpc),
    );
    let jwk = jwk_res?;
    let vk = vk_res?;
    let cfg = cfg_res?;
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("verify_federated_keyless_signature: system clock: {}", e))?
        .as_secs();
    aptos_keyless_common::verify_signature(&fpk.pk, sig, &msg_bytes, &jwk, &vk, &cfg, now_unix_secs)
        .map_err(|e| anyhow!("verify_federated_keyless_signature: {}", e))
}

fn signed_message_bytes<P: AptosPayloadBinding>(
    payload: &P,
    proof: &AptosProofOfPermission,
    context: &str,
) -> Result<Vec<u8>> {
    let pretty_msg = payload.to_pretty_message()?;
    let pretty_msg_hex = hex::encode(pretty_msg.as_bytes());
    let full_msg = &proof.full_message;
    if !full_msg.contains(&pretty_msg) && !full_msg.contains(&pretty_msg_hex) {
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

async fn check_auth_key_bytes(
    proof: &AptosProofOfPermission,
    computed: &[u8],
    label: &str,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let user_addr_str = format!("0x{}", hex::encode(proof.user_addr));
    let account = rpc
        .get_account(&user_addr_str)
        .await
        .map_err(|e| anyhow!("checkAuthKey: get_account {}: {}", user_addr_str, e))?;
    let onchain = hex::decode(account.authentication_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("checkAuthKey: parse onchain auth key: {}", e))?;
    if onchain.as_slice() != computed {
        return Err(anyhow!(
            "checkAuthKey: {} auth key mismatch for {}",
            label,
            user_addr_str
        ));
    }
    Ok(())
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

/// Calls the on-chain view function
/// `{moduleAddr}::{moduleName}::{functionName}(userAddr, domain)` and expects
/// `true` to be returned. The view function name comes from the request's
/// `AptosContractId` — typically the dapp's `check_permission` ACL view.
pub(super) async fn check_permission(
    contract: &AptosContractId,
    domain: &[u8],
    proof: &AptosProofOfPermission,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let func = format!(
        "0x{}::{}::{}",
        hex::encode(contract.module_addr),
        contract.module_name,
        contract.function_name,
    );
    let user_addr = format!("0x{}", hex::encode(proof.user_addr));
    let domain_hex = format!("0x{}", hex::encode(domain));

    let result = rpc
        .call_view(&func, &[json!(user_addr), json!(domain_hex)])
        .await
        .map_err(|e| anyhow!("checkPermission: view call failed for {}: {}", func, e))?;

    let returned = result
        .first()
        .ok_or_else(|| anyhow!("checkPermission: empty view result"))?;
    if returned.as_bool() != Some(true) && returned.to_string() != "true" {
        return Err(anyhow!("checkPermission: access denied (returned {:?})", returned));
    }

    Ok(())
}

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
                .ok_or_else(|| {
                    anyhow!("find_rsa_jwk_in_jwks_resource: missing variant.data")
                })?;
            let data_bytes = hex::decode(data_hex.trim_start_matches("0x"))
                .map_err(|e| anyhow!("find_rsa_jwk_in_jwks_resource: decode variant.data: {}", e))?;
            let rsa: aptos_keyless_common::RsaJwk = bcs::from_bytes(&data_bytes).map_err(|e| {
                anyhow!("find_rsa_jwk_in_jwks_resource: BCS decode RSA_JWK: {}", e)
            })?;
            if rsa.kid == kid {
                return Ok(Some(rsa));
            }
        }
    }
    Ok(None)
}

// ── Custom-flow verification ──────────────────────────────────────────────────

pub(super) async fn verify_custom_aptos(
    contract: &AptosContractId,
    label: &[u8],
    enc_pk_bytes: &[u8],
    payload: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let func = format!(
        "0x{}::{}::{}",
        hex::encode(contract.module_addr),
        contract.module_name,
        contract.function_name,
    );
    let label_hex = format!("0x{}", hex::encode(label));
    let enc_pk_hex = format!("0x{}", hex::encode(enc_pk_bytes));
    let payload_hex = format!("0x{}", hex::encode(payload));

    let result = rpc
        .call_view(&func, &[json!(label_hex), json!(enc_pk_hex), json!(payload_hex)])
        .await
        .map_err(|e| anyhow!("check_aptos_acl: view call failed for {}: {}", func, e))?;

    let returned = result
        .first()
        .ok_or_else(|| anyhow!("check_aptos_acl: empty view result"))?;
    if returned.as_bool() != Some(true) && returned.to_string() != "true" {
        return Err(anyhow!("check_aptos_acl: access denied (returned {:?})", returned));
    }
    Ok(())
}
