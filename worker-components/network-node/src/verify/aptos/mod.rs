// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Aptos-side proof-of-permission verification.
//!
//! Owns the wire types and helpers shared between the two scheme paths:
//!   - [`ed25519`] — legacy Ed25519 sig over the pretty message
//!   - [`keyless`] — ZK keyless signature
//!
//! The dispatcher [`verify_aptos`] matches on the typed [`AptosPublicKeyMaterial`] /
//! [`AptosSignatureMaterial`] enum payload (decoded by [`AptosProofOfPermission`]'s
//! custom serde from `pk_scheme` / `sig_scheme`) and delegates to the appropriate
//! sub-module.

pub mod ed25519;
pub mod keyless;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::ChainRpcConfig;
use super::BasicFlowRequest;

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct AptosContractId {
    pub chain_id: u8,
    pub module_addr: [u8; 32],
    pub module_name: String,
    pub function_name: String,
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
    /// pk_scheme=4. BCS wire is the inline `KeylessPublicKey` struct
    /// (`{ iss_val: String, idc: Vec<u8> }`).
    Keyless(aptos_keyless_common::KeylessPublicKey),
}

/// Inner signature payload for [`AptosProofOfPermission`].
#[derive(Clone, Debug)]
pub enum AptosSignatureMaterial {
    /// sig_scheme=0. BCS wire is `Vec<u8>(64 bytes)`.
    Ed25519([u8; 64]),
    /// sig_scheme=4. BCS wire is the inline `KeylessSignature` struct.
    Keyless(aptos_keyless_common::KeylessSignature),
}

impl AptosPublicKeyMaterial {
    fn tag_name(&self) -> &'static str {
        match self {
            AptosPublicKeyMaterial::Ed25519(_) => "ed25519",
            AptosPublicKeyMaterial::Keyless(_) => "keyless",
        }
    }
}

impl AptosSignatureMaterial {
    fn tag_name(&self) -> &'static str {
        match self {
            AptosSignatureMaterial::Ed25519(_) => "ed25519",
            AptosSignatureMaterial::Keyless(_) => "keyless",
        }
    }
}

// pk_scheme / sig_scheme constants — keep in lockstep with `_internal/aptos.ts`.
const PK_SCHEME_ED25519_WIRE: u8 = 0;
const PK_SCHEME_KEYLESS_WIRE: u8 = 4;
const SIG_SCHEME_ED25519_WIRE: u8 = 0;
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
                    PK_SCHEME_KEYLESS_WIRE => {
                        let pk: aptos_keyless_common::KeylessPublicKey = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("missing Keyless public_key"))?;
                        AptosPublicKeyMaterial::Keyless(pk)
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
            AptosPublicKeyMaterial::Keyless(pk) => t.serialize_element(pk)?,
        }
        t.serialize_element(&self.sig_scheme)?;
        match &self.signature {
            AptosSignatureMaterial::Ed25519(arr) => {
                t.serialize_element(serde_bytes::Bytes::new(arr))?
            }
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
    ephemeral_ek_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    match (&proof.public_key, &proof.signature) {
        (AptosPublicKeyMaterial::Ed25519(pk_bytes), AptosSignatureMaterial::Ed25519(sig_bytes)) => {
            ed25519::verify(
                req,
                contract,
                proof,
                pk_bytes,
                sig_bytes,
                ephemeral_ek_bytes,
                chain_rpc,
            )
            .await
        }
        (AptosPublicKeyMaterial::Keyless(pk), AptosSignatureMaterial::Keyless(sig)) => {
            keyless::verify(req, contract, proof, pk, sig, ephemeral_ek_bytes, chain_rpc).await
        }
        (pk, sig) => Err(anyhow!(
            "verify_aptos: pk/sig scheme mismatch ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
    }
}

// ── Shared helpers (used by ed25519 + keyless) ──────────────────────────────

/// Produces `DecryptionRequestPayload.toPrettyMessage(0)` from
/// `ts-sdk/src/_internal/common.ts` for an Aptos ContractID. Used by both
/// schemes' sig-binding step to check that `fullMessage` covers the correct
/// keypairId, epoch, contractId, domain, **and ephemeralEncKey**.
///
/// Binding the ephemeralEncKey is critical: it is the public key that the IDK
/// share is encrypted to in the response. If it were not part of the signed
/// message, anyone holding a valid proof could replay it with a substituted
/// ephemeralEncKey and have shares re-encrypted to themselves.
pub(super) fn pretty_message(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    ephemeral_ek_bytes: &[u8],
) -> String {
    // moduleAddr.toStringLong() = "0x" + 64 lowercase hex chars (32 bytes)
    let module_addr = format!("0x{}", hex::encode(contract.module_addr));
    let domain_hex = format!("0x{}", hex::encode(&req.domain));
    // `pke.EncryptionKey.toHex()` = bytesToHex(toBytes()); does NOT prepend "0x".
    let ephemeral_ek_hex = hex::encode(ephemeral_ek_bytes);
    let keypair_id_hex = format!("0x{}", hex::encode(req.keypair_id));

    format!(
        "ACE Decryption Request\nkeypairId: {}\nepoch: {}\ncontractId:\n  scheme: aptos\n  inner:\n      chainId: {}\n      moduleAddr: {}\n      moduleName: {}\n      functionName: {}\ndomain: {}\nephemeralEncKey: {}",
        keypair_id_hex,
        req.epoch,
        contract.chain_id,
        module_addr,
        contract.module_name,
        contract.function_name,
        domain_hex,
        ephemeral_ek_hex,
    )
}

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
