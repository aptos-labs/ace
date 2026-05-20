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
