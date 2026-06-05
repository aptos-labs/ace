// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `AnyPublicKey::Secp256r1Ecdsa` / `AnySignature::WebAuthn`
//! proof-of-permission path — the passkeys / WebAuthn account type.
//!
//! Unlike the sibling [`super::ed25519`] / [`super::secp256k1`] / [`super::keyless`]
//! paths, the wallet never sees `proof.full_message` directly. The signature
//! is produced by a passkey authenticator that wraps the application-layer
//! request inside a `clientDataJSON` JSON object and signs over
//! `authenticator_data || SHA-256(clientDataJSON)` (the WebAuthn assertion
//! format). The binding to the actual `DecryptionRequestPayload` lives in
//! `clientDataJSON.challenge`.
//!
//! Verification:
//!
//! 1. Reconstruct the BCS of the request payload from `req` — field order
//!    matches the TS-side `DecryptionRequestPayload.serialize`:
//!    `keypair_id || u64(epoch) || BCS(contract_id) || ULEB128(len)||domain || BCS(ephemeral_enc_key)`.
//! 2. Compute the application challenge:
//!    `expected_challenge = SHA3-256( SHA3-256(b"ACE::DecryptionRequestPayload") || BCS(payload) )`.
//!    Mirrors aptos-core's `CryptoHasher`/`signing_message` pattern (the seed
//!    is a hashed DST, see `aptos-crypto/src/hash.rs` `prefixed_hash`) and the
//!    WebAuthn-passkey transaction signing flow uses the analogous
//!    `SHA3-256(signing_message(RawTransaction))` for `clientDataJSON.challenge`.
//! 3. Parse `client_data_json` as JSON, read the `challenge` string, and
//!    base64url-decode it (no-padding, per the WebAuthn `CollectedClientData`
//!    encoding). The decoded bytes must equal `expected_challenge`. This is the
//!    security-critical binding to the request payload — `proof.full_message`
//!    plays no role in WebAuthn verification.
//! 4. Verify the P-256 ECDSA signature over the preimage
//!    `authenticator_data || SHA-256(client_data_json)` (64-byte raw `r||s`,
//!    low-s normalized, rejected as malleable if high-s — same rule the
//!    sibling secp256k1 path uses, and aptos-core's
//!    `p256_ecdsa::verify_signature_arbitrary_msg` enforces it inside the
//!    crypto crate).
//! 5. On-chain `authentication_key` at `userAddr` must match
//!    `SHA3-256( BCS(AnyPublicKey::Secp256r1Ecdsa(pk)) || 0x02 )` — the
//!    standard SingleKey derivation handled by [`super::authentication_key`].
//! 6. Call the app's fixed `on_ace_decryption_request(label, account, origin)` hook.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::super::super::BasicFlowRequest;
use super::super::{check_basic_ace_hook, AptosContractId, AptosProofOfPermission};
use super::{authentication_key, AnyPublicKeyInner, WebAuthnAssertion, AssertionSignature};
use crate::ChainRpcConfig;

const SIG_LEN: usize = 64;

pub(super) async fn verify(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    any_pk: &AnyPublicKeyInner,
    pk_bytes: &[u8],
    assertion: &WebAuthnAssertion,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    // 1. Extract the raw r||s from the AssertionSignature wrapper.
    let AssertionSignature::Secp256r1Ecdsa(sig_bytes) = &assertion.signature;
    if sig_bytes.len() != SIG_LEN {
        return Err(anyhow!(
            "verify_aptos_any_secp256r1: sig must be {} bytes, got {}",
            SIG_LEN,
            sig_bytes.len()
        ));
    }
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| anyhow!("verify_aptos_any_secp256r1: invalid pubkey: {}", e))?;
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|e| anyhow!("verify_aptos_any_secp256r1: invalid signature: {}", e))?;
    // Reject high-s (mirrors the sibling secp256k1 path and aptos-core's
    // `p256` low-s enforcement).
    if sig.normalize_s().is_some() {
        return Err(anyhow!(
            "verify_aptos_any_secp256r1: signature has high s (malleable); only low-s normalized signatures are accepted"
        ));
    }

    // 2. Cheap signature check first — fail fast before any RPC.
    verify_signature_only(req, proof, &vk, &sig, assertion).await?;

    // 3. Chain-side checks: SingleKey auth-key match + dapp ACL.
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let (auth_result, perm_result) = tokio::join!(
        check_auth_key(proof, any_pk, rpc),
        check_basic_ace_hook(contract, &req.payload.domain, proof, rpc),
    );
    auth_result?;
    perm_result?;
    Ok(())
}

/// WebAuthn assertion verification for one signing position. Two checks:
/// challenge binding (the decoded `clientDataJSON.challenge` must equal
/// `req.payload.to_webauthn_challenge()`) and the P-256 ECDSA verify over
/// `SHA-256(authenticator_data || SHA-256(clientDataJSON))`.
///
/// `proof.full_message` is intentionally not consulted: the security binding
/// to the request payload runs through `clientDataJSON.challenge`, and
/// `proof.full_message` is a single per-request field whose contents vary
/// across the other (non-WebAuthn) verifier paths. The MultiKey dispatcher
/// in particular shares one `proof.full_message` across positions that need
/// different bytes — Ed25519 / Keyless want the pretty message, WebAuthn
/// wants something else — so the WebAuthn path must not bind to it.
///
/// Takes already-parsed `&VerifyingKey` / `&Signature` (with low-s already
/// rejected) so the caller can hoist the SEC1 + low-s parse out of the hot
/// path. Single-key callers parse once in [`verify`]; MultiKey callers parse
/// once in [`super::verify_position`].
///
/// `async` for shape uniformity with the keyless/federated-keyless paths
/// (which fetch chain-side inputs); this variant does no RPC.
///
/// **Not** included: SingleKey auth-key check or dapp ACL check. The
/// single-key wrapper [`verify`] adds both around this.
pub(super) async fn verify_signature_only(
    req: &BasicFlowRequest,
    _proof: &AptosProofOfPermission,
    vk: &VerifyingKey,
    sig: &Signature,
    assertion: &WebAuthnAssertion,
) -> Result<()> {
    // Step 1 — recompute the expected challenge from req.
    let expected_challenge = req.payload.to_webauthn_challenge()?;

    // Step 2 — parse client_data_json, extract `challenge`, base64url-decode.
    let cdj: serde_json::Value = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|e| anyhow!("verify_aptos_any_secp256r1: parse client_data_json: {}", e))?;
    let challenge_str = cdj
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("verify_aptos_any_secp256r1: clientDataJSON missing `challenge` string"))?;
    let actual_challenge = URL_SAFE_NO_PAD
        .decode(challenge_str)
        .map_err(|e| anyhow!("verify_aptos_any_secp256r1: base64url-decode challenge: {}", e))?;
    if actual_challenge != expected_challenge {
        return Err(anyhow!(
            "verify_aptos_any_secp256r1: clientDataJSON.challenge does not bind to this request payload"
        ));
    }

    // Step 3 — verify the P-256 ECDSA signature over the WebAuthn preimage
    // `authenticator_data || SHA-256(clientDataJSON)`. The VerifyingKey::verify
    // trait impl prehashes with SHA-256 internally; do that explicitly via
    // verify_prehash to keep the contract obvious.
    let cdj_hash = Sha256::digest(&assertion.client_data_json);
    let mut ecdsa_preimage =
        Vec::with_capacity(assertion.authenticator_data.len() + cdj_hash.len());
    ecdsa_preimage.extend_from_slice(&assertion.authenticator_data);
    ecdsa_preimage.extend_from_slice(&cdj_hash);
    let prehash: [u8; 32] = Sha256::digest(&ecdsa_preimage).into();
    vk.verify_prehash(&prehash, sig)
        .map_err(|e| anyhow!("verify_aptos_any_secp256r1: P-256 ECDSA verification failed: {}", e))?;
    Ok(())
}

/// On-chain `authentication_key` at `userAddr` must equal
/// `SHA3-256( BCS(AnyPublicKey::Secp256r1Ecdsa(pk)) || 0x02 )`. Variant tag is
/// `0x02` (the third entry in `AnyPublicKey`); suffix is `Scheme::SingleKey`.
async fn check_auth_key(
    proof: &AptosProofOfPermission,
    any_pk: &AnyPublicKeyInner,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let computed = authentication_key(any_pk);

    let user_addr_str = format!("0x{}", hex::encode(proof.user_addr));
    let account = rpc
        .get_account(&user_addr_str)
        .await
        .map_err(|e| anyhow!("checkAuthKey: get_account {}: {}", user_addr_str, e))?;

    let onchain = hex::decode(account.authentication_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("checkAuthKey: parse onchain auth key: {}", e))?;

    if onchain.as_slice() != computed.as_ref() {
        return Err(anyhow!(
            "checkAuthKey: any/secp256r1 auth key mismatch for {}",
            user_addr_str
        ));
    }
    Ok(())
}
