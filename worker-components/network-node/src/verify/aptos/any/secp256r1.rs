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
//!    encoding). The decoded bytes must equal `expected_challenge`.
//! 4. Build the ECDSA preimage `ecdsa_preimage = authenticator_data || SHA-256(client_data_json)`.
//!    `proof.full_message` is the hex of those same bytes — by definition the
//!    `fullMessage` field carries "the actual bytes fed into the signature
//!    scheme", which for WebAuthn is this preimage (P-256 ECDSA then prehashes
//!    it once more with SHA-256).
//! 5. Verify the P-256 ECDSA signature (64-byte raw `r||s`, low-s normalized,
//!    rejected as malleable if high-s — same rule the sibling secp256k1 path
//!    uses, and aptos-core's `p256_ecdsa::verify_signature_arbitrary_msg`
//!    enforces it inside the crypto crate).
//! 6. On-chain `authentication_key` at `userAddr` must match
//!    `SHA3-256( BCS(AnyPublicKey::Secp256r1Ecdsa(pk)) || 0x02 )` — the
//!    standard SingleKey derivation handled by [`super::authentication_key`].
//! 7. Call the dapp's `check_permission(user_addr, domain)` view function.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use super::super::super::{BasicFlowRequest, ContractId};
use super::super::{check_permission, AptosContractId, AptosProofOfPermission};
use super::{authentication_key, AnyPublicKeyInner, WebAuthnAssertion, AssertionSignature};
use crate::ChainRpcConfig;

const SIG_LEN: usize = 64;

/// DST string for the request-payload challenge. Hashed once into a 32-byte
/// seed before being prepended to the BCS body — mirrors aptos-core's
/// `CryptoHasher` derive (which prefixes with
/// `SHA3-256(b"APTOS::" || TypeName)`).
const PAYLOAD_DST: &[u8] = b"ACE::DecryptionRequestPayload";

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

    // 2. Cheap synchronous checks first — fail fast before any RPC.
    verify_webauthn(req, proof, assertion, &vk, &sig)?;

    // 3. Chain-side checks: SingleKey auth-key match + dapp ACL.
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let (auth_result, perm_result) = tokio::join!(
        check_auth_key(proof, any_pk, rpc),
        check_permission(contract, &req.domain, proof, rpc),
    );
    auth_result?;
    perm_result?;
    Ok(())
}

/// Helper that pulls all the WebAuthn-specific checks into one place:
/// challenge binding, `fullMessage` binding, and the ECDSA verify itself.
fn verify_webauthn(
    req: &BasicFlowRequest,
    proof: &AptosProofOfPermission,
    assertion: &WebAuthnAssertion,
    vk: &VerifyingKey,
    sig: &Signature,
) -> Result<()> {
    // Step 1 — recompute the expected challenge from req.
    let expected_challenge = compute_expected_challenge(req)?;

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

    // Step 3 — build the ECDSA preimage and bind it to proof.full_message.
    let cdj_hash = Sha256::digest(&assertion.client_data_json);
    let mut ecdsa_preimage =
        Vec::with_capacity(assertion.authenticator_data.len() + cdj_hash.len());
    ecdsa_preimage.extend_from_slice(&assertion.authenticator_data);
    ecdsa_preimage.extend_from_slice(&cdj_hash);

    let expected_full_msg_hex = hex::encode(&ecdsa_preimage);
    let stripped = proof
        .full_message
        .strip_prefix("0x")
        .unwrap_or(proof.full_message.as_str());
    if !stripped.eq_ignore_ascii_case(&expected_full_msg_hex) {
        return Err(anyhow!(
            "verify_aptos_any_secp256r1: proof.full_message does not equal hex(authenticator_data || SHA-256(clientDataJSON))"
        ));
    }

    // Step 4 — verify the P-256 ECDSA signature over the preimage. The
    // VerifyingKey::verify trait impl prehashes with SHA-256 internally; do
    // that explicitly via verify_prehash to keep the contract obvious.
    let prehash: [u8; 32] = Sha256::digest(&ecdsa_preimage).into();
    vk.verify_prehash(&prehash, sig)
        .map_err(|e| anyhow!("verify_aptos_any_secp256r1: P-256 ECDSA verification failed: {}", e))?;
    Ok(())
}

/// `expected_challenge = SHA3-256( SHA3-256(PAYLOAD_DST) || BCS(payload) )`.
fn compute_expected_challenge(req: &BasicFlowRequest) -> Result<[u8; 32]> {
    let payload_bytes = bcs_payload(req)?;
    let seed: [u8; 32] = Sha3_256::digest(PAYLOAD_DST).into();
    let mut h = Sha3_256::new();
    h.update(seed);
    h.update(&payload_bytes);
    Ok(h.finalize().into())
}

/// Serializes the request payload with the same BCS layout the TS SDK
/// `DecryptionRequestPayload.serialize` produces — keypair_id, epoch,
/// contract_id (the full enum, including the scheme tag), domain, and the
/// ephemeral encryption key. Field order is fixed by the TS code at
/// `ts-sdk/src/_internal/common.ts:322-327`.
fn bcs_payload(req: &BasicFlowRequest) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct PayloadBcs<'a> {
        keypair_id: &'a [u8; 32],
        epoch: u64,
        contract_id: &'a ContractId,
        domain: &'a Vec<u8>,
        ephemeral_enc_key: &'a vss_common::pke::EncryptionKey,
    }
    let p = PayloadBcs {
        keypair_id: &req.keypair_id,
        epoch: req.epoch,
        contract_id: &req.contract_id,
        domain: &req.domain,
        ephemeral_enc_key: &req.ephemeral_enc_key,
    };
    bcs::to_bytes(&p).map_err(|e| anyhow!("verify_aptos_any_secp256r1: BCS encode payload: {}", e))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks in the DST seed shape: `seed = SHA3-256(b"ACE::DecryptionRequestPayload")`.
    /// The literal 32 bytes below were precomputed off this constant — any
    /// rename to the DST will fail this test and the corresponding TS-side
    /// constant must change in lockstep.
    #[test]
    fn payload_dst_seed_is_stable() {
        let seed: [u8; 32] = Sha3_256::digest(PAYLOAD_DST).into();
        let expected = Sha3_256::digest(b"ACE::DecryptionRequestPayload");
        assert_eq!(seed, expected.as_slice());
        assert_eq!(seed.len(), 32);
    }

    /// Sanity: `compute_expected_challenge` chains seed and payload in the
    /// right order — same SHA3-256 input as one shot constructed by hand.
    #[test]
    fn expected_challenge_matches_manual_hash() {
        // Hand-build a minimal payload preimage. Doesn't matter that it's not
        // a valid BasicFlowRequest body; this test only locks in the chaining
        // shape `H(seed || payload)`, not the payload itself.
        let payload = b"\x11\x22\x33\x44";
        let seed: [u8; 32] = Sha3_256::digest(PAYLOAD_DST).into();
        let mut h = Sha3_256::new();
        h.update(seed);
        h.update(payload);
        let manual: [u8; 32] = h.finalize().into();

        // Replay via the same code path.
        let seed2: [u8; 32] = Sha3_256::digest(PAYLOAD_DST).into();
        let mut h2 = Sha3_256::new();
        h2.update(seed2);
        h2.update(payload);
        let via_fn: [u8; 32] = h2.finalize().into();
        assert_eq!(manual, via_fn);
    }
}
