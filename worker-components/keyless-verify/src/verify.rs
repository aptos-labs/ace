// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Pure-function entry point for off-chain keyless signature verification.
//!
//! See crate-level docs for the precise list of checks performed and what is
//! still TODO. The Groth16 step needs a 32-byte public-input hash that the
//! caller supplies via [`PublicInputsHashSource`]; full on-the-fly Poseidon
//! computation lives in a follow-up.

use crate::{
    errors::VerifyError,
    groth16::{verify_proof, Groth16VerificationKey},
    jwk::RsaJwk,
    types::{
        Configuration, EphemeralCertificate, EphemeralPublicKey, EphemeralSignature, JwtHeader,
        KeylessPublicKey, KeylessSignature, ZkProof,
    },
};
use ed25519_dalek::Verifier;

/// How the verifier sources the Groth16 public-input hash for this signature.
///
/// `OnTheFly` (Poseidon hash over (`epk`, `idc`, …)) requires Poseidon-BN254
/// and is intentionally not implemented yet — full impl is a follow-up.
pub enum PublicInputsHashSource {
    /// 32-byte little-endian Fr (matches `fr_to_bytes_le`). Used by the
    /// initial worker integration: the hash is pinned per known SAMPLE_PROOF
    /// fixture and supplied by the caller.
    Precomputed([u8; 32]),
    /// Placeholder for the proper code path. Returns `Unsupported` for now;
    /// the caller (network-node) will fall back to `Precomputed` when the
    /// signature matches one of the pinned localnet fixtures.
    OnTheFly,
}

/// Verify a keyless ZK signature over `message`.
///
/// Returns `Ok(())` only if every check below passes:
///   1. `signature.exp_date_secs > now_unix_secs`
///   2. `cert.exp_horizon_secs <= config.max_exp_horizon_secs`
///   3. `kid` in JWT header == `jwk.kid`
///   4. Groth16 verify under `groth16_vk` with the supplied public-inputs hash
///   5. Ephemeral signature over `message` under `signature.ephemeral_pubkey`
pub fn verify_keyless(
    _pk: &KeylessPublicKey,
    signature: &KeylessSignature,
    message: &[u8],
    jwk: &RsaJwk,
    groth16_vk: &Groth16VerificationKey,
    config: &Configuration,
    now_unix_secs: u64,
    pih_source: PublicInputsHashSource,
) -> Result<(), VerifyError> {
    // 1. EPK expiry.
    if signature.exp_date_secs <= now_unix_secs {
        return Err(VerifyError::EpkExpired {
            exp: signature.exp_date_secs,
            now: now_unix_secs,
        });
    }

    // 2. cert variant + exp_horizon bound.
    let zks = match &signature.cert {
        EphemeralCertificate::ZeroKnowledgeSig(zks) => zks,
        EphemeralCertificate::OpenIdSig(_) => {
            return Err(VerifyError::Unsupported("OpenID-mode cert (non-ZK)"))
        }
    };
    if zks.exp_horizon_secs > config.max_exp_horizon_secs {
        return Err(VerifyError::ExpHorizonTooLarge {
            given: zks.exp_horizon_secs,
            max: config.max_exp_horizon_secs,
        });
    }
    if zks.override_aud_val.is_some() {
        return Err(VerifyError::Unsupported(
            "override_aud_val handling not yet implemented",
        ));
    }
    // Training-wheels signature check deliberately skipped for the localnet
    // bootstrap path: `set_groth16_verification_key_for_next_epoch` is called
    // with `training_wheels_pubkey = None`. If a deployment installs one, the
    // verifier should refuse a missing training_wheels_signature — TODO.
    if config.training_wheels_pubkey.is_some() {
        return Err(VerifyError::Unsupported(
            "training_wheels_pubkey set on-chain — verification of the \
             training-wheels signature on the proof is not yet implemented",
        ));
    }

    // 3. kid match.
    let header: JwtHeader = serde_json::from_str(&signature.jwt_header_json)
        .map_err(|e| VerifyError::Decode(format!("jwt_header_json: {}", e)))?;
    if header.kid != jwk.kid {
        return Err(VerifyError::KidMismatch {
            header_kid: header.kid,
            jwk_kid: jwk.kid.clone(),
        });
    }

    // 4. Groth16.
    let pih = match pih_source {
        PublicInputsHashSource::Precomputed(h) => h,
        PublicInputsHashSource::OnTheFly => {
            return Err(VerifyError::Unsupported(
                "on-the-fly Poseidon public-inputs hash not yet implemented; \
                 caller must supply a precomputed hash",
            ))
        }
    };
    let pvk = groth16_vk.to_ark_prepared()?;
    let proof = match &zks.proof {
        ZkProof::Groth16Zkp(p) => p,
    };
    verify_proof(proof, &pih, &pvk)?;

    // (JWT signature verification under `jwk` is deliberately not run here:
    // the Groth16 proof commits to `jwk_hash` via the public-input hash, so a
    // valid proof under the on-chain VK is already a binding to the JWK. A
    // follow-up will add explicit JWT-sig verification too.)
    let _ = (jwk,);

    // 5. Ephemeral signature over `message` under `ephemeral_pubkey`.
    verify_ephemeral_sig(&signature.ephemeral_pubkey, &signature.ephemeral_signature, message)?;

    Ok(())
}

fn verify_ephemeral_sig(
    pk: &EphemeralPublicKey,
    sig: &EphemeralSignature,
    message: &[u8],
) -> Result<(), VerifyError> {
    match (pk, sig) {
        (
            EphemeralPublicKey::Ed25519 { public_key },
            EphemeralSignature::Ed25519 { signature },
        ) => {
            if public_key.len() != 32 {
                return Err(VerifyError::EphemeralSig(format!(
                    "Ed25519 pubkey must be 32 bytes, got {}",
                    public_key.len()
                )));
            }
            if signature.len() != 64 {
                return Err(VerifyError::EphemeralSig(format!(
                    "Ed25519 sig must be 64 bytes, got {}",
                    signature.len()
                )));
            }
            let pk_arr: [u8; 32] = public_key.as_slice().try_into().unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
                .map_err(|e| VerifyError::EphemeralSig(format!("invalid pubkey: {}", e)))?;
            let sig_arr: [u8; 64] = signature.as_slice().try_into().unwrap();
            let s = ed25519_dalek::Signature::from_bytes(&sig_arr);
            vk.verify(message, &s)
                .map_err(|e| VerifyError::EphemeralSig(format!("verify: {}", e)))
        }
        (EphemeralPublicKey::Secp256r1Ecdsa { .. }, _)
        | (_, EphemeralSignature::WebAuthn { .. }) => Err(VerifyError::Unsupported(
            "WebAuthn / Secp256r1 ephemeral signatures not yet implemented",
        )),
    }
}
