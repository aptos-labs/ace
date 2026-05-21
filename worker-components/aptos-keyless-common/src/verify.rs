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
    public_inputs_hash::get_public_inputs_hash,
    poseidon::fr_to_bytes_le,
    types::{
        Configuration, EphemeralCertificate, EphemeralPublicKey, EphemeralSignature, Groth16Proof,
        JwtHeader, KeylessPublicKey, KeylessSignature, ZkProof,
    },
};
use ed25519_dalek::Verifier;
use sha3::{Digest, Sha3_256};

/// Verify a keyless ZK signature over `message`.
///
/// Returns `Ok(())` only if every check below passes:
///   1. `signature.exp_date_secs > now_unix_secs`
///   2. `cert.exp_horizon_secs <= config.max_exp_horizon_secs`
///   3. `kid` in JWT header == `jwk.kid`
///   4. Groth16 verify under `groth16_vk` with public-input hash computed
///      on-the-fly from `(pk, signature, jwk, config)` via
///      [`get_public_inputs_hash`]
///   5. Ephemeral signature over `message` under `signature.ephemeral_pubkey`
pub fn verify_signature(
    pk: &KeylessPublicKey,
    signature: &KeylessSignature,
    message: &[u8],
    jwk: &RsaJwk,
    groth16_vk: &Groth16VerificationKey,
    config: &Configuration,
    now_unix_secs: u64,
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
    // 3. kid match.
    let header: JwtHeader = serde_json::from_str(&signature.jwt_header_json)
        .map_err(|e| VerifyError::Decode(format!("jwt_header_json: {}", e)))?;
    if header.kid != jwk.kid {
        return Err(VerifyError::KidMismatch {
            header_kid: header.kid,
            jwk_kid: jwk.kid.clone(),
        });
    }

    // 4. Groth16. Public-input hash computed on-the-fly from
    //    `(pk, signature, jwk, config)` — bit-identical to what
    //    `aptos_types::keyless::get_public_inputs_hash` produces.
    let public_inputs_hash = get_public_inputs_hash(signature, pk, jwk, config)?;
    let public_inputs_hash_le = fr_to_bytes_le(&public_inputs_hash);
    let pvk = groth16_vk.to_ark_prepared()?;
    let proof = match &zks.proof {
        ZkProof::Groth16Zkp(p) => p,
    };
    verify_proof(proof, &public_inputs_hash_le, &pvk)?;

    // 4a. Training-wheels signature. When the on-chain configuration installs
    //     a training_wheels_pubkey, the prover service signs the proof+PIH
    //     pair with that key as a defense-in-depth check (bug in the circuit
    //     ⇒ proofs still need the operator's sign-off). The localnet bootstrap
    //     leaves it unset.
    if let Some(tw_pk_bytes) = &config.training_wheels_pubkey {
        let tw_sig = zks.training_wheels_signature.as_ref().ok_or_else(|| {
            VerifyError::TrainingWheels(
                "training_wheels_pubkey set on-chain but signature missing".into(),
            )
        })?;
        verify_training_wheels_signature(proof, &public_inputs_hash_le, tw_pk_bytes, tw_sig)?;
    }

    // (JWT signature verification under `jwk` is deliberately not run here:
    // the Groth16 proof commits to `jwk_hash` via the public-input hash, so a
    // valid proof under the on-chain VK is already a binding to the JWK. A
    // follow-up will add explicit JWT-sig verification too.)

    // 5. Ephemeral signature over `message` under `ephemeral_pubkey`.
    verify_ephemeral_sig(&signature.ephemeral_pubkey, &signature.ephemeral_signature, message)?;

    Ok(())
}

/// Verify the training-wheels Ed25519 signature carried in `ZeroKnowledgeSig`.
///
/// The signed bytes are `signing_message(Groth16ProofAndStatement)` —
/// i.e. `SHA3-256("APTOS::Groth16ProofAndStatement") || BCS(proof) ||
/// public_inputs_hash_le[32]`. (The `[u8; 32]` PIH field is BCS-serialized as
/// 32 raw bytes, no length prefix.) Matches what aptos-core's
/// `EphemeralSignature::verify::<Groth16ProofAndStatement>` checks on-chain
/// and what the ts-sdk's `Groth16ProofAndStatement.hash()` produces.
pub fn verify_training_wheels_signature(
    proof: &Groth16Proof,
    public_inputs_hash_le: &[u8; 32],
    training_wheels_pubkey: &[u8],
    training_wheels_signature: &EphemeralSignature,
) -> Result<(), VerifyError> {
    let sig_bytes = match training_wheels_signature {
        EphemeralSignature::Ed25519 { signature } => signature,
        EphemeralSignature::WebAuthn { .. } => {
            return Err(VerifyError::TrainingWheels(
                "training_wheels_signature must be Ed25519".into(),
            ));
        }
    };
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        VerifyError::TrainingWheels(format!(
            "Ed25519 sig must be 64 bytes, got {}",
            sig_bytes.len()
        ))
    })?;
    let pk_arr: [u8; 32] = training_wheels_pubkey.as_ref().try_into().map_err(|_| {
        VerifyError::TrainingWheels(format!(
            "training_wheels_pubkey must be 32 bytes, got {}",
            training_wheels_pubkey.len()
        ))
    })?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| VerifyError::TrainingWheels(format!("invalid pubkey: {}", e)))?;

    let mut msg = Sha3_256::digest(b"APTOS::Groth16ProofAndStatement").to_vec();
    bcs::serialize_into(&mut msg, proof)
        .map_err(|e| VerifyError::Internal(format!("BCS serialize proof: {}", e)))?;
    msg.extend_from_slice(public_inputs_hash_le);

    vk.verify(&msg, &ed25519_dalek::Signature::from_bytes(&sig_arr))
        .map_err(|e| VerifyError::TrainingWheels(format!("verify: {}", e)))
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

#[cfg(test)]
mod tests {
    //! End-to-end known-answer test for training-wheels signature verification,
    //! using a real testnet keyless transaction (version 8855672924) signed by
    //! 0xadd55374e2aca9ea7d8db42850867034068d479e40306d71c07846304ba6d2c0.
    //!
    //! Fixture sources (captured 2026-05-21):
    //!   * sig / pk BCS:                  /v1/transactions/by_hash/{HASH}
    //!   * RSA JWK (Google kid=41b2...56e): /v1/accounts/0x1/resource/0x1::jwks::PatchedJWKs
    //!   * Configuration:                 /v1/accounts/0x1/resource/0x1::keyless_account::Configuration
    use super::*;
    use crate::types::{EphemeralCertificate, KeylessPublicKey, KeylessSignature};

    const SIG_HEX: &str = "0000dc0e817d41c596b65acd8303de6bd7a8d878b8da13ad45f161090c4d398c251450746bbf7fe2ee622f5e019ca8d674889497d6fe696b170e92dac3b2f07c431b2a10c0081c620041b23d6aee6dba8face027b3ae0b83bc2f32648f548100c8847789cec5f60106d96f224ca7d84085889981e50f3de7254340e3bc7a22de908780969800000000000000010040b6cd408cd023085d97e252437a8eeaa83468c156e9b139fcfe881df742e83d2f36f0f27213c49a51ef71ecf5449624f5bb40e0b4c552b2d8bcc8479c7884d8034c7b22616c67223a225253323536222c226b6964223a2234316232653131666639636132366537386330323561396434613432396362303630313339353665222c22747970223a224a5754227d04ff356a000000000020c588ac42b8e68a9eebbd45cd96599981664fabdb87de53a7119d9111c6bc62240040ee5817c9a617b2a7255343ec323b6f7bea266cd4cc0560fe41d3e4fea166f308605a0b1cd5ed5ae4669478cdb32acf63ac2454eaf2a355b369f299555b048e03";
    const PK_HEX:  &str = "1b68747470733a2f2f6163636f756e74732e676f6f676c652e636f6d207b5f20d5625f664573760b7c010f33e5399419885403340a547fa6879a94f92a";

    fn fixture_jwk() -> RsaJwk {
        RsaJwk {
            kid: "41b2e11ff9ca26e78c025a9d4a429cb06013956e".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            e: "AQAB".to_string(),
            n: "rzeCTKm9k6vnoo_wIvfuGI-kChM1aGoxUgh-GyZdk6jWdVo0Zy8SY4JysW_SZl1Cl_7ah4drYauiynraU-Z_FlF1k3h023Ztc6SNGl6R7Rypi46UlxHUyD2wIc6oozDEVnxBDL5VdvlsvtjAPJRNC3WK6mgQvHmBpAOnrDfGSOytzABzF-Zdz5exQ69eapA0IbOjiy6Az2GYEhIBkhlMc9Ds4lv-cN977HYdflUdsusL_phjOJtm9A9qQ8NMG41Q1tBb6qwz6-NFz_uaxCbeE5Ny1ka4K3m0o775SPjOZoCbDw7tddKct9sr9eQ2H9z-1MbDOwi30Lyu54hUfk7szw".to_string(),
        }
    }

    fn fixture_config() -> Configuration {
        Configuration {
            override_aud_vals: vec![],
            max_signatures_per_txn: 3,
            max_exp_horizon_secs: 10_000_000,
            training_wheels_pubkey: Some(
                hex::decode("1388de358cf4701696bd58ed4b96e9d670cbbb914b888be1ceda6374a3098ed4")
                    .unwrap(),
            ),
            max_commited_epk_bytes: 93,
            max_iss_val_bytes: 120,
            max_extra_field_bytes: 350,
            max_jwt_header_b64_bytes: 300,
        }
    }

    fn fixture() -> (KeylessPublicKey, KeylessSignature, RsaJwk, Configuration, [u8; 32]) {
        let pk: KeylessPublicKey = bcs::from_bytes(&hex::decode(PK_HEX).unwrap()).unwrap();
        let sig: KeylessSignature = bcs::from_bytes(&hex::decode(SIG_HEX).unwrap()).unwrap();
        let jwk = fixture_jwk();
        let config = fixture_config();
        let pih = get_public_inputs_hash(&sig, &pk, &jwk, &config).unwrap();
        let pih_le = fr_to_bytes_le(&pih);
        (pk, sig, jwk, config, pih_le)
    }

    fn proof_and_tw_sig(sig: &KeylessSignature) -> (&Groth16Proof, &EphemeralSignature) {
        let EphemeralCertificate::ZeroKnowledgeSig(zks) = &sig.cert else { panic!("not ZK") };
        let ZkProof::Groth16Zkp(proof) = &zks.proof;
        let tw = zks.training_wheels_signature.as_ref().expect("tw sig in fixture");
        (proof, tw)
    }

    #[test]
    fn training_wheels_signature_verifies_against_real_testnet_txn() {
        let (_pk, sig, _jwk, config, pih_le) = fixture();
        let (proof, tw_sig) = proof_and_tw_sig(&sig);
        let tw_pk = config.training_wheels_pubkey.as_ref().unwrap();
        verify_training_wheels_signature(proof, &pih_le, tw_pk, tw_sig)
            .expect("real testnet training-wheels sig should verify");
    }

    #[test]
    fn training_wheels_signature_rejects_flipped_pih() {
        let (_pk, sig, _jwk, config, mut pih_le) = fixture();
        let (proof, tw_sig) = proof_and_tw_sig(&sig);
        let tw_pk = config.training_wheels_pubkey.as_ref().unwrap();
        pih_le[0] ^= 0x01;
        let err = verify_training_wheels_signature(proof, &pih_le, tw_pk, tw_sig)
            .expect_err("flipped PIH must not verify");
        assert!(matches!(err, VerifyError::TrainingWheels(_)), "got {:?}", err);
    }
}
