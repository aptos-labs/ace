// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Groth16 public-input hash (PIH) for keyless ZK signatures.
//!
//! Ports `hash_public_inputs` from
//! `aptos-core/types/src/keyless/bn254_circom.rs` + the `RSA_JWK` Poseidon
//! commitment from `aptos-core/types/src/jwks/rsa/mod.rs`. Both are pure
//! compositions on top of [`crate::poseidon`] — bit-identical Fr scalars
//! per call, so the resulting PIH matches what aptos-core computes for the
//! same `(epk, idc, exp_date, …)` bundle.

use crate::{
    circuit::MAX_AUD_VAL_BYTES,
    errors::VerifyError,
    jwk::RsaJwk,
    poseidon::{
        hash_scalars, pack_bytes_to_one_scalar, pad_and_hash_string,
        pad_and_pack_bytes_to_scalars_with_len,
    },
    types::{
        Configuration, EphemeralCertificate, EphemeralPublicKey, IdCommitment, KeylessPublicKey,
        KeylessSignature, ZkProof,
    },
};
use ark_bn254::Fr;
use ark_ff::{One, PrimeField, Zero};
use base64::Engine;
use once_cell::sync::Lazy;

// b64url(no padding) — same encoding the JWT spec uses for header / payload.
const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

// Hash of a single-space string padded to MAX_EXTRA_FIELD_BYTES (350 — the
// `Configuration::new_for_devnet` value, hardcoded here to match upstream's
// `EMPTY_EXTRA_FIELD_HASH`). Computed lazily so the cost is paid once.
//
// NOTE: aptos-core uses `circuit_constants::MAX_EXTRA_FIELD_BYTES = 350` for
// this fallback (not `config.max_extra_field_bytes`) — see upstream
// bn254_circom.rs. We match.
const FIXED_MAX_EXTRA_FIELD_BYTES: usize = 350;
static EMPTY_EXTRA_FIELD_HASH: Lazy<Fr> =
    Lazy::new(|| pad_and_hash_string(" ", FIXED_MAX_EXTRA_FIELD_BYTES).expect("Poseidon over 12 scalars"));

// Hash of the empty string padded to MAX_AUD_VAL_BYTES. Same comment as above.
static EMPTY_OVERRIDE_AUD_HASH: Lazy<Fr> =
    Lazy::new(|| pad_and_hash_string("", MAX_AUD_VAL_BYTES).expect("Poseidon over 5 scalars"));

/// Computes the Groth16 public-input hash that the ZK proof in `sig` is
/// verified against — the single Fr that goes into the Groth16 verifier as
/// `public_inputs[0]`. Drop-in replacement for
/// `aptos_types::keyless::get_public_inputs_hash`.
pub fn get_public_inputs_hash(
    sig: &KeylessSignature,
    pk: &KeylessPublicKey,
    jwk: &RsaJwk,
    config: &Configuration,
) -> Result<Fr, VerifyError> {
    let zks = match &sig.cert {
        EphemeralCertificate::ZeroKnowledgeSig(zks) => zks,
        EphemeralCertificate::OpenIdSig(_) => {
            return Err(VerifyError::Unsupported(
                "OpenID-mode signature: get_public_inputs_hash only valid for ZK proofs",
            ))
        }
    };
    // Ensure proof is Groth16 (the only variant of ZkProof, but explicit for clarity).
    match &zks.proof {
        ZkProof::Groth16Zkp(_) => {}
    }

    hash_public_inputs(
        config,
        &sig.ephemeral_pubkey,
        &pk.idc,
        sig.exp_date_secs,
        zks.exp_horizon_secs,
        &pk.iss_val,
        zks.extra_field.as_deref(),
        &sig.jwt_header_json,
        jwk,
        zks.override_aud_val.as_deref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn hash_public_inputs(
    config: &Configuration,
    epk: &EphemeralPublicKey,
    idc: &IdCommitment,
    exp_timestamp_secs: u64,
    exp_horizon_secs: u64,
    iss: &str,
    extra_field: Option<&str>,
    jwt_header_json: &str,
    jwk: &RsaJwk,
    override_aud_val: Option<&str>,
) -> Result<Fr, VerifyError> {
    let (has_extra_field, extra_field_hash) = match extra_field {
        None => (Fr::zero(), *EMPTY_EXTRA_FIELD_HASH),
        Some(s) => (
            Fr::one(),
            pad_and_hash_string(s, config.max_extra_field_bytes as usize)?,
        ),
    };

    let (override_aud_val_hash, use_override_aud) = match override_aud_val {
        Some(s) => (
            pad_and_hash_string(s, MAX_AUD_VAL_BYTES)?,
            Fr::one(),
        ),
        None => (*EMPTY_OVERRIDE_AUD_HASH, Fr::zero()),
    };

    // The hash absorbs `b64url(jwt_header_json) + "."` because that's the
    // prefix the JWT signature is computed over (header.payload.sig).
    let jwt_header_b64_with_dot = format!("{}.", B64URL.encode(jwt_header_json));
    let jwt_header_hash = pad_and_hash_string(
        &jwt_header_b64_with_dot,
        config.max_jwt_header_b64_bytes as usize,
    )?;

    let jwk_hash = jwk_to_poseidon_scalar(jwk)?;

    let iss_field_hash = pad_and_hash_string(iss, config.max_iss_val_bytes as usize)?;

    let idc_scalar = Fr::from_le_bytes_mod_order(&idc.0);
    let exp_timestamp = Fr::from(exp_timestamp_secs);
    let exp_horizon = Fr::from(exp_horizon_secs);

    let mut epk_frs = pad_and_pack_bytes_to_scalars_with_len(
        &epk_to_bytes(epk),
        config.max_commited_epk_bytes as usize,
    )?;

    let mut frs = Vec::with_capacity(epk_frs.len() + 10);
    frs.append(&mut epk_frs);
    frs.push(idc_scalar);
    frs.push(exp_timestamp);
    frs.push(exp_horizon);
    frs.push(iss_field_hash);
    frs.push(has_extra_field);
    frs.push(extra_field_hash);
    frs.push(jwt_header_hash);
    frs.push(jwk_hash);
    frs.push(override_aud_val_hash);
    frs.push(use_override_aud);
    hash_scalars(frs)
}

/// Wire form of the ephemeral public key, BCS-encoded — matches what the
/// circuit and aptos-core's `EphemeralPublicKey::to_bytes()` see.
fn epk_to_bytes(epk: &EphemeralPublicKey) -> Vec<u8> {
    bcs::to_bytes(epk).expect("BCS-encode EphemeralPublicKey")
}

/// Poseidon-commits the RSA modulus + a length scalar. Ported verbatim from
/// `aptos_types::jwks::rsa::RSA_JWK::to_poseidon_scalar` — the circuit
/// expects the modulus in 24-byte big-endian limbs (hence the `reverse()`).
fn jwk_to_poseidon_scalar(jwk: &RsaJwk) -> Result<Fr, VerifyError> {
    const RSA_MODULUS_BYTES: usize = 256;
    let mut modulus = B64URL
        .decode(jwk.n.as_bytes())
        .map_err(|e| VerifyError::Decode(format!("RSA JWK n: base64url decode: {}", e)))?;
    if modulus.len() != RSA_MODULUS_BYTES {
        return Err(VerifyError::Decode(format!(
            "RSA JWK n: modulus must be {} bytes, got {}",
            RSA_MODULUS_BYTES,
            modulus.len()
        )));
    }
    // Circuit-specific byte ordering: pack 24-byte BE limbs starting from
    // the LSB of the modulus. Upstream calls `reverse()` then chunks LE.
    modulus.reverse();
    let mut scalars: Vec<Fr> = modulus
        .chunks(24)
        .map(pack_bytes_to_one_scalar)
        .collect::<Result<_, _>>()?;
    scalars.push(Fr::from(RSA_MODULUS_BYTES as u64));
    hash_scalars(scalars)
}

impl IdCommitment {
    /// Recomputes the IDC from `(pepper, aud, uid_key, uid_val)`. Mirrors
    /// `aptos_types::keyless::IdCommitment::new_from_preimage`.
    ///
    /// `pepper` is the 31-byte commitment-hiding randomness (aptos-types
    /// `Pepper::NUM_BYTES = 31`).
    pub fn from_preimage(
        pepper: &[u8],
        aud: &str,
        uid_key: &str,
        uid_val: &str,
    ) -> Result<Self, VerifyError> {
        let aud_hash = pad_and_hash_string(aud, MAX_AUD_VAL_BYTES)?;
        let uid_key_hash = pad_and_hash_string(uid_key, crate::circuit::MAX_UID_KEY_BYTES)?;
        let uid_val_hash = pad_and_hash_string(uid_val, crate::circuit::MAX_UID_VAL_BYTES)?;
        let pepper_scalar = pack_bytes_to_one_scalar(pepper)?;
        let fr = hash_scalars(vec![pepper_scalar, aud_hash, uid_val_hash, uid_key_hash])?;
        Ok(IdCommitment(crate::poseidon::fr_to_bytes_le(&fr).to_vec()))
    }
}

#[cfg(test)]
mod tests {
    //! Validation tests against the aptos-core fixture bundle.
    //!
    //! The expected values are taken from `aptos_types::keyless::circuit_testcases::SAMPLE_*`
    //! piped through `aptos_types::keyless::{get_public_inputs_hash,
    //! IdCommitment::new_from_preimage}` — same outputs the
    //! `keyless-fixture-dumper` produced in the original PR. If these tests
    //! pass, our pure-Rust port is bit-compatible with aptos-types.

    use super::*;
    use crate::types::{
        EphemeralCertificate, EphemeralPublicKey, EphemeralSignature, Groth16Proof,
        IdCommitment, KeylessPublicKey, KeylessSignature, ZeroKnowledgeSig, ZkProof,
        G1Bytes, G2Bytes,
    };
    use hex_literal::hex;

    const SAMPLE_AUD: &str = "407408718192.apps.googleusercontent.com";
    const SAMPLE_UID_KEY: &str = "sub";
    const SAMPLE_UID_VAL: &str = "113990307082899718775";
    const SAMPLE_ISS: &str = "test.oidc.provider";
    const SAMPLE_EXP_DATE: u64 = 111_111_111_111;
    const SAMPLE_EXP_HORIZON_SECS: u64 = 999_999_999_999;
    // EPK = ed25519::PublicKey from `Ed25519PrivateKey::generate_for_testing()`
    // (StdRng::from_seed([0; 32])).
    const SAMPLE_EPK_BYTES: [u8; 32] =
        hex!("20fdbac9b10b7587bba7b5bc163bce69e796d71e4ed44c10fcb4488689f7a144");

    fn sample_pepper() -> [u8; 31] {
        let mut p = [0u8; 31];
        p[0] = 76;
        p
    }

    fn sample_config() -> Configuration {
        Configuration {
            override_aud_vals: vec!["test.recovery.aud".to_string()],
            max_signatures_per_txn: 3,
            // `Configuration::new_for_testing` = `new_for_devnet` with
            // max_exp_horizon_secs bumped to SAMPLE_EXP_HORIZON_SECS + 1.
            max_exp_horizon_secs: SAMPLE_EXP_HORIZON_SECS + 1,
            training_wheels_pubkey: None,
            max_commited_epk_bytes: 3 * crate::poseidon::BYTES_PACKED_PER_SCALAR as u16,
            max_iss_val_bytes: 120,
            max_extra_field_bytes: 350,
            max_jwt_header_b64_bytes: 300,
        }
    }

    fn sample_jwk() -> RsaJwk {
        // INSECURE_TEST_RSA_JWK from aptos-core/types/src/jwks/rsa/insecure_test_jwk.json.
        RsaJwk {
            kid: "test-rsa".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            e: "AQAB".to_string(),
            n: "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw".to_string(),
        }
    }

    #[test]
    fn idc_matches_aptos_types() {
        let idc = IdCommitment::from_preimage(
            &sample_pepper(),
            SAMPLE_AUD,
            SAMPLE_UID_KEY,
            SAMPLE_UID_VAL,
        )
        .unwrap();
        assert_eq!(
            idc.0,
            hex!("c390842e61c06e1ec945fc8504ad0830652ec1b6fc7bb0a095026be7551e001d"),
        );
    }

    #[test]
    fn public_inputs_hash_matches_aptos_types() {
        // Reconstruct SAMPLE_PROOF's full identity + signature shell.
        let idc = IdCommitment::from_preimage(
            &sample_pepper(),
            SAMPLE_AUD,
            SAMPLE_UID_KEY,
            SAMPLE_UID_VAL,
        )
        .unwrap();
        let pk = KeylessPublicKey {
            iss_val: SAMPLE_ISS.to_string(),
            idc,
        };
        // The dummy proof bytes don't affect PIH (only structural validity);
        // any 32/64/32-byte triple works for this test.
        let proof = Groth16Proof {
            a: G1Bytes([0u8; 32]),
            b: G2Bytes([0u8; 64]),
            c: G1Bytes([0u8; 32]),
        };
        let zks = ZeroKnowledgeSig {
            proof: ZkProof::Groth16Zkp(proof),
            exp_horizon_secs: SAMPLE_EXP_HORIZON_SECS,
            // ⚠️ MUST include trailing comma to match aptos-core's
            // `SAMPLE_JWT_EXTRA_FIELD` ("...":"Straka",) — what SAMPLE_PROOF
            // was generated against.
            extra_field: Some(r#""family_name":"Straka","#.to_string()),
            override_aud_val: None,
            training_wheels_signature: None,
        };
        let sig = KeylessSignature {
            cert: EphemeralCertificate::ZeroKnowledgeSig(zks),
            jwt_header_json: r#"{"alg":"RS256","typ":"JWT","kid":"test-rsa"}"#.to_string(),
            exp_date_secs: SAMPLE_EXP_DATE,
            ephemeral_pubkey: EphemeralPublicKey::Ed25519 {
                public_key: SAMPLE_EPK_BYTES.to_vec(),
            },
            ephemeral_signature: EphemeralSignature::Ed25519 {
                signature: vec![0u8; 64],
            },
        };

        let pih = get_public_inputs_hash(&sig, &pk, &sample_jwk(), &sample_config()).unwrap();
        assert_eq!(
            crate::poseidon::fr_to_bytes_le(&pih),
            hex!("f35c81dd7960104f5bdbc26def36c247544b7ebc21500890e77afa046742ac23"),
        );
    }
}
