// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! One-shot fixture dumper for `scenarios/common/keyless-fixtures.ts` and
//! `worker-components/keyless-verify/src/sample_pinned_hash.rs`.
//!
//! Run when the aptos-core test fixtures rotate (rare). Outputs:
//!   - `SAMPLE_EPHEMERAL_SK_HEX`  — Ed25519 SK used by the sample proof
//!   - `SAMPLE_JWT`               — the signed JWT for the sample fixtures
//!   - `SAMPLE_GROTH16_VK_*`      — alpha_g1 / beta_g2 / gamma_g2 / delta_g2
//!                                  / gamma_abc_g1[0]/[1] as hex of the
//!                                  compressed point bytes (Move + ark
//!                                  representation).
//!   - `SAMPLE_PUBLIC_INPUTS_HASH_HEX`
//!                                — 32-byte little-endian Fr of the
//!                                  Poseidon-BN254 public-input hash that
//!                                  SAMPLE_PROOF was generated against. Pinned
//!                                  into the worker so the verifier can do
//!                                  ark-groth16 verify without porting
//!                                  Poseidon. **Tied to the fixture identity
//!                                  bundle — regenerate if anything in
//!                                  `keyless-fixtures.ts` changes.**
//!
//! Usage:
//!   cargo run -p keyless-fixture-dumper

use aptos_crypto::{
    ed25519::Ed25519PrivateKey, poseidon_bn254::keyless::fr_to_bytes_le, PrivateKey, Uniform,
};
use aptos_types::keyless::{
    circuit_constants::prepared_vk_for_testing,
    get_public_inputs_hash,
    test_utils::{get_sample_groth16_sig_and_pk, get_sample_jwt_token},
    Configuration, Groth16VerificationKey,
};
use aptos_types::jwks::rsa::INSECURE_TEST_RSA_JWK;

fn main() {
    let esk = Ed25519PrivateKey::generate_for_testing();
    let esk_hex = hex::encode(esk.to_bytes());
    let epk_hex = hex::encode(esk.public_key().to_bytes());
    let jwt = get_sample_jwt_token();

    // Groth16 VK in Move-compatible byte representation (raw compressed bytes
    // per field, as stored in `0x1::keyless_account::Groth16VerificationKey`).
    let vk_pvk = prepared_vk_for_testing();
    let vk: Groth16VerificationKey = (&vk_pvk).into();

    // Public-input hash that SAMPLE_PROOF was generated against. Required by
    // the off-chain Groth16 verifier on the worker side (which has not yet
    // ported Poseidon-BN254 — once it does, this can be deleted).
    let (sig, pk) = get_sample_groth16_sig_and_pk();
    let idc_hex = hex::encode(&pk.idc.to_bytes()[1..]); // BCS-encoded `Vec<u8>` prefixes with uleb128 length; for a 32-byte vec the prefix is a single 0x20.
    let config = Configuration::new_for_testing();
    // SAMPLE_JWK = insecure_test_rsa_jwk in aptos-types; re-derive from the
    // secure_test_rsa_jwk helper to avoid pub(crate) accessor.
    // SAMPLE_JWK in circuit_testcases is INSECURE_TEST_RSA_JWK (iss="test.oidc.provider",
    // kid="test-rsa") — the matching JWK for SAMPLE_PROOF's public inputs.
    let pih = get_public_inputs_hash(&sig, &pk, &INSECURE_TEST_RSA_JWK, &config).unwrap();
    let pih_bytes = fr_to_bytes_le(&pih);
    let pih_hex = hex::encode(pih_bytes);

    println!("// === paste into scenarios/common/keyless-fixtures.ts ===");
    println!();
    println!("export const SAMPLE_EPHEMERAL_SK_HEX = '{}';", esk_hex);
    println!("// EPK (derive from SK in TS; pasted here for reference): {}", epk_hex);
    println!("export const SAMPLE_JWT = '{}';", jwt);

    println!();
    println!("// === paste into worker-components/keyless-verify/src/sample_pinned_hash.rs ===");
    println!();
    println!(
        "pub const SAMPLE_PUBLIC_INPUTS_HASH_LE: [u8; 32] = hex_literal::hex!(\"{}\");",
        pih_hex
    );
    println!(
        "pub const SAMPLE_IDC: [u8; 32] = hex_literal::hex!(\"{}\");",
        idc_hex
    );

    println!();
    println!("// === paste into scenarios/keyless-bootstrap-script/sources/bootstrap.move ===");
    println!();
    println!("// Groth16 VK (compressed bytes, Move-compatible):");
    println!("//   alpha_g1     ({} bytes): {}", vk.alpha_g1.len(), hex::encode(&vk.alpha_g1));
    println!("//   beta_g2      ({} bytes): {}", vk.beta_g2.len(), hex::encode(&vk.beta_g2));
    println!("//   gamma_g2     ({} bytes): {}", vk.gamma_g2.len(), hex::encode(&vk.gamma_g2));
    println!("//   delta_g2     ({} bytes): {}", vk.delta_g2.len(), hex::encode(&vk.delta_g2));
    for (i, abc) in vk.gamma_abc_g1.iter().enumerate() {
        println!(
            "//   gamma_abc_g1[{}] ({} bytes): {}",
            i,
            abc.len(),
            hex::encode(abc)
        );
    }
}
