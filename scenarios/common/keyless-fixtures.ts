// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Keyless test fixtures, copied from aptos-core's
 *   types/src/keyless/circuit_testcases.rs
 *   crates/aptos-crypto/src/poseidon_bn254/  (for the matching Poseidon constants)
 *   types/src/jwks/rsa/insecure_test_jwk.json (RSA modulus + private key)
 *
 * All values bind together — pepper, ephemeral keypair, blinder, JWT, expiry, and
 * Groth16 proof must be consistent or proof verification fails. Treat this file
 * as a single immutable bundle.
 *
 * Localnet prerequisites (installed by `setupLocalnetForKeyless` in
 * test-access-failures-keyless.ts):
 *   - 0x1::jwks installs an RSA JWK under iss="test.oidc.provider", kid="test-rsa"
 *     with the modulus from insecure_test_jwk.json.
 *   - 0x1::keyless_account installs the Groth16 verifying key that matches
 *     SAMPLE_PROOF (devnet-groth16-keys @ 02e5675).
 *
 * Regenerating this bundle (only needed if aptos-core's `SAMPLE_*` rotates, ~never):
 *   1. From aptos-core, run a one-off snippet that prints, in order:
 *        `aptos_types::keyless::test_utils::get_sample_jwt_token()`         → SAMPLE_JWT
 *        `hex::encode(aptos_types::keyless::circuit_testcases::SAMPLE_ESK.to_bytes())`
 *                                                                          → SAMPLE_EPHEMERAL_SK_HEX
 *        `Groth16VerificationKey::from(prepared_vk_for_testing())` field-by-field
 *                                                                          → VK bytes (paste into
 *                                                                            scenarios/keyless-bootstrap/sources/bootstrap.move)
 *        `aptos_types::keyless::circuit_testcases::SAMPLE_PROOF_NO_EXTRA_FIELD`
 *           a / b / c hex                                                   → SAMPLE_PROOF_{A,B,C}_HEX
 *   2. Paste each into the constants below + the bootstrap script.
 *
 * The PIH is computed on-the-fly by aptos-keyless-common from these inputs;
 * if any one drifts, Groth16 verification will reject every keyless request.
 */

// ── Identity ──────────────────────────────────────────────────────────────────

export const SAMPLE_ISS = 'test.oidc.provider';
export const SAMPLE_AUD = '407408718192.apps.googleusercontent.com';
export const SAMPLE_UID_KEY = 'sub';
export const SAMPLE_UID_VAL = '113990307082899718775';

// ── Pepper / blinder ──────────────────────────────────────────────────────────

// Pepper::from_number(76) → 31 bytes: [76, 0, 0, ..., 0]
export const SAMPLE_PEPPER_HEX = '4c' + '00'.repeat(30);

// First byte 42, rest zeros (31 bytes total).
export const SAMPLE_EPK_BLINDER_HEX = '2a' + '00'.repeat(30);

// ── Expiry ────────────────────────────────────────────────────────────────────

// 12/21/5490 — effectively never expires for test purposes.
export const SAMPLE_EXP_DATE_SECS = 111_111_111_111n;

// ~31,710 years.
export const SAMPLE_EXP_HORIZON_SECS = 999_999_999_999n;

// ── JWT ───────────────────────────────────────────────────────────────────────

// Header is well-known:
//   {"alg":"RS256","typ":"JWT","kid":"test-rsa"}
// Payload + signature depend on the ephemeral pubkey (via nonce), the issuer's
// RSA private key, and the IAT. We hardcode the resulting JWT string verbatim
// so the test does not need an RSA signer at runtime — pasted from
// `aptos_types::keyless::test_utils::get_sample_jwt_token()`. See top-of-file
// regeneration notes.
export const SAMPLE_JWT =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhIn0.ewogICAgICAgICAgICAiaXNzIjoidGVzdC5vaWRjLnByb3ZpZGVyIiwKICAgICAgICAgICAgImF6cCI6IjQwNzQwODcxODE5Mi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsCiAgICAgICAgICAgICJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLAogICAgICAgICAgICAic3ViIjoiMTEzOTkwMzA3MDgyODk5NzE4Nzc1IiwKICAgICAgICAgICAgImhkIjoiYXB0b3NsYWJzLmNvbSIsCiAgICAgICAgICAgICJlbWFpbCI6Im1pY2hhZWxAYXB0b3NsYWJzLmNvbSIsCiAgICAgICAgICAgICJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwKICAgICAgICAgICAgImF0X2hhc2giOiJieElFU3VJNTlJb1piNWFsQ0FTcUJnIiwKICAgICAgICAgICAgIm5hbWUiOiJNaWNoYWVsIFN0cmFrYSIsCiAgICAgICAgICAgICJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSnZZNGtWVUJSdEx4ZTFJcUtXTDVpN3RCREp6RnA5WXVXVlhNendQcGJzPXM5Ni1jIiwKICAgICAgICAgICAgImdpdmVuX25hbWUiOiJNaWNoYWVsIiwKICAgICAgICAgICAgImZhbWlseV9uYW1lIjoiU3RyYWthIiwKICAgICAgICAgICAgImxvY2FsZSI6ImVuIiwKICAgICAgICAgICAgImlhdCI6MTcwMDI1NTk0NCwKICAgICAgICAgICAgIm5vbmNlIjoiMjI4NDQ3MzMzMzQ0MjI1MTgwNDM3OTY4MTY0Mzk2NTMwODE1NDMxMTc3MzY2NzUyNTM5ODExOTQ5Njc5NzU0NTU5NDcwNTM1NjQ5NSIsCiAgICAgICAgICAgICJleHAiOjI3MDAyNTk1NDQKICAgICAgICAgfQ.JqX7sjovF_Nfn9ugmhCVFL-HhsE_2wSx1lz6pFKqWVH82pmUcjy2CWbbkCcIlV0nJ3Gsjw1I4J-cWoG_cNJFANH7o4kKDMK2g6xa2NwU0mG4ZGMrq15-rx80ALdf1VCE5_LbVLQgEWbM44l8k_g1_5fxa3x8cZ8JsNd2OqtnkChd_HoqrQjg-z__Mnv-QPgOJVoBLbddlX9zYiPgOE8DwIgFJM_vLec2P_ywszQ3tNQnxww1bhRgEyfaZdc5NcBRFAYFqwHXi-rbuX72JjzgCed-M5iEPmQS1tbUn7Njkor1kundNbHwSoaK6h-5Sv8HkXrvHJiCKOSZtMAwLk8ncQ';

// ── Ephemeral keypair ─────────────────────────────────────────────────────────

// `Ed25519PrivateKey::generate_for_testing()` — StdRng (ChaCha20Rng under the
// hood) seeded with `[0u8; 32]`. The 32 SK bytes aren't derivable in TS
// without porting that exact RNG, so we extract once from aptos-core's
// `SAMPLE_ESK` and paste. See top-of-file regeneration notes.
//
// The matching EPK is `20fdbac9b10b7587bba7b5bc163bce69e796d71e4ed44c10fcb4488689f7a144`.
export const SAMPLE_EPHEMERAL_SK_HEX =
    '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7';

// ── Groth16 proof ─────────────────────────────────────────────────────────────
//
// Reference: SAMPLE_PROOF_NO_EXTRA_FIELD in aptos-core/types/src/keyless/
// circuit_testcases.rs — the variant of the sample Groth16 proof that does
// NOT reveal an extra JWT claim. We pick this one over `SAMPLE_PROOF` so the
// scenario doesn't have to ship the exact `"family_name":"Straka",` literal
// the other variant commits to.
//
// Public-input flavor: uid_key="sub", no override aud, no extra_field.

export const SAMPLE_PROOF_A_HEX =
    'bdfda383c9131ab44dd3d8efe65c59842b28e17467e2d07c4020742407c580a7';
export const SAMPLE_PROOF_B_HEX =
    'd27b4c0296ec1045dd050894c635095c25ff8d89c8adf5da401b3434639c5605' +
    '50e3da14e5ec953769aac9d256ddc9b2a8071c021f271f0937fd5be404f2b919';
export const SAMPLE_PROOF_C_HEX =
    '52a25b0b58013a77f8713105d7e0f817468bbdd25d644e9f2a9b3eabd7d4bc17';
